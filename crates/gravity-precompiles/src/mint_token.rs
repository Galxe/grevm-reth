//! Mint Token Precompile Contract
//!
//! This precompile allows authorized callers (JWK Manager) to mint tokens
//! directly to specified recipient addresses by modifying the EVM journal state
//! in-place via `EvmInternals`.

use alloy_primitives::{address, Address, Bytes, U256};
use reth_evm::precompiles::{DynPrecompile, PrecompileInput};
use revm::precompile::{PrecompileHalt, PrecompileId, PrecompileOutput, PrecompileResult};
use tracing::{info, warn};

/// Address of Gravity's native mint precompile.
pub const NATIVE_MINT_PRECOMPILE_ADDR: Address =
    address!("00000000000000000000000000000001625f5000");

/// Authorized caller address (JWK Manager at 0x2018)
///
/// Only this address is allowed to call the mint precompile.
pub const AUTHORIZED_CALLER: Address = address!("0x595475934ed7d9faa7fca28341c2ce583904a44e");

/// Function ID for mint operation
const FUNC_MINT: u8 = 0x01;

/// Base gas cost for mint operation
const MINT_BASE_GAS: u64 = 21000;

/// Creates a mint token precompile contract instance.
///
/// The precompile directly modifies the recipient account's balance inside the
/// EVM journal (via [`EvmInternals::load_account`]) during execution.
///
/// # Returns
///
/// A dynamic precompile that can be registered with the EVM.
pub fn create_mint_token_precompile() -> DynPrecompile {
    let precompile_id = PrecompileId::custom("mint_token");

    (precompile_id, move |input: PrecompileInput<'_>| -> PrecompileResult {
        mint_token_handler(input)
    })
        .into()
}

/// Mint Token handler function
///
/// Directly modifies the recipient's balance in the EVM journal state, ensuring
/// the change is visible to subsequent opcodes within the same block and is
/// committed atomically with the rest of the transaction's state changes.
///
/// # Security
///
/// - Only JWK Manager (`AUTHORIZED_CALLER`) is allowed to call this precompile
/// - Calls from other addresses will be rejected with an error
///
/// # Parameter format (53 bytes)
///
/// | Offset | Size | Description |
/// |--------|------|-------------|
/// | 0      | 1    | Function ID (0x01) |
/// | 1      | 20   | Recipient address |
/// | 21     | 32   | Amount (U256, big-endian) |
///
/// # Errors
///
/// - `OutOfGas` - Less than `MINT_BASE_GAS` gas was forwarded
/// - `Unauthorized caller` - Caller is not the authorized JWK Manager
/// - `Invalid input length` - Input data is less than 53 bytes
/// - `Invalid function ID` - Function ID is not 0x01
/// - `Invalid or zero amount` - Amount is zero or exceeds `u128::MAX`
/// - `Balance overflow` - Adding amount would overflow the recipient's balance
/// - `Failed to load account` - Journal failed to load the recipient account
fn mint_token_handler(mut input: PrecompileInput<'_>) -> PrecompileResult {
    // Charge-gas check before parsing input or touching the EVM journal. The EVM
    // dispatcher charges `gas_used` after a successful precompile return; if the
    // precompile reports more gas than was forwarded, the dispatcher can panic
    // instead of producing a normal out-of-gas result.
    if let Err(halt) = ensure_mint_gas(input.gas) {
        return Ok(PrecompileOutput::halt(halt, 0));
    }

    // 1. Validate caller address
    if input.caller != AUTHORIZED_CALLER {
        warn!(
            target: "evm::precompile::mint_token",
            caller = ?input.caller,
            authorized = ?AUTHORIZED_CALLER,
            "Unauthorized caller"
        );
        return Ok(PrecompileOutput::halt(PrecompileHalt::other_static("Unauthorized caller"), 0));
    }

    // 2. Parameter length check (1 + 20 + 32 = 53 bytes)
    const EXPECTED_LEN: usize = 1 + 20 + 32;
    if input.data.len() != EXPECTED_LEN {
        warn!(
            target: "evm::precompile::mint_token",
            input_len = input.data.len(),
            expected = EXPECTED_LEN,
            "Invalid input length"
        );
        return Ok(PrecompileOutput::halt(
            PrecompileHalt::other(format!(
                "Invalid input length: {}, expected {}",
                input.data.len(),
                EXPECTED_LEN
            )),
            0,
        ));
    }

    // 3. Parse and validate function ID
    if input.data[0] != FUNC_MINT {
        warn!(
            target: "evm::precompile::mint_token",
            func_id = input.data[0],
            expected = FUNC_MINT,
            "Invalid function ID"
        );
        return Ok(PrecompileOutput::halt(
            PrecompileHalt::other(format!(
                "Invalid function ID: {:#x}, expected {:#x}",
                input.data[0], FUNC_MINT
            )),
            0,
        ));
    }

    // 4. Parse recipient address (bytes 1-20)
    let recipient = Address::from_slice(&input.data[1..21]);

    // 5. Parse amount (bytes 21-52)
    let amount_u256 = U256::from_be_slice(&input.data[21..53]);
    let amount: u128 = match amount_u256.try_into() {
        Ok(a) => a,
        Err(_) => {
            warn!(
                target: "evm::precompile::mint_token",
                ?recipient,
                amount = ?amount_u256,
                "Amount exceeds u128::MAX"
            );
            return Ok(PrecompileOutput::halt(
                PrecompileHalt::other_static("Amount exceeds u128::MAX"),
                0,
            ));
        }
    };

    if amount == 0 {
        warn!(target: "evm::precompile::mint_token", ?recipient, "Zero amount");
        return Ok(PrecompileOutput::halt(
            PrecompileHalt::other_static("Zero amount not allowed"),
            0,
        ));
    }

    // 6. Load the recipient account from the EVM journal to read its current balance, then write
    //    back via `set_balance`, which journals the change and touches the account so revm commits
    //    it to state on transaction end. The overflow check stays explicit to preserve the
    //    pre-revm-40 "Balance overflow" halt semantics.
    //
    // NOTE(gravity): revm 40's `EvmInternals::load_account` returns an immutable reference, so
    // the pre-revm-40 direct cache mutation (`account.info.balance = ..` + `mark_touch()`) is no
    // longer expressible. `set_balance` additionally records a journal entry, which means a mint
    // is now rolled back if an enclosing call frame reverts afterwards — the old direct mutation
    // survived such reverts. This only diverges on replay if a historical block ever exercised
    // "mint succeeds, enclosing frame reverts"; confirm against chain history before release.
    let old_balance = match input.internals_mut().load_account(recipient) {
        Ok(state_load) => state_load.data.info.balance,
        Err(e) => {
            return Ok(PrecompileOutput::halt(
                PrecompileHalt::other(format!("Failed to load account {recipient}: {e}")),
                0,
            ));
        }
    };
    let Some(new_balance) = old_balance.checked_add(U256::from(amount)) else {
        return Ok(PrecompileOutput::halt(PrecompileHalt::other_static("Balance overflow"), 0));
    };
    if let Err(e) = input.internals_mut().set_balance(recipient, new_balance) {
        return Ok(PrecompileOutput::halt(
            PrecompileHalt::other(format!("Failed to set balance for {recipient}: {e}")),
            0,
        ));
    }

    info!(
        target: "evm::precompile::mint_token",
        ?recipient,
        amount,
        new_balance = ?new_balance,
        "Minted tokens directly into journal state"
    );

    Ok(PrecompileOutput::new(MINT_BASE_GAS, Bytes::new(), 0))
}

fn ensure_mint_gas(gas: u64) -> Result<(), PrecompileHalt> {
    (gas >= MINT_BASE_GAS).then_some(()).ok_or(PrecompileHalt::OutOfGas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_evm::{eth::EthEvmContext, precompiles::Precompile, EvmInternals};
    use revm::{context::JournalTr, database::EmptyDB};

    fn mint_calldata(recipient: Address, amount: U256) -> [u8; 53] {
        let mut data = [0; 53];
        data[0] = FUNC_MINT;
        data[1..21].copy_from_slice(recipient.as_slice());
        data[21..].copy_from_slice(&amount.to_be_bytes::<32>());
        data
    }

    fn call_mint(ctx: &mut EthEvmContext<EmptyDB>, data: &[u8]) -> PrecompileResult {
        create_mint_token_precompile().call(PrecompileInput {
            data,
            gas: MINT_BASE_GAS,
            reservoir: 0,
            caller: AUTHORIZED_CALLER,
            value: U256::ZERO,
            is_static: false,
            target_address: Address::ZERO,
            bytecode_address: Address::ZERO,
            internals: EvmInternals::from_context(ctx),
        })
    }

    #[test]
    fn rejects_insufficient_forwarded_gas() {
        assert!(matches!(ensure_mint_gas(MINT_BASE_GAS - 1), Err(PrecompileHalt::OutOfGas)));
        assert!(ensure_mint_gas(MINT_BASE_GAS).is_ok());
    }

    #[test]
    fn mints_and_touches_recipient() {
        let recipient = address!("0x1111111111111111111111111111111111111111");
        let amount = U256::from(42);
        let data = mint_calldata(recipient, amount);
        let mut ctx = EthEvmContext::new(EmptyDB::default(), Default::default());
        let output = call_mint(&mut ctx, &data).unwrap();
        let account = ctx.journaled_state.load_account(recipient).unwrap().data;
        assert_eq!(output.gas_used, MINT_BASE_GAS);
        assert_eq!(account.info.balance, amount);
        assert!(account.is_touched());
    }
}
