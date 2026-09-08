//! Metadata transaction execution

use super::{
    new_system_call_txn,
    types::{convert_active_validators_to_bcs, onBlockStartCall, NewEpochEvent},
    SYSTEM_CALLER,
};
use crate::{onchain_config::BLOCK_ADDR, ExecuteOrderedBlockResult, OrderedBlock};
use alloy_consensus::{constants::EMPTY_WITHDRAWALS, Header, EMPTY_OMMER_ROOT_HASH};
use alloy_eips::{eip4895::Withdrawals, merge::BEACON_NONCE};
use alloy_primitives::{Address, Bytes};
use alloy_sol_types::{SolCall, SolEvent};
use gravity_api_types::events::contract_event::GravityEvent;
use gravity_primitives::PIPE_BLOCK_GAS_LIMIT;
use reth_chainspec::{ChainSpec, EthereumHardforks};
use reth_ethereum_primitives::{Block, BlockBody, TransactionSigned};
use reth_evm::Evm;
use reth_execution_types::BlockExecutionOutput;
use reth_primitives::Receipt;
use reth_provider::BlockExecutionResult;
use revm::{
    context::TxEnv,
    context_interface::result::{ExecutionResult, HaltReason},
    database::BundleState,
    state::EvmState,
    Database,
};
use std::fmt::Debug;

/// NIL proposer index constant (from Blocker.sol)
/// NIL blocks occur when consensus cannot produce a block with transactions
pub const NIL_PROPOSER_INDEX: u64 = u64::MAX;

/// Result of a metadata transaction execution
/// Merge new state changes into accumulated state changes
///
/// This is a helper function to accumulate state changes from multiple
/// sequential transaction executions.
pub fn merge_state_changes(accumulated: &mut EvmState, new_changes: EvmState) {
    for (addr, account) in new_changes {
        accumulated.insert(addr, account);
    }
}

/// Result of a system / protocol-injected transaction execution (metadata, DKG, JWK,
/// or `TestnetOwnerFix` forced transfers).
///
/// These transactions are executed before the parallel user-tx executor. Protocol
/// system txs use [`SYSTEM_CALLER`]; `TestnetOwnerFix` forced txs use the corresponding
/// `old_owner` so body `TransactionSenders` match execution.
#[derive(Debug)]
pub struct SystemTxnResult {
    /// Result of the system transaction execution
    pub result: ExecutionResult,
    /// The system transaction
    pub txn: TransactionSigned,
    /// Canonical sender recorded in `TransactionSenders` / block body recovery.
    pub sender: Address,
}

impl SystemTxnResult {
    /// Check if the transaction emitted a `NewEpoch` event
    pub fn emit_new_epoch(&self) -> Option<(u64, Bytes)> {
        for log in self.result.logs() {
            match NewEpochEvent::decode_log(log) {
                Ok(event) => {
                    // Convert ValidatorConsensusInfo[] to BCS-encoded ValidatorSet
                    let validator_bytes = convert_active_validators_to_bcs(&event.validatorSet);
                    return Some((event.newEpoch, validator_bytes));
                }
                Err(_) => {}
            }
        }
        None
    }

    /// Insert this system/protocol-injected transaction into an existing executed block
    /// result at `insert_position`. Position 0 is typically the metadata tx; later
    /// positions are validator system txs and (on Longevity) `TestnetOwnerFix` forced txs.
    pub(crate) fn insert_to_executed_ordered_block_result(
        self,
        result: &mut crate::ExecuteOrderedBlockResult,
        insert_position: usize,
    ) {
        let gas_used = self.result.gas_used();
        result.block.header.gas_used += gas_used;
        result.execution_output.gas_used += gas_used;

        // Calculate cumulative_gas_used for this system transaction:
        // It should be the cumulative gas of the previous transaction (at insert_position - 1)
        // plus this transaction's gas_used
        let cumulative_gas_used = if insert_position == 0 {
            // First transaction, cumulative equals its own gas_used
            gas_used
        } else {
            // Get cumulative from the previous receipt and add this tx's gas
            result
                .execution_output
                .receipts
                .get(insert_position - 1)
                .map(|prev| prev.cumulative_gas_used + gas_used)
                .unwrap_or(gas_used)
        };

        // Update all receipts AFTER insert_position to add this tx's gas
        for receipt in result.execution_output.receipts.iter_mut().skip(insert_position) {
            receipt.cumulative_gas_used += gas_used;
        }

        let is_success = self.result.is_success();

        result.execution_output.receipts.insert(
            insert_position,
            Receipt {
                tx_type: self.txn.tx_type(),
                success: is_success,
                cumulative_gas_used,
                logs: self.result.into_logs(),
            },
        );
        result.block.body.transactions.insert(insert_position, self.txn);
        result.senders.insert(insert_position, self.sender);
    }
}

/// Convert a completed system-transaction prefix into a full executed block result.
/// Used when a system transaction triggers a new epoch and user transactions are discarded.
pub(crate) fn system_txns_into_executed_ordered_block_result(
    system_txn_results: Vec<SystemTxnResult>,
    chain_spec: &ChainSpec,
    ordered_block: &OrderedBlock,
    base_fee: u64,
    state: BundleState,
    validators: Bytes,
) -> ExecuteOrderedBlockResult {
    debug_assert!(
        !system_txn_results.is_empty(),
        "epoch change requires at least the triggering system transaction"
    );

    let total_gas_used = system_txn_results.iter().map(|result| result.result.gas_used()).sum();
    let mut block = Block {
        header: Header {
            beneficiary: ordered_block.coinbase,
            timestamp: ordered_block.timestamp_us / 1_000_000, // convert to seconds
            mix_hash: ordered_block.prev_randao,
            base_fee_per_gas: Some(base_fee),
            number: ordered_block.number,
            gas_limit: PIPE_BLOCK_GAS_LIMIT,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            nonce: BEACON_NONCE.into(),
            gas_used: total_gas_used,
            ..Default::default()
        },
        body: BlockBody {
            transactions: Vec::with_capacity(system_txn_results.len()),
            ..Default::default()
        },
    };

    // Shanghai fork fields
    if chain_spec.is_shanghai_active_at_timestamp(block.timestamp) {
        block.header.withdrawals_root = Some(EMPTY_WITHDRAWALS);
        block.body.withdrawals = Some(Withdrawals::default());
    }

    // Cancun fork fields
    if chain_spec.is_cancun_active_at_timestamp(block.timestamp) {
        // FIXME: Is it OK to use the parent's block id as `parent_beacon_block_root` before
        // execution?
        block.header.parent_beacon_block_root = Some(ordered_block.parent_id);

        // TODO(nekomoto): fill `excess_blob_gas` and `blob_gas_used` fields
        block.header.excess_blob_gas = Some(0);
        block.header.blob_gas_used = Some(0);
    }

    let mut receipts = Vec::with_capacity(system_txn_results.len());
    let mut senders = Vec::with_capacity(system_txn_results.len());
    let mut cumulative_gas_used = 0;
    for SystemTxnResult { result, txn, sender } in system_txn_results {
        let gas_used = result.gas_used();
        cumulative_gas_used += gas_used;
        receipts.push(Receipt {
            tx_type: txn.tx_type(),
            success: result.is_success(),
            cumulative_gas_used,
            logs: result.into_logs(),
        });
        block.body.transactions.push(txn);
        senders.push(sender);
    }

    let new_epoch = ordered_block.epoch + 1;
    ExecuteOrderedBlockResult {
        block,
        senders,
        execution_output: BlockExecutionOutput {
            state,
            result: BlockExecutionResult {
                receipts,
                requests: Default::default(),
                gas_used: total_gas_used,
                blob_gas_used: 0,
            },
        },
        txs_info: vec![],
        gravity_events: vec![GravityEvent::NewEpoch(new_epoch, validators.into())],
        epoch: new_epoch,
    }
}

/// Execute a single system transaction (metadata, DKG, or JWK)
///
/// This is the unified entry point for executing all system-level transactions.
/// These transactions are executed one by one before the parallel executor.
pub fn transact_system_txn(
    evm: &mut impl Evm<DB = impl Database, Error: Debug, Tx = TxEnv, HaltReason = HaltReason>,
    txn: TransactionSigned,
) -> (SystemTxnResult, EvmState) {
    use reth_evm::IntoTxEnv;
    use reth_primitives::Recovered;

    let tx_env = Recovered::new_unchecked(txn.clone(), SYSTEM_CALLER).into_tx_env();
    let result = evm.transact_raw(tx_env).unwrap();

    // DESIGN: System transaction failures are intentionally logged, not asserted.
    // DKG and JWK system transactions can legitimately fail or revert, so a hard
    // assert would crash the node on valid failure scenarios. Graceful handling
    // (logging + continuing) is the correct behavior here.
    if !result.result.is_success() {
        super::errors::log_execution_error(&result.result);
    }

    (SystemTxnResult { result: result.result, txn, sender: SYSTEM_CALLER }, result.state)
}

/// Execute a metadata contract call (onBlockStart from Blocker.sol)
///
/// Calls Blocker.onBlockStart(proposerIndex, failedProposerIndices, timestampMicros)
/// to perform block prologue operations including:
/// - Resolving proposer address from index
/// - Updating global timestamp
/// - Checking and potentially starting epoch transition
///
/// @param proposer_index Index of the proposer in the active validator set,
///        or None for NIL blocks (will use NIL_PROPOSER_INDEX = u64::MAX)
pub fn construct_metadata_txn(
    nonce: u64,
    gas_price: u128,
    timestamp_us: u64,
    proposer_index: Option<u64>,
    failed_proposer_indices: &[u64],
) -> TransactionSigned {
    // For NIL blocks, use NIL_PROPOSER_INDEX (type(uint64).max in Solidity)
    let proposer_idx = proposer_index.unwrap_or(NIL_PROPOSER_INDEX);

    let call = onBlockStartCall {
        proposerIndex: proposer_idx,
        failedProposerIndices: failed_proposer_indices.to_vec(),
        timestampMicros: timestamp_us,
    };
    let input: Bytes = call.abi_encode().into();

    new_system_call_txn(BLOCK_ADDR, nonce, gas_price, input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256};
    use revm::context_interface::result::{Output, SuccessReason};

    fn system_txn_result(nonce: u64, gas_used: u64) -> SystemTxnResult {
        SystemTxnResult {
            result: ExecutionResult::Success {
                reason: SuccessReason::Return,
                gas: revm::context_interface::result::ResultGas::default()
                    .with_total_gas_spent(gas_used),
                logs: vec![],
                output: Output::Call(Bytes::new()),
            },
            txn: construct_metadata_txn(nonce, 1, 1_000_000, Some(0), &[]),
            sender: SYSTEM_CALLER,
        }
    }

    fn ordered_block() -> OrderedBlock {
        OrderedBlock {
            epoch: 3,
            parent_id: B256::with_last_byte(1),
            id: B256::with_last_byte(2),
            number: 11,
            timestamp_us: 1_000_000,
            coinbase: Address::ZERO,
            prev_randao: B256::ZERO,
            withdrawals: Withdrawals::default(),
            transactions: vec![],
            senders: vec![],
            proposer_index: Some(0),
            failed_proposer_indices: vec![],
            extra_data: vec![],
            randomness: U256::ZERO,
        }
    }

    #[test]
    fn system_txns_into_epoch_change_result_preserves_completed_prefix() {
        let results =
            vec![system_txn_result(10, 3), system_txn_result(11, 5), system_txn_result(12, 7)];
        let result = system_txns_into_executed_ordered_block_result(
            results,
            &ChainSpec::default(),
            &ordered_block(),
            1,
            BundleState::default(),
            Bytes::from_static(b"validators"),
        );

        assert_eq!(result.block.body.transactions.len(), 3);
        assert_eq!(result.execution_output.result.receipts.len(), 3);
        assert_eq!(result.senders, vec![SYSTEM_CALLER; 3]);
        assert_eq!(result.block.header.gas_used, 15);
        assert_eq!(result.execution_output.result.gas_used, 15);
        assert_eq!(result.execution_output.result.receipts[0].cumulative_gas_used, 3);
        assert_eq!(result.execution_output.result.receipts[1].cumulative_gas_used, 8);
        assert_eq!(result.execution_output.result.receipts[2].cumulative_gas_used, 15);
        assert_eq!(result.epoch, 4);
        assert!(matches!(result.gravity_events.as_slice(), [GravityEvent::NewEpoch(4, _)]));
    }
}
