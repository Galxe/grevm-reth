//! Onchain config extension for Gravity

#![allow(missing_docs)]

pub mod base;
pub mod consensus_config;
pub mod dkg;
pub mod epoch;
pub mod errors;
pub mod jwk_consensus_config;
pub mod jwk_oracle;
pub mod metadata_txn;
pub mod observed_jwk;
pub mod oracle_state;
pub mod oracle_task_helpers;
pub mod performance;
pub mod types;
pub mod validator_set;

// Re-export main types for convenience
pub use base::{ConfigFetcher, OnchainConfigFetcher};
pub use consensus_config::ConsensusConfigFetcher;
pub use epoch::EpochFetcher;
pub(crate) use metadata_txn::system_txns_into_executed_ordered_block_result;
pub use metadata_txn::{construct_metadata_txn, transact_system_txn, SystemTxnResult};
pub use types::{
    convert_active_validators_to_bcs, convert_validator_consensus_info, ValidatorConsensusInfo,
    ValidatorStatus,
};
pub use validator_set::ValidatorSetFetcher;

// Common addresses and constants
use alloy_primitives::{address, Address};

pub const GRAVITY_FRAMEWORK_ADDRESS: Address = address!("00000000000000000000000000000000000000ff");
pub const RECONFIGURATION_ADDRESS: Address = address!("00000000000000000000000000000000000000f0");
pub const BLOCK_MODULE_ADDRESS: Address = address!("00000000000000000000000000000000000000f1");
pub const CONSENSUS_CONFIG_CONTRACT_ADDRESS: Address =
    address!("00000000000000000000000000000000000000f2");
pub const VALIDATOR_SET_CONTRACT_ADDRESS: Address =
    address!("00000000000000000000000000000000000000f3");

pub const DEAD_ADDRESS: Address = address!("000000000000000000000000000000000000dEaD");

// ============================================================================
// System Addresses (aligned with gravity_chain_core_contracts/src/foundation/SystemAddresses.sol)
// Address ranges:
//   0x1625F0xxx: Consensus Engine
//   0x1625F1xxx: Runtime Configurations
//   0x1625F2xxx: Staking & Validator
//   0x1625F3xxx: Governance
//   0x1625F4xxx: Oracle
//   0x1625F5xxx: Precompiles
// ============================================================================

// Consensus Engine (0x1625F0xxx)
//
// `SYSTEM_CALLER` is re-exported from `reth_chainspec` so the literal lives in a
// single source of truth (see `crates/chainspec/src/gravity.rs`). Downstream
// modules continue to import it from this module path for backwards compatibility.
pub use reth_chainspec::SYSTEM_CALLER;
pub const GENESIS_ADDR: Address = address!("00000000000000000000000000000001625f0001");

// Runtime Configurations (0x1625F1xxx)
pub const TIMESTAMP_ADDR: Address = address!("00000000000000000000000000000001625f1000");
pub const STAKE_CONFIG_ADDR: Address = address!("00000000000000000000000000000001625f1001");
pub const VALIDATOR_CONFIG_ADDR: Address = address!("00000000000000000000000000000001625f1002");
pub const RANDOMNESS_CONFIG_ADDR: Address = address!("00000000000000000000000000000001625f1003");
pub const GOVERNANCE_CONFIG_ADDR: Address = address!("00000000000000000000000000000001625f1004");
pub const EPOCH_CONFIG_ADDR: Address = address!("00000000000000000000000000000001625f1005");
pub const VERSION_CONFIG_ADDR: Address = address!("00000000000000000000000000000001625f1006");
pub const CONSENSUS_CONFIG_ADDR: Address = address!("00000000000000000000000000000001625f1007");
pub const EXECUTION_CONFIG_ADDR: Address = address!("00000000000000000000000000000001625f1008");
pub const ORACLE_TASK_CONFIG_ADDR: Address = address!("00000000000000000000000000000001625f1009");
pub const ON_DEMAND_ORACLE_TASK_CONFIG_ADDR: Address =
    address!("00000000000000000000000000000001625f100a");

// Staking & Validator (0x1625F2xxx)
pub const STAKING_ADDR: Address = address!("00000000000000000000000000000001625f2000");
pub const VALIDATOR_MANAGER_ADDR: Address = address!("00000000000000000000000000000001625f2001");
pub const DKG_ADDR: Address = address!("00000000000000000000000000000001625f2002");
pub const RECONFIGURATION_ADDR: Address = address!("00000000000000000000000000000001625f2003");
pub const BLOCK_ADDR: Address = address!("00000000000000000000000000000001625f2004");
pub const PERFORMANCE_TRACKER_ADDR: Address = address!("00000000000000000000000000000001625f2005");

// Governance (0x1625F3xxx)
pub const GOVERNANCE_ADDR: Address = address!("00000000000000000000000000000001625f3000");

// Oracle (0x1625F4xxx)
pub const NATIVE_ORACLE_ADDR: Address = address!("00000000000000000000000000000001625f4000");
pub const JWK_MANAGER_ADDR: Address = address!("00000000000000000000000000000001625f4001");
pub const ORACLE_REQUEST_QUEUE_ADDR: Address = address!("00000000000000000000000000000001625f4002");

// Precompiles (0x1625F5xxx)
pub use gravity_precompiles::{
    mint_token::NATIVE_MINT_PRECOMPILE_ADDR,
    randomness_by_height::RANDOMNESS_BY_HEIGHT_PRECOMPILE_ADDR,
};
// Reserved synthetic protocol-log emitter; not an executable precompile.
pub use reth_chainspec::GRAVITY_TX_SKIPPED_LOG_ADDRESS;

// Legacy aliases (for backward compatibility)
pub const SYSTEM_CONTRACT_ADDRESS: Address = SYSTEM_CALLER;
pub const EPOCH_MANAGER_ADDR: Address = RECONFIGURATION_ADDR;
pub const RECONFIGURATION_WITH_DKG_ADDR: Address = RECONFIGURATION_ADDR;

// ============================================================================
// Validator Transactions Construction
// ============================================================================

use alloy_consensus::{EthereumTxEnvelope, TxEip4844, TxLegacy};
use alloy_primitives::{Bytes, Signature, U256};
use reth_ethereum_primitives::{Transaction, TransactionSigned};
use revm_primitives::TxKind;
use tracing::{debug, info};

/// Construct validator transactions envelope (JWK updates and DKG transcripts)
///
/// Uses ExtraDataType to construct appropriate transactions:
/// - `ExtraDataType::JWK` → `upsertObservedJWKs` transaction to JWK_MANAGER_ADDR
/// - `ExtraDataType::DKG` → `finishWithDkgResult` transaction to RECONFIGURATION_WITH_DKG_ADDR
pub fn construct_validator_txns_envelope(
    extra_data: &Vec<gravity_api_types::ExtraDataType>,
    system_caller_nonce: u64,
    gas_price: u128,
    is_alpha_active: bool,
) -> Result<Vec<EthereumTxEnvelope<TxEip4844>>, String> {
    let system_caller_nonce = system_caller_nonce + 1;
    let mut txns = Vec::new();

    for (index, data) in extra_data.iter().enumerate() {
        let current_nonce = system_caller_nonce + index as u64;

        // Process data based on ExtraDataType variant
        match construct_validator_txn_from_extra_data(
            data,
            current_nonce,
            gas_price,
            is_alpha_active,
        ) {
            Ok(transaction) => txns.push(transaction),
            Err(e) => {
                return Err(format!("Failed to process extra data at index {}: {}", index, e));
            }
        }
    }

    Ok(txns)
}

/// Construct a single validator transaction from ExtraDataType
///
/// Supports:
/// - JWK/Oracle updates (ExtraDataType::JWK) - includes both RSA JWKs and blockchain events
/// - DKG transcripts (ExtraDataType::DKG)
pub fn construct_validator_txn_from_extra_data(
    data: &gravity_api_types::ExtraDataType,
    nonce: u64,
    gas_price: u128,
    is_alpha_active: bool,
) -> Result<TransactionSigned, String> {
    match data {
        gravity_api_types::ExtraDataType::JWK(data_bytes) => {
            // Deserialize as ProviderJWKs
            let provider_jwks = bcs::from_bytes::<
                gravity_api_types::on_chain_config::jwks::ProviderJWKs,
            >(data_bytes)
            .map_err(|e| format!("Failed to deserialize JWK data: {}", e))?;

            let issuer_str = String::from_utf8_lossy(&provider_jwks.issuer);
            info!("Processing oracle update for issuer: {}", issuer_str);

            // Unified handler for all oracle data (JWK and blockchain events)
            // Routing between sourceType is done inside construct_oracle_record_transaction
            jwk_oracle::construct_oracle_record_transaction(provider_jwks, nonce, gas_price)
        }
        gravity_api_types::ExtraDataType::DKG(data_bytes) => {
            // Deserialize as DKGTranscript
            let dkg_transcript = bcs::from_bytes::<
                gravity_api_types::on_chain_config::dkg::DKGTranscript,
            >(data_bytes)
            .map_err(|e| format!("Failed to deserialize DKG data: {}", e))?;
            debug!("Processing DKG transcript for epoch: {:?}", dkg_transcript);
            dkg::construct_dkg_transaction(dkg_transcript, nonce, gas_price, is_alpha_active)
        }
    }
}

/// Create a new system call transaction
///
/// Helper function used by both JWK and DKG transaction construction
pub(crate) fn new_system_call_txn(
    contract: Address,
    nonce: u64,
    gas_price: u128,
    input: Bytes,
) -> TransactionSigned {
    TransactionSigned::new_unhashed(
        Transaction::Legacy(TxLegacy {
            chain_id: None,
            nonce,
            gas_price,
            gas_limit: 30_000_000,
            to: TxKind::Call(contract),
            value: U256::ZERO,
            input,
        }),
        Signature::new(U256::ZERO, U256::ZERO, false),
    )
}
