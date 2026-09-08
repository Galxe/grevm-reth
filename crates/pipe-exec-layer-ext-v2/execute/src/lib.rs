//! Pipeline execution layer extension
#[macro_use]
mod channel;
mod custom_precompiles;
mod eip_2935;
mod metrics;
pub mod onchain_config;
pub mod randomness_precompile;
mod system_caller_migration;
mod testnet_owner_fix;
mod tx_filter;
use alloy_sol_types::SolEvent;

use channel::Channel;
use gravity_api_types::{
    config_storage::{BlockNumber, ConfigStorage, OnChainConfig, OnChainConfigResType},
    events::contract_event::GravityEvent,
    ExtraDataType,
};
use metrics::PipeExecLayerMetrics;

use alloy_consensus::{
    constants::EMPTY_WITHDRAWALS, BlockHeader, Header, Transaction, EMPTY_OMMER_ROOT_HASH,
};
use alloy_eips::{eip4895::Withdrawals, merge::BEACON_NONCE, BlockNumberOrTag};
use alloy_primitives::{Address, Bytes, TxHash, B256, U256};
use alloy_rpc_types_eth::TransactionRequest;
use gravity_precompiles::{
    bls_pop_verify::{create_bls_pop_verify_precompile, BLS_PRECOMPILE_ADDR},
    mint_token::{create_mint_token_precompile, NATIVE_MINT_PRECOMPILE_ADDR},
    randomness_by_height::randomness_by_height_gas_policy_at_block,
};
use gravity_primitives::PIPE_BLOCK_GAS_LIMIT;
use grevm::{DelegatedSafetyConfig, DynParallelPrecompile};
use reth_chain_state::{ExecutedBlockWithTrieUpdates, ExecutedTrieUpdates};
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks, GravityHardfork};
use reth_ethereum_primitives::{Block, BlockBody, Receipt, TransactionSigned};
use reth_evm::{
    execute::BlockExecutionError, precompiles::DynPrecompile, ConfigureEvm, IntoTxEnv,
    NextBlockEnvAttributes,
};
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_types::{BlockExecutionOutput, ExecutionOutcome};
use reth_pipe_exec_layer_event_bus::{
    MakeCanonicalEvent, PipeExecLayerEvent, PipeExecLayerEventBus, WaitForPersistenceEvent,
    PIPE_EXEC_LAYER_EVENT_BUS,
};
use reth_primitives::{EthPrimitives, Recovered};
use reth_primitives_traits::{
    proofs::{self},
    Block as _, RecoveredBlock,
};
use reth_provider::{OriginalValuesKnown, PersistBlockCache, PERSIST_BLOCK_CACHE};
use reth_rpc_eth_api::RpcTypes;
use revm::DatabaseRef;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use gravity_storage::GravityStorage;
use onchain_config::OnchainConfigFetcher;
use reth_evm::parallel_execute::ParallelExecutor;
use reth_rpc_eth_api::helpers::EthCall;
use reth_trie::{HashedPostState, KeccakKeyHasher};
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot, Mutex,
};
use tracing::*;

use crate::{
    onchain_config::{
        construct_metadata_txn, construct_validator_txn_from_extra_data,
        dkg::{convert_dkg_start_event_to_api, DKGStartEvent},
        system_txns_into_executed_ordered_block_result,
        types::{DataRecorded, OracleDelivered},
        SystemTxnResult, DKG_ADDR, NATIVE_ORACLE_ADDR, RANDOMNESS_BY_HEIGHT_PRECOMPILE_ADDR,
        SYSTEM_CALLER,
    },
    randomness_precompile::{ExecutionRandomnessProvider, GravityStorageRandomnessProvider},
};

fn extract_gravity_events_from_system_receipts(
    receipts: &[Receipt],
    block_number: u64,
    epoch: u64,
) -> Vec<GravityEvent> {
    use gravity_api_types::on_chain_config::jwks::ProviderJWKs;

    let mut gravity_events = vec![];
    // Map from (sourceType, sourceId) to latest nonce
    let mut data_records: BTreeMap<(u32, U256), u128> = BTreeMap::new();

    for receipt in receipts {
        debug!(target: "execute_ordered_block",
            number=?block_number,
            logs_len=?receipt.logs.len(),
            "extract gravity events from receipt"
        );
        for log in &receipt.logs {
            // Parse both historical and current delivery events only from NativeOracle.
            if log.address == NATIVE_ORACLE_ADDR {
                let delivery = DataRecorded::decode_log(&log)
                    .map(|event| (event.sourceType, event.sourceId, event.nonce))
                    .or_else(|_| {
                        OracleDelivered::decode_log(&log)
                            .map(|event| (event.sourceType, event.sourceId, event.nonce))
                    });

                if let Ok((source_type, source_id, nonce)) = delivery {
                    info!(target: "execute_ordered_block",
                        number=?block_number,
                        source_type=?source_type,
                        source_id=?source_id,
                        nonce=?nonce,
                        "oracle delivery event"
                    );
                    // Keep only the latest nonce for each (sourceType, sourceId)
                    let key = (source_type, source_id);
                    data_records
                        .entry(key)
                        .and_modify(|existing_nonce| {
                            if nonce > *existing_nonce {
                                *existing_nonce = nonce;
                            }
                        })
                        .or_insert(nonce);
                }
            }

            // Parse DKG events only from the DKG contract.
            if log.address == DKG_ADDR {
                if let Ok(event) = DKGStartEvent::decode_log(&log) {
                    info!(target: "execute_ordered_block",
                        number=?block_number,
                        dealer_epoch=?event.dealerEpoch,
                        "dkg start"
                    );
                    gravity_events.push(GravityEvent::DKG(convert_dkg_start_event_to_api(&event)));
                }
            }
        }
    }

    // Convert collected delivery events to ProviderJWKs.
    if !data_records.is_empty() {
        let api_jwks: Vec<ProviderJWKs> = data_records
            .into_iter()
            .map(|((source_type, source_id), nonce)| {
                // issuer format: "gravity://sourceType/sourceId"
                let issuer = format!("gravity://{}/{}", source_type, source_id);
                ProviderJWKs {
                    issuer: issuer.into_bytes(),
                    version: nonce as u64, // nonce as version
                    jwks: vec![gravity_api_types::on_chain_config::jwks::JWKStruct {
                        // gaptos reads gravity:// oracle progress from Any.data as a raw
                        // 16-byte nonce. The GravityEvent adapter only preserves raw bytes
                        // for known JWK wrappers, so this entry is a nonce carrier rather
                        // than an RSA key.
                        type_name: "0x1::jwks::RSA_JWK".to_string(),
                        data: nonce.to_be_bytes().to_vec(),
                    }],
                }
            })
            .collect();

        info!(target: "execute_ordered_block",
            number=?block_number,
            epoch=?epoch,
            provider_count=?api_jwks.len(),
            "constructed ProviderJWKs from oracle delivery events"
        );

        gravity_events.push(GravityEvent::ObservedJWKsUpdated(epoch, api_jwks));
    }

    gravity_events
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onchain_config::dkg::{
        ConfigV2Data, ConfigVariant, DKGSessionMetadata, DKGStartEvent, RandomnessConfigData,
    };
    use alloy_primitives::{Address, Log};
    use alloy_sol_types::SolEvent;

    fn receipt_with_log(address: Address, data: alloy_primitives::LogData) -> Receipt {
        Receipt {
            success: true,
            cumulative_gas_used: 0,
            logs: vec![Log { address, data }],
            ..Default::default()
        }
    }

    #[test]
    fn extract_gravity_events_ignores_data_recorded_from_wrong_emitter() {
        let event = DataRecorded {
            sourceType: 1,
            sourceId: U256::from(2),
            nonce: 3,
            dataLength: U256::ZERO,
        };
        let forged_receipts =
            vec![receipt_with_log(Address::from([0x42; 20]), event.encode_log_data())];

        let events = extract_gravity_events_from_system_receipts(&forged_receipts, 10, 7);
        assert!(events.is_empty(), "forged DataRecorded emitter must not produce GravityEvent");

        let valid_receipts = vec![receipt_with_log(NATIVE_ORACLE_ADDR, event.encode_log_data())];
        let events = extract_gravity_events_from_system_receipts(&valid_receipts, 10, 7);
        assert_eq!(events.len(), 1);
        match &events[0] {
            GravityEvent::ObservedJWKsUpdated(epoch, jwks) => {
                assert_eq!(*epoch, 7);
                assert_eq!(jwks.len(), 1);
                assert_eq!(jwks[0].version, 3);
            }
            other => panic!("expected ObservedJWKsUpdated, got {other:?}"),
        }
    }

    #[test]
    fn extract_gravity_events_accepts_oracle_delivered_from_native_oracle_only() {
        let event = OracleDelivered {
            sourceType: 3,
            sourceId: U256::from(4),
            nonce: 5,
            sourcePosition: 6,
            payloadHash: B256::from([0x77; 32]),
        };
        let forged_receipts =
            vec![receipt_with_log(Address::from([0x42; 20]), event.encode_log_data())];

        let events = extract_gravity_events_from_system_receipts(&forged_receipts, 10, 7);
        assert!(events.is_empty(), "forged OracleDelivered emitter must not produce GravityEvent");

        let valid_receipts = vec![receipt_with_log(NATIVE_ORACLE_ADDR, event.encode_log_data())];
        let events = extract_gravity_events_from_system_receipts(&valid_receipts, 10, 7);
        assert_eq!(events.len(), 1);
        match &events[0] {
            GravityEvent::ObservedJWKsUpdated(epoch, jwks) => {
                assert_eq!(*epoch, 7);
                assert_eq!(jwks.len(), 1);
                assert_eq!(jwks[0].version, 5);
            }
            other => panic!("expected ObservedJWKsUpdated, got {other:?}"),
        }
    }

    #[test]
    fn extract_gravity_events_ignores_dkg_start_from_wrong_emitter() {
        let event = DKGStartEvent {
            dealerEpoch: 9,
            startTimeUs: 123,
            metadata: DKGSessionMetadata {
                dealerEpoch: 9,
                randomnessConfig: RandomnessConfigData {
                    variant: ConfigVariant::Off,
                    configV2: ConfigV2Data {
                        secrecyThreshold: 0,
                        reconstructionThreshold: 0,
                        fastPathSecrecyThreshold: 0,
                    },
                },
                dealerValidatorSet: vec![],
                targetValidatorSet: vec![],
            },
        };
        let forged_receipts =
            vec![receipt_with_log(Address::from([0x24; 20]), event.encode_log_data())];

        let events = extract_gravity_events_from_system_receipts(&forged_receipts, 10, 7);
        assert!(events.is_empty(), "forged DKGStartEvent emitter must not produce GravityEvent");

        let valid_receipts = vec![receipt_with_log(DKG_ADDR, event.encode_log_data())];
        let events = extract_gravity_events_from_system_receipts(&valid_receipts, 10, 7);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], GravityEvent::DKG(_)));
    }
}

/// Metadata about an executed block
#[derive(Debug, Clone, Copy)]
pub struct ExecutedBlockMeta {
    /// Which ordered block is used to execute the block
    pub block_id: B256,
    /// Block hash of the executed block
    pub block_hash: B256,
    /// Block number of the executed block
    pub block_number: u64,
}

/// An ordered block received from Coordinator for execution
#[derive(Debug)]
pub struct OrderedBlock {
    /// Epoch of the block
    pub epoch: u64,
    /// `BlockId` of the parent block generated by Gravity SDK
    pub parent_id: B256,
    /// `BlockId` of the block generated by Gravity SDK
    pub id: B256,
    /// Block number of the block
    pub number: u64,
    /// Timestamp of the block in microseconds
    pub timestamp_us: u64,
    /// Coinbase address of the block
    pub coinbase: Address,
    /// Block header mix hash, used as prevRandao in the block
    pub prev_randao: B256,
    /// Withdrawals in the block, if any
    /// See <https://github.com/ethereum/execution-apis/blob/6709c2a795b707202e93c4f2867fa0bf2640a84f/src/engine/shanghai.md#executionpayloadv2>
    pub withdrawals: Withdrawals,
    /// Ordered transactions in the block
    pub transactions: Vec<TransactionSigned>,
    /// Senders of the transactions in the block
    pub senders: Vec<Address>,
    /// The proposer index in the active validator set (None for NIL blocks)
    pub proposer_index: Option<u64>,
    /// Failed Proposer indices
    pub failed_proposer_indices: Vec<u64>,
    /// Validator-related transactions (JWK updates and DKG transcripts) sent by system caller
    pub extra_data: Vec<ExtraDataType>,
    /// Randomness for the block, generated by DKG
    pub randomness: U256,
}

enum ReceivedBlock {
    /// Block received from Coordinator
    #[allow(clippy::large_enum_variant)]
    OrderedBlock(OrderedBlock),
    /// History block to be processed. Only used for testing.
    HistoryBlock(Box<RecoveredBlock<Block>>),
}

impl ReceivedBlock {
    fn id(&self) -> B256 {
        match self {
            Self::OrderedBlock(block) => block.id,
            Self::HistoryBlock(block) => block.hash(),
        }
    }

    fn parent_id(&self) -> B256 {
        match self {
            Self::OrderedBlock(block) => block.parent_id,
            Self::HistoryBlock(block) => block.parent_hash(),
        }
    }

    fn number(&self) -> u64 {
        match self {
            Self::OrderedBlock(block) => block.number,
            Self::HistoryBlock(block) => block.number(),
        }
    }

    fn epoch(&self) -> u64 {
        match self {
            Self::OrderedBlock(block) => block.epoch,
            Self::HistoryBlock(_) => 0,
        }
    }
}

/// Events emitted by the pipeline execution layer
#[derive(Debug)]
pub struct ExecutionArgs {
    /// The latest block number and its corresponding block id.
    pub block_number_to_block_id: BTreeMap<u64, B256>,
}

/// Owned by EL
#[derive(Debug)]
struct PipeExecService<Storage: GravityStorage> {
    /// Immutable part of the state
    core: Arc<Core<Storage>>,
    /// Receive ordered block from Coordinator
    ordered_block_rx: UnboundedReceiver<ReceivedBlock>,
    /// Receive the execution init args from `GravitySDK`
    execution_args_rx: oneshot::Receiver<ExecutionArgs>,
}

/// Information about a transaction in the executed block
#[derive(Debug, Clone)]
pub struct TxInfo {
    /// Transaction hash
    pub tx_hash: TxHash,
    /// Sender address of the transaction
    pub sender: Address,
    /// Nonce of the transaction
    pub nonce: u64,
    /// Whether the transaction is discarded due to validation failure
    pub is_discarded: bool,
}

/// Result of the executed block
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Block id of the executed block
    /// This is the block id generated by Gravity SDK
    pub block_id: B256,
    /// Block number of the executed block
    pub block_number: u64,
    /// Epoch of the executed block.
    pub epoch: u64,
    /// Block hash of the executed block
    /// This is the block hash generated by EL after execution and merklization
    pub block_hash: B256,
    /// Information about the transactions in the executed block
    pub txs_info: Vec<TxInfo>,
    /// Gravity events emitted by the executed block
    pub gravity_events: Vec<GravityEvent>,
}

#[derive(Debug, Clone)]
struct ExecuteBlockContext {
    parent_header: Header,
    prev_start_execute_time: Instant,
    epoch: u64,
}

#[derive(Debug)]
struct Core<Storage: GravityStorage> {
    /// Send executed block hash to Coordinator
    execution_result_tx: UnboundedSender<ExecutionResult>,
    /// Receive verified block hash from Coordinator
    verified_block_hash_rx: Arc<Channel<B256 /* block id */, Option<B256> /* block hash */>>,
    storage: Arc<Storage>,
    evm_config: EthEvmConfig,
    chain_spec: Arc<ChainSpec>,
    bls_pop_verify_precompile: DynParallelPrecompile,
    pre_alpha_precompiles: Arc<Vec<(Address, DynParallelPrecompile)>>,
    event_tx: std::sync::mpsc::Sender<PipeExecLayerEvent<EthPrimitives>>,
    execute_block_barrier: Channel<(u64, u64) /* epoch, block number */, ExecuteBlockContext>,
    merklize_barrier: Channel<u64 /* block number */, ()>,
    seal_barrier: Channel<u64 /* block number */, B256 /* block hash */>,
    make_canonical_barrier: Channel<u64 /* block number */, Instant>,
    discard_txs_tx: UnboundedSender<Vec<TxHash>>,
    cache: PersistBlockCache,
    // Ordering rationale: `Ordering::Release` (stores) / `Ordering::Acquire` (loads) is
    // sufficient — `SeqCst` is unnecessary. The `execute_block_barrier` Channel (backed by
    // `Mutex<Inner>`) enforces strict serial block execution: block N's `process()` cannot
    // proceed past `wait((epoch, N-1))` until block N-1 has completed and called
    // `notify((epoch, N-1), ...)`. Both stores sit inside this serialized critical section,
    // so there is only ever a single writer — no concurrent writer can interleave.
    //
    // The only concurrent readers are in the timeout branch below (`self.epoch()` /
    // `self.execute_height()`), which merely check for stale/duplicate blocks. Each
    // individual Acquire load sees the latest Release store (no staleness); the two
    // reads are simply not atomic *with respect to each other*, so at worst a concurrent
    // update between the two loads causes one extra wait-loop iteration, never an
    // incorrect discard. Note that even `SeqCst` would not help here — two separate
    // loads are never atomic as a pair regardless of ordering; only an `AtomicU128`
    // or a lock could provide an atomic snapshot, but neither is needed.
    epoch: AtomicU64,
    execute_height: AtomicU64,
    metrics: PipeExecLayerMetrics,
}

impl<Storage: GravityStorage> PipeExecService<Storage> {
    async fn run(mut self) {
        self.core.init_storage(self.execution_args_rx.await.unwrap());
        loop {
            let start_time = Instant::now();
            let block = match self.ordered_block_rx.recv().await {
                Some(block) => block,
                None => {
                    self.core.execute_block_barrier.close();
                    self.core.merklize_barrier.close();
                    self.core.make_canonical_barrier.close();
                    return;
                }
            };
            let elapsed = start_time.elapsed();
            self.core.metrics.recv_block_time_diff.record(elapsed);
            info!(target: "PipeExecService.run",
                id=?block.id(),
                parent_id=?block.parent_id(),
                number=?block.number(),
                epoch=?block.epoch(),
                elapsed=?elapsed,
                "new ordered block"
            );

            let core = self.core.clone();
            tokio::spawn(async move {
                let start_time = Instant::now();
                core.process(block).await;
                core.metrics.process_block_duration.record(start_time.elapsed());
            });
        }
    }
}

#[derive(Debug)]
struct ExecuteOrderedBlockResult {
    /// Block without roots and block hash
    block: Block,
    senders: Vec<Address>,
    execution_output: BlockExecutionOutput<Receipt>,
    txs_info: Vec<TxInfo>,
    gravity_events: Vec<GravityEvent>,
    epoch: u64,
}

/// Result of protocol system-transaction execution (metadata / DKG / JWK).
///
/// Epoch change returns unfinished protocol results so the caller can append
/// optional `TestnetOwnerFix` forced txs, then `take_bundle` and assemble.
enum SystemTxnExecutionOutcome {
    /// Normal execution completed, continue with user-tx processing
    Continue { metadata_result: Option<SystemTxnResult>, validator_results: Vec<SystemTxnResult> },
    /// NewEpoch emitted; user txs are discarded. Caller finalizes the block.
    EpochChanged { system_results: Vec<SystemTxnResult>, validators: Bytes },
}

// DESIGN: This validation is intentionally debug-only.
// These checks (gas overflow, gas accounting consistency, timestamp-unit sanity)
// detect logic bugs during development and testing. They are not needed in
// production and use `panic!` which is inappropriate for release builds.
#[cfg(debug_assertions)]
fn validate_execution_output(
    block: &Block,
    execution_output: &BlockExecutionOutput<Receipt>,
) -> Result<(), String> {
    if block.gas_limit() < block.gas_used() {
        return Err(format!("gas_limit({}) < gas_used({})", block.gas_limit(), block.gas_used()));
    }
    let expected_gas_used =
        execution_output.receipts.last().map(|r| r.cumulative_gas_used).unwrap_or(0);
    if block.gas_used() != expected_gas_used {
        return Err(format!(
            "block gas_used({}) != last receipt cumulative_gas_used({})",
            block.gas_used(),
            expected_gas_used
        ));
    }
    if execution_output.gas_used != block.gas_used {
        return Err(format!(
            "execution_output.gas_used({}) != block.gas_used({})",
            execution_output.gas_used, block.gas_used
        ));
    }
    let now_secs =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    if block.timestamp() > now_secs * 2 {
        return Err(format!(
            "block timestamp({}) is not in seconds, likely in milliseconds or microseconds",
            block.timestamp()
        ));
    }
    Ok(())
}

impl<Storage: GravityStorage> Core<Storage> {
    fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    fn execute_height(&self) -> u64 {
        self.execute_height.load(Ordering::Acquire)
    }

    fn custom_precompiles_for_ordered_block(
        &self,
        ordered_block: &OrderedBlock,
        parent_header: &Header,
    ) -> Arc<Vec<(Address, DynParallelPrecompile)>> {
        let block_number = ordered_block.number;
        let block_timestamp = ordered_block.timestamp_us / 1_000_000;
        if !self
            .chain_spec
            .gravity_hardforks()
            .is_fork_active_at_timestamp(GravityHardfork::Alpha, block_timestamp)
        {
            return self.pre_alpha_precompiles.clone()
        }

        let canonical_provider = GravityStorageRandomnessProvider::new(self.storage.clone());
        let gas_policy =
            randomness_by_height_gas_policy_at_block(self.chain_spec.as_ref(), block_number);
        let execution_provider = Arc::new(ExecutionRandomnessProvider::new_with_gas_policy(
            canonical_provider,
            block_number,
            ordered_block.prev_randao,
            parent_header.number,
            parent_header.mix_hash(),
            gas_policy,
        ));

        Arc::new(vec![
            (BLS_PRECOMPILE_ADDR, self.bls_pop_verify_precompile.clone()),
            (
                RANDOMNESS_BY_HEIGHT_PRECOMPILE_ADDR,
                custom_precompiles::create_randomness_by_height_precompile(execution_provider),
            ),
        ])
    }

    /// DESIGN: All `.unwrap()` calls on barrier wait/notify, state root, and
    /// `verify_executed_block_hash` in this function are intentional. In the gravity-sdk
    /// integration the panic handler is configured to abort the process (via
    /// `std::process::exit`), so a panic terminates the entire node rather than
    /// silently killing a single tokio task. Downstream barrier deadlocks therefore
    /// cannot occur, and a full process restart is the correct recovery strategy.
    async fn process(&self, block: ReceivedBlock) {
        // Wait until there's no large gap between cache and db
        let block_number = block.number();
        let block_id = block.id();
        let (randomness, block_epoch) = if let ReceivedBlock::OrderedBlock(ordered_block) = &block {
            (ordered_block.randomness, ordered_block.epoch)
        } else {
            (U256::ZERO, self.epoch())
        };
        self.metrics.start_process_block_number.set(block_number as f64);

        // Retrieve the parent block header to generate the necessary configs for
        // executing the current block
        let ExecuteBlockContext { parent_header, prev_start_execute_time, epoch } = loop {
            info!(
                "Wait execute_block_barrier {} => ({}, {})",
                block_number,
                block_epoch,
                block_number - 1
            );
            match self
                .execute_block_barrier
                .wait_timeout((block_epoch, block_number - 1), Duration::from_secs(2))
                .await
            {
                Some(parent) => break parent,
                // Make sure the ordered blocks are idempotent.
                // NOTE: Each Acquire load below sees the latest Release
                // store to its respective atomic. The two reads are not mutually
                // atomic, but a concurrent update between them at worst causes one
                // extra wait-loop iteration, never an incorrect discard.
                None => {
                    if block_epoch < self.epoch() || block_number <= self.execute_height() {
                        warn!(target: "PipeExecService.process",
                            block_number=?block_number,
                            block_id=?block_id,
                            block_epoch=?block_epoch,
                            current_epoch=?self.epoch(),
                            execute_height=?self.execute_height(),
                            "epoch or execute height mismatch"
                        );
                        return;
                    } else {
                        warn!(target: "PipeExecService.process",
                            block_number=?block_number,
                            block_id=?block_id,
                            block_epoch=?block_epoch,
                            "timeout(2s) wait for execute_block_barrier"
                        );
                    }
                }
            }
        };
        if let ReceivedBlock::OrderedBlock(ordered_block) = &block {
            assert!(ordered_block.epoch == epoch);
        }
        self.storage.insert_block_id(block_number, block_id);

        // Give transient disk stalls time to recover without waiting long enough to make the
        // consensus layer time out.
        self.cache.wait_persist_gap(Some(2000));
        let start_time = Instant::now();
        let ExecuteOrderedBlockResult {
            mut block,
            senders,
            execution_output,
            txs_info,
            gravity_events,
            epoch,
        } = match block {
            ReceivedBlock::OrderedBlock(ordered_block) => {
                self.execute_ordered_block(ordered_block, &parent_header)
            }
            ReceivedBlock::HistoryBlock(recovered_block) => {
                self.execute_history_block(*recovered_block)
            }
        };

        #[cfg(debug_assertions)]
        validate_execution_output(&block, &execution_output).unwrap_or_else(|e| {
            panic!("validate_execution_output failed. error: {e:?}\n{:?}", block.header());
        });

        let write_start = Instant::now();
        self.cache.write_state_changes(
            block_number,
            OriginalValuesKnown::No,
            &execution_output.state.state,
            &execution_output.state.contracts,
        );
        let hashed_state =
            HashedPostState::from_bundle_state::<KeccakKeyHasher>(&execution_output.state.state);
        self.metrics.cache_account_state.record(write_start.elapsed());
        let elapsed = start_time.elapsed();
        info!(target: "PipeExecService.process",
            block_number=?block_number,
            block_id=?block_id,
            gas_used=execution_output.gas_used,
            elapsed=?elapsed,
            epoch=?epoch,
            "block executed"
        );
        self.metrics.execute_duration.record(elapsed);
        self.metrics.start_execute_time_diff.record(start_time - prev_start_execute_time);

        if epoch > block_epoch {
            info!(target: "PipeExecService.process",
                block_number=?block_number,
                block_id=?block_id,
                prev_epoch=?block_epoch,
                new_epoch=?epoch,
                "new epoch"
            );
            // SAFETY: Release ordering is sufficient here — see comment on field
            // declarations.
            assert_eq!(self.epoch.fetch_max(epoch, Ordering::Release), block_epoch);
        }
        // SAFETY: Release ordering is sufficient — the execute_block_barrier
        // serializes writers; only the timeout branch reads these concurrently (harmlessly).
        assert_eq!(self.execute_height.fetch_add(1, Ordering::Release), block_number - 1);
        self.execute_block_barrier
            .notify(
                (epoch, block_number),
                ExecuteBlockContext {
                    parent_header: block.header.clone(),
                    prev_start_execute_time: start_time,
                    epoch,
                },
            )
            .unwrap();

        let execution_outcome = self.calculate_roots(&mut block, execution_output);

        // Merkling the state trie
        self.merklize_barrier.wait(block_number - 1).await.unwrap();
        let start_time = Instant::now();
        let (state_root, trie_updates) = self.storage.state_root(&hashed_state).unwrap();
        let write_start = Instant::now();
        self.cache.write_trie_updates(&trie_updates, block_number);
        self.metrics.cache_trie_state.record(write_start.elapsed());
        let elapsed = start_time.elapsed();
        self.metrics.merklize_duration.record(elapsed);
        self.merklize_barrier.notify(block_number, ()).unwrap();
        info!(target: "PipeExecService.process",
            block_number=?block_number,
            block_id=?block_id,
            state_root=?state_root,
            elapsed=?elapsed,
            "state trie merklized"
        );
        block.header.state_root = state_root;
        if !self
            .chain_spec
            .gravity_hardforks()
            .is_fork_active_at_timestamp(GravityHardfork::Alpha, block.header.timestamp)
        {
            block.header.difficulty = randomness;
        }

        // Seal the block
        let parent_hash = self.seal_barrier.wait(block_number - 1).await.unwrap();
        let start_time = Instant::now();
        block.header.parent_hash = parent_hash;
        let sealed_block = block.seal_slow();
        let block_hash = sealed_block.hash();
        self.metrics.seal_duration.record(start_time.elapsed());
        self.seal_barrier.notify(block_number, block_hash).unwrap();
        debug!(target: "PipeExecService.process",
            block_number=?block_number,
            block_id=?block_id,
            block_hash=?block_hash,
            header=?sealed_block.header(),
            "block sealed"
        );

        let gas_used = sealed_block.gas_used;
        let executed_block = ExecutedBlockWithTrieUpdates::new(
            Arc::new(RecoveredBlock::new_sealed(sealed_block, senders)),
            Arc::new(execution_outcome),
            Arc::new(hashed_state),
            ExecutedTrieUpdates::empty(),
            Arc::new(trie_updates),
        );
        let execution_result =
            ExecutionResult { block_id, block_number, epoch, block_hash, txs_info, gravity_events };

        self.verify_executed_block_hash(execution_result).await.unwrap();
        self.make_canonical(&block_id, executed_block).await;
        self.metrics.total_gas_used.increment(gas_used);
        self.metrics.end_process_block_number.set(block_number as f64);
    }

    /// Push executed block hash to Coordinator and wait for verification result from Coordinator.
    /// Returns `None` if the channel has been closed.
    async fn verify_executed_block_hash(&self, execution_result: ExecutionResult) -> Option<()> {
        let start_time = Instant::now();
        let block_id = execution_result.block_id;
        let block_number = execution_result.block_number;
        let executed_block_hash = execution_result.block_hash;
        self.execution_result_tx.send(execution_result).ok()?;
        let block_hash = self.verified_block_hash_rx.wait(block_id).await?;
        match block_hash {
            Some(verified_hash) => {
                assert_eq!(executed_block_hash, verified_hash, "Block hash mismatch");
            }
            None => {
                // EXPECTED: commit_ledger() batches multiple blocks but LedgerInfo
                // only carries the tip block's hash, so non-tip blocks arrive with
                // None. Safe because every block is fully executed/merklized/sealed
                // and the tip hash transitively validates the batch via parent_hash.
                info!(
                    target: "PipeExecService.process",
                    block_number = ?block_number,
                    block_id = ?block_id,
                    block_hash = ?executed_block_hash,
                    "consensus did not provide a verification hash for this block"
                );
            }
        }
        let elapsed = start_time.elapsed();
        self.metrics.verify_duration.record(elapsed);
        info!(target: "PipeExecService.process",
            block_number=?block_number,
            block_id=?block_id,
            block_hash=?executed_block_hash,
            elapsed=?elapsed,
            "block verified"
        );
        Some(())
    }

    fn create_block_for_executor(
        &self,
        ordered_block: OrderedBlock,
        base_fee: u64,
        state: &Storage::StateView,
        mut validator_txns: Vec<TransactionSigned>,
        // System-txn gas already consumed before this block runs; subtracted from the user
        // filter budget so `header.gas_used` stays `≤ header.gas_limit` after metadata +
        // validator receipts are appended. Closes gravity-audit#621.
        sum_system_gas: u64,
    ) -> (RecoveredBlock<Block>, Vec<TxInfo>) {
        assert_eq!(ordered_block.transactions.len(), ordered_block.senders.len());
        let mut block = Block {
            header: Header {
                // Transient carrier: feeds parent_id to the upstream EIP-2935 SystemCaller
                // as the blockhash-contract calldata. Overwritten with the real chain
                // parent hash by the seal step below before sealing.
                parent_hash: ordered_block.parent_id,
                beneficiary: ordered_block.coinbase,
                timestamp: ordered_block.timestamp_us / 1_000_000, // convert to seconds
                mix_hash: ordered_block.prev_randao,
                base_fee_per_gas: Some(base_fee),
                number: ordered_block.number,
                gas_limit: PIPE_BLOCK_GAS_LIMIT,
                ommers_hash: EMPTY_OMMER_ROOT_HASH,
                nonce: BEACON_NONCE.into(),
                ..Default::default()
            },
            body: BlockBody::default(),
        };
        debug!(target: "create_block_for_executor",
            header=?block.header,
            "created block"
        );

        if self.chain_spec.is_shanghai_active_at_timestamp(block.timestamp) {
            if ordered_block.withdrawals.is_empty() {
                block.header.withdrawals_root = Some(EMPTY_WITHDRAWALS);
                block.body.withdrawals = Some(Withdrawals::default());
            } else {
                block.header.withdrawals_root =
                    Some(proofs::calculate_withdrawals_root(&ordered_block.withdrawals));
                block.body.withdrawals = Some(ordered_block.withdrawals);
            }
        }

        // only determine cancun fields when active
        if self.chain_spec.is_cancun_active_at_timestamp(block.timestamp) {
            // FIXME: Is it OK to use the parent's block id as `parent_beacon_block_root` before
            // execution?
            block.header.parent_beacon_block_root = Some(ordered_block.parent_id);

            // TODO(nekomoto): fill `excess_blob_gas` and `blob_gas_used` fields
            block.header.excess_blob_gas = Some(0);
            block.header.blob_gas_used = Some(0);
        }

        // Discard the invalid txs.
        // `saturating_sub`: a byzantine proposer (or a future system-txn addition that
        // overshoots) yields budget=0, dropping every user tx — the only safe fallback
        // when `sum_system_gas ≥ block.gas_limit`.
        let user_gas_budget = block.gas_limit.saturating_sub(sum_system_gas);
        let start_time = Instant::now();
        let (txs, senders, txs_info) = self.filter_invalid_txs(
            state,
            ordered_block.transactions,
            ordered_block.senders,
            base_fee,
            user_gas_budget,
            block.timestamp,
            block.number,
        );
        self.metrics.filter_transaction_duration.record(start_time.elapsed());
        let (txs, senders) = if !validator_txns.is_empty() {
            let mut address = vec![SYSTEM_CALLER; validator_txns.len()];
            address.extend(senders);
            validator_txns.extend(txs);
            (validator_txns, address)
        } else {
            (txs, senders)
        };

        block.body.transactions = txs;
        (RecoveredBlock::new_unhashed(block, senders), txs_info)
    }

    /// Execute protocol system transactions (metadata, DKG, JWK) sequentially.
    ///
    /// Does not run `TestnetOwnerFix` and does not assemble the final block —
    /// the caller owns that single seam after this returns.
    ///
    /// Returns `SystemTxnExecutionOutcome::EpochChanged` if a new epoch was triggered,
    /// otherwise returns `SystemTxnExecutionOutcome::Continue` with the results.
    ///
    /// DESIGN: system transaction failures must not prevent user transaction execution.
    /// EVM-level revert/halt results are kept as failed receipts in the block. Rust-level
    /// execution errors do not produce a valid receipt, so they are logged and the offending
    /// system transaction is skipped.
    ///
    /// `system_tx_gas_price` is computed once by the caller (Alpha gas-exempt → 0).
    fn execute_system_transactions(
        executor: &mut dyn ParallelExecutor<
            Primitives = EthPrimitives,
            Error = BlockExecutionError,
        >,
        evm_env: reth_evm::EvmEnv,
        ordered_block: &OrderedBlock,
        epoch: u64,
        block_id: B256,
        parent_id: B256,
        block_number: u64,
        initial_nonce: u64,
        is_alpha_active: bool,
        system_tx_gas_price: u128,
    ) -> SystemTxnExecutionOutcome {
        let mint_precompile = create_mint_token_precompile();
        let bls_precompile = create_bls_pop_verify_precompile();
        let system_precompiles: Vec<(Address, DynPrecompile)> = vec![
            (NATIVE_MINT_PRECOMPILE_ADDR, mint_precompile),
            (BLS_PRECOMPILE_ADDR, bls_precompile),
        ];

        let mut current_nonce = initial_nonce;
        // -----------------------------------------------------------------------
        // Metadata transaction (onBlockStart)
        // -----------------------------------------------------------------------
        let metadata_txn = construct_metadata_txn(
            current_nonce,
            system_tx_gas_price,
            ordered_block.timestamp_us,
            ordered_block.proposer_index,
            &ordered_block.failed_proposer_indices,
        );

        let metadata_tx_env =
            Recovered::new_unchecked(metadata_txn.clone(), SYSTEM_CALLER).into_tx_env();
        let metadata_txn_result = match executor.transact_system_txn(
            evm_env.clone(),
            system_precompiles.clone(),
            metadata_tx_env,
        ) {
            Ok(metadata_execution_result) => {
                current_nonce = metadata_txn.nonce() + 1;
                Some(SystemTxnResult {
                    result: metadata_execution_result,
                    txn: metadata_txn,
                    sender: SYSTEM_CALLER,
                })
            }
            Err(error) => {
                if !is_alpha_active {
                    panic!("metadata txn execution failed: {error:?}");
                }
                error!(target: "execute_ordered_block",
                    block_number=?block_number,
                    error=?error,
                    "metadata system transaction execution failed, skipping"
                );
                None
            }
        };

        // Check for epoch change from metadata txn
        if let Some((new_epoch, validators)) =
            metadata_txn_result.as_ref().and_then(SystemTxnResult::emit_new_epoch)
        {
            assert_eq!(new_epoch, epoch + 1);
            info!(target: "execute_ordered_block",
                id=?block_id,
                parent_id=?parent_id,
                number=?block_number,
                new_epoch=?new_epoch,
                "emit new epoch, discard the block"
            );
            // merge_transitions was already called inside transact_system_txn;
            // caller appends optional TestnetOwnerFix, then take_bundle + assemble.
            return SystemTxnExecutionOutcome::EpochChanged {
                system_results: vec![
                    metadata_txn_result.expect("metadata result exists when it emits NewEpoch")
                ],
                validators,
            };
        }

        if let Some(metadata_txn_result) = metadata_txn_result.as_ref() {
            if !metadata_txn_result.result.is_success() {
                error!(target: "execute_ordered_block",
                    block_number=?block_number,
                    gas_used=?metadata_txn_result.result.gas_used(),
                    output=?metadata_txn_result.result.output(),
                    "metadata system transaction reverted"
                );
            }

            debug!(target: "execute_ordered_block",
                metadata_txn_result=?metadata_txn_result,
                "metadata transaction result"
            );
        }

        // -----------------------------------------------------------------------
        // Validator transactions (DKG and JWK) — sorted: DKG first, JWK second
        // -----------------------------------------------------------------------
        let mut validator_txn_results: Vec<SystemTxnResult> = Vec::new();

        let mut sorted_extra_data: Vec<_> = ordered_block.extra_data.iter().collect();
        sorted_extra_data.sort_by_key(|data| match data {
            ExtraDataType::DKG(_) => 0,
            ExtraDataType::JWK(_) => 1,
        });

        for (index, extra_data) in sorted_extra_data.iter().enumerate() {
            let is_dkg = matches!(extra_data, ExtraDataType::DKG(_));
            let txn = match construct_validator_txn_from_extra_data(
                extra_data,
                current_nonce,
                system_tx_gas_price,
                is_alpha_active,
            ) {
                Ok(txn) => txn,
                Err(e) => {
                    error!(target: "execute_ordered_block",
                        index=?index,
                        is_dkg=?is_dkg,
                        block_number=?block_number,
                        error=?e,
                        "Failed to construct validator transaction, skipping"
                    );
                    continue;
                }
            };

            debug!(target: "execute_ordered_block",
                index=?index,
                nonce=?current_nonce,
                is_dkg=?is_dkg,
                block_number=?block_number,
                "executing validator transaction one by one"
            );

            let tx_env = Recovered::new_unchecked(txn.clone(), SYSTEM_CALLER).into_tx_env();
            let execution_result = match executor.transact_system_txn(
                evm_env.clone(),
                system_precompiles.clone(),
                tx_env,
            ) {
                Ok(execution_result) => execution_result,
                Err(error) => {
                    if !is_alpha_active {
                        panic!("validator txn execution failed: {error:?}");
                    }
                    error!(target: "execute_ordered_block",
                        index=?index,
                        is_dkg=?is_dkg,
                        block_number=?block_number,
                        error=?error,
                        "validator system transaction execution failed, skipping"
                    );
                    continue;
                }
            };

            current_nonce += 1;
            let validator_result =
                SystemTxnResult { result: execution_result, txn, sender: SYSTEM_CALLER };

            if !validator_result.result.is_success() {
                error!(target: "execute_ordered_block",
                    index=?index,
                    is_dkg=?is_dkg,
                    block_number=?block_number,
                    gas_used=?validator_result.result.gas_used(),
                    output=?validator_result.result.output(),
                    "validator system transaction reverted"
                );
            } else {
                // DKG transactions may trigger epoch change
                if is_dkg {
                    if let Some((new_epoch, validators)) = validator_result.emit_new_epoch() {
                        assert_eq!(new_epoch, epoch + 1);
                        info!(target: "execute_ordered_block",
                            id=?block_id,
                            parent_id=?parent_id,
                            number=?block_number,
                            new_epoch=?new_epoch,
                            "DKG triggered new epoch, discard the block"
                        );
                        // Pre-Alpha epoch-change assembly only keeps the DKG
                        // validator txn (historical behavior). Caller still runs
                        // the TestnetOwnerFix seam; gate no-ops off Longevity /
                        // non-crossing blocks.
                        if !is_alpha_active {
                            return SystemTxnExecutionOutcome::EpochChanged {
                                system_results: vec![validator_result],
                                validators,
                            };
                        }
                        let mut epoch_change_results = Vec::with_capacity(
                            usize::from(metadata_txn_result.is_some()) +
                                validator_txn_results.len() +
                                1,
                        );
                        if let Some(metadata_txn_result) = metadata_txn_result {
                            epoch_change_results.push(metadata_txn_result);
                        }
                        epoch_change_results.extend(validator_txn_results);
                        epoch_change_results.push(validator_result);
                        return SystemTxnExecutionOutcome::EpochChanged {
                            system_results: epoch_change_results,
                            validators,
                        };
                    }
                }

                info!(target: "execute_ordered_block",
                    index=?index,
                    is_dkg=?is_dkg,
                    gas_used=?validator_result.result.gas_used(),
                    block_number=?block_number,
                    "validator transaction executed successfully"
                );
            }

            validator_txn_results.push(validator_result);
        }

        SystemTxnExecutionOutcome::Continue {
            metadata_result: metadata_txn_result,
            validator_results: validator_txn_results,
        }
    }

    /// Extract gravity events from execution receipts
    /// Returns gravity_events containing DKG events and ObservedJWKsUpdated from system-contract
    /// receipts. Emitter addresses are checked here so the function remains safe even if its
    /// caller's receipt slice changes.
    fn extract_gravity_events_from_receipts(
        &self,
        receipts: &[Receipt],
        block_number: u64,
        epoch: u64,
    ) -> Vec<GravityEvent> {
        extract_gravity_events_from_system_receipts(receipts, block_number, epoch)
    }

    fn execute_ordered_block(
        &self,
        ordered_block: OrderedBlock,
        parent_header: &Header,
    ) -> ExecuteOrderedBlockResult {
        let block_id = ordered_block.id;
        let parent_id = ordered_block.parent_id;
        let block_number = ordered_block.number;
        assert_eq!(block_number, parent_header.number + 1);
        let epoch = ordered_block.epoch;

        let state = self.storage.get_state_view().unwrap();

        let evm_env = self
            .evm_config
            .next_evm_env(
                parent_header,
                &NextBlockEnvAttributes {
                    timestamp: ordered_block.timestamp_us / 1_000_000, // convert to seconds
                    suggested_fee_recipient: ordered_block.coinbase,
                    prev_randao: ordered_block.prev_randao,
                    gas_limit: PIPE_BLOCK_GAS_LIMIT,
                    parent_beacon_block_root: Some(ordered_block.parent_id),
                    withdrawals: Some(ordered_block.withdrawals.clone()),
                    // `next_evm_env` only reads env-relevant fields; gravity assembles its own
                    // headers in the pipeline, so extra_data here is inert. slot_number is
                    // post-Amsterdam (gravity does not activate Amsterdam).
                    extra_data: Default::default(),
                    slot_number: None,
                },
            )
            .unwrap();
        debug!(target: "execute_ordered_block",
            evm_env=?evm_env,
            block_number=?block_number,
        );
        let base_fee = evm_env.block_env.basefee;

        // Read SYSTEM_CALLER nonce from state BEFORE moving state into executor.
        // ParallelDatabase (Storage::StateView) implements DatabaseRef, so we can read directly.
        // The Alpha balance migration below reads SYSTEM_CALLER independently via the
        // executor's own `basic` accessor (see `system_caller_migration`), so this read
        // only serves `execute_system_transactions` nonce sequencing.
        let initial_nonce = state
            .basic_ref(SYSTEM_CALLER)
            .expect("failed to read SYSTEM_CALLER account from state")
            .map(|a| a.nonce)
            .unwrap_or(0);

        // Create executor with state. System transactions will commit directly to its
        // ParallelState, so there is a single source of truth for both system and user txns.
        let mut executor = self
            .evm_config
            .parallel_executor_with_delegated_safety(state, DelegatedSafetyConfig::enabled());
        executor.apply_custom_precompiles(
            self.custom_precompiles_for_ordered_block(&ordered_block, parent_header),
        );

        // EIP-2935 (Prague) boundary state change: deploy `HISTORY_STORAGE_ADDRESS`
        // on the Prague activation block. Idempotency is gated by
        // `transitions_at_timestamp(current_ts, parent_ts)` — see `eip_2935` for the
        // full rationale.
        eip_2935::apply_state_changes_for_block(
            &mut *executor,
            &self.chain_spec,
            ordered_block.timestamp_us / 1_000_000,
            parent_header.timestamp,
            block_number,
        );

        let is_alpha_active = self.chain_spec.gravity_hardforks().is_fork_active_at_timestamp(
            GravityHardfork::Alpha,
            ordered_block.timestamp_us / 1_000_000,
        );

        // Gravity Alpha (system-tx gas-exempt) boundary state change: zero
        // `SYSTEM_CALLER.balance` once, on the Alpha activation block. Runs
        // BEFORE system transactions in the same block so the post-execution
        // bundle reflects the zero balance — preserving nonce and code keeps
        // the account non-empty under EIP-161 (design §3.3, R5).
        system_caller_migration::apply_state_changes_for_block(
            &mut *executor,
            &self.chain_spec,
            ordered_block.timestamp_us / 1_000_000,
            parent_header.timestamp,
            block_number,
        );

        // Gravity Alpha hardfork: gas-exempt system transactions (L2 —
        // construction side). Computed once for protocol system txs and
        // optional TestnetOwnerFix. See system-tx gas-exempt design §3.2.
        let block_ts = ordered_block.timestamp_us / 1_000_000;
        let parent_timestamp = parent_header.timestamp;
        let system_tx_gas_price: u128 =
            if reth_chainspec::is_system_tx_gas_exempt(self.chain_spec.as_ref(), block_ts) {
                0
            } else {
                base_fee as u128
            };

        // Protocol system txs (metadata, DKG, JWK). State commits into ParallelState.
        let system_outcome = Self::execute_system_transactions(
            &mut *executor,
            evm_env.clone(),
            &ordered_block,
            epoch,
            block_id,
            parent_id,
            block_number,
            initial_nonce,
            is_alpha_active,
            system_tx_gas_price,
        );

        // Single TestnetOwnerFix seam: after protocol system txs, before user
        // txs / epoch-block assembly. Longevity-only one-shot via
        // transitions_at_timestamp; forced-tx revert → panic inside the helper.
        let fix_owner_results = testnet_owner_fix::execute_forced_transfers(
            &mut *executor,
            self.chain_spec.as_ref(),
            evm_env,
            system_tx_gas_price,
            block_number,
            block_ts,
            parent_timestamp,
        );

        let (metadata_txn_result, validator_txn_results) = match system_outcome {
            SystemTxnExecutionOutcome::EpochChanged { mut system_results, validators } => {
                system_results.extend(fix_owner_results);
                let bundle = executor.take_bundle();
                return system_txns_into_executed_ordered_block_result(
                    system_results,
                    self.chain_spec.as_ref(),
                    &ordered_block,
                    base_fee,
                    bundle,
                    validators,
                );
            }
            SystemTxnExecutionOutcome::Continue { metadata_result, validator_results } => {
                (metadata_result, validator_results)
            }
        };

        // DESIGN: `filter_invalid_txs` reads from storage, not the executor's in-memory
        // ParallelState cache, so it sees the pre-system-transaction state. This means that if
        // a system transaction (e.g. mint precompile) credits an EOA, a user transaction from
        // that EOA depending on the newly minted balance will be filtered out as invalid in this
        // block and must be resubmitted in the next block.
        //
        // This is an intentional, accepted trade-off:
        //   1. System txn sender is always SYSTEM_CALLER, so user nonces are never affected.
        //   2. Only balance changes from mint are relevant; the one-block delay is negligible for
        //      reward-style minting and users do not rely on same-block spending.
        //   3. Discarded transactions are sent to `discard_txs_tx` for pool cleanup.
        //
        // If same-block spending of minted balance is ever required, the fix is:
        //   - Add a `basic_ref(&self, Address) -> Option<AccountInfo>` method to the
        //     `ParallelExecutor` trait.
        //   - Before calling `filter_invalid_txs`, query each sender's account via
        //     `executor.basic_ref(sender)` and collect overrides into a HashMap.
        // Pre-execution system-txn gas is now known and exact (these txns already ran
        // against the executor). Pass it down so the user-tx filter reserves the same
        // amount, keeping `header.gas_used ≤ header.gas_limit` once metadata + validator
        // receipts get appended below. Closes gravity-audit#621.
        let sum_system_gas = metadata_txn_result.as_ref().map_or(0, |r| r.result.gas_used()) +
            validator_txn_results.iter().map(|r| r.result.gas_used()).sum::<u64>() +
            fix_owner_results.iter().map(|r| r.result.gas_used()).sum::<u64>();
        let state_for_block = self.storage.get_state_view().unwrap();
        let (block, txs_info) = self.create_block_for_executor(
            ordered_block,
            base_fee,
            &state_for_block,
            vec![],
            sum_system_gas,
        );

        info!(target: "execute_ordered_block",
            id=?block_id,
            parent_id=?parent_id,
            number=?block_number,
            num_txs=?block.transaction_count(),
            validator_txn_count=?validator_txn_results.len(),
            "ready to execute block"
        );

        let outcome = executor.execute(&block).unwrap_or_else(|err| {
            serde_json::to_writer_pretty(
                std::io::BufWriter::new(std::fs::File::create(format!("{block_id}.json")).unwrap()),
                &block,
            )
            .unwrap();
            panic!("failed to execute block {block_id:?}: {err:?}")
        });
        info!(target: "execute_ordered_block",
            id=?block_id,
            parent_id=?parent_id,
            number=?block_number,
            receipts_len=?outcome.receipts.len(),
            "executed block done"
        );

        let (mut block, senders) = block.split();
        block.header.gas_used = outcome.gas_used;
        let mut result = ExecuteOrderedBlockResult {
            block,
            senders,
            execution_output: outcome,
            txs_info,
            gravity_events: vec![],
            epoch,
        };
        let has_metadata_result = metadata_txn_result.is_some();
        // Gravity events are mined from SYSTEM_CALLER protocol txs only (metadata +
        // validator). FixOwner forced txs sit after that prefix and must not be
        // scanned for NewEpoch / DKG / JWK events.
        let n_protocol_system_receipts =
            usize::from(has_metadata_result) + validator_txn_results.len();
        if let Some(metadata_txn_result) = metadata_txn_result {
            metadata_txn_result.insert_to_executed_ordered_block_result(&mut result, 0);
        }
        // Insert validator transaction results one by one after the metadata transaction,
        // or at the front if the metadata transaction failed before producing a receipt.
        for (index, validator_result) in validator_txn_results.into_iter().enumerate() {
            let insert_position = usize::from(has_metadata_result) + index;
            validator_result.insert_to_executed_ordered_block_result(&mut result, insert_position);
        }
        // TestnetOwnerFix forced transfers: after SYSTEM_CALLER prefix, before user txs.
        // Preserves `system_txs_form_head_prefix` (FixOwner senders are not SYSTEM_CALLER).
        for (index, fix_result) in fix_owner_results.into_iter().enumerate() {
            let insert_position = n_protocol_system_receipts + index;
            fix_result.insert_to_executed_ordered_block_result(&mut result, insert_position);
        }
        debug!(target: "execute_ordered_block",
            number=?result.block.number,
            receipts_len=?result.execution_output.receipts.len(),
            protocol_system_receipts=?n_protocol_system_receipts,
            "insert metadata, validator, and TestnetOwnerFix transaction results"
        );
        // Only extract gravity events from protocol system transaction receipts.
        let gravity_events = self.extract_gravity_events_from_receipts(
            &result.execution_output.receipts[..n_protocol_system_receipts],
            result.block.number,
            epoch,
        );

        result.gravity_events.extend(gravity_events);
        result
    }

    /// Only used for testing.
    fn execute_history_block(&self, block: RecoveredBlock<Block>) -> ExecuteOrderedBlockResult {
        let state = self.storage.get_state_view().unwrap();
        let mut executor = self.evm_config.parallel_executor(state);
        let outcome = executor.execute(&block).unwrap_or_else(|err| {
            serde_json::to_writer(
                std::io::BufWriter::new(
                    std::fs::File::create(format!("{}.json", block.number)).unwrap(),
                ),
                &block,
            )
            .unwrap();
            panic!("failed to execute block {:?}: {:?}", block.number, err)
        });
        let (block, senders) = block.split();
        ExecuteOrderedBlockResult {
            block,
            senders,
            execution_output: outcome,
            txs_info: vec![],
            gravity_events: vec![],
            epoch: 0,
        }
    }

    /// Calculate the receipts root, logs bloom, and transactions root, etc. and fill them into the
    /// block header.
    fn calculate_roots(
        &self,
        block: &mut Block,
        execution_output: BlockExecutionOutput<Receipt>,
    ) -> ExecutionOutcome {
        // only determine cancun fields when active
        if self.chain_spec.is_prague_active_at_timestamp(block.timestamp) {
            block.header.requests_hash = Some(execution_output.requests.requests_hash());
        }

        let execution_outcome = ExecutionOutcome::new(
            execution_output.state,
            vec![execution_output.result.receipts],
            block.number,
            vec![execution_output.result.requests],
        );

        // Fill the block header with the calculated values
        block.header.transactions_root =
            proofs::calculate_transaction_root(&block.body.transactions);
        if self.chain_spec.is_byzantium_active_at_block(block.number()) {
            block.header.receipts_root =
                execution_outcome.ethereum_receipts_root(block.number).unwrap();
            block.header.logs_bloom = execution_outcome.block_logs_bloom(block.number).unwrap();
        }

        execution_outcome
    }

    /// DESIGN: The three operations here — (1) engine tree `MakeCanonical`
    /// event (updates in-memory `TreeState`), (2) `storage.update_canonical`
    /// (reclaims in-memory caches), and (3) `advance_persistence` (writes to
    /// reth DB, triggered later in the engine tree event loop) — are **all
    /// in-memory** except for (3). `GravityStorage` performs no disk I/O, so on
    /// crash and restart the reth DB is the sole source of truth. There is no
    /// "split-brain" risk between `GravityStorage` and the reth DB because
    /// `GravityStorage` state does not survive a restart.
    async fn make_canonical(&self, block_id: &B256, executed_block: ExecutedBlockWithTrieUpdates) {
        let block_number = executed_block.recovered_block.number();
        let block_hash = executed_block.recovered_block.hash();
        let prev_finish_commit_time =
            self.make_canonical_barrier.wait(block_number - 1).await.unwrap();
        let start_time = Instant::now();
        let (tx, rx) = oneshot::channel();
        self.event_tx
            .send(PipeExecLayerEvent::MakeCanonical(MakeCanonicalEvent { executed_block, tx }))
            .unwrap();
        rx.await.unwrap();
        self.storage.update_canonical(block_number, block_hash);
        let elapsed = start_time.elapsed();
        info!(target: "PipeExecService.process",
            block_number=?block_number,
            block_id=?block_id,
            block_hash=?block_hash,
            elapsed=?elapsed,
            "block made canonical"
        );
        let finish_commit_time = Instant::now();
        self.metrics.make_canonical_duration.record(elapsed);
        self.metrics.finish_commit_time_diff.record(finish_commit_time - prev_finish_commit_time);
        self.make_canonical_barrier.notify(block_number, finish_commit_time).unwrap();
    }

    fn init_storage(&self, execution_args: ExecutionArgs) {
        execution_args.block_number_to_block_id.into_iter().for_each(|(block_number, block_id)| {
            self.storage.insert_block_id(block_number, block_id);
        });
    }

    /// Return the filtered valid transactions with sender without changing the relative order of
    /// the transactions.
    ///
    /// All excluded txs are discarded from the pool (`is_discarded` + `discard_txs_tx`), including
    /// Beta+ gas-budget exclusions. Pre-Beta uses legacy gas prefix-cut; Beta+ packs with gas as
    /// last gate but still discards non-fitting txs (audit#646 packing fix, no keep-in-pool defer).
    fn filter_invalid_txs(
        &self,
        db: &Storage::StateView,
        txs: Vec<TransactionSigned>,
        senders: Vec<Address>,
        base_fee_per_gas: u64,
        gas_limit: u64,
        block_timestamp: u64,
        block_number: u64,
    ) -> (Vec<TransactionSigned>, Vec<Address>, Vec<TxInfo>) {
        let invalid_idxs = tx_filter::filter_invalid_txs(
            db,
            &txs,
            &senders,
            base_fee_per_gas,
            gas_limit,
            &self.chain_spec,
            block_timestamp,
            block_number,
        );
        if invalid_idxs.is_empty() {
            let mut txs_info = Vec::with_capacity(txs.len());
            for (tx, sender) in txs.iter().zip(senders.iter()) {
                txs_info.push(TxInfo {
                    tx_hash: *tx.hash(),
                    sender: *sender,
                    nonce: tx.nonce(),
                    is_discarded: false,
                });
            }
            (txs, senders, txs_info)
        } else {
            let _ = self
                .discard_txs_tx
                .send(invalid_idxs.iter().map(|&idx| txs[idx].hash()).copied().collect::<Vec<_>>());

            let mut filtered_txs = Vec::with_capacity(txs.len() - invalid_idxs.len());
            let mut filtered_senders = Vec::with_capacity(filtered_txs.capacity());
            let mut txs_info = Vec::with_capacity(txs.len());
            for (i, (tx, sender)) in txs.into_iter().zip(senders.into_iter()).enumerate() {
                if invalid_idxs.contains(&i) {
                    txs_info.push(TxInfo {
                        tx_hash: *tx.hash(),
                        sender,
                        nonce: tx.nonce(),
                        is_discarded: true,
                    });
                    continue;
                }

                txs_info.push(TxInfo {
                    tx_hash: *tx.hash(),
                    sender,
                    nonce: tx.nonce(),
                    is_discarded: false,
                });
                filtered_txs.push(tx);
                filtered_senders.push(sender);
            }
            (filtered_txs, filtered_senders, txs_info)
        }
    }
}

/// Called by Coordinator
#[derive(Debug)]
pub struct PipeExecLayerApi<Storage, EthApi> {
    ordered_block_tx: UnboundedSender<ReceivedBlock>,
    execution_result_rx: Mutex<UnboundedReceiver<ExecutionResult>>,
    verified_block_hash_tx: Arc<Channel<B256 /* block id */, Option<B256> /* block hash */>>,
    event_tx: std::sync::mpsc::Sender<PipeExecLayerEvent<EthPrimitives>>,
    storage: Arc<Storage>,
    onchain_config_fetcher: OnchainConfigFetcher<EthApi>,
}

impl<Storage, EthApi> ConfigStorage for PipeExecLayerApi<Storage, EthApi>
where
    Storage: Sync + Send + 'static,
    EthApi: EthCall,
    EthApi::NetworkTypes: RpcTypes<TransactionRequest = TransactionRequest>,
{
    fn fetch_config_bytes(
        &self,
        config_name: OnChainConfig,
        block_id: BlockNumber,
    ) -> Option<OnChainConfigResType> {
        self.onchain_config_fetcher.fetch_config_bytes(
            config_name,
            match block_id {
                BlockNumber::Number(number) => number.into(),
                BlockNumber::Latest => alloy_eips::BlockId::Number(BlockNumberOrTag::Latest),
            },
        )
    }
}

impl<Storage: GravityStorage, EthApi> PipeExecLayerApi<Storage, EthApi> {
    /// Push ordered block to EL for execution.
    /// Returns `None` if the channel has been closed.
    pub fn push_ordered_block(&self, block: OrderedBlock) -> Option<()> {
        self.ordered_block_tx.send(ReceivedBlock::OrderedBlock(block)).ok()
    }

    /// Only used for testing.
    pub fn push_history_block(&self, block: RecoveredBlock<Block>) -> Option<()> {
        self.ordered_block_tx.send(ReceivedBlock::HistoryBlock(block.into())).ok()
    }

    /// Pull executed block hash from EL for verification.
    /// Returns `None` if the channel has been closed.
    pub async fn pull_executed_block_hash(&self) -> Option<ExecutionResult> {
        self.execution_result_rx.lock().await.recv().await
    }

    /// Push verified block hash to EL for commit.
    /// The caller can optionally pass in a verified block hash, which is solely used for the EL
    /// defensive check to ensure the consistency of the block hash before and after verification.
    /// Returns `None` if the channel has been closed.
    pub fn commit_executed_block_hash(
        &self,
        block_id: B256,
        block_hash: Option<B256>,
    ) -> Option<()> {
        self.verified_block_hash_tx.notify(block_id, block_hash)
    }

    /// Wait for the block with the given block number to be persisted in the storage.
    /// Returns `None` if the channel has been closed.
    pub async fn wait_for_block_persistence(&self, block_number: u64) -> Option<()> {
        let (tx, rx) = oneshot::channel();
        self.event_tx
            .send(PipeExecLayerEvent::WaitForPersistence(WaitForPersistenceEvent {
                block_number,
                tx,
            }))
            .ok()?;
        rx.await.ok()
    }

    /// Get the block id by block number.
    pub fn get_block_id(&self, block_number: u64) -> Option<B256> {
        self.storage.get_block_id(block_number)
    }
}

impl<Storage, EthApi> Drop for PipeExecLayerApi<Storage, EthApi> {
    fn drop(&mut self) {
        self.verified_block_hash_tx.close();
    }
}

/// Create a new `PipeExecLayerApi` instance and launch a `PipeExecService`.
pub fn new_pipe_exec_layer_api<Storage, EthApi>(
    chain_spec: Arc<ChainSpec>,
    storage: Storage,
    latest_block_header: Header,
    latest_block_hash: B256,
    execution_args_rx: oneshot::Receiver<ExecutionArgs>,
    eth_api: EthApi,
) -> PipeExecLayerApi<Storage, EthApi>
where
    Storage: GravityStorage,
    EthApi: EthCall,
    EthApi::NetworkTypes: RpcTypes<TransactionRequest = TransactionRequest>,
{
    let (ordered_block_tx, ordered_block_rx) = tokio::sync::mpsc::unbounded_channel();
    let (execution_result_tx, execution_result_rx) = tokio::sync::mpsc::unbounded_channel();
    let verified_block_hash_ch = Arc::new(Channel::new());
    let (event_tx, event_rx) = std::sync::mpsc::channel();
    let (discard_txs_tx, discard_txs_rx) = tokio::sync::mpsc::unbounded_channel();

    let storage = Arc::new(storage);
    let onchain_config_fetcher = OnchainConfigFetcher::new(eth_api);

    let latest_block_number = latest_block_header.number;
    let epoch = onchain_config_fetcher
        .fetch_epoch(latest_block_number.into())
        .expect("Failed to fetch epoch");
    info!(target: "PipeExecService.new_pipe_exec_layer_api",
        latest_block_number=?latest_block_number,
        latest_block_hash=?latest_block_hash,
        epoch=?epoch,
        "new pipe exec layer api"
    );

    let bls_pop_verify_precompile = custom_precompiles::create_bls_pop_verify_precompile();
    let pre_alpha_precompiles =
        Arc::new(vec![(BLS_PRECOMPILE_ADDR, bls_pop_verify_precompile.clone())]);
    let start_time = Instant::now();
    let service = PipeExecService {
        core: Arc::new(Core {
            execution_result_tx,
            verified_block_hash_rx: verified_block_hash_ch.clone(),
            storage: storage.clone(),
            evm_config: EthEvmConfig::new(chain_spec.clone()),
            chain_spec,
            bls_pop_verify_precompile,
            pre_alpha_precompiles,
            event_tx: event_tx.clone(),
            execute_block_barrier: Channel::new_with_states([(
                (epoch, latest_block_number),
                ExecuteBlockContext {
                    parent_header: latest_block_header,
                    prev_start_execute_time: start_time,
                    epoch,
                },
            )]),
            merklize_barrier: Channel::new_with_states([(latest_block_number, ())]),
            seal_barrier: Channel::new_with_states([(latest_block_number, latest_block_hash)]),
            make_canonical_barrier: Channel::new_with_states([(latest_block_number, start_time)]),
            discard_txs_tx,
            cache: PERSIST_BLOCK_CACHE.clone(),
            epoch: AtomicU64::new(epoch),
            execute_height: AtomicU64::new(latest_block_number),
            metrics: PipeExecLayerMetrics::default(),
        }),
        ordered_block_rx,
        execution_args_rx,
    };
    tokio::spawn(service.run());

    PIPE_EXEC_LAYER_EVENT_BUS.get_or_init(|| PipeExecLayerEventBus {
        event_rx: std::sync::Mutex::new(Some(event_rx)),
        discard_txs: tokio::sync::Mutex::new(Some(discard_txs_rx)),
    });

    PipeExecLayerApi {
        ordered_block_tx,
        execution_result_rx: Mutex::new(execution_result_rx),
        verified_block_hash_tx: verified_block_hash_ch,
        event_tx,
        storage,
        onchain_config_fetcher,
    }
}
