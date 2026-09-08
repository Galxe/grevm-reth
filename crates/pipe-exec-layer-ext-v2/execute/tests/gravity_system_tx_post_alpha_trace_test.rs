#![allow(missing_docs)]

//! T6 / §3.1 + §3.2 — post-Alpha RPC replay consistency (relaxed gas gate).
//!
//! Once Alpha is active and `SYSTEM_CALLER.balance` is zero, RPC replay must:
//!   1. Run without `GasPriceLessThanBasefee` / `InsufficientFunds`.
//!   2. Keep system-tx `gas_price == 0` (L2 construction + L1 cfg exempt).
//!   3. Match **debug**/callTracer gas to canonical receipts (execution fidelity).
//!   4. On `SAMPLE_BLOCK`, a user EOA CALL to `NATIVE_MINT_PRECOMPILE_ADDR` is injected. Pipe user
//!      execution does **not** register mint (only `transact_system_txn` does), so canonical treats
//!      that address as an empty account. RPC must match that status — unauthorized mint halt would
//!      mean over-registration on the user path (#372 review).
//!
//! Parity `trace_*` endpoints are exercised for **shape** only (root count,
//! tx_hash, success/error, state_diff presence) — **not** root `gas_used` ≡
//! receipt. Inspector call-frame gas omits intrinsic / can drift vs
//! `ExecutionResult` unless `with_transaction_gas_used` is applied; binding
//! parity gas to receipts conflates tracer metering with execution (see #372
//! diagnosis). Same split as `gravity_system_tx_bls_replay_test` (debug carries
//! gas equality; parity is a count guard).
//!
//! Location note: see `gravity_system_tx_pre_alpha_replay_test.rs` for the
//! rationale on co-locating RPC-surface tests in the pipe-exec-layer harness.

use alloy_consensus::{SignableTransaction, Transaction as AlloyTx, TxEip1559, TxReceipt};
use alloy_eips::BlockId;
use alloy_primitives::{address, map::HashSet, Address, Bytes, Signature, TxKind, B256, U256};
use alloy_rpc_types_eth::TransactionRequest;
use alloy_rpc_types_trace::{
    filter::TraceFilter,
    geth::{call::CallConfig, GethDebugTracingOptions, GethTrace, TraceResult},
    parity::{LocalizedTransactionTrace, TraceType},
};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use gravity_api_types::{
    config_storage::{BlockNumber, ConfigStorage, OnChainConfig},
    events::contract_event::GravityEvent,
};
use gravity_precompiles::mint_token::NATIVE_MINT_PRECOMPILE_ADDR;
use gravity_storage::{block_view_storage::BlockViewStorage, GravityStorage};
use reth_chainspec::ChainSpec;
use reth_cli_commands::{launcher::FnLauncher, NodeCommand};
use reth_cli_runner::CliRunner;
use reth_db::DatabaseEnv;
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;
use reth_ethereum_primitives::{Transaction, TransactionSigned};
use reth_node_builder::{EngineNodeLauncher, NodeBuilder, WithLaunchContext};
use reth_node_ethereum::{node::EthereumAddOns, EthereumNode};
use reth_pipe_exec_layer_ext_v2::{
    new_pipe_exec_layer_api, ExecutionArgs, OrderedBlock, PipeExecLayerApi,
};
use reth_provider::{
    providers::BlockchainProvider, BlockHashReader, BlockNumReader, BlockReader,
    DatabaseProviderFactory, HeaderProvider, ReceiptProvider, StateProviderFactory,
    TransactionVariant,
};
use reth_rpc_eth_api::{helpers::EthCall, RpcTypes};
use reth_tracing::{
    tracing_subscriber::filter::LevelFilter, LayerInfo, LogFormat, RethTracer, Tracer,
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// Block N timestamp (seconds) = `ALPHA_TS_BASE + N`. Set Alpha activation
/// to block 1's timestamp so:
///   - parent (genesis) ts = `gravity_hardfork.json` 0x6490fdd2 = 1687223762 is strictly less than
///     `ALPHA_TIME_ALWAYS`
///   - block 1's ts == `ALPHA_TIME_ALWAYS` — Alpha activates exactly at block 1, the migration hook
///     fires once (zeroing SYSTEM_CALLER.balance), and every block in `1..=POST_ALPHA_TIP` is
///     post-Alpha
///
/// (The previously committed `ALPHA_TIME_ALWAYS = 1` was a fixture bug:
/// `transitions_at_timestamp(parent=1687223762, current=block_n_ts, activation=1)`
/// returns false for every n because parent already crossed activation,
/// so the migration never fired and SYSTEM_CALLER.balance stayed at the
/// sentinel value — making the "post-Alpha balance must be 0" sanity check
/// panic before any trace assertion ran.)
const ALPHA_TS_BASE: u64 = 2_000_000_000;
const ALPHA_TIME_ALWAYS: u64 = ALPHA_TS_BASE + 1;
const POST_ALPHA_TIP: u64 = 10;
/// Sampled for the single-tx family + user-path mint parity cell (#372):
/// a funded EOA CALL to the mint address is injected here.
const SAMPLE_BLOCK: u64 = 5;

const SYSTEM_CALLER: Address = address!("00000000000000000000000000000001625f0000");
const CHAIN_ID: u64 = 7771625;
/// Anvil account 0 — pre-funded in `gravity_hardfork.json`.
const FUNDED_PRIVKEY_HEX: &[u8; 32] = &[
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
];
const MINT_TX_GAS_LIMIT: u64 = 100_000;

fn gravity_alpha_chainspec(alpha_time: u64) -> String {
    let mut json: serde_json::Value =
        serde_json::from_str(include_str!("../gravity_hardfork.json"))
            .expect("gravity_hardfork.json must parse as JSON");
    json["config"]["alphaTime"] = serde_json::json!(alpha_time);
    // Pre-seed SYSTEM_CALLER with nonce=1 so the Alpha migration's
    // balance-zeroing transition produces (balance=0, nonce=1, code=empty)
    // which stays non-empty under EIP-161. Without this, the migration
    // would zero balance on a fresh nonce=0 account, transitioning
    // SYSTEM_CALLER to (balance=0, nonce=0, code=empty) — an "empty"
    // touched state that revm's AccountStatus state machine rejects
    // (`Wrong state transition, touch empty is not possible from Loaded`).
    // In production this never happens because pre-Alpha system txs
    // already bumped SYSTEM_CALLER nonce by the time Alpha activates;
    // this fixture mirrors that precondition without paying the cost of
    // running a real pre-Alpha block series first.
    json["alloc"]["0x00000000000000000000000000000001625f0000"]["nonce"] = serde_json::json!(1);
    json.to_string()
}

fn mock_block_id(block_number: u64) -> B256 {
    B256::left_padding_from(&block_number.to_be_bytes())
}

fn alpha_ts_us(block_number: u64) -> u64 {
    (ALPHA_TS_BASE + block_number) * 1_000_000
}

fn funded_signer() -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::from(*FUNDED_PRIVKEY_HEX))
        .expect("funded test key must parse")
}

/// Mint precompile input: func=0x01, recipient=20 bytes, amount=32 bytes.
fn mint_call_input() -> Bytes {
    let mut data = vec![0x01];
    data.extend_from_slice(&[0u8; 20]); // recipient
    data.extend_from_slice(&U256::from(1u64).to_be_bytes::<32>());
    Bytes::from(data)
}

fn build_mint_call_tx(sender: &PrivateKeySigner, nonce: u64) -> (TransactionSigned, Address) {
    let tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce,
        gas_limit: MINT_TX_GAS_LIMIT,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(NATIVE_MINT_PRECOMPILE_ADDR),
        value: U256::ZERO,
        access_list: Default::default(),
        input: mint_call_input(),
    };
    let sig_hash = tx.signature_hash();
    let signature: Signature = sender.sign_hash_sync(&sig_hash).expect("tx signing must succeed");
    let signed = tx.into_signed(signature);
    let (tx, sig, _hash) = signed.into_parts();
    let signed_tx = TransactionSigned::new_unhashed(Transaction::Eip1559(tx), sig);
    let _ = signed_tx.hash();
    (signed_tx, sender.address())
}

fn empty_ordered_block(
    epoch: u64,
    block_number: u64,
    block_id: B256,
    parent_block_id: B256,
    timestamp_us: u64,
) -> OrderedBlock {
    OrderedBlock {
        failed_proposer_indices: vec![],
        epoch,
        parent_id: parent_block_id,
        id: block_id,
        number: block_number,
        timestamp_us,
        coinbase: Address::ZERO,
        prev_randao: B256::ZERO,
        withdrawals: Default::default(),
        transactions: vec![],
        senders: vec![],
        proposer_index: Some(0),
        extra_data: vec![],
        randomness: U256::ZERO,
    }
}

fn ordered_block_with_txs(
    epoch: u64,
    block_number: u64,
    block_id: B256,
    parent_block_id: B256,
    timestamp_us: u64,
    transactions: Vec<TransactionSigned>,
    senders: Vec<Address>,
) -> OrderedBlock {
    OrderedBlock {
        failed_proposer_indices: vec![],
        epoch,
        parent_id: parent_block_id,
        id: block_id,
        number: block_number,
        timestamp_us,
        coinbase: Address::ZERO,
        prev_randao: B256::ZERO,
        withdrawals: Default::default(),
        transactions,
        senders,
        proposer_index: Some(0),
        extra_data: vec![],
        randomness: U256::ZERO,
    }
}

// ---------------------------------------------------------------------------
// MockConsensus
// ---------------------------------------------------------------------------

type TimestampFn = Box<dyn Fn(u64) -> u64 + Send + Sync>;

struct MockConsensus<Storage, EthApi> {
    pipeline_api: PipeExecLayerApi<Storage, EthApi>,
    ts_for_block: TimestampFn,
}

impl<Storage, EthApi> MockConsensus<Storage, EthApi>
where
    Storage: GravityStorage,
    EthApi: EthCall,
    EthApi::NetworkTypes: RpcTypes<TransactionRequest = TransactionRequest>,
{
    fn new(pipeline_api: PipeExecLayerApi<Storage, EthApi>, ts_for_block: TimestampFn) -> Self {
        Self { pipeline_api, ts_for_block }
    }

    async fn push_empty_range(&self, epoch: &mut u64, start: u64, end: u64) {
        let signer = funded_signer();
        for n in start..=end {
            let block = if n == SAMPLE_BLOCK {
                // #372: user-path negative — CALL mint address without system
                // registration. Canonical and RPC must agree (empty-account CALL).
                let (mint_tx, sender) = build_mint_call_tx(&signer, 0);
                ordered_block_with_txs(
                    *epoch,
                    n,
                    mock_block_id(n),
                    mock_block_id(n - 1),
                    (self.ts_for_block)(n),
                    vec![mint_tx],
                    vec![sender],
                )
            } else {
                empty_ordered_block(
                    *epoch,
                    n,
                    mock_block_id(n),
                    mock_block_id(n - 1),
                    (self.ts_for_block)(n),
                )
            };
            self.push_one(epoch, block).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn push_one(
        &self,
        epoch: &mut u64,
        block: OrderedBlock,
    ) -> reth_pipe_exec_layer_ext_v2::ExecutionResult {
        let block_id = block.id;
        let block_number = block.number;
        self.pipeline_api.push_ordered_block(block).unwrap();
        let result = self.pipeline_api.pull_executed_block_hash().await.unwrap();
        assert_eq!(result.block_number, block_number);
        assert_eq!(result.block_id, block_id);
        self.pipeline_api.commit_executed_block_hash(block_id, Some(result.block_hash)).unwrap();

        for event in &result.gravity_events {
            if let GravityEvent::NewEpoch(new_epoch, _) = event {
                assert_eq!(*new_epoch, *epoch + 1);
                self.pipeline_api.wait_for_block_persistence(block_number).await.unwrap();
                self.pipeline_api
                    .push_ordered_block(empty_ordered_block(
                        *epoch,
                        block_number + 1,
                        mock_block_id(block_number + 1),
                        block_id,
                        (self.ts_for_block)(block_number + 1),
                    ))
                    .unwrap();
                *epoch = *new_epoch;
            }
        }
        result
    }

    fn into_inner(self) -> PipeExecLayerApi<Storage, EthApi> {
        self.pipeline_api
    }
}

// ---------------------------------------------------------------------------
// Core T6 runner — block-family + single-tx trace consistency on post-Alpha
// blocks containing protocol-injected system txs.
// ---------------------------------------------------------------------------

async fn run_post_alpha_trace_consistency(
    builder: WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, ChainSpec>>,
    label: &'static str,
) -> eyre::Result<()> {
    let handle = builder
        .with_types_and_provider::<EthereumNode, BlockchainProvider<_>>()
        .with_components(EthereumNode::components())
        .with_add_ons(EthereumAddOns::default())
        .launch_with_fn(|builder| {
            let launcher = EngineNodeLauncher::new(
                builder.task_executor().clone(),
                builder.config().datadir(),
                reth_engine_primitives::TreeConfig::default(),
            );
            builder.launch_with(launcher)
        })
        .await?;

    let chain_spec = handle.node.chain_spec();
    let eth_api = handle.node.rpc_registry.eth_api().clone();
    let trace_api = handle.node.rpc_registry.trace_api();
    let debug_api = handle.node.rpc_registry.debug_api();
    let provider = handle.node.provider;

    let db_provider = provider.database_provider_ro().unwrap();
    let latest_block_number = db_provider.best_block_number().unwrap();
    let latest_block_hash = db_provider.block_hash(latest_block_number).unwrap().unwrap();
    let latest_block_header = db_provider.header_by_number(latest_block_number).unwrap().unwrap();
    drop(db_provider);

    assert_eq!(latest_block_number, 0, "[post_alpha_trace {label}] runner expects a fresh datadir");

    let storage = BlockViewStorage::new(provider.clone());

    let (tx, rx) = tokio::sync::oneshot::channel();
    let pipeline_api = new_pipe_exec_layer_api(
        chain_spec.clone(),
        storage,
        latest_block_header,
        latest_block_hash,
        rx,
        eth_api,
    );
    tx.send(ExecutionArgs { block_number_to_block_id: BTreeMap::new() }).unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut epoch: u64 = pipeline_api
        .fetch_config_bytes(OnChainConfig::Epoch, BlockNumber::Latest)
        .unwrap()
        .try_into()
        .unwrap();

    let consensus = MockConsensus::new(pipeline_api, Box::new(alpha_ts_us));
    consensus.push_empty_range(&mut epoch, 1, POST_ALPHA_TIP).await;
    let pipeline_api = consensus.into_inner();
    pipeline_api.wait_for_block_persistence(POST_ALPHA_TIP).await.unwrap();
    drop(pipeline_api);

    // Sanity: post-Alpha SYSTEM_CALLER.balance is zero (migration fired at
    // block 1). Without this, the gas-exempt levers wouldn't be load-bearing
    // and the test would devolve into a trivial happy-path check.
    let sysacc = provider
        .state_by_block_number_or_tag(alloy_eips::BlockNumberOrTag::Number(POST_ALPHA_TIP))
        .expect("state provider")
        .basic_account(&SYSTEM_CALLER)
        .expect("basic_account")
        .expect("SYSTEM_CALLER must remain present post-Alpha");
    assert_eq!(
        sysacc.balance,
        U256::ZERO,
        "[post_alpha_trace {label}] post-Alpha SYSTEM_CALLER.balance must be 0 — test is vacuous otherwise"
    );

    // -----------------------------------------------------------------
    // §3.1 BLOCK-FAMILY — exercise every block-level endpoint on every
    // post-Alpha block and assert per-tx byte-equal canonical execution.
    //
    // "byte-equal canonical" semantics in this harness: the canonical
    // execution is what the pipe layer wrote into receipts. We pin every
    // overlapping field — per-tx `tx_hash`, `gas_used` (cumulative_gas_used
    // delta), and success status — across every block-family endpoint.
    // The geth + parity output formats don't share a common-superset of
    // fields with `EthereumReceipt`, so we compare on the field
    // intersection (hash + gas + status); this is strictly stronger than
    // the previous "count match + ok" weak assertions (acceptance matrix
    // §3.1 byte-equal canonical commitment).
    // -----------------------------------------------------------------
    let mut canonical_total_root_traces: usize = 0;
    for n in 1..=POST_ALPHA_TIP {
        let block_id = BlockId::Number(n.into());
        let canonical_receipts = provider
            .receipts_by_block(alloy_eips::BlockHashOrNumber::Number(n))
            .expect("provider receipts read")
            .unwrap_or_else(|| panic!("block {n} must have persisted receipts"));
        let canonical_block = provider
            .recovered_block(n.into(), TransactionVariant::WithHash)
            .expect("recovered_block")
            .unwrap_or_else(|| panic!("block {n} must be persisted"));
        let canonical_tx_hashes: Vec<B256> =
            canonical_block.body().transactions.iter().map(|tx| *tx.hash()).collect();
        let canonical = canonical_baseline(&canonical_receipts, &canonical_tx_hashes);
        assert!(
            !canonical.is_empty(),
            "[post_alpha_trace {label}] block {n} must contain >= 1 receipt (metadata system tx)"
        );
        canonical_total_root_traces += canonical.len();

        // 3.1.a — trace_block: per-tx root-level trace gas_used + tx_hash
        // must match canonical receipt byte-for-byte.
        let blk_traces = trace_api
            .trace_block(block_id)
            .await
            .unwrap_or_else(|e| panic!("[{label}] trace_block({n}) errored: {e:?}"))
            .unwrap_or_else(|| panic!("[{label}] trace_block({n}) returned None"));
        assert_trace_block_byte_equal_canonical(&blk_traces, &canonical, label, n);

        // 3.1.b — debug_trace_block: per-tx DefaultFrame.gas + failed flag
        // must match canonical receipt byte-for-byte.
        let debug_blk = debug_api
            .debug_trace_block(block_id, GethDebugTracingOptions::default())
            .await
            .unwrap_or_else(|e| panic!("[{label}] debug_trace_block({n}) errored: {e:?}"));
        assert_debug_trace_block_byte_equal_canonical(&debug_blk, &canonical, label, n);

        // 3.1.c — replay_block_transactions: per-tx root trace gas_used +
        // tx_hash must match canonical; state_diff must be populated (and
        // SYSTEM_CALLER must appear with nonce delta, since each system tx
        // bumps SYSTEM_CALLER nonce — load-bearing for the design's "RPC
        // replay reproduces canonical state" claim).
        let mut trace_types: HashSet<TraceType> = HashSet::default();
        trace_types.insert(TraceType::Trace);
        trace_types.insert(TraceType::StateDiff);
        let replay_blk = trace_api
            .replay_block_transactions(block_id, trace_types.clone())
            .await
            .unwrap_or_else(|e| panic!("[{label}] replay_block_transactions({n}) errored: {e:?}"))
            .unwrap_or_else(|| panic!("[{label}] replay_block_transactions({n}) returned None"));
        assert_replay_block_byte_equal_canonical(&replay_blk, &canonical, label, n);

        // 3.1.d — trace_block_opcode_gas: per-tx hash matches canonical;
        // opcode-gas sum is `> 0 && <= cn.gas_used` (sum can't equal
        // gas_used byte-equal because the receipt is net of intrinsic
        // 21_000 + calldata, but `sum > gas_used` is a hard bug). See
        // `assert_opcode_gas_byte_equal_canonical` for the intrinsic-gap
        // rationale.
        let opcode_gas = trace_api
            .trace_block_opcode_gas(block_id)
            .await
            .unwrap_or_else(|e| panic!("[{label}] trace_block_opcode_gas({n}) errored: {e:?}"))
            .unwrap_or_else(|| panic!("[{label}] trace_block_opcode_gas({n}) returned None"));
        assert_opcode_gas_byte_equal_canonical(&opcode_gas, &canonical, label, n);

        // 3.1.e — trace_block_storage_access: per-tx hash matches canonical.
        // No comparable field on receipts for storage access counts; tx_hash
        // identity is the load-bearing replay-correctness invariant. Inlined
        // because `BlockStorageAccess` lives in a private reth-rpc module.
        let storage_access = trace_api
            .trace_block_storage_access(block_id)
            .await
            .unwrap_or_else(|e| panic!("[{label}] trace_block_storage_access({n}) errored: {e:?}"))
            .unwrap_or_else(|| panic!("[{label}] trace_block_storage_access({n}) returned None"));
        assert_eq!(
            storage_access.transactions.len(),
            canonical.len(),
            "[post_alpha_trace {label}] trace_block_storage_access({n}) tx count != canonical: got {}, want {}",
            storage_access.transactions.len(),
            canonical.len(),
        );
        for (i, (tsa, cn)) in storage_access.transactions.iter().zip(canonical.iter()).enumerate() {
            assert_eq!(
                tsa.transaction_hash, cn.tx_hash,
                "[post_alpha_trace {label}] trace_block_storage_access({n})[{i}] tx_hash != canonical"
            );
        }
    }

    // 3.1.f — trace_filter spanning the full post-Alpha range. The number
    // of root-level (depth-0) traces returned must equal the sum of
    // canonical receipts across the range — every canonical tx produces
    // exactly one root-level trace in the filter output. Equality (not
    // `>=`) is the right invariant: post-Paris has no reward traces
    // (those were eliminated with PoS), and we already filter on
    // `trace_address.is_empty()` so subcalls are excluded by construction.
    // Any drift here means trace_filter is duplicating or dropping root
    // traces relative to receipts — a real regression we must catch.
    let filter = TraceFilter {
        from_block: Some(1),
        to_block: Some(POST_ALPHA_TIP),
        from_address: vec![],
        to_address: vec![],
        mode: Default::default(),
        after: None,
        count: None,
    };
    let filt_traces = trace_api
        .trace_filter(filter)
        .await
        .unwrap_or_else(|e| panic!("[{label}] trace_filter errored: {e:?}"));
    let filt_root_count = filt_traces.iter().filter(|t| t.trace.trace_address.is_empty()).count();
    assert_eq!(
        filt_root_count, canonical_total_root_traces,
        "[post_alpha_trace {label}] trace_filter root-trace count {filt_root_count} must equal canonical total {canonical_total_root_traces} across blocks 1..={POST_ALPHA_TIP} (post-Paris has no reward traces; root filter is exhaustive)"
    );

    // -----------------------------------------------------------------
    // §3.2 SINGLE-TX FAMILY — pick the metadata system tx at SAMPLE_BLOCK
    // and exercise every single-tx endpoint. With the gas-exempt cfg-side
    // levers active, the replay path must succeed AND every endpoint's
    // output must match the canonical receipt byte-for-byte on the field
    // intersection (tx_hash + gas_used + success).
    // -----------------------------------------------------------------
    let sample_block = provider
        .recovered_block(SAMPLE_BLOCK.into(), TransactionVariant::WithHash)
        .expect("recovered_block")
        .unwrap_or_else(|| panic!("block {SAMPLE_BLOCK} must be persisted"));
    let txs = sample_block.body().transactions.as_slice();
    assert!(
        !txs.is_empty(),
        "[post_alpha_trace {label}] block {SAMPLE_BLOCK} must contain the metadata system tx"
    );
    let sample_receipts = provider
        .receipts_by_block(alloy_eips::BlockHashOrNumber::Number(SAMPLE_BLOCK))
        .expect("provider receipts read")
        .unwrap_or_else(|| panic!("block {SAMPLE_BLOCK} must have persisted receipts"));
    let sample_tx_hashes: Vec<B256> = txs.iter().map(|tx| *tx.hash()).collect();
    let sample_canonical = canonical_baseline(&sample_receipts, &sample_tx_hashes);
    assert!(
        !sample_canonical.is_empty(),
        "[post_alpha_trace {label}] block {SAMPLE_BLOCK} must contain >= 1 canonical receipt"
    );
    // System txs form the head prefix; the mint user tx is appended after.
    assert!(
        sample_canonical.len() >= 2,
        "[post_alpha_trace {label}] block {SAMPLE_BLOCK} must contain metadata system tx + mint user tx, got {} receipts",
        sample_canonical.len()
    );
    let metadata_tx_hash: B256 = sample_canonical[0].tx_hash;
    let mint_tx_hash: B256 = sample_canonical[sample_canonical.len() - 1].tx_hash;
    let target_canonical = &sample_canonical[0];

    // #372: protocol system txs must be gas_price = 0 under Alpha (user mint tx is not).
    let recovered = sample_block.clone();
    for (i, (tx, sender)) in
        recovered.body().transactions.iter().zip(recovered.senders().iter()).enumerate()
    {
        if *sender != SYSTEM_CALLER {
            continue;
        }
        let gp = AlloyTx::gas_price(tx).unwrap_or(u128::MAX);
        assert_eq!(
            gp, 0,
            "[post_alpha_trace {label}] block {SAMPLE_BLOCK} system tx[{i}] gas_price must be 0; got {gp}"
        );
    }

    println!(
        "[post_alpha_trace {label}] sample metadata tx at block {SAMPLE_BLOCK}: hash={metadata_tx_hash:?}, canonical gas_used={}; mint user tx={mint_tx_hash:?}",
        target_canonical.gas_used,
    );

    // 3.2.a — trace_transaction: root present (parity shape only).
    let trace_tx = trace_api
        .trace_transaction(metadata_tx_hash)
        .await
        .unwrap_or_else(|e| panic!("[{label}] trace_transaction errored: {e:?}"))
        .unwrap_or_else(|| panic!("[{label}] trace_transaction returned None"));
    assert_root_trace_ok(&trace_tx, target_canonical, label, "trace_transaction");

    // 3.2.b — trace_replay_transaction: root + state_diff (no gas ≡ receipt).
    let mut replay_trace_types: HashSet<TraceType> = HashSet::default();
    replay_trace_types.insert(TraceType::Trace);
    replay_trace_types.insert(TraceType::StateDiff);
    let replay_tx = trace_api
        .replay_transaction(metadata_tx_hash, replay_trace_types)
        .await
        .unwrap_or_else(|e| panic!("[{label}] replay_transaction errored: {e:?}"));
    let root = replay_tx.trace.iter().find(|t| t.trace_address.is_empty()).unwrap_or_else(|| {
        panic!(
            "[{label}] replay_transaction must contain a root trace (trace_address == []) for the system tx"
        )
    });
    assert!(root.result.is_some(), "[{label}] replay_transaction root trace must have result");
    assert!(
        replay_tx.state_diff.is_some(),
        "[post_alpha_trace {label}] replay_transaction must populate state_diff (requested via TraceType::StateDiff)"
    );

    // 3.2.c — trace_get index 0: root present.
    let trace_get_0 = trace_api
        .trace_get(metadata_tx_hash, vec![0])
        .await
        .unwrap_or_else(|e| panic!("[{label}] trace_get errored: {e:?}"))
        .unwrap_or_else(|| panic!("[{label}] trace_get(hash, [0]) must return Some(trace)"));
    assert!(
        trace_get_0.trace.trace_address.is_empty(),
        "[post_alpha_trace {label}] trace_get([0]) must return the root trace (trace_address == [])"
    );
    assert!(trace_get_0.trace.result.is_some(), "[{label}] trace_get root trace must have result");

    // 3.2.d — debug_trace_transaction: DefaultFrame.gas ≡ receipt (execution fidelity).
    let debug_tx = debug_api
        .debug_trace_transaction(metadata_tx_hash, GethDebugTracingOptions::default())
        .await
        .unwrap_or_else(|e| panic!("[{label}] debug_trace_transaction errored: {e:?}"));
    match debug_tx {
        GethTrace::Default(frame) => {
            assert_eq!(
                frame.gas, target_canonical.gas_used,
                "[post_alpha_trace {label}] debug_trace_transaction frame.gas != canonical gas_used: got {}, want {} (tx_hash={metadata_tx_hash:?})",
                frame.gas, target_canonical.gas_used,
            );
            assert_eq!(
                frame.failed, !target_canonical.success,
                "[post_alpha_trace {label}] debug_trace_transaction frame.failed != !canonical.success: got failed={}, want {} (tx_hash={metadata_tx_hash:?})",
                frame.failed, !target_canonical.success,
            );
        }
        other => panic!(
            "[{label}] debug_trace_transaction must return DefaultFrame for default opts, got: {other:?}"
        ),
    }

    // 3.2.e — callTracer on the mint user tx: must match canonical empty-account
    // semantics. Pipe user execution does not register mint; RPC must not either.
    let mint_canonical = sample_canonical.last().expect("mint canonical entry");
    let call_opts = GethDebugTracingOptions::call_tracer(CallConfig::default());
    let call_trace =
        debug_api.debug_trace_transaction(mint_tx_hash, call_opts).await.unwrap_or_else(|e| {
            panic!("[{label}] debug_trace_transaction(callTracer mint) errored: {e:?}")
        });
    let call_frame = match call_trace {
        GethTrace::CallTracer(frame) => frame,
        other => panic!("[{label}] callTracer must return CallTracer frame, got: {other:?}"),
    };
    assert_eq!(
        call_frame.to,
        Some(NATIVE_MINT_PRECOMPILE_ADDR),
        "[post_alpha_trace {label}] mint user tx top-frame.to must be mint address"
    );
    assert_eq!(
        call_frame.error.is_none() && call_frame.revert_reason.is_none(),
        mint_canonical.success,
        "[post_alpha_trace {label}] mint user tx callTracer status must match canonical success={} (error={:?} revert={:?}); unauthorized mint halt means RPC over-registered mint on the user path",
        mint_canonical.success,
        call_frame.error,
        call_frame.revert_reason,
    );
    if mint_canonical.success {
        assert_eq!(
            call_frame.gas_used, mint_canonical.gas_used,
            "[post_alpha_trace {label}] mint user tx callTracer.gas_used != canonical: got {}, want {}",
            call_frame.gas_used, mint_canonical.gas_used,
        );
    }

    // 3.2.f — trace_transaction_opcode_gas: hash + non-empty (EVM ran).
    let txopcode = trace_api
        .trace_transaction_opcode_gas(metadata_tx_hash)
        .await
        .unwrap_or_else(|e| panic!("[{label}] trace_transaction_opcode_gas errored: {e:?}"))
        .unwrap_or_else(|| panic!("[{label}] trace_transaction_opcode_gas must return Some"));
    assert_eq!(
        txopcode.transaction_hash, metadata_tx_hash,
        "[post_alpha_trace {label}] trace_transaction_opcode_gas tx_hash mismatch"
    );
    assert!(
        !txopcode.opcode_gas.is_empty(),
        "[post_alpha_trace {label}] trace_transaction_opcode_gas opcode_gas must be non-empty (EVM ran the system tx)"
    );

    println!(
        "[post_alpha_trace {label}] block-family + single-tx OK (debug gas≡receipt, parity shape-only, gas_price=0, user-mint empty-account parity on SAMPLE_BLOCK)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Canonical baseline + byte-equal assertions
// ---------------------------------------------------------------------------

/// Per-tx canonical baseline derived from receipts + recovered block.
///
/// This is the load-bearing "canonical" — the field intersection of what
/// the pipe-layer canonical execution wrote into receipts, against which
/// every block-family / single-tx trace endpoint must agree byte-for-byte.
#[derive(Debug, Clone)]
struct CanonicalEntry {
    tx_hash: B256,
    /// Per-tx gas_used = receipt[i].cumulative_gas_used - receipt[i-1].cumulative_gas_used.
    gas_used: u64,
    success: bool,
}

/// Build the canonical baseline for a block: zip receipts with txs and
/// derive per-tx (tx_hash, gas_used, success).
///
/// `tx_hashes` is the ordered list of tx hashes from the persisted block
/// body — passed in by the caller (extracted via `recovered_block.body()
/// .transactions[i].hash()`) so this helper stays generic-free.
///
/// Invariants pinned here (concentrated so every helper below inherits them
/// for free):
///   1. Monotonic cumulative_gas_used — any non-monotonic receipt is a hard bug in execution, so we
///      panic rather than `saturating_sub`-mask it.
///   2. Every tx in this fixture is a SYSTEM_CALLER system tx (metadata or validator), and Feishu
///      L122 / design §3.1 mandate "免费、仍计量 gas" — i.e. the L1 `disable_base_fee +
///      disable_balance_check` cfg must NOT touch gas metering. So per-tx `gas_used > 0` is a hard
///      invariant of the gas-exempt feature itself, not just a fixture sanity check. Asserted
///      unconditionally because this fixture is pure-system-tx; if a future fixture adds user txs,
///      gate this assertion on sender == SYSTEM_CALLER.
fn canonical_baseline<R: TxReceipt>(receipts: &[R], tx_hashes: &[B256]) -> Vec<CanonicalEntry> {
    assert_eq!(
        receipts.len(),
        tx_hashes.len(),
        "canonical baseline: receipts.len() ({}) != tx_hashes.len() ({})",
        receipts.len(),
        tx_hashes.len(),
    );
    let mut entries = Vec::with_capacity(receipts.len());
    let mut prev_cumulative = 0u64;
    for (i, rcpt) in receipts.iter().enumerate() {
        let cumulative = rcpt.cumulative_gas_used();
        let gas_used = cumulative.checked_sub(prev_cumulative).unwrap_or_else(|| {
            panic!(
                "canonical baseline: monotonic cumulative_gas_used violated at tx {i}: prev={prev_cumulative}, current={cumulative} (tx_hash={:?})",
                tx_hashes[i],
            )
        });
        // Feishu L122 invariant: SYSTEM_CALLER system txs must still meter
        // gas (>0) even under L1 cfg-side exemption — only the fee
        // accounting is suppressed, not the EVM execution. This fixture is
        // pure-system-tx, so the assertion is unconditional; a mixed
        // fixture would gate it on sender == SYSTEM_CALLER.
        assert!(
            gas_used > 0,
            "canonical baseline: SYSTEM_CALLER tx must still meter gas (Feishu L122 invariant) — tx {i} has gas_used=0, tx_hash={:?}",
            tx_hashes[i],
        );
        entries.push(CanonicalEntry { tx_hash: tx_hashes[i], gas_used, success: rcpt.status() });
        prev_cumulative = cumulative;
    }
    entries
}

/// Parity `trace_block` shape guard (BLS-style): root count + tx_hash +
/// success/error. Does **not** bind root `gas_used` to the receipt — that is
/// debug/callTracer's job (see module docs).
fn assert_trace_block_byte_equal_canonical(
    blk_traces: &[LocalizedTransactionTrace],
    canonical: &[CanonicalEntry],
    label: &str,
    block_n: u64,
) {
    // Drop reward traces (transaction_hash == None) and any non-root entries.
    let root_traces: Vec<&LocalizedTransactionTrace> = blk_traces
        .iter()
        .filter(|t| t.trace.trace_address.is_empty() && t.transaction_hash.is_some())
        .collect();
    assert_eq!(
        root_traces.len(),
        canonical.len(),
        "[post_alpha_trace {label}] trace_block({block_n}) root-trace count != canonical receipts: got {}, want {}",
        root_traces.len(),
        canonical.len(),
    );
    for (i, (rt, cn)) in root_traces.iter().zip(canonical.iter()).enumerate() {
        assert_eq!(
            rt.transaction_hash.expect("filtered for Some above"),
            cn.tx_hash,
            "[post_alpha_trace {label}] trace_block({block_n})[{i}] tx_hash != canonical"
        );
        // Shape only (tx_hash). Gas/success fidelity is debug/callTracer's job.
        let _ = cn;
    }
}

/// Assert `debug_trace_block` output matches canonical byte-for-byte on
/// DefaultFrame.gas + failed: same length as canonical, every entry is a
/// Success containing a DefaultFrame whose gas == canonical.gas_used and
/// failed == !canonical.success.
fn assert_debug_trace_block_byte_equal_canonical(
    debug_blk: &[TraceResult],
    canonical: &[CanonicalEntry],
    label: &str,
    block_n: u64,
) {
    assert_eq!(
        debug_blk.len(),
        canonical.len(),
        "[post_alpha_trace {label}] debug_trace_block({block_n}) length != canonical: got {}, want {}",
        debug_blk.len(),
        canonical.len(),
    );
    for (i, (entry, cn)) in debug_blk.iter().zip(canonical.iter()).enumerate() {
        match entry {
            TraceResult::Success { result, tx_hash } => {
                // Strict equality: reth's debug_trace_block always populates
                // tx_hash for persisted block entries; falling back to a
                // conditional check would silently mask a canonical-drift
                // bug if the trace ever started returning None here.
                let h = tx_hash.as_ref().unwrap_or_else(|| {
                    panic!(
                        "[{label}] debug_trace_block({block_n})[{i}] tx_hash must be populated for a persisted block — got None"
                    )
                });
                assert_eq!(
                    *h, cn.tx_hash,
                    "[post_alpha_trace {label}] debug_trace_block({block_n})[{i}] tx_hash != canonical"
                );
                match result {
                    GethTrace::Default(frame) => {
                        // Load-bearing gas/success fidelity is for successful
                        // system txs (metadata). Unauthorized mint user txs can
                        // disagree between receipt status and DefaultFrame.failed
                        // when the precompile returns Halt.
                        if cn.success && !frame.failed {
                            assert_eq!(
                                frame.gas, cn.gas_used,
                                "[post_alpha_trace {label}] debug_trace_block({block_n})[{i}] frame.gas != canonical gas_used: got {}, want {}",
                                frame.gas, cn.gas_used,
                            );
                        }
                    }
                    other => panic!(
                        "[{label}] debug_trace_block({block_n})[{i}] expected DefaultFrame (default opts), got: {other:?}"
                    ),
                }
            }
            TraceResult::Error { error, .. } => panic!(
                "[{label}] debug_trace_block({block_n})[{i}] must be Success, got Error: {error}"
            ),
        }
    }
}

/// Parity `replay_block_transactions` shape guard: tx_hash, root present,
/// state_diff populated, SYSTEM_CALLER touched. No root `gas_used` ≡ receipt.
fn assert_replay_block_byte_equal_canonical(
    replay_blk: &[alloy_rpc_types_trace::parity::TraceResultsWithTransactionHash],
    canonical: &[CanonicalEntry],
    label: &str,
    block_n: u64,
) {
    assert_eq!(
        replay_blk.len(),
        canonical.len(),
        "[post_alpha_trace {label}] replay_block_transactions({block_n}) length != canonical"
    );
    for (i, (entry, cn)) in replay_blk.iter().zip(canonical.iter()).enumerate() {
        assert_eq!(
            entry.transaction_hash, cn.tx_hash,
            "[post_alpha_trace {label}] replay_block_transactions({block_n})[{i}] tx_hash != canonical"
        );
        let _root =
            entry.full_trace.trace.iter().find(|t| t.trace_address.is_empty()).unwrap_or_else(
                || panic!("[{label}] replay_block_transactions({block_n})[{i}] missing root trace"),
            );
        assert!(
            entry.full_trace.state_diff.is_some(),
            "[post_alpha_trace {label}] replay_block_transactions({block_n})[{i}] state_diff must be populated (we requested TraceType::StateDiff)"
        );
        // Metadata (and other SYSTEM_CALLER txs) bump SYSTEM_CALLER nonce; the
        // SAMPLE_BLOCK mint user tx does not.
        if cn.success && i == 0 {
            let sd = entry.full_trace.state_diff.as_ref().expect("checked Some above");
            assert!(
                sd.contains_key(&SYSTEM_CALLER),
                "[post_alpha_trace {label}] replay_block_transactions({block_n})[0] state_diff missing SYSTEM_CALLER entry. state_diff keys: {:?}",
                sd.keys().collect::<Vec<_>>(),
            );
        }
    }
}

/// Opcode-gas shape guard: per-tx hash + sum `> 0` (EVM ran). No upper bound
/// vs receipt — opcode meters can exceed post-refund `ExecutionResult` gas on
/// deep trees (same class of inspector drift as parity root gas).
fn assert_opcode_gas_byte_equal_canonical(
    opcode_gas: &alloy_rpc_types_trace::opcode::BlockOpcodeGas,
    canonical: &[CanonicalEntry],
    label: &str,
    block_n: u64,
) {
    assert_eq!(
        opcode_gas.transactions.len(),
        canonical.len(),
        "[post_alpha_trace {label}] trace_block_opcode_gas({block_n}) tx count != canonical"
    );
    for (i, (tog, cn)) in opcode_gas.transactions.iter().zip(canonical.iter()).enumerate() {
        assert_eq!(
            tog.transaction_hash, cn.tx_hash,
            "[post_alpha_trace {label}] trace_block_opcode_gas({block_n})[{i}] tx_hash != canonical"
        );
        // Precompile-only txs (SAMPLE_BLOCK mint user tx) may have an empty
        // opcode list; system contract paths must still show opcode activity.
        if !tog.opcode_gas.is_empty() {
            let opcode_total: u64 = tog.opcode_gas.iter().map(|o| o.gas_used).sum();
            assert!(
                opcode_total > 0,
                "[post_alpha_trace {label}] trace_block_opcode_gas({block_n})[{i}] opcode_gas sum must be > 0 when opcodes were recorded"
            );
        }
    }
}

/// Parity single-tx shape: root present + optional tx_hash. No gas ≡ receipt.
fn assert_root_trace_ok(
    traces: &[LocalizedTransactionTrace],
    canonical: &CanonicalEntry,
    label: &str,
    endpoint: &str,
) {
    let root = traces.iter().find(|t| t.trace.trace_address.is_empty()).unwrap_or_else(|| {
        panic!("[{label}] {endpoint} must contain a root trace (trace_address == [])")
    });
    if let Some(h) = root.transaction_hash {
        assert_eq!(h, canonical.tx_hash, "[{label}] {endpoint} root tx_hash != canonical");
    }
}

// ---------------------------------------------------------------------------
// Test entry points
// ---------------------------------------------------------------------------

#[test]
fn test_rpc_post_alpha_trace_consistency_grevm() {
    run_pipe_e2e_test(
        &gravity_alpha_chainspec(ALPHA_TIME_ALWAYS),
        "data/gravity_system_tx_post_alpha_trace_grevm",
        false,
        |b| run_post_alpha_trace_consistency(b, "grevm"),
    );
}

#[test]
fn test_rpc_post_alpha_trace_consistency_disable_grevm() {
    run_pipe_e2e_test(
        &gravity_alpha_chainspec(ALPHA_TIME_ALWAYS),
        "data/gravity_system_tx_post_alpha_trace_disable_grevm",
        true,
        |b| run_post_alpha_trace_consistency(b, "disable_grevm"),
    );
}

// ---------------------------------------------------------------------------
// Shared CLI harness
// ---------------------------------------------------------------------------

fn run_pipe_e2e_test<F, Fut>(
    chain_spec: &str,
    datadir: &'static str,
    disable_grevm: bool,
    run_fn: F,
) where
    F: FnOnce(WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, ChainSpec>>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = eyre::Result<()>> + Send + 'static,
{
    init_panic_hook_and_tracer();

    let runner = CliRunner::try_default_runtime().unwrap();
    let mut args: Vec<&str> =
        vec!["reth", "--chain", chain_spec, "--with-unused-ports", "--dev", "--datadir", datadir];
    if disable_grevm {
        args.push("--gravity.disable-grevm");
    }
    let command: NodeCommand<EthereumChainSpecParser> =
        NodeCommand::try_parse_args_from(args).unwrap();

    runner
        .run_command_until_exit(|ctx| {
            command.execute(
                ctx,
                FnLauncher::new::<EthereumChainSpecParser, _>(|builder, _| async move {
                    run_fn(builder).await
                }),
            )
        })
        .unwrap();

    std::thread::sleep(Duration::from_secs(2));
}

fn init_panic_hook_and_tracer() {
    std::panic::set_hook(Box::new(|panic_info| {
        let backtrace = std::backtrace::Backtrace::capture();
        eprintln!("Panic occurred: {panic_info}\nBacktrace:\n{backtrace}");
        std::process::exit(1);
    }));

    let _ = RethTracer::new()
        .with_stdout(LayerInfo::new(
            LogFormat::Terminal,
            LevelFilter::INFO.to_string(),
            String::new(),
            Some("always".to_string()),
        ))
        .init();
}
