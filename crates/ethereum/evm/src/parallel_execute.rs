//! Ethereum block executor using grevm.

use crate::{
    dao_fork::{DAO_HARDFORK_BENEFICIARY, DAO_HARDKFORK_ACCOUNTS},
    execute::EthExecuteOutput,
};
use std::sync::Arc;

use crate::debug_ext::DEBUG_EXT;
use reth_chainspec::{ChainSpec, EthereumHardfork, EthereumHardforks};
use reth_ethereum_consensus::validate_block_post_execution;
use reth_evm::{
    execute::{
        BatchExecutor, BlockExecutionError, BlockValidationError, Executor, ParallelDatabase,
        ParallelExecutorProvider,
    },
    system_calls::{
        apply_beacon_root_contract_call, apply_blockhashes_contract_call,
        apply_consolidation_requests_contract_call, apply_withdrawal_requests_contract_call,
    },
    ConfigureEvm,
};
use reth_execution_types::{BlockExecutionInput, BlockExecutionOutput, ExecutionOutcome};
use reth_grevm::new_grevm_scheduler;
use reth_primitives::{BlockNumber, BlockWithSenders, Header, Receipt};
use reth_prune_types::PruneModes;
use reth_revm::{
    batch::BlockBatchRecord,
    db::{states::bundle_state::BundleRetention, State},
    state_change::post_block_balance_increments,
};
use revm_primitives::{
    db::WrapDatabaseRef, BlockEnv, CfgEnvWithHandlerCfg, EnvWithHandlerCfg, TxEnv, U256,
};
use tracing::*;

/// Provides grevm executors to execute regular ethereum blocks
#[derive(Debug)]
pub struct GrevmExecutorProvider<'a, EvmConfig> {
    chain_spec: &'a Arc<ChainSpec>,
    evm_config: &'a EvmConfig,
}

impl<'a, EvmConfig> GrevmExecutorProvider<'a, EvmConfig> {
    /// Create a new instance of the provider
    pub fn new(chain_spec: &'a Arc<ChainSpec>, evm_config: &'a EvmConfig) -> Self {
        Self { chain_spec, evm_config }
    }
}

impl<EvmConfig> ParallelExecutorProvider for GrevmExecutorProvider<'_, EvmConfig>
where
    EvmConfig: ConfigureEvm<Header = Header>,
{
    type Executor<DB: ParallelDatabase> = GrevmBlockExecutor<EvmConfig, DB>;

    type BatchExecutor<DB: ParallelDatabase> = GrevmBatchExecutor<EvmConfig, DB>;

    fn executor<DB>(&self, db: DB) -> Self::Executor<DB>
    where
        DB: ParallelDatabase,
    {
        GrevmBlockExecutor::new(self.chain_spec.clone(), self.evm_config.clone(), db)
    }

    fn batch_executor<DB>(&self, db: DB) -> Self::BatchExecutor<DB>
    where
        DB: ParallelDatabase,
    {
        GrevmBatchExecutor {
            executor: GrevmBlockExecutor::new(self.chain_spec.clone(), self.evm_config.clone(), db),
            batch_record: BlockBatchRecord::default(),
        }
    }
}

/// A basic Ethereum block executor.
///
/// Expected usage:
/// - Create a new instance of the executor.
/// - Execute the block.
#[derive(Debug)]
pub struct GrevmBlockExecutor<EvmConfig, DB>
where
    DB: ParallelDatabase,
{
    chain_spec: Arc<ChainSpec>,
    evm_config: EvmConfig,
    state: State<WrapDatabaseRef<DB>>,
}

impl<EvmConfig, DB> GrevmBlockExecutor<EvmConfig, DB>
where
    DB: ParallelDatabase,
{
    /// Create a new instance of the executor
    pub fn new(chain_spec: Arc<ChainSpec>, evm_config: EvmConfig, database: DB) -> Self {
        Self {
            chain_spec,
            evm_config,
            state: State::builder()
                .with_database(database.into())
                .with_bundle_update()
                .without_state_clear()
                .build(),
        }
    }
}

impl<EvmConfig, DB> Executor<DB> for GrevmBlockExecutor<EvmConfig, DB>
where
    EvmConfig: ConfigureEvm<Header = Header>,
    DB: ParallelDatabase,
{
    type Input<'a> = BlockExecutionInput<'a, BlockWithSenders>;
    type Output = BlockExecutionOutput<Receipt>;
    type Error = BlockExecutionError;

    fn execute(mut self, input: Self::Input<'_>) -> Result<Self::Output, Self::Error> {
        let BlockExecutionInput { block, total_difficulty } = input;
        let EthExecuteOutput { receipts, requests, gas_used } =
            self.execute_without_verification(block, total_difficulty)?;

        // NOTE: we need to merge keep the reverts for the bundle retention
        self.state.merge_transitions(BundleRetention::Reverts);
        Ok(BlockExecutionOutput { state: self.state.take_bundle(), receipts, requests, gas_used })
    }
}

impl<EvmConfig, DB> GrevmBlockExecutor<EvmConfig, DB>
where
    EvmConfig: ConfigureEvm<Header = Header>,
    DB: ParallelDatabase,
{
    /// Execute a single block and apply the state changes to the internal state.
    ///
    /// Returns the receipts of the transactions in the block, the total gas used and the list of
    /// EIP-7685 [requests](Request).
    ///
    /// Returns an error if execution fails.
    fn execute_without_verification(
        &mut self,
        block: &BlockWithSenders,
        total_difficulty: U256,
    ) -> Result<EthExecuteOutput, BlockExecutionError> {
        debug!(target: "GrevmBlockExecutor", "Executing block {}", block.number);

        let revm_transition_state = if DEBUG_EXT.compare_with_revm_executor {
            let mut state = State::builder()
                .with_database(self.state.database.clone())
                .with_bundle_update()
                .without_state_clear()
                .build();
            state.cache = self.state.cache.clone();
            state.transition_state = self.state.transition_state.clone();
            state.bundle_state = self.state.bundle_state.clone();
            state.block_hashes = self.state.block_hashes.clone();
            let mut executor = super::execute::EthBlockExecutor::new(
                self.chain_spec.clone(),
                self.evm_config.clone(),
                state,
            );
            let _ = executor.execute_without_verification(block, total_difficulty).unwrap();
            Some(executor.state.transition_state.unwrap())
        } else {
            None
        };

        // Prepare state on new block
        self.on_new_block(&block.header);

        // Configure the evm and execute
        let env = self.evm_env_for_block(&block.header, total_difficulty);
        self.pre_execution(block, &env)?;

        // Fill TxEnv from transaction
        let mut txs = vec![TxEnv::default(); block.body.len()];
        for (tx_env, (sender, tx)) in txs.iter_mut().zip(block.transactions_with_sender()) {
            self.evm_config.fill_tx_env(tx_env, tx, *sender);
        }

        let txs = Arc::new(txs);
        // TODO(gravity): pipeline hints generation
        let mut executor = new_grevm_scheduler(
            env.spec_id(),
            env.env.as_ref().clone(),
            self.state.database.0.clone(),
            txs.clone(),
            Some(Box::new(reth_grevm::storage::State {
                cache: std::mem::take(&mut self.state.cache),
                transition_state: std::mem::take(&mut self.state.transition_state),
                bundle_state: std::mem::take(&mut self.state.bundle_state),
                block_hashes: std::mem::take(&mut self.state.block_hashes),
            })),
        );
        let output = if DEBUG_EXT.force_seq_exec {
            executor.force_sequential_execute().map_err(|e| BlockExecutionError::msg(e))?
        } else {
            if DEBUG_EXT.compare_with_seq_exec {
                let mut seq_executor = new_grevm_scheduler(
                    env.spec_id(),
                    env.env.as_ref().clone(),
                    self.state.database.0.clone(),
                    txs.clone(),
                    Some(executor.database.state.clone()),
                );
                seq_executor.force_sequential_execute().map_err(|e| BlockExecutionError::msg(e))?;
                let output =
                    executor.parallel_execute().map_err(|e| BlockExecutionError::msg(e))?;
                let seq_state = seq_executor.take_state();
                if !crate::debug_ext::compare_transition_state(
                    seq_state.transition_state.as_ref().unwrap(),
                    executor.database.state.transition_state.as_ref().unwrap(),
                ) {
                    crate::debug_ext::dump_transitions(
                        block.number,
                        seq_state.transition_state.as_ref().unwrap(),
                        "seq_transitions.json",
                    )
                    .unwrap();
                    crate::debug_ext::dump_transitions(
                        block.number,
                        executor.database.state.transition_state.as_ref().unwrap(),
                        "parallel_transitions.json",
                    )
                    .unwrap();
                    crate::debug_ext::dump_block_env(
                        &env,
                        &txs.as_ref(),
                        &seq_state.cache,
                        &seq_state.transition_state.as_ref().unwrap(),
                        &seq_state.block_hashes,
                    )
                    .unwrap();
                    panic!("Transition state mismatch, block number: {}", block.number);
                }
                output
            } else {
                executor.parallel_execute().map_err(|e| BlockExecutionError::msg(e))?
            }
        };

        // Take state from grevm scheduler after execution
        let state = executor.take_state();
        self.state.cache = state.cache;
        self.state.transition_state = state.transition_state;
        self.state.bundle_state = state.bundle_state;
        self.state.block_hashes = state.block_hashes;

        if DEBUG_EXT.dump_block_env {
            if let Err(err) = crate::debug_ext::dump_block_env(
                &env,
                &txs.as_ref(),
                &self.state.cache,
                self.state.transition_state.as_ref().unwrap(),
                &self.state.block_hashes,
            ) {
                eprintln!("Failed to dump block env: {err}");
            }
        }

        if DEBUG_EXT.dump_transitions {
            if let Err(err) = crate::debug_ext::dump_transitions(
                block.number,
                self.state.transition_state.as_ref().unwrap(),
                "transitions.json",
            ) {
                eprintln!("Failed to dump transitions: {err}");
            }
        }

        let mut receipts = Vec::with_capacity(output.results.len());
        let mut cumulative_gas_used = 0;
        for (result, tx_type) in
            output.results.into_iter().zip(block.transactions().map(|tx| tx.tx_type()))
        {
            cumulative_gas_used += result.gas_used();
            receipts.push(Receipt {
                tx_type,
                success: result.is_success(),
                cumulative_gas_used,
                logs: result.into_logs(),
                ..Default::default()
            });
        }

        if DEBUG_EXT.dump_receipts {
            if let Err(err) = crate::debug_ext::dump_receipts(block.number, &receipts) {
                eprintln!("Failed to dump receipts: {err}");
            }
        }

        let requests = if self.chain_spec.is_prague_active_at_timestamp(block.timestamp) {
            // Collect all EIP-6110 deposits
            let deposit_requests =
                crate::eip6110::parse_deposits_from_receipts(&self.chain_spec, &receipts)?;

            let mut evm = self.evm_config.evm_with_env(&mut self.state, env);

            // Collect all EIP-7685 requests
            let withdrawal_requests =
                apply_withdrawal_requests_contract_call(&self.evm_config, &mut evm)?;

            // Collect all EIP-7251 requests
            let consolidation_requests =
                apply_consolidation_requests_contract_call(&self.evm_config, &mut evm)?;

            [deposit_requests, withdrawal_requests, consolidation_requests].concat()
        } else {
            vec![]
        };

        // Apply post execution changes
        self.post_execution(block, total_difficulty)?;

        if let Some(revm_transition_state) = revm_transition_state.as_ref() {
            // Debug compare transition state between grevm executor and revm executor
            if revm_transition_state != self.state.transition_state.as_ref().unwrap() {
                crate::debug_ext::dump_transitions(
                    block.number,
                    revm_transition_state,
                    "revm_transitions.json",
                )
                .unwrap();
                crate::debug_ext::dump_transitions(
                    block.number,
                    self.state.transition_state.as_ref().unwrap(),
                    "grevm_transitions.json",
                )
                .unwrap();
                panic!("Transition state mismatch, block number: {}", block.number);
            }
        }

        Ok(EthExecuteOutput { receipts, requests, gas_used: cumulative_gas_used })
    }

    /// Apply settings before a new block is executed.
    fn on_new_block(&mut self, header: &Header) {
        // Set state clear flag if the block is after the Spurious Dragon hardfork.
        let state_clear_flag = self.chain_spec.is_spurious_dragon_active_at_block(header.number);
        self.state.set_state_clear_flag(state_clear_flag);
    }

    fn evm_env_for_block(&self, header: &Header, total_difficulty: U256) -> EnvWithHandlerCfg {
        let mut cfg = CfgEnvWithHandlerCfg::new(Default::default(), Default::default());
        let mut block_env = BlockEnv::default();
        self.evm_config.fill_cfg_and_block_env(&mut cfg, &mut block_env, header, total_difficulty);
        EnvWithHandlerCfg::new_with_cfg_env(cfg, block_env, Default::default())
    }

    /// Apply pre execution changes
    fn pre_execution(
        &mut self,
        block: &BlockWithSenders,
        env: &EnvWithHandlerCfg,
    ) -> Result<(), BlockExecutionError> {
        if !self.chain_spec.is_cancun_active_at_timestamp(block.timestamp) {
            return Ok(())
        }

        let mut evm = self.evm_config.evm_with_env(&mut self.state, env.clone());
        apply_beacon_root_contract_call(
            &self.evm_config,
            &self.chain_spec,
            block.timestamp,
            block.number,
            block.parent_beacon_block_root,
            &mut evm,
        )?;
        apply_blockhashes_contract_call(
            &self.evm_config,
            &self.chain_spec,
            block.timestamp,
            block.number,
            block.parent_hash,
            &mut evm,
        )
    }

    /// Apply post execution state changes that do not require an [EVM](Evm), such as: block
    /// rewards, withdrawals, and irregular DAO hardfork state change
    pub fn post_execution(
        &mut self,
        block: &BlockWithSenders,
        total_difficulty: U256,
    ) -> Result<(), BlockExecutionError> {
        let mut balance_increments =
            post_block_balance_increments(self.chain_spec.as_ref(), block, total_difficulty);

        // Irregular state change at Ethereum DAO hardfork
        if self.chain_spec.as_ref().fork(EthereumHardfork::Dao).transitions_at_block(block.number) {
            // drain balances from hardcoded addresses.
            let drained_balance: u128 = self
                .state
                .drain_balances(DAO_HARDKFORK_ACCOUNTS)
                .map_err(|_| BlockValidationError::IncrementBalanceFailed)?
                .into_iter()
                .sum();

            // return balance to DAO beneficiary.
            *balance_increments.entry(DAO_HARDFORK_BENEFICIARY).or_default() += drained_balance;
        }
        // increment balances
        self.state
            .increment_balances(balance_increments)
            .map_err(|_| BlockValidationError::IncrementBalanceFailed)?;
        Ok(())
    }
}

/// An executor for a batch of blocks.
///
/// State changes are tracked until the executor is finalized.
#[derive(Debug)]
pub struct GrevmBatchExecutor<EvmConfig, DB>
where
    DB: ParallelDatabase,
{
    /// The executor used to execute single blocks
    ///
    /// All state changes are committed to the [CacheState].
    executor: GrevmBlockExecutor<EvmConfig, DB>,
    /// Keeps track of the batch and records receipts based on the configured prune mode
    batch_record: BlockBatchRecord,
}

impl<EvmConfig, DB> BatchExecutor<DB> for GrevmBatchExecutor<EvmConfig, DB>
where
    EvmConfig: ConfigureEvm<Header = Header>,
    DB: ParallelDatabase,
{
    type Input<'a> = BlockExecutionInput<'a, BlockWithSenders>;
    type Output = ExecutionOutcome;
    type Error = BlockExecutionError;

    fn execute_and_verify_one(&mut self, input: Self::Input<'_>) -> Result<(), Self::Error> {
        let BlockExecutionInput { block, total_difficulty } = input;

        if self.batch_record.first_block().is_none() {
            self.batch_record.set_first_block(block.number);
        }

        let EthExecuteOutput { receipts, requests, gas_used: _ } =
            self.executor.execute_without_verification(block, total_difficulty)?;

        validate_block_post_execution(
            block,
            self.executor.chain_spec.as_ref(),
            &receipts,
            &requests,
        )?;

        // prepare the state according to the prune mode
        let retention = self.batch_record.bundle_retention(block.number);
        self.executor.state.merge_transitions(retention);

        // store receipts in the set
        self.batch_record.save_receipts(receipts)?;

        // store requests in the set
        self.batch_record.save_requests(requests);

        Ok(())
    }

    fn finalize(mut self) -> Self::Output {
        ExecutionOutcome::new(
            self.executor.state.take_bundle(),
            self.batch_record.take_receipts(),
            self.batch_record.first_block().unwrap_or_default(),
            self.batch_record.take_requests(),
        )
    }

    fn set_tip(&mut self, tip: BlockNumber) {
        self.batch_record.set_tip(tip);
    }

    fn set_prune_modes(&mut self, prune_modes: PruneModes) {
        self.batch_record.set_prune_modes(prune_modes);
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.executor.state.bundle_state.size_hint())
    }
}
