use core::fmt::{Debug, Display};
use std::sync::Arc;

use reth_chainspec::ChainSpec;
use reth_evm::{
    execute::{BlockExecutionError, Executor, ParallelDatabase},
    ConfigureEvm,
};
use reth_execution_types::{BlockExecutionInput, BlockExecutionOutput};
use reth_grevm::{new_grevm_scheduler, GrevmScheduler};

use reth_primitives::{BlockWithSenders, Receipt};
use revm_primitives::{BlockEnv, CfgEnvWithHandlerCfg, EnvWithHandlerCfg, TxEnv};

pub struct EthGrevmExecutor<EvmConfig, DB> {
    chain_spec: Arc<ChainSpec>,
    evm_config: EvmConfig,
    database: DB,
}

impl<EvmConfig, DB> EthGrevmExecutor<EvmConfig, DB> {
    pub fn new(chain_spec: Arc<ChainSpec>, evm_config: EvmConfig, database: DB) -> Self {
        Self { chain_spec, evm_config, database }
    }
}

impl<EvmConfig, DB> Executor<DB> for EthGrevmExecutor<EvmConfig, DB>
where
    EvmConfig: ConfigureEvm,
    DB: ParallelDatabase<Error: Display + Clone>,
{
    type Input<'a> = BlockExecutionInput<'a, BlockWithSenders>;
    type Output = BlockExecutionOutput<Receipt>;
    type Error = BlockExecutionError;

    fn execute(self, input: Self::Input<'_>) -> Result<Self::Output, Self::Error> {
        // Initialize evm env
        let mut cfg = CfgEnvWithHandlerCfg::new(Default::default(), Default::default());
        let mut block_env = BlockEnv::default();
        self.evm_config.fill_cfg_and_block_env(
            &mut cfg,
            &mut block_env,
            self.chain_spec.as_ref(),
            &input.block.header,
            input.total_difficulty,
        );
        let env = EnvWithHandlerCfg::new_with_cfg_env(cfg, block_env, Default::default());

        // Fill TxEnv from transaction
        let mut txs = vec![TxEnv::default(); input.block.body.len()];
        for (tx_env, (sender, tx)) in txs.iter_mut().zip(input.block.transactions_with_sender()) {
            self.evm_config.fill_tx_env(tx_env, tx, *sender);
        }

        let executor = new_grevm_scheduler(env.spec_id(), *env.env, self.database, txs);
        let output = executor.parallel_execute().map_err(|e| BlockExecutionError::msg(e))?;

        let mut receipts = Vec::with_capacity(output.results.len());
        let mut cumulative_gas_used = 0;
        for (result, tx_type) in
            output.results.into_iter().zip(input.block.transactions().map(|tx| tx.tx_type()))
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

        Ok(BlockExecutionOutput {
            state: output.state,
            receipts,
            requests: vec![],
            gas_used: cumulative_gas_used,
        })
    }
}
