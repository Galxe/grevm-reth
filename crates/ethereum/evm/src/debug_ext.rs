#![allow(missing_docs)]

use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    io::BufWriter,
};

use lazy_static::lazy_static;
use reth_primitives::{Address, Receipt, B256};
use reth_revm::{db::PlainAccount, CacheState, TransitionState};
use revm_primitives::{EnvWithHandlerCfg, TxEnv};

#[derive(Debug)]
pub(crate) struct DebugExtArgs {
    pub disable_grevm: bool,
    pub force_seq_exec: bool,
    pub dump_path: String,
    pub dump_transitions: bool,
    pub dump_block_env: bool,
    pub dump_receipts: bool,
    pub compare_with_seq_exec: bool,
}

lazy_static! {
    pub(crate) static ref DEBUG_EXT: DebugExtArgs = DebugExtArgs {
        disable_grevm: std::env::var("EVM_DISABLE_GREVM").is_ok(),
        force_seq_exec: std::env::var("EVM_FORCE_SEQ_EXEC").is_ok(),
        dump_path: std::env::var("EVM_DUMP_PATH").unwrap_or("data/blocks".to_string()),
        dump_transitions: std::env::var("EVM_DUMP_TRANSITIONS").is_ok(),
        dump_block_env: std::env::var("EVM_BLOCK_ENV").is_ok(),
        dump_receipts: std::env::var("EVM_DUMP_RECEIPTS").is_ok(),
        compare_with_seq_exec: std::env::var("EVM_COMPARE_WITH_SEQ_EXEC").is_ok(),
    };
}

pub(crate) fn dump_block_env(
    env: &EnvWithHandlerCfg,
    txs: &[TxEnv],
    cache_state: &CacheState,
    transition_state: &TransitionState,
    block_hashes: &BTreeMap<u64, B256>,
) -> Result<(), Box<dyn Error>> {
    let path = format!("{}/{}", DEBUG_EXT.dump_path, env.block.number);
    std::fs::create_dir_all(&path)?;

    // Write env data to file
    serde_json::to_writer(BufWriter::new(std::fs::File::create(format!("{path}/env.json"))?), env)?;

    // Write txs data to file
    serde_json::to_writer(BufWriter::new(std::fs::File::create(format!("{path}/txs.json"))?), txs)?;

    // Write pre-state and bytecodes data to file
    let mut pre_state: HashMap<Address, PlainAccount> =
        HashMap::with_capacity(transition_state.transitions.len());
    for (addr, account) in cache_state.accounts.iter() {
        if let Some(transition_account) = transition_state.transitions.get(addr) {
            // account has been modified by execution, use previous info
            if let Some(info) = transition_account.previous_info.as_ref() {
                pre_state.insert(
                    *addr,
                    PlainAccount {
                        info: info.clone(),
                        storage: transition_account
                            .storage
                            .iter()
                            .map(|(k, v)| (*k, v.original_value()))
                            .collect(),
                    },
                );
            }
        } else if let Some(account) = account.account.as_ref() {
            // account has not been modified, use current info in cache
            pre_state.insert(*addr, account.clone());
        }
    }

    serde_json::to_writer(
        BufWriter::new(std::fs::File::create(format!("{path}/pre_state.json"))?),
        &pre_state,
    )?;
    bincode::serialize_into(
        BufWriter::new(std::fs::File::create(format!("{path}/bytecodes.bincode"))?),
        &cache_state.contracts,
    )?;

    // Write block hashes to file
    serde_json::to_writer(
        BufWriter::new(std::fs::File::create(format!("{path}/block_hashes.json"))?),
        block_hashes,
    )?;

    Ok(())
}

pub(crate) fn dump_receipts(block_number: u64, receipts: &[Receipt]) -> Result<(), Box<dyn Error>> {
    let path = format!("{}/{}", DEBUG_EXT.dump_path, block_number);
    std::fs::create_dir_all(&path)?;

    // Write receipts data to file
    serde_json::to_writer(
        BufWriter::new(std::fs::File::create(format!("{path}/receipts.json"))?),
        receipts,
    )?;

    Ok(())
}

pub(crate) fn dump_transitions(
    block_number: u64,
    transitions: &TransitionState,
    filename: &str,
) -> Result<(), Box<dyn Error>> {
    let path = format!("{}/{}", DEBUG_EXT.dump_path, block_number);
    std::fs::create_dir_all(&path)?;

    // Write receipts data to file
    serde_json::to_writer(
        BufWriter::new(std::fs::File::create(format!("{path}/{filename}"))?),
        &transitions.transitions,
    )?;

    Ok(())
}
