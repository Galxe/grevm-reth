#![allow(missing_docs)]

use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    io::BufWriter,
};

use once_cell::sync::Lazy;
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
    pub compare_with_revm_executor: bool,
}

pub(crate) static DEBUG_EXT: Lazy<DebugExtArgs> = Lazy::new(|| DebugExtArgs {
    disable_grevm: std::env::var("EVM_DISABLE_GREVM").is_ok(),
    force_seq_exec: std::env::var("EVM_FORCE_SEQ_EXEC").is_ok(),
    dump_path: std::env::var("EVM_DUMP_PATH").unwrap_or("data/blocks".to_string()),
    dump_transitions: std::env::var("EVM_DUMP_TRANSITIONS").is_ok(),
    dump_block_env: std::env::var("EVM_BLOCK_ENV").is_ok(),
    dump_receipts: std::env::var("EVM_DUMP_RECEIPTS").is_ok(),
    compare_with_seq_exec: std::env::var("EVM_COMPARE_WITH_SEQ_EXEC").is_ok(),
    compare_with_revm_executor: std::env::var("EVM_COMPARE_WITH_REVM_EXECUTOR").is_ok(),
});

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
    let mut bytecodes = cache_state.contracts.clone();
    for (addr, account) in cache_state.accounts.iter() {
        if let Some(transition_account) = transition_state.transitions.get(addr) {
            // account has been modified by execution, use previous info
            if let Some(info) = transition_account.previous_info.as_ref() {
                let mut storage = if let Some(account) = account.account.as_ref() {
                    account.storage.clone()
                } else {
                    HashMap::new()
                };
                storage.extend(
                    transition_account.storage.iter().map(|(k, v)| (*k, v.original_value())),
                );

                let mut info = info.clone();
                if let Some(code) = info.code.take() {
                    bytecodes.entry(info.code_hash).or_insert_with(|| code);
                }
                pre_state.insert(*addr, PlainAccount { info, storage });
            }
        } else if let Some(account) = account.account.as_ref() {
            // account has not been modified, use current info in cache
            let mut account = account.clone();
            if let Some(code) = account.info.code.take() {
                bytecodes.entry(account.info.code_hash).or_insert_with(|| code);
            }
            pre_state.insert(*addr, account.clone());
        }
    }

    serde_json::to_writer(
        BufWriter::new(std::fs::File::create(format!("{path}/pre_state.json"))?),
        &pre_state,
    )?;
    bincode::serialize_into(
        BufWriter::new(std::fs::File::create(format!("{path}/bytecodes.bincode"))?),
        &bytecodes,
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

/// Compare two transition states, return true if they are equal
pub(crate) fn compare_transition_state(left: &TransitionState, right: &TransitionState) -> bool {
    if left.transitions.len() != right.transitions.len() {
        return false;
    }

    for (addr, left_account) in left.transitions.iter() {
        if let Some(right_account) = right.transitions.get(addr) {
            // Bundle state ignore previous status, so skip comparing it
            if left_account.info != right_account.info ||
                left_account.previous_info != right_account.previous_info ||
                left_account.storage != right_account.storage ||
                left_account.status != right_account.status
            {
                return false;
            }
        } else {
            return false;
        }
    }

    return true;
}
