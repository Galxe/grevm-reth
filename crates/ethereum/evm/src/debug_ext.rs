#![allow(missing_docs)]

use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    io::{BufWriter, Write},
};

use lazy_static::lazy_static;
use reth_primitives::{Address, B256};
use reth_revm::{
    db::PlainAccount, primitives::AccountInfo, CacheState, TransitionAccount, TransitionState,
};
use revm_primitives::{EnvWithHandlerCfg, TxEnv};

#[derive(Debug)]
pub(crate) struct DebugExtArgs {
    pub disable_grevm: bool,
    pub force_seq_exec: bool,
    pub dump_block_path: String,
    pub dump_transition: bool,
}

lazy_static! {
    pub(crate) static ref DEBUG_EXT: DebugExtArgs = DebugExtArgs {
        disable_grevm: std::env::var("EVM_DISABLE_GREVM").is_ok(),
        force_seq_exec: std::env::var("EVM_FORCE_SEQ_EXEC").is_ok(),
        dump_block_path: std::env::var("EVM_DUMP_BLOCK_PATH").unwrap_or_default(),
        dump_transition: std::env::var("EVM_DUMP_TRANSITION").is_ok(),
    };
}

pub(crate) fn dump_block_data(
    env: &EnvWithHandlerCfg,
    txs: &[TxEnv],
    cache_state: &CacheState,
    transition_state: &TransitionState,
    block_hashes: &BTreeMap<u64, B256>,
) -> Result<(), Box<dyn Error>> {
    let path = format!("{}/{}", DEBUG_EXT.dump_block_path, env.block.number);
    std::fs::create_dir_all(&path)?;

    // Write env data to file
    serde_json::to_writer(BufWriter::new(std::fs::File::create(format!("{path}/env.json"))?), env)?;

    // Write txs data to file
    serde_json::to_writer(BufWriter::new(std::fs::File::create(format!("{path}/txs.json"))?), txs)?;

    if DEBUG_EXT.dump_transition {
        // Write transition state data to file
        let sorted: BTreeMap<Address, TransitionAccount> = transition_state
            .transitions
            .iter()
            .map(|(addr, account)| {
                (
                    *addr,
                    TransitionAccount {
                        info: account.info.as_ref().and_then(|info| {
                            Some(AccountInfo {
                                balance: info.balance,
                                nonce: info.nonce,
                                code_hash: info.code_hash,
                                code: None,
                            })
                        }),
                        status: account.status,
                        previous_info: account.previous_info.as_ref().and_then(|info| {
                            Some(AccountInfo {
                                balance: info.balance,
                                nonce: info.nonce,
                                code_hash: info.code_hash,
                                code: None,
                            })
                        }),
                        previous_status: account.previous_status,
                        storage: account.storage.clone(),
                        storage_was_destroyed: account.storage_was_destroyed,
                    },
                )
            })
            .collect();

        BufWriter::new(std::fs::File::create(format!("{path}/transitions"))?)
            .write(format!("{sorted:?}").as_bytes())?;
    }

    // Write pre-state and bytecodes data to file
    let mut pre_state: HashMap<Address, PlainAccount> =
        HashMap::with_capacity(transition_state.transitions.len());
    for (addr, account) in cache_state.accounts.iter() {
        if let Some(transition_account) = transition_state.transitions.get(addr) {
            if let Some(info) = transition_account.previous_info.as_ref() {
                // account has been modified, use previous info
                pre_state.insert(
                    *addr,
                    PlainAccount {
                        info: AccountInfo {
                            balance: info.balance,
                            nonce: info.nonce,
                            code_hash: info.code_hash,
                            code: None,
                        },
                        storage: transition_account
                            .storage
                            .iter()
                            .map(|(k, v)| (*k, v.original_value()))
                            .collect(),
                    },
                );
            } else if let Some(account) = account.account.as_ref() {
                // account has not been modified, use current info
                pre_state.insert(
                    *addr,
                    PlainAccount {
                        info: AccountInfo {
                            balance: account.info.balance,
                            nonce: account.info.nonce,
                            code_hash: account.info.code_hash,
                            code: None,
                        },
                        storage: account.storage.clone(),
                    },
                );
            }
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
