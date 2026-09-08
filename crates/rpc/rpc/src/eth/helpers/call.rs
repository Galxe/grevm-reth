//! Contains RPC handler implementations specific to endpoints that call/execute within evm.

use crate::EthApi;
use alloy_consensus::BlockHeader;
use alloy_primitives::{B256, U256};
use gravity_precompiles::{
    bls_pop_verify::{create_bls_pop_verify_precompile, BLS_PRECOMPILE_ADDR},
    mint_token::{create_mint_token_precompile, NATIVE_MINT_PRECOMPILE_ADDR},
    randomness_by_height::{
        create_randomness_by_height_precompile, randomness_by_height_gas_policy_at_block,
        RandomnessByHeightGasPolicy, RandomnessByHeightLookup, RandomnessByHeightProvider,
        RANDOMNESS_BY_HEIGHT_PRECOMPILE_ADDR,
    },
};
use reth_chainspec::{is_system_tx_gas_exempt, ChainSpecProvider};
use reth_errors::ProviderError;
use reth_evm::{precompiles::PrecompilesMap, Evm};
use reth_rpc_convert::RpcConvert;
use reth_rpc_eth_api::{
    helpers::{estimate::EstimateCall, Call, EthCall},
    FromEvmError, RpcNodeCore,
};
use reth_rpc_eth_types::EthApiError;
use reth_storage_api::HeaderProvider;
use std::sync::Arc;

#[derive(Clone, Debug)]
struct HeaderRandomnessProvider<Provider> {
    provider: Provider,
    reference_number: u64,
    current_randomness: Option<B256>,
    gas_policy: RandomnessByHeightGasPolicy,
}

impl<Provider> HeaderRandomnessProvider<Provider> {
    const fn new(
        provider: Provider,
        reference_number: u64,
        current_randomness: Option<B256>,
        gas_policy: RandomnessByHeightGasPolicy,
    ) -> Self {
        Self { provider, reference_number, current_randomness, gas_policy }
    }
}

impl<Provider> RandomnessByHeightProvider for HeaderRandomnessProvider<Provider>
where
    Provider: HeaderProvider,
{
    type Error = ProviderError;

    fn randomness_by_height(&self, height: u64) -> Result<RandomnessByHeightLookup, Self::Error> {
        if height == self.reference_number && self.current_randomness.is_some() {
            return Ok(self.gas_policy.recent(self.current_randomness));
        }

        if height > self.reference_number {
            return Ok(self.gas_policy.recent(None));
        }

        let is_recent = self.reference_number - height <= self.gas_policy.recent_window;
        self.provider
            .header_by_number(height)
            .map(|header| header.and_then(|header| header.mix_hash()))
            .map(|value| {
                if is_recent {
                    self.gas_policy.recent(value)
                } else {
                    self.gas_policy.storage(value)
                }
            })
    }
}

impl<N, Rpc> EthCall for EthApi<N, Rpc>
where
    N: RpcNodeCore,
    EthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = EthApiError, Evm = N::Evm>,
{
}

impl<N, Rpc> Call for EthApi<N, Rpc>
where
    N: RpcNodeCore,
    EthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = EthApiError, Evm = N::Evm>,
{
    #[inline]
    fn call_gas_limit(&self) -> u64 {
        self.inner.gas_cap()
    }

    #[inline]
    fn max_simulate_blocks(&self) -> u64 {
        self.inner.max_simulate_blocks()
    }

    #[inline]
    fn compute_state_root_for_eth_simulate(&self) -> bool {
        self.inner.compute_state_root_for_eth_simulate()
    }

    #[inline]
    fn evm_memory_limit(&self) -> u64 {
        self.inner.evm_memory_limit()
    }

    fn register_custom_precompiles<EV>(
        &self,
        evm: &mut EV,
        block_number: U256,
        block_timestamp: U256,
        current_randomness: Option<B256>,
        for_system_tx: bool,
    ) where
        EV: Evm<Precompiles = PrecompilesMap>,
    {
        // BLS pop-verify precompile is registered **unconditionally** to mirror the pipe
        // execution layer, which has registered it both pre-Alpha (via `pre_alpha_precompiles`)
        // and post-Alpha. Gating it behind Alpha would cause RPC replay (debug_trace*, trace_*)
        // to diverge from canonical for any historical block — pre- *or* post-Alpha — that
        // calls `0x…625f5001`. See gravity-audit §3.5.0.
        let bls_precompile = create_bls_pop_verify_precompile();
        evm.precompiles_mut().apply_precompile(&BLS_PRECOMPILE_ADDR, move |_| Some(bls_precompile));

        // Mint mirrors pipe `system_precompiles` in `transact_system_txn` only — not
        // `custom_precompiles_for_ordered_block`. Registering it for user txs would make
        // a direct EOA CALL halt as unauthorized on RPC while canonical treats the mint
        // address as an empty account. See #372 / PR review.
        //
        // System set stops here (BLS + mint). Randomness is user-executor only on the
        // pipe; installing it for SYSTEM_CALLER replay would create the same divergence
        // class if a system tx reached `0x…1625f5002`.
        if for_system_tx {
            let mint_precompile = create_mint_token_precompile();
            evm.precompiles_mut()
                .apply_precompile(&NATIVE_MINT_PRECOMPILE_ADDR, move |_| Some(mint_precompile));
            return;
        }

        let Ok(block_number) = u64::try_from(block_number) else { return };
        let Ok(block_timestamp) = u64::try_from(block_timestamp) else { return };
        let chain_spec = self.provider().chain_spec();
        if !is_system_tx_gas_exempt(chain_spec.as_ref(), block_timestamp) {
            return
        }

        // Randomness-by-height: user-tx path only, Alpha-gated to match
        // `custom_precompiles_for_ordered_block` (pipe post-Alpha branch).
        // Gas tier is anchored to the EVM block being simulated so eth_call /
        // estimateGas / debug tracing stay aligned with that execution context.
        let precompile =
            create_randomness_by_height_precompile(Arc::new(HeaderRandomnessProvider::new(
                self.provider().clone(),
                block_number,
                current_randomness,
                randomness_by_height_gas_policy_at_block(chain_spec.as_ref(), block_number),
            )));
        evm.precompiles_mut()
            .apply_precompile(&RANDOMNESS_BY_HEIGHT_PRECOMPILE_ADDR, move |_| Some(precompile));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_primitives::{BlockHash, BlockNumber};
    use reth_primitives_traits::SealedHeader;
    use std::{collections::BTreeMap, ops::RangeBounds};

    #[derive(Clone, Debug, Default)]
    struct MockHeaderProvider {
        headers: BTreeMap<u64, Header>,
    }

    impl MockHeaderProvider {
        fn with_header(mut self, number: u64, randomness: B256) -> Self {
            self.headers
                .insert(number, Header { number, mix_hash: randomness, ..Default::default() });
            self
        }
    }

    impl HeaderProvider for MockHeaderProvider {
        type Header = Header;

        fn header(&self, _block_hash: &BlockHash) -> Result<Option<Self::Header>, ProviderError> {
            Ok(None)
        }

        fn header_by_number(&self, num: u64) -> Result<Option<Self::Header>, ProviderError> {
            Ok(self.headers.get(&num).cloned())
        }

        fn header_td(&self, _hash: &BlockHash) -> Result<Option<U256>, ProviderError> {
            Ok(None)
        }

        fn header_td_by_number(&self, _number: BlockNumber) -> Result<Option<U256>, ProviderError> {
            Ok(None)
        }

        fn headers_range(
            &self,
            range: impl RangeBounds<BlockNumber>,
        ) -> Result<Vec<Self::Header>, ProviderError> {
            Ok(self
                .headers
                .iter()
                .filter_map(|(number, header)| range.contains(number).then_some(header.clone()))
                .collect())
        }

        fn sealed_header(
            &self,
            number: BlockNumber,
        ) -> Result<Option<SealedHeader<Self::Header>>, ProviderError> {
            Ok(self.header_by_number(number)?.map(SealedHeader::seal_slow))
        }

        fn sealed_headers_while(
            &self,
            range: impl RangeBounds<BlockNumber>,
            mut predicate: impl FnMut(&SealedHeader<Self::Header>) -> bool,
        ) -> Result<Vec<SealedHeader<Self::Header>>, ProviderError> {
            Ok(self
                .headers_range(range)?
                .into_iter()
                .map(SealedHeader::seal_slow)
                .take_while(|header| predicate(header))
                .collect())
        }
    }

    fn provider(
        reference_number: u64,
        current_randomness: Option<B256>,
    ) -> HeaderRandomnessProvider<MockHeaderProvider> {
        HeaderRandomnessProvider::new(
            MockHeaderProvider::default()
                .with_header(100, B256::with_last_byte(100))
                .with_header(140, B256::with_last_byte(140)),
            reference_number,
            current_randomness,
            RandomnessByHeightGasPolicy { recent_window: 10, recent_gas: 4, lookup_gas: 20 },
        )
    }

    #[test]
    fn header_randomness_provider_uses_current_randomness_from_evm_env() {
        let lookup =
            provider(150, Some(B256::with_last_byte(1))).randomness_by_height(150).unwrap();

        assert_eq!(
            lookup,
            RandomnessByHeightLookup { value: Some(B256::with_last_byte(1)), gas_used: 4 }
        );
    }

    #[test]
    fn header_randomness_provider_falls_back_to_header_for_current_height() {
        let lookup = HeaderRandomnessProvider::new(
            MockHeaderProvider::default().with_header(150, B256::with_last_byte(150)),
            150,
            None,
            RandomnessByHeightGasPolicy { recent_window: 10, recent_gas: 4, lookup_gas: 20 },
        )
        .randomness_by_height(150)
        .unwrap();

        assert_eq!(
            lookup,
            RandomnessByHeightLookup { value: Some(B256::with_last_byte(150)), gas_used: 4 }
        );
    }

    #[test]
    fn header_randomness_provider_charges_recent_tier_for_recent_headers_and_future_misses() {
        let provider = provider(150, Some(B256::with_last_byte(1)));

        assert_eq!(
            provider.randomness_by_height(140).unwrap(),
            RandomnessByHeightLookup { value: Some(B256::with_last_byte(140)), gas_used: 4 }
        );
        assert_eq!(
            provider.randomness_by_height(151).unwrap(),
            RandomnessByHeightLookup { value: None, gas_used: 4 }
        );
    }

    #[test]
    fn header_randomness_provider_charges_lookup_tier_for_older_headers_and_misses() {
        let provider = provider(150, Some(B256::with_last_byte(1)));

        assert_eq!(
            provider.randomness_by_height(100).unwrap(),
            RandomnessByHeightLookup { value: Some(B256::with_last_byte(100)), gas_used: 20 }
        );
        assert_eq!(
            provider.randomness_by_height(99).unwrap(),
            RandomnessByHeightLookup { value: None, gas_used: 20 }
        );
    }

    /// R9 equivalence — pipe `ExecutionRandomnessProvider` vs RPC
    /// `HeaderRandomnessProvider` must produce byte-identical
    /// `RandomnessByHeightLookup`s on the same `(block_number, query_height)`
    /// matrix when given consistent data sources.
    ///
    /// Design `_local/drafts/system-tx-gas-exempt/system-tx-gas-exempt-design-2026-06-25.md`
    /// §3.5.0 / §6.2 / §7 decision 6: both providers register the same
    /// `RANDOMNESS_BY_HEIGHT_PRECOMPILE_ADDR` precompile (Alpha-gated), but read
    /// from intentionally different data sources:
    ///
    /// - **pipe**: `ExecutionRandomnessProvider` reads the in-flight `OrderedBlock.prev_randao` for
    ///   the current (executing) block, the explicit `parent_header.mix_hash()` for the parent, and
    ///   a canonical `GravityStorage`-backed fallback for older heights.
    /// - **RPC**: `HeaderRandomnessProvider` reads `header.mix_hash` from the `HeaderProvider` for
    ///   past heights, and uses the EVM env's `prev_randao` (passed as `current_randomness`) for
    ///   the simulated block.
    ///
    /// For RPC replay (`debug_trace*`, `trace_*`) to stay byte-equal with
    /// canonical execution on any historical block containing a
    /// `randomness_by_height` call, the two providers must agree on every
    /// `(block_number, query_height)` input. Any divergence is a pipe/RPC
    /// fork — same class of bug as the BLS precompile RPC-registration gap
    /// closed in commit `23a55587c4`.
    ///
    /// This test feeds both providers the **same** underlying data
    /// (`current_randomness`, `parent_randomness == parent_header.mix_hash`,
    /// and pipe's storage-fallback returning the same value as RPC's
    /// `HeaderProvider.header_by_number(h).mix_hash`) and asserts
    /// `RandomnessByHeightLookup` byte-equality across a `query_height` matrix
    /// that covers every branch in both implementations:
    /// - far past (`0`, `1`)
    /// - older-than-recent boundary (`current - recent_window - 1`)
    /// - recent-window edge (`current - recent_window`)
    /// - inside-window (`current - recent_window + 1`, `current - 2`)
    /// - parent (`current - 1`)
    /// - current (`current`)
    /// - future (`current + 1`, `u64::MAX`)
    /// - heights absent from the data source (asserts both agree on misses)
    ///
    /// Equivalence covered here is the *logic* equivalence. The data sources
    /// themselves (pipe's `GravityStorage::randomness_by_height` vs RPC's
    /// `HeaderProvider::header_by_number(h).mix_hash`) must independently
    /// agree — that's a separate invariant from the engine API ingestion
    /// path, not under test here. The test asserts: given a fixed data set,
    /// the two providers' lookup *logic* is byte-equal.
    ///
    /// Placement note: ideally this would live in
    /// `crates/pipe-exec-layer-ext-v2/execute/src/randomness_precompile.rs#tests`
    /// alongside `ExecutionRandomnessProvider`, but `HeaderRandomnessProvider`
    /// is a private struct local to this file. Moving it to a shared crate is
    /// a refactor (route A in the R9 task taxonomy) that the design decision
    /// did not require — the shared trait `RandomnessByHeightProvider`
    /// already exists in `gravity-precompiles` and both providers already
    /// implement it. So the test lives in the `rpc-rpc` crate, where both are
    /// in scope (`reth_pipe_exec_layer_ext_v2` is a dev-dep of `reth-rpc`).
    #[test]
    fn execution_provider_and_header_provider_agree_byte_for_byte() {
        use reth_pipe_exec_layer_ext_v2::randomness_precompile::ExecutionRandomnessProvider;
        use std::convert::Infallible;

        /// Mock fallback for `ExecutionRandomnessProvider`. In production this
        /// is a `GravityStorageRandomnessProvider` wrapping `GravityStorage`;
        /// for this test, we use a `BTreeMap` so both providers share the same
        /// in-memory data set.
        ///
        /// Returns `RandomnessByHeightLookup::storage(...)` because
        /// `ExecutionRandomnessProvider` discards the fallback's `gas_used`
        /// and rewrites it via its own gas policy — only `value` is used.
        #[derive(Default)]
        struct MockFallback {
            values: BTreeMap<u64, B256>,
        }

        impl RandomnessByHeightProvider for MockFallback {
            type Error = Infallible;
            fn randomness_by_height(
                &self,
                height: u64,
            ) -> Result<RandomnessByHeightLookup, Self::Error> {
                Ok(RandomnessByHeightLookup::storage(self.values.get(&height).copied()))
            }
        }

        const CURRENT_NUMBER: u64 = 1_000;
        let recent_window: u64 = 100;
        let policy =
            RandomnessByHeightGasPolicy { recent_window, recent_gas: 4_000, lookup_gas: 20_000 };

        // Shared data source: a sparse BTreeMap covering every boundary the
        // providers exercise plus several interior heights. Missing heights
        // (e.g. CURRENT_NUMBER / 2 below) exercise the agreed-miss path.
        let mut headers: BTreeMap<u64, B256> = BTreeMap::new();
        let seed_heights = [
            0u64,
            1,
            CURRENT_NUMBER - recent_window - 1,
            CURRENT_NUMBER - recent_window,
            CURRENT_NUMBER - recent_window + 1,
            CURRENT_NUMBER - 2,
            CURRENT_NUMBER - 1, // parent
            CURRENT_NUMBER,     // current/in-flight
        ];
        for h in seed_heights {
            // Distinct mix_hash per height — last-byte cycles through 1..=251,
            // covering enough of the byte space to catch any byte-level swap.
            headers.insert(h, B256::with_last_byte((h % 251) as u8 + 1));
        }

        let current_randomness = headers[&CURRENT_NUMBER];
        // In production wiring (`pipe-exec-layer-ext-v2/execute/src/lib.rs:390`),
        // pipe passes `parent_header.mix_hash()` as `parent_randomness`. RPC's
        // `HeaderRandomnessProvider` reads `header_by_number(parent).mix_hash`.
        // For the providers to be equivalent at the parent height, these must
        // be the same value — and they are, because both originate from the
        // same persisted parent header. We model that here by reading the
        // parent value from the shared data set.
        let parent_randomness = headers.get(&(CURRENT_NUMBER - 1)).copied();

        let mut mock_header_provider = MockHeaderProvider::default();
        for (h, r) in &headers {
            mock_header_provider = mock_header_provider.with_header(*h, *r);
        }

        let header_provider = HeaderRandomnessProvider::new(
            mock_header_provider,
            CURRENT_NUMBER,
            Some(current_randomness),
            policy,
        );

        // `ExecutionRandomnessProvider` never consults its fallback for the
        // current block (that's the in-flight one, not yet persisted), so
        // exclude `CURRENT_NUMBER` from the fallback to mirror production —
        // the in-flight block is not in `GravityStorage` while it's executing.
        let mut fallback_values = headers.clone();
        fallback_values.remove(&CURRENT_NUMBER);
        let execution_provider = ExecutionRandomnessProvider::new_with_gas_policy(
            MockFallback { values: fallback_values },
            CURRENT_NUMBER,
            current_randomness,
            CURRENT_NUMBER - 1,
            parent_randomness,
            policy,
        );

        // `(block_number, query_height)` sweep. `block_number` is implicit:
        // both providers are constructed with the same `CURRENT_NUMBER`
        // anchor.
        let query_heights = [
            0u64,
            1,
            // Height with no header — both providers must agree on "miss".
            CURRENT_NUMBER / 2,
            CURRENT_NUMBER - recent_window - 1,
            CURRENT_NUMBER - recent_window,
            CURRENT_NUMBER - recent_window + 1,
            CURRENT_NUMBER - 2,
            CURRENT_NUMBER - 1,
            CURRENT_NUMBER,
            CURRENT_NUMBER + 1,
            u64::MAX,
        ];

        for qh in query_heights {
            let exec = execution_provider
                .randomness_by_height(qh)
                .expect("execution provider lookup never errors with Infallible fallback");
            let hdr = header_provider
                .randomness_by_height(qh)
                .expect("header provider lookup never errors against MockHeaderProvider");
            assert_eq!(
                exec, hdr,
                "ExecutionRandomnessProvider and HeaderRandomnessProvider must agree byte-for-byte \
                 at query_height={qh} (current={CURRENT_NUMBER}, recent_window={recent_window}); \
                 a mismatch here is a pipe/RPC divergence — any historical block calling the \
                 randomness-by-height precompile would replay differently between canonical and \
                 debug_trace*/trace_*"
            );
        }
    }
}

impl<N, Rpc> EstimateCall for EthApi<N, Rpc>
where
    N: RpcNodeCore,
    EthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = EthApiError, Evm = N::Evm>,
{
}
