#!/usr/bin/env bash
#
# Long-term regression invariants for the Gravity Alpha system-tx gas-exempt
# design (PR #367). Each invariant fails with a paste-able rg command on
# stderr for fast reproduction. Both invariant logic + thresholds come from
# the design's code-review §6.1 + acceptance-tests §5; the original Rust
# version lived under `crates/ethereum/evm/tests/grep_checklist.rs` until
# CI runners (ubuntu-latest) showed they don't ship ripgrep — making
# `Command::new("rg")` shell-out from a `#[test]` non-portable. A bash
# script that the CI step explicitly `apt-get install`s ripgrep for is the
# correct home: this is a lint, not a unit test, and a self-contained
# shell script keeps the assertion text usable as both a hard check AND a
# paste-able reproduction recipe.
#
# Invariants (10 total):
#   1. `fn transact_system_txn` lives in exactly two source files
#      (serial impl + grevm impl).
#   2. SYSTEM_CALLER address literal `625f0000` has a single source of
#      truth (chainspec/src/gravity.rs + helper + tests only).
#   3. trace.rs RPC replay uses historical state (`state_at_block_id` or
#      `parent_hash()`), never node tip — the gas-exempt gate's correctness
#      depends on it.
#   4. `execute_history_block` / `push_history_block` has no non-test
#      callers (R6 / design §3.6 keeps this debug-only).
#   5. Pipe-layer custom precompile registration mirrors RPC re-registration
#      so RPC trace replay doesn't silently lose BLS/mint/randomness.
#   6. `is_system_tx_gas_exempt` predicate is referenced by all three
#      layers: evm, pipe, rpc (single-source-of-truth invariant).
#   7. (HP-2) `disable_base_fee` / `disable_balance_check` writes are
#      either fork-gated (file co-references `is_system_tx_gas_exempt` /
#      `GravityHardfork::Alpha`) or live in approved
#      simulation-endpoint files / test files.
#   8. (HP-2) RPC replay paths (`replay_transactions_until`,
#      `trace_block_until_with_inspector`) per-tx sender-check by
#      referencing `is_system_tx_gas_exempt` (or
#      `is_gravity_system_caller`) in the same file.
#   9. CI allowlist parity: every integration test binary matching
#      `gravity_system_tx_*_test.rs` or `gravity_bls_*_test.rs` under
#      `crates/pipe-exec-layer-ext-v2/execute/tests/` must EITHER appear
#      in the `--test <name>` allowlist in `.github/workflows/integration.yml`
#      OR be listed in the `KNOWN_UNWIRED_TESTS` skip set inside invariant 9
#      with a documented reason. Rationale: `-p reth-pipe-exec-layer-ext-v2`
#      alone would try to compile every binary in the dir, including ones
#      with dev-dep gaps, so the workflow uses an explicit allowlist.
#      Without invariant 9, a newly added test file is silently skipped by
#      CI (as happened with the six #367 / #370 files) — assertions may
#      pass locally but never gate a merge.
#  10. Every address identifier in the pipe's `system_precompiles` vec is
#      referenced by RPC `register_custom_precompiles` in
#      `crates/rpc/rpc/src/eth/helpers/call.rs`. Today: BLS + mint (mint
#      gated on `for_system_tx`). A new system precompile that lands only
#      on the pipe side is the #372 class of RPC replay divergence.
#
# Invocation:
#   bash scripts/check-gravity-invariants.sh
#
# Exit code: 0 = all invariants pass; 1 = first failure aborts with the
# reproduction rg command on stderr.

set -euo pipefail

# Repo root: this script lives in <repo>/scripts, so `..` is the repo root.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v rg >/dev/null 2>&1; then
    echo "FAIL: ripgrep (rg) must be installed to run this lint." >&2
    echo "      On ubuntu/debian: sudo apt-get install -y ripgrep" >&2
    exit 1
fi

fail() {
    # $1 = invariant id, $2 = human description, $3 = reproduction rg command
    echo "FAIL: invariant $1 — $2" >&2
    echo "  reproduce with: $3" >&2
    exit 1
}

ok() {
    echo "OK:   invariant $1 — $2"
}

# ---------------------------------------------------------------------------
# Invariant 1 — `fn transact_system_txn` lives in exactly two files.
# ---------------------------------------------------------------------------
echo "Invariant 1: fn transact_system_txn must live in exactly 2 source files (serial + grevm)"
files_count=$(rg --type rust -l 'fn transact_system_txn' crates/ethereum/evm/src | sort -u | wc -l)
if [ "$files_count" -ne 2 ]; then
    fail 1 "expected exactly 2 files defining fn transact_system_txn under crates/ethereum/evm/src, got $files_count" \
           "rg --type rust -l 'fn transact_system_txn' crates/ethereum/evm/src"
fi
has_lib=$(rg --type rust -l 'fn transact_system_txn' crates/ethereum/evm/src | grep -c 'lib\.rs$' || true)
has_parallel=$(rg --type rust -l 'fn transact_system_txn' crates/ethereum/evm/src | grep -c 'parallel_execute\.rs$' || true)
if [ "$has_lib" -lt 1 ] || [ "$has_parallel" -lt 1 ]; then
    fail 1 "expected serial impl in lib.rs and grevm impl in parallel_execute.rs" \
           "rg --type rust -l 'fn transact_system_txn' crates/ethereum/evm/src"
fi
ok 1 "fn transact_system_txn in serial + grevm impls only"

# ---------------------------------------------------------------------------
# Invariant 2 — SYSTEM_CALLER literal `625f0000` is a single source of truth.
# Allowed buckets:
#   - canonical const in crates/chainspec/src/gravity.rs
#   - test files (path under tests/ OR filename ends with `_test.rs`)
#   - system_caller_migration.rs (asserts the literal stays canonical)
# Anything else is a re-declaration regression.
# ---------------------------------------------------------------------------
echo "Invariant 2: SYSTEM_CALLER literal 625f0000 single source"
unapproved=$(rg --type rust -l '625f0000' crates/ | sort -u | \
    grep -vE 'crates/chainspec/src/gravity\.rs$' | \
    grep -vE '/tests/' | \
    grep -vE '_test\.rs$' | \
    grep -vE 'system_caller_migration\.rs$' || true)
if [ -n "$unapproved" ]; then
    fail 2 "SYSTEM_CALLER literal 625f0000 found outside chainspec/src/gravity.rs, tests, and system_caller_migration.rs. Unapproved files:
$unapproved" \
        "rg --type rust -n '625f0000' crates/"
fi
ok 2 "SYSTEM_CALLER literal lives in the canonical const + helpers + tests only"

# ---------------------------------------------------------------------------
# Invariant 3 — RPC trace replay uses historical state.
# Hard gate: trace.rs must reference `state_at_block_id` or `parent_hash()`.
# If both vanish, the gas-exempt gate's "replay against parent state"
# argument (design §3.5.2) collapses.
# ---------------------------------------------------------------------------
echo "Invariant 3: trace.rs RPC replay uses historical state"
trace_rs="crates/rpc/rpc-eth-api/src/helpers/trace.rs"
if ! rg -q 'state_at_block_id|parent_hash\(\)' "$trace_rs"; then
    fail 3 "trace.rs must call state_at_block_id or parent_hash() — historical state lookup is load-bearing" \
        "rg -n 'state_at_block_id|parent_hash\\(\\)' $trace_rs"
fi
ok 3 "trace.rs references state_at_block_id / parent_hash()"

# ---------------------------------------------------------------------------
# Invariant 4 — execute_history_block has no non-test callers.
# Approved hits live in:
#   - pipe-exec-layer-ext-v2/execute/src/lib.rs (def + dispatch)
#   - pipe-exec-layer-ext-v2/execute/tests/* (any test)
#   - scripts/check-gravity-invariants.sh (this script, by naming the symbol)
# ---------------------------------------------------------------------------
echo "Invariant 4: execute_history_block / push_history_block has no non-test callers"
unapproved=$(rg --type rust -l 'push_history_block|execute_history_block' crates/ | sort -u | \
    grep -vE 'crates/pipe-exec-layer-ext-v2/execute/src/lib\.rs$' | \
    grep -vE 'crates/pipe-exec-layer-ext-v2/execute/tests/' || true)
if [ -n "$unapproved" ]; then
    fail 4 "execute_history_block/push_history_block referenced outside pipe-exec-layer-ext-v2 lib.rs + tests. Unapproved files:
$unapproved" \
        "rg --type rust -n 'push_history_block|execute_history_block' crates/"
fi
ok 4 "history_block dispatch confined to pipe-exec-layer src/lib.rs and tests"

# ---------------------------------------------------------------------------
# Invariant 5 — pipe + RPC precompile registration in sync.
# Pipe-side: at least one hit in pipe-exec-layer-ext-v2/execute/src/lib.rs
# RPC-side : at least one hit anywhere under crates/rpc/.
# ---------------------------------------------------------------------------
echo "Invariant 5: pipe + RPC precompile registration in sync"
if ! rg --type rust -q 'custom_precompiles_for_ordered_block|register_custom_precompiles' \
        crates/pipe-exec-layer-ext-v2/execute/src/lib.rs; then
    fail 5 "pipe-exec-layer-ext-v2/execute/src/lib.rs must register custom precompiles for ordered blocks" \
        "rg --type rust -n 'custom_precompiles_for_ordered_block|register_custom_precompiles' crates/pipe-exec-layer-ext-v2/execute/src/lib.rs"
fi
if ! rg --type rust -q 'custom_precompiles_for_ordered_block|register_custom_precompiles' crates/rpc/; then
    fail 5 "crates/rpc/ must have at least one register_custom_precompiles callsite — RPC trace replay would otherwise lose custom precompiles" \
        "rg --type rust -n 'register_custom_precompiles' crates/rpc/"
fi
ok 5 "pipe-layer + RPC precompile registration both present"

# ---------------------------------------------------------------------------
# Invariant 6 — is_system_tx_gas_exempt referenced by all 3 layers.
# evm  : crates/ethereum/evm/
# pipe : crates/pipe-exec-layer-ext-v2/
# rpc  : crates/rpc/
# ---------------------------------------------------------------------------
echo "Invariant 6: is_system_tx_gas_exempt referenced by evm + pipe + rpc"
for layer_dir in crates/ethereum/evm crates/pipe-exec-layer-ext-v2 crates/rpc; do
    if ! rg --type rust -q 'is_system_tx_gas_exempt' "$layer_dir"; then
        fail 6 "is_system_tx_gas_exempt missing from $layer_dir — single-source-of-truth predicate must be wired everywhere" \
            "rg --type rust -n 'is_system_tx_gas_exempt' $layer_dir"
    fi
done
ok 6 "is_system_tx_gas_exempt wired in evm + pipe + rpc"

# ---------------------------------------------------------------------------
# Invariant 7 (HP-2 #1) — disable_base_fee / disable_balance_check writes
# must either be fork-gated (file co-references is_system_tx_gas_exempt /
# is_gravity_system_caller / GravityHardfork::Alpha / SYSTEM_CALLER) OR be
# in an approved bucket:
#   - test files (path under /tests/ OR filename ends _test.rs)
#   - approved pure-simulation endpoint files that legitimately set
#     disable_base_fee unconditionally (eth_estimateGas etc.); since these
#     don't replay user-signed txs, the gas-exempt feature does not apply.
#     The allowlist is held tight to force a future contributor to audit
#     each addition.
# ---------------------------------------------------------------------------
echo "Invariant 7 (HP-2 #1): disable_base_fee / disable_balance_check writes are fork-gated"
approved_sim_endpoints='crates/rpc/rpc-eth-api/src/helpers/estimate\.rs$'
hits=$(rg --type rust -l 'disable_base_fee|disable_balance_check' \
    crates/rpc crates/ethereum/evm crates/pipe-exec-layer-ext-v2 | sort -u)
unapproved=""
for f in $hits; do
    # bucket: tests
    if echo "$f" | grep -qE '/tests/|_test\.rs$'; then continue; fi
    # bucket: known pure-simulation endpoint allowlist
    if echo "$f" | grep -qE "$approved_sim_endpoints"; then continue; fi
    # bucket: file co-references a fork gate or sender check
    if rg --type rust -q 'is_system_tx_gas_exempt|is_gravity_system_caller|GravityHardfork::Alpha|SYSTEM_CALLER' "$f"; then
        continue
    fi
    unapproved="${unapproved}${f}
"
done
if [ -n "$unapproved" ]; then
    fail 7 "disable_base_fee/disable_balance_check writes appear in files lacking a fork gate or sender check. Unapproved files:
${unapproved}If a new pure-simulation endpoint legitimately needs these flags unconditionally, add it to the allowlist in this script." \
        "rg --type rust -n 'disable_base_fee|disable_balance_check' crates/rpc crates/ethereum/evm crates/pipe-exec-layer-ext-v2"
fi
ok 7 "disable_* writes are either fork-gated or in approved simulation/test files"

# ---------------------------------------------------------------------------
# Invariant 8 (HP-2 #2) — RPC replay paths reference the SYSTEM_CALLER
# exemption check. Every file that calls `replay_transactions_until` or
# `trace_block_until_with_inspector` (the two per-tx-cfg-toggling APIs)
# must also reference `is_system_tx_gas_exempt` or `is_gravity_system_caller`
# so the per-tx sender check stays paired with the per-tx replay.
# ---------------------------------------------------------------------------
echo "Invariant 8 (HP-2 #2): RPC replay paths have SYSTEM_CALLER exemption check"
hits=$(rg --type rust -l 'replay_transactions_until|trace_block_until_with_inspector' crates/rpc | sort -u)
unapproved=""
for f in $hits; do
    # skip the trait/helper definition itself if the gate is implemented by
    # callers, not the trait file — but every consumer file MUST have the
    # gate. (As of 2026-06-27 every hit file has both, so no exception
    # exists; an exception would have to be added explicitly here with a
    # comment.)
    if ! rg --type rust -q 'is_system_tx_gas_exempt|is_gravity_system_caller' "$f"; then
        unapproved="${unapproved}${f}
"
    fi
done
if [ -n "$unapproved" ]; then
    fail 8 "RPC replay-path file calls replay_transactions_until / trace_block_until_with_inspector but lacks any reference to is_system_tx_gas_exempt or is_gravity_system_caller. Unapproved files:
${unapproved}A new replay caller must per-tx check sender against SYSTEM_CALLER." \
        "rg --type rust -n 'replay_transactions_until|trace_block_until_with_inspector' crates/rpc"
fi
ok 8 "RPC replay paths reference SYSTEM_CALLER exemption check"

# ---------------------------------------------------------------------------
# Invariant 9 — CI allowlist parity for post-#367 / post-#370 RPC replay tests.
# Every file under `crates/pipe-exec-layer-ext-v2/execute/tests/` matching
# `gravity_system_tx_*_test.rs` or `gravity_bls_*_test.rs` must EITHER appear
# as a `--test <basename>` argument in `.github/workflows/integration.yml`
# OR be listed in `KNOWN_UNWIRED_TESTS` below with a documented reason. The
# workflow uses an explicit allowlist (not `-p reth-pipe-exec-layer-ext-v2`
# alone) because the crate has integration binaries whose dev-deps are
# missing in this workspace; that same allowlist silently skips new files
# unless they are added by hand.
#
# Deferred entries force a future contributor to make an explicit
# claim ("wire" or "defer, with reason"), preventing another silent-skip
# incident like #367 / #370.
# ---------------------------------------------------------------------------
echo "Invariant 9: CI --test allowlist covers all gravity_system_tx_* / gravity_bls_* integration tests (or explicit KNOWN_UNWIRED_TESTS)"

# Known-unwired: test file basename → one-line reason. Any entry here
# should also have a follow-up issue / PR tracked. Removing an entry
# means the corresponding `--test <name>` line must be added to the
# workflow.
declare -A KNOWN_UNWIRED_TESTS=(
    # Empty: `gravity_system_tx_post_alpha_trace_test` is wired to
    # integration.yml after #372 (mint precompile RPC registration).
)

workflow="$REPO_ROOT/.github/workflows/integration.yml"
tests_dir="crates/pipe-exec-layer-ext-v2/execute/tests"
if [ ! -f "$workflow" ]; then
    fail 9 "expected workflow file at .github/workflows/integration.yml — invariant needs to know where to look for the allowlist" \
        "ls .github/workflows/integration.yml"
fi
missing=""
double_claimed=""
for f in $(ls "$tests_dir"/gravity_system_tx_*_test.rs "$tests_dir"/gravity_bls_*_test.rs 2>/dev/null); do
    binary=$(basename "$f" .rs)
    in_workflow=false
    if grep -qE "^[[:space:]]*--test[[:space:]]+${binary}([[:space:]]|\\\\|$)" "$workflow"; then
        in_workflow=true
    fi
    in_unwired=false
    if [ "${KNOWN_UNWIRED_TESTS[$binary]+set}" = "set" ]; then
        in_unwired=true
    fi
    if [ "$in_workflow" = "false" ] && [ "$in_unwired" = "false" ]; then
        missing="${missing}${binary}
"
    fi
    if [ "$in_workflow" = "true" ] && [ "$in_unwired" = "true" ]; then
        double_claimed="${double_claimed}${binary}
"
    fi
done
if [ -n "$missing" ]; then
    fail 9 "integration test file(s) neither wired to CI nor in KNOWN_UNWIRED_TESTS. Add \`--test <name> \\\` line(s) to .github/workflows/integration.yml (gravity-pipe-test job) OR add an entry to KNOWN_UNWIRED_TESTS in this script with a documented reason. Missing:
${missing}Rationale: silently-skipped tests can't gate merges (see integration.yml comment)." \
        "grep -E '^[[:space:]]*--test' .github/workflows/integration.yml"
fi
if [ -n "$double_claimed" ]; then
    fail 9 "integration test file(s) both in CI allowlist AND KNOWN_UNWIRED_TESTS — pick one. Double-claimed:
${double_claimed}Remove the KNOWN_UNWIRED_TESTS entry if now wired, or drop the workflow line if you meant to defer." \
        "grep -E '^[[:space:]]*--test' .github/workflows/integration.yml"
fi
# Also flag KNOWN_UNWIRED_TESTS references to files that no longer exist —
# likely a rename / deletion missed the invariant update.
stale=""
if [ "${#KNOWN_UNWIRED_TESTS[@]}" -gt 0 ]; then
    for binary in "${!KNOWN_UNWIRED_TESTS[@]}"; do
        if [ ! -f "$tests_dir/${binary}.rs" ]; then
            stale="${stale}${binary}
"
        fi
    done
fi
if [ -n "$stale" ]; then
    fail 9 "KNOWN_UNWIRED_TESTS references file(s) that no longer exist under $tests_dir/. Remove the stale entries or restore the files. Stale:
${stale}" \
        "ls $tests_dir/"
fi
ok 9 "CI --test allowlist + KNOWN_UNWIRED_TESTS jointly cover all gravity_system_tx_* / gravity_bls_* integration tests"

# ---------------------------------------------------------------------------
# Invariant 10 — every address ident in pipe `system_precompiles` is
# registered in RPC `register_custom_precompiles` (`call.rs`).
# Today: BLS + mint. A new system precompile that lands only on the pipe
# side is the exact #372 class of RPC replay divergence.
# ---------------------------------------------------------------------------
echo "Invariant 10: RPC call.rs registers every pipe system_precompiles address ident"

pipe_lib="crates/pipe-exec-layer-ext-v2/execute/src/lib.rs"
rpc_call="crates/rpc/rpc/src/eth/helpers/call.rs"

if [ ! -f "$pipe_lib" ] || [ ! -f "$rpc_call" ]; then
    fail 10 "expected $pipe_lib and $rpc_call to exist" \
        "ls $pipe_lib $rpc_call"
fi

# Extract *_ADDR identifiers from the address slot of `system_precompiles`
# vec entries (`(SOME_ADDR, some_precompile),`).
mapfile -t addrs < <(awk '/let system_precompiles/,/];/' "$pipe_lib" | \
    rg -o '[A-Z][A-Z0-9_]*_ADDR' | sort -u)

if [ "${#addrs[@]}" -eq 0 ]; then
    fail 10 "could not extract any *_ADDR identifiers from system_precompiles vec in $pipe_lib" \
        "rg -n -A 10 'let system_precompiles' $pipe_lib"
fi

missing=""
for addr in "${addrs[@]}"; do
    if ! rg --type rust -q "$addr" "$rpc_call"; then
        missing="${missing}${addr}
"
    fi
done
if [ -n "$missing" ]; then
    fail 10 "RPC $rpc_call does not register every pipe system_precompiles address. Missing:
${missing}Register each in register_custom_precompiles (unconditionally, matching the pipe)." \
        "rg -n 'NATIVE_MINT_PRECOMPILE_ADDR|BLS_PRECOMPILE_ADDR' $rpc_call $pipe_lib"
fi
ok 10 "RPC call.rs references every system_precompiles address ident (${addrs[*]})"

echo
echo "All Gravity invariants passed."
