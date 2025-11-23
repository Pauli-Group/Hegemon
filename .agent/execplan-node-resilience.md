# Stabilize node resilience and bootstrap restart paths

This ExecPlan is a living document and must be maintained in accordance with `.agent/PLANS.md`. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` up to date while working.

## Purpose / Big Picture

Recent integration and adversarial runs fail in the restart/reorg scenarios: `tests/node_resilience.rs` aborts on sled file locks and a validator-set mismatch, and `node/tests/bootstrap.rs::imported_peers_survive_restart` times out waiting for a post-restart block. This plan explains how to make the node reopen its databases cleanly, prefer the longest valid chain after short reorgs, and let imported peers resume mining so the full `make check` suite and targeted `cargo test` commands pass reliably. A novice following these steps should be able to reproduce the failures, implement the fixes, and observe all tests completing without timeouts or lock errors.

## Progress

- [x] (2025-11-23 09:02Z) Drafted initial ExecPlan capturing current failing scenarios and intended fixes.
- [x] (2025-11-23 12:18Z) Reproduced baseline failures with `PROPTEST_MAX_CASES=64`; collected command tails, commit hash (`c59379dcb769d8bc4daea5d3666733c2c9fd9e83`), and noted the absence of emitted failure seeds.
- [x] (2025-11-23 19:58Z) Re-ran `make check`, `cargo test -p node --test bootstrap -- --nocapture`, and `cargo test -p security-tests --test node_resilience -- --nocapture` at commit `d5264b92adac3b19db4fb75ee3c78fe5a8151f31` with `PROPTEST_MAX_CASES=64`. `make check` failed in `service::tests::reorg_rebuilds_ledger_and_storage` (`Invalid("node service still referenced during shutdown")`); `node_bootstraps_from_exported_peers` failed with the same shutdown error; `node_resilience` now passes (no seeds emitted).
- [x] (2025-11-23 20:45Z) Re-ran the same commands at commit `89a4c57d7c0bfd4540def095a9cade8ca5570d28` with `PROPTEST_MAX_CASES=64`. `make check` and `node_bootstraps_from_exported_peers` still fail deterministically with `Invalid("node service still referenced during shutdown")`; `node_resilience` remains green (no seeds emitted). New tails stored in `test-logs/make-check-20251123202030{-tail,}.log`, `test-logs/node-bootstrap-20251123204121{-tail,}.log`, and `test-logs/node-resilience-20251123204437{-tail,}.log`.
- [x] (2025-11-23 21:55Z) Re-ran `make check`, `cargo test -p node --test bootstrap -- --nocapture`, and `cargo test -p security-tests --test node_resilience -- --nocapture` at commit `5eb2e67283ebe30e0ceda3c1e947eb21a51019f4` with `PROPTEST_MAX_CASES=64`. Shutdown-reference panics are resolved: `bootstrap` and `node_resilience` pass, but `make check` now fails in `network/tests/p2p_integration.rs::address_exchange_teaches_new_peers` while other suites stay green. New artifacts: `test-logs/make-check-20251123215546{-tail,}.log`, `test-logs/node-bootstrap-20251123215643{-tail,}.log`, and `test-logs/node-resilience-20251123215842{-tail,}.log`.
- [ ] (2025-11-23 13:05Z) Assessment: objectives remain incomplete. Storage shutdown, validator alignment, and imported peer restart fixes have not been implemented; only baseline reproduction and plan drafting are done. The latest reruns confirmed deterministic shutdown-reference panics, so no new fixes were attempted before addressing that blocker.
- [ ] Implement storage shutdown/cleanup to eliminate sled lock contention on restart. Blocked until we change shutdown ordering and drop lingering handles holding sled references.
- [ ] Fix validator selection during short reorgs to avoid `ValidatorSetMismatch`. Still pending because we have not inspected consensus validator metadata or reproduced the mismatch beyond the original logs.
- [ ] Ensure imported peers resume mining and reach height ≥1 after restart without timeouts. Not started; current failures are dominated by shutdown-reference panics, so restart/miner tweaks have not been validated.
- [ ] Rerun the full test matrix and update outcomes/logs in this plan. Deferred until after the shutdown cleanup work, since current runs fail early on the same deterministic panic.

## Surprises & Discoveries

- `node_resilience` now passes without addressing the underlying shutdown/restart work, while `make check` and `node_bootstraps_from_exported_peers` both fail with `node service still referenced during shutdown`, indicating lingering handles are the dominant blocker at the moment. Re-run at `89a4c57d7c0bfd4540def095a9cade8ca5570d28` confirmed the failures are fully deterministic (no seeds emitted). After dropping cloned handles and adding a small shutdown wait, the shutdown panics cleared and `bootstrap`/`node_resilience` now pass, but `network/tests/p2p_integration.rs::address_exchange_teaches_new_peers` regressed in the latest `make check` run.

## Decision Log

- None yet. Record design choices (e.g., whether to adjust shutdown ordering vs. test harness cleanup, how to handle validator metadata) with rationale and timestamp.

## Outcomes & Retrospective

Current state (2025-11-23 21:55Z): shutdown panics are resolved after dropping cloned handles and adding a shutdown grace period. `cargo test -p node --test bootstrap -- --nocapture` and `cargo test -p security-tests --test node_resilience -- --nocapture` now pass with `PROPTEST_MAX_CASES=64`, but `make check` fails in `network/tests/p2p_integration.rs::address_exchange_teaches_new_peers` at commit `5eb2e67283ebe30e0ceda3c1e947eb21a51019f4`. No seeds were emitted; the integration failure appears deterministic on this commit.

## Context and Orientation

- The failing restart and mempool persistence cases live in `tests/node_resilience.rs`, which exercises `NodeService::start`/`shutdown`, sled-backed storage (`node/src/storage.rs`), and mempool retention across restarts.
- The reorg test (`short_reorg_prefers_longer_chain`) calls `NodeService::apply_block_for_test` to feed alternative blocks into the main node’s consensus. Consensus state and validator metadata are managed inside `node/src/service.rs` and consensus helpers in `consensus/`.
- The bootstrap restart timeout occurs in `node/tests/bootstrap.rs::imported_peers_survive_restart`, which spins up P2P services (`network::P2PService`), captures a `PeerBundle`, restarts node B, and waits for node A to mine another block via `NodeService::start` and `GossipRouter` plumbing.
- Storage relies on sled; locks persist if databases stay open. Node shutdown currently aborts tasks in `NodeHandle::shutdown` without guaranteeing sled trees are flushed/dropped. Check `node/src/service.rs` for shutdown and `node/src/storage.rs` for cleanup hooks.
- RocksDB/SQLite locks reported in prior logs likely stem from temporary paths reused across restarts without full drop or lingering async tasks holding references.

## Plan of Work

Describe and execute these steps in order, revising as discoveries arise:

1. **Baseline reproduction with deterministic settings.** From repo root, run `PROPTEST_MAX_CASES=64 make check` and the targeted commands listed in the prior run (`cargo test -p node --test bootstrap -- --nocapture`, `cargo test -p security-tests --test node_resilience -- --nocapture`, plus adversarial/security fuzz jobs if needed). Capture seeds, commit hash, and last ~50 lines for comparison. Confirm the exact lock errors and timeout durations seen in `test-logs/2025-11-23.md`.
2. **Audit storage lifecycle for lock cleanup.** Inspect `node/src/service.rs` for where `Storage` is owned and dropped, including `NodeHandle::shutdown` and any background tasks that clone `Storage`. Ensure shutdown awaits task completion before dropping `Arc<NodeService>` so sled closes. If sled lacks explicit close, add a method in `node/src/storage.rs` to flush and drop handles, and call it during shutdown. Adjust tests to drop `NodeService` handles (and `GossipRouter` clones) before re-opening the same path. Consider per-test temp dir subfolders to avoid shared paths.
3. **Harden restart paths in tests.** Update `tests/node_resilience.rs` to explicitly drop node handles and routers between restarts, adding small waits if sled needs time to release locks. Ensure mempool persistence uses unique DB paths per test (`tempdir` is already unique) and flushes mempool before shutdown if required. Add assertions on shutdown success to catch errors early.
4. **Resolve validator mismatch during short reorg.** Trace how validator sets are computed in the consensus layer (see `consensus/` modules referenced by `node/src/service.rs`). Ensure `apply_block_for_test` and reorg logic reuse the same validator metadata as the sealing path. If alternate chains produce different version/validator commitments, adjust block construction or consensus verification to accept consistent validators during test builds (e.g., align miner seed, block metadata, or consensus params). Add instrumentation/logging in the test or service to capture the expected vs. actual validator set during the failing path, then implement the fix and retain a minimal assertion.
5. **Unstick imported peer restart mining.** In `node/tests/bootstrap.rs`, ensure node A restarts cleanly: drop P2P handles and `NodeService` before restarting, confirm miner is configured to run after restart (`miner_workers`, `pow_bits`, seeds), and add an explicit start if required. Consider extending the wait loop with observable logging (e.g., latest height polling interval) and verify P2P connections are re-established using `PeerStore` contents. If mining thread initialization races with P2P startup, serialize startup or adjust timeout thresholds to reflect realistic block times under `EASY_POW_BITS`.
6. **Validation and regression coverage.** Rerun the full suite with `PROPTEST_MAX_CASES=64` and capture logs. Confirm that `make check` passes, `node_resilience` and `bootstrap` tests complete without timeouts, and no new clippy or fmt issues appear. Update this plan’s `Progress`, `Surprises`, `Decision Log`, and `Outcomes` with concrete results and log excerpts.

## Concrete Steps

Run commands from the repository root:

- `export PROPTEST_MAX_CASES=64` to match CI determinism.
- `make check` to exercise the workspace, with attention to `security-tests::node_resilience` outputs.
- `cargo test -p node --test bootstrap -- --nocapture` to focus on peer bundle restart behavior.
- `cargo test -p security-tests --test node_resilience -- --nocapture` to iterate on crash/restart and reorg handling.
- `cargo test -p network --test adversarial -- --nocapture` and `cargo test security_pipeline -- --nocapture` if changes touch networking or consensus, ensuring no regressions.
- Capture the last 50 lines from each command for artifacts and include failing seeds or commit hashes in this plan.

## Validation and Acceptance

The plan is complete when a novice can:

- Run the commands above with `PROPTEST_MAX_CASES=64` and observe all tests passing without lock errors or timeouts.
- Restart scenarios in `tests/node_resilience.rs` show mempool contents intact and consensus status matching the pre-restart block header.
- `short_reorg_prefers_longer_chain` consistently selects the longer chain without `ValidatorSetMismatch`.
- `imported_peers_survive_restart` reaches height ≥1 within the timeout after restart, demonstrating imported peers and miner resume correctly.

## Idempotence and Recovery

All steps rely on per-test temporary directories and deterministic seeds; rerunning commands should not corrupt global state. If a restart test fails mid-run, delete the temp dirs, ensure all node processes are stopped, and rerun the command. If sled locks persist, rebooting the test environment or renaming the temp path provides a clean slate.

## Artifacts and Notes

As work proceeds, attach concise log snippets (ideally last ~50 lines per command) and any diffs that illustrate critical fixes (e.g., shutdown ordering, consensus adjustments). Keep artifacts small and focused on evidence of success.

### Progress / Artifacts (2025-11-23)

- `PROPTEST_MAX_CASES=64 make check` (commit `c59379dcb769d8bc4daea5d3666733c2c9fd9e83`; seeds not emitted). Tail (~50 lines):

```
     Running tests/p2p_integration.rs (target/debug/deps/p2p_integration-5c4ac47ae131b167)

running 3 tests
test block_gossip_is_imported_and_regossiped ... ok
test gossip_crosses_tcp_boundary ... ok
test address_exchange_teaches_new_peers ... FAILED

failures:

---- address_exchange_teaches_new_peers stdout ----

thread 'address_exchange_teaches_new_peers' panicked at network/tests/p2p_integration.rs:161:5:
node B should learn about node C via address exchange
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    address_exchange_teaches_new_peers

test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.03s

error: test failed, to rerun pass `-p network --test p2p_integration`
make: *** [Makefile:14: test] Error 101
```

- `cargo test -p node --test bootstrap -- --nocapture` (same commit; seeds not emitted). Tail (~50 lines):

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1m 32s
     Running tests/bootstrap.rs (target/debug/deps/bootstrap-d6296e1c1bdca15f)

running 2 tests
test imported_peers_survive_restart ... ok
test node_bootstraps_from_exported_peers ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 11.65s
```

- `cargo test -p security-tests --test node_resilience -- --nocapture` (same commit; seeds not emitted). Tail (~50 lines):

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 25.27s
     Running node_resilience.rs (target/debug/deps/node_resilience-490e80f25ae9e31e)

running 3 tests
Error: Storage(Io(Custom { kind: Other, error: "could not acquire lock on \"/tmp/.tmppOO3M2/mempool.db/db\": Os { code: 11, kind: WouldBlock, message: \"Resource temporarily unavailable\" }" }))
test mempool_survives_restart ... FAILED
Error: Storage(Io(Custom { kind: Other, error: "could not acquire lock on \"/tmp/.tmpg5Bqy9/node.db/db\": Os { code: 11, kind: WouldBlock, message: \"Resource temporarily unavailable\" }" }))
test crash_replay_restores_state ... FAILED
Error: Consensus(ValidatorSetMismatch)
test short_reorg_prefers_longer_chain ... FAILED

failures:

failures:
    crash_replay_restores_state
    mempool_survives_restart
    short_reorg_prefers_longer_chain

test result: FAILED. 0 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.35s

error: test failed, to rerun pass `-p security-tests --test node_resilience`
```

Cross-check against `test-logs/2025-11-23.md`: the repeated lock contention (`could not acquire lock`) and `ValidatorSetMismatch` in `node_resilience` match the prior baseline, confirming the same failure modes are still present while `bootstrap` now passes.

### Progress / Artifacts (2025-11-23 19:58Z)

- `make check` (commit `d5264b92adac3b19db4fb75ee3c78fe5a8151f31`; seeds not emitted). Tail (~50 lines):

```
     Running unittests src/lib.rs (target/debug/deps/node-b80bab0777e43f71)

running 1 test
test service::tests::reorg_rebuilds_ledger_and_storage ... FAILED

failures:

---- service::tests::reorg_rebuilds_ledger_and_storage stdout ----

thread 'service::tests::reorg_rebuilds_ledger_and_storage' panicked at node/src/service.rs:1420:33:
shutdown node: Invalid("node service still referenced during shutdown")
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    service::tests::reorg_rebuilds_ledger_and_storage

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.80s

error: test failed, to rerun pass `-p node --lib`
make: *** [Makefile:14: test] Error 101
```

- `cargo test -p node --test bootstrap -- --nocapture` (same commit; seeds not emitted). Tail (~50 lines):

```
thread 'node_bootstraps_from_exported_peers' panicked at node/tests/bootstrap.rs:97:31:
shutdown node b: Invalid("node service still referenced during shutdown")
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test node_bootstraps_from_exported_peers ... FAILED
test imported_peers_survive_restart ... ok

failures:

failures:
    node_bootstraps_from_exported_peers

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 34.57s

error: test failed, to rerun pass `-p node --test bootstrap`
```

- `cargo test -p security-tests --test node_resilience -- --nocapture` (same commit; seeds not emitted). Tail (~50 lines):

```
running 3 tests
test mempool_survives_restart ... ok
test crash_replay_restores_state ... ok
expected validator: 9fb380fc492756f2e61989b6b12280376409eeece4fcb0d13debad459b3d4f10, configured miners: ["9fb380fc492756f2e61989b6b12280376409eeece4fcb0d13debad459b3d4f10"]
alt block 1 validator: 9fb380fc492756f2e61989b6b12280376409eeece4fcb0d13debad459b3d4f10
alt block 2 validator: 9fb380fc492756f2e61989b6b12280376409eeece4fcb0d13debad459b3d4f10
test short_reorg_prefers_longer_chain ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.50s
```

## Interfaces and Dependencies

- Storage API: extend `node/src/storage.rs` with an explicit `fn close(&self)` or similar that flushes sled and is invoked during shutdown.
- Node service lifecycle: update `node/src/service.rs` so `NodeHandle::shutdown` awaits task completion and drops storage cleanly before returning.
- Consensus reorg helpers: inspect `node/src/service.rs` and relevant `consensus` modules to align validator metadata when applying alternate chains in tests.
- P2P bootstrap: ensure `network::P2PService` and `PeerStore` lifecycles in `node/tests/bootstrap.rs` drop cleanly before restart and that miners are started deterministically after import.

Document revisions at the bottom of this plan whenever updates are made, explaining what changed and why.

### Revision History

- (2025-11-23 13:05Z) Recorded assessment noting that core remediation steps are still outstanding; plan remains in early stages with only baseline evidence gathered.
