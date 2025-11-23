# Stabilize node resilience and bootstrap restart paths

This ExecPlan is a living document and must be maintained in accordance with `.agent/PLANS.md`. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` up to date while working.

## Purpose / Big Picture

Recent integration and adversarial runs fail in the restart/reorg scenarios: `tests/node_resilience.rs` aborts on sled file locks and a validator-set mismatch, and `node/tests/bootstrap.rs::imported_peers_survive_restart` times out waiting for a post-restart block. This plan explains how to make the node reopen its databases cleanly, prefer the longest valid chain after short reorgs, and let imported peers resume mining so the full `make check` suite and targeted `cargo test` commands pass reliably. A novice following these steps should be able to reproduce the failures, implement the fixes, and observe all tests completing without timeouts or lock errors.

## Progress

- [x] (2025-11-23 09:02Z) Drafted initial ExecPlan capturing current failing scenarios and intended fixes.
- [ ] Reproduce current failures with `PROPTEST_MAX_CASES=64` to confirm baseline symptoms and seeds.
- [ ] Implement storage shutdown/cleanup to eliminate sled lock contention on restart.
- [ ] Fix validator selection during short reorgs to avoid `ValidatorSetMismatch`.
- [ ] Ensure imported peers resume mining and reach height ≥1 after restart without timeouts.
- [ ] Rerun the full test matrix and update outcomes/logs in this plan.

## Surprises & Discoveries

- None yet; populate as investigations uncover unexpected behaviors (e.g., sled lock behavior, consensus edge cases, peer bootstrap delays), with short evidence excerpts from logs or traces.

## Decision Log

- None yet. Record design choices (e.g., whether to adjust shutdown ordering vs. test harness cleanup, how to handle validator metadata) with rationale and timestamp.

## Outcomes & Retrospective

Summarize results after implementing the fixes: which tests now pass, any residual flakes, and lessons learned about storage lifecycle, consensus reorg handling, or peer bootstrap sequencing.

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

## Interfaces and Dependencies

- Storage API: extend `node/src/storage.rs` with an explicit `fn close(&self)` or similar that flushes sled and is invoked during shutdown.
- Node service lifecycle: update `node/src/service.rs` so `NodeHandle::shutdown` awaits task completion and drops storage cleanly before returning.
- Consensus reorg helpers: inspect `node/src/service.rs` and relevant `consensus` modules to align validator metadata when applying alternate chains in tests.
- P2P bootstrap: ensure `network::P2PService` and `PeerStore` lifecycles in `node/tests/bootstrap.rs` drop cleanly before restart and that miners are started deterministically after import.

Document revisions at the bottom of this plan whenever updates are made, explaining what changed and why.
