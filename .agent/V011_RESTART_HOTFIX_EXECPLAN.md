# Ship the v0.11.1 restart correction

This living plan follows `.agent/PLANS.md`. It covers the startup-only hotfix and its rolling release; it does not change consensus, proof bytes, network identity or wallet custody.

## Purpose / Big Picture

An existing v0.11 node should restart on its current database without repeatedly constructing historical fork rollback plans. All historical proofs must still be verified before RPC/P2P publication. New downloads must contain the correction, and hegemon-dev and hegemon-ovh must run it on the existing public chain.

## Progress

- [x] Reproduced the published binary at height 192: 44 ms storage reload, 36.304856 s until services; profiler identifies quadratic historical V8 branch planning.
- [x] Confirmed the forward V8 scratch replay independently enforces proof validity and exact persisted-state equality.
- [x] Implement startup-only reconstruction and progress logging; preserve standalone/full replay and import/reorg paths.
- [x] Pass focused restart, malformed-proof, index/body integrity checks and measure the same retained database.
- [x] Freeze exact changed source/version pins; all four platform builds, executable proof checks and assembly passed in run 40434419105; PR #209 merged as bb3ad63e653c75a9a5eedc1684a392ea8243020a.
- [ ] Publish v0.11.1 as Latest with compatible joining bundles; retain the v0.11 chain manifest and state directory.
- [x] Upgrade dev (41.061 s) and OVH (39.417 s); both report 0.11.1, preserve data/identity/payouts, agree at H602 and keep advancing. Explorer fully indexed H603.

## Surprises & Discoveries

Startup first rebuilt ordinary state with the full V8 fork verifier against the loaded final tip, then independently replayed V8 forward again. At height H the first pass plans H(H+1)/2 detach entries, including reward-only blocks. Each record decode repeatedly derives immutable default Merkle nodes. The published binary profile confirmed this path dominates CPU. No data corruption or mining activity is required to reproduce it.

## Decision Log

- Use a private startup-only mode for the first pass and retain the mandatory forward scratch verification before any successful open or index repair. Standalone replay stays fully verified.
- Publish v0.11.1; keep `config/testnet/0.11/network-manifest.json`, network-family identity and `~/.hegemon-node-v0.11` unchanged. No genesis reset or data migration.
- Reuse unchanged PR205/proof evidence and existing platform build/actual-binary verification. Exhaustive formal remains nonblocking; no new qualification framework.
- Upgrade one host at a time, dev first. Keep old executable and unit preimages for rollback. Never copy a running sled database.

## Context and Orientation

The clean release checkout is `/Users/pldd/.codex/worktrees/premainnet-v011-release/Hegemon`. Primary checkout research is unrelated and preserved. `node/src/native/node_impl.rs` owns startup replay. `block_flow.rs` already separates legacy artifact verification from V8 fork planning; the existing forward canonical V8 pass verifies proofs, roots, nullifiers, rewards and complete durable row equality. `protocol/versioning/src/lib.rs` controls displayed software version. Exact release-source checkers and joining packagers bind reviewed source and actual platform binaries.

## Plan of Work and Milestones

First, share historical block reconstruction with an explicit private startup mode; only startup skips the duplicate fork-verification call. Keep forward V8 reconciliation unconditional. Add deterministic counters for tests and bounded progress logs. Add regressions proving N forward blocks, zero historical branch calls, unchanged standalone verification and rejection of a self-consistent invalid V8 historical proof even with a persisted verified marker.

Second, run focused release-mode tests with two build jobs in the existing idle target. Reopen a copy of the same height-192 database using the final node and compare exact tip/hash with the baseline. Record timing and preserve originals. Freeze the exact changed source/version bindings and run the existing final executable proof/identity checks.

Third, commit/push the scoped hotfix PR, require existing runtime/binary checks, assemble verified platform bundles and publish v0.11.1. A joining bundle must bind its actual node bytes and preserve the public network manifest. Update supported joining links to the corrected release.

Finally, install immutable versioned executable directories on each seed. Save unit preimages, switch only the executable/versioned manifest path while preserving environment and state. Restart dev, validate loopback RPC, existing genesis and mining payout, and wait for canonical agreement; repeat on OVH. Verify both keep advancing and explorer indexes the same public chain.

## Concrete Steps / Validation and Acceptance

Use `CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 cargo test --locked --offline --release -p hegemon-node --lib <focused filter>`. Require startup regression and invalid-proof rejection to pass; existing canonical index/body/sidecar and legacy marker tests must pass. Build `hegemon-node` with no default features, then use the existing release-artifact script/PR matrix for the four platform binaries. Run exact-source successor controls and actual new-binary five-proof/30-rejection verification; these results do not relabel historical G8 or authorize a new chain.

Acceptance: same database opens with identical tip and typed state; no historical detach work in startup; invalid historical proof still fails before listeners; four platform bundles identify v0.11.1; both hosts retain genesis `d9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3`, mining recipients and current data, agree on a common block hash and advance after upgrade.

## Idempotence and Recovery

Use new evidence/output directories, never overwrite existing wallets or chain data. Preserve the original diagnostic DB and current seed executables. If a seed fails readiness or identity, stop only its hotfix service and restore its saved unit executable path; do not reset the database. Leave the other seed running. No existing data deletion is authorized.

## Artifacts and Notes

Focused startup tests: 25 passed. Existing persisted-marker restart and same-process reorg proof rejection: 2 passed. Same height-192 database, no peers/mining: 36.304856 seconds before, 7.125888 seconds after (80.4% shorter); exact genesis and tip preserved. New binary SHA-256 `c8124fd2adae5e11622b76929383b3d134d6e163849be84355b226176811b028`.

Baseline evidence is `/Users/pldd/Projects/Reflexivity/Hegemon/.agent/v011-cutover-20261026/restart-diagnosis/diagnosis-evidence.json`. Keep hotfix measurements and deployment receipts in a sibling `hotfix-v0111` directory. Record final commit, asset SHA-256 values, host executable hashes and before/after RPC evidence.

## Outcomes & Retrospective

Runtime correction is merged and both seeds run v0.11.1. Release publication and a clean public-download joining check remain. Both hosts retained chain data, launch manifest and payout settings; no reset or resync occurred.

## Interfaces and Dependencies

No consensus/public proof API changes. No new dependencies. The existing private startup path, release-source checkers, joining packager, GitHub PR builds, SSH/systemd and loopback JSON-RPC provide the required interfaces.
