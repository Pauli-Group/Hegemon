# Close the actionable PR #205 wallet review findings

This living ExecPlan follows `.agent/PLANS.md`. Update Progress, Surprises & Discoveries, Decision Log and Outcomes & Retrospective as work advances.

## Purpose / Big Picture

Prevent concurrent V8 wallet submissions from spending the same selected notes, make the trusted full-node RPC requirement visible, remove wallet-linked identifiers from opt-in pending logs, and exclude unused experimental storage helpers from the ordinary node build without losing their tests. No proof relation, transmitted proof bytes, production activation or network deployment changes are authorized by this task. Finish with the actual PR #205 CI checks passing on the resulting commit.

## Progress

- [x] Verified PR #205 head `f322352ccdfe6da3310fb43dfc0adcb35660095f` and all 24 existing CI checks passing; stacked ASIC PR #206 also has all 24 checks passing.
- [x] Created isolated worktree `/private/tmp/rp05-review-hygiene.YIwqpR`, branch `codex/rp05-review-hygiene`, preserving the dirty primary checkout and ASIC worktree.
- [x] Assigned exclusive wallet implementation, trust documentation and storage isolation work to separate workers.
- [x] Implement durable V8 input reservations and lifecycle reconciliation with backwards-compatible wallet persistence.
- [x] Redact pending identifiers and document the full-node RPC trust boundary.
- [x] Isolate unused storage helpers while retaining tests and active state authority.
- [x] Independent source review found no unresolved correctness defects after repairing path ownership, durable rename, reorg tombstones and the retained-carrier borrow lifetime.
- [x] Full wallet tests passed: 179 library tests, 4 CLI tests, 1 memo test, 9 RPC tests, 2 wire tests and 3 doctests; existing ignored tests remain ignored.
- [x] Normal node library/binary compilation passed; default and no-default-feature node suites each passed 746 tests with 10 existing ignored tests and no failures. All 27 prototype storage tests remain in those suites.
- [x] Review integrated changes and pass focused wallet/node tests and formatting/lints. `scripts/check-core.sh lint` passed, along with formatting and whitespace checks.
- [x] Actual focused governance tests passed 14/14 at 2026-10-03 04:14:29 UTC. Refreshed source fingerprints and executed-gate metadata without changing review statuses, reviewer identities, claim contents or production authority. Three source fingerprints also depend on the refreshed claims evidence; their resulting blueprint fingerprint was refreshed after that evidence update.
- [ ] Publish the scoped commit to the existing PR #205 branch and wait for all required CI checks on that commit to pass.

## Surprises & Discoveries

The review's M1 claim is defeated by the existing pending group commit: it combines existing and proposed V8 actions, then verifies their typed nullifiers and state transitions before persistence. This task does not add another mempool spend authority. The wallet sync path is already documented as a localhost or trusted operator control plane, not an independently validating light client. Adding only a STARK verification call would not authenticate chain selection. Recovering abandoned pre-submission work on restart requires exclusive writer ownership, while status must remain available through read-only snapshots. Explicit stale-parent abandonment must retain a tombstone: a later reorg can otherwise make the original possibly delivered proof eligible again.

## Decision Log

Keep ordinary transaction relation and node admission unchanged. Reserve input notes locally before expensive proof construction; never unlock a possibly submitted transaction merely because a timeout expires. Preserve encrypted-store compatibility explicitly, because bincode does not treat new trailing fields like JSON defaults. Keep unused storage tests rather than integrating an unnecessary second storage path. Publish to the already authorized PR #205 destination, not a new public PR or live network.

## Outcomes & Retrospective

Implementation, independent source review, full wallet tests, both node test configurations, lint and actual governance tests are complete. Remaining acceptance is the final source-binding check, publication and exact-head CI. Baseline checks are not credited as verification of the new patch.

Published implementation commit `a77f4043`; remote wallet/node jobs passed, but app E2E exposed a missed daemon integration: walletd acquired the same sibling lock before opening the newly locking WalletStore. Correct that duplicate ownership in walletd, preserve `StoreLocked` error semantics, add daemon startup/lock tests and run the actual app E2E before publishing the correction. PR #206 is stacked on #205 and needs fingerprint-only conflict resolution against its combined source; no ASIC behavior changes are part of this integration.

The correction removes duplicate daemon lock ownership and adds an atomic non-overwriting `create_full_if_missing` wallet entry point. Full wallet tests passed again (180 library tests, 2 existing ignored), daemon tests passed (11), formatting and clippy passed. Actual `scripts/check-app-no-ssh-e2e.sh --review-only` passed with seed authoring, relay join/sync and both wallets synchronized to height 2. Funded transfers were outside that mode. Governance tests passed 14/14 again at 2026-10-03 04:35:47 UTC. Publish this correction, then require all CI checks on its exact head to pass.

## Context and Orientation

`wallet/src/poseidon2_v8_sync.rs` maintains the seven-limb note mirror and selects two inputs. `wallet/src/poseidon2_v8.rs` builds, proves, verifies and submits them. `wallet/src/store.rs` serializes encrypted state and applies mirror changes transactionally. A reservation is a durable wallet-local claim on the exact inputs so another builder cannot select them; it is not a consensus nullifier or proof field. `node/src/native/mod.rs` declares the unused `canonical_membership`, `reorg_wal` and `block_store_v3` helpers. The active seven-limb node state and existing canonical reorg path remain unchanged.

## Plan of Work

First add reservation transitions and tests through the existing encrypted wallet store. Cover pre-submit errors, cancellation, possible submission, confirmation, rollback and restart, preserving uncertain spends conservatively. Next add concise trust statements near user-facing sync documentation and APIs and remove raw pending identifiers from debug output. Finally isolate unused storage modules using conditional compilation where their dependency graph permits it; do not delete evidence or migrate active node state. Review the integrated diff before running validation and publishing.

## Concrete Steps

Work in `/private/tmp/rp05-review-hygiene.YIwqpR`. Reuse compatible existing build dependencies from `/private/tmp/rp05-ci-20261001.223oOy/target` with one build coordinator to avoid concurrent cache writers. Inspect exact script invocations before choosing environment options. Run `cargo fmt --all -- --check`, `cargo test --locked -p wallet`, and affected default and no-default-feature node library tests. Run the lint gate after implementation is stable. Recheck PR #205's remote head before a fast-forward push; do not force-update another contributor's work.

## Validation and Acceptance

Tests must demonstrate two concurrent builders cannot obtain the same inputs, reservations survive encrypted store reopen, old stores decode under an explicit migration, failures before submission release only their own reservation, uncertain/submitted transactions stay reserved, and canonical spend/reorg reconciliation maintains the correct status. Tests must also demonstrate pending log output contains no wallet-linked nullifier values. Normal node compilation must exclude the unused storage modules and node test builds must retain their tests. Final acceptance requires every required CI check passing for the exact published PR #205 commit; no test removal or disabled gate is part of this change.

## Idempotence and Recovery

All state tests use temporary wallets. Do not modify deployed nodes or existing user wallets. Preserve unresolved submissions conservatively and provide a deliberate recovery path instead of silently allowing reuse. A failed build is repaired in the isolated worktree. If the remote PR head advances, integrate the new remote changes before pushing rather than overwriting them.

## Artifacts and Notes

Baseline: PR #205 `f322352c`, PR #206 `5ca8fc45`, both 24/24 checks successful at the start of this task. Existing retained proof bytes are untouched and are not regenerated merely for wallet documentation or unused-module isolation.

## Interfaces and Dependencies

Use existing encrypted persistence, source-selected V8 constructors and canonical sync callbacks. Keep reservation metadata local; do not alter the network action, circuit statement or proof profile. `fs2` 0.4.3, already present in the lockfile, supplies cross-process advisory writer ownership; the root lockfile change only adds the existing package to wallet's dependency list. V12 appends the reservation journal and preserves frozen V11 decoding. This is wallet-local data migration, not a consensus state migration.

Initial plan added for the user-authorized review fixes and exact-head CI acceptance.
