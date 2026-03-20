# Fix Fork Sync Recovery After Same-Height PoW Races

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, a Hegemon node that loses a same-height proof-of-work race must recover onto the longer chain without requiring an operator to stop and restart the process. The observable result is that when two miners produce competing sibling blocks at the same height and one branch becomes longer, the lagging node resumes sync automatically and converges to the network tip while the process stays up.

The user-visible proof is a regression test that reproduces the sibling-fork scenario and a live sync path that keeps advancing after a competing local block instead of freezing at the fork height.

## Progress

- [x] (2026-03-19 22:39Z) Read `DESIGN.md`, `METHODS.md`, and `.agent/PLANS.md` before implementation.
- [x] (2026-03-19 22:39Z) Reproduced the production symptom from live RPC evidence: local node stayed at height `1199` while a peer advanced to `1243+`, with both branches sharing block `1198` and diverging at sibling `1199`.
- [x] (2026-03-19 22:39Z) Narrowed the fault domain to `node/src/substrate/sync.rs` and `node/src/substrate/service.rs`.
- [x] (2026-03-19 23:34Z) Identified the wedging transition: imported PoW blocks were explicitly finalized immediately, and the sync importer dropped downloaded block tails on transient parent/state availability errors instead of retrying them.
- [x] (2026-03-19 23:34Z) Patched the importer/sync coordination so transient `UnknownBlock` and `UnknownParent` paths requeue the remaining downloaded range instead of discarding it.
- [x] (2026-03-19 23:34Z) Removed explicit post-import finalization for PoW blocks so longest-chain reorgs remain possible after same-height sibling races.
- [x] (2026-03-19 23:34Z) Added automated regression coverage for a same-height sibling race in `node/src/substrate/sync.rs` plus helper coverage for deferred download requeueing in `node/src/substrate/service.rs`.
- [x] (2026-03-19 23:35Z) Ran focused and broad `hegemon-node` library tests and recorded the passing evidence below.
- [x] (2026-03-20 00:37Z) Confirmed the remaining live failure was persisted finalized-head state from the pre-fix bug: local `chain_getFinalizedHead` was still the losing `1199` sibling while peers had finalized far ahead on the winning branch.
- [x] (2026-03-20 00:37Z) Added runtime recovery so sync import treats `NotInFinalizedChain` as a poisoned-finality case, reverts one finalized block through the backend, resets the sync cursor to the new local best, and retries the deferred branch.
- [x] (2026-03-20 00:37Z) Rebuilt the release binary after the poisoned-finality recovery patch.
- [x] (2026-03-20 00:59Z) Confirmed the next live wedge was a sync/import deadlock: deferred blocks `1200..1214` stayed in the download queue while `tick()` refused to request the missing peer `1199`.
- [x] (2026-03-20 00:59Z) Added cursor rewind on missing-parent deferrals plus gap-fetch behavior so sync can request the missing ancestor height even when higher deferred blocks remain queued.
- [x] (2026-03-20 01:08Z) Re-ran focused sync/service tests, the full `hegemon-node` test suite, and rebuilt the release binary with the ancestor-gap recovery patch.

## Surprises & Discoveries

- Observation: The live failure was not a network reachability issue. The lagging laptop still had an outbound peer entry for OVH with `best_height: 1243` and recent `last_seen_secs`, so it knew a longer chain existed.
  Evidence: `hegemon_peerList` on the laptop reported OVH at height `1243`, while `hegemon_consensusStatus` remained at `1199`.

- Observation: The fork started at a same-height race, not at a missing-parent gap. Both nodes agreed on blocks `1196` through `1198`, then produced different block hashes at height `1199`.
  Evidence: `chain_getBlockHash(1198)` matched on both nodes; `chain_getBlockHash(1199)` differed.

- Observation: The current sync code already contains explicit fork backtracking logic in `node/src/substrate/sync.rs`, so the bug is likely in how downloaded blocks are retried or dropped after import-time parent-state checks.
  Evidence: `handle_blocks_response` backtracks one height when the first downloaded block does not connect to the current sync tip, while `node/src/substrate/service.rs` currently drops some downloaded blocks on `UnknownBlock` parent-state errors instead of requeuing them.

- Observation: The block import glue in `node/src/substrate/service.rs` explicitly finalized every imported PoW block, including network sync and local mining imports.
  Evidence: `finalize_imported_block(...)` was called on `ImportResult::Imported` and `ImportResult::AlreadyInChain` for local mining, initial sync, and network broadcast imports.

- Observation: Immediate finalization is hostile to ordinary PoW fork choice because finalization marks the current tip as irreversible before the node has any finality mechanism or canonicality proof beyond cumulative work.
  Evidence: the production failure signature was a node pinned to the losing sibling at height `1199` even though it knew about the longer branch and Substrate PoW import was still being used.

- Observation: Removing explicit finalization fixed future reorg safety, but an already-poisoned database still cannot follow the winning branch because Substrate refuses to import competing blocks at or below the stale finalized height.
  Evidence: after restarting on the patched binary, the laptop still reported `chain_getFinalizedHead = 0x32173a2c...` (local losing `1199`) and sync import failed with `Potential long-range attack: block not in finalized chain.`

- Observation: After fixing poisoned finality, the node could still deadlock if the import loop requeued downloaded blocks above the fork point while the sync tick refused to send any new request until the queue emptied.
  Evidence: the live console repeated `Deferred synced block tail requeued for retry deferred=15 first_number=1200 last_number=1214` while local height remained `1199` and the peer stayed at `1290`; `chain_getHeader(0xed3cc8dc...)` on the laptop returned `null`, proving the peer's sibling `1199` had never been imported.

## Decision Log

- Decision: Treat this as a correctness bug in sync/import coordination, not an operator workflow problem.
  Rationale: The user explicitly rejected restart-based recovery, and comparable chains recover from losing forks while the process remains alive.
  Date/Author: 2026-03-19 / Codex

- Decision: Use the live failure signature as the acceptance target: same-height sibling fork, local node on losing branch, peer advances, local node must converge without restart.
  Rationale: The current test suite has general reorg coverage, but it does not clearly cover the exact stuck-at-sibling-height production failure.
  Date/Author: 2026-03-19 / Codex

- Decision: Stop explicitly finalizing imported PoW blocks in the service-layer import glue.
  Rationale: Comparable PoW chains keep blocks reorgable under longest-chain rules; immediate finalization at import time defeats that model and can pin the node to a losing sibling.
  Date/Author: 2026-03-19 / Codex

- Decision: Treat `UnknownBlock`, `UnknownParent`, and related transient parent-state gaps during sync import as retryable queue conditions, not terminal drops.
  Rationale: During sibling-fork recovery the parent header or parent state may become visible only after earlier imports complete. Preserving the tail of the downloaded range is safer than discarding it and hoping later polling reconstructs the exact branch.
  Date/Author: 2026-03-19 / Codex

- Decision: When sync import hits `NotInFinalizedChain` on this PoW node, perform a one-block unsafe backend revert and retry instead of leaving the operator wedged on poisoned finality.
  Rationale: This error means historical finality metadata is blocking the reorg. Comparable longest-chain nodes recover by walking back the stale branch to the common ancestor; on Substrate this requires an explicit backend revert because finalized metadata survives restart.
  Date/Author: 2026-03-20 / Codex

- Decision: When import defers a downloaded block because its parent is missing locally, rewind the sync cursor to `child_number - 2` and let `tick()` fetch the missing ancestor even if higher deferred blocks are still buffered.
  Rationale: Requeueing `1200+` without rewinding leaves the downloader asking for nothing, because the queue is non-empty and the missing peer `1199` never arrives. Comparable chain sync must keep ancestor discovery moving while preserving the deferred tail.
  Date/Author: 2026-03-20 / Codex

## Outcomes & Retrospective

Implementation completed for the two failure points that matched the production signature.

First, the service-layer import path no longer explicitly finalizes PoW blocks after import. That restores ordinary longest-chain behavior so a node can reorg away from a losing same-height sibling when a peer extends the competing branch.

Second, the downloaded sync import loop now preserves and requeues the current block plus the remaining downloaded tail whenever the parent header or parent state is temporarily unavailable. That keeps the sync cursor moving through the winning branch instead of silently dropping blocks and waiting for operator intervention.

Third, the node now recovers from already-poisoned finalized metadata left behind by the old bug. If sync import encounters `NotInFinalizedChain`, the service reverts one finalized block through the backend, resets the sync cursor to the new local best, and retries the deferred branch. This lets an existing stuck node walk itself back to the common ancestor instead of requiring a wipe.

Fourth, the sync/import boundary now breaks the deferred-tail deadlock discovered in live validation. When import sees that block `N` is missing its parent locally, it rewinds the sync cursor to `N-2`; `tick()` is now allowed to request `N-1` even if the import queue already contains `N..`. This preserves the deferred tail without blocking ancestor fetches.

The new regression tests in `node/src/substrate/sync.rs` prove both behaviors: the sync state machine backtracks from a losing local `1199` sibling to the common ancestor and then requests `1199` on the competing branch, and a queued deferred block at `1200` does not prevent the node from requesting the missing `1199`. The service-side helper tests continue to prove deferred download tails are preserved in order and that `UnknownBlock`-style parent-state failures are treated as retryable.

The remaining gap is live multi-node validation against a running fork race after redeploy. Unit and library tests are green, but I have not yet re-run the original laptop-versus-OVH scenario end to end with the patched binary.

## Context and Orientation

The relevant code lives in two places.

`node/src/substrate/sync.rs` implements the chain sync state machine. In this repository, “sync” means the logic that watches peer announcements, decides whether the node is behind, asks peers for blocks, and tracks a temporary sync cursor while blocks are downloaded. The important pieces are `SyncState::Downloading`, `SyncService::on_block_announce`, `SyncService::handle_blocks_response`, `SyncService::create_block_request`, and `SyncService::on_block_imported`.

`node/src/substrate/service.rs` hosts the long-running tasks that glue the network and the sync state machine together. The `chain-sync-tick` task calls `sync.tick()` once per second and sends sync requests. The `block-import-handler` drains downloaded blocks from the sync service and imports them through the Substrate PoW import path. This importer also performs pre-import checks for data availability and proof verification. A bad interaction here can stall sync even if the sync state machine keeps asking for the right heights.

The observed production failure is:

1. The local node mined a block at height `1199`.
2. A peer mined a different block at the same height and extended that sibling branch.
3. The local node knew the peer was ahead but never advanced beyond `1199`.
4. Operators currently recover by restarting, which is unacceptable.

In plain terms, a “same-height sibling fork” means two miners built different valid blocks on the same parent. A robust node must keep the losing block in storage if needed, follow the longer branch as soon as it becomes strictly better, and never require a restart just because it mined the losing sibling.

## Plan of Work

First, inspect the sync and import transition around a competing sibling block. The likely failure is one of two cases. Either the sync state machine stops making progress after backtracking to the common ancestor, or the importer drops downloaded blocks on a transient parent-state condition and never gives the sync cursor a clean way to retry them in order. The code already hints at the latter because downloaded blocks are dropped on `UnknownBlock`-style proof-policy and parent-state errors in `node/src/substrate/service.rs`, even though the sync state machine expects historical progress to continue after `on_block_imported`.

Next, change the importer so fork-following blocks are not lost when the parent state is not yet usable at that instant. The repair should keep downloaded blocks in a retryable queue, or otherwise preserve enough progress information that the next import attempt continues from the right sibling branch without forcing an operator restart. The exact code should be added in `node/src/substrate/service.rs` near the downloaded-block import loop and, if needed, in `node/src/substrate/sync.rs` where downloaded blocks are queued and requeued.

Then add regression coverage. The new test should explicitly model the losing-sibling case instead of a generic longer-chain reorg. The preferred location is `tests/node_resilience.rs` or a focused unit test in `node/src/substrate/sync.rs` plus an integration-style test in `tests/` if the behavior spans both sync and import layers. The test must demonstrate that after a node imports or mines a losing sibling, receiving the winning sibling branch causes it to keep progressing to the longer tip without process restart.

Finally, run focused tests for the node crate and any integration target that covers the repaired path, then record the commands and outcomes below.

## Concrete Steps

From the repository root `/Users/pldd/Projects/Reflexivity/Hegemon`:

1. Read the sync and import code:

       sed -n '1060,1305p' node/src/substrate/sync.rs
       sed -n '1500,1655p' node/src/substrate/sync.rs
       sed -n '8375,8948p' node/src/substrate/service.rs

2. Edit the importer and sync queueing logic in:

       node/src/substrate/service.rs
       node/src/substrate/sync.rs

3. Add or extend regression tests in:

       tests/node_resilience.rs
       node/src/substrate/sync.rs

4. Run focused tests:

       cargo test -p hegemon-node --lib substrate::sync::tests::test_same_height_sibling_fork_backtracks_and_requests_common_ancestor_plus_one -- --exact
       cargo test -p hegemon-node --lib substrate::service::import_tests::
       cargo test -p hegemon-node --lib substrate::sync::tests::
       cargo test -p hegemon-node --lib

## Validation and Acceptance

Acceptance requires all of the following:

1. A regression test reproduces the losing-sibling scenario and fails before the fix.
2. After the fix, the same test passes and shows the lagging node moving beyond the losing height onto the longer branch.
3. The code path does not rely on operator restart or database wipe to resume progress.
4. The importer still preserves normal PoW fork-choice behavior for ordinary block downloads and does not regress existing reorg tests.

Observed validation on 2026-03-19:

1. `cargo test -p hegemon-node --lib substrate::sync::tests::test_same_height_sibling_fork_backtracks_and_requests_common_ancestor_plus_one -- --exact`
   Result: passed.
2. `cargo test -p hegemon-node --lib substrate::service::import_tests::`
   Result: 9 passed, 0 failed.
3. `cargo test -p hegemon-node --lib substrate::sync::tests::`
   Result: 5 passed, 0 failed.
4. `cargo test -p hegemon-node --lib`
   Result: 191 passed, 0 failed, 5 ignored.
5. `cargo test -p hegemon-node`
   Result: package tests passed; library tests, bin test harnesses, and doc-tests all completed without failures.
6. `make node`
   Result: release `hegemon-node` rebuilt successfully with the first reorg-recovery patch in `target/release/hegemon-node`.
7. `cargo test -p hegemon-node --lib substrate::sync::tests::test_on_local_revert_resets_downloading_cursor_to_local_best -- --exact`
   Result: passed.
8. `cargo test -p hegemon-node --lib substrate::service::import_tests::test_finalized_chain_conflict_error_matches_not_in_finalized_chain -- --exact`
   Result: passed.
9. `cargo test -p hegemon-node --lib substrate::sync::tests::`
   Result: 6 passed, 0 failed.
10. `cargo test -p hegemon-node --lib substrate::service::import_tests::`
    Result: 10 passed, 0 failed.
11. `cargo test -p hegemon-node`
    Result: 193 passed, 0 failed, 5 ignored after adding poisoned-finality recovery.
12. `make node`
    Result: release `hegemon-node` rebuilt successfully with the poisoned-finality recovery patch in `target/release/hegemon-node`.
13. `cargo test -p hegemon-node --lib substrate::sync::tests::test_on_downloaded_parent_missing_rewinds_cursor_to_missing_parent_height -- --exact`
    Result: passed.
14. `cargo test -p hegemon-node --lib substrate::sync::tests::test_tick_requests_missing_height_even_with_deferred_queue -- --exact`
    Result: passed.
15. `cargo test -p hegemon-node --lib substrate::sync::tests::`
    Result: 8 passed, 0 failed.
16. `cargo test -p hegemon-node --lib substrate::service::import_tests::`
    Result: 10 passed, 0 failed.
17. `cargo test -p hegemon-node`
    Result: 195 passed, 0 failed, 5 ignored after adding ancestor-gap recovery.
18. `make node`
    Result: release `hegemon-node` rebuilt successfully with the ancestor-gap recovery patch in `target/release/hegemon-node`.

If a manual proof is needed, start two miners on the same chainspec, force a sibling block at the same height, extend one branch, and observe the lagging node’s `hegemon_consensusStatus.height` rise beyond the fork height while the original process remains alive.

## Idempotence and Recovery

The code changes are additive and safe to rerun. Test fixtures and temporary databases should live under test temp directories so repeated runs do not require manual cleanup. If an intermediate test crashes, rerun the same test command after cleanup of only that test’s temp directory; no global node database reset should be necessary.

If a partial implementation leaves the sync path unstable, revert only the work introduced for this plan and keep the regression test that demonstrates the failure, so the next attempt starts from a reproducible case instead of anecdotal reports.

## Artifacts and Notes

Important live evidence gathered before implementation:

    laptop hegemon_consensusStatus.height = 1199
    ovh    hegemon_consensusStatus.height = 1243

    chain_getBlockHash(1198):
      laptop = 0xe151f64dd6c82cc0b39da5a0618981209303a204a265e61c2f59f1b2d6aa8d90
      ovh    = 0xe151f64dd6c82cc0b39da5a0618981209303a204a265e61c2f59f1b2d6aa8d90

    chain_getBlockHash(1199):
      laptop = 0x32173a2c51f640aa56b7ea902ee35573b2eeb0d0f1b3eec5ba57f841531b9b62
      ovh    = 0xed3cc8dc22a24136531013c1a85d510c019c133667634ae245de1f12f858121a

These hashes are the concrete fork signature this plan is intended to harden against.

## Interfaces and Dependencies

Do not introduce a new sync subsystem. Keep using the existing interfaces:

- `crate::substrate::sync::SyncService`
- `crate::substrate::sync::DownloadedBlock`
- `crate::substrate::service` block import loop
- Substrate `sc_consensus::BlockImport`

At the end of this work, the sync/import boundary must still obey this contract:

- `SyncService::drain_downloaded()` returns blocks in download order.
- The block import loop may defer blocks that are temporarily not importable, but it must preserve enough ordering/state to retry them.
- `SyncService::on_block_imported(number, hash)` remains the single way sync learns that forward progress actually occurred.

Revision note: created this ExecPlan after diagnosing a live same-height sibling-fork stall so the repair can be implemented and verified against a concrete failure mode instead of operator folklore.
