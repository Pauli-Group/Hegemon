# Stabilize PoW Sync Import Ordering and DA Encoding

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan is maintained in accordance with `./.agent/PLANS.md`.

## Purpose / Big Picture

When a node syncs from a peer, it should import blocks in order without failing because a parent header is not yet in the local database, and it should not reject historical blocks because DA sampling asks a peer for chunks it no longer has. After this change, a fresh sync from a peer should steadily advance height without “UnknownBlock” proof verification errors or “DA sampling failed” rejections. You can see this working by starting a clean VPS node, watching it import beyond the previous stall height, and confirming that `chain_getHeader` keeps increasing.

## Progress

- [x] (2026-01-13 11:58Z) Review sync import path and verify where proof verification and DA sampling run for downloaded blocks.
- [x] (2026-01-13 11:58Z) Draft service-layer changes to sort downloaded blocks, defer blocks with missing parents, and avoid DA sampling during sync by deriving DA encoding locally.
- [x] (2026-01-13 12:00Z) Add a requeue API to `node/src/substrate/sync.rs` so deferred blocks can be retried without re-downloading.
- [ ] (2026-01-13 12:03Z) Commit code changes and rebuild on VPS (completed: local `make node` + git commit; remaining: VPS build).
- [ ] (2026-01-13 11:58Z) Deploy the new binary to the VPS, wipe the VPS chain data, restart the service, and confirm sync progresses.
- [ ] (2026-01-13 11:58Z) Reboot the VPS after confirming the new sync behavior.

## Surprises & Discoveries

- Observation: Proof verification during sync depends on runtime APIs that require the parent header to exist in the local DB, so importing out-of-order blocks yields `UnknownBlock` errors even though the blocks are valid.
  Evidence: VPS logs showed `runtime api error (compact_merkle_tree): UnknownBlock` during `verify_proof_carrying_block`.
- Observation: DA sampling in the sync path requests chunks from a peer, which can fail for historical blocks that are no longer served, even though the full extrinsics are already present.
  Evidence: VPS logs showed `Rejecting synced block (DA sampling failed)` with missing chunk errors.

## Decision Log

- Decision: Defer downloaded blocks whose parents are missing or whose proof verification hits `UnknownBlock`, then requeue them for later import.
  Rationale: Sync receives blocks in batches that can be out of order; deferring prevents premature rejection while keeping the proof verification intact.
  Date/Author: 2026-01-13 / Codex
- Decision: Replace DA sampling with local DA encoding derivation during sync import.
  Rationale: For historical sync we already have the block body, so sampling is redundant and can fail due to missing peer data.
  Date/Author: 2026-01-13 / Codex

## Outcomes & Retrospective

No milestone completed yet.

## Context and Orientation

The PoW sync loop lives in `node/src/substrate/service.rs` inside `new_full_with_client`, where downloaded blocks are drained from `ChainSyncService` and imported. Proof verification for commitment blocks is performed by `verify_proof_carrying_block`, which calls the runtime API `compact_merkle_tree` using the parent hash. DA sampling currently calls `sample_da_for_block`, which depends on peer-served chunks. The sync queue itself is managed by `ChainSyncService` in `node/src/substrate/sync.rs`, which stores `DownloadedBlock` entries in a `VecDeque` and exposes `drain_downloaded` for the service layer to consume.

“DA encoding” here refers to the data-availability encoding derived from block extrinsics using the DA parameters, which can be computed locally via `build_da_encoding_from_extrinsics`.

## Plan of Work

Update the sync service to support requeueing blocks: add a method that takes a vector of `DownloadedBlock` and pushes them back onto the front of the `downloaded_blocks` deque while respecting `MAX_IMPORT_BUFFER`. Then finish the service-layer import loop so it sorts downloaded blocks, defers blocks whose parent headers are not yet known, and retries them by calling the new requeue method. Adjust the sync import path so DA encoding is built locally instead of sampled from peers. Keep proof verification enabled, but treat `UnknownBlock` errors as deferrable rather than fatal.

## Concrete Steps

Run the following from the repository root:

1) Edit `node/src/substrate/sync.rs` to add a `requeue_downloaded` method on `ChainSyncService` and log when blocks are requeued.
2) Ensure `node/src/substrate/service.rs` calls `requeue_downloaded` after deferring blocks, and that DA encoding uses `build_da_encoding_from_extrinsics` for sync imports.
3) Build the node: run `make node`.
4) On the VPS, pull the branch, run `make node`, copy the binary to `/opt/hegemon/hegemon-node`, wipe `/opt/hegemon/data`, and restart `hegemon-node.service`.

Expected build transcript excerpt (example):

  make node
  ...
  Finished release [optimized] target(s) in 4m 12s

## Validation and Acceptance

Start the VPS node with a clean data directory and observe logs. Sync should move past the previous stall height (around 12) without `UnknownBlock` proof verification errors or DA sampling errors. Run the RPC query:

  curl -s -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"chain_getHeader"}' http://127.0.0.1:9944

Acceptance: the reported header number increases over time and peers are non-zero.

## Idempotence and Recovery

Requeueing blocks is safe to repeat because it only reorders pending downloads without mutating on-disk state. If sync still stalls, wipe `/opt/hegemon/data` and restart the service to force a clean sync. If the VPS build fails, rerun `make setup` then `make node` to restore the toolchain.

## Artifacts and Notes

No artifacts yet.

## Interfaces and Dependencies

In `node/src/substrate/sync.rs`, add:

    pub fn requeue_downloaded(&mut self, blocks: Vec<DownloadedBlock>)

The method must push blocks back into `self.downloaded_blocks` without incrementing `stats` and must respect `MAX_IMPORT_BUFFER`.

Plan update: Initial ExecPlan created to guide sync import stabilization and VPS deployment. Reason: change spans sync ordering, proof verification, and DA handling, so it qualifies as a significant behavioral fix.
Plan update: Marked requeue API as implemented after adding `requeue_downloaded` to `node/src/substrate/sync.rs`. Reason: keep progress section accurate for the new method.
Plan update: Noted local rebuild completion and split remaining commit/VPS build work in Progress. Reason: reflect the actual state after running `make node` locally.
Plan update: Recorded that the code changes are now committed locally. Reason: keep the Progress section aligned with the repository state.
