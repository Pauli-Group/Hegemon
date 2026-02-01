```md
# Make PQ chain sync fork-aware (ancestor backtracking)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan is maintained in accordance with `./.agent/PLANS.md`.

## Purpose / Big Picture

Nodes that briefly mine in isolation (0 peers) can end up on a different PoW fork even when the genesis is identical. When they later reconnect, the current “sync by height” implementation can get stuck requesting blocks whose parents are not in the local DB, causing endless `UnknownParent` / `UnknownBlock` behavior and preventing convergence.

After this change, a node that reconnects to a longer peer chain must automatically find the common ancestor, import the peer’s fork from that ancestor forward, and converge to the longest chain without wiping its database.

You can see this working by letting a node mine alone for a short period, then reconnecting it to a peer with a different chain tip: the behind node should backtrack, import, and then both nodes’ `chain_getBlockHash` should match at the same heights again.

## Progress

- [x] (2026-02-01 18:00Z) Identify root cause: sync requests by height cannot recover once the parent at `our_best` differs from the peer’s parent.
- [x] (2026-02-01 18:10Z) Implement fork-aware sync cursor tracking `(height, hash)` and backtrack-on-mismatch in `node/src/substrate/sync.rs`.
- [x] (2026-02-01 18:12Z) Treat `AlreadyInChain` as sync progress by advancing the sync cursor in `node/src/substrate/service.rs`.
- [x] (2026-02-01 18:20Z) Update mining runbook to document the approved seed list and NTP requirement.
- [ ] Run full monorepo CI-equivalent checks locally (`make check`).
- [ ] Deploy updated `hegemon-node` binary to the VPS and re-test live fork recovery with only approved seeds configured.
- [ ] Open PR, ensure CI green, merge to `main`.

## Surprises & Discoveries

- Observation: The current sync protocol’s `GetBlocks(start_height)` implicitly assumes the peer’s block at `start_height` extends our canonical block at `start_height - 1`. This is false on forks.
  Evidence: Live testnet divergence at height 1759 with identical genesis; `chain_getBlockHash(1759)` differed between nodes while peer connections remained non-zero.

## Decision Log

- Decision: Make the sync client track `(current_height, current_hash)` and validate that the peer’s first returned block builds on `current_hash`. If not, backtrack one block along our current branch and retry.
  Rationale: This is the minimal fork-recovery mechanism that works with a height-based `GetBlocks` request without introducing a new “locator” protocol or requiring libp2p.
  Date/Author: 2026-02-01 / Codex

- Decision: Advance the sync cursor on `ImportResult::AlreadyInChain` for downloaded blocks.
  Rationale: During fork recovery, nodes may re-request blocks they already imported earlier (or imported as side effects). Treating them as progress prevents sync stalls.
  Date/Author: 2026-02-01 / Codex

## Outcomes & Retrospective

TBD after live validation and CI.

## Context and Orientation

- Sync state machine: `node/src/substrate/sync.rs` (`ChainSyncService`).
- Downloaded block import: `node/src/substrate/service.rs` (task `block-import-handler`, Part 1).
- Symptom to eliminate: nodes remain connected but cannot converge after a fork, often logging `UnknownParent` and repeatedly requesting the same heights.

Key constraint: PQ sync uses height-based requests (`SyncRequest::GetBlocks`) over the PQ transport, not Substrate/libp2p. We therefore must implement fork recovery at the application sync layer.

## Plan of Work

1) Update `ChainSyncService`:
   - Store `current_hash` alongside `current_height` inside `SyncState::Downloading`.
   - When receiving a `Blocks` response, decode the first header and compare its `parent_hash` to `current_hash`.
   - On mismatch: walk one block backwards by loading the header for `current_hash`, setting `(current_height, current_hash)` to its parent, and retrying on the next tick.
   - Drive requests from `current_height + 1` and avoid sending a new request while the downloaded queue is non-empty.

2) Update the service import loop:
   - Call `sync.on_block_imported(number, hash)` for `Imported` and `AlreadyInChain` results for downloaded blocks.

3) Update operator-facing docs:
   - Ensure mining runbooks mention the approved seed list for `HEGEMON_SEEDS` and that miners must share the same list.
   - Remind operators to enable time sync (NTP/chrony).

## Concrete Steps

From repo root:

  make check

Deploy to VPS (example):

  ssh hegemon-ovh 'cd /home/ubuntu/hegemon && make node'
  scp target/release/hegemon-node hegemon-ovh:/opt/hegemon/hegemon-node
  ssh hegemon-ovh 'sudo systemctl restart hegemon-node'

## Validation and Acceptance

Local reproducible test (manual):

1) Start node A with no seeds (mines alone).
2) Start node B with seeds and mine for a bit (or vice versa).
3) Restart node A with `HEGEMON_SEEDS` pointing at node B.
4) Acceptance: node A transitions from `system_health.isSyncing=true` to `false` and `chain_getBlockHash(h)` matches node B for several heights including the previously divergent height.

Live validation:

- With the approved seed list only (no third-party hardwired seeds), bring up the VPS and a non-seed miner, let them mine concurrently, and verify they do not get stuck after transient disconnects.

## Idempotence and Recovery

All changes are safe to re-run. If live nodes are already forked, you can still wipe a node database to recover quickly, but the acceptance criteria for this plan is that wiping is no longer required for fork convergence.

## Artifacts and Notes

TBD after CI + live validation.

## Interfaces and Dependencies

- `node/src/substrate/sync.rs`: extend `SyncState::Downloading` with `current_hash: [u8; 32]` and change `on_block_imported` to `on_block_imported(number: u64, hash: [u8; 32])`.
```
