# Headers-first sync protocol with recovery

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this file per `.agent/PLANS.md`.

## Purpose / Big Picture

Enable full nodes to synchronize from genesis to the network tip using a headers-first protocol layered on the existing P2P service. Peers should advertise chain tips, serve batches of headers, then provide block bodies and transaction inventory so a freshly started node can validate proof-of-work and seals before joining steady-state gossip.

## Progress

- [x] (2025-02-16 12:00Z) Drafted initial ExecPlan with scope, orientation, and work outline.
- [x] Implement protocol messages and service wiring.
- [x] Build consensus/storage sync loop with validation and recovery.
- [x] Add integration tests covering genesis-to-tip sync via a single peer.
- [x] Update plan sections after implementation and validation.

## Surprises & Discoveries

- Storage lacked per-hash lookups and header serialization helpers, so the sync implementation adds lightweight codecs and a block retrieval method to serve requests.

## Decision Log

- Decision: Use a dedicated protocol ID for sync separate from gossip to isolate validation and retries.  
  Rationale: Avoid overloading gossip paths and allow targeted recovery logic per peer.  
  Date/Author: 2025-02-16 / assistant

## Outcomes & Retrospective

- Headers-first sync now runs over a dedicated protocol with retry-on-failure fallback; integration tests cover genesis-to-tip catch-up.

## Context and Orientation

The P2P layer lives in `network/src`, with `service.rs` managing peer connections and dispatching `ProtocolMessage` payloads keyed by `ProtocolId`. Consensus validation and storage reside in `node/src/service.rs` and `node/src/storage.rs`, where blocks are imported and metadata tracked. Currently only gossip is consumed; there is no headers-first sync or recovery handling. Tests for networking exist in `network/tests/p2p_integration.rs` and `node/tests/network.rs`.

## Plan of Work

Describe edits in sequence:
1. Define a new sync protocol ID and message structs (headers range requests/responses, block body requests, transaction inventory notices) in a shared module accessible to node and network layers. Extend `ProtocolId` use sites accordingly.
2. Update `network/src/service.rs` to allow per-peer protocol messages instead of only broadcast so sync can target specific peers; wire handlers to send and receive sync messages.
3. Build a sync manager in the node layer (new module) that registers with the P2P service, drives headers-first download from peer tip to local best/genesis, validates headers via consensus PoW/seal checks, requests missing bodies/transactions, and transitions to gossip once caught up.
4. Implement recovery logic to fall back to alternate peers on validation or response failures, resuming from last verified height.
5. Add tests spinning up lightweight peers to assert a fresh node syncs from genesis to peer tip, including retry paths on invalid data.

## Concrete Steps

- Work from repository root.
- Add protocol definitions in `network` or shared crate; ensure serialization derives.
- Adjust `P2PService` to support targeted protocol sends and inbound routing to sync handler.
- Create `node/src/sync.rs` (or similar) implementing the headers-first state machine and hooking into `NodeService` startup.
- Extend storage/consensus helpers if needed to query blocks/headers for range responses and to import validated data.
- Write integration tests under `node/tests` that start two nodes with in-memory storage and assert the follower reaches the leader's tip using the new protocol.
- Run `cargo test -p node` (and targeted tests) to verify behavior.

## Validation and Acceptance

A contributor should be able to run `cargo test -p node sync` (or the full suite) and see tests proving:
- A new node connects to a peer, downloads headers from tip back to genesis/local best, validates PoW/seals, then fetches bodies/transactions to match tip height.
- If a peer serves an invalid header/body, the sync logic retries another peer and still reaches the correct tip.
- Once synced, nodes rely on gossip for ongoing blocks/transactions.

## Idempotence and Recovery

Changes should be additive and resilient: rerunning the sync should resume from the last persisted height without duplicating data. Tests and sync loops must handle disconnects by re-requesting ranges from remaining peers.

## Artifacts and Notes

After implementation, capture key logs or test outputs that demonstrate sync progress and recovery behavior.

## Interfaces and Dependencies

- New sync protocol messages (request/response enums) exposed from a shared module (likely `node::sync` or `network::sync`), serialized with `serde`.
- `P2PService` must expose a per-peer send method for protocol messages and forward inbound sync payloads to registered handlers.
- Sync manager requires access to `Storage` for persisting headers/bodies and `PowConsensus` for validation (e.g., `import_pow_block`).
