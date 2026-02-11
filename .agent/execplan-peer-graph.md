# Extend Peer Graph With Multi-Hop Discovery

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

PLANS.md reference: `.agent/PLANS.md`. This document must be maintained in accordance with that file.

## Purpose / Big Picture

Operators need to see not only their direct peers but also each peer’s own connected peers so the dashboard can render a multi-hop graph. After this change, the node will periodically request a peer list from each connected peer, cache the results, and expose a new `hegemon_peerGraph` RPC that combines direct peers with reported peers. The dashboard will show the local node in one color, direct peers in another, and indirect peers in a third. Success is visible by opening the Peers modal and seeing a two-ring graph with indirect nodes that were not directly connected.

## Progress

- [x] (2026-02-10T00:00Z) Add discovery protocol messages for peer graph requests/responses and implement response handling.
- [x] (2026-02-10T00:00Z) Track peer graph reports in the node service and expose `hegemon_peerGraph` RPC.
- [x] (2026-02-10T00:00Z) Update the dashboard graph to render local, direct, and indirect peers with distinct colors.
- [x] (2026-02-10T00:00Z) Update API and ops docs (`docs/API_REFERENCE.md`, `DESIGN.md`, `METHODS.md`) for the new peer graph flow.
- [ ] (2026-02-10T00:00Z) Validate by rebuilding the node and confirming the UI graph updates.

## Surprises & Discoveries

None yet.

## Decision Log

- Decision: Use the existing PQ discovery protocol (`/hegemon/discovery/pq/1`) to carry peer graph messages instead of inventing a new protocol ID.
  Rationale: Keeps PQ transport plumbing minimal and leverages the existing message dispatch.
  Date/Author: 2026-02-10 / gpt-5.2-codex

- Decision: Render indirect peers on a second (outer) ring and use neutral vs. warning colors to maintain contrast without overusing accents.
  Rationale: Two rings keep the graph readable while keeping the accent palette within brand guidance.
  Date/Author: 2026-02-10 / gpt-5.2-codex

## Outcomes & Retrospective

Not completed yet.

## Context and Orientation

The PQ network does not expose `system_peers`. The dashboard currently calls `hegemon_peerList` to obtain direct peers and renders a graph locally in `node/static/block-dashboard.html`. PQ discovery messages live in `node/src/substrate/discovery.rs` and are processed in the PQ event handler inside `node/src/substrate/service.rs`. Custom RPC methods are defined in `node/src/substrate/rpc/hegemon.rs` and implemented in `node/src/substrate/rpc/production_service.rs`. The `rpc_methods` list in `node/src/substrate/service.rs` is a static list used by Polkadot.js Apps.

Terms:
“Direct peers” are the peers our node is connected to. “Indirect peers” are peers that direct peers report as their connections. The “peer graph report” is the cached list of indirect peers reported by a given direct peer.

## Plan of Work

First, extend the discovery protocol message enum with new request/response variants and a small struct that serializes peer identifiers and socket addresses. Then, update the PQ event handler to respond to peer graph requests and to cache peer graph responses keyed by the reporting peer. Add a periodic tick (and an on-connect trigger) to request peer graphs from connected peers. Next, introduce a new RPC method `hegemon_peerGraph` that returns the local peer id, direct peers, and reported peers, and plumb the cached data into `ProductionRpcService`. Update the dashboard to call `hegemon_peerGraph`, render a two-ring graph, and color nodes according to role. Finally, document the new RPC and discovery behavior in `docs/API_REFERENCE.md`, `DESIGN.md`, and `METHODS.md`.

## Concrete Steps

1. Edit `node/src/substrate/discovery.rs` to add:
   - `DEFAULT_PEER_GRAPH_LIMIT`.
   - `PeerGraphEntry { peer_id: [u8; 32], addr: SocketAddr }`.
   - `DiscoveryMessage::GetPeerGraph { limit }` and `DiscoveryMessage::PeerGraph { peers }`.

2. Edit `node/src/substrate/service.rs` to:
   - Add a `PeerGraphReport` struct holding `reported_at` and `Vec<PeerGraphEntry>`.
   - Add `peer_graph_reports: Arc<RwLock<HashMap<PeerId, PeerGraphReport>>>`.
   - On `PeerConnected`, send `GetPeerGraph`.
   - On `PeerDisconnected`, remove report.
   - On `DiscoveryMessage::GetPeerGraph`, respond with our connected peer list (bounded by limit).
   - On `DiscoveryMessage::PeerGraph`, update the report cache.
   - Add a periodic tick to request peer graphs every N seconds.

3. Edit `node/src/substrate/rpc/hegemon.rs` to:
   - Define `PeerGraphSnapshot` and `PeerGraphReport` types for JSON-RPC.
   - Add `hegemon_peerGraph` to the API and service trait.

4. Edit `node/src/substrate/rpc/production_service.rs` and `node/src/substrate/service.rs` to:
   - Store `peer_graph_reports` and `local_peer_id` in the RPC service.
   - Implement `peer_graph()` to return direct peers plus the cached reports.

5. Update `node/static/block-dashboard.html` and `node/static/dashboard.css` to:
   - Call `hegemon_peerGraph` in the Peers modal.
   - Render local, direct, and indirect nodes with distinct colors and two rings.
   - Ensure labels only appear on hover.

6. Update docs:
   - `docs/API_REFERENCE.md` to include `hegemon_peerGraph` and its schema.
   - `DESIGN.md` peer discovery section to mention peer graph requests.
   - `METHODS.md` to instruct operators to use `hegemon_peerGraph`.

## Validation and Acceptance

Build the node from the repo root with:
  make node
Start a local node and at least one peer. Open `node/static/block-dashboard.html`, click “Peers”, and observe:
- Direct peers appear on the inner ring with their color.
- Indirect peers appear on the outer ring with their distinct color.
- Hovering a node reveals its IP address.
- The “Peers” list in the modal still shows direct peers.

## Idempotence and Recovery

All changes are additive and safe to reapply. If build errors occur, revert only the last edit and reapply with the plan steps; no stateful migrations are required. Removing the new discovery message variants returns behavior to the current direct-peer-only graph.

## Artifacts and Notes

Expected new RPC method name:
  hegemon_peerGraph

Expected discovery message additions:
  GetPeerGraph, PeerGraph

## Interfaces and Dependencies

The discovery protocol is defined in `node/src/substrate/discovery.rs` and serialized with `bincode` over the PQ discovery protocol. The RPC interface is defined via `jsonrpsee` in `node/src/substrate/rpc/hegemon.rs`. The dashboard renders from `node/static/block-dashboard.html` and `node/static/dashboard.css`.

Plan updated: initial version created to cover multi-hop peer graph discovery and visualization.
