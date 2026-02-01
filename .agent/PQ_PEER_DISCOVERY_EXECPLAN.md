# PQ Peer Discovery: Address Exchange + Opportunistic Dialing

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Make Hegemon testnet nodes robust when they are not listed as “seed” nodes.

After this work, a node that only knows the same `HEGEMON_SEEDS` list as everyone else (but is not itself in that list) should still:

1. Learn additional peer addresses via the network (peer discovery), without requiring libp2p’s Kademlia/mDNS stack.
2. Maintain multiple peers over time (not just a single seed).
3. Stay synced while mining, because it can keep getting blocks/headers from multiple peers even if one connection stalls or drops.

You can see this working by starting 3 nodes where only 1 node is in `HEGEMON_SEEDS`, then confirming the two “non-seed” nodes converge to >1 peers and continue to advance `chain_getHeader` while mining.

## Progress

- [x] (2026-02-01T01:30Z) Draft ExecPlan and identify the current networking path used by the Substrate node (`PqNetworkBackend`), including where peer lists come from.
- [x] (2026-02-01T01:33Z) Implement a minimal peer-discovery protocol over the existing PQ network framing: `Hello` (announce listen port), `GetAddrs`, `Addrs`.
- [x] (2026-02-01T01:34Z) Persist discovered addresses under the node base path (`<base-path>/pq-peers.bin`).
- [x] (2026-02-01T01:37Z) Opportunistically dial discovered addresses when peer count is low (bounded fanout, avoid duplicate overwrites).
- [x] (2026-02-01T01:39Z) Add focused tests for discovery message round-trip and address filtering.
- [x] (2026-02-01T01:48Z) Validate via `cargo test -p network` and `cargo test -p hegemon-node` (macOS requires `LIBCLANG_PATH` / `DYLD_LIBRARY_PATH`).
- [x] (2026-02-01T15:30Z) Add periodic discovery refresh (`GetAddrs` tick + cached dial attempts) so early-joining nodes learn later peers; gate dialing on a minimum peer target (`HEGEMON_PQ_DISCOVERY_MIN_PEERS`, `HEGEMON_PQ_DISCOVERY_TICK_SECS`).
- [x] (2026-02-01T15:30Z) Defer announced blocks when the parent header is missing (avoid `forced_inclusions(parent_hash)` runtime API errors during proof verification).

## Surprises & Discoveries

- Observation: The node crate is Rust 2021 edition, so “let-chains” (`if let ... && ...`) are rejected.
  Evidence: `cargo test -p hegemon-node` failed with “let chains are only allowed in Rust 2024 or later”.

- Observation: On macOS, `cargo test` fails building `librocksdb-sys` unless `libclang.dylib` is discoverable.
  Evidence: `dyld: Library not loaded: @rpath/libclang.dylib` (fixed by exporting `LIBCLANG_PATH`/`DYLD_LIBRARY_PATH` per `Makefile`).

## Decision Log

- Decision: Implement “Bitcoin-style” address exchange (addr/getaddr) rather than a DHT (Kademlia).
  Rationale: Our Substrate node does not currently use sc-network/libp2p. Address exchange is enough to fix the observed “only seeds stay connected” behavior with minimal risk and can be extended later.
  Date/Author: 2026-02-01 / Codex

- Decision: Encode discovery messages with serde+bincode, carried inside the existing PQ framed message format.
  Rationale: `SocketAddr` is already serde-friendly and we avoid adding SCALE codec dependencies to the `network` crate just for discovery.
  Date/Author: 2026-02-01 / Codex

- Decision: Use `Hello { listen_port }` so receivers can derive a dialable `IP:port` from the observed peer IP.
  Rationale: The TCP source port is often ephemeral for outbound connections; advertising the listening port is the minimum needed to reconstruct a reachable address without libp2p Identify.
  Date/Author: 2026-02-01 / Codex

## Outcomes & Retrospective

The Substrate node now performs basic peer discovery over the PQ network:

- Nodes exchange `Hello` (listen port) and `GetAddrs`/`Addrs` on connect.
- Learned addresses are persisted at `<base-path>/pq-peers.bin`.
- Nodes periodically re-request addresses and opportunistically dial a small batch of learned addresses until reaching the minimum peer target (defaults: 4 peers, 30s tick).
- The PQ backend drops duplicate peer connections (same peer ID) rather than overwriting an existing connection entry.

This should make “non-seed” nodes converge to multiple peers over time, removing the seed-only connectivity cliff observed on the testnet.

## Context and Orientation

Hegemon’s Substrate node does not use libp2p/sc-network discovery today.

Instead, the node starts `network::PqNetworkBackend` (file: `network/src/network_backend.rs`) and only maintains outbound connections to the configured bootstrap nodes (`HEGEMON_SEEDS`). The rest of the node learns about peers only through inbound connections.

This means seed nodes act as the only “rendezvous” points; nodes that are not seeds can end up with too few peers and miss blocks (especially while mining), leading to unknown-parent / sync churn.

We already have a non-Substrate P2P service (`network/src/service.rs`) that implements address exchange and opportunistic dialing, but the Substrate node path does not use it. This plan ports the essential “address exchange” idea into the Substrate node’s PQ backend path.

Terms used in this plan:

- “Seed”: a bootstrap node address listed in `HEGEMON_SEEDS` that every node dials on startup.
- “Discovery”: the process of learning additional reachable peer addresses beyond seeds.
- “Address exchange”: a small protocol where peers ask for and share lists of socket addresses (IP:port) to dial.

## Plan of Work

Implement a small discovery protocol and integrate it into the Substrate node’s PQ network event handler.

1. Define a discovery protocol name (string constant) and a serde/bincode-encoded message enum:

   - `Hello { listen_port }`: sent after connect so the receiver can turn the observed peer IP into a dialable `IP:listen_port` even when the connection’s source port is ephemeral.
   - `GetAddrs { limit }`: ask a peer for up to `limit` addresses.
   - `Addrs { addrs }`: return a bounded list of addresses.

2. Add a small persistent address store to `node/src/substrate/service.rs`:

   - Use the existing `network::PeerStore` (file: `network/src/peer_store.rs`) with a store path under the Substrate `--base-path` (for example `<base-path>/pq-peers.bin`).
   - On startup, load known addresses and use them as candidates for dialing.

3. Wire the discovery protocol into the PQ network event handler loop in `node/src/substrate/service.rs`:

   - On `PeerConnected`:
     - Record the peer’s observed `SocketAddr` keyed by peer ID.
     - Send `Hello` and `GetAddrs` to the new peer.
     - If the connection is outbound (we dialed them), record the dialed address as a known address.
   - On `MessageReceived` for the discovery protocol:
     - If `Hello`, compute `SocketAddr(peer_ip, listen_port)` and record it as a dial candidate.
     - If `GetAddrs`, respond with `Addrs` sampled from the store (bounded).
     - If `Addrs`, record them and opportunistically dial a small batch if peer count is below target.

4. Keep dialing bounded and safe:

   - Limit outbound dials per “Addrs” response to a small number (e.g. 4).
   - Exclude addresses currently connected (avoid duplicate connections to the same address).
   - Never dial local/loopback/unspecified addresses.

5. Add a targeted test:

   - Ensure discovery messages round-trip via bincode.
   - Ensure we can persist/load learned addresses via `PeerStore`.

## Concrete Steps

Run from repository root:

1) Implement discovery in `node/src/substrate/service.rs`.
2) Add tests (either in `node/src/substrate/service.rs` existing test module, or a new `tests/*` file if more appropriate).
3) Run:

    cargo test -p network
    cargo test -p hegemon-node

4) Manual validation (devnet):

    make setup
    make node

    # Terminal 1: seed node (must be reachable)
    HEGEMON_MINE=1 HEGEMON_SEEDS="<SEED_IP>:30333" ./target/release/hegemon-node --dev --tmp --name seed

    # Terminal 2/3: non-seed nodes (not in the seed list)
    HEGEMON_MINE=1 HEGEMON_SEEDS="<SEED_IP>:30333" ./target/release/hegemon-node --dev --tmp --name a
    HEGEMON_MINE=1 HEGEMON_SEEDS="<SEED_IP>:30333" ./target/release/hegemon-node --dev --tmp --name b

    # Expect: nodes a/b eventually show >1 peers (system_health) and keep advancing height while mining.

## Validation and Acceptance

Acceptance is behavioral:

1. Start a seed node and two non-seed nodes with identical `HEGEMON_SEEDS`.
2. Within a minute or two, each non-seed node’s `system_health` reports peers > 1.
3. While mining is enabled (`HEGEMON_MINE=1`), non-seed nodes continue to advance `chain_getHeader` height and do not permanently stall after the seed is temporarily restarted.

## Idempotence and Recovery

The discovery store is a cache. It is safe to delete `<base-path>/pq-peers.bin` to reset discovery state.

If dialing becomes too aggressive, reduce the dial batch size and add stricter filtering (only dial globally-routable IPs).

## Artifacts and Notes

Plan created because peer discovery is a cross-cutting networking behavior change that affects operator experience and testnet stability.
