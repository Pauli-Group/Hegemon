# P2P address discovery and DNS seeding

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document according to `.agent/PLANS.md`.

## Purpose / Big Picture

After this change a node can accept DNS seed entries instead of hard-coded IPs, resolve them at startup, and automatically dial the resolved peers. Peers will exchange compact address lists on connection, learn new peers without manual configuration, and opportunistically dial new peers whenever the active connection count is below the configured target. Operators should see peers connecting even when only DNS seeds are provided, and newly learned addresses should appear in the address book and be used for outbound dialing.

## Progress

- [x] (2025-02-22 15:00Z) Drafted ExecPlan outlining DNS seed resolution, address exchange messages, and opportunistic dialing.
- [x] (2025-02-22 16:00Z) Implemented DNS seed resolution, address exchange messaging, and opportunistic dialing hooks.
- [x] (2025-02-22 16:20Z) Validated behavior with network crate tests.
- [x] (2025-02-22 16:30Z) Recorded outcomes and retrospective.

## Surprises & Discoveries

- None yet; populate as work proceeds.

## Decision Log

- Decision: Use compact address structs inside a dedicated wire message instead of reusing the broader gossip envelope to keep discovery payloads minimal and scope-limited.
  Rationale: Address exchange is a peer management concern and does not need to enter the global gossip router. A compact struct minimizes serialized size while supporting IPv4 and IPv6.
  Date/Author: 2025-02-22 / assistant

## Outcomes & Retrospective

Implemented DNS/hostname seed resolution that feeds outbound dialing, compact address exchange over the wire to seed the address book on every new connection, and opportunistic dialing when below the peer target. Network crate tests pass, confirming handshake, address conversion, and integration flows remain healthy.

## Context and Orientation

P2P networking lives in `network/src/`, with the transport and wire protocol in `p2p.rs`, peer tracking in `peer_manager.rs`, and orchestration in `service.rs`. Node configuration (`node/src/config.rs`, `node/src/bin/node.rs`) passes seed addresses and listener information into `P2PService`. Gossip currently includes an `Addresses` variant but is not wired into a dedicated discovery flow. The goal is to extend `WireMessage` with compact address exchange, resolve DNS seeds before dialing, update the peer manager's address book with received entries, and trigger outbound dials when below `max_peers`.

## Plan of Work

First, extend configuration handling so seed entries may be hostnames, resolving them to socket addresses during `P2PService` startup. Store resolved addresses for dialing and record them in the address book. Next, define a compact address representation that supports IPv4 and IPv6 with minimal encoding, add a new wire-level message for exchanging address sets, and integrate it into the connection loop. When a peer joins, send the local listening address plus a sampled subset of known addresses; upon receiving an exchange, insert the addresses into the address book. Finally, introduce a periodic opportunistic dialer that, when the active peer count is below `max_peers`, samples stored addresses not currently connected and attempts outbound connections without interfering with the seed reconnection loop. Ensure the peer manager exposes helpers to sample addresses for sharing and dialing while avoiding duplicates of already connected peers or the local endpoint.

## Concrete Steps

1. Update `node/src/config.rs` and `node/src/bin/node.rs` to clarify that seeds may be hostnames; pass the list unchanged into the P2P layer.
2. In `network/src/p2p.rs`, add a compact address type and a wire message variant dedicated to address exchange; include conversions to and from `SocketAddr`.
3. Extend `network/src/peer_manager.rs` to track known addresses, sample subsets for sharing, expose the current peer count, and provide candidates for opportunistic dialing that exclude connected peers and the local address.
4. In `network/src/service.rs`, resolve seed hostnames at startup (using `lookup_host`), enqueue successful resolutions for dialing, and seed the address book. On new peer connections, send the local listening address and a sample of known addresses using the new wire message. When receiving address exchanges, update the address book. Add a periodic check (aligned with heartbeat or a dedicated interval) to attempt outbound dials against sampled addresses whenever the active peer count is below `max_peers`.
5. Add targeted tests for the compact address conversion and peer manager sampling/dialing selection. Run the network crate tests to validate the new behavior.

## Validation and Acceptance

- Start the node with a hostname in `--seeds`; on startup, the service resolves it to socket addresses and attempts outbound connections without panicking. Logs should show resolution success or failure per host and connection attempts to the resolved addresses.
- When two nodes connect, each sends an address exchange containing its listening address and a subset of known peers; receiving nodes add these to their address book. Logged updates should confirm new addresses are recorded.
- While below `max_peers`, the service periodically attempts to dial addresses from the address book; logs show opportunistic dial attempts and successful promotions to active peers.
- `cargo test -p network` passes.

## Idempotence and Recovery

DNS resolution is performed on startup and can be retried on subsequent runs. Opportunistic dialing samples addresses while excluding active peers, so repeated checks will not spam established connections. Failed dial attempts are logged and retried only when the sampling logic surfaces them again, avoiding tight loops. No persistent state is mutated beyond the in-memory address book.

## Artifacts and Notes

Add short log excerpts demonstrating DNS seed resolution, address exchange reception, and opportunistic dialing once implemented.

## Interfaces and Dependencies

- New wire message variant: `WireMessage::AddrExchange(Vec<CompactAddress>)` in `network/src/p2p.rs` to carry compact IPv4/IPv6 endpoints.
- Compact address type with conversions: `CompactAddress::from(SocketAddr)` and `CompactAddress::to_socket_addr()`.
- Peer manager helpers: `peer_count()`, `sample_addresses(limit)`, `address_candidates(local, connected, limit)` returning `SocketAddr` values suitable for dialing; `record_addresses` accepts iterators of `SocketAddr`.
- P2P service hooks: startup DNS resolution using `tokio::net::lookup_host`, address exchange on `NewPeer`, handling of `AddrExchange` messages, and periodic opportunistic dial attempts when `peer_count() < max_peers`.
