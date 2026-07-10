# Hegemon libp2p-Style Functionality Review

This note evaluates the current networking stack against the libp2p-inspired task list that was previously sketched. It highlights what is already implemented and what remains to close the gap.

## Features implemented today

- **Peer identity and authenticated transport**
  - `PeerId` is a 32-byte SHA-256 fingerprint of the post-quantum signing key, surfaced by `PeerIdentity::peer_id` and used throughout the handshake and connection lifecycle.【F:network/src/lib.rs†L23-L104】【F:network/src/p2p.rs†L81-L142】
  - The handshake establishes a PQ-encrypted channel before any `WireMessage` exchange, giving us authenticated, encrypted links similar to libp2p’s secio/noise layers.【F:network/src/p2p.rs†L81-L169】

- **Protocol multiplexing (message-level)**
  - `ProtocolMessage { protocol: ProtocolId, payload }` is carried inside `WireMessage::Proto`, and a `ProtocolMultiplexer` routes inbound messages to per-protocol channels while fan-outing outbound streams across peers.【F:network/src/lib.rs†L23-L30】【F:network/src/p2p.rs†L58-L66】【F:network/src/service.rs†L18-L175】
  - Gossip remains a dedicated `WireMessage` variant, keeping compatibility with existing block/tx propagation while enabling new protocols to plug in.【F:network/src/p2p.rs†L58-L66】【F:network/src/service.rs†L265-L299】

- **Peer management and connection limits**
  - `PeerManager` tracks peers by `PeerId`, retains bounded address books, and rejects new sessions when a nonzero `max_peers` limit is full. Zero means unlimited admission.【F:network/src/peer_manager.rs†L10-L200】
  - Heartbeats increment a simple score and stale peers are pruned after timeouts, with broadcast/ping helpers akin to a minimal connection manager.【F:network/src/peer_manager.rs†L92-L134】【F:network/src/service.rs†L318-L320】

- **Discovery and address exchange**
  - DNS seeding resolves hostnames at startup, merges relay hints, and dials the resulting addresses.【F:network/src/service.rs†L198-L209】【F:network/src/service.rs†L503-L520】
  - Peers exchange compact address lists on connect and on a periodic rotating refresh. Opportunistic dials rotate across the learned pool when capacity remains, with endpoint deduplication, concurrency bounds, connect/handshake timeouts, and exponential failure backoff.【F:network/src/service.rs】【F:network/src/peer_manager.rs】
  - An unspecified relay registration acts only as a port hint. The authenticated session's observed IP supplies the address, explicit registrations must use that same IP, and the ephemeral inbound source port is never advertised. Accepted registrations are propagated to other peers.【F:network/src/service.rs】
  - Gossip also transports address lists so the gossip layer and peer manager stay aligned.【F:network/src/service.rs†L268-L310】

- **NAT traversal and relay hooks**
  - The network crate contains best-effort mapping support, but the native launcher deliberately leaves automatic router mapping disabled. Public reachability therefore still depends on the host firewall/NAT setup or an explicit caller configuration.【F:network/src/nat.rs】【F:node/src/native/service.rs】
  - A relay configuration flag enables forwarding of hole-punch coordination messages, and nodes announce reachable addresses for registration. There is still no relay data plane or complete simultaneous-open implementation.【F:network/src/service.rs】

## Gaps relative to libp2p capabilities

- **Stream/connection multiplexing** – Messages are multiplexed at the application layer, but there is no stream-based transport mux (e.g., yamux/mplex). Protocol negotiation/upgrade semantics are implicit rather than negotiated.
- **Peer scoring and bans** – Failed endpoint dials now back off, but live-peer scores still only increment on heartbeats; there are no behavioral penalties or bans to resist abusive connected peers or prioritize long-lived peers.
- **Discovery richness** – DNS seeds and ad-hoc address gossip exist, but there is no DHT/Kademlia, mdns, or structured peer exchange to mirror libp2p’s discovery suite.
- **Relay data plane** – Coordination messages exist, yet there is no data forwarding/relay circuit functionality analogous to libp2p’s circuit relay v2; hole punching is partially stubbed via coordination but lacks simultaneous-open logic.
- **Protocol ecosystem** – Only gossip and generic `Proto` envelopes are present; there is no gossipsub-compatible topic mesh, RPC, telemetry, or DHT protocol implementations.
- **libp2p bridge** – No bridge daemon exists to interoperate with a native libp2p node; messages stay within the bespoke stack.

## Overall assessment

The stack now mirrors several libp2p building blocks—identity-derived peer IDs, authenticated transport, message-level protocol multiplexing, rotating address exchange, bounded/backed-off opportunistic dialing, and DNS seeding. These changes remove the seed from the steady-state routing path for publicly reachable peers, but they do not create full libp2p parity: stream multiplexing, DHT/mDNS discovery, robust scoring and bans, reachability verification, relay forwarding, and complete NAT hole punching remain open work.
