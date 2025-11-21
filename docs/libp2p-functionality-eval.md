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
  - `PeerManager` tracks peers by `PeerId`, retains an address book (`PeerId -> HashSet<SocketAddr>`), and enforces `max_peers` by evicting the lowest-score entry when full.【F:network/src/peer_manager.rs†L10-L200】
  - Heartbeats increment a simple score and stale peers are pruned after timeouts, with broadcast/ping helpers akin to a minimal connection manager.【F:network/src/peer_manager.rs†L92-L134】【F:network/src/service.rs†L318-L320】

- **Discovery and address exchange**
  - DNS seeding resolves hostnames at startup, merges relay hints, and dials the resulting addresses.【F:network/src/service.rs†L198-L209】【F:network/src/service.rs†L503-L520】
  - Peers exchange compact address lists on connect and feed them into the address book; opportunistic dials pull from that pool when under target peer count.【F:network/src/service.rs†L226-L318】【F:network/src/peer_manager.rs†L153-L192】
  - Gossip also transports address lists so the gossip layer and peer manager stay aligned.【F:network/src/service.rs†L268-L310】

- **NAT traversal and relay hooks**
  - Best-effort UPnP/NAT-PMP/PCP mapping discovers external addresses and advertises them; the result is broadcast to peers and recorded in the address book.【F:network/src/nat.rs†L8-L200】【F:network/src/service.rs†L186-L260】
  - A relay configuration flag enables forwarding of hole-punch coordination messages, and nodes announce reachable addresses for relay registration.【F:network/src/service.rs†L248-L260】【F:network/src/service.rs†L442-L500】

## Gaps relative to libp2p capabilities

- **Stream/connection multiplexing** – Messages are multiplexed at the application layer, but there is no stream-based transport mux (e.g., yamux/mplex). Protocol negotiation/upgrade semantics are implicit rather than negotiated.
- **Peer scoring and bans** – Scores only increment on heartbeats; there are no penalties, bans, or backoff timers to resist abuse or prioritize long-lived peers.
- **Discovery richness** – DNS seeds and ad-hoc address gossip exist, but there is no DHT/Kademlia, mdns, or structured peer exchange to mirror libp2p’s discovery suite.
- **Relay data plane** – Coordination messages exist, yet there is no data forwarding/relay circuit functionality analogous to libp2p’s circuit relay v2; hole punching is partially stubbed via coordination but lacks simultaneous-open logic.
- **Protocol ecosystem** – Only gossip and generic `Proto` envelopes are present; there is no gossipsub-compatible topic mesh, RPC, telemetry, or DHT protocol implementations.
- **libp2p bridge** – No bridge daemon exists to interoperate with a native libp2p node; messages stay within the bespoke stack.

## Overall assessment

The stack now mirrors several libp2p building blocks—identity-derived peer IDs, authenticated transport, message-level protocol multiplexing, address books with opportunistic dialing, DNS seeding, and NAT traversal attempts. However, it stops short of libp2p’s full feature set: stream-based multiplexer/negotiation, rich discovery (DHT/mdns), robust peer scoring and bans, relay data forwarding, and a broad protocol ecosystem remain to be built. Completing those areas would move Hegemon much closer to libp2p parity.
