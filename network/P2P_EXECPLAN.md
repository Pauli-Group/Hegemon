# P2P Infrastructure Execution Plan

**Goal:** Ship the first working P2P testnet for the Synthetic Hegemonic Currency.
**Strategy:** Replace the current in-memory `GossipRouter` with a TCP-based P2P layer using the existing Post-Quantum (PQ) handshake and encryption primitives.

## 1. Architecture

The P2P layer will sit alongside the `NodeService`. It will bridge the internal `tokio::sync::broadcast` channel (used by the node components) with external TCP connections.

### 1.1 Components

*   **`P2PService`**: The main actor managing the network layer.
*   **`Transport`**: Handles TCP connections, framing, and the transition from plaintext to `SecureChannel`.
*   **`PeerManager`**: Manages the set of connected peers, handles peer discovery (static seeds for v1), and connection lifecycle.
*   **`GossipBridge`**: Forwards messages between the internal `GossipRouter` and the `P2PService`.

### 1.2 Protocol Stack

1.  **Transport**: TCP.
2.  **Handshake**: PQ-authenticated key exchange (ML-KEM + ML-DSA) as defined in `network/src/lib.rs`.
3.  **Encryption**: AES-256-GCM (via `SecureChannel`).
4.  **Framing**: 4-byte length prefix.
5.  **Serialization**: Bincode.
6.  **Application**: `WireMessage` enum (Gossip, Ping/Pong).

## 2. Implementation Steps

### Phase 1: Wire Protocol & Transport (`network/src/p2p.rs`)

Define the messages exchanged over the wire.

```rust
#[derive(Serialize, Deserialize)]
pub enum WireMessage {
    // Handshake messages are handled separately during connection setup
    Ping,
    Pong,
    Gossip(GossipMessage), // Wraps the existing GossipMessage
}
```

Implement a `Connection` struct that wraps a `TcpStream`.
*   **Buffering**: Use `tokio_util::codec` with `LengthDelimitedCodec` or manual buffering.
*   **Handshake Flow**:
    1.  Initiator sends `HandshakeOffer`.
    2.  Responder sends `HandshakeAcceptance`.
    3.  Initiator sends `HandshakeConfirmation`.
    4.  Both sides derive `SecureChannel`.
*   **Encrypted I/O**: Once the channel is secure, all subsequent reads/writes go through `SecureChannel::encrypt` / `SecureChannel::decrypt`.

### Phase 2: Peer Management (`network/src/peer_manager.rs`)

Implement `PeerManager` to handle:
*   **Active Peers**: Map of `PeerId` -> `mpsc::Sender<WireMessage>`.
*   **Connection Pool**: Maintain a target number of outbound connections.
*   **Seed Nodes**: Load a list of static IP:Ports from config to bootstrap the network.
*   **Heartbeats**: Periodically send `Ping` and disconnect if no `Pong`.

### Phase 3: The P2P Service (`network/src/service.rs`)

The `P2PService` orchestrates everything:
1.  **Listen**: Bind to a TCP port (e.g., 9000) and accept incoming connections.
2.  **Connect**: proactively connect to seed nodes.
3.  **Loop**:
    *   Select on incoming TCP connections.
    *   Select on internal `GossipRouter` receiver.
    *   Select on peer messages.

**Bridging Logic:**
*   **Outbound**: When `GossipRouter` receives a message (from the local miner/wallet), `P2PService` broadcasts it to all connected TCP peers.
*   **Inbound**: When a TCP peer sends a `GossipMessage`, `P2PService` injects it into the `GossipRouter` so the local node processes it.

### Phase 4: Node Integration (`node/src/bin/node.rs`)

Update the node binary to start the P2P service.

1.  **Config**: Add `p2p_addr` (default `0.0.0.0:9000`) and `seeds` (Vec<String>) to `NodeConfig`.
2.  **Startup**:
    *   Initialize `PeerIdentity` (load from disk or generate).
    *   Start `P2PService` with the `GossipRouter` handle.
    *   Ensure `P2PService` runs in the background (tokio::spawn).

## 3. Task List

- [x] **Define `WireMessage`** in `network/src/lib.rs`.
- [x] **Implement `Connection` wrapper**:
    - [x] Handle raw TCP read/write.
    - [x] Implement the 3-way handshake using `PeerIdentity`.
    - [x] Implement `send_encrypted` and `recv_encrypted`.
- [x] **Implement `P2PService`**:
    - [x] TCP Listener loop.
    - [x] Outbound connector loop (reconnect to seeds).
    - [x] Message dispatch loop.
- [x] **Update `NodeConfig`**: Add P2P settings.
- [x] **Update `main`**: Launch P2P service.
- [ ] **Test**:
    - [ ] Unit test handshake flow with mock streams.
    - [ ] Integration test: Spin up Node A and Node B, connect them, ensure a block mined on A reaches B.

## 4. Future Improvements (Post-Testnet)

*   **DNS Seeding**: Replace static lists with DNS records.
*   **Peer Discovery**: Implement a simple address book exchange (GetAddr/Addr).
*   **Block Aggregation**: Implement the "Block + Proof" gossip optimization to reduce bandwidth.
*   **NAT Traversal**: UPnP or hole punching.
