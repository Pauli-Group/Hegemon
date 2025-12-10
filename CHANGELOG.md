# Changelog

## 2025-02-17
- **Phase 3: PQ libp2p Integration** - Implemented post-quantum secure peer connections
  - Created `pq-noise` crate implementing pure ML-KEM-768 handshake protocol
  - Added AES-256-GCM encrypted sessions with ML-KEM-derived keys
  - Integrated ML-DSA-65 signature authentication for peer identity verification
  - Added `network/src/pq_transport.rs` for network layer integration
  - Created `node/src/substrate/network.rs` for Substrate sc-network integration
  - Updated `node/src/substrate/service.rs` with PQ network configuration
  - All cryptographic material uses post-quantum primitives only (no classical ECDH)
  - Added comprehensive test suite: 13 pq-noise tests + 7 network integration tests

## 2025-02-15
- Rewrote README quickstart/setup to anchor on the unified `hegemon-node` binary with Polkadot.js Apps dashboard.
- Updated contributor and operational runbooks to use Substrate-based node and systemd on VPS seeds.
- Dashboard: Use Polkadot.js Apps at `https://polkadot.js.org/apps/?rpc=ws://127.0.0.1:9944`

## v0.1.0 - Initial public release
- Initial release of the Hegemon protocol
- Core consensus mechanism with Proof of Work and difficulty adjustment
- Basic pallet structure including asset registry, identity, and settlement
- Networking layer with initial P2P capabilities
- Wallet implementation for key management and transaction signing
