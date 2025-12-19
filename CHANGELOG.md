# Changelog

## v0.3-alpha - 2025-12-19
- Disclosure-on-demand payment proofs: new disclosure circuit, wallet persistence, and `payment-proof` CLI (create/verify/purge).
- Proof verification hardening across transaction/settlement verification and shielded-pool enforcement, plus value balance/fee plumbing.
- Chainspec 0.3 refresh and transaction builder cleanup (ciphertext padding removal).

## v0.2-alpha - 2025-12-18
- STARK transaction batching (2/4/8/16): `batch-circuit`, pallet verification, and wallet CLI support.
- Recursive epoch proof plumbing and verifier recursion circuits for aggregation experiments.
- PQ networking robustness improvements and peer persistence fixes.

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
