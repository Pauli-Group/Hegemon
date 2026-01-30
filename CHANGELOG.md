# Changelog

## v0.8.0 - 2026-01-23
- Version bump: `hegemon-node`, `wallet`, and `walletd` are now `0.8.0`.

## v0.7.1 - 2026-01-14
- Version bump: `hegemon-node` and `wallet` are now `0.7.1`.
- Core console: always pass `--dev` when the dev toggle is enabled, resolve chain spec paths reliably, and bundle the dev chainspec in packaged builds.
- P2P seeds: allow host-only defaults (port 30333 implied) to match UI defaults.

## v0.7.0 - 2026-01-14
- Version bump: `hegemon-node` and `wallet` are now `0.7.0`.

## v0.6.1 - 2026-01-13
- Version bump: `hegemon-node` and `wallet` are now `0.6.1`.
- App defaults: seed `hegemon.pauli.group:30333` for first-run connections and prefer live peer counts.

## v0.6.0 - 2026-01-09
- Version bump: `hegemon-node` and `wallet` are now `0.6.0`.

## v0.5-alpha - 2026-01-06
- Scalability architecture pivot: commitment block proofs + parallel transaction-proof verification (supersedes legacy recursive proofs as the default validity path).
- Block production + RPC plumbing for commitment proofs (including `block_getCommitmentProof`) and DA chunk retrieval (`da_getParams`, `da_getChunk`).
- Ops/runbooks refreshed for the commitment-proof flow; legacy recursive-proof docs explicitly marked as superseded.
- Fix: keep production mining (real difficulty) enabled even if PQ networking fails to bind, instead of falling back to scaffold mining.

## v0.4-alpha - 2025-12-25
- Production hardening: shielded-only coinbase, proof-backed transfers, legacy commitment gating + Merkle root history, and subsidy/proof size enforcement.
- Stablecoin issuance/burn: new stablecoin-policy pallet, runtime bindings, wallet mint/burn support, and chain spec updates through 0.4.2 (genesis shielded verifying key).
- Wallet/RPC resilience: metadata-driven extrinsic encoding, stricter anchor encoding validation, and RPC hardening guidance in runbooks.
- Ops tooling: dependency audit script improvements and persisted PQ identity seed.

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
