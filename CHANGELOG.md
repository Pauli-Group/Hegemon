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
- Rewrote README quickstart/setup to anchor on the unified `hegemon` binary, embedded dashboard, and peer export/import bundles with runbook cross-links.
- Updated contributor and operational runbooks to deprecate the legacy Python/Vite orchestration in favor of `hegemon`-served UI flows and systemd usage on VPS seeds.
- Refreshed dashboard troubleshooting guidance to align with the embedded bundle and call out token/binding checks.
- Branding deviations: none; embedded assets remain aligned with `BRAND.md` and any future UI edits must refresh the bundled assets via `./scripts/build_dashboard.sh`.
