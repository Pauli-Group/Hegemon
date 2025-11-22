# Runtime upgrade runbook

This runbook covers how to stage, execute, and verify runtime upgrades across Testnet0/1/2 and pre-mainnet. Pair this with the chain specs in `docs/CHAIN_SPECS.md` and the migration tests captured in CI.

## Preconditions
- Runtime code reviewed and merged with a bumped `spec_version` and relevant pallet storage versions.
- Migration tests passing in CI (pallet `on_runtime_upgrade` hooks, weight regression tests, wasm build smoke tests).
- Full nodes synced and telemetry dashboards green for the target network.
- Release artifacts published (native binary + wasm blob) with signed checksums.

## Staging checklist
1. Run `cargo test -p runtime migration` locally to validate migrations before proposing.
2. Generate the wasm blob: `cargo build -p runtime --release --target wasm32-unknown-unknown`.
3. Post the proposal hash and checksum in the ops channel; attach the feature flags to toggle during rollout.
4. Dry-run the upgrade on the next-lower testnet (e.g., Testnet1 before Testnet2) and confirm block production plus event stream health.

## Execution
1. Submit the upgrade extrinsic (council/technical origin) with the new wasm blob.
2. Monitor block authorship and inclusion latency for 3 epochs; ensure validators rotate without stalls.
3. Observe `System::events` for pallet migration logs and verify storage versions advanced to their targets.
4. If the upgrade includes feature flag cohorting, activate the cohort in stages: validators → council → public users.

## Verification and rollback
- Verification: confirm pallet storage versions via RPC state queries and check that `pallet-observability` emits the new metrics.
- Rollback: if a migration panics or a pallet fails invariants, schedule an emergency downgrade using the last known-good wasm and disable the failed feature flag cohort. Coordinate with validators via the incident bridge.
- Post-incident: file a retro doc and extend migration tests to cover the regression path.
