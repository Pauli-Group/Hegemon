# SDK developer guide

This guide explains how to build against the Rust SDK crates in this monorepo and how to use `pallet-feature-flags` for staged rollouts.

## SDK layout
- **`wallet/`** – client primitives for crafting and signing transactions; includes benchmarking helpers under `wallet-bench`.
- **`network/`** – libp2p-based networking layer and RPC helpers for node integrations.
- **`protocol/`** – protocol constants, versioning, and cross-component types.
- **`pallets/`** – FRAME pallets consumed by the runtime; feature-flag hooks live here.

When adding a new SDK surface:
1. Expose the API from the crate root and re-export stable types under a `prelude` module.
2. Include an example under `examples/` that demonstrates end-to-end usage (construct call, sign, submit, and parse events).
3. Update `DESIGN.md`/`METHODS.md` with any new invariants and link back to this guide.

## Feature flags
`pallet-feature-flags` gates runtime functionality behind named cohorts.

- Use bounded feature names (`MaxNameLength` in the runtime) and register a cohort of accounts allowed to use the feature during rollout.
- Guard runtime upgrades or migrations with `FeatureFlags::guard_on_runtime_upgrade` so only active cohorts execute new logic.
- Expose SDK toggles: surface a `FeatureToggle` struct in SDK clients that maps feature names to activation status pulled from on-chain storage.
- Testing: add `cargo test -p runtime migration` to confirm `on_runtime_upgrade` honors feature flags when migrating storage.

## Feature flag workflow for SDKs
1. Query `FeatureFlags::features` via RPC to fetch active/inactive sets.
2. Enable the corresponding code path in the SDK only when the feature is active for the caller’s account.
3. During staged rollouts, ship SDK builds that default to the old behavior and require an explicit `--enable-feature <name>` flag to opt in.
4. After the feature is fully active, remove the guard and mark the flag as immutable in the SDK changelog.

## Developer checklist
- Run `cargo fmt` and `cargo clippy --workspace --all-targets --all-features` before pushing.
- Add integration tests that cover event decoding for any new RPC/client surfaces.
- Document required feature flags and their cohorts in PRs so ops can align runtime upgrades with SDK releases.
