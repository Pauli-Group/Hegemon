# Feature flags pallet and runtime gating

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

We need a runtime feature-flag pallet that governance can use to stage rollouts and guard upgrades. After this change, governance can propose a feature with a targeted cohort, activate or deactivate it, and other pallets can call helper functions to allow or skip runtime upgrades and entrypoints based on flag status. Validation will come from new unit tests that show feature lifecycle transitions and gating helpers.

## Progress

- [x] (2025-11-22 02:26Z) Captured initial plan covering scope, storage, extrinsics, and guards.
- [x] (2025-11-22 02:34Z) Implemented the feature-flags pallet with storage, extrinsics, helpers, and migration baseline.
- [x] (2025-11-22 02:34Z) Added unit tests covering lifecycle transitions, cohort targeting, and guard helpers.
- [x] (2025-11-22 02:35Z) Registered the new pallet crate in the workspace with default zero weights.
- [x] (2025-11-22 03:02Z) Validate with `cargo test -p pallet-feature-flags`.

## Surprises & Discoveries

- None yet.

## Decision Log

- Decision: Model cohorts as bounded vectors of account IDs to keep targeting simple and compatible with gating helpers.
  Rationale: Direct account lists avoid adding new identity abstractions and allow cheap membership checks needed for staged rollouts.
  Date/Author: 2025-11-22 / assistant

## Outcomes & Retrospective

Pending implementation and testing.

## Context and Orientation

The repository hosts several FRAME pallets under `pallets/`. Each pallet defines storage, extrinsics, weight traits, migrations, and unit tests in `src/lib.rs`. Workspace membership is declared in the root `Cargo.toml`. No existing feature-flag pallet exists. Governance origins are generally provided via an associated `EnsureOrigin` type. Follow the patterns in `pallets/asset-registry/src/lib.rs` for storage versioning, migrations, and `WeightInfo` defaults.

## Plan of Work

1. Create a new pallet crate at `pallets/feature-flags` with a `Cargo.toml` mirroring dependencies used by other pallets (frame-support/system, parity-scale-codec, scale-info) and a default `WeightInfo` trait returning zero weights. Add the crate to the workspace members in the root `Cargo.toml`.
2. Define types: `FeatureStatus` enum (`Proposed`, `Active`, `Inactive`), `FeatureDetails` struct storing status, cohort members (`BoundedVec<AccountId, MaxCohortSize>`), and activation metadata (`BlockNumberFor<T>`). Introduce `FeatureId` as a configurable key type (bounded bytes) to allow human-readable identifiers.
3. Storage: `Features` map from `FeatureId` to `FeatureDetails` with `StorageVersion` set to 1. Provide getters for status and cohort. Add migration helper that sets the storage version to 1 on first run and returns zero weight otherwise.
4. Extrinsics (all gated by `GovernanceOrigin`):
   - `propose_feature(feature_id, cohort)`: insert a new entry in `Proposed` status with provided cohort, rejecting duplicates.
   - `activate_feature(feature_id)`: switch an existing feature to `Active` and record activation block.
   - `deactivate_feature(feature_id)`: mark feature `Inactive` while preserving cohort targeting.
   Emit events for each lifecycle change and expose errors for missing features, duplicates, or invalid transitions.
5. Helpers for guarding other pallets:
   - `is_active(feature_id)` boolean.
   - `is_enabled_for(feature_id, &AccountId)` that respects cohort targeting when active.
   - `ensure_feature_active`/`ensure_enabled_for` returning `DispatchResult` for easy use inside dispatchables.
   - `guard_on_runtime_upgrade(feature_id, upgrade: impl FnOnce() -> Weight) -> Weight` that executes an upgrade hook only when the flag is active.
6. Implement `Hooks` with `on_runtime_upgrade` calling migration helper to write the initial storage version.
7. Add unit tests in `src/lib.rs` mocking a runtime to validate proposing, activating, deactivating, cohort targeting, and runtime-upgrade guard behavior.
8. Run `cargo test -p pallet-feature-flags` to ensure the pallet builds and tests pass.

## Concrete Steps

- Add the new pallet crate files under `pallets/feature-flags/`.
- Update root `Cargo.toml` workspace members to include the crate.
- Implement pallet logic, events, errors, storage, extrinsics, helpers, and migration.
- Write unit tests demonstrating lifecycle transitions and gating helpers.
- Run the targeted cargo test command from the repository root.

## Validation and Acceptance

- `cargo test -p pallet-feature-flags` succeeds.
- Tests confirm that governance can propose, activate, and deactivate features, cohort checks gate access, and `guard_on_runtime_upgrade` runs inner logic only when the feature is active.

## Idempotence and Recovery

The migration helper sets storage version only when below 1, making repeated runtime upgrades safe. Extrinsics guard against duplicate proposals and invalid transitions to keep state consistent. Running the test command is repeatable.

## Artifacts and Notes

None yet.

## Interfaces and Dependencies

- Config associates: `FeatureId` (bounded bytes), `MaxFeatureNameLength` (u32), `MaxCohortSize` (u32), `GovernanceOrigin: EnsureOrigin<RuntimeOrigin>`, `WeightInfo`.
- Helper signatures:
    - `pub fn is_active(feature: &T::FeatureId) -> bool`
    - `pub fn is_enabled_for(feature: &T::FeatureId, who: &T::AccountId) -> bool`
    - `pub fn ensure_feature_active(feature: &T::FeatureId) -> DispatchResult`
    - `pub fn ensure_enabled_for(feature: &T::FeatureId, who: &T::AccountId) -> DispatchResult`
    - `pub fn guard_on_runtime_upgrade(feature: &T::FeatureId, upgrade: impl FnOnce() -> Weight) -> Weight`
