# Observability pallet for per-actor quotas and metrics events

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Introduce a FRAME pallet that records usage counters for on-chain actors, applies governance/identity-managed quota hints, and emits metrics-friendly events and optional off-chain exports. After completion, governance can set or clear quotas for accounts, other pallets can record usage, actors can trigger snapshot events for their own metrics, and an off-chain worker can periodically emit aggregate export events for monitoring systems. Benchmarks and `WeightInfo` will quantify dispatch costs.

## Progress

- [x] (2025-11-22 02:50Z) Captured initial plan with storage layout, extrinsics, events, OCW hooks, benchmarking, and validation approach.
- [x] (2025-11-22 02:56Z) Implemented the observability pallet with storage, events, extrinsics, hooks, and benchmarks plus mock runtime tests.
- [x] (2025-11-22 02:56Z) Validated with `cargo test -p pallet-observability`.

## Surprises & Discoveries

- Observation: System events remained empty in tests until the mock runtime advanced the block number.
  Evidence: Setting `frame_system::Pallet::<TestRuntime>::set_block_number(1)` during test setup allowed quota and usage events to appear.

## Decision Log

- Decision: Use both governance and identity origins for quota management rather than a single superuser origin.
  Rationale: Allows either governance motions or identity/operations desks to maintain quota hints without overloading one origin.
  Date/Author: 2025-11-22 / assistant

## Outcomes & Retrospective

The observability pallet now records per-actor quotas and usage counters, emits metrics-friendly events (including off-chain worker exports), and includes benchmarking hooks. Targeted tests exercise governance and identity quota updates, usage tracking, snapshots, and off-chain metrics emission.

## Context and Orientation

The repository hosts FRAME pallets under `pallets/`. Each pallet defines storage, events, extrinsics, helpers, weight traits, and tests inside `src/lib.rs`, with optional `benchmarking.rs` gated by `runtime-benchmarks`. The workspace members live in `Cargo.toml` at the repository root. Existing pallets (e.g., `pallets/feature-flags`) provide examples for storage versioning, weight traits, and mocked runtimes for tests. Off-chain workers implement `Hooks::offchain_worker` and may use bounded actor lists to keep workloads predictable.

## Plan of Work

1. Create a new crate at `pallets/observability` with a `Cargo.toml` mirroring other pallets (frame-support/system, parity-scale-codec, scale-info) and a default `WeightInfo` trait returning zero weights. Register the crate in the workspace `Cargo.toml`.
2. In `src/lib.rs`, define types for `Quota` (max usage and per-block rate hint) and `UsageCounter` (totals plus last block). Provide helper type aliases for bounded actor identifiers and tracked lists.
3. Storage: `Quotas` map actors to `Quota`, `UsageCounters` map actors to `UsageCounter`, and `TrackedActors` bounded list/map to feed off-chain export. Apply `StorageVersion` for migrations.
4. Events: quota set/cleared, usage recorded, usage snapshot requested, and metrics export summaries (for OCW). Errors cover missing quota, quota overflow, not tracked, and bad origins.
5. Extrinsics:
   - `set_quota(origin, actor, quota)`: allowed for governance or identity origins, updates storage and tracked actors.
   - `clear_quota(origin, actor)`: same gating, removes quota entry.
   - `record_self_usage(origin, amount)`: signed origin increments own usage counter and emits an event for metrics.
   - `emit_snapshot(origin)`: signed origin emits an event containing current usage and optional quota for that actor.
6. Expose helper functions `note_usage(actor, amount)` for other pallets to record usage and `quota_for`/`usage_of` getters. Ensure counters saturate on overflow rather than panic.
7. Hooks: implement `offchain_worker` to emit a `MetricsExported` event summarizing tracked actor count for visibility without external networking. Implement `on_runtime_upgrade` to set storage version and return weight from `WeightInfo`.
8. Add benchmarking module under `src/benchmarking.rs` covering quota set, self usage, and snapshot emission. Wire it under `cfg(feature = "runtime-benchmarks")` and expose `impl_benchmark_test_suite!`.
9. Add tests in `lib.rs` using a mocked runtime to cover quota updates with dual origins, usage recording, snapshots, and off-chain worker event emission. Use `note_usage` helper in tests to simulate other pallets.
10. Run `cargo test -p pallet-observability` from the repository root to validate compilation and behavior.

## Concrete Steps

- Scaffold `pallets/observability/Cargo.toml` and `src/lib.rs`, plus `src/benchmarking.rs` behind feature flag.
- Update root `Cargo.toml` workspace members.
- Implement storage, events, extrinsics, helpers, hooks, default weights, and benchmarking wiring.
- Write unit tests for quota management, usage tracking, snapshots, and off-chain exports.
- Execute the targeted cargo test command to confirm success.

## Validation and Acceptance

- `cargo test -p pallet-observability` succeeds.
- Tests demonstrate governance/identity quota updates, usage accumulation, snapshot events reflecting current counters and quotas, and off-chain worker emitting metrics export events using tracked actors.

## Idempotence and Recovery

Storage version migration writes only when outdated, making runtime upgrades repeatable. Quota and usage updates use checked arithmetic with saturation to avoid panics. Tests and benchmark scaffolding are repeatable.

## Artifacts and Notes

None yet.

## Interfaces and Dependencies

- Config associated types: `RuntimeEvent`, `GovernanceOrigin`, `IdentityOrigin`, `MaxTrackedActors`, `WeightInfo`.
- Core helpers:
    - `pub fn note_usage(actor: &T::AccountId, amount: u64)`
    - `pub fn quota_for(actor: &T::AccountId) -> Option<Quota>`
    - `pub fn usage_of(actor: &T::AccountId) -> UsageCounter`
- Events to emit snapshots and metrics exports usable by telemetry collectors.
