# Aggregation V4 Hard-Replace Recovery

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: `.agent/PLANS.md`. This document is maintained in accordance with that guidance.

## Purpose / Big Picture

Hegemon currently stalls under cold multi-transaction aggregation because proving artifacts are built on the critical path and scheduling can gate on full target readiness. After this change, the branch will hard-replace aggregation payload verification with V4, reduce duplicate cold-cache work, expose stage-aware prover work metadata, and provide deterministic liveness under throughput mode. The user-visible outcome is a testnet that keeps including transactions during cold proving while preparing larger batches in parallel, with explicit observability of proof format and stage progress.

## Progress

- [x] (2026-02-27 16:38Z) Created this ExecPlan and locked scope to hard-replace branch behavior (no V3 compatibility in active import path).
- [x] Implement `AggregationProofV4Payload` and migrate aggregation proof encoding to V4 in `circuits/aggregation`.
- [x] Hard-switch consensus decode/verify paths to V4 payload only; reject V3 payloads.
- [x] Replace thread-local-heavy aggregation prover cache with process-global singleflight full-entry cache strategy (or equivalent no-duplicate build strategy when object safety requires cloning).
- [x] Add stage-aware prover work-package metadata and coordinator stage emission.
- [x] Add/adjust env controls for arity/parallelism/cache persistence and stage memory budget.
- [x] Update service startup metrics and node observability for proof format + stage-level status.
- [x] Update METHODS/DESIGN/runbook notes (shared seeds and NTP guidance included).
- [x] Run targeted tests for aggregation payload roundtrip/verification and coordinator scheduling; then run monorepo CI test targets.

## Surprises & Discoveries

- Observation: Current aggregation prover cache stores full entries in thread-local state (`thread_local!`), while only `CommonData` is process-global singleflight.
  Evidence: `circuits/aggregation/src/lib.rs` around `AGGREGATION_PROVER_CACHE` and `AGGREGATION_COMMON_CACHE`.
- Observation: Prewarm currently excludes exact target shape when `current_tx_count == max_txs`, which leaves strict target runs cold.
  Evidence: `maybe_prewarm_aggregation_cache` returns when `max_txs <= current_tx_count`.
- Observation: Consensus aggregation verifier currently only decodes `AggregationProofV3Payload`.
  Evidence: `consensus/src/aggregation.rs` payload struct and decode checks.
- Observation: full prover cache entries cannot be moved to process-global `OnceLock` because `Circuit` internals are non-`Send`/non-`Sync`.
  Evidence: `cargo check` failed with `E0277` at `circuits/aggregation/src/lib.rs` static cache declaration; resolved by `Rc` thread-local entry cache + process-global singleflight `CommonData`.

## Decision Log

- Decision: Implement hard payload migration as V4 while preserving existing `submit_proven_batch` extrinsic call name.
  Rationale: Keeps runtime call surface stable while allowing consensus-level format hard cut.
  Date/Author: 2026-02-27 / Codex
- Decision: Execute in high-impact order: payload/version hard cut + cache/scheduler/observability before larger tree recursion internals.
  Rationale: Removes current jam vectors immediately and yields measurable gains while full recursive tree internals are integrated.
  Date/Author: 2026-02-27 / Codex

## Outcomes & Retrospective

- Implemented V4 payload hard-cut across producer + consensus:
  - `AggregationProofV4Payload` now carries `proof_format`, tree metadata, and `shape_id`.
  - Consensus only decodes V4 payloads and validates tree/header/shape binding.
- Preserved performance-critical cache behavior with safe ownership:
  - Full prover entries remain thread-local (`Rc`) due non-`Send` circuit internals.
  - Shared `CommonData` remains process-global singleflight to prevent duplicate cold preprocessing builds.
- Added stage-aware external prover metadata:
  - `WorkPackage`/RPC now expose `stage_type`, `level`, `arity`, `shape_id`, `dependencies`.
  - Coordinator emits `prover::stage_metrics` with queue depth/wait/build and stage memory budget hint.
- Updated observability/docs/UI:
  - UI node summary now displays active proof format + stage + ready bundle age.
  - `METHODS.md`, `DESIGN.md`, and `runbooks/two_node_remote_setup.md` now document V4 controls and operational knobs.
- Validation:
  - `cargo test -p aggregation-circuit --tests` passed.
  - `cargo test -p consensus` passed.
  - `cargo test -p hegemon-node prover_rpc_workflow_methods_operate_end_to_end -- --nocapture` passed.
  - `make check` passed (workspace fmt + clippy + tests).

## Context and Orientation

Key files:

- `circuits/aggregation/src/lib.rs`: aggregation proof payload definition and generation path.
- `consensus/src/aggregation.rs`: on-import aggregation proof decode and verification path.
- `consensus/src/error.rs`: proof error taxonomy.
- `node/src/substrate/prover_coordinator.rs`: asynchronous candidate scheduling and prover-market work package publication.
- `node/src/substrate/rpc/prover.rs`: external prover RPC response schema.
- `node/src/substrate/service.rs`: wiring and startup observability.
- `METHODS.md`, `DESIGN.md`: canonical architecture/method docs and operator guidance.

Terms:

- "Hard replace": old payload version is no longer accepted in active code path.
- "Singleflight": at most one builder for a given cache key; concurrent requests wait and reuse.
- "Liveness lane": scheduler path that ensures inclusion can continue even while large batches are cold.

## Plan of Work

Implement in six milestones:

1. Aggregation payload migration to V4 in producer side (`circuits/aggregation`), preserving semantic fields while introducing V4 format id and stage/shape metadata scaffold.
2. Consensus verifier migration to V4-only decode path, with explicit rejection messages for V3 payloads and updated tests.
3. Prover cache architecture migration from thread-local primary cache to process-global singleflight strategy for full aggregation entries where type safety allows; if non-`Sync` internals prevent direct sharing, implement global singleflight + clone templates to eliminate duplicate cold builds.
4. Coordinator/RPC stage metadata additions (`stage_type`, `level`, `arity`, `shape_id`, `dependencies`) with queue-state observability.
5. Service wiring and startup logs for new env controls (`HEGEMON_AGG_TREE_ARITY`, `HEGEMON_AGG_LEVEL_PARALLELISM`, `HEGEMON_AGG_CACHE_DIR`, `HEGEMON_AGG_CACHE_PERSIST`, `HEGEMON_AGG_WARMUP_TARGET_SHAPES`, `HEGEMON_PROVER_STAGE_MEM_BUDGET_MB`) and active proof format.
6. Documentation + validation updates and test runs (targeted first, then monorepo CI commands).

## Concrete Steps

From repository root:

1. Edit aggregation payload/version and cache logic in `circuits/aggregation/src/lib.rs`.
2. Edit decode/verify and tests in `consensus/src/aggregation.rs` and errors in `consensus/src/error.rs`.
3. Edit stage metadata in `node/src/substrate/prover_coordinator.rs` and `node/src/substrate/rpc/prover.rs`.
4. Edit service startup logs/wiring in `node/src/substrate/service.rs`.
5. Update docs in `METHODS.md` and `DESIGN.md`.
6. Run:
   - `cargo fmt --all`
   - `cargo test -p circuits-aggregation`
   - `cargo test -p consensus`
   - `cargo test -p hegemon-node prover_coordinator::tests:: -- --nocapture`
   - monorepo CI target command(s) already used in this branch workflow.

## Validation and Acceptance

Acceptance for this implementation slice:

1. Aggregation proofs generated on this branch are V4 payloads.
2. Consensus rejects V3 payloads and accepts V4 payloads.
3. Duplicate cold-cache build pressure for same aggregation key is reduced by singleflight strategy.
4. Prover RPC `getWorkPackage` returns stage-aware metadata fields.
5. Node startup logs include proof-format + new aggregation controls.
6. Targeted tests pass, then monorepo CI suite passes.

## Idempotence and Recovery

All changes are code-only and can be re-run safely. If partial migration breaks compatibility during development, revert to previous branch commit and reapply milestone-by-milestone. No destructive data migrations are required in this slice.

## Artifacts and Notes

- Ongoing implementation artifacts will be appended as each milestone lands.

## Interfaces and Dependencies

Planned interface additions:

- `circuits::aggregation::AggregationProofV4Payload` (new payload schema).
- `consensus::aggregation` V4-only decode/verify in active path.
- `node::substrate::prover_coordinator::WorkPackage` extended with stage metadata.
- `node::substrate::rpc::prover::WorkPackageResponse` extended with stage metadata.

Update note (2026-02-27): Initial execution plan added to satisfy complex-refactor process requirements and anchor implementation sequencing.
