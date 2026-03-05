# Adaptive Cold-Path Recovery For Aggregation Throughput

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root and must be maintained in accordance with its requirements.

## Purpose / Big Picture

Users should not see shielded transactions jam for minutes when the target aggregation batch shape is cold on a fresh node. After this change, throughput-first mode (`HEGEMON_PROVER_LIVENESS_LANE=0`) keeps trying the large target batch, but if that cold path exceeds a configured wait budget, the coordinator injects one singleton liveness candidate so inclusion can continue while the large batch is still proving.

The observable result is that a cold target-batch prover no longer hard-stalls transaction inclusion indefinitely.

## Progress

- [x] (2026-02-27 07:40Z) Measured and confirmed cold aggregation target path bottleneck on `hegemon-prover` (`cache_circuit_build` + `cache_airs_setup` + stalled `common_commit_preprocessed`) with strict target-batch readiness timeout.
- [x] (2026-02-27 07:58Z) Implemented coordinator configuration and state plumbing for adaptive liveness timeout in `node/src/substrate/prover_coordinator.rs`.
- [x] (2026-02-27 08:05Z) Implemented scheduling logic that injects one singleton candidate after timeout in throughput-first mode.
- [x] (2026-02-27 08:12Z) Added regression test `throughput_mode_adaptive_liveness_unjams_cold_target_batches`.
- [x] (2026-02-27 08:16Z) Updated runtime startup logs and architecture/method docs with new operator control (`HEGEMON_PROVER_ADAPTIVE_LIVENESS_MS`).
- [ ] Run focused coordinator tests and then benchmark behavior on `hegemon-prover` with adaptive mode enabled.
- [ ] Update report with validated before/after timing deltas for cold-path unjam behavior.

## Surprises & Discoveries

- Observation: Strict target-batch readiness (`tx_count=4`) can time out before any prepared bundle appears even on 32-core / 256 GiB prover hosts.
  Evidence: `Strict aggregation mode: timed out waiting for local proven batch candidate.` with profile showing long pre-cache stages.
- Observation: Existing benchmark strict mode can hide liveness behavior by forcing full-batch readiness and disabling proofless hydration.
  Evidence: script settings set `HEGEMON_DISABLE_PROOFLESS_HYDRATION=1` and `HEGEMON_MIN_READY_PROVEN_BATCH_TXS=TX_COUNT`.

## Decision Log

- Decision: Add adaptive singleton fallback in coordinator rather than changing proof-system parameters first.
  Rationale: It removes user-visible jams immediately without weakening proof correctness or changing circuit security assumptions.
  Date/Author: 2026-02-27 / Codex.
- Decision: Keep fallback scoped to throughput-first mode (`liveness_lane=false`) and gated by timeout.
  Rationale: Preserve existing deterministic target-batch behavior while adding an explicit liveness escape hatch.
  Date/Author: 2026-02-27 / Codex.
- Decision: Default timeout to 30s only when liveness is disabled.
  Rationale: Liveness-enabled mode already has singleton lane; timeout mechanism is only needed where operators intentionally disabled it.
  Date/Author: 2026-02-27 / Codex.

## Outcomes & Retrospective

Implementation is complete for coordinator-level adaptive fallback and tests/docs wiring. Final outcome validation is pending focused test execution and remote throughput verification to confirm unjam behavior under cold target-batch conditions.

## Context and Orientation

`node/src/substrate/prover_coordinator.rs` owns candidate selection and async proving job scheduling. In throughput-first mode (`HEGEMON_PROVER_LIVENESS_LANE=0`), it historically scheduled only full target batches, which can wedge inclusion when the first target recursion shape is cold.

`node/src/substrate/service.rs` instantiates this coordinator and logs effective runtime configuration.

`METHODS.md` and `DESIGN.md` document operator-facing behavior and controls for proving and scheduling.

## Plan of Work

Add one new coordinator config field (`adaptive_liveness_timeout`) sourced from `HEGEMON_PROVER_ADAPTIVE_LIVENESS_MS`. Add coordinator state fields to track when target-batch proving was scheduled and whether adaptive fallback already fired for the current generation.

When throughput-first mode sees no upsizing opportunity (`candidate.len() <= existing_best`) and no prepared bundle is available past timeout, enqueue a singleton candidate at queue front once per generation.

Keep this bounded and explicit:

- no effect in liveness-enabled mode,
- no effect when timeout is zero,
- no repeated singleton spam once fired.

Add an async test that reproduces cold target proving and verifies singleton lane becomes available before target completion.

Update startup logs and docs to expose the new operator knob.

## Concrete Steps

From repository root (`/Users/pldd/Projects/Reflexivity/Hegemon`):

1. Edit `node/src/substrate/prover_coordinator.rs`:
   - Extend `ProverCoordinatorConfig` with `adaptive_liveness_timeout`.
   - Parse `HEGEMON_PROVER_ADAPTIVE_LIVENESS_MS` in `from_env`.
   - Track target schedule/fallback state in `CoordinatorState`.
   - Add `maybe_schedule_adaptive_liveness_lane` and invoke it when candidate upsizing is otherwise blocked.
   - Add test `throughput_mode_adaptive_liveness_unjams_cold_target_batches`.
2. Edit `node/src/substrate/service.rs` startup tracing to include `prover_adaptive_liveness_timeout_ms`.
3. Edit `METHODS.md` and `DESIGN.md` to describe adaptive timeout behavior and operator intent.
4. Run focused tests and benchmarks.

Expected focused test command:

    cargo test -p hegemon-node prover_coordinator::tests:: -- --nocapture

Expected benchmark command (remote `hegemon-prover`, from `~/Hegemon-bench`):

    HEGEMON_TP_FORCE=1 HEGEMON_TP_FAST=1 HEGEMON_TP_PROFILE=max HEGEMON_TP_TX_COUNT=4 HEGEMON_TP_WORKERS=1 HEGEMON_TP_COINBASE_BLOCKS=6 HEGEMON_TP_PROVER_WORKERS=4 HEGEMON_TP_STRICT_AGGREGATION=1 HEGEMON_TP_PROOF_MODE=aggregation HEGEMON_PROVER_ADAPTIVE_LIVENESS_MS=30000 scripts/throughput_sidecar_aggregation_tmux.sh

## Validation and Acceptance

Acceptance criteria:

1. Unit/integration: coordinator test suite passes with the new adaptive test.
2. Behavior: in throughput-first cold-target conditions, a singleton candidate is scheduled after timeout and becomes visible through `pending_transactions` before the long target job completes.
3. Observability: startup logs include `prover_adaptive_liveness_timeout_ms`.
4. Documentation: METHODS and DESIGN explicitly define the new timeout knob and expected effect.

## Idempotence and Recovery

All edits are additive and can be re-applied safely. If adaptive behavior is not desired, set `HEGEMON_PROVER_ADAPTIVE_LIVENESS_MS=0` to disable and restore old throughput-first semantics.

## Artifacts and Notes

Key log evidence for the cold bottleneck before this fix includes:

    aggregation_profile stage=cache_circuit_build tx_count=4 build_ms=226222 total_ms=235086
    aggregation_profile stage=cache_airs_setup tx_count=4 setup_ms=25422 total_ms=260509
    aggregation_profile stage=common_prepare_metadata air_count=5 prep_matrices=5 total_ms=26300
    Strict aggregation mode: timed out waiting for local proven batch candidate.

## Interfaces and Dependencies

New/updated interfaces:

- `node::substrate::prover_coordinator::ProverCoordinatorConfig` gains:

    pub adaptive_liveness_timeout: Duration

- Environment variable:

    HEGEMON_PROVER_ADAPTIVE_LIVENESS_MS

Behavioral contract:

- In `liveness_lane=false` mode, when no prepared bundle exists and target proving stays cold past timeout, schedule one singleton lane candidate for inclusion continuity.

---

Revision note (2026-02-27): Initial plan created during implementation to satisfy PLANS.md requirements and capture design rationale, validation steps, and acceptance criteria for adaptive cold-path recovery.
