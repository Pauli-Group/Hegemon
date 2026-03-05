# Aggregation Slot Stabilization for V4 Recursion

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` and must be maintained in accordance with that file.

## Purpose / Big Picture

After this change, aggregation proving no longer needs a unique recursion shape for every exact block tx count. Instead, proving can use a bounded padded slot count (`slot_tx_count`) to stabilize cache keys and reduce cold recursion rebuild storms that were jamming inclusion. You can see this working by running the consensus/aggregation tests and verifying V4 payload validation accepts bounded slot padding, derives statement commitment from the active tx prefix only, and rejects excessive padding.

## Progress

- [x] (2026-02-28 03:35Z) Implemented padded slot sizing in `circuits/aggregation/src/lib.rs` with bounded factor and optional `HEGEMON_AGG_FIXED_SLOT_COUNT`.
- [x] (2026-02-28 03:48Z) Updated V4 payload semantics and verifier/import logic in `consensus/src/aggregation.rs` to treat payload `tx_count` as `slot_tx_count`.
- [x] (2026-02-28 03:55Z) Added/updated consensus tests for padded-slot commitment semantics and excessive-padding rejection.
- [x] (2026-02-28 04:12Z) Updated `DESIGN.md` and `METHODS.md` to document slot semantics, bounds, and tuning controls.
- [x] (2026-02-28 04:20Z) Ran monorepo CI gate (`make check`) successfully.
- [ ] Run remote throughput ablation on `hegemon-prover` + `hegemon-ovh` with slot-stabilized payloads and report delta vs previous branch baseline.

## Surprises & Discoveries

- Observation: `TransactionProofP3` in the aggregation path could not be duplicated via simple clone in the new padding branch.
  Evidence: `cargo test -p aggregation-circuit --lib` failed with `expected Proof<...>, found &Proof<...>` at `inner_proofs.extend(...)`.
- Observation: Slot padding must be fail-closed bounded, otherwise payload amplification could become a resource abuse vector.
  Evidence: verifier-side header checks now reject `slot_tx_count > block_tx_count * 16`, covered by a dedicated consensus test.

## Decision Log

- Decision: Keep compatibility strict and interpret payload `tx_count` as recursion slot count for V4 only.
  Rationale: This preserves hard-cut V4 semantics while solving shape-entropy/cache-churn without re-enabling legacy ambiguity.
  Date/Author: 2026-02-28 / Codex

- Decision: Commit statement binding only over active tx prefix (`block_tx_count`) even when slot padded.
  Rationale: Preserves consensus semantics and prevents padded replicas from changing statement commitment.
  Date/Author: 2026-02-28 / Codex

- Decision: Bound padding factor to 16x at both prover and verifier.
  Rationale: Enables cache-shape stabilization while fail-closing unbounded payload inflation.
  Date/Author: 2026-02-28 / Codex

## Outcomes & Retrospective

Current outcome: the refactor is implemented, documented, and passes workspace CI, with consensus tests proving slot semantics and rejection behavior. Remaining gap: throughput impact still needs direct remote measurement; correctness and compatibility guarantees are complete, but performance claims are not accepted until remote ablation confirms reduced cold-shape churn and higher sustained inclusion rate.

## Context and Orientation

The relevant proving path starts in `circuits/aggregation/src/lib.rs`, where `prove_aggregation(...)` builds recursion inputs and outer proofs. Import verification lives in `consensus/src/aggregation.rs`, where V4 payload decoding and binding checks happen. Documentation of architecture and operations lives in `DESIGN.md` and `METHODS.md`.

Terms used in this plan:

- `slot_tx_count`: number of recursion slots proven in outer aggregation proof (can be greater than block tx count).
- `block tx count`: number of shielded transactions actually in the block.
- `shape_id`: deterministic digest binding recursion shape parameters for compatibility and cache selection.

## Plan of Work

The implementation sequence is:

1. Add slot-count computation in the aggregation prover, defaulting to the next power of two or operator-fixed value, with a hard cap of 16x the active count.
2. Pad recursion witness/proof inputs to `slot_tx_count` in prover path only, while preserving active transaction commitment semantics.
3. Switch verifier/import header validation to allow bounded padded slots and derive statement commitment from active-prefix public inputs.
4. Update and extend tests to cover malformed encoding, legacy rejections, padded commitment behavior, and bound enforcement.
5. Update architecture/method docs with exact payload semantics and tuning knobs.
6. Run full workspace check and tests.

## Concrete Steps

All commands run from repository root `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Implement/refine prover and verifier changes.

    cargo test -p aggregation-circuit --lib
    cargo test -p consensus --lib aggregation

2. Run full monorepo CI gate.

    make check

Expected outcome: format, clippy, and workspace tests complete without failure.

## Validation and Acceptance

Acceptance criteria for this milestone:

1. `make check` passes on the branch.
2. Consensus tests include and pass:
   - padded slot commitment uses active tx prefix only,
   - excessive slot padding is rejected fail-closed,
   - legacy payload version/format rejection still enforced.
3. Docs clearly state V4 slot semantics and `HEGEMON_AGG_FIXED_SLOT_COUNT` behavior.

## Idempotence and Recovery

These edits are idempotent at source level and safe to rerun. If an intermediate compile fails, rerun the targeted crate tests after fixing the compile issue. If performance testing fails in remote environments, keep the correctness changes and tune only runtime knobs (`HEGEMON_AGG_FIXED_SLOT_COUNT`, queue depth, parallelism) without reverting fail-closed checks.

## Artifacts and Notes

Key verification command outcomes from this milestone:

- `cargo test -p consensus --lib aggregation`: all 9 aggregation-related tests passed.
- `cargo test -p aggregation-circuit --lib`: passed.
- `make check`: passed across fmt, clippy, workspace tests, and doc tests.

## Interfaces and Dependencies

This milestone defines/changes these interfaces and controls:

- Prover-side slot selection in `circuits/aggregation/src/lib.rs`:
  - `aggregation_slot_count(actual_tx_count: usize) -> usize`
  - env control `HEGEMON_AGG_FIXED_SLOT_COUNT`
- Verifier-side payload semantics in `consensus/src/aggregation.rs`:
  - `validate_payload_header(...) -> Result<usize, ProofError>` now returns `slot_tx_count`
  - `derive_statement_commitment_from_packed_public_values(...)` now takes both `slot_tx_count` and `active_tx_count`
- Runtime/documentation controls:
  - bounded slot padding behavior (16x)
  - fixed slot override for shape stabilization

Change note (2026-02-28): Added this ExecPlan after implementing the slot-stabilization refactor so the applied architecture decisions, checks, and remaining performance validation are self-contained for any follow-on contributor.
