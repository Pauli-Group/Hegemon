# Private multisig universal authorization circuit

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md`. It is self-contained for the current repository and describes the first implementation slice for replacing one global transaction spend secret with a fixed-shape private authorization relation in the transaction SmallWood frontend.

## Purpose / Big Picture

After this change, the active transaction proof frontend can carry one fixed private authorization block that selects exactly one authorization path without changing public transaction fields. A legacy spend still proves the existing single-key relation. The same private row budget can also describe an approval step that consumes an accumulator note plus a signer capability note and emits the next accumulator note, and a final spend that consumes a value note plus an accumulator note and checks the hidden approval threshold for the current canonical transaction statement. The observable result is focused SmallWood relation tests that accept valid legacy, approval, and final witnesses and reject duplicate signer, wrong intent, wrong policy, and below-threshold witnesses through proof constraints rather than host-only validation.

## Progress

- [x] (2026-06-26T03:21:18Z) Created branch `codex/private-multisig-universal-auth-circuit`, read `AGENTS.md`, `DESIGN.md`, `METHODS.md`, and `.agent/PLANS.md`, and mapped the existing global `sk_spend` authorization path.
- [x] (2026-06-26T03:21:18Z) Narrowed the first code slice to fixed hidden authorization rows and SmallWood frontend relation tests, preserving old single-key witnesses.
- [x] (2026-06-26T05:53:00Z) Implemented private authorization witness structs, default legacy mapping, and field-native accumulator helper functions.
- [x] (2026-06-26T05:53:00Z) Added hidden authorization rows to the SmallWood secret witness layout with private one-hot mode selectors and neutral inactive rows.
- [x] (2026-06-26T05:53:00Z) Changed SmallWood input authorization constraints from one global `sk_spend` hash to per-input private authorization rows.
- [x] (2026-06-26T05:53:00Z) Added focused relation tests for valid approval, duplicate signer rejection, wrong intent rejection, wrong policy rejection, exact-threshold final acceptance, below-threshold rejection, single-key preservation, and unchanged public statement length.
- [ ] Measure focused proof-byte and tx cap impact after integrating this relation with the main branch and wallet flow.

## Surprises & Discoveries

- Observation: The active SmallWood public statement is derived from the existing P3 public input vector plus version fields. Adding public policy or approval fields would directly violate the constant public-shape requirement.
  Evidence: `smallwood_public_statement_values_for_p3` chains `TransactionPublicInputsP3::to_vec()` with the circuit and crypto suite identifiers.
- Observation: The shipped SmallWood frontend has its own compact semantic rows and sparse constraints; it is not just proving the full P3 trace.
  Evidence: `semantic_secret_witness_rows_with_shape`, `build_packed_bridge_linear_constraints`, and `compute_constraints` define the active relation surface.
- Observation: The canonical authorization intent must project out public nullifiers and the Merkle root to avoid self-reference while still binding the stable spend statement, outputs, fee, balance, stablecoin fields, and version.
  Evidence: `smallwood_intent_public_value` is used by both the authorization intent trace and the matching linear constraints.
- Observation: Final mode needs an effective inactive next accumulator derived by the material path, not by callers.
  Evidence: `smallwood_effective_next_accumulator` derives the final-mode next hash preimage from the current hidden policy, intent, threshold, and neutral approval rows.

## Decision Log

- Decision: Implement the first verified subcomponent in the SmallWood frontend before changing P3 AIR.
  Rationale: The coordinator explicitly prioritized this slice, and the active backend is SmallWood. Legacy P3 witnesses remain unchanged while the new hidden relation is proven in SmallWood constraints.
  Date/Author: 2026-06-26 / Codex
- Decision: Keep authorization modes private and fixed-width: single-key, approval-step, and final-threshold all occupy the same row budget.
  Rationale: Public transaction and action surfaces must not reveal signer set, threshold, approval count, policy root, approval leaves, or approval-specific nullifier material.
  Date/Author: 2026-06-26 / Codex

## Outcomes & Retrospective

Focused relation validation passed:

    CARGO_INCREMENTAL=0 cargo test -p transaction-circuit universal_auth --lib -- --nocapture

Result: 12 passed, 0 failed, 116 filtered out. `git diff --check` also passed. The commit intentionally stops at the SmallWood relation slice: it proves the hidden fixed-shape authorization block and focused rejection cases, but it does not yet wire wallet transaction builders, P3 AIR production witnesses, live node validation, or proof-byte measurement.

## Context and Orientation

The legacy transaction witness is `circuits/transaction/src/witness.rs::TransactionWitness`. It has a global `sk_spend` field. The P3 prover in `circuits/transaction/src/p3_prover.rs` hashes that secret once and writes one PRF key plus one spend-auth key into trace columns for every active input. The SmallWood frontend in `circuits/transaction/src/smallwood_frontend.rs` mirrors that behavior by making one Poseidon hash of `sk_spend`, using the first output limb as the nullifier PRF key, and using the next four limbs as the expected hidden `pk_auth` limbs in every input note commitment.

The public transaction statement is represented by `TransactionPublicInputsP3` in `circuits/transaction-core/src/p3_air.rs`; the active SmallWood public statement copies those public values and appends version identifiers. This plan must not add public fields. A note commitment already includes hidden `pk_auth`, so private policy and accumulator state can be bound by changing the hidden relation that explains that slot.

An accumulator note is a normal shielded note whose hidden `pk_auth` slot commits to accumulator state. In this slice the state is a field-native digest of hidden policy root, hidden final transaction intent digest, hidden threshold, hidden approval count, and two hidden signer slots. A signer capability note is a normal shielded note authorized by the signer’s capability secret for the approval transaction. The final spend consumes a value note plus the accumulator note; it does not carry reusable signer secrets.

## Plan of Work

First add hidden authorization witness types beside `TransactionWitness`. The default must preserve existing callers: if no authorization object is supplied, the witness behaves as a single-key spend using `sk_spend`. New authorization fields must serialize as witness-only data and must not appear in public inputs or proof wrappers.

Next add a fixed private authorization row block to the SmallWood secret witness. The block will carry private mode selectors, per-input PRF/auth limbs, accumulator opening rows, next accumulator rows, signer identity rows, and inverse rows used to prove duplicate signer rejection. The row block exists for every mode. Legacy mode zeroes accumulator-only rows. Approval and final modes zero rows that are inactive for that mode.

Then update the SmallWood semantic constraints. The private mode selectors must be boolean and sum to one. Existing input note commitment auth checks must compare against per-input private auth rows instead of one global auth hash. Existing nullifier checks must use per-input private PRF rows. Single-key mode constrains per-input rows to the legacy hash of `sk_spend`. Approval mode constrains input 0 and output 0 to the accumulator state transition, input 1 to the signer capability key, and rejects duplicate signer rows. Final mode constrains input 1 to the accumulator state and checks that the hidden count reaches the hidden threshold for the canonical current statement digest.

Finally add focused relation tests that call the SmallWood frontend material builder and `test_candidate_witness` or `test_candidate_witness_with_auxiliary`. The tests must mutate private rows or witness openings and observe proof-constraint failure, not just `TransactionWitness::validate()` failure.

## Concrete Steps

Run commands from `/Users/pldd/.codex/worktrees/9398/Hegemon`.

Use focused tests while editing:

    cargo test -p transaction-circuit universal_auth -- --nocapture

After integration, run a focused proof-size projection:

    cargo test -p transaction-circuit smallwood_candidate_profile_surface -- --nocapture

If exact release-size commands are too slow, record the structural projection and the skipped exact command in this plan and the final response.

## Validation and Acceptance

Acceptance for this slice is concrete: the new tests named with `universal_auth` pass, old single-key SmallWood witness tests still pass, public statement length remains unchanged at 78 values, and the focused projection stays below the native `tx_leaf` cap or reports the exact over-cap blocker with row counts.

## Idempotence and Recovery

The changes are additive to witness data and SmallWood relation code. Re-running tests is safe. If a partial relation fails to compile, restore the last compiling patch by reverting only files changed in this branch, then reapply smaller changes from this plan. Do not reset unrelated user changes.

## Artifacts and Notes

Artifacts will be added here after tests and projection commands run.

## Interfaces and Dependencies

In `circuits/transaction/src/smallwood_frontend.rs`, define private authorization witness structs and helpers that return per-input PRF/auth field limbs for the requested SmallWood mode without widening `TransactionWitness` or public proof wrappers in this slice.

In `circuits/transaction/src/smallwood_frontend.rs`, add fixed row offsets for the private authorization block, extend `SmallwoodBridgeRowLayout::secret_witness_rows`, populate those rows in `semantic_secret_witness_rows_with_shape`, and update sparse constraints for input auth and nullifier binding.

In `circuits/transaction/src/smallwood_semantics.rs`, mirror the fixed row offsets and add nonlinear constraints for selector one-hot, threshold/count domain, duplicate signer rejection, and accumulator transition checks.

Revision note 2026-06-26: Initial plan created after coordinator narrowed the first slice to SmallWood hidden authorization rows and focused relation tests.
