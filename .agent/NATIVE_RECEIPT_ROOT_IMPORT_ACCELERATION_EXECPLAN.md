# Accelerate Native Receipt-Root Import With Verified Records and Prototype Compact Block Proofs

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

## Purpose / Big Picture

After this change, Hegemon’s block importer will stop paying the worst part of the receipt-root verification cost twice. The importer already verifies native `tx_leaf` artifacts while deriving transaction statement bindings; this plan makes the native receipt-root verifier consume those already-verified leaf records directly instead of replaying each leaf check again. The visible proof is quantitative: the product import path should use the verified-record root verifier by default, and the benchmark delta between replay-heavy root verification and record-based root verification should move toward the currently measured `26x` gap on the `8`-leaf sample. This plan also contains a separate prototyping milestone for a future compact block proof, because replacing replay with one compact proof is new cryptographic work and must not be smuggled in as an “engineering cleanup.”

## Progress

- [x] (2026-04-05 18:45Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, `consensus/src/proof.rs`, `circuits/superneo-hegemon/src/lib.rs`, `circuits/superneo-bench/src/main.rs`, and `docs/crypto/native_backend_verified_aggregation.md`.
- [x] (2026-04-05 19:00Z) Confirmed the repo already has the key ingredients for the import fast path: a verified native leaf store in `consensus/src/proof.rs` and a records-only receipt-root verifier in `circuits/superneo-hegemon/src/lib.rs`.
- [x] (2026-04-05 19:11Z) Recorded the current local benchmark baseline: on `8` leaves, root replay verification took `0.695s` while records-only root verification took `0.027s`, which is about `25.7x` faster.
- [ ] Thread verified native leaf records through the product block-verification path so import uses the records-only receipt-root verifier by default.
- [ ] Extend the benchmark and proof reports so they show when import uses replay versus verified-record fast path.
- [ ] Add cache-prewarm and failure-mode tests for the record fast path.
- [ ] Prototype, but do not yet ship, a compact block proof that proves leaf checks and fold checks were done correctly once.
- [ ] Decide from measurements whether the compact-proof prototype is worth promoting beyond the research lane.

## Surprises & Discoveries

- Observation: the repo already exposes `verify_native_tx_leaf_receipt_root_artifact_from_records_with_params`, but the main product-path verifier still routes through the artifact-based replay-heavy path.
  Evidence: `circuits/superneo-hegemon/src/lib.rs` defines the records-only verifier, while `consensus/src/proof.rs` currently calls `verify_experimental_native_receipt_root_artifact(...)`, which decodes native artifacts and verifies the root from those artifacts.

- Observation: verified native leaf records are already cached by artifact hash during tx-artifact verification.
  Evidence: `consensus/src/proof.rs` computes `native_tx_leaf_artifact_hash(...)`, stores `VerifiedNativeTxLeaf`, and exposes `prewarm_verified_native_tx_leaf_store(...)`.

- Observation: compact block proof work is not the same problem as the record fast path. The fast path is engineering because the repo already has the data and verifier. A compact proof is new cryptography because it would replace replay with a new proof object.
  Evidence: `docs/crypto/native_backend_verified_aggregation.md` explicitly defines the current security object as verified-leaf aggregation and explicitly says the fold layer alone is not CCS soundness.

## Decision Log

- Decision: Treat the verified-record import path as the immediate deliverable and the compact proof as a separate prototype milestone.
  Rationale: The record fast path uses code that already exists and directly targets the measured `26x` root-step gap. The compact proof needs new theorem and review work, so it must remain an explicit research track until it proves its value.
  Date/Author: 2026-04-05 / Codex

- Decision: Preserve the replay-heavy verifier as a debug and cross-check path even after the records fast path becomes the default.
  Rationale: The replay-heavy path is the simpler ground truth today. It remains valuable for diagnostics, fuzzing, and regression checks even after the faster records path ships.
  Date/Author: 2026-04-05 / Codex

- Decision: Do not advertise a consensus or product win from the compact proof until the prototype beats the records fast path on at least one meaningful axis.
  Rationale: The records fast path is already cheap relative to the replay-heavy root step. A compact proof that is larger, slower, or weaker would be churn, not progress.
  Date/Author: 2026-04-05 / Codex

## Outcomes & Retrospective

This plan is not implemented yet. Its intended near-term outcome is simple and measurable: block import should use verified records instead of replaying leaf checks a second time, and the native receipt-root report should make that visible. Its intended longer-term outcome is a truthful go/no-go answer on a compact block-proof design. Success for the first part is a product win; success for the second part may be either a working prototype or a documented rejection if the prototype cannot beat the simpler fast path.

## Context and Orientation

`consensus/src/proof.rs` is the bridge between transaction-artifact verification and block-artifact verification. During transaction-artifact verification, Hegemon already validates native `tx_leaf` artifacts and caches a `VerifiedNativeTxLeaf` record keyed by the artifact hash. That record contains the canonical receipt, the derived statement binding, and the leaf summary needed for aggregation checks.

`circuits/superneo-hegemon/src/lib.rs` owns the native receipt-root verifier. It has two relevant entry points:

- `verify_native_tx_leaf_receipt_root_artifact_bytes_with_params(...)`, which takes full native artifacts and replays leaf verification;
- `verify_native_tx_leaf_receipt_root_artifact_from_records_with_params(...)`, which takes leaf records that are already trusted and skips replaying the leaf verifier.

`circuits/superneo-bench/src/main.rs` already measures both paths. The current local measured baseline for `8` leaves is:

- `receipt_root_replay_verify = 0.695s`
- `receipt_root_records_verify = 0.027s`

That is the quantitative motivation for the first half of this plan.

For this plan, the following plain-language terms matter:

- A `verified record` is the cached summary of one already-verified native `tx_leaf`.
- A `fast path` means “use the verified record directly instead of rerunning the full leaf verification.”
- A `compact block proof` means one proof object that says “all the leaf checks and fold checks were done correctly,” so verifiers do not need either the replay-heavy path or the records fast path.

## Plan of Work

Start with the engineering path in `consensus/src/proof.rs`. Thread verified leaf records through the block-artifact verification call graph instead of discarding them after statement binding derivation. The concrete goal is that the product-path native receipt-root verifier calls the records-only verifier in `circuits/superneo-hegemon/src/lib.rs` whenever the block importer already has verified leaf records for all included transactions.

This requires making the verified leaf records available at the point where `verify_experimental_native_receipt_root_artifact(...)` is currently called. The cleanest path is to add one new helper in `consensus/src/proof.rs`, with a name like:

    verify_experimental_native_receipt_root_artifact_from_records(...)

That helper must accept the verified native leaf records collected during tx-artifact verification and then call `verify_native_tx_leaf_receipt_root_artifact_from_records_with_params(...)`. Keep the existing replay-heavy verifier and add one cross-check test that proves both verifiers agree on valid and invalid inputs.

Next, make the import report explicit. `BlockArtifactVerifyReport` already exists in `consensus/src/proof.rs`. Extend it so the report says whether root verification used:

- `replay`
- `verified_records`
- `compact_prototype`

The first two are product and diagnostic modes. The third is for the later prototype milestone only.

Then extend `circuits/superneo-bench/src/main.rs` so the verify-only benchmark reports the same mode labels and, separately, so one new benchmark can exercise the exact consensus import path rather than only the raw library helpers.

After the engineering fast path lands, prototype the compact block proof as a new research-only relation. Do not bolt it directly into product routing. Create a dedicated relation and proof artifact whose only purpose is to prove, over a small benchmark-sized leaf set at first, that:

1. each included `tx_leaf` check succeeded,
2. each fold step was recomputed correctly,
3. the final root matches the canonical ordered leaf set.

The plan assumes a new experimental relation in `circuits/superneo-hegemon/src/lib.rs` or a nearby crate with a name like `ReceiptRootVerifierRelation`, plus a benchmark-only command in `circuits/superneo-bench/src/main.rs` to build and verify that prototype proof. The prototype remains explicitly non-product until it proves better than the records fast path on bytes or verification time and until its security claim is documented in the crypto notes.

## Concrete Steps

All commands run from repository root `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Implement the verified-record import path in `consensus/src/proof.rs`, then run:

    cargo test -p consensus --test raw_active_mode receipt_root_ -- --ignored --nocapture
    cargo test -p hegemon-node receipt_root -- --nocapture
    cargo test -p superneo-hegemon native_receipt_root_ -- --nocapture

Expected result: valid native receipt-root blocks still verify, tampered roots still fail, and the product-path verifier now routes through verified records when those records are available.

2. Extend the benchmark and run:

    cargo run -p superneo-bench -- --measure-native-receipt-root-verify-only --leaf-count 8 --verify-runs 3

Expected result: the report still shows both replay and records timing, and the consensus-path report identifies the default mode as `verified_records`.

3. Add the compact-proof prototype and run:

    cargo run -p superneo-bench -- --relation native_tx_leaf_receipt_root --allow-diagnostic-relation --compact-receipt-root-prototype --leaf-count 8

Expected result: the prototype either verifies successfully and emits a measurable proof size and verify time, or fails fast with a documented reason. The result must be captured in the plan and docs either way.

4. Run the full gate:

    ./scripts/check-core.sh test

Expected result: the workspace remains green after the fast path and prototype additions.

## Validation and Acceptance

This plan is accepted in two stages.

Stage 1, the import fast path, is accepted when:

1. The product-path native receipt-root verifier uses verified records by default whenever all included `tx_leaf` artifacts have already been validated.
2. The benchmark and verify reports label the mode used.
3. On the local `8`-leaf benchmark, the product-path root step stays within `2x` of the current `0.027s` records-only measurement and remains dramatically below the replay-heavy `0.695s` path.
4. Replay-heavy verification remains available for diagnostics and continues to agree with the fast path on valid and invalid cases.

Stage 2, the compact-proof prototype, is accepted when:

1. The repo can build and verify a compact prototype proof over at least an `8`-leaf benchmark case.
2. The prototype has an explicit security note describing what it proves and what it does not prove.
3. The prototype beats either replay-heavy verification or records-fast-path verification on at least one meaningful axis, or else is explicitly documented as rejected for promotion.

The second stage is intentionally not required for the first stage to ship.

## Idempotence and Recovery

The verified-record fast path must remain safely reversible by one local switch or code path if a regression appears. Do not delete the replay-heavy verifier during this plan. The compact-proof prototype must be isolated behind an explicit benchmark or feature gate so it cannot accidentally become consensus-critical. If the prototype fails to beat the fast path, keep the implementation quarantined to the research lane or delete it after recording the result.

## Artifacts and Notes

The key evidence for stage 1 is the timing delta and mode report. A successful report should look like this in shape:

    {
      "leaf_count": 8,
      "root_verify_mode": "verified_records",
      "receipt_root_replay_verify_ms": 695.3,
      "receipt_root_records_verify_ms": 27.1
    }

The key evidence for stage 2 is a prototype report like:

    {
      "leaf_count": 8,
      "prototype_proof_bytes": 18240,
      "prototype_verify_ms": 11.7,
      "baseline_records_verify_ms": 27.1,
      "promotion_recommendation": "keep_research_lane"
    }

Those numbers are examples of the outputs the plan must produce, not promises of the exact final values.

## Interfaces and Dependencies

At the end of stage 1, the following interfaces must exist:

- In `consensus/src/proof.rs`:

    verify_experimental_native_receipt_root_artifact_from_records(...)

  or an equivalent helper that accepts verified native leaf records and feeds them to the records-only verifier.

- `BlockArtifactVerifyReport` must expose which verification mode was used.

- In `circuits/superneo-bench/src/main.rs`, the verify-only report must label replay versus verified-record mode and must be able to exercise the product import path.

At the end of stage 2, the following research-only interfaces must exist:

- A compact prototype relation and builder, for example:

    build_compact_receipt_root_prototype(...)
    verify_compact_receipt_root_prototype(...)

- A benchmark entry point in `circuits/superneo-bench/src/main.rs` that can build and verify the compact prototype over a small leaf set.

Dependencies:

- Reuse the verified native leaf store already implemented in `consensus/src/proof.rs`.
- Reuse `verify_native_tx_leaf_receipt_root_artifact_from_records_with_params(...)` in `circuits/superneo-hegemon/src/lib.rs`.
- Keep the compact-proof prototype logically separate from the existing `verified_leaf_aggregation` claim until the crypto note is updated and reviewed.

Change note (2026-04-05): created to split the immediate import-speed win from the longer-term compact-proof research so Hegemon can ship the engineering gain now without confusing it with unfinished cryptographic work.
