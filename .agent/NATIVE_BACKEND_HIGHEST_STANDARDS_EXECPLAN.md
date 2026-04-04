# Native Backend Highest Standards Hardening

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, the native backend review surface will stop underspecifying the shipped property and stop asking reviewers to trust one repo-owned claim printout. A reviewer will be able to see, in code and in the packaged review tarball, that the active product lane is explicitly a verified-leaf aggregation system over STARK-validated leaves rather than a generic CCS-sound folding proof system, and will also be able to recompute the published security claim from machine-readable attack-model artifacts using the independent reference tool. The visible proof of success is a rebuilt review package that contains the theorem notes, attack-model JSON, live message-class JSON, claim sweep JSON, production and reference verifier reports, and a verifier script that checks all of them.

## Progress

- [x] (2026-04-03 21:18Z) Re-read `.agent/PLANS.md`, the native backend theorem work, the review-package scripts, and the backend/core interfaces.
- [x] (2026-04-03 21:26Z) Confirmed the core structural gap: `superneo_core::FoldedInstance` carries only relation id, shape digest, statement digest, and witness commitment, so the current fold layer has no residual or relaxed-instance state to support Neo/SuperNeo-style CCS soundness.
- [x] (2026-04-03 21:31Z) Confirmed the review-package gap: `scripts/package_native_backend_review.sh` packages claim prose and vectors, but not the new theorem note or any machine-readable attack-model artifact beyond `current_claim.json`.
- [x] (2026-04-04 03:25Z) Added a machine-readable claim-scope label for the active line (`verified_leaf_aggregation`), propagated the aggregation replay assumption id into the exported claim, and aligned the review-manifest guarantee object with the shipped property.
- [x] (2026-04-04 03:25Z) Added machine-readable attack-model, live message-class, estimator-trace, and claim-sweep artifacts to `superneo-bench`, including failure rows for unsupported sweep points instead of aborting package generation.
- [x] (2026-04-04 03:25Z) Added an independent claim-recomputation command to `native-backend-ref`, packaged its report, and wired both package scripts to run claim verification plus production bundle replay from the staged package contents.
- [x] (2026-04-04 03:25Z) Updated review docs/templates, regenerated `testdata/native_backend_vectors/bundle.json`, rebuilt the review package, and reran the relevant tests plus package verification.

## Surprises & Discoveries

- Observation: the current `Relation` model does not encode enough semantics for verifier-side CCS checking.
  Evidence: [circuits/superneo-ccs/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-ccs/src/lib.rs) defines `CcsShape`, `StatementEncoding`, and `Assignment`, but no generic evaluation rule; relation semantics currently live inside `build_assignment` implementations such as [ToyBalanceRelation::build_assignment](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) and [TxLeafPublicRelation::build_assignment](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs).

- Observation: the independent reference tool is only independent for artifact verification today, not for claim arithmetic.
  Evidence: [tools/native-backend-ref/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref/src/main.rs) currently exposes only `verify-vectors`.

- Observation: the production verifier parity check already exists in code, but only as an internal bench test.
  Evidence: [review_vectors_agree_between_production_and_reference_verifiers](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs) replays the review bundle through both verifiers, but there is no packaged CLI or report for that parity check.

- Observation: the initial claim-sweep implementation crashed when it reached parameter points where the estimator model was invalid instead of recording those rows as unsupported.
  Evidence: the first `./scripts/package_native_backend_review.sh` run failed with `BK-MSIS Euclidean estimator failed: target delta ... is below 1` while generating `claim_sweep.json`.

- Observation: the checked-in deterministic review bundle lagged the current claim schema.
  Evidence: the first staged production replay failed to parse `bundle.json` because the embedded `native_security_claim` object did not yet include `soundness_scope_label`.

## Decision Log

- Decision: do not pretend the current fold backend can be upgraded to Neo/SuperNeo CCS soundness by changing prose alone.
  Rationale: the current core types do not carry residuals, relaxed-instance scalars, or any verifier-side CCS evaluation object. The honest “highest standards” move is to codify and prove the exact shipped property, not to overclaim.
  Date/Author: 2026-04-03 / Codex

- Decision: encode the active product property as `verified_leaf_aggregation` in the machine-readable claim surface.
  Rationale: the active Hegemon lane already replays STARK leaf verification and deterministic commitment reconstruction at receipt-root verification time. That is the real shipped soundness envelope and should be part of the exported claim, the docs, and the package.
  Date/Author: 2026-04-03 / Codex

- Decision: add an independent claim-checking command to `native-backend-ref` instead of relying only on `superneo-bench` JSON dumps.
  Rationale: the cleanest improvement beyond “repo-owned estimator only” is to let the independent reference tool recompute the published claim from packaged machine-readable inputs.
  Date/Author: 2026-04-03 / Codex

## Outcomes & Retrospective

The repo now packages the exact shipped security object and the exact arithmetic behind its exported claim at a materially higher standard. The active claim surface is machine-readable as `verified_leaf_aggregation`, not generic fold soundness; the review package now contains `current_claim.json`, `attack_model.json`, `message_class.json`, `claim_sweep.json`, `review_manifest.json`, `reference_verifier_report.json`, `reference_claim_verifier_report.json`, and `production_verifier_report.json`; and the package verifier rechecks all of them from the tarball itself.

The most useful fixes were not cosmetic. One patch changed the sweep generator so reviewers can see where the claim fails without crashing the package build. The other regenerated the deterministic review bundle and added backward-tolerant parsing for `soundness_scope_label`, so the fixed vectors and the production replay path now agree on the actual current schema.

Validation completed with:

- `cargo test -p native-backend-ref -- --nocapture`
- `cargo test -p superneo-bench review_vectors_agree_between_production_and_reference_verifiers -- --nocapture`
- `cargo test -p superneo-backend-lattice --lib -- --nocapture`
- `cargo run -p superneo-bench -- --emit-review-vectors testdata/native_backend_vectors`
- `./scripts/package_native_backend_review.sh`
- `./scripts/verify_native_backend_review_package.sh`

The rebuilt package hash is `cda6fbbe412a9374b2a9b5a7ce190e22b8fbbfee93a2097542f3225995add308`.

## Context and Orientation

The native backend is split across several crates. [circuits/superneo-core/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-core/src/lib.rs) defines the generic backend trait and the `FoldedInstance` type. [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs) implements the current native commitment and fold backend. [circuits/superneo-ccs/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-ccs/src/lib.rs) defines the CCS shape and relation interfaces. [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) defines the Hegemon-specific relations and the native `tx_leaf -> receipt_root` product path. [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs) already emits review vectors and claim JSON. [tools/native-backend-ref/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref/src/lib.rs) is the separate reference verifier used in the review package. [scripts/package_native_backend_review.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/package_native_backend_review.sh) and [scripts/verify_native_backend_review_package.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/verify_native_backend_review_package.sh) build and verify the package.

In this plan, “verified-leaf aggregation” means the exact shipped property that receipt-root verification replays every tx-leaf verification step, where each tx-leaf verification already checks the STARK proof, the canonical receipt, the public-input digest, the deterministic public-witness reconstruction, and the deterministic commitment digest. This is different from “CCS soundness,” which would require the fold layer itself to preserve a verifier-checkable algebraic relation state such as a residual vector or relaxed-instance accumulator. The current repo does not have that state.

In this plan, “attack-model artifact” means a machine-readable JSON file that contains the exact numeric inputs and intermediate values behind the exported security claim: the active modulus, dimensions, coefficient bounds, live message-class size, transcript-law inputs, estimator trace, and sensitivity sweep rows. The goal is that the reference tool can recompute the published claim from these artifacts without calling production claim code.

## Plan of Work

First, extend the exported claim surface to distinguish the actual active soundness scope from generic folding folklore. In [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs), add a machine-readable label on `NativeSecurityClaim` that identifies the active lane as `verified_leaf_aggregation`. Also extend the active `assumption_ids` so the claim explicitly depends on receipt-root verification replaying tx-leaf verification. Then add a new theorem note under `docs/crypto/` that proves the exact shipped product property: acceptance of a native receipt-root artifact implies every leaf is a valid native tx-leaf artifact for the supplied records and every internal node matches the deterministic fold transcript. Update the existing security-analysis and claim docs so that this property is the first-class statement of shipped soundness, while still leaving the Neo/SuperNeo caveat intact as a non-goal.

Second, extend [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs) so it can emit machine-readable review artifacts beyond `current_claim.json`. Add serializable structs and CLI paths for `attack_model.json`, `message_class.json`, and `claim_sweep.json`. `attack_model.json` must contain the exact theorem and estimator inputs for the active conservative instance and the exact live message-class subclass. `message_class.json` must lock the current `TxLeafPublicRelation` witness size (`4935` bits, `617` digits, `12` ring elements, `6492` live `B_2`). `claim_sweep.json` must show how the exported floor changes as `max_commitment_message_ring_elems` and `max_claimed_receipt_root_leaves` vary around the active point, with explicit rows that show where a `128`-bit claim would fail validation. Also add a CLI path that replays a review bundle through the production verifier and prints a JSON report, reusing the existing internal production parity helper.

Third, extend [tools/native-backend-ref/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref/src/lib.rs) and [tools/native-backend-ref/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref/src/main.rs) with an independent claim-recomputation command. This code must read the packaged `attack_model.json` and `current_claim.json`, recompute the transcript term, composition loss, commitment geometry statistics, and estimator outputs independently of the production crate, and fail if any exported field disagrees. Keep the formulas local to the reference tool even if they mirror the production code; the point is package reproducibility from the independent tool, not avoiding repeated arithmetic. The command should be usable both on a package directory and on explicit JSON files so the package verifier can call it directly.

Fourth, update the packaging and verification scripts. [scripts/package_native_backend_review.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/package_native_backend_review.sh) must package the new theorem note and new JSON artifacts, plus a production verifier report created by the new `superneo-bench` bundle-replay CLI. [scripts/verify_native_backend_review_package.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/verify_native_backend_review_package.sh) must assert the presence of those files, run the reference verifier on `bundle.json`, run the independent claim checker on the packaged attack-model files, and run the production bundle replay so the package proves production/reference agreement rather than merely assuming it.

Finally, update the review docs. [audits/native-backend-128b/REVIEW_QUESTIONS.md](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/REVIEW_QUESTIONS.md) and [audits/native-backend-128b/REPORT_TEMPLATE.md](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/REPORT_TEMPLATE.md) should instruct reviewers to recompute the claim from `attack_model.json`, inspect `claim_sweep.json`, and compare the production and reference verifier reports. The package claim summary should mention the new `soundness_scope_label` and the exact reviewed property.

## Concrete Steps

Work from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

Implement and validate in this order:

    cargo test -p superneo-backend-lattice --lib -- --nocapture
    cargo test -p superneo-bench review_vectors_agree_between_production_and_reference_verifiers -- --nocapture
    cargo test -p native-backend-ref -- --nocapture
    cargo run -p superneo-bench -- --print-native-security-claim
    cargo run -p superneo-bench -- --emit-review-vectors testdata/native_backend_vectors
    ./scripts/package_native_backend_review.sh
    ./scripts/verify_native_backend_review_package.sh

If the new production bundle-replay CLI has its own command, include it in the package verification transcript and in this plan once implemented.

## Validation and Acceptance

This work is accepted when all of the following are true:

1. The exported claim surface contains a machine-readable label that the active Hegemon lane is `verified_leaf_aggregation`, not generic CCS-sound folding.
2. The repository contains a theorem note proving the shipped verified-leaf aggregation property with code references to the tx-leaf and receipt-root verification path.
3. The review package contains `native_backend_formal_theorems.md`, the new verified-leaf aggregation theorem note, `attack_model.json`, `message_class.json`, `claim_sweep.json`, `current_claim.json`, a production verifier report, and a reference verifier report.
4. `native-backend-ref` can independently recompute and verify the packaged claim arithmetic from those artifacts.
5. The package verification script runs the reference verifier, the independent claim checker, and the production bundle replay successfully.

## Idempotence and Recovery

These changes are additive and safe to rerun. Rebuilding the review package is deterministic for a fixed working tree, so rerunning the package script simply refreshes the tarball and checksum. If any claim-surface field changes during implementation, update the bench JSON structs, the reference-tool claim checker, the package script, and the docs together; partial updates are unsafe because the package verifier will then compare inconsistent files.

## Artifacts and Notes

Capture these exact outputs after implementation:

    cargo test -p superneo-backend-lattice --lib -- --nocapture
    cargo test -p superneo-bench review_vectors_agree_between_production_and_reference_verifiers -- --nocapture
    cargo test -p native-backend-ref -- --nocapture
    ./scripts/package_native_backend_review.sh
    ./scripts/verify_native_backend_review_package.sh

Also capture the rebuilt package hash from `audits/native-backend-128b/package.sha256` and note the names of the new package artifacts.

## Interfaces and Dependencies

The final repository state must keep these surfaces usable:

- `superneo_backend_lattice::NativeSecurityClaim`
- `superneo_bench` CLI `--print-native-security-claim`
- `superneo_bench` review-vector emission
- `native_backend_ref` CLI `verify-vectors`

It must add and preserve these surfaces:

- a machine-readable claim-scope label on `NativeSecurityClaim`
- a `superneo-bench` CLI path that emits the machine-readable attack-model artifacts
- a `superneo-bench` CLI path that replays a review bundle through the production verifier
- a `native-backend-ref` CLI path that independently recomputes the packaged claim arithmetic

Revision note (2026-04-03 / Codex): created this ExecPlan after the theorem pass closed the in-repo math gap but left two honest caveats: the active lane still is not Neo/SuperNeo CCS soundness, and the package still does not let outsiders recompute the claim without trusting repo-generated JSON. This plan raises the standard by codifying the exact shipped soundness scope and by making the package independently reproducible.
