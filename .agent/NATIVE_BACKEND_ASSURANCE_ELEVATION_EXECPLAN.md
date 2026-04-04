# Elevate Native Backend Assurance To The Actual Shipped Security Object

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, the native backend review surface will match the actual security object the product ships instead of leaving reviewers to reverse-engineer it from scattered notes. A reviewer will be able to inspect one explicit “verified-leaf aggregation” note for the `tx_leaf -> receipt_root` lane, inspect one machine-generated review manifest that includes the exact live and conservative commitment dimensions plus the theorem-backed claim numbers, run the packaged verifier, and see targeted tests that prove receipt-root verification really replays every leaf verification and every fold recomputation. This does not turn the backend into Neo/SuperNeo CCS soundness, but it does raise the repo from “admits the caveat” to “packages the exact shipped guarantee and the exact external-review brief at a high standard.”

## Progress

- [x] (2026-04-03 21:32Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, `circuits/superneo-core/src/lib.rs`, `circuits/superneo-ccs/src/lib.rs`, `circuits/superneo-backend-lattice/src/lib.rs`, `circuits/superneo-hegemon/src/lib.rs`, `scripts/package_native_backend_review.sh`, `scripts/verify_native_backend_review_package.sh`, and `docs/SECURITY_REVIEWS.md`.
- [x] (2026-04-03 21:40Z) Confirmed the current fold layer cannot be made CCS-sound by a small patch because `superneo-ccs` does not define relation-evaluation semantics and `FoldedInstance` carries only relation id, shape digest, statement digest, and a witness commitment.
- [ ] Add machine-readable native review reports that expose the exact live `TxLeafPublicRelation` commitment dimensions, the conservative exported claim dimensions, and the precise verified-aggregation guarantees.
- [ ] Add a high-standard note that defines the actual shipped `tx_leaf -> receipt_root` security object as verified-leaf aggregation rather than CCS soundness.
- [ ] Tighten the receipt-root tamper regressions so the code proves it rejects tampered leaf proof digests and tampered leaf statement digests inside root artifacts.
- [ ] Extend the review package so it includes the theorem note, the verified-aggregation note, the native review manifest JSON, and the external-review workflow doc for cryptanalysis consumers.
- [ ] Rebuild and verify the review package after the new artifacts land.

## Surprises & Discoveries

- Observation: `superneo-ccs` currently validates shape metadata and witness lengths but does not define any generic CCS relation-evaluation function.
  Evidence: [circuits/superneo-ccs/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-ccs/src/lib.rs) exposes `CcsShape`, `Relation`, `StatementEncoding`, and shape hashing, but no function that evaluates matrix rows against assignments or public inputs.

- Observation: `FoldedInstance` is too small to carry CCS residual state.
  Evidence: [circuits/superneo-core/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-core/src/lib.rs) stores only `relation_id`, `shape_digest`, `statement_digest`, and `witness_commitment`, so there is nowhere to carry folded residual vectors, sum-check state, or evaluation claims.

- Observation: the shipped `receipt_root` verifier already implements a strong closure property over verified tx-leaf artifacts, but that property is encoded only in code and tests, not as a first-class review artifact.
  Evidence: [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) replays `verify_native_tx_leaf_artifact_bytes_with_params` for every leaf and then replays `backend.fold_pair` and `backend.verify_fold` for every parent, yet the current review package does not include a dedicated note or machine-generated manifest for that guarantee.

## Decision Log

- Decision: do not pretend this turn can deliver Neo/SuperNeo CCS soundness.
  Rationale: the current repository lacks CCS evaluation semantics and folded residual state, so a truthful CCS-sound fold would require a new protocol and new proof objects, not just more checks around the existing deterministic fold path.
  Date/Author: 2026-04-03 / Codex

- Decision: elevate the repo by formalizing the actual shipped security object as verified-leaf aggregation and by turning its exact review inputs into generated artifacts.
  Rationale: this is the strongest truthful improvement available inside the current architecture. It gives reviewers exact guarantees, exact dimensions, and exact parameter manifests instead of caveats plus scattered prose.
  Date/Author: 2026-04-03 / Codex

## Outcomes & Retrospective

Pending implementation.

## Context and Orientation

The current native backend is spread across four layers. [circuits/superneo-core/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-core/src/lib.rs) defines the generic backend interface and the `FoldedInstance` type. [circuits/superneo-ccs/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-ccs/src/lib.rs) defines lightweight CCS metadata objects such as `CcsShape`, `StatementEncoding`, and `Relation`, but it does not implement generic relation evaluation. [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs) implements the deterministic commitment kernel, leaf proof hashing, and fold canonicalization. [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) defines the Hegemon-specific `TxLeafPublicRelation`, builds native tx-leaf artifacts, and verifies `receipt_root` artifacts by replaying every leaf verification and every fold recomputation.

In this plan, “verified-leaf aggregation” means the actual shipped property of the `receipt_root` lane: every accepted root is built only from tx-leaf artifacts that individually pass tx-leaf verification under the active parameter set, and every fold step in the root artifact is recomputed and checked against those verified leaves. This is stronger than a loose “hash chain” description, but it is not Neo/SuperNeo CCS soundness because the fold layer does not prove generic relation satisfaction by itself.

The review package today already contains protocol prose, vectors, the reference verifier, and the current claim JSON. What is missing is a generated manifest for the exact live commitment subclass and a first-class note for the verified-leaf aggregation guarantee. This plan adds those missing artifacts and validates them end to end.

## Plan of Work

First, add a small exported helper in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) that computes the exact current `TxLeafPublicRelation` commitment dimensions from the live relation shape and the active native backend parameters. This helper must return the exact witness bits, digit count, live ring-element count, live coefficient dimension, coefficient bound, and live `l2` bound so the review surface stops relying on handwritten arithmetic. Add unit tests that lock the current values `4935`, `617`, `12`, `648`, and `6492`.

Second, extend [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs) with a new JSON-emission mode for a native backend review manifest. This report must include: the active backend params, the exported native security claim, the exact live tx-leaf commitment stats from the new helper, the conservative exported dimensions, and a short machine-readable guarantee block that says the root lane re-verifies every tx-leaf and recomputes every fold. Keep the existing `--print-native-security-claim` behavior intact; add a separate flag for the richer manifest.

Third, write a new prose note under `docs/crypto/` that defines the verified-leaf aggregation guarantee precisely. It must state what `verify_native_tx_leaf_receipt_root_artifact_bytes_with_params` proves in repository terms, what fields it rechecks on each leaf, what fold fields it recomputes, and what it does not claim. The note must cite the exact code paths in `superneo-hegemon` and `superneo-backend-lattice`. This note will sit alongside the theorem note and must be included in the review package.

Fourth, tighten the implementation evidence in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) with new tamper regressions. Add one test that mutates a root artifact leaf’s `proof_digest` and confirms root verification rejects. Add another that mutates a root artifact leaf’s `statement_digest` and confirms rejection. These tests should exercise the exact shipped verified-leaf aggregation guarantee and fail before the checks they rely on are in place.

Fifth, upgrade the external review package scripts. Update [scripts/package_native_backend_review.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/package_native_backend_review.sh) to copy the theorem note, the new verified-aggregation note, and `docs/SECURITY_REVIEWS.md`, and to emit the new review-manifest JSON into the staged package. Update [scripts/verify_native_backend_review_package.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/verify_native_backend_review_package.sh) to assert those files exist and to sanity-check the generated review-manifest JSON before running the reference verifier.

Finally, update the native backend claim and review docs so they point at the new verified-aggregation note and the new manifest JSON. Then rebuild and reverify the package so the tarball reflects the stricter artifact set.

## Concrete Steps

Work from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

Implement and validate with:

    cargo test -p superneo-hegemon -- --nocapture
    cargo test -p superneo-bench -- --nocapture
    cargo run -p superneo-bench -- --print-native-review-manifest
    ./scripts/package_native_backend_review.sh
    ./scripts/verify_native_backend_review_package.sh

Acceptance means the new review-manifest mode prints valid JSON, the new tamper tests pass, the new docs are packaged, and the review-package verification script still passes on the rebuilt tarball.

## Validation and Acceptance

This work is accepted when all of the following are true:

1. The repo contains one dedicated note for the actual shipped verified-leaf aggregation guarantee.
2. The repo contains a generated native review manifest with both exact live and conservative commitment dimensions.
3. Receipt-root verification has explicit regression coverage for tampered leaf proof digests and tampered leaf statement digests.
4. The rebuilt review package contains the theorem note, the verified-aggregation note, the new review manifest JSON, and the security-review workflow doc.
5. The rebuilt package self-verifies with the reference verifier.

## Idempotence and Recovery

These edits are additive and safe to rerun. The review-package rebuild overwrites the tarball and checksum deterministically for the current worktree. If the new manifest JSON changes shape, update the package verification script in the same change so the package remains self-consistent.

## Artifacts and Notes

Capture the final outputs of:

    cargo run -p superneo-bench -- --print-native-review-manifest
    ./scripts/package_native_backend_review.sh
    ./scripts/verify_native_backend_review_package.sh

Also capture the exact live stats locked by the new helper and tests.

## Interfaces and Dependencies

The final repository state must expose:

- an exported helper in `superneo_hegemon` for exact live tx-leaf commitment stats,
- a new `superneo-bench` CLI flag that emits the native review manifest JSON,
- a verified-aggregation note under `docs/crypto/`,
- upgraded package scripts that include and verify the new artifacts.

The implementation must keep the existing `tx_leaf -> receipt_root` behavior intact. The goal is to elevate assurance and reviewer clarity, not to change the live artifact format or consensus behavior.

Revision note (2026-04-03 / Codex): created this ExecPlan after confirming that the remaining assurance gap is architectural, not a missing check. The strongest truthful upgrade inside the current repo is to formalize the shipped verified-leaf aggregation guarantee and package its exact review inputs at a high standard.
