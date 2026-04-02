# Replace The Fully-Splitting Native Ring With A Real Frog Profile

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, the native `tx_leaf -> receipt_root` backend will stop relying on the fully-splitting `X^8 + 1` ring used by the current `GoldilocksCyclotomic24` profile. The active family will instead use a real `GoldilocksFrog` profile with an explicitly implemented non-negacyclic ring law, while keeping the overall commitment surface and artifact size in the same rough budget. A reviewer will be able to see the new ring profile in the code and docs, regenerate the native review package, and verify that the backend, reference verifier, and product-path tests still pass.

## Progress

- [x] (2026-04-02 09:57 MDT) Audited the current backend and confirmed `GoldilocksFrog` is only a label today; no real ring-law distinction exists yet.
- [x] (2026-04-02 11:24 MDT) Implemented a real `GoldilocksFrog` ring profile in the production backend and reference verifier, including profile-owned degree/reduction metadata, profile-aware fold mixing, and exact `v8` manifest updates.
- [x] (2026-04-02 11:37 MDT) Moved the active parameter set and docs from the fully-splitting cyclotomic profile to the real frog profile, updated the claim numbers, and rotated the review questions/known gaps to the new live quotient.
- [x] (2026-04-02 11:55 MDT) Regenerated native review vectors and rebuilt the external review package; both the local reference verifier and the packaged verifier report now pass on the `v8` frog bundle.
- [x] (2026-04-02 12:13 MDT) Reran the native crate tests plus the product-path `receipt_root` consensus/node gates against the migrated backend.
- [x] (2026-04-02 12:53 MDT) Refreshed the packaged benchmark snapshot with a new release benchmark archive and rebuilt the review tarball against it.

## Surprises & Discoveries

- Observation: the existing `GoldilocksFrog` profile is not a real algebraic alternative yet; it only changes domain-separation labels.
  Evidence: `circuits/superneo-backend-lattice/src/lib.rs` uses `ring_profile.label()` in fingerprints and transcripts, but the live multiplication/reduction path is still hardcoded negacyclic logic.
- Observation: moving from degree `8` to degree `54` exposed a real arithmetic bug in the generic ring multiplier; raw convolution accumulation could overflow `i128` before reduction.
  Evidence: `cargo run -p superneo-bench -- --emit-review-vectors testdata/native_backend_vectors` panicked in `multiply_ring_elems_with_mode` until the accumulator was changed to reduce each product modulo Goldilocks during accumulation.
- Observation: the package verify failure after the first rebuild was not a crypto mismatch; it was caused by verifying the tarball in parallel with the package rebuild.
  Evidence: the packaged `bundle.json` already carried the new `v8` frog parameters, and `./scripts/verify_native_backend_review_package.sh` passed immediately when rerun after package completion.

## Decision Log

- Decision: keep the overall commitment footprint near the current one by moving from `(matrix_rows = 74, ring_degree = 8)` to a larger ring degree with fewer rows such that `matrix_rows * ring_degree` stays roughly constant.
  Rationale: this derisks the ring choice without gratuitously inflating artifact bytes or verification work.
  Date/Author: 2026-04-02 / Codex

- Decision: implement the new ring as the meaning of the existing `GoldilocksFrog` profile instead of inventing another profile name.
  Rationale: the enum and reference-verifier scaffolding already carry that profile label, so using it avoids unnecessary interface churn while still forcing a real spec/version bump.
  Date/Author: 2026-04-02 / Codex

- Decision: keep the flattened commitment message dimension exactly at `4104` coefficients by moving from `(matrix_rows = 74, ring_degree = 8, max_commitment_message_ring_elems = 513)` to `(matrix_rows = 11, ring_degree = 54, max_commitment_message_ring_elems = 76)`.
  Rationale: this removes the live fully-splitting degree-8 quotient while preserving the exact ambient witness dimension used by the active commitment reduction and estimator path.
  Date/Author: 2026-04-02 / Codex

## Outcomes & Retrospective

The proactive derisking pass is complete. The live backend now uses a real `GoldilocksFrog` ring profile with quotient `Z_q[X] / (X^54 + X^27 + 1)` instead of the old fully-splitting degree-8 `X^8 + 1` line. The active manifest is now `hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v8`, the active `parameter_fingerprint` is `dc2fae3cd1f05cf81a446b46afa6ad70ed8582de8402e598bae1dd3bdf35b429acb87c9939969efa0c54b97b9920a0d7`, and the active `spec_digest` is `c441d06521bf6e604fda75378aea05e341ad3f4a8769d74a9cca4e3ff582eb23`.

The main implementation surprise was arithmetic rather than architecture: the degree-54 generic convolution path overflowed `i128` until the multiplier was changed to reduce each product modulo Goldilocks during accumulation. Once that was fixed, the regenerated review vectors, reference verifier, package rebuild, native crate tests, and product-path `receipt_root` tests all passed. The new release benchmark archive now lives at [native_tx_leaf_receipt_root_claim_alignment_20260402.json](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/benchmarks/native_tx_leaf_receipt_root_claim_alignment_20260402.json), and the rebuilt review package checksum is recorded in [package.sha256](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/package.sha256).

## Context and Orientation

The live native backend is implemented across three main areas. [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs) contains the parameter object, witness embedding, commitment kernel, leaf verification, and fold verification. [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) defines the Hegemon-specific relations, native artifact byte formats, and the `tx_leaf` / `receipt_root` builders and verifiers. [tools/native-backend-ref/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref/src/lib.rs) is the separate reference verifier used in the external review package.

Today the active family is documented as `GoldilocksCyclotomic24`, which means the ring law is the negacyclic degree-8 quotient `Z_q[X] / (X^8 + 1)`. That is the profile external reviewers flagged as fully splitting over Goldilocks. The repository already admits the backend is not paper-equivalent Neo/SuperNeo in [docs/crypto/native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md) and [audits/native-backend-128b/KNOWN_GAPS.md](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/KNOWN_GAPS.md), but the proactive de-risking step is to stop using the fully-splitting live ring at all.

In this repo, a “ring profile” means the quotient-polynomial law used when multiplying and folding ring elements, plus the parameter and manifest values that identify that algebra. The key invariant for this plan is that the ring profile must affect the actual multiplication/reduction rules, not only labels or hashes.

## Plan of Work

The implementation begins in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs). Replace the hardcoded negacyclic assumptions with profile-owned ring metadata: degree, reduction polynomial, and helper routines for reducing products and multiplying by low-degree challenge polynomials. The existing `GoldilocksCyclotomic24` path should remain available for tests and historical artifacts, but the active default must move to a real `GoldilocksFrog` profile. The frog profile should use a non-negacyclic polynomial of higher degree so Goldilocks no longer gives a fully-splitting `X^8 + 1` quotient. The row count and message-cap parameters should then be retuned so the total coefficient surface remains close to the current shipped size budget.

Mirror that exact ring law in [tools/native-backend-ref/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref/src/lib.rs). The reference verifier must not silently keep the old negacyclic rule after the production backend changes. Every function that currently assumes “rotation with sign flip” or “negacyclic product” needs the same profile-aware reduction logic.

Once the algebra changes, update the active manifest/spec identity, security analysis, commitment reduction note, review questions, and packaged claims under [docs/crypto](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto) and [audits/native-backend-128b](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b). The docs must say exactly which polynomial defines `GoldilocksFrog`, how the active dimensions changed, and that the live profile is no longer the fully-splitting cyclotomic line. Regenerate the native vectors and review package so external reviewers see the new exact surface.

## Concrete Steps

Work from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

Implement the production backend and reference-verifier changes, then regenerate and validate with:

    cargo test -p superneo-backend-lattice -p native-backend-ref -p superneo-hegemon -p superneo-bench
    cargo run -p superneo-bench -- --emit-review-vectors testdata/native_backend_vectors
    cargo run -p native-backend-ref -- verify-vectors testdata/native_backend_vectors
    ./scripts/package_native_backend_review.sh
    ./scripts/verify_native_backend_review_package.sh

If the active family or vectors change, rerun the CI-relevant native-path checks:

    cargo test -p consensus --test raw_active_mode receipt_root_ -- --ignored --nocapture
    cargo test -p hegemon-node receipt_root -- --nocapture
    ./scripts/check-core.sh test

Expected success is all commands exiting `0`, regenerated vectors verifying cleanly, and the review package rebuilding with a new checksum if the spec identity changed.

## Validation and Acceptance

Acceptance is not “the code compiles.” Acceptance means:

1. The active native family in [docs/crypto/native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md) no longer names the fully-splitting degree-8 cyclotomic profile as the live ring.
2. Production and reference verification both succeed on regenerated native vectors under the new ring law.
3. Receipt-root construction and verification tests still pass on the product path.
4. The review package can be rebuilt and self-verified with the updated exact source snapshot and vectors.

## Idempotence and Recovery

This work is safe to rerun. Vector emission and package generation overwrite the review artifacts deterministically for the current working tree. If the new ring profile causes an unexpected performance or compatibility regression, the safe rollback is to revert the active parameter object and regenerated docs/vectors together; partial rollbacks are unsafe because the `spec_digest`, vectors, and package must always match the code.

## Artifacts and Notes

Important evidence to capture after the implementation lands:

    cargo run -p native-backend-ref -- verify-vectors testdata/native_backend_vectors
    ./scripts/package_native_backend_review.sh
    ./scripts/verify_native_backend_review_package.sh

Also capture the new active `spec_label`, `parameter_fingerprint`, and `spec_digest` in the final notes once they are regenerated.

## Interfaces and Dependencies

The backend still exposes the same top-level interfaces:

- `superneo_backend_lattice::NativeBackendParams`
- `superneo_backend_lattice::LatticeBackend`
- `superneo_hegemon::build_native_tx_leaf_artifact_bytes`
- `superneo_hegemon::verify_native_tx_leaf_artifact_bytes_with_params`
- `superneo_hegemon::verify_native_tx_leaf_receipt_root_artifact_bytes_with_params`

What changes is the meaning of `RingProfile::GoldilocksFrog`: it must own a concrete reduction law, and every production/reference code path that multiplies or folds ring elements must dispatch through that law instead of assuming the old negacyclic quotient.

Revision note: created this ExecPlan to turn the “replace the degree-8 fully-splitting ring” idea into a concrete, testable migration with explicit acceptance gates. The immediate trigger was confirming that `GoldilocksFrog` was only a label and therefore not a real de-risking step.
