# Replace The Native Commitment With A Geometry-Derived Binding Floor

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

This plan starts after [`.agent/NATIVE_BACKEND_128B_SECURITY_PACKAGE_EXECPLAN.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/NATIVE_BACKEND_128B_SECURITY_PACKAGE_EXECPLAN.md) completed the security-package pass and made the remaining gap explicit: the active `goldilocks_128b_rewrite` family still reaches `128` claimed bits only through `commitment_assumption_bits = 128`, while the repo’s own conservative bounded-message random-matrix term is `0`. This successor plan exists to kill that contradiction. After this plan, the active native backend family must derive its commitment binding floor from the implemented geometry itself, or the line dies.

## Purpose / Big Picture

After this change, the active native backend will no longer rely on `commitment_assumption_bits` to hit its claimed security floor. A contributor will be able to print the current claim and see a positive, geometry-derived `commitment_random_matrix_bits` term that itself clears the target floor. The observable outcome is simple: the active family’s benchmark JSON, vector bundle, review package, and security-analysis docs must all show a positive structural commitment term, and the code must reject any active family whose geometry would collapse that term back below the claimed level.

## Progress

- [x] (2026-03-28 02:04Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, and `.agent/NATIVE_BACKEND_128B_SECURITY_PACKAGE_EXECPLAN.md` to anchor the successor work in the current `goldilocks_128b_rewrite` state.
- [x] (2026-03-28 02:05Z) Confirmed the exact structural gap from code and docs: `commitment_codomain_bits = 4032`, `commitment_same_seed_search_bits = 36936`, `commitment_random_matrix_bits = 0`, so the active floor still depends on `commitment_assumption_bits = 128`.
- [x] (2026-03-28 02:06Z) Computed the first feasible threshold under the current bounded-message model: with `matrix_cols = 8`, `decomposition_bits = 8`, and `max_commitment_message_ring_elems = 513`, the smallest geometry that yields a nonnegative structural surplus above `128` bits is `matrix_rows = 74`.
- [x] (2026-03-28 03:11Z) Introduced the successor family `goldilocks_128b_structural_commitment`, switched the active default to it, and made the active claim model derive `commitment_binding_bits` from `commitment_random_matrix_bits` instead of `commitment_assumption_bits`.
- [x] (2026-03-28 03:58Z) Regenerated vectors, rebuilt the review package, updated the security docs/audit files, and reran the focused validation set plus the canonical release benchmark around the new active family.

## Surprises & Discoveries

- Observation: increasing `matrix_cols` does not help the current conservative bound.
  Evidence: both `commitment_codomain_bits` and `commitment_same_seed_search_bits` scale linearly with `matrix_cols`, so the sign of the surplus is controlled by `63 * matrix_rows - max_commitment_message_ring_elems * (decomposition_bits + 1)`.

- Observation: the smallest row count that clears the current `128`-bit target is only modestly above the threshold, so choosing the exact minimum leaves little margin for future message-cap growth.
  Evidence: `matrix_rows = 74` yields `360` structural bits, while `matrix_rows = 72` still yields `-648`.

## Decision Log

- Decision: Keep the bounded-message union-bound model as the active first-principles floor for this rewrite instead of inventing a new proof argument mid-turn.
  Rationale: the repository already computes and exposes this model, so replacing the active family with one that satisfies the existing structural criterion is a real improvement instead of another label swap.
  Date/Author: 2026-03-28 / Codex

- Decision: Introduce a new successor family instead of silently mutating `goldilocks_128b_rewrite`.
  Rationale: changing commitment geometry changes the protocol surface, parameter fingerprint, `spec_digest`, artifact sizes, vectors, and benchmarks. It needs a new manifest identity so archived evidence remains honest.
  Date/Author: 2026-03-28 / Codex

## Outcomes & Retrospective

The plan is complete. The active family is now `goldilocks_128b_structural_commitment` with fingerprint `c24ea2de5d61afbe99ccc1befeb7eea3df8ada33965369f22ff220fa377078ef68ce6179a0769e6db2202a989f5eb559` and `spec_digest = 5c11c4456ae0492ecefca5301e1d76816ec55283d9e4b697818f8d0a4d67dc67`. The machine-derived claim now reports `commitment_codomain_bits = 37296`, `commitment_same_seed_search_bits = 36936`, `commitment_random_matrix_bits = 360`, `commitment_binding_bits = 360`, and `soundness_floor_bits = 128`, so the active family no longer depends on `commitment_assumption_bits` for its binding floor. The cost is also explicit: the canonical release benchmark archive [native_tx_leaf_receipt_root_structural_commitment_20260328.json](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/benchmarks/native_tx_leaf_receipt_root_structural_commitment_20260328.json) records a larger byte curve of `22,625..27,561 B/tx`, and the docs now present that trade honestly instead of hiding it.

## Context and Orientation

The active backend implementation lives in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs). That file defines `BackendManifest`, `NativeBackendParams`, `NativeSecurityClaim`, the commitment/opening logic, the fold transcript, and the current first-principles structural bound. The Hegemon-specific artifact layer lives in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs); that file computes artifact size caps and encodes/decodes native `TxLeaf` and `ReceiptRoot` bytes. The benchmark and vector generator live in [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs). The reference verifier and vector consumer live in [tools/native-backend-ref/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref/src/lib.rs). The review package scripts live in [scripts/package_native_backend_review.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/package_native_backend_review.sh) and [scripts/verify_native_backend_review_package.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/verify_native_backend_review_package.sh).

The important current fact is this: the repo models commitment binding conservatively as a bounded-message random linear map. The codomain contributes `63 * matrix_rows * ring_degree` bits. The message search space contributes `max_commitment_message_ring_elems * ring_degree * (decomposition_bits + 1)` bits. The active family currently loses because `8` rows are too few. This plan fixes that by replacing the active geometry with one that makes the same model positive instead of hiding the gap behind `commitment_assumption_bits`.

## Plan of Work

First, add a successor manifest family in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs). Give it a new `family_label`, `spec_label`, and `maturity_label`, and make it the `Default` path. Keep the old `goldilocks_128b_rewrite` constructor in tree as a historical baseline so old archived artifacts still have a precise home. The new family must raise `matrix_rows` high enough that the existing `commitment_random_matrix_bits` model clears the claimed floor with margin. The active family must also stop feeding `commitment_binding_bits` from `commitment_assumption_bits`; instead the claim model must set `commitment_binding_bits = commitment_random_matrix_bits` for the new family and reject any overclaim if that structural term drops below the target.

Second, thread that new family through the artifact layer, benchmark JSON, review vectors, reference verifier, and size-cap helpers. Any field that depends on the parameter fingerprint or `spec_digest` must update automatically once the new family becomes default. The tx-leaf and receipt-root max-size helpers in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) must continue to over-approximate the larger commitment rows so consensus import does not reject valid new-family artifacts.

Third, update the security package and the docs. [docs/crypto/native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md), [docs/crypto/native_backend_security_analysis.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_security_analysis.md), [audits/native-backend-128b/CLAIMS.md](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/CLAIMS.md), [audits/native-backend-128b/KNOWN_GAPS.md](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/KNOWN_GAPS.md), [DESIGN.md](/Users/pldd/Projects/Reflexivity/Hegemon/DESIGN.md), and [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md) must stop describing the active family as assumption-backed on commitment binding if the new geometry succeeds. If the benchmark or verification costs become unacceptable, this plan must say so plainly instead of hiding behind the security improvement.

## Concrete Steps

From the repository root `/Users/pldd/Projects/Reflexivity/Hegemon`, run the work in this order.

1. Implement the successor family and claim-model switch in the backend, then run:

       cargo test -p superneo-backend-lattice

2. Regenerate the vector bundle and rerun the cross-verifier agreement path:

       cargo run -p superneo-bench -- --emit-review-vectors testdata/native_backend_vectors
       cargo run -p native-backend-ref -- verify-vectors testdata/native_backend_vectors
       cargo test -p native-backend-ref -p superneo-hegemon -p superneo-bench

3. Rerun the integration and benchmark surface:

       cargo test -p consensus receipt_root_ -- --nocapture
       cargo test -p hegemon-node receipt_root -- --nocapture
       cargo run -p native-backend-timing --release
       cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128

4. Rebuild and reverify the review package:

       ./scripts/package_native_backend_review.sh
       ./scripts/verify_native_backend_review_package.sh

## Validation and Acceptance

This rewrite is accepted only if all of these are true at the same time:

- the active family’s `commitment_binding_bits` is derived from `commitment_random_matrix_bits`, not from `commitment_assumption_bits`;
- the active family prints a positive structural term that itself clears the claimed floor;
- the vector bundle and review tarball carry the new fingerprint and `spec_digest`;
- the focused backend, reference-verifier, consensus, and node tests all pass;
- the timing harness still passes; and
- the release benchmark still completes so the repo can record the size/performance cost of the new geometry honestly.

If any of those fail, the active family must not be presented as fixed.

## Idempotence and Recovery

The vector bundle and review package are deterministic and safe to regenerate. If the new family changes the parameter fingerprint or `spec_digest` again, regenerate the vectors before rerunning the reference verifier; stale vectors are expected to fail on fingerprint mismatch. If the release benchmark regresses too far, keep the old family as an explicit historical constructor but do not revert the docs silently; record the failure here.

## Artifacts and Notes

The new active benchmark archive must replace the current active evidence at:

- [testdata/native_backend_vectors/bundle.json](/Users/pldd/Projects/Reflexivity/Hegemon/testdata/native_backend_vectors/bundle.json)
- [audits/native-backend-128b/native-backend-128b-review-package.tar.gz](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/native-backend-128b-review-package.tar.gz)
- [audits/native-backend-128b/package.sha256](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/package.sha256)
- [`.agent/benchmarks/native_tx_leaf_receipt_root_structural_commitment_20260328.json`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/benchmarks/native_tx_leaf_receipt_root_structural_commitment_20260328.json)

The claim surface after this rewrite must include:

    "native_security_claim": {
      "claimed_security_bits": 128,
      "commitment_codomain_bits": ...,
      "commitment_same_seed_search_bits": ...,
      "commitment_random_matrix_bits": ...,
      "commitment_binding_bits": ...,
      "soundness_floor_bits": ...,
      "review_state": "candidate_under_review"
    }

and for the active family it must satisfy:

    commitment_binding_bits == commitment_random_matrix_bits

## Interfaces and Dependencies

In [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs), the end state must include one explicit successor constructor for the active family and one explicit switch in `NativeBackendParams::security_claim()` that derives `commitment_binding_bits` from geometry for that family. The benchmark and reference-verifier parameter structs in [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs) and [tools/native-backend-ref/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref/src/lib.rs) must expose enough parameter data to prove which geometry was used to derive the floor.

Change note: this plan was added because the previous security-package plan ended with an honest but still assumption-fed commitment floor. The new work is narrower and harsher: replace that active geometry or admit defeat.
