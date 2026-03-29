# Native Backend Estimator And Reference Split

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, the native backend no longer claims commitment binding from a hand-set `128`-bit constant, and the review package no longer reuses the production backend as its “independent” verifier. A reviewer can inspect one exact estimator-backed commitment claim, rerun the bundled vectors, and see a verifier that recomputes the commitment and fold logic locally instead of delegating to production backend helpers.

## Progress

- [x] (2026-03-28 21:55Z) Confirmed the active backend still used a manual `commitment_bkmsis_target_bits = 128` parameter and the reference verifier still imported `LatticeBackend`, `TxLeafPublicRelation`, and `verify_transaction_proof_bytes_p3`.
- [x] (2026-03-28 22:18Z) Pulled the exact SIS Euclidean estimator formulas from the lattice-estimator reference implementation and mapped the active coefficient-space instance to `n = 592`, `m = 4104`, `q = 18446744069414584321`, `B_2 = 16336`.
- [ ] Replace the manual BK-MSIS target parameter with an estimator-backed concrete claim in `circuits/superneo-backend-lattice/src/lib.rs`, then update `docs/crypto/native_backend_commitment_reduction.md` and the review docs.
- [ ] Split `tools/native-backend-ref` away from production backend and STARK wrapper dependencies, then rerun vectors, tests, and the review package scripts.

## Surprises & Discoveries

- Observation: The standard SIS Euclidean estimator is not remotely close to the previous manual `128`-bit target for the active instance. The coefficient-space instance maps to `d = 4104`, `β = 3267`, which puts even the ADPS16 quantum estimate far above `128` bits.
  Evidence: local reproduction of the lattice-estimator `cost_euclidean` flow on the active instance produced `quantum_bits ≈ 865.755`.

- Observation: The current reference verifier is still a semantic wrapper over production backend code, not just a parser-sharing issue.
  Evidence: `tools/native-backend-ref/src/lib.rs` still called `LatticeBackend::new`, `backend.commit_witness`, `backend.fold_pair`, `backend.verify_fold`, and `verify_transaction_proof_bytes_p3` before this refactor.

## Decision Log

- Decision: Use the standard SIS Euclidean estimator path as the active concrete binding model for the implemented bounded-kernel instance.
  Rationale: The collision reduction already exports an exact Euclidean norm bound `B_2`. Using the lattice-estimator SIS Euclidean route is conservative, standard, reproducible, and does not require the much heavier infinity-norm attack machinery to justify a `>= 128` claim.
  Date/Author: 2026-03-28 / Codex

- Decision: Replace the manual BK-MSIS target parameter entirely rather than leaving it in the manifest as a dead “override”.
  Rationale: The user explicitly asked for the manual target to be replaced, and leaving it in the protocol surface would preserve an unnecessary source of ambiguity.
  Date/Author: 2026-03-28 / Codex

- Decision: Keep the review verifier allowed to share plain data schemas and core transaction AIR/public-input types, but remove production backend, relation, packer, and transaction proof wrapper dependencies.
  Rationale: The main reviewability problem is semantic dependence on the production backend and wrapper verifier logic. Reusing plain data containers is acceptable; reusing the backend algorithm is not.
  Date/Author: 2026-03-28 / Codex

## Outcomes & Retrospective

This section will be updated after the estimator-backed claim and the reference-verifier split land and are validated.

## Context and Orientation

The active native backend lives in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs). That file defines the parameter object `NativeBackendParams`, the exported claim object `NativeSecurityClaim`, the deterministic random-matrix commitment kernel, and the commitment reduction bookkeeping. The current defect is that the active binding floor still comes from the manifest field `commitment_bkmsis_target_bits`, not from a concrete estimator.

The review package verifier lives in [tools/native-backend-ref/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref/src/lib.rs). That file parses bundled vectors and is supposed to be the second implementation a reviewer can trust. The current defect is that it still imports and calls production backend logic for commitment, folding, relation layout, and STARK proof verification wrappers.

The bundle generator and JSON schema live in [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs). Any new claim fields or parameter fields must be mirrored there so the review package stays deterministic.

The active public security story lives in [docs/crypto/native_backend_commitment_reduction.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_commitment_reduction.md), [docs/crypto/native_backend_security_analysis.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_security_analysis.md), and [audits/native-backend-128b](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b). Those files must be updated together so the packaged claim matches the live code.

## Plan of Work

First, replace the current manual commitment target in `circuits/superneo-backend-lattice/src/lib.rs` with a concrete estimator helper. The helper will compute the active coefficient-space SIS instance from the live backend parameters, run the standard Euclidean SIS estimator flow, and export the concrete block size and bit estimates inside `NativeSecurityClaim`. The parameter surface will stop carrying the old manual `commitment_bkmsis_target_bits` knob. The spec label must be bumped because the claim derivation is part of the frozen protocol surface.

Second, mirror the updated parameter and claim fields through the benchmark and review-vector schemas in `circuits/superneo-bench/src/main.rs` and `tools/native-backend-ref/src/lib.rs`. The bundle must continue to round-trip and validate deterministically.

Third, refactor `tools/native-backend-ref/src/lib.rs` so it computes the commitment kernel, leaf proof digest, fold challenges, fold rows, fold proof digest, and transaction STARK verification locally. The verifier should stop importing the production backend, stop importing the production relation/packer, and stop calling the production transaction proof wrapper. It may still use shared plain-data types from `superneo_ccs`, `protocol_versioning`, and `transaction-core` where those are acting as protocol data definitions rather than executable backend logic.

Fourth, regenerate the vectors and review package and update the docs to reflect the new claim path and the reduced verifier coupling.

## Concrete Steps

Run all commands from the repository root `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Implement the estimator-backed claim and schema updates.

       cargo test -p superneo-backend-lattice --lib -- --nocapture
       cargo run -p superneo-bench -- --print-native-security-claim

   The printed claim must show concrete estimator fields instead of the old manual BK-MSIS target.

2. Refactor the reference verifier and re-run the fixed vectors.

       cargo test -p native-backend-ref -- --nocapture
       cargo run -p native-backend-ref -- verify-vectors testdata/native_backend_vectors

   The vector run must report all bundled cases as passing.

3. Rebuild the review package and re-verify it.

       ./scripts/package_native_backend_review.sh
       ./scripts/verify_native_backend_review_package.sh

   The verify script must exit successfully and confirm that the packaged vectors still verify.

## Validation and Acceptance

Acceptance requires all of the following to be true:

1. `cargo run -p superneo-bench -- --print-native-security-claim` prints a claim whose commitment binding floor is computed from an estimator-backed concrete instance and no longer references a manual `commitment_bkmsis_target_bits` input.
2. The active docs and packaged claims explain the estimator route and name the exact attack model used for the concrete binding estimate.
3. `cargo run -p native-backend-ref -- verify-vectors testdata/native_backend_vectors` passes using a reference verifier that no longer imports the production backend or the production transaction proof wrapper.
4. `./scripts/verify_native_backend_review_package.sh` passes on a freshly regenerated package.

## Idempotence and Recovery

The vector emission and package scripts are safe to rerun. If schema or fingerprint changes cause temporary bundle mismatches, regenerate `testdata/native_backend_vectors/bundle.json` before rerunning the reference verifier. If the ref-verifier split breaks parsing, restore deterministic agreement first before touching throughput or product-path code.

## Artifacts and Notes

The key evidence to capture after implementation is:

    cargo run -p superneo-bench -- --print-native-security-claim

showing the estimator-backed commitment fields, and:

    cargo run -p native-backend-ref -- verify-vectors testdata/native_backend_vectors

showing the full vector bundle still clears.

## Interfaces and Dependencies

In `circuits/superneo-backend-lattice/src/lib.rs`, define any new estimator helper structs and helper functions near `NativeSecurityClaim` and `NativeBackendParams::security_claim()`. The claim object must expose the concrete estimator outputs needed for review, not just the final floor.

In `tools/native-backend-ref/src/lib.rs`, define local equivalents of the backend key, ring element, lattice commitment, leaf proof digest, fold proof digest, witness packing logic, and tx-leaf public relation shape. The final verifier path must not call `superneo_backend_lattice::LatticeBackend`, `superneo_hegemon::TxLeafPublicRelation`, `superneo_ring::GoldilocksPayPerBitPacker`, or `transaction_circuit::verify_transaction_proof_bytes_p3`.

Revision note: created on 2026-03-28 to cover the estimator-backed commitment claim replacement and the deeper reference-verifier split requested by the user.
