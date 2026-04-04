# Native Backend Formal Theorems And Claim Realignment

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, the native backend will stop relying on the ad hoc `floor(challenge_bits * fold_challenge_count / 2)` transcript term. Instead, the repository will carry a theorem-grade note for the exact `GoldilocksFrog` fold schedule, an exact collision-to-BK-MSIS reduction for the live deterministic commitment class, an explicit zero-loss flattening argument to coefficient-space SIS, and a concrete security calculation written as math instead of only as code. A reviewer will be able to read one theorem note, see the corresponding claim-model updates in the code and docs, and rerun the native backend tests to confirm the exported claim matches the new derivation.

## Progress

- [x] (2026-04-03 16:33Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, `docs/crypto/native_backend_spec.md`, `docs/crypto/native_backend_commitment_reduction.md`, and `docs/crypto/native_backend_security_analysis.md`.
- [x] (2026-04-03 16:54Z) Established the key algebraic fact for the active quotient: `q ≡ 1 (mod 3)`, so `X^54 + X^27 + 1` factors as `(X^27 - ω)(X^27 - ω^2)`, but every nonzero polynomial of degree `< 27` is still a unit mod the quotient.
- [x] (2026-04-03 17:07Z) Computed the exact live `TxLeafPublicRelation` public-witness size from the current schema: `4935` bits, `617` base-256 digits, and `12` ring elements. This is tighter than the conservative manifest cap `M = 76`.
- [x] (2026-04-03 20:11Z) Wrote `docs/crypto/native_backend_formal_theorems.md`, proving the active frog-ring lemmas, the exact five-challenge tuple law, the deterministic-commitment collision reduction, the zero-loss flattening step, and the explicit conservative security arithmetic.
- [x] (2026-04-03 20:18Z) Updated `native_backend_commitment_reduction.md`, `native_backend_security_analysis.md`, `native_backend_attack_worksheet.md`, `audits/native-backend-128b/CLAIMS.md`, and `KNOWN_GAPS.md` to point at the theorem note and remove the stale `513` / `592` / `360` / `/2` leftovers.
- [x] (2026-04-03 20:22Z) Realigned `NativeSecurityClaim` and its tests with the theorem-backed challenge-tuple min-entropy term, replacing the old `floor(k * b / 2)` cap with the exact active value `312`.
- [x] (2026-04-03 20:57Z) Updated the in-repo claim summary and reran the native backend tests. `cargo test -p superneo-backend-lattice --lib -- --nocapture` passed with `20` tests. `cargo test -p superneo-hegemon native_receipt_root_rejects_tampered_fold_rows -- --nocapture` passed in `120.19s`.
- [x] (2026-04-03 21:07Z) Rebuilt and reverified the external review package so the packaged tarball now matches the theorem note and revised claim docs. `./scripts/package_native_backend_review.sh` completed and rotated `package.sha256`. `./scripts/verify_native_backend_review_package.sh` passed on all `11` bundled vectors.

## Surprises & Discoveries

- Observation: the active frog quotient is not a domain because `q ≡ 1 (mod 3)` and `X^54 + X^27 + 1 = (X^27 - ω)(X^27 - ω^2)` over `F_q`.
  Evidence: `18446744069414584321 mod 3 = 1`, so primitive cube roots of unity exist in Goldilocks.

- Observation: the exact live public witness is much smaller than the manifest cap used in the conservative security estimate.
  Evidence: the `TxLeafPublicRelation` schema currently totals `4935` witness bits, which means `617` digits and `12` ring elements at `digit_bits = 8` and `ring_degree = 54`.

- Observation: the earlier “every degree-`<27` polynomial is a unit” argument needs the irreducibility of `X^27 - ω` and `X^27 - ω^2`; the bare factorization of `X^54 + X^27 + 1` is not enough by itself.
  Evidence: a degree argument alone would fail if either degree-27 factor split further. The correct proof route uses primitive `81`st roots and `ord_81(q) = 27`, which forces both factors to be irreducible over `F_q`.

## Decision Log

- Decision: keep the conservative `M = 76` flattened instance in the claim model while explicitly documenting the tighter exact live `TxLeafPublicRelation` length.
  Rationale: the conservative cap is the manifest-owned code surface and matches the current estimator machinery, while the theorem note can still prove that the shipped public relation occupies a strict sub-class with length `12`.
  Date/Author: 2026-04-03 / Codex

- Decision: replace the `/2` transcript cap with a theorem-backed challenge-schedule term derived from the exact reduction rule’s tuple min-entropy, while documenting separately that the fold verifier itself is a deterministic canonicalization check rather than a CCS soundness protocol.
  Rationale: this preserves a machine-checkable quantitative term without pretending the current fold layer implements a random-linear-combination CCS soundness proof.
  Date/Author: 2026-04-03 / Codex

## Outcomes & Retrospective

The theorem work landed as a repo-native proof package rather than another hand-wavy analysis note. The active backend now carries an explicit theorem note for the exact GoldilocksFrog algebra, the exact indexed five-challenge reduction rule, the deterministic-commitment collision reduction, the zero-loss flattening map, and the concrete conservative estimator arithmetic. The exported `NativeSecurityClaim` no longer uses the blanket `/2` transcript rule; it now reports the theorem-backed challenge-tuple term `312`, giving `soundness_floor_bits = 305` for the active conservative manifest.

The main caution is conceptual, not mechanical: the fold layer is still not a Neo/SuperNeo CCS soundness protocol. The theorem note makes that explicit and only claims what the code actually implements, namely deterministic canonicalization plus the exact random-oracle challenge law. That is a stronger and cleaner repository state than the earlier heuristic cap, but it still leaves external cryptanalysis of the chosen coefficient-space attack model as an open review item.

## Context and Orientation

The active native backend lives in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs). That file defines the active parameter object `NativeBackendParams`, the exported review object `NativeSecurityClaim`, the exact fold-challenge derivation, the commitment kernel, and the current Euclidean SIS estimator. The Hegemon-specific live product path is in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs), where tx-leaf artifacts are built from public tx data plus serialized STARK public inputs and then verified by replaying the embedded STARK proof and reconstructing the deterministic commitment.

In this repository, “BK-MSIS” means the bounded-kernel Module-SIS collision problem induced by the deterministic commitment matrix over the active ring. “Flattening” means mapping a ring/module equation over `R_q = F_q[X] / (X^54 + X^27 + 1)` into an ordinary coefficient-space linear equation over `F_q`. “Challenge schedule” means the five challenge values the fold verifier derives from the exact transcript bytes listed in [docs/crypto/native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md).

The current bug is not an implementation crash. The bug is mathematical and documentary: the repo still reports a theorem-less `/2` transcript term and still leaves the reduction/flattening story partly implicit. This plan closes that gap.

## Plan of Work

First, add a new theorem note under `docs/crypto/` that states and proves the active frog-ring lemmas and the exact theorems needed for review: the low-degree unit lemma for the active challenge subspace, the uniqueness/canonicality theorem for accepted fold proofs, the collision-to-BK-MSIS reduction, the flattening theorem from ring/module BK-MSIS to coefficient-space Euclidean SIS, and the concrete attack-cost calculation for the conservative active instance. This note must define the exact game being bounded; it must not use “soundness” loosely.

Second, rewrite [docs/crypto/native_backend_commitment_reduction.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_commitment_reduction.md) and [docs/crypto/native_backend_security_analysis.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_security_analysis.md) to point at that theorem note, correct the stale `513` / `592` / `360` leftovers, record the exact live `TxLeafPublicRelation` size, and explain the conservative zero-padding to `M = 76`.

Third, update `NativeSecurityClaim` in `circuits/superneo-backend-lattice/src/lib.rs` so the reported challenge-schedule term matches the theorem-backed value instead of `floor(k*b/2)`. Keep the public shape stable if possible, but ensure the meaning documented in the theorem note matches what the code now prints and validates.

Finally, update the packaged claim summary under `audits/native-backend-128b/CLAIMS.md` and rerun the native backend tests so the theorem note, the claim docs, and the code all agree.

## Concrete Steps

Work from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

Implement and validate with:

    cargo test -p superneo-backend-lattice --lib -- --nocapture
    cargo test -p superneo-backend-lattice structural_128b_security_claim_matches_current_floor -- --nocapture
    cargo test -p superneo-backend-lattice validate_rejects_security_target_above_soundness_floor -- --nocapture

If any claim-shape changes affect the reference-verifier or bench structs, rerun:

    cargo test -p native-backend-ref -- --nocapture
    cargo test -p superneo-bench -- --nocapture

Acceptance is the theorem note landing, the reduction/security docs aligning with it, and the code-exported claim matching the new theorem-backed values.

## Validation and Acceptance

This work is accepted when all of the following are true:

1. The repository contains one self-contained theorem note that proves the four requested items against the exact active code surface.
2. The stale contradictory numbers in the native backend crypto docs are removed.
3. The exported `NativeSecurityClaim` no longer derives its challenge-schedule term from `floor(challenge_bits * fold_challenge_count / 2)`.
4. The native backend unit tests pass with the revised claim numbers.

## Idempotence and Recovery

These edits are source-only and safe to rerun. If the theorem work shows the current quantitative claim should weaken rather than strengthen, keep the weaker result and update the docs and tests together; do not preserve a larger number for compatibility. If a claim-model refactor grows too large, keep the theorem note and doc corrections and record the remaining code-alignment work in this ExecPlan before stopping.

## Artifacts and Notes

Capture these exact outputs after the claim-model update:

    cargo test -p superneo-backend-lattice structural_128b_security_claim_matches_current_floor -- --nocapture
    cargo test -p superneo-backend-lattice validate_rejects_security_target_above_soundness_floor -- --nocapture

Also record the final theorem-backed challenge-schedule term and final floor in the theorem note and in `audits/native-backend-128b/CLAIMS.md`.

## Interfaces and Dependencies

The final repository state must keep these code surfaces usable:

- `superneo_backend_lattice::NativeSecurityClaim`
- `superneo_backend_lattice::NativeBackendParams::security_claim`
- `docs/crypto/native_backend_commitment_reduction.md`
- `docs/crypto/native_backend_security_analysis.md`
- `audits/native-backend-128b/CLAIMS.md`

If the meaning of an exported field changes, the prose in the theorem note and security-analysis doc must state the new meaning explicitly.

Revision note (2026-04-03 / Codex): created this ExecPlan because replacing a heuristic claim term with theorem-backed math changes the review package, the exported claim model, and the meaning of the shipped security analysis. This qualifies as a significant cross-cutting proof-surface change under `.agent/PLANS.md`.
