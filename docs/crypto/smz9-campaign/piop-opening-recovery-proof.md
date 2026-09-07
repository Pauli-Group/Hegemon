# Prove source PIOP mask-opening recovery

This ExecPlan follows `.agent/PLANS.md`. It is a bounded, local algebraic component of the SMZ9 privacy campaign, not a complete security proof or release authorization.

## Purpose / Big Picture

The new Lean module derives nonlinear and linear mask evaluations from the chronological PIOP transcript, public constraints/challenges, and six opened witness rows. This closes the algebraic interface needed to reconstruct PCS public combination heads without recovering secret witness polynomials in the public observation.

## Progress

- [x] 2026-09-07: Trace `piop_run`, `piop_recompute_transcript`, and both constraint-evaluation helpers.
- [x] 2026-09-07: Define source-shaped quotient and omitted-constant recovery operations.
- [x] 2026-09-07 15:48 UTC: Compile the independent module against cached Lean dependencies and freeze the verified result.
- [x] 2026-09-07: Check the four central recovery/loop theorems' axiom inventories; each uses only `propext`, `Classical.choice`, and `Quot.sound`.

## Context and Orientation

`circuits/transaction/src/smallwood_engine.rs` constructs the nonlinear batch, removes all 64 packing factors, adds the nonlinear mask, and serializes all 489 coefficients. Its linear branch adds a zero-packing-sum degree-132 mask and serializes only coefficients 1 through 132. The verifier evaluates constraints using opened witness rows. The active Poseidon2 V8 adapter in `smallwood_poseidon2_v8_semantics.rs` returns an empty auxiliary-witness slice and rejects nonempty auxiliary input.

The new file `formal/crypto/HegemonCrypto/SmallWoodV8Smz9PiopOpeningRecovery.lean` is independent of the concurrently developed eager-privacy module. It uses existing polynomial arithmetic and the generic generated arithmetic-program evaluation invariant, not the older PCS geometry.

## Plan of Work

First prove that validity at 64 distinct packing points implies divisibility by their vanishing polynomial. Evaluate the quotient outside that domain and subtract it from the nonlinear transcript. Then reconstruct the omitted linear constant using its public packing sum and prove the linear constraint polynomial evaluates from opened witness rows. Finally check the entire module with the cached Lean toolchain, without building dependencies or modifying shared imports.

## Concrete Steps

Run from `formal/crypto` with the cached `leanprover/lean4:v4.32.2` toolchain:

    lake env lean -DwarningAsError=true -o /private/tmp/smz9-piop-recovery.zB3Ux6/HegemonCrypto/SmallWoodV8Smz9PiopOpeningRecovery.olean HegemonCrypto/SmallWoodV8Smz9PiopOpeningRecovery.lean

The command exited zero with no warnings. The output is a task-local compiled artifact; no shared `.lake/build` output was modified. The final source SHA-256 is `c59a6fc2dfe84879f62d8491f7dc588f470b8639828e8c99b58f2c877fb7bd6f`. The compiled artifact SHA-256 is `6c7acae2c4376c2f3c143731935401b719a63159cea784b3224fca8706c86b2b`. Together the new source, note, and compiled artifact occupy less than 1 MiB. The final free-space check reported 42,423,488 KiB, above the 40 GiB floor.

No Rust build, node launch, network access, shared build output, git operation, or publication is part of this task. The worker output budget is 25 MiB, and checking stops below 40 GiB free space.

## Validation and Acceptance

Lean must accept every theorem without `sorry` or additional axioms. Nonlinear recovery must derive divisibility from valid packing constraints; linear recovery must derive the constant from the public target sum. A successful check establishes these algebraic identities, not implementation equivalence, a runtime randomness distribution, or a quantum-computational bound.

## Surprises & Discoveries

The linear constant is not generally zero: the mask has zero packing sum, while the unmasked linear polynomial has the public batched target sum. Therefore the complete linear transcript constant depends on that target and all 132 published nonconstant coefficients. Outside-packing nonzero denominators suffice for nonlinear recovery; the verifier's extra linear-correction predicate belongs to its interpolation algorithm.

## Decision Log

The module retains explicit validity, degree, and denominator hypotheses, and does not assume the desired honest/simulator distribution equality. The older generated polynomial-program evaluation invariant is reused only as a generic arithmetic interpreter lemma; exact HGV8RP03 specialization and Rust execution are not inferred from it. Root coordinates shared integration.

## Milestones

The first milestone is a checked nonlinear quotient/recovery identity. The second is a checked source linear evaluation and omitted-constant identity. The final milestone is a frozen module with its exact remaining source-specialization obligations documented.

## Idempotence and Recovery

Only the two new task-owned files are changed. Lean checks can be repeated without altering node, wallet, or shared build state. No existing data is deleted.

## Artifacts and Notes

The checked nonlinear chain is `packing_vanishing_dvd_of_valid`, `sequential_packing_removal_matches_quotient`, `nonlinear_quotient_degree`, `source_constraint_sampling_interpolation_exact`, and `recover_nonlinear_mask_opening`. The module also proves the generated arithmetic interpreter's root evaluations and their nonlinear batched recovery formula. The sample-interpolation theorem uses exactly 553 samples and the degree bound 552; monic division lowers that bound to 488.

The checked linear chain constructs all 132 independent mask coefficients, derives the zero packing sum, proves the mask and unmasked-polynomial degree bounds, obtains the public target from valid CSR constraints, reconstructs the omitted coefficient, and concludes `source_linear_coins_recovered_from_opened_rows`. Its mask-zero-sum and transcript-coefficient identities are conclusions of the component lemmas, not assumed honest/simulator output equalities.

Write `Z(r)=product over x=0,...,63 of (r-x)` and let `W(r)` denote the 686 opened witness rows. The source formulas are `Qn(r)=Tn(r)-sum gamma*C(W(r))/Z(r)` and `Ql(r)=Tl(r)-sum_row W_row(r)*sum_lane weight(row,lane)*L_lane(r)`. The omitted linear coefficient is `Tl(0)=(target-sum_packing(high))/64`, where `target=sum gamma*public_linear_target`. Nonlinear validity is essential: the batch must vanish at all packing points before division is exact. Linear witness validity supplies the public target sum. Recovery does not require any further secret witness coordinate once `T`, public challenges/metadata, and `W(r)` are fixed.

The field must have distinct packing points and nonzero 64; nonlinear recovery points must lie outside the packing domain. The verifier additionally needs six distinct nonzero opening points and a nonzero linear-correction factor for its own seven-point interpolation. The recovery formula from all 132 nonconstant transcript coefficients does not divide by that correction factor. It is not a claim that the wire separately transmits all these conceptual transcript coefficients: the source wire retains 483 nonlinear and 126 linear high coefficients and reconstructs the remainder from openings.

## Interfaces and Dependencies

The Lean namespace is `HegemonCrypto.SmallWood.V8Smz9PiopOpeningRecovery`. Principal interfaces are `recoverNonlinearMaskOpening`, `recoverLinearMaskOpening`, `nonlinear_quotient_evaluation`, and `restored_linear_transcript_exact`. Imports are existing frozen polynomial-program, linear-mask, and Mathlib modules. The eager-privacy coordinator can instantiate these identities without introducing an import cycle.

## Outcomes & Retrospective

The independent polynomial recovery component is complete and checked. The active Rust adapter was inspected: it forbids auxiliary witness words, ignores the evaluation point inside the nonlinear relation evaluator, and computes constraints from public values plus the opened witness rows. The prover does need full witness polynomials to construct its original transcript; the proved recovery expressions do not.

Explicit remaining boundary: the reused generic arithmetic-program evaluator has the older expression datatype. The current HGV8RP03 `FieldExpression` language additionally includes inverse, equality selection, and bit extraction. The exact current program must be specialized at public inputs, with witness-independent use of those non-polynomial operations justified, before treating the generic polynomial evaluation theorem as an exact HGV8RP03 execution refinement. The current generated program, degree certificate, native interpolation routine, field arithmetic, coefficient serialization, transcript hash stages, and compressed-proof reconstruction are not automatically refined by the new module. No complete SMZ9 privacy proof, runtime distribution claim, QROM theorem, or production authorization is asserted here.

Revision note: initial bounded source-algebra plan and implementation added on 2026-09-07; updated at 15:48 UTC with final verification evidence and exact source-specialization limits.
