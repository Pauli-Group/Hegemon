# Prove fixed-candidate SMZ9 PIOP soundness

This bounded ExecPlan follows `.agent/PLANS.md`. It records an ideal finite-sampling component, not complete SMZ9 soundness, a Fiat–Shamir/QROM theorem, or production authority.

## Purpose / Big Picture

For a semantically invalid candidate fixed before PIOP batching, derive the two possible acceptance failures: five affine cancellations, or six roots of a nonzero discrepancy selected before the openings. The new module proves the joint bound

    Pr[opening equations accept] ≤ p^-5 + (552)_6 / ((p - 64)_6 - 414*p^5),

where `p = 18446744069414584321` and `(n)_6` is the falling product. The six-point denominator is the correction-aware admissible-set bound, not an unconditioned field-cube denominator.

## Progress

- [x] 2026-09-07: Inspect the source batching, transcript reconstruction, and existing generic finite affine counting theorem.
- [x] 2026-09-07: Derive the public target sum for every adversarial choice of the 132 transmitted nonconstant linear coefficients.
- [x] 2026-09-07: Derive nonlinear and linear discrepancy nonzeroness and degree bounds.
- [x] 2026-09-07 16:01 UTC: Strictly compile the joint `p^-5 + epsilon3` theorem against cached dependencies.
- [x] 2026-09-07 16:03 UTC: Audit five main theorem axiom inventories; each uses only `propext`, `Classical.choice`, and `Quot.sound`.

## Context and Orientation

The implementation is `formal/crypto/HegemonCrypto/SmallWoodV8Smz9PiopSoundness.lean`. It leaves `SmallWoodV8Smz9PiopOpeningRecovery.lean` frozen and does not change runtime code or shared imports.

`smallwood_engine.rs:11929` derives five PIOP coefficient rows with width equal to the larger nonlinear/linear constraint count. The two families use the same row prefix, so the formal model zero-pads both to one generic width. `piop_run` at line 9980 constructs the nonlinear quotient-plus-mask transcript and omits the linear constant. `piop_recompute_transcript` at line 10049 reconstructs nonlinear evaluations from `batch/Z + mask`; its linear branch corrects the polynomial to the public batched target sum before serializing only the nonconstant coefficients. The public CSR linear evaluator and nonlinear program evaluation must separately refine the formal candidate polynomials.

## Plan of Work

First fix a candidate system and all ten candidate masks before a uniform five-row matrix. Reconstruct each claimed linear polynomial from its public batched target and its 132 free high coefficients. Next, outside the affine cancellation event, select a nonzero discrepancy and prove that acceptance requires all six later opening points to be roots. Count that conditional event on `FullAdmissibleOpeningTuple`, then average over the matrix. Finally audit and freeze the independent module.

## Mathematical Contract

`Candidate width` contains fixed nonlinear polynomials of degree at most 552, linear polynomials of degree at most 132, public linear targets, five nonlinear masks of degree at most 488, and five linear masks of degree at most 132. Invalid means at least one nonlinear constraint fails at a packing point, or one linear polynomial has the wrong packing sum. The degree certificates are inputs to this component; source witness-to-constraint degree derivation is a separate interface.

`ClaimedTranscript` contains five claimed nonlinear polynomials of degree at most 488 and five vectors of 132 linear high coefficients. Its strategy type is `Matrix width → ClaimedTranscript`. Thus it can depend arbitrarily on the complete matrix, but not on the later six-point tuple. The candidate itself is not a function of that matrix. `prior_decs_indexed_soundness` explicitly allows the candidate and response strategy to depend on arbitrary earlier DECS state, such as `(A,R)`.

The linear reconstruction is

    TL = C((targetGamma - packingSum(highPolynomial))/64) + highPolynomial.

`claimed_linear_target` proves its packing sum equals `targetGamma` for every high vector. No mask-zero-sum assumption is made: the affine cancellation equation includes the fixed candidate mask sum. This is essential for adversarial recovered candidates.

If all five affine rows hide an invalid fixed system, the generic `PiopExtraction.unsatisfied_affine_batch_failure_probability_le` bounds that event by `p^-5`. That theorem chooses a violated original constraint or linear target before the coefficient matrix. A nonzero residual dot product has one affine fiber of size `p^(width-1)` per row; five independent rows supply the fifth power. No old V4 profile specialization is imported as an SMZ9 premise.

Otherwise one row fails. For a nonlinear failure use

    DNL = Z * (TNL - MNL) - sum_check gamma * C_check.

At the failed packing point it evaluates to the negative batch residual, hence is nonzero. Its degree is at most `64 + 488 = 552`. For a linear failure use

    DL = TL - ML - sum_check gamma * L_check.

Its packing sum is `targetGamma - packingSum(ML) - packingSum(linearBatch)`, which is nonzero by the failed affine equation. Therefore `DL` is nonzero and its degree is at most 132, hence at most 552. The omitted constant cannot be freely chosen to remove this discrepancy.

`discrepancy_of_affine_failure` selects one such polynomial after the matrix and claimed transcript are fixed, but before opening sampling. `OpeningAccepts` requires both discrepancy equations at every one of the five rows and all six points. Therefore its event injects into the all-roots event for the selected polynomial. No independence between the five row discrepancies is assumed and no unnecessary factor of five is introduced.

The imported root-count theorem uses ordered distinct roots and the existing correction-aware admissible-set cardinality lower bound. Its six-point predicate includes the packing-domain, linear-correction, and conservative PCS exclusions represented by `FullAdmissibleOpeningTuple`. This module does not identify the runtime sampler or rejection loop with the uniform law on that set.

Finally `FiniteEvents.jointProbability` counts accepted pairs in the independent uniform matrix/admissible-tuple product. Its equality to the average conditional probability is proved in the reused finite-counting component. Bounding each matrix fiber by its affine-event indicator plus `epsilon3`, and then counting the indicators, yields `invalid_candidate_soundness_probability_le`. This is a union/averaging argument, not multiplication of unrelated failure probabilities.

## Concrete Steps

Run from `formal/crypto` using the existing cached `leanprover/lean4:v4.32.2` toolchain:

    lake env lean -DwarningAsError=true -o /private/tmp/smz9-piop-soundness.lTebCe/HegemonCrypto/SmallWoodV8Smz9PiopSoundness.olean HegemonCrypto/SmallWoodV8Smz9PiopSoundness.lean

The final command exited zero without warnings at 16:05 UTC. The frozen source SHA-256 is `0cc090a3176f7c26c18d0253d9205edce8b08fd9c694f91e7682f28d818814cf`; its independent compiled artifact SHA-256 is `98e77ec77082e18dafcdb857d3bb4acc37b832a00521fa81a8ef3835ca2f88c0`. Scratch output occupies 412 KiB; source and note together occupy 28 KiB. Available space was 42,421,580 KiB, above the 40 GiB floor.

No dependency build, cache fetch, shared `.lake/build` write, git operation, node launch, network access, or publication is part of this task. The bounded lane permits at most 35 MiB of output and one Lean process; stop if available space falls below 40 GiB.

## Validation and Acceptance

Strict Lean checking must exit zero without warnings, `sorry`, or added axioms. The principal theorem must allow arbitrary matrix-dependent claimed transcripts while keeping candidates pre-matrix and discrepancies pre-opening. Both nonlinear and linear failure branches must derive nonzeroness; neither may assume the desired soundness conclusion or omit the linear target constraint. The actual six-point admissible-root theorem must be used with 552, not a historical degree-544/five-opening wrapper.

The five audited declarations are `claimed_linear_target`, `discrepancy_of_affine_failure`, `opening_probability_le_of_affine_failure`, `invalid_candidate_soundness_probability_le`, and `prior_decs_indexed_soundness`. All reported only the standard three axioms. Temporary diagnostic print commands were removed before freezing the source.

## Surprises & Discoveries

Arbitrary candidate linear masks need not have zero packing sum. The cancellation theorem remains valid because their sums are fixed before batching and appear as affine offsets. Restricting the proof to honest zero-sum masks would miss a real recovered-candidate case.

The two constraint families share the same source challenge row, with common width equal to their maximum count. Independence between families is unnecessary: one fixed violated constraint suffices for the five-row cancellation bound.

The linear omitted constant is a security-relevant target binding. It is derived from all published nonconstant coefficients and the public target, not supplied as a free adversarial coefficient or assumed zero.

## Decision Log

Reuse generic affine finite counting only; specialize the polynomial and opening parameters to current SMZ9. Keep source interpreter/degree refinements, compressed-proof reconstruction, and challenge chronology as explicit separate obligations. Do not change runtime guards or previously frozen proof modules in this lane.

## Milestones

The algebraic discrepancy, conditional six-point probability, full matrix/opening product bound, and prior-DECS indexed interface are complete. The final milestone is a reproducible independent artifact and this reviewable limitation record.

## Idempotence and Recovery

Only the two new task-owned files are changed. Repeating the strict command writes only the designated scratch artifact. No existing node, wallet, retained proof, or unrelated worktree data is changed or deleted.

## Interfaces and Dependencies

The namespace is `HegemonCrypto.SmallWood.V8Smz9PiopSoundness`. Integrators construct a `Candidate`, establish invalidity of `candidate.system`, and provide a pre-opening `Matrix width → ClaimedTranscript`. The final result is `invalid_candidate_soundness_probability_le`; `prior_decs_indexed_soundness` is its pointwise chronological form.

Imports are the frozen PIOP recovery module, current admissible-root counting, generic PIOP extraction, and finite product counting. The module does not import a concurrently changing active-program-polynomial file or introduce a shared import cycle.

## Outcomes & Retrospective

This closes the requested fixed-candidate PIOP finite-soundness component. It does not yet show that an accepted Rust proof gives the formal opening equations for one previously fixed candidate and transcript. In particular, commitment/DECS extraction must produce a pre-PIOP candidate; exact HGV8RP03 and CSR specialization must produce its polynomials and bounds; compressed-proof reconstruction and transcript binding must establish the claimed polynomial chronology; and a separate interactive-to-Fiat–Shamir/QROM argument must account for adversarial oracle queries, list sizes, and adaptive selection. These are not assumptions discharged by successful Lean compilation here.

Revision note: bounded independent component added and verified on 2026-09-07.
