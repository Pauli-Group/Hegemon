# Current-program PIOP adapter

Status: **strict Lean check passed**, with `warningAsError=true` and
`autoImplicit=false`. All eight audited endpoints depend only on `propext`,
`Classical.choice`, and `Quot.sound`. The earlier temporary disk-reserve pause
was lifted explicitly by the user; this adapter was then checked against the
coordinator-cached current-program module. No runtime or acceptance rule changed.

The artifact is
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9CurrentProgramPiop.lean`.
It does not modify the earlier frozen eager-simulator or PIOP-recovery modules.

## Why this adapter is necessary

The earlier `PublicPiopParameters` exposes a list of
`ProductionConstraintExpression` and arbitrary root indices. That older grammar
is not the actual current `FieldExpression` program. Consequently its eager
output theorem could not establish a current-program source claim.

The new `CurrentPublicParameters` has public words, five nonlinear batching
vectors, public linear weights and public linear targets. It has no expression
list, root list, witness, mask or supplied mask-opening callback. Its nonlinear
definitions directly call `V8Smz9ProgramPolynomials.constraintPolynomials` and
`constraintOpenings`, which fix the actual 8,271 expressions and 830 roots.

Those definitions include the actual inverse, bit and equality-selector
instructions. Their polynomial interpretation is justified by the checked
safe-operation/degree certificate in the imported module; it is not a generic
claim that inverse and bit extraction commute with polynomial evaluation.

## Checked bridge endpoints

The new file supplies the following checked proof terms:

- `current_constraint_evaluation` extends the 686 witness polynomials with zero
  outside their range and applies actual-program evaluation commutation.
- `current_constraint_degree` and `current_nonlinear_batch_degree` derive the
  552 degree bound from witness degree at most 69. There is no caller-supplied
  nonlinear degree premise.
- `accepted_current_packing_constraints_vanish` specializes actual successful
  interpreter acceptance at each of the 64 packing assignments to vanishing of
  all 830 constraint polynomials. The explicit row-opening premise binds those
  assignments to the given polynomials.
- `current_public_mask_openings_match_source_masks` reconstructs each nonlinear
  mask opening as transcript evaluation minus the actual batched constraint
  opening divided by the 64-factor packing polynomial. Distinct packing points,
  outside opening points and source validity provide divisibility/nonzero
  denominators. The linear half uses the public target to restore the omitted
  constant before subtracting the public-weighted witness expression.
- `current_response_is_affine_mask_map` and
  `current_recovered_masks_reproduce_full_transcript` instantiate the exact
  translation `T = F_current(W) + Q` and inverse `Q = T - F_current(W)`.
- `current_program_eager_algebraic_output_law` uses that inverse in the actual
  corrected cross-column PCS geometry and 70-by-736 physical head reshape. Its
  right side has only public parameters, the existing full responses and fresh
  opening coordinates. The optional target-selection abort remains in the law.

All high coefficient fields continue to come from the same full `D,T`
responses through the existing `eagerAlgebraicFields`; they are not resampled.
The inverse Q depends on W, not on later PCS or LVCS tail coins.

## Remaining obligations and claim boundary

These are checked local theorem results, not an end-to-end privacy proof. In particular:

- Coordinator-owned cache and campaign-gate integration remain separate from
  the successful direct source check and eight-endpoint axiom audit.
- The checked `CurrentProgramOpeningBinding` companion now binds source witness
  interpolation to the exact 64 packing assignments and derives the physical
  column-degree and opened raw-suffix equalities. Its source specialization
  retains actual interpreter acceptance and public linear weighted-value
  validity. Bind the public linear weight/target parameters to the exact
  current public CSR transcript generation.
- Instantiate those proved suffix equalities at the actual indexed target
  context required by the eager oracle-game comparison. The algebraic
  output-law statement alone does not discharge that context integration.
- Specialize the currently older-parameter oracle-game constructor to
  `CurrentPublicParameters`, preserving the independent hidden tapes, prior
  oracle state, sampled indices, salt, fixed labels and aborts.
- Preserve the independent quantum hybrid, finite-sampler and Rust execution
  obligations. No capability flag, production authorization, security level,
  carrier, runtime or verifier acceptance rule is changed by this file.

Verification command, passed:

```sh
lake env lean -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9CurrentProgramPiop.lean
```

Run from `formal/crypto` using the coordinator-cached imports. The axiom audit
covered current constraint evaluation, constraint degree, batch degree,
accepted packing vanishing, public mask recovery, the affine mask map, the
recovered-transcript identity, and the current-program eager output law.
