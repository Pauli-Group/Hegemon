# Current six-opening PIOP reconstruction

This coordinator-owned module follows the complete-security ExecPlan. It
formalizes the polynomial operations in `piop_recompute_transcript` at
`circuits/transaction/src/smallwood_engine.rs:10049`, for the current
SMZ9/profile-6 geometry only.

The serialized proof supplies five rows each of 483 nonlinear high
coefficients and 126 linear high coefficients. Nonlinear restoration uses
six supplied evaluations and produces a polynomial of degree at most 488.
Linear restoration appends a zero evaluation at zero, uses seven
interpolation nodes, and produces a degree-at-most-132 base polynomial.
The verifier then adds a multiple of the normalized polynomial vanishing
at all six opening points. Its nonzero packing-sum divisor follows from
the exact admissibility predicate, not a new rank assumption. This addition
preserves all supplied opening evaluations while imposing the public
batched target sum.

The reconstructed transcript hashes all 489 nonlinear coefficients and
132 nonconstant linear coefficients per repetition. The missing constant
is uniquely recovered from the public target sum; it is not an extra
adversarial free coefficient. `reconstructed_linear_omitted_constant`
connects this source correction to the `ClaimedTranscript` interface used
by the finite PIOP theorem.

`candidateEvaluationTrace` computes the nonlinear quotient-plus-mask and
linear-batch-plus-mask evaluations from the candidate. This definition does
not assert that arbitrary transmitted proof scalars equal those evaluations.
The theorem `reconstructed_candidate_opening_accepts` derives the actual
six-opening equations from executing restoration and correction on this
computed trace. Its current-program specialization uses the generated
decoded nonlinear roots and retained public CSR rows.

## Important chronology boundary

The reconstructed polynomial depends on the opening tuple. Even a false
candidate can reconstruct a polynomial satisfying the equations at those
chosen points. This theorem therefore cannot be substituted for the
pre-opening polynomial commitment required by soundness. The next links are:

- derive the evaluation trace from decoded PCS/LVCS source consistency;
- extract the earlier full transcript hash preimage and identify its
  coefficients with the verifier's reconstructed transcript;
- only then apply the fixed-pre-opening discrepancy bound.

The generic interpolation lemmas reused here are parameterized over field,
support and sample count. No historical five-opening geometry is imported
as a current-profile fact. The degree bounds, six/seven interpolation counts,
483/126 transmitted highs and 489/132 hashed coefficients are constructed
at the current dimensions.

## Verification

Strict checking passed on 2026-09-07 with `-j1 -M3072`, warnings as errors,
and implicit variable creation disabled. Canonical finite-index aliases were
normalized explicitly; no statement or degree bound was weakened. Central
caching and the aggregate principal-axiom audit are the remaining integration
checks; their result is recorded in the complete-security execution plan.
No protocol, proof bytes, generated relation, dependency or production
authority is changed.
