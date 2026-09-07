# Current-program indexed privacy-game comparison

The companion module is
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9CurrentPrivacyGame.lean`.
Its strict direct Lean check has passed with `warningAsError=true` and
`autoImplicit=false`. All eleven endpoint axiom audits passed with only
`propext`, `Classical.choice`, and `Quot.sound`. Shared campaign-gate integration
remains coordinator-owned.

## Result and exact boundary

For the actual current-program algebraic state after the randomized-leaf-label
and full-mask-coordinate steps, the module constructs two finite physical
experiments and proves

\[
  |\Pr[G_{\mathrm{source},w}=1]-\Pr[G_{\mathrm{public}}=1]|
  \le \operatorname{hiddenPatchLoss}(q)
  = \frac{4q}{2^{256}}.
\]

The public reference definition has no witness values or inverse source-mask
arguments. Two valid witnesses with the same public parameters and continuation
therefore differ in this phase by at most `2 * hiddenPatchLoss(q)`, or
`8q / 2^256`. The probabilities here are actual nested finite weighted sums of
Born-rule experiments, not caller-supplied probability fields.

This closes the current-program indexed-context/opened-suffix/hidden-table
comparison. It does not establish the earlier honest-hash to randomized-label
QROM transition, its complete multi-invocation accounting, public CSR generator
refinement, or Rust execution of the complete game. In particular the local loss
formula alone is not a blanket PQ128 claim: for example `q = 2^128` gives the
one-witness upper bound `2^-126`, before any other hybrid loss.

## Current-program public context

`currentIndexedContext` consumes `CurrentPublicParameters`, the same full D,T
responses, public batching data and the existing witness/PCS/LVCS opening
coordinates. It calls `currentEagerAlgebraicFields`, not the older generic
`ProductionConstraintExpression` interface. There are no expression-list or
root-list parameters in this path.

The context also retains the actual selected 20 leaf indices and all algebraic
fields. A failed index selector remains `none`. The fallback used to extend the
coordinate map to a bijection affects only a discarded late coordinate; no
conditioning-on-success equality is used.

`current_indexed_context_fresh_tape_law` specializes the checked source
coordinate transport to this current-program context. Its stronger conditional
form explicitly separates uniformly sampled revealed tapes from uniformly
sampled hidden tapes, while preserving any reference generated from the public
context and revealed tapes.

## The source table is not an arbitrary completion

`fullPhysicalSuffix` evaluates all 140 actual physical LVCS row polynomials and
all five recovered DECS mask polynomials at every one of the `2^23` leaf indices.
Unopened positions are not filled from a selected opening or assigned arbitrary
suffixes. `currentSourceSuffix` inserts exactly the current-program recovered
Q and DECS M coins into that all-index definition.

`current_source_suffix_matches_public_opened_suffix` proves the opened-index
equality required by the physical hidden-table comparison. It:

1. Derives the source context's exact indexed physical-view form.
2. Extracts the opening slot from membership in the image of the 20 distinct
   selected indices.
3. Applies the checked actual-source-witness suffix reconstruction theorem.
4. Uses the two exact mask inverses to preserve the original full D,T objects.
5. Reverses the proved public-to-source equality into source-to-public order.

No source-suffix equality premise appears. On selector abort the opened set is
empty, but the source experiment still retains the genuine full programmed
table. Only its public opened-only reference has no retained leaf programs.

## Physical continuation and averaging order

`CurrentContinuationFactory` can inspect the public context and revealed tapes.
It then supplies the complete previous oracle, fixed physical state, normalized
state proof, query steps, query count, final unitary and observation event.
The hidden tape draw occurs afterward. There is no hidden-tape argument to the
reference-state or query-step generator.

The physical table bound is first applied separately to each source-coordinate
and revealed-tape fiber. Only its public-reference side is then transported
through the exact coordinate bijection. A witness-dependent source suffix is
never pushed through an observation that has erased its source coins.

The final averaged theorem uses the already-proved finite mixture inequality;
there is no factor equal to the number of source coins, public contexts, leaves,
or revealed tapes. `queryBound` bounds every query in every generated physical
continuation, including any later honest raw-oracle calls. Final processing
that is represented as a non-query unitary must not conceal additional oracle
queries.

## Remaining explicit premises

- The actual fixed interpreter accepts the source witness at all 64 packing
  assignments. This is not a generic nonlinear-root vanishing premise.
- The public linear weighted values equal the public targets. Binding those
  weights and targets to the exact source public CSR generator is separate.
- PIOP opening points are admissible/nonzero, the selected LVCS block is
  injective, and the packing/interpolation field nodes are nondegenerate.
- The index chooser returns the existing admissible indexed-target subtype or
  failure. Its exact hash/sampler execution is a source-refinement obligation.
- Earlier full-response/public-context generation must be connected using the
  established chronological mask transport and the randomized-label hybrid.
- The old oracle and continuation are fixed before the fresh hidden tapes;
  unchanged previous proof entries are restored by the opened-only oracle.

The theorem does not alter a production capability, release gate, proof carrier,
verifier predicate, randomness source, or runtime code.

Audited endpoints cover abort preservation, both fresh-tape laws, the source
physical-context identity, opened-suffix equality, the coordinate/context
bijection, closed-form loss, public-reference averaging, the physical table
bound, the complete averaged bound, and the two-witness corollary.

Passed direct command from `formal/crypto`:

```sh
lake env lean -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9CurrentPrivacyGame.lean
```
