# Factor-free arbitrary-source recovery

The checked module is
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9RandomDirectionRecovery.lean`.
It strengthens the original [source decoder bound](mca-recovery-proof.md) for
the same source table, same arbitrary response, same decoder and same exact
twenty-subset. No protocol or challenge distribution changes.

## Result

Put `p = 18446744069414584321` and
`B = smz9LineBudget / choose(2^23,20)`. The actual source-layout failure event
satisfies

```text
Pr[all 20 queries accept and the computed source decoder returns none]
  <= choose(415,20) / choose(2^23,20) + p/(p-1) * B/p^5.
```

The earlier factor `140` is absent. `smz9LineBudget` remains the defined finite
maximum over arbitrary prior words, arbitrary scalar directions and all
bounded five-polynomial responses. This theorem does not prove `B <= 2^52`
or another numerical upper bound on that maximum.

## Auxiliary direction and fixed-support detection

Fix the complete matrix, response and its full agreement set `G` first. If
`|G| >= 416` and recovery fails, at least one data column is not a degree-387
codeword on `G`. Otherwise every data column is coded there, and subtracting
its coded matrix combination from the coded response recovers every mask.
This implication is proved using the actual code submodule.

Now draw an independent proof-only direction `v` over all 140 base-field
coordinates, and form `V_v = sum_j v_j W_j`. On a fiber in a non-codeword
column, at most one scalar makes `V_v` coded on this already-fixed `G`: two
such scalars would recover that column by subtracting their polynomials and
dividing by their nonzero difference. Consequently, a uniformly averaged
direction detects failure with probability at least `1 - 1/p`.

The direction is sampled only in the counting proof. It is not another
Fiat–Shamir challenge, an extractor input, a change to the source, or a claim
that the adversarial response is independent of the original matrix.

## One line after a bijective matrix shear

Fix a nonzero direction and choose one of its nonzero coordinates as pivot.
There is an explicit invertible shear from a new coefficient matrix `C` to
the original matrix `A`:

```text
A_pivot = C_pivot * v_pivot
A_i     = C_i + C_pivot * v_i, for i != pivot.
```

The five pivot coefficients remain uniformly distributed and independent of
all other new columns. The original source mixture becomes exactly a prior
word plus those five coefficients times `V_v`. The prior is independent of
the pivot coefficients. The response may still depend arbitrarily on the
whole original matrix, because the line budget maximizes over every response
separately at every coefficient.

The zero direction contributes zero detected weight. Summing the line bound
over all directions and summing the detection inequality over all matrices
gives

```text
(p-1) * p^5 * sum_A largeFailureWeight(A)
  <= numberOfMatrices * p * smz9LineBudget.
```

Small supports contribute at most `choose(415,20)` each. Division by the
exact coefficient/subset product cardinality gives the stated probability.
The source-layout adapter uses the already-checked matrix transpose
equivalence, exact accepted-query/subset equivalence, and exact computed
decoder-failure criterion. Thus no new ideal event replaces the old one.

## Verification and boundary

The complete file, including the final
`source_decoder_failure_probability_factor_free`, passed

```sh
cd formal/crypto
lake env lean -DwarningAsError=true -DautoImplicit=false \
  HegemonCrypto/SmallWoodV8Smz9RandomDirectionRecovery.lean
```

The coordinator's integrated gate passed with 237 audited declarations,
including the five selected endpoints from this module. The unrestricted
finite line-budget inequality, coherent
extraction of the input source table, PIOP composition, full semantic adequacy,
raw-oracle transfer and compiled verifier refinement remain independent
obligations. Removing a reduction loss does not prove those obligations.
