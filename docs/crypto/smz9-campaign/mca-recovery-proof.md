# Arbitrary-source weighted recovery and a specified decoder

The implementation is `SmallWoodV8Smz9McaRecovery.lean` and
`SmallWoodV8Smz9McaDecoder.lean`. Unlike the earlier piecewise-source theorem,
this result assumes no polynomial patch cover and no small list of candidates.
It is not yet a numerical SMZ9 security certificate or a quantum extractor.

## Exact experiment

Fix all 140 data words and five mask words before the independently uniform
five-by-140 DECS matrix. The response may be any function of that complete
matrix. It has five polynomials of degree at most 387 and is fixed before
the independently uniform twenty-subset of the exact `2^23`-point coset.
Its full agreement set is the set of positions satisfying all five response
equations. No later PIOP challenge or query is supplied to the decoder.

The decoder computes that agreement set, selects its first 388 positions in
canonical index order, interpolates all 145 words, and checks every computed
polynomial on the entire agreement set. It returns none if there are fewer
than 388 positions or a comparison fails. It never searches existentially
over polynomial witnesses or accepts a caller-supplied candidate list.

`code_on_iff_decoded_agreement` proves that this particular interpolation
succeeds exactly when the corresponding bounded codeword exists. A successful
source decoder supplies bounded polynomials agreeing everywhere on that set.
`decoded_response_equals_projection` proves that their matrix projection is
the complete response polynomial, by uniqueness on more than 387 distinct
points. Thus the candidate is fixed before PIOP batching, although it may
depend on the earlier DECS matrix and response.

## Weighted reduction

Reverse the 140 column combinations, always retaining the original final
agreement set. Each intermediate full agreement can enlarge. If the retained
support is large but a source word is unrecoverable, some column has a bad
line event with at least the same query weight.

For each line, maximize the exact `choose(g,20)` query count over every
bounded response at each five-coordinate coefficient, then sum those maxima.
`universalLineBudget` maximizes this finite, unnormalized sum over all possible
prior words and directions. It is a definition of a finite integer, not an
assumption asserting a security bound. Coordinate-fiber counting is valid
because the prefix before column j is independent of that column's coefficient;
the final adversarial response need not have that independence.

The original column-counting bound is

```text
Pr[all 20 queries agree and decoder returns none]
  <= choose(415,20)/choose(2^23,20)
     + 140 * smz9LineBudget / (p^5 * choose(2^23,20)).
```

The checked [random-direction refinement](random-direction-recovery-proof.md)
strengthens the same actual source-decoder event to

```text
Pr[all 20 queries agree and decoder returns none]
  <= choose(415,20)/choose(2^23,20)
     + p/(p-1) * smz9LineBudget / (p^5 * choose(2^23,20)).
```

The numerical research target is
`smz9LineBudget / choose(2^23,20) <= 2^52`. It remains unproved for arbitrary
sources. The separate [weighted MCA research](weighted-mca-research.md)
establishes only specified dimensional ranges and construction exclusions.

## Computation and extraction boundary

The mathematical implementation uses finite noncomputable interfaces. Its
specified interpolation-and-check procedure is polynomial in the supplied
table size, but no extracted executable or running-time theorem is claimed.
A straightforward Horner check alone uses approximately
`145 * 388 * 2^23 = 471943086080` field multiply-add steps; a full 145-word
table occupies 9.0625 GiB if represented as eight-byte field words. These are
algorithmic size estimates, not benchmark results. Faster multipoint evaluation
and precise extraction overhead need separate analysis.

Most importantly, this theorem receives the full table. It does not obtain it
from a coherently queried Merkle commitment or an accepted proof. The raw-oracle
quantum extraction and candidate chronology require their own proof.

## Verification state

The complete generic recovery module passed strict Lean and a central cached
build. The generic decoder, including its response-projection and failure
probability theorems, passed strict Lean with warnings as errors and automatic
implicit variables disabled. Its source-layout adapter,
`SmallWoodV8Smz9McaSourceBinding.lean`, also passes a strict kernel check and
central build, including the exact actual matrix/query failure probability.
The integrated 207-root gate passed, including these endpoints. The
unrestricted numerical line budget and quantum input-table extraction remain
separate. The further auxiliary-direction proof, including its exact
probability/source adapters, has also passed strict Lean and the integrated
237-declaration axiom audit.
No wire, relation, profile, production capability, or retained proof changed.
