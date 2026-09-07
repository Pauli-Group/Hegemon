# SMZ9 soundness: the accumulated-support obstruction

## Verdict and scope

The current fixed-oracle `p^-5` theorem cannot be substituted for the DECS extraction term in a complete SMZ9 proof. An accepted-support completion is selected after the matrix challenge; that changes the experiment. The published SmallWood proof explicitly pays for this selection. With the current `N = 2^23`, degree `387`, five matrix rows, and Goldilocks field, its published bound is vacuous. A stronger extraction/correlated-agreement theorem is required before the source's favorable arithmetic can become a soundness claim.

This result is a counterexample to a proposed proof bridge, not an accepted SMZ9 forgery, an attack on SHA-512, or a demonstrated counterfeit. No wire format, dependencies, runtime verifier, registry, or production authority changed.

## The exact published result

Primary source: the [2026-02-13 SmallWood revision](https://eprint.iacr.org/archive/2025/1085/20260213:134127), PDF SHA-256 `3be53ec6655b7c56eda1dfac8fddc6cc0301a5ee078b78001604c92a2d0648fa`, 865,376 bytes. Theorem 1 on page 7 gives

`epsilon_decs = choose(N, d_decs + 2) * epsilon_D + (Q + 1)^2 / 2^(2*lambda + 1)`.

Here `epsilon_D` is the maximum, over a fixed nonzero residual vector `v` and fixed offset `u`, of `Pr[Gamma*v + u = 0]`. A full independent uniform matrix makes this inner probability `p^-eta`. It does not remove the binomial coefficient. Equation 14 on page 25 explicitly retains `epsilon_1 = choose(N, d_decs + 2) / p^eta` under uniform challenge distributions.

The page-8 proof extracts authenticated rows that also satisfy the response equation. This support depends on the challenge and response. If its interpolated data is not degree bounded, a `(d_decs + 2)`-point subset witnesses a nonzero top coefficient. The proof union-bounds over those possible subsets. The paper's Theorem 9 is a classical independent-ROM result; it is not a ready-made quantum-ROM theorem for the current implementation.

For the current constants, `log2(choose(8388608, 389)) = 6155.756873365286` and `log2(choose(8388608, 389) / p^5) = 5835.756873366966`, approximately. Clamping that upper bound to one yields no useful security certificate. These are properties of the published bound, not attack probabilities.

## A fixed-source counterexample to the missing bridge

Use two distinct indices `x0` and `x1` in the actual certified SMZ9 coset. Fix the 140 data rows before sampling the matrix: row zero is the indicator of `x0`, row one is the indicator of `x1`, and all other data and all five masking rows are zero. Fix all five response polynomials to zero as well.

For a uniform `5 x 140` matrix `A`, let `E0` mean that its first column is zero and `E1` that its second column is zero. Select the support as follows:

- On `E0`, select all domain indices except `x1`.
- Otherwise, on `E1`, select all domain indices except `x0`.
- Otherwise, select all domain indices except both exceptional indices.

Every selected row satisfies the zero response. On `E0 union E1`, at least one selected data row is an indicator on a support of size `N - 1`. No degree-387 polynomial can match that row: it would have at least `N - 2` distinct roots and a nonzero value at the exceptional coordinate. In particular, interpolation over that selected support produces a non-codeword completion. The original source and response stayed fixed; the selected support did not.

The exact matrix counts are `|E0| = |E1| = p^695` and `|E0 intersect E1| = p^690`, out of `p^700` matrices. Thus the selected bad-completion event has probability `2*p^-5 - p^-10`, strictly greater than `p^-5`. Authentication consistency does not remove this counterexample: both supports use unchanged rows from one fixed source. This construction concerns the DECS response equations and interpolation only; no proof of all later PIOP/PCS acceptance is supplied.

The owned Lean module `formal/crypto/HegemonCrypto/SmallWoodV8Smz9AccumulatedExtraction.lean` supplies these kernel-checkable components:

- `adaptive_two_candidate_probability_exceeds_fixed_oracle_bound` proves the strict inequality for the actual five-by-140 matrix space. The exact inclusion-exclusion expression above is a separate elementary count, not asserted as that theorem's conclusion.
- `indicator_word_not_degree_bounded_on_large_support` proves the indicator obstruction using the actual coset's injectivity.
- `fixed_source_selected_support_obstruction` joins a fixed 140-row field-valued source, the selected supports, their zero-response agreement for every matrix, the selected non-codeword condition, and the strict probability inequality. It does not construct a successful serialized verifier execution or a measured-Merkle extraction trace.

## A sound bounded-family replacement

`selected_affine_residual_failure_probability_le` proves the useful corrected statement. Fix a finite family of nonzero 140-component residuals and five-component offsets before the matrix is sampled. A selector may then choose any family member after observing the complete matrix. Its selected affine-zero event has probability at most

`card(Candidate) * p^-5`.

The proof derives event inclusion in the fixed-family union and invokes the exact uniform affine-fiber count. It does not assume the desired probability bound. This repairs the quantifier order, but the current extractor has no established suitable fixed-family cardinal bound.

A bound on the number of candidates actually inspected after observing a matrix is insufficient: the candidate-generation rule itself can depend on that matrix. The needed bound is on the pre-challenge family of possible residual/offset pairs, or an alternative sequential argument must prove that each residual is chosen before a fresh independent matrix. Quantum queries and rewinds additionally require a state-disturbance and extraction-work argument; a classical family union does not provide those facts.

As a numerical diagnostic only, the largest integer `L` for which `L*p^-5` is at most the current epsilon4 term `(387)_20/(8388608)_20` is `2,472,498,524`. This does not say that assigning this entire budget preserves the aggregate ledger: all the other terms still add. The unrestricted support family has approximately 6,156 bits of cardinality and is not a viable substitute.

## A stronger, separately researched selection lower envelope

For fixed source rows `X^388` and `X^389`, interpolation on any 389-point support `S` has residual direction `(1, sum(S), 0, ...)`. The second interpolant is `X^389 - product_{s in S}(X - s)`; its degree-388 coefficient is `sum(S)`. Distinct sums give distinct affine matrix events. For `L` such directions, the exact union probability is `L*p^-5 - (L - 1)*p^-10`, since all pairwise intersections are the event that both matrix columns vanish.

In this monomial strengthening, response polynomials are chosen after the matrix and selected support. Unlike the earlier indicator construction, it does not use one fixed zero response. The source rows themselves remain fixed before the matrix.

The [Dias da Silva–Hamidoune restricted-sum theorem](https://londmathsoc.onlinelibrary.wiley.com/doi/abs/10.1112/blms/26.2.140) applies to any subset of the prime field, including this actual multiplicative coset. It gives at least `389*(8388608 - 389) + 1 = 3,263,017,192` distinct 389-subset sums. Consequently this modeled adaptive completion event has a lower envelope approximately `2^-288.396440556`. This source construction and the external restricted-sum theorem are reviewed paper mathematics here, not additional Lean-certified claims.

Adding that replacement-term lower envelope to the unchanged epsilon4 expression already exceeds `2^-288`. This rules out retaining that particular additive 288-bit certificate for these modeled terms. It is not an additive lower bound on real verifier failure: the events may overlap, and full verifier acceptance has not been established. It also does not by itself refute a 128-bit quantum-security claim obtained through some different, proved argument.

The actual multiplicative-coset structure strengthens this beyond 32 bits of amplification. [Cochrane–Pinner, Theorem 2.1, page 3](https://www.math.ksu.edu/~cochrane/research/binsum7.pdf) bounds subgroup additive energy by `(16/3)*N^(5/2)` when `N < p^(2/3)`, as here. Scaling preserves energy, so Cauchy–Schwarz gives `|H+H| >= (3/16)*N^(3/2) > 543*N`; the last strict inequality follows from `2896^2 < N`. Fix `c in H` and discard at most `2*N` sums arising from equal summands or use of `c`. The remaining translated sums have three distinct summands. Because `-H = H`, append 193 disjoint opposite pairs avoiding those summands. This produces 389-element support sums without changing their values. Hence `L >= 541*N + 1 = 4,538,236,929 > 2^32`.

Exact integer comparison gives `L/p^5 - (L-1)/p^10 > 2^-288` already for that conservative integer `L`. Thus the broad support-selected event alone cannot have the current 288-bit bound, even without adding epsilon4. The additive-energy theorem and this strengthening remain separately reviewed primary-source mathematics, not a Lean certificate or a successful verifier attack. A future proof must narrow the event using the actual extractor/acceptance experiment or establish a different sound bound; it cannot merely restate the broad selected-support event with `p^-5`.

## The precise next research target

The next target is a current-parameter, masked/interleaved correlated-agreement extraction theorem, not another deterministic interpolation port. For a fixed source array of 140 data rows and five masks, quantify the probability over the five-by-140 matrix that a degree-387 response has a large agreement set but cannot be explained by a prefix-fixed, extractable family of degree-387 data candidates. The theorem must construct that family or extractor, control its size/work and the agreement threshold, and bind the resulting witness to the exact current PIOP and relation. Its exceptional-matrix loss and its twenty-position sampling loss must be proved in the same experiment.

A theorem at the near-Singleton threshold used by the current `(387)_20/(N)_20` screen has not been supplied. A scalar Reed–Solomon Johnson-range fallback is not numerically close: at agreement fraction approximately `sqrt(387/8388608) = 0.0067922010465`, the twenty-probe term is approximately `2^-144.038102439`. The current `12*Q^2*epsilon` CMS expression at `Q = 2^64` would leave only about 12.45 bits from that term alone. This is a limitation of that fallback certificate, not an attack and not a universal lower bound on all possible extractors.

The inspected better.codes/ArkLib theorem does not discharge this exact 140-data/five-mask, Goldilocks, degree-387 obligation. Its scalar/interleaved statement and numerical MCA assumptions require a fresh parameter and applicability proof; the inspected Johnson-range MCA alternative is admitted upstream and cannot supply an axiom-clean security cone. The existing local accumulated-opening algebra remains useful after a correct sampling/extractor theorem is established, but neither it nor a query-count assumption currently removes the published support-selection loss.

## Verification and authority boundary

Only the two owned soundness files are intended to change in this author phase. The coordinator owns imports, gate integration, review, and commits. Use the existing Lean cache and a direct command with temporary output:

`cd formal/crypto && lake env lean -o /tmp/SmallWoodV8Smz9AccumulatedExtraction.olean HegemonCrypto/SmallWoodV8Smz9AccumulatedExtraction.lean`

A successful kernel check validates only the named definitions and theorems. It does not constitute current-source release evidence, full privacy/soundness, a quantum reduction, or production authorization.
