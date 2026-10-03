# SMZ9 joint large-agreement extraction research

Date: 2026-09-07. Status: finite-field paper derivations, not an end-to-end security theorem. This document changes no protocol, carrier, runtime, dependency, registry, or release authority. The author performed no builds or Git operations. The coordinator owns independent review, formalization, and integration.

## Concrete progress and remaining obstruction

Two useful conclusions follow from the full five-row matrix experiment, without replacing it by a scalar challenge:

1. **High local residual rank is quantitatively suppressible.** A double-counting argument bounds large agreement, and a stronger version charges the twenty openings in the same experiment. For example, splitting at 416 agreeing positions bounds the joint rank-at-least-20 branch by approximately `2^-290.70615`; the at-most-415-position sampling branch is approximately `2^-286.73172`. The remaining large-agreement branch has local residual rank 1 through 19.
2. **Small global residual dimension has a constructive decoder.** When all data and mask words together have dimension at most five modulo degree-387 polynomials, an injective projected matrix gives an explicit common polynomial tuple. Its matrix-rank exception has an exact formula, including mask-only directions. No prefix-fixed candidate list is needed for this case.

Neither result proves that the arbitrary committed source falls into the second case. A source of global residual dimension 140 can have very large agreement of residual rank one. Closing that low-local-rank/high-global-rank branch, with robust witness extraction and the joint sampling loss, remains the central unresolved theorem. The numerical bounds below cannot be credited after silently discarding it.

The fixed profile is imported from the source-owned [SMZ9 accounting definitions](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9QromAccounting.lean#L27-L137) and [runtime profile](../../../circuits/transaction/src/smallwood_engine.rs#L240-L252). The [published SmallWood theorem](https://eprint.iacr.org/archive/2025/1085/20260213:134127), Theorem 1 and Equation (14), is background for the missing extraction term; the deductions here do not claim to be its theorem or an established replacement reduction.

## Exact finite experiment

Let `F` be Goldilocks, `p = 2^64 - 2^32 + 1`, and let `D` be the fixed set of `N = 2^23` distinct evaluation points. Put `k = 388`, so `C_S` denotes the restrictions to `S` of polynomials of degree `< k`.

Before the matrix challenge, fix arbitrary functions

`W : D -> F^140`, and `M : D -> F^5`.

Sample `A` uniformly in `F^(5 x 140)`. An arbitrary selector, after seeing all of `A`, chooses a vector `R` of five degree-`< k` polynomials. Set

`G(A,R) = {x in D : A W(x) + M(x) = R(x)}`.

Only afterwards sample a uniform twenty-element subset `J` of `D`, independently of `A` and the response-selection randomness. The ideal DECS equations accept exactly when `J` is contained in `G`. Thus, conditionally on the already chosen `G` of size `g`,

`Pr[J subset G | A,R] = choose(g,20)/choose(N,20)`.

Every statement below allows adaptive `R`; none requires it to have been fixed before `A`. The transcript-to-this-experiment refinement, bounded sampler behavior, coherent oracle queries, authentication, and subsequent PIOP/semantic extraction remain separate obligations. In particular, `A` is genuinely uniform here, not an unproved replacement for the raw oracle's expanded outputs.

## Fixed-support affine rank, with masks included

For a fixed support `S` of at least `k` points, take the images of the 140 data words in the quotient vector space `F^S / C_S`. Let

`L_S : F^140 -> F^S/C_S`, `a |-> sum_j a_j [W_j|S]`,

and let `r_S` be its rank. A matrix row `a_i` can have a degree-`< k` response on `S` exactly when

`L_S(a_i) = -[M_i|S]`.

If the right side is outside the image, this event is impossible. Otherwise its solutions form one affine coset of `ker L_S`, of size `p^(140-r_S)`. The five independently sampled rows therefore give

`Pr_A[all five projected words are in C_S] <= p^(-5*r_S)`,

with equality when all five offsets are consistent. This is a statement about existence of a response on a fixed support, so it already accounts for the response being chosen after `A`.

If `r_S=0` and the response equations hold on `S`, the masks also lie in `C_S`. All 145 restricted source words are then represented by one common degree-bounded tuple. For `|S|>=k`, interpolate the tuple from any `k` positions and verify it on `S`. This does not assert that the source is globally degree bounded.

## High-rank incidence theorem

Use augmented data columns

`v_x = (1,x,...,x^(k-1),W_1(x),...,W_140(x))`.

Every `k` distinct columns are independent by their Vandermonde prefix. On a support `S` with at least `k` points, their rank is `k+r_S`.

Fix `1 <= r <= 140`. Call a `(k+r)`-element subset `I` a basis witness when its augmented data columns are independent. Let `B_I(A)` be the event that all five words `A W+M`, restricted to `I`, lie in `C_I`. The fixed-support calculation gives `Pr[B_I] <= p^(-5r)`. Define the concrete nonnegative integer

`X(A) = number of basis witnesses I for which B_I(A) holds`.

Then

`E[X] <= choose(N,k+r) * p^(-5r)`.

Now suppose the chosen agreement support `G` has `g` points and `r_G >= r`. Every `k`-subset of `G` can be extended inside `G` to a basis witness of size `k+r`. Counting incidences between such `k`-subsets and witnesses gives

`choose(g,k) <= X(A) * choose(k+r,k)`.

There is no uniqueness assumption: each `k`-subset has at least one extension, and any witness contains at most `choose(k+r,k)` such subsets. Each witness inside `G` satisfies `B_I(A)` by the actual response equations.

For `a >= k`, it follows that

`Pr[g >= a and r_G >= r] <= F_r(a)`,

`F_r(a) = choose(N,k)*choose(N-k,r) / (choose(a,k)*p^(5r))`.

One may take the minimum with `1` and the simpler existence bound `choose(N,k+r)/p^(5r)`. The high-rank event itself requires `g >= k+r`, so `a` can be replaced by `max(a,k+r)` in this branch. This matters when a chosen split is very close to `k`.

### Stronger joint opening bound

For `t=20 <= k`, the ratio `choose(g,t)/choose(g,k)` is nonincreasing for `g>=k`. Therefore the same pointwise witness count, before taking expectation, proves

`Pr[J subset G, g>=a, r_G>=r] <= F_r(a)*choose(a,20)/choose(N,20)`.

This is not multiplication of independent events. Both factors arise from the same realized agreement support, using the decreasing ratio above. More explicitly, on this branch,

`choose(g,20)/choose(N,20)`

`<= X(A)*choose(k+r,k)*choose(a,20)/(choose(a,k)*choose(N,20))`.

Taking expectation proves the claim. The expression remains valid if it exceeds one, but must then be capped or combined with other bounds. A proof that chooses `G` only after seeing `J` is outside this theorem.

### Current numerical splits

The following are floating-log diagnostics of exact rational expressions, not independent security receipts. The small branch is `choose(a-1,20)/choose(N,20)`. The joint high-rank column uses the formula at the displayed `a` without the optional `max(a,k+r)` improvement.

| Split `a` | High-rank cutoff `r` | Small-agreement bits | Joint high-rank bits | Unresolved large-agreement ranks |
| ---: | ---: | ---: | ---: | --- |
| 400 | 21 | 287.893540 | 523.580571 | 1 through 20 |
| 416 | 20 | 286.731723 | 290.706150 | 1 through 19 |
| 448 | 20 | 284.539690 | 394.529856 | 1 through 19 |
| 768 | 18 | 268.698762 | 288.630149 | 1 through 17 |
| 1024 | 18 | 260.297827 | 492.375290 | 1 through 17 |

For example, at `(a,r)=(416,20)`, the sum of the two proved branch bounds is approximately `2^-286.64`. This does not bound total failure: the large-agreement rank-1-through-19 branch is absent from that sum. The decomposition concerns DECS consistency/extraction, not the remaining PIOP terms or a quantum lifting coefficient.

## Constructive decoder when the global quotient dimension is small

This is a separate positive case, suggested in the coordinator's independent derivation. It is not an assumption that the local rank bound implies a global one.

Take the global quotient `F^D / C_D` of all 145 source words, and let their span have dimension `z`. Choose a basis of quotient classes, represented by functions `U_1,...,U_z`. By linear algebra there are degree-`< k` polynomial vectors `P` and `H`, and constant matrices `B` and `C`, such that

`W(x) = P(x) + B U(x)`, `M(x) = H(x) + C U(x)`,

where `B` has shape `140 x z`, `C` has shape `5 x z`, and the stacked matrix `[B;C]` has column rank `z`. These objects are constructed from the fixed full source before `A`; their existence follows from the quotient-basis construction rather than being a claimed transcript equality.

Put `E = A B + C`. Suppose `E` is injective, choose a left inverse `L`, and define the polynomial vector

`U_star = L*(R - A P - H)`.

On every point of `G`, `U_star(x)=U(x)`. If `|G|>=k`, the degree-`< k` vector polynomial

`E U_star - (R - A P - H)`

has at least `k` roots and is identically zero. Hence

`Q_data = P + B U_star`, `Q_mask = H + C U_star`

is an explicit common degree-bounded tuple that agrees with all source rows on `G` and satisfies `A Q_data+Q_mask=R` as a polynomial identity. Gaussian elimination, interpolation, and a left inverse give a finite-field algorithm from the full source, `A`, and `R`. No prefix candidate-list enumeration or global equality `W=Q` is required. This still does not construct the full source from accepted Merkle openings or prove the resulting tuple satisfies the HGV8RP03 program.

### Exact rank exception, including mask-only directions

Let `r_B = rank B` and `s=z-r_B`. On `ker B`, `E` equals `C`, which is injective because `[B;C]` has full column rank. Its image has dimension `s`. Quotienting that fixed image out of the five-dimensional codomain leaves a uniform matrix of shape `(5-s) x r_B`: on a complement of `ker B`, uniform `A` times the injective data-coefficient map is uniform, and adding the fixed mask map preserves uniformity.

For `z<=5`, the exact probability that `E` is not injective is consequently

`delta_global = 1 - product_{i=0}^{r_B-1}(1-p^(i-(5-s)))`.

If `r_B=0`, the empty product is one and the exception is zero. If there are no mask-only directions, this reduces to `1-product_{i=0}^{z-1}(1-p^(i-5))`. For positive `r_B`, its leading scale is `p^(-(6-z))`: roughly 320 bits for `z=1`, 256 for `z=2`, 192 for `z=3`, and so on. This is the exact singularity-event probability, not a claim that every singular matrix yields an accepted false proof. Joint agreement/opening analysis can be stronger.

For arbitrary sources with `z>5`, `E` cannot be injective, so this decoder theorem supplies no exceptional-probability bound. In particular, replacing `z` here by a rank measured only on the adaptively selected `G` would be circular: that would change the fixed decomposition and its matrix distribution after observing `A`.

## Robust list alternative: charge the sampled inconsistency

A different constructive route is possible if one constructs a manageable prefix-fixed list `L` of common degree-bounded data/mask tuples. For a fixed listed tuple `Q`, define its projected response `R_Q(A)=A Q_data+Q_mask`. Under any adaptive selector `R(A)`,

`Pr[R=R_Q(A), J subset G, and some x in J has (W(x),M(x)) != Q(x)] <= 20*p^-5`.

Proof: at a mismatching coordinate, a nonzero data residual imposes five independent affine constraints on `A`, of probability `p^-5`; a zero data residual with a nonzero mask residual is impossible. Apply a union bound to the twenty sampled coordinates. Requiring the response equality and all other opening equations only shrinks the event. Union over the fixed list gives `20*|L|*p^-5`.

The remaining coverage obligation is algebraic: outside a quantitatively bounded exception, every relevant large-agreement response must equal the projection of some listed tuple. The list must be constructed from the fixed source with controlled size and work, not selected or generated after seeing `A` and then counted as if fixed. This is an alternative to the global-dimension decoder, not a necessary form of every possible extractor. Neither coverage nor a useful list bound is proved here for the residual low-rank branch.

## Why rank one does not justify a factor-free adaptive bound

A compact large-agreement example identifies the robust-extraction distinction. Fix a core of `B>387` positions. On it put both data words equal to zero. At the remaining `L=N-B` positions put `(W_1,W_2)=(1,t)` for distinct field elements `t`; all other data and mask rows are zero. Choose `R=0`. If `a,b` are the first two columns of `A`, an outside point agrees exactly when `a+t*b=0`.

For `b!=0`, at most one outside point can agree. The event that at least one agrees has exact probability

`L*p^-5 - (L-1)*p^-10`.

It produces a very large support that is not a common polynomial tuple: the core forces the first polynomial to be zero, but the extra agreeing point has value one. With `B=N/2`, this large-support event is approximately `2^-298`, not `2^-320`. On the `a=b=0` branch, the whole source agrees and has residual rank two; otherwise the one-extra-point branch has residual rank one.

Nevertheless, the zero tuple correctly explains the entire core. For twenty openings, accepted equations together with observing a discrepancy from this tuple have exact probability

`L*(p^5-1)/p^10 * choose(B,19)/choose(N,20)`

`+ p^-10 * (1 - choose(B,20)/choose(N,20))`.

The first branch must actually sample the exceptional point; multiplying only by the probability of remaining within the large support would overcount robust-extraction failure. At `B=N/2`, the leading scale of this sampled-inconsistency expression is approximately `2^-335.678`. This is a DECS equation example, not a proof of the later relation or an SMZ9 forgery.

Likewise, a zero core of more than `k` points and 140 exceptional positions with data values the distinct standard basis vectors has global data quotient rank 140. If exactly one column of `A` vanishes, its agreement support has residual rank one and size `N-139`. Thus the unresolved branch cannot be collapsed into the global-`z<=5` decoder merely because its local rank is small.

## Precise next theorem

The target is now narrower than a generic 140-word MCA theorem: for the fixed arbitrary source, control the joint twenty-opening contribution of large supports whose quotient data rank is small. A successful result can construct source-dependent low-rank patches and their polynomial lifts, derive a robust candidate decoder directly, or prove a weighted exceptional-matrix bound. It must handle large overlaps between patches without counting a valid common core as failure.

The unproved step is **not** the fixed-support affine fiber count, high-rank incidence count, root argument, or small-global-dimension decoder. It is a uniform low-local-rank structural/decoding theorem with the correct adaptive quantifier order and concrete loss. Even after that theorem, accepted-proof extraction, full program/semantic satisfaction, and the actual QROM/lifetime composition still require their separate bindings.
