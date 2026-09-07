# SMZ9 universal weighted MCA gap: continued research

Date: 2026-09-07. This document records finite mathematical research, not a completed universal security proof, a Lean theorem, a QROM implementation refinement, or production authority. The universal bound below remains unproved. There is no protocol or runtime change.

## Actual target and conservative query accounting

Let `p=2^64-2^32+1`, `N=2^23`, `d=387`, and `K=F_(p^5)`. The domain is the existing set of `N` distinct points in the shifted Goldilocks coset. Fix arbitrary `U:D->K` and `V:D->F_p`, both before the uniformly sampled parameter `alpha in K`. A bounded response is a polynomial `P in K[X]` of degree at most `d`. Write

`G(alpha,P) = {x: U(x)+alpha V(x)=P(x)}`,

`w(g) = choose(g,20)/choose(N,20)`.

A response is bad when `g=|G|>=416` and `V` has no degree-at-most-`387` polynomial lift on **all** of `G`. Define `B_416` as the supremum over fixed `U,V` of `sum_alpha max_badP w(g)`, with empty maxima zero. The maximizing response may be an arbitrary function of the entire challenge. No polynomial, rational, circuit-degree, or list-size assumption on that function is allowed.

The already derived independent-direction matrix reduction gives the classical error bound

`w(415) + [p/(p-1)] B_416/p^5`.

With the separately supplied loss `320(2Q)^2`, `Q=2^64`, requiring this isolated contribution to remain below `2^-128` is equivalent to

`1280 * 2^256 * [w(415) + p B_416/((p-1)p^5)] < 1`.

The corresponding maximum line budget has logarithm approximately `53.67807`. A proof of `B_416<=2^53` would leave some margin for this term; the stronger previously studied `2^52` would leave more. Neither is established universally here. The raw-query simulation and all other errors remain separate obligations.

Exact integer cross-multiplication, including the small-support term and `p/(p-1)`, shows that a hypothetical universal maximum bad support of `832` would fit this isolated budget; `833` would not. This is only a scale calculation: no such support ceiling is asserted. In the stricter `2^53` line-budget normalization, the unrestricted `p^5 w(g)` cap crosses at `g=813`.

## Fixed-subspace sampling: a valid moment lemma, not a universal reduction

Let `W` be a fixed `r`-dimensional subspace of degree-at-most-`d` polynomials, with `1<=r<=20`. Evaluate it on a uniformly sampled ordered sequence of twenty distinct domain points. Whenever the accumulated evaluation map has rank less than `r`, choose a nonzero polynomial in its kernel. At most `d` points can fail to increase the rank, because any rank-nonincreasing point must be a root of that polynomial. Conditional on the earlier distinct points, the failure probability is at most `d/(N-19)`.

If the final rank is less than `r`, at least `21-r` of the twenty steps failed to increase rank. A union bound over their positions gives

`Pr[rank(ev_J|W)<r] <= choose(20,r-1) [d/(N-19)]^(21-r)`.

The same statement holds for unordered twenty-subsets. In particular, the rank-two failure has nineteen powers of the small ratio `d/N`.

The missing implication is not hidden in this lemma: an accepted subset `J` of a bad full support does not itself specify a **fixed pre-J** two-dimensional polynomial space on which rank fails. Such a space can be obtained from several response polynomials only after paying for their selection. Charging an adaptively selected response pair or triple as if it were fixed would reintroduce the unresolved family-count problem.

Equivalently, lift the code to alphabet `K^20` indexed by all twenty-subsets. A response then has lifted agreement exactly `w(g)`. This rephrasing does not by itself yield a numerical MCA theorem: the lifted block length is `choose(N,20)`, and the standard subspace-design curve-decoding argument carries a dimension-dependent agreement loss. The attractive fixed-rank sampling estimate cannot be substituted for a bound on the unrestricted response span.

## A complete polynomial-multiple, five-coordinate source class

This is a source-structure theorem, not a regularity assumption on the response selector. It applies with all five challenge coordinates and permits large global quotient dimension.

Let `V:D->F_p` be **any** function, including one with zeros. Suppose the five coordinate words of `U` have the form

`U_i(x)=Q_i(x)+A_i(x)V(x)`,

with `degree(Q_i)<=d` and `degree(A_i)<=a`. In particular, this covers `V=1/B`, `U_i=A_i/B` for any nowhere-zero denominator word `B`, with no degree bound on that denominator.

For `a<=425`, the entire line budget of this source is strictly below `2^53`.

### Algebraic count above `a+d`

Subtract the fixed `Q_i` from a bad response tuple and call the resulting bounded tuple `R_i`. Put `C_i=A_i+alpha_i`. On the full agreement set,

`R_i(x)=C_i(x)V(x)`.

If `g>a+d`, every polynomial

`R_i C_j - R_j C_i`

has more roots than its degree, so it vanishes identically. If the tuple `C_i` is not identically zero, write `C_i=H c_i` with `gcd(c_1,...,c_5)=1`. The pairwise identities imply `R_i=S c_i` for one polynomial `S`: by Bezout, take polynomials `b_i` with `sum_i b_i c_i=1`, and set `S=sum_i b_i R_i`. Then `S c_j=R_j`. Since some `c_j` is nonzero, `degree(S)<=d`.

If `H` is constant, at every domain point some `c_i` is nonzero, and the agreement equations imply `S=H V` on `G`. Thus `V=S/H` is a degree-at-most-`d` polynomial on all of `G`, contradicting badness. This cancellation is valid even where `V(x)=0`. Hence a high-agreement bad parameter forces either all `C_i=0`, or a nonconstant common factor `H`.

If some `A_i` is nonconstant, the all-zero case is impossible. A common root `z` over an algebraic closure gives `alpha_j=-A_j(z)` for all coordinates. Fixing the base-field value `alpha_i` leaves at most `a` choices of `z`, and each root fixes the whole parameter vector. Therefore there are at most `a p` distinct high-agreement parameters. This counts extension roots correctly and does not assume `z` belongs to the base field.

If all `A_i` are constant, every parameter except the one cancelling all `C_i` has constant gcd and is not high-agreement bad; the exceptional count is at most one.

### Complete weighted accounting

For `a=425`, supports below the algebraic cutoff have at most `812` points. Between that cutoff and `N/16`, there are at most `425p` parameters, each with weight at most `2^-80`. Above `N/16`, use the independently proved universal cubic-incidence tail, which counts fewer than `2^36` bad parameters. Consequently

`B_416(U,V) <= p^5 w(812) + 425p/2^80 + 2^36 < 2^53`.

Exact integer arithmetic gives a ratio below `0.977014` to `2^53`. The constant-multiplier case is smaller. The scalar word `V` is arbitrary, so this result is not restricted to short rational functions or a low-degree representation of the adversary. Its unproved extension would be removing the source premise `U_i=Q_i+A_i V` with the displayed polynomial bounds. The source count and final arithmetic were independently checked.

### Rational multipliers, still with arbitrary `V`

The same conclusion holds for

`U_i=Q_i+(A_i/C)V`,

where `C` is nonzero on `D`, `gcd(C,A_1,...,A_5)=1`, and all numerator and denominator degrees are at most `425`. There remains no constraint on `V` or the response selector.

Set `F_i=A_i+alpha_i C`. Above `g>a+d`, cross-polynomial identities again hold. If `gcd(F_i)=1`, write `R_i=S F_i`; the full support then satisfies `V=C S`. This is a bounded polynomial unless all `F_i` have degree less than `degree(C)`, since otherwise `degree(CS)<=max_i degree(R_i)<=d`. Such simultaneous leading-coefficient cancellation has at most one parameter vector. If the `F_i` have a nonconstant common factor, a common root `z` cannot be a root of `C`, by the normalization. Thus `alpha_i=-A_i(z)/C(z)`. A nonconstant coordinate ratio has at most `a` preimages for each fixed base-field coordinate value, giving at most `a p` such parameters. The all-constant-ratio case reduces to at most one exceptional vector.

The safe elementary count is therefore `a p+1`. Replacing `425p` by `425p+1` in the displayed weighted bound still gives a ratio below `0.977014` to `2^53`. This corollary and its exact arithmetic were independently checked; no projective-root shortcut is required by the bound.

## An arbitrary received-word pole class, without numerator-degree restrictions

There is also a complete, different class. Fix `c in F_p` outside `D`, and suppose `u:D->F_p^4` is entirely arbitrary. Embed these four coordinates in the five-coordinate challenge alphabet, with fifth coordinate zero, and take

`U(x)=u(x)/(x-c)`, `V(x)=1/(x-c)`.

At full agreement `g>=416`, the fifth response coordinate forces the fifth challenge coordinate to zero: otherwise `(X-c)R_5-alpha_5` is a nonzero degree-at-most-`388` polynomial with too many roots. For the remaining coordinates, put

`P_i=(X-c)R_i-alpha_i`, so `degree(P_i)<=388` and `alpha_i=-P_i(c)`.

The exact full support is `{x:u(x)=P(x)}`. This class does **not** assume that `u` is rational of small degree.

Construct a polynomial `Q(X,Y_1,...,Y_4)` of weighted degree at most `9879`, with weights `(1,388,388,388,388)`, having multiplicity at least two at all `N` graph points `(x,u(x))`. Such a nonzero polynomial exists by linear algebra, because the exact monomial count is

`sum_(ell=0..25) choose(ell+3,3)(9879-388ell+1)`

`  = 50352120 > 6N = 50331648`.

For a response with `g>=4940`, substitution gives a polynomial `Q(X,P(X))` of degree at most `9879` with at least `2g>=9880` roots counted with multiplicity. It is zero identically. Remove the maximal factor `(X-c)^e` from `Q`; this preserves the graph-point multiplicities because no graph point has first coordinate `c`, and preserves the substituted identity. The resulting `Q(c,Y)` is nonzero, with total `Y`-degree at most `25`. Therefore at most `25p^3` distinct high-agreement challenge values occur, by the elementary finite-field polynomial zero bound. No Hensel or nonsingularity condition is involved.

Using this count up to the first strict Johnson agreement `56978`, and the universal tails already proved in the preceding dossier, gives

`B_416(U,V) <= p^4 w(4939) + 25p^3 w(56977) + 2^44 + 2^36 < 2^53`.

The `2^44` term uses the earlier first-Johnson count below `2^124` times the weight bound `2^-80` for supports below `N/16`; the last term uses the cubic tail. Exact integer arithmetic gives a ratio below `0.760612` to `2^53`. The interpolation count, source-to-pole mapping, and final arithmetic were independently checked.

This does not close the full five-coordinate pole class: the analogous five-coordinate guaranteed interpolation threshold approaches `(N*388^5)^(1/6)`, around two thousand agreements. The unrestricted `p^5` weight below that threshold exceeds the required line budget. Nor does this pole argument apply to arbitrary `V`: substitution then leaves an uncontrolled bivariate polynomial evaluated at `(x,V(x))`, and the univariate root-count step is unavailable.

## Primary-source applicability checks

- [Guruswami and Xing, Section 7.1](https://eccc.weizmann.ac.il/report/2020/172/download/) does address ordinary Reed--Solomon evaluation on a subfield. Its Frobenius interpolation uses `s<=m` and guarantees agreement at least `(N+s k)/(s+1)`. With the actual `m=5`, even the best `s=5` needs about `1.4 million` agreements. The resulting candidates occupy a structured affine space; smaller lists additionally use subcodes. This is not a theorem for the needed `416..56977` interval.
- [Diamond and Gruen](https://www.researchgate.net/publication/387966611_Proximity_Gaps_in_Interleaved_Codes) transports proximity gaps to interleaved codes within the unique-decoding radius. That range does not reach this near-capacity agreement interval. It does not justify a five-coordinate extension of an unproved below-Johnson scalar bound.
- [Jeronimo, TR26-169](https://eccc.weizmann.ac.il/report/2026/169/download), Proposition 3.8, requires an actual finite interpolation incidence inequality with `r<K`; its MCA proof then adds a geometric degree budget and up to `r+1` support cuts. Section 8.5 explicitly leaves prescribed finite-length numerical certification unclaimed. The asymptotic existence of effective constants is not a numerical `B_416` certificate for these parameters.

## Current boundary

The fixed-subspace moment lemma and the polynomial-multiple source theorem are proved above. Neither supplies the required universal estimate for unrestricted `U,V`. No fixed-coset source exceeding the target has been constructed in this pass. In particular, failing to find a counterexample is not evidence authorizing a security claim.
