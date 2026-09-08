# Weighted SMZ9 MCA: direct finite research

Date: 2026-09-07. This is local mathematical research, not a completed arbitrary-source bound, a Lean proof, a QROM reduction, or production authority. The target below is **not proved** for arbitrary sources. The retained results include uniform high-agreement tails, a completed range through global quotient dimension four using a published support-wise MCA theorem, and a higher-rank rational-source exclusion. No protocol parameter or runtime field changes here.

## Exact target

The current continuation adds a [conditional global stress lemma](weighted-mca-global-shift-stress.md),
a [legal rank-six large-gcd counterfamily](weighted-mca-global-escape-family.md),
and a [sharp per-affine-response-family charge](weighted-mca-affine-response-charge.md).
The counterfamily refutes the proposed universal `M(813)<=212` shortcut,
not the weighted security target. The family charge needs an independently
proved global cover before it can bound unrestricted responses.

The [support-capped affine charge](weighted-mca-support-capped-charge.md)
and [rational-graph charge](weighted-mca-rational-graph-charge.md) reduce the
missing cover to maximizing responses with full support in `813..56977`.
Respectively, at most `2^168` affine families or total non-affine graph
degree at most `2^184` would suffice for the weighted inequality; neither
cover is established. The [zero-stress branch](weighted-mca-zero-stress-branch.md)
is closed by a separate diagonal-kernel argument. Nonzero stress remains
an independent obstruction, and no numerical K8 receipt is populated.

Write `p = 2^64 - 2^32 + 1`, `N = 2^23`, `k = 388`, and `K = F_(p^5)`. The domain `D` is the existing shifted Goldilocks coset, with its `N` distinct base-field points. The five coordinates of `K` only group the existing five base-field matrix rows.

Fix arbitrary `U : D -> K` and `V : D -> F_p`. For `alpha in K` and `P in K[X]` of degree less than `k`, put

`G(alpha,P) = {x in D : U(x) + alpha V(x) = P(x)}`.

A witness is bad when `|G| >= 416` and no polynomial of degree less than `k` agrees with `V` on all of `G`. Using `F_p[X]` or `K[X]` in this last condition is equivalent: interpolation at `k` distinct base-field points makes a `K` polynomial with these base-field values a base-field polynomial.

Let `w(g) = choose(g,20) / choose(N,20)`, with the exact without-replacement sampling law. Define

`B_416 = sup_(U,V) sum_(alpha in K) max_(bad P at alpha) w(|G(alpha,P)|)`,

where the empty maximum is zero. The research target is the concrete inequality

`B_416 <= 2^52`.

The reduction below removes a factor of `140` from the earlier column-by-column experiment. With the subsequently supplied quantum coefficient `320 Q^2`, the isolated DECS budget permits approximately `log2(B_416) < 55.67807`, before other error terms. Thus `B_416 <= 2^52` remains a sufficient, stronger research target; it is still not proved universally. This document does not treat either desired numerical bound as a completed theorem.

## Amortized whole-matrix reduction: no factor of 140

This is a finite classical counting theorem. Its use in a quantum cryptographic theorem still requires that theorem's separate game/refinement hypotheses.

For `n>=1`, fix arbitrary base-field data words `W_1,...,W_n`, five arbitrary mask words, and a bounded response selector `A -> R(A)` for the complete uniformly sampled five-by-`n` matrix. The response may depend on every matrix entry, but not on the later query subset. Group each matrix column into `K`; then the actual combined word is `M + sum_j A_j W_j`. Let `G_A` be its actual full agreement with `R(A)`. All source words and masks are fixed before `A`.

Introduce an independent proof-only vector `v in F_p^n \ {0}`. It is never added to the protocol or supplied to the response selector. Define `V_v = sum_j v_j W_j`. If `G_A` is large and at least one source word is not polynomial there, at least one **data** word is not polynomial there: otherwise subtraction from the bounded response makes every mask polynomial too. The linear map

`v -> [sum_j v_j W_j] in F_p^(G_A) / RS(G_A,388)`

therefore has nonzero rank. At least `D_n = p^n - p^(n-1)` nonzero vectors have nonzero image. Crucially `A`, its response, and `G_A` do not depend on `v`.

For any fixed nonzero `v`, choose a coordinate `j` with `v_j != 0` and set

`alpha = A_j / v_j`, `A_0 = A - alpha v`.

Then `(A_0)_j=0`. This is a bijection between all actual matrices and the product of unrestricted other columns of `A_0` with `alpha in K`. In particular `alpha` is fresh uniform conditional on `A_0,v`. The same actual combined word is exactly

`(M + sum_i (A_0)_i W_i) + alpha V_v`.

For each fixed `A_0,v`, summing the retained-support weight over `alpha` is bounded by the defined one-line budget. This uses all possible bounded responses at each `alpha`, so the arbitrary selector `R(A_0+alpha v)` is allowed.

For an exact integer statement, put `M_n=p^(5n)`, `T_n=p^n-1`, and let `L=choose(N,20) B_416` be the universal unnormalized line budget. Let `X_A` be `choose(|G_A|,20)` when `|G_A|>=416` and the source is unrecovered, and zero otherwise. Let `Y_(A,v)` use the same weight when `|G_A|>=416` and `V_v` is not polynomial on `G_A`. The two counts above give

`D_n X_A <= sum_(v!=0) Y_(A,v)`,

`sum_A Y_(A,v) <= p^(5(n-1)) L` for each nonzero `v`,

and hence

`p^5 D_n sum_A X_A <= T_n M_n L`.

After restoring the small-support branch and dividing by the exact matrix/subset sample-space size,

`Pr[query accepts and full source unrecovered]`

`  <= w(415) + gamma_n B_416/p^5`,

`gamma_n = (p^n-1)/(p^n-p^(n-1)) = 1 + p^-1 + ... + p^(-(n-1)) < p/(p-1)`.

Using all vectors, including zero, in the auxiliary average gives the slightly weaker coefficient `p/(p-1)` directly: zero contributes nothing to the detection event. No `n=140` union factor remains. A randomized response selector is handled by fixing and then averaging its independent private randomness.

With `n=140`, `Q=2^64`, and a separate quantum loss `320 Q^2`, the maximum budget for this DECS term alone is

`B_416 < (p^5/gamma_140) * (1/(320 * 2^256) - w(415))`.

Its base-two logarithm is approximately `55.67807`. This is not an end-to-end security claim: other cryptographic errors and the coherent implementation binding still require their own verified accounting.

## Uniform high-agreement theorem

**Theorem.** For every fixed `U,V`, at most `N` distinct parameters `alpha` have a bad witness whose full agreement set has size at least `5N/8`.

This theorem uses only distinct evaluation points, the degree bound, and finite incidence counting. It applies to all source dimensions and does not assume a fixed patch cover or an MCA theorem.

**Proof.** Suppose instead that there are `M > N` such parameters. Choose one witnessing polynomial `P_i` and full support `G_i` for each distinct parameter `alpha_i`. Set `s = 5N/8`, an integer, and choose an `s`-element subset `H_i` of each `G_i`. The subsets are used only for counting; no badness assertion is made about `H_i`.

For a point `x`, let `d_x` count the sets `H_i` containing it. Then `sum_x d_x = M s`. Cauchy--Schwarz and counting pairs through points imply that some distinct pair `i,j` satisfies

`|H_i intersect H_j| >= s^2/N - s(N-s)/(N(M-1)) >= 25N/64 - 1/4`.

Call this intersection `T`. Define the degree-less-than-`k` polynomials

`Q_V = (P_i - P_j)/(alpha_i - alpha_j)`,

`Q_U = P_i - alpha_i Q_V`.

The two response equations show that `Q_V = V` and `Q_U = U` on `T`. Every other full support obeys

`|T intersect G_l| >= |T| + |G_l| - N >= N/64 - 1/4 > 387`.

Consequently the polynomial `P_l - Q_U - alpha_l Q_V`, whose degree is at most `387`, has more than `387` roots. It is zero identically. In particular every selected response lies on this same polynomial line. Also `|T| >= k`, so `Q_V` has base-field coefficients by interpolation.

Because the full witness `G_l` is bad, it contains a point `x_l` with `V(x_l) != Q_V(x_l)`. The response equation at that point now determines the entire extension-field parameter:

`alpha_l = (Q_U(x_l) - U(x_l))/(V(x_l) - Q_V(x_l))`.

A fixed point can therefore be chosen for at most one distinct parameter. Choosing one such point for every witness injects the `M` parameters into `D`, contradicting `M > N`. This proves the theorem.

**Weighted consequence.** The portion of `B_416` whose maximizing bad support has size at least `5N/8` is at most `N = 2^23`, since each sampling weight is at most one. This is a complete universal tail estimate, not the full target.

## Where the extension-field parameters can live

Let `C` be the base-field degree-less-than-`k` evaluation code on all of `D`. Choose a base-field basis of `K` and write `U = sum_i e_i U_i`, with five base-field words `U_i`.

If `[V] = 0` in `F_p^D / C`, there are no bad witnesses. Otherwise set

`z = dim_Fp span{[V],[U_1],...,[U_5]}`,

so `1 <= z <= 6`.

**Theorem.** All bad parameters lie in one fixed affine base-field subspace of `K` of dimension `z-1`. In particular their number is at most `p^(z-1)`.

**Proof.** Extend `[V]` to a basis `[V],[T_2],...,[T_z]` of the displayed quotient span. The fixed source then has a decomposition

`U_i = Q_i + c_i V + sum_(j=2..z) D_ij T_j`,

where each `Q_i` is a degree-less-than-`k` base-field polynomial. The `5 by (z-1)` matrix `D` has column rank `z-1`, since the quotient classes of `V` and the `U_i` span dimension `z`.

View `alpha` and `c` as five-coordinate vectors. If `alpha+c` is outside the column space of `D`, choose a base-field linear functional `ell` annihilating that column space and satisfying `ell(alpha+c)=1`. Applying `ell` to the five response equations, after subtracting the fixed `Q_i`, expresses `V` on the full agreement set as a degree-less-than-`k` polynomial. Such a witness is not bad. Thus every bad parameter belongs to the fixed affine space `-c + col(D)`, which has exactly `p^(z-1)` points.

The conclusion is global-source-specific; it does not substitute an adaptively measured local rank for a fixed global decomposition. In the hard case `z=6`, the affine space is all of `K`, and this theorem alone imposes no restriction.

## A completed dimensional range

Combining the preceding two theorems, every source with `z <= 2` satisfies

`sum_alpha max_badP w(|G|) <= p (5/8)^20 + N < 2^51 < 2^52`.

Indeed, there are at most `p` bad parameters altogether; those below the high-agreement cutoff have sampling weight at most `(5/8)^20`, while the remaining parameters contribute at most `N`. The without-replacement weight is no larger than the displayed with-replacement power.

The final strict inequality was checked by exact integer comparison:

`p * 5^20 + N * 8^20 = 1759218613703406557012400829290033`,

`2^51 * 8^20 = 2596148429267413814265248164610048`.

The logarithm of the resulting upper bound is approximately `50.43856191`. This range includes arbitrary base-field `U` embedded in `K`, but not arbitrary extension-field `U`.

## Stronger uniform tail from cubic incidence

**Theorem.** For every `U,V`, the number of bad parameters having a full agreement set of size at least `N/16` is at most

`(N^2 + 3N)/(N/4096 - 387) = (N^2 + 3N)/1661 < 2^36`.

**Proof.** Select one bad response `P_i` with full support `G_i` for each of the `M` distinct parameters being counted. Regard `(alpha_i,P_i)` as points in the affine space of one scalar and `k` polynomial coefficients over `K`.

Every affine line through two selected points has at most `N` selected points. Indeed, the distinct parameter coordinates make it the graph of a polynomial line `P = Q_U + alpha Q_V`. Each bad witness on it contains a point where `V != Q_V`; that point determines the whole parameter by the quotient used in the preceding proof. If `V` agreed with `Q_V` on an entire bad support, interpolation would give the prohibited base-field lift. Thus the point-charging argument works even when `Q_V` was initially written over `K`.

For any three noncollinear selected points, their three full supports have at most `387` common positions. Otherwise the difference between the two polynomial secant slopes,

`(P_i-P_j)/(alpha_i-alpha_j) - (P_i-P_l)/(alpha_i-alpha_l)`,

would be a nonzero polynomial of degree at most `387` with too many roots. Noncollinearity says precisely that this polynomial is nonzero.

Let `n_x` count the full supports containing `x`. Ordered triples of distinct, collinear selected points number at most `N M^2`, because an ordered pair fixes a line containing at most `N` selected points. Charge each such triple at most `N` common positions, and each noncollinear triple at most `387`. Ordered triples with a repeated index number at most `3 M^2` and can each be charged at most `N` positions. Consequently

`sum_x n_x^3 <= 387 M^3 + (N^2 + 3N) M^2`.

On the other hand, `sum_x n_x >= M N/16`, so Holder's inequality gives

`sum_x n_x^3 >= (sum_x n_x)^3/N^2 >= M^3 N/4096`.

For `M > 0`, division yields the claimed bound; the empty case is immediate.

**Completed additional dimension.** Every source with global quotient dimension `z <= 3` therefore satisfies

`sum_alpha max_badP w(|G|) <= p^2 (1/16)^20 + 2^36 < 2^48 + 2^36 < 2^49`.

This uses at most `p^2` bad parameters below the density cutoff and the uniform cubic-incidence bound above it. It completes a larger dimensional range without a proximity-gap theorem. It still does not establish the arbitrary-source target.

## Published MCA theorem closes quotient dimension four

**Source-verbatim certificate.** The same [BCHKS author manuscript](https://www.math.toronto.edu/swastik/rs-proximity-gaps-2025.pdf), Theorem 4.6, pages 28--29, directly bounds support-wise MCA: the combination is polynomial on a support where the coefficient words are not jointly polynomial. Take its `M=1`, field `K`, degree `d=387`, `rho=d/N`, and `gamma=1-65536/N`. Its integer multiplicity is

`m = max(ceil(sqrt(rho)/(1-sqrt(rho)-gamma)),3) = 7`.

This is a direct ordinary-field application, not an interleaved-code theorem. A bad witness here is one of its witnesses: if `V` is not polynomial on that support, the pair `U,V` is not jointly polynomial there. The full agreement is an admissible choice of the source theorem's support.

The exact Johnson and multiplicity checks are `65536^2 > 387 N` and

`49 * 16384 * 387 > 36 N`, `64 * 16384 * 387 < 49 N`.

Write `h=m+1/2`, `DX=h sqrt(Nd)`, `DY=h sqrt(N/d)`, `DZ=h^2 N/(3d)`. The theorem's numerator is `2 DX DY^2 DZ + (gamma N+1) DY`. For `m=7`, upper bounds `DX<427329`, `DY<1105`, `DZ<406425` bound it by

`E_direct = 2 * 427329 * 1105^2 * 406425 + N * 1105`

`         = 424128388239503090 < 2^59`.

Thus the universal number of bad parameters with agreement at least `65536` is below `2^59`. Using this count for `65536 <= g < N/16`, the earlier affine-parameter bound below it, and the cubic tail above it gives, for every `z <= 4`,

`p^3 choose(65535,20)/choose(N,20) + E_direct/2^80 + 2^36 < 2^52`.

The final inequality passes exact integer cross-multiplication. Alternatively the first term is less than `2^52 - 2^37 + 2^20`, the middle term is less than one, and the last term is `2^36`. **This direct Theorem 4.6 certificate suffices for the dimension-four result; the stronger factor calculation below is not required.**

### Stronger factor calculation, not needed by the certificate

The manuscript's Lemma 3.1 and Section 3.2, steps 1--4, also support a stronger deduction: assign only bad full-support responses to factor clusters. A linear factor fixes every response in its cluster to one polynomial line; the earlier mismatch-point injection then bounds that cluster by `N`. The non-linear cluster thresholds, plus content exceptions, sum to

`E(s) <= DZ + 2 DX DY^2 DZ + N DY`.

At `s=65536`, `m=4`, safe bounds `(DX,DY,DZ)<(256398,663,146313)` give `E(s) <= 32980305488098629 < 2^55`. This separately reviewed strengthening is not load-bearing: the source-verbatim `m=7` theorem above already completes the claimed dimensional range. Neither result is a Lean formalization here.

## A larger common-denominator counterexample mechanism is excluded

This section proves a restricted-source result, not the universal target. Fix a base-field point `c` outside `D`. For a received word `u : D -> K`, take

`U(x) = u(x)/(x-c)`, `V(x) = 1/(x-c)`.

A response `R` of degree at most `387` at parameter `alpha` corresponds exactly to

`P(X) = (X-c) R(X) - alpha`, `degree(P) <= 388`, `alpha = -P(c)`.

Its full agreement set is exactly `{x : u(x)=P(x)}`. On any set of at least `389` distinct points, `V` has no degree-at-most-`387` lift: multiplication by `X-c` would give a polynomial of degree at most `388` with too many roots and value `-1` at `c`. Thus this pole construction converts the relevant degree-`388` list directly into bad parameters, retaining full supports and counting **distinct values `-P(c)`**, not codewords.

**Theorem.** Suppose `u(x)=A(x)/B(x)`, where `A in K[X]`, `B in F_p[X]` is nonzero at every point of `D`, `t=degree(B)<=1989`, and `degree(A)<=388+t`. Then the entire weighted sum for this pole construction is strictly less than `2^52`.

**Proof.** If `u` is exactly a degree-at-most-`388` polynomial, a different such polynomial has at most `388` agreements, so at threshold `416` there is just one parameter and its score is `1`. Otherwise every candidate has nonzero residual `A-BP`, hence at most `388+t<=2377` agreements.

Consider all candidates `P_i` with at least `786` agreements, and let `H_i` be the product of `X-x` over their full agreement sets. Write

`A-BP_i = H_i Q_i`.

Each `Q_i` has five coordinate polynomials over `F_p`, all of degree at most `t-398`. Also `H_i` is coprime to `B`. In any five-column coordinate determinant of the vectors `Q_i`, multiply column `i` by `H_i` and subtract the first resulting column from each other column. The latter four columns are divisible by `B`, since their values before subtraction are `A-BP_i`. Therefore `B^4` divides the original determinant: the scaling factors `H_i` are coprime to `B`. But that determinant's degree is at most

`5(t-398) < 4t`, since `t<=1989`.

It must vanish identically. If `t<398`, no nonzero residual can have `786` roots and the high branch is simply empty. Otherwise the whole family of vectors `Q_i`, and hence of residuals `H_i Q_i`, has rank at most four over `F_p(X)`.

Fix one high-agreement candidate `P_0`. All differences `P_i-P_0` belong to that same rank-at-most-four rational-function subspace, because `B(P_i-P_0)` is a difference of residuals. Every five-column coordinate minor of these **polynomial** differences therefore vanishes identically. Evaluating those zero polynomials at `c` shows directly that the values `P_i(c)-P_0(c)` span at most four dimensions over `F_p`, even if a chosen rational-function basis would have a pole at `c`. Consequently there are at most `p^4` distinct high-agreement parameters.

The low branch has at most all `p^5` parameters, with agreement at most `785`; the high branch has at most `p^4`, with agreement at most `2377`. Thus

`B_416(U,V) <= p^5 choose(785,20)/choose(N,20)`

`               + p^4 choose(2377,20)/choose(N,20)`

`             < 2^52 - 2^45 + 2^21 < 2^52`.

Both strict component inequalities were checked by exact integer cross-multiplication. This proof permits all five output coordinates and does not impose low global quotient rank. It rules out this rational-word mechanism through base-denominator degree `1989`; arbitrary received words and larger denominators remain outside its scope.

**Revised-budget corollary.** With the amortized whole-matrix reduction and the supplied `320 Q^2` factor, the same determinant proof works at high cutoff `892`, base-denominator degree `t<=2519`, and maximum nonzero-residual agreement `2907`. It gives

`B_416(U,V) <= p^5 w(891) + p^4 w(2907)`.

Exact integer arithmetic verifies

`320 * 2^256 * [w(415) + gamma_140 * (w(891) + p^-1 w(2907))] < 1`.

This includes the small-support term, but still concerns only the isolated DECS contribution and the stated rational pole family.

## Polynomial response strategies: a broad but restricted exclusion

Fix arbitrary `U,V`. Suppose the response strategy `P(a,X)` has five base-field challenge coordinates `a=(a_1,...,a_5)`, degree at most `387` in `X`, and every coefficient has total polynomial degree at most `h` in `a`, with `h>=1`. This is an additional adversary restriction, not a property proved for the universal maximizing selector.

For each coordinate `j` and domain point `x`, form

`F_(j,x)(a) = P_j(a,x) - U_j(x) - a_j V(x)`.

At a bad parameter, the Jacobian rows belonging to its full agreement set have rank five. Otherwise a nonzero kernel vector `delta` would give, for every agreeing point,

`delta_j V(x) = sum_i delta_i (partial P_j / partial a_i)(a,x)`.

Choose `j` with `delta_j!=0`. The right side is a degree-at-most-`387` polynomial in `X`, contradicting badness of `V` on the same full support. Thus five of the `5N` fixed equations isolate that parameter with nonsingular Jacobian. A selected five-equation system has at most `h^5` nonsingular common zeros by [Bafna, Sudan, Velusamy, and Xiang, Corollary 1.3](https://arxiv.org/pdf/2102.00602), which holds over any field without requiring the entire zero set to be zero-dimensional. Consequently the number of bad parameters of this fixed strategy is at most

`h^5 choose(5N,5)`.

At the first strict Johnson agreement `s=56978`, Theorem 4.6 has `m=64167`. Exact integer guards give

`DX<3656078837`, `DY<9447233`, `DZ<29750065009822`,

`E_first <= 19415238057946677331930434730749083756 < 2^124`.

The low/medium/high split at `56978` and `N/16` therefore proves the strategy's weighted bound

`B_strategy <= h^5 choose(5N,5) w(56977) + E_first/2^80 + 2^36`.

For `h<=32768`, this is below `2^51`. Exact cross-multiplication including `gamma_140` and `w(415)` also verifies the isolated `320 Q^2`, `Q=2^64` DECS target for `h=65536`: the ratio to that isolated error allowance is less than `0.987703`. The multiplicity, Johnson, three degree-ceiling, and final integer inequalities were independently recomputed; no floating-point comparison is load-bearing.

The same counting argument permits a fixed rational-response chart with common denominator `Delta(a)` nonzero on that chart. If numerator degrees are at most `H` and `1+degree(Delta)<=H`, clear the denominator in each `F_(j,x)`. At an agreement zero, the cleared Jacobian equals `Delta` times the rational-response Jacobian and still has rank five. This yields at most `H^5 choose(5N,5)` bad parameters on that chart. Multiple charts or pole branches require their own explicit union accounting; no bound on their number is assumed here.

This does **not** bound arbitrary response selectors. Finite-field functions admit polynomial representations of much higher degree, and high algebraic degree can be computed by short exponentiation circuits. There is no justified inference from efficient computation to the displayed degree limit.

## Precise unresolved range, and screens that did not close it

The arbitrary-source target remains unproved for global quotient dimensions `5` and `6` and intermediate agreement densities. The worst unrestricted parameter freedom occurs at `z=6`: six globally independent quotient words can still become a rank-one quotient on an adaptively selected support. In augmented coordinates, each bad support is a rich rank-`k+1` flat in a rank-at-most-`k+6` extension of the actual Vandermonde configuration.

The following observations are screens, not substitutes for the missing universal count:

- Even allowing all `p^5` parameters, supports of size at most `785` contribute less than `2^52` in isolation: `log2(p^5 w(785)) = 51.97889442...`. At size `786` the same trivial cap already exceeds the target. This does not allocate a budget to the larger-support branches.
- Independent scalar exceptional-set products are too coarse for a common core. A point where `V` differs from an already fixed explaining polynomial determines all five coordinates of `alpha` simultaneously; it does not provide five independent choices of exceptional points. Conversely, assuming that every support possesses such a fixed common core would be an unproved coverage assumption.
- Pair-intersection peeling loses up to `k-1` points of agreement per removal and does not resolve the near-capacity range. The high-density proof above does not license extrapolation to agreement near `416`.
- Optimizing only the scalar Guruswami--Sudan multiplicity or cutoff cannot close dimensions five and six. The first strict Johnson agreement is `56978`; even an ideal zero tail above it would leave the low-branch caps `p^4 w(56977)` and `p^5 w(56977)`, whose base-two logarithms are approximately `111.95706203` and `175.95706203`. A new below-Johnson estimate is necessary for this route.
- Subgroup-fiber and low-common-denominator examples examined so far do not produce a counterexample. Their extra structure reduces the number of parameters or caps the bad agreement size. No arbitrary-source inference follows from those examples.

No construction exceeding `2^52` and no proof covering these remaining dimensions in general is supplied. The high-density, affine-dimension, published-MCA, and rational-source results are retained as independently checkable progress toward that exact target.
