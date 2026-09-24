# Weighted MCA: projection transfer and an interpolation-method barrier

Date: 2026-09-07. This is a read-only mathematical research result subsequently recorded for review. It is not a Lean formalization, a universal bound at the required security budget, a fixed-coset attack, a QROM refinement, or production authority. No protocol or runtime parameter changes follow.

## Exact setting and result boundary

Use `p=2^64-2^32+1`, `N=2^23`, response degree at most `387`, and `w(g)=choose(g,20)/choose(N,20)`. The actual target and raw-query accounting are in `weighted-mca-universal-gap.md`: the unrestricted five-coordinate line budget must be below approximately `2^53.67807`, including its isolated small-support contribution under the conservative `320(2Q)^2` loss.

This note proves a cardinality projection-transfer lemma, rejects a proposed weighted-only version, and derives `B_416<2^80` for the full five-coordinate pole class. That class fixes any `c in F_p` outside the existing shifted evaluation coset `D`, permits entirely arbitrary `u:D->F_p^5`, and takes

    U(x)=u(x)/(x-c),    V(x)=1/(x-c).

No low-degree, rational-function, circuit-degree, or list-size premise is imposed on `u` or the maximizing response selector. This remains a source restriction on `U,V`, not the unrestricted target.

## A valid cardinality projection transfer

Let `S` be any subset of `F_p^n`, with size `M`, and suppose that for every linear map `L:F_p^n->F_p^r` the image `L(S)` has at most `A` points, where `A<p^r`. Then

    M <= A (p^r-1)/(p^r-A).

The empty case is immediate. Otherwise let `C_L` count ordered pairs `(a,b) in S^2` with `L(a)=L(b)`. For a fixed map, the fiber-size Cauchy inequality gives `C_L >= M^2/|L(S)| >= M^2/A`. Choose each entry of the `r by n` matrix independently and uniformly from `F_p`; no rank conditioning is needed. For distinct `a,b`, each row annihilates `a-b` with probability exactly `1/p`, so

    E_L C_L = M + (M^2-M)/p^r.

Combining these inequalities and rearranging proves the displayed bound. In particular an `A=25p^3` image bound under all maps to four coordinates implies

    M <= 25p^3 (p^4-1)/(p^4-25p^3) < 26p^3.

The last strict inequality is an exact integer comparison for the specified prime.

For the pole class, agreement is preserved by linear projection of `u`, the response coefficients, and the challenge parameter. A projected full agreement set can become larger, which is harmless for counting parameters above a fixed agreement threshold. The pole `V` has no degree-at-most-387 lift on any set of at least 389 points: otherwise `(X-c)R-1` would have too many roots and would have value `-1` at `c`. Thus badness is preserved on every sufficiently large projected full support.

The existing four-coordinate interpolation result in `weighted-mca-universal-gap.md` therefore supplies `A=25p^3` for every projection when the original support has at least 4940 points. Applying the lemma gives fewer than `26p^3` such parameters for arbitrary five-coordinate `u`. This conclusion is stronger than merely appending an unconstrained fifth parameter to one fixed projection.

## Why the weighted-only transfer is false

A bound on the sum of maximum weights in projection fibers does not by itself give a comparable bound before projection. To see this rigorously, take the abstract weighted set `S=F_p^5` and assign every point the same positive weight `t=w(833)`. Every surjective three-coordinate projection has weighted max-fiber sum exactly `p^3 t`, whereas the original weighted sum is `p^5 t`.

For the actual parameters,

    log2(p^3 w(833)) = -74.28817791839407...
    log2(p^5 w(833)) =  53.711822080934155...

Thus every projected sum is much smaller than `2^52`, but the original sum exceeds the current isolated allowance. Exact cross-multiplication verifies

    1280 * 2^256 * [w(415) + p*w(833)/(p-1)] > 1.

This is a counterexample to an abstract weighted-projection inference only. No fixed `U,V` and family of polynomial responses realizing this weighted set has been constructed. It must not be described as a source attack. A threshold-level count extracted from a weighted bound is also useless when its derived count is at least all `p^r` projection values; the cardinality lemma deliberately requires the strict inequality `A<p^r`.

## A complete full-five-coordinate pole bound below 2^80

A degree-at-most-387 response `R` at parameter `alpha` corresponds to

    P(X)=(X-c)R(X)-alpha,    degree(P)<=388,    alpha=-P(c).

Its full support is exactly `{x:u(x)=P(x)}`. Work over the base field in coordinates `Y_1,...,Y_5`. Give `X` weight one and every `Y_i` weight `k=388`. A polynomial of weighted degree at most `D` has

    M(D) = sum_(ell=0..floor(D/k)) choose(ell+4,4)(D-k*ell+1)
         = (D+1) choose(L+5,5) - 5k choose(L+5,6),
    L=floor(D/k),

available monomials. Requiring multiplicity at least `m` at all `N` graph points imposes at most `N*choose(m+5,6)` homogeneous linear conditions. The count concerns six variables; Hasse-derivative multiplicity works without a characteristic restriction.

Choose

    m=512,    D=1052667,    L=2713.

The exact excess of monomials over constraints is `816362022332076`, so a nonzero interpolation polynomial `Q` exists. On a support of at least 2056 points, `Q(X,P(X))` has degree at most `D` and at least `512*2056=1052672>D` zeros counted with multiplicity. It is therefore identically zero.

Remove the maximal factor `(X-c)^e` from `Q`. This neither destroys multiplicity at graph points, whose first coordinate is never `c`, nor the substituted identity. The remaining polynomial has a nonzero specialization at `X=c`, of total `Y`-degree at most 2713. The finite-field polynomial zero bound gives at most `2713p^4` distinct parameter values `-P(c)` above the 2056 threshold. This counts values, not response polynomials, and needs no nonsingularity or Hensel-lifting premise.

Between 4940 and the first strict Johnson threshold 56978, use the projection-transferred count below `26p^3`. From 56978 up to `N/16`, use the previously established universal first-Johnson count below `2^124` and the sampling bound `w(g)<=2^-80`. Above `N/16`, use the existing universal cubic-incidence count below `2^36`. These two tail bounds are proved or source-certified in `weighted-mca-research.md`; they are not newly formalized here.

Partitioning the maximizing full supports gives

    B_416(U,V)
      <= p^5 w(2055) + 2713p^4 w(4939) + 26p^3 w(56977) + 2^44 + 2^36
      < 2^80.

The exact rational bound divided by `2^80` is less than `0.975811561579633`. Its logarithm is approximately `79.9646744818`; the low branch dominates. This is far above the required universal security budget.

## A barrier for the standard dimension-count interpolation route

For the same five-coordinate weighted-degree construction, no multiplicity `m>=1` makes the generic monomial count exceed the graph multiplicity constraints at degree `D=2047m-1`. Consequently this standard dimension-count argument cannot guarantee an interpolation identity by agreement 2047. It does not rule out specially dependent graph constraints, another interpolation construction, or a different mathematical method.

Here is an exact finite certificate for the all-multiplicity statement. Put

    f(m)=N*choose(m+5,6)-M(2047m-1).

Write `m=r+388q`, with `1<=r<=388` and `q>=0`. Within each residue class, `floor((2047m-1)/388)` is affine in `q`, so `f(r+388q)` is a polynomial of degree at most six. Its Newton expansion is

    f(r+388q) = sum_(j=0..6) Delta^j f(r) * choose(q,j),

where each forward difference advances `m` by 388. All seven coefficients are strictly positive in every one of the 388 residue classes. The minimum coefficient at each order is, respectively,

    [8280164,
     1390339313903456674,
     44435149734650671744,
     244882166842920427987,
     463162838695007286978,
     337557843438720679935,
     75126074402478276220].

Since `choose(q,j)` is nonnegative, with its zeroth term one, this proves `f(m)>0` for every positive integer `m`. Ordinary monotonicity of the monomial count covers every smaller degree. The resulting unavoidable low branch of this method is `p^5 w(2047)`, whose logarithm is approximately `79.8516040041`, about 26.17 bits above the required budget. This is a method limitation, not a lower bound on the actual optimum `B_416`.

## Reproducible exact arithmetic

The following standard-library calculation uses only small loops, exact integers, and binomial coefficients. It does not construct the evaluation domain, an interpolation polynomial, a response family, or any shared cache artifact. Run from any directory with Python 3 and `-B` to suppress bytecode caches; provide this code on standard input rather than writing generated data into the repository.

    from math import comb
    p, N, k = 2**64-2**32+1, 2**23, 388
    def monomials(D):
        L = D // k
        return (D+1)*comb(L+5,5) - 5*k*comb(L+5,6)
    assert monomials(1052667)-N*comb(517,6) == 816362022332076
    assert 512*2056 > 1052667
    assert 25*p**3*(p**4-1) < 26*p**3*(p**4-25*p**3)
    denominator = comb(N,20)
    numerator = (p**5*comb(2055,20) + 2713*p**4*comb(4939,20)
                 + 26*p**3*comb(56977,20) + (2**44+2**36)*denominator)
    assert numerator < 2**80 * denominator
    assert (1280*2**256*(comb(415,20)*(p-1)+p*comb(833,20))
            > (p-1)*denominator)
    def gap(m):
        return N*comb(m+5,6)-monomials(2047*m-1)
    minima = [None]*7
    for r in range(1,389):
        row = [gap(r+388*q) for q in range(7)]
        for j in range(7):
            assert row[0] > 0
            minima[j] = row[0] if minima[j] is None else min(minima[j], row[0])
            row = [b-a for a,b in zip(row,row[1:])]
    assert minima == [8280164,1390339313903456674,44435149734650671744,
                      244882166842920427987,463162838695007286978,
                      337557843438720679935,75126074402478276220]

All assertions passed in the bounded research pass. No universal `B_416<2^53.67807`, fixed-coset counterexample, or efficient reversible-extraction claim is supplied by this note.
