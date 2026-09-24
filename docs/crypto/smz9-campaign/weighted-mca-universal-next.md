# SMZ9 universal weighted MCA: next bounded checkpoint

Date: 2026-09-07. This is source-only mathematical research. The universal target remains unproved, and no source on the actual Goldilocks coset exceeding it has been constructed. Nothing in this note changes protocol parameters, the verifier, a Lean assumption, or production authority.

## Target and outcome

Use `p=2^64-2^32+1`, `K=F_(p^5)`, the existing shifted multiplicative coset `D` of size `N=2^23`, and degree bound `d=387`. Fix arbitrary `U:D->K` and `V:D->F_p` before `alpha` is sampled uniformly from `K`. A response `P_alpha` is any degree-at-most-387 polynomial over `K`; its selection may depend arbitrarily on all of `alpha`, but precedes the twenty sampled positions. Its full agreement support is

    G_alpha = {x in D : U(x)+alpha V(x)=P_alpha(x)}.

A support is bad if `|G_alpha|>=416` and `V` has no degree-at-most-387 polynomial lift on all of that support. Put `w(g)=choose(g,20)/choose(N,20)`. The required universal bound is `sum_alpha max_badP w(|G_alpha|)<=2^53`; the isolated allowance including the separate conservative query loss is approximately `2^53.67807`, as defined in `weighted-mca-universal-gap.md`.

This pass proves two finite restrictions. A family whose responses all agree on one fixed 388-point interpolation core has weighted budget below `2^18`. A family with sources constant on the fibers of `x->x^32` and whose bad full supports contain thirteen complete fibers has budget at most `262131`. Both statements allow an unrestricted response selector. Neither premise has been derived for arbitrary sources and supports. These restrictions therefore exclude construction mechanisms, not the universal gap.

## Exact all-test counting lemma

Let a distinct-point Reed--Solomon code have length `n` and dimension `k`: its polynomials have degree less than `k`. Keep the same scalar-extension-field parameter `alpha`, extension-field word `U`, and base-field word `V`. Select one bad full support `H_alpha` of size `h_alpha` per retained parameter, where badness now means that `V` is not degree-less-than-`k` polynomial on `H_alpha`.

Every `k`-subset `S` of `H_alpha` has at least one point `x` of `H_alpha` outside `S` at which the unique interpolant to `V` on `S` fails. Otherwise that interpolant would code `V` on the whole support. Consequently the number of `(k+1)`-subsets `T` of `H_alpha` on which `V` is not coded is at least

    choose(h_alpha,k)/(k+1).

Indeed, each `k`-subset gives at least one pair `(S,x)`, and each resulting `T=S union {x}` has only `k+1` predecessor pairs. This is a statement about the original fixed word `V`, not about an inconsistency in the already consistent word `U+alpha V`.

Such a test `T` belongs to at most one parameter. The evaluation matrix on its `k+1` points has a one-dimensional left kernel over `F_p`; let a nonzero kernel vector be `c`. Non-coding of `V` means `b=sum_x c_x V(x)` is nonzero. Polynomial consistency of `U+alpha V` gives

    alpha = -[sum_x c_x U(x)]/b.

This determines the entire element of `K`, equivalently all five base-field challenge coordinates. It is not a hyperplane constraint for five unrelated direction words: the same scalar base-field word `V` multiplies every coordinate. The selected tests for distinct parameters are disjoint, giving

    sum_alpha choose(h_alpha,k) <= (k+1) choose(n,k+1).

For ordinary sampling of `q>=k` distinct quotient positions, `choose(h,q)/choose(n,q)<=choose(h,k)/choose(n,k)`. Thus the corresponding entire weighted budget is at most `n-k`. The actual unfurled code has `k=388>20`, so this lemma cannot be applied to it by simply substituting the twenty-query weight.

## Complete 32-point fibers cannot supply the missing counterexample

The map `x->x^32` sends `D` onto a shifted multiplicative coset of size `n=N/32=2^18`, with exactly 32 points in each fiber. In this section assume that both fixed sources are constant on each such fiber. Retain only bad responses whose full support includes at least thirteen complete fibers. This is a restriction on the counted family, not an assertion that every bad support has that shape.

Let `zeta` have order 32. The polynomial `P_alpha(zeta X)-P_alpha(X)` vanishes on all points of every complete agreement fiber. Thirteen complete fibers give 416 roots, more than its degree bound 387, so it is zero identically. Therefore every nonzero coefficient of `P_alpha` has exponent divisible by 32, and

    P_alpha(X)=R_alpha(X^32),    degree(R_alpha)<=12.

In particular the entire support, not just the initially identified thirteen fibers, is a union of full fibers. On the quotient it has size `h_alpha`, with original size `32h_alpha`. The quotient direction word cannot be degree-at-most-12 polynomial on this support, since composing such a lift with `X^32` would give a degree-at-most-384 lift of the original `V`. We can therefore use the all-test lemma with `k=13`.

The original twenty-query weight must still be retained; the queries are not replaced by thirteen distinct quotient queries. The required comparison is

    choose(32h,20)/choose(32n,20) <= choose(h,13)/choose(n,13)

for `13<=h<=n`. First the left side is at most `(h/n)^20`. For real `h>=35`, the logarithmic derivative of `h^20/choose(h,13)` is

    20/h - sum_(i=0..12) 1/(h-i)
      >= 20/h - 13/(h-12)
      = (7h-240)/(h(h-12)) >= 0.

Comparison with the endpoint `h=n` gives the result in that interval. For integer `13<=h<=34`, use `choose(h,13)>=1`, `choose(n,13)<=n^13/13!`, and the exact integer inequality `34^20<13! n^7`. This proves the comparison throughout; an independent exact check also verified every one of its 262132 integer cases.

Combining it with the all-test count gives

    sum_alpha w(32h_alpha)
      <= 14 choose(n,14)/choose(n,13)
      = n-13
      = 262131.

The algebra and sample-weight comparison received a separate read-only review. A non-invariant response in this fiber-constant source class has at most twelve complete fibers. It can still have many agreement points spread among incomplete fibers. Counting or ruling out that remaining family is not accomplished here. In particular, the map `x->x^32` is not a universal code-dimension reduction.

## A fixed interpolation core gives a sharp small budget

This section imposes no fiber or source-structure premise. Fix a set `I` of 388 domain points and retain only responses whose full support contains `I`. Let `U_I` and `V_I` be the unique degree-at-most-387 interpolants to the fixed sources on `I`. Every retained response is forced to be

    P_alpha=U_I+alpha V_I.

Define `A(x)=U(x)-U_I(x)`, `B(x)=V(x)-V_I(x)`, and

    C={x : A(x)=0 and B(x)=0},
    T_alpha={x : B(x)!=0 and alpha=-A(x)/B(x)}.

The full support is exactly `C union T_alpha`. The sets `T_alpha` are pairwise disjoint. Badness is equivalent to `T_alpha` being nonempty: any degree-at-most-387 lift of `V` on a support containing `I` must equal `V_I`, and it fails on such a bucket. Set `c=|C|` and `R=N-c`. The nonempty bucket sizes `b_1,...,b_M` satisfy `sum b_i<=R`.

Because `choose(c+b,20)` is a discrete convex function of `b`, for fixed `M` its sum is maximized by `M-1` singleton buckets and one bucket of size `R-M+1`. This bounds the weighted sum by

    (M-1) w(c+1)+w(N-M+1).

This expression is itself convex in the integer variable `M`. Its endpoint values for `1<=M<=R` are `1` and `R w(c+1)`. Hence the fixed-core family has budget at most

    max(1, (N-c) choose(c+1,20)/choose(N,20)).

For the actual `N`, the second expression is largest at `c+1=7989152`; its value is approximately `150551.5459705298`, and exact integer comparison places it below `2^18`. To check the maximizing index, put `t=c+1`; the ratio of adjacent values of `(N+1-t) choose(t,20)` is at least one exactly when `21t<=20(N+1)-1`.

Consequently, if the selected bad supports can be covered by at most `2^35` fixed 388-point cores, where every support contains one whole core, then their entire weighted sum is below `2^53`. The bucket-convexity argument and maximizing-index algebra also received a separate read-only review. This is only a sufficient criterion. No such core cover has been constructed or proved to exist for arbitrary fixed `U,V` and arbitrary responses. Unioning over all 388-subsets is much too expensive. A common-core argument without its cover count is not a universal MCA proof.

## Current literature does not remove these premises

The March 2026 Kumar--Ron-Zewi survey gives the exact subfield-evaluation threshold `(n+r(k-1)+1)/(r+1)` with `r<=s`, where `s` is the alphabet extension degree. With the actual `s=5`, `k=388`, and `n=N`, the best displayed choice requires at least 1398424 agreements. Its constant-list refinement uses a restricted subcode. Its explicit large-list construction instead uses characteristic-two additive subspaces. Neither statement supplies a bound or counterexample for arbitrary sources on this fixed prime-field multiplicative coset in the missing low-agreement interval. These are direct hypothesis checks, not a claim that every relevant coding-theory result has been surveyed. [Kumar and Ron-Zewi, Sections 3.4, 4.3, and 5.3](https://arxiv.org/html/2603.03841v1).

## Reproducible arithmetic and freeze boundary

The following Python standard-library calculation makes no files or cache writes. It checks the original-query comparison on all relevant integer quotient support sizes and checks the exact fixed-core upper bound. The analytic arguments above, not finite experiments alone, establish the two inequalities.

    from math import comb, factorial
    N = 2**23
    n = N//32
    assert 34**20 < factorial(13)*n**7
    denominator = comb(N,20)
    quotient_denominator = comb(n,13)
    for h in range(13,n+1):
        assert (comb(32*h,20)*quotient_denominator
                <= denominator*comb(h,13))
    t = (20*(N+1)-1)//21 + 1
    assert t == 7989152
    assert (N+1-t)*comb(t,20) < 2**18*denominator
    assert n-13 == 262131
    assert (N+5*387+1+5)//6 == 1398424

The query-comparison and core-bound assertions passed in a source-only process using no Lean/build slot. The thirty-minute research checkpoint remains: no universal `B_416<=2^53` proof, no actual-coset counterexample, and no authorization to replace the missing theorem by either restricted result. The unresolved family includes arbitrary sources with five-coordinate parameter freedom and supports with no controlled interpolation-core cover or complete-fiber structure.
