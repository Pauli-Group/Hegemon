# SMZ9 universal MCA: finite literature boundary

Date: 2026-09-07 (checked through 2026-09-08 UTC).

**Verdict: the exact universal weighted bound remains OPEN.** The checked
primary results below either require more agreement, fail their displayed
finite-parameter construction, or leave an uninstantiated numerical bound.
This is not an impossibility result, a counterexample, or production authority.
No protocol parameter, source restriction, or Lean premise is changed.

## Exact object and necessary quantitative target

The live `SmallWoodV8Smz9McaRecovery.lean` definitions `badResponseWeight`,
`badCoefficientWeight`, `universalLineBudget`, and `smz9LineBudget` use actual
whole supports and arbitrary source functions. `domainSize` in
`SmallWoodV8Smz9DisjointCoset.lean` is **2^23, not 65536**. Write

```text
p = 2^64 - 2^32 + 1; N = 2^23; k = 388; d = k-1 = 387
K = F_(p^5); D = the fixed current multiplicative coset in F_p
U:D->K arbitrary; V:D->F_p arbitrary; alpha in K; P in K[X], deg P<=387
G(alpha,P) = {x in D : U(x)+alpha V(x)=P(x)}
w(a) = choose(a,20)/choose(N,20)
```

Bad means `|G|>=416` and no degree-at-most-387 polynomial lifts `V` on
**all** of `G`. Taking a lift over `K` or over `F_p` is equivalent here:
apply an `F_p`-linear coordinate projection fixing `F_p` to a `K`-lift.
Identifying five rows with `K` is only a change of coordinates, not a
restriction to polynomial sources or low-dimensional response families.

The normalized quantity is
`B416 = sup_(U,V) sum_alpha max_(bad P) w(|G(alpha,P)|)`, with empty maximum
zero. The factor-free reduction and separately budgeted conservative quantum
loss in `weighted-mca-universal-final.md` ask for

```text
1280*2^256 * [w(415) + p*B416/((p-1)*p^5)] < 1.
B_allow = ((p-1)*p^4) * [1/(1280*2^256) - w(415)]
log2(B_allow) = 53.6780708678...; sufficient B416<=2^53 remains unproved.
```

In particular, `p^5*w(832)<B_allow<p^5*w(833)`. Their logarithms are respectively
`53.6767609376...` and `53.7118220809...`. These are comparisons of upper-bound
routes, not assertions that either field-cap configuration is realizable.

## Primary theorem substitutions

### Whole-support MCA: applicable, but only above Johnson

[Improved Proximity Gaps for Reed-Solomon Codes, Theorem 4.6, pp. 28-29](https://www.math.toronto.edu/swastik/rs-proximity-gaps-2025.pdf)
allows arbitrary words and arbitrary distinct evaluation points over a finite
field. Set its field to `K`, curve degree `M=1`, degree parameter `387`, and
`rho=387/N`. Its exceptional event is exactly the relevant support-wise bad
event: on an agreement set, a lift of `V` also gives a lift of `U=P-alpha V`.
Thus whole-support quantification is not an obstacle to applying this result.

Its hypothesis is `gamma<1-sqrt(rho)`, so support size `a` must satisfy
`a^2>387*N`. The first integer is **56978**, not 416. Leaving the lower range
at the field cap yields `p^5*w(56977)=2^175.9570620262...`, far above `B_allow`.
Corollary 4.4's coordinate measure is not the twenty-subset weight; tail
summation, stated below, is the appropriate conversion. The newer
[Bordage--Chiesa--Guan--Manzur theorem, Theorem 5, p. 5](https://drops.dagstuhl.de/storage/00lipics/lipics-vol383-ccc2026/LIPIcs.CCC.2026.24/LIPIcs.CCC.2026.24.pdf)
also stays on the Johnson side, with additional positive slack.

### Prescribed-domain capacity: advertised finite construction fails

[Jeronimo, TR26-169, Theorem 1.2; Proposition 3.8, p. 15; Lemma 4.1, p. 17](https://eccc.weizmann.ac.il/report/2026/169/download)
does provide prescribed-domain MCA asymptotically. Its uniform construction
requires `388+ceil(gamma*N)<=A`, chooses `theta=gamma/2`, and has
`r<Kpad<=A`. Proposition 3.8 chooses
`u0=1/(1-theta)`, `c=u0-2/log(er)`, and requires `c>=(1+u0)/2`.
For every `416<=A<=833`, these imply

```text
gamma<=445/N
log(er)>=4/(u0-1)=8/gamma-4>=8*N/445-4>150000,
but r<=832 implies log(er)<8.
```

Even directly tuning Proposition 3.8 at `A=416` gives
`theta<=29/416`, hence `log(er)>=1548/29>53`, again impossible with `r<=415`.
These contradictions exclude the advertised choices, not all possible finite
interpolants. Proposition 3.7 and other direct finite tuning remain
uninstantiated alternatives. Section 8.4, p. 32, expressly permits extension
fields when `p>max(k-1,B_(gamma,L))`; extension degree five is **not** a
rejection reason. Section 8.5 requires finite length/field checks and supplies
no competitive prescribed-length certificate.

### Another all-rates capacity result: direct hypotheses fail

[BCPZZ, TR26-164 revision 1, Theorem 4.1, p. 20; Corollary 5.1 and proof, pp. 22-23](https://eccc.weizmann.ac.il/report/2026/164/revision/1/download)
requires `k>ceil(epsilon^(-3/theta))`, `0<theta<1`. At any `A<=833`, putting
`epsilon=A/N` gives `epsilon<1/10000`, so the required dimension exceeds
`10^12`, not 388. The proof's all-rates padding chooses
`eta<A/N`, `k'>eta^(-3/theta)`, and length `n'>=k'/((1-theta)*eta)`.
It needs `eta*n'<=A`; instead `eta*n'>10^12>A` here.
The corollary's abstract statement uses an implicit field constant and a
`q^O_(R,delta)(1)` list bound. The calculation excludes this displayed padding
certificate, not every interpretation or finite implementation of that
corollary. No sufficiently small numerical list bound was obtained from it.

### Finite MDS counting and shortening: applicable but vacuous

[Chojecki, author manuscript, equations (1.3), (SH2), and their proofs](https://raw.githubusercontent.com/przchojecki/rs-mca/refs/heads/main/RS_MCA_Paving_v9.2.tex)
reproduces [Jo's Theorems 4.2 and 3.2](https://eprint.iacr.org/2026/1432).
The reproduced proofs were checked; Jo's original PDF was unavailable.
For the number `M(a)` of parameters with a bad support of size at least `a`,
the all-test envelope is

```text
M(a) <= min(p^5, min_(389<=b<=a) floor(choose(N,b)/choose(a-1,b-1))).
```

For `416<=a<=833`, every ratio exceeds `(N/833)^389>p^5`, so this envelope
is exactly the field cap. Johnson-safe shortening by `t<388` positions needs
`t=387`: every `t<=386` still has `(a-t)^2<=(N-t)*(387-t)`.
This leaves a dimension-one code, outside the displayed positive-degree
formula of Theorem 4.6. The counting multiplier
`choose(N,387)/choose(a,387)` alone exceeds `(N/833)^387>p^5`, so even an
ideal universal shortened numerator of one would give no saving.
The explicit MDS and shortening envelopes are numerically instantiated but
vacuous here, unlike the uninstantiated capacity alternatives above.

### Subfield/interleaving results: missing range or base bound

[Guruswami--Xing, Section 7.1, Definition 6 and Lemmas 7.1, 7.3-7.4, pp. 25-27](https://eccc.weizmann.ac.il/report/2020/172/download/)
allows these distinct base-field points. With five Frobenius coordinates and
punctured length `n=N-1`, its interpolation threshold is
`floor((n-388+1)/6)+388 = 1398424` outside agreements. Its candidates lie in
an `F_p`-affine space of dimension at most `4*388=1552`; this does not place
the entire selected response family in one `K`-affine space of dimension at
most 21. Later small-list guarantees restrict the code.
[Jo's 2026/891 author abstract](https://eprint.iacr.org/2026/891)
does state all-radius interleaving transfer, but transfers an existing
base-code bound rather than proving the missing one. Abstract only was
available: no theorem/page claim is made for that paper.

## Exact one-point subclass and remaining obligation

Fix `x0 in D`, `V=1_{x0}`, `U(x0)=0`, and arbitrary
`u=U|_(D\{x0})`. Set `H(P)={x!=x0:P(x)=u(x)}`. Exactly,

```text
B_delta(u) = sum_(a in K)
  max_(deg P<=387, P(x0)=a, |H(P)|>=415) w(1+|H(P)|).
```

If `alpha!=P(x0)`, the full support excludes `x0`, so `V=0` there and is
good. Otherwise a putative lift would have at least 415 zeros but value one
at `x0`, impossible in degree 387. This is an actual fixed-source subclass,
not an abstract support-packing problem.

For arbitrary sources let `M(a)` count parameters whose largest bad full
support has size at least `a`. The exact layer-cake identity is

```text
B(U,V) = w(416)*M(416)
       + sum_(a=417..N) [w(a)-w(a-1)]*M(a).
```

For the one-point subclass, `M(a)` counts distinct extrapolated values
`P(x0)` among polynomials with `|H(P)|>=a-1`. An ordinary list-size bound
would suffice, but grouping by extrapolated symbol may be strictly sharper.
No checked result bounds this functional below `B_allow` universally. A direct
finite support-tail bound, with the displayed weighted sum below `B_allow`, is
still needed; a restricted source/response theorem cannot replace it.


## Additional direct finite reduction

The [five-coordinate stress reduction](weighted-mca-stress-reduction.md)
removes the arbitrary source words and response polynomials exactly, replacing
their simultaneous realizability with a finite-dimensional annihilator condition
on shortened dual Reed–Solomon spaces. It retains all actual whole supports and
all five coefficient coordinates. This is a derived mathematical equivalence,
not a proved numerical bound or a Lean endpoint.

The [seventeen-witness barrier](weighted-mca-seventeen-witness-barrier.md)
constructs an actual-domain support family whose abstract weight exceeds the
allowance, while every at-most-seventeen subfamily has exact bad whole-support
realizations. Those local realizations use different source words. Consequently
this is neither a global source attack nor an impossibility result for the
desired bound; it excludes using only forbidden subfamilies of that bounded
size. Exact integer/rational checks confirm the displayed support capacities
and the abstract score ratio `1.023670357449717...`. Global compatibility and
the required universal weighted inequality remain open.

## Exact arithmetic reproduction

Run this standard-library Python snippet; it performs no file writes.
Every asserted comparison is integer/rational. Decimal logarithms above are
only diagnostics, not acceptance tests.

```python
from fractions import Fraction as F
from math import comb, factorial, isqrt
p, N, k = 2**64 - 2**32 + 1, 2**23, 388
q = p**5
w = lambda a: F(comb(a, 20), comb(N, 20))
B_allow = (p-1)*p**4 * (F(1, 1280*2**256) - w(415))
assert 2**53 < B_allow
assert q*w(832) < B_allow < q*w(833)
assert isqrt(387*N) == 56977
assert 56977**2 < 387*N < 56978**2
assert q*w(56977) > B_allow
assert F(8*N, 445)-4 > 150000
assert F(1548, 29) > 53
# e<3 and this lower bound on e^8 prove e*832<e^8, so log(e*r)<8.
assert sum((F(8**j, factorial(j)) for j in range(16)), F(0)) > 3*832
assert 833*10000 < N and k < 10**12
assert N**389 > q*833**389
assert N**387 > q*833**387
assert all((833-t)**2 <= (N-t)*(387-t) for t in range(387))
assert ((N-1)-388+1)//6 + 388 == 1398424
print("All finite cutoff comparisons passed; universal B416 remains open.")
```
