# Finite obstruction to the additive local-rank interpolation route

Date: 2026-09-08. This is an independently reviewed mathematical derivation,
not a Lean proof or a universal MCA certificate. The actual arbitrary-source
weighted bound remains **OPEN**. No protocol parameter is changed.

## Exact subject and result

The live problem has `p=2^64-2^32+1`, `N=2^23`, degree at most `387`,
and five coefficient coordinates over the base field. It can be expressed
over `K=F_(p^5)` and its rational-function field without changing the fixed
evaluation domain. See [the exact shared-source formulation](weighted-mca-stress-reduction.md).

The interpolation space in Jeronimo's Equations (9)-(15) and Proposition 3.7
uses padded message dimension `Kpad`, `h=Kpad-1`, derivative order
`1<=r<Kpad`, and multiplicity `m=r^3`. Its permitted finite choices satisfy
`388<=Kpad<=A`, where `A` is the desired agreement threshold.
[Primary paper, ECCC TR26-169](https://eccc.weizmann.ac.il/report/2026/169/).

For this exact monomial space `Q`, write `R` for the rank of one actual
local incidence map, not the paper's larger auxiliary rank majorant. Then

    dim Q <= A ceil(A(r+1)/h) R.                              (1)

This holds over any coefficient field, for every positive `m`, and for every
allowed derivative-tail shape. All local incidence maps have the same rank.
For every permitted parameter choice with `388<=A<=2892`, (1) implies

    dim Q < N R = sum_i rank(local incidence map i).

Thus the displayed dimension-versus-sum-of-local-ranks sufficient condition
cannot pass, even if each individual rank and the monomial dimension were
known exactly. It cannot be repaired by tuning the paper's hidden constants
or replacing its rank majorant by a tighter individual bound.

This does **not** lower-bound the rank of the globally stacked map. Its
different incidence blocks can be dependent. A global-dependence proof or
a different interpolation space is not excluded.

## Proof of the finite rank bound

The monomial basis consists of `X^a Y0^b Y1^b1 Y^v` subject to the stated
tail and degree conditions, including

    a+h(b+b1+|v|)<mA,  b1<=m,  b+b1+|v|<=ceil(mA/h).

Its essential property here is downward closure in `a` and `b`. Translations
of `X` and `Y0` therefore act invertibly on `Q`, and turn any point-symbol
incidence into `(0,0)`. Hence every local map has rank `R`.

At `(0,0)` the actual substitution is

    X=T,
    Y0=T E + sum_(j=1..r) (-1)^(j+1) T^j Yj.

The map records precisely the coefficients of terms with `T`/`E` weight
`i+r e<m`. Every term obtained from a monomial with
`a+(r+1)b<m` is recorded. The untruncated substitution is injective: the
highest nonzero `Y0` coefficient becomes the highest `E` coefficient,
multiplied by a power of `T`, and cannot vanish in the polynomial ring.
Thus the number `G` of such admissible monomials satisfies `G<=R`.

Set `Lb=ceil(A(r+1)/h)`. Send each admissible monomial to the one with
exponents `(floor(a/A),floor(b/Lb),b1,v)`. Downward closure keeps the image
in `Q`, and

    floor(a/A)+(r+1)floor(b/Lb) <= (a+h b)/A < m.

The image is counted by `G`. Each image has at most `A Lb` preimages, so
`dim Q<=A Lb G<=A Lb R`, proving (1). This argument is characteristic
independent and also covers `r=m=1`.

## Exact finite and weighted consequences

Since `r<=h` and `h>=387`,

    A ceil(A(r+1)/h) <= A(A+ceil(A/387)).

The monotone right side is `696388` at `A=833` and `8386800` at `A=2892`,
still `1808` below `N=8388608`. Since the constant monomial gives `R>=1`,
the required strict dimension comparison fails throughout that range.
The coarse envelope exceeds `N` at `A=2893`; this is not a success
certificate there. Characteristic-size constraints are not the obstruction:
`ceil(r^3 A/h)<=h^2 A<A^3<p` and `r^3 A<A^4<p^2` in the excluded range.

For `w(a)=choose(a,20)/choose(N,20)`, the isolated allowance is

    B_allow=(p-1)p^4(1/(1280*2^256)-w(415)).

If `M(a)` counts coefficients with a bad full support of size at least `a`,
the exact layer-cake identity is

    B=w(416) M(416)+sum_(a=417..N)(w(a)-w(a-1)) M(a).

An upper-bound route that uses only the field cap `M(a)<=p^5` below some
threshold has envelope at least `p^5 w(a0-1)`, even if it gives the idealized
zero bound at and above `a0`. Exact arithmetic gives

    p^5 w(832)<B_allow<p^5 w(833),
    p^5 w(2892)>2^36 B_allow.

Consequently, leaving this range unresolved cannot meet the allowance.
The latter ratio is approximately `78,067,440,765.8`; it is a lower bound on
that proposed **upper-bound envelope**, not on any realizable source's `B`.

## Explicit boundary and validation

A nonzero common global kernel can exist despite this rank-sum obstruction.
If the received symbols are `P0(x_i)` with `degree(P0)<=h`, then
`Q0=(Y0-P0(X))^m` belongs to the same monomial space. At each local incidence,
the substituted inner factor is divisible by `T`, so `Q0` satisfies every
local constraint. Taking `P0=0` also respects the original unpadded degree
bound. Failure of the additive certificate is therefore not a proof that
every global interpolant vanishes.

Two independent mathematical reviews checked the translation, injectivity,
floor-map fiber count and claim boundaries. A standard-library exact-integer
and rational check covered every `388<=A<=2892` and every permitted padded
`h`, with all `r` covered by monotonicity, plus the weighted comparisons.
The scratch reproduction is
`/private/tmp/smz9-weighted-stress.C6mft8/prop37_finite_rank_budget_checks.py`.
These are finite arithmetic and reviewed mathematical evidence, not a
machine-checked universal MCA result. The remaining task is a competitive
global shared-source argument or a genuine violating source on the actual
domain; this result supplies neither.
