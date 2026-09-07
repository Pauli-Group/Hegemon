# SMZ9 universal weighted MCA: final bounded checkpoint

Date: 2026-09-07. The unrestricted endpoint is **OPEN**. This note excludes a
concrete smooth-domain counterexample mechanism; it does not prove the
universal line bound, a QROM theorem, or production security. No protocol,
runtime, relation, or retained artifact changes here.

## Exact endpoint

Put

```text
p = 2^64 - 2^32 + 1
N = 2^23
d = 387
K = F_(p^5)
w(g) = choose(g,20) / choose(N,20).
```

For arbitrary fixed `U:D->K` and `V:D->F_p`, and `alpha in K`, a response is
any `P_alpha in K[X]` of degree at most `d`. Its full agreement support is

```text
G_alpha = {x in D : U(x) + alpha V(x) = P_alpha(x)}.
```

It is bad when `|G_alpha|>=416` and `V` has no degree-at-most-`d` lift on all
of `G_alpha`. The unresolved quantity is

```text
B_416 = sup_(U,V) sum_alpha max_(bad P_alpha) w(|G_alpha|).
```

The factor-free matrix reduction and the conservative separate quantum loss
require

```text
1280 * 2^256 * [w(415) + p B_416 / ((p-1)p^5)] < 1.
```

Solving this exact inequality for `B_416` gives a base-two allowance of
approximately `53.6780708678`. The convenient sufficient target
`B_416<=2^53` remains unproved.

## The quotient/pole family being screened

This section concerns the construction in Appendix A of
[Krachun--Kazanin--Haboeck](https://eprint.iacr.org/2026/782), not arbitrary
sources. Let `m` be a power of two dividing `N`, let `s=N/m`, and let
`pi:D->G` be the `m`-to-one quotient `pi(x)=x^m` onto the corresponding
shifted quotient coset. Fix `beta in F_p` outside `G` and take the common pole

```text
V(x) = 1 / (pi(x) - beta).
```

For an `r`-subset `S` of `G`, set

```text
v_S(Y) = product_(a in S) (Y-a)
p_S(Y) = Y^r - v_S(Y).
```

Then `degree(p_S)<=r-1`, and

```text
q_S(X) = [p_S(pi(X)) - p_S(beta)] / [pi(X)-beta]
```

has degree at most `(r-2)m`. On the line with numerator `Y^r`, the parameter
`alpha_S=-p_S(beta)` gives exact agreement on the `rm` points in
`pi^-1(S)`. With five coordinates, allow five subsets `S_1,...,S_5`; the
common full support is the inverse image of their intersection. This is a
generous model: the original scalar construction supplies fewer parameter
vectors than an arbitrary deterministic map from subset tuples into `F_p^5`.

## Ambient badness forces all five subsets to coincide

Suppose a designated common support contains `h` complete quotient fibers.
The pole has an exact lift dichotomy on that support.

If `(h-1)m<=d`, interpolate `1/(Y-beta)` on the `h` quotient values with a
polynomial of degree at most `h-1`, then compose with `pi`. This produces a
degree-at-most-`d` lift of `V`, so the support is not bad.

If `(h-1)m>d`, a putative degree-at-most-`d` lift `R` would make

```text
(pi(X)-beta)R(X)-1
```

vanish at `hm>d+m` points despite having degree at most `d+m`. It cannot be
the zero polynomial: at a root of `pi(X)-beta` over the algebraic closure its
value is `-1`. Thus no lift exists. These two cases are complementary, so a
complete-fiber support is bad exactly when `(h-1)m>d`.

Admissibility of the constructed response gives

```text
(r-2)m <= d,
r <= floor(d/m)+2.
```

Badness and `h<=r` give

```text
h >= floor(d/m)+2.
```

Therefore every ambient-bad designated witness has

```text
h = r = floor(387/m)+2,
S_1 = S_2 = S_3 = S_4 = S_5.
```

This is the key point: five independently chosen quotient subsets cannot
multiply the bad-witness count. Even if five different invariants of the one
remaining subset are used as challenge coordinates, there are at most

```text
min(p^5, choose(s,r))
```

distinct parameters.

The resulting constructed-witness budget is

```text
B_KKH(m)
  <= min(p^5, choose(N/m,r)) * choose(mr,20) / choose(N,20),
r = floor(387/m)+2.
```

The threshold `mr>=416` first occurs at `m=16`. The maximum over all
admissible quotient scales is

```text
B_KKH(16)
  <= p^5 * choose(416,20) / choose(2^23,20)
  = 2^33.3393600054479...
  < 2^34.
```

This is `20.3387108623` bits below the exact isolated allowance. At the next
scales the logarithms of the constructed-witness bounds are:

| `m` | `r` | `mr` | `log2 B_KKH(m)` |
|---:|---:|---:|---:|
| 16 | 26 | 416 | 33.3393600054 |
| 32 | 14 | 448 | -68.8175525076 |
| 64 | 8 | 512 | -159.8417877831 |
| 128 | 5 | 640 | -200.9012336365 |
| 256 | 3 | 768 | -226.2457883351 |
| 512 | 2 | 1024 | -233.2694584812 |

For all larger nondegenerate powers of two, this constructed-witness bound
remains at most one; at the final scale `m=2^22`, `s=r=2`, it equals one.
Even summing the bounds over every admissible scale gives logarithm only
`33.3393600056`.

## Stronger bound for all responses on the smaller quotient lines

For the explicit maximal-`r` KKH source, not merely its subset-generated
response, any ambient response `P` has agreement zeros among the roots of

```text
Y^r|_(Y=pi(X)) + alpha - (pi(X)-beta)P(X).
```

Here `rm>d+m`, so the leading term cannot cancel and this nonzero polynomial
has degree `rm`. Consequently every response has agreement at most `rm`, and
the whole five-coordinate line satisfies

```text
B_line(m) <= p^5 w(mr).
```

For `m=16,32,64,128,256`, the respective base-two logarithms are

```text
33.3393600054
35.5261981871
39.4577284324
46.0058771003
51.3393062500.
```

All five pass the exact conservative isolated inequality, with the tightest
margin `2.3387646178` bits at `m=256`. At `m>=512`, this crude all-response
cap no longer fits; only the subset-generated KKH witnesses above have been
excluded there. Arbitrary cancellation supports at those scales are not
silently counted as part of the construction.

## A support-packing obstruction to support-only proofs

The convenient `2^53` target cannot be proved from support cardinality,
pairwise-intersection, or interpolation-core packing alone. At `g=813`, an
abstract family containing one support for every `alpha in K` would have score

```text
p^5 * choose(813,20) / choose(N,20)
  = 2^53.00237390462212...
  = 1.0016468198166157... * 2^53.
```

This crosses the convenient target slightly, though it remains below the
larger exact isolated allowance `2^53.6780708678`.

Such an abstract support family exists even with every pair intersecting in
at most `387` points. For one chosen `813`-set, the number of other
`813`-sets having intersection at least `388` with it is

```text
sum_(i=388..813) choose(813,i) choose(N-813,813-i).
```

The exact greedy inequality

```text
choose(N,813)
  > p^5 * sum_(i=388..813)
      choose(813,i) choose(N-813,813-i)
```

therefore constructs `p^5` sets with pairwise intersections at most `387`:
after fewer than `p^5` selections, the union of all deleted conflict
neighborhoods is still smaller than the full set space. The stronger
`388`-core packing audit also has enormous room,

```text
p^5 choose(813,388) <= choose(N,388),
```

with base-two ratio slack `5014.7339067811` bits.

This is compatible with a concrete bad direction on the actual shifted
Goldilocks coset: take `V(x)=x^388`. On any `813` distinct domain points, a
degree-at-most-`387` lift would make `X^388-R(X)` have more than `388` roots,
which is impossible.

This is **not a source counterexample**. No one fixed word `U` and family of
degree-at-most-`387` responses realizing these supports for all `p^5`
parameters has been constructed. Precisely that missing simultaneous
realizability is the information discarded by support-only arguments. A
universal proof at `2^53` therefore needs a new cross-core algebraic incidence
inequality tying the shared `U`, the response polynomials, and distinct
parameters together.

## Reproducible exact arithmetic

The assertions below use exact integers for every security comparison. The
decimal logarithms are display values only.

```python
from math import comb, log2

p = 2**64 - 2**32 + 1
N = 2**23
d = 387
loss = 1280 * 2**256
den = comb(N, 20)
small = comb(415, 20)

def isolated_passes(budget_numerator):
    # budget_numerator / den is the normalized line budget.
    return (loss * (small * (p-1) * p**5 + p * budget_numerator)
            < den * (p-1) * p**5)

constructed_total = 0
rows = []
for j in range(24):
    m = 2**j
    s = N // m
    r = d // m + 2
    if r > s or m*r < 416:
        continue
    numerator = min(p**5, comb(s, r)) * comb(m*r, 20)
    constructed_total += numerator
    rows.append((m, r, m*r, log2(numerator / den)))

assert max(rows, key=lambda row: row[3])[:3] == (16, 26, 416)
assert p**5 * comb(416, 20) < 2**34 * den
assert isolated_passes(constructed_total)
assert log2(constructed_total / den) < 33.3393600056

# A support-only packing model already crosses the convenient 2^53 target.
g = 813
k = 388
abstract_numerator = p**5 * comb(g, 20)
assert abstract_numerator > 2**53 * den
assert 53.0023739046 < log2(abstract_numerator / den) < 53.0023739047
assert (1.0016468198
        < abstract_numerator / (2**53 * den)
        < 1.0016468199)

conflict_ball = sum(comb(g, i) * comb(N-g, g-i)
                    for i in range(k, g+1))
assert comb(N, g) > p**5 * conflict_ball
assert p**5 * comb(g, k) <= comb(N, k)
packing_slack = log2(comb(N, k)) - log2(p**5 * comb(g, k))
assert 5014.7339 < packing_slack < 5014.7340

for m in (16, 32, 64, 128, 256):
    r = d // m + 2
    assert (r-2)*m <= d < (r-1)*m
    assert isolated_passes(p**5 * comb(m*r, 20))

allow_num = (p-1) * p**5 * (den - loss*small)
allow_den = p * loss * den
assert 53.6780708677 < log2(allow_num / allow_den) < 53.6780708679
```

## Why the new capacity theorem does not close this instance

[Jeronimo, TR26-169](https://eccc.weizmann.ac.il/report/2026/169/) proves a
fixed-slack asymptotic MCA theorem with effective constants. Its optimized
interpolant requires `r<K<=A` and an incidence inequality of the form

```text
M <= a_vartheta (K-1) r^vartheta / log^4(er).
```

At `A=416` and actual polynomial dimension `388`, padding forces `K>=388`
and hence `vartheta<=29/416`; also `r<416`, so `r^vartheta<1.53` while the
singleton incidence ratio `M/(K-1)` is above twenty thousand. More
importantly, the theorem leaves `a_vartheta` and the sufficiently-large-length
threshold unevaluated for this shrinking slack. Its Section 8.5 explicitly
claims no useful certificate for a prescribed small block length. It is
therefore not a numerical theorem for this endpoint.

## Final boundary

The equal-fiber, common-pole KKH mechanism is excluded with exact finite
margin. The unrestricted cases of arbitrary `U,V`, non-common quotient
partitions or poles, incomplete-fiber and cancellation supports, and arbitrary
maximizing responses remain outside this result. There is still neither a
proof of `B_416<=2^53` nor an actual-coset source exceeding it. The endpoint
must remain **OPEN**.
