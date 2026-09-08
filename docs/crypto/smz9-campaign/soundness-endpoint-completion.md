# SMZ9 soundness endpoint: completed large-quotient source theorem

Date: 2026-09-07. The arbitrary-source accepted-byte soundness endpoint remains
open. This document proves an all-response bound for a concrete source family
that the preceding weighted-MCA checkpoint left unresolved. It supplies no
universal MCA inequality or completed QROM composition.

## Exact current target

Let `p=2^64-2^32+1`, `K=F_(p^5)`, `N=2^23`, and `d=387`. For the current
shifted multiplicative coset `D`, put

```text
w(g) = choose(g,20)/choose(N,20).
G(alpha,P) = {x in D : U(x)+alpha V(x)=P(x)}.
```

The fixed sources are `U:D->K` and `V:D->F_p`. Each response `P in K[X]`
has degree at most `d` and may depend arbitrarily on the complete challenge.
A full support is bad when it has at least 416 points and `V` has no
degree-at-most-`d` polynomial lift on all of that support. The line budget
is the sum, over distinct `alpha in K`, of the maximum bad-response weight.

The factor-free matrix reduction and current conservative isolated quantum
accounting require

```text
1280 * 2^256 * [w(415) + p*B_416/((p-1)*p^5)] < 1.
```

The previously established exact allowance is approximately `2^53.67807`.
The proof below covers its stated sources with budget less than two. It
does not give the required bound for arbitrary `U,V`.

## Every response on the large quadratic quotient sources

Fix a power of two `m` with `512<=m<=2^22`. Write `s=N/m`, and let `Y=x^m`
map `D` onto its `s` quotient values, each with exactly `m` preimages. Choose
`beta in F_p` outside that quotient set and fix any `A,B,C in K`. Consider

```text
V(x) = 1/(Y-beta),
U(x) = A*Y+B+C/(Y-beta).
```

This includes all five-coordinate quadratic numerators in `Y` divided by
`Y-beta`: polynomial division gives precisely the displayed form. In
particular it includes the actual `r=2` quotient/pole source from
[the preceding checkpoint](weighted-mca-universal-final.md). The proof
counts every bounded response, including responses not obtained by choosing
quotient subsets.

### Bad parameters occupy one affine base-field line

If `A=0`, every parameter except possibly `alpha=-C` yields a lift of `V`
immediately by solving the agreement equation for `V`. Thus the budget is
at most one.

Suppose `A!=0`. If `alpha+C` does not belong to the one-dimensional
base-field space `F_p*A`, choose a base-field linear functional
`L:K->F_p` with `L(A)=0` and `L(alpha+C)=1`. Apply it coefficientwise to
the response polynomial. On the whole agreement support,

```text
V(x) = L(P)(x)-L(B).
```

Evaluation commutes with `L` because every domain point belongs to `F_p`.
This is a degree-at-most-`d` lift, contradicting badness. Therefore every
bad parameter has the unique form `alpha=-C+t*A`, with `t in F_p`.
There are at most `p` such parameters.

Normalize the response to `R=(P-B)/A`. Its agreement equation becomes

```text
R(x) = Y+t/(Y-beta).
```

On any support larger than `d`, the polynomial `R` has base-field
coefficients: expand in a base-field basis of `K` containing one, and apply
the root bound to each other coordinate polynomial. The counting below
also works directly over `K`.

### Nonconstant responses have two simultaneous root ceilings

For a nonconstant `R`, within any one quotient fiber `Y=a`, agreement
requires `R(x)=a+t/(a-beta)`. This nonzero polynomial equation has at most
`d` roots. Summing over the `s` fibers gives `g<=s*d`.

After clearing the nonvanishing denominator, every agreement point is a
root of

```text
F(X) = X^(2m)-beta*X^m+t-(X^m-beta)*R(X).
```

Since `d<m`, its leading term cannot cancel: `degree(F)=2m`. Hence also
`g<=2m`. Every nonconstant response consequently has

```text
g <= min(2m,s*d).
```

### Constant responses have at most one parameter per quotient pair

For constant `R=r`, the agreement equation is the quadratic

```text
Y^2-(beta+r)*Y+(t+r*beta)=0.
```

Thus its full support consists of at most two entire quotient fibers.
Zero or one fiber cannot be bad, because `V` is constant on each individual
fiber. Two distinct quotient values `a,b` determine

```text
r = a+b-beta,
t = (a-beta)*(b-beta).
```

There are therefore at most `choose(s,2)` parameters with a constant bad
response, each of weight `w(2m)`. Distinct quotient pairs may determine the
same parameter; counting pairs only increases this upper bound.

For completeness, two fibers really are bad at these scales. A bounded
lift `H` would make `(X^m-beta)*H(X)-1` vanish at `2m>d+m` points. This
polynomial cannot be zero, since evaluation at any algebraic root of
`X^m-beta` gives `-1`. The root bound rules out the lift.

### Complete finite budget

For each parameter, its maximizing response is either constant or
nonconstant. Adding the two corresponding bounds, even if both classes
occur at the same parameter, gives

```text
B_line(m) <= choose(s,2)*w(2m)+p*w(min(2m,s*d)).
```

For any `g<=N`, sampling without replacement satisfies
`w(g)<=(g/N)^20`. At the dyadic scales considered here,

```text
min(2m,s*d) <= 65536 = N/128.
```

Indeed, for `m<=2^15` use `2m<=65536`; for `m>=2^16` use
`s*d<=128*387=49536`. Since `p<2^64`, the nonconstant term is strictly
less than `2^64*(1/128)^20=2^-76`.

If `s=2`, the constant term is exactly one. Otherwise `s` is a power of
two at least four, and

```text
choose(s,2)*w(2m)
  <= (s^2/2)*(2/s)^20
  = 2^19/s^18
  <= 2^-17.
```

Consequently every source in this family, including the `A=0` case, obeys

```text
B_line(m) < 1+2^-76 < 2.
```

Substituting the conservative envelope `B=2` into the isolated accounting
expression gives a contribution strictly below `2^-148`, with the exact
`w(415)` term retained. Its displayed base-two security is approximately
148.40979 bits. This numerical substitution remains restricted to the
stated source class and the separately supplied quantum multiplier; it
does not establish that multiplier or a complete soundness theorem.

All inequalities above are finite integer or rational inequalities; no
asymptotic estimate, floating-point comparison, candidate-list premise, or
regularity assumption on the response strategy is used.

## What this closes and what it does not

The previous checkpoint left arbitrary responses at `m>=512` outside its
subset-generated witness count. The affine-parameter restriction and the
fiber root bound close that specific gap. The support-only packing family
and the weighted-projection example remain examples about those methods;
they have not been realized by one fixed source and are not attacks.

For unrestricted `U:D->K`, the decisive affine-parameter restriction above
need not hold. Its proof uses the source identity
`U=A*Y+B+C*V`. The existing global-quotient argument allows all `p^5`
parameters when the six quotient words are independent. The current
arbitrary-source recovery theorem still consumes the universal line-budget
inequality; this restricted result does not fill that premise.

Moreover, a universal finite MCA bound would close only the classical
sampling component. The actual accepted-byte event still needs the
commitment-to-source extraction and pre-PIOP candidate chronology. The
logical-QROM theorem separately requires its two-sided instability bound
and the raw SHA-512-to-logical-oracle transfer. Neither a passing
fixed-monomial sampled-acceptance theorem nor the source theorem above
constructs those reductions.

## Reproducible exact arithmetic

This bounded standard-library check verifies every dyadic scale, using exact
integers. It allocates no evaluation domain, source table, or proof artifact.

```python
from math import comb

p, N, d = 2**64-2**32+1, 2**23, 387
den = comb(N, 20)
for exponent in range(9, 23):
    m = 2**exponent
    s = N//m
    g = min(2*m, s*d)
    assert g <= N//128
    assert p*comb(g, 20)*2**76 < den
    constant = comb(s, 2)*comb(2*m, 20)
    assert constant <= den
    numerator = constant+p*comb(g, 20)
    assert numerator*2**76 < (2**76+1)*den
    assert numerator < 2*den
isolated_num = comb(415,20)*(p-1)*p**5+2*p*den
isolated_den = den*(p-1)*p**5
assert 1280*2**128*isolated_num*2**148 < isolated_den
```

No Lean module or shared build artifact is changed by this result. This
document is a mathematical proof and exact-arithmetic check, not a
mechanized universal endpoint certificate.
