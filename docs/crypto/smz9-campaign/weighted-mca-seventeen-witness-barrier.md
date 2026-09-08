# SMZ9: a seventeen-witness local-realizability barrier

Status: proved finite mathematical restriction on one class of rejection
criteria. This is **not** a globally realized source attack, a universal MCA
bound, a Lean theorem, or production authority. No protocol or source premise
is changed.

## Exact setting and conclusion

Let

```text
p = 2^64 - 2^32 + 1
N = 2^23
k = 388
d = 387
D = the actual fixed N-element Goldilocks evaluation coset
w(g) = choose(g,20) / choose(N,20).
```

There is a family of 833-element subsets `S_alpha` of this actual domain,
one for every `alpha in F_p^5`, such that:

1. Its abstract weighted score is `p^5 w(833) > B_allow`.
2. Every subfamily of at most seventeen labeled supports is simultaneously
   realizable by one base-field word `V:D->F_p`, one five-coordinate word
   `U:D->F_p^5`, and degree-at-most-387 responses.
3. For each such local realization, the prescribed sets are the **exact full
   joint agreement supports**, and `V` has no degree-at-most-387 lift on any
   of them.

The words and responses in item 2 may differ between subfamilies. No single
pair `U,V` realizing the entire family is constructed or asserted.

## 1. Build the support family on the actual domain

Use an auxiliary field `Q = F_(2^13)` solely as a combinatorial indexing set.
Choose a set `A subset Q` with `|A|=833`. The grid has size

```text
|A x Q| = 833 * 8192 = 6,823,936 < 8,388,608 = N.
```

Fix any injection `iota:A x Q -> D`. No homomorphism between the auxiliary
field and Goldilocks is needed or asserted.

For each polynomial `f in Q[X]` of degree at most 24, form the support

```text
S_f = {iota(x,f(x)) : x in A}.
```

Each support has exactly 833 points. Distinct polynomials have distinct
supports, because a nonzero polynomial of degree at most 24 cannot vanish
at all 833 points of `A`. The same root bound gives

```text
|S_f intersect S_g| <= 24          for f != g.
```

There are

```text
8192^25 = 2^325 > p^5
```

such polynomials: there are 25 freely chosen coefficients, and
`p < 2^64` implies `p^5 < 2^320`. Choose an injection from `F_p^5` into this
polynomial family and label its selected supports by the challenge vectors.
The family now has one support `S_alpha` for every actual challenge vector.
Its intersection bounds are preserved by the injection into `D`.

## 2. The abstract score exceeds the exact allowance

Write `C_g = choose(g,20)` and `C_N = choose(N,20)`. The isolated allowance is

```text
B_allow = (p-1) p^4 * [1/(1280 * 2^256) - C_415/C_N].
```

The required comparison `p^5 C_833/C_N > B_allow` is exactly the positive
integer comparison

```text
1280 * 2^256 * [(p-1) C_415 + p C_833] > (p-1) C_N.
```

This is the `833` comparison already recorded in
`docs/crypto/smz9-campaign/mca-universal-literature-boundary.md`, where the
exact arithmetic establishes `p^5 w(832) < B_allow < p^5 w(833)`.
No floating-point approximation is needed for this comparison. No checker
was run to create this proof note.

## 3. Every at-most-seventeen subfamily is locally realizable

Fix any selected subfamily with distinct labels
`alpha_1,...,alpha_m`, where `1 <= m <= 17`. Write its supports as
`S_1,...,S_m`. Define the shared and private parts of each support by

```text
T_i = S_i intersect union_(j != i) S_j
E_i = S_i \ T_i.
```

The graph intersection bound gives

```text
|T_i| <= sum_(j != i) |S_i intersect S_j|
      <= 24(m-1) <= 384.
```

Thus `E_i` is nonempty (in fact it has at least 449 points), and the private
sets `E_i` are pairwise disjoint. Choose one point `y_i in E_i` for each `i`.
All remaining arithmetic and polynomial constructions are now over the
actual field `F_p` and the actual coordinates of points in `D`.

Put

```text
L_i(X) = product_(x in T_i) (X-x),
P_i(X) = b_i L_i(X),              b_i in F_p^5 \ {0}.
```

The empty product is one. These are five-coordinate polynomials with

```text
degree(P_i) <= |T_i| <= 384 <= 387.
```

Define the common scalar word by

```text
V(x) = 1  if x is one of y_1,...,y_m,
       0  otherwise.
```

Define the common five-coordinate word by

```text
U(x) = P_i(x) - alpha_i V(x)   if x in E_i,
       0                      otherwise.
```

This is well-defined because the `E_i` are disjoint. If `x in E_i`, the
agreement equation for index `i` holds by definition. If `x in T_i`, then
`L_i(x)=0`, `U(x)=0`, and `V(x)=0`: no private point `y_j` belongs to a shared
position. Therefore

```text
U(x) + alpha_i V(x) = P_i(x)      for every x in S_i.
```

### Badness is exact and independent of coefficient choices

On `S_i`, the word `V` is precisely the one-point delta at `y_i`: no other
private point `y_j` can lie in `S_i`. A polynomial agreeing with `V` on all
of `S_i` would have 832 distinct zeros and value one at `y_i`. This is
impossible in degree at most 387, over `F_p` or any extension field.
Consequently every designated support is bad.

## 4. Choose coefficients to make every full support exactly S_i

It remains to rule out accidental agreements outside each prescribed
support. Initially choose `b_1,...,b_m` independently and uniformly from
`F_p^5`; exclude the following events.

First exclude `b_i=0` for each `i`. Each has probability `p^-5`.

For every ordered pair `i != j` and every `x in E_j`, exclude the affine
vector equality

```text
b_i L_i(x) = b_j L_j(x) + (alpha_i-alpha_j) V(x).
```

Here `x notin S_i` by privacy of `E_j`, so `L_i(x) != 0`. Conditional on
`b_j` and all other coefficient vectors, exactly one value of `b_i` makes
this equality hold. Each excluded collision therefore has probability
exactly `p^-5`.

There are at most

```text
m + m(m-1) * 833
    <= 17 + 17*16*833
     = 226593 < 226594 < 2^18 < p^5
```

excluded events. The union bound gives total probability strictly less
than one, so a choice of all the coefficient vectors avoiding every event
exists.

Fix such a choice. For an index `i` and a point `x notin S_i`, there are two
cases.

- If `x in E_j` for some `j != i`, the excluded collision is precisely the
  equation `U(x)+alpha_i V(x)=P_i(x)`. Thus no accidental agreement occurs.
- Otherwise `x` is either shared among other supports or outside the entire
  support union. In either case `U(x)=V(x)=0`. Since `x notin S_i`, it is not
  in `T_i`, so `L_i(x)!=0`; since `b_i!=0`, the vector `P_i(x)` is nonzero.
  Again there is no accidental agreement.

Hence the exact full joint agreement set is

```text
{x in D : U(x)+alpha_i V(x)=P_i(x)} = S_i
```

for every index in the chosen subfamily. In particular the argument does
not rely on silently enlarging the proposed supports.

## 5. Equivalent local dual-space explanation

Let `C=RS_387(D)` and `H_i=C^perp intersect F_p^(S_i)`. The minimum support
size of a nonzero vector in `C^perp` is `k+1=389`: any at-most-388 columns of
the degree-at-most-387 Vandermonde generator matrix are independent.

If `sum_i h_i=0` with `h_i in H_i`, then `h_i` vanishes at every private
point of `S_i`; only another summand could cancel a nonzero coordinate.
Thus `support(h_i) subset T_i`, whose size is at most 384. The dual minimum
support bound forces every `h_i=0`. Therefore the `H_i` form a direct sum.

In the five-coordinate stress formulation, this says the relation space
and hence the stress space are zero for every such local subfamily. The
explicit construction above strengthens that local feasibility statement
by ensuring exact whole supports.

## Precise scope of the barrier

This overbudget abstract family has **no non-realizable subfamily of at
most seventeen labeled witnesses**, even when a witness is required to be
an exact bad full support on the actual Goldilocks domain. A rejection
criterion based solely on finding such a forbidden local subfamily cannot
rule it out.

The conclusion does not rule out proofs that aggregate local identities
through global shared-source constraints. In particular, the local words
constructed for two different subfamilies need not be compatible. There
is no construction here of one global `U,V` realizing all `p^5` supports,
and thus no actual source counterexample to the universal weighted bound.
The auxiliary-field graphs supply only the support system; the unresolved
obligation remains simultaneous realizability for the entire family.
