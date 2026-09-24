# Global polynomial-shift stress lemma

Status: new finite mathematical lemma, with a quantitative conditional label
bound. The universal SMZ9 weighted bound remains OPEN. No Lean or Rust jobs
ran. No source restriction, replacement domain, response regularity premise,
or protocol change is made. Only scratch files were written.

## 1. Family, actual domain, and definitions

Fix the actual Goldilocks field and coset, p=2^64-2^32+1 and |D|=N=2^23,
and put k=388. Fix ANY six words U_1,...,U_5,V on D.
Choose distinct labels alpha_i in F_p^5, degree-below-k responses P_i, and
sets S_i contained in their actual full supports, all of the same size a>k.
Require V to be nonpolynomial of degree below k on EACH S_i.

This is a proof device for the unchanged full-support problem. Every bad
full support of size at least a has a bad a-subset: interpolate V on k of
its points, select one point where the interpolant fails, and extend those
k+1 points to a points. No weight is replaced by a restricted-support weight.

Let D0 be the UNION of the selected S_i, N0=|D0|, n=N0-a, and t=a-k-1.
All points still have their actual coordinates in D. Restricting the words
to this union is only an algebraic step in the proof. Define

    Z0(X)=product_(x in D0)(X-x),
    f_i(X)=Z0(X)/product_(x in S_i)(X-x),       degree f_i=n.

Write P_l for the vector space of polynomials of degree at most l.
Identify the dual of RS_{k-1}(D0) with P_(n+t) through

    f -> (f(x)/Z0'(x))_(x in D0).

Then H_i, the shortened dual on S_i, is exactly f_i P_t.
All denominators are nonzero. Define

    F=span{f_i} subset P_n,       u=(n+1)-dim F,
    R={ (b_i): sum_i b_i f_i=0 },
    W=span{ sum_i alpha_(i,j)b_i f_i : b in R, 1<=j<=5 } subset P_n.

W is the COMPRESSED constant-multiplier stress space. It need not equal
the full stress space Z from the authoritative stress reduction.
If W=0, the following criterion gives no conclusion.

For W!=0, let w=dim W and c=(n+1)-w. Homogenize every element of W to
degree n in variables X,Y, and let G(X,Y) be their homogeneous gcd, of
degree delta. All gcds and spaces are over F_p. Equivalently, if
e=max(degree f:f in W) and g is the monic ordinary gcd of W, then

    G = Y^(n-e) * homogenization(g),
    delta=(n-e)+degree g,
    c-delta=e+1-dim W-degree g >=0.

There is no generic-label or generic-evaluation hypothesis.

## 2. The finite global theorem

Suppose W!=0 and the two global inequalities hold:

    c-delta <= t,                 u <= t-delta.             (A)

Then all SIX restricted source classes modulo RS_{k-1}(D0) lie in the
same subspace of dimension delta. More explicitly, for g(X)=G(X,1),
each of the six words T has a polynomial A_T of degree below k+delta with

    g(x) T(x)=A_T(x)              for every x in D0.         (B)

If delta=0, there can be NO bad selected support.

Let E={x in D0:g(x)=0} and e0=|E|<=delta. If, in addition,

    a >= k+delta+e0,                                       (C)

the number m of distinct selected labels is at most max(1,e0), and hence
at most max(1,delta). The easily checked sufficient version of (C) is
a>=k+2delta. These are conditional conclusions: (A) is NOT known to
hold automatically for all large feasible families.

## 3. Elementary polynomial growth lemma

For any nonzero finite-dimensional L subset F[X],

    dim(L+XL) >= dim L+1.

Indeed, multiplying a polynomial of maximal degree by X gives a new degree.
Equality occurs ONLY when L=h P_(dim L-1) for a polynomial h.
Here is a characteristic-independent induction proving that assertion.
Put V0={f in L:Xf in L}. Under equality, dim V0=dim L-1, and
V0+X V0 is contained in L and has dimension at least dim L, hence equals L.
Induction applied to V0 proves V0=h P_(dim L-2) and then the stated form
of L. The dimension-one case is immediate.

Consequently, let L subset P_b have dimension v, maximum degree b, and
ordinary gcd h of degree d0. The space L P_s has the same gcd and maximum
degree b+s. Until it becomes the whole h P_(b+s-d0), its dimension grows
by at least TWO at the next multiplication by P_1; otherwise the preceding
equality classification would already make it the whole space.
Its codimension within that principal space therefore decreases by at
least one each step. In particular,

    L P_s = h P_(b+s-d0)     whenever s>=b+1-v-d0.           (D)

This is exact over every field; it does not use numerical sampling,
algebraic closure, separability of G, or a bound on the characteristic.

## 4. Why the polynomial shifts are genuine full stresses

If b belongs to R and 0<=r<=t, the tuple (b_i X^r f_i)_i is an ACTUAL
relation among H_i because its sum is zero and every summand belongs to H_i.
Its j-th coordinate stress is X^r sum_i alpha_(i,j)b_i f_i. Thus

    W P_t is contained in the true full stress space Z.     (E)

This multiplies by the evaluation variable X within the permitted degree
slack. It never multiplies relations again by challenge labels and does
not use the previously falsified label-weight saturation.

Let nu(f)=sum_x f(x)V(x)/Z0'(x), and define lambda_j similarly using U_j.
The actual agreement equations give

    lambda_j|H_i = -alpha_(i,j) nu|H_i.

By (D), the first inequality in (A), and (E), nu annihilates the full
homogeneous principal space G H_(n+t-delta), where H_l denotes binary
forms of total degree l. Its dehomogenization is

    g P_(n+t-delta).

Now the polynomials f_i have ordinary gcd ONE: each factor of every f_i
would be a point excluded from every S_i, contradicting their union D0.
They are monic of degree n, so their homogeneous gcd is also one.
The second inequality in (A), followed by (D), gives

    F P_(t-delta) = P_(n+t-delta).                          (F)

For each i and each homogeneous multiplier R0 of degree t-delta,
G f_i R0 belongs to H_i and to the principal space already annihilated by
nu. Agreement therefore makes lambda_j annihilate G f_i R0 as well.
Spanning with (F) proves that EVERY lambda_j annihilates the SAME full
principal space. This establishes the shared-source part of the theorem.

The principal space has dimension N0-k-delta, so its annihilator in the
source quotient has dimension delta. Its annihilation equations say that
gT is orthogonal to all x^r/Z0'(x), 0<=r<N0-k-delta. RS duality is exactly
statement (B). For delta=0 this makes V itself degree below k on D0,
contradicting badness on S_i.

## 5. Why the number of labels is small

Under (C), at least k+delta points of each S_i lie outside E. On these,

    A_(U_j)+alpha_(i,j) A_V-g P_(i,j)=0.

This is a polynomial of degree below k+delta, so it is identically zero.
If there is only one label the bound is already proved. Otherwise choose
two distinct labels and a coordinate on which they differ. Subtracting
their two polynomial identities gives

    A_V=g Q_V,   degree Q_V<k.

The remaining identities give A_(U_j)=g Q_(U_j) with degree Q_(U_j)<k,
and EVERY selected response is the same polynomial affine family

    P_(i,j)=Q_(U_j)+alpha_(i,j) Q_V.

Outside E, the actual words equal these Q polynomials. Since S_i is bad,
it contains some x_i where V(x_i)!=Q_V(x_i), necessarily in E. At that
point its agreement equation determines the ENTIRE vector alpha_i:

    alpha_i=(Q_U(x_i)-U(x_i))/(V(x_i)-Q_V(x_i)).

One point cannot serve two distinct labels. Hence m<=e0 whenever m>=2,
which proves m<=max(1,e0). There is no independent-coordinate product bound.

## 6. Exact critical finite effect and escape conditions

At a=833, t=444. For 1<=delta<=222, the conditions

    u <= 444-delta,           c <= 444+delta               (G)

imply m<=max(1,delta)<=222. The delta=0 branch under (G) is impossible.
For N0=N the coefficient ambient dimension n+1 is 8,387,776; for smaller
unions its correct dimension is N0-832. No full-union assumption is needed.

Thus any feasible 833-subset family with m>222 must escape through at
least one of the following, calculated on THAT actual family:

    W=0;
    delta>=223;
    u>444-delta;
    c>444+delta.

This does NOT bound the number of escaping families or prove that any
bad-subset choice satisfies (G).

If the missing global step did establish M(833)<=222 for every source,
the unchanged whole-support budget would satisfy

    B <= p^5 w(832)+222 < B_allow.

That conditional conclusion meets the separately documented conservative
allowance; it does NOT meet the stronger 2^53 target. For the stronger target,
instantiate the SAME theorem at a=813: t=424, 1<=delta<=212, with

    u<=424-delta,             c<=424+delta.

The certified branch then has m<=212. A universal proof that M(813)<=212
would imply the unchanged whole-support bound

    B <= p^5 w(812)+212 < 2^53.

Both conditional arithmetic statements are checked by scripts/check_smz9_global_stress_arithmetic.py.
The remaining work is precisely a global bound on the large-gcd / deficient-span
escape branches (or a proof that a suitable choice of bad subsets avoids
them). Neither the available local-witness barrier nor independent rank sums
establishes that step. No universal weighted certificate is claimed here.

## Subsequent counterexample boundary

The [exact large-gcd family](weighted-mca-global-escape-family.md) shows that
`M(813) <= 212` is false for unrestricted source words, even at global quotient
rank six. It also shows that bad-subset selection cannot universally remove
the large-gcd escape. The theorem above remains conditional; its hypotheses
cannot be promoted to an unconditional family-selection assertion. The new
example satisfies the weighted allowance and leaves a weighted charging
argument, not a source restriction or protocol change, as the open direction.

## Reproduction and evidence scope

Run `python3 scripts/check_smz9_global_stress_arithmetic.py` from the repository
root. It checks the attached integer/rational inequalities, not the universal
mathematical statements or cryptographic security. The proof above is a
source-reviewed mathematical argument, not an additional kernel-checked
Lean theorem. No production authority follows from either.
