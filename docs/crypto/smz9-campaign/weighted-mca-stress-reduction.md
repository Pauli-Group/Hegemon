# Exact five-coordinate stress reduction for weighted SMZ9 MCA

Date: 2026-09-08. Mathematical derivation; no Lean or Rust checker
was run. The universal numerical bound remains **OPEN**. This note proves a
source-free simultaneous-realizability criterion and states an unproved finite
expansion lemma that would suffice. It does not restrict the source words,
response selector, profile, or actual whole agreement supports.

## 1. Exact live object

Let F be the current Goldilocks field, p=2^64-2^32+1, D the actual shifted
multiplicative coset of N=2^23 distinct elements, k=388, and d=k-1=387.
Write U=(U_1,...,U_5):D->F^5 and V:D->F for arbitrary fixed words. For each
alpha in F^5, a response is a tuple P of five polynomials of degree at most d.
Its full agreement is

    G(alpha,P) = {x in D : P_j(x)=U_j(x)+alpha_j V(x), all j=1,...,5}.

It is bad if |G|>=416 and V has no degree-at-most-d polynomial lift on all
of G. Put w(a)=choose(a,20)/choose(N,20). The exact normalized worst case is

    B416 = max_(U,V) sum_alpha max_(bad P) w(|G(alpha,P)|),

where the maximum of the empty set is zero. This is the normalization of
`badResponseWeight`, `badCoefficientWeight`, `universalLineBudget`, and
`smz9LineBudget` in the live `SmallWoodV8Smz9McaRecovery.lean`, with five base
rows, degree 387, threshold 416, and 20 distinct queries. The older 2^52
comment in that module is not itself a theorem or the current allowance.

The supplied conservative isolated numerical target is

    B416 < B_allow,
    B_allow = (p-1)*p^4 * [1/(1280*2^256)-w(415)].

The convenient stronger target B416<=2^53 is also unproved.

## 2. Shortened Reed--Solomon dual spaces

Let C=RS_d(D) be the k-dimensional evaluation code in F^D, and E=C^perp
under the ordinary dot product. For S subset D with |S|>=k, define

    H_S = E intersect F^S,

where F^S denotes words supported on S, embedded in F^D by zero extension.
Then dim H_S=|S|-k. For any word W,

    W has a degree-at-most-d lift on S
      iff <h,W>=0 for every h in H_S.                         (1)

Indeed, restricting C to S has dimension k because the points are distinct;
its orthogonal complement is precisely the restriction of H_S. Equation (1)
is ordinary finite-dimensional orthogonal-complement duality.

This space has an explicit basis depending only on the actual evaluation
points and S. Set Z_S(X)=product_(x in S)(X-x). For 0<=t<|S|-k, let

    h_(S,t)(x) = x^t / Z'_S(x) if x in S, and zero otherwise.

The denominators are nonzero. Lagrange interpolation gives

    sum_(x in S) x^r / Z'_S(x) = 0   for 0<=r<=|S|-2.

Taking r=t+j with j<k proves orthogonality to each code monomial. The basis
vectors are independent: a nonzero polynomial of degree less than |S|-k
cannot vanish at all |S| distinct points after multiplying out the nonzero
denominators. Their number is |S|-k, as required.

Also, every nonzero word in E has support at least k+1=389. A smaller support
would give a nontrivial dependence among at most k columns of the Vandermonde
generator, contrary to their independence.

## 3. The five-coordinate stress space

Choose any finite family of distinct labels alpha_i in F^5 and sets S_i with
|S_i|>=416. The sets are proposed supports, not assumed to arise from words.
Put

    H_i = H_(S_i),
    H = sum_i H_i,
    R = kernel( direct_sum_i H_i -> H, (h_i)_i -> sum_i h_i ),

and define the subspace

    Z = span { sum_i alpha_(i,j) h_i : (h_i)_i in R, j=1,...,5 } subset H.

All linear relations among the shortened dual spaces matter here. Z is not
defined from pairwise intersections alone.

### Theorem: exact simultaneous realizability

There are one fixed V, one fixed five-coordinate U, and degree-at-most-d
responses P_i agreeing on every S_i, with V nonpolynomial on every S_i, iff

    exists nu in H*:  nu(Z)=0 and nu restricted to H_i is nonzero for every i. (2)

Necessity: set nu(h)=<h,V> and lambda_j(h)=<h,U_j>. By (1), agreement on S_i
means lambda_j|H_i=-alpha_(i,j) nu|H_i. Applying these equations to any relation
sum_i h_i=0 shows nu(sum_i alpha_(i,j)h_i)=0. Badness is exactly the nonzero
restriction condition in (2).

Sufficiency: given nu, define a functional on H by

    lambda_j(sum_i h_i) = -sum_i alpha_(i,j) nu(h_i).

This is well-defined because the difference between two decompositions lies
in R, whose weighted sum lies in Z. Extend nu and the five lambda_j linearly
from H to E. The nondegenerate pairing gives F^D/C isomorphic to E*, so choose
representative words V,U_j. Their restrictions satisfy (1), yielding the
responses P_i, and nu|H_i!=0 proves badness. Since |S_i|>=k, each coordinate
response is uniquely determined by its values on S_i.

### Actual full supports and exact equality of optimization problems

The constructed full agreement G_i can be larger than S_i. This is harmless
for the reduction: S_i subset G_i, nonpolynomiality on S_i implies
nonpolynomiality on G_i, and w(|G_i|)>=w(|S_i|). Distinct labels ensure that
these weights belong to distinct coefficient maxima in the original sum.

Conversely, choose a maximizing actual full bad support at each coefficient
of any fixed source. This family satisfies (2). Consequently B416 is exactly
the maximum of sum_i w(|S_i|) over distinct-label families satisfying (2).
This equivalence has neither a source-word restriction nor an unproved
whole-support closure premise.

## 4. A finite matrix formulation with no U, V, or response variables

Let A_i be the N-by-(|S_i|-k) matrix of the explicit basis above, let A be their
horizontal concatenation, and let K be any matrix whose columns form a basis
of kernel A. For j=1,...,5, let D_j be diagonal, multiplying every column in
block i by alpha_(i,j). Then

    Z = column_space [A D_1 K | A D_2 K | ... | A D_5 K].

Equation (2) is equivalently

    exists v in F^N:
      v^T A D_j K = 0 for all j,
      v^T A_i != 0 for every i.                              (3)

The words can be recovered by solving

    u_j^T A = -v^T A D_j.

The right-hand side lies in the row space of A precisely because it
annihilates kernel A. This displays explicitly why validating only local
support ranks or using independently chosen U for different supports loses
the critical information.

## 5. Exact finite-field avoidance, not a rank shortcut

Let Q=H/Z and B_i=(H_i+Z)/Z. The permissible directions correspond to

    Q* minus union_i B_i^perp.

The exact number of permissible functionals is the integer

    sum_(J subset I) (-1)^|J| * p^(dim Q - dim(sum_(i in J) B_i)).           (4)

In particular, merely checking H_i not contained in Z for each i does not
in general establish a globally usable direction: many proper annihilator
subspaces can cover Q* over a finite field. Conversely, the union bound gives
the useful sufficient condition

    sum_i p^(-dim B_i) < 1.                                  (5)

There are at most p^5 distinct labels. Thus dim B_i>=6 for every i implies
(5), and would certify a genuine shared-source construction, not a toy
support arrangement. No over-budget family meeting this condition was found.

## 6. Genuine affine-label implications

Suppose an affine hyperplane beta.alpha=c contains all labels indexed by J
and excludes alpha_i. Then

    H_i intersect sum_(j in J) H_j subset Z.                  (6)

To prove this, write h_i+sum_(j in J)h_j=0 and apply the linear combination
of coordinate stresses with coefficients beta. Subtract c times the original
zero relation. The result is (beta.alpha_i-c)h_i in Z, and the scalar is nonzero.

For at most six affinely independent labels, an affine functional can isolate
each label. Hence, putting R_i=H_i intersect sum_(l!=i)H_l,

    Z=sum_i R_i,       Z intersect H_i=R_i,
    H/Z = direct_sum_i image(H_i).

A simultaneous bad realization then exists exactly when H_i is not contained
in the sum of the others for every i. This is a complete small-family result;
it is not a quantitative theorem for families as large as p^5.

## 7. A precise missing quantitative lemma

The separate [finite local-rank obstruction](weighted-mca-local-rank-barrier.md)
excludes the displayed Proposition 3.7 additive-incidence-rank certificate
through agreement 2,892, even with exact individual ranks. It does not exclude
dependencies between different incidence blocks, the stress formulation here,
or a nonzero global kernel. Do not treat that route's failure as a universal
impossibility theorem or as a source counterexample.

The following stronger-than-necessary finite statement would establish the
desired universal bound without changing the profile:

> For every family of distinct alpha_i in F^5 and sets S_i in the actual D,
> |S_i|>=416, if sum_i w(|S_i|)>=B_allow, the associated five-coordinate stress
> space contains H_i for at least one index i.

This would contradict (2), establishing the strict allowance inequality.
The version with antecedent sum_i w(|S_i|)>2^53 instead establishes the
stronger sufficient target B416<=2^53. **Neither version has been proved.**
The exact necessary
and sufficient impossibility condition is instead the covering of Q* by all
B_i^perp, equivalently the zero value of (4).

The companion [seventeen-witness barrier](weighted-mca-seventeen-witness-barrier.md) shows why a theorem that only
forbids a non-realizable subfamily of at most seventeen witnesses cannot be
this missing lemma: a concrete over-budget support family passes all such
tests, even with exact whole supports. Different local realizations have
different source words. No globally shared-source counterexample is claimed.

## Outcome

The new result is a rigorous global compatibility reduction and a bounded
local-realizability barrier, not a numerical closure. It identifies the missing
object as a five-coordinate stress expansion/annihilator-covering inequality
for shortened dual spaces of the actual Vandermonde code. No native source, protocol parameter, retained artifact, or release claim is
changed by this derivation. It is not a machine-checked Lean endpoint.
