# Random-combination counting for compressed-stress dimension at most twenty

Status: independently reviewed mathematical derivation and exact arithmetic,
not a Lean-certified theorem. No unrestricted weighted-budget inequality or
cryptographic endpoint is claimed. This is a separately frozen strengthening
of the earlier dimension<=16 branch, whose files are unchanged.

## 1. All finite assumptions

Work over F_p for a prime p. Let D0 be N0 distinct field elements. Fix
integers 1<=a<=N0 and s>=1, and put n=N0-a. Consider a finite nonempty family
of distinct labels alpha_i in F_p^s and DISTINCT monic polynomials f_i of
degree n, each having exactly n distinct roots in D0. Define

    F=span{f_i},              r=dim F,
    R={b:sum_i b_i f_i=0},
    W=span{sum_i alpha_(i,j)b_i f_i:b in R,1<=j<=s}.

Assume r<p and dim W<=w for an integer w>=1. Put

    C=choose(a+w-1,w-1).

Then the number m of labels satisfies

    m <= r^s + p^2 C/(p-r).                               (1)

The empty family has zero weight and is immediate. No generic-point,
generic-label, response-regularity, source-rank, or gcd hypothesis appears
in (1). The polynomials and all maps below are over the base field F_p.

## 2. The minimum-weight fact needed to bound regular fibers

A zero-dimensional code or polynomial subspace has no nonzero columns.
Any d-dimensional linear code with d>=1 and minimum distance at least a has at most
choose(a+d-1,d-1) projective codewords of weight exactly a. Here is a
field-independent proof. Dimension one gives at most one such line. At
distance threshold one, distinct projective words of weight one are
independent coordinate axes, so there are at most d. For d,a>=2, choose an
active coordinate. Words zero there lie in the shortened code, of dimension
d-1 and minimum distance at least a. Puncturing the full code is injective
because no nonzero word is supported on that one coordinate; its dimension
is d and minimum distance at least a-1. Weight-a words nonzero at the chosen
coordinate puncture projectively injectively to weight-(a-1) words. The two
inductive bounds add to choose(a+d-1,d-1) by Pascal's identity. A code whose
minimum distance is greater than the threshold has zero words being counted.

Evaluation of any subspace of P_n on D0 is injective, and every nonzero
evaluation has weight at least a by the ordinary polynomial root bound.
Each f_i has weight exactly a. Monicity and distinctness make these
projectively distinct. Consequently a polynomial subspace of dimension
at most w contains at most C members of the family. This fact is about
the ACTUAL cofactor evaluations, not abstract support packing.

## 3. Descended matrices and random combinations

For each j, the rule f_i -> alpha_(i,j) f_i defines a well-defined linear
map F->F/W: a relation's weighted image belongs to W by definition.
Choose an arbitrary linear lift T_j:F->F of this map. Therefore

    T_j f_i-alpha_(i,j) f_i belongs to W.                   (2)

For beta in F_p^s write T_beta=sum_j beta_j T_j. A label alpha_i is
REGULAR at beta if T_beta-(beta.alpha_i) Id is invertible on F.
Fix beta and a scalar t in F_p for which T_beta-t Id is invertible.
Every column with beta.alpha_i=t lies in

    (T_beta-t Id)^(-1) W,

which has dimension at most w. Section 2 bounds that fiber by C labels.
There are at most p scalar fibers, so, for EVERY beta,

    number of regular labels at beta <= p C.              (3)

The labels remain full s-coordinate labels throughout (3). Nothing asserts
that a weighted maximum over projection fibers equals the original weight.

## 4. Singular labels that persist for every combination

For each label alpha define the formal polynomial

    Delta_alpha(B_1,...,B_s)
      =det(sum_j B_j(T_j-alpha_j Id)).

Its total degree is at most r. If it is not identically zero, the finite
polynomial root bound shows that it vanishes on at most r p^(s-1) points
of F_p^s. Thus such a label is regular for at least a 1-r/p fraction of
all beta. The factor is strictly positive because r<p.

For completeness, the multivariable root bound follows by induction: write
a nonzero degree-d polynomial with degree e in its last variable. Its leading
coefficient has degree at most d-e in the other variables. At most
(d-e)p^(s-2) assignments kill that coefficient; all other assignments have
at most e roots in the last variable. This gives at most d p^(s-1) zeros.
The one-variable case is the ordinary root bound.

If Delta_alpha IS identically zero, evaluate it at each coordinate unit
vector. This gives

    det(T_j-alpha_j Id)=0 for every j.

Each T_j has at most r eigenvalues in F_p because its characteristic
polynomial is a nonzero monic polynomial of degree r. Therefore all labels
with identically zero Delta lie in a product of s sets, each of size at
most r. Their total number is at most r^s. No common-eigenvector assertion
is needed; this is only an upper bound using individual spectra.

Let m_nonid count the other labels. Average (3) over beta. The preceding
root count implies

    (1-r/p) m_nonid <= p C.

Add the at most r^s identically singular labels to obtain (1). This proof
neither iterates label-weighted nonzero stresses nor assumes that a source
direction annihilates such iterations. The T_j are proof operators, not
a regularity restriction on the adversary's selected response polynomials.

## 5. Actual-source and full-support application at w=20

Use the unchanged p=2^64-2^32+1, N=2^23, k=388, and a=813. For arbitrary
fixed U:D->F_p^5 and V:D->F_p, choose one maximizing actual full bad response
for EVERY label whose maximum bad full support lies in 813..56977.
An empty selected family contributes zero. Otherwise, choose one bad
813-subset S_i from each full support. Set D0=union_i S_i and

    f_i=Z_(D0)/Z_(S_i).

These f_i obey section 1. To verify distinctness, equal cofactors would give
the same bad subset. Subtracting responses at two distinct labels on that
subset, and dividing in a coordinate where they differ, would give a
degree-below-k lift of V, contradicting the subset's badness.

Now suppose the compressed stress of this selected family has dimension
at most20. We have r<=N0-812<=r0=N-812<p. The right-hand side of (1) is
increasing in r for 0<=r<p. With s=5 and

    C20=choose(832,19)
       =202917499647411935202774832309045124800,

the middle-support label count is at most the following integer:

    M20=r0^5+floor(p^2 C20/(p-r0))
       =3743167183203034151303853822236727914500710913488939544761.

Its diagnostic logarithm is 191.25416089416498. Keep the actual full-support
sampling weight wgt(g)=choose(g,20)/choose(N,20), and use only its upper
endpoint on the selected middle interval. The existing low branch and the
already documented documented mathematical tails then yield

    B <= p^5 wgt(812)+M20 wgt(56977)+2^44+2^36 < 2^53.      (4)

The exact rational bound divided by 2^53 is approximately
0.9970553954682987. The exact permitted middle-count logarithm is
191.47174904138168. The tail next to the middle interval starts56978
inclusive, and the high interval startsN/16 inclusive.

Thus, CONDITIONAL on the displayed small-stress premise, the unrestricted
source's weighted-budget inequality follows. Equivalently, any hypothetical
weighted-budget counterexample must have compressed-stress dimension at
least21 for EVERY choice of bad813-subsets of this ENTIRE selected
middle-support family. No universal small-stress selection, counterexample,
accepted-byte extraction theorem, or production authority is established.

## 6. Quantified boundary and reproduction

For w=21 the same formula, without further structure or weighting, gives a
middle-count logarithm196.63440548464317 and an overall bound divided by
2^53 of about1.7323561493881336. Its failure is a limit of this bound, not
evidence that the actual source realizes such a count.

Run `python3 scripts/check_smz9_global_stress_arithmetic.py` from the repository
root. Its stress-twenty section verifies the stated constants, exact count
floor, selected monotone substitutions, and budget comparisons. It does not formally verify the mathematical proof or
establish the small-stress premise for arbitrary sources.
