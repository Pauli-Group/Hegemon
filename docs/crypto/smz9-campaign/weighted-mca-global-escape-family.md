# Exact large-gcd escape family on the actual coset

Status: proved counterexample to forcing a forbidden family of 213 bad
labels at agreement 813, and to removing every large-gcd escape by selecting
bad subsets or minimizing their union. It is NOT a violation of the weighted
allowance: the entire constructed source has B<2^52. Only scratch files were
written, and no native or formal checker was run.

## 1. Explicit arbitrary-source instance

Use the actual D, p=2^64-2^32+1, N=2^23, and degree bound d=387, k=388.
Choose ANY set C of 812 actual points, and write R=D\C. Set

    V(x)=1_R(x),
    U_j(x)=-x^j 1_R(x),             j=1,...,5,
    alpha_x=(x,x^2,x^3,x^4,x^5),   x in D.

The N labels alpha_x are distinct because their first coordinate is x.
For any alpha put Q_(alpha,j)(X)=alpha_j-X^j, a degree-at-most-five tuple.

For x in R, response P=0 has EXACT full support C union {x}, of size 813.
V is zero at 812 points there and one at x, so it has no degree-387 lift.

For x in C, response P=Q_alpha_x has EXACT full support R union {x}, of
size N-811. V equals one on R and zero at x, again forbidding a degree-387
lift. Exactness uses Q_alpha_x(y)=0 iff y=x, from its first coordinate.

## 2. Every other response, not only the selected ones

For arbitrary alpha and P, if P!=0, some coordinate of P is a nonzero
degree-at-most-387 polynomial, so agreement inside C has at most 387 points.
If P!=Q_alpha, some coordinate of P-Q_alpha is a nonzero polynomial of
degree at most 387, so agreement inside R has at most 387 points.
Therefore

    P notin {0,Q_alpha}  ==>  |G(alpha,P)|<=774.

If alpha is not alpha_x for any x in D, the two canonical responses have
full supports C and R respectively, on each of which V is constant and
hence polynomial. If x in R, Q_alpha_x has good full support R. If x in C,
P=0 has good full support C. Thus the exact upper-tail count is

    M(a)=N,      775<=a<=813;
    M(a)=812,    814<=a<=N-811;
    M(a)=0,      a>N-811.

In particular M(813)=N=8,388,608, not at most 212.

This source has maximum global quotient rank SIX. If
aV+sum_j b_j U_j equals a degree-387 polynomial Q on D, then Q vanishes at
all 812 points of C and is zero. On R, the polynomial a-sum_j b_j X^j is
then zero at more than five points, so all six coefficients vanish.

The complete weighted source satisfies

    B <= 812 w(N-811)+(N-812)w(813)+(p^5-N)w(774) < 2^52.

This includes every other response and every other coefficient. The upper
bound is checked by exact integer/rational arithmetic in scripts/check_smz9_global_stress_arithmetic.py.
No unverified claim about the exact smaller-support maxima is needed.

## 3. Even the 213-label minimal-union test has no stress

Select any m private labels alpha_x with x in R, where 1<=m<=N-812.
Their largest bad full supports are precisely the corresponding 813-point
sets C union {x}; the preceding response classification leaves no alternative
bad 813-subset. Their union has size 812+m and cannot be made smaller.

Let R_m be those m selected private points. The compressed factors from
weighted-mca-global-shift-stress.md are

    f_x=product_(y in R_m\{x})(X-y),    n=m-1.

They are a basis of P_(m-1): evaluate at R_m, where their matrix is diagonal
with nonzero diagonal. Hence F=P_n, u=0, but the constant relation space and
compressed stress W are ZERO. This holds in particular for m=213, whose
actual minimal union has only 1025 points. A small union and full factor
span alone therefore do not force nonzero stress.

## 4. All N labels: every bad-subset choice retains a huge gcd

Now select ALL N bad labels and choose an arbitrary bad 813-subset for each.
The private labels still force S_x=C union {x}. A core label c in C must
choose

    S_c={c} union T_c,       T_c subset R, |T_c|=812.

It must include c, since V is constant on R. The union of all selected
supports is D regardless of these choices. Put n=N-813 and Z_R=product_R(X-x).
The private factors

    f_x=Z_R/(X-x),    x in R,

already form a basis of P_n, so u=0 for EVERY choice. The additional core
factor f_c vanishes at every point of R\T_c. Its unique expansion in the
private basis therefore uses only those f_x with x in T_c:

    f_c=sum_(x in T_c) b_(c,x) f_x,
    b_(c,x)=f_c(x)/Z_R'(x) !=0.

These 812 expansions form a basis of the entire constant relation space.
Every corresponding coordinate stress vanishes at R\T_c. Consequently
the ordinary gcd of ALL compressed stresses contains

    product_(y in R\union_c T_c)(X-y).

Since |union_c T_c|<=812^2, this is a factor of degree at least

    N-812-812^2 = N-660156 = 7,728,452.

The stress is nonzero: its first-coordinate vector for c has private-basis
coefficients (c-x)b_(c,x), all nonzero on T_c. Also dim W<=5*812=4060.
Thus, for every possible choice of the bad 813-subsets, the factor span is
already maximal but the homogeneous stress gcd degree is at least 7,728,452.
Maximizing stress, or minimizing the union, cannot remove this escape.

## Boundary

The conditional global shift-stress theorem remains valid. What fails is
the prospective assertion that every sufficiently large feasible label
family, already at 213 labels or even at N labels, can be made to satisfy
its small-gcd hypotheses by selecting bad a-subsets.

This example occupies a harmless part of the weighted budget, and does not
disprove a larger sufficient unconditional M(813) bound or the universal
weighted inequality. A complete proof must CHARGE such legal large-gcd
families, or establish another bound on them, rather than forbid them.

## Reproduction and evidence scope

Run `python3 scripts/check_smz9_global_stress_arithmetic.py` from the repository
root. It checks the attached integer/rational inequalities, not the universal
mathematical statements or cryptographic security. The proof above is a
source-reviewed mathematical argument, not an additional kernel-checked
Lean theorem. No production authority follows from either.
