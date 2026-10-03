# The zero-stress escape branch has a small label count

This closes one branch of the existing global-shift-stress reduction. It is
not a universal weighted-budget proof: nonzero stress with deficient span,
large gcd, or inadequate polynomial-shift growth remains uncontrolled.

## 1. Compressed zero stress is exactly independence

The empty family has zero contribution and is immediate. Assume henceforth
that the family is nonempty, so N0>=a. Use the existing notation on its
actual union D0 of selected bad a-subsets:
N0=|D0|, n=N0-a, f_i=Z_(D0)/Z_(S_i) in P_n, F=span{f_i}, and

    R={b: sum_i b_i f_i=0},
    W=span{sum_i alpha_(i,j) b_i f_i : b in R, 1<=j<=5}.

The labels alpha_i in F_p^5 are distinct and every f_i is nonzero.
Then W=0 if and only if the family (f_i)_i is linearly independent.

Independence makes R=0, giving one implication. Conversely suppose W=0.
For each j, the rule

    T_j(sum_i b_i f_i)=sum_i alpha_(i,j)b_i f_i

defines a linear endomorphism of F: its value is independent of the chosen
representation precisely because W=0. Thus T_j f_i=alpha_(i,j) f_i.
For a fixed i and each l!=i, select a coordinate j_l with
alpha_(i,j_l)!=alpha_(l,j_l). Apply the operator product

    product_(l!=i) (T_(j_l)-alpha_(l,j_l) Id)

to any relation sum_l b_l f_l=0. Every term other than the ith is killed;
the ith is multiplied by a nonzero scalar. Since f_i!=0, b_i=0. Repeating
for each i proves independence. Every factor acts by a scalar on each f_l,
so the displayed argument does not need an additional commutativity premise.

This operator iteration is legitimate ONLY because W=0 first establishes
well-defined endomorphisms. It is not the invalid general operation of
repeatedly multiplying a nonzero stress by label coordinates while claiming
that the source direction still annihilates the result.

In particular,

    W=0  ==>  m<=dim P_n=N0-a+1<=N-a+1.                   (1)

## 2. Consequence for the actual weighted optimization

For arbitrary fixed U,V, retain ALL labels whose maximizing actual full bad
response has support size at least a=813, and choose one such maximizing
response per label. From each support
choose a bad 813-subset, as permitted by the existing stress reduction.
If the compressed stress of that family is zero, (1) bounds the number of
all these large-support labels by N-812=8,387,796. Keeping the actual full
supports and simply using w(g)<=1 gives

    B <= p^5 w(812)+(N-812) < 2^53.                        (2)

The exact rational bound divided by 2^53 is approximately
0.9770060625727776. Thus an unrestricted weighted-budget counterexample
cannot have W=0 for any such choice of bad 813-subsets. This is a necessary
condition on a hypothetical counterexample, not an existence claim.

No common-core or affine-response restriction is imposed. The small
zero-stress family in the retained rank-six escape example is consistent
with (1): its cofactor columns are independent. The full escape example has
nonzero stress and still escapes through the large-gcd branch.

## 3. Optional stronger full-stress statement

If the TRUE full stress Z from weighted-mca-stress-reduction.md is zero,
the same diagonal-kernel argument shows that the shortened dual spaces H_i
form a direct sum. Indeed, on H=sum H_i each T_j acts as scalar alpha_(i,j)
on H_i; the operator isolation argument forces every relation among the H_i
to be zero. Therefore

    sum_i (|S_i|-k) <= dim RS_(k-1)(D0)^perp=N0-k.

For equal a=813 this yields m<=floor((N0-388)/425)<=19736.
This is a different, stronger premise than compressed W=0. The two stress
spaces must not be conflated.

## 4. Exact arithmetic reproduction

The following standard-library arithmetic verifies only the displayed
numerical consequences, not the linear-algebra proof or a universal bound.

    from fractions import Fraction
    from math import comb
    p,N=2**64-2**32+1,2**23
    w812=Fraction(comb(812,20),comb(N,20))
    assert N-812==8387796
    assert (N-388)//425==19736
    assert p**5*w812+(N-812)<2**53
