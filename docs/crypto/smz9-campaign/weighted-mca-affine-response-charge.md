# Sharp unconditional weight charge for one affine response family

This is an unconditional theorem for each fixed affine family of polynomial
responses, valid for arbitrary U,V on the actual domain. It is NOT a claim
that an unrestricted response selector admits a bounded number of such
families. The latter covering step remains open.

Use K=F_(p^5) only to group the existing five base-field coordinates. Fix
ANY Q_U,Q_V in K[X] of degree below k=388. The family supplies the response

    P_alpha=Q_U+alpha Q_V             for each alpha in K.

Let B_family count the live weights of its bad full supports, with the
original threshold 416 and w(g)=choose(g,20)/choose(N,20).

## Exact common-part/fiber decomposition

Set

    C={x: U(x)=Q_U(x) and V(x)=Q_V(x)},     z=|C|,
    A={x: V(x)!=Q_V(x)},
    E_alpha={x in A:
                alpha=(Q_U(x)-U(x))/(V(x)-Q_V(x))}.

Then the EXACT full agreement is G_alpha=C union E_alpha. The nonempty
E_alpha are disjoint and their total size is at most N-z. If E_alpha is
empty, the response is good: V agrees with Q_V on C, which gives a base-field
degree-below-k lift by interpolation at the actual base-field points.
Thus B_family is at most the sum of w(z+|E_alpha|) over nonempty fibers.

The function w is increasing and discretely convex, since

    w(b+1)-w(b)=choose(b,19)/choose(N,20).

For m nonempty fibers of total size L, convexity concentrates all excess
above one into one fiber, giving

    sum_i w(z+e_i) <= w(z+L-m+1)+(m-1)w(z+1).

Increase L to N-z. The resulting function of m is discretely convex, so
its maximum on 1<=m<=N-z occurs at an endpoint. Therefore

    B_family <= max{1,(N-z) w(z+1)}.                        (1)

If z=N there are no bad fibers and the actual value is zero.

## Exact universal maximum and sharpness

For q=20 define

    a_star=floor((q(N+1)-1)/(q+1))+1,
    C_q=(N+1-a_star)*choose(a_star,q)/choose(N,q).

The ratio of successive values of f(a)=(N+1-a)choose(a,q) is at least
one precisely when (q+1)a<=q(N+1)-1. Hence this a_star maximizes f,
including its possible adjacent tie. For the actual N,

    a_star=7,989,152,
    C_20>1,
    B_family<=C_20<150552.

This bound is sharp for a single family's contribution. Choose a_star-1
common points with U=V=0. Set V=1 on all other points and assign distinct
labels beta_x there, setting U(x)=-beta_x. In the family P_alpha=0, each
beta_x has exact full support consisting of the common part plus x. It is
bad because the common part has at least k zeros of V. Their total weight
is exactly C_20. This uses at most N actual field labels.

The same fiber decomposition gives the sharp unweighted threshold bound

    number of this family's bad labels with |G|>=a <= N-a+1,
                                                        416<=a<=N.

Indeed, each retained fiber has size at least max(1,a-z), while their sum
is at most N-z. Maximizing (N-z)/max(1,a-z) gives N-a+1. The construction
with z=a-1 and singleton fibers attains it.

## What a global cover would have to establish

If the maximizing responses with full support at least 813 were covered
by L affine polynomial families of the displayed form, then, allowing
overcounting at intersecting families,

    B <= p^5 w(812)+L C_20.                                (2)

The exact integer floor of (2^53-p^5 w(812))/C_20 is computed in the adjacent
scripts/check_smz9_global_stress_arithmetic.py. No bound on L is asserted. Families may be selected
from the fixed source and the full selected response family, but their
number must be independently justified; selecting one family per label
does not furnish the missing covering theorem.

The explicit M(813)=N source in weighted-mca-global-escape-family.md uses only TWO
affine families for its large responses, so its legal large-gcd escape is
cheap under this charge. Extending that fact to arbitrary sources is the
remaining mathematical obligation, not an established consequence of the
stress ranks or local witness bounds.

## Evidence scope

Independent mathematical source review found no issue in the exact fiber,
convexity or sharpness argument. The repository arithmetic checker verifies
these numerical constants with exact rational arithmetic. This is not a Lean
root, a proof of a global affine-family cover, or an endpoint security receipt.
