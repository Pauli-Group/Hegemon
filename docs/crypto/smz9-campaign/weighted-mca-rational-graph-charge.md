# Support-capped charge for non-affine rational response graphs

This is an unconditional charge for each fixed response graph and a
conditional global-cover criterion. It does not prove a universal graph
cover, the unrestricted weighted-budget inequality, accepted-byte quantum
extraction, or any other concrete security endpoint.

Fix arbitrary U:D->K and V:D->F_p on the actual domain, where
K=F_(p^5), p=2^64-2^32+1, N=|D|=2^23, and k=388. Let
w(g)=choose(g,20)/choose(N,20). The response degree in X remains below k.

## 1. Graph and exact incidence bound

Take nonzero B(T) in K[T] and A(X,T) in K[X,T] with degree_X A<k.
For B(alpha)!=0 define the response

    P_alpha(X)=A(X,alpha)/B(alpha).

Put H=max(degree_T A,degree_T B+1). Require the graph to be genuinely
non-affine: there are no Q_U,Q_V in K[X], both of degree below k, such that

    A(X,T)=B(T)(Q_U(X)+T Q_V(X))

as a formal polynomial identity. Affine graphs are handled separately by
weighted-mca-support-capped-charge.md; no graph at its denominator roots is used.

For each x in D define the formal polynomial

    F_x(T)=A(x,T)-B(T)U(x)-T B(T)V(x).

Let C={x:F_x is identically zero}, z=|C|. Then z<=k-1=387.
Indeed, if C contained k points, let Q_U,Q_V interpolate U,V on those
points. Every coefficient in T of
A(X,T)-B(T)(Q_U(X)+T Q_V(X)) has degree in X below k and vanishes on all
k points. Every coefficient is zero, contradicting genuine non-affinity.

For x outside C, F_x is a nonzero polynomial of degree at most H, so it
vanishes at at most H elements of K. Therefore for ANY retained subset of
admissible parameters, with their ACTUAL FULL supports G_alpha,

    sum_alpha (|G_alpha|-z) <= H(N-z).                      (1)

Every full support contains C; every counted point outside C supplies one
root of F_x. This proof neither truncates full supports nor assumes badness.
It therefore applies, in particular, to retained maximizing bad responses
that happen to lie on this fixed graph.

## 2. Charge on the unresolved support interval

Retain only parameters whose full supports satisfy

    813 <= g_alpha <= b=56977.

For fixed z<=387, the ratio w(g)/(g-z) is increasing throughout this
interval. The numerator minus denominator in its consecutive-ratio test is

    (g+1)(g-z)-(g+1-20)(g+1-z)
      = 19(g+1)-20z > 0.

Thus w(g)<= (g-z) w(b)/(b-z). Applying (1) and then the monotonicity of
(N-z)/(b-z) as a function of z yields

    sum_alpha w(g_alpha)
      <= H (N-z)/(b-z) w(b)
      <= H (N-387)/(56977-387) w(56977).                    (2)

No sharpness claim is made for (2). The root-incidence statement is over K,
and remains valid for every formal degree H; it is not an estimate obtained
by treating five independent base-coordinate parameters as one base scalar.

## 3. More flexible sufficient covering criterion

Use the same already documented mathematical tails as the
capped-affine note: contributions from supports at least 56978 are below
2^44+2^36. The low branch is bounded by p^5 w(812).

Suppose the selected maximizing bad responses with full supports in
813..56977 can be covered by finitely many genuinely non-affine rational
graphs of this form, with sum of their degrees H equal to D_total.
Denominator roots must be absent from that graph's assigned parameters or
covered by another graph. Choose one covering graph per selected response;
each graph's assigned subset obeys (2), so

    B <= p^5 w(812)
         + D_total*(N-387)/(56977-387)*w(56977)
         + 2^44+2^36.                                      (3)

The exact admissible floor of D_total is

    29363621245169047705124401626686126827795598631859831321,

whose diagnostic logarithm is 184.26007511717302. In particular,
D_total<=2^184 would suffice for B<=2^53. The resulting bound divided by
2^53 is approximately 0.9965304593569303. These are conditional arithmetic
consequences, not an established graph-cover bound.

Affine and non-affine covers can also be mixed. If L affine families and
non-affine total degree D_total cover the selected middle-support responses,
the sufficient bound is

    B <= p^5 w(812) + [L*(N-56976)
           + D_total*(N-387)/(56977-387)]*w(56977)
           + 2^44+2^36.                                   (4)

This graph criterion is more flexible than an affine-family-only cover,
but no universal bound on either L or D_total has been proved. An arbitrary
selector's mere finite-field polynomial representability gives degrees far
too large to justify (3) or (4).

## 4. Reproduction

Run `python3 scripts/check_smz9_global_stress_arithmetic.py` from the repository root. It checks the
exact rational budget, its maximal integer degree allowance, and every
integer consecutive-ratio inequality used on the retained interval. The
symbolic graph/common-core and incidence proofs above are mathematical
arguments, not Lean-checked claims or consequences of finite experiments.
