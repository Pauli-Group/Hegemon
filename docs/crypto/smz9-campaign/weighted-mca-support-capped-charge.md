# Sharp affine-family charge with a support cap

This is a new unconditional weighted bound for each fixed polynomial affine
family and a tighter sufficient GLOBAL cover target. No universal cover is
proved. It keeps the actual full supports, arbitrary U,V, and all five base
coordinates grouped into K=F_(p^5).

Fix Q_U,Q_V in K[X] of degree below 388, and retain any subset of its bad
responses P_alpha=Q_U+alpha Q_V whose full supports have size at most b.
Let w(s)=choose(s,20)/choose(N,20), N=2^23. Put

    F_q(s)=(N+1-s) w(s),       q=20,
    a_star=7,989,152.

Then the retained weight is at most

    max_(1<=s<=b) F_q(s).

In particular, for b<=a_star the sharp bound is simply

    B_family,<=b <= (N+1-b) w(b).                           (1)

## Proof, with every full-support branch included

Use the exact decomposition already proved in weighted-mca-affine-response-charge.md:
every full support is C union E_alpha, |C|=z, with disjoint nonempty fibers
E_alpha outside C; empty fibers are good. Let e=|E_alpha|. Retained fibers
have 1<=e<=b-z, and their total size is at most N-z. If z>=b there are none.

For a nonnegative convex function f on integer points 1,...,E, its chord
bound gives

    f(e)/e <= max{f(1),f(E)/E}.

Indeed, dividing the chord bound by e gives a convex combination of those
two endpoint ratios, with coefficients (E-e)/(e(E-1)) and
E(e-1)/(e(E-1)); E=1 is immediate. Apply this to f(e)=w(z+e), whose forward
differences are choose(z+e,19)/choose(N,20), and E=b-z. Summing the fiber
sizes bounds the total by the maximum of

    (N-z)w(z+1)=F_q(z+1),
    (N-z)w(b)/(b-z) <= (N+1-b)w(b)=F_q(b).

Both are at most max_(s<=b)F_q(s), proving the general statement.
The previously derived consecutive-ratio test shows F_q is increasing
through a_star, proving (1).

For the live badness threshold 416, sharpness holds for every
416<=b<=a_star: take b-1 common points with U=V=0,
put V=1 elsewhere, and set U(x)=-alpha_x with distinct labels outside the
common part. The response family P_alpha=0 has N-b+1 exact bad full
supports of size b and total weight exactly the right side of (1).

## New sufficient global covering target

Use the already documented universal tails from weighted-mca-research.md:
at and above the first strict Johnson agreement 56978 the medium-tail count is
below 2^124; below N/16 the corresponding sampling weight is at most
2^-80. At and above N/16, the universal cubic-incidence count is below 2^36.
Those are previously documented mathematical results, not re-proved or
newly formalized here. They give a combined contribution below 2^44+2^36.

It is therefore enough to cover ONLY the maximizing bad responses with

    813 <= full support <= 56977

by L fixed K-polynomial affine families. By (1), the original budget obeys

    B <= p^5 w(812) + L*(N-56976)w(56977) + 2^44 + 2^36.    (2)

The exact floor of the allowed L is computed by `scripts/check_smz9_global_stress_arithmetic.py`.
It exceeds 2^168, which is much larger than the earlier sufficient count
1,375,681,552 obtained by charging every family its worst possible support.

No bound on this cover number L is established. In particular, the
arrangement P(x)=U(x)+alpha V(x), Vandermonde independence, and the
conditional stress lemma do not currently imply such a cover. This result
substantially relaxes the quantified missing covering obligation; it does
not discharge it or impose an affine response strategy on the adversary.
