# A shorter universal tail using already retained MCA counts

Status: an independently reviewed arithmetic partition of existing mathematical
universal counts, not a new proximity theorem or a full weighted-budget proof.
No protocol, sources, response selector, actual full supports, or query weights
are changed. This is not a source-execution or Lean certificate.

The existing weighted-mca-research.md explicitly supplies two universal
support-wise counts, not merely counts for a restricted quotient-rank class:

    agreement>=56978:
      E_first<=19415238057946677331930434730749083756<2^124,
    agreement>=65536:
      E_direct<=424128388239503090<2^59.

Its cubic-incidence theorem also bounds the number at agreement>=N/16
by less than2^36. Here N=2^23 and
wgt(g)=choose(g,20)/choose(N,20). The first two counts are direct
applications of [BCHKS, Theorem4.6](https://www.math.toronto.edu/swastik/rs-proximity-gaps-2025.pdf),
whose support-wise statement was checked again in this pass. This note
does not claim that these source theorems have been newly formalized.

Split the actual maximizing bad full supports at BOTH65536 andN/16:

    56978<=g<=65535:
      contribution<=E_first*wgt(65535)<2^124*2^-140=2^-16,
    65536<=g<N/16:
      contribution<=E_direct*wgt(N/16-1)<2^59*2^-80=2^-21,
    g>=N/16:
      contribution<2^36.

The without-replacement sampling weight is at most(g/N)^20. Both displayed
power bounds are strict because65535<N/128 andN/16-1<N/16. Thus the ENTIRE
universal tail at support>=56978 is below

    2^36+2^-16+2^-21.                                    (1)

This replaces the previous looser2^44+2^36 when desired. Existing proofs
using the looser bound remain valid and unchanged. In particular, the
dimension<=20 and dimension<=21 branch freezes did not need (1).

One can also use the slightly sharper exact rational expression

    E_first*wgt(65535)+E_direct*wgt(N/16-1)+2^36.

Only the upper bound on the tail changes. The small-support branch remains
p^5*wgt(812), the unresolved middle interval remains813..56977, and no
bound on its arbitrary-source stress dimension or global affine/graph
cover is supplied.

Run `python3 scripts/check_smz9_global_stress_arithmetic.py` from the repository root. The exact checks
verify the partition's arithmetic and weight inequalities, not the external
source theorems or the unrestricted weighted-budget inequality.
