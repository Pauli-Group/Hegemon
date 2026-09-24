# Retained mixed-BaseFold query and size audit

Status: source-static correction, 2026-08-22. No Cargo, Rust, Lake, prover, or
heavy command was run. This is not a soundness theorem, a proof measurement,
or production authority.

## Corrected verdict

`q=319` is **not** the minimum query count for composed PQ128. It is the
conservative with-replacement count produced by asking the pinned DP24
query-phase formula for 264 classical component bits at inverse rate 3. The
new backend samples without replacement, which lowers that component minimum
to 318. If the other eleven terms in the existing `strict_pq_profile.py`
scaffold are frozen at their configured values, the minimum query count making
that incomplete modeled union strictly exceed 128 post-quantum bits is 310.

No production minimum exists yet. The PCS/IOP/Fiat--Shamir/hash/grinding and
history reductions are not proved, so their real nonzero losses can only raise
the required count. Capability flags remain false.

The retained 4+3-tree E384 projection remains noncompetitive at the corrected
scaffold count: its exact synthetic-transcript serializer projection is
1,528,928 bytes at `q=310`, 184,100 bytes above the retained 1,344,828-byte
three-copy B128 comparator. This does not disqualify every BaseFold topology:
the query/frontier counts are for fixed synthetic roots rather than a live
maximum-relation artifact, and neither a 512-KiB cap nor one transcript sample
is a theorem-level lower bound. It does disqualify continuing this exact
retained-tree implementation as the smallest current route.

## Exact query arithmetic

Pinned `binius64/crates/iop/src/fri/common.rs::calculate_n_test_queries` uses

```text
rho = 2^-3 = 1/8
p_miss = (1 + rho) / 2 = 9/16
epsilon_query_with_replacement = (9/16)^q.
```

The backend's distinct global query domain has `M=2^20` pair positions. At
the DP24 unique-decoding-radius screen, the largest fixed miss set has
`G=(9/16)M=589,824` positions. Sampling without replacement gives the exact
rational

```text
epsilon_query_distinct(q)
  = (589824)_q / (1048576)_q
  = product_(i=0..q-1) (589824-i)/(1048576-i),
```

where `(x)_q` is a falling factorial. The exact exponents are:

| q | classical query bits | after modeled square-root QROM loss | composed bits in the incomplete scaffold |
|---:|---:|---:|---:|
| 116 | 96.295838223 | 48.147919111 | 48.147919111 |
| 155 | 128.674398333 | 64.337199166 | 64.337199166 |
| 309 | 256.544110888 | 128.272055444 | 127.810157464 |
| **310** | **257.374516688** | **128.687258344** | **128.099226608** |
| 317 | 263.187387271 | 131.593693635 | 129.338867354 |
| **318** | **264.017801638** | **132.008900819** | **129.416515703** |
| 319 | 264.848217076 | 132.424108538 | 129.477616473 |

Thus 318, not 319, is the exact distinct-query minimum exceeding the local
264-bit component target; 317 misses it. The ordinary independent-draw bound
does require `ceil(264 / -log2(9/16)) = 319`.

The existing scaffold has eleven non-FRI terms whose total probability is
`0.3125003784660465 * 2^-128`. The FRI term must therefore be strictly below
`0.6874996215339535 * 2^-128`, requiring

```text
FRI post-quantum bits > 128.54056917556088
FRI classical bits    > 257.08113835112175.
```

This explains why a target just above 128 post-quantum bits still needs about
257 classical FRI bits: the scaffold charges a square-root QROM degradation,
then reserves probability for every other term in the composed union. The
264-bit policy adds component and union headroom and matches the separate
`384 - 120 = 264` E384 algebraic screen. None of this substitutes for the
missing actual QROM reductions.

## Exact retained-tree serializer decompositions

These are exact evaluations of
`project_retained_m4_mixed_depth(q)` for its fixed synthetic SHA-512 roots and
canonical distinct-query sampler. They are source-static projections, not
measurements and not transcript-independent lower bounds.

### Corrected scaffold minimum, q=310

```text
opened leaves  = [305, 310, 310, 292, 310, 301, 237]
frontier nodes = [1234,2771,3391, 654,2151, 937, 194]
```

| term | count | bytes |
|---|---:|---:|
| Input B128 values | 2,434 | 38,944 |
| Fold-round E384 values | 11,672 | 560,256 |
| E384 terminal values | 512 | 24,576 |
| Explicit E384 M4 messages | 984 | 47,232 |
| SHA-512 roots | 8 | 512 |
| Independent opened-leaf tapes | 2,065 | 132,160 |
| Compact-frontier SHA-512 nodes | 11,332 | 725,248 |
| **Total** |  | **1,528,928** |

### Historical weak query count, q=116

```text
opened leaves  = [116,116,116,115,116,116,105]
frontier nodes = [620,1200,1432,390,968,504,183]
```

| term | count | bytes |
|---|---:|---:|
| Input B128 values | 926 | 14,816 |
| Fold-round E384 values | 4,552 | 218,496 |
| E384 terminal values | 512 | 24,576 |
| Explicit E384 M4 messages | 984 | 47,232 |
| SHA-512 roots | 8 | 512 |
| Independent opened-leaf tapes | 800 | 51,200 |
| Compact-frontier SHA-512 nodes | 5,297 | 339,008 |
| **Total** |  | **695,840** |

Even retaining the old 96-classical-bit query count does not fit 512 KiB once
later values are genuine E384 elements, nodes/tapes are 64 bytes, and compact
frontiers are charged. The checked-in 448,224-byte artifact is not a
contradiction: it used B128 later values, 50-byte digests, no independent
opened-leaf tapes, and the old path grammar.

### Previously reported q=319 decomposition

The earlier 1,548,704-byte arithmetic itself remains exact for its synthetic
schedule:

```text
39,968 input values
+ 571,776 fold values
+ 24,576 terminal
+ 47,232 messages
+ 512 roots
+ 135,040 tapes
+ 729,600 frontier
= 1,548,704 bytes.
```

Only its claim label changes: it is a conservative 264-bit source screen, not
the minimum composed-PQ128 proof size and not a universal lower bound.

## Rate and grouping screens

Holding the retained fold arities `[4,4,3]`, shifting every tree depth and the
terminal consistently with inverse rate, and recomputing the fixed synthetic
SHA-512 schedule gives the following counterfactual screen. Rates above 6 are
rejected by the current parser; rate 1 requires more than its 512-query limit.

| log2 inverse rate | exact q for 264 component bits | projected bytes | scaffold q for modeled >128 | projected bytes |
|---:|---:|---:|---:|---:|
| 1 | 636, unencodable | n/a | 619, unencodable | n/a |
| 2 | 390 | 1,598,592 | 379 | 1,572,384 |
| **3** | **318** | **1,555,840** | **310** | **1,528,928** |
| 4 | 290 | 1,601,728 | 282 | 1,567,104 |
| 5 | 277 | 1,723,200 | 270 | 1,700,416 |
| 6 | 271 | 1,930,400 | 263 | 1,860,640 |

The retained rate 3 is the smallest row in both screens. Raising the inverse
rate saves too few queries to pay for deeper trees and a larger terminal.
These are topology projections, not optimizer or live-proof measurements.

Changing grouping is materially different. The checked-in n16 rectangular
refold model, still at `q=310`, finds an authentication-free optimistic floor
of 184,656 bytes with folds `[3,1,2]`, and a deterministic maximum-frontier
wire of 335,600 bytes with one fold of five. Both omit complete ZK, actual
multi-oracle M4 binding, and composed QROM evidence. This shows why the 4+3
retained-tree result cannot disqualify all BaseFold/refold topologies.

## Complete-ZK hard gate and exact geometry consequence

The scalar Gao--Mateer encoder is systematic at leaf zero, and the initial
opening serializes `pi` and `omega` separately. Appended tail dummies are zero
at that leaf. Conditioned on opening leaf zero, two same-statement witnesses
can therefore have total-variation distance one. With distinct queries the
bad event is exactly `q/L`; a 64-byte leaf tape hides unopened leaves but does
not mask the opened value.

Any surviving BaseFold/refold route must instead commit on a domain disjoint
from the relation domain and use

```text
P_masked(X) = P(X) + Z_H(X) R(X),    deg R < q,
```

with at least `q` independent B128 coefficients for the initial raw views,
plus whatever extra rank is required by the joint fold/terminal observation
matrix. This algebraic minimum is not evidence that a source-faithful ZK
BaseFold repair fits unused symbols. Diamond, ePrint 2025/1015, Construction
4.1 runs DP24 setup on `ell + 1` and appends
`kappa = gamma * 2^vartheta` random coefficients before the virtual
combination, sumcheck, and FRI phases. The default source-faithful size screen
must therefore double the relation dimension, then add and authenticate those
random coefficients, unless an exact compiler mapping proves that the
unmasked relation actually occupies a smaller `ell`.

Only under a separately proved custom construction could `S` relation-bound
message symbols and the required mask coefficients fit the current
power-of-two capacity `N` with zero direct payload or PCS wire delta. Otherwise
the elementary capacity lower bound is

```text
N' = next_power_of_two(S + q),
```

and every depth, terminal, query union, and compact frontier must be
recomputed. The current diagnostic finalists have 79,128 raw nonlinear words
for mixed BLAKE2b-448/SHAKE and 90,600 for split SHA3-512/SHAKE. Packing two
u64 words per B128 symbol gives lower bounds of 39,564 and 45,300 symbols, so
both force at least n16 before non-hash work. Merely observing that those lower
bounds plus `q=310` are numerically below 65,536 does **not** prove the mask
fits: the exact committed polynomial's relation domain must exclude a
relation-free tail. If padding coordinates are fixed or part of the full MLE
domain, `Z_H R` forces degree/dimension growth despite syntactic slack. The
exact full relation-bound `S` and domain geometry are not yet available, so
zero overhead may not be claimed; for the source-faithful Diamond repair,
dimension doubling is the operative projection. The two full-E384 endpoint
dummy multiplication rows and the whole-view
`rank(O G_r)=rank([O G_r|O G_w])` gate remain additional mandatory costs.

## Next smallest viable screen

The single next implementation screen is a one-level authenticated B128
Johnson/Ligerito opening with genuine E384 algebra, full SHA-512 transcript
and nodes, and an exact n16-or-larger compiled M4 relation. It removes the
three wide recursive FRI trees and uses the Johnson query term rather than 310
rectangular DP24 queries. The one-level protocol is itself non-ZK: it needs a
separately specified and priced hiding wrapper. Diamond Construction 4.1 is a
BaseFold repair, not evidence that the same mask or dimension claim transfers
to Ligerito.

The most optimistic checked-in n16 model is 144,496 proof bytes at inverse
rate `2^-16`, `q=38`, and a 64-GiB encoded oracle. Its exact modeled
decomposition is 64-byte header, 5,424 bytes of M4 reductions, one 64-byte
root, 576 sumcheck bytes, 49,152 terminal bytes, 38,912 opened B128 bytes, and
50,304 authentication bytes. Under a 512-MiB oracle bound, the model is
168,688 bytes at inverse rate `2^-9`, `q=61`: 62,464 opened bytes and 50,944
authentication bytes replace the preceding opening terms.

Those figures are honest model-only lower screens for the fresh relation tier,
not qualifying proofs. They assume exactly n16, use a SHAKE256-512 prototype
whose 64-byte wire can be replaced by SHA-512 only after new KAT/domain work,
and omit the full relation reduction, a separately proved hiding wrapper and
rank completion, complete-ZK simulator, QROM composition, refinement, and
production parser.
Both current diagnostic nonlinear-word lower bounds force at least n16. The
exact non-hash work and disjoint-domain mask may force n17 and must be repriced.

Concrete implementation seam after the disk gate reopens:

1. Freeze the exact standard-hash M4 relation in
   `prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/src/`
   (or its standardized successor), including its local vendored-tree digest.
2. Add one narrowly scoped `strict-mixed-field/src/mixed_ligerito_pcs.rs` and
   serializer report, porting only the proved arithmetic/wire ideas from
   `.agent/hardening/binius-pq128-proof-size/strict_refold_pcs_model.py` and
   `strict_refold_pcs_prototype.py` to SHA-512/E384.
3. Integrate the exact `O`, `G_w`, `G_r`, disjoint-domain mask-capacity plan,
   two full-E384 endpoints, and whole-view simulator from `complete_zk.rs`.
4. Keep every production and security capability false until an exact compiled
   n16/n17 artifact, composed reduction, canonical parser, and restart/mutation
   transport evidence exist.

E512 is not the successor: at identical topology it widens every E384 value by
16 bytes and still needs the same mixed-channel work if B128 commitments are
retained. Repeated B128 proofs remain nonqualifying because no direct-product
QROM or complete-ZK theorem exists.
