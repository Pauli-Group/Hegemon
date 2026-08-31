# V6 proof-field and challenge audit

## Verdict

There are two different profiles and two different rejection reasons.  They
must not be conflated.

1. The **unmodified live profile** is a negative control: B128 challenges,
   `StdChallenger = HasherChallenger<Sha256>`, and `SECURITY_BITS = 96`.
   Wider reads cannot raise a 256-bit transcript state/entropy cap.  Its
   rate-`1/8`, 116-query DP24 query term is only about `2^-96.29`, and the
   source says this excludes folding and every other protocol.  This profile
   is rejected independently of any candidate channel.
2. The **source-static candidate** replaces the transcript and Merkle hashes
   with framed SHA-512, samples query positions canonically without
   replacement, and uses either E384 or E512 challenges.  It avoids the live
   SHA-256 entropy cap, but it is still rejected: its fixed-bad-set calculation
   is not an adaptive/composed FRI/QROM theorem, its complete-ZK mechanism is
   false, and its retained 4+3-tree projection is noncompetitive.  The local
   512-KiB parser-safety bound is a provisional screen, not an immutable
   consensus limit or a theorem-level architecture disqualifier.

For the actual retained M4 rate `1/8`, the DP24 unique-radius miss fraction is
`9/16`, so the bad fraction is `7/16`.  The deepest tree has depth 20 and the
candidate samples one global distinct-query schedule from
`M = 2^20 = 1,048,576` pair/leaf positions; smaller trees are lifted into that
universe and their openings deduplicate after right shifts.  Thus
`B = 7M/16 = 458,752`.  The exact finite-population screen is

```text
P_miss(q) = product_(i=0..q-1) (589,824-i)/(1,048,576-i).
```

For the historical 264-bit component allocation `P_miss < 2^-264`, `q=317`
fails and `q=318` is the exact fixed-set minimum.  The old `q=319` came from
the with-replacement formula; it is one query conservative for that allocation.
Replaying the source-pinned SHA-512 query sampler and exact
compact-frontier formula at `q=318` gives **1,555,840 bytes for mixed E384**,
**1,770,496 bytes for mixed E512**, and **1,889,920 bytes for all-E512**.  The
E384 projection exceeds the provisional 524,288-byte screen by **1,031,552
bytes**.  Counterintuitively it is
7,136 bytes larger than the pinned `q=319` projection because changing `q`
changes the transcript, query set, collision pattern, and compact frontier.
These are exact serializer-term projections for one fixed synthetic
transcript, not measurements or transcript-independent lower bounds.  They
charge zero bytes for framing or complete-ZK repair.

There is a second, deliberately weaker number.  If all eleven non-FRI terms in
the existing incomplete scaffold are frozen at their configured values,
`q=309` composes to only 127.810157 modeled bits while `q=310` composes to
128.099227 modeled bits.  Its exact fixed-schedule E384 projection is
**1,528,928 bytes** (mixed E512 **1,739,616**, all-E512 **1,856,448**).  This is
the current incomplete-ledger minimum, not a production minimum.  Real
PCS/IOP/Fiat–Shamir/hash/grinding/history losses can only change the required
count; neither `q=310` nor `q=318` is production-selectable.

The field-width engineering comparison is unchanged.  A genuine
`E512 = GF(2^512)` is the smallest B128 extension whose relative degree is a
power of two and whose absolute width satisfies the live Binius field/NTT
contracts.  `E384 = B128[Y]/(Y^3+Y+1)` cannot implement those contracts
honestly because `ExtensionField::DEGREE = 2^LOG_DEGREE` and Gao–Mateer asserts
a power-of-two absolute degree.  E512 therefore wins implementation risk, not
proof size.  On the exact `q=319` schedule, mixed E512 adds **214,528 bytes**
and all-E512 adds **334,432 bytes** over E384; on the exact `q=318` schedule
those deltas are **214,656** and **334,080 bytes**.  At `q=310` they are
**210,688** and **327,520 bytes**.

There is also a decisive privacy blocker.  The current Gao–Mateer encoder is
systematic at leaf zero and the initial opening exposes raw `pi` and `omega`.
Conditioned on querying leaf zero, two same-statement witnesses can have view
distance exactly one; an independent 64-byte leaf tape authenticates/hides a
hash preimage but does not mask the algebraic value.  A candidate must commit
`P_masked = P + Z_H R_g` on a commitment domain disjoint from the relation
domain.  Every independently encoded group needs `m` independent B128 mask
coefficients, where `m` is the maximum number of distinct opened B128
coordinates for that group across both initial siblings, every later E384
lane, and the full terminal—not the nominal query count.  The total entropy is
`g*m`.  Both the `q=310` and `q=318` projections are zero-ZK-cost
counterfactuals.  They are not valid proof-size projections for a
source-faithful masked BaseFold.  Diamond ePrint 2025/1015, Construction 4.1,
sets BaseFold up on `ell+1` and appends
`kappa = gamma * 2^theta` random coefficients.  Any repair faithful to that
construction therefore changes at least the polynomial dimension and may
change tree depths, folding, query collisions, frontiers, and the serializer.
All byte counts and both query checkpoints must be recomputed after the exact
mask geometry lands.  The stabilized source assessment is exact and negative:
the current mixed backend has no `ell+1` doubled setup, `kappa` high
coefficients/openings, fresh blind commitment, virtual oracle
`f^(0)=alpha*f+f'`, interleaved sumcheck/FRI, final `(c0,c1)` pair, or cited BCS
salted-opening grammar.  A zero-growth alternative is permissible only after a
separate refinement proves at least `m` relation-free tail points in the
current capacity.  If the relation occupies the full domain, every nonzero
mask forces a power-of-two dimension increase and invalidates the retained
geometry.

`production_authorized`, `complete_zero_knowledge`, `composed_pq128`, the
adaptive FRI theorem, the exact QROM Fiat–Shamir reduction, and the exact FRI
folding bound therefore remain false.

## Exact symbolic ledger

Let the challenge field be `F = GF(2^m)`.  Let `h_FS` be the proven entropy of
one transcript challenge under the pinned sampler and transcript construction,
not merely the number of bytes requested.  The usable denominator is

```text
m_eff = min(m, h_FS).
```

For one fully specified proof grammar, define the integer field bad-set
coefficient without suppressing any union:

```text
A_collision = R * (R - 1) / 2
A_SZ        = sum_j d_j
A_sumcheck  = sum_i n_i * delta_i
A_batch     = sum_k (claims_k - 1)
A_FRI_fold  = exact field-cardinality numerator from the selected FRI theorem

A_field = A_collision + A_SZ + A_sumcheck + A_batch + A_FRI_fold.
```

Here `R` counts only challenge pairs whose equality is a bad protocol event;
`d_j` is the total degree of each independently tested nonzero identity;
`n_i` and `delta_i` are the round count and per-round univariate degree of each
sumcheck/MLE-check; and each random linear combination of `claims_k` fixed
claims contributes degree `claims_k - 1`.  The live BaseFold relation batching
comment pins one such term as `sum_i(k_i - 1)/|F|`.  A production ledger must
enumerate each actual call, including the inner IOP, outer ZK wrapper, combined
opening, constraint-family batches, ring switch, and any action-level union.

For a query-phase inverse-rate exponent `ell` and `q_FRI` test queries, the
live source's with-replacement DP24 query screen is exactly

```text
epsilon_FRI_query = ((1 + 2^-ell) / 2)^q_FRI
                  = (2^ell + 1)^q_FRI / 2^((ell + 1) q_FRI).
```

The source explicitly excludes folding and every other protocol from this
quantity.  `A_FRI_fold` may not be set to zero until a theorem specialized to
the actual batch, arities, distance, terminal codeword, and field is pinned.

For the candidate's canonical without-replacement sampler, let `M` be the
global query universe and let the committed roots fix a bad set of exactly `B`
positions before query sampling.  Its finite-population miss term is

```text
epsilon_fixed_set(M,B,q)
  = falling(M-B,q) / falling(M,q)
  = product_(i=0..q-1) (M-B-i)/(M-i).
```

The retained geometry uses one depth-20 global universe, not seven independent
local samplers.  All seven tree depths are `13,18,20,11,16,12,9`; the smaller
oracles are virtually lifted and the same global queries map down by right
shift.  With inverse rate `1/8`, the exact candidate screen substitutes
`M=2^20` and `B=7*2^16`.  This fixed-set product may replace the
with-replacement query estimate only inside a theorem that proves the bad set
is fixed relative to the SHA-512 Fiat–Shamir queries and that handles all
fold-round correlations.  The standalone kernel supplies no such theorem.

The provisional field-search screen used by the executable checker is

```text
C = C_QROM * N_history * G_restart

epsilon_field_screen(Q) = C * A_field * Q^2 / 2^m_eff.
```

`C_QROM` is the exact reduction constant, `N_history` is the union over proof,
network, action, and security histories not already internal to the theorem,
and `G_restart` is the enforced prover grinding/restart/abort multiplier.  This
is a conservative screening form, not a completed Fiat–Shamir reduction.  If
the selected theorem has a different query exponent, measure-and-reprogram
loss, multi-round factor, or additive term, the production ledger must encode
that exact form instead.

The full required composition is additive and keeps the non-field terms
separate:

```text
epsilon_total(Q)
  <= epsilon_PCS_binding(Q)
   + epsilon_IOP_field(Q)
   + epsilon_FRI_query
   + epsilon_FRI_nonfield(Q)
   + epsilon_FS_transform(Q)
   + epsilon_transcript_hash(Q)
   + epsilon_Merkle_hash(Q)
   + epsilon_grinding_abort(Q)
   + epsilon_extraction(Q)
   + epsilon_ZK_failure(Q)
   + epsilon_remaining_unions(Q).
```

No term may be credited twice, and no invocation count may be silently omitted.
In particular, Merkle collision/second-preimage binding and leaf hiding are
hash properties, not benefits obtained by enlarging the challenge field.
Fiat–Shamir needs a domain- and profile-bound QROM transformation, not just a
wide digest.  Grinding needs an enforced retry cap and abort/selective-failure
model.  Complete ZK and knowledge extraction remain external obligations.

## Exact integer thresholds

The fail-closed gates are:

```text
C A_field 2^(2*64)  / 2^m_eff < 2^-128
C A_field 2^(2*128) / 2^m_eff < 1/2.
```

For positive integer `A_charged = C * A_field`, the minimum effective width is

```text
m_min = 258 + floor(log2(A_charged)).
```

The second gate is one bit stronger than the first.  Equality fails.  Thus:

- with `A_charged = 1`, the minimum is 258 bits; E256 fails even before real
  counts are charged;
- with the deliberately loose whole-proof screen `A_charged = 2^64`, the
  minimum is 322 bits;
- E384 has 62 integer bits of width slack against that screen;
- E512 has 190 integer bits of width slack;
- with the candidate plan's still-unproved aggregate algebraic allowance
  `A_charged = 2^120`, the minimum is 378 bits, leaving only 6 bits of E384
  width slack and 134 bits of E512 slack;
- unioning six separate coefficients of at most `2^120` gives
  `A_charged = 6*2^120`, minimum width 380, and only 4 E384 bits of integer
  slack before any history, restart, or reduction constant is charged;
- a 256-bit transcript entropy cap gives `m_eff = 256` for either field and
  fails by 66 bits;
- E384 accepts at most `A_charged < 2^127` under these two gates; E512 accepts
  at most `A_charged < 2^255`.

The `2^64` coefficient is intentionally a screen, not a derived production
bound.  It is very loose relative to the retained one-copy geometry—51,449 AND
constraints, 52,374 private words, 114 public words, 83 Keccak permutations,
and a 448,224-byte proof—but an exact reduction must replace it with the real
sum above.  No production number is inferred from this screen.

Even the fixed-synthetic-transcript retained-tree projection at the rejected
historical `q=116` count is 695,840 E384 bytes, 171,552 bytes above the
provisional parser-safety screen, before framing or ZK repair.  Thus no
currently enumerated retained 4+3-tree checkpoint both clears the screen and
approaches strict composition.  This is not a universal BaseFold bound:
another grouping, topology, serializer, or parser policy must be analyzed on
its own terms.

The exact minimum **with-replacement** query counts for the FRI query term
alone are:

| `log2(1/rate)` | strictly below `2^-128` | strictly below `2^-129` |
| ---: | ---: | ---: |
| 1 | 309 | 311 |
| 2 | 189 | 191 |
| 3 | 155 | 156 |
| 4 | 141 | 142 |

The current rate-`1/8`, 116-query profile fails this table.  A composed target
must choose an allocation for the query term after the hash, PCS, IOP,
Fiat–Shamir, grinding, extraction, ZK, and history terms are known.

For the candidate's actual depth-20 global schedule at rate `1/8`, the exact
**without-replacement fixed-set** minima are:

| classical target | minimum `q` |
| ---: | ---: |
| 128 | 155 |
| 129 | 156 |
| 256 | 309 |
| 257 | 310 |
| 264 | 318 |
| 265 | 320 |
| 266 | 321 |
| 272 | 328 |

At `q=318`, the finite product has about 264.0178 diagnostic bits; applying a
bare square-root heuristic gives about 132.0089 bits for this term.  Unioning
six equal-size 132-bit terms would leave about 129.42 bits, which explains the
historical 264-bit allocation.  Those decimals are diagnostics only: the
required adaptive Fiat–Shamir/QROM reduction and non-query FRI terms are not
present, so this arithmetic cannot set `composed_pq128=true`.

The old scaffold's eleven frozen non-FRI terms total
`0.3125003784660465 * 2^-128`.  Its FRI term must therefore be below
`0.6874996215339535 * 2^-128`, or more than 257.081138 classical bits after
undoing the modeled square-root loss.  The exact finite-product diagnostics
are 256.544111 bits at `q=309` and 257.374517 at `q=310`, producing the
127.810157/128.099227 modeled composed results above.  This explains `q=310`;
it does not authorize it.  No exact production query minimum exists until the
eleven configured screens are replaced by actual reductions and the union is
recomputed.

## Required property by proof-system role

| Role | Required property | Field-width effect | Current status |
| --- | --- | --- | --- |
| challenge sampling | uniform canonical element; no bias/rejection ambiguity | denominator capped by `m_eff` | live SHA-256 is capped at 256; candidate SHA-512 removes that cap but lacks a QROM sampler reduction |
| challenge collision | pairwise bad-event bound when equality harms independence | `A_collision / 2^m_eff` | exact bad-pair registry absent |
| constraint/identity testing | Schwartz–Zippel over a nonzero pinned polynomial | `A_SZ / 2^m_eff` | complete degree registry absent |
| sumcheck/MLE-check | per-round degree and fixed-prechallenge claim | `A_sumcheck / 2^m_eff` | call/degree union absent |
| claim/oracle batching | fixed claims before coefficient; degree `k-1` | `A_batch / 2^m_eff` | one BaseFold term documented, global registry absent |
| FRI folding | theorem-specific field bad-set and proximity loss | field part uses E384/E512 | live calculator omits it explicitly |
| FRI query phase | proximity detection, independent query entropy | independent of field width | live target is 96 bits; candidate fixed-set `q=318` screen is not an adaptive theorem |
| PCS/Merkle root and paths | collision/second-preimage binding; hiding where leaves are secret | no field-width credit | live suite is SHA-256; candidate SHA-512 has width but no exact QROM binding/hiding reduction |
| Fiat–Shamir | transcript collision resistance, challenge pseudorandomness, multi-round QROM transform, typed domain | entropy cap and external loss | live SHA-256 fails; candidate framed SHA-512 still lacks the exact transform |
| grinding/restarts | bounded trials, abort/selective-failure composition | multiplier on affected terms | production cap absent |
| proof/history union | exact global proof, fork, action, and network count | multiplier unless theorem internalizes it | production ledger absent |
| complete ZK | witness-free simulation of every raw/folded/terminal value | no field-width credit | systematic leaf zero has conditional TV 1; per-group `P+Z_H R_g` with whole-view coordinate count `m` is specified but not integrated |

## SHA-512 candidate composition checkpoint

The candidate channel is numerically distinct from the live SHA-256 negative
control.  In an ideal SHA-512 random-oracle screen, truncating one digest to 48
bytes supplies an E384 bit string without field rejection; a full digest could
supply one E512 string.  The width-only global screens are

```text
SHA-512 collision screen       <= 4 Q^3 / 2^512
SHA-512 preimage/hiding screen <=   Q^2 / 2^512.
```

They have ample low-query width: at `Q=2^64` the displayed terms are
`2^-318` and `2^-384`.  This does not instantiate SHA-512 as an ideal QROM,
prove Merkle second-preimage binding, or prove Fiat–Shamir measure-and-
reprogram security.  At the `q=318` projection, the wire contains exactly 8
roots, 11,507 authentication nodes, and 2,111 independently framed leaf tapes;
these are cost/role counts, not independent union terms unless the selected
hash theorem says so.

The smallest current arithmetic checkpoint is therefore conditional:

| Term | Exact candidate expression or allocation | Status |
| --- | --- | --- |
| IOP identities / Schwartz–Zippel | `A_SZ / 2^m_eff` | actual nonzero-polynomial degree registry absent |
| sumcheck/MLE checks | `A_sumcheck / 2^m_eff` | exact rounds/degrees/call union absent |
| batching and challenge collisions | `(A_batch + C(R,2))/2^m_eff` | exact challenge-role registry absent |
| FRI folding | `A_FRI_fold/2^m_eff + epsilon_nonfield` | pinned source expressly omits it |
| FRI queries | historical component: `falling(589824,318)/falling(1048576,318) < 2^-264`; frozen incomplete union: `q=310` | exact fixed-set arithmetic only; adaptive theorem and production minimum absent |
| PCS/Merkle SHA-512 | theorem-specific global collision/second-preimage advantage | width screen only |
| Fiat–Shamir SHA-512 | theorem-specific QROM transform over the exact transcript order | absent |
| grinding/restarts | enforced trial/abort multiplier on every affected term | cap and selective-failure proof absent |
| extraction / knowledge soundness | extractor failure under the same QROM history | absent |
| complete ZK | joint simulator distance over all openings | current systematic opening fails; per-group `m`-coordinate `P+Z_H R_g` repair and exact `rank(O G_r)=rank([O G_r|O G_w])` remain unintegrated |
| proof/network/history union | theorem-owned global oracle or exact count multiplier | absent |

If the as-yet-unproved aggregate field coefficient really is at most `2^120`,
E384 gives 264 classical field bits and the bare square-root heuristic gives
132 bits.  Six equal 132-bit protocol terms union to about 129.415 bits before
the smaller SHA-512 and 192-bit statistical terms.  This reproduces the old
scaffold arithmetic but not its missing premises.  E384 can tolerate a total
charged coefficient only below `2^127`; after six `2^120` terms, fewer than 22
additional whole-proof multiplier units remain before the exact work-factor
gate fails.  E512 has much larger algebraic headroom, but no field width can
repair a missing theorem, a TV-one privacy event, or a proof already over the
provisional parser-safety screen.  Nothing in this ledger chooses between
`q=310`, `q=318`, or a larger production count.

## Live trait and integration comparison

### E384

The prototype polynomial `Y^3 + Y + 1` may define a genuine degree-three
extension over B128, but it is outside the live Binius field tower:

- `ExtensionField<F>::DEGREE` is exactly `1 << LOG_DEGREE`; three is
  unrepresentable.
- `BinaryField` requires `ExtensionField<BinaryField1b>`.  E384 has absolute
  degree 384, also not a power of two.
- `impl_field_extension!` uses power-of-two bit layout and stride arithmetic.
- `gao_mateer_basis` has a compile-time assertion that `F::N_BITS` is a power
  of two.
- BaseFold and FRI are parameterized by `F: BinaryField` throughout.

Consequently a production E384 path must retain a bespoke field, domain/NTT,
mixed channel, mixed Merkle layout, heterogeneous first fold, proof-size
optimizer, ring switch, and verifier/prover integration.  The existing
dependency-free E384 KATs establish arithmetic/interface behavior only; they
do not close those seams.

### E512

The live source already supplies the useful lower layers:

- `M512` exists on x86-64, aarch64/portable, wasm, and fallback routes.
- `GhashSq256b` is a genuine quadratic extension of B128, serialized in 32
  bytes, with `ExtensionField<B128>` and `ExtensionField<B1>`.
- packed E256 arithmetic already uses M512 for two interleaved E256 lanes and
  for four sliced E256 lanes.
- the low-level FRI fold is generic over a fold field `F` and an NTT field
  `FS`, requiring `F: ExtensionField<FS>`; an E512/B128 instantiation matches
  that shape.
- `BaseFoldVerifierCompiler<F>`, FRI parameters, and generic Merkle schemes can
  be instantiated with a new binary field when the whole channel uses it.

A genuine E512 scalar can therefore be specified as a quadratic extension of
the existing E256 (and hence degree four over B128), backed by M512.  This is
an architecture direction, not an implemented field identity.  Admission
requires a pinned irreducible polynomial, canonical B128/E256 bases and
little-endian 64-byte encoding, trace-one element, full multiplicative
generator, multiplication/square/inversion/wide-multiply implementations,
subfield operations, `ExtensionField<B128>`, `ExtensionField<E256>`, and
`ExtensionField<B1>`, packed/scalar differential KATs on every architecture,
and independent algebra review.

The top-level blockers remain substantial:

- `IPVerifierChannel<F>` requires `Elem: FieldOps<Scalar=F>`; a concrete E512
  has scalar E512, so `IPVerifierChannel<B128, Elem=E512>` is ill-typed.
- concrete transcript and Merkle channels set `Elem=F`, serialize/open the same
  `F`, and sample the same `F`.
- the M4 verifier owns `BaseFoldVerifierCompiler<B128>` and requires a B128
  channel; the prover requires `P::Scalar=B128` and B128 word packing.
- an all-E512 substitution packs eight 64-bit words per element instead of
  two, changing the canonical relation and commitment layout.
- preserving B128 source symbols needs the same split message/challenge field,
  layout-tagged Merkle openings, mixed Phase-A sumcheck, B128-to-E512 first
  fold, and generalized ring switch identified by the existing mixed-field
  seam audit.

E512 therefore beats E384 on implementation risk, not on current proof bytes.
It reuses the live field/NTT/FRI abstractions and avoids a permanent fork of the
power-of-two tower.  The 16-byte premium per explicit wide value is material.
On the exact pinned `q=319` schedule there are 13,408 explicit wide values
(`11,912` opened fold values, `512` terminal values, and `984` messages), so
mixed E512 adds exactly `16*13,408 = 214,528` bytes.  All-E512 additionally
widens 2,498 initial B128 values by 48 bytes, for a total delta of 334,432
bytes.  On the exact minimum fixed-set `q=318` schedule, the corresponding
deltas are 214,656 and 334,080 bytes.  These fixed-synthetic-transcript counts supersede the
older 98,176/113,024 projection, which omitted values in the retained mixed
serializer.

At the incomplete-ledger `q=310` schedule, 13,168 explicit wide values create
a 210,688-byte mixed-E512 delta; widening the 2,434 initial B128 values adds
another 116,832 bytes, for a 327,520-byte all-E512 delta.

The exact retained 4+3-tree route does not merit a live port in the current
tournament: its `q=310` E384 projection is already 184,100 bytes larger than
the retained 1,344,828-byte three-copy B128 comparator before complete-ZK
repair.  This is a current implementation comparison, not a universal
BaseFold lower bound or an immutable 512-KiB rejection.  Different grouping
can change the topology materially.  E512 remains the lower-risk field
implementation control if a different PCS topology first fits.  A one-level
mixed Ligerito/TensorSwitch-style opening is the current falsifiable direction;
it needs its own exact theorem, field ledger, ZK mask, serializer, and byte
screen.  Do not rotate a proof profile or network identity until the field
identity, transcript domain, exact FRI/IOP/QROM ledger, complete ZK, compiled
verifier refinement, and measured retained artifact all pass.

## Source and profile pins

The live checkout was read at commit
`3f96163049f680b2909f6545690bd929f1b48c44`; `git status --short` contained
only the checkout marker `.cargo-ok`.  Paths below are relative to that pinned
Binius checkout.

```text
e546abe8655e92c6730f1f4adc032df6f8e3673b5f55a9f9de813b1a28cb6300  crates/field/src/extension.rs
14d008d79defaafb9bfac7393bea8a2fe27aeb28a368cfa8f08e3f436e573324  crates/field/src/field.rs
7e50a743d940ba83a97c95561001cd9833d7e0569eb00787bfb84b72d8312579  crates/field/src/binary_field.rs
746b8df934cd665a93ff53c09dbabe867a05581f717179b5a2fa4e0366d06182  crates/field/src/ghash_sq.rs
ab8e50ed20a7b82f9cde34aab6875fa03f5c0c038af9e9db8c1313ecafa1b82e  crates/field/src/packed_ghash_sq.rs
055c673ca10a508643e469758885a3f99212407c53cac2f05433f816f653aeef  crates/field/src/arch/mod.rs
bd3b06a90ebd96285a7823951e103a2943b1ad14ac3b54608c91e7aab2671779  crates/field/src/arch/portable/m512.rs
3baf36ca35ea505dc0ab0f92923b514a434847a828f4a7d1074b6cf0ed363013  crates/math/src/ntt/domain_context.rs
62236feaefac28ddb191190de694ef9efb9887beb53a0105f7015556f18af850  crates/ip/src/channel.rs
aaa7c7dab7df90d021b13012934433b6566c3e931bb73173eb6f59ccda67237a  crates/transcript/src/transcript.rs
e18d55b4450e381bcd99090a54eb3526489a525424f007636a65a3eab101330e  crates/transcript/src/fiat_shamir/hasher_challenger.rs
92dac2f5993339057d439a5a9b6fdcd0ac9ecd2a194d5f3ab91a98927e21bb09  crates/hash/src/lib.rs
4f7f6857757f21c91ffaf2f2129f7f7256070011809e5f0936a7e8058d4ee66b  crates/verifier/src/config.rs
9d16a14e2812dd1ebeb73302a8e3c8d3ab8a48213b0433b232501fabb14dac2f  crates/verifier/src/verify.rs
03d7f000144c0839e045ce1eb0a1c8d7659bb111b3bf26d2d4647f77db1e6164  crates/iop/src/merkle_channel.rs
fbad7eacb1256a8b90659c6e6103556e0f6e0149b888e25ec4741a15ad71c6a7  crates/iop/src/basefold/channel.rs
4fe42f9d33cf3f72b787edb7261f32384ade0cd3183eb1f702e8962d1252b78a  crates/iop/src/basefold/compiler.rs
76c07c770a12900ac0fe7c79790bbb1bc3e9e68546b0ba7bc0c000388e89628b  crates/iop/src/basefold/opening.rs
2131676d78f0b56b4cb96a80199c8cc35339c71666bb26a5a0dcd5acf56c2420  crates/iop/src/fri/common.rs
3f7039e7a9382b50c46aa859822162162e21ee6d3a0660e2c609b1e118548512  crates/iop/src/fri/fold.rs
166d0eaa1d8991eebcb6efc3254874637084c9a3f2deb4ce8b2b722e5c240eed  crates/iop/src/fri/verify.rs
d8bcd73dd7c8f8afa829a2de29d4826f1043afdab6121a217597712585f473c0  crates/m4-verifier/src/composite.rs
d2ac41db2809f2c394c239c0de24fddf89d808775842a7333d00918261d08e77  crates/m4-prover/src/composite.rs
```

Local retained-profile pins:

```text
6acbda09925fd727010ce8486906329f026a43f662b4142b18b088d3d41da424  prototypes/standalone-shake256-binius/m4-strict-full-shake400-v1/BYTE_PROFILE.md
ffe17fc93ccb1a16ebefcc496ce061ae014ae08a79e342777fc9da1659df6b58  prototypes/standalone-shake256-binius/m4-strict-full-shake400-v1/artifacts/shake400-v1-final/manifest.json
abbeb105529b336aa0fa8d76eeee878ea49101b9e8bad7f752064b891d28101f  prototypes/standalone-shake256-binius/m4-full-pay1x2-prototype/Cargo.lock
afd82b2b03e12882871b64e4f9deed0593d1d00d6762a9d528d95abb321f6707  .agent/hardening/smallwood-v6-qrom-composition/composition.py
e6d2d71714ab6625186f92cd37f7a726fdb58449674bd6ee69fcc28064ed3973  .agent/hardening/smallwood-v6-qrom-composition/profile.json
2d91f0e844fe7f46bf5b7c114bf365071d880a1a3a914c12bccb4e059cf9d8dc  .agent/hardening/smallwood-v6-qrom-composition/field_challenge_gate.py
d9fbd3ea04b05556ffbba02c5bbc197487af77a3a992df6c45669f15c1673730  .agent/hardening/smallwood-v6-qrom-composition/test_field_challenge_gate.py
bc453b6fbd5096b7333dcb5e79e260f7639a6c1af538a8a68aa3d21bcc79f1eb  circuits/transaction/src/full_blake2b448_relation.rs
a5869ebe5ee0bc5640837bb683a8c4c636a82f6a4ecfded538ad8acb1de1df82  prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/src/mixed_candidate.rs
707da29ccb9f03a581195c35a0ece4f4edaaa14eee4e72efd1eaf935623df884  prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/check_source.py
9ce8337a263e880e5f6c117fb2d922cab56ab9d2f7c0aa085e45fd0cefe66ec2  .agent/hardening/conventional-hash-successor/README.md
ca1b195659244c72b1f1a2a8ea453a26c2771e5b1f694a4523b3af32bc8de4ac  .agent/hardening/standard-hash-successor/README.md
dd2f249a3834f3fe5cbe303d939c267296101f9a1541849bca990eb88e4cf29f  prototypes/standalone-shake256-binius/strict-mixed-field/src/mixed_basefold_pcs.rs
0babc2344eedaa9cfefb03312a086e2b69f041579fbb7f6d21ffa338423e8780  prototypes/standalone-shake256-binius/strict-mixed-field/src/complete_zk.rs
28a044e3fb4b66adab8d1e0b93c397eb3fa96e9f5feb4fb1b08032a59769fdee  .agent/hardening/binius-e384-complete-zk/README.md
2d0ebab678760b04e7cd62d7f19b6458773c008d37aa3d3f17e78169fd6592ad  .agent/hardening/binius-e384-complete-zk/candidate.json
0a2ba3f6dc57bfd2bd1a24ac846ad652eda7b51834543e9acd07dfc80c31b461  .agent/hardening/binius-e384-complete-zk/check_candidate.py
e8ee3bc055507dfa201dd796ce3301f36c107b1b208135d3b4ca867ee6c87905  .agent/hardening/mixed-architecture-size-tournament/E384_BACKEND_RESULT.md
a2313b5eef527bd8632f275212f6ccd45b4edf406ce7367ac76ee277a6a3054e  .agent/hardening/mixed-architecture-size-tournament/QROM_QUERY_AND_SIZE_AUDIT.md
```

The complete-ZK candidate records primary-source PDF SHA-256
`b6db1430de0cd46cba2719b1d1b23ebdc0f0e14a8e546df767fd011800beaeaf`.
That PDF is not retained in this lane, so the digest is a cross-lane source
identifier rather than locally rehashed evidence.  The stabilized Rust seam
above remains uncompiled under the disk stop; its source hash is not an
executed backend/refinement claim.

The retained manifest is historical evidence only: it uses B128, a 96-bit
per-copy query target, three sequential repetitions, and incomplete ZK/QROM
claims.  It is not a baseline security certificate for E384 or E512.

## Lightweight validation

Run only the dependency-free test under the current disk stop:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s .agent/hardening/smallwood-v6-qrom-composition \
  -p 'test_field_challenge_gate.py' -v
```

The current result is 16/16 passing.  Tests reject equality at 128 bits,
enforce the live SHA-256 entropy cap, check the exact E384 coefficient
boundary, derive both with-replacement and finite without-replacement query
minima, reproduce the source-pinned `q=116` and `q=319` counts, pin the `q=318`
historical component and `q=310` incomplete-scaffold projections, and assert that every
production/security authority flag stays false.  No Cargo, Lake, prover,
network, or heavy build was run.
