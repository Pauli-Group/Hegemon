# Mixed-relation architecture size tournament

Status: bounded source-only audit, 2026-08-22. No Cargo/Lake/prover run was
performed. All byte counts below are serializer arithmetic or retained
historical measurements; no weak-profile artifact is promoted.

## Verdict

There is no qualifying winner today. The current direct Boolean-to-SmallWood
route is, however, decisively eliminated: its hash-only row count is already at
least 1,258,569, while its strict `SMZ2` inner proof loses the retained
1,344,828-byte M4 size comparator at row 21,157 and cannot encode more than
65,525 rows in its current `u16` matrix grammar. It would require a new
Boolean-native arithmetization, copy argument, PCS, and wire; finishing the
current adapter is not a competitive repair.

The single quickest falsifiable route is a fresh **one-level authenticated B128
Ligerito/TensorSwitch opening with real E384 algebra and a SHA-512 transcript**,
after lowering the `HX448C01` non-hash host checks into constraints and running
the honest scalar-to-M4 parity corpus. It still needs its own hiding wrapper,
whole-view simulator, and composed QROM proof. Stock repeated B128 M4 is not
the route: three repetitions do not repair the B128 statistical/QROM union
terms, and the retained direct-product claim is unproved. The retained 4+3-tree
BaseFold projection is already noncompetitive before ZK; Diamond's
source-faithful repair is expected to double its relation dimension. The local
112,784-byte Ligerito number is a Pay1x2/n14 non-ZK toy with no full M4 binding,
so it is a screen to implement, not an accepted-verifier head start.

The assumed 79-call/145-permutation `HGF6HR02` relation is itself rejected
input evidence, not a production candidate. `full_shake448_relation.rs`
explicitly records that rate-72/capacity-1024 `SHAKE512` is not a FIPS-202
algorithm and unconditionally fails the conventional-hash gate. The test-only
`HX448C01` scalar oracle now compares mixed unkeyed BLAKE2b-448/SHAKE256-448
against split SHA3-512/SHAKE256-448, but only the Boolean hash traces are
constrained; the non-hash rules remain host checks, scalar-to-M4 parity has not
executed, and neither profile is selected.

## Exact strict SMZ2 formula

Let `R` be `adapter.row_count()` and `D` its maximum constraint degree. For
packing 64, `rho=5`, five opened evaluations, `beta=2`, `q=23` DECS openings,
`eta=5`, `N=2^20`, full 64-byte SHA-512 commitments, exactly 23 depth-20 paths,
23 independent 64-byte leaf tapes, and zero auxiliary words:

```text
nb_polys          = R + 10
nb_unstacked_cols = R + 5D + 10
C = nb_lvcs_cols  = ceil((R + 5D + 10) / 2)

SMZ2(R,D) = 60,114 + 2,920D + 40R + 40C bytes.
```

This follows directly from the current encoder:

| component | bytes |
|---|---:|
| magic + salt + nonce + SHA-512 transcript digest | 104 |
| `ppol_highs` | `4 + 2,720(D-1)` |
| `plin_highs` | 5,044 |
| `rcombi_tails` | 1,844 |
| `subset_evals` | 23,556 |
| `partial_evals` | `4 + 200D` |
| 23 depth-20 SHA-512 paths | 29,465 |
| 23 independent leaf tapes | 1,472 |
| masking evaluations | 924 |
| high coefficients | `4 + 40C` |
| five opened rows of width `R+10`, mode/count fields | `413 + 40R` |

For the degree-five Keccak relation, the exact comparator boundary is:

```text
R=21,156 -> 1,344,794 bytes
R=21,157 -> 1,344,834 bytes
```

For degree eight, the first losing row is 21,006. The SWV6 envelope adds 967
bytes (74-byte header plus 893-byte statement) and caps the inner proof at
523,321 bytes. At degree five it accepts at most row 7,465
(`SMZ2=523,314`, envelope 524,281); row 7,466 is 523,394 inner bytes.

The formula describes a serializable `SMZ2` only while every matrix dimension
fits `u16`. The opened-row matrix imposes `R+10 <= 65,535`, so `R <= 65,525`.
Larger-row evaluations below are counterfactual widened-wire arithmetic, not
claims that an `SMZ2` artifact exists.

## Exact landed hash inventory and packing audit

A lightweight source-linked execution called the landed typed trace constructors
and `gate_counts()` for the exact rejected HGF6HR02 79-role/145-Keccak
multiplicities. This inventory is historical SmallWood-disqualification
evidence, not the current conventional-hash successor. It compiled no proof
backend and allocated no PCS oracle. The intrinsic traces contain:

```text
17,968,396 witness bits
17,968,398 scalar polynomial identities
```

The difference is the two one-hot constraints, which create no output wire.
The aggregate identity inventory is:

| template | scalar identities | operands | packed batches | occurrence rows |
|---|---:|---:|---:|---:|
| constant zero and one | 79 each | 1 | 2 each | 4 |
| Boolean/public Boolean | 131,746 | 1 | 2,059 | 2,059 |
| one-hot-5 | 2 | 5 | 1 | 5 |
| one-hot mux-5 | 5,248 | 11 | 82 | 902 |
| XOR | 11,136,712 | 3 | 174,012 | 522,036 |
| NOT | 12,932 | 2 | 203 | 406 |
| parity-5 | 1,113,600 | 6 | 17,400 | 104,400 |
| fused chi | 5,568,000 | 4 | 87,000 | 348,000 |
| **total** | **17,968,398** |  | **280,761** | **977,812** |

The adapter does group 64 identities of the same exact polynomial template; it
does not accidentally allocate one engine row per bit constraint. The expensive
step is intentional occurrence lowering: every packed batch receives one row
per operand, and every one of its 64 lanes is linearly tied back to the canonical
witness. Engine `row_count()` is `total_witness_rows`, not the much smaller
`packed_constraint_polynomials` count.

Therefore the intrinsic hash-only projection is already:

```text
canonical rows  = ceil(17,968,396 / 64) = 280,757
occurrence rows = 977,812
R_hash_only     = 1,258,569
```

It entails 62,579,968 occurrence-copy equalities and 80,548,416 packed witness
field words (644,387,328 raw bytes) before final relation metadata. The landed
explicit boundary API additionally needs 168,930 message/digest/authorization
equalities, and the exact statement requires 7,144 public-bit bindings. Those
and all non-hash R1CS identities are deliberately omitted from the decisive
lower bound.

At `R=1,258,569,D=5`, mechanically extending the formula gives 75,589,554
bytes: 25,172,084 high-coefficient bytes and 50,343,173 opened-witness bytes.
Current SMZ2 cannot serialize it (`C=629,302` and `R+10=1,258,579`).

## Tournament comparison and implementation route

| route | current evidence | decision |
|---|---|---|
| Direct Boolean SmallWood | Exact landed trace counts and exact serializer formula | Eliminated: >=75.59 MB counterfactual hash-only wire, u16 failure, incomplete ZK/QROM, and assumed hash registry is nonstandard |
| Stock repeated B128 M4 | Retained 83-Keccak/51,449-AND three-copy artifact, measured 1,344,828 bytes | Rejected: wrong relation, B128/96-bit component, incomplete joint ZK, no direct-product QROM theorem |
| Single mixed E384 M4/BaseFold | Executable scalar RS/fold/compact-frontier kernel; retained-tree synthetic projection is 1,528,928 bytes at the incomplete-ledger `q=310` scaffold minimum | This exact 4+3-tree implementation is noncompetitive with 1,344,828-byte comparator; not a universal BaseFold lower bound and not live M4 |
| Mixed or all-scalar E512 M4/BaseFold | Same fixed synthetic schedule gives 1,763,232 / 1,883,136-byte projections | Noncompetitive; mixed E512 needs the same channel split and all-E512 widens input oracles/M4 packing |
| M4 + one-level Ligerito opening | 112,784-byte Pay1x2/n14 non-ZK model | **Next bounded screen only**; no exact maximum M4 binding, no hiding wrapper or complete ZK, and n16 model is already 168,688 bytes before full composition |
| STIR/WHIR/Flock/VOLE/lattice routes | Local screens only | No exact same-relation, complete-ZK, PQ128/QROM, parser/refinement, or retained proof artifact; none beats the implementation lead of M4 |

Query-count correction: at rate 1/8 the exact without-replacement miss product
is `(589824)_q/(1048576)_q`. It reaches 264.017801638 classical bits at
`q=318`; `q=319` is only the conservative with-replacement count. Freezing the
other eleven terms of the incomplete strict-profile scaffold gives a modeled
composed threshold of 257.081138352 classical FRI bits, first crossed at
`q=310` (128.099226608 composed bits). This is not a production minimum because
the PCS/IOP/Fiat--Shamir/hash/grinding reductions are missing. Exact q310/q116
serializer decompositions, the rate screen, and the disjoint-domain ZK mask
geometry are recorded in `QROM_QUERY_AND_SIZE_AUDIT.md`.

The current diagnostic finalists have 79,128 raw nonlinear u64 words for mixed
BLAKE2b-448/SHAKE and 90,600 for split SHA3-512/SHAKE, versus 49,800 in the
retained 83-Keccak source. Packing two u64 words per B128 symbol gives lower
bounds of 39,564 and 45,300, so both force at least n16 before non-hash work.
The old 448,224-byte copy is therefore not a size projection for either new
relation; a new compile and artifact are mandatory after the disk gate passes.

Concrete shortest remaining path after the E384 implementation result:

1. Freeze an actually standardized fresh hash-role registry and compile its
   exact full live Hegemon semantics directly into the one-main M4 source,
   including signed value balance, all 16 masks, zero-valued enabled stablecoin
   fields, all authorization modes, intent/balance/ciphertext hashes, and exact
   statement/action/network bindings. Differential-test scalar versus M4 first.
2. Screen one one-level E384 Ligerito/TensorSwitch opening against the exact
   maximum compiled relation, including every full-E384 mask, opened-leaf
   tape, SHA-512 frontier node, and parser byte. Both current raw nonlinear
   inventories force at least n16; checked-in n16 model-only screens are
   144,496 bytes with a 64-GiB oracle and 168,688 bytes under a 512-MiB oracle
   bound. Do not
   continue the retained 4+3-tree BaseFold port unless its topology changes:
   its corrected fixed-schedule projection is 1,528,928 bytes at `q=310`.
3. Land the disjoint-domain `P+Z_H R` relation mask and a whole-view simulator.
   The outer endpoint needs two full-E384 dummy multiplication rows, plus exact
   `O`, `G_w`, and `G_r` rank coverage for every raw, folded, and terminal view,
   abort/selective-failure handling, and QROM composition. Diamond ePrint
   2025/1015 Construction 4.1 uses DP24 setup on `ell+1` and appends
   `kappa=gamma*2^vartheta` random coefficients before virtual combination,
   sumcheck, and FRI, so the source-faithful BaseFold repair must be budgeted as
   dimension-doubling unless an exact compiler mapping proves a smaller
   unmasked `ell`. Syntactic n16 slack is not evidence that the mask fits
   without degree growth. A one-level Ligerito screen remains non-ZK until a
   separate hiding wrapper and simulator are implemented and priced.
4. Only then measure the exact proof, bind one canonical parser/envelope, run
   mutation/restart/fresh-sync/reorg transport tests, complete refinement and
   release manifests, and activate under a fresh rules hash. Keep production
   fail closed until all of those artifacts exist.

The concrete source spine for that bounded screen is
`circuits/transaction/src/full_shake448_relation.rs` and
`full_shake448_statement.rs` for the corrected standardized role registry and
statement, `prototypes/standalone-shake256-binius/m4-full-production-prototype/src/lib.rs`
and `src/main.rs` for the one-main relation/wire, and
`prototypes/standalone-shake256-binius/strict-mixed-field/src/lib.rs` for the
existing E384 arithmetic and transcript seam, plus the strict refold/Ligerito
model under `.agent/hardening/binius-pq128-proof-size/` as a non-authoritative
starting point. Do not treat the local model's Pay1x2 number as transferable.
If and only if the exact maximum screen fits, close the whole-view simulator
against `m4-zk-joint-simulator-audit` and `m4-zk-outer-distribution-audit`, then
bind the admitted proof in
`circuits/transaction/src/proof.rs`; do not extend
`smallwood_v6_adapter.rs`, because its occurrence-row representation is the
disqualified path.
