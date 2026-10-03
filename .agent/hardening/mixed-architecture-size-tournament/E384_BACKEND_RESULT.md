# E384 BaseFold backend result

Status: **source-verified research kernel landed; retained-tree implementation
noncompetitive; qualifying frontier empty**.

This report distinguishes executable code, serializer-derived static
accounting, retained weak-profile measurements, and missing security evidence.
Nothing here is a complete-ZK, PQ128/QROM, live-M4, or production proof.

## Delivered executable kernel

The isolated crate now contains:

- `src/mixed_basefold_pcs.rs`: exact GHASH-B128 Gao--Mateer
  Reed--Solomon encoding, true cubic-E384 DP24 folding, SHA-512 transcript and
  Merkle commitments, B128 initial openings, three-lane later openings,
  caller-supplied per-leaf independent 64-byte tapes, canonical distinct-query
  sampling, compact per-layer Merkle frontiers, exact parser/serializer, and
  mutation negatives.
- `src/bin/mixed_basefold_size_report.rs`: an executable report generated from
  the serializer formula and the retained 4+3-tree geometry.
- `src/complete_zk.rs`: integrated fail-closed exact rank audit from the
  complete-ZK workstream. It requires the real relation-bound `O`, `G_w`, and
  `G_r`; the PCS currently exports only its raw observation inventory.
- `src/authenticated_basefold.rs`: a lower-level authenticated E384
  coefficient-lane fold KAT. Its own header correctly withholds a PCS claim.

The canonical scalar-kernel grammar is

```text
B(d,r,g,q)
 = 160 + 64*(d+1) + 2^r*(48*g+64)
   + u_0*(16*g+64) + 64*f_0
   + sum_(l=1..d-1) [u_l*(48*g+64) + 64*f_l],
```

where `u_l` is the sorted/deduplicated transcript-derived opened-leaf union and
`f_l` is the unique minimal depth-first compact frontier. The proof carries no
query indexes, duplicate policy, frontier indexes, or padding authority.

The exact fixed-bad-set miss probability for `q` queries without replacement
from `M` pairs with `B` bad pairs is separately emitted as

```text
P[miss] = product_(i=0..q-1) (M-B-i)/(M-i).
```

This is not an adaptive/composed FRI theorem.

## Source validation

No Cargo, Lake, maximum proof, or heavy build ran. The dependency-free sources
were formatted, compiled directly with `rustc`, and the resulting temporary
test binary was run:

```text
48 passed; 0 failed; 0 ignored
```

That is the last executed checkpoint. The current source contains 51 test
functions after later complete-ZK additions; those additions were not rerun
after the hard disk stop.

The suite covers FIPS SHA-512 KATs; E384 arithmetic; exact RS/fold/terminal
checks; independent tape geometry; canonical distinct queries; coefficient,
lane, group, root-order, context, truncation, and suffix rejection; compact
frontier reconstruction; and the fail-closed complete-ZK rank controls.

The executable size report prints `complete_zero_knowledge=false`,
`composed_pq128_qrom=false`, and `production_authorized=false`.

## Corrected 4+3-tree fixed-schedule byte result

The retained M4 proof has four input trees at depths `13,18,20,11`, three FRI
trees at depths `16,12,9`, fold arities `4,4,3`, and a 512-element terminal.
For the conservative with-replacement 264-component-bit source screen
`q=319`, the exact fixed-synthetic-transcript opened
leaf and compact-frontier counts are:

```text
opened leaves:  [315, 319, 319, 296, 318, 310, 233]
frontier nodes: [1224,2807,3445, 637,2171, 919, 197]
```

The E384 serializer-term projection is:

| term | count | bytes |
|---|---:|---:|
| Input B128 values | 2,498 | 39,968 |
| Fold-round E384 values | 11,912 | 571,776 |
| E384 terminal values | 512 | 24,576 |
| Explicit E384 M4 messages | 984 | 47,232 |
| SHA-512 roots | 8 | 512 |
| Independent opened-leaf tapes | 2,110 | 135,040 |
| Compact-frontier SHA-512 nodes | 11,400 | 729,600 |
| **Projection** |  | **1,548,704** |

This count sets framing, relation masks, the two full-E384 dummy multiplication
rows, complete-ZK repair, QROM composition, parser integration, and production
transport to **zero**, but its Merkle counts come from fixed synthetic roots.
It is therefore neither a proof-size measurement nor a transcript-independent
lower bound. It exceeds the local 524,288-byte screening cap by **1,024,416
bytes**. The explicit common-`2^20` padding alternative is worse:
**4,145,888 bytes**, exceeding the cap by **3,621,600 bytes**.

The query premise has also been corrected. With exact sampling without
replacement from `M=2^20`, `q=318` is the minimum exceeding the local 264-bit
component target. With the other terms in the incomplete strict-profile
scaffold frozen, `q=310` is its minimum modeled composed->128 count. The exact
fixed-schedule q310 projection is 1,528,928 bytes. Neither count is a production
minimum because the PCS/IOP/Fiat--Shamir/hash/grinding reductions are missing.
See `QROM_QUERY_AND_SIZE_AUDIT.md` for the exact product, union arithmetic,
q310/q116 decompositions, rate screen, and complete-ZK capacity consequence.

The old 448,224-byte one-copy artifact used `q=116`, 50-byte digests, B128 fold
values, no independent opened-leaf tapes, and no strict or complete-ZK claim.
It is neither a baseline nor a contradiction to this fresh static result.

## Actual pinned M4 integration seam

Pinned revision `3f96163049f680b2909f6545690bd929f1b48c44`
already has the right mixed-depth batching shape:

- `crates/iop/src/fri/common.rs`: `FRIParams::optimal_for_batch` and
  `CodewordSpec::log_lift` select mixed input lengths.
- `crates/iop/src/fri/verify.rs`: `FRIQueryVerifier::new_batch` accepts all
  input commitments and is generic in `E: FieldOps<Scalar=F> + From<F>`.
- `crates/iop/src/fri/batch.rs`: verifier-side input batching and FRI coset
  folding are already extension-element generic.

The prover is not mixed-field generic:

- `crates/ip-prover/src/channel.rs`: `IPProverChannel<F>` sends, observes, and
  samples only `F`; it has no associated extension element.
- `crates/iop-prover/src/merkle_channel.rs`:
  `MerkleIPProverChannel<F>` commits and opens only
  `PackedField<Scalar=F>` and its multi-opening grammar repeats per-query
  paths/internal-layer advice rather than this module's canonical frontier.
- `crates/iop-prover/src/fri/fold.rs`: challenges are `Vec<F>`, later
  codewords are `FieldBuffer<F>`, and `commit_round` commits only `F`.
- `crates/iop-prover/src/fri/query.rs`: fold-round query oracles likewise carry
  only `F` buffers.

A real port must therefore add a prover-channel associated `Elem`, SHA-512
E384 sampling/serialization, E384 fold buffers, and explicit E384-to-three-B128
lane commitment/opening methods while preserving B128 input oracles. It must
also replace the current opening advice with the same canonical compact union
on both prover and verifier. The current M4 candidate now resolves the exact
local `../binius64` tree and binds its framed 688-file tree through a SHA-512
constant checked by `check_source.py`. That closes dependency provenance only;
the candidate remains uncompiled and the standalone module still cannot be
described as live M4 PCS integration.

Because the corrected retained-tree projection is larger than both the local
screening cap and the retained 1,344,828-byte comparator before missing repair
costs, performing that invasive port is not the smallest implementation route
without a different opening topology. The scalar kernel is intentionally left
isolated and all capability flags remain false.

## Bounded E512 competitor

A degree-four E512 extension over B128 could satisfy the upstream
power-of-two `ExtensionField` shape, but no such scalar/packed field exists in
the pinned tree. Keeping B128 commitments still requires the same associated
prover-element and coefficient-lane channel refactor as E384. Avoiding that
refactor by setting the whole protocol scalar to E512 widens the input-oracle
openings as well and changes the M4 packing/relation.

On the exact same compact query/frontier schedule:

| candidate | fixed-schedule projected bytes | over local 524,288 screen |
|---|---:|---:|
| Mixed B128/E384 | 1,548,704 | 1,024,416 |
| Mixed B128/E512 | 1,763,232 | 1,238,944 |
| All-E512 stock scalar | 1,883,136 | 1,358,848 |

The mixed E512 delta is exactly
`16*(11,912+512+984)=214,528` bytes. The all-E512 route adds another
`48*2,498=119,904` bytes for initial openings. E512 is therefore more
invasive or materially larger on this schedule and cannot be the smallest
repair.

## Security and winner decision

The integrated complete-ZK audit found a concrete generic failure before those
missing objects: Gao--Mateer leaf zero is systematic and the initial opening
reveals `pi` and `omega` separately, so appended dummies do not mask an active
coordinate. Conditioned on that query, two same-statement views have exact TV
one. A surviving route needs a disjoint commitment domain and
`P_masked=P+Z_H R` with at least q independent B128 coefficients, then the
exact compiler-bound witness generator `G_w`, relation-mask generator `G_r`,
and whole SHA-512 QROM simulator. Diamond ePrint 2025/1015 Construction 4.1
runs DP24 setup on `ell+1` and appends `kappa=gamma*2^vartheta` random
coefficients before virtual combination, sumcheck, and FRI. A source-faithful
BaseFold ZK repair must therefore be screened as dimension-doubling, not as a
zero-overhead use of apparent n16 slack, unless the exact compiler mapping
proves a smaller unmasked `ell`. No PCS/IOP/Fiat--Shamir/hash/grinding/union
composition certificate exists. No Rust/M4 refinement, production parser,
same-byte transport, release manifest, or retained strict proof artifact
exists. All flags correctly remain false.

There is **no qualifying architecture winner**. Direct Boolean SmallWood is
eliminated at at least 75.59 MB; this retained-tree E384 projection is larger
than the 1,344,828-byte comparator before strict repair; E512 is larger still;
stock repeated M4 is weak-profile and not complete ZK.

The quickest next falsifiable Boolean-native route is a **one-level mixed-field
Ligerito/TensorSwitch opening over the eventual exact compiled M4 relation**, because it
removes the three wide FRI-round trees that dominate this result while reusing
the exact M4 compiler and E384 arithmetic. The current diagnostic finalists
have 79,128 raw nonlinear words for mixed BLAKE2b-448/SHAKE and 90,600 for
split SHA3-512/SHAKE. Packing two u64 words per B128 symbol gives lower bounds
of 39,564 and 45,300, so either forces at least n16 before non-hash work. The
checked-in n16 one-level model is 144,496 bytes only with a 64-GiB oracle, or
168,688 bytes under a 512-MiB oracle screen. Both are non-ZK, unmeasured, and
omit a separately proved hiding wrapper and exact M4 binding; syntactic n16
slack is not evidence of free ZK capacity, and Diamond's BaseFold construction
does not make the one-level protocol ZK. The old 112,784-byte
Pay1x2/n14 number is not authority. Do not resume the live 4+3-tree BaseFold
channel port unless the topology changes and its exact repaired geometry beats
this route.
