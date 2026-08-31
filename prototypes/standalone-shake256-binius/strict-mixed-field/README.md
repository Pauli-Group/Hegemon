# Strict mixed-field prototype

This isolated crate answers the algebraic part of the strict profile. It does
not claim that the pinned Binius64 proof system already supports the profile.

The pinned revision is
`3f96163049f680b2909f6545690bd929f1b48c44`. Its committed symbols are
`BinaryField128bGhash`, i.e. `GF(2^128)` with modulus
`X^128 + X^7 + X^2 + X + 1`. The pinned IOP traits require the challenge type
to implement `BinaryField`; their binary-tower implementation only supplies
power-of-two extension degrees. There is no `GF(2^384)` type or mixed-field
challenge interface in that source.

This crate provides the missing field as

```text
E384 = GF(2^128)[Y] / (Y^3 + Y + 1).
```

The cubic is certified in the test suite, rather than assumed: the base-field
Frobenius computation gives `Y^(2^128) - Y = Y^2 (mod Y^3 + Y + 1)`, and the
cubic is coprime to `Y^2` because its constant term is one. Hence it has no
root over `GF(2^128)` and is irreducible. Serialization is exactly three
little-endian B128 symbols (48 bytes).

Independent B128 challenges are not an equivalent implementation. Their
componentwise product is the product ring `GF(2^128)^3`, which has nonzero zero
divisors. The zero-divisor test is included because treating three independent
challenges as one scalar would invalidate the field-based
Schwartz–Zippel/FRI reasoning. The protocol must either use `E384` operations
or provide a separate, reviewed direct-product soundness theorem.

## Mixed IOP seam

`lift_b128_codeword` embeds each committed symbol into the constant
coefficient lane of `E384`. `CoefficientLanes` then stores every E384 value as
three parallel B128 vectors. `fold` performs the low-bit-first multilinear
fold

```text
fold(a0, a1; r) = (1-r) * a0 + r * a1
```

using E384 multiplication, and `evaluate_multilinear_b128` checks the result
against the direct multilinear sum. The randomized tests cover arities 0
through 7 and independently test arbitrary E384 lane round trips and one-step
folds. A product-ring negative control uses the same input/challenges and
demonstrates that cross-component products disappear (`Y * Y² = Y + 1` in
E384, but is zero in the componentwise product ring).

The coefficient representation is algebraically exact, but it is not a free
compression: an E384 value costs three 16-byte B128 symbols when all lanes are
materialized. `FieldSerializerCounters` reports this explicitly, while an
explicit 48-byte E384 payload is tracked separately. Both encodings cost 48
bytes per value; transcript-derived challenges still cost zero proof bytes.

`MixedFieldProverChannel` and `MixedFieldVerifierChannel` are the first
type-separated replacement seam for the pinned single-`F` IP channels. Their
committed-symbol type is B128, while their challenge and claim types are E384.
`Shake256E384Transcript` samples one E384 challenge from exactly 48 SHAKE256
bytes and feeds that value back into the transcript. Every 48-byte string is a
canonical E384 element, so there is no rejection loop or sampling bias. The
local dependency-free SHAKE implementation is pinned to the standard
empty-input KAT.

## Executable transparent sumcheck

`prove_toy_mixed_sumcheck` and `verify_toy_mixed_sumcheck_exact` exercise the
seam end to end. The proof uses the canonical `HGMXSC01` grammar, commits the
three B128 coefficient lanes with a 64-byte SHAKE256 root, derives every fold
challenge as E384, sends degree-one round claims as canonical 48-byte E384
values, and exact-consumes the proof. For a table of `N = 2^n` values its wire
is exactly

```text
16 + 48*N + 64 + 96*n bytes.
```

The serializer itself produces the counters: `3*N` B128 symbols, `2*n`
explicit E384 round claims, one 64-byte root, and 16 fixed bytes. For the
four-value KAT this is exactly 464 bytes. Transcript challenges are not charged
as explicit E384 values. Mutation tests reject the root, public claim, context,
round message, truncation, trailing bytes, and wrong magic.

This toy intentionally transmits the full coefficient-lane table. It therefore
has no compact opening, PCS binding theorem, hiding, zero knowledge, degree
budget, or PQ/QROM reduction. It is an executable interface/KAT, not a strict
proof and not a frontier point.

## Authenticated low-degree kernel

`mixed_basefold_pcs.rs` is a separate dependency-free SHA-512 profile. It
implements the scalar Gao--Mateer additive-NTT Reed--Solomon encoder used by
the pinned BaseFold source, DP24 inverse-butterfly folds under true E384
challenges, a constant terminal-code check, and grouped Merkle commitments.
The initial encoded oracle stays B128 on the wire; later folded values are
exactly three ordered B128 coefficient lanes. Every opened grouped leaf carries
one caller-supplied independent 64-byte tape. There is deliberately no master
seed or statement-derived tape API.

Queries use transcript-bound unbiased sampling without replacement. The proof
does not serialize query indexes, duplicate leaves, frontier indexes, or path
padding. Each layer instead serializes the sorted/deduplicated opened-leaf
union followed by the unique depth-first, left-to-right compact Merkle
frontier. The verifier derives that schedule, exact-consumes the wire, rebuilds
every root, checks every fold link, and rejects coefficient, lane, group, root,
context, truncation, and suffix mutations. For a fixed transcript schedule its
exact grammar is

```text
160 + 64*(d+1) + 2^r*(48*g+64)
    + u_0*(16*g+64) + 64*f_0
    + sum_(l=1..d-1) (u_l*(48*g+64) + 64*f_l)
```

where `u_l` is the exact opened-leaf union and `f_l` its compact frontier.
`DistinctQuerySoundness` separately returns the exact fixed-bad-set miss
product `prod_i (M-B-i)/(M-i)`; that product is not promoted into a composed
adaptive FRI/QROM claim.

The dedicated `mixed_basefold_size_report` binary calls the same
`project_retained_m4_mixed_depth` serializer projection used by the kernel and
prints every B128, E384, root, tape, and compact-frontier term. Its optional
argument is the distinct-query count; the default is the incomplete-ledger
`q=310` scaffold:

```text
cargo run --bin mixed_basefold_size_report -- 310
```

For the fixed synthetic roots, the q310 source projection has opened-leaf
counts `[305,310,310,292,310,301,237]`, frontier counts
`[1234,2771,3391,654,2151,937,194]`, and totals 1,528,928 E384 bytes. Passing
the conservative historical `q=319` gives 1,548,704 E384 bytes, 1,763,232
mixed-E512 bytes, and 1,883,136 all-E512 bytes. These are serializer-term
projections, not proof measurements or transcript-independent lower bounds.
The separate common-`2^20` padding formula projects to 4,145,888 bytes at
q319 but has no claim to be the live M4 layout. Exact without-replacement
sampling needs `q=318`, not 319, to exceed the local 264-bit component target.
With the other terms of the current incomplete security scaffold frozen,
`q=310` is its minimum modeled composed->128 count; no production minimum
exists until the missing reductions are proved. The result makes this exact
retained-tree implementation noncompetitive with the retained 1,344,828-byte
comparator. The 524,288-byte constant is a local screening cap, not authority
to disqualify every topology or change the user's proof objective. See
`.agent/hardening/mixed-architecture-size-tournament/QROM_QUERY_AND_SIZE_AUDIT.md`.

The scalar kernel is not the live M4 PCS. It accepts equal-dimension groups;
the actual pinned M4 path already handles input trees of depths
`13,18,20,11` and FRI trees of depths `16,12,9` through
`FRIParams::optimal_for_batch` and `FRIQueryVerifier::new_batch`. The live
prover cannot yet carry E384: `IPProverChannel<F>` sends and samples only `F`,
`FRIFoldProver` stores challenges and every later codeword as `F`, and
`MerkleIPProverChannel<F>` can commit/open only `PackedField<Scalar=F>`.
Closing that seam requires an associated extension element on the prover
channel, canonical SHA-512 E384 transcript serialization, E384 fold buffers,
and coefficient-lane commitment/opening methods while retaining B128 input
oracles. The verifier is already substantially closer because its channel has
`Elem: FieldOps<Scalar=F>` and its mixed-depth query verifier is generic in
that element.

`complete_zk.rs` makes the corresponding privacy gate executable. It checks
the exact fixed-transcript condition
`rank(O*G_r)=rank([O*G_r | O*G_w])`, relation-kernel membership, declared
witness-delta rank, full-E384 endpoint rows, and whole-view coverage. The PCS
exports its raw opening inventory but not the exact relation-bound `G_w` and
`G_r` matrices, so `complete_zero_knowledge`, `composed_pq128_qrom`, and
`production_authorized` all remain false.

The wire model keeps committed symbols compact:

```text
proof_bytes = fixed_bytes
            + 16 * base_symbol_elements
            + 48 * explicit_wide_elements
            + 64 * (merkle_root_count + merkle_auth_node_count)
```

Transcript-derived challenges never increment `explicit_wide_elements`;
explicit E384 sumcheck claims do. The 64-byte digest term is the strict
SHAKE256-512 commitment/authentication width. This formula is exact for the
declared wire fields; it is not a measured strict proof because the pinned
Binius verifier has not been changed to carry `E384` challenges.

Run the KATs with:

```sh
cargo test --manifest-path prototypes/standalone-shake256-binius/strict-mixed-field/Cargo.toml
```

Run the fixed executable toy with:

```sh
cargo run --manifest-path prototypes/standalone-shake256-binius/strict-mixed-field/Cargo.toml
```

Run the source-static serializer report with:

```sh
cargo run --manifest-path prototypes/standalone-shake256-binius/strict-mixed-field/Cargo.toml \
  --bin mixed_basefold_size_report
```

The toy must report `research_only=true`, `proof_bytes=464`, `b128_symbols=12`,
`explicit_e384_claims=4`, `roots=1`, and `rounds=2`. The last dependency-free
direct run passed 48 tests. The current source contains 51 test functions after
later complete-ZK additions; those additions have not been rerun because the
hard disk stop is active. These commands remain subject to the repository
disk-admission gate; the recorded validation used a lightweight direct Rust
build and left no Cargo target or binary behind.

No consensus code imports this crate. Neither the toy channel nor the
standalone scalar PCS earns a live M4, ZK, PQ128/QROM, proof-size, or production
capability. The retained-tree E384 projection is also larger than the retained
comparator before its missing gates are priced, so the smallest-route screen
must change the opening topology, not merely finish this channel port.
