# Strict E256-by-two mixed-field IOP seam

This isolated prototype implements a real quadratic extension already present
in pinned Binius and tests two protocol repetitions over one committed B128
table. It does not implement or claim a strict Hegemon proof backend.

The pinned source revision is
`3f96163049f680b2909f6545690bd929f1b48c44`. Its `GhashSq256b` field is

```text
B128 = GF(2)[X] / (X^128 + X^7 + X^2 + X + 1)
E256 = B128[Y] / (Y^2 + X*Y + X)
```

An E256 value is `a + b*Y`, encoded as the 16-byte little-endian B128
coefficient `a` followed by `b`. The code uses the pinned reduction
`Y^2 = X*Y + X`. The test suite checks the characteristic-two irreducibility
criterion directly: after scaling the quadratic to `Z^2 + Z + X^-1`, the
absolute B128 trace of `X^-1` is one. Thus each stream uses a field, not two
independent B128 coordinates.

## What the seam implements

`DualE256Transcript` starts two SHAKE256 branches from the same public context
and one SHAKE256-512 B128 Merkle root. The branches are separated by fixed
`stream-a` and `stream-b` frames. Challenge responses feed back only into the
branch that produced them, so sampling A then B gives the same per-stream
sequences as sampling B then A. Each challenge is exactly 32 XOF bytes mapped
bijectively to two B128 coefficients.

`evaluate_dual_multilinear_b128` lifts one B128 table into E256 and evaluates
its multilinear extension independently at the two challenge points. The
randomized tests compare arities zero through seven with a direct multilinear
sum. They also compare 256 B128 products with a separate shift-and-reduce
routine and 256 E256 products with a separate polynomial reduction routine.

`B128MerkleTree`, `QuerySchedule`, and `CanonicalOpeningProof` exercise the
opening boundary. Both modes carry exactly one root:

- `Shared` derives one unique query set and reuses it for both repetitions.
- `Independent` derives separate unique sets and serializes their sorted union.

Indices are transcript-derived and cost zero wire bytes. The research grammar
`HGE2X2P1` exact-consumes a 16-byte header, one 64-byte root, two explicit
32-byte E256 terminal claims, and for each distinct opened index one 16-byte
B128 value plus a full `n`-node SHAKE256-512 authentication path. It does not
deduplicate common internal path nodes and does not call that cost a compressed
multiproof.

For a schedule whose canonical union contains `U` indices, the serializer's
exact equation is

```text
proof_bytes = 16 + 64 + 2*32 + U*(16 + 64*n).
```

For the fixed n15 reference and 264 unique requested indices per stream:

```text
shared:      U=264, overlap=264, bytes=257,808
independent: U=525, overlap=3,   bytes=512,544
```

Those are exact bytes for this declared full-path grammar, not a measured
Binius proof. The number 264 is an input to the wire model; this prototype does
not prove that it is the right FRI/proximity query count. The reference root is
the actual SHAKE256-512 Merkle root of 32,768 deterministically generated B128
symbols; the Rust test and independent Python audit both rebuild it rather than
treating an arbitrary digest as a table commitment.

### Do not substitute the optimistic rate-dependent screen

These figures are intentionally not the figures in
`.agent/hardening/binius-pq128-proof-size/strict-mixed-pcs-screen/`. This KAT
fixes 264 unique requests **per stream**, opens the unencoded `2^15` table with
one B128 symbol per leaf, uses 64-byte SHAKE256-512 nodes, and sends a complete
15-node path for every distinct leaf without deduplicating internal nodes.

The other screen applies the optimistic TensorSwitch distance term
`ceil(264 / -log2(1-(1-rate)^2))`, yielding 637/222/127/87/66 queries at rates
`1/2` through `1/32`. It expands the oracle to `2^15 * rate_denominator^2`,
packs four B128 symbols per leaf, deduplicates a worst-case canonical Merkle
frontier, uses 56-byte SHAKE256-448 nodes, and charges a published first-level
`5*q` field-message term. Its E256-by-two rows use one shared proximity
schedule and report only a first-level lower bound, not a complete proof.

Consequently, this crate's 257,808/512,544-byte full-path opening KAT must not
be compared as if it refuted or verified that screen's 104,208/88,248-byte
rate-`1/16`/`1/32` first-level models. The assumptions, encoded-oracle sizes,
hash widths, query counts, path encodings, and included protocol messages are
different. Both remain fail-closed.

## Security verdict

Two E256 streams are not one E512 field. Treating a pair as a componentwise
product ring would introduce zero divisors. A degree-bound scaffold may note
that 256 minus an assumed degree log of 120 leaves 136 bits per field test, but
multiplying two error terms requires a theorem covering conditional
independence, the shared statement/table/transcript, aborts, query schedules,
and the quantum random-oracle model. No such theorem is provided here.

The Merkle KAT authenticates the opened B128 leaves. It does not bind the two
explicit E256 claims to the whole table, prove FRI proximity/degree, hide the
openings, or simulate the complete transcript. Therefore the fail-closed
manifest keeps all of these false: PCS binding proof, proximity proof,
dual-stream independence theorem, product soundness, complete zero knowledge,
QROM composition, strict PQ128, current 384-bit challenge-policy compliance,
and production-frontier eligibility.

In short, shared queries are smaller but cannot support a product conclusion;
independent queries are almost twice as large and still need the missing
composition theorem. This seam validates arithmetic and exposes costs. It is
not a compactness or security win.

## Disk-safe validation

Check `df -k .` first. Do not invoke Cargo below 28 GiB free. The recorded
validation used a temporary direct-Rust test binary and removed it:

```sh
rustfmt --edition 2024 prototypes/standalone-shake256-binius/strict-e256x2-iop/src/lib.rs
rustc --edition 2024 --test -C opt-level=1 -C debuginfo=0 \
  -o /private/tmp/hegemon-e256x2-tests \
  prototypes/standalone-shake256-binius/strict-e256x2-iop/src/lib.rs
/private/tmp/hegemon-e256x2-tests
rm /private/tmp/hegemon-e256x2-tests
PYTHONDONTWRITEBYTECODE=1 python3 \
  prototypes/standalone-shake256-binius/strict-e256x2-iop/check_manifest.py
```

The current dependency-free suite has 13 tests. The Python checker independently
derives the n15 schedules and must print `E256X2_MANIFEST_PASS`.

No production, consensus, ledger, or frontier file imports this prototype.
