# VOLE-in-the-head screen for full M4

Status: **source-only, not a frontier point, not a proof implementation, and
not a strict-security claim.** This directory does not import production code,
run a prover, or alter the sealed ledger.

## Result

No screened transparent VOLE-in-the-head, QuickSilver, or MPC-in-the-head
instantiation beats the `124,068`-byte cap for the frozen full M4 relation at a
defensible strict PQ128 boundary.

The relation has `83 * 24 * 25 = 49,800` 64-bit word-AND operations in Keccak
chi. Each operation is 64 independent Boolean ANDs, so the valid binary
relation has `3,187,200` Boolean multiplications. Pricing 49,800 word-ANDs as
49,800 field multiplications gives a seductive `99,600`-byte figure at the
paper's 16-bit/gate rate, but it is invalid: component-wise multiplication in
`F2^64` is not multiplication in a field. The valid generic screen is
`3,187,200 * 16 / 8 = 6,374,400` bytes. The primary paper's Limbo/MPCitH
comparison is `16,732,800` bytes at 42 bits per Boolean AND.

The real relation-specific improvement is the degree-16 Keccak construction
from the PoMFRIT paper. It commits one 1,600-bit state every six rounds and
checks each six-round interval by evaluating four forward rounds (degree 16)
and two inverse rounds (degree 9). This reduces the committed nonlinear data
for one Keccak-f permutation from 4,800 to 800 bytes. The model independently
prices a one-permutation, lambda-128 forest at `14,690` bytes, within 210 bytes
of the paper's measured `14.9 KB` proof without fitting a constant to that
result.

For full M4, however, those checkpoint vectors are repeated across the small
VOLE instances. Exhaustively screening checkpoint spans 1 through 24 gives:

| screen | best span / degree | total bytes | cap multiple | conservative numeric QROM bits |
|---|---:|---:|---:|---:|
| FAEST-256s-shaped, not strict PQ128 | 12 / 243 | 1,031,576 | 8.31x | 120 |
| lambda-384 strict numeric screen, transparent forest | 12 / 243 | 1,632,012 | 13.15x | 170 |

Lambda 256 is not silently labeled PQ128: after the degree term, an eight-bit
union reserve, and a conservative QROM square-root screen, it has only 120
numeric bits. Lambda 384 clears the numeric screen, but no official FAEST
parameter set or exact QROM theorem exists for this customized M4 transcript,
so all security/capability gates remain false.

There is also a checkpoint-independent no-go for the modeled strict forest:
replicating only the existing 5,368 private bytes across 32 small VOLEs costs
`171,776` bytes. That already exceeds the cap before one Keccak checkpoint,
tree opening, QuickSilver response, public input, transcript seed, or parser
byte is added. Evading this bound requires a different proven VOLE generator
or witness commitment, not relabeling word-ANDs or deleting proof sections.

## Relation pin and serialization boundary

The byte model pins these source facts:

- `83` Keccak-f permutations;
- `671` private 64-bit words (`5,368` bytes);
- `114` public 64-bit words (`912` bytes);
- `49,800` lane-word ANDs and `3,187,200` Boolean ANDs.

The existing M4 transport is not “114 arbitrary integers.” The public transport
is the exact 853-byte canonical statement followed by three zero pad bytes to
the 856-byte word boundary, then the 56-byte verifier-derived `intent.1`
digest. It is chunked with `u64::from_le_bytes`. The private witness is the
exact 5,368-byte stream from
`serialize_private_witness`: semantic integers and Boolean words are encoded
big-endian, opaque byte arrays are copied verbatim, and each eight-byte chunk
is then loaded with `u64::from_le_bytes`. A future VOLE circuit must prove that
wire bit `8*j+k` is `(serialized[j] >> k) & 1`; changing this mapping changes
the relation.

The proposed standalone envelope in `wire_layout.py` embeds the 912 public
bytes and has a fixed 200-byte little-endian header. It rejects unknown flags,
wrong geometry, nonzero reserved bytes, inconsistent section lengths,
truncation, and trailing bytes. This is only a transport parser; the production
parser gate stays false until a cryptographic verifier consumes every section
and negative vectors cover all malleability cases.

## Exact priced sections

For a checkpoint span `s`, the model computes the minimum degree

`d = min_a max(2^a, 3^(s-a))`.

It then prices these standalone proof sections, in order:

1. fixed parser header and embedded 114-word public instance;
2. `tau-1` small-VOLE correction vectors;
3. VOLE consistency response;
4. witness/checkpoint derandomization vector;
5. all `d` QuickSilver response coefficients (one more than FAEST's compact
   reconstructed-coefficient encoding);
6. conservative per-tree GGM seed openings and hidden-leaf commitments;
7. 64-byte SHAKE256-512 final Fiat-Shamir challenge and 64-byte salt;
8. the `4*lambda`-bit complete-ZK simulator randomizer from the PoMFRIT
   appendix;
9. the 32-bit counter.

The forest opening deliberately avoids credit for FAEST v2's one-tree
compression at unsupported lambda 384. The exact FAEST-v2 formula is included
separately and regression-tested against the official 4,506-byte FAEST-128s
and 20,696-byte FAEST-256s rows.

## Transcript proposal and security gates

A future implementation should use SHAKE256 with exactly 64 output bytes per
Fiat-Shamir call. Each call must absorb a fixed ASCII protocol/version label,
the 64-byte relation digest, the complete 912-byte public transport, the phase
number, and length-prefixed prior proof sections. All integer lengths are
little-endian and no raw concatenation without lengths is allowed. Challenge
field elements use a separately specified canonical polynomial basis; unused
high bits and padding must be zero and rejected otherwise.

This proposal has no setup or CRS, but it is not admitted because the following
are still missing:

- an exact scalar-M4-to-VOLE relation refinement, including SHAKE bit order,
  masks, inactive canonicalization, auth modes, balance, and root equivalence;
- a complete-ZK simulator theorem for the exact standalone transcript;
- a QROM proof for the exact multi-round SHAKE256-512 transform and selected
  VOLE parameters;
- an official/independently reviewed lambda-384 implementation;
- a production verifier, exact parser integration, and adversarial vectors.

## Run

These commands are lightweight and do not build Rust or generate proofs:

```sh
cd .agent/hardening/binius-pq128-proof-size/vole-zk-screen
python3 -m unittest -v test_vole_zk_screen.py test_wire_layout.py
python3 vole_zk_screen.py --profile strict384 --compact
python3 vole_zk_screen.py --profile faest256 --compact
```

## Primary sources and official implementations

- Baum et al., *Publicly Verifiable Zero-Knowledge and Post-Quantum Signatures
  from VOLE-in-the-Head*, CRYPTO 2023, ePrint 2023/996. Table 1 gives 16 bits
  per Boolean AND for the binary VOLEitH construction and 42 for Limbo at
  128-bit soundness: <https://eprint.iacr.org/2023/996.pdf>
- Yang, Sarkar, Weng, and Wang, *QuickSilver: Efficient and Affordable
  Zero-Knowledge Proofs for Circuits and Polynomials over Any Field*, CCS 2021:
  <https://eprint.iacr.org/2021/076.pdf>
- FAEST team, *FAEST v2 Algorithm Specifications*. Section 3.1 gives the exact
  signature formula; sections 5--7 give the proof components and parser order;
  section 9 gives the ROM/QROM boundaries:
  <https://faest.info/faest-spec-v2.0.pdf>
- Official FAEST reference implementation:
  <https://github.com/faest-sign/faest-ref>
- Baum et al., *Concretely Efficient Blind Signatures Based on VOLE-in-the-Head
  Proofs and the One-More Preimage Problem*, USENIX Security 2026 prepublication.
  It gives the degree-16 Keccak checkpoint construction, the 800-byte
  nonlinear vector, 14.9 KB proof, exact `ell+t` plus `d` QuickSilver
  communication, and the `4*lambda` complete-ZK randomizer:
  <https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_baum.pdf>
- Official EMP QuickSilver/Wolverine implementation. It is interactive and
  designated-verifier, so it fails the standalone-proof requirement by itself:
  <https://github.com/emp-toolkit/emp-zk>
- Official Picnic reference implementation and specification. Picnic is a
  transparent MPC-in-the-head comparator, not a compact escape from M4's
  nonlinear scale: <https://github.com/microsoft/Picnic>
- NIST FIPS 202 for SHAKE256:
  <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf>
