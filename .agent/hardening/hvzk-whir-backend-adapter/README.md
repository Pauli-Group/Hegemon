# HVZK-WHIR backend adapter: source-only, fail-closed

This directory contains the most concrete adapter that the present evidence
supports. It implements an exact bounded outer wire, the current odd-field
R1CS input grammar, conventional SHA-512/SHAKE256 framing, transcript replay,
Goldilocks canonicality, and explicit prove/verify entry points. Those entry
points always return the complete unresolved production-gate set after any
input or wire rejection.

It is not a proof backend. Plonky3 at
`5df89eeadae18d6935bb874f8a92808dcc200c9d` supplies
`HidingWhirPcs`, a hiding multilinear PCS whose witness is `Poly<F>` and whose
opening protocol is `Vec<Point<EF>>`. It does not supply CFW26 Section 11's
R1CS-to-constrained-code carrier. The primary paper's mask coefficient and
inner succinct-linear-form state are internally inconsistent, so this adapter
does not silently select a repair.

## Exact relation input boundary

The BLAKE2b-448/SHAKE odd-field compiler currently exposes 10,152 public bits:
869 canonical `HX448C02` statement bytes followed by 50 little-endian
consensus-state transport words (400 bytes). Its private transport is exactly
1,209 words (9,672 bytes); the five padding bytes in each fixed ciphertext
allocation must be zero. The final retained source geometry is 20,457,227
constraints, 19,311,555 nonconstant variables, and 94,551,238 sparse-matrix
nonzeros.

The candidate equal-half Section 11 embedding needs `ell = 2^25`, because the
19,301,403 private-plus-derived variables exceed `2^24`. The full assignment
and padded row carrier are therefore `2*ell = 2^26`, not `2^25`. One base-field
half alone is 256 MiB of raw scalar values and the two-half assignment is 512
MiB before matrices, masks, codewords, or prover state. These are source-shape
memory identities, not proof-byte estimates.

The paper-described communication shape at this `ell` has 78 inner-mask
oracles, 26 outer-mask oracles, and one witness oracle: 105 encoded oracles in
total, with the same 105 multiplier on the stated ZK union term. The audited
Section 11 Step 9 also has two typing defects, so no theorem is inherited and
none of those 105 oracles is mapped to the one-polynomial `HidingWhirPcs` API.
Specifically, the printed `st2=(0,1,0,...)` selects coefficient 1 rather than
the value `s(1)` (the needed state is `pow(1)=(1,1,...)`), and the main form
needs the missing typed definition `row_M(M,alpha)[b]=Mhat(alpha,b,1)`. The
mask `X^2-X` is an immediate counterexample to the printed endpoint check: it
vanishes at both endpoints but fails the printed output. A one-polynomial PCS
serialization therefore cannot be reported as the full R1CS proof.

## Field and conventional-hash map

The pinned Goldilocks source implements two-adic binomial extensions at degrees
2 and 5. `BinomialExtensionField<Goldilocks,5>` satisfies the generic
`ExtensionField + TwoAdicField` shape required by `HidingWhirPcs`, has
two-adicity 32, and can source-shape the candidate `num_variables = 25` half.
No degree-6 or degree-8 Goldilocks binomial type exists at this pin. E320 is
only API-feasible: no concrete composition ledger has selected it or proved
strictly more than 128 post-quantum/QROM bits.

Plonky3's local `ProtocolParameters::security_level` is not strict-security
authority here. `CapacityBound` depends on a conjectural capacity/list-decoding
regime, and the pinned Johnson path keeps only a dominant BCSS25 term using
floating-point arithmetic. Both remain diagnostic. The adapter can
structurally validate a separately supplied, SHA-512-pinned exact
UniqueDecoding or full-Johnson certificate only if it covers PCS, IOP/IOR,
Fiat-Shamir, hash, grinding, every union term, and the QROM reduction with an
exact lower bound strictly above 128 bits. No such certificate is present, and
even a structurally admitted certificate would not bypass the other production
blockers.

The direct modified-BCS hiding term is `p*2^(-lambda/4+2)`, where `p` is the
total IOP proof length, not a witness or one codeword count. Using only the
absolute floor `p >= ell = 2^25`, lambda=512 gives exactly `2^-101`; strict
`<2^-128` first needs integer lambda=621, or 624 bits (78 bytes) when
byte-aligned. That ell-only bound is already too weak for the printed message
shape: with canonical 320-bit E320 elements and rate-one minima
`ell + 78*4 + 26*8 + 26*9 + 4`, `p` is at least 33,555,190 field elements or
10,737,660,800 bits. Lambda=512 then gives approximately `2^-92.678`; 648 bits
still fails and 656 bits (82 bytes) is the first byte-aligned value passing
only this stronger floor. The adapter exposes a domain-separated,
parameterized SHAKE256 salt derivation, but rejects 624 and admits 656 only as
an unselected lower-bound candidate. Actual code lengths and randomness can
push `p` higher, so actual minimum lambda, salt selection, canonical wire
location, and total wire delta all remain null. At the E320 rate-one floor,
replacing one 64-byte salt-shaped value would add 18 bytes. This does not alter
the 64-byte SHA-512 transcript/MMCS type map.

The generic API also permits a 64-byte conventional SHA-512 type shape:

```text
HashChallenger<u8, HegemonSha512Hasher, 64>
  -> SerializingChallenger64<Goldilocks, ...>

SerializingHasher<HegemonSha512Hasher>
CompressionFunctionFromHasher<HegemonSha512Hasher, 2, 64>
  -> MerkleTreeMmcs<Goldilocks, u8, ..., 2, 64>
```

`SerializingChallenger64::new` is generic and can wrap the 64-byte inner
challenger; its `from_hasher` convenience constructor is only specialized for
32 bytes. This source type map is not an exact transcript/MMCS bridge. Plonky3's
generic hashing calls do not automatically implement this adapter's role and
length framing. Local Keccak-256 is explicitly not a fallback.

## Verification boundary

`src/hash.rs` contains dependency-free reference SHA-512 and SHAKE256,
including FIPS KATs. `src/lib.rs` implements the exact-consumption codec,
statement/private-input validation, transcript replay, challenge sampling, and
fail-closed backend interface. `src/plonky3_api.rs` freezes the inspected API
types and method sequence. `check_adapter.py` performs only bounded source and
artifact checks; it does not invoke Cargo, Rust, a prover, or dependency fetches.

Run the source-only gate with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hvzk-whir-backend-adapter/check_adapter.py
```

No proof has been generated or measured. `proof.bytes` remains null and
production authority remains false.
