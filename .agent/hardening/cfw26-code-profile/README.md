# CFW26 exact code/profile screen

Verdict: **disqualified, source-only, fail closed**. This package turns the
CFW26 Section 11 `ell=2^25` shape into one fully enumerated plain
Reed--Solomon profile, but it is not a proof system, a proof artifact, or a
production parameter set. `proof_bytes` is deliberately `null`.

## Exact code selection

The candidate field is the locally implemented Goldilocks degree-five
extension `F_p[X]/(X^5-3)`, where `p=2^64-2^32+1`. A field element is exactly
five canonical little-endian `u64` coefficients, or 40 bytes. The RS
coefficient order is `randomness || message`, so the random coefficients have
degrees `0..r-1`; Proposition 3.19's Vandermonde argument gives perfect
privacy for at most `r` distinct positions.

- Main code: message `2^25`, randomness/query budget `512`, dimension
  `33,554,944`, block `2^26`, one E320 element per symbol.
- Inner mask code: effective message length `4`, padded with four fixed zeros
  into the common eight-element mask message, randomness/query budget `512`,
  dimension `520`, block `2^10`.
- Outer mask code: message length `8`, randomness/query budget `512`,
  dimension `520`, block `2^10`.
- Proximity radii are exactly `65535/262144` and `63/256`. Twice each radius
  is strictly below the corresponding RS minimum distance. The exact
  spot-check terms are `(196609/262144)^512` and `(193/256)^512`, both below
  `2^-128`.

`profile.json` lists every codeword separately: one witness, 78 inner masks,
and 26 outer masks, for exactly 105 Section 11 encoded oracles. The common
mask code implements the paper's stated zero-padding route back to the common
constrained-code relation.

## Exact interactive communication

The profile composes the Section 11 IOR with Construction 7.2, the paper's
theorem-compatible non-succinct base IOPP. Construction 7.2 sends a second
main codeword and 104 second-layer mask codewords. Construction-level
accounting also retains the explicitly sent `mu'` and `mu'_i` targets; these
183 field elements are not visible in Theorem 7.1's displayed communication
formula.

The exact prover communication is

```text
(m + 104*mzk) + 238
+ (m + 104*mzk) + 183
+ (ell + r + 104*(ellzk + rzk))
= 67,215,360 + 238 + 67,215,360 + 183 + 33,609,024
= 168,040,165 E320 field elements
= 53,772,852,800 bits
= 6,721,606,600 bytes.
```

This is the BCS `p(x)` used in the direct privacy term. It is not a measured
non-interactive proof size.

## BCS privacy and exact wire projections

BCS Lemma 3.4 and Lemma 7.5 use an oracle output of `lambda` bits and a fresh
`2*lambda`-bit salt per real leaf, with classical statistical term

```text
p(x) * 2^(-lambda/4 + 2).
```

For the exact `p(x)` above, `lambda=660` fails the strict `<2^-128` test and
the first multiple of four that is also byte aligned is `lambda=664`. Thus a
direct theorem-shaped leaf uses an 83-byte output and a 166-byte salt. This is
only a classical explicitly-programmable-ROM calculation; BCS does not supply
the required QROM theorem or a concrete SHAKE256 reduction.

The canonical theorem-faithful projection serializes every E320 prover
message as bits and builds 30 bit-leaf Merkle trees. All verifier-consumed
field elements expand to 320 bit queries. A bit opening contains one canonical
value byte, a 166-byte salt, and `depth*83` sibling bytes. Query order and bit
positions are transcript-derived, so no redundant index is carried. The exact
wire equation is

```text
176 + 30*83 + 83 + sum_round q_i*(1 + 166 + depth_i*83)
= 32,252,325,377,789 bytes.
```

For sensitivity only, the ledger also gives an unproved field-symbol batching
projection with 210 separate codeword trees and fixed individual paths:

```text
176 + 210*(12+83)
+ 1024*(16+40+166+26*83)
+ 106496*(16+40+166+10*83)
+ 3*12 + 33609445*40
= 1,458,868,874 bytes.
```

The field-symbol projection is not covered by the cited bit-query BCS theorem
and is not advertised as a proof. Both projections exceed the retained
17 MiB source-wire diagnostic cap by orders of magnitude.

## Fail-closed boundary

The local Section 11 repair checks factor-two consistency, `st2=pow(1)`, a
typed `row_M(alpha)`, and the corrected RBR numerator/premise, but independent
theorem inheritance is still false. The base IOPP's two MCA terms have no
selected exact bound. Modified-BCS QROM lifting, SHAKE256 ideal-to-concrete
QROM loss, hash/grinding/retry/RNG/history unions, verifier refinement, and
consensus lifecycle refinement are all absent rather than silently zero.

Accordingly:

```text
complete_zk = false
strictly_greater_than_128_pq_qrom = false
measured_retained_proof_artifact = false
proof_bytes = null
production_authorized = false
```

## Recheck

From the repository root, without Cargo, rustc, a proof run, or a build:

```text
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/cfw26-code-profile/check_profile.py
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s .agent/hardening/cfw26-code-profile -p 'test_*.py' -v
```

The executable small-field control exhaustively checks the two-query RS
simulator distribution and rejects a mutated linear-combination opening. The
checker regenerates the ledger, verifies retained source hashes, runs those
controls, and rejects every mutation in `mutation_corpus.json`.

