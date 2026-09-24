# Conventional wide-capacity semantic-hash successor audit

## Verdict

**No winner is authorized.**  The two executable finalists are:

1. unkeyed RFC 7693 BLAKE2b with `nn = 56` for 15 hidden/preimage calls,
   plus FIPS 202 SHAKE256-448 for 68 collision-only calls; and
2. separately tagged FIPS 202 SHA3-512 invocations truncated to 56 bytes for
   the same 15 calls, plus the same 68 SHAKE256-448 calls.

The mixed BLAKE profile has 28 compression functions and 105 Keccak-f[1600]
permutations.  The split-SHA3 profile has 46 SHA3 permutations and 105 SHAKE
permutations.  Both have exactly 83 physical calls.  The pinned M4 cost model
shows an 11,472-word raw-AND advantage for BLAKE, but that excludes linear
constraints, mux/counter/final metadata, DCE, and proof geometry.  A
same-backend compiled/DCE and proof-byte artifact for both profiles is the
winner gate.

BLAKE additionally requires an explicit concrete-hash-as-quantum-random-
oracle instantiation assumption.  RFC 7693 specifies the algorithm and calls
keyed BLAKE2 a MAC, but explicitly makes no independent security assertion.
No checked theorem currently reduces concrete twelve-round BLAKE2b to a QRO
against quantum attackers.  If Hegemon requires such an indifferentiability
theorem, BLAKE is disqualified independently of cost.  Neither condition is
silently waived by this audit.

Do not use keyed BLAKE2b, HMAC, or HKDF in the selected relation.  They cannot
create entropy and they add compression calls.  The security statement is not
"BLAKE2 keyed mode is a PRF".  It is: an honestly generated 384-bit hidden
seed is queried at prefix-free, separately tagged points of one QRO, and the
two derived 448-bit strings are hidden-point outputs.  The registry should
name this purpose `HiddenSeedDerivation`, not silently promote it to an
unqualified standard-model PRF.

## Standards and reduction boundary

FIPS 202 defines SHA3-512 as `KECCAK[1024](M || 01, 512)` and defines only
SHAKE128 and SHAKE256 as SHA-3 XOFs.  Thus separately tagged SHA3-512 calls are
standard, while the rejected rate-72/suffix-0x1f "SHAKE512" is not.

RFC 7693 fixes BLAKE2b's 128-byte block, twelve rounds, 64-bit words, digest
length `1 <= nn <= 64`, and optional key length `0 <= kk <= 64`.  Its exact
unkeyed block count for every nonempty Hegemon frame is `ceil(frame_bytes /
128)`.  Keyed mode prepends one padded key block.  The selected profile uses
only `kk = 0`.

RFC 5869 standardizes HMAC-based extract-then-expand and says that HKDF can
concentrate existing entropy but cannot amplify it.  Its SHA-256/SHA-1 test
vectors are not SHA-512 or SHA3-512 KATs.  HMAC-SHA-512 has a relevant QROM
qPRF literature: the tight generic query scale is controlled by
`min(2^(n/3), 2^(k/2))`.  It is nevertheless larger here, requires a new
Boolean SHA-512 relation, and does not improve the selected 384-bit source
entropy.

Primary sources:

- FIPS 202: https://doi.org/10.6028/NIST.FIPS.202
- RFC 7693: https://www.rfc-editor.org/rfc/rfc7693.html
- RFC 5869: https://www.rfc-editor.org/rfc/rfc5869.html
- RFC 6234, SHA/HMAC/HKDF code and tests: https://www.rfc-editor.org/rfc/rfc6234.html
- Akshima et al., *On Tight Quantum Security of HMAC and NMAC in the Quantum
  Random Oracle Model*: https://eprint.iacr.org/2021/774
- Hofheinz, Hovelmanns, and Kiltz, algorithmic one-way-to-hiding lemma and
  hidden-prefix QRO use: https://www.iacr.org/archive/eurocrypt2018/10822185/10822185.pdf

Application framing, lane tags, field order, and the Hegemon role registry are
protocol domain separation.  They are not additions to or renamed variants of
the underlying standard primitive.

## Exact maximum 2x2 schedule

All frame lengths below are the current exact semantic lengths.  A fresh
identity must replace the profile tag.  For each split output, replace the
existing fixed eight-byte output-order field with distinct eight-byte lane-A
and lane-B tags, so the frame length does not change.  Length-prefixed fields
and the eight-byte role remain prefix-free.

| Family | Purpose | Physical calls | Frame bytes | Selected primitive | Cores per call | Total cores |
| --- | --- | ---: | ---: | --- | ---: | ---: |
| `note.cm` | preimage hiding, collision binding | 4 | 232 | BLAKE2b-448 | 2 compressions | 8 |
| `nullif` | hidden-seed derivation, binding | 2 | 135 | BLAKE2b-448 | 2 | 4 |
| `merk.nd` | collision-only binding | 64 | 133 | SHAKE256-448 | 1 permutation | 64 |
| `sp.key.A` | hidden-seed derivation, first 56 bytes | 2 | 77 | BLAKE2b-448 | 1 | 2 |
| `sp.key.B` | hidden-seed derivation, second 56 bytes | 2 | 77 | BLAKE2b-448 | 1 | 2 |
| `policy` | preimage hiding, collision binding | 1 | 385 | BLAKE2b-448 | 4 | 4 |
| `auth.A` | hidden-seed derivation, first 56 bytes | 2 | 181 maximum | BLAKE2b-448 | 2 | 4 |
| `auth.B` | hidden-seed derivation, second 56 bytes | 2 | 181 maximum | BLAKE2b-448 | 2 | 4 |
| `intent` | collision-only public binding | 1 | 744 | SHAKE256-448 | 6 permutations | 6 |
| `bal.tag` | collision-only public binding | 1 | 100 | SHAKE256-448 | 1 | 1 |
| `ct.hash` | collision-only canonical-byte binding | 2 | 2,182 | SHAKE256-448 | 17 | 34 |
| **Total** |  | **83** |  |  | **28 BLAKE2b + 105 Keccak-f** | **133 heterogeneous cores** |

The authorization count assumes four fixed two-compression pipelines: two
authorization slots times two output lanes.  Every one of the five mode arms
must materialize its exact RFC blocks, byte counter, and final-block flag;
one-hot selection must bind both message blocks and metadata.  A canonical
two-block dummy is required.  Host hashing or hashing all five arms and
selecting afterward is not the 28-compression architecture.

For comparison, using SHA3-512 only for the same secret roles gives 15 calls /
46 permutations.  Keeping the 105 collision-only SHAKE256 permutations gives
83 physical calls / 151 Keccak permutations.  Replacing every role with
SHA3-512 would be 83 calls / 249 permutations.  Replacing every role with
unkeyed BLAKE2b-448 would be 83 calls / 199 compressions, but that is not the
minimum mixed profile.

## QROM ledger that the mixed BLAKE construction would permit

The honest-generation contract must guarantee at least 384 conditional
min-entropy bits for each root secret source.  Each note carries 48-byte `rho`
and 48-byte commitment randomness; conservatively credit only one independent
384-bit source, not 768 bits.  Each spend seed is exactly 48 bytes.  Derived
nullifier and authorization material cannot receive more entropy than the
seed from which it descends.  Policy/accumulator/value-lock hiding must either
trace to one such honestly generated source or fail the role gate.  Consensus
cannot prove randomness statistically; wallet RNG generation and its
refinement into the relation are explicit external assumptions.

Use one prefix-free tagged-product BLAKE2b QRO and one prefix-free
SHAKE256 QRO with one global query budget `Q`.  A deliberately conservative
15-target union and factor four gives the following primitive screens:

    hidden 384-bit source points <= 60 Q^2 / 2^384
    BLAKE2b-448 target preimages <= 60 Q^2 / 2^448
    BLAKE2b-448 collisions       <=  4 Q^3 / 2^448
    SHAKE256-448 collisions      <=  4 Q^3 / 2^448

The coefficient 60 is `4 * 15`, where 15 is the number of physical BLAKE2b
secret-role invocations.  This is intentionally more conservative than
grouping calls that share a seed.  A final certificate must replace the
placeholder factor four with the exact constant and query convention of its
selected O2H/multi-target theorem; it must not silently treat this audit as
that theorem.

At `Q = 2^64`, the four exponents are approximately 250.093, 314.093, 254,
and 254 bits.  For constant success probability one half, the corresponding
generic query-work exponents are approximately 188.547, 220.547, 148.333,
and 148.333 bits.  Every primitive screen therefore has positive margin above
128.  The final composed inequality must add these exact rational terms to
PCS, IOP, Fiat-Shamir, proof-transcript hash, grinding/abort, extraction,
history, and all other union terms.  These hash screens do not establish that
the whole proof exceeds 128 bits.

The exact security blocker is therefore not a numerical 128-bit ceiling.  It
is one of the following missing bridges: the direct BLAKE2b-as-QRO
instantiation assumption is rejected by policy; an honest 384-bit source does
not reach a secret role; the selected O2H theorem and constants are not
instantiated; or the sum with the proof-system terms fails.  Any one keeps
production false.

## Native-Binius cost screen

These are source-static Boolean-core counts, not compiled constraints, proof
bytes, or measurements.

Keccak-f has exactly `24 * 25 = 600` native 64-lane AND/FAX gates per full
permutation.  BLAKE2b has `12 rounds * 8 G * 6 = 576` binary 64-bit additions
and `12 * 8 * 4 = 384` rotations per compression.  In the pinned M4 backend,
`CircuitBuilder::iadd` emits one AND plus one linear constraint, while `rotr`
emits one linear `Shift` constraint and no AND.  The corrected raw-AND screen
is:

    SHAKE collision roles: 105 * 600 = 63,000 native AND words
    BLAKE2b secret roles:    28 * 576 = 16,128 native AND words
    total raw AND core:                 79,128 native AND words

The same 28 BLAKE compressions emit 16,128 addition-linear constraints and
10,752 rotation-linear constraints (`28 * 384`) separately.  Source words,
one-hot authorization muxes, counter/final selection, output bindings,
non-hash transaction constraints, zero-knowledge masking, and proof-system
padding are additional.

The directly tagged SHA3-512 alternative is `151 * 600 = 90,600` raw native
AND words, so BLAKE leads by 11,472 raw AND words. Existing Keccak backward
liveness projects split SHA3 to 89,106 live FAX outputs before non-hash logic,
demonstrating why raw AND counts cannot decide total compiled geometry.
Goldilocks diagnostic traces measure 813,624 scalar constraints across the
four canonical BLAKE authorization muxes and 1,497,512 for split SHA3, but
those are not native-Binius geometry and confer no selection authority.

For completeness, a direct HMAC-SHA3-512 lower schedule is 173 Keccak
permutations, 103,800 raw native AND words, or 102,136 under the same terminal
liveness projection.  A canonical SHA-512 compression needs 760 packed
modular additions plus 160 packed `Ch`/`Maj` ANDs, or 920 native nonlinear
words.  Direct HMAC-SHA-512 on the nullifier/spend/auth roles needs 44 SHA-512
compressions; with 127 retained Keccak permutations its raw projection is
116,680 native nonlinear words.  HKDF extract plus two-block expansion raises
that role schedule to 68 SHA-512 compressions and the raw projection to
138,760.  There is no executable Binius SHA-512 or optimized BLAKE2b compiler
that makes these figures measured authority.

## Retained KAT and mutation evidence

The executable candidate retains 56-byte BLAKE2b and SHA3-512/truncated KATs
for empty, `abc`, 127-, 128-, and 129-byte messages.  It verifies every scalar
Boolean constraint.  The fixed five-arm tests bind all arm sources, select
both BLAKE blocks/counters/final flags, and reject source, selector, and digest
mutations.  The canonical frame test covers all eleven roles, both lanes, both
authorization slots, all 16 activity masks, all five modes, typed Merkle
sources, stablecoin zero edges, and historical-identity rejection.

These tests passed in the final admitted narrow run on 2026-08-22.  Promotion
still requires retained independent-generator identities for 232-, 385-, and
2,182-byte BLAKE vectors and mutations of every byte/counter/final metadata
position; RFC 7693 Appendix A supplies BLAKE2b-512 `abc`, not this complete
BLAKE2b-448 set.

Mutations must cover output-length parameter 56, every application profile,
role and lane tag, every field length and byte, 128-byte boundary behavior,
the 128-bit byte counter, final-block flag, zero padding, source-bit binding,
digest-bit binding, and all five authorization selectors/arms.  The emitted
binary program and compiler source, not a descriptor-only digest, must be
bound into the release manifest.

## Identity implications

Never reinterpret rejected `HGF6ST02`, `HEG-F6V2`, `HGF6HR02`, `HGR6RM02`,
`HGV6PB02`, SWV6-v2, or `SMZ2`.  The BLAKE2b-448 schedule needs a fresh,
atomically rotated statement/profile/domain registry, relation manifest,
envelope version, transcript preamble, proof-wire magic, rules/genesis hashes,
and release capability.  The new registry has eleven families because spend
and authorization each split into lane A and lane B.  Exact numeric IDs and
magic strings should be allocated only after the proof-engine tournament
fixes the backend, so that another rejected descriptor is not frozen early.
