# M4 full mixed-hash candidate

Status: source implementation under a research-only diagnostic identity. It is
not compiled, measured, proved, zero knowledge, strict PQ128, or production
authorized. `WINNER=None` and `PRODUCTION_AUTHORIZED=false` are code constants.

The compiler builds the same exact 869-byte, two-input/two-output semantic
layout under either of two conventional-hash profiles:

- `Blake2b448Mixed`: 15 unkeyed RFC 7693 BLAKE2b-448 calls / 28 compression
  functions for secret-derived roles, plus 68 FIPS 202 SHAKE256-448 calls / 105
  Keccak-f[1600] permutations for collision-only roles.
- `Sha3_512SplitControl`: the same 15 separately tagged secret-role calls using
  FIPS 202 SHA3-512 truncated to 56 bytes / 46 permutations, plus the identical
  68-call/105-permutation SHAKE layer.

Both are 83-call relations. The BLAKE profile has 133 primitive cores and the
SHA3 control has 151. That does **not** select BLAKE on this backend: pinned
M4's `rotr` lowers to one linear Shift constraint, while `iadd` contributes one
AND and one linear constraint. The raw hash projections are therefore 79,128
ANDs for BLAKE-mixed versus 90,600 for split SHA3, an 11,472-AND advantage,
while BLAKE additionally carries 10,752 rotation-linear constraints (and the
16,128 addition-linear rows paired with its 16,128 `iadd` ANDs). Non-hash
semantics, compiler fusion/DCE, and proof bytes remain unmeasured. Only
`compiled_geometry()` may decide the relation-size winner.

The broader source-static hash-program ledger (including hash mux and
counter/final metadata, excluding non-hash transaction semantics) is 79,128
AND / 265,963 linear / 452 BMUL for BLAKE and 90,600 AND / 327,437 linear /
444 BMUL for split SHA3. Thus BLAKE saves 11,472 AND and 61,474 linear constraints
at the cost of 8 BMUL in this pre-pass. These are not post-compiler/DCE counts
and do not change `WINNER=None`.

## Exact relation surface

- Public statement: 869 bytes packed losslessly into 109 little-endian M4
  words; unused high 24 bits of the final word are constrained zero. The
  scalar diagnostic compiler's seven-byte limbs are already below the
  Goldilocks modulus, so no stronger eight-byte M4 limb gate is added. A
  separate 50-word typed consensus-state seam brings the total M4 public input
  to 159 words without changing the HX448C02 grammar.
- Private transport: the prior 671 semantic words plus two fixed 2,147-byte
  canonical ciphertext witnesses, each padded to 269 words with its high 40
  padding bits constrained zero; total 1,209 words / 9,672 bytes.
- The relation computes and binds all four note commitments, two nullifiers,
  64 Merkle nodes, split spend-key lanes, one shared policy digest, four fixed
  authorization lane pipelines, intent, balance tag, and both ciphertext
  hashes. Intent, balance, and ciphertext digests are not host authority.
- Activity is one nonempty mask out of all 16 encodings; the zero mask is
  rejected. Inactive payloads, public digests/sizes, and fixed ciphertext bytes
  are zero constrained. Signed native value balance, ordinary non-native
  conservation, live-policy mint and burn, all four asset slots, and all five
  authorization modes use the corrected semantics. Enabled zero issuance is
  rejected by both the typed M4 lifecycle seam and the scalar live-policy view.
- Authorization is selected before hashing. Each of four pipelines (slot A/B
  times lane A/B) muxes five canonical arms. BLAKE muxes both message blocks,
  both 128-bit counters, and both final masks before two compression calls.
  SHA3 muxes three padded absorption blocks and selects the exact state-2 or
  state-3 digest boundary; a 143-byte value-lock frame is never silently hashed
  as a 216-byte surrogate.
- Every one of the 83 call indices has an explicit algorithm, purpose, exact
  frame width (or all five authorization arm widths), source/output binding,
  output width, and primitive-core count. Frames are assembled from the same
  statement, witness, and internal-digest wires consumed by the non-hash
  relation; the registry is not inferred from names or aggregate counts.
- Lane tags `lane.A01` and `lane.B01` are distinct eight-byte fields. Spend,
  accumulator, value-lock, and framed dummy widths are exactly 77/181/143/136
  bytes.

## Identity and security boundary

The source matches the scalar diagnostic candidate exactly: statement magic
and application-frame tag `HX448C02`, grammar two, typed nonzero activation
fields, and a route that must not equal the rejected V6 route. It explicitly
rejects retired diagnostic `HX448C01` and `HGF6ST02`, `HGF6HR02`, `HGR6RM02`,
and `HGV6PB02` only at identity
positions, never by scanning arbitrary payload bytes. The final statement,
profile, domain, manifest, envelope, transcript, proof wire, and rules identity
remain unallocated until a backend/profile wins compiled geometry and proof
tests. The source and selected program each expose a SHA-512 digest; the
program digest binds the full verifier-selected 184-byte activation. A future
verifier/transcript must pin it before any proof can have authority.

All Binius dependencies resolve to the local `../binius64` path. That path is
currently a symlink into the transient, dirty
`/private/tmp/hegemon-strict-full-baseline-binius` checkout at revision
`3f96163049f680b2909f6545690bd929f1b48c44`, so the candidate is not yet a
self-contained retained source tree. A dependency-free checker recomputes a
canonically framed SHA-512 digest over its selected 688-file Cargo/source
inventory, but that byte pin does not retain the modified checkout or its
untracked grouped-sumcheck file. A qualifying winner must vendor the exact
reviewed tree and licenses, or reproduce the complete patch set from a clean
immutable base, and retain a Cargo lock before build/proof identity can freeze.

The crate reuses the pinned `B128`/`E384` types from `strict-mixed-field`, but
there is no integrated E384 PCS or challenger. It also lacks complete ZK,
composed QROM PQ128, formal/Rust refinement, an accepted parser/envelope,
mutation/restart/fresh-node proof artifacts, and measured proof bytes. Every
one of those is a release blocker.

The scalar oracle retains a semantic certificate and exact `CallSpec` for all
83 calls, but explicitly has no machine-enforced aggregate source/digest
equality graph. This M4 source lowers every call from shared statement,
witness, and prior-digest wires and closes a typed 83-index coverage ledger;
that aggregate circuit has not been built or verified under the disk stop, so
`M4_AGGREGATE_RELATION_ARTIFACT_VERIFIED=false` remains authoritative.

The grammar-two compatibility bridge carries the exact production-kernel
stablecoin widths:
a 48-byte RFC 7693 BLAKE2b-384 policy hash over the exact 61-byte SCALE tuple
under `hegemon.kernel.stablecoin-policy.v2`, plus opaque 48-byte oracle and
attestation commitments. M4 binds each field as six public 64-bit words and
the intent frame binds the same statement bytes. No value is padded, truncated,
rehash-converted, or reinterpreted. Hash call 74 remains the private accumulator
authorization-policy call; it is not repurposed for the public stablecoin
manifest. For enabled issuance, the scalar compiler retains an entire external
`ProtocolManifest` view plus current height, repeats native admission's
existential search over plausible manifest members, and rechecks active,
lifecycle, asset, policy hash/version, opaque commitment equality, dispute,
freshness, nonzero issuance, and the live per-transaction cap in native order.
The M4 source now takes a separate 50-word public state seam. It constrains an
explicit v1 tag, selected-entry presence and typed widths, expected/provided
manifest-commitment equality and nonzero values, expected/provided height
equality, exact statement/entry authority equalities, active/lifecycle and
strict retirement bounds, nonfuture/saturating-fresh oracle state, undisputed
attestation, nonzero issuance, and the full u128 cap. Disabled transactions
require all 50 state words to be zero.

The conventional state commitment is the inactive kernel
`StablecoinManifestStateCommitmentV1`: 48-byte RFC 7693 BLAKE2b-384 under
`hegemon.kernel.stablecoin-manifest-state.v1`, over every ordered 183-byte
policy entry. Its width is unrelated to the PCS challenge field and receives
no strict-PQ credit. The M4 source does not yet recompute that whole-manifest
hash or prove that the selected entry/index is a member, and consensus does not
yet authenticate the expected root or current height. Those four facts remain
host-oracle-only. Even the source equality seam is not execution evidence: the
aggregate relation remains unbuilt under the disk stop.

The exact source inventory is 20 local non-hash groups, seven transaction hash
link groups, and nine consensus-state seam groups. The candidate also records
a 20-case counterfeit matrix: 16 cases target M4 rejection, while policy-hash
derivation, whole-manifest recomputation, selected-entry membership, and
consensus authentication remain explicitly host-oracle-only.

The current source manifest's sole stablecoin entry is `active=false` and
`retired_at=Some(0)`, so it authorizes no mint or burn at any height. Synthetic
active manifests appear only in diagnostic fixtures; they do not activate a
production route.

This exact 48-byte compatibility closure does not supply a positive strict-PQ
composition margin for three opaque authorities. `STRICT_STABLECOIN_PQ_MARGIN`
is false. A final successor must atomically add wider bindings derived from the
authoritative policy/oracle/attestation constructors or preimages while keeping
the live 48-byte gate as a compatibility check. If the opaque oracle and
attestation preimages are unavailable, manifest migration is a hard blocker.

## Verification status

The dependency-free `python3 check_source.py` contract is permitted
while free disk is below 28 GiB. Cargo, circuit compilation, proof generation,
and backend builds have not been run. The disk-gated differential tests are
also present for all 33 accepted and all 47 rejected mask/mode pairs under
both profiles, but deliberately unrun; they are not parity evidence yet. When
the disk gate opens, obtain exact post-DCE counts with one profile at a time:

```text
HEGEMON_M4_ALLOW_COMPILE_GEOMETRY=1 cargo run -- blake --compile-geometry
HEGEMON_M4_ALLOW_COMPILE_GEOMETRY=1 cargo run -- sha3 --compile-geometry
```

These commands compile relations; they do not prove or benchmark. After the
smaller relation is independently confirmed, the next gate is a single E384
PCS/channel integration with complete-ZK and composed-QROM certificates, then
retained proof measurement and end-to-end production transport/refinement.
