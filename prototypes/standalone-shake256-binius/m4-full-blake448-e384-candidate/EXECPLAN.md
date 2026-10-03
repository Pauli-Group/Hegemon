# Compile and compare the exact mixed conventional-hash M4 relation

This ExecPlan is a living document. The implementation remains isolated and
fail closed until every validation gate below is complete.

## Purpose

Compile the corrected 869-byte full Hegemon transaction semantics twice in the
same pinned one-main M4 backend: once with unkeyed BLAKE2b-448 for secret roles,
and once with separately tagged SHA3-512 truncated to 448 bits. Keep the
collision-only roles identical SHAKE256-448, measure whole post-DCE geometry,
and select no winner before that evidence exists.

## Progress

- [x] Preserve the current maximum M4 non-hash word gadgets in an isolated
  crate.
- [x] Add exact 869-byte public decoding and fixed two-by-2,147-byte ciphertext
  source wires.
- [x] Internalize intent, balance-tag, and ciphertext hashing.
- [x] Add unkeyed RFC 7693 BLAKE2b-448 word constraints with exact byte
  counters and final masks.
- [x] Add separately tagged SHA3-512/truncated-448 control calls.
- [x] Add fixed five-arm pre-hash authorization muxes for both profiles.
- [x] Add typed role inventories, source/program digests, diagnostic identity,
  fail-closed flags, KAT sources, and compiled-geometry instrumentation.
- [x] Validate every typed call index, exact ordinary/auth-arm width,
  algorithm, source/output binding, and primitive-core count. Preserve the
  scalar compiler's seven-byte limb semantics without adding a stronger
  eight-byte M4 transport gate.
- [x] Bind the active stablecoin manifest's three 48-byte public authorities
  directly as six words each, retaining the scalar adapter's exact 61-byte
  policy-hash recomputation and all strict-PQ and production gates.
- [x] Lower the selected policy entry, current-height equality, lifecycle,
  freshness, dispute, nonzero issuance, u128 cap, and expected/provided inactive
  v1 manifest-state commitment equality into a separate 50-word public seam.
  Keep whole-manifest hash recomputation, selected-entry membership, and
  consensus authentication explicit blockers.
- [ ] Run Cargo/typecheck and both compiled/DCE geometry builds after the 28 GiB
  disk gate opens.
- [ ] Differential-test every nonempty mask, all five authorization modes,
  stablecoin edge cases, signed value balance, and source/output mutations.
- [ ] Select the smaller compiled relation or declare no winner.
- [ ] Integrate one E384 PCS/channel and complete-ZK simulator; prove composed
  QROM PQ128 with exact union terms.
- [ ] Generate, retain, mutate, restart-verify, and measure the canonical proof;
  complete parser/consensus/refinement/release gates before allocating identity.

## Surprises and discoveries

- The pinned Binius `CircuitBuilder::rotr` is a linear Shift constraint, not an
  AND. `iadd` contributes one AND plus one linear constraint. The corrected raw
  hash projections are 79,128 ANDs for BLAKE-mixed and 90,600 for split SHA3,
  a BLAKE advantage of 11,472 ANDs, while BLAKE separately contributes 10,752
  rotation-linear constraints and 16,128 addition-linear constraints. Total
  compiled geometry remains decisive.
- The source-static hash-program ledger, including authorization hash mux and
  counter/final metadata but excluding non-hash semantics, is BLAKE
  79,128 AND / 265,963 linear / 452 BMUL versus split SHA3 90,600 AND /
  327,437 linear / 444 BMUL. The delta favors BLAKE by 11,472 AND and 61,474
  linear at a cost of 8 BMUL, but it is not a post-DCE winner measurement.
- The scalar oracle's retained semantic certificate and per-index `CallSpec`
  do not form a machine aggregate source/digest equality graph. The M4 source
  now routes every call through a shared-wire typed lowering ledger, but no
  aggregate artifact has been built or verified under the disk stop.
- The prior M4 circuit externalized intent and balance tag and did not witness
  ciphertext bytes. A hash-function swap alone could never be an exact full
  relation; private transport had to grow from 671 to 1,209 words.
- The rejected HGF6 identity cannot be reused for either conventional
  successor. Both compilers now share the exact `HX448C02` grammar-two scalar
  diagnostic codec and typed non-V6 activation; the production identity remains
  unallocated until compiled evidence selects a backend/profile. The retired
  893-byte `HX448C01` diagnostic is explicitly rejected.
- Remote Binius resolution was not reproducible against the locally modified
  PCS/channel tree. Dependencies now use local paths and a canonical
  path/length/byte-framed tree digest, provisionally pinned pending independent
  reproduction after all local backend edits stabilize.
- The production kernel's stablecoin manifest schema uses a 48-byte
  BLAKE2b-384 policy hash over an
  exact 61-byte SCALE tuple under `hegemon.kernel.stablecoin-policy.v2`, plus
  two opaque 48-byte commitments. Grammar two carries those widths directly;
  it performs no 48-to-56 conversion. This is compatibility evidence only:
  the opaque commitments have no positive strict-PQ composition margin or
  known wider constructor bridge. The scalar adapter now retains an entire
  external `ProtocolManifest` view and mirrors native existential candidate
  selection. The M4 source now constrains the selected entry and lifecycle via
  the typed state seam, but whole-manifest hash/membership and authentication of
  the expected root/current height against consensus state remain external.
  The current source manifest entry is inactive and retired at height zero;
  active entries used by the corpus are diagnostic fixtures only.

## Decisions

- Compare both profiles inside identical source semantics and expose actual
  compiled counts; do not select from primitive-core arithmetic.
- Use unkeyed BLAKE2b only. Keyed mode adds a block and does not create entropy.
- Split each former 112-byte KDF output into distinct lane-A/lane-B frames.
- Mux authorization messages and BLAKE metadata before hashing. Hashing all
  five arms is outside the 28-compression architecture.
- Keep `winner`, production, ZK, PQ128, E384-PCS, and identity flags false.
- Keep production, identity, and strict-stablecoin-PQ flags false. A final
  successor must add fresh wider bindings from authoritative preimages or
  constructors while retaining the live 48-byte compatibility gate. Missing
  opaque oracle/attestation preimages require manifest migration.

## Validation and acceptance

Source-stage acceptance under the current disk stop is `python3 check_source.py`
plus an owned-directory diff. Compiled-stage acceptance requires both runtime
profiles to build the one chip-free main and report all constraint families,
including auth mux/counter metadata. Selection requires smaller post-DCE total
private words and AND constraints without semantic divergence. Production
acceptance additionally requires complete ZK, composed >128-bit QROM security,
E384 PCS/channel integration, canonical proof bytes, negative mutations,
restart/reorg/fresh-node verification, formal/refinement closure, release
manifest, and fail-closed consensus activation.
