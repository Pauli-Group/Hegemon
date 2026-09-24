# Build the diagnostic dual-profile conventional-hash transaction relation

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current. It follows `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon needs executable conventional-hash candidates for the exact two-input/two-output shielded transaction semantics without granting any new consensus identity or production authority. The same diagnostic compiler now supports two profiles over exactly the same 83 canonical frames: (a) 15 unkeyed RFC 7693 BLAKE2b-448 calls using 28 compressions plus 68 FIPS 202 SHAKE256-448 calls using 105 Keccak permutations, and (b) 15 separately tagged FIPS 202 SHA3-512 calls truncated to 56 bytes using 46 permutations plus the same SHAKE calls. The relation checks canonical source bytes, hash-output consumers, all five private authorization modes, all activity masks, exact stablecoin semantics, and fixed authorization muxes. No winner, production identity, or production authorization is allocated.

## Progress

- [x] (2026-08-22) Read `AGENTS.md`, `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, and `README.md`; inspected the existing exact statement, non-hash semantics, BLAKE2b Boolean trace, and SHAKE256 Boolean trace.
- [x] (2026-08-22) Source-audited SHA3-512, unkeyed/keyed BLAKE2b-448, HMAC, and HKDF schedules; retained BLAKE and split SHA3 as conditional finalists with no winner pending same-backend compiled/DCE geometry.
- [x] (2026-08-22) Implemented `circuits/transaction/src/full_blake2b448_relation.rs` with a diagnostic-only fresh codec/domain registry, exact 83-call schedule, canonical typed frames, both trace profiles, and fixed five-arm authorization muxes.
- [x] (2026-08-22) Added the minimal module export in `circuits/transaction/src/lib.rs`.
- [x] (2026-08-22) Added KAT, schedule, source/digest/selector mutation, frame, activity-mask, authorization-mode, stablecoin-edge, historical-identity, and production-failure tests.
- [x] (2026-08-22) Ran the last admitted narrow checks before the parent reasserted the 28 GiB Cargo disk gate: offline library/test type-check passed; the nine scoped tests had one faulty test-only source-index assertion, which was corrected; its canonical-frame rerun passed. No further Cargo was run after the stop instruction.

## Surprises & Discoveries

- Observation: `full_shake448_relation.rs` contains the corrected non-hash semantics, but its executable wire graph is inseparable from the rejected uniform SHAKE256 oracle and the rejected HGF6 identities.
  Evidence: `FullShake448QirInstance::materialize_hash_constraint_system` materializes SHAKE traces for every QIR slot, and `ValidatedFullShake448Relation::materialize_constraint_system` consumes those SHAKE output wires directly.

- Observation: the existing BLAKE2b Boolean gadget has no fixed five-arm pre-compression mux API.
  Evidence: `smallwood_blake2b384::blake2b_relation` accepts one variable-length message and allocates only that message's bits; its private `compress` function fixes counters and final flags from the selected host length.

- Observation: the pinned M4 backend lowers `iadd` to one AND plus one linear constraint and `rotr` to one linear Shift constraint with no AND.
  Evidence: corrected mixed raw-AND geometry is 79,128 versus 90,600 for split SHA3, an 11,472-word BLAKE advantage. BLAKE's 10,752 rotation-linear constraints and 16,128 addition-linear constraints are reported separately; total mux/metadata/DCE/proof geometry remains unmeasured.

## Decision Log

- Decision: compile both unkeyed BLAKE2b-448 and split SHA3-512/truncated-448 over the same 15 hidden/preimage calls, retaining SHAKE256-448 for the 68 collision-only calls; set tournament winner to `None`.
  Rationale: BLAKE avoids keyed-mode entropy/PRF claims, has positive generic QROM margin under an explicit BLAKE2b-as-QRO assumption, and leads by 11,472 raw AND words. Total linear constraints, mux/metadata, DCE, and proof bytes remain unmeasured, so the raw screen cannot allocate a winner.
  Date/Author: 2026-08-22 / Codex.

- Decision: allocate only diagnostic candidate tags and reject every retained HGF6/SWV6 identity.
  Rationale: the proof-engine tournament has not frozen a production backend or consensus identity. Candidate tags prevent cross-role aliases while remaining explicitly unreachable from production dispatch.
  Date/Author: 2026-08-22 / Codex.

- Decision: implement the authorization mux before BLAKE compression and select full padded blocks, the 128-bit byte counters, and final flags.
  Rationale: hashing five arms and selecting an output would cost forty auth compression functions instead of eight; selecting only host frame bytes would leave counter/final semantics and fixed shape unproved.
  Date/Author: 2026-08-22 / Codex.

- Decision: type enabled stablecoin bindings without strengthening the admitted source relation; enabled zero metadata is accepted, while disabled bindings must be uniquely all zero.
  Rationale: the exact source relation permits enabled zero metadata. Any stronger authority policy requires a separately versioned statement and cannot be smuggled into this parity candidate.
  Date/Author: 2026-08-22 / Codex.

## Outcomes & Retrospective

The scalar diagnostic compiler, fresh codec, role/frame oracle, two profile traces, and fail-closed tests are implemented. The last admitted checks type-checked the library and tests; eight of nine scoped tests passed in one run, the sole failure was an invalid test assertion that interpreted source-relative byte indices as frame-relative, and the corrected canonical-frame test passed. Exact canonical four-call authorization-mux scalar counts are 813,624 for BLAKE and 1,497,512 for split SHA3; these are not native-Binius authority. No production identity, proof route, release authorization, complete-ZK proof, composed proof-system/QROM certificate, or Rust/backend/verifier refinement has been allocated.

## Context and Orientation

`circuits/transaction/src/full_shake448_statement.rs` owns the rejected V6 statement layout. Its semantic Rust structures remain useful as field containers, but its magic, route, profile, domains, registry, and envelope are not reused. `circuits/transaction/src/full_shake448_relation.rs` contains the corrected host semantics and an executable non-hash Goldilocks graph, but that graph consumes outputs from an all-SHAKE diagnostic oracle. `circuits/transaction/src/smallwood_blake2b384.rs` provides exact RFC 7693 unkeyed BLAKE2b Boolean traces for any legal output width, including 56 bytes. `circuits/transaction/src/smallwood_shake256_full_relation.rs` provides exact SHAKE256 Boolean traces.

The new module is a candidate semantic relation, not a proof backend. A physical call means one separately domain-framed hash invocation. A compression core means one BLAKE2b compression function or one Keccak-f permutation. The fixed authorization mux is a Boolean program that materializes all five mode arms, selects one arm with a one-hot private selector, and sends only the selected two blocks and metadata through one two-compression BLAKE pipeline.

## Plan of Work

Create `circuits/transaction/src/full_blake2b448_relation.rs`. Define diagnostic-only eight-byte profile and role tags, distinct same-length spend/auth lane tags, a registry with eleven families, and constants for all 83 call indices. Validate the registry structurally and reject all historical HGF6/SWV6 identifiers.

Encode the 893-byte candidate statement using the corrected field order but a diagnostic magic and caller-supplied expected activation. Do not call the HGF6 statement encoder. Make statement bytes and their lossless seven-byte limb projection the public source authority.

Build canonical length-prefixed frames for notes, nullifiers, Merkle nodes, split spend material, policy material, four split authorization pipelines, intent, balance, and fixed-width ciphertexts. Record one typed source for each byte. Build ordinary BLAKE2b-448 and SHAKE256-448 traces and verify every polynomial constraint, message-source bit, digest-output bit, frame length, block/permutation count, and public/internal target.

Implement the BLAKE authorization mux locally because the existing BLAKE gadget does not expose its private compression builder. Allocate five one-hot selector bits, every arm's two padded blocks, per-block 128-bit counter and final flag, select all of them with explicit mux constraints, and run exactly two BLAKE2b compression rounds over the selected values. Bind all non-dummy source bytes and all constant dummy/padding bytes.

Port the corrected scalar checks for activity, inactive padding, canonical note/range/asset slots, balance, Merkle membership, output commitments/ciphertexts, nullifiers, and five authorization modes. Replace raw stablecoin enablement with `StablecoinAuthority::try_from_statement`, which is the only constructor admitted by compilation.

Keep all fields private except audit accessors, and make the sole production authorization function return a dedicated error. Do not modify proof dispatch, version schedules, envelopes, manifests, wallet, RPC, consensus, or release gates.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, edit only the new relation module, this plan, the audit note, and the single `lib.rs` module line. Run:

    rustfmt --edition 2021 --check circuits/transaction/src/full_blake2b448_relation.rs circuits/transaction/src/lib.rs
    git diff --check -- circuits/transaction/src/full_blake2b448_relation.rs circuits/transaction/src/lib.rs .agent/FULL_BLAKE2B448_RELATION_EXECPLAN.md .agent/hardening/standard-hash-successor/README.md

Do not run Cargo below the repository's 28 GiB disk gate. The final narrow run occurred before that gate was reasserted; with approximately 18 GiB free, perform only formatting/source/static checks and record any unrun test blocker accurately.

## Validation and Acceptance

The registry test must observe exactly eleven families, 83 physical calls, 15 BLAKE calls, 28 BLAKE compressions, 68 SHAKE calls, and 105 Keccak permutations. The lane test must show that equal payloads under lane A and lane B have distinct frames and digests. The fixed-mux test must show four two-compression pipelines in every mode, exact one-hot selection of both 128-byte blocks and both counters/final flags, and rejection after mutating a selector, arm byte, counter, final flag, or digest bit.

KAT tests must compare BLAKE2b-448 outputs for empty, `abc`, and 127/128/129-byte boundary messages against retained independent vectors, then verify every Boolean constraint. SHAKE tests may rely on the already retained FIPS relation tests but the new mixed-call verifier must still verify each SHAKE trace. Source and target mutation tests must prove no frame byte or output byte can change without failure.

Mask tests must cover all sixteen masks and reject only the all-empty mask at the global shape layer. Authorization tests must cover SingleKey, AccumulatorInit, ApprovalStep, ValueLockCreation, and FinalThresholdSpend shape rules. Stablecoin tests must accept the unique disabled encoding and a typed enabled authority including the exact source relation's zero-metadata edge, while rejecting disabled nonzero metadata. The production gate must always fail.

## Idempotence and Recovery

All changes are additive and rerunnable. No cleanup, network access, release publication, identity allocation, or production route mutation is needed. If a focused build exceeds the disk gate, stop it and retain source/static evidence; do not delete shared caches without approval. Preserve all unrelated changes in the shared checkout.

## Artifacts and Notes

The architecture and QROM audit lives at `.agent/hardening/standard-hash-successor/README.md`. It is a source audit, not a proof or security certificate. This ExecPlan and the Rust module are the retained implementation artifacts for the candidate relation.

## Interfaces and Dependencies

The new module must expose `compile_full_blake2b448_candidate`, `validate_mixed_hash_registry`, `mixed_hash_registry`, `candidate_statement_bytes`, `StablecoinAuthority`, `FullBlake2b448Relation`, `MixedRelationStats`, and `ensure_full_blake2b448_relation_production_authorized`. It reuses `smallwood_blake2b384::blake2b_relation::<56>` for ordinary BLAKE calls and `smallwood_shake256_full_relation::shake256_relation` for SHAKE calls. The fixed authorization mux has its own exact Boolean trace because neither public dependency can select BLAKE message blocks and compression metadata before hashing.

Revision note 2026-08-22: Created for the conditional mixed BLAKE candidate and revised after pinned M4 accounting established 79,128 versus 90,600 raw AND words while reporting BLAKE rotation-linear constraints separately. The implemented tournament compiles both profiles over one frame registry and intentionally returns no winner pending total compiled/DCE/proof geometry.
