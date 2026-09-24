# Port the complete SmallWood relation to framed BLAKE2b-384

This ExecPlan is a living document and must be maintained in accordance with `.agent/PLANS.md`. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` record the actual state of the work.

## Purpose / Big Picture

Hegemon needs one transparent, zero-knowledge transaction proof whose semantic hashes do not depend on Poseidon. After this change, the transaction crate has an executable, fixed-geometry description of the complete two-input/two-output SmallWood relation using framed RFC 7693 BLAKE2b-384 calls. The relation keeps the canonical 78-field public vector, covers all sixteen activity masks, preserves the three shipped private-authorization modes, validates stablecoin and four-slot conservation, and exposes a deterministic 48-byte schedule identity for the production envelope. This milestone does not authorize production proving: the separate Boolean BLAKE2b gadget and SmallWood row compiler must consume the schedule and pass the security gates before admission can open.

## Progress

- [x] (2026-08-22 06:55Z) Read the repository operating instructions and inspected the active Poseidon SmallWood frontend, nonlinear relation, canonical public-field ranges, witness structures, and centralized hash domains.
- [x] (2026-08-22 06:55Z) Fixed the port boundary: retain exactly 78 public Goldilocks values and constrain each raw 48-byte BLAKE2b digest to six canonical words through explicit per-word modular reduction.
- [x] (2026-08-22 07:34Z) Added the centralized SmallWood private-authorization and relation-schedule domains.
- [x] (2026-08-22 07:34Z) Implemented `circuits/transaction/src/smallwood_blake2b384_semantics.rs` with the fixed 77-call schedule, public binding, arithmetic and authorization validation, geometry, schedule digest, and V5 envelope adapter.
- [x] (2026-08-22 07:34Z) Added all-mask geometry, all representable prefix-activity shapes, stablecoin, all three authorization modes, and public/hash/auth/Merkle mutation tests.
- [x] (2026-08-22 07:34Z) Connected every scheduled call to the concrete Boolean-gadget trace while keeping production admission false.
- [x] (2026-08-22 07:39Z) Focused tests pass 6/6, including every concrete Boolean trace; transaction-crate Clippy passes with `-D warnings`; rustfmt and scoped diff check pass.

## Surprises & Discoveries

- Observation: the active transaction vector has only six Goldilocks words for every 48-byte digest, while a native BLAKE2b-384 output is an unrestricted 384-bit string.
  Evidence: `TransactionVerifierInputs::to_vec` allocates six field elements per digest and the existing byte adapter reduces each big-endian `u64` through `Felt::from_u64`. The new schedule therefore retains the raw digest and the six reduced public words so the Boolean relation can prove this conversion instead of treating it as an unchecked adapter.

- Observation: the Poseidon implementation hashes padded inputs and outputs even when their activity flags are zero.
  Evidence: `poseidon_subtrace_rows_with_auth` materializes both fixed input slots, both fixed output slots, every depth-32 path, and all authorization hashes. The conventional-hash schedule must remain mask-independent to preserve zero-knowledge shape.

- Observation: the canonical 78-field vector contains no balance-tag field.
  Evidence: the exported field map ends at `circuit_version = 76` and `crypto_suite = 77`. The dormant V5 envelope therefore appends the relation-computed 48-byte tag to the 624-byte public vector, for an exact 672-byte statement.

- Observation: exact Boolean BLAKE2b geometry is a compactness kill gate, not a production candidate.
  Evidence: the 77 framed calls contain 15,065 framed bytes and 164 compression blocks. Actual generated traces contain 16,322,454 scalar witness values and constraints, or 255,100 packed-64 witness rows and 255,100 constraint rows, before non-hash transaction logic. Output binding adds 462 rows; digest reduction adds 462 identities.

- Observation: the unchanged six-word digest surface is incompatible with a semantic hash wider than 384 bits.
  Evidence: BLAKE2b-384 has generic quantum collision exponent exactly 128 and zero composition margin. A strict >=400-bit output cannot be represented without widening the public map or adding a reviewed different binding construction. The strict V5 architecture lane consequently selects SHAKE256-448/SHA-512 and rejects this BLAKE2b scaffold.

## Decision Log

- Decision: keep the 78-field public statement and make digest reduction an explicit relation operation.
  Rationale: changing the statement width would break the existing parser, profile, formal-map, and native wrapper boundary. An unchecked truncation would be unsound; carrying both raw and reduced forms gives the Boolean compiler an exact obligation.
  Date/Author: 2026-08-22 / Codex SmallWood relation-port worker.

- Decision: preserve the shipped `SingleKey`, `ApprovalStep`, and `FinalThresholdSpend` semantics exactly and do not silently import the five-mode prospective direct-M4 policy.
  Rationale: this is a hash-port of the production SmallWood relation. Adding note kinds or new state transitions is a separate consensus feature and would invalidate equivalence claims.
  Date/Author: 2026-08-22 / Codex SmallWood relation-port worker.

- Decision: production admission remains closed after the scalar schedule lands.
  Rationale: a scalar/reference evaluator proves neither that BLAKE2b Boolean gates are present in the committed SmallWood witness nor complete ZK/PQ128 security.
  Date/Author: 2026-08-22 / Codex SmallWood relation-port worker.

- Decision: retain the complete BLAKE2b port as a negative, executable architecture measurement and do not route it into V5 proving.
  Rationale: 255,100 packed hash rows alone are incompatible with the compact proof target, and 384 output bits have no PQ128 composition margin. The module remains valuable as an exact semantic oracle, mutation suite, and proof that an ARX hash is the wrong circuit choice here.
  Date/Author: 2026-08-22 / Codex SmallWood relation-port worker.

## Outcomes & Retrospective

The complete reference port is executable and fail closed. It preserves the 78-word statement, returns the balance tag separately, covers stablecoin and all three shipped authorization modes, gives all sixteen runtime masks one identical schedule, and rejects statement, tag, authorization, and Merkle mutations. Its pinned schedule digest is `010633b7154ab5efeae4de9c02c43802a206247162e89690055f7be8e789cd18d20a453e8d52ba649e53df69befc45f1`.

The result rules out Boolean BLAKE2b for the compact production architecture: 16.3 million scalar constraints and 255,100 packed rows are already present before transaction arithmetic. The shipped module therefore remains non-authorizing and provides evidence for selecting a bitwise SHAKE/Keccak relation plus a redesigned proof opening schedule.

## Context and Orientation

`circuits/transaction/src/smallwood_frontend.rs` builds the canonical 78-field statement and the fixed private witness. `circuits/transaction/src/smallwood_semantics.rs` checks conservation, activity flags, Merkle selection, authorization transitions, ranges, and Poseidon transition rows. `circuits/transaction/src/smallwood_blake2b384.rs` is owned by the Boolean-gadget workstream and supplies exact framed BLAKE2b-384 traces. The new `circuits/transaction/src/smallwood_blake2b384_semantics.rs` is the semantic bridge: it orders every domain-separated hash invocation, binds the resulting canonical words to the 78 fields, checks the non-hash relation, and exposes the immutable schedule identity. `crypto/hash384/src/lib.rs` owns all semantic domain strings and the common framing grammar.

A hash-call schedule is the ordered list of BLAKE2b invocations, their semantic roles, domains, and part lengths. It is fixed independently of the secret activity mask. A schedule digest is a BLAKE2b-384 commitment to that public description, not to a witness. The production envelope binds this digest so a verifier cannot interpret proof bytes under another relation layout.

## Plan of Work

First add only the missing authorization and schedule domains to `hegemon_hash384::domains`, including them in the uniqueness test inventory. Then implement a relation module that accepts a `TransactionWitness`, `SmallwoodPrivateAuthWitness`, and exact public vector. The module pads to two inputs and two outputs, emits every hash call in a canonical order, retains raw and reduced digests, validates each active Merkle path and public nullifier/commitment, checks inactive public zeros, checks 61-bit amounts and canonical signed magnitudes, checks ordered balance assets and stablecoin policy shape, enforces per-slot conservation, and reproduces the existing authorization transition rules. It also derives the external balance tag and relation schedule digest.

Tests construct deterministic BLAKE2b trees and run all sixteen activity masks through the same geometry. Separate fixtures cover enabled stablecoin, approval, and final-threshold authorization. Mutations target each public family, Merkle orientation, note preimage, inactive padding, balance, stablecoin, intent, policy membership, approval count, output authorization, and version fields. Every mutation must fail before a proof can be considered.

Once the Boolean gadget API is present, add an adapter that materializes a gadget trace for every scheduled call and requires `verify_constraints()` for each trace. Keep the profile capability false until that material is compiled into the SmallWood committed witness and the complete proof/security gates pass.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Run the focused relation tests without a heavy prover:

    cargo test -p transaction-circuit smallwood_blake2b384_semantics --lib

Run formatting and static checks:

    cargo fmt --all -- --check
    cargo clippy -p transaction-circuit --lib --tests -- -D warnings
    git diff --check

No full proof generation is part of this milestone because the host is below the repository's heavy-run disk admission floor.

## Validation and Acceptance

The focused test suite must show that all sixteen masks produce the identical hash-role/part-length schedule, while each honest public vector verifies. The approval and final-threshold fixtures must verify, and a mutation to any committed public/hash/auth/balance/version value must reject. The schedule digest must be stable and nonzero. The module-level compiled/authorized flag must remain false until the separate Boolean row compiler is complete.

## Idempotence and Recovery

All changes are additive. The legacy Poseidon implementation remains available for bounded historical/research decoding. If the new module fails to compile while the gadget workstream is landing, keep the scalar/reference adapter and retry after rebasing the concrete gadget import; do not weaken the production gate. No cleanup or destructive command is required.

## Artifacts and Notes

Validation evidence:

    cargo test -p transaction-circuit smallwood_blake2b384_semantics --lib --locked
    test result: ok. 6 passed; 0 failed; 200 filtered out

    cargo clippy -p transaction-circuit --lib --tests --locked -- -D warnings
    Finished `dev` profile

The shared root Cargo invocation currently needs the unrelated nested standalone-SHAKE workspace dependency removed or isolated first; it otherwise reports `multiple workspace roots`. Validation temporarily omitted that wallet-only optional dependency and restored the file byte-for-byte afterward. No heavy proof was generated.

## Interfaces and Dependencies

The module will expose `SMALLWOOD_BLAKE2B384_RELATION_PROFILE_V5`, `smallwood_blake2b384_relation_schedule_digest() -> [u8; 48]`, a fixed geometry report, a material builder, and an exact verifier over the 78 public values. Each hash-call record contains its role, domain, framed message, raw digest, canonical digest, and six Goldilocks words. The concrete gadget adapter uses `crate::smallwood_blake2b384::blake2b384_domain_relation` and never reimplements RFC 7693 compression.

Revision note (2026-08-22 06:55Z): created the plan after mapping the active relation and identifying the digest-to-field bridge that must be constrained.

Revision note (2026-08-22 07:39Z): recorded the complete implementation, exact 77-call Boolean geometry, security/public-width no-go, pinned schedule identity, focused tests, and final non-authorizing architecture verdict.
