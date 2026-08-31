# Ship the fail-closed SmallWood V5 conventional-hash production boundary

This ExecPlan is a living document. It is maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon needs one canonical, self-contained transaction-proof byte string for a future SmallWood profile whose relation uses conventional hashes instead of Poseidon. This change gives wallets, relays, the mempool, miners, blocks, sync, restart, and reorg code an exact candidate wire to preserve without silently enabling it. The profile remains rejected by production until checked proof, complete zero-knowledge, composed post-quantum 128-bit security, formal refinement, verifier refinement, and byte-artifact evidence all exist.

## Progress

- [x] (2026-08-22 00:00Z) Inspected the active version binding, SmallWood proof wrapper, native transaction-leaf artifact, inline/sidecar transfer payloads, consensus verifier cache, native action admission, canonical block-action storage, restart replay, reorg replay, and release authorization checker.
- [x] (2026-08-22) Added the fresh V5/Delta candidate identity without changing the active V4/Gamma default or production version mapper.
- [x] (2026-08-22) Added the canonical borrowed envelope parser, encoder, full transcript binding, inline-only source admission, and compiled fail-closed capability lock.
- [x] (2026-08-22) Added a checked-in candidate manifest and independent strict checker/tests.
- [x] (2026-08-22) Added adversarial tests for malformed bytes, all binding swaps, and non-inline substitutions, plus an exact-byte journey covering relay through reorg.
- [x] (2026-08-22) Added the shared bounded SCALE transport wrapper for action 7, with exact wallet/RPC round-trip coverage, per-stage byte equality checks, pre-allocation caps, and native route rejection before payload parsing.
- [x] (2026-08-22) Restored Cargo discovery with an explicit root-workspace exclusion for the standalone prototype, ran all focused Rust/Python/release-policy checks, and updated this plan, `DESIGN.md`, and `METHODS.md`.

## Surprises & Discoveries

- Observation: The current native transaction-leaf artifact contains an embedded SmallWood proof plus a receipt and a lattice leaf wrapper. The future V5 boundary must not let that historical wrapper, a receipt, a cache hit, an aggregate, or a sidecar become proof authority.
  Evidence: `circuits/superneo-hegemon/src/lib.rs` defines `NativeTxLeafArtifact` and its exact parser; `node/src/native/admission.rs` still has inline and sidecar transfer branches.

- Observation: The current full SmallWood public verifier vector has exactly 78 Goldilocks values.
  Evidence: `circuits/transaction/src/smallwood_frontend.rs` fixes `SMALLWOOD_BASE_PUBLIC_VALUE_COUNT` to 78 and rejects other production-map widths.

- Observation: The 78-value production map does not contain the 48-byte balance tag. Treating an outer wrapper tag as authoritative would leave it free to float.
  Evidence: `smallwood_production_public_field_ranges()` maps flags, nullifiers, commitments, ciphertext hashes, fee, root, slot assets, stable fields, and version across indices 0 through 77. The V5 envelope therefore appends and binds the relation-computed tag as a distinct statement component.

- Observation: Workspace Cargo discovery initially failed because `wallet/Cargo.toml` discovers the nested `[workspace]` at `circuits/standalone-full-shake256-relation-prototype`.
  Evidence: `cargo metadata --no-deps --format-version 1` reported “multiple workspace roots found” for that prototype and the repository root. Adding that explicitly standalone crate to root `workspace.exclude` restored metadata and focused tests without changing the prototype manifest or wallet feature.

- Observation: The completed BLAKE2b-384 semantic adapter fits this envelope API but cannot instantiate the strict V5 profile.
  Evidence: its own source/ExecPlan records 255,100 packed hash rows before transaction logic and a 384-bit generic quantum-collision exponent with zero composition margin. V5 therefore fixes SHAKE256-448/SHA-512; the BLAKE2b adapter remains a non-authorizing semantic oracle.

- Observation: A whole-workspace format check still reports drift in concurrently owned hash, wallet, walletd, and consensus files.
  Evidence: `cargo fmt --all -- --check` lists only those unrelated paths; the V5 files were formatted directly, their focused clippy checks pass, and `git diff --check` is clean.

## Decision Log

- Decision: Assign circuit version 5 and crypto suite Delta 4 to the candidate, while leaving `DEFAULT_VERSION_BINDING` at V4/Gamma and returning no production backend for V5.
  Rationale: A fresh identity prevents old V4 proof/profile bytes from being reinterpreted after the relation hash changes, and the absent production mapping is the first authorization lock.
  Date/Author: 2026-08-22 / Codex

- Decision: Use an 80-byte fixed header followed by exactly 672 statement bytes and one inline proof. The statement is 624 bytes of canonical 78-word public values followed by the relation-computed 48-byte balance tag.
  Rationale: Fixed offsets and a borrowed parser enforce caps before allocation. Carrying the complete statement, including the tag that is absent from the 78-word map, lets restart and historical replay verify the exact same artifact, while action admission must byte-compare it to the statement reconstructed from authoritative action and relation fields.
  Date/Author: 2026-08-22 / Codex

- Decision: Require a 48-byte relation-schedule digest and bind it together with the version, route, network, complete statement, and proof profile in the verifier transcript.
  Rationale: A backend or relation swap must change the proof transcript and fail before proof verification.
  Date/Author: 2026-08-22 / Codex

- Decision: Keep all compiled capability fields false and maintain a second checked-in candidate-manifest lock.
  Rationale: Parser completeness and wire tests are not evidence of a working proof, complete zero knowledge, PQ128 security, or formal/refinement closure.
  Date/Author: 2026-08-22 / Codex

- Decision: Bind active manifest authorization to the strict SHAKE256-448/SHA-512 security evaluator and require its trust-root digest from protected release configuration.
  Rationale: Candidate-controlled booleans and self-authored content hashes cannot establish complete ZK or PQ128. The strict evaluator derives authority from all receipts, and `HEGEMON_SMALLWOOD_V5_TRUST_ROOT_SHA256` keeps the trust pin outside the candidate manifest.
  Date/Author: 2026-08-22 / Codex

- Decision: Exclude `circuits/standalone-full-shake256-relation-prototype` from the root workspace while retaining it as the wallet's optional path dependency.
  Rationale: The crate deliberately owns its own nested workspace. Root exclusion is the minimal Cargo-supported boundary that preserves isolation and allows normal workspace discovery.
  Date/Author: 2026-08-22 / Codex

## Outcomes & Retrospective

The candidate identity, exact envelope, inactive route, bounded transport wrapper, dual capability/manifest locks, negative fixtures, and release/checker wiring are implemented. The shared action wrapper carries the canonical `SWV5` bytes verbatim; wallet serialization and RPC base64 decode are covered, and the native node rejects action 7 before nullifier or public-payload parsing. Focused validation passed: the transport module 5/5, transaction envelope 12/12, and wallet canonical-envelope RPC round-trip 1/1. The full native-node check is currently blocked by unrelated concurrent `block-recursion` exhaustiveness errors for `Sha512V6`/`DirectPacked64CompressedV6Sha512Smz2`; no proof backend ran and no production authorization was granted.

## Context and Orientation

`protocol/versioning/src/lib.rs` owns circuit and crypto-suite identities and maps only production-recognized bindings to proof backends. `circuits/transaction/src/smallwood_v5_envelope.rs` will own the candidate wire and its authorization boundary. `protocol/shielded-pool/src/family.rs` owns action identifiers; action 7 is reserved for the candidate but remains absent from the active kernel manifest. `config/smallwood-v5-conventional-hash-candidate.json` records the release evidence state, and `scripts/check_smallwood_v5_candidate_gate.py` validates it independently.

The word “candidate” means bytes may be parsed and tested, but normal wallet proving, mempool admission, mining, block import, sync, and restart verification must reject them. “Exact consumption” means every input byte belongs to the one envelope; truncation and any trailing byte reject. “Inline-only” means the proof is physically inside the action and block bytes; a locator, receipt, aggregate, cache entry, or sidecar cannot replace it.

## Plan of Work

First add V5/Delta constants and tests proving that they are distinct from V4/Gamma and have no production backend mapping. Then add the envelope module. Its parser checks the complete envelope cap before reading dynamic regions, checks the fixed 672-byte statement length and proof cap before slicing, requires canonical Goldilocks public-value words, rejects every unsupported route field and reserved byte, and returns borrowed statement/proof slices.

The module will also define an action-source structure that accepts exactly one inline envelope and rejects sidecar, aggregate, cached-receipt, and historical-wrapper substitutions. Action composition supplies the authoritative network, family, action, version, canonical statement, and relation digest and requires byte equality before a backend can run. The backend receives a binding object capable of writing one unambiguous transcript preamble. The public production entry point consults a private compiled capability record whose fields are all false in this change.

Finally add a JSON candidate manifest and Python validator. The normal check requires the identity and all current false/null evidence fields to remain inactive. An explicit authorization mode requires every named capability, concrete PQ bits at least 128, the exact SHAKE256-448/SHA-512 strict profile, a nonzero relation digest, an exact measured proof size below the envelope cap, content-addressed proof/security/formal/refinement/end-to-end artifacts, the exact derived strict report, and an independently supplied trust-root digest pin. The action-7 transport wrapper is deliberately decode-compatible but remains behind the native V3 route gate until those artifacts authorize it.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Run focused tests without a heavy proof build:

    cargo test -p protocol-versioning
    cargo test -p transaction-circuit smallwood_v5_envelope --lib
    python3 -B scripts/test_check_smallwood_v5_candidate_gate.py
    python3 -B scripts/check_smallwood_v5_candidate_gate.py
    git diff --check

The candidate checker prints an inactive-pass result. Running it with `--require-authorized` fails until all real artifacts exist. The temporary direct `rustc` harness was used as an early disk-light check; after the workspace exclusion restored Cargo discovery, all three native focused tests passed as well.

## Validation and Acceptance

The Rust tests must show that a canonical envelope round-trips and that the exact envelope bytes survive independent wallet, RPC, relay, mempool, mining, block, sync, restart, and reorg copies. Mutating any stage must reject. The SCALE wrapper must reject noncanonical compact lengths, truncation, trailing bytes, oversized declared lengths before allocation, and malformed envelope headers/proof declarations. Short headers, invalid magic/version/backend/profile/mode/reserved bytes, oversized declarations, wrong statement length, empty proof, truncated proof, trailing bytes, noncanonical field words, zero relation binding, profile swap, statement swap, network/family/action/version swap, sidecar substitution, aggregate substitution, cached-receipt substitution, historical-wrapper substitution, and mixed-source inputs must reject. The native route gate must reject action 7 before malformed public arguments or nullifiers are parsed. The mock backend must never run through the public production entry point while capability evidence is incomplete.

## Idempotence and Recovery

All changes are additive and tests use in-memory bytes or temporary directories. No proof generation, network access, large target directory, destructive cleanup, or repository push is required. Existing dirty worktree changes must be preserved.

## Artifacts and Notes

The active profile remains V4/Gamma. The new candidate identity and parser are not a security claim and are not a production route.

## Interfaces and Dependencies

`protocol_versioning::SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING` is the stable candidate identity. `transaction_circuit::smallwood_v5_envelope::decode_envelope_exact` returns a borrowed decoded envelope. `protocol_shielded_pool::smallwood_v5_transport::encode_smallwood_v5_inline_args` and `decode_smallwood_v5_inline_args_exact` are the bounded SCALE action wrapper; `ensure_smallwood_v5_stage_bytes` compares each persisted/relayed copy against the canonical artifact. `canonical_statement_from_values_and_balance_tag` converts the relation's `[u64; 78]` and computed `[u8; 48]` tag to the exact 672-byte statement. `verify_production_inline` is the only production-shaped verifier entry and must remain blocked by the private compiled capability lock. Future relation code must also provide the exact 48-byte schedule digest. Future backend code must implement `SmallwoodV5BackendVerifier::verify_exact` and consume `SmallwoodV5ProofBinding::write_transcript_preamble` before all proof messages.

Revision note (2026-08-22): completed the fail-closed integration boundary, corrected the 624-plus-48-byte statement split, added the byte-preserving action transport boundary and native pre-parse gate, restored Cargo discovery through the explicit standalone-prototype exclusion, and recorded native focused validation.
