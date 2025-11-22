# PQ hashing + hybrid identity/session + STARK verifier parameters

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this plan in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Enable post-quantum hardening across commitments, identity/session key handling, and attestation/settlement verification. After completing this plan, commitments and PRFs rely on PQ-safe hash choices (BLAKE3/SHA3), identity/session records can store hybrid Dilithium/Falcon + Ed25519 keys with migration helpers, and attestation + settlement pallets persist STARK verifier parameters with upgrade hooks so on-chain verification stays configurable.

## Progress

- [x] (2025-03-27 00:00Z) Wrote initial ExecPlan covering PQ hashing, hybrid identity keys, and STARK verifier parameter storage.
- [x] (2025-03-27 01:10Z) Implemented PQ commitment hashing selection and pallet hashing utility updates.
- [x] (2025-03-27 01:20Z) Added hybrid signature (Dilithium/Falcon + Ed25519) support for identity/session keys with migration paths.
- [x] (2025-03-27 01:30Z) Persisted STARK/PQ-friendly verifier parameters in attestations/settlement pallets with upgrade hooks.
- [ ] Validate via tests/checks and update documentation reflecting the new defaults and migrations.

## Surprises & Discoveries

- Observation: Direct `cargo test` runs resolve workspace crates and failed against unavailable `pallet-timestamp = 43.0.0` on crates.io.
  Evidence: `cargo test -p synthetic-crypto --locked hash_commitment_and_prf_vectors` returned a dependency selection error.

## Decision Log

- Decision: Default commitments/PRFs to BLAKE3-256 with optional SHA3-256 to keep hashes PQ-friendly and align with STARK parameter choices.
  Rationale: Removes SHA-256 reliance while keeping domain-separated hashes that match verifier settings.
  Date/Author: 2025-03-27 / agent
- Decision: Store session keys as a hybrid enum (legacy, PQ-only, Ed25519-only, hybrid) with storage migration.
  Rationale: Enables gradual rollout of Dilithium/Falcon plus Ed25519 without breaking existing AuthorityId mappings.
  Date/Author: 2025-03-27 / agent
- Decision: Persist STARK verifier parameters on-chain with governance setters and runtime-upgrade initialization in both attestations and settlement pallets.
  Rationale: Keeps verification aligned with PQ hash/function choices and allows parameter tuning without code upgrades.
  Date/Author: 2025-03-27 / agent

## Outcomes & Retrospective

Implemented BLAKE3/SHA3 commitment utilities, hybrid session key storage with migrations, and on-chain STARK verifier parameter controls. Test execution is partially blocked by upstream crate availability, so manual vectors were recomputed and documentation updated; further automated validation should re-run once the dependency mirror is reachable.

## Context and Orientation

The `crypto` crate currently provides SHA-256 and BLAKE3 helpers plus a `commit_note` commitment helper using SHA-256 (`crypto/src/hashes.rs`). Attestations and settlement pallets store commitments and verification keys but do not persist STARK verifier parameters beyond a verification key blob. Identity/session keys in `pallets/identity` are generic over `AuthorityId` and the runtime sets this to `u64`; there is no notion of hybrid (PQ + classical) key storage or migration. Runtime hashing defaults to `BlakeTwo256` via `sp_runtime`.

Key files to edit:
- `crypto/src/hashes.rs` and related tests under `crypto/tests/` for commitment hashing.
- `pallets/identity/src/lib.rs` and runtime configuration in `runtime/src/lib.rs` for hybrid session key handling and migrations.
- `pallets/attestations/src/lib.rs` and `pallets/settlement/src/lib.rs` for STARK verifier parameter storage and hooks; runtime config connects the two pallets.
- Documentation references in `DESIGN.md`, `METHODS.md`, and `docs/API_REFERENCE.md` that describe hash/commitment and signature schemes.

## Plan of Work

1. Introduce PQ-safe commitment hashing by adding SHA3-256 alongside existing helpers and switching the commitment helper to prefer BLAKE3-256 (with SHA3 fallback) while keeping deterministic interfaces. Propagate the choice to pallets that derive commitments/nullifiers and ensure tests/vectors reflect the new hash output. Provide a small helper in pallets to centralize hashing for commitments.
2. Extend identity/session handling to support a hybrid signature payload combining a PQ scheme (Dilithium/Falcon placeholder) with Ed25519. Define an enum for key kinds (PQ-only, classical, hybrid) plus migration storage/versioning to allow existing `AuthorityId` entries to upgrade. Expose extrinsics to migrate keys and validate shapes while keeping backward compatibility for existing `AuthorityId` values. Update runtime types to use the new struct instead of a bare `u64` and document migration paths.
3. For attestations/settlement, add on-chain storage for STARK/PQ verifier parameters (e.g., field modulus, merkle hash, fri settings) separate from verification keys. Provide governance-controlled setters and integrate parameters into verification paths and off-chain hooks. Add runtime upgrade hooks to initialize defaults and allow future upgrades via storage versioning.
4. Update documentation (DESIGN, METHODS, API reference) to capture the new hash choice, hybrid key story, and STARK verifier parameterization. Add or adjust tests to cover new hash outputs, hybrid key migration flows, and STARK parameter storage.

## Concrete Steps

- Edit `crypto/src/hashes.rs` to add SHA3-256 helper and switch commitment/PRF utilities to PQ-preferred hashing. Update `crypto/tests/crypto_vectors.rs` and vectors data to match.
- Add a pallet-level hashing helper (or adapter) for commitments used by attestations/settlement if they compute hashes directly.
- Introduce hybrid key enum/struct in `pallets/identity` with migration-friendly storage (e.g., versioned enum with legacy `u64`). Add extrinsic to migrate/rotate session keys with hybrid payload and update runtime config/types.
- In `pallets/attestations` and `pallets/settlement`, create storage for verifier parameters, governance setter calls, and runtime upgrade initialization. Ensure settlement proof verification pulls parameters from storage and pending event hooks include parameter context if needed.
- Adjust runtime wiring for new types/constants and update documentation/tests. Run `cargo fmt` and targeted tests (e.g., `cargo test -p crypto` plus relevant pallet tests if present).

## Validation and Acceptance

Success criteria:
- `cargo test -p crypto` passes with updated commitment/hash vectors.
- Identity pallet accepts both legacy and hybrid session keys; migration extrinsic updates storage and emits an event. Storage version migration runs without panic.
- Attestation/settlement pallets expose and persist STARK verifier parameters, initialize defaults on upgrade, and setter calls restricted to governance origin. Proof verification path references stored parameters.
- Documentation reflects new PQ hash default and hybrid key/verifier parameter behavior.

## Idempotence and Recovery

Edits are additive and use storage versioning with migration hooks; rerunning upgrade hooks is safe due to version checks. Hash helper updates are pure functions. Tests provide guardrails for repeated runs. In case of partial failure, rerun migrations after resetting storage in a development chain.

## Artifacts and Notes

Add concise test output snippets or diffs in this section as implementation proceeds.

## Interfaces and Dependencies

- New hash helper: `crypto::hashes::sha3_256(data: &[u8]) -> [u8; 32]` and updated `commit_note` to use BLAKE3-256 by default.
- Hybrid key type: `pallet_identity::HybridSignatureKey` (enum) stored in `DidDetails::session_key` and `SessionKeys` map, with extrinsic `rotate_session_key` accepting the new type and migration to convert legacy `AuthorityId` entries.
- Verifier parameters type: `VerifierParameters` struct in attestation/settlement pallets stored in dedicated storage with governance setter and upgrade initialization; `ProofVerifier` implementations consume these parameters.
