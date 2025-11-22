# Identity and Credential Pallet

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain it in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Introduce a FRAME-based identity pallet that records decentralized identifiers (DIDs), credential schemas, issued credentials, and role assignments so other pallets can enforce permissions and apply identity-based tags such as fee discounts or asset freezes. Users should be able to register and update their DID data, issuers can mint and revoke credentials with external attestation hooks, and governance can rotate session keys or assign roles. A stub proof verifier allows privacy-preserving credential checks to integrate later.

## Progress

- [x] (2025-02-24 00:00Z) Planned storage layout, extrinsics, events, and helper traits for role/credential checks.
- [x] (2025-02-24 01:00Z) Implemented pallet storage, events, extrinsics, helper traits, and attestation/proof hooks.
- [x] (2025-02-24 01:20Z) Added workspace wiring and ran `cargo fmt` plus `cargo check -p pallet-identity`.

## Surprises & Discoveries

- Substrate crates pulled a large dependency tree, making the first `cargo check -p pallet-identity` compile lengthy.

## Decision Log

- Decision: Use `BlockNumberFor<T>` and manual `Debug` impls for identity tags to satisfy FRAME trait bounds without constraining the runtime config to implement `Debug`.
  Rationale: New FRAME versions enforce stricter trait bounds; manual implementations keep the pallet ergonomic for runtimes.
  Date/Author: 2025-02-24 / Assistant

## Outcomes & Retrospective

- Implemented a FRAME identity pallet with DID storage, credential schemas, issuance/revocation, role management, session keys, proof verification hooks, and identity provider helpers. Workspace membership and formatting/checks are in place.

## Context and Orientation

The repository currently lacks a Substrate-style identity pallet. New code will live under `pallets/identity/`. The pallet should define storage for DID documents, credential schemas, issued credentials with revocations, role assignments, and session keys. It needs extrinsics for registering/updating DIDs, issuing/revoking credentials, assigning roles, rotating session keys, and verifying credential proofs via a pluggable verifier. Events and weight plumbing must be present, and helper traits should expose permission checks and identity tags for other pallets (asset registry, attestations, settlement).

## Plan of Work

Add a new crate `pallets/identity` with a FRAME pallet. Define configuration items for `AuthorityId`, `CredentialSchemaId`, `RoleId`, sizing constants, `ExternalAttestation` hooks, a stub `CredentialProofVerifier`, and `WeightInfo`. Implement storage maps for DIDs with tags/session keys, credential schemas, issued credential records, revocation flags, and role assignments. Implement helper traits and ensure functions that check roles, credentials, and identity tags for use by other pallets. Add events for DIDs, credential issuance/revocation, role changes, proof verification, and session key rotation. Provide extrinsics for registering/updating DIDs, assigning roles, issuing/revoking credentials, rotating session keys, verifying proofs, and updating schemas if needed. Update the workspace `Cargo.toml`, format, and run targeted checks.

## Concrete Steps

1. Create `pallets/identity/Cargo.toml` declaring dependencies on FRAME primitives, SCALE codec, and workspace settings with `std`/`no_std` feature toggles.
2. Implement `pallets/identity/src/lib.rs` with `#[frame_support::pallet]`, configuration, storage, events, errors, weight trait, helper traits (`IdentityProvider`, proof verifier, external attestation hooks), and all extrinsics.
3. Update the root `Cargo.toml` workspace members to include the new pallet.
4. Run `cargo fmt` (and `cargo check -p pallet-identity` if feasible) to validate formatting and compilation.

## Validation and Acceptance

A successful implementation compiles the new pallet crate and exposes callable extrinsics and helper traits matching the design. Running `cargo fmt` should succeed. If time permits, `cargo check -p pallet-identity` should build without errors, demonstrating the pallet integrates into the workspace.

## Idempotence and Recovery

Steps are additive: creating files and running formatting/checks are safe to repeat. Re-running the extrinsic implementations is just editing code; git history preserves earlier states for rollback.

## Artifacts and Notes

None yet.

## Interfaces and Dependencies

- `pallets/identity/src/lib.rs` defines:
    - `Config` with associated types for authority identifiers, credential schema IDs, role IDs, bounds, attestation hooks, proof verifier, and `WeightInfo`.
    - `IdentityTag`, `DidDetails`, `CredentialSchema`, and `CredentialRecord` data structures using bounded vectors for on-chain storage.
    - Storage maps: `Dids`, `CredentialSchemas`, `Credentials`, `Revocations`, `RoleAssignments`, `SessionKeys`.
    - Helper traits `IdentityProvider`, `ExternalAttestation`, and `CredentialProofVerifier` implemented for `Pallet`/`()` to enable other pallets to check roles and credentials and to verify proofs.
    - Extrinsics for DID registration/update, credential issuance/revocation, role assignment toggling, session key rotation, schema updates, and credential-proof verification.
    - Events for DID lifecycle, credential issuance/revocation, role changes, proof verification, schema updates, and session key rotation with weight plumbing via `WeightInfo`.
