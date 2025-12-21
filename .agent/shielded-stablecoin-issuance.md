---
name: shielded-stablecoin-issuance
description: ExecPlan for stablecoin issuance in the fully shielded pool
---

# Shielded Stablecoin Issuance

This ExecPlan is a living document. The sections Progress, Surprises and Discoveries, Decision Log, and Outcomes and Retrospective must be kept up to date as work proceeds.

Reference: repository root .agent/PLANS.md defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

This change makes stablecoin issuance real inside the single fully shielded pool. After completion, authorized issuers can mint and burn a stablecoin without revealing amounts, and the node will only accept the transaction if its proof shows compliance with on-chain peg policy and current oracle and audit commitments. Regular users can receive and transfer the stablecoin like any other shielded asset, while policy violations are rejected during proof verification rather than after the fact.

The visible proof is that on a dev node you can mint stablecoin notes when policy inputs are fresh and valid, and the exact same transaction fails when an oracle commitment is stale, an attestation is disputed, or the issuer lacks authorization.

## Progress

- [x] (2025-12-21 07:10Z) Draft initial ExecPlan for shielded stablecoin issuance.
- [x] (2025-12-21 19:20Z) Implement stablecoin policy pallet and runtime wiring; run `cargo test -p pallet-stablecoin-policy`.
- [x] (2025-12-21 19:20Z) Extend MASP circuit/public inputs for stablecoin issuance, fix selector-sum degree mismatch, and run `cargo test -p transaction-core` plus `cargo test -p transaction-circuit proving_and_verification_succeeds -- --nocapture`.
- [x] (2025-12-21 20:50Z) Implement shielded-pool runtime verification and unsigned rejection, wire provider hooks, and run `cargo test -p pallet-shielded-pool`.
- [ ] (2025-12-21 19:20Z) Update wallet and issuer tooling (remaining).
- [ ] (2025-12-21 19:20Z) Documentation, tests, and hardening (remaining: DESIGN/METHODS/README updates, runtime tests).

## Surprises & Discoveries

- Observation: Winterfell debug degree checks flagged the stablecoin selector-sum constraint as over-declared (expected 65534, actual 32767) because the mask multiplies a linear expression, so the base degree is 1. Evidence: `transition constraint degrees didn't match ... expected ... 65534 ... actual ... 32767`.
- Observation: The end-to-end proof test is slow; `cargo test -p transaction-circuit proving_and_verification_succeeds -- --nocapture` finished in ~273s. Evidence: test output `finished in 273.42s`.
- Observation: `cargo test -p pallet-shielded-pool` initially failed due to an unused `winter_math` import in the verifier. Evidence: `unresolved import winter_math`.

## Decision Log

Decision: Model the stablecoin as a MASP asset_id with explicit issuance allowance enforced in the proof rather than a transparent pool. Rationale: the repository design mandates a single shielded pool and forbids transparent balances in production. Date/Author: 2025-12-21 / Codex.

Decision: Store peg policy parameters in a dedicated pallet and expose a deterministic policy hash to the shielded pool verifier. Rationale: this keeps policy governance separate from proof verification while making the inputs auditable and deterministic. Date/Author: 2025-12-21 / Codex.

Decision: Bind issuance proofs to on-chain oracle commitments and attestation commitments instead of external data. Rationale: the verifier must be deterministic and based only on chain state. Date/Author: 2025-12-21 / Codex.

Decision: Require stablecoin issuance to use the signed shielded_transfer path only, and reject any stablecoin issuance in unsigned transactions. Rationale: signed extrinsics provide nonce-based replay protection and allow role checks for authorized issuers. Date/Author: 2025-12-21 / Codex.

Decision: Store minimum collateral ratio as a ppm-scaled `u128` (1_000_000 = 1.0) in the policy and hash it as-is. Rationale: avoids floating point, keeps the policy hash deterministic, and stays within a safe integer range for runtime and circuit bindings. Date/Author: 2025-12-21 / Codex.

Decision: Require exactly one oracle feed id in stablecoin policies for now. Rationale: the circuit binds a single oracle commitment, so enforcing a single feed keeps constraints simple while leaving room for a multi-feed upgrade later. Date/Author: 2025-12-21 / Codex.

Decision: Allow genesis policy insertion to bypass asset-registry checks. Rationale: dev chains can pre-seed policies for assets that are registered later, keeping policies inactive until assets exist. Date/Author: 2025-12-21 / Codex.

## Outcomes & Retrospective

Outcome (2025-12-21): Milestones 1–2 landed. Stablecoin policy storage is wired into the runtime, and the transaction circuit now binds issuance deltas to policy/oracle/attestation commitments with passing `transaction-core` and `transaction-circuit` tests. Remaining work is shielded-pool runtime verification, wallet tooling, and documentation/test hardening.
Outcome (2025-12-21): Milestone 3 landed with stablecoin binding checks in the shielded pool and passing `cargo test -p pallet-shielded-pool`.

## Context and Orientation

This repository implements a single shielded pool with STARK proofs. A shielded pool is a ledger where balances are represented as hidden notes and only cryptographic proofs reveal that updates are valid. A note is a private record holding a value and an asset identifier. A commitment is the public hash of a note, and a nullifier is the public hash that prevents double spends. A STARK proof is a transparent proof system that uses only hash functions and does not require a trusted setup. MASP means multi asset shielded pool, where the proof enforces conservation for each asset identifier instead of a single native token.

Oracle commitments are on-chain hashes of feed updates stored by `pallets/oracles`. Attestations are on-chain records of audit or reserve proofs stored by `pallets/attestations`, including dispute status. A peg policy is a set of on-chain parameters that define which oracle feeds and attestation records must be bound into a stablecoin issuance proof, how fresh those inputs must be, and how much the issuer can mint per epoch. A policy hash is a deterministic 32 byte hash computed from the policy fields so the circuit can bind to a single value rather than the full policy structure.

The shielded pool pallet is `pallets/shielded-pool`, which verifies proofs and updates the commitment tree and nullifier set. The MASP circuit lives under `circuits/transaction-core` and `circuits/transaction`, and its public inputs are enforced by the verifier in the shielded pool pallet. Asset metadata and regulatory tags live in `pallets/asset-registry`, and identity roles live in `pallets/identity`. The stablecoin policy lives in `pallets/stablecoin-policy`, is wired into `runtime/src/lib.rs`, and must be referenced by the shielded pool verifier.

Before changing code, read `DESIGN.md` and `METHODS.md` and keep them updated if the architecture or methods evolve. If the README whitepaper is updated, preserve the title and subtitle and keep the whitepaper before the Monorepo layout and Getting started sections.

## Plan of Work

The work is organized into milestones so each step is independently verifiable and adds a new observable behavior. Each milestone describes the change, the commands to run, and what success looks like.

### Milestone 0: Feasibility spike for policy proof binding

Implement a minimal circuit path that binds an issuance delta to a policy hash and an oracle commitment, then route it through the existing verifier pipeline. This is a targeted spike to prove the public input wiring works before the full policy pallet exists. Add a focused test under `circuits/transaction` that generates a proof and verifies it when the policy hash matches, and fails when the hash is changed. Run `cargo test -p transaction-circuit` from the repository root and expect the new test to fail before the change and pass after it. The observable outcome is a passing test that demonstrates the proof is rejected when policy inputs do not match.

### Milestone 1: Stablecoin policy pallet and runtime wiring

Create `pallets/stablecoin-policy` to store peg policies keyed by asset_id. The pallet must enforce that the asset exists in `pallets/asset-registry` and that only accounts with the appropriate identity role can create or update a policy. The pallet should expose a policy hash for each asset and an active flag for enabling or disabling issuance. Wire the new pallet into `runtime/src/lib.rs` with genesis configuration for a dev stablecoin policy. Run `cargo test -p pallet-stablecoin-policy` once it exists and run the runtime tests that exercise policy storage. The observable outcome is that a policy can be created, updated, and read by hash via runtime APIs, and that unauthorized updates are rejected.

### Milestone 2: Extend MASP circuit and public inputs for stablecoin issuance

Extend the MASP circuit to allow a non zero net issuance delta for exactly one configured stablecoin asset_id, and only when the proof includes a policy binding. The proof must bind to the policy hash, the latest oracle commitment, the latest attestation commitment, and a policy version so upgrades are explicit. The circuit must still enforce per asset conservation for all other asset_ids. Update `circuits/transaction-core` types, public input encoding, and the AIR so these values are enforced. Run `cargo test -p transaction-core` and `cargo test -p transaction-circuit`, and expect a new test that verifies issuance proofs with valid policy inputs to pass while mismatched inputs fail.

### Milestone 3: Runtime verification and transaction surface

Extend `pallets/shielded-pool` to accept the stablecoin policy binding in `ShieldedTransfer` and verify that the on chain policy hash and commitments match the proof inputs. Add a config hook for a policy provider, an oracle commitment provider, and an attestation commitment provider so the verifier can access chain state without hard coupling. Ensure stablecoin issuance is only permitted in the signed `shielded_transfer` call, and explicitly reject any stablecoin issuance in `shielded_transfer_unsigned`. Run `cargo test -p pallet-shielded-pool` and add runtime tests that ensure missing or stale commitments cause the transaction to be rejected. The observable outcome is that valid issuance proofs are accepted and invalid or unsigned ones are rejected.

### Milestone 4: Wallet and issuer tooling

Update the wallet to build stablecoin issuance and burn transactions. Add issuer commands to the CLI that construct the policy binding, generate the proof, and submit the signed extrinsic. The wallet should display balances per asset_id and include stablecoin metadata from `pallets/asset-registry`. Run `cargo test -p wallet` and execute a dev flow against a local node where issuance succeeds for authorized issuers and fails for unauthorized accounts. The observable outcome is that an issuer can mint shielded stablecoin notes, and a regular user can receive and transfer them without seeing amounts on chain.

### Milestone 5: Documentation, tests, and hardening

Update `DESIGN.md`, `METHODS.md`, and the whitepaper section of `README.md` to describe the stablecoin issuance path, the policy hash binding, and the fully shielded enforcement model. Add or extend tests in `circuits/transaction`, `pallets/shielded-pool`, `pallets/oracles`, and `pallets/attestations` to cover the new policy checks and commitment freshness. Keep the README title and subtitle intact and keep the whitepaper ahead of the Monorepo layout and Getting started sections. The observable outcome is that documentation matches the implemented behavior and the new tests pass locally.

## Concrete Steps

On a fresh clone, run the required setup commands before any build. From the repository root, run:

    make setup
    make node

To start a dev node with mining enabled and a temporary database, run:

    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

Use the same root directory for all cargo commands. During development, run targeted tests as they are added, for example:

    cargo test -p transaction-core
    cargo test -p transaction-circuit
    cargo test -p transaction-circuit proving_and_verification_succeeds -- --nocapture
    cargo test -p pallet-shielded-pool
    cargo test -p pallet-oracles
    cargo test -p pallet-attestations
    cargo test -p wallet

Update this section with any additional commands introduced during implementation.

## Validation and Acceptance

Acceptance is behavioral and must be demonstrated on a dev node. Register a stablecoin asset in `pallets/asset-registry`, configure an active policy in `pallets/stablecoin-policy`, and submit oracle and attestation commitments that satisfy the policy. Use the wallet issuer command to mint stablecoin notes and confirm the transaction is accepted and the wallet sees the new shielded balance. Then submit the same mint with a stale oracle commitment or a disputed attestation and confirm the transaction is rejected during verification. Finally, submit a mint without the policy proof and confirm it fails. Transfers between users should succeed without revealing amounts and without creating any transparent balances.

## Idempotence and Recovery

These steps are safe to repeat on a dev node when using `--tmp`. If a circuit or runtime change requires a state reset, purge the local chain database and wallet store before retrying. If a proof path change breaks verification, temporarily disable the new version in the version schedule and revert to the last known good verifying key until the issue is resolved.

## Artifacts and Notes

Capture concise logs or test output that demonstrates acceptance and rejection. Example snippets should look like:

    shielded-pool: stablecoin issuance verified for asset_id 1001
    shielded-pool: rejected stablecoin issuance, oracle commitment too old
    shielded-pool: rejected stablecoin issuance, missing policy proof

## Interfaces and Dependencies

In `pallets/stablecoin-policy/src/lib.rs`, define a policy struct and a provider trait with a deterministic policy hash. The hash should be BLAKE3 256 over SCALE encoded fields with a domain tag `stablecoin-policy-v1` so the hash is stable across versions. The policy must include the asset_id, the oracle feed ids, the attestation id, a minimum collateral ratio, a maximum mint per epoch, an oracle max age, a policy version, and an active flag.

In `pallets/shielded-pool/src/lib.rs`, add config hooks for reading the policy and fetching current oracle and attestation commitments. Use these hooks in the verifier path to compare the proof inputs to current chain state.

In `pallets/shielded-pool/src/types.rs`, extend `ShieldedTransfer` to carry an optional stablecoin policy binding when an issuance delta is present. The binding should include the stablecoin asset_id, the policy hash, the oracle commitment, the attestation commitment, the issuance delta, and the policy version. The binding should be optional for normal transfers and required for any non zero issuance delta.

In `circuits/transaction-core/src/types.rs` and `circuits/transaction/src/public_inputs.rs`, add matching fields in the public input encoding so the circuit enforces the policy binding. The verifier must reject proofs when the binding does not match chain state. The signed `shielded_transfer` path must be the only entry point for stablecoin issuance, and `shielded_transfer_unsigned` must reject any transaction that includes a stablecoin issuance binding.

In `runtime/src/lib.rs`, wire the new pallet and configure its roles using `pallets/identity`, and ensure the oracle and attestation pallets are available for commitment lookups. All new proof verification must use the production verifier path and must not accept empty or placeholder proofs.

Plan update note (2025-12-21 20:50Z): Completed milestone 3 with runtime verification and stablecoin binding checks, noted the `winter_math` import fix, and recorded the `cargo test -p pallet-shielded-pool` run.
