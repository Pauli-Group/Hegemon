# Private multisig accumulator wallet flow

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` in this repository. It is self-contained so a future contributor can continue the private multisig wallet flow without relying on prior chat context.

## Purpose / Big Picture

This change gives Hegemon wallets safe scaffolding for stateful shielded accumulator multisig. After it lands, a full wallet can create a private multisig account record and compute exact spend-intent digests, but approval and final-spend APIs fail closed until the real approval-step and final-spend shielded circuit transaction hooks exist. Unit tests may use private fake hooks to enforce intended privacy and replay boundaries, but product code must not emit or accept local opaque approval packages.

The user-visible path is through `walletd` newline JSON methods. A coordinator calls `multisig.accountCreate` and privately distributes the resulting account identifier and policy commitment out of band. Until the circuit worker lands real shielded approval/final transactions, `multisig.approvalCreate`, `multisig.approvalImport`, and `multisig.finalize` return structured fail-closed errors. Responses never publish threshold, signer set, policy root, approval count, or approval nullifiers.

## Progress

- [x] (2026-06-25 00:00Z) Read `AGENTS.md`, `.agent/PLANS.md`, `DESIGN.md`, and `METHODS.md`; confirmed predicate notes are the native direction and the shipped witness is still single-secret.
- [x] (2026-06-25 00:00Z) Created branch `codex/private-multisig-accumulator-wallet-flow`.
- [x] (2026-06-25 00:00Z) Cherry-picked reference commit `714a693c` as `b02bea93` to reuse the hidden policy-through-`pk_auth` note-binding API.
- [x] (2026-06-25 00:00Z) Added additive wallet multisig data model with real hook names, exact intent digesting, and product functions that fail closed while circuit integration is missing.
- [x] (2026-06-25 00:00Z) Added encrypted store persistence for hidden account metadata and a v6-to-v7 wallet migration.
- [x] (2026-06-25 00:00Z) Added walletd JSON scaffolding for account creation/listing and fail-closed approval/finalization methods.
- [x] (2026-06-25 00:00Z) Updated design/method docs to describe the wallet/protocol flow and call out the real circuit hooks still required.
- [x] (2026-06-25 00:00Z) Added serialization/API tests and a unit-only fake exact-intent accumulator flow test.
- [x] (2026-06-25 00:00Z) Ran focused wallet multisig tests successfully.
- [ ] Run focused walletd multisig tests; blocked by host storage exhaustion during dependency compilation.
- [ ] Commit coherent changes without pushing.

## Surprises & Discoveries

- Observation: The active transaction witness still carries one `sk_spend` and one `pk_auth`-based authorization path.
  Evidence: `METHODS.md` describes `sk_spend` as the shielded spend witness, and `circuits/transaction/src/witness.rs` is still shaped around that model. The multisig work must therefore be a protocol-flow scaffold with explicit provisional proof hooks until the circuit relation is implemented.

- Observation: Coordinator steering forbids product-facing fake proof paths.
  Evidence: Wallet APIs now expose real hook names and return a missing-circuit error for approval/finalization outside tests. Fake approval packages are private `#[cfg(test)]` helpers only.

- Observation: Focused walletd validation could not complete because the host filesystem filled while compiling dependencies.
  Evidence: `cargo test -p walletd multisig` failed with `No space left on device (os error 28)` while compiling existing dependencies including `synthetic-crypto`, `superneo-backend-lattice`, and `transaction-core`.

## Decision Log

- Decision: Implement multisig as an additive `wallet::multisig` flow with opaque commitments and provisional proof bytes, not by modifying `TransactionWitness`.
  Rationale: The user asked to assume the circuit relation will expose approval-step and final-spend modes privately, but the current circuit does not. Touching the production spend witness would create a false integration. A wallet-level flow with clear replacement hooks lets API, serialization, and coordinator/signer boundaries become testable now.
  Date/Author: 2026-06-25 / Codex

- Decision: Do not expose provisional proof bytes in product code; product approval/finalization APIs fail closed until real shielded circuit transaction hooks exist.
  Rationale: The integrated product must submit real approval and final-spend transactions, not local opaque packages accepted by wallet host logic. Test-only fake hooks can still exercise exact-intent accumulator behavior without creating a shippable false path.
  Date/Author: 2026-06-25 / Codex

- Decision: Persist only local coordinator/signer metadata in the encrypted wallet store and keep public packages free of threshold, signer set, policy root, approval count, and approval nullifiers.
  Rationale: The privacy requirement is about what leaves the wallet. The coordinator may have local policy data if they created the account, but packages exchanged over walletd must not reveal policy shape or signer participation.
  Date/Author: 2026-06-25 / Codex

## Outcomes & Retrospective

Implemented safe wallet-side scaffolding only. Account creation/listing is usable as encrypted local data-model setup; approval creation/import/finalization intentionally fail closed until real shielded approval-step and final-spend transaction builders are available. The test-only fake accumulator path verifies exact-intent binding and finalization rejection for a changed intent or accumulator note, but it is private to unit tests and is not exported as a product path.

## Context and Orientation

The repository root is `/Users/pldd/.codex/worktrees/9c47/Hegemon`. The wallet library lives in `wallet/src`, the non-interactive JSON daemon lives in `walletd/src/main.rs`, and wallet state persistence lives in `wallet/src/store.rs`. A "walletd method" means one newline-delimited JSON request written to `walletd` stdin after the passphrase line; responses are JSON objects with `ok`, `result`, and `error` fields.

A "policy commitment" is a 48-byte hash commitment to hidden multisig policy data. The policy data includes the threshold and signer secret commitments, but that data is not published by the walletd API. An "accumulator note" is a 48-byte commitment representing the state of private approvals. In the future, the approval-step circuit will consume the previous accumulator note privately and create the next accumulator note, while proving that one eligible signer approved the exact spend intent. A "spend intent" is the exact transaction intent being approved; approvals bind to its digest so they cannot be reused for another destination, fee, anchor, output set, or transaction binding.

The product hook names are `hegemon_multisig_approval_step_circuit_v1` and `hegemon_multisig_final_spend_circuit_v1`. The only provisional proof bytes in this branch are private `#[cfg(test)]` helpers with explicit `PROVISIONAL_WALLET_MULTISIG_*` domain tags. They are not cryptographic circuit proofs and are not callable from walletd or exported wallet APIs.

## Plan of Work

Add `wallet/src/multisig.rs` with serializable public account records, exact intent objects, future approval/final package shapes, and private local records. The module exposes functions for creating an account and deriving a signer commitment from the local spend key. Product approval/finalization functions currently return missing-circuit errors; private unit-test helpers can build fake packages to test exact-intent binding and privacy shape without becoming a product path.

Extend `wallet/src/store.rs` with a `multisig_accounts` field and methods to create/list hidden local accounts. Because wallet state is exact serialized, add an explicit v6 migration shape and bump the wallet file version to 7.

Extend `walletd/src/main.rs` with `multisig.accountCreate`, `multisig.accountList`, `multisig.approvalCreate`, `multisig.approvalImport`, and `multisig.finalize`. These methods use camelCase request/response fields and hex strings for opaque byte arrays. Account creation/listing works; approval/finalization fail closed until real circuit hooks exist.

Update `DESIGN.md` and `METHODS.md` with a concise section that documents the stateful accumulator flow, the privacy invariants, and the provisional circuit hook boundary.

Add focused tests in `wallet/src/multisig.rs`, `wallet/src/store.rs`, and `walletd/src/main.rs` for serialization, local flow, replay rejection, and API shape. Run `cargo test -p wallet multisig` and `cargo test -p walletd multisig`.

## Concrete Steps

From `/Users/pldd/.codex/worktrees/9c47/Hegemon`, run:

    git switch -c codex/private-multisig-accumulator-wallet-flow
    cargo test -p wallet multisig
    cargo test -p walletd multisig

Focused wallet validation passed:

    cargo test -p wallet multisig
    result: 5 passed; 0 failed; 101 filtered out

Focused walletd validation was attempted but blocked by host storage exhaustion:

    cargo test -p walletd multisig
    error: No space left on device (os error 28)

The branch should rerun `cargo test -p walletd multisig` once the host has enough free disk for dependency compilation.

## Validation and Acceptance

Acceptance is behavioral. Product tests create a private account and prove the public response omits `threshold`, `signers`, `policyRoot`, `approvalCount`, and `approvalNullifier`. Product walletd approval creation is coded to fail closed with a missing-circuit error, but the focused walletd test did not complete on this host because dependency compilation exhausted disk space. Unit-only fake tests create exact-intent approval packages and prove changing recipient, amount, fee, asset, root, or transaction binding changes the digest, and that finalization rejects a changed intent or accumulator note; those helpers are not compiled into product APIs.

## Idempotence and Recovery

All changes are additive. Running tests repeatedly should not mutate repository state beyond build artifacts. Wallet store migration is one-way from file version 6 to 7 when opening an old encrypted store and writing it again; tests cover new stores and the migration shape.

## Artifacts and Notes

Focused wallet validation:

    cargo test -p wallet multisig
    running 5 tests
    test result: ok. 5 passed; 0 failed; 101 filtered out

Focused walletd validation blocker:

    cargo test -p walletd multisig
    error: No space left on device (os error 28)

## Interfaces and Dependencies

In `wallet/src/multisig.rs`, define:

    pub struct MultisigAccountPublic
    pub struct MultisigAccountRecord
    pub struct MultisigSpendIntent
    pub struct MultisigApprovalPackage
    pub struct MultisigFinalSpendPackage
    pub fn signer_commitment_from_spend_key(spend_key: &[u8; 32]) -> [u8; 48]
    pub fn intent_digest(intent: &MultisigSpendIntent) -> Result<[u8; 48], WalletError>
    pub fn create_account_record(...)
    pub fn create_approval(...) -> missing-circuit error until circuit integration exists
    pub fn create_final_spend_package(...) -> missing-circuit error until circuit integration exists

The walletd methods are:

    multisig.accountCreate
    multisig.accountList
    multisig.approvalCreate
    multisig.approvalImport
    multisig.finalize

These methods are local wallet orchestration APIs. Only account creation/listing is active in this branch. Approval creation/import/finalization refuse to proceed until the real approval-step and final-spend circuit transaction hooks exist.
