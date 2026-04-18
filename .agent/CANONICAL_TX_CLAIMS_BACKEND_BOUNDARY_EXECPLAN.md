# Canonical Tx Claims Above Backend Adapters

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, the generic node and consensus layers stop treating proof-carrying tx artifacts as the main proof object. The product-facing object becomes one canonical transaction-validity claim: a transaction-validity receipt paired with the canonical statement binding that consensus already needs. Backend-specific proof envelopes remain available, but they are confined to verifier/build helpers and compatibility payload translators instead of leaking through the main service and block-verification flow.

The user-visible result is architectural, but still observable. The existing route-focused node tests continue to pass, and the block-verification tests that previously threaded backend tx artifacts through the generic `Block` model now pass while carrying `tx_validity_claims` in the block object and passing raw tx artifacts through explicit backend-input helpers instead. The explicit `ReceiptRoot` compatibility lane still works, but only translation helpers should touch its raw receipt list.

## Progress

- [x] (2026-04-17 22:53Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, and `METHODS.md`, then traced the live receipt/artifact flow through `consensus/src/types.rs`, `consensus/src/proof.rs`, `node/src/substrate/service.rs`, and `node/src/substrate/prover_coordinator.rs`.
- [x] Introduce one canonical `TxValidityClaim` object in `consensus::types` and migrate the generic block model to carry claims instead of separate statement-binding lists.
- [x] Refactor consensus proof helpers so generic verification logic consumes claims, while backend-specific tx artifacts stay confined to verifier/build helpers.
- [x] Refactor node service and receipt-root translation helpers so they derive and transport claims, and only decode/build compatibility payloads at dedicated boundaries.
- [x] Update docs and focused tests so the new claim boundary is explicit and verified.

## Surprises & Discoveries

- Observation: the generic block model already had two parallel proof-adjacent views of the same transaction set: `tx_validity_artifacts` and `tx_statement_bindings`.
  Evidence: `consensus/src/types.rs` currently defines both fields on `Block<BH>`, and `consensus/src/proof.rs` reconstructs commitments from bindings while separately checking receipt-root receipts against artifacts.

- Observation: the clean boundary is one layer lower than the first draft assumed. It is not enough to rename bindings to claims while leaving backend tx artifacts on `Block<BH>`; the generic block model itself has to stop carrying those artifacts.
  Evidence: once `ParallelProofVerifier` was claim-based, the last remaining cross-layer leak was `block.tx_validity_artifacts`, so the final cut introduced explicit `BlockBackendInputs` on the verifier edge and removed tx-artifact storage from `consensus::types::Block`.

- Observation: service-level receipt-root builders still depend on `TxValidityArtifact` for two different reasons that should be separated: native backend proof bytes and canonical receipt transport.
  Evidence: `node/src/substrate/service.rs` uses `consensus::TxValidityArtifact` both to build native receipt-root artifacts and to populate `ReceiptRootProofPayload.receipts`.

- Observation: the existing canonical shape already exists in the repo under a different name in the experimental backend crates.
  Evidence: `circuits/superneo-hegemon/src/lib.rs` defines `CanonicalTxValidityReceipt`, while consensus currently redefines the same four-field receipt in `consensus/src/types.rs`.

## Decision Log

- Decision: keep the on-wire pallet `ReceiptRootProofPayload` schema unchanged for this slice.
  Rationale: the goal is to move raw receipt lists and compatibility payload handling deeper into translation helpers, not to trigger a storage or schema migration in the same change.
  Date/Author: 2026-04-17 / Codex

- Decision: introduce `TxValidityClaim` in `consensus::types` rather than inventing a new crate immediately.
  Rationale: the immediate leak is in consensus/node/service code. A later dedicated proof-interface crate may still make sense, but this slice should first prove the claim object works and removes the current duplication.
  Date/Author: 2026-04-17 / Codex

- Decision: keep backend-specific `TxValidityArtifact` values available to verifier/build helpers during this slice, but treat them as backend input material, not as the canonical generic proof object.
  Rationale: recursive-block and native receipt-root builders still require exact tx-leaf proof bytes. Forcing a deeper backend rewrite in the same patch would hide the architectural cleanup under too much churn.
  Date/Author: 2026-04-17 / Codex

- Decision: remove backend tx artifacts from `consensus::types::Block` entirely and pass them through explicit `BlockBackendInputs` at verifier/build call sites.
  Rationale: the user requirement was “canonical tx claims/receipts the only cross-layer proof object above backend adapters.” Leaving tx artifacts on `Block<BH>` would have preserved the leak. `BlockBackendInputs` keeps the backend seam explicit without perturbing the on-wire payloads or the higher-level consensus models.
  Date/Author: 2026-04-17 / Codex

## Outcomes & Retrospective

The migration landed cleanly. `consensus::types::Block` now carries canonical `tx_validity_claims` and no longer carries backend tx artifacts. `consensus::proof` owns claim derivation plus the new `BlockBackendInputs` seam, so `ParallelProofVerifier` consumes claims for generic logic and sees raw tx artifacts only through that explicit backend-input argument. `node/src/substrate/service.rs` now constructs generic blocks with claims only and passes tx artifacts to verification through `BlockBackendInputs`. The explicit `ReceiptRoot` lane remains available, but its raw receipt list is now handled only inside dedicated translation/build helpers and compatibility payloads rather than as a generic service-layer proof object.

## Context and Orientation

There are four files that define the current leak.

`consensus/src/types.rs` defines the generic in-memory `Block<BH>` model used by proof verification. The final shape now carries `tx_validity_claims` and no backend tx artifacts. A transaction-validity claim in this repository means one canonical transaction-validity receipt (statement hash, proof digest, public-input digest, verifier-profile digest) paired with the canonical transaction statement binding (statement hash, anchor, fee, circuit version). The statement binding is the public statement context consensus needs to build `tx_statements_commitment`; the receipt is the proof-facing statement digest that receipt-root and native leaf verification already consume.

`consensus/src/proof.rs` is the main verification layer. It now owns claim derivation helpers and claim-based verification logic, and it exposes `BlockBackendInputs` as the explicit backend seam for raw tx artifacts.

`node/src/substrate/service.rs` is the main authoring/import bridge. It extracts transactions and tx-validity artifacts from extrinsics, derives claims and statement bindings, builds receipt-root and recursive block payloads, constructs the generic `consensus::types::Block` with claims only, and passes raw tx artifacts into the verifier through `BlockBackendInputs`.

`node/src/substrate/prover_coordinator.rs` owns prepared bundles keyed by route identity. It does not need to understand backend-specific proof internals, but its tests currently build receipt-root payloads directly with raw receipt lists. Those tests should move to the same claim-oriented helper vocabulary as the service.

In scope for this slice:

- add a canonical claim type to `consensus::types`
- move the generic `Block<BH>` model from separate binding/artifact views to canonical `tx_validity_claims`
- add claim derivation helpers to `consensus::proof`
- update service and node tests to use claims in the generic path
- confine direct `ReceiptRootProofPayload.receipts` handling to dedicated translation/build helpers

Out of scope for this slice:

- storage migrations or pallet schema changes
- replacing `TxValidityArtifact` inside backend build functions
- deleting the explicit `ReceiptRoot` compatibility lane
- creating a brand new shared crate for proof interfaces

## Plan of Work

The first step is to define `TxValidityClaim` in `consensus/src/types.rs`. This struct contains exactly two fields: `receipt: TxValidityReceipt` and `binding: TxStatementBinding`. Then update `Block<BH>` so the generic block model carries `tx_validity_claims` and no backend tx artifacts.

The second step is to make `consensus/src/proof.rs` the owner of claim derivation. Replace the current `verify_tx_validity_artifacts -> Vec<TxStatementBinding>` flow with a claim-oriented helper, for example `tx_validity_claims_from_tx_artifacts`, that verifies each tx artifact and returns the matching canonical claim. Add helper functions to derive receipts or bindings from claims and to compute statement commitments from claims. Then update `ParallelProofVerifier` so the generic logic uses claims rather than a raw binding list and sees raw tx artifacts only through `BlockBackendInputs`. On the self-contained aggregation path, it should require `block.tx_validity_claims`, validate the count, validate that each claim’s receipt statement hash matches the binding statement hash, compute the expected `tx_statements_commitment` from claims, and compare receipt-root payload receipts against the receipt view of the claims rather than against raw artifact receipts.

The third step is to move service code to claims. In `node/src/substrate/service.rs`, keep `CandidateBlockContext` deriving `tx_validity_claims: Option<Vec<consensus::TxValidityClaim>>` alongside backend tx artifacts, but construct the generic `consensus::types::Block` with claims only. Where the service currently derives `statement_bindings` from artifacts, derive claims first and obtain bindings from claims when needed. Add explicit translation helpers such as `consensus_receipt_root_payload_from_pallet` and the pallet receipt-root payload builders so the raw `ReceiptRootProofPayload.receipts` list is only touched in those helpers. The prove-ahead native receipt-root builders may still take `&[consensus::TxValidityArtifact]` because they need backend proof bytes, but the generic path should stop carrying artifacts when claims suffice.

The fourth step is to push compatibility lanes deeper into decode-only modules. In practice that means reducing open-coded `receipt_root.receipts` manipulation in service and tests. `node/src/substrate/prover_coordinator.rs` tests and `node/src/substrate/service.rs` tests should use claim-oriented helpers to assemble receipt-root payloads instead of building raw receipt vectors in-line. Similarly, the RPC/prover translation should continue to expose route identity and artifact hashes, not receipt payload structure.

The fifth step is to update the docs. `DESIGN.md` and `METHODS.md` should explicitly say that canonical tx claims/receipts are now the only generic cross-layer proof object above backend adapters, while backend-specific tx artifacts remain confined to verifier/build helpers. The docs should also say that the explicit `ReceiptRoot` lane still exists, but its raw receipt list is now a decode/build detail rather than a generic service-layer concept.

## Concrete Steps

All commands below run from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Start with the focused compile after the type migration:

    cargo check -p consensus -p hegemon-node

Then run the claim-focused consensus tests:

    cargo test -p consensus self_contained_mode_rejects_missing_tx_validity_claims_before_proven_batch -- --ignored --nocapture
    cargo test -p consensus self_contained_mode_rejects_claim_statement_hash_tampering -- --ignored --nocapture

Run the node-facing claim/route tests:

    cargo test -p hegemon-node map_artifact_announcement_supports_recursive_block -- --nocapture
    cargo test -p hegemon-node recursive_block_mode_is_selected_from_env -- --nocapture
    cargo test -p hegemon-node substrate::prover_coordinator::tests::prepared_lookup_requires_exact_proof_identity -- --exact --nocapture

Run a final diff hygiene check:

    git diff --check -- \
      consensus/src/types.rs \
      consensus/src/proof.rs \
      consensus/src/lib.rs \
      node/src/substrate/service.rs \
      node/src/substrate/prover_coordinator.rs \
      node/src/codec.rs \
      node/src/test_utils.rs \
      consensus/tests/common.rs \
      consensus/tests/self_contained_mode.rs \
      consensus/tests/raw_active_mode.rs \
      consensus/tests/parallel_verification.rs \
      DESIGN.md \
      METHODS.md \
      .agent/CANONICAL_TX_CLAIMS_BACKEND_BOUNDARY_EXECPLAN.md

Expected observable results include:

    test self_contained_mode_rejects_missing_tx_validity_claims_before_proven_batch ... ok
    test substrate::rpc::prover::tests::map_artifact_announcement_supports_recursive_block ... ok

## Validation and Acceptance

Acceptance is behavior.

The first acceptance condition is that generic block verification now requires claims, not separate binding lists. A self-contained aggregation block with tx artifacts but no `tx_validity_claims` must fail with a claim-specific error before the proven-batch lane logic runs.

The second acceptance condition is receipt-root claim fidelity. If a receipt-root payload carries a receipt list that no longer matches the canonical claims on the block, verification must fail cleanly. A tampered claim whose receipt statement hash no longer matches its binding statement hash must also fail cleanly.

The third acceptance condition is that shipped node behavior is unchanged where it should be unchanged. The route-focused node tests (`map_artifact_announcement_supports_recursive_block`, `recursive_block_mode_is_selected_from_env`, and the prepared-bundle exact-identity tests) must still pass after the claim migration.

The fourth acceptance condition is code-shape evidence. `node/src/substrate/service.rs` must no longer open-code receipt-field copying or receipt-root payload receipt assembly in the generic path; those operations should be isolated to named helper functions.

## Idempotence and Recovery

This migration is safe to stage incrementally because the block and service models are in-memory only. There is no on-chain migration and no database rewrite. If the work stops halfway and the tree does not compile, the safest recovery path is:

1. keep `TxValidityClaim` in `consensus::types`
2. finish replacing `tx_statement_bindings` with `tx_validity_claims` in `consensus::types::Block`
3. update all `Block { ... }` constructors to set the new field
4. rerun `cargo check -p consensus -p hegemon-node`

Do not try to partly revert only one side of the `Block` change; that creates the most confusing compiler state.

## Artifacts and Notes

The key evidence that this change is worthwhile is already present in the repo:

    node/src/substrate/service.rs currently carries both backend tx artifacts
    and a separate claim/binding view inside `CandidateBlockContext`, because
    the service still has to build backend artifacts while generic blocks must not.

    consensus/src/proof.rs now compares receipt-root payload receipts
    against the receipt view derived from canonical claims while receiving
    raw tx artifacts only through `BlockBackendInputs`.

That duplication is exactly what this plan removes.

## Interfaces and Dependencies

In `consensus/src/types.rs`, define:

    pub struct TxValidityClaim {
        pub receipt: TxValidityReceipt,
        pub binding: TxStatementBinding,
    }

and update:

    pub struct Block<BH> {
        ...
        pub block_artifact: Option<ProofEnvelope>,
        pub tx_validity_claims: Option<Vec<TxValidityClaim>>,
        pub tx_statements_commitment: Option<[u8; 48]>,
        ...
    }

    pub struct BlockBackendInputs {
        pub tx_validity_artifacts: Option<Vec<TxValidityArtifact>>,
    }

In `consensus/src/proof.rs`, add and keep helpers with stable names:

    pub fn tx_validity_claims_from_tx_artifacts(
        transactions: &[crate::types::Transaction],
        artifacts: &[TxValidityArtifact],
    ) -> Result<Vec<TxValidityClaim>, ProofError>;

    pub fn tx_validity_receipts_from_claims(
        claims: &[TxValidityClaim],
    ) -> Vec<TxValidityReceipt>;

    pub fn tx_statement_bindings_from_claims(
        claims: &[TxValidityClaim],
    ) -> Vec<TxStatementBinding>;

and update `ParallelProofVerifier::verify_block` to consume claims for the generic proof-facing logic.

In `node/src/substrate/service.rs`, keep explicit boundary helpers for conversion. The exact final names may differ, but the service must expose one helper that builds a pallet receipt-root payload from canonical claims plus built artifact bytes, and one helper that converts a pallet receipt-root payload back into a consensus-facing payload/claim view without in-line receipt-field copying in the call site.

Revision note: created this plan on 2026-04-17 after the route-identity cleanup landed. The new plan is separate because the next slice changes the generic proof object carried by the block/service layers rather than only the route abstraction.
