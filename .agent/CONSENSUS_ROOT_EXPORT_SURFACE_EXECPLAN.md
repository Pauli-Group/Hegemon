# Consensus Crate-Root Proof Surface Reduction

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

The proof stack is cleaner after the `backend_interface` and `proof_interface` splits, but in-repo callers can still dodge that architecture by importing proof APIs from the `consensus` crate root. That keeps `consensus::lib` acting like a grab bag of proof exports and weakens the boundary the previous refactors established.

This slice makes callers use the real modules. After it lands, in-repo code will import backend helpers from `consensus::backend_interface`, generic proof contracts from `consensus::proof_interface`, and implementation-specific proof helpers from `consensus::proof`. Then `consensus/src/lib.rs` will stop broadly re-exporting proof APIs at the crate root.

## Progress

- [x] (2026-04-17 22:01Z) Audit the proof-related root re-exports in `consensus/src/lib.rs` and enumerate in-repo callers still using them.
- [x] (2026-04-17 22:01Z) Reroute node and consensus callers to `proof_interface`, `backend_interface`, or `proof` explicitly.
- [x] (2026-04-17 22:01Z) Trim the proof-related crate-root re-export surface in `consensus/src/lib.rs`.
- [x] (2026-04-17 22:01Z) Update docs and validate the slice with compile/tests plus structural searches.

## Surprises & Discoveries

- Observation: most remaining root-dependent callers are node-side orchestration helpers, not core consensus logic.
  Evidence: `rg -n "consensus::(experimental_|tx_validity_|tx_statement_bindings_from_claims|BlockBackendInputs|ProofVerifier|ParallelProofVerifier|recursive_block_artifact_verifier_profile|commitment_nullifier_lists)" node/src consensus/src -g'*.rs'` points mainly at `node/src/substrate/service.rs`, `node/src/substrate/proof_boundary.rs`, `node/src/substrate/receipt_root_builder.rs`, and related substrate helper modules.
- Observation: after the reroute, the hard cut in `consensus/src/lib.rs` landed cleanly. The only compile fallout was a few test-only imports left in production import lists.
  Evidence: `cargo check -p consensus -p hegemon-node` stayed green after removing the `pub use proof::{...}` and `pub use proof_interface::{...}` blocks, with only unused-import warnings in `node/src/substrate/service.rs` and `node/src/substrate/receipt_root_builder.rs`.

## Decision Log

- Decision: remove proof-related root re-exports for internal architecture enforcement, not just deprecate them in comments.
  Rationale: if the root exports remain, internal code will keep using them because they are shorter. The point of this slice is to make the module structure operationally real.
  Date/Author: 2026-04-17 / Codex

## Outcomes & Retrospective

The root proof namespace is no longer the default API surface for in-repo code. `consensus/src/lib.rs` no longer re-exports the broad proof helper surface from `proof` and `proof_interface`, and the rerouted callers now import `consensus::proof`, `consensus::proof_interface`, or `consensus::backend_interface` directly. That makes the backend boundary operationally real: module ownership is now visible from imports instead of being bypassed through crate-root shortcuts.

## Context and Orientation

The `consensus` crate now has three relevant proof layers:

- `consensus/src/backend_interface.rs`: the only place allowed to import backend proof crates directly
- `consensus/src/proof_interface.rs`: stable backend-neutral proof traits, carriers, and receipt-root interface helpers
- `consensus/src/proof.rs`: concrete verifier implementation and implementation-specific helpers

The remaining problem is `consensus/src/lib.rs`. It still re-exports many proof items from `proof_interface` and `proof`, so callers can write `consensus::ProofVerifier`, `consensus::experimental_native_tx_leaf_verifier_profile()`, or `consensus::tx_validity_artifact_from_proof(...)` without using the modules that now own those APIs.

The goal of this slice is to make the ownership explicit in actual call sites and then shrink the root exports so that new code follows the architecture by default.

## Plan of Work

First, reroute the in-repo callers. Node-side files such as `node/src/substrate/service.rs`, `node/src/substrate/proof_boundary.rs`, `node/src/substrate/receipt_root_builder.rs`, `node/src/substrate/receipt_root_compat.rs`, and `node/src/substrate/artifact_market.rs` should import proof APIs from `consensus::proof_interface`, `consensus::backend_interface`, or `consensus::proof` directly instead of calling through `consensus::...`. Where they still need implementation types like `ParallelProofVerifier`, they should import `consensus::proof::ParallelProofVerifier`.

Second, update any consensus internal callers still reaching through the root. `consensus/src/pow.rs`, `consensus/src/bft.rs`, and `consensus/src/substrate.rs` should keep using `proof_interface` or `proof` explicitly.

Third, trim `consensus/src/lib.rs`. Remove the broad proof-related `pub use` items that are now module-owned. Keep only the non-proof crate-root exports that are still part of the stable public product surface for this repo. The intent is not to make the root empty; it is to stop using it as the default proof namespace.

## Concrete Steps

Run from `/Users/pldd/Projects/Reflexivity/Hegemon`:

    cargo check -p consensus -p hegemon-node
    cargo test -p consensus self_contained_mode_rejects_missing_tx_validity_artifacts_before_proven_batch -- --nocapture
    cargo test -p hegemon-node map_artifact_announcement_supports_recursive_block -- --nocapture
    cargo test -p hegemon-node require_native_block_proof_accepts_recursive_block_payload -- --nocapture
    cargo test -p hegemon-node receipt_root_work_plan_splits_into_mini_roots -- --nocapture
    cargo test -p hegemon-node substrate::prover_coordinator::tests::prepared_lookup_requires_exact_proof_identity -- --exact --nocapture

Then run structural searches:

    rg -n "consensus::(ParallelProofVerifier|ProofVerifier|BlockBackendInputs|ExperimentalReceiptRootArtifact|experimental_native_receipt_root_params_fingerprint|experimental_native_receipt_root_verifier_profile|experimental_native_tx_leaf_verifier_profile|experimental_receipt_root_verifier_profile|experimental_tx_leaf_verifier_profile|tx_statement_bindings_from_claims|tx_validity_receipts_from_claims|tx_validity_artifact_from_native_tx_leaf_bytes|tx_validity_artifact_from_proof|tx_validity_artifact_from_receipt|tx_validity_artifact_from_tx_leaf_proof|tx_validity_claims_from_tx_artifacts|tx_validity_receipt_from_proof|verify_commitment_proof_payload|recursive_block_artifact_verifier_profile|commitment_nullifier_lists)\\b" node/src consensus/src -g'*.rs'

The remaining matches, if any, must be intentional and documented in this plan.

Finally run:

    git diff --check -- \
      consensus/src/lib.rs \
      consensus/src/proof.rs \
      consensus/src/proof_interface.rs \
      consensus/src/backend_interface.rs \
      consensus/src/pow.rs \
      consensus/src/bft.rs \
      consensus/src/substrate.rs \
      node/src/substrate/proof_boundary.rs \
      node/src/substrate/service.rs \
      node/src/substrate/receipt_root_builder.rs \
      node/src/substrate/receipt_root_compat.rs \
      node/src/substrate/artifact_market.rs \
      DESIGN.md \
      METHODS.md \
      .agent/CONSENSUS_ROOT_EXPORT_SURFACE_EXECPLAN.md

## Validation and Acceptance

Acceptance is structural and behavioral.

Structurally, in-repo proof callers should use the owning module, not `consensus::...`, for proof-related APIs. `consensus/src/lib.rs` should no longer re-export the broad proof surface that these callers used before.

Behaviorally, the focused `consensus` and `hegemon-node` tests above must continue to pass unchanged.

Architecturally, the proof ownership should read clearly from imports alone:

- `backend_interface` for backend helpers
- `proof_interface` for generic proof contracts
- `proof` for implementation-specific verifier machinery
