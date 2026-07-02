# Consensus Proof Interface Layer

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

The previous slice introduced `consensus::backend_interface` so `node` and `consensus` stop reaching into backend crates directly. One impurity remains: some stable, backend-neutral proof APIs still live in `consensus::proof`, and `backend_interface` currently re-exports one consensus-owned receipt-root builder only because `node` needs it.

This slice introduces a narrower proof-interface layer owned by `consensus`. After it lands, generic traits, generic backend-input carriers, and stable receipt-root interface helpers will live outside `consensus::proof`. `backend_interface` will go back to being a pure backend façade, while `proof.rs` becomes implementation instead of the place generic interfaces have to live.

## Progress

- [x] (2026-04-17 21:33Z) Create `consensus::proof_interface` and move the stable generic proof interfaces into it.
- [x] (2026-04-17 21:39Z) Move the consensus-owned receipt-root interface helpers out of `consensus::proof` so `backend_interface` no longer re-exports them.
- [x] (2026-04-17 21:45Z) Route `consensus` and `node` imports through the new interface layer.
- [x] (2026-04-17 21:56Z) Update docs and validate the slice with focused compile/tests.

## Surprises & Discoveries

- Observation: `backend_interface` only became “impure” because one consensus-owned native receipt-root builder lived in `consensus::proof`.
  Evidence: `consensus/src/backend_interface.rs` currently re-exports `crate::proof::build_experimental_native_receipt_root_artifact` solely so `node/src/substrate/receipt_root_builder.rs` can stay off `consensus::proof`.

- Observation: the true stable boundary was slightly larger than one builder helper.
  Evidence: once `build_experimental_native_receipt_root_artifact` moved, the same generic module also wanted `ExperimentalReceiptRootArtifact`, `ProofVerifier`, `HeaderProofExt`, `BlockBackendInputs`, and `verify_commitments`; leaving those behind would have preserved the same architectural smell in a smaller form.

- Observation: `consensus::proof` still needed one shared canonical-receipt conversion helper after the move.
  Evidence: the concrete verifier implementation uses `canonical_receipt_from_tx_receipt` in tx-artifact verification. Making that helper `pub(crate)` inside `proof_interface.rs` avoided duplicating receipt canonicalization logic.

## Decision Log

- Decision: create a new module inside `consensus`, not another crate.
  Rationale: these interfaces depend on `consensus` types (`Block`, `TxValidityArtifact`, `ProofError`, `CommitmentTreeState`) and are meant to be stable within the crate boundary. A new crate would either cycle or force a much wider move.
  Date/Author: 2026-04-17 / Codex

- Decision: move `verify_commitments` into `proof_interface` along with the traits.
  Rationale: `verify_commitments` is backend-neutral block/header interface logic. Keeping it in `proof.rs` would force consensus callers (`pow`, `bft`) to keep importing the implementation module just to get a generic contract check.
  Date/Author: 2026-04-17 / Codex

- Decision: keep `tx_validity_claims_from_tx_artifacts` in `proof.rs`.
  Rationale: that helper still depends on `VerifierRegistry` and the concrete verifier implementation path, so it is not yet a stable interface-layer function.
  Date/Author: 2026-04-17 / Codex

## Outcomes & Retrospective

The slice is complete. `consensus/src/proof_interface.rs` now owns the stable generic proof contracts:

- `ProofVerifier`
- `HeaderProofExt`
- `BlockBackendInputs`
- `ExperimentalReceiptRootArtifact`
- stable receipt-root build/verify helpers
- backend-neutral claim/binding helpers
- `verify_commitments`

`consensus/src/proof.rs` now imports those interfaces instead of defining them, and `consensus/src/backend_interface.rs` is back to being a pure backend façade. The node-side receipt-root builder imports the consensus-owned builder from `consensus::proof_interface`, not from `backend_interface`.

Focused validation is green:

    cargo check -p consensus -p hegemon-node
    cargo test -p consensus self_contained_mode_rejects_missing_tx_validity_artifacts_before_proven_batch -- --nocapture
    cargo test -p hegemon-node map_artifact_announcement_supports_recursive_block -- --nocapture
    cargo test -p hegemon-node require_native_block_proof_accepts_recursive_block_payload -- --nocapture
    cargo test -p hegemon-node receipt_root_work_plan_splits_into_mini_roots -- --nocapture
    cargo test -p hegemon-node substrate::prover_coordinator::tests::prepared_lookup_requires_exact_proof_identity -- --exact --nocapture
    rg -n "(block_circuit|block_recursion|superneo_hegemon|transaction_circuit::proof)" consensus/src node/src -g'*.rs'

The final `rg` result is the structural proof for this slice: the only remaining direct backend-proof imports in `consensus/src` and `node/src` are inside `consensus/src/backend_interface.rs`.

## Context and Orientation

Today there are three proof-related layers in `consensus`:

- `consensus/src/backend_interface.rs`: a façade over backend crates like `block_recursion`, `superneo_hegemon`, and `transaction_circuit::proof`
- `consensus/src/proof.rs`: verifier implementation plus several generic interfaces and helper builders
- `node/src/substrate/*`: orchestration code that should depend only on generic interfaces or the backend façade

The architectural smell is that `consensus::proof` still mixes two jobs:

- implementation details such as verifier registries and concrete verification flows
- stable interfaces such as `ProofVerifier`, `HeaderProofExt`, `BlockBackendInputs`, and the public receipt-root builder/verification helpers

The goal of this slice is to separate those. After the refactor:

- `backend_interface` contains only backend-facing adapters and wrappers
- `proof_interface` contains stable generic proof traits/types and stable receipt-root interface helpers
- `proof.rs` contains implementation logic and uses `proof_interface`, not the other way around

## Plan of Work

First, add `consensus/src/proof_interface.rs`. Move the generic proof traits and carriers there: `BlockBackendInputs`, `ProofVerifier`, and `HeaderProofExt`. Move the stable consensus-owned receipt-root interface type and helpers there as well: `ExperimentalReceiptRootArtifact`, the receipt-root build helpers, the receipt-root verify helpers, and the backend-neutral claim/binding helpers that do not require the caller to know about backend crates.

Second, update `consensus/src/proof.rs` so it imports these interfaces from `crate::proof_interface`. Keep verifier implementation, cache/state management, and registry logic in `proof.rs`. If a helper still depends on `VerifierRegistry` or internal verifier behavior, it stays in `proof.rs`.

Third, remove the consensus-owned re-export from `consensus/src/backend_interface.rs`. That module should expose backend helper types and functions only.

Fourth, reroute imports in `consensus` and `node` to the new interface module. The important call sites are `consensus/src/pow.rs`, `consensus/src/bft.rs`, `consensus/src/substrate.rs`, `node/src/substrate/proof_boundary.rs`, `node/src/substrate/service.rs`, and `node/src/substrate/receipt_root_builder.rs`.

## Concrete Steps

Run from `/Users/pldd/Projects/Reflexivity/Hegemon`:

    cargo check -p consensus -p hegemon-node
    cargo test -p consensus self_contained_mode_rejects_missing_tx_validity_artifacts_before_proven_batch -- --nocapture
    cargo test -p hegemon-node map_artifact_announcement_supports_recursive_block -- --nocapture
    cargo test -p hegemon-node require_native_block_proof_accepts_recursive_block_payload -- --nocapture
    cargo test -p hegemon-node receipt_root_work_plan_splits_into_mini_roots -- --nocapture
    cargo test -p hegemon-node substrate::prover_coordinator::tests::prepared_lookup_requires_exact_proof_identity -- --exact --nocapture

Then run:

    rg -n "(block_circuit|block_recursion|superneo_hegemon|transaction_circuit::proof)" consensus/src node/src -g'*.rs'

The only remaining matches should be inside `consensus/src/backend_interface.rs`.

Finally run:

    git diff --check -- \
      consensus/src/proof_interface.rs \
      consensus/src/backend_interface.rs \
      consensus/src/proof.rs \
      consensus/src/lib.rs \
      consensus/src/pow.rs \
      consensus/src/bft.rs \
      consensus/src/substrate.rs \
      node/src/substrate/proof_boundary.rs \
      node/src/substrate/service.rs \
      node/src/substrate/receipt_root_builder.rs \
      DESIGN.md \
      METHODS.md \
      .agent/PROOF_INTERFACE_LAYER_EXECPLAN.md

## Validation and Acceptance

Acceptance is both structural and behavioral.

Structurally, `consensus::backend_interface` must no longer re-export any consensus-owned helper from `consensus::proof`. The generic proof traits/types and stable receipt-root interface helpers must live in `consensus::proof_interface`.

Behaviorally, the focused `consensus` and `hegemon-node` tests above must continue to pass, proving the route/payload logic still works after the module split.

Architecturally, imports in `consensus` and `node` should show the intended layering:

- implementation code may import `crate::proof_interface`
- product code may import `consensus::proof_interface` and `consensus::backend_interface`
- only `consensus::backend_interface` may import backend proof crates directly
