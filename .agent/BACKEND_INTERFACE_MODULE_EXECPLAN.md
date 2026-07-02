# Consensus Backend Interface Module

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

The proof-stack cleanup is not finished while `node` and `consensus` still import `block_recursion`, `superneo_hegemon`, `block_circuit`, and `transaction_circuit::proof` directly all over the tree. That makes a future backend swap expensive because product code still reaches into backend crates instead of one explicit seam.

This slice introduces a real `consensus::backend_interface` module. After it lands, `node` and `consensus` modules will import backend proof helpers only through that façade. The backends still exist, but they stop leaking through arbitrary service, RPC, pool, and verifier files.

## Progress

- [x] (2026-04-17 20:30Z) Add `consensus::backend_interface` and move backend proof imports behind it.
- [x] (2026-04-17 20:47Z) Route `consensus` production modules through the backend interface.
- [x] (2026-04-17 21:01Z) Route `node` production modules through the backend interface.
- [x] (2026-04-17 21:18Z) Update focused tests/docs and validate the slice.

## Surprises & Discoveries

- Observation: the dependency graph does not justify a new crate yet.
  Evidence: `consensus` already owns the generic block model and node-facing proof API. A new crate depending on `consensus` would cycle, while moving all consensus proof types out today would explode the scope. A module cut inside `consensus` gives the same boundary without destabilizing the workspace.

- Observation: the seam needed one consensus-owned export, not just backend re-exports.
  Evidence: `node/src/substrate/receipt_root_builder.rs` depends on `build_experimental_native_receipt_root_artifact`, which is implemented in `consensus/src/proof.rs`, not in a backend crate. Re-exporting it from `consensus::backend_interface` kept the node boundary clean without moving builder logic into a new crate.

- Observation: the remaining leaks after the first pass were mostly path expressions, not `use` lines.
  Evidence: `rg -n "(block_circuit|block_recursion|superneo_hegemon|transaction_circuit::proof)" consensus/src node/src -g'*.rs'` initially still found direct references in `consensus/src/proof.rs`, `node/src/substrate/service.rs`, and `node/src/substrate/rpc/production_service.rs` even after the top-level imports were routed.

## Decision Log

- Decision: implement the backend seam as `consensus::backend_interface`, not a new workspace crate.
  Rationale: this is the smallest cut that still enforces a single import surface for proof backends across `consensus` and `node`.
  Date/Author: 2026-04-17 / Codex

- Decision: let `consensus::backend_interface` re-export the one consensus-owned native receipt-root builder helper.
  Rationale: the module’s job is to be the only proof-boundary import surface above the backend adapters. For this slice, preserving that import discipline mattered more than keeping the module limited to third-party/backend crates only.
  Date/Author: 2026-04-17 / Codex

## Outcomes & Retrospective

The slice is complete. `consensus::backend_interface` is now the single direct import site for backend proof helpers in mainline `consensus` and `node` code. The important product files now import recursive-block, tx-leaf, receipt-root, and transaction-proof helper types/functions only through that façade. Generic `consensus` and `node` logic no longer reach into `block_recursion`, `block_circuit`, `superneo_hegemon`, or `transaction_circuit::proof` directly.

Focused validation is green:

    cargo check -p consensus -p hegemon-node
    cargo test -p consensus self_contained_mode_rejects_missing_tx_validity_artifacts_before_proven_batch -- --nocapture
    cargo test -p hegemon-node map_artifact_announcement_supports_recursive_block -- --nocapture
    cargo test -p hegemon-node require_native_block_proof_accepts_recursive_block_payload -- --nocapture
    cargo test -p hegemon-node receipt_root_work_plan_splits_into_mini_roots -- --nocapture
    cargo test -p hegemon-node substrate::prover_coordinator::tests::prepared_lookup_requires_exact_proof_identity -- --exact --nocapture
    git diff --check -- consensus/src/backend_interface.rs consensus/src/lib.rs consensus/src/proof.rs consensus/src/types.rs consensus/src/aggregation.rs consensus/src/aggregation/v5.rs node/src/transaction.rs node/src/substrate/service.rs node/src/substrate/transaction_pool.rs node/src/substrate/rpc/da.rs node/src/substrate/rpc/production_service.rs node/src/substrate/rpc/block.rs node/src/substrate/receipt_root_builder.rs DESIGN.md METHODS.md .agent/BACKEND_INTERFACE_MODULE_EXECPLAN.md

The next architecture step is a different slice: move more backend-neutral semantics and builder/verifier contracts out of `consensus::proof` into a slimmer stable interface. That is outside this ExecPlan.

## Context and Orientation

Today the repo has three layers:

- generic product logic in `consensus` and `node`
- backend-specific proof helpers in `block_recursion`, `block_circuit`, `superneo_hegemon`, and `transaction_circuit::proof`
- several partial node-side boundary modules already extracted from `service.rs`

The problem is that the middle layer still leaks upward. `consensus/src/proof.rs` imports backend crates directly. `node/src/substrate/service.rs`, `node/src/substrate/transaction_pool.rs`, `node/src/substrate/rpc/da.rs`, `node/src/substrate/rpc/production_service.rs`, and `node/src/transaction.rs` also import backend proof helpers directly. That means a backend swap still requires touching many product-facing files.

The goal of this slice is simple: one module, `consensus/src/backend_interface.rs`, becomes the only direct import site for backend proof helpers in the mainline `consensus` and `node` code. Product code then imports that module instead of reaching into backend crates itself.

## Plan of Work

First, add `consensus/src/backend_interface.rs`. This module will be a façade: it will re-export and lightly wrap the backend proof types and functions that product code already uses. It must include the commitment-proof types, recursive-block builder/verifier types, native tx-leaf decode/verify helpers, receipt-root builder helpers, and transaction-proof types/functions that currently leak upward.

Second, wire `consensus` through that façade. `consensus/src/proof.rs` and `consensus/src/types.rs` must stop importing backend crates directly. They should import from `crate::backend_interface` instead. This does not change behavior; it changes ownership of backend imports.

Third, wire `node` through that façade. `node/src/substrate/service.rs`, `node/src/substrate/transaction_pool.rs`, `node/src/substrate/rpc/da.rs`, `node/src/substrate/rpc/production_service.rs`, `node/src/substrate/rpc/block.rs`, and `node/src/transaction.rs` should import backend proof helpers only from `consensus::backend_interface` or from existing consensus APIs. The node may still import non-proof transaction semantics from `transaction_circuit` where needed, but proof backends must stop leaking in directly.

Fourth, update the tests that import proof helpers directly if they are in `consensus` or `node` and are easy to reroute through the façade. The purpose is to keep the main crates honest: if the tests need direct proof imports, that should be intentional and narrow.

## Concrete Steps

Run from `/Users/pldd/Projects/Reflexivity/Hegemon`:

    cargo check -p consensus -p hegemon-node
    cargo test -p hegemon-node map_artifact_announcement_supports_recursive_block -- --nocapture
    cargo test -p hegemon-node receipt_root_work_plan_splits_into_mini_roots -- --nocapture
    cargo test -p hegemon-node require_native_block_proof_accepts_recursive_block_payload -- --nocapture
    cargo test -p consensus self_contained_mode_rejects_missing_tx_validity_artifacts_before_proven_batch -- --nocapture

Then run:

    git diff --check -- \
      consensus/src/backend_interface.rs \
      consensus/src/lib.rs \
      consensus/src/proof.rs \
      consensus/src/types.rs \
      node/src/transaction.rs \
      node/src/substrate/service.rs \
      node/src/substrate/transaction_pool.rs \
      node/src/substrate/rpc/da.rs \
      node/src/substrate/rpc/production_service.rs \
      node/src/substrate/rpc/block.rs \
      DESIGN.md \
      METHODS.md \
      .agent/BACKEND_INTERFACE_MODULE_EXECPLAN.md

## Validation and Acceptance

Acceptance is architectural and behavioral.

The first acceptance condition is that the mainline `consensus` and `node` modules named above no longer import backend proof helpers directly from backend crates.

The second acceptance condition is that the focused node tests for shipped and alternate proof lanes still pass unchanged.

The third acceptance condition is that `consensus::backend_interface` is the only direct import site for backend proof helpers in those production modules, making the backend seam explicit and swappable.
