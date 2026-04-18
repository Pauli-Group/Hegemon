# Node Proof Boundary and ReceiptRoot Compatibility Modules

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

The canonical-claims slice fixed the generic cross-layer object model, but `node/src/substrate/service.rs` still owns too much proof-boundary logic directly. The next cleanup is to pull two concerns out of that file:

1. generic proof-boundary helpers
2. explicit `ReceiptRoot` compatibility-lane helpers

After this change, `service.rs` should stop hand-owning receipt conversion, block-verifier backend-input wrapping, and the canonical `ReceiptRoot` payload gating logic. Those helpers should live in small dedicated modules so the future backend swap touches one boundary module instead of a 600kB service file.

## Progress

- [x] Create a node-side proof-boundary module that owns receipt conversion plus verifier backend-input wrapping.
- [x] Create a node-side `ReceiptRoot` compatibility module that owns canonical payload checks and receipt-root lane gating.
- [x] Route `node/src/substrate/service.rs` through those modules and remove the duplicated local helpers.
- [x] Update focused docs/tests and validate the slice.

## Surprises & Discoveries

- Observation: the claims cut removed backend tx artifacts from `consensus::types::Block`, but `service.rs` still owns the wrapper logic that turns tx artifacts into `BlockBackendInputs`.
  Evidence: the verification path in `node/src/substrate/service.rs` still constructs `BlockBackendInputs` inline before calling `verify_block_with_backend`.

- Observation: `ReceiptRoot` compatibility is already mostly centralized conceptually, but the helpers still live in `service.rs`, which keeps the compatibility lane looking like a first-class service concern.
  Evidence: `consensus_receipt_root_payload_from_pallet`, `ensure_experimental_receipt_root_payload`, `ensure_native_block_proof_payload`, and `receipt_root_lane_requires_embedded_proof_bytes` all currently live in `node/src/substrate/service.rs`.

## Decision Log

- Decision: do not create a new crate for this slice.
  Rationale: the immediate cleanup is local to node-side orchestration. Small `substrate` modules are enough to prove the boundary without paying the cost of another crate now.
  Date/Author: 2026-04-17 / Codex

- Decision: keep receipt-root build logic in `service.rs` for now, but move receipt conversion and compatibility gating out first.
  Rationale: the work-plan/cache/build structs are still tightly coupled to service-side prove-ahead orchestration. The lower-risk win is to extract the interface helpers first and leave the heavier worker/cache extraction for a later slice.
  Date/Author: 2026-04-17 / Codex

## Outcomes & Retrospective

The slice is complete.

`node/src/substrate/service.rs` no longer defines local helpers for:

- pallet `<->` consensus receipt conversion
- pallet receipt-root payload -> consensus receipt-root payload translation
- tx artifacts -> `(claims, bindings)` derivation
- backend-input wrapping for generic block verification
- canonical explicit `ReceiptRoot` payload checks
- `ReceiptRoot` lane embedded-proof-byte gating

Those concerns now live in:

- [node/src/substrate/proof_boundary.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/proof_boundary.rs)
- [node/src/substrate/receipt_root_compat.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/receipt_root_compat.rs)

That keeps service orchestration in `service.rs` while pushing the proof-boundary and compatibility-lane policy into small dedicated modules that can survive a future backend swap.

## Context and Orientation

`node/src/substrate/service.rs` is still doing three jobs at once:

- service orchestration
- proof-boundary translation
- compatibility-lane policy checks

The first one belongs there. The other two do not.

The claims cleanup already made `consensus::types::Block` claim-only on the generic path, and `consensus::proof` now exposes `BlockBackendInputs`. The node should consume that boundary through one helper module rather than reassembling it inline each time.

Likewise, the explicit `ReceiptRoot` lane is a compatibility/research route. The payload checks for that lane should live in a dedicated compatibility module so the shipped path reads like the shipped path and the alternate lane reads like an alternate lane.

## Plan of Work

First, add `node/src/substrate/proof_boundary.rs`. It should own:

- pallet `<->` consensus receipt conversion helpers
- pallet receipt-root payload -> consensus receipt-root payload conversion
- tx artifacts -> `(claims, bindings)` derivation helper
- tx artifacts -> `BlockBackendInputs` helper
- one verifier wrapper that calls `verify_block_with_backend`

Second, add `node/src/substrate/receipt_root_compat.rs`. It should own:

- `ReceiptRoot` canonical payload classification
- explicit `ReceiptRoot` payload acceptance checks
- native-block-proof payload checks that depend on the explicit alternate route
- receipt-root lane requirement that embedded proof bytes be present

Third, update `node/src/substrate/mod.rs` and `node/src/substrate/service.rs` to use the new modules and remove the duplicated local helper definitions.

Fourth, update `DESIGN.md` / `METHODS.md` only if the wording still implies that `service.rs` itself owns the compatibility and proof-boundary logic.

## Concrete Steps

Run from `/Users/pldd/Projects/Reflexivity/Hegemon`:

    cargo check -p hegemon-node -p consensus
    cargo test -p hegemon-node map_artifact_announcement_supports_recursive_block -- --nocapture
    cargo test -p hegemon-node recursive_block_mode_is_selected_from_env -- --nocapture
    cargo test -p hegemon-node substrate::prover_coordinator::tests::prepared_lookup_requires_exact_proof_identity -- --exact --nocapture

Then run:

    git diff --check -- \
      node/src/substrate/mod.rs \
      node/src/substrate/service.rs \
      node/src/substrate/proof_boundary.rs \
      node/src/substrate/receipt_root_compat.rs \
      DESIGN.md \
      METHODS.md \
      .agent/NODE_PROOF_BOUNDARY_COMPAT_MODULE_EXECPLAN.md

## Validation and Acceptance

Acceptance is behavior and shape.

The first acceptance condition is that `service.rs` no longer defines receipt conversion or canonical `ReceiptRoot` payload-check helpers locally.

The second acceptance condition is that the existing route-focused node tests still pass unchanged.

The third acceptance condition is that the new modules are genuinely generic boundary modules, not just renames of service-local code with the same entanglement.
