# Purge Dead Proof Surfaces From The Native-Only Chain

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](.agent/PLANS.md).

## Purpose / Big Picture

After this change, the fresh-chain 0.10.x product surface is brutally simpler: consensus and the node only carry the live native shielded transaction path plus the single remaining native receipt-root research baseline where that baseline is still useful. The dead recursive and residual block-proof lanes (`MergeRoot`, `FlatBatches`, `receipt_accumulation`, and `receipt_arc_whir`) disappear from live routing, tests, and operator selection. Historical execplans stop polluting the active `.agent/` surface. The observable result is that `cargo test` and `cargo check` still pass on the native path, `service.rs` loses the dead proof-mode branches, and the repo no longer advertises or compiles abandoned proof lanes as if they are product candidates.

## Progress

- [x] (2026-03-27 22:31Z) Audited the current dead-lane footprint across `node/src/substrate/service.rs`, `consensus/src/proof.rs`, `consensus/src/types.rs`, `pallets/shielded-pool/src/types.rs`, `node/src/substrate/artifact_market.rs`, the `receipt-arc-whir` crate, backend constructors, and `.agent/`.
- [x] (2026-03-27 22:39Z) Wrote this purge ExecPlan with the concrete deletion scope and validation gates.
- [x] (2026-03-27 23:58Z) Removed `MergeRoot` and `FlatBatches` from pallet and consensus type surfaces, artifact routing, payload construction, and focused tests.
- [x] (2026-03-28 00:09Z) Removed `receipt_accumulation` and `receipt_arc_whir` from node authoring/import paths, consensus verification, public exports, and workspace membership.
- [x] (2026-03-28 00:21Z) Removed frozen backend family constructors and stale comparison tests that only existed for archived replay.
- [x] (2026-03-28 00:31Z) Archived historical proof-surface ExecPlans out of the active `.agent/` root and rewrote active docs away from the dead prover-market topology.
- [x] (2026-03-28 01:17Z) Ran the surviving native-path validation surface (`cargo fmt --all`, `cargo check -p consensus -p hegemon-node -p runtime`, `cargo test -p consensus --tests --no-run`, `cargo test -p hegemon-node --lib --tests --no-run`, `cargo test -p runtime kernel_wallet_unsigned_transfer_survives_kernel_validate_and_apply -- --nocapture`, `cargo test -p runtime kernel_wallet_rejects_non_native_transfer_payload -- --nocapture`, `cargo test -p hegemon-node extract_inline_transfer_accepts_native_tx_leaf_payload -- --nocapture`, and `cargo test -p consensus --test raw_active_mode -- --nocapture`) and fixed the local warnings introduced by the purge.

## Surprises & Discoveries

- Observation: the dead lanes are not isolated to one module; they are wired through pallet enums, consensus enums, artifact-market mappings, service-side prove-ahead caches, and large test blocks in `node/src/substrate/service.rs`.
  Evidence: `rg -n "MergeRoot|FlatBatches|receipt_accumulation|receipt_arc_whir" consensus/src/proof.rs node/src/substrate/service.rs pallets/shielded-pool/src/types.rs consensus/src/types.rs node/src/substrate/artifact_market.rs` hit all of those files.
- Observation: dead-lane cleanup also had to cut stale plan and operator text, not just Rust branches, because the repository still described a deleted prover-worker market long after the code had moved on.
  Evidence: active `DESIGN.md`, `METHODS.md`, and several `.agent/*EXECPLAN*.md` files still described `hegemon-prover-worker`, stage work packages, or removed proof-mode branches after the local worker-only native path had already landed.

## Decision Log

- Decision: keep the purge scoped to dead block-artifact lanes plus dead backend comparison constructors; do not fold in a larger redesign of the native `tx_leaf` shipped path in the same change.
  Rationale: the user asked for dead-lane removal and service shrinkage, not another architecture rewrite. Removing the abandoned branches without disturbing the live native path gives a sharp, verifiable cut.
  Date/Author: 2026-03-27 / Codex
- Decision: treat historical inline-upgrade tests as expendable if they block the purge of no-longer-shipped block-proof modes.
  Rationale: the repo already proved the versioning boundary in prior work. The fresh-chain product path no longer needs long-lived test scaffolding for dead proof lanes.
  Date/Author: 2026-03-27 / Codex

## Outcomes & Retrospective

The code purge removed the dead proof lanes from live product code. `BlockProofMode`, `ProofArtifactKind`, pallet payloads, consensus artifact routing, and node authoring/import now only carry the shipped direct path plus the explicit `ReceiptRoot` research lane. The old recursive `MergeRoot`, manifest-style `FlatBatches`, warm-store accumulation wrapper, and residual ARC/WHIR lane are gone from consensus, node routing, the focused test surface, and the workspace itself. The external prover-market RPC and standalone `hegemon-prover-worker` binary are also gone, replaced by a bounded local artifact-worker pool for the remaining explicit research lane.

The cleanup also shrank the active repo surface outside Rust code. Frozen backend comparison constructors were deleted from `circuits/superneo-backend-lattice`, dead-lane plans were moved under `.agent/archive/proof-history/`, and active docs now describe the local native path honestly instead of preserving stale prover-market topology language. The surviving native-only validation surface passed after the purge, including the runtime native unsigned-transfer tests, the node native extraction test, and the mixed-history consensus regression that proves inline history can still transition into the native receipt-root research lane.

## Context and Orientation

The current product shape is the fresh-chain native shielded transaction path: wallets emit native `tx_leaf` artifacts, runtime validation accepts those artifacts directly, and block import can verify native transaction validity without the older inline STARK payloads defining the product. Dead research code remains because the repository still carries old block-artifact selectors and verifier code for recursive merge proofs (`MergeRoot`), manifest-style flat proof batches (`FlatBatches`), a warm-store receipt wrapper (`receipt_accumulation`), and a residual Reed-Solomon lane (`receipt_arc_whir`).

Those dead lanes show up in five places. `pallets/shielded-pool/src/types.rs` defines the runtime-facing block-proof enums and payload structs. `consensus/src/types.rs` mirrors those concepts for consensus verification. `node/src/substrate/artifact_market.rs` maps pallet payloads into consensus artifact identities. `node/src/substrate/service.rs` is the giant Substrate node service that still selects block-proof lanes from `HEGEMON_BLOCK_PROOF_MODE`, builds payloads, and runs prove-ahead caching. `consensus/src/proof.rs` registers artifact verifiers and evaluates block artifacts during import. The `circuits/receipt-arc-whir` crate and `consensus/src/receipt_arc_whir.rs` exist only for the dead residual lane. The backend crate `circuits/superneo-backend-lattice` also still publishes frozen historical constructors for benchmark comparison that are no longer needed if archived replay is no longer part of product maintenance.

The cleanup must preserve the live native path. That means the following behavior must still work after the purge: wallet-built native tx payloads, runtime validation of those payloads, consensus import on the native path, and the focused native tests already in the repo. The purge should also keep docs truthful: `DESIGN.md` and `METHODS.md` must stop presenting deleted lanes as current operator choices.

## Plan of Work

First, delete dead public type variants and mappings so the compiler stops allowing dead block-artifact modes. In `pallets/shielded-pool/src/types.rs`, remove `FlatBatches` and `MergeRoot` from `BlockProofMode`, remove the corresponding `ProofArtifactKind` variants if they are no longer representable, and delete `BatchProofItem`, `MergeRootMetadata`, `MergeRootProofPayload`, and any `ProvenBatch` fields that only exist for those modes. Mirror the same shrink in `consensus/src/types.rs`. In `node/src/substrate/artifact_market.rs`, collapse the pallet-to-consensus mode mapping so it no longer knows about those dead variants.

Next, delete dead authoring/import branches from `node/src/substrate/service.rs`. Remove the `PreparedArtifactSelector` constructors and environment parsing for `merge_root`, `flat`, `receipt_accumulation`, and `receipt_arc_whir`. Remove the builders `build_flat_batch_proofs_from_materials`, `build_merge_root_proof_from_materials`, `build_receipt_accumulation_proof_from_materials`, `build_receipt_arc_whir_proof_from_materials`, and the receipt-accumulation cache rewarm path. Collapse `PreparedAggregationArtifacts` and `PreparedAggregationOutcome` so they only represent the still-supported product/research outcomes. Delete tests that only exercise the removed selectors or their fallback logic. If a compatibility test only existed to prove the old lanes still parsed, remove it.

Then, delete dead consensus-side verification. In `consensus/src/proof.rs`, remove verifier registration and verifier implementations for `MergeRoot`, `receipt_accumulation`, and `receipt_arc_whir`, along with helper functions, metrics, and artifact-size accounting that only exist for those lanes. Delete `consensus/src/receipt_arc_whir.rs`, remove `pub mod receipt_arc_whir;` and related re-exports from `consensus/src/lib.rs`, drop the `receipt-arc-whir` dependency from `consensus/Cargo.toml`, and remove the crate from the workspace in `Cargo.toml`.

After the proof-lane purge, remove dead backend comparison constructors from `circuits/superneo-backend-lattice/src/lib.rs`, related tests that only assert historical baseline claims, and doc references that describe those constructors as live comparison families. Keep the active structural family only.

Finally, archive historical ExecPlans. Move no-longer-live `.agent/*EXECPLAN*.md` files into a dated archive folder under `.agent/archive/`, leaving only `PLANS.md`, this purge plan, and the small set of currently live architectural plans in the root. Update `DESIGN.md` and `METHODS.md` so they stop referencing archived plans as current guidance.

## Concrete Steps

Run all commands from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

Audit dead references before the purge:

    rg -n "MergeRoot|FlatBatches|receipt_accumulation|receipt_arc_whir" \
      consensus/src node/src/substrate pallets/shielded-pool/src circuits docs .agent

After editing, rerun focused native-path validation:

    cargo test -p wallet build_transaction_can_emit_native_tx_leaf_payloads -- --nocapture
    cargo test -p runtime kernel_wallet_unsigned_transfer_survives_kernel_validate_and_apply -- --nocapture
    cargo test -p runtime kernel_wallet_rejects_non_native_transfer_payload -- --nocapture
    cargo test -p hegemon-node extract_inline_transfer_accepts_native_tx_leaf_payload -- --nocapture
    cargo test -p consensus --test raw_active_mode -- --nocapture
    cargo check -p consensus -p hegemon-node -p runtime
    cargo fmt --all

The exact consensus/node test names may change as dead-lane tests are deleted; update this section to match the surviving native-only suite.

## Validation and Acceptance

Acceptance is behavioral and structural.

Structurally, the following searches must return no product-code references outside archives or intentional historical benchmark/docs surfaces:

    rg -n "MergeRoot|FlatBatches|receipt_accumulation|receipt_arc_whir" \
      consensus/src node/src/substrate pallets/shielded-pool/src circuits

Behaviorally, the native shipped path must still pass the focused wallet/runtime/node tests and `cargo check` for the key crates. If any old test only exists to defend deleted dead lanes, remove it and replace it with a tighter native-only assertion rather than preserving dead coverage.

The `.agent/` root is accepted when it contains only live plans plus `PLANS.md`, while historical plans live under `.agent/archive/...`.

## Idempotence and Recovery

This purge is idempotent because deleting dead branches twice is a no-op once the branches are gone. If a deletion cuts too deep, recovery means restoring the specific file from git and re-applying only the live native-path edits; do not reintroduce the full dead lane just to make one test pass. Archival moves are safe to repeat if the destination path is stable.

## Artifacts and Notes

Expected post-purge structural evidence looks like:

    $ rg -n "MergeRoot|FlatBatches|receipt_accumulation|receipt_arc_whir" \
        consensus/src node/src/substrate pallets/shielded-pool/src circuits
    <no output>

or only hits in archived docs and benchmark JSON paths outside the active product code.

## Interfaces and Dependencies

At the end of the purge:

- `pallet_shielded_pool::types::BlockProofMode` must no longer expose dead recursive or residual lanes.
- `consensus::types::ProvenBatchMode` and `consensus::types::ProofArtifactKind` must no longer expose dead recursive or residual lanes.
- `node::substrate::service::prepared_artifact_selector_from_env()` must no longer parse or route dead proof modes.
- `consensus::proof::VerifierRegistry::default_for_stage1()` must no longer register verifiers for removed lanes.
- The workspace `Cargo.toml` must no longer include `circuits/receipt-arc-whir`, and `consensus/Cargo.toml` must no longer depend on it.

Revision note (2026-03-27): created this ExecPlan to drive a native-only purge of dead proof lanes, dead backend constructors, and stale `.agent/` surface clutter before further product work.
