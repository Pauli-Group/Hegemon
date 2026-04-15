# Release 0.10.0 Architecture Cleanup

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

Release `0.10.0` needs one honest architecture story. After this cleanup, a novice reading the code or operator docs should see the same thing everywhere: the shipped shielded block lane is `RecursiveBlockV1`, `ReceiptRoot` is an explicit experimental/native comparison lane, and `RecursiveBlockV2` is an explicit experimental tree lane. The node should prefer the shipped recursive lane whenever multiple prepared artifacts exist, and the docs should stop describing `receipt_root` as the current shipping path.

The observable result is simple. Running the existing selectors and tests should still show `recursive_block` as the default product mode, while the repository docs, helper names, and bundle-ranking behavior stop implying that the explicit `receipt_root` lane is the primary shipping surface.

## Progress

- [x] (2026-04-14 13:34Z) Audited the current release surface across `DESIGN.md`, `METHODS.md`, `docs/SCALABILITY_PATH.md`, `pallets/shielded-pool`, `consensus`, `node/src/substrate/service.rs`, and `node/src/substrate/prover_coordinator.rs`.
- [x] (2026-04-14 20:31Z) Defined the release-facing classification helpers in `pallets/shielded-pool/src/types.rs`, including the canonical shipped recursive artifact kind plus shipped-vs-experimental predicates for block-proof lanes.
- [x] (2026-04-14 20:35Z) Renamed the stale node helper functions and release-surface error strings in `node/src/substrate/service.rs` so `receipt_root` is consistently described as an explicit experimental lane rather than a product-default path.
- [x] (2026-04-14 20:37Z) Changed prepared-bundle ranking in `node/src/substrate/prover_coordinator.rs` so the shipped recursive lane outranks the explicit experimental receipt-root lane when tx count is equal.
- [x] (2026-04-14 20:40Z) Rewrote `docs/SCALABILITY_PATH.md` so it matches the actual `0.10.0` shipped architecture instead of the older receipt-root shipping story.
- [x] (2026-04-14 20:52Z) Ran the focused release-surface tests and checks, confirmed they pass, and recorded the outcomes below.

## Surprises & Discoveries

- Observation: `docs/SCALABILITY_PATH.md` still describes the same-block native `receipt_root` path as the current shipping topology, while `DESIGN.md`, `METHODS.md`, and the code default all point to `RecursiveBlockV1`.
  Evidence: `docs/SCALABILITY_PATH.md` says the authoring node builds a same-block native `receipt_root`, while `pallets/shielded-pool/src/types.rs::proof_artifact_kind_from_mode` maps `RecursiveBlock` to `RecursiveBlockV1`.

- Observation: several node helper names still encode the old mental model even though they already accept recursive-block payloads.
  Evidence: at the start of this cleanup, `node/src/substrate/service.rs` had `ensure_native_only_receipt_root_*` helpers that allowed both explicit `ReceiptRoot` and `RecursiveBlock` payloads.

## Decision Log

- Decision: Keep the experimental lanes in-tree for `0.10.0`, but make the shipped-vs-experimental split explicit in names, ranking, and docs instead of trying to delete the research surfaces in one pass.
  Rationale: The repo still has useful explicit tests and alternate-lane plumbing, but the release surface needs clarity more than deletion right now.
  Date/Author: 2026-04-14 / Codex

- Decision: Prefer the shipped recursive lane over the explicit experimental receipt-root lane when sorting competing prepared bundles with equal transaction count.
  Rationale: The current release story should not accidentally privilege the experimental lane during local selection if both artifacts are present.
  Date/Author: 2026-04-14 / Codex

## Outcomes & Retrospective

This cleanup did what it needed to do for `0.10.0`: the release story is now explicit in both the code and the operator-facing documentation. The shipped path is `RecursiveBlockV1`, `ReceiptRoot` is clearly described as an explicit experimental/native comparison lane, and `RecursiveBlockV2` remains explicit experimental surface rather than something that can be misread as the default product lane.

The release-surface validation that passed in this cleanup was:

    cargo test -p consensus recursive_block_v1_verifier_ -- --nocapture
    cargo test -p hegemon-node default_block_proof_mode_is_recursive_block -- --nocapture
    cargo test -p hegemon-node recursive_block_mode_is_selected_from_env -- --nocapture
    cargo test -p hegemon-node require_native_block_proof_accepts_recursive_block_payload -- --nocapture
    cargo test -p pallet-shielded-pool validate_submit_recursive_candidate_artifact_ -- --nocapture
    cargo check -p block-recursion -p consensus -p pallet-shielded-pool -p hegemon-node

The main repository-level surprise was that the biggest release drift was not cryptographic code. It was naming and narrative drift: the runtime and consensus defaults were already on the shipped recursive lane, but an operator reading `docs/SCALABILITY_PATH.md` or several node helper names could still come away with the older receipt-root mental model. Cleaning that up was the right release cut.

## Context and Orientation

The proof-mode surface spans four places. `pallets/shielded-pool/src/types.rs` defines the runtime-facing `BlockProofMode` and `ProofArtifactKind` enums that appear in unsigned shielded submissions and candidate artifacts. `consensus/src/types.rs` mirrors the neutral proof-envelope surface used during import. `node/src/substrate/service.rs` and `node/src/substrate/prover_coordinator.rs` choose which block-proof lane to prepare and seal. `docs/SCALABILITY_PATH.md`, `DESIGN.md`, and `METHODS.md` tell operators and contributors what the shipped path actually is.

The key terms are simple. A “lane” means one block-proof topology. `RecursiveBlockV1` is the shipped constant-size same-block recursive artifact. `ReceiptRoot` is an explicit native comparison lane that still carries a commitment proof plus a native receipt-root artifact. `RecursiveBlockV2` is the explicit experimental tree lane. “Product lane” means the lane a normal `0.10.0` operator gets by default without opting into a comparison or experimental path.

## Plan of Work

First, define release-surface helpers in `pallets/shielded-pool/src/types.rs`. Add small predicate helpers that make the shipped lane explicit: the canonical shipped recursive artifact kind, whether a block-proof mode is the shipped product mode, and whether a proof artifact kind is experimental. Keep them tiny and pure so they can be reused in the node without another interpretation layer.

Second, update the node authoring helpers in `node/src/substrate/service.rs` and `node/src/substrate/prover_coordinator.rs`. Rename the old `receipt_root`-centric native-only helpers so they describe “native block proof” or “explicit experimental receipt_root” accurately. Keep behavior the same where it is already correct, but change warnings and error strings so the default forced path is clearly the shipped recursive lane. Change bundle ranking so `RecursiveBlock` sorts ahead of `ReceiptRoot`, and `ReceiptRoot` sorts ahead of `InlineTx`.

Third, align the operator narrative in `docs/SCALABILITY_PATH.md` with the actual `0.10.0` shipped path. The document must describe `tx_leaf -> RecursiveBlockV1` as the current shipping topology, treat `ReceiptRoot` as an explicit experimental/native comparison lane, and explain that `RecursiveBlockV2` remains experimental.

Finally, run the focused tests that prove the cleanup is real. The checks need to cover the selector defaults, the node service release-path guards, the downstream pallet acceptance logic, and at least one consensus test to ensure the release lane still resolves as `RecursiveBlockV1`.

## Concrete Steps

Work from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

Add the release-surface helpers and rename the stale helper functions with `apply_patch`, then run:

    cargo test -p pallet-shielded-pool validate_submit_recursive_candidate_artifact_ -- --nocapture
    cargo test -p consensus recursive_block_v1_verifier_ -- --nocapture
    cargo test -p hegemon-node default_block_proof_mode_is_recursive_block -- --nocapture
    cargo test -p hegemon-node recursive_block_mode_is_selected_from_env -- --nocapture
    cargo test -p hegemon-node require_native_block_proof_accepts_recursive_block_payload -- --nocapture
    cargo check -p block-recursion -p consensus -p pallet-shielded-pool -p hegemon-node
    git diff --check -- .agent/RELEASE_0_10_0_ARCHITECTURE_CLEANUP_EXECPLAN.md docs/SCALABILITY_PATH.md pallets/shielded-pool/src/types.rs node/src/substrate/service.rs node/src/substrate/prover_coordinator.rs node/src/substrate/artifact_market.rs

Expected outcomes:

    test result: ok

for each targeted test command, and no output from `git diff --check`.

## Validation and Acceptance

Acceptance means a newcomer can inspect the repo and see a single release story:

- `docs/SCALABILITY_PATH.md` describes `RecursiveBlockV1` as the shipped lane.
- `pallets/shielded-pool/src/types.rs` exposes a canonical shipped recursive artifact helper and marks the other block-proof kinds as experimental or legacy.
- `node/src/substrate/prover_coordinator.rs` still defaults to `recursive_block` and now prefers that shipped lane over `receipt_root` when sorting equal-size prepared bundles.
- `node/src/substrate/service.rs` no longer uses helper names that imply `receipt_root` is the product lane.

The tests above are the concrete proof that the release surface still works after the cleanup.

## Idempotence and Recovery

These changes are text and routing cleanups. Re-running the edits is safe as long as the helper names remain consistent. If a rename causes a compile failure, rerun `cargo check -p hegemon-node` and follow the compiler references until every old helper name is removed. No destructive migration or data rewrite is involved.

## Artifacts and Notes

The most important evidence to capture during implementation is:

    cargo test -p hegemon-node default_block_proof_mode_is_recursive_block -- --nocapture
    cargo test -p consensus recursive_block_v1_verifier_ -- --nocapture

Those two commands prove the release lane is still `RecursiveBlockV1` after the cleanup.

## Interfaces and Dependencies

Keep the release-surface helpers in `pallets/shielded-pool/src/types.rs` as plain functions on existing enums. Do not add a new crate or a separate “architecture policy” module for this release cleanup.

In `pallets/shielded-pool/src/types.rs`, define:

    pub const fn canonical_recursive_block_artifact_kind() -> ProofArtifactKind
    pub const fn is_shipped_block_proof_mode(mode: BlockProofMode) -> bool
    pub const fn is_experimental_block_proof_mode(mode: BlockProofMode) -> bool
    pub const fn is_experimental_block_artifact_kind(kind: ProofArtifactKind) -> bool

Use those helpers from:

- `node/src/substrate/prover_coordinator.rs`
- `node/src/substrate/service.rs`

Do not change the wire enums for `0.10.0`. This cleanup is about release semantics, naming, and selection, not a SCALE-breaking protocol change.

Revision note: created this ExecPlan to drive the `0.10.0` release-surface cleanup after the experimental lane push made the shipped-vs-experimental split harder to read from the repository alone.
