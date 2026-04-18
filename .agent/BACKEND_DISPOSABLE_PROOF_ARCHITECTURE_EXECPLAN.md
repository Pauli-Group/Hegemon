# Backend-Disposable Proof Architecture Cleanup

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, the shipped Hegemon proof stack has one canonical product route for block proofs and one compatibility route for research and historical decoding. Node authoring, consensus, and the pallet stop treating `BlockProofMode` and `ProofArtifactKind` as separate product choices. Instead they consume one explicit route object that says both pieces together. That makes the current Smallwood plus `RecursiveBlockV2` stack cleaner today, and it makes a future backend replacement possible without rewriting node-side routing again.

The user-visible outcome is simple. Running the existing targeted node and pallet tests should prove that the shipped `recursive_block_v2` lane is still the default, that the explicit `receipt_root` lane still works when selected, and that legacy lanes remain compatibility-only instead of first-class product choices. The architecture also becomes easier to read because the code stops duplicating “if mode is recursive, map it to this kind” logic in multiple places.

## Progress

- [x] (2026-04-18 03:32Z) Researched the current architecture in `DESIGN.md`, `METHODS.md`, `pallets/shielded-pool/src/types.rs`, `consensus/src/types.rs`, `consensus/src/proof.rs`, `node/src/substrate/artifact_market.rs`, `node/src/substrate/prover_coordinator.rs`, and `node/src/substrate/service.rs`.
- [x] (2026-04-18 03:32Z) Added `pallet_shielded_pool::types::BlockProofRoute` and canonical route helpers so mode and artifact kind can travel together instead of being recomputed ad hoc.
- [x] (2026-04-18 03:32Z) Switched pallet bundle validation, artifact-market compatibility mapping, and prepared-bundle coordinator identity matching over to the route object.
- [x] (2026-04-18 04:06Z) Finished the route migration in `node/src/substrate/service.rs`, including route-based prepared-bundle gating and route-based prepared-bundle keys.
- [x] (2026-04-18 04:06Z) Added `consensus::types::ArtifactRoute` so consensus-facing artifact identity now mirrors the pallet route abstraction instead of carrying the split only by convention.
- [x] (2026-04-18 04:06Z) Moved route translation and receipt translation into explicit helpers so service no longer hand-copies route identity and receipt fields on the hot path.
- [x] (2026-04-18 04:06Z) Updated `DESIGN.md` and `METHODS.md` so they describe the new route boundary explicitly and state that compatibility lanes are second-class routing surfaces.
- [x] (2026-04-18 04:32Z) Finished the heavier node-side route/cache behavioral tests. The warmed `hegemon-node` binary now passes the route-focused RPC, env-selection, and prepared-bundle identity checks listed in this plan.

## Surprises & Discoveries

- Observation: the hard part is not proof verification. It is the duplicated product routing above verification. `BlockProofMode`, `ProofArtifactKind`, environment selection, prepared-bundle cache identity, and payload normalization were all carrying overlapping truth.
  Evidence: `node/src/substrate/service.rs`, `node/src/substrate/prover_coordinator.rs`, and `node/src/substrate/artifact_market.rs` each contained their own “mode implies kind” logic before this cleanup started.

- Observation: the current shipped path is already simpler than the type surface makes it look. The product default is one route: `RecursiveBlockV2`. The only other live block-artifact route is the explicit `ReceiptRoot` compatibility/research lane.
  Evidence: `DESIGN.md` and `METHODS.md` already describe `RecursiveBlockV2` as the shipped constant-size recursive lane and `ReceiptRoot` as the explicit alternate lane.

- Observation: Rust `const fn` is not worth fighting here. The route helpers are part of runtime routing logic, not compile-time evaluation, so forcing them through `const` only obscures the code.
  Evidence: `cargo check` failed on `PartialEq` use inside `const fn` in `pallets/shielded-pool/src/types.rs` until those helpers were relaxed back to normal functions.

- Observation: the route abstraction needed to exist in `consensus` too. Leaving it only in the pallet/node code would have forced the translation layer to keep re-splitting and rejoining `mode` and `kind`, which is exactly the drift this cleanup is trying to kill.
  Evidence: `node/src/substrate/artifact_market.rs`, `node/src/substrate/rpc/prover.rs`, and the artifact broadcast path in `node/src/substrate/service.rs` all still had manual conversions until `consensus::types::ArtifactRoute` was added.

- Observation: receipt field copying was a quieter version of the same architectural leak. The bytes were correct, but the service layer still manually reconstructed receipt structs at the pallet/consensus boundary.
  Evidence: `node/src/substrate/service.rs` had duplicate `statement_hash`, `proof_digest`, `public_inputs_digest`, and `verifier_profile` field copies in both directions before the boundary helpers were added.

## Decision Log

- Decision: introduce `BlockProofRoute { mode, kind }` in `pallets/shielded-pool/src/types.rs` instead of deleting `BlockProofMode` immediately.
  Rationale: the runtime schema and compatibility vocabulary still carry `proof_mode`, so the safest cleanup is to centralize the pairing first and remove duplicated routing logic before considering any on-chain schema reduction.
  Date/Author: 2026-04-18 / Codex

- Decision: keep `RecursiveBlockV1` and `ReceiptRoot` in-tree as compatibility routes, but stop treating them as first-class product defaults.
  Rationale: the repo still needs decode and test coverage for old and explicit alternate lanes, but product-path code should stop implying that all lanes are equally live.
  Date/Author: 2026-04-18 / Codex

- Decision: route-based matching is the first streamline slice, not a full backend trait rewrite.
  Rationale: the immediate architectural debt is duplicated lane-selection logic in the pallet/node path. Fixing that now reduces risk and makes the later backend-seam work easier to stage.
  Date/Author: 2026-04-18 / Codex

- Decision: add the same route abstraction to `consensus::types` instead of treating route identity there as “just mode and kind side by side.”
  Rationale: consensus artifacts and RPC announcements are part of the same product boundary. If the route is explicit only on the pallet side, the cross-layer translation code remains structurally duplicated.
  Date/Author: 2026-04-18 / Codex

- Decision: keep receipt translation as explicit boundary helpers in `node/src/substrate/service.rs` for now rather than introducing a new shared crate only for conversions.
  Rationale: the immediate goal is to stop hot-path hand-copying and clarify the boundary without creating another crate during the same refactor. A later claim/receipt crate can absorb these helpers once the backend seam is ready.
  Date/Author: 2026-04-18 / Codex

## Outcomes & Retrospective

This plan is complete for the intended slice. Route identity is explicit in the pallet, consensus, and node/service layers, and the translation layer owns both route conversion and receipt conversion instead of scattering them through authoring and RPC code. The route-focused compile, pallet, consensus, RPC, env-selection, and prepared-bundle cache tests are now green on the current tree. The remaining larger architecture work is the next phase: promote canonical tx claims/receipts into the only cross-layer proof object above backend adapters and push compatibility lanes deeper into decode-only modules.

## Context and Orientation

The current Hegemon proof architecture has three layers that matter for this work.

The first layer is the runtime-visible block artifact. That lives in `pallets/shielded-pool/src/types.rs` as `CandidateArtifact`. A `CandidateArtifact` still carries `proof_mode` for compatibility, `proof_kind` for backend-neutral artifact identification, `verifier_profile` for exact verifier binding, and one of the actual payloads (`receipt_root` or `recursive_block`).

The second layer is node-side authoring and caching. `node/src/substrate/prover_coordinator.rs` keeps prepared bundles in a local cache and decides whether a candidate set already has a usable prepared artifact. `node/src/substrate/service.rs` selects the active block-artifact route from the environment, builds or reuses prepared artifacts, and normalizes payload identity before submitting unsigned block-proof extrinsics. `node/src/substrate/artifact_market.rs` translates between consensus-facing artifact identity and pallet-facing artifact identity.

The third layer is backend verification. `consensus/src/proof.rs` and the proof crates under `circuits/` verify the actual bytes. This ExecPlan is not changing the backend math. It is changing the product routing above the backend so the rest of the system can treat the backend as a replaceable component later.

The important product facts are already established in the repository. `RecursiveBlockV2` is the shipped same-block constant-size route. `ReceiptRoot` is an explicit alternate native compatibility/research route. `RecursiveBlockV1` remains legacy-only. `InlineTx` survives as compatibility vocabulary, not as the shipped path. The architecture cleanup in this plan must preserve those facts.

In this plan, “route” means the exact pair `(BlockProofMode, ProofArtifactKind)`. That pair is the real product choice. A mode without a kind is ambiguous because `RecursiveBlock` historically allowed both `RecursiveBlockV1` and `RecursiveBlockV2`, and a kind without a mode is ambiguous because payload admission still uses the compatibility `proof_mode` field on chain.

## Plan of Work

The first step is to make the route explicit in `pallets/shielded-pool/src/types.rs`. Define `BlockProofRoute` with helpers for the shipped `RecursiveBlockV2` route and the explicit `ReceiptRoot` route. Add helper methods that answer four concrete questions: whether the route is compatible with the encoded mode, whether it is canonical for that mode, whether it is the shipped route, and whether it is the explicit experimental route. Keep `CandidateArtifact` unchanged on the wire, but give it methods that derive and compare its route. The purpose is to centralize interpretation without forcing a storage migration.

The second step is to move all product-path matching over to the route object. In `pallets/shielded-pool/src/lib.rs`, use the route helper during bundle validation instead of open-coding recursive-mode exceptions. In `node/src/substrate/artifact_market.rs`, add route-based compatibility identity helpers and make mode-to-kind compatibility flow through that one function. In `node/src/substrate/prover_coordinator.rs`, replace cache keys that separately store mode and kind with a single route field so exact prepared-bundle matching always keys on the same abstraction the product uses. In `node/src/substrate/service.rs`, make `PreparedArtifactSelector` hold a route plus verifier profile, route the environment helpers through the artifact-market compatibility helper, and replace scattered “proof kind requires prepared bundle” logic with route-based helpers.

The third step is to extend the same cleanup into `consensus::types`. Define `ArtifactRoute` there as the consensus-facing equivalent of the pallet route object. Give `ProvenBatch` and `ArtifactAnnouncement` helper methods that derive their route. Then update the translation code in `node/src/substrate/artifact_market.rs`, the artifact broadcast path in `node/src/substrate/service.rs`, and the prover RPC mapping in `node/src/substrate/rpc/prover.rs` so route conversion happens in one place instead of every caller re-spelling mode/kind conversions.

The fourth step is to trim receipt boundary leakage. `node/src/substrate/service.rs` still needs to translate between pallet and consensus receipt types because the crates remain separate, but those field copies should live in one tiny boundary helper each. The service hot path must stop rebuilding the same four-field receipt structs by hand.

The fifth step is to document the architecture the code now implements. Update `DESIGN.md` and `METHODS.md` to say plainly that the shipped block-artifact contract now has one canonical product route and one explicit alternate route. The docs should say that route identity is now explicit in both pallet and consensus types, while the older separate fields remain because the pallet and consensus payload schemas are still compatibility-shaped.

The sixth step is to prove the result. Run the targeted pallet, consensus, and node tests listed below. They must show that `RecursiveBlockV2` remains the default route, that the explicit `ReceiptRoot` route still works when selected, and that prepared-bundle matching is exact on the combined route identity rather than on loose mode-only matching.

## Concrete Steps

All commands below run from the repository root `/Users/pldd/Projects/Reflexivity/Hegemon`.

Start by formatting and checking the focused crates:

    cargo fmt --all
    cargo check -p pallet-shielded-pool -p consensus -p hegemon-node

Then run the route-focused tests:

    cargo test -p consensus canonical_artifact_routes_are_explicit -- --nocapture
    cargo test -p consensus artifact_route_classification_distinguishes_legacy_and_shipped_paths -- --nocapture
    cargo test -p pallet-shielded-pool canonical_routes_are_explicit -- --nocapture
    cargo test -p pallet-shielded-pool route_classification_distinguishes_shipped_and_compatibility_paths -- --nocapture
    cargo test -p hegemon-node map_artifact_announcement_supports_recursive_block -- --nocapture
    cargo test -p hegemon-node substrate::prover_coordinator::tests::prepared_lookup_requires_exact_proof_identity -- --exact --nocapture
    cargo test -p hegemon-node substrate::prover_coordinator::tests::authoring_transactions_ignore_wrong_lane_prepared_bundle_for_current_parent -- --exact --nocapture
    cargo test -p hegemon-node default_block_proof_mode_is_recursive_block -- --nocapture
    cargo test -p hegemon-node recursive_block_mode_is_selected_from_env -- --nocapture

If `cargo check` fails because a selector or test still expects separate `compat_mode` and `proof_kind` fields, search for those names and convert the remaining initializer or helper to `BlockProofRoute`.

To verify the actual code changes after the test pass, run:

    git diff --check -- \
      pallets/shielded-pool/src/types.rs \
      pallets/shielded-pool/src/lib.rs \
      node/src/substrate/artifact_market.rs \
      node/src/substrate/prover_coordinator.rs \
      node/src/substrate/rpc/prover.rs \
      node/src/substrate/service.rs \
      consensus/src/types.rs \
      DESIGN.md \
      METHODS.md \
      .agent/BACKEND_DISPOSABLE_PROOF_ARCHITECTURE_EXECPLAN.md

Expected success looks like this:

    cargo test -p pallet-shielded-pool canonical_routes_are_explicit -- --nocapture
    ...
    test canonical_routes_are_explicit ... ok

    cargo test -p hegemon-node recursive_block_mode_is_selected_from_env -- --nocapture
    ...
    test recursive_block_mode_is_selected_from_env ... ok

## Validation and Acceptance

Acceptance is behavior, not just compilation.

The first acceptance condition is pallet-side classification. `canonical_routes_are_explicit` must prove that `canonical_shipped_block_proof_route()` resolves to `(RecursiveBlock, RecursiveBlockV2)` and that the explicit alternate route resolves to `(ReceiptRoot, ReceiptRoot)`.

The second acceptance condition is exact prepared-bundle identity. `prepared_lookup_requires_exact_proof_identity` must prove that the coordinator does not treat a wrong route as a cache hit, even when parent hash, statement commitment, and tx count match.

The third acceptance condition is node-side operator selection. `recursive_block_mode_is_selected_from_env` must prove that the unconfigured product path still resolves to the shipped recursive route, and `default_block_proof_mode_is_recursive_block` must continue to pass.

The fourth acceptance condition is cross-layer route fidelity. `canonical_artifact_routes_are_explicit` in `consensus` and the artifact-market/prover-RPC route tests in `hegemon-node` must prove that consensus-facing artifact identity now carries the same shipped-vs-compatibility meaning as the pallet-facing route object.

The fifth acceptance condition is documentation fidelity. After the code and docs are updated, the product-path sections in `DESIGN.md` and `METHODS.md` must explicitly describe one shipped route (`RecursiveBlockV2`) and one explicit alternate route (`ReceiptRoot`) instead of speaking about proof modes as if they were the complete product selector.

## Idempotence and Recovery

This plan is safe to apply incrementally. The route helpers are additive, and the cleanup replaces duplicated matching logic with central helper calls. If a partial edit leaves compilation broken, the recovery path is straightforward: search for remaining uses of `compat_mode` and `proof_kind` in selector and prepared-bundle code, convert them to `route`, rerun `cargo fmt --all`, and rerun the targeted `cargo check`.

There is no storage migration in this slice. `CandidateArtifact` still carries the same compatibility fields. That means retries are low-risk and do not require chain-state resets.

## Artifacts and Notes

Important evidence from the codebase that motivates this cleanup:

    DESIGN.md now states that `RecursiveBlockV2` is the shipped bounded-domain lane and
    `ReceiptRoot` is the explicit alternate native lane.

    METHODS.md now states that generic node/consensus code should consume neutral artifact
    identity and verified receipts instead of backend-specific proof internals.

The route object introduced in this plan is the code-level expression of those two facts.

## Interfaces and Dependencies

In `pallets/shielded-pool/src/types.rs`, define and keep:

    pub struct BlockProofRoute {
        pub mode: BlockProofMode,
        pub kind: ProofArtifactKind,
    }

with these methods:

    impl BlockProofRoute {
        pub const fn new(mode: BlockProofMode, kind: ProofArtifactKind) -> Self;
        pub fn from_mode(mode: BlockProofMode) -> Self;
        pub const fn shipped_recursive_block_v2() -> Self;
        pub const fn explicit_receipt_root() -> Self;
        pub fn is_compatible_with_mode(self) -> bool;
        pub fn is_canonical(self) -> bool;
        pub fn is_shipped(self) -> bool;
        pub fn is_experimental(self) -> bool;
    }

In the same file, keep helper functions:

    pub fn canonical_shipped_block_proof_route() -> BlockProofRoute;
    pub fn canonical_experimental_block_proof_route() -> BlockProofRoute;

In `node/src/substrate/artifact_market.rs`, expose:

    pub(crate) fn compat_pallet_route_identity(
        mode: pallet_shielded_pool::types::BlockProofMode,
    ) -> (
        pallet_shielded_pool::types::BlockProofRoute,
        pallet_shielded_pool::types::VerifierProfileDigest,
    )

In `consensus/src/types.rs`, define and keep:

    pub struct ArtifactRoute {
        pub mode: ProvenBatchMode,
        pub kind: ProofArtifactKind,
    }

and add:

    impl ProvenBatch {
        pub fn route(&self) -> ArtifactRoute;
    }

    impl ArtifactAnnouncement {
        pub fn route(&self) -> ArtifactRoute;
    }

In `node/src/substrate/service.rs`, keep one explicit boundary helper in each direction:

    fn pallet_receipt_from_consensus(
        receipt: consensus::types::TxValidityReceipt,
    ) -> pallet_shielded_pool::types::TxValidityReceipt;

    fn consensus_receipt_from_pallet(
        receipt: pallet_shielded_pool::types::TxValidityReceipt,
    ) -> consensus::types::TxValidityReceipt;

In `node/src/substrate/service.rs`, keep:

    struct PreparedArtifactSelector {
        route: pallet_shielded_pool::types::BlockProofRoute,
        verifier_profile: pallet_shielded_pool::types::VerifierProfileDigest,
    }

and route all environment selection and prepared-bundle readiness logic through that selector instead of through separate mode and kind fields.

Revision note (2026-04-18 / Codex): created this ExecPlan after implementing the first route cleanup slice so the continuing work is grounded in the actual code path rather than in an abstract future rewrite.

Revision note (2026-04-18 / Codex): updated the plan after finishing the second cleanup slice. Route identity is now explicit in `consensus` as well as in the pallet/node path, the translation layer owns route conversion, and receipt translation on the hot path is centralized into boundary helpers instead of field-by-field copies.
