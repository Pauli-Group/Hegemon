# Recursive Constant-Size Lane Cutover

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, the repository will stop pretending that `RecursiveBlockV1` is a general constant-size recursive proof lane. The shipped recursive block lane will be the one that actually satisfies the invariant on the current backend: `RecursiveBlockV2`. The user-visible effect is simple. The default shipped recursive artifact kind, runtime caps, node authoring defaults, and operator docs will all describe one real bounded recursive block artifact instead of a stale `v1` envelope. Success is visible by running the existing `block-recursion` ignored tests and seeing a fixed-width `v2` artifact under `1 MiB`, then running the node/runtime tests and seeing that the default shipped recursive kind is `RecursiveBlockV2`.

## Progress

- [x] (2026-04-17T22:54Z) Revalidated on the current worktree that `RecursiveBlockV1` is not a general steady-state constant-size recursive lane and that `RecursiveBlockV2` is the only current bounded recursive lane.
- [x] (2026-04-17T23:47Z) Measured `RecursiveBlockV2` on the current backend at `TREE_RECURSIVE_CHUNK_SIZE_V2 = 256`. The printed cap report now gives `p_chunk_a = 165,275`, `p_merge_a = 787,643`, `p_merge_b = 372,731`, `p_carry_a = 414,115`, `p_carry_b = 206,659`, `root_proof_cap = 787,643`, and full fixed artifact bytes `788,431`.
- [x] (2026-04-18T00:18Z) Revalidated the `v2` prove/verify surface at the base case, first merge boundary, first carry boundary, and deepest-supported prove/verify case on the `256`-chunk geometry. All four ignored tests passed.
- [x] (2026-04-18T00:39Z) Promoted the winning `v2` geometry into `circuits/block-recursion`, `pallets/shielded-pool`, `consensus`, and the node default selector so the shipped recursive lane is the real bounded lane.
- [x] (2026-04-18T00:56Z) Demoted `RecursiveBlockV1` from the shipped default path and quarantined it as a legacy compatibility/debug lane while preserving explicit compatibility handling for `v1` payloads.
- [x] (2026-04-18T01:07Z) Rewrote docs and sizing/operator language so the repo consistently states that `v2` is the shipped constant-size recursive lane and `v1` is legacy.
- [x] (2026-04-18T01:28Z) Ran targeted verification across block recursion, pallet validation, node default-selection tests, compile sweep, and diff hygiene.

## Surprises & Discoveries

- Observation: the current dirty worktree already contains direct evidence that `RecursiveBlockV1` is not a real depth-independent constant-size lane on the current backend.
  Evidence: `recursive_block_v1_proof_cap_report_reveals_steady_state_growth` measures `BaseA = 41,371`, first `StepB = 162,763`, first `StepA = 561,075`, and steady-state `StepB = 1,868,811`, which exceeds the old `699,404` envelope.

- Observation: `RecursiveBlockV2` is the only recursive lane in the repo with a validated bounded-domain invariant after the compact proof-prefix decode fix.
  Evidence: the `prove_and_verify_recursive_artifact_v2_*` ignored tests pass on the current worktree after `tree_v2.rs` was fixed to decode the canonical compact proof prefix from the padded proof field.

- Observation: on the current backend, the right chunk-size move was to make the tree chunks larger, not smaller.
  Evidence: `TREE_RECURSIVE_CHUNK_SIZE_V2 = 256` produces `root_proof_cap = 787,643` and full fixed artifact bytes `788,431`, which clears the sub-`1 MiB` bar while preserving the merge/carry/deepest prove/verify surface.

## Decision Log

- Decision: stop treating `RecursiveBlockV1` as a candidate for “restoring” the constant-size invariant.
  Rationale: the current proving path and fresh diagnostic show that `v1` is a fixed outer envelope over a recursively growing proof, not a true steady-state constant-size recursive lane.
  Date/Author: 2026-04-17 / Codex

- Decision: target `RecursiveBlockV2` for the sub-`1 MiB` invariant instead of trying to save the stale `v1` envelope.
  Rationale: `v2` is already the only lane with a bounded-domain proof-cap report, and chunk geometry is the live lever for size/performance tradeoffs.
  Date/Author: 2026-04-17 / Codex

- Decision: keep `TREE_RECURSIVE_CHUNK_SIZE_V2 = 256` and make `RecursiveBlockV2` the shipped recursive lane.
  Rationale: the measured fixed artifact is `788,431` bytes, the prove/verify boundary tests remain green, and the runtime/node selectors were still incorrectly defaulting to legacy `v1`.
  Date/Author: 2026-04-17 / Codex

## Outcomes & Retrospective

The cutover achieved the main goal. The repo once again has one shipped recursive lane with a defensible constant-size invariant: `RecursiveBlockV2` at `788,431` bytes under `TREE_RECURSIVE_CHUNK_SIZE_V2 = 256`. The old `v1` story is no longer the shipped selector path, and the deepest fixed-width test, pallet admission tests, node default-selector tests, compile sweep, and diff hygiene all passed on the cutover tree. The main lesson is that the right fix was not “rescue `v1`.” It was to stop lying about `v1`, promote the real bounded lane, and retune the one live geometry that still had honest headroom.

## Context and Orientation

The recursive block proof code lives in `circuits/block-recursion`. `RecursiveBlockV1` is the older linear recursion lane. Its artifact width constants live in `circuits/block-recursion/src/artifacts.rs`, and the current diagnostic test showing steady-state growth lives in `circuits/block-recursion/src/tests.rs`. `RecursiveBlockV2` is the tree-reduced recursive lane. Its bounded-domain cap logic lives in `circuits/block-recursion/src/tree_v2.rs`, and the runtime admission caps for both recursive kinds live in `pallets/shielded-pool/src/types.rs`.

The node decides which recursive artifact kind is the shipped default through `pallets/shielded-pool::types::canonical_recursive_block_artifact_kind()` and the node tests under `node/src/substrate/service.rs` and `node/src/substrate/prover_coordinator.rs`. Those selectors now need to stay pinned to `RecursiveBlockV2`; any drift back to `v1` would reintroduce the old stale invariant.

The goal of this plan is not to optimize generic recursion in the abstract. It is to make the shipped recursive lane truthful again. That means a fixed-width recursive artifact, bounded by current tests, below `1 MiB`, selected by default by the runtime and node, and described consistently in `DESIGN.md`, `METHODS.md`, `README.md`, and `docs/SCALABILITY_PATH.md`.

## Plan of Work

Start by measuring `RecursiveBlockV2` under a larger chunk geometry. The active tree chunk size is `128`. The first serious candidate is `256`, because earlier local work suggested that this size materially shrinks the artifact while keeping verification alive. Update `circuits/block-recursion/src/tree_v2.rs`, add or refresh a report test in `circuits/block-recursion/src/tests.rs` so the current `TreeProofCapReportV2` prints the derived fixed width under `--nocapture`, and run the ignored `v2` prove/verify tests at the merge boundary, carry boundary, and deepest supported level. If the derived artifact width is below `1 MiB` and the tests stay green, keep that geometry. If not, record the rejection and try the next justified chunk size only if there is real remaining headroom.

Once a winning `v2` geometry is established, update `pallets/shielded-pool/src/types.rs` so the canonical shipped recursive artifact kind is `RecursiveBlockV2`, its size cap is the derived fixed width, and `RecursiveBlockV1` is treated as legacy rather than shipped. Then update the node default-selection code and tests in `node/src/substrate/service.rs` and `node/src/substrate/prover_coordinator.rs` so the default recursive block mode resolves to `RecursiveBlockV2`.

After the code cutover, rewrite the design/method/operator documents. `DESIGN.md`, `METHODS.md`, `README.md`, and `docs/SCALABILITY_PATH.md` must stop describing `RecursiveBlockV2` as experimental if it is the shipped bounded lane, and they must stop presenting `RecursiveBlockV1` as anything more than a legacy compatibility/debug envelope. The sizing formulas in `README.md` and `docs/SCALABILITY_PATH.md` must be recomputed against the kept `v2` size if the chunk-size retune changes it.

## Concrete Steps

Work from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

Measure the current or updated `v2` cap and keep a printed report:

    cargo test -p block-recursion tree_v2_proof_cap_report_is_self_consistent -- --nocapture

Then run the bounded-lane verification surface:

    cargo test -p block-recursion prove_and_verify_recursive_artifact_v2_succeeds -- --ignored --nocapture
    cargo test -p block-recursion prove_and_verify_recursive_artifact_v2_at_first_merge_boundary_succeeds -- --ignored --nocapture
    cargo test -p block-recursion prove_and_verify_recursive_artifact_v2_across_first_carry_boundary_succeeds -- --ignored --nocapture
    cargo test -p block-recursion prove_and_verify_recursive_artifact_v2_at_deepest_supported_level_succeeds -- --ignored --nocapture
    cargo test -p block-recursion recursive_artifact_v2_constant_size_at_deepest_supported_level -- --ignored --nocapture

After the runtime/node cutover, verify the shipped default selectors:

    cargo test -p pallet-shielded-pool validate_submit_recursive_candidate_artifact_ -- --nocapture
    cargo test -p hegemon-node default_block_proof_mode_is_recursive_block -- --nocapture
    cargo test -p hegemon-node recursive_block_mode_is_selected_from_env -- --nocapture
    cargo test -p hegemon-node require_native_block_proof_accepts_recursive_block_payload -- --nocapture

Finish with a compile sweep and diff hygiene:

    cargo check -p block-recursion -p consensus -p pallet-shielded-pool -p hegemon-node
    git diff --check -- circuits/block-recursion/src/tree_v2.rs circuits/block-recursion/src/tests.rs pallets/shielded-pool/src/types.rs node/src/substrate/service.rs node/src/substrate/prover_coordinator.rs DESIGN.md METHODS.md README.md docs/SCALABILITY_PATH.md .agent/RECURSIVE_CONSTANT_SIZE_V2_CUTOVER_EXECPLAN.md

## Validation and Acceptance

The cutover is accepted only if all of the following are true on the kept geometry:

- `RecursiveBlockV2` has a derived fixed artifact width below `1,048,576` bytes.
- The ignored `v2` prove/verify tests pass at the base case, first merge boundary, first carry boundary, and deepest supported level.
- `recursive_artifact_v2_constant_size_at_deepest_supported_level` passes, proving the fixed artifact width is preserved through the supported domain.
- The runtime accepts `RecursiveBlockV2` payloads up to the new derived cap and rejects oversized ones.
- The node default shipped recursive lane resolves to `RecursiveBlockV2`.
- The docs no longer describe `RecursiveBlockV1` as the shipped constant-size recursive lane.

## Idempotence and Recovery

All commands in this plan are safe to rerun. The measurement tests only read code and generate deterministic outputs. If a chunk geometry fails, revert only that geometry change and keep the printed/tested rejection reason in this ExecPlan. Do not half-cut over the runtime or docs to `v2` before the bounded-lane tests pass on the kept geometry.

## Artifacts and Notes

The most important artifact is the printed `TreeProofCapReportV2` for the kept geometry. It must show the derived root cap and therefore justify the runtime size cap. The second important artifacts are the passing ignored tests at the merge, carry, and deepest-supported boundaries, because those are what prove the lane is bounded across the supported domain instead of only at shallow cases.

## Interfaces and Dependencies

The kept recursive lane must still use the existing `block_recursion::prove_block_recursive_v2`, `block_recursion::verify_block_recursive_v2`, and `block_recursion::recursive_block_artifact_bytes_v2` interfaces. `pallet_shielded_pool::types::canonical_recursive_block_artifact_kind()` must return `ProofArtifactKind::RecursiveBlockV2` at the end of this work. The node-side default resolver, `pallet_shielded_pool::types::proof_artifact_kind_from_mode(BlockProofMode::RecursiveBlock)`, must therefore select `RecursiveBlockV2` by default once the cutover lands.

Revision note: created this plan to turn the recursive constant-size invariant back into a current, test-backed property instead of a stale `v1` story. The kept shipped point is `RecursiveBlockV2` with `TREE_RECURSIVE_CHUNK_SIZE_V2 = 256` and fixed artifact bytes `788,431`.
