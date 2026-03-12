# Recursive Aggregation Tree Cutover

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](./PLANS.md).

## Purpose / Big Picture

The current `MergeRoot` path still builds one monolithic recursion proof that verifies every transaction proof directly. That design makes the first strict proofless batch cold-start on one expensive shape, and the coordinator’s published `leaf_batch_prove` / `merge` stage metadata is mostly decorative because only `root_finalize` performs real work. After this cutover, the default fresh-testnet path uses a real fixed-fan-in recursion tree: leaf jobs prove fixed-size batches of transaction proofs, merge jobs prove fixed-size batches of child aggregation proofs, and the root stage only assembles the final `CandidateArtifact` with the root recursive proof plus the commitment proof.

The user-visible result is that additional prover workers can reduce prepared-artifact latency for proofless batches instead of idling behind one root-only proving bottleneck. The observable acceptance target is a strict proofless batch on a fresh testnet that reaches a prepared artifact through leaf and merge stage completions, plus targeted tests that prove consensus accepts V5 recursive payloads and rejects legacy V4 by default.

## Progress

- [x] (2026-03-12 10:11Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, and `config/testnet-initialization.md`.
- [x] (2026-03-12 10:18Z) Audited the current aggregation, consensus, coordinator, RPC, worker, and service paths in `circuits/aggregation/src/lib.rs`, `consensus/src/aggregation.rs`, `consensus/src/proof.rs`, `node/src/substrate/prover_coordinator.rs`, `node/src/substrate/rpc/prover.rs`, `node/src/bin/prover_worker.rs`, and `node/src/substrate/service.rs`.
- [x] (2026-03-12 10:27Z) Confirmed the key technical feasibility point: the vendored recursion stack already exposes recursive batch-proof verification helpers (`verify_p3_recursion_proof_circuit`, `BatchStarkVerifierInputsBuilder`, `generate_batch_challenges`) that can verify child aggregation proofs inside a merge circuit.
- [x] (2026-03-12 04:08Z) Implemented the first V5 cut in `circuits/aggregation`: new V5 payload schema, fixed-size leaf proving, fixed-size merge-over-leaf proving, shape-based ids, and exact-shape prewarm routing through `circuits/aggregation/src/v5.rs`.
- [x] (2026-03-12 04:08Z) Hard-cut consensus verification to V5 by default in `consensus/src/aggregation.rs`, keeping V4 only behind `HEGEMON_AGG_LEGACY_V4`, and added V5-specific error variants in `consensus/src/error.rs`.
- [x] (2026-03-12 04:08Z) Updated block-import metadata checks in `consensus/src/proof.rs` and artifact assembly metadata in `node/src/substrate/service.rs` so `leaf_count`, `tree_levels`, and `leaf_manifest_commitment` match the new leaf tree instead of the old monolithic stub.
- [x] (2026-03-12 04:08Z) Verified targeted compile/tests for the landed slice: `cargo check -p aggregation-circuit`, `cargo check -p consensus`, `cargo test -p aggregation-circuit --test aggregation aggregation_v5_payload_validation_rejects_invalid_encodings -- --nocapture`, and `cargo test -p consensus verify_aggregation_proof_rejects_legacy_payload_version -- --nocapture`.
- [ ] Replace placeholder stage scheduling in `node/src/substrate/prover_coordinator.rs` with a real leaf/merge DAG and local-only root assembly.
- [ ] Extend prover RPC and `node/src/bin/prover_worker.rs` for `leaf_batch_prove` and `merge_node_prove`, and treat stale/rejected packages as normal churn.
- [ ] Update docs/scripts and run the full targeted node/integration harnesses after the node-side DAG lands.

## Surprises & Discoveries

- Observation: the repository already has a recursive verifier for `BatchStarkProof` objects, not just transaction proofs.
  Evidence: `spikes/recursion/vendor/plonky3-recursion/recursion/src/verifier/batch_stark.rs` exports `verify_p3_recursion_proof_circuit`, and the recursion tests under `spikes/recursion/vendor/plonky3-recursion/recursion/tests/` use it to build satisfiable recursive batch-verifier circuits.

- Observation: the coordinator already publishes `leaf_batch_prove` work packages, but the heavy work remains root-only.
  Evidence: `node/src/substrate/prover_coordinator.rs` publishes `stage_type = "leaf_batch_prove"` for external work packages, but `WorkerPool::new` only calls the heavy builder when `job.stage_type == "root_finalize"`; all other stage jobs return `WorkerOutcome::StageOnly`.

- Observation: root metadata already has a composable leaf-manifest hook that can bind tree structure separately from the monolithic V4 public-input blob.
  Evidence: `pallets/shielded-pool/src/types.rs` and `consensus/src/types.rs` already define `MergeRootMetadata { tree_arity, tree_levels, leaf_count, leaf_manifest_commitment }`.

- Observation: `config/testnet-initialization.md` is the actual testnet bootstrap runbook referenced indirectly by `config/testnet/README.md` and `runbooks/two_person_testnet.md`, not a top-level `TESTNET_INITIALIZATION.MD`.
  Evidence: both docs link directly to `/Users/pldd/Projects/Reflexivity/Hegemon/config/testnet-initialization.md`, which states the canonical boot-wallet flow, the approved `HEGEMON_SEEDS` rollout rule, and the NTP/chrony requirement.

- Observation: proving and verifying child aggregation proofs in the recursive merge stage does not require the non-serializable `BatchStarkProof` wrapper to be carried in the payload. The serializable inner `BatchProof` plus cached AIR/common data is sufficient.
  Evidence: `circuits/aggregation/src/v5.rs` and `consensus/src/aggregation/v5.rs` now build merge circuits from cached leaf AIRs/common data and decode only `p3_batch_stark::BatchProof` from `outer_proof`.

- Observation: the current V5 cut is bounded to a two-level tree (`leaf` or `merge-over-leaf`) because the merge recursion is wired specifically against leaf children.
  Evidence: `circuits/aggregation/src/v5.rs` and `consensus/src/aggregation/v5.rs` currently reject non-leaf merge children with `"merge stage currently expects leaf children"` / `"merge nodes currently require leaf children"`.

## Decision Log

- Decision: create a dedicated ExecPlan for this cutover instead of extending the broader permissionless-scaling plan.
  Rationale: this change is a self-contained proving/consensus/coordinator refactor with its own implementation and test matrix, and it needs a restartable document that points a contributor directly at the touched files and validation commands.
  Date/Author: 2026-03-12 / Codex

- Decision: implement merge recursion using the vendored batch-verifier recursion API rather than inventing a bespoke child-proof verifier.
  Rationale: the repo already vendors the exact primitive needed to verify `BatchStarkProof` outputs inside another recursion circuit, which materially reduces risk for the V5 cutover.
  Date/Author: 2026-03-12 / Codex

- Decision: keep `BlockProofMode::MergeRoot` and `MergeRootProofPayload` as the runtime vocabulary while hard-cutting the embedded bytes to V5 recursion.
  Rationale: the on-chain naming is already the accepted fresh-testnet public surface; the required cut is in payload semantics and default verification behavior, not in runtime field names.
  Date/Author: 2026-03-12 / Codex

- Decision: use `config/testnet-initialization.md` as the authoritative bootstrap guide for testnet validation during this work.
  Rationale: it is the actual file shipped in the repo, and it already captures the required boot-wallet, shared-chainspec, `HEGEMON_SEEDS`, and NTP/chrony invariants for fresh-testnet testing.
  Date/Author: 2026-03-12 / Codex

- Decision: ship the first V5 cut as a real two-level tree (`leaf` or `merge-over-leaf`) before generalizing to merge-of-merge recursion.
  Rationale: the immediate throughput acceptance target in the user’s plan is `tx_count=32` and `64`, which fit exactly inside an `8 x 8` leaf/merge tree. General multi-merge recursion requires another layer of node/public-value plumbing in the recursive batch verifier and would have blocked the usable cutover already implemented in circuits/consensus.
  Date/Author: 2026-03-12 / Codex

## Outcomes & Retrospective

The circuit and consensus cutover is now partially landed. The repository compiles with a V5 aggregation payload, leaf proofs recurse over fixed-size transaction-proof groups, merge proofs recurse over fixed-size batches of leaf proofs, and consensus rejects V4 by default unless `HEGEMON_AGG_LEGACY_V4=1` is explicitly set. The block-import metadata path also now expects real leaf-tree metadata instead of the old hard-coded `tree_levels=1` / `leaf_count=1` stub.

The remaining gap is entirely node-side orchestration. The coordinator/RPC/worker stack still needs to publish and consume leaf and merge stage payloads end-to-end so the prepared-bundle path actually scales with external workers. Until that lands, the new V5 proof format exists and can be verified, but the shipped node still uses the old monolithic local assembly path for recursion scheduling.

## Context and Orientation

The current producer path spans three crates and one node service layer.

`circuits/aggregation/src/lib.rs` currently produces `AggregationProofV4Payload` and a single `prove_aggregation(...)` routine that verifies all transaction proofs directly inside one recursion circuit. Its cache keys still depend on `tx_count`, and prewarm targets still derive from batch size rather than the exact leaf and merge shapes that a fixed-fan-in tree needs.

`consensus/src/aggregation.rs` currently decodes and verifies only V4 payloads. It derives `tx_statements_commitment` from the packed recursion public values and rebuilds one verifier cache keyed by `(tx_count, pub_inputs_len, log_blowup, shape)`.

`node/src/substrate/prover_coordinator.rs`, `node/src/substrate/rpc/prover.rs`, and `node/src/bin/prover_worker.rs` already expose a stage-work API. Today that API is misleading for the recursive path: external `leaf_batch_prove` packages exist, but they still expect `CandidateArtifact` submissions rather than stage-specific leaf/merge outputs, and the worker binary only knows how to build a full root payload. `node/src/substrate/service.rs` still prepares a `MergeRoot` artifact by calling `build_merge_root_proof_from_materials(...)`, which calls the monolithic `prove_aggregation(...)`.

Terms used in this plan:

- A “leaf aggregation proof” is a recursive proof that verifies up to `HEGEMON_AGG_LEAF_FANIN` transaction STARK proofs. In this branch the default fan-in is `8`, and incomplete leaves are padded deterministically.
- A “merge aggregation proof” is a recursive proof that verifies up to `HEGEMON_AGG_MERGE_FANIN` child aggregation proofs. The child proofs may be leaf proofs or lower-level merge proofs, but every merge shape is keyed by child shape rather than by live candidate size.
- “Root assembly” means building the final `CandidateArtifact` after the final merge proof already exists. It should generate the commitment proof and package the root recursive proof; it should not perform the heavy recursion proving itself.
- The “leaf manifest commitment” is a composable hash over the ordered leaf descriptors for a candidate. It lets consensus and root assembly bind the recursive tree to canonical transaction order without keeping the old monolithic direct-verifier semantics.

## Plan of Work

The implementation proceeds in five technical slices.

First, replace the monolithic V4 payload path in `circuits/aggregation` with a V5 node model. Add `AggregationProofV5Payload` plus explicit `AggregationNodeKind` values for `leaf` and `merge`. Refactor the prover internals so there are two cache-entry builders: one that verifies fixed-fan-in transaction proofs, and one that verifies fixed-fan-in child aggregation proofs using the vendored batch-recursion API. The leaf cache key must be shape-based `(node_kind=leaf, fan_in, inner_tx_shape, pub_inputs_len, log_blowup)` and the merge cache key must be shape-based `(node_kind=merge, fan_in, child_shape_id, child_public_inputs_len)`. Add `prove_leaf_aggregation(...)`, `prove_merge_aggregation(...)`, and exact-shape thread-local prewarm helpers.

Second, hard-cut `consensus/src/aggregation.rs` to V5 by default. Keep V4 decode and verification only behind an explicit environment gate for rollback. The verifier must understand both node kinds so coordinator-side and unit tests can verify leaf, merge, and root payloads. Root verification must derive the canonical statement commitment from the recursively packed public values, reject mismatched `child_count`, `tree_levels`, `shape_id`, or `tx_statements_commitment`, and reject V4 on the fresh chain when the legacy gate is absent.

Third, rework the coordinator into a real proving DAG. Candidate scheduling still begins from the ordered shielded transaction set, but instead of publishing decorative leaves plus one root package, it must materialize leaf packages over contiguous proof slices, wait for leaf completions, publish deterministic merge packages, and only when the final merge result exists perform local root assembly into a prepared `CandidateArtifact`. The state machine must preserve expiry and rate limits while treating stale or rejected packages as ordinary churn instead of fatal worker errors.

Fourth, extend the prover RPC and worker binary for stage-specific payloads. `node/src/substrate/rpc/prover.rs` needs additive payload objects for `leaf_batch_prove` and `merge_node_prove`. The worker binary must dispatch on `stage_type`, prove the requested node, submit a typed stage result, and keep polling when a package is stale or rejected. `root_finalize` should become local-only unless the implementation discovers an unavoidable dependency that still needs it externalized.

Fifth, update docs and scripts. `DESIGN.md` and `METHODS.md` must describe the V5 tree semantics, exact-shape prewarm, and the fact that `FlatBatches` is optional compatibility rather than the main scaling lane. `scripts/throughput_sidecar_aggregation_tmux.sh` must enable blocking prewarm when `HEGEMON_TP_AGG_PREWARM_MAX_TXS > 0` and widen the RPC wait accordingly. Operator-facing notes must continue to repeat the approved `HEGEMON_SEEDS` rule and the NTP/chrony requirement from `config/testnet-initialization.md`.

## Concrete Steps

All commands run from repository root `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Implement and iterate on the aggregation/prover/consensus code:

    cargo test -p aggregation-circuit --tests aggregation -- --nocapture
    cargo test -p consensus aggregation -- --nocapture
    cargo test -p hegemon-node prover_coordinator -- --nocapture
    cargo test -p hegemon-node prover_rpc -- --nocapture

2. Validate the worker and stage loop on a local dev chain:

    make node
    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

3. Exercise the strict proofless path with the throughput harness using the fresh-testnet bootstrap assumptions from `config/testnet-initialization.md` when moving beyond a local `--dev` node.

4. If the full workspace remains green after targeted fixes, run:

    make check

## Validation and Acceptance

Acceptance for this cutover is behavior, not just compiled code.

`circuits/aggregation` must have tests that round-trip a leaf V5 proof for fan-in `8`, a merge V5 proof for fan-in `8`, a root verification path over a two-level tree, and cache prewarm that produces a cache hit on second use.

`consensus` must verify V5 leaf, merge, and root payloads, reject V4 by default, and reject malformed `child_count`, `tree_levels`, `shape_id`, and `tx_statements_commitment`.

`node` tests must prove that the coordinator creates `ceil(tx_count / leaf_fanin)` leaf packages, turns completed leaves into deterministic merge packages, assembles a final `CandidateArtifact` after the merge root is ready, allows the external worker to consume leaf and merge packages, and keeps the worker loop alive when a package has gone stale.

Integration acceptance is a strict proofless batch that produces a prepared artifact before timeout, plus throughput runs where prepared-bundle latency improves as external worker count increases for `tx_count=32` and `tx_count=64`.

## Idempotence and Recovery

These changes are source-only and safe to rerun. Use `--dev --tmp` or explicit temporary base paths for all local node runs so retries do not require hand-cleaning persistent chain state. If the fresh-testnet validation moves onto a shared chainspec, follow `config/testnet-initialization.md`: do not improvise wallets, use the laptop-created boot-wallet address as the payout address everywhere, keep the same `config/dev-chainspec.json` on every host, keep the exact approved `HEGEMON_SEEDS` list on all miners and provers once the fresh rollout publishes it, and keep NTP/chrony enabled because future-skewed PoW timestamps are rejected.

If rollback is required during implementation, the safe fallback is the explicit V4 legacy gate in consensus rather than silently accepting both formats by default.

## Artifacts and Notes

Important file paths for this cutover:

- `circuits/aggregation/src/lib.rs`
- `circuits/aggregation/tests/aggregation.rs`
- `consensus/src/aggregation.rs`
- `consensus/src/error.rs`
- `consensus/src/proof.rs`
- `node/src/substrate/prover_coordinator.rs`
- `node/src/substrate/rpc/prover.rs`
- `node/src/bin/prover_worker.rs`
- `node/src/substrate/service.rs`
- `scripts/throughput_sidecar_aggregation_tmux.sh`
- `config/testnet-initialization.md`

Evidence snippets and final command output will be appended here as milestones complete.

## Interfaces and Dependencies

The implementation must leave these interfaces in place:

- In `circuits/aggregation/src/lib.rs`, define:

    pub const AGGREGATION_PROOF_FORMAT_ID_V5: u8 = 5;
    pub enum AggregationNodeKind { Leaf, Merge }
    pub struct AggregationProofV5Payload { ... }
    pub fn prove_leaf_aggregation(...) -> Result<Vec<u8>, AggregationError>;
    pub fn prove_merge_aggregation(...) -> Result<Vec<u8>, AggregationError>;
    pub fn prewarm_leaf_and_merge_caches_from_env() -> Result<(), AggregationError>;

- In `consensus/src/aggregation.rs`, expose V5 verification entry points that accept the same top-level call sites used by `consensus/src/proof.rs`, and keep V4 support off by default behind an explicit environment check.

- In `node/src/substrate/rpc/prover.rs`, extend `WorkPackageResponse` with additive stage payload objects:

    pub leaf_batch_payload: Option<LeafBatchPayloadResponse>
    pub merge_node_payload: Option<MergeNodePayloadResponse>

- In `node/src/substrate/prover_coordinator.rs`, the work DAG must become stage-based and shape-based instead of monolithic root-only scheduling. Stage results must distinguish leaf recursive proofs, merge recursive proofs, and final assembled artifacts.

- In `node/src/bin/prover_worker.rs`, dispatch must handle `leaf_batch_prove` and `merge_node_prove` and keep looping on stale/rejected work instead of exiting.

Plan update note (2026-03-12 10:31Z / Codex): Created this ExecPlan before implementation so the recursive-tree cutover has a self-contained execution record separate from the broader permissionless-scaling plan.
