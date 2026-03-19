# InlineTx Authoring Cleanup

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

Hegemon’s shipping topology says ordinary `InlineTx` traffic is already proof-ready when it reaches the public authoring node. After this cleanup, a miner running the normal `InlineTx` lane will admit and mine those proof-ready transactions directly, while still requiring a prepared bundle only for proofless or recursive experiments. A human can see the result by running the focused coordinator and service tests: ordinary `InlineTx` authoring should no longer wait for a prepared bundle, but proofless `MergeRoot` traffic should still do so.

## Progress

- [x] (2026-03-19 02:40Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, `docs/SCALABILITY_PATH.md`, and `config/testnet-initialization.md` to confirm the intended shipping behavior.
- [x] (2026-03-19 02:40Z) Captured the current drift: `node/src/substrate/prover_coordinator.rs` still exposes `InlineTx` authoring only through prepared bundles, and `node/src/substrate/service.rs` still schedules `prepare_block_proof_bundle` work for ordinary canonical inline proofs.
- [x] (2026-03-19 02:46Z) Refactored coordinator and service wiring so proof-ready `InlineTx` authoring bypasses prepared-bundle scheduling while proofless and `MergeRoot` flows keep strict ready-bundle semantics.
- [x] (2026-03-19 02:46Z) Updated focused tests to pin proving-lane behavior to `MergeRoot` and assert direct proof-ready `InlineTx` authoring.
- [x] (2026-03-19 02:46Z) Ran focused validation: `cargo test -p hegemon-node inline_tx_ -- --nocapture`, `cargo test -p hegemon-node pending_transactions_ -- --nocapture`, `cargo test -p hegemon-node throughput_mode_ -- --nocapture`, `cargo test -p hegemon-node upsizing_ -- --nocapture`, `cargo test -p hegemon-node work_package_upsizes_while_smaller_job_is_inflight -- --nocapture`, `cargo test -p hegemon-node parent_ -- --nocapture`, `cargo test -p hegemon-node failed_jobs_release_worker_slots -- --nocapture`, and `cargo test -p hegemon-node mining_pause_reason_ -- --nocapture`.
- [ ] Deploy or soak-test the cleanup on the live OVH/local relay topology if operational rollout is desired.

## Surprises & Discoveries

- Observation: The documentation already describes the desired shipping behavior more cleanly than the current code.
  Evidence: `config/testnet-initialization.md` says “Transactions must already carry canonical tx proof bytes when they reach block assembly” and “The authoring node builds only the parent-bound commitment proof at block assembly time.”

- Observation: The current live patch fixed block assembly but left wasteful background bundle preparation active.
  Evidence: On the live OVH node, the transfer mined in block `87`, but the journal still emitted `prepare_block_proof_bundle` and `Prepared proven batch candidate` before importing the block with `proven_batch_present=false`.

- Observation: Several scheduler tests were implicitly depending on the old “default InlineTx means prepared-bundle authoring” behavior.
  Evidence: The liveness-lane and batch-upsizing tests only kept their intended meaning after being pinned explicitly to `merge_root`.

## Decision Log

- Decision: Treat this as a significant cleanup and write an ExecPlan before editing code.
  Rationale: The bug crosses scheduler behavior, block assembly, operator expectations, and live deployment shape, so the change needs a self-contained record.
  Date/Author: 2026-03-19 / Codex

- Decision: Preserve strict ready-bundle gates only for proofless or recursive paths, not for ordinary proof-carrying `InlineTx` traffic.
  Rationale: This matches the documented shipping topology and the already-working import semantics.
  Date/Author: 2026-03-19 / Codex

- Decision: Keep the prover coordinator in the `InlineTx` path for candidate selection, but stop it from scheduling local proving jobs or mining holds there.
  Rationale: This removes the false dependency without throwing away the existing candidate filtering and parent-rotation plumbing.
  Date/Author: 2026-03-19 / Codex

## Outcomes & Retrospective

The code now matches the shipping docs more closely. Ordinary proof-carrying `InlineTx` authoring uses the selected candidate directly, does not queue local prove-ahead jobs, and does not enable “hold mining while proving” behavior. The proving scheduler, liveness lane, and strict ready-bundle semantics still exist for `MergeRoot`, and the focused tests covering both sides passed locally.

This plan did not include live redeployment. The remaining operational step, if desired, is to rebuild and restart the OVH/local relay nodes on this cleaned commit and verify the logs no longer show `prepare_block_proof_bundle` for ordinary inline-proof transfers.

## Context and Orientation

The relevant authoring code lives in two files. `node/src/substrate/prover_coordinator.rs` owns candidate selection, background proving jobs, and reusable prepared bundles. `node/src/substrate/service.rs` wires that coordinator into block authoring and import validation. A “prepared bundle” in this repository means a `CandidateArtifact` payload that has already been assembled for a specific parent block and candidate set. In the `MergeRoot` proofless experiment, a prepared bundle is required because the shielded transfer extrinsics may omit per-transaction proof bytes. In the shipping `InlineTx` lane, ordinary transactions already carry canonical proof bytes, so the only extra block-level work should be the parent-bound commitment proof that block assembly creates when sealing the block.

The current bug is not import correctness anymore. Import already accepts proof-carrying `InlineTx` blocks without a `submit_candidate_artifact` when no proof bytes are missing. The bug is that the coordinator and authoring wiring still behave as if every `InlineTx` block needs prepared-bundle readiness. That causes wasted local work, misleading logs, and worker-count configuration that only exists to satisfy an unnecessary dependency.

## Plan of Work

First, update `node/src/substrate/prover_coordinator.rs` so `authoring_transactions` returns the ordinary selected candidate in `InlineTx` mode instead of forcing a prepared-bundle lookup. At the same time, update `ProverCoordinatorConfig::from_env` so worker clamping only treats `MergeRoot` as requiring prepared bundles for local mining safety. The coordinator will still retain prepared-bundle logic for recursive and proofless lanes, and it will still support imported reusable artifacts because those are valid for experimentation.

Next, update `node/src/substrate/service.rs` so InlineTx readiness helpers stop pretending a ready bundle matters when no proof bytes are missing. The mining-pause helper has already been partially corrected; the remaining trace and logging paths must match it. If needed, make the coordinator wiring or bundle-builder closure conditional so ordinary `InlineTx` authoring does not queue unnecessary bundle-preparation work.

Finally, replace the now-wrong tests in `node/src/substrate/prover_coordinator.rs` and add or update focused assertions in `node/src/substrate/service.rs` so the expected behavior is explicit: proof-ready `InlineTx` authoring proceeds immediately, while proofless `MergeRoot` still waits for an exact-parent prepared bundle.

## Concrete Steps

Work from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

Inspect the affected coordinator and service logic:

    sed -n '1240,1325p' node/src/substrate/prover_coordinator.rs
    sed -n '4360,4475p' node/src/substrate/service.rs
    sed -n '9660,9895p' node/src/substrate/service.rs

After the edits, run the focused tests:

    cargo test -p hegemon-node inline_tx_authoring_transactions_expose_selected_candidate -- --nocapture
    cargo test -p hegemon-node mining_pause_reason_ -- --nocapture

Final focused validation commands that passed:

    cargo test -p hegemon-node inline_tx_ -- --nocapture
    cargo test -p hegemon-node pending_transactions_ -- --nocapture
    cargo test -p hegemon-node throughput_mode_ -- --nocapture
    cargo test -p hegemon-node upsizing_ -- --nocapture
    cargo test -p hegemon-node work_package_upsizes_while_smaller_job_is_inflight -- --nocapture
    cargo test -p hegemon-node parent_ -- --nocapture
    cargo test -p hegemon-node failed_jobs_release_worker_slots -- --nocapture
    cargo test -p hegemon-node mining_pause_reason_ -- --nocapture

## Validation and Acceptance

Acceptance is behavioral, not stylistic.

Run the focused coordinator test and expect `InlineTx` authoring to expose the selected proof-ready candidate before any prepared bundle exists. Run the mining-pause tests and expect proofless batches to remain gated while proof-carrying inline batches do not pause mining. If a service-level trace helper test is added, it should show that ordinary `InlineTx` candidates do not emit ready-bundle traces when no proof bytes are missing. The cleanup is complete when these tests pass and no assertion still describes prepared-bundle authoring as mandatory for ordinary `InlineTx`.

## Idempotence and Recovery

All edits in this plan are source-only and safe to repeat. Focused tests can be rerun without cleanup. If a partial refactor breaks assumptions, retry by keeping `MergeRoot` strictness intact and narrowing the InlineTx bypass to candidates whose extrinsics already contain canonical proof bytes.

## Artifacts and Notes

Live evidence of the residue this cleanup is removing:

    OVH block 87 journal:
      prepare_block_proof_bundle: start ...
      Prepared proven batch candidate ...
      block_payload_size_metrics ... proven_batch_present=false
      Block imported successfully block_number=87

That log sequence proves the live path worked while still doing unnecessary prepared-bundle work.

## Interfaces and Dependencies

The implementation must keep these repository interfaces coherent:

In `node/src/substrate/prover_coordinator.rs`, `impl ProverCoordinator` must still expose:

    pub fn pending_transactions(&self, max_txs: usize) -> Vec<Vec<u8>>;
    pub fn authoring_transactions(&self, max_txs: usize) -> Vec<Vec<u8>>;

In `node/src/substrate/service.rs`, the following helpers must continue to exist and reflect the new semantics:

    fn mining_pause_reason_for_pending_shielded_batch(...)
    fn ready_bundle_trace_for_candidate(...)

Any worker scheduling or config change must preserve `MergeRoot` and proofless readiness guarantees while removing the false dependency for proof-ready `InlineTx`.

Revision note (2026-03-19, Codex): Initial ExecPlan created after confirming that the code path still schedules prepared bundles for ordinary `InlineTx` authoring despite the shipping docs and live import semantics saying it should not.

Revision note (2026-03-19, Codex): Updated after implementation to record the direct-authoring InlineTx branch, the retained MergeRoot readiness rules, and the focused validation commands that passed locally.
