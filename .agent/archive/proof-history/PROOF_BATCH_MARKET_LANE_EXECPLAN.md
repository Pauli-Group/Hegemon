# Proof-Bytes Batch Market Lane

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Repository policy reference: `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, Hegemon will no longer treat witness-based batching or generic recursive aggregation as the only path for parallel external provers. Instead, the repository will have a new proof-bytes batch primitive that accepts canonical transaction proof bytes plus decoded public inputs, emits fixed-shape batch proof artifacts, and lets the coordinator publish parent-independent chunk work. The block author will still bind the ordered transaction set to the chosen parent with the existing commitment proof, but the heavy work package that a prover market performs will no longer require spend witnesses and will no longer be keyed by parent hash.

The user-visible result is that the flat proving lane can be re-enabled without leaking witness secrets. A prover worker will be able to accept a work package, prove a chunk using only transaction proof material, submit that result, and the node will assemble a contiguous `FlatBatches` payload for inclusion while still using the block commitment proof for parent binding.

## Progress

- [x] (2026-03-14 00:00Z) Read current `DESIGN.md`, `METHODS.md`, `consensus/src/proof.rs`, `consensus/src/batch_proof.rs`, `circuits/batch`, `circuits/aggregation`, and coordinator/service paths to confirm the current split-brain design.
- [x] Add a new `circuits/proof-batch` crate whose witness is canonical transaction proof bytes plus decoded transaction public inputs, and whose public outputs are ordered statement hashes, ordered padded nullifiers, ordered padded commitments, and total fee.
- [x] Extend `consensus/src/batch_proof.rs` with a new flat-batch proof kind for proof-bytes batch proofs while preserving the payload envelope and contiguous-coverage semantics.
- [x] Update `consensus/src/proof.rs` to verify the new proof-batch payload kind and to check the public outputs against the covered transaction subset.
- [x] Rewire `node/src/substrate/service.rs` so `PreparedProofMode::FlatBatches` uses the new proof-batch crate instead of the witness-batch crate or the current hard error.
- [x] Change `node/src/substrate/prover_coordinator.rs` so parent-independent chunk work ids derive only from ordered tx content / proof content, while the final prepared bundle remains keyed by parent hash because the commitment proof stays parent-bound.
- [x] Update `DESIGN.md` and `METHODS.md` to describe the new proof-batch lane and the trust-model distinction between witness batching and proof batching.
- [x] Run focused tests for the new crate, consensus flat-batch verification, and node coordinator/service proof flow.

## Surprises & Discoveries

- Observation: `node/src/substrate/service.rs` still rejects `PreparedProofMode::FlatBatches` outright with the message `flat batch proof mode is disabled: witness sidecar uploads are blocked; use merge-root aggregation proofs`.
  Evidence: `node/src/substrate/service.rs:3137`.

- Observation: `circuits/batch` is explicitly documented as a bounded wallet/trusted utility path and not the public scaling lane.
  Evidence: `circuits/batch/src/lib.rs:7-10`.

- Observation: the existing batch prover is witness-based and derives nullifiers from `prf_key(&witness.sk_spend)`, which makes it unsuitable as a permissionless external prover-market primitive.
  Evidence: `circuits/batch/src/p3_prover.rs:40-42` and `circuits/batch/src/p3_prover.rs:120-123`.

- Observation: the existing batch prover calls `setup_preprocessed()` inside `prove()`, which means preprocessed setup work is paid per job unless memoized above that API.
  Evidence: `circuits/batch/src/p3_prover.rs:171-188`.

- Observation: current fan-out chunk assembly and work-package ids are still parent-bound.
  Evidence: `node/src/substrate/prover_coordinator.rs:1491-1495`, `node/src/substrate/prover_coordinator.rs:1523`, and `node/src/substrate/prover_coordinator.rs:2552-2560`.

- Observation: the external flat worker path had already drifted into a broken half-state before this refactor. `hegemon-prover-worker` imported proof-batch RPC payload types that did not exist in `node/src/substrate/rpc/prover.rs`, while coordinator flat packages carried no proveable payload at all.
  Evidence: `node/src/bin/prover_worker.rs` imported `FlatChunkPayloadResponse` / `FlatChunkCommonPayloadResponse`, but `node/src/substrate/rpc/prover.rs` exposed no such fields and `node/src/substrate/prover_coordinator.rs` populated flat `WorkPackage`s with `leaf_batch_payload: None`.

## Decision Log

- Decision: keep the existing block-level commitment proof as the only parent-bound proof on the critical path.
  Rationale: the commitment proof is already the cheap parent-binding artifact and consensus already knows how to verify it.
  Date/Author: 2026-03-14 / Codex.

- Decision: do not reuse `circuits/batch` as the permissionless prover-market primitive.
  Rationale: it consumes `TransactionWitness`, derives nullifiers from spend secret material, and is explicitly documented as a non-public utility path.
  Date/Author: 2026-03-14 / Codex.

- Decision: preserve the flat-batch payload envelope in consensus and add a new proof kind behind that envelope instead of inventing a brand new block semantics.
  Rationale: `verify_flat_batch_payload` already enforces exact contiguous coverage and subset/public-output matching; replacing the proving primitive under the envelope is lower risk.
  Date/Author: 2026-03-14 / Codex.

- Decision: make chunk work ids parent-independent, but keep final prepared bundles parent-bound.
  Rationale: chunk work should be reusable across parent changes, while the commitment proof binds the final block candidate to a specific parent state transition.
  Date/Author: 2026-03-14 / Codex.

## Outcomes & Retrospective

This section will be updated after implementation milestones land. The expected outcome is that the repository stops forcing flat-batch authoring back onto `MergeRoot`, gains a witness-safe public batch primitive, and narrows the live proving path to a parent-independent batch stage plus the existing parent-bound commitment stage.

Implemented on 2026-03-14:

- Added `circuits/proof-batch` as a proof-byte batch primitive. Its witness model is canonical transaction proof bytes plus decoded transaction public inputs, and its verifier replays single-tx proof verification before checking ordered statement hashes, padded nullifiers, padded commitments, fee sum, and circuit version.
- Added flat-batch proof kind `2` in consensus for proof-byte batches while preserving `FlatBatchProofPayloadV2`.
- Re-enabled `PreparedProofMode::FlatBatches` in the node service. The local prepare path now produces proof-byte batch payloads instead of hard-erroring.
- Rewired the coordinator flat lane to publish real `proof_batch_prove` work packages with proof material when root-finalize data is available. Chunk ids are parent-independent; the final prepared bundle still uses `candidate_bundle_key(parent_hash, payload)` because the commitment proof remains parent-bound.
- Rewired the prover RPC / worker path so external flat workers can actually consume a proof-batch payload and submit chunk results.

Focused validation completed:

- `cargo test -p proof-batch --lib`
- `cargo test -p consensus batch_proof -- --nocapture`
- `cargo test -p hegemon-node prover_coordinator -- --nocapture`

## Context and Orientation

The current proving split lives across four main areas.

`circuits/batch` defines a slot-copy batch STARK that copies single-transaction traces into fixed slots. It is fast enough to be interesting, but it is witness-based and therefore unsuitable for a permissionless external prover market.

`circuits/aggregation` defines proof-bytes recursive aggregation over transaction proofs. This is safe for external provers because it consumes proof bytes instead of spend witnesses, but it has been too expensive on the live path.

`consensus/src/batch_proof.rs` defines the flat-batch proof payload envelope used on-chain. Right now it only supports the witness-batch proof kind. `consensus/src/proof.rs` enforces contiguous batch coverage and checks batch public outputs against the covered transactions.

`node/src/substrate/service.rs` and `node/src/substrate/prover_coordinator.rs` own the live authoring and prover-market paths. Today they still force `FlatBatches` off in the prepare path and use parent-bound work ids for chunk plans.

The term “proof-batch” in this plan means a new circuit crate whose witness is a list of canonical transaction proof bytes and decoded public inputs, not raw spend witnesses. The term “parent-independent” means the work id and proving task do not depend on the current parent hash or block number. The term “parent-bound” means the artifact proves something about the exact chosen parent state root, which is currently only true for the commitment proof.

## Plan of Work

First create a new crate at `circuits/proof-batch`. This crate will expose a proof format and public-input structure for fixed-size proof batches. The witness will include, for each transaction in the chunk, the canonical transaction proof bytes and decoded transaction public inputs. The public output structure will expose the ordered statement hashes, ordered padded nullifiers, ordered padded commitments, total fee, and batch size. For the first implementation, the crate may internally verify transaction proofs outside the AIR before constructing the batch witness, but the public API must be proof-byte based and must not accept `TransactionWitness`.

Then extend `consensus/src/batch_proof.rs` with a second `proof_kind` for proof-batch proofs. Keep the envelope shape `FlatBatchProofPayloadV2`, but add a codec path for the new proof kind. The new payload must carry proof bytes plus the canonical field-element encoding of the proof-batch public outputs.

Next update `consensus/src/proof.rs`. In `verify_flat_batch_payload`, add a branch for the new proof kind. That branch must decode the proof-batch public outputs, verify the proof with the new crate, check contiguous coverage, compare ordered nullifiers and commitments against the covered transaction subset, check total fee, and validate statement hashes or a subset commitment derived from them. The existing `BatchStark` path must continue to work.

Then rewire the node service path in `node/src/substrate/service.rs`. The `PreparedProofMode::FlatBatches` branch must stop hard-erroring and instead build flat-batch chunk proofs using the new proof-batch crate from transaction proof bytes already available in candidate context. The current witness-batch helper should not be used for the external market lane.

Finally update `node/src/substrate/prover_coordinator.rs`. Introduce a parent-independent candidate artifact id derived only from the ordered candidate transaction/proof content. Use that id for `candidate_set_id` and chunk `package_id` generation. Leave `PreparedBundle` and `BundleMatchKey` parent-bound because the assembled payload still includes the parent-bound commitment proof. The coordinator should still track which parent a currently assembled prepared bundle targets, but chunk work identity should survive parent changes.

## Concrete Steps

From repository root:

1. Create the new crate and add it to the workspace:

    mkdir -p circuits/proof-batch/src

2. Add its `Cargo.toml`, `src/lib.rs`, prover/verifier/public-input modules, and tests.

3. Update:

    consensus/src/batch_proof.rs
    consensus/src/proof.rs
    consensus/src/lib.rs
    node/src/substrate/service.rs
    node/src/substrate/prover_coordinator.rs
    node/src/substrate/rpc/prover.rs
    DESIGN.md
    METHODS.md

4. Run formatter:

    cargo fmt --all

5. Run focused checks:

    cargo test -p proof-batch --lib
    cargo test -p consensus batch_proof -- --nocapture
    cargo test -p hegemon-node prover_coordinator -- --nocapture

If macOS build-time `libclang` is needed:

    export LIBCLANG_PATH=/Library/Developer/CommandLineTools/usr/lib
    export DYLD_LIBRARY_PATH=/Library/Developer/CommandLineTools/usr/lib

## Validation and Acceptance

Acceptance is behavioral:

- `PreparedProofMode::FlatBatches` must no longer fail with the “flat batch proof mode is disabled” error.
- A flat work package must be proveable using only transaction proof bytes and decoded public inputs, with no `TransactionWitness` involved.
- `verify_flat_batch_payload` must accept a valid proof-batch payload and reject:
  - coverage gaps
  - coverage overlaps
  - mismatched nullifiers
  - mismatched commitments
  - mismatched fee totals
  - malformed proof kind / payload versions
- Coordinator chunk `candidate_set_id` / `package_id` generation for proof-batch jobs must not depend on parent hash or block number.
- Final prepared bundle lookup must remain parent-bound through the commitment proof path.

## Idempotence and Recovery

This plan is additive. Creating the new crate and payload kind is safe to repeat. If the new proof-batch path fails partway through implementation, the repository can still fall back to the existing `MergeRoot` lane by restoring the previous `PreparedProofMode::FlatBatches` error branch, but that should be treated only as a temporary rollback. Avoid deleting `circuits/batch`; keep it available for trusted/local batching experiments.

## Artifacts and Notes

Important evidence for this refactor:

    node/src/substrate/service.rs:3137
      PreparedProofMode::FlatBatches => Err("flat batch proof mode is disabled ...")

    circuits/batch/src/lib.rs:7-10
      "not the primary world-commerce throughput lane"

    circuits/batch/src/p3_prover.rs:121
      let prf = prf_key(&witness.sk_spend);

    circuits/batch/src/p3_prover.rs:187
      let (prep_prover, _) = setup_preprocessed(...)

    node/src/substrate/prover_coordinator.rs:2552-2560
      work_package_id(parent_hash, block_number, candidate_txs)

## Interfaces and Dependencies

Create in `circuits/proof-batch/src/lib.rs`:

    pub struct ProofBatchWitnessEntry {
        pub proof_bytes: Vec<u8>,
        pub public_inputs: transaction_circuit::public_inputs::TransactionPublicInputs,
        pub statement_hash: [u8; 48],
    }

    pub struct ProofBatchPublicInputs {
        pub batch_size: u32,
        pub statement_hashes: Vec<[u8; 48]>,
        pub nullifiers: Vec<[u8; 48]>,
        pub commitments: Vec<[u8; 48]>,
        pub total_fee: u64,
        pub circuit_version: u32,
    }

    pub fn prove_proof_batch(
        entries: &[ProofBatchWitnessEntry],
    ) -> Result<(Vec<u8>, ProofBatchPublicInputs), ProofBatchError>;

    pub fn verify_proof_batch(
        proof_bytes: &[u8],
        public_inputs: &ProofBatchPublicInputs,
    ) -> Result<(), ProofBatchError>;

Extend `consensus/src/batch_proof.rs` with a new proof kind constant and matching encode/decode helpers for the proof-batch public values.

In `node/src/substrate/prover_coordinator.rs`, define a parent-independent candidate id helper alongside the existing parent-bound bundle key helpers. The chunk work-package id helper must use the parent-independent candidate id plus chunk offsets/counts, not `parent_hash` or `block_number`.

Update note (2026-03-14 / Codex): created before implementation to satisfy `.agent/PLANS.md` for this significant prover-lane refactor.
