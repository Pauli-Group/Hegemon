# Eliminate Linear Import Cost With A Receipt-Root Accumulation Layer

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

## Purpose / Big Picture

Hegemon’s native lane already has promising bytes and promising edge-proving numbers. The remaining structural blocker is import. Today, import still resolves and verifies every tx-level leaf before accepting a `ReceiptRoot`, which means verifier work remains linear in the block size. After this plan, Hegemon will have an accumulation prototype that can prove or at least tightly test the next architectural step: import verifying a root artifact plus a small residual object, instead of re-verifying every leaf. That is the difference between “interesting native lane” and a believable path to `10s` and `100s` of TPS.

The user-visible behavior after the first milestone is a new experimental accumulation lane with benchmark and import hooks. A contributor should be able to run a benchmark or import test and compare current `ReceiptRoot` behavior against an accumulation prototype using the same ordered native tx leaf receipts.

## Progress

- [x] (2026-03-26 02:02Z) Re-read `.agent/PLANS.md`, `.agent/PROOF_BACKEND_MIGRATION_EXECPLAN.md`, `.agent/SUPERNEO_EXPERIMENT_EXECPLAN.md`, `METHODS.md`, `DESIGN.md`, and the current `ReceiptRoot` verifier path.
- [x] (2026-03-26 02:02Z) Confirmed that the live structural issue is linear import verification through the tx-artifact verifier loop in `ReceiptRootVerifier`.
- [x] (2026-03-26 02:02Z) Authored this ExecPlan as a dedicated roadmap for the import-killing accumulation branch.
- [ ] Add a reusable verified-native-leaf store that survives across candidate assembly and repeated import checks.
- [ ] Add artifact-hash references so block import can hit the verified-leaf store before touching the full proof bytes.
- [ ] Define a generic accumulation interface over canonical native tx-validity receipts.
- [ ] Prototype the first accumulation backend, prioritizing the transparent/code-based branch.
- [ ] Add import benchmarks that compare current `ReceiptRoot` verification against the accumulation prototype at `k=16,32,64,128`.
- [ ] Promote or kill the prototype based on measured import reduction and complexity.

## Surprises & Discoveries

- Observation: Hegemon already has the right consensus boundary for this work. The hard part is not consensus surgery; it is replacing the inner verification pattern.
  Evidence: `ProofEnvelope`, `TxValidityArtifact`, and the verifier registry already exist in [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs#L158) and [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs#L188).

- Observation: the current `ReceiptRoot` path is native-only but still linear on import.
  Evidence: `ReceiptRootVerifier` calls the generic tx-artifact verifier across all artifacts in [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs#L505).

- Observation: not all recent accumulation work attacks the same problem. Some papers primarily reduce prover costs, while others directly target accumulation depth, verifier queries, or code-based oracle reuse.
  Evidence: `WARP`, `FACS`, `Arc`, `BOIL`, and `WHIR` live on the accumulation / code / verifier side, while `2026/587` is a prover-optimization paper.

## Decision Log

- Decision: build this plan around canonical native tx-validity receipts, not around raw `TransactionProof`s and not around ad hoc tx-leaf bytes.
  Rationale: receipts are the stable parent-independent binding that already fits the proof-backend-neutral architecture and generalizes across future backends.
  Date/Author: 2026-03-26 / Codex

- Decision: prototype the transparent/code-based accumulation branch first.
  Rationale: `WARP`, `FACS`, `Arc`, `BOIL`, and `WHIR` most directly target the exact problem Hegemon has today: too much per-leaf verifier work. They are also structurally closer to the existing proof-neutral artifact architecture than a full new folding backend would be.
  Date/Author: 2026-03-26 / Codex

- Decision: stage this plan so the first milestones improve import even before the final accumulation backend exists.
  Rationale: a verified-leaf store and artifact-hash references give immediate operational benefit and also provide the substrate the final accumulator will need anyway.
  Date/Author: 2026-03-26 / Codex

## Outcomes & Retrospective

This plan is design-only at creation time. No new accumulation backend or import decider exists yet. The expected outcome is a staged reduction of import work: first by reusing verified leaves, then by allowing blocks to reference previously verified artifacts, and finally by replacing linear per-leaf import with a root-level accumulation proof.

## Context and Orientation

In Hegemon, a “receipt” is the canonical, parent-independent binding of a transaction-validity proof or native tx-validity artifact to the statement it proves. A “leaf” is the tx-level proof artifact. A “root” is the block-level aggregate over the ordered leaf set. An “accumulation scheme” is a proof system that combines many verification obligations into one smaller obligation. For Hegemon, the reason to care is simple: if import must still verify every leaf, the chain remains verifier-linear even if the leaf bytes are tiny.

The current import path is in `consensus/src/proof.rs`. `NativeTxLeafVerifier` verifies a native tx leaf and caches successful results in a local LRU-style cache. `ReceiptRootVerifier` still calls `verify_tx_validity_artifacts(...)` across the whole artifact set before verifying the root. The architecture already has a neutral proof envelope and a neutral tx-artifact type, so this plan does not need to redesign consensus. It needs to change what the receipt-root lane proves and how import reuses verified work.

The recent paper lines relevant to this plan are the code-based and accumulation papers: `WARP` for linear-time hash-based accumulation, `FICS/FACS` for fast IOPPs and accumulation via code-switching, `Arc` for Reed–Solomon accumulation, `BOIL` for correlated holographic IOP accumulation, and `WHIR` for fast Reed–Solomon proximity verification. This plan does not assume one of them is already the answer. It requires prototyping against Hegemon’s actual import surface before promotion.

## Plan of Work

Begin with the import substrate that any future accumulation lane needs. Add a verified-native-leaf store keyed by artifact hash and statement commitment, not just the current in-process `(tx_id, artifact_digest)` cache. This store should live at the node or consensus boundary and survive long enough to benefit repeated candidate assembly, repeated block validation, and peer-announced artifact reuse. The first milestone is complete when import can skip full native-leaf verification for artifacts that have already been verified locally and whose statement binding matches the current block’s ordered statement set.

Next, teach block artifacts and the artifact market to reference verified leaves by digest instead of always embedding every proof byte inline. This does not yet eliminate verification, but it changes the import surface from “here are all the bytes, verify them again” to “here is the root artifact and here are the expected verified leaf digests.” The purpose is to make root-level verification and cached admission-time verification compose cleanly.

Once the substrate exists, define a generic accumulation interface over canonical tx-validity receipts. Put this interface behind the proof-neutral boundary, not inside one backend crate. The interface should allow a backend to absorb ordered receipts or ordered verified-leaf digests, produce an accumulation artifact, and verify that artifact against the ordered receipt set and the expected statement commitment.

Then prototype the first backend. The preferred order is `FACS/WHIR` first, then `WARP`, then `Arc/BOIL` if the first two stall. The prototype does not need to ship on the first pass, but it must be real enough to benchmark import behavior. That means it must emit an actual block artifact kind, register a verifier adapter, and be exercised through the same consensus import path as `ReceiptRoot`.

Finally, benchmark cold and warm import at `k=16,32,64,128`. If the accumulation prototype does not materially reduce import work relative to the current native `ReceiptRoot` lane, kill it cleanly and document why. The purpose of this plan is to answer the question, not to preserve a fashionable paper line.

## Concrete Steps

From the repo root `/Users/pldd/Projects/Reflexivity/Hegemon`, implement this plan in the following order.

1. Extend the current native-leaf cache into a reusable verified-artifact store and add targeted tests:

       cargo test -p consensus receipt_root_ -- --nocapture
       cargo test -p hegemon-node receipt_root -- --nocapture

2. Add artifact-hash references and wire them through the artifact-market and block-import path.

3. Define the generic accumulation interface and add a new experimental block artifact kind for the prototype backend.

4. Implement the first backend candidate and benchmark it with:

       cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 16,32,64,128 --compare-inline-tx

   plus a new import benchmark or test harness specific to the accumulation prototype.

5. Record the measured import delta and decide whether to promote or kill the backend.

## Validation and Acceptance

Acceptance happens in layers.

The first acceptance point is operational reuse: repeated verification of the same native tx leaf across candidate assembly or repeated import attempts must hit a verified-artifact store rather than re-run full verification. The second acceptance point is block shape: the experimental accumulation artifact must verify through the proof-neutral consensus boundary without special-case imports. The final acceptance point is performance: the accumulation lane must reduce import work materially at the larger `k` values that matter for scalability.

The benchmark criterion is not subtle. If the new lane does not obviously beat the current linear-import native `ReceiptRoot` path at `k=32,64,128`, it does not earn a product roadmap slot.

## Idempotence and Recovery

Each stage in this plan is additive. The verified-artifact store can land before the final accumulation backend. Artifact-hash references can coexist with byte-carrying artifacts during migration. If the chosen accumulation backend loses, remove only that backend adapter and keep the reusable verified-artifact substrate.

## Artifacts and Notes

The current choke point this plan is meant to remove is visible in:

    consensus/src/proof.rs
        ReceiptRootVerifier::verify_block_artifact(...)
        -> verify_tx_validity_artifacts(...)
        -> verify every native tx leaf before verifying the root

The first benchmark or import report added by this plan must print both the old path and the new accumulation path side by side for the same `k` values. Without that, the plan has not produced a decision-grade result.

## Interfaces and Dependencies

This plan should introduce a generic accumulation interface. Preferred names are:

    pub trait ReceiptAccumulator: Send + Sync {
        fn kind(&self) -> ProofArtifactKind;
        fn verifier_profile(&self) -> VerifierProfileDigest;
        fn build(
            &self,
            receipts: &[TxValidityReceipt],
            artifacts: &[TxValidityArtifact],
        ) -> Result<ProofEnvelope, ProofError>;
        fn verify(
            &self,
            receipts: &[TxValidityReceipt],
            expected_commitment: &[u8; 48],
            envelope: &ProofEnvelope,
        ) -> Result<BlockArtifactVerifyReport, ProofError>;
    }

If a persistent verified-leaf store is added, prefer a neutral interface such as:

    pub trait VerifiedTxArtifactStore {
        fn get(&self, artifact_hash: [u8; 48]) -> Option<TxStatementBinding>;
        fn put(&self, artifact_hash: [u8; 48], binding: TxStatementBinding);
    }

Keep the first backend under an experimental namespace. This plan is about import architecture, not about prematurely sanctifying one paper family.

Revision note: this ExecPlan was created on 2026-03-26 to turn the “import is still linear” diagnosis on the native `ReceiptRoot` lane into an executable roadmap. It intentionally combines immediate operational reuse steps with a later accumulation prototype so the branch can make progress even before one specific paper line wins.
