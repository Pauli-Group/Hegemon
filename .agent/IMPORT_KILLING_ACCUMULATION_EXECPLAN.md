# Build A Real ARC/WHIR Cold-Import Accumulator

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, a fresh Hegemon peer will be able to import an experimental receipt lane block from block contents alone, without a warm verified-leaf store and without replaying per-transaction native leaf verification. The block will carry receipt-only transaction artifacts plus one residual block artifact built by a new Reed-Solomon accumulation backend. The user-visible proof that this worked is a release benchmark that shows cold verification at `k=32,64,128` beating the current linear native `ReceiptRoot` baseline while keeping `cold_residual_replayed_leaf_verifications = 0`.

This plan replaces the previous accumulation plan because that plan drifted into wrappers around the old aggregation backend. The fix is not “be more disciplined.” The fix is to choose one research line that actually matches the cold-import goal and write the implementation contract around it.

After checking the papers again, the right primary line is `ARC -> WHIR`, not `FACS -> WHIR`.

- `ARC` is explicitly an accumulation scheme for Reed-Solomon code proximity claims.
- `WHIR` is explicitly a Reed-Solomon proximity test with super-fast verification.

That split is internally coherent for Hegemon’s cold-import problem. `FICS/FACS` remains relevant as a secondary code-switching line, but it is not the first plan of attack here.

## Progress

- [x] (2026-03-26 21:08Z) Replaced the previous drift-prone accumulation plan with a paper-checked `ARC -> WHIR` plan.
- [x] (2026-03-26 21:08Z) Recorded the current honest starting point: `receipt_accumulation` is warm-store-only; `receipt_decider` and `receipt_residual_diag` are rejected negative results.
- [x] (2026-03-26 22:11Z) Hardened the warm-store-only `receipt_accumulation` experiment so cached prove-ahead hits re-run verified-leaf prewarm before they reuse a stored accumulation payload.
- [ ] Create a new standalone `circuits/receipt-arc-whir` crate that proves and verifies a receipt-only residual artifact without any dependency on the old aggregation backend.
- [ ] Define a canonical receipt-row encoding and receipt commitment that bind all receipt fields, not just `statement_hash`.
- [ ] Implement an `ARC` accumulation layer that compresses many ordered Reed-Solomon proximity claims over receipt rows into one residual claim.
- [ ] Implement a `WHIR` verification layer for that residual claim over the committed Reed-Solomon codeword.
- [ ] Add a consensus verifier that accepts only receipt-only tx artifacts and one `receipt_arc_whir` block artifact.
- [ ] Add node authoring/import support behind `HEGEMON_BLOCK_PROOF_MODE=receipt_arc_whir`.
- [ ] Add a diagnostic benchmark lane `native_tx_leaf_receipt_arc_whir` and decision-grade cold runs at `k=32,64,128`.
- [ ] Promote or kill the lane strictly by the acceptance criteria in this document.

## Surprises & Discoveries

- Observation: warm-store reuse is real, but it is not the target.
  Evidence: `receipt_accumulation` reduces warm verification dramatically only after verified-leaf prewarm; it fails closed on cold import.

- Observation: cached warm-store payloads still need current warm-store state.
  Evidence: prove-ahead cache hits for `receipt_accumulation` must re-run verified-leaf prewarm before reuse; otherwise the cached payload can outlive the verifier-local store entries it still assumes.

- Observation: a “self-contained cold lane” can still be garbage if it embeds per-tx proof objects or replays per-leaf verification.
  Evidence: `receipt_decider` and `receipt_residual_diag` were both removed after review and benchmarking.

- Observation: the easiest failure mode is backend drift.
  Evidence: earlier cold-lane attempts reused `prove_aggregation(...)` and `verify_aggregation_proof_safely(...)`, which made them wrappers around the old aggregation backend instead of a new accumulator.

- Observation: the original `FACS -> WHIR` split was too loose.
  Evidence: after re-checking the paper line, `FICS/FACS` is one code-switching family and `ARC/WHIR` is the cleaner Reed-Solomon-specific accumulation plus verifier split.

- Observation: `WHIR` is still relevant, but conservative parameterization matters.
  Evidence: `WHIR` is explicitly a Reed-Solomon proximity verifier, but later work on mutual correlated agreement means the implementation should stay on conservative, explicit parameters instead of hand-wavy “up to capacity” language.

## Decision Log

- Decision: use `ARC -> WHIR` as the primary cold-import backend line.
  Rationale: `ARC` is already an accumulation scheme for Reed-Solomon code proximity claims, and `WHIR` is already a Reed-Solomon proximity verifier with fast verification. That pairing is a much cleaner fit than the earlier `FACS -> WHIR` wording.
  Date/Author: 2026-03-26 / Codex

- Decision: keep `FICS/FACS` as a secondary research line, not the implementation target of this plan.
  Rationale: `FICS/FACS` is still relevant because it shows a code-switching approach to fast IOPPs and accumulation, but it is not the cleanest first implementation for Hegemon’s cold-import problem.
  Date/Author: 2026-03-26 / Codex

- Decision: the new backend must start in a new crate and must not call the old aggregation helpers.
  Rationale: if it is wired directly into consensus first, the implementation will drift back into local wrappers again. The cryptographic core has to prove itself in isolation.
  Date/Author: 2026-03-26 / Codex

- Decision: the cold lane will accept only receipt-only `TxValidityArtifact`s with `proof = None`.
  Rationale: if per-tx proof objects are still carried on-chain, the lane has already failed the purpose of the plan.
  Date/Author: 2026-03-26 / Codex

- Decision: release `k=32,64,128` is the only decision gate.
  Rationale: `k=1` smoke runs and debug-mode integration tests are not good enough to judge a cold-import accumulator.
  Date/Author: 2026-03-26 / Codex

## Outcomes & Retrospective

At the moment this plan is written, there is no real cold-import accumulator in the tree. The repo has a linear native `ReceiptRoot` baseline and a real warm-store `receipt_accumulation` experiment. The rejected cold-lane experiments are useful only as negative results. This plan is the reset that stops further wrapper work from masquerading as backend work and replaces an insufficiently justified `FACS -> WHIR` split with a cleaner `ARC -> WHIR` implementation target.

## Context and Orientation

The current proof-routing code lives in `consensus/src/proof.rs`. It already knows about these block-artifact lanes:

- `InlineTx`, the shipping path.
- `MergeRoot`, the rejected recursive hot-path experiment.
- `ReceiptRoot`, the native linear baseline over native `TxLeaf` artifacts.
- `receipt_accumulation`, an additive warm-store experiment that wraps native receipt-root bytes plus ordered leaf hashes and reuses the verified-native-leaf store.

The current node authoring and import logic lives in `node/src/substrate/service.rs`. It selects lanes from `HEGEMON_BLOCK_PROOF_MODE`, prepares candidate proof material, and falls back to `InlineTx` when an experimental lane cannot be built safely.

The current benchmark harness lives in `circuits/superneo-bench/src/main.rs`. The only decision-grade experimental relation today is `native_tx_leaf_receipt_root`, and its `import_comparison` block currently shows two honest surfaces: the linear native baseline and the warm-store `receipt_accumulation` path.

The current native receipt-root cryptography lives in `circuits/superneo-hegemon/src/lib.rs`. That code produces native `TxLeaf` artifacts, folds them into native receipt-root artifacts, and verifies them. This plan does not replace that lane. It adds a new cold-import accumulator beside it.

Terms used in this plan:

- A **receipt** is `consensus::TxValidityReceipt`, the four-field object containing `statement_hash`, `proof_digest`, `public_inputs_digest`, and `verifier_profile`.
- A **receipt row** is the exact ordered byte representation of one receipt. In this plan the row hash must bind all four fields.
- **Cold import** means verification by a fresh peer from block contents alone. No verified-leaf store, no local sidecars, no candidate-preparation cache.
- `ARC` means the accumulation layer. In this repository it will accumulate claims that ordered receipt rows lie close to a Reed-Solomon codeword representation.
- `WHIR` means the fast Reed-Solomon proximity verification layer for the residual claim produced by `ARC`.
- A **residual artifact** is the one block-level proof object produced by the new backend. It is not allowed to contain a bundled per-tx proof family.

The two forbidden failure modes are:

1. Building a new lane that still calls any of these helpers:
   `prove_aggregation(...)`, `verify_aggregation_proof_safely(...)`, `verify_tx_validity_artifacts(...)`, `verify_native_tx_leaf_artifact_bytes(...)`, `verify_native_tx_leaf_receipt_root_artifact_bytes(...)`, or `verify_native_tx_leaf_receipt_root_artifact_from_records(...)`.

2. Building a new lane that still depends on any of these stateful shortcuts:
   `prewarm_verified_native_tx_leaf_store(...)`, `verify_experimental_native_receipt_accumulation_artifact(...)`, or any importer-local sidecar proof material.

If either forbidden pattern appears in the implementation, the milestone has failed and the code must not be integrated.

## Research Notes That Justify This Plan

The point of this section is to make the paper choice explicit so the next contributor does not repeat the earlier drift.

`ARC` is recorded in the 2024 ePrint listing as:

    "ARC: Accumulation for Reed-Solomon Codes"
    ePrint 2024/1731

The paper is described in search/index material as an accumulation scheme for claims about proximity of codewords to Reed-Solomon codes and as an almost-drop-in replacement for IOP-based PCD deployments.

Source:
- https://eprint-classic.github.io/2024.html
- https://eprint.iacr.org/2024/1731.pdf

`WHIR` is recorded in the 2024 ePrint listing as:

    "WHIR: Reed-Solomon Proximity Testing with Super-Fast Verification"
    ePrint 2024/1586

Source:
- https://eprint-classic.github.io/2024.html
- https://eprint.iacr.org/2024/1586.pdf

`FICS/FACS` is recorded in the 2025 ePrint listing as:

    "FICS and FACS: Fast IOPPs and Accumulation via Code-Switching"
    ePrint 2025/737

This matters because it shows that the code-switching family is real and relevant, but it also shows why the earlier `FACS -> WHIR` wording was sloppy: `FICS/FACS` is already an internally coherent pair, and `ARC/WHIR` is the cleaner Reed-Solomon-specific pair.

Source:
- https://eprint-classic.github.io/2025.html
- https://eprint.iacr.org/2025/737

This plan therefore commits to `ARC -> WHIR` as the first implementation line. If that line loses, `FICS/FACS` can become the next plan, but not by quietly mutating this one.

## Plan of Work

### Milestone 1: Build the backend in isolation

Create a new workspace crate at `circuits/receipt-arc-whir`. Do not put the first implementation in `consensus` or `node`. The entire point of this milestone is to prove that the backend exists independently of the current receipt-root helpers.

In `circuits/receipt-arc-whir/src/lib.rs`, define the minimal public surface:

    pub const RECEIPT_ARC_WHIR_ARTIFACT_KIND_BYTES: [u8; 16];
    pub const RECEIPT_ARC_WHIR_ARTIFACT_VERSION: u16;

    pub struct ReceiptRow {
        pub statement_hash: [u8; 48],
        pub proof_digest: [u8; 48],
        pub public_inputs_digest: [u8; 48],
        pub verifier_profile: [u8; 48],
    }

    pub struct ReceiptArcWhirParams {
        pub log_blowup: u8,
        pub query_count: u8,
        pub folding_rounds: u8,
    }

    pub struct ReceiptResidualArtifact {
        pub version: u16,
        pub receipt_commitment: [u8; 48],
        pub codeword_len: u32,
        pub arc_bytes: Vec<u8>,
        pub whir_bytes: Vec<u8>,
    }

    pub struct ReceiptResidualVerifyReport {
        pub row_count: usize,
        pub artifact_bytes: usize,
        pub replayed_leaf_verifications: usize,
        pub used_old_aggregation_backend: bool,
    }

    pub fn canonical_receipt_row_hash(row: &ReceiptRow) -> [u8; 48];
    pub fn receipt_rows_commitment(rows: &[ReceiptRow]) -> [u8; 48];
    pub fn prove_receipt_arc_whir(
        rows: &[ReceiptRow],
        params: &ReceiptArcWhirParams,
    ) -> anyhow::Result<Vec<u8>>;
    pub fn verify_receipt_arc_whir(
        rows: &[ReceiptRow],
        artifact_bytes: &[u8],
        params: &ReceiptArcWhirParams,
    ) -> anyhow::Result<ReceiptResidualVerifyReport>;
    pub fn max_receipt_arc_whir_artifact_bytes(row_count: usize) -> usize;

The semantics are strict:

- `canonical_receipt_row_hash` must hash the full row in order: `statement_hash || proof_digest || public_inputs_digest || verifier_profile`.
- `receipt_rows_commitment` must commit to the ordered row hashes, not just `statement_hash`.
- `prove_receipt_arc_whir` must produce one artifact for the full ordered receipt list.
- `verify_receipt_arc_whir` must verify only from `rows`, `artifact_bytes`, and `params`.
- `ReceiptResidualVerifyReport.replayed_leaf_verifications` must stay `0`.
- `ReceiptResidualVerifyReport.used_old_aggregation_backend` must stay `false`.

The `ARC` instructions for this crate are:

1. Treat the ordered receipt rows as the source data. Do not use `TransactionProof`, native `TxLeaf` openings, or the verified-native-leaf store here.
2. Hash each receipt row with `canonical_receipt_row_hash`.
3. Lift the ordered row hashes into field elements for a Reed-Solomon codeword domain.
4. Encode the ordered rows as a Reed-Solomon claim set.
5. Accumulate those Reed-Solomon proximity claims into one residual claim. In this repository, that means `arc_bytes` must summarize one residual claim for the whole receipt vector, not one proof per row.
6. The artifact may contain accumulator state, challenge material, and residual openings. It may not contain embedded per-row proof blobs.

The `WHIR` instructions for this crate are:

1. Take the residual Reed-Solomon claim from the `ARC` layer.
2. Produce `whir_bytes` that verify that residual claim with fast verifier work.
3. Keep the verifier interface receipt-only: it may query the residual codeword state carried in the artifact, but it may not query old tx-leaf artifacts or any importer-local cache.
4. Use `ReceiptArcWhirParams` to expose explicit, conservative codeword settings that matter for performance: blowup, query count, and accumulation/folding rounds.

This milestone is complete only when the crate can prove and verify standalone receipt vectors and fail on receipt mutation, receipt reordering, artifact truncation, and oversized artifact input.

### Milestone 2: Wire the backend into consensus without lying

After Milestone 1 works standalone, integrate it into `consensus/src/proof.rs` and `consensus/src/lib.rs`.

Add a new custom block-artifact kind named `receipt_arc_whir`. Use a new custom `ProofArtifactKind::Custom(...)` tag and a dedicated verifier-profile digest derived from a stable domain string such as `hegemon:receipt_arc_whir:v1`.

The consensus integration must define:

    pub fn experimental_receipt_arc_whir_artifact_kind() -> ProofArtifactKind;
    pub fn experimental_receipt_arc_whir_verifier_profile() -> VerifierProfileDigest;
    pub fn build_experimental_receipt_arc_whir_artifact(
        receipts: &[TxValidityReceipt],
    ) -> Result<ExperimentalReceiptRootArtifact, ProofError>;
    pub fn verify_experimental_receipt_arc_whir_artifact(
        receipts: &[TxValidityReceipt],
        expected_commitment: &[u8; 48],
        envelope: &ProofEnvelope,
    ) -> Result<BlockArtifactVerifyReport, ProofError>;

Create a dedicated module `consensus/src/receipt_arc_whir.rs` for the adapter layer. This module must:

- convert `TxValidityReceipt` into `ReceiptRow`
- compute the ordered receipt commitment with all receipt fields bound
- call only the new `circuits/receipt-arc-whir` crate
- apply explicit encoded artifact size caps before decode
- expose the no-replay / no-old-backend counters to tests and benchmarks

The consensus verifier for this lane must reject all of the following:

- any tx artifact whose `proof` field is present
- any block artifact whose kind or verifier profile is wrong
- any artifact whose bytes exceed `max_receipt_arc_whir_artifact_bytes(txs.len())`
- any artifact that causes `replayed_leaf_verifications != 0`
- any artifact that causes `used_old_aggregation_backend == true`

Do not reuse `ReceiptRootVerifier` or `ExperimentalNativeReceiptAccumulator`. This lane is new code, not a variant of an existing verifier.

### Milestone 3: Make node authoring and import cold-self-contained

Only after Milestone 2 passes should the node path change.

In `node/src/substrate/service.rs`, add `HEGEMON_BLOCK_PROOF_MODE=receipt_arc_whir`. Do not add aliases.

Authoring on this lane must do exactly this:

1. Start from the current candidate set and whatever local proof material exists today.
2. Derive the canonical `TxValidityReceipt` for each ordered tx.
3. Emit `tx_validity_artifacts` that contain those receipts and `proof = None`.
4. Build exactly one block artifact through `build_experimental_receipt_arc_whir_artifact(...)`.
5. Refuse to author the lane if steps `2-4` cannot be completed self-contained. Fall back to `InlineTx` with an explicit log reason.

Import on this lane must do exactly this:

1. Read the receipt-only `tx_validity_artifacts` from the block.
2. Reconstruct the ordered receipt rows from those block-carried receipts alone.
3. Verify the one `receipt_arc_whir` block artifact.
4. Reject the block if any tx artifact carries proof bytes, if any receipt is missing, or if the verifier touches warm-store or per-leaf replay helpers.

This lane is not allowed to depend on:

- local sidecar proof bytes
- the verified-native-leaf store
- prewarm state
- old aggregation proof bytes

### Milestone 4: Benchmark honestly and kill quickly if it loses

After node and consensus integration, add a diagnostic benchmark lane in `circuits/superneo-bench/src/main.rs` named `native_tx_leaf_receipt_arc_whir`. Keep `native_tx_leaf_receipt_root` as the canonical benchmark surface until the new lane wins.

The new benchmark must:

- clear the verified-native-leaf store before each run
- clear any backend-local prepared caches before each cold verify
- report the full cold artifact bytes, not just the residual bytes
- report `cold_residual_verify_ns`
- report `cold_residual_artifact_bytes`
- report `cold_residual_replayed_leaf_verifications`
- report `cold_residual_used_old_aggregation_backend`

The benchmark must never describe the new lane as canonical before it wins the gate below.

## Concrete Steps

All commands run from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Milestone 1 commands:

    cargo test -p receipt-arc-whir

Expected success:

    running N tests
    test receipt_arc_whir_accepts_canonical_rows ... ok
    test receipt_arc_whir_rejects_reordered_rows ... ok
    test receipt_arc_whir_rejects_mutated_receipt_metadata ... ok
    test receipt_arc_whir_rejects_oversized_artifact ... ok

Milestone 2 commands:

    cargo test -p consensus receipt_arc_whir_ -- --nocapture

Expected success:

    test receipt_arc_whir_block_is_accepted_from_receipt_only_artifacts ... ok
    test receipt_arc_whir_rejects_tx_artifacts_with_proof_bytes ... ok
    test receipt_arc_whir_rejects_old_backend_replay ... ok

Milestone 3 commands:

    cargo test -p hegemon-node receipt_arc_whir_ -- --nocapture

Expected success:

    test receipt_arc_whir_mode_is_selected_from_env ... ok
    test receipt_arc_whir_mode_falls_back_when_receipts_cannot_be_built ... ok
    test receipt_arc_whir_import_rejects_sidecar_only_dependency ... ok

Milestone 4 commands:

    cargo run --release -p superneo-bench -- \
      --relation native_tx_leaf_receipt_arc_whir \
      --allow-diagnostic-relation \
      --k 32,64,128 \
      --compare-inline-tx

Expected output shape:

    [
      {
        "relation": "native_tx_leaf_receipt_arc_whir",
        "k": 32,
        "bytes_per_tx": ...,
        "import_comparison": {
          "baseline_verify_ns": ...,
          "cold_residual_verify_ns": ...,
          "cold_residual_artifact_bytes": ...,
          "cold_residual_replayed_leaf_verifications": 0,
          "cold_residual_used_old_aggregation_backend": false
        }
      }
    ]

## Validation and Acceptance

This plan succeeds only if all of these are true:

1. The new backend exists in `circuits/receipt-arc-whir` and can prove / verify standalone receipt vectors.
2. The consensus verifier for `receipt_arc_whir` does not call any forbidden helper from the old aggregation or native leaf paths.
3. Node import verifies the lane from block contents alone. No warm store, no sidecars, no per-leaf replay.
4. The benchmark reports `cold_residual_replayed_leaf_verifications = 0`.
5. The benchmark reports `cold_residual_used_old_aggregation_backend = false`.
6. On the same machine and in release mode, `cold_residual_verify_ns < baseline_verify_ns` for `k = 32, 64, 128`.
7. On the same machine and in release mode, `bytes_per_tx <= native_tx_leaf_receipt_root bytes_per_tx` for `k = 32, 64, 128`.

If any of conditions `4-7` fail, the lane is a loss. Record the numbers in this plan, update `DESIGN.md` and `METHODS.md`, remove the lane from supported node selectors, and stop.

## Idempotence and Recovery

This work must be additive until the benchmark gate is passed. The new crate, verifier, and node selector are allowed to exist behind an experimental mode. If the lane loses the gate, recovery is simple: remove the new proof kind from `consensus/src/proof.rs`, remove the env selector from `node/src/substrate/service.rs`, delete the benchmark relation, and keep only the negative result in the docs.

Do not modify the shipping `InlineTx` path while building this prototype. All experiments must remain deletable.

## Artifacts and Notes

The most important artifact for this plan is the release benchmark JSON for `k=32,64,128`.

When the benchmark is run, archive its JSON under `.agent/benchmarks/` with a timestamped filename. If the process is OOM-killed or exits without JSON, archive the exit status file as evidence and treat the lane as failed unless a smaller reproducible bug is found and fixed first.

The second most important artifacts are the guard tests that prove the lane does not replay leaf verification and does not call the old aggregation backend.

## Interfaces and Dependencies

The new crate `circuits/receipt-arc-whir` may depend on field and hash crates already in the repository, but it must not depend on:

- `aggregation_circuit`
- `transaction_circuit::proof`
- `superneo-hegemon`
- `superneo-backend-lattice`

Use existing repository primitives where they help:

- `crypto::hashes::blake3_384` for stable 48-byte row hashes and commitments
- existing field crates already used by the repo for codeword arithmetic
- `consensus::TxValidityReceipt` as the source receipt object at the adapter boundary

At the end of Milestone 2, these public functions must exist:

In `circuits/receipt-arc-whir/src/lib.rs`:

    pub fn prove_receipt_arc_whir(
        rows: &[ReceiptRow],
        params: &ReceiptArcWhirParams,
    ) -> anyhow::Result<Vec<u8>>;

    pub fn verify_receipt_arc_whir(
        rows: &[ReceiptRow],
        artifact_bytes: &[u8],
        params: &ReceiptArcWhirParams,
    ) -> anyhow::Result<ReceiptResidualVerifyReport>;

In `consensus/src/receipt_arc_whir.rs`:

    pub fn build_receipt_arc_whir_artifact_from_receipts(
        receipts: &[TxValidityReceipt],
    ) -> Result<ProofEnvelope, ProofError>;

    pub fn verify_receipt_arc_whir_artifact_from_receipts(
        receipts: &[TxValidityReceipt],
        expected_commitment: &[u8; 48],
        envelope: &ProofEnvelope,
    ) -> Result<BlockArtifactVerifyReport, ProofError>;

In `consensus/src/proof.rs`:

    pub fn experimental_receipt_arc_whir_artifact_kind() -> ProofArtifactKind;
    pub fn experimental_receipt_arc_whir_verifier_profile() -> VerifierProfileDigest;

The benchmark relation name must be exactly `native_tx_leaf_receipt_arc_whir`. The env selector must be exactly `receipt_arc_whir`. Do not add aliases until the lane is proven good enough to survive.

Revision note: this file was rewritten from scratch on 2026-03-26 after re-checking the paper line. The earlier `FACS -> WHIR` wording was directionally related but not the cleanest primary implementation target. This version commits to `ARC -> WHIR` as the first real cold-import backend for Hegemon and leaves `FICS/FACS` as a secondary line if this one loses.
