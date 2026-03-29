# Cut Over The Product Path To Mandatory Native Receipt-Root Blocks

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

## Purpose / Big Picture

After this change, Hegemon will stop pretending that the shipping path is “native” while still building shielded blocks through `InlineRequired`. A wallet will continue to submit native `tx_leaf` bytes, but every non-empty shielded block on the fresh 0.10.x product path must also carry a same-block native `receipt_root` candidate artifact and must verify through the native receipt-root lane during import. The visible proof that the cutover worked is simple: mining and shielded sends still succeed locally, throughput logs no longer say `verification_mode=InlineRequired`, and authoring/import fail closed if the native block artifact is missing.

## Progress

- [x] (2026-03-28 23:05Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, `node/src/substrate/service.rs`, `consensus/src/proof.rs`, `runtime/src/manifest.rs`, and `pallets/shielded-pool/src/lib.rs`.
- [x] (2026-03-28 23:05Z) Confirmed the current bug: wallets emit native `tx_leaf` artifacts, but authoring still falls through to `proven_batch: None` unless proofless sidecars or explicit aggregation mode force the prepared-bundle path.
- [x] (2026-03-29 00:10Z) Made `receipt_root` + self-contained aggregation the default product selector/policy in `runtime/src/manifest.rs`, `node/src/substrate/prover_coordinator.rs`, and `node/src/substrate/service.rs`.
- [x] (2026-03-29 00:10Z) Required a prepared native candidate artifact for every non-empty shielded block and removed the silent `proven_batch: None` fallback from authoring/import.
- [x] (2026-03-29 00:10Z) Removed the non-empty `InlineRequired` block-verification path from `service.rs` and `consensus/src/proof.rs`.
- [x] (2026-03-29 00:10Z) Updated docs/tests and reran local mining, shielded sends, and throughput, capturing logs that prove the product path now imports under `SelfContainedAggregation`.

## Surprises & Discoveries

- Observation: the node already has a complete same-block native candidate-artifact path; the live bug is that authoring only treats it as mandatory for proofless sidecars.
  Evidence: `node/src/substrate/service.rs` currently computes `requires_proven_batch = shielded_tx_count > 0 && (!missing_proof_bindings.is_empty() || aggregation_mode_enabled)`.

- Observation: the runtime manifest still defaults to `ProofAvailabilityPolicy::InlineRequired`, which is incompatible with the desired fresh-chain product path.
  Evidence: `runtime/src/manifest.rs` sets `proof_availability_policy: ProofAvailabilityPolicy::InlineRequired`.

## Decision Log

- Decision: the fresh-chain 0.10.x product path will treat native receipt-root aggregation as mandatory for every non-empty shielded block, even when per-tx proof bytes are embedded.
  Rationale: this removes the hybrid authoring/import behavior and makes the block-verification path match the advertised architecture instead of using the native lane only as an optional acceleration path.
  Date/Author: 2026-03-28 / Codex

- Decision: the cutover will keep native `tx_leaf` per-transaction artifacts in extrinsics for now and change only the block-verification path in this pass.
  Rationale: the immediate bug is architectural inconsistency (`InlineRequired` still shipping). Reducing per-tx artifact size is separate work and should be measured after the product path is actually native end to end.
  Date/Author: 2026-03-28 / Codex

## Outcomes & Retrospective

The cutover landed. Fresh-chain product defaults now force `receipt_root` aggregation with `ProofAvailabilityPolicy::SelfContained`; non-empty shielded blocks fail closed unless they carry a ready same-block native `receipt_root` proven batch; and the old `InlineRequired` product branch is gone from authoring and import.

Behavioral evidence:

* Local mining and two real shielded transfers succeeded on a fresh dev chain after the cutover. The final clean smoke is under `/tmp/hegemon-native-product-20260328-smoke3`, with tx hashes `0x7f419db48677005dd68e47e65172970abb0f3fc176a12657cd27a757165caf9b` and `0x38d993fb8b6c9dbccb641f914605fa2f5c66e5c264e5ffa15d111b818e945643`.
* The clean product-path node log at `/tmp/hegemon-native-product-20260328-smoke3/node.log` contains no `InlineRequired`, no `BadProof`, and no `invalid-shielded-action`.
* Shipped-path throughput reruns at `tx_count = 1, 2, 4` all reported `verification_mode=SelfContainedAggregation` with `proven_batch_present=true`:
  * `/tmp/hegemon-throughput-artifacts/receipt-root-product-tx1.json`
  * `/tmp/hegemon-throughput-artifacts/receipt-root-product-tx2.json`
  * `/tmp/hegemon-throughput-artifacts/receipt-root-product-tx4.json`

Measured receipt-root bundle sizes on the cleaned product path were `182,278` bytes (`k=1`), `209,974` bytes (`k=2`), and `244,574` bytes (`k=4`), which brought payload cost down to `182,278.00`, `104,987.00`, and `61,143.50` bytes per included transfer respectively. Import verification for those bundled blocks measured `282 ms`, `357 ms`, and `215 ms`.

## Context and Orientation

`runtime/src/manifest.rs` defines the fresh-chain default protocol policy. Right now it still tells the runtime to behave as if per-transaction inline proof verification is the normal path. `node/src/substrate/service.rs` is the real authoring/import bridge. It already knows how to build a native `receipt_root` candidate artifact, attach it as `submit_candidate_artifact`, and verify it during import, but it also still contains a second product path that builds a block with `proven_batch: None` and `proof_verification_mode: InlineRequired`. `consensus/src/proof.rs` then honors that path and directly verifies each tx artifact instead of requiring the block artifact.

The goal of this plan is to remove that split for the fresh-chain product path. “Mandatory native receipt-root” means: every non-empty shielded block includes `enable_aggregation_mode` plus `submit_candidate_artifact`, the runtime accepts those blocks under `ProofAvailabilityPolicy::SelfContained`, and consensus rejects any non-empty shielded block that does not provide the native receipt-root artifact.

## Plan of Work

First, change the defaults. `runtime/src/manifest.rs`, `node/src/substrate/service.rs`, and `node/src/substrate/prover_coordinator.rs` must all stop defaulting to `inline_tx`. The fresh product default becomes `receipt_root`, with aggregation proofs enabled by default on that path. The old env toggles may remain as explicit overrides for diagnostics, but the default behavior of an unconfigured dev node must be native receipt-root.

Second, make authoring fail closed. In `node/src/substrate/service.rs`, a non-empty shielded candidate set must always push `enable_aggregation_mode` and must always require a ready prepared bundle. If the prepared native bundle is missing or falls back to `InlineTx`, block construction must fail instead of silently producing a hybrid block.

Third, remove the old verification lane. In `node/src/substrate/service.rs`, the branch that builds a `consensus::types::Block` with `proven_batch: None` for non-empty shielded blocks must go away. In `consensus/src/proof.rs`, the matching verification branch that accepts non-empty blocks without `proven_batch` or with `ProofVerificationMode::InlineRequired` must also go away. Empty shielded blocks still remain valid without a block artifact.

Fourth, update docs and tests so the repo states the truth. `DESIGN.md` and `METHODS.md` must describe the product path as mandatory native receipt-root aggregation. Focused runtime/node tests must assert that a shielded block without a candidate artifact is rejected and that a native receipt-root block verifies successfully.

Finally, rerun the actual behavior: local mining, two real shielded transfers, and the throughput harness. Acceptance requires the logs to show receipt-root aggregation instead of `InlineRequired`.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`:

1. Edit `runtime/src/manifest.rs`, `node/src/substrate/service.rs`, `node/src/substrate/prover_coordinator.rs`, and `consensus/src/proof.rs` to force the native receipt-root product path.
2. Update `DESIGN.md` and `METHODS.md` to match the cutover.
3. Run focused tests:

       cargo test -p wallet build_transaction_can_emit_native_tx_leaf_payloads -- --nocapture
       cargo test -p runtime kernel_wallet_unsigned_transfer_survives_kernel_validate_and_apply -- --nocapture
       cargo test -p runtime kernel_wallet_rejects_non_native_transfer_payload -- --nocapture
       cargo test -p consensus --test raw_active_mode -- --nocapture
       cargo test -p hegemon-node receipt_root -- --nocapture

4. Rebuild and rerun the local smoke:

       make node
       cargo build --release -p wallet

   then start a fresh dev node, mine, send two shielded transfers, and confirm clean inclusion.

5. Rerun shipped-path throughput:

       HEGEMON_TP_PROFILE=max HEGEMON_TP_PROOF_MODE=single HEGEMON_TP_TX_COUNT=1 HEGEMON_TP_MINE_THREADS=8 HEGEMON_TP_SKIP_BUILD=1 HEGEMON_TP_FORCE=1 HEGEMON_TP_RUN_ID=current-native-rerun-tx1 scripts/throughput_sidecar_aggregation_tmux.sh
       HEGEMON_TP_PROFILE=max HEGEMON_TP_PROOF_MODE=single HEGEMON_TP_TX_COUNT=2 HEGEMON_TP_COINBASE_BLOCKS=2 HEGEMON_TP_MINE_THREADS=8 HEGEMON_TP_SKIP_BUILD=1 HEGEMON_TP_FORCE=1 HEGEMON_TP_RUN_ID=current-native-rerun-tx2 scripts/throughput_sidecar_aggregation_tmux.sh
       HEGEMON_TP_PROFILE=max HEGEMON_TP_PROOF_MODE=single HEGEMON_TP_TX_COUNT=4 HEGEMON_TP_COINBASE_BLOCKS=5 HEGEMON_TP_MINE_THREADS=8 HEGEMON_TP_SKIP_BUILD=1 HEGEMON_TP_FORCE=1 HEGEMON_TP_RUN_ID=current-native-rerun-tx4 scripts/throughput_sidecar_aggregation_tmux.sh

## Validation and Acceptance

Acceptance is behavioral:

- a fresh dev node mines and accepts shielded transfers on the new branch;
- authoring a non-empty shielded block without a native candidate artifact fails closed;
- consensus rejects non-empty shielded blocks that do not carry the candidate artifact;
- throughput logs no longer report `verification_mode=InlineRequired`;
- the native candidate artifact path is no longer optional product plumbing.

## Idempotence and Recovery

This cut targets a fresh chain. Repeating the local smoke or throughput runs is safe as long as each run uses a fresh `--tmp` node or a forced harness reset. If authoring fails after the cut, the safe retry path is to fix the prepared-bundle path and rerun from a clean dev chain rather than trying to reuse stale wallet/node state.

## Artifacts and Notes

The key evidence to capture after the cut is:

    block_payload_size_metrics ... verification_mode=SelfContainedAggregation ...

or equivalent log output that proves the old inline-required block path is gone for non-empty shielded blocks.

## Interfaces and Dependencies

At the end of this work:

- `runtime::manifest::protocol_manifest()` must default `proof_availability_policy` to `pallet_shielded_pool::types::ProofAvailabilityPolicy::SelfContained`.
- `node::substrate::service::prepared_artifact_selector_from_env()` and `node::substrate::prover_coordinator::prepared_proof_mode_from_env()` must default to `receipt_root`.
- Non-empty shielded blocks must be built with `consensus::types::ProofVerificationMode::SelfContainedAggregation`.
- `consensus::ParallelProofVerifier::verify_block` must reject non-empty shielded blocks that do not carry `proven_batch`.

Revision note: created on 2026-03-28 after confirming that the wallet/native tx-leaf path was fixed but the product block-verification path still silently shipped `InlineRequired`.
