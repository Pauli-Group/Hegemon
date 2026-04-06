# Introduce Mini-Roots and Hierarchical Native Receipt-Root Trees

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

## Purpose / Big Picture

After this change, Hegemon will be able to summarize shielded transactions in layers instead of rebuilding one flat tree every time. A small change to one transaction will only force recomputation of that transaction’s local mini-root and the short path above it, rather than the whole block-wide fold tree. The user-visible proof is straightforward: a new benchmark will show that a one-transaction change inside a `128`-leaf block rebuilds only `11` internal fold nodes when mini-root size is `8`, instead of `127`, and an epoch-scale benchmark will show that changing one block updates only the short path to the epoch root instead of every epoch node.

## Progress

- [x] (2026-04-05 18:45Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, `docs/crypto/native_backend_verified_aggregation.md`, `circuits/superneo-hegemon/src/lib.rs`, `circuits/superneo-backend-lattice/src/lib.rs`, and `circuits/superneo-bench/src/main.rs`.
- [x] (2026-04-05 18:58Z) Confirmed the current native receipt-root builder is a flat binary fold tree built in `circuits/superneo-hegemon/src/lib.rs` and that no mini-root or epoch-root artifact exists yet.
- [x] (2026-04-05 19:10Z) Recorded the current measured baseline that motivates this plan: on the local verify-only harness, `8` leaves required `0.695s` for root replay verification while verified-record root verification took `0.027s`, and the current flat tree has no internal reuse surface.
- [x] (2026-04-05 21:50Z) Landed the deterministic mini-root hierarchy helpers and hierarchy report surfaces in `circuits/superneo-hegemon/src/lib.rs` and `circuits/superneo-bench/src/main.rs`.
- [x] (2026-04-05 23:10Z) Updated `DESIGN.md`, `METHODS.md`, and `docs/SCALABILITY_PATH.md` so the current hierarchy, cache, and verified-record import path are described accurately.
- [x] (2026-04-05 23:25Z) Completed the `1024`-block epoch hierarchy benchmark and confirmed one changed block touches only `10` internal epoch nodes instead of `1023`.
- [x] (2026-04-05 23:34Z) Completed the `16`-leaf block hierarchy benchmark and confirmed one changed leaf rebuilds only `1` of `2` mini-roots and touches `4` internal block nodes instead of `15`.
- [ ] Keep extending the hierarchy measurements toward larger build-side shapes as proving time permits.

## Surprises & Discoveries

- Observation: Hegemon already has the exact building blocks needed for hierarchical composition. `tx_leaf` verification, fold-step canonicalization, and verified-leaf replay all exist; the missing piece is only the intermediate tree structure.
  Evidence: `circuits/superneo-hegemon/src/lib.rs` already exposes `build_native_tx_leaf_artifact_bytes_with_params`, `verify_native_tx_leaf_artifact_bytes_with_params`, `build_native_tx_leaf_receipt_root_artifact_bytes_with_params`, and `verify_native_tx_leaf_receipt_root_artifact_bytes_with_params`.

- Observation: Hierarchy by itself does not reduce the number of folds in a fresh full build. The savings come from incremental recomputation and reuse after small changes.
  Evidence: a flat binary tree over `128` leaves uses `127` internal fold nodes no matter how it is parenthesized; the benefit of `8`-leaf mini-roots is that a single changed leaf only touches `7` internal mini-root folds plus `4` higher-level folds.

## Decision Log

- Decision: Use a fixed default mini-root size of `8` leaves for the first shipped hierarchy.
  Rationale: At the current `128`-leaf cap, `8` leaves per mini-root gives `16` mini-roots. One changed leaf then rebuilds `11` internal nodes (`7` inside the mini-root and `4` above it), which is about `11.5x` less recomputation than rebuilding all `127` internal nodes. Larger default chunks weaken the incremental win without a compensating product benefit at the current cap.
  Date/Author: 2026-04-05 / Codex

- Decision: Keep the ordered leaf semantics identical to the current flat receipt-root lane.
  Rationale: The hierarchy must be an internal aggregation shape change, not a semantic change to which ordered `tx_leaf` sequence the block commits to. A block that is valid under the hierarchical builder must still commit to the same ordered leaf list and the same statement commitment.
  Date/Author: 2026-04-05 / Codex

- Decision: Stage epoch roots as an off-chain artifact first, not as an immediate consensus object.
  Rationale: Block-level hierarchy solves the near-term authoring and recomputation problem. Epoch roots are useful for checkpoints, archive compression, and future sync work, but forcing epoch roots directly into consensus would entangle this plan with unrelated policy and chain-upgrade work.
  Date/Author: 2026-04-05 / Codex

## Outcomes & Retrospective

The hierarchy surface is now real and measurable. The current local benchmark evidence is already enough to prove the qualitative goal of the plan: on a `16`-leaf block with mini-root size `8`, changing one leaf rebuilt only `1` of `2` mini-roots and touched `4` internal block nodes instead of `15`; on a `1024`-block epoch tree, changing one block touched only `10` internal epoch nodes instead of `1023`. The remaining work here is mostly to extend those measurements to larger authoring-time shapes, not to prove that the hierarchy exists.

## Context and Orientation

The current native aggregation path lives in two crates.

`circuits/superneo-hegemon/src/lib.rs` owns the Hegemon-specific artifact formats. A `tx_leaf` artifact is one checked summary of one shielded transaction. A `receipt_root` artifact is one checked summary of many `tx_leaf` artifacts. The builder `build_native_tx_leaf_receipt_root_artifact_bytes_with_params` currently takes the entire ordered leaf list, folds it as one flat binary tree, and emits one artifact. The verifier `verify_native_tx_leaf_receipt_root_artifact_bytes_with_params` re-verifies every supplied leaf and replays every fold step in that same flat tree.

`circuits/superneo-backend-lattice/src/lib.rs` owns the fold operation itself. A `fold` means “combine two checked summaries into one parent summary.” The backend already provides deterministic `fold_pair` and `verify_fold` functions. A `folded instance` is the parent summary object; it carries the relation id, shape digest, statement digest, and witness commitment.

`circuits/superneo-bench/src/main.rs` already contains the verify-only measurement harness and is the right place to prove hierarchy actually changes recomputation behavior. The existing `measure_native_receipt_root_verify_only` function is the baseline that this plan must extend.

For this plan, the following terms matter:

- A `mini-root` is a receipt-root over a small contiguous slice of ordered `tx_leaf` artifacts. In the first implementation, a mini-root will cover up to `8` leaves.
- A `hierarchical block root` is a root built by first folding leaves into mini-roots and then folding the mini-roots into the final block root.
- An `epoch root` is an off-chain root built over many block roots. It is not consensus-critical in this plan.
- `Incremental recomputation` means “rebuild only the pieces touched by a local change.”

## Plan of Work

Start inside `circuits/superneo-hegemon/src/lib.rs`. Introduce explicit internal types for hierarchical aggregation. The plan assumes the following concrete names:

- `MiniReceiptRootArtifact`
- `HierarchicalReceiptRootArtifact`
- `EpochReceiptRootArtifact`

The first two are product-relevant; the third is off-chain only in this pass. A mini-root artifact must carry the same leaf-level binding material the current root builder uses, plus metadata that identifies the inclusive leaf range and mini-root size. A hierarchical block-root artifact must carry the ordered leaf list, the ordered mini-root summaries, the higher-level fold steps, and the final root digests. The final root digests must remain exactly the ones obtained from the same ordered leaf sequence; hierarchy must not change the committed sequence.

Add new builders and verifiers in `circuits/superneo-hegemon/src/lib.rs` rather than changing the current flat functions in place. Use additive names so a novice can compare flat and hierarchical behavior directly:

    build_native_tx_leaf_mini_root_artifact_bytes_with_params(...)
    verify_native_tx_leaf_mini_root_artifact_bytes_with_params(...)
    build_hierarchical_native_receipt_root_artifact_bytes_with_params(...)
    verify_hierarchical_native_receipt_root_artifact_bytes_with_params(...)
    build_epoch_receipt_root_artifact_bytes(...)
    verify_epoch_receipt_root_artifact_bytes(...)

The hierarchical builder must process the ordered leaf list in contiguous chunks of `8` by default. Each chunk becomes a mini-root. The final block root is then built from the ordered mini-root sequence using the same fold backend. If the block has fewer than `8` leaves in the final chunk, the final mini-root simply has fewer leaves; do not pad fake leaves into the security object.

The verifier must replay the same structure. It must verify every leaf, then every mini-root, then every higher-level fold. If any leaf, mini-root, or parent digest differs from the recomputed value, it must reject. The first implementation may keep the current full replay behavior, because the goal of this plan is hierarchy and reuse boundaries, not yet the import fast path.

Next, extend `circuits/superneo-bench/src/main.rs` with hierarchy-specific measurement commands. Add one command that builds a hierarchical root, mutates one leaf, rebuilds, and reports how many mini-roots and fold nodes changed. Add a second command that builds many block roots and an epoch root, mutates one block root, rebuilds, and reports the number of epoch nodes touched. These benchmarks are the visible proof that the hierarchy is working.

Then integrate the hierarchical artifact into the node’s explicit receipt-root research lane in `node/src/substrate/service.rs`. Keep the outer `BlockProofBundle` stable if possible by continuing to carry one `ReceiptRootProofPayload`; the hierarchy should live inside the artifact bytes and metadata. The node does not need epoch roots for authoring in this pass.

Finally, update `DESIGN.md`, `METHODS.md`, and `docs/SCALABILITY_PATH.md`. These documents must explain that hierarchy does not make fresh builds free, but it does create a bounded recomputation surface and an off-chain path toward epoch-level summaries.

## Concrete Steps

All commands run from repository root `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Add the hierarchical artifact types and builders in `circuits/superneo-hegemon/src/lib.rs`, then run:

    cargo test -p superneo-hegemon mini_root -- --nocapture
    cargo test -p superneo-hegemon hierarchical_receipt_root -- --nocapture

Expected result: new tests prove that the hierarchical builder accepts the same ordered leaf sequence, rejects tampering at the mini-root and parent levels, and preserves the final root digest semantics.

2. Add benchmark commands in `circuits/superneo-bench/src/main.rs`, then run:

    cargo run -p superneo-bench -- --measure-native-receipt-root-hierarchy --leaf-count 128 --mini-root-size 8 --mutate-leaf-index 17
    cargo run -p superneo-bench -- --measure-native-epoch-root-hierarchy --block-count 1024

Expected result: the first report shows that one changed leaf touches at most `11` internal fold nodes and reuses `15` of `16` mini-roots; the second report shows that one changed block root touches only `10` parent nodes in a `1024`-block epoch tree.

3. Integrate hierarchical receipt-root artifact build and verify into the node’s explicit receipt-root lane, then run:

    cargo test -p hegemon-node receipt_root -- --nocapture
    cargo test -p consensus --test raw_active_mode receipt_root_ -- --ignored --nocapture

Expected result: node and consensus tests continue to accept valid receipt-root blocks and reject wrong statement sets, but now do so using the hierarchical artifact encoding.

4. Update docs and run the local gate:

    ./scripts/check-core.sh test

Expected result: the workspace test gate remains green, and the docs explain the hierarchy in plain language.

## Validation and Acceptance

This plan is accepted when all of the following are true:

1. The repository can build and verify mini-roots deterministically from ordered `tx_leaf` artifacts.
2. The repository can build and verify a hierarchical block root whose final root semantics match the current ordered leaf sequence.
3. The benchmark for a `128`-leaf block with mini-root size `8` shows at most `11` internal fold-node recomputations after one changed leaf and reuse of at least `15` of `16` mini-roots.
4. The epoch benchmark shows that changing one block root in a `1024`-block epoch touches at most `10` parent nodes.
5. The node and consensus tests still accept valid native receipt-root blocks and still reject tampering.

Acceptance is behavioral, not structural. The implementation is not done merely because new types compile; the new benchmark reports must show the claimed recomputation savings.

## Idempotence and Recovery

The implementation should be additive and versioned. Keep the current flat artifact builder until the hierarchical builder passes all tests and measurements. If the new hierarchical artifact format proves incompatible with existing product-path assumptions, leave the flat path intact, gate the hierarchy behind a new artifact version, and keep the benchmark-only commands available so work can continue without destabilizing the shipped path. Re-running the builders and benchmarks should be safe because they only operate on generated local artifacts.

## Artifacts and Notes

The most important evidence for this plan is the benchmark output. A successful `128`-leaf incremental rebuild report should look like this in shape:

    {
      "leaf_count": 128,
      "mini_root_size": 8,
      "mini_roots_total": 16,
      "mini_roots_reused": 15,
      "mini_roots_rebuilt": 1,
      "block_internal_nodes_touched": 11,
      "flat_internal_nodes_touched": 127
    }

A successful epoch report should look like this in shape:

    {
      "block_count": 1024,
      "epoch_internal_nodes_touched": 10,
      "flat_epoch_internal_nodes": 1023
    }

These are examples of the observable outcomes this plan must produce.

## Interfaces and Dependencies

At the end of this plan, the following interfaces must exist:

- In `circuits/superneo-hegemon/src/lib.rs`:

    pub fn build_native_tx_leaf_mini_root_artifact_bytes_with_params(...)
    pub fn verify_native_tx_leaf_mini_root_artifact_bytes_with_params(...)
    pub fn build_hierarchical_native_receipt_root_artifact_bytes_with_params(...)
    pub fn verify_hierarchical_native_receipt_root_artifact_bytes_with_params(...)
    pub fn build_epoch_receipt_root_artifact_bytes(...)
    pub fn verify_epoch_receipt_root_artifact_bytes(...)

- In `circuits/superneo-bench/src/main.rs`:

    --measure-native-receipt-root-hierarchy
    --measure-native-epoch-root-hierarchy

- In `node/src/substrate/service.rs` and `consensus/src/proof.rs`:

  one versioned path that accepts the hierarchical receipt-root artifact bytes for the explicit native receipt-root lane without changing the ordered transaction statement commitment semantics.

Dependencies:

- Reuse `LatticeBackend::fold_pair` and `LatticeBackend::verify_fold` from `circuits/superneo-backend-lattice/src/lib.rs`; do not invent a second folding rule.
- Reuse the current `TxLeafPublicRelation` and `NativeTxLeafArtifact` semantics from `circuits/superneo-hegemon/src/lib.rs`.
- Keep the hierarchy deterministic and parameter-bound under the existing `NativeBackendParams`.

Change note (2026-04-05): created to turn the high-level “mini-roots + hierarchy” scaling discussion into a concrete, measurable implementation plan with explicit block-level and epoch-level reuse targets.
