# RecursiveBlockV2 Size Shrink

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, the shipped constant-size recursive block artifact, `RecursiveBlockV2`, should be materially smaller without weakening its bounded-domain invariant or changing its public verification model. The visible outcome is that the derived `recursive_block_v2` artifact width in the runtime and docs drops below the current `788,431` bytes, and the existing `tree_v2` prove/verify tests still pass.

## Progress

- [x] (2026-04-17 18:30Z) Audit the current `tree_v2` witness geometry and identify the remaining structural payload: full chunk records and full merge child statements.
- [x] (2026-04-17 19:08Z) Implement a `tree_v2` witness-size report and shrink the chunk witness by reconstructing `tx_index` from slot position.
- [x] (2026-04-17 19:08Z) Shrink the merge witness to only non-derivable child boundary fields and reconstruct full child statements from the parent target statement.
- [x] (2026-04-17 19:26Z) Re-derive the `tree_v2` proof cap, update the shipped runtime/doc constants, and rerun the existing `tree_v2` prove/verify suite.

## Surprises & Discoveries

- Observation: `tree_v2` is now small enough to ship, but the cap is still dominated by recursive witness transport rather than public bytes.
  Evidence: [circuits/block-recursion/src/tree_v2.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/tree_v2.rs) derives `root_proof_cap = 787,643` and `artifact_bytes = 788,431`, while the public section is only `676` bytes.

- Observation: the remaining obvious `v2` payload is not the child proof bytes anymore; it is the witness metadata around them.
  Evidence: chunk witnesses still serialize full `BlockLeafRecordV1` bytes per slot, and merge witnesses still serialize two full `RecursiveSegmentStatementV2` values even though the parent target statement already fixes most of each child statement.

- Observation: the two structural witness cuts were both real and composable.
  Evidence: after omitting `tx_index` from chunk slots and compacting merge child statements to a `388`-byte summary, the cap report moved from `artifact_bytes = 788,431` to `artifact_bytes = 783,135`; the report now prints `chunk_slot_bytes = 480`, `full_chunk_witness_bytes = 122,880`, and `merge_summary_bytes = 388`.

## Decision Log

- Decision: stay inside `v2` first instead of jumping straight to a new `v3`.
  Rationale: `v2` is now the shipped lane and already below `1 MB`. The first job is to remove clearly redundant witness transport inside the shipped geometry before introducing a new proof language.
  Date/Author: 2026-04-17 / Codex

- Decision: attack witness bytes, not public bytes or padding.
  Rationale: the outer artifact is already mostly proof field. The realistic near-term wins are in chunk and merge witness payloads.
  Date/Author: 2026-04-17 / Codex

- Decision: reconstruct child statements from the parent target statement inside `merge_relation_mismatch_v2` instead of storing both full child statements in the witness.
  Rationale: the parent target statement already fixes tx-commitment, boundaries, and half of each child state/tree commitments. Only the non-derivable boundary fields and tree digests need to be carried.
  Date/Author: 2026-04-17 / Codex

- Decision: keep the public `RecursiveBlockV2` artifact format unchanged while shrinking only the internal recursive witness geometry.
  Rationale: the shipped lane needed a smaller cap without another version bump. The safe move was to keep the external artifact and verification contract stable and only change the recursive relation’s auxiliary witness encoding.
  Date/Author: 2026-04-17 / Codex

## Outcomes & Retrospective

- Outcome: the shipped `RecursiveBlockV2` cap dropped from `788,431` to `783,135` bytes without changing the public artifact format or weakening the bounded-domain invariant.
  Gap: this was a modest shrink, not a new order-of-magnitude win.
  Lesson: the remaining `v2` headroom is real but narrower than the old structural waste. Further major wins now require a new backend object or a new recursive lane, not more obvious witness cleanup.

## Context and Orientation

`RecursiveBlockV2` lives in [circuits/block-recursion/src/tree_v2.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/tree_v2.rs). It is the shipped constant-size recursive block lane. The runtime cap that external code enforces lives in [pallets/shielded-pool/src/types.rs](/Users/pldd/Projects/Reflexivity/Hegemon/pallets/shielded-pool/src/types.rs). The human-facing statements about that cap live in [DESIGN.md](/Users/pldd/Projects/Reflexivity/Hegemon/DESIGN.md), [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md), [README.md](/Users/pldd/Projects/Reflexivity/Hegemon/README.md), and [docs/SCALABILITY_PATH.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/SCALABILITY_PATH.md).

The current `v2` design proves a block by splitting its ordered native `tx_leaf` stream into contiguous chunks, proving each chunk, then merging or carrying child segments up a binary tree. The proof is constant-size because the domain is bounded to `TREE_RECURSIVE_MAX_SUPPORTED_TXS_V2 = 1000`, but the derived cap still depends on how many witness bytes each chunk and merge relation stores.

Two terms matter here. A `chunk witness` is the auxiliary witness payload for a leaf chunk relation. A `merge witness` is the auxiliary witness payload for a parent relation that joins two adjacent child segments. Both are serialized into the recursive proof, so shaving them can reduce the derived cap.

## Plan of Work

First, add a narrow internal report in `tree_v2.rs` that makes the witness geometry visible: chunk slot bytes, full-chunk witness bytes, and merge child summary bytes. This is only for measurement and test output.

Second, shrink the chunk witness. Today `TreeRelationV2::new_chunk` writes `canonical_verified_leaf_record_bytes_v1(record)` for every slot, which includes `tx_index`. That field is redundant because the chunk relation already knows `target_statement.start_index` and the slot position. Replace the stored bytes with a chunk-slot encoding that omits `tx_index`, and update chunk decoding to reconstruct `BlockLeafRecordV1 { tx_index, ... }` from the slot position plus the parent start index before re-running the existing digest checks.

Third, shrink the merge witness. Today `TreeRelationV2::new_merge` and `TreeRelationV2::new_merge_with_child_cap` write two full `RecursiveSegmentStatementV2` values. Replace that with one compact merge summary that stores only the child fields that cannot be derived from the parent target statement and the left-child boundary: left segment length, left end-state digest, left end-tree commitment, the three left tree digests, and the three right tree digests. Update merge decoding to rebuild the exact left and right child statements from that compact summary before child verification.

Fourth, rerun the `tree_v2` cap derivation and the existing prove/verify tests. If the derived width drops, update the runtime constant and the docs in the files listed above. If the width does not move materially, leave the report in place and document that the remaining path is backend redesign, not more `v2` witness surgery.

## Concrete Steps

Run all commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Start by re-deriving the current `v2` cap:

    cargo test -p block-recursion tree_v2_proof_cap_report_is_self_consistent -- --nocapture

After the witness edits, rerun that command and capture the new `p_chunk_a`, `p_merge_a`, and `artifact_bytes` values.

Then rerun the `v2` behavioral suite:

    cargo test -p block-recursion prove_and_verify_recursive_artifact_v2_succeeds -- --ignored --nocapture
    cargo test -p block-recursion prove_and_verify_recursive_artifact_v2_at_first_merge_boundary_succeeds -- --ignored --nocapture
    cargo test -p block-recursion prove_and_verify_recursive_artifact_v2_across_first_carry_boundary_succeeds -- --ignored --nocapture
    cargo test -p block-recursion prove_and_verify_recursive_artifact_v2_at_deepest_supported_level_succeeds -- --ignored --nocapture
    cargo test -p block-recursion recursive_artifact_v2_constant_size_at_deepest_supported_level -- --ignored --nocapture

If the cap changes, rerun:

    cargo test -p pallet-shielded-pool validate_submit_recursive_candidate_artifact_ -- --nocapture
    cargo test -p hegemon-node default_block_proof_mode_is_recursive_block -- --nocapture
    cargo test -p hegemon-node recursive_block_mode_is_selected_from_env -- --nocapture
    cargo test -p hegemon-node require_native_block_proof_accepts_recursive_block_payload -- --nocapture
    cargo check -p block-recursion -p consensus -p pallet-shielded-pool -p hegemon-node

## Validation and Acceptance

Acceptance means all of the following are true:

- `tree_v2` still proves and verifies across the existing chunk, merge-boundary, carry-boundary, and deepest-supported-level tests.
- `recursive_block_artifact_bytes_v2()` is smaller than `788,431`.
- The runtime cap in `pallets/shielded-pool/src/types.rs` matches the derived size from the `tree_v2` report.
- The docs named above describe the new size and still call out `v2` as the shipped bounded lane.

## Idempotence and Recovery

These edits are safe to rerun because they only change the internal witness encoding for `v2` and its derived cap. If a witness compaction attempt fails to verify, revert that compaction but keep any diagnostic reporting that helped explain the failure. Do not change the shipped selector away from `v2` during this work.

## Artifacts and Notes

Starting point before this plan landed:

    TREE_RECURSIVE_CHUNK_SIZE_V2 = 256
    TREE_RECURSIVE_MAX_SUPPORTED_TXS_V2 = 1000
    root_proof_cap = 787,643
    artifact_bytes = 788,431

Kept result after the witness compaction:

    chunk_slot_bytes = 480
    full_chunk_witness_bytes = 122,880
    merge_summary_bytes = 388
    root_proof_cap = 782,347
    artifact_bytes = 783,135

This pass kept the expected first-order savings:

    chunk witness: 4 bytes saved per slot by dropping tx_index
    merge witness: one full child-statement-equivalent replaced by a compact non-derivable summary

The outcome is intentionally modest. The point of this plan was to keep `v2` honest and smaller before concluding whether a deeper backend redesign is necessary.

## Interfaces and Dependencies

The end state must keep these interfaces intact:

- `circuits/block-recursion/src/tree_v2.rs`
  - `pub fn derive_tree_proof_cap_v2() -> Result<TreeProofCapReportV2, BlockRecursionError>`
  - `pub fn recursive_block_artifact_bytes_v2() -> usize`
  - `pub fn prove_block_recursive_v2(...)`
  - `pub fn verify_block_recursive_v2(...)`
- `pallets/shielded-pool/src/types.rs`
  - `pub const RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE: usize`

Only the internal `tree_v2` witness encoding may change. The public block artifact format and the runtime admission API must remain version `v2`.
