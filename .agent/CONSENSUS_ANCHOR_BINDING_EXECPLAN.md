# Consensus: bind recursive proofs to commitment-tree anchors

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This repository contains `.agent/PLANS.md` at the repo root. This ExecPlan must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, the consensus layer rejects blocks whose recursive proof payloads are not bound to the chain’s commitment-tree state. Concretely: a recursive proof can no longer “float” over arbitrary `root_before` anchors or claim arbitrary `starting_root`/`ending_root` values while still being accepted by consensus.

You can see it working by running the consensus tests: new/updated tests will fail on the old code (accepting invalid anchors / root mismatches) and pass once this plan is implemented.

## Progress

- [x] (2026-01-03 00:10Z) Write this ExecPlan (completed: initial plan; remaining: update as implementation progresses).
- [x] (2026-01-03 00:55Z) Implement compact commitment-tree state in `consensus/src/commitment_tree.rs` (frontier + leaf_count + bounded root-history).
- [x] (2026-01-03 01:05Z) Thread commitment-tree state into PoW/BFT fork nodes (`consensus/src/pow.rs`, `consensus/src/bft.rs`) and initialize at genesis.
- [x] (2026-01-03 01:20Z) Enforce anchor-window membership + starting/ending-root binding in `consensus/src/proof.rs`.
- [x] (2026-01-03 02:00Z) Add fast unit tests for anchor/root binding in `consensus/src/proof.rs` (no recursive proof generation required).
- [x] (2026-01-03 01:30Z) Update state-root computation to use the commitment-tree root in PoW/BFT consensus and update tests to build matching headers.
- [x] (2026-01-03 01:50Z) Run `cargo test -p consensus` successfully.

## Surprises & Discoveries

- Observation: `consensus/src/proof.rs` currently verifies recursive proof bytes and binds only `(nullifiers, commitments)` to the transaction list; it does not enforce that the transaction `merkle_root` anchor is a valid historical root, and it does not bind `RecursiveBlockProof.starting_root/ending_root` to the chain state.
  Evidence: `consensus/src/proof.rs` function `verify_recursive_proof_payload` compares only `expected_nullifiers` and `expected_commitments` and never reads `TransactionPublicInputsStark.merkle_root` or checks `starting_root/ending_root`.

## Decision Log

- Decision: Maintain commitment-tree state inside consensus fork nodes (one per fork tip) using a compact “frontier” representation rather than the full `state/merkle::CommitmentTree`.
  Rationale: Consensus must validate anchors and compute the next root without storing all leaves; storing a full tree per fork node would be unbounded memory.
  Date/Author: 2026-01-03 / GPT-5.2

- Decision: Treat `BlockHeader.state_root` as the commitment-tree root after applying all transaction commitments in the block.
  Rationale: This binds the signed header to the same state transition that the recursive proof claims (`ending_root`) and makes consensus validation self-contained.
  Date/Author: 2026-01-03 / GPT-5.2

## Outcomes & Retrospective

- (Pending) Once complete, consensus will be able to reject blocks that present valid recursive proof bytes but are not anchored to the chain’s commitment-tree history.
  Outcome: Implemented and validated in `consensus` crate tests; added fast unit tests for the anchor/root transition checker without requiring recursive STARK proof generation.

## Context and Orientation

Key files and the current behavior:

- `consensus/src/proof.rs`
  - `verify_recursive_proof_payload` verifies the recursive proof (via `block_circuit::verify_recursive_proof`) and checks that each transaction’s `(nullifiers, commitments)` match the recursive proof’s inner public inputs.
  - Missing checks: transaction `merkle_root` (anchor) validity, and `RecursiveBlockProof.starting_root/ending_root` binding to the chain’s commitment-tree state transition.

- `circuits/block/src/recursive.rs`
  - Defines `RecursiveBlockProof { starting_root, ending_root, ... }`.
  - In `verify_block_recursive`, it checks `starting_root`, validates each transaction anchor against `tree.root_history()`, applies commitments to the tree, and checks `ending_root`.
  - Consensus should enforce the same invariants, but consensus does not carry a `CommitmentTree`.

- `transaction-circuit` hashing
  - The commitment tree uses circuit-compatible hashing via `transaction_circuit::hashing::merkle_node_bytes(left, right) -> [u8; 32]`.

Terminology used here:

- “Commitment tree”: the append-only Merkle tree of note commitments used as the anchor for shielded spends.
- “Anchor” / `root_before`: the Merkle root a transaction proves membership against (encoded in the transaction proof public inputs).
- “Root history window”: a bounded list of recent commitment-tree roots that are considered valid anchors.
- “State transition binding”: enforcing that the block’s recursive proof claims `starting_root == parent_root` and `ending_root == root_after_applying_block_commitments`.

## Plan of Work

1. Add a compact commitment-tree implementation to the consensus crate.

   Create `consensus/src/commitment_tree.rs` implementing a compact incremental Merkle tree with:

   - `depth = 32` (match the transaction circuit).
   - `leaf_count` and `frontier` (rightmost non-default node per level) to support O(depth) appends.
   - A bounded `root_history` (size 100 to match the runtime’s configured history size) used for anchor validation.
   - Hashing via `transaction_circuit::hashing::merkle_node_bytes`.

2. Thread commitment-tree state through consensus fork nodes.

   - Extend `PowNode` (`consensus/src/pow.rs`) and `ForkNode` (`consensus/src/bft.rs`) to store the commitment-tree state for that fork tip.
   - Initialize genesis nodes with an empty tree whose root is the default root (computed by hashing `[0;32]` up to depth 32) and with `root_history = [default_root]`.

3. Refactor block verification flow so parent state is available when verifying recursive proofs.

   - In `PowConsensus::apply_block` and `BftConsensus::apply_block`, load and validate the parent node before running recursive proof verification, because anchor checks depend on parent commitment-tree state.
   - Update the `ProofVerifier` interface (and `HashVerifier` / `RecursiveProofVerifier`) so proof verification can:
     - take `parent_commitment_tree` as input,
     - return an updated commitment-tree state (post-commitments).

4. Enforce anchor and root binding in `consensus/src/proof.rs`.

   Implement (or refactor into) a function that:

   - Extracts each transaction’s `merkle_root` anchor from the recursive verifier inputs.
   - Checks the anchor is present in the current bounded root-history window before applying that transaction’s commitments.
   - Checks `proof.starting_root == parent_tree.root()`.
   - Applies all non-zero commitments (in order) to compute the post-block root.
   - Checks `proof.ending_root == computed_root`.
   - Returns the updated tree state so consensus can persist it for the new fork node.

   Add new `ProofError` variants for anchor/root mismatches.

5. Update state-root computation.

   Replace the current SHA-256 “accumulator” in `consensus/src/pow.rs` and `consensus/src/bft.rs` with the commitment-tree root derived from the same tree update used for proof binding. Ensure `BlockHeader.state_root` is compared against this computed commitment-tree root.

6. Update and add tests.

   - Update `consensus/tests/common.rs` to compute `state_root` using the commitment-tree transition (so existing PoW/BFT tests keep passing).
   - Add a unit test (in `consensus/src/proof.rs` or a dedicated module) that exercises anchor binding logic without generating a full recursive STARK proof (by calling the “anchor binding” helper directly with synthetic anchors).
   - Keep the existing heavy recursive-proof generation test ignored, but ensure it still passes when run explicitly.

## Concrete Steps

Run these from the repository root.

1. Implement code changes:

   - Edit `consensus/src/error.rs`
   - Add `consensus/src/commitment_tree.rs`
   - Edit `consensus/src/proof.rs`
   - Edit `consensus/src/pow.rs`
   - Edit `consensus/src/bft.rs`
   - Edit `consensus/src/lib.rs`
   - Update `consensus/tests/common.rs` and any tests that build headers.

2. Run tests:

   - `cargo test -p consensus`

   Expected: all non-ignored tests pass.

3. (Optional, slow) Run the heavy recursive proof test:

   - `cargo test -p consensus --test recursive_proof -- --ignored`

## Validation and Acceptance

Acceptance is based on observable behavior:

- Consensus rejects a recursive proof payload if:
  - `RecursiveBlockProof.starting_root` does not match the parent commitment-tree root, or
  - any transaction’s anchor `merkle_root` is not in the bounded root-history window at the point the transaction is applied, or
  - `RecursiveBlockProof.ending_root` does not match the computed post-block root.

- `BlockHeader.state_root` is verified against the computed commitment-tree root and therefore is cryptographically bound into the header signature / block hash.

- `cargo test -p consensus` passes.

## Idempotence and Recovery

- These changes are deterministic and safe to re-run. If a test fails, revert to the previous commit or `git checkout -- <files>` and re-apply changes in smaller patches.
- There are no database migrations or on-disk formats changed in this plan; it is in-memory consensus validation only.

## Artifacts and Notes

- The core security invariant this plan enforces is:

  - The recursive proof’s transaction public inputs must reference only anchors that the node considers valid recent roots (root-history window), and the block’s claimed `starting_root/ending_root` must match the node’s computed commitment-tree transition.

## Interfaces and Dependencies

New/updated interfaces that must exist at the end:

- In `consensus/src/commitment_tree.rs`, define:

    - `pub struct CommitmentTreeState { ... }`
    - `impl CommitmentTreeState { pub fn new_empty(depth: usize, history_limit: usize) -> Self; pub fn root(&self) -> [u8; 32]; pub fn contains_root(&self, root: &[u8; 32]) -> bool; pub fn append(&mut self, leaf: [u8; 32]) -> Result<[u8; 32], _>; }`

- In `consensus/src/proof.rs`, update `ProofVerifier` to accept parent commitment-tree state and return the updated state, and ensure `RecursiveProofVerifier` enforces anchor/root binding for blocks with recursive proofs.

At the bottom of this file, note any revisions made during implementation and why.

## Revision Notes

Updated 2026-01-03: implemented the full plan in code, changed the `ProofVerifier` interface to accept parent commitment-tree state and return the updated tree, and updated consensus tests to treat `BlockHeader.state_root` as the commitment-tree root instead of the legacy SHA-256 accumulator.
