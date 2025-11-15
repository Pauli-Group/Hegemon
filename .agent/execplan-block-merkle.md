# Block proving pipeline with Merkle state

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. The plan must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

We need a working block-level proving pipeline. After implementation, a developer can assemble a synthetic block composed of multiple transaction proofs, have the block verifier enforce ordered note-commitment roots and nullifier uniqueness, update an append-only commitment tree using hash primitives, and produce a succinct proof artifact representing the entire block. End-to-end tests will show that applying the block changes the Merkle root exactly as expected and that duplicated nullifiers are rejected.

## Progress

- [x] (2025-02-14 05:30Z) Established references for transaction circuit APIs and hash primitives; reviewed `circuits/transaction` modules.
- [x] (2025-02-14 05:45Z) Designed and implemented the `state/merkle` crate with append-only tree, default nodes, and path queries.
- [x] (2025-02-14 05:55Z) Implemented the `circuits/block` crate including per-transaction verification, root ordering enforcement, and Merkle updates.
- [x] (2025-02-14 05:58Z) Added recursive aggregation placeholder hashing transaction artifacts into a digest stored in `RecursiveAggregation`.
- [x] (2025-02-14 06:10Z) Updated `DESIGN.md` and `METHODS.md` with implementation notes on the Merkle tree and block proof crates.
- [x] (2025-02-14 06:05Z) Wrote integration tests covering block state transitions, nullifier uniqueness, and root ordering enforcement.
- [x] (2025-02-14 06:06Z) Ran `cargo test --workspace` to validate new crates and integration tests.

## Surprises & Discoveries

- Observation: `Felt` elements cannot be hashed directly for nullifier tracking, so block verification stores `as_int()` values inside a `HashSet<u64>`.
  Evidence: Adjusted `circuits/block/src/proof.rs` duplicate nullifier detection to hash integer representations.

## Decision Log

- Decision: Store nullifiers in the block verifier as `u64` values derived from `Felt::as_int()` to enable hash set enforcement.
  Rationale: `Felt` lacks a `Hash` implementation, and converting to integers maintains deterministic equality while avoiding additional dependencies.
  Date/Author: 2025-02-14 / assistant.

## Outcomes & Retrospective

Initial implementation delivers a working Merkle state layer and block proof aggregator. State and block crates compile, workspace tests cover block flows, and documentation now references the concrete APIs. Future work will replace the hash-based `RecursiveAggregation` placeholder with an actual recursive STARK proof once the proving stack lands.

## Context and Orientation

The workspace currently exposes two crates: `crypto/` and `circuits/transaction/`. The transaction circuit crate defines a Poseidon-like hash primitive in `circuits/transaction/src/hashing.rs` and exposes proof generation and verification helpers in `circuits/transaction/src/proof.rs`. We will introduce two new crates:

1. `state/merkle`: library that stores an append-only Merkle commitment tree. It must compute leaves as `Felt` from transaction commitments, use the same Poseidon-style hash from the transaction circuit to hash internal nodes, and expose efficient append operations and root history retrieval. The tree should track insertion index, allow retrieving authentication paths for existing leaves, and maintain previous roots for ordered verification.
2. `circuits/block`: crate that validates a sequence of `TransactionProof`s, enforces that each transaction’s `public_inputs.merkle_root` equals the running root when the transaction is applied, ensures nullifiers are globally unique within the block, updates the Merkle tree with new commitments, and produces a block-level proof artifact or placeholder verifying structure. This crate should depend on both `transaction-circuit` and `state/merkle`.

The hash functions in `transaction-circuit` operate over `Felt = winterfell::math::fields::f64::BaseElement`. Reuse that type to ensure compatibility. The Merkle tree will likely store nodes in `Vec<Felt>` arranged in breadth-first layers or by depth to enable incremental updates similar to Orchard’s incremental Merkle trees.

Tests live under `tests/` at the workspace root (currently empty). We will add integration tests there to simulate block processing, using deterministic witnesses from the transaction circuit fixtures or manually constructed synthetic data.

## Plan of Work

1. **Understand transaction public inputs and proof structure.** Review `TransactionPublicInputs`, `TransactionProof`, and related constants to know how many nullifiers and commitments to expect. Document key fields in this plan if not already recorded.

2. **Design Merkle tree API.** Create `state/merkle/Cargo.toml` and `src/lib.rs` with modules for:
   - `mod node` or simple helper to hash left/right child using `transaction-circuit` Poseidon hash (or replicate logic for tree hashing if needed).
   - `CommitmentTree` struct supporting:
     * `fn new(depth: usize) -> Self` creating an empty tree with zero leaves and precomputed default hashes per level.
     * `fn append(&mut self, value: Felt) -> (usize, Felt)` inserting a new commitment, returning the leaf index and new root.
     * `fn root(&self) -> Felt` for current root.
     * `fn authentication_path(&self, index: usize) -> Option<Vec<Felt>>` to fetch sibling path.
     * `fn root_history(&self) -> &[Felt]` to inspect previous roots for ordered root enforcement.
     * `fn extend(&mut self, values: impl IntoIterator<Item = Felt>) -> Result<Vec<Felt>, MerkleError>` for efficient batch insertion.
   - Provide `MerkleError` enum using `thiserror::Error` for overflow and invalid operations.
   - Mirror append-only behavior by precomputing default nodes (all-zero leaves hashed upward) and by storing branch nodes per level for incremental updates (like a frontier). For efficiency, use the “frontier” technique: track one node per level representing the last partially filled subtree, enabling O(log n) append time with O(depth) memory.
   - Document operations in module-level comments.

3. **Implement tree hashing helpers.** Because Merkle tree requires binary hashing, add `fn hash_nodes(left: Felt, right: Felt) -> Felt` using Poseidon sponge with domain tag dedicated for the tree. Either reuse `transaction-circuit` hashing or define a new domain tag constant in `state/merkle`. Ensure tree hashing is consistent with commitments produced by transaction circuit (both use Poseidon). Document domain tag choices in plan.

4. **Block crate structure.** Create `circuits/block/Cargo.toml` with dependencies on `transaction-circuit`, `state-merkle` (the new crate name), `serde`, `thiserror`, and `winterfell` (if recursion uses same math). In `src/lib.rs`, define modules:
   - `pub mod error;`
   - `pub mod proof;`
   - `pub mod state;` (if needed for aggregator state machine) or simply include aggregator logic within `proof.rs`.
   Expose `BlockVerifier`, `BlockProver`, and `BlockProof` structures.

5. **Per-transaction verification.** In `proof.rs`, implement logic to:
   - Accept an ordered list of `TransactionProof` plus verifying key.
   - Check each proof using `transaction_circuit::verify`.
   - Verify that `public_inputs.merkle_root` equals the running root before applying the transaction.
   - Enforce nullifier uniqueness using a `HashSet<Felt>`.
   - Insert each transaction’s padded commitments (filtering trailing zero placeholders) into the Merkle tree via `CommitmentTree::append`.
   - Record intermediate roots to prove root ordering and store them in `BlockProof`.

6. **Block proof artifact.** Implement recursion tooling placeholder:
   - Define `BlockProof` struct containing: `starting_root`, `ending_root`, ordered list of transaction proofs (or compressed representation), aggregated nullifiers, aggregated commitments, and maybe a `winterfell::AirProof` placeholder to represent recursive proof. Because full recursion is complex, provide a stub `RecursiveProof` struct with serialized transaction verification trace data that can later integrate with Winterfell recursion.
   - Provide `prove_block(transactions: &[TransactionProof], verifying_key: &VerifyingKey) -> Result<BlockProof, BlockError>` that performs the checks and returns aggregated data plus maybe empty recursion proof for now.
   - Provide `verify_block(proof: &BlockProof, verifying_key: &VerifyingKey) -> Result<BlockVerificationReport, BlockError>` that replays the checks (including Merkle updates) to ensure deterministic acceptance.
   - Ensure recursion placeholder is structured so future work can replace stub with actual Winterfell proof generation without breaking API. Document fields accordingly.

7. **Root ordering enforcement.** Store `root_before` values for each transaction; ensure each matches the running root. After applying all commitments, compute final root and set as `proof.ending_root`. Provide `BlockVerificationReport { verified: bool }` similar to transaction crate.

8. **Integration tests.** Under `tests/`, create `block_flow.rs` (or similar) that:
   - Constructs dummy `TransactionWitness` objects using existing transaction crate fixtures or synthetic data. Use deterministic random from `rand` for secrets if necessary.
   - Generates proofs via `transaction_circuit::prove` (even if they are logical placeholders) and collects them into a block.
   - Uses `state::merkle::CommitmentTree` to compute expected final root and ensures `prove_block` matches it.
   - Tests duplicate nullifier detection by creating a second transaction with same nullifier and verifying `prove_block` returns error.
   - Tests root ordering by shuffling transaction order and verifying error.
   - Ensures the integration test touches both the block and state crates.

9. **Documentation updates.** Update `DESIGN.md` section 6 (tree evolution and block-level recursion) with details about the new `state/merkle` crate and block proof aggregator. Update `METHODS.md` if necessary to reflect the recursion placeholder and append-only tree implementation.

10. **Validation commands.** Ensure the plan lists commands to build and test the workspace: `cargo fmt`, `cargo clippy --all-targets`, and `cargo test --workspace`. Document expected outputs here and update after running.

11. **Idempotence considerations.** Note in this plan how repeated block verification should produce same root; mention any state resets needed before tests.

12. **Artifact references.** Plan to include any significant terminal outputs or test diffs in the `Artifacts and Notes` section when recorded.

## Concrete Steps

- From repository root, run `cargo test --all` to observe current baseline (likely passes or is empty). Record output in `Artifacts and Notes` once run.
- Create new crate directories `state/merkle` and `circuits/block` with their respective `Cargo.toml` files and module structures as described.
- Implement modules following the plan of work, running `cargo fmt` and `cargo test` after major steps to ensure incremental correctness.
- Update `Cargo.toml` at workspace root to include new members and ensure dependency graph compiles.
- Write integration tests under `tests/` and ensure they compile by referencing the newly exposed APIs.
- Update documentation as described.
- Final validation: run `cargo test --workspace` and capture output.

## Validation and Acceptance

Successful implementation is demonstrated when:

1. Running `cargo test --workspace` from repository root passes and includes the new integration tests covering block verification, root ordering, and nullifier uniqueness.
2. `prove_block` returns a `BlockProof` whose `starting_root` matches the Merkle tree root before applying transactions and whose `ending_root` matches the result of replaying the transaction commitments through `CommitmentTree`.
3. Attempting to prove a block with duplicate nullifiers returns a specific `BlockError::DuplicateNullifier` (or similar) and leaves the tree untouched.
4. Documentation clearly explains how the block proof aggregator and Merkle state interact.

## Idempotence and Recovery

The append-only tree API should allow resetting by constructing a new `CommitmentTree`. Tests must instantiate fresh trees per scenario to avoid state leakage. Re-running block verification on the same inputs must yield identical roots because operations are deterministic. If an append fails, the tree should remain in the state prior to the failed operation; ensure the API returns errors without partial mutation.

## Artifacts and Notes

- Baseline `cargo test --all` prior to changes succeeded; see chunk 18000f.
- Workspace `cargo test --workspace` after implementing block and state crates passed; see chunk a26bd7.


## Interfaces and Dependencies

- `state::merkle::CommitmentTree` must expose `new`, `append`, `extend`, `root`, and `authentication_path`. It will depend on `winterfell::math::fields::f64::BaseElement` and share Poseidon hashing constants defined in `transaction-circuit::constants` to ensure compatibility.
- `state::merkle::hash_nodes(left: Felt, right: Felt) -> Felt` defines the tree hash function.
- `circuits::block::BlockProver` and `BlockVerifier` depend on `transaction_circuit::{TransactionProof, VerifyingKey, verify}` and `state::merkle::CommitmentTree`. They produce a `BlockProof` struct containing aggregated transaction metadata and a recursion placeholder `RecursiveAggregation` struct.
- Errors use `thiserror::Error`. Tests depend on `rand` for deterministic note generation.

