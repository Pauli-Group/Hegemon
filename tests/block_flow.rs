//! Block aggregation circuit integration tests.
//!
//! These tests verify that the block_circuit correctly aggregates multiple
//! transaction proofs and maintains proper Merkle tree state.

use block_circuit::{prove_block, verify_block, BlockError};
use protocol_versioning::{VersionBinding, DEFAULT_VERSION_BINDING};
use std::collections::HashMap;
use transaction_circuit::{
    constants::{CIRCUIT_MERKLE_DEPTH, NATIVE_ASSET_ID},
    hashing::{merkle_node, Felt},
    keys::generate_keys,
    note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness},
    proof::prove,
    TransactionWitness,
};
use winter_math::FieldElement;

/// Build a Merkle tree with 2 leaves at positions 0 and 1.
/// Returns paths and root consistent with CIRCUIT_MERKLE_DEPTH.
fn build_two_leaf_merkle_tree(leaf0: Felt, leaf1: Felt) -> (MerklePath, MerklePath, Felt) {
    let mut siblings0 = vec![leaf1];
    let mut siblings1 = vec![leaf0];

    let mut current = merkle_node(leaf0, leaf1);

    for _ in 1..CIRCUIT_MERKLE_DEPTH {
        siblings0.push(Felt::ZERO);
        siblings1.push(Felt::ZERO);
        current = merkle_node(current, Felt::ZERO);
    }

    let path0 = MerklePath { siblings: siblings0 };
    let path1 = MerklePath { siblings: siblings1 };

    (path0, path1, current)
}

/// Create a valid witness with proper Merkle paths for testing.
/// The witness spends 2 notes (native + asset) and creates 2 outputs.
fn make_valid_witness(seed: u64) -> (TransactionWitness, Vec<Felt>) {
    // Create input notes
    let input_native = NoteData {
        value: 9,
        asset_id: NATIVE_ASSET_ID,
        pk_recipient: [seed as u8 + 1; 32],
        rho: [seed as u8 + 2; 32],
        r: [seed as u8 + 3; 32],
    };

    let input_asset = NoteData {
        value: 7,
        asset_id: seed + 100,
        pk_recipient: [seed as u8 + 5; 32],
        rho: [seed as u8 + 6; 32],
        r: [seed as u8 + 7; 32],
    };

    // Build Merkle tree with input note commitments
    let leaf0 = input_native.commitment();
    let leaf1 = input_asset.commitment();
    let (path0, path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

    // Create output notes
    let output_native = OutputNoteWitness {
        note: NoteData {
            value: 4, // 9 - 5 (fee)
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [seed as u8 + 9; 32],
            rho: [seed as u8 + 10; 32],
            r: [seed as u8 + 11; 32],
        },
    };

    let output_asset = OutputNoteWitness {
        note: NoteData {
            value: 7,
            asset_id: seed + 100,
            pk_recipient: [seed as u8 + 12; 32],
            rho: [seed as u8 + 13; 32],
            r: [seed as u8 + 14; 32],
        },
    };

    let witness = TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_native,
                position: 0,
                rho_seed: [seed as u8 + 4; 32],
                merkle_path: path0,
            },
            InputNoteWitness {
                note: input_asset,
                position: 1,
                rho_seed: [seed as u8 + 8; 32],
                merkle_path: path1,
            },
        ],
        outputs: vec![output_native.clone(), output_asset.clone()],
        sk_spend: [seed as u8 + 15; 32],
        merkle_root,
        fee: 5,
        version: DEFAULT_VERSION_BINDING,
    };

    // Return the output commitments for tracking state
    let output_commitments = vec![
        output_native.note.commitment(),
        output_asset.note.commitment(),
    ];

    (witness, output_commitments)
}

#[test]
fn block_proof_single_transaction() {
    let (proving_key, verifying_key) = generate_keys();
    let mut verifying_keys = HashMap::new();
    verifying_keys.insert(DEFAULT_VERSION_BINDING, verifying_key);

    // Create a single valid transaction
    let (witness, _commitments) = make_valid_witness(0);
    let proof = prove(&witness, &proving_key).expect("prove transaction");

    let proofs = vec![proof];

    // Use CommitmentTree for state tracking
    let mut tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    let block_proof = prove_block(&mut tree, &proofs, &verifying_keys).expect("block proof");

    assert_eq!(block_proof.root_trace.len(), 2); // start + 1 tx
    assert!(block_proof.transactions.len() == 1);

    // Verify the block proof
    let mut verify_tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    let report = verify_block(&mut verify_tree, &block_proof, &verifying_keys).expect("verify");
    assert!(report.verified);
}

#[test]
fn duplicate_nullifiers_across_transactions_rejected() {
    let (proving_key, verifying_key) = generate_keys();
    let mut verifying_keys = HashMap::new();
    verifying_keys.insert(DEFAULT_VERSION_BINDING, verifying_key);

    // Create two proofs from SAME witness = same nullifiers
    let (witness_a, _) = make_valid_witness(0);
    let proof_a = prove(&witness_a, &proving_key).expect("prove a");
    let proof_b = prove(&witness_a, &proving_key).expect("prove b");

    // The block should reject duplicate nullifiers
    let proofs = vec![proof_a, proof_b];
    let mut tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");

    let result = prove_block(&mut tree, &proofs, &verifying_keys);
    assert!(matches!(result, Err(BlockError::DuplicateNullifier(_))));
}

#[test]
fn multiple_independent_transactions_aggregate() {
    let (proving_key, verifying_key) = generate_keys();
    let mut verifying_keys = HashMap::new();
    verifying_keys.insert(DEFAULT_VERSION_BINDING, verifying_key);

    // Create multiple transactions with different seeds (independent nullifiers)
    let (witness_0, _) = make_valid_witness(0);
    let (witness_1, _) = make_valid_witness(100);

    let proof_0 = prove(&witness_0, &proving_key).expect("prove 0");
    let proof_1 = prove(&witness_1, &proving_key).expect("prove 1");

    let proofs = vec![proof_0, proof_1];
    let mut tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");

    let block_proof = prove_block(&mut tree, &proofs, &verifying_keys).expect("block proof");

    // Should have tracked both transactions
    assert_eq!(block_proof.root_trace.len(), 3); // start + 2 txs
    assert_eq!(block_proof.transactions.len(), 2);

    // Verify
    let mut verify_tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    let report = verify_block(&mut verify_tree, &block_proof, &verifying_keys).expect("verify");
    assert!(report.verified);
}

#[test]
fn missing_version_key_rejected() {
    let (proving_key, verifying_key) = generate_keys();

    // Only register the default version key
    let mut verifying_keys = HashMap::new();
    verifying_keys.insert(DEFAULT_VERSION_BINDING, verifying_key);

    // Create a transaction with a different version
    let (mut witness, _) = make_valid_witness(0);
    witness.version = VersionBinding::new(99, DEFAULT_VERSION_BINDING.crypto);

    let proof = prove(&witness, &proving_key).expect("prove");
    let proofs = vec![proof];

    let mut tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    let result = prove_block(&mut tree, &proofs, &verifying_keys);

    assert!(matches!(result, Err(BlockError::UnsupportedVersion { .. })));
}

#[test]
fn mixed_versions_work_with_all_keys() {
    let (proving_key, verifying_key) = generate_keys();

    // Register multiple version keys
    let mut verifying_keys = HashMap::new();
    verifying_keys.insert(DEFAULT_VERSION_BINDING, verifying_key.clone());
    let v2 = VersionBinding::new(2, DEFAULT_VERSION_BINDING.crypto);
    verifying_keys.insert(v2, verifying_key);

    // Create transactions with different versions
    let (witness_v1, _) = make_valid_witness(0);
    let (mut witness_v2, _) = make_valid_witness(100);
    witness_v2.version = v2;

    let proof_v1 = prove(&witness_v1, &proving_key).expect("prove v1");
    let proof_v2 = prove(&witness_v2, &proving_key).expect("prove v2");

    let proofs = vec![proof_v1, proof_v2];
    let mut tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");

    let block_proof = prove_block(&mut tree, &proofs, &verifying_keys).expect("block proof");

    // Should track version counts
    assert_eq!(block_proof.version_counts.len(), 2);

    // Verify
    let mut verify_tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    let report = verify_block(&mut verify_tree, &block_proof, &verifying_keys).expect("verify");
    assert!(report.verified);
}
