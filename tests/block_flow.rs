//! Block aggregation circuit integration tests.
//!
//! These tests verify that the block_circuit correctly aggregates multiple
//! transaction proofs and maintains proper Merkle tree state.

use block_circuit::{prove_block_fast, verify_block, BlockError};
use protocol_versioning::{VersionBinding, DEFAULT_VERSION_BINDING};
use std::collections::HashMap;
use transaction_circuit::{
    constants::{CIRCUIT_MERKLE_DEPTH, NATIVE_ASSET_ID},
    hashing::{felts_to_bytes32, merkle_node, Felt, HashFelt},
    keys::generate_keys,
    note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness},
    proof::{SerializedStarkInputs, TransactionProof},
    rpo_prover::TransactionProverStarkRpo,
    StablecoinPolicyBinding, TransactionWitness,
    trace::TransactionTrace,
};
use winterfell::Prover;

/// Build a Merkle tree with 2 leaves at positions 0 and 1.
/// Returns paths and root consistent with CIRCUIT_MERKLE_DEPTH.
fn build_two_leaf_merkle_tree(
    leaf0: HashFelt,
    leaf1: HashFelt,
) -> (MerklePath, MerklePath, HashFelt) {
    let mut siblings0 = vec![leaf1];
    let mut siblings1 = vec![leaf0];

    let mut current = merkle_node(leaf0, leaf1);

    for _ in 1..CIRCUIT_MERKLE_DEPTH {
        let zero = [Felt::ZERO; 4];
        siblings0.push(zero);
        siblings1.push(zero);
        current = merkle_node(current, zero);
    }

    let path0 = MerklePath { siblings: siblings0 };
    let path1 = MerklePath { siblings: siblings1 };

    (path0, path1, current)
}

/// Create a valid witness with proper Merkle paths for testing.
/// The witness spends 2 notes (native + asset) and creates 2 outputs.
fn make_valid_witness(seed: u64) -> (TransactionWitness, Vec<HashFelt>) {
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
        merkle_root: felts_to_bytes32(&merkle_root),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: DEFAULT_VERSION_BINDING,
    };

    // Return the output commitments for tracking state
    let output_commitments = vec![
        output_native.note.commitment(),
        output_asset.note.commitment(),
    ];

    (witness, output_commitments)
}

fn rpo_prover() -> TransactionProverStarkRpo {
    #[cfg(feature = "stark-fast")]
    {
        let options = winterfell::ProofOptions::new(
            8,
            8,
            0,
            winterfell::FieldExtension::None,
            2,
            7,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        );
        TransactionProverStarkRpo::new(options)
    }
    #[cfg(not(feature = "stark-fast"))]
    {
        let options = winterfell::ProofOptions::new(
            32,
            8,
            0,
            winterfell::FieldExtension::None,
            2,
            7,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        );
        TransactionProverStarkRpo::new(options)
    }
}

fn build_rpo_proof(witness: &TransactionWitness) -> TransactionProof {
    let public_inputs = witness.public_inputs().expect("public inputs");
    let legacy_trace = TransactionTrace::from_witness(witness).expect("trace");
    let prover = rpo_prover();
    let trace = prover.build_trace(witness).expect("stark trace");
    let stark_pub_inputs = prover.get_pub_inputs(&trace);
    let proof_bytes = prover.prove(trace).expect("rpo proof").to_bytes();

    let input_flags = stark_pub_inputs
        .input_flags
        .iter()
        .map(|f| f.as_int() as u8)
        .collect();
    let output_flags = stark_pub_inputs
        .output_flags
        .iter()
        .map(|f| f.as_int() as u8)
        .collect();
    let fee = stark_pub_inputs.fee.as_int();
    let value_balance_sign = stark_pub_inputs.value_balance_sign.as_int() as u8;
    let value_balance_magnitude = stark_pub_inputs.value_balance_magnitude.as_int();
    let stablecoin_enabled = stark_pub_inputs.stablecoin_enabled.as_int() as u8;
    let stablecoin_asset_id = stark_pub_inputs.stablecoin_asset.as_int();
    let stablecoin_policy_version = stark_pub_inputs.stablecoin_policy_version.as_int() as u32;
    let stablecoin_issuance_sign = stark_pub_inputs.stablecoin_issuance_sign.as_int() as u8;
    let stablecoin_issuance_magnitude = stark_pub_inputs.stablecoin_issuance_magnitude.as_int();

    let nullifiers = stark_pub_inputs
        .nullifiers
        .iter()
        .map(felts_to_bytes32)
        .collect();
    let commitments = stark_pub_inputs
        .commitments
        .iter()
        .map(felts_to_bytes32)
        .collect();
    let merkle_root = felts_to_bytes32(&stark_pub_inputs.merkle_root);
    let stablecoin_policy_hash = felts_to_bytes32(&stark_pub_inputs.stablecoin_policy_hash);
    let stablecoin_oracle_commitment =
        felts_to_bytes32(&stark_pub_inputs.stablecoin_oracle_commitment);
    let stablecoin_attestation_commitment =
        felts_to_bytes32(&stark_pub_inputs.stablecoin_attestation_commitment);

    TransactionProof {
        public_inputs,
        nullifiers,
        commitments,
        balance_slots: legacy_trace.padded_balance_slots(),
        stark_proof: proof_bytes,
        stark_public_inputs: Some(SerializedStarkInputs {
            input_flags,
            output_flags,
            fee,
            value_balance_sign,
            value_balance_magnitude,
            merkle_root,
            stablecoin_enabled,
            stablecoin_asset_id,
            stablecoin_policy_version,
            stablecoin_issuance_sign,
            stablecoin_issuance_magnitude,
            stablecoin_policy_hash,
            stablecoin_oracle_commitment,
            stablecoin_attestation_commitment,
        }),
    }
}

#[test]
fn block_proof_single_transaction() {
    let (_proving_key, verifying_key) = generate_keys();
    let mut verifying_keys = HashMap::new();
    verifying_keys.insert(DEFAULT_VERSION_BINDING, verifying_key);

    // Create a single valid transaction
    let (witness, _commitments) = make_valid_witness(0);
    let proof = build_rpo_proof(&witness);

    let proofs = vec![proof];

    // Use CommitmentTree for state tracking
    let mut tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    let block_proof = prove_block_fast(&mut tree, &proofs, &verifying_keys).expect("block proof");

    assert_eq!(block_proof.recursive_proof.tx_count, 1);
    assert_eq!(block_proof.transactions.len(), 1);

    // Verify the block proof
    let mut verify_tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    let report = verify_block(&mut verify_tree, &block_proof, &verifying_keys).expect("verify");
    assert!(report.verified);
}

#[test]
fn duplicate_nullifiers_across_transactions_rejected() {
    let (_proving_key, verifying_key) = generate_keys();
    let mut verifying_keys = HashMap::new();
    verifying_keys.insert(DEFAULT_VERSION_BINDING, verifying_key);

    // Create two proofs from SAME witness = same nullifiers
    let (witness_a, _) = make_valid_witness(0);
    let proof_a = build_rpo_proof(&witness_a);
    let proof_b = build_rpo_proof(&witness_a);

    // The block should reject duplicate nullifiers
    let proofs = vec![proof_a, proof_b];
    let mut tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");

    let result = prove_block_fast(&mut tree, &proofs, &verifying_keys);
    assert!(matches!(result, Err(BlockError::DuplicateNullifier(_))));
}

#[test]
fn multiple_independent_transactions_aggregate() {
    let (_proving_key, verifying_key) = generate_keys();
    let mut verifying_keys = HashMap::new();
    verifying_keys.insert(DEFAULT_VERSION_BINDING, verifying_key);

    // Create multiple transactions with different seeds (independent nullifiers)
    let (witness_0, _) = make_valid_witness(0);
    let (witness_1, _) = make_valid_witness(100);

    let proof_0 = build_rpo_proof(&witness_0);
    let proof_1 = build_rpo_proof(&witness_1);

    let proofs = vec![proof_0, proof_1];
    let mut tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");

    let block_proof = prove_block_fast(&mut tree, &proofs, &verifying_keys).expect("block proof");

    // Should have tracked both transactions
    assert_eq!(block_proof.recursive_proof.tx_count, 2);
    assert_eq!(block_proof.transactions.len(), 2);

    // Verify
    let mut verify_tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    let report = verify_block(&mut verify_tree, &block_proof, &verifying_keys).expect("verify");
    assert!(report.verified);
}

#[test]
fn missing_version_key_rejected() {
    let (_proving_key, verifying_key) = generate_keys();

    // Only register the default version key
    let mut verifying_keys = HashMap::new();
    verifying_keys.insert(DEFAULT_VERSION_BINDING, verifying_key);

    // Create a transaction with a different version
    let (mut witness, _) = make_valid_witness(0);
    witness.version = VersionBinding::new(99, DEFAULT_VERSION_BINDING.crypto);

    let proof = build_rpo_proof(&witness);
    let proofs = vec![proof];

    let mut tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    let result = prove_block_fast(&mut tree, &proofs, &verifying_keys);

    assert!(matches!(result, Err(BlockError::UnsupportedVersion { .. })));
}

#[test]
fn mixed_versions_work_with_all_keys() {
    let (_proving_key, verifying_key) = generate_keys();

    // Register multiple version keys
    let mut verifying_keys = HashMap::new();
    verifying_keys.insert(DEFAULT_VERSION_BINDING, verifying_key.clone());
    let v2 = VersionBinding::new(2, DEFAULT_VERSION_BINDING.crypto);
    verifying_keys.insert(v2, verifying_key);

    // Create transactions with different versions
    let (witness_v1, _) = make_valid_witness(0);
    let (mut witness_v2, _) = make_valid_witness(100);
    witness_v2.version = v2;

    let proof_v1 = build_rpo_proof(&witness_v1);
    let proof_v2 = build_rpo_proof(&witness_v2);

    let proofs = vec![proof_v1, proof_v2];
    let mut tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");

    let block_proof = prove_block_fast(&mut tree, &proofs, &verifying_keys).expect("block proof");

    // Should track version counts
    assert_eq!(block_proof.version_counts.len(), 2);

    // Verify
    let mut verify_tree = state_merkle::CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    let report = verify_block(&mut verify_tree, &block_proof, &verifying_keys).expect("verify");
    assert!(report.verified);
}
