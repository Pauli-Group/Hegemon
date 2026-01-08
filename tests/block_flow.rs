//! Block commitment circuit integration tests.
//!
//! These tests verify that the block commitment proof aggregates transaction
//! proofs and enforces nullifier uniqueness and anchor validation.

use block_circuit::{verify_block_commitment, BlockError, CommitmentBlockProver};
use protocol_versioning::DEFAULT_VERSION_BINDING;
use state_merkle::CommitmentTree;
use transaction_circuit::{
    constants::{CIRCUIT_MERKLE_DEPTH, NATIVE_ASSET_ID},
    hashing_pq::{bytes48_to_felts, felts_to_bytes48},
    note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness},
    proof,
    TransactionProof, TransactionWitness, StablecoinPolicyBinding,
};

fn append_note(tree: &mut CommitmentTree, note: &NoteData) -> usize {
    let commitment = felts_to_bytes48(&note.commitment());
    let (index, _) = tree.append(commitment).expect("append");
    index
}

fn merkle_path_from_tree(tree: &CommitmentTree, index: usize) -> MerklePath {
    let siblings = tree
        .authentication_path(index)
        .expect("merkle path")
        .into_iter()
        .map(|sibling| bytes48_to_felts(&sibling).expect("canonical merkle sibling"))
        .collect();
    MerklePath { siblings }
}

fn make_valid_witness(seed: u64, tree: &mut CommitmentTree) -> TransactionWitness {
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

    let pos0 = append_note(tree, &input_native);
    let pos1 = append_note(tree, &input_asset);
    let merkle_root = tree.root();

    let path0 = merkle_path_from_tree(tree, pos0);
    let path1 = merkle_path_from_tree(tree, pos1);

    let output_native = OutputNoteWitness {
        note: NoteData {
            value: 4,
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

    TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_native,
                position: pos0 as u64,
                rho_seed: [seed as u8 + 4; 32],
                merkle_path: path0,
            },
            InputNoteWitness {
                note: input_asset,
                position: pos1 as u64,
                rho_seed: [seed as u8 + 8; 32],
                merkle_path: path1,
            },
        ],
        outputs: vec![output_native, output_asset],
        sk_spend: [seed as u8 + 15; 32],
        merkle_root,
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: DEFAULT_VERSION_BINDING,
    }
}

fn build_proof(witness: &TransactionWitness) -> TransactionProof {
    let (proving_key, _) = transaction_circuit::generate_keys();
    proof::prove(witness, &proving_key).expect("proof")
}

#[test]
fn block_commitment_single_transaction() {
    let mut tree = CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    let witness = make_valid_witness(0, &mut tree);
    let proof = build_proof(&witness);
    let proofs = vec![proof];

    let prover = CommitmentBlockProver::new();
    let block_proof = prover
        .prove_block_commitment_with_tree(&mut tree, &proofs, [0u8; 48])
        .expect("block proof");

    assert_eq!(block_proof.public_inputs.tx_count, 1);
    verify_block_commitment(&block_proof).expect("verify");
}

#[test]
fn duplicate_nullifiers_across_transactions_rejected() {
    let mut tree = CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    let witness = make_valid_witness(0, &mut tree);
    let proof = build_proof(&witness);
    let proofs = vec![proof.clone(), proof];

    let prover = CommitmentBlockProver::new();
    let result = prover.prove_block_commitment_with_tree(&mut tree, &proofs, [0u8; 48]);

    assert!(matches!(result, Err(BlockError::DuplicateNullifier(_))));
}

#[test]
fn multiple_independent_transactions_aggregate() {
    let mut tree = CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    let witness_0 = make_valid_witness(0, &mut tree);
    let witness_1 = make_valid_witness(100, &mut tree);

    let proof_0 = build_proof(&witness_0);
    let proof_1 = build_proof(&witness_1);
    let proofs = vec![proof_0, proof_1];

    let prover = CommitmentBlockProver::new();
    let block_proof = prover
        .prove_block_commitment_with_tree(&mut tree, &proofs, [0u8; 48])
        .expect("block proof");

    assert_eq!(block_proof.public_inputs.tx_count, 2);
    verify_block_commitment(&block_proof).expect("verify");
}

#[test]
fn anchor_not_in_history_rejected() {
    let mut tree = CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    let witness = make_valid_witness(0, &mut tree);
    let proof = build_proof(&witness);

    let mut other_tree = CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    let prover = CommitmentBlockProver::new();
    let result = prover.prove_block_commitment_with_tree(&mut other_tree, &[proof], [0u8; 48]);

    assert!(matches!(result, Err(BlockError::UnexpectedMerkleRoot { .. })));
}
