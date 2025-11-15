use block_circuit::{prove_block, verify_block, BlockError};
use state_merkle::CommitmentTree;
use transaction_circuit::{
    constants::NATIVE_ASSET_ID,
    hashing::Felt,
    keys::generate_keys,
    note::{InputNoteWitness, NoteData, OutputNoteWitness},
    proof::prove,
    TransactionProof, TransactionWitness,
};

fn make_witness(root: Felt, seed: u64) -> TransactionWitness {
    let input_native = InputNoteWitness {
        note: NoteData {
            value: 9,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [seed as u8 + 1; 32],
            rho: [seed as u8 + 2; 32],
            r: [seed as u8 + 3; 32],
        },
        position: seed * 10 + 1,
        rho_seed: [seed as u8 + 4; 32],
    };

    let input_asset = InputNoteWitness {
        note: NoteData {
            value: 7,
            asset_id: seed + 100,
            pk_recipient: [seed as u8 + 5; 32],
            rho: [seed as u8 + 6; 32],
            r: [seed as u8 + 7; 32],
        },
        position: seed * 10 + 2,
        rho_seed: [seed as u8 + 8; 32],
    };

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
        inputs: vec![input_native, input_asset],
        outputs: vec![output_native, output_asset],
        sk_spend: [seed as u8 + 15; 32],
        merkle_root: root,
        fee: 5,
    }
}

fn apply_commitments(tree: &mut CommitmentTree, proof: &TransactionProof) {
    let zero = Felt::new(0);
    for &commitment in proof.commitments.iter().filter(|c| **c != zero) {
        tree.append(commitment).expect("append");
    }
}

#[test]
fn block_proof_updates_state_and_verifies() {
    let depth = 8;
    let mut tree = CommitmentTree::new(depth).expect("tree depth");
    let mut expected_tree = tree.clone();
    let (proving_key, verifying_key) = generate_keys();

    let mut proofs = Vec::new();
    for seed in 0..2u64 {
        let root = expected_tree.root();
        let witness = make_witness(root, seed);
        let proof = prove(&witness, &proving_key).expect("prove transaction");
        apply_commitments(&mut expected_tree, &proof);
        proofs.push(proof);
    }

    let block_proof = prove_block(&mut tree, &proofs, &verifying_key).expect("block proof");
    assert_eq!(tree.root(), expected_tree.root());
    assert_eq!(block_proof.root_trace.len(), proofs.len() + 1);
    assert_eq!(block_proof.starting_root, block_proof.root_trace[0]);
    assert_eq!(block_proof.ending_root, tree.root());

    let mut verification_tree = CommitmentTree::new(depth).expect("tree depth");
    let report = verify_block(&mut verification_tree, &block_proof, &verifying_key)
        .expect("verify block");
    assert!(report.verified);
    assert_eq!(verification_tree.root(), tree.root());
}

#[test]
fn duplicate_nullifiers_trigger_error() {
    let depth = 8;
    let mut tree = CommitmentTree::new(depth).expect("tree depth");
    let mut expected_tree = tree.clone();
    let (proving_key, verifying_key) = generate_keys();

    let root = expected_tree.root();
    let witness_a = make_witness(root, 0);
    let proof_a = prove(&witness_a, &proving_key).expect("proof");
    apply_commitments(&mut expected_tree, &proof_a);

    let witness_b = make_witness(expected_tree.root(), 1);
    let mut proof_b = prove(&witness_b, &proving_key).expect("proof");
    proof_b.nullifiers[0] = proof_a.nullifiers[0];
    proof_b.public_inputs.nullifiers[0] = proof_a.nullifiers[0];

    let proofs = vec![proof_a.clone(), proof_b];
    let err = prove_block(&mut tree, &proofs, &verifying_key).expect_err("duplicate");
    assert!(matches!(err, BlockError::DuplicateNullifier(_)));
}

#[test]
fn root_ordering_is_enforced() {
    let depth = 8;
    let mut tree = CommitmentTree::new(depth).expect("tree depth");
    let mut expected_tree = tree.clone();
    let (proving_key, verifying_key) = generate_keys();

    let mut proofs = Vec::new();
    for seed in 0..2u64 {
        let root = expected_tree.root();
        let witness = make_witness(root, seed);
        let proof = prove(&witness, &proving_key).expect("prove");
        apply_commitments(&mut expected_tree, &proof);
        proofs.push(proof);
    }

    let swapped = vec![proofs[1].clone(), proofs[0].clone()];
    let err = prove_block(&mut tree, &swapped, &verifying_key).expect_err("ordering");
    assert!(matches!(err, BlockError::UnexpectedMerkleRoot { .. }));
}
