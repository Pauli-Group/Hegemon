use aggregation_circuit::prove_aggregation;
use consensus::verify_aggregation_proof;
use transaction_circuit::constants::CIRCUIT_MERKLE_DEPTH;
use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, Felt, HashFelt};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::{MerklePath, NoteData};
use transaction_circuit::{
    InputNoteWitness, OutputNoteWitness, StablecoinPolicyBinding, TransactionWitness,
};

fn compute_merkle_root(leaf: HashFelt, position: u64, path: &[HashFelt]) -> HashFelt {
    let mut current = leaf;
    let mut pos = position;
    for sibling in path.iter().take(CIRCUIT_MERKLE_DEPTH) {
        current = if pos & 1 == 0 {
            merkle_node(current, *sibling)
        } else {
            merkle_node(*sibling, current)
        };
        pos >>= 1;
    }
    current
}

fn build_two_leaf_merkle_tree(
    leaf0: HashFelt,
    leaf1: HashFelt,
) -> (MerklePath, MerklePath, HashFelt) {
    let mut siblings0 = vec![leaf1];
    let mut siblings1 = vec![leaf0];
    let mut current = merkle_node(leaf0, leaf1);

    for _ in 1..CIRCUIT_MERKLE_DEPTH {
        let zero = [Felt::ZERO; 6];
        siblings0.push(zero);
        siblings1.push(zero);
        current = merkle_node(current, zero);
    }

    (
        MerklePath { siblings: siblings0 },
        MerklePath { siblings: siblings1 },
        current,
    )
}

fn sample_witness() -> TransactionWitness {
    let input_note_native = NoteData {
        value: 8,
        asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
        pk_recipient: [2u8; 32],
        rho: [3u8; 32],
        r: [4u8; 32],
    };
    let input_note_asset = NoteData {
        value: 5,
        asset_id: 1,
        pk_recipient: [5u8; 32],
        rho: [6u8; 32],
        r: [7u8; 32],
    };

    let leaf0 = input_note_native.commitment();
    let leaf1 = input_note_asset.commitment();
    let (merkle_path0, merkle_path1, merkle_root) =
        build_two_leaf_merkle_tree(leaf0, leaf1);
    assert_eq!(
        compute_merkle_root(leaf0, 0, &merkle_path0.siblings),
        merkle_root
    );
    assert_eq!(
        compute_merkle_root(leaf1, 1, &merkle_path1.siblings),
        merkle_root
    );

    let output_native = OutputNoteWitness {
        note: NoteData {
            value: 3,
            asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
            pk_recipient: [11u8; 32],
            rho: [12u8; 32],
            r: [13u8; 32],
        },
    };
    let output_asset = OutputNoteWitness {
        note: NoteData {
            value: 5,
            asset_id: 1,
            pk_recipient: [21u8; 32],
            rho: [22u8; 32],
            r: [23u8; 32],
        },
    };

    TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_note_native,
                position: 0,
                rho_seed: [9u8; 32],
                merkle_path: merkle_path0,
            },
            InputNoteWitness {
                note: input_note_asset,
                position: 1,
                rho_seed: [8u8; 32],
                merkle_path: merkle_path1,
            },
        ],
        outputs: vec![output_native, output_asset],
        sk_spend: [42u8; 32],
        merkle_root: felts_to_bytes48(&merkle_root),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    }
}

#[test]
#[ignore = "slow aggregation proof generation"]
fn aggregation_proof_roundtrip() {
    let witness = sample_witness();
    let (proving_key, _verifying_key) = generate_keys();
    let proof = transaction_circuit::proof::prove(&witness, &proving_key)
        .expect("generate transaction proof");

    let proofs = vec![proof.clone(), proof.clone()];
    let aggregation_bytes = prove_aggregation(&proofs).expect("generate aggregation proof");

    verify_aggregation_proof(&aggregation_bytes, &proofs)
        .expect("verify aggregation proof");

    let mut corrupted = proofs.clone();
    corrupted[0].stark_proof[0] ^= 0x01;

    let err = verify_aggregation_proof(&aggregation_bytes, &corrupted)
        .expect_err("corrupted proof should fail");
    assert!(matches!(
        err,
        consensus::ProofError::AggregationProofVerification(_)
    ));
}
