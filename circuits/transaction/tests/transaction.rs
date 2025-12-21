use transaction_circuit::constants::CIRCUIT_MERKLE_DEPTH;
use transaction_circuit::hashing::{felts_to_bytes32, merkle_node, Felt, HashFelt};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::{MerklePath, NoteData};
use transaction_circuit::proof::{prove, verify};
use transaction_circuit::{
    InputNoteWitness, OutputNoteWitness, StablecoinPolicyBinding, TransactionCircuitError,
    TransactionWitness,
};
use winterfell::math::FieldElement;

/// Compute the Merkle root from a leaf and path using CIRCUIT_MERKLE_DEPTH levels.
/// This matches what the STARK circuit actually verifies.
fn compute_merkle_root(leaf: HashFelt, position: u64, path: &[HashFelt]) -> HashFelt {
    let mut current = leaf;
    let mut pos = position;
    for (_level, sibling) in path.iter().enumerate().take(CIRCUIT_MERKLE_DEPTH) {
        current = if pos & 1 == 0 {
            merkle_node(current, *sibling)
        } else {
            merkle_node(*sibling, current)
        };
        pos >>= 1;
    }
    current
}

/// Build a minimal Merkle tree with 2 leaves at positions 0 and 1.
/// Returns paths and root consistent with CIRCUIT_MERKLE_DEPTH.
fn build_two_leaf_merkle_tree(
    leaf0: HashFelt,
    leaf1: HashFelt,
) -> (MerklePath, MerklePath, HashFelt) {
    // At level 0: leaf0 at position 0, leaf1 at position 1 (siblings of each other)
    let mut siblings0 = vec![leaf1]; // For position 0, sibling is leaf1
    let mut siblings1 = vec![leaf0]; // For position 1, sibling is leaf0

    // Compute parent and continue up the tree with zero siblings
    let mut current = merkle_node(leaf0, leaf1);

    // Fill remaining levels up to CIRCUIT_MERKLE_DEPTH with zeros
    for _ in 1..CIRCUIT_MERKLE_DEPTH {
        let zero = [Felt::ZERO; 4];
        siblings0.push(zero);
        siblings1.push(zero);
        current = merkle_node(current, zero);
    }

    let path0 = MerklePath {
        siblings: siblings0,
    };
    let path1 = MerklePath {
        siblings: siblings1,
    };

    (path0, path1, current)
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

    // Build proper Merkle tree with both input notes using CIRCUIT_MERKLE_DEPTH
    let leaf0 = input_note_native.commitment();
    let leaf1 = input_note_asset.commitment();
    let (merkle_path0, merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

    // Verify paths compute to root correctly
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
        merkle_root: felts_to_bytes32(&merkle_root),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    }
}

fn stablecoin_witness() -> TransactionWitness {
    let input_note_native = NoteData {
        value: 5,
        asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
        pk_recipient: [1u8; 32],
        rho: [2u8; 32],
        r: [3u8; 32],
    };

    let leaf0 = input_note_native.commitment();
    let leaf1 = [Felt::ZERO; 4];
    let (merkle_path0, _merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

    let output_stablecoin = OutputNoteWitness {
        note: NoteData {
            value: 5,
            asset_id: 4242,
            pk_recipient: [4u8; 32],
            rho: [5u8; 32],
            r: [6u8; 32],
        },
    };

    TransactionWitness {
        inputs: vec![InputNoteWitness {
            note: input_note_native,
            position: 0,
            rho_seed: [7u8; 32],
            merkle_path: merkle_path0,
        }],
        outputs: vec![output_stablecoin],
        sk_spend: [8u8; 32],
        merkle_root: felts_to_bytes32(&merkle_root),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding {
            enabled: true,
            asset_id: 4242,
            policy_hash: [10u8; 32],
            oracle_commitment: [11u8; 32],
            attestation_commitment: [12u8; 32],
            issuance_delta: -5,
            policy_version: 1,
        },
        version: TransactionWitness::default_version_binding(),
    }
}

#[test]
fn proving_and_verification_succeeds() -> Result<(), TransactionCircuitError> {
    let witness = sample_witness();
    let (proving_key, verifying_key) = generate_keys();
    let proof = prove(&witness, &proving_key)?;
    assert!(
        proof.has_stark_proof(),
        "Proof should have real STARK proof bytes"
    );
    let report = verify(&proof, &verifying_key)?;
    assert!(report.verified);
    Ok(())
}

#[test]
fn verification_fails_for_bad_balance() {
    let witness = sample_witness();
    let (proving_key, verifying_key) = generate_keys();
    let mut proof = prove(&witness, &proving_key).expect("proof generation");
    proof.balance_slots[1].delta = 1; // corrupt non-native slot
    let err = verify(&proof, &verifying_key).expect_err("expected failure");
    assert!(matches!(err, TransactionCircuitError::BalanceMismatch(_)));
}

#[test]
fn verification_fails_for_nullifier_mutation() {
    let witness = sample_witness();
    let (proving_key, verifying_key) = generate_keys();
    let mut proof = prove(&witness, &proving_key).expect("proof generation");
    proof.nullifiers[0][0] ^= 0x01; // tamper with nullifier
                                    // With real STARK proofs, tampering with public inputs causes verification failure.
    let err = verify(&proof, &verifying_key).expect_err("expected failure");
    // STARK proofs return generic constraint violation for any tampering
    assert!(
        matches!(err, TransactionCircuitError::ConstraintViolation(_)),
        "Expected STARK verification failure, got: {:?}",
        err
    );
}

#[test]
fn verification_fails_for_stablecoin_policy_hash_mutation() {
    let witness = stablecoin_witness();
    let (proving_key, verifying_key) = generate_keys();
    let mut proof = prove(&witness, &proving_key).expect("proof generation");
    let mut stark_inputs = proof
        .stark_public_inputs
        .clone()
        .expect("stark public inputs");
    stark_inputs.stablecoin_policy_hash[0] ^= 0x01;
    proof.stark_public_inputs = Some(stark_inputs);
    let err = verify(&proof, &verifying_key).expect_err("expected failure");
    assert!(
        matches!(err, TransactionCircuitError::ConstraintViolation(_)),
        "Expected STARK verification failure, got: {:?}",
        err
    );
}
