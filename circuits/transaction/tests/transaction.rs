use p3_field::PrimeCharacteristicRing;
use protocol_versioning::{DEFAULT_TX_PROOF_BACKEND, SMALLWOOD_CANDIDATE_VERSION_BINDING};
use transaction_circuit::constants::CIRCUIT_MERKLE_DEPTH;
use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, Felt, HashFelt};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::{MerklePath, NoteData};
use transaction_circuit::p3_prover::TransactionProofParams;
use transaction_circuit::p3_verifier::{
    verify_transaction_proof_bytes_p3, verify_transaction_proof_bytes_p3_for_version,
};
use transaction_circuit::proof::{prove, prove_with_params, stark_public_inputs_p3, verify};
use transaction_circuit::{
    projected_smallwood_candidate_proof_bytes, prove_smallwood_candidate, InputNoteWitness,
    OutputNoteWitness, StablecoinPolicyBinding, TransactionCircuitError, TransactionWitness,
};

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
        let zero = [Felt::ZERO; 6];
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
    let sk_spend = [42u8; 32];
    let pk_auth = transaction_circuit::hashing_pq::spend_auth_key_bytes(&sk_spend);
    let input_note_native = NoteData {
        value: 8,
        asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
        pk_recipient: [2u8; 32],
        pk_auth,
        rho: [3u8; 32],
        r: [4u8; 32],
    };
    let input_note_asset = NoteData {
        value: 5,
        asset_id: 1,
        pk_recipient: [5u8; 32],
        pk_auth,
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
            pk_auth: [111u8; 32],
            rho: [12u8; 32],
            r: [13u8; 32],
        },
    };
    let output_asset = OutputNoteWitness {
        note: NoteData {
            value: 5,
            asset_id: 1,
            pk_recipient: [21u8; 32],
            pk_auth: [121u8; 32],
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
        ciphertext_hashes: vec![[0u8; 48]; 2],
        sk_spend,
        merkle_root: felts_to_bytes48(&merkle_root),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    }
}

fn stablecoin_witness() -> TransactionWitness {
    let sk_spend = [8u8; 32];
    let pk_auth = transaction_circuit::hashing_pq::spend_auth_key_bytes(&sk_spend);
    let input_note_native = NoteData {
        value: 5,
        asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
        pk_recipient: [1u8; 32],
        pk_auth,
        rho: [2u8; 32],
        r: [3u8; 32],
    };

    let leaf0 = input_note_native.commitment();
    let leaf1 = [Felt::ZERO; 6];
    let (merkle_path0, _merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

    let output_stablecoin = OutputNoteWitness {
        note: NoteData {
            value: 5,
            asset_id: 4242,
            pk_recipient: [4u8; 32],
            pk_auth: [104u8; 32],
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
        ciphertext_hashes: vec![[0u8; 48]; 1],
        sk_spend,
        merkle_root: felts_to_bytes48(&merkle_root),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding {
            enabled: true,
            asset_id: 4242,
            policy_hash: [10u8; 48],
            oracle_commitment: [11u8; 48],
            attestation_commitment: [12u8; 48],
            issuance_delta: -5,
            policy_version: 1,
        },
        version: TransactionWitness::default_version_binding(),
    }
}

#[test]
#[cfg_attr(
    not(feature = "plonky3-e2e"),
    ignore = "slow: generates a full Plonky3 proof; run with --features plonky3-e2e --release"
)]
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
    let (_proving_key, verifying_key) = generate_keys();
    let public_inputs = witness.public_inputs().expect("public inputs");
    let trace =
        transaction_circuit::trace::TransactionTrace::from_witness(&witness).expect("trace");
    let mut proof = transaction_circuit::proof::TransactionProof {
        nullifiers: public_inputs.nullifiers.clone(),
        commitments: public_inputs.commitments.clone(),
        balance_slots: trace.padded_balance_slots(),
        public_inputs,
        backend: DEFAULT_TX_PROOF_BACKEND,
        stark_proof: Vec::new(),
        stark_public_inputs: None,
    };
    proof.balance_slots[1].delta = 1; // corrupt non-native slot
    let err = verify(&proof, &verifying_key).expect_err("expected failure");
    assert!(matches!(err, TransactionCircuitError::BalanceMismatch(_)));
}

#[test]
#[cfg_attr(
    not(feature = "plonky3-e2e"),
    ignore = "slow: generates a full Plonky3 proof; run with --features plonky3-e2e --release"
)]
fn verification_fails_for_nullifier_mutation() {
    let witness = sample_witness();
    let (proving_key, verifying_key) = generate_keys();
    let mut proof = prove(&witness, &proving_key).expect("proof generation");
    proof.nullifiers[0][0] ^= 0x01; // tamper with nullifier
                                    // With real STARK proofs, tampering with public inputs causes verification failure.
    let err = verify(&proof, &verifying_key).expect_err("expected failure");
    // STARK proofs return generic constraint violation for any tampering
    assert!(
        matches!(
            err,
            TransactionCircuitError::ConstraintViolation(_)
                | TransactionCircuitError::ConstraintViolationOwned(_)
        ),
        "Expected STARK verification failure, got: {:?}",
        err
    );
}

#[test]
#[ignore = "experimental SmallWood packed candidate release proving is still too slow for the default test profile"]
fn smallwood_candidate_roundtrip_verifies() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let (_proving_key, verifying_key) = generate_keys();
    let proof = prove_smallwood_candidate(&witness).expect("smallwood candidate proof");
    eprintln!(
        "smallwood candidate proof bytes: {}",
        proof.stark_proof.len()
    );
    let report = verify(&proof, &verifying_key).expect("smallwood verification");
    assert!(report.verified);
}

#[test]
fn smallwood_candidate_proof_stays_below_shipped_plonky3_baseline() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let proof_bytes = projected_smallwood_candidate_proof_bytes(&witness)
        .expect("projected smallwood candidate proof bytes");
    eprintln!("smallwood candidate projected proof bytes: {proof_bytes}");
    assert!(
        proof_bytes < 354_081,
        "expected smallwood candidate proof to stay below the shipped plonky3 baseline, got {} bytes",
        proof_bytes
    );
}

#[test]
fn smallwood_candidate_proof_stays_below_native_tx_leaf_cap() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let proof_bytes = projected_smallwood_candidate_proof_bytes(&witness)
        .expect("projected smallwood candidate proof bytes");
    eprintln!("smallwood candidate projected proof bytes: {proof_bytes}");
    assert!(
        proof_bytes < 524_288,
        "expected smallwood candidate proof to stay below the native tx-leaf cap, got {} bytes",
        proof_bytes
    );
}

#[test]
#[ignore = "experimental SmallWood packed candidate release proving is still too slow for the default test profile"]
fn smallwood_candidate_rejects_semantic_mutation() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let (_proving_key, verifying_key) = generate_keys();
    let mut proof = prove_smallwood_candidate(&witness).expect("smallwood candidate proof");
    proof.public_inputs.balance_tag[0] ^= 0x5a;
    let err = verify(&proof, &verifying_key).expect_err("tampered candidate must fail");
    assert!(
        err.to_string().contains("smallwood candidate") || err.to_string().contains("mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
#[cfg_attr(
    not(feature = "plonky3-e2e"),
    ignore = "slow: generates a full Plonky3 proof; run with --features plonky3-e2e --release"
)]
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
        matches!(
            err,
            TransactionCircuitError::ConstraintViolation(_)
                | TransactionCircuitError::ConstraintViolationOwned(_)
        ),
        "Expected STARK verification failure, got: {:?}",
        err
    );
}

#[test]
#[cfg_attr(
    not(feature = "plonky3-e2e"),
    ignore = "slow: generates a full Plonky3 proof; run with --features plonky3-e2e --release"
)]
fn low_query_proof_is_rejected_by_release_profile() {
    let witness = sample_witness();
    let (proving_key, _verifying_key) = generate_keys();
    let proof = prove_with_params(
        &witness,
        &proving_key,
        TransactionProofParams {
            log_blowup: 4,
            num_queries: 16,
        },
    )
    .expect("proof generation");
    let stark_public_inputs = stark_public_inputs_p3(&proof).expect("decode public inputs");
    verify_transaction_proof_bytes_p3(&proof.stark_proof, &stark_public_inputs)
        .expect("shape-specific verifier should accept the proof");
    let err = verify_transaction_proof_bytes_p3_for_version(
        &proof.stark_proof,
        &stark_public_inputs,
        witness.version,
    )
    .expect_err("release verifier should reject low-query proof");
    assert!(
        err.to_string().contains("proof FRI profile mismatch"),
        "unexpected verifier error: {err}"
    );
}
