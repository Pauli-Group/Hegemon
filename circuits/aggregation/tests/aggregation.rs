use aggregation_circuit::{
    prove_aggregation, prove_leaf_aggregation, prove_merge_aggregation, AggregationNodeKind,
    AggregationProofV5Payload, AGGREGATION_PROOF_FORMAT_ID_V5,
    AGGREGATION_PUBLIC_VALUES_ENCODING_V2,
};
use block_circuit::CommitmentBlockProver;
use consensus::verify_aggregation_proof;
use crypto::hashes::blake3_384;
use p3_field::PrimeCharacteristicRing;
use std::time::Instant;
use transaction_circuit::constants::CIRCUIT_MERKLE_DEPTH;
use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, Felt, HashFelt};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::{MerklePath, NoteData};
use transaction_circuit::p3_prover::TransactionProofParams;
use transaction_circuit::{
    InputNoteWitness, OutputNoteWitness, StablecoinPolicyBinding, TransactionProof,
    TransactionWitness,
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
        MerklePath {
            siblings: siblings0,
        },
        MerklePath {
            siblings: siblings1,
        },
        current,
    )
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

    let leaf0 = input_note_native.commitment();
    let leaf1 = input_note_asset.commitment();
    let (merkle_path0, merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);
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

fn statement_hash_from_proof(proof: &TransactionProof) -> [u8; 48] {
    let public = &proof.public_inputs;
    let mut statement_message = Vec::new();
    statement_message.extend_from_slice(b"tx-statement-v1");
    statement_message.extend_from_slice(&public.merkle_root);
    for nf in &public.nullifiers {
        statement_message.extend_from_slice(nf);
    }
    for cm in &public.commitments {
        statement_message.extend_from_slice(cm);
    }
    for ct in &public.ciphertext_hashes {
        statement_message.extend_from_slice(ct);
    }
    statement_message.extend_from_slice(&public.native_fee.to_le_bytes());
    statement_message.extend_from_slice(&public.value_balance.to_le_bytes());
    statement_message.extend_from_slice(&public.balance_tag);
    statement_message.extend_from_slice(&public.circuit_version.to_le_bytes());
    statement_message.extend_from_slice(&public.crypto_suite.to_le_bytes());
    statement_message.push(public.stablecoin.enabled as u8);
    statement_message.extend_from_slice(&public.stablecoin.asset_id.to_le_bytes());
    statement_message.extend_from_slice(&public.stablecoin.policy_hash);
    statement_message.extend_from_slice(&public.stablecoin.oracle_commitment);
    statement_message.extend_from_slice(&public.stablecoin.attestation_commitment);
    statement_message.extend_from_slice(&public.stablecoin.issuance_delta.to_le_bytes());
    statement_message.extend_from_slice(&public.stablecoin.policy_version.to_le_bytes());
    blake3_384(&statement_message)
}

fn tx_statements_commitment_from_proofs(proofs: &[TransactionProof]) -> [u8; 48] {
    let statement_hashes = proofs
        .iter()
        .map(statement_hash_from_proof)
        .collect::<Vec<_>>();
    CommitmentBlockProver::commitment_from_statement_hashes(&statement_hashes)
        .expect("statement commitment")
}

fn statement_hashes_from_proofs(proofs: &[TransactionProof]) -> Vec<[u8; 48]> {
    proofs.iter().map(statement_hash_from_proof).collect()
}

fn configured_leaf_fanin() -> usize {
    std::env::var("HEGEMON_AGG_LEAF_FANIN")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(8)
        .max(1)
}

fn configured_merge_fanin() -> usize {
    std::env::var("HEGEMON_AGG_MERGE_FANIN")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(8)
        .max(1)
}

#[test]
#[ignore = "expensive end-to-end aggregation proof generation; run manually"]
fn aggregation_v5_leaf_roundtrip() {
    let witness = sample_witness();
    let (proving_key, _verifying_key) = generate_keys();
    let proof = transaction_circuit::proof::prove_with_params(
        &witness,
        &proving_key,
        TransactionProofParams::recursion(),
    )
    .expect("generate transaction proof");

    let proofs = vec![proof];
    let tx_statements_commitment = tx_statements_commitment_from_proofs(&proofs);
    let aggregation_bytes =
        prove_aggregation(&proofs, tx_statements_commitment).expect("generate aggregation proof");

    verify_aggregation_proof(&aggregation_bytes, proofs.len(), &tx_statements_commitment)
        .expect("verify aggregation proof");

    let mut corrupted_payload: aggregation_circuit::AggregationProofV5Payload =
        postcard::from_bytes(&aggregation_bytes).expect("decode payload");
    corrupted_payload.outer_proof[0] ^= 0x01;
    let corrupted_bytes = postcard::to_allocvec(&corrupted_payload).expect("encode payload");

    let err = verify_aggregation_proof(&corrupted_bytes, proofs.len(), &tx_statements_commitment)
        .expect_err("corrupted proof should fail");
    assert!(matches!(
        err,
        consensus::ProofError::AggregationProofVerification(_)
    ));
}

#[test]
fn aggregation_v5_payload_validation_rejects_invalid_encodings() {
    let expected_commitment = [0u8; 48];
    let payload = AggregationProofV5Payload {
        version: AGGREGATION_PROOF_FORMAT_ID_V5,
        proof_format: AGGREGATION_PROOF_FORMAT_ID_V5,
        node_kind: AggregationNodeKind::Leaf,
        fan_in: 8,
        child_count: 1,
        subtree_tx_count: 1,
        tree_arity: 8,
        tree_levels: 1,
        root_level: 0,
        shape_id: [0u8; 32],
        tx_statements_commitment: expected_commitment.to_vec(),
        public_values_encoding: AGGREGATION_PUBLIC_VALUES_ENCODING_V2,
        inner_public_inputs_len: 1,
        representative_child_proof: vec![0xAA], // intentionally invalid postcard proof bytes
        packed_public_values: vec![0, 0],
        outer_proof: vec![0xBB], // intentionally invalid postcard proof bytes
    };
    let encoded = postcard::to_allocvec(&payload).expect("encode payload");
    let err = verify_aggregation_proof(&encoded, 1, &expected_commitment)
        .expect_err("invalid proof encoding must be rejected");
    assert!(matches!(
        err,
        consensus::ProofError::AggregationProofV5Decode(_)
            | consensus::ProofError::AggregationProofV5Binding(_)
    ));
}

#[test]
#[ignore = "expensive leaf-only profiling run; use HEGEMON_AGG_PROFILE=1 on target hardware"]
fn aggregation_v5_leaf_fanin8_profile_roundtrip() {
    let witness = sample_witness();
    let (proving_key, _verifying_key) = generate_keys();
    let proof = transaction_circuit::proof::prove_with_params(
        &witness,
        &proving_key,
        TransactionProofParams::recursion(),
    )
    .expect("generate transaction proof");
    let proofs = vec![proof; configured_leaf_fanin()];
    let statement_hashes = statement_hashes_from_proofs(&proofs);
    let commitment = tx_statements_commitment_from_proofs(&proofs);

    let leaf_bytes =
        prove_leaf_aggregation(&proofs, &statement_hashes, 1, 0).expect("generate leaf proof");
    verify_aggregation_proof(&leaf_bytes, proofs.len(), &commitment).expect("verify leaf proof");
}

#[test]
#[ignore = "expensive leaf cold/warm profiling run; use HEGEMON_AGG_PROFILE=1 on target hardware"]
fn aggregation_v5_leaf_fanin8_cold_warm_profile() {
    let witness = sample_witness();
    let (proving_key, _verifying_key) = generate_keys();
    let proof = transaction_circuit::proof::prove_with_params(
        &witness,
        &proving_key,
        TransactionProofParams::recursion(),
    )
    .expect("generate transaction proof");
    let fan_in = configured_leaf_fanin();
    let proofs = vec![proof; fan_in];
    let statement_hashes = statement_hashes_from_proofs(&proofs);
    let cold_started = Instant::now();
    let _cold_leaf =
        prove_leaf_aggregation(&proofs, &statement_hashes, 1, 0).expect("cold leaf proof");
    let cold_ms = cold_started.elapsed().as_millis();

    let warm_started = Instant::now();
    let _warm_leaf =
        prove_leaf_aggregation(&proofs, &statement_hashes, 1, 0).expect("warm leaf proof");
    let warm_ms = warm_started.elapsed().as_millis();

    eprintln!(
        "leaf_cold_warm_profile fan_in={} cold_ms={} warm_ms={}",
        fan_in, cold_ms, warm_ms
    );
}

#[test]
#[ignore = "expensive merge cold/warm profiling run; use HEGEMON_AGG_PROFILE=1 on target hardware"]
fn aggregation_v5_merge_cold_warm_profile() {
    let witness = sample_witness();
    let (proving_key, _verifying_key) = generate_keys();
    let proof = transaction_circuit::proof::prove_with_params(
        &witness,
        &proving_key,
        TransactionProofParams::recursion(),
    )
    .expect("generate transaction proof");
    let leaf_fanin = configured_leaf_fanin();
    let merge_fanin = configured_merge_fanin();
    let leaf_proofs = vec![proof; leaf_fanin];
    let leaf_statement_hashes = statement_hashes_from_proofs(&leaf_proofs);
    let leaf_payload =
        prove_leaf_aggregation(&leaf_proofs, &leaf_statement_hashes, 2, 0).expect("leaf proof");
    let child_payloads = vec![leaf_payload; merge_fanin];

    let all_proofs = std::iter::repeat_n(leaf_proofs.clone(), merge_fanin)
        .flatten()
        .collect::<Vec<_>>();
    let commitment = tx_statements_commitment_from_proofs(&all_proofs);
    let tx_count = all_proofs.len();
    let tree_levels: usize = if tx_count <= configured_leaf_fanin() {
        1
    } else {
        2
    };
    let root_level: usize = tree_levels.saturating_sub(1);

    let cold_started = Instant::now();
    let cold_merge = prove_merge_aggregation(
        &child_payloads,
        commitment,
        tree_levels as u16,
        root_level as u16,
    )
    .expect("cold merge proof");
    let cold_ms = cold_started.elapsed().as_millis();
    verify_aggregation_proof(&cold_merge, tx_count, &commitment).expect("verify cold merge proof");

    let warm_started = Instant::now();
    let warm_merge = prove_merge_aggregation(
        &child_payloads,
        commitment,
        tree_levels as u16,
        root_level as u16,
    )
    .expect("warm merge proof");
    let warm_ms = warm_started.elapsed().as_millis();
    verify_aggregation_proof(&warm_merge, tx_count, &commitment).expect("verify warm merge proof");

    eprintln!(
        "merge_cold_warm_profile leaf_fan_in={} merge_fan_in={} tx_count={} cold_ms={} warm_ms={}",
        leaf_fanin, merge_fanin, tx_count, cold_ms, warm_ms
    );
}
