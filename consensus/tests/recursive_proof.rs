use std::collections::HashMap;

use block_circuit::recursive::prove_block_recursive_fast;
use consensus::header::BlockHeader;
use consensus::proof::{verify_commitments, RecursiveProofVerifier};
use consensus::ProofVerifier;
use consensus::types::{
    ConsensusBlock, DaParams, compute_fee_commitment, compute_proof_commitment,
    compute_version_commitment, da_root,
};
use protocol_versioning::DEFAULT_VERSION_BINDING;
use state_merkle::CommitmentTree;
use transaction_circuit::{
    StablecoinPolicyBinding, TransactionWitness,
    constants::{CIRCUIT_MERKLE_DEPTH, NATIVE_ASSET_ID},
    hashing::{bytes32_to_felts, felt_to_bytes32, felts_to_bytes32},
    keys::generate_keys,
    note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness},
    proof::{SerializedStarkInputs, TransactionProof},
    rpo_prover::TransactionProverStarkRpo,
    trace::TransactionTrace,
};
use winterfell::{BatchingMethod, FieldExtension, ProofOptions, Prover};

fn make_valid_witness(seed: u64, tree: &CommitmentTree) -> TransactionWitness {
    let input_note = NoteData {
        value: 5,
        asset_id: NATIVE_ASSET_ID,
        pk_recipient: [seed as u8 + 1; 32],
        rho: [seed as u8 + 2; 32],
        r: [seed as u8 + 3; 32],
    };
    let merkle_root = tree.root();
    let merkle_path = tree
        .authentication_path(0)
        .expect("path")
        .into_iter()
        .map(|sibling| bytes32_to_felts(&sibling).expect("path felts"))
        .collect();

    let output_note = OutputNoteWitness {
        note: NoteData {
            value: 4,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [seed as u8 + 9; 32],
            rho: [seed as u8 + 10; 32],
            r: [seed as u8 + 11; 32],
        },
    };

    TransactionWitness {
        inputs: vec![InputNoteWitness {
            note: input_note,
            position: 0,
            rho_seed: [seed as u8 + 4; 32],
            merkle_path: MerklePath { siblings: merkle_path },
        }],
        outputs: vec![output_note],
        sk_spend: [seed as u8 + 12; 32],
        merkle_root,
        fee: 1,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: DEFAULT_VERSION_BINDING,
    }
}

fn rpo_prover() -> TransactionProverStarkRpo {
    // Match the recursion verifier's remainder size (8 coeffs) and keep queries minimal.
    let options = ProofOptions::new(
        2,
        8,
        0,
        FieldExtension::None,
        2,
        7,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    TransactionProverStarkRpo::new(options)
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
#[ignore = "heavy: recursive proof generation"]
fn recursive_proof_verifier_accepts_valid_block() {
    let (_proving_key, verifying_key) = generate_keys();
    let mut verifying_keys = HashMap::new();
    verifying_keys.insert(DEFAULT_VERSION_BINDING, verifying_key);

    let input_note = NoteData {
        value: 5,
        asset_id: NATIVE_ASSET_ID,
        pk_recipient: [1u8; 32],
        rho: [2u8; 32],
        r: [3u8; 32],
    };
    let mut tree = CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).expect("tree");
    tree.append(felts_to_bytes32(&input_note.commitment()))
        .expect("append");

    let witness = make_valid_witness(0, &tree);
    let root_felts = bytes32_to_felts(&witness.merkle_root).expect("root felts");
    let input = &witness.inputs[0];
    assert!(
        input
            .merkle_path
            .verify(input.note.commitment(), input.position, root_felts),
        "merkle path must match tree root"
    );
    let proof = build_rpo_proof(&witness);

    let recursive_proof =
        prove_block_recursive_fast(&mut tree, &[proof.clone()], &verifying_keys)
            .expect("recursive");

    let nullifiers: Vec<[u8; 32]> = proof
        .nullifiers
        .iter()
        .copied()
        .filter(|value| *value != [0u8; 32])
        .collect();
    let commitments: Vec<[u8; 32]> = proof
        .commitments
        .iter()
        .copied()
        .filter(|value| *value != [0u8; 32])
        .collect();
    let balance_tag = felt_to_bytes32(proof.public_inputs.balance_tag);
    let transaction = consensus::Transaction::new(
        nullifiers,
        commitments,
        balance_tag,
        proof.version_binding(),
        Vec::new(),
    );

    let transactions = vec![transaction];
    let da_params = DaParams {
        chunk_size: 1024,
        sample_count: 4,
    };
    let header = BlockHeader {
        version: 1,
        height: 1,
        view: 0,
        timestamp_ms: 0,
        parent_hash: [0u8; 32],
        state_root: [0u8; 32],
        nullifier_root: [0u8; 32],
        proof_commitment: compute_proof_commitment(&transactions),
        recursive_proof_hash: recursive_proof.recursive_proof_hash,
        da_root: da_root(&transactions, da_params).expect("da root"),
        da_params,
        version_commitment: compute_version_commitment(&transactions),
        tx_count: transactions.len() as u32,
        fee_commitment: compute_fee_commitment(&transactions),
        supply_digest: 0,
        validator_set_commitment: [0u8; 32],
        signature_aggregate: Vec::new(),
        signature_bitmap: None,
        pow: None,
    };

    let block = ConsensusBlock {
        header,
        transactions,
        coinbase: None,
        recursive_proof: Some(recursive_proof),
    };

    verify_commitments(&block).expect("commitments");
    RecursiveProofVerifier
        .verify_block(&block)
        .expect("recursive proof");
}
