use p3_goldilocks::Goldilocks;
use superneo_hegemon::{
    build_native_tx_leaf_artifact_bytes_with_params_and_seed,
    build_native_tx_leaf_receipt_root_artifact_bytes_with_params,
    decode_native_tx_leaf_artifact_bytes, native_backend_params, tx_leaf_public_tx_from_witness,
    CanonicalTxValidityReceipt, NativeTxLeafRecord,
};
use transaction_circuit::constants::NATIVE_ASSET_ID;
use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, HashFelt};
use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
use transaction_circuit::{StablecoinPolicyBinding, TransactionWitness};

pub fn sample_witness(seed: u64) -> TransactionWitness {
    let sk_spend = [seed as u8 + 42; 32];
    let pk_auth = transaction_circuit::hashing_pq::spend_auth_key_bytes(&sk_spend);
    let input_note_native = NoteData {
        value: 8,
        asset_id: NATIVE_ASSET_ID,
        pk_recipient: [seed as u8 + 2; 32],
        pk_auth,
        rho: [seed as u8 + 3; 32],
        r: [seed as u8 + 4; 32],
    };
    let input_note_asset = NoteData {
        value: 5,
        asset_id: seed + 100,
        pk_recipient: [seed as u8 + 5; 32],
        pk_auth,
        rho: [seed as u8 + 6; 32],
        r: [seed as u8 + 7; 32],
    };
    let leaf0 = input_note_native.commitment();
    let leaf1 = input_note_asset.commitment();
    let (merkle_path0, merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

    let output_native = OutputNoteWitness {
        note: NoteData {
            value: 3,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [seed as u8 + 11; 32],
            pk_auth: [seed as u8 + 12; 32],
            rho: [seed as u8 + 13; 32],
            r: [seed as u8 + 14; 32],
        },
    };
    let output_asset = OutputNoteWitness {
        note: NoteData {
            value: 5,
            asset_id: seed + 100,
            pk_recipient: [seed as u8 + 21; 32],
            pk_auth: [seed as u8 + 22; 32],
            rho: [seed as u8 + 23; 32],
            r: [seed as u8 + 24; 32],
        },
    };

    TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_note_native,
                position: 0,
                rho_seed: [seed as u8 + 9; 32],
                merkle_path: merkle_path0,
            },
            InputNoteWitness {
                note: input_note_asset,
                position: 1,
                rho_seed: [seed as u8 + 10; 32],
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

pub fn review_vector_seed(tag: u8) -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (idx, byte) in seed.iter_mut().enumerate() {
        *byte = tag.wrapping_add(idx as u8);
    }
    seed
}

pub fn valid_native_tx_leaf_case() -> (
    superneo_hegemon::TxLeafPublicTx,
    CanonicalTxValidityReceipt,
    Vec<u8>,
) {
    let params = native_backend_params();
    let witness = sample_witness(1);
    let tx = tx_leaf_public_tx_from_witness(&witness).expect("tx view");
    let built = build_native_tx_leaf_artifact_bytes_with_params_and_seed(
        &params,
        &witness,
        review_vector_seed(1),
    )
    .expect("build deterministic native leaf");
    (tx, built.receipt, built.artifact_bytes)
}

pub fn valid_receipt_root_case() -> (Vec<NativeTxLeafRecord>, Vec<u8>) {
    let params = native_backend_params();
    let built_leaf_a = build_native_tx_leaf_artifact_bytes_with_params_and_seed(
        &params,
        &sample_witness(1),
        review_vector_seed(1),
    )
    .expect("leaf a");
    let built_leaf_b = build_native_tx_leaf_artifact_bytes_with_params_and_seed(
        &params,
        &sample_witness(2),
        review_vector_seed(2),
    )
    .expect("leaf b");
    let leaf_a =
        decode_native_tx_leaf_artifact_bytes(&built_leaf_a.artifact_bytes).expect("decode leaf a");
    let leaf_b =
        decode_native_tx_leaf_artifact_bytes(&built_leaf_b.artifact_bytes).expect("decode leaf b");
    let built_root = build_native_tx_leaf_receipt_root_artifact_bytes_with_params(
        &params,
        &[leaf_a.clone(), leaf_b.clone()],
    )
    .expect("build root");
    let records = vec![
        superneo_hegemon::native_tx_leaf_record_from_artifact(&leaf_a),
        superneo_hegemon::native_tx_leaf_record_from_artifact(&leaf_b),
    ];
    (records, built_root.artifact_bytes)
}

pub fn mutate_bytes(valid: &[u8], data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return valid.to_vec();
    }
    let mut out = valid.to_vec();
    for (idx, byte) in data.iter().enumerate() {
        let offset = idx % out.len();
        out[offset] ^= *byte;
    }
    if data.len() % 7 == 0 {
        out.push(data[0]);
    }
    out
}

fn build_two_leaf_merkle_tree(
    leaf0: HashFelt,
    leaf1: HashFelt,
) -> (MerklePath, MerklePath, HashFelt) {
    let mut siblings0 = vec![leaf1];
    let mut siblings1 = vec![leaf0];
    let mut current = merkle_node(leaf0, leaf1);
    for _ in 1..transaction_circuit::constants::CIRCUIT_MERKLE_DEPTH {
        let zero = [Goldilocks::new(0); 6];
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
