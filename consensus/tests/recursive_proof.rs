use std::collections::HashMap;

use block_circuit::prove_block_recursive;
use consensus::header::BlockHeader;
use consensus::proof::{verify_commitments, RecursiveProofVerifier};
use consensus::ProofVerifier;
use consensus::types::{
    ConsensusBlock, DaParams, compute_fee_commitment, compute_proof_commitment,
    compute_version_commitment,
};
use protocol_versioning::DEFAULT_VERSION_BINDING;
use state_merkle::CommitmentTree;
use transaction_circuit::{
    StablecoinPolicyBinding, TransactionWitness,
    constants::{CIRCUIT_MERKLE_DEPTH, NATIVE_ASSET_ID},
    hashing::{bytes32_to_felts, felt_to_bytes32, felts_to_bytes32},
    keys::generate_keys,
    note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness},
    proof::prove,
};

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

#[test]
#[ignore = "heavy: recursive proof generation"]
fn recursive_proof_verifier_accepts_valid_block() {
    let (proving_key, verifying_key) = generate_keys();
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
    let proof = prove(&witness, &proving_key).expect("transaction proof");

    let recursive_proof =
        prove_block_recursive(&mut tree, &[proof.clone()], &verifying_keys).expect("recursive");

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
        da_root: [0u8; 32],
        da_params: DaParams {
            chunk_size: 1024,
            sample_count: 4,
        },
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
