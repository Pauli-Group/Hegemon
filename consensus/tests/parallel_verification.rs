mod common;

use block_circuit::CommitmentBlockProver;
use common::{PowBlockParams, assemble_pow_block, dummy_coinbase, make_validators};
use consensus::pow::DEFAULT_GENESIS_POW_BITS;
use consensus::{
    CommitmentTreeState, NullifierSet, ParallelProofVerifier, ProofError, ProofVerifier,
    commitment_nullifier_lists,
};
use crypto::hashes::blake3_256;
use transaction_circuit::constants::CIRCUIT_MERKLE_DEPTH;
use transaction_circuit::hashing::{felt_to_bytes32, felts_to_bytes32, merkle_node, Felt, HashFelt};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::{MerklePath, NoteData};
use transaction_circuit::proof::prove;
use transaction_circuit::{InputNoteWitness, OutputNoteWitness, StablecoinPolicyBinding, TransactionWitness};
use winterfell::math::FieldElement;

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
    let mut defaults = Vec::with_capacity(CIRCUIT_MERKLE_DEPTH + 1);
    defaults.push([Felt::ZERO; 4]);
    for level in 0..CIRCUIT_MERKLE_DEPTH {
        let prev = defaults[level];
        defaults.push(merkle_node(prev, prev));
    }

    let mut siblings0 = vec![leaf1];
    let mut siblings1 = vec![leaf0];

    let mut current = merkle_node(leaf0, leaf1);
    for level in 1..CIRCUIT_MERKLE_DEPTH {
        let default_sibling = defaults[level];
        siblings0.push(default_sibling);
        siblings1.push(default_sibling);
        current = merkle_node(current, default_sibling);
    }

    let path0 = MerklePath { siblings: siblings0 };
    let path1 = MerklePath { siblings: siblings1 };

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

#[test]
#[ignore = "heavy: transaction + commitment proof generation"]
fn parallel_verifier_accepts_valid_commitment_proof() {
    let witness = sample_witness();
    let (proving_key, _verifying_key) = generate_keys();
    let tx_proof = prove(&witness, &proving_key).expect("transaction proof");

    let nullifiers: Vec<[u8; 32]> = tx_proof
        .nullifiers
        .iter()
        .copied()
        .filter(|value| *value != [0u8; 32])
        .collect();
    let commitments: Vec<[u8; 32]> = tx_proof
        .commitments
        .iter()
        .copied()
        .filter(|value| *value != [0u8; 32])
        .collect();
    let balance_tag = felt_to_bytes32(tx_proof.public_inputs.balance_tag);
    let transaction = consensus::Transaction::new(
        nullifiers,
        commitments,
        balance_tag,
        tx_proof.version_binding(),
        Vec::new(),
    );

    let base_nullifiers = NullifierSet::new();
    let mut base_tree = CommitmentTreeState::default();
    for input in &witness.inputs {
        base_tree
            .append(felts_to_bytes32(&input.note.commitment()))
            .expect("append input commitment");
    }
    assert_eq!(base_tree.root(), tx_proof.public_inputs.merkle_root);

    let mut miners = make_validators(1, 0);
    let miner = miners.remove(0);

    let params = PowBlockParams {
        height: 1,
        parent_hash: [0u8; 32],
        timestamp_ms: 1_000,
        transactions: vec![transaction],
        miner: &miner,
        base_nullifiers: &base_nullifiers,
        base_commitment_tree: &base_tree,
        pow_bits: DEFAULT_GENESIS_POW_BITS,
        nonce: [0u8; 32],
        parent_supply: 0,
        coinbase: dummy_coinbase(1),
    };

    let (mut block, updated_nullifiers, updated_tree) =
        assemble_pow_block(params).expect("assemble block");

    let lists = commitment_nullifier_lists(&block.transactions).expect("nullifier lists");
    let proof_hashes = vec![blake3_256(&tx_proof.stark_proof)];
    let prover = CommitmentBlockProver::new();
    let commitment_proof = prover
        .prove_from_hashes_with_inputs(
            &proof_hashes,
            base_tree.root(),
            updated_tree.root(),
            updated_nullifiers.commitment(),
            block.header.da_root,
            lists.nullifiers,
            lists.sorted_nullifiers,
        )
        .expect("commitment proof");

    block.commitment_proof = Some(commitment_proof);
    block.transaction_proofs = Some(vec![tx_proof.clone()]);

    let verifier = ParallelProofVerifier::new();
    let updated = verifier
        .verify_block(&block, &base_tree)
        .expect("parallel verification");
    assert_eq!(updated.root(), updated_tree.root());

    let mut tampered = block.clone();
    if let Some(proofs) = tampered.transaction_proofs.as_mut() {
        let mut inputs = proofs[0]
            .stark_public_inputs
            .clone()
            .expect("stark public inputs");
        inputs.fee = inputs.fee.saturating_add(1);
        proofs[0].stark_public_inputs = Some(inputs);
    }

    let err = verifier
        .verify_block(&tampered, &base_tree)
        .expect_err("tampered proof should fail");
    assert!(matches!(
        err,
        ProofError::TransactionProofVerification { .. }
    ));
}
