mod common;

use block_circuit::CommitmentBlockProver;
use common::{PowBlockParams, assemble_pow_block, dummy_coinbase, dummy_transaction, make_validators};
use consensus::pow::DEFAULT_GENESIS_POW_BITS;
use consensus::{
    CommitmentTreeState, NullifierSet, ProofError, commitment_nullifier_lists,
    verify_commitment_proof_payload,
};

#[test]
fn commitment_proof_handoff_accepts_matching_nullifiers() {
    let mut miners = make_validators(1, 0);
    let miner = miners.remove(0);
    let base_nullifiers = NullifierSet::new();
    let base_tree = CommitmentTreeState::default();
    let transactions = vec![dummy_transaction(1), dummy_transaction(2)];

    let params = PowBlockParams {
        height: 1,
        parent_hash: [0u8; 32],
        timestamp_ms: 1_000,
        transactions,
        miner: &miner,
        base_nullifiers: &base_nullifiers,
        base_commitment_tree: &base_tree,
        pow_bits: DEFAULT_GENESIS_POW_BITS,
        nonce: [0u8; 32],
        parent_supply: 0,
        coinbase: dummy_coinbase(1),
    };

    let (block, updated_nullifiers, updated_tree) =
        assemble_pow_block(params).expect("assemble block");

    let lists = commitment_nullifier_lists(&block.transactions).expect("nullifier lists");
    let proof_hashes = vec![[9u8; 32]; block.transactions.len()];
    let prover = CommitmentBlockProver::new();
    let proof = prover
        .prove_from_hashes_with_inputs(
            &proof_hashes,
            base_tree.root(),
            updated_tree.root(),
            updated_nullifiers.commitment(),
            block.header.da_root,
            lists.nullifiers.clone(),
            lists.sorted_nullifiers.clone(),
        )
        .expect("commitment proof");

    verify_commitment_proof_payload(&block, &base_tree, &proof).expect("commitment proof valid");
}

#[test]
fn commitment_proof_handoff_rejects_nullifier_mismatch() {
    let mut miners = make_validators(1, 0);
    let miner = miners.remove(0);
    let base_nullifiers = NullifierSet::new();
    let base_tree = CommitmentTreeState::default();
    let transactions = vec![dummy_transaction(3), dummy_transaction(4)];

    let params = PowBlockParams {
        height: 1,
        parent_hash: [0u8; 32],
        timestamp_ms: 1_000,
        transactions,
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
    let proof_hashes = vec![[7u8; 32]; block.transactions.len()];
    let prover = CommitmentBlockProver::new();
    let proof = prover
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

    block.transactions[0].nullifiers[0] = [99u8; 32];
    let err = verify_commitment_proof_payload(&block, &base_tree, &proof)
        .expect_err("nullifier mismatch should fail");
    assert!(matches!(
        err,
        ProofError::CommitmentProofInputsMismatch(_)
    ));
}

#[test]
fn commitment_nullifier_lists_rejects_empty_block() {
    let err = commitment_nullifier_lists(&[]).expect_err("empty block should fail");
    assert!(matches!(err, ProofError::CommitmentProofEmptyBlock));
}
