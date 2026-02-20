mod common;

use block_circuit::CommitmentBlockProver;
use common::{
    PowBlockParams, assemble_pow_block, dummy_coinbase, dummy_transaction, make_validators,
};
use consensus::pow::DEFAULT_GENESIS_POW_BITS;
use consensus::types::{ConsensusBlock, ProofVerificationMode, Transaction};
use consensus::{
    CommitmentTreeState, NullifierSet, ParallelProofVerifier, ProofError, ProofVerifier,
    commitment_nullifier_lists,
};
use crypto::hashes::blake3_384;

fn fallback_statement_hash(tx: &Transaction) -> [u8; 48] {
    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(b"tx-statement-fallback-v1");
    data.extend_from_slice(&tx.hash());
    blake3_384(&data)
}

fn build_block_with_commitment_proof(
    mode: ProofVerificationMode,
) -> (ConsensusBlock, CommitmentTreeState) {
    let mut miners = make_validators(1, 0);
    let miner = miners.remove(0);
    let base_nullifiers = NullifierSet::new();
    let base_tree = CommitmentTreeState::default();
    let transactions = vec![dummy_transaction(9)];

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
    let statement_hashes = block
        .transactions
        .iter()
        .map(fallback_statement_hash)
        .collect::<Vec<_>>();

    let commitment_proof = CommitmentBlockProver::new()
        .prove_from_statement_hashes_with_inputs(
            &statement_hashes,
            base_tree.root(),
            updated_tree.root(),
            updated_nullifiers.commitment(),
            block.header.da_root,
            lists.nullifiers,
            lists.sorted_nullifiers,
        )
        .expect("commitment proof");

    block.commitment_proof = Some(commitment_proof);
    block.proof_verification_mode = mode;

    (block, base_tree)
}

#[test]
fn self_contained_mode_rejects_missing_aggregation_proof() {
    let (block, base_tree) =
        build_block_with_commitment_proof(ProofVerificationMode::SelfContainedAggregation);

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block(&block, &base_tree)
        .expect_err("missing aggregation proof must be rejected");

    assert!(matches!(
        err,
        ProofError::MissingAggregationProofForSelfContainedMode
    ));
}

#[test]
fn inline_required_mode_rejects_missing_transaction_proofs() {
    let (block, base_tree) =
        build_block_with_commitment_proof(ProofVerificationMode::InlineRequired);

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block(&block, &base_tree)
        .expect_err("missing tx proofs must be rejected in inline mode");

    assert!(matches!(err, ProofError::MissingTransactionProofs));
}
