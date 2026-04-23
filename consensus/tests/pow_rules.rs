mod common;

use common::{
    PowBlockParams, TestValidator, assemble_pow_block, dummy_coinbase, dummy_transaction,
    make_validators,
};
use consensus::pow::DEFAULT_GENESIS_POW_BITS;
use consensus::proof::HashVerifier;
use consensus::{CommitmentTreeState, ConsensusError, NullifierSet, PowConsensus, Transaction};

const ALWAYS_VALID_TEST_POW_BITS: u32 = 0x3f00_ffff;

fn base_pow_params<'a>(
    miner: &'a TestValidator,
    base_nullifiers: &'a NullifierSet,
    base_commitment_tree: &'a CommitmentTreeState,
    transactions: Vec<Transaction>,
) -> PowBlockParams<'a> {
    PowBlockParams {
        height: 1,
        parent_hash: [0u8; 32],
        timestamp_ms: 1_000,
        transactions,
        miner,
        base_nullifiers,
        base_commitment_tree,
        pow_bits: DEFAULT_GENESIS_POW_BITS,
        nonce: [0u8; 32],
        parent_supply: 0,
        coinbase: dummy_coinbase(1),
    }
}

fn easy_pow_params<'a>(
    miner: &'a TestValidator,
    base_nullifiers: &'a NullifierSet,
    base_commitment_tree: &'a CommitmentTreeState,
    transactions: Vec<Transaction>,
) -> PowBlockParams<'a> {
    PowBlockParams {
        pow_bits: ALWAYS_VALID_TEST_POW_BITS,
        ..base_pow_params(miner, base_nullifiers, base_commitment_tree, transactions)
    }
}

#[test]
fn pow_bits_must_match_expected_target() {
    let mut miners = make_validators(1, 0);
    let miner = miners.remove(0);
    let nullifiers = NullifierSet::new();
    let base_tree = CommitmentTreeState::default();
    let mut consensus = PowConsensus::new(
        vec![miner.validator.public_key().clone()],
        base_tree.clone(),
        HashVerifier,
    );
    let mut params = base_pow_params(&miner, &nullifiers, &base_tree, vec![dummy_transaction(5)]);
    params.pow_bits ^= 0x0100_0000;
    let (block, _, _) = assemble_pow_block(params).expect("assemble block");
    let err = consensus.apply_block(block).expect_err("invalid pow bits");
    assert!(matches!(err, ConsensusError::Pow(_)));
}

#[test]
fn median_time_past_violation_rejected() {
    let mut miners = make_validators(1, 0);
    let miner = miners.remove(0);
    let nullifiers = NullifierSet::new();
    let base_tree = CommitmentTreeState::default();
    let mut consensus = PowConsensus::new(
        vec![miner.validator.public_key().clone()],
        base_tree.clone(),
        HashVerifier,
    );
    let mut params = base_pow_params(&miner, &nullifiers, &base_tree, vec![dummy_transaction(6)]);
    params.timestamp_ms = 0; // equal to median, should fail
    let (block, _, _) = assemble_pow_block(params).expect("assemble block");
    let err = consensus.apply_block(block).expect_err("timestamp error");
    assert!(matches!(err, ConsensusError::Timestamp));
}

#[test]
fn subsidy_overshoot_is_enforced() {
    let mut miners = make_validators(1, 0);
    let miner = miners.remove(0);
    let nullifiers = NullifierSet::new();
    let base_tree = CommitmentTreeState::default();
    let mut consensus = PowConsensus::new(
        vec![miner.validator.public_key().clone()],
        base_tree.clone(),
        HashVerifier,
    );
    let mut params = base_pow_params(&miner, &nullifiers, &base_tree, vec![dummy_transaction(7)]);
    params.coinbase.minted += 1;
    let (block, _, _) = assemble_pow_block(params).expect("assemble block");
    let err = consensus.apply_block(block).expect_err("subsidy violation");
    assert!(matches!(err, ConsensusError::Subsidy { .. }));
}

#[test]
fn pow_block_requires_registered_miner_identity() {
    let mut miners = make_validators(2, 0);
    let known_miner = miners.remove(0);
    let attacker_miner = miners.remove(0);
    let nullifiers = NullifierSet::new();
    let base_tree = CommitmentTreeState::default();
    let mut consensus = PowConsensus::with_genesis_pow_bits(
        vec![known_miner.validator.public_key().clone()],
        base_tree.clone(),
        HashVerifier,
        ALWAYS_VALID_TEST_POW_BITS,
    );

    let params = easy_pow_params(
        &attacker_miner,
        &nullifiers,
        &base_tree,
        vec![dummy_transaction(8)],
    );
    let (block, _, _) = assemble_pow_block(params).expect("assemble block");

    let err = consensus
        .apply_block(block)
        .expect_err("unregistered miner must be rejected");
    assert!(matches!(err, ConsensusError::ValidatorSetMismatch));
}

#[test]
fn pow_block_requires_valid_miner_signature() {
    let mut miners = make_validators(1, 0);
    let miner = miners.remove(0);
    let nullifiers = NullifierSet::new();
    let base_tree = CommitmentTreeState::default();
    let mut consensus = PowConsensus::with_genesis_pow_bits(
        vec![miner.validator.public_key().clone()],
        base_tree.clone(),
        HashVerifier,
        ALWAYS_VALID_TEST_POW_BITS,
    );

    let params = easy_pow_params(&miner, &nullifiers, &base_tree, vec![dummy_transaction(9)]);
    let (mut block, _, _) = assemble_pow_block(params).expect("assemble block");
    block.header.signature_aggregate[0] ^= 0x80;

    let err = consensus
        .apply_block(block)
        .expect_err("tampered miner signature must be rejected");
    assert!(matches!(
        err,
        ConsensusError::SignatureVerificationFailed { .. }
    ));
}

#[test]
fn pow_block_requires_exactly_one_miner_signature() {
    let mut miners = make_validators(1, 0);
    let miner = miners.remove(0);
    let nullifiers = NullifierSet::new();
    let base_tree = CommitmentTreeState::default();
    let mut consensus = PowConsensus::with_genesis_pow_bits(
        vec![miner.validator.public_key().clone()],
        base_tree.clone(),
        HashVerifier,
        ALWAYS_VALID_TEST_POW_BITS,
    );

    let params = easy_pow_params(&miner, &nullifiers, &base_tree, vec![dummy_transaction(10)]);
    let (mut block, _, _) = assemble_pow_block(params).expect("assemble block");
    block.header.signature_aggregate.clear();

    let err = consensus
        .apply_block(block)
        .expect_err("missing miner signature must be rejected");
    assert!(matches!(
        err,
        ConsensusError::InvalidHeader("invalid pow miner signature length")
    ));
}

#[test]
fn pow_block_rejects_bft_signature_bitmap() {
    let mut miners = make_validators(1, 0);
    let miner = miners.remove(0);
    let nullifiers = NullifierSet::new();
    let base_tree = CommitmentTreeState::default();
    let mut consensus = PowConsensus::with_genesis_pow_bits(
        vec![miner.validator.public_key().clone()],
        base_tree.clone(),
        HashVerifier,
        ALWAYS_VALID_TEST_POW_BITS,
    );

    let params = easy_pow_params(&miner, &nullifiers, &base_tree, vec![dummy_transaction(11)]);
    let (mut block, _, _) = assemble_pow_block(params).expect("assemble block");
    block.header.signature_bitmap = Some(vec![1]);

    let err = consensus
        .apply_block(block)
        .expect_err("pow header signature bitmap must be rejected");
    assert!(matches!(
        err,
        ConsensusError::InvalidHeader("pow header must not carry a signature bitmap")
    ));
}
