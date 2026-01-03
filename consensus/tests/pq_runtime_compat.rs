mod common;

use common::{
    PowBlockParams, assemble_pow_block, dummy_coinbase, dummy_transaction, make_validators,
};
use consensus::nullifier::NullifierSet;
use consensus::pow::PowConsensus;
use consensus::proof::HashVerifier;
use consensus::CommitmentTreeState;
use crypto::ml_dsa::{ML_DSA_SIGNATURE_LEN, MlDsaPublicKey, MlDsaSignature};
use crypto::traits::{SigningKey, VerifyKey};

const EASY_POW_BITS: u32 = 0x3f00ffff;

#[test]
fn runtime_signatures_verify_pow_blocks() {
    let mut validators = make_validators(1, 1);
    let miner = validators.pop().expect("validator exists");
    let base_nullifiers = NullifierSet::new();
    let genesis_tree = CommitmentTreeState::default();
    let height = 1;
    let parent_hash = [0u8; 32];
    let parent_supply = 0;
    let timestamp_ms = 1;
    let nonce = [0u8; 32];
    let (block, _, _) = assemble_pow_block(PowBlockParams {
        height,
        parent_hash,
        timestamp_ms,
        transactions: vec![dummy_transaction(7)],
        recursive_proof: None,
        miner: &miner,
        base_nullifiers: &base_nullifiers,
        base_commitment_tree: &genesis_tree,
        pow_bits: EASY_POW_BITS,
        nonce,
        parent_supply,
        coinbase: dummy_coinbase(height),
    })
    .expect("block assembly");

    let signing_hash = block.header.signing_hash().expect("signing hash");
    let runtime_public: MlDsaPublicKey = miner.secret.verify_key();
    let runtime_signature = MlDsaSignature::from_bytes(&block.header.signature_aggregate)
        .expect("valid ml-dsa signature bytes");

    runtime_public
        .verify(&signing_hash, &runtime_signature)
        .expect("runtime-compatible signature");
    assert_eq!(block.header.signature_aggregate.len(), ML_DSA_SIGNATURE_LEN);

    let mut pow = PowConsensus::with_genesis_pow_bits(
        vec![miner.secret.verify_key()],
        genesis_tree.clone(),
        HashVerifier,
        EASY_POW_BITS,
    );
    assert!(pow.apply_block(block).is_ok());
}
