mod common;

use common::{
    PowBlockParams, assemble_pow_block, dummy_coinbase, dummy_transaction, empty_nullifier_root,
    make_validators,
};
use consensus::nullifier::NullifierSet;
use consensus::pow::{DEFAULT_GENESIS_POW_BITS, PowConsensus};
use consensus::proof::HashVerifier;
use crypto::ml_dsa::ML_DSA_SIGNATURE_LEN;
use runtime::{PqPublic, PqSignature};
use sp_runtime::traits::Verify;

#[test]
fn runtime_signatures_verify_pow_blocks() {
    let mut validators = make_validators(1, 1);
    let miner = validators.pop().expect("validator exists");
    let base_nullifiers = NullifierSet::new();
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
        miner: &miner,
        base_nullifiers: &base_nullifiers,
        base_state_root: empty_nullifier_root(),
        pow_bits: DEFAULT_GENESIS_POW_BITS,
        nonce,
        parent_supply,
        coinbase: dummy_coinbase(height),
    })
    .expect("block assembly");

    let signing_hash = block.header.signing_hash().expect("signing hash");
    let runtime_public: PqPublic = miner.secret.verify_key().into();
    let runtime_signature = PqSignature::MlDsa(
        block
            .header
            .signature_aggregate
            .as_slice()
            .try_into()
            .expect("ml-dsa signature length"),
    );

    assert!(runtime_signature.verify(signing_hash, &runtime_public));
    assert_eq!(block.header.signature_aggregate.len(), ML_DSA_SIGNATURE_LEN);

    let mut pow = PowConsensus::new(
        vec![miner.secret.verify_key()],
        empty_nullifier_root(),
        HashVerifier,
    );
    assert!(pow.apply_block(block).is_ok());
}
