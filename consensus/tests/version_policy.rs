mod common;

use common::{
    BftBlockParams, assemble_bft_block, dummy_transaction_with_version, make_validators,
    validator_set,
};
use consensus::nullifier::NullifierSet;
use consensus::{
    BftConsensus, ConsensusError, DEFAULT_VERSION_BINDING, HashVerifier, VersionProposal,
    VersionSchedule,
};
use protocol_versioning::VersionBinding;

#[test]
fn version_schedule_controls_activation() {
    let validators = make_validators(4, 10);
    let validator_set = validator_set(&validators);
    let mut consensus = BftConsensus::new(validator_set.clone(), [0u8; 32], HashVerifier);
    let tx =
        dummy_transaction_with_version(7, VersionBinding::new(2, DEFAULT_VERSION_BINDING.crypto));
    let params = BftBlockParams {
        height: 1,
        view: 1,
        parent_hash: [0u8; 32],
        timestamp_ms: 1000,
        transactions: vec![tx],
        validators: &validators,
        signer_indices: &[0, 1, 2],
        base_nullifiers: &NullifierSet::new(),
        base_state_root: [0u8; 32],
    };
    let (block, _, _) = assemble_bft_block(params).expect("block");
    let err = consensus
        .apply_block(block)
        .expect_err("unsupported version");
    assert!(matches!(err, ConsensusError::UnsupportedVersion { .. }));

    let upgraded = VersionBinding::new(2, DEFAULT_VERSION_BINDING.crypto);
    let mut schedule = VersionSchedule::default();
    schedule.register(VersionProposal {
        binding: upgraded,
        activates_at: 1,
        retires_at: None,
        upgrade: None,
    });
    let mut consensus =
        BftConsensus::with_schedule(validator_set, [0u8; 32], HashVerifier, schedule);
    let params = BftBlockParams {
        height: 1,
        view: 1,
        parent_hash: [0u8; 32],
        timestamp_ms: 1000,
        transactions: vec![dummy_transaction_with_version(9, upgraded)],
        validators: &validators,
        signer_indices: &[0, 1, 2],
        base_nullifiers: &NullifierSet::new(),
        base_state_root: [0u8; 32],
    };
    let (block, _, _) = assemble_bft_block(params).expect("block");
    consensus.apply_block(block).expect("version allowed");
}
