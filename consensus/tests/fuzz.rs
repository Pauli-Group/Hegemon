mod common;

use common::{BftBlockParams, assemble_bft_block, make_validators, validator_set};
use consensus::{
    BftConsensus, CommitmentTreeState, DEFAULT_VERSION_BINDING, HashVerifier, NullifierSet,
    Transaction,
};
use proptest::prelude::*;

fn has_duplicates(values: &[[u8; 32]]) -> bool {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    for value in values {
        if !set.insert(*value) {
            return true;
        }
    }
    false
}

proptest! {
    #[test]
    fn duplicate_nullifiers_cause_rejection(nullifiers in proptest::collection::vec(any::<[u8; 32]>(), 2..5)) {
        let duplicates = has_duplicates(&nullifiers);
        let validators = make_validators(3, 10);
        let validator_set = validator_set(&validators);
        let genesis_tree = CommitmentTreeState::default();
        let mut consensus = BftConsensus::new(validator_set, genesis_tree.clone(), HashVerifier);
        let transaction = Transaction::new(
            nullifiers.clone(),
            vec![[9u8; 32]],
            [7u8; 32],
            DEFAULT_VERSION_BINDING,
            vec![],
        );
        let result = assemble_bft_block(BftBlockParams {
            height: 1,
            view: 1,
            parent_hash: [0u8; 32],
            timestamp_ms: 1234,
            transactions: vec![transaction],
            recursive_proof: None,
            validators: &validators,
            signer_indices: &[0, 1, 2],
            base_nullifiers: &NullifierSet::new(),
            base_commitment_tree: &genesis_tree,
            supply_digest: 0,
        });
        if duplicates {
            prop_assert!(result.is_err());
        } else {
            let (block, _, _) = result.expect("block assembly");
            prop_assert!(consensus.apply_block(block).is_ok());
        }
    }
}
