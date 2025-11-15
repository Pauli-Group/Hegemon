mod common;

use common::{assemble_bft_block, make_validators, validator_set};
use consensus::{BftConsensus, HashVerifier, NullifierSet, Transaction};
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
        let mut consensus = BftConsensus::new(validator_set, [0u8; 32], HashVerifier::default());
        let transaction = Transaction::new(nullifiers.clone(), vec![[9u8; 32]], [7u8; 32]);
        let result = assemble_bft_block(
            1,
            1,
            [0u8; 32],
            1234,
            vec![transaction],
            &validators,
            &[0, 1, 2],
            &NullifierSet::new(),
            [0u8; 32],
        );
        if duplicates {
            prop_assert!(result.is_err());
        } else {
            let (block, _, _) = result.expect("block assembly");
            prop_assert!(consensus.apply_block(block).is_ok());
        }
    }
}
