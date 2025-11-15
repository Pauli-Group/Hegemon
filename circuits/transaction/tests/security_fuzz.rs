#![allow(dead_code)]

use std::collections::BTreeMap;

use proptest::{collection::vec, prelude::*};
use transaction_circuit::constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS, NATIVE_ASSET_ID};
use transaction_circuit::hashing::Felt;
use transaction_circuit::note::{InputNoteWitness, NoteData, OutputNoteWitness};
use transaction_circuit::{TransactionCircuitError, TransactionWitness};
use winterfell::math::FieldElement;

fn arb_bytes32() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

fn asset_strategy() -> impl Strategy<Value = u64> {
    prop_oneof![Just(NATIVE_ASSET_ID), (1u64..4u64)]
}

fn arb_note_data() -> impl Strategy<Value = NoteData> {
    (
        0u64..100_000,
        asset_strategy(),
        arb_bytes32(),
        arb_bytes32(),
        arb_bytes32(),
    )
        .prop_map(|(value, asset_id, pk, rho, r)| NoteData {
            value,
            asset_id,
            pk_recipient: pk,
            rho,
            r,
        })
}

fn arb_input_note() -> impl Strategy<Value = InputNoteWitness> {
    (arb_note_data(), any::<u32>(), arb_bytes32()).prop_map(|(note, position, rho_seed)| {
        InputNoteWitness {
            note,
            position: position as u64,
            rho_seed,
        }
    })
}

fn arb_output_note() -> impl Strategy<Value = OutputNoteWitness> {
    arb_note_data().prop_map(|note| OutputNoteWitness { note })
}

fn normalize_outputs(
    inputs: &[InputNoteWitness],
    outputs: &mut [OutputNoteWitness],
    fee_seed: u64,
) -> u64 {
    let mut budgets: BTreeMap<u64, u128> = BTreeMap::new();
    for input in inputs {
        *budgets.entry(input.note.asset_id).or_default() += input.note.value as u128;
    }
    let native_budget = budgets.entry(NATIVE_ASSET_ID).or_default();
    let fee_cap = if *native_budget == 0 {
        0
    } else {
        fee_seed % (*native_budget as u64 + 1)
    };
    *native_budget = native_budget.saturating_sub(fee_cap as u128);

    for output in outputs.iter_mut() {
        let budget = budgets.entry(output.note.asset_id).or_default();
        let cap = (*budget).min(u128::from(output.note.value));
        let new_value = if *budget == 0 {
            0
        } else {
            let bound = (*budget + 1).min(u128::from(u64::MAX));
            (u128::from(output.note.value) % bound) as u64
        };
        output.note.value = if cap == 0 {
            0
        } else {
            new_value.min(cap as u64)
        };
        *budget = budget.saturating_sub(output.note.value as u128);
    }

    fee_cap
}

fn arb_witness() -> impl Strategy<Value = TransactionWitness> {
    (
        vec(arb_input_note(), 1..=MAX_INPUTS),
        vec(arb_output_note(), 1..=MAX_OUTPUTS),
        arb_bytes32(),
        any::<u64>(),
        any::<u64>(),
    )
        .prop_map(|(inputs, mut outputs, sk_spend, fee_seed, merkle)| {
            let fee = normalize_outputs(&inputs, &mut outputs, fee_seed);
            TransactionWitness {
                inputs,
                outputs,
                sk_spend,
                merkle_root: Felt::new(merkle),
                fee,
                version: TransactionWitness::default_version_binding(),
            }
        })
}

fn balance_map(witness: &TransactionWitness) -> BTreeMap<u64, i128> {
    let mut map = BTreeMap::new();
    for input in &witness.inputs {
        *map.entry(input.note.asset_id).or_default() += input.note.value as i128;
    }
    for output in &witness.outputs {
        *map.entry(output.note.asset_id).or_default() -= output.note.value as i128;
    }
    map
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    fn balance_slots_match_witness(witness in arb_witness()) {
        witness.validate().expect("valid witness");
        let slots = witness.balance_slots().expect("balance slots");
        prop_assert_eq!(slots.len(), BALANCE_SLOTS);
        let expected = balance_map(&witness);
        let filtered: BTreeMap<u64, i128> = slots
            .iter()
            .filter(|slot| slot.asset_id != u64::MAX)
            .map(|slot| (slot.asset_id, slot.delta))
            .collect();
        prop_assert_eq!(filtered, expected);
    }
}

#[test]
fn witness_rejects_oversized_inputs() {
    let mut witness = TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: NoteData {
                    value: 1,
                    asset_id: NATIVE_ASSET_ID,
                    pk_recipient: [1u8; 32],
                    rho: [2u8; 32],
                    r: [3u8; 32],
                },
                position: 0,
                rho_seed: [4u8; 32],
            };
            MAX_INPUTS + 1
        ],
        outputs: vec![OutputNoteWitness {
            note: NoteData {
                value: 0,
                asset_id: NATIVE_ASSET_ID,
                pk_recipient: [5u8; 32],
                rho: [6u8; 32],
                r: [7u8; 32],
            },
        }],
        sk_spend: [0u8; 32],
        merkle_root: Felt::ZERO,
        fee: 0,
        version: TransactionWitness::default_version_binding(),
    };
    witness.outputs.resize(
        MAX_OUTPUTS,
        OutputNoteWitness {
            note: NoteData {
                value: 0,
                asset_id: NATIVE_ASSET_ID,
                pk_recipient: [8u8; 32],
                rho: [9u8; 32],
                r: [10u8; 32],
            },
        },
    );
    let err = witness.validate().expect_err("too many inputs should fail");
    assert!(matches!(err, TransactionCircuitError::TooManyInputs(_)));
}
