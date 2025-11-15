use transaction_circuit::hashing::Felt;
use transaction_circuit::keys::generate_keys;
use transaction_circuit::proof::{prove, verify};
use transaction_circuit::{
    InputNoteWitness, OutputNoteWitness, TransactionCircuitError, TransactionWitness,
};
use winterfell::math::FieldElement;

fn sample_witness() -> TransactionWitness {
    let input_note_native = InputNoteWitness {
        note: transaction_circuit::note::NoteData {
            value: 8,
            asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
            pk_recipient: [2u8; 32],
            rho: [3u8; 32],
            r: [4u8; 32],
        },
        position: 1,
        rho_seed: [9u8; 32],
    };
    let input_note_asset = InputNoteWitness {
        note: transaction_circuit::note::NoteData {
            value: 5,
            asset_id: 1,
            pk_recipient: [5u8; 32],
            rho: [6u8; 32],
            r: [7u8; 32],
        },
        position: 2,
        rho_seed: [8u8; 32],
    };
    let output_native = OutputNoteWitness {
        note: transaction_circuit::note::NoteData {
            value: 3,
            asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
            pk_recipient: [11u8; 32],
            rho: [12u8; 32],
            r: [13u8; 32],
        },
    };
    let output_asset = OutputNoteWitness {
        note: transaction_circuit::note::NoteData {
            value: 5,
            asset_id: 1,
            pk_recipient: [21u8; 32],
            rho: [22u8; 32],
            r: [23u8; 32],
        },
    };
    TransactionWitness {
        inputs: vec![input_note_native, input_note_asset],
        outputs: vec![output_native, output_asset],
        sk_spend: [42u8; 32],
        merkle_root: Felt::new(99),
        fee: 5,
        version: TransactionWitness::default_version_binding(),
    }
}

#[test]
fn proving_and_verification_succeeds() -> Result<(), TransactionCircuitError> {
    let witness = sample_witness();
    let (proving_key, verifying_key) = generate_keys();
    let proof = prove(&witness, &proving_key)?;
    let report = verify(&proof, &verifying_key)?;
    assert!(report.verified);
    Ok(())
}

#[test]
fn verification_fails_for_bad_balance() {
    let witness = sample_witness();
    let (proving_key, verifying_key) = generate_keys();
    let mut proof = prove(&witness, &proving_key).expect("proof generation");
    proof.balance_slots[1].delta = 1; // corrupt non-native slot
    let err = verify(&proof, &verifying_key).expect_err("expected failure");
    assert!(matches!(err, TransactionCircuitError::BalanceMismatch(_)));
}

#[test]
fn verification_fails_for_nullifier_mutation() {
    let witness = sample_witness();
    let (proving_key, verifying_key) = generate_keys();
    let mut proof = prove(&witness, &proving_key).expect("proof generation");
    proof.nullifiers[0] += Felt::ONE; // tamper with nullifier
    let err = verify(&proof, &verifying_key).expect_err("expected failure");
    assert!(matches!(err, TransactionCircuitError::NullifierMismatch(_)));
}
