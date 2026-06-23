use disclosure_circuit::{
    prove_payment_disclosure, verify_payment_disclosure, DisclosureCircuitError,
    DisclosureVerifyError, PaymentDisclosureClaim, PaymentDisclosureWitness,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

use transaction_core::{
    constants::BALANCE_SLOT_PADDING_FIELD_ID, hashing_pq::note_commitment_bytes,
};

fn sample_claim_and_witness() -> (PaymentDisclosureClaim, PaymentDisclosureWitness) {
    let mut rng = StdRng::seed_from_u64(42);
    let mut pk_recipient = [0u8; 32];
    let mut pk_auth = [0u8; 32];
    let mut rho = [0u8; 32];
    let mut r = [0u8; 32];
    rng.fill_bytes(&mut pk_recipient);
    rng.fill_bytes(&mut pk_auth);
    rng.fill_bytes(&mut rho);
    rng.fill_bytes(&mut r);

    let value = 1_000_000u64;
    let asset_id = 0u64;
    let commitment = note_commitment_bytes(value, asset_id, &pk_recipient, &pk_auth, &rho, &r);

    (
        PaymentDisclosureClaim {
            value,
            asset_id,
            pk_recipient,
            pk_auth,
            commitment,
        },
        PaymentDisclosureWitness { rho, r },
    )
}

#[test]
fn roundtrip_verifies() {
    let (claim, witness) = sample_claim_and_witness();
    let bundle = prove_payment_disclosure(&claim, &witness).expect("proof");
    verify_payment_disclosure(&bundle).expect("verify");
}

#[test]
fn tamper_value_rejects() {
    let (claim, witness) = sample_claim_and_witness();
    let mut bundle = prove_payment_disclosure(&claim, &witness).expect("proof");
    bundle.claim.value += 1;
    assert!(verify_payment_disclosure(&bundle).is_err());
}

#[test]
fn tamper_asset_id_rejects() {
    let (claim, witness) = sample_claim_and_witness();
    let mut bundle = prove_payment_disclosure(&claim, &witness).expect("proof");
    bundle.claim.asset_id = 1;
    assert!(verify_payment_disclosure(&bundle).is_err());
}

#[test]
fn tamper_pk_recipient_rejects() {
    let (claim, witness) = sample_claim_and_witness();
    let mut bundle = prove_payment_disclosure(&claim, &witness).expect("proof");
    bundle.claim.pk_recipient[0] ^= 0x01;
    assert!(verify_payment_disclosure(&bundle).is_err());
}

#[test]
fn tamper_commitment_rejects() {
    let (claim, witness) = sample_claim_and_witness();
    let mut bundle = prove_payment_disclosure(&claim, &witness).expect("proof");
    bundle.claim.commitment[47] ^= 0x01;
    assert!(verify_payment_disclosure(&bundle).is_err());
}

#[test]
fn trailing_bytes_in_disclosure_proof_reject() {
    let (claim, witness) = sample_claim_and_witness();
    let mut bundle = prove_payment_disclosure(&claim, &witness).expect("proof");
    bundle.proof_bytes.extend_from_slice(&[0xde, 0xad]);
    assert!(verify_payment_disclosure(&bundle).is_err());
}

#[test]
fn reject_non_canonical_commitment() {
    let (mut claim, witness) = sample_claim_and_witness();
    claim.commitment = [0xFF; 48];
    let err = prove_payment_disclosure(&claim, &witness).unwrap_err();
    match err {
        DisclosureCircuitError::NonCanonicalCommitment => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn reject_padding_field_alias_asset_id() {
    let (mut claim, witness) = sample_claim_and_witness();
    claim.asset_id = BALANCE_SLOT_PADDING_FIELD_ID;
    claim.commitment = note_commitment_bytes(
        claim.value,
        claim.asset_id,
        &claim.pk_recipient,
        &claim.pk_auth,
        &witness.rho,
        &witness.r,
    );
    let err = prove_payment_disclosure(&claim, &witness).unwrap_err();
    match err {
        DisclosureCircuitError::InvalidAssetId => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn verifier_rejects_padding_field_alias_asset_id() {
    let (claim, witness) = sample_claim_and_witness();
    let mut bundle = prove_payment_disclosure(&claim, &witness).expect("proof");
    bundle.claim.asset_id = BALANCE_SLOT_PADDING_FIELD_ID;

    let err = verify_payment_disclosure(&bundle).unwrap_err();
    match err {
        DisclosureVerifyError::InvalidPublicInputs(message) => {
            assert!(message.contains("asset identifier"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
