use disclosure_circuit::{
    prove_payment_disclosure, verify_payment_disclosure, DisclosureCircuitError,
    PaymentDisclosureClaim, PaymentDisclosureWitness,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

use transaction_core::hashing::note_commitment_bytes;

fn sample_claim_and_witness() -> (PaymentDisclosureClaim, PaymentDisclosureWitness) {
    let mut rng = StdRng::seed_from_u64(42);
    let mut pk_recipient = [0u8; 32];
    let mut rho = [0u8; 32];
    let mut r = [0u8; 32];
    rng.fill_bytes(&mut pk_recipient);
    rng.fill_bytes(&mut rho);
    rng.fill_bytes(&mut r);

    let value = 1_000_000u64;
    let asset_id = 0u64;
    let commitment = note_commitment_bytes(value, asset_id, &pk_recipient, &rho, &r);

    (
        PaymentDisclosureClaim {
            value,
            asset_id,
            pk_recipient,
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
    bundle.claim.commitment[31] ^= 0x01;
    assert!(verify_payment_disclosure(&bundle).is_err());
}

#[test]
fn reject_non_canonical_commitment() {
    let (mut claim, witness) = sample_claim_and_witness();
    claim.commitment = [0xFF; 32];
    let err = prove_payment_disclosure(&claim, &witness).unwrap_err();
    match err {
        DisclosureCircuitError::NonCanonicalCommitment => {}
        other => panic!("unexpected error: {other:?}"),
    }
}
