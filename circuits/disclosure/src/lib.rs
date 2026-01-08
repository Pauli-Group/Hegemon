//! Disclosure circuit for payment proofs.

pub mod air;
pub mod constants;
mod poseidon2;
mod prover;
mod verifier;

use serde::{Deserialize, Serialize};
use winterfell::math::{fields::f64::BaseElement, FieldElement};
use winterfell::Prover;

use transaction_core::hashing_pq::{is_canonical_bytes48, note_commitment_bytes};

use crate::air::DisclosurePublicInputs;
use crate::constants::expected_air_hash;
use crate::prover::DisclosureProver;
use crate::verifier::verify_disclosure_proof_bytes;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentDisclosureClaim {
    pub value: u64,
    pub asset_id: u64,
    pub pk_recipient: [u8; 32],
    pub commitment: [u8; 48],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentDisclosureWitness {
    pub rho: [u8; 32],
    pub r: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentDisclosureProofBundle {
    pub claim: PaymentDisclosureClaim,
    pub proof_bytes: Vec<u8>,
    pub air_hash: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum DisclosureCircuitError {
    #[error("commitment bytes are not canonical")]
    NonCanonicalCommitment,
    #[error("commitment does not match claim and witness")]
    CommitmentMismatch,
    #[error("invalid witness: {0}")]
    InvalidWitness(&'static str),
    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(String),
}

#[derive(Debug, thiserror::Error)]
pub enum DisclosureVerifyError {
    #[error("AIR hash mismatch")]
    InvalidAirHash,
    #[error("invalid proof format")]
    InvalidProofFormat,
    #[error("verification failed: {0:?}")]
    VerificationFailed(winterfell::VerifierError),
    #[error("invalid public inputs: {0}")]
    InvalidPublicInputs(String),
}

pub fn prove_payment_disclosure(
    claim: &PaymentDisclosureClaim,
    witness: &PaymentDisclosureWitness,
) -> Result<PaymentDisclosureProofBundle, DisclosureCircuitError> {
    if !is_canonical_bytes48(&claim.commitment) {
        return Err(DisclosureCircuitError::NonCanonicalCommitment);
    }

    let expected = note_commitment_bytes(
        claim.value,
        claim.asset_id,
        &claim.pk_recipient,
        &witness.rho,
        &witness.r,
    );
    if expected != claim.commitment {
        return Err(DisclosureCircuitError::CommitmentMismatch);
    }

    let prover = DisclosureProver::with_defaults();
    let trace = prover.build_trace(claim, witness)?;
    let proof = prover
        .prove(trace)
        .map_err(|e| DisclosureCircuitError::ProofGenerationFailed(format!("{:?}", e)))?;

    Ok(PaymentDisclosureProofBundle {
        claim: claim.clone(),
        proof_bytes: proof.to_bytes(),
        air_hash: expected_air_hash(),
    })
}

pub fn verify_payment_disclosure(
    bundle: &PaymentDisclosureProofBundle,
) -> Result<(), DisclosureVerifyError> {
    if bundle.air_hash != expected_air_hash() {
        return Err(DisclosureVerifyError::InvalidAirHash);
    }

    let pub_inputs = claim_to_public_inputs(&bundle.claim)?;
    verify_disclosure_proof_bytes(&bundle.proof_bytes, &pub_inputs)
}

pub(crate) fn claim_to_public_inputs(
    claim: &PaymentDisclosureClaim,
) -> Result<DisclosurePublicInputs, DisclosureVerifyError> {
    let commitment = bytes48_to_field_elements(&claim.commitment).ok_or(
        DisclosureVerifyError::InvalidPublicInputs("commitment bytes are not canonical".into()),
    )?;

    Ok(DisclosurePublicInputs {
        value: BaseElement::new(claim.value),
        asset_id: BaseElement::new(claim.asset_id),
        pk_recipient: bytes32_to_field_elements(&claim.pk_recipient),
        commitment,
    })
}

fn bytes32_to_field_elements(bytes: &[u8; 32]) -> [BaseElement; 4] {
    let mut out = [BaseElement::ZERO; 4];
    for (idx, chunk) in bytes.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        out[idx] = BaseElement::new(u64::from_be_bytes(buf));
    }
    out
}

fn bytes48_to_field_elements(bytes: &[u8; 48]) -> Option<[BaseElement; 6]> {
    if !is_canonical_bytes48(bytes) {
        return None;
    }
    let mut out = [BaseElement::ZERO; 6];
    for (idx, chunk) in bytes.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        out[idx] = BaseElement::new(u64::from_be_bytes(buf));
    }
    Some(out)
}
