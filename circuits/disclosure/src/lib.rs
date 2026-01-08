//! Disclosure circuit for payment proofs.

pub mod air;
pub mod constants;
mod prover;
mod verifier;

use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use transaction_core::hashing_pq::{bytes48_to_felts, is_canonical_bytes48, note_commitment_bytes};

use crate::air::DisclosurePublicInputsP3;
use crate::constants::expected_air_hash;
use crate::prover::DisclosureProverP3;
use crate::verifier::verify_disclosure_proof_bytes;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentDisclosureClaim {
    pub value: u64,
    pub asset_id: u64,
    pub pk_recipient: [u8; 32],
    #[serde(with = "serde_bytes48")]
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
    #[error("verification failed: {0}")]
    VerificationFailed(String),
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

    let prover = DisclosureProverP3::new();
    let trace = prover.build_trace(claim, witness)?;
    let pub_inputs = prover.public_inputs(claim)?;
    let proof_bytes = prover.prove_bytes(trace, &pub_inputs)?;

    Ok(PaymentDisclosureProofBundle {
        claim: claim.clone(),
        proof_bytes,
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
) -> Result<DisclosurePublicInputsP3, DisclosureVerifyError> {
    let commitment = bytes48_to_felts(&claim.commitment).ok_or(
        DisclosureVerifyError::InvalidPublicInputs("commitment bytes are not canonical".into()),
    )?;

    Ok(DisclosurePublicInputsP3 {
        value: transaction_core::hashing_pq::Felt::from_u64(claim.value),
        asset_id: transaction_core::hashing_pq::Felt::from_u64(claim.asset_id),
        pk_recipient: bytes32_to_field_elements(&claim.pk_recipient),
        commitment,
    })
}

fn bytes32_to_field_elements(bytes: &[u8; 32]) -> [transaction_core::hashing_pq::Felt; 4] {
    let mut out = [transaction_core::hashing_pq::Felt::ZERO; 4];
    for (idx, chunk) in bytes.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        out[idx] = transaction_core::hashing_pq::Felt::from_u64(u64::from_be_bytes(buf));
    }
    out
}

mod serde_bytes48 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 48 {
            return Err(serde::de::Error::custom("expected 48 bytes"));
        }
        let mut out = [0u8; 48];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}
