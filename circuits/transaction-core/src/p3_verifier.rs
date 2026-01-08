//! Plonky3 verifier helpers for transaction proofs.

use crate::p3_air::{TransactionAirP3, TransactionPublicInputsP3};
use crate::p3_config::{default_config, TransactionProofP3};
use p3_uni_stark::verify;

pub fn verify_transaction_proof_p3(
    proof: &TransactionProofP3,
    pub_inputs: &TransactionPublicInputsP3,
) -> Result<(), TransactionVerifyErrorP3> {
    pub_inputs
        .validate()
        .map_err(TransactionVerifyErrorP3::InvalidPublicInputs)?;

    let config = default_config();
    verify(
        &config.config,
        &TransactionAirP3,
        proof,
        &pub_inputs.to_vec(),
    )
    .map_err(|err| TransactionVerifyErrorP3::VerificationFailed(format!("{err:?}")))
}

pub fn verify_transaction_proof_bytes_p3(
    proof_bytes: &[u8],
    pub_inputs: &TransactionPublicInputsP3,
) -> Result<(), TransactionVerifyErrorP3> {
    pub_inputs
        .validate()
        .map_err(TransactionVerifyErrorP3::InvalidPublicInputs)?;

    let proof: TransactionProofP3 = bincode::deserialize(proof_bytes)
        .map_err(|_| TransactionVerifyErrorP3::InvalidProofFormat)?;
    verify_transaction_proof_p3(&proof, pub_inputs)
}

#[derive(Debug, Clone)]
pub enum TransactionVerifyErrorP3 {
    InvalidProofFormat,
    InvalidPublicInputs(String),
    VerificationFailed(String),
}

impl core::fmt::Display for TransactionVerifyErrorP3 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidProofFormat => write!(f, "Invalid proof format"),
            Self::InvalidPublicInputs(err) => write!(f, "Invalid public inputs: {}", err),
            Self::VerificationFailed(err) => write!(f, "Verification failed: {}", err),
        }
    }
}
