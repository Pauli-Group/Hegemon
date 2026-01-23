//! Plonky3 verifier helpers for transaction proofs.

use alloc::{format, string::String};

use crate::p3_air::{TransactionAirP3, TransactionPublicInputsP3};
use crate::p3_config::{config_with_fri, FRI_LOG_BLOWUP, FRI_NUM_QUERIES, TransactionProofP3, Val};
use p3_uni_stark::{get_log_num_quotient_chunks, verify};

pub fn verify_transaction_proof_p3(
    proof: &TransactionProofP3,
    pub_inputs: &TransactionPublicInputsP3,
) -> Result<(), TransactionVerifyErrorP3> {
    pub_inputs
        .validate()
        .map_err(TransactionVerifyErrorP3::InvalidPublicInputs)?;

    let pub_inputs_vec = pub_inputs.to_vec();
    let log_chunks =
        get_log_num_quotient_chunks::<Val, _>(&TransactionAirP3, 0, pub_inputs_vec.len(), 0);
    let log_blowup = FRI_LOG_BLOWUP.max(log_chunks);
    let config = config_with_fri(log_blowup, FRI_NUM_QUERIES);
    verify(
        &config.config,
        &TransactionAirP3,
        proof,
        &pub_inputs_vec,
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

    let proof: TransactionProofP3 = postcard::from_bytes(proof_bytes)
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
