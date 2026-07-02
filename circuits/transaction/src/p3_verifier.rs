//! Plonky3 verifier for the transaction circuit.

use crate::p3_config::TransactionProofP3;
use protocol_versioning::{TxFriProfile, VersionBinding};
use transaction_core::p3_air::TransactionPublicInputsP3;
pub use transaction_core::p3_verifier::InferredFriProfileP3;
use transaction_core::p3_verifier::{
    infer_fri_profile_from_proof_p3,
    prewarm_transaction_verifier_cache_p3 as core_prewarm_transaction_verifier_cache_p3,
    verify_transaction_proof_bytes_p3 as core_verify_transaction_proof_bytes_p3,
    verify_transaction_proof_bytes_p3_for_version as core_verify_transaction_proof_bytes_p3_for_version,
    verify_transaction_proof_bytes_p3_with_profile as core_verify_transaction_proof_bytes_p3_with_profile,
    verify_transaction_proof_p3 as core_verify_transaction_proof_p3,
    verify_transaction_proof_p3_for_version as core_verify_transaction_proof_p3_for_version,
    verify_transaction_proof_p3_with_profile as core_verify_transaction_proof_p3_with_profile,
    TransactionVerifyErrorP3 as CoreTransactionVerifyErrorP3,
};

pub fn verify_transaction_proof_p3(
    proof: &TransactionProofP3,
    pub_inputs: &TransactionPublicInputsP3,
) -> Result<(), TransactionVerifyErrorP3> {
    core_verify_transaction_proof_p3(proof, pub_inputs).map_err(Into::into)
}

pub fn verify_transaction_proof_bytes_p3(
    proof_bytes: &[u8],
    pub_inputs: &TransactionPublicInputsP3,
) -> Result<(), TransactionVerifyErrorP3> {
    core_verify_transaction_proof_bytes_p3(proof_bytes, pub_inputs).map_err(Into::into)
}

pub fn verify_transaction_proof_p3_with_profile(
    proof: &TransactionProofP3,
    pub_inputs: &TransactionPublicInputsP3,
    expected_profile: TxFriProfile,
) -> Result<(), TransactionVerifyErrorP3> {
    core_verify_transaction_proof_p3_with_profile(proof, pub_inputs, expected_profile)
        .map_err(Into::into)
}

pub fn verify_transaction_proof_p3_for_version(
    proof: &TransactionProofP3,
    pub_inputs: &TransactionPublicInputsP3,
    version: VersionBinding,
) -> Result<(), TransactionVerifyErrorP3> {
    core_verify_transaction_proof_p3_for_version(proof, pub_inputs, version).map_err(Into::into)
}

pub fn verify_transaction_proof_bytes_p3_with_profile(
    proof_bytes: &[u8],
    pub_inputs: &TransactionPublicInputsP3,
    expected_profile: TxFriProfile,
) -> Result<(), TransactionVerifyErrorP3> {
    core_verify_transaction_proof_bytes_p3_with_profile(proof_bytes, pub_inputs, expected_profile)
        .map_err(Into::into)
}

pub fn verify_transaction_proof_bytes_p3_for_version(
    proof_bytes: &[u8],
    pub_inputs: &TransactionPublicInputsP3,
    version: VersionBinding,
) -> Result<(), TransactionVerifyErrorP3> {
    core_verify_transaction_proof_bytes_p3_for_version(proof_bytes, pub_inputs, version)
        .map_err(Into::into)
}

pub fn infer_transaction_fri_profile_p3(
    proof: &TransactionProofP3,
) -> Result<InferredFriProfileP3, TransactionVerifyErrorP3> {
    infer_fri_profile_from_proof_p3(proof).map_err(Into::into)
}

pub fn prewarm_transaction_verifier_cache_p3(
    fri: InferredFriProfileP3,
) -> Result<(), TransactionVerifyErrorP3> {
    core_prewarm_transaction_verifier_cache_p3(fri).map_err(Into::into)
}

#[derive(Debug, Clone)]
pub enum TransactionVerifyErrorP3 {
    InvalidProofFormat,
    InvalidPublicInputs(String),
    VerificationFailed(String),
}

impl From<CoreTransactionVerifyErrorP3> for TransactionVerifyErrorP3 {
    fn from(value: CoreTransactionVerifyErrorP3) -> Self {
        match value {
            CoreTransactionVerifyErrorP3::InvalidProofFormat => Self::InvalidProofFormat,
            CoreTransactionVerifyErrorP3::InvalidPublicInputs(err) => {
                Self::InvalidPublicInputs(err)
            }
            CoreTransactionVerifyErrorP3::VerificationFailed(err) => Self::VerificationFailed(err),
        }
    }
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
