//! Plonky3 verifier for settlement commitments.

use crate::p3_air::{SettlementAirP3, SettlementPublicInputsP3};
use transaction_circuit::p3_config::{default_config, new_challenger, TransactionProofP3};

pub fn verify_settlement_proof_p3(
    proof: &TransactionProofP3,
    pub_inputs: &SettlementPublicInputsP3,
) -> Result<(), SettlementVerifyErrorP3> {
    pub_inputs
        .validate()
        .map_err(SettlementVerifyErrorP3::InvalidPublicInputs)?;

    let config = default_config();
    let mut challenger = new_challenger(&config.perm);
    p3_uni_stark::verify(
        &config.config,
        &SettlementAirP3,
        &mut challenger,
        proof,
        &pub_inputs.to_vec(),
    )
    .map_err(|err| SettlementVerifyErrorP3::VerificationFailed(format!("{err:?}")))
}

pub fn verify_settlement_proof_bytes_p3(
    proof_bytes: &[u8],
    pub_inputs: &SettlementPublicInputsP3,
) -> Result<(), SettlementVerifyErrorP3> {
    pub_inputs
        .validate()
        .map_err(SettlementVerifyErrorP3::InvalidPublicInputs)?;

    let proof: TransactionProofP3 = bincode::deserialize(proof_bytes)
        .map_err(|_| SettlementVerifyErrorP3::InvalidProofFormat)?;
    verify_settlement_proof_p3(&proof, pub_inputs)
}

#[derive(Debug, Clone)]
pub enum SettlementVerifyErrorP3 {
    InvalidProofFormat,
    InvalidPublicInputs(String),
    VerificationFailed(String),
}

impl core::fmt::Display for SettlementVerifyErrorP3 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidProofFormat => write!(f, "Invalid proof format"),
            Self::InvalidPublicInputs(err) => write!(f, "Invalid public inputs: {err}"),
            Self::VerificationFailed(err) => write!(f, "Verification failed: {err}"),
        }
    }
}
