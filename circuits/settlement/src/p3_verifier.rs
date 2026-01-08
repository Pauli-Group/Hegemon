//! Plonky3 verifier for settlement commitments.

use crate::p3_air::{SettlementAirP3, SettlementPublicInputsP3, PREPROCESSED_WIDTH};
use p3_uni_stark::{get_log_num_quotient_chunks, setup_preprocessed, verify_with_preprocessed};
use transaction_circuit::p3_config::{
    config_with_fri, FRI_LOG_BLOWUP, FRI_NUM_QUERIES, TransactionProofP3, Val,
};

pub fn verify_settlement_proof_p3(
    proof: &TransactionProofP3,
    pub_inputs: &SettlementPublicInputsP3,
) -> Result<(), SettlementVerifyErrorP3> {
    pub_inputs
        .validate()
        .map_err(SettlementVerifyErrorP3::InvalidPublicInputs)?;

    let pub_inputs_vec = pub_inputs.to_vec();
    let log_chunks = get_log_num_quotient_chunks::<Val, _>(
        &SettlementAirP3,
        PREPROCESSED_WIDTH,
        pub_inputs_vec.len(),
        0,
    );
    let log_blowup = FRI_LOG_BLOWUP.max(log_chunks);
    let config = config_with_fri(log_blowup, FRI_NUM_QUERIES);
    let degree_bits = proof.degree_bits;
    let prep_vk = setup_preprocessed(&config.config, &SettlementAirP3, degree_bits)
        .map(|(_, vk)| vk)
        .expect("SettlementAirP3 preprocessed trace missing");
    verify_with_preprocessed(
        &config.config,
        &SettlementAirP3,
        proof,
        &pub_inputs_vec,
        Some(&prep_vk),
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
