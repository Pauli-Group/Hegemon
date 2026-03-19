//! Plonky3 verifier helpers for transaction proofs.

use alloc::{format, string::String};

use crate::p3_air::{TransactionAirP3, TransactionPublicInputsP3};
use crate::p3_config::{config_with_fri, TransactionProofP3};
use p3_uni_stark::verify;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InferredFriProfileP3 {
    pub log_blowup: usize,
    pub num_queries: usize,
}

pub fn prewarm_transaction_verifier_cache_p3(
    _fri: InferredFriProfileP3,
) -> Result<(), TransactionVerifyErrorP3> {
    Ok(())
}

pub fn infer_fri_profile_from_proof_p3(
    proof: &TransactionProofP3,
) -> Result<InferredFriProfileP3, TransactionVerifyErrorP3> {
    let num_queries = proof.opening_proof.query_proofs.len();
    if num_queries == 0 {
        return Err(TransactionVerifyErrorP3::VerificationFailed(String::from(
            "proof has zero FRI queries",
        )));
    }

    let final_poly_len = proof.opening_proof.final_poly.len();
    if final_poly_len == 0 || !final_poly_len.is_power_of_two() {
        return Err(TransactionVerifyErrorP3::VerificationFailed(String::from(
            "proof final polynomial length is invalid",
        )));
    }
    let log_final_poly_len = final_poly_len.ilog2() as usize;
    let commit_phase_len = proof.opening_proof.commit_phase_commits.len();
    let baseline = commit_phase_len + log_final_poly_len;

    let mut observed_log_max_height: Option<usize> = None;
    for (query_index, query_proof) in proof.opening_proof.query_proofs.iter().enumerate() {
        let query_max = query_proof
            .input_proof
            .iter()
            .map(|batch| batch.opening_proof.len())
            .max()
            .ok_or_else(|| {
                TransactionVerifyErrorP3::VerificationFailed(format!(
                    "query {query_index} has no input opening proofs"
                ))
            })?;
        if query_max < baseline {
            return Err(TransactionVerifyErrorP3::VerificationFailed(format!(
                "query {query_index} opening depth {query_max} smaller than required baseline {baseline}"
            )));
        }
        match observed_log_max_height {
            Some(expected) if expected != query_max => {
                return Err(TransactionVerifyErrorP3::VerificationFailed(format!(
                    "query opening depth mismatch: expected {expected}, got {query_max} at query {query_index}"
                )));
            }
            Some(_) => {}
            None => observed_log_max_height = Some(query_max),
        }
    }

    let observed_log_max_height = observed_log_max_height.ok_or_else(|| {
        TransactionVerifyErrorP3::VerificationFailed(String::from(
            "proof has no query opening paths",
        ))
    })?;
    let log_blowup = observed_log_max_height
        .checked_sub(baseline)
        .ok_or_else(|| {
            TransactionVerifyErrorP3::VerificationFailed(String::from(
                "failed to infer FRI blowup from proof shape",
            ))
        })?;

    Ok(InferredFriProfileP3 {
        log_blowup,
        num_queries,
    })
}

pub fn verify_transaction_proof_p3(
    proof: &TransactionProofP3,
    pub_inputs: &TransactionPublicInputsP3,
) -> Result<(), TransactionVerifyErrorP3> {
    pub_inputs
        .validate()
        .map_err(TransactionVerifyErrorP3::InvalidPublicInputs)?;

    let pub_inputs_vec = pub_inputs.to_vec();
    let fri_profile = infer_fri_profile_from_proof_p3(proof)?;
    let config = config_with_fri(fri_profile.log_blowup, fri_profile.num_queries);
    verify(&config.config, &TransactionAirP3, proof, &pub_inputs_vec)
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
