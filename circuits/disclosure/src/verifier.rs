//! Plonky3 verifier for disclosure proofs.

use p3_uni_stark::{get_log_num_quotient_chunks, setup_preprocessed, verify_with_preprocessed};
use transaction_core::p3_config::{config_with_fri, Val, FRI_LOG_BLOWUP, FRI_NUM_QUERIES};

use crate::air::{DisclosureAirP3, DisclosurePublicInputsP3, PREPROCESSED_WIDTH};
use crate::prover::DisclosureProofP3;
use crate::DisclosureVerifyError;

pub fn verify_disclosure_proof(
    proof: &DisclosureProofP3,
    pub_inputs: &DisclosurePublicInputsP3,
) -> Result<(), DisclosureVerifyError> {
    pub_inputs
        .validate()
        .map_err(DisclosureVerifyError::InvalidPublicInputs)?;

    let pub_inputs_vec = pub_inputs.to_vec();
    let degree_bits = proof.degree_bits;
    let trace_len = 1usize << degree_bits;
    let air = DisclosureAirP3::new(trace_len);
    let log_chunks =
        get_log_num_quotient_chunks::<Val, _>(&air, PREPROCESSED_WIDTH, pub_inputs_vec.len(), 0);
    let log_blowup = FRI_LOG_BLOWUP.max(log_chunks);
    let config = config_with_fri(log_blowup, FRI_NUM_QUERIES);
    let prep_vk = setup_preprocessed(&config.config, &air, degree_bits)
        .map(|(_, vk)| vk)
        .expect("DisclosureAirP3 preprocessed trace missing");
    verify_with_preprocessed(&config.config, &air, proof, &pub_inputs_vec, Some(&prep_vk))
        .map_err(|err| DisclosureVerifyError::VerificationFailed(format!("{err:?}")))
}

pub fn verify_disclosure_proof_bytes(
    proof_bytes: &[u8],
    pub_inputs: &DisclosurePublicInputsP3,
) -> Result<(), DisclosureVerifyError> {
    let proof: DisclosureProofP3 =
        bincode::deserialize(proof_bytes).map_err(|_| DisclosureVerifyError::InvalidProofFormat)?;
    verify_disclosure_proof(&proof, pub_inputs)
}
