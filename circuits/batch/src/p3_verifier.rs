//! Plonky3 verifier for batch transaction proofs.

use crate::error::BatchCircuitError;
use crate::p3_air::{BatchPublicInputsP3, BatchTransactionAirP3, PREPROCESSED_WIDTH};
use crate::p3_prover::BatchProofP3;
use p3_uni_stark::{get_log_num_quotient_chunks, setup_preprocessed, verify_with_preprocessed};
use transaction_circuit::p3_config::{config_with_fri, Val, FRI_LOG_BLOWUP, FRI_NUM_QUERIES};

pub fn verify_batch_proof_p3(
    proof: &BatchProofP3,
    pub_inputs: &BatchPublicInputsP3,
) -> Result<(), BatchCircuitError> {
    pub_inputs
        .validate()
        .map_err(BatchCircuitError::InvalidPublicInputs)?;

    let pub_inputs_vec = pub_inputs.to_vec();
    let degree_bits = proof.degree_bits;
    let trace_len = 1usize << degree_bits;
    let air = BatchTransactionAirP3::new(trace_len);
    let log_chunks =
        get_log_num_quotient_chunks::<Val, _>(&air, PREPROCESSED_WIDTH, pub_inputs_vec.len(), 0);
    let log_blowup = FRI_LOG_BLOWUP.max(log_chunks);
    let config = config_with_fri(log_blowup, FRI_NUM_QUERIES);
    let prep_vk = setup_preprocessed(&config.config, &air, degree_bits)
        .map(|(_, vk)| vk)
        .expect("BatchTransactionAirP3 preprocessed trace missing");
    verify_with_preprocessed(&config.config, &air, proof, &pub_inputs_vec, Some(&prep_vk))
        .map_err(|err| BatchCircuitError::VerificationError(format!("{err:?}")))
}

pub fn verify_batch_proof_bytes_p3(
    proof_bytes: &[u8],
    pub_inputs: &BatchPublicInputsP3,
) -> Result<(), BatchCircuitError> {
    pub_inputs
        .validate()
        .map_err(BatchCircuitError::InvalidPublicInputs)?;

    let proof: BatchProofP3 =
        bincode::deserialize(proof_bytes).map_err(|_| BatchCircuitError::InvalidProofFormat)?;
    verify_batch_proof_p3(&proof, pub_inputs)
}
