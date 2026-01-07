//! Plonky3 verifier for batch transaction proofs.

use crate::error::BatchCircuitError;
use crate::p3_air::{BatchPublicInputsP3, BatchTransactionAirP3};
use crate::p3_prover::BatchProofP3;
use p3_uni_stark::{setup_preprocessed, verify_with_preprocessed};
use transaction_circuit::p3_config::default_config;

pub fn verify_batch_proof_p3(
    proof: &BatchProofP3,
    pub_inputs: &BatchPublicInputsP3,
) -> Result<(), BatchCircuitError> {
    pub_inputs
        .validate()
        .map_err(BatchCircuitError::InvalidPublicInputs)?;

    let config = default_config();
    let degree_bits = proof.degree_bits;
    let trace_len = 1usize << degree_bits;
    let air = BatchTransactionAirP3::new(trace_len);
    let prep_vk = setup_preprocessed(&config.config, &air, degree_bits)
        .map(|(_, vk)| vk)
        .expect("BatchTransactionAirP3 preprocessed trace missing");
    verify_with_preprocessed(
        &config.config,
        &air,
        proof,
        &pub_inputs.to_vec(),
        Some(&prep_vk),
    )
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
