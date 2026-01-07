//! Plonky3 verifier for batch transaction proofs.

use crate::error::BatchCircuitError;
use crate::p3_air::{BatchPublicInputsP3, BatchTransactionAirP3};
use crate::p3_prover::BatchProofP3;
use transaction_circuit::p3_config::{default_config, new_challenger};

pub fn verify_batch_proof_p3(
    proof: &BatchProofP3,
    pub_inputs: &BatchPublicInputsP3,
) -> Result<(), BatchCircuitError> {
    pub_inputs
        .validate()
        .map_err(BatchCircuitError::InvalidPublicInputs)?;

    let config = default_config();
    let mut challenger = new_challenger(&config.perm);
    p3_uni_stark::verify(
        &config.config,
        &BatchTransactionAirP3,
        &mut challenger,
        proof,
        &pub_inputs.to_vec(),
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
