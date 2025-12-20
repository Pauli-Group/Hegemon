//! Batch proof verifier for STARK proofs.
//!
//! This module provides verification of batch transaction proofs.

use winter_crypto::hashers::Blake3_256;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::fields::f64::BaseElement,
    verify, AcceptableOptions, Proof,
};

use crate::air::BatchTransactionAir;
use crate::error::BatchCircuitError;
use crate::public_inputs::BatchPublicInputs;

type Blake3 = Blake3_256<BaseElement>;

#[cfg(all(feature = "production", feature = "stark-fast"))]
compile_error!("feature \"production\" cannot be combined with \"stark-fast\"");

/// Verify a batch STARK proof.
///
/// This function cryptographically verifies that the proof is valid
/// for the given public inputs.
pub fn verify_batch_proof(
    proof: &Proof,
    pub_inputs: &BatchPublicInputs,
) -> Result<(), BatchCircuitError> {
    // Validate public inputs first
    pub_inputs
        .validate()
        .map_err(|e| BatchCircuitError::InvalidPublicInputs(e.to_string()))?;

    let acceptable = acceptable_options();

    verify::<BatchTransactionAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
        proof.clone(),
        pub_inputs.clone(),
        &acceptable,
    )
    .map_err(|e| BatchCircuitError::VerificationError(format!("{:?}", e)))
}

/// Verify a batch proof from serialized bytes.
pub fn verify_batch_proof_bytes(
    proof_bytes: &[u8],
    pub_inputs: &BatchPublicInputs,
) -> Result<(), BatchCircuitError> {
    let proof =
        Proof::from_bytes(proof_bytes).map_err(|_| BatchCircuitError::InvalidProofFormat)?;

    verify_batch_proof(&proof, pub_inputs)
}

/// Default acceptable options for verification.
fn default_acceptable_options() -> winterfell::ProofOptions {
    winterfell::ProofOptions::new(
        32,
        8,
        0,
        winterfell::FieldExtension::None,
        4,
        31,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    )
}

/// Fast acceptable options for verification (used in testing).
#[cfg(feature = "stark-fast")]
fn fast_acceptable_options() -> winterfell::ProofOptions {
    winterfell::ProofOptions::new(
        8,
        16,
        0,
        winterfell::FieldExtension::None,
        2,
        15,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    )
}

fn acceptable_options() -> AcceptableOptions {
    #[cfg(all(feature = "stark-fast", not(feature = "production")))]
    {
        AcceptableOptions::OptionSet(vec![
            default_acceptable_options(),
            fast_acceptable_options(),
        ])
    }
    #[cfg(any(not(feature = "stark-fast"), feature = "production"))]
    {
        AcceptableOptions::OptionSet(vec![default_acceptable_options()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_batch_proof_rejects_invalid_inputs() {
        // Empty batch should fail validation
        let invalid_inputs = BatchPublicInputs {
            batch_size: 0,
            ..Default::default()
        };

        let dummy_proof_bytes = vec![0u8; 100];
        let result = verify_batch_proof_bytes(&dummy_proof_bytes, &invalid_inputs);
        assert!(result.is_err());
    }
}
