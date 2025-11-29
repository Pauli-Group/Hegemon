//! Real STARK verifier for transaction circuits.
//!
//! Actually calls winterfell::verify() to verify proofs.

use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement},
    verify, AcceptableOptions, Proof, VerifierError,
};
use winter_crypto::hashers::Blake3_256;

use crate::stark_air::{TransactionAirStark, TransactionPublicInputsStark};

type Blake3 = Blake3_256<BaseElement>;

// ================================================================================================
// VERIFICATION
// ================================================================================================

/// Verify a STARK proof of a transaction.
///
/// This function ACTUALLY calls winterfell::verify() to cryptographically
/// verify that the proof is valid for the given public inputs.
pub fn verify_transaction_proof(
    proof: &Proof,
    pub_inputs: &TransactionPublicInputsStark,
) -> Result<(), VerifierError> {
    let acceptable = AcceptableOptions::OptionSet(vec![
        default_acceptable_options(),
        fast_acceptable_options(),
    ]);

    verify::<TransactionAirStark, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
        proof.clone(),
        pub_inputs.clone(),
        &acceptable,
    )
}

/// Verify from serialized proof bytes.
pub fn verify_transaction_proof_bytes(
    proof_bytes: &[u8],
    pub_inputs: &TransactionPublicInputsStark,
) -> Result<(), TransactionVerifyError> {
    let proof = Proof::from_bytes(proof_bytes)
        .map_err(|_| TransactionVerifyError::InvalidProofFormat)?;

    verify_transaction_proof(&proof, pub_inputs)
        .map_err(TransactionVerifyError::VerificationFailed)
}

// ================================================================================================
// ERROR TYPES
// ================================================================================================

#[derive(Debug, Clone)]
pub enum TransactionVerifyError {
    InvalidProofFormat,
    VerificationFailed(VerifierError),
    InvalidPublicInputs(String),
}

impl core::fmt::Display for TransactionVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidProofFormat => write!(f, "Invalid proof format"),
            Self::VerificationFailed(e) => write!(f, "Verification failed: {:?}", e),
            Self::InvalidPublicInputs(s) => write!(f, "Invalid public inputs: {}", s),
        }
    }
}

// ================================================================================================
// ACCEPTABLE OPTIONS
// ================================================================================================

fn default_acceptable_options() -> winterfell::ProofOptions {
    winterfell::ProofOptions::new(
        32, 8, 0,
        winterfell::FieldExtension::None,
        4, 31,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    )
}

fn fast_acceptable_options() -> winterfell::ProofOptions {
    // Blowup factor must be at least 2 * constraint_degree = 2 * 5 = 10
    // Use 16 to be safe (power of 2)
    winterfell::ProofOptions::new(
        8, 16, 0,
        winterfell::FieldExtension::None,
        2, 15,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    )
}

// ================================================================================================
// PUBLIC INPUT VALIDATION
// ================================================================================================

impl TransactionPublicInputsStark {
    /// Validate public inputs before verification.
    pub fn validate(&self) -> Result<(), TransactionVerifyError> {
        // Check that balance equation holds
        if self.total_input != self.total_output + self.fee {
            return Err(TransactionVerifyError::InvalidPublicInputs(
                "Balance equation violated: input != output + fee".into()
            ));
        }

        // Check for non-zero nullifiers (at least one input required)
        let has_input = self.nullifiers.iter().any(|nf| *nf != BaseElement::ZERO);
        if !has_input {
            return Err(TransactionVerifyError::InvalidPublicInputs(
                "No non-zero nullifiers found".into()
            ));
        }

        Ok(())
    }
}

// ================================================================================================
// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        note::{InputNoteWitness, NoteData, OutputNoteWitness},
        stark_prover::{TransactionProverStark, fast_proof_options},
        witness::TransactionWitness,
    };
    use winterfell::Prover;

    fn make_test_witness() -> TransactionWitness {
        let input_note = NoteData {
            value: 1000,
            asset_id: 0,
            pk_recipient: [0u8; 32],
            rho: [1u8; 32],
            r: [2u8; 32],
        };

        let output_note = NoteData {
            value: 900,
            asset_id: 0,
            pk_recipient: [3u8; 32],
            rho: [4u8; 32],
            r: [5u8; 32],
        };

        TransactionWitness {
            inputs: vec![InputNoteWitness {
                note: input_note,
                position: 0,
                rho_seed: [7u8; 32],
            }],
            outputs: vec![OutputNoteWitness { note: output_note }],
            sk_spend: [6u8; 32],
            merkle_root: BaseElement::new(12345),
            fee: 100,
            version: protocol_versioning::DEFAULT_VERSION_BINDING,
        }
    }

    #[test]
    fn test_verify_valid_proof() {
        let prover = TransactionProverStark::new(fast_proof_options());
        let witness = make_test_witness();

        let trace = prover.build_trace(&witness).unwrap();
        // Use get_pub_inputs which is what the prover uses internally
        let pub_inputs = prover.get_pub_inputs(&trace);

        let proof = prover.prove(trace).expect("proving should succeed");
        let result = verify_transaction_proof(&proof, &pub_inputs);
        assert!(result.is_ok(), "Verification should succeed: {:?}", result);
    }

    #[test]
    fn test_verify_invalid_public_inputs() {
        let prover = TransactionProverStark::new(fast_proof_options());
        let witness = make_test_witness();

        let trace = prover.build_trace(&witness).unwrap();
        let mut pub_inputs = prover.get_pub_inputs(&trace);

        let proof = prover.prove(trace).expect("proving should succeed");

        // Tamper with public inputs
        pub_inputs.nullifiers[0] = BaseElement::new(99999);

        let result = verify_transaction_proof(&proof, &pub_inputs);
        assert!(result.is_err(), "Verification should fail with wrong public inputs");
    }

    #[test]
    fn test_verify_from_bytes_roundtrip() {
        let prover = TransactionProverStark::new(fast_proof_options());
        let witness = make_test_witness();

        let trace = prover.build_trace(&witness).unwrap();
        let pub_inputs = prover.get_pub_inputs(&trace);

        let proof = prover.prove(trace).expect("proving should succeed");
        let proof_bytes = proof.to_bytes();

        let result = verify_transaction_proof_bytes(&proof_bytes, &pub_inputs);
        assert!(result.is_ok(), "Verification from bytes should succeed: {:?}", result);
    }

    #[test]
    fn test_public_input_validation() {
        // Valid inputs
        let valid = TransactionPublicInputsStark {
            nullifiers: vec![BaseElement::new(123), BaseElement::ZERO],
            commitments: vec![BaseElement::new(456), BaseElement::ZERO],
            total_input: BaseElement::new(1000),
            total_output: BaseElement::new(900),
            fee: BaseElement::new(100),
            merkle_root: BaseElement::new(789),
        };
        assert!(valid.validate().is_ok());

        // Invalid balance
        let invalid_balance = TransactionPublicInputsStark {
            nullifiers: vec![BaseElement::new(123)],
            commitments: vec![BaseElement::new(456)],
            total_input: BaseElement::new(1000),
            total_output: BaseElement::new(900),
            fee: BaseElement::new(50), // Wrong fee
            merkle_root: BaseElement::new(789),
        };
        assert!(invalid_balance.validate().is_err());

        // No inputs
        let no_inputs = TransactionPublicInputsStark {
            nullifiers: vec![BaseElement::ZERO, BaseElement::ZERO],
            commitments: vec![BaseElement::new(456)],
            total_input: BaseElement::ZERO,
            total_output: BaseElement::ZERO,
            fee: BaseElement::ZERO,
            merkle_root: BaseElement::new(789),
        };
        assert!(no_inputs.validate().is_err());
    }
}
