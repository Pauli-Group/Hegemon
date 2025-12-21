//! Real STARK verifier for transaction circuits.
//!
//! Actually calls winterfell::verify() to verify proofs.

use alloc::string::String;
use alloc::vec;
use winter_crypto::hashers::Blake3_256;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement},
    verify, AcceptableOptions, Proof, VerifierError,
};

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
    let acceptable = acceptable_options();

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
    pub_inputs.validate()?;
    let proof =
        Proof::from_bytes(proof_bytes).map_err(|_| TransactionVerifyError::InvalidProofFormat)?;

    verify_transaction_proof(&proof, pub_inputs).map_err(TransactionVerifyError::VerificationFailed)
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

fn acceptable_options() -> AcceptableOptions {
    #[cfg(feature = "stark-fast")]
    {
        AcceptableOptions::OptionSet(vec![
            default_acceptable_options(),
            fast_acceptable_options(),
        ])
    }
    #[cfg(not(feature = "stark-fast"))]
    {
        AcceptableOptions::OptionSet(vec![default_acceptable_options()])
    }
}

#[cfg(feature = "stark-fast")]
fn fast_acceptable_options() -> winterfell::ProofOptions {
    // Blowup factor must be at least 2 * constraint_degree = 2 * 5 = 10
    // Use 16 to be safe (power of 2)
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

// ================================================================================================
// PUBLIC INPUT VALIDATION
// ================================================================================================

impl TransactionPublicInputsStark {
    /// Validate public inputs before verification.
    pub fn validate(&self) -> Result<(), TransactionVerifyError> {
        if self.input_flags.len() != crate::constants::MAX_INPUTS {
            return Err(TransactionVerifyError::InvalidPublicInputs(
                "input_flags length mismatch".into(),
            ));
        }
        if self.output_flags.len() != crate::constants::MAX_OUTPUTS {
            return Err(TransactionVerifyError::InvalidPublicInputs(
                "output_flags length mismatch".into(),
            ));
        }
        if self.nullifiers.len() != crate::constants::MAX_INPUTS {
            return Err(TransactionVerifyError::InvalidPublicInputs(
                "nullifiers length mismatch".into(),
            ));
        }
        if self.commitments.len() != crate::constants::MAX_OUTPUTS {
            return Err(TransactionVerifyError::InvalidPublicInputs(
                "commitments length mismatch".into(),
            ));
        }

        let is_zero_hash =
            |value: &[BaseElement; 4]| value.iter().all(|elem| *elem == BaseElement::ZERO);

        for (idx, flag) in self.input_flags.iter().enumerate() {
            if *flag != BaseElement::ZERO && *flag != BaseElement::ONE {
                return Err(TransactionVerifyError::InvalidPublicInputs(
                    "input flag must be 0 or 1".into(),
                ));
            }
            let nf = &self.nullifiers[idx];
            if *flag == BaseElement::ZERO && !is_zero_hash(nf) {
                return Err(TransactionVerifyError::InvalidPublicInputs(
                    "inactive input has non-zero nullifier".into(),
                ));
            }
            if *flag == BaseElement::ONE && is_zero_hash(nf) {
                return Err(TransactionVerifyError::InvalidPublicInputs(
                    "active input has zero nullifier".into(),
                ));
            }
        }

        for (idx, flag) in self.output_flags.iter().enumerate() {
            if *flag != BaseElement::ZERO && *flag != BaseElement::ONE {
                return Err(TransactionVerifyError::InvalidPublicInputs(
                    "output flag must be 0 or 1".into(),
                ));
            }
            let cm = &self.commitments[idx];
            if *flag == BaseElement::ZERO && !is_zero_hash(cm) {
                return Err(TransactionVerifyError::InvalidPublicInputs(
                    "inactive output has non-zero commitment".into(),
                ));
            }
            if *flag == BaseElement::ONE && is_zero_hash(cm) {
                return Err(TransactionVerifyError::InvalidPublicInputs(
                    "active output has zero commitment".into(),
                ));
            }
        }

        let has_input = self.nullifiers.iter().any(|nf| !is_zero_hash(nf));
        let has_output = self.commitments.iter().any(|cm| !is_zero_hash(cm));
        if !has_input && !has_output {
            return Err(TransactionVerifyError::InvalidPublicInputs(
                "Transaction has no inputs or outputs".into(),
            ));
        }

        if self.value_balance_sign != BaseElement::ZERO
            && self.value_balance_sign != BaseElement::ONE
        {
            return Err(TransactionVerifyError::InvalidPublicInputs(
                "Value balance sign must be 0 or 1".into(),
            ));
        }

        Ok(())
    }
}
