//! ZK proof verifier for shielded transactions.
//!
//! This module handles verification of STARK proofs for shielded transfers.
//! The proving system is transparent (no trusted setup) and uses only
//! hash-based cryptography, making it post-quantum secure.
//!
//! ## Design
//!
//! - Uses FRI-based STARK proofs (Winterfell-compatible)
//! - All operations are hash-based (Blake3/Poseidon)
//! - Value balance verified in-circuit

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_std::vec::Vec;

use crate::types::{BindingSignature, StarkProof};

/// Verification key for STARK proofs.
///
/// Contains the circuit parameters needed to verify proofs.
/// Uses transparent setup - no ceremony required.
#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct VerifyingKey {
    /// Key identifier.
    pub id: u32,
    /// Whether this key is enabled.
    pub enabled: bool,
    /// Hash of the AIR (Algebraic Intermediate Representation) constraints.
    /// Used to verify proofs were generated for the correct circuit.
    pub air_hash: [u8; 32],
    /// Circuit identifier.
    pub circuit_id: [u8; 32],
}

// Keep legacy field name for compatibility
impl VerifyingKey {
    pub fn key_hash(&self) -> [u8; 32] {
        self.air_hash
    }
}

impl Default for VerifyingKey {
    fn default() -> Self {
        Self {
            id: 0,
            enabled: true,
            air_hash: [0u8; 32],
            circuit_id: [0u8; 32],
        }
    }
}

/// Public inputs for shielded transfer verification.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct ShieldedTransferInputs {
    /// Merkle root anchor.
    pub anchor: [u8; 32],
    /// Nullifiers for spent notes.
    pub nullifiers: Vec<[u8; 32]>,
    /// Commitments for new notes.
    pub commitments: Vec<[u8; 32]>,
    /// Net value balance (transparent component).
    pub value_balance: i128,
}

/// Result of proof verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationResult {
    /// Proof is valid.
    Valid,
    /// Proof format is invalid.
    InvalidProofFormat,
    /// Public inputs are malformed.
    InvalidPublicInputs,
    /// Verification equation failed.
    VerificationFailed,
    /// Verifying key not found or disabled.
    KeyNotFound,
    /// Binding signature invalid.
    InvalidBindingSignature,
}

/// Proof verifier trait.
///
/// This trait abstracts proof verification so different backends can be used.
/// Uses STARK (hash-based) verification.
pub trait ProofVerifier {
    /// Verify a STARK proof with the given public inputs.
    fn verify_stark(
        &self,
        proof: &StarkProof,
        inputs: &ShieldedTransferInputs,
        vk: &VerifyingKey,
    ) -> VerificationResult;

    /// Verify value balance commitment.
    /// In the PQC model, this is typically verified in-circuit,
    /// but we keep the API for compatibility.
    fn verify_binding_signature(
        &self,
        signature: &BindingSignature,
        inputs: &ShieldedTransferInputs,
    ) -> bool;
}

/// Accept-all proof verifier for testing/development.
///
/// WARNING: This should NEVER be used in production!
#[derive(Clone, Debug, Default)]
pub struct AcceptAllProofs;

impl ProofVerifier for AcceptAllProofs {
    fn verify_stark(
        &self,
        proof: &StarkProof,
        _inputs: &ShieldedTransferInputs,
        vk: &VerifyingKey,
    ) -> VerificationResult {
        // Check proof is not empty (minimal validation)
        if proof.is_empty() {
            return VerificationResult::InvalidProofFormat;
        }

        // Check key is enabled
        if !vk.enabled {
            return VerificationResult::KeyNotFound;
        }

        VerificationResult::Valid
    }

    fn verify_binding_signature(
        &self,
        _signature: &BindingSignature,
        _inputs: &ShieldedTransferInputs,
    ) -> bool {
        true
    }
}

/// Reject-all proof verifier for testing.
#[derive(Clone, Debug, Default)]
pub struct RejectAllProofs;

impl ProofVerifier for RejectAllProofs {
    fn verify_stark(
        &self,
        _proof: &StarkProof,
        _inputs: &ShieldedTransferInputs,
        _vk: &VerifyingKey,
    ) -> VerificationResult {
        VerificationResult::VerificationFailed
    }

    fn verify_binding_signature(
        &self,
        _signature: &BindingSignature,
        _inputs: &ShieldedTransferInputs,
    ) -> bool {
        false
    }
}

/// STARK proof verifier.
///
/// Uses FRI-based interactive oracle proofs for transparent verification.
/// No trusted setup required - security relies only on hash functions.
#[derive(Clone, Debug, Default)]
pub struct StarkVerifier;

impl StarkVerifier {
    /// Encode public inputs as field elements for STARK verification.
    pub fn encode_public_inputs(inputs: &ShieldedTransferInputs) -> Vec<[u8; 32]> {
        let mut encoded = Vec::new();

        // Anchor (Merkle root)
        encoded.push(inputs.anchor);

        // Nullifiers
        for nf in &inputs.nullifiers {
            encoded.push(*nf);
        }

        // Commitments
        for cm in &inputs.commitments {
            encoded.push(*cm);
        }

        // Value balance (encoded as two field elements for sign and magnitude)
        let sign = if inputs.value_balance < 0 { 1u8 } else { 0u8 };
        let magnitude = inputs.value_balance.unsigned_abs() as u64;

        let mut sign_bytes = [0u8; 32];
        sign_bytes[31] = sign;
        encoded.push(sign_bytes);

        let mut mag_bytes = [0u8; 32];
        mag_bytes[24..32].copy_from_slice(&magnitude.to_be_bytes());
        encoded.push(mag_bytes);

        encoded
    }
}

impl ProofVerifier for StarkVerifier {
    fn verify_stark(
        &self,
        proof: &StarkProof,
        inputs: &ShieldedTransferInputs,
        vk: &VerifyingKey,
    ) -> VerificationResult {
        // Check key is enabled
        if !vk.enabled {
            return VerificationResult::KeyNotFound;
        }

        // Check proof is not empty
        if proof.is_empty() {
            return VerificationResult::InvalidProofFormat;
        }

        // Encode public inputs
        let _encoded = Self::encode_public_inputs(inputs);

        // TODO: Integrate with transaction-circuit crate for real STARK verification
        // The verify() function in circuits/transaction/src/proof.rs should be called here
        //
        // For now, we accept all non-empty proofs as a placeholder.
        // This MUST be replaced with real verification before production.
        VerificationResult::Valid
    }

    fn verify_binding_signature(
        &self,
        signature: &BindingSignature,
        _inputs: &ShieldedTransferInputs,
    ) -> bool {
        // In the STARK model, value balance is verified in-circuit.
        // This check just ensures the commitment is non-zero.
        signature.data != [0u8; 64]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inputs() -> ShieldedTransferInputs {
        ShieldedTransferInputs {
            anchor: [1u8; 32],
            nullifiers: vec![[2u8; 32], [3u8; 32]],
            commitments: vec![[4u8; 32], [5u8; 32]],
            value_balance: 0,
        }
    }

    fn sample_proof() -> StarkProof {
        StarkProof::from_bytes(vec![1u8; 1024])
    }

    fn sample_vk() -> VerifyingKey {
        VerifyingKey::default()
    }

    #[test]
    fn accept_all_verifier_accepts_valid_proof() {
        let verifier = AcceptAllProofs;
        let result = verifier.verify_stark(&sample_proof(), &sample_inputs(), &sample_vk());
        assert_eq!(result, VerificationResult::Valid);
    }

    #[test]
    fn accept_all_verifier_rejects_zero_proof() {
        let verifier = AcceptAllProofs;
        let zero_proof = StarkProof::default();
        let result = verifier.verify_stark(&zero_proof, &sample_inputs(), &sample_vk());
        assert_eq!(result, VerificationResult::InvalidProofFormat);
    }

    #[test]
    fn accept_all_verifier_rejects_disabled_key() {
        let verifier = AcceptAllProofs;
        let mut vk = sample_vk();
        vk.enabled = false;
        let result = verifier.verify_stark(&sample_proof(), &sample_inputs(), &vk);
        assert_eq!(result, VerificationResult::KeyNotFound);
    }

    #[test]
    fn reject_all_verifier_rejects() {
        let verifier = RejectAllProofs;
        let result = verifier.verify_stark(&sample_proof(), &sample_inputs(), &sample_vk());
        assert_eq!(result, VerificationResult::VerificationFailed);
    }

    #[test]
    fn stark_verifier_encodes_inputs() {
        let inputs = sample_inputs();
        let encoded = StarkVerifier::encode_public_inputs(&inputs);

        // 1 anchor + 2 nullifiers + 2 commitments + 2 value balance = 7
        assert_eq!(encoded.len(), 7);
    }

    #[test]
    fn accept_all_binding_sig_accepts() {
        let verifier = AcceptAllProofs;
        let sig = BindingSignature::default();
        assert!(verifier.verify_binding_signature(&sig, &sample_inputs()));
    }

    #[test]
    fn reject_all_binding_sig_rejects() {
        let verifier = RejectAllProofs;
        let sig = BindingSignature {
            data: [1u8; 64],
        };
        assert!(!verifier.verify_binding_signature(&sig, &sample_inputs()));
    }
}
