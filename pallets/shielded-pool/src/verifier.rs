//! ZK proof verifier for shielded transactions.
//!
//! This module handles verification of Groth16 proofs for shielded transfers.
//! In production, this would use a proper Groth16 verifier; for now we provide
//! a placeholder that can be swapped out.

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_std::vec::Vec;

use crate::types::{BindingSignature, Groth16Proof, GROTH16_PROOF_SIZE};

/// Verification key for Groth16 proofs.
///
/// In production, this would contain the actual BLS12-381 group elements.
/// For now we use a simplified representation with a key hash.
#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct VerifyingKey {
    /// Key identifier.
    pub id: u32,
    /// Whether this key is enabled.
    pub enabled: bool,
    /// Hash of the full verifying key parameters.
    /// In production, actual curve points would be stored off-chain
    /// and this hash used to verify they match.
    pub key_hash: [u8; 32],
    /// Circuit identifier this key is for.
    pub circuit_id: [u8; 32],
}

impl Default for VerifyingKey {
    fn default() -> Self {
        Self {
            id: 0,
            enabled: true,
            key_hash: [0u8; 32],
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
pub trait ProofVerifier {
    /// Verify a Groth16 proof with the given public inputs.
    fn verify_groth16(
        &self,
        proof: &Groth16Proof,
        inputs: &ShieldedTransferInputs,
        vk: &VerifyingKey,
    ) -> VerificationResult;

    /// Verify binding signature.
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
    fn verify_groth16(
        &self,
        proof: &Groth16Proof,
        _inputs: &ShieldedTransferInputs,
        vk: &VerifyingKey,
    ) -> VerificationResult {
        // Check proof is not all zeros (minimal validation)
        if proof.data == [0u8; GROTH16_PROOF_SIZE] {
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
    fn verify_groth16(
        &self,
        _proof: &Groth16Proof,
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

/// Placeholder production verifier.
///
/// This would be replaced with actual Groth16 verification using
/// the BLS12-381 curve in production.
#[derive(Clone, Debug, Default)]
pub struct Groth16Verifier;

impl Groth16Verifier {
    /// Parse proof from bytes into curve points.
    fn parse_proof(proof: &Groth16Proof) -> Option<ParsedProof> {
        // Proof structure for BLS12-381:
        // - A (G1): 48 bytes
        // - B (G2): 96 bytes
        // - C (G1): 48 bytes
        // Total: 192 bytes
        if proof.data.len() != GROTH16_PROOF_SIZE {
            return None;
        }

        Some(ParsedProof {
            a_g1: proof.data[0..48].try_into().ok()?,
            b_g2: proof.data[48..144].try_into().ok()?,
            c_g1: proof.data[144..192].try_into().ok()?,
        })
    }

    /// Encode public inputs as field elements.
    fn encode_public_inputs(inputs: &ShieldedTransferInputs) -> Vec<[u8; 32]> {
        let mut encoded = Vec::new();

        // Anchor
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

/// Parsed Groth16 proof.
#[allow(dead_code)]
struct ParsedProof {
    a_g1: [u8; 48],
    b_g2: [u8; 96],
    c_g1: [u8; 48],
}

impl ProofVerifier for Groth16Verifier {
    fn verify_groth16(
        &self,
        proof: &Groth16Proof,
        inputs: &ShieldedTransferInputs,
        vk: &VerifyingKey,
    ) -> VerificationResult {
        // Check key is enabled
        if !vk.enabled {
            return VerificationResult::KeyNotFound;
        }

        // Parse proof
        let Some(_parsed) = Self::parse_proof(proof) else {
            return VerificationResult::InvalidProofFormat;
        };

        // Encode public inputs
        let _encoded = Self::encode_public_inputs(inputs);

        // TODO: Implement actual pairing check:
        // e(A, B) = e(alpha, beta) * e(sum(IC[i] * input[i]), gamma) * e(C, delta)
        //
        // For now, we accept all well-formed proofs as a placeholder.
        // This MUST be replaced with real verification before production.
        VerificationResult::Valid
    }

    fn verify_binding_signature(
        &self,
        signature: &BindingSignature,
        _inputs: &ShieldedTransferInputs,
    ) -> bool {
        // TODO: Implement actual binding signature verification
        // The binding signature ensures value balance is correct
        // using the Jubjub curve (or PQ equivalent).

        // For now, accept non-zero signatures
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

    fn sample_proof() -> Groth16Proof {
        Groth16Proof {
            data: [1u8; GROTH16_PROOF_SIZE],
        }
    }

    fn sample_vk() -> VerifyingKey {
        VerifyingKey::default()
    }

    #[test]
    fn accept_all_verifier_accepts_valid_proof() {
        let verifier = AcceptAllProofs;
        let result = verifier.verify_groth16(&sample_proof(), &sample_inputs(), &sample_vk());
        assert_eq!(result, VerificationResult::Valid);
    }

    #[test]
    fn accept_all_verifier_rejects_zero_proof() {
        let verifier = AcceptAllProofs;
        let zero_proof = Groth16Proof::default();
        let result = verifier.verify_groth16(&zero_proof, &sample_inputs(), &sample_vk());
        assert_eq!(result, VerificationResult::InvalidProofFormat);
    }

    #[test]
    fn accept_all_verifier_rejects_disabled_key() {
        let verifier = AcceptAllProofs;
        let mut vk = sample_vk();
        vk.enabled = false;
        let result = verifier.verify_groth16(&sample_proof(), &sample_inputs(), &vk);
        assert_eq!(result, VerificationResult::KeyNotFound);
    }

    #[test]
    fn reject_all_verifier_rejects() {
        let verifier = RejectAllProofs;
        let result = verifier.verify_groth16(&sample_proof(), &sample_inputs(), &sample_vk());
        assert_eq!(result, VerificationResult::VerificationFailed);
    }

    #[test]
    fn groth16_verifier_parses_proof() {
        let proof = sample_proof();
        let parsed = Groth16Verifier::parse_proof(&proof);
        assert!(parsed.is_some());
    }

    #[test]
    fn groth16_verifier_encodes_inputs() {
        let inputs = sample_inputs();
        let encoded = Groth16Verifier::encode_public_inputs(&inputs);

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
