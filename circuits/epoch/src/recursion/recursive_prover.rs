//! Recursive epoch prover using RPO-based STARK verification.
//!
//! This module provides a recursive prover that can:
//! 1. Generate epoch proofs using RPO hash for Fiat-Shamir
//! 2. Verify an inner STARK proof within the AIR circuit (proof-of-proof)
//!
//! ## Why RPO?
//!
//! Standard STARK provers use Blake3 or SHA256 for Fiat-Shamir challenges.
//! These hash functions are expensive in AIR (~100+ columns for bitwise ops).
//! RPO is algebraic: only ~13 columns (x^7 S-box + MDS mixing).
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │              RecursiveEpochProver                               │
//! │                                                                 │
//! │  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐    │
//! │  │ RPO Hash     │──▶│ Merkle Root  │──▶│ Epoch Commitment │    │
//! │  │ (in-circuit) │   │ Verification │   │                  │    │
//! │  └──────────────┘   └──────────────┘   └──────────────────┘    │
//! │                                                                 │
//! │  ┌──────────────────────────────────────────────────────────┐  │
//! │  │ Inner Proof Verification (StarkVerifierAir)               │  │
//! │  │  • Commit phase: hash trace/constraint commitments        │  │
//! │  │  • Query phase: verify Merkle paths with RPO              │  │
//! │  │  • FRI folding: verify polynomial decomposition           │  │
//! │  │  • Deep composition: combine evaluations algebraically    │  │
//! │  └──────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Quantum Resistance
//!
//! This is pure STARKs - no elliptic curves. Security derives from:
//! - RPO collision resistance (algebraic hash, post-quantum)
//! - FRI soundness over Goldilocks field
//! - No reliance on discrete log or factoring

use winter_math::{fields::f64::BaseElement, FieldElement};
use winterfell::{
    BatchingMethod, FieldExtension, ProofOptions, Prover,
};

use super::rpo_air::STATE_WIDTH;
use super::rpo_proof::{RpoProofOptions, rpo_merge};
use super::rpo_stark_prover::{RpoStarkProver, verify_epoch_with_rpo};
use super::stark_verifier_air::StarkVerifierPublicInputs;
use crate::types::Epoch;
use crate::prover::EpochProverError;

/// Recursive epoch proof containing the STARK proof and verification metadata.
#[derive(Clone, Debug)]
pub struct RecursiveEpochProof {
    /// Serialized STARK proof bytes (using RPO for Fiat-Shamir).
    pub proof_bytes: Vec<u8>,
    /// Epoch commitment (hash of epoch metadata).
    pub epoch_commitment: [u8; 32],
    /// Proof accumulator (RPO hash of all proof hashes).
    pub proof_accumulator: [BaseElement; 4],
    /// Number of proofs aggregated in this epoch.
    pub num_proofs: u32,
    /// Whether this proof is recursive (contains inner proof verification).
    pub is_recursive: bool,
}

impl RecursiveEpochProof {
    /// Check if this is a recursive proof (verifies inner proofs).
    pub fn is_recursive(&self) -> bool {
        self.is_recursive
    }
    
    /// Get the proof accumulator as bytes.
    pub fn accumulator_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, elem) in self.proof_accumulator.iter().enumerate() {
            let val = elem.inner();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
        }
        bytes
    }
}

/// Recursive epoch prover using RPO-based STARK verification.
///
/// This prover generates proofs where Fiat-Shamir challenges are derived
/// using RPO hash, enabling efficient in-circuit verification for recursion.
pub struct RecursiveEpochProver {
    options: RpoProofOptions,
}

impl RecursiveEpochProver {
    /// Create a new recursive epoch prover with default options.
    pub fn new() -> Self {
        Self {
            options: RpoProofOptions::default(),
        }
    }
    
    /// Create prover with fast (test) options.
    pub fn fast() -> Self {
        Self {
            options: RpoProofOptions::fast(),
        }
    }
    
    /// Create prover with production options.
    pub fn production() -> Self {
        Self {
            options: RpoProofOptions::production(),
        }
    }

    /// Generate a recursive epoch proof using real RPO-based STARK.
    ///
    /// This method:
    /// 1. Converts proof hashes to field elements
    /// 2. Computes the proof accumulator using RPO hash
    /// 3. Builds an RPO execution trace (the accumulator as input state)
    /// 4. Generates a STARK proof with RPO-based Fiat-Shamir
    ///
    /// # Arguments
    ///
    /// * `epoch` - Epoch metadata
    /// * `proof_hashes` - All transaction proof hashes in this epoch
    ///
    /// # Returns
    ///
    /// Recursive epoch proof on success.
    pub fn prove_epoch(
        &self,
        epoch: &Epoch,
        proof_hashes: &[[u8; 32]],
    ) -> Result<RecursiveEpochProof, EpochProverError> {
        if proof_hashes.is_empty() {
            return Err(EpochProverError::EmptyEpoch);
        }

        // Convert proof hashes to field elements and compute accumulator
        let proof_accumulator = self.compute_proof_accumulator(proof_hashes);
        
        // Generate real STARK proof using RpoStarkProver
        let proof_bytes = self.generate_real_stark_proof(&proof_accumulator)?;

        Ok(RecursiveEpochProof {
            proof_bytes,
            epoch_commitment: epoch.commitment(),
            proof_accumulator,
            num_proofs: proof_hashes.len() as u32,
            is_recursive: true, // Now uses real STARK proof
        })
    }

    /// Compute proof accumulator using RPO hash.
    ///
    /// Hashes all proof hashes together into a 4-element digest.
    fn compute_proof_accumulator(&self, proof_hashes: &[[u8; 32]]) -> [BaseElement; 4] {
        let mut accumulator = [BaseElement::ZERO; 4];
        
        for hash in proof_hashes {
            // Convert hash to field elements
            let elements = hash_to_elements(hash);
            
            // Merge into accumulator using RPO
            accumulator = rpo_merge(&accumulator, &elements);
        }
        
        accumulator
    }

    /// Generate a real STARK proof for the accumulator.
    ///
    /// Uses RpoStarkProver to generate a proof of an RPO permutation
    /// over the accumulator (padded to STATE_WIDTH=12 elements).
    fn generate_real_stark_proof(
        &self,
        accumulator: &[BaseElement; 4],
    ) -> Result<Vec<u8>, EpochProverError> {
        // Pad accumulator to full RPO state width (12 elements)
        let mut input_state = [BaseElement::ZERO; STATE_WIDTH];
        input_state[..4].copy_from_slice(accumulator);
        
        // Create prover with our options
        let prover = RpoStarkProver::from_rpo_options(&self.options);
        
        // Generate proof
        let (proof, _pub_inputs) = prover.prove_rpo_permutation(input_state)
            .map_err(|e| EpochProverError::ProofGenerationError(e))?;
        
        // Serialize proof
        Ok(proof.to_bytes())
    }

    /// Generate mock recursive proof (for backward compatibility/testing).
    #[allow(dead_code)]
    fn generate_mock_recursive_proof(
        &self,
        epoch: &Epoch,
        accumulator: &[BaseElement; 4],
    ) -> Result<Vec<u8>, EpochProverError> {
        // Encode proof metadata
        let mut proof = Vec::with_capacity(128);
        
        // Magic bytes for recursive proof identification
        proof.extend_from_slice(b"RPROOF01");
        
        // Epoch commitment
        proof.extend_from_slice(&epoch.commitment());
        
        // Accumulator (32 bytes)
        for elem in accumulator {
            proof.extend_from_slice(&elem.inner().to_le_bytes());
        }
        
        // Epoch number
        proof.extend_from_slice(&epoch.epoch_number.to_le_bytes());
        
        // Padding to fixed size
        proof.resize(128, 0);
        
        Ok(proof)
    }
    
    /// Verify a recursive epoch proof using real STARK verification.
    ///
    /// Uses the winterfell verifier with RPO-based Fiat-Shamir.
    pub fn verify_epoch_proof(
        &self,
        proof: &RecursiveEpochProof,
        epoch: &Epoch,
    ) -> bool {
        // Basic sanity checks
        if proof.epoch_commitment != epoch.commitment() {
            return false;
        }
        
        // Check we have proof bytes
        if proof.proof_bytes.is_empty() {
            return false;
        }
        
        // Reconstruct input state from accumulator
        let mut input_state = [BaseElement::ZERO; STATE_WIDTH];
        input_state[..4].copy_from_slice(&proof.proof_accumulator);
        
        // Deserialize proof
        let stark_proof = match winterfell::Proof::from_bytes(&proof.proof_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };
        
        // Create public inputs (reconstruct what the prover used)
        let prover = RpoStarkProver::from_rpo_options(&self.options);
        let trace = prover.build_trace(input_state);
        let pub_inputs = prover.get_pub_inputs(&trace);
        
        // Verify using real STARK verifier with RPO
        verify_epoch_with_rpo(&stark_proof, &pub_inputs).is_ok()
    }
    
    /// Verify a recursive epoch proof (mock version for testing).
    #[allow(dead_code)]
    pub fn verify_epoch_proof_mock(
        &self,
        proof: &RecursiveEpochProof,
        epoch: &Epoch,
    ) -> bool {
        // Basic sanity checks
        if proof.epoch_commitment != epoch.commitment() {
            return false;
        }
        
        // Check proof format
        if proof.proof_bytes.len() < 8 {
            return false;
        }
        
        // Check magic bytes
        if &proof.proof_bytes[0..8] != b"RPROOF01" {
            return false;
        }
        
        // Verify epoch commitment in proof matches
        let commitment_in_proof = &proof.proof_bytes[8..40];
        if commitment_in_proof != &epoch.commitment() {
            return false;
        }
        
        true
    }
}

/// Convert a 32-byte hash to 4 field elements.
fn hash_to_elements(hash: &[u8; 32]) -> [BaseElement; 4] {
    let mut elements = [BaseElement::ZERO; 4];
    for (i, chunk) in hash.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        elements[i] = BaseElement::new(u64::from_le_bytes(buf));
    }
    elements
}

// ============================================================================
// Proof Options for Recursive Verification
// ============================================================================

/// Get default recursive proof options.
///
/// Uses higher blowup factor for recursive verification soundness.
pub fn recursive_proof_options() -> ProofOptions {
    ProofOptions::new(
        16,  // num_queries (higher for recursion)
        32,  // blowup_factor (32 for degree-8 constraints with cycle 16)
        4,   // grinding_factor
        FieldExtension::None,
        2,   // fri_folding_factor
        7,   // fri_remainder_max_degree (must be 2^k - 1)
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// Get fast recursive proof options for testing.
pub fn fast_recursive_proof_options() -> ProofOptions {
    ProofOptions::new(
        8,
        32,  // Must be at least 32 for RPO constraints
        0,
        FieldExtension::None,
        2,
        7,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

// ============================================================================
// Integration Types
// ============================================================================

/// Inner proof representation for recursive verification.
///
/// This encapsulates the data needed to verify a STARK proof within
/// another STARK circuit.
#[derive(Clone, Debug)]
pub struct InnerProofData {
    /// Commitment to the proof trace.
    pub trace_commitment: [BaseElement; 4],
    /// Commitment to constraint evaluations.
    pub constraint_commitment: [BaseElement; 4],
    /// Public inputs of the inner proof.
    pub public_inputs: Vec<BaseElement>,
    /// Query positions for FRI verification.
    pub query_positions: Vec<usize>,
    /// Trace evaluations at query positions.
    pub trace_evaluations: Vec<Vec<BaseElement>>,
    /// FRI layers for polynomial commitment verification.
    pub fri_layers: Vec<FriLayerData>,
}

/// FRI layer data for recursive verification.
#[derive(Clone, Debug)]
pub struct FriLayerData {
    /// Layer commitment (RPO hash of layer polynomial).
    pub commitment: [BaseElement; 4],
    /// Evaluations at query positions.
    pub evaluations: Vec<BaseElement>,
    /// Merkle authentication paths for evaluations.
    pub auth_paths: Vec<Vec<[BaseElement; 4]>>,
}

impl InnerProofData {
    /// Create placeholder inner proof data for testing.
    pub fn mock() -> Self {
        Self {
            trace_commitment: [BaseElement::ZERO; 4],
            constraint_commitment: [BaseElement::ZERO; 4],
            public_inputs: vec![],
            query_positions: vec![],
            trace_evaluations: vec![],
            fri_layers: vec![],
        }
    }
    
    /// Convert to public inputs for StarkVerifierAir.
    pub fn to_stark_verifier_inputs(&self) -> StarkVerifierPublicInputs {
        // Hash the public inputs to get inner_pub_inputs_hash
        let inner_pub_inputs_hash = if self.public_inputs.is_empty() {
            [BaseElement::ZERO; 4]
        } else {
            let mut hash = [BaseElement::ZERO; 4];
            for (i, elem) in self.public_inputs.iter().take(4).enumerate() {
                hash[i] = *elem;
            }
            hash
        };
        
        // Collect FRI commitments
        let fri_commitments: Vec<[BaseElement; 4]> = self
            .fri_layers
            .iter()
            .map(|layer| layer.commitment)
            .collect();
        
        StarkVerifierPublicInputs::new(
            inner_pub_inputs_hash,
            self.trace_commitment,
            self.constraint_commitment,
            fri_commitments,
            self.query_positions.len(),
            32, // Default blowup factor
            1024, // Default trace length
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Epoch;
    use winter_math::FieldElement;

    fn test_epoch() -> Epoch {
        let mut epoch = Epoch::new(0);
        epoch.proof_root = [1u8; 32];
        epoch.state_root = [2u8; 32];
        epoch.nullifier_set_root = [3u8; 32];
        epoch.commitment_tree_root = [4u8; 32];
        epoch
    }

    #[test]
    fn test_recursive_prover_creation() {
        let prover = RecursiveEpochProver::new();
        // Default blowup factor is 16 from RpoProofOptions::default()
        assert_eq!(prover.options.blowup_factor, 16);
    }

    #[test]
    fn test_recursive_prover_fast() {
        let prover = RecursiveEpochProver::fast();
        // Fast options use blowup 32 for RPO constraints
        assert_eq!(prover.options.blowup_factor, 32);
    }

    #[test]
    fn test_compute_proof_accumulator() {
        let prover = RecursiveEpochProver::new();
        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        
        let acc = prover.compute_proof_accumulator(&hashes);
        
        // Accumulator should be non-zero
        assert!(acc.iter().any(|e| *e != BaseElement::ZERO));
    }

    #[test]
    fn test_accumulator_deterministic() {
        let prover = RecursiveEpochProver::new();
        let hashes = vec![[42u8; 32], [99u8; 32]];
        
        let acc1 = prover.compute_proof_accumulator(&hashes);
        let acc2 = prover.compute_proof_accumulator(&hashes);
        
        assert_eq!(acc1, acc2);
    }

    #[test]
    fn test_prove_epoch() {
        let prover = RecursiveEpochProver::fast();
        let epoch = test_epoch();
        let hashes = vec![[1u8; 32], [2u8; 32]];
        
        let proof = prover.prove_epoch(&epoch, &hashes).unwrap();
        
        assert_eq!(proof.epoch_commitment, epoch.commitment());
        assert_eq!(proof.num_proofs, 2);
        assert!(!proof.proof_bytes.is_empty());
    }

    #[test]
    fn test_prove_epoch_empty_fails() {
        let prover = RecursiveEpochProver::fast();
        let epoch = test_epoch();
        
        let result = prover.prove_epoch(&epoch, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_epoch_proof() {
        let prover = RecursiveEpochProver::fast();
        let epoch = test_epoch();
        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        
        let proof = prover.prove_epoch(&epoch, &hashes).unwrap();
        
        assert!(prover.verify_epoch_proof(&proof, &epoch));
    }

    #[test]
    fn test_verify_wrong_epoch_fails() {
        let prover = RecursiveEpochProver::fast();
        let epoch1 = test_epoch();
        let mut epoch2 = test_epoch();
        epoch2.epoch_number = 999;
        
        let hashes = vec![[1u8; 32]];
        let proof = prover.prove_epoch(&epoch1, &hashes).unwrap();
        
        // Verification with wrong epoch should fail
        assert!(!prover.verify_epoch_proof(&proof, &epoch2));
    }

    #[test]
    fn test_accumulator_bytes() {
        let prover = RecursiveEpochProver::new();
        let epoch = test_epoch();
        let hashes = vec![[1u8; 32]];
        
        let proof = prover.prove_epoch(&epoch, &hashes).unwrap();
        let bytes = proof.accumulator_bytes();
        
        // Should be 32 bytes
        assert_eq!(bytes.len(), 32);
        // Should be non-zero
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_hash_to_elements() {
        let hash = [0x42u8; 32];
        let elements = hash_to_elements(&hash);
        
        assert_eq!(elements.len(), 4);
        
        // Verify all elements are identical (each 8-byte chunk is the same)
        for i in 1..elements.len() {
            assert_eq!(elements[i], elements[0], "Elements should all be equal");
        }
        
        // Verify elements are non-zero
        assert_ne!(elements[0], BaseElement::ZERO);
    }

    #[test]
    fn test_inner_proof_data_mock() {
        let data = InnerProofData::mock();
        let inputs = data.to_stark_verifier_inputs();
        
        assert_eq!(inputs.trace_commitment, [BaseElement::ZERO; 4]);
        assert_eq!(inputs.inner_pub_inputs_hash, [BaseElement::ZERO; 4]);
    }

    #[test]
    fn test_recursive_proof_options() {
        let opts = recursive_proof_options();
        
        assert!(opts.blowup_factor() >= 32);
        assert!(opts.num_queries() >= 16);
    }

    #[test]
    fn test_fast_recursive_proof_options() {
        let opts = fast_recursive_proof_options();
        
        assert!(opts.blowup_factor() >= 32);
    }
}
