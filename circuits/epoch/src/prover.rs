//! Epoch proof generation.
//!
//! Generates STARK proofs that attest to epoch validity by proving
//! knowledge of all transaction proof hashes that form the claimed
//! proof accumulator.

use winter_crypto::hashers::Blake3_256;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement},
    matrix::ColMatrix,
    AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, ProofOptions, Prover, StarkDomain, TraceInfo,
    TracePolyTable, TraceTable,
};

use crate::air::{
    EpochProofAir, EpochPublicInputs, COL_ACCUMULATOR, COL_PROOF_INPUT, COL_S0, COL_S1, COL_S2,
    EPOCH_TRACE_WIDTH, POSEIDON_ROUNDS,
};
use crate::types::Epoch;

use transaction_circuit::stark_air::{mds_mix, round_constant, sbox, CYCLE_LENGTH};

type Blake3 = Blake3_256<BaseElement>;

/// Epoch proof (serialized STARK proof with metadata).
#[derive(Clone, Debug)]
pub struct EpochProof {
    /// Serialized winterfell proof bytes.
    pub proof_bytes: Vec<u8>,
    /// Epoch commitment for verification.
    pub epoch_commitment: [u8; 32],
    /// Proof accumulator (Poseidon hash of all proof hashes).
    pub proof_accumulator: BaseElement,
    /// Number of proofs in this epoch.
    pub num_proofs: u32,
}

/// Error type for epoch prover.
#[derive(Clone, Debug, thiserror::Error)]
pub enum EpochProverError {
    #[error("Cannot create epoch proof for empty epoch")]
    EmptyEpoch,
    #[error("Trace generation failed: {0}")]
    TraceBuildError(String),
    #[error("Proof generation failed: {0}")]
    ProofGenerationError(String),
}

/// Epoch prover.
///
/// Generates STARK proofs for epoch validity.
pub struct EpochProver {
    options: ProofOptions,
    pub_inputs: Option<EpochPublicInputs>,
}

impl EpochProver {
    /// Create new epoch prover with default options.
    pub fn new() -> Self {
        Self {
            options: default_epoch_options(),
            pub_inputs: None,
        }
    }

    /// Create prover with production security settings.
    ///
    /// Uses a quadratic field extension to raise soundness over a ~64-bit base field.
    ///
    /// Note: overall security is also bounded by the chosen ProofOptions and hash collision
    /// resistance; do not treat "quadratic extension" as a magic "128-bit" label.
    pub fn production() -> Self {
        Self {
            options: production_epoch_options(),
            pub_inputs: None,
        }
    }

    /// Create prover with fast (less secure) options for testing.
    pub fn with_fast_options() -> Self {
        Self {
            options: fast_epoch_options(),
            pub_inputs: None,
        }
    }

    /// Generate epoch proof from epoch metadata and proof hashes.
    ///
    /// # Arguments
    ///
    /// * `epoch` - Epoch metadata (must have proof_root computed)
    /// * `proof_hashes` - All transaction proof hashes in this epoch
    ///
    /// # Returns
    ///
    /// The epoch proof on success, or an error if proof generation fails.
    pub fn prove_epoch(
        &self,
        epoch: &Epoch,
        proof_hashes: &[[u8; 32]],
    ) -> Result<EpochProof, EpochProverError> {
        if proof_hashes.is_empty() {
            return Err(EpochProverError::EmptyEpoch);
        }

        // Build execution trace
        let (trace, proof_accumulator) = self.build_trace(proof_hashes)?;

        // Store public inputs for Prover trait
        let pub_inputs = EpochPublicInputs {
            proof_accumulator,
            num_proofs: proof_hashes.len() as u32,
            epoch_commitment: epoch.commitment(),
        };

        // Generate proof using the Prover trait method
        let prover = Self {
            options: self.options.clone(),
            pub_inputs: Some(pub_inputs.clone()),
        };
        let proof = prover
            .prove(trace)
            .map_err(|e| EpochProverError::ProofGenerationError(format!("{:?}", e)))?;

        Ok(EpochProof {
            proof_bytes: proof.to_bytes(),
            epoch_commitment: epoch.commitment(),
            proof_accumulator,
            num_proofs: proof_hashes.len() as u32,
        })
    }

    /// Build execution trace for epoch proof.
    ///
    /// Converts all proof hashes to field elements and absorbs them into
    /// a Poseidon sponge, producing a trace of the entire computation.
    pub fn build_trace(
        &self,
        proof_hashes: &[[u8; 32]],
    ) -> Result<(TraceTable<BaseElement>, BaseElement), EpochProverError> {
        // Convert proof hashes to field elements (4 elements per hash)
        let inputs = hash_bytes_to_field_elements(proof_hashes);

        let trace_len = EpochProofAir::trace_length(proof_hashes.len());
        let mut trace = vec![vec![BaseElement::ZERO; trace_len]; EPOCH_TRACE_WIDTH];

        // Initialize Poseidon state
        let mut state = [BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO];

        let mut row = 0;
        let mut input_idx = 0;

        // Process each input element
        while row < trace_len {
            // Get input for this cycle (or zero for padding)
            let input = if input_idx < inputs.len() {
                inputs[input_idx]
            } else {
                BaseElement::ZERO
            };
            input_idx += 1;

            // Absorb input into state at the start of the cycle
            state[0] += input;

            // Run Poseidon rounds (first POSEIDON_ROUNDS steps of cycle)
            for step in 0..POSEIDON_ROUNDS {
                let r = row + step;
                if r >= trace_len {
                    break;
                }

                // Record state before round
                trace[COL_S0][r] = state[0];
                trace[COL_S1][r] = state[1];
                trace[COL_S2][r] = state[2];
                trace[COL_PROOF_INPUT][r] = if step == 0 { input } else { BaseElement::ZERO };
                trace[COL_ACCUMULATOR][r] = state[0];

                // Apply Poseidon round
                let t0 = state[0] + round_constant(step, 0);
                let t1 = state[1] + round_constant(step, 1);
                let t2 = state[2] + round_constant(step, 2);
                state = mds_mix(&[sbox(t0), sbox(t1), sbox(t2)]);
            }

            // Idle steps (remaining steps - copy state)
            for step in POSEIDON_ROUNDS..CYCLE_LENGTH {
                let r = row + step;
                if r >= trace_len {
                    break;
                }

                trace[COL_S0][r] = state[0];
                trace[COL_S1][r] = state[1];
                trace[COL_S2][r] = state[2];
                trace[COL_PROOF_INPUT][r] = BaseElement::ZERO;
                trace[COL_ACCUMULATOR][r] = state[0];
            }

            row += CYCLE_LENGTH;
        }

        Ok((TraceTable::init(trace), state[0])) // Final S0 is the proof accumulator
    }
}

impl Default for EpochProver {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert proof hashes to field elements.
///
/// Each 32-byte hash becomes 4 field elements (8 bytes each).
fn hash_bytes_to_field_elements(proof_hashes: &[[u8; 32]]) -> Vec<BaseElement> {
    let mut inputs = Vec::with_capacity(proof_hashes.len() * 4);
    for hash in proof_hashes {
        for chunk in hash.chunks(8) {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            let value = u64::from_le_bytes(buf);
            inputs.push(BaseElement::new(value));
        }
    }
    inputs
}

// ================================================================================================
// MOCK PROVER (for pallet integration testing)
// ================================================================================================

/// Mock epoch prover for pallet integration testing.
///
/// Returns a fixed proof that passes AcceptAllEpochProofs verifier.
/// Use this during development before the real prover is complete.
pub struct MockEpochProver;

impl MockEpochProver {
    /// Generate mock epoch proof.
    pub fn prove(epoch: &Epoch, proof_hashes: &[[u8; 32]]) -> Result<EpochProof, EpochProverError> {
        if proof_hashes.is_empty() {
            return Err(EpochProverError::EmptyEpoch);
        }

        Ok(EpochProof {
            proof_bytes: vec![0u8; 32], // Minimal mock proof
            epoch_commitment: epoch.commitment(),
            proof_accumulator: BaseElement::new(proof_hashes.len() as u64),
            num_proofs: proof_hashes.len() as u32,
        })
    }
}

// ================================================================================================
// PROOF OPTIONS
// ================================================================================================

/// Default proof options for epoch proofs.
pub fn default_epoch_options() -> ProofOptions {
    ProofOptions::new(
        8,  // num_queries
        16, // blowup_factor
        4,  // grinding_factor
        winterfell::FieldExtension::None,
        2,  // fri_folding_factor
        31, // fri_remainder_max_degree
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// Higher-soundness proof options for epoch proofs.
pub fn production_epoch_options() -> ProofOptions {
    ProofOptions::new(
        8,
        16,
        4,
        winterfell::FieldExtension::Quadratic,
        2,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// Fast proof options for testing (less secure).
pub fn fast_epoch_options() -> ProofOptions {
    ProofOptions::new(
        4,
        8,
        0,
        winterfell::FieldExtension::None,
        2,
        15,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

// ================================================================================================
// PROVER TRAIT IMPLEMENTATION
// ================================================================================================

impl Prover for EpochProver {
    type BaseField = BaseElement;
    type Air = EpochProofAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3;
    type VC = MerkleTree<Blake3>;
    type RandomCoin = DefaultRandomCoin<Blake3>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> EpochPublicInputs {
        // Return default - actual pub_inputs are set during prove_epoch
        // This is a limitation of the Prover trait design
        self.pub_inputs.clone().unwrap_or_default()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_trace_poly_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_trace_poly_columns,
            domain,
            partition_options,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Epoch;
    use winterfell::Trace;

    fn test_epoch() -> Epoch {
        let mut epoch = Epoch::new(0);
        epoch.proof_root = [1u8; 32];
        epoch.state_root = [2u8; 32];
        epoch.nullifier_set_root = [3u8; 32];
        epoch.commitment_tree_root = [4u8; 32];
        epoch
    }

    #[test]
    fn test_mock_prover() {
        let epoch = test_epoch();
        let hashes = vec![[1u8; 32], [2u8; 32]];

        let proof = MockEpochProver::prove(&epoch, &hashes).unwrap();
        assert_eq!(proof.epoch_commitment, epoch.commitment());
        assert_eq!(proof.num_proofs, 2);
    }

    #[test]
    fn test_mock_prover_empty_fails() {
        let epoch = test_epoch();
        let result = MockEpochProver::prove(&epoch, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_bytes_to_field_elements() {
        let hash = [0x01u8; 32];
        let elements = hash_bytes_to_field_elements(&[hash]);
        assert_eq!(elements.len(), 4);

        // Each chunk of 8 bytes should produce one field element
        let expected = u64::from_le_bytes([0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);
        assert_eq!(elements[0], BaseElement::new(expected));
    }

    #[test]
    fn test_trace_building() {
        let prover = EpochProver::with_fast_options();
        let hashes = vec![[1u8; 32], [2u8; 32]];

        let (trace, accumulator) = prover.build_trace(&hashes).unwrap();

        // 2 proofs × 4 elements = 8 cycles = 128 base rows → 512 padded
        assert_eq!(trace.length(), 512);
        assert_ne!(accumulator, BaseElement::ZERO);
    }

    #[test]
    fn test_trace_building_single_proof() {
        let prover = EpochProver::with_fast_options();
        let hashes = vec![[42u8; 32]];

        let (trace, accumulator) = prover.build_trace(&hashes).unwrap();

        // 1 proof × 4 elements = 4 cycles = 64 base rows → 256 padded
        assert_eq!(trace.length(), 256);
        assert_ne!(accumulator, BaseElement::ZERO);
    }

    #[test]
    fn test_trace_deterministic() {
        let prover = EpochProver::with_fast_options();
        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        let (_, acc1) = prover.build_trace(&hashes).unwrap();
        let (_, acc2) = prover.build_trace(&hashes).unwrap();

        assert_eq!(acc1, acc2);
    }

    #[test]
    #[ignore] // Slow test, run with --ignored
    fn test_full_proof_generation() {
        let prover = EpochProver::with_fast_options();
        let epoch = test_epoch();
        let hashes: Vec<[u8; 32]> = (0..10)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();

        let proof = prover.prove_epoch(&epoch, &hashes).unwrap();
        assert!(!proof.proof_bytes.is_empty());
        assert_eq!(proof.epoch_commitment, epoch.commitment());
        assert_eq!(proof.num_proofs, 10);
    }
}
