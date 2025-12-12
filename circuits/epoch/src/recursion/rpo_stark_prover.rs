//! Full STARK prover using RPO-based Fiat-Shamir.
//!
//! This module implements a winterfell `Prover` that uses miden-crypto's
//! `Rpo256` for hashing and `RpoRandomCoin` for Fiat-Shamir challenges.
//!
//! ## Key Benefits
//!
//! - **Recursive-friendly**: RPO hash can be efficiently verified in-circuit
//! - **Quantum-safe**: No elliptic curves, pure algebraic hash
//! - **Compatible**: Uses winterfell's standard Prover trait
//!
//! ## Usage
//!
//! ```rust,ignore
//! use epoch_circuit::recursion::rpo_stark_prover::RpoStarkProver;
//!
//! let prover = RpoStarkProver::new(options);
//! let trace = build_trace();
//! let proof = prover.prove(trace).expect("proof generation failed");
//! ```

use miden_crypto::hash::rpo::Rpo256;
use miden_crypto::rand::RpoRandomCoin;
use winter_air::{ProofOptions, TraceInfo};
use winter_crypto::MerkleTree;
use winter_math::FieldElement;
use winterfell::{
    matrix::ColMatrix,
    math::fields::f64::BaseElement,
    AuxRandElements, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions, Prover, StarkDomain,
    TracePolyTable, TraceTable, CompositionPoly, CompositionPolyTrace,
    Proof, AcceptableOptions, verify,
};

use super::rpo_air::{RpoAir, RpoPublicInputs, STATE_WIDTH, NUM_ROUNDS, TRACE_WIDTH, ROWS_PER_PERMUTATION};
use super::rpo_proof::RpoProofOptions;

// Type aliases for RPO-based STARK components
type RpoMerkleTree = MerkleTree<Rpo256>;

/// STARK prover using RPO hash for Fiat-Shamir.
///
/// This prover generates STARK proofs where all Fiat-Shamir challenges
/// are derived using RPO, making the proofs efficient to verify in-circuit.
pub struct RpoStarkProver {
    options: ProofOptions,
}

impl RpoStarkProver {
    /// Create new RPO STARK prover with given options.
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    /// Create prover from RpoProofOptions.
    pub fn from_rpo_options(opts: &RpoProofOptions) -> Self {
        Self {
            options: opts.to_winter_options(),
        }
    }

    /// Create prover with fast (testing) options.
    pub fn fast() -> Self {
        Self::from_rpo_options(&RpoProofOptions::fast())
    }

    /// Create prover with production options.
    pub fn production() -> Self {
        Self::from_rpo_options(&RpoProofOptions::production())
    }

    /// Build an execution trace for an RPO permutation.
    pub fn build_trace(&self, input_state: [BaseElement; STATE_WIDTH]) -> TraceTable<BaseElement> {
        let mut trace = TraceTable::new(TRACE_WIDTH, ROWS_PER_PERMUTATION);

        // Row 0: Initial state (input)
        for (col, &val) in input_state.iter().enumerate() {
            trace.set(col, 0, val);
        }
        trace.set(STATE_WIDTH, 0, BaseElement::ZERO); // Round counter

        // Initialize state
        let mut state: [BaseElement; STATE_WIDTH] = input_state;

        // Execute 7 rounds, each with 2 half-rounds
        for round in 0..NUM_ROUNDS {
            // First half-round: MDS → add ARK1 → forward S-box (x^7)
            apply_mds(&mut state);
            add_constants(&mut state, round, true);
            apply_sbox(&mut state);

            let row = 1 + round * 2;
            for (col, &val) in state.iter().enumerate() {
                trace.set(col, row, val);
            }
            trace.set(STATE_WIDTH, row, BaseElement::new((round * 2 + 1) as u64));

            // Second half-round: MDS → add ARK2 → inverse S-box
            apply_mds(&mut state);
            add_constants(&mut state, round, false);
            apply_inv_sbox(&mut state);

            let row = 2 + round * 2;
            if row < ROWS_PER_PERMUTATION {
                for (col, &val) in state.iter().enumerate() {
                    trace.set(col, row, val);
                }
                trace.set(STATE_WIDTH, row, BaseElement::new((round * 2 + 2) as u64));
            }
        }

        // Row 15: padding (copy of final output)
        for (col, &val) in state.iter().enumerate() {
            trace.set(col, 15, val);
        }
        trace.set(STATE_WIDTH, 15, BaseElement::new(15));

        trace
    }

    /// Compute the output state after RPO permutation.
    pub fn compute_output(&self, input_state: [BaseElement; STATE_WIDTH]) -> [BaseElement; STATE_WIDTH] {
        let mut state = input_state;

        for round in 0..NUM_ROUNDS {
            // First half-round
            apply_mds(&mut state);
            add_constants(&mut state, round, true);
            apply_sbox(&mut state);

            // Second half-round
            apply_mds(&mut state);
            add_constants(&mut state, round, false);
            apply_inv_sbox(&mut state);
        }

        state
    }

    /// Generate a STARK proof for an RPO permutation.
    ///
    /// Returns the proof bytes and public inputs.
    pub fn prove_rpo_permutation(
        &self,
        input_state: [BaseElement; STATE_WIDTH],
    ) -> Result<(Proof, RpoPublicInputs), String> {
        let trace = self.build_trace(input_state);
        let pub_inputs = self.get_pub_inputs(&trace);
        
        let proof = self.prove(trace)
            .map_err(|e| format!("Proof generation failed: {:?}", e))?;
        
        Ok((proof, pub_inputs))
    }
}

impl Prover for RpoStarkProver {
    type BaseField = BaseElement;
    type Air = RpoAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Rpo256;
    type VC = RpoMerkleTree;
    type RandomCoin = RpoRandomCoin;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> RpoPublicInputs {
        // Extract input state from first row
        let mut input_state = [BaseElement::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            input_state[i] = trace.get(i, 0);
        }

        // Compute expected output
        let output_state = self.compute_output(input_state);

        RpoPublicInputs::new(input_state, output_state)
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
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

// ============================================================================
// HELPER FUNCTIONS (duplicated from rpo_air.rs to avoid circular deps)
// ============================================================================

use super::rpo_air::{MDS, ARK1, ARK2, ALPHA, INV_ALPHA};

/// Apply MDS matrix multiplication to state
fn apply_mds(state: &mut [BaseElement; STATE_WIDTH]) {
    let mut result = [BaseElement::ZERO; STATE_WIDTH];

    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            result[i] += MDS[i][j] * state[j];
        }
    }

    *state = result;
}

/// Add round constants to state
fn add_constants(state: &mut [BaseElement; STATE_WIDTH], round: usize, first_half: bool) {
    let constants = if first_half { &ARK1[round] } else { &ARK2[round] };
    for i in 0..STATE_WIDTH {
        state[i] += constants[i];
    }
}

/// Apply forward S-box (x^7) to state
fn apply_sbox(state: &mut [BaseElement; STATE_WIDTH]) {
    for i in 0..STATE_WIDTH {
        state[i] = state[i].exp(ALPHA.into());
    }
}

/// Apply inverse S-box (x^{INV_ALPHA}) to state
fn apply_inv_sbox(state: &mut [BaseElement; STATE_WIDTH]) {
    for i in 0..STATE_WIDTH {
        state[i] = state[i].exp(INV_ALPHA.into());
    }
}

// ============================================================================
// VERIFICATION
// ============================================================================

/// Verify a STARK proof using RPO-based Fiat-Shamir.
pub fn verify_rpo_proof(
    proof: &Proof,
    pub_inputs: &RpoPublicInputs,
    acceptable_options: &AcceptableOptions,
) -> Result<(), String> {
    verify::<RpoAir, Rpo256, RpoRandomCoin, RpoMerkleTree>(
        proof.clone(),
        pub_inputs.clone(),
        acceptable_options,
    )
    .map_err(|e| format!("Verification failed: {:?}", e))
}

/// Create default acceptable options for verification.
pub fn default_acceptable_options() -> AcceptableOptions {
    AcceptableOptions::OptionSet(vec![
        RpoProofOptions::fast().to_winter_options(),
        RpoProofOptions::production().to_winter_options(),
    ])
}

/// Prove an RPO permutation and return the proof.
pub fn prove_epoch_with_rpo(
    input_state: [BaseElement; STATE_WIDTH],
    options: &RpoProofOptions,
) -> Result<(Proof, RpoPublicInputs), String> {
    let prover = RpoStarkProver::from_rpo_options(options);
    let trace = prover.build_trace(input_state);
    let pub_inputs = prover.get_pub_inputs(&trace);
    
    let proof = prover.prove(trace)
        .map_err(|e| format!("Proof generation failed: {:?}", e))?;
    
    Ok((proof, pub_inputs))
}

/// Verify an RPO STARK proof.
pub fn verify_epoch_with_rpo(
    proof: &Proof,
    pub_inputs: &RpoPublicInputs,
) -> Result<(), String> {
    let acceptable = default_acceptable_options();
    verify_rpo_proof(proof, pub_inputs, &acceptable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::Trace;

    #[test]
    fn test_rpo_stark_prover_creation() {
        let prover = RpoStarkProver::fast();
        assert_eq!(prover.options.blowup_factor(), 32);
    }

    #[test]
    fn test_rpo_trace_generation() {
        let prover = RpoStarkProver::fast();
        let input = [BaseElement::new(1); STATE_WIDTH];
        
        let trace = prover.build_trace(input);
        
        assert_eq!(trace.length(), ROWS_PER_PERMUTATION);
        assert_eq!(trace.width(), TRACE_WIDTH);
    }

    #[test]
    fn test_rpo_compute_output_deterministic() {
        let prover = RpoStarkProver::fast();
        let input = [BaseElement::new(42); STATE_WIDTH];
        
        let output1 = prover.compute_output(input);
        let output2 = prover.compute_output(input);
        
        assert_eq!(output1, output2);
    }

    #[test]
    fn test_rpo_stark_proof_generation() {
        let prover = RpoStarkProver::fast();
        let input = [BaseElement::new(1); STATE_WIDTH];
        
        let (proof, pub_inputs) = prover.prove_rpo_permutation(input)
            .expect("Proof generation should succeed");
        
        // Verify proof is non-empty
        assert!(!proof.to_bytes().is_empty());
        
        // Verify public inputs are correct
        assert_eq!(pub_inputs.input_state, input);
    }

    #[test]
    fn test_rpo_stark_proof_verification() {
        let prover = RpoStarkProver::fast();
        let input = [BaseElement::new(123); STATE_WIDTH];
        
        let (proof, pub_inputs) = prover.prove_rpo_permutation(input)
            .expect("Proof generation should succeed");
        
        // Verify the proof
        verify_epoch_with_rpo(&proof, &pub_inputs)
            .expect("Proof verification should succeed");
    }

    #[test]
    fn test_rpo_stark_proof_fails_with_wrong_inputs() {
        let prover = RpoStarkProver::fast();
        let input = [BaseElement::new(1); STATE_WIDTH];
        
        let (proof, mut pub_inputs) = prover.prove_rpo_permutation(input)
            .expect("Proof generation should succeed");
        
        // Corrupt the public inputs
        pub_inputs.output_state[0] += BaseElement::ONE;
        
        // Verification should fail
        let result = verify_epoch_with_rpo(&proof, &pub_inputs);
        assert!(result.is_err(), "Verification should fail with corrupted inputs");
    }

    #[test]
    fn test_rpo_stark_multiple_proofs() {
        let prover = RpoStarkProver::fast();
        
        // Generate proofs for different inputs
        for i in 0..3 {
            let mut input = [BaseElement::ZERO; STATE_WIDTH];
            input[0] = BaseElement::new(i as u64);
            
            let (proof, pub_inputs) = prover.prove_rpo_permutation(input)
                .expect("Proof generation should succeed");
            
            verify_epoch_with_rpo(&proof, &pub_inputs)
                .expect("Proof verification should succeed");
        }
    }
}
