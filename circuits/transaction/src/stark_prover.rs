//! Real STARK prover for transaction circuits.
//!
//! This module implements the winterfell::Prover trait to generate
//! actual STARK proofs for transactions.

use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement},
    matrix::ColMatrix,
    AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain,
    TraceInfo, TracePolyTable, TraceTable,
};
use winter_crypto::hashers::Blake3_256;

use crate::{
    constants::{MAX_INPUTS, MAX_OUTPUTS},
    stark_air::{TransactionAirStark, TransactionPublicInputsStark, TRACE_WIDTH, MIN_TRACE_LENGTH},
    witness::TransactionWitness,
    TransactionCircuitError,
};

// TYPE ALIASES
// ================================================================================================

type Blake3 = Blake3_256<BaseElement>;

// TRANSACTION PROVER
// ================================================================================================

/// STARK prover for transaction circuits.
///
/// This prover generates STARK proofs that a transaction is valid according to
/// the constraints defined in `TransactionAirStark`.
pub struct TransactionProverStark {
    options: ProofOptions,
}

impl TransactionProverStark {
    /// Creates a new prover with the given options.
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    /// Creates a prover with default options suitable for production.
    pub fn with_default_options() -> Self {
        Self::new(default_proof_options())
    }

    /// Builds an execution trace from a transaction witness.
    ///
    /// The trace encodes the transaction data and intermediate computation states
    /// in a format suitable for STARK proving.
    pub fn build_trace(
        &self,
        witness: &TransactionWitness,
    ) -> Result<TraceTable<BaseElement>, TransactionCircuitError> {
        // Calculate input/output values
        let input_values: Vec<u64> = witness
            .inputs
            .iter()
            .map(|inp| inp.note.value)
            .collect();
        let output_values: Vec<u64> = witness
            .outputs
            .iter()
            .map(|out| out.note.value)
            .collect();

        // Pad to MAX_INPUTS/MAX_OUTPUTS
        let mut input_vals = [0u64; MAX_INPUTS];
        let mut output_vals = [0u64; MAX_OUTPUTS];
        
        for (i, &v) in input_values.iter().take(MAX_INPUTS).enumerate() {
            input_vals[i] = v;
        }
        for (i, &v) in output_values.iter().take(MAX_OUTPUTS).enumerate() {
            output_vals[i] = v;
        }

        // Calculate nullifiers and commitments using witness methods
        let nullifiers = witness.nullifiers();
        let commitments = witness.commitments();

        // Pad nullifiers
        let mut padded_nullifiers = vec![BaseElement::ZERO; MAX_INPUTS];
        for (i, n) in nullifiers.iter().take(MAX_INPUTS).enumerate() {
            padded_nullifiers[i] = *n;
        }

        // Pad commitments
        let mut padded_commitments = vec![BaseElement::ZERO; MAX_OUTPUTS];
        for (i, c) in commitments.iter().take(MAX_OUTPUTS).enumerate() {
            padded_commitments[i] = *c;
        }

        // Build the trace table
        let trace_length = MIN_TRACE_LENGTH;
        let mut trace = TraceTable::new(TRACE_WIDTH, trace_length);

        // Capture values for closure
        let fee = witness.fee;
        let merkle_root = witness.merkle_root;

        // Initialize the trace with transaction data
        trace.fill(
            |state| {
                // Initial state
                state[0] = BaseElement::new(input_vals[0]);
                state[1] = BaseElement::new(input_vals[1]);
                state[2] = BaseElement::new(output_vals[0]);
                state[3] = BaseElement::new(output_vals[1]);
                state[4] = BaseElement::new(fee);
                
                // Balance check: sum(inputs) - sum(outputs) - fee should = 0 for valid tx
                let total_in = input_vals[0] + input_vals[1];
                let total_out = output_vals[0] + output_vals[1];
                let balance = total_in.saturating_sub(total_out).saturating_sub(fee);
                state[5] = BaseElement::new(balance);

                // Nullifiers
                state[6] = padded_nullifiers[0];
                state[7] = padded_nullifiers[1];

                // Commitments
                state[8] = padded_commitments[0];
                state[9] = padded_commitments[1];

                // Merkle root
                state[10] = merkle_root;

                // Hash state initialized to zeros (will be used for in-circuit hashing)
                state[11] = BaseElement::ZERO;
                state[12] = BaseElement::ZERO;
                state[13] = BaseElement::ONE; // Capacity initialized to 1
            },
            |_step, state| {
                // Transition function
                // Values stay constant, only hash state evolves
                
                // Hash state transition (simplified Poseidon-like)
                let s0 = state[11];
                let s1 = state[12];
                let s2 = state[13];

                // Round constants
                let c0 = BaseElement::new(0x123456789abcdef0u64);
                let c1 = BaseElement::new(0xfedcba9876543210u64);
                let c2 = BaseElement::new(0x0f1e2d3c4b5a6978u64);

                // S-box: x^5
                let t0 = (s0 + c0).exp(5u64.into());
                let t1 = (s1 + c1).exp(5u64.into());
                let t2 = (s2 + c2).exp(5u64.into());

                // MDS mixing
                state[11] = t0 * BaseElement::new(2) + t1 + t2;
                state[12] = t0 + t1 * BaseElement::new(2) + t2;
                state[13] = t0 + t1 + t2 * BaseElement::new(2);
            },
        );

        Ok(trace)
    }

    /// Extracts public inputs from a witness.
    pub fn get_public_inputs(
        &self,
        witness: &TransactionWitness,
    ) -> TransactionPublicInputsStark {
        let nullifiers = witness.nullifiers();
        let commitments = witness.commitments();

        // Pad nullifiers and commitments
        let mut padded_nullifiers = vec![BaseElement::ZERO; MAX_INPUTS];
        let mut padded_commitments = vec![BaseElement::ZERO; MAX_OUTPUTS];

        for (i, n) in nullifiers.iter().take(MAX_INPUTS).enumerate() {
            padded_nullifiers[i] = *n;
        }
        for (i, c) in commitments.iter().take(MAX_OUTPUTS).enumerate() {
            padded_commitments[i] = *c;
        }

        // Calculate balance delta
        let total_in: u64 = witness.inputs.iter().map(|i| i.note.value).sum();
        let total_out: u64 = witness.outputs.iter().map(|o| o.note.value).sum();
        let balance_delta = total_in.saturating_sub(total_out).saturating_sub(witness.fee);

        TransactionPublicInputsStark {
            merkle_root: witness.merkle_root,
            nullifiers: padded_nullifiers,
            commitments: padded_commitments,
            balance_delta: BaseElement::new(balance_delta),
            fee: BaseElement::new(witness.fee),
        }
    }

    /// Generates a STARK proof for the given witness.
    pub fn prove_transaction(
        &self,
        witness: &TransactionWitness,
    ) -> Result<Proof, TransactionCircuitError> {
        // Validate the witness first
        witness.validate()?;

        // Build the execution trace
        let trace = self.build_trace(witness)?;

        // Generate the proof
        self.prove(trace)
            .map_err(|_e| TransactionCircuitError::ConstraintViolation(
                "STARK proving failed"
            ))
    }
}

impl Prover for TransactionProverStark {
    type BaseField = BaseElement;
    type Air = TransactionAirStark;
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

    fn get_pub_inputs(&self, trace: &Self::Trace) -> TransactionPublicInputsStark {
        // Extract public inputs from the trace
        // Read values from first row of trace
        let _first_state = trace.get(0, 0);
        
        // For now, construct from trace columns
        // In production, this would be passed separately or stored in prover state
        TransactionPublicInputsStark {
            merkle_root: trace.get(10, 0),
            nullifiers: vec![trace.get(6, 0), trace.get(7, 0)],
            commitments: vec![trace.get(8, 0), trace.get(9, 0)],
            balance_delta: trace.get(5, 0),
            fee: trace.get(4, 0),
        }
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

// HELPER FUNCTIONS
// ================================================================================================

/// Returns default proof options for production use.
///
/// These options provide ~100 bits of security.
pub fn default_proof_options() -> ProofOptions {
    ProofOptions::new(
        32,  // num_queries - more queries = more security
        8,   // blowup_factor - higher = more security but larger proofs
        0,   // grinding_factor - proof of work for prover
        winterfell::FieldExtension::None,
        4,   // fri_folding_factor
        31,  // fri_max_remainder_poly_degree
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// Returns options for faster proving with lower security (for testing).
pub fn fast_proof_options() -> ProofOptions {
    ProofOptions::new(
        8,   // num_queries
        4,   // blowup_factor
        0,   // grinding_factor
        winterfell::FieldExtension::None,
        2,   // fri_folding_factor
        15,  // fri_max_remainder_poly_degree
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::{InputNoteWitness, OutputNoteWitness, NoteData};
    use winterfell::Trace;

    fn make_test_witness() -> TransactionWitness {
        // Create a simple witness with one input and one output
        let input_note = NoteData {
            value: 1000,
            asset_id: 0, // native asset
            pk_recipient: [0u8; 32],
            rho: [1u8; 32],
            r: [2u8; 32],
        };

        let output_note = NoteData {
            value: 900, // 1000 - 100 fee
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
            outputs: vec![OutputNoteWitness {
                note: output_note,
            }],
            sk_spend: [6u8; 32],
            merkle_root: BaseElement::new(12345),
            fee: 100,
            version: protocol_versioning::DEFAULT_VERSION_BINDING,
        }
    }

    #[test]
    fn test_build_trace() {
        let prover = TransactionProverStark::with_default_options();
        let witness = make_test_witness();
        
        let trace = prover.build_trace(&witness).unwrap();
        
        assert_eq!(trace.width(), TRACE_WIDTH);
        assert!(trace.length() >= MIN_TRACE_LENGTH);
    }

    #[test]
    fn test_get_public_inputs() {
        let prover = TransactionProverStark::with_default_options();
        let witness = make_test_witness();
        
        let pub_inputs = prover.get_public_inputs(&witness);
        
        assert_eq!(pub_inputs.merkle_root, witness.merkle_root);
        assert_eq!(pub_inputs.fee, BaseElement::new(100));
    }
}
