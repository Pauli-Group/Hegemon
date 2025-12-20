//! Batch transaction prover for STARK proofs.
//!
//! This module builds traces for multiple transactions and generates
//! batch proofs covering all transactions together.

use winter_crypto::hashers::Blake3_256;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement},
    matrix::ColMatrix,
    AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, Trace, TraceInfo,
    TracePolyTable, TraceTable,
};

use crate::air::BatchTransactionAir;
use crate::error::BatchCircuitError;
use crate::public_inputs::{BatchPublicInputs, MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::dimensions::{
    batch_trace_rows, slot_start_row, validate_batch_size, ROWS_PER_TX, TRACE_WIDTH,
};
use transaction_circuit::hashing::{bytes32_to_felts, nullifier, prf_key};
use transaction_circuit::stark_air::COL_S0;
use transaction_circuit::{TransactionProverStark, TransactionWitness};

type Blake3 = Blake3_256<BaseElement>;

/// Batch transaction prover.
///
/// Builds traces for multiple transactions and generates a single
/// STARK proof covering all transactions.
pub struct BatchTransactionProver {
    options: ProofOptions,
    pub_inputs: Option<BatchPublicInputs>,
}

impl BatchTransactionProver {
    /// Create a new batch prover with the given options.
    pub fn new(options: ProofOptions) -> Self {
        Self {
            options,
            pub_inputs: None,
        }
    }

    /// Create a new batch prover with default options.
    pub fn with_default_options() -> Self {
        Self::new(default_batch_options())
    }

    /// Create a new batch prover with fast (less secure) options for testing.
    pub fn with_fast_options() -> Self {
        Self::new(fast_batch_options())
    }

    /// Build batch trace from multiple transaction witnesses.
    ///
    /// The trace layout places each transaction's trace sequentially:
    /// ```text
    /// [TX0 trace (2048 rows)] [TX1 trace (2048 rows)] ... [TXN-1 trace (2048 rows)] [padding]
    /// ```
    pub fn build_trace(
        &self,
        witnesses: &[TransactionWitness],
    ) -> Result<TraceTable<BaseElement>, BatchCircuitError> {
        let batch_size = witnesses.len();
        validate_batch_size(batch_size)
            .map_err(|_| BatchCircuitError::InvalidBatchSize(batch_size))?;

        if batch_size == 0 {
            return Err(BatchCircuitError::EmptyBatch);
        }

        // Validate all witnesses have the same anchor
        let anchor = witnesses[0].merkle_root;
        for witness in witnesses.iter().skip(1) {
            if witness.merkle_root != anchor {
                return Err(BatchCircuitError::AnchorMismatch);
            }
        }

        // Validate all witnesses
        for (idx, witness) in witnesses.iter().enumerate() {
            witness
                .validate()
                .map_err(|e| BatchCircuitError::InvalidWitness {
                    index: idx,
                    reason: e.to_string(),
                })?;
        }

        let trace_len = batch_trace_rows(batch_size);
        let mut trace = vec![vec![BaseElement::ZERO; trace_len]; TRACE_WIDTH];

        // Build trace for each transaction using the single-transaction prover
        let single_prover = TransactionProverStark::with_default_options();

        for (tx_idx, witness) in witnesses.iter().enumerate() {
            let single_trace = single_prover
                .build_trace(witness)
                .map_err(|e| BatchCircuitError::TraceBuildError(format!("TX {}: {}", tx_idx, e)))?;

            // Copy into batch trace at appropriate offset
            let offset = slot_start_row(tx_idx);
            for (col, column) in trace.iter_mut().enumerate() {
                for row in 0..ROWS_PER_TX {
                    if row < single_trace.length() {
                        column[offset + row] = single_trace.get(col, row);
                    }
                }
            }
        }

        // Fill remaining rows with valid Poseidon hash cycles (padding)
        // This ensures the entire trace satisfies the AIR constraints
        let used_rows = batch_size * ROWS_PER_TX;
        if used_rows < trace_len {
            fill_padding_rows(&mut trace, used_rows, trace_len);
        }

        Ok(TraceTable::init(trace))
    }

    /// Extract public inputs from witnesses.
    pub fn extract_public_inputs(
        &self,
        witnesses: &[TransactionWitness],
    ) -> Result<BatchPublicInputs, BatchCircuitError> {
        let batch_size = witnesses.len();
        validate_batch_size(batch_size)
            .map_err(|_| BatchCircuitError::InvalidBatchSize(batch_size))?;

        if batch_size == 0 {
            return Err(BatchCircuitError::EmptyBatch);
        }

        // All transactions must use the same anchor
        let anchor = witnesses[0].merkle_root;
        for witness in witnesses.iter().skip(1) {
            if witness.merkle_root != anchor {
                return Err(BatchCircuitError::AnchorMismatch);
            }
        }

        let anchor = bytes32_to_felts(&anchor)
            .ok_or(BatchCircuitError::InvalidPublicInputs("anchor not canonical".into()))?;

        // Collect all nullifiers and commitments
        let mut nullifiers = Vec::with_capacity(batch_size * MAX_INPUTS);
        let mut commitments = Vec::with_capacity(batch_size * MAX_OUTPUTS);
        let mut total_fee = 0u64;

        for witness in witnesses {
            let prf = prf_key(&witness.sk_spend);

            // Add nullifiers for this transaction
            for (i, input) in witness.inputs.iter().enumerate() {
                if i < MAX_INPUTS {
                    nullifiers.push(nullifier(prf, &input.note.rho, input.position));
                }
            }
            // Pad with zeros if needed
            for _ in witness.inputs.len()..MAX_INPUTS {
                nullifiers.push([BaseElement::ZERO; 4]);
            }

            // Add commitments for this transaction
            for (i, output) in witness.outputs.iter().enumerate() {
                if i < MAX_OUTPUTS {
                    commitments.push(output.note.commitment());
                }
            }
            // Pad with zeros if needed
            for _ in witness.outputs.len()..MAX_OUTPUTS {
                commitments.push([BaseElement::ZERO; 4]);
            }

            total_fee += witness.fee;
        }

        Ok(BatchPublicInputs::new(
            batch_size as u32,
            anchor,
            nullifiers,
            commitments,
            BaseElement::new(total_fee),
        ))
    }

    /// Generate a batch proof for multiple transactions.
    pub fn prove_batch(
        &mut self,
        witnesses: &[TransactionWitness],
    ) -> Result<(Proof, BatchPublicInputs), BatchCircuitError> {
        let trace = self.build_trace(witnesses)?;
        let pub_inputs = self.extract_public_inputs(witnesses)?;

        // Store pub inputs so Prover::get_pub_inputs can feed AirContext assertions.
        self.pub_inputs = Some(pub_inputs.clone());
        let proof = self
            .prove(trace)
            .map_err(|e| BatchCircuitError::ProofGenerationError(format!("{:?}", e)))?;
        self.pub_inputs = None;

        Ok((proof, pub_inputs))
    }
}

/// Fill padding rows with valid Poseidon hash cycles.
///
/// This ensures the entire trace satisfies the AIR constraints,
/// even in the padding region.
fn fill_padding_rows(trace: &mut [Vec<BaseElement>], start_row: usize, end_row: usize) {
    use transaction_circuit::stark_air::{
        mds_mix, round_constant, sbox, COL_S1, COL_S2, CYCLE_LENGTH,
    };

    const POSEIDON_ROUNDS: usize = 8;

    let mut state = [BaseElement::ZERO, BaseElement::ZERO, BaseElement::ONE];

    let mut row = start_row;
    while row < end_row {
        // Process one cycle (16 rows)

        // Hash rounds (first 8 steps)
        for step in 0..POSEIDON_ROUNDS {
            let r = row + step;
            if r >= end_row {
                break;
            }

            trace[COL_S0][r] = state[0];
            trace[COL_S1][r] = state[1];
            trace[COL_S2][r] = state[2];

            // Apply Poseidon round
            let t0 = state[0] + round_constant(step, 0);
            let t1 = state[1] + round_constant(step, 1);
            let t2 = state[2] + round_constant(step, 2);
            state = mds_mix(&[sbox(t0), sbox(t1), sbox(t2)]);
        }

        // Copy steps (remaining steps)
        for step in POSEIDON_ROUNDS..CYCLE_LENGTH {
            let r = row + step;
            if r >= end_row {
                break;
            }

            trace[COL_S0][r] = state[0];
            trace[COL_S1][r] = state[1];
            trace[COL_S2][r] = state[2];
        }

        row += CYCLE_LENGTH;
    }
}

impl Prover for BatchTransactionProver {
    type BaseField = BaseElement;
    type Air = BatchTransactionAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> BatchPublicInputs {
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

/// Default proof options for batch proofs.
pub fn default_batch_options() -> ProofOptions {
    ProofOptions::new(
        32,
        8,
        0,
        winterfell::FieldExtension::None,
        4,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// Fast proof options for testing (less secure).
pub fn fast_batch_options() -> ProofOptions {
    ProofOptions::new(
        8,
        16,
        0,
        winterfell::FieldExtension::None,
        2,
        15,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_prover_creation() {
        let prover = BatchTransactionProver::with_default_options();
        assert_eq!(prover.options().num_queries(), 32);
    }

    #[test]
    fn test_fast_options() {
        let prover = BatchTransactionProver::with_fast_options();
        assert_eq!(prover.options().num_queries(), 8);
    }
}
