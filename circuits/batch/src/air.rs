//! Batch transaction AIR (Algebraic Intermediate Representation).
//!
//! This module implements the STARK AIR for batch transaction proofs.
//! It extends the single-transaction AIR pattern to process N transactions
//! sequentially in one larger trace.

use winterfell::{
    math::{fields::f64::BaseElement, FieldElement},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use crate::public_inputs::BatchPublicInputs;
use transaction_circuit::dimensions::{
    batch_trace_rows, commitment_output_row, merkle_root_output_row, nullifier_output_row,
};
use transaction_circuit::stark_air::{
    round_constant, COL_OUT0, COL_OUT1, COL_S0, COL_S1, COL_S2, CYCLE_LENGTH,
};

fn is_zero_hash(value: &[BaseElement; 4]) -> bool {
    value.iter().all(|elem| *elem == BaseElement::ZERO)
}

/// Number of Poseidon rounds per cycle.
pub const POSEIDON_ROUNDS: usize = 8;

/// Batch transaction AIR - proves N transactions in one trace.
///
/// The trace layout is:
/// ```text
/// Transaction 0:  [nullifier_0 | merkle_0 | commitment_0]  (2048 rows)
/// Transaction 1:  [nullifier_1 | merkle_1 | commitment_1]  (2048 rows)
/// ...
/// Transaction N-1: [nullifier_{N-1} | merkle_{N-1} | commitment_{N-1}]
/// (Padding to power of 2)
/// ```
///
/// Each transaction slot uses the same 5-column layout as the single-transaction AIR:
/// - Columns 0-2: Poseidon state (S0, S1, S2)
/// - Column 3: Merkle sibling values
/// - Column 4: Value accumulator
pub struct BatchTransactionAir {
    context: AirContext<BaseElement>,
    pub_inputs: BatchPublicInputs,
}

impl BatchTransactionAir {
    /// Calculate trace length for given batch size.
    pub fn trace_length(batch_size: usize) -> usize {
        batch_trace_rows(batch_size)
    }

    /// Get the batch size.
    pub fn batch_size(&self) -> usize {
        self.pub_inputs.batch_size as usize
    }
}

impl Air for BatchTransactionAir {
    type BaseField = BaseElement;
    type PublicInputs = BatchPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Same constraint degrees as single transaction (Poseidon x^5)
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
        ];

        // Count assertions:
        // For each transaction: up to 2 nullifiers + 2 Merkle roots + 2 commitments
        let batch_size = pub_inputs.batch_size as usize;
        let mut num_assertions = 0;

        for tx_idx in 0..batch_size {
            // Count nullifier assertions
            for nf_idx in 0..2 {
                let pub_idx = tx_idx * 2 + nf_idx;
                if pub_idx < pub_inputs.nullifiers.len() {
                    let nf = pub_inputs.nullifiers[pub_idx];
                    if !is_zero_hash(&nf) {
                        num_assertions += 4; // Nullifier output
                        num_assertions += 4; // Merkle root
                    }
                }
            }

            // Count commitment assertions
            for cm_idx in 0..2 {
                let pub_idx = tx_idx * 2 + cm_idx;
                if pub_idx < pub_inputs.commitments.len() {
                    let cm = pub_inputs.commitments[pub_idx];
                    if !is_zero_hash(&cm) {
                        num_assertions += 4;
                    }
                }
            }
        }

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    /// Evaluate Poseidon round constraints.
    ///
    /// These are identical to the single-transaction AIR constraints.
    /// When hash_flag=1: next = MDS(S-box(current + round_constant))
    /// When hash_flag=0: no constraint (allows state change at cycle boundaries)
    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // Periodic values: [hash_flag, rc0, rc1, rc2]
        let hash_flag = periodic_values[0];
        let rc0 = periodic_values[1];
        let rc1 = periodic_values[2];
        let rc2 = periodic_values[3];

        // Compute Poseidon round result
        let t0 = current[COL_S0] + rc0;
        let t1 = current[COL_S1] + rc1;
        let t2 = current[COL_S2] + rc2;

        // S-box: x^5
        let s0 = t0.exp(5u64.into());
        let s1 = t1.exp(5u64.into());
        let s2 = t2.exp(5u64.into());

        // MDS mixing: [[2,1,1],[1,2,1],[1,1,2]]
        let two: E = E::from(BaseElement::new(2));
        let hash_s0 = s0 * two + s1 + s2;
        let hash_s1 = s0 + s1 * two + s2;
        let hash_s2 = s0 + s1 + s2 * two;

        // Constraint: hash_flag * (next - hash_result) = 0
        result[0] = hash_flag * (next[COL_S0] - hash_s0);
        result[1] = hash_flag * (next[COL_S1] - hash_s1);
        result[2] = hash_flag * (next[COL_S2] - hash_s2);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();
        let batch_size = self.pub_inputs.batch_size as usize;
        let trace_len = self.context.trace_len();

        for tx_idx in 0..batch_size {
            // Nullifier and Merkle root assertions
            for nf_idx in 0..2 {
                let pub_idx = tx_idx * 2 + nf_idx;
                if pub_idx < self.pub_inputs.nullifiers.len() {
                    let nf = self.pub_inputs.nullifiers[pub_idx];
                    if !is_zero_hash(&nf) {
                        // Nullifier hash output
                        let nf_row = nullifier_output_row(tx_idx, nf_idx);
                        if nf_row < trace_len {
                            assertions.push(Assertion::single(COL_OUT0, nf_row, nf[0]));
                            assertions.push(Assertion::single(COL_OUT1, nf_row, nf[1]));
                            assertions.push(Assertion::single(COL_S0, nf_row, nf[2]));
                            assertions.push(Assertion::single(COL_S1, nf_row, nf[3]));
                        }

                        // Merkle root output (must match shared anchor)
                        let merkle_row = merkle_root_output_row(tx_idx, nf_idx);
                        if merkle_row < trace_len {
                            assertions.push(Assertion::single(
                                COL_OUT0,
                                merkle_row,
                                self.pub_inputs.anchor[0],
                            ));
                            assertions.push(Assertion::single(
                                COL_OUT1,
                                merkle_row,
                                self.pub_inputs.anchor[1],
                            ));
                            assertions.push(Assertion::single(
                                COL_S0,
                                merkle_row,
                                self.pub_inputs.anchor[2],
                            ));
                            assertions.push(Assertion::single(
                                COL_S1,
                                merkle_row,
                                self.pub_inputs.anchor[3],
                            ));
                        }
                    }
                }
            }

            // Commitment assertions
            for cm_idx in 0..2 {
                let pub_idx = tx_idx * 2 + cm_idx;
                if pub_idx < self.pub_inputs.commitments.len() {
                    let cm = self.pub_inputs.commitments[pub_idx];
                    if !is_zero_hash(&cm) {
                        let cm_row = commitment_output_row(tx_idx, cm_idx);
                        if cm_row < trace_len {
                            assertions.push(Assertion::single(COL_OUT0, cm_row, cm[0]));
                            assertions.push(Assertion::single(COL_OUT1, cm_row, cm[1]));
                            assertions.push(Assertion::single(COL_S0, cm_row, cm[2]));
                            assertions.push(Assertion::single(COL_S1, cm_row, cm[3]));
                        }
                    }
                }
            }
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut result = vec![make_hash_mask()];

        // Round constants for each position
        for pos in 0..3 {
            let mut column = Vec::with_capacity(CYCLE_LENGTH);
            for step in 0..CYCLE_LENGTH {
                if step < POSEIDON_ROUNDS {
                    column.push(round_constant(step, pos));
                } else {
                    column.push(BaseElement::ZERO);
                }
            }
            result.push(column);
        }

        result
    }
}

/// Create the hash mask periodic column.
/// 1 for hash rounds (steps 0-7), 0 for copy steps (steps 8-15).
fn make_hash_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
    for value in mask.iter_mut().take(POSEIDON_ROUNDS) {
        *value = BaseElement::ONE;
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::math::ToElements;

    #[test]
    fn test_batch_air_trace_length() {
        assert_eq!(BatchTransactionAir::trace_length(2), 4096);
        assert_eq!(BatchTransactionAir::trace_length(4), 8192);
        assert_eq!(BatchTransactionAir::trace_length(8), 16384);
        assert_eq!(BatchTransactionAir::trace_length(16), 32768);
    }

    #[test]
    fn test_hash_mask_structure() {
        let mask = make_hash_mask();
        assert_eq!(mask.len(), CYCLE_LENGTH);

        // First 8 should be 1 (hash active)
        for (i, value) in mask.iter().take(POSEIDON_ROUNDS).enumerate() {
            assert_eq!(*value, BaseElement::ONE, "Step {} should be 1", i);
        }

        // Rest should be 0 (copy/idle)
        for (i, value) in mask.iter().enumerate().skip(POSEIDON_ROUNDS) {
            assert_eq!(*value, BaseElement::ZERO, "Step {} should be 0", i);
        }
    }

    #[test]
    fn test_batch_public_inputs_elements() {
        let pub_inputs = BatchPublicInputs::new(
            2,
            [BaseElement::new(12345), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
            vec![
                [BaseElement::new(1), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
                [BaseElement::new(2), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
                [BaseElement::new(3), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
                [BaseElement::new(4), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
            ],
            vec![
                [BaseElement::new(10), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
                [BaseElement::new(20), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
                [BaseElement::new(30), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
                [BaseElement::new(40), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
            ],
            BaseElement::new(100),
        );

        let elements = pub_inputs.to_elements();
        assert!(!elements.is_empty());
        assert_eq!(elements[0], BaseElement::new(2)); // batch_size
        assert_eq!(elements[1], BaseElement::new(12345)); // anchor
    }
}
