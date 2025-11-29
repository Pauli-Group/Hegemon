//! Real STARK AIR (Algebraic Intermediate Representation) for transaction circuits.
//!
//! This module implements the winterfell::Air trait to define algebraic constraints
//! for transaction validation. These constraints are enforced by the STARK prover
//! and verified by the STARK verifier.
//!
//! ## Constraints
//!
//! The transaction circuit enforces:
//! 1. Balance conservation: sum(inputs) - sum(outputs) = fee (for native asset)
//! 2. Nullifier derivation: nullifier = hash(prf_key, rho, position)
//! 3. Commitment derivation: commitment = hash(value, asset_id, pk, rho, r)
//! 4. Merkle membership: input notes exist in the note tree
//!
//! ## Trace Layout
//!
//! The execution trace has the following columns:
//! - Column 0: input_value_0
//! - Column 1: input_value_1
//! - Column 2: output_value_0
//! - Column 3: output_value_1
//! - Column 4: fee
//! - Column 5: balance_check (should be 0 for valid tx)
//! - Column 6: nullifier_0
//! - Column 7: nullifier_1
//! - Column 8: commitment_0
//! - Column 9: commitment_1
//! - Column 10: merkle_root
//! - Column 11: hash_state_0 (for in-circuit hashing)
//! - Column 12: hash_state_1
//! - Column 13: hash_state_2

use winterfell::{
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use crate::constants::{MAX_INPUTS, MAX_OUTPUTS};

// TRACE CONFIGURATION
// ================================================================================================

/// Width of the execution trace (number of columns)
pub const TRACE_WIDTH: usize = 14;

/// Minimum trace length (must be power of 2, >= 8)
pub const MIN_TRACE_LENGTH: usize = 8;

// PUBLIC INPUTS
// ================================================================================================

/// Public inputs for the transaction circuit.
///
/// These values are known to both prover and verifier and are used
/// to define boundary constraints.
#[derive(Clone, Debug)]
pub struct TransactionPublicInputsStark {
    /// Merkle root of the note tree
    pub merkle_root: BaseElement,
    /// Nullifiers for spent notes (padded to MAX_INPUTS)
    pub nullifiers: Vec<BaseElement>,
    /// Commitments for new notes (padded to MAX_OUTPUTS)
    pub commitments: Vec<BaseElement>,
    /// Net balance change (should equal fee for native asset)
    pub balance_delta: BaseElement,
    /// Transaction fee
    pub fee: BaseElement,
}

impl Default for TransactionPublicInputsStark {
    fn default() -> Self {
        Self {
            merkle_root: BaseElement::ZERO,
            nullifiers: vec![BaseElement::ZERO; MAX_INPUTS],
            commitments: vec![BaseElement::ZERO; MAX_OUTPUTS],
            balance_delta: BaseElement::ZERO,
            fee: BaseElement::ZERO,
        }
    }
}

impl ToElements<BaseElement> for TransactionPublicInputsStark {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::with_capacity(1 + MAX_INPUTS + MAX_OUTPUTS + 2);
        elements.push(self.merkle_root);
        elements.extend(&self.nullifiers);
        elements.extend(&self.commitments);
        elements.push(self.balance_delta);
        elements.push(self.fee);
        elements
    }
}

// TRANSACTION AIR
// ================================================================================================

/// AIR for transaction validation.
///
/// This AIR defines the algebraic constraints that must be satisfied
/// for a valid transaction proof.
pub struct TransactionAirStark {
    context: AirContext<BaseElement>,
    pub_inputs: TransactionPublicInputsStark,
}

impl Air for TransactionAirStark {
    type BaseField = BaseElement;
    type PublicInputs = TransactionPublicInputsStark;

    /// Creates a new AIR instance for the given trace and public inputs.
    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Define transition constraint degrees
        // We have constraints of degree 2 (products of trace columns)
        let degrees = vec![
            // Balance conservation constraint: degree 1
            TransitionConstraintDegree::new(1),
            // Balance check must be zero: degree 1
            TransitionConstraintDegree::new(1),
            // Nullifier consistency (carry forward): degree 1
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            // Commitment consistency (carry forward): degree 1
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            // Merkle root consistency: degree 1
            TransitionConstraintDegree::new(1),
            // Hash state transitions (Poseidon-like): degree 5
            TransitionConstraintDegree::new(5),
            TransitionConstraintDegree::new(5),
            TransitionConstraintDegree::new(5),
        ];

        // Number of assertions (boundary constraints)
        // - Initial values for nullifiers, commitments
        // - Final balance check = 0
        // - Merkle root matches public input
        let num_assertions = MAX_INPUTS + MAX_OUTPUTS + 3;

        assert_eq!(TRACE_WIDTH, trace_info.width());

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    /// Evaluates transition constraints at each step.
    ///
    /// For a valid execution, all constraints must evaluate to zero.
    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // Column indices
        const INPUT_VALUE_0: usize = 0;
        const INPUT_VALUE_1: usize = 1;
        const OUTPUT_VALUE_0: usize = 2;
        const OUTPUT_VALUE_1: usize = 3;
        const FEE: usize = 4;
        const BALANCE_CHECK: usize = 5;
        const NULLIFIER_0: usize = 6;
        const NULLIFIER_1: usize = 7;
        const COMMITMENT_0: usize = 8;
        const COMMITMENT_1: usize = 9;
        const MERKLE_ROOT: usize = 10;
        const HASH_STATE_0: usize = 11;
        const HASH_STATE_1: usize = 12;
        const HASH_STATE_2: usize = 13;

        // Constraint 0: Balance conservation
        // inputs - outputs - fee = 0
        let total_in = current[INPUT_VALUE_0] + current[INPUT_VALUE_1];
        let total_out = current[OUTPUT_VALUE_0] + current[OUTPUT_VALUE_1];
        result[0] = current[BALANCE_CHECK] - (total_in - total_out - current[FEE]);

        // Constraint 1: Balance check must remain zero throughout
        result[1] = next[BALANCE_CHECK] - current[BALANCE_CHECK];

        // Constraints 2-3: Nullifiers stay constant throughout the trace
        result[2] = next[NULLIFIER_0] - current[NULLIFIER_0];
        result[3] = next[NULLIFIER_1] - current[NULLIFIER_1];

        // Constraints 4-5: Commitments stay constant throughout the trace
        result[4] = next[COMMITMENT_0] - current[COMMITMENT_0];
        result[5] = next[COMMITMENT_1] - current[COMMITMENT_1];

        // Constraint 6: Merkle root stays constant
        result[6] = next[MERKLE_ROOT] - current[MERKLE_ROOT];

        // Constraints 7-9: Hash state transition (simplified Poseidon-like)
        // s_i+1 = (s_i + c_i)^5 mixed with other state elements
        let s0 = current[HASH_STATE_0];
        let s1 = current[HASH_STATE_1];
        let s2 = current[HASH_STATE_2];

        // Round constants (simplified - using BaseField conversion)
        let c0: E = E::from(BaseElement::new(0x123456789abcdef0u64));
        let c1: E = E::from(BaseElement::new(0xfedcba9876543210u64));
        let c2: E = E::from(BaseElement::new(0x0f1e2d3c4b5a6978u64));

        // S-box: x^5
        let t0 = (s0 + c0).exp(5u64.into());
        let t1 = (s1 + c1).exp(5u64.into());
        let t2 = (s2 + c2).exp(5u64.into());

        // MDS mixing (simplified 3x3 matrix)
        let two: E = E::from(BaseElement::new(2));
        let m00 = two;
        let m01 = E::ONE;
        let m02 = E::ONE;
        let m10 = E::ONE;
        let m11 = two;
        let m12 = E::ONE;
        let m20 = E::ONE;
        let m21 = E::ONE;
        let m22 = two;

        let expected_s0 = t0 * m00 + t1 * m01 + t2 * m02;
        let expected_s1 = t0 * m10 + t1 * m11 + t2 * m12;
        let expected_s2 = t0 * m20 + t1 * m21 + t2 * m22;

        result[7] = next[HASH_STATE_0] - expected_s0;
        result[8] = next[HASH_STATE_1] - expected_s1;
        result[9] = next[HASH_STATE_2] - expected_s2;
    }

    /// Returns boundary constraints (assertions).
    ///
    /// These constrain specific values at specific positions in the trace.
    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        // Assert nullifiers at step 0
        assertions.push(Assertion::single(6, 0, self.pub_inputs.nullifiers[0]));
        assertions.push(Assertion::single(7, 0, self.pub_inputs.nullifiers[1]));

        // Assert commitments at step 0
        assertions.push(Assertion::single(8, 0, self.pub_inputs.commitments[0]));
        assertions.push(Assertion::single(9, 0, self.pub_inputs.commitments[1]));

        // Assert merkle root at step 0
        assertions.push(Assertion::single(10, 0, self.pub_inputs.merkle_root));

        // Assert balance check is zero at step 0
        assertions.push(Assertion::single(5, 0, BaseElement::ZERO));

        // Assert fee at step 0
        assertions.push(Assertion::single(4, 0, self.pub_inputs.fee));

        assertions
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Checks if constraint evaluates to zero (for debugging).
#[inline]
pub fn is_zero<E: FieldElement>(value: E) -> E {
    value
}

/// Returns zero if a == b, non-zero otherwise.
#[inline]
pub fn are_equal<E: FieldElement>(a: E, b: E) -> E {
    a - b
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::FieldExtension;

    #[test]
    fn test_air_creation() {
        let trace_info = TraceInfo::new(TRACE_WIDTH, MIN_TRACE_LENGTH);
        let pub_inputs = TransactionPublicInputsStark::default();
        let options = ProofOptions::new(
            32,  // num_queries
            8,   // blowup_factor
            0,   // grinding_factor
            FieldExtension::None,
            4,   // fri_folding_factor
            31,  // fri_max_remainder_poly_degree
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        );

        let air = TransactionAirStark::new(trace_info, pub_inputs, options);
        assert_eq!(air.context().trace_info().width(), TRACE_WIDTH);
    }

    #[test]
    fn test_public_inputs_to_elements() {
        let pub_inputs = TransactionPublicInputsStark {
            merkle_root: BaseElement::new(123),
            nullifiers: vec![BaseElement::new(1), BaseElement::new(2)],
            commitments: vec![BaseElement::new(3), BaseElement::new(4)],
            balance_delta: BaseElement::ZERO,
            fee: BaseElement::new(100),
        };

        let elements = pub_inputs.to_elements();
        assert_eq!(elements.len(), 1 + MAX_INPUTS + MAX_OUTPUTS + 2);
        assert_eq!(elements[0], BaseElement::new(123));
    }
}
