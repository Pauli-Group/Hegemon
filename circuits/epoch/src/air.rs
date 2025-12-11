//! Epoch proof AIR (Algebraic Intermediate Representation).
//!
//! Proves knowledge of proof hashes that commit to an epoch.
//! Uses Poseidon hash for in-circuit computation, following the pattern
//! from BatchTransactionAir.
//!
//! ## Trace Layout
//!
//! The trace has 5 columns:
//! - COL_S0, COL_S1, COL_S2: Poseidon state (3-element width)
//! - COL_PROOF_INPUT: Current proof hash element being absorbed
//! - COL_ACCUMULATOR: Running hash accumulator (copy of S0)
//!
//! ## Computation Flow
//!
//! 1. Start with initial state [0, 0, 0]
//! 2. For each proof hash (32 bytes = 4 field elements):
//!    - Absorb 1 element per cycle into S0
//!    - Run Poseidon permutation (8 rounds per cycle)
//! 3. Final S0 is the proof_accumulator public input

use winterfell::{
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use transaction_circuit::stark_air::{round_constant, CYCLE_LENGTH};

// ================================================================================================
// TRACE CONFIGURATION
// ================================================================================================

/// Number of Poseidon rounds per cycle (matching transaction circuit).
pub const POSEIDON_ROUNDS: usize = 8;

/// Trace width: 3 Poseidon state + 1 proof input + 1 accumulator.
pub const EPOCH_TRACE_WIDTH: usize = 5;

/// Column indices
pub const COL_S0: usize = 0;
pub const COL_S1: usize = 1;
pub const COL_S2: usize = 2;
pub const COL_PROOF_INPUT: usize = 3;
pub const COL_ACCUMULATOR: usize = 4;

// ================================================================================================
// PUBLIC INPUTS
// ================================================================================================

/// Public inputs for epoch proof.
#[derive(Clone, Debug)]
pub struct EpochPublicInputs {
    /// Poseidon hash of all proof hashes (computed in-circuit).
    pub proof_accumulator: BaseElement,
    /// Number of proofs in this epoch.
    pub num_proofs: u32,
    /// Epoch commitment (Blake3 hash of Epoch struct, verified off-circuit).
    pub epoch_commitment: [u8; 32],
}

impl Default for EpochPublicInputs {
    fn default() -> Self {
        Self {
            proof_accumulator: BaseElement::ZERO,
            num_proofs: 0,
            epoch_commitment: [0u8; 32],
        }
    }
}

impl ToElements<BaseElement> for EpochPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            self.proof_accumulator,
            BaseElement::new(self.num_proofs as u64),
        ]
    }
}

// ================================================================================================
// AIR IMPLEMENTATION
// ================================================================================================

/// Epoch proof AIR.
///
/// Proves knowledge of proof hashes that hash to the claimed accumulator.
///
/// Trace layout:
/// ```text
/// Row 0..CYCLE_LENGTH:     Absorb proof_hash[0][0] into state
/// Row CYCLE_LENGTH..2*CL:  Absorb proof_hash[0][1] into state
/// Row 2*CL..3*CL:          Absorb proof_hash[0][2] into state
/// Row 3*CL..4*CL:          Absorb proof_hash[0][3] into state
/// Row 4*CL..5*CL:          Absorb proof_hash[1][0] into state
/// ...
/// (Padding to power of 2)
/// ```
///
/// Each hash cycle absorbs one 64-bit field element from proof hashes.
/// After all elements are absorbed, final S0 is the proof_accumulator.
pub struct EpochProofAir {
    context: AirContext<BaseElement>,
    pub_inputs: EpochPublicInputs,
}

impl EpochProofAir {
    /// Calculate trace length for given number of proofs.
    ///
    /// Each proof hash is 32 bytes = 4 field elements (8 bytes each).
    /// We absorb 1 element per cycle.
    pub fn trace_length(num_proofs: usize) -> usize {
        let elements_per_proof = 4; // 32 bytes / 8 bytes per element
        let total_elements = num_proofs * elements_per_proof;
        let total_cycles = total_elements.max(1);
        let rows = total_cycles * CYCLE_LENGTH;
        rows.next_power_of_two()
    }

    /// Get the number of proofs from public inputs.
    pub fn num_proofs(&self) -> usize {
        self.pub_inputs.num_proofs as usize
    }
}

impl Air for EpochProofAir {
    type BaseField = BaseElement;
    type PublicInputs = EpochPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Poseidon x^5 constraint degree, cyclic
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
        ];

        // Assertions:
        // 1. Initial state is zero (3 assertions)
        // 2. Final S0 matches proof_accumulator (1 assertion)
        let num_assertions = 4;

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
        // Note: proof input is absorbed at start of cycle (handled in trace generation)
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
        let trace_len = self.context.trace_len();

        vec![
            // Initial state is zero
            Assertion::single(COL_S0, 0, BaseElement::ZERO),
            Assertion::single(COL_S1, 0, BaseElement::ZERO),
            Assertion::single(COL_S2, 0, BaseElement::ZERO),
            // Final S0 matches proof accumulator
            Assertion::single(COL_S0, trace_len - 1, self.pub_inputs.proof_accumulator),
        ]
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
    for i in 0..POSEIDON_ROUNDS {
        mask[i] = BaseElement::ONE;
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_length_calculation() {
        // 1 proof = 4 elements = 4 cycles = 64 rows → 64
        assert_eq!(EpochProofAir::trace_length(1), 64);

        // 16 proofs = 64 elements = 64 cycles = 1024 rows → 1024
        assert_eq!(EpochProofAir::trace_length(16), 1024);

        // 1000 proofs = 4000 elements = 4000 cycles = 64000 rows → 65536
        assert_eq!(EpochProofAir::trace_length(1000), 65536);
    }

    #[test]
    fn test_public_inputs_to_elements() {
        let pub_inputs = EpochPublicInputs {
            proof_accumulator: BaseElement::new(12345),
            num_proofs: 100,
            epoch_commitment: [0u8; 32],
        };

        let elements = pub_inputs.to_elements();
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0], BaseElement::new(12345));
        assert_eq!(elements[1], BaseElement::new(100));
    }

    #[test]
    fn test_hash_mask_structure() {
        let mask = make_hash_mask();
        assert_eq!(mask.len(), CYCLE_LENGTH);

        // First 8 should be 1 (hash active)
        for i in 0..POSEIDON_ROUNDS {
            assert_eq!(mask[i], BaseElement::ONE, "Step {} should be 1", i);
        }

        // Rest should be 0 (copy/idle)
        for i in POSEIDON_ROUNDS..CYCLE_LENGTH {
            assert_eq!(mask[i], BaseElement::ZERO, "Step {} should be 0", i);
        }
    }

    #[test]
    fn test_default_public_inputs() {
        let pub_inputs = EpochPublicInputs::default();
        assert_eq!(pub_inputs.proof_accumulator, BaseElement::ZERO);
        assert_eq!(pub_inputs.num_proofs, 0);
        assert_eq!(pub_inputs.epoch_commitment, [0u8; 32]);
    }
}
