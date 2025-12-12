//! RPO (Rescue Prime Optimized) permutation as AIR constraints.
//!
//! This module implements the RPO permutation as winterfell AIR constraints,
//! enabling in-circuit hashing for recursive proof verification.
//!
//! ## RPO Parameters (from miden-crypto)
//!
//! - State width: 12 field elements (Goldilocks: p = 2^64 - 2^32 + 1)
//! - Rate: 8 elements (indices 4-11)
//! - Capacity: 4 elements (indices 0-3)
//! - Rounds: 7
//! - S-box: x^7 (forward), x^{10540996611094048183} (inverse)
//! - MDS: 12x12 circulant matrix
//!
//! ## Why RPO instead of Blake3?
//!
//! Blake3 uses bitwise operations (XOR, rotation, AND) that require ~100 columns
//! when encoded as field constraints. RPO uses algebraic operations (x^7, linear
//! combinations) that map directly to low-degree polynomial constraints.
//!
//! Estimated costs:
//! - Blake3: ~100 columns, degree ~8 (via decomposition)
//! - RPO: ~13 columns, degree 7 (native x^7 S-box)

use miden_crypto::hash::rpo::Rpo256;
use winter_air::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use winter_math::{FieldElement, ToElements};
use winter_crypto::{hashers::Blake3_256, MerkleTree};
use winterfell::{
    crypto::DefaultRandomCoin,
    math::fields::f64::BaseElement,
    matrix::ColMatrix,
    AuxRandElements, ConstraintCompositionCoefficients, PartitionOptions,
    DefaultConstraintEvaluator, DefaultTraceLde, Prover, StarkDomain,
    TracePolyTable, TraceTable, DefaultConstraintCommitment,
    CompositionPoly, CompositionPolyTrace,
};

// RPO CONSTANTS
// ================================================================================================

/// Number of field elements in RPO state.
pub const STATE_WIDTH: usize = Rpo256::STATE_WIDTH;

/// Number of rounds in RPO permutation.
pub const NUM_ROUNDS: usize = Rpo256::NUM_ROUNDS;

/// S-box exponent (x^7)
pub const ALPHA: u64 = 7;

/// Inverse S-box exponent: x^{(p-1)/7} where p = 2^64 - 2^32 + 1
/// INV_ALPHA * ALPHA ≡ 1 (mod p-1)
pub const INV_ALPHA: u64 = 10540996611094048183;

/// Trace width: 12 state columns + 1 round counter = 13 columns
pub const TRACE_WIDTH: usize = STATE_WIDTH + 1;

/// Rows per RPO permutation: 7 rounds × 2 half-rounds = 14 rows
/// (Each round has forward S-box then inverse S-box)
/// Padded to 16 for power-of-two requirement
pub const ROWS_PER_PERMUTATION: usize = 16;

/// Actual computation rows (before padding)
const COMPUTATION_ROWS: usize = NUM_ROUNDS * 2; // 14 rows

/// Column index for round counter
const ROUND_COL: usize = STATE_WIDTH;

// MDS MATRIX
// ================================================================================================

/// RPO MDS matrix (from miden-crypto).
pub const MDS: [[BaseElement; STATE_WIDTH]; STATE_WIDTH] = Rpo256::MDS;

// ROUND CONSTANTS (ARK1 - first half of each round)
// ================================================================================================

/// Round constants for the first half of each RPO round (from miden-crypto).
pub const ARK1: [[BaseElement; STATE_WIDTH]; NUM_ROUNDS] = Rpo256::ARK1;

/// Round constants for the second half of each RPO round (from miden-crypto).
pub const ARK2: [[BaseElement; STATE_WIDTH]; NUM_ROUNDS] = Rpo256::ARK2;

// PUBLIC INPUTS
// ================================================================================================

/// Public inputs for RPO AIR: input state and expected output state
#[derive(Clone, Debug)]
pub struct RpoPublicInputs {
    /// Initial state (12 field elements)
    pub input_state: [BaseElement; STATE_WIDTH],
    /// Expected output state after permutation (12 field elements)
    pub output_state: [BaseElement; STATE_WIDTH],
}

impl RpoPublicInputs {
    /// Create new public inputs
    pub fn new(input: [BaseElement; STATE_WIDTH], output: [BaseElement; STATE_WIDTH]) -> Self {
        Self {
            input_state: input,
            output_state: output,
        }
    }
}

impl ToElements<BaseElement> for RpoPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::with_capacity(STATE_WIDTH * 2);
        elements.extend_from_slice(&self.input_state);
        elements.extend_from_slice(&self.output_state);
        elements
    }
}

// RPO AIR
// ================================================================================================

/// AIR for verifying RPO permutation in-circuit.
///
/// This AIR proves that `output_state = RPO_permutation(input_state)`.
///
/// ## Trace Layout (13 columns × 14 rows)
///
/// | Col 0-11 | Col 12     |
/// |----------|------------|
/// | state[0..12] | round_idx |
///
/// Each round uses 2 rows:
/// - Row 2r: After MDS + ARK1 + forward S-box (x^7)
/// - Row 2r+1: After MDS + ARK2 + inverse S-box (x^{INV_ALPHA})
pub struct RpoAir {
    context: AirContext<BaseElement>,
    pub_inputs: RpoPublicInputs,
}

impl Air for RpoAir {
    type BaseField = BaseElement;
    type PublicInputs = RpoPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Constraint degree calculation:
        // - S-box constraint: x^7 or y^7 = degree 7
        // - Selector multiplication adds degree 2 from periodic values
        // - Total: 7 + 2 - 1 = 8 (periodic degree is multiplied, not added)
        // Periodic column cycles: length 16 (same as trace)
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(8, vec![ROWS_PER_PERMUTATION]); 
            STATE_WIDTH
        ];

        // Assertions: 12 input + 12 output = 24
        let num_assertions = 2 * STATE_WIDTH;

        let context = AirContext::new(trace_info, degrees, num_assertions, options);

        Self { context, pub_inputs }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // Get round index from the trace (column 12)
        let round_idx = current[ROUND_COL];
        
        // Periodic values layout:
        // [0]: half_round_selector (0 = padding/input, 1 = forward sbox, 2 = inverse sbox)
        // [1..13]: ARK constants for this row (12 values)
        let half_round_type = periodic_values[0];
        
        // Extract per-element round constants
        let ark: [E; STATE_WIDTH] = core::array::from_fn(|i| periodic_values[1 + i]);

        // Build MDS result: MDS(current)
        let mut mds_result: [E; STATE_WIDTH] = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            for j in 0..STATE_WIDTH {
                let mds_coeff = E::from(MDS[i][j]);
                mds_result[i] += mds_coeff * current[j];
            }
        }

        // Add round constants: MDS(current) + ARK
        let mut intermediate: [E; STATE_WIDTH] = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            intermediate[i] = mds_result[i] + ark[i];
        }

        // Apply constraints based on half-round type
        // Type 0: No constraint (input row or padding)
        // Type 1: Forward S-box constraint: next = (MDS(current) + ARK)^7
        // Type 2: Inverse S-box constraint: next^7 = MDS(current) + ARK
        
        let one = E::ONE;
        let two = one + one;
        
        // Selector for forward S-box (type == 1)
        let is_forward = half_round_type * (two - half_round_type);
        
        // Selector for inverse S-box (type == 2)  
        let is_inverse = half_round_type * (half_round_type - one);
        
        // Selector for no constraint (type == 0)
        let is_padding = (one - half_round_type) * (two - half_round_type);

        for i in 0..STATE_WIDTH {
            // Forward S-box: next = intermediate^7
            // Compute intermediate^7 = intermediate * intermediate^2 * intermediate^4
            let x = intermediate[i];
            let x2 = x * x;
            let x4 = x2 * x2;
            let x3 = x2 * x;
            let x7 = x3 * x4;
            let forward_constraint = next[i] - x7;

            // Inverse S-box: next^7 = intermediate
            // Compute next^7
            let y = next[i];
            let y2 = y * y;
            let y4 = y2 * y2;
            let y3 = y2 * y;
            let y7 = y3 * y4;
            let inverse_constraint = y7 - intermediate[i];

            // Padding: next = current (state unchanged)
            let padding_constraint = next[i] - current[i];

            // Combined constraint with selectors
            // Only one of these will be non-zero based on half_round_type
            result[i] = is_forward * forward_constraint 
                      + is_inverse * inverse_constraint
                      + is_padding * padding_constraint;
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        // Assert initial state at row 0
        for i in 0..STATE_WIDTH {
            assertions.push(Assertion::single(i, 0, self.pub_inputs.input_state[i]));
        }

        // Assert final state at last row
        let last_row = ROWS_PER_PERMUTATION - 1;
        for i in 0..STATE_WIDTH {
            assertions.push(Assertion::single(i, last_row, self.pub_inputs.output_state[i]));
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        // Periodic columns for RPO constraints
        // Column 0: half_round_type selector (0=padding, 1=forward sbox, 2=inverse sbox)
        // Columns 1-12: ARK constants for each state element
        //
        // The periodic value at row r controls the transition r → r+1
        
        let trace_len = ROWS_PER_PERMUTATION;
        
        // Half-round type selector:
        // Row 0 → 1: forward sbox (type 1), uses ARK1[0]
        // Row 1 → 2: inverse sbox (type 2), uses ARK2[0]
        // Row 2 → 3: forward sbox (type 1), uses ARK1[1]
        // Row 3 → 4: inverse sbox (type 2), uses ARK2[1]
        // ...
        // Row 12 → 13: forward sbox (type 1), uses ARK1[6]
        // Row 13 → 14: inverse sbox (type 2), uses ARK2[6]
        // Row 14 → 15: padding (type 0), copy state
        // Row 15: last row, no outgoing transition checked
        let mut half_round_type = Vec::with_capacity(trace_len);
        for row in 0..trace_len {
            let val = if row >= 14 {
                0  // Rows 14, 15: padding transition or last row
            } else if row % 2 == 0 {
                1  // Even rows (0,2,4,...,12): forward sbox transition
            } else {
                2  // Odd rows (1,3,5,...,13): inverse sbox transition
            };
            half_round_type.push(BaseElement::new(val));
        }

        // ARK constants - one column per state element
        // The constants at row r are used for transition r → r+1
        // Row 0: ARK1[0] (forward sbox for round 0)
        // Row 1: ARK2[0] (inverse sbox for round 0)
        // Row 2: ARK1[1] (forward sbox for round 1)
        // etc.
        let mut ark_columns: [Vec<BaseElement>; STATE_WIDTH] = 
            core::array::from_fn(|_| Vec::with_capacity(trace_len));

        for row in 0..trace_len {
            let constants = if row >= ROWS_PER_PERMUTATION - 1 {
                [BaseElement::ZERO; STATE_WIDTH] // Padding transition
            } else if row % 2 == 0 {
                // Even row: forward sbox uses ARK1
                let round = row / 2;
                if round < NUM_ROUNDS {
                    ARK1[round]
                } else {
                    [BaseElement::ZERO; STATE_WIDTH]
                }
            } else {
                // Odd row: inverse sbox uses ARK2
                let round = row / 2;
                if round < NUM_ROUNDS {
                    ARK2[round]
                } else {
                    [BaseElement::ZERO; STATE_WIDTH]
                }
            };

            for (i, &c) in constants.iter().enumerate() {
                ark_columns[i].push(c);
            }
        }

        // Combine into result: [half_round_type, ark[0], ark[1], ..., ark[11]]
        let mut result = vec![half_round_type];
        for col in ark_columns {
            result.push(col);
        }

        result
    }
}

// RPO PROVER
// ================================================================================================

/// Prover for RPO permutation circuit
pub struct RpoProver {
    options: ProofOptions,
}

impl RpoProver {
    /// Create new RPO prover with given options
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    /// Build the execution trace for an RPO permutation
    pub fn build_trace(&self, input_state: [BaseElement; STATE_WIDTH]) -> TraceTable<BaseElement> {
        let mut trace = TraceTable::new(TRACE_WIDTH, ROWS_PER_PERMUTATION);

        // Row 0: Initial state (input)
        for (col, &val) in input_state.iter().enumerate() {
            trace.set(col, 0, val);
        }
        trace.set(ROUND_COL, 0, BaseElement::ZERO);

        // Initialize state
        let mut state: [BaseElement; STATE_WIDTH] = input_state;

        // Execute 7 rounds, each with 2 half-rounds
        // Rows 1-14 store intermediate states
        for round in 0..NUM_ROUNDS {
            // First half-round: MDS → add ARK1 → forward S-box (x^7)
            apply_mds(&mut state);
            add_constants(&mut state, round, true);
            apply_sbox(&mut state);

            let row = 1 + round * 2;
            for (col, &val) in state.iter().enumerate() {
                trace.set(col, row, val);
            }
            trace.set(ROUND_COL, row, BaseElement::new((round * 2 + 1) as u64));

            // Second half-round: MDS → add ARK2 → inverse S-box (x^{INV_ALPHA})
            apply_mds(&mut state);
            add_constants(&mut state, round, false);
            apply_inv_sbox(&mut state);

            let row = 2 + round * 2;
            if row < ROWS_PER_PERMUTATION {
                for (col, &val) in state.iter().enumerate() {
                    trace.set(col, row, val);
                }
                trace.set(ROUND_COL, row, BaseElement::new((round * 2 + 2) as u64));
            }
        }

        // Row 15: padding (copy of final output)
        // Already covered by the last iteration if row < ROWS_PER_PERMUTATION
        // But the last valid row is 14, so we need to set row 15
        for (col, &val) in state.iter().enumerate() {
            trace.set(col, 15, val);
        }
        trace.set(ROUND_COL, 15, BaseElement::new(15));

        trace
    }

    /// Get the output state after permutation
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
}

impl Prover for RpoProver {
    type BaseField = BaseElement;
    type Air = RpoAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
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

// HELPER FUNCTIONS
// ================================================================================================

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

/// Apply forward S-box (x^7) to all state elements
fn apply_sbox(state: &mut [BaseElement; STATE_WIDTH]) {
    for elem in state.iter_mut() {
        // x^7 = x * x^2 * x^4
        let x2 = elem.square();
        let x4 = x2.square();
        let x3 = x2 * *elem;
        *elem = x3 * x4;
    }
}

/// Apply inverse S-box (x^INV_ALPHA) to all state elements
fn apply_inv_sbox(state: &mut [BaseElement; STATE_WIDTH]) {
    for elem in state.iter_mut() {
        *elem = elem.exp(INV_ALPHA.into());
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::Trace;

    #[test]
    fn test_sbox_inverse() {
        // Verify that apply_sbox and apply_inv_sbox are inverses
        let x = BaseElement::new(12345678901234567890);

        // Apply forward S-box
        let mut state = [x; STATE_WIDTH];
        apply_sbox(&mut state);

        // Apply inverse S-box
        apply_inv_sbox(&mut state);

        // Should be back to original
        assert_eq!(state[0], x, "S-box and inverse S-box should be inverses");
    }

    #[test]
    fn test_mds_matrix() {
        // Simple test that MDS application doesn't panic
        let mut state = [BaseElement::ONE; STATE_WIDTH];
        apply_mds(&mut state);

        // All elements should be non-zero after MDS (since MDS is invertible)
        for elem in state.iter() {
            assert_ne!(*elem, BaseElement::ZERO);
        }
    }

    #[test]
    fn test_full_permutation() {
        let prover = RpoProver::new(crate::prover::fast_epoch_options());

        // Test with zero state
        let input = [BaseElement::ZERO; STATE_WIDTH];
        let output = prover.compute_output(input);

        // Output should be non-zero (permutation is bijective)
        let all_zero = output.iter().all(|x| *x == BaseElement::ZERO);
        assert!(!all_zero, "RPO output should not be all zeros");
    }

    #[test]
    fn test_trace_generation() {
        let prover = RpoProver::new(crate::prover::fast_epoch_options());

        let input = [BaseElement::new(42); STATE_WIDTH];
        let trace = prover.build_trace(input);

        assert_eq!(trace.width(), TRACE_WIDTH);
        assert_eq!(trace.length(), ROWS_PER_PERMUTATION);
    }

    #[test]
    fn test_permutation_matches_miden_crypto() {
        use miden_crypto::hash::rpo::Rpo256;

        let prover = RpoProver::new(crate::prover::fast_epoch_options());
        let input: [BaseElement; STATE_WIDTH] =
            core::array::from_fn(|i| BaseElement::new((i as u64 + 1) * 1234567));

        let actual = prover.compute_output(input);

        let mut expected = input;
        Rpo256::apply_permutation(&mut expected);

        assert_eq!(actual, expected);
    }
}
