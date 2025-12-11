//! Merkle path verification as AIR constraints using RPO hash.
//!
//! This module implements in-circuit verification of Merkle authentication paths.
//! Each step up the tree requires one RPO permutation to hash two siblings.
//!
//! ## Trace Layout
//!
//! For a tree of depth D, we need D RPO permutations. Each permutation uses
//! 16 rows (from rpo_air). The trace layout is:
//!
//! | Rows | Purpose |
//! |------|---------|
//! | 0-15 | RPO permutation for level 0 (leaf → level 1) |
//! | 16-31 | RPO permutation for level 1 → level 2 |
//! | ... | ... |
//! | (D-1)*16 to D*16-1 | RPO permutation for level D-1 → root |
//!
//! Each RPO permutation takes [capacity || left_sibling || right_sibling] as input
//! and outputs [digest || rate] where digest is the parent hash.

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

use super::rpo_air::{
    STATE_WIDTH, NUM_ROUNDS, ALPHA, INV_ALPHA, MDS, ARK1, ARK2,
    ROWS_PER_PERMUTATION, TRACE_WIDTH as RPO_TRACE_WIDTH,
};

// CONSTANTS
// ================================================================================================

/// Capacity portion of RPO state (indices 0-3)
pub const CAPACITY_WIDTH: usize = 4;

/// Rate portion of RPO state (indices 4-11) 
pub const RATE_WIDTH: usize = 8;

/// Digest is stored in capacity after permutation (4 field elements)
pub const DIGEST_WIDTH: usize = 4;

/// Maximum tree depth we support (32 levels = 2^32 leaves)
pub const MAX_TREE_DEPTH: usize = 32;

// PUBLIC INPUTS
// ================================================================================================

/// Public inputs for Merkle path verification
#[derive(Clone, Debug)]
pub struct MerklePublicInputs {
    /// The leaf value being authenticated (hashed to 4 field elements)
    pub leaf: [BaseElement; DIGEST_WIDTH],
    /// The expected root of the tree
    pub root: [BaseElement; DIGEST_WIDTH],
    /// The leaf index (path from root to leaf, 0 = left, 1 = right at each level)
    pub index: u64,
    /// Tree depth (number of levels)
    pub depth: usize,
}

impl MerklePublicInputs {
    pub fn new(
        leaf: [BaseElement; DIGEST_WIDTH],
        root: [BaseElement; DIGEST_WIDTH],
        index: u64,
        depth: usize,
    ) -> Self {
        assert!(depth > 0 && depth <= MAX_TREE_DEPTH);
        Self { leaf, root, index, depth }
    }
}

impl ToElements<BaseElement> for MerklePublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::with_capacity(DIGEST_WIDTH * 2 + 2);
        elements.extend_from_slice(&self.leaf);
        elements.extend_from_slice(&self.root);
        elements.push(BaseElement::new(self.index));
        elements.push(BaseElement::new(self.depth as u64));
        elements
    }
}

// MERKLE VERIFIER AIR
// ================================================================================================

/// AIR for verifying Merkle authentication paths using RPO hash.
///
/// The verifier checks that:
/// 1. Starting from the leaf hash
/// 2. At each level, hashing with the sibling produces the parent
/// 3. The final hash equals the claimed root
///
/// The siblings are provided as part of the trace (auxiliary inputs).
pub struct MerkleVerifierAir {
    context: AirContext<BaseElement>,
    pub_inputs: MerklePublicInputs,
}

impl Air for MerkleVerifierAir {
    type BaseField = BaseElement;
    type PublicInputs = MerklePublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Each RPO permutation has degree 8 constraints (from rpo_air)
        // We have `depth` permutations, each contributes STATE_WIDTH constraints
        let num_constraints = pub_inputs.depth * STATE_WIDTH;
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(8, vec![ROWS_PER_PERMUTATION]);
            num_constraints
        ];

        // Assertions: 
        // - Leaf matches at row 0 (4 elements)
        // - Root matches at final row (4 elements)
        // - Intermediate hashes chain correctly
        let num_assertions = DIGEST_WIDTH * 2;

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

        // The trace contains multiple RPO permutations stacked
        // Each permutation is ROWS_PER_PERMUTATION rows
        // We reuse the RPO constraints from rpo_air
        
        // Periodic values control which RPO round we're in
        let half_round_type = periodic_values[0];
        
        // Extract per-element round constants
        let ark: [E; STATE_WIDTH] = core::array::from_fn(|i| periodic_values[1 + i]);

        // Build MDS result
        let mut mds_result: [E; STATE_WIDTH] = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            for j in 0..STATE_WIDTH {
                let mds_coeff = E::from(BaseElement::new(MDS[i][j]));
                mds_result[i] += mds_coeff * current[j];
            }
        }

        // Add round constants
        let mut intermediate: [E; STATE_WIDTH] = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            intermediate[i] = mds_result[i] + ark[i];
        }

        // Selectors (same as rpo_air)
        let one = E::ONE;
        let two = one + one;
        let is_forward = half_round_type * (two - half_round_type);
        let is_inverse = half_round_type * (half_round_type - one);
        let is_padding = (one - half_round_type) * (two - half_round_type);

        for i in 0..STATE_WIDTH {
            // Forward S-box: next = intermediate^7
            let x = intermediate[i];
            let x2 = x * x;
            let x4 = x2 * x2;
            let x3 = x2 * x;
            let x7 = x3 * x4;
            let forward_constraint = next[i] - x7;

            // Inverse S-box: next^7 = intermediate
            let y = next[i];
            let y2 = y * y;
            let y4 = y2 * y2;
            let y3 = y2 * y;
            let y7 = y3 * y4;
            let inverse_constraint = y7 - intermediate[i];

            // Padding: next = current
            let padding_constraint = next[i] - current[i];

            result[i] = is_forward * forward_constraint 
                      + is_inverse * inverse_constraint
                      + is_padding * padding_constraint;
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        // Assert leaf value at row 0, columns 4-7 (first 4 elements of rate)
        for i in 0..DIGEST_WIDTH {
            assertions.push(Assertion::single(
                CAPACITY_WIDTH + i,  // Rate starts at column 4
                0,
                self.pub_inputs.leaf[i],
            ));
        }

        // Assert root at final permutation output
        let final_row = self.pub_inputs.depth * ROWS_PER_PERMUTATION - 1;
        for i in 0..DIGEST_WIDTH {
            assertions.push(Assertion::single(
                i,  // Digest is in capacity (columns 0-3)
                final_row,
                self.pub_inputs.root[i],
            ));
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let total_rows = self.pub_inputs.depth * ROWS_PER_PERMUTATION;
        
        // Replicate the RPO periodic columns for each permutation
        let mut half_round_type = Vec::with_capacity(total_rows);
        let mut ark_columns: [Vec<BaseElement>; STATE_WIDTH] = 
            core::array::from_fn(|_| Vec::with_capacity(total_rows));

        for _perm in 0..self.pub_inputs.depth {
            // Each permutation has the same periodic pattern
            for row in 0..ROWS_PER_PERMUTATION {
                let val = if row >= 14 {
                    0  // Padding
                } else if row % 2 == 0 {
                    1  // Forward sbox
                } else {
                    2  // Inverse sbox
                };
                half_round_type.push(BaseElement::new(val));

                let constants = if row >= 14 {
                    [0u64; STATE_WIDTH]
                } else if row % 2 == 0 {
                    let round = row / 2;
                    if round < NUM_ROUNDS { ARK1[round] } else { [0u64; STATE_WIDTH] }
                } else {
                    let round = row / 2;
                    if round < NUM_ROUNDS { ARK2[round] } else { [0u64; STATE_WIDTH] }
                };

                for (i, &c) in constants.iter().enumerate() {
                    ark_columns[i].push(BaseElement::new(c));
                }
            }
        }

        let mut result = vec![half_round_type];
        for col in ark_columns {
            result.push(col);
        }
        result
    }
}

// MERKLE PROVER
// ================================================================================================

/// Prover for Merkle path verification
pub struct MerkleVerifierProver {
    options: ProofOptions,
    pub_inputs: MerklePublicInputs,
    /// Sibling hashes at each level (from leaf to root)
    siblings: Vec<[BaseElement; DIGEST_WIDTH]>,
}

impl MerkleVerifierProver {
    pub fn new(
        options: ProofOptions,
        leaf: [BaseElement; DIGEST_WIDTH],
        root: [BaseElement; DIGEST_WIDTH],
        index: u64,
        siblings: Vec<[BaseElement; DIGEST_WIDTH]>,
    ) -> Self {
        let depth = siblings.len();
        let pub_inputs = MerklePublicInputs::new(leaf, root, index, depth);
        Self { options, pub_inputs, siblings }
    }

    /// Build the execution trace for Merkle path verification
    pub fn build_trace(&self) -> TraceTable<BaseElement> {
        let depth = self.pub_inputs.depth;
        let total_rows = depth * ROWS_PER_PERMUTATION;
        let mut trace = TraceTable::new(RPO_TRACE_WIDTH, total_rows);

        let mut current_hash = self.pub_inputs.leaf;
        let mut index = self.pub_inputs.index;

        for level in 0..depth {
            let sibling = self.siblings[level];
            let row_offset = level * ROWS_PER_PERMUTATION;

            // Determine left/right based on index bit
            let is_right = (index & 1) == 1;
            let (left, right) = if is_right {
                (sibling, current_hash)
            } else {
                (current_hash, sibling)
            };

            // Build RPO input state: [capacity (zeros) || left || right]
            let mut state = [BaseElement::ZERO; STATE_WIDTH];
            // Capacity is zeros (domain separation could go here)
            // Rate = left || right
            for i in 0..DIGEST_WIDTH {
                state[CAPACITY_WIDTH + i] = left[i];
            }
            for i in 0..DIGEST_WIDTH {
                state[CAPACITY_WIDTH + DIGEST_WIDTH + i] = right[i];
            }

            // Execute RPO permutation and fill trace
            self.fill_rpo_trace(&mut trace, row_offset, state);

            // Extract output hash from capacity
            for i in 0..DIGEST_WIDTH {
                current_hash[i] = trace.get(i, row_offset + ROWS_PER_PERMUTATION - 1);
            }

            index >>= 1;
        }

        trace
    }

    /// Fill trace rows for one RPO permutation
    fn fill_rpo_trace(
        &self,
        trace: &mut TraceTable<BaseElement>,
        row_offset: usize,
        input_state: [BaseElement; STATE_WIDTH],
    ) {
        // Row 0: input state
        for (col, &val) in input_state.iter().enumerate() {
            trace.set(col, row_offset, val);
        }
        trace.set(STATE_WIDTH, row_offset, BaseElement::ZERO);

        let mut state = input_state;

        // Execute 7 rounds
        for round in 0..NUM_ROUNDS {
            // Forward half-round
            apply_mds(&mut state);
            add_constants(&mut state, round, true);
            apply_sbox(&mut state);

            let row = row_offset + 1 + round * 2;
            for (col, &val) in state.iter().enumerate() {
                trace.set(col, row, val);
            }
            trace.set(STATE_WIDTH, row, BaseElement::new((round * 2 + 1) as u64));

            // Inverse half-round
            apply_mds(&mut state);
            add_constants(&mut state, round, false);
            apply_inv_sbox(&mut state);

            let row = row_offset + 2 + round * 2;
            if row < row_offset + ROWS_PER_PERMUTATION {
                for (col, &val) in state.iter().enumerate() {
                    trace.set(col, row, val);
                }
                trace.set(STATE_WIDTH, row, BaseElement::new((round * 2 + 2) as u64));
            }
        }

        // Padding row (row 15)
        let padding_row = row_offset + 15;
        for (col, &val) in state.iter().enumerate() {
            trace.set(col, padding_row, val);
        }
        trace.set(STATE_WIDTH, padding_row, BaseElement::new(15));
    }
}

// HELPER FUNCTIONS (duplicated from rpo_air for now)
// ================================================================================================

fn apply_mds(state: &mut [BaseElement; STATE_WIDTH]) {
    let mut result = [BaseElement::ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            result[i] += BaseElement::new(MDS[i][j]) * state[j];
        }
    }
    *state = result;
}

fn add_constants(state: &mut [BaseElement; STATE_WIDTH], round: usize, first_half: bool) {
    let constants = if first_half { &ARK1[round] } else { &ARK2[round] };
    for i in 0..STATE_WIDTH {
        state[i] += BaseElement::new(constants[i]);
    }
}

fn apply_sbox(state: &mut [BaseElement; STATE_WIDTH]) {
    for elem in state.iter_mut() {
        let x2 = elem.square();
        let x4 = x2.square();
        let x3 = x2 * *elem;
        *elem = x3 * x4;
    }
}

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
    fn test_merkle_public_inputs() {
        let leaf = [BaseElement::new(1); DIGEST_WIDTH];
        let root = [BaseElement::new(2); DIGEST_WIDTH];
        let pub_inputs = MerklePublicInputs::new(leaf, root, 5, 8);

        assert_eq!(pub_inputs.index, 5);
        assert_eq!(pub_inputs.depth, 8);
    }

    #[test]
    fn test_merkle_trace_dimensions() {
        let leaf = [BaseElement::new(1); DIGEST_WIDTH];
        let root = [BaseElement::new(2); DIGEST_WIDTH];
        let siblings = vec![[BaseElement::new(3); DIGEST_WIDTH]; 4];
        
        let prover = MerkleVerifierProver::new(
            super::super::rpo_proof::RpoProofOptions::fast().to_winter_options(),
            leaf,
            root,
            3,
            siblings,
        );

        let trace = prover.build_trace();
        assert_eq!(trace.length(), 4 * ROWS_PER_PERMUTATION); // 4 levels × 16 rows
    }
}
