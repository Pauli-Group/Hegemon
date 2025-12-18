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
use winter_crypto::{hashers::Blake3_256, MerkleTree};
use winter_math::{FieldElement, ToElements};
use winterfell::{
    crypto::DefaultRandomCoin, math::fields::f64::BaseElement, matrix::ColMatrix, AuxRandElements,
    CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions,
    Prover, StarkDomain, TracePolyTable, TraceTable,
};

use super::rpo_air::{
    ARK1, ARK2, INV_ALPHA, MDS, NUM_ROUNDS, ROWS_PER_PERMUTATION, STATE_WIDTH,
    TRACE_WIDTH as RPO_TRACE_WIDTH,
};

type Blake3 = Blake3_256<BaseElement>;
type Blake3MerkleTree = MerkleTree<Blake3>;

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
        Self {
            leaf,
            root,
            index,
            depth,
        }
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
        // Constraints:
        // - RPO transition constraints for each permutation (STATE_WIDTH)
        // - Chaining constraints between permutations inside the path (DIGEST_WIDTH)
        let num_constraints = STATE_WIDTH + DIGEST_WIDTH;
        let mut degrees = Vec::with_capacity(num_constraints);

        // RPO transition constraints are gated by two periodic selectors:
        // - half_round_type (quadratic selector, two periodic multiplications)
        // - perm_mask (disable boundary transitions, one periodic multiplication)
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(
                7,
                vec![
                    ROWS_PER_PERMUTATION,
                    ROWS_PER_PERMUTATION,
                    ROWS_PER_PERMUTATION,
                ],
            ));
        }

        // Boundary chaining constraints are quadratic in trace columns and gated by a selector
        // which is not strictly periodic after padding. Model this as a full-length cycle.
        let full_cycle = trace_info.length();
        for _ in 0..DIGEST_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(2, vec![full_cycle]));
        }

        // Assertions:
        // - Leaf matches at row 0 (4 elements)
        // - Root matches at final row (4 elements)
        // - Intermediate hashes chain correctly
        let num_assertions = DIGEST_WIDTH * 2;

        let context = AirContext::new(trace_info, degrees, num_assertions, options);

        Self {
            context,
            pub_inputs,
        }
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

        // Periodic values control which RPO round we're in.
        // Layout: [half_round_type, ark[0..STATE_WIDTH], perm_mask, boundary_mask, path_bit]
        let half_round_type = periodic_values[0];
        let ark: [E; STATE_WIDTH] = core::array::from_fn(|i| periodic_values[1 + i]);
        let perm_mask = periodic_values[1 + STATE_WIDTH];
        let boundary_mask = periodic_values[1 + STATE_WIDTH + 1];
        let path_bit = periodic_values[1 + STATE_WIDTH + 2];

        // Build MDS result
        let mut mds_result: [E; STATE_WIDTH] = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            for j in 0..STATE_WIDTH {
                let mds_coeff = E::from(MDS[i][j]);
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

            let rpo_constraint = is_forward * forward_constraint
                + is_inverse * inverse_constraint
                + is_padding * padding_constraint;
            // Disable RPO constraints on boundary transitions between permutations.
            result[i] = perm_mask * rpo_constraint;
        }

        // Chaining constraints at permutation boundaries.
        // When boundary_mask=1, we are transitioning from the last row of one
        // permutation to the first row of the next permutation. The next
        // permutation must take the previous digest as either the left or right
        // sibling depending on the public index bit for that level.
        //
        // RPO digests live in the first half of the rate (columns 4..7), matching
        // `Rpo256::merge`.
        //
        // path_bit=0 => previous digest is on the left
        // path_bit=1 => previous digest is on the right
        let one = E::ONE;
        for i in 0..DIGEST_WIDTH {
            let prev_digest = current[CAPACITY_WIDTH + i]; // digest lives in rate columns 4..7
            let next_left = next[CAPACITY_WIDTH + i];
            let next_right = next[CAPACITY_WIDTH + DIGEST_WIDTH + i];

            let left_constraint = next_left - prev_digest;
            let right_constraint = next_right - prev_digest;

            // Select which side must match prev_digest.
            result[STATE_WIDTH + i] =
                boundary_mask * ((one - path_bit) * left_constraint + path_bit * right_constraint);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        // Assert leaf value at row 0. The leaf can be on the left or right
        // depending on the lowest index bit.
        let leaf_start = if self.pub_inputs.index & 1 == 1 {
            CAPACITY_WIDTH + DIGEST_WIDTH
        } else {
            CAPACITY_WIDTH
        };
        for i in 0..DIGEST_WIDTH {
            assertions.push(Assertion::single(
                leaf_start + i,
                0,
                self.pub_inputs.leaf[i],
            ));
        }

        // Assert root at final permutation output (digest range of the rate).
        let final_row = self.pub_inputs.depth * ROWS_PER_PERMUTATION - 1;
        for i in 0..DIGEST_WIDTH {
            assertions.push(Assertion::single(
                CAPACITY_WIDTH + i, // Digest is in rate (columns 4-7)
                final_row,
                self.pub_inputs.root[i],
            ));
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let total_rows = self.trace_length();
        let total_perms = total_rows / ROWS_PER_PERMUTATION;

        // Replicate the RPO periodic columns for each permutation and add
        // boundary/path-bit masks for chaining.
        let mut half_round_type = Vec::with_capacity(total_rows);
        let mut ark_columns: [Vec<BaseElement>; STATE_WIDTH] =
            core::array::from_fn(|_| Vec::with_capacity(total_rows));
        let mut perm_mask = Vec::with_capacity(total_rows);
        let mut boundary_mask = Vec::with_capacity(total_rows);
        let mut path_bit = Vec::with_capacity(total_rows);

        let active_depth = self.pub_inputs.depth;
        for perm in 0..total_perms {
            // Each permutation has the same periodic pattern
            for row in 0..ROWS_PER_PERMUTATION {
                let val = if row >= 14 {
                    0 // Padding
                } else if row % 2 == 0 {
                    1 // Forward sbox
                } else {
                    2 // Inverse sbox
                };
                half_round_type.push(BaseElement::new(val));

                let constants = if row >= 14 {
                    [BaseElement::ZERO; STATE_WIDTH]
                } else if row % 2 == 0 {
                    let round = row / 2;
                    if round < NUM_ROUNDS {
                        ARK1[round]
                    } else {
                        [BaseElement::ZERO; STATE_WIDTH]
                    }
                } else {
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

                // Apply RPO constraints on all transitions except boundaries between permutations.
                let mask = (row < ROWS_PER_PERMUTATION - 1) as u64;
                perm_mask.push(BaseElement::new(mask));

                // Boundary mask is 1 only on the last row of a permutation,
                // and only if there is a following permutation.
                let is_boundary = row == ROWS_PER_PERMUTATION - 1 && perm + 1 < active_depth;
                boundary_mask.push(BaseElement::new(is_boundary as u64));

                // Path bit used for chaining into the *next* permutation level.
                // At the boundary after permutation `perm`, the sibling order for the next
                // permutation is determined by bit `perm + 1` of the original index.
                let bit = if perm + 1 < active_depth {
                    (self.pub_inputs.index >> (perm + 1)) & 1
                } else {
                    0
                };
                path_bit.push(BaseElement::new(bit));
            }
        }

        let mut result = vec![half_round_type];
        for col in ark_columns {
            result.push(col);
        }
        result.push(perm_mask);
        result.push(boundary_mask);
        result.push(path_bit);
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
        Self {
            options,
            pub_inputs,
            siblings,
        }
    }

    /// Build the execution trace for Merkle path verification
    pub fn build_trace(&self) -> TraceTable<BaseElement> {
        let depth = self.pub_inputs.depth;
        let active_rows = depth * ROWS_PER_PERMUTATION;
        let total_rows = active_rows.next_power_of_two();
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
            state[CAPACITY_WIDTH..CAPACITY_WIDTH + DIGEST_WIDTH].copy_from_slice(&left);
            state[CAPACITY_WIDTH + DIGEST_WIDTH..CAPACITY_WIDTH + 2 * DIGEST_WIDTH]
                .copy_from_slice(&right);

            // Execute RPO permutation and fill trace
            self.fill_rpo_trace(&mut trace, row_offset, state);

            // Extract output hash from digest range (rate columns 4..7).
            for (i, value) in current_hash.iter_mut().enumerate() {
                *value = trace.get(CAPACITY_WIDTH + i, row_offset + ROWS_PER_PERMUTATION - 1);
            }

            index >>= 1;
        }

        // Pad with dummy permutations to keep trace length power-of-two and periodic columns valid.
        let total_perms = total_rows / ROWS_PER_PERMUTATION;
        for perm in depth..total_perms {
            let row_offset = perm * ROWS_PER_PERMUTATION;
            let mut state = [BaseElement::ZERO; STATE_WIDTH];
            for (i, value) in state.iter_mut().enumerate() {
                *value = BaseElement::new(((perm as u64) + 1) * ((i as u64) + 7));
            }
            self.fill_rpo_trace(&mut trace, row_offset, state);
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
            result[i] += MDS[i][j] * state[j];
        }
    }
    *state = result;
}

fn add_constants(state: &mut [BaseElement; STATE_WIDTH], round: usize, first_half: bool) {
    let constants = if first_half {
        &ARK1[round]
    } else {
        &ARK2[round]
    };
    for i in 0..STATE_WIDTH {
        state[i] += constants[i];
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

impl Prover for MerkleVerifierProver {
    type BaseField = BaseElement;
    type Air = MerkleVerifierAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3;
    type VC = Blake3MerkleTree;
    type RandomCoin = DefaultRandomCoin<Blake3>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> MerklePublicInputs {
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &winter_air::TraceInfo,
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use miden_crypto::hash::rpo::Rpo256;
    use miden_crypto::{Felt, Word};
    use winterfell::verify;
    use winterfell::AcceptableOptions;
    use winterfell::Trace;

    fn word_to_digest(word: Word) -> [BaseElement; 4] {
        [
            BaseElement::new(word[0].as_int()),
            BaseElement::new(word[1].as_int()),
            BaseElement::new(word[2].as_int()),
            BaseElement::new(word[3].as_int()),
        ]
    }

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
        assert!(trace.length().is_power_of_two());
        assert!(trace.length() >= 4 * ROWS_PER_PERMUTATION);
    }

    #[test]
    fn test_merkle_verifier_proof_roundtrip() {
        type Blake3 = Blake3_256<BaseElement>;
        type Blake3MerkleTree = MerkleTree<Blake3>;

        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();

        // Build a small RPO Merkle tree of 8 leaves.
        let leaves: Vec<Word> = (0..8)
            .map(|i| {
                let felts = [
                    Felt::new(i as u64 + 1),
                    Felt::new(7),
                    Felt::new(9),
                    Felt::new(11),
                ];
                Rpo256::hash_elements(&felts)
            })
            .collect();

        let tree = MerkleTree::<Rpo256>::new(leaves.clone()).unwrap();
        let index = 3usize;
        let (leaf_word, proof_words) = tree.prove(index).unwrap();

        let leaf = word_to_digest(leaf_word);
        let root = word_to_digest(*tree.root());
        let siblings: Vec<[BaseElement; 4]> = proof_words.into_iter().map(word_to_digest).collect();

        let prover = MerkleVerifierProver::new(options.clone(), leaf, root, index as u64, siblings);
        let trace = prover.build_trace();
        let proof = prover.prove(trace).unwrap();

        let acceptable = AcceptableOptions::OptionSet(vec![options]);
        let result = verify::<MerkleVerifierAir, Blake3, DefaultRandomCoin<Blake3>, Blake3MerkleTree>(
            proof,
            prover.pub_inputs.clone(),
            &acceptable,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_merkle_verifier_tamper_panics() {
        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();
        let leaves: Vec<Word> = (0..8)
            .map(|i| {
                let felts = [
                    Felt::new(i as u64 + 1),
                    Felt::new(7),
                    Felt::new(9),
                    Felt::new(11),
                ];
                Rpo256::hash_elements(&felts)
            })
            .collect();
        let tree = MerkleTree::<Rpo256>::new(leaves).unwrap();
        let index = 2usize;
        let (leaf_word, proof_words) = tree.prove(index).unwrap();

        let leaf = word_to_digest(leaf_word);
        let root = word_to_digest(*tree.root());
        let siblings: Vec<[BaseElement; 4]> = proof_words.into_iter().map(word_to_digest).collect();

        let prover = MerkleVerifierProver::new(options.clone(), leaf, root, index as u64, siblings);
        let mut trace = prover.build_trace();

        // Flip a sibling element in the first permutation input.
        let val = trace.get(CAPACITY_WIDTH, 0);
        trace.set(CAPACITY_WIDTH, 0, val + BaseElement::ONE);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prover.prove(trace)));
        assert!(result.is_err());
    }
}
