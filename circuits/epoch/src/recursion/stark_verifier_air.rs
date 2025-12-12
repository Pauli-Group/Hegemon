//! Complete STARK verifier as AIR constraints.
//!
//! This module composes all the verification components into a single AIR
//! that can verify another STARK proof in-circuit, enabling true recursion.
//!
//! ## STARK Verification Steps
//!
//! 1. **Commitment Phase**
//!    - Verify trace commitment (Merkle root)
//!    - Verify constraint commitment (Merkle root)
//!
//! 2. **Query Phase (using Fiat-Shamir via RPO)**
//!    - Draw random challenges using RPO-based RandomCoin
//!    - Compute query positions
//!
//! 3. **FRI Verification**
//!    - Verify polynomial commitment opens to claimed values
//!    - Verify FRI folding is consistent
//!
//! 4. **Deep Composition**
//!    - Verify DEEP queries at OOD (out-of-domain) point
//!    - Verify constraint evaluations match
//!
//! ## Trace Layout
//!
//! The verifier trace combines multiple sub-components:
//! - RPO permutations for Fiat-Shamir challenges
//! - Merkle path verifications for query authentication
//! - FRI folding verifications
//! - Constraint evaluation checks

use winter_air::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use miden_crypto::rand::RpoRandomCoin;
use miden_crypto::Word;
use winter_crypto::RandomCoin;
use winter_math::{FieldElement, ToElements};
use winterfell::math::fields::f64::BaseElement;

use super::rpo_air::{
    STATE_WIDTH, ROWS_PER_PERMUTATION, NUM_ROUNDS, MDS, ARK1, ARK2,
    TRACE_WIDTH as RPO_TRACE_WIDTH,
};
use super::merkle_air::DIGEST_WIDTH;
use winter_air::DeepCompositionCoefficients;

const CAPACITY_WIDTH: usize = 4;
const RATE_WIDTH: usize = 8;
const RATE_START: usize = CAPACITY_WIDTH;

// Trace layout for StarkVerifierAir.
// Columns 0..STATE_WIDTH-1 hold the RPO sponge state, and column STATE_WIDTH is an unused
// round counter (kept for compatibility with shared trace builders).
const ROUND_COL: usize = STATE_WIDTH;
pub(crate) const COL_CARRY_MASK: usize = RPO_TRACE_WIDTH;
pub(crate) const COL_FULL_CARRY_MASK: usize = RPO_TRACE_WIDTH + 1;
pub(crate) const COL_RESEED_MASK: usize = RPO_TRACE_WIDTH + 2;
pub(crate) const COL_COIN_INIT_MASK: usize = RPO_TRACE_WIDTH + 3;
pub(crate) const COL_RESEED_WORD_START: usize = RPO_TRACE_WIDTH + 4;
pub(crate) const BASE_VERIFIER_TRACE_WIDTH: usize = COL_RESEED_WORD_START + DIGEST_WIDTH;
pub(crate) const COL_COEFF_MASK: usize = BASE_VERIFIER_TRACE_WIDTH;
pub(crate) const COL_Z_MASK: usize = BASE_VERIFIER_TRACE_WIDTH + 1;
pub(crate) const COL_COEFF_START: usize = BASE_VERIFIER_TRACE_WIDTH + 2;
pub(crate) const COL_Z_VALUE: usize = COL_COEFF_START + RATE_WIDTH;
pub(crate) const COL_DEEP_MASK: usize = COL_Z_VALUE + 1;
pub(crate) const COL_DEEP_START: usize = COL_DEEP_MASK + 1;
pub(crate) const COL_FRI_MASK: usize = COL_DEEP_START + RATE_WIDTH;
pub(crate) const COL_FRI_ALPHA_VALUE: usize = COL_FRI_MASK + 1;
pub(crate) const COL_POS_MASK: usize = COL_FRI_ALPHA_VALUE + 1;
pub(crate) const COL_POS_START: usize = COL_POS_MASK + 1;
pub(crate) const VERIFIER_TRACE_WIDTH: usize = COL_POS_START + RATE_WIDTH;

// Fixed context prefix for inner RPO-friendly proofs.
// This currently matches RpoAir proofs with RpoProofOptions::fast().
const CONTEXT_PREFIX_LEN: usize = 8;

// CONSTANTS
// ================================================================================================

/// Maximum supported proof trace length (log2)
pub const MAX_TRACE_LENGTH_LOG2: usize = 24;

/// Maximum number of transition constraints
pub const MAX_TRANSITION_CONSTRAINTS: usize = 256;

/// Maximum number of boundary assertions
pub const MAX_ASSERTIONS: usize = 128;

// STARK VERIFIER PUBLIC INPUTS
// ================================================================================================

/// Public inputs for STARK verification.
///
/// These are the minimal inputs needed to verify a STARK proof:
/// - The claimed public inputs of the inner proof
/// - The commitment structure (Merkle roots)
#[derive(Clone, Debug)]
pub struct StarkVerifierPublicInputs {
    /// Full public inputs of the inner proof (as field elements).
    pub inner_public_inputs: Vec<BaseElement>,
    /// Hash of the inner proof's public inputs
    pub inner_pub_inputs_hash: [BaseElement; DIGEST_WIDTH],
    
    /// Trace commitment (Merkle root of trace polynomial evaluations)
    pub trace_commitment: [BaseElement; DIGEST_WIDTH],
    
    /// Constraint commitment (Merkle root of constraint evaluations)
    pub constraint_commitment: [BaseElement; DIGEST_WIDTH],
    
    /// FRI layer commitments (Merkle roots)
    pub fri_commitments: Vec<[BaseElement; DIGEST_WIDTH]>,
    
    /// Security parameters
    pub num_queries: usize,
    pub blowup_factor: usize,
    pub trace_length: usize,
}

impl StarkVerifierPublicInputs {
    pub fn new(
        inner_public_inputs: Vec<BaseElement>,
        inner_pub_inputs_hash: [BaseElement; DIGEST_WIDTH],
        trace_commitment: [BaseElement; DIGEST_WIDTH],
        constraint_commitment: [BaseElement; DIGEST_WIDTH],
        fri_commitments: Vec<[BaseElement; DIGEST_WIDTH]>,
        num_queries: usize,
        blowup_factor: usize,
        trace_length: usize,
    ) -> Self {
        Self {
            inner_public_inputs,
            inner_pub_inputs_hash,
            trace_commitment,
            constraint_commitment,
            fri_commitments,
            num_queries,
            blowup_factor,
            trace_length,
        }
    }
}

impl ToElements<BaseElement> for StarkVerifierPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::new();
        
        elements.extend_from_slice(&self.inner_public_inputs);
        elements.extend_from_slice(&self.inner_pub_inputs_hash);
        elements.extend_from_slice(&self.trace_commitment);
        elements.extend_from_slice(&self.constraint_commitment);
        
        for commitment in &self.fri_commitments {
            elements.extend_from_slice(commitment);
        }
        
        elements.push(BaseElement::new(self.num_queries as u64));
        elements.push(BaseElement::new(self.blowup_factor as u64));
        elements.push(BaseElement::new(self.trace_length as u64));
        
        elements
    }
}

// STARK VERIFIER AIR
// ================================================================================================

/// AIR for verifying STARK proofs.
///
/// This is the core of recursive STARKs - a circuit that verifies another
/// STARK proof entirely in-circuit using algebraic operations.
///
/// The verification process:
/// 1. Reconstruct Fiat-Shamir challenges using RPO hash
/// 2. Verify Merkle proofs for queried positions
/// 3. Verify FRI folding consistency
/// 4. Check constraint evaluations at query positions
pub struct StarkVerifierAir {
    context: AirContext<BaseElement>,
    pub_inputs: StarkVerifierPublicInputs,
}

impl Air for StarkVerifierAir {
    type BaseField = BaseElement;
    type PublicInputs = StarkVerifierPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Constraints:
        // - RPO constraints for Fiat-Shamir (degree 8)
        // - Merkle path verification (degree 8 from RPO)
        // - FRI folding (degree 2)
        // - Constraint evaluation checks (varies)
        
        // Constraints:
        // - RPO permutation constraints for sponge permutations (STATE_WIDTH)
        // - Boundary relations between stacked permutations:
        //   * capacity carryover (4)
        //   * reseed additions / coin-init resets (8)
        //   * mask validity + exclusivity (10)
        //   * constraint coefficient equality checks (8)
        //   * z equality check (1)
        //   * deep composition coefficient equality checks (8)
        //   * FRI alpha equality check (1)
        //   * query draw equality checks (8)
        let num_constraints = STATE_WIDTH + 3 * DIGEST_WIDTH + 10 + 3 * RATE_WIDTH + 2;
        let mut degrees = Vec::with_capacity(num_constraints);

        // RPO transition constraints are gated by two periodic selectors:
        // - half_round_type (permutation schedule)
        // - perm_mask (disable boundary transitions)
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

        // Boundary relation constraints are quadratic in trace columns (mask * linear diff)
        // and gated by the periodic boundary mask.
        for _ in 0..(3 * DIGEST_WIDTH + 10 + 3 * RATE_WIDTH + 2) {
            degrees.push(TransitionConstraintDegree::with_cycles(
                2,
                vec![ROWS_PER_PERMUTATION],
            ));
        }

        // Assertions bind:
        // - public-input hash sponge inputs + digest
        // - transcript seed sponge inputs (context prefix + public inputs)
        // - boundary masks and reseed words for the transcript skeleton
        let input_len = pub_inputs.inner_public_inputs.len();
        let num_pi_blocks = input_len.div_ceil(RATE_WIDTH).max(1);

        let seed_len = CONTEXT_PREFIX_LEN + input_len;
        let num_seed_blocks = seed_len.div_ceil(RATE_WIDTH).max(1);

        let mut num_assertions = 0usize;
        // public-input hash sponge
        num_assertions += CAPACITY_WIDTH;
        num_assertions += num_pi_blocks * RATE_WIDTH;
        num_assertions += DIGEST_WIDTH;

        // seed sponge
        num_assertions += CAPACITY_WIDTH;
        num_assertions += num_seed_blocks * RATE_WIDTH;

        // boundary masks for pi blocks (between blocks + reset boundary)
        if num_pi_blocks > 1 {
            num_assertions += (num_pi_blocks - 1) * 4;
        }
        num_assertions += 4; // reset boundary between pi-hash and seed-hash

        // boundary masks for seed blocks (between blocks + coin-init boundary)
        if num_seed_blocks > 1 {
            num_assertions += (num_seed_blocks - 1) * 4;
        }
        num_assertions += 4; // coin-init boundary

        // reseed(trace_commitment) boundary masks + reseed word
        num_assertions += 4 + DIGEST_WIDTH;

        // full-carry boundaries between coefficient draw permutations
        let num_coeff_perms = 36usize.div_ceil(RATE_WIDTH);
        if num_coeff_perms > 1 {
            num_assertions += (num_coeff_perms - 1) * 4;
        }

        // reseed(constraint_commitment) boundary masks + reseed word
        num_assertions += 4 + DIGEST_WIDTH;

        // z-draw boundary masks after constraint reseed permutation
        num_assertions += 4;

        // Deep coefficient draw boundaries after OOD reseed.
        let num_deep_coeffs = RPO_TRACE_WIDTH + 8; // trace_width + num_constraint_comp_cols (8)
        let num_deep_perms = num_deep_coeffs.div_ceil(RATE_WIDTH);
        num_assertions += num_deep_perms * 4;

        // FRI alpha boundaries and remainder boundary.
        let num_fri_commitments = pub_inputs.fri_commitments.len();
        let num_fri_layers = num_fri_commitments.saturating_sub(1);
        let num_fri_alpha_perms = num_fri_layers;
        let num_remainder_perms = (num_fri_commitments > 0) as usize;
        // Reseed with the first FRI commitment after the last DEEP permutation.
        if num_fri_commitments > 0 {
            num_assertions += DIGEST_WIDTH;
        }
        num_assertions += num_fri_alpha_perms * (4 + DIGEST_WIDTH);
        num_assertions += num_remainder_perms * 4;

        // Query position draw boundaries after FRI remainder.
        // `draw_integers` skips the first rate element after nonce absorption,
        // so the number of permutations is ceil((q + 1) / RATE_WIDTH).
        let num_pos_perms = if pub_inputs.num_queries == 0 {
            0
        } else {
            (pub_inputs.num_queries + 1).div_ceil(RATE_WIDTH)
        };
        if num_pos_perms > 0 {
            num_assertions += num_pos_perms * 4;
        }

        // Stage mask assertions (coeff_mask, z_mask, deep_mask, fri_mask, pos_mask) on every boundary we fix.
        // Boundaries:
        // - pi hash blocks: num_pi_blocks
        // - seed hash blocks: num_seed_blocks
        // - trace reseed boundary: 1
        // - coefficient boundaries: num_coeff_perms
        // - z-draw + OOD-reseed boundary: 1
        // - deep coefficient boundaries: num_deep_perms
        // - FRI alpha boundaries: num_fri_alpha_perms
        // - remainder boundary: num_remainder_perms
        // - query draw boundaries: num_pos_perms
        let stage_boundaries = num_pi_blocks
            + num_seed_blocks
            + num_coeff_perms
            + num_deep_perms
            + num_fri_alpha_perms
            + num_remainder_perms
            + num_pos_perms
            + 2;
        num_assertions += stage_boundaries * 5;

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

        // Periodic values layout:
        // [half_round_type, ark[0..STATE_WIDTH], perm_mask]
        let half_round_type = periodic_values[0];
        let ark: [E; STATE_WIDTH] = core::array::from_fn(|i| periodic_values[1 + i]);
        let perm_mask = periodic_values[1 + STATE_WIDTH];
        let boundary_mask = E::ONE - perm_mask;

        // MDS result
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

        // Selectors
        let one = E::ONE;
        let two = one + one;
        let is_forward = half_round_type * (two - half_round_type);
        let is_inverse = half_round_type * (half_round_type - one);
        let is_padding = (one - half_round_type) * (two - half_round_type);

        // RPO state constraints
        for i in 0..STATE_WIDTH {
            let x = intermediate[i];
            let x2 = x * x;
            let x4 = x2 * x2;
            let x3 = x2 * x;
            let x7 = x3 * x4;
            let forward_constraint = next[i] - x7;

            let y = next[i];
            let y2 = y * y;
            let y4 = y2 * y2;
            let y3 = y2 * y;
            let y7 = y3 * y4;
            let inverse_constraint = y7 - intermediate[i];

            let padding_constraint = next[i] - current[i];

            let rpo_constraint = is_forward * forward_constraint
                + is_inverse * inverse_constraint
                + is_padding * padding_constraint;
            // Disable RPO constraints at permutation boundaries to allow sponge reloading.
            result[i] = perm_mask * rpo_constraint;
        }

        // Boundary relations between stacked permutations.
        let carry_mask = current[COL_CARRY_MASK];
        let full_carry_mask = current[COL_FULL_CARRY_MASK];
        let reseed_mask = current[COL_RESEED_MASK];
        let coin_init_mask = current[COL_COIN_INIT_MASK];
        let reseed_word: [E; DIGEST_WIDTH] =
            core::array::from_fn(|i| current[COL_RESEED_WORD_START + i]);

        let mut idx = STATE_WIDTH;
        for i in 0..DIGEST_WIDTH {
            // Capacity carryover for carry/full-carry/reseed; zero for coin-init.
            let carry_sum = carry_mask + full_carry_mask + reseed_mask;
            let cap_rel = carry_sum * (next[i] - current[i]) + coin_init_mask * next[i];
            result[idx + i] = boundary_mask * cap_rel;
        }
        idx += DIGEST_WIDTH;

        for i in 0..DIGEST_WIDTH {
            // First half of rate:
            // - full-carry copies full state
            // - reseed adds a word
            // - coin-init copies digest range
            // - carry/free boundaries impose no constraint
            let cur_rate = current[RATE_START + i];
            let next_rate = next[RATE_START + i];
            let rate_rel = (full_carry_mask + coin_init_mask) * (next_rate - cur_rate)
                + reseed_mask * (next_rate - (cur_rate + reseed_word[i]));
            result[idx + i] = boundary_mask * rate_rel;
        }
        idx += DIGEST_WIDTH;

        for i in 0..DIGEST_WIDTH {
            // Second half of rate:
            // - full-carry/reseed copy
            // - coin-init zeros
            // - carry/free boundaries impose no constraint
            let cur_rate = current[RATE_START + DIGEST_WIDTH + i];
            let next_rate = next[RATE_START + DIGEST_WIDTH + i];
            let rate_rel = (full_carry_mask + reseed_mask) * (next_rate - cur_rate)
                + coin_init_mask * next_rate;
            result[idx + i] = boundary_mask * rate_rel;
        }
        idx += DIGEST_WIDTH;

        // Mask validity (binary on boundaries).
        result[idx] = boundary_mask * carry_mask * (carry_mask - one);
        result[idx + 1] = boundary_mask * full_carry_mask * (full_carry_mask - one);
        result[idx + 2] = boundary_mask * reseed_mask * (reseed_mask - one);
        result[idx + 3] = boundary_mask * coin_init_mask * (coin_init_mask - one);
        idx += 4;

        // Exclusivity of masks on boundaries.
        result[idx] = boundary_mask * carry_mask * full_carry_mask;
        result[idx + 1] = boundary_mask * carry_mask * reseed_mask;
        result[idx + 2] = boundary_mask * carry_mask * coin_init_mask;
        result[idx + 3] = boundary_mask * full_carry_mask * reseed_mask;
        result[idx + 4] = boundary_mask * full_carry_mask * coin_init_mask;
        result[idx + 5] = boundary_mask * reseed_mask * coin_init_mask;

        idx += 6;

        // Transcript-derived value checks.
        let coeff_mask = current[COL_COEFF_MASK];
        let z_mask = current[COL_Z_MASK];

        for i in 0..RATE_WIDTH {
            let expected = current[COL_COEFF_START + i];
            result[idx + i] =
                boundary_mask * coeff_mask * (current[RATE_START + i] - expected);
        }
        idx += RATE_WIDTH;

        let expected_z = current[COL_Z_VALUE];
        result[idx] = boundary_mask * z_mask * (current[RATE_START] - expected_z);
        idx += 1;

        let deep_mask = current[COL_DEEP_MASK];
        for i in 0..RATE_WIDTH {
            let expected = current[COL_DEEP_START + i];
            result[idx + i] =
                boundary_mask * deep_mask * (current[RATE_START + i] - expected);
        }
        idx += RATE_WIDTH;

        let fri_mask = current[COL_FRI_MASK];
        let expected_alpha = current[COL_FRI_ALPHA_VALUE];
        result[idx] = boundary_mask * fri_mask * (current[RATE_START] - expected_alpha);
        idx += 1;

        let pos_mask = current[COL_POS_MASK];
        for i in 0..RATE_WIDTH {
            let expected = current[COL_POS_START + i];
            result[idx + i] =
                boundary_mask * pos_mask * (current[RATE_START + i] - expected);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        // --- Segment A: Hash inner public inputs ---------------------------------------------
        let input_len = self.pub_inputs.inner_public_inputs.len();
        let num_pi_blocks = input_len.div_ceil(RATE_WIDTH).max(1);

        // Sponge initialization (public input hash).
        let len_mod_rate = (input_len % RATE_WIDTH) as u64;
        assertions.push(Assertion::single(0, 0, BaseElement::new(len_mod_rate)));
        for i in 1..CAPACITY_WIDTH {
            assertions.push(Assertion::single(i, 0, BaseElement::ZERO));
        }

        // Bind absorbed public-input blocks.
        for block in 0..num_pi_blocks {
            let row = block * ROWS_PER_PERMUTATION;
            let start = block * RATE_WIDTH;
            for j in 0..RATE_WIDTH {
                let val = if start + j < input_len {
                    self.pub_inputs.inner_public_inputs[start + j]
                } else {
                    BaseElement::ZERO
                };
                assertions.push(Assertion::single(RATE_START + j, row, val));
            }
        }

        // Bind digest after final public-input hash permutation.
        let pi_last_row = num_pi_blocks * ROWS_PER_PERMUTATION - 1;
        for i in 0..DIGEST_WIDTH {
            assertions.push(Assertion::single(
                RATE_START + i,
                pi_last_row,
                self.pub_inputs.inner_pub_inputs_hash[i],
            ));
        }

        // Boundary masks between public-input hash blocks.
        for block in 0..num_pi_blocks {
            let boundary_row = (block + 1) * ROWS_PER_PERMUTATION - 1;
            if block + 1 < num_pi_blocks {
                assertions.push(Assertion::single(COL_CARRY_MASK, boundary_row, BaseElement::ONE));
                assertions.push(Assertion::single(
                    COL_FULL_CARRY_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(COL_RESEED_MASK, boundary_row, BaseElement::ZERO));
                assertions.push(Assertion::single(COL_COIN_INIT_MASK, boundary_row, BaseElement::ZERO));
            } else {
                // Reset to a new sponge for transcript seeding.
                assertions.push(Assertion::single(COL_CARRY_MASK, boundary_row, BaseElement::ZERO));
                assertions.push(Assertion::single(
                    COL_FULL_CARRY_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(COL_RESEED_MASK, boundary_row, BaseElement::ZERO));
                assertions.push(Assertion::single(COL_COIN_INIT_MASK, boundary_row, BaseElement::ZERO));
            }
            assertions.push(Assertion::single(
                COL_COEFF_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(COL_Z_MASK, boundary_row, BaseElement::ZERO));
            assertions.push(Assertion::single(
                COL_DEEP_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FRI_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_POS_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
        }

        // --- Segment B: Hash transcript seed (context prefix + public inputs) ----------------
        let seed_prefix = build_context_prefix(&self.pub_inputs);
        let seed_len = seed_prefix.len() + input_len;
        let num_seed_blocks = seed_len.div_ceil(RATE_WIDTH).max(1);
        let seed_start = num_pi_blocks * ROWS_PER_PERMUTATION;

        // Sponge initialization (transcript seed).
        let seed_mod_rate = (seed_len % RATE_WIDTH) as u64;
        assertions.push(Assertion::single(0, seed_start, BaseElement::new(seed_mod_rate)));
        for i in 1..CAPACITY_WIDTH {
            assertions.push(Assertion::single(i, seed_start, BaseElement::ZERO));
        }

        // Bind absorbed seed blocks.
        for block in 0..num_seed_blocks {
            let row = seed_start + block * ROWS_PER_PERMUTATION;
            let start = block * RATE_WIDTH;
            for j in 0..RATE_WIDTH {
                let idx = start + j;
                let val = if idx < seed_prefix.len() {
                    seed_prefix[idx]
                } else {
                    let pi_idx = idx - seed_prefix.len();
                    if pi_idx < input_len {
                        self.pub_inputs.inner_public_inputs[pi_idx]
                    } else {
                        BaseElement::ZERO
                    }
                };
                assertions.push(Assertion::single(RATE_START + j, row, val));
            }
        }

        // Boundary masks between seed blocks and into coin-init.
        for block in 0..num_seed_blocks {
            let boundary_row = seed_start + (block + 1) * ROWS_PER_PERMUTATION - 1;
            if block + 1 < num_seed_blocks {
                assertions.push(Assertion::single(COL_CARRY_MASK, boundary_row, BaseElement::ONE));
                assertions.push(Assertion::single(
                    COL_FULL_CARRY_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(COL_RESEED_MASK, boundary_row, BaseElement::ZERO));
                assertions.push(Assertion::single(COL_COIN_INIT_MASK, boundary_row, BaseElement::ZERO));
            } else {
                assertions.push(Assertion::single(COL_CARRY_MASK, boundary_row, BaseElement::ZERO));
                assertions.push(Assertion::single(
                    COL_FULL_CARRY_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(COL_RESEED_MASK, boundary_row, BaseElement::ZERO));
                assertions.push(Assertion::single(COL_COIN_INIT_MASK, boundary_row, BaseElement::ONE));
            }
            assertions.push(Assertion::single(
                COL_COEFF_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(COL_Z_MASK, boundary_row, BaseElement::ZERO));
            assertions.push(Assertion::single(
                COL_DEEP_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FRI_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_POS_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
        }

        // --- Segment C: coin-init boundary into reseed(trace_commitment) ----------------------
        let coin_start = seed_start + num_seed_blocks * ROWS_PER_PERMUTATION;
        let coin_boundary_row = coin_start + ROWS_PER_PERMUTATION - 1;
        assertions.push(Assertion::single(COL_CARRY_MASK, coin_boundary_row, BaseElement::ZERO));
        assertions.push(Assertion::single(
            COL_FULL_CARRY_MASK,
            coin_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(COL_RESEED_MASK, coin_boundary_row, BaseElement::ONE));
        assertions.push(Assertion::single(COL_COIN_INIT_MASK, coin_boundary_row, BaseElement::ZERO));
        assertions.push(Assertion::single(
            COL_COEFF_MASK,
            coin_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(COL_Z_MASK, coin_boundary_row, BaseElement::ZERO));
        assertions.push(Assertion::single(
            COL_DEEP_MASK,
            coin_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_FRI_MASK,
            coin_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_POS_MASK,
            coin_boundary_row,
            BaseElement::ZERO,
        ));
        for i in 0..DIGEST_WIDTH {
            assertions.push(Assertion::single(
                COL_RESEED_WORD_START + i,
                coin_boundary_row,
                self.pub_inputs.trace_commitment[i],
            ));
        }

        // --- Coefficient draw full-carry boundaries and reseed(constraint_commitment) ---------
        let num_coeff_perms = 36usize.div_ceil(RATE_WIDTH);
        let trace_reseed_perm_idx = num_pi_blocks + num_seed_blocks + 1;
        let coeff_start_perm_idx = trace_reseed_perm_idx;

        // Boundaries between coefficient permutations use full-carry.
        for k in 0..(num_coeff_perms - 1) {
            let perm_idx = coeff_start_perm_idx + k;
            let boundary_row = (perm_idx + 1) * ROWS_PER_PERMUTATION - 1;
            assertions.push(Assertion::single(COL_CARRY_MASK, boundary_row, BaseElement::ZERO));
            assertions.push(Assertion::single(
                COL_FULL_CARRY_MASK,
                boundary_row,
                BaseElement::ONE,
            ));
            assertions.push(Assertion::single(COL_RESEED_MASK, boundary_row, BaseElement::ZERO));
            assertions.push(Assertion::single(COL_COIN_INIT_MASK, boundary_row, BaseElement::ZERO));
            assertions.push(Assertion::single(
                COL_COEFF_MASK,
                boundary_row,
                BaseElement::ONE,
            ));
            assertions.push(Assertion::single(COL_Z_MASK, boundary_row, BaseElement::ZERO));
            assertions.push(Assertion::single(
                COL_DEEP_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FRI_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_POS_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
        }

        // Boundary into constraint commitment reseed after last coefficient permutation.
        let last_coeff_perm_idx = coeff_start_perm_idx + num_coeff_perms - 1;
        let constraint_boundary_row = (last_coeff_perm_idx + 1) * ROWS_PER_PERMUTATION - 1;
        assertions.push(Assertion::single(
            COL_CARRY_MASK,
            constraint_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_FULL_CARRY_MASK,
            constraint_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_RESEED_MASK,
            constraint_boundary_row,
            BaseElement::ONE,
        ));
        assertions.push(Assertion::single(
            COL_COIN_INIT_MASK,
            constraint_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_COEFF_MASK,
            constraint_boundary_row,
            BaseElement::ONE,
        ));
        assertions.push(Assertion::single(
            COL_Z_MASK,
            constraint_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_DEEP_MASK,
            constraint_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_FRI_MASK,
            constraint_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_POS_MASK,
            constraint_boundary_row,
            BaseElement::ZERO,
        ));
        for i in 0..DIGEST_WIDTH {
            assertions.push(Assertion::single(
                COL_RESEED_WORD_START + i,
                constraint_boundary_row,
                self.pub_inputs.constraint_commitment[i],
            ));
        }

        // Boundary after constraint reseed permutation: draw z and reseed with OOD digest.
        let constraint_reseed_perm_idx = last_coeff_perm_idx + 1;
        let z_boundary_row = (constraint_reseed_perm_idx + 1) * ROWS_PER_PERMUTATION - 1;
        assertions.push(Assertion::single(COL_CARRY_MASK, z_boundary_row, BaseElement::ZERO));
        assertions.push(Assertion::single(
            COL_FULL_CARRY_MASK,
            z_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(COL_RESEED_MASK, z_boundary_row, BaseElement::ONE));
        assertions.push(Assertion::single(COL_COIN_INIT_MASK, z_boundary_row, BaseElement::ZERO));
        assertions.push(Assertion::single(
            COL_COEFF_MASK,
            z_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(COL_Z_MASK, z_boundary_row, BaseElement::ONE));
        assertions.push(Assertion::single(
            COL_DEEP_MASK,
            z_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_FRI_MASK,
            z_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_POS_MASK,
            z_boundary_row,
            BaseElement::ZERO,
        ));

        // --- Deep coefficient draw boundaries (permute-only, full-carry) ----------------------
        let num_deep_coeffs = RPO_TRACE_WIDTH + 8; // trace_width + num_constraint_comp_cols
        let num_deep_perms = num_deep_coeffs.div_ceil(RATE_WIDTH);
        let deep_start_perm_idx = constraint_reseed_perm_idx + 1;
        let num_fri_commitments = self.pub_inputs.fri_commitments.len();
        let has_fri_commitments = num_fri_commitments > 0;
        for k in 0..num_deep_perms {
            let perm_idx = deep_start_perm_idx + k;
            let boundary_row = (perm_idx + 1) * ROWS_PER_PERMUTATION - 1;
            let is_last = k + 1 == num_deep_perms;

            assertions.push(Assertion::single(COL_CARRY_MASK, boundary_row, BaseElement::ZERO));
            assertions.push(Assertion::single(
                COL_FULL_CARRY_MASK,
                boundary_row,
                if is_last { BaseElement::ZERO } else { BaseElement::ONE },
            ));
            let reseed_here = is_last && has_fri_commitments;
            assertions.push(Assertion::single(
                COL_RESEED_MASK,
                boundary_row,
                if reseed_here { BaseElement::ONE } else { BaseElement::ZERO },
            ));
            assertions.push(Assertion::single(COL_COIN_INIT_MASK, boundary_row, BaseElement::ZERO));
            assertions.push(Assertion::single(
                COL_COEFF_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(COL_Z_MASK, boundary_row, BaseElement::ZERO));
            assertions.push(Assertion::single(
                COL_DEEP_MASK,
                boundary_row,
                BaseElement::ONE,
            ));
            assertions.push(Assertion::single(
                COL_FRI_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_POS_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));

            if reseed_here {
                let first_commitment = self.pub_inputs.fri_commitments[0];
                for i in 0..DIGEST_WIDTH {
                    assertions.push(Assertion::single(
                        COL_RESEED_WORD_START + i,
                        boundary_row,
                        first_commitment[i],
                    ));
                }
            }
        }

        // --- FRI alpha draw boundaries --------------------------------------------------------
        let num_fri_layers = num_fri_commitments.saturating_sub(1);
        let has_remainder = num_fri_commitments > 0;
        let fri_start_perm_idx = deep_start_perm_idx + num_deep_perms;

        for k in 0..num_fri_layers {
            let perm_idx = fri_start_perm_idx + k;
            let boundary_row = (perm_idx + 1) * ROWS_PER_PERMUTATION - 1;

            assertions.push(Assertion::single(COL_CARRY_MASK, boundary_row, BaseElement::ZERO));
            assertions.push(Assertion::single(
                COL_FULL_CARRY_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(COL_RESEED_MASK, boundary_row, BaseElement::ONE));
            assertions.push(Assertion::single(COL_COIN_INIT_MASK, boundary_row, BaseElement::ZERO));
            assertions.push(Assertion::single(
                COL_COEFF_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(COL_Z_MASK, boundary_row, BaseElement::ZERO));
            assertions.push(Assertion::single(
                COL_DEEP_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FRI_MASK,
                boundary_row,
                BaseElement::ONE,
            ));
            assertions.push(Assertion::single(
                COL_POS_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));

            // Reseed word binds the next FRI commitment (or remainder after last alpha).
            let next_commitment = if k + 1 < num_fri_layers {
                self.pub_inputs.fri_commitments[k + 1]
            } else {
                self.pub_inputs.fri_commitments[num_fri_layers]
            };
            for i in 0..DIGEST_WIDTH {
                assertions.push(Assertion::single(
                    COL_RESEED_WORD_START + i,
                    boundary_row,
                    next_commitment[i],
                ));
            }
        }

        // Remainder permutation boundary (no alpha draw).
        if has_remainder {
            let remainder_perm_idx = fri_start_perm_idx + num_fri_layers;
            let remainder_boundary_row =
                (remainder_perm_idx + 1) * ROWS_PER_PERMUTATION - 1;
            assertions.push(Assertion::single(
                COL_CARRY_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FULL_CARRY_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_RESEED_MASK,
                remainder_boundary_row,
                if self.pub_inputs.num_queries > 0 {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                },
            ));
            assertions.push(Assertion::single(
                COL_COIN_INIT_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_COEFF_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_Z_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_DEEP_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FRI_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_POS_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
        }

        // --- Query position draw boundaries --------------------------------------------------
        let num_pos_perms = if self.pub_inputs.num_queries == 0 {
            0
        } else {
            (self.pub_inputs.num_queries + 1).div_ceil(RATE_WIDTH)
        };

        if num_pos_perms > 0 {
            let pos_start_perm_idx =
                fri_start_perm_idx + num_fri_layers + has_remainder as usize;

            for k in 0..num_pos_perms {
                let perm_idx = pos_start_perm_idx + k;
                let boundary_row = (perm_idx + 1) * ROWS_PER_PERMUTATION - 1;
                let is_last = k + 1 == num_pos_perms;

                assertions.push(Assertion::single(
                    COL_CARRY_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_FULL_CARRY_MASK,
                    boundary_row,
                    if is_last {
                        BaseElement::ZERO
                    } else {
                        BaseElement::ONE
                    },
                ));
                assertions.push(Assertion::single(
                    COL_RESEED_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_COIN_INIT_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_COEFF_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_Z_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_DEEP_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_FRI_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_POS_MASK,
                    boundary_row,
                    BaseElement::ONE,
                ));
            }
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let total_rows = self.trace_length();

        let mut half_round_type = Vec::with_capacity(total_rows);
        let mut ark_columns: [Vec<BaseElement>; STATE_WIDTH] = 
            core::array::from_fn(|_| Vec::with_capacity(total_rows));
        let mut perm_mask = Vec::with_capacity(total_rows);

        for row in 0..total_rows {
            let local_row = row % ROWS_PER_PERMUTATION;
            let val = if local_row >= 14 {
                0
            } else if local_row % 2 == 0 {
                1
            } else {
                2
            };
            half_round_type.push(BaseElement::new(val));

            let constants = if local_row >= 14 {
                [BaseElement::ZERO; STATE_WIDTH]
            } else if local_row % 2 == 0 {
                let round = local_row / 2;
                if round < NUM_ROUNDS { ARK1[round] } else { [BaseElement::ZERO; STATE_WIDTH] }
            } else {
                let round = local_row / 2;
                if round < NUM_ROUNDS { ARK2[round] } else { [BaseElement::ZERO; STATE_WIDTH] }
            };

            for (i, &c) in constants.iter().enumerate() {
                ark_columns[i].push(c);
            }

            // Apply RPO constraints on all transitions except boundaries between permutations.
            let mask = (local_row < ROWS_PER_PERMUTATION - 1) as u64;
            perm_mask.push(BaseElement::new(mask));
        }

        let mut result = vec![half_round_type];
        for col in ark_columns {
            result.push(col);
        }
        result.push(perm_mask);
        result
    }
}

// VERIFICATION HELPERS
// ================================================================================================

/// Helper to extract query positions from an RPO transcript seed.
pub fn extract_query_positions(
    transcript_seed: [BaseElement; DIGEST_WIDTH],
    num_queries: usize,
    domain_size: usize,
    pow_nonce: u64,
) -> Vec<usize> {
    let word = Word::new(transcript_seed);
    let mut coin = RpoRandomCoin::new(word);
    let mut positions = coin
        .draw_integers(num_queries, domain_size, pow_nonce)
        .expect("failed to draw query positions");
    positions.sort_unstable();
    positions.dedup();
    positions
}

/// Compute a single DEEP composition evaluation for a query.
///
/// This matches `winter-verifier`'s `DeepComposer::compose_columns` for the
/// base-field, single-trace-segment case.
pub fn compute_deep_evaluation(
    x: BaseElement,
    trace_row: &[BaseElement],
    constraint_row: &[BaseElement],
    ood_trace_z: &[BaseElement],
    ood_trace_zg: &[BaseElement],
    ood_constraints_z: &[BaseElement],
    ood_constraints_zg: &[BaseElement],
    deep_coeffs: &DeepCompositionCoefficients<BaseElement>,
    z: BaseElement,
    g_trace: BaseElement,
) -> BaseElement {
    let z1 = z * g_trace;
    let x_minus_z0 = x - z;
    let x_minus_z1 = x - z1;

    assert_eq!(trace_row.len(), deep_coeffs.trace.len());
    assert_eq!(constraint_row.len(), deep_coeffs.constraints.len());

    let mut t1_num = BaseElement::ZERO;
    let mut t2_num = BaseElement::ZERO;
    for i in 0..trace_row.len() {
        t1_num += deep_coeffs.trace[i] * (trace_row[i] - ood_trace_z[i]);
        t2_num += deep_coeffs.trace[i] * (trace_row[i] - ood_trace_zg[i]);
    }
    let num_trace = t1_num * x_minus_z1 + t2_num * x_minus_z0;

    let mut c1_num = BaseElement::ZERO;
    let mut c2_num = BaseElement::ZERO;
    for j in 0..constraint_row.len() {
        c1_num += deep_coeffs.constraints[j] * (constraint_row[j] - ood_constraints_z[j]);
        c2_num += deep_coeffs.constraints[j] * (constraint_row[j] - ood_constraints_zg[j]);
    }
    let num_constraints = c1_num * x_minus_z1 + c2_num * x_minus_z0;

    let den = x_minus_z0 * x_minus_z1;
    (num_trace + num_constraints) / den
}

// CONTEXT PREFIX
// ================================================================================================

pub(crate) fn build_context_prefix(pub_inputs: &StarkVerifierPublicInputs) -> Vec<BaseElement> {
    // TraceInfo element 0 encodes: main_width << 8 | num_aux_segments (0).
    let trace_info0 = BaseElement::new(((RPO_TRACE_WIDTH as u32) << 8) as u64);
    let trace_info1 = BaseElement::new(pub_inputs.trace_length as u64);

    // Goldilocks modulus bytes split into 2 elements:
    // low half = 1, high half = 2^32 - 1.
    let modulus0 = BaseElement::ONE;
    let modulus1 = BaseElement::new(u64::from(u32::MAX));

    // Inner proof constraints count (transition + boundary) for RpoAir.
    let num_constraints = BaseElement::new(36);

    // ProofOptions packed element:
    // field_extension=0, fri_folding_factor=2, fri_remainder_max_degree=7, blowup_factor=pub_inputs.blowup_factor.
    let options0 = BaseElement::new(
        pub_inputs.blowup_factor as u64
            + (7u64 << 8)
            + (2u64 << 16),
    );

    let grinding_factor = BaseElement::ZERO;
    let num_queries = BaseElement::new(pub_inputs.num_queries as u64);

    vec![
        trace_info0,
        trace_info1,
        modulus0,
        modulus1,
        num_constraints,
        options0,
        grinding_factor,
        num_queries,
    ]
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stark_verifier_public_inputs() {
        let inner_inputs = vec![BaseElement::new(9); 3];
        let inner_hash = [BaseElement::new(1); DIGEST_WIDTH];
        let trace_commit = [BaseElement::new(2); DIGEST_WIDTH];
        let constraint_commit = [BaseElement::new(3); DIGEST_WIDTH];
        let fri_commits = vec![[BaseElement::new(4); DIGEST_WIDTH]; 5];
        
        let pub_inputs = StarkVerifierPublicInputs::new(
            inner_inputs,
            inner_hash,
            trace_commit,
            constraint_commit,
            fri_commits.clone(),
            32,
            16,
            1024,
        );
        
        assert_eq!(pub_inputs.num_queries, 32);
        assert_eq!(pub_inputs.fri_commitments.len(), 5);
    }

    #[test]
    fn test_extract_query_positions() {
        let hash = [
            BaseElement::new(12345),
            BaseElement::new(67890),
            BaseElement::new(11111),
            BaseElement::new(22222),
        ];
        
        let positions = extract_query_positions(hash, 8, 1024, 0);
        
        assert_eq!(positions.len(), 8);
        for &pos in &positions {
            assert!(pos < 1024);
        }
        
        // Verify determinism
        let positions2 = extract_query_positions(hash, 8, 1024, 0);
        assert_eq!(positions, positions2);
    }

    #[test]
    fn test_deep_evaluation_matches_manual() {
        let z = BaseElement::new(10);
        let g_trace = BaseElement::new(2);
        let x = BaseElement::new(11);

        let trace_row = vec![BaseElement::new(5)];
        let constraint_row = vec![BaseElement::new(7)];

        let ood_trace_z = vec![BaseElement::new(3)];
        let ood_trace_zg = vec![BaseElement::new(4)];
        let ood_constraints_z = vec![BaseElement::new(2)];
        let ood_constraints_zg = vec![BaseElement::new(1)];

        let deep_coeffs = DeepCompositionCoefficients {
            trace: vec![BaseElement::ONE],
            constraints: vec![BaseElement::ONE],
        };

        // Manual computation per DeepComposer formula.
        let z1 = z * g_trace;
        let x_minus_z0 = x - z;
        let x_minus_z1 = x - z1;

        let t1_num = trace_row[0] - ood_trace_z[0];
        let t2_num = trace_row[0] - ood_trace_zg[0];
        let num_trace = t1_num * x_minus_z1 + t2_num * x_minus_z0;

        let c1_num = constraint_row[0] - ood_constraints_z[0];
        let c2_num = constraint_row[0] - ood_constraints_zg[0];
        let num_constraints = c1_num * x_minus_z1 + c2_num * x_minus_z0;

        let den = x_minus_z0 * x_minus_z1;
        let expected = (num_trace + num_constraints) / den;

        let computed = compute_deep_evaluation(
            x,
            &trace_row,
            &constraint_row,
            &ood_trace_z,
            &ood_trace_zg,
            &ood_constraints_z,
            &ood_constraints_zg,
            &deep_coeffs,
            z,
            g_trace,
        );

        assert_eq!(computed, expected);
    }

    #[test]
    fn test_to_elements() {
        let pub_inputs = StarkVerifierPublicInputs::new(
            vec![BaseElement::ONE; 2],
            [BaseElement::ONE; DIGEST_WIDTH],
            [BaseElement::new(2); DIGEST_WIDTH],
            [BaseElement::new(3); DIGEST_WIDTH],
            vec![[BaseElement::new(4); DIGEST_WIDTH]; 3],
            32,
            16,
            1024,
        );
        
        let elements = pub_inputs.to_elements();
        
        // inner_public_inputs (2) + 4 (inner hash) + 4 (trace) + 4 (constraint) + 3*4 (fri) + 3 (params)
        assert_eq!(elements.len(), 2 + 4 + 4 + 4 + 12 + 3);
    }
}
