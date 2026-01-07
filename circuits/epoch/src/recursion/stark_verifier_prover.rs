//! Prover for `StarkVerifierAir`.
//!
//! This builds verifier traces which reconstruct the inner proof transcript and
//! verify the inner proof’s Merkle openings, DEEP composition, and FRI folding
//! checks inside the AIR.

use winter_air::{DeepCompositionCoefficients, FieldExtension, ProofOptions};
use winter_crypto::{hashers::Blake3_256, MerkleTree};
use winter_math::{fields::QuadExtension, FieldElement, StarkField};
#[cfg(test)]
use winterfell::Proof;
use winterfell::{
    crypto::DefaultRandomCoin, math::fields::f64::BaseElement, matrix::ColMatrix, AuxRandElements,
    CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions,
    Prover, StarkDomain, Trace, TracePolyTable, TraceTable,
};

use super::fri_air::MAX_FRI_LAYERS;
use super::merkle_air::DIGEST_WIDTH;
use super::recursive_prover::InnerProofData;
use super::rpo_air::{
    ARK1, ARK2, MDS, NUM_ROUNDS, ROWS_PER_PERMUTATION, STATE_WIDTH, TRACE_WIDTH as RPO_TRACE_WIDTH,
};
use super::rpo_proof::{rpo_hash_elements, rpo_merge};
use super::stark_verifier_air::{
    build_context_prefix, compute_deep_evaluation, compute_deep_evaluation_quadratic,
    StarkVerifierAir, StarkVerifierPublicInputs, COL_CARRY_MASK, COL_COEFF_MASK, COL_COEFF_START,
    COL_COIN_INIT_MASK, COL_COIN_RESTORE_MASK, COL_COIN_SAVE_MASK, COL_CONSTRAINT_COEFFS_START,
    COL_DEEP_C1_ACC, COL_DEEP_C1_ACC_LIMB1, COL_DEEP_C2_ACC, COL_DEEP_C2_ACC_LIMB1,
    COL_DEEP_COEFFS_START, COL_DEEP_MASK, COL_DEEP_START, COL_DEEP_T1_ACC, COL_DEEP_T1_ACC_LIMB1,
    COL_DEEP_T2_ACC, COL_DEEP_T2_ACC_LIMB1, COL_FRI_ALPHA_START, COL_FRI_ALPHA_VALUE, COL_FRI_EVAL,
    COL_FRI_EVAL_LIMB1, COL_FRI_MASK, COL_FRI_MSB_BITS_START, COL_FRI_POW, COL_FRI_X,
    COL_FULL_CARRY_MASK, COL_MERKLE_INDEX, COL_MERKLE_PATH_BIT, COL_OOD_DIGEST_START,
    COL_OOD_EVALS_START, COL_POS_ACC, COL_POS_BIT0, COL_POS_BIT1, COL_POS_BIT2, COL_POS_BIT3,
    COL_POS_DECOMP_MASK, COL_POS_HI_AND, COL_POS_LO_ACC, COL_POS_MASK, COL_POS_MASKED_ACC,
    COL_POS_PERM_ACC, COL_POS_PERM_ACC_LIMB1, COL_POS_RAW, COL_POS_SORTED_VALUE, COL_POS_START,
    COL_REMAINDER_COEFFS_EXT_START, COL_REMAINDER_COEFFS_START, COL_RESEED_MASK,
    COL_RESEED_WORD_START, COL_SAVED_COIN_START, COL_TAPE_INDEX, COL_TAPE_KIND, COL_TAPE_MASK,
    COL_TAPE_VALUES_START, COL_Z_MASK, COL_Z_VALUE, COL_Z_VALUE_LIMB1, NUM_CONSTRAINT_COEFFS,
    NUM_DEEP_COEFFS, NUM_FRI_MSB_BITS, NUM_REMAINDER_COEFFS, RATE_WIDTH, TAPE_WIDTH,
    VERIFIER_TRACE_WIDTH,
};
use winter_fri::utils::map_positions_to_indexes;

type Blake3 = Blake3_256<BaseElement>;
type Blake3MerkleTree = MerkleTree<Blake3>;
type Quad = QuadExtension<BaseElement>;
type ExtElem = [BaseElement; 2];

const EXTENSION_LIMBS: usize = 2;
const RESERVED_CONSTRAINT_COEFF_COLS: usize = 2;

fn quad_from_ext(value: ExtElem) -> Quad {
    Quad::new(value[0], value[1])
}

fn ext_from_base(value: BaseElement) -> ExtElem {
    [value, BaseElement::ZERO]
}

fn ext_from_flat(values: &[BaseElement]) -> ExtElem {
    debug_assert!(values.len() >= EXTENSION_LIMBS);
    [values[0], values[1]]
}

const TAPE_KIND_NONE: u64 = 0;
const TAPE_KIND_COEFF: u64 = 1;
const TAPE_KIND_DEEP: u64 = 2;
const TAPE_KIND_ALPHA: u64 = 3;

/// Prover for the minimal StarkVerifierAir.
pub struct StarkVerifierProver {
    options: ProofOptions,
    pub_inputs: StarkVerifierPublicInputs,
}

impl StarkVerifierProver {
    pub fn new(options: ProofOptions, pub_inputs: StarkVerifierPublicInputs) -> Self {
        Self {
            options,
            pub_inputs,
        }
    }

    #[cfg(test)]
    pub fn prove_pub_inputs_hash(
        inner_public_inputs: Vec<BaseElement>,
        options: ProofOptions,
    ) -> Result<(Proof, StarkVerifierPublicInputs), String> {
        let digest = rpo_hash_elements(&inner_public_inputs);
        let trace_length = ROWS_PER_PERMUTATION;
        let blowup_factor = options.blowup_factor();
        let lde_domain_size = trace_length * blowup_factor;
        let depth_trace = if lde_domain_size == 0 {
            0
        } else {
            lde_domain_size.trailing_zeros() as usize
        };

        let compute_dummy_root =
            |leaf: [BaseElement; DIGEST_WIDTH], depth: usize| -> [BaseElement; DIGEST_WIDTH] {
                let mut current = leaf;
                for _ in 0..depth {
                    current = rpo_merge(&current, &current);
                }
                current
            };

        // Dummy trace commitment.
        let dummy_trace_leaf = vec![BaseElement::ZERO; RPO_TRACE_WIDTH];
        let trace_leaf = rpo_hash_elements(&dummy_trace_leaf);
        let trace_root = compute_dummy_root(trace_leaf, depth_trace);

        // Dummy constraint commitment.
        let dummy_constraint_leaf = vec![BaseElement::ZERO; 8];
        let constraint_leaf = rpo_hash_elements(&dummy_constraint_leaf);
        let constraint_root = compute_dummy_root(constraint_leaf, depth_trace);

        // Dummy single FRI layer commitment + remainder commitment.
        let dummy_fri_leaf = vec![BaseElement::ZERO; 2];
        let fri_leaf = rpo_hash_elements(&dummy_fri_leaf);
        let fri_root0 = compute_dummy_root(fri_leaf, depth_trace.saturating_sub(1));
        let dummy_remainder = vec![BaseElement::ZERO; 8];
        let remainder_commitment = rpo_hash_elements(&dummy_remainder);

        let fri_options = options.to_fri_options();
        let pub_inputs = StarkVerifierPublicInputs::new(
            inner_public_inputs.clone(),
            digest,
            trace_root,
            constraint_root,
            vec![BaseElement::ZERO; RPO_TRACE_WIDTH],
            vec![BaseElement::ZERO; 8],
            vec![BaseElement::ZERO; RPO_TRACE_WIDTH],
            vec![BaseElement::ZERO; 8],
            vec![fri_root0, remainder_commitment],
            options.num_queries(),
            options.num_queries(),
            RPO_TRACE_WIDTH,
            8,
            blowup_factor,
            fri_options.folding_factor(),
            fri_options.remainder_max_degree(),
            options.grinding_factor() as usize,
            trace_length,
            RPO_TRACE_WIDTH,
            8,
            STATE_WIDTH,
            2 * STATE_WIDTH,
            winter_air::FieldExtension::None,
        );

        let prover = StarkVerifierProver::new(options.clone(), pub_inputs.clone());
        let trace = prover.build_trace_for_pub_inputs_hash();
        let proof = prover
            .prove(trace)
            .map_err(|e| format!("outer proof generation failed: {e:?}"))?;

        Ok((proof, pub_inputs))
    }

    /// Build a trace which hashes `inner_public_inputs` using the RPO sponge.
    ///
    /// This is a legacy “transcript-only” trace builder and does **not** bind a real inner proof.
    /// Prefer `build_trace_from_inner()`.
    #[deprecated(note = "Transcript-only helper; use build_trace_from_inner() instead.")]
    pub fn build_trace_for_pub_inputs_hash(&self) -> TraceTable<BaseElement> {
        let inputs = &self.pub_inputs.inner_public_inputs;
        let input_len = inputs.len();
        let num_pi_blocks = input_len.div_ceil(8).max(1);

        let seed_prefix = build_context_prefix(&self.pub_inputs);
        let seed_len = seed_prefix.len() + input_len;
        let num_seed_blocks = seed_len.div_ceil(8).max(1);

        let extension_degree = match self.pub_inputs.field_extension {
            FieldExtension::None => 1,
            FieldExtension::Quadratic => 2,
            FieldExtension::Cubic => 3,
        };
        let num_coeffs_total = (self.pub_inputs.num_transition_constraints
            + self.pub_inputs.num_assertions)
            * extension_degree;
        let num_coeff_perms = num_coeffs_total.div_ceil(RATE_WIDTH).max(1);

        let num_deep_coeffs = (self.pub_inputs.trace_width
            + self.pub_inputs.constraint_frame_width)
            * extension_degree;
        let num_deep_perms = num_deep_coeffs.div_ceil(RATE_WIDTH);

        let ood_eval_len = 2 * num_deep_coeffs;
        let num_ood_perms = ood_eval_len.div_ceil(RATE_WIDTH);
        let num_fri_commitments = self.pub_inputs.fri_commitments.len();
        let num_fri_layers = num_fri_commitments.saturating_sub(1);
        let num_fri_alpha_perms = num_fri_layers;
        let remainder_coeffs_len =
            (self.pub_inputs.fri_remainder_max_degree + 1) * extension_degree;
        let num_remainder_perms = if num_fri_commitments > 0 {
            remainder_coeffs_len.div_ceil(RATE_WIDTH)
        } else {
            0
        };
        let num_pos_perms = if self.pub_inputs.num_draws == 0 {
            0
        } else {
            (self.pub_inputs.num_draws + 1).div_ceil(8)
        };
        let num_pow_nonce_perms = if num_fri_commitments > 0 { 1 } else { 0 };
        let transcript_perms = num_pi_blocks
            + num_seed_blocks
            + num_coeff_perms
            + num_ood_perms
            + num_deep_perms
            + num_fri_alpha_perms
            + num_pow_nonce_perms
            + num_pos_perms
            + 2;
        let num_pos_decomp_perms = self.pub_inputs.num_draws;
        let pre_merkle_perms = transcript_perms + num_pos_decomp_perms;

        let lde_domain_size = self.pub_inputs.trace_length * self.pub_inputs.blowup_factor;
        let depth_trace = if lde_domain_size == 0 {
            0
        } else {
            lde_domain_size.trailing_zeros() as usize
        };
        let trace_leaf_len = self.pub_inputs.trace_width * extension_degree;
        let constraint_leaf_len = self.pub_inputs.constraint_frame_width * extension_degree;
        let constraint_partition_size_base =
            self.pub_inputs.constraint_partition_size * extension_degree;
        let trace_leaf_perms =
            leaf_perm_count(trace_leaf_len, self.pub_inputs.trace_partition_size);
        let constraint_leaf_perms =
            leaf_perm_count(constraint_leaf_len, constraint_partition_size_base);
        let trace_leaf_chains =
            leaf_chain_count(trace_leaf_len, self.pub_inputs.trace_partition_size);
        let constraint_leaf_chains =
            leaf_chain_count(constraint_leaf_len, constraint_partition_size_base);
        let fri_leaf_len = 2 * extension_degree;
        let fri_leaf_perms = fri_leaf_len.div_ceil(RATE_WIDTH).max(1);
        let mut merkle_perms_per_query =
            trace_leaf_perms + depth_trace + constraint_leaf_perms + depth_trace;
        let replay_draws_per_query = trace_leaf_chains + constraint_leaf_chains;
        merkle_perms_per_query += replay_draws_per_query;
        for layer_idx in 0..num_fri_layers {
            merkle_perms_per_query += fri_leaf_perms + depth_trace.saturating_sub(layer_idx + 1);
        }
        let merkle_perms_total = self.pub_inputs.num_queries * merkle_perms_per_query;
        let remainder_hash_perms = num_remainder_perms;
        let active_perms = pre_merkle_perms + merkle_perms_total + remainder_hash_perms;
        let active_rows = active_perms * ROWS_PER_PERMUTATION;
        let total_rows = active_rows.next_power_of_two();

        let mut columns = Vec::with_capacity(VERIFIER_TRACE_WIDTH);
        for _ in 0..VERIFIER_TRACE_WIDTH {
            columns.push(vec![BaseElement::ZERO; total_rows]);
        }
        let mut trace = TraceTable::init(columns);
        let inner_is_rpo_air = self.pub_inputs.inner_public_inputs.len() == 2 * STATE_WIDTH;
        let inner_is_transaction_air =
            self.pub_inputs.inner_public_inputs.len() == transaction_public_inputs_len();

        let mut perm_idx = 0usize;
        let mut perm_acc_val = Quad::ONE;
        let mut draw_positions: Vec<u64> = Vec::with_capacity(self.pub_inputs.num_draws);
        let mut constraint_coeffs: Vec<BaseElement> = Vec::with_capacity(num_coeffs_total);
        let mut deep_coeffs: Vec<BaseElement> = Vec::with_capacity(num_deep_coeffs);
        let mut fri_alphas: Vec<BaseElement> = Vec::with_capacity(num_fri_layers);
        let mut fri_alphas_ext: Vec<Quad> = Vec::with_capacity(num_fri_layers);

        // --- Segment A: RPO hash of inner public inputs ------------------------------------
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[0] = BaseElement::new((input_len % 8) as u64);

        for block in 0..num_pi_blocks {
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;

            let start = block * 8;
            for i in 0..8 {
                state[4 + i] = if start + i < input_len {
                    inputs[start + i]
                } else {
                    BaseElement::ZERO
                };
            }

            self.fill_rpo_trace(&mut trace, row_offset, state);

            // Boundary masks for this permutation.
            let (carry, full_carry, reseed, coin_init) = if block + 1 < num_pi_blocks {
                (
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                )
            } else {
                (
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                )
            };
            set_masks(
                &mut trace,
                perm_idx,
                carry,
                full_carry,
                reseed,
                coin_init,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                [BaseElement::ZERO; 4],
                perm_acc_val,
            );

            // Carry full state forward.
            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }

            perm_idx += 1;
        }

        // --- Segment B: RPO hash of transcript seed ----------------------------------------
        let mut seed_state = [BaseElement::ZERO; STATE_WIDTH];
        seed_state[0] = BaseElement::new((seed_len % 8) as u64);

        for block in 0..num_seed_blocks {
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;

            let start = block * 8;
            for j in 0..8 {
                let idx = start + j;
                let val = if idx < seed_prefix.len() {
                    seed_prefix[idx]
                } else {
                    let pi_idx = idx - seed_prefix.len();
                    if pi_idx < input_len {
                        inputs[pi_idx]
                    } else {
                        BaseElement::ZERO
                    }
                };
                seed_state[4 + j] = val;
            }

            self.fill_rpo_trace(&mut trace, row_offset, seed_state);

            let (carry, full_carry, reseed, coin_init) = if block + 1 < num_seed_blocks {
                (
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                )
            } else {
                (
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                )
            };
            set_masks(
                &mut trace,
                perm_idx,
                carry,
                full_carry,
                reseed,
                coin_init,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                [BaseElement::ZERO; 4],
                perm_acc_val,
            );

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in seed_state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }

            perm_idx += 1;
        }

        // --- Segment C: coin.init(digest(seed)) ---------------------------------------------
        let digest = [seed_state[4], seed_state[5], seed_state[6], seed_state[7]];
        let mut coin_state = [BaseElement::ZERO; STATE_WIDTH];
        coin_state[4..8].copy_from_slice(&digest);

        let row_offset = perm_idx * ROWS_PER_PERMUTATION;
        self.fill_rpo_trace(&mut trace, row_offset, coin_state);
        set_masks(
            &mut trace,
            perm_idx,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ONE,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            self.pub_inputs.trace_commitment,
            perm_acc_val,
        );

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for (i, value) in coin_state.iter_mut().enumerate() {
            *value = trace.get(i, last);
        }
        perm_idx += 1;

        // --- Segment D: reseed with trace commitment (coefficient perm 0) -------------------
        for (state_value, commitment) in coin_state[4..8]
            .iter_mut()
            .zip(self.pub_inputs.trace_commitment.iter())
        {
            *state_value += *commitment;
        }
        let row_offset = perm_idx * ROWS_PER_PERMUTATION;
        self.fill_rpo_trace(&mut trace, row_offset, coin_state);
        let last_coeff_here = num_coeff_perms == 1;
        if last_coeff_here {
            set_masks(
                &mut trace,
                perm_idx,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ONE,
                BaseElement::ZERO,
                BaseElement::ONE,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                self.pub_inputs.constraint_commitment,
                perm_acc_val,
            );
        } else {
            set_masks(
                &mut trace,
                perm_idx,
                BaseElement::ZERO,
                BaseElement::ONE,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ONE,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                [BaseElement::ZERO; 4],
                perm_acc_val,
            );
        }

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for (i, value) in coin_state.iter_mut().enumerate() {
            *value = trace.get(i, last);
        }
        for value in coin_state[4..4 + RATE_WIDTH].iter().copied() {
            if constraint_coeffs.len() >= num_coeffs_total {
                break;
            }
            constraint_coeffs.push(value);
        }
        set_coeff_witness(&mut trace, perm_idx, &coin_state);
        let tape_values = core::array::from_fn(|i| coin_state[4 + i]);
        set_tape_meta(&mut trace, perm_idx, TAPE_KIND_COEFF, 0, tape_values);
        perm_idx += 1;

        // --- Additional coefficient permutations (permute-only, full-carry) ----------------
        for coeff_idx in 1..num_coeff_perms {
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;
            self.fill_rpo_trace(&mut trace, row_offset, coin_state);

            let is_last = coeff_idx + 1 == num_coeff_perms;
            if is_last {
                set_masks(
                    &mut trace,
                    perm_idx,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    self.pub_inputs.constraint_commitment,
                    perm_acc_val,
                );
            } else {
                set_masks(
                    &mut trace,
                    perm_idx,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    [BaseElement::ZERO; 4],
                    perm_acc_val,
                );
            }

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in coin_state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }
            for value in coin_state[4..4 + RATE_WIDTH].iter().copied() {
                if constraint_coeffs.len() >= num_coeffs_total {
                    break;
                }
                constraint_coeffs.push(value);
            }
            set_coeff_witness(&mut trace, perm_idx, &coin_state);
            let tape_values = core::array::from_fn(|i| coin_state[4 + i]);
            set_tape_meta(
                &mut trace,
                perm_idx,
                TAPE_KIND_COEFF,
                coeff_idx as u64,
                tape_values,
            );
            perm_idx += 1;
        }

        // --- Reseed with constraint commitment ---------------------------------------------
        for (state_value, commitment) in coin_state[4..8]
            .iter_mut()
            .zip(self.pub_inputs.constraint_commitment.iter())
        {
            *state_value += *commitment;
        }
        let row_offset = perm_idx * ROWS_PER_PERMUTATION;
        self.fill_rpo_trace(&mut trace, row_offset, coin_state);
        // Draw z. The coin is reseeded with the OOD digest in-circuit after hashing OOD frames.
        set_masks(
            &mut trace,
            perm_idx,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ONE,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ONE,
            BaseElement::ZERO,
            [BaseElement::ZERO; 4],
            perm_acc_val,
        );

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for (i, value) in coin_state.iter_mut().enumerate() {
            *value = trace.get(i, last);
        }
        let z_ext = if extension_degree == 2 {
            [coin_state[4], coin_state[5]]
        } else {
            [coin_state[4], BaseElement::ZERO]
        };
        let gamma = quad_from_ext(z_ext);
        set_z_witness(&mut trace, perm_idx, z_ext);
        perm_idx += 1;

        // Save the coin state immediately after z draw so we can restore it after hashing
        // merged OOD evaluations.
        let saved_coin_state = coin_state;

        // --- Segment E: Hash merged OOD evaluations (dummy zeros in this minimal trace) -----
        let ood_evals = vec![BaseElement::ZERO; ood_eval_len];

        let mut ood_state = [BaseElement::ZERO; STATE_WIDTH];
        ood_state[0] = BaseElement::new((ood_eval_len % RATE_WIDTH) as u64);

        for block in 0..num_ood_perms {
            let start = block * RATE_WIDTH;
            for (j, value) in ood_state[4..4 + RATE_WIDTH].iter_mut().enumerate() {
                let idx = start + j;
                *value = ood_evals.get(idx).copied().unwrap_or(BaseElement::ZERO);
            }

            let row_offset = perm_idx * ROWS_PER_PERMUTATION;
            self.fill_rpo_trace(&mut trace, row_offset, ood_state);

            let is_last = block + 1 == num_ood_perms;
            set_masks(
                &mut trace,
                perm_idx,
                if is_last {
                    BaseElement::ZERO
                } else {
                    BaseElement::ONE
                },
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                [BaseElement::ZERO; 4],
                perm_acc_val,
            );

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in ood_state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }
            perm_idx += 1;
        }

        let ood_digest = [ood_state[4], ood_state[5], ood_state[6], ood_state[7]];

        // Apply OOD reseed before drawing DEEP composition coefficients.
        coin_state = saved_coin_state;
        for (state_value, digest_value) in coin_state[4..8].iter_mut().zip(ood_digest.iter()) {
            *state_value += *digest_value;
        }

        // --- Segment E: DEEP composition coefficient draws (permute-only, full-carry) --------
        for deep_idx in 0..num_deep_perms {
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;
            self.fill_rpo_trace(&mut trace, row_offset, coin_state);
            let restore_mask = if deep_idx == 0 {
                BaseElement::ONE
            } else {
                BaseElement::ZERO
            };

            let is_last = deep_idx + 1 == num_deep_perms;
            if is_last {
                let has_fri_commitments = num_fri_commitments > 0;
                let reseed_word = if has_fri_commitments {
                    self.pub_inputs.fri_commitments[0]
                } else {
                    [BaseElement::ZERO; 4]
                };
                set_masks(
                    &mut trace,
                    perm_idx,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    if has_fri_commitments {
                        BaseElement::ONE
                    } else {
                        BaseElement::ZERO
                    },
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    restore_mask,
                    reseed_word,
                    perm_acc_val,
                );
            } else {
                set_masks(
                    &mut trace,
                    perm_idx,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    restore_mask,
                    [BaseElement::ZERO; 4],
                    perm_acc_val,
                );
            }

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in coin_state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }
            for value in coin_state[4..4 + RATE_WIDTH].iter().copied() {
                if deep_coeffs.len() >= num_deep_coeffs {
                    break;
                }
                deep_coeffs.push(value);
            }
            set_deep_witness(&mut trace, perm_idx, &coin_state);
            let tape_values = core::array::from_fn(|i| coin_state[4 + i]);
            set_tape_meta(
                &mut trace,
                perm_idx,
                TAPE_KIND_DEEP,
                deep_idx as u64,
                tape_values,
            );
            perm_idx += 1;
        }

        // --- Segment F: FRI alpha draws and remainder reseed --------------------------------
        if let Some(first_commitment) = self.pub_inputs.fri_commitments.first() {
            for (state_value, commitment_value) in
                coin_state[4..8].iter_mut().zip(first_commitment.iter())
            {
                *state_value += *commitment_value;
            }
        }

        for layer_idx in 0..num_fri_layers {
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;
            self.fill_rpo_trace(&mut trace, row_offset, coin_state);

            let next_commitment = if layer_idx + 1 < num_fri_layers {
                self.pub_inputs.fri_commitments[layer_idx + 1]
            } else {
                // Reseed with remainder commitment after last alpha.
                self.pub_inputs.fri_commitments[num_fri_layers]
            };

            set_masks(
                &mut trace,
                perm_idx,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ONE,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ONE,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                next_commitment,
                perm_acc_val,
            );

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in coin_state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }
            let alpha_ext = if extension_degree == 2 {
                [coin_state[4], coin_state[5]]
            } else {
                [coin_state[4], BaseElement::ZERO]
            };
            fri_alphas_ext.push(quad_from_ext(alpha_ext));
            if fri_alphas.len() < num_fri_layers {
                fri_alphas.push(alpha_ext[0]);
            }
            set_fri_alpha_witness(&mut trace, perm_idx, alpha_ext);
            let tape_values = core::array::from_fn(|i| coin_state[4 + i]);
            set_tape_meta(
                &mut trace,
                perm_idx,
                TAPE_KIND_ALPHA,
                layer_idx as u64,
                tape_values,
            );
            perm_idx += 1;

            for (state_value, commitment_value) in
                coin_state[4..8].iter_mut().zip(next_commitment.iter())
            {
                *state_value += *commitment_value;
            }
        }

        // Placeholder proof-of-work nonce for query grinding.
        // Full recursion will bind this to the inner proof's pow_nonce.
        let pow_nonce_elem = BaseElement::ZERO;
        let nonce_word = [
            pow_nonce_elem,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
        ];
        let remainder_reseed = if num_pos_perms > 0 {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        };

        if num_fri_commitments > 0 {
            // Remainder permutation (no alpha draw).
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;
            self.fill_rpo_trace(&mut trace, row_offset, coin_state);
            set_masks(
                &mut trace,
                perm_idx,
                BaseElement::ZERO,
                BaseElement::ZERO,
                remainder_reseed,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                nonce_word,
                perm_acc_val,
            );

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in coin_state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }
            perm_idx += 1;
        }

        // --- Query position draw permutations + decomposition -------------------------------
        if num_pos_perms > 0 {
            // Absorb nonce into the coin before the first draw permutation.
            coin_state[4] += pow_nonce_elem;

            let mut remaining_draws = self.pub_inputs.num_draws;
            let domain_size = lde_domain_size.max(1);
            let depth_trace_bits = domain_size.trailing_zeros() as usize;
            let v_mask = (domain_size - 1) as u64;

            for pos_idx in 0..num_pos_perms {
                let row_offset = perm_idx * ROWS_PER_PERMUTATION;
                self.fill_rpo_trace(&mut trace, row_offset, coin_state);

                let pos_full_carry = if pos_idx + 1 == num_pos_perms {
                    BaseElement::ZERO
                } else {
                    BaseElement::ONE
                };

                // Carry full state into the following pos permutation (if any).
                set_masks(
                    &mut trace,
                    perm_idx,
                    BaseElement::ZERO,
                    pos_full_carry,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    [BaseElement::ZERO; 4],
                    perm_acc_val,
                );

                let last = row_offset + ROWS_PER_PERMUTATION - 1;
                for (i, value) in coin_state.iter_mut().enumerate() {
                    *value = trace.get(i, last);
                }
                set_pos_witness(&mut trace, perm_idx, &coin_state);
                let rate_outputs: [BaseElement; RATE_WIDTH] =
                    core::array::from_fn(|i| coin_state[4 + i]);
                perm_idx += 1;

                let draws_here = if pos_idx == 0 {
                    remaining_draws.min(RATE_WIDTH - 1)
                } else {
                    remaining_draws.min(RATE_WIDTH)
                };
                let start_rate = if pos_idx == 0 { 1 } else { 0 };

                for d in 0..draws_here {
                    let raw_val = rate_outputs[start_rate + d];
                    let raw_u64 = raw_val.as_int();

                    // Decomp perm: freeze RPO state, carry buffer, and decompose raw into bits.
                    let row0 = perm_idx * ROWS_PER_PERMUTATION;
                    let gamma_limbs = gamma.to_base_elements();
                    for r in 0..ROWS_PER_PERMUTATION {
                        let row = row0 + r;
                        for (i, value) in coin_state.iter().copied().enumerate() {
                            trace.set(i, row, value);
                        }
                        trace.set(COL_POS_DECOMP_MASK, row, BaseElement::ONE);
                        trace.set(COL_POS_RAW, row, raw_val);
                        for (j, value) in rate_outputs.iter().copied().enumerate() {
                            trace.set(COL_POS_START + j, row, value);
                        }
                        trace.set(COL_Z_VALUE, row, gamma_limbs[0]);
                    }

                    // Fill nibble bits and accumulators row-by-row.
                    let mut acc = 0u64;
                    let mut lo_acc = 0u64;
                    let mut masked_acc = 0u64;
                    let mut hi_and = 0u64;

                    for local_row in 0..ROWS_PER_PERMUTATION {
                        let row = row0 + local_row;
                        let nibble = (raw_u64 >> (4 * local_row)) & 0xF;
                        let bits = [
                            (nibble & 1) as u64,
                            ((nibble >> 1) & 1) as u64,
                            ((nibble >> 2) & 1) as u64,
                            ((nibble >> 3) & 1) as u64,
                        ];
                        trace.set(COL_POS_BIT0, row, BaseElement::new(bits[0]));
                        trace.set(COL_POS_BIT1, row, BaseElement::new(bits[1]));
                        trace.set(COL_POS_BIT2, row, BaseElement::new(bits[2]));
                        trace.set(COL_POS_BIT3, row, BaseElement::new(bits[3]));

                        trace.set(COL_POS_ACC, row, BaseElement::new(acc));
                        trace.set(COL_POS_LO_ACC, row, BaseElement::new(lo_acc));
                        trace.set(COL_POS_MASKED_ACC, row, BaseElement::new(masked_acc));

                        if local_row == 8 {
                            hi_and = 1;
                        }
                        trace.set(COL_POS_HI_AND, row, BaseElement::new(hi_and));

                        // Update accumulators for next row.
                        let base_exp = 4 * local_row;
                        for (j, bit) in bits.iter().copied().enumerate() {
                            if bit == 1 {
                                acc = acc.wrapping_add(1u64 << (base_exp + j));
                                if base_exp + j < 32 {
                                    lo_acc = lo_acc.wrapping_add(1u64 << (base_exp + j));
                                }
                                if base_exp + j < depth_trace_bits {
                                    masked_acc = masked_acc.wrapping_add(1u64 << (base_exp + j));
                                }
                            }
                        }
                        if local_row >= 8 {
                            let nibble_prod = bits.iter().product::<u64>();
                            hi_and *= nibble_prod;
                        }
                    }

                    let masked_pos = (raw_u64 & v_mask) as u64;
                    let p_elem = BaseElement::new(masked_pos);
                    for r in 0..ROWS_PER_PERMUTATION {
                        let row = row0 + r;
                        trace.set(COL_POS_SORTED_VALUE, row, p_elem);
                    }

                    let full_carry = BaseElement::ZERO;

                    // No boundary carry on decomp perms (RPO state is frozen inside the perm).
                    set_masks(
                        &mut trace,
                        perm_idx,
                        BaseElement::ZERO,
                        full_carry,
                        BaseElement::ZERO,
                        BaseElement::ZERO,
                        BaseElement::ZERO,
                        BaseElement::ZERO,
                        BaseElement::ZERO,
                        BaseElement::ZERO,
                        BaseElement::ZERO,
                        BaseElement::ONE,
                        BaseElement::ZERO,
                        BaseElement::ZERO,
                        [BaseElement::ZERO; 4],
                        perm_acc_val,
                    );

                    draw_positions.push(masked_pos);
                    perm_acc_val *= Quad::from(p_elem) + gamma;

                    perm_idx += 1;
                    remaining_draws -= 1;
                    if remaining_draws == 0 {
                        break;
                    }
                }

                if remaining_draws == 0 {
                    break;
                }
            }
        }

        // --- Dummy Merkle authentication segment -------------------------------------------
        // For transcript-only proofs we still need to satisfy Merkle constraints and degrees.
        assert_eq!(perm_idx, pre_merkle_perms, "pre-merkle perm count mismatch");

        let dummy_trace_row = vec![BaseElement::ZERO; RPO_TRACE_WIDTH];
        let dummy_constraint_row = vec![BaseElement::ZERO; 8];
        let dummy_fri_row = vec![BaseElement::ZERO; 2 * extension_degree];
        let dummy_remainder = vec![BaseElement::ZERO; 8];

        let dummy_trace_leaf_digest = rpo_hash_elements(&dummy_trace_row);
        let dummy_constraint_leaf_digest = rpo_hash_elements(&dummy_constraint_row);
        let dummy_fri_leaf_digest = rpo_hash_elements(&dummy_fri_row);

        let build_self_siblings = |mut cur: [BaseElement; DIGEST_WIDTH], depth: usize| {
            let mut siblings = Vec::with_capacity(depth);
            for _ in 0..depth {
                siblings.push(cur);
                cur = rpo_merge(&cur, &cur);
            }
            siblings
        };

        let trace_siblings = build_self_siblings(dummy_trace_leaf_digest, depth_trace);
        let constraint_siblings = build_self_siblings(dummy_constraint_leaf_digest, depth_trace);
        let mut fri_siblings_by_layer: Vec<Vec<[BaseElement; DIGEST_WIDTH]>> =
            Vec::with_capacity(num_fri_layers);
        for layer_idx in 0..num_fri_layers {
            let layer_depth = depth_trace.saturating_sub(layer_idx + 1);
            fri_siblings_by_layer.push(build_self_siblings(dummy_fri_leaf_digest, layer_depth));
        }

        assert_eq!(
            draw_positions.len(),
            self.pub_inputs.num_queries,
            "draw count must match num_queries for dummy Merkle segment"
        );

        let mut replay_state = if replay_draws_per_query > 0 {
            Some(DeepReplayState::new(replay_draws_per_query))
        } else {
            None
        };

        for &trace_index in draw_positions.iter() {
            if let Some(replay) = replay_state.as_mut() {
                replay.reset(saved_coin_state, ood_digest);
            }
            let trace_leaf = hash_row_partitioned_perms(
                self,
                &mut trace,
                &mut perm_idx,
                &dummy_trace_row,
                self.pub_inputs.trace_partition_size,
                perm_acc_val,
                trace_index,
                replay_state.as_mut(),
            );
            perm_acc_val /= Quad::from(BaseElement::new(trace_index)) + gamma;
            authenticate_merkle_path(
                self,
                &mut trace,
                &mut perm_idx,
                perm_acc_val,
                trace_leaf,
                trace_index,
                &trace_siblings,
            );

            let constraint_leaf = hash_row_partitioned_perms(
                self,
                &mut trace,
                &mut perm_idx,
                &dummy_constraint_row,
                constraint_partition_size_base,
                perm_acc_val,
                trace_index,
                replay_state.as_mut(),
            );
            authenticate_merkle_path(
                self,
                &mut trace,
                &mut perm_idx,
                perm_acc_val,
                constraint_leaf,
                trace_index,
                &constraint_siblings,
            );
            if let Some(replay) = replay_state.as_ref() {
                debug_assert_eq!(
                    replay.draw_idx, replay.draws_per_query,
                    "deep replay draw count mismatch for dummy Merkle segment"
                );
            }

            for sibs in fri_siblings_by_layer.iter() {
                let fri_index = 0u64;
                let fri_leaf = hash_leaf_perms(
                    self,
                    &mut trace,
                    &mut perm_idx,
                    &dummy_fri_row,
                    perm_acc_val,
                    fri_index,
                    0,
                );
                authenticate_merkle_path(
                    self,
                    &mut trace,
                    &mut perm_idx,
                    perm_acc_val,
                    fri_leaf,
                    fri_index,
                    sibs,
                );
            }
        }

        // --- Remainder polynomial commitment hash -----------------------------------------
        if !self.pub_inputs.fri_commitments.is_empty() {
            let _ = hash_leaf_perms(
                self,
                &mut trace,
                &mut perm_idx,
                &dummy_remainder,
                perm_acc_val,
                0,
                0,
            );
        }

        // --- Padding permutations -----------------------------------------------------------
        let total_perms = total_rows / ROWS_PER_PERMUTATION;
        while perm_idx < total_perms {
            coin_state[4..4 + RATE_WIDTH].fill(BaseElement::ZERO);
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;
            self.fill_rpo_trace(&mut trace, row_offset, coin_state);
            set_masks(
                &mut trace,
                perm_idx,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                [BaseElement::ZERO; 4],
                perm_acc_val,
            );

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in coin_state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }
            perm_idx += 1;
        }

        if inner_is_rpo_air || inner_is_transaction_air {
            debug_assert_eq!(
                constraint_coeffs.len(),
                num_coeffs_total,
                "unexpected constraint coeff count"
            );
            debug_assert_eq!(
                deep_coeffs.len(),
                num_deep_coeffs,
                "unexpected DEEP coeff count"
            );
        }
        debug_assert!(
            fri_alphas.len() <= MAX_FRI_LAYERS,
            "too many FRI alphas for configured MAX_FRI_LAYERS"
        );

        // Fill constant columns (used by in-circuit checks).
        for row in 0..trace.length() {
            for (i, value) in ood_digest.iter().copied().enumerate() {
                trace.set(COL_OOD_DIGEST_START + i, row, value);
            }
            for (i, value) in saved_coin_state.iter().copied().enumerate() {
                trace.set(COL_SAVED_COIN_START + i, row, value);
            }
            for (i, value) in constraint_coeffs
                .iter()
                .copied()
                .take(NUM_CONSTRAINT_COEFFS)
                .enumerate()
            {
                if i < RESERVED_CONSTRAINT_COEFF_COLS {
                    continue;
                }
                trace.set(COL_CONSTRAINT_COEFFS_START + i, row, value);
            }
            for (i, value) in deep_coeffs
                .iter()
                .copied()
                .take(NUM_DEEP_COEFFS)
                .enumerate()
            {
                trace.set(COL_DEEP_COEFFS_START + i, row, value);
            }
            if extension_degree == 2 {
                let gamma_limb1 = gamma.to_base_elements()[1];
                trace.set(COL_Z_VALUE_LIMB1, row, gamma_limb1);
            }
            for (i, value) in fri_alphas
                .iter()
                .copied()
                .chain(core::iter::repeat(BaseElement::ZERO))
                .take(MAX_FRI_LAYERS)
                .enumerate()
            {
                trace.set(COL_FRI_ALPHA_START + i, row, value);
            }
            if inner_is_rpo_air {
                for (i, value) in ood_evals.iter().copied().enumerate() {
                    trace.set(COL_OOD_EVALS_START + i, row, value);
                }
            }
        }

        // Populate DEEP/FRI recursion state columns (TraceTable::new() leaves memory uninitialized).
        let deep_evals = vec![Quad::ZERO; self.pub_inputs.num_queries];
        let remainder_coeffs = vec![BaseElement::ZERO; NUM_REMAINDER_COEFFS * extension_degree];
        let ood_trace = vec![BaseElement::ZERO; self.pub_inputs.trace_width * extension_degree];
        let ood_quotient =
            vec![BaseElement::ZERO; self.pub_inputs.constraint_frame_width * extension_degree];
        let deep_coeffs = DeepCompositionCoefficients {
            trace: vec![BaseElement::ZERO; self.pub_inputs.trace_width * extension_degree],
            constraints: vec![
                BaseElement::ZERO;
                self.pub_inputs.constraint_frame_width * extension_degree
            ],
        };
        self.populate_deep_fri_state(
            &mut trace,
            pre_merkle_perms,
            trace_leaf_perms,
            constraint_leaf_perms,
            depth_trace,
            num_fri_layers,
            &deep_evals,
            &fri_alphas_ext,
            &remainder_coeffs,
            &ood_trace,
            &ood_trace,
            &ood_quotient,
            &ood_quotient,
            &deep_coeffs,
        );

        trace
    }

    /// Build a full verifier trace for a concrete inner proof.
    ///
    /// This extends the transcript segment with in‑circuit hashing of all queried
    /// leaves and Merkle authentication paths for trace, constraint, and FRI layers.
    pub fn build_trace_from_inner(&self, inner: &InnerProofData) -> TraceTable<BaseElement> {
        assert!(
            matches!(
                inner.field_extension,
                FieldExtension::None | FieldExtension::Quadratic
            ),
            "StarkVerifierAir recursion supports only base/quadratic inner proofs"
        );
        assert_eq!(
            inner.fri_folding_factor, 2,
            "StarkVerifierAir recursion currently assumes FRI folding factor 2"
        );
        let inputs = &self.pub_inputs.inner_public_inputs;
        let input_len = inputs.len();
        let num_pi_blocks = input_len.div_ceil(8).max(1);

        let seed_prefix = build_context_prefix(&self.pub_inputs);
        let seed_len = seed_prefix.len() + input_len;
        let num_seed_blocks = seed_len.div_ceil(8).max(1);

        let extension_degree = match self.pub_inputs.field_extension {
            FieldExtension::None => 1,
            FieldExtension::Quadratic => 2,
            FieldExtension::Cubic => 3,
        };
        let num_coeffs_total = (self.pub_inputs.num_transition_constraints
            + self.pub_inputs.num_assertions)
            * extension_degree;
        let num_coeff_perms = num_coeffs_total.div_ceil(RATE_WIDTH).max(1);

        let num_deep_coeffs = (self.pub_inputs.trace_width
            + self.pub_inputs.constraint_frame_width)
            * extension_degree;
        let num_deep_perms = num_deep_coeffs.div_ceil(RATE_WIDTH);

        let ood_eval_len = 2 * num_deep_coeffs;
        let num_ood_perms = ood_eval_len.div_ceil(RATE_WIDTH);
        let num_fri_commitments = self.pub_inputs.fri_commitments.len();
        let num_fri_layers = num_fri_commitments.saturating_sub(1);
        let num_fri_alpha_perms = num_fri_layers;
        let remainder_coeffs_len =
            (self.pub_inputs.fri_remainder_max_degree + 1) * extension_degree;
        let num_remainder_perms = if num_fri_commitments > 0 {
            remainder_coeffs_len.div_ceil(RATE_WIDTH)
        } else {
            0
        };
        let num_pos_perms = if self.pub_inputs.num_draws == 0 {
            0
        } else {
            (self.pub_inputs.num_draws + 1).div_ceil(8)
        };
        let num_pow_nonce_perms = if num_fri_commitments > 0 { 1 } else { 0 };

        let transcript_perms = num_pi_blocks
            + num_seed_blocks
            + num_coeff_perms
            + num_ood_perms
            + num_deep_perms
            + num_fri_alpha_perms
            + num_pow_nonce_perms
            + num_pos_perms
            + 2;
        let num_pos_decomp_perms = self.pub_inputs.num_draws;
        let pre_merkle_perms = transcript_perms + num_pos_decomp_perms;

        // Merkle permutations count (must match AIR periodic schedule).
        let lde_domain_size = self.pub_inputs.trace_length * self.pub_inputs.blowup_factor;
        let depth_trace = if lde_domain_size == 0 {
            0
        } else {
            lde_domain_size.trailing_zeros() as usize
        };
        let trace_leaf_len = self.pub_inputs.trace_width * extension_degree;
        let constraint_leaf_len = self.pub_inputs.constraint_frame_width * extension_degree;
        let constraint_partition_size_base =
            self.pub_inputs.constraint_partition_size * extension_degree;
        let trace_leaf_perms =
            leaf_perm_count(trace_leaf_len, self.pub_inputs.trace_partition_size);
        let constraint_leaf_perms =
            leaf_perm_count(constraint_leaf_len, constraint_partition_size_base);
        let trace_leaf_chains =
            leaf_chain_count(trace_leaf_len, self.pub_inputs.trace_partition_size);
        let constraint_leaf_chains =
            leaf_chain_count(constraint_leaf_len, constraint_partition_size_base);
        let fri_leaf_len = 2 * extension_degree;
        let fri_leaf_perms = fri_leaf_len.div_ceil(RATE_WIDTH).max(1);
        let mut merkle_perms_per_query =
            trace_leaf_perms + depth_trace + constraint_leaf_perms + depth_trace;
        let replay_draws_per_query = trace_leaf_chains + constraint_leaf_chains;
        merkle_perms_per_query += replay_draws_per_query;
        for layer_idx in 0..num_fri_layers {
            merkle_perms_per_query += fri_leaf_perms + depth_trace.saturating_sub(layer_idx + 1);
        }
        let merkle_perms_total = self.pub_inputs.num_queries * merkle_perms_per_query;

        let remainder_hash_perms = if num_fri_commitments > 0 {
            assert!(
                inner.fri_remainder.len() == remainder_coeffs_len,
                "inner remainder has {} coeffs; expected {} for extension degree {}",
                inner.fri_remainder.len(),
                remainder_coeffs_len,
                extension_degree
            );
            assert!(
                inner.fri_remainder.len() <= NUM_REMAINDER_COEFFS * extension_degree,
                "inner remainder has {} coeffs; recursion layout supports at most {}",
                inner.fri_remainder.len(),
                NUM_REMAINDER_COEFFS * extension_degree
            );
            num_remainder_perms
        } else {
            0usize
        };
        let active_perms = pre_merkle_perms + merkle_perms_total + remainder_hash_perms;
        let active_rows = active_perms * ROWS_PER_PERMUTATION;
        let total_rows = active_rows.next_power_of_two();
        log::info!(
            target: "recursion",
            "StarkVerifierProver trace sizing: trace_length={} blowup={} trace_width={} constraint_width={} num_queries={} num_draws={} trace_partition_size={} constraint_partition_size={} extension_degree={} merkle_perms_per_query={} merkle_perms_total={} active_perms={} total_rows={}",
            self.pub_inputs.trace_length,
            self.pub_inputs.blowup_factor,
            self.pub_inputs.trace_width,
            self.pub_inputs.constraint_frame_width,
            self.pub_inputs.num_queries,
            self.pub_inputs.num_draws,
            self.pub_inputs.trace_partition_size,
            self.pub_inputs.constraint_partition_size,
            extension_degree,
            merkle_perms_per_query,
            merkle_perms_total,
            active_perms,
            total_rows
        );

        let mut columns = Vec::with_capacity(VERIFIER_TRACE_WIDTH);
        for _ in 0..VERIFIER_TRACE_WIDTH {
            columns.push(vec![BaseElement::ZERO; total_rows]);
        }
        let mut trace = TraceTable::init(columns);

        let mut perm_idx = 0usize;
        let expected_z = if extension_degree == 2 {
            ext_from_flat(&inner.z)
        } else {
            ext_from_base(inner.z[0])
        };
        let gamma = quad_from_ext(expected_z);
        let mut perm_acc_val = Quad::ONE;
        let mut draw_positions: Vec<u64> = Vec::with_capacity(self.pub_inputs.num_draws);
        let mut constraint_coeffs: Vec<BaseElement> = Vec::with_capacity(num_coeffs_total);
        let mut deep_coeffs: Vec<BaseElement> = Vec::with_capacity(num_deep_coeffs);
        let mut fri_alphas: Vec<BaseElement> = Vec::with_capacity(num_fri_layers);

        // --- Segment A: RPO hash of inner public inputs ------------------------------------
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[0] = BaseElement::new((input_len % 8) as u64);

        for block in 0..num_pi_blocks {
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;

            let start = block * 8;
            for i in 0..8 {
                state[4 + i] = if start + i < input_len {
                    inputs[start + i]
                } else {
                    BaseElement::ZERO
                };
            }

            self.fill_rpo_trace(&mut trace, row_offset, state);

            let (carry, full_carry, reseed, coin_init) = if block + 1 < num_pi_blocks {
                (
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                )
            } else {
                (
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                )
            };
            set_masks(
                &mut trace,
                perm_idx,
                carry,
                full_carry,
                reseed,
                coin_init,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                [BaseElement::ZERO; 4],
                perm_acc_val,
            );
            set_path_bit(&mut trace, perm_idx, 0);

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }

            perm_idx += 1;
        }

        // --- Segment B: RPO hash of transcript seed ----------------------------------------
        let mut seed_state = [BaseElement::ZERO; STATE_WIDTH];
        seed_state[0] = BaseElement::new((seed_len % 8) as u64);

        for block in 0..num_seed_blocks {
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;

            let start = block * 8;
            for j in 0..8 {
                let idx = start + j;
                let val = if idx < seed_prefix.len() {
                    seed_prefix[idx]
                } else {
                    let pi_idx = idx - seed_prefix.len();
                    if pi_idx < input_len {
                        inputs[pi_idx]
                    } else {
                        BaseElement::ZERO
                    }
                };
                seed_state[4 + j] = val;
            }

            self.fill_rpo_trace(&mut trace, row_offset, seed_state);

            let (carry, full_carry, reseed, coin_init) = if block + 1 < num_seed_blocks {
                (
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                )
            } else {
                (
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                )
            };
            set_masks(
                &mut trace,
                perm_idx,
                carry,
                full_carry,
                reseed,
                coin_init,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                [BaseElement::ZERO; 4],
                perm_acc_val,
            );
            set_path_bit(&mut trace, perm_idx, 0);

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in seed_state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }

            perm_idx += 1;
        }

        // --- Segment C: coin.init(digest(seed)) ---------------------------------------------
        let digest = [seed_state[4], seed_state[5], seed_state[6], seed_state[7]];
        let mut coin_state = [BaseElement::ZERO; STATE_WIDTH];
        coin_state[4..8].copy_from_slice(&digest);

        let row_offset = perm_idx * ROWS_PER_PERMUTATION;
        self.fill_rpo_trace(&mut trace, row_offset, coin_state);
        set_masks(
            &mut trace,
            perm_idx,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ONE,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            self.pub_inputs.trace_commitment,
            perm_acc_val,
        );
        set_path_bit(&mut trace, perm_idx, 0);

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for (i, value) in coin_state.iter_mut().enumerate() {
            *value = trace.get(i, last);
        }
        perm_idx += 1;

        // --- Segment D: reseed with trace commitment (coefficient perm 0) -------------------
        for (state_value, commitment) in coin_state[4..8]
            .iter_mut()
            .zip(self.pub_inputs.trace_commitment.iter())
        {
            *state_value += *commitment;
        }
        let row_offset = perm_idx * ROWS_PER_PERMUTATION;
        self.fill_rpo_trace(&mut trace, row_offset, coin_state);
        let last_coeff_here = num_coeff_perms == 1;
        if last_coeff_here {
            set_masks(
                &mut trace,
                perm_idx,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ONE,
                BaseElement::ZERO,
                BaseElement::ONE,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                self.pub_inputs.constraint_commitment,
                perm_acc_val,
            );
        } else {
            set_masks(
                &mut trace,
                perm_idx,
                BaseElement::ZERO,
                BaseElement::ONE,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ONE,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                [BaseElement::ZERO; 4],
                perm_acc_val,
            );
        }
        set_path_bit(&mut trace, perm_idx, 0);

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for (i, value) in coin_state.iter_mut().enumerate() {
            *value = trace.get(i, last);
        }
        for value in coin_state[4..4 + RATE_WIDTH].iter().copied() {
            if constraint_coeffs.len() >= num_coeffs_total {
                break;
            }
            constraint_coeffs.push(value);
        }
        set_coeff_witness(&mut trace, perm_idx, &coin_state);
        let tape_values = core::array::from_fn(|i| coin_state[4 + i]);
        set_tape_meta(&mut trace, perm_idx, TAPE_KIND_COEFF, 0, tape_values);
        perm_idx += 1;

        // --- Additional coefficient permutations (permute-only, full-carry) ----------------
        for coeff_idx in 1..num_coeff_perms {
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;
            self.fill_rpo_trace(&mut trace, row_offset, coin_state);

            let is_last = coeff_idx + 1 == num_coeff_perms;
            if is_last {
                set_masks(
                    &mut trace,
                    perm_idx,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    self.pub_inputs.constraint_commitment,
                    perm_acc_val,
                );
            } else {
                set_masks(
                    &mut trace,
                    perm_idx,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    [BaseElement::ZERO; 4],
                    perm_acc_val,
                );
            }
            set_path_bit(&mut trace, perm_idx, 0);

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in coin_state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }
            for value in coin_state[4..4 + RATE_WIDTH].iter().copied() {
                if constraint_coeffs.len() >= num_coeffs_total {
                    break;
                }
                constraint_coeffs.push(value);
            }
            set_coeff_witness(&mut trace, perm_idx, &coin_state);
            let tape_values = core::array::from_fn(|i| coin_state[4 + i]);
            set_tape_meta(
                &mut trace,
                perm_idx,
                TAPE_KIND_COEFF,
                coeff_idx as u64,
                tape_values,
            );
            perm_idx += 1;
        }

        // --- Reseed with constraint commitment ---------------------------------------------
        for (state_value, commitment) in coin_state[4..8]
            .iter_mut()
            .zip(self.pub_inputs.constraint_commitment.iter())
        {
            *state_value += *commitment;
        }
        let row_offset = perm_idx * ROWS_PER_PERMUTATION;
        self.fill_rpo_trace(&mut trace, row_offset, coin_state);
        // Draw z. The coin is reseeded with the OOD digest in-circuit after hashing OOD frames.
        set_masks(
            &mut trace,
            perm_idx,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ONE,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ONE,
            BaseElement::ZERO,
            [BaseElement::ZERO; 4],
            perm_acc_val,
        );
        set_path_bit(&mut trace, perm_idx, 0);

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for (i, value) in coin_state.iter_mut().enumerate() {
            *value = trace.get(i, last);
        }
        set_z_witness(&mut trace, perm_idx, expected_z);
        perm_idx += 1;

        // Save the coin state immediately after z draw so we can restore it after hashing merged
        // OOD evaluations.
        let saved_coin_state = coin_state;

        // --- Hash merged OOD evaluations ---------------------------------------------------
        let mut ood_evals = Vec::with_capacity(ood_eval_len);
        ood_evals.extend_from_slice(&inner.ood_trace_current);
        ood_evals.extend_from_slice(&inner.ood_quotient_current);
        ood_evals.extend_from_slice(&inner.ood_trace_next);
        ood_evals.extend_from_slice(&inner.ood_quotient_next);
        debug_assert_eq!(ood_evals.len(), ood_eval_len);

        let mut ood_state = [BaseElement::ZERO; STATE_WIDTH];
        ood_state[0] = BaseElement::new((ood_eval_len % RATE_WIDTH) as u64);

        for block in 0..num_ood_perms {
            let start = block * RATE_WIDTH;
            for (j, value) in ood_state[4..4 + RATE_WIDTH].iter_mut().enumerate() {
                let idx = start + j;
                *value = ood_evals.get(idx).copied().unwrap_or(BaseElement::ZERO);
            }

            let row_offset = perm_idx * ROWS_PER_PERMUTATION;
            self.fill_rpo_trace(&mut trace, row_offset, ood_state);

            let is_last = block + 1 == num_ood_perms;
            set_masks(
                &mut trace,
                perm_idx,
                if is_last {
                    BaseElement::ZERO
                } else {
                    BaseElement::ONE
                },
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                [BaseElement::ZERO; 4],
                perm_acc_val,
            );
            set_path_bit(&mut trace, perm_idx, 0);

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in ood_state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }
            perm_idx += 1;
        }

        let ood_digest = [ood_state[4], ood_state[5], ood_state[6], ood_state[7]];

        // Apply OOD reseed before drawing DEEP composition coefficients.
        coin_state = saved_coin_state;
        for (state_value, digest_value) in coin_state[4..8].iter_mut().zip(ood_digest.iter()) {
            *state_value += *digest_value;
        }

        // --- Segment E: DEEP composition coefficient draws (permute-only, full-carry) -------
        for deep_idx in 0..num_deep_perms {
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;
            self.fill_rpo_trace(&mut trace, row_offset, coin_state);
            let restore_mask = if deep_idx == 0 {
                BaseElement::ONE
            } else {
                BaseElement::ZERO
            };

            let is_last = deep_idx + 1 == num_deep_perms;
            if is_last {
                let has_fri_commitments = num_fri_commitments > 0;
                let reseed_word = if has_fri_commitments {
                    self.pub_inputs.fri_commitments[0]
                } else {
                    [BaseElement::ZERO; 4]
                };
                set_masks(
                    &mut trace,
                    perm_idx,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    if has_fri_commitments {
                        BaseElement::ONE
                    } else {
                        BaseElement::ZERO
                    },
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    restore_mask,
                    reseed_word,
                    perm_acc_val,
                );
            } else {
                set_masks(
                    &mut trace,
                    perm_idx,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    restore_mask,
                    [BaseElement::ZERO; 4],
                    perm_acc_val,
                );
            }
            set_path_bit(&mut trace, perm_idx, 0);

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in coin_state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }
            for value in coin_state[4..4 + RATE_WIDTH].iter().copied() {
                if deep_coeffs.len() >= num_deep_coeffs {
                    break;
                }
                deep_coeffs.push(value);
            }
            set_deep_witness(&mut trace, perm_idx, &coin_state);
            let tape_values = core::array::from_fn(|i| coin_state[4 + i]);
            set_tape_meta(
                &mut trace,
                perm_idx,
                TAPE_KIND_DEEP,
                deep_idx as u64,
                tape_values,
            );
            perm_idx += 1;
        }

        // --- Segment F: reseed with first FRI commitment before alpha draws -----------------
        if num_fri_commitments > 0 {
            for (state_value, commitment_value) in coin_state[4..8]
                .iter_mut()
                .zip(self.pub_inputs.fri_commitments[0].iter())
            {
                *state_value += *commitment_value;
            }
        }

        // --- FRI alpha stage ----------------------------------------------------------------
        for layer_idx in 0..num_fri_layers {
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;
            self.fill_rpo_trace(&mut trace, row_offset, coin_state);

            let next_commitment = if layer_idx + 1 < num_fri_layers {
                self.pub_inputs.fri_commitments[layer_idx + 1]
            } else {
                // Reseed remainder commitment after last alpha.
                self.pub_inputs.fri_commitments[num_fri_layers]
            };
            set_masks(
                &mut trace,
                perm_idx,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ONE,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ONE,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                next_commitment,
                perm_acc_val,
            );
            set_path_bit(&mut trace, perm_idx, 0);

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in coin_state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }
            let alpha_ext = if extension_degree == 2 {
                [coin_state[4], coin_state[5]]
            } else {
                [coin_state[4], BaseElement::ZERO]
            };
            if fri_alphas.len() < num_fri_layers {
                fri_alphas.push(alpha_ext[0]);
            }
            set_fri_alpha_witness(&mut trace, perm_idx, alpha_ext);
            let tape_values = core::array::from_fn(|i| coin_state[4 + i]);
            set_tape_meta(
                &mut trace,
                perm_idx,
                TAPE_KIND_ALPHA,
                layer_idx as u64,
                tape_values,
            );
            perm_idx += 1;

            for (state_value, commitment_value) in
                coin_state[4..8].iter_mut().zip(next_commitment.iter())
            {
                *state_value += *commitment_value;
            }
        }

        // Placeholder proof-of-work nonce for query grinding.
        let pow_nonce_elem = BaseElement::new(inner.pow_nonce);
        let nonce_word = [
            pow_nonce_elem,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
        ];
        let remainder_reseed = if num_pos_perms > 0 {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        };

        if num_fri_commitments > 0 {
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;
            self.fill_rpo_trace(&mut trace, row_offset, coin_state);
            set_masks(
                &mut trace,
                perm_idx,
                BaseElement::ZERO,
                BaseElement::ZERO,
                remainder_reseed,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                nonce_word,
                perm_acc_val,
            );
            set_path_bit(&mut trace, perm_idx, 0);

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in coin_state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }
            perm_idx += 1;
        }

        // --- Query position draw permutations + decomposition -------------------------------
        if num_pos_perms > 0 {
            coin_state[4] += pow_nonce_elem;

            let mut remaining_draws = self.pub_inputs.num_draws;
            let domain_size = lde_domain_size.max(1);
            let depth_trace_bits = domain_size.trailing_zeros() as usize;
            let v_mask = (domain_size - 1) as u64;

            for pos_idx in 0..num_pos_perms {
                let row_offset = perm_idx * ROWS_PER_PERMUTATION;
                self.fill_rpo_trace(&mut trace, row_offset, coin_state);

                let pos_full_carry = if pos_idx + 1 == num_pos_perms {
                    BaseElement::ZERO
                } else {
                    BaseElement::ONE
                };

                set_masks(
                    &mut trace,
                    perm_idx,
                    BaseElement::ZERO,
                    pos_full_carry,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ONE,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    [BaseElement::ZERO; 4],
                    perm_acc_val,
                );
                set_path_bit(&mut trace, perm_idx, 0);

                let last = row_offset + ROWS_PER_PERMUTATION - 1;
                for (i, value) in coin_state.iter_mut().enumerate() {
                    *value = trace.get(i, last);
                }
                set_pos_witness(&mut trace, perm_idx, &coin_state);
                let rate_outputs: [BaseElement; RATE_WIDTH] =
                    core::array::from_fn(|i| coin_state[4 + i]);
                perm_idx += 1;

                let draws_here = if pos_idx == 0 {
                    remaining_draws.min(RATE_WIDTH - 1)
                } else {
                    remaining_draws.min(RATE_WIDTH)
                };
                let start_rate = if pos_idx == 0 { 1 } else { 0 };

                for d in 0..draws_here {
                    let raw_val = rate_outputs[start_rate + d];
                    let raw_u64 = raw_val.as_int();
                    let masked_pos = (raw_u64 & v_mask) as u64;
                    let p_elem = BaseElement::new(masked_pos);
                    draw_positions.push(masked_pos);

                    // Decomp perm: freeze RPO state and carry buffer.
                    let row0 = perm_idx * ROWS_PER_PERMUTATION;
                    let gamma_limbs = gamma.to_base_elements();
                    for r in 0..ROWS_PER_PERMUTATION {
                        let row = row0 + r;
                        for (i, value) in coin_state.iter().copied().enumerate() {
                            trace.set(i, row, value);
                        }
                        trace.set(COL_POS_DECOMP_MASK, row, BaseElement::ONE);
                        trace.set(COL_POS_RAW, row, raw_val);
                        for (j, value) in rate_outputs.iter().copied().enumerate() {
                            trace.set(COL_POS_START + j, row, value);
                        }
                        trace.set(COL_Z_VALUE, row, gamma_limbs[0]);
                    }

                    let mut acc = 0u64;
                    let mut lo_acc = 0u64;
                    let mut masked_acc = 0u64;
                    let mut hi_and = 0u64;

                    for local_row in 0..ROWS_PER_PERMUTATION {
                        let row = row0 + local_row;
                        let nibble = (raw_u64 >> (4 * local_row)) & 0xF;
                        let bits = [
                            (nibble & 1) as u64,
                            ((nibble >> 1) & 1) as u64,
                            ((nibble >> 2) & 1) as u64,
                            ((nibble >> 3) & 1) as u64,
                        ];
                        trace.set(COL_POS_BIT0, row, BaseElement::new(bits[0]));
                        trace.set(COL_POS_BIT1, row, BaseElement::new(bits[1]));
                        trace.set(COL_POS_BIT2, row, BaseElement::new(bits[2]));
                        trace.set(COL_POS_BIT3, row, BaseElement::new(bits[3]));

                        trace.set(COL_POS_ACC, row, BaseElement::new(acc));
                        trace.set(COL_POS_LO_ACC, row, BaseElement::new(lo_acc));
                        trace.set(COL_POS_MASKED_ACC, row, BaseElement::new(masked_acc));

                        if local_row == 8 {
                            hi_and = 1;
                        }
                        trace.set(COL_POS_HI_AND, row, BaseElement::new(hi_and));

                        let base_exp = 4 * local_row;
                        for (j, bit) in bits.iter().copied().enumerate() {
                            if bit == 1 {
                                acc = acc.wrapping_add(1u64 << (base_exp + j));
                                if base_exp + j < 32 {
                                    lo_acc = lo_acc.wrapping_add(1u64 << (base_exp + j));
                                }
                                if base_exp + j < depth_trace_bits {
                                    masked_acc = masked_acc.wrapping_add(1u64 << (base_exp + j));
                                }
                            }
                        }
                        if local_row >= 8 {
                            let nibble_prod = bits.iter().product::<u64>();
                            hi_and *= nibble_prod;
                        }
                    }

                    for r in 0..ROWS_PER_PERMUTATION {
                        let row = row0 + r;
                        trace.set(COL_POS_SORTED_VALUE, row, p_elem);
                    }

                    let full_carry = BaseElement::ZERO;

                    set_masks(
                        &mut trace,
                        perm_idx,
                        BaseElement::ZERO,
                        full_carry,
                        BaseElement::ZERO,
                        BaseElement::ZERO,
                        BaseElement::ZERO,
                        BaseElement::ZERO,
                        BaseElement::ZERO,
                        BaseElement::ZERO,
                        BaseElement::ZERO,
                        BaseElement::ONE,
                        BaseElement::ZERO,
                        BaseElement::ZERO,
                        [BaseElement::ZERO; 4],
                        perm_acc_val,
                    );
                    set_path_bit(&mut trace, perm_idx, 0);

                    perm_acc_val *= Quad::from(p_elem) + gamma;

                    perm_idx += 1;
                    remaining_draws -= 1;
                    if remaining_draws == 0 {
                        break;
                    }
                }

                if remaining_draws == 0 {
                    break;
                }
            }
        }

        // --- Merkle authentication segment -------------------------------------------------
        assert_eq!(perm_idx, pre_merkle_perms, "pre-merkle perm count mismatch");

        assert_eq!(
            draw_positions.len(),
            self.pub_inputs.num_queries,
            "draw count must match num_queries for Merkle segment"
        );
        assert_eq!(
            inner.query_positions.len(),
            draw_positions.len(),
            "inner query positions must be per-draw"
        );
        assert!(
            inner
                .query_positions
                .iter()
                .zip(draw_positions.iter())
                .all(|(inner_pos, draw_pos)| *inner_pos as u64 == *draw_pos),
            "inner query positions must match transcript draws"
        );

        let mut replay_state = if replay_draws_per_query > 0 {
            Some(DeepReplayState::new(replay_draws_per_query))
        } else {
            None
        };

        // Pre-compute FRI leaf indexes per layer.
        let folding_factor = 2usize;
        let fri_num_partitions = inner.fri_num_partitions;
        let mut positions: Vec<usize> = draw_positions.iter().map(|&p| p as usize).collect();
        let mut domain_size = lde_domain_size;
        let mut fri_indexes: Vec<Vec<usize>> = Vec::with_capacity(num_fri_layers);
        for _layer_idx in 0..num_fri_layers {
            let target_domain_size = domain_size / folding_factor;
            let folded_positions: Vec<usize> =
                positions.iter().map(|p| p % target_domain_size).collect();
            let position_indexes = map_positions_to_indexes(
                &folded_positions,
                domain_size,
                folding_factor,
                fri_num_partitions,
            );
            fri_indexes.push(position_indexes);
            positions = folded_positions;
            domain_size = target_domain_size;
        }

        for (q, &trace_index) in draw_positions.iter().enumerate() {
            if let Some(replay) = replay_state.as_mut() {
                replay.reset(saved_coin_state, ood_digest);
            }
            // Trace leaf + path.
            let trace_row = &inner.trace_evaluations[q];
            let leaf_digest = hash_row_partitioned_perms(
                self,
                &mut trace,
                &mut perm_idx,
                trace_row,
                self.pub_inputs.trace_partition_size,
                perm_acc_val,
                trace_index,
                replay_state.as_mut(),
            );
            perm_acc_val /= Quad::from(BaseElement::new(trace_index)) + gamma;
            let trace_siblings = &inner.trace_auth_paths[q];
            authenticate_merkle_path(
                self,
                &mut trace,
                &mut perm_idx,
                perm_acc_val,
                leaf_digest,
                trace_index,
                trace_siblings,
            );

            // Constraint leaf + path.
            let constraint_index = trace_index;
            let constraint_row = &inner.constraint_evaluations[q];
            let constraint_digest = hash_row_partitioned_perms(
                self,
                &mut trace,
                &mut perm_idx,
                constraint_row,
                constraint_partition_size_base,
                perm_acc_val,
                constraint_index,
                replay_state.as_mut(),
            );
            let constraint_siblings = &inner.constraint_auth_paths[q];
            authenticate_merkle_path(
                self,
                &mut trace,
                &mut perm_idx,
                perm_acc_val,
                constraint_digest,
                constraint_index,
                constraint_siblings,
            );
            if let Some(replay) = replay_state.as_ref() {
                debug_assert_eq!(
                    replay.draw_idx, replay.draws_per_query,
                    "deep replay draw count mismatch for query {q}"
                );
            }

            // FRI layers.
            for (layer, indexes_for_layer) in inner
                .fri_layers
                .iter()
                .take(num_fri_layers)
                .zip(fri_indexes.iter())
            {
                let leaf_len = folding_factor * extension_degree;
                let start = q * leaf_len;
                let end = start + leaf_len;
                let leaf_vals = &layer.evaluations[start..end];
                let fri_index = indexes_for_layer[q] as u64;
                let fri_digest = hash_leaf_perms(
                    self,
                    &mut trace,
                    &mut perm_idx,
                    leaf_vals,
                    perm_acc_val,
                    fri_index,
                    fri_index & 1,
                );
                let fri_siblings = &layer.auth_paths[q];
                authenticate_merkle_path(
                    self,
                    &mut trace,
                    &mut perm_idx,
                    perm_acc_val,
                    fri_digest,
                    fri_index,
                    fri_siblings,
                );
            }
        }

        // --- Remainder polynomial commitment hash -----------------------------------------
        if num_fri_commitments > 0 {
            let _ = hash_leaf_perms(
                self,
                &mut trace,
                &mut perm_idx,
                &inner.fri_remainder,
                perm_acc_val,
                0,
                0,
            );
        }

        // --- Padding permutations -----------------------------------------------------------
        let total_perms = total_rows / ROWS_PER_PERMUTATION;
        let mut pad_state = [BaseElement::ZERO; STATE_WIDTH];
        while perm_idx < total_perms {
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;
            self.fill_rpo_trace(&mut trace, row_offset, pad_state);
            set_masks(
                &mut trace,
                perm_idx,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
                [BaseElement::ZERO; 4],
                perm_acc_val,
            );
            set_path_bit(&mut trace, perm_idx, 0);

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, value) in pad_state.iter_mut().enumerate() {
                *value = trace.get(i, last);
            }
            perm_idx += 1;
        }

        let inner_is_rpo_air = self.pub_inputs.inner_public_inputs.len() == 2 * STATE_WIDTH;
        let inner_is_transaction_air =
            self.pub_inputs.inner_public_inputs.len() == transaction_public_inputs_len();
        if inner_is_rpo_air || inner_is_transaction_air {
            debug_assert_eq!(
                constraint_coeffs.len(),
                num_coeffs_total,
                "unexpected constraint coeff count"
            );
            debug_assert_eq!(
                deep_coeffs.len(),
                num_deep_coeffs,
                "unexpected DEEP coeff count"
            );
        }
        debug_assert_eq!(
            fri_alphas.len(),
            num_fri_layers,
            "unexpected FRI alpha count"
        );

        // Fill constant columns (used by in-circuit checks).
        for row in 0..trace.length() {
            for (i, value) in ood_digest.iter().copied().enumerate() {
                trace.set(COL_OOD_DIGEST_START + i, row, value);
            }
            for (i, value) in saved_coin_state.iter().copied().enumerate() {
                trace.set(COL_SAVED_COIN_START + i, row, value);
            }
            for (i, value) in constraint_coeffs
                .iter()
                .copied()
                .take(NUM_CONSTRAINT_COEFFS)
                .enumerate()
            {
                if i < RESERVED_CONSTRAINT_COEFF_COLS {
                    continue;
                }
                trace.set(COL_CONSTRAINT_COEFFS_START + i, row, value);
            }
            for (i, value) in deep_coeffs
                .iter()
                .copied()
                .take(NUM_DEEP_COEFFS)
                .enumerate()
            {
                trace.set(COL_DEEP_COEFFS_START + i, row, value);
            }
            if extension_degree == 2 {
                let gamma_limb1 = gamma.to_base_elements()[1];
                trace.set(COL_Z_VALUE_LIMB1, row, gamma_limb1);
            }
            for (i, value) in fri_alphas
                .iter()
                .copied()
                .chain(core::iter::repeat(BaseElement::ZERO))
                .take(MAX_FRI_LAYERS)
                .enumerate()
            {
                trace.set(COL_FRI_ALPHA_START + i, row, value);
            }
            if inner_is_rpo_air {
                for (i, value) in ood_evals.iter().copied().enumerate() {
                    trace.set(COL_OOD_EVALS_START + i, row, value);
                }
            }
        }

        // Populate DEEP/FRI recursion state columns (TraceTable::new() leaves memory uninitialized).
        //
        // For verifier-as-inner proofs (depth-2+), DEEP/FRI logic remains gated off; for RPO and
        // transaction proofs we compute the full state so recursion constraints are sound.
        if inner_is_rpo_air || inner_is_transaction_air {
            let g_trace = BaseElement::get_root_of_unity(self.pub_inputs.trace_length.ilog2());
            let g_lde = BaseElement::get_root_of_unity(lde_domain_size.ilog2());
            let domain_offset = BaseElement::GENERATOR;
            let deep_evals: Vec<Quad> = draw_positions
                .iter()
                .copied()
                .enumerate()
                .map(|(q, pos)| {
                    let x = domain_offset * g_lde.exp(pos);
                    if extension_degree == 2 {
                        quad_from_ext(compute_deep_evaluation_quadratic(
                            x,
                            &inner.trace_evaluations[q],
                            &inner.constraint_evaluations[q],
                            &inner.ood_trace_current,
                            &inner.ood_trace_next,
                            &inner.ood_quotient_current,
                            &inner.ood_quotient_next,
                            &inner.deep_coeffs,
                            expected_z,
                            g_trace,
                        ))
                    } else {
                        Quad::from(compute_deep_evaluation(
                            x,
                            &inner.trace_evaluations[q],
                            &inner.constraint_evaluations[q],
                            &inner.ood_trace_current,
                            &inner.ood_trace_next,
                            &inner.ood_quotient_current,
                            &inner.ood_quotient_next,
                            &inner.deep_coeffs,
                            expected_z[0],
                            g_trace,
                        ))
                    }
                })
                .collect();
            let fri_alphas_ext: Vec<Quad> = if extension_degree == 2 {
                inner
                    .fri_alphas
                    .chunks_exact(EXTENSION_LIMBS)
                    .map(|chunk| Quad::new(chunk[0], chunk[1]))
                    .collect()
            } else {
                inner.fri_alphas.iter().copied().map(Quad::from).collect()
            };
            self.populate_deep_fri_state(
                &mut trace,
                pre_merkle_perms,
                trace_leaf_perms,
                constraint_leaf_perms,
                depth_trace,
                num_fri_layers,
                &deep_evals,
                &fri_alphas_ext,
                &inner.fri_remainder,
                &inner.ood_trace_current,
                &inner.ood_trace_next,
                &inner.ood_quotient_current,
                &inner.ood_quotient_next,
                &inner.deep_coeffs,
            );
        } else {
            #[cfg(feature = "unsound-recursion")]
            {
                for row in 0..trace.length() {
                    trace.set(COL_DEEP_T1_ACC, row, BaseElement::ZERO);
                    trace.set(COL_DEEP_T1_ACC_LIMB1, row, BaseElement::ZERO);
                    trace.set(COL_DEEP_T2_ACC, row, BaseElement::ZERO);
                    trace.set(COL_DEEP_T2_ACC_LIMB1, row, BaseElement::ZERO);
                    trace.set(COL_DEEP_C1_ACC, row, BaseElement::ZERO);
                    trace.set(COL_DEEP_C1_ACC_LIMB1, row, BaseElement::ZERO);
                    trace.set(COL_DEEP_C2_ACC, row, BaseElement::ZERO);
                    trace.set(COL_DEEP_C2_ACC_LIMB1, row, BaseElement::ZERO);

                    trace.set(COL_FRI_EVAL, row, BaseElement::ZERO);
                    trace.set(COL_FRI_EVAL_LIMB1, row, BaseElement::ZERO);
                    trace.set(COL_FRI_X, row, BaseElement::ZERO);
                    trace.set(COL_FRI_POW, row, BaseElement::ZERO);

                    for i in 0..NUM_FRI_MSB_BITS {
                        trace.set(COL_FRI_MSB_BITS_START + i, row, BaseElement::ZERO);
                    }
                    for i in 0..NUM_REMAINDER_COEFFS {
                        trace.set(COL_REMAINDER_COEFFS_START + i, row, BaseElement::ZERO);
                    }
                    if extension_degree == 2 {
                        for i in 0..NUM_REMAINDER_COEFFS {
                            trace.set(COL_REMAINDER_COEFFS_EXT_START + i, row, BaseElement::ZERO);
                        }
                    }
                }
            }
            #[cfg(not(feature = "unsound-recursion"))]
            {
                panic!(
                    "verifier-as-inner recursion is disabled; enable `epoch-circuit/unsound-recursion` to allow gated DEEP/FRI"
                );
            }
        }

        trace
    }

    fn populate_deep_fri_state(
        &self,
        trace: &mut TraceTable<BaseElement>,
        pre_merkle_perms: usize,
        trace_leaf_perms: usize,
        constraint_leaf_perms: usize,
        depth_trace: usize,
        num_fri_layers: usize,
        deep_evals: &[Quad],
        fri_alphas: &[Quad],
        remainder_coeffs: &[BaseElement],
        ood_trace_current: &[BaseElement],
        ood_trace_next: &[BaseElement],
        ood_quotient_current: &[BaseElement],
        ood_quotient_next: &[BaseElement],
        deep_coeffs: &DeepCompositionCoefficients<BaseElement>,
    ) {
        const RATE_START_COL: usize = 4;

        let total_rows = trace.length();
        let num_queries = self.pub_inputs.num_queries;
        debug_assert_eq!(deep_evals.len(), num_queries, "unexpected deep eval count");
        debug_assert_eq!(
            fri_alphas.len(),
            num_fri_layers,
            "unexpected FRI alpha count"
        );
        let extension_degree = match self.pub_inputs.field_extension {
            FieldExtension::None => 1,
            FieldExtension::Quadratic => 2,
            FieldExtension::Cubic => 3,
        };
        let is_quadratic = extension_degree == 2;
        let trace_leaf_len = ood_trace_current.len();
        let constraint_leaf_len = ood_quotient_current.len();
        let constraint_partition_size_base =
            self.pub_inputs.constraint_partition_size * extension_degree;
        let trace_leaf_chain =
            leaf_chain_flags(trace_leaf_len, self.pub_inputs.trace_partition_size);
        let constraint_leaf_chain =
            leaf_chain_flags(constraint_leaf_len, constraint_partition_size_base);
        debug_assert_eq!(
            trace_leaf_chain.len(),
            trace_leaf_perms,
            "trace leaf chain length mismatch"
        );
        debug_assert_eq!(
            constraint_leaf_chain.len(),
            constraint_leaf_perms,
            "constraint leaf chain length mismatch"
        );
        debug_assert_eq!(
            deep_coeffs.trace.len(),
            ood_trace_current.len(),
            "trace coeff length mismatch"
        );
        debug_assert_eq!(
            deep_coeffs.constraints.len(),
            ood_quotient_current.len(),
            "constraint coeff length mismatch"
        );

        let build_data_perm_map = |len: usize, partition_size: usize| {
            let hash_perms = |input_len: usize| input_len.div_ceil(RATE_WIDTH).max(1);
            if len == 0 {
                return (Vec::new(), Vec::new());
            }

            let mut data_perm_map = Vec::new();
            let mut data_perm_starts = Vec::new();
            let mut remaining = len;
            let mut offset = 0usize;
            let mut data_idx = 0usize;

            if partition_size >= len {
                let perms = hash_perms(len);
                for perm in 0..perms {
                    data_perm_map.push(Some(data_idx));
                    data_perm_starts.push(offset + perm * RATE_WIDTH);
                    data_idx += 1;
                }
                return (data_perm_map, data_perm_starts);
            }

            while remaining > 0 {
                let part_len = remaining.min(partition_size);
                let perms = hash_perms(part_len);
                for perm in 0..perms {
                    data_perm_map.push(Some(data_idx));
                    data_perm_starts.push(offset + perm * RATE_WIDTH);
                    data_idx += 1;
                }
                remaining -= part_len;
                offset += part_len;
            }

            let num_partitions = len.div_ceil(partition_size);
            let merged_len = num_partitions * DIGEST_WIDTH;
            let merged_perms = hash_perms(merged_len);
            for _ in 0..merged_perms {
                data_perm_map.push(None);
            }
            (data_perm_map, data_perm_starts)
        };

        let (trace_data_perm_map, trace_data_starts) =
            build_data_perm_map(trace_leaf_len, self.pub_inputs.trace_partition_size);
        let (constraint_data_perm_map, constraint_data_starts) =
            build_data_perm_map(constraint_leaf_len, constraint_partition_size_base);
        debug_assert_eq!(
            trace_data_perm_map.len(),
            trace_leaf_perms,
            "trace data perm map length mismatch"
        );
        debug_assert_eq!(
            constraint_data_perm_map.len(),
            constraint_leaf_perms,
            "constraint data perm map length mismatch"
        );

        // Fill remainder coefficients (constant across the entire verifier trace).
        let mut remainder0 = [BaseElement::ZERO; NUM_REMAINDER_COEFFS];
        let mut remainder1 = [BaseElement::ZERO; NUM_REMAINDER_COEFFS];
        for (i, coeff) in remainder_coeffs
            .iter()
            .take(NUM_REMAINDER_COEFFS)
            .enumerate()
        {
            remainder0[i] = *coeff;
        }
        if is_quadratic {
            for (i, coeff) in remainder_coeffs
                .iter()
                .skip(NUM_REMAINDER_COEFFS)
                .take(NUM_REMAINDER_COEFFS)
                .enumerate()
            {
                remainder1[i] = *coeff;
            }
        }
        for row in 0..total_rows {
            for (i, value) in remainder0.iter().copied().enumerate() {
                trace.set(COL_REMAINDER_COEFFS_START + i, row, value);
            }
            if is_quadratic {
                for (i, value) in remainder1.iter().copied().enumerate() {
                    trace.set(COL_REMAINDER_COEFFS_EXT_START + i, row, value);
                }
            }
        }

        #[derive(Clone, Copy, Debug)]
        enum Event {
            QueryReset { query_idx: usize },
            TraceLeaf { start_idx: usize, block_len: usize },
            ConstraintLeaf { start_idx: usize, block_len: usize },
            TraceMerkleBit { bit_idx: usize },
            FriLeaf { layer_idx: usize },
        }

        let mut events: Vec<Option<Event>> = vec![None; total_rows];

        let mut perm_idx = pre_merkle_perms;
        for query_idx in 0..num_queries {
            let query_row0 = perm_idx * ROWS_PER_PERMUTATION;
            if query_row0 > 0 && query_row0 - 1 < total_rows {
                debug_assert!(
                    events[query_row0 - 1].is_none(),
                    "duplicate event at row {}",
                    query_row0 - 1
                );
                events[query_row0 - 1] = Some(Event::QueryReset { query_idx });
            }

            // --- Trace leaf hashing -----------------------------------------------------
            let trace_chain_start =
                |rel_perm: usize| rel_perm == 0 || !trace_leaf_chain[rel_perm - 1];
            let constraint_chain_start =
                |rel_perm: usize| rel_perm == 0 || !constraint_leaf_chain[rel_perm - 1];

            let mut rel_perm = 0usize;
            while rel_perm < trace_leaf_perms {
                if trace_chain_start(rel_perm) {
                    perm_idx += 1; // paired deep replay draw perm
                }
                let row0 = perm_idx * ROWS_PER_PERMUTATION;
                let boundary = row0 + ROWS_PER_PERMUTATION - 1;

                if row0 < total_rows {
                    if let Some(data_idx) = trace_data_perm_map[rel_perm] {
                        let start_idx = trace_data_starts[data_idx];
                        let block_len = trace_leaf_len.saturating_sub(start_idx).min(RATE_WIDTH);
                        debug_assert!(events[row0].is_none(), "duplicate event at row {}", row0);
                        events[row0] = Some(Event::TraceLeaf {
                            start_idx,
                            block_len,
                        });
                    }
                }

                if depth_trace > 0 && rel_perm + 1 == trace_leaf_perms && boundary < total_rows {
                    debug_assert!(
                        events[boundary].is_none(),
                        "duplicate event at row {}",
                        boundary
                    );
                    events[boundary] = Some(Event::TraceMerkleBit { bit_idx: 0 });
                }

                perm_idx += 1;
                rel_perm += 1;
            }

            // --- Trace Merkle path ------------------------------------------------------
            for level in 0..depth_trace {
                let row0 = perm_idx * ROWS_PER_PERMUTATION;
                let boundary = row0 + ROWS_PER_PERMUTATION - 1;
                if level + 1 < depth_trace && boundary < total_rows {
                    debug_assert!(
                        events[boundary].is_none(),
                        "duplicate event at row {}",
                        boundary
                    );
                    events[boundary] = Some(Event::TraceMerkleBit { bit_idx: level + 1 });
                }
                perm_idx += 1;
            }

            // --- Constraint leaf hashing ------------------------------------------------
            let mut rel_perm = 0usize;
            while rel_perm < constraint_leaf_perms {
                if constraint_chain_start(rel_perm) {
                    perm_idx += 1; // paired deep replay draw perm
                }
                let row0 = perm_idx * ROWS_PER_PERMUTATION;
                if row0 < total_rows {
                    if let Some(data_idx) = constraint_data_perm_map[rel_perm] {
                        let start_idx = constraint_data_starts[data_idx];
                        let block_len = constraint_leaf_len
                            .saturating_sub(start_idx)
                            .min(RATE_WIDTH);
                        debug_assert!(events[row0].is_none(), "duplicate event at row {}", row0);
                        events[row0] = Some(Event::ConstraintLeaf {
                            start_idx,
                            block_len,
                        });
                    }
                }
                perm_idx += 1;
                rel_perm += 1;
            }

            // --- Constraint Merkle path -------------------------------------------------
            perm_idx += depth_trace;

            // --- FRI layers --------------------------------------------------------------
            for layer_idx in 0..num_fri_layers {
                let row0 = perm_idx * ROWS_PER_PERMUTATION;
                if row0 < total_rows {
                    debug_assert!(events[row0].is_none(), "duplicate event at row {}", row0);
                    events[row0] = Some(Event::FriLeaf { layer_idx });
                }
                perm_idx += 1; // leaf
                let layer_depth = depth_trace.saturating_sub(layer_idx + 1);
                perm_idx += layer_depth;
            }
        }

        // Compute verifier-domain parameters (must match StarkVerifierAir::new).
        let lde_domain_size = self.pub_inputs.trace_length * self.pub_inputs.blowup_factor;
        let g_lde = BaseElement::get_root_of_unity(lde_domain_size.ilog2());
        let domain_offset = BaseElement::GENERATOR;
        let inv_domain_offset = domain_offset.inv();

        #[derive(Clone, Debug)]
        struct State {
            t1: Quad,
            t2: Quad,
            c1: Quad,
            c2: Quad,
            eval: Quad,
            x: BaseElement,
            pow: BaseElement,
            msb_bits: Vec<BaseElement>,
        }

        let mut state = State {
            t1: Quad::ZERO,
            t2: Quad::ZERO,
            c1: Quad::ZERO,
            c2: Quad::ZERO,
            eval: Quad::ZERO,
            x: domain_offset,
            pow: g_lde,
            msb_bits: vec![BaseElement::ZERO; num_fri_layers],
        };

        let write_row = |trace: &mut TraceTable<BaseElement>, row: usize, state: &State| {
            let t1 = state.t1.to_base_elements();
            let t2 = state.t2.to_base_elements();
            let c1 = state.c1.to_base_elements();
            let c2 = state.c2.to_base_elements();
            let eval = state.eval.to_base_elements();
            trace.set(COL_DEEP_T1_ACC, row, t1[0]);
            trace.set(COL_DEEP_T1_ACC_LIMB1, row, t1[1]);
            trace.set(COL_DEEP_T2_ACC, row, t2[0]);
            trace.set(COL_DEEP_T2_ACC_LIMB1, row, t2[1]);
            trace.set(COL_DEEP_C1_ACC, row, c1[0]);
            trace.set(COL_DEEP_C1_ACC_LIMB1, row, c1[1]);
            trace.set(COL_DEEP_C2_ACC, row, c2[0]);
            trace.set(COL_DEEP_C2_ACC_LIMB1, row, c2[1]);
            trace.set(COL_FRI_EVAL, row, eval[0]);
            trace.set(COL_FRI_EVAL_LIMB1, row, eval[1]);
            trace.set(COL_FRI_X, row, state.x);
            trace.set(COL_FRI_POW, row, state.pow);
            for i in 0..NUM_FRI_MSB_BITS {
                let b = state.msb_bits.get(i).copied().unwrap_or(BaseElement::ZERO);
                trace.set(COL_FRI_MSB_BITS_START + i, row, b);
            }
        };

        // Set row 0 deterministically.
        write_row(trace, 0, &state);

        let one = BaseElement::ONE;
        let two = BaseElement::new(2);

        for (row, event) in events
            .iter()
            .copied()
            .enumerate()
            .take(total_rows.saturating_sub(1))
        {
            let mut next = state.clone();

            if let Some(event) = event {
                match event {
                    Event::QueryReset { query_idx } => {
                        next.t1 = Quad::ZERO;
                        next.t2 = Quad::ZERO;
                        next.c1 = Quad::ZERO;
                        next.c2 = Quad::ZERO;
                        next.eval = deep_evals[query_idx];
                        next.x = domain_offset;
                        next.pow = g_lde;
                        for b in next.msb_bits.iter_mut() {
                            *b = BaseElement::ZERO;
                        }
                    }
                    Event::TraceLeaf {
                        start_idx,
                        block_len,
                    } => {
                        let mut t1_delta = Quad::ZERO;
                        let mut t2_delta = Quad::ZERO;
                        let mut j = 0usize;
                        if is_quadratic {
                            debug_assert!(block_len.is_multiple_of(EXTENSION_LIMBS));
                        }
                        while j < block_len {
                            let idx = start_idx + j;
                            let coeff = if is_quadratic {
                                Quad::new(deep_coeffs.trace[idx], deep_coeffs.trace[idx + 1])
                            } else {
                                Quad::from(deep_coeffs.trace[idx])
                            };
                            let trace_val = if is_quadratic {
                                Quad::new(
                                    trace.get(RATE_START_COL + j, row),
                                    trace.get(RATE_START_COL + j + 1, row),
                                )
                            } else {
                                Quad::from(trace.get(RATE_START_COL + j, row))
                            };
                            let ood_z = if is_quadratic {
                                Quad::new(ood_trace_current[idx], ood_trace_current[idx + 1])
                            } else {
                                Quad::from(ood_trace_current[idx])
                            };
                            let ood_zg = if is_quadratic {
                                Quad::new(ood_trace_next[idx], ood_trace_next[idx + 1])
                            } else {
                                Quad::from(ood_trace_next[idx])
                            };
                            t1_delta += coeff * (trace_val - ood_z);
                            t2_delta += coeff * (trace_val - ood_zg);
                            j += extension_degree;
                        }
                        next.t1 += t1_delta;
                        next.t2 += t2_delta;
                    }
                    Event::ConstraintLeaf {
                        start_idx,
                        block_len,
                    } => {
                        let mut c1_delta = Quad::ZERO;
                        let mut c2_delta = Quad::ZERO;
                        let mut j = 0usize;
                        if is_quadratic {
                            debug_assert!(block_len.is_multiple_of(EXTENSION_LIMBS));
                        }
                        while j < block_len {
                            let idx = start_idx + j;
                            let coeff = if is_quadratic {
                                Quad::new(
                                    deep_coeffs.constraints[idx],
                                    deep_coeffs.constraints[idx + 1],
                                )
                            } else {
                                Quad::from(deep_coeffs.constraints[idx])
                            };
                            let val = if is_quadratic {
                                Quad::new(
                                    trace.get(RATE_START_COL + j, row),
                                    trace.get(RATE_START_COL + j + 1, row),
                                )
                            } else {
                                Quad::from(trace.get(RATE_START_COL + j, row))
                            };
                            let ood_z = if is_quadratic {
                                Quad::new(ood_quotient_current[idx], ood_quotient_current[idx + 1])
                            } else {
                                Quad::from(ood_quotient_current[idx])
                            };
                            let ood_zg = if is_quadratic {
                                Quad::new(ood_quotient_next[idx], ood_quotient_next[idx + 1])
                            } else {
                                Quad::from(ood_quotient_next[idx])
                            };
                            c1_delta += coeff * (val - ood_z);
                            c2_delta += coeff * (val - ood_zg);
                            j += extension_degree;
                        }
                        next.c1 += c1_delta;
                        next.c2 += c2_delta;
                    }
                    Event::TraceMerkleBit { bit_idx } => {
                        let path_bit = trace.get(COL_MERKLE_PATH_BIT, row);
                        next.x = state.x + state.x * path_bit * (state.pow - one);
                        next.pow = state.pow * state.pow;

                        let capture_layer = depth_trace.saturating_sub(1 + bit_idx);
                        if capture_layer < num_fri_layers {
                            next.msb_bits[capture_layer] = path_bit;
                        }
                    }
                    Event::FriLeaf { layer_idx } => {
                        let b = state.msb_bits[layer_idx];
                        let v0 = if is_quadratic {
                            Quad::new(
                                trace.get(RATE_START_COL, row),
                                trace.get(RATE_START_COL + 1, row),
                            )
                        } else {
                            Quad::from(trace.get(RATE_START_COL, row))
                        };
                        let v1 = if is_quadratic {
                            Quad::new(
                                trace.get(RATE_START_COL + 2, row),
                                trace.get(RATE_START_COL + 3, row),
                            )
                        } else {
                            Quad::from(trace.get(RATE_START_COL + 1, row))
                        };
                        let alpha = fri_alphas[layer_idx];

                        let selected = v0 + (v1 - v0) * Quad::from(b);
                        debug_assert_eq!(
                            state.eval, selected,
                            "FRI layer {layer_idx} eval mismatch at row {row}"
                        );

                        let sign = one - two * b;
                        let x_base = state.x * sign;
                        let x_ext = Quad::from(x_base);
                        let rhs = (x_ext + alpha) * v0 + (x_ext - alpha) * v1;
                        let denom = Quad::from(two * x_base);
                        next.eval = rhs / denom;
                        next.x = state.x * state.x * inv_domain_offset;
                    }
                }
            }

            write_row(trace, row + 1, &next);
            state = next;
        }
    }

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

fn set_masks(
    trace: &mut TraceTable<BaseElement>,
    perm_idx: usize,
    carry: BaseElement,
    full_carry: BaseElement,
    reseed: BaseElement,
    coin_init: BaseElement,
    coeff_mask: BaseElement,
    z_mask: BaseElement,
    deep_mask: BaseElement,
    fri_mask: BaseElement,
    pos_mask: BaseElement,
    decomp_mask: BaseElement,
    coin_save_mask: BaseElement,
    coin_restore_mask: BaseElement,
    reseed_word: [BaseElement; 4],
    perm_acc: Quad,
) {
    let row_start = perm_idx * ROWS_PER_PERMUTATION;
    let perm_acc = perm_acc.to_base_elements();
    for r in 0..ROWS_PER_PERMUTATION {
        let row = row_start + r;
        trace.set(COL_CARRY_MASK, row, carry);
        trace.set(COL_FULL_CARRY_MASK, row, full_carry);
        trace.set(COL_RESEED_MASK, row, reseed);
        trace.set(COL_COIN_INIT_MASK, row, coin_init);
        trace.set(COL_COEFF_MASK, row, coeff_mask);
        trace.set(COL_Z_MASK, row, z_mask);
        trace.set(COL_DEEP_MASK, row, deep_mask);
        trace.set(COL_FRI_MASK, row, fri_mask);
        trace.set(COL_POS_MASK, row, pos_mask);
        trace.set(COL_POS_DECOMP_MASK, row, decomp_mask);
        trace.set(COL_COIN_SAVE_MASK, row, coin_save_mask);
        let restore = if r == 0 {
            coin_restore_mask
        } else {
            BaseElement::ZERO
        };
        trace.set(COL_COIN_RESTORE_MASK, row, restore);
        trace.set(COL_POS_PERM_ACC, row, perm_acc[0]);
        trace.set(COL_POS_PERM_ACC_LIMB1, row, perm_acc[1]);
        for (i, value) in reseed_word.iter().copied().enumerate() {
            trace.set(COL_RESEED_WORD_START + i, row, value);
        }
    }
}

fn set_tape_meta(
    trace: &mut TraceTable<BaseElement>,
    perm_idx: usize,
    kind: u64,
    index: u64,
    values: [BaseElement; TAPE_WIDTH],
) {
    let row_start = perm_idx * ROWS_PER_PERMUTATION;
    let tape_mask = if kind == TAPE_KIND_NONE {
        BaseElement::ZERO
    } else {
        BaseElement::ONE
    };
    let kind_elem = BaseElement::new(kind);
    let index_elem = BaseElement::new(index);
    for r in 0..ROWS_PER_PERMUTATION {
        let row = row_start + r;
        trace.set(COL_TAPE_MASK, row, tape_mask);
        trace.set(COL_TAPE_KIND, row, kind_elem);
        trace.set(COL_TAPE_INDEX, row, index_elem);
        for (i, value) in values.iter().copied().enumerate() {
            trace.set(COL_TAPE_VALUES_START + i, row, value);
        }
    }
}

fn set_coeff_witness(
    trace: &mut TraceTable<BaseElement>,
    perm_idx: usize,
    state: &[BaseElement; STATE_WIDTH],
) {
    let row_start = perm_idx * ROWS_PER_PERMUTATION;
    for r in 0..ROWS_PER_PERMUTATION {
        let row = row_start + r;
        for i in 0..8 {
            trace.set(COL_COEFF_START + i, row, state[4 + i]);
        }
    }
}

fn set_z_witness(trace: &mut TraceTable<BaseElement>, perm_idx: usize, z: ExtElem) {
    let row_start = perm_idx * ROWS_PER_PERMUTATION;
    for r in 0..ROWS_PER_PERMUTATION {
        trace.set(COL_Z_VALUE, row_start + r, z[0]);
    }
}

fn set_fri_alpha_witness(trace: &mut TraceTable<BaseElement>, perm_idx: usize, alpha: ExtElem) {
    let row_start = perm_idx * ROWS_PER_PERMUTATION;
    for r in 0..ROWS_PER_PERMUTATION {
        trace.set(COL_FRI_ALPHA_VALUE, row_start + r, alpha[0]);
    }
}

fn set_deep_witness(
    trace: &mut TraceTable<BaseElement>,
    perm_idx: usize,
    state: &[BaseElement; STATE_WIDTH],
) {
    let row_start = perm_idx * ROWS_PER_PERMUTATION;
    for r in 0..ROWS_PER_PERMUTATION {
        let row = row_start + r;
        for i in 0..8 {
            trace.set(COL_DEEP_START + i, row, state[4 + i]);
        }
    }
}

fn set_pos_witness(
    trace: &mut TraceTable<BaseElement>,
    perm_idx: usize,
    state: &[BaseElement; STATE_WIDTH],
) {
    let row_start = perm_idx * ROWS_PER_PERMUTATION;
    for r in 0..ROWS_PER_PERMUTATION {
        let row = row_start + r;
        for i in 0..8 {
            trace.set(COL_POS_START + i, row, state[4 + i]);
        }
    }
}

fn set_path_bit(trace: &mut TraceTable<BaseElement>, perm_idx: usize, bit: u64) {
    let row_start = perm_idx * ROWS_PER_PERMUTATION;
    let val = BaseElement::new(bit);
    for r in 0..ROWS_PER_PERMUTATION {
        trace.set(COL_MERKLE_PATH_BIT, row_start + r, val);
    }
}

fn set_merkle_index(trace: &mut TraceTable<BaseElement>, perm_idx: usize, index: u64) {
    let row_start = perm_idx * ROWS_PER_PERMUTATION;
    let val = BaseElement::new(index);
    for r in 0..ROWS_PER_PERMUTATION {
        trace.set(COL_MERKLE_INDEX, row_start + r, val);
    }
}

fn transaction_public_inputs_len() -> usize {
    (transaction_circuit::constants::MAX_INPUTS + transaction_circuit::constants::MAX_OUTPUTS) * 5
        + 24
}

fn leaf_perm_count(leaf_len: usize, partition_size: usize) -> usize {
    let hash_perms = |input_len: usize| input_len.div_ceil(RATE_WIDTH).max(1);

    if partition_size >= leaf_len {
        return hash_perms(leaf_len);
    }

    let mut perms = 0usize;
    let mut remaining = leaf_len;
    while remaining > 0 {
        let part_len = remaining.min(partition_size);
        perms += hash_perms(part_len);
        remaining -= part_len;
    }

    let num_partitions = leaf_len.div_ceil(partition_size);
    let merged_len = num_partitions * DIGEST_WIDTH;
    perms + hash_perms(merged_len)
}

fn leaf_chain_count(leaf_len: usize, partition_size: usize) -> usize {
    if leaf_len == 0 {
        return 0;
    }
    if partition_size >= leaf_len {
        return 1;
    }
    let num_partitions = leaf_len.div_ceil(partition_size);
    num_partitions + 1
}

fn leaf_chain_flags(leaf_len: usize, partition_size: usize) -> Vec<bool> {
    let hash_perms = |input_len: usize| input_len.div_ceil(RATE_WIDTH).max(1);

    if leaf_len == 0 {
        return Vec::new();
    }
    if partition_size >= leaf_len {
        let perms = hash_perms(leaf_len);
        let mut chain = vec![false; perms];
        for value in chain.iter_mut().take(perms.saturating_sub(1)) {
            *value = true;
        }
        return chain;
    }

    let mut chain = Vec::new();
    let mut remaining = leaf_len;
    while remaining > 0 {
        let part_len = remaining.min(partition_size);
        let perms = hash_perms(part_len);
        chain.extend((0..perms).map(|i| i + 1 < perms));
        remaining -= part_len;
    }

    let num_partitions = leaf_len.div_ceil(partition_size);
    let merged_len = num_partitions * DIGEST_WIDTH;
    let merged_perms = hash_perms(merged_len);
    chain.extend((0..merged_perms).map(|i| i + 1 < merged_perms));
    chain
}

struct DeepReplayState {
    coin_state: [BaseElement; STATE_WIDTH],
    draw_idx: usize,
    draws_per_query: usize,
}

impl DeepReplayState {
    fn new(draws_per_query: usize) -> Self {
        Self {
            coin_state: [BaseElement::ZERO; STATE_WIDTH],
            draw_idx: 0,
            draws_per_query,
        }
    }

    fn reset(
        &mut self,
        saved_coin_state: [BaseElement; STATE_WIDTH],
        ood_digest: [BaseElement; DIGEST_WIDTH],
    ) {
        self.coin_state = saved_coin_state;
        for (state_value, digest_value) in self.coin_state[4..8].iter_mut().zip(ood_digest.iter()) {
            *state_value += *digest_value;
        }
        self.draw_idx = 0;
    }

    fn emit(
        &mut self,
        prover: &StarkVerifierProver,
        trace: &mut TraceTable<BaseElement>,
        perm_idx: &mut usize,
        perm_acc: Quad,
    ) {
        debug_assert!(
            self.draw_idx < self.draws_per_query,
            "deep replay draw index out of bounds"
        );
        let row_offset = *perm_idx * ROWS_PER_PERMUTATION;
        prover.fill_rpo_trace(trace, row_offset, self.coin_state);

        let is_first = self.draw_idx == 0;
        let full_carry = BaseElement::ZERO;
        let coin_restore_mask = if is_first {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        };

        set_masks(
            trace,
            *perm_idx,
            BaseElement::ZERO,
            full_carry,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ONE,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            coin_restore_mask,
            [BaseElement::ZERO; 4],
            perm_acc,
        );
        set_path_bit(trace, *perm_idx, 0);

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for (i, value) in self.coin_state.iter_mut().enumerate() {
            *value = trace.get(i, last);
        }
        set_deep_witness(trace, *perm_idx, &self.coin_state);
        let tape_values = core::array::from_fn(|i| self.coin_state[4 + i]);
        set_tape_meta(
            trace,
            *perm_idx,
            TAPE_KIND_DEEP,
            self.draw_idx as u64,
            tape_values,
        );
        *perm_idx += 1;
        self.draw_idx += 1;
    }
}

fn hash_row_partitioned_perms(
    prover: &StarkVerifierProver,
    trace: &mut TraceTable<BaseElement>,
    perm_idx: &mut usize,
    row: &[BaseElement],
    partition_size: usize,
    perm_acc: Quad,
    merkle_index: u64,
    mut deep_replay: Option<&mut DeepReplayState>,
) -> [BaseElement; DIGEST_WIDTH] {
    if partition_size >= row.len() {
        if let Some(replay) = deep_replay.as_mut() {
            (*replay).emit(prover, trace, perm_idx, perm_acc);
        }
        return hash_leaf_perms(
            prover,
            trace,
            perm_idx,
            row,
            perm_acc,
            merkle_index,
            merkle_index & 1,
        );
    }

    let num_partitions = row.len().div_ceil(partition_size);
    let mut merged_elements = Vec::with_capacity(num_partitions * DIGEST_WIDTH);
    for chunk in row.chunks(partition_size) {
        if let Some(replay) = deep_replay.as_mut() {
            (*replay).emit(prover, trace, perm_idx, perm_acc);
        }
        let digest = hash_leaf_perms(prover, trace, perm_idx, chunk, perm_acc, 0, 0);
        merged_elements.extend_from_slice(&digest);
    }

    if let Some(replay) = deep_replay.as_mut() {
        (*replay).emit(prover, trace, perm_idx, perm_acc);
    }
    hash_leaf_perms(
        prover,
        trace,
        perm_idx,
        &merged_elements,
        perm_acc,
        merkle_index,
        merkle_index & 1,
    )
}

fn hash_leaf_perms(
    prover: &StarkVerifierProver,
    trace: &mut TraceTable<BaseElement>,
    perm_idx: &mut usize,
    leaf_elems: &[BaseElement],
    perm_acc: Quad,
    merkle_index: u64,
    final_path_bit: u64,
) -> [BaseElement; DIGEST_WIDTH] {
    let leaf_len = leaf_elems.len();
    let num_blocks = leaf_len.div_ceil(8).max(1);

    let mut leaf_state = [BaseElement::ZERO; STATE_WIDTH];
    leaf_state[0] = BaseElement::new((leaf_len % 8) as u64);

    for block in 0..num_blocks {
        let row_offset = *perm_idx * ROWS_PER_PERMUTATION;
        let start = block * 8;
        for i in 0..8 {
            leaf_state[4 + i] = if start + i < leaf_len {
                leaf_elems[start + i]
            } else {
                BaseElement::ZERO
            };
        }

        prover.fill_rpo_trace(trace, row_offset, leaf_state);

        let carry = if block + 1 < num_blocks {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        };
        set_masks(
            trace,
            *perm_idx,
            carry,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            [BaseElement::ZERO; 4],
            perm_acc,
        );
        let path_bit = if block + 1 == num_blocks {
            final_path_bit
        } else {
            0
        };
        set_path_bit(trace, *perm_idx, path_bit);
        set_merkle_index(trace, *perm_idx, merkle_index);

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for (i, value) in leaf_state.iter_mut().enumerate() {
            *value = trace.get(i, last);
        }

        *perm_idx += 1;
    }

    [leaf_state[4], leaf_state[5], leaf_state[6], leaf_state[7]]
}

fn authenticate_merkle_path(
    prover: &StarkVerifierProver,
    trace: &mut TraceTable<BaseElement>,
    perm_idx: &mut usize,
    perm_acc: Quad,
    leaf_digest: [BaseElement; DIGEST_WIDTH],
    index: u64,
    siblings: &[[BaseElement; DIGEST_WIDTH]],
) -> [BaseElement; DIGEST_WIDTH] {
    let mut current_hash = leaf_digest;
    let depth = siblings.len();

    for (level, &sibling) in siblings.iter().enumerate() {
        let bit = (index >> level) & 1;
        let (left, right) = if bit == 1 {
            (sibling, current_hash)
        } else {
            (current_hash, sibling)
        };

        let mut merge_state = [BaseElement::ZERO; STATE_WIDTH];
        merge_state[4..4 + DIGEST_WIDTH].copy_from_slice(&left);
        merge_state[4 + DIGEST_WIDTH..4 + 2 * DIGEST_WIDTH].copy_from_slice(&right);

        let row_offset = *perm_idx * ROWS_PER_PERMUTATION;
        prover.fill_rpo_trace(trace, row_offset, merge_state);
        set_masks(
            trace,
            *perm_idx,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            [BaseElement::ZERO; 4],
            perm_acc,
        );

        let next_bit = if level + 1 < depth {
            (index >> (level + 1)) & 1
        } else {
            0
        };
        set_path_bit(trace, *perm_idx, next_bit);
        set_merkle_index(trace, *perm_idx, index >> (level + 1));

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for (i, value) in current_hash.iter_mut().enumerate() {
            *value = trace.get(4 + i, last);
        }

        *perm_idx += 1;
    }

    current_hash
}

impl Prover for StarkVerifierProver {
    type BaseField = BaseElement;
    type Air = StarkVerifierAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> StarkVerifierPublicInputs {
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

// ----------------------------------------------------------------------------
// Helper functions (duplicated from rpo_air)

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
    use super::rpo_air::INV_ALPHA;
    for elem in state.iter_mut() {
        *elem = elem.exp(INV_ALPHA.into());
    }
}

#[cfg(test)]
mod tests {
    use super::super::rpo_air::STATE_WIDTH as INNER_STATE_WIDTH;
    use super::super::{RpoAir, RpoStarkProver};
    use super::*;
    use miden_crypto::hash::rpo::Rpo256;
    use miden_crypto::rand::RpoRandomCoin;
    use transaction_circuit::constants::NATIVE_ASSET_ID;
    use transaction_circuit::hashing::{felts_to_bytes32, merkle_node, HashFelt};
    use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
    use transaction_circuit::public_inputs::StablecoinPolicyBinding;
    use transaction_circuit::rpo_prover::TransactionProverStarkRpo;
    use transaction_circuit::witness::TransactionWitness;
    use transaction_circuit::TransactionAirStark;
    use winter_air::{AirContext, Assertion, TraceInfo, TransitionConstraintDegree};
    use winter_air::{BatchingMethod, EvaluationFrame, FieldExtension};
    use winter_crypto::MerkleTree;
    use winter_math::FieldElement;
    use winter_math::ToElements;
    use winterfell::verify;
    use winterfell::AcceptableOptions;
    use winterfell::Air;
    use winterfell::Prover;
    use winterfell::Trace;

    fn test_options(num_queries: usize) -> ProofOptions {
        ProofOptions::new(
            num_queries,
            32, // RPO constraints need blowup >= 32 for cycle length 16.
            0,
            FieldExtension::None,
            2,
            7,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        )
    }

    fn eval_transition_row(
        air: &StarkVerifierAir,
        trace: &TraceTable<BaseElement>,
        periodic_columns: &[Vec<BaseElement>],
        row: usize,
    ) -> Vec<BaseElement> {
        let mut periodic_values_row = Vec::with_capacity(periodic_columns.len());
        for col in periodic_columns.iter() {
            periodic_values_row.push(col[row]);
        }

        let width = trace.width();
        let current_row: Vec<BaseElement> = (0..width).map(|c| trace.get(c, row)).collect();
        let next_row: Vec<BaseElement> = (0..width).map(|c| trace.get(c, row + 1)).collect();
        let frame = EvaluationFrame::from_rows(current_row, next_row);

        let mut result = vec![BaseElement::ZERO; air.context().num_transition_constraints()];
        air.evaluate_transition(&frame, &periodic_values_row, &mut result);
        result
    }

    fn leaf_data_block_count(leaf_len: usize, partition_size: usize) -> usize {
        let hash_perms = |input_len: usize| input_len.div_ceil(RATE_WIDTH).max(1);
        if leaf_len == 0 {
            return 0;
        }
        if partition_size >= leaf_len {
            return hash_perms(leaf_len);
        }

        let mut remaining = leaf_len;
        let mut count = 0usize;
        while remaining > 0 {
            let part_len = remaining.min(partition_size);
            count += hash_perms(part_len);
            remaining -= part_len;
        }
        count
    }

    fn compute_merkle_root_from_path(leaf: HashFelt, position: u64, path: &MerklePath) -> HashFelt {
        let mut current = leaf;
        let mut pos = position;
        for sibling in &path.siblings {
            current = if pos & 1 == 0 {
                merkle_node(current, *sibling)
            } else {
                merkle_node(*sibling, current)
            };
            pos >>= 1;
        }
        current
    }

    fn sample_transaction_witness() -> TransactionWitness {
        let input_note = NoteData {
            value: 5,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [2u8; 32],
            rho: [3u8; 32],
            r: [4u8; 32],
        };
        let output_note = OutputNoteWitness {
            note: NoteData {
                value: 4,
                asset_id: NATIVE_ASSET_ID,
                pk_recipient: [9u8; 32],
                rho: [10u8; 32],
                r: [11u8; 32],
            },
        };

        let merkle_path = MerklePath::default();
        let position = 0u64;
        let merkle_root = felts_to_bytes32(&compute_merkle_root_from_path(
            input_note.commitment(),
            position,
            &merkle_path,
        ));

        TransactionWitness {
            inputs: vec![InputNoteWitness {
                note: input_note,
                position,
                rho_seed: [7u8; 32],
                merkle_path,
                #[cfg(feature = "plonky3")]
                merkle_path_pq: None,
            }],
            outputs: vec![output_note],
            sk_spend: [8u8; 32],
            merkle_root,
            #[cfg(feature = "plonky3")]
            merkle_root_pq: [0u8; 48],
            fee: 1,
            value_balance: 0,
            stablecoin: StablecoinPolicyBinding::default(),
            version: TransactionWitness::default_version_binding(),
        }
    }

    type RpoMerkleTree = MerkleTree<Rpo256>;

    /// A "different AIR with the same proof context" used to catch missing OOD constraint checks.
    ///
    /// This AIR uses the same trace width/length, the same periodic columns, and the same number
    /// of constraints/assertions as `RpoAir`, but its transition constraints implement a different
    /// permutation (no MDS mixing). A proof for this AIR must not be accepted by `StarkVerifierAir`
    /// when interpreted as an `RpoAir` proof.
    struct NoMdsAir {
        context: AirContext<BaseElement>,
        pub_inputs: super::super::rpo_air::RpoPublicInputs,
    }

    impl Air for NoMdsAir {
        type BaseField = BaseElement;
        type PublicInputs = super::super::rpo_air::RpoPublicInputs;

        fn new(
            trace_info: TraceInfo,
            pub_inputs: Self::PublicInputs,
            options: ProofOptions,
        ) -> Self {
            let degrees =
                vec![
                    TransitionConstraintDegree::with_cycles(8, vec![ROWS_PER_PERMUTATION]);
                    INNER_STATE_WIDTH
                ];
            let num_assertions = 2 * INNER_STATE_WIDTH;
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

            let half_round_type = periodic_values[0];
            let ark: [E; INNER_STATE_WIDTH] = core::array::from_fn(|i| periodic_values[1 + i]);

            let one = E::ONE;
            let two = one + one;
            let is_forward = half_round_type * (two - half_round_type);
            let is_inverse = half_round_type * (half_round_type - one);
            let is_padding = (one - half_round_type) * (two - half_round_type);

            for i in 0..INNER_STATE_WIDTH {
                let intermediate = current[i] + ark[i];

                let x2 = intermediate * intermediate;
                let x4 = x2 * x2;
                let x3 = x2 * intermediate;
                let x7 = x3 * x4;
                let forward_constraint = next[i] - x7;

                let y = next[i];
                let y2 = y * y;
                let y4 = y2 * y2;
                let y3 = y2 * y;
                let y7 = y3 * y4;
                let inverse_constraint = y7 - intermediate;

                let padding_constraint = next[i] - current[i];
                result[i] = is_forward * forward_constraint
                    + is_inverse * inverse_constraint
                    + is_padding * padding_constraint;
            }
        }

        fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
            let mut assertions = Vec::new();

            for i in 0..INNER_STATE_WIDTH {
                assertions.push(Assertion::single(i, 0, self.pub_inputs.input_state[i]));
            }

            let last_row = ROWS_PER_PERMUTATION - 1;
            for i in 0..INNER_STATE_WIDTH {
                assertions.push(Assertion::single(
                    i,
                    last_row,
                    self.pub_inputs.output_state[i],
                ));
            }

            assertions
        }

        fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
            // Mirror `RpoAir`'s periodic columns so the proof context stays identical.
            let trace_len = ROWS_PER_PERMUTATION;

            let mut half_round_type = Vec::with_capacity(trace_len);
            for row in 0..trace_len {
                let val = if row >= 14 {
                    0
                } else if row % 2 == 0 {
                    1
                } else {
                    2
                };
                half_round_type.push(BaseElement::new(val));
            }

            let mut ark_columns: [Vec<BaseElement>; INNER_STATE_WIDTH] =
                core::array::from_fn(|_| Vec::with_capacity(trace_len));

            for row in 0..trace_len {
                let constants = if row >= trace_len - 1 {
                    [BaseElement::ZERO; INNER_STATE_WIDTH]
                } else if row % 2 == 0 {
                    let round = row / 2;
                    if round < NUM_ROUNDS {
                        ARK1[round]
                    } else {
                        [BaseElement::ZERO; INNER_STATE_WIDTH]
                    }
                } else {
                    let round = row / 2;
                    if round < NUM_ROUNDS {
                        ARK2[round]
                    } else {
                        [BaseElement::ZERO; INNER_STATE_WIDTH]
                    }
                };

                for (i, &c) in constants.iter().enumerate() {
                    ark_columns[i].push(c);
                }
            }

            let mut result = vec![half_round_type];
            for col in ark_columns {
                result.push(col);
            }
            result
        }
    }

    struct NoMdsProver {
        options: ProofOptions,
        pub_inputs: super::super::rpo_air::RpoPublicInputs,
    }

    impl NoMdsProver {
        fn new(options: ProofOptions, pub_inputs: super::super::rpo_air::RpoPublicInputs) -> Self {
            Self {
                options,
                pub_inputs,
            }
        }

        fn compute_output(
            mut state: [BaseElement; INNER_STATE_WIDTH],
        ) -> [BaseElement; INNER_STATE_WIDTH] {
            for row in 0..(ROWS_PER_PERMUTATION - 1) {
                let constants = if row >= ROWS_PER_PERMUTATION - 1 {
                    [BaseElement::ZERO; INNER_STATE_WIDTH]
                } else if row % 2 == 0 {
                    let round = row / 2;
                    if round < NUM_ROUNDS {
                        ARK1[round]
                    } else {
                        [BaseElement::ZERO; INNER_STATE_WIDTH]
                    }
                } else {
                    let round = row / 2;
                    if round < NUM_ROUNDS {
                        ARK2[round]
                    } else {
                        [BaseElement::ZERO; INNER_STATE_WIDTH]
                    }
                };

                for (value, constant) in state.iter_mut().zip(constants.iter()) {
                    *value += *constant;
                }

                if row >= 14 {
                    continue;
                }
                if row % 2 == 0 {
                    apply_sbox(&mut state);
                } else {
                    apply_inv_sbox(&mut state);
                }
            }
            state
        }

        fn build_trace(&self) -> TraceTable<BaseElement> {
            let mut trace = TraceTable::new(RPO_TRACE_WIDTH, ROWS_PER_PERMUTATION);

            let mut state = self.pub_inputs.input_state;
            for (i, value) in state.iter().copied().enumerate() {
                trace.set(i, 0, value);
            }
            trace.set(INNER_STATE_WIDTH, 0, BaseElement::ZERO);

            for row in 0..(ROWS_PER_PERMUTATION - 1) {
                let constants = if row >= ROWS_PER_PERMUTATION - 1 {
                    [BaseElement::ZERO; INNER_STATE_WIDTH]
                } else if row % 2 == 0 {
                    let round = row / 2;
                    if round < NUM_ROUNDS {
                        ARK1[round]
                    } else {
                        [BaseElement::ZERO; INNER_STATE_WIDTH]
                    }
                } else {
                    let round = row / 2;
                    if round < NUM_ROUNDS {
                        ARK2[round]
                    } else {
                        [BaseElement::ZERO; INNER_STATE_WIDTH]
                    }
                };

                for (value, constant) in state.iter_mut().zip(constants.iter()) {
                    *value += *constant;
                }

                if row < 14 {
                    if row % 2 == 0 {
                        apply_sbox(&mut state);
                    } else {
                        apply_inv_sbox(&mut state);
                    }
                }

                let next_row = row + 1;
                for (i, value) in state.iter().copied().enumerate() {
                    trace.set(i, next_row, value);
                }
                trace.set(
                    INNER_STATE_WIDTH,
                    next_row,
                    BaseElement::new(next_row as u64),
                );
            }

            trace
        }
    }

    impl Prover for NoMdsProver {
        type BaseField = BaseElement;
        type Air = NoMdsAir;
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

        fn get_pub_inputs(&self, _trace: &Self::Trace) -> super::super::rpo_air::RpoPublicInputs {
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

    #[test]
    fn test_ood_consistency_check_rejects_wrong_inner_air() {
        let inner_options = test_options(1);
        let outer_options = test_options(1);

        // Compute a "different" output state under NoMdsAir so the proof is valid for NoMdsAir.
        let input_state = core::array::from_fn(|i| BaseElement::new((i as u64) + 1));
        let output_state = NoMdsProver::compute_output(input_state);

        let real_output = RpoStarkProver::new(inner_options.clone()).compute_output(input_state);
        assert_ne!(
            output_state, real_output,
            "no-mds output unexpectedly matched real RPO output"
        );

        let inner_pub_inputs =
            super::super::rpo_air::RpoPublicInputs::new(input_state, output_state);

        let no_mds_prover = NoMdsProver::new(inner_options.clone(), inner_pub_inputs.clone());
        let inner_trace = no_mds_prover.build_trace();
        let inner_proof = no_mds_prover
            .prove(inner_trace)
            .expect("NoMds proof should build");

        let acceptable = AcceptableOptions::OptionSet(vec![inner_options.clone()]);

        // Sanity: proof verifies for NoMdsAir.
        assert!(verify::<NoMdsAir, Rpo256, RpoRandomCoin, RpoMerkleTree>(
            inner_proof.clone(),
            inner_pub_inputs.clone(),
            &acceptable,
        )
        .is_ok());

        // Sanity: same proof must fail for RpoAir.
        assert!(verify::<RpoAir, Rpo256, RpoRandomCoin, RpoMerkleTree>(
            inner_proof.clone(),
            inner_pub_inputs.clone(),
            &acceptable,
        )
        .is_err());

        // Build a recursive verifier trace as-if the inner proof were an RpoAir proof.
        let inner_data =
            InnerProofData::from_proof::<RpoAir>(&inner_proof.to_bytes(), inner_pub_inputs)
                .expect("proof should parse under RpoAir structure");
        let pub_inputs = inner_data.to_stark_verifier_inputs();
        let prover = StarkVerifierProver::new(outer_options.clone(), pub_inputs.clone());
        let trace = prover.build_trace_from_inner(&inner_data);

        let air = StarkVerifierAir::new(trace.info().clone(), pub_inputs.clone(), outer_options);
        let periodic = air.get_periodic_column_values();

        // The OOD consistency constraint should be violated on any row (it only depends on constant columns).
        let result = eval_transition_row(&air, &trace, &periodic, 0);
        assert!(
            result.iter().any(|v| *v != BaseElement::ZERO),
            "expected verifier constraints to detect an inner proof for the wrong AIR"
        );
    }

    #[test]
    fn test_trace_from_inner_merkle_roundtrip() {
        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();

        // Generate a small inner RPO proof and extract recursion data.
        let inner_prover = RpoStarkProver::fast();
        let input_state = [BaseElement::new(9); INNER_STATE_WIDTH];
        let (inner_proof, inner_pub_inputs) = inner_prover
            .prove_rpo_permutation(input_state)
            .expect("inner proof generation should succeed");

        let inner_data =
            InnerProofData::from_proof::<RpoAir>(&inner_proof.to_bytes(), inner_pub_inputs)
                .unwrap();
        let pub_inputs = inner_data.to_stark_verifier_inputs();

        // Context prefix must match the inner proof context exactly; otherwise transcript
        // reconstruction (e.g., z) will drift.
        let expected_context = inner_proof.context.to_elements();
        let actual_context = build_context_prefix(&pub_inputs);
        assert_eq!(actual_context, expected_context, "context prefix mismatch");

        let lde_domain_size = pub_inputs.trace_length * pub_inputs.blowup_factor;
        let depth_trace = lde_domain_size.trailing_zeros() as usize;
        assert!(inner_data
            .trace_auth_paths
            .iter()
            .all(|p| p.len() == depth_trace));
        assert!(inner_data
            .constraint_auth_paths
            .iter()
            .all(|p| p.len() == depth_trace));
        for (layer_idx, layer) in inner_data.fri_layers.iter().enumerate() {
            let expected_depth = depth_trace.saturating_sub(layer_idx + 1);
            assert!(layer.auth_paths.iter().all(|p| p.len() == expected_depth));
        }

        let prover = StarkVerifierProver::new(options.clone(), pub_inputs.clone());
        let trace = prover.build_trace_from_inner(&inner_data);

        // Sanity-check Merkle root locations in the constructed trace.
        let input_len = pub_inputs.inner_public_inputs.len();
        let num_pi_blocks = input_len.div_ceil(8).max(1);
        let seed_prefix = build_context_prefix(&pub_inputs);
        let seed_len = seed_prefix.len() + input_len;
        let num_seed_blocks = seed_len.div_ceil(8).max(1);
        let num_coeff_perms = 36usize.div_ceil(8);
        let num_ood_perms = (2 * (RPO_TRACE_WIDTH + 8)).div_ceil(RATE_WIDTH);
        let num_deep_coeffs = RPO_TRACE_WIDTH + 8;
        let num_deep_perms = num_deep_coeffs.div_ceil(8);
        let num_fri_layers = pub_inputs.fri_commitments.len().saturating_sub(1);
        let num_pow_nonce_perms = (!pub_inputs.fri_commitments.is_empty()) as usize;
        let num_pos_perms = (pub_inputs.num_draws + 1).div_ceil(8);
        let transcript_perms = num_pi_blocks
            + num_seed_blocks
            + num_coeff_perms
            + num_ood_perms
            + num_deep_perms
            + num_fri_layers
            + num_pow_nonce_perms
            + num_pos_perms
            + 2;
        let pre_merkle_perms = transcript_perms + pub_inputs.num_draws;
        let trace_leaf_perms = leaf_perm_count(RPO_TRACE_WIDTH, pub_inputs.trace_partition_size);
        let constraint_leaf_perms = leaf_perm_count(8, pub_inputs.constraint_partition_size);
        let trace_leaf_chains = leaf_chain_count(RPO_TRACE_WIDTH, pub_inputs.trace_partition_size);
        let constraint_leaf_chains = leaf_chain_count(8, pub_inputs.constraint_partition_size);
        let depth_trace =
            (pub_inputs.trace_length * pub_inputs.blowup_factor).trailing_zeros() as usize;

        let mut perm_idx = pre_merkle_perms;
        for q in 0..pub_inputs.num_queries {
            perm_idx += trace_leaf_chains + trace_leaf_perms;
            if depth_trace > 0 {
                let trace_root_perm = perm_idx + depth_trace - 1;
                let row = trace_root_perm * ROWS_PER_PERMUTATION + (ROWS_PER_PERMUTATION - 1);
                let digest: [BaseElement; 4] = core::array::from_fn(|i| trace.get(4 + i, row));
                assert_eq!(
                    digest, pub_inputs.trace_commitment,
                    "trace root mismatch q={q}"
                );
            }
            perm_idx += depth_trace;

            perm_idx += constraint_leaf_chains + constraint_leaf_perms;
            if depth_trace > 0 {
                let constraint_root_perm = perm_idx + depth_trace - 1;
                let row = constraint_root_perm * ROWS_PER_PERMUTATION + (ROWS_PER_PERMUTATION - 1);
                let digest: [BaseElement; 4] = core::array::from_fn(|i| trace.get(4 + i, row));
                assert_eq!(
                    digest, pub_inputs.constraint_commitment,
                    "constraint root mismatch q={q}"
                );
            }
            perm_idx += depth_trace;

            for layer_idx in 0..num_fri_layers {
                perm_idx += 1; // FRI leaf perm
                let layer_depth = depth_trace.saturating_sub(layer_idx + 1);
                if layer_depth > 0 {
                    let root_perm = perm_idx + layer_depth - 1;
                    let row = root_perm * ROWS_PER_PERMUTATION + (ROWS_PER_PERMUTATION - 1);
                    let digest: [BaseElement; 4] = core::array::from_fn(|i| trace.get(4 + i, row));
                    assert_eq!(
                        digest, pub_inputs.fri_commitments[layer_idx],
                        "fri root mismatch q={q} layer={layer_idx}"
                    );
                }
                perm_idx += layer_depth;
            }
        }

        // Ensure the AIR's periodic FRI root mask for layer 1 only fires on rows
        // where the trace digest equals the expected commitment.
        if num_fri_layers > 1 {
            let air =
                StarkVerifierAir::new(trace.info().clone(), pub_inputs.clone(), options.clone());
            let periodic = air.get_periodic_column_values();
            let fri_root_mask_start =
                1 + STATE_WIDTH + 1 + DIGEST_WIDTH + DIGEST_WIDTH + 7 + RATE_WIDTH + 5;
            let fri_root_mask_1 = &periodic[fri_root_mask_start + 1];
            for (row, &mask) in fri_root_mask_1.iter().enumerate() {
                if mask != BaseElement::ONE {
                    continue;
                }
                let digest: [BaseElement; 4] = core::array::from_fn(|i| trace.get(4 + i, row));
                assert_eq!(
                    digest, pub_inputs.fri_commitments[1],
                    "fri root mask(1) mismatch at row={row}",
                );
            }
        }

        assert_eq!(
            trace.get(COL_OOD_DIGEST_START, 0),
            trace.get(COL_OOD_DIGEST_START, 1),
            "OOD digest column is not constant at the start of the trace"
        );
        let mut z_boundary_row = None;
        for row in 0..trace.length() {
            if trace.get(COL_Z_MASK, row) == BaseElement::ONE
                && row % ROWS_PER_PERMUTATION == ROWS_PER_PERMUTATION - 1
            {
                z_boundary_row = Some(row);
                break;
            }
        }
        let z_boundary_row = z_boundary_row.expect("expected to find z boundary row");
        for i in 0..STATE_WIDTH {
            assert_eq!(
                trace.get(COL_SAVED_COIN_START + i, z_boundary_row),
                trace.get(i, z_boundary_row),
                "saved coin mismatch at z boundary row={z_boundary_row} col={i}",
            );
        }

        let proof = prover.prove(trace).unwrap();

        let acceptable = AcceptableOptions::OptionSet(vec![options.clone()]);
        let result = verify::<StarkVerifierAir, Blake3, DefaultRandomCoin<Blake3>, Blake3MerkleTree>(
            proof.clone(),
            pub_inputs.clone(),
            &acceptable,
        );
        assert!(result.is_ok());

        // Tamper with trace commitment; should invalidate transcript reseed binding.
        let mut tampered_inputs = pub_inputs;
        tampered_inputs.trace_commitment[0] += BaseElement::ONE;
        let bad = verify::<StarkVerifierAir, Blake3, DefaultRandomCoin<Blake3>, Blake3MerkleTree>(
            proof,
            tampered_inputs,
            &acceptable,
        );
        assert!(bad.is_err());
    }

    #[test]
    fn test_coeff_tape_matches_coeff_witness() {
        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();

        let inner_prover = RpoStarkProver::fast();
        let input_state = [BaseElement::new(7); INNER_STATE_WIDTH];
        let (inner_proof, inner_pub_inputs) = inner_prover
            .prove_rpo_permutation(input_state)
            .expect("inner proof generation should succeed");

        let inner_data =
            InnerProofData::from_proof::<RpoAir>(&inner_proof.to_bytes(), inner_pub_inputs)
                .unwrap();
        let pub_inputs = inner_data.to_stark_verifier_inputs();

        let prover = StarkVerifierProver::new(options, pub_inputs);
        let trace = prover.build_trace_from_inner(&inner_data);

        let mut expected_index = 0u64;
        let total_perms = trace.length() / ROWS_PER_PERMUTATION;
        for perm_idx in 0..total_perms {
            let boundary_row = (perm_idx + 1) * ROWS_PER_PERMUTATION - 1;
            let coeff_mask = trace.get(COL_COEFF_MASK, boundary_row);
            if coeff_mask == BaseElement::ONE {
                assert_eq!(
                    trace.get(COL_TAPE_MASK, boundary_row),
                    BaseElement::ONE,
                    "tape mask missing on coeff draw perm {perm_idx}"
                );
                assert_eq!(
                    trace.get(COL_TAPE_KIND, boundary_row),
                    BaseElement::new(super::TAPE_KIND_COEFF),
                    "unexpected tape kind on coeff draw perm {perm_idx}"
                );
                assert_eq!(
                    trace.get(COL_TAPE_INDEX, boundary_row),
                    BaseElement::new(expected_index),
                    "unexpected tape index on coeff draw perm {perm_idx}"
                );
                for i in 0..TAPE_WIDTH {
                    let tape_val = trace.get(COL_TAPE_VALUES_START + i, boundary_row);
                    let coeff_val = trace.get(COL_COEFF_START + i, boundary_row);
                    assert_eq!(
                        tape_val, coeff_val,
                        "tape value mismatch at coeff perm {perm_idx} idx {i}"
                    );
                }
                expected_index += 1;
            }
        }

        assert!(
            expected_index > 0,
            "expected at least one coeff draw perm with tape"
        );
    }

    #[test]
    fn test_merkle_sibling_tamper_fails() {
        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();

        let inner_prover = RpoStarkProver::fast();
        let input_state = [BaseElement::new(11); INNER_STATE_WIDTH];
        let (inner_proof, inner_pub_inputs) = inner_prover
            .prove_rpo_permutation(input_state)
            .expect("inner proof generation should succeed");

        let mut inner_data =
            InnerProofData::from_proof::<RpoAir>(&inner_proof.to_bytes(), inner_pub_inputs)
                .unwrap();

        // Tamper with the first trace sibling.
        if let Some(path) = inner_data.trace_auth_paths.get_mut(0) {
            if let Some(sib) = path.get_mut(0) {
                sib[0] += BaseElement::ONE;
            }
        }

        let pub_inputs = inner_data.to_stark_verifier_inputs();
        let prover = StarkVerifierProver::new(options.clone(), pub_inputs.clone());
        let trace = prover.build_trace_from_inner(&inner_data);

        let prove_result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prover.prove(trace)));
        assert!(prove_result.is_err());
    }

    #[test]
    fn test_merkle_leaf_to_merge_path_bit_tamper_fails() {
        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();

        let inner_prover = RpoStarkProver::fast();
        let input_state = [BaseElement::new(13); INNER_STATE_WIDTH];
        let (inner_proof, inner_pub_inputs) = inner_prover
            .prove_rpo_permutation(input_state)
            .expect("inner proof generation should succeed");

        let inner_data =
            InnerProofData::from_proof::<RpoAir>(&inner_proof.to_bytes(), inner_pub_inputs)
                .unwrap();
        let pub_inputs = inner_data.to_stark_verifier_inputs();
        let prover = StarkVerifierProver::new(options.clone(), pub_inputs.clone());
        let mut trace = prover.build_trace_from_inner(&inner_data);

        // Compute the last trace-leaf hash permutation for q=0 and flip its path bit.
        let input_len = pub_inputs.inner_public_inputs.len();
        let num_pi_blocks = input_len.div_ceil(RATE_WIDTH).max(1);
        let seed_prefix = build_context_prefix(&pub_inputs);
        let seed_len = seed_prefix.len() + input_len;
        let num_seed_blocks = seed_len.div_ceil(RATE_WIDTH).max(1);
        let num_coeff_perms = 36usize.div_ceil(RATE_WIDTH);
        let num_ood_perms = (2 * (RPO_TRACE_WIDTH + 8)).div_ceil(RATE_WIDTH);
        let num_deep_coeffs = RPO_TRACE_WIDTH + 8;
        let num_deep_perms = num_deep_coeffs.div_ceil(RATE_WIDTH);
        let num_fri_layers = pub_inputs.fri_commitments.len().saturating_sub(1);
        let num_pow_nonce_perms = (!pub_inputs.fri_commitments.is_empty()) as usize;
        let num_pos_perms = if pub_inputs.num_draws == 0 {
            0
        } else {
            (pub_inputs.num_draws + 1).div_ceil(RATE_WIDTH)
        };
        let transcript_perms = num_pi_blocks
            + num_seed_blocks
            + num_coeff_perms
            + num_ood_perms
            + num_deep_perms
            + num_fri_layers
            + num_pow_nonce_perms
            + num_pos_perms
            + 2;
        let pre_merkle_perms = transcript_perms + pub_inputs.num_draws;
        let trace_leaf_perms = leaf_perm_count(RPO_TRACE_WIDTH, pub_inputs.trace_partition_size);
        let trace_leaf_chains = leaf_chain_count(RPO_TRACE_WIDTH, pub_inputs.trace_partition_size);

        let last_trace_leaf_perm = pre_merkle_perms + trace_leaf_chains + trace_leaf_perms - 1;
        let boundary_row = last_trace_leaf_perm * ROWS_PER_PERMUTATION + (ROWS_PER_PERMUTATION - 1);
        let bit = trace.get(COL_MERKLE_PATH_BIT, boundary_row);
        trace.set(COL_MERKLE_PATH_BIT, boundary_row, BaseElement::ONE - bit);

        let prove_result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prover.prove(trace)));
        assert!(prove_result.is_err());
    }

    #[test]
    fn test_merkle_index_shift_tamper_fails() {
        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();

        let inner_prover = RpoStarkProver::fast();
        let input_state = [BaseElement::new(17); INNER_STATE_WIDTH];
        let (inner_proof, inner_pub_inputs) = inner_prover
            .prove_rpo_permutation(input_state)
            .expect("inner proof generation should succeed");

        let inner_data =
            InnerProofData::from_proof::<RpoAir>(&inner_proof.to_bytes(), inner_pub_inputs)
                .unwrap();
        let pub_inputs = inner_data.to_stark_verifier_inputs();
        let prover = StarkVerifierProver::new(options.clone(), pub_inputs.clone());
        let mut trace = prover.build_trace_from_inner(&inner_data);

        // Compute the first trace-merge permutation for q=0 and tamper with its index witness.
        let input_len = pub_inputs.inner_public_inputs.len();
        let num_pi_blocks = input_len.div_ceil(RATE_WIDTH).max(1);
        let seed_prefix = build_context_prefix(&pub_inputs);
        let seed_len = seed_prefix.len() + input_len;
        let num_seed_blocks = seed_len.div_ceil(RATE_WIDTH).max(1);
        let num_coeff_perms = 36usize.div_ceil(RATE_WIDTH);
        let num_ood_perms = (2 * (RPO_TRACE_WIDTH + 8)).div_ceil(RATE_WIDTH);
        let num_deep_coeffs = RPO_TRACE_WIDTH + 8;
        let num_deep_perms = num_deep_coeffs.div_ceil(RATE_WIDTH);
        let num_fri_layers = pub_inputs.fri_commitments.len().saturating_sub(1);
        let num_pow_nonce_perms = (!pub_inputs.fri_commitments.is_empty()) as usize;
        let num_pos_perms = if pub_inputs.num_draws == 0 {
            0
        } else {
            (pub_inputs.num_draws + 1).div_ceil(RATE_WIDTH)
        };
        let transcript_perms = num_pi_blocks
            + num_seed_blocks
            + num_coeff_perms
            + num_ood_perms
            + num_deep_perms
            + num_fri_layers
            + num_pow_nonce_perms
            + num_pos_perms
            + 2;
        let pre_merkle_perms = transcript_perms + pub_inputs.num_draws;
        let trace_leaf_perms = leaf_perm_count(RPO_TRACE_WIDTH, pub_inputs.trace_partition_size);
        let trace_leaf_chains = leaf_chain_count(RPO_TRACE_WIDTH, pub_inputs.trace_partition_size);

        let first_trace_merge_perm = pre_merkle_perms + trace_leaf_chains + trace_leaf_perms;
        let row0 = first_trace_merge_perm * ROWS_PER_PERMUTATION;
        let idx = trace.get(COL_MERKLE_INDEX, row0);
        trace.set(COL_MERKLE_INDEX, row0, idx + BaseElement::ONE);

        let prove_result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prover.prove(trace)));
        assert!(prove_result.is_err());
    }

    #[test]
    fn test_query_position_draw_value_tamper_detected() {
        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();

        let inner_prover = RpoStarkProver::fast();
        let input_state = [BaseElement::new(23); INNER_STATE_WIDTH];
        let (inner_proof, inner_pub_inputs) = inner_prover
            .prove_rpo_permutation(input_state)
            .expect("inner proof generation should succeed");

        let inner_data =
            InnerProofData::from_proof::<RpoAir>(&inner_proof.to_bytes(), inner_pub_inputs)
                .unwrap();
        let pub_inputs = inner_data.to_stark_verifier_inputs();

        let prover = StarkVerifierProver::new(options.clone(), pub_inputs.clone());
        let mut trace = prover.build_trace_from_inner(&inner_data);

        let air = StarkVerifierAir::new(trace.info().clone(), pub_inputs, options);
        let periodic = air.get_periodic_column_values();

        // Find the first decomp-boundary row and ensure constraints are satisfied before tamper.
        let boundary_row = (0..trace.length().saturating_sub(1))
            .find(|&row| {
                trace.get(COL_POS_DECOMP_MASK, row) == BaseElement::ONE
                    && row % ROWS_PER_PERMUTATION == ROWS_PER_PERMUTATION - 1
            })
            .expect("expected to find a query decomp boundary row");

        let ok = eval_transition_row(&air, &trace, &periodic, boundary_row);
        assert!(
            ok.iter().all(|v| *v == BaseElement::ZERO),
            "expected query-position constraints to be satisfied before tamper"
        );

        // Tamper with the draw value witness; the new binding constraint should catch it.
        let cur = trace.get(COL_POS_SORTED_VALUE, boundary_row);
        trace.set(COL_POS_SORTED_VALUE, boundary_row, cur + BaseElement::ONE);
        let bad = eval_transition_row(&air, &trace, &periodic, boundary_row);
        assert!(
            bad.iter().any(|v| *v != BaseElement::ZERO),
            "expected query-position draw binding to detect tampering"
        );
    }

    #[test]
    fn test_duplicate_query_draws_roundtrip_trace_constraints_hold() {
        let inner_options = test_options(32);
        let outer_options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();

        // Search deterministically for an inner proof whose draw_integers output contains
        // duplicates. This is probabilistic per seed, but the search space is large enough to be
        // effectively deterministic in practice.
        let mut found: Option<InnerProofData> = None;
        for seed in 1u64..=256 {
            let inner_prover = RpoStarkProver::new(inner_options.clone());
            let input_state = [BaseElement::new(seed); INNER_STATE_WIDTH];
            let (inner_proof, inner_pub_inputs) = inner_prover
                .prove_rpo_permutation(input_state)
                .expect("inner proof generation should succeed");

            let data =
                InnerProofData::from_proof::<RpoAir>(&inner_proof.to_bytes(), inner_pub_inputs)
                    .unwrap();
            if data.unique_query_positions.len() < data.query_positions.len() {
                found = Some(data);
                break;
            }
        }
        let inner_data = found.expect("expected to find a proof with duplicate query draws");

        let pub_inputs = inner_data.to_stark_verifier_inputs();
        let prover = StarkVerifierProver::new(outer_options.clone(), pub_inputs.clone());
        let trace = prover.build_trace_from_inner(&inner_data);
        assert_eq!(
            trace.get(COL_POS_PERM_ACC, trace.length() - 1),
            BaseElement::ONE,
            "expected binding accumulator to end at 1"
        );

        // Find two decomp-boundary rows with identical draw values, and ensure transition
        // constraints hold at both boundaries.
        use std::collections::HashMap;
        let air = StarkVerifierAir::new(trace.info().clone(), pub_inputs.clone(), outer_options);
        let periodic = air.get_periodic_column_values();

        let mut first_by_draw: HashMap<u64, usize> = HashMap::new();
        let mut dup_rows: Option<(usize, usize)> = None;
        for row in 0..trace.length().saturating_sub(1) {
            if trace.get(COL_POS_DECOMP_MASK, row) != BaseElement::ONE {
                continue;
            }
            if row % ROWS_PER_PERMUTATION != ROWS_PER_PERMUTATION - 1 {
                continue;
            }
            let draw = trace.get(COL_POS_SORTED_VALUE, row).as_int();
            if let Some(prev) = first_by_draw.insert(draw, row) {
                dup_rows = Some((prev, row));
                break;
            }
        }

        let (row_a, row_b) = dup_rows.expect("expected to locate duplicate draw boundary rows");
        for row in [row_a, row_b] {
            let evals = eval_transition_row(&air, &trace, &periodic, row);
            assert!(
                evals.iter().all(|v| *v == BaseElement::ZERO),
                "expected constraints to hold at duplicate draw boundary row {row}"
            );
        }
    }

    #[test]
    fn test_fri_folding_constraint_detects_tamper() {
        let inner_options = test_options(1);
        let outer_options = test_options(1);

        let inner_prover = RpoStarkProver::new(inner_options);
        let input_state = [BaseElement::new(19); INNER_STATE_WIDTH];
        let (inner_proof, inner_pub_inputs) = inner_prover
            .prove_rpo_permutation(input_state)
            .expect("inner proof generation should succeed");

        let inner_data =
            InnerProofData::from_proof::<RpoAir>(&inner_proof.to_bytes(), inner_pub_inputs)
                .unwrap();
        let pub_inputs = inner_data.to_stark_verifier_inputs();

        let prover = StarkVerifierProver::new(outer_options.clone(), pub_inputs.clone());
        let mut trace = prover.build_trace_from_inner(&inner_data);

        let num_fri_layers = pub_inputs.fri_commitments.len().saturating_sub(1);
        let air = StarkVerifierAir::new(trace.info().clone(), pub_inputs.clone(), outer_options);
        let periodic = air.get_periodic_column_values();
        assert!(num_fri_layers > 0, "expected at least one FRI layer");

        // Locate the first FRI leaf row for layer 0.
        let extension_degree = match pub_inputs.field_extension {
            FieldExtension::None => 1,
            FieldExtension::Quadratic => 2,
            FieldExtension::Cubic => 3,
        };
        let trace_leaf_len = pub_inputs.trace_width * extension_degree;
        let constraint_leaf_len = pub_inputs.constraint_frame_width * extension_degree;
        let constraint_partition_size_base =
            pub_inputs.constraint_partition_size * extension_degree;
        let trace_data_blocks =
            leaf_data_block_count(trace_leaf_len, pub_inputs.trace_partition_size);
        let constraint_data_blocks =
            leaf_data_block_count(constraint_leaf_len, constraint_partition_size_base);
        let appended_len = trace_data_blocks + constraint_data_blocks + 4 + 2 * num_fri_layers;
        let appended_start = periodic.len() - appended_len;
        let fri_leaf_row_mask_0_idx =
            appended_start + 2 + trace_data_blocks + constraint_data_blocks + num_fri_layers;
        let fri_leaf_row_mask_0 = &periodic[fri_leaf_row_mask_0_idx];
        let row = fri_leaf_row_mask_0
            .iter()
            .position(|v| *v == BaseElement::ONE)
            .expect("expected at least one FRI leaf row");
        assert!(
            row + 1 < trace.length(),
            "FRI leaf row must have a next row"
        );

        // Sanity: original trace satisfies constraints at this row.
        let result_ok = eval_transition_row(&air, &trace, &periodic, row);
        assert!(
            result_ok.iter().all(|v| *v == BaseElement::ZERO),
            "expected constraints to be satisfied at row {row}"
        );

        // Tamper with eval_next; this should violate the folding check at `row`.
        let eval_next = trace.get(COL_FRI_EVAL, row + 1);
        trace.set(COL_FRI_EVAL, row + 1, eval_next + BaseElement::ONE);
        let result_bad = eval_transition_row(&air, &trace, &periodic, row);
        assert!(
            result_bad.iter().any(|v| *v != BaseElement::ZERO),
            "expected folding constraints to detect tampering at row {row}"
        );
    }

    #[test]
    fn test_fri_remainder_evaluation_detects_tamper() {
        let inner_options = test_options(1);
        let outer_options = test_options(1);

        let inner_prover = RpoStarkProver::new(inner_options);
        let input_state = [BaseElement::new(23); INNER_STATE_WIDTH];
        let (inner_proof, inner_pub_inputs) = inner_prover
            .prove_rpo_permutation(input_state)
            .expect("inner proof generation should succeed");

        let inner_data =
            InnerProofData::from_proof::<RpoAir>(&inner_proof.to_bytes(), inner_pub_inputs)
                .unwrap();
        let pub_inputs = inner_data.to_stark_verifier_inputs();

        let prover = StarkVerifierProver::new(outer_options.clone(), pub_inputs.clone());
        let mut trace = prover.build_trace_from_inner(&inner_data);

        let num_fri_layers = pub_inputs.fri_commitments.len().saturating_sub(1);
        let air = StarkVerifierAir::new(trace.info().clone(), pub_inputs.clone(), outer_options);
        let periodic = air.get_periodic_column_values();
        assert!(num_fri_layers > 0, "expected at least one FRI layer");

        // Compute the periodic column index for the last FRI root mask (see StarkVerifierAir layout).
        let fri_root_mask_start =
            1 + STATE_WIDTH + 1 + DIGEST_WIDTH + DIGEST_WIDTH + 7 + RATE_WIDTH + 5;
        let last_root_mask = &periodic[fri_root_mask_start + (num_fri_layers - 1)];

        // Locate a row where the remainder check is gated on (last FRI root boundary).
        let remainder_row = last_root_mask
            .iter()
            .position(|v| *v == BaseElement::ONE)
            .expect("expected a remainder check row");

        // Find the last FRI leaf row (layer = num_fri_layers - 1) and shift eval after the leaf
        // permutation ends. This avoids triggering eval-freeze constraints, but should break the
        // remainder evaluation check at `remainder_row`.
        let extension_degree = match pub_inputs.field_extension {
            FieldExtension::None => 1,
            FieldExtension::Quadratic => 2,
            FieldExtension::Cubic => 3,
        };
        let trace_leaf_len = pub_inputs.trace_width * extension_degree;
        let constraint_leaf_len = pub_inputs.constraint_frame_width * extension_degree;
        let constraint_partition_size_base =
            pub_inputs.constraint_partition_size * extension_degree;
        let trace_data_blocks =
            leaf_data_block_count(trace_leaf_len, pub_inputs.trace_partition_size);
        let constraint_data_blocks =
            leaf_data_block_count(constraint_leaf_len, constraint_partition_size_base);
        let appended_len = trace_data_blocks + constraint_data_blocks + 4 + 2 * num_fri_layers;
        let appended_start = periodic.len() - appended_len;
        let fri_leaf_row_mask_last_idx = appended_start
            + 2
            + trace_data_blocks
            + constraint_data_blocks
            + num_fri_layers
            + (num_fri_layers - 1);
        let fri_leaf_row_mask_last = &periodic[fri_leaf_row_mask_last_idx];
        let leaf_row0 = fri_leaf_row_mask_last
            .iter()
            .position(|v| *v == BaseElement::ONE)
            .expect("expected a final-layer FRI leaf row");
        let shift_start = leaf_row0 + ROWS_PER_PERMUTATION;
        assert!(
            shift_start < trace.length(),
            "shift must start inside trace"
        );
        assert!(
            remainder_row >= shift_start,
            "expected remainder row to occur after final FRI leaf permutation"
        );

        // Sanity: original trace satisfies constraints at the remainder row.
        let ok = eval_transition_row(&air, &trace, &periodic, remainder_row);
        assert!(
            ok.iter().all(|v| *v == BaseElement::ZERO),
            "expected constraints to be satisfied at remainder row {remainder_row}"
        );

        // Apply a constant delta to `eval` after `shift_start`.
        for row in shift_start..trace.length() {
            let v = trace.get(COL_FRI_EVAL, row);
            trace.set(COL_FRI_EVAL, row, v + BaseElement::ONE);
        }

        let bad = eval_transition_row(&air, &trace, &periodic, remainder_row);
        assert!(
            bad.iter().any(|v| *v != BaseElement::ZERO),
            "expected remainder evaluation check to detect tampering at row {remainder_row}"
        );
    }

    #[test]
    #[ignore = "heavy: transaction inner proof recursion"]
    fn test_transaction_inner_proof_recursion() {
        let inner_options = ProofOptions::new(
            8,
            8,
            0,
            FieldExtension::None,
            2,
            7,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let outer_options = test_options(1);

        let witness = sample_transaction_witness();
        let tx_prover = TransactionProverStarkRpo::new(inner_options);
        let tx_trace = tx_prover.build_trace(&witness).expect("tx trace");
        let tx_pub_inputs = tx_prover.get_pub_inputs(&tx_trace);
        let tx_proof = tx_prover.prove(tx_trace).expect("tx proof");

        let inner_data =
            InnerProofData::from_proof::<TransactionAirStark>(&tx_proof.to_bytes(), tx_pub_inputs)
                .expect("inner proof parsing");
        let verifier_inputs = inner_data.to_stark_verifier_inputs();

        let prover = StarkVerifierProver::new(outer_options.clone(), verifier_inputs.clone());
        let trace = prover.build_trace_from_inner(&inner_data);

        let air = StarkVerifierAir::new(
            trace.info().clone(),
            verifier_inputs.clone(),
            outer_options.clone(),
        );

        for assertion in air.get_assertions() {
            let row = assertion.first_step();
            let col = assertion.column();
            let expected = assertion.values()[0];
            let observed = trace.get(col, row);
            if observed != expected {
                let perm_idx = row / ROWS_PER_PERMUTATION;
                let row_in_perm = row % ROWS_PER_PERMUTATION;
                let mask_snapshot = [
                    ("carry", trace.get(COL_CARRY_MASK, row)),
                    ("full_carry", trace.get(COL_FULL_CARRY_MASK, row)),
                    ("reseed", trace.get(COL_RESEED_MASK, row)),
                    ("coin_init", trace.get(COL_COIN_INIT_MASK, row)),
                    ("coeff", trace.get(COL_COEFF_MASK, row)),
                    ("z", trace.get(COL_Z_MASK, row)),
                    ("deep", trace.get(COL_DEEP_MASK, row)),
                    ("fri", trace.get(COL_FRI_MASK, row)),
                    ("pos", trace.get(COL_POS_MASK, row)),
                    ("pos_decomp", trace.get(COL_POS_DECOMP_MASK, row)),
                    ("coin_save", trace.get(COL_COIN_SAVE_MASK, row)),
                    ("coin_restore", trace.get(COL_COIN_RESTORE_MASK, row)),
                    ("tape", trace.get(COL_TAPE_MASK, row)),
                ];
                panic!(
                    "assertion failed at row {row} (perm={perm_idx}, offset={row_in_perm}) col {col}: expected {expected}, got {observed}, masks={mask_snapshot:?}"
                );
            }
        }

        let proof = prover.prove(trace).expect("outer proof");

        let acceptable = AcceptableOptions::OptionSet(vec![outer_options]);
        let result = verify::<StarkVerifierAir, Blake3, DefaultRandomCoin<Blake3>, Blake3MerkleTree>(
            proof,
            verifier_inputs,
            &acceptable,
        );
        assert!(
            result.is_ok(),
            "transaction recursion proof failed: {result:?}"
        );
    }
}
