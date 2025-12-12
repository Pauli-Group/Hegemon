//! Minimal prover for `StarkVerifierAir`.
//!
//! For now this prover only builds a trace which hashes the inner public inputs
//! using the RPO sponge and exposes the resulting digest for checking in-circuit.

use winter_air::ProofOptions;
use winter_crypto::{hashers::Blake3_256, MerkleTree};
use winter_math::FieldElement;
use winterfell::{
    crypto::DefaultRandomCoin,
    math::fields::f64::BaseElement,
    matrix::ColMatrix,
    AuxRandElements, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions, Prover, StarkDomain,
    TracePolyTable, TraceTable, CompositionPoly, CompositionPolyTrace, Proof, AcceptableOptions,
};

use super::rpo_air::{
    STATE_WIDTH, ROWS_PER_PERMUTATION, NUM_ROUNDS, MDS, ARK1, ARK2,
    TRACE_WIDTH as RPO_TRACE_WIDTH,
};
use super::merkle_air::DIGEST_WIDTH;
use super::rpo_proof::{rpo_hash_elements, rpo_merge};
use super::stark_verifier_air::{
    build_context_prefix, compute_expected_z, StarkVerifierAir, StarkVerifierPublicInputs,
    VERIFIER_TRACE_WIDTH,
    RATE_WIDTH,
    COL_CARRY_MASK, COL_FULL_CARRY_MASK, COL_RESEED_MASK, COL_COIN_INIT_MASK,
    COL_RESEED_WORD_START, COL_COEFF_MASK, COL_Z_MASK, COL_COEFF_START, COL_Z_VALUE,
    COL_DEEP_MASK, COL_DEEP_START, COL_FRI_MASK, COL_FRI_ALPHA_VALUE,
    COL_POS_MASK, COL_POS_START, COL_MERKLE_PATH_BIT,
    COL_POS_DECOMP_MASK, COL_POS_RAW, COL_POS_BIT0, COL_POS_BIT1, COL_POS_BIT2, COL_POS_BIT3,
    COL_POS_ACC, COL_POS_LO_ACC, COL_POS_MASKED_ACC, COL_POS_HI_AND, COL_POS_SORTED_VALUE,
    COL_POS_PERM_ACC,
};
use super::recursive_prover::InnerProofData;
use winter_fri::folding::fold_positions;
use winter_fri::utils::map_positions_to_indexes;

type Blake3 = Blake3_256<BaseElement>;
type Blake3MerkleTree = MerkleTree<Blake3>;

/// Prover for the minimal StarkVerifierAir.
pub struct StarkVerifierProver {
    options: ProofOptions,
    pub_inputs: StarkVerifierPublicInputs,
}

impl StarkVerifierProver {
    pub fn new(options: ProofOptions, pub_inputs: StarkVerifierPublicInputs) -> Self {
        Self { options, pub_inputs }
    }

    /// Convenience: build a verifier proof that only checks the RPO hash of public inputs.
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

        let zero_digest = [BaseElement::ZERO; DIGEST_WIDTH];
        // Use a non‑trivial dummy index so that Merkle path bits are not constant in
        // transcript‑only verifier proofs; this avoids zero‑degree quotients in debug mode.
        let dummy_index: u64 = 0x55;

        let compute_dummy_root =
            |leaf: [BaseElement; DIGEST_WIDTH], depth: usize| -> [BaseElement; DIGEST_WIDTH] {
                let mut current = leaf;
                for level in 0..depth {
                    let bit = (dummy_index >> level) & 1;
                    current = if bit == 1 {
                        rpo_merge(&zero_digest, &current)
                    } else {
                        rpo_merge(&current, &zero_digest)
                    };
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

        let pub_inputs = StarkVerifierPublicInputs::new(
            inner_public_inputs.clone(),
            digest,
            trace_root,
            constraint_root,
            vec![fri_root0, [BaseElement::ZERO; DIGEST_WIDTH]],
            options.num_queries(),
            options.num_queries(),
            RPO_TRACE_WIDTH,
            8,
            blowup_factor,
            trace_length,
        );

        let prover = StarkVerifierProver::new(options.clone(), pub_inputs.clone());
        let trace = prover.build_trace_for_pub_inputs_hash();
        let proof = prover
            .prove(trace)
            .map_err(|e| format!("outer proof generation failed: {e:?}"))?;

        Ok((proof, pub_inputs))
    }

    /// Build a trace which hashes `inner_public_inputs` using the RPO sponge.
    pub fn build_trace_for_pub_inputs_hash(&self) -> TraceTable<BaseElement> {
        let inputs = &self.pub_inputs.inner_public_inputs;
        let input_len = inputs.len();
        let num_pi_blocks = input_len.div_ceil(8).max(1);

        let seed_prefix = build_context_prefix(&self.pub_inputs);
        let seed_len = seed_prefix.len() + input_len;
        let num_seed_blocks = seed_len.div_ceil(8).max(1);

        let num_coeff_perms = 36usize.div_ceil(8);
        let num_deep_coeffs = RPO_TRACE_WIDTH + 8;
        let num_deep_perms = num_deep_coeffs.div_ceil(8);
        let num_fri_commitments = self.pub_inputs.fri_commitments.len();
        let num_fri_layers = num_fri_commitments.saturating_sub(1);
        let num_fri_alpha_perms = num_fri_layers;
        let num_remainder_perms = (num_fri_commitments > 0) as usize;
        let num_pos_perms = if self.pub_inputs.num_draws == 0 {
            0
        } else {
            (self.pub_inputs.num_draws + 1).div_ceil(8)
        };
        let transcript_perms = num_pi_blocks
            + num_seed_blocks
            + num_coeff_perms
            + num_deep_perms
            + num_fri_alpha_perms
            + num_remainder_perms
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
        let trace_leaf_perms =
            leaf_perm_count(RPO_TRACE_WIDTH, self.pub_inputs.trace_partition_size);
        let constraint_leaf_perms =
            leaf_perm_count(8, self.pub_inputs.constraint_partition_size);
        let fri_leaf_perms = 1usize;
        let mut merkle_perms_per_query =
            trace_leaf_perms + depth_trace + constraint_leaf_perms + depth_trace;
        for layer_idx in 0..num_fri_layers {
            merkle_perms_per_query +=
                fri_leaf_perms + depth_trace.saturating_sub(layer_idx + 1);
        }
        let merkle_perms_total = self.pub_inputs.num_queries * merkle_perms_per_query;
        let active_perms = pre_merkle_perms + merkle_perms_total;
        let active_rows = active_perms * ROWS_PER_PERMUTATION;
        let total_rows = active_rows.next_power_of_two();

        let mut trace = TraceTable::new(VERIFIER_TRACE_WIDTH, total_rows);

        let mut perm_idx = 0usize;

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
                [BaseElement::ZERO; 4],
            );

            // Carry full state forward.
            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for i in 0..STATE_WIDTH {
                state[i] = trace.get(i, last);
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
                [BaseElement::ZERO; 4],
            );

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for i in 0..STATE_WIDTH {
                seed_state[i] = trace.get(i, last);
            }

            perm_idx += 1;
        }

        // --- Segment C: coin.init(digest(seed)) ---------------------------------------------
        let digest = [seed_state[4], seed_state[5], seed_state[6], seed_state[7]];
        let mut coin_state = [BaseElement::ZERO; STATE_WIDTH];
        for i in 0..4 {
            coin_state[4 + i] = digest[i];
        }

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
            self.pub_inputs.trace_commitment,
        );

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for i in 0..STATE_WIDTH {
            coin_state[i] = trace.get(i, last);
        }
        perm_idx += 1;

        // --- Segment D: reseed with trace commitment (coefficient perm 0) -------------------
        for i in 0..4 {
            coin_state[4 + i] += self.pub_inputs.trace_commitment[i];
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
                self.pub_inputs.constraint_commitment,
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
                [BaseElement::ZERO; 4],
            );
        }

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for i in 0..STATE_WIDTH {
            coin_state[i] = trace.get(i, last);
        }
        set_coeff_witness(&mut trace, perm_idx, &coin_state);
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
                    self.pub_inputs.constraint_commitment,
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
                    [BaseElement::ZERO; 4],
                );
            }

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for i in 0..STATE_WIDTH {
                coin_state[i] = trace.get(i, last);
            }
            set_coeff_witness(&mut trace, perm_idx, &coin_state);
            perm_idx += 1;
        }

        // --- Reseed with constraint commitment ---------------------------------------------
        for i in 0..4 {
            coin_state[4 + i] += self.pub_inputs.constraint_commitment[i];
        }
        let row_offset = perm_idx * ROWS_PER_PERMUTATION;
        self.fill_rpo_trace(&mut trace, row_offset, coin_state);
        // Out-of-domain digest is treated as a private witness for now.
        let ood_digest = [BaseElement::ZERO; 4];
        set_masks(
            &mut trace,
            perm_idx,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ONE,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ONE,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            ood_digest,
        );

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for i in 0..STATE_WIDTH {
            coin_state[i] = trace.get(i, last);
        }
        set_z_witness(&mut trace, perm_idx, coin_state[4]);
        perm_idx += 1;

        // Apply OOD reseed before drawing DEEP composition coefficients.
        for i in 0..4 {
            coin_state[4 + i] += ood_digest[i];
        }

        // --- Segment E: DEEP composition coefficient draws (permute-only, full-carry) --------
        for deep_idx in 0..num_deep_perms {
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;
            self.fill_rpo_trace(&mut trace, row_offset, coin_state);

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
                    if has_fri_commitments { BaseElement::ONE } else { BaseElement::ZERO },
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
	                    BaseElement::ONE,
	                    BaseElement::ZERO,
	                    BaseElement::ZERO,
	                    BaseElement::ZERO,
	                    reseed_word,
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
	                    [BaseElement::ZERO; 4],
	                );
            }

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for i in 0..STATE_WIDTH {
                coin_state[i] = trace.get(i, last);
            }
            set_deep_witness(&mut trace, perm_idx, &coin_state);
            perm_idx += 1;
        }

        // --- Segment F: FRI alpha draws and remainder reseed --------------------------------
        if num_fri_commitments > 0 {
            for i in 0..4 {
                coin_state[4 + i] += self.pub_inputs.fri_commitments[0][i];
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
                next_commitment,
            );

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for i in 0..STATE_WIDTH {
                coin_state[i] = trace.get(i, last);
            }
            set_fri_alpha_witness(&mut trace, perm_idx, coin_state[4]);
            perm_idx += 1;

            for i in 0..4 {
                coin_state[4 + i] += next_commitment[i];
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
                nonce_word,
            );

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for i in 0..STATE_WIDTH {
                coin_state[i] = trace.get(i, last);
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

            let expected_z = compute_expected_z(&self.pub_inputs);

            // Permutation accumulator for multiset equality. Transcript-only uses q=p so acc stays 1.
            let mut perm_acc_val = BaseElement::ONE;

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
                    [BaseElement::ZERO; 4],
                );

                let last = row_offset + ROWS_PER_PERMUTATION - 1;
                for i in 0..STATE_WIDTH {
                    coin_state[i] = trace.get(i, last);
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
                    for r in 0..ROWS_PER_PERMUTATION {
                        let row = row0 + r;
                        for i in 0..STATE_WIDTH {
                            trace.set(i, row, coin_state[i]);
                        }
                        trace.set(COL_POS_DECOMP_MASK, row, BaseElement::ONE);
                        trace.set(COL_POS_RAW, row, raw_val);
                        for j in 0..RATE_WIDTH {
                            trace.set(COL_POS_START + j, row, rate_outputs[j]);
                        }
                        trace.set(COL_Z_VALUE, row, expected_z);
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
                        for j in 0..4 {
                            if bits[j] == 1 {
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
                        trace.set(COL_POS_PERM_ACC, row, perm_acc_val);
                    }

                    let full_carry = if remaining_draws == 1 {
                        BaseElement::ZERO
                    } else {
                        BaseElement::ONE
                    };

                    // Masks on this perm boundary: carry transcript state unless this is the final decomp.
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
                        [BaseElement::ZERO; 4],
                    );

                    // Update permutation accumulator (stays 1 since q=p).
                    // perm_acc_val remains 1 since q=p in transcript-only traces.

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
        let dummy_fri_row = vec![BaseElement::ZERO; 2];

        let trace_siblings = vec![[BaseElement::ZERO; DIGEST_WIDTH]; depth_trace];
        let constraint_siblings = vec![[BaseElement::ZERO; DIGEST_WIDTH]; depth_trace];
        let mut fri_siblings_by_layer: Vec<Vec<[BaseElement; DIGEST_WIDTH]>> =
            Vec::with_capacity(num_fri_layers);
        for layer_idx in 0..num_fri_layers {
            fri_siblings_by_layer.push(vec![
                [BaseElement::ZERO; DIGEST_WIDTH];
                depth_trace.saturating_sub(layer_idx + 1)
            ]);
        }

        let dummy_index: u64 = 0x55;
        for _q in 0..self.pub_inputs.num_queries {
            let trace_leaf = hash_row_partitioned_perms(
                self,
                &mut trace,
                &mut perm_idx,
                &dummy_trace_row,
                self.pub_inputs.trace_partition_size,
            );
            authenticate_merkle_path(
                self,
                &mut trace,
                &mut perm_idx,
                trace_leaf,
                dummy_index,
                &trace_siblings,
            );

            let constraint_leaf = hash_row_partitioned_perms(
                self,
                &mut trace,
                &mut perm_idx,
                &dummy_constraint_row,
                self.pub_inputs.constraint_partition_size,
            );
            authenticate_merkle_path(
                self,
                &mut trace,
                &mut perm_idx,
                constraint_leaf,
                dummy_index,
                &constraint_siblings,
            );

            for layer_idx in 0..num_fri_layers {
                let fri_leaf =
                    hash_leaf_perms(self, &mut trace, &mut perm_idx, &dummy_fri_row);
                let sibs = &fri_siblings_by_layer[layer_idx];
                authenticate_merkle_path(
                    self,
                    &mut trace,
                    &mut perm_idx,
                    fri_leaf,
                    dummy_index,
                    sibs,
                );
            }
        }

        // --- Padding permutations -----------------------------------------------------------
        let total_perms = total_rows / ROWS_PER_PERMUTATION;
        for _ in perm_idx..total_perms {
            for i in 0..8 {
                coin_state[4 + i] = BaseElement::ZERO;
            }
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
                [BaseElement::ZERO; 4],
            );

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for i in 0..STATE_WIDTH {
                coin_state[i] = trace.get(i, last);
            }
            perm_idx += 1;
        }

        trace
    }

    /// Build a full verifier trace for a concrete inner proof.
    ///
    /// This extends the transcript segment with in‑circuit hashing of all queried
    /// leaves and Merkle authentication paths for trace, constraint, and FRI layers.
    pub fn build_trace_from_inner(&self, inner: &InnerProofData) -> TraceTable<BaseElement> {
        let inputs = &self.pub_inputs.inner_public_inputs;
        let input_len = inputs.len();
        let num_pi_blocks = input_len.div_ceil(8).max(1);

        let seed_prefix = build_context_prefix(&self.pub_inputs);
        let seed_len = seed_prefix.len() + input_len;
        let num_seed_blocks = seed_len.div_ceil(8).max(1);

        let num_coeff_perms = 36usize.div_ceil(8);
        let num_deep_coeffs = RPO_TRACE_WIDTH + 8;
        let num_deep_perms = num_deep_coeffs.div_ceil(8);
        let num_fri_commitments = self.pub_inputs.fri_commitments.len();
        let num_fri_layers = num_fri_commitments.saturating_sub(1);
        let num_fri_alpha_perms = num_fri_layers;
        let num_remainder_perms = (num_fri_commitments > 0) as usize;
        let num_pos_perms = if self.pub_inputs.num_draws == 0 {
            0
        } else {
            (self.pub_inputs.num_draws + 1).div_ceil(8)
        };

        let transcript_perms = num_pi_blocks
            + num_seed_blocks
            + num_coeff_perms
            + num_deep_perms
            + num_fri_alpha_perms
            + num_remainder_perms
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
        let trace_leaf_perms =
            leaf_perm_count(RPO_TRACE_WIDTH, self.pub_inputs.trace_partition_size);
        let constraint_leaf_perms =
            leaf_perm_count(8, self.pub_inputs.constraint_partition_size);
        let fri_leaf_perms = 1usize; // 2‑element FRI leaves
        let mut merkle_perms_per_query =
            trace_leaf_perms + depth_trace + constraint_leaf_perms + depth_trace;
        for layer_idx in 0..num_fri_layers {
            merkle_perms_per_query +=
                fri_leaf_perms + depth_trace.saturating_sub(layer_idx + 1);
        }
        let merkle_perms_total = self.pub_inputs.num_queries * merkle_perms_per_query;

        let active_perms = pre_merkle_perms + merkle_perms_total;
        let active_rows = active_perms * ROWS_PER_PERMUTATION;
        let total_rows = active_rows.next_power_of_two();

        let mut trace = TraceTable::new(VERIFIER_TRACE_WIDTH, total_rows);

        let mut perm_idx = 0usize;

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
                (BaseElement::ONE, BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO)
            } else {
                (BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO)
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
                [BaseElement::ZERO; 4],
            );
            set_path_bit(&mut trace, perm_idx, 0);

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for i in 0..STATE_WIDTH {
                state[i] = trace.get(i, last);
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
                (BaseElement::ONE, BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO)
            } else {
                (BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO, BaseElement::ONE)
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
                [BaseElement::ZERO; 4],
            );
            set_path_bit(&mut trace, perm_idx, 0);

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for i in 0..STATE_WIDTH {
                seed_state[i] = trace.get(i, last);
            }

            perm_idx += 1;
        }

        // --- Segment C: coin.init(digest(seed)) ---------------------------------------------
        let digest = [seed_state[4], seed_state[5], seed_state[6], seed_state[7]];
        let mut coin_state = [BaseElement::ZERO; STATE_WIDTH];
        for i in 0..4 {
            coin_state[4 + i] = digest[i];
        }

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
            self.pub_inputs.trace_commitment,
        );
        set_path_bit(&mut trace, perm_idx, 0);

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for i in 0..STATE_WIDTH {
            coin_state[i] = trace.get(i, last);
        }
        perm_idx += 1;

        // --- Segment D: reseed with trace commitment (coefficient perm 0) -------------------
        for i in 0..4 {
            coin_state[4 + i] += self.pub_inputs.trace_commitment[i];
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
                self.pub_inputs.constraint_commitment,
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
                [BaseElement::ZERO; 4],
            );
        }
        set_path_bit(&mut trace, perm_idx, 0);

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for i in 0..STATE_WIDTH {
            coin_state[i] = trace.get(i, last);
        }
        set_coeff_witness(&mut trace, perm_idx, &coin_state);
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
                    self.pub_inputs.constraint_commitment,
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
                    [BaseElement::ZERO; 4],
                );
            }
            set_path_bit(&mut trace, perm_idx, 0);

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for i in 0..STATE_WIDTH {
                coin_state[i] = trace.get(i, last);
            }
            set_coeff_witness(&mut trace, perm_idx, &coin_state);
            perm_idx += 1;
        }

        // --- Reseed with constraint commitment ---------------------------------------------
        for i in 0..4 {
            coin_state[4 + i] += self.pub_inputs.constraint_commitment[i];
        }
        let row_offset = perm_idx * ROWS_PER_PERMUTATION;
        self.fill_rpo_trace(&mut trace, row_offset, coin_state);
        let ood_digest = [BaseElement::ZERO; 4];
        set_masks(
            &mut trace,
            perm_idx,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ONE,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ONE,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            ood_digest,
        );
        set_path_bit(&mut trace, perm_idx, 0);

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for i in 0..STATE_WIDTH {
            coin_state[i] = trace.get(i, last);
        }
        set_z_witness(&mut trace, perm_idx, coin_state[4]);
        perm_idx += 1;

        // Apply OOD reseed before drawing DEEP composition coefficients.
        for i in 0..4 {
            coin_state[4 + i] += ood_digest[i];
        }

        // --- Segment E: DEEP composition coefficient draws (permute-only, full-carry) -------
        for deep_idx in 0..num_deep_perms {
            let row_offset = perm_idx * ROWS_PER_PERMUTATION;
            self.fill_rpo_trace(&mut trace, row_offset, coin_state);

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
                    reseed_word,
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
                    [BaseElement::ZERO; 4],
                );
            }
            set_path_bit(&mut trace, perm_idx, 0);

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for i in 0..STATE_WIDTH {
                coin_state[i] = trace.get(i, last);
            }
            set_deep_witness(&mut trace, perm_idx, &coin_state);
            perm_idx += 1;
        }

        // --- Segment F: reseed with first FRI commitment before alpha draws -----------------
        if num_fri_commitments > 0 {
            for i in 0..4 {
                coin_state[4 + i] += self.pub_inputs.fri_commitments[0][i];
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
                next_commitment,
            );
            set_path_bit(&mut trace, perm_idx, 0);

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for i in 0..STATE_WIDTH {
                coin_state[i] = trace.get(i, last);
            }
            set_fri_alpha_witness(&mut trace, perm_idx, coin_state[4]);
            perm_idx += 1;

            for i in 0..4 {
                coin_state[4 + i] += next_commitment[i];
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
                nonce_word,
            );
            set_path_bit(&mut trace, perm_idx, 0);

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for i in 0..STATE_WIDTH {
                coin_state[i] = trace.get(i, last);
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

            let gamma = inner.z;
            let mut perm_acc_val = BaseElement::ONE;
            let mut sorted_iter = inner.query_positions.iter();

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
                    [BaseElement::ZERO; 4],
                );
                set_path_bit(&mut trace, perm_idx, 0);

                let last = row_offset + ROWS_PER_PERMUTATION - 1;
                for i in 0..STATE_WIDTH {
                    coin_state[i] = trace.get(i, last);
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

                    let q_idx = sorted_iter.next().copied().unwrap_or(0) as u64;
                    let q_elem = BaseElement::new(q_idx);

                    // Decomp perm: freeze RPO state and carry buffer.
                    let row0 = perm_idx * ROWS_PER_PERMUTATION;
                    for r in 0..ROWS_PER_PERMUTATION {
                        let row = row0 + r;
                        for i in 0..STATE_WIDTH {
                            trace.set(i, row, coin_state[i]);
                        }
                        trace.set(COL_POS_DECOMP_MASK, row, BaseElement::ONE);
                        trace.set(COL_POS_RAW, row, raw_val);
                        for j in 0..RATE_WIDTH {
                            trace.set(COL_POS_START + j, row, rate_outputs[j]);
                        }
                        trace.set(COL_Z_VALUE, row, gamma);
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
                        for j in 0..4 {
                            if bits[j] == 1 {
                                acc = acc.wrapping_add(1u64 << (base_exp + j));
                                if base_exp + j < 32 {
                                    lo_acc = lo_acc.wrapping_add(1u64 << (base_exp + j));
                                }
                                if base_exp + j < depth_trace_bits {
                                    masked_acc =
                                        masked_acc.wrapping_add(1u64 << (base_exp + j));
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
                        trace.set(COL_POS_SORTED_VALUE, row, q_elem);
                        trace.set(COL_POS_PERM_ACC, row, perm_acc_val);
                    }

                    let full_carry = if remaining_draws == 1 {
                        BaseElement::ZERO
                    } else {
                        BaseElement::ONE
                    };

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
                        [BaseElement::ZERO; 4],
                    );
                    set_path_bit(&mut trace, perm_idx, 0);

                    perm_acc_val *= (p_elem + gamma) / (q_elem + gamma);

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

        // Pre-compute FRI leaf indexes per layer.
        let folding_factor = 2usize;
        let fri_num_partitions = inner.fri_num_partitions;
        let mut positions = inner.query_positions.clone();
        let mut domain_size = lde_domain_size;
        let mut fri_indexes: Vec<Vec<usize>> = Vec::with_capacity(num_fri_layers);
        for _layer_idx in 0..num_fri_layers {
            let folded_positions = fold_positions(&positions, domain_size, folding_factor);
            let position_indexes = map_positions_to_indexes(
                &folded_positions,
                domain_size,
                folding_factor,
                fri_num_partitions,
            );
            fri_indexes.push(position_indexes);
            positions = folded_positions;
            domain_size /= folding_factor;
        }

        for q in 0..self.pub_inputs.num_queries {
            // Trace leaf + path.
            let trace_row = &inner.trace_evaluations[q];
            let leaf_digest = hash_row_partitioned_perms(
                self,
                &mut trace,
                &mut perm_idx,
                trace_row,
                self.pub_inputs.trace_partition_size,
            );
            let trace_index = inner.query_positions[q] as u64;
            let trace_siblings = &inner.trace_auth_paths[q];
            authenticate_merkle_path(
                self,
                &mut trace,
                &mut perm_idx,
                leaf_digest,
                trace_index,
                trace_siblings,
            );

            // Constraint leaf + path.
            let constraint_row = &inner.constraint_evaluations[q];
            let constraint_digest = hash_row_partitioned_perms(
                self,
                &mut trace,
                &mut perm_idx,
                constraint_row,
                self.pub_inputs.constraint_partition_size,
            );
            let constraint_index = inner.query_positions[q] as u64;
            let constraint_siblings = &inner.constraint_auth_paths[q];
            authenticate_merkle_path(
                self,
                &mut trace,
                &mut perm_idx,
                constraint_digest,
                constraint_index,
                constraint_siblings,
            );

            // FRI layers.
            for layer_idx in 0..num_fri_layers {
                let layer = &inner.fri_layers[layer_idx];
                let start = q * folding_factor;
                let end = start + folding_factor;
                let leaf_vals = &layer.evaluations[start..end];
                let fri_digest =
                    hash_leaf_perms(self, &mut trace, &mut perm_idx, leaf_vals);

                let fri_index = fri_indexes
                    .get(layer_idx)
                    .and_then(|idxs| idxs.get(q))
                    .copied()
                    .unwrap_or(0) as u64;
                let fri_siblings = &layer.auth_paths[q];
                authenticate_merkle_path(
                    self,
                    &mut trace,
                    &mut perm_idx,
                    fri_digest,
                    fri_index,
                    fri_siblings,
                );
            }
        }

        // --- Padding permutations -----------------------------------------------------------
        let total_perms = total_rows / ROWS_PER_PERMUTATION;
        let mut pad_state = [BaseElement::ZERO; STATE_WIDTH];
        for _ in perm_idx..total_perms {
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
                [BaseElement::ZERO; 4],
            );
            set_path_bit(&mut trace, perm_idx, 0);

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for i in 0..STATE_WIDTH {
                pad_state[i] = trace.get(i, last);
            }
            perm_idx += 1;
        }

        trace
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
    reseed_word: [BaseElement; 4],
) {
    let row_start = perm_idx * ROWS_PER_PERMUTATION;
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
        for i in 0..4 {
            trace.set(COL_RESEED_WORD_START + i, row, reseed_word[i]);
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

fn set_z_witness(trace: &mut TraceTable<BaseElement>, perm_idx: usize, z: BaseElement) {
    let row_start = perm_idx * ROWS_PER_PERMUTATION;
    for r in 0..ROWS_PER_PERMUTATION {
        trace.set(COL_Z_VALUE, row_start + r, z);
    }
}

fn set_fri_alpha_witness(
    trace: &mut TraceTable<BaseElement>,
    perm_idx: usize,
    alpha: BaseElement,
) {
    let row_start = perm_idx * ROWS_PER_PERMUTATION;
    for r in 0..ROWS_PER_PERMUTATION {
        trace.set(COL_FRI_ALPHA_VALUE, row_start + r, alpha);
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

fn hash_row_partitioned_perms(
    prover: &StarkVerifierProver,
    trace: &mut TraceTable<BaseElement>,
    perm_idx: &mut usize,
    row: &[BaseElement],
    partition_size: usize,
) -> [BaseElement; DIGEST_WIDTH] {
    if partition_size >= row.len() {
        return hash_leaf_perms(prover, trace, perm_idx, row);
    }

    let num_partitions = row.len().div_ceil(partition_size);
    let mut merged_elements = Vec::with_capacity(num_partitions * DIGEST_WIDTH);
    for chunk in row.chunks(partition_size) {
        let digest = hash_leaf_perms(prover, trace, perm_idx, chunk);
        merged_elements.extend_from_slice(&digest);
    }

    hash_leaf_perms(prover, trace, perm_idx, &merged_elements)
}

fn hash_leaf_perms(
    prover: &StarkVerifierProver,
    trace: &mut TraceTable<BaseElement>,
    perm_idx: &mut usize,
    leaf_elems: &[BaseElement],
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
            [BaseElement::ZERO; 4],
        );
        set_path_bit(trace, *perm_idx, 0);

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for i in 0..STATE_WIDTH {
            leaf_state[i] = trace.get(i, last);
        }

        *perm_idx += 1;
    }

    [leaf_state[4], leaf_state[5], leaf_state[6], leaf_state[7]]
}

fn authenticate_merkle_path(
    prover: &StarkVerifierProver,
    trace: &mut TraceTable<BaseElement>,
    perm_idx: &mut usize,
    leaf_digest: [BaseElement; DIGEST_WIDTH],
    index: u64,
    siblings: &Vec<[BaseElement; DIGEST_WIDTH]>,
) -> [BaseElement; DIGEST_WIDTH] {
    let mut current_hash = leaf_digest;
    let depth = siblings.len();

    for level in 0..depth {
        let sibling = siblings[level];
        let bit = (index >> level) & 1;
        let (left, right) = if bit == 1 {
            (sibling, current_hash)
        } else {
            (current_hash, sibling)
        };

        let mut merge_state = [BaseElement::ZERO; STATE_WIDTH];
        for i in 0..DIGEST_WIDTH {
            merge_state[4 + i] = left[i];
            merge_state[4 + DIGEST_WIDTH + i] = right[i];
        }

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
            [BaseElement::ZERO; 4],
        );

        let next_bit = if level + 1 < depth {
            (index >> (level + 1)) & 1
        } else {
            0
        };
        set_path_bit(trace, *perm_idx, next_bit);

        let last = row_offset + ROWS_PER_PERMUTATION - 1;
        for i in 0..DIGEST_WIDTH {
            current_hash[i] = trace.get(4 + i, last);
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
    let constants = if first_half { &ARK1[round] } else { &ARK2[round] };
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
    use super::*;
    use winterfell::Air;
    use winterfell::verify;
    use winterfell::Trace;
    use super::super::{RpoAir, RpoStarkProver};
    use super::super::rpo_air::STATE_WIDTH as INNER_STATE_WIDTH;

    #[test]
    fn test_pub_inputs_hash_proof_roundtrip() {
        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();
        let inner_public_inputs: Vec<BaseElement> =
            (0..24).map(|i| BaseElement::new(i as u64 + 1)).collect();

        let (proof, pub_inputs) =
            StarkVerifierProver::prove_pub_inputs_hash(inner_public_inputs, options.clone())
                .unwrap();

        let acceptable = AcceptableOptions::OptionSet(vec![options]);
        let result = verify::<StarkVerifierAir, Blake3, DefaultRandomCoin<Blake3>, Blake3MerkleTree>(
            proof,
            pub_inputs,
            &acceptable,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_transcript_reseed_binding_tamper_fails() {
        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();
        let inner_public_inputs: Vec<BaseElement> =
            (0..16).map(|i| BaseElement::new(i as u64 + 1)).collect();

        let (proof, mut pub_inputs) =
            StarkVerifierProver::prove_pub_inputs_hash(inner_public_inputs, options.clone())
                .unwrap();

        let acceptable = AcceptableOptions::OptionSet(vec![options]);
        let ok = verify::<StarkVerifierAir, Blake3, DefaultRandomCoin<Blake3>, Blake3MerkleTree>(
            proof.clone(),
            pub_inputs.clone(),
            &acceptable,
        );
        assert!(ok.is_ok());

        // Tamper with trace commitment; should invalidate reseed boundary assertions.
        pub_inputs.trace_commitment[0] += BaseElement::ONE;
        let bad =
            verify::<StarkVerifierAir, Blake3, DefaultRandomCoin<Blake3>, Blake3MerkleTree>(
                proof,
                pub_inputs,
                &acceptable,
            );
        assert!(bad.is_err());
    }

    #[test]
    fn test_query_position_witness_tamper_fails() {
        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();
        let inner_public_inputs: Vec<BaseElement> =
            (0..24).map(|i| BaseElement::new(i as u64 + 1)).collect();

        let digest = rpo_hash_elements(&inner_public_inputs);
        let pub_inputs = StarkVerifierPublicInputs::new(
            inner_public_inputs.clone(),
            digest,
            [BaseElement::ZERO; 4],
            [BaseElement::ZERO; 4],
            vec![[BaseElement::ZERO; 4], [BaseElement::ZERO; 4]],
            options.num_queries(),
            options.num_queries(),
            RPO_TRACE_WIDTH,
            8,
            options.blowup_factor(),
            ROWS_PER_PERMUTATION,
        );

        let prover = StarkVerifierProver::new(options.clone(), pub_inputs.clone());
        let mut trace = prover.build_trace_for_pub_inputs_hash();

        // Find a row in a query-position permutation and tamper with its witness.
        let mut tampered = false;
        for row in 0..trace.length() {
            if trace.get(COL_POS_MASK, row) == BaseElement::ONE
                && row % ROWS_PER_PERMUTATION == ROWS_PER_PERMUTATION - 1
            {
                let val = trace.get(COL_POS_START, row);
                trace.set(COL_POS_START, row, val + BaseElement::ONE);
                tampered = true;
                break;
            }
        }
        assert!(tampered, "expected at least one query-position permutation");

        let prove_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prover.prove(trace)
        }));
        assert!(prove_result.is_err());
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
        let num_deep_coeffs = RPO_TRACE_WIDTH + 8;
        let num_deep_perms = num_deep_coeffs.div_ceil(8);
        let num_fri_layers = pub_inputs.fri_commitments.len().saturating_sub(1);
        let num_remainder_perms = (pub_inputs.fri_commitments.len() > 0) as usize;
        let num_pos_perms = (pub_inputs.num_draws + 1).div_ceil(8);
        let transcript_perms = num_pi_blocks
            + num_seed_blocks
            + num_coeff_perms
            + num_deep_perms
            + num_fri_layers
            + num_remainder_perms
            + num_pos_perms
            + 2;
        let pre_merkle_perms = transcript_perms + pub_inputs.num_draws;
        let trace_leaf_perms = leaf_perm_count(RPO_TRACE_WIDTH, pub_inputs.trace_partition_size);
        let constraint_leaf_perms = leaf_perm_count(8, pub_inputs.constraint_partition_size);
        let depth_trace = (pub_inputs.trace_length * pub_inputs.blowup_factor).trailing_zeros() as usize;

        let mut perm_idx = pre_merkle_perms;
        for q in 0..pub_inputs.num_queries {
            perm_idx += trace_leaf_perms;
            if depth_trace > 0 {
                let trace_root_perm = perm_idx + depth_trace - 1;
                let row = trace_root_perm * ROWS_PER_PERMUTATION + (ROWS_PER_PERMUTATION - 1);
                let digest: [BaseElement; 4] = core::array::from_fn(|i| trace.get(4 + i, row));
                assert_eq!(digest, pub_inputs.trace_commitment, "trace root mismatch q={q}");
            }
            perm_idx += depth_trace;

            perm_idx += constraint_leaf_perms;
            if depth_trace > 0 {
                let constraint_root_perm = perm_idx + depth_trace - 1;
                let row =
                    constraint_root_perm * ROWS_PER_PERMUTATION + (ROWS_PER_PERMUTATION - 1);
                let digest: [BaseElement; 4] = core::array::from_fn(|i| trace.get(4 + i, row));
                assert_eq!(
                    digest,
                    pub_inputs.constraint_commitment,
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
                        digest,
                        pub_inputs.fri_commitments[layer_idx],
                        "fri root mismatch q={q} layer={layer_idx}"
                    );
                }
                perm_idx += layer_depth;
            }
        }

        // Ensure the AIR's periodic FRI root mask for layer 1 only fires on rows
        // where the trace digest equals the expected commitment.
        if num_fri_layers > 1 {
            let air = StarkVerifierAir::new(trace.get_info(), pub_inputs.clone(), options.clone());
            let periodic = air.get_periodic_column_values();
            let fri_root_mask_1 = &periodic[periodic.len() - num_fri_layers + 1];
            for (row, &mask) in fri_root_mask_1.iter().enumerate() {
                if mask != BaseElement::ONE {
                    continue;
                }
                let digest: [BaseElement; 4] = core::array::from_fn(|i| trace.get(4 + i, row));
                assert_eq!(
                    digest,
                    pub_inputs.fri_commitments[1],
                    "fri root mask(1) mismatch at row={row}",
                );
            }
        }

        let proof = prover.prove(trace).unwrap();

        let acceptable = AcceptableOptions::OptionSet(vec![options]);
        let result = verify::<StarkVerifierAir, Blake3, DefaultRandomCoin<Blake3>, Blake3MerkleTree>(
            proof,
            pub_inputs,
            &acceptable,
        );
        assert!(result.is_ok());
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

        let prove_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prover.prove(trace)
        }));
        assert!(prove_result.is_err());
    }
}
