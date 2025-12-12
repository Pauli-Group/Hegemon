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
use super::rpo_proof::rpo_hash_elements;
use super::stark_verifier_air::{
    build_context_prefix, StarkVerifierAir, StarkVerifierPublicInputs, VERIFIER_TRACE_WIDTH,
    COL_CARRY_MASK, COL_FULL_CARRY_MASK, COL_RESEED_MASK, COL_COIN_INIT_MASK,
    COL_RESEED_WORD_START, COL_COEFF_MASK, COL_Z_MASK, COL_COEFF_START, COL_Z_VALUE,
    COL_DEEP_MASK, COL_DEEP_START, COL_FRI_MASK, COL_FRI_ALPHA_VALUE,
    COL_POS_MASK, COL_POS_START,
};

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
        let num_blocks = inner_public_inputs.len().div_ceil(8).max(1);
        let _active_rows = num_blocks * ROWS_PER_PERMUTATION;

        let pub_inputs = StarkVerifierPublicInputs::new(
            inner_public_inputs.clone(),
            digest,
            [BaseElement::ZERO; 4],
            [BaseElement::ZERO; 4],
            vec![[BaseElement::ZERO; 4], [BaseElement::ZERO; 4]],
            options.num_queries(),
            options.blowup_factor(),
            ROWS_PER_PERMUTATION,
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
        let num_pos_perms = if self.pub_inputs.num_queries == 0 {
            0
        } else {
            (self.pub_inputs.num_queries + 1).div_ceil(8)
        };
        let active_perms = num_pi_blocks
            + num_seed_blocks
            + num_coeff_perms
            + num_deep_perms
            + num_fri_alpha_perms
            + num_remainder_perms
            + num_pos_perms
            + 2;
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
                nonce_word,
            );

            let last = row_offset + ROWS_PER_PERMUTATION - 1;
            for i in 0..STATE_WIDTH {
                coin_state[i] = trace.get(i, last);
            }
            perm_idx += 1;
        }

        // --- Query position draw permutations ----------------------------------------------
        if num_pos_perms > 0 {
            // Absorb nonce into the coin before the first draw permutation.
            coin_state[4] += pow_nonce_elem;

            for pos_idx in 0..num_pos_perms {
                let row_offset = perm_idx * ROWS_PER_PERMUTATION;
                self.fill_rpo_trace(&mut trace, row_offset, coin_state);

                let is_last = pos_idx + 1 == num_pos_perms;
                set_masks(
                    &mut trace,
                    perm_idx,
                    BaseElement::ZERO,
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
                    BaseElement::ONE,
                    [BaseElement::ZERO; 4],
                );

                let last = row_offset + ROWS_PER_PERMUTATION - 1;
                for i in 0..STATE_WIDTH {
                    coin_state[i] = trace.get(i, last);
                }
                set_pos_witness(&mut trace, perm_idx, &coin_state);
                perm_idx += 1;
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
    use winterfell::verify;
    use winterfell::Trace;

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
}
