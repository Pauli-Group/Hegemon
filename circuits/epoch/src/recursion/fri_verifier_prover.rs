//! Minimal prover for `FriVerifierAir`.
//!
//! This prover is for recursion development only. It builds a tiny trace which
//! (1) executes a single RPO permutation to satisfy RPO transition constraints and
//! (2) repeats one valid folding relation in the extra columns.

use winter_air::ProofOptions;
use winter_crypto::{hashers::Blake3_256, MerkleTree};
use winter_fri::folding::fold_positions;
use winter_math::{FieldElement, StarkField};
use winterfell::{
    crypto::DefaultRandomCoin, math::fields::f64::BaseElement, matrix::ColMatrix,
    AcceptableOptions, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, Proof, Prover, StarkDomain, TraceInfo, TracePolyTable,
    TraceTable,
};

use super::fri_air::{
    FriFoldingVerifier, FriPublicInputs, FriVerifierAir, COL_ALPHA, COL_FOLD_MASK, COL_F_NEG_X,
    COL_F_NEXT, COL_F_X, COL_REM_ACC, COL_REM_COEFF, COL_REM_MASK, COL_X, COL_X_REM,
};
use super::recursive_prover::InnerProofData;
use super::rpo_air::{ARK1, ARK2, INV_ALPHA, MDS, NUM_ROUNDS, ROWS_PER_PERMUTATION, STATE_WIDTH};

type Blake3 = Blake3_256<BaseElement>;
type Blake3MerkleTree = MerkleTree<Blake3>;

/// Prover for a minimal FriVerifierAir trace.
pub struct FriVerifierProver {
    options: ProofOptions,
    pub_inputs: FriPublicInputs,
}

impl FriVerifierProver {
    pub fn new(options: ProofOptions, pub_inputs: FriPublicInputs) -> Self {
        Self {
            options,
            pub_inputs,
        }
    }

    /// Build a minimal trace containing one RPO permutation and one folding check.
    pub fn build_trace(&self) -> TraceTable<BaseElement> {
        let num_perms = 4usize;
        let total_rows = num_perms * ROWS_PER_PERMUTATION;
        let mut trace = TraceTable::new(STATE_WIDTH + 10, total_rows);

        // --- RPO permutations in columns 0..STATE_WIDTH-1 --------------------
        for perm in 0..num_perms {
            let row_offset = perm * ROWS_PER_PERMUTATION;
            let mut state = [BaseElement::ZERO; STATE_WIDTH];
            if perm == 0 {
                // Bind first layer commitment to capacity at row 0.
                if let Some(first) = self.pub_inputs.layer_commitments.get(0) {
                    state[..4].copy_from_slice(first);
                }
            } else {
                // Use distinct inputs for each stacked permutation so that trace polynomials are
                // not 16-periodic. This avoids DEEP composer degree assertions during proof gen.
                for i in 0..STATE_WIDTH {
                    state[i] = BaseElement::new(((perm as u64) + 1) * ((i as u64) + 3));
                }
            }

            // Row 0 of this permutation: input state.
            for (i, v) in state.iter().enumerate() {
                trace.set(i, row_offset, *v);
            }

            for round in 0..NUM_ROUNDS {
                // Forward half-round.
                apply_mds(&mut state);
                add_constants(&mut state, round, true);
                apply_sbox(&mut state);
                let row = row_offset + 1 + round * 2;
                for (i, v) in state.iter().enumerate() {
                    trace.set(i, row, *v);
                }

                // Inverse half-round.
                apply_mds(&mut state);
                add_constants(&mut state, round, false);
                apply_inv_sbox(&mut state);
                let row = row_offset + 2 + round * 2;
                if row < row_offset + ROWS_PER_PERMUTATION {
                    for (i, v) in state.iter().enumerate() {
                        trace.set(i, row, *v);
                    }
                }
            }

            // Padding row 15 for this permutation.
            let padding_row = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, v) in state.iter().enumerate() {
                trace.set(i, padding_row, *v);
            }
        }

        // --- Folding columns (STATE_WIDTH..STATE_WIDTH+5) --------------------
        // Vary folding witnesses per permutation so the folding constraint polynomial
        // is non-trivial but still divisible by the transition divisor.
        let remainder_perm = num_perms.saturating_sub(2);
        for perm in 0..num_perms {
            let x = BaseElement::new(7 * (perm as u64 + 1));
            let alpha = BaseElement::new(3 * (perm as u64 + 2));
            let f_x = BaseElement::new(100 + perm as u64);
            let f_neg_x = BaseElement::new(50 + (perm as u64) * 2);
            let folded_next = FriFoldingVerifier::compute_folded(x, f_x, f_neg_x, alpha);

            let is_remainder = perm == remainder_perm;
            let fold_mask = if perm + 1 == num_perms || is_remainder {
                BaseElement::ZERO
            } else {
                BaseElement::ONE
            };

            // Provide one non-trivial remainder permutation so declared degrees match.
            let x_rem = BaseElement::new(5 * (perm as u64 + 11));
            let rem_coeffs: [BaseElement; 8] =
                core::array::from_fn(|i| BaseElement::new((perm as u64 + 2) * (i as u64 + 3)));
            let mut rem_acc_eval = BaseElement::ZERO;
            for coeff in rem_coeffs.iter() {
                rem_acc_eval = rem_acc_eval * x_rem + *coeff;
            }

            let f_next = if is_remainder {
                rem_acc_eval
            } else {
                folded_next
            };

            let row_start = perm * ROWS_PER_PERMUTATION;
            let mut acc = BaseElement::ZERO;
            for r in 0..ROWS_PER_PERMUTATION {
                let row = row_start + r;
                trace.set(COL_F_X, row, f_x);
                trace.set(COL_F_NEG_X, row, f_neg_x);
                trace.set(COL_ALPHA, row, alpha);
                trace.set(COL_X, row, x);
                trace.set(COL_F_NEXT, row, f_next);
                trace.set(COL_FOLD_MASK, row, fold_mask);

                if is_remainder {
                    trace.set(COL_REM_MASK, row, BaseElement::ONE);
                    trace.set(COL_X_REM, row, x_rem);
                    trace.set(COL_REM_ACC, row, acc);
                    if r < 8 {
                        let coeff = rem_coeffs[r];
                        trace.set(COL_REM_COEFF, row, coeff);
                        acc = acc * x_rem + coeff;
                    } else {
                        trace.set(COL_REM_COEFF, row, BaseElement::ZERO);
                    }
                } else {
                    trace.set(COL_REM_MASK, row, BaseElement::ZERO);
                    trace.set(COL_X_REM, row, BaseElement::ZERO);
                    trace.set(COL_REM_COEFF, row, BaseElement::ZERO);
                    trace.set(COL_REM_ACC, row, BaseElement::ZERO);
                }
            }
        }

        trace
    }

    /// Build a trace for real inner-proof FRI folding checks.
    ///
    /// This consumes `InnerProofData` extracted from an RPO-friendly inner proof and
    /// verifies folding relations between successive FRI layers and the remainder polynomial.
    /// Merkle authentication for layer openings is not yet included.
    pub fn build_trace_from_inner(&self, inner: &InnerProofData) -> TraceTable<BaseElement> {
        let num_layers = inner.fri_layers.len();

        if num_layers == 0 || inner.query_positions.is_empty() {
            return self.build_trace();
        }

        // One fold check per queried coset in each committed layer transition,
        // plus one remainder check per queried coset in the last committed layer.
        let fold_perms: usize = inner
            .fri_layers
            .iter()
            .take(num_layers.saturating_sub(1))
            .map(|l| l.evaluations.len() / 2)
            .sum();
        let remainder_perms = inner.fri_layers[num_layers - 1].evaluations.len() / 2;
        let active_perms = fold_perms + remainder_perms;
        let active_rows = active_perms * ROWS_PER_PERMUTATION;
        let total_rows = (active_rows + ROWS_PER_PERMUTATION).next_power_of_two();
        let total_perms = total_rows / ROWS_PER_PERMUTATION;

        let mut trace = TraceTable::new(STATE_WIDTH + 10, total_rows);

        // --- RPO permutations (dummy for now) --------------------------------------------
        for perm in 0..total_perms {
            let row_offset = perm * ROWS_PER_PERMUTATION;
            let mut state = [BaseElement::ZERO; STATE_WIDTH];
            if perm == 0 {
                if let Some(first) = self.pub_inputs.layer_commitments.get(0) {
                    state[..4].copy_from_slice(first);
                }
            } else {
                for i in 0..STATE_WIDTH {
                    state[i] = BaseElement::new(((perm as u64) + 1) * ((i as u64) + 7));
                }
            }

            for (i, v) in state.iter().enumerate() {
                trace.set(i, row_offset, *v);
            }

            for round in 0..NUM_ROUNDS {
                apply_mds(&mut state);
                add_constants(&mut state, round, true);
                apply_sbox(&mut state);
                let row = row_offset + 1 + round * 2;
                for (i, v) in state.iter().enumerate() {
                    trace.set(i, row, *v);
                }

                apply_mds(&mut state);
                add_constants(&mut state, round, false);
                apply_inv_sbox(&mut state);
                let row = row_offset + 2 + round * 2;
                if row < row_offset + ROWS_PER_PERMUTATION {
                    for (i, v) in state.iter().enumerate() {
                        trace.set(i, row, *v);
                    }
                }
            }

            let padding_row = row_offset + ROWS_PER_PERMUTATION - 1;
            for (i, v) in state.iter().enumerate() {
                trace.set(i, padding_row, *v);
            }
        }

        // --- Folding witnesses ------------------------------------------------------------
        let offset = BaseElement::GENERATOR;
        let mut positions = inner.query_positions.clone();
        let mut domain_size = inner.trace_length * inner.blowup_factor;
        let mut perm_idx = 0usize;

        for layer_idx in 0..num_layers.saturating_sub(1) {
            let alpha = inner.fri_alphas[layer_idx];
            let g = BaseElement::get_root_of_unity(domain_size.ilog2());

            let cur_vals = &inner.fri_layers[layer_idx].evaluations;
            let folded_positions = fold_positions(&positions, domain_size, 2);
            let num_pairs = folded_positions.len().min(cur_vals.len() / 2);

            for q in 0..num_pairs {
                if perm_idx >= active_perms {
                    break;
                }
                let f_x = cur_vals[2 * q];
                let f_neg_x = cur_vals[2 * q + 1];
                let x = g.exp(folded_positions[q] as u64);
                let f_next = FriFoldingVerifier::compute_folded(x, f_x, f_neg_x, alpha);

                let row_start = perm_idx * ROWS_PER_PERMUTATION;
                for r in 0..ROWS_PER_PERMUTATION {
                    let row = row_start + r;
                    trace.set(COL_F_X, row, f_x);
                    trace.set(COL_F_NEG_X, row, f_neg_x);
                    trace.set(COL_ALPHA, row, alpha);
                    trace.set(COL_X, row, x);
                    trace.set(COL_F_NEXT, row, f_next);
                    trace.set(COL_FOLD_MASK, row, BaseElement::ONE);
                    trace.set(COL_REM_MASK, row, BaseElement::ZERO);
                    trace.set(COL_X_REM, row, BaseElement::ZERO);
                    trace.set(COL_REM_COEFF, row, BaseElement::ZERO);
                    trace.set(COL_REM_ACC, row, BaseElement::ZERO);
                }

                perm_idx += 1;
            }

            positions = folded_positions;
            domain_size /= 2;
        }

        // --- Remainder checks (final fold + Horner) --------------------------------------
        let last_layer_idx = num_layers - 1;
        let last_alpha = inner.fri_alphas[last_layer_idx];
        let g_cur = BaseElement::get_root_of_unity(domain_size.ilog2());
        let positions_next = fold_positions(&positions, domain_size, 2);
        let g_next = BaseElement::get_root_of_unity((domain_size / 2).ilog2());
        let last_vals = &inner.fri_layers[last_layer_idx].evaluations;

        let mut coeffs = inner.fri_remainder.clone();
        assert!(
            coeffs.len() <= 8,
            "remainder polynomial too large for current recursion AIR ({} coefficients)",
            coeffs.len()
        );
        coeffs.reverse(); // high-to-low order for Horner
        if coeffs.len() < 8 {
            let mut padded = vec![BaseElement::ZERO; 8 - coeffs.len()];
            padded.extend_from_slice(&coeffs);
            coeffs = padded;
        }

        let num_pairs = positions_next.len().min(last_vals.len() / 2);
        for q in 0..num_pairs {
            if perm_idx >= active_perms {
                break;
            }
            let f_x = last_vals[2 * q];
            let f_neg_x = last_vals[2 * q + 1];
            let x_fold = offset * g_cur.exp(positions_next[q] as u64);
            let x_rem = offset * g_next.exp(positions_next[q] as u64);

            // Evaluate remainder polynomial at x_rem; folding constraint will enforce that this
            // matches the final DRP fold from the last committed layer.
            let mut rem_eval = BaseElement::ZERO;
            for coeff in coeffs.iter().take(8) {
                rem_eval = rem_eval * x_rem + *coeff;
            }
            let f_next = rem_eval;

            let row_start = perm_idx * ROWS_PER_PERMUTATION;
            let mut acc = BaseElement::ZERO;
            for r in 0..ROWS_PER_PERMUTATION {
                let row = row_start + r;
                trace.set(COL_F_X, row, f_x);
                trace.set(COL_F_NEG_X, row, f_neg_x);
                trace.set(COL_ALPHA, row, last_alpha);
                trace.set(COL_X, row, x_fold);
                trace.set(COL_F_NEXT, row, f_next);
                trace.set(COL_FOLD_MASK, row, BaseElement::ZERO);
                trace.set(COL_REM_MASK, row, BaseElement::ONE);
                trace.set(COL_X_REM, row, x_rem);
                trace.set(COL_REM_ACC, row, acc);

                if r < 8 {
                    let coeff = coeffs[r];
                    trace.set(COL_REM_COEFF, row, coeff);
                    acc = acc * x_rem + coeff;
                } else {
                    trace.set(COL_REM_COEFF, row, BaseElement::ZERO);
                }
            }

            perm_idx += 1;
        }

        if fold_perms == 0 && perm_idx < total_perms {
            let x = BaseElement::new(7);
            let alpha = BaseElement::new(3);
            let f_x = BaseElement::new(111);
            let f_neg_x = BaseElement::new(222);
            let f_next = FriFoldingVerifier::compute_folded(x, f_x, f_neg_x, alpha);

            let row_start = perm_idx * ROWS_PER_PERMUTATION;
            for r in 0..ROWS_PER_PERMUTATION {
                let row = row_start + r;
                trace.set(COL_F_X, row, f_x);
                trace.set(COL_F_NEG_X, row, f_neg_x);
                trace.set(COL_ALPHA, row, alpha);
                trace.set(COL_X, row, x);
                trace.set(COL_F_NEXT, row, f_next);
                trace.set(COL_FOLD_MASK, row, BaseElement::ONE);
                trace.set(COL_REM_MASK, row, BaseElement::ZERO);
                trace.set(COL_X_REM, row, BaseElement::ZERO);
                trace.set(COL_REM_COEFF, row, BaseElement::ZERO);
                trace.set(COL_REM_ACC, row, BaseElement::ZERO);
            }
            perm_idx += 1;
        }

        // Disable folding and remainder checks on any remaining permutations.
        for perm in perm_idx..total_perms {
            let row_start = perm * ROWS_PER_PERMUTATION;
            for r in 0..ROWS_PER_PERMUTATION {
                trace.set(COL_FOLD_MASK, row_start + r, BaseElement::ZERO);
                trace.set(COL_REM_MASK, row_start + r, BaseElement::ZERO);
                trace.set(COL_X_REM, row_start + r, BaseElement::ZERO);
                trace.set(COL_REM_COEFF, row_start + r, BaseElement::ZERO);
                trace.set(COL_REM_ACC, row_start + r, BaseElement::ZERO);
            }
        }

        trace
    }

    /// Convenience: prove a minimal FriVerifierAir trace.
    pub fn prove_minimal(options: ProofOptions) -> Result<(Proof, FriPublicInputs), String> {
        let alpha = BaseElement::new(3);
        let pub_inputs = FriPublicInputs::new(
            vec![[BaseElement::ZERO; 4]],
            vec![alpha],
            ROWS_PER_PERMUTATION,
            ROWS_PER_PERMUTATION,
        );

        let prover = FriVerifierProver::new(options.clone(), pub_inputs.clone());
        let trace = prover.build_trace();
        let proof = prover
            .prove(trace)
            .map_err(|e| format!("fri verifier proof generation failed: {e:?}"))?;

        Ok((proof, pub_inputs))
    }
}

impl Prover for FriVerifierProver {
    type BaseField = BaseElement;
    type Air = FriVerifierAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> FriPublicInputs {
        self.pub_inputs.clone()
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
    for elem in state.iter_mut() {
        *elem = elem.exp(INV_ALPHA.into());
    }
}

#[cfg(test)]
mod tests {
    use super::super::rpo_air::STATE_WIDTH as INNER_STATE_WIDTH;
    use super::super::{RpoAir, RpoStarkProver};
    use super::*;
    use winter_air::{Air, EvaluationFrame};
    use winterfell::verify;
    use winterfell::Trace;

    #[test]
    fn test_fri_verifier_proof_roundtrip() {
        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();
        let (proof, pub_inputs) = FriVerifierProver::prove_minimal(options.clone()).unwrap();

        let acceptable = AcceptableOptions::OptionSet(vec![options]);
        let result = verify::<FriVerifierAir, Blake3, DefaultRandomCoin<Blake3>, Blake3MerkleTree>(
            proof,
            pub_inputs,
            &acceptable,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_minimal_trace_satisfies_air() {
        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();
        let alpha = BaseElement::new(3);
        let pub_inputs = FriPublicInputs::new(
            vec![[BaseElement::ZERO; 4]],
            vec![alpha],
            ROWS_PER_PERMUTATION,
            ROWS_PER_PERMUTATION,
        );
        let prover = FriVerifierProver::new(options.clone(), pub_inputs.clone());
        let trace = prover.build_trace();
        let air = FriVerifierAir::new(trace.info().clone(), pub_inputs, options);

        let periodic_columns = air.get_periodic_column_values();
        let mut periodic_values_row = Vec::with_capacity(periodic_columns.len());

        let mut result = vec![BaseElement::ZERO; STATE_WIDTH + 5];
        let width = trace.width();
        for row in 0..trace.length() - 1 {
            periodic_values_row.clear();
            for col in periodic_columns.iter() {
                periodic_values_row.push(col[row]);
            }
            let current_row: Vec<BaseElement> = (0..width).map(|c| trace.get(c, row)).collect();
            let next_row: Vec<BaseElement> = (0..width).map(|c| trace.get(c, row + 1)).collect();
            let frame = EvaluationFrame::from_rows(current_row, next_row);
            air.evaluate_transition(&frame, &periodic_values_row, &mut result);
            assert!(
                result.iter().all(|v| *v == BaseElement::ZERO),
                "non-zero constraints at row {row}: {result:?}"
            );
        }
    }

    #[test]
    fn test_trace_from_inner_rpo_proof_roundtrip() {
        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();

        // Generate a small inner RPO proof and extract recursion data.
        let inner_prover = RpoStarkProver::fast();
        let input_state = [BaseElement::new(7); INNER_STATE_WIDTH];
        let (inner_proof, inner_pub_inputs) = inner_prover
            .prove_rpo_permutation(input_state)
            .expect("inner proof generation should succeed");

        let inner_data =
            InnerProofData::from_proof::<RpoAir>(&inner_proof.to_bytes(), inner_pub_inputs)
                .unwrap();

        let layer_commitments: Vec<[BaseElement; 4]> =
            inner_data.fri_layers.iter().map(|l| l.commitment).collect();

        let pub_inputs = FriPublicInputs::new(
            layer_commitments,
            inner_data.fri_alphas.clone(),
            inner_data.trace_length * inner_data.blowup_factor,
            inner_data.trace_length,
        );

        let prover = FriVerifierProver::new(options.clone(), pub_inputs.clone());
        let trace = prover.build_trace_from_inner(&inner_data);
        let proof = prover.prove(trace).unwrap();

        let acceptable = AcceptableOptions::OptionSet(vec![options]);
        let result = verify::<FriVerifierAir, Blake3, DefaultRandomCoin<Blake3>, Blake3MerkleTree>(
            proof,
            pub_inputs,
            &acceptable,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_trace_from_inner_tamper_panics() {
        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();
        let inner_prover = RpoStarkProver::fast();
        let input_state = [BaseElement::new(7); INNER_STATE_WIDTH];
        let (inner_proof, inner_pub_inputs) = inner_prover
            .prove_rpo_permutation(input_state)
            .expect("inner proof generation should succeed");

        let inner_data =
            InnerProofData::from_proof::<RpoAir>(&inner_proof.to_bytes(), inner_pub_inputs)
                .unwrap();

        let layer_commitments: Vec<[BaseElement; 4]> =
            inner_data.fri_layers.iter().map(|l| l.commitment).collect();

        let pub_inputs = FriPublicInputs::new(
            layer_commitments,
            inner_data.fri_alphas.clone(),
            inner_data.trace_length * inner_data.blowup_factor,
            inner_data.trace_length,
        );

        let prover = FriVerifierProver::new(options.clone(), pub_inputs);
        let mut trace = prover.build_trace_from_inner(&inner_data);

        // Tamper with a folding witness on a boundary row where folding is enabled.
        let mut tampered = false;
        for row in 0..trace.length() {
            if trace.get(COL_FOLD_MASK, row) == BaseElement::ONE
                && row % ROWS_PER_PERMUTATION == ROWS_PER_PERMUTATION - 1
            {
                let val = trace.get(COL_F_X, row);
                trace.set(COL_F_X, row, val + BaseElement::ONE);
                tampered = true;
                break;
            }
        }
        assert!(tampered);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prover.prove(trace)));
        assert!(result.is_err());
    }

    #[test]
    fn test_trace_from_inner_remainder_tamper_panics() {
        let options = super::super::rpo_proof::RpoProofOptions::fast().to_winter_options();
        let inner_prover = RpoStarkProver::fast();
        let input_state = [BaseElement::new(7); INNER_STATE_WIDTH];
        let (inner_proof, inner_pub_inputs) = inner_prover
            .prove_rpo_permutation(input_state)
            .expect("inner proof generation should succeed");

        let inner_data =
            InnerProofData::from_proof::<RpoAir>(&inner_proof.to_bytes(), inner_pub_inputs)
                .unwrap();

        let layer_commitments: Vec<[BaseElement; 4]> =
            inner_data.fri_layers.iter().map(|l| l.commitment).collect();

        let pub_inputs = FriPublicInputs::new(
            layer_commitments,
            inner_data.fri_alphas.clone(),
            inner_data.trace_length * inner_data.blowup_factor,
            inner_data.trace_length,
        );

        let prover = FriVerifierProver::new(options.clone(), pub_inputs);
        let mut trace = prover.build_trace_from_inner(&inner_data);

        // Tamper with a remainder coefficient in the first remainder permutation.
        let mut tampered = false;
        for row in 0..trace.length() {
            if trace.get(COL_REM_MASK, row) == BaseElement::ONE && row % ROWS_PER_PERMUTATION == 0 {
                let val = trace.get(COL_REM_COEFF, row);
                trace.set(COL_REM_COEFF, row, val + BaseElement::ONE);
                tampered = true;
                break;
            }
        }
        assert!(tampered);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prover.prove(trace)));
        assert!(result.is_err());
    }
}
