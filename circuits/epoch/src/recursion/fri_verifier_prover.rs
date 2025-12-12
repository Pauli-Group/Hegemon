//! Minimal prover for `FriVerifierAir`.
//!
//! This prover is for recursion development only. It builds a tiny trace which
//! (1) executes a single RPO permutation to satisfy RPO transition constraints and
//! (2) repeats one valid folding relation in the extra columns.

use winter_air::ProofOptions;
use winter_crypto::{hashers::Blake3_256, MerkleTree};
use winter_math::FieldElement;
use winterfell::{
    crypto::DefaultRandomCoin,
    math::fields::f64::BaseElement,
    matrix::ColMatrix,
    AuxRandElements, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions, Prover, StarkDomain,
    TraceInfo, TracePolyTable, TraceTable, CompositionPoly, CompositionPolyTrace, Proof,
    AcceptableOptions,
};

use super::fri_air::{
    FriPublicInputs, FriVerifierAir, FriFoldingVerifier, COL_ALPHA, COL_F_NEG_X, COL_F_NEXT, COL_F_X,
    COL_X,
};
use super::rpo_air::{STATE_WIDTH, NUM_ROUNDS, ROWS_PER_PERMUTATION, MDS, ARK1, ARK2, INV_ALPHA};

type Blake3 = Blake3_256<BaseElement>;
type Blake3MerkleTree = MerkleTree<Blake3>;

/// Prover for a minimal FriVerifierAir trace.
pub struct FriVerifierProver {
    options: ProofOptions,
    pub_inputs: FriPublicInputs,
}

impl FriVerifierProver {
    pub fn new(options: ProofOptions, pub_inputs: FriPublicInputs) -> Self {
        Self { options, pub_inputs }
    }

    /// Build a minimal trace containing one RPO permutation and one folding check.
    pub fn build_trace(&self) -> TraceTable<BaseElement> {
        let num_perms = 4usize;
        let total_rows = num_perms * ROWS_PER_PERMUTATION;
        let mut trace = TraceTable::new(STATE_WIDTH + 5, total_rows);

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

        // --- Folding columns (STATE_WIDTH..STATE_WIDTH+4) --------------------
        let x = BaseElement::new(7);
        let alpha = BaseElement::new(3);
        let f_x = BaseElement::new(100);
        let f_neg_x = BaseElement::new(50);
        let f_next = FriFoldingVerifier::compute_folded(x, f_x, f_neg_x, alpha);

        for row in 0..total_rows {
            trace.set(COL_F_X, row, f_x);
            trace.set(COL_F_NEG_X, row, f_neg_x);
            trace.set(COL_ALPHA, row, alpha);
            trace.set(COL_X, row, x);
            trace.set(COL_F_NEXT, row, f_next);
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
    for elem in state.iter_mut() {
        *elem = elem.exp(INV_ALPHA.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::verify;
    use winter_air::{Air, EvaluationFrame};
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

        let mut result = vec![BaseElement::ZERO; STATE_WIDTH + 1];
        let width = trace.width();
        for row in 0..trace.length() - 1 {
            periodic_values_row.clear();
            for col in periodic_columns.iter() {
                periodic_values_row.push(col[row]);
            }
            let current_row: Vec<BaseElement> =
                (0..width).map(|c| trace.get(c, row)).collect();
            let next_row: Vec<BaseElement> =
                (0..width).map(|c| trace.get(c, row + 1)).collect();
            let frame = EvaluationFrame::from_rows(current_row, next_row);
            air.evaluate_transition(&frame, &periodic_values_row, &mut result);
            assert!(
                result.iter().all(|v| *v == BaseElement::ZERO),
                "non-zero constraints at row {row}: {result:?}"
            );
        }
    }
}
