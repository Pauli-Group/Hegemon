//! Prover for `StarkVerifierBatchAir`.
//!
//! This builds batch verifier traces by concatenating multiple `StarkVerifierProver` segment
//! traces into a single batch trace.

use winter_air::ProofOptions;
use winter_crypto::{hashers::Blake3_256, MerkleTree};
use winter_math::FieldElement;
use winterfell::{
    crypto::DefaultRandomCoin, math::fields::f64::BaseElement, matrix::ColMatrix,
    AcceptableOptions, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, Proof, Prover, StarkDomain, Trace, TracePolyTable,
    TraceTable,
};

use super::recursive_prover::InnerProofData;
use super::stark_verifier_air::{StarkVerifierPublicInputs, VERIFIER_TRACE_WIDTH};
use super::stark_verifier_batch_air::{StarkVerifierBatchAir, StarkVerifierBatchPublicInputs};
use super::stark_verifier_prover::StarkVerifierProver;

type Blake3 = Blake3_256<BaseElement>;
type Blake3MerkleTree = MerkleTree<Blake3>;

/// Prover for batch STARK verifier.
///
/// Generates an outer proof that verifies N inner proofs in a single proof.
pub struct StarkVerifierBatchProver {
    options: ProofOptions,
    pub_inputs: StarkVerifierBatchPublicInputs,
}

impl StarkVerifierBatchProver {
    /// Create a new batch verifier prover.
    pub fn new(options: ProofOptions, pub_inputs: StarkVerifierBatchPublicInputs) -> Self {
        Self {
            options,
            pub_inputs,
        }
    }

    /// Build the batch trace by concatenating per-proof segment traces.
    ///
    /// Each segment is built using the existing `StarkVerifierProver::build_trace_from_inner()`
    /// method, ensuring the same DEEP/FRI/Merkle constraints are satisfied for each inner proof.
    pub fn build_trace_from_inners(&self, inners: &[InnerProofData]) -> TraceTable<BaseElement> {
        assert_eq!(
            inners.len(),
            self.pub_inputs.num_inner(),
            "number of inner proofs must match public inputs"
        );
        assert!(
            !inners.is_empty(),
            "batch prover requires at least one inner proof"
        );
        assert!(
            inners.len().is_power_of_two(),
            "batch prover requires power-of-two inner proof count (got {})",
            inners.len()
        );

        // Build each segment trace using the per-proof prover.
        let mut segment_traces: Vec<TraceTable<BaseElement>> = Vec::with_capacity(inners.len());
        for (_idx, (inner_data, inner_pub)) in
            inners.iter().zip(self.pub_inputs.inner.iter()).enumerate()
        {
            let segment_prover = StarkVerifierProver::new(self.options.clone(), inner_pub.clone());
            let segment_trace = segment_prover.build_trace_from_inner(inner_data);
            segment_traces.push(segment_trace);
        }

        // All segments must have the same length (uniform inner proofs).
        let segment_len = segment_traces[0].length();
        for (idx, t) in segment_traces.iter().enumerate().skip(1) {
            assert_eq!(
                t.length(),
                segment_len,
                "segment {idx} trace length mismatch: expected {segment_len}, got {}",
                t.length()
            );
        }

        // Concatenate into a single batch trace.
        let batch_len = segment_len * inners.len();
        let batch_len_pow2 = batch_len.next_power_of_two();
        let mut columns = Vec::with_capacity(VERIFIER_TRACE_WIDTH);
        for _ in 0..VERIFIER_TRACE_WIDTH {
            columns.push(vec![BaseElement::ZERO; batch_len_pow2]);
        }
        let mut batch_trace = TraceTable::init(columns);

        for (seg_idx, segment) in segment_traces.iter().enumerate() {
            let offset = seg_idx * segment_len;
            for col in 0..VERIFIER_TRACE_WIDTH {
                for row in 0..segment_len {
                    batch_trace.set(col, offset + row, segment.get(col, row));
                }
            }
        }

        // If `batch_len < batch_len_pow2`, the remaining rows are already zero-padded.

        batch_trace
    }
}

impl Prover for StarkVerifierBatchProver {
    type BaseField = BaseElement;
    type Air = StarkVerifierBatchAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> StarkVerifierBatchPublicInputs {
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

/// Generate a batch proof verifying N inner proofs.
///
/// This is the main entry point for Phase 3b batch verification.
pub fn prove_batch(
    inner_datas: &[InnerProofData],
    inner_pub_inputs: Vec<StarkVerifierPublicInputs>,
    options: ProofOptions,
) -> Result<Proof, String> {
    if inner_datas.is_empty() {
        return Err("batch prover requires at least one inner proof".to_string());
    }
    if inner_datas.len() != inner_pub_inputs.len() {
        return Err(format!(
            "inner proof count mismatch: {} data vs {} pub_inputs",
            inner_datas.len(),
            inner_pub_inputs.len()
        ));
    }
    if !inner_datas.len().is_power_of_two() {
        return Err(format!(
            "batch prover requires power-of-two inner proof count (got {})",
            inner_datas.len()
        ));
    }

    let batch_pub_inputs = StarkVerifierBatchPublicInputs {
        inner: inner_pub_inputs,
    };

    let prover = StarkVerifierBatchProver::new(options, batch_pub_inputs);
    let trace = prover.build_trace_from_inners(inner_datas);
    prover
        .prove(trace)
        .map_err(|e| format!("batch proof generation failed: {e:?}"))
}

/// Verify a batch proof.
pub fn verify_batch(
    proof: &Proof,
    inner_pub_inputs: Vec<StarkVerifierPublicInputs>,
    acceptable_options: impl Into<AcceptableOptions>,
) -> Result<(), String> {
    let batch_pub_inputs = StarkVerifierBatchPublicInputs {
        inner: inner_pub_inputs,
    };

    winterfell::verify::<StarkVerifierBatchAir, Blake3, DefaultRandomCoin<Blake3>, Blake3MerkleTree>(
        proof.clone(),
        batch_pub_inputs,
        &acceptable_options.into(),
    )
    .map_err(|e| format!("batch verification failed: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::rpo_air::{RpoAir, RpoPublicInputs, STATE_WIDTH};
    use crate::recursion::rpo_proof::RpoProofOptions;
    use crate::recursion::rpo_stark_prover::RpoStarkProver;
    use winterfell::Prover;

    /// Generate a test RpoAir proof with the given input state.
    fn generate_test_inner_proof(
        input_state: [BaseElement; STATE_WIDTH],
        options: &RpoProofOptions,
    ) -> Result<(Vec<u8>, StarkVerifierPublicInputs, InnerProofData), String> {
        // Inner proofs must be RPO-friendly (RPO Fiat-Shamir + RPO Merkle commitments) so they can
        // be verified by `StarkVerifierAir` / `StarkVerifierBatchAir`.
        let prover = RpoStarkProver::new(options.to_winter_options());

        // Compute the expected output state
        let output_state = prover.compute_output(input_state);

        // Build trace and generate proof
        let trace = prover.build_trace(input_state);
        let proof = prover
            .prove(trace)
            .map_err(|e| format!("inner proof generation failed: {e:?}"))?;

        // Build public inputs
        let pub_inputs = RpoPublicInputs::new(input_state, output_state);

        // Build verifier public inputs from the proof
        let inner_data = InnerProofData::from_proof::<RpoAir>(&proof.to_bytes(), pub_inputs)
            .map_err(|e| format!("{:?}", e))?;
        let verifier_pub_inputs = inner_data.to_stark_verifier_inputs();

        Ok((proof.to_bytes(), verifier_pub_inputs, inner_data))
    }

    #[test]
    #[ignore = "heavy batch proof generation"]
    fn test_batch_prover_two_proofs() {
        let options = RpoProofOptions::fast();

        // Generate two distinct inner RpoAir proofs
        let input1: [BaseElement; STATE_WIDTH] =
            core::array::from_fn(|i| BaseElement::new((i as u64 + 1) * 100));
        let input2: [BaseElement; STATE_WIDTH] =
            core::array::from_fn(|i| BaseElement::new((i as u64 + 1) * 200));

        let (_, pub_inputs1, inner_data1) =
            generate_test_inner_proof(input1, &options).expect("proof 1");
        let (_, pub_inputs2, inner_data2) =
            generate_test_inner_proof(input2, &options).expect("proof 2");

        // Generate batch proof
        let batch_proof = prove_batch(
            &[inner_data1, inner_data2],
            vec![pub_inputs1.clone(), pub_inputs2.clone()],
            options.to_winter_options(),
        )
        .expect("batch proof");

        // Verify batch proof
        let acceptable = AcceptableOptions::OptionSet(vec![options.to_winter_options()]);
        verify_batch(&batch_proof, vec![pub_inputs1, pub_inputs2], acceptable)
            .expect("batch verification");
    }

    #[test]
    #[ignore = "heavy batch proof generation"]
    fn test_batch_prover_tamper_reject() {
        let options = RpoProofOptions::fast();

        // Generate two distinct inner RpoAir proofs
        let input1: [BaseElement; STATE_WIDTH] =
            core::array::from_fn(|i| BaseElement::new((i as u64 + 1) * 100));
        let input2: [BaseElement; STATE_WIDTH] =
            core::array::from_fn(|i| BaseElement::new((i as u64 + 1) * 200));

        let (_, pub_inputs1, inner_data1) =
            generate_test_inner_proof(input1, &options).expect("proof 1");
        let (_, pub_inputs2, inner_data2) =
            generate_test_inner_proof(input2, &options).expect("proof 2");

        // Generate batch proof
        let batch_proof = prove_batch(
            &[inner_data1, inner_data2],
            vec![pub_inputs1.clone(), pub_inputs2.clone()],
            options.to_winter_options(),
        )
        .expect("batch proof");

        // Tamper: swap the public inputs order
        let acceptable = AcceptableOptions::OptionSet(vec![options.to_winter_options()]);
        let result = verify_batch(
            &batch_proof,
            vec![pub_inputs2, pub_inputs1], // swapped
            acceptable,
        );

        assert!(
            result.is_err(),
            "batch verification should fail with swapped public inputs"
        );
    }
}
