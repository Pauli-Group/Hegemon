//! STARK prover for `StarkVerifierAir` using RPO-based Fiat–Shamir.
//!
//! This enables generating outer verifier proofs which are themselves efficient to verify
//! in-circuit (as an inner proof) because:
//! - Fiat–Shamir uses `RpoRandomCoin`
//! - Vector commitments use `MerkleTree<Rpo256>`
//!
//! This is the Phase 3b.1 building block for recursion depth 2+.

use miden_crypto::hash::rpo::Rpo256;
use miden_crypto::rand::RpoRandomCoin;
use winter_air::{ProofOptions, TraceInfo};
use winter_crypto::MerkleTree;
use winter_math::FieldElement;
use winterfell::{
    math::fields::f64::BaseElement, matrix::ColMatrix, AuxRandElements, CompositionPoly,
    CompositionPolyTrace, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions, Prover, StarkDomain,
    TracePolyTable, TraceTable,
};

use super::recursive_prover::InnerProofData;
use super::stark_verifier_air::{StarkVerifierAir, StarkVerifierPublicInputs};
use super::stark_verifier_prover::StarkVerifierProver;

type RpoMerkleTree = MerkleTree<Rpo256>;

/// Prover for `StarkVerifierAir` with RPO commitments + RPO Fiat–Shamir.
pub struct RpoStarkVerifierProver {
    options: ProofOptions,
    pub_inputs: StarkVerifierPublicInputs,
    trace_builder: StarkVerifierProver,
}

impl RpoStarkVerifierProver {
    pub fn new(options: ProofOptions, pub_inputs: StarkVerifierPublicInputs) -> Self {
        let trace_builder = StarkVerifierProver::new(options.clone(), pub_inputs.clone());
        Self {
            options,
            pub_inputs,
            trace_builder,
        }
    }

    pub fn build_trace_from_inner(&self, inner: &InnerProofData) -> TraceTable<BaseElement> {
        self.trace_builder.build_trace_from_inner(inner)
    }
}

impl Prover for RpoStarkVerifierProver {
    type BaseField = BaseElement;
    type Air = StarkVerifierAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> StarkVerifierPublicInputs {
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

