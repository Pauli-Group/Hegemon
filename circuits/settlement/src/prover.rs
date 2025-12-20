//! Settlement STARK prover.
//!
//! Builds the execution trace and generates a STARK proof for the
//! settlement commitment circuit.

use winter_crypto::hashers::Blake3_256;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement},
    matrix::ColMatrix,
    AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, TraceInfo,
    TracePolyTable, TraceTable,
};

use crate::air::{SettlementAir, SettlementPublicInputs};
use crate::constants::{
    ABSORB_CYCLES, COL_IN0, COL_IN1, COL_S0, COL_S1, COL_S2, CYCLE_LENGTH,
    INPUT_PAIRS_PER_TRACE, PADDED_INPUT_COUNT, SETTLEMENT_DOMAIN_TAG, TRACE_LENGTH, TRACE_WIDTH,
};
use crate::hashing::{poseidon_round, Felt};

type Blake3 = Blake3_256<BaseElement>;

pub struct SettlementProver {
    options: ProofOptions,
    pub_inputs: Option<SettlementPublicInputs>,
}

impl SettlementProver {
    pub fn new(options: ProofOptions) -> Self {
        Self {
            options,
            pub_inputs: None,
        }
    }

    pub fn with_default_options() -> Self {
        Self::new(default_proof_options())
    }

    pub fn with_fast_options() -> Self {
        Self::new(fast_proof_options())
    }

    pub fn build_trace(&self, pub_inputs: &SettlementPublicInputs) -> TraceTable<BaseElement> {
        let inputs = pub_inputs.input_elements();
        debug_assert_eq!(inputs.len(), PADDED_INPUT_COUNT);

        let mut columns = vec![vec![BaseElement::ZERO; TRACE_LENGTH]; TRACE_WIDTH];
        let mut state = [
            BaseElement::new(SETTLEMENT_DOMAIN_TAG),
            BaseElement::ZERO,
            BaseElement::ONE,
        ];

        for cycle in 0..INPUT_PAIRS_PER_TRACE {
            let (in0, in1) = if cycle < ABSORB_CYCLES {
                (inputs[2 * cycle], inputs[2 * cycle + 1])
            } else {
                (BaseElement::ZERO, BaseElement::ZERO)
            };
            for step in 0..CYCLE_LENGTH {
                let row = cycle * CYCLE_LENGTH + step;
                columns[COL_S0][row] = state[0];
                columns[COL_S1][row] = state[1];
                columns[COL_S2][row] = state[2];
                columns[COL_IN0][row] = in0;
                columns[COL_IN1][row] = in1;

                if row + 1 < TRACE_LENGTH {
                    match step {
                        0 => {
                            state[0] += in0;
                            state[1] += in1;
                        }
                        1..=8 => {
                            poseidon_round(&mut state, step - 1);
                        }
                        _ => {
                            // Copy step: keep state unchanged.
                        }
                    }
                }
            }
        }

        TraceTable::init(columns)
    }

    pub fn prove_settlement(
        &mut self,
        pub_inputs: SettlementPublicInputs,
    ) -> Result<(Proof, SettlementPublicInputs), String> {
        let trace = self.build_trace(&pub_inputs);
        self.pub_inputs = Some(pub_inputs.clone());
        let proof = self
            .prove(trace)
            .map_err(|e| format!("proof generation failed: {e:?}"))?;
        self.pub_inputs = None;
        Ok((proof, pub_inputs))
    }
}

impl Prover for SettlementProver {
    type BaseField = BaseElement;
    type Air = SettlementAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3;
    type VC = MerkleTree<Blake3>;
    type RandomCoin = DefaultRandomCoin<Blake3>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> SettlementPublicInputs {
        self.pub_inputs.clone().unwrap_or(SettlementPublicInputs {
            instruction_count: 0,
            nullifier_count: 0,
            instructions: vec![Felt::ZERO; crate::constants::MAX_INSTRUCTIONS],
            nullifiers: vec![[Felt::ZERO; 4]; crate::constants::MAX_NULLIFIERS],
            commitment: [Felt::ZERO; 4],
        })
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
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

pub fn default_proof_options() -> ProofOptions {
    ProofOptions::new(
        28,
        16,
        0,
        winterfell::FieldExtension::None,
        4,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

pub fn fast_proof_options() -> ProofOptions {
    ProofOptions::new(
        4,
        16,
        0,
        winterfell::FieldExtension::None,
        2,
        15,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::commitment_from_inputs;

    #[test]
    fn prove_and_verify_roundtrip() {
        let mut instructions = vec![Felt::ZERO; crate::constants::MAX_INSTRUCTIONS];
        instructions[0] = Felt::new(10);
        let mut nullifiers = vec![[Felt::ZERO; 4]; crate::constants::MAX_NULLIFIERS];
        nullifiers[0][0] = Felt::new(22);

        let pub_inputs = SettlementPublicInputs {
            instruction_count: 1,
            nullifier_count: 1,
            instructions,
            nullifiers,
            commitment: [Felt::ZERO; 4],
        };
        let inputs = pub_inputs.input_elements();
        let commitment = commitment_from_inputs(&inputs);
        let mut pub_inputs = pub_inputs;
        pub_inputs.commitment = commitment;

        let mut prover = SettlementProver::with_fast_options();
        let (proof, pub_inputs) = prover.prove_settlement(pub_inputs).expect("proof");

        let acceptable = winterfell::AcceptableOptions::OptionSet(vec![fast_proof_options()]);
        let result = winterfell::verify::<
            SettlementAir,
            Blake3,
            DefaultRandomCoin<Blake3>,
            MerkleTree<Blake3>,
        >(proof, pub_inputs, &acceptable);
        assert!(result.is_ok());
    }

    #[test]
    fn tamper_rejects_commitment() {
        let instructions = vec![Felt::ZERO; crate::constants::MAX_INSTRUCTIONS];
        let nullifiers = vec![[Felt::ZERO; 4]; crate::constants::MAX_NULLIFIERS];

        let mut pub_inputs = SettlementPublicInputs {
            instruction_count: 0,
            nullifier_count: 0,
            instructions,
            nullifiers,
            commitment: [Felt::ZERO; 4],
        };
        let inputs = pub_inputs.input_elements();
        pub_inputs.commitment = commitment_from_inputs(&inputs);

        let mut prover = SettlementProver::with_fast_options();
        let (proof, pub_inputs) = prover.prove_settlement(pub_inputs).expect("proof");

        let mut tampered = pub_inputs.clone();
        tampered.commitment[0] += Felt::ONE;

        let acceptable = winterfell::AcceptableOptions::OptionSet(vec![fast_proof_options()]);
        let result = winterfell::verify::<
            SettlementAir,
            Blake3,
            DefaultRandomCoin<Blake3>,
            MerkleTree<Blake3>,
        >(proof, tampered, &acceptable);
        assert!(result.is_err());
    }
}
