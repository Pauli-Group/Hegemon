//! Disclosure circuit prover.

use winter_crypto::hashers::Blake3_256;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement},
    matrix::ColMatrix,
    AuxRandElements, CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions,
    ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

use crate::air::{
    commitment_row, DisclosureAir, DisclosurePublicInputs, COL_DOMAIN, COL_IN0, COL_IN1, COL_IN2,
    COL_IN3, COL_IN4, COL_IN5, COL_RESET, COL_S0,
};
use crate::constants::{
    CYCLE_LENGTH, INPUT_CHUNKS, NOTE_DOMAIN_TAG, POSEIDON2_RATE, POSEIDON2_STEPS, POSEIDON2_WIDTH,
    TOTAL_CYCLES, TRACE_LENGTH, TRACE_WIDTH,
};
use crate::poseidon2::poseidon2_step;
use crate::{DisclosureCircuitError, PaymentDisclosureClaim, PaymentDisclosureWitness};

type Blake3 = Blake3_256<BaseElement>;

#[derive(Clone, Copy, Debug)]
struct CycleSpec {
    reset: bool,
    domain: u64,
    inputs: [BaseElement; POSEIDON2_RATE],
}

pub struct DisclosureProver {
    options: ProofOptions,
}

impl DisclosureProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    pub fn with_defaults() -> Self {
        Self::new(default_proof_options())
    }

    pub fn build_trace(
        &self,
        claim: &PaymentDisclosureClaim,
        witness: &PaymentDisclosureWitness,
    ) -> Result<TraceTable<BaseElement>, DisclosureCircuitError> {
        let inputs = commitment_inputs(claim, witness);
        let expected_len = 2 + 4 + 4 + 4;
        if inputs.len() != expected_len {
            return Err(DisclosureCircuitError::InvalidWitness(
                "commitment input length mismatch",
            ));
        }

        let mut cycle_specs = Vec::with_capacity(INPUT_CHUNKS);
        for (idx, chunk) in inputs.chunks(POSEIDON2_RATE).enumerate() {
            let reset = idx == 0;
            let domain = if reset { NOTE_DOMAIN_TAG } else { 0 };
            let mut in_values = [BaseElement::ZERO; POSEIDON2_RATE];
            for (pos, value) in chunk.iter().enumerate() {
                in_values[pos] = *value;
            }
            cycle_specs.push(CycleSpec {
                reset,
                domain,
                inputs: in_values,
            });
        }
        if cycle_specs.len() != INPUT_CHUNKS {
            return Err(DisclosureCircuitError::InvalidWitness(
                "commitment input chunk mismatch",
            ));
        }

        let trace_len = TRACE_LENGTH;
        let mut trace = vec![vec![BaseElement::ZERO; trace_len]; TRACE_WIDTH];

        let mut prev_state = [BaseElement::ZERO; POSEIDON2_WIDTH];

        for cycle in 0..TOTAL_CYCLES {
            let cycle_start = cycle * CYCLE_LENGTH;
            let state_start = if cycle == 0 {
                prev_state
            } else {
                let spec = cycle_specs.get(cycle - 1).copied().unwrap_or(CycleSpec {
                    reset: false,
                    domain: 0,
                    inputs: [BaseElement::ZERO; POSEIDON2_RATE],
                });
                if spec.reset {
                    let mut state = [BaseElement::ZERO; POSEIDON2_WIDTH];
                    state[0] = BaseElement::new(spec.domain) + spec.inputs[0];
                    for idx in 1..POSEIDON2_RATE {
                        state[idx] = spec.inputs[idx];
                    }
                    state[POSEIDON2_WIDTH - 1] = BaseElement::ONE;
                    state
                } else {
                    let mut state = prev_state;
                    for idx in 0..POSEIDON2_RATE {
                        state[idx] += spec.inputs[idx];
                    }
                    state
                }
            };

            let mut state = state_start;
            for step in 0..POSEIDON2_STEPS {
                let row = cycle_start + step;
                for idx in 0..POSEIDON2_WIDTH {
                    trace[COL_S0 + idx][row] = state[idx];
                }
                poseidon2_step(&mut state, step);
            }

            for step in POSEIDON2_STEPS..CYCLE_LENGTH {
                let row = cycle_start + step;
                for idx in 0..POSEIDON2_WIDTH {
                    trace[COL_S0 + idx][row] = state[idx];
                }
            }

            prev_state = state;

            let end_row = cycle_start + (CYCLE_LENGTH - 1);
            if cycle < INPUT_CHUNKS {
                let next_spec = cycle_specs[cycle];
                for idx in 0..POSEIDON2_RATE {
                    trace[COL_IN0 + idx][end_row] = next_spec.inputs[idx];
                }
                trace[COL_RESET][end_row] = if next_spec.reset {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                };
                trace[COL_DOMAIN][end_row] = if next_spec.reset {
                    BaseElement::new(next_spec.domain)
                } else {
                    BaseElement::ZERO
                };
            } else {
                for idx in 0..POSEIDON2_RATE {
                    trace[COL_IN0 + idx][end_row] = BaseElement::ZERO;
                }
                trace[COL_RESET][end_row] = BaseElement::ZERO;
                trace[COL_DOMAIN][end_row] = BaseElement::ZERO;
            }
        }

        Ok(TraceTable::init(trace))
    }
}

impl Default for DisclosureProver {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl Prover for DisclosureProver {
    type BaseField = BaseElement;
    type Air = DisclosureAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3;
    type VC = MerkleTree<Blake3>;
    type RandomCoin = DefaultRandomCoin<Blake3>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, DisclosureAir, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> DisclosurePublicInputs {
        let row_inputs = crate::air::absorb_row(0);
        let value = trace.get(COL_IN0, row_inputs);
        let asset_id = trace.get(COL_IN1, row_inputs);
        let pk0 = trace.get(COL_IN2, row_inputs);
        let pk1 = trace.get(COL_IN3, row_inputs);
        let pk2 = trace.get(COL_IN4, row_inputs);
        let pk3 = trace.get(COL_IN5, row_inputs);
        let row = commitment_row();
        let commitment = [
            trace.get(COL_S0, row),
            trace.get(COL_S0 + 1, row),
            trace.get(COL_S0 + 2, row),
            trace.get(COL_S0 + 3, row),
            trace.get(COL_S0 + 4, row),
            trace.get(COL_S0 + 5, row),
        ];

        DisclosurePublicInputs {
            value,
            asset_id,
            pk_recipient: [pk0, pk1, pk2, pk3],
            commitment,
        }
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

fn commitment_inputs(
    claim: &PaymentDisclosureClaim,
    witness: &PaymentDisclosureWitness,
) -> Vec<BaseElement> {
    let mut inputs = Vec::with_capacity(2 + 4 + 4 + 4);
    inputs.push(BaseElement::new(claim.value));
    inputs.push(BaseElement::new(claim.asset_id));
    inputs.extend(bytes32_to_felts(&claim.pk_recipient));
    inputs.extend(bytes32_to_felts(&witness.rho));
    inputs.extend(bytes32_to_felts(&witness.r));
    inputs
}

fn bytes32_to_felts(bytes: &[u8; 32]) -> [BaseElement; 4] {
    let mut out = [BaseElement::ZERO; 4];
    for (idx, chunk) in bytes.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        out[idx] = BaseElement::new(u64::from_be_bytes(buf));
    }
    out
}

fn default_proof_options() -> ProofOptions {
    ProofOptions::new(
        32,
        8,
        0,
        winterfell::FieldExtension::None,
        4,
        31,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    )
}
