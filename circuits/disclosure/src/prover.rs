//! Disclosure circuit prover.

use winter_crypto::hashers::Blake3_256;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement},
    matrix::ColMatrix,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions,
    ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

use crate::air::{DisclosureAir, DisclosurePublicInputs, COL_DOMAIN, COL_IN0, COL_IN1, COL_RESET, COL_S0, COL_S1, COL_S2};
use crate::constants::{CYCLE_LENGTH, INPUT_PAIRS, NOTE_DOMAIN_TAG, POSEIDON_ROUNDS, TOTAL_CYCLES, TRACE_LENGTH, TRACE_WIDTH};
use crate::{DisclosureCircuitError, PaymentDisclosureClaim, PaymentDisclosureWitness};

use transaction_core::stark_air::poseidon_round;

type Blake3 = Blake3_256<BaseElement>;

#[derive(Clone, Copy, Debug)]
struct CycleSpec {
    reset: bool,
    domain: u64,
    in0: BaseElement,
    in1: BaseElement,
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

    pub fn get_public_inputs(
        &self,
        claim: &PaymentDisclosureClaim,
    ) -> Result<DisclosurePublicInputs, DisclosureCircuitError> {
        let commitment = transaction_core::hashing::bytes32_to_felt(&claim.commitment)
            .ok_or(DisclosureCircuitError::NonCanonicalCommitment)?;
        Ok(DisclosurePublicInputs {
            value: BaseElement::new(claim.value),
            asset_id: BaseElement::new(claim.asset_id),
            pk_recipient: bytes32_to_felts(&claim.pk_recipient),
            commitment,
        })
    }

    pub fn build_trace(
        &self,
        claim: &PaymentDisclosureClaim,
        witness: &PaymentDisclosureWitness,
    ) -> Result<TraceTable<BaseElement>, DisclosureCircuitError> {
        let inputs = commitment_inputs(claim, witness);
        if inputs.len() != INPUT_PAIRS * 2 {
            return Err(DisclosureCircuitError::InvalidWitness(
                "commitment input length mismatch",
            ));
        }

        let mut cycle_specs = Vec::with_capacity(INPUT_PAIRS);
        for (idx, chunk) in inputs.chunks(2).enumerate() {
            let reset = idx == 0;
            let domain = if reset { NOTE_DOMAIN_TAG } else { 0 };
            cycle_specs.push(CycleSpec {
                reset,
                domain,
                in0: chunk[0],
                in1: chunk[1],
            });
        }

        let trace_len = TRACE_LENGTH;
        let mut trace = vec![vec![BaseElement::ZERO; trace_len]; TRACE_WIDTH];

        let mut prev_state = [BaseElement::ZERO; 3];

        for cycle in 0..TOTAL_CYCLES {
            let cycle_start = cycle * CYCLE_LENGTH;
            let state_start = if cycle == 0 {
                prev_state
            } else {
                let spec = cycle_specs.get(cycle - 1).copied().unwrap_or(CycleSpec {
                    reset: false,
                    domain: 0,
                    in0: BaseElement::ZERO,
                    in1: BaseElement::ZERO,
                });
                if spec.reset {
                    [
                        BaseElement::new(spec.domain) + spec.in0,
                        spec.in1,
                        BaseElement::ONE,
                    ]
                } else {
                    [
                        prev_state[0] + spec.in0,
                        prev_state[1] + spec.in1,
                        prev_state[2],
                    ]
                }
            };

            let mut state = state_start;
            for round in 0..POSEIDON_ROUNDS {
                let row = cycle_start + round;
                trace[COL_S0][row] = state[0];
                trace[COL_S1][row] = state[1];
                trace[COL_S2][row] = state[2];
                poseidon_round(&mut state, round);
            }

            for step in POSEIDON_ROUNDS..CYCLE_LENGTH {
                let row = cycle_start + step;
                trace[COL_S0][row] = state[0];
                trace[COL_S1][row] = state[1];
                trace[COL_S2][row] = state[2];
            }

            prev_state = state;

            let end_row = cycle_start + (CYCLE_LENGTH - 1);
            if cycle < INPUT_PAIRS {
                let next_spec = cycle_specs[cycle];
                trace[COL_IN0][end_row] = next_spec.in0;
                trace[COL_IN1][end_row] = next_spec.in1;
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
                trace[COL_IN0][end_row] = BaseElement::ZERO;
                trace[COL_IN1][end_row] = BaseElement::ZERO;
                trace[COL_RESET][end_row] = BaseElement::ZERO;
                trace[COL_DOMAIN][end_row] = BaseElement::ZERO;
            }
        }

        Ok(TraceTable::init(trace))
    }

    pub fn prove_disclosure(
        &self,
        claim: &PaymentDisclosureClaim,
        witness: &PaymentDisclosureWitness,
    ) -> Result<winterfell::Proof, DisclosureCircuitError> {
        let trace = self.build_trace(claim, witness)?;
        self.prove(trace)
            .map_err(|e| DisclosureCircuitError::ProofGenerationFailed(format!("{:?}", e)))
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
        let value = trace.get(COL_IN0, crate::air::absorb_row(0));
        let asset_id = trace.get(COL_IN1, crate::air::absorb_row(0));
        let pk0 = trace.get(COL_IN0, crate::air::absorb_row(1));
        let pk1 = trace.get(COL_IN1, crate::air::absorb_row(1));
        let pk2 = trace.get(COL_IN0, crate::air::absorb_row(2));
        let pk3 = trace.get(COL_IN1, crate::air::absorb_row(2));
        let commitment = trace.get(COL_S0, crate::air::commitment_row());

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
    ) -> Self::TraceLde<E> {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }

    fn new_trace_poly_table<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        trace_lde: &Self::TraceLde<E>,
    ) -> TracePolyTable<E> {
        TracePolyTable::new(trace_info, trace_lde)
    }
}

fn commitment_inputs(
    claim: &PaymentDisclosureClaim,
    witness: &PaymentDisclosureWitness,
) -> Vec<BaseElement> {
    let mut inputs = Vec::with_capacity(INPUT_PAIRS * 2);
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
