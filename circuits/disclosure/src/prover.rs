//! Plonky3 prover for disclosure proofs.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{get_log_num_quotient_chunks, prove_with_preprocessed, setup_preprocessed};

use crate::air::{
    DisclosureAirP3, DisclosurePublicInputsP3, PREPROCESSED_WIDTH, COL_DOMAIN, COL_IN0, COL_RESET,
    COL_S0,
};
use crate::constants::{
    CYCLE_LENGTH, INPUT_CHUNKS, NOTE_DOMAIN_TAG, POSEIDON2_RATE, POSEIDON2_STEPS,
    POSEIDON2_WIDTH, TOTAL_CYCLES, TRACE_LENGTH, TRACE_WIDTH,
};
use crate::{DisclosureCircuitError, PaymentDisclosureClaim, PaymentDisclosureWitness};
use transaction_core::hashing_pq::bytes48_to_felts;
use transaction_core::poseidon2::poseidon2_step;
use transaction_core::p3_config::{
    config_with_fri, FRI_LOG_BLOWUP, FRI_NUM_QUERIES, TransactionProofP3,
};

pub type Val = Goldilocks;
pub type DisclosureProofP3 = TransactionProofP3;

#[derive(Clone, Copy, Debug)]
struct CycleSpec {
    reset: bool,
    domain: u64,
    inputs: [Val; POSEIDON2_RATE],
}

pub struct DisclosureProverP3;

impl DisclosureProverP3 {
    pub fn new() -> Self {
        Self
    }

    pub fn build_trace(
        &self,
        claim: &PaymentDisclosureClaim,
        witness: &PaymentDisclosureWitness,
    ) -> Result<RowMajorMatrix<Val>, DisclosureCircuitError> {
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
            let mut in_values = [Val::ZERO; POSEIDON2_RATE];
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
        let mut trace =
            RowMajorMatrix::new(vec![Val::ZERO; trace_len * TRACE_WIDTH], TRACE_WIDTH);

        let mut prev_state = [Val::ZERO; POSEIDON2_WIDTH];

        for cycle in 0..TOTAL_CYCLES {
            let cycle_start = cycle * CYCLE_LENGTH;
            let state_start = if cycle == 0 {
                prev_state
            } else {
                let spec = cycle_specs.get(cycle - 1).copied().unwrap_or(CycleSpec {
                    reset: false,
                    domain: 0,
                    inputs: [Val::ZERO; POSEIDON2_RATE],
                });
                if spec.reset {
                    let mut state = [Val::ZERO; POSEIDON2_WIDTH];
                    state[0] = Val::from_u64(spec.domain) + spec.inputs[0];
                    for idx in 1..POSEIDON2_RATE {
                        state[idx] = spec.inputs[idx];
                    }
                    state[POSEIDON2_WIDTH - 1] = Val::ONE;
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
                let row_slice = trace.row_mut(row);
                for idx in 0..POSEIDON2_WIDTH {
                    row_slice[COL_S0 + idx] = state[idx];
                }
                poseidon2_step(&mut state, step);
            }

            for step in POSEIDON2_STEPS..CYCLE_LENGTH {
                let row = cycle_start + step;
                let row_slice = trace.row_mut(row);
                for idx in 0..POSEIDON2_WIDTH {
                    row_slice[COL_S0 + idx] = state[idx];
                }
            }

            prev_state = state;

            let end_row = cycle_start + (CYCLE_LENGTH - 1);
            let row_slice = trace.row_mut(end_row);
            if cycle < INPUT_CHUNKS {
                let next_spec = cycle_specs[cycle];
                for idx in 0..POSEIDON2_RATE {
                    row_slice[COL_IN0 + idx] = next_spec.inputs[idx];
                }
                row_slice[COL_RESET] = if next_spec.reset { Val::ONE } else { Val::ZERO };
                row_slice[COL_DOMAIN] = if next_spec.reset {
                    Val::from_u64(next_spec.domain)
                } else {
                    Val::ZERO
                };
            } else {
                for idx in 0..POSEIDON2_RATE {
                    row_slice[COL_IN0 + idx] = Val::ZERO;
                }
                row_slice[COL_RESET] = Val::ZERO;
                row_slice[COL_DOMAIN] = Val::ZERO;
            }
        }

        Ok(trace)
    }

    pub fn public_inputs(
        &self,
        claim: &PaymentDisclosureClaim,
    ) -> Result<DisclosurePublicInputsP3, DisclosureCircuitError> {
        let commitment = bytes48_to_felts(&claim.commitment)
            .ok_or(DisclosureCircuitError::NonCanonicalCommitment)?;

        Ok(DisclosurePublicInputsP3 {
            value: Val::from_u64(claim.value),
            asset_id: Val::from_u64(claim.asset_id),
            pk_recipient: bytes32_to_felts(&claim.pk_recipient),
            commitment,
        })
    }

    pub fn prove(
        &self,
        trace: RowMajorMatrix<Val>,
        pub_inputs: &DisclosurePublicInputsP3,
    ) -> DisclosureProofP3 {
        let pub_inputs_vec = pub_inputs.to_vec();
        let degree_bits = trace.height().ilog2() as usize;
        let air = DisclosureAirP3::new(trace.height());
        let log_chunks = get_log_num_quotient_chunks::<Val, _>(
            &air,
            PREPROCESSED_WIDTH,
            pub_inputs_vec.len(),
            0,
        );
        let log_blowup = FRI_LOG_BLOWUP.max(log_chunks);
        let config = config_with_fri(log_blowup, FRI_NUM_QUERIES);
        let (prep_prover, _) =
            setup_preprocessed(&config.config, &air, degree_bits)
                .expect("DisclosureAirP3 preprocessed trace missing");
        prove_with_preprocessed(
            &config.config,
            &air,
            trace,
            &pub_inputs_vec,
            Some(&prep_prover),
        )
    }

    pub fn prove_bytes(
        &self,
        trace: RowMajorMatrix<Val>,
        pub_inputs: &DisclosurePublicInputsP3,
    ) -> Result<Vec<u8>, DisclosureCircuitError> {
        let proof = self.prove(trace, pub_inputs);
        bincode::serialize(&proof)
            .map_err(|_| DisclosureCircuitError::ProofGenerationFailed("serialize".into()))
    }
}

fn commitment_inputs(
    claim: &PaymentDisclosureClaim,
    witness: &PaymentDisclosureWitness,
) -> Vec<Val> {
    let mut inputs = Vec::with_capacity(2 + 4 + 4 + 4);
    inputs.push(Val::from_u64(claim.value));
    inputs.push(Val::from_u64(claim.asset_id));
    inputs.extend(bytes32_to_felts(&claim.pk_recipient));
    inputs.extend(bytes32_to_felts(&witness.rho));
    inputs.extend(bytes32_to_felts(&witness.r));
    inputs
}

fn bytes32_to_felts(bytes: &[u8; 32]) -> [Val; 4] {
    let mut out = [Val::ZERO; 4];
    for (idx, chunk) in bytes.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        out[idx] = Val::from_u64(u64::from_be_bytes(buf));
    }
    out
}
