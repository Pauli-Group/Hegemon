//! Plonky3 prover for settlement commitments.

use p3_goldilocks::Goldilocks;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{get_log_num_quotient_chunks, prove_with_preprocessed, setup_preprocessed};

use crate::constants::{
    ABSORB_CYCLES, INPUT_CYCLES_PER_TRACE, PADDED_INPUT_COUNT, SETTLEMENT_DOMAIN_TAG, TRACE_LENGTH,
};
use crate::p3_air::{
    SettlementAirP3, SettlementPublicInputsP3, COL_IN0, COL_IN1, COL_IN2, COL_IN3, COL_IN4,
    COL_IN5, COL_S0, COL_S1, COL_S10, COL_S11, COL_S2, COL_S3, COL_S4, COL_S5, COL_S6, COL_S7,
    COL_S8, COL_S9, PREPROCESSED_WIDTH, TRACE_WIDTH,
};
use transaction_circuit::p3_config::{
    config_with_fri, FRI_LOG_BLOWUP, FRI_NUM_QUERIES, TransactionProofP3,
};
use transaction_core::constants::{POSEIDON2_RATE, POSEIDON2_STEPS, POSEIDON2_WIDTH};
use transaction_core::p3_air::CYCLE_LENGTH;
use transaction_core::poseidon2::poseidon2_step;

type Val = Goldilocks;
pub type SettlementProofP3 = TransactionProofP3;

pub struct SettlementProverP3;

impl SettlementProverP3 {
    pub fn new() -> Self {
        Self
    }

    pub fn build_trace(&self, pub_inputs: &SettlementPublicInputsP3) -> RowMajorMatrix<Val> {
        let inputs = pub_inputs.input_elements();
        debug_assert_eq!(inputs.len(), PADDED_INPUT_COUNT);

        let mut trace =
            RowMajorMatrix::new(vec![Val::ZERO; TRACE_LENGTH * TRACE_WIDTH], TRACE_WIDTH);
        let mut state = [Val::ZERO; POSEIDON2_WIDTH];
        state[0] = Val::from_u64(SETTLEMENT_DOMAIN_TAG) + inputs[0];
        state[1] = inputs[1];
        state[2] = inputs[2];
        state[3] = inputs[3];
        state[4] = inputs[4];
        state[5] = inputs[5];
        state[POSEIDON2_WIDTH - 1] = Val::ONE;

        for cycle in 0..INPUT_CYCLES_PER_TRACE {
            let (in0, in1, in2, in3, in4, in5) = if cycle < ABSORB_CYCLES {
                let base = cycle * POSEIDON2_RATE;
                (
                    inputs[base],
                    inputs[base + 1],
                    inputs[base + 2],
                    inputs[base + 3],
                    inputs[base + 4],
                    inputs[base + 5],
                )
            } else {
                (Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO)
            };
            let (next_in0, next_in1, next_in2, next_in3, next_in4, next_in5) =
                if cycle + 1 < ABSORB_CYCLES {
                    let base = (cycle + 1) * POSEIDON2_RATE;
                    (
                        inputs[base],
                        inputs[base + 1],
                        inputs[base + 2],
                        inputs[base + 3],
                        inputs[base + 4],
                        inputs[base + 5],
                    )
                } else {
                    (Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO)
                };

            for step in 0..CYCLE_LENGTH {
                let row = cycle * CYCLE_LENGTH + step;
                let row_slice = trace.row_mut(row);
                row_slice[COL_S0] = state[0];
                row_slice[COL_S1] = state[1];
                row_slice[COL_S2] = state[2];
                row_slice[COL_S3] = state[3];
                row_slice[COL_S4] = state[4];
                row_slice[COL_S5] = state[5];
                row_slice[COL_S6] = state[6];
                row_slice[COL_S7] = state[7];
                row_slice[COL_S8] = state[8];
                row_slice[COL_S9] = state[9];
                row_slice[COL_S10] = state[10];
                row_slice[COL_S11] = state[11];
                row_slice[COL_IN0] = in0;
                row_slice[COL_IN1] = in1;
                row_slice[COL_IN2] = in2;
                row_slice[COL_IN3] = in3;
                row_slice[COL_IN4] = in4;
                row_slice[COL_IN5] = in5;

                if row + 1 < TRACE_LENGTH {
                    if step < POSEIDON2_STEPS {
                        poseidon2_step(&mut state, step);
                    } else if step + 1 == CYCLE_LENGTH {
                        state[0] += next_in0;
                        state[1] += next_in1;
                        state[2] += next_in2;
                        state[3] += next_in3;
                        state[4] += next_in4;
                        state[5] += next_in5;
                    }
                }
            }
        }

        trace
    }

    pub fn prove(
        &self,
        trace: RowMajorMatrix<Val>,
        pub_inputs: &SettlementPublicInputsP3,
    ) -> SettlementProofP3 {
        let pub_inputs_vec = pub_inputs.to_vec();
        let log_chunks = get_log_num_quotient_chunks::<Val, _>(
            &SettlementAirP3,
            PREPROCESSED_WIDTH,
            pub_inputs_vec.len(),
            0,
        );
        let log_blowup = FRI_LOG_BLOWUP.max(log_chunks);
        let config = config_with_fri(log_blowup, FRI_NUM_QUERIES);
        let degree_bits = trace.height().ilog2() as usize;
        let (prep_prover, _) =
            setup_preprocessed(&config.config, &SettlementAirP3, degree_bits)
                .expect("SettlementAirP3 preprocessed trace missing");
        prove_with_preprocessed(
            &config.config,
            &SettlementAirP3,
            trace,
            &pub_inputs_vec,
            Some(&prep_prover),
        )
    }

    pub fn prove_bytes(
        &self,
        trace: RowMajorMatrix<Val>,
        pub_inputs: &SettlementPublicInputsP3,
    ) -> Result<Vec<u8>, String> {
        let proof = self.prove(trace, pub_inputs);
        bincode::serialize(&proof).map_err(|_| "failed to serialize Plonky3 proof".into())
    }

    pub fn prove_settlement(
        &self,
        pub_inputs: SettlementPublicInputsP3,
    ) -> Result<(SettlementProofP3, SettlementPublicInputsP3), String> {
        let trace = self.build_trace(&pub_inputs);
        let proof = self.prove(trace, &pub_inputs);
        Ok((proof, pub_inputs))
    }
}
