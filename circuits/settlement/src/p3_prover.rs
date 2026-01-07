//! Plonky3 prover for settlement commitments.

use p3_goldilocks::Goldilocks;
use p3_field::AbstractField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::prove;

use crate::constants::{
    ABSORB_CYCLES, INPUT_PAIRS_PER_TRACE, PADDED_INPUT_COUNT, SETTLEMENT_DOMAIN_TAG, TRACE_LENGTH,
};
use crate::p3_air::{
    SettlementAirP3, SettlementPublicInputsP3, COL_CYCLE_BIT0, COL_IN0, COL_IN1, COL_S0, COL_S1,
    COL_S2, COL_STEP_BIT0, TRACE_WIDTH,
};
use transaction_circuit::p3_config::{default_config, new_challenger, TransactionProofP3};
use transaction_core::constants::POSEIDON_ROUNDS;
use transaction_core::p3_air::{poseidon_round, CYCLE_LENGTH};

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
            RowMajorMatrix::new(vec![Val::zero(); TRACE_LENGTH * TRACE_WIDTH], TRACE_WIDTH);
        let mut state = [
            Val::from_canonical_u64(SETTLEMENT_DOMAIN_TAG) + inputs[0],
            inputs[1],
            Val::one(),
        ];

        for cycle in 0..INPUT_PAIRS_PER_TRACE {
            let pair_index = cycle + 1;
            let (in0, in1) = if pair_index < ABSORB_CYCLES {
                (inputs[2 * pair_index], inputs[2 * pair_index + 1])
            } else {
                (Val::zero(), Val::zero())
            };
            for step in 0..CYCLE_LENGTH {
                let row = cycle * CYCLE_LENGTH + step;
                let row_slice = trace.row_mut(row);
                row_slice[COL_S0] = state[0];
                row_slice[COL_S1] = state[1];
                row_slice[COL_S2] = state[2];
                row_slice[COL_IN0] = in0;
                row_slice[COL_IN1] = in1;

                if row + 1 < TRACE_LENGTH {
                    if step < POSEIDON_ROUNDS {
                        poseidon_round(&mut state, step);
                    } else {
                        state[0] += in0;
                        state[1] += in1;
                    }
                }
            }
        }

        for row in 0..TRACE_LENGTH {
            let step = row % CYCLE_LENGTH;
            let cycle = row / CYCLE_LENGTH;
            let row_slice = trace.row_mut(row);
            for bit in 0..6 {
                let is_one = ((step >> bit) & 1) == 1;
                row_slice[COL_STEP_BIT0 + bit] = Val::from_bool(is_one);
            }
            for bit in 0..5 {
                let is_one = ((cycle >> bit) & 1) == 1;
                row_slice[COL_CYCLE_BIT0 + bit] = Val::from_bool(is_one);
            }
        }

        trace
    }

    pub fn prove(
        &self,
        trace: RowMajorMatrix<Val>,
        pub_inputs: &SettlementPublicInputsP3,
    ) -> SettlementProofP3 {
        let config = default_config();
        let mut challenger = new_challenger(&config.perm);
        prove(
            &config.config,
            &SettlementAirP3,
            &mut challenger,
            trace,
            &pub_inputs.to_vec(),
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
