//! Plonky3 prover for settlement commitments.

use p3_goldilocks::Goldilocks;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed};

use crate::constants::{
    ABSORB_CYCLES, INPUT_PAIRS_PER_TRACE, PADDED_INPUT_COUNT, SETTLEMENT_DOMAIN_TAG, TRACE_LENGTH,
};
use crate::p3_air::{
    SettlementAirP3, SettlementPublicInputsP3, COL_IN0, COL_IN1, COL_S0, COL_S1, COL_S2,
    TRACE_WIDTH,
};
use transaction_circuit::p3_config::{default_config, TransactionProofP3};
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
            RowMajorMatrix::new(vec![Val::ZERO; TRACE_LENGTH * TRACE_WIDTH], TRACE_WIDTH);
        let mut state = [
            Val::from_u64(SETTLEMENT_DOMAIN_TAG) + inputs[0],
            inputs[1],
            Val::ONE,
        ];

        for cycle in 0..INPUT_PAIRS_PER_TRACE {
            let pair_index = cycle + 1;
            let (in0, in1) = if pair_index < ABSORB_CYCLES {
                (inputs[2 * pair_index], inputs[2 * pair_index + 1])
            } else {
                    (Val::ZERO, Val::ZERO)
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

        trace
    }

    pub fn prove(
        &self,
        trace: RowMajorMatrix<Val>,
        pub_inputs: &SettlementPublicInputsP3,
    ) -> SettlementProofP3 {
        let config = default_config();
        let degree_bits = trace.height().ilog2() as usize;
        let (prep_prover, _) =
            setup_preprocessed(&config.config, &SettlementAirP3, degree_bits)
                .expect("SettlementAirP3 preprocessed trace missing");
        prove_with_preprocessed(
            &config.config,
            &SettlementAirP3,
            trace,
            &pub_inputs.to_vec(),
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
