//! Plonky3 prover for batch transaction proofs.

use p3_goldilocks::Goldilocks;
use p3_field::AbstractField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::prove;

use crate::error::BatchCircuitError;
use crate::p3_air::{
    BatchPublicInputsP3, BatchTransactionAirP3, COL_BATCH_CYCLE_BIT10, COL_BATCH_CYCLE_BIT11,
    COL_BATCH_CYCLE_BIT12, COL_BATCH_CYCLE_BIT9, TRACE_WIDTH,
};
use crate::public_inputs::{MAX_BATCH_SIZE, MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::hashing::{bytes32_to_felts, nullifier, prf_key, HashFelt};
use transaction_circuit::p3_config::{default_config, new_challenger, TransactionProofP3};
use transaction_circuit::p3_prover::TransactionProverP3;
use transaction_circuit::TransactionWitness;
use transaction_core::dimensions::{batch_trace_rows, slot_start_row, validate_batch_size, ROWS_PER_TX};
use transaction_core::p3_air::{CYCLE_LENGTH, COL_CYCLE_BIT0, COL_FEE, COL_STEP_BIT0, TRACE_WIDTH as TX_TRACE_WIDTH};

type Val = Goldilocks;

pub type BatchProofP3 = TransactionProofP3;

pub struct BatchTransactionProverP3;

impl BatchTransactionProverP3 {
    pub fn new() -> Self {
        Self
    }

    pub fn build_trace(
        &self,
        witnesses: &[TransactionWitness],
    ) -> Result<RowMajorMatrix<Val>, BatchCircuitError> {
        let batch_size = witnesses.len();
        validate_batch_size(batch_size)
            .map_err(|_| BatchCircuitError::InvalidBatchSize(batch_size))?;

        if batch_size == 0 {
            return Err(BatchCircuitError::EmptyBatch);
        }

        let anchor = witnesses[0].merkle_root;
        for witness in witnesses.iter().skip(1) {
            if witness.merkle_root != anchor {
                return Err(BatchCircuitError::AnchorMismatch);
            }
        }

        for (idx, witness) in witnesses.iter().enumerate() {
            witness
                .validate()
                .map_err(|e| BatchCircuitError::InvalidWitness {
                    index: idx,
                    reason: e.to_string(),
                })?;
        }

        let trace_len = batch_trace_rows(batch_size);
        let mut trace = RowMajorMatrix::new(vec![Val::zero(); trace_len * TRACE_WIDTH], TRACE_WIDTH);
        let single_prover = TransactionProverP3::new();

        for (tx_idx, witness) in witnesses.iter().enumerate() {
            let single_trace = single_prover
                .build_trace(witness)
                .map_err(|e| BatchCircuitError::TraceBuildError(format!("TX {tx_idx}: {e}")))?;
            let offset = slot_start_row(tx_idx);
            let rows = single_trace.height().min(ROWS_PER_TX);
            for row in 0..rows {
                let dst_row = offset + row;
                let dst_start = dst_row * TRACE_WIDTH;
                let src_start = row * TX_TRACE_WIDTH;
                trace.values[dst_start..dst_start + TX_TRACE_WIDTH]
                    .copy_from_slice(&single_trace.values[src_start..src_start + TX_TRACE_WIDTH]);
            }
        }

        let total_fee: u64 = witnesses.iter().map(|w| w.fee).sum();
        let last_row = trace_len.saturating_sub(1);
        trace.row_mut(last_row)[COL_FEE] = Val::from_canonical_u64(total_fee);

        for row in 0..trace_len {
            let step = row % CYCLE_LENGTH;
            let cycle = row / CYCLE_LENGTH;
            let row_slice = trace.row_mut(row);
            for bit in 0..6 {
                let is_one = ((step >> bit) & 1) == 1;
                row_slice[COL_STEP_BIT0 + bit] = Val::from_bool(is_one);
            }
            for bit in 0..9 {
                let is_one = ((cycle >> bit) & 1) == 1;
                row_slice[COL_CYCLE_BIT0 + bit] = Val::from_bool(is_one);
            }
            row_slice[COL_BATCH_CYCLE_BIT9] = Val::from_bool(((cycle >> 9) & 1) == 1);
            row_slice[COL_BATCH_CYCLE_BIT10] = Val::from_bool(((cycle >> 10) & 1) == 1);
            row_slice[COL_BATCH_CYCLE_BIT11] = Val::from_bool(((cycle >> 11) & 1) == 1);
            row_slice[COL_BATCH_CYCLE_BIT12] = Val::from_bool(((cycle >> 12) & 1) == 1);
        }

        Ok(trace)
    }

    pub fn public_inputs(
        &self,
        witnesses: &[TransactionWitness],
    ) -> Result<BatchPublicInputsP3, BatchCircuitError> {
        let batch_size = witnesses.len();
        validate_batch_size(batch_size)
            .map_err(|_| BatchCircuitError::InvalidBatchSize(batch_size))?;

        if batch_size == 0 {
            return Err(BatchCircuitError::EmptyBatch);
        }

        let anchor = witnesses[0].merkle_root;
        for witness in witnesses.iter().skip(1) {
            if witness.merkle_root != anchor {
                return Err(BatchCircuitError::AnchorMismatch);
            }
        }

        let anchor = bytes32_to_felts(&anchor)
            .map(hash_to_gl)
            .ok_or_else(|| BatchCircuitError::InvalidPublicInputs("anchor not canonical".into()))?;

        let mut nullifiers = Vec::with_capacity(MAX_BATCH_SIZE * MAX_INPUTS);
        let mut commitments = Vec::with_capacity(MAX_BATCH_SIZE * MAX_OUTPUTS);
        let mut total_fee = 0u64;

        for witness in witnesses {
            let prf = prf_key(&witness.sk_spend);
            for (i, input) in witness.inputs.iter().enumerate().take(MAX_INPUTS) {
                nullifiers.push(hash_to_gl(nullifier(prf, &input.note.rho, input.position)));
            }
            for _ in witness.inputs.len()..MAX_INPUTS {
                nullifiers.push([Val::zero(); 4]);
            }

            for (i, output) in witness.outputs.iter().enumerate().take(MAX_OUTPUTS) {
                commitments.push(hash_to_gl(output.note.commitment()));
                if i + 1 >= MAX_OUTPUTS {
                    break;
                }
            }
            for _ in witness.outputs.len()..MAX_OUTPUTS {
                commitments.push([Val::zero(); 4]);
            }

            total_fee += witness.fee;
        }

        for _ in batch_size..MAX_BATCH_SIZE {
            for _ in 0..MAX_INPUTS {
                nullifiers.push([Val::zero(); 4]);
            }
            for _ in 0..MAX_OUTPUTS {
                commitments.push([Val::zero(); 4]);
            }
        }

        let mut tx_active = Vec::with_capacity(MAX_BATCH_SIZE);
        for idx in 0..MAX_BATCH_SIZE {
            tx_active.push(Val::from_bool(idx < batch_size));
        }

        Ok(BatchPublicInputsP3 {
            batch_size: batch_size as u32,
            anchor,
            tx_active,
            nullifiers,
            commitments,
            total_fee: Val::from_canonical_u64(total_fee),
            circuit_version: 1,
        })
    }

    pub fn prove(
        &self,
        trace: RowMajorMatrix<Val>,
        pub_inputs: &BatchPublicInputsP3,
    ) -> BatchProofP3 {
        let config = default_config();
        let mut challenger = new_challenger(&config.perm);
        prove(
            &config.config,
            &BatchTransactionAirP3,
            &mut challenger,
            trace,
            &pub_inputs.to_vec(),
        )
    }

    pub fn prove_bytes(
        &self,
        trace: RowMajorMatrix<Val>,
        pub_inputs: &BatchPublicInputsP3,
    ) -> Result<Vec<u8>, BatchCircuitError> {
        let proof = self.prove(trace, pub_inputs);
        bincode::serialize(&proof).map_err(|_| BatchCircuitError::InvalidProofFormat)
    }

    pub fn prove_batch(
        &self,
        witnesses: &[TransactionWitness],
    ) -> Result<(BatchProofP3, BatchPublicInputsP3), BatchCircuitError> {
        let trace = self.build_trace(witnesses)?;
        let pub_inputs = self.public_inputs(witnesses)?;
        Ok((self.prove(trace, &pub_inputs), pub_inputs))
    }
}

fn hash_to_gl(hash: HashFelt) -> [Val; 4] {
    [
        Val::from_canonical_u64(hash[0].as_int()),
        Val::from_canonical_u64(hash[1].as_int()),
        Val::from_canonical_u64(hash[2].as_int()),
        Val::from_canonical_u64(hash[3].as_int()),
    ]
}
