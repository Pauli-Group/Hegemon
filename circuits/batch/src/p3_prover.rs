//! Plonky3 prover for batch transaction proofs.

use p3_goldilocks::Goldilocks;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed};

use crate::error::BatchCircuitError;
use crate::p3_air::{BatchPublicInputsP3, BatchTransactionAirP3, TRACE_WIDTH};
use crate::constants::{MAX_BATCH_SIZE, MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::hashing_pq::{bytes48_to_felts, note_commitment, nullifier, prf_key};
use transaction_circuit::p3_config::{default_config, TransactionProofP3};
use transaction_circuit::p3_prover::TransactionProverP3;
use transaction_circuit::TransactionWitness;
use transaction_core::dimensions::{batch_trace_rows, slot_start_row, validate_batch_size, ROWS_PER_TX};
use transaction_core::p3_air::{COL_FEE, TRACE_WIDTH as TX_TRACE_WIDTH};

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
        let mut trace =
            RowMajorMatrix::new(vec![Val::ZERO; trace_len * TRACE_WIDTH], TRACE_WIDTH);
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
        trace.row_mut(last_row)[COL_FEE] = Val::from_u64(total_fee);

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

        let anchor = bytes48_to_felts(&anchor)
            .ok_or_else(|| BatchCircuitError::InvalidPublicInputs("anchor not canonical".into()))?;

        let mut nullifiers = Vec::with_capacity(MAX_BATCH_SIZE * MAX_INPUTS);
        let mut commitments = Vec::with_capacity(MAX_BATCH_SIZE * MAX_OUTPUTS);
        let mut total_fee = 0u64;

        for witness in witnesses {
            let prf = prf_key(&witness.sk_spend);
            for input in witness.inputs.iter().take(MAX_INPUTS) {
                nullifiers.push(nullifier(prf, &input.note.rho, input.position));
            }
            for _ in witness.inputs.len()..MAX_INPUTS {
                nullifiers.push([Val::ZERO; 6]);
            }

            for output in witness.outputs.iter().take(MAX_OUTPUTS) {
                commitments.push(note_commitment(
                    output.note.value,
                    output.note.asset_id,
                    &output.note.pk_recipient,
                    &output.note.rho,
                    &output.note.r,
                ));
            }
            for _ in witness.outputs.len()..MAX_OUTPUTS {
                commitments.push([Val::ZERO; 6]);
            }

            total_fee += witness.fee;
        }

        for _ in batch_size..MAX_BATCH_SIZE {
            for _ in 0..MAX_INPUTS {
                nullifiers.push([Val::ZERO; 6]);
            }
            for _ in 0..MAX_OUTPUTS {
                commitments.push([Val::ZERO; 6]);
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
            total_fee: Val::from_u64(total_fee),
            circuit_version: 1,
        })
    }

    pub fn prove(
        &self,
        trace: RowMajorMatrix<Val>,
        pub_inputs: &BatchPublicInputsP3,
    ) -> BatchProofP3 {
        let config = default_config();
        let degree_bits = trace.height().ilog2() as usize;
        let air = BatchTransactionAirP3::new(trace.height());
        let (prep_prover, _) =
            setup_preprocessed(&config.config, &air, degree_bits)
                .expect("BatchTransactionAirP3 preprocessed trace missing");
        prove_with_preprocessed(
            &config.config,
            &air,
            trace,
            &pub_inputs.to_vec(),
            Some(&prep_prover),
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
