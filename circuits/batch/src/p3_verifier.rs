//! Plonky3 verifier for batch transaction proofs.

use crate::error::BatchCircuitError;
use crate::p3_air::{BatchPublicInputsP3, BatchTransactionAirP3, PREPROCESSED_WIDTH};
use crate::p3_prover::BatchProofP3;
use p3_uni_stark::{get_log_num_quotient_chunks, setup_preprocessed, verify_with_preprocessed};
use transaction_circuit::p3_config::{config_with_fri, Val, FRI_LOG_BLOWUP, FRI_NUM_QUERIES};

pub fn verify_batch_proof_p3(
    proof: &BatchProofP3,
    pub_inputs: &BatchPublicInputsP3,
) -> Result<(), BatchCircuitError> {
    pub_inputs
        .validate()
        .map_err(BatchCircuitError::InvalidPublicInputs)?;

    let pub_inputs_vec = pub_inputs.to_vec();
    let degree_bits = proof.degree_bits;
    let trace_len = 1usize << degree_bits;
    let air = BatchTransactionAirP3::new(trace_len);
    let log_chunks =
        get_log_num_quotient_chunks::<Val, _>(&air, PREPROCESSED_WIDTH, pub_inputs_vec.len(), 0);
    let log_blowup = FRI_LOG_BLOWUP.max(log_chunks);
    let config = config_with_fri(log_blowup, FRI_NUM_QUERIES);
    let prep_vk = setup_preprocessed(&config.config, &air, degree_bits)
        .map(|(_, vk)| vk)
        .expect("BatchTransactionAirP3 preprocessed trace missing");
    verify_with_preprocessed(&config.config, &air, proof, &pub_inputs_vec, Some(&prep_vk))
        .map_err(|err| BatchCircuitError::VerificationError(format!("{err:?}")))
}

pub fn verify_batch_proof_bytes_p3(
    proof_bytes: &[u8],
    pub_inputs: &BatchPublicInputsP3,
) -> Result<(), BatchCircuitError> {
    pub_inputs
        .validate()
        .map_err(BatchCircuitError::InvalidPublicInputs)?;

    let proof: BatchProofP3 =
        bincode::deserialize(proof_bytes).map_err(|_| BatchCircuitError::InvalidProofFormat)?;
    verify_batch_proof_p3(&proof, pub_inputs)
}

#[cfg(test)]
mod tests {
    use super::{verify_batch_proof_p3, BatchCircuitError};
    use crate::p3_prover::BatchTransactionProverP3;
    use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, note_commitment};
    use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
    use transaction_circuit::public_inputs::StablecoinPolicyBinding;
    use transaction_circuit::witness::TransactionWitness;

    fn compute_merkle_root_from_path(
        leaf: [transaction_circuit::hashing_pq::Felt; 6],
        position: u64,
        path: &MerklePath,
    ) -> [transaction_circuit::hashing_pq::Felt; 6] {
        let mut current = leaf;
        let mut pos = position;
        for sibling in &path.siblings {
            current = if pos & 1 == 0 {
                merkle_node(current, *sibling)
            } else {
                merkle_node(*sibling, current)
            };
            pos >>= 1;
        }
        current
    }

    fn single_input_two_output_witness() -> TransactionWitness {
        let input_note = NoteData {
            value: 100,
            asset_id: 0,
            pk_recipient: [1u8; 32],
            rho: [2u8; 32],
            r: [3u8; 32],
        };
        let output0 = NoteData {
            value: 40,
            asset_id: 0,
            pk_recipient: [4u8; 32],
            rho: [5u8; 32],
            r: [6u8; 32],
        };
        let output1 = NoteData {
            value: 60,
            asset_id: 0,
            pk_recipient: [7u8; 32],
            rho: [8u8; 32],
            r: [9u8; 32],
        };
        let merkle_path = MerklePath::default();
        let leaf = note_commitment(
            input_note.value,
            input_note.asset_id,
            &input_note.pk_recipient,
            &input_note.rho,
            &input_note.r,
        );
        let merkle_root = felts_to_bytes48(&compute_merkle_root_from_path(leaf, 0, &merkle_path));
        TransactionWitness {
            inputs: vec![InputNoteWitness {
                note: input_note,
                position: 0,
                rho_seed: [10u8; 32],
                merkle_path,
            }],
            outputs: vec![
                OutputNoteWitness { note: output0 },
                OutputNoteWitness { note: output1 },
            ],
            ciphertext_hashes: vec![[0u8; 48]; 2],
            sk_spend: [11u8; 32],
            merkle_root,
            fee: 0,
            value_balance: 0,
            stablecoin: StablecoinPolicyBinding::default(),
            version: TransactionWitness::default_version_binding(),
        }
    }

    #[test]
    fn batch_proof_verifies_for_single_input_witness() -> Result<(), BatchCircuitError> {
        let witness = single_input_two_output_witness();
        witness
            .validate()
            .map_err(|err| BatchCircuitError::InvalidWitness {
                index: 0,
                reason: err.to_string(),
            })?;
        let prover = BatchTransactionProverP3::new();
        let (proof, pub_inputs) = prover.prove_batch(&[witness])?;
        verify_batch_proof_p3(&proof, &pub_inputs)
    }

    #[test]
    fn batch_proof_verifies_for_four_single_input_witnesses() -> Result<(), BatchCircuitError> {
        let witness = single_input_two_output_witness();
        witness
            .validate()
            .map_err(|err| BatchCircuitError::InvalidWitness {
                index: 0,
                reason: err.to_string(),
            })?;
        let witnesses = vec![witness.clone(), witness.clone(), witness.clone(), witness];
        let prover = BatchTransactionProverP3::new();
        let (proof, pub_inputs) = prover.prove_batch(&witnesses)?;
        verify_batch_proof_p3(&proof, &pub_inputs)
    }
}
