//! Plonky3 verifier for batch transaction proofs.

use crate::error::BatchCircuitError;
use crate::p3_air::{BatchPublicInputsP3, BatchTransactionAirP3, PREPROCESSED_WIDTH};
use crate::p3_prover::BatchProofP3;
use p3_uni_stark::{
    get_log_num_quotient_chunks, setup_preprocessed, verify_with_preprocessed,
    PreprocessedVerifierKey,
};
use transaction_circuit::p3_config::{
    config_with_fri, Config as BatchStarkConfig, Val, FRI_LOG_BLOWUP, FRI_NUM_QUERIES,
};
#[cfg(feature = "std")]
use transaction_core::dimensions::{batch_trace_rows, validate_batch_size};

#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::sync::{Arc, OnceLock, RwLock};

type BatchPreprocessedVk = PreprocessedVerifierKey<BatchStarkConfig>;

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct BatchVerifierCacheKey {
    degree_bits: usize,
    log_blowup: usize,
}

#[cfg(feature = "std")]
fn batch_verifier_cache(
) -> &'static RwLock<BTreeMap<BatchVerifierCacheKey, Arc<BatchPreprocessedVk>>> {
    static CACHE: OnceLock<RwLock<BTreeMap<BatchVerifierCacheKey, Arc<BatchPreprocessedVk>>>> =
        OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(BTreeMap::new()))
}

fn build_preprocessed_vk(
    degree_bits: usize,
    log_blowup: usize,
) -> Result<BatchPreprocessedVk, BatchCircuitError> {
    let trace_len = 1usize << degree_bits;
    let air = BatchTransactionAirP3::new(trace_len);
    let config = config_with_fri(log_blowup, FRI_NUM_QUERIES);
    setup_preprocessed(&config.config, &air, degree_bits)
        .map(|(_, vk)| vk)
        .ok_or_else(|| {
            BatchCircuitError::VerificationError(
                "BatchTransactionAirP3 preprocessed verifier key missing".into(),
            )
        })
}

#[cfg(feature = "std")]
fn get_or_build_cached_preprocessed_vk(
    degree_bits: usize,
    log_blowup: usize,
) -> Result<Arc<BatchPreprocessedVk>, BatchCircuitError> {
    let key = BatchVerifierCacheKey {
        degree_bits,
        log_blowup,
    };
    if let Some(vk) = batch_verifier_cache()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&key)
        .cloned()
    {
        return Ok(vk);
    }

    let built = Arc::new(build_preprocessed_vk(degree_bits, log_blowup)?);
    let mut cache = batch_verifier_cache()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = cache.entry(key).or_insert_with(|| built.clone());
    Ok(entry.clone())
}

#[cfg(feature = "std")]
pub fn prewarm_batch_verifier_cache_p3(batch_sizes: &[usize]) -> Result<usize, BatchCircuitError> {
    let mut warmed = 0usize;
    let pub_inputs_len = BatchPublicInputsP3::default().to_vec().len();
    for &batch_size in batch_sizes {
        validate_batch_size(batch_size)
            .map_err(|_| BatchCircuitError::InvalidBatchSize(batch_size))?;
        let trace_len = batch_trace_rows(batch_size);
        let degree_bits = trace_len.ilog2() as usize;
        let air = BatchTransactionAirP3::new(trace_len);
        let log_chunks =
            get_log_num_quotient_chunks::<Val, _>(&air, PREPROCESSED_WIDTH, pub_inputs_len, 0);
        let log_blowup = FRI_LOG_BLOWUP.max(log_chunks);

        let key = BatchVerifierCacheKey {
            degree_bits,
            log_blowup,
        };
        let already_warm = batch_verifier_cache()
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&key);
        let _ = get_or_build_cached_preprocessed_vk(degree_bits, log_blowup)?;
        if !already_warm {
            warmed = warmed.saturating_add(1);
        }
    }
    Ok(warmed)
}

#[cfg(not(feature = "std"))]
pub fn prewarm_batch_verifier_cache_p3(_batch_sizes: &[usize]) -> Result<usize, BatchCircuitError> {
    Ok(0)
}

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
    #[cfg(feature = "std")]
    let prep_vk = get_or_build_cached_preprocessed_vk(degree_bits, log_blowup)?;
    #[cfg(not(feature = "std"))]
    let prep_vk = build_preprocessed_vk(degree_bits, log_blowup)?;
    #[cfg(feature = "std")]
    let prep_vk_ref = prep_vk.as_ref();
    #[cfg(not(feature = "std"))]
    let prep_vk_ref = &prep_vk;

    verify_with_preprocessed(
        &config.config,
        &air,
        proof,
        &pub_inputs_vec,
        Some(prep_vk_ref),
    )
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
        let sk_spend = [11u8; 32];
        let pk_auth = transaction_circuit::hashing_pq::spend_auth_key_bytes(&sk_spend);
        let input_note = NoteData {
            value: 100,
            asset_id: 0,
            pk_recipient: [1u8; 32],
            pk_auth,
            rho: [2u8; 32],
            r: [3u8; 32],
        };
        let output0 = NoteData {
            value: 40,
            asset_id: 0,
            pk_recipient: [4u8; 32],
            pk_auth: [14u8; 32],
            rho: [5u8; 32],
            r: [6u8; 32],
        };
        let output1 = NoteData {
            value: 60,
            asset_id: 0,
            pk_recipient: [7u8; 32],
            pk_auth: [17u8; 32],
            rho: [8u8; 32],
            r: [9u8; 32],
        };
        let merkle_path = MerklePath::default();
        let leaf = note_commitment(
            input_note.value,
            input_note.asset_id,
            &input_note.pk_recipient,
            &input_note.pk_auth,
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
            sk_spend,
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
