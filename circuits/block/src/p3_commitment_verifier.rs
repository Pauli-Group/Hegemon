//! Plonky3 verifier for commitment block proofs.

use blake3::Hasher as Blake3Hasher;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_uni_stark::{get_log_num_quotient_chunks, setup_preprocessed, verify_with_preprocessed};
use transaction_circuit::constants::MAX_INPUTS;
use transaction_circuit::p3_config::{
    config_with_fri, TransactionProofP3, FRI_LOG_BLOWUP, FRI_NUM_QUERIES,
};

use crate::error::BlockError;
use crate::p3_commitment_air::{
    CommitmentBlockAirP3, CommitmentBlockPublicInputsP3, Felt, PREPROCESSED_WIDTH,
};
use crate::p3_commitment_prover::CommitmentBlockProofP3;

pub fn verify_block_commitment_p3(proof: &CommitmentBlockProofP3) -> Result<(), BlockError> {
    verify_block_commitment_proof_p3(&proof.proof_bytes, &proof.public_inputs)
}

pub fn verify_block_commitment_proof_p3(
    proof_bytes: &[u8],
    pub_inputs: &CommitmentBlockPublicInputsP3,
) -> Result<(), BlockError> {
    pub_inputs
        .validate()
        .map_err(BlockError::CommitmentProofInvalidInputs)?;

    let (expected_alpha, expected_beta) = derive_nullifier_challenges_inputs(pub_inputs)?;
    if pub_inputs.perm_alpha != expected_alpha || pub_inputs.perm_beta != expected_beta {
        return Err(BlockError::CommitmentProofInvalidInputs(
            "perm challenges mismatch".into(),
        ));
    }

    let proof: TransactionProofP3 = bincode::deserialize(proof_bytes)
        .map_err(|_| BlockError::CommitmentProofVerification("invalid proof format".into()))?;
    let tx_count = pub_inputs.tx_count as usize;
    let trace_len = CommitmentBlockAirP3::trace_length(tx_count);
    let degree_bits = trace_len.ilog2() as usize;
    let air = CommitmentBlockAirP3::new(tx_count);
    let pub_inputs_vec = pub_inputs.to_vec();
    let log_chunks =
        get_log_num_quotient_chunks::<Felt, _>(&air, PREPROCESSED_WIDTH, pub_inputs_vec.len(), 0);
    let log_blowup = FRI_LOG_BLOWUP.max(log_chunks);
    let config = config_with_fri(log_blowup, FRI_NUM_QUERIES);
    let (_, prep_vk) = setup_preprocessed(&config.config, &air, degree_bits)
        .expect("CommitmentBlockAirP3 preprocessed trace missing");
    verify_with_preprocessed(
        &config.config,
        &air,
        &proof,
        &pub_inputs_vec,
        Some(&prep_vk),
    )
    .map_err(|err| BlockError::CommitmentProofVerification(format!("{err:?}")))
}

fn derive_nullifier_challenges_inputs(
    inputs: &CommitmentBlockPublicInputsP3,
) -> Result<(Felt, Felt), BlockError> {
    let nullifiers: Vec<[u8; 48]> = inputs.nullifiers.iter().map(limbs_to_bytes).collect();
    let sorted_nullifiers: Vec<[u8; 48]> = inputs
        .sorted_nullifiers
        .iter()
        .map(limbs_to_bytes)
        .collect();
    let tx_count = inputs.tx_count;
    let expected_nullifiers = (tx_count as usize).saturating_mul(MAX_INPUTS);
    if nullifiers.len() != expected_nullifiers || sorted_nullifiers.len() != expected_nullifiers {
        return Err(BlockError::CommitmentProofInvalidInputs(
            "nullifier length mismatch".into(),
        ));
    }

    let mut hasher = Blake3Hasher::new();
    hasher.update(b"blk-nullifier-perm-v1");
    hasher.update(&limbs_to_bytes(&inputs.starting_state_root));
    hasher.update(&limbs_to_bytes(&inputs.ending_state_root));
    hasher.update(&limbs_to_bytes(&inputs.nullifier_root));
    hasher.update(&limbs_to_bytes(&inputs.da_root));
    hasher.update(&tx_count.to_le_bytes());
    hasher.update(&(nullifiers.len() as u64).to_le_bytes());
    hasher.update(&(sorted_nullifiers.len() as u64).to_le_bytes());
    for nf in &nullifiers {
        hasher.update(nf);
    }
    for nf in &sorted_nullifiers {
        hasher.update(nf);
    }
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    let mut alpha = Felt::from_u64(u64::from_le_bytes(
        bytes[0..8].try_into().expect("8-byte alpha"),
    ));
    let mut beta = Felt::from_u64(u64::from_le_bytes(
        bytes[8..16].try_into().expect("8-byte beta"),
    ));
    if alpha.is_zero() {
        alpha = Felt::ONE;
    }
    if beta.is_zero() {
        beta = Felt::from_u64(2);
    }
    Ok((alpha, beta))
}

fn limbs_to_bytes(limbs: &[Felt; 6]) -> [u8; 48] {
    let mut out = [0u8; 48];
    for (idx, limb) in limbs.iter().enumerate() {
        let start = idx * 8;
        out[start..start + 8].copy_from_slice(&limb.as_canonical_u64().to_be_bytes());
    }
    out
}
