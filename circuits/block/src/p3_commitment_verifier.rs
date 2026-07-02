//! Plonky3 verifier for commitment block proofs.

use blake3::Hasher as Blake3Hasher;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_uni_stark::{setup_preprocessed, verify_with_preprocessed};
use std::io::Cursor;
use transaction_circuit::constants::MAX_INPUTS;
use transaction_circuit::p3_config::{config_with_fri, TransactionProofP3};
use transaction_circuit::p3_verifier::infer_transaction_fri_profile_p3;

use crate::error::BlockError;
use crate::p3_commitment_air::{CommitmentBlockAirP3, CommitmentBlockPublicInputsP3, Felt};
use crate::p3_commitment_prover::CommitmentBlockProofP3;

/// Pre-decode cap for the legacy commitment-block proof wrapper.
///
/// This path is a compatibility verifier; the shipped recursive block lanes have
/// tighter versioned caps. Keep this limit high enough for historical P3 proofs
/// while rejecting allocation-sized garbage before bincode sees it.
pub const MAX_COMMITMENT_BLOCK_PROOF_BYTES: usize = 64 * 1024 * 1024;

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

    let proof = decode_commitment_block_proof_bytes_exact(proof_bytes)?;
    let tx_count = pub_inputs.tx_count as usize;
    let trace_len = CommitmentBlockAirP3::trace_length(tx_count);
    let degree_bits = trace_len.ilog2() as usize;
    let air = CommitmentBlockAirP3::new(tx_count);
    let pub_inputs_vec = pub_inputs.to_vec();
    let fri_profile = infer_transaction_fri_profile_p3(&proof).map_err(|err| {
        BlockError::CommitmentProofVerification(format!(
            "failed to infer commitment proof FRI profile: {err}"
        ))
    })?;
    let config = config_with_fri(fri_profile.log_blowup, fri_profile.num_queries);
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

fn decode_commitment_block_proof_bytes_exact(
    proof_bytes: &[u8],
) -> Result<TransactionProofP3, BlockError> {
    if proof_bytes.is_empty() {
        return Err(BlockError::CommitmentProofVerification(
            "commitment proof bytes are empty".into(),
        ));
    }
    if proof_bytes.len() > MAX_COMMITMENT_BLOCK_PROOF_BYTES {
        return Err(BlockError::CommitmentProofVerification(format!(
            "commitment proof bytes exceed cap: actual={} cap={}",
            proof_bytes.len(),
            MAX_COMMITMENT_BLOCK_PROOF_BYTES
        )));
    }

    let mut cursor = Cursor::new(proof_bytes);
    let proof: TransactionProofP3 = bincode::deserialize_from(&mut cursor)
        .map_err(|_| BlockError::CommitmentProofVerification("invalid proof format".into()))?;
    if cursor.position() as usize != proof_bytes.len() {
        return Err(BlockError::CommitmentProofVerification(
            "commitment proof bytes have trailing bytes".into(),
        ));
    }
    let canonical = bincode::serialize(&proof)
        .map_err(|_| BlockError::CommitmentProofVerification("invalid proof format".into()))?;
    if canonical != proof_bytes {
        return Err(BlockError::CommitmentProofVerification(
            "commitment proof bytes must use canonical serialization".into(),
        ));
    }
    Ok(proof)
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
    hasher.update(&limbs_to_bytes(&inputs.starting_kernel_root));
    hasher.update(&limbs_to_bytes(&inputs.ending_kernel_root));
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

#[cfg(test)]
mod tests {
    use super::{decode_commitment_block_proof_bytes_exact, MAX_COMMITMENT_BLOCK_PROOF_BYTES};

    #[test]
    fn commitment_block_proof_decode_rejects_empty_before_bincode() {
        let err = match decode_commitment_block_proof_bytes_exact(&[]) {
            Ok(_) => panic!("empty commitment proof accepted"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("empty"), "unexpected error: {err}");
    }

    #[test]
    fn commitment_block_proof_decode_rejects_oversized_before_bincode() {
        let oversized = vec![0u8; MAX_COMMITMENT_BLOCK_PROOF_BYTES + 1];
        let err = match decode_commitment_block_proof_bytes_exact(&oversized) {
            Ok(_) => panic!("oversized commitment proof accepted"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("exceed cap"),
            "unexpected error: {err}"
        );
    }
}
