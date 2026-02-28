use crate::error::ProofError;
use serde::{Deserialize, Serialize};

/// Flat batch proof payload format id accepted in this branch.
pub const FLAT_BATCH_PROOF_FORMAT_ID_V5: u8 = crate::types::BLOCK_PROOF_FORMAT_ID_V5;
/// Flat batch proof payload schema version.
pub const FLAT_BATCH_PROOF_SCHEMA_V2: u8 = 2;
/// Flat batch proof kind for Plonky3 batch STARK proof bytes.
pub const FLAT_BATCH_PROOF_KIND_P3_BATCH_STARK: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatBatchProofPayloadV2 {
    pub version: u8,
    pub proof_kind: u8,
    pub batch_proof: Vec<u8>,
    /// Canonical u64 representation of batch public inputs field elements.
    pub batch_public_values: Vec<u64>,
}

pub fn encode_flat_batch_proof_bytes(
    batch_proof: &[u8],
    batch_public_values: &[u64],
) -> Result<Vec<u8>, ProofError> {
    if batch_proof.is_empty() {
        return Err(ProofError::FlatBatchProofEncodeFailed(
            "batch proof payload contains empty proof bytes".to_string(),
        ));
    }
    if batch_public_values.is_empty() {
        return Err(ProofError::FlatBatchProofEncodeFailed(
            "batch proof payload contains no public values".to_string(),
        ));
    }
    let payload = FlatBatchProofPayloadV2 {
        version: FLAT_BATCH_PROOF_SCHEMA_V2,
        proof_kind: FLAT_BATCH_PROOF_KIND_P3_BATCH_STARK,
        batch_proof: batch_proof.to_vec(),
        batch_public_values: batch_public_values.to_vec(),
    };
    bincode::serialize(&payload).map_err(|err| {
        ProofError::FlatBatchProofEncodeFailed(format!("flat batch proof encode failed: {err}"))
    })
}

pub fn decode_flat_batch_proof_bytes(bytes: &[u8]) -> Result<FlatBatchProofPayloadV2, ProofError> {
    let payload: FlatBatchProofPayloadV2 = bincode::deserialize(bytes).map_err(|err| {
        ProofError::FlatBatchProofDecodeFailed(format!("flat batch proof decode failed: {err}"))
    })?;
    if payload.version != FLAT_BATCH_PROOF_SCHEMA_V2 {
        return Err(ProofError::FlatBatchProofDecodeFailed(format!(
            "unsupported flat batch payload version {}",
            payload.version
        )));
    }
    if payload.proof_kind != FLAT_BATCH_PROOF_KIND_P3_BATCH_STARK {
        return Err(ProofError::FlatBatchProofDecodeFailed(format!(
            "unsupported flat batch proof kind {}",
            payload.proof_kind
        )));
    }
    if payload.batch_proof.is_empty() {
        return Err(ProofError::FlatBatchProofDecodeFailed(
            "flat batch proof payload contains empty proof bytes".to_string(),
        ));
    }
    if payload.batch_public_values.is_empty() {
        return Err(ProofError::FlatBatchProofDecodeFailed(
            "flat batch proof payload contains no public values".to_string(),
        ));
    }
    Ok(payload)
}
