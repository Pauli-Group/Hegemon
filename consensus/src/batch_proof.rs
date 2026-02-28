use crate::error::ProofError;
use serde::{Deserialize, Serialize};
use transaction_circuit::TransactionProof;

/// Flat batch proof payload format id accepted in this branch.
pub const FLAT_BATCH_PROOF_FORMAT_ID_V5: u8 = crate::types::BLOCK_PROOF_FORMAT_ID_V5;
/// Flat batch proof payload schema version.
pub const FLAT_BATCH_PROOF_SCHEMA_V1: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatBatchProofPayloadV1 {
    pub version: u8,
    pub tx_proofs: Vec<TransactionProof>,
}

pub fn encode_flat_batch_proof_bytes(
    tx_proofs: &[TransactionProof],
) -> Result<Vec<u8>, ProofError> {
    let payload = FlatBatchProofPayloadV1 {
        version: FLAT_BATCH_PROOF_SCHEMA_V1,
        tx_proofs: tx_proofs.to_vec(),
    };
    bincode::serialize(&payload).map_err(|err| {
        ProofError::FlatBatchProofEncodeFailed(format!("flat batch proof encode failed: {err}"))
    })
}

pub fn decode_flat_batch_proof_bytes(bytes: &[u8]) -> Result<Vec<TransactionProof>, ProofError> {
    let payload: FlatBatchProofPayloadV1 = bincode::deserialize(bytes).map_err(|err| {
        ProofError::FlatBatchProofDecodeFailed(format!("flat batch proof decode failed: {err}"))
    })?;
    if payload.version != FLAT_BATCH_PROOF_SCHEMA_V1 {
        return Err(ProofError::FlatBatchProofDecodeFailed(format!(
            "unsupported flat batch payload version {}",
            payload.version
        )));
    }
    if payload.tx_proofs.is_empty() {
        return Err(ProofError::FlatBatchProofDecodeFailed(
            "flat batch proof payload contains no transaction proofs".to_string(),
        ));
    }
    Ok(payload.tx_proofs)
}
