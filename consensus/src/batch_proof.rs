use crate::error::ProofError;
use serde::{Deserialize, Serialize};
use std::io::Cursor;

/// Flat batch proof payload format id accepted in this branch.
pub const FLAT_BATCH_PROOF_FORMAT_ID_V5: u8 = crate::types::BLOCK_PROOF_FORMAT_ID_V5;
/// Flat batch proof payload schema version.
pub const FLAT_BATCH_PROOF_SCHEMA_V2: u8 = 2;
/// Flat batch proof kind for Plonky3 batch STARK proof bytes.
pub const FLAT_BATCH_PROOF_KIND_P3_BATCH_STARK: u8 = 1;
/// Flat batch proof kind for proof-byte batch proofs over canonical tx proof bytes.
pub const FLAT_BATCH_PROOF_KIND_TX_PROOF_MANIFEST: u8 = 2;

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
    encode_flat_batch_proof_bytes_with_kind(
        FLAT_BATCH_PROOF_KIND_P3_BATCH_STARK,
        batch_proof,
        batch_public_values,
    )
}

pub fn encode_flat_batch_proof_bytes_with_kind(
    proof_kind: u8,
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
        proof_kind,
        batch_proof: batch_proof.to_vec(),
        batch_public_values: batch_public_values.to_vec(),
    };
    bincode::serialize(&payload).map_err(|err| {
        ProofError::FlatBatchProofEncodeFailed(format!("flat batch proof encode failed: {err}"))
    })
}

pub fn decode_flat_batch_proof_bytes(bytes: &[u8]) -> Result<FlatBatchProofPayloadV2, ProofError> {
    let mut cursor = Cursor::new(bytes);
    let payload: FlatBatchProofPayloadV2 = bincode::deserialize_from(&mut cursor).map_err(|err| {
        ProofError::FlatBatchProofDecodeFailed(format!("flat batch proof decode failed: {err}"))
    })?;
    if cursor.position() as usize != bytes.len() {
        return Err(ProofError::FlatBatchProofDecodeFailed(
            "flat batch proof payload has trailing bytes".to_string(),
        ));
    }
    let canonical = bincode::serialize(&payload).map_err(|err| {
        ProofError::FlatBatchProofDecodeFailed(format!(
            "flat batch proof canonical re-encode failed: {err}"
        ))
    })?;
    if canonical != bytes {
        return Err(ProofError::FlatBatchProofDecodeFailed(
            "flat batch proof payload must use canonical serialization".to_string(),
        ));
    }
    if payload.version != FLAT_BATCH_PROOF_SCHEMA_V2 {
        return Err(ProofError::FlatBatchProofDecodeFailed(format!(
            "unsupported flat batch payload version {}",
            payload.version
        )));
    }
    if payload.proof_kind != FLAT_BATCH_PROOF_KIND_P3_BATCH_STARK
        && payload.proof_kind != FLAT_BATCH_PROOF_KIND_TX_PROOF_MANIFEST
    {
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

#[cfg(test)]
mod tests {
    use super::{
        FLAT_BATCH_PROOF_KIND_P3_BATCH_STARK, FLAT_BATCH_PROOF_KIND_TX_PROOF_MANIFEST,
        decode_flat_batch_proof_bytes, encode_flat_batch_proof_bytes,
        encode_flat_batch_proof_bytes_with_kind,
    };

    #[test]
    fn tx_proof_manifest_kind_round_trips() {
        let encoded = encode_flat_batch_proof_bytes_with_kind(
            FLAT_BATCH_PROOF_KIND_TX_PROOF_MANIFEST,
            &[1, 2, 3],
            &[4, 5, 6],
        )
        .expect("encode");
        let decoded = decode_flat_batch_proof_bytes(&encoded).expect("decode");
        assert_eq!(decoded.proof_kind, FLAT_BATCH_PROOF_KIND_TX_PROOF_MANIFEST);
        assert_eq!(decoded.batch_proof, vec![1, 2, 3]);
        assert_eq!(decoded.batch_public_values, vec![4, 5, 6]);
    }

    #[test]
    fn legacy_batch_stark_kind_still_round_trips() {
        let encoded = encode_flat_batch_proof_bytes(&[9, 8, 7], &[6, 5, 4]).expect("encode");
        let decoded = decode_flat_batch_proof_bytes(&encoded).expect("decode");
        assert_eq!(decoded.proof_kind, FLAT_BATCH_PROOF_KIND_P3_BATCH_STARK);
    }

    #[test]
    fn trailing_bytes_in_flat_batch_payload_reject() {
        let mut encoded = encode_flat_batch_proof_bytes(&[9, 8, 7], &[6, 5, 4]).expect("encode");
        encoded.push(0);
        let err = decode_flat_batch_proof_bytes(&encoded).expect_err("trailing bytes accepted");
        assert!(err
            .to_string()
            .contains("trailing bytes"));
    }
}
