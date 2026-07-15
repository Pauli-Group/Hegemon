use std::io::Cursor;

use transaction_circuit::TransactionProof;
use zstd::stream::{decode_all, encode_all};

use crate::error::ProofError;

const AGGREGATION_PROOF_MAGIC: [u8; 4] = *b"HGA0";
const AGGREGATION_PROOF_VERSION: u8 = 1;
const AGGREGATION_PROOF_HEADER_LEN: usize = 9;
const AGGREGATION_PROOF_ZSTD_LEVEL: i32 = 3;
const MAX_AGGREGATION_PROOF_UNCOMPRESSED_LEN: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct AggregationCacheWarmup {
    pub cache_hit: bool,
    pub cache_build_ms: u128,
}

#[derive(Clone, Copy, Debug)]
pub struct AggregationVerifyMetrics {
    pub cache_hit: bool,
    pub cache_build_ms: u128,
    pub verify_batch_ms: u128,
    pub total_ms: u128,
}

pub fn encode_aggregation_proof_bytes(raw_bytes: Vec<u8>) -> Vec<u8> {
    if raw_bytes.is_empty() {
        return raw_bytes;
    }
    let compressed = match encode_all(raw_bytes.as_slice(), AGGREGATION_PROOF_ZSTD_LEVEL) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => return raw_bytes,
    };

    let mut encoded = Vec::with_capacity(AGGREGATION_PROOF_HEADER_LEN + compressed.len());
    encoded.extend_from_slice(&AGGREGATION_PROOF_MAGIC);
    encoded.push(AGGREGATION_PROOF_VERSION);
    encoded.extend_from_slice(&(raw_bytes.len() as u32).to_le_bytes());
    encoded.extend_from_slice(&compressed);
    if encoded.len() < raw_bytes.len() {
        encoded
    } else {
        raw_bytes
    }
}

pub fn aggregation_proof_uncompressed_len(bytes: &[u8]) -> usize {
    if bytes.len() < AGGREGATION_PROOF_HEADER_LEN
        || bytes[..4] != AGGREGATION_PROOF_MAGIC
        || bytes[4] != AGGREGATION_PROOF_VERSION
    {
        return bytes.len();
    }
    let length = u32::from_le_bytes(bytes[5..9].try_into().expect("length header")) as usize;
    if length == 0 || length > MAX_AGGREGATION_PROOF_UNCOMPRESSED_LEN {
        bytes.len()
    } else {
        length
    }
}

pub fn decode_aggregation_proof_bytes(bytes: &[u8]) -> Result<Vec<u8>, ProofError> {
    if bytes.len() < AGGREGATION_PROOF_HEADER_LEN || bytes[..4] != AGGREGATION_PROOF_MAGIC {
        return Ok(bytes.to_vec());
    }
    if bytes[4] != AGGREGATION_PROOF_VERSION {
        return Err(input_error(
            "aggregation proof compression version mismatch",
        ));
    }
    let expected_len = u32::from_le_bytes(bytes[5..9].try_into().expect("length header")) as usize;
    if expected_len == 0 || expected_len > MAX_AGGREGATION_PROOF_UNCOMPRESSED_LEN {
        return Err(input_error("aggregation proof uncompressed length invalid"));
    }
    let compressed = &bytes[AGGREGATION_PROOF_HEADER_LEN..];
    if compressed.is_empty() {
        return Err(input_error("aggregation proof compressed payload missing"));
    }
    let decoded = decode_all(Cursor::new(compressed)).map_err(|error| {
        input_error(&format!("aggregation proof decompression failed: {error}"))
    })?;
    if decoded.len() != expected_len {
        return Err(input_error(
            "aggregation proof decompressed length mismatch",
        ));
    }
    Ok(decoded)
}

pub fn warm_aggregation_cache(
    _representative_proof: &TransactionProof,
    _tx_count: usize,
) -> Result<AggregationCacheWarmup, ProofError> {
    retired()
}

pub fn warm_aggregation_cache_from_proof_bytes(
    _aggregation_proof: &[u8],
    _tx_count: usize,
    _expected_statement_commitment: &[u8; 48],
) -> Result<AggregationCacheWarmup, ProofError> {
    retired()
}

pub fn verify_aggregation_proof_with_metrics(
    _aggregation_proof: &[u8],
    _tx_count: usize,
    _expected_statement_commitment: &[u8; 48],
) -> Result<AggregationVerifyMetrics, ProofError> {
    retired()
}

pub fn verify_aggregation_proof(
    _aggregation_proof: &[u8],
    _tx_count: usize,
    _expected_statement_commitment: &[u8; 48],
) -> Result<(), ProofError> {
    retired()
}

fn retired<T>() -> Result<T, ProofError> {
    Err(ProofError::UnsupportedProofArtifact(
        "retired aggregation proof backend is not executable".to_string(),
    ))
}

fn input_error(message: &str) -> ProofError {
    ProofError::AggregationProofInputsMismatch(message.to_string())
}

#[cfg(test)]
mod tests {
    use super::verify_aggregation_proof;
    use crate::error::ProofError;

    #[test]
    fn retired_aggregation_verifier_is_fail_closed() {
        let error = verify_aggregation_proof(b"legacy", 1, &[0u8; 48])
            .expect_err("retired aggregation proof accepted");
        assert!(matches!(error, ProofError::UnsupportedProofArtifact(_)));
    }
}
