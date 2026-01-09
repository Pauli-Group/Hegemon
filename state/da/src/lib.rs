//! Data availability encoding and Merkle proofs.
//!
//! This module turns a byte blob into erasure-coded chunks, builds a Merkle root
//! over those chunks, and verifies chunk proofs.

use codec::{Decode, Encode};
use crypto::hashes::blake3_384;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::HashSet;
use thiserror::Error;

pub type DaRoot = [u8; 48];

const LEAF_DOMAIN: &[u8] = b"da-leaf";
const NODE_DOMAIN: &[u8] = b"da-node";
const MIN_SAMPLE_COUNT: u32 = 1;
const MAX_SHARDS: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct DaParams {
    pub chunk_size: u32,
    pub sample_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct DaChunk {
    pub index: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct DaChunkProof {
    pub chunk: DaChunk,
    pub merkle_path: Vec<DaRoot>,
}

#[derive(Debug, Error)]
pub enum DaError {
    #[error("chunk size must be non-zero")]
    ChunkSizeZero,
    #[error("sample count must be at least 1")]
    SampleCountZero,
    #[error("data shard count overflow")]
    ShardCountOverflow,
    #[error("total shard count {total} exceeds max {max}")]
    TooManyShards { total: usize, max: usize },
    #[error("chunk index out of range")]
    ChunkIndex,
    #[error("erasure coding failed: {0}")]
    Encoding(String),
    #[error("merkle proof verification failed")]
    MerkleProof,
}

#[derive(Debug)]
pub struct DaEncoding {
    params: DaParams,
    data_len: usize,
    data_shards: usize,
    parity_shards: usize,
    chunk_size: usize,
    chunks: Vec<DaChunk>,
    merkle_levels: Vec<Vec<DaRoot>>,
}

impl DaEncoding {
    pub fn params(&self) -> DaParams {
        self.params
    }

    pub fn data_len(&self) -> usize {
        self.data_len
    }

    pub fn data_shards(&self) -> usize {
        self.data_shards
    }

    pub fn parity_shards(&self) -> usize {
        self.parity_shards
    }

    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    pub fn chunks(&self) -> &[DaChunk] {
        &self.chunks
    }

    pub fn root(&self) -> DaRoot {
        self.merkle_levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .unwrap_or([0u8; 48])
    }

    pub fn proof(&self, index: u32) -> Result<DaChunkProof, DaError> {
        let idx = index as usize;
        if idx >= self.chunks.len() {
            return Err(DaError::ChunkIndex);
        }
        let mut path = Vec::with_capacity(self.merkle_levels.len().saturating_sub(1));
        let mut node_idx = idx;
        for level in &self.merkle_levels[..self.merkle_levels.len().saturating_sub(1)] {
            let sibling_idx = if node_idx.is_multiple_of(2) {
                (node_idx + 1).min(level.len() - 1)
            } else {
                node_idx - 1
            };
            path.push(level[sibling_idx]);
            node_idx /= 2;
        }
        Ok(DaChunkProof {
            chunk: self.chunks[idx].clone(),
            merkle_path: path,
        })
    }
}

pub fn encode_da_blob(blob: &[u8], params: DaParams) -> Result<DaEncoding, DaError> {
    validate_params(params)?;
    let chunk_size = params.chunk_size as usize;
    let data_len = blob.len();
    let data_shards = data_shards_for_len(data_len, chunk_size);
    let parity_shards = parity_shards_for_data(data_shards);
    let total_shards = data_shards
        .checked_add(parity_shards)
        .ok_or(DaError::ShardCountOverflow)?;
    if total_shards > MAX_SHARDS {
        return Err(DaError::TooManyShards {
            total: total_shards,
            max: MAX_SHARDS,
        });
    }
    if total_shards > u32::MAX as usize {
        return Err(DaError::ShardCountOverflow);
    }

    let mut shards = vec![vec![0u8; chunk_size]; total_shards];
    for (idx, shard) in shards.iter_mut().take(data_shards).enumerate() {
        let start = idx * chunk_size;
        if start >= data_len {
            break;
        }
        let end = (start + chunk_size).min(data_len);
        shard[..end - start].copy_from_slice(&blob[start..end]);
    }

    let rs = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|err| DaError::Encoding(err.to_string()))?;
    rs.encode(&mut shards)
        .map_err(|err| DaError::Encoding(err.to_string()))?;

    let chunks = shards
        .into_iter()
        .enumerate()
        .map(|(idx, data)| DaChunk {
            index: idx as u32,
            data,
        })
        .collect::<Vec<_>>();
    let merkle_levels = build_merkle_levels(&chunks);

    Ok(DaEncoding {
        params,
        data_len,
        data_shards,
        parity_shards,
        chunk_size,
        chunks,
        merkle_levels,
    })
}

pub fn da_root(blob: &[u8], params: DaParams) -> Result<DaRoot, DaError> {
    let encoding = encode_da_blob(blob, params)?;
    Ok(encoding.root())
}

pub fn verify_da_chunk(root: DaRoot, proof: &DaChunkProof) -> Result<(), DaError> {
    if proof.merkle_path.is_empty() {
        if hash_leaf(proof.chunk.index, &proof.chunk.data) == root {
            return Ok(());
        }
        return Err(DaError::MerkleProof);
    }
    let mut hash = hash_leaf(proof.chunk.index, &proof.chunk.data);
    let mut idx = proof.chunk.index as usize;
    for sibling in &proof.merkle_path {
        hash = if idx.is_multiple_of(2) {
            hash_node(&hash, sibling)
        } else {
            hash_node(sibling, &hash)
        };
        idx /= 2;
    }
    if hash == root {
        Ok(())
    } else {
        Err(DaError::MerkleProof)
    }
}

pub fn chunk_count_for_blob(blob_len: usize, params: DaParams) -> Result<usize, DaError> {
    validate_params(params)?;
    let chunk_size = params.chunk_size as usize;
    let data_shards = data_shards_for_len(blob_len, chunk_size);
    let parity_shards = parity_shards_for_data(data_shards);
    let total = data_shards
        .checked_add(parity_shards)
        .ok_or(DaError::ShardCountOverflow)?;
    if total > MAX_SHARDS {
        return Err(DaError::TooManyShards {
            total,
            max: MAX_SHARDS,
        });
    }
    Ok(total)
}

fn validate_params(params: DaParams) -> Result<(), DaError> {
    if params.chunk_size == 0 {
        return Err(DaError::ChunkSizeZero);
    }
    if params.sample_count < MIN_SAMPLE_COUNT {
        return Err(DaError::SampleCountZero);
    }
    Ok(())
}

fn data_shards_for_len(len: usize, chunk_size: usize) -> usize {
    let shards = len.div_ceil(chunk_size);
    if shards == 0 {
        1
    } else {
        shards
    }
}

fn parity_shards_for_data(data_shards: usize) -> usize {
    // Use a 1.5x overhead baseline: p = ceil(k / 2).
    let parity = (data_shards + 1) / 2;
    parity.max(1)
}

fn build_merkle_levels(chunks: &[DaChunk]) -> Vec<Vec<DaRoot>> {
    let mut leaves: Vec<DaRoot> = chunks
        .iter()
        .map(|chunk| hash_leaf(chunk.index, &chunk.data))
        .collect();
    if leaves.is_empty() {
        leaves.push(hash_leaf(0, &[]));
    }
    let mut levels = vec![leaves];
    while levels.last().map(|level| level.len()).unwrap_or(0) > 1 {
        let prev = levels.last().expect("level exists");
        let mut next = Vec::with_capacity(prev.len().div_ceil(2));
        let mut idx = 0usize;
        while idx < prev.len() {
            let left = prev[idx];
            let right = if idx + 1 < prev.len() {
                prev[idx + 1]
            } else {
                prev[idx]
            };
            next.push(hash_node(&left, &right));
            idx += 2;
        }
        levels.push(next);
    }
    levels
}

fn hash_leaf(index: u32, data: &[u8]) -> DaRoot {
    let mut input = Vec::with_capacity(LEAF_DOMAIN.len() + 4 + data.len());
    input.extend_from_slice(LEAF_DOMAIN);
    input.extend_from_slice(&index.to_le_bytes());
    input.extend_from_slice(data);
    blake3_384(&input)
}

fn hash_node(left: &DaRoot, right: &DaRoot) -> DaRoot {
    let mut input = [0u8; 48 * 2 + 7];
    input[..NODE_DOMAIN.len()].copy_from_slice(NODE_DOMAIN);
    let mut offset = NODE_DOMAIN.len();
    input[offset..offset + 48].copy_from_slice(left);
    offset += 48;
    input[offset..offset + 48].copy_from_slice(right);
    blake3_384(&input)
}

/// Generate sample indices using per-node secret + block hash.
///
/// This ensures:
/// 1. Block producer cannot predict which chunks any given node will sample
/// 2. Different nodes sample different chunks (due to different secrets)
/// 3. Same node samples same chunks for same block (deterministic replay)
///
/// The `node_secret` should be generated once at node startup and kept private.
/// The `block_hash` is the hash of the block header being validated.
///
/// Returns a vector of unique chunk indices to sample. If `sample_count` exceeds
/// `total_chunks`, returns indices for all chunks.
pub fn sample_indices(
    node_secret: [u8; 32],
    block_hash: [u8; 32],
    total_chunks: u32,
    sample_count: u32,
) -> Vec<u32> {
    if total_chunks == 0 {
        return Vec::new();
    }

    // Combine node secret with block hash using XOR
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = node_secret[i] ^ block_hash[i];
    }

    let mut rng = ChaCha20Rng::from_seed(seed);
    let effective_sample_count = sample_count.min(total_chunks) as usize;
    let mut indices = Vec::with_capacity(effective_sample_count);
    let mut seen = HashSet::with_capacity(effective_sample_count);

    while indices.len() < effective_sample_count {
        let idx = rng.gen_range(0..total_chunks);
        if seen.insert(idx) {
            indices.push(idx);
        }
    }

    indices
}

/// Generate a fresh node secret for DA sampling.
///
/// This should be called once at node startup and the result persisted
/// (or derived from a stable node identity seed).
pub fn generate_node_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    rand::thread_rng().fill(&mut secret);
    secret
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn encode_and_verify_roundtrip() {
        let mut blob = vec![0u8; 4096];
        rand::thread_rng().fill_bytes(&mut blob);
        let params = DaParams {
            chunk_size: 512,
            sample_count: 4,
        };
        let encoding = encode_da_blob(&blob, params).expect("encode");
        let proof = encoding.proof(0).expect("proof");
        verify_da_chunk(encoding.root(), &proof).expect("verify");
    }

    #[test]
    fn tampered_chunk_fails() {
        let blob = vec![42u8; 2048];
        let params = DaParams {
            chunk_size: 512,
            sample_count: 4,
        };
        let encoding = encode_da_blob(&blob, params).expect("encode");
        let mut proof = encoding.proof(1).expect("proof");
        proof.chunk.data[0] ^= 0xFF;
        assert!(verify_da_chunk(encoding.root(), &proof).is_err());
    }

    #[test]
    fn empty_blob_still_hashes() {
        let params = DaParams {
            chunk_size: 512,
            sample_count: 1,
        };
        let encoding = encode_da_blob(&[], params).expect("encode");
        assert_eq!(encoding.data_shards(), 1);
        assert_eq!(encoding.chunks().len(), 2);
    }

    #[test]
    fn sample_indices_deterministic_for_same_inputs() {
        let secret = [42u8; 32];
        let block_hash = [7u8; 32];
        let indices1 = sample_indices(secret, block_hash, 100, 10);
        let indices2 = sample_indices(secret, block_hash, 100, 10);
        assert_eq!(
            indices1, indices2,
            "same inputs should produce same samples"
        );
    }

    #[test]
    fn sample_indices_differ_for_different_secrets() {
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];
        let block_hash = [7u8; 32];
        let indices1 = sample_indices(secret1, block_hash, 100, 10);
        let indices2 = sample_indices(secret2, block_hash, 100, 10);
        assert_ne!(
            indices1, indices2,
            "different secrets should produce different samples"
        );
    }

    #[test]
    fn sample_indices_differ_for_different_blocks() {
        let secret = [42u8; 32];
        let block1 = [1u8; 32];
        let block2 = [2u8; 32];
        let indices1 = sample_indices(secret, block1, 100, 10);
        let indices2 = sample_indices(secret, block2, 100, 10);
        assert_ne!(
            indices1, indices2,
            "different blocks should produce different samples"
        );
    }

    #[test]
    fn sample_indices_are_unique() {
        let secret = [42u8; 32];
        let block_hash = [7u8; 32];
        let indices = sample_indices(secret, block_hash, 50, 30);
        let unique: HashSet<u32> = indices.iter().copied().collect();
        assert_eq!(indices.len(), unique.len(), "indices should be unique");
    }

    #[test]
    fn sample_indices_caps_at_total_chunks() {
        let secret = [42u8; 32];
        let block_hash = [7u8; 32];
        let indices = sample_indices(secret, block_hash, 5, 100);
        assert_eq!(indices.len(), 5, "should not sample more than total chunks");
    }

    #[test]
    fn sample_indices_empty_for_zero_chunks() {
        let secret = [42u8; 32];
        let block_hash = [7u8; 32];
        let indices = sample_indices(secret, block_hash, 0, 10);
        assert!(indices.is_empty());
    }
}
