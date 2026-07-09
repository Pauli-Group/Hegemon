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
pub const MAX_DA_CHUNK_SIZE: u32 = 256 * 1024;
pub const MAX_DA_TOTAL_SHARD_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_DA_CHUNK_MERKLE_PATH_LEN: usize = 8;
pub const MAX_DA_PAGE_MERKLE_PATH_LEN: usize = 32;

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

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct DaMultiChunkProof {
    pub page_index: u32,
    pub page_root: DaRoot,
    pub page_proof: DaChunkProof,
    pub page_merkle_path: Vec<DaRoot>,
}

#[derive(Debug, Error)]
pub enum DaError {
    #[error("chunk size must be non-zero")]
    ChunkSizeZero,
    #[error("chunk size {chunk_size} exceeds max {max}")]
    ChunkSizeTooLarge { chunk_size: u32, max: u32 },
    #[error("sample count must be at least 1")]
    SampleCountZero,
    #[error("data shard count overflow")]
    ShardCountOverflow,
    #[error("total shard count {total} exceeds max {max}")]
    TooManyShards { total: usize, max: usize },
    #[error("total shard allocation {total_bytes} bytes exceeds max {max} bytes")]
    ShardAllocationTooLarge { total_bytes: usize, max: usize },
    #[error("chunk index out of range")]
    ChunkIndex,
    #[error("Merkle proof path length {path_len} exceeds max {max}")]
    ProofPathTooLong { path_len: usize, max: usize },
    #[error("erasure coding failed: {0}")]
    Encoding(String),
    #[error("merkle proof verification failed")]
    MerkleProof,
}

#[derive(Debug, Encode, Decode)]
pub struct DaEncoding {
    params: DaParams,
    data_len: u64,
    data_shards: u64,
    parity_shards: u64,
    chunk_size: u64,
    chunks: Vec<DaChunk>,
    merkle_levels: Vec<Vec<DaRoot>>,
}

#[derive(Debug, Encode, Decode)]
pub struct DaMultiEncoding {
    params: DaParams,
    page_len: u64,
    pages: Vec<DaEncoding>,
    page_roots: Vec<DaRoot>,
    page_merkle_levels: Vec<Vec<DaRoot>>,
}

impl DaEncoding {
    pub fn params(&self) -> DaParams {
        self.params
    }

    pub fn data_len(&self) -> u64 {
        self.data_len
    }

    pub fn data_shards(&self) -> u64 {
        self.data_shards
    }

    pub fn parity_shards(&self) -> u64 {
        self.parity_shards
    }

    pub fn chunk_size(&self) -> u64 {
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

impl DaMultiEncoding {
    pub fn params(&self) -> DaParams {
        self.params
    }

    pub fn page_len(&self) -> u64 {
        self.page_len
    }

    pub fn pages(&self) -> &[DaEncoding] {
        &self.pages
    }

    pub fn root(&self) -> DaRoot {
        self.page_merkle_levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .unwrap_or([0u8; 48])
    }

    pub fn proof(&self, global_index: u32) -> Result<DaMultiChunkProof, DaError> {
        let global_index = global_index as usize;
        let page_index = global_index / MAX_SHARDS;
        let chunk_index = global_index % MAX_SHARDS;
        if page_index >= self.pages.len() {
            return Err(DaError::ChunkIndex);
        }
        let page = &self.pages[page_index];
        if chunk_index >= page.chunks().len() {
            return Err(DaError::ChunkIndex);
        }
        let page_proof = page.proof(chunk_index as u32)?;
        let page_root = self.page_roots[page_index];
        let page_merkle_path = self.page_merkle_path(page_index)?;
        Ok(DaMultiChunkProof {
            page_index: page_index as u32,
            page_root,
            page_proof,
            page_merkle_path,
        })
    }

    fn page_merkle_path(&self, page_index: usize) -> Result<Vec<DaRoot>, DaError> {
        if page_index >= self.page_roots.len() {
            return Err(DaError::ChunkIndex);
        }
        let mut path = Vec::with_capacity(self.page_merkle_levels.len().saturating_sub(1));
        let mut node_idx = page_index;
        for level in &self.page_merkle_levels[..self.page_merkle_levels.len().saturating_sub(1)] {
            let sibling_idx = if node_idx.is_multiple_of(2) {
                (node_idx + 1).min(level.len() - 1)
            } else {
                node_idx - 1
            };
            path.push(level[sibling_idx]);
            node_idx /= 2;
        }
        Ok(path)
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
    validate_shard_allocation(total_shards, chunk_size)?;

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
        data_len: data_len as u64,
        data_shards: data_shards as u64,
        parity_shards: parity_shards as u64,
        chunk_size: chunk_size as u64,
        chunks,
        merkle_levels,
    })
}

pub fn encode_da_blob_multipage(blob: &[u8], params: DaParams) -> Result<DaMultiEncoding, DaError> {
    validate_params(params)?;
    let page_len = max_page_len(params)?;
    let mut pages = Vec::new();

    if blob.is_empty() {
        pages.push(encode_da_blob(&[], params)?);
    } else {
        for page in blob.chunks(page_len) {
            pages.push(encode_da_blob(page, params)?);
        }
    }

    let page_roots = pages.iter().map(|page| page.root()).collect::<Vec<_>>();
    let page_merkle_levels = build_page_root_levels(&page_roots);

    Ok(DaMultiEncoding {
        params,
        page_len: page_len as u64,
        pages,
        page_roots,
        page_merkle_levels,
    })
}

pub fn da_root(blob: &[u8], params: DaParams) -> Result<DaRoot, DaError> {
    let encoding = encode_da_blob(blob, params)?;
    Ok(encoding.root())
}

pub fn verify_da_chunk(root: DaRoot, proof: &DaChunkProof) -> Result<(), DaError> {
    if !da_chunk_merkle_path_len_is_admissible(proof.merkle_path.len()) {
        return Err(DaError::ProofPathTooLong {
            path_len: proof.merkle_path.len(),
            max: MAX_DA_CHUNK_MERKLE_PATH_LEN,
        });
    }
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

pub fn verify_da_multi_chunk(root: DaRoot, proof: &DaMultiChunkProof) -> Result<(), DaError> {
    verify_da_chunk(proof.page_root, &proof.page_proof)?;
    verify_page_root(
        root,
        proof.page_index,
        proof.page_root,
        &proof.page_merkle_path,
    )
}

pub fn da_chunk_merkle_path_len_is_admissible(path_len: usize) -> bool {
    path_len <= MAX_DA_CHUNK_MERKLE_PATH_LEN
}

pub fn da_page_merkle_path_len_is_admissible(path_len: usize) -> bool {
    path_len <= MAX_DA_PAGE_MERKLE_PATH_LEN
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
    validate_shard_allocation(total, chunk_size)?;
    Ok(total)
}

fn validate_params(params: DaParams) -> Result<(), DaError> {
    if params.chunk_size == 0 {
        return Err(DaError::ChunkSizeZero);
    }
    if params.chunk_size > MAX_DA_CHUNK_SIZE {
        return Err(DaError::ChunkSizeTooLarge {
            chunk_size: params.chunk_size,
            max: MAX_DA_CHUNK_SIZE,
        });
    }
    if params.sample_count < MIN_SAMPLE_COUNT {
        return Err(DaError::SampleCountZero);
    }
    Ok(())
}

fn validate_shard_allocation(total_shards: usize, chunk_size: usize) -> Result<(), DaError> {
    let total_bytes =
        total_shards
            .checked_mul(chunk_size)
            .ok_or(DaError::ShardAllocationTooLarge {
                total_bytes: usize::MAX,
                max: MAX_DA_TOTAL_SHARD_BYTES,
            })?;
    if total_bytes > MAX_DA_TOTAL_SHARD_BYTES {
        return Err(DaError::ShardAllocationTooLarge {
            total_bytes,
            max: MAX_DA_TOTAL_SHARD_BYTES,
        });
    }
    Ok(())
}

fn max_page_len(params: DaParams) -> Result<usize, DaError> {
    validate_params(params)?;
    let chunk_size = params.chunk_size as usize;
    let data_shards = max_data_shards();
    chunk_size
        .checked_mul(data_shards)
        .ok_or(DaError::ShardCountOverflow)
}

fn max_data_shards() -> usize {
    let mut data_shards = MAX_SHARDS;
    while data_shards > 0 {
        let parity = parity_shards_for_data(data_shards);
        if data_shards + parity <= MAX_SHARDS {
            return data_shards;
        }
        data_shards -= 1;
    }
    1
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
    let parity = data_shards.div_ceil(2);
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

fn build_page_root_levels(page_roots: &[DaRoot]) -> Vec<Vec<DaRoot>> {
    let mut leaves: Vec<DaRoot> = page_roots
        .iter()
        .enumerate()
        .map(|(idx, root)| hash_leaf(idx as u32, root))
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

fn verify_page_root(
    root: DaRoot,
    page_index: u32,
    page_root: DaRoot,
    merkle_path: &[DaRoot],
) -> Result<(), DaError> {
    if !da_page_merkle_path_len_is_admissible(merkle_path.len()) {
        return Err(DaError::ProofPathTooLong {
            path_len: merkle_path.len(),
            max: MAX_DA_PAGE_MERKLE_PATH_LEN,
        });
    }
    if merkle_path.is_empty() {
        if hash_leaf(page_index, &page_root) == root {
            return Ok(());
        }
        return Err(DaError::MerkleProof);
    }
    let mut hash = hash_leaf(page_index, &page_root);
    let mut idx = page_index as usize;
    for sibling in merkle_path {
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

fn hash_leaf(index: u32, data: &[u8]) -> DaRoot {
    let input = da_leaf_preimage(index, data);
    blake3_384(&input)
}

fn hash_node(left: &DaRoot, right: &DaRoot) -> DaRoot {
    let input = da_node_preimage(left, right);
    blake3_384(&input)
}

pub fn da_leaf_preimage(index: u32, data: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(LEAF_DOMAIN.len() + 4 + data.len());
    input.extend_from_slice(LEAF_DOMAIN);
    input.extend_from_slice(&index.to_le_bytes());
    input.extend_from_slice(data);
    input
}

pub fn da_node_preimage(left: &DaRoot, right: &DaRoot) -> [u8; 48 * 2 + 7] {
    let mut input = [0u8; 48 * 2 + 7];
    input[..NODE_DOMAIN.len()].copy_from_slice(NODE_DOMAIN);
    let mut offset = NODE_DOMAIN.len();
    input[offset..offset + 48].copy_from_slice(left);
    offset += 48;
    input[offset..offset + 48].copy_from_slice(right);
    input
}

pub fn da_merkle_step_preimage(index: u32, current: &DaRoot, sibling: &DaRoot) -> [u8; 48 * 2 + 7] {
    if (index as usize).is_multiple_of(2) {
        da_node_preimage(current, sibling)
    } else {
        da_node_preimage(sibling, current)
    }
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

    fn deterministic_blob(len: usize, domain: u8) -> Vec<u8> {
        (0..len)
            .map(|idx| {
                let idx = idx as u64;
                (idx.wrapping_mul(37)
                    .wrapping_add(idx.rotate_left(7))
                    .wrapping_add(domain as u64)
                    & 0xff) as u8
            })
            .collect()
    }

    fn oracle_da_leaf(index: u32, data: &[u8]) -> DaRoot {
        let mut input = Vec::with_capacity(b"da-leaf".len() + 4 + data.len());
        input.extend_from_slice(b"da-leaf");
        input.extend_from_slice(&index.to_le_bytes());
        input.extend_from_slice(data);
        crypto::hashes::blake3_384(&input)
    }

    fn oracle_da_node(left: &DaRoot, right: &DaRoot) -> DaRoot {
        let mut input = Vec::with_capacity(b"da-node".len() + 48 + 48);
        input.extend_from_slice(b"da-node");
        input.extend_from_slice(left);
        input.extend_from_slice(right);
        crypto::hashes::blake3_384(&input)
    }

    fn oracle_levels_from_leaves(mut leaves: Vec<DaRoot>) -> Vec<Vec<DaRoot>> {
        if leaves.is_empty() {
            leaves.push(oracle_da_leaf(0, &[]));
        }
        let mut levels = vec![leaves];
        while levels.last().expect("oracle level exists").len() > 1 {
            let prev = levels.last().expect("oracle level exists");
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            for pair in prev.chunks(2) {
                let left = pair[0];
                let right = if pair.len() == 2 { pair[1] } else { pair[0] };
                next.push(oracle_da_node(&left, &right));
            }
            levels.push(next);
        }
        levels
    }

    fn oracle_chunk_levels(chunks: &[DaChunk]) -> Vec<Vec<DaRoot>> {
        oracle_levels_from_leaves(
            chunks
                .iter()
                .map(|chunk| oracle_da_leaf(chunk.index, &chunk.data))
                .collect(),
        )
    }

    fn oracle_page_root_levels(page_roots: &[DaRoot]) -> Vec<Vec<DaRoot>> {
        oracle_levels_from_leaves(
            page_roots
                .iter()
                .enumerate()
                .map(|(index, page_root)| oracle_da_leaf(index as u32, page_root))
                .collect(),
        )
    }

    fn oracle_root(levels: &[Vec<DaRoot>]) -> DaRoot {
        levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .unwrap_or([0u8; 48])
    }

    fn oracle_proof_path(levels: &[Vec<DaRoot>], index: usize) -> Vec<DaRoot> {
        let mut path = Vec::with_capacity(levels.len().saturating_sub(1));
        let mut node_index = index;
        for level in &levels[..levels.len().saturating_sub(1)] {
            let sibling_index = if node_index % 2 == 0 {
                (node_index + 1).min(level.len() - 1)
            } else {
                node_index - 1
            };
            path.push(level[sibling_index]);
            node_index /= 2;
        }
        path
    }

    fn oracle_replay_leaf_path(index: u32, data: &[u8], path: &[DaRoot]) -> DaRoot {
        let mut hash = oracle_da_leaf(index, data);
        let mut node_index = index as usize;
        for sibling in path {
            hash = if node_index % 2 == 0 {
                oracle_da_node(&hash, sibling)
            } else {
                oracle_da_node(sibling, &hash)
            };
            node_index /= 2;
        }
        hash
    }

    fn oracle_replay_chunk(proof: &DaChunkProof) -> DaRoot {
        oracle_replay_leaf_path(proof.chunk.index, &proof.chunk.data, &proof.merkle_path)
    }

    fn oracle_replay_page_root(proof: &DaMultiChunkProof) -> DaRoot {
        oracle_replay_leaf_path(proof.page_index, &proof.page_root, &proof.page_merkle_path)
    }

    fn selected_chunk_indices(chunk_count: usize) -> Vec<u32> {
        let mut indices = Vec::new();
        for index in [0, chunk_count / 2, chunk_count.saturating_sub(1)] {
            let index = index as u32;
            if !indices.contains(&index) {
                indices.push(index);
            }
        }
        indices
    }

    fn assert_encoding_matches_oracle(label: &str, encoding: &DaEncoding) {
        let levels = oracle_chunk_levels(encoding.chunks());
        assert_eq!(
            oracle_root(&levels),
            encoding.root(),
            "{label}: oracle chunk root must match production root"
        );
        for chunk_index in selected_chunk_indices(encoding.chunks().len()) {
            let proof = encoding.proof(chunk_index).expect("production proof");
            assert_eq!(
                oracle_proof_path(&levels, chunk_index as usize),
                proof.merkle_path,
                "{label}: oracle proof path must match production path for chunk {chunk_index}"
            );
            assert_eq!(
                oracle_replay_chunk(&proof),
                encoding.root(),
                "{label}: oracle chunk proof replay must reach production root"
            );
            verify_da_chunk(encoding.root(), &proof)
                .unwrap_or_else(|err| panic!("{label}: production chunk proof rejected: {err}"));
        }
    }

    fn assert_multipage_encoding_matches_oracle(label: &str, encoding: &DaMultiEncoding) {
        let mut page_roots = Vec::with_capacity(encoding.pages().len());
        for (page_index, page) in encoding.pages().iter().enumerate() {
            assert_encoding_matches_oracle(&format!("{label}: page {page_index}"), page);
            page_roots.push(page.root());
        }
        assert_eq!(
            page_roots, encoding.page_roots,
            "{label}: production page roots must match page encodings"
        );

        let page_levels = oracle_page_root_levels(&page_roots);
        assert_eq!(
            oracle_root(&page_levels),
            encoding.root(),
            "{label}: oracle page-root tree must match production root"
        );

        let mut global_indices = Vec::new();
        global_indices.push(0);
        if encoding.pages().len() > 1 {
            global_indices.push(MAX_SHARDS as u32);
        }
        let last_page_index = encoding.pages().len() - 1;
        let last_chunk_index = encoding.pages()[last_page_index].chunks().len() - 1;
        let last_global_index = last_page_index * MAX_SHARDS + last_chunk_index;
        if !global_indices.contains(&(last_global_index as u32)) {
            global_indices.push(last_global_index as u32);
        }

        for global_index in global_indices {
            let proof = encoding.proof(global_index).expect("multipage proof");
            let page_index = proof.page_index as usize;
            let chunk_levels = oracle_chunk_levels(encoding.pages()[page_index].chunks());
            assert_eq!(
                oracle_proof_path(&chunk_levels, proof.page_proof.chunk.index as usize),
                proof.page_proof.merkle_path,
                "{label}: oracle chunk path must match production multipage path"
            );
            assert_eq!(
                oracle_replay_chunk(&proof.page_proof),
                proof.page_root,
                "{label}: oracle chunk replay must reach production page root"
            );
            assert_eq!(
                oracle_proof_path(&page_levels, page_index),
                proof.page_merkle_path,
                "{label}: oracle page path must match production page path"
            );
            assert_eq!(
                oracle_replay_page_root(&proof),
                encoding.root(),
                "{label}: oracle page proof replay must reach production root"
            );
            verify_da_multi_chunk(encoding.root(), &proof).unwrap_or_else(|err| {
                panic!("{label}: production multipage proof rejected: {err}")
            });
        }
    }

    fn assert_chunk_rejected(root: DaRoot, proof: &DaChunkProof, label: &str) {
        assert_ne!(
            oracle_replay_chunk(proof),
            root,
            "{label}: oracle replay should not reach root after mutation"
        );
        assert!(
            verify_da_chunk(root, proof).is_err(),
            "{label}: production verifier accepted mutated chunk proof"
        );
    }

    fn assert_multi_rejected(root: DaRoot, proof: &DaMultiChunkProof, label: &str) {
        let chunk_replay = oracle_replay_chunk(&proof.page_proof);
        let page_replay = oracle_replay_page_root(proof);
        assert!(
            chunk_replay != proof.page_root || page_replay != root,
            "{label}: oracle replay should not accept mutated multipage proof"
        );
        assert!(
            verify_da_multi_chunk(root, proof).is_err(),
            "{label}: production verifier accepted mutated multipage proof"
        );
    }

    #[test]
    fn da_proof_verifier_rejects_overlong_paths_before_hash_replay() {
        let params = DaParams {
            chunk_size: 8,
            sample_count: 1,
        };
        let encoding = encode_da_blob(&deterministic_blob(17, 0x51), params).expect("encode");
        let mut chunk_proof = encoding.proof(1).expect("chunk proof");
        chunk_proof.merkle_path =
            vec![[0x33u8; 48]; MAX_DA_CHUNK_MERKLE_PATH_LEN.saturating_add(1)];
        match verify_da_chunk(encoding.root(), &chunk_proof) {
            Err(DaError::ProofPathTooLong { path_len, max }) => {
                assert_eq!(path_len, MAX_DA_CHUNK_MERKLE_PATH_LEN + 1);
                assert_eq!(max, MAX_DA_CHUNK_MERKLE_PATH_LEN);
            }
            other => panic!("expected chunk proof path cap rejection, got {other:?}"),
        }

        let page_len = max_page_len(params).expect("page len");
        let multi = encode_da_blob_multipage(&deterministic_blob(page_len + 17, 0x52), params)
            .expect("multipage encode");
        let mut multi_proof = multi.proof(MAX_SHARDS as u32).expect("multipage proof");
        multi_proof.page_merkle_path =
            vec![[0x44u8; 48]; MAX_DA_PAGE_MERKLE_PATH_LEN.saturating_add(1)];
        match verify_da_multi_chunk(multi.root(), &multi_proof) {
            Err(DaError::ProofPathTooLong { path_len, max }) => {
                assert_eq!(path_len, MAX_DA_PAGE_MERKLE_PATH_LEN + 1);
                assert_eq!(max, MAX_DA_PAGE_MERKLE_PATH_LEN);
            }
            other => panic!("expected page proof path cap rejection, got {other:?}"),
        }
    }

    #[test]
    fn da_params_reject_oversized_chunk_before_allocation() {
        let params = DaParams {
            chunk_size: MAX_DA_CHUNK_SIZE + 1,
            sample_count: 1,
        };
        match encode_da_blob(&[], params) {
            Err(DaError::ChunkSizeTooLarge { chunk_size, max }) => {
                assert_eq!(chunk_size, MAX_DA_CHUNK_SIZE + 1);
                assert_eq!(max, MAX_DA_CHUNK_SIZE);
            }
            other => panic!("expected oversized chunk rejection, got {other:?}"),
        }
        match chunk_count_for_blob(0, params) {
            Err(DaError::ChunkSizeTooLarge { chunk_size, max }) => {
                assert_eq!(chunk_size, MAX_DA_CHUNK_SIZE + 1);
                assert_eq!(max, MAX_DA_CHUNK_SIZE);
            }
            other => panic!("expected public chunk-count oversized rejection, got {other:?}"),
        }
    }

    #[test]
    fn da_shard_allocation_budget_is_enforced_before_allocation() {
        let oversized_total = MAX_DA_TOTAL_SHARD_BYTES + 1;
        match validate_shard_allocation(1, oversized_total) {
            Err(DaError::ShardAllocationTooLarge { total_bytes, max }) => {
                assert_eq!(total_bytes, oversized_total);
                assert_eq!(max, MAX_DA_TOTAL_SHARD_BYTES);
            }
            other => panic!("expected shard allocation budget rejection, got {other:?}"),
        }
    }

    #[test]
    fn da_merkle_oracle_matches_production_and_rejects_orientation_mutations() {
        let params = DaParams {
            chunk_size: 8,
            sample_count: 4,
        };

        let empty = encode_da_blob(&[], params).expect("encode empty");
        assert_eq!(empty.chunks().len(), 2);
        assert_encoding_matches_oracle("empty blob", &empty);

        let empty_multipage =
            encode_da_blob_multipage(&[], params).expect("encode empty multipage");
        assert_eq!(empty_multipage.pages().len(), 1);
        assert_multipage_encoding_matches_oracle("empty multipage blob", &empty_multipage);

        let single_page =
            encode_da_blob(&deterministic_blob(8, 0x11), params).expect("encode single-page blob");
        assert_eq!(single_page.chunks().len(), 2);
        assert_encoding_matches_oracle("single-page blob", &single_page);

        let single_page_multipage = encode_da_blob_multipage(&deterministic_blob(8, 0x12), params)
            .expect("encode single-page multipage blob");
        assert_eq!(single_page_multipage.pages().len(), 1);
        assert_multipage_encoding_matches_oracle(
            "single-page multipage blob",
            &single_page_multipage,
        );

        let odd_leaf_page =
            encode_da_blob(&deterministic_blob(9, 0x29), params).expect("encode odd leaf page");
        assert_eq!(odd_leaf_page.chunks().len(), 3);
        assert_encoding_matches_oracle("odd leaf page", &odd_leaf_page);

        let odd_leaf_multipage = encode_da_blob_multipage(&deterministic_blob(9, 0x2a), params)
            .expect("encode odd leaf multipage blob");
        assert_eq!(odd_leaf_multipage.pages().len(), 1);
        assert_eq!(odd_leaf_multipage.pages()[0].chunks().len(), 3);
        assert_multipage_encoding_matches_oracle("odd leaf multipage blob", &odd_leaf_multipage);

        let page_len = max_page_len(params).expect("page len");
        let multipage_blob = deterministic_blob(page_len * 2 + 17, 0x43);
        let multipage =
            encode_da_blob_multipage(&multipage_blob, params).expect("encode multipage blob");
        assert_eq!(multipage.pages().len(), 3);
        assert!(
            multipage
                .pages()
                .iter()
                .any(|page| page.chunks().len() % 2 == 1),
            "multipage fixture must cover duplicate-last odd chunk padding"
        );
        assert_multipage_encoding_matches_oracle("multipage blob", &multipage);

        let odd_root = odd_leaf_page.root();
        let mut flipped_index = odd_leaf_page.proof(2).expect("odd proof");
        flipped_index.chunk.index ^= 1;
        assert_chunk_rejected(odd_root, &flipped_index, "flipped chunk index");

        let mut swapped_siblings = odd_leaf_page.proof(1).expect("odd proof");
        swapped_siblings.merkle_path.swap(0, 1);
        assert_chunk_rejected(odd_root, &swapped_siblings, "swapped chunk sibling order");

        let mut flipped_sibling = odd_leaf_page.proof(1).expect("odd proof");
        flipped_sibling.merkle_path[0][0] ^= 0x01;
        assert_chunk_rejected(odd_root, &flipped_sibling, "flipped chunk path sibling");

        let multipage_root = multipage.root();
        let base_multi_proof = multipage.proof(MAX_SHARDS as u32).expect("multipage proof");

        let mut flipped_page_index = base_multi_proof.clone();
        flipped_page_index.page_index ^= 1;
        assert_multi_rejected(
            multipage_root,
            &flipped_page_index,
            "flipped multipage page index",
        );

        let mut flipped_page_root = base_multi_proof.clone();
        flipped_page_root.page_root[0] ^= 0x01;
        assert_multi_rejected(
            multipage_root,
            &flipped_page_root,
            "flipped multipage page root",
        );

        let mut flipped_page_sibling = base_multi_proof.clone();
        flipped_page_sibling.page_merkle_path[0][0] ^= 0x01;
        assert_multi_rejected(
            multipage_root,
            &flipped_page_sibling,
            "flipped multipage page sibling",
        );
    }

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
    fn multipage_encode_and_verify_roundtrip() {
        let params = DaParams {
            chunk_size: 64,
            sample_count: 4,
        };
        let page_len = max_page_len(params).expect("page len");
        let mut blob = vec![0u8; page_len + 1];
        rand::thread_rng().fill_bytes(&mut blob);
        let encoding = encode_da_blob_multipage(&blob, params).expect("encode");
        assert!(encoding.pages().len() > 1);
        let proof = encoding.proof(MAX_SHARDS as u32).expect("proof");
        verify_da_multi_chunk(encoding.root(), &proof).expect("verify");
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
    fn multipage_tampered_chunk_fails() {
        let params = DaParams {
            chunk_size: 64,
            sample_count: 4,
        };
        let page_len = max_page_len(params).expect("page len");
        let blob = vec![7u8; page_len + 1];
        let encoding = encode_da_blob_multipage(&blob, params).expect("encode");
        let mut proof = encoding.proof(MAX_SHARDS as u32).expect("proof");
        proof.page_proof.chunk.data[0] ^= 0xFF;
        assert!(verify_da_multi_chunk(encoding.root(), &proof).is_err());
    }

    #[test]
    fn empty_blob_still_hashes() {
        let params = DaParams {
            chunk_size: 512,
            sample_count: 1,
        };
        let encoding = encode_da_blob(&[], params).expect("encode");
        assert_eq!(encoding.data_shards(), 1u64);
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
