//! Core epoch types and proof hash computation.
//!
//! An epoch is a fixed number of blocks (`EPOCH_SIZE`). At epoch boundaries,
//! all transaction proof hashes are accumulated into a Merkle tree, and an
//! epoch proof is generated that attests to the validity of the entire epoch.

use crate::dimensions::EPOCH_SIZE;

/// Compute Blake3-256 hash of input bytes.
///
/// Returns a 32-byte hash digest.
fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

fn blake3_hash_with_domain(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Epoch metadata committed to in the epoch proof.
///
/// This structure captures all the data that uniquely identifies an epoch
/// and its state. The commitment is computed as Blake3-256 of the serialized fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Epoch {
    /// Epoch number (0, 1, 2, ...).
    pub epoch_number: u64,
    /// First block number in this epoch.
    pub start_block: u64,
    /// Last block number in this epoch (inclusive).
    pub end_block: u64,
    /// Merkle root of all proof hashes in this epoch.
    pub proof_root: [u8; 32],
    /// State root at end of epoch.
    pub state_root: [u8; 32],
    /// Nullifier set root at end of epoch.
    pub nullifier_set_root: [u8; 32],
    /// Commitment tree root at end of epoch.
    pub commitment_tree_root: [u8; 32],
}

impl Epoch {
    /// Create a new epoch with the given number.
    ///
    /// Computes start/end blocks from epoch number.
    pub fn new(epoch_number: u64) -> Self {
        Self {
            epoch_number,
            start_block: epoch_number * EPOCH_SIZE,
            end_block: (epoch_number + 1) * EPOCH_SIZE - 1,
            proof_root: [0u8; 32],
            state_root: [0u8; 32],
            nullifier_set_root: [0u8; 32],
            commitment_tree_root: [0u8; 32],
        }
    }

    /// Compute the epoch commitment (used as public input).
    ///
    /// This is a Blake3-256 hash of all epoch metadata, providing a unique
    /// fingerprint that binds the epoch proof to specific chain state.
    pub fn commitment(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(256);
        data.extend_from_slice(&self.epoch_number.to_le_bytes());
        data.extend_from_slice(&self.start_block.to_le_bytes());
        data.extend_from_slice(&self.end_block.to_le_bytes());
        data.extend_from_slice(&self.proof_root);
        data.extend_from_slice(&self.state_root);
        data.extend_from_slice(&self.nullifier_set_root);
        data.extend_from_slice(&self.commitment_tree_root);
        blake3_hash(&data)
    }

    /// Check if a block number falls within this epoch.
    pub fn contains_block(&self, block_number: u64) -> bool {
        block_number >= self.start_block && block_number <= self.end_block
    }

    /// Get the epoch number for a given block number.
    pub fn epoch_for_block(block_number: u64) -> u64 {
        block_number / EPOCH_SIZE
    }
}

impl Default for Epoch {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Inputs for hashing a single transaction proof into an epoch leaf.
#[derive(Clone, Debug)]
pub struct ProofHashInputs<'a> {
    pub proof_bytes: &'a [u8],
    pub anchor: [u8; 32],
    pub nullifiers: &'a [[u8; 32]],
    pub commitments: &'a [[u8; 32]],
    pub fee: u64,
    pub value_balance: i128,
}

/// Inputs for hashing a batch transaction proof into an epoch leaf.
#[derive(Clone, Debug)]
pub struct BatchProofHashInputs<'a> {
    pub proof_bytes: &'a [u8],
    pub anchor: [u8; 32],
    pub nullifiers: &'a [[u8; 32]],
    pub commitments: &'a [[u8; 32]],
    pub total_fee: u128,
    pub batch_size: u32,
}

/// Compute the hash of a transaction proof and its public inputs.
///
/// This binds the epoch leaf to the public inputs required for verification.
pub fn proof_hash(inputs: &ProofHashInputs<'_>) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&inputs.anchor);
    buf.extend_from_slice(&(inputs.nullifiers.len() as u32).to_le_bytes());
    for nf in inputs.nullifiers {
        buf.extend_from_slice(nf);
    }
    buf.extend_from_slice(&(inputs.commitments.len() as u32).to_le_bytes());
    for cm in inputs.commitments {
        buf.extend_from_slice(cm);
    }
    buf.extend_from_slice(&inputs.fee.to_le_bytes());
    buf.extend_from_slice(&inputs.value_balance.to_le_bytes());
    buf.extend_from_slice(&(inputs.proof_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(inputs.proof_bytes);
    blake3_hash_with_domain(b"hegemon-proof-hash-v2", &buf)
}

/// Compute the hash of a batch proof and its public inputs.
pub fn batch_proof_hash(inputs: &BatchProofHashInputs<'_>) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&inputs.anchor);
    buf.extend_from_slice(&inputs.batch_size.to_le_bytes());
    buf.extend_from_slice(&(inputs.nullifiers.len() as u32).to_le_bytes());
    for nf in inputs.nullifiers {
        buf.extend_from_slice(nf);
    }
    buf.extend_from_slice(&(inputs.commitments.len() as u32).to_le_bytes());
    for cm in inputs.commitments {
        buf.extend_from_slice(cm);
    }
    buf.extend_from_slice(&inputs.total_fee.to_le_bytes());
    buf.extend_from_slice(&(inputs.proof_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(inputs.proof_bytes);
    blake3_hash_with_domain(b"hegemon-batch-proof-hash-v1", &buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_new() {
        let epoch = Epoch::new(0);
        assert_eq!(epoch.epoch_number, 0);
        assert_eq!(epoch.start_block, 0);
        assert_eq!(epoch.end_block, EPOCH_SIZE - 1);

        let epoch1 = Epoch::new(1);
        assert_eq!(epoch1.epoch_number, 1);
        assert_eq!(epoch1.start_block, EPOCH_SIZE);
        assert_eq!(epoch1.end_block, (2 * EPOCH_SIZE) - 1);
    }

    #[test]
    fn test_epoch_commitment_deterministic() {
        let mut epoch = Epoch::new(0);
        epoch.proof_root = [1u8; 32];
        epoch.state_root = [2u8; 32];
        epoch.nullifier_set_root = [3u8; 32];
        epoch.commitment_tree_root = [4u8; 32];

        let commitment1 = epoch.commitment();
        let commitment2 = epoch.commitment();

        assert_eq!(commitment1, commitment2);
        assert_ne!(commitment1, [0u8; 32]);
    }

    #[test]
    fn test_epoch_commitment_changes_with_data() {
        let mut epoch1 = Epoch::new(0);
        epoch1.proof_root = [1u8; 32];

        let mut epoch2 = Epoch::new(0);
        epoch2.proof_root = [2u8; 32];

        assert_ne!(epoch1.commitment(), epoch2.commitment());
    }

    #[test]
    fn test_contains_block() {
        let epoch = Epoch::new(1);
        assert!(!epoch.contains_block(EPOCH_SIZE - 1));
        assert!(epoch.contains_block(EPOCH_SIZE));
        assert!(epoch.contains_block(EPOCH_SIZE + (EPOCH_SIZE / 2)));
        assert!(epoch.contains_block((2 * EPOCH_SIZE) - 1));
        assert!(!epoch.contains_block(2 * EPOCH_SIZE));
    }

    #[test]
    fn test_epoch_for_block() {
        assert_eq!(Epoch::epoch_for_block(0), 0);
        assert_eq!(Epoch::epoch_for_block(EPOCH_SIZE - 1), 0);
        assert_eq!(Epoch::epoch_for_block(EPOCH_SIZE), 1);
        assert_eq!(Epoch::epoch_for_block(2 * EPOCH_SIZE + 10), 2);
    }

    #[test]
    fn test_proof_hash() {
        let proof = vec![1, 2, 3, 4, 5];
        let anchor = [9u8; 32];
        let nullifiers = vec![[1u8; 32]];
        let commitments = vec![[2u8; 32]];
        let inputs = ProofHashInputs {
            proof_bytes: &proof,
            anchor,
            nullifiers: &nullifiers,
            commitments: &commitments,
            fee: 7,
            value_balance: -5,
        };

        let hash = proof_hash(&inputs);
        assert_ne!(hash, [0u8; 32]);

        // Same input should produce same hash
        let hash2 = proof_hash(&inputs);
        assert_eq!(hash, hash2);

        // Different input should produce different hash
        let other_proof = vec![1, 2, 3, 4, 6];
        let other_inputs = ProofHashInputs {
            proof_bytes: &other_proof,
            anchor,
            nullifiers: &nullifiers,
            commitments: &commitments,
            fee: 7,
            value_balance: -5,
        };
        let other_hash = proof_hash(&other_inputs);
        assert_ne!(hash, other_hash);
    }

    #[test]
    fn test_batch_proof_hash() {
        let proof = vec![8, 7, 6, 5];
        let anchor = [5u8; 32];
        let nullifiers = vec![[3u8; 32], [4u8; 32]];
        let commitments = vec![[6u8; 32], [7u8; 32]];
        let inputs = BatchProofHashInputs {
            proof_bytes: &proof,
            anchor,
            nullifiers: &nullifiers,
            commitments: &commitments,
            total_fee: 42,
            batch_size: 2,
        };

        let hash = batch_proof_hash(&inputs);
        assert_ne!(hash, [0u8; 32]);

        let other_inputs = BatchProofHashInputs {
            proof_bytes: &proof,
            anchor,
            nullifiers: &nullifiers,
            commitments: &commitments,
            total_fee: 43,
            batch_size: 2,
        };
        let other_hash = batch_proof_hash(&other_inputs);
        assert_ne!(hash, other_hash);
    }
}
