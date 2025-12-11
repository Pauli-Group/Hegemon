//! Core epoch types and proof hash computation.
//!
//! An epoch is a fixed number of blocks (1000 by default). At epoch boundaries,
//! all transaction proof hashes are accumulated into a Merkle tree, and an
//! epoch proof is generated that attests to the validity of the entire epoch.

use crate::dimensions::EPOCH_SIZE;

/// Compute Blake3-256 hash of input bytes.
///
/// Returns a 32-byte hash digest.
fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
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

/// Compute the hash of a serialized STARK proof.
///
/// Uses Blake3-256 to create a 32-byte digest of the proof bytes.
/// This hash is used as a leaf in the epoch's Merkle tree.
pub fn proof_hash(proof_bytes: &[u8]) -> [u8; 32] {
    blake3_hash(proof_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_new() {
        let epoch = Epoch::new(0);
        assert_eq!(epoch.epoch_number, 0);
        assert_eq!(epoch.start_block, 0);
        assert_eq!(epoch.end_block, 999);

        let epoch1 = Epoch::new(1);
        assert_eq!(epoch1.epoch_number, 1);
        assert_eq!(epoch1.start_block, 1000);
        assert_eq!(epoch1.end_block, 1999);
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
        assert!(!epoch.contains_block(999));
        assert!(epoch.contains_block(1000));
        assert!(epoch.contains_block(1500));
        assert!(epoch.contains_block(1999));
        assert!(!epoch.contains_block(2000));
    }

    #[test]
    fn test_epoch_for_block() {
        assert_eq!(Epoch::epoch_for_block(0), 0);
        assert_eq!(Epoch::epoch_for_block(999), 0);
        assert_eq!(Epoch::epoch_for_block(1000), 1);
        assert_eq!(Epoch::epoch_for_block(2500), 2);
    }

    #[test]
    fn test_proof_hash() {
        let proof = vec![1, 2, 3, 4, 5];
        let hash = proof_hash(&proof);
        assert_ne!(hash, [0u8; 32]);

        // Same input should produce same hash
        let hash2 = proof_hash(&proof);
        assert_eq!(hash, hash2);

        // Different input should produce different hash
        let other_proof = vec![1, 2, 3, 4, 6];
        let other_hash = proof_hash(&other_proof);
        assert_ne!(hash, other_hash);
    }
}
