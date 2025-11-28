//! Core types for the shielded pool pallet.
//!
//! This module defines the fundamental types used in shielded transactions:
//! - Note: The basic unit of value with hiding commitment
//! - EncryptedNote: Note encrypted for recipient with memo
//! - MerklePath: Authentication path for note in commitment tree

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_std::vec::Vec;

/// The depth of the Merkle tree for note commitments.
/// Depth 32 supports ~4 billion notes.
pub const MERKLE_TREE_DEPTH: u32 = 32;

/// Maximum number of nullifiers per transaction.
pub const MAX_NULLIFIERS_PER_TX: u32 = 4;

/// Maximum number of commitments (output notes) per transaction.
pub const MAX_COMMITMENTS_PER_TX: u32 = 4;

/// Size of a Groth16 proof in bytes (BLS12-381).
pub const GROTH16_PROOF_SIZE: usize = 192;

/// Size of a binding signature.
pub const BINDING_SIG_SIZE: usize = 64;

/// Size of the memo field in bytes.
pub const MEMO_SIZE: usize = 512;

/// Size of the encrypted note ciphertext.
/// Recipient (43) + Value (8) + Rcm (32) + Memo (512) + AEAD overhead (16)
pub const ENCRYPTED_NOTE_SIZE: usize = 611;

/// Diversified address size (post-quantum compatible).
pub const DIVERSIFIED_ADDRESS_SIZE: usize = 43;

/// A shielded note representing a unit of value.
///
/// Notes are the fundamental unit of value in the shielded pool.
/// They are never stored directly on-chain; only their commitments are.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct Note {
    /// Recipient's diversified address (PQ public key derived).
    pub recipient: [u8; DIVERSIFIED_ADDRESS_SIZE],
    /// Value in atomic units.
    pub value: u64,
    /// Unique randomness for commitment hiding.
    pub rcm: [u8; 32],
    /// Memo field for arbitrary data.
    pub memo: [u8; MEMO_SIZE],
}

impl Note {
    /// Create a new note with the given parameters.
    pub fn new(
        recipient: [u8; DIVERSIFIED_ADDRESS_SIZE],
        value: u64,
        rcm: [u8; 32],
        memo: [u8; MEMO_SIZE],
    ) -> Self {
        Self {
            recipient,
            value,
            rcm,
            memo,
        }
    }

    /// Create a note with a default (empty) memo.
    pub fn with_empty_memo(
        recipient: [u8; DIVERSIFIED_ADDRESS_SIZE],
        value: u64,
        rcm: [u8; 32],
    ) -> Self {
        Self {
            recipient,
            value,
            rcm,
            memo: [0u8; MEMO_SIZE],
        }
    }
}

/// Encrypted note ciphertext for on-chain storage.
///
/// This is the encrypted form of a Note that is stored on-chain.
/// Only the recipient can decrypt it using their viewing key.
#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct EncryptedNote {
    /// Encrypted ciphertext containing note data.
    pub ciphertext: [u8; ENCRYPTED_NOTE_SIZE],
    /// Ephemeral public key for ECDH key agreement.
    pub ephemeral_pk: [u8; 32],
}

impl Default for EncryptedNote {
    fn default() -> Self {
        Self {
            ciphertext: [0u8; ENCRYPTED_NOTE_SIZE],
            ephemeral_pk: [0u8; 32],
        }
    }
}

/// Groth16 ZK-SNARK proof for shielded transfers.
#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct Groth16Proof {
    /// The proof bytes (A, B, C points on BLS12-381).
    pub data: [u8; GROTH16_PROOF_SIZE],
}

impl Default for Groth16Proof {
    fn default() -> Self {
        Self {
            data: [0u8; GROTH16_PROOF_SIZE],
        }
    }
}

/// Binding signature for value balance verification.
#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct BindingSignature {
    /// The signature bytes.
    pub data: [u8; BINDING_SIG_SIZE],
}

impl Default for BindingSignature {
    fn default() -> Self {
        Self {
            data: [0u8; BINDING_SIG_SIZE],
        }
    }
}

/// Merkle authentication path for proving note membership.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct MerklePath {
    /// Sibling hashes from leaf to root.
    pub siblings: Vec<[u8; 32]>,
    /// Position bits indicating left/right at each level.
    pub position_bits: Vec<bool>,
}

impl MerklePath {
    /// Create a new Merkle path.
    pub fn new(siblings: Vec<[u8; 32]>, position_bits: Vec<bool>) -> Self {
        Self {
            siblings,
            position_bits,
        }
    }

    /// Get the depth of this path.
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }
}

/// A shielded transfer transaction.
///
/// This structure contains all the data needed for a shielded transfer:
/// - ZK proof that the transaction is valid
/// - Nullifiers for spent notes (prevents double-spending)
/// - Commitments for new notes (added to Merkle tree)
/// - Encrypted notes for recipients
/// - Anchor (Merkle root the proof was generated against)
/// - Binding signature (ensures value balance)
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct ShieldedTransfer<MaxNullifiers: Get<u32>, MaxCommitments: Get<u32>> {
    /// Groth16 proof.
    pub proof: Groth16Proof,
    /// Nullifiers for spent notes.
    pub nullifiers: BoundedVec<[u8; 32], MaxNullifiers>,
    /// New note commitments.
    pub commitments: BoundedVec<[u8; 32], MaxCommitments>,
    /// Encrypted notes for recipients.
    pub ciphertexts: BoundedVec<EncryptedNote, MaxCommitments>,
    /// Merkle root the proof was generated against.
    pub anchor: [u8; 32],
    /// Binding signature for value balance.
    pub binding_sig: BindingSignature,
    /// Net value change (positive = deposit from transparent, negative = withdraw to transparent).
    pub value_balance: i128,
}

/// Transfer direction for shielding/unshielding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub enum TransferType {
    /// Transparent to shielded (shielding).
    Shield,
    /// Shielded to shielded (private transfer).
    ShieldedToShielded,
    /// Shielded to transparent (unshielding).
    Unshield,
}

impl Default for TransferType {
    fn default() -> Self {
        Self::ShieldedToShielded
    }
}

impl DecodeWithMemTracking for TransferType {}

/// Parameters for the Groth16 verifying key.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub struct VerifyingKeyParams {
    /// The verifying key identifier.
    pub key_id: u32,
    /// Whether this key is active.
    pub active: bool,
    /// Block number when this key was activated.
    pub activated_at: u64,
}

impl Default for VerifyingKeyParams {
    fn default() -> Self {
        Self {
            key_id: 0,
            active: true,
            activated_at: 0,
        }
    }
}

impl DecodeWithMemTracking for VerifyingKeyParams {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_creation_works() {
        let recipient = [1u8; DIVERSIFIED_ADDRESS_SIZE];
        let value = 1000u64;
        let rcm = [2u8; 32];
        let memo = [3u8; MEMO_SIZE];

        let note = Note::new(recipient, value, rcm, memo);
        assert_eq!(note.recipient, recipient);
        assert_eq!(note.value, value);
        assert_eq!(note.rcm, rcm);
        assert_eq!(note.memo, memo);
    }

    #[test]
    fn note_with_empty_memo_works() {
        let recipient = [1u8; DIVERSIFIED_ADDRESS_SIZE];
        let value = 1000u64;
        let rcm = [2u8; 32];

        let note = Note::with_empty_memo(recipient, value, rcm);
        assert_eq!(note.memo, [0u8; MEMO_SIZE]);
    }

    #[test]
    fn encrypted_note_default_works() {
        let enc = EncryptedNote::default();
        assert_eq!(enc.ciphertext, [0u8; ENCRYPTED_NOTE_SIZE]);
        assert_eq!(enc.ephemeral_pk, [0u8; 32]);
    }

    #[test]
    fn merkle_path_depth_works() {
        let siblings = vec![[0u8; 32]; 5];
        let position_bits = vec![true, false, true, false, true];
        let path = MerklePath::new(siblings, position_bits);
        assert_eq!(path.depth(), 5);
    }
}
