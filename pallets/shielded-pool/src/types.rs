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

/// Maximum size of a STARK proof in bytes.
/// STARK proofs require NO trusted setup.
/// Typical range: 20KB-100KB depending on circuit complexity.
pub const STARK_PROOF_MAX_SIZE: usize = 65536;

/// Size of a binding signature.
pub const BINDING_SIG_SIZE: usize = 64;

/// Size of the memo field in bytes.
pub const MEMO_SIZE: usize = 512;

/// Size of the encrypted note ciphertext.
/// Recipient (43) + Value (8) + Rcm (32) + Memo (512) + AEAD overhead (16)
pub const ENCRYPTED_NOTE_SIZE: usize = 611;

/// Size of the ML-KEM-768 ciphertext for key encapsulation.
pub const ML_KEM_CIPHERTEXT_LEN: usize = 1088;

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
    /// ML-KEM-768 ciphertext for key encapsulation (1088 bytes).
    pub kem_ciphertext: [u8; ML_KEM_CIPHERTEXT_LEN],
}

impl Default for EncryptedNote {
    fn default() -> Self {
        Self {
            ciphertext: [0u8; ENCRYPTED_NOTE_SIZE],
            kem_ciphertext: [0u8; ML_KEM_CIPHERTEXT_LEN],
        }
    }
}

/// STARK proof for shielded transfers.
///
/// Uses a transparent proving system (FRI-based IOP) with no trusted setup.
/// Security relies only on hash functions.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct StarkProof {
    /// Variable-length proof data.
    /// Contains FRI layers, query responses, and auxiliary data.
    pub data: Vec<u8>,
}

impl Default for StarkProof {
    fn default() -> Self {
        Self {
            data: Vec::new(),
        }
    }
}

impl StarkProof {
    /// Create a proof from raw bytes.
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Check if the proof is empty (invalid).
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Balance commitment for value balance verification.
///
/// In the PQC model, value balance is verified inside the STARK proof itself.
/// This struct exists for API compatibility but is checked in-circuit.
#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct BindingSignature {
    /// Hash-based commitment to the value balance.
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

/// Coinbase note data for shielded mining rewards.
///
/// This structure contains the encrypted note plus public audit data.
/// The encrypted note can only be decrypted by the miner.
/// The plaintext fields allow public supply auditing.
#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct CoinbaseNoteData {
    /// The note commitment (H(note_contents))
    pub commitment: [u8; 32],
    /// Encrypted note for the miner (only they can decrypt)
    pub encrypted_note: EncryptedNote,
    /// Plaintext recipient address (for audit)
    pub recipient_address: [u8; DIVERSIFIED_ADDRESS_SIZE],
    /// Plaintext amount (for supply audit)
    pub amount: u64,
    /// Public seed for deterministic rho/r derivation
    /// seed = H("coinbase_seed" || block_hash || block_height)
    pub public_seed: [u8; 32],
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
/// - ZK proof that the transaction is valid (STARK)
/// - Nullifiers for spent notes (prevents double-spending)
/// - Commitments for new notes (added to Merkle tree)
/// - Encrypted notes for recipients
/// - Anchor (Merkle root the proof was generated against)
/// - Value balance commitment (verified in-circuit)
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct ShieldedTransfer<MaxNullifiers: Get<u32>, MaxCommitments: Get<u32>> {
    /// STARK proof (FRI-based, no trusted setup).
    pub proof: StarkProof,
    /// Nullifiers for spent notes.
    pub nullifiers: BoundedVec<[u8; 32], MaxNullifiers>,
    /// New note commitments.
    pub commitments: BoundedVec<[u8; 32], MaxCommitments>,
    /// Encrypted notes for recipients.
    pub ciphertexts: BoundedVec<EncryptedNote, MaxCommitments>,
    /// Merkle root the proof was generated against.
    pub anchor: [u8; 32],
    /// Value balance commitment (verified in STARK circuit).
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

/// Parameters for the STARK verifying key.
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
        assert_eq!(enc.kem_ciphertext, [0u8; ML_KEM_CIPHERTEXT_LEN]);
    }

    #[test]
    fn merkle_path_depth_works() {
        let siblings = vec![[0u8; 32]; 5];
        let position_bits = vec![true, false, true, false, true];
        let path = MerklePath::new(siblings, position_bits);
        assert_eq!(path.depth(), 5);
    }

    #[test]
    fn encrypted_note_scale_encoding() {
        // Create a test note with known data
        let mut note = EncryptedNote::default();
        note.ciphertext[0] = 0xAB;
        note.ciphertext[610] = 0xCD;
        note.kem_ciphertext[0] = 0xEF;
        note.kem_ciphertext[1087] = 0x99;

        // Encode it
        let encoded = note.encode();
        
        // Verify exact size - fixed arrays encode without length prefix
        assert_eq!(
            encoded.len(),
            ENCRYPTED_NOTE_SIZE + ML_KEM_CIPHERTEXT_LEN,
            "EncryptedNote should encode to exactly {} bytes",
            ENCRYPTED_NOTE_SIZE + ML_KEM_CIPHERTEXT_LEN
        );

        // Decode it back
        let decoded = EncryptedNote::decode(&mut &encoded[..])
            .expect("Should decode successfully");
        
        assert_eq!(decoded.ciphertext[0], 0xAB);
        assert_eq!(decoded.ciphertext[610], 0xCD);
        assert_eq!(decoded.kem_ciphertext[0], 0xEF);
        assert_eq!(decoded.kem_ciphertext[1087], 0x99);
    }

    #[test]
    fn encrypted_note_raw_bytes_decode() {
        // Simulate wallet-style encoding (just concatenating raw bytes)
        let mut raw_bytes = vec![0u8; ENCRYPTED_NOTE_SIZE + ML_KEM_CIPHERTEXT_LEN];
        raw_bytes[0] = 0x42;  // first byte of ciphertext
        raw_bytes[ENCRYPTED_NOTE_SIZE] = 0x43;  // first byte of kem_ciphertext
        
        // This should decode correctly
        let decoded = EncryptedNote::decode(&mut raw_bytes.as_slice())
            .expect("Should decode raw concatenated bytes");
        
        assert_eq!(decoded.ciphertext[0], 0x42);
        assert_eq!(decoded.kem_ciphertext[0], 0x43);
    }
}
