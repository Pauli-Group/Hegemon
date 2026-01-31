//! Core types for the shielded pool pallet.
//!
//! This module defines the fundamental types used in shielded transactions:
//! - Note: The basic unit of value with hiding commitment
//! - EncryptedNote: Note encrypted for recipient with memo
//! - MerklePath: Authentication path for note in commitment tree

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_std::vec;
use sp_std::vec::Vec;

/// The depth of the Merkle tree for note commitments.
/// Must match CIRCUIT_MERKLE_DEPTH in transaction-circuit.
/// Depth 32 supports 4 billion notes.
pub const MERKLE_TREE_DEPTH: u32 = 32;

/// Maximum number of nullifiers per transaction.
pub const MAX_NULLIFIERS_PER_TX: u32 = 2;

/// Maximum number of commitments (output notes) per transaction.
pub const MAX_COMMITMENTS_PER_TX: u32 = 2;

/// Maximum size of a STARK proof in bytes.
/// STARK proofs require NO trusted setup.
/// Proof size is configuration-dependent (FRI params, trace width/rows, hash digest).
/// We cap proofs to prevent DoS via oversized extrinsics while still allowing
/// production Plonky3 proofs to fit within runtime block length limits.
///
/// Note: Production Plonky3 transaction proofs are ~350–500KB today; this limit is a DoS
/// guardrail, not a target size.
pub const STARK_PROOF_MAX_SIZE: usize = 2 * 1024 * 1024;

/// Size of a binding hash.
pub const BINDING_HASH_SIZE: usize = 64;

/// Size of the memo field in bytes.
pub const MEMO_SIZE: usize = 512;

/// Note encryption version used in the ciphertext header.
pub const NOTE_ENCRYPTION_VERSION: u8 = 2;
/// Crypto suite identifier for ML-KEM-1024 note encryption.
pub const CRYPTO_SUITE_GAMMA: u16 = 3;

/// Size of the encrypted note ciphertext container.
/// Layout: version(1) + crypto_suite(2) + diversifier_index(4) + note_len(4) + note_payload +
/// memo_len(4) + memo_payload + padding.
pub const ENCRYPTED_NOTE_SIZE: usize = 579;

/// Maximum size of the ML-KEM ciphertext for key encapsulation.
pub const MAX_KEM_CIPHERTEXT_LEN: u32 = 1568;
/// Maximum total ciphertext bytes (container + KEM ciphertext).
pub const MAX_CIPHERTEXT_BYTES: usize = ENCRYPTED_NOTE_SIZE + MAX_KEM_CIPHERTEXT_LEN as usize;

/// Diversified address size used inside commitments: version(1) + diversifier_index(4) + pk_recipient(32).
pub const DIVERSIFIED_ADDRESS_SIZE: usize = 37;

/// Commitment bytes (48-byte PQ sponge output).
pub type Commitment = [u8; 48];
/// Nullifier bytes (48-byte PQ sponge output).
pub type Nullifier = [u8; 48];
/// Merkle root bytes (48-byte PQ sponge output).
pub type MerkleRoot = [u8; 48];

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
    /// ML-KEM ciphertext for key encapsulation (suite-dependent length).
    pub kem_ciphertext: BoundedVec<u8, ConstU32<MAX_KEM_CIPHERTEXT_LEN>>,
}

impl Default for EncryptedNote {
    fn default() -> Self {
        Self {
            ciphertext: [0u8; ENCRYPTED_NOTE_SIZE],
            kem_ciphertext: BoundedVec::truncate_from(vec![0u8; MAX_KEM_CIPHERTEXT_LEN as usize]),
        }
    }
}

/// STARK proof for shielded transfers.
///
/// Uses a transparent proving system (FRI-based IOP) with no trusted setup.
/// Security relies only on hash functions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct StarkProof {
    /// Variable-length proof data.
    /// Contains FRI layers, query responses, and auxiliary data.
    pub data: Vec<u8>,
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
pub struct BindingHash {
    /// Hash-based commitment to the value balance.
    pub data: [u8; BINDING_HASH_SIZE],
}

impl Default for BindingHash {
    fn default() -> Self {
        Self {
            data: [0u8; BINDING_HASH_SIZE],
        }
    }
}

/// Stablecoin policy binding for issuance proofs.
///
/// When present, these fields are bound into the transaction proof and must
/// match on-chain policy, oracle, and attestation commitments.
#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct StablecoinPolicyBinding {
    /// Stablecoin asset identifier (MASP asset id).
    pub asset_id: u64,
    /// Deterministic policy hash (BLAKE3-384).
    pub policy_hash: [u8; 48],
    /// Latest oracle commitment bound into the proof.
    pub oracle_commitment: [u8; 48],
    /// Latest attestation commitment bound into the proof.
    pub attestation_commitment: [u8; 48],
    /// Signed issuance delta (positive for mint, negative for burn).
    pub issuance_delta: i128,
    /// Policy version to make upgrades explicit.
    pub policy_version: u32,
}

/// Data availability validation policy for block import.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    MaxEncodedLen,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum DaAvailabilityPolicy {
    /// Require full DA fetch and verify `da_root` against the reconstructed blob.
    FullFetch,
    /// Require only randomized sampling of DA chunks (no full reconstruction).
    Sampling,
}

impl Default for DaAvailabilityPolicy {
    fn default() -> Self {
        DaAvailabilityPolicy::FullFetch
    }
}

/// Policy for allowing inline ciphertext bytes inside extrinsics.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    MaxEncodedLen,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum CiphertextPolicy {
    /// Inline ciphertexts are permitted (legacy path).
    InlineAllowed,
    /// Inline ciphertexts are rejected; sidecar-only is enforced.
    SidecarOnly,
}

impl Default for CiphertextPolicy {
    fn default() -> Self {
        CiphertextPolicy::InlineAllowed
    }
}

/// Policy for how per-transaction proof bytes are made available to verifiers.
///
/// This matters only in "aggregation mode", where the runtime may skip per-transaction proof
/// verification and instead rely on an aggregation proof verified during block import.
///
/// In Phase A ("proof availability by DA"), we allow transfers to omit proof bytes from the
/// extrinsic, but we require the block to commit to the proof bytes via a DA root so other
/// validators can retrieve them and verify the aggregation proof deterministically.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    MaxEncodedLen,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum ProofAvailabilityPolicy {
    /// Each transfer extrinsic must carry its STARK proof bytes (legacy path).
    InlineRequired,
    /// Transfer extrinsics may omit proof bytes in aggregation mode, but proof bytes must be made
    /// available via a DA commitment during block import.
    DaRequired,
}

impl Default for ProofAvailabilityPolicy {
    fn default() -> Self {
        ProofAvailabilityPolicy::InlineRequired
    }
}

/// On-chain manifest entry for locating per-transaction proof bytes in proof-DA.
///
/// The `binding_hash` identifies the transfer this proof belongs to. The `(proof_len, proof_offset)`
/// pair describes where the proof bytes live inside the proof-DA blob committed by
/// `submit_proof_da_commitment`.
///
/// The `proof_hash` (BLAKE3-384) is committed on-chain so verifiers can bind commitment proofs and
/// other block-level commitments without downloading the proof bytes.
#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen,
)]
pub struct ProofDaManifestEntry {
    pub binding_hash: BindingHash,
    pub proof_hash: [u8; 48],
    pub proof_len: u32,
    pub proof_offset: u32,
}

impl Default for StablecoinPolicyBinding {
    fn default() -> Self {
        Self {
            asset_id: 0,
            policy_hash: [0u8; 48],
            oracle_commitment: [0u8; 48],
            attestation_commitment: [0u8; 48],
            issuance_delta: 0,
            policy_version: 0,
        }
    }
}

/// Merkle authentication path for proving note membership.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct MerklePath {
    /// Sibling hashes from leaf to root.
    pub siblings: Vec<Commitment>,
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
    pub commitment: [u8; 48],
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
    pub fn new(siblings: Vec<Commitment>, position_bits: Vec<bool>) -> Self {
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
    pub nullifiers: BoundedVec<Nullifier, MaxNullifiers>,
    /// New note commitments.
    pub commitments: BoundedVec<Commitment, MaxCommitments>,
    /// Encrypted notes for recipients.
    pub ciphertexts: BoundedVec<EncryptedNote, MaxCommitments>,
    /// Merkle root the proof was generated against.
    pub anchor: MerkleRoot,
    /// Value balance commitment (verified in STARK circuit).
    pub binding_hash: BindingHash,
    /// Optional stablecoin policy binding (required for issuance/burn).
    pub stablecoin: Option<StablecoinPolicyBinding>,
    /// Native fee encoded in the proof.
    pub fee: u64,
    /// Net value change (must be 0 when no transparent pool is enabled).
    pub value_balance: i128,
}

/// Proof kinds used for fee quotes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub enum FeeProofKind {
    Single,
    Batch,
}

/// Fee schedule parameters for shielded transfers.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    MaxEncodedLen,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct FeeParameters {
    /// Base fee charged per single-transfer proof.
    pub proof_fee: u128,
    /// Base fee charged per batch proof.
    pub batch_proof_fee: u128,
    /// Fee per ciphertext byte for DA publication.
    pub da_byte_fee: u128,
    /// Fee per ciphertext byte per block of hot retention.
    pub retention_byte_fee: u128,
    /// Hot retention window in blocks used for fee quotes.
    pub hot_retention_blocks: u32,
}

impl Default for FeeParameters {
    fn default() -> Self {
        Self {
            proof_fee: 0,
            batch_proof_fee: 0,
            da_byte_fee: 0,
            retention_byte_fee: 0,
            hot_retention_blocks: 0,
        }
    }
}

/// Public view of a forced inclusion commitment.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct ForcedInclusionStatus {
    pub commitment: [u8; 32],
    pub expiry: u64,
}

/// On-chain record of a DA commitment for a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct DaCommitment {
    pub root: [u8; 48],
    pub chunk_count: u32,
}

impl DecodeWithMemTracking for DaCommitment {}

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

// ================================================================================================
// BATCH PROOF TYPES
// ================================================================================================

/// Maximum batch size for batch proofs.
pub const MAX_BATCH_SIZE: u32 = 16;

/// STARK batch proof for proving multiple transactions together.
///
/// This reduces verification costs from O(N) to O(1) by proving
/// N transactions in a single STARK proof.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct BatchStarkProof {
    /// Variable-length proof data.
    /// Contains the combined proof for all transactions in the batch.
    pub data: Vec<u8>,
    /// Number of transactions in this batch (2, 4, 8, or 16).
    pub batch_size: u32,
}

impl BatchStarkProof {
    /// Create a batch proof from raw bytes.
    pub fn from_bytes(data: Vec<u8>, batch_size: u32) -> Self {
        Self { data, batch_size }
    }

    /// Check if the proof is empty (invalid).
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Validate batch size.
    pub fn is_valid_batch_size(&self) -> bool {
        self.batch_size > 0
            && self.batch_size <= MAX_BATCH_SIZE
            && self.batch_size.is_power_of_two()
    }
}

/// A batch shielded transfer containing multiple transactions.
///
/// All transactions in the batch must use the same Merkle anchor.
/// The batch proof verifies all transactions together.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct BatchShieldedTransfer<MaxNullifiers: Get<u32>, MaxCommitments: Get<u32>> {
    /// STARK batch proof (covers all transactions).
    pub proof: BatchStarkProof,
    /// All nullifiers from all transactions in the batch.
    pub nullifiers: BoundedVec<Nullifier, MaxNullifiers>,
    /// All new note commitments from all transactions.
    pub commitments: BoundedVec<Commitment, MaxCommitments>,
    /// Encrypted notes for all recipients.
    pub ciphertexts: BoundedVec<EncryptedNote, MaxCommitments>,
    /// Shared Merkle root all transactions were proven against.
    pub anchor: MerkleRoot,
    /// Total fee across all transactions.
    pub total_fee: u128,
}

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
        assert_eq!(enc.kem_ciphertext.len(), MAX_KEM_CIPHERTEXT_LEN as usize);
        assert!(enc.kem_ciphertext.iter().all(|b| *b == 0));
    }

    #[test]
    fn merkle_path_depth_works() {
        let siblings = vec![[0u8; 48]; 5];
        let position_bits = vec![true, false, true, false, true];
        let path = MerklePath::new(siblings, position_bits);
        assert_eq!(path.depth(), 5);
    }

    #[test]
    fn encrypted_note_scale_encoding() {
        // Create a test note with known data
        let mut note = EncryptedNote::default();
        note.ciphertext[0] = 0xAB;
        note.ciphertext[ENCRYPTED_NOTE_SIZE - 1] = 0xCD;
        note.kem_ciphertext[0] = 0xEF;
        let last = note.kem_ciphertext.len() - 1;
        note.kem_ciphertext[last] = 0x99;

        // Encode it
        let encoded = note.encode();

        let kem_len = note.kem_ciphertext.len();
        let compact_len_bytes = if kem_len < 0x40 {
            1
        } else if kem_len < 0x4000 {
            2
        } else if kem_len < 0x4000_0000 {
            4
        } else {
            let bits = 64 - (kem_len as u64).leading_zeros();
            1 + ((bits + 7) / 8) as usize
        };

        // Verify exact size - BoundedVec encodes with compact length prefix
        assert_eq!(
            encoded.len(),
            ENCRYPTED_NOTE_SIZE + compact_len_bytes + kem_len,
            "EncryptedNote should encode to exactly {} bytes",
            ENCRYPTED_NOTE_SIZE + compact_len_bytes + kem_len
        );

        // Decode it back
        let decoded = EncryptedNote::decode(&mut &encoded[..]).expect("Should decode successfully");

        assert_eq!(decoded.ciphertext[0], 0xAB);
        assert_eq!(decoded.ciphertext[ENCRYPTED_NOTE_SIZE - 1], 0xCD);
        assert_eq!(decoded.kem_ciphertext[0], 0xEF);
        assert_eq!(decoded.kem_ciphertext[last], 0x99);
    }

    #[test]
    fn encrypted_note_raw_bytes_decode() {
        // Simulate wallet-style encoding with compact length prefix.
        let kem_len = 3usize;
        let mut raw_bytes = vec![0u8; ENCRYPTED_NOTE_SIZE];
        raw_bytes[0] = 0x42; // first byte of ciphertext

        // Compact length prefix for kem_len = 3 (single-byte mode)
        raw_bytes.push((kem_len as u8) << 2);
        raw_bytes.extend_from_slice(&[0x43, 0x44, 0x45]);

        let decoded =
            EncryptedNote::decode(&mut raw_bytes.as_slice()).expect("Should decode raw bytes");

        assert_eq!(decoded.ciphertext[0], 0x42);
        assert_eq!(decoded.kem_ciphertext[0], 0x43);
    }
}
