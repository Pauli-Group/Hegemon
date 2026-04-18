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

/// Maximum size of a raw embedded STARK proof in bytes.
///
/// This caps the inner Plonky3 proof payload carried by native `tx_leaf` artifacts
/// and sidecar proof submissions. It must stay aligned with the active native backend
/// proof-byte cap (`superneo_hegemon::MAX_NATIVE_TX_STARK_PROOF_BYTES`), which is
/// currently `512KiB` on the shipped `v8` product lane.
pub const STARK_PROOF_MAX_SIZE: usize = 512 * 1024;

/// Maximum size of a `recursive_block_v1` artifact payload.
///
/// This is the full serialized `Pi_block(B)` object carried on the `v1`
/// recursive lane. It must stay aligned with `block_recursion`'s
/// `recursive_block_artifact_bytes_v1()` geometry.
pub const RECURSIVE_BLOCK_V1_ARTIFACT_MAX_SIZE: usize = 699_404;

/// Maximum size of a `recursive_block_v2` artifact payload.
///
/// `v2` is the bounded-domain tree lane. The current cap is derived from:
/// - `TREE_RECURSIVE_CHUNK_SIZE_V2 = 1000`
/// - `TREE_RECURSIVE_MAX_SUPPORTED_TXS_V2 = 1000`
/// - the level-capped recursive proof report in `block_recursion`
///
/// The current full serialized `Pi_block_v2(B)` size is `522_159`.
pub const RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE: usize = 522_159;

/// Maximum size of any accepted recursive block artifact payload.
///
/// This remains the fail-closed upper bound for generic recursive lane plumbing
/// during `v1`/`v2` coexistence. Kind-specific validation must still use
/// `recursive_block_artifact_max_size`.
pub const RECURSIVE_BLOCK_ARTIFACT_MAX_SIZE: usize = RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE;

/// Maximum size of a native `tx_leaf` artifact payload submitted on the unsigned
/// shielded transfer path.
///
/// This is the full artifact envelope, not just the embedded STARK proof bytes.
/// The value is derived from the active `v8` native backend envelope geometry, including the
/// trailing tx-proof-backend selector byte, and
/// must stay aligned with `superneo_hegemon::max_native_tx_leaf_artifact_bytes()`.
pub const NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE: usize = 530_368;

/// Size of a binding hash.
pub const BINDING_HASH_SIZE: usize = 64;

/// Size of the memo field in bytes.
pub const MEMO_SIZE: usize = 512;

/// Note encryption version used in the ciphertext header.
///
/// This must remain aligned with the wallet shielded address version accepted by
/// `wallet::address::ShieldedAddress` (currently v3).
pub const NOTE_ENCRYPTION_VERSION: u8 = 3;
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

/// Diversified address size used inside commitments:
/// version(1) + diversifier_index(4) + pk_recipient(32) + pk_auth(32).
pub const DIVERSIFIED_ADDRESS_SIZE: usize = 69;

/// Commitment bytes (48-byte PQ sponge output).
pub type Commitment = [u8; 48];
/// Nullifier bytes (48-byte PQ sponge output).
pub type Nullifier = [u8; 48];
/// Merkle root bytes (48-byte PQ sponge output).
pub type MerkleRoot = [u8; 48];
/// Verifier profile digest for a proof artifact family and parameter profile.
pub type VerifierProfileDigest = [u8; 48];

#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen,
)]
pub struct TxValidityReceipt {
    pub statement_hash: [u8; 48],
    pub proof_digest: [u8; 48],
    pub public_inputs_digest: [u8; 48],
    pub verifier_profile: VerifierProfileDigest,
}

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

/// Version tag for the block proof bundle payload format.
pub const BLOCK_PROOF_BUNDLE_SCHEMA: u8 = 2;
/// Proof format id used for flat batch proof items in this branch.
pub const BLOCK_PROOF_FORMAT_ID_V5: u8 = 5;
/// Maximum number of flat proof batches allowed in a single block payload.
pub const MAX_FLAT_BATCHES_PER_BLOCK: usize = 1024;
/// Maximum cumulative proof bytes accepted in a single block payload.
pub const BLOCK_PROOF_BUNDLE_MAX_TOTAL_PROOF_BYTES: usize = 64 * 1024 * 1024;

/// Per-block payload that carries all consensus-required proof material for
/// self-contained aggregation blocks.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    MaxEncodedLen,
)]
pub enum BlockProofMode {
    /// Historical inline lane retained only for compatibility/error handling.
    InlineTx,
    /// Explicit experimental native comparison lane.
    ReceiptRoot,
    /// Shipped 0.10.0 product lane over the canonical verified leaf stream.
    RecursiveBlock,
}

/// Backend-neutral proof artifact kind. `proof_mode` remains for legacy block-payload handling,
/// while this enum is the forward-compatible selector for artifact routing.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    MaxEncodedLen,
)]
pub enum ProofArtifactKind {
    InlineTx,
    TxLeaf,
    ReceiptRoot,
    RecursiveBlockV1,
    RecursiveBlockV2,
    Custom([u8; 16]),
}

impl ProofArtifactKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::InlineTx => "inline_tx",
            Self::TxLeaf => "tx_leaf",
            Self::ReceiptRoot => "receipt_root",
            Self::RecursiveBlockV1 => "recursive_block_v1",
            Self::RecursiveBlockV2 => "recursive_block_v2",
            Self::Custom(_) => "custom",
        }
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    MaxEncodedLen,
)]
pub struct BlockProofRoute {
    pub mode: BlockProofMode,
    pub kind: ProofArtifactKind,
}

impl BlockProofRoute {
    pub const fn new(mode: BlockProofMode, kind: ProofArtifactKind) -> Self {
        Self { mode, kind }
    }

    pub fn from_mode(mode: BlockProofMode) -> Self {
        Self::new(mode, proof_artifact_kind_from_mode(mode))
    }

    pub const fn shipped_recursive_block_v2() -> Self {
        Self::new(
            BlockProofMode::RecursiveBlock,
            ProofArtifactKind::RecursiveBlockV2,
        )
    }

    pub const fn explicit_receipt_root() -> Self {
        Self::new(BlockProofMode::ReceiptRoot, ProofArtifactKind::ReceiptRoot)
    }

    pub fn is_compatible_with_mode(self) -> bool {
        match self.mode {
            BlockProofMode::InlineTx => self.kind == ProofArtifactKind::InlineTx,
            BlockProofMode::ReceiptRoot => self.kind == ProofArtifactKind::ReceiptRoot,
            BlockProofMode::RecursiveBlock => is_recursive_block_artifact_kind(self.kind),
        }
    }

    pub fn is_canonical(self) -> bool {
        match self.mode {
            BlockProofMode::InlineTx => self.kind == ProofArtifactKind::InlineTx,
            BlockProofMode::ReceiptRoot => self.kind == ProofArtifactKind::ReceiptRoot,
            BlockProofMode::RecursiveBlock => self.kind == ProofArtifactKind::RecursiveBlockV2,
        }
    }

    pub fn is_shipped(self) -> bool {
        self.mode == BlockProofMode::RecursiveBlock
            && self.kind == ProofArtifactKind::RecursiveBlockV2
    }

    pub fn is_experimental(self) -> bool {
        self.mode == BlockProofMode::ReceiptRoot && self.kind == ProofArtifactKind::ReceiptRoot
    }
}

pub const fn is_recursive_block_artifact_kind(kind: ProofArtifactKind) -> bool {
    matches!(
        kind,
        ProofArtifactKind::RecursiveBlockV1 | ProofArtifactKind::RecursiveBlockV2
    )
}

pub const fn canonical_recursive_block_artifact_kind() -> ProofArtifactKind {
    ProofArtifactKind::RecursiveBlockV2
}

pub fn canonical_shipped_block_proof_route() -> BlockProofRoute {
    BlockProofRoute::shipped_recursive_block_v2()
}

pub fn canonical_experimental_block_proof_route() -> BlockProofRoute {
    BlockProofRoute::explicit_receipt_root()
}

pub const fn is_shipped_block_proof_mode(mode: BlockProofMode) -> bool {
    matches!(mode, BlockProofMode::RecursiveBlock)
}

pub const fn is_experimental_block_proof_mode(mode: BlockProofMode) -> bool {
    matches!(mode, BlockProofMode::ReceiptRoot)
}

pub const fn is_experimental_block_artifact_kind(kind: ProofArtifactKind) -> bool {
    matches!(kind, ProofArtifactKind::ReceiptRoot)
}

pub const fn recursive_block_artifact_max_size(kind: ProofArtifactKind) -> Option<usize> {
    match kind {
        ProofArtifactKind::RecursiveBlockV1 => Some(RECURSIVE_BLOCK_V1_ARTIFACT_MAX_SIZE),
        ProofArtifactKind::RecursiveBlockV2 => Some(RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE),
        _ => None,
    }
}

pub fn proof_artifact_kind_from_mode(mode: BlockProofMode) -> ProofArtifactKind {
    match mode {
        BlockProofMode::InlineTx => ProofArtifactKind::InlineTx,
        BlockProofMode::ReceiptRoot => ProofArtifactKind::ReceiptRoot,
        BlockProofMode::RecursiveBlock => canonical_recursive_block_artifact_kind(),
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen,
)]
pub struct ReceiptRootMetadata {
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    pub leaf_count: u32,
    pub fold_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct ReceiptRootProofPayload {
    pub root_proof: StarkProof,
    pub metadata: ReceiptRootMetadata,
    pub receipts: Vec<TxValidityReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct RecursiveBlockProofPayload {
    pub proof: StarkProof,
}

/// Parent-agnostic proof object over an ordered transaction set.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct CandidateArtifact {
    /// Payload format version.
    pub version: u8,
    /// Number of shielded transfers covered by this payload.
    pub tx_count: u32,
    /// Commitment over canonical transaction statements in canonical tx order.
    pub tx_statements_commitment: [u8; 48],
    /// DA root for the candidate block.
    pub da_root: [u8; 48],
    /// DA chunk count for the candidate block.
    pub da_chunk_count: u32,
    /// Legacy block commitment proof bytes.
    ///
    /// This is required on the `ReceiptRoot` lane and must be empty on the
    /// `RecursiveBlock` lane so no linear public-input payload can be smuggled
    /// into the constant-size block-proof artifact.
    pub commitment_proof: StarkProof,
    /// Proof mode for this bundle.
    pub proof_mode: BlockProofMode,
    /// Backend-neutral proof artifact kind for routing and future verifier agility.
    pub proof_kind: ProofArtifactKind,
    /// Verifier profile digest for the artifact family and parameter profile.
    pub verifier_profile: VerifierProfileDigest,
    /// Optional receipt-root proof payload (required in ReceiptRoot mode).
    pub receipt_root: Option<ReceiptRootProofPayload>,
    /// Optional recursive block-proof artifact payload (required in RecursiveBlock mode).
    pub recursive_block: Option<RecursiveBlockProofPayload>,
}

impl CandidateArtifact {
    pub fn route(&self) -> BlockProofRoute {
        BlockProofRoute::new(self.proof_mode, self.proof_kind)
    }

    pub fn uses_route(&self, route: BlockProofRoute) -> bool {
        self.proof_mode == route.mode && self.proof_kind == route.kind
    }
}

#[allow(deprecated)]
#[deprecated(note = "Use CandidateArtifact instead.")]
pub type BlockProofBundle = CandidateArtifact;

/// Public metadata for announcing a reusable candidate artifact without
/// sending the full payload immediately.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct ArtifactAnnouncement {
    pub artifact_hash: [u8; 32],
    pub tx_statements_commitment: [u8; 48],
    pub tx_count: u32,
    pub proof_mode: BlockProofMode,
    pub proof_kind: ProofArtifactKind,
    pub verifier_profile: VerifierProfileDigest,
}

#[deprecated(note = "Use BLOCK_PROOF_BUNDLE_SCHEMA instead.")]
pub const PROVEN_BATCH_V1_VERSION: u8 = BLOCK_PROOF_BUNDLE_SCHEMA;

#[deprecated(note = "Use CandidateArtifact instead.")]
pub type ProvenBatchV1 = CandidateArtifact;

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
/// In Phase C ("self-contained aggregation"), transfers may omit proof bytes from the extrinsic,
/// and block validity is established by the aggregation proof plus statement commitments.
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
    /// Transfer extrinsics may omit proof bytes in aggregation mode, and validators verify the
    /// block from the aggregation proof and statement commitments without proof-DA fetch.
    SelfContained,
}

impl Default for ProofAvailabilityPolicy {
    fn default() -> Self {
        ProofAvailabilityPolicy::InlineRequired
    }
}

/// Legacy proof-DA manifest entry retained for test helpers only.
///
/// Phase C consensus no longer uses proof-DA manifests. This struct remains under `#[cfg(test)]`
/// to support unit tests that exercise historical parser/layout helpers.
#[cfg(test)]
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

/// Per-block shielded reward bundle.
#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct BlockRewardBundle {
    pub miner_note: CoinbaseNoteData,
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
    /// Optional miner tip encoded in the proof.
    pub fee: u64,
    /// Net value change (must be 0 when no transparent pool is enabled).
    pub value_balance: i128,
}

/// Per-block fee accumulators credited to the block miner.
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
    Default,
)]
pub struct BlockFeeBuckets {
    pub miner_fees: u128,
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
pub const MAX_BATCH_SIZE: u32 = 32;

/// STARK batch proof for proving multiple transactions together.
///
/// This reduces verification costs from O(N) to O(1) by proving
/// N transactions in a single STARK proof.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct BatchStarkProof {
    /// Variable-length proof data.
    /// Contains the combined proof for all transactions in the batch.
    pub data: Vec<u8>,
    /// Number of transactions in this batch (2, 4, 8, 16, or 32).
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
    /// Total optional miner tip across all transactions.
    pub total_fee: u128,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_routes_are_explicit() {
        assert_eq!(
            canonical_shipped_block_proof_route(),
            BlockProofRoute::new(
                BlockProofMode::RecursiveBlock,
                ProofArtifactKind::RecursiveBlockV2
            )
        );
        assert_eq!(
            canonical_experimental_block_proof_route(),
            BlockProofRoute::new(BlockProofMode::ReceiptRoot, ProofArtifactKind::ReceiptRoot)
        );
    }

    #[test]
    fn route_classification_distinguishes_shipped_and_compatibility_paths() {
        assert!(canonical_shipped_block_proof_route().is_shipped());
        assert!(canonical_shipped_block_proof_route().is_canonical());
        assert!(canonical_shipped_block_proof_route().is_compatible_with_mode());

        let legacy_recursive = BlockProofRoute::new(
            BlockProofMode::RecursiveBlock,
            ProofArtifactKind::RecursiveBlockV1,
        );
        assert!(legacy_recursive.is_compatible_with_mode());
        assert!(!legacy_recursive.is_canonical());
        assert!(!legacy_recursive.is_shipped());

        let invalid_route = BlockProofRoute::new(
            BlockProofMode::ReceiptRoot,
            ProofArtifactKind::RecursiveBlockV2,
        );
        assert!(!invalid_route.is_compatible_with_mode());
        assert!(!invalid_route.is_canonical());
    }

    #[test]
    fn recursive_block_v2_artifact_cap_matches_block_recursion_geometry() {
        assert_eq!(
            RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE,
            block_recursion::recursive_block_artifact_bytes_v2(),
            "runtime recursive_block_v2 cap drifted away from block-recursion geometry"
        );
    }

    #[test]
    fn native_tx_leaf_artifact_cap_stays_aligned_with_live_backend() {
        assert_eq!(
            NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
            superneo_hegemon::max_native_tx_leaf_artifact_bytes(),
            "runtime native tx-leaf artifact cap drifted away from the shipped backend envelope"
        );
    }

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
