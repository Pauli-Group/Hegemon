use alloc::vec;
use alloc::vec::Vec;

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

pub const MERKLE_TREE_DEPTH: u32 = 32;
pub const MAX_NULLIFIERS_PER_TX: u32 = 2;
pub const MAX_COMMITMENTS_PER_TX: u32 = 2;
pub const STARK_PROOF_MAX_SIZE: usize = 512 * 1024;
pub const RECURSIVE_BLOCK_V1_ARTIFACT_MAX_SIZE: usize = 699_404;
pub const RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE: usize = 522_159;
pub const RECURSIVE_BLOCK_ARTIFACT_MAX_SIZE: usize = RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE;
pub const NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE: usize = 530_368;
pub const BINDING_HASH_SIZE: usize = 64;
pub const MEMO_SIZE: usize = 512;
pub const NOTE_ENCRYPTION_VERSION: u8 = 3;
pub const CRYPTO_SUITE_GAMMA: u16 = 3;
pub const ENCRYPTED_NOTE_SIZE: usize = 579;
pub const MAX_KEM_CIPHERTEXT_LEN: u32 = 1568;
pub const MAX_CIPHERTEXT_BYTES: usize = ENCRYPTED_NOTE_SIZE + MAX_KEM_CIPHERTEXT_LEN as usize;
pub const DIVERSIFIED_ADDRESS_SIZE: usize = 69;

pub type Commitment = [u8; 48];
pub type Nullifier = [u8; 48];
pub type MerkleRoot = [u8; 48];
pub type VerifierProfileDigest = [u8; 48];

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct Note {
    pub recipient: [u8; DIVERSIFIED_ADDRESS_SIZE],
    pub value: u64,
    pub rcm: [u8; 32],
    pub memo: [u8; MEMO_SIZE],
}

impl Note {
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

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct EncryptedNote {
    pub ciphertext: [u8; ENCRYPTED_NOTE_SIZE],
    pub kem_ciphertext: Vec<u8>,
}

impl Default for EncryptedNote {
    fn default() -> Self {
        Self {
            ciphertext: [0u8; ENCRYPTED_NOTE_SIZE],
            kem_ciphertext: vec![0u8; MAX_KEM_CIPHERTEXT_LEN as usize],
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct StarkProof {
    pub data: Vec<u8>,
}

impl StarkProof {
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

pub const BLOCK_PROOF_BUNDLE_SCHEMA: u8 = 2;
pub const BLOCK_PROOF_FORMAT_ID_V5: u8 = 5;
pub const MAX_FLAT_BATCHES_PER_BLOCK: usize = 1024;
pub const BLOCK_PROOF_BUNDLE_MAX_TOTAL_PROOF_BYTES: usize = 64 * 1024 * 1024;

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
    InlineTx,
    ReceiptRoot,
    RecursiveBlock,
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

pub fn proof_artifact_kind_from_mode(mode: BlockProofMode) -> ProofArtifactKind {
    match mode {
        BlockProofMode::InlineTx => ProofArtifactKind::InlineTx,
        BlockProofMode::ReceiptRoot => ProofArtifactKind::ReceiptRoot,
        BlockProofMode::RecursiveBlock => canonical_recursive_block_artifact_kind(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
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

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct CandidateArtifact {
    pub version: u8,
    pub tx_count: u32,
    pub tx_statements_commitment: [u8; 48],
    pub da_root: [u8; 48],
    pub da_chunk_count: u32,
    pub commitment_proof: StarkProof,
    pub proof_mode: BlockProofMode,
    pub proof_kind: ProofArtifactKind,
    pub verifier_profile: VerifierProfileDigest,
    pub receipt_root: Option<ReceiptRootProofPayload>,
    pub recursive_block: Option<RecursiveBlockProofPayload>,
}

impl CandidateArtifact {
    pub fn route(&self) -> BlockProofRoute {
        BlockProofRoute::new(self.proof_mode, self.proof_kind)
    }
}

pub type BlockProofBundle = CandidateArtifact;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct ArtifactAnnouncement {
    pub artifact_hash: [u8; 32],
    pub tx_statements_commitment: [u8; 48],
    pub tx_count: u32,
    pub proof_mode: BlockProofMode,
    pub proof_kind: ProofArtifactKind,
    pub verifier_profile: VerifierProfileDigest,
}

pub type ProvenBatchV1 = CandidateArtifact;
pub const PROVEN_BATCH_V1_VERSION: u8 = BLOCK_PROOF_BUNDLE_SCHEMA;

#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct BindingHash {
    pub data: [u8; BINDING_HASH_SIZE],
}

impl Default for BindingHash {
    fn default() -> Self {
        Self {
            data: [0u8; BINDING_HASH_SIZE],
        }
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct StablecoinPolicyBinding {
    pub asset_id: u64,
    pub policy_hash: [u8; 48],
    pub oracle_commitment: [u8; 48],
    pub attestation_commitment: [u8; 48],
    pub issuance_delta: i128,
    pub policy_version: u32,
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
)]
pub enum DaAvailabilityPolicy {
    FullFetch,
    Sampling,
}

impl Default for DaAvailabilityPolicy {
    fn default() -> Self {
        DaAvailabilityPolicy::FullFetch
    }
}

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
)]
pub enum CiphertextPolicy {
    InlineAllowed,
    SidecarOnly,
}

impl Default for CiphertextPolicy {
    fn default() -> Self {
        CiphertextPolicy::InlineAllowed
    }
}

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
)]
pub enum ProofAvailabilityPolicy {
    InlineRequired,
    SelfContained,
}

impl Default for ProofAvailabilityPolicy {
    fn default() -> Self {
        ProofAvailabilityPolicy::InlineRequired
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct CoinbaseNoteData {
    pub commitment: [u8; 48],
    pub encrypted_note: EncryptedNote,
    pub recipient_address: [u8; DIVERSIFIED_ADDRESS_SIZE],
    pub amount: u64,
    pub public_seed: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct BlockRewardBundle {
    pub miner_note: CoinbaseNoteData,
}

#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen,
)]
pub struct TxValidityReceipt {
    pub statement_hash: [u8; 48],
    pub proof_digest: [u8; 48],
    pub public_inputs_digest: [u8; 48],
    pub verifier_profile: VerifierProfileDigest,
}

pub const MAX_BATCH_SIZE: u32 = 32;

#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct BatchStarkProof {
    pub data: Vec<u8>,
    pub batch_size: u32,
}

impl BatchStarkProof {
    pub fn from_bytes(data: Vec<u8>, batch_size: u32) -> Self {
        Self { data, batch_size }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn is_valid_batch_size(&self) -> bool {
        self.batch_size > 0
            && self.batch_size <= MAX_BATCH_SIZE
            && self.batch_size.is_power_of_two()
    }
}
