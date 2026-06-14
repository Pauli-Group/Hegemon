//! Native Hegemon node service.
//!
//! Native Hegemon node service.
//! It keeps the existing JSON-RPC compatibility surface while the ledger,
//! mempool, sync, and shielded state machines are native.

use anyhow::{anyhow, Context, Result};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use codec::{Decode, Encode};
use consensus::{
    CommitmentTreeState, DaParams, ProofEnvelope, Transaction, TxValidityArtifact,
    COMMITMENT_TREE_DEPTH,
};
use consensus_light_client::{
    bridge_checkpoint_output, bridge_checkpoint_output_with_tip,
    canonical_bridge_checkpoint_output_bytes_v1, canonical_trusted_checkpoint_bytes_v1,
    compare_work, cumulative_work_after, decode_risc0_bridge_journal, empty_header_mmr_root,
    flyclient_sample_indices, hash_meets_target, header_mmr_opening_from_hashes,
    header_mmr_root_from_hashes, pow_hash_from_pre_hash, verify_pow_header,
    BridgeCheckpointOutputV1, BridgeMessageV1, Hash32, HeaderMmrLeafWitnessV1,
    HegemonLightClientProofReceiptV1, HegemonLongRangeProofV1, PowHeaderV1,
    RiscZeroBridgeReceiptV1, TrustedCheckpointV1, HEGEMON_CHAIN_ID_V1,
    HEGEMON_LIGHT_CLIENT_RULES_HASH_V1, HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V1,
    HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1,
};
use crypto::ml_dsa::{
    MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, ML_DSA_PUBLIC_KEY_LEN, ML_DSA_SIGNATURE_LEN,
};
use crypto::traits::{Signature, SigningKey, VerifyKey};
use network::{
    service::DirectedProtocolMessage, wire, GossipRouter, NatTraversalConfig, P2PService, PeerId,
    PeerIdentity, PeerStore, PeerStoreConfig, ProtocolHandle, ProtocolId, ProtocolMessage,
    RelayConfig,
};
use parking_lot::{Mutex, RwLock};
use protocol_kernel::types::KernelVersionBinding;
use protocol_kernel::{
    bridge_message_root, bridge_payload_hash, empty_bridge_message_root, inbound_replay_key,
    BridgeVerifierRegistrationV1, InboundBridgeArgsV1, InboundReplayReject, InboundReplayState,
    OutboundBridgeArgsV1, ACTION_BRIDGE_INBOUND, ACTION_BRIDGE_OUTBOUND,
    ACTION_REGISTER_BRIDGE_VERIFIER, FAMILY_BRIDGE,
};
use protocol_shielded_pool::family::{
    MintCoinbaseArgs, ShieldedTransferInlineArgs, ShieldedTransferSidecarArgs,
    SubmitCandidateArtifactArgs, ACTION_MINT_COINBASE, ACTION_SHIELDED_TRANSFER_INLINE,
    ACTION_SHIELDED_TRANSFER_SIDECAR, ACTION_SUBMIT_CANDIDATE_ARTIFACT, FAMILY_SHIELDED_POOL,
};
use protocol_shielded_pool::types::{
    BlockProofMode, BlockRewardBundle, CandidateArtifact, CoinbaseNoteData, EncryptedNote,
    ProofArtifactKind as PoolProofArtifactKind, StablecoinPolicyBinding, BLOCK_PROOF_BUNDLE_SCHEMA,
    DIVERSIFIED_ADDRESS_SIZE, ENCRYPTED_NOTE_SIZE, MAX_BATCH_SIZE, MAX_CIPHERTEXT_BYTES,
    NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE, RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE,
};
use protocol_shielded_pool::verifier::{ShieldedTransferInputs, StarkVerifier};
use protocol_shielded_pool::{NullifierReject, NullifierState};
use rand::{rngs::OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sled::transaction::Transactional;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use transaction_circuit::hashing_pq::felts_to_bytes48;
use transaction_core::hashing_pq::ciphertext_hash_bytes;
use wallet::{NoteCiphertext, NotePlaintext, ShieldedAddress};

const META_BEST_KEY: &[u8] = b"best";
const META_GENESIS_KEY: &[u8] = b"genesis";
const NATIVE_DEV_POW_BITS: u32 = 0x1f00_ffff;
const HASHES_PER_ROUND: u64 = 16_384;
const DEFAULT_DA_CHUNK_SIZE: u32 = 1024;
const DEFAULT_DA_SAMPLE_COUNT: u32 = 4;
const DEFAULT_BRIDGE_FLYCLIENT_SAMPLE_COUNT: u32 = 8;
const MIN_INBOUND_BRIDGE_CONFIRMATIONS: u32 = 2;
const NATIVE_RISC0_RECEIPT_VERIFIER_ENABLED: bool = false;
const MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS: u64 = 4_096;
const MAX_NATIVE_MEMPOOL_ACTIONS: usize = 10_000;
const MAX_PREPARED_MINING_WORKS: usize = 128;
const NATIVE_SYNC_PROTOCOL_ID: ProtocolId = 0x4847_4e53;
const MAX_NATIVE_SYNC_RESPONSE_BLOCKS: u64 = 512;
const MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE: usize = MAX_NATIVE_SYNC_RESPONSE_BLOCKS as usize;
const NATIVE_ANNOUNCE_INTERVAL: u64 = 16;
const PQ_IDENTITY_SEED_FILE: &str = "pq-identity.seed";
const PQ_IDENTITY_SEED_LEN: usize = 32;
const MINER_IDENTITY_SEED_FILE: &str = "miner-identity.seed";
const MAX_NATIVE_RPC_ACTION_BYTES: usize = 2 * 1024 * 1024;
const MAX_NATIVE_DA_CIPHERTEXT_UPLOADS: usize = 1024;
const MAX_NATIVE_DA_PROOF_UPLOADS: usize = 256;
const MAX_NATIVE_STAGED_CIPHERTEXTS: usize = 100_000;
const MAX_NATIVE_STAGED_PROOFS: usize = 10_000;
const MAX_NATIVE_STAGED_PROOF_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_NATIVE_WALLET_PAGE_LIMIT: u64 = 128;
const MAX_NATIVE_WALLET_PAGE_LIMIT: u64 = 1024;
const MIN_NATIVE_ARCHIVE_KEM_CIPHERTEXT_BYTES: usize = 32;
const MIN_NATIVE_WALLET_CIPHERTEXT_BYTES: usize =
    ENCRYPTED_NOTE_SIZE + MIN_NATIVE_ARCHIVE_KEM_CIPHERTEXT_BYTES;
const MAX_NATIVE_TIMESTAMP_ROWS: u64 = 4096;
const MAX_NATIVE_RPC_BATCH_REQUESTS: usize = 128;
const MAX_NATIVE_RPC_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_NATIVE_MEMPOOL_ACTION_BYTES: usize = 64 * 1024 * 1024;
const MAX_NATIVE_SYNC_MESSAGE_BYTES: usize = wire::MAX_WIRE_FRAME_LEN;
const MAX_NATIVE_MINING_THREADS: u32 = 64;
const NATIVE_EMPTY_DIGEST48: [u8; 48] = [0u8; 48];

#[derive(Clone, Debug, Parser)]
#[command(name = "hegemon-node")]
#[command(about = "Native Hegemon node")]
pub struct NativeCli {
    /// Run an ephemeral development chain.
    #[arg(long)]
    pub dev: bool,
    /// Store node state in a process-specific temporary directory.
    #[arg(long)]
    pub tmp: bool,
    /// Node base path.
    #[arg(long, value_name = "PATH")]
    pub base_path: Option<PathBuf>,
    /// JSON-RPC port.
    #[arg(long, default_value_t = 9944)]
    pub rpc_port: u16,
    /// Expose JSON-RPC on all interfaces.
    #[arg(long)]
    pub rpc_external: bool,
    /// RPC method policy: auto, safe, or unsafe.
    #[arg(long, default_value = "auto")]
    pub rpc_methods: String,
    /// CORS policy. Accepted for CLI compatibility; currently reflected as a permissive header.
    #[arg(long)]
    pub rpc_cors: Option<String>,
    /// P2P listen port.
    #[arg(long, default_value_t = 30333)]
    pub port: u16,
    /// P2P listen address.
    #[arg(long)]
    pub listen_addr: Option<String>,
    /// Node display name.
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NativeConfig {
    pub dev: bool,
    pub tmp: bool,
    pub base_path: PathBuf,
    pub db_path: PathBuf,
    pub rpc_addr: SocketAddr,
    pub p2p_listen_addr: String,
    pub node_name: String,
    pub rpc_methods: String,
    pub rpc_external: bool,
    pub rpc_cors: Option<String>,
    pub seeds: Vec<String>,
    pub max_peers: u32,
    pub mine: bool,
    pub mine_threads: u32,
    pub miner_address: Option<String>,
    pub pow_bits: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RpcMethodPolicy {
    Safe,
    Unsafe,
}

impl RpcMethodPolicy {
    fn label(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Unsafe => "unsafe",
        }
    }
}

impl NativeConfig {
    pub fn from_cli(cli: NativeCli) -> Result<Self> {
        let base_path = resolve_base_path(&cli)?;
        let db_path = base_path.join("native-chain.sled");
        let rpc_methods =
            effective_rpc_methods_label(&cli.rpc_methods, cli.rpc_external)?.to_string();
        let rpc_ip = if cli.rpc_external {
            IpAddr::from(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::from(Ipv4Addr::LOCALHOST)
        };
        let rpc_addr = SocketAddr::new(rpc_ip, cli.rpc_port);
        let p2p_listen_addr = cli
            .listen_addr
            .clone()
            .unwrap_or_else(|| format!("0.0.0.0:{}", cli.port));
        let seeds = env_list("HEGEMON_SEEDS");
        let max_peers = std::env::var("HEGEMON_MAX_PEERS")
            .ok()
            .and_then(|raw| raw.parse::<u32>().ok())
            .unwrap_or(64);
        let mine = env_bool("HEGEMON_MINE");
        let mine_threads = std::env::var("HEGEMON_MINE_THREADS")
            .ok()
            .map(|raw| parse_mining_thread_count_str(&raw, "HEGEMON_MINE_THREADS"))
            .transpose()?
            .unwrap_or(1);
        let miner_address = std::env::var("HEGEMON_MINER_ADDRESS")
            .ok()
            .map(|raw| raw.trim().to_string())
            .filter(|raw| !raw.is_empty());
        let pow_bits = if cli.dev {
            NATIVE_DEV_POW_BITS
        } else {
            consensus::pow::DEFAULT_GENESIS_POW_BITS
        };

        Ok(Self {
            dev: cli.dev,
            tmp: cli.tmp,
            base_path,
            db_path,
            rpc_addr,
            p2p_listen_addr,
            node_name: cli.name.unwrap_or_else(|| "hegemon-native".to_string()),
            rpc_methods,
            rpc_external: cli.rpc_external,
            rpc_cors: cli.rpc_cors,
            seeds,
            max_peers,
            mine,
            mine_threads,
            miner_address,
            pow_bits,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct NativeBlockMeta {
    chain_id: [u8; 32],
    rules_hash: [u8; 32],
    height: u64,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    state_root: [u8; 48],
    #[serde(with = "serde_array48")]
    kernel_root: [u8; 48],
    #[serde(with = "serde_array48")]
    nullifier_root: [u8; 48],
    extrinsics_root: [u8; 32],
    #[serde(with = "serde_array48")]
    message_root: [u8; 48],
    message_count: u32,
    header_mmr_root: [u8; 32],
    header_mmr_len: u64,
    timestamp_ms: u64,
    pow_bits: u32,
    nonce: [u8; 32],
    work_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    cumulative_work: [u8; 48],
    supply_digest: u128,
    tx_count: u32,
    #[serde(default)]
    action_bytes: Vec<Vec<u8>>,
    #[serde(default = "native_empty_digest48_default", with = "serde_array48")]
    miner_commitment: [u8; 48],
    #[serde(default)]
    miner_public_key: Vec<u8>,
    #[serde(default)]
    miner_signature: Vec<u8>,
}

fn native_empty_digest48_default() -> [u8; 48] {
    NATIVE_EMPTY_DIGEST48
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LegacyNativeBlockMetaV1 {
    chain_id: [u8; 32],
    rules_hash: [u8; 32],
    height: u64,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    state_root: [u8; 48],
    #[serde(with = "serde_array48")]
    kernel_root: [u8; 48],
    #[serde(with = "serde_array48")]
    nullifier_root: [u8; 48],
    extrinsics_root: [u8; 32],
    #[serde(with = "serde_array48")]
    message_root: [u8; 48],
    message_count: u32,
    header_mmr_root: [u8; 32],
    header_mmr_len: u64,
    timestamp_ms: u64,
    pow_bits: u32,
    nonce: [u8; 32],
    work_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    cumulative_work: [u8; 48],
    supply_digest: u128,
    tx_count: u32,
    #[serde(default)]
    action_bytes: Vec<Vec<u8>>,
}

impl From<LegacyNativeBlockMetaV1> for NativeBlockMeta {
    fn from(meta: LegacyNativeBlockMetaV1) -> Self {
        Self {
            chain_id: meta.chain_id,
            rules_hash: meta.rules_hash,
            height: meta.height,
            hash: meta.hash,
            parent_hash: meta.parent_hash,
            state_root: meta.state_root,
            kernel_root: meta.kernel_root,
            nullifier_root: meta.nullifier_root,
            extrinsics_root: meta.extrinsics_root,
            message_root: meta.message_root,
            message_count: meta.message_count,
            header_mmr_root: meta.header_mmr_root,
            header_mmr_len: meta.header_mmr_len,
            timestamp_ms: meta.timestamp_ms,
            pow_bits: meta.pow_bits,
            nonce: meta.nonce,
            work_hash: meta.work_hash,
            cumulative_work: meta.cumulative_work,
            supply_digest: meta.supply_digest,
            tx_count: meta.tx_count,
            action_bytes: meta.action_bytes,
            miner_commitment: [0u8; 48],
            miner_public_key: Vec::new(),
            miner_signature: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
struct NativeWork {
    height: u64,
    parent_hash: [u8; 32],
    pre_hash: [u8; 32],
    state_root: [u8; 48],
    kernel_root: [u8; 48],
    nullifier_root: [u8; 48],
    extrinsics_root: [u8; 32],
    message_root: [u8; 48],
    message_count: u32,
    header_mmr_root: [u8; 32],
    header_mmr_len: u64,
    cumulative_work: [u8; 48],
    supply_digest: u128,
    tx_count: u32,
    timestamp_ms: u64,
    pow_bits: u32,
}

#[derive(Clone, Debug)]
struct NativeSeal {
    nonce: [u8; 32],
    work_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum NativeSyncMessage {
    Announce(Box<NativeBlockMeta>),
    Request {
        from_height: u64,
        to_height: u64,
    },
    Response {
        best_height: u64,
        blocks: Vec<NativeBlockMeta>,
    },
}

#[derive(Clone, Debug, Encode, Decode)]
struct PendingAction {
    tx_hash: [u8; 32],
    binding: KernelVersionBinding,
    family_id: u16,
    action_id: u16,
    anchor: [u8; 48],
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    ciphertext_hashes: Vec<[u8; 48]>,
    ciphertext_sizes: Vec<u32>,
    public_args: Vec<u8>,
    fee: u64,
    candidate_artifact: Option<CandidateArtifact>,
    received_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeSyncRange {
    from_height: u64,
    to_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeSyncResponseRangeInput {
    from_height: u64,
    to_height: u64,
    best_height: u64,
    max_blocks: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeSyncMissingRequestInput {
    best_height: u64,
    announced_height: u64,
    max_blocks: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeSyncResponseCountAdmissionInput {
    block_count: usize,
    max_blocks: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeSyncAdmissionRejection {
    ResponseBlockCountTooLarge,
}

impl NativeSyncAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::ResponseBlockCountTooLarge => "response_block_count_too_large",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeActionHashAdmissionInput {
    action_count_matches: bool,
    action_hashes_match: bool,
    action_hashes_unique: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativePendingActionReloadInput {
    key_well_formed: bool,
    embedded_hash_matches_key: bool,
    recomputed_hash_matches_embedded: bool,
    action_hash_unique: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeActionHashAdmissionRejection {
    ActionCountMismatch,
    ActionHashMismatch,
    DuplicateActionHash,
}

impl NativeActionHashAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::ActionCountMismatch => "action_count_mismatch",
            Self::ActionHashMismatch => "action_hash_mismatch",
            Self::DuplicateActionHash => "duplicate_action_hash",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeAnnouncedBlockAdmissionInput {
    parent_height: u64,
    announced_height: u64,
    parent_hash_matches: bool,
    parent_timestamp_ms: u64,
    announced_timestamp_ms: u64,
    now_ms: u64,
    max_future_skew_ms: u64,
    hash_matches_work_hash: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeBlockIndexReloadInput {
    chain_reconstructed: bool,
    chain_nonempty: bool,
    genesis_matches_expected: bool,
    best_metadata_matches_chain: bool,
    canonical_heights_contiguous: bool,
    canonical_chain_ids_match: bool,
    canonical_rules_hashes_match: bool,
    canonical_hashes_match_work_hashes: bool,
    canonical_parent_hashes_contiguous: bool,
    height_keys_well_formed: bool,
    height_values_well_formed: bool,
    no_extra_height_indexes: bool,
    height_index_heights_match_chain: bool,
    height_index_hashes_match_chain: bool,
    all_canonical_heights_indexed: bool,
    genesis_marker_present: bool,
    genesis_marker_length_valid: bool,
    genesis_marker_matches_expected: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeBlockIndexReloadAdmission {
    repair_missing_genesis_marker: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeCanonicalStateReloadInput {
    nullifier_keys_well_formed: bool,
    nullifier_markers_valid: bool,
    commitment_keys_well_formed: bool,
    commitment_values_well_formed: bool,
    commitment_indexes_contiguous: bool,
    commitment_tree_rebuilt: bool,
    commitment_root_matches_best: bool,
    nullifier_root_matches_best: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeBridgeReplayReloadInput {
    replay_keys_well_formed: bool,
    replay_markers_valid: bool,
    canonical_replay_keys_unique: bool,
    no_missing_loaded_replay_keys: bool,
    no_extra_loaded_replay_keys: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeStagedCiphertextReloadInput {
    key_well_formed: bool,
    ciphertext_within_limit: bool,
    ciphertext_hash_matches_key: bool,
    capacity_available: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeStagedProofReloadInput {
    key_well_formed: bool,
    proof_nonempty: bool,
    proof_within_limit: bool,
    capacity_available: bool,
    byte_capacity_available: bool,
    proof_binding_hash_matches_key: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeMinedWorkAdmissionInput {
    best_height: u64,
    work_height: u64,
    parent_hash_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeMinerIdentityAdmissionInput {
    height: u64,
    public_key_len: usize,
    signature_len: usize,
    public_key_bytes_parse: bool,
    miner_commitment_matches: bool,
    signature_bytes_parse: bool,
    signature_verifies: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeWorkTemplateAdmissionInput {
    best_height: u64,
    cumulative_work_advances: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeRecursiveArtifactContextAdmissionInput {
    best_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeAnnouncedBlockAdmissionRejection {
    HeightNotNext,
    ParentHashMismatch,
    TimestampDidNotAdvance,
    FutureSkew,
    HashWorkHashMismatch,
}

impl NativeAnnouncedBlockAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::HeightNotNext => "height_not_next",
            Self::ParentHashMismatch => "parent_hash_mismatch",
            Self::TimestampDidNotAdvance => "timestamp_did_not_advance",
            Self::FutureSkew => "future_skew",
            Self::HashWorkHashMismatch => "hash_work_hash_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeBlockIndexReloadRejection {
    ChainReconstructionFailed,
    ChainEmpty,
    GenesisMismatch,
    BestMetadataMismatch,
    CanonicalHeightMismatch,
    ChainIdMismatch,
    RulesHashMismatch,
    HashWorkHashMismatch,
    ParentHashMismatch,
    MalformedHeightKey,
    MalformedHeightValue,
    ExtraHeightIndex,
    HeightIndexMismatch,
    HeightHashMismatch,
    MissingHeightIndex,
    GenesisMarkerInvalidLength,
    GenesisMarkerMismatch,
}

impl NativeBlockIndexReloadRejection {
    fn label(self) -> &'static str {
        match self {
            Self::ChainReconstructionFailed => "chain_reconstruction_failed",
            Self::ChainEmpty => "chain_empty",
            Self::GenesisMismatch => "genesis_mismatch",
            Self::BestMetadataMismatch => "best_metadata_mismatch",
            Self::CanonicalHeightMismatch => "canonical_height_mismatch",
            Self::ChainIdMismatch => "chain_id_mismatch",
            Self::RulesHashMismatch => "rules_hash_mismatch",
            Self::HashWorkHashMismatch => "hash_work_hash_mismatch",
            Self::ParentHashMismatch => "parent_hash_mismatch",
            Self::MalformedHeightKey => "malformed_height_key",
            Self::MalformedHeightValue => "malformed_height_value",
            Self::ExtraHeightIndex => "extra_height_index",
            Self::HeightIndexMismatch => "height_index_mismatch",
            Self::HeightHashMismatch => "height_hash_mismatch",
            Self::MissingHeightIndex => "missing_height_index",
            Self::GenesisMarkerInvalidLength => "genesis_marker_invalid_length",
            Self::GenesisMarkerMismatch => "genesis_marker_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeCanonicalStateReloadRejection {
    MalformedNullifierKey,
    InvalidNullifierMarker,
    MalformedCommitmentKey,
    MalformedCommitmentValue,
    CommitmentIndexGap,
    CommitmentTreeRebuildFailed,
    CommitmentRootMismatch,
    NullifierRootMismatch,
}

impl NativeCanonicalStateReloadRejection {
    fn label(self) -> &'static str {
        match self {
            Self::MalformedNullifierKey => "malformed_nullifier_key",
            Self::InvalidNullifierMarker => "invalid_nullifier_marker",
            Self::MalformedCommitmentKey => "malformed_commitment_key",
            Self::MalformedCommitmentValue => "malformed_commitment_value",
            Self::CommitmentIndexGap => "commitment_index_gap",
            Self::CommitmentTreeRebuildFailed => "commitment_tree_rebuild_failed",
            Self::CommitmentRootMismatch => "commitment_root_mismatch",
            Self::NullifierRootMismatch => "nullifier_root_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeBridgeReplayReloadRejection {
    MalformedReplayKey,
    InvalidReplayMarker,
    CanonicalReplayDuplicate,
    MissingConsumedReplayKey,
    ExtraConsumedReplayKey,
}

impl NativeBridgeReplayReloadRejection {
    fn label(self) -> &'static str {
        match self {
            Self::MalformedReplayKey => "malformed_replay_key",
            Self::InvalidReplayMarker => "invalid_replay_marker",
            Self::CanonicalReplayDuplicate => "canonical_replay_duplicate",
            Self::MissingConsumedReplayKey => "missing_consumed_replay_key",
            Self::ExtraConsumedReplayKey => "extra_consumed_replay_key",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativePendingActionReloadRejection {
    MalformedActionKey,
    KeyHashMismatch,
    RecomputedHashMismatch,
    DuplicatePendingAction,
}

impl NativePendingActionReloadRejection {
    fn label(self) -> &'static str {
        match self {
            Self::MalformedActionKey => "malformed_action_key",
            Self::KeyHashMismatch => "key_hash_mismatch",
            Self::RecomputedHashMismatch => "recomputed_hash_mismatch",
            Self::DuplicatePendingAction => "duplicate_pending_action",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeStagedCiphertextReloadRejection {
    MalformedCiphertextKey,
    OversizedCiphertext,
    CiphertextHashMismatch,
    StagedCiphertextCapacityReached,
}

impl NativeStagedCiphertextReloadRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::MalformedCiphertextKey => "malformed_ciphertext_key",
            Self::OversizedCiphertext => "oversized_ciphertext",
            Self::CiphertextHashMismatch => "ciphertext_hash_mismatch",
            Self::StagedCiphertextCapacityReached => "staged_ciphertext_capacity_reached",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeStagedProofReloadRejection {
    MalformedProofKey,
    EmptyProof,
    OversizedProof,
    StagedProofCapacityReached,
    StagedProofByteCapacityReached,
    ProofBindingHashMismatch,
}

impl NativeStagedProofReloadRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::MalformedProofKey => "malformed_proof_key",
            Self::EmptyProof => "empty_proof",
            Self::OversizedProof => "oversized_proof",
            Self::StagedProofCapacityReached => "staged_proof_capacity_reached",
            Self::StagedProofByteCapacityReached => "staged_proof_byte_capacity_reached",
            Self::ProofBindingHashMismatch => "proof_binding_hash_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeMinedWorkAdmissionRejection {
    ParentHashMismatch,
    HeightNotNext,
}

impl NativeMinedWorkAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::ParentHashMismatch => "parent_hash_mismatch",
            Self::HeightNotNext => "height_not_next",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeMinerIdentityAdmissionRejection {
    InvalidMinerPublicKeyLength,
    InvalidMinerSignatureLength,
    InvalidMinerPublicKeyBytes,
    MinerCommitmentMismatch,
    InvalidMinerSignatureBytes,
    NativeMinerSignatureVerificationFailed,
}

impl NativeMinerIdentityAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::InvalidMinerPublicKeyLength => "invalid_miner_public_key_length",
            Self::InvalidMinerSignatureLength => "invalid_miner_signature_length",
            Self::InvalidMinerPublicKeyBytes => "invalid_miner_public_key_bytes",
            Self::MinerCommitmentMismatch => "miner_commitment_mismatch",
            Self::InvalidMinerSignatureBytes => "invalid_miner_signature_bytes",
            Self::NativeMinerSignatureVerificationFailed => {
                "native_miner_signature_verification_failed"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeWorkTemplateAdmissionRejection {
    HeightNotNext,
    CumulativeWorkOverflow,
}

impl NativeWorkTemplateAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::HeightNotNext => "height_not_next",
            Self::CumulativeWorkOverflow => "cumulative_work_overflow",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeRecursiveArtifactContextAdmissionRejection {
    HeightNotNext,
}

impl NativeRecursiveArtifactContextAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::HeightNotNext => "height_not_next",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeActionScopeAdmissionInput {
    candidate_artifact_payload_scoped: bool,
    bridge_route: bool,
    bridge_scope_valid: bool,
    candidate_artifact_route: bool,
    candidate_scope_valid: bool,
    candidate_payload_present: bool,
    coinbase_route: bool,
    coinbase_scope_valid: bool,
    transfer_route: bool,
    transfer_scope_valid: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeActionScopeAdmissionRoute {
    Bridge,
    CandidateArtifact,
    Coinbase,
    Transfer,
}

impl NativeActionScopeAdmissionRoute {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::CandidateArtifact => "candidate_artifact",
            Self::Coinbase => "coinbase",
            Self::Transfer => "transfer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeActionScopeAdmissionRejection {
    CandidateArtifactPayloadWrongRoute,
    BridgeScopeInvalid,
    CandidateScopeInvalid,
    CandidatePayloadMissing,
    CoinbaseScopeInvalid,
    UnsupportedActionRoute,
    TransferScopeInvalid,
}

impl NativeActionScopeAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::CandidateArtifactPayloadWrongRoute => "candidate_artifact_payload_wrong_route",
            Self::BridgeScopeInvalid => "bridge_scope_invalid",
            Self::CandidateScopeInvalid => "candidate_scope_invalid",
            Self::CandidatePayloadMissing => "candidate_payload_missing",
            Self::CoinbaseScopeInvalid => "coinbase_scope_invalid",
            Self::UnsupportedActionRoute => "unsupported_action_route",
            Self::TransferScopeInvalid => "transfer_scope_invalid",
        }
    }
}

#[derive(Clone, Debug)]
struct NativeBlockActionValidationState {
    bridge_replay_state: InboundReplayState,
    previous_transfer_key: Option<[u8; 32]>,
    validated_action_count: usize,
    imported_bridge_replay_count: usize,
}

#[derive(Clone, Copy, Debug)]
struct NativeBlockActionValidationStep {
    scope_input: NativeActionScopeAdmissionInput,
    payload_valid: bool,
    transfer_key: [u8; 32],
    transfer_state_input: NativeTransferStateAdmissionInput,
    bridge_replay_key: Option<[u8; 48]>,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeBlockActionValidationSummary {
    validated_action_count: usize,
    imported_bridge_replay_count: usize,
    last_transfer_key: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeBlockActionValidationRejection {
    ActionCountMismatch,
    ActionHashMismatch,
    DuplicateActionHash,
    CandidateArtifactPayloadWrongRoute,
    BridgeScopeInvalid,
    CandidateScopeInvalid,
    CandidatePayloadMissing,
    CoinbaseScopeInvalid,
    UnsupportedActionRoute,
    TransferScopeInvalid,
    BridgePayloadInvalid,
    CandidatePayloadInvalid,
    CoinbasePayloadInvalid,
    TransferPayloadInvalid,
    BridgeReplayDuplicate,
    TransferOrderInvalid,
    TransferUnknownAnchor,
    TransferNullifierZero,
    TransferNullifierAlreadySpent,
    TransferDuplicateNullifier,
    TransferNullifierAlreadyPending,
    TransferCommitmentZero,
    TransferSidecarCiphertextMissing,
    TransferSidecarCiphertextSizeMissing,
    TransferSidecarCiphertextSizeMismatch,
}

impl NativeBlockActionValidationRejection {
    fn label(self) -> &'static str {
        match self {
            Self::ActionCountMismatch => "action_count_mismatch",
            Self::ActionHashMismatch => "action_hash_mismatch",
            Self::DuplicateActionHash => "duplicate_action_hash",
            Self::CandidateArtifactPayloadWrongRoute => "candidate_artifact_payload_wrong_route",
            Self::BridgeScopeInvalid => "bridge_scope_invalid",
            Self::CandidateScopeInvalid => "candidate_scope_invalid",
            Self::CandidatePayloadMissing => "candidate_payload_missing",
            Self::CoinbaseScopeInvalid => "coinbase_scope_invalid",
            Self::UnsupportedActionRoute => "unsupported_action_route",
            Self::TransferScopeInvalid => "transfer_scope_invalid",
            Self::BridgePayloadInvalid => "bridge_payload_invalid",
            Self::CandidatePayloadInvalid => "candidate_payload_invalid",
            Self::CoinbasePayloadInvalid => "coinbase_payload_invalid",
            Self::TransferPayloadInvalid => "transfer_payload_invalid",
            Self::BridgeReplayDuplicate => "bridge_replay_duplicate",
            Self::TransferOrderInvalid => "transfer_order_invalid",
            Self::TransferUnknownAnchor => "transfer_unknown_anchor",
            Self::TransferNullifierZero => "transfer_nullifier_zero",
            Self::TransferNullifierAlreadySpent => "transfer_nullifier_already_spent",
            Self::TransferDuplicateNullifier => "transfer_duplicate_nullifier",
            Self::TransferNullifierAlreadyPending => "transfer_nullifier_already_pending",
            Self::TransferCommitmentZero => "transfer_commitment_zero",
            Self::TransferSidecarCiphertextMissing => "transfer_sidecar_ciphertext_missing",
            Self::TransferSidecarCiphertextSizeMissing => {
                "transfer_sidecar_ciphertext_size_missing"
            }
            Self::TransferSidecarCiphertextSizeMismatch => {
                "transfer_sidecar_ciphertext_size_mismatch"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeBridgeActionPayloadAdmissionInput {
    bridge_route: bool,
    state_deltas_absent: bool,
    action_kind: NativeBridgeActionPayloadKind,
    outbound_payload_nonempty: bool,
    inbound_proof_receipt_nonempty: bool,
    inbound_replay_key_matches: bool,
    inbound_destination_matches: bool,
    inbound_payload_hash_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeBridgeWitnessExportAdmissionInput {
    block_hash_parameter_valid: bool,
    block_known: bool,
    canonical_height_present: bool,
    block_is_canonical: bool,
    block_actions_decoded: bool,
    message_index_in_bounds: bool,
    parent_known: bool,
    best_height: u64,
    message_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeInboundBridgeReceiptAdmissionInput {
    source_chain_matches: bool,
    rules_hash_matches: bool,
    message_nonce_matches: bool,
    message_hash_matches: bool,
    checkpoint_height: u64,
    canonical_tip_height: u64,
    confirmations_checked: u32,
    min_confirmations: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeBridgeWitnessBackscanEntry {
    height: u64,
    canonical_hash_present: bool,
    block_known: bool,
    block_actions_decoded: bool,
    message_index_in_bounds: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeBridgeActionPayloadKind {
    Outbound,
    Inbound,
    Register,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeBridgeActionPayloadAdmissionRejection {
    NotBridgeAction,
    StateDeltasPresent,
    UnsupportedBridgeAction,
    OutboundPayloadEmpty,
    InboundProofReceiptEmpty,
    InboundReplayKeyMismatch,
    InboundDestinationMismatch,
    InboundPayloadHashMismatch,
}

impl NativeBridgeActionPayloadAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::NotBridgeAction => "not_bridge_action",
            Self::StateDeltasPresent => "state_deltas_present",
            Self::UnsupportedBridgeAction => "unsupported_bridge_action",
            Self::OutboundPayloadEmpty => "outbound_payload_empty",
            Self::InboundProofReceiptEmpty => "inbound_proof_receipt_empty",
            Self::InboundReplayKeyMismatch => "inbound_replay_key_mismatch",
            Self::InboundDestinationMismatch => "inbound_destination_mismatch",
            Self::InboundPayloadHashMismatch => "inbound_payload_hash_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeBridgeWitnessExportAdmissionRejection {
    MalformedBlockHash,
    UnknownBlock,
    MissingCanonicalHeight,
    NoncanonicalBlock,
    BlockActionsDecodeFailed,
    MessageIndexOutOfBounds,
    MissingParent,
    TipBeforeMessage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeInboundBridgeReceiptAdmissionRejection {
    SourceChainMismatch,
    RulesHashMismatch,
    MessageNonceMismatch,
    MessageHashMismatch,
    TipBeforeMessage,
    ConfirmationsOverstated,
    Underconfirmed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeBridgeWitnessBackscanRejection {
    BlockActionsDecodeFailed,
    NoBridgeMessageInBackscan,
}

impl NativeBridgeWitnessExportAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::MalformedBlockHash => "malformed_block_hash",
            Self::UnknownBlock => "unknown_block",
            Self::MissingCanonicalHeight => "missing_canonical_height",
            Self::NoncanonicalBlock => "noncanonical_block",
            Self::BlockActionsDecodeFailed => "block_actions_decode_failed",
            Self::MessageIndexOutOfBounds => "message_index_out_of_bounds",
            Self::MissingParent => "missing_parent",
            Self::TipBeforeMessage => "tip_before_message",
        }
    }
}

impl NativeInboundBridgeReceiptAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::SourceChainMismatch => "source_chain_mismatch",
            Self::RulesHashMismatch => "rules_hash_mismatch",
            Self::MessageNonceMismatch => "message_nonce_mismatch",
            Self::MessageHashMismatch => "message_hash_mismatch",
            Self::TipBeforeMessage => "tip_before_message",
            Self::ConfirmationsOverstated => "confirmations_overstated",
            Self::Underconfirmed => "underconfirmed",
        }
    }
}

impl NativeBridgeWitnessBackscanRejection {
    fn label(self) -> &'static str {
        match self {
            Self::BlockActionsDecodeFailed => "block_actions_decode_failed",
            Self::NoBridgeMessageInBackscan => "no_bridge_message_in_backscan",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeRisc0ReleaseVerifierInput {
    image_id_matches: bool,
    journal_decodes: bool,
    verifier_enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeRisc0ReleaseVerifierRejection {
    ImageIdMismatch,
    JournalDecodeFailed,
    VerifierDisabled,
}

impl NativeRisc0ReleaseVerifierRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::ImageIdMismatch => "image_id_mismatch",
            Self::JournalDecodeFailed => "journal_decode_failed",
            Self::VerifierDisabled => "verifier_disabled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeTransferPayloadAdmissionInput {
    proof_bytes: usize,
    max_proof_bytes: usize,
    anchor_matches: bool,
    commitments_match: bool,
    inline_ciphertext_bytes: usize,
    max_ciphertext_bytes: usize,
    ciphertext_hashes_match: bool,
    ciphertext_sizes_match: bool,
    binding_hash_matches: bool,
    proof_binding_hash_matches_key: bool,
    fee_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeTransferPayloadRoute {
    Inline,
    Sidecar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeTransferPayloadAdmissionRejection {
    ProofMissing,
    ProofTooLarge,
    AnchorMismatch,
    CommitmentsMismatch,
    InlineCiphertextTooLarge,
    CiphertextHashesMismatch,
    CiphertextSizesMismatch,
    BindingHashMismatch,
    ProofBindingHashMismatch,
    FeeMismatch,
}

impl NativeTransferPayloadAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::ProofMissing => "proof_missing",
            Self::ProofTooLarge => "proof_too_large",
            Self::AnchorMismatch => "anchor_mismatch",
            Self::CommitmentsMismatch => "commitments_mismatch",
            Self::InlineCiphertextTooLarge => "inline_ciphertext_too_large",
            Self::CiphertextHashesMismatch => "ciphertext_hashes_mismatch",
            Self::CiphertextSizesMismatch => "ciphertext_sizes_mismatch",
            Self::BindingHashMismatch => "binding_hash_mismatch",
            Self::ProofBindingHashMismatch => "proof_binding_hash_mismatch",
            Self::FeeMismatch => "fee_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeTransferStateAdmissionInput {
    anchor_known: bool,
    nullifier_state: NativeTransferNullifierAdmissionState,
    commitments_nonzero: bool,
    sidecar_route: bool,
    sidecar_ciphertexts_available: bool,
    sidecar_ciphertext_sizes_present: bool,
    sidecar_ciphertext_sizes_match: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeTransferNullifierAdmissionState {
    Valid,
    Zero,
    AlreadySpent,
    Duplicate,
    AlreadyPending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeTransferStateAdmissionContext {
    Mempool,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeTransferStateAdmissionRejection {
    UnknownAnchor,
    NullifierZero,
    NullifierAlreadySpent,
    DuplicateNullifier,
    NullifierAlreadyPending,
    CommitmentZero,
    SidecarCiphertextMissing,
    SidecarCiphertextSizeMissing,
    SidecarCiphertextSizeMismatch,
}

impl NativeTransferStateAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::UnknownAnchor => "unknown_anchor",
            Self::NullifierZero => "nullifier_zero",
            Self::NullifierAlreadySpent => "nullifier_already_spent",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::NullifierAlreadyPending => "nullifier_already_pending",
            Self::CommitmentZero => "commitment_zero",
            Self::SidecarCiphertextMissing => "sidecar_ciphertext_missing",
            Self::SidecarCiphertextSizeMissing => "sidecar_ciphertext_size_missing",
            Self::SidecarCiphertextSizeMismatch => "sidecar_ciphertext_size_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeActionStateEffect {
    next_leaf_count: u64,
    imported_nullifier_count: usize,
    imported_bridge_replay: bool,
}

#[derive(Clone, Debug)]
struct NativePlannedActionEffect {
    commitment_start: u64,
    ciphertexts: Vec<Vec<u8>>,
    replay_key: Option<[u8; 48]>,
}

#[derive(Clone, Debug)]
struct NativeMaterializedActionPayload {
    ciphertexts: Vec<Vec<u8>>,
    replay_key: Option<[u8; 48]>,
}

#[derive(Clone, Debug)]
struct NativeCanonicalIndexPlan {
    commitment_entries: Vec<(u64, [u8; 48])>,
    nullifier_entries: Vec<[u8; 48]>,
    bridge_replay_entries: Vec<[u8; 48]>,
    ciphertext_index_entries: Vec<([u8; 48], Vec<u8>)>,
    ciphertext_archive_entries: Vec<(u64, Vec<u8>)>,
}

#[derive(Clone, Copy, Debug)]
struct NativeActionStreamStep<'a> {
    commitment_count: usize,
    ciphertext_count: usize,
    nullifiers: &'a [[u8; 48]],
    replay_key: Option<[u8; 48]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeActionStreamEffect {
    next_leaf_count: u64,
    imported_nullifier_count: usize,
    imported_bridge_replay_count: usize,
    planned_starts: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeActionPlanApplicationSummary {
    next_leaf_count: u64,
    applied_action_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeActionPlanApplicationAdmissionRejection {
    PlanLengthMismatch,
    PlannedStartMismatch,
    CommitmentIndexOverflow,
}

impl NativeActionPlanApplicationAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::PlanLengthMismatch => "plan_length_mismatch",
            Self::PlannedStartMismatch => "planned_start_mismatch",
            Self::CommitmentIndexOverflow => "commitment_index_overflow",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct NativeActionWireReplayProjectionStep {
    ciphertext_hash_count: usize,
    ciphertext_size_count: usize,
    planned_ciphertext_count: usize,
    ciphertext_hashes_match: bool,
    ciphertext_sizes_match: bool,
    planned_replay_present: bool,
    replay_key_matches: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeActionWireReplayProjectionSummary {
    projected_action_count: usize,
    projected_ciphertext_row_count: usize,
    projected_bridge_replay_row_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeActionWireReplayProjectionAdmissionRejection {
    PlanLengthMismatch,
    CiphertextCountMismatch,
    CiphertextHashMismatch,
    CiphertextSizeMismatch,
    ReplayKeyMismatch,
}

impl NativeActionWireReplayProjectionAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::PlanLengthMismatch => "plan_length_mismatch",
            Self::CiphertextCountMismatch => "ciphertext_count_mismatch",
            Self::CiphertextHashMismatch => "ciphertext_hash_mismatch",
            Self::CiphertextSizeMismatch => "ciphertext_size_mismatch",
            Self::ReplayKeyMismatch => "replay_key_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeActionStateEffectRejection {
    CiphertextCountMismatch,
    CommitmentIndexOverflow,
    NullifierZero,
    DuplicateNullifier,
    BridgeReplayDuplicate,
}

impl NativeActionStateEffectRejection {
    fn label(self) -> &'static str {
        match self {
            Self::CiphertextCountMismatch => "ciphertext_count_mismatch",
            Self::CommitmentIndexOverflow => "commitment_index_overflow",
            Self::NullifierZero => "nullifier_zero",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::BridgeReplayDuplicate => "bridge_replay_duplicate",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeCoinbaseActionPayloadAdmissionInput {
    amount_nonzero: bool,
    commitment_matches: bool,
    commitment_nonzero: bool,
    ciphertext_bytes: usize,
    max_ciphertext_bytes: usize,
    ciphertext_hash_matches: bool,
    ciphertext_size_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeCoinbaseActionPayloadAdmissionRejection {
    AmountZero,
    CommitmentMismatch,
    CommitmentZero,
    CiphertextTooLarge,
    CiphertextHashMismatch,
    CiphertextSizeMismatch,
}

impl NativeCoinbaseActionPayloadAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::AmountZero => "amount_zero",
            Self::CommitmentMismatch => "commitment_mismatch",
            Self::CommitmentZero => "commitment_zero",
            Self::CiphertextTooLarge => "ciphertext_too_large",
            Self::CiphertextHashMismatch => "ciphertext_hash_mismatch",
            Self::CiphertextSizeMismatch => "ciphertext_size_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeCandidateArtifactAdmissionInput {
    state_deltas_absent: bool,
    artifact_present: bool,
    schema_matches: bool,
    tx_count: u32,
    max_tx_count: u32,
    da_chunk_count: u32,
    proof_mode_recursive_block: bool,
    proof_kind_recursive_block_v2: bool,
    verifier_profile_matches: bool,
    commitment_proof_empty: bool,
    receipt_root_absent: bool,
    recursive_payload_present: bool,
    recursive_proof_bytes: usize,
    max_recursive_proof_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeCandidateArtifactAdmissionRejection {
    StateDeltasPresent,
    ArtifactMissing,
    SchemaMismatch,
    TxCountZero,
    TxCountTooLarge,
    DaChunkCountZero,
    WrongProofMode,
    WrongProofKind,
    VerifierProfileMismatch,
    CommitmentProofPresent,
    ReceiptRootPresent,
    RecursivePayloadMissing,
    RecursiveProofEmpty,
    RecursiveProofTooLarge,
}

impl NativeCandidateArtifactAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::StateDeltasPresent => "state_deltas_present",
            Self::ArtifactMissing => "artifact_missing",
            Self::SchemaMismatch => "schema_mismatch",
            Self::TxCountZero => "tx_count_zero",
            Self::TxCountTooLarge => "tx_count_too_large",
            Self::DaChunkCountZero => "da_chunk_count_zero",
            Self::WrongProofMode => "wrong_proof_mode",
            Self::WrongProofKind => "wrong_proof_kind",
            Self::VerifierProfileMismatch => "verifier_profile_mismatch",
            Self::CommitmentProofPresent => "commitment_proof_present",
            Self::ReceiptRootPresent => "receipt_root_present",
            Self::RecursivePayloadMissing => "recursive_payload_missing",
            Self::RecursiveProofEmpty => "recursive_proof_empty",
            Self::RecursiveProofTooLarge => "recursive_proof_too_large",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeCandidateArtifactCouplingAdmissionInput {
    transfer_count: usize,
    candidate_artifact_count: usize,
    candidate_tx_count_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeCandidateArtifactCouplingAdmissionRejection {
    CandidateWithoutTransfers,
    MissingOrMultipleCandidateArtifact,
    CandidateTxCountMismatch,
}

impl NativeCandidateArtifactCouplingAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::CandidateWithoutTransfers => "candidate_without_transfers",
            Self::MissingOrMultipleCandidateArtifact => "missing_or_multiple_candidate_artifact",
            Self::CandidateTxCountMismatch => "candidate_tx_count_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeMineableActionAdmissionInput {
    candidate_artifact_route: bool,
    candidate_artifact_selected: bool,
    sidecar_transfer_route: bool,
    sidecar_ciphertexts_available: bool,
    sidecar_ciphertext_sizes_present: bool,
    sidecar_ciphertext_sizes_match: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeMineableActionAdmissionRejection {
    UnselectedCandidateArtifact,
    SidecarCiphertextMissing,
    SidecarCiphertextSizeMissing,
    SidecarCiphertextSizeMismatch,
}

impl NativeMineableActionAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::UnselectedCandidateArtifact => "unselected_candidate_artifact",
            Self::SidecarCiphertextMissing => "sidecar_ciphertext_missing",
            Self::SidecarCiphertextSizeMissing => "sidecar_ciphertext_size_missing",
            Self::SidecarCiphertextSizeMismatch => "sidecar_ciphertext_size_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeTxLeafActionBindingAdmissionInput {
    nullifiers_match: bool,
    commitments_match: bool,
    ciphertext_hashes_match: bool,
    input_count_matches: bool,
    output_count_matches: bool,
    version_matches: bool,
    fee_matches: bool,
    stablecoin_payload_matches: bool,
    balance_tag_matches: bool,
    receipt_statement_hash_matches: bool,
    public_inputs_digest_matches: bool,
    proof_digest_matches: bool,
    proof_backend_matches: bool,
    ciphertext_payload_hashes_match: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeTxLeafActionBindingAdmissionRejection {
    NullifiersMismatch,
    CommitmentsMismatch,
    CiphertextHashesMismatch,
    InputCountMismatch,
    OutputCountMismatch,
    VersionMismatch,
    FeeMismatch,
    StablecoinPayloadMismatch,
    BalanceTagMismatch,
    ReceiptStatementHashMismatch,
    PublicInputsDigestMismatch,
    ProofDigestMismatch,
    ProofBackendMismatch,
    CiphertextPayloadHashMismatch,
}

impl NativeTxLeafActionBindingAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::NullifiersMismatch => "nullifiers_mismatch",
            Self::CommitmentsMismatch => "commitments_mismatch",
            Self::CiphertextHashesMismatch => "ciphertext_hashes_mismatch",
            Self::InputCountMismatch => "input_count_mismatch",
            Self::OutputCountMismatch => "output_count_mismatch",
            Self::VersionMismatch => "version_mismatch",
            Self::FeeMismatch => "fee_mismatch",
            Self::StablecoinPayloadMismatch => "stablecoin_payload_mismatch",
            Self::BalanceTagMismatch => "balance_tag_mismatch",
            Self::ReceiptStatementHashMismatch => "receipt_statement_hash_mismatch",
            Self::PublicInputsDigestMismatch => "public_inputs_digest_mismatch",
            Self::ProofDigestMismatch => "proof_digest_mismatch",
            Self::ProofBackendMismatch => "proof_backend_mismatch",
            Self::CiphertextPayloadHashMismatch => "ciphertext_payload_hash_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeCandidateArtifactBindingAdmissionInput {
    da_root_matches: bool,
    tx_statements_commitment_matches: bool,
    recursive_state_root_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeCandidateArtifactBindingAdmissionRejection {
    DaRootMismatch,
    TxStatementCommitmentMismatch,
    RecursiveStateRootMismatch,
}

impl NativeCandidateArtifactBindingAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::DaRootMismatch => "da_root_mismatch",
            Self::TxStatementCommitmentMismatch => "tx_statement_commitment_mismatch",
            Self::RecursiveStateRootMismatch => "recursive_state_root_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeCoinbaseAccountingAdmissionInput {
    coinbase_count: usize,
    height: u64,
    transfer_fee_total: Option<u64>,
    observed_coinbase_amount: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeCoinbaseAccountingAdmissionRejection {
    MultipleCoinbase,
    FeeTotalOverflow,
    RewardOverflow,
    CoinbaseAmountMissing,
    AmountMismatch,
}

impl NativeCoinbaseAccountingAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::MultipleCoinbase => "multiple_coinbase",
            Self::FeeTotalOverflow => "fee_total_overflow",
            Self::RewardOverflow => "reward_overflow",
            Self::CoinbaseAmountMissing => "coinbase_amount_missing",
            Self::AmountMismatch => "amount_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeBlockCommitmentAdmissionInput {
    tx_count_matches: bool,
    state_root_matches: bool,
    kernel_root_matches: bool,
    nullifier_root_matches: bool,
    extrinsics_root_matches: bool,
    message_root_matches: bool,
    message_count_matches: bool,
    header_mmr_root_matches: bool,
    header_mmr_len_matches: bool,
    supply_digest_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeBlockReplayRefinementInput {
    leaf_start: u64,
    parent_supply: u128,
    height: u64,
    fee_total: u64,
    has_coinbase: bool,
    claimed_supply: u128,
    tx_count_matches: bool,
    state_root_matches: bool,
    kernel_root_matches: bool,
    nullifier_root_matches: bool,
    extrinsics_root_matches: bool,
    message_root_matches: bool,
    message_count_matches: bool,
    header_mmr_root_matches: bool,
    header_mmr_len_matches: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeBlockReplayRefinementSummary {
    next_leaf_count: u64,
    imported_nullifier_count: usize,
    imported_bridge_replay_count: usize,
    planned_starts: Vec<u64>,
    expected_supply: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeCanonicalReorgChainAdmissionInput {
    chain_nonempty: bool,
    genesis_matches_expected: bool,
    best_metadata_matches_chain: bool,
    canonical_heights_contiguous: bool,
    canonical_chain_ids_match: bool,
    canonical_rules_hashes_match: bool,
    canonical_hashes_match_work_hashes: bool,
    canonical_parent_hashes_contiguous: bool,
    block_record_count_matches_chain: bool,
    block_records_match_chain: bool,
    height_entry_count_matches_chain: bool,
    height_entries_match_chain: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeCanonicalReorgChainAdmissionRejection {
    ChainEmpty,
    GenesisMismatch,
    BestMetadataMismatch,
    CanonicalHeightMismatch,
    ChainIdMismatch,
    RulesHashMismatch,
    HashWorkHashMismatch,
    ParentHashMismatch,
    BlockRecordCountMismatch,
    BlockRecordMismatch,
    HeightEntryCountMismatch,
    HeightEntryMismatch,
}

impl NativeCanonicalReorgChainAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::ChainEmpty => "chain_empty",
            Self::GenesisMismatch => "genesis_mismatch",
            Self::BestMetadataMismatch => "best_metadata_mismatch",
            Self::CanonicalHeightMismatch => "canonical_height_mismatch",
            Self::ChainIdMismatch => "chain_id_mismatch",
            Self::RulesHashMismatch => "rules_hash_mismatch",
            Self::HashWorkHashMismatch => "hash_work_hash_mismatch",
            Self::ParentHashMismatch => "parent_hash_mismatch",
            Self::BlockRecordCountMismatch => "block_record_count_mismatch",
            Self::BlockRecordMismatch => "block_record_mismatch",
            Self::HeightEntryCountMismatch => "height_entry_count_mismatch",
            Self::HeightEntryMismatch => "height_entry_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeBlockCommitmentAdmissionRejection {
    TxCountMismatch,
    StateRootMismatch,
    KernelRootMismatch,
    NullifierRootMismatch,
    ExtrinsicsRootMismatch,
    MessageRootMismatch,
    MessageCountMismatch,
    HeaderMmrRootMismatch,
    HeaderMmrLenMismatch,
    SupplyDigestMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeAtomicCommitKind {
    MinedBlockCommit,
    CanonicalReorgCommit,
    CanonicalIndexRepair,
    NoncanonicalBlockRecord,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeAtomicCommitManifestAdmissionInput {
    kind: NativeAtomicCommitKind,
    action_count: usize,
    planned_action_count: usize,
    chain_block_count: usize,
    height_entry_count: usize,
    pending_entry_count: usize,
    source_commitment_count: usize,
    source_nullifier_count: usize,
    source_bridge_replay_count: usize,
    source_ciphertext_index_count: usize,
    source_ciphertext_archive_count: usize,
    source_staged_ciphertext_removal_count: usize,
    block_record_writes: usize,
    height_index_writes: usize,
    best_pointer_writes: usize,
    canonical_index_cleared: bool,
    pending_tree_cleared: bool,
    pending_action_removals: usize,
    pending_action_writes: usize,
    commitment_writes: usize,
    nullifier_writes: usize,
    bridge_replay_writes: usize,
    ciphertext_index_writes: usize,
    ciphertext_archive_writes: usize,
    staged_ciphertext_removals: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeAtomicCommitManifestAdmissionRejection {
    MinedPlanLengthMismatch,
    BlockRecordWritesMismatch,
    HeightIndexWritesMismatch,
    BestPointerWritesMismatch,
    CanonicalIndexClearMismatch,
    PendingTreeClearMismatch,
    PendingActionRemovalMismatch,
    PendingActionWriteMismatch,
    CommitmentWriteMismatch,
    NullifierWriteMismatch,
    BridgeReplayWriteMismatch,
    CiphertextIndexWriteMismatch,
    CiphertextArchiveWriteMismatch,
    StagedCiphertextRemovalMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeStorageDurabilityAdmissionInput {
    transaction_accepted: bool,
    durability_flushed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeStorageDurabilityAdmissionRejection {
    TransactionRejected,
    DurabilityFlushFailed,
}

impl NativeStorageDurabilityAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::TransactionRejected => "transaction_rejected",
            Self::DurabilityFlushFailed => "durability_flush_failed",
        }
    }
}

impl NativeAtomicCommitManifestAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::MinedPlanLengthMismatch => "mined_plan_length_mismatch",
            Self::BlockRecordWritesMismatch => "block_record_writes_mismatch",
            Self::HeightIndexWritesMismatch => "height_index_writes_mismatch",
            Self::BestPointerWritesMismatch => "best_pointer_writes_mismatch",
            Self::CanonicalIndexClearMismatch => "canonical_index_clear_mismatch",
            Self::PendingTreeClearMismatch => "pending_tree_clear_mismatch",
            Self::PendingActionRemovalMismatch => "pending_action_removal_mismatch",
            Self::PendingActionWriteMismatch => "pending_action_write_mismatch",
            Self::CommitmentWriteMismatch => "commitment_write_mismatch",
            Self::NullifierWriteMismatch => "nullifier_write_mismatch",
            Self::BridgeReplayWriteMismatch => "bridge_replay_write_mismatch",
            Self::CiphertextIndexWriteMismatch => "ciphertext_index_write_mismatch",
            Self::CiphertextArchiveWriteMismatch => "ciphertext_archive_write_mismatch",
            Self::StagedCiphertextRemovalMismatch => "staged_ciphertext_removal_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeBlockReplayRefinementRejection {
    CiphertextCountMismatch,
    CommitmentIndexOverflow,
    NullifierZero,
    DuplicateNullifier,
    BridgeReplayDuplicate,
    SupplyDeltaInvalid,
    TxCountMismatch,
    StateRootMismatch,
    KernelRootMismatch,
    NullifierRootMismatch,
    ExtrinsicsRootMismatch,
    MessageRootMismatch,
    MessageCountMismatch,
    HeaderMmrRootMismatch,
    HeaderMmrLenMismatch,
    SupplyDigestMismatch,
}

impl NativeBlockReplayRefinementRejection {
    fn label(self) -> &'static str {
        match self {
            Self::CiphertextCountMismatch => "ciphertext_count_mismatch",
            Self::CommitmentIndexOverflow => "commitment_index_overflow",
            Self::NullifierZero => "nullifier_zero",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::BridgeReplayDuplicate => "bridge_replay_duplicate",
            Self::SupplyDeltaInvalid => "supply_delta_invalid",
            Self::TxCountMismatch => "tx_count_mismatch",
            Self::StateRootMismatch => "state_root_mismatch",
            Self::KernelRootMismatch => "kernel_root_mismatch",
            Self::NullifierRootMismatch => "nullifier_root_mismatch",
            Self::ExtrinsicsRootMismatch => "extrinsics_root_mismatch",
            Self::MessageRootMismatch => "message_root_mismatch",
            Self::MessageCountMismatch => "message_count_mismatch",
            Self::HeaderMmrRootMismatch => "header_mmr_root_mismatch",
            Self::HeaderMmrLenMismatch => "header_mmr_len_mismatch",
            Self::SupplyDigestMismatch => "supply_digest_mismatch",
        }
    }
}

impl NativeBlockCommitmentAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::TxCountMismatch => "tx_count_mismatch",
            Self::StateRootMismatch => "state_root_mismatch",
            Self::KernelRootMismatch => "kernel_root_mismatch",
            Self::NullifierRootMismatch => "nullifier_root_mismatch",
            Self::ExtrinsicsRootMismatch => "extrinsics_root_mismatch",
            Self::MessageRootMismatch => "message_root_mismatch",
            Self::MessageCountMismatch => "message_count_mismatch",
            Self::HeaderMmrRootMismatch => "header_mmr_root_mismatch",
            Self::HeaderMmrLenMismatch => "header_mmr_len_mismatch",
            Self::SupplyDigestMismatch => "supply_digest_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeMempoolByteBudgetAdmissionInput {
    pending_bytes: usize,
    candidate_bytes: usize,
    max_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeStagedProofByteBudgetAdmissionInput {
    staged_bytes: usize,
    existing_bytes: usize,
    proof_bytes: usize,
    max_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeResourceBudgetAdmissionRejection {
    MempoolByteBudgetExceeded,
    StagedProofByteBudgetExceeded,
}

impl NativeResourceBudgetAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::MempoolByteBudgetExceeded => "mempool_byte_budget_exceeded",
            Self::StagedProofByteBudgetExceeded => "staged_proof_byte_budget_exceeded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeSidecarRequestCountAdmissionInput {
    item_count: usize,
    max_items: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeSidecarCapacityAdmissionInput {
    staged_count: usize,
    max_staged_count: usize,
    replaces_existing: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeProofSidecarMetadataAdmissionInput {
    binding_hash_present: bool,
    binding_hash_valid: bool,
    proof_present: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeProofSidecarDecodedAdmissionInput {
    proof_bytes: usize,
    max_proof_bytes: usize,
    proof_binding_hash_matches_key: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeSidecarUploadAdmissionRejection {
    TooManyCiphertexts,
    TooManyProofs,
    StagedCiphertextCapacityReached,
    StagedProofCapacityReached,
    ProofBindingHashMissing,
    InvalidBindingHash,
    ProofMissing,
    ProofEmpty,
    ProofTooLarge,
    ProofBindingHashMismatch,
}

impl NativeSidecarUploadAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::TooManyCiphertexts => "too_many_ciphertexts",
            Self::TooManyProofs => "too_many_proofs",
            Self::StagedCiphertextCapacityReached => "staged_ciphertext_capacity_reached",
            Self::StagedProofCapacityReached => "staged_proof_capacity_reached",
            Self::ProofBindingHashMissing => "proof_binding_hash_missing",
            Self::InvalidBindingHash => "invalid_binding_hash",
            Self::ProofMissing => "proof_missing",
            Self::ProofEmpty => "proof_empty",
            Self::ProofTooLarge => "proof_too_large",
            Self::ProofBindingHashMismatch => "proof_binding_hash_mismatch",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitActionRpcRequest {
    binding_circuit: u16,
    binding_crypto: u16,
    family_id: u16,
    action_id: u16,
    #[serde(default)]
    object_refs: Vec<SubmitActionObjectRef>,
    #[serde(default)]
    new_nullifiers: Vec<String>,
    public_args: String,
    #[serde(default)]
    authorization_proof: Option<String>,
    #[serde(default)]
    authorization_signatures: Vec<SubmitActionSignature>,
    #[serde(default)]
    aux_data: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct SubmitActionObjectRef {
    family_id: u16,
    object_id: String,
    expected_root: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct SubmitActionSignature {
    key_id: String,
    signature_scheme: u16,
    signature_bytes: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeActionRequestProjectionAdmissionRejection {
    JsonDecodeRejected,
    KernelEnvelopeFieldsPresent,
    UnsupportedRoute,
    NonTransferNullifiers,
    TooManyNullifiers,
    InvalidNullifierHex,
    PublicArgsTooLarge,
    PublicArgsBase64Rejected,
    DecodedPublicArgsTooLarge,
    RoutePayloadDecodeNotExact,
}

#[cfg(test)]
impl NativeActionRequestProjectionAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::JsonDecodeRejected => "json_decode_rejected",
            Self::KernelEnvelopeFieldsPresent => "kernel_envelope_fields_present",
            Self::UnsupportedRoute => "unsupported_route",
            Self::NonTransferNullifiers => "non_transfer_nullifiers",
            Self::TooManyNullifiers => "too_many_nullifiers",
            Self::InvalidNullifierHex => "invalid_nullifier_hex",
            Self::PublicArgsTooLarge => "public_args_too_large",
            Self::PublicArgsBase64Rejected => "public_args_base64_rejected",
            Self::DecodedPublicArgsTooLarge => "decoded_public_args_too_large",
            Self::RoutePayloadDecodeNotExact => "route_payload_decode_not_exact",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct NativeActionRequestProjectionAdmissionInput {
    json_decode_accepts: bool,
    kernel_envelope_fields_absent: bool,
    route_supported: bool,
    nullifier_scope_valid: bool,
    nullifier_count_within_limit: bool,
    nullifier_hex_valid: bool,
    public_args_encoded_within_limit: bool,
    public_args_base64_decodes: bool,
    public_args_decoded_within_limit: bool,
    route_payload_decodes_exactly: bool,
}

fn evaluate_native_action_request_projection_admission(
    input: NativeActionRequestProjectionAdmissionInput,
) -> std::result::Result<(), NativeActionRequestProjectionAdmissionRejection> {
    if !input.json_decode_accepts {
        Err(NativeActionRequestProjectionAdmissionRejection::JsonDecodeRejected)
    } else if !input.kernel_envelope_fields_absent {
        Err(NativeActionRequestProjectionAdmissionRejection::KernelEnvelopeFieldsPresent)
    } else if !input.route_supported {
        Err(NativeActionRequestProjectionAdmissionRejection::UnsupportedRoute)
    } else if !input.nullifier_scope_valid {
        Err(NativeActionRequestProjectionAdmissionRejection::NonTransferNullifiers)
    } else if !input.nullifier_count_within_limit {
        Err(NativeActionRequestProjectionAdmissionRejection::TooManyNullifiers)
    } else if !input.nullifier_hex_valid {
        Err(NativeActionRequestProjectionAdmissionRejection::InvalidNullifierHex)
    } else if !input.public_args_encoded_within_limit {
        Err(NativeActionRequestProjectionAdmissionRejection::PublicArgsTooLarge)
    } else if !input.public_args_base64_decodes {
        Err(NativeActionRequestProjectionAdmissionRejection::PublicArgsBase64Rejected)
    } else if !input.public_args_decoded_within_limit {
        Err(NativeActionRequestProjectionAdmissionRejection::DecodedPublicArgsTooLarge)
    } else if !input.route_payload_decodes_exactly {
        Err(NativeActionRequestProjectionAdmissionRejection::RoutePayloadDecodeNotExact)
    } else {
        Ok(())
    }
}

fn native_action_request_projection_error(
    rejection: NativeActionRequestProjectionAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeActionRequestProjectionAdmissionRejection::JsonDecodeRejected => {
            anyhow!("native action request JSON decode rejected")
        }
        NativeActionRequestProjectionAdmissionRejection::KernelEnvelopeFieldsPresent => anyhow!(
            "native action request contains non-empty kernel envelope fields not implemented by native consensus"
        ),
        NativeActionRequestProjectionAdmissionRejection::UnsupportedRoute => {
            anyhow!("unsupported native action route")
        }
        NativeActionRequestProjectionAdmissionRejection::NonTransferNullifiers => {
            anyhow!("new_nullifiers must be empty for non-transfer actions")
        }
        NativeActionRequestProjectionAdmissionRejection::TooManyNullifiers => anyhow!(
            "new_nullifiers length exceeds MAX_INPUTS {}",
            transaction_core::constants::MAX_INPUTS
        ),
        NativeActionRequestProjectionAdmissionRejection::InvalidNullifierHex => {
            anyhow!("invalid nullifier hex")
        }
        NativeActionRequestProjectionAdmissionRejection::PublicArgsTooLarge => anyhow!(
            "public_args exceeds native action limit of {MAX_NATIVE_RPC_ACTION_BYTES} bytes"
        ),
        NativeActionRequestProjectionAdmissionRejection::PublicArgsBase64Rejected => {
            anyhow!("decode public_args failed")
        }
        NativeActionRequestProjectionAdmissionRejection::DecodedPublicArgsTooLarge => anyhow!(
            "decoded public_args exceeds native action limit of {MAX_NATIVE_RPC_ACTION_BYTES} bytes"
        ),
        NativeActionRequestProjectionAdmissionRejection::RoutePayloadDecodeNotExact => anyhow!(
            "native action request route payload decode not exact: trailing bytes or non-canonical payload"
        ),
    }
}

fn decode_submit_action_rpc_request(request: Value) -> Result<SubmitActionRpcRequest> {
    serde_json::from_value(request).context("decode submit action request")
}

fn native_submit_action_is_transfer_route(family_id: u16, action_id: u16) -> bool {
    family_id == FAMILY_SHIELDED_POOL
        && matches!(
            action_id,
            ACTION_SHIELDED_TRANSFER_INLINE | ACTION_SHIELDED_TRANSFER_SIDECAR
        )
}

fn native_submit_action_route_supported(family_id: u16, action_id: u16) -> bool {
    matches!(
        (family_id, action_id),
        (FAMILY_BRIDGE, ACTION_BRIDGE_OUTBOUND)
            | (FAMILY_BRIDGE, ACTION_BRIDGE_INBOUND)
            | (FAMILY_BRIDGE, ACTION_REGISTER_BRIDGE_VERIFIER)
            | (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE)
            | (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_SIDECAR)
            | (FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT)
            | (FAMILY_SHIELDED_POOL, ACTION_MINT_COINBASE)
    )
}

fn native_action_request_kernel_fields_absent(request: &SubmitActionRpcRequest) -> bool {
    request.object_refs.is_empty()
        && request.authorization_proof.is_none()
        && request.authorization_signatures.is_empty()
        && request.aux_data.is_none()
}

fn native_action_request_nullifiers_decode(
    request: &SubmitActionRpcRequest,
    transfer_route: bool,
) -> bool {
    !transfer_route
        || request
            .new_nullifiers
            .iter()
            .all(|raw| parse_hex48(raw).is_some())
}

fn native_action_request_route_payload_decodes_exactly(
    request: &SubmitActionRpcRequest,
    public_args: &[u8],
) -> bool {
    match (request.family_id, request.action_id) {
        (FAMILY_BRIDGE, ACTION_BRIDGE_OUTBOUND) => decode_scale_exact::<OutboundBridgeArgsV1>(
            public_args,
            "native outbound bridge action request args",
        )
        .is_ok(),
        (FAMILY_BRIDGE, ACTION_BRIDGE_INBOUND) => decode_scale_exact::<InboundBridgeArgsV1>(
            public_args,
            "native inbound bridge action request args",
        )
        .is_ok(),
        (FAMILY_BRIDGE, ACTION_REGISTER_BRIDGE_VERIFIER) => {
            decode_scale_exact::<BridgeVerifierRegistrationV1>(
                public_args,
                "native bridge verifier registration request args",
            )
            .is_ok()
        }
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE) => {
            decode_scale_exact::<ShieldedTransferInlineArgs>(
                public_args,
                "native shielded inline action request args",
            )
            .is_ok()
        }
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_SIDECAR) => {
            decode_scale_exact::<ShieldedTransferSidecarArgs>(
                public_args,
                "native shielded sidecar action request args",
            )
            .is_ok()
        }
        (FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT) => {
            decode_scale_exact::<SubmitCandidateArtifactArgs>(
                public_args,
                "native candidate artifact action request args",
            )
            .is_ok()
        }
        (FAMILY_SHIELDED_POOL, ACTION_MINT_COINBASE) => decode_scale_exact::<MintCoinbaseArgs>(
            public_args,
            "native coinbase action request args",
        )
        .is_ok(),
        _ => false,
    }
}

fn evaluate_native_action_request_projection(
    request: &SubmitActionRpcRequest,
) -> std::result::Result<Vec<u8>, NativeActionRequestProjectionAdmissionRejection> {
    let transfer_route =
        native_submit_action_is_transfer_route(request.family_id, request.action_id);
    let route_supported =
        native_submit_action_route_supported(request.family_id, request.action_id);
    let public_args_encoded_within_limit =
        request.public_args.len() <= encoded_len_limit(MAX_NATIVE_RPC_ACTION_BYTES);
    let decoded_public_args = if public_args_encoded_within_limit {
        decode_base64(&request.public_args).ok()
    } else {
        None
    };
    let public_args_base64_decodes = decoded_public_args.is_some();
    let public_args_decoded_within_limit = decoded_public_args
        .as_ref()
        .map(|public_args| public_args.len() <= MAX_NATIVE_RPC_ACTION_BYTES)
        .unwrap_or(false);
    let route_payload_decodes_exactly = if route_supported && public_args_decoded_within_limit {
        decoded_public_args
            .as_ref()
            .map(|public_args| {
                native_action_request_route_payload_decodes_exactly(request, public_args)
            })
            .unwrap_or(false)
    } else {
        false
    };

    let input = NativeActionRequestProjectionAdmissionInput {
        json_decode_accepts: true,
        kernel_envelope_fields_absent: native_action_request_kernel_fields_absent(request),
        route_supported,
        nullifier_scope_valid: transfer_route || request.new_nullifiers.is_empty(),
        nullifier_count_within_limit: request.new_nullifiers.len()
            <= transaction_core::constants::MAX_INPUTS,
        nullifier_hex_valid: native_action_request_nullifiers_decode(request, transfer_route),
        public_args_encoded_within_limit,
        public_args_base64_decodes,
        public_args_decoded_within_limit,
        route_payload_decodes_exactly,
    };
    evaluate_native_action_request_projection_admission(input)?;
    decoded_public_args
        .ok_or(NativeActionRequestProjectionAdmissionRejection::PublicArgsBase64Rejected)
}

fn admit_native_action_request_projection(request: &SubmitActionRpcRequest) -> Result<Vec<u8>> {
    evaluate_native_action_request_projection(request)
        .map_err(native_action_request_projection_error)
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct NativePagination {
    #[serde(default)]
    start: u64,
    #[serde(default = "default_native_wallet_page_limit")]
    limit: u64,
}

#[derive(Clone, Debug)]
struct NativeState {
    best: NativeBlockMeta,
    pending_actions: BTreeMap<[u8; 32], PendingAction>,
    commitment_tree: CommitmentTreeState,
    nullifiers: BTreeSet<[u8; 48]>,
    consumed_bridge_messages: BTreeSet<[u8; 48]>,
    staged_ciphertexts: BTreeMap<String, u32>,
    staged_proofs: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone)]
struct NativeMinerIdentity {
    secret_key: MlDsaSecretKey,
    public_key: MlDsaPublicKey,
}

impl NativeMinerIdentity {
    fn from_seed(seed: &[u8]) -> Self {
        let secret_key = MlDsaSecretKey::generate_deterministic(seed);
        let public_key = secret_key.verify_key();
        Self {
            secret_key,
            public_key,
        }
    }
}

pub struct NativeNode {
    config: NativeConfig,
    db: sled::Db,
    meta_tree: sled::Tree,
    height_tree: sled::Tree,
    block_tree: sled::Tree,
    action_tree: sled::Tree,
    nullifier_tree: sled::Tree,
    commitment_tree: sled::Tree,
    bridge_inbound_tree: sled::Tree,
    ciphertext_index_tree: sled::Tree,
    ciphertext_archive_tree: sled::Tree,
    da_ciphertext_tree: sled::Tree,
    da_proof_tree: sled::Tree,
    state: RwLock<NativeState>,
    start_instant: Instant,
    mining: AtomicBool,
    mining_threads: AtomicU32,
    mining_round: AtomicU64,
    mining_hashes: AtomicU64,
    blocks_found: AtomicU64,
    last_announce_height: AtomicU64,
    mining_task: Mutex<Option<JoinHandle<()>>>,
    sync_tx: Mutex<Option<mpsc::Sender<DirectedProtocolMessage>>>,
    miner_identity: NativeMinerIdentity,
    prepared_mining_actions: Mutex<BTreeMap<[u8; 32], Vec<PendingAction>>>,
}

impl NativeNode {
    pub fn open(config: NativeConfig) -> Result<Arc<Self>> {
        fs::create_dir_all(&config.base_path)
            .with_context(|| format!("create native base path {}", config.base_path.display()))?;
        let db = sled::open(&config.db_path)
            .with_context(|| format!("open native sled db {}", config.db_path.display()))?;
        let meta_tree = db.open_tree("meta")?;
        let height_tree = db.open_tree("block_hash_by_height")?;
        let block_tree = db.open_tree("block_meta_by_hash")?;
        let action_tree = db.open_tree("mempool_actions")?;
        let nullifier_tree = db.open_tree("shielded_nullifiers")?;
        let commitment_tree = db.open_tree("shielded_commitments")?;
        let bridge_inbound_tree = db.open_tree("bridge_inbound_messages")?;
        let ciphertext_index_tree = db.open_tree("shielded_ciphertext_index")?;
        let ciphertext_archive_tree = db.open_tree("shielded_ciphertexts_by_index")?;
        let da_ciphertext_tree = db.open_tree("da_pending_ciphertexts")?;
        let da_proof_tree = db.open_tree("da_pending_proofs")?;

        let best =
            load_best_or_genesis(&db, &meta_tree, &height_tree, &block_tree, config.pow_bits)?;
        validate_loaded_block_indexes(
            &db,
            &best,
            &meta_tree,
            &height_tree,
            &block_tree,
            config.pow_bits,
        )?;
        let pending_actions = load_pending_actions(&action_tree)?;
        let nullifiers = load_nullifiers(&nullifier_tree)?;
        let commitment_state = load_commitment_tree(&commitment_tree)?;
        validate_loaded_canonical_state(&best, &commitment_state, &nullifiers)?;
        let consumed_bridge_messages = load_consumed_bridge_messages(&bridge_inbound_tree)?;
        validate_loaded_bridge_replay_state(&best, &block_tree, &consumed_bridge_messages)?;
        let staged_ciphertexts = load_staged_sizes(&db, &da_ciphertext_tree)?;
        let staged_proofs = load_staged_proofs(&db, &da_proof_tree)?;
        let startup_state = build_validated_startup_state(
            &db,
            &action_tree,
            best,
            pending_actions,
            commitment_state,
            nullifiers,
            consumed_bridge_messages,
            staged_ciphertexts,
            staged_proofs,
        )?;
        let miner_identity = load_native_miner_identity(&config)?;

        let node = Arc::new(Self {
            config,
            db,
            meta_tree,
            height_tree,
            block_tree,
            action_tree,
            nullifier_tree,
            commitment_tree,
            bridge_inbound_tree,
            ciphertext_index_tree,
            ciphertext_archive_tree,
            da_ciphertext_tree,
            da_proof_tree,
            state: RwLock::new(startup_state),
            start_instant: Instant::now(),
            mining: AtomicBool::new(false),
            mining_threads: AtomicU32::new(0),
            mining_round: AtomicU64::new(0),
            mining_hashes: AtomicU64::new(0),
            blocks_found: AtomicU64::new(0),
            last_announce_height: AtomicU64::new(0),
            mining_task: Mutex::new(None),
            sync_tx: Mutex::new(None),
            miner_identity,
            prepared_mining_actions: Mutex::new(BTreeMap::new()),
        });
        Self::ensure_ciphertext_archive_index(&node)?;
        Ok(node)
    }

    fn set_sync_sender(&self, sync_tx: mpsc::Sender<DirectedProtocolMessage>) {
        *self.sync_tx.lock() = Some(sync_tx);
    }

    fn start_mining(self: &Arc<Self>, threads: u32) {
        let threads = threads.max(1);
        self.mining_threads.store(threads, Ordering::Relaxed);
        self.mining.store(true, Ordering::SeqCst);

        let mut task = self.mining_task.lock();
        if task.is_none() || task.as_ref().is_some_and(JoinHandle::is_finished) {
            let node = Arc::clone(self);
            *task = Some(tokio::spawn(async move {
                mining_loop(node).await;
            }));
        }
    }

    fn stop_mining(&self) {
        self.mining.store(false, Ordering::SeqCst);
        self.mining_threads.store(0, Ordering::Relaxed);
        if let Some(handle) = self.mining_task.lock().take() {
            handle.abort();
        }
    }

    fn append_auto_coinbase_action(
        &self,
        height: u64,
        actions: &mut Vec<PendingAction>,
        received_ms: u64,
    ) -> Result<Option<PendingAction>> {
        let Some(action) = self.auto_coinbase_action(height, actions, received_ms)? else {
            return Ok(None);
        };
        actions.push(action.clone());
        Ok(Some(action))
    }

    fn auto_coinbase_action(
        &self,
        height: u64,
        actions: &[PendingAction],
        received_ms: u64,
    ) -> Result<Option<PendingAction>> {
        let Some(miner_address) = self.config.miner_address.as_deref() else {
            return Ok(None);
        };
        if actions.iter().any(is_coinbase_action) {
            return Ok(None);
        }
        let amount = expected_coinbase_amount(actions, height)?;
        if amount == 0 {
            return Ok(None);
        }

        let recipient = ShieldedAddress::decode(miner_address)
            .with_context(|| "decode HEGEMON_MINER_ADDRESS for native coinbase")?;
        let mut rng = OsRng;
        let mut public_seed = [0u8; 32];
        rng.fill_bytes(&mut public_seed);

        let note = NotePlaintext::coinbase(amount, &public_seed);
        let wallet_ciphertext = NoteCiphertext::encrypt(&recipient, &note, &mut rng)
            .with_context(|| "encrypt native coinbase note")?;
        let chain_bytes = wallet_ciphertext
            .to_chain_bytes()
            .with_context(|| "serialize native coinbase note")?;
        let encrypted_note = EncryptedNote::decode(&mut &chain_bytes[..])
            .map_err(|err| anyhow!("decode generated native coinbase encrypted note: {err}"))?;
        let note_data = note.to_note_data(recipient.pk_recipient, recipient.pk_auth);
        let commitment = felts_to_bytes48(&note_data.commitment());
        let miner_note = CoinbaseNoteData {
            commitment,
            encrypted_note,
            recipient_address: coinbase_recipient_address_bytes(&recipient),
            amount,
            public_seed,
        };
        let args = MintCoinbaseArgs {
            reward_bundle: BlockRewardBundle { miner_note },
        };
        let (_, ciphertext_metadata) =
            coinbase_ciphertext_metadata(&args.reward_bundle.miner_note.encrypted_note);
        let Some((ciphertext_hash, ciphertext_size)) = ciphertext_metadata else {
            return Err(anyhow!(
                "generated native coinbase ciphertext exceeds native cap"
            ));
        };
        let mut action = PendingAction {
            tx_hash: [0u8; 32],
            binding: protocol_versioning::DEFAULT_VERSION_BINDING.into(),
            family_id: FAMILY_SHIELDED_POOL,
            action_id: ACTION_MINT_COINBASE,
            anchor: [0u8; 48],
            nullifiers: Vec::new(),
            commitments: vec![commitment],
            ciphertext_hashes: vec![ciphertext_hash],
            ciphertext_sizes: vec![ciphertext_size],
            public_args: args.encode(),
            fee: 0,
            candidate_artifact: None,
            received_ms,
        };
        action.tx_hash = pending_action_hash(&action);
        validate_coinbase_action_payload(&action)?;
        let mut accounting_actions = actions.to_vec();
        accounting_actions.push(action.clone());
        validate_coinbase_accounting(&accounting_actions, height)?;
        Ok(Some(action))
    }

    fn cache_prepared_mining_actions(&self, pre_hash: [u8; 32], actions: Vec<PendingAction>) {
        let mut cache = self.prepared_mining_actions.lock();
        cache.insert(pre_hash, actions);
        while cache.len() > MAX_PREPARED_MINING_WORKS {
            let Some(oldest_key) = cache.keys().next().copied() else {
                break;
            };
            cache.remove(&oldest_key);
        }
    }

    fn prepared_mining_actions_for_work(&self, work: &NativeWork) -> Option<Vec<PendingAction>> {
        self.prepared_mining_actions
            .lock()
            .get(&work.pre_hash)
            .cloned()
    }

    fn forget_prepared_mining_actions(&self, work: &NativeWork) {
        self.prepared_mining_actions.lock().remove(&work.pre_hash);
    }

    fn mineable_actions_for_work(
        &self,
        state: &NativeState,
        work: &NativeWork,
    ) -> Vec<PendingAction> {
        if work.tx_count == 0 {
            return Vec::new();
        }
        if let Some(actions) = self.prepared_mining_actions_for_work(work) {
            if prepared_mining_actions_match_state(state, &actions) {
                return actions;
            }
        }
        select_mineable_actions(state)
    }

    fn prepare_work(&self) -> Result<NativeWork> {
        let state = self.state.read();
        let best = state.best.clone();
        let mut pending_actions = select_mineable_actions(&state);
        if self.config.miner_address.is_some() {
            pending_actions.retain(|action| !is_coinbase_action(action));
        }
        let cumulative_work = cumulative_work_after(&best.cumulative_work, self.config.pow_bits)
            .map_err(|_| NativeWorkTemplateAdmissionRejection::CumulativeWorkOverflow);
        let height = evaluate_native_work_template_admission(NativeWorkTemplateAdmissionInput {
            best_height: best.height,
            cumulative_work_advances: cumulative_work.is_ok(),
        })
        .map_err(native_work_template_admission_error)?;
        let cumulative_work = cumulative_work.map_err(native_work_template_admission_error)?;
        let received_ms = current_time_ms();
        let mut prepared_coinbase =
            match self.append_auto_coinbase_action(height, &mut pending_actions, received_ms) {
                Ok(action) => action,
                Err(err) => {
                    warn!(
                        error = %err,
                        "dropping native pending actions before auto coinbase"
                    );
                    pending_actions.clear();
                    self.append_auto_coinbase_action(height, &mut pending_actions, received_ms)?
                }
            };
        let (mut actions, mut state_root, mut nullifier_root, mut extrinsics_root, mut tx_count) =
            match preview_pending_roots(&self.da_ciphertext_tree, &state, &pending_actions) {
                Ok((state_root, nullifier_root, extrinsics_root, tx_count)) => (
                    pending_actions,
                    state_root,
                    nullifier_root,
                    extrinsics_root,
                    tx_count,
                ),
                Err(err) => {
                    warn!(error = %err, "failed to preview native pending action roots");
                    let mut fallback_actions = Vec::new();
                    prepared_coinbase = self.append_auto_coinbase_action(
                        height,
                        &mut fallback_actions,
                        received_ms,
                    )?;
                    match preview_pending_roots(&self.da_ciphertext_tree, &state, &fallback_actions)
                    {
                        Ok((state_root, nullifier_root, extrinsics_root, tx_count)) => (
                            fallback_actions,
                            state_root,
                            nullifier_root,
                            extrinsics_root,
                            tx_count,
                        ),
                        Err(fallback_err) => {
                            warn!(
                                error = %fallback_err,
                                "failed to preview native auto coinbase fallback"
                            );
                            prepared_coinbase = None;
                            (
                                Vec::new(),
                                best.state_root,
                                best.nullifier_root,
                                actions_extrinsics_root(&[]),
                                0,
                            )
                        }
                    }
                }
            };
        let timestamp_ms = received_ms.max(best.timestamp_ms.saturating_add(1));
        let supply_digest = match advance_native_supply_digest(best.supply_digest, &actions, height)
        {
            Ok(supply_digest) => supply_digest,
            Err(err) => {
                warn!(error = %err, "dropping native pending actions with invalid supply accounting");
                prepared_coinbase = None;
                actions = Vec::new();
                state_root = best.state_root;
                nullifier_root = best.nullifier_root;
                extrinsics_root = actions_extrinsics_root(&[]);
                tx_count = 0;
                best.supply_digest
            }
        };
        let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
        let bridge_messages = bridge_messages_from_actions(&actions, height)?;
        let message_root = bridge_message_root(&bridge_messages);
        let message_count = u32::try_from(bridge_messages.len()).unwrap_or(u32::MAX);
        let header_history = self.header_hashes_to_hash(best.hash)?;
        let header_mmr_root = header_mmr_root_from_hashes(&header_history);
        let header_mmr_len = header_history.len() as u64;
        let pre_header = native_pow_header_from_parts(
            height,
            timestamp_ms,
            best.hash,
            self.config.pow_bits,
            [0u8; 32],
            cumulative_work,
            &state_root,
            &kernel_root,
            &nullifier_root,
            &extrinsics_root,
            &message_root,
            message_count,
            &header_mmr_root,
            header_mmr_len,
            supply_digest,
            tx_count,
        );
        let pre_hash = pre_header.pre_hash();
        if prepared_coinbase.is_some() {
            self.cache_prepared_mining_actions(pre_hash, actions.clone());
        }
        Ok(NativeWork {
            height,
            parent_hash: best.hash,
            pre_hash,
            state_root,
            kernel_root,
            nullifier_root,
            extrinsics_root,
            message_root,
            message_count,
            header_mmr_root,
            header_mmr_len,
            cumulative_work,
            supply_digest,
            tx_count,
            timestamp_ms,
            pow_bits: self.config.pow_bits,
        })
    }

    fn import_mined_block(
        &self,
        work: &NativeWork,
        seal: NativeSeal,
    ) -> Result<Option<NativeBlockMeta>> {
        let mut state = self.state.write();
        if evaluate_native_mined_work_admission(native_mined_work_admission_input(
            &state.best,
            work,
        ))
        .is_err()
        {
            return Ok(None);
        }

        let actions = self.mineable_actions_for_work(&state, work);
        let (preview_state_root, preview_nullifier_root, preview_extrinsics_root, preview_tx_count) =
            match preview_pending_roots(&self.da_ciphertext_tree, &state, &actions) {
                Ok(roots) => roots,
                Err(err) => {
                    debug!(error = %err, "native mined work no longer matches pending actions");
                    return Ok(None);
                }
            };
        let preview_kernel_root =
            consensus::types::kernel_root_from_shielded_root(&preview_state_root);
        let preview_bridge_messages = bridge_messages_from_actions(&actions, work.height)?;
        let preview_message_count = u32::try_from(preview_bridge_messages.len())
            .map_err(|_| anyhow!("native bridge message count overflow"))?;
        let preview_message_root = bridge_message_root(&preview_bridge_messages);
        let expected_header_history = self.header_hashes_to_hash(state.best.hash)?;
        let supply_digest =
            advance_native_supply_digest(state.best.supply_digest, &actions, work.height)?;
        match evaluate_native_block_commitment_admission(NativeBlockCommitmentAdmissionInput {
            tx_count_matches: preview_tx_count == work.tx_count,
            state_root_matches: preview_state_root == work.state_root,
            kernel_root_matches: preview_kernel_root == work.kernel_root,
            nullifier_root_matches: preview_nullifier_root == work.nullifier_root,
            extrinsics_root_matches: preview_extrinsics_root == work.extrinsics_root,
            message_root_matches: preview_message_root == work.message_root,
            message_count_matches: preview_message_count == work.message_count,
            header_mmr_root_matches: work.header_mmr_root
                == header_mmr_root_from_hashes(&expected_header_history),
            header_mmr_len_matches: work.header_mmr_len == expected_header_history.len() as u64,
            supply_digest_matches: supply_digest == work.supply_digest,
        }) {
            Ok(()) => {}
            Err(
                rejection @ (NativeBlockCommitmentAdmissionRejection::HeaderMmrRootMismatch
                | NativeBlockCommitmentAdmissionRejection::HeaderMmrLenMismatch),
            ) => {
                return Err(native_block_commitment_admission_error(
                    "native mined block commitment mismatch",
                    rejection,
                ));
            }
            Err(_) => return Ok(None),
        }
        let (fee_total, has_coinbase) = native_block_replay_supply_parts(&actions, work.height)?;
        evaluate_native_block_replay_refinement_for_actions(
            "native mined block replay refinement failed",
            &self.da_ciphertext_tree,
            &state,
            &actions,
            native_block_replay_refinement_input_from_state(
                &state,
                work.height,
                fee_total,
                has_coinbase,
                supply_digest,
                preview_tx_count == work.tx_count,
                preview_state_root == work.state_root,
                preview_kernel_root == work.kernel_root,
                preview_nullifier_root == work.nullifier_root,
                preview_extrinsics_root == work.extrinsics_root,
                preview_message_root == work.message_root,
                preview_message_count == work.message_count,
                work.header_mmr_root == header_mmr_root_from_hashes(&expected_header_history),
                work.header_mmr_len == expected_header_history.len() as u64,
            ),
        )?;
        let mut meta = NativeBlockMeta {
            chain_id: HEGEMON_CHAIN_ID_V1,
            rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
            height: work.height,
            hash: seal.work_hash,
            parent_hash: work.parent_hash,
            state_root: work.state_root,
            kernel_root: work.kernel_root,
            nullifier_root: work.nullifier_root,
            extrinsics_root: work.extrinsics_root,
            message_root: work.message_root,
            message_count: work.message_count,
            header_mmr_root: work.header_mmr_root,
            header_mmr_len: work.header_mmr_len,
            timestamp_ms: work.timestamp_ms,
            pow_bits: work.pow_bits,
            nonce: seal.nonce,
            work_hash: seal.work_hash,
            cumulative_work: work.cumulative_work,
            supply_digest,
            tx_count: work.tx_count,
            action_bytes: actions.iter().map(Encode::encode).collect(),
            miner_commitment: [0u8; 48],
            miner_public_key: Vec::new(),
            miner_signature: Vec::new(),
        };
        sign_native_block_meta(&mut meta, &self.miner_identity);
        verify_native_pow_meta(&state.best, &meta)?;

        validate_block_actions_locked(&state, &actions)?;
        verify_native_block_artifacts_locked(self, &state, &actions, &meta)?;
        let pending_action_effects =
            plan_pending_action_effects(&self.da_ciphertext_tree, &state, &actions)?;
        let mut next_state = state.clone();
        apply_planned_actions_to_memory(&mut next_state, &actions, &pending_action_effects)?;
        if next_state.commitment_tree.root() != work.state_root
            || nullifier_root_from_set(&next_state.nullifiers) != work.nullifier_root
        {
            return Err(anyhow!("native pending action preview mismatch"));
        }

        self.commit_mined_block_atomically(&actions, &pending_action_effects, &meta)?;
        self.flush_native_durability_barrier("native mined block commit")?;
        self.forget_prepared_mining_actions(work);
        next_state.best = meta.clone();
        publish_mined_state(&mut state, next_state);
        self.blocks_found.fetch_add(1, Ordering::Relaxed);
        self.broadcast_block_announce(&meta);
        info!(
            height = meta.height,
            hash = %hex32(&meta.hash),
            "native PoW block imported"
        );
        Ok(Some(meta))
    }

    fn import_announced_block(&self, meta: NativeBlockMeta) -> Result<bool> {
        let mut state = self.state.write();
        if self.header_by_hash(&meta.hash)?.is_some() {
            return Ok(false);
        }
        let Some(parent) = self.header_by_hash(&meta.parent_hash)? else {
            return Ok(false);
        };
        validate_announced_block(&parent, &meta)?;
        let expected_header_history = self.header_hashes_to_hash(parent.hash)?;

        let parent_state = if parent.hash == state.best.hash {
            NativeState {
                best: state.best.clone(),
                pending_actions: BTreeMap::new(),
                commitment_tree: state.commitment_tree.clone(),
                nullifiers: state.nullifiers.clone(),
                consumed_bridge_messages: state.consumed_bridge_messages.clone(),
                staged_ciphertexts: BTreeMap::new(),
                staged_proofs: BTreeMap::new(),
            }
        } else {
            self.replay_state_to_hash(parent.hash)?
        };
        let actions = decode_block_actions(&meta)?;
        verify_decoded_action_root(&actions, &meta, "announced block action root")?;
        let (state_root, nullifier_root, extrinsics_root, tx_count) =
            preview_pending_roots(&self.da_ciphertext_tree, &parent_state, &actions)?;
        let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
        let bridge_messages = bridge_messages_from_actions(&actions, meta.height)?;
        let message_root = bridge_message_root(&bridge_messages);
        let message_count = u32::try_from(bridge_messages.len())
            .map_err(|_| anyhow!("native bridge message count overflow"))?;
        let (fee_total, has_coinbase) = native_block_replay_supply_parts(&actions, meta.height)?;
        evaluate_native_block_replay_refinement_for_actions(
            "announced block replay refinement failed",
            &self.da_ciphertext_tree,
            &parent_state,
            &actions,
            native_block_replay_refinement_input_from_state(
                &parent_state,
                meta.height,
                fee_total,
                has_coinbase,
                meta.supply_digest,
                tx_count == meta.tx_count,
                state_root == meta.state_root,
                kernel_root == meta.kernel_root,
                nullifier_root == meta.nullifier_root,
                extrinsics_root == meta.extrinsics_root,
                message_root == meta.message_root,
                message_count == meta.message_count,
                meta.header_mmr_root == header_mmr_root_from_hashes(&expected_header_history),
                meta.header_mmr_len == expected_header_history.len() as u64,
            ),
        )?;
        validate_block_actions_locked(&parent_state, &actions)?;
        verify_native_block_artifacts_locked(self, &parent_state, &actions, &meta)?;
        let candidate_wins = native_meta_better_than(&meta, &state.best);
        if candidate_wins {
            let mut new_chain = self.chain_to_hash(parent.hash)?;
            new_chain.push(meta.clone());
            self.reorganize_chain_to_best_locked(&mut state, new_chain)?;
            Ok(true)
        } else {
            self.persist_noncanonical_block_record(&meta)?;
            Ok(false)
        }
    }

    fn persist_noncanonical_block_record(&self, meta: &NativeBlockMeta) -> Result<()> {
        evaluate_native_atomic_commit_manifest_admission(
            native_noncanonical_block_record_manifest(),
        )
        .map_err(|rejection| {
            native_atomic_commit_manifest_admission_error(
                "native noncanonical block record manifest",
                rejection,
            )
        })?;
        persist_block_record(&self.block_tree, meta)?;
        self.flush_native_durability_barrier("noncanonical native block record")?;
        Ok(())
    }

    fn flush_native_durability_barrier(&self, context: &'static str) -> Result<()> {
        flush_native_db_durability_barrier(&self.db, context)
    }

    fn broadcast_block_announce(&self, meta: &NativeBlockMeta) {
        if meta.height > 1 && !meta.height.is_multiple_of(NATIVE_ANNOUNCE_INTERVAL) {
            return;
        }
        self.last_announce_height
            .store(meta.height, Ordering::Relaxed);
        let Some(sync_tx) = self.sync_tx.lock().clone() else {
            return;
        };
        let announce = NativeSyncMessage::Announce(Box::new(meta.clone()));
        let payload = match encode_sync_message(&announce) {
            Ok(payload) => payload,
            Err(err) => {
                warn!(error = %err, "failed to encode native block announce");
                return;
            }
        };
        let message = DirectedProtocolMessage {
            target: None,
            message: ProtocolMessage {
                protocol: NATIVE_SYNC_PROTOCOL_ID,
                payload,
            },
        };
        if let Err(err) = sync_tx.try_send(message) {
            debug!(error = %err, "failed to queue native block announce");
        }
    }

    fn block_range(&self, from_height: u64, to_height: u64) -> Result<Vec<NativeBlockMeta>> {
        let best_height = self.best_meta().height;
        let Some(range) = native_sync_response_range(NativeSyncResponseRangeInput {
            from_height,
            to_height,
            best_height,
            max_blocks: MAX_NATIVE_SYNC_RESPONSE_BLOCKS,
        }) else {
            return Ok(Vec::new());
        };
        let mut blocks = Vec::new();
        let mut parent = if range.from_height == 0 {
            None
        } else {
            Some(self.load_canonical_sync_block_at_height(range.from_height - 1)?)
        };
        for height in range.from_height..=range.to_height {
            let meta = self.load_canonical_sync_block_at_height(height)?;
            if let Some(parent) = parent.as_ref() {
                if meta.parent_hash != parent.hash {
                    return Err(anyhow!(
                        "canonical native block parent mismatch at height {}: expected {}, got {}",
                        height,
                        hex32(&parent.hash),
                        hex32(&meta.parent_hash)
                    ));
                }
            }
            parent = Some(meta.clone());
            blocks.push(meta);
        }
        Ok(blocks)
    }

    fn load_canonical_sync_block_at_height(&self, height: u64) -> Result<NativeBlockMeta> {
        let meta = self.load_canonical_block_at_height_unverified(height)?;
        if meta.height == 0 {
            verify_native_block_meta_projection(None, &meta)
                .context("validate genesis native sync block metadata")?;
        } else {
            let parent =
                self.load_canonical_block_at_height_unverified(height.saturating_sub(1))?;
            verify_native_block_meta_projection(Some(&parent), &meta).with_context(|| {
                format!(
                    "validate canonical native sync block metadata at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                )
            })?;
            verify_canonical_sync_block_body(&meta).with_context(|| {
                format!(
                    "validate canonical native sync block body at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                )
            })?;
        }
        Ok(meta)
    }

    fn load_canonical_block_at_height_unverified(&self, height: u64) -> Result<NativeBlockMeta> {
        let hash = self
            .hash_by_height(height)?
            .ok_or_else(|| anyhow!("missing canonical height index for native block {height}"))?;
        let meta = self.header_by_hash(&hash)?.ok_or_else(|| {
            anyhow!(
                "missing native block record for canonical height {} ({})",
                height,
                hex32(&hash)
            )
        })?;
        if meta.hash != hash {
            return Err(anyhow!(
                "canonical height {} points to {} but block metadata hash is {}",
                height,
                hex32(&hash),
                hex32(&meta.hash)
            ));
        }
        if meta.height != height {
            return Err(anyhow!(
                "canonical height {} points to block metadata at height {} ({})",
                height,
                meta.height,
                hex32(&hash)
            ));
        }
        if meta.hash != meta.work_hash {
            return Err(anyhow!(
                "canonical native block {} has hash/work-hash mismatch: {} != {}",
                height,
                hex32(&meta.hash),
                hex32(&meta.work_hash)
            ));
        }
        Ok(meta)
    }

    fn chain_to_hash(&self, hash: [u8; 32]) -> Result<Vec<NativeBlockMeta>> {
        load_chain_to_hash(&self.block_tree, hash)
    }

    fn header_hashes_to_hash(&self, hash: [u8; 32]) -> Result<Vec<Hash32>> {
        Ok(self
            .chain_to_hash(hash)?
            .into_iter()
            .map(|meta| meta.hash)
            .collect())
    }

    fn replay_state_to_hash(&self, hash: [u8; 32]) -> Result<NativeState> {
        let chain = self.chain_to_hash(hash)?;
        self.replay_chain_state(&chain)
    }

    fn replay_chain_state(&self, chain: &[NativeBlockMeta]) -> Result<NativeState> {
        let genesis = chain
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("empty native chain replay"))?;
        let mut state = NativeState {
            best: genesis,
            pending_actions: BTreeMap::new(),
            commitment_tree: CommitmentTreeState::default(),
            nullifiers: BTreeSet::new(),
            consumed_bridge_messages: BTreeSet::new(),
            staged_ciphertexts: BTreeMap::new(),
            staged_proofs: BTreeMap::new(),
        };
        for (idx, meta) in chain.iter().cloned().enumerate().skip(1) {
            verify_native_block_meta_projection(Some(&state.best), &meta).with_context(|| {
                format!(
                    "replay stored native block metadata at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                )
            })?;
            let actions = decode_block_actions(&meta)?;
            verify_decoded_action_root(&actions, &meta, "native replay action root")?;
            validate_block_actions_locked(&state, &actions)?;
            let (state_root, nullifier_root, extrinsics_root, tx_count) =
                preview_pending_roots(&self.da_ciphertext_tree, &state, &actions)?;
            let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
            let bridge_messages = bridge_messages_from_actions(&actions, meta.height)?;
            let message_root = bridge_message_root(&bridge_messages);
            let message_count = u32::try_from(bridge_messages.len())
                .map_err(|_| anyhow!("native bridge message count overflow"))?;
            let expected_header_history: Vec<Hash32> =
                chain[..idx].iter().map(|header| header.hash).collect();
            let (fee_total, has_coinbase) =
                native_block_replay_supply_parts(&actions, meta.height)?;
            evaluate_native_block_replay_refinement_for_actions(
                "native replay refinement failed",
                &self.da_ciphertext_tree,
                &state,
                &actions,
                native_block_replay_refinement_input_from_state(
                    &state,
                    meta.height,
                    fee_total,
                    has_coinbase,
                    meta.supply_digest,
                    tx_count == meta.tx_count,
                    state_root == meta.state_root,
                    kernel_root == meta.kernel_root,
                    nullifier_root == meta.nullifier_root,
                    extrinsics_root == meta.extrinsics_root,
                    message_root == meta.message_root,
                    message_count == meta.message_count,
                    meta.header_mmr_root == header_mmr_root_from_hashes(&expected_header_history),
                    meta.header_mmr_len == expected_header_history.len() as u64,
                ),
            )?;
            verify_native_block_artifacts_locked(self, &state, &actions, &meta)?;
            apply_actions_to_memory(&self.da_ciphertext_tree, &mut state, &actions)?;
            state.best = meta;
        }
        Ok(state)
    }

    fn reorganize_chain_to_best_locked(
        &self,
        state: &mut NativeState,
        new_chain: Vec<NativeBlockMeta>,
    ) -> Result<()> {
        let old_chain = self.chain_to_hash(state.best.hash)?;
        let block_entries = new_chain
            .iter()
            .map(|meta| Ok((meta.hash, bincode::serialize(meta)?)))
            .collect::<Result<Vec<_>>>()?;
        let height_entries = new_chain
            .iter()
            .map(|meta| (meta.height, meta.hash))
            .collect::<Vec<_>>();
        evaluate_native_canonical_reorg_chain_admission(
            native_canonical_reorg_chain_admission_input(
                &new_chain,
                &block_entries,
                &height_entries,
                new_chain.last(),
                self.config.pow_bits,
            )?,
        )
        .map_err(native_canonical_reorg_chain_admission_error)?;

        let mut new_state = self.replay_chain_state(&new_chain)?;
        let canonical_index_plan =
            plan_canonical_index_rebuild(&new_chain, &self.da_ciphertext_tree)?;
        let new_action_hashes = action_hashes_from_chain(&new_chain)?;
        let mut pending = state.pending_actions.clone();
        for hash in &new_action_hashes {
            pending.remove(hash);
        }
        pending = revalidate_reorg_pending_actions(
            &new_state,
            pending,
            orphaned_actions(&old_chain, &new_action_hashes)?,
        );

        let pending_entries = pending
            .values()
            .map(|action| (action.tx_hash, action.encode()))
            .collect::<Vec<_>>();
        self.commit_reorg_state_atomically(
            canonical_index_plan,
            &block_entries,
            &height_entries,
            &pending_entries,
            &new_state.best,
        )?;
        self.flush_native_durability_barrier("native canonical reorg commit")?;

        new_state.staged_ciphertexts = state.staged_ciphertexts.clone();
        for meta in new_chain.iter().skip(1) {
            for action in decode_block_actions(meta)? {
                clear_staged_ciphertext_markers(&mut new_state, &action);
            }
        }
        new_state.pending_actions = pending;
        new_state.staged_proofs = state.staged_proofs.clone();
        publish_reorganized_state(state, new_state);
        Ok(())
    }

    fn commit_reorg_state_atomically(
        &self,
        canonical_index_plan: NativeCanonicalIndexPlan,
        block_entries: &[([u8; 32], Vec<u8>)],
        height_entries: &[(u64, [u8; 32])],
        pending_entries: &[([u8; 32], Vec<u8>)],
        best: &NativeBlockMeta,
    ) -> Result<()> {
        let height_keys = collect_tree_keys(&self.height_tree, "native height")?;
        let commitment_keys = collect_tree_keys(&self.commitment_tree, "native commitment")?;
        let nullifier_keys = collect_tree_keys(&self.nullifier_tree, "native nullifier")?;
        let bridge_replay_keys =
            collect_tree_keys(&self.bridge_inbound_tree, "native bridge replay")?;
        let ciphertext_index_keys =
            collect_tree_keys(&self.ciphertext_index_tree, "native ciphertext index")?;
        let ciphertext_archive_keys =
            collect_tree_keys(&self.ciphertext_archive_tree, "native ciphertext archive")?;
        let action_keys = collect_tree_keys(&self.action_tree, "native pending action")?;
        let best_record = bincode::serialize(best)?;
        evaluate_native_atomic_commit_manifest_admission(native_reorg_commit_manifest(
            &canonical_index_plan,
            block_entries,
            height_entries,
            pending_entries,
        ))
        .map_err(|rejection| {
            native_atomic_commit_manifest_admission_error(
                "native canonical reorg manifest",
                rejection,
            )
        })?;
        let NativeCanonicalIndexPlan {
            commitment_entries,
            nullifier_entries,
            bridge_replay_entries,
            ciphertext_index_entries,
            ciphertext_archive_entries,
        } = canonical_index_plan;

        let commit_result: sled::transaction::TransactionResult<(), std::convert::Infallible> = (
            &self.meta_tree,
            &self.height_tree,
            &self.block_tree,
            &self.commitment_tree,
            &self.nullifier_tree,
            &self.bridge_inbound_tree,
            &self.ciphertext_index_tree,
            &self.ciphertext_archive_tree,
            &self.action_tree,
        )
            .transaction(
                |(
                    meta_tree,
                    height_tree,
                    block_tree,
                    commitment_tree,
                    nullifier_tree,
                    bridge_inbound_tree,
                    ciphertext_index_tree,
                    ciphertext_archive_tree,
                    action_tree,
                )| {
                    for key in &height_keys {
                        height_tree.remove(key.clone())?;
                    }
                    for key in &commitment_keys {
                        commitment_tree.remove(key.clone())?;
                    }
                    for key in &nullifier_keys {
                        nullifier_tree.remove(key.clone())?;
                    }
                    for key in &bridge_replay_keys {
                        bridge_inbound_tree.remove(key.clone())?;
                    }
                    for key in &ciphertext_index_keys {
                        ciphertext_index_tree.remove(key.clone())?;
                    }
                    for key in &ciphertext_archive_keys {
                        ciphertext_archive_tree.remove(key.clone())?;
                    }
                    for key in &action_keys {
                        action_tree.remove(key.clone())?;
                    }

                    for (hash, encoded) in block_entries {
                        block_tree.insert(hash.to_vec(), encoded.clone())?;
                    }
                    for (height, hash) in height_entries {
                        height_tree.insert(height_key(*height).to_vec(), hash.to_vec())?;
                    }
                    for (index, commitment) in &commitment_entries {
                        commitment_tree
                            .insert(index.to_be_bytes().to_vec(), commitment.to_vec())?;
                    }
                    for (index, bytes) in &ciphertext_archive_entries {
                        ciphertext_archive_tree
                            .insert(index.to_be_bytes().to_vec(), bytes.clone())?;
                    }
                    for nullifier in &nullifier_entries {
                        nullifier_tree.insert(nullifier.to_vec(), b"1".to_vec())?;
                    }
                    for replay_key in &bridge_replay_entries {
                        bridge_inbound_tree.insert(replay_key.to_vec(), b"1".to_vec())?;
                    }
                    for (hash, value) in &ciphertext_index_entries {
                        ciphertext_index_tree.insert(hash.to_vec(), value.clone())?;
                    }
                    for (tx_hash, encoded) in pending_entries {
                        action_tree.insert(tx_hash.to_vec(), encoded.clone())?;
                    }
                    meta_tree.insert(META_BEST_KEY.to_vec(), best_record.clone())?;
                    Ok(())
                },
            );
        commit_result.map_err(|err| anyhow!("atomic native reorg commit failed: {err}"))?;
        Ok(())
    }

    fn commit_canonical_index_repair_atomically(
        &self,
        canonical_index_plan: NativeCanonicalIndexPlan,
    ) -> Result<()> {
        let commitment_keys = collect_tree_keys(&self.commitment_tree, "native commitment")?;
        let nullifier_keys = collect_tree_keys(&self.nullifier_tree, "native nullifier")?;
        let bridge_replay_keys =
            collect_tree_keys(&self.bridge_inbound_tree, "native bridge replay")?;
        let ciphertext_index_keys =
            collect_tree_keys(&self.ciphertext_index_tree, "native ciphertext index")?;
        let ciphertext_archive_keys =
            collect_tree_keys(&self.ciphertext_archive_tree, "native ciphertext archive")?;
        evaluate_native_atomic_commit_manifest_admission(native_canonical_index_repair_manifest(
            &canonical_index_plan,
        ))
        .map_err(|rejection| {
            native_atomic_commit_manifest_admission_error(
                "native canonical index repair manifest",
                rejection,
            )
        })?;
        let NativeCanonicalIndexPlan {
            commitment_entries,
            nullifier_entries,
            bridge_replay_entries,
            ciphertext_index_entries,
            ciphertext_archive_entries,
        } = canonical_index_plan;

        let repair_result: sled::transaction::TransactionResult<(), std::convert::Infallible> = (
            &self.commitment_tree,
            &self.nullifier_tree,
            &self.bridge_inbound_tree,
            &self.ciphertext_index_tree,
            &self.ciphertext_archive_tree,
        )
            .transaction(
                |(
                    commitment_tree,
                    nullifier_tree,
                    bridge_inbound_tree,
                    ciphertext_index_tree,
                    ciphertext_archive_tree,
                )| {
                    for key in &commitment_keys {
                        commitment_tree.remove(key.clone())?;
                    }
                    for key in &nullifier_keys {
                        nullifier_tree.remove(key.clone())?;
                    }
                    for key in &bridge_replay_keys {
                        bridge_inbound_tree.remove(key.clone())?;
                    }
                    for key in &ciphertext_index_keys {
                        ciphertext_index_tree.remove(key.clone())?;
                    }
                    for key in &ciphertext_archive_keys {
                        ciphertext_archive_tree.remove(key.clone())?;
                    }

                    for (index, commitment) in &commitment_entries {
                        commitment_tree
                            .insert(index.to_be_bytes().to_vec(), commitment.to_vec())?;
                    }
                    for (index, bytes) in &ciphertext_archive_entries {
                        ciphertext_archive_tree
                            .insert(index.to_be_bytes().to_vec(), bytes.clone())?;
                    }
                    for nullifier in &nullifier_entries {
                        nullifier_tree.insert(nullifier.to_vec(), b"1".to_vec())?;
                    }
                    for replay_key in &bridge_replay_entries {
                        bridge_inbound_tree.insert(replay_key.to_vec(), b"1".to_vec())?;
                    }
                    for (hash, value) in &ciphertext_index_entries {
                        ciphertext_index_tree.insert(hash.to_vec(), value.clone())?;
                    }
                    Ok(())
                },
            );
        repair_result
            .map_err(|err| anyhow!("atomic native canonical index repair failed: {err}"))?;
        self.flush_native_durability_barrier("native canonical index repair")?;
        Ok(())
    }

    fn commit_mined_block_atomically(
        &self,
        actions: &[PendingAction],
        planned: &[NativePlannedActionEffect],
        meta: &NativeBlockMeta,
    ) -> Result<()> {
        evaluate_native_atomic_commit_manifest_admission(native_mined_block_commit_manifest(
            actions, planned,
        ))
        .map_err(|rejection| {
            native_atomic_commit_manifest_admission_error(
                "native mined block commit manifest",
                rejection,
            )
        })?;

        let block_record = bincode::serialize(meta)?;
        let best_record = block_record.clone();
        let height_key = height_key(meta.height);
        let commit_result: sled::transaction::TransactionResult<(), std::convert::Infallible> = (
            &self.meta_tree,
            &self.height_tree,
            &self.block_tree,
            &self.commitment_tree,
            &self.nullifier_tree,
            &self.bridge_inbound_tree,
            &self.ciphertext_index_tree,
            &self.ciphertext_archive_tree,
            &self.da_ciphertext_tree,
            &self.action_tree,
        )
            .transaction(
                |(
                    meta_tree,
                    height_tree,
                    block_tree,
                    commitment_tree,
                    nullifier_tree,
                    bridge_inbound_tree,
                    ciphertext_index_tree,
                    ciphertext_archive_tree,
                    da_ciphertext_tree,
                    action_tree,
                )| {
                    block_tree.insert(meta.hash.to_vec(), block_record.clone())?;
                    height_tree.insert(height_key.to_vec(), meta.hash.to_vec())?;
                    meta_tree.insert(META_BEST_KEY.to_vec(), best_record.clone())?;

                    for (action, effect) in actions.iter().zip(planned.iter()) {
                        for (offset, commitment) in action.commitments.iter().enumerate() {
                            let index = effect
                                .commitment_start
                                .checked_add(offset as u64)
                                .expect("planned commitment index arithmetic must not overflow");
                            commitment_tree
                                .insert(index.to_be_bytes().to_vec(), commitment.to_vec())?;
                        }
                        for (offset, bytes) in effect.ciphertexts.iter().enumerate() {
                            let index = effect
                                .commitment_start
                                .checked_add(offset as u64)
                                .expect("planned ciphertext index arithmetic must not overflow");
                            ciphertext_archive_tree
                                .insert(index.to_be_bytes().to_vec(), bytes.clone())?;
                        }

                        for nullifier in &action.nullifiers {
                            nullifier_tree.insert(nullifier.to_vec(), b"1".to_vec())?;
                        }
                        if let Some(replay_key) = effect.replay_key {
                            bridge_inbound_tree.insert(replay_key.to_vec(), b"1".to_vec())?;
                        }

                        for (idx, hash) in action.ciphertext_hashes.iter().enumerate() {
                            let size = action
                                .ciphertext_sizes
                                .get(idx)
                                .copied()
                                .unwrap_or_default();
                            let mut value = Vec::with_capacity(32 + 4 + 8);
                            value.extend_from_slice(&action.tx_hash);
                            value.extend_from_slice(&size.to_le_bytes());
                            value.extend_from_slice(&(idx as u64).to_le_bytes());
                            ciphertext_index_tree.insert(hash.to_vec(), value)?;
                        }

                        action_tree.remove(action.tx_hash.to_vec())?;
                        for hash in &action.ciphertext_hashes {
                            da_ciphertext_tree.remove(hash.to_vec())?;
                        }
                    }
                    Ok(())
                },
            );
        commit_result.map_err(|err| anyhow!("atomic native mined block commit failed: {err}"))?;
        Ok(())
    }

    fn ensure_ciphertext_archive_index(&self) -> Result<()> {
        let chain = self.chain_to_hash(self.best_meta().hash)?;
        let replayed_state = self.replay_chain_state(&chain)?;
        self.validate_loaded_state_matches_replay(&replayed_state)?;
        let canonical_index_plan = plan_canonical_index_rebuild(&chain, &self.da_ciphertext_tree)?;
        if self.canonical_index_matches_plan(&canonical_index_plan)? {
            return Ok(());
        }

        warn!(
            commitments = canonical_index_plan.commitment_entries.len(),
            nullifiers = canonical_index_plan.nullifier_entries.len(),
            bridge_replay = canonical_index_plan.bridge_replay_entries.len(),
            ciphertext_index = canonical_index_plan.ciphertext_index_entries.len(),
            ciphertext_archive = canonical_index_plan.ciphertext_archive_entries.len(),
            "rebuilding canonical native indexes after validated replay"
        );
        self.commit_canonical_index_repair_atomically(canonical_index_plan)?;
        Ok(())
    }

    fn validate_loaded_state_matches_replay(&self, replayed: &NativeState) -> Result<()> {
        let state = self.state.read();
        if state.best != replayed.best {
            return Err(anyhow!("startup canonical replay best metadata mismatch"));
        }
        if state.commitment_tree != replayed.commitment_tree {
            return Err(anyhow!("startup canonical replay commitment tree mismatch"));
        }
        if state.nullifiers != replayed.nullifiers {
            return Err(anyhow!("startup canonical replay nullifier set mismatch"));
        }
        if state.consumed_bridge_messages != replayed.consumed_bridge_messages {
            return Err(anyhow!(
                "startup canonical replay bridge replay set mismatch"
            ));
        }
        Ok(())
    }

    fn canonical_index_matches_plan(&self, plan: &NativeCanonicalIndexPlan) -> Result<bool> {
        if self.commitment_tree.len() != plan.commitment_entries.len()
            || self.nullifier_tree.len() != plan.nullifier_entries.len()
            || self.bridge_inbound_tree.len() != plan.bridge_replay_entries.len()
            || self.ciphertext_index_tree.len() != plan.ciphertext_index_entries.len()
            || self.ciphertext_archive_tree.len() != plan.ciphertext_archive_entries.len()
        {
            return Ok(false);
        }
        for (index, commitment) in &plan.commitment_entries {
            if self.commitment_tree.get(index.to_be_bytes())?.as_deref()
                != Some(commitment.as_slice())
            {
                return Ok(false);
            }
        }
        for nullifier in &plan.nullifier_entries {
            if self.nullifier_tree.get(nullifier.as_slice())?.as_deref() != Some(b"1".as_slice()) {
                return Ok(false);
            }
        }
        for replay_key in &plan.bridge_replay_entries {
            if self
                .bridge_inbound_tree
                .get(replay_key.as_slice())?
                .as_deref()
                != Some(b"1".as_slice())
            {
                return Ok(false);
            }
        }
        for (hash, value) in &plan.ciphertext_index_entries {
            if self.ciphertext_index_tree.get(hash.as_slice())?.as_deref() != Some(value.as_slice())
            {
                return Ok(false);
            }
        }
        for (index, bytes) in &plan.ciphertext_archive_entries {
            if self
                .ciphertext_archive_tree
                .get(index.to_be_bytes())?
                .as_deref()
                != Some(bytes.as_slice())
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn header_by_hash(&self, hash: &[u8; 32]) -> Result<Option<NativeBlockMeta>> {
        load_block_meta_by_hash(&self.block_tree, hash)
    }

    fn hash_by_height(&self, height: u64) -> Result<Option<[u8; 32]>> {
        self.height_tree
            .get(height_key(height))?
            .map(|bytes| {
                let slice = bytes.as_ref();
                if slice.len() != 32 {
                    return Err(anyhow!("stored block hash has invalid length"));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(slice);
                Ok(hash)
            })
            .transpose()
    }

    fn best_meta(&self) -> NativeBlockMeta {
        self.state.read().best.clone()
    }

    fn mining_status(&self) -> Value {
        let best = self.best_meta();
        json!({
            "is_mining": self.mining.load(Ordering::SeqCst),
            "threads": self.mining_threads.load(Ordering::Relaxed),
            "hash_rate": self.hash_rate(),
            "blocks_found": self.blocks_found.load(Ordering::Relaxed),
            "difficulty": self.config.pow_bits,
            "block_height": best.height,
        })
    }

    fn consensus_status(&self) -> Value {
        let best = self.best_meta();
        json!({
            "height": best.height,
            "best_hash": hex32(&best.hash),
            "state_root": hex48(&best.state_root),
            "nullifier_root": hex48(&best.nullifier_root),
            "supply_digest": best.supply_digest,
            "syncing": false,
            "peers": 0,
        })
    }

    fn telemetry_snapshot(&self) -> Value {
        json!({
            "uptime_secs": self.start_instant.elapsed().as_secs(),
            "tx_count": self.state.read().pending_actions.len() as u64,
            "blocks_imported": self.best_meta().height,
            "blocks_mined": self.blocks_found.load(Ordering::Relaxed),
            "memory_bytes": 0u64,
            "network_rx_bytes": 0u64,
            "network_tx_bytes": 0u64,
        })
    }

    fn storage_footprint(&self) -> Value {
        let total_bytes = dir_size(&self.config.db_path).unwrap_or(0);
        json!({
            "total_bytes": total_bytes,
            "blocks_bytes": tree_size_hint(&self.block_tree),
            "state_bytes": tree_size_hint(&self.meta_tree),
            "transactions_bytes": tree_size_hint(&self.action_tree),
            "nullifiers_bytes": tree_size_hint(&self.nullifier_tree),
        })
    }

    fn node_config_snapshot(&self) -> Value {
        json!({
            "nodeName": self.config.node_name,
            "chainSpecId": if self.config.dev { "hegemon-native-dev" } else { "hegemon-native" },
            "chainSpecName": if self.config.dev { "Hegemon Native Dev" } else { "Hegemon Native" },
            "chainType": if self.config.dev { "dev" } else { "live" },
            "basePath": self.config.base_path.display().to_string(),
            "p2pListenAddr": self.config.p2p_listen_addr,
            "rpcListenAddr": self.config.rpc_addr.to_string(),
            "rpcMethods": self.config.rpc_methods,
            "rpcExternal": self.config.rpc_external,
            "bootstrapNodes": self.config.seeds,
            "pqVerbose": env_bool("HEGEMON_PQ_VERBOSE"),
            "maxPeers": self.config.max_peers,
        })
    }

    fn rpc_policy(&self) -> Result<RpcMethodPolicy> {
        rpc_method_policy(&self.config.rpc_methods, self.config.rpc_external)
    }

    fn note_status(&self) -> Value {
        let state = self.state.read();
        let root = state.commitment_tree.root();
        let leaf_count = state.commitment_tree.leaf_count();
        json!({
            "leaf_count": leaf_count,
            "depth": COMMITMENT_TREE_DEPTH as u64,
            "root": hex48(&root),
            "next_index": leaf_count,
        })
    }

    fn latest_block(&self) -> Value {
        let best = self.best_meta();
        json!({
            "height": best.height,
            "hash": hex32(&best.hash),
            "state_root": hex48(&best.state_root),
            "nullifier_root": hex48(&best.nullifier_root),
            "supply_digest": best.supply_digest,
            "timestamp": best.timestamp_ms,
        })
    }

    fn pending_extrinsics(&self) -> Value {
        let state = self.state.read();
        Value::Array(
            state
                .pending_actions
                .values()
                .map(|action| json!(hex32(&action.tx_hash)))
                .collect(),
        )
    }

    fn wallet_commitments(&self, params: Value) -> Result<Value> {
        let page = pagination_from_params(params)?;
        let mut entries = Vec::new();
        let mut expected_index = 0u64;
        for item in self.commitment_tree.iter() {
            let (index, commitment) = decode_wallet_commitment_row(item)?;
            if index != expected_index {
                return Err(anyhow!(
                    "native commitment archive index gap: expected {}, got {}",
                    expected_index,
                    index
                ));
            }
            if index >= page.start && entries.len() < page.limit as usize {
                let commitment_hex = hex48(&commitment);
                entries.push(json!({
                    "index": index,
                    "value": commitment_hex,
                    "commitment": commitment_hex,
                }));
            }
            expected_index = expected_index
                .checked_add(1)
                .ok_or_else(|| anyhow!("native commitment archive index overflow"))?;
        }
        Ok(json!({
            "entries": entries,
            "total": expected_index,
            "has_more": page.start.saturating_add(page.limit) < expected_index,
        }))
    }

    fn wallet_ciphertexts(&self, params: Value) -> Result<Value> {
        let page = pagination_from_params(params)?;
        let (entries, total) = self.ciphertext_entries_page(page)?;
        Ok(json!({
            "entries": entries,
            "total": total,
            "has_more": page.start.saturating_add(page.limit) < total,
        }))
    }

    fn ciphertext_entries_page(&self, page: NativePagination) -> Result<(Vec<Value>, u64)> {
        use base64::Engine;

        let mut entries = Vec::new();
        let mut total = 0u64;
        for item in self.ciphertext_archive_tree.iter() {
            let (index, value) = decode_wallet_ciphertext_row(item)?;
            if index >= page.start && entries.len() < page.limit as usize {
                entries.push(json!({
                    "index": index,
                    "ciphertext": base64::engine::general_purpose::STANDARD.encode(value.as_slice()),
                }));
            }
            total = total
                .checked_add(1)
                .ok_or_else(|| anyhow!("native ciphertext archive count overflow"))?;
        }
        Ok((entries, total))
    }

    fn wallet_nullifiers(&self, params: Value) -> Result<Value> {
        let page = pagination_from_params(params)?;
        let state = self.state.read();
        let total = state.nullifiers.len() as u64;
        let nullifiers = state
            .nullifiers
            .iter()
            .skip(page.start as usize)
            .take(page.limit as usize)
            .map(hex48)
            .collect::<Vec<_>>();
        Ok(json!({
            "nullifiers": nullifiers,
            "total": total,
            "has_more": page.start.saturating_add(page.limit) < total,
        }))
    }

    fn is_valid_anchor(&self, params: Value) -> Result<Value> {
        let raw = first_param(&params)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("hegemon_isValidAnchor requires a 48-byte anchor hex string"))?;
        let anchor = parse_hex48(raw).ok_or_else(|| anyhow!("invalid anchor hex"))?;
        let state = self.state.read();
        Ok(json!(state.commitment_tree.contains_root(&anchor)))
    }

    fn submit_action(&self, request: Value) -> Value {
        match self.validate_and_stage_action(request) {
            Ok(action) => {
                let tx_hash = hex32(&action.tx_hash);
                json!({
                    "success": true,
                    "tx_hash": tx_hash,
                    "error": null,
                })
            }
            Err(err) => json!({
                "success": false,
                "tx_hash": null,
                "error": err.to_string(),
            }),
        }
    }

    fn validate_and_stage_action(&self, request: Value) -> Result<PendingAction> {
        let request = decode_submit_action_rpc_request(request)?;
        let public_args = admit_native_action_request_projection(&request)?;
        let transfer_route =
            native_submit_action_is_transfer_route(request.family_id, request.action_id);
        let binding = KernelVersionBinding {
            circuit: request.binding_circuit,
            crypto: request.binding_crypto,
        };
        let nullifiers = if transfer_route {
            request
                .new_nullifiers
                .iter()
                .map(|raw| parse_hex48(raw).ok_or_else(|| anyhow!("invalid nullifier hex")))
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };

        let received_ms = current_time_ms();
        let mut pending = match (request.family_id, request.action_id) {
            (
                FAMILY_BRIDGE,
                ACTION_BRIDGE_OUTBOUND | ACTION_BRIDGE_INBOUND | ACTION_REGISTER_BRIDGE_VERIFIER,
            ) => PendingAction {
                tx_hash: [0u8; 32],
                binding,
                family_id: request.family_id,
                action_id: request.action_id,
                anchor: [0u8; 48],
                nullifiers: Vec::new(),
                commitments: Vec::new(),
                ciphertext_hashes: Vec::new(),
                ciphertext_sizes: Vec::new(),
                public_args,
                fee: 0,
                candidate_artifact: None,
                received_ms,
            },
            (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE) => {
                let args: ShieldedTransferInlineArgs =
                    decode_scale_exact(&public_args, "shielded inline action args")?;
                let ciphertext_hashes = args
                    .ciphertexts
                    .iter()
                    .map(|note| {
                        let mut bytes =
                            Vec::with_capacity(note.ciphertext.len() + note.kem_ciphertext.len());
                        bytes.extend_from_slice(&note.ciphertext);
                        bytes.extend_from_slice(&note.kem_ciphertext);
                        ciphertext_hash_bytes(&bytes)
                    })
                    .collect::<Vec<_>>();
                let ciphertext_sizes = args
                    .ciphertexts
                    .iter()
                    .map(|note| {
                        u32::try_from(note.ciphertext.len() + note.kem_ciphertext.len())
                            .unwrap_or(u32::MAX)
                    })
                    .collect::<Vec<_>>();
                validate_binding_hash(
                    args.anchor,
                    &nullifiers,
                    &args.commitments,
                    &ciphertext_hashes,
                    args.balance_slot_asset_ids,
                    args.fee,
                    args.binding_hash,
                    args.stablecoin,
                )?;
                PendingAction {
                    tx_hash: [0u8; 32],
                    binding,
                    family_id: request.family_id,
                    action_id: request.action_id,
                    anchor: args.anchor,
                    nullifiers,
                    commitments: args.commitments,
                    ciphertext_hashes,
                    ciphertext_sizes,
                    public_args,
                    fee: args.fee,
                    candidate_artifact: None,
                    received_ms,
                }
            }
            (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_SIDECAR) => {
                let mut args: ShieldedTransferSidecarArgs =
                    decode_scale_exact(&public_args, "shielded sidecar action args")?;
                let public_args = if args.proof.is_empty() {
                    let proof_key = hex64(&args.binding_hash);
                    let proof = self
                        .state
                        .read()
                        .staged_proofs
                        .get(&proof_key)
                        .cloned()
                        .ok_or_else(|| anyhow!("missing staged proof for {proof_key}"))?;
                    args.proof = proof;
                    args.encode()
                } else {
                    public_args
                };
                validate_binding_hash(
                    args.anchor,
                    &nullifiers,
                    &args.commitments,
                    &args.ciphertext_hashes,
                    args.balance_slot_asset_ids,
                    args.fee,
                    args.binding_hash,
                    args.stablecoin,
                )?;
                PendingAction {
                    tx_hash: [0u8; 32],
                    binding,
                    family_id: request.family_id,
                    action_id: request.action_id,
                    anchor: args.anchor,
                    nullifiers,
                    commitments: args.commitments,
                    ciphertext_hashes: args.ciphertext_hashes,
                    ciphertext_sizes: args.ciphertext_sizes,
                    public_args,
                    fee: args.fee,
                    candidate_artifact: None,
                    received_ms,
                }
            }
            (FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT) => {
                let args: SubmitCandidateArtifactArgs =
                    decode_scale_exact(&public_args, "candidate artifact action args")?;
                validate_candidate_artifact(&args.payload)?;
                PendingAction {
                    tx_hash: [0u8; 32],
                    binding,
                    family_id: request.family_id,
                    action_id: request.action_id,
                    anchor: [0u8; 48],
                    nullifiers: Vec::new(),
                    commitments: Vec::new(),
                    ciphertext_hashes: Vec::new(),
                    ciphertext_sizes: Vec::new(),
                    public_args,
                    fee: 0,
                    candidate_artifact: Some(args.payload),
                    received_ms,
                }
            }
            (FAMILY_SHIELDED_POOL, ACTION_MINT_COINBASE) => {
                let args: MintCoinbaseArgs =
                    decode_scale_exact(&public_args, "coinbase action args")?;
                let note = &args.reward_bundle.miner_note.encrypted_note;
                let (ciphertext_bytes, ciphertext_metadata) = coinbase_ciphertext_metadata(note);
                let (ciphertext_hash, ciphertext_size) =
                    ciphertext_metadata.unwrap_or((NATIVE_EMPTY_DIGEST48, u32::MAX));
                PendingAction {
                    tx_hash: [0u8; 32],
                    binding,
                    family_id: request.family_id,
                    action_id: request.action_id,
                    anchor: [0u8; 48],
                    nullifiers: Vec::new(),
                    commitments: vec![args.reward_bundle.miner_note.commitment],
                    ciphertext_hashes: vec![ciphertext_hash],
                    ciphertext_sizes: vec![
                        u32::try_from(ciphertext_bytes).unwrap_or(ciphertext_size)
                    ],
                    public_args,
                    fee: 0,
                    candidate_artifact: None,
                    received_ms,
                }
            }
            (_, other) => return Err(anyhow!("unsupported native action {other}")),
        };

        self.validate_action_state(&pending)?;
        pending.tx_hash = pending_action_hash(&pending);

        {
            let mut state = self.state.write();
            if state.pending_actions.len() >= MAX_NATIVE_MEMPOOL_ACTIONS {
                return Err(anyhow!("native mempool full"));
            }
            validate_mempool_byte_budget(
                &state.pending_actions,
                &pending,
                MAX_NATIVE_MEMPOOL_ACTION_BYTES,
            )?;
            if state.pending_actions.contains_key(&pending.tx_hash) {
                return Err(anyhow!("duplicate pending action"));
            }
            if pending_action_semantic_duplicate_exists(&state.pending_actions, &pending) {
                return Err(anyhow!("duplicate semantic pending action"));
            }
            validate_pending_action_against_mempool_state(&state, &pending)?;
            self.action_tree
                .insert(pending.tx_hash.as_slice(), pending.encode())?;
            self.flush_native_durability_barrier("native pending action stage")?;
            state
                .pending_actions
                .insert(pending.tx_hash, pending.clone());
        }

        Ok(pending)
    }

    fn validate_action_state(&self, action: &PendingAction) -> Result<()> {
        let state = self.state.read();
        validate_pending_action_against_mempool_state(&state, action)
    }

    fn submit_transaction(&self, _bundle: Value) -> Value {
        json!({
            "success": false,
            "tx_id": null,
            "error": "generic transaction submission is disabled; use hegemon_submitAction",
        })
    }

    fn submit_ciphertexts(&self, request: Value) -> Result<Value> {
        let ciphertexts = request
            .get("ciphertexts")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("da_submitCiphertexts requires ciphertexts array"))?;
        evaluate_native_ciphertext_sidecar_request_admission(
            NativeSidecarRequestCountAdmissionInput {
                item_count: ciphertexts.len(),
                max_items: MAX_NATIVE_DA_CIPHERTEXT_UPLOADS,
            },
        )
        .map_err(native_sidecar_upload_admission_error)?;
        let mut results = Vec::with_capacity(ciphertexts.len());
        let mut state = self.state.write();
        let mut staged_ciphertexts = state.staged_ciphertexts.clone();
        for ciphertext in ciphertexts {
            let raw =
                parse_bytes_value(ciphertext, MAX_CIPHERTEXT_BYTES, "ciphertext upload item")?;
            if raw.len() > MAX_CIPHERTEXT_BYTES {
                return Err(anyhow!(
                    "ciphertext size {} exceeds limit {}",
                    raw.len(),
                    MAX_CIPHERTEXT_BYTES
                ));
            }
            let hash = ciphertext_hash_bytes(&raw);
            let hash_hex = hex48(&hash);
            evaluate_native_ciphertext_sidecar_capacity_admission(
                NativeSidecarCapacityAdmissionInput {
                    staged_count: staged_ciphertexts.len(),
                    max_staged_count: MAX_NATIVE_STAGED_CIPHERTEXTS,
                    replaces_existing: staged_ciphertexts.contains_key(&hash_hex),
                },
            )
            .map_err(native_sidecar_upload_admission_error)?;
            let size = u32::try_from(raw.len()).unwrap_or(u32::MAX);
            self.da_ciphertext_tree.insert(hash.as_slice(), raw)?;
            staged_ciphertexts.insert(hash_hex.clone(), size);
            results.push(json!({
                "hash": hash_hex,
                "size": size,
            }));
        }
        self.flush_native_durability_barrier("native staged ciphertext upload")?;
        publish_staged_ciphertexts(&mut state, staged_ciphertexts);
        Ok(Value::Array(results))
    }

    fn submit_proofs(&self, request: Value) -> Result<Value> {
        let proofs = request
            .get("proofs")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("da_submitProofs requires proofs array"))?;
        evaluate_native_proof_sidecar_request_admission(NativeSidecarRequestCountAdmissionInput {
            item_count: proofs.len(),
            max_items: MAX_NATIVE_DA_PROOF_UPLOADS,
        })
        .map_err(native_sidecar_upload_admission_error)?;
        let mut results = Vec::with_capacity(proofs.len());
        let mut state = self.state.write();
        let mut staged_proofs = state.staged_proofs.clone();
        for item in proofs {
            let binding_hash_value = item.get("binding_hash").and_then(Value::as_str);
            let binding_hash_bytes = binding_hash_value.and_then(parse_hex64);
            let proof_value = item.get("proof");
            evaluate_native_proof_sidecar_metadata_admission(
                NativeProofSidecarMetadataAdmissionInput {
                    binding_hash_present: binding_hash_value.is_some(),
                    binding_hash_valid: binding_hash_bytes.is_some(),
                    proof_present: proof_value.is_some(),
                },
            )
            .map_err(native_sidecar_upload_admission_error)?;
            let binding_hash_bytes = binding_hash_bytes.expect("validated binding_hash hex shape");
            let binding_hash_key = hex64(&binding_hash_bytes);
            let proof = parse_bytes_value(
                proof_value.expect("validated proof presence"),
                NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
                "proof item proof",
            )?;
            evaluate_native_proof_sidecar_decoded_admission(
                NativeProofSidecarDecodedAdmissionInput {
                    proof_bytes: proof.len(),
                    max_proof_bytes: NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
                    proof_binding_hash_matches_key:
                        native_tx_leaf_artifact_binding_hash_matches_key(binding_hash_bytes, &proof),
                },
            )
            .map_err(native_sidecar_upload_admission_error)?;
            let proof_hash =
                hash48_with_parts(&[b"da-proof-v1", binding_hash_bytes.as_slice(), &proof]);
            let proof_hash_hex = hex48(&proof_hash);
            evaluate_native_proof_sidecar_capacity_admission(NativeSidecarCapacityAdmissionInput {
                staged_count: staged_proofs.len(),
                max_staged_count: MAX_NATIVE_STAGED_PROOFS,
                replaces_existing: staged_proofs.contains_key(&binding_hash_key),
            })
            .map_err(native_sidecar_upload_admission_error)?;
            validate_staged_proof_byte_budget(
                &staged_proofs,
                &binding_hash_key,
                proof.len(),
                MAX_NATIVE_STAGED_PROOF_BYTES,
            )?;
            let size = u32::try_from(proof.len()).unwrap_or(u32::MAX);
            self.da_proof_tree
                .insert(binding_hash_bytes.as_slice(), proof.as_slice())?;
            staged_proofs.insert(binding_hash_key.clone(), proof);
            results.push(json!({
                "binding_hash": binding_hash_key,
                "proof_hash": proof_hash_hex,
                "size": size,
            }));
        }
        self.flush_native_durability_barrier("native staged proof upload")?;
        publish_staged_proofs(&mut state, staged_proofs);
        Ok(Value::Array(results))
    }

    fn hash_rate(&self) -> f64 {
        let elapsed = self.start_instant.elapsed().as_secs_f64();
        if elapsed <= 0.0 {
            return 0.0;
        }
        self.mining_hashes.load(Ordering::Relaxed) as f64 / elapsed
    }
}

pub async fn run(cli: NativeCli) -> Result<()> {
    let config = NativeConfig::from_cli(cli)?;
    let node = NativeNode::open(config.clone())?;
    start_native_p2p(Arc::clone(&node), &config)?;

    info!(
        rpc = %config.rpc_addr,
        base_path = %config.base_path.display(),
        db_path = %config.db_path.display(),
        tmp = config.tmp,
        seeds = ?config.seeds,
        miner_address = ?config.miner_address,
        "starting native Hegemon node"
    );

    if config.mine {
        node.start_mining(config.mine_threads);
    }

    let listener = TcpListener::bind(config.rpc_addr)
        .await
        .with_context(|| format!("bind native JSON-RPC {}", config.rpc_addr))?;
    let app = Router::new()
        .route(
            "/",
            post(rpc_handler).get(root_handler).options(options_handler),
        )
        .route("/health", get(health_handler))
        .layer(DefaultBodyLimit::max(MAX_NATIVE_RPC_BODY_BYTES))
        .with_state(Arc::clone(&node));

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(Arc::clone(&node)))
        .await
        .context("native JSON-RPC server failed")?;

    Ok(())
}

fn start_native_p2p(node: Arc<NativeNode>, config: &NativeConfig) -> Result<()> {
    let listen_addr = config
        .p2p_listen_addr
        .parse::<SocketAddr>()
        .with_context(|| format!("parse p2p listen address {}", config.p2p_listen_addr))?;
    let gossip_router = GossipRouter::new(1024);
    let gossip_handle = gossip_router.handle();

    let peer_store = PeerStore::new(PeerStoreConfig::with_path(
        config.base_path.join("pq-peers.bin"),
    ));
    let identity_seed = load_native_identity_seed(config)?;
    let mut service = P2PService::new(
        PeerIdentity::generate(&identity_seed),
        listen_addr,
        config.seeds.clone(),
        Vec::new(),
        gossip_handle,
        config.max_peers as usize,
        peer_store,
        RelayConfig::default(),
        NatTraversalConfig::disabled(listen_addr),
    );
    let sync_handle = service.register_protocol(NATIVE_SYNC_PROTOCOL_ID);
    node.set_sync_sender(sync_handle.sender());

    tokio::spawn(async move {
        if let Err(err) = service.run().await {
            warn!(error = %err, "native PQ service stopped");
        }
    });

    tokio::spawn(native_sync_loop(Arc::clone(&node), sync_handle));

    let mut gossip_rx = gossip_router.handle().subscribe();
    tokio::spawn(async move {
        loop {
            match gossip_rx.recv().await {
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "native gossip receiver lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    Ok(())
}

async fn native_sync_loop(node: Arc<NativeNode>, mut handle: ProtocolHandle) {
    while let Some((peer_id, msg)) = handle.recv().await {
        if msg.protocol != NATIVE_SYNC_PROTOCOL_ID {
            continue;
        }
        let sync_msg = match decode_sync_message(&msg.payload) {
            Ok(sync_msg) => sync_msg,
            Err(err) => {
                warn!(error = %err, "failed to decode native sync message");
                continue;
            }
        };

        match sync_msg {
            NativeSyncMessage::Announce(meta) => {
                let meta = *meta;
                let announced_height = meta.height;
                match node.import_announced_block(meta.clone()) {
                    Ok(true) => {
                        info!(
                            height = meta.height,
                            hash = %hex32(&meta.hash),
                            "imported native block announce"
                        );
                    }
                    Ok(false) => {
                        request_missing_blocks(&node, &handle, peer_id, announced_height).await;
                    }
                    Err(err) => {
                        warn!(
                            height = meta.height,
                            hash = %hex32(&meta.hash),
                            error = %err,
                            "failed to import native block announce"
                        );
                    }
                }
            }
            NativeSyncMessage::Request {
                from_height,
                to_height,
            } => {
                if to_height < from_height {
                    continue;
                }
                let blocks = match node.block_range(from_height, to_height) {
                    Ok(blocks) => blocks,
                    Err(err) => {
                        warn!(
                            from_height,
                            to_height,
                            error = %err,
                            "failed to load native sync block range"
                        );
                        continue;
                    }
                };
                send_sync_message(
                    &handle,
                    peer_id,
                    NativeSyncMessage::Response {
                        best_height: node.best_meta().height,
                        blocks,
                    },
                )
                .await;
            }
            NativeSyncMessage::Response {
                best_height,
                mut blocks,
            } => {
                if let Err(rejection) = evaluate_native_sync_response_count_admission(
                    NativeSyncResponseCountAdmissionInput {
                        block_count: blocks.len(),
                        max_blocks: MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE,
                    },
                ) {
                    warn!(
                        block_count = blocks.len(),
                        max_blocks = MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE,
                        rejection = rejection.label(),
                        "rejecting oversized native sync response"
                    );
                    continue;
                }
                blocks.sort_by_key(|meta| meta.height);
                let had_blocks = !blocks.is_empty();
                let mut imported = 0u64;
                for meta in blocks {
                    match node.import_announced_block(meta.clone()) {
                        Ok(true) => {
                            imported = imported.saturating_add(1);
                        }
                        Ok(false) => {}
                        Err(err) => {
                            warn!(
                                height = meta.height,
                                hash = %hex32(&meta.hash),
                                error = %err,
                                "failed to import native sync block"
                            );
                            break;
                        }
                    }
                }
                if imported > 0 {
                    info!(
                        imported,
                        best_height = node.best_meta().height,
                        peer_best_height = best_height,
                        "imported native sync response"
                    );
                }
                if had_blocks && node.best_meta().height < best_height {
                    request_missing_blocks(&node, &handle, peer_id, best_height).await;
                }
            }
        }
    }
}

async fn request_missing_blocks(
    node: &NativeNode,
    handle: &ProtocolHandle,
    peer_id: PeerId,
    announced_height: u64,
) {
    let best_height = node.best_meta().height;
    let Some(range) = native_sync_missing_request_range(NativeSyncMissingRequestInput {
        best_height,
        announced_height,
        max_blocks: MAX_NATIVE_SYNC_RESPONSE_BLOCKS,
    }) else {
        return;
    };
    send_sync_message(
        handle,
        peer_id,
        NativeSyncMessage::Request {
            from_height: range.from_height,
            to_height: range.to_height,
        },
    )
    .await;
}

async fn send_sync_message(handle: &ProtocolHandle, peer_id: PeerId, message: NativeSyncMessage) {
    let payload = match encode_sync_message(&message) {
        Ok(payload) => payload,
        Err(err) => {
            warn!(error = %err, "failed to encode native sync message");
            return;
        }
    };
    if let Err(err) = handle.send_to(peer_id, payload).await {
        warn!(error = %err, "failed to send native sync message");
    }
}

fn encode_sync_message(message: &NativeSyncMessage) -> Result<Vec<u8>> {
    wire::encode(message, MAX_NATIVE_SYNC_MESSAGE_BYTES).context("encode native sync message")
}

fn decode_sync_message(payload: &[u8]) -> Result<NativeSyncMessage> {
    wire::decode(payload, MAX_NATIVE_SYNC_MESSAGE_BYTES).context("decode native sync message")
}

async fn rpc_handler(State(node): State<Arc<NativeNode>>, Json(payload): Json<Value>) -> Response {
    let response = match payload {
        Value::Array(requests) => {
            if requests.is_empty() {
                return json_response(
                    &node,
                    StatusCode::OK,
                    rpc_error(Value::Null, -32600, "empty JSON-RPC batch"),
                );
            }
            if requests.len() > MAX_NATIVE_RPC_BATCH_REQUESTS {
                return json_response(
                    &node,
                    StatusCode::OK,
                    rpc_error(
                        Value::Null,
                        -32600,
                        format!(
                            "JSON-RPC batch too large: {} > {}",
                            requests.len(),
                            MAX_NATIVE_RPC_BATCH_REQUESTS
                        ),
                    ),
                );
            }
            let responses = requests
                .into_iter()
                .map(|request| dispatch_rpc_request(&node, request))
                .collect::<Vec<_>>();
            Value::Array(responses)
        }
        request => dispatch_rpc_request(&node, request),
    };
    json_response(&node, StatusCode::OK, response)
}

async fn root_handler(State(node): State<Arc<NativeNode>>) -> Response {
    json_response(
        &node,
        StatusCode::OK,
        json!({
            "name": "hegemon-node",
            "version": env!("CARGO_PKG_VERSION"),
            "best": node.consensus_status(),
        }),
    )
}

async fn health_handler(State(node): State<Arc<NativeNode>>) -> Response {
    json_response(
        &node,
        StatusCode::OK,
        json!({
            "ok": true,
            "height": node.best_meta().height,
            "syncing": false,
        }),
    )
}

async fn options_handler(State(node): State<Arc<NativeNode>>) -> Response {
    with_cors(&node, StatusCode::NO_CONTENT.into_response())
}

fn dispatch_rpc_request(node: &Arc<NativeNode>, request: Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return rpc_error(id, -32600, "invalid JSON-RPC request");
    };
    let params = request
        .get("params")
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));

    match dispatch_rpc_method(node, method, params) {
        Ok(result) => json!({
            "jsonrpc": "2.0",
            "result": result,
            "id": id,
        }),
        Err(err) => rpc_error(id, -32602, err.to_string()),
    }
}

fn dispatch_rpc_method(node: &Arc<NativeNode>, method: &str, params: Value) -> Result<Value> {
    if is_unsafe_rpc_method(method) && node.rpc_policy()? != RpcMethodPolicy::Unsafe {
        return Err(anyhow!(
            "unsafe RPC method {method} is disabled; use --rpc-methods=unsafe only on a trusted local control plane"
        ));
    }

    match method {
        "rpc_methods" => Ok(json!({
            "methods": native_rpc_methods(node.rpc_policy()?),
        })),
        "system_health" => Ok(json!({
            "isSyncing": false,
            "peers": 0u32,
            "shouldHavePeers": !node.config.seeds.is_empty(),
        })),
        "system_peers" => Ok(Value::Array(Vec::new())),
        "system_version" => Ok(json!(format!(
            "Hegemon Native Node {}",
            env!("CARGO_PKG_VERSION")
        ))),
        "system_name" => Ok(json!("Hegemon Native Node")),
        "system_chain" => Ok(json!(if node.config.dev {
            "Hegemon Native Dev"
        } else {
            "Hegemon Native"
        })),
        "chain_getHeader" => chain_get_header(node, params),
        "chain_getBlockHash" => chain_get_block_hash(node, params),
        "chain_getBlock" => chain_get_block(node, params),
        "state_getRuntimeVersion" => Ok(json!({
            "specName": "hegemon-native",
            "implName": "hegemon-native",
            "authoringVersion": 1u32,
            "specVersion": 10u32,
            "implVersion": 0u32,
            "transactionVersion": 1u32,
            "stateVersion": 1u8,
            "apis": [],
        })),
        "state_getStorage" | "state_getStorageAt" => Ok(Value::Null),
        "state_getStorageHash" | "state_getStorageHashAt" => Ok(Value::Null),
        "state_getStorageSize" | "state_getStorageSizeAt" => Ok(Value::Null),
        "author_pendingExtrinsics" => Ok(node.pending_extrinsics()),
        "chain_subscribeNewHeads" | "chain_subscribeFinalizedHeads" => Err(anyhow!(
            "subscriptions require the native WebSocket RPC milestone"
        )),
        "hegemon_miningStatus" => Ok(node.mining_status()),
        "hegemon_startMining" => {
            let threads = start_mining_threads_from_params(&params)?;
            node.start_mining(threads);
            Ok(json!({
                "success": true,
                "message": "mining started",
                "status": node.mining_status(),
            }))
        }
        "hegemon_stopMining" => {
            node.stop_mining();
            Ok(json!({
                "success": true,
                "message": "mining stopped",
                "status": node.mining_status(),
            }))
        }
        "hegemon_consensusStatus" => Ok(node.consensus_status()),
        "hegemon_exportBridgeWitness" => export_bridge_witness(node, params),
        "hegemon_telemetry" => Ok(node.telemetry_snapshot()),
        "hegemon_storageFootprint" => Ok(node.storage_footprint()),
        "hegemon_nodeConfig" => Ok(node.node_config_snapshot()),
        "hegemon_blockTimestamps" => block_timestamps(node, params, false),
        "hegemon_minedBlockTimestamps" => block_timestamps(node, Value::Array(vec![]), true),
        "hegemon_peerList" => Ok(Value::Array(Vec::new())),
        "hegemon_peerGraph" => Ok(json!({
            "local_peer_id": "",
            "peers": [],
            "reports": [],
        })),
        "hegemon_submitAction" => {
            Ok(node.submit_action(first_param(&params).cloned().unwrap_or(params)))
        }
        "hegemon_isValidAnchor" => node.is_valid_anchor(params),
        "hegemon_walletNotes" => Ok(node.note_status()),
        "hegemon_walletCommitments" => node.wallet_commitments(params),
        "hegemon_walletCiphertexts" => node.wallet_ciphertexts(params),
        "hegemon_walletNullifiers" => node.wallet_nullifiers(params),
        "hegemon_latestBlock" => Ok(node.latest_block()),
        "hegemon_generateProof" => Ok(json!({
            "success": false,
            "proof": null,
            "public_inputs": null,
            "error": "native proof generation has not moved into the node yet",
            "generation_time_ms": 0u64,
        })),
        "hegemon_submitTransaction" => {
            Ok(node.submit_transaction(first_param(&params).cloned().unwrap_or(params)))
        }
        "hegemon_poolWork" => Ok(json!({
            "available": false,
            "height": null,
            "pre_hash": null,
            "parent_hash": null,
            "network_difficulty": node.config.pow_bits,
            "share_difficulty": null,
            "reason": "native pool RPC is not enabled in milestone 1",
        })),
        "hegemon_compactJob" => Ok(json!({
            "available": false,
            "job_id": null,
            "height": null,
            "pre_hash": null,
            "parent_hash": null,
            "network_bits": node.config.pow_bits,
            "share_bits": null,
            "reason": "native compact-job RPC is not enabled in milestone 1",
        })),
        "hegemon_submitPoolShare" | "hegemon_submitCompactSolution" => Ok(json!({
            "accepted": false,
            "block_candidate": false,
            "network_target_met": false,
            "error": "native pool submissions are not enabled in milestone 1",
            "accepted_shares": 0u64,
            "rejected_shares": 1u64,
            "worker_accepted_shares": 0u64,
            "worker_rejected_shares": 1u64,
        })),
        "hegemon_poolStatus" => Ok(json!({
            "available": false,
            "network_difficulty": node.config.pow_bits,
            "share_difficulty": null,
            "accepted_shares": 0u64,
            "rejected_shares": 0u64,
            "worker_count": 0usize,
            "workers": [],
        })),
        "da_getParams" => Ok(json!({
            "chunk_size": DEFAULT_DA_CHUNK_SIZE,
            "sample_count": DEFAULT_DA_SAMPLE_COUNT,
        })),
        "da_getChunk" => Ok(Value::Null),
        "da_submitCiphertexts" => {
            node.submit_ciphertexts(first_param(&params).cloned().unwrap_or(params))
        }
        "da_submitProofs" => node.submit_proofs(first_param(&params).cloned().unwrap_or(params)),
        "da_submitWitnesses" => Err(anyhow!("witness sidecar upload is disabled")),
        "archive_listProviders" => Ok(Value::Array(Vec::new())),
        "archive_getProvider" => Ok(Value::Null),
        "archive_providerCount" => Ok(json!(0u64)),
        "archive_listContracts" => Ok(Value::Array(Vec::new())),
        "archive_getContract" => Ok(Value::Null),
        "block_getCommitmentProof" => Ok(Value::Null),
        other => Err(anyhow!("method not found: {other}")),
    }
}

fn chain_get_header(node: &NativeNode, params: Value) -> Result<Value> {
    let meta = match first_param(&params) {
        Some(Value::String(hash_hex)) => {
            let Some(hash) = parse_hash32(hash_hex) else {
                return Ok(Value::Null);
            };
            node.header_by_hash(&hash)?
        }
        Some(Value::Null) | None => Some(node.best_meta()),
        Some(_) => return Ok(Value::Null),
    };
    Ok(meta.as_ref().map(header_json).unwrap_or(Value::Null))
}

fn chain_get_block_hash(node: &NativeNode, params: Value) -> Result<Value> {
    let hash = match first_param(&params) {
        Some(Value::Number(number)) => match number.as_u64() {
            Some(height) => node.hash_by_height(height)?,
            None => None,
        },
        Some(Value::String(raw)) => match parse_height(raw) {
            Some(height) => node.hash_by_height(height)?,
            None => None,
        },
        Some(Value::Null) | None => Some(node.best_meta().hash),
        Some(_) => None,
    };
    Ok(hash.map(|hash| json!(hex32(&hash))).unwrap_or(Value::Null))
}

fn chain_get_block(node: &NativeNode, params: Value) -> Result<Value> {
    let hash = match first_param(&params) {
        Some(Value::String(hash_hex)) => {
            let Some(hash) = parse_hash32(hash_hex) else {
                return Ok(Value::Null);
            };
            hash
        }
        Some(Value::Null) | None => node.best_meta().hash,
        Some(_) => return Ok(Value::Null),
    };
    let Some(meta) = node.header_by_hash(&hash)? else {
        return Ok(Value::Null);
    };
    Ok(json!({
        "block": {
            "header": header_json(&meta),
            "extrinsics": meta
                .action_bytes
                .iter()
                .map(|bytes| format!("0x{}", hex::encode(bytes)))
                .collect::<Vec<_>>(),
        },
        "justifications": null,
    }))
}

fn block_timestamps(node: &NativeNode, params: Value, mined_only: bool) -> Result<Value> {
    if mined_only {
        let best = node.best_meta();
        if best.height == 0 {
            return Ok(Value::Array(Vec::new()));
        }
        let start = best
            .height
            .saturating_sub(MAX_NATIVE_TIMESTAMP_ROWS.saturating_sub(1))
            .max(1);
        let mut rows = Vec::new();
        for height in start..=best.height {
            if let Some(meta) = timestamp_meta_by_height(node, height)? {
                rows.push(json!({
                    "height": meta.height,
                    "timestamp_ms": meta.timestamp_ms,
                }));
            }
        }
        return Ok(Value::Array(rows));
    }

    let start = first_param(&params).and_then(Value::as_u64).unwrap_or(0);
    let end = nth_param(&params, 1)
        .and_then(Value::as_u64)
        .unwrap_or(start);
    if end < start {
        return Err(anyhow!("timestamp range end is before start"));
    }
    let requested = end
        .checked_sub(start)
        .and_then(|delta| delta.checked_add(1))
        .ok_or_else(|| anyhow!("timestamp range overflow"))?;
    if requested > MAX_NATIVE_TIMESTAMP_ROWS {
        return Err(anyhow!(
            "timestamp range too large: {} > {}",
            requested,
            MAX_NATIVE_TIMESTAMP_ROWS
        ));
    }
    let mut rows = Vec::new();
    for height in start..=end {
        let timestamp_ms = timestamp_meta_by_height(node, height)?.map(|meta| meta.timestamp_ms);
        rows.push(json!({
            "height": height,
            "timestamp_ms": timestamp_ms,
        }));
    }
    Ok(Value::Array(rows))
}

fn timestamp_meta_by_height(node: &NativeNode, height: u64) -> Result<Option<NativeBlockMeta>> {
    if node.hash_by_height(height)?.is_none() {
        if height <= node.best_meta().height {
            return Err(anyhow!(
                "missing canonical height index for native block {height}"
            ));
        }
        return Ok(None);
    };
    node.load_canonical_sync_block_at_height(height).map(Some)
}

fn decode_wallet_commitment_row(
    item: sled::Result<(sled::IVec, sled::IVec)>,
) -> Result<(u64, [u8; 48])> {
    let (key, value) = item.context("read native commitment archive row")?;
    if key.len() != 8 {
        return Err(anyhow!(
            "native commitment archive key has invalid length: expected 8, got {}",
            key.len()
        ));
    }
    if value.len() != 48 {
        return Err(anyhow!(
            "native commitment archive value has invalid length: expected 48, got {}",
            value.len()
        ));
    }
    let mut index = [0u8; 8];
    index.copy_from_slice(key.as_ref());
    let mut commitment = [0u8; 48];
    commitment.copy_from_slice(value.as_ref());
    Ok((u64::from_be_bytes(index), commitment))
}

fn decode_wallet_ciphertext_row(
    item: sled::Result<(sled::IVec, sled::IVec)>,
) -> Result<(u64, Vec<u8>)> {
    let (key, value) = item.context("read native ciphertext archive row")?;
    if key.len() != 8 {
        return Err(anyhow!(
            "native ciphertext archive key has invalid length: expected 8, got {}",
            key.len()
        ));
    }
    validate_wallet_ciphertext_archive_value(value.as_ref())?;
    let mut index = [0u8; 8];
    index.copy_from_slice(key.as_ref());
    Ok((u64::from_be_bytes(index), value.to_vec()))
}

fn validate_wallet_ciphertext_archive_value(bytes: &[u8]) -> Result<()> {
    if bytes.len() < MIN_NATIVE_WALLET_CIPHERTEXT_BYTES {
        return Err(anyhow!(
            "native ciphertext archive value is too short: expected at least {}, got {}",
            MIN_NATIVE_WALLET_CIPHERTEXT_BYTES,
            bytes.len()
        ));
    }
    if bytes.len() > MAX_CIPHERTEXT_BYTES {
        return Err(anyhow!(
            "native ciphertext archive value exceeds max: {} > {}",
            bytes.len(),
            MAX_CIPHERTEXT_BYTES
        ));
    }
    Ok(())
}

fn export_bridge_witness(node: &NativeNode, params: Value) -> Result<Value> {
    let message_index = bridge_witness_message_index(&params)?;
    let block_hash = match bridge_witness_explicit_block_hash(&params)? {
        Some(hash) => hash,
        None => latest_bridge_message_block_hash(node, message_index)?,
    };
    let meta = node.header_by_hash(&block_hash)?;
    let canonical_hash = match &meta {
        Some(meta) => node.hash_by_height(meta.height)?,
        None => None,
    };
    let canonical_height_present = match &meta {
        Some(_) => canonical_hash.is_some(),
        None => true,
    };
    let block_is_canonical = match (&meta, canonical_hash) {
        (Some(meta), Some(hash)) => hash == meta.hash,
        (Some(_), None) | (None, _) => true,
    };
    let actions = match meta.as_ref() {
        Some(meta) if canonical_height_present && block_is_canonical => {
            Some(decode_block_actions(meta).context("decode bridge witness block actions")?)
        }
        _ => None,
    };
    let messages = match (actions.as_ref(), meta.as_ref()) {
        (Some(actions), Some(meta)) => Some(bridge_messages_from_actions(actions, meta.height)?),
        _ => None,
    };
    let message_index_in_bounds = match &messages {
        Some(messages) => messages.get(message_index).is_some(),
        None => true,
    };
    let parent = match meta.as_ref() {
        Some(meta) if canonical_height_present && block_is_canonical && message_index_in_bounds => {
            node.header_by_hash(&meta.parent_hash)?
        }
        _ => None,
    };
    let best = node.best_meta();
    let confirmations_checked =
        evaluate_native_bridge_witness_export_admission(NativeBridgeWitnessExportAdmissionInput {
            block_hash_parameter_valid: true,
            block_known: meta.is_some(),
            canonical_height_present,
            block_is_canonical,
            block_actions_decoded: true,
            message_index_in_bounds,
            parent_known: parent.is_some()
                || !(meta.is_some()
                    && canonical_height_present
                    && block_is_canonical
                    && message_index_in_bounds),
            best_height: best.height,
            message_height: meta.as_ref().map(|meta| meta.height).unwrap_or(best.height),
        })
        .map_err(native_bridge_witness_export_admission_error)?;
    let meta = meta.expect("bridge witness admission ensures block exists");
    let messages = messages.expect("bridge witness admission ensures actions decoded");
    let message = messages
        .get(message_index)
        .cloned()
        .expect("bridge witness admission ensures message index is in bounds");
    let parent = parent.expect("bridge witness admission ensures parent exists");
    verify_native_block_meta_projection(Some(&parent), &meta).with_context(|| {
        format!(
            "validate bridge witness native block metadata at height {} ({})",
            meta.height,
            hex32(&meta.hash)
        )
    })?;
    let header = pow_header_from_meta(&meta);
    let parent_checkpoint = checkpoint_from_meta(&parent);
    let output = bridge_checkpoint_output_with_tip(
        &checkpoint_from_meta(&meta),
        &checkpoint_from_meta(&best),
        meta.message_root,
        &message,
        confirmations_checked,
        [0u8; 48],
    );
    let direct_output = bridge_checkpoint_output(
        &checkpoint_from_meta(&meta),
        meta.message_root,
        &message,
        1,
        [0u8; 48],
    );
    let light_client_receipt = HegemonLightClientProofReceiptV1 {
        verifier_hash: HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V1,
        parent_checkpoint: parent_checkpoint.clone(),
        header: header.clone(),
        messages: messages.clone(),
        message_index: message_index
            .try_into()
            .map_err(|_| anyhow!("bridge message index out of bounds"))?,
        output: direct_output,
    };
    let long_range_proof = build_long_range_bridge_proof(
        node,
        &meta,
        &best,
        &messages,
        message_index,
        output.clone(),
    )?;
    let canonical_long_range_proof = long_range_proof
        .as_ref()
        .map(|proof| format!("0x{}", hex::encode(proof.encode())));
    Ok(json!({
        "schema": "hegemon.bridge-witness.v1",
        "parent_checkpoint": checkpoint_json(&parent_checkpoint),
        "header": pow_header_json(&header),
        "header_hashes": node.header_hashes_to_hash(parent.hash)?
            .into_iter()
            .map(|hash| hex32(&hash))
            .collect::<Vec<_>>(),
        "message_index": message_index,
        "messages": messages.iter().map(bridge_message_json).collect::<Vec<_>>(),
        "output": bridge_checkpoint_output_json(&output),
        "canonical": {
            "parent_checkpoint": format!("0x{}", hex::encode(canonical_trusted_checkpoint_bytes_v1(&parent_checkpoint))),
            "header": format!("0x{}", hex::encode(header.canonical_bytes())),
            "message": format!("0x{}", hex::encode(message.encode())),
            "output": format!("0x{}", hex::encode(canonical_bridge_checkpoint_output_bytes_v1(&output))),
            "light_client_receipt": format!("0x{}", hex::encode(light_client_receipt.encode())),
            "long_range_proof": canonical_long_range_proof,
        },
    }))
}

fn bridge_witness_message_index(params: &Value) -> Result<usize> {
    let raw = nth_param(params, 1).and_then(Value::as_u64).unwrap_or(0);
    raw.try_into().map_err(|_| {
        native_bridge_witness_export_admission_error(
            NativeBridgeWitnessExportAdmissionRejection::MessageIndexOutOfBounds,
        )
    })
}

fn bridge_witness_explicit_block_hash(params: &Value) -> Result<Option<Hash32>> {
    match first_param(params) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::String(raw)) => parse_hash32(raw).map(Some).ok_or_else(|| {
            native_bridge_witness_export_admission_error(
                NativeBridgeWitnessExportAdmissionRejection::MalformedBlockHash,
            )
        }),
        Some(_) => Err(native_bridge_witness_export_admission_error(
            NativeBridgeWitnessExportAdmissionRejection::MalformedBlockHash,
        )),
    }
}

fn latest_bridge_message_block_hash(node: &NativeNode, message_index: usize) -> Result<Hash32> {
    let best = node.best_meta();
    let min_height = best
        .height
        .saturating_sub(MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS.saturating_sub(1));
    let mut entries = Vec::new();
    let mut hashes = Vec::new();
    for height in (min_height..=best.height).rev() {
        let mut entry = NativeBridgeWitnessBackscanEntry {
            height,
            canonical_hash_present: false,
            block_known: false,
            block_actions_decoded: true,
            message_index_in_bounds: false,
        };
        let mut selected_hash = None;
        if let Some(hash) = node.hash_by_height(height)? {
            entry.canonical_hash_present = true;
            if let Some(meta) = node.header_by_hash(&hash)? {
                entry.block_known = true;
                selected_hash = Some(meta.hash);
                let actions = decode_block_actions(&meta).with_context(|| {
                    format!("decode bridge witness backscan block actions at height {height}")
                })?;
                let messages = bridge_messages_from_actions(&actions, meta.height)?;
                entry.message_index_in_bounds = messages.len() > message_index;
            }
        }
        entries.push(entry);
        hashes.push(selected_hash);
        match evaluate_native_bridge_witness_backscan(&entries) {
            Ok(selected_height) => {
                let selected_index = entries
                    .iter()
                    .position(|candidate| candidate.height == selected_height)
                    .expect("backscan selected height must come from scanned entries");
                return hashes[selected_index].ok_or_else(|| {
                    anyhow!(
                        "bridge witness backscan selected missing block hash at height {selected_height}"
                    )
                });
            }
            Err(NativeBridgeWitnessBackscanRejection::BlockActionsDecodeFailed) => {
                return Err(anyhow!(
                    "bridge witness backscan block action decode failed ({})",
                    NativeBridgeWitnessBackscanRejection::BlockActionsDecodeFailed.label()
                ))
            }
            Err(NativeBridgeWitnessBackscanRejection::NoBridgeMessageInBackscan) => {}
        }
    }
    Err(anyhow!(
        "no bridge message found in the last {MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS} canonical blocks; pass the source block hash explicitly for older messages"
    ))
}

fn build_long_range_bridge_proof(
    node: &NativeNode,
    message_meta: &NativeBlockMeta,
    tip_meta: &NativeBlockMeta,
    messages: &[BridgeMessageV1],
    message_index: usize,
    output: BridgeCheckpointOutputV1,
) -> Result<Option<HegemonLongRangeProofV1>> {
    if tip_meta.height <= message_meta.height {
        return Ok(None);
    }
    let genesis_hash = node
        .hash_by_height(0)?
        .ok_or_else(|| anyhow!("missing genesis hash for bridge witness"))?;
    let genesis = node
        .header_by_hash(&genesis_hash)?
        .ok_or_else(|| anyhow!("missing genesis header for bridge witness"))?;
    let tip_history = node.header_hashes_to_hash(tip_meta.parent_hash)?;
    let message_header = pow_header_from_meta(message_meta);
    let tip_header = pow_header_from_meta(tip_meta);
    let message_header_opening = header_mmr_opening_from_hashes(&tip_history, message_meta.height)
        .map_err(|err| anyhow!("build message header MMR opening failed: {err:?}"))?;
    let sample_indices = flyclient_sample_indices(
        tip_meta.header_mmr_root,
        tip_meta.hash,
        message_meta.hash,
        genesis.height.saturating_add(1),
        tip_meta.height,
        DEFAULT_BRIDGE_FLYCLIENT_SAMPLE_COUNT,
    );
    let mut sample_headers = Vec::with_capacity(sample_indices.len());
    for sample_height in sample_indices {
        let sample_hash = node
            .hash_by_height(sample_height)?
            .ok_or_else(|| anyhow!("missing sampled header at height {sample_height}"))?;
        let sample_meta = node
            .header_by_hash(&sample_hash)?
            .ok_or_else(|| anyhow!("missing sampled header {}", hex32(&sample_hash)))?;
        let opening = header_mmr_opening_from_hashes(&tip_history, sample_height)
            .map_err(|err| anyhow!("build sampled header MMR opening failed: {err:?}"))?;
        sample_headers.push(HeaderMmrLeafWitnessV1 {
            header: pow_header_from_meta(&sample_meta),
            opening,
        });
    }
    Ok(Some(HegemonLongRangeProofV1 {
        verifier_hash: HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V1,
        trusted_checkpoint: checkpoint_from_meta(&genesis),
        tip_header,
        message_header,
        message_header_opening,
        messages: messages.to_vec(),
        message_index: message_index
            .try_into()
            .map_err(|_| anyhow!("bridge message index out of bounds"))?,
        sample_headers,
        sample_count: DEFAULT_BRIDGE_FLYCLIENT_SAMPLE_COUNT,
        output,
    }))
}

fn header_json(meta: &NativeBlockMeta) -> Value {
    json!({
        "parentHash": hex32(&meta.parent_hash),
        "number": format!("0x{:x}", meta.height),
        "stateRoot": hex32(&hash32_with_parts(&[b"native-state-root-view", &meta.state_root])),
        "extrinsicsRoot": hex32(&meta.extrinsics_root),
        "chainId": hex32(&meta.chain_id),
        "rulesHash": hex32(&meta.rules_hash),
        "kernelRoot": hex48(&meta.kernel_root),
        "nullifierRoot": hex48(&meta.nullifier_root),
        "messageRoot": hex48(&meta.message_root),
        "messageCount": meta.message_count,
        "headerMmrRoot": hex32(&meta.header_mmr_root),
        "headerMmrLen": meta.header_mmr_len,
        "cumulativeWork": format!("0x{}", hex::encode(meta.cumulative_work)),
        "powBits": meta.pow_bits,
        "nonce": hex32(&meta.nonce),
        "digest": {
            "logs": [],
        },
    })
}

fn checkpoint_json(checkpoint: &TrustedCheckpointV1) -> Value {
    json!({
        "chain_id": hex32(&checkpoint.chain_id),
        "rules_hash": hex32(&checkpoint.rules_hash),
        "height": checkpoint.height,
        "header_hash": hex32(&checkpoint.header_hash),
        "timestamp_ms": checkpoint.timestamp_ms,
        "pow_bits": checkpoint.pow_bits,
        "cumulative_work": format!("0x{}", hex::encode(checkpoint.cumulative_work)),
        "header_mmr_root": hex32(&checkpoint.header_mmr_root),
        "header_mmr_len": checkpoint.header_mmr_len,
    })
}

fn pow_header_json(header: &PowHeaderV1) -> Value {
    json!({
        "chain_id": hex32(&header.chain_id),
        "rules_hash": hex32(&header.rules_hash),
        "height": header.height,
        "timestamp_ms": header.timestamp_ms,
        "parent_hash": hex32(&header.parent_hash),
        "state_root": hex48(&header.state_root),
        "kernel_root": hex48(&header.kernel_root),
        "nullifier_root": hex48(&header.nullifier_root),
        "action_root": hex32(&header.action_root),
        "message_root": hex48(&header.message_root),
        "message_count": header.message_count,
        "header_mmr_root": hex32(&header.header_mmr_root),
        "header_mmr_len": header.header_mmr_len,
        "pow_bits": header.pow_bits,
        "nonce": hex32(&header.nonce),
        "cumulative_work": format!("0x{}", hex::encode(header.cumulative_work)),
        "pow_hash": hex32(&header.pow_hash()),
    })
}

fn bridge_message_json(message: &BridgeMessageV1) -> Value {
    json!({
        "source_chain_id": hex32(&message.source_chain_id),
        "destination_chain_id": hex32(&message.destination_chain_id),
        "app_family_id": message.app_family_id,
        "message_nonce": message.message_nonce.to_string(),
        "source_height": message.source_height,
        "payload_hash": hex48(&message.payload_hash),
        "payload": format!("0x{}", hex::encode(&message.payload)),
        "message_hash": hex48(&message.message_hash()),
    })
}

fn bridge_checkpoint_output_json(output: &BridgeCheckpointOutputV1) -> Value {
    json!({
        "source_chain_id": hex32(&output.source_chain_id),
        "rules_hash": hex32(&output.rules_hash),
        "checkpoint_height": output.checkpoint_height,
        "checkpoint_header_hash": hex32(&output.checkpoint_header_hash),
        "checkpoint_cumulative_work": format!("0x{}", hex::encode(output.checkpoint_cumulative_work)),
        "canonical_tip_height": output.canonical_tip_height,
        "canonical_tip_header_hash": hex32(&output.canonical_tip_header_hash),
        "canonical_tip_cumulative_work": format!("0x{}", hex::encode(output.canonical_tip_cumulative_work)),
        "message_root": hex48(&output.message_root),
        "message_hash": hex48(&output.message_hash),
        "message_nonce": output.message_nonce.to_string(),
        "confirmations_checked": output.confirmations_checked,
        "min_work_checked": format!("0x{}", hex::encode(output.min_work_checked)),
    })
}

async fn mining_loop(node: Arc<NativeNode>) {
    while node.mining.load(Ordering::SeqCst) {
        let work = match node.prepare_work() {
            Ok(work) => work,
            Err(err) => {
                warn!(error = %err, "failed to prepare native mining work");
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
        };
        let start_round = node.mining_round.fetch_add(1, Ordering::Relaxed);
        let work_for_task = work.clone();

        let mined =
            tokio::task::spawn_blocking(move || mine_native_round(work_for_task, start_round))
                .await;

        match mined {
            Ok(Some(seal)) => {
                if let Err(err) = node.import_mined_block(&work, seal) {
                    warn!(error = %err, "failed to import native mined block");
                }
            }
            Ok(None) => {
                node.mining_hashes
                    .fetch_add(HASHES_PER_ROUND, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(err) => {
                warn!(error = %err, "native mining task failed");
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
}

fn mine_native_round(work: NativeWork, round: u64) -> Option<NativeSeal> {
    let start = round.saturating_mul(HASHES_PER_ROUND);
    let end = start.saturating_add(HASHES_PER_ROUND);
    for counter in start..end {
        let nonce = nonce_from_counter(counter);
        let work_hash = native_pow_work_hash(&work.pre_hash, nonce);
        if native_seal_meets_target(&work_hash, work.pow_bits) {
            debug!(height = work.height, counter, "native PoW seal found");
            return Some(NativeSeal { nonce, work_hash });
        }
    }
    None
}

fn publish_mined_state(state: &mut NativeState, next_state: NativeState) {
    *state = next_state;
}

fn publish_reorganized_state(state: &mut NativeState, next_state: NativeState) {
    *state = next_state;
}

fn publish_staged_ciphertexts(state: &mut NativeState, staged_ciphertexts: BTreeMap<String, u32>) {
    state.staged_ciphertexts = staged_ciphertexts;
}

fn publish_staged_proofs(state: &mut NativeState, staged_proofs: BTreeMap<String, Vec<u8>>) {
    state.staged_proofs = staged_proofs;
}

fn collect_tree_keys(tree: &sled::Tree, tree_name: &str) -> Result<Vec<Vec<u8>>> {
    tree.iter()
        .keys()
        .map(|key| {
            key.map(|key| key.to_vec())
                .with_context(|| format!("collect {tree_name} tree keys"))
        })
        .collect()
}

fn load_best_or_genesis(
    db: &sled::Db,
    meta_tree: &sled::Tree,
    height_tree: &sled::Tree,
    block_tree: &sled::Tree,
    pow_bits: u32,
) -> Result<NativeBlockMeta> {
    if let Some(bytes) = meta_tree.get(META_BEST_KEY)? {
        return bincode_deserialize_native_block_meta_exact(&bytes, "native best metadata");
    }

    let genesis = genesis_meta(pow_bits)?;
    persist_block(meta_tree, height_tree, block_tree, &genesis)?;
    meta_tree.insert(META_GENESIS_KEY, genesis.hash.as_slice())?;
    flush_native_db_durability_barrier(db, "native genesis bootstrap")?;
    Ok(genesis)
}

fn genesis_meta(pow_bits: u32) -> Result<NativeBlockMeta> {
    let state_root = CommitmentTreeState::default().root();
    let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
    let nullifier_root = nullifier_root_from_set(&BTreeSet::new());
    let timestamp_ms = 0;
    let extrinsics_root = empty_extrinsics_root(0);
    let message_root = empty_bridge_message_root();
    let hash = hash32_with_parts(&[
        b"hegemon-native-genesis-v1",
        &state_root,
        &kernel_root,
        &nullifier_root,
        &extrinsics_root,
        &message_root,
        &pow_bits.to_le_bytes(),
    ]);

    Ok(NativeBlockMeta {
        chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
        height: 0,
        hash,
        parent_hash: [0u8; 32],
        state_root,
        kernel_root,
        nullifier_root,
        extrinsics_root,
        message_root,
        message_count: 0,
        header_mmr_root: empty_header_mmr_root(),
        header_mmr_len: 0,
        timestamp_ms,
        pow_bits,
        nonce: [0u8; 32],
        work_hash: hash,
        cumulative_work: [0u8; 48],
        supply_digest: 0,
        tx_count: 0,
        action_bytes: Vec::new(),
        miner_commitment: [0u8; 48],
        miner_public_key: Vec::new(),
        miner_signature: Vec::new(),
    })
}

fn persist_block(
    meta_tree: &sled::Tree,
    height_tree: &sled::Tree,
    block_tree: &sled::Tree,
    meta: &NativeBlockMeta,
) -> Result<()> {
    persist_block_record(block_tree, meta)?;
    height_tree.insert(height_key(meta.height), meta.hash.as_slice())?;
    meta_tree.insert(META_BEST_KEY, bincode::serialize(meta)?)?;
    meta_tree.flush()?;
    height_tree.flush()?;
    Ok(())
}

fn persist_block_record(block_tree: &sled::Tree, meta: &NativeBlockMeta) -> Result<()> {
    block_tree.insert(meta.hash.as_slice(), bincode::serialize(meta)?)?;
    block_tree.flush()?;
    Ok(())
}

fn load_block_meta_by_hash(
    block_tree: &sled::Tree,
    hash: &[u8; 32],
) -> Result<Option<NativeBlockMeta>> {
    match block_tree.get(hash)? {
        Some(bytes) => {
            let meta =
                bincode_deserialize_native_block_meta_exact(&bytes, "native block metadata")?;
            if meta.hash != *hash {
                return Err(anyhow!(
                    "stored native block hash mismatch: key={} embedded={}",
                    hex32(hash),
                    hex32(&meta.hash)
                ));
            }
            if meta.hash != meta.work_hash {
                return Err(anyhow!(
                    "stored native block work-hash mismatch: hash={} work_hash={}",
                    hex32(&meta.hash),
                    hex32(&meta.work_hash)
                ));
            }
            Ok(Some(meta))
        }
        None => Ok(None),
    }
}

fn load_chain_to_hash(block_tree: &sled::Tree, hash: [u8; 32]) -> Result<Vec<NativeBlockMeta>> {
    let mut chain = Vec::new();
    let mut cursor = hash;
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(cursor) {
            return Err(anyhow!(
                "stored native block parent cycle at {}",
                hex32(&cursor)
            ));
        }
        let meta = load_block_meta_by_hash(block_tree, &cursor)?
            .ok_or_else(|| anyhow!("missing native block {}", hex32(&cursor)))?;
        if meta.hash != cursor {
            return Err(anyhow!(
                "stored native block hash mismatch: key={} embedded={}",
                hex32(&cursor),
                hex32(&meta.hash)
            ));
        }
        let parent = meta.parent_hash;
        let is_genesis = meta.height == 0;
        chain.push(meta);
        if is_genesis {
            break;
        }
        cursor = parent;
    }
    chain.reverse();
    Ok(chain)
}

fn evaluate_native_block_index_reload(
    input: NativeBlockIndexReloadInput,
) -> Result<NativeBlockIndexReloadAdmission, NativeBlockIndexReloadRejection> {
    if !input.chain_reconstructed {
        Err(NativeBlockIndexReloadRejection::ChainReconstructionFailed)
    } else if !input.chain_nonempty {
        Err(NativeBlockIndexReloadRejection::ChainEmpty)
    } else if !input.genesis_matches_expected {
        Err(NativeBlockIndexReloadRejection::GenesisMismatch)
    } else if !input.best_metadata_matches_chain {
        Err(NativeBlockIndexReloadRejection::BestMetadataMismatch)
    } else if !input.canonical_heights_contiguous {
        Err(NativeBlockIndexReloadRejection::CanonicalHeightMismatch)
    } else if !input.canonical_chain_ids_match {
        Err(NativeBlockIndexReloadRejection::ChainIdMismatch)
    } else if !input.canonical_rules_hashes_match {
        Err(NativeBlockIndexReloadRejection::RulesHashMismatch)
    } else if !input.canonical_hashes_match_work_hashes {
        Err(NativeBlockIndexReloadRejection::HashWorkHashMismatch)
    } else if !input.canonical_parent_hashes_contiguous {
        Err(NativeBlockIndexReloadRejection::ParentHashMismatch)
    } else if !input.height_keys_well_formed {
        Err(NativeBlockIndexReloadRejection::MalformedHeightKey)
    } else if !input.height_values_well_formed {
        Err(NativeBlockIndexReloadRejection::MalformedHeightValue)
    } else if !input.no_extra_height_indexes {
        Err(NativeBlockIndexReloadRejection::ExtraHeightIndex)
    } else if !input.height_index_heights_match_chain {
        Err(NativeBlockIndexReloadRejection::HeightIndexMismatch)
    } else if !input.height_index_hashes_match_chain {
        Err(NativeBlockIndexReloadRejection::HeightHashMismatch)
    } else if !input.all_canonical_heights_indexed {
        Err(NativeBlockIndexReloadRejection::MissingHeightIndex)
    } else if !input.genesis_marker_present {
        Ok(NativeBlockIndexReloadAdmission {
            repair_missing_genesis_marker: true,
        })
    } else if !input.genesis_marker_length_valid {
        Err(NativeBlockIndexReloadRejection::GenesisMarkerInvalidLength)
    } else if !input.genesis_marker_matches_expected {
        Err(NativeBlockIndexReloadRejection::GenesisMarkerMismatch)
    } else {
        Ok(NativeBlockIndexReloadAdmission {
            repair_missing_genesis_marker: false,
        })
    }
}

fn native_block_index_reload_error(rejection: NativeBlockIndexReloadRejection) -> anyhow::Error {
    match rejection {
        NativeBlockIndexReloadRejection::ChainReconstructionFailed => anyhow!(
            "stored native canonical chain reconstruction failed ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::ChainEmpty => anyhow!(
            "stored native canonical chain is empty ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::GenesisMismatch => {
            anyhow!("stored native genesis mismatch ({})", rejection.label())
        }
        NativeBlockIndexReloadRejection::BestMetadataMismatch => {
            anyhow!("stored best metadata mismatch ({})", rejection.label())
        }
        NativeBlockIndexReloadRejection::CanonicalHeightMismatch => anyhow!(
            "stored canonical block height mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::ChainIdMismatch => anyhow!(
            "stored canonical block chain id mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::RulesHashMismatch => anyhow!(
            "stored canonical block rules hash mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::HashWorkHashMismatch => anyhow!(
            "stored canonical block hash/work-hash mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::ParentHashMismatch => anyhow!(
            "stored canonical block parent mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::MalformedHeightKey => anyhow!(
            "stored canonical height key has invalid length ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::MalformedHeightValue => anyhow!(
            "stored canonical height value has invalid length ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::ExtraHeightIndex => anyhow!(
            "stored extra canonical height index ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::HeightIndexMismatch => anyhow!(
            "stored canonical height index mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::HeightHashMismatch => anyhow!(
            "stored canonical height hash mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::MissingHeightIndex => anyhow!(
            "stored canonical height index missing ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::GenesisMarkerInvalidLength => anyhow!(
            "stored native genesis marker has invalid length ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::GenesisMarkerMismatch => anyhow!(
            "stored native genesis marker mismatch ({})",
            rejection.label()
        ),
    }
}

fn evaluate_native_canonical_state_reload(
    input: NativeCanonicalStateReloadInput,
) -> Result<(), NativeCanonicalStateReloadRejection> {
    if !input.nullifier_keys_well_formed {
        Err(NativeCanonicalStateReloadRejection::MalformedNullifierKey)
    } else if !input.nullifier_markers_valid {
        Err(NativeCanonicalStateReloadRejection::InvalidNullifierMarker)
    } else if !input.commitment_keys_well_formed {
        Err(NativeCanonicalStateReloadRejection::MalformedCommitmentKey)
    } else if !input.commitment_values_well_formed {
        Err(NativeCanonicalStateReloadRejection::MalformedCommitmentValue)
    } else if !input.commitment_indexes_contiguous {
        Err(NativeCanonicalStateReloadRejection::CommitmentIndexGap)
    } else if !input.commitment_tree_rebuilt {
        Err(NativeCanonicalStateReloadRejection::CommitmentTreeRebuildFailed)
    } else if !input.commitment_root_matches_best {
        Err(NativeCanonicalStateReloadRejection::CommitmentRootMismatch)
    } else if !input.nullifier_root_matches_best {
        Err(NativeCanonicalStateReloadRejection::NullifierRootMismatch)
    } else {
        Ok(())
    }
}

fn native_canonical_state_reload_error(
    rejection: NativeCanonicalStateReloadRejection,
) -> anyhow::Error {
    match rejection {
        NativeCanonicalStateReloadRejection::MalformedNullifierKey => anyhow!(
            "stored nullifier key has invalid length ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::InvalidNullifierMarker => {
            anyhow!("stored nullifier marker is invalid ({})", rejection.label())
        }
        NativeCanonicalStateReloadRejection::MalformedCommitmentKey => anyhow!(
            "stored commitment key has invalid length ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::MalformedCommitmentValue => anyhow!(
            "stored commitment value has invalid length ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::CommitmentIndexGap => anyhow!(
            "stored commitment index is not contiguous ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::CommitmentTreeRebuildFailed => anyhow!(
            "rebuild native commitment tree failed ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::CommitmentRootMismatch => anyhow!(
            "stored commitment tree root mismatch ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::NullifierRootMismatch => {
            anyhow!("stored nullifier root mismatch ({})", rejection.label())
        }
    }
}

fn evaluate_native_bridge_replay_reload(
    input: NativeBridgeReplayReloadInput,
) -> Result<(), NativeBridgeReplayReloadRejection> {
    if !input.replay_keys_well_formed {
        Err(NativeBridgeReplayReloadRejection::MalformedReplayKey)
    } else if !input.replay_markers_valid {
        Err(NativeBridgeReplayReloadRejection::InvalidReplayMarker)
    } else if !input.canonical_replay_keys_unique {
        Err(NativeBridgeReplayReloadRejection::CanonicalReplayDuplicate)
    } else if !input.no_missing_loaded_replay_keys {
        Err(NativeBridgeReplayReloadRejection::MissingConsumedReplayKey)
    } else if !input.no_extra_loaded_replay_keys {
        Err(NativeBridgeReplayReloadRejection::ExtraConsumedReplayKey)
    } else {
        Ok(())
    }
}

fn native_bridge_replay_reload_error(
    rejection: NativeBridgeReplayReloadRejection,
) -> anyhow::Error {
    match rejection {
        NativeBridgeReplayReloadRejection::MalformedReplayKey => anyhow!(
            "stored bridge replay key has invalid length ({})",
            rejection.label()
        ),
        NativeBridgeReplayReloadRejection::InvalidReplayMarker => anyhow!(
            "stored bridge replay marker is invalid ({})",
            rejection.label()
        ),
        NativeBridgeReplayReloadRejection::CanonicalReplayDuplicate => anyhow!(
            "canonical chain contains duplicate inbound bridge replay key ({})",
            rejection.label()
        ),
        NativeBridgeReplayReloadRejection::MissingConsumedReplayKey => anyhow!(
            "stored bridge replay set missing consumed key ({})",
            rejection.label()
        ),
        NativeBridgeReplayReloadRejection::ExtraConsumedReplayKey => anyhow!(
            "stored bridge replay set has extra consumed key ({})",
            rejection.label()
        ),
    }
}

fn evaluate_native_pending_action_reload(
    input: NativePendingActionReloadInput,
) -> Result<(), NativePendingActionReloadRejection> {
    if !input.key_well_formed {
        Err(NativePendingActionReloadRejection::MalformedActionKey)
    } else if !input.embedded_hash_matches_key {
        Err(NativePendingActionReloadRejection::KeyHashMismatch)
    } else if !input.recomputed_hash_matches_embedded {
        Err(NativePendingActionReloadRejection::RecomputedHashMismatch)
    } else if !input.action_hash_unique {
        Err(NativePendingActionReloadRejection::DuplicatePendingAction)
    } else {
        Ok(())
    }
}

fn native_pending_action_reload_error(
    rejection: NativePendingActionReloadRejection,
    hash: Option<[u8; 32]>,
    action: Option<&PendingAction>,
) -> anyhow::Error {
    match rejection {
        NativePendingActionReloadRejection::MalformedActionKey => anyhow!(
            "stored pending action key has invalid length ({})",
            rejection.label()
        ),
        NativePendingActionReloadRejection::KeyHashMismatch => {
            let hash = hash.expect("pending action hash exists after key-shape validation");
            let action = action.expect("pending action exists after decode");
            anyhow!(
                "stored pending action key/hash mismatch: key={} embedded={} ({})",
                hex32(&hash),
                hex32(&action.tx_hash),
                rejection.label()
            )
        }
        NativePendingActionReloadRejection::RecomputedHashMismatch => {
            let hash = hash.expect("pending action hash exists after key-shape validation");
            anyhow!(
                "stored pending action hash mismatch: key={} ({})",
                hex32(&hash),
                rejection.label()
            )
        }
        NativePendingActionReloadRejection::DuplicatePendingAction => {
            let hash = hash.expect("pending action hash exists after key-shape validation");
            anyhow!(
                "duplicate stored pending action {} ({})",
                hex32(&hash),
                rejection.label()
            )
        }
    }
}

fn evaluate_native_staged_ciphertext_reload(
    input: NativeStagedCiphertextReloadInput,
) -> Result<(), NativeStagedCiphertextReloadRejection> {
    if !input.key_well_formed {
        Err(NativeStagedCiphertextReloadRejection::MalformedCiphertextKey)
    } else if !input.ciphertext_within_limit {
        Err(NativeStagedCiphertextReloadRejection::OversizedCiphertext)
    } else if !input.ciphertext_hash_matches_key {
        Err(NativeStagedCiphertextReloadRejection::CiphertextHashMismatch)
    } else if !input.capacity_available {
        Err(NativeStagedCiphertextReloadRejection::StagedCiphertextCapacityReached)
    } else {
        Ok(())
    }
}

fn evaluate_native_staged_proof_reload(
    input: NativeStagedProofReloadInput,
) -> Result<(), NativeStagedProofReloadRejection> {
    if !input.key_well_formed {
        Err(NativeStagedProofReloadRejection::MalformedProofKey)
    } else if !input.proof_nonempty {
        Err(NativeStagedProofReloadRejection::EmptyProof)
    } else if !input.proof_within_limit {
        Err(NativeStagedProofReloadRejection::OversizedProof)
    } else if !input.capacity_available {
        Err(NativeStagedProofReloadRejection::StagedProofCapacityReached)
    } else if !input.byte_capacity_available {
        Err(NativeStagedProofReloadRejection::StagedProofByteCapacityReached)
    } else if !input.proof_binding_hash_matches_key {
        Err(NativeStagedProofReloadRejection::ProofBindingHashMismatch)
    } else {
        Ok(())
    }
}

fn validate_loaded_block_indexes(
    db: &sled::Db,
    best: &NativeBlockMeta,
    meta_tree: &sled::Tree,
    height_tree: &sled::Tree,
    block_tree: &sled::Tree,
    pow_bits: u32,
) -> Result<()> {
    let expected_genesis = genesis_meta(pow_bits)?;
    let chain = load_chain_to_hash(block_tree, best.hash)?;

    let chain_nonempty = !chain.is_empty();
    let genesis_matches_expected = chain
        .first()
        .map(|genesis| genesis == &expected_genesis)
        .unwrap_or(false);
    let best_metadata_matches_chain = chain
        .last()
        .map(|canonical_best| canonical_best == best)
        .unwrap_or(false);
    let mut canonical_heights_contiguous = true;
    let mut canonical_chain_ids_match = true;
    let mut canonical_rules_hashes_match = true;
    let mut canonical_hashes_match_work_hashes = true;
    let mut canonical_parent_hashes_contiguous = true;
    for (index, meta) in chain.iter().enumerate() {
        let expected_height =
            u64::try_from(index).map_err(|_| anyhow!("stored native chain height overflow"))?;
        if meta.height != expected_height {
            canonical_heights_contiguous = false;
        }
        if meta.chain_id != HEGEMON_CHAIN_ID_V1 {
            canonical_chain_ids_match = false;
        }
        if meta.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_V1 {
            canonical_rules_hashes_match = false;
        }
        if meta.hash != meta.work_hash {
            canonical_hashes_match_work_hashes = false;
        }
        if index > 0 {
            let parent = &chain[index - 1];
            if meta.parent_hash != parent.hash {
                canonical_parent_hashes_contiguous = false;
            }
        }
    }

    let mut height_keys_well_formed = true;
    let mut height_values_well_formed = true;
    let mut no_extra_height_indexes = true;
    let mut height_index_heights_match_chain = true;
    let mut height_index_hashes_match_chain = true;
    for item in height_tree.iter() {
        let (key, value) = item?;
        if key.len() != 8 {
            height_keys_well_formed = false;
            continue;
        }
        if value.len() != 32 {
            height_values_well_formed = false;
            continue;
        }
        let mut height_bytes = [0u8; 8];
        height_bytes.copy_from_slice(key.as_ref());
        let height = u64::from_be_bytes(height_bytes);
        let Some(meta) = usize::try_from(height)
            .ok()
            .and_then(|index| chain.get(index))
        else {
            no_extra_height_indexes = false;
            continue;
        };
        if height != meta.height {
            height_index_heights_match_chain = false;
        }
        if value.as_ref() != meta.hash.as_slice() {
            height_index_hashes_match_chain = false;
        }
    }

    let mut all_canonical_heights_indexed = true;
    for meta in &chain {
        match height_tree.get(height_key(meta.height))? {
            Some(bytes) => {
                if bytes.len() != 32 {
                    height_values_well_formed = false;
                } else if bytes.as_ref() != meta.hash.as_slice() {
                    height_index_hashes_match_chain = false;
                }
            }
            None => {
                all_canonical_heights_indexed = false;
            }
        }
    }

    let genesis_marker = meta_tree.get(META_GENESIS_KEY)?;
    let genesis_marker_present = genesis_marker.is_some();
    let mut genesis_marker_length_valid = true;
    let mut genesis_marker_matches_expected = true;
    if let Some(bytes) = genesis_marker.as_ref() {
        genesis_marker_length_valid = bytes.len() == 32;
        genesis_marker_matches_expected =
            genesis_marker_length_valid && bytes.as_ref() == expected_genesis.hash.as_slice();
    }

    let admission = evaluate_native_block_index_reload(NativeBlockIndexReloadInput {
        chain_reconstructed: true,
        chain_nonempty,
        genesis_matches_expected,
        best_metadata_matches_chain,
        canonical_heights_contiguous,
        canonical_chain_ids_match,
        canonical_rules_hashes_match,
        canonical_hashes_match_work_hashes,
        canonical_parent_hashes_contiguous,
        height_keys_well_formed,
        height_values_well_formed,
        no_extra_height_indexes,
        height_index_heights_match_chain,
        height_index_hashes_match_chain,
        all_canonical_heights_indexed,
        genesis_marker_present,
        genesis_marker_length_valid,
        genesis_marker_matches_expected,
    })
    .map_err(native_block_index_reload_error)?;

    if admission.repair_missing_genesis_marker {
        meta_tree.insert(META_GENESIS_KEY, expected_genesis.hash.as_slice())?;
        flush_native_db_durability_barrier(db, "native genesis marker repair")?;
    }
    for index in 0..chain.len() {
        let parent = if index == 0 {
            None
        } else {
            chain.get(index - 1)
        };
        let meta = &chain[index];
        verify_native_block_meta_projection(parent, meta).with_context(|| {
            format!(
                "validate stored canonical native block metadata at height {} ({})",
                meta.height,
                hex32(&meta.hash)
            )
        })?;
    }

    Ok(())
}

fn load_staged_sizes(db: &sled::Db, tree: &sled::Tree) -> Result<BTreeMap<String, u32>> {
    load_staged_sizes_with_limits(
        db,
        tree,
        MAX_NATIVE_STAGED_CIPHERTEXTS,
        MAX_CIPHERTEXT_BYTES,
    )
}

fn load_staged_sizes_with_limits(
    db: &sled::Db,
    tree: &sled::Tree,
    max_staged_count: usize,
    max_ciphertext_bytes: usize,
) -> Result<BTreeMap<String, u32>> {
    let mut entries = BTreeMap::new();
    let mut stale_keys = Vec::new();
    for item in tree.iter() {
        let (key, value) = item?;
        if let Err(rejection) =
            evaluate_native_staged_ciphertext_reload(NativeStagedCiphertextReloadInput {
                key_well_formed: key.len() == 48,
                ciphertext_within_limit: true,
                ciphertext_hash_matches_key: true,
                capacity_available: true,
            })
        {
            debug_assert_eq!(
                rejection,
                NativeStagedCiphertextReloadRejection::MalformedCiphertextKey
            );
            warn!(
                key_len = key.len(),
                "dropping malformed staged ciphertext sidecar key during reload"
            );
            stale_keys.push(key.to_vec());
            continue;
        }

        let mut hash = [0u8; 48];
        hash.copy_from_slice(&key);
        if let Err(rejection) =
            evaluate_native_staged_ciphertext_reload(NativeStagedCiphertextReloadInput {
                key_well_formed: true,
                ciphertext_within_limit: value.len() <= max_ciphertext_bytes,
                ciphertext_hash_matches_key: true,
                capacity_available: true,
            })
        {
            debug_assert_eq!(
                rejection,
                NativeStagedCiphertextReloadRejection::OversizedCiphertext
            );
            warn!(
                hash = %hex48(&hash),
                size = value.len(),
                max = max_ciphertext_bytes,
                "dropping oversized staged ciphertext sidecar during reload"
            );
            stale_keys.push(key.to_vec());
            continue;
        }

        let observed = ciphertext_hash_bytes(&value);
        if let Err(rejection) =
            evaluate_native_staged_ciphertext_reload(NativeStagedCiphertextReloadInput {
                key_well_formed: true,
                ciphertext_within_limit: true,
                ciphertext_hash_matches_key: observed == hash,
                capacity_available: true,
            })
        {
            debug_assert_eq!(
                rejection,
                NativeStagedCiphertextReloadRejection::CiphertextHashMismatch
            );
            warn!(
                key_hash = %hex48(&hash),
                observed_hash = %hex48(&observed),
                "dropping hash-mismatched staged ciphertext sidecar during reload"
            );
            stale_keys.push(key.to_vec());
            continue;
        }

        let capacity_available = evaluate_native_ciphertext_sidecar_capacity_admission(
            NativeSidecarCapacityAdmissionInput {
                staged_count: entries.len(),
                max_staged_count,
                replaces_existing: false,
            },
        )
        .is_ok();
        if let Err(rejection) =
            evaluate_native_staged_ciphertext_reload(NativeStagedCiphertextReloadInput {
                key_well_formed: true,
                ciphertext_within_limit: true,
                ciphertext_hash_matches_key: true,
                capacity_available,
            })
        {
            debug_assert_eq!(
                rejection,
                NativeStagedCiphertextReloadRejection::StagedCiphertextCapacityReached
            );
            warn!(
                hash = %hex48(&hash),
                max = max_staged_count,
                "dropping staged ciphertext sidecar beyond reload capacity"
            );
            stale_keys.push(key.to_vec());
            continue;
        }

        let size = u32::try_from(value.len()).unwrap_or(u32::MAX);
        entries.insert(hex48(&hash), size);
    }
    let removed_stale_entries = !stale_keys.is_empty();
    for key in stale_keys {
        tree.remove(key)?;
    }
    if removed_stale_entries {
        flush_native_db_durability_barrier(db, "native startup staged ciphertext repair")?;
    }
    Ok(entries)
}

fn load_staged_proofs(db: &sled::Db, tree: &sled::Tree) -> Result<BTreeMap<String, Vec<u8>>> {
    load_staged_proofs_with_limits(
        db,
        tree,
        MAX_NATIVE_STAGED_PROOFS,
        NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
        MAX_NATIVE_STAGED_PROOF_BYTES,
    )
}

fn load_staged_proofs_with_limits(
    db: &sled::Db,
    tree: &sled::Tree,
    max_staged_count: usize,
    max_proof_bytes: usize,
    max_total_bytes: usize,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut entries = BTreeMap::new();
    let mut total_bytes = 0usize;
    let mut stale_keys = Vec::new();
    for item in tree.iter() {
        let (key, value) = item?;
        let key_well_formed = key.len() == 64;
        let proof_nonempty = !value.is_empty();
        let proof_within_limit = value.len() <= max_proof_bytes;
        let capacity_available = entries.len() < max_staged_count;
        let next_total_bytes = total_bytes.saturating_add(value.len());
        let byte_capacity_available = next_total_bytes <= max_total_bytes;
        let mut binding_hash = [0u8; 64];
        if key_well_formed {
            binding_hash.copy_from_slice(&key);
        }
        let proof_binding_hash_matches_key = key_well_formed
            && proof_nonempty
            && proof_within_limit
            && capacity_available
            && byte_capacity_available
            && native_tx_leaf_artifact_binding_hash_matches_key(binding_hash, &value);
        if let Err(rejection) = evaluate_native_staged_proof_reload(NativeStagedProofReloadInput {
            key_well_formed,
            proof_nonempty,
            proof_within_limit,
            capacity_available,
            byte_capacity_available,
            proof_binding_hash_matches_key,
        }) {
            match rejection {
                NativeStagedProofReloadRejection::MalformedProofKey => warn!(
                    key_len = key.len(),
                    "dropping malformed staged proof sidecar key during reload"
                ),
                NativeStagedProofReloadRejection::EmptyProof => {
                    warn!("dropping empty staged proof sidecar during reload")
                }
                NativeStagedProofReloadRejection::OversizedProof => warn!(
                    proof_bytes = value.len(),
                    max = max_proof_bytes,
                    "dropping oversized staged proof sidecar during reload"
                ),
                NativeStagedProofReloadRejection::StagedProofCapacityReached => warn!(
                    max = max_staged_count,
                    "dropping staged proof sidecar beyond reload capacity"
                ),
                NativeStagedProofReloadRejection::StagedProofByteCapacityReached => warn!(
                    total_bytes = next_total_bytes,
                    max = max_total_bytes,
                    "dropping staged proof sidecar beyond reload byte capacity"
                ),
                NativeStagedProofReloadRejection::ProofBindingHashMismatch => warn!(
                    binding_hash = %hex64(&binding_hash),
                    "dropping binding-mismatched staged proof sidecar during reload"
                ),
            }
            stale_keys.push(key.to_vec());
            continue;
        }

        total_bytes = next_total_bytes;
        entries.insert(hex64(&binding_hash), value.to_vec());
    }
    let removed_stale_entries = !stale_keys.is_empty();
    for key in stale_keys {
        tree.remove(key)?;
    }
    if removed_stale_entries {
        flush_native_db_durability_barrier(db, "native startup staged proof repair")?;
    }
    Ok(entries)
}

fn load_pending_actions(tree: &sled::Tree) -> Result<BTreeMap<[u8; 32], PendingAction>> {
    let mut actions = BTreeMap::new();
    let mut semantic_hashes = BTreeSet::new();
    for item in tree.iter() {
        let (key, value) = item?;
        if key.len() != 32 {
            return Err(native_pending_action_reload_error(
                evaluate_native_pending_action_reload(NativePendingActionReloadInput {
                    key_well_formed: false,
                    embedded_hash_matches_key: false,
                    recomputed_hash_matches_embedded: false,
                    action_hash_unique: false,
                })
                .expect_err("malformed pending action key must reject"),
                None,
                None,
            ));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&key);
        let action: PendingAction = decode_scale_exact(&value, "pending action")?;
        if action.encode().as_slice() != value.as_ref() {
            return Err(anyhow!(
                "pending action {} has noncanonical SCALE encoding",
                hex32(&hash)
            ));
        }
        validate_loaded_pending_action_hash(hash, &action, !actions.contains_key(&hash))?;
        if !semantic_hashes.insert(pending_action_semantic_hash(&action)) {
            return Err(anyhow!(
                "duplicate semantic stored pending action {}",
                hex32(&hash)
            ));
        }
        actions.insert(hash, action);
    }
    Ok(actions)
}

fn validate_loaded_pending_action_hash(
    hash: [u8; 32],
    action: &PendingAction,
    action_hash_unique: bool,
) -> Result<()> {
    evaluate_native_pending_action_reload(NativePendingActionReloadInput {
        key_well_formed: true,
        embedded_hash_matches_key: action.tx_hash == hash,
        recomputed_hash_matches_embedded: action.tx_hash == pending_action_hash(action),
        action_hash_unique,
    })
    .map_err(|rejection| native_pending_action_reload_error(rejection, Some(hash), Some(action)))
}

fn build_validated_startup_state(
    db: &sled::Db,
    action_tree: &sled::Tree,
    best: NativeBlockMeta,
    pending_actions: BTreeMap<[u8; 32], PendingAction>,
    commitment_tree: CommitmentTreeState,
    nullifiers: BTreeSet<[u8; 48]>,
    consumed_bridge_messages: BTreeSet<[u8; 48]>,
    staged_ciphertexts: BTreeMap<String, u32>,
    staged_proofs: BTreeMap<String, Vec<u8>>,
) -> Result<NativeState> {
    build_validated_startup_state_with_limits(
        db,
        action_tree,
        best,
        pending_actions,
        commitment_tree,
        nullifiers,
        consumed_bridge_messages,
        staged_ciphertexts,
        staged_proofs,
        MAX_NATIVE_MEMPOOL_ACTIONS,
        MAX_NATIVE_MEMPOOL_ACTION_BYTES,
    )
}

fn build_validated_startup_state_with_limits(
    db: &sled::Db,
    action_tree: &sled::Tree,
    best: NativeBlockMeta,
    pending_actions: BTreeMap<[u8; 32], PendingAction>,
    commitment_tree: CommitmentTreeState,
    nullifiers: BTreeSet<[u8; 48]>,
    consumed_bridge_messages: BTreeSet<[u8; 48]>,
    staged_ciphertexts: BTreeMap<String, u32>,
    staged_proofs: BTreeMap<String, Vec<u8>>,
    max_pending_actions: usize,
    max_pending_action_bytes: usize,
) -> Result<NativeState> {
    let mut state = NativeState {
        best,
        pending_actions: BTreeMap::new(),
        commitment_tree,
        nullifiers,
        consumed_bridge_messages,
        staged_ciphertexts,
        staged_proofs,
    };
    let mut dropped_pending = Vec::new();
    for (hash, action) in pending_actions {
        if state.pending_actions.len() >= max_pending_actions {
            dropped_pending.push(hash);
            continue;
        }
        if let Err(err) = validate_startup_pending_action_against_mempool_state(&state, &action) {
            debug!(
                tx_hash = %hex32(&hash),
                error = %err,
                "dropping semantically invalid persisted pending action during startup"
            );
            dropped_pending.push(hash);
            continue;
        }
        if let Err(err) = validate_startup_mempool_byte_budget(
            &state.pending_actions,
            &action,
            max_pending_action_bytes,
        ) {
            debug!(
                tx_hash = %hex32(&hash),
                error = %err,
                "dropping over-budget persisted pending action during startup"
            );
            dropped_pending.push(hash);
            continue;
        }
        state.pending_actions.insert(hash, action);
    }
    if !dropped_pending.is_empty() {
        for hash in dropped_pending {
            action_tree.remove(hash.as_slice()).with_context(|| {
                format!("remove invalid persisted pending action {}", hex32(&hash))
            })?;
        }
        flush_native_db_durability_barrier(db, "native startup pending action repair")?;
    }
    Ok(state)
}

fn validate_startup_pending_action_against_mempool_state(
    state: &NativeState,
    action: &PendingAction,
) -> Result<()> {
    validate_pending_action_against_mempool_state(state, action)
}

fn validate_startup_mempool_byte_budget(
    pending: &BTreeMap<[u8; 32], PendingAction>,
    candidate: &PendingAction,
    max_bytes: usize,
) -> Result<()> {
    validate_mempool_byte_budget(pending, candidate, max_bytes)
}

fn validate_pending_action_against_mempool_state(
    state: &NativeState,
    action: &PendingAction,
) -> Result<()> {
    match evaluate_native_action_scope_admission(native_action_scope_admission_input(action))
        .map_err(native_action_scope_admission_error)?
    {
        NativeActionScopeAdmissionRoute::Bridge => {
            validate_bridge_action_payload(action)?;
            if let Some(replay_key) = bridge_inbound_replay_key_from_action(action)? {
                let mut replay_state = inbound_replay_state_for_mempool(state)?;
                match replay_state.stage(replay_key) {
                    Ok(()) => {}
                    Err(InboundReplayReject::AlreadyConsumed) => {
                        return Err(anyhow!("inbound bridge message already consumed"));
                    }
                    Err(InboundReplayReject::AlreadyPending) => {
                        return Err(anyhow!("inbound bridge message already pending"));
                    }
                }
            }
            Ok(())
        }
        NativeActionScopeAdmissionRoute::CandidateArtifact => {
            validate_candidate_action_payload(action)?;
            Ok(())
        }
        NativeActionScopeAdmissionRoute::Coinbase => {
            validate_coinbase_action_payload(action)?;
            Ok(())
        }
        NativeActionScopeAdmissionRoute::Transfer => {
            validate_transfer_action_payload(action)?;
            let input = native_transfer_state_admission_input_for_mempool(state, action);
            evaluate_native_transfer_state_admission(input).map_err(|rejection| {
                native_transfer_state_admission_error(
                    NativeTransferStateAdmissionContext::Mempool,
                    rejection,
                )
            })?;
            Ok(())
        }
    }
}

fn load_nullifiers(tree: &sled::Tree) -> Result<BTreeSet<[u8; 48]>> {
    let mut nullifiers = BTreeSet::new();
    let mut nullifier_keys_well_formed = true;
    let mut nullifier_markers_valid = true;
    for item in tree.iter() {
        let (key, value) = item?;
        if key.len() != 48 {
            nullifier_keys_well_formed = false;
            continue;
        }
        if value.as_ref() != b"1" {
            nullifier_markers_valid = false;
            continue;
        }

        let mut nullifier = [0u8; 48];
        nullifier.copy_from_slice(&key);
        nullifiers.insert(nullifier);
    }
    evaluate_native_canonical_state_reload(NativeCanonicalStateReloadInput {
        nullifier_keys_well_formed,
        nullifier_markers_valid,
        commitment_keys_well_formed: true,
        commitment_values_well_formed: true,
        commitment_indexes_contiguous: true,
        commitment_tree_rebuilt: true,
        commitment_root_matches_best: true,
        nullifier_root_matches_best: true,
    })
    .map_err(native_canonical_state_reload_error)?;
    Ok(nullifiers)
}

fn load_consumed_bridge_messages(tree: &sled::Tree) -> Result<BTreeSet<[u8; 48]>> {
    let mut consumed = BTreeSet::new();
    let mut replay_keys_well_formed = true;
    let mut replay_markers_valid = true;
    for item in tree.iter() {
        let (key, value) = item?;
        if key.len() != 48 {
            replay_keys_well_formed = false;
            continue;
        }
        if value.as_ref() != b"1" {
            replay_markers_valid = false;
            continue;
        }

        let mut replay_key = [0u8; 48];
        replay_key.copy_from_slice(&key);
        consumed.insert(replay_key);
    }
    evaluate_native_bridge_replay_reload(NativeBridgeReplayReloadInput {
        replay_keys_well_formed,
        replay_markers_valid,
        canonical_replay_keys_unique: true,
        no_missing_loaded_replay_keys: true,
        no_extra_loaded_replay_keys: true,
    })
    .map_err(native_bridge_replay_reload_error)?;
    Ok(consumed)
}

fn load_commitment_tree(tree: &sled::Tree) -> Result<CommitmentTreeState> {
    let mut commitments = Vec::new();
    let mut commitment_keys_well_formed = true;
    let mut commitment_values_well_formed = true;
    let mut commitment_indexes_contiguous = true;
    for item in tree.iter() {
        let (key, value) = item?;
        if key.len() != 8 {
            commitment_keys_well_formed = false;
            continue;
        }
        if value.len() != 48 {
            commitment_values_well_formed = false;
            continue;
        }

        let mut index = [0u8; 8];
        index.copy_from_slice(&key);
        let index = u64::from_be_bytes(index);
        let expected = u64::try_from(commitments.len())
            .map_err(|_| anyhow!("stored commitment count exceeds u64"))?;
        if index != expected {
            commitment_indexes_contiguous = false;
            continue;
        }

        let mut commitment = [0u8; 48];
        commitment.copy_from_slice(&value);
        commitments.push(commitment);
    }
    evaluate_native_canonical_state_reload(NativeCanonicalStateReloadInput {
        nullifier_keys_well_formed: true,
        nullifier_markers_valid: true,
        commitment_keys_well_formed,
        commitment_values_well_formed,
        commitment_indexes_contiguous,
        commitment_tree_rebuilt: true,
        commitment_root_matches_best: true,
        nullifier_root_matches_best: true,
    })
    .map_err(native_canonical_state_reload_error)?;

    match CommitmentTreeState::from_leaves(
        COMMITMENT_TREE_DEPTH,
        consensus::DEFAULT_ROOT_HISTORY_LIMIT,
        commitments,
    ) {
        Ok(state) => Ok(state),
        Err(err) => {
            let rejection =
                evaluate_native_canonical_state_reload(NativeCanonicalStateReloadInput {
                    nullifier_keys_well_formed: true,
                    nullifier_markers_valid: true,
                    commitment_keys_well_formed: true,
                    commitment_values_well_formed: true,
                    commitment_indexes_contiguous: true,
                    commitment_tree_rebuilt: false,
                    commitment_root_matches_best: true,
                    nullifier_root_matches_best: true,
                })
                .expect_err("commitment tree rebuild failure must reject");
            Err(native_canonical_state_reload_error(rejection)
                .context(format!("commitment tree detail: {err}")))
        }
    }
}

fn validate_loaded_canonical_state(
    best: &NativeBlockMeta,
    commitment_state: &CommitmentTreeState,
    nullifiers: &BTreeSet<[u8; 48]>,
) -> Result<()> {
    let commitment_root = commitment_state.root();
    let nullifier_root = nullifier_root_from_set(nullifiers);
    let admission = evaluate_native_canonical_state_reload(NativeCanonicalStateReloadInput {
        nullifier_keys_well_formed: true,
        nullifier_markers_valid: true,
        commitment_keys_well_formed: true,
        commitment_values_well_formed: true,
        commitment_indexes_contiguous: true,
        commitment_tree_rebuilt: true,
        commitment_root_matches_best: commitment_root == best.state_root,
        nullifier_root_matches_best: nullifier_root == best.nullifier_root,
    });
    if let Err(rejection) = admission {
        return match rejection {
            NativeCanonicalStateReloadRejection::CommitmentRootMismatch => Err(anyhow!(
                "stored commitment tree root mismatch: best={} loaded={} leaves={} ({})",
                hex48(&best.state_root),
                hex48(&commitment_root),
                commitment_state.leaf_count(),
                rejection.label()
            )),
            NativeCanonicalStateReloadRejection::NullifierRootMismatch => Err(anyhow!(
                "stored nullifier root mismatch: best={} loaded={} entries={} ({})",
                hex48(&best.nullifier_root),
                hex48(&nullifier_root),
                nullifiers.len(),
                rejection.label()
            )),
            _ => Err(native_canonical_state_reload_error(rejection)),
        };
    }

    Ok(())
}

struct ExpectedBridgeReplayReloadState {
    consumed: BTreeSet<[u8; 48]>,
    duplicate_replay_key: Option<[u8; 48]>,
}

fn expected_consumed_bridge_messages_from_chain(
    chain: &[NativeBlockMeta],
) -> Result<ExpectedBridgeReplayReloadState> {
    let mut consumed = BTreeSet::new();
    let mut duplicate_replay_key = None;
    for meta in chain.iter().skip(1) {
        for action in decode_block_actions(meta)? {
            if let Some(replay_key) = bridge_inbound_replay_key_from_action(&action)? {
                if !consumed.insert(replay_key) && duplicate_replay_key.is_none() {
                    duplicate_replay_key = Some(replay_key);
                }
            }
        }
    }
    Ok(ExpectedBridgeReplayReloadState {
        consumed,
        duplicate_replay_key,
    })
}

fn validate_loaded_bridge_replay_state(
    best: &NativeBlockMeta,
    block_tree: &sled::Tree,
    consumed_bridge_messages: &BTreeSet<[u8; 48]>,
) -> Result<()> {
    let chain = load_chain_to_hash(block_tree, best.hash)?;
    let expected_state = expected_consumed_bridge_messages_from_chain(&chain)?;
    let expected = &expected_state.consumed;
    let missing = expected
        .difference(consumed_bridge_messages)
        .next()
        .copied();
    let extra = consumed_bridge_messages
        .difference(expected)
        .next()
        .copied();
    let admission = evaluate_native_bridge_replay_reload(NativeBridgeReplayReloadInput {
        replay_keys_well_formed: true,
        replay_markers_valid: true,
        canonical_replay_keys_unique: expected_state.duplicate_replay_key.is_none(),
        no_missing_loaded_replay_keys: missing.is_none(),
        no_extra_loaded_replay_keys: extra.is_none(),
    });
    if let Err(rejection) = admission {
        return match rejection {
            NativeBridgeReplayReloadRejection::CanonicalReplayDuplicate => {
                let replay_key = expected_state
                    .duplicate_replay_key
                    .map(|key| hex48(&key))
                    .unwrap_or_else(|| "unknown".to_string());
                Err(anyhow!(
                    "canonical chain contains duplicate inbound bridge replay key {} ({})",
                    replay_key,
                    rejection.label()
                ))
            }
            NativeBridgeReplayReloadRejection::MissingConsumedReplayKey
            | NativeBridgeReplayReloadRejection::ExtraConsumedReplayKey => {
                let missing = missing
                    .as_ref()
                    .map(hex48)
                    .unwrap_or_else(|| "none".to_string());
                let extra = extra
                    .as_ref()
                    .map(hex48)
                    .unwrap_or_else(|| "none".to_string());
                Err(anyhow!(
                    "stored bridge replay set mismatch: expected={} loaded={} first_missing={} first_extra={} ({})",
                    expected.len(),
                    consumed_bridge_messages.len(),
                    missing,
                    extra,
                    rejection.label()
                ))
            }
            _ => Err(native_bridge_replay_reload_error(rejection)),
        };
    }
    Ok(())
}

fn validate_binding_hash(
    anchor: [u8; 48],
    nullifiers: &[[u8; 48]],
    commitments: &[[u8; 48]],
    ciphertext_hashes: &[[u8; 48]],
    balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
    fee: u64,
    binding_hash: [u8; 64],
    stablecoin: Option<protocol_shielded_pool::types::StablecoinPolicyBinding>,
) -> Result<()> {
    if !binding_hash_matches(
        anchor,
        nullifiers,
        commitments,
        ciphertext_hashes,
        balance_slot_asset_ids,
        fee,
        binding_hash,
        stablecoin,
    ) {
        return Err(anyhow!("binding hash mismatch"));
    }
    Ok(())
}

fn binding_hash_matches(
    anchor: [u8; 48],
    nullifiers: &[[u8; 48]],
    commitments: &[[u8; 48]],
    ciphertext_hashes: &[[u8; 48]],
    balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
    fee: u64,
    binding_hash: [u8; 64],
    stablecoin: Option<protocol_shielded_pool::types::StablecoinPolicyBinding>,
) -> bool {
    let inputs = ShieldedTransferInputs {
        anchor,
        nullifiers: nullifiers.to_vec(),
        commitments: commitments.to_vec(),
        ciphertext_hashes: ciphertext_hashes.to_vec(),
        balance_slot_asset_ids,
        fee,
        value_balance: 0,
        stablecoin,
    };
    let expected = StarkVerifier::compute_binding_hash(&inputs).data;
    expected == binding_hash
}

fn native_tx_leaf_artifact_stablecoin_binding(
    decoded: &consensus::backend_interface::NativeTxLeafArtifact,
) -> Result<Option<StablecoinPolicyBinding>> {
    Ok(match decoded.stark_public_inputs.stablecoin_enabled {
        0 => {
            if decoded.stark_public_inputs.stablecoin_asset_id != 0
                || decoded.stark_public_inputs.stablecoin_policy_version != 0
                || decoded.stark_public_inputs.stablecoin_issuance_sign != 0
                || decoded.stark_public_inputs.stablecoin_issuance_magnitude != 0
                || decoded.stark_public_inputs.stablecoin_policy_hash != [0u8; 48]
                || decoded.stark_public_inputs.stablecoin_oracle_commitment != [0u8; 48]
                || decoded
                    .stark_public_inputs
                    .stablecoin_attestation_commitment
                    != [0u8; 48]
            {
                return Err(anyhow!(
                    "disabled native tx-leaf stablecoin public fields must be zero"
                ));
            }
            None
        }
        1 => Some(StablecoinPolicyBinding {
            asset_id: decoded.stark_public_inputs.stablecoin_asset_id,
            policy_hash: decoded.stark_public_inputs.stablecoin_policy_hash,
            oracle_commitment: decoded.stark_public_inputs.stablecoin_oracle_commitment,
            attestation_commitment: decoded
                .stark_public_inputs
                .stablecoin_attestation_commitment,
            issuance_delta: native_tx_leaf_decode_signed_magnitude(
                decoded.stark_public_inputs.stablecoin_issuance_sign,
                decoded.stark_public_inputs.stablecoin_issuance_magnitude,
                "stablecoin_issuance",
            )?,
            policy_version: decoded.stark_public_inputs.stablecoin_policy_version,
        }),
        other => {
            return Err(anyhow!(
                "native tx-leaf stablecoin_enabled flag must be 0 or 1, got {other}"
            ));
        }
    })
}

fn native_tx_leaf_artifact_binding_hash(
    decoded: &consensus::backend_interface::NativeTxLeafArtifact,
) -> Result<[u8; 64]> {
    let balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS] = decoded
        .stark_public_inputs
        .balance_slot_asset_ids
        .clone()
        .try_into()
        .map_err(|slots: Vec<u64>| {
            anyhow!(
                "native tx-leaf balance slot length {} does not match {}",
                slots.len(),
                transaction_core::constants::BALANCE_SLOTS
            )
        })?;
    let stablecoin = native_tx_leaf_artifact_stablecoin_binding(decoded)?;
    let value_balance = native_tx_leaf_decode_signed_magnitude(
        decoded.stark_public_inputs.value_balance_sign,
        decoded.stark_public_inputs.value_balance_magnitude,
        "value_balance",
    )?;
    let inputs = ShieldedTransferInputs {
        anchor: decoded.stark_public_inputs.merkle_root,
        nullifiers: decoded.tx.nullifiers.clone(),
        commitments: decoded.tx.commitments.clone(),
        ciphertext_hashes: decoded.tx.ciphertext_hashes.clone(),
        balance_slot_asset_ids,
        fee: decoded.stark_public_inputs.fee,
        value_balance,
        stablecoin,
    };
    Ok(StarkVerifier::compute_binding_hash(&inputs).data)
}

fn native_tx_leaf_artifact_binding_hash_matches_key(binding_hash: [u8; 64], proof: &[u8]) -> bool {
    consensus::backend_interface::decode_native_tx_leaf_artifact_bytes(proof)
        .and_then(|decoded| native_tx_leaf_artifact_binding_hash(&decoded))
        .is_ok_and(|expected| expected == binding_hash)
}

fn evaluate_native_transfer_payload_admission(
    input: NativeTransferPayloadAdmissionInput,
) -> Result<(), NativeTransferPayloadAdmissionRejection> {
    if input.proof_bytes == 0 {
        Err(NativeTransferPayloadAdmissionRejection::ProofMissing)
    } else if input.proof_bytes > input.max_proof_bytes {
        Err(NativeTransferPayloadAdmissionRejection::ProofTooLarge)
    } else if !input.anchor_matches {
        Err(NativeTransferPayloadAdmissionRejection::AnchorMismatch)
    } else if !input.commitments_match {
        Err(NativeTransferPayloadAdmissionRejection::CommitmentsMismatch)
    } else if input.inline_ciphertext_bytes > input.max_ciphertext_bytes {
        Err(NativeTransferPayloadAdmissionRejection::InlineCiphertextTooLarge)
    } else if !input.ciphertext_hashes_match {
        Err(NativeTransferPayloadAdmissionRejection::CiphertextHashesMismatch)
    } else if !input.ciphertext_sizes_match {
        Err(NativeTransferPayloadAdmissionRejection::CiphertextSizesMismatch)
    } else if !input.binding_hash_matches {
        Err(NativeTransferPayloadAdmissionRejection::BindingHashMismatch)
    } else if !input.proof_binding_hash_matches_key {
        Err(NativeTransferPayloadAdmissionRejection::ProofBindingHashMismatch)
    } else if !input.fee_matches {
        Err(NativeTransferPayloadAdmissionRejection::FeeMismatch)
    } else {
        Ok(())
    }
}

fn native_transfer_payload_admission_error(
    route: NativeTransferPayloadRoute,
    input: NativeTransferPayloadAdmissionInput,
    rejection: NativeTransferPayloadAdmissionRejection,
) -> anyhow::Error {
    let route_label = match route {
        NativeTransferPayloadRoute::Inline => "inline",
        NativeTransferPayloadRoute::Sidecar => "sidecar",
    };
    match rejection {
        NativeTransferPayloadAdmissionRejection::ProofMissing => {
            anyhow!("shielded {route_label} transfer missing proof")
        }
        NativeTransferPayloadAdmissionRejection::ProofTooLarge => anyhow!(
            "shielded {route_label} proof size {} exceeds native tx-leaf artifact limit {}",
            input.proof_bytes,
            input.max_proof_bytes
        ),
        NativeTransferPayloadAdmissionRejection::AnchorMismatch => {
            anyhow!("shielded {route_label} anchor mismatch")
        }
        NativeTransferPayloadAdmissionRejection::CommitmentsMismatch => {
            anyhow!("shielded {route_label} commitments mismatch")
        }
        NativeTransferPayloadAdmissionRejection::InlineCiphertextTooLarge => anyhow!(
            "inline ciphertext size {} exceeds limit {}",
            input.inline_ciphertext_bytes,
            input.max_ciphertext_bytes
        ),
        NativeTransferPayloadAdmissionRejection::CiphertextHashesMismatch => {
            anyhow!("shielded {route_label} ciphertext hashes mismatch")
        }
        NativeTransferPayloadAdmissionRejection::CiphertextSizesMismatch => {
            anyhow!("shielded {route_label} ciphertext sizes mismatch")
        }
        NativeTransferPayloadAdmissionRejection::BindingHashMismatch => {
            anyhow!("binding hash mismatch")
        }
        NativeTransferPayloadAdmissionRejection::ProofBindingHashMismatch => {
            anyhow!("proof binding hash mismatch")
        }
        NativeTransferPayloadAdmissionRejection::FeeMismatch => {
            anyhow!("shielded {route_label} fee mismatch")
        }
    }
}

fn evaluate_native_transfer_state_admission(
    input: NativeTransferStateAdmissionInput,
) -> Result<(), NativeTransferStateAdmissionRejection> {
    if !input.anchor_known {
        Err(NativeTransferStateAdmissionRejection::UnknownAnchor)
    } else {
        match input.nullifier_state {
            NativeTransferNullifierAdmissionState::Valid => {
                if !input.commitments_nonzero {
                    Err(NativeTransferStateAdmissionRejection::CommitmentZero)
                } else if !input.sidecar_route {
                    Ok(())
                } else if !input.sidecar_ciphertexts_available {
                    Err(NativeTransferStateAdmissionRejection::SidecarCiphertextMissing)
                } else if !input.sidecar_ciphertext_sizes_present {
                    Err(NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMissing)
                } else if !input.sidecar_ciphertext_sizes_match {
                    Err(NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMismatch)
                } else {
                    Ok(())
                }
            }
            NativeTransferNullifierAdmissionState::Zero => {
                Err(NativeTransferStateAdmissionRejection::NullifierZero)
            }
            NativeTransferNullifierAdmissionState::AlreadySpent => {
                Err(NativeTransferStateAdmissionRejection::NullifierAlreadySpent)
            }
            NativeTransferNullifierAdmissionState::Duplicate => {
                Err(NativeTransferStateAdmissionRejection::DuplicateNullifier)
            }
            NativeTransferNullifierAdmissionState::AlreadyPending => {
                Err(NativeTransferStateAdmissionRejection::NullifierAlreadyPending)
            }
        }
    }
}

fn native_transfer_state_admission_error(
    context: NativeTransferStateAdmissionContext,
    rejection: NativeTransferStateAdmissionRejection,
) -> anyhow::Error {
    match (context, rejection) {
        (_, NativeTransferStateAdmissionRejection::UnknownAnchor) => match context {
            NativeTransferStateAdmissionContext::Mempool => anyhow!("unknown shielded anchor"),
            NativeTransferStateAdmissionContext::Block => {
                anyhow!("block action references unknown anchor")
            }
        },
        (
            NativeTransferStateAdmissionContext::Mempool,
            NativeTransferStateAdmissionRejection::NullifierZero,
        ) => {
            anyhow!("zero nullifier rejected")
        }
        (
            NativeTransferStateAdmissionContext::Block,
            NativeTransferStateAdmissionRejection::NullifierZero,
        ) => {
            anyhow!("zero nullifier in block action")
        }
        (
            NativeTransferStateAdmissionContext::Mempool,
            NativeTransferStateAdmissionRejection::NullifierAlreadySpent,
        ) => {
            anyhow!("nullifier already spent")
        }
        (
            NativeTransferStateAdmissionContext::Block,
            NativeTransferStateAdmissionRejection::NullifierAlreadySpent,
        ) => {
            anyhow!("duplicate nullifier in block action")
        }
        (
            NativeTransferStateAdmissionContext::Mempool,
            NativeTransferStateAdmissionRejection::DuplicateNullifier,
        ) => {
            anyhow!("duplicate nullifier in action")
        }
        (
            NativeTransferStateAdmissionContext::Block,
            NativeTransferStateAdmissionRejection::DuplicateNullifier,
        ) => {
            anyhow!("duplicate nullifier in block action")
        }
        (
            NativeTransferStateAdmissionContext::Mempool,
            NativeTransferStateAdmissionRejection::NullifierAlreadyPending,
        ) => {
            anyhow!("nullifier already pending")
        }
        (
            NativeTransferStateAdmissionContext::Block,
            NativeTransferStateAdmissionRejection::NullifierAlreadyPending,
        ) => {
            anyhow!("duplicate nullifier in block action")
        }
        (
            NativeTransferStateAdmissionContext::Mempool,
            NativeTransferStateAdmissionRejection::CommitmentZero,
        ) => {
            anyhow!("zero commitment rejected")
        }
        (
            NativeTransferStateAdmissionContext::Block,
            NativeTransferStateAdmissionRejection::CommitmentZero,
        ) => {
            anyhow!("zero commitment in block action")
        }
        (_, NativeTransferStateAdmissionRejection::SidecarCiphertextMissing) => {
            anyhow!("missing staged ciphertext")
        }
        (_, NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMissing) => {
            anyhow!("missing staged ciphertext size")
        }
        (_, NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMismatch) => {
            anyhow!("staged ciphertext size mismatch")
        }
    }
}

fn native_action_state_effect_error(rejection: NativeActionStateEffectRejection) -> anyhow::Error {
    anyhow!("native action state effect rejected: {}", rejection.label())
}

fn evaluate_native_action_state_effect(
    leaf_start: u64,
    commitment_count: usize,
    ciphertext_count: usize,
    nullifiers: &[[u8; 48]],
    replay_key: Option<[u8; 48]>,
    nullifier_state: &mut NullifierState,
    bridge_replay_state: &mut InboundReplayState,
) -> Result<NativeActionStateEffect, NativeActionStateEffectRejection> {
    if commitment_count != ciphertext_count {
        return Err(NativeActionStateEffectRejection::CiphertextCountMismatch);
    }
    let commitment_count_u64 = u64::try_from(commitment_count)
        .map_err(|_| NativeActionStateEffectRejection::CommitmentIndexOverflow)?;
    let next_leaf_count = leaf_start
        .checked_add(commitment_count_u64)
        .ok_or(NativeActionStateEffectRejection::CommitmentIndexOverflow)?;

    for nullifier in nullifiers {
        match nullifier_state.import_one(*nullifier) {
            Ok(()) => {}
            Err(NullifierReject::Zero) => {
                return Err(NativeActionStateEffectRejection::NullifierZero);
            }
            Err(NullifierReject::AlreadySpent | NullifierReject::AlreadyPending) => {
                return Err(NativeActionStateEffectRejection::DuplicateNullifier);
            }
        }
    }

    let imported_bridge_replay = if let Some(replay_key) = replay_key {
        bridge_replay_state
            .import_one(replay_key)
            .map_err(|_| NativeActionStateEffectRejection::BridgeReplayDuplicate)?;
        true
    } else {
        false
    };

    Ok(NativeActionStateEffect {
        next_leaf_count,
        imported_nullifier_count: nullifiers.len(),
        imported_bridge_replay,
    })
}

fn evaluate_native_action_stream_effect<'a>(
    leaf_start: u64,
    steps: impl IntoIterator<Item = NativeActionStreamStep<'a>>,
    nullifier_state: &mut NullifierState,
    bridge_replay_state: &mut InboundReplayState,
) -> Result<NativeActionStreamEffect, NativeActionStateEffectRejection> {
    let mut next_leaf_count = leaf_start;
    let mut imported_nullifier_count = 0usize;
    let mut imported_bridge_replay_count = 0usize;
    let mut planned_starts = Vec::new();

    for step in steps {
        planned_starts.push(next_leaf_count);
        let effect = evaluate_native_action_state_effect(
            next_leaf_count,
            step.commitment_count,
            step.ciphertext_count,
            step.nullifiers,
            step.replay_key,
            nullifier_state,
            bridge_replay_state,
        )?;
        next_leaf_count = effect.next_leaf_count;
        imported_nullifier_count = imported_nullifier_count
            .checked_add(effect.imported_nullifier_count)
            .ok_or(NativeActionStateEffectRejection::CommitmentIndexOverflow)?;
        if effect.imported_bridge_replay {
            imported_bridge_replay_count = imported_bridge_replay_count
                .checked_add(1)
                .ok_or(NativeActionStateEffectRejection::CommitmentIndexOverflow)?;
        }
    }

    Ok(NativeActionStreamEffect {
        next_leaf_count,
        imported_nullifier_count,
        imported_bridge_replay_count,
        planned_starts,
    })
}

fn evaluate_native_action_plan_application_admission(
    leaf_start: u64,
    action_commitment_counts: &[usize],
    planned_starts: &[u64],
) -> Result<NativeActionPlanApplicationSummary, NativeActionPlanApplicationAdmissionRejection> {
    if action_commitment_counts.len() != planned_starts.len() {
        return Err(NativeActionPlanApplicationAdmissionRejection::PlanLengthMismatch);
    }

    let mut next_leaf_count = leaf_start;
    for (commitment_count, planned_start) in action_commitment_counts
        .iter()
        .copied()
        .zip(planned_starts.iter().copied())
    {
        if planned_start != next_leaf_count {
            return Err(NativeActionPlanApplicationAdmissionRejection::PlannedStartMismatch);
        }
        let commitment_count = u64::try_from(commitment_count)
            .map_err(|_| NativeActionPlanApplicationAdmissionRejection::CommitmentIndexOverflow)?;
        next_leaf_count = next_leaf_count
            .checked_add(commitment_count)
            .ok_or(NativeActionPlanApplicationAdmissionRejection::CommitmentIndexOverflow)?;
    }

    Ok(NativeActionPlanApplicationSummary {
        next_leaf_count,
        applied_action_count: action_commitment_counts.len(),
    })
}

fn native_action_plan_application_admission_error(
    context: &'static str,
    rejection: NativeActionPlanApplicationAdmissionRejection,
) -> anyhow::Error {
    anyhow!("{context}: {}", rejection.label())
}

fn action_commitment_counts(actions: &[PendingAction]) -> Vec<usize> {
    actions
        .iter()
        .map(|action| action.commitments.len())
        .collect()
}

fn planned_action_starts(planned: &[NativePlannedActionEffect]) -> Vec<u64> {
    planned
        .iter()
        .map(|effect| effect.commitment_start)
        .collect()
}

fn admit_native_action_plan_application(
    context: &'static str,
    leaf_start: u64,
    actions: &[PendingAction],
    planned: &[NativePlannedActionEffect],
) -> Result<NativeActionPlanApplicationSummary> {
    evaluate_native_action_plan_application_admission(
        leaf_start,
        &action_commitment_counts(actions),
        &planned_action_starts(planned),
    )
    .map_err(|rejection| native_action_plan_application_admission_error(context, rejection))
}

fn evaluate_native_action_wire_replay_projection_admission(
    action_count: usize,
    planned_count: usize,
    steps: &[NativeActionWireReplayProjectionStep],
) -> Result<
    NativeActionWireReplayProjectionSummary,
    NativeActionWireReplayProjectionAdmissionRejection,
> {
    if action_count != planned_count || action_count != steps.len() {
        return Err(NativeActionWireReplayProjectionAdmissionRejection::PlanLengthMismatch);
    }

    let mut projected_ciphertext_row_count = 0usize;
    let mut projected_bridge_replay_row_count = 0usize;
    for step in steps {
        if step.ciphertext_hash_count != step.ciphertext_size_count
            || step.ciphertext_hash_count != step.planned_ciphertext_count
        {
            return Err(
                NativeActionWireReplayProjectionAdmissionRejection::CiphertextCountMismatch,
            );
        }
        if !step.ciphertext_hashes_match {
            return Err(NativeActionWireReplayProjectionAdmissionRejection::CiphertextHashMismatch);
        }
        if !step.ciphertext_sizes_match {
            return Err(NativeActionWireReplayProjectionAdmissionRejection::CiphertextSizeMismatch);
        }
        if !step.replay_key_matches {
            return Err(NativeActionWireReplayProjectionAdmissionRejection::ReplayKeyMismatch);
        }
        projected_ciphertext_row_count = projected_ciphertext_row_count
            .checked_add(step.planned_ciphertext_count)
            .ok_or(NativeActionWireReplayProjectionAdmissionRejection::CiphertextCountMismatch)?;
        if step.planned_replay_present {
            projected_bridge_replay_row_count = projected_bridge_replay_row_count
                .checked_add(1)
                .ok_or(NativeActionWireReplayProjectionAdmissionRejection::ReplayKeyMismatch)?;
        }
    }

    Ok(NativeActionWireReplayProjectionSummary {
        projected_action_count: steps.len(),
        projected_ciphertext_row_count,
        projected_bridge_replay_row_count,
    })
}

fn native_action_wire_replay_projection_admission_error(
    context: &'static str,
    rejection: NativeActionWireReplayProjectionAdmissionRejection,
) -> anyhow::Error {
    anyhow!("{context}: {}", rejection.label())
}

fn native_action_wire_replay_projection_step(
    action: &PendingAction,
    effect: &NativePlannedActionEffect,
) -> Result<NativeActionWireReplayProjectionStep> {
    let ciphertext_counts_match = action.ciphertext_hashes.len() == action.ciphertext_sizes.len()
        && action.ciphertext_hashes.len() == effect.ciphertexts.len();
    let ciphertext_hashes_match = ciphertext_counts_match
        && effect
            .ciphertexts
            .iter()
            .zip(action.ciphertext_hashes.iter())
            .all(|(bytes, expected_hash)| ciphertext_hash_bytes(bytes) == *expected_hash);
    let ciphertext_sizes_match = ciphertext_counts_match
        && effect
            .ciphertexts
            .iter()
            .zip(action.ciphertext_sizes.iter())
            .all(|(bytes, expected_size)| bytes.len() == *expected_size as usize);
    let expected_replay_key = bridge_inbound_replay_key_from_action(action)
        .map_err(|err| anyhow!("decode native action replay key projection failed: {err}"))?;

    Ok(NativeActionWireReplayProjectionStep {
        ciphertext_hash_count: action.ciphertext_hashes.len(),
        ciphertext_size_count: action.ciphertext_sizes.len(),
        planned_ciphertext_count: effect.ciphertexts.len(),
        ciphertext_hashes_match,
        ciphertext_sizes_match,
        planned_replay_present: effect.replay_key.is_some(),
        replay_key_matches: effect.replay_key == expected_replay_key,
    })
}

fn admit_native_action_wire_replay_projection(
    context: &'static str,
    actions: &[PendingAction],
    planned: &[NativePlannedActionEffect],
) -> Result<NativeActionWireReplayProjectionSummary> {
    if actions.len() != planned.len() {
        return Err(native_action_wire_replay_projection_admission_error(
            context,
            NativeActionWireReplayProjectionAdmissionRejection::PlanLengthMismatch,
        ));
    }
    let steps = actions
        .iter()
        .zip(planned.iter())
        .map(|(action, effect)| native_action_wire_replay_projection_step(action, effect))
        .collect::<Result<Vec<_>>>()?;
    evaluate_native_action_wire_replay_projection_admission(actions.len(), planned.len(), &steps)
        .map_err(|rejection| {
            native_action_wire_replay_projection_admission_error(context, rejection)
        })
}

fn mempool_transfer_nullifier_admission_state(
    state: &NativeState,
    action: &PendingAction,
) -> NativeTransferNullifierAdmissionState {
    let mut nullifier_state = shielded_nullifier_state_for_mempool(state);
    let mut action_seen = BTreeSet::new();
    for nullifier in &action.nullifiers {
        let duplicate_in_action = !action_seen.insert(*nullifier);
        match nullifier_state.stage(*nullifier) {
            Ok(()) => {}
            Err(NullifierReject::Zero) => return NativeTransferNullifierAdmissionState::Zero,
            Err(NullifierReject::AlreadySpent) => {
                return NativeTransferNullifierAdmissionState::AlreadySpent;
            }
            Err(NullifierReject::AlreadyPending) if duplicate_in_action => {
                return NativeTransferNullifierAdmissionState::Duplicate;
            }
            Err(NullifierReject::AlreadyPending) => {
                return NativeTransferNullifierAdmissionState::AlreadyPending;
            }
        }
    }
    NativeTransferNullifierAdmissionState::Valid
}

fn block_transfer_nullifier_admission_state(
    nullifier_state: &mut NullifierState,
    action: &PendingAction,
) -> NativeTransferNullifierAdmissionState {
    for nullifier in &action.nullifiers {
        match nullifier_state.import_one(*nullifier) {
            Ok(()) => {}
            Err(NullifierReject::Zero) => return NativeTransferNullifierAdmissionState::Zero,
            Err(NullifierReject::AlreadySpent | NullifierReject::AlreadyPending) => {
                return NativeTransferNullifierAdmissionState::Duplicate;
            }
        }
    }
    NativeTransferNullifierAdmissionState::Valid
}

fn sidecar_ciphertext_state_for_action(
    state: &NativeState,
    action: &PendingAction,
) -> (bool, bool, bool) {
    let mut all_available = true;
    let mut all_sizes_present = true;
    let mut all_sizes_match = true;
    for (idx, hash) in action.ciphertext_hashes.iter().enumerate() {
        let observed = state.staged_ciphertexts.get(&hex48(hash)).copied();
        let expected = action.ciphertext_sizes.get(idx).copied();
        match (observed, expected) {
            (Some(observed), Some(expected)) if observed == expected => {}
            (Some(_), Some(_)) => all_sizes_match = false,
            (Some(_), None) => all_sizes_present = false,
            (None, _) => all_available = false,
        }
    }
    (all_available, all_sizes_present, all_sizes_match)
}

fn native_transfer_state_admission_input_for_mempool(
    state: &NativeState,
    action: &PendingAction,
) -> NativeTransferStateAdmissionInput {
    let sidecar_route = action.family_id == FAMILY_SHIELDED_POOL
        && action.action_id == ACTION_SHIELDED_TRANSFER_SIDECAR;
    let (
        sidecar_ciphertexts_available,
        sidecar_ciphertext_sizes_present,
        sidecar_ciphertext_sizes_match,
    ) = if sidecar_route {
        sidecar_ciphertext_state_for_action(state, action)
    } else {
        (true, true, true)
    };
    NativeTransferStateAdmissionInput {
        anchor_known: state.commitment_tree.contains_root(&action.anchor),
        nullifier_state: mempool_transfer_nullifier_admission_state(state, action),
        commitments_nonzero: action
            .commitments
            .iter()
            .all(|commitment| *commitment != [0u8; 48]),
        sidecar_route,
        sidecar_ciphertexts_available,
        sidecar_ciphertext_sizes_present,
        sidecar_ciphertext_sizes_match,
    }
}

fn native_transfer_state_admission_input_for_block(
    state: &NativeState,
    nullifier_state: &mut NullifierState,
    action: &PendingAction,
) -> NativeTransferStateAdmissionInput {
    NativeTransferStateAdmissionInput {
        anchor_known: state.commitment_tree.contains_root(&action.anchor),
        nullifier_state: block_transfer_nullifier_admission_state(nullifier_state, action),
        commitments_nonzero: action
            .commitments
            .iter()
            .all(|commitment| *commitment != [0u8; 48]),
        sidecar_route: false,
        sidecar_ciphertexts_available: true,
        sidecar_ciphertext_sizes_present: true,
        sidecar_ciphertext_sizes_match: true,
    }
}

fn inline_ciphertext_metadata(
    ciphertexts: &[protocol_shielded_pool::types::EncryptedNote],
) -> (usize, Option<(Vec<[u8; 48]>, Vec<u32>)>) {
    let max_inline_ciphertext_bytes = ciphertexts
        .iter()
        .map(|note| {
            note.ciphertext
                .len()
                .saturating_add(note.kem_ciphertext.len())
        })
        .max()
        .unwrap_or(0);
    if max_inline_ciphertext_bytes > MAX_CIPHERTEXT_BYTES {
        return (max_inline_ciphertext_bytes, None);
    }
    let ciphertext_hashes = ciphertexts
        .iter()
        .map(|note| {
            let total_len = note
                .ciphertext
                .len()
                .saturating_add(note.kem_ciphertext.len());
            let mut bytes = Vec::with_capacity(total_len);
            bytes.extend_from_slice(&note.ciphertext);
            bytes.extend_from_slice(&note.kem_ciphertext);
            ciphertext_hash_bytes(&bytes)
        })
        .collect::<Vec<_>>();
    let ciphertext_sizes = ciphertexts
        .iter()
        .map(|note| {
            u32::try_from(
                note.ciphertext
                    .len()
                    .saturating_add(note.kem_ciphertext.len()),
            )
            .unwrap_or(u32::MAX)
        })
        .collect::<Vec<_>>();
    (
        max_inline_ciphertext_bytes,
        Some((ciphertext_hashes, ciphertext_sizes)),
    )
}

fn validate_transfer_action_payload(action: &PendingAction) -> Result<()> {
    if !is_shielded_transfer_action(action) {
        return Err(anyhow!("action is not a shielded transfer"));
    }
    if action.nullifiers.is_empty() {
        return Err(anyhow!(
            "shielded transfer must include at least one nullifier"
        ));
    }
    if action.nullifiers.len() > transaction_core::constants::MAX_INPUTS {
        return Err(anyhow!("too many nullifiers"));
    }
    if action.commitments.is_empty() {
        return Err(anyhow!(
            "shielded transfer must include at least one commitment"
        ));
    }
    if action.commitments.len() > transaction_core::constants::MAX_OUTPUTS {
        return Err(anyhow!("too many commitments"));
    }
    if action.ciphertext_hashes.len() != action.commitments.len() {
        return Err(anyhow!("ciphertext hash count must match commitments"));
    }
    if action.ciphertext_sizes.len() != action.commitments.len() {
        return Err(anyhow!("ciphertext size count must match commitments"));
    }
    for size in &action.ciphertext_sizes {
        if *size as usize > MAX_CIPHERTEXT_BYTES {
            return Err(anyhow!(
                "ciphertext size {} exceeds limit {}",
                size,
                MAX_CIPHERTEXT_BYTES
            ));
        }
    }

    match action.action_id {
        ACTION_SHIELDED_TRANSFER_INLINE => {
            let args: ShieldedTransferInlineArgs =
                decode_scale_exact(&action.public_args, "shielded inline action args")?;
            let (inline_ciphertext_bytes, inline_metadata) =
                inline_ciphertext_metadata(&args.ciphertexts);
            let (ciphertext_hashes, ciphertext_sizes) = inline_metadata
                .clone()
                .unwrap_or_else(|| (Vec::new(), Vec::new()));
            let input = NativeTransferPayloadAdmissionInput {
                proof_bytes: args.proof.len(),
                max_proof_bytes: NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
                anchor_matches: args.anchor == action.anchor,
                commitments_match: args.commitments == action.commitments,
                inline_ciphertext_bytes,
                max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES,
                ciphertext_hashes_match: inline_metadata.is_some()
                    && ciphertext_hashes == action.ciphertext_hashes,
                ciphertext_sizes_match: inline_metadata.is_some()
                    && ciphertext_sizes == action.ciphertext_sizes,
                binding_hash_matches: inline_metadata.as_ref().is_some_and(
                    |(ciphertext_hashes, _)| {
                        binding_hash_matches(
                            args.anchor,
                            &action.nullifiers,
                            &args.commitments,
                            ciphertext_hashes,
                            args.balance_slot_asset_ids,
                            args.fee,
                            args.binding_hash,
                            args.stablecoin,
                        )
                    },
                ),
                proof_binding_hash_matches_key: native_tx_leaf_artifact_binding_hash_matches_key(
                    args.binding_hash,
                    &args.proof,
                ),
                fee_matches: args.fee == action.fee,
            };
            evaluate_native_transfer_payload_admission(input).map_err(|rejection| {
                native_transfer_payload_admission_error(
                    NativeTransferPayloadRoute::Inline,
                    input,
                    rejection,
                )
            })?;
        }
        ACTION_SHIELDED_TRANSFER_SIDECAR => {
            let args: ShieldedTransferSidecarArgs =
                decode_scale_exact(&action.public_args, "shielded sidecar action args")?;
            let input = NativeTransferPayloadAdmissionInput {
                proof_bytes: args.proof.len(),
                max_proof_bytes: NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
                anchor_matches: args.anchor == action.anchor,
                commitments_match: args.commitments == action.commitments,
                inline_ciphertext_bytes: 0,
                max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES,
                ciphertext_hashes_match: args.ciphertext_hashes == action.ciphertext_hashes,
                ciphertext_sizes_match: args.ciphertext_sizes == action.ciphertext_sizes,
                binding_hash_matches: binding_hash_matches(
                    args.anchor,
                    &action.nullifiers,
                    &args.commitments,
                    &args.ciphertext_hashes,
                    args.balance_slot_asset_ids,
                    args.fee,
                    args.binding_hash,
                    args.stablecoin,
                ),
                proof_binding_hash_matches_key: native_tx_leaf_artifact_binding_hash_matches_key(
                    args.binding_hash,
                    &args.proof,
                ),
                fee_matches: args.fee == action.fee,
            };
            evaluate_native_transfer_payload_admission(input).map_err(|rejection| {
                native_transfer_payload_admission_error(
                    NativeTransferPayloadRoute::Sidecar,
                    input,
                    rejection,
                )
            })?;
        }
        _ => unreachable!("transfer action checked above"),
    }

    Ok(())
}

fn validate_candidate_artifact(artifact: &CandidateArtifact) -> Result<()> {
    let input = native_candidate_artifact_admission_input(true, Some(artifact));
    evaluate_native_candidate_artifact_admission(input)
        .map_err(|rejection| native_candidate_artifact_admission_error(input, rejection))
}

fn validate_candidate_action_payload(action: &PendingAction) -> Result<()> {
    if !is_candidate_artifact_action(action) {
        return Err(anyhow!("not a candidate artifact action"));
    }
    let input = native_candidate_artifact_admission_input(
        candidate_action_has_no_state_deltas(action),
        action.candidate_artifact.as_ref(),
    );
    evaluate_native_candidate_artifact_admission(input)
        .map_err(|rejection| native_candidate_artifact_admission_error(input, rejection))
}

fn candidate_action_has_no_state_deltas(action: &PendingAction) -> bool {
    action.nullifiers.is_empty()
        && action.commitments.is_empty()
        && action.ciphertext_hashes.is_empty()
        && action.ciphertext_sizes.is_empty()
        && action.fee == 0
        && action.anchor == [0u8; 48]
}

fn native_candidate_artifact_admission_input(
    state_deltas_absent: bool,
    artifact: Option<&CandidateArtifact>,
) -> NativeCandidateArtifactAdmissionInput {
    let Some(artifact) = artifact else {
        return NativeCandidateArtifactAdmissionInput {
            state_deltas_absent,
            artifact_present: false,
            schema_matches: false,
            tx_count: 0,
            max_tx_count: MAX_BATCH_SIZE,
            da_chunk_count: 0,
            proof_mode_recursive_block: false,
            proof_kind_recursive_block_v2: false,
            verifier_profile_matches: false,
            commitment_proof_empty: false,
            receipt_root_absent: false,
            recursive_payload_present: false,
            recursive_proof_bytes: 0,
            max_recursive_proof_bytes: RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE,
        };
    };
    NativeCandidateArtifactAdmissionInput {
        state_deltas_absent,
        artifact_present: true,
        schema_matches: artifact.version == BLOCK_PROOF_BUNDLE_SCHEMA,
        tx_count: artifact.tx_count,
        max_tx_count: MAX_BATCH_SIZE,
        da_chunk_count: artifact.da_chunk_count,
        proof_mode_recursive_block: artifact.proof_mode == BlockProofMode::RecursiveBlock,
        proof_kind_recursive_block_v2: artifact.proof_kind
            == PoolProofArtifactKind::RecursiveBlockV2,
        verifier_profile_matches: artifact.verifier_profile
            == consensus::proof::recursive_block_artifact_verifier_profile(),
        commitment_proof_empty: artifact.commitment_proof.data.is_empty(),
        receipt_root_absent: artifact.receipt_root.is_none(),
        recursive_payload_present: artifact.recursive_block.is_some(),
        recursive_proof_bytes: artifact
            .recursive_block
            .as_ref()
            .map_or(0, |recursive| recursive.proof.data.len()),
        max_recursive_proof_bytes: RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE,
    }
}

fn evaluate_native_candidate_artifact_admission(
    input: NativeCandidateArtifactAdmissionInput,
) -> Result<(), NativeCandidateArtifactAdmissionRejection> {
    if !input.state_deltas_absent {
        Err(NativeCandidateArtifactAdmissionRejection::StateDeltasPresent)
    } else if !input.artifact_present {
        Err(NativeCandidateArtifactAdmissionRejection::ArtifactMissing)
    } else if !input.schema_matches {
        Err(NativeCandidateArtifactAdmissionRejection::SchemaMismatch)
    } else if input.tx_count == 0 {
        Err(NativeCandidateArtifactAdmissionRejection::TxCountZero)
    } else if input.tx_count > input.max_tx_count {
        Err(NativeCandidateArtifactAdmissionRejection::TxCountTooLarge)
    } else if input.da_chunk_count == 0 {
        Err(NativeCandidateArtifactAdmissionRejection::DaChunkCountZero)
    } else if !input.proof_mode_recursive_block {
        Err(NativeCandidateArtifactAdmissionRejection::WrongProofMode)
    } else if !input.proof_kind_recursive_block_v2 {
        Err(NativeCandidateArtifactAdmissionRejection::WrongProofKind)
    } else if !input.verifier_profile_matches {
        Err(NativeCandidateArtifactAdmissionRejection::VerifierProfileMismatch)
    } else if !input.commitment_proof_empty {
        Err(NativeCandidateArtifactAdmissionRejection::CommitmentProofPresent)
    } else if !input.receipt_root_absent {
        Err(NativeCandidateArtifactAdmissionRejection::ReceiptRootPresent)
    } else if !input.recursive_payload_present {
        Err(NativeCandidateArtifactAdmissionRejection::RecursivePayloadMissing)
    } else if input.recursive_proof_bytes == 0 {
        Err(NativeCandidateArtifactAdmissionRejection::RecursiveProofEmpty)
    } else if input.recursive_proof_bytes > input.max_recursive_proof_bytes {
        Err(NativeCandidateArtifactAdmissionRejection::RecursiveProofTooLarge)
    } else {
        Ok(())
    }
}

fn native_candidate_artifact_admission_error(
    input: NativeCandidateArtifactAdmissionInput,
    rejection: NativeCandidateArtifactAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeCandidateArtifactAdmissionRejection::StateDeltasPresent => {
            anyhow!("candidate artifact actions must not carry shielded state deltas")
        }
        NativeCandidateArtifactAdmissionRejection::ArtifactMissing => {
            anyhow!("candidate artifact action missing payload")
        }
        NativeCandidateArtifactAdmissionRejection::SchemaMismatch => {
            anyhow!("candidate artifact schema mismatch")
        }
        NativeCandidateArtifactAdmissionRejection::TxCountZero => {
            anyhow!("candidate artifact tx_count must be non-zero")
        }
        NativeCandidateArtifactAdmissionRejection::TxCountTooLarge => anyhow!(
            "candidate artifact tx_count {} exceeds max {}",
            input.tx_count,
            input.max_tx_count
        ),
        NativeCandidateArtifactAdmissionRejection::DaChunkCountZero => {
            anyhow!("candidate artifact must declare DA chunks")
        }
        NativeCandidateArtifactAdmissionRejection::WrongProofMode => {
            anyhow!("native cutover requires recursive block artifacts")
        }
        NativeCandidateArtifactAdmissionRejection::WrongProofKind => {
            anyhow!("native candidate artifact must use the shipped recursive_block_v2 route")
        }
        NativeCandidateArtifactAdmissionRejection::VerifierProfileMismatch => {
            anyhow!("native candidate artifact recursive_block_v2 verifier profile mismatch")
        }
        NativeCandidateArtifactAdmissionRejection::CommitmentProofPresent => {
            anyhow!("recursive candidate artifact must not carry commitment proof bytes")
        }
        NativeCandidateArtifactAdmissionRejection::ReceiptRootPresent => {
            anyhow!("recursive candidate artifact must not carry receipt-root payload")
        }
        NativeCandidateArtifactAdmissionRejection::RecursivePayloadMissing => {
            anyhow!("candidate artifact missing recursive proof payload")
        }
        NativeCandidateArtifactAdmissionRejection::RecursiveProofEmpty => {
            anyhow!("candidate artifact recursive proof is empty")
        }
        NativeCandidateArtifactAdmissionRejection::RecursiveProofTooLarge => anyhow!(
            "candidate artifact recursive proof size {} exceeds {}",
            input.recursive_proof_bytes,
            input.max_recursive_proof_bytes
        ),
    }
}

fn coinbase_ciphertext_metadata(
    note: &protocol_shielded_pool::types::EncryptedNote,
) -> (usize, Option<([u8; 48], u32)>) {
    let total_len = note
        .ciphertext
        .len()
        .saturating_add(note.kem_ciphertext.len());
    if total_len > MAX_CIPHERTEXT_BYTES {
        return (total_len, None);
    }
    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(&note.ciphertext);
    bytes.extend_from_slice(&note.kem_ciphertext);
    (
        total_len,
        Some((
            ciphertext_hash_bytes(&bytes),
            u32::try_from(total_len).unwrap_or(u32::MAX),
        )),
    )
}

fn coinbase_recipient_address_bytes(address: &ShieldedAddress) -> [u8; DIVERSIFIED_ADDRESS_SIZE] {
    let mut out = [0u8; DIVERSIFIED_ADDRESS_SIZE];
    out[0] = address.version;
    out[1..5].copy_from_slice(&address.diversifier_index.to_le_bytes());
    out[5..37].copy_from_slice(&address.pk_recipient);
    out[37..69].copy_from_slice(&address.pk_auth);
    out
}

fn coinbase_note_data_commitment(note: &CoinbaseNoteData) -> [u8; 48] {
    let mut pk_recipient = [0u8; 32];
    pk_recipient.copy_from_slice(&note.recipient_address[5..37]);
    let mut pk_auth = [0u8; 32];
    pk_auth.copy_from_slice(&note.recipient_address[37..69]);
    let note_plaintext = NotePlaintext::coinbase(note.amount, &note.public_seed);
    felts_to_bytes48(
        &note_plaintext
            .to_note_data(pk_recipient, pk_auth)
            .commitment(),
    )
}

fn coinbase_note_commitment_matches(action_commitment: &[u8; 48], note: &CoinbaseNoteData) -> bool {
    *action_commitment == note.commitment && note.commitment == coinbase_note_data_commitment(note)
}

fn evaluate_native_coinbase_action_payload_admission(
    input: NativeCoinbaseActionPayloadAdmissionInput,
) -> Result<(), NativeCoinbaseActionPayloadAdmissionRejection> {
    if !input.amount_nonzero {
        Err(NativeCoinbaseActionPayloadAdmissionRejection::AmountZero)
    } else if !input.commitment_matches {
        Err(NativeCoinbaseActionPayloadAdmissionRejection::CommitmentMismatch)
    } else if !input.commitment_nonzero {
        Err(NativeCoinbaseActionPayloadAdmissionRejection::CommitmentZero)
    } else if input.ciphertext_bytes > input.max_ciphertext_bytes {
        Err(NativeCoinbaseActionPayloadAdmissionRejection::CiphertextTooLarge)
    } else if !input.ciphertext_hash_matches {
        Err(NativeCoinbaseActionPayloadAdmissionRejection::CiphertextHashMismatch)
    } else if !input.ciphertext_size_matches {
        Err(NativeCoinbaseActionPayloadAdmissionRejection::CiphertextSizeMismatch)
    } else {
        Ok(())
    }
}

fn native_coinbase_action_payload_admission_error(
    input: NativeCoinbaseActionPayloadAdmissionInput,
    rejection: NativeCoinbaseActionPayloadAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeCoinbaseActionPayloadAdmissionRejection::AmountZero => {
            anyhow!("coinbase amount must be non-zero")
        }
        NativeCoinbaseActionPayloadAdmissionRejection::CommitmentMismatch => {
            anyhow!("coinbase commitment mismatch")
        }
        NativeCoinbaseActionPayloadAdmissionRejection::CommitmentZero => {
            anyhow!("zero coinbase commitment rejected")
        }
        NativeCoinbaseActionPayloadAdmissionRejection::CiphertextTooLarge => anyhow!(
            "coinbase ciphertext size {} exceeds limit {}",
            input.ciphertext_bytes,
            input.max_ciphertext_bytes
        ),
        NativeCoinbaseActionPayloadAdmissionRejection::CiphertextHashMismatch => {
            anyhow!("coinbase ciphertext hash mismatch")
        }
        NativeCoinbaseActionPayloadAdmissionRejection::CiphertextSizeMismatch => {
            anyhow!("coinbase ciphertext size mismatch")
        }
    }
}

fn validate_coinbase_action_payload(action: &PendingAction) -> Result<()> {
    if !is_coinbase_action(action) {
        return Err(anyhow!("not a coinbase action"));
    }
    if !action.nullifiers.is_empty()
        || action.commitments.len() != 1
        || action.ciphertext_hashes.len() != 1
        || action.ciphertext_sizes.len() != 1
        || action.fee != 0
        || action.anchor != [0u8; 48]
        || action.candidate_artifact.is_some()
    {
        return Err(anyhow!(
            "coinbase action must contain exactly one output and no other state deltas"
        ));
    }
    let args: MintCoinbaseArgs = decode_scale_exact(&action.public_args, "coinbase action args")?;
    let note = &args.reward_bundle.miner_note.encrypted_note;
    let (ciphertext_bytes, ciphertext_metadata) = coinbase_ciphertext_metadata(note);
    let commitment_matches = action.commitments.first().is_some_and(|commitment| {
        coinbase_note_commitment_matches(commitment, &args.reward_bundle.miner_note)
    });
    let input = NativeCoinbaseActionPayloadAdmissionInput {
        amount_nonzero: args.reward_bundle.miner_note.amount != 0,
        commitment_matches,
        commitment_nonzero: action
            .commitments
            .first()
            .is_some_and(|commitment| *commitment != [0u8; 48]),
        ciphertext_bytes,
        max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES,
        ciphertext_hash_matches: ciphertext_metadata
            .as_ref()
            .is_some_and(|(hash, _)| action.ciphertext_hashes.first() == Some(hash)),
        ciphertext_size_matches: ciphertext_metadata
            .as_ref()
            .is_some_and(|(_, size)| action.ciphertext_sizes.first() == Some(size)),
    };
    evaluate_native_coinbase_action_payload_admission(input)
        .map_err(|rejection| native_coinbase_action_payload_admission_error(input, rejection))
}

fn pending_action_hash(action: &PendingAction) -> [u8; 32] {
    let mut canonical = action.clone();
    canonical.tx_hash = [0u8; 32];
    let encoded = canonical.encode();
    hash32_with_parts(&[b"hegemon-native-action-v1", &encoded])
}

fn pending_action_semantic_hash(action: &PendingAction) -> [u8; 32] {
    let mut canonical = action.clone();
    canonical.tx_hash = [0u8; 32];
    canonical.received_ms = 0;
    let encoded = canonical.encode();
    hash32_with_parts(&[b"hegemon-native-action-semantic-v1", &encoded])
}

fn pending_action_semantic_duplicate_exists(
    actions: &BTreeMap<[u8; 32], PendingAction>,
    candidate: &PendingAction,
) -> bool {
    let candidate_hash = pending_action_semantic_hash(candidate);
    actions
        .values()
        .any(|action| pending_action_semantic_hash(action) == candidate_hash)
}

fn pending_action_mempool_bytes(action: &PendingAction) -> usize {
    action.encoded_size()
}

fn pending_mempool_bytes(actions: &BTreeMap<[u8; 32], PendingAction>) -> usize {
    actions.values().fold(0usize, |acc, action| {
        acc.saturating_add(pending_action_mempool_bytes(action))
    })
}

fn validate_mempool_byte_budget(
    actions: &BTreeMap<[u8; 32], PendingAction>,
    candidate: &PendingAction,
    max_bytes: usize,
) -> Result<()> {
    let input = NativeMempoolByteBudgetAdmissionInput {
        pending_bytes: pending_mempool_bytes(actions),
        candidate_bytes: pending_action_mempool_bytes(candidate),
        max_bytes,
    };
    evaluate_native_mempool_byte_budget_admission(input).map_err(|rejection| {
        native_resource_budget_admission_error(
            input.pending_bytes,
            input.candidate_bytes,
            input.max_bytes,
            rejection,
        )
    })?;
    Ok(())
}

fn staged_proof_bytes(proofs: &BTreeMap<String, Vec<u8>>) -> usize {
    proofs
        .values()
        .fold(0usize, |acc, proof| acc.saturating_add(proof.len()))
}

fn validate_staged_proof_byte_budget(
    staged: &BTreeMap<String, Vec<u8>>,
    binding_hash_key: &str,
    proof_len: usize,
    max_bytes: usize,
) -> Result<()> {
    let input = NativeStagedProofByteBudgetAdmissionInput {
        staged_bytes: staged_proof_bytes(staged),
        existing_bytes: staged
            .get(binding_hash_key)
            .map(Vec::len)
            .unwrap_or_default(),
        proof_bytes: proof_len,
        max_bytes,
    };
    evaluate_native_staged_proof_byte_budget_admission(input).map_err(|rejection| {
        native_resource_budget_admission_error(
            input.staged_bytes.saturating_sub(input.existing_bytes),
            input.proof_bytes,
            input.max_bytes,
            rejection,
        )
    })?;
    Ok(())
}

fn evaluate_native_mempool_byte_budget_admission(
    input: NativeMempoolByteBudgetAdmissionInput,
) -> Result<usize, NativeResourceBudgetAdmissionRejection> {
    let total = input.pending_bytes.saturating_add(input.candidate_bytes);
    if total > input.max_bytes {
        Err(NativeResourceBudgetAdmissionRejection::MempoolByteBudgetExceeded)
    } else {
        Ok(total)
    }
}

fn evaluate_native_staged_proof_byte_budget_admission(
    input: NativeStagedProofByteBudgetAdmissionInput,
) -> Result<usize, NativeResourceBudgetAdmissionRejection> {
    let total = input
        .staged_bytes
        .saturating_sub(input.existing_bytes)
        .saturating_add(input.proof_bytes);
    if total > input.max_bytes {
        Err(NativeResourceBudgetAdmissionRejection::StagedProofByteBudgetExceeded)
    } else {
        Ok(total)
    }
}

fn native_resource_budget_admission_error(
    current_bytes: usize,
    candidate_bytes: usize,
    max_bytes: usize,
    rejection: NativeResourceBudgetAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeResourceBudgetAdmissionRejection::MempoolByteBudgetExceeded => anyhow!(
            "native mempool byte budget exceeded: {} + {} > {}",
            current_bytes,
            candidate_bytes,
            max_bytes
        ),
        NativeResourceBudgetAdmissionRejection::StagedProofByteBudgetExceeded => anyhow!(
            "staged proof byte budget exceeded: {} + {} > {}",
            current_bytes,
            candidate_bytes,
            max_bytes
        ),
    }
}

fn native_sync_response_range(input: NativeSyncResponseRangeInput) -> Option<NativeSyncRange> {
    if input.max_blocks == 0 {
        return None;
    }
    let capped_to = input
        .to_height
        .min(input.best_height)
        .min(input.from_height.saturating_add(input.max_blocks - 1));
    (input.from_height <= capped_to).then_some(NativeSyncRange {
        from_height: input.from_height,
        to_height: capped_to,
    })
}

fn native_sync_missing_request_range(
    input: NativeSyncMissingRequestInput,
) -> Option<NativeSyncRange> {
    if input.max_blocks == 0 || input.announced_height <= input.best_height {
        return None;
    }
    let from_height = input.best_height.saturating_add(1);
    let cap_end = input
        .best_height
        .saturating_add(input.max_blocks)
        .max(from_height);
    Some(NativeSyncRange {
        from_height,
        to_height: input.announced_height.min(cap_end),
    })
}

fn evaluate_native_sync_response_count_admission(
    input: NativeSyncResponseCountAdmissionInput,
) -> Result<(), NativeSyncAdmissionRejection> {
    if input.block_count > input.max_blocks {
        Err(NativeSyncAdmissionRejection::ResponseBlockCountTooLarge)
    } else {
        Ok(())
    }
}

fn evaluate_native_ciphertext_sidecar_request_admission(
    input: NativeSidecarRequestCountAdmissionInput,
) -> Result<(), NativeSidecarUploadAdmissionRejection> {
    if input.item_count > input.max_items {
        Err(NativeSidecarUploadAdmissionRejection::TooManyCiphertexts)
    } else {
        Ok(())
    }
}

fn evaluate_native_proof_sidecar_request_admission(
    input: NativeSidecarRequestCountAdmissionInput,
) -> Result<(), NativeSidecarUploadAdmissionRejection> {
    if input.item_count > input.max_items {
        Err(NativeSidecarUploadAdmissionRejection::TooManyProofs)
    } else {
        Ok(())
    }
}

fn evaluate_native_ciphertext_sidecar_capacity_admission(
    input: NativeSidecarCapacityAdmissionInput,
) -> Result<(), NativeSidecarUploadAdmissionRejection> {
    if !input.replaces_existing && input.staged_count >= input.max_staged_count {
        Err(NativeSidecarUploadAdmissionRejection::StagedCiphertextCapacityReached)
    } else {
        Ok(())
    }
}

fn evaluate_native_proof_sidecar_capacity_admission(
    input: NativeSidecarCapacityAdmissionInput,
) -> Result<(), NativeSidecarUploadAdmissionRejection> {
    if !input.replaces_existing && input.staged_count >= input.max_staged_count {
        Err(NativeSidecarUploadAdmissionRejection::StagedProofCapacityReached)
    } else {
        Ok(())
    }
}

fn evaluate_native_proof_sidecar_metadata_admission(
    input: NativeProofSidecarMetadataAdmissionInput,
) -> Result<(), NativeSidecarUploadAdmissionRejection> {
    if !input.binding_hash_present {
        Err(NativeSidecarUploadAdmissionRejection::ProofBindingHashMissing)
    } else if !input.binding_hash_valid {
        Err(NativeSidecarUploadAdmissionRejection::InvalidBindingHash)
    } else if !input.proof_present {
        Err(NativeSidecarUploadAdmissionRejection::ProofMissing)
    } else {
        Ok(())
    }
}

fn evaluate_native_proof_sidecar_decoded_admission(
    input: NativeProofSidecarDecodedAdmissionInput,
) -> Result<(), NativeSidecarUploadAdmissionRejection> {
    if input.proof_bytes == 0 {
        Err(NativeSidecarUploadAdmissionRejection::ProofEmpty)
    } else if input.proof_bytes > input.max_proof_bytes {
        Err(NativeSidecarUploadAdmissionRejection::ProofTooLarge)
    } else if !input.proof_binding_hash_matches_key {
        Err(NativeSidecarUploadAdmissionRejection::ProofBindingHashMismatch)
    } else {
        Ok(())
    }
}

fn native_sidecar_upload_admission_error(
    rejection: NativeSidecarUploadAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeSidecarUploadAdmissionRejection::TooManyCiphertexts => anyhow!(
            "too many ciphertexts in one request: exceeds {}",
            MAX_NATIVE_DA_CIPHERTEXT_UPLOADS
        ),
        NativeSidecarUploadAdmissionRejection::TooManyProofs => anyhow!(
            "too many proofs in one request: exceeds {}",
            MAX_NATIVE_DA_PROOF_UPLOADS
        ),
        NativeSidecarUploadAdmissionRejection::StagedCiphertextCapacityReached => anyhow!(
            "staged ciphertext capacity reached: {}",
            MAX_NATIVE_STAGED_CIPHERTEXTS
        ),
        NativeSidecarUploadAdmissionRejection::StagedProofCapacityReached => {
            anyhow!(
                "staged proof capacity reached: {}",
                MAX_NATIVE_STAGED_PROOFS
            )
        }
        NativeSidecarUploadAdmissionRejection::ProofBindingHashMissing => {
            anyhow!("proof item missing binding_hash")
        }
        NativeSidecarUploadAdmissionRejection::InvalidBindingHash => {
            anyhow!("invalid binding_hash hex")
        }
        NativeSidecarUploadAdmissionRejection::ProofMissing => {
            anyhow!("proof item missing proof")
        }
        NativeSidecarUploadAdmissionRejection::ProofEmpty => {
            anyhow!("proof item proof must be non-empty")
        }
        NativeSidecarUploadAdmissionRejection::ProofTooLarge => anyhow!(
            "proof size exceeds native tx-leaf artifact limit {}",
            NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE
        ),
        NativeSidecarUploadAdmissionRejection::ProofBindingHashMismatch => {
            anyhow!("proof binding hash does not match native tx-leaf public fields")
        }
    }
}

fn ordered_pending_actions(state: &NativeState) -> Vec<PendingAction> {
    let mut actions = state.pending_actions.values().cloned().collect::<Vec<_>>();
    actions.sort_by_key(action_order_key);
    actions
}

fn select_mineable_actions(state: &NativeState) -> Vec<PendingAction> {
    let actions = ordered_pending_actions(state);
    let transfer_count = actions
        .iter()
        .filter(|action| is_shielded_transfer_action(action))
        .filter(|action| {
            let input = native_mineable_action_admission_input(state, action, None);
            evaluate_native_mineable_action_admission(input).is_ok()
        })
        .count();
    let selected_candidate_hash = if transfer_count == 0 {
        None
    } else {
        actions
            .iter()
            .find(|action| {
                is_candidate_artifact_action(action)
                    && action
                        .candidate_artifact
                        .as_ref()
                        .is_some_and(|artifact| artifact.tx_count as usize == transfer_count)
            })
            .map(|action| action.tx_hash)
    };
    actions
        .into_iter()
        .filter(|action| {
            let input =
                native_mineable_action_admission_input(state, action, selected_candidate_hash);
            evaluate_native_mineable_action_admission(input).is_ok()
        })
        .collect()
}

fn prepared_mining_actions_match_state(state: &NativeState, actions: &[PendingAction]) -> bool {
    actions
        .iter()
        .filter(|action| !is_coinbase_action(action))
        .all(|action| {
            state
                .pending_actions
                .get(&action.tx_hash)
                .is_some_and(|pending| pending.encode() == action.encode())
        })
}

fn native_mineable_action_admission_input(
    state: &NativeState,
    action: &PendingAction,
    selected_candidate_hash: Option<[u8; 32]>,
) -> NativeMineableActionAdmissionInput {
    let candidate_artifact_route = is_candidate_artifact_action(action);
    let candidate_artifact_selected =
        selected_candidate_hash.is_some_and(|hash| hash == action.tx_hash);
    let sidecar_transfer_route = action.family_id == FAMILY_SHIELDED_POOL
        && action.action_id == ACTION_SHIELDED_TRANSFER_SIDECAR;
    let (
        sidecar_ciphertexts_available,
        sidecar_ciphertext_sizes_present,
        sidecar_ciphertext_sizes_match,
    ) = if sidecar_transfer_route {
        sidecar_ciphertext_state_for_action(state, action)
    } else {
        (true, true, true)
    };
    NativeMineableActionAdmissionInput {
        candidate_artifact_route,
        candidate_artifact_selected,
        sidecar_transfer_route,
        sidecar_ciphertexts_available,
        sidecar_ciphertext_sizes_present,
        sidecar_ciphertext_sizes_match,
    }
}

fn evaluate_native_mineable_action_admission(
    input: NativeMineableActionAdmissionInput,
) -> Result<(), NativeMineableActionAdmissionRejection> {
    if input.candidate_artifact_route {
        if input.candidate_artifact_selected {
            Ok(())
        } else {
            Err(NativeMineableActionAdmissionRejection::UnselectedCandidateArtifact)
        }
    } else if input.sidecar_transfer_route {
        if !input.sidecar_ciphertexts_available {
            Err(NativeMineableActionAdmissionRejection::SidecarCiphertextMissing)
        } else if !input.sidecar_ciphertext_sizes_present {
            Err(NativeMineableActionAdmissionRejection::SidecarCiphertextSizeMissing)
        } else if !input.sidecar_ciphertext_sizes_match {
            Err(NativeMineableActionAdmissionRejection::SidecarCiphertextSizeMismatch)
        } else {
            Ok(())
        }
    } else {
        Ok(())
    }
}

fn is_transfer_action(action_id: u16) -> bool {
    matches!(
        action_id,
        ACTION_SHIELDED_TRANSFER_INLINE | ACTION_SHIELDED_TRANSFER_SIDECAR
    )
}

fn is_shielded_transfer_action(action: &PendingAction) -> bool {
    action.family_id == FAMILY_SHIELDED_POOL && is_transfer_action(action.action_id)
}

fn is_coinbase_action(action: &PendingAction) -> bool {
    action.family_id == FAMILY_SHIELDED_POOL && action.action_id == ACTION_MINT_COINBASE
}

fn is_candidate_artifact_action(action: &PendingAction) -> bool {
    action.family_id == FAMILY_SHIELDED_POOL && action.action_id == ACTION_SUBMIT_CANDIDATE_ARTIFACT
}

fn action_order_key(action: &PendingAction) -> [u8; 32] {
    let mut preimage = Vec::new();
    match (action.family_id, action.action_id) {
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE) => {
            if let Ok(args) = decode_scale_exact::<ShieldedTransferInlineArgs>(
                &action.public_args,
                "shielded inline action args",
            ) {
                preimage.extend_from_slice(&args.binding_hash);
            }
        }
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_SIDECAR) => {
            if let Ok(args) = decode_scale_exact::<ShieldedTransferSidecarArgs>(
                &action.public_args,
                "shielded sidecar action args",
            ) {
                preimage.extend_from_slice(&args.binding_hash);
            }
        }
        _ => {
            preimage.extend_from_slice(b"non-transfer");
            preimage.extend_from_slice(&action.family_id.to_le_bytes());
            preimage.extend_from_slice(&action.action_id.to_le_bytes());
            preimage.extend_from_slice(&action.tx_hash);
        }
    }
    for nullifier in &action.nullifiers {
        preimage.extend_from_slice(nullifier);
    }
    if preimage.is_empty() {
        preimage.extend_from_slice(&action.tx_hash);
    }
    crypto::hashes::blake2_256(&preimage)
}

fn transfer_key_extends_canonical_order(
    previous_transfer_key: Option<&[u8; 32]>,
    transfer_key: &[u8; 32],
) -> bool {
    previous_transfer_key.is_none_or(|previous| transfer_key >= previous)
}

fn validate_bridge_action_payload(action: &PendingAction) -> Result<()> {
    let bridge_route = action.family_id == FAMILY_BRIDGE;
    let state_deltas_absent = bridge_action_has_no_state_deltas(action);
    let action_kind = native_bridge_action_payload_kind(action.action_id);
    if !bridge_route || !state_deltas_absent {
        let input = native_bridge_action_payload_admission_input(
            bridge_route,
            state_deltas_absent,
            action_kind,
            true,
            true,
            true,
            true,
            true,
        );
        return evaluate_native_bridge_action_payload_admission(input).map_err(|rejection| {
            native_bridge_action_payload_admission_error(action.action_id, rejection)
        });
    }
    match action_kind {
        NativeBridgeActionPayloadKind::Outbound => {
            let args: OutboundBridgeArgsV1 =
                decode_scale_exact(&action.public_args, "outbound bridge action args")?;
            let input = native_bridge_action_payload_admission_input(
                bridge_route,
                state_deltas_absent,
                action_kind,
                !args.payload.is_empty(),
                true,
                true,
                true,
                true,
            );
            evaluate_native_bridge_action_payload_admission(input).map_err(|rejection| {
                native_bridge_action_payload_admission_error(action.action_id, rejection)
            })?;
            Ok(())
        }
        NativeBridgeActionPayloadKind::Inbound => {
            let args: InboundBridgeArgsV1 =
                decode_scale_exact(&action.public_args, "inbound bridge action args")?;
            let input = native_bridge_action_payload_admission_input(
                bridge_route,
                state_deltas_absent,
                action_kind,
                true,
                !args.proof_receipt.is_empty(),
                args.message.source_chain_id == args.source_chain_id
                    && args.message.message_nonce == args.source_message_nonce,
                args.message.destination_chain_id == HEGEMON_CHAIN_ID_V1,
                args.message.payload_hash == bridge_payload_hash(&args.message.payload),
            );
            evaluate_native_bridge_action_payload_admission(input).map_err(|rejection| {
                native_bridge_action_payload_admission_error(action.action_id, rejection)
            })?;
            verify_inbound_bridge_receipt(&args)?;
            Ok(())
        }
        NativeBridgeActionPayloadKind::Register => {
            let _: BridgeVerifierRegistrationV1 =
                decode_scale_exact(&action.public_args, "bridge verifier registration args")?;
            let input = native_bridge_action_payload_admission_input(
                bridge_route,
                state_deltas_absent,
                action_kind,
                true,
                true,
                true,
                true,
                true,
            );
            evaluate_native_bridge_action_payload_admission(input).map_err(|rejection| {
                native_bridge_action_payload_admission_error(action.action_id, rejection)
            })?;
            Ok(())
        }
        NativeBridgeActionPayloadKind::Unsupported => {
            let input = native_bridge_action_payload_admission_input(
                bridge_route,
                state_deltas_absent,
                action_kind,
                true,
                true,
                true,
                true,
                true,
            );
            evaluate_native_bridge_action_payload_admission(input).map_err(|rejection| {
                native_bridge_action_payload_admission_error(action.action_id, rejection)
            })?;
            Ok(())
        }
    }
}

fn native_bridge_action_payload_kind(action_id: u16) -> NativeBridgeActionPayloadKind {
    match action_id {
        ACTION_BRIDGE_OUTBOUND => NativeBridgeActionPayloadKind::Outbound,
        ACTION_BRIDGE_INBOUND => NativeBridgeActionPayloadKind::Inbound,
        ACTION_REGISTER_BRIDGE_VERIFIER => NativeBridgeActionPayloadKind::Register,
        _ => NativeBridgeActionPayloadKind::Unsupported,
    }
}

fn bridge_action_has_no_state_deltas(action: &PendingAction) -> bool {
    action.nullifiers.is_empty()
        && action.commitments.is_empty()
        && action.ciphertext_hashes.is_empty()
        && action.ciphertext_sizes.is_empty()
        && action.fee == 0
        && action.anchor == [0u8; 48]
        && action.candidate_artifact.is_none()
}

fn native_bridge_action_payload_admission_input(
    bridge_route: bool,
    state_deltas_absent: bool,
    action_kind: NativeBridgeActionPayloadKind,
    outbound_payload_nonempty: bool,
    inbound_proof_receipt_nonempty: bool,
    inbound_replay_key_matches: bool,
    inbound_destination_matches: bool,
    inbound_payload_hash_matches: bool,
) -> NativeBridgeActionPayloadAdmissionInput {
    NativeBridgeActionPayloadAdmissionInput {
        bridge_route,
        state_deltas_absent,
        action_kind,
        outbound_payload_nonempty,
        inbound_proof_receipt_nonempty,
        inbound_replay_key_matches,
        inbound_destination_matches,
        inbound_payload_hash_matches,
    }
}

fn evaluate_native_bridge_action_payload_admission(
    input: NativeBridgeActionPayloadAdmissionInput,
) -> Result<(), NativeBridgeActionPayloadAdmissionRejection> {
    if !input.bridge_route {
        Err(NativeBridgeActionPayloadAdmissionRejection::NotBridgeAction)
    } else if !input.state_deltas_absent {
        Err(NativeBridgeActionPayloadAdmissionRejection::StateDeltasPresent)
    } else {
        match input.action_kind {
            NativeBridgeActionPayloadKind::Outbound => {
                if !input.outbound_payload_nonempty {
                    Err(NativeBridgeActionPayloadAdmissionRejection::OutboundPayloadEmpty)
                } else {
                    Ok(())
                }
            }
            NativeBridgeActionPayloadKind::Inbound => {
                if !input.inbound_proof_receipt_nonempty {
                    Err(NativeBridgeActionPayloadAdmissionRejection::InboundProofReceiptEmpty)
                } else if !input.inbound_replay_key_matches {
                    Err(NativeBridgeActionPayloadAdmissionRejection::InboundReplayKeyMismatch)
                } else if !input.inbound_destination_matches {
                    Err(NativeBridgeActionPayloadAdmissionRejection::InboundDestinationMismatch)
                } else if !input.inbound_payload_hash_matches {
                    Err(NativeBridgeActionPayloadAdmissionRejection::InboundPayloadHashMismatch)
                } else {
                    Ok(())
                }
            }
            NativeBridgeActionPayloadKind::Register => Ok(()),
            NativeBridgeActionPayloadKind::Unsupported => {
                Err(NativeBridgeActionPayloadAdmissionRejection::UnsupportedBridgeAction)
            }
        }
    }
}

fn native_bridge_action_payload_admission_error(
    action_id: u16,
    rejection: NativeBridgeActionPayloadAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeBridgeActionPayloadAdmissionRejection::NotBridgeAction => {
            anyhow!("not a bridge action")
        }
        NativeBridgeActionPayloadAdmissionRejection::StateDeltasPresent => {
            anyhow!("bridge actions must not carry shielded state deltas")
        }
        NativeBridgeActionPayloadAdmissionRejection::UnsupportedBridgeAction => {
            anyhow!("unsupported bridge action {action_id}")
        }
        NativeBridgeActionPayloadAdmissionRejection::OutboundPayloadEmpty => {
            anyhow!("outbound bridge payload must be non-empty")
        }
        NativeBridgeActionPayloadAdmissionRejection::InboundProofReceiptEmpty => {
            anyhow!("inbound bridge proof receipt must be non-empty")
        }
        NativeBridgeActionPayloadAdmissionRejection::InboundReplayKeyMismatch => {
            anyhow!("inbound bridge replay key does not match message")
        }
        NativeBridgeActionPayloadAdmissionRejection::InboundDestinationMismatch => {
            anyhow!("inbound bridge message is not addressed to Hegemon")
        }
        NativeBridgeActionPayloadAdmissionRejection::InboundPayloadHashMismatch => {
            anyhow!("inbound bridge message payload hash mismatch")
        }
    }
}

fn native_bridge_witness_confirmations_checked(
    best_height: u64,
    message_height: u64,
) -> Option<u32> {
    let delta = best_height.checked_sub(message_height)?;
    Some(delta.saturating_add(1).min(u32::MAX as u64) as u32)
}

fn evaluate_native_bridge_witness_export_admission(
    input: NativeBridgeWitnessExportAdmissionInput,
) -> Result<u32, NativeBridgeWitnessExportAdmissionRejection> {
    if !input.block_hash_parameter_valid {
        Err(NativeBridgeWitnessExportAdmissionRejection::MalformedBlockHash)
    } else if !input.block_known {
        Err(NativeBridgeWitnessExportAdmissionRejection::UnknownBlock)
    } else if !input.canonical_height_present {
        Err(NativeBridgeWitnessExportAdmissionRejection::MissingCanonicalHeight)
    } else if !input.block_is_canonical {
        Err(NativeBridgeWitnessExportAdmissionRejection::NoncanonicalBlock)
    } else if !input.block_actions_decoded {
        Err(NativeBridgeWitnessExportAdmissionRejection::BlockActionsDecodeFailed)
    } else if !input.message_index_in_bounds {
        Err(NativeBridgeWitnessExportAdmissionRejection::MessageIndexOutOfBounds)
    } else if !input.parent_known {
        Err(NativeBridgeWitnessExportAdmissionRejection::MissingParent)
    } else {
        native_bridge_witness_confirmations_checked(input.best_height, input.message_height)
            .ok_or(NativeBridgeWitnessExportAdmissionRejection::TipBeforeMessage)
    }
}

fn native_inbound_bridge_receipt_height_confirmations(
    canonical_tip_height: u64,
    checkpoint_height: u64,
) -> Option<u32> {
    let delta = canonical_tip_height.checked_sub(checkpoint_height)?;
    Some(delta.saturating_add(1).min(u32::MAX as u64) as u32)
}

fn evaluate_native_inbound_bridge_receipt_admission(
    input: NativeInboundBridgeReceiptAdmissionInput,
) -> Result<u32, NativeInboundBridgeReceiptAdmissionRejection> {
    if !input.source_chain_matches {
        Err(NativeInboundBridgeReceiptAdmissionRejection::SourceChainMismatch)
    } else if !input.rules_hash_matches {
        Err(NativeInboundBridgeReceiptAdmissionRejection::RulesHashMismatch)
    } else if !input.message_nonce_matches {
        Err(NativeInboundBridgeReceiptAdmissionRejection::MessageNonceMismatch)
    } else if !input.message_hash_matches {
        Err(NativeInboundBridgeReceiptAdmissionRejection::MessageHashMismatch)
    } else {
        let height_confirmations = native_inbound_bridge_receipt_height_confirmations(
            input.canonical_tip_height,
            input.checkpoint_height,
        )
        .ok_or(NativeInboundBridgeReceiptAdmissionRejection::TipBeforeMessage)?;
        if height_confirmations < input.confirmations_checked {
            Err(NativeInboundBridgeReceiptAdmissionRejection::ConfirmationsOverstated)
        } else if input.confirmations_checked < input.min_confirmations {
            Err(NativeInboundBridgeReceiptAdmissionRejection::Underconfirmed)
        } else {
            Ok(height_confirmations)
        }
    }
}

fn evaluate_native_bridge_witness_backscan(
    entries: &[NativeBridgeWitnessBackscanEntry],
) -> Result<u64, NativeBridgeWitnessBackscanRejection> {
    for entry in entries {
        if !entry.canonical_hash_present || !entry.block_known {
            continue;
        }
        if !entry.block_actions_decoded {
            return Err(NativeBridgeWitnessBackscanRejection::BlockActionsDecodeFailed);
        }
        if entry.message_index_in_bounds {
            return Ok(entry.height);
        }
    }
    Err(NativeBridgeWitnessBackscanRejection::NoBridgeMessageInBackscan)
}

fn native_bridge_witness_export_admission_error(
    rejection: NativeBridgeWitnessExportAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeBridgeWitnessExportAdmissionRejection::MalformedBlockHash => {
            anyhow!(
                "malformed bridge witness block hash ({})",
                rejection.label()
            )
        }
        NativeBridgeWitnessExportAdmissionRejection::UnknownBlock => {
            anyhow!("unknown bridge witness block ({})", rejection.label())
        }
        NativeBridgeWitnessExportAdmissionRejection::MissingCanonicalHeight => anyhow!(
            "missing canonical block at bridge witness height ({})",
            rejection.label()
        ),
        NativeBridgeWitnessExportAdmissionRejection::NoncanonicalBlock => {
            anyhow!(
                "bridge witness block is not canonical ({})",
                rejection.label()
            )
        }
        NativeBridgeWitnessExportAdmissionRejection::BlockActionsDecodeFailed => anyhow!(
            "bridge witness block action decode failed ({})",
            rejection.label()
        ),
        NativeBridgeWitnessExportAdmissionRejection::MessageIndexOutOfBounds => {
            anyhow!("bridge message index out of bounds ({})", rejection.label())
        }
        NativeBridgeWitnessExportAdmissionRejection::MissingParent => {
            anyhow!("missing parent for bridge witness ({})", rejection.label())
        }
        NativeBridgeWitnessExportAdmissionRejection::TipBeforeMessage => anyhow!(
            "bridge witness tip height is before message height ({})",
            rejection.label()
        ),
    }
}

fn native_inbound_bridge_receipt_admission_error(
    input: NativeInboundBridgeReceiptAdmissionInput,
    rejection: NativeInboundBridgeReceiptAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeInboundBridgeReceiptAdmissionRejection::SourceChainMismatch
        | NativeInboundBridgeReceiptAdmissionRejection::RulesHashMismatch
        | NativeInboundBridgeReceiptAdmissionRejection::MessageNonceMismatch
        | NativeInboundBridgeReceiptAdmissionRejection::MessageHashMismatch => {
            anyhow!("Hegemon light-client bridge receipt output mismatch")
        }
        NativeInboundBridgeReceiptAdmissionRejection::TipBeforeMessage => {
            anyhow!("Hegemon light-client bridge receipt tip precedes message")
        }
        NativeInboundBridgeReceiptAdmissionRejection::ConfirmationsOverstated => {
            anyhow!("Hegemon light-client bridge receipt overstates confirmations")
        }
        NativeInboundBridgeReceiptAdmissionRejection::Underconfirmed => anyhow!(
            "Hegemon light-client bridge receipt underconfirmed: {} < {}",
            input.confirmations_checked,
            input.min_confirmations
        ),
    }
}

fn evaluate_native_risc0_release_verifier(
    input: NativeRisc0ReleaseVerifierInput,
) -> Result<(), NativeRisc0ReleaseVerifierRejection> {
    if !input.image_id_matches {
        Err(NativeRisc0ReleaseVerifierRejection::ImageIdMismatch)
    } else if !input.journal_decodes {
        Err(NativeRisc0ReleaseVerifierRejection::JournalDecodeFailed)
    } else if !input.verifier_enabled {
        Err(NativeRisc0ReleaseVerifierRejection::VerifierDisabled)
    } else {
        Ok(())
    }
}

fn native_risc0_release_verifier_error(
    rejection: NativeRisc0ReleaseVerifierRejection,
) -> anyhow::Error {
    match rejection {
        NativeRisc0ReleaseVerifierRejection::ImageIdMismatch => {
            anyhow!("RISC Zero bridge image id mismatch")
        }
        NativeRisc0ReleaseVerifierRejection::JournalDecodeFailed => {
            anyhow!("decode RISC Zero bridge journal failed")
        }
        NativeRisc0ReleaseVerifierRejection::VerifierDisabled => anyhow!(
            "RISC Zero bridge receipt verification is disabled in the PQ-only native node build"
        ),
    }
}

fn verify_inbound_bridge_receipt(args: &InboundBridgeArgsV1) -> Result<()> {
    if args.source_chain_id != HEGEMON_CHAIN_ID_V1 {
        return Err(anyhow!(
            "Hegemon RISC Zero bridge verifier only accepts Hegemon source chain"
        ));
    }
    let receipt: RiscZeroBridgeReceiptV1 =
        decode_scale_exact(&args.proof_receipt, "RISC Zero bridge receipt")?;
    if args.verifier_program_hash != HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1 {
        return Err(anyhow!("unregistered Hegemon RISC Zero bridge verifier"));
    }
    let output = verify_risc0_bridge_receipt(&receipt, HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1)?;
    let admission_input = NativeInboundBridgeReceiptAdmissionInput {
        source_chain_matches: output.source_chain_id == args.source_chain_id,
        rules_hash_matches: output.rules_hash == HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
        message_nonce_matches: output.message_nonce == args.source_message_nonce,
        message_hash_matches: output.message_hash == args.message.message_hash(),
        checkpoint_height: output.checkpoint_height,
        canonical_tip_height: output.canonical_tip_height,
        confirmations_checked: output.confirmations_checked,
        min_confirmations: MIN_INBOUND_BRIDGE_CONFIRMATIONS,
    };
    evaluate_native_inbound_bridge_receipt_admission(admission_input).map_err(|rejection| {
        native_inbound_bridge_receipt_admission_error(admission_input, rejection)
    })?;
    Ok(())
}

fn verify_risc0_bridge_receipt(
    envelope: &RiscZeroBridgeReceiptV1,
    expected_image_id: [u8; 32],
) -> Result<BridgeCheckpointOutputV1> {
    let mut release_input = NativeRisc0ReleaseVerifierInput {
        image_id_matches: envelope.image_id == expected_image_id,
        journal_decodes: false,
        verifier_enabled: NATIVE_RISC0_RECEIPT_VERIFIER_ENABLED,
    };
    if !release_input.image_id_matches {
        let rejection = evaluate_native_risc0_release_verifier(release_input)
            .expect_err("image mismatch must reject");
        return Err(native_risc0_release_verifier_error(rejection));
    }
    let output = match decode_risc0_bridge_journal(envelope) {
        Ok(output) => {
            release_input.journal_decodes = true;
            output
        }
        Err(err) => {
            let rejection = evaluate_native_risc0_release_verifier(release_input)
                .expect_err("journal decode failure must reject");
            let base = native_risc0_release_verifier_error(rejection);
            return Err(anyhow!("{base}: {err:?}"));
        }
    };
    evaluate_native_risc0_release_verifier(release_input)
        .map_err(native_risc0_release_verifier_error)?;
    Ok(output)
}

fn bridge_inbound_replay_key_from_action(action: &PendingAction) -> Result<Option<[u8; 48]>> {
    if action.family_id != FAMILY_BRIDGE || action.action_id != ACTION_BRIDGE_INBOUND {
        return Ok(None);
    }
    let args: InboundBridgeArgsV1 =
        decode_scale_exact(&action.public_args, "inbound bridge action args")?;
    Ok(Some(inbound_replay_key(
        args.source_chain_id,
        args.source_message_nonce,
    )))
}

fn inbound_replay_state_for_mempool(state: &NativeState) -> Result<InboundReplayState> {
    let mut pending = BTreeSet::new();
    for action in state.pending_actions.values() {
        if let Some(replay_key) = bridge_inbound_replay_key_from_action(action)? {
            if !pending.insert(replay_key) {
                return Err(anyhow!("duplicate inbound bridge message already pending"));
            }
        }
    }
    Ok(InboundReplayState::new(
        state.consumed_bridge_messages.clone(),
        pending,
    ))
}

fn shielded_nullifier_state_for_mempool(state: &NativeState) -> NullifierState {
    let mut pending = BTreeSet::new();
    for action in state.pending_actions.values() {
        for nullifier in &action.nullifiers {
            pending.insert(*nullifier);
        }
    }
    NullifierState::new(state.nullifiers.clone(), pending)
}

fn bridge_messages_from_actions(
    actions: &[PendingAction],
    source_height: u64,
) -> Result<Vec<BridgeMessageV1>> {
    let mut messages = Vec::new();
    for action in actions {
        if action.family_id != FAMILY_BRIDGE || action.action_id != ACTION_BRIDGE_OUTBOUND {
            continue;
        }
        let args = decode_scale_exact::<OutboundBridgeArgsV1>(
            &action.public_args,
            "outbound bridge action args",
        )?;
        let message_nonce = ((source_height as u128) << 64) | messages.len() as u128;
        messages.push(BridgeMessageV1 {
            source_chain_id: HEGEMON_CHAIN_ID_V1,
            destination_chain_id: args.destination_chain_id,
            app_family_id: args.app_family_id,
            message_nonce,
            source_height,
            payload_hash: bridge_payload_hash(&args.payload),
            payload: args.payload,
        });
    }
    Ok(messages)
}

fn decode_block_actions(meta: &NativeBlockMeta) -> Result<Vec<PendingAction>> {
    evaluate_native_action_hash_admission(NativeActionHashAdmissionInput {
        action_count_matches: meta.action_bytes.len() == meta.tx_count as usize,
        action_hashes_match: true,
        action_hashes_unique: true,
    })
    .map_err(native_action_hash_admission_error)?;
    let mut actions = Vec::with_capacity(meta.action_bytes.len());
    for bytes in &meta.action_bytes {
        let action = decode_scale_exact::<PendingAction>(bytes, "native block action")?;
        if action.encode().as_slice() != bytes.as_slice() {
            return Err(anyhow!(
                "native block action has noncanonical SCALE encoding"
            ));
        }
        actions.push(action);
    }
    evaluate_native_action_hash_admission(NativeActionHashAdmissionInput {
        action_count_matches: true,
        action_hashes_match: block_action_hashes_match(&actions),
        action_hashes_unique: block_action_hashes_unique(&actions),
    })
    .map_err(native_action_hash_admission_error)?;
    Ok(actions)
}

fn evaluate_native_action_hash_admission(
    input: NativeActionHashAdmissionInput,
) -> Result<(), NativeActionHashAdmissionRejection> {
    if !input.action_count_matches {
        Err(NativeActionHashAdmissionRejection::ActionCountMismatch)
    } else if !input.action_hashes_match {
        Err(NativeActionHashAdmissionRejection::ActionHashMismatch)
    } else if !input.action_hashes_unique {
        Err(NativeActionHashAdmissionRejection::DuplicateActionHash)
    } else {
        Ok(())
    }
}

fn native_action_hash_admission_error(
    rejection: NativeActionHashAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeActionHashAdmissionRejection::ActionCountMismatch => {
            anyhow!("block action payload count mismatch")
        }
        NativeActionHashAdmissionRejection::ActionHashMismatch => {
            anyhow!("block action hash mismatch")
        }
        NativeActionHashAdmissionRejection::DuplicateActionHash => {
            anyhow!("duplicate action in block")
        }
    }
}

fn action_has_no_shielded_state_deltas(action: &PendingAction) -> bool {
    action.nullifiers.is_empty()
        && action.commitments.is_empty()
        && action.ciphertext_hashes.is_empty()
        && action.ciphertext_sizes.is_empty()
        && action.fee == 0
        && action.anchor == [0u8; 48]
}

fn bridge_action_scope_valid(action: &PendingAction) -> bool {
    action_has_no_shielded_state_deltas(action) && action.candidate_artifact.is_none()
}

fn candidate_artifact_action_scope_valid(action: &PendingAction) -> bool {
    action_has_no_shielded_state_deltas(action)
}

fn coinbase_action_scope_valid(action: &PendingAction) -> bool {
    action.nullifiers.is_empty()
        && action.commitments.len() == 1
        && action.ciphertext_hashes.len() == 1
        && action.ciphertext_sizes.len() == 1
        && action.fee == 0
        && action.anchor == [0u8; 48]
        && action.candidate_artifact.is_none()
}

fn transfer_action_scope_valid(action: &PendingAction) -> bool {
    !action.nullifiers.is_empty()
        && action.nullifiers.len() <= transaction_core::constants::MAX_INPUTS
        && !action.commitments.is_empty()
        && action.commitments.len() <= transaction_core::constants::MAX_OUTPUTS
        && action.ciphertext_hashes.len() == action.commitments.len()
        && action.ciphertext_sizes.len() == action.commitments.len()
        && action
            .ciphertext_sizes
            .iter()
            .all(|size| *size as usize <= MAX_CIPHERTEXT_BYTES)
}

fn native_action_scope_admission_input(action: &PendingAction) -> NativeActionScopeAdmissionInput {
    NativeActionScopeAdmissionInput {
        candidate_artifact_payload_scoped: action.candidate_artifact.is_none()
            || is_candidate_artifact_action(action),
        bridge_route: action.family_id == FAMILY_BRIDGE,
        bridge_scope_valid: bridge_action_scope_valid(action),
        candidate_artifact_route: is_candidate_artifact_action(action),
        candidate_scope_valid: candidate_artifact_action_scope_valid(action),
        candidate_payload_present: action.candidate_artifact.is_some(),
        coinbase_route: is_coinbase_action(action),
        coinbase_scope_valid: coinbase_action_scope_valid(action),
        transfer_route: is_shielded_transfer_action(action),
        transfer_scope_valid: transfer_action_scope_valid(action),
    }
}

fn evaluate_native_action_scope_admission(
    input: NativeActionScopeAdmissionInput,
) -> Result<NativeActionScopeAdmissionRoute, NativeActionScopeAdmissionRejection> {
    if !input.candidate_artifact_payload_scoped {
        Err(NativeActionScopeAdmissionRejection::CandidateArtifactPayloadWrongRoute)
    } else if input.bridge_route {
        if !input.bridge_scope_valid {
            Err(NativeActionScopeAdmissionRejection::BridgeScopeInvalid)
        } else {
            Ok(NativeActionScopeAdmissionRoute::Bridge)
        }
    } else if input.candidate_artifact_route {
        if !input.candidate_scope_valid {
            Err(NativeActionScopeAdmissionRejection::CandidateScopeInvalid)
        } else if !input.candidate_payload_present {
            Err(NativeActionScopeAdmissionRejection::CandidatePayloadMissing)
        } else {
            Ok(NativeActionScopeAdmissionRoute::CandidateArtifact)
        }
    } else if input.coinbase_route {
        if !input.coinbase_scope_valid {
            Err(NativeActionScopeAdmissionRejection::CoinbaseScopeInvalid)
        } else {
            Ok(NativeActionScopeAdmissionRoute::Coinbase)
        }
    } else if !input.transfer_route {
        Err(NativeActionScopeAdmissionRejection::UnsupportedActionRoute)
    } else if !input.transfer_scope_valid {
        Err(NativeActionScopeAdmissionRejection::TransferScopeInvalid)
    } else {
        Ok(NativeActionScopeAdmissionRoute::Transfer)
    }
}

fn native_action_scope_admission_error(
    rejection: NativeActionScopeAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeActionScopeAdmissionRejection::CandidateArtifactPayloadWrongRoute => {
            anyhow!("candidate artifact payload is only valid on candidate artifact actions")
        }
        NativeActionScopeAdmissionRejection::BridgeScopeInvalid => {
            anyhow!("bridge actions must not carry shielded state deltas")
        }
        NativeActionScopeAdmissionRejection::CandidateScopeInvalid => {
            anyhow!("candidate artifact actions must not carry shielded state deltas")
        }
        NativeActionScopeAdmissionRejection::CandidatePayloadMissing => {
            anyhow!("candidate artifact action missing payload")
        }
        NativeActionScopeAdmissionRejection::CoinbaseScopeInvalid => {
            anyhow!("coinbase action must contain exactly one output and no other state deltas")
        }
        NativeActionScopeAdmissionRejection::UnsupportedActionRoute => {
            anyhow!("action is not a shielded transfer")
        }
        NativeActionScopeAdmissionRejection::TransferScopeInvalid => {
            anyhow!("shielded transfer action has invalid public metadata shape")
        }
    }
}

fn native_block_action_validation_scope_rejection(
    rejection: NativeActionScopeAdmissionRejection,
) -> NativeBlockActionValidationRejection {
    match rejection {
        NativeActionScopeAdmissionRejection::CandidateArtifactPayloadWrongRoute => {
            NativeBlockActionValidationRejection::CandidateArtifactPayloadWrongRoute
        }
        NativeActionScopeAdmissionRejection::BridgeScopeInvalid => {
            NativeBlockActionValidationRejection::BridgeScopeInvalid
        }
        NativeActionScopeAdmissionRejection::CandidateScopeInvalid => {
            NativeBlockActionValidationRejection::CandidateScopeInvalid
        }
        NativeActionScopeAdmissionRejection::CandidatePayloadMissing => {
            NativeBlockActionValidationRejection::CandidatePayloadMissing
        }
        NativeActionScopeAdmissionRejection::CoinbaseScopeInvalid => {
            NativeBlockActionValidationRejection::CoinbaseScopeInvalid
        }
        NativeActionScopeAdmissionRejection::UnsupportedActionRoute => {
            NativeBlockActionValidationRejection::UnsupportedActionRoute
        }
        NativeActionScopeAdmissionRejection::TransferScopeInvalid => {
            NativeBlockActionValidationRejection::TransferScopeInvalid
        }
    }
}

fn native_block_action_validation_hash_rejection(
    rejection: NativeActionHashAdmissionRejection,
) -> NativeBlockActionValidationRejection {
    match rejection {
        NativeActionHashAdmissionRejection::ActionCountMismatch => {
            NativeBlockActionValidationRejection::ActionCountMismatch
        }
        NativeActionHashAdmissionRejection::ActionHashMismatch => {
            NativeBlockActionValidationRejection::ActionHashMismatch
        }
        NativeActionHashAdmissionRejection::DuplicateActionHash => {
            NativeBlockActionValidationRejection::DuplicateActionHash
        }
    }
}

fn native_block_action_validation_payload_rejection(
    route: NativeActionScopeAdmissionRoute,
) -> NativeBlockActionValidationRejection {
    match route {
        NativeActionScopeAdmissionRoute::Bridge => {
            NativeBlockActionValidationRejection::BridgePayloadInvalid
        }
        NativeActionScopeAdmissionRoute::CandidateArtifact => {
            NativeBlockActionValidationRejection::CandidatePayloadInvalid
        }
        NativeActionScopeAdmissionRoute::Coinbase => {
            NativeBlockActionValidationRejection::CoinbasePayloadInvalid
        }
        NativeActionScopeAdmissionRoute::Transfer => {
            NativeBlockActionValidationRejection::TransferPayloadInvalid
        }
    }
}

fn native_block_action_validation_transfer_rejection(
    rejection: NativeTransferStateAdmissionRejection,
) -> NativeBlockActionValidationRejection {
    match rejection {
        NativeTransferStateAdmissionRejection::UnknownAnchor => {
            NativeBlockActionValidationRejection::TransferUnknownAnchor
        }
        NativeTransferStateAdmissionRejection::NullifierZero => {
            NativeBlockActionValidationRejection::TransferNullifierZero
        }
        NativeTransferStateAdmissionRejection::NullifierAlreadySpent => {
            NativeBlockActionValidationRejection::TransferNullifierAlreadySpent
        }
        NativeTransferStateAdmissionRejection::DuplicateNullifier => {
            NativeBlockActionValidationRejection::TransferDuplicateNullifier
        }
        NativeTransferStateAdmissionRejection::NullifierAlreadyPending => {
            NativeBlockActionValidationRejection::TransferNullifierAlreadyPending
        }
        NativeTransferStateAdmissionRejection::CommitmentZero => {
            NativeBlockActionValidationRejection::TransferCommitmentZero
        }
        NativeTransferStateAdmissionRejection::SidecarCiphertextMissing => {
            NativeBlockActionValidationRejection::TransferSidecarCiphertextMissing
        }
        NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMissing => {
            NativeBlockActionValidationRejection::TransferSidecarCiphertextSizeMissing
        }
        NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMismatch => {
            NativeBlockActionValidationRejection::TransferSidecarCiphertextSizeMismatch
        }
    }
}

fn evaluate_native_block_action_validation_start(
    action_count_matches: bool,
    action_hashes_match: bool,
    action_hashes_unique: bool,
    consumed_bridge_messages: BTreeSet<[u8; 48]>,
) -> Result<NativeBlockActionValidationState, NativeBlockActionValidationRejection> {
    evaluate_native_action_hash_admission(NativeActionHashAdmissionInput {
        action_count_matches,
        action_hashes_match,
        action_hashes_unique,
    })
    .map_err(native_block_action_validation_hash_rejection)?;
    Ok(NativeBlockActionValidationState {
        bridge_replay_state: InboundReplayState::new(consumed_bridge_messages, BTreeSet::new()),
        previous_transfer_key: None,
        validated_action_count: 0,
        imported_bridge_replay_count: 0,
    })
}

fn evaluate_native_block_action_validation_step(
    state: &mut NativeBlockActionValidationState,
    step: NativeBlockActionValidationStep,
) -> Result<NativeActionScopeAdmissionRoute, NativeBlockActionValidationRejection> {
    let route = evaluate_native_action_scope_admission(step.scope_input)
        .map_err(native_block_action_validation_scope_rejection)?;
    if !step.payload_valid {
        return Err(native_block_action_validation_payload_rejection(route));
    }

    match route {
        NativeActionScopeAdmissionRoute::Bridge => {
            if let Some(replay_key) = step.bridge_replay_key {
                state
                    .bridge_replay_state
                    .import_one(replay_key)
                    .map_err(|_| NativeBlockActionValidationRejection::BridgeReplayDuplicate)?;
                state.imported_bridge_replay_count = state
                    .imported_bridge_replay_count
                    .checked_add(1)
                    .expect("usize bridge replay count cannot overflow on one block");
            }
        }
        NativeActionScopeAdmissionRoute::Transfer => {
            if !transfer_key_extends_canonical_order(
                state.previous_transfer_key.as_ref(),
                &step.transfer_key,
            ) {
                return Err(NativeBlockActionValidationRejection::TransferOrderInvalid);
            }
            state.previous_transfer_key = Some(step.transfer_key);
            evaluate_native_transfer_state_admission(step.transfer_state_input)
                .map_err(native_block_action_validation_transfer_rejection)?;
        }
        NativeActionScopeAdmissionRoute::CandidateArtifact
        | NativeActionScopeAdmissionRoute::Coinbase => {}
    }

    state.validated_action_count = state
        .validated_action_count
        .checked_add(1)
        .expect("usize validated action count cannot overflow on one block");
    Ok(route)
}

#[cfg(test)]
fn native_block_action_validation_summary(
    state: NativeBlockActionValidationState,
) -> NativeBlockActionValidationSummary {
    NativeBlockActionValidationSummary {
        validated_action_count: state.validated_action_count,
        imported_bridge_replay_count: state.imported_bridge_replay_count,
        last_transfer_key: state.previous_transfer_key,
    }
}

fn native_block_action_validation_error(
    rejection: NativeBlockActionValidationRejection,
) -> anyhow::Error {
    anyhow!(
        "native block action validation failed: {}",
        rejection.label()
    )
}

fn native_block_action_validation_transfer_state_rejection(
    rejection: NativeBlockActionValidationRejection,
) -> Option<NativeTransferStateAdmissionRejection> {
    match rejection {
        NativeBlockActionValidationRejection::TransferUnknownAnchor => {
            Some(NativeTransferStateAdmissionRejection::UnknownAnchor)
        }
        NativeBlockActionValidationRejection::TransferNullifierZero => {
            Some(NativeTransferStateAdmissionRejection::NullifierZero)
        }
        NativeBlockActionValidationRejection::TransferNullifierAlreadySpent => {
            Some(NativeTransferStateAdmissionRejection::NullifierAlreadySpent)
        }
        NativeBlockActionValidationRejection::TransferDuplicateNullifier => {
            Some(NativeTransferStateAdmissionRejection::DuplicateNullifier)
        }
        NativeBlockActionValidationRejection::TransferNullifierAlreadyPending => {
            Some(NativeTransferStateAdmissionRejection::NullifierAlreadyPending)
        }
        NativeBlockActionValidationRejection::TransferCommitmentZero => {
            Some(NativeTransferStateAdmissionRejection::CommitmentZero)
        }
        NativeBlockActionValidationRejection::TransferSidecarCiphertextMissing => {
            Some(NativeTransferStateAdmissionRejection::SidecarCiphertextMissing)
        }
        NativeBlockActionValidationRejection::TransferSidecarCiphertextSizeMissing => {
            Some(NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMissing)
        }
        NativeBlockActionValidationRejection::TransferSidecarCiphertextSizeMismatch => {
            Some(NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMismatch)
        }
        _ => None,
    }
}

fn evaluate_native_block_commitment_admission(
    input: NativeBlockCommitmentAdmissionInput,
) -> Result<(), NativeBlockCommitmentAdmissionRejection> {
    if !input.tx_count_matches {
        Err(NativeBlockCommitmentAdmissionRejection::TxCountMismatch)
    } else if !input.state_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::StateRootMismatch)
    } else if !input.kernel_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::KernelRootMismatch)
    } else if !input.nullifier_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::NullifierRootMismatch)
    } else if !input.extrinsics_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::ExtrinsicsRootMismatch)
    } else if !input.message_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::MessageRootMismatch)
    } else if !input.message_count_matches {
        Err(NativeBlockCommitmentAdmissionRejection::MessageCountMismatch)
    } else if !input.header_mmr_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::HeaderMmrRootMismatch)
    } else if !input.header_mmr_len_matches {
        Err(NativeBlockCommitmentAdmissionRejection::HeaderMmrLenMismatch)
    } else if !input.supply_digest_matches {
        Err(NativeBlockCommitmentAdmissionRejection::SupplyDigestMismatch)
    } else {
        Ok(())
    }
}

fn native_block_commitment_admission_error(
    context: &'static str,
    rejection: NativeBlockCommitmentAdmissionRejection,
) -> anyhow::Error {
    anyhow!("{context}: {}", rejection.label())
}

fn expected_atomic_block_record_writes(input: NativeAtomicCommitManifestAdmissionInput) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit => 1,
        NativeAtomicCommitKind::CanonicalReorgCommit => input.chain_block_count,
        NativeAtomicCommitKind::CanonicalIndexRepair => 0,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 1,
    }
}

fn expected_atomic_height_index_writes(input: NativeAtomicCommitManifestAdmissionInput) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit => 1,
        NativeAtomicCommitKind::CanonicalReorgCommit => input.height_entry_count,
        NativeAtomicCommitKind::CanonicalIndexRepair
        | NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

fn expected_atomic_best_pointer_writes(input: NativeAtomicCommitManifestAdmissionInput) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit | NativeAtomicCommitKind::CanonicalReorgCommit => {
            1
        }
        NativeAtomicCommitKind::CanonicalIndexRepair
        | NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

fn expected_atomic_canonical_index_cleared(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> bool {
    matches!(
        input.kind,
        NativeAtomicCommitKind::CanonicalReorgCommit | NativeAtomicCommitKind::CanonicalIndexRepair
    )
}

fn expected_atomic_pending_tree_cleared(input: NativeAtomicCommitManifestAdmissionInput) -> bool {
    matches!(input.kind, NativeAtomicCommitKind::CanonicalReorgCommit)
}

fn expected_atomic_pending_action_removals(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit => input.action_count,
        _ => 0,
    }
}

fn expected_atomic_pending_action_writes(input: NativeAtomicCommitManifestAdmissionInput) -> usize {
    match input.kind {
        NativeAtomicCommitKind::CanonicalReorgCommit => input.pending_entry_count,
        _ => 0,
    }
}

fn expected_atomic_commitment_writes(input: NativeAtomicCommitManifestAdmissionInput) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit
        | NativeAtomicCommitKind::CanonicalIndexRepair => input.source_commitment_count,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

fn expected_atomic_nullifier_writes(input: NativeAtomicCommitManifestAdmissionInput) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit
        | NativeAtomicCommitKind::CanonicalIndexRepair => input.source_nullifier_count,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

fn expected_atomic_bridge_replay_writes(input: NativeAtomicCommitManifestAdmissionInput) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit
        | NativeAtomicCommitKind::CanonicalIndexRepair => input.source_bridge_replay_count,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

fn expected_atomic_ciphertext_index_writes(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit
        | NativeAtomicCommitKind::CanonicalIndexRepair => input.source_ciphertext_index_count,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

fn expected_atomic_ciphertext_archive_writes(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit
        | NativeAtomicCommitKind::CanonicalIndexRepair => input.source_ciphertext_archive_count,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

fn expected_atomic_staged_ciphertext_removals(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit => input.source_staged_ciphertext_removal_count,
        _ => 0,
    }
}

fn evaluate_native_atomic_commit_manifest_admission(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> Result<(), NativeAtomicCommitManifestAdmissionRejection> {
    if matches!(input.kind, NativeAtomicCommitKind::MinedBlockCommit)
        && input.action_count != input.planned_action_count
    {
        Err(NativeAtomicCommitManifestAdmissionRejection::MinedPlanLengthMismatch)
    } else if input.block_record_writes != expected_atomic_block_record_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::BlockRecordWritesMismatch)
    } else if input.height_index_writes != expected_atomic_height_index_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::HeightIndexWritesMismatch)
    } else if input.best_pointer_writes != expected_atomic_best_pointer_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::BestPointerWritesMismatch)
    } else if input.canonical_index_cleared != expected_atomic_canonical_index_cleared(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::CanonicalIndexClearMismatch)
    } else if input.pending_tree_cleared != expected_atomic_pending_tree_cleared(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::PendingTreeClearMismatch)
    } else if input.pending_action_removals != expected_atomic_pending_action_removals(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::PendingActionRemovalMismatch)
    } else if input.pending_action_writes != expected_atomic_pending_action_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::PendingActionWriteMismatch)
    } else if input.commitment_writes != expected_atomic_commitment_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::CommitmentWriteMismatch)
    } else if input.nullifier_writes != expected_atomic_nullifier_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::NullifierWriteMismatch)
    } else if input.bridge_replay_writes != expected_atomic_bridge_replay_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::BridgeReplayWriteMismatch)
    } else if input.ciphertext_index_writes != expected_atomic_ciphertext_index_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::CiphertextIndexWriteMismatch)
    } else if input.ciphertext_archive_writes != expected_atomic_ciphertext_archive_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::CiphertextArchiveWriteMismatch)
    } else if input.staged_ciphertext_removals != expected_atomic_staged_ciphertext_removals(input)
    {
        Err(NativeAtomicCommitManifestAdmissionRejection::StagedCiphertextRemovalMismatch)
    } else {
        Ok(())
    }
}

fn native_atomic_commit_manifest_admission_error(
    context: &str,
    rejection: NativeAtomicCommitManifestAdmissionRejection,
) -> anyhow::Error {
    anyhow!("{context}: {}", rejection.label())
}

fn native_mined_block_commit_manifest(
    actions: &[PendingAction],
    planned: &[NativePlannedActionEffect],
) -> NativeAtomicCommitManifestAdmissionInput {
    let commitment_count = actions
        .iter()
        .map(|action| action.commitments.len())
        .sum::<usize>();
    let nullifier_count = actions
        .iter()
        .map(|action| action.nullifiers.len())
        .sum::<usize>();
    let ciphertext_hash_count = actions
        .iter()
        .map(|action| action.ciphertext_hashes.len())
        .sum::<usize>();
    let materialized_ciphertext_count = planned
        .iter()
        .map(|effect| effect.ciphertexts.len())
        .sum::<usize>();
    let bridge_replay_count = planned
        .iter()
        .filter(|effect| effect.replay_key.is_some())
        .count();
    NativeAtomicCommitManifestAdmissionInput {
        kind: NativeAtomicCommitKind::MinedBlockCommit,
        action_count: actions.len(),
        planned_action_count: planned.len(),
        chain_block_count: 0,
        height_entry_count: 0,
        pending_entry_count: 0,
        source_commitment_count: commitment_count,
        source_nullifier_count: nullifier_count,
        source_bridge_replay_count: bridge_replay_count,
        source_ciphertext_index_count: ciphertext_hash_count,
        source_ciphertext_archive_count: materialized_ciphertext_count,
        source_staged_ciphertext_removal_count: ciphertext_hash_count,
        block_record_writes: 1,
        height_index_writes: 1,
        best_pointer_writes: 1,
        canonical_index_cleared: false,
        pending_tree_cleared: false,
        pending_action_removals: actions.len(),
        pending_action_writes: 0,
        commitment_writes: commitment_count,
        nullifier_writes: nullifier_count,
        bridge_replay_writes: bridge_replay_count,
        ciphertext_index_writes: ciphertext_hash_count,
        ciphertext_archive_writes: materialized_ciphertext_count,
        staged_ciphertext_removals: ciphertext_hash_count,
    }
}

fn native_reorg_commit_manifest(
    canonical_index_plan: &NativeCanonicalIndexPlan,
    block_entries: &[([u8; 32], Vec<u8>)],
    height_entries: &[(u64, [u8; 32])],
    pending_entries: &[([u8; 32], Vec<u8>)],
) -> NativeAtomicCommitManifestAdmissionInput {
    NativeAtomicCommitManifestAdmissionInput {
        kind: NativeAtomicCommitKind::CanonicalReorgCommit,
        action_count: 0,
        planned_action_count: 0,
        chain_block_count: block_entries.len(),
        height_entry_count: height_entries.len(),
        pending_entry_count: pending_entries.len(),
        source_commitment_count: canonical_index_plan.commitment_entries.len(),
        source_nullifier_count: canonical_index_plan.nullifier_entries.len(),
        source_bridge_replay_count: canonical_index_plan.bridge_replay_entries.len(),
        source_ciphertext_index_count: canonical_index_plan.ciphertext_index_entries.len(),
        source_ciphertext_archive_count: canonical_index_plan.ciphertext_archive_entries.len(),
        source_staged_ciphertext_removal_count: 0,
        block_record_writes: block_entries.len(),
        height_index_writes: height_entries.len(),
        best_pointer_writes: 1,
        canonical_index_cleared: true,
        pending_tree_cleared: true,
        pending_action_removals: 0,
        pending_action_writes: pending_entries.len(),
        commitment_writes: canonical_index_plan.commitment_entries.len(),
        nullifier_writes: canonical_index_plan.nullifier_entries.len(),
        bridge_replay_writes: canonical_index_plan.bridge_replay_entries.len(),
        ciphertext_index_writes: canonical_index_plan.ciphertext_index_entries.len(),
        ciphertext_archive_writes: canonical_index_plan.ciphertext_archive_entries.len(),
        staged_ciphertext_removals: 0,
    }
}

fn native_canonical_index_repair_manifest(
    canonical_index_plan: &NativeCanonicalIndexPlan,
) -> NativeAtomicCommitManifestAdmissionInput {
    NativeAtomicCommitManifestAdmissionInput {
        kind: NativeAtomicCommitKind::CanonicalIndexRepair,
        action_count: 0,
        planned_action_count: 0,
        chain_block_count: 0,
        height_entry_count: 0,
        pending_entry_count: 0,
        source_commitment_count: canonical_index_plan.commitment_entries.len(),
        source_nullifier_count: canonical_index_plan.nullifier_entries.len(),
        source_bridge_replay_count: canonical_index_plan.bridge_replay_entries.len(),
        source_ciphertext_index_count: canonical_index_plan.ciphertext_index_entries.len(),
        source_ciphertext_archive_count: canonical_index_plan.ciphertext_archive_entries.len(),
        source_staged_ciphertext_removal_count: 0,
        block_record_writes: 0,
        height_index_writes: 0,
        best_pointer_writes: 0,
        canonical_index_cleared: true,
        pending_tree_cleared: false,
        pending_action_removals: 0,
        pending_action_writes: 0,
        commitment_writes: canonical_index_plan.commitment_entries.len(),
        nullifier_writes: canonical_index_plan.nullifier_entries.len(),
        bridge_replay_writes: canonical_index_plan.bridge_replay_entries.len(),
        ciphertext_index_writes: canonical_index_plan.ciphertext_index_entries.len(),
        ciphertext_archive_writes: canonical_index_plan.ciphertext_archive_entries.len(),
        staged_ciphertext_removals: 0,
    }
}

fn native_noncanonical_block_record_manifest() -> NativeAtomicCommitManifestAdmissionInput {
    NativeAtomicCommitManifestAdmissionInput {
        kind: NativeAtomicCommitKind::NoncanonicalBlockRecord,
        action_count: 0,
        planned_action_count: 0,
        chain_block_count: 0,
        height_entry_count: 0,
        pending_entry_count: 0,
        source_commitment_count: 0,
        source_nullifier_count: 0,
        source_bridge_replay_count: 0,
        source_ciphertext_index_count: 0,
        source_ciphertext_archive_count: 0,
        source_staged_ciphertext_removal_count: 0,
        block_record_writes: 1,
        height_index_writes: 0,
        best_pointer_writes: 0,
        canonical_index_cleared: false,
        pending_tree_cleared: false,
        pending_action_removals: 0,
        pending_action_writes: 0,
        commitment_writes: 0,
        nullifier_writes: 0,
        bridge_replay_writes: 0,
        ciphertext_index_writes: 0,
        ciphertext_archive_writes: 0,
        staged_ciphertext_removals: 0,
    }
}

fn flush_native_db_durability_barrier(db: &sled::Db, context: &'static str) -> Result<()> {
    match db.flush() {
        Ok(flushed_bytes) => {
            evaluate_native_storage_durability_admission(NativeStorageDurabilityAdmissionInput {
                transaction_accepted: true,
                durability_flushed: true,
            })
            .map_err(|rejection| native_storage_durability_admission_error(context, rejection))?;
            debug!(
                context,
                flushed_bytes, "native storage durability barrier accepted"
            );
            Ok(())
        }
        Err(err) => {
            let rejection = evaluate_native_storage_durability_admission(
                NativeStorageDurabilityAdmissionInput {
                    transaction_accepted: true,
                    durability_flushed: false,
                },
            )
            .expect_err("failed durability flush must reject");
            Err(native_storage_durability_admission_error(
                context, rejection,
            ))
            .with_context(|| format!("native storage durability flush failed: {err}"))
        }
    }
}

fn evaluate_native_storage_durability_admission(
    input: NativeStorageDurabilityAdmissionInput,
) -> Result<(), NativeStorageDurabilityAdmissionRejection> {
    if !input.transaction_accepted {
        Err(NativeStorageDurabilityAdmissionRejection::TransactionRejected)
    } else if !input.durability_flushed {
        Err(NativeStorageDurabilityAdmissionRejection::DurabilityFlushFailed)
    } else {
        Ok(())
    }
}

fn native_storage_durability_admission_error(
    context: &str,
    rejection: NativeStorageDurabilityAdmissionRejection,
) -> anyhow::Error {
    anyhow!("{context}: {}", rejection.label())
}

fn evaluate_native_canonical_reorg_chain_admission(
    input: NativeCanonicalReorgChainAdmissionInput,
) -> Result<(), NativeCanonicalReorgChainAdmissionRejection> {
    if !input.chain_nonempty {
        Err(NativeCanonicalReorgChainAdmissionRejection::ChainEmpty)
    } else if !input.genesis_matches_expected {
        Err(NativeCanonicalReorgChainAdmissionRejection::GenesisMismatch)
    } else if !input.best_metadata_matches_chain {
        Err(NativeCanonicalReorgChainAdmissionRejection::BestMetadataMismatch)
    } else if !input.canonical_heights_contiguous {
        Err(NativeCanonicalReorgChainAdmissionRejection::CanonicalHeightMismatch)
    } else if !input.canonical_chain_ids_match {
        Err(NativeCanonicalReorgChainAdmissionRejection::ChainIdMismatch)
    } else if !input.canonical_rules_hashes_match {
        Err(NativeCanonicalReorgChainAdmissionRejection::RulesHashMismatch)
    } else if !input.canonical_hashes_match_work_hashes {
        Err(NativeCanonicalReorgChainAdmissionRejection::HashWorkHashMismatch)
    } else if !input.canonical_parent_hashes_contiguous {
        Err(NativeCanonicalReorgChainAdmissionRejection::ParentHashMismatch)
    } else if !input.block_record_count_matches_chain {
        Err(NativeCanonicalReorgChainAdmissionRejection::BlockRecordCountMismatch)
    } else if !input.block_records_match_chain {
        Err(NativeCanonicalReorgChainAdmissionRejection::BlockRecordMismatch)
    } else if !input.height_entry_count_matches_chain {
        Err(NativeCanonicalReorgChainAdmissionRejection::HeightEntryCountMismatch)
    } else if !input.height_entries_match_chain {
        Err(NativeCanonicalReorgChainAdmissionRejection::HeightEntryMismatch)
    } else {
        Ok(())
    }
}

fn native_canonical_reorg_chain_admission_error(
    rejection: NativeCanonicalReorgChainAdmissionRejection,
) -> anyhow::Error {
    anyhow!(
        "native canonical reorg chain admission: {}",
        rejection.label()
    )
}

fn native_canonical_reorg_chain_admission_input(
    chain: &[NativeBlockMeta],
    block_entries: &[([u8; 32], Vec<u8>)],
    height_entries: &[(u64, [u8; 32])],
    best: Option<&NativeBlockMeta>,
    pow_bits: u32,
) -> Result<NativeCanonicalReorgChainAdmissionInput> {
    let expected_genesis = genesis_meta(pow_bits)?;
    let chain_nonempty = !chain.is_empty();
    let genesis_matches_expected = chain
        .first()
        .map(|genesis| genesis == &expected_genesis)
        .unwrap_or(false);
    let best_metadata_matches_chain = match (chain.last(), best) {
        (Some(chain_best), Some(best)) => chain_best == best,
        _ => false,
    };
    let mut canonical_heights_contiguous = true;
    let mut canonical_chain_ids_match = true;
    let mut canonical_rules_hashes_match = true;
    let mut canonical_hashes_match_work_hashes = true;
    let mut canonical_parent_hashes_contiguous = true;
    for (index, meta) in chain.iter().enumerate() {
        if u64::try_from(index).ok() != Some(meta.height) {
            canonical_heights_contiguous = false;
        }
        if meta.chain_id != HEGEMON_CHAIN_ID_V1 {
            canonical_chain_ids_match = false;
        }
        if meta.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_V1 {
            canonical_rules_hashes_match = false;
        }
        if meta.hash != meta.work_hash {
            canonical_hashes_match_work_hashes = false;
        }
        if index > 0 {
            let parent = &chain[index - 1];
            if meta.parent_hash != parent.hash {
                canonical_parent_hashes_contiguous = false;
            }
        }
    }
    let block_record_count_matches_chain = block_entries.len() == chain.len();
    let mut block_records_match_chain = block_record_count_matches_chain;
    if block_records_match_chain {
        for (meta, (hash, encoded)) in chain.iter().zip(block_entries.iter()) {
            let expected = bincode::serialize(meta)?;
            if hash != &meta.hash || encoded != &expected {
                block_records_match_chain = false;
                break;
            }
        }
    }
    let height_entry_count_matches_chain = height_entries.len() == chain.len();
    let height_entries_match_chain = height_entry_count_matches_chain
        && chain
            .iter()
            .zip(height_entries.iter())
            .all(|(meta, entry)| {
                let (height, hash) = entry;
                *height == meta.height && *hash == meta.hash
            });
    Ok(NativeCanonicalReorgChainAdmissionInput {
        chain_nonempty,
        genesis_matches_expected,
        best_metadata_matches_chain,
        canonical_heights_contiguous,
        canonical_chain_ids_match,
        canonical_rules_hashes_match,
        canonical_hashes_match_work_hashes,
        canonical_parent_hashes_contiguous,
        block_record_count_matches_chain,
        block_records_match_chain,
        height_entry_count_matches_chain,
        height_entries_match_chain,
    })
}

fn evaluate_native_block_replay_refinement<'a>(
    input: NativeBlockReplayRefinementInput,
    steps: impl IntoIterator<Item = NativeActionStreamStep<'a>>,
    nullifier_state: &mut NullifierState,
    bridge_replay_state: &mut InboundReplayState,
) -> Result<NativeBlockReplayRefinementSummary, NativeBlockReplayRefinementRejection> {
    let (_trace, result) = evaluate_native_block_replay_refinement_with_trace(
        input,
        steps,
        nullifier_state,
        bridge_replay_state,
    );
    result
}

fn evaluate_native_block_replay_refinement_with_trace<'a>(
    input: NativeBlockReplayRefinementInput,
    steps: impl IntoIterator<Item = NativeActionStreamStep<'a>>,
    nullifier_state: &mut NullifierState,
    bridge_replay_state: &mut InboundReplayState,
) -> (
    Vec<String>,
    Result<NativeBlockReplayRefinementSummary, NativeBlockReplayRefinementRejection>,
) {
    let mut trace = vec!["action_stream_effect".to_owned()];
    let action_effect = match evaluate_native_action_stream_effect(
        input.leaf_start,
        steps,
        nullifier_state,
        bridge_replay_state,
    ) {
        Ok(effect) => effect,
        Err(rejection) => {
            let rejection = native_block_replay_refinement_action_rejection(rejection);
            trace.push(format!("rejected:{}", rejection.label()));
            return (trace, Err(rejection));
        }
    };
    trace.push("expected_supply".to_owned());
    let expected_supply = match expected_native_supply_from_parts(
        input.parent_supply,
        input.height,
        input.fee_total,
        input.has_coinbase,
    ) {
        Some(expected_supply) => expected_supply,
        None => {
            let rejection = NativeBlockReplayRefinementRejection::SupplyDeltaInvalid;
            trace.push(format!("rejected:{}", rejection.label()));
            return (trace, Err(rejection));
        }
    };
    trace.push("block_commitment".to_owned());
    if let Err(rejection) =
        evaluate_native_block_commitment_admission(NativeBlockCommitmentAdmissionInput {
            tx_count_matches: input.tx_count_matches,
            state_root_matches: input.state_root_matches,
            kernel_root_matches: input.kernel_root_matches,
            nullifier_root_matches: input.nullifier_root_matches,
            extrinsics_root_matches: input.extrinsics_root_matches,
            message_root_matches: input.message_root_matches,
            message_count_matches: input.message_count_matches,
            header_mmr_root_matches: input.header_mmr_root_matches,
            header_mmr_len_matches: input.header_mmr_len_matches,
            supply_digest_matches: expected_supply == input.claimed_supply,
        })
    {
        let rejection = native_block_replay_refinement_commitment_rejection(rejection);
        trace.push(format!("rejected:{}", rejection.label()));
        return (trace, Err(rejection));
    }
    trace.push("accepted".to_owned());

    (
        trace,
        Ok(NativeBlockReplayRefinementSummary {
            next_leaf_count: action_effect.next_leaf_count,
            imported_nullifier_count: action_effect.imported_nullifier_count,
            imported_bridge_replay_count: action_effect.imported_bridge_replay_count,
            planned_starts: action_effect.planned_starts,
            expected_supply,
        }),
    )
}

fn expected_native_supply_from_parts(
    parent_supply: u128,
    height: u64,
    fee_total: u64,
    has_coinbase: bool,
) -> Option<u128> {
    let delta = if has_coinbase {
        consensus::reward::block_subsidy(height).checked_add(fee_total)?
    } else {
        0
    };
    parent_supply.checked_add(u128::from(delta))
}

fn native_block_replay_refinement_action_rejection(
    rejection: NativeActionStateEffectRejection,
) -> NativeBlockReplayRefinementRejection {
    match rejection {
        NativeActionStateEffectRejection::CiphertextCountMismatch => {
            NativeBlockReplayRefinementRejection::CiphertextCountMismatch
        }
        NativeActionStateEffectRejection::CommitmentIndexOverflow => {
            NativeBlockReplayRefinementRejection::CommitmentIndexOverflow
        }
        NativeActionStateEffectRejection::NullifierZero => {
            NativeBlockReplayRefinementRejection::NullifierZero
        }
        NativeActionStateEffectRejection::DuplicateNullifier => {
            NativeBlockReplayRefinementRejection::DuplicateNullifier
        }
        NativeActionStateEffectRejection::BridgeReplayDuplicate => {
            NativeBlockReplayRefinementRejection::BridgeReplayDuplicate
        }
    }
}

fn native_block_replay_refinement_commitment_rejection(
    rejection: NativeBlockCommitmentAdmissionRejection,
) -> NativeBlockReplayRefinementRejection {
    match rejection {
        NativeBlockCommitmentAdmissionRejection::TxCountMismatch => {
            NativeBlockReplayRefinementRejection::TxCountMismatch
        }
        NativeBlockCommitmentAdmissionRejection::StateRootMismatch => {
            NativeBlockReplayRefinementRejection::StateRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::KernelRootMismatch => {
            NativeBlockReplayRefinementRejection::KernelRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::NullifierRootMismatch => {
            NativeBlockReplayRefinementRejection::NullifierRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::ExtrinsicsRootMismatch => {
            NativeBlockReplayRefinementRejection::ExtrinsicsRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::MessageRootMismatch => {
            NativeBlockReplayRefinementRejection::MessageRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::MessageCountMismatch => {
            NativeBlockReplayRefinementRejection::MessageCountMismatch
        }
        NativeBlockCommitmentAdmissionRejection::HeaderMmrRootMismatch => {
            NativeBlockReplayRefinementRejection::HeaderMmrRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::HeaderMmrLenMismatch => {
            NativeBlockReplayRefinementRejection::HeaderMmrLenMismatch
        }
        NativeBlockCommitmentAdmissionRejection::SupplyDigestMismatch => {
            NativeBlockReplayRefinementRejection::SupplyDigestMismatch
        }
    }
}

fn native_block_replay_refinement_error(
    context: &'static str,
    rejection: NativeBlockReplayRefinementRejection,
) -> anyhow::Error {
    anyhow!("{context}: {}", rejection.label())
}

fn native_block_replay_supply_parts(actions: &[PendingAction], height: u64) -> Result<(u64, bool)> {
    validate_coinbase_accounting(actions, height)?;
    let has_coinbase = actions.iter().any(is_coinbase_action);
    let fee_total = if has_coinbase {
        checked_transfer_fee_total(actions).ok_or_else(|| anyhow!("block fee total overflow"))?
    } else {
        checked_transfer_fee_total(actions).unwrap_or(0)
    };
    Ok((fee_total, has_coinbase))
}

fn evaluate_native_block_replay_refinement_for_actions(
    context: &'static str,
    da_ciphertext_tree: &sled::Tree,
    state: &NativeState,
    actions: &[PendingAction],
    input: NativeBlockReplayRefinementInput,
) -> Result<NativeBlockReplayRefinementSummary> {
    let materialized = materialize_native_action_payloads(da_ciphertext_tree, actions)?;
    let mut nullifier_state = NullifierState::new(state.nullifiers.clone(), BTreeSet::new());
    let mut bridge_replay_state =
        InboundReplayState::new(state.consumed_bridge_messages.clone(), BTreeSet::new());
    evaluate_native_block_replay_refinement(
        input,
        actions
            .iter()
            .zip(materialized.iter())
            .map(|(action, payload)| NativeActionStreamStep {
                commitment_count: action.commitments.len(),
                ciphertext_count: payload.ciphertexts.len(),
                nullifiers: action.nullifiers.as_slice(),
                replay_key: payload.replay_key,
            }),
        &mut nullifier_state,
        &mut bridge_replay_state,
    )
    .map_err(|rejection| native_block_replay_refinement_error(context, rejection))
}

fn native_block_replay_refinement_input_from_state(
    state: &NativeState,
    height: u64,
    fee_total: u64,
    has_coinbase: bool,
    claimed_supply: u128,
    tx_count_matches: bool,
    state_root_matches: bool,
    kernel_root_matches: bool,
    nullifier_root_matches: bool,
    extrinsics_root_matches: bool,
    message_root_matches: bool,
    message_count_matches: bool,
    header_mmr_root_matches: bool,
    header_mmr_len_matches: bool,
) -> NativeBlockReplayRefinementInput {
    NativeBlockReplayRefinementInput {
        leaf_start: state.commitment_tree.leaf_count(),
        parent_supply: state.best.supply_digest,
        height,
        fee_total,
        has_coinbase,
        claimed_supply,
        tx_count_matches,
        state_root_matches,
        kernel_root_matches,
        nullifier_root_matches,
        extrinsics_root_matches,
        message_root_matches,
        message_count_matches,
        header_mmr_root_matches,
        header_mmr_len_matches,
    }
}

fn block_action_hashes_match(actions: &[PendingAction]) -> bool {
    actions
        .iter()
        .all(|action| action.tx_hash == pending_action_hash(action))
}

fn block_action_hashes_unique(actions: &[PendingAction]) -> bool {
    let mut seen = BTreeSet::new();
    actions.iter().all(|action| seen.insert(action.tx_hash))
}

fn block_action_semantic_hashes_unique(actions: &[PendingAction]) -> bool {
    let mut seen = BTreeSet::new();
    actions
        .iter()
        .all(|action| seen.insert(pending_action_semantic_hash(action)))
}

fn validate_block_actions_locked(state: &NativeState, actions: &[PendingAction]) -> Result<()> {
    let mut validation_state = evaluate_native_block_action_validation_start(
        true,
        block_action_hashes_match(actions),
        block_action_hashes_unique(actions),
        state.consumed_bridge_messages.clone(),
    )
    .map_err(|rejection| match rejection {
        NativeBlockActionValidationRejection::ActionCountMismatch => {
            native_action_hash_admission_error(
                NativeActionHashAdmissionRejection::ActionCountMismatch,
            )
        }
        NativeBlockActionValidationRejection::ActionHashMismatch => {
            native_action_hash_admission_error(
                NativeActionHashAdmissionRejection::ActionHashMismatch,
            )
        }
        NativeBlockActionValidationRejection::DuplicateActionHash => {
            native_action_hash_admission_error(
                NativeActionHashAdmissionRejection::DuplicateActionHash,
            )
        }
        _ => native_block_action_validation_error(rejection),
    })?;
    if !block_action_semantic_hashes_unique(actions) {
        return Err(anyhow!("duplicate semantic action in block"));
    }
    let mut nullifier_state = NullifierState::new(state.nullifiers.clone(), BTreeSet::new());
    for action in actions {
        let scope_input = native_action_scope_admission_input(action);
        let route_preview = evaluate_native_action_scope_admission(scope_input);
        let mut payload_error = None;
        let mut bridge_replay_key = None;
        let mut transfer_key = [0u8; 32];
        let mut transfer_state_input = NativeTransferStateAdmissionInput {
            anchor_known: true,
            nullifier_state: NativeTransferNullifierAdmissionState::Valid,
            commitments_nonzero: true,
            sidecar_route: false,
            sidecar_ciphertexts_available: true,
            sidecar_ciphertext_sizes_present: true,
            sidecar_ciphertext_sizes_match: true,
        };

        if let Ok(route) = route_preview {
            match route {
                NativeActionScopeAdmissionRoute::Bridge => {
                    if let Err(err) = validate_bridge_action_payload(action) {
                        payload_error = Some(err);
                    } else {
                        bridge_replay_key = bridge_inbound_replay_key_from_action(action)?;
                    }
                }
                NativeActionScopeAdmissionRoute::CandidateArtifact => {
                    if let Err(err) = validate_candidate_action_payload(action) {
                        payload_error = Some(err);
                    }
                }
                NativeActionScopeAdmissionRoute::Coinbase => {
                    if let Err(err) = validate_coinbase_action_payload(action) {
                        payload_error = Some(err);
                    }
                }
                NativeActionScopeAdmissionRoute::Transfer => {
                    validate_transfer_action_payload(action)?;
                    transfer_key = action_order_key(action);
                    transfer_state_input = native_transfer_state_admission_input_for_block(
                        state,
                        &mut nullifier_state,
                        action,
                    );
                }
            }
        }

        let helper_result = evaluate_native_block_action_validation_step(
            &mut validation_state,
            NativeBlockActionValidationStep {
                scope_input,
                payload_valid: payload_error.is_none(),
                transfer_key,
                transfer_state_input,
                bridge_replay_key,
            },
        );
        if let Err(rejection) = helper_result {
            if let Err(scope_rejection) = route_preview {
                return Err(native_action_scope_admission_error(scope_rejection));
            }
            if matches!(
                rejection,
                NativeBlockActionValidationRejection::BridgePayloadInvalid
                    | NativeBlockActionValidationRejection::CandidatePayloadInvalid
                    | NativeBlockActionValidationRejection::CoinbasePayloadInvalid
                    | NativeBlockActionValidationRejection::TransferPayloadInvalid
            ) {
                return Err(payload_error
                    .unwrap_or_else(|| native_block_action_validation_error(rejection)));
            }
            if rejection == NativeBlockActionValidationRejection::BridgeReplayDuplicate {
                return Err(anyhow!("duplicate inbound bridge message in block"));
            }
            if rejection == NativeBlockActionValidationRejection::TransferOrderInvalid {
                return Err(anyhow!(
                    "shielded transfer actions are not in canonical order"
                ));
            }
            if let Some(transfer_rejection) =
                native_block_action_validation_transfer_state_rejection(rejection)
            {
                return Err(native_transfer_state_admission_error(
                    NativeTransferStateAdmissionContext::Block,
                    transfer_rejection,
                ));
            }
            return Err(native_block_action_validation_error(rejection));
        }
    }
    Ok(())
}

fn materialize_native_action_payloads(
    da_ciphertext_tree: &sled::Tree,
    actions: &[PendingAction],
) -> Result<Vec<NativeMaterializedActionPayload>> {
    actions
        .iter()
        .map(|action| {
            Ok(NativeMaterializedActionPayload {
                ciphertexts: canonical_ciphertexts_for_action(da_ciphertext_tree, action)?,
                replay_key: bridge_inbound_replay_key_from_action(action)?,
            })
        })
        .collect()
}

fn plan_materialized_action_effects(
    da_ciphertext_tree: &sled::Tree,
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<Vec<NativePlannedActionEffect>> {
    let mut bridge_replay_state =
        InboundReplayState::new(state.consumed_bridge_messages.clone(), BTreeSet::new());
    let mut nullifier_state = NullifierState::new(state.nullifiers.clone(), BTreeSet::new());
    let materialized = materialize_native_action_payloads(da_ciphertext_tree, actions)?;

    let stream = evaluate_native_action_stream_effect(
        state.commitment_tree.leaf_count(),
        actions
            .iter()
            .zip(materialized.iter())
            .map(|(action, payload)| NativeActionStreamStep {
                commitment_count: action.commitments.len(),
                ciphertext_count: payload.ciphertexts.len(),
                nullifiers: action.nullifiers.as_slice(),
                replay_key: payload.replay_key,
            }),
        &mut nullifier_state,
        &mut bridge_replay_state,
    )
    .map_err(native_action_state_effect_error)?;
    evaluate_native_action_plan_application_admission(
        state.commitment_tree.leaf_count(),
        &action_commitment_counts(actions),
        &stream.planned_starts,
    )
    .map_err(|rejection| {
        native_action_plan_application_admission_error(
            "native materialized action plan construction",
            rejection,
        )
    })?;

    let planned = stream
        .planned_starts
        .into_iter()
        .zip(materialized)
        .map(|(commitment_start, payload)| NativePlannedActionEffect {
            commitment_start,
            ciphertexts: payload.ciphertexts,
            replay_key: payload.replay_key,
        })
        .collect::<Vec<_>>();
    admit_native_action_wire_replay_projection(
        "native materialized action wire replay projection",
        actions,
        &planned,
    )?;

    Ok(planned)
}

fn apply_actions_to_memory(
    da_ciphertext_tree: &sled::Tree,
    state: &mut NativeState,
    actions: &[PendingAction],
) -> Result<()> {
    let planned = plan_materialized_action_effects(da_ciphertext_tree, state, actions)?;
    apply_planned_actions_to_memory(state, actions, &planned)
}

fn apply_planned_actions_to_memory(
    state: &mut NativeState,
    actions: &[PendingAction],
    planned: &[NativePlannedActionEffect],
) -> Result<()> {
    let mut leaf_cursor = state.commitment_tree.leaf_count();
    admit_native_action_plan_application(
        "native memory action plan application",
        leaf_cursor,
        actions,
        planned,
    )?;
    admit_native_action_wire_replay_projection(
        "native memory action wire replay projection",
        actions,
        planned,
    )?;
    for (action, effect) in actions.iter().zip(planned.iter()) {
        for (offset, commitment) in action.commitments.iter().enumerate() {
            let offset = u64::try_from(offset)
                .map_err(|_| anyhow!("native memory commitment offset overflow"))?;
            let expected_index = effect
                .commitment_start
                .checked_add(offset)
                .ok_or_else(|| anyhow!("native memory commitment index overflow"))?;
            if expected_index != leaf_cursor || expected_index != state.commitment_tree.leaf_count()
            {
                return Err(anyhow!(
                    "native memory action plan drift: expected leaf {} observed {}",
                    expected_index,
                    state.commitment_tree.leaf_count()
                ));
            }
            state
                .commitment_tree
                .append(*commitment)
                .map_err(|err| anyhow!("append native commitment failed: {err}"))?;
            leaf_cursor = leaf_cursor
                .checked_add(1)
                .ok_or_else(|| anyhow!("native memory commitment leaf overflow"))?;
        }
        for nullifier in &action.nullifiers {
            state.nullifiers.insert(*nullifier);
        }
        if let Some(replay_key) = effect.replay_key {
            state.consumed_bridge_messages.insert(replay_key);
        }
        clear_staged_ciphertext_markers(state, action);
        state.pending_actions.remove(&action.tx_hash);
    }
    Ok(())
}

fn clear_staged_ciphertext_markers(state: &mut NativeState, action: &PendingAction) {
    for hash in &action.ciphertext_hashes {
        state.staged_ciphertexts.remove(&hex48(hash));
    }
}

fn plan_canonical_index_rebuild(
    chain: &[NativeBlockMeta],
    da_ciphertext_tree: &sled::Tree,
) -> Result<NativeCanonicalIndexPlan> {
    let mut nullifier_state = NullifierState::default();
    let mut bridge_replay_state = InboundReplayState::default();
    let mut decoded_actions = Vec::new();
    for meta in chain.iter().skip(1) {
        let actions = decode_block_actions(meta)?;
        decoded_actions.extend(actions);
    }
    let materialized = materialize_native_action_payloads(da_ciphertext_tree, &decoded_actions)?;
    let planned_actions = decoded_actions
        .into_iter()
        .zip(materialized)
        .collect::<Vec<_>>();

    let stream = evaluate_native_action_stream_effect(
        0,
        planned_actions
            .iter()
            .map(|(action, payload)| NativeActionStreamStep {
                commitment_count: action.commitments.len(),
                ciphertext_count: payload.ciphertexts.len(),
                nullifiers: action.nullifiers.as_slice(),
                replay_key: payload.replay_key,
            }),
        &mut nullifier_state,
        &mut bridge_replay_state,
    )
    .map_err(native_action_state_effect_error)?;
    let rebuild_commitment_counts = planned_actions
        .iter()
        .map(|(action, _)| action.commitments.len())
        .collect::<Vec<_>>();
    evaluate_native_action_plan_application_admission(
        0,
        &rebuild_commitment_counts,
        &stream.planned_starts,
    )
    .map_err(|rejection| {
        native_action_plan_application_admission_error(
            "native canonical index rebuild action plan",
            rejection,
        )
    })?;

    let mut plan = NativeCanonicalIndexPlan {
        commitment_entries: Vec::new(),
        nullifier_entries: Vec::new(),
        bridge_replay_entries: Vec::new(),
        ciphertext_index_entries: Vec::new(),
        ciphertext_archive_entries: Vec::new(),
    };

    let planned_effects = planned_actions
        .iter()
        .zip(stream.planned_starts.iter().copied())
        .map(
            |((_, payload), commitment_start)| NativePlannedActionEffect {
                commitment_start,
                ciphertexts: payload.ciphertexts.clone(),
                replay_key: payload.replay_key,
            },
        )
        .collect::<Vec<_>>();
    let replay_projection_actions = planned_actions
        .iter()
        .map(|(action, _)| action.clone())
        .collect::<Vec<_>>();
    admit_native_action_wire_replay_projection(
        "native canonical index rebuild wire replay projection",
        &replay_projection_actions,
        &planned_effects,
    )?;

    for ((action, payload), effect) in planned_actions.into_iter().zip(planned_effects.into_iter())
    {
        let commitment_start = effect.commitment_start;
        for (offset, commitment) in action.commitments.iter().enumerate() {
            let offset =
                u64::try_from(offset).map_err(|_| anyhow!("commitment rebuild offset overflow"))?;
            let index = commitment_start
                .checked_add(offset)
                .ok_or_else(|| anyhow!("commitment rebuild index overflow"))?;
            plan.commitment_entries.push((index, *commitment));
        }
        for (offset, bytes) in payload.ciphertexts.into_iter().enumerate() {
            let offset =
                u64::try_from(offset).map_err(|_| anyhow!("ciphertext archive offset overflow"))?;
            let index = commitment_start
                .checked_add(offset)
                .ok_or_else(|| anyhow!("ciphertext archive index overflow"))?;
            plan.ciphertext_archive_entries.push((index, bytes));
        }
        for nullifier in &action.nullifiers {
            plan.nullifier_entries.push(*nullifier);
        }
        if let Some(replay_key) = payload.replay_key {
            plan.bridge_replay_entries.push(replay_key);
        }
        for (idx, hash) in action.ciphertext_hashes.iter().enumerate() {
            let idx_u64 =
                u64::try_from(idx).map_err(|_| anyhow!("ciphertext index offset overflow"))?;
            let size = action
                .ciphertext_sizes
                .get(idx)
                .copied()
                .unwrap_or_default();
            let mut value = Vec::with_capacity(32 + 4 + 8);
            value.extend_from_slice(&action.tx_hash);
            value.extend_from_slice(&size.to_le_bytes());
            value.extend_from_slice(&idx_u64.to_le_bytes());
            plan.ciphertext_index_entries.push((*hash, value));
        }
    }
    Ok(plan)
}

fn canonical_ciphertexts_for_action(
    da_ciphertext_tree: &sled::Tree,
    action: &PendingAction,
) -> Result<Vec<Vec<u8>>> {
    match (action.family_id, action.action_id) {
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE) => {
            let args: ShieldedTransferInlineArgs =
                decode_scale_exact(&action.public_args, "shielded inline action args")?;
            args.ciphertexts
                .iter()
                .map(encrypted_note_da_bytes)
                .collect()
        }
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_SIDECAR) => action
            .ciphertext_hashes
            .iter()
            .enumerate()
            .map(|(idx, hash)| {
                let bytes = da_ciphertext_tree
                    .get(hash.as_slice())?
                    .map(|bytes| bytes.to_vec())
                    .ok_or_else(|| anyhow!("missing canonical DA ciphertext {}", hex48(hash)))?;
                if bytes.len() > MAX_CIPHERTEXT_BYTES {
                    return Err(anyhow!(
                        "canonical DA ciphertext {} exceeds limit {}",
                        hex48(hash),
                        MAX_CIPHERTEXT_BYTES
                    ));
                }
                let expected_size = action
                    .ciphertext_sizes
                    .get(idx)
                    .copied()
                    .ok_or_else(|| anyhow!("missing canonical DA ciphertext size"))?;
                if bytes.len() != expected_size as usize {
                    return Err(anyhow!(
                        "canonical DA ciphertext size mismatch: expected {} observed {}",
                        expected_size,
                        bytes.len()
                    ));
                }
                let observed_hash = ciphertext_hash_bytes(&bytes);
                if observed_hash != *hash {
                    return Err(anyhow!(
                        "canonical DA ciphertext hash mismatch: expected {} observed {}",
                        hex48(hash),
                        hex48(&observed_hash)
                    ));
                }
                Ok(bytes)
            })
            .collect(),
        (FAMILY_SHIELDED_POOL, ACTION_MINT_COINBASE) => {
            let args: MintCoinbaseArgs =
                decode_scale_exact(&action.public_args, "coinbase action args")?;
            Ok(vec![encrypted_note_da_bytes(
                &args.reward_bundle.miner_note.encrypted_note,
            )?])
        }
        _ => Ok(Vec::new()),
    }
}

fn plan_pending_action_effects(
    da_ciphertext_tree: &sled::Tree,
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<Vec<NativePlannedActionEffect>> {
    plan_materialized_action_effects(da_ciphertext_tree, state, actions)
}

fn action_hashes_from_chain(chain: &[NativeBlockMeta]) -> Result<BTreeSet<[u8; 32]>> {
    let mut hashes = BTreeSet::new();
    for meta in chain.iter().skip(1) {
        for action in decode_block_actions(meta)? {
            hashes.insert(action.tx_hash);
        }
    }
    Ok(hashes)
}

fn orphaned_actions(
    old_chain: &[NativeBlockMeta],
    new_action_hashes: &BTreeSet<[u8; 32]>,
) -> Result<Vec<PendingAction>> {
    let mut actions = Vec::new();
    for meta in old_chain.iter().skip(1) {
        for action in decode_block_actions(meta)? {
            if !new_action_hashes.contains(&action.tx_hash) {
                actions.push(action);
            }
        }
    }
    Ok(actions)
}

fn revalidate_reorg_pending_actions(
    canonical_state: &NativeState,
    existing_pending: BTreeMap<[u8; 32], PendingAction>,
    orphaned_actions: Vec<PendingAction>,
) -> BTreeMap<[u8; 32], PendingAction> {
    let mut staged_state = NativeState {
        best: canonical_state.best.clone(),
        pending_actions: BTreeMap::new(),
        commitment_tree: canonical_state.commitment_tree.clone(),
        nullifiers: canonical_state.nullifiers.clone(),
        consumed_bridge_messages: canonical_state.consumed_bridge_messages.clone(),
        staged_ciphertexts: canonical_state.staged_ciphertexts.clone(),
        staged_proofs: canonical_state.staged_proofs.clone(),
    };

    for (hash, action) in existing_pending {
        stage_reorg_pending_action(&mut staged_state, hash, action, "existing");
    }
    for action in orphaned_actions {
        let hash = action.tx_hash;
        if staged_state.pending_actions.contains_key(&hash) {
            continue;
        }
        stage_reorg_pending_action(&mut staged_state, hash, action, "orphaned");
    }

    staged_state.pending_actions
}

fn stage_reorg_pending_action(
    staged_state: &mut NativeState,
    hash: [u8; 32],
    action: PendingAction,
    source: &'static str,
) {
    if staged_state.pending_actions.len() >= MAX_NATIVE_MEMPOOL_ACTIONS {
        debug!(
            tx_hash = %hex32(&hash),
            source,
            "dropping reorg pending action over mempool action cap"
        );
        return;
    }
    if let Err(err) = validate_pending_action_against_mempool_state(staged_state, &action) {
        debug!(
            tx_hash = %hex32(&hash),
            source,
            error = %err,
            "dropping semantically invalid pending action during reorg"
        );
        return;
    }
    if let Err(err) = validate_mempool_byte_budget(
        &staged_state.pending_actions,
        &action,
        MAX_NATIVE_MEMPOOL_ACTION_BYTES,
    ) {
        debug!(
            tx_hash = %hex32(&hash),
            source,
            error = %err,
            "dropping over-budget pending action during reorg"
        );
        return;
    }
    staged_state.pending_actions.insert(hash, action);
}

fn validate_coinbase_accounting(actions: &[PendingAction], height: u64) -> Result<()> {
    evaluate_native_coinbase_accounting_admission(native_coinbase_accounting_admission_input(
        actions, height,
    ))
    .map_err(native_coinbase_accounting_admission_error)
}

fn native_block_supply_delta(actions: &[PendingAction], height: u64) -> Result<u128> {
    if actions.iter().any(is_coinbase_action) {
        return expected_coinbase_amount(actions, height).map(u128::from);
    }
    Ok(0)
}

fn advance_native_supply_digest(
    parent_supply: u128,
    actions: &[PendingAction],
    height: u64,
) -> Result<u128> {
    let delta = native_block_supply_delta(actions, height)?;
    parent_supply
        .checked_add(delta)
        .ok_or_else(|| anyhow!("native supply digest overflow"))
}

fn expected_coinbase_amount(actions: &[PendingAction], height: u64) -> Result<u64> {
    let fees =
        checked_transfer_fee_total(actions).ok_or_else(|| anyhow!("block fee total overflow"))?;
    consensus::reward::block_subsidy(height)
        .checked_add(fees)
        .ok_or_else(|| anyhow!("coinbase reward overflow"))
}

fn checked_transfer_fee_total(actions: &[PendingAction]) -> Option<u64> {
    actions
        .iter()
        .filter(|action| is_shielded_transfer_action(action))
        .try_fold(0u64, |acc, action| acc.checked_add(action.fee))
}

fn native_coinbase_accounting_admission_input(
    actions: &[PendingAction],
    height: u64,
) -> NativeCoinbaseAccountingAdmissionInput {
    let coinbase_actions = actions
        .iter()
        .filter(|action| is_coinbase_action(action))
        .collect::<Vec<_>>();
    let observed_coinbase_amount = if coinbase_actions.len() == 1 {
        coinbase_action_amount(coinbase_actions[0]).ok()
    } else {
        None
    };
    NativeCoinbaseAccountingAdmissionInput {
        coinbase_count: coinbase_actions.len(),
        height,
        transfer_fee_total: checked_transfer_fee_total(actions),
        observed_coinbase_amount,
    }
}

#[cfg(test)]
fn expected_coinbase_amount_from_input(
    input: NativeCoinbaseAccountingAdmissionInput,
) -> Option<u64> {
    let fees = input.transfer_fee_total?;
    consensus::reward::block_subsidy(input.height).checked_add(fees)
}

fn evaluate_native_coinbase_accounting_admission(
    input: NativeCoinbaseAccountingAdmissionInput,
) -> Result<(), NativeCoinbaseAccountingAdmissionRejection> {
    if input.coinbase_count > 1 {
        Err(NativeCoinbaseAccountingAdmissionRejection::MultipleCoinbase)
    } else if input.coinbase_count == 0 {
        Ok(())
    } else {
        let Some(fees) = input.transfer_fee_total else {
            return Err(NativeCoinbaseAccountingAdmissionRejection::FeeTotalOverflow);
        };
        let Some(expected) = consensus::reward::block_subsidy(input.height).checked_add(fees)
        else {
            return Err(NativeCoinbaseAccountingAdmissionRejection::RewardOverflow);
        };
        let Some(observed) = input.observed_coinbase_amount else {
            return Err(NativeCoinbaseAccountingAdmissionRejection::CoinbaseAmountMissing);
        };
        if observed == expected {
            Ok(())
        } else {
            Err(NativeCoinbaseAccountingAdmissionRejection::AmountMismatch)
        }
    }
}

fn native_coinbase_accounting_admission_error(
    rejection: NativeCoinbaseAccountingAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeCoinbaseAccountingAdmissionRejection::MultipleCoinbase => {
            anyhow!("block contains multiple coinbase actions")
        }
        NativeCoinbaseAccountingAdmissionRejection::FeeTotalOverflow => {
            anyhow!("block fee total overflow")
        }
        NativeCoinbaseAccountingAdmissionRejection::RewardOverflow => {
            anyhow!("coinbase reward overflow")
        }
        NativeCoinbaseAccountingAdmissionRejection::CoinbaseAmountMissing => {
            anyhow!("coinbase action amount unavailable")
        }
        NativeCoinbaseAccountingAdmissionRejection::AmountMismatch => {
            anyhow!("coinbase amount mismatch")
        }
    }
}

fn coinbase_action_amount(action: &PendingAction) -> Result<u64> {
    let args: MintCoinbaseArgs = decode_scale_exact(&action.public_args, "coinbase action args")?;
    Ok(args.reward_bundle.miner_note.amount)
}

fn native_candidate_artifact_coupling_admission_input(
    transfer_count: usize,
    candidate_artifacts: &[&CandidateArtifact],
) -> NativeCandidateArtifactCouplingAdmissionInput {
    NativeCandidateArtifactCouplingAdmissionInput {
        transfer_count,
        candidate_artifact_count: candidate_artifacts.len(),
        candidate_tx_count_matches: candidate_artifacts
            .first()
            .filter(|_| candidate_artifacts.len() == 1)
            .and_then(|artifact| usize::try_from(artifact.tx_count).ok())
            == Some(transfer_count),
    }
}

fn evaluate_native_candidate_artifact_coupling_admission(
    input: NativeCandidateArtifactCouplingAdmissionInput,
) -> Result<(), NativeCandidateArtifactCouplingAdmissionRejection> {
    if input.transfer_count == 0 {
        if input.candidate_artifact_count == 0 {
            Ok(())
        } else {
            Err(NativeCandidateArtifactCouplingAdmissionRejection::CandidateWithoutTransfers)
        }
    } else if input.candidate_artifact_count != 1 {
        Err(NativeCandidateArtifactCouplingAdmissionRejection::MissingOrMultipleCandidateArtifact)
    } else if !input.candidate_tx_count_matches {
        Err(NativeCandidateArtifactCouplingAdmissionRejection::CandidateTxCountMismatch)
    } else {
        Ok(())
    }
}

fn native_candidate_artifact_coupling_admission_error(
    rejection: NativeCandidateArtifactCouplingAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeCandidateArtifactCouplingAdmissionRejection::CandidateWithoutTransfers => {
            anyhow!("candidate artifact action requires shielded transfer actions")
        }
        NativeCandidateArtifactCouplingAdmissionRejection::MissingOrMultipleCandidateArtifact => {
            anyhow!(
                "non-empty shielded block requires exactly one matching recursive candidate artifact"
            )
        }
        NativeCandidateArtifactCouplingAdmissionRejection::CandidateTxCountMismatch => {
            anyhow!("candidate artifact tx_count mismatch")
        }
    }
}

fn evaluate_native_tx_leaf_action_binding_admission(
    input: NativeTxLeafActionBindingAdmissionInput,
) -> Result<(), NativeTxLeafActionBindingAdmissionRejection> {
    if !input.nullifiers_match {
        Err(NativeTxLeafActionBindingAdmissionRejection::NullifiersMismatch)
    } else if !input.commitments_match {
        Err(NativeTxLeafActionBindingAdmissionRejection::CommitmentsMismatch)
    } else if !input.ciphertext_hashes_match {
        Err(NativeTxLeafActionBindingAdmissionRejection::CiphertextHashesMismatch)
    } else if !input.input_count_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::InputCountMismatch)
    } else if !input.output_count_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::OutputCountMismatch)
    } else if !input.version_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::VersionMismatch)
    } else if !input.fee_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::FeeMismatch)
    } else if !input.stablecoin_payload_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::StablecoinPayloadMismatch)
    } else if !input.balance_tag_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::BalanceTagMismatch)
    } else if !input.receipt_statement_hash_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::ReceiptStatementHashMismatch)
    } else if !input.public_inputs_digest_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::PublicInputsDigestMismatch)
    } else if !input.proof_digest_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::ProofDigestMismatch)
    } else if !input.proof_backend_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::ProofBackendMismatch)
    } else if !input.ciphertext_payload_hashes_match {
        Err(NativeTxLeafActionBindingAdmissionRejection::CiphertextPayloadHashMismatch)
    } else {
        Ok(())
    }
}

fn native_tx_leaf_action_binding_admission_error(
    rejection: NativeTxLeafActionBindingAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeTxLeafActionBindingAdmissionRejection::NullifiersMismatch => {
            anyhow!("native tx-leaf nullifiers mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::CommitmentsMismatch => {
            anyhow!("native tx-leaf commitments mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::CiphertextHashesMismatch => {
            anyhow!("native tx-leaf ciphertext hashes mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::InputCountMismatch => {
            anyhow!("native tx-leaf input count mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::OutputCountMismatch => {
            anyhow!("native tx-leaf output count mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::VersionMismatch => {
            anyhow!("native tx-leaf version mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::FeeMismatch => {
            anyhow!("native tx-leaf fee mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::StablecoinPayloadMismatch => {
            anyhow!("native tx-leaf stablecoin payload mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::BalanceTagMismatch => {
            anyhow!("native tx-leaf balance tag mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::ReceiptStatementHashMismatch => {
            anyhow!("native tx-leaf receipt statement hash mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::PublicInputsDigestMismatch => {
            anyhow!("native tx-leaf public inputs digest mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::ProofDigestMismatch => {
            anyhow!("native tx-leaf proof digest mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::ProofBackendMismatch => {
            anyhow!("native tx-leaf proof backend/profile mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::CiphertextPayloadHashMismatch => {
            anyhow!("native tx ciphertext payload hash mismatch")
        }
    }
}

fn native_tx_leaf_active_flag_count(flags: &[u8]) -> Option<usize> {
    let mut count = 0usize;
    for flag in flags {
        match *flag {
            0 => {}
            1 => count = count.checked_add(1)?,
            _ => return None,
        }
    }
    Some(count)
}

fn native_tx_leaf_decode_signed_magnitude(sign: u8, magnitude: u64, label: &str) -> Result<i128> {
    match sign {
        0 => Ok(i128::from(magnitude)),
        1 => Ok(-i128::from(magnitude)),
        other => Err(anyhow!("{label} sign flag must be 0 or 1, got {other}")),
    }
}

fn native_tx_leaf_statement_hash_from_decoded(
    decoded: &consensus::backend_interface::NativeTxLeafArtifact,
) -> Result<[u8; 48]> {
    let value_balance = native_tx_leaf_decode_signed_magnitude(
        decoded.stark_public_inputs.value_balance_sign,
        decoded.stark_public_inputs.value_balance_magnitude,
        "value_balance",
    )?;
    let stablecoin_issuance = native_tx_leaf_decode_signed_magnitude(
        decoded.stark_public_inputs.stablecoin_issuance_sign,
        decoded.stark_public_inputs.stablecoin_issuance_magnitude,
        "stablecoin_issuance",
    )?;
    consensus::backend_interface::transaction_statement_hash_from_parts(
        &decoded.stark_public_inputs.merkle_root,
        &decoded.tx.nullifiers,
        &decoded.tx.commitments,
        &decoded.tx.ciphertext_hashes,
        decoded.stark_public_inputs.fee,
        value_balance,
        &decoded.tx.balance_tag,
        decoded.tx.version.circuit,
        decoded.tx.version.crypto,
        decoded.stark_public_inputs.stablecoin_enabled,
        decoded.stark_public_inputs.stablecoin_asset_id,
        &decoded.stark_public_inputs.stablecoin_policy_hash,
        &decoded.stark_public_inputs.stablecoin_oracle_commitment,
        &decoded
            .stark_public_inputs
            .stablecoin_attestation_commitment,
        stablecoin_issuance,
        decoded.stark_public_inputs.stablecoin_policy_version,
    )
    .map_err(|err| anyhow!("derive native tx-leaf statement hash failed: {err}"))
}

fn transfer_action_stablecoin_binding(
    action: &PendingAction,
) -> Result<Option<StablecoinPolicyBinding>> {
    match action.action_id {
        ACTION_SHIELDED_TRANSFER_INLINE => {
            let args: ShieldedTransferInlineArgs =
                decode_scale_exact(&action.public_args, "shielded inline action args")?;
            Ok(args.stablecoin)
        }
        ACTION_SHIELDED_TRANSFER_SIDECAR => {
            let args: ShieldedTransferSidecarArgs =
                decode_scale_exact(&action.public_args, "shielded sidecar action args")?;
            Ok(args.stablecoin)
        }
        _ => Err(anyhow!("action is not a shielded transfer")),
    }
}

fn native_tx_leaf_action_binding_admission_input(
    decoded: &consensus::backend_interface::NativeTxLeafArtifact,
    action: &PendingAction,
    tx: &Transaction,
) -> NativeTxLeafActionBindingAdmissionInput {
    let input_count = native_tx_leaf_active_flag_count(&decoded.stark_public_inputs.input_flags);
    let output_count = native_tx_leaf_active_flag_count(&decoded.stark_public_inputs.output_flags);
    let expected_backend = protocol_versioning::tx_proof_backend_for_version(decoded.tx.version)
        .unwrap_or(protocol_versioning::DEFAULT_TX_PROOF_BACKEND);
    let expected_statement_hash = native_tx_leaf_statement_hash_from_decoded(decoded).ok();
    let expected_public_inputs_digest =
        consensus::backend_interface::transaction_public_inputs_digest_from_serialized(
            &decoded.stark_public_inputs,
        )
        .ok();
    let expected_proof_digest = transaction_circuit::proof::transaction_proof_digest_from_parts(
        decoded.proof_backend,
        &decoded.stark_proof,
    );
    let stablecoin_payload_matches = match (
        native_tx_leaf_artifact_stablecoin_binding(decoded),
        transfer_action_stablecoin_binding(action),
    ) {
        (Ok(decoded), Ok(action)) => decoded == action,
        _ => false,
    };
    NativeTxLeafActionBindingAdmissionInput {
        nullifiers_match: decoded.tx.nullifiers == action.nullifiers,
        commitments_match: decoded.tx.commitments == action.commitments,
        ciphertext_hashes_match: decoded.tx.ciphertext_hashes == action.ciphertext_hashes,
        input_count_matches: input_count == Some(action.nullifiers.len())
            && input_count == Some(decoded.tx.nullifiers.len()),
        output_count_matches: output_count == Some(action.commitments.len())
            && output_count == Some(action.ciphertext_hashes.len())
            && output_count == Some(decoded.tx.commitments.len())
            && output_count == Some(decoded.tx.ciphertext_hashes.len()),
        version_matches: decoded.tx.version == action.binding.into(),
        fee_matches: decoded.stark_public_inputs.fee == action.fee,
        stablecoin_payload_matches,
        balance_tag_matches: tx.balance_tag == decoded.tx.balance_tag,
        receipt_statement_hash_matches: expected_statement_hash
            == Some(decoded.receipt.statement_hash),
        public_inputs_digest_matches: expected_public_inputs_digest
            == Some(decoded.receipt.public_inputs_digest),
        proof_digest_matches: decoded.receipt.proof_digest == expected_proof_digest,
        proof_backend_matches: decoded.proof_backend == expected_backend
            && decoded.receipt.verifier_profile
                == consensus::proof_interface::experimental_native_tx_leaf_verifier_profile(),
        ciphertext_payload_hashes_match: tx.ciphertext_hashes == action.ciphertext_hashes,
    }
}

fn evaluate_native_candidate_artifact_binding_admission(
    input: NativeCandidateArtifactBindingAdmissionInput,
) -> Result<(), NativeCandidateArtifactBindingAdmissionRejection> {
    if !input.da_root_matches {
        Err(NativeCandidateArtifactBindingAdmissionRejection::DaRootMismatch)
    } else if !input.tx_statements_commitment_matches {
        Err(NativeCandidateArtifactBindingAdmissionRejection::TxStatementCommitmentMismatch)
    } else if !input.recursive_state_root_matches {
        Err(NativeCandidateArtifactBindingAdmissionRejection::RecursiveStateRootMismatch)
    } else {
        Ok(())
    }
}

fn native_candidate_artifact_binding_admission_error(
    rejection: NativeCandidateArtifactBindingAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeCandidateArtifactBindingAdmissionRejection::DaRootMismatch => {
            anyhow!("candidate artifact DA root mismatch")
        }
        NativeCandidateArtifactBindingAdmissionRejection::TxStatementCommitmentMismatch => {
            anyhow!("candidate artifact tx statement commitment mismatch")
        }
        NativeCandidateArtifactBindingAdmissionRejection::RecursiveStateRootMismatch => {
            anyhow!("native recursive block state root mismatch")
        }
    }
}

fn verify_native_block_artifacts_locked(
    node: &NativeNode,
    state: &NativeState,
    actions: &[PendingAction],
    meta: &NativeBlockMeta,
) -> Result<()> {
    let transfer_count = actions
        .iter()
        .filter(|action| is_shielded_transfer_action(action))
        .count();
    let candidate_artifacts = actions
        .iter()
        .filter(|action| is_candidate_artifact_action(action))
        .filter_map(|action| action.candidate_artifact.as_ref())
        .collect::<Vec<_>>();
    let coupling_input =
        native_candidate_artifact_coupling_admission_input(transfer_count, &candidate_artifacts);
    if let Err(rejection) = evaluate_native_candidate_artifact_coupling_admission(coupling_input) {
        return Err(native_candidate_artifact_coupling_admission_error(
            rejection,
        ));
    }
    if transfer_count == 0 {
        return Ok(());
    }

    let [artifact] = candidate_artifacts.as_slice() else {
        return Err(anyhow!(
            "non-empty shielded block requires exactly one matching recursive candidate artifact"
        ));
    };
    if artifact.tx_count as usize != transfer_count {
        return Err(anyhow!("candidate artifact tx_count mismatch"));
    }

    let materialized = materialize_native_action_payloads(&node.da_ciphertext_tree, actions)?;
    let transfers = actions
        .iter()
        .zip(materialized.iter())
        .filter(|(action, _)| is_shielded_transfer_action(action))
        .collect::<Vec<_>>();
    let transfer_actions = transfers
        .iter()
        .map(|(action, _)| *action)
        .collect::<Vec<_>>();
    let mut transactions = Vec::with_capacity(transfers.len());
    let mut artifacts = Vec::with_capacity(transfers.len());
    for (action, payload) in &transfers {
        let (tx, artifact) = consensus_tx_and_artifact_from_action(action, payload)?;
        transactions.push(tx);
        artifacts.push(artifact);
    }

    let da_params = native_da_params();
    let computed_da_root = consensus::da_root(&transactions, da_params)
        .map_err(|err| anyhow!("native block DA root failed: {err}"))?;
    if let Err(rejection) = evaluate_native_candidate_artifact_binding_admission(
        NativeCandidateArtifactBindingAdmissionInput {
            da_root_matches: computed_da_root == artifact.da_root,
            tx_statements_commitment_matches: true,
            recursive_state_root_matches: true,
        },
    ) {
        return Err(native_candidate_artifact_binding_admission_error(rejection));
    }

    let claims = consensus::proof::tx_validity_claims_from_tx_artifacts(&transactions, &artifacts)
        .map_err(|err| anyhow!("native tx artifact verification failed: {err}"))?;
    let tx_statements_commitment = consensus::proof::claim_statement_commitment(&claims)
        .map_err(|err| anyhow!("native tx statement commitment failed: {err}"))?;
    if let Err(rejection) = evaluate_native_candidate_artifact_binding_admission(
        NativeCandidateArtifactBindingAdmissionInput {
            da_root_matches: true,
            tx_statements_commitment_matches: tx_statements_commitment
                == artifact.tx_statements_commitment,
            recursive_state_root_matches: true,
        },
    ) {
        return Err(native_candidate_artifact_binding_admission_error(rejection));
    }

    let expected_tree = preview_commitment_tree(&state.commitment_tree, &transfer_actions)?;
    let mut expected_nullifiers = state.nullifiers.clone();
    for action in &transfer_actions {
        for nullifier in &action.nullifiers {
            expected_nullifiers.insert(*nullifier);
        }
    }
    let expected_nullifier_root = nullifier_root_from_set(&expected_nullifiers);
    let expected_kernel_root =
        consensus::types::kernel_root_from_shielded_root(&expected_tree.root());
    if meta.state_root != expected_tree.root()
        || meta.kernel_root != expected_kernel_root
        || meta.nullifier_root != expected_nullifier_root
    {
        return Err(anyhow!("native block artifact root mismatch"));
    }
    if meta.tx_count != transactions.len() as u32 {
        return Err(anyhow!("native block artifact tx_count mismatch"));
    }
    let height = evaluate_native_recursive_artifact_context_admission(
        NativeRecursiveArtifactContextAdmissionInput {
            best_height: state.best.height,
        },
    )
    .map_err(native_recursive_artifact_context_admission_error)?;
    if height != meta.height {
        return Err(anyhow!("native recursive block height mismatch"));
    }
    let header = consensus::BlockHeader {
        version: 1,
        height: meta.height,
        view: 0,
        timestamp_ms: meta.timestamp_ms,
        parent_hash: meta.parent_hash,
        state_root: meta.state_root,
        kernel_root: meta.kernel_root,
        nullifier_root: meta.nullifier_root,
        proof_commitment: consensus::types::compute_proof_commitment(&transactions),
        da_root: computed_da_root,
        da_params,
        version_commitment: consensus::types::compute_version_commitment(&transactions),
        tx_count: meta.tx_count,
        fee_commitment: consensus::types::compute_fee_commitment(&transactions),
        supply_digest: meta.supply_digest,
        validator_set_commitment: [0u8; 48],
        signature_aggregate: Vec::new(),
        signature_bitmap: None,
        pow: None,
    };
    let block_artifact = consensus_block_artifact_from_candidate(artifact)?;
    let proven_batch = consensus_proven_batch_from_candidate(artifact)?;
    let block = consensus::types::Block {
        header,
        transactions,
        coinbase: None,
        proven_batch: Some(proven_batch),
        block_artifact: Some(block_artifact),
        tx_validity_claims: Some(claims),
        tx_statements_commitment: Some(tx_statements_commitment),
        proof_verification_mode: consensus::types::ProofVerificationMode::SelfContainedAggregation,
    };
    let backend_inputs =
        consensus::proof_interface::BlockBackendInputs::from_tx_validity_artifacts(artifacts);
    let verifier = consensus::proof::ParallelProofVerifier::new();
    let verified_tree =
        <consensus::proof::ParallelProofVerifier as consensus::proof_interface::ProofVerifier>::verify_block_with_backend(
            &verifier,
            &block,
            Some(&backend_inputs),
            &state.commitment_tree,
        )
        .map_err(|err| anyhow!("native recursive block verification failed: {err}"))?;
    if let Err(rejection) = evaluate_native_candidate_artifact_binding_admission(
        NativeCandidateArtifactBindingAdmissionInput {
            da_root_matches: true,
            tx_statements_commitment_matches: true,
            recursive_state_root_matches: verified_tree.root() == expected_tree.root(),
        },
    ) {
        return Err(native_candidate_artifact_binding_admission_error(rejection));
    }
    Ok(())
}

fn consensus_tx_and_artifact_from_action(
    action: &PendingAction,
    payload: &NativeMaterializedActionPayload,
) -> Result<(Transaction, TxValidityArtifact)> {
    let proof_bytes = transfer_proof_from_action(action)?;
    let decoded = consensus::backend_interface::decode_native_tx_leaf_artifact_bytes(&proof_bytes)
        .map_err(|err| anyhow!("decode native tx-leaf artifact failed: {err}"))?;
    let action_version: consensus::VersionBinding = action.binding.into();
    let tx = Transaction::new(
        action.nullifiers.clone(),
        action.commitments.clone(),
        decoded.tx.balance_tag,
        action_version,
        payload.ciphertexts.clone(),
    );
    let admission_input = native_tx_leaf_action_binding_admission_input(&decoded, action, &tx);
    if let Err(rejection) = evaluate_native_tx_leaf_action_binding_admission(admission_input) {
        return Err(native_tx_leaf_action_binding_admission_error(rejection));
    }
    let artifact = consensus::proof::tx_validity_artifact_from_native_tx_leaf_bytes(proof_bytes)
        .map_err(|err| anyhow!("native tx-leaf artifact build failed: {err}"))?;
    Ok((tx, artifact))
}

fn transfer_proof_from_action(action: &PendingAction) -> Result<Vec<u8>> {
    if !is_shielded_transfer_action(action) {
        return Err(anyhow!("action is not a shielded transfer"));
    }
    match action.action_id {
        ACTION_SHIELDED_TRANSFER_INLINE => {
            let args: ShieldedTransferInlineArgs =
                decode_scale_exact(&action.public_args, "shielded inline action args")?;
            Ok(args.proof)
        }
        ACTION_SHIELDED_TRANSFER_SIDECAR => {
            let args: ShieldedTransferSidecarArgs =
                decode_scale_exact(&action.public_args, "shielded sidecar action args")?;
            Ok(args.proof)
        }
        _ => Err(anyhow!("action is not a shielded transfer")),
    }
}

fn encrypted_note_da_bytes(note: &protocol_shielded_pool::types::EncryptedNote) -> Result<Vec<u8>> {
    let total_len = note
        .ciphertext
        .len()
        .saturating_add(note.kem_ciphertext.len());
    if total_len > MAX_CIPHERTEXT_BYTES {
        return Err(anyhow!(
            "encrypted note size {} exceeds limit {}",
            total_len,
            MAX_CIPHERTEXT_BYTES
        ));
    }
    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(&note.ciphertext);
    bytes.extend_from_slice(&note.kem_ciphertext);
    Ok(bytes)
}

fn preview_commitment_tree(
    parent: &CommitmentTreeState,
    actions: &[&PendingAction],
) -> Result<CommitmentTreeState> {
    let mut tree = parent.clone();
    for action in actions {
        for commitment in &action.commitments {
            tree.append(*commitment)
                .map_err(|err| anyhow!("preview commitment append failed: {err}"))?;
        }
    }
    Ok(tree)
}

fn consensus_proven_batch_from_candidate(
    artifact: &CandidateArtifact,
) -> Result<consensus::types::ProvenBatch> {
    Ok(consensus::types::ProvenBatch {
        version: artifact.version,
        tx_count: artifact.tx_count,
        tx_statements_commitment: artifact.tx_statements_commitment,
        da_root: artifact.da_root,
        da_chunk_count: artifact.da_chunk_count,
        commitment_proof: empty_commitment_block_proof(),
        mode: consensus_batch_mode(artifact.proof_mode)?,
        proof_kind: consensus_proof_kind(artifact.proof_kind)?,
        verifier_profile: artifact.verifier_profile,
        receipt_root: None,
    })
}

fn consensus_block_artifact_from_candidate(artifact: &CandidateArtifact) -> Result<ProofEnvelope> {
    let recursive = artifact
        .recursive_block
        .as_ref()
        .ok_or_else(|| anyhow!("candidate artifact missing recursive proof payload"))?;
    Ok(ProofEnvelope {
        kind: consensus_proof_kind(artifact.proof_kind)?,
        verifier_profile: artifact.verifier_profile,
        artifact_bytes: recursive.proof.data.clone(),
    })
}

fn consensus_batch_mode(mode: BlockProofMode) -> Result<consensus::ProvenBatchMode> {
    match mode {
        BlockProofMode::InlineTx => Ok(consensus::ProvenBatchMode::InlineTx),
        BlockProofMode::ReceiptRoot => Ok(consensus::ProvenBatchMode::ReceiptRoot),
        BlockProofMode::RecursiveBlock => Ok(consensus::ProvenBatchMode::RecursiveBlock),
    }
}

fn consensus_proof_kind(kind: PoolProofArtifactKind) -> Result<consensus::ProofArtifactKind> {
    match kind {
        PoolProofArtifactKind::InlineTx => Ok(consensus::ProofArtifactKind::InlineTx),
        PoolProofArtifactKind::TxLeaf => Ok(consensus::ProofArtifactKind::TxLeaf),
        PoolProofArtifactKind::ReceiptRoot => Ok(consensus::ProofArtifactKind::ReceiptRoot),
        PoolProofArtifactKind::RecursiveBlockV1 => {
            Ok(consensus::ProofArtifactKind::RecursiveBlockV1)
        }
        PoolProofArtifactKind::RecursiveBlockV2 => {
            Ok(consensus::ProofArtifactKind::RecursiveBlockV2)
        }
        PoolProofArtifactKind::Custom(_) => Err(anyhow!("custom proof artifacts are unsupported")),
    }
}

fn empty_commitment_block_proof() -> consensus::backend_interface::CommitmentBlockProof {
    let zero = Default::default();
    let zero6 = [zero; 6];
    consensus::backend_interface::CommitmentBlockProof {
        proof_bytes: Vec::new(),
        proof_hash: [0u8; 48],
        public_inputs: consensus::backend_interface::CommitmentBlockPublicInputs {
            tx_statements_commitment: zero6,
            starting_state_root: zero6,
            ending_state_root: zero6,
            starting_kernel_root: zero6,
            ending_kernel_root: zero6,
            nullifier_root: zero6,
            da_root: zero6,
            tx_count: 0,
            perm_alpha: zero,
            perm_beta: zero,
            nullifiers: Vec::new(),
            sorted_nullifiers: Vec::new(),
        },
    }
}

fn native_da_params() -> DaParams {
    DaParams {
        chunk_size: DEFAULT_DA_CHUNK_SIZE,
        sample_count: DEFAULT_DA_SAMPLE_COUNT,
    }
}

fn action_root_transcript_preimage(action_hashes: &[[u8; 32]]) -> Vec<u8> {
    let action_count =
        u32::try_from(action_hashes.len()).expect("native action count exceeds u32::MAX");
    let hash_bytes = action_hashes
        .len()
        .checked_mul(32)
        .expect("native action-root preimage length overflow");
    let capacity = b"hegemon-native-extrinsics-v1"
        .len()
        .checked_add(4)
        .and_then(|prefix| prefix.checked_add(hash_bytes))
        .expect("native action-root preimage length overflow");
    let mut preimage = Vec::with_capacity(capacity);
    preimage.extend_from_slice(b"hegemon-native-extrinsics-v1");
    preimage.extend_from_slice(&action_count.to_le_bytes());
    for action_hash in action_hashes {
        preimage.extend_from_slice(action_hash);
    }
    preimage
}

fn actions_extrinsics_root(actions: &[PendingAction]) -> [u8; 32] {
    let action_hashes: Vec<[u8; 32]> = actions.iter().map(|action| action.tx_hash).collect();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&action_root_transcript_preimage(&action_hashes));
    *hasher.finalize().as_bytes()
}

fn verify_decoded_action_root(
    actions: &[PendingAction],
    meta: &NativeBlockMeta,
    context: &'static str,
) -> Result<()> {
    evaluate_native_block_commitment_admission(NativeBlockCommitmentAdmissionInput {
        tx_count_matches: true,
        state_root_matches: true,
        kernel_root_matches: true,
        nullifier_root_matches: true,
        extrinsics_root_matches: actions_extrinsics_root(actions) == meta.extrinsics_root,
        message_root_matches: true,
        message_count_matches: true,
        header_mmr_root_matches: true,
        header_mmr_len_matches: true,
        supply_digest_matches: true,
    })
    .map_err(|rejection| native_block_commitment_admission_error(context, rejection))
}

fn verify_canonical_sync_block_body(meta: &NativeBlockMeta) -> Result<()> {
    let actions = decode_block_actions(meta)?;
    verify_decoded_action_root(&actions, meta, "canonical native sync block action root")
}

fn nullifier_root_from_set(nullifiers: &BTreeSet<[u8; 48]>) -> [u8; 48] {
    let mut bytes = Vec::with_capacity(nullifiers.len() * 48);
    for nullifier in nullifiers {
        bytes.extend_from_slice(nullifier);
    }
    crypto::hashes::blake3_384(&bytes)
}

fn preview_pending_roots(
    da_ciphertext_tree: &sled::Tree,
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<([u8; 48], [u8; 48], [u8; 32], u32)> {
    let transfer_count = actions
        .iter()
        .filter(|action| is_shielded_transfer_action(action))
        .count();
    if transfer_count > 0 {
        let has_matching_recursive_artifact = actions.iter().any(|action| {
            is_candidate_artifact_action(action)
                && action
                    .candidate_artifact
                    .as_ref()
                    .is_some_and(|artifact| artifact.tx_count as usize == transfer_count)
        });
        if !has_matching_recursive_artifact {
            return Err(anyhow!(
                "non-empty shielded block requires same-block recursive candidate artifact"
            ));
        }
    }

    let planned = plan_materialized_action_effects(da_ciphertext_tree, state, actions)?;
    let mut leaf_cursor = state.commitment_tree.leaf_count();
    admit_native_action_plan_application(
        "native preview action plan application",
        leaf_cursor,
        actions,
        &planned,
    )?;
    admit_native_action_wire_replay_projection(
        "native preview action wire replay projection",
        actions,
        &planned,
    )?;
    let mut tree = state.commitment_tree.clone();
    let mut nullifiers = state.nullifiers.clone();
    for (action, effect) in actions.iter().zip(planned.iter()) {
        for (offset, commitment) in action.commitments.iter().enumerate() {
            let offset =
                u64::try_from(offset).map_err(|_| anyhow!("preview commitment offset overflow"))?;
            let expected_index = effect
                .commitment_start
                .checked_add(offset)
                .ok_or_else(|| anyhow!("preview commitment index overflow"))?;
            if expected_index != leaf_cursor || expected_index != tree.leaf_count() {
                return Err(anyhow!(
                    "native preview action plan drift: expected leaf {} observed {}",
                    expected_index,
                    tree.leaf_count()
                ));
            }
            tree.append(*commitment)
                .map_err(|err| anyhow!("preview commitment append failed: {err}"))?;
            leaf_cursor = leaf_cursor
                .checked_add(1)
                .ok_or_else(|| anyhow!("preview commitment leaf overflow"))?;
        }
        for nullifier in &action.nullifiers {
            nullifiers.insert(*nullifier);
        }
    }
    Ok((
        tree.root(),
        nullifier_root_from_set(&nullifiers),
        actions_extrinsics_root(actions),
        u32::try_from(actions.len()).unwrap_or(u32::MAX),
    ))
}

fn native_mined_work_admission_input(
    best: &NativeBlockMeta,
    work: &NativeWork,
) -> NativeMinedWorkAdmissionInput {
    NativeMinedWorkAdmissionInput {
        best_height: best.height,
        work_height: work.height,
        parent_hash_matches: best.hash == work.parent_hash,
    }
}

fn native_mined_next_height(best_height: u64) -> Option<u64> {
    best_height.checked_add(1)
}

fn evaluate_native_mined_work_admission(
    input: NativeMinedWorkAdmissionInput,
) -> Result<(), NativeMinedWorkAdmissionRejection> {
    if !input.parent_hash_matches {
        Err(NativeMinedWorkAdmissionRejection::ParentHashMismatch)
    } else if native_mined_next_height(input.best_height) != Some(input.work_height) {
        Err(NativeMinedWorkAdmissionRejection::HeightNotNext)
    } else {
        Ok(())
    }
}

fn evaluate_native_miner_identity_admission(
    input: NativeMinerIdentityAdmissionInput,
) -> Result<(), NativeMinerIdentityAdmissionRejection> {
    if input.height == 0 {
        return Ok(());
    }
    if input.public_key_len != ML_DSA_PUBLIC_KEY_LEN {
        Err(NativeMinerIdentityAdmissionRejection::InvalidMinerPublicKeyLength)
    } else if !input.public_key_bytes_parse {
        Err(NativeMinerIdentityAdmissionRejection::InvalidMinerPublicKeyBytes)
    } else if !input.miner_commitment_matches {
        Err(NativeMinerIdentityAdmissionRejection::MinerCommitmentMismatch)
    } else if input.signature_len != ML_DSA_SIGNATURE_LEN {
        Err(NativeMinerIdentityAdmissionRejection::InvalidMinerSignatureLength)
    } else if !input.signature_bytes_parse {
        Err(NativeMinerIdentityAdmissionRejection::InvalidMinerSignatureBytes)
    } else if !input.signature_verifies {
        Err(NativeMinerIdentityAdmissionRejection::NativeMinerSignatureVerificationFailed)
    } else {
        Ok(())
    }
}

fn native_work_template_next_height(best_height: u64) -> Option<u64> {
    best_height.checked_add(1)
}

fn evaluate_native_work_template_admission(
    input: NativeWorkTemplateAdmissionInput,
) -> Result<u64, NativeWorkTemplateAdmissionRejection> {
    let Some(next_height) = native_work_template_next_height(input.best_height) else {
        return Err(NativeWorkTemplateAdmissionRejection::HeightNotNext);
    };
    if !input.cumulative_work_advances {
        return Err(NativeWorkTemplateAdmissionRejection::CumulativeWorkOverflow);
    }
    Ok(next_height)
}

fn native_work_template_admission_error(
    rejection: NativeWorkTemplateAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeWorkTemplateAdmissionRejection::HeightNotNext => {
            anyhow!(
                "native work template height is not next ({})",
                rejection.label()
            )
        }
        NativeWorkTemplateAdmissionRejection::CumulativeWorkOverflow => anyhow!(
            "native work template cumulative work overflow ({})",
            rejection.label()
        ),
    }
}

fn native_recursive_artifact_context_next_height(best_height: u64) -> Option<u64> {
    best_height.checked_add(1)
}

fn evaluate_native_recursive_artifact_context_admission(
    input: NativeRecursiveArtifactContextAdmissionInput,
) -> Result<u64, NativeRecursiveArtifactContextAdmissionRejection> {
    native_recursive_artifact_context_next_height(input.best_height)
        .ok_or(NativeRecursiveArtifactContextAdmissionRejection::HeightNotNext)
}

fn native_recursive_artifact_context_admission_error(
    rejection: NativeRecursiveArtifactContextAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeRecursiveArtifactContextAdmissionRejection::HeightNotNext => {
            anyhow!(
                "native recursive artifact context height is not next ({})",
                rejection.label()
            )
        }
    }
}

fn native_announced_block_admission_input(
    parent: &NativeBlockMeta,
    meta: &NativeBlockMeta,
    now_ms: u64,
) -> NativeAnnouncedBlockAdmissionInput {
    NativeAnnouncedBlockAdmissionInput {
        parent_height: parent.height,
        announced_height: meta.height,
        parent_hash_matches: meta.parent_hash == parent.hash,
        parent_timestamp_ms: parent.timestamp_ms,
        announced_timestamp_ms: meta.timestamp_ms,
        now_ms,
        max_future_skew_ms: consensus::reward::MAX_FUTURE_SKEW_MS,
        hash_matches_work_hash: meta.hash == meta.work_hash,
    }
}

fn native_announced_next_height(parent_height: u64) -> Option<u64> {
    parent_height.checked_add(1)
}

fn native_announced_future_limit(now_ms: u64, max_future_skew_ms: u64) -> u64 {
    now_ms.saturating_add(max_future_skew_ms)
}

fn evaluate_native_announced_block_admission(
    input: NativeAnnouncedBlockAdmissionInput,
) -> Result<(), NativeAnnouncedBlockAdmissionRejection> {
    if native_announced_next_height(input.parent_height) != Some(input.announced_height) {
        Err(NativeAnnouncedBlockAdmissionRejection::HeightNotNext)
    } else if !input.parent_hash_matches {
        Err(NativeAnnouncedBlockAdmissionRejection::ParentHashMismatch)
    } else if input.announced_timestamp_ms <= input.parent_timestamp_ms {
        Err(NativeAnnouncedBlockAdmissionRejection::TimestampDidNotAdvance)
    } else if input.announced_timestamp_ms
        > native_announced_future_limit(input.now_ms, input.max_future_skew_ms)
    {
        Err(NativeAnnouncedBlockAdmissionRejection::FutureSkew)
    } else if !input.hash_matches_work_hash {
        Err(NativeAnnouncedBlockAdmissionRejection::HashWorkHashMismatch)
    } else {
        Ok(())
    }
}

fn native_announced_block_admission_error(
    rejection: NativeAnnouncedBlockAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeAnnouncedBlockAdmissionRejection::HeightNotNext => {
            anyhow!(
                "announced block height is not the next height ({})",
                rejection.label()
            )
        }
        NativeAnnouncedBlockAdmissionRejection::ParentHashMismatch => anyhow!(
            "announced block parent does not match local parent ({})",
            rejection.label()
        ),
        NativeAnnouncedBlockAdmissionRejection::TimestampDidNotAdvance => {
            anyhow!(
                "announced block timestamp did not advance ({})",
                rejection.label()
            )
        }
        NativeAnnouncedBlockAdmissionRejection::FutureSkew => anyhow!(
            "announced block timestamp exceeds future skew bound ({})",
            rejection.label()
        ),
        NativeAnnouncedBlockAdmissionRejection::HashWorkHashMismatch => {
            anyhow!(
                "native block hash must equal work hash ({})",
                rejection.label()
            )
        }
    }
}

fn validate_announced_block(parent: &NativeBlockMeta, meta: &NativeBlockMeta) -> Result<()> {
    evaluate_native_announced_block_admission(native_announced_block_admission_input(
        parent,
        meta,
        current_time_ms(),
    ))
    .map_err(native_announced_block_admission_error)?;
    verify_native_block_meta_projection(Some(parent), meta)
}

fn native_pow_header_from_parts(
    height: u64,
    timestamp_ms: u64,
    parent_hash: [u8; 32],
    pow_bits: u32,
    nonce: [u8; 32],
    cumulative_work: [u8; 48],
    state_root: &[u8; 48],
    kernel_root: &[u8; 48],
    nullifier_root: &[u8; 48],
    extrinsics_root: &[u8; 32],
    message_root: &[u8; 48],
    message_count: u32,
    header_mmr_root: &[u8; 32],
    header_mmr_len: u64,
    supply_digest: u128,
    tx_count: u32,
) -> PowHeaderV1 {
    PowHeaderV1 {
        chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
        height,
        timestamp_ms,
        parent_hash,
        state_root: *state_root,
        kernel_root: *kernel_root,
        nullifier_root: *nullifier_root,
        proof_commitment: NATIVE_EMPTY_DIGEST48,
        da_root: NATIVE_EMPTY_DIGEST48,
        action_root: *extrinsics_root,
        tx_statements_commitment: NATIVE_EMPTY_DIGEST48,
        version_commitment: NATIVE_EMPTY_DIGEST48,
        fee_commitment: NATIVE_EMPTY_DIGEST48,
        supply_digest,
        tx_count,
        message_root: *message_root,
        message_count,
        header_mmr_root: *header_mmr_root,
        header_mmr_len,
        pow_bits,
        nonce,
        cumulative_work,
    }
}

fn pow_header_from_meta(meta: &NativeBlockMeta) -> PowHeaderV1 {
    PowHeaderV1 {
        chain_id: meta.chain_id,
        rules_hash: meta.rules_hash,
        height: meta.height,
        timestamp_ms: meta.timestamp_ms,
        parent_hash: meta.parent_hash,
        state_root: meta.state_root,
        kernel_root: meta.kernel_root,
        nullifier_root: meta.nullifier_root,
        proof_commitment: NATIVE_EMPTY_DIGEST48,
        da_root: NATIVE_EMPTY_DIGEST48,
        action_root: meta.extrinsics_root,
        tx_statements_commitment: NATIVE_EMPTY_DIGEST48,
        version_commitment: NATIVE_EMPTY_DIGEST48,
        fee_commitment: NATIVE_EMPTY_DIGEST48,
        supply_digest: meta.supply_digest,
        tx_count: meta.tx_count,
        message_root: meta.message_root,
        message_count: meta.message_count,
        header_mmr_root: meta.header_mmr_root,
        header_mmr_len: meta.header_mmr_len,
        pow_bits: meta.pow_bits,
        nonce: meta.nonce,
        cumulative_work: meta.cumulative_work,
    }
}

fn checkpoint_from_meta(meta: &NativeBlockMeta) -> TrustedCheckpointV1 {
    TrustedCheckpointV1 {
        chain_id: meta.chain_id,
        rules_hash: meta.rules_hash,
        height: meta.height,
        header_hash: meta.hash,
        timestamp_ms: meta.timestamp_ms,
        pow_bits: meta.pow_bits,
        cumulative_work: meta.cumulative_work,
        header_mmr_root: meta.header_mmr_root,
        header_mmr_len: meta.header_mmr_len,
    }
}

fn native_miner_commitment(public_key_bytes: &[u8]) -> [u8; 48] {
    crypto::hashes::blake3_384(public_key_bytes)
}

fn native_miner_signature_message(meta: &NativeBlockMeta) -> Vec<u8> {
    let header_bytes = pow_header_from_meta(meta).canonical_bytes();
    let mut bytes = Vec::with_capacity(
        b"hegemon.native.miner-signature-v1".len()
            + header_bytes.len()
            + meta.nonce.len()
            + meta.work_hash.len(),
    );
    bytes.extend_from_slice(b"hegemon.native.miner-signature-v1");
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(&meta.nonce);
    bytes.extend_from_slice(&meta.work_hash);
    bytes
}

fn sign_native_block_meta(meta: &mut NativeBlockMeta, identity: &NativeMinerIdentity) {
    let signature_message = native_miner_signature_message(meta);
    let signature = identity.secret_key.sign(&signature_message);
    let public_key = identity.public_key.to_bytes();
    meta.miner_commitment = native_miner_commitment(&public_key);
    meta.miner_public_key = public_key;
    meta.miner_signature = signature.as_bytes().to_vec();
}

fn native_miner_identity_admission_input(
    meta: &NativeBlockMeta,
) -> NativeMinerIdentityAdmissionInput {
    let public_key = MlDsaPublicKey::from_bytes(&meta.miner_public_key);
    let signature = MlDsaSignature::from_bytes(&meta.miner_signature);
    let public_key_bytes_parse = public_key.is_ok();
    let signature_bytes_parse = signature.is_ok();
    let miner_commitment_matches =
        native_miner_commitment(&meta.miner_public_key) == meta.miner_commitment;
    let signature_verifies = match (public_key, signature) {
        (Ok(public_key), Ok(signature)) => public_key
            .verify(&native_miner_signature_message(meta), &signature)
            .is_ok(),
        _ => false,
    };
    NativeMinerIdentityAdmissionInput {
        height: meta.height,
        public_key_len: meta.miner_public_key.len(),
        signature_len: meta.miner_signature.len(),
        public_key_bytes_parse,
        miner_commitment_matches,
        signature_bytes_parse,
        signature_verifies,
    }
}

fn verify_native_miner_identity(meta: &NativeBlockMeta) -> Result<()> {
    evaluate_native_miner_identity_admission(native_miner_identity_admission_input(meta)).map_err(
        |rejection| {
            anyhow!(
                "native miner identity admission failed: {}",
                rejection.label()
            )
        },
    )
}

fn verify_native_pow_meta(parent: &NativeBlockMeta, meta: &NativeBlockMeta) -> Result<()> {
    verify_native_miner_identity(meta)?;
    if meta.hash != meta.work_hash {
        return Err(anyhow!("native block hash must equal work hash"));
    }
    let header = pow_header_from_meta(meta);
    let work_hash = verify_pow_header(&checkpoint_from_meta(parent), &header)
        .map_err(|err| anyhow!("native light-client header verification failed: {err:?}"))?;
    if work_hash != meta.hash {
        return Err(anyhow!("native block work hash mismatch"));
    }
    Ok(())
}

fn verify_native_block_meta_projection(
    parent: Option<&NativeBlockMeta>,
    meta: &NativeBlockMeta,
) -> Result<()> {
    if meta.height == 0 {
        verify_native_miner_identity(meta)?;
        return Ok(());
    }
    let parent = parent.ok_or_else(|| {
        anyhow!(
            "missing native block parent for metadata projection at height {} ({})",
            meta.height,
            hex32(&meta.hash)
        )
    })?;
    if meta.parent_hash != parent.hash {
        return Err(anyhow!(
            "native block metadata parent mismatch at height {}: expected {}, got {}",
            meta.height,
            hex32(&parent.hash),
            hex32(&meta.parent_hash)
        ));
    }
    verify_native_pow_meta(parent, meta)
}

fn empty_extrinsics_root(pending_count: u32) -> [u8; 32] {
    hash32_with_parts(&[b"hegemon-empty-extrinsics-v1", &pending_count.to_le_bytes()])
}

fn nonce_from_counter(counter: u64) -> [u8; 32] {
    let mut nonce = [0u8; 32];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn native_pow_work_hash(pre_hash: &[u8; 32], nonce: [u8; 32]) -> [u8; 32] {
    pow_hash_from_pre_hash(pre_hash, nonce)
}

fn native_seal_meets_target(work_hash: &[u8; 32], pow_bits: u32) -> bool {
    hash_meets_target(work_hash, pow_bits).unwrap_or(false)
}

fn native_meta_better_than(candidate: &NativeBlockMeta, current: &NativeBlockMeta) -> bool {
    consensus::fork_choice::fork_choice_prefers_candidate(
        compare_work(&candidate.cumulative_work, &current.cumulative_work),
        candidate.height,
        current.height,
        &candidate.hash,
        &current.hash,
    )
}

fn resolve_base_path(cli: &NativeCli) -> Result<PathBuf> {
    if cli.tmp {
        return Ok(std::env::temp_dir().join(format!(
            "hegemon-native-{}-{}",
            std::process::id(),
            current_time_ms()
        )));
    }
    if let Some(path) = &cli.base_path {
        return Ok(path.clone());
    }
    Ok(PathBuf::from(".hegemon/native"))
}

fn load_native_identity_seed(config: &NativeConfig) -> Result<[u8; 32]> {
    if let Ok(raw) = std::env::var("HEGEMON_PQ_IDENTITY_SEED") {
        return parse_identity_seed_hex(&raw)
            .ok_or_else(|| anyhow!("HEGEMON_PQ_IDENTITY_SEED must be 32-byte hex"));
    }
    let path = std::env::var("HEGEMON_PQ_IDENTITY_SEED_PATH")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| config.base_path.join(PQ_IDENTITY_SEED_FILE));
    load_or_create_identity_seed(&path)
}

fn load_native_miner_identity(config: &NativeConfig) -> Result<NativeMinerIdentity> {
    let seed = if let Ok(raw) = std::env::var("HEGEMON_MINER_IDENTITY_SEED") {
        parse_identity_seed_hex(&raw)
            .ok_or_else(|| anyhow!("HEGEMON_MINER_IDENTITY_SEED must be 32-byte hex"))?
    } else {
        let path = std::env::var("HEGEMON_MINER_IDENTITY_SEED_PATH")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| config.base_path.join(MINER_IDENTITY_SEED_FILE));
        load_or_create_identity_seed(&path)?
    };
    Ok(NativeMinerIdentity::from_seed(&seed))
}

fn load_or_create_identity_seed(path: &Path) -> Result<[u8; 32]> {
    if path.exists() {
        tighten_identity_seed_permissions(path)?;
        return read_identity_seed(path);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create identity seed directory {}", parent.display()))?;
    }
    let mut seed = [0u8; PQ_IDENTITY_SEED_LEN];
    OsRng.fill_bytes(&mut seed);
    let encoded = format!("{}\n", hex::encode(seed));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(encoded.as_bytes())
                .with_context(|| format!("write identity seed {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("sync identity seed {}", path.display()))?;
            tighten_identity_seed_permissions(path)?;
            Ok(seed)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            tighten_identity_seed_permissions(path)?;
            read_identity_seed(path)
        }
        Err(err) => Err(err).with_context(|| format!("create identity seed {}", path.display())),
    }
}

fn read_identity_seed(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path).with_context(|| format!("read identity seed {}", path.display()))?;
    if bytes.len() == PQ_IDENTITY_SEED_LEN {
        let mut seed = [0u8; PQ_IDENTITY_SEED_LEN];
        seed.copy_from_slice(&bytes);
        return Ok(seed);
    }
    let raw = std::str::from_utf8(&bytes)
        .ok()
        .and_then(parse_identity_seed_hex)
        .ok_or_else(|| anyhow!("identity seed file must contain 32 raw bytes or 32-byte hex"))?;
    Ok(raw)
}

fn parse_identity_seed_hex(raw: &str) -> Option<[u8; 32]> {
    let clean = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
    let bytes = hex::decode(clean).ok()?;
    if bytes.len() != PQ_IDENTITY_SEED_LEN {
        return None;
    }
    let mut seed = [0u8; PQ_IDENTITY_SEED_LEN];
    seed.copy_from_slice(&bytes);
    Some(seed)
}

fn tighten_identity_seed_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set permissions on identity seed {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn effective_rpc_methods_label(raw: &str, rpc_external: bool) -> Result<&'static str> {
    Ok(rpc_method_policy(raw, rpc_external)?.label())
}

fn rpc_method_policy(raw: &str, rpc_external: bool) -> Result<RpcMethodPolicy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "safe" => Ok(RpcMethodPolicy::Safe),
        "unsafe" => Ok(RpcMethodPolicy::Unsafe),
        "auto" | "" => {
            if rpc_external {
                Ok(RpcMethodPolicy::Safe)
            } else {
                Ok(RpcMethodPolicy::Unsafe)
            }
        }
        other => Err(anyhow!(
            "invalid --rpc-methods value {other:?}; expected auto, safe, or unsafe"
        )),
    }
}

fn default_native_wallet_page_limit() -> u64 {
    DEFAULT_NATIVE_WALLET_PAGE_LIMIT
}

fn pagination_from_params(params: Value) -> Result<NativePagination> {
    let value = first_param(&params).cloned().unwrap_or(Value::Null);
    let mut page = if value.is_null() {
        NativePagination {
            start: 0,
            limit: DEFAULT_NATIVE_WALLET_PAGE_LIMIT,
        }
    } else {
        serde_json::from_value::<NativePagination>(value).context("decode pagination params")?
    };
    if page.limit == 0 {
        page.limit = DEFAULT_NATIVE_WALLET_PAGE_LIMIT;
    }
    page.limit = page.limit.min(MAX_NATIVE_WALLET_PAGE_LIMIT);
    Ok(page)
}

fn is_unsafe_rpc_method(method: &str) -> bool {
    matches!(
        method,
        "hegemon_startMining"
            | "hegemon_stopMining"
            | "hegemon_submitAction"
            | "da_submitCiphertexts"
            | "da_submitProofs"
    )
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn height_key(height: u64) -> [u8; 8] {
    height.to_be_bytes()
}

fn first_param(params: &Value) -> Option<&Value> {
    match params {
        Value::Array(values) => values.first(),
        Value::Object(_) => Some(params),
        _ => None,
    }
}

fn parse_mining_thread_count_str(raw: &str, context: &str) -> Result<u32> {
    let requested = raw
        .trim()
        .parse::<u64>()
        .with_context(|| format!("{context} must be an unsigned integer"))?;
    parse_mining_thread_count_u64(requested, context)
}

fn parse_mining_thread_count_u64(requested: u64, context: &str) -> Result<u32> {
    if requested == 0 {
        return Err(anyhow!("{context} must be at least 1"));
    }
    if requested > u64::from(MAX_NATIVE_MINING_THREADS) {
        return Err(anyhow!(
            "{context} exceeds maximum mining threads: {} > {}",
            requested,
            MAX_NATIVE_MINING_THREADS
        ));
    }
    Ok(requested as u32)
}

fn start_mining_threads_from_params(params: &Value) -> Result<u32> {
    let Some(first) = first_param(params) else {
        return Ok(1);
    };
    let Value::Object(map) = first else {
        if first.is_null() {
            return Ok(1);
        }
        return Err(anyhow!(
            "hegemon_startMining params must be an object with optional threads"
        ));
    };
    let Some(value) = map.get("threads") else {
        return Ok(1);
    };
    let requested = value
        .as_u64()
        .ok_or_else(|| anyhow!("hegemon_startMining threads must be an unsigned integer"))?;
    parse_mining_thread_count_u64(requested, "hegemon_startMining threads")
}

fn nth_param(params: &Value, index: usize) -> Option<&Value> {
    match params {
        Value::Array(values) => values.get(index),
        _ if index == 0 => Some(params),
        _ => None,
    }
}

fn parse_height(raw: &str) -> Option<u64> {
    raw.strip_prefix("0x")
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .or_else(|| raw.parse::<u64>().ok())
}

fn parse_hash32(raw: &str) -> Option<[u8; 32]> {
    let clean = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(clean).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn parse_hex48(raw: &str) -> Option<[u8; 48]> {
    let clean = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(clean).ok()?;
    if bytes.len() != 48 {
        return None;
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn parse_hex64(raw: &str) -> Option<[u8; 64]> {
    let clean = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(clean).ok()?;
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn decode_base64(raw: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .context("decode base64")
}

fn decode_scale_exact<T: Decode + Encode>(bytes: &[u8], label: &str) -> Result<T> {
    let mut cursor = bytes;
    let value = T::decode(&mut cursor).map_err(|err| anyhow!("decode {label} failed: {err:?}"))?;
    if !cursor.is_empty() {
        return Err(anyhow!(
            "{label} has {} trailing bytes after SCALE decode",
            cursor.len()
        ));
    }
    let canonical = value.encode();
    if canonical.as_slice() != bytes {
        return Err(anyhow!(
            "{label} is not canonical SCALE encoding: input_len={}, canonical_len={}",
            bytes.len(),
            canonical.len()
        ));
    }
    Ok(value)
}

fn bincode_deserialize_exact<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    label: &str,
) -> Result<T> {
    let mut cursor = Cursor::new(bytes);
    let value: T = bincode::deserialize_from(&mut cursor)
        .map_err(|err| anyhow!("decode {label} failed: {err}"))?;
    if cursor.position() as usize != bytes.len() {
        return Err(anyhow!(
            "{label} has {} trailing bytes after bincode decode",
            bytes.len().saturating_sub(cursor.position() as usize)
        ));
    }
    let canonical =
        bincode::serialize(&value).map_err(|err| anyhow!("re-encode {label} failed: {err}"))?;
    if canonical.as_slice() != bytes {
        return Err(anyhow!(
            "{label} is not canonical bincode encoding: input_len={}, canonical_len={}",
            bytes.len(),
            canonical.len()
        ));
    }
    Ok(value)
}

fn bincode_deserialize_native_block_meta_exact(
    bytes: &[u8],
    label: &str,
) -> Result<NativeBlockMeta> {
    match bincode_deserialize_exact::<NativeBlockMeta>(bytes, label) {
        Ok(meta) => Ok(meta),
        Err(current_error) => match bincode_deserialize_exact::<LegacyNativeBlockMetaV1>(
            bytes,
            &format!("legacy {label}"),
        ) {
            Ok(meta) => Ok(meta.into()),
            Err(legacy_error) => Err(anyhow!(
                "{label} did not decode as current or legacy native metadata: current={current_error}; legacy={legacy_error}"
            )),
        },
    }
}

fn encoded_len_limit(decoded_len_limit: usize) -> usize {
    decoded_len_limit.saturating_mul(4).saturating_add(2) / 3 + 4
}

fn parse_bytes_value(value: &Value, max_decoded_len: usize, label: &str) -> Result<Vec<u8>> {
    let raw = value
        .as_str()
        .ok_or_else(|| anyhow!("expected base64 or 0x-prefixed hex string"))?;
    if let Some(hex) = raw.strip_prefix("0x") {
        if hex.len() > max_decoded_len.saturating_mul(2) {
            return Err(anyhow!(
                "{label} hex length {} exceeds decoded limit {}",
                hex.len(),
                max_decoded_len
            ));
        }
        let bytes = hex::decode(hex).context("decode hex bytes")?;
        if bytes.len() > max_decoded_len {
            return Err(anyhow!(
                "{label} decoded length {} exceeds limit {}",
                bytes.len(),
                max_decoded_len
            ));
        }
        return Ok(bytes);
    }
    if raw.len() > encoded_len_limit(max_decoded_len) {
        return Err(anyhow!(
            "{label} base64 length {} exceeds decoded limit {}",
            raw.len(),
            max_decoded_len
        ));
    }
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .context("decode base64 bytes")?;
    if bytes.len() > max_decoded_len {
        return Err(anyhow!(
            "{label} decoded length {} exceeds limit {}",
            bytes.len(),
            max_decoded_len
        ));
    }
    Ok(bytes)
}

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .map(|raw| {
            let raw = raw.trim();
            raw == "1" || raw.eq_ignore_ascii_case("true") || raw.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
}

fn env_list(name: &str) -> Vec<String> {
    std::env::var(name)
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn hash32_with_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn hash48_with_parts(parts: &[&[u8]]) -> [u8; 48] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 48];
    reader.fill(&mut out);
    out
}

fn hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn hex48(bytes: &[u8; 48]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn hex64(bytes: &[u8; 64]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn dir_size(path: &Path) -> Result<u64> {
    if path.is_file() {
        return Ok(path.metadata()?.len());
    }
    if !path.exists() {
        return Ok(0);
    }
    let mut total = 0u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        total = total.saturating_add(dir_size(&entry.path())?);
    }
    Ok(total)
}

fn tree_size_hint(tree: &sled::Tree) -> u64 {
    tree.iter()
        .filter_map(|item| item.ok())
        .map(|(key, value)| (key.len() + value.len()) as u64)
        .sum()
}

fn json_response(node: &NativeNode, status: StatusCode, body: Value) -> Response {
    with_cors(node, (status, Json(body)).into_response())
}

fn with_cors(node: &NativeNode, mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, GET, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type, authorization"),
    );
    if let Some(cors) = node.config.rpc_cors.as_deref() {
        if let Ok(value) = HeaderValue::from_str(cors) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        }
    }
    response
}

fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "error": {
            "code": code,
            "message": message.into(),
        },
        "id": id,
    })
}

fn native_rpc_methods(policy: RpcMethodPolicy) -> Vec<&'static str> {
    let mut methods = vec![
        "archive_getContract",
        "archive_getProvider",
        "archive_listContracts",
        "archive_listProviders",
        "archive_providerCount",
        "author_pendingExtrinsics",
        "block_getCommitmentProof",
        "chain_getBlock",
        "chain_getBlockHash",
        "chain_getHeader",
        "chain_subscribeFinalizedHeads",
        "chain_subscribeNewHeads",
        "da_getChunk",
        "da_getParams",
        "da_submitCiphertexts",
        "da_submitProofs",
        "da_submitWitnesses",
        "hegemon_blockTimestamps",
        "hegemon_compactJob",
        "hegemon_consensusStatus",
        "hegemon_exportBridgeWitness",
        "hegemon_generateProof",
        "hegemon_isValidAnchor",
        "hegemon_latestBlock",
        "hegemon_minedBlockTimestamps",
        "hegemon_miningStatus",
        "hegemon_nodeConfig",
        "hegemon_peerGraph",
        "hegemon_peerList",
        "hegemon_poolStatus",
        "hegemon_poolWork",
        "hegemon_startMining",
        "hegemon_stopMining",
        "hegemon_storageFootprint",
        "hegemon_submitAction",
        "hegemon_submitCompactSolution",
        "hegemon_submitPoolShare",
        "hegemon_submitTransaction",
        "hegemon_telemetry",
        "hegemon_walletCiphertexts",
        "hegemon_walletCommitments",
        "hegemon_walletNotes",
        "hegemon_walletNullifiers",
        "rpc_methods",
        "state_getRuntimeVersion",
        "state_getStorage",
        "state_getStorageAt",
        "state_getStorageHash",
        "state_getStorageHashAt",
        "state_getStorageSize",
        "state_getStorageSizeAt",
        "system_chain",
        "system_health",
        "system_name",
        "system_peers",
        "system_version",
    ];
    if policy != RpcMethodPolicy::Unsafe {
        methods.retain(|method| !is_unsafe_rpc_method(method));
    }
    methods
}

mod serde_array48 {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::Bytes::new(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        if bytes.len() != 48 {
            return Err(D::Error::custom("expected 48 bytes"));
        }
        let mut out = [0u8; 48];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

async fn shutdown_signal(node: Arc<NativeNode>) {
    let _ = tokio::signal::ctrl_c().await;
    node.stop_mining();
    if let Err(err) = node.db.flush() {
        warn!(error = %err, "failed to flush native db during shutdown");
    }
    info!("native Hegemon node shutdown complete");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy)]
    struct NormalizedScaleByte;

    impl Encode for NormalizedScaleByte {
        fn size_hint(&self) -> usize {
            1
        }

        fn encode_to<T: codec::Output + ?Sized>(&self, dest: &mut T) {
            dest.push_byte(0);
        }
    }

    impl Decode for NormalizedScaleByte {
        fn decode<I: codec::Input>(input: &mut I) -> std::result::Result<Self, codec::Error> {
            let _ = input.read_byte()?;
            Ok(Self)
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct NormalizedBincodeByte;

    impl Serialize for NormalizedBincodeByte {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_u8(0)
        }
    }

    impl<'de> Deserialize<'de> for NormalizedBincodeByte {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let _ = u8::deserialize(deserializer)?;
            Ok(Self)
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSupplyVectorFile {
        schema_version: u32,
        monetary_constants: serde_json::Value,
        subsidy_schedule_cases: Vec<serde_json::Value>,
        consensus_supply_cases: Vec<serde_json::Value>,
        native_supply_cases: Vec<LeanNativeSupplyCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanNativeSupplyCase {
        name: String,
        parent_supply: String,
        height: u64,
        fee_total: u64,
        has_coinbase: bool,
        expected_delta: Option<String>,
        expected_supply: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionOrderVectorFile {
        schema_version: u32,
        action_order_cases: Vec<LeanActionOrderCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionOrderCase {
        name: String,
        actions: Vec<LeanOrderedAction>,
        expected_valid: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanOrderedAction {
        is_transfer: bool,
        key: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionHashAdmissionVectorFile {
        schema_version: u32,
        action_hash_admission_cases: Vec<LeanActionHashAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionHashAdmissionCase {
        name: String,
        action_count_matches: bool,
        action_hashes_match: bool,
        action_hashes_unique: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionRootTranscriptVectorFile {
        schema_version: u32,
        action_root_transcript_cases: Vec<LeanActionRootTranscriptCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionRootTranscriptCase {
        name: String,
        action_hashes_hex: Vec<String>,
        expected_preimage_hex: String,
        expected_preimage_len: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanAnnouncedBlockAdmissionVectorFile {
        schema_version: u32,
        announced_block_admission_cases: Vec<LeanAnnouncedBlockAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanAnnouncedBlockAdmissionCase {
        name: String,
        parent_height: u64,
        announced_height: u64,
        parent_hash_matches: bool,
        parent_timestamp_ms: u64,
        announced_timestamp_ms: u64,
        now_ms: u64,
        max_future_skew_ms: u64,
        hash_matches_work_hash: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBlockIndexReloadVectorFile {
        schema_version: u32,
        block_index_reload_cases: Vec<LeanBlockIndexReloadCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBlockIndexReloadCase {
        name: String,
        chain_reconstructed: bool,
        chain_nonempty: bool,
        genesis_matches_expected: bool,
        best_metadata_matches_chain: bool,
        canonical_heights_contiguous: bool,
        canonical_chain_ids_match: bool,
        canonical_rules_hashes_match: bool,
        canonical_hashes_match_work_hashes: bool,
        canonical_parent_hashes_contiguous: bool,
        height_keys_well_formed: bool,
        height_values_well_formed: bool,
        no_extra_height_indexes: bool,
        height_index_heights_match_chain: bool,
        height_index_hashes_match_chain: bool,
        all_canonical_heights_indexed: bool,
        genesis_marker_present: bool,
        genesis_marker_length_valid: bool,
        genesis_marker_matches_expected: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
        expected_repairs_genesis_marker: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCanonicalReorgChainAdmissionVectorFile {
        schema_version: u32,
        canonical_reorg_chain_admission_cases: Vec<LeanCanonicalReorgChainAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCanonicalReorgChainAdmissionCase {
        name: String,
        chain_nonempty: bool,
        genesis_matches_expected: bool,
        best_metadata_matches_chain: bool,
        canonical_heights_contiguous: bool,
        canonical_chain_ids_match: bool,
        canonical_rules_hashes_match: bool,
        canonical_hashes_match_work_hashes: bool,
        canonical_parent_hashes_contiguous: bool,
        block_record_count_matches_chain: bool,
        block_records_match_chain: bool,
        height_entry_count_matches_chain: bool,
        height_entries_match_chain: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCanonicalStateReloadVectorFile {
        schema_version: u32,
        canonical_state_reload_cases: Vec<LeanCanonicalStateReloadCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCanonicalStateReloadCase {
        name: String,
        nullifier_keys_well_formed: bool,
        nullifier_markers_valid: bool,
        commitment_keys_well_formed: bool,
        commitment_values_well_formed: bool,
        commitment_indexes_contiguous: bool,
        commitment_tree_rebuilt: bool,
        commitment_root_matches_best: bool,
        nullifier_root_matches_best: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBridgeReplayReloadVectorFile {
        schema_version: u32,
        bridge_replay_reload_cases: Vec<LeanBridgeReplayReloadCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBridgeReplayReloadCase {
        name: String,
        replay_keys_well_formed: bool,
        replay_markers_valid: bool,
        canonical_replay_keys_unique: bool,
        no_missing_loaded_replay_keys: bool,
        no_extra_loaded_replay_keys: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBridgeWitnessExportAdmissionVectorFile {
        schema_version: u32,
        bridge_witness_export_admission_cases: Vec<LeanBridgeWitnessExportAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBridgeWitnessExportAdmissionCase {
        name: String,
        block_hash_parameter_valid: bool,
        block_known: bool,
        canonical_height_present: bool,
        block_is_canonical: bool,
        block_actions_decoded: bool,
        message_index_in_bounds: bool,
        parent_known: bool,
        best_height: u64,
        message_height: u64,
        expected_valid: bool,
        expected_confirmations_checked: Option<u32>,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanInboundBridgeReceiptAdmissionVectorFile {
        schema_version: u32,
        inbound_bridge_receipt_admission_cases: Vec<LeanInboundBridgeReceiptAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanInboundBridgeReceiptAdmissionCase {
        name: String,
        source_chain_matches: bool,
        rules_hash_matches: bool,
        message_nonce_matches: bool,
        message_hash_matches: bool,
        checkpoint_height: u64,
        canonical_tip_height: u64,
        confirmations_checked: u32,
        min_confirmations: u32,
        expected_valid: bool,
        expected_height_confirmations: Option<u32>,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBridgeWitnessBackscanVectorFile {
        schema_version: u32,
        bridge_witness_backscan_cases: Vec<LeanBridgeWitnessBackscanCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBridgeWitnessBackscanCase {
        name: String,
        entries: Vec<LeanBridgeWitnessBackscanEntry>,
        expected_valid: bool,
        expected_selected_height: Option<u64>,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBridgeWitnessBackscanEntry {
        height: u64,
        canonical_hash_present: bool,
        block_known: bool,
        block_actions_decoded: bool,
        message_index_in_bounds: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanPendingActionReloadVectorFile {
        schema_version: u32,
        pending_action_reload_cases: Vec<LeanPendingActionReloadCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanPendingActionReloadCase {
        name: String,
        key_well_formed: bool,
        embedded_hash_matches_key: bool,
        recomputed_hash_matches_embedded: bool,
        action_hash_unique: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanStagedCiphertextReloadVectorFile {
        schema_version: u32,
        staged_ciphertext_reload_cases: Vec<LeanStagedCiphertextReloadCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanStagedCiphertextReloadCase {
        name: String,
        key_well_formed: bool,
        ciphertext_within_limit: bool,
        ciphertext_hash_matches_key: bool,
        capacity_available: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanStagedProofReloadVectorFile {
        schema_version: u32,
        staged_proof_reload_cases: Vec<LeanStagedProofReloadCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanStagedProofReloadCase {
        name: String,
        key_well_formed: bool,
        proof_nonempty: bool,
        proof_within_limit: bool,
        capacity_available: bool,
        byte_capacity_available: bool,
        proof_binding_hash_matches_key: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanMinedWorkAdmissionVectorFile {
        schema_version: u32,
        mined_work_admission_cases: Vec<LeanMinedWorkAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanNativeMinerIdentityVectorFile {
        schema_version: u32,
        native_miner_identity_cases: Vec<LeanNativeMinerIdentityCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanNativeMinerIdentityCase {
        name: String,
        height: u64,
        public_key_len: usize,
        signature_len: usize,
        public_key_bytes_parse: bool,
        miner_commitment_matches: bool,
        signature_bytes_parse: bool,
        signature_verifies: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanMinedWorkAdmissionCase {
        name: String,
        best_height: u64,
        work_height: u64,
        parent_hash_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanWorkTemplateAdmissionVectorFile {
        schema_version: u32,
        work_template_admission_cases: Vec<LeanWorkTemplateAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanWorkTemplateAdmissionCase {
        name: String,
        best_height: u64,
        cumulative_work_advances: bool,
        expected_height: Option<u64>,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRecursiveArtifactContextAdmissionVectorFile {
        schema_version: u32,
        recursive_artifact_context_admission_cases: Vec<LeanRecursiveArtifactContextAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRecursiveArtifactContextAdmissionCase {
        name: String,
        best_height: u64,
        expected_height: Option<u64>,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCodecAdmissionVectorFile {
        schema_version: u32,
        sync_codec_cases: Vec<LeanSyncCodecCase>,
        exact_decode_cases: Vec<LeanExactDecodeCase>,
        block_action_decode_cases: Vec<LeanBlockActionDecodeCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionRequestProjectionAdmissionVectorFile {
        schema_version: u32,
        action_request_projection_admission_cases: Vec<LeanActionRequestProjectionAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionRequestProjectionAdmissionCase {
        name: String,
        fixture: String,
        json_decode_accepts: bool,
        kernel_envelope_fields_absent: bool,
        route_supported: bool,
        nullifier_scope_valid: bool,
        nullifier_count_within_limit: bool,
        nullifier_hex_valid: bool,
        public_args_encoded_within_limit: bool,
        public_args_base64_decodes: bool,
        public_args_decoded_within_limit: bool,
        route_payload_decodes_exactly: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSyncCodecCase {
        name: String,
        fixture: String,
        bounded_wire_decode_accepts: bool,
        consumed_all_bytes: bool,
        legacy_bincode_payload: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanExactDecodeCase {
        name: String,
        codec: String,
        fixture: String,
        parser_accepts: bool,
        consumed_all_bytes: bool,
        canonical_reencode_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBlockActionDecodeCase {
        name: String,
        fixture: String,
        declared_tx_count: usize,
        actual_action_payload_count: usize,
        every_action_decodes_exactly: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanStorageDurabilityAdmissionVectorFile {
        schema_version: u32,
        storage_durability_admission_cases: Vec<LeanStorageDurabilityAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanStorageDurabilityAdmissionCase {
        name: String,
        operation: String,
        transaction_accepted: bool,
        durability_flushed: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanAtomicCommitManifestAdmissionVectorFile {
        schema_version: u32,
        atomic_commit_manifest_admission_cases: Vec<LeanAtomicCommitManifestAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanAtomicCommitManifestAdmissionCase {
        name: String,
        kind: String,
        action_count: usize,
        planned_action_count: usize,
        chain_block_count: usize,
        height_entry_count: usize,
        pending_entry_count: usize,
        source_commitment_count: usize,
        source_nullifier_count: usize,
        source_bridge_replay_count: usize,
        source_ciphertext_index_count: usize,
        source_ciphertext_archive_count: usize,
        source_staged_ciphertext_removal_count: usize,
        block_record_writes: usize,
        height_index_writes: usize,
        best_pointer_writes: usize,
        canonical_index_cleared: bool,
        pending_tree_cleared: bool,
        pending_action_removals: usize,
        pending_action_writes: usize,
        commitment_writes: usize,
        nullifier_writes: usize,
        bridge_replay_writes: usize,
        ciphertext_index_writes: usize,
        ciphertext_archive_writes: usize,
        staged_ciphertext_removals: usize,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionScopeAdmissionVectorFile {
        schema_version: u32,
        action_scope_admission_cases: Vec<LeanActionScopeAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionScopeAdmissionCase {
        name: String,
        candidate_artifact_payload_scoped: bool,
        bridge_route: bool,
        bridge_scope_valid: bool,
        candidate_artifact_route: bool,
        candidate_scope_valid: bool,
        candidate_payload_present: bool,
        coinbase_route: bool,
        coinbase_scope_valid: bool,
        transfer_route: bool,
        transfer_scope_valid: bool,
        expected_valid: bool,
        expected_route: Option<String>,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBridgeActionPayloadAdmissionVectorFile {
        schema_version: u32,
        bridge_action_payload_admission_cases: Vec<LeanBridgeActionPayloadAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBridgeActionPayloadAdmissionCase {
        name: String,
        bridge_route: bool,
        state_deltas_absent: bool,
        action_kind: String,
        outbound_payload_nonempty: bool,
        inbound_proof_receipt_nonempty: bool,
        inbound_replay_key_matches: bool,
        inbound_destination_matches: bool,
        inbound_payload_hash_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRisc0ReleaseVerifierVectorFile {
        schema_version: u32,
        risc0_release_verifier_cases: Vec<LeanRisc0ReleaseVerifierCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRisc0ReleaseVerifierCase {
        name: String,
        image_id_matches: bool,
        journal_decodes: bool,
        verifier_enabled: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanTransferActionPayloadAdmissionVectorFile {
        schema_version: u32,
        transfer_action_payload_admission_cases: Vec<LeanTransferActionPayloadAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanTransferActionPayloadAdmissionCase {
        name: String,
        proof_bytes: usize,
        max_proof_bytes: usize,
        anchor_matches: bool,
        commitments_match: bool,
        inline_ciphertext_bytes: usize,
        max_ciphertext_bytes: usize,
        ciphertext_hashes_match: bool,
        ciphertext_sizes_match: bool,
        binding_hash_matches: bool,
        #[serde(default = "default_true")]
        proof_binding_hash_matches_key: bool,
        fee_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanTransferStateAdmissionVectorFile {
        schema_version: u32,
        transfer_state_admission_cases: Vec<LeanTransferStateAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanTransferStateAdmissionCase {
        name: String,
        anchor_known: bool,
        nullifier_state: String,
        commitments_nonzero: bool,
        sidecar_route: bool,
        sidecar_ciphertexts_available: bool,
        sidecar_ciphertext_sizes_present: bool,
        sidecar_ciphertext_sizes_match: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionStateEffectVectorFile {
        schema_version: u32,
        action_state_effect_cases: Vec<LeanActionStateEffectCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionStateEffectCase {
        name: String,
        leaf_start: u64,
        commitment_count: usize,
        ciphertext_count: usize,
        nullifier_count: usize,
        nullifier_state: String,
        bridge_replay_state: String,
        expected_next_leaf_count: Option<u64>,
        expected_imported_nullifier_count: Option<usize>,
        expected_imported_bridge_replay: Option<bool>,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionStreamEffectVectorFile {
        schema_version: u32,
        action_stream_effect_cases: Vec<LeanActionStreamEffectCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionStreamEffectCase {
        name: String,
        leaf_start: u64,
        spent_nullifiers: Vec<u64>,
        consumed_bridge_replays: Vec<u64>,
        actions: Vec<LeanActionStreamActionCase>,
        expected_next_leaf_count: Option<u64>,
        expected_imported_nullifier_count: Option<usize>,
        expected_imported_bridge_replay_count: Option<usize>,
        expected_planned_starts: Option<Vec<u64>>,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionStreamActionCase {
        commitment_count: usize,
        ciphertext_count: usize,
        nullifiers: Vec<u64>,
        bridge_replay_key: Option<u64>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionPlanApplicationAdmissionVectorFile {
        schema_version: u32,
        action_plan_application_admission_cases: Vec<LeanActionPlanApplicationAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionPlanApplicationAdmissionCase {
        name: String,
        leaf_start: u64,
        action_commitment_counts: Vec<usize>,
        planned_starts: Vec<u64>,
        expected_next_leaf_count: Option<u64>,
        expected_applied_action_count: Option<usize>,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionWireReplayProjectionAdmissionVectorFile {
        schema_version: u32,
        action_wire_replay_projection_admission_cases:
            Vec<LeanActionWireReplayProjectionAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionWireReplayProjectionAdmissionCase {
        name: String,
        action_count: usize,
        planned_count: usize,
        actions: Vec<LeanActionWireReplayProjectionActionCase>,
        expected_projected_action_count: Option<usize>,
        expected_projected_ciphertext_row_count: Option<usize>,
        expected_projected_bridge_replay_row_count: Option<usize>,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanActionWireReplayProjectionActionCase {
        ciphertext_hash_count: usize,
        ciphertext_size_count: usize,
        planned_ciphertext_count: usize,
        ciphertext_hashes_match: bool,
        ciphertext_sizes_match: bool,
        planned_replay_present: bool,
        replay_key_matches: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBlockActionValidationVectorFile {
        schema_version: u32,
        block_action_validation_cases: Vec<LeanBlockActionValidationCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBlockActionValidationCase {
        name: String,
        action_count_matches: bool,
        action_hashes_match: bool,
        action_hashes_unique: bool,
        consumed_bridge_replays: Vec<u64>,
        actions: Vec<LeanBlockActionValidationActionCase>,
        expected_valid: bool,
        expected_rejection: Option<String>,
        expected_validated_action_count: Option<usize>,
        expected_imported_bridge_replay_count: Option<usize>,
        expected_last_transfer_key: Option<u64>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBlockActionValidationActionCase {
        scope: LeanBlockActionValidationScopeCase,
        payload_valid: bool,
        transfer_key: u64,
        transfer_state: LeanBlockActionValidationTransferStateCase,
        bridge_replay_key: Option<u64>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBlockActionValidationScopeCase {
        candidate_artifact_payload_scoped: bool,
        bridge_route: bool,
        bridge_scope_valid: bool,
        candidate_artifact_route: bool,
        candidate_scope_valid: bool,
        candidate_payload_present: bool,
        coinbase_route: bool,
        coinbase_scope_valid: bool,
        transfer_route: bool,
        transfer_scope_valid: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBlockActionValidationTransferStateCase {
        anchor_known: bool,
        nullifier_state: String,
        commitments_nonzero: bool,
        sidecar_route: bool,
        sidecar_ciphertexts_available: bool,
        sidecar_ciphertext_sizes_present: bool,
        sidecar_ciphertext_sizes_match: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCandidateArtifactAdmissionVectorFile {
        schema_version: u32,
        candidate_artifact_admission_cases: Vec<LeanCandidateArtifactAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCandidateArtifactAdmissionCase {
        name: String,
        state_deltas_absent: bool,
        artifact_present: bool,
        schema_matches: bool,
        tx_count: u32,
        max_tx_count: u32,
        da_chunk_count: u32,
        proof_mode_recursive_block: bool,
        proof_kind_recursive_block_v2: bool,
        verifier_profile_matches: bool,
        commitment_proof_empty: bool,
        receipt_root_absent: bool,
        recursive_payload_present: bool,
        recursive_proof_bytes: usize,
        max_recursive_proof_bytes: usize,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCandidateArtifactCouplingAdmissionVectorFile {
        schema_version: u32,
        candidate_artifact_coupling_admission_cases:
            Vec<LeanCandidateArtifactCouplingAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCandidateArtifactCouplingAdmissionCase {
        name: String,
        transfer_count: usize,
        candidate_artifact_count: usize,
        candidate_tx_count_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanMineableActionAdmissionVectorFile {
        schema_version: u32,
        mineable_action_admission_cases: Vec<LeanMineableActionAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanMineableActionAdmissionCase {
        name: String,
        candidate_artifact_route: bool,
        candidate_artifact_selected: bool,
        sidecar_transfer_route: bool,
        sidecar_ciphertexts_available: bool,
        sidecar_ciphertext_sizes_present: bool,
        sidecar_ciphertext_sizes_match: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBlockArtifactBindingAdmissionVectorFile {
        schema_version: u32,
        tx_leaf_action_binding_cases: Vec<LeanTxLeafActionBindingAdmissionCase>,
        candidate_artifact_binding_cases: Vec<LeanCandidateArtifactBindingAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanTxLeafActionBindingAdmissionCase {
        name: String,
        nullifiers_match: bool,
        commitments_match: bool,
        ciphertext_hashes_match: bool,
        input_count_matches: bool,
        output_count_matches: bool,
        version_matches: bool,
        fee_matches: bool,
        #[serde(default = "default_true")]
        stablecoin_payload_matches: bool,
        balance_tag_matches: bool,
        receipt_statement_hash_matches: bool,
        public_inputs_digest_matches: bool,
        proof_digest_matches: bool,
        proof_backend_matches: bool,
        ciphertext_payload_hashes_match: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCandidateArtifactBindingAdmissionCase {
        name: String,
        da_root_matches: bool,
        tx_statements_commitment_matches: bool,
        recursive_state_root_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBlockCommitmentAdmissionVectorFile {
        schema_version: u32,
        block_commitment_admission_cases: Vec<LeanBlockCommitmentAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBlockReplayRefinementVectorFile {
        schema_version: u32,
        block_replay_refinement_cases: Vec<LeanBlockReplayRefinementCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBlockReplayRefinementCase {
        name: String,
        leaf_start: u64,
        spent_nullifiers: Vec<u64>,
        consumed_bridge_replays: Vec<u64>,
        actions: Vec<LeanActionStreamActionCase>,
        parent_supply: String,
        height: u64,
        fee_total: u64,
        has_coinbase: bool,
        claimed_supply: String,
        tx_count_matches: bool,
        state_root_matches: bool,
        kernel_root_matches: bool,
        nullifier_root_matches: bool,
        extrinsics_root_matches: bool,
        message_root_matches: bool,
        message_count_matches: bool,
        header_mmr_root_matches: bool,
        header_mmr_len_matches: bool,
        expected_next_leaf_count: Option<String>,
        expected_imported_nullifier_count: Option<String>,
        expected_imported_bridge_replay_count: Option<String>,
        expected_planned_starts: Option<Vec<u64>>,
        expected_supply: Option<String>,
        expected_valid: bool,
        expected_rejection: Option<String>,
        expected_trace: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBlockCommitmentAdmissionCase {
        name: String,
        tx_count_matches: bool,
        state_root_matches: bool,
        kernel_root_matches: bool,
        nullifier_root_matches: bool,
        extrinsics_root_matches: bool,
        message_root_matches: bool,
        message_count_matches: bool,
        header_mmr_root_matches: bool,
        header_mmr_len_matches: bool,
        supply_digest_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCoinbaseAccountingAdmissionVectorFile {
        schema_version: u32,
        coinbase_accounting_admission_cases: Vec<LeanCoinbaseAccountingAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCoinbaseAccountingAdmissionCase {
        name: String,
        coinbase_count: usize,
        height: u64,
        transfer_fee_total: Option<String>,
        observed_coinbase_amount: Option<String>,
        expected_coinbase_amount: Option<String>,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCoinbaseActionPayloadAdmissionVectorFile {
        schema_version: u32,
        coinbase_action_payload_admission_cases: Vec<LeanCoinbaseActionPayloadAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCoinbaseActionPayloadAdmissionCase {
        name: String,
        amount_nonzero: bool,
        commitment_matches: bool,
        commitment_nonzero: bool,
        ciphertext_bytes: usize,
        max_ciphertext_bytes: usize,
        ciphertext_hash_matches: bool,
        ciphertext_size_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanResourceBudgetAdmissionVectorFile {
        schema_version: u32,
        mempool_budget_cases: Vec<LeanMempoolBudgetCase>,
        staged_proof_budget_cases: Vec<LeanStagedProofBudgetCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanMempoolBudgetCase {
        name: String,
        pending_bytes: usize,
        candidate_bytes: usize,
        max_bytes: usize,
        expected_total_bytes: usize,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanStagedProofBudgetCase {
        name: String,
        staged_bytes: usize,
        existing_bytes: usize,
        proof_bytes: usize,
        max_bytes: usize,
        expected_total_bytes: usize,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRpcAdmissionVectorFile {
        schema_version: u32,
        policy_cases: Vec<LeanRpcPolicyCase>,
        method_gate_cases: Vec<LeanRpcMethodGateCase>,
        method_list_cases: Vec<LeanRpcMethodListCase>,
        timestamp_range_cases: Vec<LeanRpcTimestampRangeCase>,
        byte_parse_cases: Vec<LeanRpcByteParseCase>,
        batch_cases: Vec<LeanRpcBatchCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRpcPolicyCase {
        name: String,
        raw: String,
        raw_tag: String,
        rpc_external: bool,
        expected_valid: bool,
        expected_policy: Option<String>,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRpcMethodGateCase {
        name: String,
        policy: String,
        method: String,
        is_unsafe_method: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRpcMethodListCase {
        name: String,
        policy: String,
        expected_unsafe_methods_visible: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRpcTimestampRangeCase {
        name: String,
        start_height: u64,
        end_height: u64,
        max_rows: u64,
        expected_requested_rows: Option<String>,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRpcByteParseCase {
        name: String,
        encoding: String,
        raw_text_bytes: usize,
        decoded_bytes: usize,
        max_decoded_bytes: usize,
        expected_encoded_len_limit: usize,
        expected_hex_len_limit: usize,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRpcBatchCase {
        name: String,
        request_count: usize,
        max_requests: usize,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSidecarUploadAdmissionVectorFile {
        schema_version: u32,
        request_count_cases: Vec<LeanSidecarRequestCountCase>,
        capacity_cases: Vec<LeanSidecarCapacityCase>,
        proof_metadata_cases: Vec<LeanProofSidecarMetadataCase>,
        proof_decoded_cases: Vec<LeanProofSidecarDecodedCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSidecarRequestCountCase {
        name: String,
        kind: String,
        item_count: usize,
        max_items: usize,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSidecarCapacityCase {
        name: String,
        kind: String,
        staged_count: usize,
        max_staged_count: usize,
        replaces_existing: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanProofSidecarMetadataCase {
        name: String,
        binding_hash_present: bool,
        binding_hash_valid: bool,
        proof_present: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    fn default_true() -> bool {
        true
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanProofSidecarDecodedCase {
        name: String,
        proof_bytes: usize,
        max_proof_bytes: usize,
        #[serde(default = "default_true")]
        proof_binding_hash_matches_key: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSyncAdmissionVectorFile {
        schema_version: u32,
        sync_response_range_cases: Vec<LeanSyncResponseRangeCase>,
        sync_missing_request_cases: Vec<LeanSyncMissingRequestCase>,
        sync_response_count_cases: Vec<LeanSyncResponseCountCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSyncResponseRangeCase {
        name: String,
        from_height: u64,
        to_height: u64,
        best_height: u64,
        max_blocks: u64,
        expected_has_range: bool,
        expected_from_height: Option<u64>,
        expected_to_height: Option<u64>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSyncMissingRequestCase {
        name: String,
        best_height: u64,
        announced_height: u64,
        max_blocks: u64,
        expected_has_request: bool,
        expected_from_height: Option<u64>,
        expected_to_height: Option<u64>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSyncResponseCountCase {
        name: String,
        block_count: usize,
        max_blocks: usize,
        expected_valid: bool,
    }

    #[test]
    fn native_genesis_is_stable() {
        let a = genesis_meta(NATIVE_DEV_POW_BITS).expect("genesis");
        let b = genesis_meta(NATIVE_DEV_POW_BITS).expect("genesis");
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.height, 0);
    }

    #[test]
    fn parse_block_hash_height_params() {
        assert_eq!(parse_height("15"), Some(15));
        assert_eq!(parse_height("0xf"), Some(15));
    }

    #[test]
    fn submit_action_stages_and_imports_shielded_transfer() {
        use base64::Engine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let test_pow_bits = 0x207f_ffff;
        let config = NativeConfig {
            dev: true,
            tmp: false,
            base_path: tmp.path().to_path_buf(),
            db_path: tmp.path().join("native-chain.sled"),
            rpc_addr: "127.0.0.1:0".parse().expect("rpc addr"),
            p2p_listen_addr: "127.0.0.1:0".to_string(),
            node_name: "test".to_string(),
            rpc_methods: "unsafe".to_string(),
            rpc_external: false,
            rpc_cors: None,
            seeds: Vec::new(),
            max_peers: 0,
            mine: false,
            mine_threads: 1,
            miner_address: None,
            pow_bits: test_pow_bits,
        };
        let node = NativeNode::open(config).expect("node");
        let anchor = node.state.read().commitment_tree.root();
        let nullifier = [1u8; 48];
        let commitment = [2u8; 48];
        let note = protocol_shielded_pool::types::EncryptedNote {
            ciphertext: [3u8; protocol_shielded_pool::types::ENCRYPTED_NOTE_SIZE],
            kem_ciphertext: vec![4u8; 32],
        };
        let mut note_bytes = Vec::new();
        note_bytes.extend_from_slice(&note.ciphertext);
        note_bytes.extend_from_slice(&note.kem_ciphertext);
        let ciphertext_hash = ciphertext_hash_bytes(&note_bytes);
        let inputs = ShieldedTransferInputs {
            anchor,
            nullifiers: vec![nullifier],
            commitments: vec![commitment],
            ciphertext_hashes: vec![ciphertext_hash],
            balance_slot_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
            fee: 7,
            value_balance: 0,
            stablecoin: None,
        };
        let binding_hash = StarkVerifier::compute_binding_hash(&inputs).data;
        let binding = KernelVersionBinding {
            circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
        };
        let balance_slot_asset_ids = [0, u64::MAX, u64::MAX, u64::MAX];
        let proof = test_transfer_proof_artifact(
            anchor,
            &[nullifier],
            &[commitment],
            &[ciphertext_hash],
            balance_slot_asset_ids,
            7,
            None,
            binding,
        );
        let args = ShieldedTransferInlineArgs {
            proof,
            commitments: vec![commitment],
            ciphertexts: vec![note],
            anchor,
            balance_slot_asset_ids,
            binding_hash,
            stablecoin: None,
            fee: 7,
        };
        let request = json!({
            "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            "family_id": FAMILY_SHIELDED_POOL,
            "action_id": ACTION_SHIELDED_TRANSFER_INLINE,
            "new_nullifiers": [hex48(&nullifier)],
            "public_args": base64::engine::general_purpose::STANDARD.encode(args.encode()),
        });

        let action = node
            .validate_and_stage_action(request.clone())
            .expect("stage action");
        assert_eq!(node.state.read().pending_actions.len(), 1);
        assert!(node.validate_and_stage_action(request).is_err());

        let candidate = CandidateArtifact {
            version: BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count: 1,
            tx_statements_commitment: [5u8; 48],
            da_root: [6u8; 48],
            da_chunk_count: 1,
            commitment_proof: protocol_shielded_pool::types::StarkProof::default(),
            proof_mode: BlockProofMode::RecursiveBlock,
            proof_kind: PoolProofArtifactKind::RecursiveBlockV2,
            verifier_profile: consensus::proof::recursive_block_artifact_verifier_profile(),
            receipt_root: None,
            recursive_block: Some(protocol_shielded_pool::types::RecursiveBlockProofPayload {
                proof: protocol_shielded_pool::types::StarkProof {
                    data: vec![8u8; 32],
                },
            }),
        };
        let candidate_args = SubmitCandidateArtifactArgs { payload: candidate };
        node.validate_and_stage_action(json!({
            "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            "family_id": FAMILY_SHIELDED_POOL,
            "action_id": ACTION_SUBMIT_CANDIDATE_ARTIFACT,
            "new_nullifiers": [],
            "public_args": base64::engine::general_purpose::STANDARD.encode(candidate_args.encode()),
        }))
        .expect("stage candidate artifact");

        let work = node.prepare_work().expect("prepare native work");
        let seal = mine_native_round(work.clone(), 0).expect("test seal");
        let err = node
            .import_mined_block(&work, seal)
            .expect_err("invalid recursive artifacts must be rejected");
        let err_text = err.to_string();
        assert!(
            err_text.contains("candidate artifact"),
            "unexpected import rejection: {err_text}"
        );
        assert_eq!(node.state.read().pending_actions.len(), 2);
        assert!(!node.state.read().nullifiers.contains(&action.nullifiers[0]));
        assert_eq!(node.state.read().commitment_tree.leaf_count(), 0);
    }

    #[test]
    fn side_branch_with_more_work_reorganizes_canonical_chain() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let test_pow_bits = 0x207f_ffff;
        let config = NativeConfig {
            dev: true,
            tmp: false,
            base_path: tmp.path().to_path_buf(),
            db_path: tmp.path().join("native-chain.sled"),
            rpc_addr: "127.0.0.1:0".parse().expect("rpc addr"),
            p2p_listen_addr: "127.0.0.1:0".to_string(),
            node_name: "test".to_string(),
            rpc_methods: "unsafe".to_string(),
            rpc_external: false,
            rpc_cors: None,
            seeds: Vec::new(),
            max_peers: 0,
            mine: false,
            mine_threads: 1,
            miner_address: None,
            pow_bits: test_pow_bits,
        };
        let node = NativeNode::open(config).expect("node");
        let genesis = node.best_meta();

        let canonical_work = node.prepare_work().expect("prepare canonical native work");
        let canonical_seal = mine_native_round(canonical_work.clone(), 0).expect("canonical seal");
        let canonical = node
            .import_mined_block(&canonical_work, canonical_seal)
            .expect("canonical import")
            .expect("canonical block");
        assert_eq!(node.best_meta().hash, canonical.hash);

        let side_one = mined_empty_child(&genesis, 1, test_pow_bits, 1);
        node.import_announced_block(side_one.clone())
            .expect("side one import");
        let side_two = mined_empty_child(&side_one, 2, test_pow_bits, 2);
        assert!(node
            .import_announced_block(side_two.clone())
            .expect("side two import"));

        let best = node.best_meta();
        assert_eq!(best.hash, side_two.hash);
        assert_eq!(best.height, 2);
        assert_eq!(
            node.hash_by_height(1).expect("height one"),
            Some(side_one.hash)
        );
        assert_eq!(
            node.hash_by_height(2).expect("height two"),
            Some(side_two.hash)
        );
        assert_eq!(
            node.header_by_hash(&canonical.hash)
                .expect("old block")
                .unwrap()
                .hash,
            canonical.hash
        );
    }

    #[test]
    fn canonical_reorg_chain_admission_rejects_write_set_drift() {
        let pow_bits = 0x207f_ffff;
        let genesis = genesis_meta(pow_bits).expect("genesis");
        let child = mined_empty_child(&genesis, 1, pow_bits, 11);
        let chain = vec![genesis.clone(), child.clone()];
        let block_entries = chain
            .iter()
            .map(|meta| {
                (
                    meta.hash,
                    bincode::serialize(meta).expect("serialize block"),
                )
            })
            .collect::<Vec<_>>();
        let height_entries = chain
            .iter()
            .map(|meta| (meta.height, meta.hash))
            .collect::<Vec<_>>();
        let valid_input = native_canonical_reorg_chain_admission_input(
            &chain,
            &block_entries,
            &height_entries,
            Some(&child),
            pow_bits,
        )
        .expect("valid reorg input");
        assert!(evaluate_native_canonical_reorg_chain_admission(valid_input).is_ok());

        let mut bad_height_entries = height_entries.clone();
        bad_height_entries[1].1 = genesis.hash;
        let input = native_canonical_reorg_chain_admission_input(
            &chain,
            &block_entries,
            &bad_height_entries,
            Some(&child),
            pow_bits,
        )
        .expect("height mismatch input");
        assert_eq!(
            evaluate_native_canonical_reorg_chain_admission(input).err(),
            Some(NativeCanonicalReorgChainAdmissionRejection::HeightEntryMismatch)
        );

        let mut bad_block_entries = block_entries.clone();
        bad_block_entries[1].0 = genesis.hash;
        let input = native_canonical_reorg_chain_admission_input(
            &chain,
            &bad_block_entries,
            &height_entries,
            Some(&child),
            pow_bits,
        )
        .expect("block mismatch input");
        assert_eq!(
            evaluate_native_canonical_reorg_chain_admission(input).err(),
            Some(NativeCanonicalReorgChainAdmissionRejection::BlockRecordMismatch)
        );

        let input = native_canonical_reorg_chain_admission_input(
            &chain,
            &block_entries,
            &height_entries,
            Some(&genesis),
            pow_bits,
        )
        .expect("best mismatch input");
        assert_eq!(
            evaluate_native_canonical_reorg_chain_admission(input).err(),
            Some(NativeCanonicalReorgChainAdmissionRejection::BestMetadataMismatch)
        );
    }

    #[test]
    fn reorg_replay_revalidates_historical_parent_metadata_before_publish() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let genesis = node.best_meta();
        let first = mined_empty_child(&genesis, 1, pow_bits, 0);
        assert!(node
            .import_announced_block(first.clone())
            .expect("first block import"));
        assert_eq!(node.best_meta().hash, first.hash);

        let unsigned_first = unsigned_native_meta(first.clone());
        persist_block_record(&node.block_tree, &unsigned_first)
            .expect("replace persisted parent with unsigned metadata");
        let second = mined_empty_child(&first, 2, pow_bits, 1);
        let err = node
            .import_announced_block(second)
            .expect_err("historical parent metadata must be revalidated during replay");
        let err = format!("{err:?}");
        assert!(err.contains("invalid_miner_public_key_length"), "{err}");
        assert_eq!(node.best_meta().hash, first.hash);
        assert!(node.hash_by_height(2).expect("height two").is_none());
    }

    #[test]
    fn nonwinning_announced_side_branch_record_reloads_without_canonicalizing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let test_pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), test_pow_bits, "unsafe", false);

        let (canonical, side_one) = {
            let node = NativeNode::open(config.clone()).expect("node");
            let genesis = node.best_meta();

            let canonical_work = node.prepare_work().expect("prepare canonical native work");
            let canonical_seal = strongest_test_seal(&canonical_work, 0..512);
            let canonical = node
                .import_mined_block(&canonical_work, canonical_seal)
                .expect("canonical import")
                .expect("canonical block");
            assert_eq!(node.best_meta().hash, canonical.hash);

            let side_one = (1..128)
                .map(|round| mined_empty_child(&genesis, 1, test_pow_bits, round))
                .find(|candidate| !native_meta_better_than(candidate, &canonical))
                .expect("side child that does not beat canonical tip");
            assert!(
                !node
                    .import_announced_block(side_one.clone())
                    .expect("side branch import"),
                "nonwinning side branch must not reorganize the canonical chain"
            );
            assert_eq!(node.best_meta().hash, canonical.hash);
            assert_eq!(
                node.hash_by_height(1).expect("canonical height index"),
                Some(canonical.hash)
            );
            assert_eq!(
                node.header_by_hash(&side_one.hash)
                    .expect("side branch block record")
                    .expect("side branch block should be hash-addressable"),
                side_one
            );
            node.db.flush().expect("flush side branch record");
            (canonical, side_one)
        };

        let reopened = NativeNode::open(config).expect("reopen node");
        assert_eq!(reopened.best_meta().hash, canonical.hash);
        assert_eq!(
            reopened
                .hash_by_height(1)
                .expect("height index after reopen"),
            Some(canonical.hash),
            "nonwinning side branch must not replace the canonical height index"
        );
        assert_eq!(
            reopened
                .header_by_hash(&canonical.hash)
                .expect("canonical block record after reopen")
                .expect("canonical block remains addressable"),
            canonical
        );
        assert_eq!(
            reopened
                .header_by_hash(&side_one.hash)
                .expect("side branch block record after reopen")
                .expect("nonwinning side branch block remains addressable"),
            side_one
        );
    }

    #[test]
    fn reorg_replay_rechecks_historical_side_branch_artifacts_before_publish() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let test_pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), test_pow_bits, "unsafe", false);

        let (canonical, side_parent, side_child) = {
            let node = NativeNode::open(config.clone()).expect("node");
            let genesis = node.best_meta();

            let canonical_work = node.prepare_work().expect("prepare canonical native work");
            let canonical_seal = strongest_test_seal(&canonical_work, 0..512);
            let canonical = node
                .import_mined_block(&canonical_work, canonical_seal)
                .expect("canonical import")
                .expect("canonical block");
            assert_eq!(node.best_meta().hash, canonical.hash);

            let invalid_transfer =
                test_inline_transfer_action(genesis.state_root, [71u8; 48], [72u8; 48], 0);
            let invalid_candidate = test_candidate_artifact_action(1, 73);
            let side_parent = (1..1024)
                .map(|round| {
                    mined_child_with_actions(
                        &genesis,
                        1,
                        test_pow_bits,
                        round,
                        vec![invalid_transfer.clone(), invalid_candidate.clone()],
                    )
                })
                .find(|candidate| !native_meta_better_than(candidate, &canonical))
                .expect("side parent that does not beat canonical tip");
            persist_block_record(&node.block_tree, &side_parent).expect("persist side parent");
            node.db.flush().expect("flush persisted side parent");

            let side_child = mined_empty_child(&side_parent, 2, test_pow_bits, 2048);
            (canonical, side_parent, side_child)
        };

        let node = NativeNode::open(config).expect("reopen node with side branch parent");
        assert_eq!(node.best_meta().hash, canonical.hash);
        assert_eq!(
            node.header_by_hash(&side_parent.hash)
                .expect("side parent record")
                .expect("persisted side parent reloads"),
            side_parent
        );

        let err = node
            .import_announced_block(side_child.clone())
            .expect_err("reorg replay must recheck historical side-branch artifacts");
        let err_text = err.to_string();
        assert!(
            err_text.contains("native tx-leaf artifact") || err_text.contains("candidate artifact"),
            "unexpected replay artifact error: {err_text}"
        );
        assert_eq!(node.best_meta().hash, canonical.hash);
        assert_eq!(
            node.hash_by_height(1)
                .expect("height one after failed reorg"),
            Some(canonical.hash),
            "failed replay artifact verification must not replace canonical height index"
        );
        assert_eq!(node.commitment_tree.len(), 0);
        assert!(
            node.header_by_hash(&side_child.hash)
                .expect("side child lookup after failed import")
                .is_none(),
            "failed reorg child must not be persisted"
        );
    }

    #[test]
    fn reorg_rejects_missing_old_canonical_chain_before_publish() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let test_pow_bits = 0x207f_ffff;
        let node = NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false))
            .expect("node");
        let genesis = node.best_meta();

        stage_test_coinbase(&node, consensus::reward::block_subsidy(1), [81u8; 48]);
        let canonical_work = node.prepare_work().expect("prepare canonical native work");
        let canonical_seal = mine_native_round(canonical_work.clone(), 0).expect("canonical seal");
        let canonical = node
            .import_mined_block(&canonical_work, canonical_seal)
            .expect("canonical import")
            .expect("canonical block");
        assert_eq!(node.best_meta().hash, canonical.hash);
        let old_height_one = node.hash_by_height(1).expect("height one before reorg");
        let old_pending_len = node.state.read().pending_actions.len();
        let old_state_root = node.state.read().commitment_tree.root();

        let side_one = (1..128)
            .map(|round| mined_empty_child(&genesis, 1, test_pow_bits, round))
            .find(|candidate| !native_meta_better_than(candidate, &canonical))
            .expect("side child that does not beat canonical tip");
        persist_block_record(&node.block_tree, &side_one).expect("persist side parent");

        node.block_tree
            .remove(canonical.hash)
            .expect("remove old canonical best block record");
        node.block_tree.flush().expect("flush corrupted old chain");

        let side_two = mined_empty_child(&side_one, 2, test_pow_bits, 129);
        let err = node
            .import_announced_block(side_two.clone())
            .expect_err("missing old canonical chain must reject winning reorg");
        let err_text = err.to_string();
        assert!(
            err_text.contains("missing native block"),
            "unexpected reorg error: {err_text}"
        );
        assert_eq!(node.best_meta().hash, canonical.hash);
        assert_eq!(
            node.hash_by_height(1)
                .expect("height index after rejected reorg"),
            old_height_one,
            "failed reorg must not replace the old canonical height index"
        );
        assert_eq!(
            node.hash_by_height(2)
                .expect("height two after rejected reorg"),
            None,
            "failed reorg must not publish the side tip height index"
        );
        assert_eq!(node.state.read().pending_actions.len(), old_pending_len);
        assert_eq!(node.state.read().commitment_tree.root(), old_state_root);
        assert!(
            node.header_by_hash(&side_two.hash)
                .expect("side tip lookup after rejected reorg")
                .is_none(),
            "failed reorg child must not be persisted"
        );
    }

    #[test]
    fn reorg_action_block_commit_reloads_canonical_sled_state() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let test_pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), test_pow_bits, "safe", false);
        let canonical_reward = consensus::reward::block_subsidy(1);
        let side_reward = consensus::reward::block_subsidy(2);

        let (canonical, old_action_hash, side_one, side_two, side_action_hash, side_commitment) = {
            let node = NativeNode::open(config.clone()).expect("node");
            let genesis = node.best_meta();

            stage_test_coinbase(&node, canonical_reward, [31u8; 48]);
            let old_action_hash = *node
                .state
                .read()
                .pending_actions
                .keys()
                .next()
                .expect("staged canonical action");
            let canonical_work = node.prepare_work().expect("prepare canonical native work");
            let canonical_seal =
                mine_native_round(canonical_work.clone(), 0).expect("canonical seal");
            let canonical = node
                .import_mined_block(&canonical_work, canonical_seal)
                .expect("canonical import")
                .expect("canonical block");
            assert_eq!(node.commitment_tree.len(), 1);
            assert_eq!(node.ciphertext_archive_tree.len(), 1);

            let side_one = (1..128)
                .map(|round| mined_empty_child(&genesis, 1, test_pow_bits, round))
                .find(|candidate| !native_meta_better_than(candidate, &canonical))
                .expect("side child that does not beat canonical tip");
            persist_block_record(&node.block_tree, &side_one).expect("persist side parent");

            let side_action = test_coinbase_action(side_reward);
            let side_action_hash = side_action.tx_hash;
            let side_commitment = side_action.commitments[0];
            let side_two =
                mined_child_with_actions(&side_one, 2, test_pow_bits, 129, vec![side_action]);
            assert!(
                node.header_by_hash(&side_two.hash)
                    .expect("read side tip before import")
                    .is_none(),
                "winning announced side tip should not be pre-persisted by this test"
            );
            assert!(
                node.import_announced_block(side_two.clone())
                    .expect("side two import"),
                "side action block must trigger reorg"
            );
            assert_eq!(node.best_meta().hash, side_two.hash);
            assert_eq!(node.commitment_tree.len(), 1);
            assert_eq!(node.ciphertext_archive_tree.len(), 1);
            assert!(node
                .action_tree
                .get(side_action_hash.as_slice())
                .expect("read side action")
                .is_none());

            (
                canonical,
                old_action_hash,
                side_one,
                side_two,
                side_action_hash,
                side_commitment,
            )
        };

        let reopened = NativeNode::open(config).expect("reopen node after reorg commit");
        let state = reopened.state.read();
        assert_eq!(state.best.hash, side_two.hash);
        assert_eq!(state.best.height, 2);
        assert_eq!(state.best.supply_digest, side_reward as u128);
        assert_eq!(state.commitment_tree.leaf_count(), 1);
        assert_eq!(state.commitment_tree.root(), side_two.state_root);
        assert!(
            state.pending_actions.contains_key(&old_action_hash),
            "orphaned old canonical action should be pending after reorg"
        );
        assert!(
            !state.pending_actions.contains_key(&side_action_hash),
            "canonical side action must not remain pending after reorg"
        );
        drop(state);

        assert_eq!(
            reopened.hash_by_height(1).expect("height one"),
            Some(side_one.hash)
        );
        assert_eq!(
            reopened.hash_by_height(2).expect("height two"),
            Some(side_two.hash)
        );
        assert_eq!(
            reopened
                .header_by_hash(&canonical.hash)
                .expect("old canonical header")
                .expect("old canonical block remains addressable")
                .hash,
            canonical.hash
        );
        assert_eq!(
            reopened
                .header_by_hash(&side_two.hash)
                .expect("side tip header")
                .expect("winning side tip block record reloads")
                .hash,
            side_two.hash
        );
        assert_eq!(reopened.commitment_tree.len(), 1);
        assert_eq!(reopened.ciphertext_archive_tree.len(), 1);
        assert_eq!(
            reopened
                .commitment_tree
                .get(0u64.to_be_bytes())
                .expect("read canonical commitment")
                .expect("canonical commitment")
                .as_ref(),
            side_commitment.as_slice()
        );
        assert!(reopened
            .action_tree
            .get(side_action_hash.as_slice())
            .expect("read side action after reopen")
            .is_none());
        assert!(reopened
            .action_tree
            .get(old_action_hash.as_slice())
            .expect("read orphaned action after reopen")
            .is_some());
    }

    #[test]
    fn reorg_pending_revalidation_prioritizes_existing_pending_over_orphaned_duplicate_nullifier() {
        let test_pow_bits = 0x207f_ffff;
        let canonical_state = test_state(genesis_meta(test_pow_bits).expect("genesis"));
        let anchor = canonical_state.commitment_tree.root();
        let nullifier = [73u8; 48];
        let orphaned = test_inline_transfer_action(anchor, nullifier, [74u8; 48], 0);
        let existing = test_inline_transfer_action(anchor, nullifier, [75u8; 48], 0);
        assert_ne!(existing.tx_hash, orphaned.tx_hash);

        let mut existing_pending = BTreeMap::new();
        existing_pending.insert(existing.tx_hash, existing.clone());
        let revalidated = revalidate_reorg_pending_actions(
            &canonical_state,
            existing_pending,
            vec![orphaned.clone()],
        );

        assert!(
            revalidated.contains_key(&existing.tx_hash),
            "existing pending action should keep priority"
        );
        assert!(
            !revalidated.contains_key(&orphaned.tx_hash),
            "orphaned duplicate nullifier must be quarantined before reorg persistence"
        );
        assert_eq!(revalidated.len(), 1);
    }

    #[test]
    fn reorg_rebuild_failure_preserves_canonical_indexes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let test_pow_bits = 0x207f_ffff;
        let node = NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false))
            .expect("node");
        let genesis = node.best_meta();

        stage_test_coinbase(&node, consensus::reward::block_subsidy(1), [61u8; 48]);
        let canonical_work = node.prepare_work().expect("prepare canonical native work");
        let canonical_seal = mine_native_round(canonical_work.clone(), 0).expect("canonical seal");
        let canonical = node
            .import_mined_block(&canonical_work, canonical_seal)
            .expect("canonical import")
            .expect("canonical block");
        assert_eq!(node.best_meta().hash, canonical.hash);
        assert_eq!(node.commitment_tree.len(), 1);
        assert_eq!(node.ciphertext_archive_tree.len(), 1);

        let side_one = (1..128)
            .map(|round| mined_empty_child(&genesis, 1, test_pow_bits, round))
            .find(|candidate| !native_meta_better_than(candidate, &canonical))
            .expect("side child that does not beat canonical tip");
        persist_block_record(&node.block_tree, &side_one).expect("persist side parent");

        let parent_state = test_state(side_one.clone());
        let sidecar = test_sidecar_transfer_action(
            parent_state.commitment_tree.root(),
            [62u8; 48],
            [63u8; 48],
            0,
        );
        let candidate = test_candidate_artifact_action(1, 64);
        let side_two =
            mined_child_with_actions(&side_one, 2, test_pow_bits, 129, vec![sidecar, candidate]);
        persist_block_record(&node.block_tree, &side_two).expect("persist side tip");

        let old_height_one = node.hash_by_height(1).expect("height index before reorg");
        let old_commitments = node.commitment_tree.len();
        let old_ciphertexts = node.ciphertext_archive_tree.len();
        let old_best = node.best_meta().hash;
        let err = {
            let mut state = node.state.write();
            let new_chain = node
                .chain_to_hash(side_two.hash)
                .expect("load side chain for reorg");
            let err = node
                .reorganize_chain_to_best_locked(&mut state, new_chain)
                .expect_err("missing sidecar ciphertext must reject before canonical clear");
            assert_eq!(state.best.hash, old_best);
            err
        };
        let err_text = err.to_string();
        assert!(
            err_text.contains("missing canonical DA ciphertext"),
            "unexpected reorg error: {err_text}"
        );
        assert_eq!(node.best_meta().hash, old_best);
        assert_eq!(
            node.hash_by_height(1)
                .expect("height index after failed reorg"),
            old_height_one,
            "failed reorg must leave canonical height index untouched"
        );
        assert_eq!(
            node.commitment_tree.len(),
            old_commitments,
            "failed reorg must not clear canonical commitments"
        );
        assert_eq!(
            node.ciphertext_archive_tree.len(),
            old_ciphertexts,
            "failed reorg must not clear canonical ciphertext archive"
        );
    }

    #[test]
    fn coinbase_action_mints_shielded_output_and_updates_supply() {
        use base64::Engine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let test_pow_bits = 0x207f_ffff;
        let config = NativeConfig {
            dev: true,
            tmp: false,
            base_path: tmp.path().to_path_buf(),
            db_path: tmp.path().join("native-chain.sled"),
            rpc_addr: "127.0.0.1:0".parse().expect("rpc addr"),
            p2p_listen_addr: "127.0.0.1:0".to_string(),
            node_name: "test".to_string(),
            rpc_methods: "unsafe".to_string(),
            rpc_external: false,
            rpc_cors: None,
            seeds: Vec::new(),
            max_peers: 0,
            mine: false,
            mine_threads: 1,
            miner_address: None,
            pow_bits: test_pow_bits,
        };
        let node = NativeNode::open(config).expect("node");
        let reward = consensus::reward::block_subsidy(1);
        let coinbase = test_coinbase_action(reward);
        let args: MintCoinbaseArgs = decode_scale_exact(&coinbase.public_args, "coinbase args")
            .expect("decode test coinbase args");
        node.validate_and_stage_action(json!({
            "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            "family_id": FAMILY_SHIELDED_POOL,
            "action_id": ACTION_MINT_COINBASE,
            "new_nullifiers": [],
            "public_args": base64::engine::general_purpose::STANDARD.encode(args.encode()),
        }))
        .expect("stage coinbase");

        let work = node.prepare_work().expect("prepare native work");
        let seal = mine_native_round(work.clone(), 0).expect("coinbase seal");
        let imported = node
            .import_mined_block(&work, seal)
            .expect("coinbase import")
            .expect("coinbase block");
        assert_eq!(imported.supply_digest, reward as u128);
        assert_eq!(node.state.read().commitment_tree.leaf_count(), 1);
        assert_eq!(node.state.read().pending_actions.len(), 0);
    }

    #[test]
    fn prepare_work_auto_coinbase_is_imported_and_wallet_decryptable() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let keys = wallet::RootSecret::from_bytes([7u8; 32]).derive();
        let material = keys.address(0).expect("address material");
        let address = material.shielded_address();
        let mut config = test_config(tmp.path(), pow_bits, "unsafe", false);
        config.miner_address = Some(address.encode().expect("encode miner address"));
        let node = NativeNode::open(config).expect("node");

        let reward = consensus::reward::block_subsidy(1);
        let work = node.prepare_work().expect("prepare native work");
        assert_eq!(work.tx_count, 1);
        let seal = mine_native_round(work.clone(), 0).expect("auto coinbase seal");
        let imported = node
            .import_mined_block(&work, seal)
            .expect("auto coinbase import")
            .expect("auto coinbase block");
        assert_eq!(imported.supply_digest, reward as u128);
        assert_eq!(node.state.read().commitment_tree.leaf_count(), 1);

        let actions = decode_block_actions(&imported).expect("decode imported actions");
        assert_eq!(actions.len(), 1);
        assert!(is_coinbase_action(&actions[0]));
        let args: MintCoinbaseArgs =
            decode_scale_exact(&actions[0].public_args, "auto coinbase args")
                .expect("decode auto coinbase args");
        let miner_note = &args.reward_bundle.miner_note;
        assert_eq!(miner_note.amount, reward);
        assert_eq!(
            miner_note.recipient_address,
            coinbase_recipient_address_bytes(&address)
        );
        assert_eq!(
            miner_note.commitment,
            coinbase_note_data_commitment(miner_note)
        );

        let ciphertext = NoteCiphertext::from_chain_bytes(&miner_note.encrypted_note.encode())
            .expect("wallet decode auto coinbase ciphertext");
        let recovered = ciphertext
            .decrypt(&material)
            .expect("decrypt auto coinbase note");
        assert_eq!(recovered.value, reward);
        assert_eq!(recovered.asset_id, 0);
        assert_eq!(recovered.memo.as_bytes(), b"");
    }

    #[test]
    fn prepare_work_auto_coinbase_ignores_staged_coinbase_recipient() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let keys = wallet::RootSecret::from_bytes([8u8; 32]).derive();
        let material = keys.address(0).expect("address material");
        let address = material.shielded_address();
        let mut config = test_config(tmp.path(), pow_bits, "unsafe", false);
        config.miner_address = Some(address.encode().expect("encode miner address"));
        let node = NativeNode::open(config).expect("node");
        let reward = consensus::reward::block_subsidy(1);
        stage_test_coinbase(&node, reward, [0xe5u8; 48]);

        let staged = node
            .state
            .read()
            .pending_actions
            .values()
            .next()
            .cloned()
            .expect("staged coinbase");
        let work = node.prepare_work().expect("prepare native work");
        assert_eq!(work.tx_count, 1);
        let seal = mine_native_round(work.clone(), 0).expect("auto coinbase seal");
        let imported = node
            .import_mined_block(&work, seal)
            .expect("auto coinbase import")
            .expect("auto coinbase block");
        let actions = decode_block_actions(&imported).expect("decode imported actions");
        assert_eq!(actions.len(), 1);
        assert_ne!(actions[0].tx_hash, staged.tx_hash);
        let args: MintCoinbaseArgs =
            decode_scale_exact(&actions[0].public_args, "auto coinbase args")
                .expect("decode auto coinbase args");
        assert_eq!(
            args.reward_bundle.miner_note.recipient_address,
            coinbase_recipient_address_bytes(&address)
        );
    }

    #[test]
    fn mined_action_block_commit_reloads_canonical_sled_state() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), pow_bits, "safe", false);
        let reward = consensus::reward::block_subsidy(1);
        let commitment = [17u8; 48];
        let imported = {
            let node = NativeNode::open(config.clone()).expect("node");
            stage_test_coinbase(&node, reward, commitment);
            let action_hash = *node
                .state
                .read()
                .pending_actions
                .keys()
                .next()
                .expect("staged coinbase action");
            let work = node.prepare_work().expect("prepare native work");
            let seal = mine_native_round(work.clone(), 0).expect("coinbase seal");
            let imported = node
                .import_mined_block(&work, seal)
                .expect("coinbase import")
                .expect("coinbase block");
            assert_eq!(node.best_meta().hash, imported.hash);
            assert_eq!(node.commitment_tree.len(), 1);
            assert_eq!(node.ciphertext_archive_tree.len(), 1);
            assert!(node
                .action_tree
                .get(action_hash.as_slice())
                .expect("read action tree")
                .is_none());
            imported
        };

        let reopened = NativeNode::open(config).expect("reopen node after mined commit");
        let state = reopened.state.read();
        assert_eq!(state.best.hash, imported.hash);
        assert_eq!(state.best.height, 1);
        assert_eq!(state.best.supply_digest, reward as u128);
        assert_eq!(state.commitment_tree.leaf_count(), 1);
        assert_eq!(state.commitment_tree.root(), imported.state_root);
        assert_eq!(state.pending_actions.len(), 0);
        drop(state);
        assert_eq!(
            reopened.hash_by_height(1).expect("height index"),
            Some(imported.hash)
        );
        assert_eq!(
            reopened
                .header_by_hash(&imported.hash)
                .expect("header lookup")
                .expect("persisted header")
                .hash,
            imported.hash
        );
        assert_eq!(reopened.commitment_tree.len(), 1);
        assert_eq!(reopened.ciphertext_archive_tree.len(), 1);
        assert_eq!(reopened.action_tree.len(), 0);
    }

    #[test]
    fn startup_canonical_index_repair_rebuilds_archive_atomically() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), pow_bits, "safe", false);
        let reward = consensus::reward::block_subsidy(1);
        let stale_ciphertext_hash = [99u8; 48];
        let (
            imported,
            expected_commitment,
            expected_archive,
            expected_index_hash,
            expected_index_value,
        ) = {
            let node = NativeNode::open(config.clone()).expect("node");
            stage_test_coinbase(&node, reward, [23u8; 48]);
            let action = node
                .state
                .read()
                .pending_actions
                .values()
                .next()
                .expect("staged coinbase")
                .clone();
            let expected_commitment = action.commitments[0];
            let expected_index_hash = action.ciphertext_hashes[0];
            let mut expected_index_value = Vec::with_capacity(32 + 4 + 8);
            expected_index_value.extend_from_slice(&action.tx_hash);
            expected_index_value.extend_from_slice(&action.ciphertext_sizes[0].to_le_bytes());
            expected_index_value.extend_from_slice(&0u64.to_le_bytes());

            let work = node.prepare_work().expect("prepare native work");
            let seal = mine_native_round(work.clone(), 0).expect("coinbase seal");
            let imported = node
                .import_mined_block(&work, seal)
                .expect("coinbase import")
                .expect("coinbase block");
            assert_eq!(node.commitment_tree.len(), 1);
            assert_eq!(node.ciphertext_index_tree.len(), 1);
            assert_eq!(node.ciphertext_archive_tree.len(), 1);
            let expected_archive = node
                .ciphertext_archive_tree
                .get(0u64.to_be_bytes())
                .expect("read canonical archive")
                .expect("canonical archive entry")
                .to_vec();
            node.db.flush().expect("flush mined test db");
            (
                imported,
                expected_commitment,
                expected_archive,
                expected_index_hash,
                expected_index_value,
            )
        };

        {
            let db = sled::open(&config.db_path).expect("open test db for repair corruption");
            let ciphertext_index_tree = db
                .open_tree("shielded_ciphertext_index")
                .expect("ciphertext index tree");
            let ciphertext_archive_tree = db
                .open_tree("shielded_ciphertexts_by_index")
                .expect("ciphertext archive tree");
            ciphertext_index_tree
                .remove(expected_index_hash.as_slice())
                .expect("remove canonical index");
            ciphertext_index_tree
                .insert(stale_ciphertext_hash.as_slice(), b"stale".as_slice())
                .expect("insert stale index");
            ciphertext_archive_tree
                .remove(0u64.to_be_bytes())
                .expect("remove canonical archive");
            db.flush().expect("flush repair corruption");
        }

        let reopened = NativeNode::open(config).expect("reopen with canonical index repair");
        let state = reopened.state.read();
        assert_eq!(state.best.hash, imported.hash);
        assert_eq!(state.best.height, 1);
        assert_eq!(state.best.supply_digest, reward as u128);
        assert_eq!(state.commitment_tree.leaf_count(), 1);
        assert_eq!(state.commitment_tree.root(), imported.state_root);
        drop(state);

        assert_eq!(reopened.commitment_tree.len(), 1);
        assert_eq!(
            reopened
                .commitment_tree
                .get(0u64.to_be_bytes())
                .expect("read repaired commitment")
                .expect("repaired commitment")
                .as_ref(),
            expected_commitment.as_slice()
        );
        assert_eq!(reopened.ciphertext_archive_tree.len(), 1);
        assert_eq!(
            reopened
                .ciphertext_archive_tree
                .get(0u64.to_be_bytes())
                .expect("read repaired archive")
                .expect("repaired archive")
                .as_ref(),
            expected_archive.as_slice()
        );
        assert_eq!(reopened.ciphertext_index_tree.len(), 1);
        assert_eq!(
            reopened
                .ciphertext_index_tree
                .get(expected_index_hash.as_slice())
                .expect("read repaired ciphertext index")
                .expect("repaired ciphertext index")
                .as_ref(),
            expected_index_value.as_slice()
        );
        assert!(
            reopened
                .ciphertext_index_tree
                .get(stale_ciphertext_hash.as_slice())
                .expect("read stale ciphertext index")
                .is_none(),
            "startup repair must remove stale ciphertext index rows in the same replacement"
        );
    }

    #[test]
    fn startup_replays_canonical_block_actions_before_accepting_state() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), pow_bits, "safe", false);
        let imported = {
            let node = NativeNode::open(config.clone()).expect("node");
            let work = node.prepare_work().expect("prepare empty work");
            let seal = mine_native_round(work.clone(), 0).expect("empty seal");
            let imported = node
                .import_mined_block(&work, seal)
                .expect("empty import")
                .expect("empty block");
            node.db.flush().expect("flush empty block");
            imported
        };

        {
            let db = sled::open(&config.db_path).expect("open test db for body corruption");
            let meta_tree = db.open_tree("meta").expect("meta tree");
            let block_tree = db.open_tree("block_meta_by_hash").expect("block tree");
            let mut corrupted = imported;
            corrupted.action_bytes.push(vec![0xaa]);
            let encoded = bincode::serialize(&corrupted).expect("serialize corrupted metadata");
            meta_tree
                .insert(META_BEST_KEY, encoded.clone())
                .expect("corrupt best body");
            block_tree
                .insert(corrupted.hash.as_slice(), encoded)
                .expect("corrupt block body");
            db.flush().expect("flush body corruption");
        }

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("startup must replay canonical block bodies"),
            Err(err) => err,
        };
        let err = format!("{err:?}");
        assert!(err.contains("block action payload count mismatch"), "{err}");
    }

    #[test]
    fn wallet_archive_rpcs_are_paginated_and_wallet_compatible() {
        use base64::Engine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let test_pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), test_pow_bits, "safe", false)).expect("node");

        stage_test_coinbase(&node, consensus::reward::block_subsidy(1), [21u8; 48]);
        let work = node.prepare_work().expect("prepare native work");
        let seal = mine_native_round(work.clone(), 0).expect("first seal");
        node.import_mined_block(&work, seal)
            .expect("first import")
            .expect("first block");

        stage_test_coinbase(&node, consensus::reward::block_subsidy(2), [22u8; 48]);
        let work = node.prepare_work().expect("prepare native work");
        let seal = mine_native_round(work.clone(), 0).expect("second seal");
        node.import_mined_block(&work, seal)
            .expect("second import")
            .expect("second block");

        {
            let mut state = node.state.write();
            state.nullifiers.insert([31u8; 48]);
            state.nullifiers.insert([32u8; 48]);
        }

        let commitments = node
            .wallet_commitments(json!({"start": 0, "limit": 1}))
            .expect("commitments page");
        assert_eq!(commitments["total"], json!(2));
        assert_eq!(commitments["has_more"], json!(true));
        let commitment_entry = commitments["entries"][0].as_object().expect("entry object");
        assert!(commitment_entry.contains_key("value"));
        assert!(commitment_entry.contains_key("commitment"));

        let ciphertexts = node
            .wallet_ciphertexts(json!({"start": 0, "limit": 1}))
            .expect("ciphertexts page");
        assert_eq!(ciphertexts["total"], json!(2));
        assert_eq!(ciphertexts["has_more"], json!(true));
        let ciphertext = ciphertexts["entries"][0]["ciphertext"]
            .as_str()
            .expect("ciphertext string");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(ciphertext)
            .expect("base64 ciphertext");
        assert_eq!(
            decoded.len(),
            protocol_shielded_pool::types::ENCRYPTED_NOTE_SIZE + 32
        );
        assert_eq!(node.ciphertext_archive_tree.len(), 2);
        let best_hash = node.best_meta().hash;
        node.block_tree
            .remove(best_hash.as_slice())
            .expect("remove block record");
        let archived_ciphertexts = node
            .wallet_ciphertexts(json!({"start": 1, "limit": 1}))
            .expect("ciphertexts from archive");
        assert_eq!(archived_ciphertexts["total"], json!(2));
        assert_eq!(
            archived_ciphertexts["entries"]
                .as_array()
                .expect("archive entries")
                .len(),
            1
        );

        let nullifiers = node
            .wallet_nullifiers(json!({"start": 1, "limit": 1}))
            .expect("nullifier page");
        assert_eq!(nullifiers["total"], json!(2));
        assert_eq!(nullifiers["has_more"], json!(false));
        assert_eq!(nullifiers["nullifiers"].as_array().expect("array").len(), 1);
    }

    #[test]
    fn wallet_commitments_rejects_malformed_commitment_key() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        node.commitment_tree
            .insert(b"bad-key", [1u8; 48].as_slice())
            .expect("insert malformed commitment key");

        let err = node
            .wallet_commitments(json!({"start": 0, "limit": 1024}))
            .expect_err("malformed commitment key must reject wallet RPC");
        assert!(err
            .to_string()
            .contains("native commitment archive key has invalid length"));
    }

    #[test]
    fn wallet_commitments_rejects_malformed_commitment_value() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        node.commitment_tree
            .insert(0u64.to_be_bytes(), vec![2u8; 47])
            .expect("insert malformed commitment value");

        let err = node
            .wallet_commitments(json!({"start": 0, "limit": 1024}))
            .expect_err("malformed commitment value must reject wallet RPC");
        assert!(err
            .to_string()
            .contains("native commitment archive value has invalid length"));
    }

    #[test]
    fn wallet_commitments_rejects_commitment_index_gap() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        node.commitment_tree
            .insert(1u64.to_be_bytes(), [3u8; 48].as_slice())
            .expect("insert gapped commitment value");

        let err = node
            .wallet_commitments(json!({"start": 0, "limit": 1024}))
            .expect_err("commitment index gap must reject wallet RPC");
        assert!(err
            .to_string()
            .contains("native commitment archive index gap"));
    }

    #[test]
    fn wallet_ciphertexts_rejects_malformed_archive_key() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        node.ciphertext_archive_tree
            .insert(b"bad-key", vec![4u8; MIN_NATIVE_WALLET_CIPHERTEXT_BYTES])
            .expect("insert malformed ciphertext key");

        let err = node
            .wallet_ciphertexts(json!({"start": 0, "limit": 1024}))
            .expect_err("malformed ciphertext key must reject wallet RPC");
        assert!(err
            .to_string()
            .contains("native ciphertext archive key has invalid length"));
    }

    #[test]
    fn wallet_ciphertexts_rejects_malformed_archive_value() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        node.ciphertext_archive_tree
            .insert(
                0u64.to_be_bytes(),
                vec![5u8; MIN_NATIVE_WALLET_CIPHERTEXT_BYTES - 1],
            )
            .expect("insert short ciphertext value");

        let short_err = node
            .wallet_ciphertexts(json!({"start": 0, "limit": 1024}))
            .expect_err("short ciphertext value must reject wallet RPC");
        assert!(short_err
            .to_string()
            .contains("native ciphertext archive value is too short"));

        node.ciphertext_archive_tree
            .insert(0u64.to_be_bytes(), vec![6u8; MAX_CIPHERTEXT_BYTES + 1])
            .expect("insert oversized ciphertext value");
        let oversize_err = node
            .wallet_ciphertexts(json!({"start": 0, "limit": 1024}))
            .expect_err("oversized ciphertext value must reject wallet RPC");
        assert!(oversize_err
            .to_string()
            .contains("native ciphertext archive value exceeds max"));
    }

    #[test]
    fn empty_block_does_not_advance_supply_digest() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let test_pow_bits = 0x207f_ffff;
        let node = NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false))
            .expect("node");

        let work = node.prepare_work().expect("prepare native work");
        let seal = mine_native_round(work.clone(), 0).expect("empty seal");
        let imported = node
            .import_mined_block(&work, seal)
            .expect("empty import")
            .expect("empty block");

        assert_eq!(imported.supply_digest, 0);
        assert_eq!(node.best_meta().supply_digest, 0);
    }

    #[test]
    fn mined_block_rejects_supply_digest_template_mismatch() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let test_pow_bits = 0x207f_ffff;
        let node = NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false))
            .expect("node");

        let mut work = node.prepare_work().expect("prepare native work");
        work.supply_digest = work.supply_digest.saturating_add(1);
        let seal = mine_native_round(work.clone(), 0).expect("mismatched supply seal");
        let imported = node
            .import_mined_block(&work, seal)
            .expect("supply mismatch should fail as stale work");

        assert!(imported.is_none());
        assert_eq!(node.best_meta().height, 0);
        assert_eq!(node.best_meta().supply_digest, 0);
    }

    #[test]
    fn prepare_work_drops_actions_after_supply_digest_overflow() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let test_pow_bits = 0x207f_ffff;
        let node = NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false))
            .expect("node");

        let subsidy = consensus::reward::block_subsidy(1);
        let mut parent = node.best_meta();
        parent.supply_digest = u128::MAX - u128::from(subsidy) + 1;
        {
            let mut state = node.state.write();
            state.best = parent.clone();
        }
        stage_test_coinbase(&node, subsidy, [55u8; 48]);

        let work = node.prepare_work().expect("prepare native work");
        assert_eq!(work.tx_count, 0);
        assert_eq!(work.state_root, parent.state_root);
        assert_eq!(work.nullifier_root, parent.nullifier_root);
        assert_eq!(work.extrinsics_root, actions_extrinsics_root(&[]));
        assert_eq!(work.message_count, 0);
        assert_eq!(work.message_root, empty_bridge_message_root());
        assert_eq!(work.supply_digest, parent.supply_digest);

        let expected_kernel_root =
            consensus::types::kernel_root_from_shielded_root(&parent.state_root);
        let expected_pre_header = native_pow_header_from_parts(
            work.height,
            work.timestamp_ms,
            parent.hash,
            test_pow_bits,
            [0u8; 32],
            work.cumulative_work,
            &parent.state_root,
            &expected_kernel_root,
            &parent.nullifier_root,
            &actions_extrinsics_root(&[]),
            &empty_bridge_message_root(),
            0,
            &work.header_mmr_root,
            work.header_mmr_len,
            parent.supply_digest,
            0,
        );
        assert_eq!(work.pre_hash, expected_pre_header.pre_hash());
    }

    #[test]
    fn prepare_work_rejects_missing_header_mmr_history() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let test_pow_bits = 0x207f_ffff;
        let node = NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false))
            .expect("node");
        let best = node.best_meta();
        node.block_tree
            .remove(best.hash)
            .expect("remove best block record");
        node.block_tree.flush().expect("flush block tree");

        let err = node
            .prepare_work()
            .expect_err("missing header-MMR history must reject work template");

        assert!(err.to_string().contains("missing native block"));
        assert_eq!(node.best_meta().height, best.height);
        assert_eq!(node.best_meta().hash, best.hash);
    }

    #[test]
    fn mined_invalid_pow_does_not_mutate_pending_state() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let test_pow_bits = 0x207f_ffff;
        let node = NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false))
            .expect("node");

        let reward = consensus::reward::block_subsidy(1);
        stage_test_coinbase(&node, reward, [42u8; 48]);

        let work = node.prepare_work().expect("prepare native work");
        let mut invalid_seal = mine_native_round(work.clone(), 0).expect("valid seal");
        invalid_seal.work_hash[0] ^= 0x80;

        let err = node
            .import_mined_block(&work, invalid_seal)
            .expect_err("invalid mined PoW must reject before mutation");
        assert!(err.to_string().contains("native"));

        let state = node.state.read();
        assert_eq!(state.best.height, 0);
        assert_eq!(state.best.supply_digest, 0);
        assert_eq!(state.pending_actions.len(), 1);
        assert_eq!(state.commitment_tree.leaf_count(), 0);
    }

    #[test]
    fn native_mined_block_carries_valid_miner_identity() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");

        let imported = mine_empty_native_block(&node);

        assert_eq!(imported.miner_public_key.len(), ML_DSA_PUBLIC_KEY_LEN);
        assert_eq!(imported.miner_signature.len(), ML_DSA_SIGNATURE_LEN);
        assert_eq!(
            imported.miner_commitment,
            native_miner_commitment(&imported.miner_public_key)
        );
        verify_native_miner_identity(&imported).expect("mined block signature verifies");
    }

    #[test]
    fn native_miner_identity_rejects_unsigned_non_genesis() {
        let pow_bits = 0x207f_ffff;
        let parent = genesis_meta(pow_bits).expect("genesis");
        let mut block = mined_empty_child(&parent, 1, pow_bits, 0);
        block.miner_public_key.clear();
        block.miner_signature.clear();
        block.miner_commitment = [0u8; 48];

        let err = validate_announced_block(&parent, &block)
            .expect_err("unsigned non-genesis announced block must reject");
        assert!(
            err.to_string().contains("invalid_miner_public_key_length"),
            "{err:?}"
        );
        assert!(verify_native_miner_identity(&parent).is_ok());
    }

    #[test]
    fn native_miner_identity_binds_commitment_nonce_and_work_hash() {
        let pow_bits = 0x207f_ffff;
        let parent = genesis_meta(pow_bits).expect("genesis");
        let block = mined_empty_child(&parent, 1, pow_bits, 0);

        let mut bad_commitment = block.clone();
        bad_commitment.miner_commitment[0] ^= 1;
        let err = validate_announced_block(&parent, &bad_commitment)
            .expect_err("miner commitment mismatch must reject");
        assert!(err.to_string().contains("miner_commitment_mismatch"));

        let mut bad_nonce = block.clone();
        bad_nonce.nonce[0] ^= 1;
        let err = validate_announced_block(&parent, &bad_nonce)
            .expect_err("nonce tamper must invalidate miner signature before PoW");
        assert!(err
            .to_string()
            .contains("native_miner_signature_verification_failed"));

        let mut bad_work_hash = block.clone();
        bad_work_hash.work_hash[0] ^= 1;
        bad_work_hash.hash = bad_work_hash.work_hash;
        let err = validate_announced_block(&parent, &bad_work_hash)
            .expect_err("work-hash tamper must invalidate miner signature before PoW");
        assert!(err
            .to_string()
            .contains("native_miner_signature_verification_failed"));
    }

    #[test]
    fn native_miner_identity_rejects_wrong_public_key() {
        let pow_bits = 0x207f_ffff;
        let parent = genesis_meta(pow_bits).expect("genesis");
        let mut block = mined_empty_child(&parent, 1, pow_bits, 0);
        let other = NativeMinerIdentity::from_seed(b"other native miner identity");
        block.miner_public_key = other.public_key.to_bytes();
        block.miner_commitment = native_miner_commitment(&block.miner_public_key);

        let err = validate_announced_block(&parent, &block)
            .expect_err("wrong public key must fail signature verification");
        assert!(err
            .to_string()
            .contains("native_miner_signature_verification_failed"));
    }

    #[test]
    fn legacy_native_block_metadata_decodes_without_miner_identity() {
        let current = mined_empty_child(
            &genesis_meta(0x207f_ffff).expect("genesis"),
            1,
            0x207f_ffff,
            0,
        );
        let legacy = legacy_meta_from_current(&current);
        let encoded = bincode::serialize(&legacy).expect("serialize legacy native metadata");
        let decoded =
            bincode_deserialize_native_block_meta_exact(&encoded, "legacy native metadata")
                .expect("decode legacy native metadata");

        assert_eq!(decoded.height, current.height);
        assert_eq!(decoded.hash, current.hash);
        assert!(decoded.miner_public_key.is_empty());
        assert!(decoded.miner_signature.is_empty());
        assert_eq!(decoded.miner_commitment, [0u8; 48]);
    }

    #[test]
    fn native_metadata_projection_rejects_legacy_unsigned_startup() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        {
            let node =
                NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
            let imported = mine_empty_native_block(&node);
            assert_eq!(imported.height, 1);
            let legacy = legacy_meta_from_current(&imported);
            let encoded = bincode::serialize(&legacy).expect("serialize legacy metadata");
            node.block_tree
                .insert(imported.hash.as_slice(), encoded.clone())
                .expect("replace block row with legacy metadata");
            node.meta_tree
                .insert(META_BEST_KEY, encoded)
                .expect("replace best row with legacy metadata");
            node.block_tree.flush().expect("flush block tree");
            node.meta_tree.flush().expect("flush meta tree");
        }

        let err = match NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)) {
            Ok(_) => panic!("legacy unsigned non-genesis metadata must fail startup"),
            Err(err) => err,
        };
        let err = format!("{err:?}");
        assert!(err.contains("invalid_miner_public_key_length"), "{err}");
    }

    #[test]
    fn native_metadata_projection_rejects_unsigned_sync_range() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let imported = mine_empty_native_block(&node);
        let unsigned = unsigned_native_meta(imported.clone());
        persist_block_record(&node.block_tree, &unsigned).expect("replace signed block row");

        let err = node
            .block_range(imported.height, imported.height)
            .expect_err("unsigned canonical metadata must not be served over sync");
        let err = format!("{err:?}");
        assert!(err.contains("invalid_miner_public_key_length"), "{err}");
    }

    #[test]
    fn announced_block_rejects_future_timestamp_skew() {
        let pow_bits = 0x207f_ffff;
        let parent = genesis_meta(pow_bits).expect("genesis");
        let timestamp_ms =
            current_time_ms().saturating_add(consensus::reward::MAX_FUTURE_SKEW_MS + 10_000);
        let future = mined_empty_child_at(&parent, 1, pow_bits, 0, timestamp_ms);

        let err = validate_announced_block(&parent, &future)
            .expect_err("future-dated block should be rejected");
        assert!(err.to_string().contains("future skew"));
    }

    #[test]
    fn announced_block_rejects_height_overflow() {
        let pow_bits = 0x207f_ffff;
        let mut parent = genesis_meta(pow_bits).expect("genesis");
        parent.height = u64::MAX;
        parent.timestamp_ms = 1000;
        parent.hash = [3u8; 32];
        let mut announced = parent.clone();
        announced.parent_hash = parent.hash;
        announced.timestamp_ms = parent.timestamp_ms + 1;
        announced.hash = [4u8; 32];
        announced.work_hash = announced.hash;

        let err = validate_announced_block(&parent, &announced)
            .expect_err("height overflow must fail closed");
        assert!(err.to_string().contains("height_not_next"));
    }

    #[test]
    fn mined_work_rejects_height_overflow() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
        let mut best = node.best_meta();
        best.height = u64::MAX;
        best.hash = [9u8; 32];
        best.timestamp_ms = 1000;
        {
            let mut state = node.state.write();
            state.best = best.clone();
        }
        let work = NativeWork {
            height: u64::MAX,
            parent_hash: best.hash,
            pre_hash: [0u8; 32],
            state_root: best.state_root,
            kernel_root: best.kernel_root,
            nullifier_root: best.nullifier_root,
            extrinsics_root: actions_extrinsics_root(&[]),
            message_root: empty_bridge_message_root(),
            message_count: 0,
            header_mmr_root: [0u8; 32],
            header_mmr_len: 0,
            cumulative_work: best.cumulative_work,
            supply_digest: best.supply_digest,
            tx_count: 0,
            timestamp_ms: best.timestamp_ms.saturating_add(1),
            pow_bits,
        };
        let imported = node
            .import_mined_block(
                &work,
                NativeSeal {
                    nonce: [0u8; 32],
                    work_hash: [0u8; 32],
                },
            )
            .expect("overflow work admission should fail closed");
        assert!(imported.is_none());
        assert_eq!(node.best_meta().height, u64::MAX);
    }

    #[test]
    fn prepare_work_rejects_height_overflow() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
        {
            let mut state = node.state.write();
            state.best.height = u64::MAX;
        }

        let err = node
            .prepare_work()
            .expect_err("max-height tip must not produce a native work template");
        assert!(err.to_string().contains("height_not_next"));
    }

    #[test]
    fn prepare_work_rejects_cumulative_work_overflow() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
        {
            let mut state = node.state.write();
            state.best.cumulative_work = [0xff; 48];
        }

        let err = node
            .prepare_work()
            .expect_err("work48 overflow must not produce a native work template");
        assert!(err.to_string().contains("cumulative_work_overflow"));
    }

    #[test]
    fn announced_block_rejects_counterfeit_body_commitments() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let parent = node.best_meta();
        let cases = [
            (TestCommitmentMutation::StateRoot, "state_root_mismatch"),
            (TestCommitmentMutation::KernelRoot, "kernel_root_mismatch"),
            (
                TestCommitmentMutation::NullifierRoot,
                "nullifier_root_mismatch",
            ),
            (
                TestCommitmentMutation::ExtrinsicsRoot,
                "extrinsics_root_mismatch",
            ),
            (TestCommitmentMutation::MessageRoot, "message_root_mismatch"),
            (
                TestCommitmentMutation::MessageCount,
                "message_count_mismatch",
            ),
            (
                TestCommitmentMutation::SupplyDigest,
                "supply_digest_mismatch",
            ),
        ];

        for (idx, (mutation, expected)) in cases.into_iter().enumerate() {
            let block =
                mined_empty_child_with_commitment_mutation(&parent, pow_bits, idx as u64, mutation);
            let err = node
                .import_announced_block(block)
                .expect_err("counterfeit body commitment should be rejected");
            assert!(
                err.to_string().contains(expected),
                "{mutation:?} should reject with {expected}, got {err}"
            );
        }
        assert_eq!(node.best_meta().height, 0);
    }

    #[test]
    fn announced_block_replay_commitment_mismatch_precedes_payload_validation() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let parent = node.best_meta();
        let height = parent.height.saturating_add(1);
        let mut coinbase = test_coinbase_action(consensus::reward::block_subsidy(height));
        tamper_coinbase_public_seed_without_rebinding(&mut coinbase);
        let mut block = mined_child_with_actions(&parent, height, pow_bits, 0, vec![coinbase]);
        block.state_root[0] ^= 1;
        let pre_header = native_pow_header_from_parts(
            block.height,
            block.timestamp_ms,
            block.parent_hash,
            block.pow_bits,
            [0u8; 32],
            block.cumulative_work,
            &block.state_root,
            &block.kernel_root,
            &block.nullifier_root,
            &block.extrinsics_root,
            &block.message_root,
            block.message_count,
            &block.header_mmr_root,
            block.header_mmr_len,
            block.supply_digest,
            block.tx_count,
        );
        let work = NativeWork {
            height: block.height,
            parent_hash: block.parent_hash,
            pre_hash: pre_header.pre_hash(),
            state_root: block.state_root,
            kernel_root: block.kernel_root,
            nullifier_root: block.nullifier_root,
            extrinsics_root: block.extrinsics_root,
            message_root: block.message_root,
            message_count: block.message_count,
            header_mmr_root: block.header_mmr_root,
            header_mmr_len: block.header_mmr_len,
            cumulative_work: block.cumulative_work,
            supply_digest: block.supply_digest,
            tx_count: block.tx_count,
            timestamp_ms: block.timestamp_ms,
            pow_bits: block.pow_bits,
        };
        let seal = mine_native_round(work, 1).expect("reseal mutated announced block");
        block.hash = seal.work_hash;
        block.work_hash = seal.work_hash;
        block.nonce = seal.nonce;
        sign_test_block_meta(&mut block);

        let err = node
            .import_announced_block(block)
            .expect_err("counterfeit commitment must reject before payload validation");

        assert!(
            err.to_string().contains("state_root_mismatch"),
            "state-root replay mismatch should not be masked by payload validation: {err}"
        );
        assert_eq!(node.best_meta().height, 0);
    }

    #[test]
    fn announced_block_action_root_mismatch_precedes_payload_materialization() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let parent = node.best_meta();
        let height = parent.height.saturating_add(1);
        let mut coinbase = test_coinbase_action(consensus::reward::block_subsidy(height));
        tamper_coinbase_public_seed_without_rebinding(&mut coinbase);
        let mut block = mined_child_with_actions(&parent, height, pow_bits, 0, vec![coinbase]);
        block.extrinsics_root[0] ^= 1;
        let pre_header = native_pow_header_from_parts(
            block.height,
            block.timestamp_ms,
            block.parent_hash,
            block.pow_bits,
            [0u8; 32],
            block.cumulative_work,
            &block.state_root,
            &block.kernel_root,
            &block.nullifier_root,
            &block.extrinsics_root,
            &block.message_root,
            block.message_count,
            &block.header_mmr_root,
            block.header_mmr_len,
            block.supply_digest,
            block.tx_count,
        );
        let work = NativeWork {
            height: block.height,
            parent_hash: block.parent_hash,
            pre_hash: pre_header.pre_hash(),
            state_root: block.state_root,
            kernel_root: block.kernel_root,
            nullifier_root: block.nullifier_root,
            extrinsics_root: block.extrinsics_root,
            message_root: block.message_root,
            message_count: block.message_count,
            header_mmr_root: block.header_mmr_root,
            header_mmr_len: block.header_mmr_len,
            cumulative_work: block.cumulative_work,
            supply_digest: block.supply_digest,
            tx_count: block.tx_count,
            timestamp_ms: block.timestamp_ms,
            pow_bits: block.pow_bits,
        };
        let seal = mine_native_round(work, 2).expect("reseal action-root mutation");
        block.hash = seal.work_hash;
        block.work_hash = seal.work_hash;
        block.nonce = seal.nonce;
        sign_test_block_meta(&mut block);

        let err = node
            .import_announced_block(block)
            .expect_err("action-root mismatch must reject before payload validation");

        assert!(
            err.to_string().contains("extrinsics_root_mismatch"),
            "action-root mismatch should not be masked by payload validation: {err}"
        );
        assert_eq!(node.best_meta().height, 0);
    }

    #[test]
    fn replay_rejects_counterfeit_message_commitment() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let parent = node.best_meta();
        let block = mined_empty_child_with_commitment_mutation(
            &parent,
            pow_bits,
            0,
            TestCommitmentMutation::MessageCount,
        );
        persist_block_record(&node.block_tree, &block).expect("persist counterfeit block");

        let err = node
            .replay_state_to_hash(block.hash)
            .expect_err("replay must reject counterfeit message commitment");
        assert!(err.to_string().contains("message_count_mismatch"));
    }

    #[test]
    fn rpc_policy_gates_unsafe_methods() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let safe_node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false))
            .expect("safe node");
        let err = dispatch_rpc_method(
            &safe_node,
            "da_submitCiphertexts",
            json!({"ciphertexts": []}),
        )
        .expect_err("safe RPC should reject DA staging");
        assert!(err.to_string().contains("unsafe RPC method"));
        let err = dispatch_rpc_method(&safe_node, "hegemon_submitAction", json!({}))
            .expect_err("safe RPC should reject action staging");
        assert!(err.to_string().contains("unsafe RPC method"));
        assert_eq!(safe_node.state.read().pending_actions.len(), 0);
        assert_eq!(safe_node.action_tree.len(), 0);

        assert_eq!(
            rpc_method_policy("auto", true).expect("external auto"),
            RpcMethodPolicy::Safe
        );
        assert_eq!(
            rpc_method_policy("auto", false).expect("local auto"),
            RpcMethodPolicy::Unsafe
        );

        let tmp = tempfile::tempdir().expect("tempdir");
        let unsafe_node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false))
            .expect("unsafe node");
        let allowed = dispatch_rpc_method(
            &unsafe_node,
            "da_submitCiphertexts",
            json!({"ciphertexts": []}),
        )
        .expect("unsafe RPC should allow DA staging");
        assert_eq!(allowed, Value::Array(Vec::new()));

        let methods = native_rpc_methods(RpcMethodPolicy::Safe);
        assert!(!methods.contains(&"da_submitCiphertexts"));
        assert!(!methods.contains(&"hegemon_startMining"));
        assert!(!methods.contains(&"hegemon_submitAction"));
        let unsafe_methods = native_rpc_methods(RpcMethodPolicy::Unsafe);
        assert!(unsafe_methods.contains(&"hegemon_submitAction"));
    }

    #[test]
    fn is_valid_anchor_rpc_matches_commitment_tree() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        let anchor = node.state.read().commitment_tree.root();

        let valid =
            dispatch_rpc_method(&node, "hegemon_isValidAnchor", json!([hex::encode(anchor)]))
                .expect("valid anchor RPC");
        assert_eq!(valid, json!(true));

        let unknown =
            dispatch_rpc_method(&node, "hegemon_isValidAnchor", json!([hex48(&[9u8; 48])]))
                .expect("unknown anchor RPC");
        assert_eq!(unknown, json!(false));

        let err = dispatch_rpc_method(&node, "hegemon_isValidAnchor", json!(["aa"]))
            .expect_err("malformed anchor must reject");
        assert!(err.to_string().contains("invalid anchor hex"));

        let methods = native_rpc_methods(RpcMethodPolicy::Safe);
        assert!(methods.contains(&"hegemon_isValidAnchor"));
    }

    #[test]
    fn submit_action_rejects_non_transfer_or_excess_nullifiers_before_parsing() {
        use base64::Engine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        let args = OutboundBridgeArgsV1 {
            destination_chain_id: [7u8; 32],
            app_family_id: 9,
            payload: b"unexpected nullifier".to_vec(),
        };
        let err = node
            .validate_and_stage_action(json!({
                "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
                "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
                "family_id": FAMILY_BRIDGE,
                "action_id": ACTION_BRIDGE_OUTBOUND,
                "new_nullifiers": ["not-hex"],
                "public_args": base64::engine::general_purpose::STANDARD.encode(args.encode()),
            }))
            .expect_err("non-transfer routes must reject nullifier lists");
        assert!(err.to_string().contains("new_nullifiers must be empty"));

        let too_many = vec!["00".repeat(48); transaction_core::constants::MAX_INPUTS + 1];
        let err = node
            .validate_and_stage_action(json!({
                "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
                "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
                "family_id": FAMILY_SHIELDED_POOL,
                "action_id": ACTION_SHIELDED_TRANSFER_INLINE,
                "new_nullifiers": too_many,
                "public_args": "not-base64",
            }))
            .expect_err("oversized nullifier list must reject before public_args decode");
        assert!(err.to_string().contains("exceeds MAX_INPUTS"));
        assert_eq!(node.state.read().pending_actions.len(), 0);
    }

    #[test]
    fn submit_action_rejects_unknown_or_nonempty_kernel_projection_fields() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");

        let accepted = node
            .validate_and_stage_action(action_request_projection_fixture(
                "valid_empty_wallet_envelope_fields",
            ))
            .expect("empty wallet envelope compatibility fields must be accepted");
        assert_eq!(node.state.read().pending_actions.len(), 1);
        assert_eq!(accepted.tx_hash, pending_action_hash(&accepted));

        let unknown = node
            .validate_and_stage_action(action_request_projection_fixture("unknown_field"))
            .expect_err("unknown action request fields must reject");
        assert!(
            unknown.to_string().contains("decode submit action request"),
            "unexpected unknown-field error: {unknown}"
        );

        for fixture in [
            "object_ref_present",
            "authorization_proof_present",
            "authorization_signature_present",
            "aux_data_present",
        ] {
            let err = node
                .validate_and_stage_action(action_request_projection_fixture(fixture))
                .expect_err("non-empty kernel envelope projection fields must reject");
            assert!(
                err.to_string().contains("kernel envelope fields"),
                "unexpected projection error for {fixture}: {err}"
            );
        }
    }

    #[test]
    fn submit_action_rejects_trailing_public_args() {
        use base64::Engine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        let args = OutboundBridgeArgsV1 {
            destination_chain_id: [7u8; 32],
            app_family_id: 9,
            payload: b"trailing-byte exploit".to_vec(),
        };
        let mut encoded = args.encode();
        encoded.push(0xaa);
        let err = node
            .validate_and_stage_action(json!({
                "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
                "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
                "family_id": FAMILY_BRIDGE,
                "action_id": ACTION_BRIDGE_OUTBOUND,
                "new_nullifiers": [],
                "public_args": base64::engine::general_purpose::STANDARD.encode(encoded),
            }))
            .expect_err("trailing bytes must be rejected");
        assert!(err.to_string().contains("trailing bytes"));
        assert_eq!(node.state.read().pending_actions.len(), 0);
    }

    #[test]
    fn native_metadata_rejects_trailing_bincode_bytes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let genesis = node.best_meta();
        let mut block_record = bincode::serialize(&genesis).expect("serialize genesis metadata");
        block_record.push(0xaa);
        node.block_tree
            .insert(genesis.hash.as_slice(), block_record)
            .expect("corrupt block record");

        let err = node
            .header_by_hash(&genesis.hash)
            .expect_err("trailing block metadata bytes must fail");
        assert!(err.to_string().contains("trailing bytes"));

        let mut best_record = bincode::serialize(&genesis).expect("serialize best metadata");
        best_record.push(0xbb);
        node.meta_tree
            .insert(META_BEST_KEY, best_record)
            .expect("corrupt best record");
        drop(node);

        let err = match NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)) {
            Ok(_) => panic!("trailing best metadata bytes must fail on reload"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("trailing bytes"));
    }

    #[test]
    fn chain_rpc_rejects_malformed_explicit_hash_without_latest_fallback() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");

        let latest_header = chain_get_header(&node, Value::Array(Vec::new()))
            .expect("no explicit header hash should return latest");
        assert_ne!(latest_header, Value::Null);
        let latest_block = chain_get_block(&node, Value::Array(Vec::new()))
            .expect("no explicit block hash should return latest");
        assert_ne!(latest_block, Value::Null);

        assert_eq!(
            chain_get_header(&node, json!(["0x1234"])).expect("malformed header hash"),
            Value::Null
        );
        assert_eq!(
            chain_get_header(&node, json!([42])).expect("wrong header param type"),
            Value::Null
        );
        assert_eq!(
            chain_get_block(&node, json!(["0x1234"])).expect("malformed block hash"),
            Value::Null
        );
        assert_eq!(
            chain_get_block(&node, json!([{"hash": hex32(&node.best_meta().hash)}]))
                .expect("wrong block param type"),
            Value::Null
        );
    }

    #[test]
    fn chain_rpc_rejects_block_record_key_hash_mismatch() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        let genesis = node.best_meta();
        let mut forged = genesis.clone();
        forged.hash[0] ^= 1;
        forged.work_hash = forged.hash;
        node.block_tree
            .insert(
                genesis.hash.as_slice(),
                bincode::serialize(&forged).expect("serialize forged metadata"),
            )
            .expect("forge block record");

        let params = json!([hex32(&genesis.hash)]);
        let err = chain_get_header(&node, params.clone())
            .expect_err("header RPC must reject key/hash drift");
        assert!(err
            .to_string()
            .contains("stored native block hash mismatch"));
        let err = chain_get_block(&node, params).expect_err("block RPC must reject key/hash drift");
        assert!(err
            .to_string()
            .contains("stored native block hash mismatch"));
    }

    #[test]
    fn chain_rpc_rejects_block_record_work_hash_mismatch() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        let genesis = node.best_meta();
        let mut forged = genesis.clone();
        forged.work_hash[0] ^= 1;
        node.block_tree
            .insert(
                genesis.hash.as_slice(),
                bincode::serialize(&forged).expect("serialize forged metadata"),
            )
            .expect("forge block record");

        let err = chain_get_block(&node, json!([hex32(&genesis.hash)]))
            .expect_err("block RPC must reject hash/work-hash drift");
        assert!(err
            .to_string()
            .contains("stored native block work-hash mismatch"));
    }

    #[test]
    fn start_mining_thread_param_accepts_default_and_valid_threads() {
        assert_eq!(start_mining_threads_from_params(&json!({})).unwrap(), 1);
        assert_eq!(
            start_mining_threads_from_params(&Value::Array(Vec::new())).unwrap(),
            1
        );
        assert_eq!(
            start_mining_threads_from_params(&json!({"threads": 1})).unwrap(),
            1
        );
        assert_eq!(
            start_mining_threads_from_params(&json!([{"threads": 2}])).unwrap(),
            2
        );
        assert_eq!(
            start_mining_threads_from_params(&json!({"threads": MAX_NATIVE_MINING_THREADS}))
                .unwrap(),
            MAX_NATIVE_MINING_THREADS
        );
    }

    #[test]
    fn start_mining_thread_param_rejects_malformed_explicit_threads() {
        let err = start_mining_threads_from_params(&json!(["bad params"]))
            .expect_err("non-object explicit params must reject");
        assert!(err.to_string().contains("params must be an object"));

        let err = start_mining_threads_from_params(&json!({"threads": "many"}))
            .expect_err("string thread count must reject");
        assert!(err.to_string().contains("unsigned integer"));

        let err = start_mining_threads_from_params(&json!({"threads": 0}))
            .expect_err("zero thread count must reject");
        assert!(err.to_string().contains("at least 1"));

        let err = start_mining_threads_from_params(
            &json!({"threads": u64::from(MAX_NATIVE_MINING_THREADS) + 1}),
        )
        .expect_err("overlarge thread count must reject");
        assert!(err.to_string().contains("exceeds maximum mining threads"));

        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
        let err = dispatch_rpc_method(&node, "hegemon_startMining", json!({"threads": "many"}))
            .expect_err("malformed start mining RPC must reject before side effects");
        let message = err.to_string();
        assert!(
            message.contains("unsigned integer"),
            "unexpected start-mining RPC error: {message}"
        );
        assert!(!node.mining.load(Ordering::SeqCst));
    }

    #[test]
    fn timestamp_rpc_rejects_unbounded_ranges() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");

        let err = block_timestamps(&node, json!([0, MAX_NATIVE_TIMESTAMP_ROWS]), false)
            .expect_err("range one larger than cap must fail");
        assert!(err.to_string().contains("timestamp range too large"));

        let err =
            block_timestamps(&node, json!([9, 8]), false).expect_err("inverted range must fail");
        assert!(err.to_string().contains("before start"));

        let mined = block_timestamps(&node, Value::Array(Vec::new()), true)
            .expect("genesis-only mined timestamps");
        assert_eq!(mined, Value::Array(Vec::new()));
    }

    #[test]
    fn timestamp_rpc_rejects_corrupt_explicit_range_header() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let genesis = node.best_meta();
        let mut block_record = bincode::serialize(&genesis).expect("serialize genesis metadata");
        block_record.push(0xaa);
        node.block_tree
            .insert(genesis.hash.as_slice(), block_record)
            .expect("corrupt block record");

        let err = block_timestamps(&node, json!([genesis.height, genesis.height]), false)
            .expect_err("explicit timestamp range must reject corrupt header metadata");
        assert!(err.to_string().contains("trailing bytes"));
    }

    #[test]
    fn timestamp_rpc_rejects_missing_canonical_height_inside_best_range() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        let future = block_timestamps(&node, json!([1, 1]), false)
            .expect("future timestamp rows may be absent");
        assert_eq!(
            future,
            json!([{
                "height": 1,
                "timestamp_ms": Value::Null,
            }])
        );

        let genesis = node.best_meta();
        node.height_tree
            .remove(height_key(genesis.height))
            .expect("remove canonical genesis height index");
        node.height_tree.flush().expect("flush height tree");

        let err = block_timestamps(&node, json!([genesis.height, genesis.height]), false)
            .expect_err("timestamp RPC must reject missing canonical height inside best range");
        assert!(err.to_string().contains("missing canonical height index"));
    }

    #[test]
    fn timestamp_rpc_rejects_canonical_record_height_mismatch() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        let genesis = node.best_meta();
        let mut forged = genesis.clone();
        forged.height = 1;
        node.block_tree
            .insert(
                genesis.hash.as_slice(),
                bincode::serialize(&forged).expect("serialize forged metadata"),
            )
            .expect("forge canonical block record");

        let err = block_timestamps(&node, json!([0, 0]), false)
            .expect_err("timestamp RPC must reject height/hash metadata drift");
        assert!(err
            .to_string()
            .contains("points to block metadata at height 1"));
    }

    #[test]
    fn timestamp_rpc_rejects_canonical_record_work_hash_mismatch() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        let genesis = node.best_meta();
        let mut forged = genesis.clone();
        forged.work_hash[0] ^= 1;
        node.block_tree
            .insert(
                genesis.hash.as_slice(),
                bincode::serialize(&forged).expect("serialize forged metadata"),
            )
            .expect("forge canonical block record");

        let err = block_timestamps(&node, json!([0, 0]), false)
            .expect_err("timestamp RPC must reject hash/work-hash metadata drift");
        assert!(err
            .to_string()
            .contains("stored native block work-hash mismatch"));
    }

    #[test]
    fn mempool_byte_budget_rejects_aggregate_overflow() {
        let state = test_state(genesis_meta(0x207f_ffff).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let first = test_inline_transfer_action(anchor, [41u8; 48], [51u8; 48], 0);
        let second = test_inline_transfer_action(anchor, [42u8; 48], [52u8; 48], 0);
        let mut pending = BTreeMap::new();
        pending.insert(first.tx_hash, first);
        let max = pending_mempool_bytes(&pending)
            .saturating_add(pending_action_mempool_bytes(&second))
            .saturating_sub(1);

        let err = validate_mempool_byte_budget(&pending, &second, max)
            .expect_err("aggregate byte budget must reject over-limit candidate");
        assert!(err.to_string().contains("mempool byte budget"));
    }

    #[test]
    fn staged_proof_byte_budget_rejects_aggregate_overflow() {
        let mut staged = BTreeMap::new();
        staged.insert("first".to_string(), vec![0u8; 4]);

        let err = validate_staged_proof_byte_budget(&staged, "second", 2, 5)
            .expect_err("aggregate staged proof bytes must be capped");
        assert!(err.to_string().contains("staged proof byte budget"));

        validate_staged_proof_byte_budget(&staged, "first", 5, 5)
            .expect("replacement should subtract existing proof bytes");
    }

    #[test]
    fn sidecar_upload_capacity_replacement_accepts_full_staging() {
        evaluate_native_ciphertext_sidecar_capacity_admission(
            NativeSidecarCapacityAdmissionInput {
                staged_count: 4,
                max_staged_count: 4,
                replaces_existing: true,
            },
        )
        .expect("ciphertext replacement at capacity should be accepted");
        evaluate_native_proof_sidecar_capacity_admission(NativeSidecarCapacityAdmissionInput {
            staged_count: 4,
            max_staged_count: 4,
            replaces_existing: true,
        })
        .expect("proof replacement at capacity should be accepted");

        let ciphertext_err = evaluate_native_ciphertext_sidecar_capacity_admission(
            NativeSidecarCapacityAdmissionInput {
                staged_count: 4,
                max_staged_count: 4,
                replaces_existing: false,
            },
        )
        .expect_err("new ciphertext at capacity must reject");
        assert_eq!(
            ciphertext_err,
            NativeSidecarUploadAdmissionRejection::StagedCiphertextCapacityReached
        );

        let proof_err =
            evaluate_native_proof_sidecar_capacity_admission(NativeSidecarCapacityAdmissionInput {
                staged_count: 4,
                max_staged_count: 4,
                replaces_existing: false,
            })
            .expect_err("new proof at capacity must reject");
        assert_eq!(
            proof_err,
            NativeSidecarUploadAdmissionRejection::StagedProofCapacityReached
        );
    }

    #[test]
    fn submit_ciphertexts_rejects_too_many_uploads() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
        let ciphertexts = vec![json!(""); MAX_NATIVE_DA_CIPHERTEXT_UPLOADS + 1];
        let err = node
            .submit_ciphertexts(json!({ "ciphertexts": ciphertexts }))
            .expect_err("too many ciphertext uploads must reject before decode");
        assert!(err.to_string().contains("too many ciphertexts"));
    }

    #[test]
    fn submit_proofs_rejects_too_many_uploads() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
        let proofs = vec![json!({}); MAX_NATIVE_DA_PROOF_UPLOADS + 1];
        let err = node
            .submit_proofs(json!({ "proofs": proofs }))
            .expect_err("too many proof uploads must reject before item decode");
        assert!(err.to_string().contains("too many proofs"));
    }

    #[test]
    fn submit_proofs_rejects_invalid_metadata_and_empty_proof() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
        let err = node
            .submit_proofs(json!({ "proofs": [{ "proof": "AA==" }] }))
            .expect_err("missing binding hash must reject first");
        assert!(err.to_string().contains("missing binding_hash"));

        let err = node
            .submit_proofs(json!({
                "proofs": [{ "binding_hash": "0x12", "proof": "AA==" }]
            }))
            .expect_err("invalid binding hash must reject before proof parsing");
        assert!(err.to_string().contains("invalid binding_hash"));

        let valid_binding_hash = format!("0x{}", "11".repeat(64));
        let err = node
            .submit_proofs(json!({
                "proofs": [{ "binding_hash": valid_binding_hash, "proof": "" }]
            }))
            .expect_err("empty proof must reject after metadata admission");
        assert!(err.to_string().contains("must be non-empty"));
    }

    #[test]
    fn submit_sidecars_accepts_valid_uploads_and_replacements() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");

        let ciphertexts = node
            .submit_ciphertexts(json!({ "ciphertexts": ["0x010203"] }))
            .expect("valid ciphertext sidecar should stage");
        let ciphertexts = ciphertexts
            .as_array()
            .expect("ciphertext result should be array");
        assert_eq!(ciphertexts.len(), 1);
        assert_eq!(ciphertexts[0]["size"].as_u64(), Some(3));
        assert!(ciphertexts[0]["hash"].as_str().unwrap().starts_with("0x"));

        let (binding_hash, proof) = staged_proof_fixture();
        let binding_hash = format!("0x{}", hex::encode(binding_hash));
        let proof_hex = format!("0x{}", hex::encode(&proof));
        let proofs = node
            .submit_proofs(json!({
                "proofs": [{ "binding_hash": binding_hash, "proof": proof_hex }]
            }))
            .expect("valid proof sidecar should stage");
        let proofs = proofs.as_array().expect("proof result should be array");
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0]["size"].as_u64(), Some(proof.len() as u64));
        assert!(proofs[0]["proof_hash"].as_str().unwrap().starts_with("0x"));
        assert_eq!(proofs[0]["binding_hash"], json!(binding_hash));

        let replacement_binding_hash = proofs[0]["binding_hash"].clone();
        node.submit_proofs(json!({
            "proofs": [{ "binding_hash": replacement_binding_hash, "proof": format!("0x{}", hex::encode(&proof)) }]
        }))
        .expect("same binding hash replacement should be accepted");

        let state = node.state.read();
        assert_eq!(state.staged_ciphertexts.len(), 1);
        assert_eq!(state.staged_proofs.len(), 1);
        assert_eq!(
            state.staged_proofs.values().next().unwrap().len(),
            proof.len()
        );
    }

    #[test]
    fn submit_proofs_canonicalizes_binding_hash_before_response_hashing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
        let (binding_hash, proof) = staged_proof_fixture();
        let prefixed_binding_hash = format!("0x{}", hex::encode(binding_hash));
        let uppercase_unprefixed_binding_hash = hex::encode(binding_hash).to_uppercase();
        let proof_hex = format!("0x{}", hex::encode(&proof));

        let prefixed_response = node
            .submit_proofs(json!({
                "proofs": [{ "binding_hash": prefixed_binding_hash, "proof": proof_hex }]
            }))
            .expect("prefixed proof sidecar");
        let prefixed = prefixed_response
            .as_array()
            .expect("prefixed response")
            .first()
            .expect("prefixed response entry")
            .clone();
        let uppercase_response = node
            .submit_proofs(json!({
                "proofs": [{ "binding_hash": uppercase_unprefixed_binding_hash, "proof": format!("0x{}", hex::encode(&proof)) }]
            }))
            .expect("uppercase unprefixed proof sidecar");
        let uppercase_unprefixed = uppercase_response
            .as_array()
            .expect("uppercase response")
            .first()
            .expect("uppercase response entry")
            .clone();

        assert_eq!(
            prefixed["binding_hash"],
            json!(format!("0x{}", hex::encode(binding_hash)))
        );
        assert_eq!(
            uppercase_unprefixed["binding_hash"],
            prefixed["binding_hash"]
        );
        assert_eq!(uppercase_unprefixed["proof_hash"], prefixed["proof_hash"]);
        assert_eq!(node.state.read().staged_proofs.len(), 1);
    }

    #[test]
    fn submit_proofs_rejects_binding_hash_mismatch_before_staging() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
        let (mut binding_hash, proof) = staged_proof_fixture();
        binding_hash[0] ^= 0xff;

        let err = node
            .submit_proofs(json!({
                "proofs": [{
                    "binding_hash": format!("0x{}", hex::encode(binding_hash)),
                    "proof": format!("0x{}", hex::encode(proof)),
                }]
            }))
            .expect_err("mismatched proof binding hash must reject before staging");
        assert!(err.to_string().contains("proof binding hash"));
        assert!(node.state.read().staged_proofs.is_empty());
        assert_eq!(node.da_proof_tree.len(), 0);
    }

    #[test]
    fn submit_proofs_rejects_non_native_tx_leaf_artifact() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
        let err = node
            .submit_proofs(json!({
                "proofs": [{
                    "binding_hash": format!("0x{}", "11".repeat(64)),
                    "proof": "0x01020304",
                }]
            }))
            .expect_err("non-native tx leaf artifact must reject before staging");
        assert!(err.to_string().contains("proof binding hash"));
        assert!(node.state.read().staged_proofs.is_empty());
        assert_eq!(node.da_proof_tree.len(), 0);
    }

    #[test]
    fn submit_proofs_rejects_repartitioned_tx_leaf_binding_alias() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
        let (binding_hash, proof) = repartitioned_tx_leaf_binding_alias_fixture();

        let err = node
            .submit_proofs(json!({
                "proofs": [{
                    "binding_hash": format!("0x{}", hex::encode(binding_hash)),
                    "proof": format!("0x{}", hex::encode(proof)),
                }]
            }))
            .expect_err("repartitioned tx-leaf artifact must not alias binding hash");
        assert!(err.to_string().contains("proof binding hash"));
        assert!(node.state.read().staged_proofs.is_empty());
        assert_eq!(node.da_proof_tree.len(), 0);
    }

    #[test]
    fn submit_proofs_rejects_value_balance_binding_alias() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
        let anchor = [45u8; 48];
        let nullifier = [46u8; 48];
        let commitment = [47u8; 48];
        let ciphertext_hash = [48u8; 48];
        let balance_slot_asset_ids = [0, u64::MAX, u64::MAX, u64::MAX];
        let fee = 3;
        let binding = KernelVersionBinding {
            circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
        };
        let zero_value_binding_hash =
            StarkVerifier::compute_binding_hash(&ShieldedTransferInputs {
                anchor,
                nullifiers: vec![nullifier],
                commitments: vec![commitment],
                ciphertext_hashes: vec![ciphertext_hash],
                balance_slot_asset_ids,
                fee,
                value_balance: 0,
                stablecoin: None,
            })
            .data;
        let proof = test_transfer_proof_artifact_with_value_balance(
            anchor,
            &[nullifier],
            &[commitment],
            &[ciphertext_hash],
            balance_slot_asset_ids,
            fee,
            -17,
            None,
            binding,
        );
        assert!(
            !native_tx_leaf_artifact_binding_hash_matches_key(zero_value_binding_hash, &proof),
            "artifact binding must bind decoded value balance"
        );

        let err = node
            .submit_proofs(json!({
                "proofs": [{
                    "binding_hash": format!("0x{}", hex::encode(zero_value_binding_hash)),
                    "proof": format!("0x{}", hex::encode(proof)),
                }]
            }))
            .expect_err("value-balance alias must not stage proof sidecar");
        assert!(err.to_string().contains("proof binding hash"));
        assert!(node.state.read().staged_proofs.is_empty());
        assert_eq!(node.da_proof_tree.len(), 0);
    }

    #[test]
    fn rpc_byte_parser_rejects_oversized_strings_before_trust_boundary_decode() {
        use base64::Engine;

        let oversized_base64 = "A".repeat(encoded_len_limit(4) + 1);
        let err = parse_bytes_value(&json!(oversized_base64), 4, "test base64")
            .expect_err("oversized base64 text should be rejected before decode");
        assert!(err.to_string().contains("base64 length"));

        let oversized_hex = format!("0x{}", "00".repeat(5));
        let err = parse_bytes_value(&json!(oversized_hex), 4, "test hex")
            .expect_err("oversized hex text should be rejected before decode");
        assert!(err.to_string().contains("hex length"));

        let encoded_five = base64::engine::general_purpose::STANDARD.encode([0u8; 5]);
        let err = parse_bytes_value(&json!(encoded_five), 4, "test decoded")
            .expect_err("decoded bytes above cap should be rejected");
        assert!(err.to_string().contains("decoded length"));

        let encoded_four = base64::engine::general_purpose::STANDARD.encode([7u8; 4]);
        assert_eq!(
            parse_bytes_value(&json!(encoded_four), 4, "test exact").expect("exact limit"),
            vec![7u8; 4]
        );
        assert_eq!(
            parse_bytes_value(&json!("0x01020304"), 4, "test exact hex").expect("exact hex"),
            vec![1, 2, 3, 4]
        );
    }

    #[test]
    fn native_sync_codec_rejects_legacy_or_trailing_bytes() {
        let message = NativeSyncMessage::Request {
            from_height: 1,
            to_height: 2,
        };
        let encoded = encode_sync_message(&message).expect("encode native sync message");
        assert!(decode_sync_message(&encoded).is_ok());

        let legacy = bincode::serialize(&message).expect("legacy bincode sync message");
        assert!(decode_sync_message(&legacy).is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_sync_message(&trailing).is_err());
    }

    #[tokio::test]
    async fn rpc_handler_rejects_oversized_batches() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        let payload = Value::Array(
            (0..=MAX_NATIVE_RPC_BATCH_REQUESTS)
                .map(|idx| {
                    json!({
                        "jsonrpc": "2.0",
                        "id": idx,
                        "method": "system_health",
                        "params": [],
                    })
                })
                .collect(),
        );

        let response = rpc_handler(State(node), Json(payload)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let decoded: Value = serde_json::from_slice(&body).expect("json body");
        assert!(decoded["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("batch too large"));
    }

    #[test]
    fn identity_seed_is_random_persisted_and_reloaded() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("pq-identity.seed");
        let first = load_or_create_identity_seed(&path).expect("create seed");
        let second = load_or_create_identity_seed(&path).expect("reload seed");
        assert_eq!(first, second);
        assert_eq!(parse_identity_seed_hex(&hex::encode(first)), Some(first));

        let old_deterministic = hash32_with_parts(&[
            b"hegemon-native-peer-v1",
            b"test",
            tmp.path().display().to_string().as_bytes(),
        ]);
        assert_ne!(first, old_deterministic);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn imported_block_actions_require_canonical_transfer_order() {
        let pow_bits = 0x207f_ffff;
        let best = genesis_meta(pow_bits).expect("genesis");
        let state = test_state(best.clone());
        let anchor = state.commitment_tree.root();
        let first = test_inline_transfer_action(anchor, [1u8; 48], [11u8; 48], 0);
        let second = test_inline_transfer_action(anchor, [2u8; 48], [22u8; 48], 0);
        let mut ordered = vec![first, second];
        ordered.sort_by_key(action_order_key);
        validate_block_actions_locked(&state, &ordered).expect("ordered actions should validate");

        let mut reversed = ordered.clone();
        reversed.reverse();
        if action_order_key(&reversed[0]) != action_order_key(&reversed[1]) {
            let err = validate_block_actions_locked(&state, &reversed)
                .expect_err("reversed actions should fail ordering");
            assert!(err.to_string().contains("canonical order"));
        }
    }

    #[test]
    fn lean_generated_action_order_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_ORDER_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_ACTION_ORDER_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean action-order vectors");
        let vectors: LeanActionOrderVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean action-order vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.action_order_cases.is_empty(),
            "Lean action-order cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.action_order_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_action_order_case(case);
        }
    }

    fn verify_lean_action_order_case(case: &LeanActionOrderCase) {
        let transfer_keys = case
            .actions
            .iter()
            .filter(|action| action.is_transfer)
            .map(|action| {
                parse_hash32(&action.key).expect("Lean action-order key must be 32-byte hex")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            lean_transfer_keys_are_canonical_order(&transfer_keys),
            case.expected_valid,
            "{} native transfer-order predicate drifted from Lean spec",
            case.name
        );
    }

    fn lean_transfer_keys_are_canonical_order(keys: &[[u8; 32]]) -> bool {
        let mut previous: Option<[u8; 32]> = None;
        for key in keys {
            if !transfer_key_extends_canonical_order(previous.as_ref(), key) {
                return false;
            }
            previous = Some(*key);
        }
        true
    }

    #[test]
    fn lean_generated_action_hash_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_HASH_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_ACTION_HASH_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean action-hash admission vectors");
        let vectors: LeanActionHashAdmissionVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean action-hash vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.action_hash_admission_cases.is_empty(),
            "Lean action-hash admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.action_hash_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_action_hash_admission_case(case);
        }
    }

    fn verify_lean_action_hash_admission_case(case: &LeanActionHashAdmissionCase) {
        let input = NativeActionHashAdmissionInput {
            action_count_matches: case.action_count_matches,
            action_hashes_match: case.action_hashes_match,
            action_hashes_unique: case.action_hashes_unique,
        };
        let actual_rejection = evaluate_native_action_hash_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native action-hash admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native action-hash admission rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_action_root_transcript_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_ROOT_TRANSCRIPT_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_ACTION_ROOT_TRANSCRIPT_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean action-root transcript vectors");
        let vectors: LeanActionRootTranscriptVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean action-root vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.action_root_transcript_cases.is_empty(),
            "Lean action-root transcript cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.action_root_transcript_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_action_root_transcript_case(case);
        }
    }

    fn verify_lean_action_root_transcript_case(case: &LeanActionRootTranscriptCase) {
        let action_hashes = case
            .action_hashes_hex
            .iter()
            .map(|raw| parse_hash32(raw).expect("Lean action hash must be 32-byte hex"))
            .collect::<Vec<_>>();
        let expected_preimage =
            decode_lean_hex_bytes(&case.expected_preimage_hex).expect("decode Lean preimage hex");
        let actual_preimage = action_root_transcript_preimage(&action_hashes);
        assert_eq!(
            actual_preimage.len(),
            case.expected_preimage_len,
            "{} native action-root preimage length drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_preimage, expected_preimage,
            "{} native action-root preimage bytes drifted from Lean spec",
            case.name
        );
    }

    fn decode_lean_hex_bytes(raw: &str) -> Option<Vec<u8>> {
        hex::decode(raw.strip_prefix("0x").unwrap_or(raw)).ok()
    }

    #[test]
    fn lean_generated_announced_block_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_ANNOUNCED_BLOCK_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_ANNOUNCED_BLOCK_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean announced-block admission vectors");
        let vectors: LeanAnnouncedBlockAdmissionVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean announced-block vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.announced_block_admission_cases.is_empty(),
            "Lean announced-block admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.announced_block_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_announced_block_admission_case(case);
        }
    }

    fn verify_lean_announced_block_admission_case(case: &LeanAnnouncedBlockAdmissionCase) {
        let input = NativeAnnouncedBlockAdmissionInput {
            parent_height: case.parent_height,
            announced_height: case.announced_height,
            parent_hash_matches: case.parent_hash_matches,
            parent_timestamp_ms: case.parent_timestamp_ms,
            announced_timestamp_ms: case.announced_timestamp_ms,
            now_ms: case.now_ms,
            max_future_skew_ms: case.max_future_skew_ms,
            hash_matches_work_hash: case.hash_matches_work_hash,
        };
        let actual_rejection = evaluate_native_announced_block_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native announced-block admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native announced-block admission rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_block_index_reload_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BLOCK_INDEX_RELOAD_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_BLOCK_INDEX_RELOAD_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw =
            std::fs::read_to_string(&path).expect("read generated Lean block-index reload vectors");
        let vectors: LeanBlockIndexReloadVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean block-index reload vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.block_index_reload_cases.is_empty(),
            "Lean block-index reload cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.block_index_reload_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_block_index_reload_case(case);
        }
    }

    fn verify_lean_block_index_reload_case(case: &LeanBlockIndexReloadCase) {
        let input = NativeBlockIndexReloadInput {
            chain_reconstructed: case.chain_reconstructed,
            chain_nonempty: case.chain_nonempty,
            genesis_matches_expected: case.genesis_matches_expected,
            best_metadata_matches_chain: case.best_metadata_matches_chain,
            canonical_heights_contiguous: case.canonical_heights_contiguous,
            canonical_chain_ids_match: case.canonical_chain_ids_match,
            canonical_rules_hashes_match: case.canonical_rules_hashes_match,
            canonical_hashes_match_work_hashes: case.canonical_hashes_match_work_hashes,
            canonical_parent_hashes_contiguous: case.canonical_parent_hashes_contiguous,
            height_keys_well_formed: case.height_keys_well_formed,
            height_values_well_formed: case.height_values_well_formed,
            no_extra_height_indexes: case.no_extra_height_indexes,
            height_index_heights_match_chain: case.height_index_heights_match_chain,
            height_index_hashes_match_chain: case.height_index_hashes_match_chain,
            all_canonical_heights_indexed: case.all_canonical_heights_indexed,
            genesis_marker_present: case.genesis_marker_present,
            genesis_marker_length_valid: case.genesis_marker_length_valid,
            genesis_marker_matches_expected: case.genesis_marker_matches_expected,
        };
        let actual = evaluate_native_block_index_reload(input);
        let actual_rejection = actual
            .as_ref()
            .err()
            .map(|rejection| rejection.label().to_owned());
        let actual_repairs_genesis_marker = actual
            .as_ref()
            .ok()
            .map(|admission| admission.repair_missing_genesis_marker)
            .unwrap_or(false);
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native block-index reload validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native block-index reload rejection drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_repairs_genesis_marker, case.expected_repairs_genesis_marker,
            "{} native block-index reload repair decision drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_canonical_reorg_chain_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_CANONICAL_REORG_CHAIN_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_CANONICAL_REORG_CHAIN_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean canonical reorg chain admission vectors");
        let vectors: LeanCanonicalReorgChainAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean canonical reorg chain admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.canonical_reorg_chain_admission_cases.is_empty(),
            "Lean canonical reorg chain admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.canonical_reorg_chain_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_canonical_reorg_chain_admission_case(case);
        }
    }

    fn verify_lean_canonical_reorg_chain_admission_case(
        case: &LeanCanonicalReorgChainAdmissionCase,
    ) {
        let input = NativeCanonicalReorgChainAdmissionInput {
            chain_nonempty: case.chain_nonempty,
            genesis_matches_expected: case.genesis_matches_expected,
            best_metadata_matches_chain: case.best_metadata_matches_chain,
            canonical_heights_contiguous: case.canonical_heights_contiguous,
            canonical_chain_ids_match: case.canonical_chain_ids_match,
            canonical_rules_hashes_match: case.canonical_rules_hashes_match,
            canonical_hashes_match_work_hashes: case.canonical_hashes_match_work_hashes,
            canonical_parent_hashes_contiguous: case.canonical_parent_hashes_contiguous,
            block_record_count_matches_chain: case.block_record_count_matches_chain,
            block_records_match_chain: case.block_records_match_chain,
            height_entry_count_matches_chain: case.height_entry_count_matches_chain,
            height_entries_match_chain: case.height_entries_match_chain,
        };
        let actual_rejection = evaluate_native_canonical_reorg_chain_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native canonical reorg chain admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native canonical reorg chain admission rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_canonical_state_reload_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_CANONICAL_STATE_RELOAD_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_CANONICAL_STATE_RELOAD_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean canonical-state reload vectors");
        let vectors: LeanCanonicalStateReloadVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean canonical-state reload vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.canonical_state_reload_cases.is_empty(),
            "Lean canonical-state reload cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.canonical_state_reload_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_canonical_state_reload_case(case);
        }
    }

    fn verify_lean_canonical_state_reload_case(case: &LeanCanonicalStateReloadCase) {
        let input = NativeCanonicalStateReloadInput {
            nullifier_keys_well_formed: case.nullifier_keys_well_formed,
            nullifier_markers_valid: case.nullifier_markers_valid,
            commitment_keys_well_formed: case.commitment_keys_well_formed,
            commitment_values_well_formed: case.commitment_values_well_formed,
            commitment_indexes_contiguous: case.commitment_indexes_contiguous,
            commitment_tree_rebuilt: case.commitment_tree_rebuilt,
            commitment_root_matches_best: case.commitment_root_matches_best,
            nullifier_root_matches_best: case.nullifier_root_matches_best,
        };
        let actual_rejection = evaluate_native_canonical_state_reload(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native canonical-state reload validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native canonical-state reload rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_bridge_replay_reload_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_REPLAY_RELOAD_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_BRIDGE_REPLAY_RELOAD_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean bridge-replay reload vectors");
        let vectors: LeanBridgeReplayReloadVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean bridge-replay reload vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.bridge_replay_reload_cases.is_empty(),
            "Lean bridge-replay reload cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.bridge_replay_reload_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_bridge_replay_reload_case(case);
        }
    }

    fn verify_lean_bridge_replay_reload_case(case: &LeanBridgeReplayReloadCase) {
        let input = NativeBridgeReplayReloadInput {
            replay_keys_well_formed: case.replay_keys_well_formed,
            replay_markers_valid: case.replay_markers_valid,
            canonical_replay_keys_unique: case.canonical_replay_keys_unique,
            no_missing_loaded_replay_keys: case.no_missing_loaded_replay_keys,
            no_extra_loaded_replay_keys: case.no_extra_loaded_replay_keys,
        };
        let actual_rejection = evaluate_native_bridge_replay_reload(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native bridge-replay reload validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native bridge-replay reload rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_bridge_witness_export_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_WITNESS_EXPORT_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_BRIDGE_WITNESS_EXPORT_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean bridge witness export admission vectors");
        let vectors: LeanBridgeWitnessExportAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean bridge witness export admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.bridge_witness_export_admission_cases.is_empty(),
            "Lean bridge witness export admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.bridge_witness_export_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_bridge_witness_export_admission_case(case);
        }
    }

    fn verify_lean_bridge_witness_export_admission_case(
        case: &LeanBridgeWitnessExportAdmissionCase,
    ) {
        let input = NativeBridgeWitnessExportAdmissionInput {
            block_hash_parameter_valid: case.block_hash_parameter_valid,
            block_known: case.block_known,
            canonical_height_present: case.canonical_height_present,
            block_is_canonical: case.block_is_canonical,
            block_actions_decoded: case.block_actions_decoded,
            message_index_in_bounds: case.message_index_in_bounds,
            parent_known: case.parent_known,
            best_height: case.best_height,
            message_height: case.message_height,
        };
        let actual = evaluate_native_bridge_witness_export_admission(input);
        let actual_rejection = actual
            .as_ref()
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} native bridge witness export admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual.ok(),
            case.expected_confirmations_checked,
            "{} native bridge witness confirmations drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native bridge witness export admission rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_inbound_bridge_receipt_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_INBOUND_BRIDGE_RECEIPT_ADMISSION_VECTORS")
        else {
            eprintln!(
                "HEGEMON_LEAN_INBOUND_BRIDGE_RECEIPT_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean inbound bridge receipt admission vectors");
        let vectors: LeanInboundBridgeReceiptAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean inbound bridge receipt admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.inbound_bridge_receipt_admission_cases.is_empty(),
            "Lean inbound bridge receipt admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.inbound_bridge_receipt_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_inbound_bridge_receipt_admission_case(case);
        }
    }

    fn verify_lean_inbound_bridge_receipt_admission_case(
        case: &LeanInboundBridgeReceiptAdmissionCase,
    ) {
        let input = NativeInboundBridgeReceiptAdmissionInput {
            source_chain_matches: case.source_chain_matches,
            rules_hash_matches: case.rules_hash_matches,
            message_nonce_matches: case.message_nonce_matches,
            message_hash_matches: case.message_hash_matches,
            checkpoint_height: case.checkpoint_height,
            canonical_tip_height: case.canonical_tip_height,
            confirmations_checked: case.confirmations_checked,
            min_confirmations: case.min_confirmations,
        };
        let actual = evaluate_native_inbound_bridge_receipt_admission(input);
        let actual_rejection = actual
            .as_ref()
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} native inbound bridge receipt admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual.ok(),
            case.expected_height_confirmations,
            "{} native inbound bridge receipt height-confirmation count drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native inbound bridge receipt admission rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_bridge_witness_backscan_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_WITNESS_BACKSCAN_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_BRIDGE_WITNESS_BACKSCAN_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean bridge witness backscan vectors");
        let vectors: LeanBridgeWitnessBackscanVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean bridge witness backscan vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.bridge_witness_backscan_cases.is_empty(),
            "Lean bridge witness backscan cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.bridge_witness_backscan_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_bridge_witness_backscan_case(case);
        }
    }

    fn verify_lean_bridge_witness_backscan_case(case: &LeanBridgeWitnessBackscanCase) {
        let entries = case
            .entries
            .iter()
            .map(|entry| NativeBridgeWitnessBackscanEntry {
                height: entry.height,
                canonical_hash_present: entry.canonical_hash_present,
                block_known: entry.block_known,
                block_actions_decoded: entry.block_actions_decoded,
                message_index_in_bounds: entry.message_index_in_bounds,
            })
            .collect::<Vec<_>>();
        let actual = evaluate_native_bridge_witness_backscan(&entries);
        let actual_rejection = actual
            .as_ref()
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} native bridge witness backscan validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual.ok(),
            case.expected_selected_height,
            "{} native bridge witness backscan selected height drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native bridge witness backscan rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_pending_action_reload_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_PENDING_ACTION_RELOAD_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_PENDING_ACTION_RELOAD_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean pending-action reload vectors");
        let vectors: LeanPendingActionReloadVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean pending-action reload vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.pending_action_reload_cases.is_empty(),
            "Lean pending-action reload cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.pending_action_reload_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_pending_action_reload_case(case);
        }
    }

    fn verify_lean_pending_action_reload_case(case: &LeanPendingActionReloadCase) {
        let input = NativePendingActionReloadInput {
            key_well_formed: case.key_well_formed,
            embedded_hash_matches_key: case.embedded_hash_matches_key,
            recomputed_hash_matches_embedded: case.recomputed_hash_matches_embedded,
            action_hash_unique: case.action_hash_unique,
        };
        let actual_rejection = evaluate_native_pending_action_reload(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native pending-action reload validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native pending-action reload rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_staged_ciphertext_reload_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_STAGED_CIPHERTEXT_RELOAD_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_STAGED_CIPHERTEXT_RELOAD_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean staged-ciphertext reload vectors");
        let vectors: LeanStagedCiphertextReloadVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean staged-ciphertext reload vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.staged_ciphertext_reload_cases.is_empty(),
            "Lean staged-ciphertext reload cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.staged_ciphertext_reload_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_staged_ciphertext_reload_case(case);
        }
    }

    fn verify_lean_staged_ciphertext_reload_case(case: &LeanStagedCiphertextReloadCase) {
        let input = NativeStagedCiphertextReloadInput {
            key_well_formed: case.key_well_formed,
            ciphertext_within_limit: case.ciphertext_within_limit,
            ciphertext_hash_matches_key: case.ciphertext_hash_matches_key,
            capacity_available: case.capacity_available,
        };
        let actual_rejection = evaluate_native_staged_ciphertext_reload(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native staged-ciphertext reload validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native staged-ciphertext reload rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_staged_proof_reload_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_STAGED_PROOF_RELOAD_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_STAGED_PROOF_RELOAD_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean staged-proof reload vectors");
        let vectors: LeanStagedProofReloadVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean staged-proof reload vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.staged_proof_reload_cases.is_empty(),
            "Lean staged-proof reload cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.staged_proof_reload_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_staged_proof_reload_case(case);
        }
    }

    fn verify_lean_staged_proof_reload_case(case: &LeanStagedProofReloadCase) {
        let input = NativeStagedProofReloadInput {
            key_well_formed: case.key_well_formed,
            proof_nonempty: case.proof_nonempty,
            proof_within_limit: case.proof_within_limit,
            capacity_available: case.capacity_available,
            byte_capacity_available: case.byte_capacity_available,
            proof_binding_hash_matches_key: case.proof_binding_hash_matches_key,
        };
        let actual_rejection = evaluate_native_staged_proof_reload(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native staged-proof reload validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native staged-proof reload rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_mined_work_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_MINED_WORK_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_MINED_WORK_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean mined-work admission vectors");
        let vectors: LeanMinedWorkAdmissionVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean mined-work vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.mined_work_admission_cases.is_empty(),
            "Lean mined-work admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.mined_work_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_mined_work_admission_case(case);
        }
    }

    fn verify_lean_mined_work_admission_case(case: &LeanMinedWorkAdmissionCase) {
        let input = NativeMinedWorkAdmissionInput {
            best_height: case.best_height,
            work_height: case.work_height,
            parent_hash_matches: case.parent_hash_matches,
        };
        let actual_rejection = evaluate_native_mined_work_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native mined-work admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native mined-work admission rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_native_miner_identity_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_NATIVE_MINER_IDENTITY_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_NATIVE_MINER_IDENTITY_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean native miner identity vectors");
        let vectors: LeanNativeMinerIdentityVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean native miner identity vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            vectors.native_miner_identity_cases.len() >= 10,
            "Lean native miner identity cases cover too few policy branches"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.native_miner_identity_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_native_miner_identity_case(case);
        }
    }

    fn verify_lean_native_miner_identity_case(case: &LeanNativeMinerIdentityCase) {
        let input = NativeMinerIdentityAdmissionInput {
            height: case.height,
            public_key_len: case.public_key_len,
            signature_len: case.signature_len,
            public_key_bytes_parse: case.public_key_bytes_parse,
            miner_commitment_matches: case.miner_commitment_matches,
            signature_bytes_parse: case.signature_bytes_parse,
            signature_verifies: case.signature_verifies,
        };
        let actual_rejection = evaluate_native_miner_identity_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native miner identity validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native miner identity rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_work_template_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_WORK_TEMPLATE_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_WORK_TEMPLATE_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean work-template admission vectors");
        let vectors: LeanWorkTemplateAdmissionVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean work-template vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.work_template_admission_cases.is_empty(),
            "Lean work-template admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.work_template_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_work_template_admission_case(case);
        }
    }

    fn verify_lean_work_template_admission_case(case: &LeanWorkTemplateAdmissionCase) {
        let input = NativeWorkTemplateAdmissionInput {
            best_height: case.best_height,
            cumulative_work_advances: case.cumulative_work_advances,
        };
        let actual = evaluate_native_work_template_admission(input);
        let actual_rejection = actual
            .as_ref()
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} native work-template admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual.ok(),
            case.expected_height,
            "{} native work-template height drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native work-template admission rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_recursive_artifact_context_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_RECURSIVE_ARTIFACT_CONTEXT_ADMISSION_VECTORS")
        else {
            eprintln!(
                "HEGEMON_LEAN_RECURSIVE_ARTIFACT_CONTEXT_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean recursive artifact context admission vectors");
        let vectors: LeanRecursiveArtifactContextAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean recursive artifact context vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors
                .recursive_artifact_context_admission_cases
                .is_empty(),
            "Lean recursive artifact context admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.recursive_artifact_context_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_recursive_artifact_context_admission_case(case);
        }
    }

    fn verify_lean_recursive_artifact_context_admission_case(
        case: &LeanRecursiveArtifactContextAdmissionCase,
    ) {
        let input = NativeRecursiveArtifactContextAdmissionInput {
            best_height: case.best_height,
        };
        let actual = evaluate_native_recursive_artifact_context_admission(input);
        let actual_rejection = actual
            .as_ref()
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} native recursive artifact context admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual.ok(),
            case.expected_height,
            "{} native recursive artifact context height drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native recursive artifact context rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_action_request_projection_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_REQUEST_PROJECTION_ADMISSION_VECTORS")
        else {
            eprintln!(
                "HEGEMON_LEAN_ACTION_REQUEST_PROJECTION_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean action request projection admission vectors");
        let vectors: LeanActionRequestProjectionAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean action request projection admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.action_request_projection_admission_cases.is_empty(),
            "Lean action request projection admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.action_request_projection_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_action_request_projection_admission_case(case);
        }
    }

    fn verify_lean_action_request_projection_admission_case(
        case: &LeanActionRequestProjectionAdmissionCase,
    ) {
        let input = NativeActionRequestProjectionAdmissionInput {
            json_decode_accepts: case.json_decode_accepts,
            kernel_envelope_fields_absent: case.kernel_envelope_fields_absent,
            route_supported: case.route_supported,
            nullifier_scope_valid: case.nullifier_scope_valid,
            nullifier_count_within_limit: case.nullifier_count_within_limit,
            nullifier_hex_valid: case.nullifier_hex_valid,
            public_args_encoded_within_limit: case.public_args_encoded_within_limit,
            public_args_base64_decodes: case.public_args_base64_decodes,
            public_args_decoded_within_limit: case.public_args_decoded_within_limit,
            route_payload_decodes_exactly: case.route_payload_decodes_exactly,
        };
        let model = evaluate_native_action_request_projection_admission(input);
        let model_rejection = model
            .as_ref()
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            model.is_ok(),
            case.expected_valid,
            "{} Lean action request projection predicate fields disagree with expected validity",
            case.name
        );
        assert_eq!(
            model_rejection, case.expected_rejection,
            "{} Lean action request projection rejection drifted from Rust model",
            case.name
        );

        let request = action_request_projection_fixture(&case.fixture);
        let actual = decode_submit_action_rpc_request(request)
            .map_err(|_| NativeActionRequestProjectionAdmissionRejection::JsonDecodeRejected)
            .and_then(|request| evaluate_native_action_request_projection(&request).map(|_| ()));
        let actual_rejection = actual
            .as_ref()
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} native action request projection validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native action request projection rejection drifted from Lean spec",
            case.name
        );
    }

    fn action_request_projection_fixture(fixture: &str) -> Value {
        use base64::Engine;

        let outbound = OutboundBridgeArgsV1 {
            destination_chain_id: [7u8; 32],
            app_family_id: 9,
            payload: b"lean action projection".to_vec(),
        };
        let mut valid_payload = outbound.encode();
        let mut request = json!({
            "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            "family_id": FAMILY_BRIDGE,
            "action_id": ACTION_BRIDGE_OUTBOUND,
            "new_nullifiers": [],
            "public_args": base64::engine::general_purpose::STANDARD.encode(&valid_payload),
        });

        match fixture {
            "valid_empty_native_request" => request,
            "valid_empty_wallet_envelope_fields" => {
                let object = request.as_object_mut().expect("request object");
                object.insert("object_refs".to_owned(), json!([]));
                object.insert("authorization_proof".to_owned(), Value::Null);
                object.insert("authorization_signatures".to_owned(), json!([]));
                object.insert("aux_data".to_owned(), Value::Null);
                request
            }
            "unknown_field" => {
                request
                    .as_object_mut()
                    .expect("request object")
                    .insert("statement_hash".to_owned(), json!("00"));
                request
            }
            "object_ref_present" => {
                request.as_object_mut().expect("request object").insert(
                    "object_refs".to_owned(),
                    json!([{
                        "family_id": FAMILY_SHIELDED_POOL,
                        "object_id": "00",
                        "expected_root": "00",
                    }]),
                );
                request
            }
            "authorization_proof_present" => {
                request
                    .as_object_mut()
                    .expect("request object")
                    .insert("authorization_proof".to_owned(), json!("AA=="));
                request
            }
            "authorization_signature_present" => {
                request.as_object_mut().expect("request object").insert(
                    "authorization_signatures".to_owned(),
                    json!([{
                        "key_id": "00",
                        "signature_scheme": 1,
                        "signature_bytes": "AA==",
                    }]),
                );
                request
            }
            "aux_data_present" => {
                request
                    .as_object_mut()
                    .expect("request object")
                    .insert("aux_data".to_owned(), json!("AA=="));
                request
            }
            "unsupported_route" => {
                request
                    .as_object_mut()
                    .expect("request object")
                    .insert("action_id".to_owned(), json!(u16::MAX));
                request
            }
            "non_transfer_nullifiers" => {
                request
                    .as_object_mut()
                    .expect("request object")
                    .insert("new_nullifiers".to_owned(), json!([hex::encode([0u8; 48])]));
                request
            }
            "too_many_nullifiers" => {
                let nullifiers =
                    vec![hex::encode([0u8; 48]); transaction_core::constants::MAX_INPUTS + 1];
                let object = request.as_object_mut().expect("request object");
                object.insert("family_id".to_owned(), json!(FAMILY_SHIELDED_POOL));
                object.insert(
                    "action_id".to_owned(),
                    json!(ACTION_SHIELDED_TRANSFER_INLINE),
                );
                object.insert("new_nullifiers".to_owned(), json!(nullifiers));
                request
            }
            "invalid_nullifier_hex" => {
                let object = request.as_object_mut().expect("request object");
                object.insert("family_id".to_owned(), json!(FAMILY_SHIELDED_POOL));
                object.insert(
                    "action_id".to_owned(),
                    json!(ACTION_SHIELDED_TRANSFER_INLINE),
                );
                object.insert("new_nullifiers".to_owned(), json!(["not-hex"]));
                request
            }
            "encoded_public_args_too_large" => {
                request.as_object_mut().expect("request object").insert(
                    "public_args".to_owned(),
                    json!("A".repeat(encoded_len_limit(MAX_NATIVE_RPC_ACTION_BYTES) + 1)),
                );
                request
            }
            "base64_public_args_rejected" => {
                request
                    .as_object_mut()
                    .expect("request object")
                    .insert("public_args".to_owned(), json!("not base64!"));
                request
            }
            "decoded_public_args_too_large" => {
                request.as_object_mut().expect("request object").insert(
                    "public_args".to_owned(),
                    json!(base64::engine::general_purpose::STANDARD.encode(vec![
                        0u8;
                        MAX_NATIVE_RPC_ACTION_BYTES
                            + 1
                    ])),
                );
                request
            }
            "route_payload_decode_rejected" => {
                valid_payload.push(0xaa);
                request.as_object_mut().expect("request object").insert(
                    "public_args".to_owned(),
                    json!(base64::engine::general_purpose::STANDARD.encode(valid_payload)),
                );
                request
            }
            other => panic!("unknown Lean action request projection fixture {other}"),
        }
    }

    #[test]
    fn lean_generated_codec_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_CODEC_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_CODEC_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw =
            std::fs::read_to_string(&path).expect("read generated Lean codec admission vectors");
        let vectors: LeanCodecAdmissionVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean codec admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.sync_codec_cases.is_empty()
                && !vectors.exact_decode_cases.is_empty()
                && !vectors.block_action_decode_cases.is_empty(),
            "Lean codec admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.sync_codec_cases {
            assert!(names.insert(format!("sync:{}", case.name)));
            verify_lean_sync_codec_case(case);
        }
        for case in &vectors.exact_decode_cases {
            assert!(names.insert(format!("exact:{}", case.name)));
            verify_lean_exact_decode_case(case);
        }
        for case in &vectors.block_action_decode_cases {
            assert!(names.insert(format!("block-action:{}", case.name)));
            verify_lean_block_action_decode_case(case);
        }
    }

    fn verify_lean_sync_codec_case(case: &LeanSyncCodecCase) {
        assert_eq!(
            case.bounded_wire_decode_accepts && case.consumed_all_bytes,
            case.expected_valid,
            "{} Lean sync codec predicate fields disagree with expected validity",
            case.name
        );
        if case.legacy_bincode_payload {
            assert_eq!(
                case.fixture, "legacy_bincode_request",
                "{} legacy bincode flag must only be used by the legacy fixture",
                case.name
            );
        }

        let message = NativeSyncMessage::Request {
            from_height: 1,
            to_height: 2,
        };
        let payload = match case.fixture.as_str() {
            "valid_request" => encode_sync_message(&message).expect("encode native sync message"),
            "legacy_bincode_request" => {
                bincode::serialize(&message).expect("legacy bincode sync message")
            }
            "valid_request_trailing" => {
                let mut encoded =
                    encode_sync_message(&message).expect("encode native sync message");
                encoded.push(0);
                encoded
            }
            other => panic!("unknown Lean sync codec fixture {other}"),
        };
        let actual = decode_sync_message(&payload);
        let actual_rejection = if actual.is_ok() {
            None
        } else if case.fixture == "valid_request_trailing" {
            Some("trailing_bytes".to_owned())
        } else {
            Some("wire_decode_rejected".to_owned())
        };
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} native sync codec validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native sync codec rejection drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_exact_decode_case(case: &LeanExactDecodeCase) {
        assert_eq!(
            case.parser_accepts && case.consumed_all_bytes && case.canonical_reencode_matches,
            case.expected_valid,
            "{} Lean exact-decode predicate fields disagree with expected validity",
            case.name
        );
        let actual = match (case.codec.as_str(), case.fixture.as_str()) {
            ("scale_pending_action", "valid_pending_action") => {
                let action = test_outbound_bridge_action(b"lean codec admission");
                decode_scale_exact::<PendingAction>(&action.encode(), "Lean pending action")
                    .map(|_| ())
            }
            ("scale_pending_action", "trailing_pending_action") => {
                let action = test_outbound_bridge_action(b"lean codec admission");
                let mut encoded = action.encode();
                encoded.push(0xaa);
                decode_scale_exact::<PendingAction>(&encoded, "Lean pending action").map(|_| ())
            }
            ("scale_normalizing_fixture", "noncanonical_byte") => {
                decode_scale_exact::<NormalizedScaleByte>(&[1], "Lean normalized SCALE byte")
                    .map(|_| ())
            }
            ("bincode_native_meta", "valid_genesis_meta") => {
                let meta = genesis_meta(0x207f_ffff).expect("genesis");
                let encoded = bincode::serialize(&meta).expect("serialize native meta");
                bincode_deserialize_exact::<NativeBlockMeta>(&encoded, "Lean native metadata")
                    .map(|_| ())
            }
            ("bincode_native_meta", "trailing_genesis_meta") => {
                let meta = genesis_meta(0x207f_ffff).expect("genesis");
                let mut encoded = bincode::serialize(&meta).expect("serialize native meta");
                encoded.push(0xbb);
                bincode_deserialize_exact::<NativeBlockMeta>(&encoded, "Lean native metadata")
                    .map(|_| ())
            }
            ("bincode_normalizing_fixture", "noncanonical_byte") => {
                let encoded = bincode::serialize(&1u8).expect("serialize noncanonical byte");
                bincode_deserialize_exact::<NormalizedBincodeByte>(
                    &encoded,
                    "Lean normalized bincode byte",
                )
                .map(|_| ())
            }
            (codec, fixture) => {
                panic!("unknown Lean exact-decode case codec={codec} fixture={fixture}")
            }
        };
        let actual_rejection = actual.as_ref().err().map(|err| {
            let message = err.to_string();
            if message.contains("trailing bytes") {
                "trailing_bytes".to_owned()
            } else if message.contains("not canonical") {
                "non_canonical_encoding".to_owned()
            } else {
                "parser_rejected".to_owned()
            }
        });
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} native exact-decode validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native exact-decode rejection drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_block_action_decode_case(case: &LeanBlockActionDecodeCase) {
        assert_eq!(
            (case.declared_tx_count == case.actual_action_payload_count)
                && case.every_action_decodes_exactly,
            case.expected_valid,
            "{} Lean block-action decode predicate fields disagree with expected validity",
            case.name
        );

        let mut block = genesis_meta(0x207f_ffff).expect("genesis");
        let action = test_outbound_bridge_action(b"lean codec admission");
        match case.fixture.as_str() {
            "valid_one_action" => {
                block.tx_count =
                    u32::try_from(case.declared_tx_count).expect("test tx_count must fit u32");
                block.action_bytes = vec![action.encode()];
            }
            "count_mismatch" => {
                block.tx_count =
                    u32::try_from(case.declared_tx_count).expect("test tx_count must fit u32");
                block.action_bytes = Vec::new();
            }
            "trailing_action_payload" => {
                block.tx_count =
                    u32::try_from(case.declared_tx_count).expect("test tx_count must fit u32");
                let mut encoded = action.encode();
                encoded.push(0xcc);
                block.action_bytes = vec![encoded];
            }
            other => panic!("unknown Lean block-action decode fixture {other}"),
        }
        assert_eq!(
            block.action_bytes.len(),
            case.actual_action_payload_count,
            "{} fixture action payload count drifted from Lean vector",
            case.name
        );

        let actual = decode_block_actions(&block);
        let actual_rejection = actual.as_ref().err().map(|err| {
            let message = err.to_string();
            if message.contains("count mismatch") {
                "action_count_mismatch".to_owned()
            } else {
                "action_decode_not_exact".to_owned()
            }
        });
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} native block-action decode validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native block-action decode rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_storage_durability_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_STORAGE_DURABILITY_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_STORAGE_DURABILITY_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean storage durability admission vectors");
        let vectors: LeanStorageDurabilityAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean storage durability admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.storage_durability_admission_cases.is_empty(),
            "Lean storage durability admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.storage_durability_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_storage_durability_admission_case(case);
        }
    }

    fn verify_lean_storage_durability_admission_case(case: &LeanStorageDurabilityAdmissionCase) {
        assert!(
            matches!(
                case.operation.as_str(),
                "mined_block_commit"
                    | "canonical_reorg_commit"
                    | "canonical_index_repair"
                    | "noncanonical_block_record"
                    | "pending_action_stage"
                    | "ciphertext_sidecar_stage"
                    | "proof_sidecar_stage"
                    | "genesis_bootstrap"
                    | "genesis_marker_repair"
                    | "startup_staged_ciphertext_repair"
                    | "startup_staged_proof_repair"
                    | "startup_pending_action_repair"
            ),
            "unknown Lean storage durability operation {}",
            case.operation
        );
        assert_eq!(
            case.transaction_accepted && case.durability_flushed,
            case.expected_valid,
            "{} Lean storage durability predicate fields disagree with expected validity",
            case.name
        );
        let actual =
            evaluate_native_storage_durability_admission(NativeStorageDurabilityAdmissionInput {
                transaction_accepted: case.transaction_accepted,
                durability_flushed: case.durability_flushed,
            });
        let actual_rejection = actual
            .as_ref()
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} native storage durability validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native storage durability rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_atomic_commit_manifest_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_ATOMIC_COMMIT_MANIFEST_ADMISSION_VECTORS")
        else {
            eprintln!(
                "HEGEMON_LEAN_ATOMIC_COMMIT_MANIFEST_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean atomic commit manifest admission vectors");
        let vectors: LeanAtomicCommitManifestAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean atomic commit manifest admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.atomic_commit_manifest_admission_cases.is_empty(),
            "Lean atomic commit manifest admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.atomic_commit_manifest_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_atomic_commit_manifest_admission_case(case);
        }
    }

    fn native_atomic_commit_kind_from_label(label: &str) -> NativeAtomicCommitKind {
        match label {
            "mined_block_commit" => NativeAtomicCommitKind::MinedBlockCommit,
            "canonical_reorg_commit" => NativeAtomicCommitKind::CanonicalReorgCommit,
            "canonical_index_repair" => NativeAtomicCommitKind::CanonicalIndexRepair,
            "noncanonical_block_record" => NativeAtomicCommitKind::NoncanonicalBlockRecord,
            other => panic!("unknown Lean atomic commit kind {other}"),
        }
    }

    fn verify_lean_atomic_commit_manifest_admission_case(
        case: &LeanAtomicCommitManifestAdmissionCase,
    ) {
        let input = NativeAtomicCommitManifestAdmissionInput {
            kind: native_atomic_commit_kind_from_label(&case.kind),
            action_count: case.action_count,
            planned_action_count: case.planned_action_count,
            chain_block_count: case.chain_block_count,
            height_entry_count: case.height_entry_count,
            pending_entry_count: case.pending_entry_count,
            source_commitment_count: case.source_commitment_count,
            source_nullifier_count: case.source_nullifier_count,
            source_bridge_replay_count: case.source_bridge_replay_count,
            source_ciphertext_index_count: case.source_ciphertext_index_count,
            source_ciphertext_archive_count: case.source_ciphertext_archive_count,
            source_staged_ciphertext_removal_count: case.source_staged_ciphertext_removal_count,
            block_record_writes: case.block_record_writes,
            height_index_writes: case.height_index_writes,
            best_pointer_writes: case.best_pointer_writes,
            canonical_index_cleared: case.canonical_index_cleared,
            pending_tree_cleared: case.pending_tree_cleared,
            pending_action_removals: case.pending_action_removals,
            pending_action_writes: case.pending_action_writes,
            commitment_writes: case.commitment_writes,
            nullifier_writes: case.nullifier_writes,
            bridge_replay_writes: case.bridge_replay_writes,
            ciphertext_index_writes: case.ciphertext_index_writes,
            ciphertext_archive_writes: case.ciphertext_archive_writes,
            staged_ciphertext_removals: case.staged_ciphertext_removals,
        };
        let actual = evaluate_native_atomic_commit_manifest_admission(input);
        let actual_rejection = actual
            .as_ref()
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} native atomic commit manifest validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native atomic commit manifest rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_action_scope_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_SCOPE_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_ACTION_SCOPE_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean action-scope admission vectors");
        let vectors: LeanActionScopeAdmissionVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean action-scope vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.action_scope_admission_cases.is_empty(),
            "Lean action-scope admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.action_scope_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_action_scope_admission_case(case);
        }
    }

    fn verify_lean_action_scope_admission_case(case: &LeanActionScopeAdmissionCase) {
        let input = NativeActionScopeAdmissionInput {
            candidate_artifact_payload_scoped: case.candidate_artifact_payload_scoped,
            bridge_route: case.bridge_route,
            bridge_scope_valid: case.bridge_scope_valid,
            candidate_artifact_route: case.candidate_artifact_route,
            candidate_scope_valid: case.candidate_scope_valid,
            candidate_payload_present: case.candidate_payload_present,
            coinbase_route: case.coinbase_route,
            coinbase_scope_valid: case.coinbase_scope_valid,
            transfer_route: case.transfer_route,
            transfer_scope_valid: case.transfer_scope_valid,
        };
        let actual = evaluate_native_action_scope_admission(input);
        let actual_route = actual.as_ref().ok().map(|route| route.label().to_owned());
        let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_route.is_some(),
            case.expected_valid,
            "{} native action-scope admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_route, case.expected_route,
            "{} native action-scope admission route drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native action-scope admission rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_bridge_action_payload_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_ACTION_PAYLOAD_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_BRIDGE_ACTION_PAYLOAD_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean bridge action payload admission vectors");
        let vectors: LeanBridgeActionPayloadAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean bridge action payload admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.bridge_action_payload_admission_cases.is_empty(),
            "Lean bridge action payload admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.bridge_action_payload_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_bridge_action_payload_admission_case(case);
        }
    }

    fn verify_lean_bridge_action_payload_admission_case(
        case: &LeanBridgeActionPayloadAdmissionCase,
    ) {
        let input = NativeBridgeActionPayloadAdmissionInput {
            bridge_route: case.bridge_route,
            state_deltas_absent: case.state_deltas_absent,
            action_kind: lean_bridge_action_payload_kind(&case.action_kind, &case.name),
            outbound_payload_nonempty: case.outbound_payload_nonempty,
            inbound_proof_receipt_nonempty: case.inbound_proof_receipt_nonempty,
            inbound_replay_key_matches: case.inbound_replay_key_matches,
            inbound_destination_matches: case.inbound_destination_matches,
            inbound_payload_hash_matches: case.inbound_payload_hash_matches,
        };
        let actual_rejection = evaluate_native_bridge_action_payload_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native bridge action payload admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native bridge action payload admission rejection drifted from Lean spec",
            case.name
        );
    }

    fn lean_bridge_action_payload_kind(
        action_kind: &str,
        case_name: &str,
    ) -> NativeBridgeActionPayloadKind {
        match action_kind {
            "outbound" => NativeBridgeActionPayloadKind::Outbound,
            "inbound" => NativeBridgeActionPayloadKind::Inbound,
            "register" => NativeBridgeActionPayloadKind::Register,
            "unsupported" => NativeBridgeActionPayloadKind::Unsupported,
            other => panic!("{case_name} has unknown bridge action kind {other}"),
        }
    }

    #[test]
    fn lean_generated_risc0_release_verifier_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_RISC0_RELEASE_VERIFIER_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_RISC0_RELEASE_VERIFIER_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean RISC0 release verifier vectors");
        let vectors: LeanRisc0ReleaseVerifierVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean RISC0 verifier vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.risc0_release_verifier_cases.is_empty(),
            "Lean RISC0 release verifier cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.risc0_release_verifier_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_risc0_release_verifier_case(case);
        }
    }

    fn verify_lean_risc0_release_verifier_case(case: &LeanRisc0ReleaseVerifierCase) {
        let input = NativeRisc0ReleaseVerifierInput {
            image_id_matches: case.image_id_matches,
            journal_decodes: case.journal_decodes,
            verifier_enabled: case.verifier_enabled,
        };
        let actual_rejection = evaluate_native_risc0_release_verifier(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native RISC0 release verifier validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native RISC0 release verifier rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_transfer_action_payload_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_TRANSFER_ACTION_PAYLOAD_ADMISSION_VECTORS")
        else {
            eprintln!(
                "HEGEMON_LEAN_TRANSFER_ACTION_PAYLOAD_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean transfer action payload admission vectors");
        let vectors: LeanTransferActionPayloadAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean transfer action payload admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.transfer_action_payload_admission_cases.is_empty(),
            "Lean transfer action payload admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.transfer_action_payload_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_transfer_action_payload_admission_case(case);
        }
    }

    fn verify_lean_transfer_action_payload_admission_case(
        case: &LeanTransferActionPayloadAdmissionCase,
    ) {
        assert_eq!(
            case.max_proof_bytes, NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
            "{} Lean proof cap must match the production native tx-leaf cap",
            case.name
        );
        assert_eq!(
            case.max_ciphertext_bytes, MAX_CIPHERTEXT_BYTES,
            "{} Lean ciphertext cap must match the production native cap",
            case.name
        );
        let input = NativeTransferPayloadAdmissionInput {
            proof_bytes: case.proof_bytes,
            max_proof_bytes: case.max_proof_bytes,
            anchor_matches: case.anchor_matches,
            commitments_match: case.commitments_match,
            inline_ciphertext_bytes: case.inline_ciphertext_bytes,
            max_ciphertext_bytes: case.max_ciphertext_bytes,
            ciphertext_hashes_match: case.ciphertext_hashes_match,
            ciphertext_sizes_match: case.ciphertext_sizes_match,
            binding_hash_matches: case.binding_hash_matches,
            proof_binding_hash_matches_key: case.proof_binding_hash_matches_key,
            fee_matches: case.fee_matches,
        };
        let actual_rejection = evaluate_native_transfer_payload_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native transfer payload admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native transfer payload admission rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_transfer_state_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_TRANSFER_STATE_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_TRANSFER_STATE_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean transfer state admission vectors");
        let vectors: LeanTransferStateAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean transfer state admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.transfer_state_admission_cases.is_empty(),
            "Lean transfer state admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.transfer_state_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_transfer_state_admission_case(case);
        }
    }

    fn verify_lean_transfer_state_admission_case(case: &LeanTransferStateAdmissionCase) {
        let input = NativeTransferStateAdmissionInput {
            anchor_known: case.anchor_known,
            nullifier_state: lean_transfer_nullifier_state(&case.nullifier_state, &case.name),
            commitments_nonzero: case.commitments_nonzero,
            sidecar_route: case.sidecar_route,
            sidecar_ciphertexts_available: case.sidecar_ciphertexts_available,
            sidecar_ciphertext_sizes_present: case.sidecar_ciphertext_sizes_present,
            sidecar_ciphertext_sizes_match: case.sidecar_ciphertext_sizes_match,
        };
        let actual_rejection = evaluate_native_transfer_state_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native transfer state admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native transfer state admission rejection drifted from Lean spec",
            case.name
        );
    }

    fn lean_transfer_nullifier_state(
        state: &str,
        case_name: &str,
    ) -> NativeTransferNullifierAdmissionState {
        match state {
            "valid" => NativeTransferNullifierAdmissionState::Valid,
            "zero" => NativeTransferNullifierAdmissionState::Zero,
            "already_spent" => NativeTransferNullifierAdmissionState::AlreadySpent,
            "duplicate" => NativeTransferNullifierAdmissionState::Duplicate,
            "already_pending" => NativeTransferNullifierAdmissionState::AlreadyPending,
            other => panic!("{case_name} has unknown transfer nullifier state {other}"),
        }
    }

    #[test]
    fn lean_generated_action_state_effect_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_STATE_EFFECT_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_ACTION_STATE_EFFECT_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean action state effect vectors");
        let vectors: LeanActionStateEffectVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean action state effect vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.action_state_effect_cases.is_empty(),
            "Lean action state effect cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.action_state_effect_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_action_state_effect_case(case);
        }
    }

    fn verify_lean_action_state_effect_case(case: &LeanActionStateEffectCase) {
        let (spent_nullifiers, nullifiers) = synthetic_action_effect_nullifiers(
            &case.nullifier_state,
            case.nullifier_count,
            &case.name,
        );
        let (consumed_replays, replay_key) =
            synthetic_action_effect_replay(&case.bridge_replay_state, &case.name);
        let mut nullifier_state = NullifierState::new(spent_nullifiers, BTreeSet::new());
        let mut bridge_replay_state = InboundReplayState::new(consumed_replays, BTreeSet::new());

        let actual = evaluate_native_action_state_effect(
            case.leaf_start,
            case.commitment_count,
            case.ciphertext_count,
            &nullifiers,
            replay_key,
            &mut nullifier_state,
            &mut bridge_replay_state,
        );
        match actual {
            Ok(effect) => {
                assert!(
                    case.expected_valid,
                    "{} action state effect unexpectedly accepted",
                    case.name
                );
                assert_eq!(
                    Some(effect.next_leaf_count),
                    case.expected_next_leaf_count,
                    "{} next leaf count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(effect.imported_nullifier_count),
                    case.expected_imported_nullifier_count,
                    "{} imported nullifier count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(effect.imported_bridge_replay),
                    case.expected_imported_bridge_replay,
                    "{} imported bridge replay flag drifted from Lean spec",
                    case.name
                );
            }
            Err(rejection) => {
                assert!(
                    !case.expected_valid,
                    "{} action state effect unexpectedly rejected: {}",
                    case.name,
                    rejection.label()
                );
                assert_eq!(
                    Some(rejection.label().to_owned()),
                    case.expected_rejection,
                    "{} rejection drifted from Lean spec",
                    case.name
                );
            }
        }
    }

    #[test]
    fn lean_generated_action_stream_effect_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_STREAM_EFFECT_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_ACTION_STREAM_EFFECT_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean action stream effect vectors");
        let vectors: LeanActionStreamEffectVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean action stream effect vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.action_stream_effect_cases.is_empty(),
            "Lean action stream effect cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.action_stream_effect_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_action_stream_effect_case(case);
        }
    }

    fn verify_lean_action_stream_effect_case(case: &LeanActionStreamEffectCase) {
        let spent_nullifiers = case
            .spent_nullifiers
            .iter()
            .map(|key| synthetic_stream_nullifier(*key, &case.name))
            .collect::<BTreeSet<_>>();
        let consumed_bridge_replays = case
            .consumed_bridge_replays
            .iter()
            .map(|key| synthetic_stream_replay_key(*key, &case.name))
            .collect::<BTreeSet<_>>();
        let action_nullifiers = case
            .actions
            .iter()
            .map(|action| {
                action
                    .nullifiers
                    .iter()
                    .map(|key| synthetic_stream_nullifier(*key, &case.name))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let replay_keys = case
            .actions
            .iter()
            .map(|action| {
                action
                    .bridge_replay_key
                    .map(|key| synthetic_stream_replay_key(key, &case.name))
            })
            .collect::<Vec<_>>();
        let mut nullifier_state = NullifierState::new(spent_nullifiers, BTreeSet::new());
        let mut bridge_replay_state =
            InboundReplayState::new(consumed_bridge_replays, BTreeSet::new());

        let actual = evaluate_native_action_stream_effect(
            case.leaf_start,
            case.actions
                .iter()
                .zip(action_nullifiers.iter())
                .zip(replay_keys.iter())
                .map(
                    |((action, nullifiers), replay_key)| NativeActionStreamStep {
                        commitment_count: action.commitment_count,
                        ciphertext_count: action.ciphertext_count,
                        nullifiers: nullifiers.as_slice(),
                        replay_key: *replay_key,
                    },
                ),
            &mut nullifier_state,
            &mut bridge_replay_state,
        );
        match actual {
            Ok(effect) => {
                assert!(
                    case.expected_valid,
                    "{} action stream effect unexpectedly accepted",
                    case.name
                );
                assert_eq!(
                    Some(effect.next_leaf_count),
                    case.expected_next_leaf_count,
                    "{} stream next leaf count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(effect.imported_nullifier_count),
                    case.expected_imported_nullifier_count,
                    "{} stream imported nullifier count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(effect.imported_bridge_replay_count),
                    case.expected_imported_bridge_replay_count,
                    "{} stream imported bridge replay count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(effect.planned_starts),
                    case.expected_planned_starts,
                    "{} stream planned starts drifted from Lean spec",
                    case.name
                );
            }
            Err(rejection) => {
                assert!(
                    !case.expected_valid,
                    "{} action stream effect unexpectedly rejected: {}",
                    case.name,
                    rejection.label()
                );
                assert_eq!(
                    Some(rejection.label().to_owned()),
                    case.expected_rejection,
                    "{} stream rejection drifted from Lean spec",
                    case.name
                );
            }
        }
    }

    #[test]
    fn lean_generated_action_plan_application_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_PLAN_APPLICATION_ADMISSION_VECTORS")
        else {
            eprintln!(
                "HEGEMON_LEAN_ACTION_PLAN_APPLICATION_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean action plan application admission vectors");
        let vectors: LeanActionPlanApplicationAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean action plan application admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.action_plan_application_admission_cases.is_empty(),
            "Lean action plan application admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.action_plan_application_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_action_plan_application_admission_case(case);
        }
    }

    fn verify_lean_action_plan_application_admission_case(
        case: &LeanActionPlanApplicationAdmissionCase,
    ) {
        let actual = evaluate_native_action_plan_application_admission(
            case.leaf_start,
            &case.action_commitment_counts,
            &case.planned_starts,
        );
        match actual {
            Ok(summary) => {
                assert!(
                    case.expected_valid,
                    "{} action plan application unexpectedly accepted",
                    case.name
                );
                assert_eq!(
                    Some(summary.next_leaf_count),
                    case.expected_next_leaf_count,
                    "{} plan application next leaf count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(summary.applied_action_count),
                    case.expected_applied_action_count,
                    "{} plan application action count drifted from Lean spec",
                    case.name
                );
            }
            Err(rejection) => {
                assert!(
                    !case.expected_valid,
                    "{} action plan application unexpectedly rejected: {}",
                    case.name,
                    rejection.label()
                );
                assert_eq!(
                    Some(rejection.label().to_owned()),
                    case.expected_rejection,
                    "{} plan application rejection drifted from Lean spec",
                    case.name
                );
            }
        }
    }

    #[test]
    fn lean_generated_action_wire_replay_projection_admission_vectors_match_production() {
        let Ok(path) =
            std::env::var("HEGEMON_LEAN_ACTION_WIRE_REPLAY_PROJECTION_ADMISSION_VECTORS")
        else {
            eprintln!(
                "HEGEMON_LEAN_ACTION_WIRE_REPLAY_PROJECTION_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean action wire replay projection admission vectors");
        let vectors: LeanActionWireReplayProjectionAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean action wire replay projection admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors
                .action_wire_replay_projection_admission_cases
                .is_empty(),
            "Lean action wire replay projection cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.action_wire_replay_projection_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_action_wire_replay_projection_admission_case(case);
        }
    }

    fn verify_lean_action_wire_replay_projection_admission_case(
        case: &LeanActionWireReplayProjectionAdmissionCase,
    ) {
        let steps = case
            .actions
            .iter()
            .map(|action| NativeActionWireReplayProjectionStep {
                ciphertext_hash_count: action.ciphertext_hash_count,
                ciphertext_size_count: action.ciphertext_size_count,
                planned_ciphertext_count: action.planned_ciphertext_count,
                ciphertext_hashes_match: action.ciphertext_hashes_match,
                ciphertext_sizes_match: action.ciphertext_sizes_match,
                planned_replay_present: action.planned_replay_present,
                replay_key_matches: action.replay_key_matches,
            })
            .collect::<Vec<_>>();
        let actual = evaluate_native_action_wire_replay_projection_admission(
            case.action_count,
            case.planned_count,
            &steps,
        );
        match actual {
            Ok(summary) => {
                assert!(
                    case.expected_valid,
                    "{} action wire replay projection unexpectedly accepted",
                    case.name
                );
                assert_eq!(
                    Some(summary.projected_action_count),
                    case.expected_projected_action_count,
                    "{} wire replay projected action count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(summary.projected_ciphertext_row_count),
                    case.expected_projected_ciphertext_row_count,
                    "{} wire replay projected ciphertext rows drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(summary.projected_bridge_replay_row_count),
                    case.expected_projected_bridge_replay_row_count,
                    "{} wire replay projected bridge replay rows drifted from Lean spec",
                    case.name
                );
            }
            Err(rejection) => {
                assert!(
                    !case.expected_valid,
                    "{} action wire replay projection unexpectedly rejected: {}",
                    case.name,
                    rejection.label()
                );
                assert_eq!(
                    Some(rejection.label().to_owned()),
                    case.expected_rejection,
                    "{} wire replay projection rejection drifted from Lean spec",
                    case.name
                );
            }
        }
    }

    #[test]
    fn lean_generated_block_action_validation_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BLOCK_ACTION_VALIDATION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_BLOCK_ACTION_VALIDATION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean block action validation vectors");
        let vectors: LeanBlockActionValidationVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean block action validation vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.block_action_validation_cases.is_empty(),
            "Lean block action validation cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.block_action_validation_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_block_action_validation_case(case);
        }
    }

    fn verify_lean_block_action_validation_case(case: &LeanBlockActionValidationCase) {
        let consumed_bridge_replays = case
            .consumed_bridge_replays
            .iter()
            .map(|key| synthetic_stream_replay_key(*key, &case.name))
            .collect::<BTreeSet<_>>();
        let mut actual_rejection = None;
        let mut validation_state = match evaluate_native_block_action_validation_start(
            case.action_count_matches,
            case.action_hashes_match,
            case.action_hashes_unique,
            consumed_bridge_replays,
        ) {
            Ok(state) => Some(state),
            Err(rejection) => {
                assert!(
                    !case.expected_valid,
                    "{} block action validation unexpectedly rejected at hash gate: {}",
                    case.name,
                    rejection.label()
                );
                actual_rejection = Some(rejection);
                None
            }
        };
        if let Some(ref mut validation_state) = validation_state {
            for action in &case.actions {
                let step = NativeBlockActionValidationStep {
                    scope_input: lean_block_action_validation_scope(&action.scope),
                    payload_valid: action.payload_valid,
                    transfer_key: synthetic_transfer_order_key(action.transfer_key),
                    transfer_state_input: lean_block_action_validation_transfer_state(
                        &action.transfer_state,
                    ),
                    bridge_replay_key: action
                        .bridge_replay_key
                        .map(|key| synthetic_stream_replay_key(key, &case.name)),
                };
                if let Err(rejection) =
                    evaluate_native_block_action_validation_step(validation_state, step)
                {
                    actual_rejection = Some(rejection);
                    break;
                }
            }
        }

        match actual_rejection {
            Some(rejection) => {
                assert!(
                    !case.expected_valid,
                    "{} block action validation unexpectedly rejected: {}",
                    case.name,
                    rejection.label()
                );
                assert_eq!(
                    Some(rejection.label().to_owned()),
                    case.expected_rejection,
                    "{} block action validation rejection drifted from Lean spec",
                    case.name
                );
            }
            None => {
                let summary = native_block_action_validation_summary(
                    validation_state.expect("accepted block action validation state"),
                );
                assert!(
                    case.expected_valid,
                    "{} block action validation unexpectedly accepted",
                    case.name
                );
                assert_eq!(
                    Some(summary.validated_action_count),
                    case.expected_validated_action_count,
                    "{} validated action count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(summary.imported_bridge_replay_count),
                    case.expected_imported_bridge_replay_count,
                    "{} imported bridge replay count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    summary.last_transfer_key.map(observed_transfer_order_key),
                    case.expected_last_transfer_key,
                    "{} last transfer key drifted from Lean spec",
                    case.name
                );
            }
        }
    }

    fn lean_block_action_validation_scope(
        scope: &LeanBlockActionValidationScopeCase,
    ) -> NativeActionScopeAdmissionInput {
        NativeActionScopeAdmissionInput {
            candidate_artifact_payload_scoped: scope.candidate_artifact_payload_scoped,
            bridge_route: scope.bridge_route,
            bridge_scope_valid: scope.bridge_scope_valid,
            candidate_artifact_route: scope.candidate_artifact_route,
            candidate_scope_valid: scope.candidate_scope_valid,
            candidate_payload_present: scope.candidate_payload_present,
            coinbase_route: scope.coinbase_route,
            coinbase_scope_valid: scope.coinbase_scope_valid,
            transfer_route: scope.transfer_route,
            transfer_scope_valid: scope.transfer_scope_valid,
        }
    }

    fn lean_block_action_validation_transfer_state(
        state: &LeanBlockActionValidationTransferStateCase,
    ) -> NativeTransferStateAdmissionInput {
        NativeTransferStateAdmissionInput {
            anchor_known: state.anchor_known,
            nullifier_state: match state.nullifier_state.as_str() {
                "valid" => NativeTransferNullifierAdmissionState::Valid,
                "zero" => NativeTransferNullifierAdmissionState::Zero,
                "already_spent" => NativeTransferNullifierAdmissionState::AlreadySpent,
                "duplicate" => NativeTransferNullifierAdmissionState::Duplicate,
                "already_pending" => NativeTransferNullifierAdmissionState::AlreadyPending,
                other => panic!("unknown block action transfer nullifier state {other}"),
            },
            commitments_nonzero: state.commitments_nonzero,
            sidecar_route: state.sidecar_route,
            sidecar_ciphertexts_available: state.sidecar_ciphertexts_available,
            sidecar_ciphertext_sizes_present: state.sidecar_ciphertext_sizes_present,
            sidecar_ciphertext_sizes_match: state.sidecar_ciphertext_sizes_match,
        }
    }

    fn synthetic_transfer_order_key(key: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&key.to_be_bytes());
        bytes
    }

    fn observed_transfer_order_key(key: [u8; 32]) -> u64 {
        u64::from_be_bytes(
            key[24..32]
                .try_into()
                .expect("synthetic transfer order key has 8 trailing bytes"),
        )
    }

    fn synthetic_action_effect_nullifiers(
        state: &str,
        count: usize,
        case_name: &str,
    ) -> (BTreeSet<[u8; 48]>, Vec<[u8; 48]>) {
        match state {
            "valid" => (
                BTreeSet::new(),
                (0..count)
                    .map(|idx| synthetic_hash48(0x20, idx, case_name))
                    .collect(),
            ),
            "zero" => (BTreeSet::new(), vec![[0u8; 48]; count.max(1)]),
            "duplicate" => {
                let duplicate = synthetic_hash48(0x40, 0, case_name);
                let mut spent = BTreeSet::new();
                spent.insert(duplicate);
                (spent, vec![duplicate; count.max(1)])
            }
            other => panic!("{case_name} has unknown action-effect nullifier state {other}"),
        }
    }

    fn synthetic_action_effect_replay(
        state: &str,
        case_name: &str,
    ) -> (BTreeSet<[u8; 48]>, Option<[u8; 48]>) {
        match state {
            "absent" => (BTreeSet::new(), None),
            "valid" => (BTreeSet::new(), Some(synthetic_hash48(0x60, 0, case_name))),
            "already_consumed" => {
                let replay_key = synthetic_hash48(0x70, 0, case_name);
                let mut consumed = BTreeSet::new();
                consumed.insert(replay_key);
                (consumed, Some(replay_key))
            }
            other => panic!("{case_name} has unknown bridge replay state {other}"),
        }
    }

    fn synthetic_stream_nullifier(key: u64, case_name: &str) -> [u8; 48] {
        if key == 0 {
            return [0u8; 48];
        }
        synthetic_stream_key(0x81, key, case_name)
    }

    fn synthetic_stream_replay_key(key: u64, case_name: &str) -> [u8; 48] {
        synthetic_stream_key(0x82, key, case_name)
    }

    fn synthetic_stream_key(domain: u8, key: u64, case_name: &str) -> [u8; 48] {
        let mut hash = [0u8; 48];
        hash[0] = domain;
        hash[1..9].copy_from_slice(&key.to_le_bytes());
        let name_bytes = case_name.as_bytes();
        for (idx, byte) in name_bytes.iter().take(39).enumerate() {
            hash[idx + 9] = *byte;
        }
        hash
    }

    fn synthetic_hash48(domain: u8, index: usize, case_name: &str) -> [u8; 48] {
        let mut hash = [0u8; 48];
        hash[0] = domain;
        hash[1] = u8::try_from(index).unwrap_or(u8::MAX);
        let name_bytes = case_name.as_bytes();
        for (idx, byte) in name_bytes.iter().take(46).enumerate() {
            hash[idx + 2] = *byte;
        }
        hash
    }

    #[test]
    fn lean_generated_candidate_artifact_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_CANDIDATE_ARTIFACT_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_CANDIDATE_ARTIFACT_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean candidate artifact admission vectors");
        let vectors: LeanCandidateArtifactAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean candidate artifact admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.candidate_artifact_admission_cases.is_empty(),
            "Lean candidate artifact admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.candidate_artifact_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_candidate_artifact_admission_case(case);
        }
    }

    fn verify_lean_candidate_artifact_admission_case(case: &LeanCandidateArtifactAdmissionCase) {
        let input = NativeCandidateArtifactAdmissionInput {
            state_deltas_absent: case.state_deltas_absent,
            artifact_present: case.artifact_present,
            schema_matches: case.schema_matches,
            tx_count: case.tx_count,
            max_tx_count: case.max_tx_count,
            da_chunk_count: case.da_chunk_count,
            proof_mode_recursive_block: case.proof_mode_recursive_block,
            proof_kind_recursive_block_v2: case.proof_kind_recursive_block_v2,
            verifier_profile_matches: case.verifier_profile_matches,
            commitment_proof_empty: case.commitment_proof_empty,
            receipt_root_absent: case.receipt_root_absent,
            recursive_payload_present: case.recursive_payload_present,
            recursive_proof_bytes: case.recursive_proof_bytes,
            max_recursive_proof_bytes: case.max_recursive_proof_bytes,
        };
        let actual_rejection = evaluate_native_candidate_artifact_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native candidate-artifact admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native candidate-artifact admission rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_candidate_artifact_coupling_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_CANDIDATE_ARTIFACT_COUPLING_ADMISSION_VECTORS")
        else {
            eprintln!(
                "HEGEMON_LEAN_CANDIDATE_ARTIFACT_COUPLING_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean candidate artifact coupling admission vectors");
        let vectors: LeanCandidateArtifactCouplingAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean candidate artifact coupling admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors
                .candidate_artifact_coupling_admission_cases
                .is_empty(),
            "Lean candidate artifact coupling admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.candidate_artifact_coupling_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_candidate_artifact_coupling_admission_case(case);
        }
    }

    fn verify_lean_candidate_artifact_coupling_admission_case(
        case: &LeanCandidateArtifactCouplingAdmissionCase,
    ) {
        let input = NativeCandidateArtifactCouplingAdmissionInput {
            transfer_count: case.transfer_count,
            candidate_artifact_count: case.candidate_artifact_count,
            candidate_tx_count_matches: case.candidate_tx_count_matches,
        };
        let actual_rejection = evaluate_native_candidate_artifact_coupling_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native candidate-artifact coupling admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native candidate-artifact coupling admission rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_mineable_action_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_MINEABLE_ACTION_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_MINEABLE_ACTION_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean mineable action admission vectors");
        let vectors: LeanMineableActionAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean mineable action admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.mineable_action_admission_cases.is_empty(),
            "Lean mineable action admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.mineable_action_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_mineable_action_admission_case(case);
        }
    }

    fn verify_lean_mineable_action_admission_case(case: &LeanMineableActionAdmissionCase) {
        let input = NativeMineableActionAdmissionInput {
            candidate_artifact_route: case.candidate_artifact_route,
            candidate_artifact_selected: case.candidate_artifact_selected,
            sidecar_transfer_route: case.sidecar_transfer_route,
            sidecar_ciphertexts_available: case.sidecar_ciphertexts_available,
            sidecar_ciphertext_sizes_present: case.sidecar_ciphertext_sizes_present,
            sidecar_ciphertext_sizes_match: case.sidecar_ciphertext_sizes_match,
        };
        let actual_rejection = evaluate_native_mineable_action_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native mineable action admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native mineable action admission rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_block_artifact_binding_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BLOCK_ARTIFACT_BINDING_ADMISSION_VECTORS")
        else {
            eprintln!(
                "HEGEMON_LEAN_BLOCK_ARTIFACT_BINDING_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean block artifact binding admission vectors");
        let vectors: LeanBlockArtifactBindingAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean block artifact binding admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.tx_leaf_action_binding_cases.is_empty(),
            "Lean tx-leaf action binding cases must not be empty"
        );
        assert!(
            !vectors.candidate_artifact_binding_cases.is_empty(),
            "Lean candidate artifact binding cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.tx_leaf_action_binding_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_tx_leaf_action_binding_admission_case(case);
        }
        for case in &vectors.candidate_artifact_binding_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_candidate_artifact_binding_admission_case(case);
        }
    }

    fn verify_lean_tx_leaf_action_binding_admission_case(
        case: &LeanTxLeafActionBindingAdmissionCase,
    ) {
        let input = NativeTxLeafActionBindingAdmissionInput {
            nullifiers_match: case.nullifiers_match,
            commitments_match: case.commitments_match,
            ciphertext_hashes_match: case.ciphertext_hashes_match,
            input_count_matches: case.input_count_matches,
            output_count_matches: case.output_count_matches,
            version_matches: case.version_matches,
            fee_matches: case.fee_matches,
            stablecoin_payload_matches: case.stablecoin_payload_matches,
            balance_tag_matches: case.balance_tag_matches,
            receipt_statement_hash_matches: case.receipt_statement_hash_matches,
            public_inputs_digest_matches: case.public_inputs_digest_matches,
            proof_digest_matches: case.proof_digest_matches,
            proof_backend_matches: case.proof_backend_matches,
            ciphertext_payload_hashes_match: case.ciphertext_payload_hashes_match,
        };
        let actual_rejection = evaluate_native_tx_leaf_action_binding_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native tx-leaf action binding validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native tx-leaf action binding rejection drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_candidate_artifact_binding_admission_case(
        case: &LeanCandidateArtifactBindingAdmissionCase,
    ) {
        let input = NativeCandidateArtifactBindingAdmissionInput {
            da_root_matches: case.da_root_matches,
            tx_statements_commitment_matches: case.tx_statements_commitment_matches,
            recursive_state_root_matches: case.recursive_state_root_matches,
        };
        let actual_rejection = evaluate_native_candidate_artifact_binding_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native candidate artifact binding validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native candidate artifact binding rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn block_artifact_binding_rejects_tx_leaf_action_mismatches_in_order() {
        let valid = NativeTxLeafActionBindingAdmissionInput {
            nullifiers_match: true,
            commitments_match: true,
            ciphertext_hashes_match: true,
            input_count_matches: true,
            output_count_matches: true,
            version_matches: true,
            fee_matches: true,
            stablecoin_payload_matches: true,
            balance_tag_matches: true,
            receipt_statement_hash_matches: true,
            public_inputs_digest_matches: true,
            proof_digest_matches: true,
            proof_backend_matches: true,
            ciphertext_payload_hashes_match: true,
        };
        assert!(evaluate_native_tx_leaf_action_binding_admission(valid).is_ok());
        assert_eq!(
            evaluate_native_tx_leaf_action_binding_admission(
                NativeTxLeafActionBindingAdmissionInput {
                    nullifiers_match: false,
                    commitments_match: false,
                    ..valid
                }
            )
            .expect_err("nullifier mismatch must reject")
            .label(),
            "nullifiers_mismatch"
        );
        assert_eq!(
            evaluate_native_tx_leaf_action_binding_admission(
                NativeTxLeafActionBindingAdmissionInput {
                    version_matches: false,
                    fee_matches: false,
                    ciphertext_payload_hashes_match: false,
                    ..valid
                }
            )
            .expect_err("version mismatch must reject before fee or payload hashes")
            .label(),
            "version_mismatch"
        );
        assert_eq!(
            evaluate_native_tx_leaf_action_binding_admission(
                NativeTxLeafActionBindingAdmissionInput {
                    fee_matches: false,
                    stablecoin_payload_matches: false,
                    balance_tag_matches: false,
                    ciphertext_payload_hashes_match: false,
                    ..valid
                }
            )
            .expect_err("fee mismatch must reject before stablecoin or payload hashes")
            .label(),
            "fee_mismatch"
        );
        assert_eq!(
            evaluate_native_tx_leaf_action_binding_admission(
                NativeTxLeafActionBindingAdmissionInput {
                    stablecoin_payload_matches: false,
                    balance_tag_matches: false,
                    receipt_statement_hash_matches: false,
                    ..valid
                }
            )
            .expect_err("stablecoin mismatch must reject before balance tag or receipt fields")
            .label(),
            "stablecoin_payload_mismatch"
        );
    }

    #[test]
    fn block_artifact_binding_rejects_extended_tx_leaf_mismatches_in_order() {
        let valid = NativeTxLeafActionBindingAdmissionInput {
            nullifiers_match: true,
            commitments_match: true,
            ciphertext_hashes_match: true,
            input_count_matches: true,
            output_count_matches: true,
            version_matches: true,
            fee_matches: true,
            stablecoin_payload_matches: true,
            balance_tag_matches: true,
            receipt_statement_hash_matches: true,
            public_inputs_digest_matches: true,
            proof_digest_matches: true,
            proof_backend_matches: true,
            ciphertext_payload_hashes_match: true,
        };
        assert_eq!(
            evaluate_native_tx_leaf_action_binding_admission(
                NativeTxLeafActionBindingAdmissionInput {
                    input_count_matches: false,
                    output_count_matches: false,
                    version_matches: false,
                    ..valid
                }
            )
            .expect_err("input count mismatch must reject before output count or version")
            .label(),
            "input_count_mismatch"
        );
        assert_eq!(
            evaluate_native_tx_leaf_action_binding_admission(
                NativeTxLeafActionBindingAdmissionInput {
                    output_count_matches: false,
                    version_matches: false,
                    ..valid
                }
            )
            .expect_err("output count mismatch must reject before version")
            .label(),
            "output_count_mismatch"
        );
        assert_eq!(
            evaluate_native_tx_leaf_action_binding_admission(
                NativeTxLeafActionBindingAdmissionInput {
                    stablecoin_payload_matches: false,
                    balance_tag_matches: false,
                    receipt_statement_hash_matches: false,
                    public_inputs_digest_matches: false,
                    proof_digest_matches: false,
                    proof_backend_matches: false,
                    ciphertext_payload_hashes_match: false,
                    ..valid
                }
            )
            .expect_err("balance tag mismatch must reject before receipt and digest fields")
            .label(),
            "stablecoin_payload_mismatch"
        );
        assert_eq!(
            evaluate_native_tx_leaf_action_binding_admission(
                NativeTxLeafActionBindingAdmissionInput {
                    balance_tag_matches: false,
                    receipt_statement_hash_matches: false,
                    public_inputs_digest_matches: false,
                    proof_digest_matches: false,
                    proof_backend_matches: false,
                    ciphertext_payload_hashes_match: false,
                    ..valid
                }
            )
            .expect_err("balance tag mismatch must reject before receipt and digest fields")
            .label(),
            "balance_tag_mismatch"
        );
        assert_eq!(
            evaluate_native_tx_leaf_action_binding_admission(
                NativeTxLeafActionBindingAdmissionInput {
                    receipt_statement_hash_matches: false,
                    public_inputs_digest_matches: false,
                    proof_digest_matches: false,
                    proof_backend_matches: false,
                    ..valid
                }
            )
            .expect_err("statement hash mismatch must reject before digest fields")
            .label(),
            "receipt_statement_hash_mismatch"
        );
        assert_eq!(
            evaluate_native_tx_leaf_action_binding_admission(
                NativeTxLeafActionBindingAdmissionInput {
                    proof_digest_matches: false,
                    proof_backend_matches: false,
                    ciphertext_payload_hashes_match: false,
                    ..valid
                }
            )
            .expect_err("proof digest mismatch must reject before backend or payload")
            .label(),
            "proof_digest_mismatch"
        );
    }

    #[test]
    fn block_artifact_binding_rejects_candidate_artifact_mismatches_in_order() {
        let valid = NativeCandidateArtifactBindingAdmissionInput {
            da_root_matches: true,
            tx_statements_commitment_matches: true,
            recursive_state_root_matches: true,
        };
        assert!(evaluate_native_candidate_artifact_binding_admission(valid).is_ok());
        assert_eq!(
            evaluate_native_candidate_artifact_binding_admission(
                NativeCandidateArtifactBindingAdmissionInput {
                    da_root_matches: false,
                    tx_statements_commitment_matches: false,
                    ..valid
                }
            )
            .expect_err("DA root mismatch must reject first")
            .label(),
            "da_root_mismatch"
        );
        assert_eq!(
            evaluate_native_candidate_artifact_binding_admission(
                NativeCandidateArtifactBindingAdmissionInput {
                    tx_statements_commitment_matches: false,
                    recursive_state_root_matches: false,
                    ..valid
                }
            )
            .expect_err("statement mismatch must reject before state root")
            .label(),
            "tx_statement_commitment_mismatch"
        );
    }

    #[test]
    fn lean_generated_block_commitment_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BLOCK_COMMITMENT_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_BLOCK_COMMITMENT_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean block commitment admission vectors");
        let vectors: LeanBlockCommitmentAdmissionVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean block commitment vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.block_commitment_admission_cases.is_empty(),
            "Lean block commitment admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.block_commitment_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_block_commitment_admission_case(case);
        }
    }

    fn verify_lean_block_commitment_admission_case(case: &LeanBlockCommitmentAdmissionCase) {
        let input = NativeBlockCommitmentAdmissionInput {
            tx_count_matches: case.tx_count_matches,
            state_root_matches: case.state_root_matches,
            kernel_root_matches: case.kernel_root_matches,
            nullifier_root_matches: case.nullifier_root_matches,
            extrinsics_root_matches: case.extrinsics_root_matches,
            message_root_matches: case.message_root_matches,
            message_count_matches: case.message_count_matches,
            header_mmr_root_matches: case.header_mmr_root_matches,
            header_mmr_len_matches: case.header_mmr_len_matches,
            supply_digest_matches: case.supply_digest_matches,
        };
        let actual_rejection = evaluate_native_block_commitment_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native block commitment admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native block commitment admission rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_block_replay_refinement_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BLOCK_REPLAY_REFINEMENT_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_BLOCK_REPLAY_REFINEMENT_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean block replay refinement vectors");
        let vectors: LeanBlockReplayRefinementVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean block replay refinement vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.block_replay_refinement_cases.is_empty(),
            "Lean block replay refinement cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.block_replay_refinement_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_block_replay_refinement_case(case);
        }
    }

    fn verify_lean_block_replay_refinement_case(case: &LeanBlockReplayRefinementCase) {
        let spent_nullifiers = case
            .spent_nullifiers
            .iter()
            .map(|key| synthetic_stream_nullifier(*key, &case.name))
            .collect::<BTreeSet<_>>();
        let consumed_replays = case
            .consumed_bridge_replays
            .iter()
            .map(|key| synthetic_stream_replay_key(*key, &case.name))
            .collect::<BTreeSet<_>>();
        let action_nullifiers = case
            .actions
            .iter()
            .map(|action| {
                action
                    .nullifiers
                    .iter()
                    .map(|key| synthetic_stream_nullifier(*key, &case.name))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let replay_keys = case
            .actions
            .iter()
            .map(|action| {
                action
                    .bridge_replay_key
                    .map(|key| synthetic_stream_replay_key(key, &case.name))
            })
            .collect::<Vec<_>>();
        let mut nullifier_state = NullifierState::new(spent_nullifiers, BTreeSet::new());
        let mut bridge_replay_state = InboundReplayState::new(consumed_replays, BTreeSet::new());
        let input = NativeBlockReplayRefinementInput {
            leaf_start: case.leaf_start,
            parent_supply: parse_u128(&case.parent_supply),
            height: case.height,
            fee_total: case.fee_total,
            has_coinbase: case.has_coinbase,
            claimed_supply: parse_u128(&case.claimed_supply),
            tx_count_matches: case.tx_count_matches,
            state_root_matches: case.state_root_matches,
            kernel_root_matches: case.kernel_root_matches,
            nullifier_root_matches: case.nullifier_root_matches,
            extrinsics_root_matches: case.extrinsics_root_matches,
            message_root_matches: case.message_root_matches,
            message_count_matches: case.message_count_matches,
            header_mmr_root_matches: case.header_mmr_root_matches,
            header_mmr_len_matches: case.header_mmr_len_matches,
        };

        let (actual_trace, actual) = evaluate_native_block_replay_refinement_with_trace(
            input,
            case.actions
                .iter()
                .zip(action_nullifiers.iter())
                .zip(replay_keys.iter())
                .map(
                    |((action, nullifiers), replay_key)| NativeActionStreamStep {
                        commitment_count: action.commitment_count,
                        ciphertext_count: action.ciphertext_count,
                        nullifiers: nullifiers.as_slice(),
                        replay_key: *replay_key,
                    },
                ),
            &mut nullifier_state,
            &mut bridge_replay_state,
        );
        assert_eq!(
            actual_trace, case.expected_trace,
            "{} replay transition trace drifted from Lean spec",
            case.name
        );
        match actual {
            Ok(summary) => {
                assert!(
                    case.expected_valid,
                    "{} block replay refinement unexpectedly accepted",
                    case.name
                );
                assert_eq!(
                    Some(summary.next_leaf_count.to_string()),
                    case.expected_next_leaf_count,
                    "{} replay next leaf count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(summary.imported_nullifier_count.to_string()),
                    case.expected_imported_nullifier_count,
                    "{} replay imported nullifier count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(summary.imported_bridge_replay_count.to_string()),
                    case.expected_imported_bridge_replay_count,
                    "{} replay imported bridge count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(summary.planned_starts),
                    case.expected_planned_starts,
                    "{} replay planned starts drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(summary.expected_supply.to_string()),
                    case.expected_supply,
                    "{} replay expected supply drifted from Lean spec",
                    case.name
                );
            }
            Err(rejection) => {
                assert!(
                    !case.expected_valid,
                    "{} block replay refinement unexpectedly rejected: {}",
                    case.name,
                    rejection.label()
                );
                assert_eq!(
                    Some(rejection.label().to_owned()),
                    case.expected_rejection,
                    "{} replay rejection drifted from Lean spec",
                    case.name
                );
            }
        }
    }

    #[test]
    fn lean_generated_coinbase_accounting_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_COINBASE_ACCOUNTING_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_COINBASE_ACCOUNTING_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean coinbase accounting admission vectors");
        let vectors: LeanCoinbaseAccountingAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean coinbase accounting admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.coinbase_accounting_admission_cases.is_empty(),
            "Lean coinbase accounting admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.coinbase_accounting_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_coinbase_accounting_admission_case(case);
        }
    }

    fn verify_lean_coinbase_accounting_admission_case(case: &LeanCoinbaseAccountingAdmissionCase) {
        let input = NativeCoinbaseAccountingAdmissionInput {
            coinbase_count: case.coinbase_count,
            height: case.height,
            transfer_fee_total: case.transfer_fee_total.as_deref().map(parse_u64),
            observed_coinbase_amount: case.observed_coinbase_amount.as_deref().map(parse_u64),
        };
        assert_eq!(
            expected_coinbase_amount_from_input(input).map(|amount| amount.to_string()),
            case.expected_coinbase_amount,
            "{} expected coinbase amount drifted from Lean spec",
            case.name
        );
        let actual_rejection = evaluate_native_coinbase_accounting_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native coinbase accounting validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native coinbase accounting rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_coinbase_action_payload_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_COINBASE_ACTION_PAYLOAD_ADMISSION_VECTORS")
        else {
            eprintln!(
                "HEGEMON_LEAN_COINBASE_ACTION_PAYLOAD_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean coinbase action payload admission vectors");
        let vectors: LeanCoinbaseActionPayloadAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean coinbase action payload admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.coinbase_action_payload_admission_cases.is_empty(),
            "Lean coinbase action payload admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.coinbase_action_payload_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_coinbase_action_payload_admission_case(case);
        }
    }

    fn verify_lean_coinbase_action_payload_admission_case(
        case: &LeanCoinbaseActionPayloadAdmissionCase,
    ) {
        assert_eq!(
            case.max_ciphertext_bytes, MAX_CIPHERTEXT_BYTES,
            "{} Lean ciphertext cap must match the production native cap",
            case.name
        );
        let input = NativeCoinbaseActionPayloadAdmissionInput {
            amount_nonzero: case.amount_nonzero,
            commitment_matches: case.commitment_matches,
            commitment_nonzero: case.commitment_nonzero,
            ciphertext_bytes: case.ciphertext_bytes,
            max_ciphertext_bytes: case.max_ciphertext_bytes,
            ciphertext_hash_matches: case.ciphertext_hash_matches,
            ciphertext_size_matches: case.ciphertext_size_matches,
        };
        let actual_rejection = evaluate_native_coinbase_action_payload_admission(input)
            .err()
            .map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native coinbase action payload admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native coinbase action payload admission rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_resource_budget_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_RESOURCE_BUDGET_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_RESOURCE_BUDGET_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean resource budget admission vectors");
        let vectors: LeanResourceBudgetAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean resource budget admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.mempool_budget_cases.is_empty(),
            "Lean mempool budget admission cases must not be empty"
        );
        assert!(
            !vectors.staged_proof_budget_cases.is_empty(),
            "Lean staged proof budget admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.mempool_budget_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_mempool_budget_case(case);
        }
        for case in &vectors.staged_proof_budget_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_staged_proof_budget_case(case);
        }
    }

    fn verify_lean_mempool_budget_case(case: &LeanMempoolBudgetCase) {
        let input = NativeMempoolByteBudgetAdmissionInput {
            pending_bytes: case.pending_bytes,
            candidate_bytes: case.candidate_bytes,
            max_bytes: case.max_bytes,
        };
        let total = case.pending_bytes.saturating_add(case.candidate_bytes);
        assert_eq!(
            total, case.expected_total_bytes,
            "{} native mempool saturated total drifted from Lean spec",
            case.name
        );
        let actual = evaluate_native_mempool_byte_budget_admission(input);
        let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native mempool budget admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native mempool budget admission rejection drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_staged_proof_budget_case(case: &LeanStagedProofBudgetCase) {
        let input = NativeStagedProofByteBudgetAdmissionInput {
            staged_bytes: case.staged_bytes,
            existing_bytes: case.existing_bytes,
            proof_bytes: case.proof_bytes,
            max_bytes: case.max_bytes,
        };
        let total = case
            .staged_bytes
            .saturating_sub(case.existing_bytes)
            .saturating_add(case.proof_bytes);
        assert_eq!(
            total, case.expected_total_bytes,
            "{} native staged-proof saturated total drifted from Lean spec",
            case.name
        );
        let actual = evaluate_native_staged_proof_byte_budget_admission(input);
        let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native staged-proof budget admission validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native staged-proof budget admission rejection drifted from Lean spec",
            case.name
        );
    }

    #[tokio::test]
    async fn lean_generated_rpc_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_RPC_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_RPC_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw =
            std::fs::read_to_string(&path).expect("read generated Lean RPC admission vectors");
        let vectors: LeanRpcAdmissionVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean RPC admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.policy_cases.is_empty(),
            "Lean RPC policy cases must not be empty"
        );
        assert!(
            !vectors.method_gate_cases.is_empty(),
            "Lean RPC method-gate cases must not be empty"
        );
        assert!(
            !vectors.method_list_cases.is_empty(),
            "Lean RPC method-list cases must not be empty"
        );
        assert!(
            !vectors.timestamp_range_cases.is_empty(),
            "Lean RPC timestamp range cases must not be empty"
        );
        assert!(
            !vectors.byte_parse_cases.is_empty(),
            "Lean RPC byte-parse cases must not be empty"
        );
        assert!(
            !vectors.batch_cases.is_empty(),
            "Lean RPC batch cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.policy_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_rpc_policy_case(case);
        }
        for case in &vectors.method_gate_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_rpc_method_gate_case(case);
        }
        for case in &vectors.method_list_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_rpc_method_list_case(case);
        }
        for case in &vectors.timestamp_range_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_rpc_timestamp_range_case(case);
        }
        for case in &vectors.byte_parse_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_rpc_byte_parse_case(case);
        }
        for case in &vectors.batch_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_rpc_batch_case(case).await;
        }
    }

    fn verify_lean_rpc_policy_case(case: &LeanRpcPolicyCase) {
        assert!(
            matches!(
                case.raw_tag.as_str(),
                "safe" | "unsafe" | "auto" | "empty" | "invalid"
            ),
            "{} unknown Lean RPC raw policy tag {}",
            case.name,
            case.raw_tag
        );
        let actual = rpc_method_policy(&case.raw, case.rpc_external);
        let actual_policy = actual.as_ref().ok().map(|policy| policy.label().to_owned());
        let actual_rejection = actual.as_ref().err().map(|_| "invalid_policy".to_string());
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} RPC policy validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_policy, case.expected_policy,
            "{} RPC policy resolution drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} RPC policy rejection drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_rpc_method_gate_case(case: &LeanRpcMethodGateCase) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, &case.policy, false))
            .expect("node");
        let params = rpc_test_params_for_method(&case.method);
        let actual = dispatch_rpc_method(&node, &case.method, params);
        let actual_rejection = actual
            .as_ref()
            .err()
            .and_then(|err| rpc_method_gate_rejection_label(&err.to_string()));
        assert_eq!(
            is_unsafe_rpc_method(&case.method),
            case.is_unsafe_method,
            "{} RPC unsafe-method classification drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} RPC method gate validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} RPC method gate rejection drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_rpc_method_list_case(case: &LeanRpcMethodListCase) {
        let policy = rpc_policy_from_label(&case.policy);
        let methods = native_rpc_methods(policy);
        let unsafe_methods = [
            "da_submitCiphertexts",
            "da_submitProofs",
            "hegemon_startMining",
            "hegemon_stopMining",
            "hegemon_submitAction",
        ];
        for method in unsafe_methods {
            assert_eq!(
                methods.contains(&method),
                case.expected_unsafe_methods_visible,
                "{} RPC method-list unsafe visibility drifted for {method}",
                case.name
            );
        }
        assert!(
            methods.contains(&"system_health"),
            "{} RPC method-list must keep safe health method visible",
            case.name
        );
    }

    fn verify_lean_rpc_timestamp_range_case(case: &LeanRpcTimestampRangeCase) {
        assert_eq!(
            case.max_rows, MAX_NATIVE_TIMESTAMP_ROWS,
            "{} Lean timestamp cap must match production native RPC cap",
            case.name
        );
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        let actual = block_timestamps(&node, json!([case.start_height, case.end_height]), false);
        let actual_rejection = actual
            .as_ref()
            .err()
            .and_then(|err| rpc_timestamp_rejection_label(&err.to_string()));
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} RPC timestamp range validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} RPC timestamp range rejection drifted from Lean spec",
            case.name
        );
        if let Ok(value) = actual {
            let rows = value
                .as_array()
                .expect("timestamp response should be an array")
                .len()
                .to_string();
            assert_eq!(
                Some(rows),
                case.expected_requested_rows,
                "{} RPC timestamp requested-row count drifted from Lean spec",
                case.name
            );
        }
    }

    fn verify_lean_rpc_byte_parse_case(case: &LeanRpcByteParseCase) {
        assert_eq!(
            encoded_len_limit(case.max_decoded_bytes),
            case.expected_encoded_len_limit,
            "{} RPC base64 encoded length limit drifted from Lean spec",
            case.name
        );
        assert_eq!(
            case.max_decoded_bytes.saturating_mul(2),
            case.expected_hex_len_limit,
            "{} RPC hex length limit drifted from Lean spec",
            case.name
        );
        let value = rpc_byte_parse_value(case);
        if case.encoding == "base64" {
            assert_eq!(
                value.as_str().expect("base64 test value").len(),
                case.raw_text_bytes,
                "{} RPC base64 raw text length fixture drifted from Lean spec",
                case.name
            );
        } else if case.encoding == "hex" {
            assert_eq!(
                value
                    .as_str()
                    .expect("hex test value")
                    .strip_prefix("0x")
                    .expect("hex prefix")
                    .len(),
                case.raw_text_bytes,
                "{} RPC hex raw text length fixture drifted from Lean spec",
                case.name
            );
        } else {
            panic!("{} unknown byte encoding {}", case.name, case.encoding);
        }
        let actual = parse_bytes_value(&value, case.max_decoded_bytes, "Lean RPC byte case");
        let actual_rejection = actual
            .as_ref()
            .err()
            .and_then(|err| rpc_byte_parse_rejection_label(&err.to_string()));
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} RPC byte parser validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} RPC byte parser rejection drifted from Lean spec",
            case.name
        );
        if let Ok(bytes) = actual {
            assert_eq!(
                bytes.len(),
                case.decoded_bytes,
                "{} RPC byte parser decoded length drifted from Lean spec",
                case.name
            );
        }
    }

    async fn verify_lean_rpc_batch_case(case: &LeanRpcBatchCase) {
        assert_eq!(
            case.max_requests, MAX_NATIVE_RPC_BATCH_REQUESTS,
            "{} Lean batch cap must match production native RPC cap",
            case.name
        );
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        let payload = Value::Array(
            (0..case.request_count)
                .map(|idx| {
                    json!({
                        "jsonrpc": "2.0",
                        "id": idx,
                        "method": "system_health",
                        "params": [],
                    })
                })
                .collect(),
        );
        let response = rpc_handler(State(node), Json(payload)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("RPC response body");
        let decoded: Value = serde_json::from_slice(&body).expect("RPC JSON body");
        let actual_rejection = decoded
            .get("error")
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .and_then(rpc_batch_rejection_label);
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} RPC batch validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} RPC batch rejection drifted from Lean spec",
            case.name
        );
        if case.expected_valid {
            assert_eq!(
                decoded.as_array().expect("batch response array").len(),
                case.request_count,
                "{} RPC batch response count drifted from Lean spec",
                case.name
            );
        }
    }

    fn rpc_policy_from_label(label: &str) -> RpcMethodPolicy {
        match label {
            "safe" => RpcMethodPolicy::Safe,
            "unsafe" => RpcMethodPolicy::Unsafe,
            other => panic!("unknown RPC method policy label {other}"),
        }
    }

    fn rpc_test_params_for_method(method: &str) -> Value {
        match method {
            "da_submitCiphertexts" => json!({ "ciphertexts": [] }),
            "da_submitProofs" => json!({ "proofs": [] }),
            "hegemon_startMining" => json!({ "threads": 1 }),
            "hegemon_stopMining" => Value::Array(Vec::new()),
            "hegemon_submitAction" => json!({}),
            _ => Value::Array(Vec::new()),
        }
    }

    fn rpc_method_gate_rejection_label(message: &str) -> Option<String> {
        if message.contains("unsafe RPC method") {
            Some("unsafe_method_disabled".to_string())
        } else {
            None
        }
    }

    fn rpc_timestamp_rejection_label(message: &str) -> Option<String> {
        if message.contains("before start") {
            Some("end_before_start".to_string())
        } else if message.contains("timestamp range overflow") {
            Some("range_overflow".to_string())
        } else if message.contains("timestamp range too large") {
            Some("range_too_large".to_string())
        } else {
            None
        }
    }

    fn rpc_byte_parse_rejection_label(message: &str) -> Option<String> {
        if message.contains("hex length") {
            Some("hex_text_too_long".to_string())
        } else if message.contains("base64 length") {
            Some("base64_text_too_long".to_string())
        } else if message.contains("decoded length") {
            Some("decoded_too_long".to_string())
        } else {
            None
        }
    }

    fn rpc_batch_rejection_label(message: &str) -> Option<String> {
        if message.contains("empty JSON-RPC batch") {
            Some("empty_batch".to_string())
        } else if message.contains("batch too large") {
            Some("batch_too_large".to_string())
        } else {
            None
        }
    }

    fn rpc_byte_parse_value(case: &LeanRpcByteParseCase) -> Value {
        match case.encoding.as_str() {
            "base64" => {
                if case.expected_rejection.as_deref() == Some("base64_text_too_long") {
                    json!("A".repeat(case.raw_text_bytes))
                } else {
                    use base64::Engine;
                    json!(base64::engine::general_purpose::STANDARD
                        .encode(vec![0u8; case.decoded_bytes]))
                }
            }
            "hex" => json!(format!("0x{}", "00".repeat(case.decoded_bytes))),
            other => panic!("{} unknown byte encoding {other}", case.name),
        }
    }

    #[test]
    fn lean_generated_sidecar_upload_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_SIDECAR_UPLOAD_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_SIDECAR_UPLOAD_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean sidecar upload admission vectors");
        let vectors: LeanSidecarUploadAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean sidecar upload admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.request_count_cases.is_empty(),
            "Lean sidecar request-count cases must not be empty"
        );
        assert!(
            !vectors.capacity_cases.is_empty(),
            "Lean sidecar capacity cases must not be empty"
        );
        assert!(
            !vectors.proof_metadata_cases.is_empty(),
            "Lean proof sidecar metadata cases must not be empty"
        );
        assert!(
            !vectors.proof_decoded_cases.is_empty(),
            "Lean proof sidecar decoded cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.request_count_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_sidecar_request_count_case(case);
        }
        for case in &vectors.capacity_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_sidecar_capacity_case(case);
        }
        for case in &vectors.proof_metadata_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_proof_sidecar_metadata_case(case);
        }
        for case in &vectors.proof_decoded_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_proof_sidecar_decoded_case(case);
        }
    }

    fn verify_lean_sidecar_request_count_case(case: &LeanSidecarRequestCountCase) {
        let input = NativeSidecarRequestCountAdmissionInput {
            item_count: case.item_count,
            max_items: case.max_items,
        };
        let actual = match case.kind.as_str() {
            "ciphertexts" => evaluate_native_ciphertext_sidecar_request_admission(input),
            "proofs" => evaluate_native_proof_sidecar_request_admission(input),
            other => panic!("{} unknown request-count kind {other}", case.name),
        };
        let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native sidecar request-count validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native sidecar request-count rejection drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_sidecar_capacity_case(case: &LeanSidecarCapacityCase) {
        let input = NativeSidecarCapacityAdmissionInput {
            staged_count: case.staged_count,
            max_staged_count: case.max_staged_count,
            replaces_existing: case.replaces_existing,
        };
        let actual = match case.kind.as_str() {
            "ciphertext" => evaluate_native_ciphertext_sidecar_capacity_admission(input),
            "proof" => evaluate_native_proof_sidecar_capacity_admission(input),
            other => panic!("{} unknown capacity kind {other}", case.name),
        };
        let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native sidecar capacity validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native sidecar capacity rejection drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_proof_sidecar_metadata_case(case: &LeanProofSidecarMetadataCase) {
        let input = NativeProofSidecarMetadataAdmissionInput {
            binding_hash_present: case.binding_hash_present,
            binding_hash_valid: case.binding_hash_valid,
            proof_present: case.proof_present,
        };
        let actual = evaluate_native_proof_sidecar_metadata_admission(input);
        let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native proof sidecar metadata validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native proof sidecar metadata rejection drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_proof_sidecar_decoded_case(case: &LeanProofSidecarDecodedCase) {
        assert_eq!(
            case.max_proof_bytes, NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
            "{} Lean proof sidecar cap must match the production native tx-leaf cap",
            case.name
        );
        let input = NativeProofSidecarDecodedAdmissionInput {
            proof_bytes: case.proof_bytes,
            max_proof_bytes: case.max_proof_bytes,
            proof_binding_hash_matches_key: case.proof_binding_hash_matches_key,
        };
        let actual = evaluate_native_proof_sidecar_decoded_admission(input);
        let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
        assert_eq!(
            actual_rejection.is_none(),
            case.expected_valid,
            "{} native proof sidecar decoded validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} native proof sidecar decoded rejection drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_sync_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_SYNC_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_SYNC_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw =
            std::fs::read_to_string(&path).expect("read generated Lean sync admission vectors");
        let vectors: LeanSyncAdmissionVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean sync admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.sync_response_range_cases.is_empty(),
            "Lean sync response-range cases must not be empty"
        );
        assert!(
            !vectors.sync_missing_request_cases.is_empty(),
            "Lean sync missing-request cases must not be empty"
        );
        assert!(
            !vectors.sync_response_count_cases.is_empty(),
            "Lean sync response-count cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.sync_response_range_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_sync_response_range_case(case);
        }
        for case in &vectors.sync_missing_request_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_sync_missing_request_case(case);
        }
        for case in &vectors.sync_response_count_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_sync_response_count_case(case);
        }
    }

    fn verify_lean_sync_response_range_case(case: &LeanSyncResponseRangeCase) {
        let actual = native_sync_response_range(NativeSyncResponseRangeInput {
            from_height: case.from_height,
            to_height: case.to_height,
            best_height: case.best_height,
            max_blocks: case.max_blocks,
        });
        assert_eq!(
            actual.is_some(),
            case.expected_has_range,
            "{} native sync response-range validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual.map(|range| range.from_height),
            case.expected_from_height,
            "{} native sync response-range start drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual.map(|range| range.to_height),
            case.expected_to_height,
            "{} native sync response-range end drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_sync_missing_request_case(case: &LeanSyncMissingRequestCase) {
        let actual = native_sync_missing_request_range(NativeSyncMissingRequestInput {
            best_height: case.best_height,
            announced_height: case.announced_height,
            max_blocks: case.max_blocks,
        });
        assert_eq!(
            actual.is_some(),
            case.expected_has_request,
            "{} native sync missing-request validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual.map(|range| range.from_height),
            case.expected_from_height,
            "{} native sync missing-request start drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual.map(|range| range.to_height),
            case.expected_to_height,
            "{} native sync missing-request end drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_sync_response_count_case(case: &LeanSyncResponseCountCase) {
        let actual =
            evaluate_native_sync_response_count_admission(NativeSyncResponseCountAdmissionInput {
                block_count: case.block_count,
                max_blocks: case.max_blocks,
            });
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} native sync response-count validity drifted from Lean spec",
            case.name
        );
        if !case.expected_valid {
            assert_eq!(
                actual.err(),
                Some(NativeSyncAdmissionRejection::ResponseBlockCountTooLarge),
                "{} native sync response-count rejection drifted from expected cap rejection",
                case.name
            );
        }
    }

    #[test]
    fn native_sync_admission_rejects_oversized_responses() {
        assert_eq!(
            evaluate_native_sync_response_count_admission(NativeSyncResponseCountAdmissionInput {
                block_count: MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE + 1,
                max_blocks: MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE,
            },),
            Err(NativeSyncAdmissionRejection::ResponseBlockCountTooLarge)
        );
    }

    #[test]
    fn native_sync_ranges_fail_closed_when_cap_zero() {
        assert_eq!(
            native_sync_response_range(NativeSyncResponseRangeInput {
                from_height: 1,
                to_height: 1,
                best_height: 1,
                max_blocks: 0,
            }),
            None
        );
        assert_eq!(
            native_sync_missing_request_range(NativeSyncMissingRequestInput {
                best_height: 1,
                announced_height: 2,
                max_blocks: 0,
            }),
            None
        );
    }

    #[test]
    fn block_range_rejects_missing_canonical_height_inside_admitted_range() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        let first = mine_empty_native_block(&node);
        let second = mine_empty_native_block(&node);
        assert_eq!(first.height, 1);
        assert_eq!(second.height, 2);

        node.height_tree
            .remove(height_key(1))
            .expect("remove height index");
        node.height_tree.flush().expect("flush height tree");

        let err = node
            .block_range(0, 2)
            .expect_err("missing admitted canonical height must reject sync range");
        assert!(err.to_string().contains("missing canonical height index"));
    }

    #[test]
    fn block_range_rejects_missing_header_inside_admitted_range() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        let first = mine_empty_native_block(&node);
        let second = mine_empty_native_block(&node);
        assert_eq!(second.height, 2);

        node.block_tree
            .remove(first.hash.as_slice())
            .expect("remove block record");
        node.block_tree.flush().expect("flush block tree");

        let err = node
            .block_range(0, 2)
            .expect_err("missing admitted block record must reject sync range");
        assert!(err.to_string().contains("missing native block record"));
    }

    #[test]
    fn block_range_rejects_height_index_pointing_to_wrong_header() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        let first = mine_empty_native_block(&node);
        let second = mine_empty_native_block(&node);
        assert_eq!(first.height, 1);
        assert_eq!(second.height, 2);

        node.height_tree
            .insert(height_key(1), second.hash.as_slice())
            .expect("forge height index");
        node.height_tree.flush().expect("flush height tree");

        let err = node
            .block_range(0, 2)
            .expect_err("wrong admitted block metadata must reject sync range");
        assert!(err
            .to_string()
            .contains("points to block metadata at height 2"));
    }

    #[test]
    fn block_range_rejects_corrupt_canonical_action_body_inside_admitted_range() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        let first = mine_empty_native_block(&node);
        let second = mine_empty_native_block(&node);
        assert_eq!(first.height, 1);
        assert_eq!(second.height, 2);

        let mut corrupted = first.clone();
        corrupted.action_bytes.push(vec![0xaa]);
        let encoded = bincode::serialize(&corrupted).expect("serialize corrupted block body");
        node.block_tree
            .insert(first.hash.as_slice(), encoded)
            .expect("replace canonical block body");
        node.block_tree.flush().expect("flush block tree");

        let err = node
            .block_range(0, 2)
            .expect_err("corrupt canonical action body must reject sync range");
        let err = format!("{err:?}");
        assert!(
            err.contains("validate canonical native sync block body"),
            "{err}"
        );
        assert!(err.contains("block action payload count mismatch"), "{err}");
    }

    #[test]
    fn imported_block_actions_reject_hash_mismatch() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_inline_transfer_action(anchor, [21u8; 48], [121u8; 48], 0);
        action.tx_hash[0] ^= 1;

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("mutated action hash should fail admission");
        assert!(err.to_string().contains("block action hash mismatch"));
    }

    #[test]
    fn imported_block_actions_reject_duplicate_hashes() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let action = test_inline_transfer_action(anchor, [22u8; 48], [122u8; 48], 0);

        let err = validate_block_actions_locked(&state, &[action.clone(), action])
            .expect_err("duplicate action hash should fail admission");
        assert!(err.to_string().contains("duplicate action in block"));
    }

    #[test]
    fn semantic_action_hash_ignores_received_time_for_duplicate_policy() {
        let first = test_outbound_bridge_action(b"same outbound body");
        let mut second = first.clone();
        second.received_ms = first.received_ms.saturating_add(42);
        second.tx_hash = pending_action_hash(&second);

        assert_ne!(first.tx_hash, second.tx_hash);
        assert_eq!(
            pending_action_semantic_hash(&first),
            pending_action_semantic_hash(&second)
        );
    }

    #[test]
    fn imported_block_actions_reject_semantic_duplicate_with_different_received_time() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let first = test_outbound_bridge_action(b"same semantic outbound body");
        let mut second = first.clone();
        second.received_ms = first.received_ms.saturating_add(1);
        second.tx_hash = pending_action_hash(&second);
        assert_ne!(first.tx_hash, second.tx_hash);

        let err = validate_block_actions_locked(&state, &[first, second])
            .expect_err("semantic duplicate must fail even when tx_hash differs");
        assert!(err.to_string().contains("duplicate semantic action"));
    }

    #[test]
    fn decode_block_actions_rejects_action_count_mismatch() {
        let pow_bits = 0x207f_ffff;
        let mut block = genesis_meta(pow_bits).expect("genesis");
        block.tx_count = 1;

        let err = decode_block_actions(&block).expect_err("count mismatch should fail admission");
        assert!(err
            .to_string()
            .contains("block action payload count mismatch"));
    }

    #[test]
    fn decode_block_actions_rejects_action_hash_mismatch() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_inline_transfer_action(anchor, [23u8; 48], [123u8; 48], 0);
        action.tx_hash[0] ^= 1;

        let mut block = genesis_meta(pow_bits).expect("genesis");
        block.tx_count = 1;
        block.action_bytes = vec![action.encode()];

        let err =
            decode_block_actions(&block).expect_err("mutated action hash should fail admission");
        assert!(err.to_string().contains("block action hash mismatch"));
    }

    #[test]
    fn decode_block_actions_rejects_duplicate_hashes() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let action = test_inline_transfer_action(anchor, [24u8; 48], [124u8; 48], 0);

        let mut block = genesis_meta(pow_bits).expect("genesis");
        block.tx_count = 2;
        block.action_bytes = vec![action.encode(), action.encode()];

        let err =
            decode_block_actions(&block).expect_err("duplicate action hash should fail admission");
        assert!(err.to_string().contains("duplicate action in block"));
    }

    #[test]
    fn load_pending_actions_accepts_valid_hash_binding() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db
            .open_tree("pending_actions")
            .expect("pending action tree");
        let action = test_outbound_bridge_action(b"persisted pending action");
        tree.insert(action.tx_hash.as_slice(), action.encode())
            .expect("insert pending action");

        let loaded = load_pending_actions(&tree).expect("load pending actions");
        let loaded_action = loaded.get(&action.tx_hash).expect("loaded action");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded_action.tx_hash, action.tx_hash);
        assert_eq!(pending_action_hash(loaded_action), action.tx_hash);
    }

    #[test]
    fn load_pending_actions_rejects_malformed_key() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db
            .open_tree("pending_actions")
            .expect("pending action tree");
        let action = test_outbound_bridge_action(b"persisted malformed key");
        tree.insert(&[7u8; 31], action.encode())
            .expect("insert malformed pending action key");

        let err =
            load_pending_actions(&tree).expect_err("malformed pending action key must reject");
        assert!(err
            .to_string()
            .contains("stored pending action key has invalid length"));
    }

    #[test]
    fn load_pending_actions_rejects_key_hash_mismatch() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db
            .open_tree("pending_actions")
            .expect("pending action tree");
        let action = test_outbound_bridge_action(b"persisted wrong key");
        let mut wrong_key = action.tx_hash;
        wrong_key[0] ^= 0x80;
        tree.insert(wrong_key.as_slice(), action.encode())
            .expect("insert mismatched pending action");

        let err =
            load_pending_actions(&tree).expect_err("stored action under the wrong key must reject");
        assert!(err
            .to_string()
            .contains("stored pending action key/hash mismatch"));
    }

    #[test]
    fn load_pending_actions_rejects_stale_embedded_hash() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db
            .open_tree("pending_actions")
            .expect("pending action tree");
        let mut action = test_outbound_bridge_action(b"persisted stale body");
        let key = action.tx_hash;
        action.received_ms = action.received_ms.saturating_add(1);
        tree.insert(key.as_slice(), action.encode())
            .expect("insert stale pending action");

        let err = load_pending_actions(&tree)
            .expect_err("stored action with stale embedded hash must reject");
        assert!(err
            .to_string()
            .contains("stored pending action hash mismatch"));
    }

    #[test]
    fn load_pending_actions_rejects_semantic_duplicate_received_time() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db
            .open_tree("pending_actions")
            .expect("pending action tree");
        let first = test_outbound_bridge_action(b"persisted duplicate semantic body");
        let mut second = first.clone();
        second.received_ms = first.received_ms.saturating_add(1);
        second.tx_hash = pending_action_hash(&second);
        assert_ne!(first.tx_hash, second.tx_hash);
        assert_eq!(
            pending_action_semantic_hash(&first),
            pending_action_semantic_hash(&second)
        );
        tree.insert(first.tx_hash.as_slice(), first.encode())
            .expect("insert first pending action");
        tree.insert(second.tx_hash.as_slice(), second.encode())
            .expect("insert second pending action");

        let err = load_pending_actions(&tree)
            .expect_err("semantic duplicate persisted pending action must reject");
        assert!(err
            .to_string()
            .contains("duplicate semantic stored pending action"));
    }

    #[test]
    fn load_staged_sizes_accepts_hash_bound_ciphertext() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db
            .open_tree("staged_ciphertexts")
            .expect("staged ciphertext tree");
        let raw = vec![1u8, 2, 3, 4, 5];
        let hash = ciphertext_hash_bytes(&raw);
        tree.insert(hash.as_slice(), raw.as_slice())
            .expect("insert staged ciphertext");

        let loaded = load_staged_sizes(&db, &tree).expect("load staged ciphertext sizes");

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(&hex48(&hash)), Some(&(raw.len() as u32)));
        assert!(tree
            .get(hash.as_slice())
            .expect("read ciphertext")
            .is_some());
    }

    #[test]
    fn load_staged_sizes_drops_hash_mismatch() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db
            .open_tree("staged_ciphertexts")
            .expect("staged ciphertext tree");
        let raw = vec![1u8, 2, 3];
        let wrong_hash = [9u8; 48];
        assert_ne!(ciphertext_hash_bytes(&raw), wrong_hash);
        tree.insert(wrong_hash.as_slice(), raw.as_slice())
            .expect("insert mismatched staged ciphertext");

        let loaded = load_staged_sizes(&db, &tree).expect("load staged ciphertext sizes");

        assert!(loaded.is_empty());
        assert!(tree
            .get(wrong_hash.as_slice())
            .expect("read dropped ciphertext")
            .is_none());
    }

    #[test]
    fn load_staged_sizes_drops_hash_mismatch_across_reopen() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let raw = vec![1u8, 2, 3];
        let wrong_hash = [9u8; 48];
        assert_ne!(ciphertext_hash_bytes(&raw), wrong_hash);

        {
            let db = sled::Config::new()
                .path(tmp.path())
                .open()
                .expect("sled db");
            let tree = db
                .open_tree("staged_ciphertexts")
                .expect("staged ciphertext tree");
            tree.insert(wrong_hash.as_slice(), raw.as_slice())
                .expect("insert mismatched staged ciphertext");

            let loaded = load_staged_sizes(&db, &tree).expect("load staged ciphertext sizes");
            assert!(loaded.is_empty());
        }

        let db = sled::Config::new()
            .path(tmp.path())
            .open()
            .expect("reopen sled db");
        let tree = db
            .open_tree("staged_ciphertexts")
            .expect("reopen staged ciphertext tree");
        assert!(tree
            .get(wrong_hash.as_slice())
            .expect("read dropped ciphertext after reopen")
            .is_none());
    }

    #[test]
    fn load_staged_sizes_drops_oversized_ciphertext() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db
            .open_tree("staged_ciphertexts")
            .expect("staged ciphertext tree");
        let raw = vec![7u8; 5];
        let hash = ciphertext_hash_bytes(&raw);
        tree.insert(hash.as_slice(), raw.as_slice())
            .expect("insert oversized staged ciphertext");

        let loaded =
            load_staged_sizes_with_limits(&db, &tree, MAX_NATIVE_STAGED_CIPHERTEXTS, raw.len() - 1)
                .expect("load staged ciphertext sizes");

        assert!(loaded.is_empty());
        assert!(tree
            .get(hash.as_slice())
            .expect("read dropped ciphertext")
            .is_none());
    }

    #[test]
    fn load_staged_sizes_drops_capacity_overflow() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db
            .open_tree("staged_ciphertexts")
            .expect("staged ciphertext tree");
        let first = vec![1u8];
        let second = vec![2u8];
        let first_hash = ciphertext_hash_bytes(&first);
        let second_hash = ciphertext_hash_bytes(&second);
        tree.insert(first_hash.as_slice(), first.as_slice())
            .expect("insert first staged ciphertext");
        tree.insert(second_hash.as_slice(), second.as_slice())
            .expect("insert second staged ciphertext");

        let loaded = load_staged_sizes_with_limits(&db, &tree, 1, MAX_CIPHERTEXT_BYTES)
            .expect("load staged ciphertext sizes");

        assert_eq!(loaded.len(), 1);
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn load_staged_proofs_accepts_valid_proof() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db.open_tree("staged_proofs").expect("staged proof tree");
        let (binding_hash, proof) = staged_proof_fixture();
        tree.insert(binding_hash.as_slice(), proof.as_slice())
            .expect("insert staged proof");

        let loaded = load_staged_proofs(&db, &tree).expect("load staged proofs");

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(&hex64(&binding_hash)), Some(&proof));
        assert!(tree
            .get(binding_hash.as_slice())
            .expect("read staged proof")
            .is_some());
    }

    #[test]
    fn load_staged_proofs_drops_malformed_key() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db.open_tree("staged_proofs").expect("staged proof tree");
        tree.insert(&[7u8; 63], [1u8, 2, 3].as_slice())
            .expect("insert malformed proof key");

        let loaded = load_staged_proofs(&db, &tree).expect("load staged proofs");

        assert!(loaded.is_empty());
        assert_eq!(tree.len(), 0);
    }

    #[test]
    fn load_staged_proofs_drops_empty_proof() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db.open_tree("staged_proofs").expect("staged proof tree");
        let binding_hash = [2u8; 64];
        tree.insert(binding_hash.as_slice(), [].as_slice())
            .expect("insert empty staged proof");

        let loaded = load_staged_proofs(&db, &tree).expect("load staged proofs");

        assert!(loaded.is_empty());
        assert!(tree
            .get(binding_hash.as_slice())
            .expect("read dropped proof")
            .is_none());
    }

    #[test]
    fn load_staged_proofs_drops_empty_proof_across_reopen() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let binding_hash = [2u8; 64];

        {
            let db = sled::Config::new()
                .path(tmp.path())
                .open()
                .expect("sled db");
            let tree = db.open_tree("staged_proofs").expect("staged proof tree");
            tree.insert(binding_hash.as_slice(), [].as_slice())
                .expect("insert empty staged proof");

            let loaded = load_staged_proofs(&db, &tree).expect("load staged proofs");
            assert!(loaded.is_empty());
        }

        let db = sled::Config::new()
            .path(tmp.path())
            .open()
            .expect("reopen sled db");
        let tree = db
            .open_tree("staged_proofs")
            .expect("reopen staged proof tree");
        assert!(tree
            .get(binding_hash.as_slice())
            .expect("read dropped proof after reopen")
            .is_none());
    }

    #[test]
    fn load_staged_proofs_drops_oversized_proof() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db.open_tree("staged_proofs").expect("staged proof tree");
        let (binding_hash, proof) = staged_proof_fixture();
        tree.insert(binding_hash.as_slice(), proof.as_slice())
            .expect("insert oversized staged proof");

        let loaded = load_staged_proofs_with_limits(
            &db,
            &tree,
            MAX_NATIVE_STAGED_PROOFS,
            proof.len() - 1,
            MAX_NATIVE_STAGED_PROOF_BYTES,
        )
        .expect("load staged proofs");

        assert!(loaded.is_empty());
        assert!(tree
            .get(binding_hash.as_slice())
            .expect("read dropped proof")
            .is_none());
    }

    #[test]
    fn load_staged_proofs_drops_binding_hash_mismatch() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db.open_tree("staged_proofs").expect("staged proof tree");
        let (mut binding_hash, proof) = staged_proof_fixture();
        binding_hash[0] ^= 0xff;
        tree.insert(binding_hash.as_slice(), proof.as_slice())
            .expect("insert mismatched staged proof");

        let loaded = load_staged_proofs(&db, &tree).expect("load staged proofs");

        assert!(loaded.is_empty());
        assert!(tree
            .get(binding_hash.as_slice())
            .expect("read dropped proof")
            .is_none());
    }

    #[test]
    fn load_staged_proofs_drops_capacity_overflow() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db.open_tree("staged_proofs").expect("staged proof tree");
        let (binding_hash, proof) = staged_proof_fixture();
        tree.insert(binding_hash.as_slice(), proof.as_slice())
            .expect("insert staged proof");

        let loaded = load_staged_proofs_with_limits(
            &db,
            &tree,
            0,
            NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
            MAX_NATIVE_STAGED_PROOF_BYTES,
        )
        .expect("load staged proofs");

        assert!(loaded.is_empty());
        assert!(tree
            .get(binding_hash.as_slice())
            .expect("read dropped proof")
            .is_none());
    }

    #[test]
    fn load_staged_proofs_drops_byte_capacity_overflow() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db.open_tree("staged_proofs").expect("staged proof tree");
        let (binding_hash, proof) = staged_proof_fixture();
        tree.insert(binding_hash.as_slice(), proof.as_slice())
            .expect("insert staged proof");

        let loaded = load_staged_proofs_with_limits(
            &db,
            &tree,
            MAX_NATIVE_STAGED_PROOFS,
            NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
            proof.len() - 1,
        )
        .expect("load staged proofs");

        assert!(loaded.is_empty());
        assert!(tree
            .get(binding_hash.as_slice())
            .expect("read dropped proof")
            .is_none());
    }

    fn staged_proof_fixture() -> ([u8; 64], Vec<u8>) {
        let bundle_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../testdata/native_backend_vectors/bundle.json");
        let bundle_bytes = std::fs::read(&bundle_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", bundle_path.display()));
        let bundle: serde_json::Value = serde_json::from_slice(&bundle_bytes)
            .unwrap_or_else(|err| panic!("parse {}: {err}", bundle_path.display()));
        let artifact_hex = bundle["cases"]
            .as_array()
            .and_then(|cases| {
                cases
                    .iter()
                    .find(|case| case["name"].as_str() == Some("native_tx_leaf_valid"))
            })
            .and_then(|case| case["artifact_hex"].as_str())
            .expect("bundle must contain native_tx_leaf_valid artifact_hex");
        let artifact_bytes =
            hex::decode(artifact_hex).expect("native_tx_leaf_valid artifact hex must decode");
        let decoded =
            consensus::backend_interface::decode_native_tx_leaf_artifact_bytes(&artifact_bytes)
                .expect("native_tx_leaf_valid artifact must decode");
        let binding_hash = native_tx_leaf_artifact_binding_hash(&decoded)
            .expect("native_tx_leaf_valid artifact binding hash");
        assert!(native_tx_leaf_artifact_binding_hash_matches_key(
            binding_hash,
            &artifact_bytes
        ));
        (binding_hash, artifact_bytes)
    }

    fn repartitioned_tx_leaf_binding_alias_fixture() -> ([u8; 64], Vec<u8>) {
        let anchor = [41u8; 48];
        let nullifier = [42u8; 48];
        let commitment = [43u8; 48];
        let ciphertext_hash = [44u8; 48];
        let balance_slot_asset_ids = [0, u64::MAX, u64::MAX, u64::MAX];
        let fee = 0;
        let stablecoin = None;
        let binding = KernelVersionBinding {
            circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
        };
        let intended = ShieldedTransferInputs {
            anchor,
            nullifiers: vec![nullifier],
            commitments: vec![commitment],
            ciphertext_hashes: vec![ciphertext_hash],
            balance_slot_asset_ids,
            fee,
            value_balance: 0,
            stablecoin: stablecoin.clone(),
        };
        let intended_binding_hash = StarkVerifier::compute_binding_hash(&intended).data;
        let alias_bytes = test_repartitioned_transfer_proof_alias(
            anchor,
            nullifier,
            commitment,
            ciphertext_hash,
            balance_slot_asset_ids,
            fee,
            stablecoin,
            binding,
        );
        assert!(
            !native_tx_leaf_artifact_binding_hash_matches_key(intended_binding_hash, &alias_bytes),
            "length-tagged binding hash must reject repartitioned tx-leaf public fields"
        );
        (intended_binding_hash, alias_bytes)
    }

    #[test]
    fn canonical_state_reload_accepts_contiguous_commitments() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db.open_tree("commitments").expect("commitment tree");
        let first = [1u8; 48];
        let second = [2u8; 48];
        tree.insert(0u64.to_be_bytes(), first.as_slice())
            .expect("insert first commitment");
        tree.insert(1u64.to_be_bytes(), second.as_slice())
            .expect("insert second commitment");
        let expected = CommitmentTreeState::from_leaves(
            COMMITMENT_TREE_DEPTH,
            consensus::DEFAULT_ROOT_HISTORY_LIMIT,
            vec![first, second],
        )
        .expect("expected commitment tree");

        let loaded = load_commitment_tree(&tree).expect("load commitment tree");

        assert_eq!(loaded.leaf_count(), 2);
        assert_eq!(loaded.root(), expected.root());
    }

    #[test]
    fn canonical_state_reload_rejects_malformed_commitment_key() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db.open_tree("commitments").expect("commitment tree");
        tree.insert(b"bad-key", [1u8; 48].as_slice())
            .expect("insert malformed commitment key");

        let err =
            load_commitment_tree(&tree).expect_err("malformed commitment key must fail reload");

        assert!(err
            .to_string()
            .contains("stored commitment key has invalid length"));
    }

    #[test]
    fn canonical_state_reload_rejects_malformed_commitment_value() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db.open_tree("commitments").expect("commitment tree");
        tree.insert(0u64.to_be_bytes(), [1u8; 47].as_slice())
            .expect("insert malformed commitment value");

        let err =
            load_commitment_tree(&tree).expect_err("malformed commitment value must fail reload");

        assert!(err
            .to_string()
            .contains("stored commitment value has invalid length"));
    }

    #[test]
    fn canonical_state_reload_rejects_commitment_index_gap() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db.open_tree("commitments").expect("commitment tree");
        tree.insert(1u64.to_be_bytes(), [1u8; 48].as_slice())
            .expect("insert commitment at nonzero index");

        let err = load_commitment_tree(&tree).expect_err("commitment index gap must fail reload");

        assert!(err
            .to_string()
            .contains("stored commitment index is not contiguous"));
    }

    #[test]
    fn canonical_state_reload_rejects_commitment_root_mismatch_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        node.commitment_tree
            .insert(0u64.to_be_bytes(), [3u8; 48].as_slice())
            .expect("insert forged commitment");
        node.commitment_tree.flush().expect("flush commitment tree");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("commitment root mismatch must fail startup"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("stored commitment tree root mismatch"));
    }

    #[test]
    fn canonical_state_reload_rejects_malformed_nullifier_key_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        node.nullifier_tree
            .insert(b"bad-nullifier-key".as_slice(), b"1")
            .expect("insert malformed nullifier key");
        node.nullifier_tree.flush().expect("flush nullifier tree");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("malformed nullifier key must fail startup"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("stored nullifier key has invalid length"));
    }

    #[test]
    fn canonical_state_reload_rejects_invalid_nullifier_marker_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        node.nullifier_tree
            .insert([5u8; 48].as_slice(), b"bad")
            .expect("insert invalid nullifier marker");
        node.nullifier_tree.flush().expect("flush nullifier tree");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("invalid nullifier marker must fail startup"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("stored nullifier marker is invalid"));
    }

    #[test]
    fn canonical_state_reload_rejects_nullifier_root_mismatch_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        node.nullifier_tree
            .insert([4u8; 48].as_slice(), b"1")
            .expect("insert forged nullifier");
        node.nullifier_tree.flush().expect("flush nullifier tree");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("nullifier root mismatch must fail startup"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("stored nullifier root mismatch"));
    }

    #[test]
    fn block_index_reload_rejects_missing_best_block_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        let best = node.best_meta();
        node.block_tree
            .remove(best.hash.as_slice())
            .expect("remove best block record");
        node.block_tree.flush().expect("flush block tree");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("missing best block record must fail startup"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("missing native block"));
    }

    #[test]
    fn block_index_reload_rejects_best_metadata_mismatch_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        let mut forged_best = node.best_meta();
        forged_best.timestamp_ms = forged_best.timestamp_ms.saturating_add(1);
        node.meta_tree
            .insert(
                META_BEST_KEY,
                bincode::serialize(&forged_best)
                    .expect("serialize forged best")
                    .as_slice(),
            )
            .expect("insert forged best metadata");
        node.meta_tree.flush().expect("flush meta tree");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("best metadata drift must fail startup"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("stored best metadata mismatch"));
    }

    #[test]
    fn block_index_reload_rejects_height_hash_mismatch_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        node.height_tree
            .insert(height_key(0), [7u8; 32].as_slice())
            .expect("insert forged height hash");
        node.height_tree.flush().expect("flush height tree");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("height hash mismatch must fail startup"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("stored canonical height hash mismatch"));
    }

    #[test]
    fn block_index_reload_rejects_extra_height_index_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        node.height_tree
            .insert(height_key(1), [8u8; 32].as_slice())
            .expect("insert extra height index");
        node.height_tree.flush().expect("flush height tree");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("extra height index must fail startup"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("stored extra canonical height index"));
    }

    #[test]
    fn block_index_reload_rejects_malformed_height_key_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        node.height_tree
            .insert(b"bad-key", [9u8; 32].as_slice())
            .expect("insert malformed height key");
        node.height_tree.flush().expect("flush height tree");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("malformed height key must fail startup"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("stored canonical height key has invalid length"));
    }

    #[test]
    fn block_index_reload_rejects_non_contiguous_parent_height_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), pow_bits, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        let genesis = node.best_meta();
        let mut child = mined_empty_child(&genesis, 1, pow_bits, 0);
        child.height = 2;
        persist_block(&node.meta_tree, &node.height_tree, &node.block_tree, &child)
            .expect("persist non-contiguous child");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("non-contiguous canonical height must fail startup"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("stored canonical block height mismatch"));
    }

    #[test]
    fn block_index_reload_repairs_missing_genesis_marker_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), pow_bits, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        node.meta_tree
            .remove(META_GENESIS_KEY)
            .expect("remove genesis marker");
        node.meta_tree.flush().expect("flush meta tree");
        drop(node);

        let reopened = NativeNode::open(config).expect("missing genesis marker should repair");
        let expected = genesis_meta(pow_bits).expect("genesis");
        let marker = reopened
            .meta_tree
            .get(META_GENESIS_KEY)
            .expect("read genesis marker")
            .expect("genesis marker restored");

        assert_eq!(marker.as_ref(), expected.hash.as_slice());
    }

    #[test]
    fn block_index_reload_rejects_short_genesis_marker_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), pow_bits, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        node.meta_tree
            .insert(META_GENESIS_KEY, [1u8; 31].as_slice())
            .expect("insert short genesis marker");
        node.meta_tree.flush().expect("flush meta tree");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("short genesis marker must fail startup"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("stored native genesis marker has invalid length"));
    }

    #[test]
    fn block_index_reload_rejects_genesis_marker_mismatch_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), pow_bits, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        node.meta_tree
            .insert(META_GENESIS_KEY, [2u8; 32].as_slice())
            .expect("insert mismatched genesis marker");
        node.meta_tree.flush().expect("flush meta tree");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("mismatched genesis marker must fail startup"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("stored native genesis marker mismatch"));
    }

    #[test]
    fn bridge_replay_reload_rejects_malformed_key_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        node.bridge_inbound_tree
            .insert(b"bad-key", b"1")
            .expect("insert malformed bridge replay key");
        node.bridge_inbound_tree
            .flush()
            .expect("flush bridge replay tree");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("malformed bridge replay key must fail startup"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("stored bridge replay key has invalid length"));
    }

    #[test]
    fn bridge_replay_reload_rejects_invalid_marker_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        node.bridge_inbound_tree
            .insert([9u8; 48].as_slice(), b"0")
            .expect("insert invalid bridge replay marker");
        node.bridge_inbound_tree
            .flush()
            .expect("flush bridge replay tree");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("invalid bridge replay marker must fail startup"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("stored bridge replay marker is invalid"));
    }

    #[test]
    fn bridge_replay_reload_rejects_extra_consumed_key_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        node.bridge_inbound_tree
            .insert([10u8; 48].as_slice(), b"1")
            .expect("insert extra bridge replay key");
        node.bridge_inbound_tree
            .flush()
            .expect("flush bridge replay tree");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("extra bridge replay key must fail startup"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("stored bridge replay set mismatch"));
        assert!(err.to_string().contains("first_extra"));
    }

    #[test]
    fn bridge_replay_reload_rejects_missing_consumed_key_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), pow_bits, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        let genesis = node.best_meta();
        let action = test_inbound_bridge_action(b"startup replay reload");
        let child = mined_child_with_actions(&genesis, 1, pow_bits, 0, vec![action]);
        persist_block(&node.meta_tree, &node.height_tree, &node.block_tree, &child)
            .expect("persist crafted inbound bridge block");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("missing bridge replay key must fail startup"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("stored bridge replay set mismatch"));
        assert!(err.to_string().contains("first_missing"));
    }

    #[test]
    fn bridge_replay_reload_rejects_duplicate_canonical_replay_key_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), pow_bits, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        let genesis = node.best_meta();
        let action = test_inbound_bridge_action(b"duplicate startup replay reload");
        let first = mined_child_with_actions(&genesis, 1, pow_bits, 0, vec![action.clone()]);
        let second = mined_child_with_actions(&first, 2, pow_bits, 0, vec![action]);
        persist_block(&node.meta_tree, &node.height_tree, &node.block_tree, &first)
            .expect("persist first inbound bridge block");
        persist_block(
            &node.meta_tree,
            &node.height_tree,
            &node.block_tree,
            &second,
        )
        .expect("persist duplicate inbound bridge block");
        drop(node);

        let err = match NativeNode::open(config) {
            Ok(_) => panic!("duplicate canonical bridge replay key must fail startup"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("canonical chain contains duplicate inbound bridge replay key"));
    }

    #[test]
    fn pending_action_startup_drops_unknown_anchor_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), pow_bits, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        let action = test_inline_transfer_action([99u8; 48], [101u8; 48], [102u8; 48], 0);
        persist_pending_action_for_startup(&node, &action);
        drop(node);

        let reopened =
            NativeNode::open(config).expect("unknown-anchor pending action should be quarantined");

        assert!(reopened.state.read().pending_actions.is_empty());
        assert_eq!(reopened.action_tree.len(), 0);
    }

    #[test]
    fn pending_action_startup_drops_duplicate_pending_nullifier_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), pow_bits, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        let anchor = node.state.read().commitment_tree.root();
        let first = test_inline_transfer_action(anchor, [103u8; 48], [104u8; 48], 0);
        let second = test_inline_transfer_action(anchor, [103u8; 48], [105u8; 48], 0);
        persist_pending_action_for_startup(&node, &first);
        persist_pending_action_for_startup(&node, &second);
        drop(node);

        let reopened = NativeNode::open(config)
            .expect("duplicate pending nullifier should quarantine one action");

        assert_eq!(reopened.state.read().pending_actions.len(), 1);
        assert_eq!(reopened.action_tree.len(), 1);
    }

    #[test]
    fn pending_action_startup_drops_disabled_risc0_inbound_bridge_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), pow_bits, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        let action =
            test_disabled_risc0_inbound_bridge_action(b"startup disabled RISC0 inbound bridge");
        persist_pending_action_for_startup(&node, &action);
        drop(node);

        let reopened = NativeNode::open(config)
            .expect("disabled RISC Zero inbound bridge action should be quarantined");

        assert!(reopened.state.read().pending_actions.is_empty());
        assert_eq!(reopened.action_tree.len(), 0);
    }

    #[test]
    fn pending_action_startup_drops_sidecar_transfer_without_reloaded_ciphertext_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), pow_bits, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        let anchor = node.state.read().commitment_tree.root();
        let action = test_sidecar_transfer_action(anchor, [106u8; 48], [107u8; 48], 0);
        persist_pending_action_for_startup(&node, &action);
        drop(node);

        let reopened = NativeNode::open(config)
            .expect("sidecar pending action without ciphertext should be quarantined");

        assert!(reopened.state.read().pending_actions.is_empty());
        assert_eq!(reopened.action_tree.len(), 0);
    }

    #[test]
    fn pending_action_startup_accepts_sidecar_transfer_with_matching_reloaded_ciphertext_on_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let config = test_config(tmp.path(), pow_bits, "safe", false);
        let node = NativeNode::open(config.clone()).expect("node");
        let anchor = node.state.read().commitment_tree.root();
        let action = test_sidecar_transfer_action(anchor, [108u8; 48], [109u8; 48], 0);
        insert_test_sidecar_ciphertext(&node.da_ciphertext_tree, &action);
        persist_pending_action_for_startup(&node, &action);
        drop(node);

        let reopened = NativeNode::open(config)
            .expect("sidecar pending action with reloaded ciphertext should pass startup");
        assert!(reopened
            .state
            .read()
            .pending_actions
            .contains_key(&action.tx_hash));
    }

    #[test]
    fn pending_action_startup_drops_mempool_byte_budget_with_small_limit() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let action = test_outbound_bridge_action(b"startup byte budget");
        let max_bytes = pending_action_mempool_bytes(&action).saturating_sub(1);
        let mut pending_actions = BTreeMap::new();
        pending_actions.insert(action.tx_hash, action);
        let (db, action_tree) = temporary_action_tree_with_pending(&pending_actions);

        let startup = build_validated_startup_state_with_limits(
            &db,
            &action_tree,
            state.best,
            pending_actions,
            state.commitment_tree,
            state.nullifiers,
            state.consumed_bridge_messages,
            state.staged_ciphertexts,
            state.staged_proofs,
            MAX_NATIVE_MEMPOOL_ACTIONS,
            max_bytes,
        )
        .expect("startup pending action byte budget should quarantine over-budget action");

        assert!(startup.pending_actions.is_empty());
        assert_eq!(action_tree.len(), 0);
    }

    #[test]
    fn pending_action_startup_drops_mempool_count_with_small_limit() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let action = test_outbound_bridge_action(b"startup count budget");
        let mut pending_actions = BTreeMap::new();
        pending_actions.insert(action.tx_hash, action);
        let (db, action_tree) = temporary_action_tree_with_pending(&pending_actions);

        let startup = build_validated_startup_state_with_limits(
            &db,
            &action_tree,
            state.best,
            pending_actions,
            state.commitment_tree,
            state.nullifiers,
            state.consumed_bridge_messages,
            state.staged_ciphertexts,
            state.staged_proofs,
            0,
            MAX_NATIVE_MEMPOOL_ACTION_BYTES,
        )
        .expect("startup pending action count budget should quarantine over-count action");

        assert!(startup.pending_actions.is_empty());
        assert_eq!(action_tree.len(), 0);
    }

    #[test]
    fn imported_block_actions_recompute_binding_hash() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_inline_transfer_action(anchor, [3u8; 48], [33u8; 48], 0);
        let mut args = ShieldedTransferInlineArgs::decode(&mut &action.public_args[..])
            .expect("decode test args");
        args.binding_hash = [99u8; 64];
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("mismatched binding hash should fail");
        assert!(err.to_string().contains("binding hash mismatch"));
    }

    #[test]
    fn transfer_action_rejects_inline_proof_binding_hash_mismatch() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_inline_transfer_action(anchor, [30u8; 48], [130u8; 48], 0);
        let mut args = ShieldedTransferInlineArgs::decode(&mut &action.public_args[..])
            .expect("decode test args");
        let (_, wrong_proof) = staged_proof_fixture();
        args.proof = wrong_proof;
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("misbound inline proof must fail transfer payload admission");
        assert!(err.to_string().contains("proof binding hash mismatch"));
    }

    #[test]
    fn transfer_action_rejects_sidecar_proof_binding_hash_mismatch() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_sidecar_transfer_action(anchor, [31u8; 48], [131u8; 48], 0);
        let mut args = ShieldedTransferSidecarArgs::decode(&mut &action.public_args[..])
            .expect("decode test args");
        let (_, wrong_proof) = staged_proof_fixture();
        args.proof = wrong_proof;
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("misbound sidecar proof must fail transfer payload admission");
        assert!(err.to_string().contains("proof binding hash mismatch"));
    }

    #[test]
    fn transfer_action_rejects_inline_repartitioned_tx_leaf_binding_alias() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_inline_transfer_action(anchor, [32u8; 48], [132u8; 48], 0);
        let mut args = ShieldedTransferInlineArgs::decode(&mut &action.public_args[..])
            .expect("decode test args");
        args.proof = test_repartitioned_transfer_proof_alias(
            anchor,
            action.nullifiers[0],
            action.commitments[0],
            action.ciphertext_hashes[0],
            args.balance_slot_asset_ids,
            args.fee,
            args.stablecoin.clone(),
            action.binding,
        );
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("repartitioned inline proof must fail transfer payload admission");
        assert!(err.to_string().contains("proof binding hash mismatch"));
    }

    #[test]
    fn transfer_action_rejects_inline_value_balance_binding_alias() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_inline_transfer_action(anchor, [36u8; 48], [136u8; 48], 0);
        let mut args = ShieldedTransferInlineArgs::decode(&mut &action.public_args[..])
            .expect("decode test args");
        args.proof = test_transfer_proof_artifact_with_value_balance(
            anchor,
            &action.nullifiers,
            &action.commitments,
            &action.ciphertext_hashes,
            args.balance_slot_asset_ids,
            args.fee,
            29,
            args.stablecoin.clone(),
            action.binding,
        );
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("inline proof with aliased value balance must fail payload admission");
        assert!(err.to_string().contains("proof binding hash mismatch"));
    }

    #[test]
    fn transfer_action_rejects_sidecar_repartitioned_tx_leaf_binding_alias() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_sidecar_transfer_action(anchor, [33u8; 48], [133u8; 48], 0);
        let mut args = ShieldedTransferSidecarArgs::decode(&mut &action.public_args[..])
            .expect("decode test args");
        args.proof = test_repartitioned_transfer_proof_alias(
            anchor,
            action.nullifiers[0],
            action.commitments[0],
            action.ciphertext_hashes[0],
            args.balance_slot_asset_ids,
            args.fee,
            args.stablecoin.clone(),
            action.binding,
        );
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("repartitioned sidecar proof must fail transfer payload admission");
        assert!(err.to_string().contains("proof binding hash mismatch"));
    }

    #[test]
    fn transfer_action_rejects_sidecar_value_balance_binding_alias() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_sidecar_transfer_action(anchor, [37u8; 48], [137u8; 48], 0);
        let mut args = ShieldedTransferSidecarArgs::decode(&mut &action.public_args[..])
            .expect("decode test args");
        args.proof = test_transfer_proof_artifact_with_value_balance(
            anchor,
            &action.nullifiers,
            &action.commitments,
            &action.ciphertext_hashes,
            args.balance_slot_asset_ids,
            args.fee,
            29,
            args.stablecoin.clone(),
            action.binding,
        );
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("sidecar proof with aliased value balance must fail payload admission");
        assert!(err.to_string().contains("proof binding hash mismatch"));
    }

    #[test]
    fn transfer_action_rejects_inline_stablecoin_proof_binding_alias() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_inline_transfer_action_with_stablecoin(
            anchor,
            [38u8; 48],
            [138u8; 48],
            0,
            Some(test_stablecoin_policy_binding(10)),
        );
        let mut args = ShieldedTransferInlineArgs::decode(&mut &action.public_args[..])
            .expect("decode test args");
        args.proof = test_transfer_proof_artifact(
            anchor,
            &action.nullifiers,
            &action.commitments,
            &action.ciphertext_hashes,
            args.balance_slot_asset_ids,
            args.fee,
            Some(test_stablecoin_policy_binding(11)),
            action.binding,
        );
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("inline proof with aliased stablecoin payload must fail payload admission");
        assert!(err.to_string().contains("proof binding hash mismatch"));
    }

    #[test]
    fn transfer_action_rejects_sidecar_stablecoin_proof_binding_alias() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_sidecar_transfer_action_with_stablecoin(
            anchor,
            [39u8; 48],
            [139u8; 48],
            0,
            Some(test_stablecoin_policy_binding(10)),
        );
        let mut args = ShieldedTransferSidecarArgs::decode(&mut &action.public_args[..])
            .expect("decode test args");
        args.proof = test_transfer_proof_artifact(
            anchor,
            &action.nullifiers,
            &action.commitments,
            &action.ciphertext_hashes,
            args.balance_slot_asset_ids,
            args.fee,
            Some(test_stablecoin_policy_binding(11)),
            action.binding,
        );
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action]).expect_err(
            "sidecar proof with aliased stablecoin payload must fail payload admission",
        );
        assert!(err.to_string().contains("proof binding hash mismatch"));
    }

    #[test]
    fn transfer_action_accepts_stablecoin_bound_inline_proof() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let action = test_inline_transfer_action_with_stablecoin(
            anchor,
            [34u8; 48],
            [134u8; 48],
            0,
            Some(test_stablecoin_policy_binding(10)),
        );

        validate_block_actions_locked(&state, &[action])
            .expect("stablecoin-bound inline transfer should pass action validation");
    }

    #[test]
    fn block_artifact_binding_rejects_decoded_stablecoin_public_field_mismatch() {
        let anchor = [44u8; 48];
        let action_stablecoin = test_stablecoin_policy_binding(11);
        let decoded_stablecoin = test_stablecoin_policy_binding(12);
        let action = test_inline_transfer_action_with_stablecoin(
            anchor,
            [35u8; 48],
            [135u8; 48],
            3,
            Some(action_stablecoin),
        );
        let args = ShieldedTransferInlineArgs::decode(&mut &action.public_args[..])
            .expect("decode test args");
        let proof = test_transfer_proof_artifact(
            anchor,
            &action.nullifiers,
            &action.commitments,
            &action.ciphertext_hashes,
            args.balance_slot_asset_ids,
            args.fee,
            Some(decoded_stablecoin),
            action.binding,
        );
        let decoded = consensus::backend_interface::decode_native_tx_leaf_artifact_bytes(&proof)
            .expect("decode native tx-leaf artifact");
        let tx = Transaction {
            id: [0u8; 32],
            nullifiers: decoded.tx.nullifiers.clone(),
            commitments: decoded.tx.commitments.clone(),
            balance_tag: decoded.tx.balance_tag,
            version: decoded.tx.version,
            ciphertexts: Vec::new(),
            ciphertext_hashes: decoded.tx.ciphertext_hashes.clone(),
        };
        let input = native_tx_leaf_action_binding_admission_input(&decoded, &action, &tx);

        assert_eq!(
            evaluate_native_tx_leaf_action_binding_admission(input)
                .expect_err("decoded stablecoin payload mismatch must reject")
                .label(),
            "stablecoin_payload_mismatch"
        );
    }

    #[test]
    fn transfer_action_rejects_missing_inline_proof() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_inline_transfer_action(anchor, [34u8; 48], [35u8; 48], 0);
        let mut args = ShieldedTransferInlineArgs::decode(&mut &action.public_args[..])
            .expect("decode test args");
        args.proof.clear();
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("missing inline proof must fail transfer payload admission");
        assert!(err.to_string().contains("missing proof"));
    }

    #[test]
    fn transfer_action_rejects_oversized_inline_proof() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_inline_transfer_action(anchor, [36u8; 48], [37u8; 48], 0);
        let mut args = ShieldedTransferInlineArgs::decode(&mut &action.public_args[..])
            .expect("decode test args");
        args.proof = vec![0x44u8; NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE + 1];
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("oversized inline proof must fail transfer payload admission");
        assert!(err.to_string().contains("proof size"));
    }

    #[test]
    fn transfer_action_rejects_oversized_inline_ciphertext() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_inline_transfer_action(anchor, [38u8; 48], [39u8; 48], 0);
        let mut args = ShieldedTransferInlineArgs::decode(&mut &action.public_args[..])
            .expect("decode test args");
        args.ciphertexts[0].kem_ciphertext =
            vec![0x55u8; protocol_shielded_pool::types::MAX_KEM_CIPHERTEXT_LEN as usize + 1];
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("oversized inline ciphertext must fail transfer payload admission");
        assert!(err.to_string().contains("inline ciphertext size"));
    }

    #[test]
    fn transfer_action_rejects_inline_fee_mismatch() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_inline_transfer_action(anchor, [40u8; 48], [41u8; 48], 7);
        action.fee = 8;
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("action fee must agree with decoded inline payload fee");
        assert!(err.to_string().contains("fee mismatch"));
    }

    #[test]
    fn transfer_state_rejects_unknown_anchor_in_block() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let action = test_inline_transfer_action([99u8; 48], [42u8; 48], [43u8; 48], 0);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("unknown transfer anchor must reject block action");
        assert!(err.to_string().contains("unknown anchor"));
    }

    #[test]
    fn transfer_state_rejects_duplicate_nullifier_in_block() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let first = test_inline_transfer_action(anchor, [44u8; 48], [45u8; 48], 0);
        let second = test_inline_transfer_action(anchor, [44u8; 48], [46u8; 48], 0);
        let mut actions = vec![first, second];
        actions.sort_by_key(action_order_key);

        let err = validate_block_actions_locked(&state, &actions)
            .expect_err("duplicate transfer nullifier must reject block action");
        assert!(err.to_string().contains("duplicate nullifier"));
    }

    #[test]
    fn action_state_effect_rejects_duplicate_before_memory_mutation() {
        let pow_bits = 0x207f_ffff;
        let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let first = test_inline_transfer_action(anchor, [48u8; 48], [49u8; 48], 0);
        let second = test_inline_transfer_action(anchor, [48u8; 48], [50u8; 48], 0);
        let before_leaf_count = state.commitment_tree.leaf_count();
        let before_root = state.commitment_tree.root();
        let before_nullifiers = state.nullifiers.clone();
        let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();

        let err = apply_actions_to_memory(&da_ciphertext_tree, &mut state, &[first, second])
            .expect_err("duplicate nullifier must reject before memory mutation");
        assert!(err.to_string().contains("duplicate_nullifier"));
        assert_eq!(state.commitment_tree.leaf_count(), before_leaf_count);
        assert_eq!(state.commitment_tree.root(), before_root);
        assert_eq!(state.nullifiers, before_nullifiers);
    }

    #[test]
    fn action_state_effect_preview_rejects_duplicate_bridge_replay_before_roots() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let first = test_inbound_bridge_action(b"inbound replay one");
        let second = test_inbound_bridge_action(b"inbound replay two");
        assert_ne!(
            first.tx_hash, second.tx_hash,
            "test actions should differ while sharing the replay key"
        );
        let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();

        let err = preview_pending_roots(&da_ciphertext_tree, &state, &[first, second])
            .expect_err("duplicate bridge replay must reject before root preview");
        assert!(err.to_string().contains("bridge_replay_duplicate"));
    }

    #[test]
    fn action_state_effect_preview_requires_materialized_sidecar_ciphertext() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let transfer = test_sidecar_transfer_action(anchor, [54u8; 48], [55u8; 48], 0);
        let candidate = test_candidate_artifact_action(1, 56);
        let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();

        let err = preview_pending_roots(&da_ciphertext_tree, &state, &[transfer, candidate])
            .expect_err("sidecar preview must materialize DA ciphertexts");

        assert!(
            err.to_string().contains("missing canonical DA ciphertext"),
            "unexpected preview error: {err}"
        );
    }

    #[test]
    fn action_state_effect_memory_replay_requires_materialized_sidecar_ciphertext() {
        let pow_bits = 0x207f_ffff;
        let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let transfer = test_sidecar_transfer_action(anchor, [57u8; 48], [58u8; 48], 0);
        let candidate = test_candidate_artifact_action(1, 59);
        let before_leaf_count = state.commitment_tree.leaf_count();
        let before_root = state.commitment_tree.root();
        let before_nullifiers = state.nullifiers.clone();
        let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();

        let err = apply_actions_to_memory(&da_ciphertext_tree, &mut state, &[transfer, candidate])
            .expect_err("sidecar memory replay must materialize DA ciphertexts");

        assert!(
            err.to_string().contains("missing canonical DA ciphertext"),
            "unexpected memory replay error: {err}"
        );
        assert_eq!(state.commitment_tree.leaf_count(), before_leaf_count);
        assert_eq!(state.commitment_tree.root(), before_root);
        assert_eq!(state.nullifiers, before_nullifiers);
    }

    #[test]
    fn block_replay_refinement_rejects_unmaterialized_sidecar_ciphertext() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let transfer = test_sidecar_transfer_action(anchor, [60u8; 48], [61u8; 48], 0);
        let candidate = test_candidate_artifact_action(1, 62);
        let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();

        let err = evaluate_native_block_replay_refinement_for_actions(
            "test replay",
            &da_ciphertext_tree,
            &state,
            &[transfer, candidate],
            NativeBlockReplayRefinementInput {
                leaf_start: state.commitment_tree.leaf_count(),
                parent_supply: 0,
                height: 1,
                fee_total: 0,
                has_coinbase: false,
                claimed_supply: 0,
                tx_count_matches: true,
                state_root_matches: true,
                kernel_root_matches: true,
                nullifier_root_matches: true,
                extrinsics_root_matches: true,
                message_root_matches: true,
                message_count_matches: true,
                header_mmr_root_matches: true,
                header_mmr_len_matches: true,
            },
        )
        .expect_err("replay refinement must not self-fulfill sidecar ciphertext count");

        assert!(
            err.to_string().contains("missing canonical DA ciphertext"),
            "unexpected replay refinement error: {err}"
        );
    }

    #[test]
    fn block_artifact_binding_rejects_size_mismatched_materialized_sidecar_ciphertext() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut transfer = test_sidecar_transfer_action(anchor, [62u8; 48], [63u8; 48], 0);
        insert_test_sidecar_ciphertext(&node.da_ciphertext_tree, &transfer);
        transfer.ciphertext_sizes[0] = transfer.ciphertext_sizes[0].saturating_add(1);
        let candidate = test_candidate_artifact_action(1, 64);
        let meta = mined_empty_child(&state.best, 1, pow_bits, 0);

        let err =
            verify_native_block_artifacts_locked(&node, &state, &[transfer, candidate], &meta)
                .expect_err("artifact verification must canonicalize sidecar size metadata");

        assert!(
            err.to_string()
                .contains("canonical DA ciphertext size mismatch"),
            "unexpected artifact verification error: {err}"
        );
    }

    #[test]
    fn block_artifact_binding_rejects_hash_mismatched_materialized_sidecar_ciphertext() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let transfer = test_sidecar_transfer_action(anchor, [65u8; 48], [66u8; 48], 0);
        let mut wrong_ciphertext = test_transfer_ciphertext_bytes();
        wrong_ciphertext[0] ^= 0xff;
        node.da_ciphertext_tree
            .insert(transfer.ciphertext_hashes[0].as_slice(), wrong_ciphertext)
            .expect("insert mismatched sidecar ciphertext");
        node.da_ciphertext_tree
            .flush()
            .expect("flush mismatched sidecar ciphertext");
        let candidate = test_candidate_artifact_action(1, 67);
        let meta = mined_empty_child(&state.best, 1, pow_bits, 0);

        let err =
            verify_native_block_artifacts_locked(&node, &state, &[transfer, candidate], &meta)
                .expect_err("artifact verification must canonicalize sidecar hash binding");

        assert!(
            err.to_string()
                .contains("canonical DA ciphertext hash mismatch"),
            "unexpected artifact verification error: {err}"
        );
    }

    #[test]
    fn action_state_effect_preview_drops_consumed_bridge_replay_from_work() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let action = test_inbound_bridge_action(b"already consumed inbound replay");
        let replay_key = bridge_inbound_replay_key_from_action(&action)
            .expect("decode replay key")
            .expect("inbound replay key");
        {
            let mut state = node.state.write();
            state.consumed_bridge_messages.insert(replay_key);
            state.pending_actions.insert(action.tx_hash, action);
        }

        let work = node.prepare_work().expect("prepare native work");
        assert_eq!(work.tx_count, 0);
        assert_eq!(work.extrinsics_root, actions_extrinsics_root(&[]));
        assert_eq!(work.message_count, 0);
        assert_eq!(work.message_root, empty_bridge_message_root());
    }

    #[test]
    fn canonical_index_rebuild_rejects_duplicate_before_sled_mutation() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let commitment_tree = db.open_tree("commitments").expect("commitment tree");
        let nullifier_tree = db.open_tree("nullifiers").expect("nullifier tree");
        let bridge_inbound_tree = db.open_tree("bridge_inbound").expect("bridge inbound tree");
        let ciphertext_index_tree = db
            .open_tree("ciphertext_index")
            .expect("ciphertext index tree");
        let ciphertext_archive_tree = db
            .open_tree("ciphertext_archive")
            .expect("ciphertext archive tree");
        let da_ciphertext_tree = db.open_tree("da_ciphertexts").expect("da ciphertext tree");
        let pow_bits = 0x207f_ffff;
        let genesis = genesis_meta(pow_bits).expect("genesis");
        let anchor = genesis.state_root;
        let first = test_inline_transfer_action(anchor, [52u8; 48], [53u8; 48], 0);
        let second = test_inline_transfer_action(anchor, [52u8; 48], [54u8; 48], 0);
        let mut block = genesis.clone();
        block.height = 1;
        block.tx_count = 2;
        block.action_bytes = vec![first.encode(), second.encode()];

        let err = plan_canonical_index_rebuild(&[genesis, block], &da_ciphertext_tree)
            .expect_err("duplicate nullifier must reject before rebuilding sled indexes");
        assert!(err.to_string().contains("duplicate_nullifier"));
        assert_eq!(
            commitment_tree.len(),
            0,
            "failed rebuild must not partially write commitments"
        );
        assert_eq!(
            nullifier_tree.len(),
            0,
            "failed rebuild must not partially write nullifiers"
        );
        assert_eq!(
            bridge_inbound_tree.len(),
            0,
            "failed rebuild must not partially write bridge replay entries"
        );
        assert_eq!(
            ciphertext_index_tree.len(),
            0,
            "failed rebuild must not partially write ciphertext index entries"
        );
        assert_eq!(
            ciphertext_archive_tree.len(),
            0,
            "failed rebuild must not partially write ciphertext archive entries"
        );
    }

    #[test]
    fn canonical_index_rebuild_rejects_hash_mismatched_materialized_sidecar_ciphertext() {
        let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();
        let pow_bits = 0x207f_ffff;
        let genesis = genesis_meta(pow_bits).expect("genesis");
        let anchor = genesis.state_root;
        let transfer = test_sidecar_transfer_action(anchor, [69u8; 48], [70u8; 48], 0);
        let mut wrong_ciphertext = test_transfer_ciphertext_bytes();
        wrong_ciphertext[0] ^= 0x7f;
        da_ciphertext_tree
            .insert(transfer.ciphertext_hashes[0].as_slice(), wrong_ciphertext)
            .expect("insert mismatched sidecar ciphertext");
        da_ciphertext_tree
            .flush()
            .expect("flush mismatched sidecar ciphertext");
        let mut block = genesis.clone();
        block.height = 1;
        block.tx_count = 1;
        block.action_bytes = vec![transfer.encode()];

        let err = plan_canonical_index_rebuild(&[genesis, block], &da_ciphertext_tree)
            .expect_err("canonical index rebuild must canonicalize sidecar hash binding");

        assert!(
            err.to_string()
                .contains("canonical DA ciphertext hash mismatch"),
            "unexpected canonical rebuild error: {err}"
        );
    }

    #[test]
    fn transfer_state_rejects_zero_commitment_in_block() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let action = test_inline_transfer_action(anchor, [47u8; 48], [0u8; 48], 0);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("zero transfer commitment must reject block action");
        assert!(err.to_string().contains("zero commitment"));
    }

    #[test]
    fn transfer_state_sidecar_requires_staged_ciphertext_in_mempool() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
        let anchor = node.state.read().commitment_tree.root();
        let action = test_sidecar_transfer_action(anchor, [48u8; 48], [49u8; 48], 0);

        let err = node
            .validate_action_state(&action)
            .expect_err("sidecar transfer without staged ciphertext must reject");
        assert!(err.to_string().contains("missing staged ciphertext"));
    }

    #[test]
    fn transfer_state_sidecar_rejects_staged_ciphertext_size_mismatch() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
        let anchor = node.state.read().commitment_tree.root();
        let action = test_sidecar_transfer_action(anchor, [50u8; 48], [51u8; 48], 0);
        {
            let mut state = node.state.write();
            state.staged_ciphertexts.insert(
                hex48(&action.ciphertext_hashes[0]),
                action.ciphertext_sizes[0].saturating_add(1),
            );
        }

        let err = node
            .validate_action_state(&action)
            .expect_err("sidecar transfer with wrong staged size must reject");
        assert!(err.to_string().contains("staged ciphertext size mismatch"));
    }

    #[test]
    fn transfer_state_sidecar_accepts_matching_staged_ciphertext() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
        let anchor = node.state.read().commitment_tree.root();
        let action = test_sidecar_transfer_action(anchor, [52u8; 48], [53u8; 48], 0);
        {
            let mut state = node.state.write();
            state.staged_ciphertexts.insert(
                hex48(&action.ciphertext_hashes[0]),
                action.ciphertext_sizes[0],
            );
        }

        node.validate_action_state(&action)
            .expect("matching staged sidecar ciphertext should pass state admission");
    }

    #[test]
    fn apply_planned_actions_clears_staged_sidecar_markers() {
        let pow_bits = 0x207f_ffff;
        let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let action =
            test_sidecar_transfer_action(state.commitment_tree.root(), [56u8; 48], [57u8; 48], 0);
        state.staged_ciphertexts.insert(
            hex48(&action.ciphertext_hashes[0]),
            action.ciphertext_sizes[0],
        );
        state.pending_actions.insert(action.tx_hash, action.clone());
        let planned = vec![NativePlannedActionEffect {
            commitment_start: state.commitment_tree.leaf_count(),
            ciphertexts: vec![test_transfer_ciphertext_bytes()],
            replay_key: None,
        }];

        apply_planned_actions_to_memory(&mut state, std::slice::from_ref(&action), &planned)
            .expect("apply planned sidecar action");

        assert!(!state.pending_actions.contains_key(&action.tx_hash));
        assert!(!state
            .staged_ciphertexts
            .contains_key(&hex48(&action.ciphertext_hashes[0])));
    }

    #[test]
    fn apply_planned_actions_rejects_plan_length_mismatch() {
        let pow_bits = 0x207f_ffff;
        let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let action = test_inline_transfer_action(anchor, [63u8; 48], [64u8; 48], 0);
        let before_leaf_count = state.commitment_tree.leaf_count();
        let before_root = state.commitment_tree.root();

        let err = apply_planned_actions_to_memory(&mut state, &[action], &[])
            .expect_err("missing plan entry must reject");

        assert!(err.to_string().contains("plan_length_mismatch"));
        assert_eq!(state.commitment_tree.leaf_count(), before_leaf_count);
        assert_eq!(state.commitment_tree.root(), before_root);
    }

    #[test]
    fn apply_planned_actions_rejects_planned_start_mismatch() {
        let pow_bits = 0x207f_ffff;
        let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let action = test_inline_transfer_action(anchor, [65u8; 48], [66u8; 48], 0);
        let before_leaf_count = state.commitment_tree.leaf_count();
        let before_root = state.commitment_tree.root();
        let planned = vec![NativePlannedActionEffect {
            commitment_start: before_leaf_count.saturating_add(1),
            ciphertexts: vec![test_transfer_ciphertext_bytes()],
            replay_key: None,
        }];

        let err = apply_planned_actions_to_memory(&mut state, &[action], &planned)
            .expect_err("wrong planned start must reject");

        assert!(err.to_string().contains("planned_start_mismatch"));
        assert_eq!(state.commitment_tree.leaf_count(), before_leaf_count);
        assert_eq!(state.commitment_tree.root(), before_root);
    }

    #[test]
    fn apply_planned_actions_rejects_ciphertext_hash_projection_mismatch() {
        let pow_bits = 0x207f_ffff;
        let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let action = test_inline_transfer_action(anchor, [67u8; 48], [68u8; 48], 0);
        let before_leaf_count = state.commitment_tree.leaf_count();
        let before_root = state.commitment_tree.root();
        let mut ciphertext = test_transfer_ciphertext_bytes();
        ciphertext[0] ^= 1;
        let planned = vec![NativePlannedActionEffect {
            commitment_start: before_leaf_count,
            ciphertexts: vec![ciphertext],
            replay_key: None,
        }];

        let err = apply_planned_actions_to_memory(&mut state, &[action], &planned)
            .expect_err("planned ciphertext hash drift must reject");

        assert!(err.to_string().contains("ciphertext_hash_mismatch"));
        assert_eq!(state.commitment_tree.leaf_count(), before_leaf_count);
        assert_eq!(state.commitment_tree.root(), before_root);
    }

    #[test]
    fn apply_planned_actions_rejects_replay_key_projection_mismatch() {
        let pow_bits = 0x207f_ffff;
        let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let action = test_inbound_bridge_action(b"wire replay key mismatch");
        let before_leaf_count = state.commitment_tree.leaf_count();
        let before_root = state.commitment_tree.root();
        let planned = vec![NativePlannedActionEffect {
            commitment_start: before_leaf_count,
            ciphertexts: Vec::new(),
            replay_key: Some([99u8; 48]),
        }];

        let err = apply_planned_actions_to_memory(&mut state, &[action], &planned)
            .expect_err("planned replay key drift must reject");

        assert!(err.to_string().contains("replay_key_mismatch"));
        assert_eq!(state.commitment_tree.leaf_count(), before_leaf_count);
        assert_eq!(state.commitment_tree.root(), before_root);
        assert!(state.consumed_bridge_messages.is_empty());
    }

    #[test]
    fn mined_commit_removes_pending_sidecar_ciphertext() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
        let parent = node.best_meta();
        let action = test_sidecar_transfer_action(parent.state_root, [58u8; 48], [59u8; 48], 0);
        insert_test_sidecar_ciphertext(&node.da_ciphertext_tree, &action);
        assert!(node
            .da_ciphertext_tree
            .get(action.ciphertext_hashes[0])
            .expect("read staged sidecar")
            .is_some());
        let mut meta = mined_empty_child(&parent, 1, pow_bits, 0);
        meta.action_bytes = vec![action.encode()];
        meta.tx_count = 1;
        let planned = vec![NativePlannedActionEffect {
            commitment_start: 0,
            ciphertexts: vec![test_transfer_ciphertext_bytes()],
            replay_key: None,
        }];

        node.commit_mined_block_atomically(std::slice::from_ref(&action), &planned, &meta)
            .expect("commit sidecar action");

        assert!(node
            .da_ciphertext_tree
            .get(action.ciphertext_hashes[0])
            .expect("read staged sidecar after commit")
            .is_none());
    }

    #[test]
    fn transfer_action_validation_requires_shielded_family() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_inline_transfer_action(anchor, [5u8; 48], [55u8; 48], 0);
        action.family_id = FAMILY_SHIELDED_POOL.saturating_add(99);
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("non-shielded family must not be accepted as a transfer");
        assert!(err.to_string().contains("not a shielded transfer"));
    }

    #[test]
    fn candidate_artifact_payload_is_candidate_action_scoped() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_inline_transfer_action(anchor, [6u8; 48], [66u8; 48], 0);
        action.candidate_artifact = Some(test_candidate_artifact(1));
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("transfer action must not carry candidate artifact payload");
        assert!(err.to_string().contains("candidate artifact payload"));
    }

    #[test]
    fn candidate_artifact_action_carries_no_state_deltas() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let mut action =
            test_empty_action(FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT, 0);
        action.candidate_artifact = Some(test_candidate_artifact(1));
        action.commitments.push([77u8; 48]);
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("candidate artifact action must not carry commitments");
        assert!(err.to_string().contains("state deltas"));
    }

    #[test]
    fn candidate_artifact_action_requires_payload() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let action = test_empty_action(FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT, 0);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("candidate artifact action must carry a payload");
        assert!(err.to_string().contains("missing payload"));
    }

    #[test]
    fn candidate_artifact_rejects_legacy_recursive_v1_route() {
        let mut artifact = test_candidate_artifact(1);
        artifact.proof_kind = PoolProofArtifactKind::RecursiveBlockV1;

        let err = validate_candidate_artifact(&artifact)
            .expect_err("native candidate artifacts must use the shipped v2 route");
        assert!(err.to_string().contains("recursive_block_v2"));
    }

    #[test]
    fn candidate_artifact_rejects_zero_tx_count() {
        let artifact = test_candidate_artifact(0);

        let err = validate_candidate_artifact(&artifact)
            .expect_err("native candidate artifacts must bind at least one tx");
        assert!(err.to_string().contains("tx_count must be non-zero"));
    }

    #[test]
    fn candidate_artifact_rejects_wrong_verifier_profile() {
        let mut artifact = test_candidate_artifact(1);
        artifact.verifier_profile = [0x77u8; 48];

        let err = validate_candidate_artifact(&artifact)
            .expect_err("native candidate artifacts must bind shipped verifier profile");
        assert!(err.to_string().contains("verifier profile mismatch"));
    }

    #[test]
    fn candidate_artifact_rejects_oversized_recursive_proof() {
        let mut artifact = test_candidate_artifact(1);
        artifact
            .recursive_block
            .as_mut()
            .expect("test recursive payload")
            .proof
            .data = vec![0x42u8; RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE + 1];

        let err = validate_candidate_artifact(&artifact)
            .expect_err("oversized recursive candidate proof must fail admission");
        assert!(err.to_string().contains("recursive proof size"));
    }

    #[test]
    fn candidate_artifact_requires_shielded_transfers() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let mut action =
            test_empty_action(FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT, 0);
        action.candidate_artifact = Some(test_candidate_artifact(1));
        action.tx_hash = pending_action_hash(&action);
        validate_block_actions_locked(&state, &[action.clone()])
            .expect("candidate artifact payload is structurally valid");

        let meta = mined_empty_child(&state.best, 1, pow_bits, 0);
        let err = verify_native_block_artifacts_locked(&node, &state, &[action], &meta)
            .expect_err("candidate artifact without transfers must be rejected");
        assert!(err.to_string().contains("requires shielded transfer"));
    }

    #[test]
    fn shielded_transfer_requires_candidate_artifact() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let transfer =
            test_inline_transfer_action(state.commitment_tree.root(), [7u8; 48], [8u8; 48], 0);
        validate_block_actions_locked(&state, &[transfer.clone()])
            .expect("transfer action is structurally valid");

        let meta = mined_empty_child(&state.best, 1, pow_bits, 0);
        let err = verify_native_block_artifacts_locked(&node, &state, &[transfer], &meta)
            .expect_err("non-empty shielded block without candidate artifact must be rejected");
        assert!(err
            .to_string()
            .contains("requires exactly one matching recursive candidate artifact"));
    }

    #[test]
    fn shielded_transfer_rejects_multiple_candidate_artifacts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let transfer =
            test_inline_transfer_action(state.commitment_tree.root(), [9u8; 48], [10u8; 48], 0);
        let first_candidate = test_candidate_artifact_action(1, 21);
        let second_candidate = test_candidate_artifact_action(1, 22);
        let actions = vec![transfer, first_candidate, second_candidate];
        validate_block_actions_locked(&state, &actions)
            .expect("multiple candidate artifacts are structurally valid before coupling");

        let meta = mined_empty_child(&state.best, 1, pow_bits, 0);
        let err = verify_native_block_artifacts_locked(&node, &state, &actions, &meta)
            .expect_err("non-empty shielded block with multiple candidates must be rejected");
        assert!(err
            .to_string()
            .contains("requires exactly one matching recursive candidate artifact"));
    }

    #[test]
    fn shielded_transfer_rejects_candidate_tx_count_mismatch() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let transfer =
            test_inline_transfer_action(state.commitment_tree.root(), [11u8; 48], [12u8; 48], 0);
        let candidate = test_candidate_artifact_action(2, 23);
        let actions = vec![transfer, candidate];
        validate_block_actions_locked(&state, &actions)
            .expect("mismatched candidate artifact is structurally valid before coupling");

        let meta = mined_empty_child(&state.best, 1, pow_bits, 0);
        let err = verify_native_block_artifacts_locked(&node, &state, &actions, &meta)
            .expect_err("candidate artifact tx_count mismatch must be rejected");
        assert!(err.to_string().contains("tx_count mismatch"));
    }

    #[test]
    fn recursive_artifact_context_rejects_height_overflow() {
        let err = evaluate_native_recursive_artifact_context_admission(
            NativeRecursiveArtifactContextAdmissionInput {
                best_height: u64::MAX,
            },
        )
        .expect_err("max-height best state must not emit a recursive artifact context height");

        assert_eq!(
            err,
            NativeRecursiveArtifactContextAdmissionRejection::HeightNotNext
        );
    }

    #[test]
    fn prepare_work_ignores_candidate_artifact_without_transfers() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let mut action =
            test_empty_action(FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT, 0);
        action.candidate_artifact = Some(test_candidate_artifact(1));
        action.tx_hash = pending_action_hash(&action);
        node.state
            .write()
            .pending_actions
            .insert(action.tx_hash, action);

        let work = node.prepare_work().expect("prepare native work");

        assert_eq!(work.tx_count, 0);
        assert_eq!(work.extrinsics_root, actions_extrinsics_root(&[]));
    }

    #[test]
    fn prepare_work_drops_sidecar_transfer_without_staged_ciphertext() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let anchor = node.state.read().commitment_tree.root();
        let transfer = test_sidecar_transfer_action(anchor, [24u8; 48], [25u8; 48], 0);
        let candidate = test_candidate_artifact_action(1, 26);
        {
            let mut state = node.state.write();
            state.pending_actions.insert(transfer.tx_hash, transfer);
            state.pending_actions.insert(candidate.tx_hash, candidate);
        }

        let work = node.prepare_work().expect("prepare native work");

        assert_eq!(work.tx_count, 0);
        assert_eq!(work.extrinsics_root, actions_extrinsics_root(&[]));
    }

    #[test]
    fn prepare_work_drops_sidecar_transfer_with_staged_size_mismatch() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let anchor = node.state.read().commitment_tree.root();
        let transfer = test_sidecar_transfer_action(anchor, [27u8; 48], [28u8; 48], 0);
        let hash = transfer.ciphertext_hashes[0];
        let mismatched_size = transfer.ciphertext_sizes[0].saturating_add(1);
        let candidate = test_candidate_artifact_action(1, 29);
        {
            let mut state = node.state.write();
            state
                .staged_ciphertexts
                .insert(hex48(&hash), mismatched_size);
            state.pending_actions.insert(transfer.tx_hash, transfer);
            state.pending_actions.insert(candidate.tx_hash, candidate);
        }

        let work = node.prepare_work().expect("prepare native work");

        assert_eq!(work.tx_count, 0);
        assert_eq!(work.extrinsics_root, actions_extrinsics_root(&[]));
    }

    #[test]
    fn prepare_work_keeps_sidecar_transfer_with_matching_staged_ciphertext() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let anchor = node.state.read().commitment_tree.root();
        let transfer = test_sidecar_transfer_action(anchor, [30u8; 48], [31u8; 48], 0);
        let hash = transfer.ciphertext_hashes[0];
        let size = transfer.ciphertext_sizes[0];
        let candidate = test_candidate_artifact_action(1, 32);
        insert_test_sidecar_ciphertext(&node.da_ciphertext_tree, &transfer);
        {
            let mut state = node.state.write();
            state.staged_ciphertexts.insert(hex48(&hash), size);
            state.pending_actions.insert(transfer.tx_hash, transfer);
            state.pending_actions.insert(candidate.tx_hash, candidate);
        }

        let work = node.prepare_work().expect("prepare native work");

        assert_eq!(work.tx_count, 2);
    }

    #[test]
    fn coinbase_action_carries_no_extra_state_deltas() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
        stage_test_coinbase(&node, consensus::reward::block_subsidy(1), [88u8; 48]);
        let mut action = node
            .state
            .read()
            .pending_actions
            .values()
            .next()
            .cloned()
            .expect("pending coinbase");
        action.nullifiers.push([89u8; 48]);
        action.tx_hash = pending_action_hash(&action);
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("coinbase action must not carry nullifiers");
        assert!(err.to_string().contains("no other state deltas"));
    }

    #[test]
    fn coinbase_action_rejects_zero_or_semantically_mismatched_commitment() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let subsidy = consensus::reward::block_subsidy(1);
        let mut action = test_coinbase_action(subsidy);
        let mut args: MintCoinbaseArgs =
            decode_scale_exact(&action.public_args, "coinbase action args")
                .expect("decode test coinbase args");
        args.reward_bundle.miner_note.commitment = [0u8; 48];
        action.commitments[0] = [0u8; 48];
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("zero coinbase commitment must reject");
        assert!(err.to_string().contains("coinbase commitment mismatch"));
    }

    #[test]
    fn coinbase_action_rejects_public_seed_commitment_mismatch() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let subsidy = consensus::reward::block_subsidy(1);
        let mut action = test_coinbase_action(subsidy);
        let mut args: MintCoinbaseArgs =
            decode_scale_exact(&action.public_args, "coinbase action args")
                .expect("decode test coinbase args");
        args.reward_bundle.miner_note.public_seed[0] ^= 1;
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("coinbase public seed tamper must reject");
        assert!(err.to_string().contains("coinbase commitment mismatch"));
    }

    #[test]
    fn coinbase_action_rejects_ciphertext_hash_mismatch() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let subsidy = consensus::reward::block_subsidy(1);
        let mut action = test_coinbase_action(subsidy);
        action.ciphertext_hashes[0][0] ^= 1;
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("coinbase ciphertext hash mismatch must reject");
        assert!(err.to_string().contains("ciphertext hash mismatch"));
    }

    #[test]
    fn coinbase_action_rejects_ciphertext_size_mismatch() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let subsidy = consensus::reward::block_subsidy(1);
        let mut action = test_coinbase_action(subsidy);
        action.ciphertext_sizes[0] = action.ciphertext_sizes[0].saturating_add(1);
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("coinbase ciphertext size mismatch must reject");
        assert!(err.to_string().contains("ciphertext size mismatch"));
    }

    #[test]
    fn coinbase_action_rejects_oversized_ciphertext() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let subsidy = consensus::reward::block_subsidy(1);
        let mut action = test_coinbase_action(subsidy);
        let mut args: MintCoinbaseArgs =
            decode_scale_exact(&action.public_args, "coinbase action args")
                .expect("decode test coinbase args");
        args.reward_bundle.miner_note.encrypted_note.kem_ciphertext =
            vec![0x55u8; MAX_CIPHERTEXT_BYTES + 1];
        let total_len = args
            .reward_bundle
            .miner_note
            .encrypted_note
            .ciphertext
            .len()
            .saturating_add(
                args.reward_bundle
                    .miner_note
                    .encrypted_note
                    .kem_ciphertext
                    .len(),
            );
        action.public_args = args.encode();
        action.ciphertext_hashes[0] = NATIVE_EMPTY_DIGEST48;
        action.ciphertext_sizes[0] = u32::try_from(total_len).unwrap_or(u32::MAX);
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("oversized coinbase ciphertext must reject");
        assert!(err.to_string().contains("coinbase ciphertext size"));
        assert!(err.to_string().contains("exceeds limit"));
    }

    #[test]
    fn transfer_action_requires_ciphertext_metadata_shape() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let anchor = state.commitment_tree.root();
        let mut action = test_inline_transfer_action(anchor, [91u8; 48], [92u8; 48], 0);
        action.ciphertext_sizes.clear();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("transfer action metadata shape must match commitments");
        assert!(err.to_string().contains("invalid public metadata shape"));
    }

    #[test]
    fn bridge_action_carries_no_state_deltas() {
        let pow_bits = 0x207f_ffff;
        let state = test_state(genesis_meta(pow_bits).expect("genesis"));
        let mut action = test_outbound_bridge_action(b"bridge fee smuggle");
        action.fee = 1;
        action.anchor = [90u8; 48];
        action.tx_hash = pending_action_hash(&action);

        let err = validate_block_actions_locked(&state, &[action])
            .expect_err("bridge action must not carry fee or anchor deltas");
        assert!(err.to_string().contains("state deltas"));
    }

    #[test]
    fn bridge_outbound_payload_must_be_non_empty() {
        let action = test_outbound_bridge_action(b"");

        let err = validate_bridge_action_payload(&action)
            .expect_err("empty outbound bridge payload must be rejected");
        assert!(err.to_string().contains("payload must be non-empty"));
    }

    #[test]
    fn bridge_inbound_proof_receipt_must_be_non_empty() {
        let mut action = test_inbound_bridge_action(b"inbound payload");
        let mut args = InboundBridgeArgsV1::decode(&mut &action.public_args[..])
            .expect("decode inbound bridge test args");
        args.proof_receipt.clear();
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_bridge_action_payload(&action)
            .expect_err("empty inbound bridge receipt must be rejected before receipt decode");
        assert!(err.to_string().contains("proof receipt must be non-empty"));
    }

    #[test]
    fn bridge_inbound_replay_key_must_match_message() {
        let mut action = test_inbound_bridge_action(b"inbound payload");
        let mut args = InboundBridgeArgsV1::decode(&mut &action.public_args[..])
            .expect("decode inbound bridge test args");
        args.source_message_nonce = args.source_message_nonce.saturating_add(1);
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_bridge_action_payload(&action).expect_err(
            "inbound bridge replay key mismatch must be rejected before receipt verify",
        );
        assert!(err.to_string().contains("replay key does not match"));
    }

    #[test]
    fn bridge_inbound_destination_must_be_hegemon() {
        let mut action = test_inbound_bridge_action(b"inbound payload");
        let mut args = InboundBridgeArgsV1::decode(&mut &action.public_args[..])
            .expect("decode inbound bridge test args");
        args.message.destination_chain_id = [19u8; 32];
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_bridge_action_payload(&action)
            .expect_err("wrong inbound bridge destination must be rejected before receipt verify");
        assert!(err.to_string().contains("not addressed to Hegemon"));
    }

    #[test]
    fn bridge_inbound_payload_hash_must_match_payload() {
        let mut action = test_inbound_bridge_action(b"inbound payload");
        let mut args = InboundBridgeArgsV1::decode(&mut &action.public_args[..])
            .expect("decode inbound bridge test args");
        args.message.payload_hash = [29u8; 48];
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(&action);

        let err = validate_bridge_action_payload(&action)
            .expect_err("wrong inbound bridge payload hash must be rejected before receipt verify");
        assert!(err.to_string().contains("payload hash mismatch"));
    }

    #[test]
    fn submit_action_routes_bridge_payload_admission_before_staging() {
        use base64::Engine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
        let outbound = OutboundBridgeArgsV1 {
            destination_chain_id: [41u8; 32],
            app_family_id: 77,
            payload: Vec::new(),
        };
        let err = node
            .validate_and_stage_action(json!({
                "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
                "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
                "family_id": FAMILY_BRIDGE,
                "action_id": ACTION_BRIDGE_OUTBOUND,
                "new_nullifiers": [],
                "public_args": base64::engine::general_purpose::STANDARD.encode(outbound.encode()),
            }))
            .expect_err("empty outbound bridge payload must reject before staging");
        assert!(err.to_string().contains("payload must be non-empty"));
        assert_eq!(node.state.read().pending_actions.len(), 0);

        let mut inbound = test_disabled_risc0_bridge_inbound_args(b"bound bridge payload");
        inbound.proof_receipt.clear();
        let err = node
            .validate_and_stage_action(json!({
                "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
                "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
                "family_id": FAMILY_BRIDGE,
                "action_id": ACTION_BRIDGE_INBOUND,
                "new_nullifiers": [],
                "public_args": base64::engine::general_purpose::STANDARD.encode(inbound.encode()),
            }))
            .expect_err("empty inbound bridge receipt must reject before staging");
        assert!(err.to_string().contains("proof receipt must be non-empty"));
        assert_eq!(node.state.read().pending_actions.len(), 0);
    }

    #[test]
    fn bridge_messages_reject_malformed_outbound_payload() {
        let bad = malformed_outbound_bridge_action(b"malformed bridge message");
        let good = test_outbound_bridge_action(b"good bridge message after malformed one");

        let err = bridge_messages_from_actions(&[bad, good], 1)
            .expect_err("malformed outbound bridge args must reject");

        assert!(err.to_string().contains("outbound bridge action args"));
    }

    #[test]
    fn prepare_work_rejects_malformed_outbound_bridge_message() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let action = malformed_outbound_bridge_action(b"bad message-root payload");
        node.state
            .write()
            .pending_actions
            .insert(action.tx_hash, action);

        let err = node
            .prepare_work()
            .expect_err("malformed outbound bridge payload must block template construction");

        assert!(err.to_string().contains("outbound bridge action args"));
        assert_eq!(node.best_meta().height, 0);
    }

    #[test]
    fn announced_block_rejects_malformed_outbound_payload_before_message_commitment() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let parent = node.best_meta();
        let malformed = malformed_outbound_bridge_action(b"bad announced bridge payload");
        let parent_state = test_state(parent.clone());
        let (state_root, nullifier_root, extrinsics_root, tx_count) = preview_pending_roots(
            &node.da_ciphertext_tree,
            &parent_state,
            std::slice::from_ref(&malformed),
        )
        .expect("preview malformed action roots");
        let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
        let header_history = node
            .header_hashes_to_hash(parent.hash)
            .expect("header history");
        let header_mmr_root = header_mmr_root_from_hashes(&header_history);
        let header_mmr_len = header_history.len() as u64;
        let cumulative_work =
            cumulative_work_after(&parent.cumulative_work, pow_bits).expect("work");
        let height = parent.height.saturating_add(1);
        let timestamp_ms = parent.timestamp_ms.saturating_add(1);
        let message_root = empty_bridge_message_root();
        let message_count = 1;
        let pre_header = native_pow_header_from_parts(
            height,
            timestamp_ms,
            parent.hash,
            pow_bits,
            [0u8; 32],
            cumulative_work,
            &state_root,
            &kernel_root,
            &nullifier_root,
            &extrinsics_root,
            &message_root,
            message_count,
            &header_mmr_root,
            header_mmr_len,
            parent.supply_digest,
            tx_count,
        );
        let work = NativeWork {
            height,
            parent_hash: parent.hash,
            pre_hash: pre_header.pre_hash(),
            state_root,
            kernel_root,
            nullifier_root,
            extrinsics_root,
            message_root,
            message_count,
            header_mmr_root,
            header_mmr_len,
            cumulative_work,
            supply_digest: parent.supply_digest,
            tx_count,
            timestamp_ms,
            pow_bits,
        };
        let seal = mine_native_round(work, 0).expect("malformed announced bridge seal");
        let meta = signed_test_block_meta(NativeBlockMeta {
            chain_id: HEGEMON_CHAIN_ID_V1,
            rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
            height,
            hash: seal.work_hash,
            parent_hash: parent.hash,
            state_root,
            kernel_root,
            nullifier_root,
            extrinsics_root,
            message_root,
            message_count,
            header_mmr_root,
            header_mmr_len,
            timestamp_ms,
            pow_bits,
            nonce: seal.nonce,
            work_hash: seal.work_hash,
            cumulative_work,
            supply_digest: parent.supply_digest,
            tx_count,
            action_bytes: vec![malformed.encode()],
            miner_commitment: [0u8; 48],
            miner_public_key: Vec::new(),
            miner_signature: Vec::new(),
        });

        let err = node
            .import_announced_block(meta)
            .expect_err("malformed outbound payload must reject before message count mismatch");

        assert!(err.to_string().contains("outbound bridge action args"));
        assert_eq!(node.best_meta().height, 0);
    }

    #[test]
    fn prepare_work_drops_actions_after_preview_failure() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
        let anchor = node.state.read().commitment_tree.root();
        let transfer = test_inline_transfer_action(anchor, [4u8; 48], [44u8; 48], 0);
        let bridge = test_outbound_bridge_action(b"phantom bridge message");
        {
            let mut state = node.state.write();
            state.pending_actions.insert(transfer.tx_hash, transfer);
            state.pending_actions.insert(bridge.tx_hash, bridge);
        }

        let work = node.prepare_work().expect("prepare native work");
        assert_eq!(work.tx_count, 0);
        assert_eq!(work.extrinsics_root, actions_extrinsics_root(&[]));
        assert_eq!(work.message_count, 0);
        assert_eq!(work.message_root, empty_bridge_message_root());
    }

    #[test]
    fn mined_empty_block_rejects_phantom_bridge_message_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let parent = node.best_meta();
        let state_root = parent.state_root;
        let kernel_root = parent.kernel_root;
        let nullifier_root = parent.nullifier_root;
        let extrinsics_root = actions_extrinsics_root(&[]);
        let bridge = test_outbound_bridge_action(b"message without action bytes");
        let bridge_messages = bridge_messages_from_actions(&[bridge], 1).expect("bridge messages");
        let message_root = bridge_message_root(&bridge_messages);
        let message_count = u32::try_from(bridge_messages.len()).expect("message count");
        assert_ne!(message_root, empty_bridge_message_root());
        let header_history = node
            .header_hashes_to_hash(parent.hash)
            .expect("header history");
        let header_mmr_root = header_mmr_root_from_hashes(&header_history);
        let header_mmr_len = header_history.len() as u64;
        let cumulative_work =
            cumulative_work_after(&parent.cumulative_work, pow_bits).expect("cumulative work");
        let pre_header = native_pow_header_from_parts(
            1,
            parent.timestamp_ms.saturating_add(1),
            parent.hash,
            pow_bits,
            [0u8; 32],
            cumulative_work,
            &state_root,
            &kernel_root,
            &nullifier_root,
            &extrinsics_root,
            &message_root,
            message_count,
            &header_mmr_root,
            header_mmr_len,
            parent.supply_digest,
            0,
        );
        let work = NativeWork {
            height: 1,
            parent_hash: parent.hash,
            pre_hash: pre_header.pre_hash(),
            state_root,
            kernel_root,
            nullifier_root,
            extrinsics_root,
            message_root,
            message_count,
            header_mmr_root,
            header_mmr_len,
            cumulative_work,
            supply_digest: parent.supply_digest,
            tx_count: 0,
            timestamp_ms: parent.timestamp_ms.saturating_add(1),
            pow_bits,
        };
        let seal = mine_native_round(work.clone(), 0).expect("phantom bridge seal");

        let imported = node
            .import_mined_block(&work, seal)
            .expect("phantom bridge work should be stale");
        assert!(imported.is_none());
        assert_eq!(node.best_meta().height, 0);
    }

    #[test]
    fn bridge_outbound_message_root_and_witness_are_exported() {
        use base64::Engine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
        let args = OutboundBridgeArgsV1 {
            destination_chain_id: [41u8; 32],
            app_family_id: 77,
            payload: b"bridge payload".to_vec(),
        };
        node.validate_and_stage_action(json!({
            "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            "family_id": FAMILY_BRIDGE,
            "action_id": ACTION_BRIDGE_OUTBOUND,
            "new_nullifiers": [],
            "public_args": base64::engine::general_purpose::STANDARD.encode(args.encode()),
        }))
        .expect("stage outbound bridge message");

        let work = node.prepare_work().expect("prepare native work");
        assert_eq!(work.message_count, 1);
        assert_ne!(work.message_root, empty_bridge_message_root());
        let seal = mine_native_round(work.clone(), 0).expect("bridge seal");
        let imported = node
            .import_mined_block(&work, seal)
            .expect("bridge import")
            .expect("bridge block");
        assert_eq!(imported.message_count, 1);
        assert_eq!(imported.message_root, work.message_root);

        let actions = decode_block_actions(&imported).expect("decode block actions");
        let messages =
            bridge_messages_from_actions(&actions, imported.height).expect("bridge messages");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].source_chain_id, HEGEMON_CHAIN_ID_V1);
        assert_eq!(messages[0].message_nonce, 1u128 << 64);
        assert_eq!(bridge_message_root(&messages), imported.message_root);

        let witness = export_bridge_witness(&node, json!([hex32(&imported.hash), 0]))
            .expect("export bridge witness");
        assert_eq!(witness["schema"], json!("hegemon.bridge-witness.v1"));
        assert_eq!(
            witness["output"]["message_root"],
            json!(hex48(&imported.message_root))
        );
        assert_eq!(witness["output"]["confirmations_checked"], json!(1));
        assert_eq!(
            witness["output"]["message_hash"],
            witness["messages"][0]["message_hash"]
        );
        assert!(witness["canonical"]["header"]
            .as_str()
            .expect("canonical header hex")
            .starts_with("0x"));
        assert!(witness["canonical"]["output"]
            .as_str()
            .expect("canonical output hex")
            .starts_with("0x"));
    }

    fn node_with_exportable_bridge_block(
        payload: &[u8],
    ) -> (tempfile::TempDir, Arc<NativeNode>, NativeBlockMeta) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
        let action = test_outbound_bridge_action(payload);
        node.state
            .write()
            .pending_actions
            .insert(action.tx_hash, action);
        let work = node.prepare_work().expect("prepare native work");
        let seal = mine_native_round(work.clone(), 0).expect("bridge seal");
        let imported = node
            .import_mined_block(&work, seal)
            .expect("bridge import")
            .expect("bridge block");
        assert_eq!(imported.message_count, 1);
        (tmp, node, imported)
    }

    #[test]
    fn bridge_witness_rejects_noncanonical_block_hash() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pow_bits = 0x207f_ffff;
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
        let genesis = node.best_meta();
        let side_action = test_outbound_bridge_action(b"side branch bridge payload");
        let side = mined_child_with_actions(&genesis, 1, pow_bits, 0, vec![side_action]);
        node.import_announced_block(side.clone())
            .expect("side bridge block import");
        assert_eq!(node.best_meta().hash, side.hash);

        let canonical = (1..=256)
            .find_map(|round| {
                let candidate = mined_empty_child(&genesis, 1, pow_bits, round);
                if candidate.hash < side.hash {
                    Some(candidate)
                } else {
                    None
                }
            })
            .expect("find better same-height canonical block");
        assert!(node
            .import_announced_block(canonical.clone())
            .expect("canonical reorg import"));
        assert_eq!(node.best_meta().hash, canonical.hash);

        let err = export_bridge_witness(&node, json!([hex32(&side.hash), 0]))
            .expect_err("side-branch bridge witness must be rejected");
        assert!(err.to_string().contains("is not canonical"));
    }

    #[test]
    fn bridge_witness_rejects_malformed_explicit_block_hash() {
        let (_tmp, node, _imported) =
            node_with_exportable_bridge_block(b"malformed hash should not backscan");

        let err = export_bridge_witness(&node, json!(["0x1234", 0]))
            .expect_err("malformed explicit hash must not fall back to latest witness");

        assert!(err
            .to_string()
            .contains("malformed bridge witness block hash"));
    }

    #[test]
    fn bridge_witness_rejects_unknown_explicit_block_hash() {
        let (_tmp, node, _imported) =
            node_with_exportable_bridge_block(b"unknown bridge witness hash");

        let err = export_bridge_witness(&node, json!([hex32(&[0xabu8; 32]), 0]))
            .expect_err("unknown explicit hash must be rejected");

        assert!(err.to_string().contains("unknown bridge witness block"));
    }

    #[test]
    fn bridge_witness_rejects_missing_canonical_height_index() {
        let (_tmp, node, imported) =
            node_with_exportable_bridge_block(b"missing canonical height index");
        node.height_tree
            .remove(height_key(imported.height))
            .expect("remove height index");
        node.height_tree.flush().expect("flush height tree");

        let err = export_bridge_witness(&node, json!([hex32(&imported.hash), 0]))
            .expect_err("missing canonical height index must reject witness export");

        assert!(err.to_string().contains("missing canonical block"));
    }

    #[test]
    fn native_metadata_projection_rejects_unsigned_bridge_witness() {
        let (_tmp, node, imported) =
            node_with_exportable_bridge_block(b"unsigned bridge witness metadata");
        let unsigned = unsigned_native_meta(imported.clone());
        persist_block_record(&node.block_tree, &unsigned)
            .expect("replace bridge block with unsigned metadata");

        let err = export_bridge_witness(&node, json!([hex32(&imported.hash), 0]))
            .expect_err("unsigned canonical metadata must not be projected into bridge witness");
        let err = format!("{err:?}");
        assert!(err.contains("invalid_miner_public_key_length"), "{err}");
    }

    #[test]
    fn bridge_witness_rejects_message_index_out_of_bounds() {
        let (_tmp, node, imported) =
            node_with_exportable_bridge_block(b"message index out of bounds");

        let err = export_bridge_witness(&node, json!([hex32(&imported.hash), 1]))
            .expect_err("missing bridge message index must reject witness export");

        assert!(err
            .to_string()
            .contains("bridge message index out of bounds"));
    }

    #[test]
    fn bridge_witness_rejects_missing_parent_header() {
        let (_tmp, node, imported) =
            node_with_exportable_bridge_block(b"missing bridge witness parent");
        node.block_tree
            .remove(imported.parent_hash.as_slice())
            .expect("remove parent header");
        node.block_tree.flush().expect("flush block tree");

        let err = export_bridge_witness(&node, json!([hex32(&imported.hash), 0]))
            .expect_err("missing parent header must reject witness export");

        assert!(err
            .to_string()
            .contains("missing parent for bridge witness"));
    }

    #[test]
    fn bridge_witness_latest_backscan_rejects_corrupt_newer_canonical_block() {
        let (_tmp, node, older_bridge) =
            node_with_exportable_bridge_block(b"older bridge message behind corrupt tip");

        let work = node.prepare_work().expect("prepare empty child");
        assert_eq!(work.height, older_bridge.height + 1);
        assert_eq!(work.message_count, 0);
        let seal = mine_native_round(work.clone(), 0).expect("empty child seal");
        let mut newer = node
            .import_mined_block(&work, seal)
            .expect("import empty child")
            .expect("empty child block");
        assert_eq!(node.best_meta().hash, newer.hash);
        newer.action_bytes.push(vec![0xff]);
        persist_block_record(&node.block_tree, &newer).expect("persist corrupt canonical child");

        let err = export_bridge_witness(&node, json!([Value::Null, 0]))
            .expect_err("latest backscan must fail closed on corrupt canonical block actions");

        assert!(err
            .to_string()
            .contains("decode bridge witness backscan block actions"));
    }

    #[test]
    fn bridge_witness_latest_backscan_rejects_malformed_outbound_payload() {
        let (_tmp, node, older_bridge) =
            node_with_exportable_bridge_block(b"older bridge behind malformed payload");
        let pow_bits = 0x207f_ffff;
        let malformed = malformed_outbound_bridge_action(b"corrupt newer bridge payload");
        let parent_state = node.state.read().clone();
        let (state_root, nullifier_root, extrinsics_root, tx_count) = preview_pending_roots(
            &node.da_ciphertext_tree,
            &parent_state,
            std::slice::from_ref(&malformed),
        )
        .expect("preview malformed action roots");
        let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
        let header_history = node
            .header_hashes_to_hash(older_bridge.hash)
            .expect("header history");
        let header_mmr_root = header_mmr_root_from_hashes(&header_history);
        let header_mmr_len = header_history.len() as u64;
        let cumulative_work =
            cumulative_work_after(&older_bridge.cumulative_work, pow_bits).expect("work");
        let height = older_bridge.height.saturating_add(1);
        let timestamp_ms = older_bridge.timestamp_ms.saturating_add(1);
        let message_root = empty_bridge_message_root();
        let message_count = 0;
        let pre_header = native_pow_header_from_parts(
            height,
            timestamp_ms,
            older_bridge.hash,
            pow_bits,
            [0u8; 32],
            cumulative_work,
            &state_root,
            &kernel_root,
            &nullifier_root,
            &extrinsics_root,
            &message_root,
            message_count,
            &header_mmr_root,
            header_mmr_len,
            older_bridge.supply_digest,
            tx_count,
        );
        let work = NativeWork {
            height,
            parent_hash: older_bridge.hash,
            pre_hash: pre_header.pre_hash(),
            state_root,
            kernel_root,
            nullifier_root,
            extrinsics_root,
            message_root,
            message_count,
            header_mmr_root,
            header_mmr_len,
            cumulative_work,
            supply_digest: older_bridge.supply_digest,
            tx_count,
            timestamp_ms,
            pow_bits,
        };
        let seal = mine_native_round(work, 0).expect("malformed bridge child seal");
        let malformed_meta = signed_test_block_meta(NativeBlockMeta {
            chain_id: HEGEMON_CHAIN_ID_V1,
            rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
            height,
            hash: seal.work_hash,
            parent_hash: older_bridge.hash,
            state_root,
            kernel_root,
            nullifier_root,
            extrinsics_root,
            message_root,
            message_count,
            header_mmr_root,
            header_mmr_len,
            timestamp_ms,
            pow_bits,
            nonce: seal.nonce,
            work_hash: seal.work_hash,
            cumulative_work,
            supply_digest: older_bridge.supply_digest,
            tx_count,
            action_bytes: vec![malformed.encode()],
            miner_commitment: [0u8; 48],
            miner_public_key: Vec::new(),
            miner_signature: Vec::new(),
        });
        let malformed_hash = malformed_meta.hash;
        persist_block_record(&node.block_tree, &malformed_meta)
            .expect("persist malformed canonical block");
        node.height_tree
            .insert(height_key(height), malformed_meta.hash.as_slice())
            .expect("persist malformed canonical height");
        node.height_tree.flush().expect("flush height tree");
        node.state.write().best = malformed_meta;

        let explicit_err = export_bridge_witness(&node, json!([hex32(&malformed_hash), 0]))
            .expect_err("explicit witness export must fail on malformed outbound payload");
        assert!(explicit_err
            .to_string()
            .contains("outbound bridge action args"));

        let err = export_bridge_witness(&node, json!([Value::Null, 0]))
            .expect_err("latest backscan must fail on malformed outbound payload");

        assert!(err.to_string().contains("outbound bridge action args"));
    }

    #[test]
    fn inbound_bridge_rejects_message_binding_tampering() {
        use base64::Engine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let destination_path = tmp.path().join("destination");
        fs::create_dir_all(&destination_path).expect("destination dir");
        let pow_bits = 0x207f_ffff;
        let destination =
            NativeNode::open(test_config(&destination_path, pow_bits, "unsafe", false))
                .expect("destination node");
        let args = test_disabled_risc0_bridge_inbound_args(b"bound bridge payload");

        let request_for = |args: &InboundBridgeArgsV1| {
            json!({
                "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
                "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
                "family_id": FAMILY_BRIDGE,
                "action_id": ACTION_BRIDGE_INBOUND,
                "new_nullifiers": [],
                "public_args": base64::engine::general_purpose::STANDARD.encode(args.encode()),
            })
        };

        let mut bad_nonce = args.clone();
        bad_nonce.source_message_nonce = bad_nonce.source_message_nonce.wrapping_add(1);
        let err = destination
            .validate_and_stage_action(request_for(&bad_nonce))
            .expect_err("source nonce must bind to message nonce");
        assert!(err.to_string().contains("replay key does not match"));

        let mut wrong_destination = args.clone();
        wrong_destination.message.destination_chain_id = [0x55u8; 32];
        let err = destination
            .validate_and_stage_action(request_for(&wrong_destination))
            .expect_err("inbound bridge message must target Hegemon");
        assert!(err.to_string().contains("not addressed"));

        let mut bad_payload_hash = args.clone();
        bad_payload_hash.message.payload.push(0x99);
        let err = destination
            .validate_and_stage_action(request_for(&bad_payload_hash))
            .expect_err("payload hash must bind payload bytes");
        assert!(err.to_string().contains("payload hash mismatch"));

        let err = destination
            .validate_and_stage_action(request_for(&args))
            .expect_err("default native node must not stage RISC Zero bridge receipts");
        assert!(err.to_string().contains("verification is disabled"));
        assert_eq!(destination.state.read().pending_actions.len(), 0);
    }

    fn test_disabled_risc0_bridge_inbound_args(payload: &[u8]) -> InboundBridgeArgsV1 {
        let message = BridgeMessageV1 {
            source_chain_id: HEGEMON_CHAIN_ID_V1,
            destination_chain_id: HEGEMON_CHAIN_ID_V1,
            app_family_id: FAMILY_BRIDGE,
            message_nonce: 42,
            source_height: 9,
            payload_hash: bridge_payload_hash(payload),
            payload: payload.to_vec(),
        };
        let output = BridgeCheckpointOutputV1 {
            source_chain_id: HEGEMON_CHAIN_ID_V1,
            rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
            checkpoint_height: message.source_height,
            checkpoint_header_hash: [0x11u8; 32],
            checkpoint_cumulative_work: [0x22u8; 48],
            canonical_tip_height: message
                .source_height
                .saturating_add(u64::from(MIN_INBOUND_BRIDGE_CONFIRMATIONS))
                .saturating_sub(1),
            canonical_tip_header_hash: [0x33u8; 32],
            canonical_tip_cumulative_work: [0x44u8; 48],
            message_root: bridge_message_root(std::slice::from_ref(&message)),
            message_hash: message.message_hash(),
            message_nonce: message.message_nonce,
            confirmations_checked: MIN_INBOUND_BRIDGE_CONFIRMATIONS,
            min_work_checked: [0u8; 48],
        };
        let receipt = RiscZeroBridgeReceiptV1 {
            proof_system_id: consensus_light_client::RISC0_STARK_BRIDGE_PROOF_SYSTEM_ID_V1,
            image_id: HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1,
            journal: consensus_light_client::bridge_checkpoint_output_wire_bytes_v1(&output),
            receipt: vec![0],
        };
        InboundBridgeArgsV1 {
            source_chain_id: message.source_chain_id,
            source_message_nonce: message.message_nonce,
            verifier_program_hash: HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1,
            proof_receipt: receipt.encode(),
            message,
        }
    }

    fn test_miner_identity() -> NativeMinerIdentity {
        NativeMinerIdentity::from_seed(b"hegemon native miner identity test seed")
    }

    fn sign_test_block_meta(meta: &mut NativeBlockMeta) {
        sign_native_block_meta(meta, &test_miner_identity());
    }

    fn signed_test_block_meta(mut meta: NativeBlockMeta) -> NativeBlockMeta {
        sign_test_block_meta(&mut meta);
        meta
    }

    fn unsigned_native_meta(mut meta: NativeBlockMeta) -> NativeBlockMeta {
        meta.miner_commitment = [0u8; 48];
        meta.miner_public_key.clear();
        meta.miner_signature.clear();
        meta
    }

    fn legacy_meta_from_current(meta: &NativeBlockMeta) -> LegacyNativeBlockMetaV1 {
        LegacyNativeBlockMetaV1 {
            chain_id: meta.chain_id,
            rules_hash: meta.rules_hash,
            height: meta.height,
            hash: meta.hash,
            parent_hash: meta.parent_hash,
            state_root: meta.state_root,
            kernel_root: meta.kernel_root,
            nullifier_root: meta.nullifier_root,
            extrinsics_root: meta.extrinsics_root,
            message_root: meta.message_root,
            message_count: meta.message_count,
            header_mmr_root: meta.header_mmr_root,
            header_mmr_len: meta.header_mmr_len,
            timestamp_ms: meta.timestamp_ms,
            pow_bits: meta.pow_bits,
            nonce: meta.nonce,
            work_hash: meta.work_hash,
            cumulative_work: meta.cumulative_work,
            supply_digest: meta.supply_digest,
            tx_count: meta.tx_count,
            action_bytes: meta.action_bytes.clone(),
        }
    }

    fn mined_empty_child(
        parent: &NativeBlockMeta,
        height: u64,
        pow_bits: u32,
        round: u64,
    ) -> NativeBlockMeta {
        mined_empty_child_at(
            parent,
            height,
            pow_bits,
            round,
            parent.timestamp_ms.saturating_add(1),
        )
    }

    fn strongest_test_seal(work: &NativeWork, rounds: std::ops::Range<u64>) -> NativeSeal {
        rounds
            .filter_map(|round| mine_native_round(work.clone(), round))
            .min_by(|left, right| left.work_hash.cmp(&right.work_hash))
            .expect("test mining rounds must produce at least one seal")
    }

    fn mined_empty_child_at(
        parent: &NativeBlockMeta,
        height: u64,
        pow_bits: u32,
        round: u64,
        timestamp_ms: u64,
    ) -> NativeBlockMeta {
        let state_root = parent.state_root;
        let kernel_root = parent.kernel_root;
        let nullifier_root = parent.nullifier_root;
        let extrinsics_root = actions_extrinsics_root(&[]);
        let message_root = empty_bridge_message_root();
        let message_count = 0;
        let header_history = if parent.height == 0 {
            vec![parent.hash]
        } else if parent.height == 1 {
            vec![parent.parent_hash, parent.hash]
        } else {
            vec![parent.hash]
        };
        let header_mmr_root = header_mmr_root_from_hashes(&header_history);
        let header_mmr_len = header_history.len() as u64;
        let cumulative_work =
            cumulative_work_after(&parent.cumulative_work, pow_bits).expect("cumulative work");
        let pre_header = native_pow_header_from_parts(
            height,
            timestamp_ms,
            parent.hash,
            pow_bits,
            [0u8; 32],
            cumulative_work,
            &state_root,
            &kernel_root,
            &nullifier_root,
            &extrinsics_root,
            &message_root,
            message_count,
            &header_mmr_root,
            header_mmr_len,
            parent.supply_digest,
            0,
        );
        let pre_hash = pre_header.pre_hash();
        let work = NativeWork {
            height,
            parent_hash: parent.hash,
            pre_hash,
            state_root,
            kernel_root,
            nullifier_root,
            extrinsics_root,
            message_root,
            message_count,
            header_mmr_root,
            header_mmr_len,
            cumulative_work,
            supply_digest: parent.supply_digest,
            tx_count: 0,
            timestamp_ms,
            pow_bits,
        };
        let seal = mine_native_round(work, round).expect("side seal");
        signed_test_block_meta(NativeBlockMeta {
            chain_id: HEGEMON_CHAIN_ID_V1,
            rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
            height,
            hash: seal.work_hash,
            parent_hash: parent.hash,
            state_root,
            kernel_root,
            nullifier_root,
            extrinsics_root,
            message_root,
            message_count,
            header_mmr_root,
            header_mmr_len,
            timestamp_ms,
            pow_bits,
            nonce: seal.nonce,
            work_hash: seal.work_hash,
            cumulative_work,
            supply_digest: parent.supply_digest,
            tx_count: 0,
            action_bytes: Vec::new(),
            miner_commitment: [0u8; 48],
            miner_public_key: Vec::new(),
            miner_signature: Vec::new(),
        })
    }

    #[derive(Clone, Copy, Debug)]
    enum TestCommitmentMutation {
        StateRoot,
        KernelRoot,
        NullifierRoot,
        ExtrinsicsRoot,
        MessageRoot,
        MessageCount,
        SupplyDigest,
    }

    fn mined_empty_child_with_commitment_mutation(
        parent: &NativeBlockMeta,
        pow_bits: u32,
        round: u64,
        mutation: TestCommitmentMutation,
    ) -> NativeBlockMeta {
        let height = parent.height.saturating_add(1);
        let timestamp_ms = parent.timestamp_ms.saturating_add(1);
        let mut state_root = parent.state_root;
        let mut kernel_root = parent.kernel_root;
        let mut nullifier_root = parent.nullifier_root;
        let mut extrinsics_root = actions_extrinsics_root(&[]);
        let mut message_root = empty_bridge_message_root();
        let mut message_count = 0;
        let header_history = if parent.height == 0 {
            vec![parent.hash]
        } else if parent.height == 1 {
            vec![parent.parent_hash, parent.hash]
        } else {
            vec![parent.hash]
        };
        let header_mmr_root = header_mmr_root_from_hashes(&header_history);
        let header_mmr_len = header_history.len() as u64;
        let cumulative_work =
            cumulative_work_after(&parent.cumulative_work, pow_bits).expect("cumulative work");
        let mut supply_digest = parent.supply_digest;

        match mutation {
            TestCommitmentMutation::StateRoot => state_root[0] ^= 1,
            TestCommitmentMutation::KernelRoot => kernel_root[0] ^= 1,
            TestCommitmentMutation::NullifierRoot => nullifier_root[0] ^= 1,
            TestCommitmentMutation::ExtrinsicsRoot => extrinsics_root[0] ^= 1,
            TestCommitmentMutation::MessageRoot => message_root[0] ^= 1,
            TestCommitmentMutation::MessageCount => message_count = 1,
            TestCommitmentMutation::SupplyDigest => supply_digest = supply_digest.saturating_add(1),
        }

        let pre_header = native_pow_header_from_parts(
            height,
            timestamp_ms,
            parent.hash,
            pow_bits,
            [0u8; 32],
            cumulative_work,
            &state_root,
            &kernel_root,
            &nullifier_root,
            &extrinsics_root,
            &message_root,
            message_count,
            &header_mmr_root,
            header_mmr_len,
            supply_digest,
            0,
        );
        let pre_hash = pre_header.pre_hash();
        let work = NativeWork {
            height,
            parent_hash: parent.hash,
            pre_hash,
            state_root,
            kernel_root,
            nullifier_root,
            extrinsics_root,
            message_root,
            message_count,
            header_mmr_root,
            header_mmr_len,
            cumulative_work,
            supply_digest,
            tx_count: 0,
            timestamp_ms,
            pow_bits,
        };
        let seal = mine_native_round(work, round).expect("mutated seal");
        signed_test_block_meta(NativeBlockMeta {
            chain_id: HEGEMON_CHAIN_ID_V1,
            rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
            height,
            hash: seal.work_hash,
            parent_hash: parent.hash,
            state_root,
            kernel_root,
            nullifier_root,
            extrinsics_root,
            message_root,
            message_count,
            header_mmr_root,
            header_mmr_len,
            timestamp_ms,
            pow_bits,
            nonce: seal.nonce,
            work_hash: seal.work_hash,
            cumulative_work,
            supply_digest,
            tx_count: 0,
            action_bytes: Vec::new(),
            miner_commitment: [0u8; 48],
            miner_public_key: Vec::new(),
            miner_signature: Vec::new(),
        })
    }

    fn mined_child_with_actions(
        parent: &NativeBlockMeta,
        height: u64,
        pow_bits: u32,
        round: u64,
        actions: Vec<PendingAction>,
    ) -> NativeBlockMeta {
        let parent_state = test_state(parent.clone());
        let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();
        for action in &actions {
            insert_test_sidecar_ciphertext(&da_ciphertext_tree, action);
        }
        let (state_root, nullifier_root, extrinsics_root, tx_count) =
            preview_pending_roots(&da_ciphertext_tree, &parent_state, &actions)
                .expect("preview action roots");
        let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
        let bridge_messages =
            bridge_messages_from_actions(&actions, height).expect("bridge messages");
        let message_root = bridge_message_root(&bridge_messages);
        let message_count = u32::try_from(bridge_messages.len()).expect("message count");
        let header_history = if parent.height == 0 {
            vec![parent.hash]
        } else if parent.height == 1 {
            vec![parent.parent_hash, parent.hash]
        } else {
            vec![parent.hash]
        };
        let header_mmr_root = header_mmr_root_from_hashes(&header_history);
        let header_mmr_len = header_history.len() as u64;
        let cumulative_work =
            cumulative_work_after(&parent.cumulative_work, pow_bits).expect("cumulative work");
        let supply_digest = advance_native_supply_digest(parent.supply_digest, &actions, height)
            .expect("supply digest");
        let pre_header = native_pow_header_from_parts(
            height,
            parent.timestamp_ms.saturating_add(1),
            parent.hash,
            pow_bits,
            [0u8; 32],
            cumulative_work,
            &state_root,
            &kernel_root,
            &nullifier_root,
            &extrinsics_root,
            &message_root,
            message_count,
            &header_mmr_root,
            header_mmr_len,
            supply_digest,
            tx_count,
        );
        let pre_hash = pre_header.pre_hash();
        let work = NativeWork {
            height,
            parent_hash: parent.hash,
            pre_hash,
            state_root,
            kernel_root,
            nullifier_root,
            extrinsics_root,
            message_root,
            message_count,
            header_mmr_root,
            header_mmr_len,
            cumulative_work,
            supply_digest,
            tx_count,
            timestamp_ms: parent.timestamp_ms.saturating_add(1),
            pow_bits,
        };
        let seal = mine_native_round(work, round).expect("action child seal");
        signed_test_block_meta(NativeBlockMeta {
            chain_id: HEGEMON_CHAIN_ID_V1,
            rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
            height,
            hash: seal.work_hash,
            parent_hash: parent.hash,
            state_root,
            kernel_root,
            nullifier_root,
            extrinsics_root,
            message_root,
            message_count,
            header_mmr_root,
            header_mmr_len,
            timestamp_ms: parent.timestamp_ms.saturating_add(1),
            pow_bits,
            nonce: seal.nonce,
            work_hash: seal.work_hash,
            cumulative_work,
            supply_digest,
            tx_count,
            action_bytes: actions.iter().map(Encode::encode).collect(),
            miner_commitment: [0u8; 48],
            miner_public_key: Vec::new(),
            miner_signature: Vec::new(),
        })
    }

    fn test_config(
        path: &Path,
        pow_bits: u32,
        rpc_methods: &str,
        rpc_external: bool,
    ) -> NativeConfig {
        NativeConfig {
            dev: true,
            tmp: false,
            base_path: path.to_path_buf(),
            db_path: path.join("native-chain.sled"),
            rpc_addr: "127.0.0.1:0".parse().expect("rpc addr"),
            p2p_listen_addr: "127.0.0.1:0".to_string(),
            node_name: "test".to_string(),
            rpc_methods: rpc_methods.to_string(),
            rpc_external,
            rpc_cors: None,
            seeds: Vec::new(),
            max_peers: 0,
            mine: false,
            mine_threads: 1,
            miner_address: None,
            pow_bits,
        }
    }

    fn mine_empty_native_block(node: &NativeNode) -> NativeBlockMeta {
        let work = node.prepare_work().expect("prepare empty native work");
        let seal = mine_native_round(work.clone(), 0).expect("empty native seal");
        node.import_mined_block(&work, seal)
            .expect("empty native import")
            .expect("empty native block")
    }

    fn test_state(best: NativeBlockMeta) -> NativeState {
        NativeState {
            best,
            pending_actions: BTreeMap::new(),
            commitment_tree: CommitmentTreeState::default(),
            nullifiers: BTreeSet::new(),
            consumed_bridge_messages: BTreeSet::new(),
            staged_ciphertexts: BTreeMap::new(),
            staged_proofs: BTreeMap::new(),
        }
    }

    fn test_da_ciphertext_tree() -> (sled::Db, sled::Tree) {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db.open_tree("da_ciphertexts").expect("da ciphertext tree");
        (db, tree)
    }

    fn temporary_action_tree_with_pending(
        pending_actions: &BTreeMap<[u8; 32], PendingAction>,
    ) -> (sled::Db, sled::Tree) {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db
            .open_tree("pending_actions")
            .expect("pending action tree");
        for (hash, action) in pending_actions {
            tree.insert(hash.as_slice(), action.encode())
                .expect("insert temporary pending action");
        }
        tree.flush().expect("flush temporary pending actions");
        (db, tree)
    }

    fn persist_pending_action_for_startup(node: &NativeNode, action: &PendingAction) {
        node.action_tree
            .insert(action.tx_hash.as_slice(), action.encode())
            .expect("insert persisted pending action");
        node.action_tree
            .flush()
            .expect("flush persisted pending action");
    }

    fn test_transfer_encrypted_note() -> protocol_shielded_pool::types::EncryptedNote {
        protocol_shielded_pool::types::EncryptedNote {
            ciphertext: [3u8; protocol_shielded_pool::types::ENCRYPTED_NOTE_SIZE],
            kem_ciphertext: vec![4u8; 32],
        }
    }

    fn test_transfer_ciphertext_bytes() -> Vec<u8> {
        let note = test_transfer_encrypted_note();
        let mut note_bytes = Vec::new();
        note_bytes.extend_from_slice(&note.ciphertext);
        note_bytes.extend_from_slice(&note.kem_ciphertext);
        note_bytes
    }

    fn insert_test_sidecar_ciphertext(tree: &sled::Tree, action: &PendingAction) {
        if action.family_id != FAMILY_SHIELDED_POOL
            || action.action_id != ACTION_SHIELDED_TRANSFER_SIDECAR
        {
            return;
        }
        let bytes = test_transfer_ciphertext_bytes();
        let hash = ciphertext_hash_bytes(&bytes);
        assert_eq!(
            action.ciphertext_hashes.as_slice(),
            [hash].as_slice(),
            "test sidecar action must use the deterministic test ciphertext"
        );
        tree.insert(hash.as_slice(), bytes)
            .expect("insert test sidecar ciphertext");
        tree.flush().expect("flush test sidecar ciphertext");
    }

    fn test_transfer_proof_artifact(
        anchor: [u8; 48],
        nullifiers: &[[u8; 48]],
        commitments: &[[u8; 48]],
        ciphertext_hashes: &[[u8; 48]],
        balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
        fee: u64,
        stablecoin: Option<StablecoinPolicyBinding>,
        binding: KernelVersionBinding,
    ) -> Vec<u8> {
        test_transfer_proof_artifact_with_value_balance(
            anchor,
            nullifiers,
            commitments,
            ciphertext_hashes,
            balance_slot_asset_ids,
            fee,
            0,
            stablecoin,
            binding,
        )
    }

    fn test_transfer_proof_artifact_with_value_balance(
        anchor: [u8; 48],
        nullifiers: &[[u8; 48]],
        commitments: &[[u8; 48]],
        ciphertext_hashes: &[[u8; 48]],
        balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
        fee: u64,
        value_balance: i128,
        stablecoin: Option<StablecoinPolicyBinding>,
        binding: KernelVersionBinding,
    ) -> Vec<u8> {
        let (_, fixture_bytes) = staged_proof_fixture();
        let mut decoded =
            consensus::backend_interface::decode_native_tx_leaf_artifact_bytes(&fixture_bytes)
                .expect("decode native tx-leaf fixture");
        let value_balance_magnitude = u64::try_from(value_balance.unsigned_abs())
            .expect("test value balance magnitude fits u64");
        decoded.tx.nullifiers = nullifiers.to_vec();
        decoded.tx.commitments = commitments.to_vec();
        decoded.tx.ciphertext_hashes = ciphertext_hashes.to_vec();
        decoded.tx.version = binding.into();
        decoded.proof_backend =
            protocol_versioning::tx_proof_backend_for_version(decoded.tx.version)
                .unwrap_or(protocol_versioning::DEFAULT_TX_PROOF_BACKEND);
        decoded.stark_public_inputs.input_flags = vec![1; nullifiers.len()];
        decoded.stark_public_inputs.output_flags = vec![1; commitments.len()];
        decoded.stark_public_inputs.fee = fee;
        decoded.stark_public_inputs.value_balance_sign = u8::from(value_balance < 0);
        decoded.stark_public_inputs.value_balance_magnitude = value_balance_magnitude;
        decoded.stark_public_inputs.merkle_root = anchor;
        decoded.stark_public_inputs.balance_slot_asset_ids = balance_slot_asset_ids.to_vec();
        match stablecoin {
            Some(stablecoin) => {
                let issuance_magnitude = u64::try_from(stablecoin.issuance_delta.unsigned_abs())
                    .expect("test stablecoin issuance delta magnitude fits u64");
                decoded.stark_public_inputs.stablecoin_enabled = 1;
                decoded.stark_public_inputs.stablecoin_asset_id = stablecoin.asset_id;
                decoded.stark_public_inputs.stablecoin_policy_version = stablecoin.policy_version;
                decoded.stark_public_inputs.stablecoin_issuance_sign =
                    u8::from(stablecoin.issuance_delta < 0);
                decoded.stark_public_inputs.stablecoin_issuance_magnitude = issuance_magnitude;
                decoded.stark_public_inputs.stablecoin_policy_hash = stablecoin.policy_hash;
                decoded.stark_public_inputs.stablecoin_oracle_commitment =
                    stablecoin.oracle_commitment;
                decoded
                    .stark_public_inputs
                    .stablecoin_attestation_commitment = stablecoin.attestation_commitment;
            }
            None => {
                decoded.stark_public_inputs.stablecoin_enabled = 0;
                decoded.stark_public_inputs.stablecoin_asset_id = 0;
                decoded.stark_public_inputs.stablecoin_policy_version = 0;
                decoded.stark_public_inputs.stablecoin_issuance_sign = 0;
                decoded.stark_public_inputs.stablecoin_issuance_magnitude = 0;
                decoded.stark_public_inputs.stablecoin_policy_hash = [0u8; 48];
                decoded.stark_public_inputs.stablecoin_oracle_commitment = [0u8; 48];
                decoded
                    .stark_public_inputs
                    .stablecoin_attestation_commitment = [0u8; 48];
            }
        }
        decoded.receipt.statement_hash =
            native_tx_leaf_statement_hash_from_decoded(&decoded).expect("statement hash");
        decoded.receipt.verifier_profile =
            consensus::proof_interface::experimental_native_tx_leaf_verifier_profile();
        decoded.receipt.public_inputs_digest =
            consensus::backend_interface::transaction_public_inputs_digest_from_serialized(
                &decoded.stark_public_inputs,
            )
            .expect("public input digest");
        decoded.receipt.proof_digest =
            transaction_circuit::proof::transaction_proof_digest_from_parts(
                decoded.proof_backend,
                &decoded.stark_proof,
            );
        let proof = consensus::backend_interface::encode_native_tx_leaf_artifact_bytes(&decoded)
            .expect("encode native tx-leaf fixture");
        let binding_hash = native_tx_leaf_artifact_binding_hash(&decoded)
            .expect("derive native tx-leaf binding hash");
        assert!(native_tx_leaf_artifact_binding_hash_matches_key(
            binding_hash,
            &proof
        ));
        proof
    }

    fn test_repartitioned_transfer_proof_alias(
        anchor: [u8; 48],
        nullifier: [u8; 48],
        commitment: [u8; 48],
        ciphertext_hash: [u8; 48],
        balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
        fee: u64,
        stablecoin: Option<StablecoinPolicyBinding>,
        binding: KernelVersionBinding,
    ) -> Vec<u8> {
        test_transfer_proof_artifact(
            anchor,
            &[nullifier, commitment],
            &[],
            &[ciphertext_hash],
            balance_slot_asset_ids,
            fee,
            stablecoin,
            binding,
        )
    }

    fn test_stablecoin_policy_binding(seed: u8) -> StablecoinPolicyBinding {
        StablecoinPolicyBinding {
            asset_id: u64::from(seed),
            policy_hash: [seed; 48],
            oracle_commitment: [seed.wrapping_add(1); 48],
            attestation_commitment: [seed.wrapping_add(2); 48],
            issuance_delta: i128::from(seed) - 20,
            policy_version: u32::from(seed),
        }
    }

    fn test_inline_transfer_action(
        anchor: [u8; 48],
        nullifier: [u8; 48],
        commitment: [u8; 48],
        fee: u64,
    ) -> PendingAction {
        test_inline_transfer_action_with_stablecoin(anchor, nullifier, commitment, fee, None)
    }

    fn test_inline_transfer_action_with_stablecoin(
        anchor: [u8; 48],
        nullifier: [u8; 48],
        commitment: [u8; 48],
        fee: u64,
        stablecoin: Option<StablecoinPolicyBinding>,
    ) -> PendingAction {
        let note = test_transfer_encrypted_note();
        let note_bytes = test_transfer_ciphertext_bytes();
        let ciphertext_hash = ciphertext_hash_bytes(&note_bytes);
        let inputs = ShieldedTransferInputs {
            anchor,
            nullifiers: vec![nullifier],
            commitments: vec![commitment],
            ciphertext_hashes: vec![ciphertext_hash],
            balance_slot_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
            fee,
            value_balance: 0,
            stablecoin: stablecoin.clone(),
        };
        let binding_hash = StarkVerifier::compute_binding_hash(&inputs).data;
        let binding = KernelVersionBinding {
            circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
        };
        let balance_slot_asset_ids = [0, u64::MAX, u64::MAX, u64::MAX];
        let proof = test_transfer_proof_artifact(
            anchor,
            &[nullifier],
            &[commitment],
            &[ciphertext_hash],
            balance_slot_asset_ids,
            fee,
            stablecoin.clone(),
            binding,
        );
        let args = ShieldedTransferInlineArgs {
            proof,
            commitments: vec![commitment],
            ciphertexts: vec![note],
            anchor,
            balance_slot_asset_ids,
            binding_hash,
            stablecoin,
            fee,
        };
        let ciphertext_size = u32::try_from(
            args.ciphertexts[0].ciphertext.len() + args.ciphertexts[0].kem_ciphertext.len(),
        )
        .expect("ciphertext size");
        let mut action = PendingAction {
            tx_hash: [0u8; 32],
            binding,
            family_id: FAMILY_SHIELDED_POOL,
            action_id: ACTION_SHIELDED_TRANSFER_INLINE,
            anchor,
            nullifiers: vec![nullifier],
            commitments: vec![commitment],
            ciphertext_hashes: vec![ciphertext_hash],
            ciphertext_sizes: vec![ciphertext_size],
            public_args: args.encode(),
            fee,
            candidate_artifact: None,
            received_ms: 0,
        };
        action.tx_hash = pending_action_hash(&action);
        action
    }

    fn test_sidecar_transfer_action(
        anchor: [u8; 48],
        nullifier: [u8; 48],
        commitment: [u8; 48],
        fee: u64,
    ) -> PendingAction {
        test_sidecar_transfer_action_with_stablecoin(anchor, nullifier, commitment, fee, None)
    }

    fn test_sidecar_transfer_action_with_stablecoin(
        anchor: [u8; 48],
        nullifier: [u8; 48],
        commitment: [u8; 48],
        fee: u64,
        stablecoin: Option<StablecoinPolicyBinding>,
    ) -> PendingAction {
        let inline = test_inline_transfer_action_with_stablecoin(
            anchor, nullifier, commitment, fee, stablecoin,
        );
        let inline_args: ShieldedTransferInlineArgs =
            decode_scale_exact(&inline.public_args, "test inline transfer args")
                .expect("decode inline args");
        let args = ShieldedTransferSidecarArgs {
            proof: inline_args.proof,
            commitments: inline_args.commitments,
            ciphertext_hashes: inline.ciphertext_hashes.clone(),
            ciphertext_sizes: inline.ciphertext_sizes.clone(),
            anchor,
            balance_slot_asset_ids: inline_args.balance_slot_asset_ids,
            binding_hash: inline_args.binding_hash,
            stablecoin: inline_args.stablecoin,
            fee,
        };
        let mut action = PendingAction {
            action_id: ACTION_SHIELDED_TRANSFER_SIDECAR,
            public_args: args.encode(),
            ..inline
        };
        action.tx_hash = pending_action_hash(&action);
        action
    }

    fn test_outbound_bridge_action(payload: &[u8]) -> PendingAction {
        let args = OutboundBridgeArgsV1 {
            destination_chain_id: [42u8; 32],
            app_family_id: FAMILY_BRIDGE,
            payload: payload.to_vec(),
        };
        let mut action = PendingAction {
            tx_hash: [0u8; 32],
            binding: KernelVersionBinding {
                circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
                crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            },
            family_id: FAMILY_BRIDGE,
            action_id: ACTION_BRIDGE_OUTBOUND,
            anchor: [0u8; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: Vec::new(),
            ciphertext_sizes: Vec::new(),
            public_args: args.encode(),
            fee: 0,
            candidate_artifact: None,
            received_ms: 0,
        };
        action.tx_hash = pending_action_hash(&action);
        action
    }

    fn malformed_outbound_bridge_action(payload: &[u8]) -> PendingAction {
        let mut action = test_outbound_bridge_action(payload);
        action.public_args.push(0xaa);
        action.tx_hash = pending_action_hash(&action);
        action
    }

    fn test_inbound_bridge_action(payload: &[u8]) -> PendingAction {
        let source_chain_id = HEGEMON_CHAIN_ID_V1;
        let source_message_nonce = 17u128;
        let message = BridgeMessageV1 {
            source_chain_id,
            destination_chain_id: HEGEMON_CHAIN_ID_V1,
            app_family_id: FAMILY_BRIDGE,
            message_nonce: source_message_nonce,
            source_height: 42,
            payload_hash: bridge_payload_hash(payload),
            payload: payload.to_vec(),
        };
        let args = InboundBridgeArgsV1 {
            source_chain_id,
            source_message_nonce,
            verifier_program_hash: [7u8; 32],
            proof_receipt: vec![1, 2, 3],
            message,
        };
        let mut action = PendingAction {
            tx_hash: [0u8; 32],
            binding: KernelVersionBinding {
                circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
                crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            },
            family_id: FAMILY_BRIDGE,
            action_id: ACTION_BRIDGE_INBOUND,
            anchor: [0u8; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: Vec::new(),
            ciphertext_sizes: Vec::new(),
            public_args: args.encode(),
            fee: 0,
            candidate_artifact: None,
            received_ms: 0,
        };
        action.tx_hash = pending_action_hash(&action);
        action
    }

    fn test_disabled_risc0_inbound_bridge_action(payload: &[u8]) -> PendingAction {
        let args = test_disabled_risc0_bridge_inbound_args(payload);
        let mut action = PendingAction {
            tx_hash: [0u8; 32],
            binding: KernelVersionBinding {
                circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
                crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            },
            family_id: FAMILY_BRIDGE,
            action_id: ACTION_BRIDGE_INBOUND,
            anchor: [0u8; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: Vec::new(),
            ciphertext_sizes: Vec::new(),
            public_args: args.encode(),
            fee: 0,
            candidate_artifact: None,
            received_ms: 0,
        };
        action.tx_hash = pending_action_hash(&action);
        action
    }

    fn test_candidate_artifact(tx_count: u32) -> CandidateArtifact {
        CandidateArtifact {
            version: BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count,
            tx_statements_commitment: [5u8; 48],
            da_root: [6u8; 48],
            da_chunk_count: 1,
            commitment_proof: protocol_shielded_pool::types::StarkProof::default(),
            proof_mode: BlockProofMode::RecursiveBlock,
            proof_kind: PoolProofArtifactKind::RecursiveBlockV2,
            verifier_profile: consensus::proof::recursive_block_artifact_verifier_profile(),
            receipt_root: None,
            recursive_block: Some(protocol_shielded_pool::types::RecursiveBlockProofPayload {
                proof: protocol_shielded_pool::types::StarkProof {
                    data: vec![8u8; 32],
                },
            }),
        }
    }

    fn test_candidate_artifact_action(tx_count: u32, tag: u8) -> PendingAction {
        let mut artifact = test_candidate_artifact(tx_count);
        artifact.tx_statements_commitment = [tag; 48];
        artifact.da_root = [tag.wrapping_add(1); 48];
        if let Some(recursive) = artifact.recursive_block.as_mut() {
            recursive.proof.data = vec![tag; 32];
        }
        let mut action =
            test_empty_action(FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT, 0);
        action.candidate_artifact = Some(artifact);
        action.received_ms = u64::from(tag);
        action.tx_hash = pending_action_hash(&action);
        action
    }

    fn test_empty_action(family_id: u16, action_id: u16, fee: u64) -> PendingAction {
        let mut action = PendingAction {
            tx_hash: [0u8; 32],
            binding: KernelVersionBinding {
                circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
                crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            },
            family_id,
            action_id,
            anchor: [0u8; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: Vec::new(),
            ciphertext_sizes: Vec::new(),
            public_args: Vec::new(),
            fee,
            candidate_artifact: None,
            received_ms: 0,
        };
        action.tx_hash = pending_action_hash(&action);
        action
    }

    fn test_coinbase_action(amount: u64) -> PendingAction {
        test_coinbase_action_with_seed(amount, [15u8; 32])
    }

    fn test_coinbase_action_with_seed(amount: u64, public_seed: [u8; 32]) -> PendingAction {
        let note = protocol_shielded_pool::types::EncryptedNote {
            ciphertext: [11u8; protocol_shielded_pool::types::ENCRYPTED_NOTE_SIZE],
            kem_ciphertext: vec![12u8; 32],
        };
        let mut miner_note = protocol_shielded_pool::types::CoinbaseNoteData {
            commitment: [0u8; 48],
            encrypted_note: note,
            recipient_address: [14u8; protocol_shielded_pool::types::DIVERSIFIED_ADDRESS_SIZE],
            amount,
            public_seed,
        };
        let commitment = coinbase_note_data_commitment(&miner_note);
        miner_note.commitment = commitment;
        let args = MintCoinbaseArgs {
            reward_bundle: protocol_shielded_pool::types::BlockRewardBundle { miner_note },
        };
        let (_, ciphertext_metadata) =
            coinbase_ciphertext_metadata(&args.reward_bundle.miner_note.encrypted_note);
        let (ciphertext_hash, ciphertext_size) =
            ciphertext_metadata.expect("test coinbase ciphertext should fit the native cap");
        let mut action = PendingAction {
            tx_hash: [0u8; 32],
            binding: KernelVersionBinding {
                circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
                crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            },
            family_id: FAMILY_SHIELDED_POOL,
            action_id: ACTION_MINT_COINBASE,
            anchor: [0u8; 48],
            nullifiers: Vec::new(),
            commitments: vec![commitment],
            ciphertext_hashes: vec![ciphertext_hash],
            ciphertext_sizes: vec![ciphertext_size],
            public_args: args.encode(),
            fee: 0,
            candidate_artifact: None,
            received_ms: 0,
        };
        action.tx_hash = pending_action_hash(&action);
        action
    }

    fn tamper_coinbase_public_seed_without_rebinding(action: &mut PendingAction) {
        let mut args: MintCoinbaseArgs =
            decode_scale_exact(&action.public_args, "coinbase action args")
                .expect("decode test coinbase args");
        args.reward_bundle.miner_note.public_seed[0] ^= 1;
        action.public_args = args.encode();
        action.tx_hash = pending_action_hash(action);
    }

    #[test]
    fn coinbase_accounting_is_family_scoped() {
        let height = 9;
        let subsidy = consensus::reward::block_subsidy(height);
        let bridge_transfer_id_collision =
            test_empty_action(FAMILY_BRIDGE, ACTION_SHIELDED_TRANSFER_INLINE, 1_337);
        assert_eq!(
            expected_coinbase_amount(&[bridge_transfer_id_collision.clone()], height)
                .expect("expected coinbase amount"),
            subsidy
        );
        assert_eq!(
            native_block_supply_delta(&[bridge_transfer_id_collision], height)
                .expect("supply delta"),
            0
        );

        let bridge_coinbase_id_collision =
            test_empty_action(FAMILY_BRIDGE, ACTION_MINT_COINBASE, 0);
        validate_coinbase_accounting(&[bridge_coinbase_id_collision.clone()], height)
            .expect("non-shielded coinbase action id is ignored");
        assert_eq!(
            native_block_supply_delta(&[bridge_coinbase_id_collision], height)
                .expect("supply delta"),
            0
        );
    }

    #[test]
    fn coinbase_accounting_rejects_multiple_coinbase_actions() {
        let height = 1;
        let subsidy = consensus::reward::block_subsidy(height);
        let err = validate_coinbase_accounting(
            &[test_coinbase_action(subsidy), test_coinbase_action(subsidy)],
            height,
        )
        .expect_err("multiple coinbase actions must reject");
        assert!(
            err.to_string().contains("multiple coinbase"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn coinbase_accounting_rejects_reward_mismatch() {
        let height = 1;
        let subsidy = consensus::reward::block_subsidy(height);
        let err = validate_coinbase_accounting(&[test_coinbase_action(subsidy + 1)], height)
            .expect_err("wrong coinbase amount must reject");
        assert!(
            err.to_string().contains("coinbase amount mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn coinbase_accounting_rejects_fee_total_overflow_when_coinbase_claims_fees() {
        let height = 1;
        let subsidy = consensus::reward::block_subsidy(height);
        let max_fee = test_empty_action(
            FAMILY_SHIELDED_POOL,
            ACTION_SHIELDED_TRANSFER_INLINE,
            u64::MAX,
        );
        let one_fee = test_empty_action(FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE, 1);
        let err = validate_coinbase_accounting(
            &[max_fee, one_fee, test_coinbase_action(subsidy)],
            height,
        )
        .expect_err("overflowing fee total with coinbase must reject");
        assert!(
            err.to_string().contains("block fee total overflow"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn coinbase_accounting_allows_no_coinbase_fee_burn_without_summing_fees() {
        let height = 1;
        let max_fee = test_empty_action(
            FAMILY_SHIELDED_POOL,
            ACTION_SHIELDED_TRANSFER_INLINE,
            u64::MAX,
        );
        let one_fee = test_empty_action(FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE, 1);
        validate_coinbase_accounting(&[max_fee.clone(), one_fee.clone()], height)
            .expect("no coinbase burns fees without minting");
        assert_eq!(
            native_block_supply_delta(&[max_fee, one_fee], height).expect("supply delta"),
            0
        );
    }

    #[test]
    fn native_supply_digest_rejects_overflow() {
        let height = 1;
        let subsidy = consensus::reward::block_subsidy(height) as u128;
        let parent = u128::MAX - subsidy + 1;
        let actions = vec![test_coinbase_action(subsidy as u64)];
        assert!(
            advance_native_supply_digest(parent, &actions, height).is_err(),
            "native supply digest overflow must reject instead of saturating"
        );
    }

    #[test]
    fn lean_generated_native_supply_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_SUPPLY_VECTORS") else {
            eprintln!("HEGEMON_LEAN_SUPPLY_VECTORS not set; skipping generated Lean vector check");
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean supply vectors");
        let vectors: LeanSupplyVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean supply vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            vectors.monetary_constants.is_object(),
            "Lean monetary constants must be present"
        );
        assert!(
            !vectors.subsidy_schedule_cases.is_empty(),
            "Lean subsidy schedule cases must not be empty"
        );
        assert!(
            !vectors.consensus_supply_cases.is_empty(),
            "Lean consensus supply cases must not be empty"
        );
        assert!(
            !vectors.native_supply_cases.is_empty(),
            "Lean native supply cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.native_supply_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_native_supply_case(case);
        }
    }

    fn verify_lean_native_supply_case(case: &LeanNativeSupplyCase) {
        let parent_supply = parse_u128(&case.parent_supply);
        let expected_delta = case.expected_delta.as_deref().map(parse_u128);
        let expected_supply = case.expected_supply.as_deref().map(parse_u128);
        let mut actions = Vec::new();
        if case.fee_total > 0 {
            actions.push(test_empty_action(
                FAMILY_SHIELDED_POOL,
                ACTION_SHIELDED_TRANSFER_INLINE,
                case.fee_total,
            ));
        }
        if case.has_coinbase {
            let amount = expected_delta
                .expect("Lean native coinbase case must expose a checked reward amount");
            let amount = u64::try_from(amount).expect("Lean native reward amount fits u64");
            actions.push(test_coinbase_action(amount));
        }

        validate_coinbase_accounting(&actions, case.height)
            .expect("Lean native supply case should have valid coinbase accounting");
        assert_eq!(
            native_block_supply_delta(&actions, case.height)
                .ok()
                .as_ref()
                .map(u128::to_string),
            expected_delta.as_ref().map(u128::to_string),
            "{} native supply delta drifted from Lean spec",
            case.name
        );
        assert_eq!(
            advance_native_supply_digest(parent_supply, &actions, case.height)
                .ok()
                .as_ref()
                .map(u128::to_string),
            expected_supply.as_ref().map(u128::to_string),
            "{} native checked supply digest drifted from Lean spec",
            case.name
        );
    }

    fn parse_u128(raw: &str) -> u128 {
        raw.parse::<u128>()
            .expect("Lean supply value must be a decimal u128")
    }

    fn parse_u64(raw: &str) -> u64 {
        raw.parse::<u64>()
            .expect("Lean native value must be a decimal u64")
    }

    fn stage_test_coinbase(node: &NativeNode, amount: u64, commitment_hint: [u8; 48]) {
        use base64::Engine;

        let public_seed = [commitment_hint[0]; 32];
        let action = test_coinbase_action_with_seed(amount, public_seed);
        let args: MintCoinbaseArgs =
            decode_scale_exact(&action.public_args, "coinbase action args")
                .expect("decode test coinbase args");
        node.validate_and_stage_action(json!({
            "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            "family_id": FAMILY_SHIELDED_POOL,
            "action_id": ACTION_MINT_COINBASE,
            "new_nullifiers": [],
            "public_args": base64::engine::general_purpose::STANDARD.encode(args.encode()),
        }))
        .expect("stage test coinbase");
    }
}
