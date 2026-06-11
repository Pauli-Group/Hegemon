//! Native Hegemon node service.
//!
//! Native Hegemon node service.
//! It keeps the existing JSON-RPC compatibility surface while the ledger,
//! mempool, sync, and shielded state machines are native.

use anyhow::{anyhow, Context, Result};
use axum::extract::State;
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
    BlockProofMode, CandidateArtifact, ProofArtifactKind as PoolProofArtifactKind,
    BLOCK_PROOF_BUNDLE_SCHEMA, MAX_BATCH_SIZE, MAX_CIPHERTEXT_BYTES,
    NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE, RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE,
};
use protocol_shielded_pool::verifier::{ShieldedTransferInputs, StarkVerifier};
use protocol_shielded_pool::{NullifierReject, NullifierState};
use rand::{rngs::OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
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
use transaction_core::hashing_pq::ciphertext_hash_bytes;

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
const NATIVE_SYNC_PROTOCOL_ID: ProtocolId = 0x4847_4e53;
const MAX_NATIVE_SYNC_RESPONSE_BLOCKS: u64 = 512;
const MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE: usize = MAX_NATIVE_SYNC_RESPONSE_BLOCKS as usize;
const NATIVE_ANNOUNCE_INTERVAL: u64 = 16;
const PQ_IDENTITY_SEED_FILE: &str = "pq-identity.seed";
const PQ_IDENTITY_SEED_LEN: usize = 32;
const MAX_NATIVE_RPC_ACTION_BYTES: usize = 2 * 1024 * 1024;
const MAX_NATIVE_DA_CIPHERTEXT_UPLOADS: usize = 1024;
const MAX_NATIVE_DA_PROOF_UPLOADS: usize = 256;
const MAX_NATIVE_STAGED_CIPHERTEXTS: usize = 100_000;
const MAX_NATIVE_STAGED_PROOFS: usize = 10_000;
const MAX_NATIVE_STAGED_PROOF_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_NATIVE_WALLET_PAGE_LIMIT: u64 = 128;
const MAX_NATIVE_WALLET_PAGE_LIMIT: u64 = 1024;
const MAX_NATIVE_TIMESTAMP_ROWS: u64 = 4096;
const MAX_NATIVE_RPC_BATCH_REQUESTS: usize = 128;
const MAX_NATIVE_MEMPOOL_ACTION_BYTES: usize = 64 * 1024 * 1024;
const MAX_NATIVE_SYNC_MESSAGE_BYTES: usize = wire::MAX_WIRE_FRAME_LEN;
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
            .and_then(|raw| raw.parse::<u32>().ok())
            .filter(|threads| *threads > 0)
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeMinedWorkAdmissionInput {
    best_height: u64,
    work_height: u64,
    parent_hash_matches: bool,
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
    version_matches: bool,
    ciphertext_payload_hashes_match: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeTxLeafActionBindingAdmissionRejection {
    NullifiersMismatch,
    CommitmentsMismatch,
    CiphertextHashesMismatch,
    VersionMismatch,
    CiphertextPayloadHashMismatch,
}

impl NativeTxLeafActionBindingAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::NullifiersMismatch => "nullifiers_mismatch",
            Self::CommitmentsMismatch => "commitments_mismatch",
            Self::CiphertextHashesMismatch => "ciphertext_hashes_mismatch",
            Self::VersionMismatch => "version_mismatch",
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

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeBlockReplayRefinementInput {
    leaf_start: u64,
    commitment_count: usize,
    ciphertext_count: usize,
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

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeBlockReplayRefinementSummary {
    next_leaf_count: u64,
    imported_nullifier_count: usize,
    imported_bridge_replay: bool,
    expected_supply: u128,
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

#[cfg(test)]
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

#[cfg(test)]
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
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct SubmitActionRpcRequest {
    binding_circuit: u16,
    binding_crypto: u16,
    family_id: u16,
    action_id: u16,
    #[serde(default)]
    new_nullifiers: Vec<String>,
    public_args: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct NativePagination {
    #[serde(default)]
    start: u64,
    #[serde(default = "default_native_wallet_page_limit")]
    limit: u64,
}

#[derive(Debug)]
struct NativeState {
    best: NativeBlockMeta,
    pending_actions: BTreeMap<[u8; 32], PendingAction>,
    commitment_tree: CommitmentTreeState,
    nullifiers: BTreeSet<[u8; 48]>,
    consumed_bridge_messages: BTreeSet<[u8; 48]>,
    staged_ciphertexts: BTreeMap<String, u32>,
    staged_proofs: BTreeMap<String, Vec<u8>>,
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

        let best = load_best_or_genesis(&meta_tree, &height_tree, &block_tree, config.pow_bits)?;
        validate_loaded_block_indexes(
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
        let staged_ciphertexts = load_staged_sizes(&da_ciphertext_tree)?;
        let staged_proofs = load_staged_proofs(&da_proof_tree)?;

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
            state: RwLock::new(NativeState {
                best,
                pending_actions,
                commitment_tree: commitment_state,
                nullifiers,
                consumed_bridge_messages,
                staged_ciphertexts,
                staged_proofs,
            }),
            start_instant: Instant::now(),
            mining: AtomicBool::new(false),
            mining_threads: AtomicU32::new(0),
            mining_round: AtomicU64::new(0),
            mining_hashes: AtomicU64::new(0),
            blocks_found: AtomicU64::new(0),
            last_announce_height: AtomicU64::new(0),
            mining_task: Mutex::new(None),
            sync_tx: Mutex::new(None),
        });
        node.ensure_ciphertext_archive_index()?;
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

    fn prepare_work(&self) -> Result<NativeWork> {
        let state = self.state.read();
        let best = state.best.clone();
        let pending_actions = select_mineable_actions(&state);
        let cumulative_work = cumulative_work_after(&best.cumulative_work, self.config.pow_bits)
            .map_err(|_| NativeWorkTemplateAdmissionRejection::CumulativeWorkOverflow);
        let height = evaluate_native_work_template_admission(NativeWorkTemplateAdmissionInput {
            best_height: best.height,
            cumulative_work_advances: cumulative_work.is_ok(),
        })
        .map_err(native_work_template_admission_error)?;
        let cumulative_work = cumulative_work.map_err(native_work_template_admission_error)?;
        let (mut actions, mut state_root, mut nullifier_root, mut extrinsics_root, mut tx_count) =
            match preview_pending_roots(&state, &pending_actions) {
                Ok((state_root, nullifier_root, extrinsics_root, tx_count)) => (
                    pending_actions,
                    state_root,
                    nullifier_root,
                    extrinsics_root,
                    tx_count,
                ),
                Err(err) => {
                    warn!(error = %err, "failed to preview native pending action roots");
                    (
                        Vec::new(),
                        best.state_root,
                        best.nullifier_root,
                        actions_extrinsics_root(&[]),
                        0,
                    )
                }
            };
        let timestamp_ms = current_time_ms().max(best.timestamp_ms.saturating_add(1));
        let supply_digest = match advance_native_supply_digest(best.supply_digest, &actions, height)
        {
            Ok(supply_digest) => supply_digest,
            Err(err) => {
                warn!(error = %err, "dropping native pending actions with invalid supply accounting");
                actions = Vec::new();
                state_root = best.state_root;
                nullifier_root = best.nullifier_root;
                extrinsics_root = actions_extrinsics_root(&[]);
                tx_count = 0;
                best.supply_digest
            }
        };
        let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
        let bridge_messages = bridge_messages_from_actions(&actions, height);
        let message_root = bridge_message_root(&bridge_messages);
        let message_count = u32::try_from(bridge_messages.len()).unwrap_or(u32::MAX);
        let header_history = self.header_hashes_to_hash(best.hash).unwrap_or_else(|err| {
            warn!(error = %err, "failed to build header MMR history for native work");
            Vec::new()
        });
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

        let actions = if work.tx_count == 0 {
            Vec::new()
        } else {
            select_mineable_actions(&state)
        };
        let (preview_state_root, preview_nullifier_root, preview_extrinsics_root, preview_tx_count) =
            match preview_pending_roots(&state, &actions) {
                Ok(roots) => roots,
                Err(err) => {
                    debug!(error = %err, "native mined work no longer matches pending actions");
                    return Ok(None);
                }
            };
        let preview_kernel_root =
            consensus::types::kernel_root_from_shielded_root(&preview_state_root);
        let preview_bridge_messages = bridge_messages_from_actions(&actions, work.height);
        let preview_message_count = u32::try_from(preview_bridge_messages.len())
            .map_err(|_| anyhow!("native bridge message count overflow"))?;
        let preview_message_root = bridge_message_root(&preview_bridge_messages);
        let expected_header_history = self.header_hashes_to_hash(state.best.hash)?;
        let commitment_admission =
            evaluate_native_block_commitment_admission(NativeBlockCommitmentAdmissionInput {
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
                supply_digest_matches: true,
            });
        match commitment_admission {
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
        let supply_digest =
            advance_native_supply_digest(state.best.supply_digest, &actions, work.height)?;
        if !actions.is_empty() {
            validate_block_actions_locked(&state, &actions)?;
            validate_coinbase_accounting(&actions, work.height)?;
            verify_native_block_artifacts_locked(self, &state, &actions)?;
            self.apply_pending_actions_locked(&mut state, &actions)?;
        }
        if state.commitment_tree.root() != work.state_root
            || nullifier_root_from_set(&state.nullifiers) != work.nullifier_root
        {
            return Err(anyhow!("native pending action preview mismatch"));
        }

        let meta = NativeBlockMeta {
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
        };
        verify_native_pow_meta(&state.best, &meta)?;

        persist_block(&self.meta_tree, &self.height_tree, &self.block_tree, &meta)?;
        state.best = meta.clone();
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
        let (state_root, nullifier_root, extrinsics_root, tx_count) =
            preview_pending_roots(&parent_state, &actions)?;
        let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
        let bridge_messages = bridge_messages_from_actions(&actions, meta.height);
        let message_root = bridge_message_root(&bridge_messages);
        let message_count = u32::try_from(bridge_messages.len())
            .map_err(|_| anyhow!("native bridge message count overflow"))?;
        let expected_supply =
            advance_native_supply_digest(parent.supply_digest, &actions, meta.height)?;
        evaluate_native_block_commitment_admission(NativeBlockCommitmentAdmissionInput {
            tx_count_matches: tx_count == meta.tx_count,
            state_root_matches: state_root == meta.state_root,
            kernel_root_matches: kernel_root == meta.kernel_root,
            nullifier_root_matches: nullifier_root == meta.nullifier_root,
            extrinsics_root_matches: extrinsics_root == meta.extrinsics_root,
            message_root_matches: message_root == meta.message_root,
            message_count_matches: message_count == meta.message_count,
            header_mmr_root_matches: meta.header_mmr_root
                == header_mmr_root_from_hashes(&expected_header_history),
            header_mmr_len_matches: meta.header_mmr_len == expected_header_history.len() as u64,
            supply_digest_matches: meta.supply_digest == expected_supply,
        })
        .map_err(|rejection| {
            native_block_commitment_admission_error(
                "announced block commitment mismatch",
                rejection,
            )
        })?;
        if !actions.is_empty() {
            validate_block_actions_locked(&parent_state, &actions)?;
            validate_coinbase_accounting(&actions, meta.height)?;
            verify_native_block_artifacts_locked(self, &parent_state, &actions)?;
        }
        persist_block_record(&self.block_tree, &meta)?;
        if native_meta_better_than(&meta, &state.best) {
            self.reorganize_to_best_locked(&mut state, meta.hash)?;
            Ok(true)
        } else {
            Ok(false)
        }
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
        match encode_sync_message(&NativeSyncMessage::Announce(Box::new(meta.clone()))) {
            Ok(payload) => {
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
            Err(err) => {
                warn!(error = %err, "failed to encode native block announce");
            }
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
        for height in range.from_height..=range.to_height {
            let Some(hash) = self.hash_by_height(height)? else {
                break;
            };
            let Some(meta) = self.header_by_hash(&hash)? else {
                break;
            };
            blocks.push(meta);
        }
        Ok(blocks)
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
            let actions = decode_block_actions(&meta)?;
            validate_block_actions_locked(&state, &actions)?;
            let (state_root, nullifier_root, extrinsics_root, tx_count) =
                preview_pending_roots(&state, &actions)?;
            let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
            let bridge_messages = bridge_messages_from_actions(&actions, meta.height);
            let message_root = bridge_message_root(&bridge_messages);
            let message_count = u32::try_from(bridge_messages.len())
                .map_err(|_| anyhow!("native bridge message count overflow"))?;
            let expected_header_history: Vec<Hash32> =
                chain[..idx].iter().map(|header| header.hash).collect();
            validate_coinbase_accounting(&actions, meta.height)?;
            let expected_supply =
                advance_native_supply_digest(state.best.supply_digest, &actions, meta.height)?;
            evaluate_native_block_commitment_admission(NativeBlockCommitmentAdmissionInput {
                tx_count_matches: tx_count == meta.tx_count,
                state_root_matches: state_root == meta.state_root,
                kernel_root_matches: kernel_root == meta.kernel_root,
                nullifier_root_matches: nullifier_root == meta.nullifier_root,
                extrinsics_root_matches: extrinsics_root == meta.extrinsics_root,
                message_root_matches: message_root == meta.message_root,
                message_count_matches: message_count == meta.message_count,
                header_mmr_root_matches: meta.header_mmr_root
                    == header_mmr_root_from_hashes(&expected_header_history),
                header_mmr_len_matches: meta.header_mmr_len == expected_header_history.len() as u64,
                supply_digest_matches: meta.supply_digest == expected_supply,
            })
            .map_err(|rejection| {
                native_block_commitment_admission_error(
                    "native replay commitment mismatch",
                    rejection,
                )
            })?;
            apply_actions_to_memory(&mut state, &actions)?;
            state.best = meta;
        }
        Ok(state)
    }

    fn reorganize_to_best_locked(&self, state: &mut NativeState, new_hash: [u8; 32]) -> Result<()> {
        let old_chain = self.chain_to_hash(state.best.hash).unwrap_or_default();
        let new_chain = self.chain_to_hash(new_hash)?;
        let mut new_state = self.replay_state_to_hash(new_hash)?;

        self.height_tree.clear()?;
        self.commitment_tree.clear()?;
        self.nullifier_tree.clear()?;
        self.bridge_inbound_tree.clear()?;
        self.ciphertext_index_tree.clear()?;
        self.ciphertext_archive_tree.clear()?;

        for meta in &new_chain {
            self.height_tree
                .insert(height_key(meta.height), meta.hash.as_slice())?;
        }
        rebuild_canonical_indexes(
            &new_chain,
            &self.commitment_tree,
            &self.nullifier_tree,
            &self.bridge_inbound_tree,
            &self.ciphertext_index_tree,
            &self.ciphertext_archive_tree,
            &self.da_ciphertext_tree,
        )?;

        let new_action_hashes = action_hashes_from_chain(&new_chain)?;
        let mut pending = state.pending_actions.clone();
        for hash in &new_action_hashes {
            pending.remove(hash);
        }
        for action in orphaned_actions(&old_chain, &new_action_hashes)? {
            if is_candidate_artifact_action(&action) {
                pending.entry(action.tx_hash).or_insert(action);
                continue;
            }
            if action
                .nullifiers
                .iter()
                .all(|nullifier| !new_state.nullifiers.contains(nullifier))
            {
                pending.entry(action.tx_hash).or_insert(action);
            }
        }

        self.action_tree.clear()?;
        for action in pending.values() {
            self.action_tree
                .insert(action.tx_hash.as_slice(), action.encode())?;
        }
        self.action_tree.flush()?;

        self.meta_tree
            .insert(META_BEST_KEY, bincode::serialize(&new_state.best)?)?;
        self.meta_tree.flush()?;
        self.height_tree.flush()?;
        self.commitment_tree.flush()?;
        self.nullifier_tree.flush()?;
        self.bridge_inbound_tree.flush()?;
        self.ciphertext_index_tree.flush()?;
        self.ciphertext_archive_tree.flush()?;

        new_state.pending_actions = pending;
        new_state.staged_ciphertexts = state.staged_ciphertexts.clone();
        new_state.staged_proofs = state.staged_proofs.clone();
        *state = new_state;
        Ok(())
    }

    fn apply_pending_actions_locked(
        &self,
        state: &mut NativeState,
        actions: &[PendingAction],
    ) -> Result<()> {
        let planned = plan_pending_action_effects(&self.da_ciphertext_tree, state, actions)?;
        for (action, effect) in actions.iter().zip(planned.iter()) {
            for (offset, commitment) in action.commitments.iter().enumerate() {
                let index = effect
                    .commitment_start
                    .checked_add(offset as u64)
                    .expect("planned commitment index arithmetic must not overflow");
                debug_assert_eq!(
                    index,
                    state.commitment_tree.leaf_count(),
                    "planned commitment index drifted during native import"
                );
                state
                    .commitment_tree
                    .append(*commitment)
                    .map_err(|err| anyhow!("append native commitment failed: {err}"))?;
                self.commitment_tree
                    .insert(index.to_be_bytes(), commitment.as_slice())?;
            }
            insert_ciphertext_archive_entries(
                &self.ciphertext_archive_tree,
                effect.commitment_start,
                &effect.ciphertexts,
            )?;

            for nullifier in &action.nullifiers {
                state.nullifiers.insert(*nullifier);
                self.nullifier_tree.insert(nullifier.as_slice(), b"1")?;
            }
            if let Some(replay_key) = effect.replay_key {
                state.consumed_bridge_messages.insert(replay_key);
                self.bridge_inbound_tree
                    .insert(replay_key.as_slice(), b"1")?;
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
                self.ciphertext_index_tree.insert(hash.as_slice(), value)?;
            }

            self.action_tree.remove(action.tx_hash.as_slice())?;
            state.pending_actions.remove(&action.tx_hash);
        }

        self.commitment_tree.flush()?;
        self.nullifier_tree.flush()?;
        self.ciphertext_index_tree.flush()?;
        self.ciphertext_archive_tree.flush()?;
        self.action_tree.flush()?;
        Ok(())
    }

    fn ensure_ciphertext_archive_index(&self) -> Result<()> {
        let expected = self.commitment_tree.len() as u64;
        if self.ciphertext_archive_tree.len() as u64 == expected {
            return Ok(());
        }

        let chain = self.chain_to_hash(self.best_meta().hash)?;
        warn!(
            expected,
            observed = self.ciphertext_archive_tree.len(),
            "rebuilding canonical native ciphertext archive"
        );
        self.commitment_tree.clear()?;
        self.nullifier_tree.clear()?;
        self.bridge_inbound_tree.clear()?;
        self.ciphertext_index_tree.clear()?;
        self.ciphertext_archive_tree.clear()?;
        rebuild_canonical_indexes(
            &chain,
            &self.commitment_tree,
            &self.nullifier_tree,
            &self.bridge_inbound_tree,
            &self.ciphertext_index_tree,
            &self.ciphertext_archive_tree,
            &self.da_ciphertext_tree,
        )?;
        self.commitment_tree.flush()?;
        self.nullifier_tree.flush()?;
        self.bridge_inbound_tree.flush()?;
        self.ciphertext_index_tree.flush()?;
        self.ciphertext_archive_tree.flush()?;
        Ok(())
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
        let start_key = page.start.to_be_bytes();
        for item in self.commitment_tree.range(start_key..) {
            let Ok((key, value)) = item else {
                continue;
            };
            if key.len() == 8 && value.len() == 48 {
                let mut index = [0u8; 8];
                index.copy_from_slice(&key);
                let index = u64::from_be_bytes(index);
                if index < page.start {
                    continue;
                }
                if entries.len() >= page.limit as usize {
                    break;
                }
                let mut commitment = [0u8; 48];
                commitment.copy_from_slice(&value);
                let commitment_hex = hex48(&commitment);
                entries.push(json!({
                    "index": index,
                    "value": commitment_hex,
                    "commitment": commitment_hex,
                }));
            }
        }
        let total = self.commitment_tree.len() as u64;
        Ok(json!({
            "entries": entries,
            "total": total,
            "has_more": page.start.saturating_add(page.limit) < total,
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
        let start_key = page.start.to_be_bytes();
        for item in self.ciphertext_archive_tree.range(start_key..) {
            let (key, value) = item?;
            if key.len() != 8 {
                continue;
            }
            if entries.len() >= page.limit as usize {
                break;
            }
            let mut index = [0u8; 8];
            index.copy_from_slice(&key);
            let index = u64::from_be_bytes(index);
            if index < page.start {
                continue;
            }
            entries.push(json!({
                "index": index,
                "ciphertext": base64::engine::general_purpose::STANDARD.encode(value.as_ref()),
            }));
        }
        Ok((entries, self.ciphertext_archive_tree.len() as u64))
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
        let request: SubmitActionRpcRequest =
            serde_json::from_value(request).context("decode submit action request")?;
        if request.family_id != FAMILY_SHIELDED_POOL && request.family_id != FAMILY_BRIDGE {
            return Err(anyhow!("unsupported family {}", request.family_id));
        }

        if request.public_args.len() > encoded_len_limit(MAX_NATIVE_RPC_ACTION_BYTES) {
            return Err(anyhow!(
                "public_args exceeds native action limit of {MAX_NATIVE_RPC_ACTION_BYTES} bytes"
            ));
        }
        let public_args = decode_base64(&request.public_args).context("decode public_args")?;
        if public_args.len() > MAX_NATIVE_RPC_ACTION_BYTES {
            return Err(anyhow!(
                "decoded public_args exceeds native action limit of {MAX_NATIVE_RPC_ACTION_BYTES} bytes"
            ));
        }
        let binding = KernelVersionBinding {
            circuit: request.binding_circuit,
            crypto: request.binding_crypto,
        };
        let nullifiers = request
            .new_nullifiers
            .iter()
            .map(|raw| parse_hex48(raw).ok_or_else(|| anyhow!("invalid nullifier hex")))
            .collect::<Result<Vec<_>>>()?;

        let received_ms = current_time_ms();
        let mut pending = match (request.family_id, request.action_id) {
            (FAMILY_BRIDGE, ACTION_BRIDGE_OUTBOUND) => {
                let args: OutboundBridgeArgsV1 =
                    decode_scale_exact(&public_args, "outbound bridge action args")?;
                if args.payload.is_empty() {
                    return Err(anyhow!("outbound bridge payload must be non-empty"));
                }
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
                    candidate_artifact: None,
                    received_ms,
                }
            }
            (FAMILY_BRIDGE, ACTION_BRIDGE_INBOUND) => {
                let args: InboundBridgeArgsV1 =
                    decode_scale_exact(&public_args, "inbound bridge action args")?;
                if args.proof_receipt.is_empty() {
                    return Err(anyhow!("inbound bridge proof receipt must be non-empty"));
                }
                if args.message.source_chain_id != args.source_chain_id
                    || args.message.message_nonce != args.source_message_nonce
                {
                    return Err(anyhow!("inbound bridge replay key does not match message"));
                }
                if args.message.destination_chain_id != HEGEMON_CHAIN_ID_V1 {
                    return Err(anyhow!(
                        "inbound bridge message is not addressed to Hegemon"
                    ));
                }
                if args.message.payload_hash != bridge_payload_hash(&args.message.payload) {
                    return Err(anyhow!("inbound bridge message payload hash mismatch"));
                }
                verify_inbound_bridge_receipt(&args)?;
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
                    candidate_artifact: None,
                    received_ms,
                }
            }
            (FAMILY_BRIDGE, ACTION_REGISTER_BRIDGE_VERIFIER) => {
                let _: BridgeVerifierRegistrationV1 =
                    decode_scale_exact(&public_args, "bridge verifier registration args")?;
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
                    candidate_artifact: None,
                    received_ms,
                }
            }
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
            self.action_tree
                .insert(pending.tx_hash.as_slice(), pending.encode())?;
            self.action_tree.flush()?;
            state
                .pending_actions
                .insert(pending.tx_hash, pending.clone());
        }

        Ok(pending)
    }

    fn validate_action_state(&self, action: &PendingAction) -> Result<()> {
        match evaluate_native_action_scope_admission(native_action_scope_admission_input(action))
            .map_err(native_action_scope_admission_error)?
        {
            NativeActionScopeAdmissionRoute::Bridge => {
                validate_bridge_action_payload(action)?;
                if let Some(replay_key) = bridge_inbound_replay_key_from_action(action)? {
                    let state = self.state.read();
                    let mut replay_state = inbound_replay_state_for_mempool(&state)?;
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

                let state = self.state.read();
                let input = native_transfer_state_admission_input_for_mempool(&state, action);
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
                    staged_count: state.staged_ciphertexts.len(),
                    max_staged_count: MAX_NATIVE_STAGED_CIPHERTEXTS,
                    replaces_existing: state.staged_ciphertexts.contains_key(&hash_hex),
                },
            )
            .map_err(native_sidecar_upload_admission_error)?;
            let size = u32::try_from(raw.len()).unwrap_or(u32::MAX);
            self.da_ciphertext_tree.insert(hash.as_slice(), raw)?;
            state.staged_ciphertexts.insert(hash_hex.clone(), size);
            results.push(json!({
                "hash": hash_hex,
                "size": size,
            }));
        }
        self.da_ciphertext_tree.flush()?;
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
            let binding_hash = binding_hash_value.expect("validated binding_hash presence");
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
                },
            )
            .map_err(native_sidecar_upload_admission_error)?;
            let proof_hash = hash48_with_parts(&[b"da-proof-v1", binding_hash.as_bytes(), &proof]);
            let proof_hash_hex = hex48(&proof_hash);
            evaluate_native_proof_sidecar_capacity_admission(NativeSidecarCapacityAdmissionInput {
                staged_count: state.staged_proofs.len(),
                max_staged_count: MAX_NATIVE_STAGED_PROOFS,
                replaces_existing: state.staged_proofs.contains_key(&binding_hash_key),
            })
            .map_err(native_sidecar_upload_admission_error)?;
            validate_staged_proof_byte_budget(
                &state.staged_proofs,
                &binding_hash_key,
                proof.len(),
                MAX_NATIVE_STAGED_PROOF_BYTES,
            )?;
            let size = u32::try_from(proof.len()).unwrap_or(u32::MAX);
            self.da_proof_tree
                .insert(binding_hash_bytes.as_slice(), proof.as_slice())?;
            state.staged_proofs.insert(binding_hash_key, proof);
            results.push(json!({
                "binding_hash": binding_hash,
                "proof_hash": proof_hash_hex,
                "size": size,
            }));
        }
        self.da_proof_tree.flush()?;
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
            let threads = first_param(&params)
                .and_then(|value| value.get("threads"))
                .and_then(Value::as_u64)
                .unwrap_or(1)
                .max(1) as u32;
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
    let meta = match first_param(&params).and_then(Value::as_str) {
        Some(hash_hex) => {
            let Some(hash) = parse_hash32(hash_hex) else {
                return Ok(Value::Null);
            };
            node.header_by_hash(&hash)?
        }
        None => Some(node.best_meta()),
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
    let hash = match first_param(&params)
        .and_then(Value::as_str)
        .and_then(parse_hash32)
    {
        Some(hash) => Some(hash),
        None => Some(node.best_meta().hash),
    };
    let Some(hash) = hash else {
        return Ok(Value::Null);
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
            if let Some(hash) = node.hash_by_height(height)? {
                if let Some(meta) = node.header_by_hash(&hash)? {
                    rows.push(json!({
                        "height": meta.height,
                        "timestamp_ms": meta.timestamp_ms,
                    }));
                }
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
        let timestamp_ms = node
            .hash_by_height(height)?
            .and_then(|hash| node.header_by_hash(&hash).ok().flatten())
            .map(|meta| meta.timestamp_ms);
        rows.push(json!({
            "height": height,
            "timestamp_ms": timestamp_ms,
        }));
    }
    Ok(Value::Array(rows))
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
    let mut block_actions_decoded = true;
    let actions = match meta.as_ref() {
        Some(meta) if canonical_height_present && block_is_canonical => {
            match decode_block_actions(meta) {
                Ok(actions) => Some(actions),
                Err(_) => {
                    block_actions_decoded = false;
                    None
                }
            }
        }
        _ => None,
    };
    let messages = actions.as_ref().and_then(|actions| {
        meta.as_ref()
            .map(|meta| bridge_messages_from_actions(actions, meta.height))
    });
    let message_index_in_bounds = match &messages {
        Some(messages) => messages.get(message_index).is_some(),
        None => true,
    };
    let parent = match meta.as_ref() {
        Some(meta)
            if canonical_height_present
                && block_is_canonical
                && block_actions_decoded
                && message_index_in_bounds =>
        {
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
            block_actions_decoded,
            message_index_in_bounds,
            parent_known: parent.is_some()
                || !(meta.is_some()
                    && canonical_height_present
                    && block_is_canonical
                    && block_actions_decoded
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
        let mut decode_error = None;
        if let Some(hash) = node.hash_by_height(height)? {
            entry.canonical_hash_present = true;
            if let Some(meta) = node.header_by_hash(&hash)? {
                entry.block_known = true;
                selected_hash = Some(meta.hash);
                match decode_block_actions(&meta) {
                    Ok(actions) => {
                        entry.message_index_in_bounds =
                            bridge_messages_from_actions(&actions, meta.height).len()
                                > message_index;
                    }
                    Err(error) => {
                        entry.block_actions_decoded = false;
                        decode_error = Some(error);
                    }
                }
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
                return Err(decode_error.unwrap_or_else(|| {
                    anyhow!(
                        "bridge witness backscan block action decode failed ({})",
                        NativeBridgeWitnessBackscanRejection::BlockActionsDecodeFailed.label()
                    )
                }))
                .with_context(|| {
                    format!("decode bridge witness backscan block actions at height {height}")
                });
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

fn load_best_or_genesis(
    meta_tree: &sled::Tree,
    height_tree: &sled::Tree,
    block_tree: &sled::Tree,
    pow_bits: u32,
) -> Result<NativeBlockMeta> {
    if let Some(bytes) = meta_tree.get(META_BEST_KEY)? {
        return bincode_deserialize_exact(&bytes, "native best metadata");
    }

    let genesis = genesis_meta(pow_bits)?;
    persist_block(meta_tree, height_tree, block_tree, &genesis)?;
    meta_tree.insert(META_GENESIS_KEY, genesis.hash.as_slice())?;
    meta_tree.flush()?;
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
    block_tree
        .get(hash)?
        .map(|bytes| bincode_deserialize_exact::<NativeBlockMeta>(&bytes, "native block metadata"))
        .transpose()
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
    } else {
        Ok(())
    }
}

fn validate_loaded_block_indexes(
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
        meta_tree.flush()?;
    }

    Ok(())
}

fn load_staged_sizes(tree: &sled::Tree) -> Result<BTreeMap<String, u32>> {
    load_staged_sizes_with_limits(tree, MAX_NATIVE_STAGED_CIPHERTEXTS, MAX_CIPHERTEXT_BYTES)
}

fn load_staged_sizes_with_limits(
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
        tree.flush()?;
    }
    Ok(entries)
}

fn load_staged_proofs(tree: &sled::Tree) -> Result<BTreeMap<String, Vec<u8>>> {
    load_staged_proofs_with_limits(
        tree,
        MAX_NATIVE_STAGED_PROOFS,
        NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
        MAX_NATIVE_STAGED_PROOF_BYTES,
    )
}

fn load_staged_proofs_with_limits(
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
        if let Err(rejection) = evaluate_native_staged_proof_reload(NativeStagedProofReloadInput {
            key_well_formed,
            proof_nonempty,
            proof_within_limit,
            capacity_available,
            byte_capacity_available,
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
            }
            stale_keys.push(key.to_vec());
            continue;
        }

        let mut binding_hash = [0u8; 64];
        binding_hash.copy_from_slice(&key);
        total_bytes = next_total_bytes;
        entries.insert(hex64(&binding_hash), value.to_vec());
    }
    let removed_stale_entries = !stale_keys.is_empty();
    for key in stale_keys {
        tree.remove(key)?;
    }
    if removed_stale_entries {
        tree.flush()?;
    }
    Ok(entries)
}

fn load_pending_actions(tree: &sled::Tree) -> Result<BTreeMap<[u8; 32], PendingAction>> {
    let mut actions = BTreeMap::new();
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
        validate_loaded_pending_action_hash(hash, &action, !actions.contains_key(&hash))?;
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
    let input = NativeCoinbaseActionPayloadAdmissionInput {
        amount_nonzero: args.reward_bundle.miner_note.amount != 0,
        commitment_matches: action.commitments.first()
            == Some(&args.reward_bundle.miner_note.commitment),
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
            })
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
    if output.source_chain_id != args.source_chain_id
        || output.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_V1
        || output.message_nonce != args.source_message_nonce
        || output.message_hash != args.message.message_hash()
    {
        return Err(anyhow!(
            "Hegemon light-client bridge receipt output mismatch"
        ));
    }
    let height_confirmations = output
        .canonical_tip_height
        .checked_sub(output.checkpoint_height)
        .map(|delta| delta.saturating_add(1).min(u32::MAX as u64) as u32)
        .ok_or_else(|| anyhow!("Hegemon light-client bridge receipt tip precedes message"))?;
    if output.confirmations_checked > height_confirmations {
        return Err(anyhow!(
            "Hegemon light-client bridge receipt overstates confirmations"
        ));
    }
    if output.confirmations_checked < MIN_INBOUND_BRIDGE_CONFIRMATIONS {
        return Err(anyhow!(
            "Hegemon light-client bridge receipt underconfirmed: {} < {}",
            output.confirmations_checked,
            MIN_INBOUND_BRIDGE_CONFIRMATIONS
        ));
    }
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
) -> Vec<BridgeMessageV1> {
    let mut messages = Vec::new();
    for action in actions {
        if action.family_id != FAMILY_BRIDGE || action.action_id != ACTION_BRIDGE_OUTBOUND {
            continue;
        }
        let Ok(args) = decode_scale_exact::<OutboundBridgeArgsV1>(
            &action.public_args,
            "outbound bridge action args",
        ) else {
            continue;
        };
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
    messages
}

fn decode_block_actions(meta: &NativeBlockMeta) -> Result<Vec<PendingAction>> {
    evaluate_native_action_hash_admission(NativeActionHashAdmissionInput {
        action_count_matches: meta.action_bytes.len() == meta.tx_count as usize,
        action_hashes_match: true,
        action_hashes_unique: true,
    })
    .map_err(native_action_hash_admission_error)?;
    let actions = meta
        .action_bytes
        .iter()
        .map(|bytes| decode_scale_exact::<PendingAction>(bytes, "native block action"))
        .collect::<Result<Vec<_>>>()?;
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

#[cfg(test)]
fn evaluate_native_block_replay_refinement(
    input: NativeBlockReplayRefinementInput,
    nullifiers: &[[u8; 48]],
    replay_key: Option<[u8; 48]>,
    nullifier_state: &mut NullifierState,
    bridge_replay_state: &mut InboundReplayState,
) -> Result<NativeBlockReplayRefinementSummary, NativeBlockReplayRefinementRejection> {
    let action_effect = evaluate_native_action_state_effect(
        input.leaf_start,
        input.commitment_count,
        input.ciphertext_count,
        nullifiers,
        replay_key,
        nullifier_state,
        bridge_replay_state,
    )
    .map_err(native_block_replay_refinement_action_rejection)?;
    let expected_supply = expected_native_supply_from_parts(
        input.parent_supply,
        input.height,
        input.fee_total,
        input.has_coinbase,
    )
    .ok_or(NativeBlockReplayRefinementRejection::SupplyDeltaInvalid)?;
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
    .map_err(native_block_replay_refinement_commitment_rejection)?;

    Ok(NativeBlockReplayRefinementSummary {
        next_leaf_count: action_effect.next_leaf_count,
        imported_nullifier_count: action_effect.imported_nullifier_count,
        imported_bridge_replay: action_effect.imported_bridge_replay,
        expected_supply,
    })
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

fn block_action_hashes_match(actions: &[PendingAction]) -> bool {
    actions
        .iter()
        .all(|action| action.tx_hash == pending_action_hash(action))
}

fn block_action_hashes_unique(actions: &[PendingAction]) -> bool {
    let mut seen = BTreeSet::new();
    actions.iter().all(|action| seen.insert(action.tx_hash))
}

fn validate_block_actions_locked(state: &NativeState, actions: &[PendingAction]) -> Result<()> {
    evaluate_native_action_hash_admission(NativeActionHashAdmissionInput {
        action_count_matches: true,
        action_hashes_match: block_action_hashes_match(actions),
        action_hashes_unique: block_action_hashes_unique(actions),
    })
    .map_err(native_action_hash_admission_error)?;
    let mut bridge_replay_state =
        InboundReplayState::new(state.consumed_bridge_messages.clone(), BTreeSet::new());
    let mut nullifier_state = NullifierState::new(state.nullifiers.clone(), BTreeSet::new());
    let mut previous_transfer_key: Option<[u8; 32]> = None;
    for action in actions {
        match evaluate_native_action_scope_admission(native_action_scope_admission_input(action))
            .map_err(native_action_scope_admission_error)?
        {
            NativeActionScopeAdmissionRoute::Bridge => {
                validate_bridge_action_payload(action)?;
                if let Some(replay_key) = bridge_inbound_replay_key_from_action(action)? {
                    bridge_replay_state
                        .import_one(replay_key)
                        .map_err(|_| anyhow!("duplicate inbound bridge message in block"))?;
                }
            }
            NativeActionScopeAdmissionRoute::CandidateArtifact => {
                validate_candidate_action_payload(action)?;
            }
            NativeActionScopeAdmissionRoute::Coinbase => {
                validate_coinbase_action_payload(action)?;
            }
            NativeActionScopeAdmissionRoute::Transfer => {
                validate_transfer_action_payload(action)?;
                let transfer_key = action_order_key(action);
                if !transfer_key_extends_canonical_order(
                    previous_transfer_key.as_ref(),
                    &transfer_key,
                ) {
                    return Err(anyhow!(
                        "shielded transfer actions are not in canonical order"
                    ));
                }
                previous_transfer_key = Some(transfer_key);
                let input = native_transfer_state_admission_input_for_block(
                    state,
                    &mut nullifier_state,
                    action,
                );
                evaluate_native_transfer_state_admission(input).map_err(|rejection| {
                    native_transfer_state_admission_error(
                        NativeTransferStateAdmissionContext::Block,
                        rejection,
                    )
                })?;
            }
        }
    }
    Ok(())
}

fn plan_action_effects_for_memory(
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<Vec<NativePlannedActionEffect>> {
    let mut bridge_replay_state =
        InboundReplayState::new(state.consumed_bridge_messages.clone(), BTreeSet::new());
    let mut nullifier_state = NullifierState::new(state.nullifiers.clone(), BTreeSet::new());
    let mut next_leaf_count = state.commitment_tree.leaf_count();
    let mut planned = Vec::with_capacity(actions.len());

    for action in actions {
        let replay_key = bridge_inbound_replay_key_from_action(action)?;
        let effect = evaluate_native_action_state_effect(
            next_leaf_count,
            action.commitments.len(),
            action.commitments.len(),
            &action.nullifiers,
            replay_key,
            &mut nullifier_state,
            &mut bridge_replay_state,
        )
        .map_err(native_action_state_effect_error)?;
        planned.push(NativePlannedActionEffect {
            commitment_start: next_leaf_count,
            ciphertexts: Vec::new(),
            replay_key,
        });
        next_leaf_count = effect.next_leaf_count;
    }

    Ok(planned)
}

fn apply_actions_to_memory(state: &mut NativeState, actions: &[PendingAction]) -> Result<()> {
    let planned = plan_action_effects_for_memory(state, actions)?;
    for (action, effect) in actions.iter().zip(planned.iter()) {
        for (offset, commitment) in action.commitments.iter().enumerate() {
            let expected_index = effect
                .commitment_start
                .checked_add(offset as u64)
                .expect("planned commitment index arithmetic must not overflow");
            debug_assert_eq!(
                expected_index,
                state.commitment_tree.leaf_count(),
                "planned commitment index drifted during memory replay"
            );
            state
                .commitment_tree
                .append(*commitment)
                .map_err(|err| anyhow!("append native commitment failed: {err}"))?;
        }
        for nullifier in &action.nullifiers {
            state.nullifiers.insert(*nullifier);
        }
        if let Some(replay_key) = effect.replay_key {
            state.consumed_bridge_messages.insert(replay_key);
        }
        state.pending_actions.remove(&action.tx_hash);
    }
    Ok(())
}

fn rebuild_canonical_indexes(
    chain: &[NativeBlockMeta],
    commitment_tree: &sled::Tree,
    nullifier_tree: &sled::Tree,
    bridge_inbound_tree: &sled::Tree,
    ciphertext_index_tree: &sled::Tree,
    ciphertext_archive_tree: &sled::Tree,
    da_ciphertext_tree: &sled::Tree,
) -> Result<()> {
    let mut next_commitment_index = 0u64;
    let mut nullifier_state = NullifierState::default();
    let mut bridge_replay_state = InboundReplayState::default();
    let mut planned_actions = Vec::new();
    for meta in chain.iter().skip(1) {
        let actions = decode_block_actions(meta)?;
        for action in actions {
            let ciphertexts = canonical_ciphertexts_for_action(da_ciphertext_tree, &action)?;
            let replay_key = bridge_inbound_replay_key_from_action(&action)?;
            let effect = evaluate_native_action_state_effect(
                next_commitment_index,
                action.commitments.len(),
                ciphertexts.len(),
                &action.nullifiers,
                replay_key,
                &mut nullifier_state,
                &mut bridge_replay_state,
            )
            .map_err(native_action_state_effect_error)?;
            planned_actions.push((
                action,
                NativePlannedActionEffect {
                    commitment_start: next_commitment_index,
                    ciphertexts,
                    replay_key,
                },
            ));
            next_commitment_index = effect.next_leaf_count;
        }
    }

    for (action, effect) in planned_actions {
        for (offset, commitment) in action.commitments.iter().enumerate() {
            let offset =
                u64::try_from(offset).map_err(|_| anyhow!("commitment rebuild offset overflow"))?;
            let index = effect
                .commitment_start
                .checked_add(offset)
                .ok_or_else(|| anyhow!("commitment rebuild index overflow"))?;
            commitment_tree.insert(index.to_be_bytes(), commitment.as_slice())?;
        }
        insert_ciphertext_archive_entries(
            ciphertext_archive_tree,
            effect.commitment_start,
            &effect.ciphertexts,
        )?;
        for nullifier in &action.nullifiers {
            nullifier_tree.insert(nullifier.as_slice(), b"1")?;
        }
        if let Some(replay_key) = effect.replay_key {
            bridge_inbound_tree.insert(replay_key.as_slice(), b"1")?;
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
            ciphertext_index_tree.insert(hash.as_slice(), value)?;
        }
    }
    Ok(())
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
            .map(|hash| {
                da_ciphertext_tree
                    .get(hash.as_slice())?
                    .map(|bytes| bytes.to_vec())
                    .ok_or_else(|| anyhow!("missing canonical DA ciphertext {}", hex48(hash)))
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
    let mut bridge_replay_state =
        InboundReplayState::new(state.consumed_bridge_messages.clone(), BTreeSet::new());
    let mut nullifier_state = NullifierState::new(state.nullifiers.clone(), BTreeSet::new());
    let mut next_leaf_count = state.commitment_tree.leaf_count();
    let mut planned = Vec::with_capacity(actions.len());

    for action in actions {
        let ciphertexts = canonical_ciphertexts_for_action(da_ciphertext_tree, action)?;
        let replay_key = bridge_inbound_replay_key_from_action(action)?;
        let effect = evaluate_native_action_state_effect(
            next_leaf_count,
            action.commitments.len(),
            ciphertexts.len(),
            &action.nullifiers,
            replay_key,
            &mut nullifier_state,
            &mut bridge_replay_state,
        )
        .map_err(native_action_state_effect_error)?;
        planned.push(NativePlannedActionEffect {
            commitment_start: next_leaf_count,
            ciphertexts,
            replay_key,
        });
        next_leaf_count = effect.next_leaf_count;
    }

    Ok(planned)
}

fn insert_ciphertext_archive_entries(
    tree: &sled::Tree,
    start_index: u64,
    ciphertexts: &[Vec<u8>],
) -> Result<()> {
    for (offset, bytes) in ciphertexts.iter().enumerate() {
        let index = start_index
            .checked_add(offset as u64)
            .ok_or_else(|| anyhow!("ciphertext archive index overflow"))?;
        tree.insert(index.to_be_bytes(), bytes.as_slice())?;
    }
    Ok(())
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
    } else if !input.version_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::VersionMismatch)
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
        NativeTxLeafActionBindingAdmissionRejection::VersionMismatch => {
            anyhow!("native tx-leaf version mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::CiphertextPayloadHashMismatch => {
            anyhow!("native tx ciphertext payload hash mismatch")
        }
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
) -> Result<()> {
    let transfers = actions
        .iter()
        .filter(|action| is_shielded_transfer_action(action))
        .collect::<Vec<_>>();
    let candidate_artifacts = actions
        .iter()
        .filter(|action| is_candidate_artifact_action(action))
        .filter_map(|action| action.candidate_artifact.as_ref())
        .collect::<Vec<_>>();
    let coupling_input =
        native_candidate_artifact_coupling_admission_input(transfers.len(), &candidate_artifacts);
    if let Err(rejection) = evaluate_native_candidate_artifact_coupling_admission(coupling_input) {
        return Err(native_candidate_artifact_coupling_admission_error(
            rejection,
        ));
    }
    if transfers.is_empty() {
        return Ok(());
    }

    let [artifact] = candidate_artifacts.as_slice() else {
        return Err(anyhow!(
            "non-empty shielded block requires exactly one matching recursive candidate artifact"
        ));
    };
    if artifact.tx_count as usize != transfers.len() {
        return Err(anyhow!("candidate artifact tx_count mismatch"));
    }

    let mut transactions = Vec::with_capacity(transfers.len());
    let mut artifacts = Vec::with_capacity(transfers.len());
    for action in &transfers {
        let (tx, artifact) = consensus_tx_and_artifact_from_action(node, action)?;
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

    let expected_tree = preview_commitment_tree(&state.commitment_tree, &transfers)?;
    let mut expected_nullifiers = state.nullifiers.clone();
    for action in &transfers {
        for nullifier in &action.nullifiers {
            expected_nullifiers.insert(*nullifier);
        }
    }
    let expected_nullifier_root = nullifier_root_from_set(&expected_nullifiers);
    let height = evaluate_native_recursive_artifact_context_admission(
        NativeRecursiveArtifactContextAdmissionInput {
            best_height: state.best.height,
        },
    )
    .map_err(native_recursive_artifact_context_admission_error)?;
    let header = consensus::BlockHeader {
        version: 1,
        height,
        view: 0,
        timestamp_ms: current_time_ms().max(state.best.timestamp_ms.saturating_add(1)),
        parent_hash: state.best.hash,
        state_root: expected_tree.root(),
        kernel_root: consensus::types::kernel_root_from_shielded_root(&expected_tree.root()),
        nullifier_root: expected_nullifier_root,
        proof_commitment: consensus::types::compute_proof_commitment(&transactions),
        da_root: computed_da_root,
        da_params,
        version_commitment: consensus::types::compute_version_commitment(&transactions),
        tx_count: transactions.len() as u32,
        fee_commitment: consensus::types::compute_fee_commitment(&transactions),
        supply_digest: state.best.supply_digest,
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
    node: &NativeNode,
    action: &PendingAction,
) -> Result<(Transaction, TxValidityArtifact)> {
    let (proof_bytes, ciphertexts) = transfer_proof_and_ciphertexts(node, action)?;
    let decoded = consensus::backend_interface::decode_native_tx_leaf_artifact_bytes(&proof_bytes)
        .map_err(|err| anyhow!("decode native tx-leaf artifact failed: {err}"))?;
    let action_version: consensus::VersionBinding = action.binding.into();
    let tx = Transaction::new(
        action.nullifiers.clone(),
        action.commitments.clone(),
        decoded.tx.balance_tag,
        action_version,
        ciphertexts,
    );
    if let Err(rejection) =
        evaluate_native_tx_leaf_action_binding_admission(NativeTxLeafActionBindingAdmissionInput {
            nullifiers_match: decoded.tx.nullifiers == action.nullifiers,
            commitments_match: decoded.tx.commitments == action.commitments,
            ciphertext_hashes_match: decoded.tx.ciphertext_hashes == action.ciphertext_hashes,
            version_matches: decoded.tx.version == action_version,
            ciphertext_payload_hashes_match: tx.ciphertext_hashes == action.ciphertext_hashes,
        })
    {
        return Err(native_tx_leaf_action_binding_admission_error(rejection));
    }
    let artifact = consensus::proof::tx_validity_artifact_from_native_tx_leaf_bytes(proof_bytes)
        .map_err(|err| anyhow!("native tx-leaf artifact build failed: {err}"))?;
    Ok((tx, artifact))
}

fn transfer_proof_and_ciphertexts(
    node: &NativeNode,
    action: &PendingAction,
) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    if !is_shielded_transfer_action(action) {
        return Err(anyhow!("action is not a shielded transfer"));
    }
    match action.action_id {
        ACTION_SHIELDED_TRANSFER_INLINE => {
            let args: ShieldedTransferInlineArgs =
                decode_scale_exact(&action.public_args, "shielded inline action args")?;
            let ciphertexts = args
                .ciphertexts
                .iter()
                .map(|note| {
                    let mut bytes =
                        Vec::with_capacity(note.ciphertext.len() + note.kem_ciphertext.len());
                    bytes.extend_from_slice(&note.ciphertext);
                    bytes.extend_from_slice(&note.kem_ciphertext);
                    bytes
                })
                .collect();
            Ok((args.proof, ciphertexts))
        }
        ACTION_SHIELDED_TRANSFER_SIDECAR => {
            let args: ShieldedTransferSidecarArgs =
                decode_scale_exact(&action.public_args, "shielded sidecar action args")?;
            let mut ciphertexts = Vec::with_capacity(args.ciphertext_hashes.len());
            for hash in &args.ciphertext_hashes {
                let bytes = node
                    .da_ciphertext_tree
                    .get(hash.as_slice())?
                    .ok_or_else(|| anyhow!("missing DA ciphertext {}", hex48(hash)))?;
                ciphertexts.push(bytes.to_vec());
            }
            Ok((args.proof, ciphertexts))
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

fn nullifier_root_from_set(nullifiers: &BTreeSet<[u8; 48]>) -> [u8; 48] {
    let mut bytes = Vec::with_capacity(nullifiers.len() * 48);
    for nullifier in nullifiers {
        bytes.extend_from_slice(nullifier);
    }
    crypto::hashes::blake3_384(&bytes)
}

fn preview_pending_roots(
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

    let planned = plan_action_effects_for_memory(state, actions)?;
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
            debug_assert_eq!(
                expected_index,
                tree.leaf_count(),
                "planned commitment index drifted during root preview"
            );
            tree.append(*commitment)
                .map_err(|err| anyhow!("preview commitment append failed: {err}"))?;
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
    verify_native_pow_meta(parent, meta)
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

fn verify_native_pow_meta(parent: &NativeBlockMeta, meta: &NativeBlockMeta) -> Result<()> {
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
        "hegemon_startMining" | "hegemon_stopMining" | "da_submitCiphertexts" | "da_submitProofs"
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

fn decode_scale_exact<T: Decode>(bytes: &[u8], label: &str) -> Result<T> {
    let mut cursor = bytes;
    let value = T::decode(&mut cursor).map_err(|err| anyhow!("decode {label} failed: {err:?}"))?;
    if !cursor.is_empty() {
        return Err(anyhow!(
            "{label} has {} trailing bytes after SCALE decode",
            cursor.len()
        ));
    }
    Ok(value)
}

fn bincode_deserialize_exact<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T> {
    let mut cursor = Cursor::new(bytes);
    let value: T = bincode::deserialize_from(&mut cursor)
        .map_err(|err| anyhow!("decode {label} failed: {err}"))?;
    if cursor.position() as usize != bytes.len() {
        return Err(anyhow!(
            "{label} has {} trailing bytes after bincode decode",
            bytes.len().saturating_sub(cursor.position() as usize)
        ));
    }
    Ok(value)
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
        version_matches: bool,
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
        commitment_count: usize,
        ciphertext_count: usize,
        nullifier_count: usize,
        nullifier_state: String,
        bridge_replay_state: String,
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
        expected_imported_bridge_replay: Option<bool>,
        expected_supply: Option<String>,
        expected_valid: bool,
        expected_rejection: Option<String>,
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

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanProofSidecarDecodedCase {
        name: String,
        proof_bytes: usize,
        max_proof_bytes: usize,
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
        let args = ShieldedTransferInlineArgs {
            proof: vec![9u8; 32],
            commitments: vec![commitment],
            ciphertexts: vec![note],
            anchor,
            balance_slot_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
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
        assert!(err.to_string().contains("native tx-leaf artifact"));
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
        let note = protocol_shielded_pool::types::EncryptedNote {
            ciphertext: [11u8; protocol_shielded_pool::types::ENCRYPTED_NOTE_SIZE],
            kem_ciphertext: vec![12u8; 32],
        };
        let commitment = [13u8; 48];
        let args = MintCoinbaseArgs {
            reward_bundle: protocol_shielded_pool::types::BlockRewardBundle {
                miner_note: protocol_shielded_pool::types::CoinbaseNoteData {
                    commitment,
                    encrypted_note: note,
                    recipient_address: [14u8;
                        protocol_shielded_pool::types::DIVERSIFIED_ADDRESS_SIZE],
                    amount: reward,
                    public_seed: [15u8; 32],
                },
            },
        };
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

        let binding_hash = format!("0x{}", "11".repeat(64));
        let proofs = node
            .submit_proofs(json!({
                "proofs": [{ "binding_hash": binding_hash, "proof": "0x010203" }]
            }))
            .expect("valid proof sidecar should stage");
        let proofs = proofs.as_array().expect("proof result should be array");
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0]["size"].as_u64(), Some(3));
        assert!(proofs[0]["proof_hash"].as_str().unwrap().starts_with("0x"));

        let replacement_binding_hash = format!("0x{}", "11".repeat(64));
        node.submit_proofs(json!({
            "proofs": [{ "binding_hash": replacement_binding_hash, "proof": "0x01020304" }]
        }))
        .expect("same binding hash replacement should be accepted");

        let state = node.state.read();
        assert_eq!(state.staged_ciphertexts.len(), 1);
        assert_eq!(state.staged_proofs.len(), 1);
        assert_eq!(state.staged_proofs.values().next().unwrap().len(), 4);
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
            case.parser_accepts && case.consumed_all_bytes,
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
            (codec, fixture) => {
                panic!("unknown Lean exact-decode case codec={codec} fixture={fixture}")
            }
        };
        let actual_rejection = actual.as_ref().err().map(|err| {
            if err.to_string().contains("trailing bytes") {
                "trailing_bytes".to_owned()
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
            version_matches: case.version_matches,
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
            version_matches: true,
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
                    ciphertext_payload_hashes_match: false,
                    ..valid
                }
            )
            .expect_err("version mismatch must reject before payload hashes")
            .label(),
            "version_mismatch"
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
        let (spent_nullifiers, nullifiers) = synthetic_action_effect_nullifiers(
            &case.nullifier_state,
            case.nullifier_count,
            &case.name,
        );
        let (consumed_replays, replay_key) =
            synthetic_action_effect_replay(&case.bridge_replay_state, &case.name);
        let mut nullifier_state = NullifierState::new(spent_nullifiers, BTreeSet::new());
        let mut bridge_replay_state = InboundReplayState::new(consumed_replays, BTreeSet::new());
        let input = NativeBlockReplayRefinementInput {
            leaf_start: case.leaf_start,
            commitment_count: case.commitment_count,
            ciphertext_count: case.ciphertext_count,
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

        let actual = evaluate_native_block_replay_refinement(
            input,
            &nullifiers,
            replay_key,
            &mut nullifier_state,
            &mut bridge_replay_state,
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
                    Some(summary.imported_bridge_replay),
                    case.expected_imported_bridge_replay,
                    "{} replay imported bridge flag drifted from Lean spec",
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

        let loaded = load_staged_sizes(&tree).expect("load staged ciphertext sizes");

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

        let loaded = load_staged_sizes(&tree).expect("load staged ciphertext sizes");

        assert!(loaded.is_empty());
        assert!(tree
            .get(wrong_hash.as_slice())
            .expect("read dropped ciphertext")
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
            load_staged_sizes_with_limits(&tree, MAX_NATIVE_STAGED_CIPHERTEXTS, raw.len() - 1)
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

        let loaded = load_staged_sizes_with_limits(&tree, 1, MAX_CIPHERTEXT_BYTES)
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
        let binding_hash = [1u8; 64];
        let proof = vec![9u8, 8, 7];
        tree.insert(binding_hash.as_slice(), proof.as_slice())
            .expect("insert staged proof");

        let loaded = load_staged_proofs(&tree).expect("load staged proofs");

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

        let loaded = load_staged_proofs(&tree).expect("load staged proofs");

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

        let loaded = load_staged_proofs(&tree).expect("load staged proofs");

        assert!(loaded.is_empty());
        assert!(tree
            .get(binding_hash.as_slice())
            .expect("read dropped proof")
            .is_none());
    }

    #[test]
    fn load_staged_proofs_drops_oversized_proof() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db.open_tree("staged_proofs").expect("staged proof tree");
        let binding_hash = [3u8; 64];
        let proof = vec![5u8; 5];
        tree.insert(binding_hash.as_slice(), proof.as_slice())
            .expect("insert oversized staged proof");

        let loaded = load_staged_proofs_with_limits(
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
    fn load_staged_proofs_drops_capacity_overflow() {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db");
        let tree = db.open_tree("staged_proofs").expect("staged proof tree");
        let first_key = [1u8; 64];
        let second_key = [2u8; 64];
        tree.insert(first_key.as_slice(), [1u8].as_slice())
            .expect("insert first staged proof");
        tree.insert(second_key.as_slice(), [2u8].as_slice())
            .expect("insert second staged proof");

        let loaded = load_staged_proofs_with_limits(
            &tree,
            1,
            NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
            MAX_NATIVE_STAGED_PROOF_BYTES,
        )
        .expect("load staged proofs");

        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key(&hex64(&first_key)));
        assert_eq!(tree.len(), 1);
        assert!(tree
            .get(second_key.as_slice())
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
        let first_key = [1u8; 64];
        let second_key = [2u8; 64];
        tree.insert(first_key.as_slice(), [1u8, 2].as_slice())
            .expect("insert first staged proof");
        tree.insert(second_key.as_slice(), [3u8, 4, 5, 6].as_slice())
            .expect("insert second staged proof");

        let loaded = load_staged_proofs_with_limits(
            &tree,
            MAX_NATIVE_STAGED_PROOFS,
            NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
            5,
        )
        .expect("load staged proofs");

        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key(&hex64(&first_key)));
        assert_eq!(tree.len(), 1);
        assert!(tree
            .get(second_key.as_slice())
            .expect("read dropped proof")
            .is_none());
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

        let err = apply_actions_to_memory(&mut state, &[first, second])
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

        let err = preview_pending_roots(&state, &[first, second])
            .expect_err("duplicate bridge replay must reject before root preview");
        assert!(err.to_string().contains("bridge_replay_duplicate"));
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

        let err = rebuild_canonical_indexes(
            &[genesis, block],
            &commitment_tree,
            &nullifier_tree,
            &bridge_inbound_tree,
            &ciphertext_index_tree,
            &ciphertext_archive_tree,
            &da_ciphertext_tree,
        )
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
            ciphertext_archive_tree.len(),
            0,
            "failed rebuild must not partially write ciphertext archive entries"
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

        let err = verify_native_block_artifacts_locked(&node, &state, &[action])
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

        let err = verify_native_block_artifacts_locked(&node, &state, &[transfer])
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

        let err = verify_native_block_artifacts_locked(&node, &state, &actions)
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

        let err = verify_native_block_artifacts_locked(&node, &state, &actions)
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
    fn coinbase_action_rejects_zero_commitment() {
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
        assert!(err.to_string().contains("zero coinbase commitment"));
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
        let bridge_messages = bridge_messages_from_actions(&[bridge], 1);
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
        let messages = bridge_messages_from_actions(&actions, imported.height);
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
            tx_count: 0,
            timestamp_ms,
            pow_bits,
        };
        let seal = mine_native_round(work, round).expect("side seal");
        NativeBlockMeta {
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
        }
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
            tx_count: 0,
            timestamp_ms,
            pow_bits,
        };
        let seal = mine_native_round(work, round).expect("mutated seal");
        NativeBlockMeta {
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
        }
    }

    fn mined_child_with_actions(
        parent: &NativeBlockMeta,
        height: u64,
        pow_bits: u32,
        round: u64,
        actions: Vec<PendingAction>,
    ) -> NativeBlockMeta {
        let parent_state = test_state(parent.clone());
        let (state_root, nullifier_root, extrinsics_root, tx_count) =
            preview_pending_roots(&parent_state, &actions).expect("preview action roots");
        let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
        let bridge_messages = bridge_messages_from_actions(&actions, height);
        let message_root = bridge_message_root(&bridge_messages);
        let message_count = u32::try_from(bridge_messages.len()).expect("message count");
        let header_history = vec![parent.hash];
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
            tx_count,
            timestamp_ms: parent.timestamp_ms.saturating_add(1),
            pow_bits,
        };
        let seal = mine_native_round(work, round).expect("action child seal");
        NativeBlockMeta {
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
        }
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

    fn test_inline_transfer_action(
        anchor: [u8; 48],
        nullifier: [u8; 48],
        commitment: [u8; 48],
        fee: u64,
    ) -> PendingAction {
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
            fee,
            value_balance: 0,
            stablecoin: None,
        };
        let binding_hash = StarkVerifier::compute_binding_hash(&inputs).data;
        let args = ShieldedTransferInlineArgs {
            proof: vec![9u8; 32],
            commitments: vec![commitment],
            ciphertexts: vec![note],
            anchor,
            balance_slot_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
            binding_hash,
            stablecoin: None,
            fee,
        };
        let ciphertext_size = u32::try_from(
            args.ciphertexts[0].ciphertext.len() + args.ciphertexts[0].kem_ciphertext.len(),
        )
        .expect("ciphertext size");
        let mut action = PendingAction {
            tx_hash: [0u8; 32],
            binding: KernelVersionBinding {
                circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
                crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            },
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
        let inline = test_inline_transfer_action(anchor, nullifier, commitment, fee);
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
        let note = protocol_shielded_pool::types::EncryptedNote {
            ciphertext: [11u8; protocol_shielded_pool::types::ENCRYPTED_NOTE_SIZE],
            kem_ciphertext: vec![12u8; 32],
        };
        let commitment = [13u8; 48];
        let args = MintCoinbaseArgs {
            reward_bundle: protocol_shielded_pool::types::BlockRewardBundle {
                miner_note: protocol_shielded_pool::types::CoinbaseNoteData {
                    commitment,
                    encrypted_note: note,
                    recipient_address: [14u8;
                        protocol_shielded_pool::types::DIVERSIFIED_ADDRESS_SIZE],
                    amount,
                    public_seed: [15u8; 32],
                },
            },
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

    fn stage_test_coinbase(node: &NativeNode, amount: u64, commitment: [u8; 48]) {
        use base64::Engine;

        let note = protocol_shielded_pool::types::EncryptedNote {
            ciphertext: [11u8; protocol_shielded_pool::types::ENCRYPTED_NOTE_SIZE],
            kem_ciphertext: vec![12u8; 32],
        };
        let args = MintCoinbaseArgs {
            reward_bundle: protocol_shielded_pool::types::BlockRewardBundle {
                miner_note: protocol_shielded_pool::types::CoinbaseNoteData {
                    commitment,
                    encrypted_note: note,
                    recipient_address: [14u8;
                        protocol_shielded_pool::types::DIVERSIFIED_ADDRESS_SIZE],
                    amount,
                    public_seed: [15u8; 32],
                },
            },
        };
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
