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
use bincode::Options;
use clap::Parser;
use codec::{Decode, Encode};
use consensus::{
    CommitmentTreeState, DaParams, ProofEnvelope, Transaction, TxValidityArtifact,
    COMMITMENT_TREE_DEPTH,
};
use consensus_light_client::{
    bridge_checkpoint_output_from_anchor, bridge_checkpoint_output_with_tip_from_anchor,
    canonical_bridge_checkpoint_output_bytes_v1, canonical_trusted_checkpoint_bytes_v1,
    compare_work, cumulative_work_after, decode_risc0_bridge_journal, empty_header_mmr_root,
    flyclient_sample_indices, hash_meets_target, header_mmr_append_peaks,
    header_mmr_opening_from_hashes, header_mmr_peaks_from_hashes, header_mmr_root_from_hashes,
    header_mmr_root_from_peaks, pow_hash_from_pre_hash, verify_pow_header_with_expected_bits,
    BridgeCheckpointOutputV1, BridgeMessageV1, Hash32, HeaderMmrLeafWitnessV1,
    HegemonLightClientProofReceiptV1, HegemonLongRangeProofV1, PowHeaderV1,
    RiscZeroBridgeReceiptV1, TrustedCheckpointV1, HEGEMON_BRIDGE_LONG_RANGE_MIN_SAMPLE_COUNT_V1,
    HEGEMON_BRIDGE_LONG_RANGE_MIN_TIP_WORK_V1, HEGEMON_CHAIN_ID_V1,
    HEGEMON_LIGHT_CLIENT_RULES_HASH_V1, HEGEMON_LONG_RANGE_PROOF_MAX_MESSAGE_PAYLOAD_BYTES_V1,
    HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V1, HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1,
};
use crypto::ml_dsa::{
    MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, ML_DSA_PUBLIC_KEY_LEN, ML_DSA_SIGNATURE_LEN,
};
use crypto::traits::{Signature, SigningKey, VerifyKey};
use network::{
    p2p::WireMessage,
    service::{ConnectedPeerSnapshot, DirectedProtocolMessage, ProtocolSender},
    wire, GossipRouter, NatTraversalConfig, P2PService, PeerId, PeerIdentity, PeerStore,
    PeerStoreConfig, ProtocolHandle, ProtocolId, ProtocolMessage, RelayConfig,
};
use parking_lot::{Mutex, RwLock};
use protocol_kernel::manifest::{
    kernel_manifest, protocol_manifest, StablecoinPolicyManifestEntry,
};
use protocol_kernel::types::KernelVersionBinding;
use protocol_kernel::{
    bridge_message_root, bridge_payload_hash, empty_bridge_message_root, inbound_replay_key,
    BridgeMintPayloadV1, BridgeVerifierRegistrationV1, InboundBridgeArgsV1, InboundReplayReject,
    InboundReplayState, OutboundBridgeArgsV1, ACTION_BRIDGE_INBOUND, ACTION_BRIDGE_OUTBOUND,
    ACTION_REGISTER_BRIDGE_VERIFIER, BRIDGE_MINT_APP_FAMILY_ID_V1, BRIDGE_MINT_PAYLOAD_VERSION_V1,
    FAMILY_BRIDGE,
};
use protocol_shielded_pool::family::{
    MintCoinbaseArgs, ShieldedTransferInlineArgs, ShieldedTransferSidecarArgs,
    SubmitCandidateArtifactArgs, ACTION_MINT_COINBASE, ACTION_SHIELDED_TRANSFER_INLINE,
    ACTION_SHIELDED_TRANSFER_SIDECAR, ACTION_SUBMIT_CANDIDATE_ARTIFACT, FAMILY_SHIELDED_POOL,
};
use protocol_shielded_pool::types::{
    BlockProofMode, BlockRewardBundle, CandidateArtifact, CoinbaseNoteData, EncryptedNote,
    ProofArtifactKind as PoolProofArtifactKind, RecursiveBlockProofPayload,
    StablecoinPolicyBinding, StarkProof, BLOCK_PROOF_BUNDLE_SCHEMA, DIVERSIFIED_ADDRESS_SIZE,
    ENCRYPTED_NOTE_SIZE, MAX_BATCH_SIZE, MAX_CIPHERTEXT_BYTES, NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
    RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE,
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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};
use tower::limit::ConcurrencyLimitLayer;
use tracing::{debug, info, warn};
use transaction_circuit::hashing_pq::felts_to_bytes48;
use transaction_core::hashing_pq::ciphertext_hash_bytes;
use wallet::{NoteCiphertext, NotePlaintext, ShieldedAddress};

const META_BEST_KEY: &[u8] = b"best";
const META_GENESIS_KEY: &[u8] = b"genesis";
const NATIVE_DEV_POW_BITS: u32 = consensus::reward::GENESIS_BITS;
const NATIVE_GENESIS_TIMESTAMP_MS: u64 = 1_782_840_600_000;
const HASHES_PER_ROUND: u64 = 16_384;
const MINING_ROUNDS_PER_WORK: u64 = 16;
const DEFAULT_DA_CHUNK_SIZE: u32 = 1024;
const DEFAULT_DA_SAMPLE_COUNT: u32 = 4;
const DEFAULT_BRIDGE_FLYCLIENT_SAMPLE_COUNT: u32 = HEGEMON_BRIDGE_LONG_RANGE_MIN_SAMPLE_COUNT_V1;
const MIN_INBOUND_BRIDGE_CONFIRMATIONS: u32 = 2;
const NATIVE_RISC0_RECEIPT_VERIFIER_ENABLED: bool = false;
const NATIVE_PQ_CLEAN_BRIDGE_VERIFIER_BOUND: bool = false;
const NATIVE_EXTERNAL_BRIDGE_VERIFIER_SOUNDNESS_ACCEPTED: bool = false;
const NATIVE_POSITIVE_INBOUND_BRIDGE_MINT_ENABLED: bool = false;
const MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS: u64 = 4_096;
const MAX_NATIVE_BRIDGE_PROOF_RECEIPT_BYTES: usize = 512 * 1024;
const MAX_NATIVE_BRIDGE_MESSAGE_PAYLOAD_BYTES: usize =
    HEGEMON_LONG_RANGE_PROOF_MAX_MESSAGE_PAYLOAD_BYTES_V1;
const MAX_NATIVE_BRIDGE_ACTION_DYNAMIC_BYTES: usize =
    MAX_NATIVE_BRIDGE_PROOF_RECEIPT_BYTES + MAX_NATIVE_BRIDGE_MESSAGE_PAYLOAD_BYTES;
const MAX_NATIVE_BRIDGE_MINT_AMOUNT: u64 = i64::MAX as u64;
const MAX_NATIVE_MEMPOOL_ACTIONS: usize = 10_000;
const MAX_PREPARED_MINING_WORKS: usize = 128;
const MAX_PREPARED_CANDIDATE_ACTIONS: usize = 128;
const NATIVE_SYNC_PROTOCOL_ID: ProtocolId = 0x4847_4e53;
const MAX_NATIVE_SYNC_RESPONSE_BLOCKS: u64 = 256;
const MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE: usize = MAX_NATIVE_SYNC_RESPONSE_BLOCKS as usize;
const NATIVE_SYNC_REQUEST_BLOCKS: u64 = 64;
const MAX_NATIVE_SYNC_IMPORT_BATCH_BLOCKS: usize = 32;
const NATIVE_SYNC_BEST_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(2);
const NATIVE_SYNC_PENDING_ACTION_REBROADCAST_INTERVAL: Duration = Duration::from_secs(5);
const NATIVE_SYNC_PENDING_ACTION_REBROADCAST_LIMIT: usize = 8;
const NATIVE_SYNC_PENDING_ACTION_REBROADCAST_BYTES: usize = 8 * 1024 * 1024;
const NATIVE_SYNC_REQUEST_RATE_WINDOW: Duration = Duration::from_secs(10);
// Sync responses carry full native block metadata. Keep one live request in
// flight, but retry quickly enough that a dropped response does not freeze
// fresh-node catch-up for minutes.
const NATIVE_SYNC_REQUEST_RETRY_AFTER: Duration = Duration::from_secs(20);
const MAX_NATIVE_SYNC_REQUESTS_PER_WINDOW: u32 = 4;
const NATIVE_SYNC_REQUEST_RATE_LIMIT_STATE_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_NATIVE_SYNC_REQUEST_RATE_LIMIT_PEERS: usize = 4096;
const NATIVE_SYNC_REORG_BACKFILL_BLOCKS: u64 = 32;
const NATIVE_SYNC_BOOTSTRAP_BACKFILL_FLOOR: u64 = 1;
const NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS: u64 = MAX_NATIVE_SYNC_RESPONSE_BLOCKS - 1;
const APPROVED_PUBLIC_JOIN_SEED_OVH: &str = "hegemon.pauli.group:30333";
const APPROVED_PUBLIC_JOIN_SEED_DEV: &str = "devnet.hegemonprotocol.com:30333";
const APPROVED_PUBLIC_JOIN_SEEDS: &str =
    "hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333";
const AES_GCM_TAG_BYTES: usize = 16;
const PQ_IDENTITY_SEED_FILE: &str = "pq-identity.seed";
const PQ_IDENTITY_SEED_LEN: usize = 32;
const MINER_IDENTITY_SEED_FILE: &str = "miner-identity.seed";
const MAX_NATIVE_RPC_ACTION_BYTES: usize = 2 * 1024 * 1024;
const MAX_NATIVE_CHAIN_GET_BLOCK_ACTION_BYTES: usize = 2 * 1024 * 1024;
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
const MAX_NATIVE_RPC_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_NATIVE_RPC_CONCURRENT_REQUESTS: usize = 8;
const MAX_NATIVE_MEMPOOL_ACTION_BYTES: usize = 64 * 1024 * 1024;
const MAX_NATIVE_BLOCK_ACTIONS: usize = MAX_NATIVE_MEMPOOL_ACTIONS;
const MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES: usize = MAX_NATIVE_RPC_ACTION_BYTES + 16 * 1024;
const MAX_NATIVE_BLOCK_ACTION_BYTES: usize = MAX_NATIVE_MEMPOOL_ACTION_BYTES;
const MAX_NATIVE_BLOCK_META_BYTES: usize =
    MAX_NATIVE_BLOCK_ACTION_BYTES + (MAX_NATIVE_BLOCK_ACTIONS * 32) + 1024 * 1024;
const MAX_NATIVE_SYNC_MESSAGE_BYTES: usize = wire::MAX_WIRE_FRAME_LEN;
const MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES: usize = wire::MAX_WIRE_FRAME_LEN / 2;
const MAX_NATIVE_SYNC_PENDING_ACTION_BYTES: usize = MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES;
const MAX_NATIVE_MINING_THREADS: u32 = 64;
const NATIVE_MINING_BACKGROUND_THREAD_CAP: u32 = 2;
const NATIVE_MINING_RESERVED_SERVICE_THREADS: u32 = 3;
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
    /// CORS policy. Default is no browser cross-origin access; set explicitly for trusted UIs.
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
    pub bootstrap_mining_authoring: bool,
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
        let bootstrap_mining_authoring = env_bool("HEGEMON_BOOTSTRAP_AUTHORING");
        if mine && !cli.dev && seeds.is_empty() && !bootstrap_mining_authoring {
            return Err(anyhow!(
                "refusing live mining with empty HEGEMON_SEEDS; set HEGEMON_SEEDS=\"{}\" or explicitly set HEGEMON_BOOTSTRAP_AUTHORING=1 for a deliberate first-author bootstrap",
                APPROVED_PUBLIC_JOIN_SEEDS
            ));
        }
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
            bootstrap_mining_authoring,
            miner_address,
            pow_bits,
        })
    }

    fn permits_empty_seed_authoring(&self) -> bool {
        self.dev || self.bootstrap_mining_authoring
    }

    fn public_testnet_profile(&self) -> bool {
        if !self.dev || self.tmp {
            return false;
        }
        self.seeds.iter().any(|seed| {
            let seed = seed.trim();
            seed.eq_ignore_ascii_case(APPROVED_PUBLIC_JOIN_SEED_OVH)
                || seed.eq_ignore_ascii_case(APPROVED_PUBLIC_JOIN_SEED_DEV)
        }) || (self.bootstrap_mining_authoring
            && self
                .base_path
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("testnet"))
    }

    fn chain_spec_id(&self) -> &'static str {
        if self.public_testnet_profile() {
            "hegemon-native-testnet"
        } else if self.dev {
            "hegemon-native-dev"
        } else {
            "hegemon-native"
        }
    }

    fn chain_type(&self) -> &'static str {
        if self.public_testnet_profile() {
            "testnet"
        } else if self.dev {
            "dev"
        } else {
            "live"
        }
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
    prepared_actions: Option<Arc<Vec<PendingAction>>>,
}

#[derive(Clone, Debug)]
struct NativeSeal {
    nonce: [u8; 32],
    work_hash: [u8; 32],
}

#[derive(Clone, Debug)]
struct NativeMiningRoundResult {
    seal: Option<NativeSeal>,
    hashes: u64,
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
    PendingAction {
        action: Vec<u8>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct NativeSyncRange {
    from_height: u64,
    to_height: u64,
}

fn native_sync_ranges_overlap(left: NativeSyncRange, right: NativeSyncRange) -> bool {
    left.from_height <= right.to_height && right.from_height <= left.to_height
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
struct NativeSyncRequestRateAdmissionInput {
    requests_in_window: u32,
    max_requests: u32,
    window_elapsed_ms: u64,
    window_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeSyncBlockRangePublicationAdmissionInput {
    range_admitted: bool,
    served_count_matches_range: bool,
    first_height_matches_range: bool,
    last_height_matches_range: bool,
    served_heights_contiguous: bool,
    previous_parent_anchor_verified: bool,
    parent_hashes_contiguous: bool,
    canonical_rows_verified: bool,
    action_bodies_verified: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeSyncAdmissionRejection {
    ResponseBlockCountTooLarge,
    RequestRateLimited,
}

impl NativeSyncAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::ResponseBlockCountTooLarge => "response_block_count_too_large",
            Self::RequestRateLimited => "request_rate_limited",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct NativeSyncRequestRateState {
    window_start: Instant,
    requests: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeSyncResponseStart {
    Started,
    DuplicateRange,
}

#[derive(Clone, Debug)]
struct NativeOutboundSyncRequest {
    range: NativeSyncRange,
    requested_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeMiningSyncEvidenceInput {
    verified_new_progress: bool,
    verified_known_at_or_below_local_best: bool,
    local_best_height: u64,
    peer_best_height: u64,
    stopped_on_error: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeMiningGateInput {
    has_seeds: bool,
    dev: bool,
    bootstrap_mining_authoring: bool,
    observed_gate_open: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeSyncResponseImportOutcome {
    Imported,
    AlreadyKnown,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeSyncResponseImportProgress {
    had_blocks: bool,
    response_block_count: usize,
    attempted_blocks: usize,
    imported_blocks: u64,
    stopped_on_error: bool,
}

impl NativeSyncResponseImportProgress {
    fn new(response_block_count: usize) -> Self {
        Self {
            had_blocks: response_block_count > 0,
            response_block_count,
            attempted_blocks: 0,
            imported_blocks: 0,
            stopped_on_error: false,
        }
    }

    fn record(&mut self, outcome: NativeSyncResponseImportOutcome) -> bool {
        if self.stopped_on_error || self.attempted_blocks >= self.response_block_count {
            return false;
        }
        self.attempted_blocks += 1;
        match outcome {
            NativeSyncResponseImportOutcome::Imported => {
                self.imported_blocks = self.imported_blocks.saturating_add(1);
                true
            }
            NativeSyncResponseImportOutcome::AlreadyKnown => true,
            NativeSyncResponseImportOutcome::Error => {
                self.stopped_on_error = true;
                false
            }
        }
    }

    fn should_request_more(self, local_best_height: u64, peer_best_height: u64) -> bool {
        self.had_blocks && local_best_height < peer_best_height
    }

    fn completed_with_only_known_blocks(self) -> bool {
        self.had_blocks
            && self.attempted_blocks == self.response_block_count
            && self.imported_blocks == 0
            && !self.stopped_on_error
    }
}

fn native_sync_response_should_escalate_reorg_backfill(
    progress: NativeSyncResponseImportProgress,
    local_best_height: u64,
    peer_best_height: u64,
) -> bool {
    progress.had_blocks
        && !progress.stopped_on_error
        && !progress.completed_with_only_known_blocks()
        && local_best_height < peer_best_height
}

fn native_mining_sync_observed_peer_height(input: NativeMiningSyncEvidenceInput) -> Option<u64> {
    if input.stopped_on_error {
        return None;
    }
    if input.verified_new_progress {
        return Some(input.peer_best_height);
    }
    if input.verified_known_at_or_below_local_best
        && input.peer_best_height <= input.local_best_height
    {
        return Some(input.local_best_height);
    }
    None
}

fn native_mining_gate_allows_work(input: NativeMiningGateInput) -> bool {
    if input.has_seeds {
        input.observed_gate_open
    } else {
        input.dev || input.bootstrap_mining_authoring
    }
}

fn native_sync_catch_up_target(
    best_height: u64,
    sync_target_observed: bool,
    sync_target_height: u64,
) -> Option<(u64, u64)> {
    if sync_target_observed && sync_target_height > best_height {
        Some((best_height, sync_target_height))
    } else {
        None
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
    TransferStablecoinPolicyUnauthorized,
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
            Self::TransferStablecoinPolicyUnauthorized => "transfer_stablecoin_policy_unauthorized",
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
struct NativeBridgeActionResourceAdmissionInput {
    raw_byte_cap: usize,
    decoded_byte_cap: usize,
    item_count_cap: usize,
    item_byte_cap: usize,
    aggregate_byte_cap: usize,
    work_unit_cap: usize,
    action_kind: NativeBridgeActionPayloadKind,
    public_args_bytes: usize,
    outbound_payload_bytes: usize,
    inbound_proof_receipt_bytes: usize,
    inbound_message_payload_bytes: usize,
}

#[derive(Clone, Debug)]
struct NativeBridgeMintReplayPolicyInput {
    inbound_bridge_mint: bool,
    state_deltas_absent: bool,
    receipt_envelope_present: bool,
    receipt_verified: bool,
    receipt_payload_matches: bool,
    replay_state: InboundReplayState,
    replay_key: [u8; 48],
    mint_authorized: bool,
    amount_matches_receipt: bool,
    amount_within_bound: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeBridgeMintPayloadAdmissionInput {
    payload_decoded: bool,
    payload_hash_matches: bool,
    receipt_message_hash_matches: bool,
    version_matches: bool,
    source_app_family_matches: bool,
    destination_matches: bool,
    mint_nonce_matches: bool,
    recipient_commitment_nonzero: bool,
    amount_nonzero: bool,
    amount_within_bound: bool,
    asset_non_native: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeBridgeVerifierRegistrationPolicyInput {
    bridge_verifier_registration: bool,
    state_deltas_absent: bool,
    registration_decoded: bool,
    descriptor_matches_release: bool,
    activation_height_reached: bool,
    pq_clean_verifier_bound: bool,
    external_verifier_soundness_accepted: bool,
    positive_minting_enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeBridgeVerifierRegistrationPolicyEffect {
    registration_observed: bool,
    production_mint_verifier_enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeBridgeWitnessExportAdmissionInput {
    block_hash_parameter_valid: bool,
    explicit_block_hash: bool,
    block_known: bool,
    canonical_height_present: bool,
    block_is_canonical: bool,
    block_actions_decoded: bool,
    message_index_in_bounds: bool,
    parent_known: bool,
    best_height: u64,
    message_height: u64,
    max_explicit_history: u64,
    max_materialized_history: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeInboundBridgeReceiptAdmissionInput {
    source_chain_matches: bool,
    rules_hash_matches: bool,
    message_nonce_matches: bool,
    message_hash_matches: bool,
    checkpoint_height: u64,
    canonical_tip_height: u64,
    canonical_tip_work: [u8; 48],
    confirmations_checked: u32,
    min_confirmations: u32,
    min_work_checked: [u8; 48],
    min_tip_work: [u8; 48],
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
enum NativeBridgeMintReplayPolicyRejection {
    NotInboundBridgeMint,
    StateDeltaMintPresent,
    ReceiptEnvelopeMissing,
    ReceiptNotVerified,
    ReceiptPayloadMismatch,
    ReplayAlreadyConsumed,
    MintNotAuthorized,
    AmountDoesNotMatchReceipt,
    AmountOutOfBounds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeBridgeMintPayloadAdmissionRejection {
    PayloadDecodeFailed,
    PayloadHashMismatch,
    ReceiptMessageHashMismatch,
    VersionMismatch,
    SourceAppFamilyMismatch,
    DestinationMismatch,
    MintNonceMismatch,
    RecipientCommitmentZero,
    AmountZero,
    AmountOutOfBounds,
    NativeAssetNotAllowed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeBridgeVerifierRegistrationPolicyRejection {
    NotBridgeVerifierRegistration,
    StateDeltasPresent,
    RegistrationDecodeFailed,
}

impl NativeBridgeMintPayloadAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::PayloadDecodeFailed => "payload_decode_failed",
            Self::PayloadHashMismatch => "payload_hash_mismatch",
            Self::ReceiptMessageHashMismatch => "receipt_message_hash_mismatch",
            Self::VersionMismatch => "version_mismatch",
            Self::SourceAppFamilyMismatch => "source_app_family_mismatch",
            Self::DestinationMismatch => "destination_mismatch",
            Self::MintNonceMismatch => "mint_nonce_mismatch",
            Self::RecipientCommitmentZero => "recipient_commitment_zero",
            Self::AmountZero => "amount_zero",
            Self::AmountOutOfBounds => "amount_out_of_bounds",
            Self::NativeAssetNotAllowed => "native_asset_not_allowed",
        }
    }
}

impl NativeBridgeVerifierRegistrationPolicyRejection {
    fn label(self) -> &'static str {
        match self {
            Self::NotBridgeVerifierRegistration => "not_bridge_verifier_registration",
            Self::StateDeltasPresent => "state_deltas_present",
            Self::RegistrationDecodeFailed => "registration_decode_failed",
        }
    }
}

impl NativeBridgeMintReplayPolicyRejection {
    fn label(self) -> &'static str {
        match self {
            Self::NotInboundBridgeMint => "not_inbound_bridge_mint",
            Self::StateDeltaMintPresent => "state_delta_mint_present",
            Self::ReceiptEnvelopeMissing => "receipt_envelope_missing",
            Self::ReceiptNotVerified => "receipt_not_verified",
            Self::ReceiptPayloadMismatch => "receipt_payload_mismatch",
            Self::ReplayAlreadyConsumed => "replay_already_consumed",
            Self::MintNotAuthorized => "mint_not_authorized",
            Self::AmountDoesNotMatchReceipt => "amount_does_not_match_receipt",
            Self::AmountOutOfBounds => "amount_out_of_bounds",
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
    ExplicitHistoryTooLong,
    MaterializedHistoryTooLong,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeInboundBridgeReceiptAdmissionRejection {
    SourceChainMismatch,
    RulesHashMismatch,
    MessageNonceMismatch,
    MessageHashMismatch,
    TipBeforeMessage,
    ConfirmationsOverflow,
    ConfirmationsOverstated,
    Underconfirmed,
    WorkPolicyMismatch,
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
            Self::ExplicitHistoryTooLong => "explicit_history_too_long",
            Self::MaterializedHistoryTooLong => "materialized_history_too_long",
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
            Self::ConfirmationsOverflow => "confirmations_overflow",
            Self::ConfirmationsOverstated => "confirmations_overstated",
            Self::Underconfirmed => "underconfirmed",
            Self::WorkPolicyMismatch => "work_policy_mismatch",
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
struct NativeInlineTransferCiphertextResourceInput {
    raw_byte_cap: usize,
    decoded_byte_cap: usize,
    item_count_cap: usize,
    item_byte_cap: usize,
    aggregate_byte_cap: usize,
    work_unit_cap: usize,
    route_payload_bytes: usize,
    proof_bytes: usize,
    ciphertext_count: usize,
    max_ciphertext_bytes_observed: usize,
    aggregate_ciphertext_bytes: usize,
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
    stablecoin_policy_authorized: bool,
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

impl NativeTransferNullifierAdmissionState {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Zero => "zero",
            Self::AlreadySpent => "already_spent",
            Self::Duplicate => "duplicate",
            Self::AlreadyPending => "already_pending",
        }
    }
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
    StablecoinPolicyUnauthorized,
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
            Self::StablecoinPolicyUnauthorized => "stablecoin_policy_unauthorized",
            Self::SidecarCiphertextMissing => "sidecar_ciphertext_missing",
            Self::SidecarCiphertextSizeMissing => "sidecar_ciphertext_size_missing",
            Self::SidecarCiphertextSizeMismatch => "sidecar_ciphertext_size_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeStablecoinPolicyAuthorizationInput {
    stablecoin_present: bool,
    policy_known: bool,
    policy_active: bool,
    policy_lifecycle_open: bool,
    asset_matches: bool,
    policy_hash_matches: bool,
    policy_version_matches: bool,
    oracle_commitment_matches: bool,
    attestation_commitment_matches: bool,
    attestation_not_disputed: bool,
    oracle_fresh: bool,
    issuance_nonzero: bool,
    issuance_within_limit: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeStablecoinPolicyAuthorizationRejection {
    PolicyMissing,
    PolicyInactive,
    PolicyNotLive,
    AssetMismatch,
    PolicyHashMismatch,
    PolicyVersionMismatch,
    OracleCommitmentMismatch,
    AttestationCommitmentMismatch,
    AttestationDisputed,
    OracleStale,
    IssuanceZero,
    IssuanceOverLimit,
}

impl NativeStablecoinPolicyAuthorizationRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::PolicyMissing => "policy_missing",
            Self::PolicyInactive => "policy_inactive",
            Self::PolicyNotLive => "policy_not_live",
            Self::AssetMismatch => "asset_mismatch",
            Self::PolicyHashMismatch => "policy_hash_mismatch",
            Self::PolicyVersionMismatch => "policy_version_mismatch",
            Self::OracleCommitmentMismatch => "oracle_commitment_mismatch",
            Self::AttestationCommitmentMismatch => "attestation_commitment_mismatch",
            Self::AttestationDisputed => "attestation_disputed",
            Self::OracleStale => "oracle_stale",
            Self::IssuanceZero => "issuance_zero",
            Self::IssuanceOverLimit => "issuance_over_limit",
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
    PlanLength,
    CiphertextCount,
    CiphertextHash,
    CiphertextSize,
    ReplayKey,
}

impl NativeActionWireReplayProjectionAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::PlanLength => "plan_length_mismatch",
            Self::CiphertextCount => "ciphertext_count_mismatch",
            Self::CiphertextHash => "ciphertext_hash_mismatch",
            Self::CiphertextSize => "ciphertext_size_mismatch",
            Self::ReplayKey => "replay_key_mismatch",
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
    route_payload_decodes_exactly: bool,
    route_payload_matches_artifact: bool,
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
struct NativeCandidateArtifactResourceProjectionInput {
    raw_byte_cap: usize,
    decoded_byte_cap: usize,
    item_count_cap: usize,
    item_byte_cap: usize,
    aggregate_byte_cap: usize,
    work_unit_cap: usize,
    declared_bytes: usize,
    proof_bytes: usize,
    receipt_bytes: usize,
    recursive_bytes: usize,
    tx_count: usize,
    da_chunk_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeCandidateArtifactAdmissionRejection {
    StateDeltasPresent,
    RoutePayloadDecodeFailed,
    RoutePayloadArtifactMismatch,
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
            Self::RoutePayloadDecodeFailed => "route_payload_decode_failed",
            Self::RoutePayloadArtifactMismatch => "route_payload_artifact_mismatch",
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
    Nullifiers,
    Commitments,
    CiphertextHashes,
    InputCount,
    OutputCount,
    Version,
    Fee,
    StablecoinPayload,
    BalanceTag,
    ReceiptStatementHash,
    PublicInputsDigest,
    ProofDigest,
    ProofBackend,
    CiphertextPayloadHash,
}

impl NativeTxLeafActionBindingAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::Nullifiers => "nullifiers_mismatch",
            Self::Commitments => "commitments_mismatch",
            Self::CiphertextHashes => "ciphertext_hashes_mismatch",
            Self::InputCount => "input_count_mismatch",
            Self::OutputCount => "output_count_mismatch",
            Self::Version => "version_mismatch",
            Self::Fee => "fee_mismatch",
            Self::StablecoinPayload => "stablecoin_payload_mismatch",
            Self::BalanceTag => "balance_tag_mismatch",
            Self::ReceiptStatementHash => "receipt_statement_hash_mismatch",
            Self::PublicInputsDigest => "public_inputs_digest_mismatch",
            Self::ProofDigest => "proof_digest_mismatch",
            Self::ProofBackend => "proof_backend_mismatch",
            Self::CiphertextPayloadHash => "ciphertext_payload_hash_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeCandidateArtifactBindingAdmissionInput {
    da_root_matches: bool,
    da_chunk_count_matches: bool,
    tx_statements_commitment_matches: bool,
    recursive_state_root_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeCandidateArtifactBindingAdmissionRejection {
    DaRoot,
    DaChunkCount,
    TxStatementCommitment,
    RecursiveStateRoot,
}

impl NativeCandidateArtifactBindingAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::DaRoot => "da_root_mismatch",
            Self::DaChunkCount => "da_chunk_count_mismatch",
            Self::TxStatementCommitment => "tx_statement_commitment_mismatch",
            Self::RecursiveStateRoot => "recursive_state_root_mismatch",
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
    TxCount,
    StateRoot,
    KernelRoot,
    NullifierRoot,
    ExtrinsicsRoot,
    MessageRoot,
    MessageCount,
    HeaderMmrRoot,
    HeaderMmrLen,
    SupplyDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeAtomicCommitKind {
    MinedBlockCommit,
    TipExtensionBatchCommit,
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
    MinedPlanLength,
    BlockRecordWrites,
    HeightIndexWrites,
    BestPointerWrites,
    CanonicalIndexClear,
    PendingTreeClear,
    PendingActionRemoval,
    PendingActionWrite,
    CommitmentWrite,
    NullifierWrite,
    BridgeReplayWrite,
    CiphertextIndexWrite,
    CiphertextArchiveWrite,
    StagedCiphertextRemoval,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeStorageDurabilityOperation {
    MinedBlockCommit,
    CanonicalReorgCommit,
    CanonicalIndexRepair,
    NoncanonicalBlockRecord,
    PendingActionStage,
    CiphertextSidecarStage,
    ProofSidecarStage,
    GenesisBootstrap,
    GenesisMarkerRepair,
    StartupStagedCiphertextRepair,
    StartupStagedProofRepair,
    StartupPendingActionRepair,
    ShutdownFlush,
}

impl NativeStorageDurabilityOperation {
    fn label(self) -> &'static str {
        match self {
            Self::MinedBlockCommit => "mined_block_commit",
            Self::CanonicalReorgCommit => "canonical_reorg_commit",
            Self::CanonicalIndexRepair => "canonical_index_repair",
            Self::NoncanonicalBlockRecord => "noncanonical_block_record",
            Self::PendingActionStage => "pending_action_stage",
            Self::CiphertextSidecarStage => "ciphertext_sidecar_stage",
            Self::ProofSidecarStage => "proof_sidecar_stage",
            Self::GenesisBootstrap => "genesis_bootstrap",
            Self::GenesisMarkerRepair => "genesis_marker_repair",
            Self::StartupStagedCiphertextRepair => "startup_staged_ciphertext_repair",
            Self::StartupStagedProofRepair => "startup_staged_proof_repair",
            Self::StartupPendingActionRepair => "startup_pending_action_repair",
            Self::ShutdownFlush => "shutdown_flush",
        }
    }

    #[cfg(test)]
    fn from_label(label: &str) -> Option<Self> {
        match label {
            "mined_block_commit" => Some(Self::MinedBlockCommit),
            "canonical_reorg_commit" => Some(Self::CanonicalReorgCommit),
            "canonical_index_repair" => Some(Self::CanonicalIndexRepair),
            "noncanonical_block_record" => Some(Self::NoncanonicalBlockRecord),
            "pending_action_stage" => Some(Self::PendingActionStage),
            "ciphertext_sidecar_stage" => Some(Self::CiphertextSidecarStage),
            "proof_sidecar_stage" => Some(Self::ProofSidecarStage),
            "genesis_bootstrap" => Some(Self::GenesisBootstrap),
            "genesis_marker_repair" => Some(Self::GenesisMarkerRepair),
            "startup_staged_ciphertext_repair" => Some(Self::StartupStagedCiphertextRepair),
            "startup_staged_proof_repair" => Some(Self::StartupStagedProofRepair),
            "startup_pending_action_repair" => Some(Self::StartupPendingActionRepair),
            "shutdown_flush" => Some(Self::ShutdownFlush),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeStorageDurabilityAdmissionInput {
    operation_supported: bool,
    transaction_accepted: bool,
    durability_flushed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeStorageDurabilityAdmissionRejection {
    UnsupportedOperation,
    TransactionRejected,
    DurabilityFlushFailed,
}

impl NativeStorageDurabilityAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::UnsupportedOperation => "unsupported_operation",
            Self::TransactionRejected => "transaction_rejected",
            Self::DurabilityFlushFailed => "durability_flush_failed",
        }
    }
}

impl NativeAtomicCommitManifestAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::MinedPlanLength => "mined_plan_length_mismatch",
            Self::BlockRecordWrites => "block_record_writes_mismatch",
            Self::HeightIndexWrites => "height_index_writes_mismatch",
            Self::BestPointerWrites => "best_pointer_writes_mismatch",
            Self::CanonicalIndexClear => "canonical_index_clear_mismatch",
            Self::PendingTreeClear => "pending_tree_clear_mismatch",
            Self::PendingActionRemoval => "pending_action_removal_mismatch",
            Self::PendingActionWrite => "pending_action_write_mismatch",
            Self::CommitmentWrite => "commitment_write_mismatch",
            Self::NullifierWrite => "nullifier_write_mismatch",
            Self::BridgeReplayWrite => "bridge_replay_write_mismatch",
            Self::CiphertextIndexWrite => "ciphertext_index_write_mismatch",
            Self::CiphertextArchiveWrite => "ciphertext_archive_write_mismatch",
            Self::StagedCiphertextRemoval => "staged_ciphertext_removal_mismatch",
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
            Self::TxCount => "tx_count_mismatch",
            Self::StateRoot => "state_root_mismatch",
            Self::KernelRoot => "kernel_root_mismatch",
            Self::NullifierRoot => "nullifier_root_mismatch",
            Self::ExtrinsicsRoot => "extrinsics_root_mismatch",
            Self::MessageRoot => "message_root_mismatch",
            Self::MessageCount => "message_count_mismatch",
            Self::HeaderMmrRoot => "header_mmr_root_mismatch",
            Self::HeaderMmrLen => "header_mmr_len_mismatch",
            Self::SupplyDigest => "supply_digest_mismatch",
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
struct NativeBoundedRequestAdmissionInput {
    raw_byte_cap: usize,
    decoded_byte_cap: usize,
    item_count_cap: usize,
    item_byte_cap: usize,
    aggregate_byte_cap: usize,
    work_unit_cap: usize,
    raw_bytes: usize,
    decoded_bytes: usize,
    item_count: usize,
    max_item_bytes: usize,
    aggregate_bytes: usize,
    work_units: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeBoundedRequestAdmissionRejection {
    RawBytes,
    DecodedBytes,
    ItemCount,
    ItemBytes,
    AggregateBytes,
    WorkUnits,
}

impl NativeBoundedRequestAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::RawBytes => "raw_bytes_exceeded",
            Self::DecodedBytes => "decoded_bytes_exceeded",
            Self::ItemCount => "item_count_exceeded",
            Self::ItemBytes => "item_bytes_exceeded",
            Self::AggregateBytes => "aggregate_bytes_exceeded",
            Self::WorkUnits => "work_units_exceeded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeSyncBlockRangePublicationAdmissionRejection {
    RangeNotAdmitted,
    ServedCountMismatch,
    FirstHeightMismatch,
    LastHeightMismatch,
    HeightContinuityMismatch,
    ParentHashMismatch,
    CanonicalRowsUnverified,
    ActionBodiesUnverified,
}

impl NativeSyncBlockRangePublicationAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::RangeNotAdmitted => "range_not_admitted",
            Self::ServedCountMismatch => "served_count_mismatch",
            Self::FirstHeightMismatch => "first_height_mismatch",
            Self::LastHeightMismatch => "last_height_mismatch",
            Self::HeightContinuityMismatch => "height_continuity_mismatch",
            Self::ParentHashMismatch => "parent_hash_mismatch",
            Self::CanonicalRowsUnverified => "canonical_rows_unverified",
            Self::ActionBodiesUnverified => "action_bodies_unverified",
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitCiphertextsRpcRequest {
    #[serde(default)]
    ciphertexts: Option<Vec<Value>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitProofsRpcRequest {
    #[serde(default)]
    proofs: Option<Vec<SubmitProofsRpcItem>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitProofsRpcItem {
    #[serde(default)]
    binding_hash: Option<String>,
    #[serde(default)]
    proof: Option<Value>,
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

fn decode_submit_ciphertexts_rpc_request(request: Value) -> Result<SubmitCiphertextsRpcRequest> {
    serde_json::from_value(request).context("decode da ciphertext upload request")
}

fn decode_submit_proofs_rpc_request(request: Value) -> Result<SubmitProofsRpcRequest> {
    serde_json::from_value(request).context("decode da proof upload request")
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
    header_mmr_peaks: Vec<Hash32>,
    pending_actions: BTreeMap<[u8; 32], PendingAction>,
    commitment_tree: CommitmentTreeState,
    nullifiers: BTreeSet<[u8; 48]>,
    consumed_bridge_messages: BTreeSet<[u8; 48]>,
    stablecoin_policy_authorizations: BTreeSet<Vec<u8>>,
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
    pending_action_rebroadcast_cursor: AtomicU64,
    sync_target_height: AtomicU64,
    sync_target_observed: AtomicBool,
    sync_target_peer: Mutex<Option<PeerId>>,
    sync_target_hash: Mutex<Option<[u8; 32]>>,
    sync_reorg_backfill_blocks: AtomicU64,
    mining_sync_gate_open: AtomicBool,
    sync_import_in_flight: AtomicBool,
    network_peer_count: Arc<AtomicUsize>,
    network_local_peer_id: Arc<StdRwLock<Option<PeerId>>>,
    network_peer_snapshot: Arc<StdRwLock<Vec<ConnectedPeerSnapshot>>>,
    sync_request_rate_limits: Mutex<BTreeMap<PeerId, NativeSyncRequestRateState>>,
    sync_response_in_flight_peers: Mutex<BTreeMap<PeerId, BTreeSet<NativeSyncRange>>>,
    outbound_sync_requests: Mutex<BTreeMap<Option<PeerId>, NativeOutboundSyncRequest>>,
    mining_tasks: Mutex<Vec<JoinHandle<()>>>,
    sync_tx: Mutex<Option<ProtocolSender>>,
    miner_identity: NativeMinerIdentity,
    prepared_mining_actions: Mutex<BTreeMap<[u8; 32], Vec<PendingAction>>>,
    prepared_candidate_actions: Mutex<BTreeMap<[u8; 32], PendingAction>>,
    prepared_candidate_build_lock: Mutex<()>,
}

impl NativeNode {
    pub fn open(config: NativeConfig) -> Result<Arc<Self>> {
        let startup_started = Instant::now();
        info!(
            base_path = %config.base_path.display(),
            db_path = %config.db_path.display(),
            "opening native Hegemon node storage"
        );
        fs::create_dir_all(&config.base_path)
            .with_context(|| format!("create native base path {}", config.base_path.display()))?;
        let db_open_started = Instant::now();
        let db = sled::open(&config.db_path)
            .with_context(|| format!("open native sled db {}", config.db_path.display()))?;
        info!(
            db_open_elapsed_ms = db_open_started.elapsed().as_millis(),
            "native sled database opened"
        );
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
        let prune_persisted_coinbase_actions = config.miner_address.is_some();
        let nullifiers = load_nullifiers(&nullifier_tree)?;
        let commitment_state = load_commitment_tree(&commitment_tree)?;
        validate_loaded_canonical_state(&best, &commitment_state, &nullifiers)?;
        let consumed_bridge_messages = load_consumed_bridge_messages(&bridge_inbound_tree)?;
        validate_loaded_bridge_replay_state(&best, &block_tree, &consumed_bridge_messages)?;
        let staged_ciphertexts = load_staged_sizes(&db, &da_ciphertext_tree)?;
        let staged_proofs = load_staged_proofs(&db, &da_proof_tree)?;
        let header_mmr_peaks = load_header_mmr_peaks_for_best(&block_tree, &best)?;
        let startup_state = build_validated_startup_state(
            &db,
            &action_tree,
            best,
            header_mmr_peaks,
            pending_actions,
            commitment_state,
            nullifiers,
            consumed_bridge_messages,
            staged_ciphertexts,
            staged_proofs,
            prune_persisted_coinbase_actions,
        )?;
        let miner_identity = load_native_miner_identity(&config)?;
        info!(
            startup_reload_elapsed_ms = startup_started.elapsed().as_millis(),
            "native Hegemon node storage reload completed"
        );

        let initial_mining_sync_gate_open = config.bootstrap_mining_authoring
            || (config.seeds.is_empty() && config.permits_empty_seed_authoring());
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
            pending_action_rebroadcast_cursor: AtomicU64::new(0),
            sync_target_height: AtomicU64::new(0),
            sync_target_observed: AtomicBool::new(initial_mining_sync_gate_open),
            sync_target_peer: Mutex::new(None),
            sync_target_hash: Mutex::new(None),
            sync_reorg_backfill_blocks: AtomicU64::new(NATIVE_SYNC_REORG_BACKFILL_BLOCKS),
            mining_sync_gate_open: AtomicBool::new(initial_mining_sync_gate_open),
            sync_import_in_flight: AtomicBool::new(false),
            network_peer_count: Arc::new(AtomicUsize::new(0)),
            network_local_peer_id: Arc::new(StdRwLock::new(None)),
            network_peer_snapshot: Arc::new(StdRwLock::new(Vec::new())),
            sync_request_rate_limits: Mutex::new(BTreeMap::new()),
            sync_response_in_flight_peers: Mutex::new(BTreeMap::new()),
            outbound_sync_requests: Mutex::new(BTreeMap::new()),
            mining_tasks: Mutex::new(Vec::new()),
            sync_tx: Mutex::new(None),
            miner_identity,
            prepared_mining_actions: Mutex::new(BTreeMap::new()),
            prepared_candidate_actions: Mutex::new(BTreeMap::new()),
            prepared_candidate_build_lock: Mutex::new(()),
        });
        Self::ensure_ciphertext_archive_index(&node)?;
        Ok(node)
    }

    fn set_sync_sender(&self, sync_tx: ProtocolSender) {
        *self.sync_tx.lock() = Some(sync_tx);
    }

    fn network_peer_count(&self) -> u32 {
        let count = self.network_peer_count.load(Ordering::Relaxed);
        count.min(u32::MAX as usize) as u32
    }

    fn set_network_local_peer_id(&self, peer_id: PeerId) {
        if let Ok(mut current) = self.network_local_peer_id.write() {
            *current = Some(peer_id);
        }
    }

    fn network_local_peer_id(&self) -> Option<PeerId> {
        self.network_local_peer_id
            .read()
            .ok()
            .and_then(|current| *current)
    }

    fn network_peer_snapshot(&self) -> Vec<ConnectedPeerSnapshot> {
        self.network_peer_snapshot
            .read()
            .map(|snapshot| snapshot.clone())
            .unwrap_or_default()
    }

    fn observe_verified_sync_peer_height(&self, peer_best_height: u64) {
        self.sync_target_observed.store(true, Ordering::SeqCst);
        let best = self.best_meta();
        let target_before = self.sync_target_height.load(Ordering::Relaxed);
        if peer_best_height > target_before {
            self.sync_target_height
                .store(peer_best_height, Ordering::Relaxed);
        } else if peer_best_height <= best.height {
            self.clear_unanchored_sync_target_to_local_tip(
                peer_best_height,
                "verified local-tip sync evidence",
            );
        }
        let target = self.sync_target_height.load(Ordering::Relaxed);
        if target <= best.height && peer_best_height <= best.height {
            *self.sync_target_peer.lock() = None;
            *self.sync_target_hash.lock() = None;
        }
        self.refresh_mining_sync_gate();
    }

    fn clear_unanchored_sync_target_to_local_tip(
        &self,
        evidence_peer_height: u64,
        reason: &'static str,
    ) -> bool {
        let best = self.best_meta();
        let target = self.sync_target_height.load(Ordering::Relaxed);
        if target <= best.height {
            return false;
        }
        if self.sync_target_hash.lock().is_some() {
            return false;
        }
        self.sync_target_height
            .store(best.height, Ordering::Relaxed);
        *self.sync_target_peer.lock() = None;
        info!(
            target,
            local_height = best.height,
            evidence_peer_height,
            reason,
            "cleared unanchored native sync target"
        );
        true
    }

    fn clear_hash_anchored_sync_target_to_local_tip(
        &self,
        evidence_peer_height: u64,
        evidence_hash: [u8; 32],
        reason: &'static str,
    ) -> bool {
        let best = self.best_meta();
        let target = self.sync_target_height.load(Ordering::Relaxed);
        if target <= best.height {
            return false;
        }
        let Some(target_hash) = *self.sync_target_hash.lock() else {
            return false;
        };
        if target_hash != evidence_hash {
            return false;
        }
        self.sync_target_height
            .store(best.height, Ordering::Relaxed);
        *self.sync_target_peer.lock() = None;
        *self.sync_target_hash.lock() = None;
        self.refresh_mining_sync_gate();
        info!(
            target,
            local_height = best.height,
            evidence_peer_height,
            evidence_hash = %hex32(&evidence_hash),
            reason,
            "cleared hash-anchored native sync target"
        );
        true
    }

    fn clear_nonwinning_sync_target_response_to_local_tip(
        &self,
        peer_best_height: u64,
        blocks: &[NativeBlockMeta],
    ) -> bool {
        let best = self.best_meta();
        let target = self.sync_target_height.load(Ordering::Relaxed);
        if target <= best.height {
            return false;
        }
        let Some(target_hash) = *self.sync_target_hash.lock() else {
            return false;
        };
        let Some(target_meta) = blocks
            .iter()
            .rev()
            .find(|meta| meta.height == target && meta.hash == target_hash)
        else {
            return false;
        };
        if native_meta_better_than(target_meta, &best) {
            return false;
        }
        self.clear_hash_anchored_sync_target_to_local_tip(
            peer_best_height,
            target_hash,
            "non-winning native sync target response",
        )
    }

    fn observe_pending_sync_peer_height(&self, peer_best_height: u64) {
        self.observe_pending_sync_peer_tip(None, peer_best_height, None);
    }

    fn observe_pending_sync_peer_tip(
        &self,
        peer_id: Option<PeerId>,
        peer_best_height: u64,
        peer_best_hash: Option<[u8; 32]>,
    ) {
        let best = self.best_meta();
        let unresolved_equal_height_tip =
            peer_best_height == best.height && peer_best_hash.is_some_and(|hash| hash != best.hash);
        if peer_best_height < best.height
            || (peer_best_height == best.height && !unresolved_equal_height_tip)
        {
            return;
        }
        self.sync_target_observed.store(true, Ordering::SeqCst);
        self.sync_target_height
            .fetch_max(peer_best_height, Ordering::Relaxed);
        if let Some(peer_id) = peer_id {
            *self.sync_target_peer.lock() = Some(peer_id);
        }
        if let Some(peer_best_hash) = peer_best_hash {
            *self.sync_target_hash.lock() = Some(peer_best_hash);
        }
        self.mining_sync_gate_open.store(false, Ordering::SeqCst);
    }

    fn has_verified_header_hash(&self, hash: &[u8; 32]) -> Result<bool> {
        Ok(self.header_by_hash(hash)?.is_some())
    }

    fn begin_sync_import(&self) -> bool {
        self.sync_import_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn end_sync_import(&self) {
        self.sync_import_in_flight.store(false, Ordering::Release);
    }

    fn sync_import_in_flight(&self) -> bool {
        self.sync_import_in_flight.load(Ordering::Acquire)
    }

    fn begin_sync_response_for_peer(
        &self,
        peer_id: PeerId,
        range: NativeSyncRange,
    ) -> NativeSyncResponseStart {
        let mut responses = self.sync_response_in_flight_peers.lock();
        let ranges = responses.entry(peer_id).or_default();
        if !ranges.insert(range) {
            NativeSyncResponseStart::DuplicateRange
        } else {
            NativeSyncResponseStart::Started
        }
    }

    fn end_sync_response_for_peer(&self, peer_id: PeerId, range: NativeSyncRange) {
        let mut responses = self.sync_response_in_flight_peers.lock();
        if let Some(ranges) = responses.get_mut(&peer_id) {
            ranges.remove(&range);
            if ranges.is_empty() {
                responses.remove(&peer_id);
            }
        }
    }

    fn begin_outbound_sync_request(&self, peer_id: Option<PeerId>, range: NativeSyncRange) -> bool {
        let now = Instant::now();
        let mut requests = self.outbound_sync_requests.lock();
        requests.retain(|_, request| {
            now.saturating_duration_since(request.requested_at) <= NATIVE_SYNC_REQUEST_RETRY_AFTER
        });
        if requests.contains_key(&peer_id) {
            return false;
        }
        if requests
            .values()
            .any(|request| native_sync_ranges_overlap(request.range, range))
        {
            return false;
        }
        requests.insert(
            peer_id,
            NativeOutboundSyncRequest {
                range,
                requested_at: now,
            },
        );
        true
    }

    fn complete_outbound_sync_request(&self, peer_id: PeerId) {
        let mut requests = self.outbound_sync_requests.lock();
        requests.remove(&Some(peer_id));
        requests.remove(&None);
    }

    fn complete_outbound_sync_response(
        &self,
        peer_id: PeerId,
        response_range: Option<NativeSyncRange>,
    ) -> bool {
        let mut requests = self.outbound_sync_requests.lock();
        let mut completed = false;
        for target in [Some(peer_id), None] {
            let should_remove = requests.get(&target).is_some_and(|request| {
                response_range.is_none_or(|range| native_sync_ranges_overlap(request.range, range))
            });
            if should_remove {
                requests.remove(&target);
                completed = true;
            }
        }
        completed
    }

    fn complete_outbound_sync_request_target(&self, peer_id: Option<PeerId>) {
        self.outbound_sync_requests.lock().remove(&peer_id);
    }

    fn sync_reorg_backfill_blocks(&self) -> u64 {
        self.sync_reorg_backfill_blocks
            .load(Ordering::Relaxed)
            .clamp(
                NATIVE_SYNC_REORG_BACKFILL_BLOCKS,
                NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS,
            )
    }

    fn reset_sync_reorg_backfill(&self) {
        self.sync_reorg_backfill_blocks
            .store(NATIVE_SYNC_REORG_BACKFILL_BLOCKS, Ordering::Relaxed);
    }

    fn escalate_sync_reorg_backfill(&self) -> u64 {
        let mut current = self.sync_reorg_backfill_blocks();
        loop {
            let next = current
                .saturating_mul(2)
                .max(NATIVE_SYNC_REORG_BACKFILL_BLOCKS.saturating_add(1))
                .min(NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS);
            match self.sync_reorg_backfill_blocks.compare_exchange(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return next,
                Err(observed) => {
                    current = observed.clamp(
                        NATIVE_SYNC_REORG_BACKFILL_BLOCKS,
                        NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS,
                    );
                    if current >= NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS {
                        return current;
                    }
                }
            }
        }
    }

    fn admit_sync_request_from_peer(
        &self,
        peer_id: PeerId,
    ) -> Result<(), NativeSyncAdmissionRejection> {
        let now = Instant::now();
        let window_ms = duration_millis_u64(NATIVE_SYNC_REQUEST_RATE_WINDOW);
        let mut limits = self.sync_request_rate_limits.lock();
        Self::prune_sync_request_rate_limits(&mut limits, now);
        debug_assert!(
            Self::sync_request_rate_limit_entries_after_insert(
                limits.len(),
                MAX_NATIVE_SYNC_REQUEST_RATE_LIMIT_PEERS
            ) <= MAX_NATIVE_SYNC_REQUEST_RATE_LIMIT_PEERS
        );
        let state = limits.entry(peer_id).or_insert(NativeSyncRequestRateState {
            window_start: now,
            requests: 0,
        });
        let elapsed_ms = duration_millis_u64(now.saturating_duration_since(state.window_start));
        evaluate_native_sync_request_rate_admission(NativeSyncRequestRateAdmissionInput {
            requests_in_window: state.requests,
            max_requests: MAX_NATIVE_SYNC_REQUESTS_PER_WINDOW,
            window_elapsed_ms: elapsed_ms,
            window_ms,
        })?;
        if elapsed_ms >= window_ms {
            state.window_start = now;
            state.requests = 1;
        } else {
            state.requests = state.requests.saturating_add(1);
        }
        Ok(())
    }

    fn prune_sync_request_rate_limits(
        limits: &mut BTreeMap<PeerId, NativeSyncRequestRateState>,
        now: Instant,
    ) {
        limits.retain(|_, state| {
            now.saturating_duration_since(state.window_start)
                <= NATIVE_SYNC_REQUEST_RATE_LIMIT_STATE_TTL
        });
        let retained_before_insert = Self::sync_request_rate_limit_entries_before_insert(
            limits.len(),
            MAX_NATIVE_SYNC_REQUEST_RATE_LIMIT_PEERS,
        );
        if limits.len() <= retained_before_insert {
            return;
        }

        let evict_count = limits.len().saturating_sub(retained_before_insert);
        let mut oldest: Vec<_> = limits
            .iter()
            .map(|(peer_id, state)| (*peer_id, state.window_start))
            .collect();
        oldest.sort_by_key(|(_, window_start)| *window_start);
        for (peer_id, _) in oldest.into_iter().take(evict_count) {
            limits.remove(&peer_id);
        }
    }

    fn sync_request_rate_limit_entries_before_insert(
        current_entries: usize,
        max_entries: usize,
    ) -> usize {
        if max_entries == 0 {
            0
        } else {
            current_entries.min(max_entries.saturating_sub(1))
        }
    }

    fn sync_request_rate_limit_entries_after_insert(
        current_entries: usize,
        max_entries: usize,
    ) -> usize {
        if max_entries == 0 {
            0
        } else {
            Self::sync_request_rate_limit_entries_before_insert(current_entries, max_entries)
                .saturating_add(1)
        }
    }

    fn refresh_mining_sync_gate(&self) {
        if self.config.seeds.is_empty() {
            self.mining_sync_gate_open
                .store(self.config.permits_empty_seed_authoring(), Ordering::SeqCst);
            return;
        }
        if !self.sync_target_observed.load(Ordering::SeqCst) {
            return;
        }
        let target = self.sync_target_height.load(Ordering::Relaxed);
        let resolved = self.sync_target_resolved(target);
        self.mining_sync_gate_open.store(resolved, Ordering::SeqCst);
        if resolved {
            *self.sync_target_peer.lock() = None;
        }
    }

    fn sync_target_resolved(&self, target: u64) -> bool {
        let best = self.best_meta();
        if best.height < target {
            return false;
        }
        let Some(target_hash) = *self.sync_target_hash.lock() else {
            return true;
        };
        if best.hash == target_hash {
            return true;
        }
        if best.height > target {
            return true;
        }
        match self.header_by_hash(&target_hash) {
            Ok(Some(target_meta)) => !native_meta_better_than(&target_meta, &best),
            Ok(None) => false,
            Err(err) => {
                warn!(
                    target,
                    target_hash = %hex32(&target_hash),
                    error = %err,
                    "failed to resolve native sync target hash"
                );
                false
            }
        }
    }

    fn mining_sync_gate_allows_work(&self) -> bool {
        native_mining_gate_allows_work(NativeMiningGateInput {
            has_seeds: !self.config.seeds.is_empty(),
            dev: self.config.dev,
            bootstrap_mining_authoring: self.config.bootstrap_mining_authoring,
            observed_gate_open: self.mining_sync_gate_open.load(Ordering::SeqCst),
        })
    }

    fn sync_status_fields(&self) -> (bool, u64) {
        let target = self.sync_target_height.load(Ordering::Relaxed);
        let observed = self.sync_target_observed.load(Ordering::SeqCst);
        let target_resolved = self.sync_target_resolved(target);
        let syncing = !self.config.seeds.is_empty()
            && (!observed
                || !self.mining_sync_gate_open.load(Ordering::SeqCst)
                || !target_resolved);
        (syncing, target)
    }

    fn catching_up_to_sync_target(&self) -> Option<(u64, u64)> {
        native_sync_catch_up_target(
            self.best_meta().height,
            self.sync_target_observed.load(Ordering::SeqCst),
            self.sync_target_height.load(Ordering::Relaxed),
        )
    }

    fn start_mining(self: &Arc<Self>, threads: u32) {
        let requested_threads = threads.max(1);
        let available_threads = native_available_parallelism();
        let threads = effective_native_mining_threads(requested_threads, available_threads);
        if threads < requested_threads {
            warn!(
                requested_threads,
                effective_threads = threads,
                available_threads,
                background_thread_cap = NATIVE_MINING_BACKGROUND_THREAD_CAP,
                reserved_service_threads = NATIVE_MINING_RESERVED_SERVICE_THREADS,
                "capped native mining threads to preserve sync and RPC liveness"
            );
        }
        self.mining.store(true, Ordering::SeqCst);

        let mut tasks = self.mining_tasks.lock();
        tasks.retain(|task| !task.is_finished());
        if tasks.len() == threads as usize {
            self.mining_threads.store(threads, Ordering::Relaxed);
            return;
        }
        for task in tasks.drain(..) {
            task.abort();
        }
        self.mining_threads.store(threads, Ordering::Relaxed);
        for _ in 0..threads {
            let node = Arc::clone(self);
            tasks.push(tokio::spawn(async move {
                mining_loop(node).await;
            }));
        }
    }

    fn stop_mining(&self) {
        self.mining.store(false, Ordering::SeqCst);
        self.mining_threads.store(0, Ordering::Relaxed);
        let mut tasks = self.mining_tasks.lock();
        for task in tasks.drain(..) {
            task.abort();
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

    fn auto_candidate_cache_key(
        parent_hash: [u8; 32],
        transfer_actions: &[PendingAction],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"hegemon-native-auto-recursive-candidate-v1");
        hasher.update(&parent_hash);
        let count = u32::try_from(transfer_actions.len()).unwrap_or(u32::MAX);
        hasher.update(&count.to_le_bytes());
        for action in transfer_actions {
            hasher.update(&action.tx_hash);
        }
        *hasher.finalize().as_bytes()
    }

    fn prepared_candidate_action(&self, key: [u8; 32]) -> Option<PendingAction> {
        self.prepared_candidate_actions.lock().get(&key).cloned()
    }

    fn cache_prepared_candidate_action(&self, key: [u8; 32], action: PendingAction) {
        let mut cache = self.prepared_candidate_actions.lock();
        cache.insert(key, action);
        while cache.len() > MAX_PREPARED_CANDIDATE_ACTIONS {
            let Some(oldest_key) = cache.keys().next().copied() else {
                break;
            };
            cache.remove(&oldest_key);
        }
    }

    fn build_auto_recursive_candidate_action(
        &self,
        state: &NativeState,
        height: u64,
        received_ms: u64,
        actions: &[PendingAction],
    ) -> Result<Option<PendingAction>> {
        let transfer_actions = actions
            .iter()
            .filter(|action| is_shielded_transfer_action(action))
            .cloned()
            .collect::<Vec<_>>();
        if transfer_actions.is_empty() {
            return Ok(None);
        }
        if actions.iter().any(|action| {
            is_candidate_artifact_action(action)
                && action
                    .candidate_artifact
                    .as_ref()
                    .is_some_and(|artifact| artifact.tx_count as usize == transfer_actions.len())
        }) {
            return Ok(None);
        }

        let cache_key = Self::auto_candidate_cache_key(state.best.hash, &transfer_actions);
        if let Some(action) = self.prepared_candidate_action(cache_key) {
            return Ok(Some(action));
        }

        let _build_guard = self.prepared_candidate_build_lock.lock();
        if let Some(action) = self.prepared_candidate_action(cache_key) {
            return Ok(Some(action));
        }

        let materialized = materialize_native_action_payloads_from_state(
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
            state,
            &transfer_actions,
        )?;
        let mut transactions = Vec::with_capacity(transfer_actions.len());
        let mut artifacts = Vec::with_capacity(transfer_actions.len());
        for (action, payload) in transfer_actions.iter().zip(materialized.iter()) {
            let (tx, artifact) = consensus_tx_and_artifact_from_action(action, payload)?;
            transactions.push(tx);
            artifacts.push(artifact);
        }

        let transfer_refs = transfer_actions.iter().collect::<Vec<_>>();
        let expected_tree = preview_commitment_tree(&state.commitment_tree, &transfer_refs)?;
        let mut expected_nullifiers = state.nullifiers.clone();
        for action in &transfer_actions {
            for nullifier in &action.nullifiers {
                expected_nullifiers.insert(*nullifier);
            }
        }
        let expected_nullifier_root = nullifier_root_from_set(&expected_nullifiers);
        let expected_kernel_root =
            consensus::types::kernel_root_from_shielded_root(&expected_tree.root());
        let da_params = native_da_params();
        let da_encoding = consensus::encode_da_blob(&transactions, da_params)
            .map_err(|err| anyhow!("native recursive candidate DA encoding failed: {err}"))?;
        let tx_count = u32::try_from(transactions.len())
            .map_err(|_| anyhow!("native recursive candidate tx_count exceeds u32"))?;
        let header = consensus::BlockHeader {
            version: 1,
            height,
            view: 0,
            timestamp_ms: received_ms.max(state.best.timestamp_ms.saturating_add(1)),
            parent_hash: state.best.hash,
            state_root: expected_tree.root(),
            kernel_root: expected_kernel_root,
            nullifier_root: expected_nullifier_root,
            proof_commitment: consensus::types::compute_proof_commitment(&transactions),
            da_root: da_encoding.root(),
            da_params,
            version_commitment: consensus::types::compute_version_commitment(&transactions),
            tx_count,
            fee_commitment: consensus::types::compute_fee_commitment(&transactions),
            supply_digest: state.best.supply_digest,
            validator_set_commitment: [0u8; 48],
            signature_aggregate: Vec::new(),
            signature_bitmap: None,
            pow: None,
        };
        let block = consensus::types::Block {
            header,
            transactions,
            coinbase: None,
            proven_batch: None,
            block_artifact: None,
            tx_validity_claims: None,
            tx_statements_commitment: None,
            proof_verification_mode:
                consensus::types::ProofVerificationMode::SelfContainedAggregation,
        };
        let built = consensus::proof::build_recursive_block_v2_artifact_for_native_txs(
            &block,
            &artifacts,
            &state.commitment_tree,
        )
        .map_err(|err| anyhow!("build native recursive candidate artifact failed: {err}"))?;
        let artifact = CandidateArtifact {
            version: BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count: built.tx_count,
            tx_statements_commitment: built.tx_statements_commitment,
            da_root: built.da_root,
            da_chunk_count: built.da_chunk_count,
            commitment_proof: StarkProof::default(),
            proof_mode: BlockProofMode::RecursiveBlock,
            proof_kind: PoolProofArtifactKind::RecursiveBlockV2,
            verifier_profile: built.verifier_profile,
            receipt_root: None,
            recursive_block: Some(RecursiveBlockProofPayload {
                proof: StarkProof {
                    data: built.artifact_bytes,
                },
            }),
        };
        validate_candidate_artifact(&artifact)?;
        let mut action = PendingAction {
            tx_hash: [0u8; 32],
            binding: protocol_versioning::DEFAULT_VERSION_BINDING.into(),
            family_id: FAMILY_SHIELDED_POOL,
            action_id: ACTION_SUBMIT_CANDIDATE_ARTIFACT,
            anchor: [0u8; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: Vec::new(),
            ciphertext_sizes: Vec::new(),
            public_args: SubmitCandidateArtifactArgs {
                payload: artifact.clone(),
            }
            .encode(),
            fee: 0,
            candidate_artifact: Some(artifact),
            received_ms,
        };
        action.tx_hash = pending_action_hash(&action);
        validate_candidate_action_payload(&action)?;
        self.cache_prepared_candidate_action(cache_key, action.clone());
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
        if let Some(actions) = work.prepared_actions.as_ref() {
            if prepared_mining_actions_match_state(state, actions) {
                return actions.as_ref().clone();
            }
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
        if native_work_template_next_height(best.height).is_none() {
            return Err(native_work_template_admission_error(
                NativeWorkTemplateAdmissionRejection::HeightNotNext,
            ));
        }
        let pow_bits = self.expected_child_pow_bits(&best)?;
        let cumulative_work = cumulative_work_after(&best.cumulative_work, pow_bits)
            .map_err(|_| NativeWorkTemplateAdmissionRejection::CumulativeWorkOverflow);
        let height = evaluate_native_work_template_admission(NativeWorkTemplateAdmissionInput {
            best_height: best.height,
            cumulative_work_advances: cumulative_work.is_ok(),
        })
        .map_err(native_work_template_admission_error)?;
        let cumulative_work = cumulative_work.map_err(native_work_template_admission_error)?;
        let received_ms = current_time_ms();
        match self.build_auto_recursive_candidate_action(
            &state,
            height,
            received_ms,
            &pending_actions,
        ) {
            Ok(Some(action)) => pending_actions.push(action),
            Ok(None) => {}
            Err(err) => {
                warn!(
                    error = %err,
                    "dropping native pending actions before recursive candidate artifact"
                );
                pending_actions.clear();
            }
        }
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
        let header_mmr_len = header_history.len() as u64;
        let header_mmr_root = header_mmr_root_from_hashes(&header_history);
        let pre_header = native_pow_header_from_parts(
            height,
            timestamp_ms,
            best.hash,
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
            pow_bits,
            prepared_actions: Some(Arc::new(actions)),
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
        let expected_pow_bits = self.expected_child_pow_bits(&state.best)?;
        if work.pow_bits != expected_pow_bits {
            debug!(
                expected_pow_bits,
                observed_pow_bits = work.pow_bits,
                "native mined work no longer matches scheduled PoW bits"
            );
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
                rejection @ (NativeBlockCommitmentAdmissionRejection::HeaderMmrRoot
                | NativeBlockCommitmentAdmissionRejection::HeaderMmrLen),
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
            Some(&self.ciphertext_archive_tree),
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
        verify_native_pow_meta(&state.best, &meta, expected_pow_bits)?;

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
        self.flush_native_durability_barrier(
            "native mined block commit",
            NativeStorageDurabilityOperation::MinedBlockCommit,
        )?;
        self.verify_persisted_canonical_head(&meta, "native mined block commit")?;
        self.forget_prepared_mining_actions(work);
        next_state.header_mmr_peaks = append_header_mmr_peak_state(&state, &meta)?;
        next_state.best = meta.clone();
        self.prune_invalid_pending_actions_after_state_advance(
            &mut next_state,
            "native mined block pending action repair",
        )?;
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
        self.validate_stored_block_meta_parent_chain(&parent)?;
        let expected_pow_bits = self.expected_child_pow_bits(&parent)?;
        validate_announced_block(&parent, &meta, expected_pow_bits)?;
        let (expected_header_mmr_root, expected_header_mmr_len) = if parent.hash == state.best.hash
        {
            (
                header_mmr_root_from_peaks(
                    header_mmr_leaf_count_after_best(&state.best)?,
                    &state.header_mmr_peaks,
                ),
                header_mmr_leaf_count_after_best(&state.best)?,
            )
        } else {
            let expected_header_history = self.header_hashes_to_hash(parent.hash)?;
            (
                header_mmr_root_from_hashes(&expected_header_history),
                expected_header_history.len() as u64,
            )
        };

        let parent_state = if parent.hash == state.best.hash {
            NativeState {
                best: state.best.clone(),
                header_mmr_peaks: state.header_mmr_peaks.clone(),
                pending_actions: BTreeMap::new(),
                commitment_tree: state.commitment_tree.clone(),
                nullifiers: state.nullifiers.clone(),
                consumed_bridge_messages: state.consumed_bridge_messages.clone(),
                stablecoin_policy_authorizations: state.stablecoin_policy_authorizations.clone(),
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
            Some(&self.ciphertext_archive_tree),
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
                meta.header_mmr_root == expected_header_mmr_root,
                meta.header_mmr_len == expected_header_mmr_len,
            ),
        )?;
        validate_block_actions_locked(&parent_state, &actions)?;
        verify_native_block_artifacts_locked(self, &parent_state, &actions, &meta)?;
        let candidate_wins = native_meta_better_than(&meta, &state.best);
        if candidate_wins {
            if parent.hash == state.best.hash {
                self.commit_announced_tip_extension_locked(&mut state, &actions, &meta)?;
            } else {
                let mut new_chain = self.chain_to_hash(parent.hash)?;
                new_chain.push(meta.clone());
                self.reorganize_chain_to_best_locked(&mut state, new_chain)?;
            }
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
        self.flush_native_durability_barrier(
            "noncanonical native block record",
            NativeStorageDurabilityOperation::NoncanonicalBlockRecord,
        )?;
        Ok(())
    }

    fn validate_stored_block_meta_parent_chain(&self, meta: &NativeBlockMeta) -> Result<()> {
        if meta.height == 0 {
            return verify_native_block_meta_projection(None, meta, None).with_context(|| {
                format!(
                    "validate stored native parent metadata at genesis ({})",
                    hex32(&meta.hash)
                )
            });
        }
        let parent = self
            .header_by_hash(&meta.parent_hash)?
            .ok_or_else(|| anyhow!("missing stored native parent for {}", hex32(&meta.hash)))?;
        let expected_pow_bits = self.expected_child_pow_bits(&parent)?;
        verify_native_block_meta_projection(Some(&parent), meta, Some(expected_pow_bits))
            .with_context(|| {
                format!(
                    "validate stored native parent metadata at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                )
            })
    }

    fn flush_native_durability_barrier(
        &self,
        context: &'static str,
        operation: NativeStorageDurabilityOperation,
    ) -> Result<()> {
        flush_native_db_durability_barrier(&self.db, context, operation)
    }

    fn broadcast_block_announce(&self, meta: &NativeBlockMeta) {
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
        } else {
            info!(
                height = meta.height,
                hash = %hex32(&meta.hash),
                "queued native block announce"
            );
        }
    }

    fn peer_relayable_pending_actions_from(
        &self,
        start: usize,
        limit: usize,
        max_bytes: usize,
    ) -> Vec<PendingAction> {
        if limit == 0 || max_bytes == 0 {
            return Vec::new();
        }
        let state = self.state.read();
        let pending = state
            .pending_actions
            .values()
            .filter(|action| pending_action_peer_relayable(action))
            .collect::<Vec<_>>();
        if pending.is_empty() {
            return Vec::new();
        }
        let start = start % pending.len();
        let mut selected = Vec::new();
        let mut selected_bytes = 0usize;
        for offset in 0..pending.len() {
            if selected.len() >= limit {
                break;
            }
            let action = pending[(start + offset) % pending.len()];
            let action_bytes = pending_action_mempool_bytes(action).max(1);
            if !selected.is_empty() && selected_bytes.saturating_add(action_bytes) > max_bytes {
                break;
            }
            selected_bytes = selected_bytes.saturating_add(action_bytes);
            selected.push(action.clone());
            if selected_bytes >= max_bytes {
                break;
            }
        }
        selected
    }

    fn rebroadcast_peer_relayable_pending_actions(&self) {
        let start = self.pending_action_rebroadcast_cursor.fetch_add(
            NATIVE_SYNC_PENDING_ACTION_REBROADCAST_LIMIT as u64,
            Ordering::Relaxed,
        ) as usize;
        let actions = self.peer_relayable_pending_actions_from(
            start,
            NATIVE_SYNC_PENDING_ACTION_REBROADCAST_LIMIT,
            NATIVE_SYNC_PENDING_ACTION_REBROADCAST_BYTES,
        );
        if actions.is_empty() {
            return;
        }
        let action_bytes = actions.iter().fold(0usize, |total, action| {
            total.saturating_add(pending_action_mempool_bytes(action))
        });
        debug!(
            action_count = actions.len(),
            action_bytes, "rebroadcasting native pending actions to peers"
        );
        for action in actions {
            self.broadcast_pending_action(&action);
        }
    }

    fn broadcast_pending_action(&self, action: &PendingAction) {
        if !pending_action_peer_relayable(action) {
            return;
        }
        let action_bytes = action.encode();
        if action_bytes.len() > MAX_NATIVE_SYNC_PENDING_ACTION_BYTES {
            warn!(
                tx_hash = %hex32(&action.tx_hash),
                action_bytes = action_bytes.len(),
                max_bytes = MAX_NATIVE_SYNC_PENDING_ACTION_BYTES,
                "refusing to relay oversized native pending action"
            );
            return;
        }
        let Some(sync_tx) = self.sync_tx.lock().clone() else {
            return;
        };
        let relay = NativeSyncMessage::PendingAction {
            action: action_bytes,
        };
        let payload = match encode_sync_message(&relay) {
            Ok(payload) => payload,
            Err(err) => {
                warn!(
                    tx_hash = %hex32(&action.tx_hash),
                    error = %err,
                    "failed to encode native pending action relay"
                );
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
            warn!(
                tx_hash = %hex32(&action.tx_hash),
                error = %err,
                "failed to queue native pending action relay"
            );
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
        let mut previous_parent_anchor_verified = range.from_height == 0;
        let mut parent = if range.from_height == 0 {
            None
        } else {
            Some(self.load_canonical_block_at_height_unverified(range.from_height - 1)?)
        };
        let mut action_bodies_verified = 0usize;
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
                if height == range.from_height {
                    previous_parent_anchor_verified = true;
                }
            }
            if meta.height != 0 {
                action_bodies_verified = action_bodies_verified.saturating_add(1);
            }
            parent = Some(meta.clone());
            blocks.push(meta);
        }
        truncate_native_sync_response_blocks_to_wire_budget(
            best_height,
            range.from_height,
            &mut blocks,
        );
        let Some(published_to_height) = blocks.last().map(|block| block.height) else {
            return Ok(Vec::new());
        };
        let published_range = NativeSyncRange {
            from_height: range.from_height,
            to_height: published_to_height,
        };
        evaluate_native_sync_block_range_publication_admission(
            native_sync_block_range_publication_admission_input(
                published_range,
                &blocks,
                blocks.len(),
                action_bodies_verified,
                previous_parent_anchor_verified,
            ),
        )
        .map_err(|rejection| {
            anyhow!(
                "native sync block range publication admission: {}",
                rejection.label()
            )
        })?;
        Ok(native_sync_block_range_publication_rows(blocks))
    }

    fn load_canonical_sync_block_at_height(&self, height: u64) -> Result<NativeBlockMeta> {
        let meta = self.load_canonical_block_at_height_unverified(height)?;
        if meta.height == 0 {
            verify_native_block_meta_projection(None, &meta, None)
                .context("validate genesis native sync block metadata")?;
        } else {
            let parent =
                self.load_canonical_block_at_height_unverified(height.saturating_sub(1))?;
            let expected_pow_bits = self.expected_canonical_child_pow_bits(&parent)?;
            verify_native_block_meta_projection(Some(&parent), &meta, Some(expected_pow_bits))
                .with_context(|| {
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

    fn expected_child_pow_bits(&self, parent: &NativeBlockMeta) -> Result<u32> {
        let chain = self.chain_to_hash(parent.hash)?;
        let Some(chain_parent) = chain.last() else {
            return Err(anyhow!(
                "native PoW schedule cannot evaluate an empty parent chain"
            ));
        };
        if chain_parent.height != parent.height
            || chain_parent.hash != parent.hash
            || chain_parent.pow_bits != parent.pow_bits
            || chain_parent.timestamp_ms != parent.timestamp_ms
        {
            return Err(anyhow!(
                "native PoW schedule parent chain ended at height {} hash {} bits {} timestamp {}, expected height {} hash {} bits {} timestamp {}",
                chain_parent.height,
                hex32(&chain_parent.hash),
                chain_parent.pow_bits,
                chain_parent.timestamp_ms,
                parent.height,
                hex32(&parent.hash),
                parent.pow_bits,
                parent.timestamp_ms
            ));
        }
        native_expected_child_pow_bits_from_chain(&chain, self.config.pow_bits)
    }

    fn expected_canonical_child_pow_bits(&self, parent: &NativeBlockMeta) -> Result<u32> {
        let new_height = parent
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow!("native PoW child height overflow"))?;
        let anchor_timestamp_ms = if let Some(anchor_steps) =
            consensus::pow::pow_retarget_anchor_steps(parent.height, new_height)
        {
            let anchor_height = parent.height.checked_sub(anchor_steps).ok_or_else(|| {
                anyhow!(
                    "native PoW retarget anchor underflow at parent height {}",
                    parent.height
                )
            })?;
            Some(
                self.load_canonical_block_at_height_unverified(anchor_height)?
                    .timestamp_ms,
            )
        } else {
            None
        };
        consensus::pow::expected_pow_bits_from_schedule(
            self.config.pow_bits,
            parent.pow_bits,
            parent.height,
            new_height,
            parent.timestamp_ms,
            anchor_timestamp_ms,
        )
        .map_err(|err| anyhow!("native PoW bits schedule failed: {err}"))
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
            header_mmr_peaks: header_mmr_peaks_from_hashes(&[genesis.hash]),
            best: genesis,
            pending_actions: BTreeMap::new(),
            commitment_tree: CommitmentTreeState::default(),
            nullifiers: BTreeSet::new(),
            consumed_bridge_messages: BTreeSet::new(),
            stablecoin_policy_authorizations: BTreeSet::new(),
            staged_ciphertexts: BTreeMap::new(),
            staged_proofs: BTreeMap::new(),
        };
        for (index, meta) in chain.iter().enumerate().skip(1) {
            let meta = meta.clone();
            let expected_pow_bits = native_expected_child_pow_bits_for_chain_index(
                chain,
                index - 1,
                self.config.pow_bits,
            )?;
            verify_native_block_meta_projection(Some(&state.best), &meta, Some(expected_pow_bits))
                .with_context(|| {
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
                preview_pending_roots_with_archive(
                    &self.da_ciphertext_tree,
                    Some(&self.ciphertext_archive_tree),
                    &state,
                    &actions,
                )?;
            let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
            let bridge_messages = bridge_messages_from_actions(&actions, meta.height)?;
            let message_root = bridge_message_root(&bridge_messages);
            let message_count = u32::try_from(bridge_messages.len())
                .map_err(|_| anyhow!("native bridge message count overflow"))?;
            let expected_header_mmr_len = header_mmr_leaf_count_after_best(&state.best)?;
            let expected_header_mmr_root =
                header_mmr_root_from_peaks(expected_header_mmr_len, &state.header_mmr_peaks);
            let (fee_total, has_coinbase) =
                native_block_replay_supply_parts(&actions, meta.height)?;
            evaluate_native_block_replay_refinement_for_actions(
                "native replay refinement failed",
                &self.da_ciphertext_tree,
                Some(&self.ciphertext_archive_tree),
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
                    meta.header_mmr_root == expected_header_mmr_root,
                    meta.header_mmr_len == expected_header_mmr_len,
                ),
            )?;
            verify_native_block_artifacts_locked(self, &state, &actions, &meta)?;
            apply_actions_to_memory_with_archive(
                &self.da_ciphertext_tree,
                Some(&self.ciphertext_archive_tree),
                &mut state,
                &actions,
            )?;
            state.header_mmr_peaks = append_header_mmr_peak_state(&state, &meta)?;
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
        let canonical_index_plan = plan_canonical_index_rebuild(
            &new_chain,
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
        )?;
        let new_action_hashes = action_hashes_from_chain(&new_chain)?;
        let mut pending = state.pending_actions.clone();
        for hash in &new_action_hashes {
            pending.remove(hash);
        }
        new_state.staged_ciphertexts = state.staged_ciphertexts.clone();
        new_state.staged_proofs = state.staged_proofs.clone();
        let mut staged_ciphertext_removals = Vec::new();
        for meta in new_chain.iter().skip(1) {
            for action in decode_block_actions(meta)? {
                staged_ciphertext_removals.extend(action.ciphertext_hashes.iter().copied());
                clear_staged_ciphertext_markers(&mut new_state, &action);
            }
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
            &staged_ciphertext_removals,
        )?;
        self.flush_native_durability_barrier(
            "native canonical reorg commit",
            NativeStorageDurabilityOperation::CanonicalReorgCommit,
        )?;
        self.verify_persisted_canonical_head(&new_state.best, "native canonical reorg commit")?;

        new_state.pending_actions = pending;
        publish_reorganized_state(state, new_state);
        Ok(())
    }

    fn commit_announced_tip_extension_locked(
        &self,
        state: &mut NativeState,
        actions: &[PendingAction],
        meta: &NativeBlockMeta,
    ) -> Result<()> {
        let planned = plan_pending_action_effects(&self.da_ciphertext_tree, state, actions)?;
        let mut next_state = state.clone();
        apply_planned_actions_to_memory(&mut next_state, actions, &planned)?;
        if next_state.commitment_tree.root() != meta.state_root
            || nullifier_root_from_set(&next_state.nullifiers) != meta.nullifier_root
        {
            return Err(anyhow!("native announced tip extension preview mismatch"));
        }

        self.commit_mined_block_atomically(actions, &planned, meta)?;
        self.flush_native_durability_barrier(
            "native announced tip extension commit",
            NativeStorageDurabilityOperation::MinedBlockCommit,
        )?;
        self.verify_persisted_canonical_head(meta, "native announced tip extension commit")?;

        next_state.header_mmr_peaks = append_header_mmr_peak_state(state, meta)?;
        next_state.best = meta.clone();
        self.prune_invalid_pending_actions_after_state_advance(
            &mut next_state,
            "native announced block pending action repair",
        )?;
        publish_mined_state(state, next_state);
        Ok(())
    }

    fn commit_sync_tip_extension_batch_locked(
        &self,
        state: &mut NativeState,
        metas: &[NativeBlockMeta],
    ) -> Result<usize> {
        if metas.is_empty() {
            return Ok(0);
        }

        let mut next_state = state.clone();
        let mut pow_chain = self.chain_to_hash(state.best.hash)?;
        let mut parent = next_state.best.clone();
        let mut block_entries = Vec::with_capacity(metas.len());
        let mut height_entries = Vec::with_capacity(metas.len());
        let mut commitment_entries = Vec::new();
        let mut ciphertext_archive_entries = Vec::new();
        let mut nullifier_entries = Vec::new();
        let mut bridge_replay_entries = Vec::new();
        let mut ciphertext_index_entries = Vec::new();
        let mut pending_action_removals = Vec::new();
        let mut staged_ciphertext_removals = Vec::new();
        let mut action_count = 0usize;
        let mut planned_action_count = 0usize;

        for meta in metas {
            if self.header_by_hash(&meta.hash)?.is_some() {
                return Err(anyhow!(
                    "native sync tip extension batch includes already known block {}",
                    hex32(&meta.hash)
                ));
            }
            if meta.parent_hash != parent.hash {
                return Err(anyhow!(
                    "native sync tip extension batch is not contiguous at height {}",
                    meta.height
                ));
            }

            let expected_pow_bits =
                native_expected_child_pow_bits_from_chain(&pow_chain, self.config.pow_bits)?;
            validate_announced_block(&parent, meta, expected_pow_bits)?;
            let expected_header_mmr_len = header_mmr_leaf_count_after_best(&next_state.best)?;
            let expected_header_mmr_root =
                header_mmr_root_from_peaks(expected_header_mmr_len, &next_state.header_mmr_peaks);
            let parent_state = NativeState {
                best: next_state.best.clone(),
                header_mmr_peaks: next_state.header_mmr_peaks.clone(),
                pending_actions: BTreeMap::new(),
                commitment_tree: next_state.commitment_tree.clone(),
                nullifiers: next_state.nullifiers.clone(),
                consumed_bridge_messages: next_state.consumed_bridge_messages.clone(),
                stablecoin_policy_authorizations: next_state
                    .stablecoin_policy_authorizations
                    .clone(),
                staged_ciphertexts: BTreeMap::new(),
                staged_proofs: BTreeMap::new(),
            };

            let actions = decode_block_actions(meta)?;
            let expected_action_bytes: Vec<Vec<u8>> = actions.iter().map(Encode::encode).collect();
            if meta.action_bytes != expected_action_bytes {
                return Err(anyhow!(
                    "native sync tip extension action bytes mismatch at height {}",
                    meta.height
                ));
            }
            verify_decoded_action_root(&actions, meta, "native sync tip extension action root")?;
            let (state_root, nullifier_root, extrinsics_root, tx_count) =
                preview_pending_roots(&self.da_ciphertext_tree, &parent_state, &actions)?;
            let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
            let bridge_messages = bridge_messages_from_actions(&actions, meta.height)?;
            let message_root = bridge_message_root(&bridge_messages);
            let message_count = u32::try_from(bridge_messages.len())
                .map_err(|_| anyhow!("native bridge message count overflow"))?;
            let (fee_total, has_coinbase) =
                native_block_replay_supply_parts(&actions, meta.height)?;
            evaluate_native_block_replay_refinement_for_actions(
                "native sync tip extension replay refinement failed",
                &self.da_ciphertext_tree,
                Some(&self.ciphertext_archive_tree),
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
                    meta.header_mmr_root == expected_header_mmr_root,
                    meta.header_mmr_len == expected_header_mmr_len,
                ),
            )?;
            validate_block_actions_locked(&parent_state, &actions)?;
            verify_native_block_artifacts_locked(self, &parent_state, &actions, meta)?;

            let planned =
                plan_pending_action_effects(&self.da_ciphertext_tree, &next_state, &actions)?;
            let action_len = actions.len();
            let planned_len = planned.len();
            append_native_block_commit_index_entries(
                "native sync tip extension",
                &actions,
                &planned,
                &mut commitment_entries,
                &mut ciphertext_archive_entries,
                &mut nullifier_entries,
                &mut bridge_replay_entries,
                &mut ciphertext_index_entries,
                &mut pending_action_removals,
                &mut staged_ciphertext_removals,
            )?;
            action_count = action_count
                .checked_add(action_len)
                .ok_or_else(|| anyhow!("native sync tip extension action count overflow"))?;
            planned_action_count =
                planned_action_count
                    .checked_add(planned_len)
                    .ok_or_else(|| {
                        anyhow!("native sync tip extension planned action count overflow")
                    })?;

            apply_planned_actions_to_memory(&mut next_state, &actions, &planned)?;
            if next_state.commitment_tree.root() != meta.state_root
                || nullifier_root_from_set(&next_state.nullifiers) != meta.nullifier_root
            {
                return Err(anyhow!(
                    "native sync tip extension preview mismatch at height {}",
                    meta.height
                ));
            }

            block_entries.push((meta.hash, bincode::serialize(meta)?));
            height_entries.push((meta.height, meta.hash));
            next_state.header_mmr_peaks = append_header_mmr_peak_state(&next_state, meta)?;
            next_state.best = meta.clone();
            pow_chain.push(meta.clone());
            parent = meta.clone();
        }

        let canonical_index_plan = NativeCanonicalIndexPlan {
            commitment_entries,
            nullifier_entries,
            bridge_replay_entries,
            ciphertext_index_entries,
            ciphertext_archive_entries,
        };
        self.commit_sync_tip_extension_batch_atomically(
            canonical_index_plan,
            &block_entries,
            &height_entries,
            &pending_action_removals,
            &staged_ciphertext_removals,
            action_count,
            planned_action_count,
            &next_state.best,
        )?;
        self.flush_native_durability_barrier(
            "native sync tip extension batch commit",
            NativeStorageDurabilityOperation::MinedBlockCommit,
        )?;
        self.verify_persisted_canonical_head(
            &next_state.best,
            "native sync tip extension batch commit",
        )?;
        self.prune_invalid_pending_actions_after_state_advance(
            &mut next_state,
            "native sync tip extension pending action repair",
        )?;
        publish_mined_state(state, next_state);
        Ok(metas.len())
    }

    fn prune_invalid_pending_actions_after_state_advance(
        &self,
        state: &mut NativeState,
        context: &'static str,
    ) -> Result<()> {
        if state.pending_actions.is_empty() {
            return Ok(());
        }

        let original_pending = std::mem::take(&mut state.pending_actions);
        let original_hashes = original_pending.keys().copied().collect::<BTreeSet<_>>();
        let retained = revalidate_pending_actions_after_state_advance(state, original_pending);
        let retained_hashes = retained.keys().copied().collect::<BTreeSet<_>>();
        let mut dropped = original_hashes
            .difference(&retained_hashes)
            .copied()
            .collect::<BTreeSet<_>>();
        state.pending_actions = retained;
        if self.config.miner_address.is_some() {
            let pending_before_coinbase_prune =
                state.pending_actions.keys().copied().collect::<Vec<_>>();
            prune_auto_coinbase_actions_from_pending(state, context);
            for hash in pending_before_coinbase_prune {
                if !state.pending_actions.contains_key(&hash) {
                    dropped.insert(hash);
                }
            }
        }

        if dropped.is_empty() {
            return Ok(());
        }

        let dropped = dropped.into_iter().collect::<Vec<_>>();
        for hash in &dropped {
            self.action_tree.remove(hash.as_slice()).with_context(|| {
                format!(
                    "remove invalid pending action after state advance {}",
                    hex32(hash)
                )
            })?;
        }
        self.flush_native_durability_barrier(
            context,
            NativeStorageDurabilityOperation::StartupPendingActionRepair,
        )?;
        info!(
            context,
            dropped_count = dropped.len(),
            "pruned native pending actions after canonical state advance"
        );
        Ok(())
    }

    fn commit_reorg_state_atomically(
        &self,
        canonical_index_plan: NativeCanonicalIndexPlan,
        block_entries: &[([u8; 32], Vec<u8>)],
        height_entries: &[(u64, [u8; 32])],
        pending_entries: &[([u8; 32], Vec<u8>)],
        best: &NativeBlockMeta,
        staged_ciphertext_removals: &[[u8; 48]],
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
            staged_ciphertext_removals.len(),
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
                    for hash in staged_ciphertext_removals {
                        da_ciphertext_tree.remove(hash.to_vec())?;
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
        self.flush_native_durability_barrier(
            "native canonical index repair",
            NativeStorageDurabilityOperation::CanonicalIndexRepair,
        )?;
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
        let expected_action_bytes: Vec<Vec<u8>> = actions.iter().map(Encode::encode).collect();
        if meta.action_bytes != expected_action_bytes {
            return Err(anyhow!(
                "native mined block action bytes mismatch committed actions"
            ));
        }

        let mut commitment_entries = Vec::new();
        let mut ciphertext_archive_entries = Vec::new();
        let mut nullifier_entries = Vec::new();
        let mut bridge_replay_entries = Vec::new();
        let mut ciphertext_index_entries = Vec::new();
        let mut pending_action_removals = Vec::new();
        let mut staged_ciphertext_removals = Vec::new();

        for (action, effect) in actions.iter().zip(planned.iter()) {
            if action.ciphertext_hashes.len() != action.ciphertext_sizes.len() {
                return Err(anyhow!(
                    "native mined block ciphertext metadata count mismatch: hashes={} sizes={}",
                    action.ciphertext_hashes.len(),
                    action.ciphertext_sizes.len()
                ));
            }

            for (offset, commitment) in action.commitments.iter().enumerate() {
                let offset = u64::try_from(offset)
                    .map_err(|_| anyhow!("native mined block commitment offset overflow"))?;
                let index = effect
                    .commitment_start
                    .checked_add(offset)
                    .ok_or_else(|| anyhow!("native mined block commitment index overflow"))?;
                commitment_entries.push((index, *commitment));
            }
            for (offset, bytes) in effect.ciphertexts.iter().enumerate() {
                let offset = u64::try_from(offset)
                    .map_err(|_| anyhow!("native mined block ciphertext offset overflow"))?;
                let index = effect
                    .commitment_start
                    .checked_add(offset)
                    .ok_or_else(|| anyhow!("native mined block ciphertext index overflow"))?;
                ciphertext_archive_entries.push((index, bytes.clone()));
            }

            nullifier_entries.extend(action.nullifiers.iter().copied());
            if let Some(replay_key) = effect.replay_key {
                bridge_replay_entries.push(replay_key);
            }

            for (idx, hash) in action.ciphertext_hashes.iter().enumerate() {
                let size = action.ciphertext_sizes[idx];
                let idx = u64::try_from(idx)
                    .map_err(|_| anyhow!("native mined block ciphertext row offset overflow"))?;
                let mut value = Vec::with_capacity(32 + 4 + 8);
                value.extend_from_slice(&action.tx_hash);
                value.extend_from_slice(&size.to_le_bytes());
                value.extend_from_slice(&idx.to_le_bytes());
                ciphertext_index_entries.push((*hash, value));
            }

            pending_action_removals.push(action.tx_hash);
            staged_ciphertext_removals.extend(action.ciphertext_hashes.iter().copied());
        }

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
                    for hash in &pending_action_removals {
                        action_tree.remove(hash.to_vec())?;
                    }
                    for hash in &staged_ciphertext_removals {
                        da_ciphertext_tree.remove(hash.to_vec())?;
                    }
                    Ok(())
                },
            );
        commit_result.map_err(|err| anyhow!("atomic native mined block commit failed: {err}"))?;
        Ok(())
    }

    fn commit_sync_tip_extension_batch_atomically(
        &self,
        canonical_index_plan: NativeCanonicalIndexPlan,
        block_entries: &[([u8; 32], Vec<u8>)],
        height_entries: &[(u64, [u8; 32])],
        pending_action_removals: &[[u8; 32]],
        staged_ciphertext_removals: &[[u8; 48]],
        action_count: usize,
        planned_action_count: usize,
        best: &NativeBlockMeta,
    ) -> Result<()> {
        evaluate_native_atomic_commit_manifest_admission(
            native_tip_extension_batch_commit_manifest(
                &canonical_index_plan,
                block_entries,
                height_entries,
                pending_action_removals.len(),
                staged_ciphertext_removals.len(),
                action_count,
                planned_action_count,
            ),
        )
        .map_err(|rejection| {
            native_atomic_commit_manifest_admission_error(
                "native sync tip extension batch commit manifest",
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
        let best_record = bincode::serialize(best)?;
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
                    for hash in pending_action_removals {
                        action_tree.remove(hash.to_vec())?;
                    }
                    for hash in staged_ciphertext_removals {
                        da_ciphertext_tree.remove(hash.to_vec())?;
                    }
                    meta_tree.insert(META_BEST_KEY.to_vec(), best_record.clone())?;
                    Ok(())
                },
            );
        commit_result.map_err(|err| {
            anyhow!("atomic native sync tip extension batch commit failed: {err}")
        })?;
        Ok(())
    }

    fn ensure_ciphertext_archive_index(&self) -> Result<()> {
        let chain = self.chain_to_hash(self.best_meta().hash)?;
        let replayed_state = self.replay_chain_state(&chain)?;
        self.validate_loaded_state_matches_replay(&replayed_state)?;
        let canonical_index_plan = plan_canonical_index_rebuild(
            &chain,
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
        )?;
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

    fn verify_persisted_canonical_head(&self, meta: &NativeBlockMeta, context: &str) -> Result<()> {
        let best_bytes = self
            .meta_tree
            .get(META_BEST_KEY)?
            .ok_or_else(|| anyhow!("{context} missing persisted best pointer"))?;
        let persisted_best = bincode_deserialize_native_block_meta_exact(
            &best_bytes,
            &format!("{context} persisted best metadata"),
        )?;
        if &persisted_best != meta {
            return Err(anyhow!(
                "{context} persisted best pointer mismatch: expected height {} hash {}, got height {} hash {}",
                meta.height,
                hex32(&meta.hash),
                persisted_best.height,
                hex32(&persisted_best.hash)
            ));
        }

        let persisted_height_hash = self
            .hash_by_height(meta.height)?
            .ok_or_else(|| anyhow!("{context} missing canonical height index {}", meta.height))?;
        if persisted_height_hash != meta.hash {
            return Err(anyhow!(
                "{context} canonical height {} points to {}, expected {}",
                meta.height,
                hex32(&persisted_height_hash),
                hex32(&meta.hash)
            ));
        }

        let persisted_block = self.header_by_hash(&meta.hash)?.ok_or_else(|| {
            anyhow!(
                "{context} missing persisted block record for {}",
                hex32(&meta.hash)
            )
        })?;
        if &persisted_block != meta {
            return Err(anyhow!(
                "{context} persisted block record mismatch at height {} ({})",
                meta.height,
                hex32(&meta.hash)
            ));
        }
        Ok(())
    }

    fn best_meta(&self) -> NativeBlockMeta {
        self.state.read().best.clone()
    }

    fn mining_status(&self) -> Value {
        let best = self.best_meta();
        let (syncing, sync_target_height) = self.sync_status_fields();
        let next_pow_bits = self.expected_child_pow_bits(&best).ok();
        json!({
            "is_mining": self.mining.load(Ordering::SeqCst),
            "threads": self.mining_threads.load(Ordering::Relaxed),
            "hash_rate": self.hash_rate(),
            "blocks_found": self.blocks_found.load(Ordering::Relaxed),
            "difficulty": best.pow_bits,
            "next_difficulty": next_pow_bits,
            "block_height": best.height,
            "syncing": syncing,
            "sync_target_height": sync_target_height,
            "mining_sync_gate_open": self.mining_sync_gate_allows_work(),
            "bootstrap_authoring": self.config.bootstrap_mining_authoring,
        })
    }

    fn consensus_status(&self) -> Value {
        let best = self.best_meta();
        let (syncing, sync_target_height) = self.sync_status_fields();
        json!({
            "height": best.height,
            "best_hash": hex32(&best.hash),
            "state_root": hex48(&best.state_root),
            "nullifier_root": hex48(&best.nullifier_root),
            "supply_digest": best.supply_digest,
            "syncing": syncing,
            "sync_target_height": sync_target_height,
            "peers": self.network_peer_count(),
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
        json!({
            "total_bytes": Value::Null,
            "exact_bytes_available": false,
            "blocks_entries": self.block_tree.len() as u64,
            "state_entries": self.meta_tree.len() as u64,
            "transactions_entries": self.action_tree.len() as u64,
            "nullifiers_entries": self.nullifier_tree.len() as u64,
        })
    }

    fn node_config_snapshot(&self, policy: RpcMethodPolicy) -> Value {
        if policy != RpcMethodPolicy::Unsafe {
            return json!({
                "chainSpecId": self.config.chain_spec_id(),
                "chainSpecName": "Hegemon",
                "chainType": self.config.chain_type(),
                "rpcMethods": self.config.rpc_methods,
                "redacted": true,
            });
        }

        json!({
            "nodeName": self.config.node_name,
            "chainSpecId": self.config.chain_spec_id(),
            "chainSpecName": "Hegemon",
            "chainType": self.config.chain_type(),
            "basePath": self.config.base_path.display().to_string(),
            "p2pListenAddr": self.config.p2p_listen_addr,
            "rpcListenAddr": self.config.rpc_addr.to_string(),
            "rpcMethods": self.config.rpc_methods,
            "rpcExternal": self.config.rpc_external,
            "bootstrapNodes": self.config.seeds,
            "bootstrapMiningAuthoring": self.config.bootstrap_mining_authoring,
            "pqVerbose": env_bool("HEGEMON_PQ_VERBOSE"),
            "maxPeers": self.config.max_peers,
            "redacted": false,
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
        let total = self.state.read().commitment_tree.leaf_count();
        let end = wallet_page_end(page, total)?;
        let sources = self.wallet_commitment_sources_for_range(page.start, end)?;
        for index in page.start..end {
            let commitment = self.load_wallet_commitment_at(index)?;
            let commitment_hex = hex48(&commitment);
            entries.push(json!({
                "index": index,
                "value": commitment_hex,
                "commitment": commitment_hex,
                "source": sources.get(&index).copied().unwrap_or("unknown"),
            }));
        }
        Ok(json!({
            "entries": entries,
            "total": total,
            "has_more": end < total,
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

        let leaf_count = self.state.read().commitment_tree.leaf_count();
        let mut entries = Vec::new();
        let end = wallet_page_end(page, leaf_count)?;
        for index in page.start..end {
            let value = self.load_wallet_ciphertext_at(index)?;
            entries.push(json!({
                "index": index,
                "ciphertext": base64::engine::general_purpose::STANDARD.encode(value.as_slice()),
            }));
        }
        Ok((entries, leaf_count))
    }

    fn wallet_commitment_sources_for_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<BTreeMap<u64, &'static str>> {
        let mut sources = BTreeMap::new();
        if start >= end {
            return Ok(sources);
        }

        let best_height = self.state.read().best.height;
        let mut commitment_index = 0u64;
        for height in 1..=best_height {
            if commitment_index >= end {
                break;
            }
            let meta = self.load_canonical_block_at_height_unverified(height)?;
            for action in decode_block_actions(&meta)? {
                let source = wallet_commitment_source_label(&action);
                for _ in &action.commitments {
                    if commitment_index >= start && commitment_index < end {
                        sources.insert(commitment_index, source);
                    }
                    commitment_index = commitment_index
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("native commitment source index overflow"))?;
                    if commitment_index >= end {
                        break;
                    }
                }
                if commitment_index >= end {
                    break;
                }
            }
        }
        Ok(sources)
    }

    fn load_wallet_commitment_at(&self, index: u64) -> Result<[u8; 48]> {
        let value = self
            .commitment_tree
            .get(height_key(index))?
            .ok_or_else(|| anyhow!("native commitment archive index gap: missing {index}"))?;
        if value.len() != 48 {
            return Err(anyhow!(
                "native commitment archive value has invalid length: expected 48, got {}",
                value.len()
            ));
        }
        let mut commitment = [0u8; 48];
        commitment.copy_from_slice(value.as_ref());
        Ok(commitment)
    }

    fn load_wallet_ciphertext_at(&self, index: u64) -> Result<Vec<u8>> {
        let value = self
            .ciphertext_archive_tree
            .get(height_key(index))?
            .ok_or_else(|| anyhow!("native ciphertext archive index gap: missing {index}"))?;
        validate_wallet_ciphertext_archive_value(value.as_ref())?;
        Ok(value.to_vec())
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
        let action = match self.validate_and_stage_action(request) {
            Ok(action) => action,
            Err(err) => {
                return json!({
                "success": false,
                "tx_hash": null,
                "error": err.to_string(),
                });
            }
        };

        let tx_hash = hex32(&action.tx_hash);
        self.broadcast_pending_action(&action);
        json!({
            "success": true,
            "tx_hash": tx_hash,
            "error": null,
        })
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
        let current_height = self.best_meta().height;
        if !kernel_manifest().binding_allowed(binding, current_height) {
            return Err(anyhow!(
                "native action version binding circuit={} crypto={} is not active at height {}",
                binding.circuit,
                binding.crypto,
                current_height
            ));
        }
        let mut consumed_staged_proof: Option<([u8; 64], Vec<u8>)> = None;
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
                let (_, ciphertext_hashes, ciphertext_sizes) = admitted_inline_ciphertext_metadata(
                    public_args.len(),
                    args.proof.len(),
                    &args.ciphertexts,
                )?;
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
                    consumed_staged_proof = Some((args.binding_hash, proof.clone()));
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
            if is_candidate_artifact_action(&pending)
                && state
                    .pending_actions
                    .values()
                    .any(is_shielded_transfer_action)
            {
                return Err(anyhow!(
                    "candidate artifact submissions are disabled while shielded transfers are pending; native block templates build same-block candidates locally"
                ));
            }
            if let Some((binding_hash, proof)) = &consumed_staged_proof {
                let proof_key = hex64(binding_hash);
                match state.staged_proofs.get(&proof_key) {
                    Some(current) if current == proof => {}
                    Some(_) => {
                        return Err(anyhow!(
                            "staged proof changed before native pending action stage"
                        ));
                    }
                    None => {
                        return Err(anyhow!(
                            "staged proof missing before native pending action stage"
                        ));
                    }
                }
            }
            let pending_encoded = pending.encode();
            let dropped_candidates = if is_shielded_transfer_action(&pending) {
                pending_candidate_artifact_hashes(&state)
            } else {
                Vec::new()
            };
            let stage_result: sled::transaction::TransactionResult<(), std::convert::Infallible> =
                (&self.action_tree, &self.da_proof_tree).transaction(
                    |(action_tree, da_proof_tree)| {
                        for hash in &dropped_candidates {
                            action_tree.remove(hash.as_slice())?;
                        }
                        action_tree.insert(pending.tx_hash.as_slice(), pending_encoded.clone())?;
                        if let Some((binding_hash, _)) = &consumed_staged_proof {
                            da_proof_tree.remove(binding_hash.to_vec())?;
                        }
                        Ok(())
                    },
                );
            stage_result
                .map_err(|err| anyhow!("atomic native pending action stage failed: {err}"))?;
            self.flush_native_durability_barrier(
                "native pending action stage",
                NativeStorageDurabilityOperation::PendingActionStage,
            )?;
            if let Some((binding_hash, _)) = &consumed_staged_proof {
                state.staged_proofs.remove(&hex64(binding_hash));
            }
            for hash in &dropped_candidates {
                debug!(
                    tx_hash = %hex32(hash),
                    "dropping pending candidate artifact before staging shielded transfer"
                );
                state.pending_actions.remove(hash);
            }
            state
                .pending_actions
                .insert(pending.tx_hash, pending.clone());
        }

        Ok(pending)
    }

    fn stage_relayed_pending_action(
        &self,
        pending: PendingAction,
    ) -> Result<Option<PendingAction>> {
        if !pending_action_peer_relayable(&pending) {
            return Err(anyhow!("native pending action route is not peer-relayable"));
        }
        if pending.tx_hash != pending_action_hash(&pending) {
            return Err(anyhow!("native pending action hash binding mismatch"));
        }
        if pending_action_mempool_bytes(&pending) > MAX_NATIVE_SYNC_PENDING_ACTION_BYTES {
            return Err(anyhow!(
                "native pending action exceeds peer relay limit of {MAX_NATIVE_SYNC_PENDING_ACTION_BYTES} bytes"
            ));
        }
        let pending_encoded = pending.encode();
        let staged = {
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
                return Ok(None);
            }
            if pending_action_semantic_duplicate_exists(&state.pending_actions, &pending) {
                return Ok(None);
            }
            validate_pending_action_against_mempool_state(&state, &pending)?;
            let dropped_candidates = if is_shielded_transfer_action(&pending) {
                pending_candidate_artifact_hashes(&state)
            } else {
                Vec::new()
            };
            let stage_result: sled::transaction::TransactionResult<(), std::convert::Infallible> =
                self.action_tree.transaction(|action_tree| {
                    for hash in &dropped_candidates {
                        action_tree.remove(hash.as_slice())?;
                    }
                    action_tree.insert(pending.tx_hash.as_slice(), pending_encoded.clone())?;
                    Ok(())
                });
            stage_result.map_err(|err| {
                anyhow!("atomic native relayed pending action stage failed: {err}")
            })?;
            self.flush_native_durability_barrier(
                "native relayed pending action stage",
                NativeStorageDurabilityOperation::PendingActionStage,
            )?;
            for hash in &dropped_candidates {
                debug!(
                    tx_hash = %hex32(hash),
                    "dropping pending candidate artifact before staging relayed shielded transfer"
                );
                state.pending_actions.remove(hash);
            }
            state
                .pending_actions
                .insert(pending.tx_hash, pending.clone());
            pending
        };
        Ok(Some(staged))
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
        let request = decode_submit_ciphertexts_rpc_request(request)?;
        let ciphertexts = request
            .ciphertexts
            .as_ref()
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
        let mut prepared_ciphertexts: Vec<([u8; 48], Vec<u8>, u32)> =
            Vec::with_capacity(ciphertexts.len());
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
            prepared_ciphertexts.push((hash, raw, size));
            staged_ciphertexts.insert(hash_hex.clone(), size);
            results.push(json!({
                "hash": hash_hex,
                "size": size,
            }));
        }
        let stage_result: sled::transaction::TransactionResult<(), std::convert::Infallible> =
            self.da_ciphertext_tree.transaction(|da_ciphertext_tree| {
                for (hash, raw, _) in &prepared_ciphertexts {
                    da_ciphertext_tree.insert(hash.to_vec(), raw.clone())?;
                }
                Ok(())
            });
        stage_result
            .map_err(|err| anyhow!("atomic native staged ciphertext upload failed: {err}"))?;
        self.flush_native_durability_barrier(
            "native staged ciphertext upload",
            NativeStorageDurabilityOperation::CiphertextSidecarStage,
        )?;
        publish_staged_ciphertexts(&mut state, staged_ciphertexts);
        Ok(Value::Array(results))
    }

    fn submit_proofs(&self, request: Value) -> Result<Value> {
        let request = decode_submit_proofs_rpc_request(request)?;
        let proofs = request
            .proofs
            .as_ref()
            .ok_or_else(|| anyhow!("da_submitProofs requires proofs array"))?;
        evaluate_native_proof_sidecar_request_admission(NativeSidecarRequestCountAdmissionInput {
            item_count: proofs.len(),
            max_items: MAX_NATIVE_DA_PROOF_UPLOADS,
        })
        .map_err(native_sidecar_upload_admission_error)?;
        let mut results = Vec::with_capacity(proofs.len());
        let mut state = self.state.write();
        let mut staged_proofs = state.staged_proofs.clone();
        let mut prepared_proofs: Vec<([u8; 64], Vec<u8>)> = Vec::with_capacity(proofs.len());
        for item in proofs {
            let binding_hash_value = item.binding_hash.as_deref();
            let binding_hash_bytes = binding_hash_value.and_then(parse_hex64);
            let proof_value = item.proof.as_ref();
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
            validate_staged_proof_byte_budget(
                &staged_proofs,
                &binding_hash_key,
                proof.len(),
                MAX_NATIVE_STAGED_PROOF_BYTES,
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
            let size = u32::try_from(proof.len()).unwrap_or(u32::MAX);
            prepared_proofs.push((binding_hash_bytes, proof.clone()));
            staged_proofs.insert(binding_hash_key.clone(), proof);
            results.push(json!({
                "binding_hash": binding_hash_key,
                "proof_hash": proof_hash_hex,
                "size": size,
            }));
        }
        let stage_result: sled::transaction::TransactionResult<(), std::convert::Infallible> =
            self.da_proof_tree.transaction(|da_proof_tree| {
                for (binding_hash, proof) in &prepared_proofs {
                    da_proof_tree.insert(binding_hash.to_vec(), proof.clone())?;
                }
                Ok(())
            });
        stage_result.map_err(|err| anyhow!("atomic native staged proof upload failed: {err}"))?;
        self.flush_native_durability_barrier(
            "native staged proof upload",
            NativeStorageDurabilityOperation::ProofSidecarStage,
        )?;
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
        .layer(ConcurrencyLimitLayer::new(
            MAX_NATIVE_RPC_CONCURRENT_REQUESTS,
        ))
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
    let identity = PeerIdentity::generate(&identity_seed);
    node.set_network_local_peer_id(identity.peer_id());
    let mut service = P2PService::new(
        identity,
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
    service.set_peer_count_observer(Arc::clone(&node.network_peer_count));
    service.set_peer_snapshot_observer(Arc::clone(&node.network_peer_snapshot));
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

fn admit_native_sync_request_from_peer(
    node: &NativeNode,
    peer_id: PeerId,
) -> Result<(), NativeSyncAdmissionRejection> {
    node.admit_sync_request_from_peer(peer_id)
}

async fn native_sync_loop(node: Arc<NativeNode>, mut handle: ProtocolHandle) {
    let sync_tx = handle.sender();
    let mut best_announce = interval(NATIVE_SYNC_BEST_ANNOUNCE_INTERVAL);
    best_announce.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut pending_rebroadcast = interval(NATIVE_SYNC_PENDING_ACTION_REBROADCAST_INTERVAL);
    pending_rebroadcast.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        let Some((peer_id, msg)) = (tokio::select! {
            maybe_msg = handle.recv() => maybe_msg,
            _ = best_announce.tick() => {
                queue_native_best_sync_announce(&node, &sync_tx);
                queue_missing_blocks_from_sync_target(&node, &sync_tx).await;
                continue;
            }
            _ = pending_rebroadcast.tick() => {
                node.rebroadcast_peer_relayable_pending_actions();
                continue;
            }
        }) else {
            break;
        };
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
                info!(
                    peer = %hex32(&peer_id),
                    height = announced_height,
                    hash = %hex32(&meta.hash),
                    "received native sync announce"
                );
                match node.import_announced_block(meta.clone()) {
                    Ok(true) => {
                        node.observe_verified_sync_peer_height(announced_height);
                        info!(
                            height = meta.height,
                            hash = %hex32(&meta.hash),
                            "imported native block announce"
                        );
                    }
                    Ok(false) => {
                        let known_verified = match node.has_verified_header_hash(&meta.hash) {
                            Ok(known_verified) => known_verified,
                            Err(err) => {
                                warn!(
                                    height = meta.height,
                                    hash = %hex32(&meta.hash),
                                    error = %err,
                                    "failed to check known native block announce for sync evidence"
                                );
                                false
                            }
                        };
                        if !native_meta_better_than(&meta, &node.best_meta()) {
                            if known_verified {
                                let local_height = node.best_meta().height;
                                node.clear_hash_anchored_sync_target_to_local_tip(
                                    announced_height,
                                    meta.hash,
                                    "non-winning native sync announce",
                                );
                                node.observe_verified_sync_peer_height(local_height);
                                debug!(
                                    peer = %hex32(&peer_id),
                                    height = announced_height,
                                    hash = %hex32(&meta.hash),
                                    local_height,
                                    "ignored verified non-winning native sync announce"
                                );
                            } else {
                                debug!(
                                    peer = %hex32(&peer_id),
                                    height = announced_height,
                                    hash = %hex32(&meta.hash),
                                    local_height = node.best_meta().height,
                                    "ignored unverified non-winning native sync announce"
                                );
                            }
                            continue;
                        }
                        if let Some(observed_height) =
                            native_mining_sync_observed_peer_height(NativeMiningSyncEvidenceInput {
                                verified_new_progress: false,
                                verified_known_at_or_below_local_best: known_verified,
                                local_best_height: node.best_meta().height,
                                peer_best_height: announced_height,
                                stopped_on_error: false,
                            })
                        {
                            node.observe_verified_sync_peer_height(observed_height);
                        }
                        request_missing_blocks(
                            &node,
                            &handle,
                            peer_id,
                            announced_height,
                            Some(meta.hash),
                        )
                        .await;
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
                info!(
                    peer = %hex32(&peer_id),
                    from_height,
                    to_height,
                    "received native sync request"
                );
                if to_height < from_height {
                    continue;
                }
                let requested_range = NativeSyncRange {
                    from_height,
                    to_height,
                };
                let local_best_height = node.best_meta().height;
                if let Some((best_height, target_height)) = node.catching_up_to_sync_target() {
                    debug!(
                        from_height,
                        to_height,
                        best_height,
                        target_height,
                        peer = %hex32(&peer_id),
                        "ignoring native sync request while catching up"
                    );
                    continue;
                }
                if from_height > local_best_height.saturating_add(1) {
                    debug!(
                        from_height,
                        to_height,
                        local_best_height,
                        peer = %hex32(&peer_id),
                        "ignoring native sync request above local tip"
                    );
                    continue;
                }
                match node.begin_sync_response_for_peer(peer_id, requested_range) {
                    NativeSyncResponseStart::Started => {}
                    NativeSyncResponseStart::DuplicateRange => {
                        debug!(
                            from_height,
                            to_height,
                            peer = %hex32(&peer_id),
                            "ignoring duplicate native sync response range already in flight"
                        );
                        continue;
                    }
                }
                if let Err(rejection) = admit_native_sync_request_from_peer(node.as_ref(), peer_id)
                {
                    node.end_sync_response_for_peer(peer_id, requested_range);
                    warn!(
                        from_height,
                        to_height,
                        peer = %hex32(&peer_id),
                        rejection = rejection.label(),
                        "rejecting rate-limited native sync request"
                    );
                    continue;
                }
                let range_node = Arc::clone(&node);
                let response_node = Arc::clone(&node);
                let response_tx = sync_tx.clone();
                let response_range = requested_range;
                let load_started = Instant::now();
                tokio::spawn(async move {
                    match tokio::task::spawn_blocking(move || {
                        range_node.block_range(from_height, to_height)
                    })
                    .await
                    {
                        Ok(Ok(blocks)) => {
                            let best_height = response_node.best_meta().height;
                            info!(
                                from_height,
                                to_height,
                                block_count = blocks.len(),
                                load_elapsed_ms = load_started.elapsed().as_millis(),
                                "loaded native sync block range"
                            );
                            send_sync_response_with_sender(
                                &response_tx,
                                peer_id,
                                best_height,
                                blocks,
                            )
                            .await;
                        }
                        Ok(Err(err)) => {
                            warn!(
                                from_height,
                                to_height,
                                error = %err,
                                "failed to load native sync block range"
                            );
                        }
                        Err(err) => {
                            warn!(
                                from_height,
                                to_height,
                                error = %err,
                                "native sync block range worker failed"
                            );
                        }
                    }
                    response_node.end_sync_response_for_peer(peer_id, response_range);
                });
            }
            NativeSyncMessage::Response {
                best_height,
                mut blocks,
            } => {
                let received_from_height = blocks.first().map(|block| block.height);
                let received_to_height = blocks.last().map(|block| block.height);
                info!(
                    peer = %hex32(&peer_id),
                    best_height,
                    block_count = blocks.len(),
                    from_height = ?received_from_height,
                    to_height = ?received_to_height,
                    "received native sync response"
                );
                if let Err(rejection) = admit_and_sort_native_sync_response_blocks(
                    &mut blocks,
                    MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE,
                ) {
                    warn!(
                        block_count = blocks.len(),
                        max_blocks = MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE,
                        rejection = rejection.label(),
                        "rejecting oversized native sync response"
                    );
                    continue;
                }
                let response_range = match (blocks.first(), blocks.last()) {
                    (Some(first), Some(last)) => Some(NativeSyncRange {
                        from_height: first.height,
                        to_height: last.height,
                    }),
                    _ => None,
                };
                let completed_request =
                    node.complete_outbound_sync_response(peer_id, response_range);
                if !completed_request {
                    debug!(
                        peer = %hex32(&peer_id),
                        best_height,
                        block_count = blocks.len(),
                        "native sync response did not match current in-flight request"
                    );
                }
                if native_sync_response_stale_for_local_tip(&node, best_height, &blocks) {
                    debug!(
                        peer = %hex32(&peer_id),
                    best_height,
                    block_count = blocks.len(),
                    local_height = node.best_meta().height,
                    "dropping stale native sync response"
                    );
                    continue;
                }
                if node.clear_nonwinning_sync_target_response_to_local_tip(best_height, &blocks) {
                    debug!(
                        peer = %hex32(&peer_id),
                        best_height,
                        block_count = blocks.len(),
                        local_height = node.best_meta().height,
                        "ignored non-winning native sync target response"
                    );
                    continue;
                }
                node.observe_pending_sync_peer_height(best_height);
                if !node.begin_sync_import() {
                    debug!(
                        peer = %hex32(&peer_id),
                        best_height,
                        block_count = blocks.len(),
                        "deferring native sync response while another import is active"
                    );
                    continue;
                }
                let progress = NativeSyncResponseImportProgress::new(blocks.len());
                let import_node = Arc::clone(&node);
                let report = match tokio::task::spawn_blocking(move || {
                    import_native_sync_response_blocks(&import_node, blocks, best_height, progress)
                })
                .await
                {
                    Ok(report) => {
                        node.end_sync_import();
                        report
                    }
                    Err(err) => {
                        node.end_sync_import();
                        warn!(error = %err, "native sync import worker failed");
                        continue;
                    }
                };
                let progress = report.progress;
                node.refresh_mining_sync_gate();
                if let Some(failure) = report.failure {
                    warn!(
                        height = failure.height,
                        hash = %hex32(&failure.hash),
                        error = %failure.error,
                        "failed to import native sync block"
                    );
                }
                let local_best_height = node.best_meta().height;
                if let Some(observed_height) =
                    native_mining_sync_observed_peer_height(NativeMiningSyncEvidenceInput {
                        verified_new_progress: progress.imported_blocks > 0,
                        verified_known_at_or_below_local_best: progress
                            .completed_with_only_known_blocks(),
                        local_best_height,
                        peer_best_height: best_height,
                        stopped_on_error: progress.stopped_on_error,
                    })
                {
                    node.observe_verified_sync_peer_height(observed_height);
                }
                if progress.imported_blocks > 0 {
                    node.reset_sync_reorg_backfill();
                    info!(
                        imported = progress.imported_blocks,
                        best_height = local_best_height,
                        peer_best_height = best_height,
                        "imported native sync response"
                    );
                } else if native_sync_response_should_escalate_reorg_backfill(
                    progress,
                    local_best_height,
                    best_height,
                ) {
                    let backfill_blocks = node.escalate_sync_reorg_backfill();
                    info!(
                        best_height = local_best_height,
                        peer_best_height = best_height,
                        backfill_blocks,
                        "expanded native sync reorg backfill after unproductive response"
                    );
                } else if !progress.had_blocks && best_height > local_best_height {
                    node.clear_unanchored_sync_target_to_local_tip(
                        best_height,
                        "empty sync response from advertised target",
                    );
                }
                if progress.should_request_more(local_best_height, best_height) {
                    request_missing_blocks(&node, &handle, peer_id, best_height, None).await;
                } else {
                    queue_missing_blocks_from_sync_target(&node, &sync_tx).await;
                    node.refresh_mining_sync_gate();
                }
            }
            NativeSyncMessage::PendingAction { action } => {
                if action.len() > MAX_NATIVE_SYNC_PENDING_ACTION_BYTES {
                    warn!(
                        peer = %hex32(&peer_id),
                        action_bytes = action.len(),
                        max_bytes = MAX_NATIVE_SYNC_PENDING_ACTION_BYTES,
                        "rejecting oversized native pending action relay"
                    );
                    continue;
                }
                let pending = match decode_scale_exact::<PendingAction>(
                    &action,
                    "native pending action relay",
                ) {
                    Ok(pending) => pending,
                    Err(err) => {
                        warn!(
                            peer = %hex32(&peer_id),
                            error = %err,
                            "rejecting malformed native pending action relay"
                        );
                        continue;
                    }
                };
                let tx_hash = pending.tx_hash;
                let staged = match stage_relayed_pending_action(node.as_ref(), pending) {
                    Ok(Some(staged)) => staged,
                    Ok(None) => {
                        debug!(
                            peer = %hex32(&peer_id),
                            tx_hash = %hex32(&tx_hash),
                            "ignored duplicate native pending action relay"
                        );
                        continue;
                    }
                    Err(err) => {
                        warn!(
                            peer = %hex32(&peer_id),
                            tx_hash = %hex32(&tx_hash),
                            error = %err,
                            "rejecting invalid native pending action relay"
                        );
                        continue;
                    }
                };
                info!(
                    peer = %hex32(&peer_id),
                    tx_hash = %hex32(&tx_hash),
                    "staged native pending action from peer relay"
                );
                node.broadcast_pending_action(&staged);
            }
        }
    }
}

struct NativeSyncImportFailure {
    height: u64,
    hash: [u8; 32],
    error: String,
}

struct NativeSyncImportReport {
    progress: NativeSyncResponseImportProgress,
    failure: Option<NativeSyncImportFailure>,
}

fn import_native_sync_response_blocks(
    node: &NativeNode,
    blocks: Vec<NativeBlockMeta>,
    peer_best_height: u64,
    mut progress: NativeSyncResponseImportProgress,
) -> NativeSyncImportReport {
    if let Some(report) =
        import_native_sync_response_winning_branch(node, &blocks, peer_best_height, &mut progress)
    {
        return report;
    }

    let mut failure = None;
    for meta in blocks {
        match skip_stale_nonwinning_sync_block(node, &meta, peer_best_height) {
            Ok(true) => {
                progress.record(NativeSyncResponseImportOutcome::AlreadyKnown);
                continue;
            }
            Ok(false) => {}
            Err(err) => {
                progress.record(NativeSyncResponseImportOutcome::Error);
                failure = Some(NativeSyncImportFailure {
                    height: meta.height,
                    hash: meta.hash,
                    error: err.to_string(),
                });
                break;
            }
        }
        match node.import_announced_block(meta.clone()) {
            Ok(true) => {
                progress.record(NativeSyncResponseImportOutcome::Imported);
                if progress.imported_blocks == 1 {
                    node.observe_verified_sync_peer_height(peer_best_height);
                }
            }
            Ok(false) => {
                progress.record(NativeSyncResponseImportOutcome::AlreadyKnown);
            }
            Err(err) => {
                progress.record(NativeSyncResponseImportOutcome::Error);
                failure = Some(NativeSyncImportFailure {
                    height: meta.height,
                    hash: meta.hash,
                    error: err.to_string(),
                });
                break;
            }
        }
    }
    NativeSyncImportReport { progress, failure }
}

fn import_native_sync_response_winning_branch(
    node: &NativeNode,
    blocks: &[NativeBlockMeta],
    peer_best_height: u64,
    progress: &mut NativeSyncResponseImportProgress,
) -> Option<NativeSyncImportReport> {
    let response_tip = blocks.last()?;
    let local_best = node.best_meta();
    if peer_best_height <= local_best.height || !native_meta_better_than(response_tip, &local_best)
    {
        return None;
    }

    let mut first_unknown = 0usize;
    while first_unknown < blocks.len() {
        match node.has_verified_header_hash(&blocks[first_unknown].hash) {
            Ok(true) => {
                progress.record(NativeSyncResponseImportOutcome::AlreadyKnown);
                first_unknown += 1;
            }
            Ok(false) => break,
            Err(err) => {
                progress.record(NativeSyncResponseImportOutcome::Error);
                return Some(NativeSyncImportReport {
                    progress: *progress,
                    failure: Some(NativeSyncImportFailure {
                        height: blocks[first_unknown].height,
                        hash: blocks[first_unknown].hash,
                        error: err.to_string(),
                    }),
                });
            }
        }
    }

    if let Some(report) = import_native_sync_response_tip_extension(
        node,
        blocks,
        first_unknown,
        peer_best_height,
        progress,
    ) {
        return Some(report);
    }

    let new_chain = if first_unknown == blocks.len() {
        match node.chain_to_hash(response_tip.hash) {
            Ok(chain) => chain,
            Err(err) => {
                progress.record(NativeSyncResponseImportOutcome::Error);
                return Some(NativeSyncImportReport {
                    progress: *progress,
                    failure: Some(NativeSyncImportFailure {
                        height: response_tip.height,
                        hash: response_tip.hash,
                        error: err.to_string(),
                    }),
                });
            }
        }
    } else {
        let anchor_hash = if first_unknown == 0 {
            blocks[first_unknown].parent_hash
        } else {
            blocks[first_unknown - 1].hash
        };
        let _anchor = (match node.header_by_hash(&anchor_hash) {
            Ok(anchor) => anchor,
            Err(err) => {
                progress.record(NativeSyncResponseImportOutcome::Error);
                return Some(NativeSyncImportReport {
                    progress: *progress,
                    failure: Some(NativeSyncImportFailure {
                        height: blocks[first_unknown].height,
                        hash: blocks[first_unknown].hash,
                        error: err.to_string(),
                    }),
                });
            }
        })?;
        let mut chain = match node.chain_to_hash(anchor_hash) {
            Ok(chain) => chain,
            Err(err) => {
                progress.record(NativeSyncResponseImportOutcome::Error);
                return Some(NativeSyncImportReport {
                    progress: *progress,
                    failure: Some(NativeSyncImportFailure {
                        height: blocks[first_unknown].height,
                        hash: blocks[first_unknown].hash,
                        error: err.to_string(),
                    }),
                });
            }
        };
        chain.extend(blocks[first_unknown..].iter().cloned());
        chain
    };

    let mut state = node.state.write();
    if !native_meta_better_than(
        new_chain.last().expect("sync response branch has tip"),
        &state.best,
    ) {
        return None;
    }
    let previous_height = state.best.height;
    let new_tip = new_chain
        .last()
        .expect("sync response branch has tip")
        .clone();
    match node.reorganize_chain_to_best_locked(&mut state, new_chain) {
        Ok(()) => {
            let imported = if first_unknown == blocks.len() {
                1
            } else {
                blocks.len().saturating_sub(first_unknown)
            };
            progress.attempted_blocks = progress.response_block_count;
            progress.imported_blocks = progress
                .imported_blocks
                .saturating_add(u64::try_from(imported).unwrap_or(u64::MAX));
            info!(
                imported,
                previous_height,
                best_height = new_tip.height,
                peer_best_height,
                "imported native sync response by batch reorg"
            );
            Some(NativeSyncImportReport {
                progress: *progress,
                failure: None,
            })
        }
        Err(err) => {
            progress.record(NativeSyncResponseImportOutcome::Error);
            Some(NativeSyncImportReport {
                progress: *progress,
                failure: Some(NativeSyncImportFailure {
                    height: new_tip.height,
                    hash: new_tip.hash,
                    error: err.to_string(),
                }),
            })
        }
    }
}

fn import_native_sync_response_tip_extension(
    node: &NativeNode,
    blocks: &[NativeBlockMeta],
    first_unknown: usize,
    peer_best_height: u64,
    progress: &mut NativeSyncResponseImportProgress,
) -> Option<NativeSyncImportReport> {
    if first_unknown >= blocks.len() {
        return None;
    }
    let local_best = node.best_meta();
    let anchor_hash = if first_unknown == 0 {
        blocks[first_unknown].parent_hash
    } else {
        blocks[first_unknown - 1].hash
    };
    if anchor_hash != local_best.hash {
        return None;
    }

    let mut expected_parent = anchor_hash;
    for meta in &blocks[first_unknown..] {
        if meta.parent_hash != expected_parent {
            return None;
        }
        expected_parent = meta.hash;
    }

    let mut offset = first_unknown;
    let mut imported_total = 0usize;
    let mut last_imported_height = local_best.height;
    while offset < blocks.len() {
        let expected_anchor = if offset == first_unknown {
            anchor_hash
        } else {
            blocks[offset - 1].hash
        };
        let end = offset
            .saturating_add(MAX_NATIVE_SYNC_IMPORT_BATCH_BLOCKS)
            .min(blocks.len());
        let batch = &blocks[offset..end];
        let batch_tip = batch.last().expect("non-empty sync tip extension batch");
        let imported = {
            let mut state = node.state.write();
            if state.best.hash != expected_anchor {
                if imported_total == 0 {
                    return None;
                }
                break;
            }
            match node.commit_sync_tip_extension_batch_locked(&mut state, batch) {
                Ok(imported) => imported,
                Err(err) => {
                    progress.attempted_blocks = progress.response_block_count;
                    progress.imported_blocks = progress
                        .imported_blocks
                        .saturating_add(u64::try_from(imported_total).unwrap_or(u64::MAX));
                    progress.stopped_on_error = true;
                    return Some(NativeSyncImportReport {
                        progress: *progress,
                        failure: Some(NativeSyncImportFailure {
                            height: batch_tip.height,
                            hash: batch_tip.hash,
                            error: err.to_string(),
                        }),
                    });
                }
            }
        };
        imported_total = imported_total.saturating_add(imported);
        last_imported_height = batch_tip.height;
        offset = end;
    }

    if imported_total == 0 {
        return None;
    }
    progress.attempted_blocks = progress.response_block_count;
    progress.imported_blocks = progress
        .imported_blocks
        .saturating_add(u64::try_from(imported_total).unwrap_or(u64::MAX));
    node.observe_verified_sync_peer_height(peer_best_height);
    info!(
        imported = imported_total,
        best_height = last_imported_height,
        peer_best_height,
        "imported native sync response by chunked tip-extension batches"
    );
    Some(NativeSyncImportReport {
        progress: *progress,
        failure: None,
    })
}

fn skip_stale_nonwinning_sync_block(
    node: &NativeNode,
    meta: &NativeBlockMeta,
    peer_best_height: u64,
) -> Result<bool> {
    let local_best = node.best_meta();
    if peer_best_height > local_best.height {
        return Ok(false);
    }
    if meta.height > local_best.height {
        return Ok(false);
    }
    if node.has_verified_header_hash(&meta.hash)? {
        return Ok(false);
    }
    Ok(!native_meta_better_than(meta, &local_best))
}

fn native_sync_response_stale_for_local_tip(
    node: &NativeNode,
    peer_best_height: u64,
    blocks: &[NativeBlockMeta],
) -> bool {
    let local_best = node.best_meta();
    if peer_best_height > local_best.height {
        return false;
    }
    let Some(response_tip) = blocks.last() else {
        return true;
    };
    if response_tip.height > local_best.height {
        return false;
    }
    if response_tip.hash == local_best.hash {
        return true;
    }
    if native_meta_better_than(response_tip, &local_best) {
        return false;
    }
    match node.has_verified_header_hash(&response_tip.hash) {
        Ok(true) => true,
        Ok(false) | Err(_) => !native_meta_better_than(response_tip, &local_best),
    }
}

fn queue_native_best_sync_announce(node: &NativeNode, sync_tx: &ProtocolSender) {
    let meta = node.best_meta();
    if let Some((best_height, target_height)) = node.catching_up_to_sync_target() {
        debug!(
            best_height,
            target_height, "skipping native sync announce while catching up"
        );
        return;
    }
    let announce = NativeSyncMessage::Announce(Box::new(meta.clone()));
    let payload = match encode_sync_message(&announce) {
        Ok(payload) => payload,
        Err(err) => {
            warn!(error = %err, "failed to encode native best sync announce");
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
        debug!(
            height = meta.height,
            error = %err,
            "failed to queue native best sync announce"
        );
    } else {
        debug!(
            height = meta.height,
            hash = %hex32(&meta.hash),
            "queued native best sync announce"
        );
    }
}

async fn queue_missing_blocks_from_sync_target(node: &NativeNode, sync_tx: &ProtocolSender) {
    if node.sync_import_in_flight() {
        return;
    }
    let target = node.sync_target_height.load(Ordering::Relaxed);
    let target_hash = *node.sync_target_hash.lock();
    let target_peer = *node.sync_target_peer.lock();
    let best = node.best_meta();
    let Some(range) = native_sync_observed_tip_request_range(
        best.height,
        best.hash,
        target,
        target_hash,
        NATIVE_SYNC_REQUEST_BLOCKS,
        node.sync_reorg_backfill_blocks(),
    ) else {
        return;
    };
    if !node.begin_outbound_sync_request(target_peer, range) {
        debug!(
            best_height = best.height,
            target,
            from_height = range.from_height,
            to_height = range.to_height,
            "skipping duplicate in-flight native sync target request"
        );
        return;
    }
    let request = NativeSyncMessage::Request {
        from_height: range.from_height,
        to_height: range.to_height,
    };
    let payload = match encode_sync_message(&request) {
        Ok(payload) => payload,
        Err(err) => {
            node.complete_outbound_sync_request_target(target_peer);
            warn!(error = %err, "failed to encode native sync target request");
            return;
        }
    };
    let message = DirectedProtocolMessage {
        target: target_peer,
        message: ProtocolMessage {
            protocol: NATIVE_SYNC_PROTOCOL_ID,
            payload,
        },
    };
    if let Err(err) = sync_tx.send(message).await {
        node.complete_outbound_sync_request_target(target_peer);
        debug!(error = %err, "failed to queue native sync target request");
    } else {
        let target_peer_label = target_peer
            .map(|peer| hex32(&peer))
            .unwrap_or_else(|| "broadcast".to_string());
        debug!(
            best_height = best.height,
            target,
            from_height = range.from_height,
            to_height = range.to_height,
            target_peer = target_peer_label,
            "queued native sync target request"
        );
    }
}

async fn request_missing_blocks(
    node: &NativeNode,
    handle: &ProtocolHandle,
    peer_id: PeerId,
    announced_height: u64,
    announced_hash: Option<[u8; 32]>,
) {
    node.observe_pending_sync_peer_tip(Some(peer_id), announced_height, announced_hash);
    if node.sync_import_in_flight() {
        debug!(
            peer = %hex32(&peer_id),
            announced_height,
            "deferring missing native sync request while import is active"
        );
        return;
    }
    let best = node.best_meta();
    let missing_request_input = NativeSyncMissingRequestInput {
        best_height: best.height,
        announced_height,
        max_blocks: NATIVE_SYNC_REQUEST_BLOCKS,
    };
    let admitted_missing_range = native_sync_missing_request_range(missing_request_input);
    let Some(range) = native_sync_observed_tip_request_range_from_admitted_missing(
        missing_request_input,
        best.hash,
        announced_hash,
        node.sync_reorg_backfill_blocks(),
        admitted_missing_range,
    ) else {
        return;
    };
    if !node.begin_outbound_sync_request(Some(peer_id), range) {
        debug!(
            peer = %hex32(&peer_id),
            best_height = best.height,
            announced_height,
            from_height = range.from_height,
            to_height = range.to_height,
            "skipping duplicate in-flight native sync request"
        );
        return;
    }
    debug!(
        best_height = best.height,
        announced_height,
        from_height = range.from_height,
        to_height = range.to_height,
        "requesting missing native sync blocks"
    );
    let queued = send_sync_message(
        handle,
        peer_id,
        NativeSyncMessage::Request {
            from_height: range.from_height,
            to_height: range.to_height,
        },
    )
    .await;
    if !queued {
        node.complete_outbound_sync_request(peer_id);
    }
}

async fn send_sync_message(
    handle: &ProtocolHandle,
    peer_id: PeerId,
    message: NativeSyncMessage,
) -> bool {
    let label = native_sync_message_label(&message);
    let (from_height, to_height) = match &message {
        NativeSyncMessage::Request {
            from_height,
            to_height,
        } => (Some(*from_height), Some(*to_height)),
        _ => (None, None),
    };
    let payload = match encode_sync_message(&message) {
        Ok(payload) => payload,
        Err(err) => {
            warn!(error = %err, "failed to encode native sync message");
            return false;
        }
    };
    if let Err(err) = handle.send_to(peer_id, payload).await {
        warn!(error = %err, "failed to send native sync message");
        false
    } else {
        info!(
            peer = %hex32(&peer_id),
            message = label,
            from_height = ?from_height,
            to_height = ?to_height,
            "queued native sync message"
        );
        true
    }
}

async fn send_sync_response_with_sender(
    sync_tx: &ProtocolSender,
    peer_id: PeerId,
    best_height: u64,
    blocks: Vec<NativeBlockMeta>,
) {
    let from_height = blocks.first().map(|block| block.height);
    let to_height = blocks.last().map(|block| block.height);
    let block_count = blocks.len();
    let response = NativeSyncMessage::Response {
        best_height,
        blocks,
    };
    let payload = match encode_sync_message(&response) {
        Ok(payload) => payload,
        Err(err) => {
            warn!(
                max_bytes = MAX_NATIVE_SYNC_MESSAGE_BYTES,
                error = %err,
                "failed to encode admitted native sync response"
            );
            return;
        }
    };
    let message = DirectedProtocolMessage {
        target: Some(peer_id),
        message: ProtocolMessage {
            protocol: NATIVE_SYNC_PROTOCOL_ID,
            payload,
        },
    };
    if let Err(err) = sync_tx.send(message).await {
        warn!(
            error = %err,
            "failed to queue native sync response"
        );
    } else {
        info!(
            peer = %hex32(&peer_id),
            best_height,
            block_count,
            from_height = ?from_height,
            to_height = ?to_height,
            "queued native sync response"
        );
    }
}

fn native_sync_message_label(message: &NativeSyncMessage) -> &'static str {
    match message {
        NativeSyncMessage::Announce(_) => "announce",
        NativeSyncMessage::Request { .. } => "request",
        NativeSyncMessage::Response { .. } => "response",
        NativeSyncMessage::PendingAction { .. } => "pending_action",
    }
}

fn truncate_native_sync_response_blocks_to_wire_budget(
    best_height: u64,
    from_height: u64,
    blocks: &mut Vec<NativeBlockMeta>,
) {
    let original_len = blocks.len();
    loop {
        let Some(last) = blocks.last() else {
            return;
        };
        match native_sync_response_wire_bytes(best_height, blocks) {
            Ok(bytes) if bytes <= MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES || blocks.len() == 1 => {
                if blocks.len() < original_len {
                    warn!(
                        from_height,
                        to_height = last.height,
                        admitted_blocks = blocks.len(),
                        original_blocks = original_len,
                        target_bytes = MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES,
                        wire_bytes = bytes,
                        "truncated native sync response to fit live relay budget"
                    );
                }
                return;
            }
            Ok(bytes) => {
                let current_len = blocks.len();
                let estimated_len = ((current_len as u128)
                    .saturating_mul(MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES as u128)
                    / (bytes as u128))
                    .max(1) as usize;
                let shrink_to = estimated_len.min(current_len.saturating_sub(1)).max(1);
                blocks.truncate(shrink_to);
            }
            Err(err) => {
                warn!(
                    from_height,
                    attempted_blocks = blocks.len(),
                    max_bytes = MAX_NATIVE_SYNC_MESSAGE_BYTES,
                    error = %err,
                    "truncated native sync response before materializing an oversized wire payload"
                );
                blocks.pop();
            }
        }
    }
}

fn native_sync_response_wire_bytes(best_height: u64, blocks: &[NativeBlockMeta]) -> Result<usize> {
    let response = NativeSyncMessage::Response {
        best_height,
        blocks: blocks.to_vec(),
    };
    let payload = encode_sync_message(&response)?;
    let wire_message = WireMessage::Proto(ProtocolMessage {
        protocol: NATIVE_SYNC_PROTOCOL_ID,
        payload,
    });
    let frame = wire::encode(&wire_message, wire::MAX_WIRE_FRAME_LEN)
        .context("encode native sync protocol wire message")?;
    if frame.len().saturating_add(AES_GCM_TAG_BYTES) > wire::MAX_WIRE_FRAME_LEN {
        return Err(anyhow!(
            "native sync protocol wire frame would exceed encrypted transport cap: frame_bytes={} tag_bytes={} max_bytes={}",
            frame.len(),
            AES_GCM_TAG_BYTES,
            wire::MAX_WIRE_FRAME_LEN
        ));
    }
    Ok(frame.len().saturating_add(AES_GCM_TAG_BYTES))
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
        "system_health" => {
            let (syncing, _) = node.sync_status_fields();
            Ok(json!({
                "isSyncing": syncing,
                "peers": node.network_peer_count(),
                "shouldHavePeers": !node.config.seeds.is_empty(),
            }))
        }
        "system_peers" => Ok(system_peers_snapshot(node)),
        "system_version" => Ok(json!(format!(
            "Hegemon Native Node {}",
            env!("CARGO_PKG_VERSION")
        ))),
        "system_name" => Ok(json!("Hegemon Native Node")),
        "system_chain" => Ok(json!("Hegemon")),
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
        "hegemon_nodeConfig" => Ok(node.node_config_snapshot(node.rpc_policy()?)),
        "hegemon_blockTimestamps" => block_timestamps(node, params, false),
        "hegemon_minedBlockTimestamps" => block_timestamps(node, Value::Array(vec![]), true),
        "hegemon_peerList" => Ok(hegemon_peer_list_snapshot(node)),
        "hegemon_peerGraph" => Ok(hegemon_peer_graph_snapshot(node)),
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
            "network_difficulty": node.best_meta().pow_bits,
            "share_difficulty": null,
            "reason": "native pool RPC is not enabled in milestone 1",
        })),
        "hegemon_compactJob" => Ok(json!({
            "available": false,
            "job_id": null,
            "height": null,
            "pre_hash": null,
            "parent_hash": null,
            "network_bits": node.best_meta().pow_bits,
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
            "network_difficulty": node.best_meta().pow_bits,
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
    admit_chain_get_block_response(&meta)?;
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

fn admit_chain_get_block_response(meta: &NativeBlockMeta) -> Result<()> {
    let total = meta
        .action_bytes
        .iter()
        .try_fold(0usize, |total, bytes| total.checked_add(bytes.len()))
        .ok_or_else(|| anyhow!("chain_getBlock action bytes overflow"))?;
    if total > MAX_NATIVE_CHAIN_GET_BLOCK_ACTION_BYTES {
        return Err(anyhow!(
            "chain_getBlock action bytes exceed safe RPC cap: {} > {}",
            total,
            MAX_NATIVE_CHAIN_GET_BLOCK_ACTION_BYTES
        ));
    }
    Ok(())
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
    let explicit_block_hash = bridge_witness_explicit_block_hash(&params)?;
    let block_hash_was_explicit = explicit_block_hash.is_some();
    let block_hash = match explicit_block_hash {
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
            explicit_block_hash: block_hash_was_explicit,
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
            max_explicit_history: MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS,
            max_materialized_history: MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS,
        })
        .map_err(native_bridge_witness_export_admission_error)?;
    let meta = meta.expect("bridge witness admission ensures block exists");
    let messages = messages.expect("bridge witness admission ensures actions decoded");
    let message = messages
        .get(message_index)
        .cloned()
        .expect("bridge witness admission ensures message index is in bounds");
    let parent = parent.expect("bridge witness admission ensures parent exists");
    let expected_pow_bits = node.expected_child_pow_bits(&parent)?;
    verify_native_block_meta_projection(Some(&parent), &meta, Some(expected_pow_bits))
        .with_context(|| {
            format!(
                "validate bridge witness native block metadata at height {} ({})",
                meta.height,
                hex32(&meta.hash)
            )
        })?;
    let header = pow_header_from_meta(&meta);
    let parent_checkpoint = checkpoint_from_meta(&parent);
    let long_range_trusted_checkpoint = if best.height > meta.height {
        let genesis_hash = node
            .hash_by_height(0)?
            .ok_or_else(|| anyhow!("missing genesis hash for bridge witness"))?;
        let genesis = node
            .header_by_hash(&genesis_hash)?
            .ok_or_else(|| anyhow!("missing genesis header for bridge witness"))?;
        Some(checkpoint_from_meta(&genesis))
    } else {
        None
    };
    let output_anchor = long_range_trusted_checkpoint
        .as_ref()
        .unwrap_or(&parent_checkpoint);
    let message_checkpoint = checkpoint_from_meta(&meta);
    let best_checkpoint = checkpoint_from_meta(&best);
    let output = bridge_checkpoint_output_with_tip_from_anchor(
        output_anchor,
        &message_checkpoint,
        &best_checkpoint,
        meta.message_root,
        &message,
        confirmations_checked,
        HEGEMON_BRIDGE_LONG_RANGE_MIN_TIP_WORK_V1,
    );
    let direct_output = bridge_checkpoint_output_from_anchor(
        &parent_checkpoint,
        &message_checkpoint,
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
                ));
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
    let tip_parent_opening = header_mmr_opening_from_hashes(
        &tip_history,
        tip_meta
            .height
            .checked_sub(1)
            .ok_or_else(|| anyhow!("bridge witness tip has no parent"))?,
    )
    .map_err(|err| anyhow!("build tip parent MMR opening failed: {err:?}"))?;
    let message_header_opening = header_mmr_opening_from_hashes(&tip_history, message_meta.height)
        .map_err(|err| anyhow!("build message header MMR opening failed: {err:?}"))?;
    let message_parent_opening = header_mmr_opening_from_hashes(
        &tip_history,
        message_meta
            .height
            .checked_sub(1)
            .ok_or_else(|| anyhow!("bridge witness message header has no parent"))?,
    )
    .map_err(|err| anyhow!("build message parent MMR opening failed: {err:?}"))?;
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
        let parent_opening = header_mmr_opening_from_hashes(
            &tip_history,
            sample_height
                .checked_sub(1)
                .ok_or_else(|| anyhow!("sampled bridge header has no parent"))?,
        )
        .map_err(|err| anyhow!("build sampled parent MMR opening failed: {err:?}"))?;
        sample_headers.push(HeaderMmrLeafWitnessV1 {
            header: pow_header_from_meta(&sample_meta),
            opening,
            parent_opening,
        });
    }
    Ok(Some(HegemonLongRangeProofV1 {
        verifier_hash: HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V1,
        trusted_checkpoint: checkpoint_from_meta(&genesis),
        tip_header,
        tip_parent_opening,
        message_header,
        message_header_opening,
        message_parent_opening,
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
        "trusted_checkpoint_digest": hex32(&output.trusted_checkpoint_digest),
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
        node.refresh_mining_sync_gate();
        if !node.mining_sync_gate_allows_work() {
            tokio::time::sleep(Duration::from_millis(250)).await;
            continue;
        }
        let work = match node.prepare_work() {
            Ok(work) => work,
            Err(err) => {
                warn!(error = %err, "failed to prepare native mining work");
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
        };
        let start_round = node
            .mining_round
            .fetch_add(MINING_ROUNDS_PER_WORK, Ordering::Relaxed);
        let work_for_task = work.clone();

        let mined = tokio::task::spawn_blocking(move || {
            mine_native_rounds(work_for_task, start_round, MINING_ROUNDS_PER_WORK)
        })
        .await;

        match mined {
            Ok(result) => {
                node.mining_hashes
                    .fetch_add(result.hashes, Ordering::Relaxed);
                let Some(seal) = result.seal else {
                    continue;
                };
                if let Err(err) = node.import_mined_block(&work, seal) {
                    warn!(error = %err, "failed to import native mined block");
                }
            }
            Err(err) => {
                warn!(error = %err, "native mining task failed");
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
}

#[cfg(test)]
fn mine_native_round(work: NativeWork, round: u64) -> Option<NativeSeal> {
    mine_native_rounds(work, round, 1).seal
}

fn mine_native_rounds(work: NativeWork, start_round: u64, rounds: u64) -> NativeMiningRoundResult {
    let rounds = rounds.max(1);
    let mut hashes = 0u64;
    for offset in 0..rounds {
        let round = start_round.saturating_add(offset);
        if let Some(seal) = mine_native_round_inner(&work, round, &mut hashes) {
            return NativeMiningRoundResult {
                seal: Some(seal),
                hashes,
            };
        }
    }
    NativeMiningRoundResult { seal: None, hashes }
}

fn mine_native_round_inner(work: &NativeWork, round: u64, hashes: &mut u64) -> Option<NativeSeal> {
    let start = round.saturating_mul(HASHES_PER_ROUND);
    let end = start.saturating_add(HASHES_PER_ROUND);
    for counter in start..end {
        let nonce = nonce_from_counter(counter);
        let work_hash = native_pow_work_hash(&work.pre_hash, nonce);
        *hashes = (*hashes).saturating_add(1);
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
    flush_native_db_durability_barrier(
        db,
        "native genesis bootstrap",
        NativeStorageDurabilityOperation::GenesisBootstrap,
    )?;
    Ok(genesis)
}

fn load_header_mmr_peaks_for_best(
    block_tree: &sled::Tree,
    best: &NativeBlockMeta,
) -> Result<Vec<Hash32>> {
    let hashes = load_chain_to_hash(block_tree, best.hash)?
        .into_iter()
        .map(|meta| meta.hash)
        .collect::<Vec<_>>();
    if hashes.len() as u64 != header_mmr_leaf_count_after_best(best)? {
        return Err(anyhow!(
            "native header MMR peak state chain length mismatch"
        ));
    }
    Ok(header_mmr_peaks_from_hashes(&hashes))
}

fn header_mmr_leaf_count_after_best(best: &NativeBlockMeta) -> Result<u64> {
    best.height
        .checked_add(1)
        .ok_or_else(|| anyhow!("native header MMR leaf count overflow"))
}

fn append_header_mmr_peak_state(
    state: &NativeState,
    meta: &NativeBlockMeta,
) -> Result<Vec<Hash32>> {
    let leaf_count = header_mmr_leaf_count_after_best(&state.best)?;
    header_mmr_append_peaks(leaf_count, &state.header_mmr_peaks, meta.hash)
        .map_err(|err| anyhow!("native header MMR peak append failed: {err:?}"))
}

fn genesis_meta(pow_bits: u32) -> Result<NativeBlockMeta> {
    let state_root = CommitmentTreeState::default().root();
    let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
    let nullifier_root = nullifier_root_from_set(&BTreeSet::new());
    let timestamp_ms = NATIVE_GENESIS_TIMESTAMP_MS;
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
        flush_native_db_durability_barrier(
            db,
            "native genesis marker repair",
            NativeStorageDurabilityOperation::GenesisMarkerRepair,
        )?;
    }
    for index in 0..chain.len() {
        let parent = if index == 0 {
            None
        } else {
            chain.get(index - 1)
        };
        let meta = &chain[index];
        let expected_pow_bits = if index == 0 {
            None
        } else {
            Some(native_expected_child_pow_bits_for_chain_index(
                &chain,
                index - 1,
                pow_bits,
            )?)
        };
        verify_native_block_meta_projection(parent, meta, expected_pow_bits).with_context(
            || {
                format!(
                    "validate stored canonical native block metadata at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                )
            },
        )?;
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
        flush_native_db_durability_barrier(
            db,
            "native startup staged ciphertext repair",
            NativeStorageDurabilityOperation::StartupStagedCiphertextRepair,
        )?;
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
        flush_native_db_durability_barrier(
            db,
            "native startup staged proof repair",
            NativeStorageDurabilityOperation::StartupStagedProofRepair,
        )?;
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
    header_mmr_peaks: Vec<Hash32>,
    pending_actions: BTreeMap<[u8; 32], PendingAction>,
    commitment_tree: CommitmentTreeState,
    nullifiers: BTreeSet<[u8; 48]>,
    consumed_bridge_messages: BTreeSet<[u8; 48]>,
    staged_ciphertexts: BTreeMap<String, u32>,
    staged_proofs: BTreeMap<String, Vec<u8>>,
    prune_persisted_coinbase_actions: bool,
) -> Result<NativeState> {
    build_validated_startup_state_with_limits(
        db,
        action_tree,
        best,
        header_mmr_peaks,
        pending_actions,
        commitment_tree,
        nullifiers,
        consumed_bridge_messages,
        staged_ciphertexts,
        staged_proofs,
        prune_persisted_coinbase_actions,
        MAX_NATIVE_MEMPOOL_ACTIONS,
        MAX_NATIVE_MEMPOOL_ACTION_BYTES,
    )
}

fn build_validated_startup_state_with_limits(
    db: &sled::Db,
    action_tree: &sled::Tree,
    best: NativeBlockMeta,
    header_mmr_peaks: Vec<Hash32>,
    pending_actions: BTreeMap<[u8; 32], PendingAction>,
    commitment_tree: CommitmentTreeState,
    nullifiers: BTreeSet<[u8; 48]>,
    consumed_bridge_messages: BTreeSet<[u8; 48]>,
    staged_ciphertexts: BTreeMap<String, u32>,
    staged_proofs: BTreeMap<String, Vec<u8>>,
    prune_persisted_coinbase_actions: bool,
    max_pending_actions: usize,
    max_pending_action_bytes: usize,
) -> Result<NativeState> {
    let mut state = NativeState {
        best,
        header_mmr_peaks,
        pending_actions: BTreeMap::new(),
        commitment_tree,
        nullifiers,
        consumed_bridge_messages,
        stablecoin_policy_authorizations: BTreeSet::new(),
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
    let pending_before_transfer_candidate_prune =
        state.pending_actions.keys().copied().collect::<Vec<_>>();
    prune_candidate_artifacts_when_transfers_pending(&mut state, "startup");
    for hash in pending_before_transfer_candidate_prune {
        if !state.pending_actions.contains_key(&hash) {
            dropped_pending.push(hash);
        }
    }
    let pending_before_candidate_prune = state.pending_actions.keys().copied().collect::<Vec<_>>();
    prune_unselected_candidate_artifacts_from_pending(&mut state, "startup");
    for hash in pending_before_candidate_prune {
        if !state.pending_actions.contains_key(&hash) {
            dropped_pending.push(hash);
        }
    }
    if prune_persisted_coinbase_actions {
        let pending_before_coinbase_prune =
            state.pending_actions.keys().copied().collect::<Vec<_>>();
        prune_auto_coinbase_actions_from_pending(&mut state, "startup");
        for hash in pending_before_coinbase_prune {
            if !state.pending_actions.contains_key(&hash) {
                dropped_pending.push(hash);
            }
        }
    }
    if !dropped_pending.is_empty() {
        for hash in dropped_pending {
            action_tree.remove(hash.as_slice()).with_context(|| {
                format!("remove invalid persisted pending action {}", hex32(&hash))
            })?;
        }
        flush_native_db_durability_barrier(
            db,
            "native startup pending action repair",
            NativeStorageDurabilityOperation::StartupPendingActionRepair,
        )?;
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
            if action.family_id == FAMILY_BRIDGE && action.action_id == ACTION_BRIDGE_INBOUND {
                let mut replay_state = inbound_replay_state_for_mempool(state)?;
                validate_bridge_action_payload_with_replay_state(action, Some(&replay_state))?;
                if let Some(replay_key) = bridge_inbound_replay_key_from_action(action)? {
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
            } else {
                validate_bridge_action_payload(action)?;
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
                } else if !input.stablecoin_policy_authorized {
                    Err(NativeTransferStateAdmissionRejection::StablecoinPolicyUnauthorized)
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
        (_, NativeTransferStateAdmissionRejection::StablecoinPolicyUnauthorized) => {
            anyhow!("stablecoin policy unauthorized")
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
        return Err(NativeActionWireReplayProjectionAdmissionRejection::PlanLength);
    }

    let mut projected_ciphertext_row_count = 0usize;
    let mut projected_bridge_replay_row_count = 0usize;
    for step in steps {
        if step.ciphertext_hash_count != step.ciphertext_size_count
            || step.ciphertext_hash_count != step.planned_ciphertext_count
        {
            return Err(NativeActionWireReplayProjectionAdmissionRejection::CiphertextCount);
        }
        if !step.ciphertext_hashes_match {
            return Err(NativeActionWireReplayProjectionAdmissionRejection::CiphertextHash);
        }
        if !step.ciphertext_sizes_match {
            return Err(NativeActionWireReplayProjectionAdmissionRejection::CiphertextSize);
        }
        if !step.replay_key_matches {
            return Err(NativeActionWireReplayProjectionAdmissionRejection::ReplayKey);
        }
        projected_ciphertext_row_count = projected_ciphertext_row_count
            .checked_add(step.planned_ciphertext_count)
            .ok_or(NativeActionWireReplayProjectionAdmissionRejection::CiphertextCount)?;
        if step.planned_replay_present {
            projected_bridge_replay_row_count = projected_bridge_replay_row_count
                .checked_add(1)
                .ok_or(NativeActionWireReplayProjectionAdmissionRejection::ReplayKey)?;
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
            NativeActionWireReplayProjectionAdmissionRejection::PlanLength,
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
    mempool_transfer_nullifier_admission_state_from_nullifiers(
        &mut nullifier_state,
        &action.nullifiers,
    )
}

fn mempool_transfer_nullifier_admission_state_from_nullifiers(
    nullifier_state: &mut NullifierState,
    nullifiers: &[[u8; 48]],
) -> NativeTransferNullifierAdmissionState {
    let mut action_seen = BTreeSet::new();
    for nullifier in nullifiers {
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
    block_transfer_nullifier_admission_state_from_nullifiers(nullifier_state, &action.nullifiers)
}

fn block_transfer_nullifier_admission_state_from_nullifiers(
    nullifier_state: &mut NullifierState,
    nullifiers: &[[u8; 48]],
) -> NativeTransferNullifierAdmissionState {
    for nullifier in nullifiers {
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

#[cfg(test)]
fn stablecoin_policy_authorization_key(binding: &StablecoinPolicyBinding) -> Vec<u8> {
    binding.encode()
}

fn evaluate_native_stablecoin_policy_authorization(
    input: NativeStablecoinPolicyAuthorizationInput,
) -> Result<(), NativeStablecoinPolicyAuthorizationRejection> {
    if !input.stablecoin_present {
        Ok(())
    } else if !input.policy_known {
        Err(NativeStablecoinPolicyAuthorizationRejection::PolicyMissing)
    } else if !input.policy_active {
        Err(NativeStablecoinPolicyAuthorizationRejection::PolicyInactive)
    } else if !input.policy_lifecycle_open {
        Err(NativeStablecoinPolicyAuthorizationRejection::PolicyNotLive)
    } else if !input.asset_matches {
        Err(NativeStablecoinPolicyAuthorizationRejection::AssetMismatch)
    } else if !input.policy_hash_matches {
        Err(NativeStablecoinPolicyAuthorizationRejection::PolicyHashMismatch)
    } else if !input.policy_version_matches {
        Err(NativeStablecoinPolicyAuthorizationRejection::PolicyVersionMismatch)
    } else if !input.oracle_commitment_matches {
        Err(NativeStablecoinPolicyAuthorizationRejection::OracleCommitmentMismatch)
    } else if !input.attestation_commitment_matches {
        Err(NativeStablecoinPolicyAuthorizationRejection::AttestationCommitmentMismatch)
    } else if !input.attestation_not_disputed {
        Err(NativeStablecoinPolicyAuthorizationRejection::AttestationDisputed)
    } else if !input.oracle_fresh {
        Err(NativeStablecoinPolicyAuthorizationRejection::OracleStale)
    } else if !input.issuance_nonzero {
        Err(NativeStablecoinPolicyAuthorizationRejection::IssuanceZero)
    } else if !input.issuance_within_limit {
        Err(NativeStablecoinPolicyAuthorizationRejection::IssuanceOverLimit)
    } else {
        Ok(())
    }
}

fn native_stablecoin_policy_authorization_input_for_entry(
    current_height: u64,
    binding: &StablecoinPolicyBinding,
    entry: Option<&StablecoinPolicyManifestEntry>,
) -> NativeStablecoinPolicyAuthorizationInput {
    let Some(entry) = entry else {
        return NativeStablecoinPolicyAuthorizationInput {
            stablecoin_present: true,
            policy_known: false,
            policy_active: false,
            policy_lifecycle_open: false,
            asset_matches: false,
            policy_hash_matches: false,
            policy_version_matches: false,
            oracle_commitment_matches: false,
            attestation_commitment_matches: false,
            attestation_not_disputed: false,
            oracle_fresh: false,
            issuance_nonzero: false,
            issuance_within_limit: false,
        };
    };
    let oracle_fresh = entry.oracle_submitted_at <= current_height
        && current_height.saturating_sub(entry.oracle_submitted_at) <= entry.oracle_max_age;
    let policy_lifecycle_open = current_height >= entry.enabled_at
        && match entry.retired_at {
            Some(retired_at) => current_height < retired_at,
            None => true,
        };
    let issuance_abs = binding.issuance_delta.unsigned_abs();
    NativeStablecoinPolicyAuthorizationInput {
        stablecoin_present: true,
        policy_known: true,
        policy_active: entry.active,
        policy_lifecycle_open,
        asset_matches: u64::from(entry.asset_id) == binding.asset_id,
        policy_hash_matches: entry.policy_hash() == binding.policy_hash,
        policy_version_matches: entry.policy_version == binding.policy_version,
        oracle_commitment_matches: entry.oracle_commitment == binding.oracle_commitment,
        attestation_commitment_matches: entry.attestation_commitment
            == binding.attestation_commitment,
        attestation_not_disputed: !entry.attestation_disputed,
        oracle_fresh,
        issuance_nonzero: binding.issuance_delta != 0,
        issuance_within_limit: issuance_abs <= entry.max_mint_per_epoch
            && issuance_abs <= u64::MAX as u128,
    }
}

fn native_stablecoin_policy_binding_authorized_by_entries(
    current_height: u64,
    binding: &StablecoinPolicyBinding,
    entries: &[StablecoinPolicyManifestEntry],
) -> bool {
    entries.iter().any(|entry| {
        let plausible_candidate = u64::from(entry.asset_id) == binding.asset_id
            || entry.policy_hash() == binding.policy_hash;
        plausible_candidate
            && evaluate_native_stablecoin_policy_authorization(
                native_stablecoin_policy_authorization_input_for_entry(
                    current_height,
                    binding,
                    Some(entry),
                ),
            )
            .is_ok()
    })
}

fn native_stablecoin_policy_binding_authorized_by_protocol_manifest(
    current_height: u64,
    binding: &StablecoinPolicyBinding,
) -> bool {
    let manifest = protocol_manifest();
    native_stablecoin_policy_binding_authorized_by_entries(
        current_height,
        binding,
        &manifest.stablecoin_policies,
    )
}

fn native_transfer_stablecoin_policy_authorized(
    state: &NativeState,
    action: &PendingAction,
) -> bool {
    match transfer_action_stablecoin_binding(action) {
        Ok(None) => true,
        Ok(Some(binding)) => {
            let manifest_authorized =
                native_stablecoin_policy_binding_authorized_by_protocol_manifest(
                    state.best.height,
                    &binding,
                );
            #[cfg(test)]
            {
                manifest_authorized
                    || state
                        .stablecoin_policy_authorizations
                        .contains(&stablecoin_policy_authorization_key(&binding))
            }
            #[cfg(not(test))]
            {
                manifest_authorized
            }
        }
        Err(_) => false,
    }
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
        stablecoin_policy_authorized: native_transfer_stablecoin_policy_authorized(state, action),
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
        stablecoin_policy_authorized: native_transfer_stablecoin_policy_authorized(state, action),
        sidecar_route: false,
        sidecar_ciphertexts_available: true,
        sidecar_ciphertext_sizes_present: true,
        sidecar_ciphertext_sizes_match: true,
    }
}

fn inline_transfer_ciphertext_resource_input(
    route_payload_bytes: usize,
    proof_bytes: usize,
    ciphertexts: &[protocol_shielded_pool::types::EncryptedNote],
) -> NativeInlineTransferCiphertextResourceInput {
    let mut max_ciphertext_bytes_observed = 0usize;
    let mut aggregate_ciphertext_bytes = 0usize;
    for note in ciphertexts {
        let ciphertext_bytes = note
            .ciphertext
            .len()
            .saturating_add(note.kem_ciphertext.len());
        max_ciphertext_bytes_observed = max_ciphertext_bytes_observed.max(ciphertext_bytes);
        aggregate_ciphertext_bytes = aggregate_ciphertext_bytes.saturating_add(ciphertext_bytes);
    }
    let output_count_cap = transaction_core::constants::MAX_OUTPUTS;
    NativeInlineTransferCiphertextResourceInput {
        raw_byte_cap: MAX_NATIVE_RPC_ACTION_BYTES,
        decoded_byte_cap: MAX_NATIVE_RPC_ACTION_BYTES,
        item_count_cap: output_count_cap,
        item_byte_cap: MAX_CIPHERTEXT_BYTES,
        aggregate_byte_cap: output_count_cap.saturating_mul(MAX_CIPHERTEXT_BYTES),
        work_unit_cap: output_count_cap,
        route_payload_bytes,
        proof_bytes,
        ciphertext_count: ciphertexts.len(),
        max_ciphertext_bytes_observed,
        aggregate_ciphertext_bytes,
    }
}

fn inline_transfer_ciphertext_resource_bounded_request(
    input: NativeInlineTransferCiphertextResourceInput,
) -> NativeBoundedRequestAdmissionInput {
    NativeBoundedRequestAdmissionInput {
        raw_byte_cap: input.raw_byte_cap,
        decoded_byte_cap: input.decoded_byte_cap,
        item_count_cap: input.item_count_cap,
        item_byte_cap: input.item_byte_cap,
        aggregate_byte_cap: input.aggregate_byte_cap,
        work_unit_cap: input.work_unit_cap,
        raw_bytes: input.route_payload_bytes,
        decoded_bytes: input
            .proof_bytes
            .saturating_add(input.aggregate_ciphertext_bytes),
        item_count: input.ciphertext_count,
        max_item_bytes: input.max_ciphertext_bytes_observed,
        aggregate_bytes: input.aggregate_ciphertext_bytes,
        work_units: input.ciphertext_count,
    }
}

fn validate_inline_transfer_ciphertext_resource(
    input: NativeInlineTransferCiphertextResourceInput,
) -> Result<NativeBoundedRequestAdmissionInput> {
    let bounded = inline_transfer_ciphertext_resource_bounded_request(input);
    evaluate_native_bounded_request_admission(bounded)
        .map(|_| bounded)
        .map_err(|rejection| {
            inline_transfer_ciphertext_resource_admission_error(bounded, rejection)
        })
}

fn inline_transfer_ciphertext_resource_admission_error(
    input: NativeBoundedRequestAdmissionInput,
    rejection: NativeBoundedRequestAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeBoundedRequestAdmissionRejection::RawBytes => anyhow!(
            "inline transfer route payload bytes {} exceeds cap {}",
            input.raw_bytes,
            input.raw_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::DecodedBytes => anyhow!(
            "inline transfer decoded proof+ciphertext bytes {} exceeds cap {}",
            input.decoded_bytes,
            input.decoded_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::ItemCount => anyhow!(
            "inline ciphertext count {} exceeds limit {}",
            input.item_count,
            input.item_count_cap
        ),
        NativeBoundedRequestAdmissionRejection::ItemBytes => anyhow!(
            "inline ciphertext size {} exceeds limit {}",
            input.max_item_bytes,
            input.item_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::AggregateBytes => anyhow!(
            "inline ciphertext aggregate bytes {} exceeds cap {}",
            input.aggregate_bytes,
            input.aggregate_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::WorkUnits => anyhow!(
            "inline ciphertext work units {} exceeds cap {}",
            input.work_units,
            input.work_unit_cap
        ),
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

fn admitted_inline_ciphertext_metadata(
    route_payload_bytes: usize,
    proof_bytes: usize,
    ciphertexts: &[protocol_shielded_pool::types::EncryptedNote],
) -> Result<(usize, Vec<[u8; 48]>, Vec<u32>)> {
    let input =
        inline_transfer_ciphertext_resource_input(route_payload_bytes, proof_bytes, ciphertexts);
    validate_inline_transfer_ciphertext_resource(input)?;
    let (max_inline_ciphertext_bytes, metadata) = inline_ciphertext_metadata(ciphertexts);
    let (ciphertext_hashes, ciphertext_sizes) = metadata.ok_or_else(|| {
        inline_transfer_ciphertext_resource_admission_error(
            inline_transfer_ciphertext_resource_bounded_request(input),
            NativeBoundedRequestAdmissionRejection::ItemBytes,
        )
    })?;
    Ok((
        max_inline_ciphertext_bytes,
        ciphertext_hashes,
        ciphertext_sizes,
    ))
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
            let (inline_ciphertext_bytes, ciphertext_hashes, ciphertext_sizes) =
                admitted_inline_ciphertext_metadata(
                    action.public_args.len(),
                    args.proof.len(),
                    &args.ciphertexts,
                )?;
            let input = NativeTransferPayloadAdmissionInput {
                proof_bytes: args.proof.len(),
                max_proof_bytes: NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
                anchor_matches: args.anchor == action.anchor,
                commitments_match: args.commitments == action.commitments,
                inline_ciphertext_bytes,
                max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES,
                ciphertext_hashes_match: ciphertext_hashes == action.ciphertext_hashes,
                ciphertext_sizes_match: ciphertext_sizes == action.ciphertext_sizes,
                binding_hash_matches: binding_hash_matches(
                    args.anchor,
                    &action.nullifiers,
                    &args.commitments,
                    &ciphertext_hashes,
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
    let input = native_candidate_artifact_admission_input(true, true, true, Some(artifact));
    evaluate_native_candidate_artifact_admission(input)
        .map_err(|rejection| native_candidate_artifact_admission_error(input, rejection))?;
    validate_candidate_artifact_resource_projection(artifact)
}

fn validate_candidate_action_payload(action: &PendingAction) -> Result<()> {
    if !is_candidate_artifact_action(action) {
        return Err(anyhow!("not a candidate artifact action"));
    }
    let route_payload = decode_scale_exact::<SubmitCandidateArtifactArgs>(
        &action.public_args,
        "candidate artifact action args",
    );
    let route_payload_decodes_exactly = route_payload.is_ok();
    let route_payload_matches_artifact = match (
        route_payload.as_ref().ok(),
        action.candidate_artifact.as_ref(),
    ) {
        (Some(args), Some(artifact)) => &args.payload == artifact,
        _ => true,
    };
    let input = native_candidate_artifact_admission_input(
        candidate_action_has_no_state_deltas(action),
        route_payload_decodes_exactly,
        route_payload_matches_artifact,
        action.candidate_artifact.as_ref(),
    );
    evaluate_native_candidate_artifact_admission(input)
        .map_err(|rejection| native_candidate_artifact_admission_error(input, rejection))?;
    validate_candidate_artifact_resource_projection(
        action
            .candidate_artifact
            .as_ref()
            .expect("candidate artifact was accepted as present"),
    )
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
    route_payload_decodes_exactly: bool,
    route_payload_matches_artifact: bool,
    artifact: Option<&CandidateArtifact>,
) -> NativeCandidateArtifactAdmissionInput {
    let Some(artifact) = artifact else {
        return NativeCandidateArtifactAdmissionInput {
            state_deltas_absent,
            route_payload_decodes_exactly,
            route_payload_matches_artifact,
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
        route_payload_decodes_exactly,
        route_payload_matches_artifact,
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

fn native_candidate_artifact_resource_projection_input(
    artifact: &CandidateArtifact,
) -> NativeCandidateArtifactResourceProjectionInput {
    let proof_bytes = artifact.commitment_proof.data.len();
    let receipt_bytes = artifact
        .receipt_root
        .as_ref()
        .map_or(0, |receipt| receipt.encoded_size());
    let recursive_bytes = artifact
        .recursive_block
        .as_ref()
        .map_or(0, |recursive| recursive.proof.data.len());
    let variable_bytes = proof_bytes
        .saturating_add(receipt_bytes)
        .saturating_add(recursive_bytes);
    let declared_bytes = artifact.encoded_size().saturating_sub(variable_bytes);
    NativeCandidateArtifactResourceProjectionInput {
        raw_byte_cap: MAX_NATIVE_RPC_ACTION_BYTES,
        decoded_byte_cap: MAX_NATIVE_RPC_ACTION_BYTES,
        item_count_cap: MAX_BATCH_SIZE as usize,
        item_byte_cap: RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE,
        aggregate_byte_cap: RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE,
        work_unit_cap: usize::MAX,
        declared_bytes,
        proof_bytes,
        receipt_bytes,
        recursive_bytes,
        tx_count: artifact.tx_count as usize,
        da_chunk_count: artifact.da_chunk_count as usize,
    }
}

fn native_candidate_artifact_resource_bounded_request(
    input: NativeCandidateArtifactResourceProjectionInput,
) -> NativeBoundedRequestAdmissionInput {
    let aggregate_bytes = input
        .proof_bytes
        .saturating_add(input.receipt_bytes)
        .saturating_add(input.recursive_bytes);
    NativeBoundedRequestAdmissionInput {
        raw_byte_cap: input.raw_byte_cap,
        decoded_byte_cap: input.decoded_byte_cap,
        item_count_cap: input.item_count_cap,
        item_byte_cap: input.item_byte_cap,
        aggregate_byte_cap: input.aggregate_byte_cap,
        work_unit_cap: input.work_unit_cap,
        raw_bytes: input.declared_bytes,
        decoded_bytes: input.declared_bytes.saturating_add(aggregate_bytes),
        item_count: input.tx_count,
        max_item_bytes: input
            .proof_bytes
            .max(input.receipt_bytes)
            .max(input.recursive_bytes),
        aggregate_bytes,
        work_units: input.da_chunk_count,
    }
}

fn validate_candidate_artifact_resource_projection(artifact: &CandidateArtifact) -> Result<()> {
    let input = native_candidate_artifact_resource_projection_input(artifact);
    let bounded = native_candidate_artifact_resource_bounded_request(input);
    evaluate_native_bounded_request_admission(bounded)
        .map_err(|rejection| native_candidate_artifact_resource_admission_error(bounded, rejection))
}

fn evaluate_native_candidate_artifact_admission(
    input: NativeCandidateArtifactAdmissionInput,
) -> Result<(), NativeCandidateArtifactAdmissionRejection> {
    if !input.state_deltas_absent {
        Err(NativeCandidateArtifactAdmissionRejection::StateDeltasPresent)
    } else if !input.route_payload_decodes_exactly {
        Err(NativeCandidateArtifactAdmissionRejection::RoutePayloadDecodeFailed)
    } else if !input.route_payload_matches_artifact {
        Err(NativeCandidateArtifactAdmissionRejection::RoutePayloadArtifactMismatch)
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

fn native_candidate_artifact_resource_admission_error(
    input: NativeBoundedRequestAdmissionInput,
    rejection: NativeBoundedRequestAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeBoundedRequestAdmissionRejection::RawBytes => anyhow!(
            "candidate artifact declared byte count {} exceeds cap {}",
            input.raw_bytes,
            input.raw_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::DecodedBytes => anyhow!(
            "candidate artifact decoded byte count {} exceeds cap {}",
            input.decoded_bytes,
            input.decoded_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::ItemCount => anyhow!(
            "candidate artifact tx_count {} exceeds bounded request cap {}",
            input.item_count,
            input.item_count_cap
        ),
        NativeBoundedRequestAdmissionRejection::ItemBytes => anyhow!(
            "candidate artifact proof-like item byte count {} exceeds cap {}",
            input.max_item_bytes,
            input.item_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::AggregateBytes => anyhow!(
            "candidate artifact aggregate proof-like byte count {} exceeds cap {}",
            input.aggregate_bytes,
            input.aggregate_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::WorkUnits => anyhow!(
            "candidate artifact DA chunk count {} exceeds bounded request work cap {}",
            input.work_units,
            input.work_unit_cap
        ),
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
        NativeCandidateArtifactAdmissionRejection::RoutePayloadDecodeFailed => {
            anyhow!("candidate artifact action args must decode exactly")
        }
        NativeCandidateArtifactAdmissionRejection::RoutePayloadArtifactMismatch => {
            anyhow!("candidate artifact action args do not match candidate artifact payload")
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

fn evaluate_native_bounded_request_admission(
    input: NativeBoundedRequestAdmissionInput,
) -> Result<(), NativeBoundedRequestAdmissionRejection> {
    if input.raw_bytes > input.raw_byte_cap {
        Err(NativeBoundedRequestAdmissionRejection::RawBytes)
    } else if input.decoded_bytes > input.decoded_byte_cap {
        Err(NativeBoundedRequestAdmissionRejection::DecodedBytes)
    } else if input.item_count > input.item_count_cap {
        Err(NativeBoundedRequestAdmissionRejection::ItemCount)
    } else if input.max_item_bytes > input.item_byte_cap {
        Err(NativeBoundedRequestAdmissionRejection::ItemBytes)
    } else if input.aggregate_bytes > input.aggregate_byte_cap {
        Err(NativeBoundedRequestAdmissionRejection::AggregateBytes)
    } else if input.work_units > input.work_unit_cap {
        Err(NativeBoundedRequestAdmissionRejection::WorkUnits)
    } else {
        Ok(())
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

fn evaluate_native_sync_request_rate_admission(
    input: NativeSyncRequestRateAdmissionInput,
) -> Result<(), NativeSyncAdmissionRejection> {
    if input.max_requests == 0 {
        return Err(NativeSyncAdmissionRejection::RequestRateLimited);
    }
    if input.window_elapsed_ms >= input.window_ms {
        return Ok(());
    }
    if input.requests_in_window < input.max_requests {
        Ok(())
    } else {
        Err(NativeSyncAdmissionRejection::RequestRateLimited)
    }
}

fn native_sync_missing_request_range(
    input: NativeSyncMissingRequestInput,
) -> Option<NativeSyncRange> {
    if input.max_blocks == 0 || input.announced_height <= input.best_height {
        return None;
    }
    let from_height = if input.best_height > 0 && input.best_height < input.max_blocks {
        NATIVE_SYNC_BOOTSTRAP_BACKFILL_FLOOR
    } else {
        input.best_height.saturating_add(1)
    };
    let cap_end = input
        .max_blocks
        .saturating_sub(1)
        .saturating_add(from_height)
        .max(from_height);
    Some(NativeSyncRange {
        from_height,
        to_height: input.announced_height.min(cap_end),
    })
}

#[cfg(test)]
fn native_sync_missing_request_range_with_reorg_backfill(
    input: NativeSyncMissingRequestInput,
    backfill_blocks: u64,
) -> Option<NativeSyncRange> {
    let range = native_sync_missing_request_range(input)?;
    Some(native_sync_missing_request_range_apply_reorg_backfill(
        input,
        range,
        backfill_blocks,
    ))
}

fn native_sync_observed_tip_request_range(
    best_height: u64,
    best_hash: [u8; 32],
    announced_height: u64,
    announced_hash: Option<[u8; 32]>,
    max_blocks: u64,
    backfill_blocks: u64,
) -> Option<NativeSyncRange> {
    let input = NativeSyncMissingRequestInput {
        best_height,
        announced_height,
        max_blocks,
    };
    let admitted_missing_range = native_sync_missing_request_range(input);
    native_sync_observed_tip_request_range_from_admitted_missing(
        input,
        best_hash,
        announced_hash,
        backfill_blocks,
        admitted_missing_range,
    )
}

fn native_sync_observed_tip_request_range_from_admitted_missing(
    input: NativeSyncMissingRequestInput,
    best_hash: [u8; 32],
    announced_hash: Option<[u8; 32]>,
    backfill_blocks: u64,
    admitted_missing_range: Option<NativeSyncRange>,
) -> Option<NativeSyncRange> {
    if let Some(admitted_range) = admitted_missing_range {
        let gap = input.announced_height.saturating_sub(input.best_height);
        if gap > input.max_blocks && backfill_blocks <= NATIVE_SYNC_REORG_BACKFILL_BLOCKS {
            return Some(admitted_range);
        }
        return Some(native_sync_missing_request_range_apply_reorg_backfill(
            input,
            admitted_range,
            backfill_blocks,
        ));
    }

    if input.announced_height == 0
        || input.announced_height != input.best_height
        || announced_hash.is_none_or(|hash| hash == best_hash)
        || input.max_blocks == 0
    {
        return None;
    }

    let from_height = input
        .announced_height
        .saturating_sub(backfill_blocks)
        .saturating_add(1);
    Some(NativeSyncRange {
        from_height,
        to_height: input
            .announced_height
            .min(from_height.saturating_add(input.max_blocks - 1)),
    })
}

fn native_sync_missing_request_range_apply_reorg_backfill(
    input: NativeSyncMissingRequestInput,
    range: NativeSyncRange,
    backfill_blocks: u64,
) -> NativeSyncRange {
    let gap = input.announced_height.saturating_sub(input.best_height);
    if gap == 0 || backfill_blocks == 0 || input.max_blocks <= backfill_blocks {
        return range;
    }

    let from_height = input
        .best_height
        .saturating_sub(backfill_blocks)
        .saturating_add(1)
        .min(range.from_height);
    let to_height = input
        .announced_height
        .min(from_height.saturating_add(input.max_blocks - 1));
    NativeSyncRange {
        from_height,
        to_height,
    }
}

fn native_sync_block_range_publication_rows(blocks: Vec<NativeBlockMeta>) -> Vec<NativeBlockMeta> {
    blocks
}

fn evaluate_native_sync_block_range_publication_admission(
    input: NativeSyncBlockRangePublicationAdmissionInput,
) -> Result<(), NativeSyncBlockRangePublicationAdmissionRejection> {
    if !input.range_admitted {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::RangeNotAdmitted)
    } else if !input.served_count_matches_range {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::ServedCountMismatch)
    } else if !input.first_height_matches_range {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::FirstHeightMismatch)
    } else if !input.last_height_matches_range {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::LastHeightMismatch)
    } else if !input.served_heights_contiguous {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::HeightContinuityMismatch)
    } else if !input.previous_parent_anchor_verified || !input.parent_hashes_contiguous {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::ParentHashMismatch)
    } else if !input.canonical_rows_verified {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::CanonicalRowsUnverified)
    } else if !input.action_bodies_verified {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::ActionBodiesUnverified)
    } else {
        Ok(())
    }
}

fn native_sync_block_range_publication_admission_input(
    range: NativeSyncRange,
    blocks: &[NativeBlockMeta],
    canonical_rows_verified: usize,
    action_bodies_verified: usize,
    previous_parent_anchor_verified: bool,
) -> NativeSyncBlockRangePublicationAdmissionInput {
    let expected_count = range
        .to_height
        .checked_sub(range.from_height)
        .and_then(|delta| delta.checked_add(1))
        .and_then(|count| usize::try_from(count).ok());
    let served_count_matches_range = expected_count == Some(blocks.len());
    let first_height_matches_range = blocks
        .first()
        .map(|meta| meta.height == range.from_height)
        .unwrap_or(false);
    let last_height_matches_range = blocks
        .last()
        .map(|meta| meta.height == range.to_height)
        .unwrap_or(false);
    let served_heights_contiguous = blocks.windows(2).all(|window| {
        window[0]
            .height
            .checked_add(1)
            .map(|expected| window[1].height == expected)
            .unwrap_or(false)
    });
    let parent_hashes_contiguous = blocks
        .windows(2)
        .all(|window| window[1].parent_hash == window[0].hash);
    let expected_action_body_rows = blocks.iter().filter(|meta| meta.height != 0).count();

    NativeSyncBlockRangePublicationAdmissionInput {
        range_admitted: true,
        served_count_matches_range,
        first_height_matches_range,
        last_height_matches_range,
        served_heights_contiguous,
        previous_parent_anchor_verified,
        parent_hashes_contiguous,
        canonical_rows_verified: canonical_rows_verified == blocks.len(),
        action_bodies_verified: action_bodies_verified == expected_action_body_rows,
    }
}

fn evaluate_native_sync_response_count_admission(
    input: NativeSyncResponseCountAdmissionInput,
) -> Result<(), NativeSyncAdmissionRejection> {
    let bounded = native_sync_response_count_bounded_request(input);
    evaluate_native_bounded_request_admission(bounded)
        .map_err(|_| NativeSyncAdmissionRejection::ResponseBlockCountTooLarge)
}

fn native_sync_response_count_bounded_request(
    input: NativeSyncResponseCountAdmissionInput,
) -> NativeBoundedRequestAdmissionInput {
    NativeBoundedRequestAdmissionInput {
        raw_byte_cap: usize::MAX,
        decoded_byte_cap: usize::MAX,
        item_count_cap: input.max_blocks,
        item_byte_cap: usize::MAX,
        aggregate_byte_cap: usize::MAX,
        work_unit_cap: usize::MAX,
        raw_bytes: 0,
        decoded_bytes: 0,
        item_count: input.block_count,
        max_item_bytes: 0,
        aggregate_bytes: 0,
        work_units: 0,
    }
}

fn admit_and_sort_native_sync_response_blocks(
    blocks: &mut [NativeBlockMeta],
    max_blocks: usize,
) -> Result<(), NativeSyncAdmissionRejection> {
    evaluate_native_sync_response_count_admission(NativeSyncResponseCountAdmissionInput {
        block_count: blocks.len(),
        max_blocks,
    })?;
    blocks.sort_by_key(|meta| meta.height);
    Ok(())
}

#[cfg(test)]
fn native_sync_response_import_progress<I>(
    response_block_count: usize,
    outcomes: I,
) -> NativeSyncResponseImportProgress
where
    I: IntoIterator<Item = NativeSyncResponseImportOutcome>,
{
    let mut progress = NativeSyncResponseImportProgress::new(response_block_count);
    for outcome in outcomes {
        if !progress.record(outcome) {
            break;
        }
    }
    progress
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
        .filter(|action| !is_coinbase_action(action) && !is_candidate_artifact_action(action))
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

fn wallet_commitment_source_label(action: &PendingAction) -> &'static str {
    if is_coinbase_action(action) {
        "mining_reward"
    } else if is_shielded_transfer_action(action) {
        "transfer"
    } else {
        "unknown"
    }
}

fn is_candidate_artifact_action(action: &PendingAction) -> bool {
    action.family_id == FAMILY_SHIELDED_POOL && action.action_id == ACTION_SUBMIT_CANDIDATE_ARTIFACT
}

fn pending_action_peer_relayable(action: &PendingAction) -> bool {
    !is_coinbase_action(action) && !is_candidate_artifact_action(action)
}

fn stage_relayed_pending_action(
    node: &NativeNode,
    pending: PendingAction,
) -> Result<Option<PendingAction>> {
    node.stage_relayed_pending_action(pending)
}

fn action_order_key_preimage(action: &PendingAction) -> Vec<u8> {
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
            return non_transfer_action_order_key_preimage(
                action.family_id,
                action.action_id,
                pending_action_semantic_hash(action),
                &action.nullifiers,
            );
        }
    }
    for nullifier in &action.nullifiers {
        preimage.extend_from_slice(nullifier);
    }
    if preimage.is_empty() {
        preimage.extend_from_slice(&action.tx_hash);
    }
    preimage
}

fn non_transfer_action_order_key_preimage(
    family_id: u16,
    action_id: u16,
    semantic_hash: [u8; 32],
    nullifiers: &[[u8; 48]],
) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(12 + 2 + 2 + 32 + 48 * nullifiers.len());
    preimage.extend_from_slice(b"non-transfer");
    preimage.extend_from_slice(&family_id.to_le_bytes());
    preimage.extend_from_slice(&action_id.to_le_bytes());
    preimage.extend_from_slice(&semantic_hash);
    for nullifier in nullifiers {
        preimage.extend_from_slice(nullifier);
    }
    preimage
}

fn action_order_key(action: &PendingAction) -> [u8; 32] {
    let preimage = action_order_key_preimage(action);
    crypto::hashes::blake2_256(&preimage)
}

fn transfer_key_extends_canonical_order(
    previous_transfer_key: Option<&[u8; 32]>,
    transfer_key: &[u8; 32],
) -> bool {
    previous_transfer_key.is_none_or(|previous| transfer_key >= previous)
}

fn validate_bridge_action_payload(action: &PendingAction) -> Result<()> {
    validate_bridge_action_payload_with_replay_state(action, None)
}

fn validate_bridge_action_payload_with_replay_state(
    action: &PendingAction,
    replay_state: Option<&InboundReplayState>,
) -> Result<()> {
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
            validate_bridge_action_resource_projection(
                native_bridge_action_resource_projection_input(
                    action_kind,
                    action.public_args.len(),
                    args.payload.len(),
                    0,
                    0,
                ),
            )?;
            Ok(())
        }
        NativeBridgeActionPayloadKind::Inbound => {
            let args: InboundBridgeArgsV1 =
                decode_scale_exact(&action.public_args, "inbound bridge action args")?;
            validate_bridge_action_resource_projection(
                native_bridge_action_resource_projection_input(
                    action_kind,
                    action.public_args.len(),
                    0,
                    args.proof_receipt.len(),
                    args.message.payload.len(),
                ),
            )?;
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
            verify_inbound_bridge_receipt(action, &args, replay_state.cloned())?;
            Ok(())
        }
        NativeBridgeActionPayloadKind::Register => {
            let registration: BridgeVerifierRegistrationV1 =
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
            let registration_effect = evaluate_native_bridge_verifier_registration_policy(
                native_bridge_verifier_registration_policy_input(action, Some(&registration)),
            )
            .map_err(native_bridge_verifier_registration_policy_error)?;
            debug_assert!(!registration_effect.production_mint_verifier_enabled);
            validate_bridge_action_resource_projection(
                native_bridge_action_resource_projection_input(
                    action_kind,
                    action.public_args.len(),
                    0,
                    0,
                    0,
                ),
            )?;
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

fn native_bridge_action_resource_projection_input(
    action_kind: NativeBridgeActionPayloadKind,
    public_args_bytes: usize,
    outbound_payload_bytes: usize,
    inbound_proof_receipt_bytes: usize,
    inbound_message_payload_bytes: usize,
) -> NativeBridgeActionResourceAdmissionInput {
    NativeBridgeActionResourceAdmissionInput {
        raw_byte_cap: MAX_NATIVE_RPC_ACTION_BYTES,
        decoded_byte_cap: MAX_NATIVE_RPC_ACTION_BYTES,
        item_count_cap: 2,
        item_byte_cap: MAX_NATIVE_BRIDGE_PROOF_RECEIPT_BYTES,
        aggregate_byte_cap: MAX_NATIVE_BRIDGE_ACTION_DYNAMIC_BYTES,
        work_unit_cap: MAX_NATIVE_BRIDGE_MESSAGE_PAYLOAD_BYTES,
        action_kind,
        public_args_bytes,
        outbound_payload_bytes,
        inbound_proof_receipt_bytes,
        inbound_message_payload_bytes,
    }
}

fn native_bridge_action_resource_item_count(
    input: NativeBridgeActionResourceAdmissionInput,
) -> usize {
    match input.action_kind {
        NativeBridgeActionPayloadKind::Outbound => 1,
        NativeBridgeActionPayloadKind::Inbound => 2,
        NativeBridgeActionPayloadKind::Register | NativeBridgeActionPayloadKind::Unsupported => 0,
    }
}

fn bridge_action_resource_bounded_request(
    input: NativeBridgeActionResourceAdmissionInput,
) -> NativeBoundedRequestAdmissionInput {
    let aggregate_bytes = input
        .outbound_payload_bytes
        .saturating_add(input.inbound_proof_receipt_bytes)
        .saturating_add(input.inbound_message_payload_bytes);
    NativeBoundedRequestAdmissionInput {
        raw_byte_cap: input.raw_byte_cap,
        decoded_byte_cap: input.decoded_byte_cap,
        item_count_cap: input.item_count_cap,
        item_byte_cap: input.item_byte_cap,
        aggregate_byte_cap: input.aggregate_byte_cap,
        work_unit_cap: input.work_unit_cap,
        raw_bytes: input.public_args_bytes,
        decoded_bytes: input.public_args_bytes,
        item_count: native_bridge_action_resource_item_count(input),
        max_item_bytes: input
            .outbound_payload_bytes
            .max(input.inbound_proof_receipt_bytes)
            .max(input.inbound_message_payload_bytes),
        aggregate_bytes,
        work_units: input
            .outbound_payload_bytes
            .max(input.inbound_message_payload_bytes),
    }
}

fn validate_bridge_action_resource_projection(
    input: NativeBridgeActionResourceAdmissionInput,
) -> Result<NativeBoundedRequestAdmissionInput> {
    let bounded = bridge_action_resource_bounded_request(input);
    evaluate_native_bounded_request_admission(bounded)
        .map(|_| bounded)
        .map_err(|rejection| bridge_action_resource_admission_error(bounded, rejection))
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

fn bridge_action_resource_admission_error(
    input: NativeBoundedRequestAdmissionInput,
    rejection: NativeBoundedRequestAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeBoundedRequestAdmissionRejection::RawBytes => anyhow!(
            "bridge action public_args byte count {} exceeds cap {}",
            input.raw_bytes,
            input.raw_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::DecodedBytes => anyhow!(
            "bridge action decoded byte count {} exceeds cap {}",
            input.decoded_bytes,
            input.decoded_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::ItemCount => anyhow!(
            "bridge action dynamic item count {} exceeds cap {}",
            input.item_count,
            input.item_count_cap
        ),
        NativeBoundedRequestAdmissionRejection::ItemBytes => anyhow!(
            "bridge action proof receipt or payload item byte count {} exceeds cap {}",
            input.max_item_bytes,
            input.item_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::AggregateBytes => anyhow!(
            "bridge action dynamic byte aggregate {} exceeds cap {}",
            input.aggregate_bytes,
            input.aggregate_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::WorkUnits => anyhow!(
            "bridge action message payload byte count {} exceeds cap {}",
            input.work_units,
            input.work_unit_cap
        ),
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

fn evaluate_native_bridge_mint_replay_policy(
    input: NativeBridgeMintReplayPolicyInput,
) -> Result<InboundReplayState, NativeBridgeMintReplayPolicyRejection> {
    if !input.inbound_bridge_mint {
        Err(NativeBridgeMintReplayPolicyRejection::NotInboundBridgeMint)
    } else if !input.state_deltas_absent {
        Err(NativeBridgeMintReplayPolicyRejection::StateDeltaMintPresent)
    } else if !input.receipt_envelope_present {
        Err(NativeBridgeMintReplayPolicyRejection::ReceiptEnvelopeMissing)
    } else if !input.receipt_verified {
        Err(NativeBridgeMintReplayPolicyRejection::ReceiptNotVerified)
    } else if !input.receipt_payload_matches {
        Err(NativeBridgeMintReplayPolicyRejection::ReceiptPayloadMismatch)
    } else if input.replay_state.consumed().contains(&input.replay_key) {
        Err(NativeBridgeMintReplayPolicyRejection::ReplayAlreadyConsumed)
    } else if !input.mint_authorized {
        Err(NativeBridgeMintReplayPolicyRejection::MintNotAuthorized)
    } else if !input.amount_matches_receipt {
        Err(NativeBridgeMintReplayPolicyRejection::AmountDoesNotMatchReceipt)
    } else if !input.amount_within_bound {
        Err(NativeBridgeMintReplayPolicyRejection::AmountOutOfBounds)
    } else {
        let mut next_replay_state = input.replay_state;
        next_replay_state
            .import_one(input.replay_key)
            .map_err(|_| NativeBridgeMintReplayPolicyRejection::ReplayAlreadyConsumed)?;
        Ok(next_replay_state)
    }
}

fn evaluate_native_bridge_mint_payload_admission(
    input: NativeBridgeMintPayloadAdmissionInput,
) -> Result<(), NativeBridgeMintPayloadAdmissionRejection> {
    if !input.payload_decoded {
        Err(NativeBridgeMintPayloadAdmissionRejection::PayloadDecodeFailed)
    } else if !input.payload_hash_matches {
        Err(NativeBridgeMintPayloadAdmissionRejection::PayloadHashMismatch)
    } else if !input.receipt_message_hash_matches {
        Err(NativeBridgeMintPayloadAdmissionRejection::ReceiptMessageHashMismatch)
    } else if !input.version_matches {
        Err(NativeBridgeMintPayloadAdmissionRejection::VersionMismatch)
    } else if !input.source_app_family_matches {
        Err(NativeBridgeMintPayloadAdmissionRejection::SourceAppFamilyMismatch)
    } else if !input.destination_matches {
        Err(NativeBridgeMintPayloadAdmissionRejection::DestinationMismatch)
    } else if !input.mint_nonce_matches {
        Err(NativeBridgeMintPayloadAdmissionRejection::MintNonceMismatch)
    } else if !input.recipient_commitment_nonzero {
        Err(NativeBridgeMintPayloadAdmissionRejection::RecipientCommitmentZero)
    } else if !input.amount_nonzero {
        Err(NativeBridgeMintPayloadAdmissionRejection::AmountZero)
    } else if !input.amount_within_bound {
        Err(NativeBridgeMintPayloadAdmissionRejection::AmountOutOfBounds)
    } else if !input.asset_non_native {
        Err(NativeBridgeMintPayloadAdmissionRejection::NativeAssetNotAllowed)
    } else {
        Ok(())
    }
}

fn evaluate_native_bridge_verifier_registration_policy(
    input: NativeBridgeVerifierRegistrationPolicyInput,
) -> Result<
    NativeBridgeVerifierRegistrationPolicyEffect,
    NativeBridgeVerifierRegistrationPolicyRejection,
> {
    if !input.bridge_verifier_registration {
        Err(NativeBridgeVerifierRegistrationPolicyRejection::NotBridgeVerifierRegistration)
    } else if !input.state_deltas_absent {
        Err(NativeBridgeVerifierRegistrationPolicyRejection::StateDeltasPresent)
    } else if !input.registration_decoded {
        Err(NativeBridgeVerifierRegistrationPolicyRejection::RegistrationDecodeFailed)
    } else {
        Ok(NativeBridgeVerifierRegistrationPolicyEffect {
            registration_observed: true,
            production_mint_verifier_enabled: input.descriptor_matches_release
                && input.activation_height_reached
                && input.pq_clean_verifier_bound
                && input.external_verifier_soundness_accepted
                && input.positive_minting_enabled,
        })
    }
}

fn native_bridge_verifier_registration_policy_input(
    action: &PendingAction,
    registration: Option<&BridgeVerifierRegistrationV1>,
) -> NativeBridgeVerifierRegistrationPolicyInput {
    NativeBridgeVerifierRegistrationPolicyInput {
        bridge_verifier_registration: action.family_id == FAMILY_BRIDGE
            && action.action_id == ACTION_REGISTER_BRIDGE_VERIFIER,
        state_deltas_absent: bridge_action_has_no_state_deltas(action),
        registration_decoded: registration.is_some(),
        descriptor_matches_release: registration.is_some_and(|registration| {
            registration.source_chain_id == HEGEMON_CHAIN_ID_V1
                && registration.verifier_program_hash == HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1
                && registration.rules_hash == HEGEMON_LIGHT_CLIENT_RULES_HASH_V1
        }),
        activation_height_reached: registration
            .is_some_and(|registration| registration.enabled_at_height == 0),
        pq_clean_verifier_bound: NATIVE_PQ_CLEAN_BRIDGE_VERIFIER_BOUND,
        external_verifier_soundness_accepted: NATIVE_EXTERNAL_BRIDGE_VERIFIER_SOUNDNESS_ACCEPTED,
        positive_minting_enabled: NATIVE_POSITIVE_INBOUND_BRIDGE_MINT_ENABLED,
    }
}

fn bridge_mint_payload_admission_input(
    args: &InboundBridgeArgsV1,
    output: &BridgeCheckpointOutputV1,
    payload: Option<&BridgeMintPayloadV1>,
) -> NativeBridgeMintPayloadAdmissionInput {
    let payload_hash_matches =
        args.message.payload_hash == bridge_payload_hash(&args.message.payload);
    let receipt_message_hash_matches = output.message_hash == args.message.message_hash();
    if let Some(payload) = payload {
        NativeBridgeMintPayloadAdmissionInput {
            payload_decoded: true,
            payload_hash_matches,
            receipt_message_hash_matches,
            version_matches: payload.version == BRIDGE_MINT_PAYLOAD_VERSION_V1,
            source_app_family_matches: args.message.app_family_id == BRIDGE_MINT_APP_FAMILY_ID_V1,
            destination_matches: payload.destination_chain_id == HEGEMON_CHAIN_ID_V1,
            mint_nonce_matches: payload.mint_nonce == args.source_message_nonce,
            recipient_commitment_nonzero: payload.recipient_commitment != [0u8; 48],
            amount_nonzero: payload.amount != 0,
            amount_within_bound: payload.amount <= MAX_NATIVE_BRIDGE_MINT_AMOUNT,
            asset_non_native: payload.asset_id != transaction_core::constants::NATIVE_ASSET_ID,
        }
    } else {
        NativeBridgeMintPayloadAdmissionInput {
            payload_decoded: false,
            payload_hash_matches,
            receipt_message_hash_matches,
            version_matches: false,
            source_app_family_matches: false,
            destination_matches: false,
            mint_nonce_matches: false,
            recipient_commitment_nonzero: false,
            amount_nonzero: false,
            amount_within_bound: false,
            asset_non_native: false,
        }
    }
}

fn native_bridge_mint_payload_admission_error(
    rejection: NativeBridgeMintPayloadAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeBridgeMintPayloadAdmissionRejection::PayloadDecodeFailed => anyhow!(
            "inbound bridge mint payload exact decode failed ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::PayloadHashMismatch => anyhow!(
            "inbound bridge mint payload hash mismatch ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::ReceiptMessageHashMismatch => anyhow!(
            "inbound bridge mint receipt/message hash mismatch ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::VersionMismatch => anyhow!(
            "inbound bridge mint payload version mismatch ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::SourceAppFamilyMismatch => anyhow!(
            "inbound bridge mint source app family mismatch ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::DestinationMismatch => anyhow!(
            "inbound bridge mint payload is not addressed to Hegemon ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::MintNonceMismatch => anyhow!(
            "inbound bridge mint payload nonce does not match receipt replay nonce ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::RecipientCommitmentZero => anyhow!(
            "inbound bridge mint payload recipient commitment is zero ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::AmountZero => {
            anyhow!("inbound bridge mint amount is zero ({})", rejection.label())
        }
        NativeBridgeMintPayloadAdmissionRejection::AmountOutOfBounds => anyhow!(
            "inbound bridge mint amount exceeds native bridge mint cap ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::NativeAssetNotAllowed => anyhow!(
            "inbound bridge mint payload must target a non-native bridge asset ({})",
            rejection.label()
        ),
    }
}

fn native_bridge_verifier_registration_policy_error(
    rejection: NativeBridgeVerifierRegistrationPolicyRejection,
) -> anyhow::Error {
    match rejection {
        NativeBridgeVerifierRegistrationPolicyRejection::NotBridgeVerifierRegistration => {
            anyhow!("not a bridge verifier registration ({})", rejection.label())
        }
        NativeBridgeVerifierRegistrationPolicyRejection::StateDeltasPresent => anyhow!(
            "bridge verifier registration carries shielded state deltas ({})",
            rejection.label()
        ),
        NativeBridgeVerifierRegistrationPolicyRejection::RegistrationDecodeFailed => anyhow!(
            "bridge verifier registration exact decode failed ({})",
            rejection.label()
        ),
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

fn native_bridge_mint_replay_policy_error(
    rejection: NativeBridgeMintReplayPolicyRejection,
) -> anyhow::Error {
    match rejection {
        NativeBridgeMintReplayPolicyRejection::NotInboundBridgeMint => {
            anyhow!("not an inbound bridge mint action ({})", rejection.label())
        }
        NativeBridgeMintReplayPolicyRejection::StateDeltaMintPresent => anyhow!(
            "inbound bridge mint action carries shielded state deltas ({})",
            rejection.label()
        ),
        NativeBridgeMintReplayPolicyRejection::ReceiptEnvelopeMissing => {
            anyhow!(
                "inbound bridge receipt envelope missing ({})",
                rejection.label()
            )
        }
        NativeBridgeMintReplayPolicyRejection::ReceiptNotVerified => {
            anyhow!(
                "inbound bridge receipt is not verified ({})",
                rejection.label()
            )
        }
        NativeBridgeMintReplayPolicyRejection::ReceiptPayloadMismatch => {
            anyhow!(
                "inbound bridge receipt payload mismatch ({})",
                rejection.label()
            )
        }
        NativeBridgeMintReplayPolicyRejection::ReplayAlreadyConsumed => {
            anyhow!(
                "inbound bridge message already consumed ({})",
                rejection.label()
            )
        }
        NativeBridgeMintReplayPolicyRejection::MintNotAuthorized => anyhow!(
            "inbound bridge mint authorization is disabled until a PQ-clean bridge mint decoder and verifier are production-bound ({})",
            rejection.label()
        ),
        NativeBridgeMintReplayPolicyRejection::AmountDoesNotMatchReceipt => anyhow!(
            "inbound bridge mint amount does not match receipt ({})",
            rejection.label()
        ),
        NativeBridgeMintReplayPolicyRejection::AmountOutOfBounds => {
            anyhow!(
                "inbound bridge mint amount out of bounds ({})",
                rejection.label()
            )
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
        let confirmations =
            native_bridge_witness_confirmations_checked(input.best_height, input.message_height)
                .ok_or(NativeBridgeWitnessExportAdmissionRejection::TipBeforeMessage)?;
        if input.explicit_block_hash && u64::from(confirmations) > input.max_explicit_history {
            Err(NativeBridgeWitnessExportAdmissionRejection::ExplicitHistoryTooLong)
        } else if input.best_height > input.max_materialized_history {
            Err(NativeBridgeWitnessExportAdmissionRejection::MaterializedHistoryTooLong)
        } else {
            Ok(confirmations)
        }
    }
}

fn native_inbound_bridge_receipt_height_confirmations(
    canonical_tip_height: u64,
    checkpoint_height: u64,
) -> Result<u32, NativeInboundBridgeReceiptAdmissionRejection> {
    let delta = canonical_tip_height
        .checked_sub(checkpoint_height)
        .ok_or(NativeInboundBridgeReceiptAdmissionRejection::TipBeforeMessage)?;
    let confirmations = delta
        .checked_add(1)
        .ok_or(NativeInboundBridgeReceiptAdmissionRejection::ConfirmationsOverflow)?;
    u32::try_from(confirmations)
        .map_err(|_| NativeInboundBridgeReceiptAdmissionRejection::ConfirmationsOverflow)
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
        )?;
        if height_confirmations < input.confirmations_checked {
            Err(NativeInboundBridgeReceiptAdmissionRejection::ConfirmationsOverstated)
        } else if input.confirmations_checked < input.min_confirmations {
            Err(NativeInboundBridgeReceiptAdmissionRejection::Underconfirmed)
        } else if compare_work(&input.canonical_tip_work, &input.min_tip_work).is_lt()
            || compare_work(&input.min_work_checked, &input.min_tip_work).is_lt()
        {
            Err(NativeInboundBridgeReceiptAdmissionRejection::WorkPolicyMismatch)
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
        NativeBridgeWitnessExportAdmissionRejection::ExplicitHistoryTooLong => anyhow!(
            "explicit bridge witness block is too old for full export; checked confirmations exceed {MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS} ({})",
            rejection.label()
        ),
        NativeBridgeWitnessExportAdmissionRejection::MaterializedHistoryTooLong => anyhow!(
            "bridge witness export requires a materialized header history longer than {MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS}; enable an indexed bridge proof store before raising this safe-RPC cap ({})",
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
        NativeInboundBridgeReceiptAdmissionRejection::ConfirmationsOverflow => {
            anyhow!("Hegemon light-client bridge receipt confirmation count exceeds native width")
        }
        NativeInboundBridgeReceiptAdmissionRejection::ConfirmationsOverstated => {
            anyhow!("Hegemon light-client bridge receipt overstates confirmations")
        }
        NativeInboundBridgeReceiptAdmissionRejection::Underconfirmed => anyhow!(
            "Hegemon light-client bridge receipt underconfirmed: {} < {}",
            input.confirmations_checked,
            input.min_confirmations
        ),
        NativeInboundBridgeReceiptAdmissionRejection::WorkPolicyMismatch => {
            anyhow!("Hegemon light-client bridge receipt does not meet native work policy")
        }
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

fn verify_inbound_bridge_receipt(
    action: &PendingAction,
    args: &InboundBridgeArgsV1,
    replay_state: Option<InboundReplayState>,
) -> Result<()> {
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
        canonical_tip_work: output.canonical_tip_cumulative_work,
        confirmations_checked: output.confirmations_checked,
        min_confirmations: MIN_INBOUND_BRIDGE_CONFIRMATIONS,
        min_work_checked: output.min_work_checked,
        min_tip_work: HEGEMON_BRIDGE_LONG_RANGE_MIN_TIP_WORK_V1,
    };
    evaluate_native_inbound_bridge_receipt_admission(admission_input).map_err(|rejection| {
        native_inbound_bridge_receipt_admission_error(admission_input, rejection)
    })?;
    enforce_verified_inbound_bridge_mint_replay_policy(action, args, &output, replay_state)?;
    Ok(())
}

fn enforce_verified_inbound_bridge_mint_replay_policy(
    action: &PendingAction,
    args: &InboundBridgeArgsV1,
    output: &BridgeCheckpointOutputV1,
    replay_state: Option<InboundReplayState>,
) -> Result<()> {
    let Some(replay_state) = replay_state else {
        return Err(anyhow!(
            "inbound bridge mint replay state is required before accepting verified bridge receipts"
        ));
    };
    let mint_payload = decode_scale_exact::<BridgeMintPayloadV1>(
        &args.message.payload,
        "inbound bridge mint payload",
    );
    let payload_input =
        bridge_mint_payload_admission_input(args, output, mint_payload.as_ref().ok());
    evaluate_native_bridge_mint_payload_admission(payload_input)
        .map_err(native_bridge_mint_payload_admission_error)?;
    let _mint_payload = mint_payload.expect("payload admission requires exact decode");
    let replay_key = inbound_replay_key(args.source_chain_id, args.source_message_nonce);
    let policy_input = NativeBridgeMintReplayPolicyInput {
        inbound_bridge_mint: action.family_id == FAMILY_BRIDGE
            && action.action_id == ACTION_BRIDGE_INBOUND,
        state_deltas_absent: bridge_action_has_no_state_deltas(action),
        receipt_envelope_present: !args.proof_receipt.is_empty(),
        receipt_verified: true,
        receipt_payload_matches: output.source_chain_id == args.source_chain_id
            && output.rules_hash == HEGEMON_LIGHT_CLIENT_RULES_HASH_V1
            && output.message_nonce == args.source_message_nonce
            && output.message_hash == args.message.message_hash(),
        replay_state,
        replay_key,
        mint_authorized: false,
        amount_matches_receipt: true,
        amount_within_bound: true,
    };
    match evaluate_native_bridge_mint_replay_policy(policy_input) {
        Ok(_) => Err(anyhow!(
            "inbound bridge mint policy unexpectedly accepted without production mint authorization"
        )),
        Err(rejection) => Err(native_bridge_mint_replay_policy_error(rejection)),
    }
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
    validate_block_action_byte_budget(
        meta.tx_count,
        meta.action_bytes.len(),
        meta.action_bytes.iter().map(Vec::len),
    )?;
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

fn validate_block_action_byte_budget<I>(
    declared_tx_count: u32,
    action_payload_count: usize,
    action_payload_lengths: I,
) -> Result<()>
where
    I: IntoIterator<Item = usize>,
{
    let declared_count = declared_tx_count as usize;
    if declared_count > MAX_NATIVE_BLOCK_ACTIONS || action_payload_count > MAX_NATIVE_BLOCK_ACTIONS
    {
        return Err(anyhow!(
            "native block action count exceeds limit: declared={}, payloads={}, max={}",
            declared_count,
            action_payload_count,
            MAX_NATIVE_BLOCK_ACTIONS
        ));
    }

    let mut total = 0usize;
    for len in action_payload_lengths {
        if len > MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES {
            return Err(anyhow!(
                "native block action payload exceeds per-action limit: {} > {}",
                len,
                MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES
            ));
        }
        total = total
            .checked_add(len)
            .ok_or_else(|| anyhow!("native block action byte total overflow"))?;
        if total > MAX_NATIVE_BLOCK_ACTION_BYTES {
            return Err(anyhow!(
                "native block action bytes exceed aggregate limit: {} > {}",
                total,
                MAX_NATIVE_BLOCK_ACTION_BYTES
            ));
        }
    }
    Ok(())
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
        NativeTransferStateAdmissionRejection::StablecoinPolicyUnauthorized => {
            NativeBlockActionValidationRejection::TransferStablecoinPolicyUnauthorized
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
        NativeBlockActionValidationRejection::TransferStablecoinPolicyUnauthorized => {
            Some(NativeTransferStateAdmissionRejection::StablecoinPolicyUnauthorized)
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
        Err(NativeBlockCommitmentAdmissionRejection::TxCount)
    } else if !input.state_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::StateRoot)
    } else if !input.kernel_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::KernelRoot)
    } else if !input.nullifier_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::NullifierRoot)
    } else if !input.extrinsics_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::ExtrinsicsRoot)
    } else if !input.message_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::MessageRoot)
    } else if !input.message_count_matches {
        Err(NativeBlockCommitmentAdmissionRejection::MessageCount)
    } else if !input.header_mmr_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::HeaderMmrRoot)
    } else if !input.header_mmr_len_matches {
        Err(NativeBlockCommitmentAdmissionRejection::HeaderMmrLen)
    } else if !input.supply_digest_matches {
        Err(NativeBlockCommitmentAdmissionRejection::SupplyDigest)
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
        NativeAtomicCommitKind::TipExtensionBatchCommit => input.chain_block_count,
        NativeAtomicCommitKind::CanonicalReorgCommit => input.chain_block_count,
        NativeAtomicCommitKind::CanonicalIndexRepair => 0,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 1,
    }
}

fn expected_atomic_height_index_writes(input: NativeAtomicCommitManifestAdmissionInput) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit => 1,
        NativeAtomicCommitKind::TipExtensionBatchCommit => input.height_entry_count,
        NativeAtomicCommitKind::CanonicalReorgCommit => input.height_entry_count,
        NativeAtomicCommitKind::CanonicalIndexRepair
        | NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

fn expected_atomic_best_pointer_writes(input: NativeAtomicCommitManifestAdmissionInput) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::TipExtensionBatchCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit => 1,
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
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::TipExtensionBatchCommit => input.action_count,
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
        | NativeAtomicCommitKind::TipExtensionBatchCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit
        | NativeAtomicCommitKind::CanonicalIndexRepair => input.source_commitment_count,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

fn expected_atomic_nullifier_writes(input: NativeAtomicCommitManifestAdmissionInput) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::TipExtensionBatchCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit
        | NativeAtomicCommitKind::CanonicalIndexRepair => input.source_nullifier_count,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

fn expected_atomic_bridge_replay_writes(input: NativeAtomicCommitManifestAdmissionInput) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::TipExtensionBatchCommit
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
        | NativeAtomicCommitKind::TipExtensionBatchCommit
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
        | NativeAtomicCommitKind::TipExtensionBatchCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit
        | NativeAtomicCommitKind::CanonicalIndexRepair => input.source_ciphertext_archive_count,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

fn expected_atomic_staged_ciphertext_removals(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::TipExtensionBatchCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit => {
            input.source_staged_ciphertext_removal_count
        }
        _ => 0,
    }
}

fn evaluate_native_atomic_commit_manifest_admission(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> Result<(), NativeAtomicCommitManifestAdmissionRejection> {
    if matches!(
        input.kind,
        NativeAtomicCommitKind::MinedBlockCommit | NativeAtomicCommitKind::TipExtensionBatchCommit
    ) && input.action_count != input.planned_action_count
    {
        Err(NativeAtomicCommitManifestAdmissionRejection::MinedPlanLength)
    } else if input.block_record_writes != expected_atomic_block_record_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::BlockRecordWrites)
    } else if input.height_index_writes != expected_atomic_height_index_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::HeightIndexWrites)
    } else if input.best_pointer_writes != expected_atomic_best_pointer_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::BestPointerWrites)
    } else if input.canonical_index_cleared != expected_atomic_canonical_index_cleared(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::CanonicalIndexClear)
    } else if input.pending_tree_cleared != expected_atomic_pending_tree_cleared(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::PendingTreeClear)
    } else if input.pending_action_removals != expected_atomic_pending_action_removals(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::PendingActionRemoval)
    } else if input.pending_action_writes != expected_atomic_pending_action_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::PendingActionWrite)
    } else if input.commitment_writes != expected_atomic_commitment_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::CommitmentWrite)
    } else if input.nullifier_writes != expected_atomic_nullifier_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::NullifierWrite)
    } else if input.bridge_replay_writes != expected_atomic_bridge_replay_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::BridgeReplayWrite)
    } else if input.ciphertext_index_writes != expected_atomic_ciphertext_index_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::CiphertextIndexWrite)
    } else if input.ciphertext_archive_writes != expected_atomic_ciphertext_archive_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::CiphertextArchiveWrite)
    } else if input.staged_ciphertext_removals != expected_atomic_staged_ciphertext_removals(input)
    {
        Err(NativeAtomicCommitManifestAdmissionRejection::StagedCiphertextRemoval)
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

fn native_tip_extension_batch_commit_manifest(
    canonical_index_plan: &NativeCanonicalIndexPlan,
    block_entries: &[([u8; 32], Vec<u8>)],
    height_entries: &[(u64, [u8; 32])],
    pending_action_removal_count: usize,
    staged_ciphertext_removal_count: usize,
    action_count: usize,
    planned_action_count: usize,
) -> NativeAtomicCommitManifestAdmissionInput {
    NativeAtomicCommitManifestAdmissionInput {
        kind: NativeAtomicCommitKind::TipExtensionBatchCommit,
        action_count,
        planned_action_count,
        chain_block_count: block_entries.len(),
        height_entry_count: height_entries.len(),
        pending_entry_count: 0,
        source_commitment_count: canonical_index_plan.commitment_entries.len(),
        source_nullifier_count: canonical_index_plan.nullifier_entries.len(),
        source_bridge_replay_count: canonical_index_plan.bridge_replay_entries.len(),
        source_ciphertext_index_count: canonical_index_plan.ciphertext_index_entries.len(),
        source_ciphertext_archive_count: canonical_index_plan.ciphertext_archive_entries.len(),
        source_staged_ciphertext_removal_count: staged_ciphertext_removal_count,
        block_record_writes: block_entries.len(),
        height_index_writes: height_entries.len(),
        best_pointer_writes: 1,
        canonical_index_cleared: false,
        pending_tree_cleared: false,
        pending_action_removals: pending_action_removal_count,
        pending_action_writes: 0,
        commitment_writes: canonical_index_plan.commitment_entries.len(),
        nullifier_writes: canonical_index_plan.nullifier_entries.len(),
        bridge_replay_writes: canonical_index_plan.bridge_replay_entries.len(),
        ciphertext_index_writes: canonical_index_plan.ciphertext_index_entries.len(),
        ciphertext_archive_writes: canonical_index_plan.ciphertext_archive_entries.len(),
        staged_ciphertext_removals: staged_ciphertext_removal_count,
    }
}

fn native_reorg_commit_manifest(
    canonical_index_plan: &NativeCanonicalIndexPlan,
    block_entries: &[([u8; 32], Vec<u8>)],
    height_entries: &[(u64, [u8; 32])],
    pending_entries: &[([u8; 32], Vec<u8>)],
    staged_ciphertext_removal_count: usize,
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
        source_staged_ciphertext_removal_count: staged_ciphertext_removal_count,
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
        staged_ciphertext_removals: staged_ciphertext_removal_count,
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

fn flush_native_db_durability_barrier(
    db: &sled::Db,
    context: &'static str,
    operation: NativeStorageDurabilityOperation,
) -> Result<()> {
    match db.flush() {
        Ok(flushed_bytes) => {
            evaluate_native_storage_durability_admission(NativeStorageDurabilityAdmissionInput {
                operation_supported: true,
                transaction_accepted: true,
                durability_flushed: true,
            })
            .map_err(|rejection| native_storage_durability_admission_error(context, rejection))?;
            debug!(
                context,
                operation = operation.label(),
                flushed_bytes,
                "native storage durability barrier accepted"
            );
            Ok(())
        }
        Err(err) => {
            let rejection = evaluate_native_storage_durability_admission(
                NativeStorageDurabilityAdmissionInput {
                    operation_supported: true,
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
    if !input.operation_supported {
        Err(NativeStorageDurabilityAdmissionRejection::UnsupportedOperation)
    } else if !input.transaction_accepted {
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
        NativeBlockCommitmentAdmissionRejection::TxCount => {
            NativeBlockReplayRefinementRejection::TxCountMismatch
        }
        NativeBlockCommitmentAdmissionRejection::StateRoot => {
            NativeBlockReplayRefinementRejection::StateRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::KernelRoot => {
            NativeBlockReplayRefinementRejection::KernelRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::NullifierRoot => {
            NativeBlockReplayRefinementRejection::NullifierRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::ExtrinsicsRoot => {
            NativeBlockReplayRefinementRejection::ExtrinsicsRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::MessageRoot => {
            NativeBlockReplayRefinementRejection::MessageRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::MessageCount => {
            NativeBlockReplayRefinementRejection::MessageCountMismatch
        }
        NativeBlockCommitmentAdmissionRejection::HeaderMmrRoot => {
            NativeBlockReplayRefinementRejection::HeaderMmrRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::HeaderMmrLen => {
            NativeBlockReplayRefinementRejection::HeaderMmrLenMismatch
        }
        NativeBlockCommitmentAdmissionRejection::SupplyDigest => {
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
    ciphertext_archive_tree: Option<&sled::Tree>,
    state: &NativeState,
    actions: &[PendingAction],
    input: NativeBlockReplayRefinementInput,
) -> Result<NativeBlockReplayRefinementSummary> {
    let materialized = materialize_native_action_payloads_from_state(
        da_ciphertext_tree,
        ciphertext_archive_tree,
        state,
        actions,
    )?;
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
            stablecoin_policy_authorized: true,
            sidecar_route: false,
            sidecar_ciphertexts_available: true,
            sidecar_ciphertext_sizes_present: true,
            sidecar_ciphertext_sizes_match: true,
        };

        if let Ok(route) = route_preview {
            match route {
                NativeActionScopeAdmissionRoute::Bridge => {
                    let replay_state_before = validation_state.bridge_replay_state.clone();
                    if let Err(err) = validate_bridge_action_payload_with_replay_state(
                        action,
                        Some(&replay_state_before),
                    ) {
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

#[allow(dead_code)]
fn materialize_native_action_payloads(
    da_ciphertext_tree: &sled::Tree,
    actions: &[PendingAction],
) -> Result<Vec<NativeMaterializedActionPayload>> {
    let starts = vec![0u64; actions.len()];
    materialize_native_action_payloads_at_starts(da_ciphertext_tree, None, actions, &starts)
}

fn materialize_native_action_payloads_from_state(
    da_ciphertext_tree: &sled::Tree,
    ciphertext_archive_tree: Option<&sled::Tree>,
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<Vec<NativeMaterializedActionPayload>> {
    let starts = planned_action_starts_from_wire_counts(state, actions)?;
    materialize_native_action_payloads_at_starts(
        da_ciphertext_tree,
        ciphertext_archive_tree,
        actions,
        &starts,
    )
}

fn materialize_native_action_payloads_at_starts(
    da_ciphertext_tree: &sled::Tree,
    ciphertext_archive_tree: Option<&sled::Tree>,
    actions: &[PendingAction],
    commitment_starts: &[u64],
) -> Result<Vec<NativeMaterializedActionPayload>> {
    if actions.len() != commitment_starts.len() {
        return Err(anyhow!(
            "native materialized action start count mismatch: actions={} starts={}",
            actions.len(),
            commitment_starts.len()
        ));
    }
    actions
        .iter()
        .zip(commitment_starts.iter().copied())
        .map(|(action, commitment_start)| {
            Ok(NativeMaterializedActionPayload {
                ciphertexts: canonical_ciphertexts_for_action(
                    da_ciphertext_tree,
                    ciphertext_archive_tree,
                    action,
                    commitment_start,
                )?,
                replay_key: bridge_inbound_replay_key_from_action(action)?,
            })
        })
        .collect()
}

fn planned_action_starts_from_wire_counts(
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<Vec<u64>> {
    let mut bridge_replay_state =
        InboundReplayState::new(state.consumed_bridge_messages.clone(), BTreeSet::new());
    let mut nullifier_state = NullifierState::new(state.nullifiers.clone(), BTreeSet::new());
    let wire_steps = actions
        .iter()
        .map(|action| {
            Ok(NativeActionStreamStep {
                commitment_count: action.commitments.len(),
                ciphertext_count: canonical_ciphertext_count_for_action(action)?,
                nullifiers: action.nullifiers.as_slice(),
                replay_key: bridge_inbound_replay_key_from_action(action)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let stream = evaluate_native_action_stream_effect(
        state.commitment_tree.leaf_count(),
        wire_steps.iter().copied(),
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
            "native wire-count action plan construction",
            rejection,
        )
    })?;
    Ok(stream.planned_starts)
}

fn plan_materialized_action_effects(
    da_ciphertext_tree: &sled::Tree,
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<Vec<NativePlannedActionEffect>> {
    plan_materialized_action_effects_with_archive(da_ciphertext_tree, None, state, actions)
}

fn plan_materialized_action_effects_with_archive(
    da_ciphertext_tree: &sled::Tree,
    ciphertext_archive_tree: Option<&sled::Tree>,
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<Vec<NativePlannedActionEffect>> {
    let mut bridge_replay_state =
        InboundReplayState::new(state.consumed_bridge_messages.clone(), BTreeSet::new());
    let mut nullifier_state = NullifierState::new(state.nullifiers.clone(), BTreeSet::new());
    let wire_steps = actions
        .iter()
        .map(|action| {
            Ok(NativeActionStreamStep {
                commitment_count: action.commitments.len(),
                ciphertext_count: canonical_ciphertext_count_for_action(action)?,
                nullifiers: action.nullifiers.as_slice(),
                replay_key: bridge_inbound_replay_key_from_action(action)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let stream = evaluate_native_action_stream_effect(
        state.commitment_tree.leaf_count(),
        wire_steps.iter().copied(),
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
    let materialized = materialize_native_action_payloads_at_starts(
        da_ciphertext_tree,
        ciphertext_archive_tree,
        actions,
        &stream.planned_starts,
    )?;

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

#[cfg(test)]
fn apply_actions_to_memory(
    da_ciphertext_tree: &sled::Tree,
    state: &mut NativeState,
    actions: &[PendingAction],
) -> Result<()> {
    apply_actions_to_memory_with_archive(da_ciphertext_tree, None, state, actions)
}

fn apply_actions_to_memory_with_archive(
    da_ciphertext_tree: &sled::Tree,
    ciphertext_archive_tree: Option<&sled::Tree>,
    state: &mut NativeState,
    actions: &[PendingAction],
) -> Result<()> {
    let planned = plan_materialized_action_effects_with_archive(
        da_ciphertext_tree,
        ciphertext_archive_tree,
        state,
        actions,
    )?;
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
    let mut next_commitment_tree = state.commitment_tree.clone();
    let mut planned_commitments = Vec::new();
    for (action, effect) in actions.iter().zip(planned.iter()) {
        for (offset, commitment) in action.commitments.iter().enumerate() {
            let offset = u64::try_from(offset)
                .map_err(|_| anyhow!("native memory commitment offset overflow"))?;
            let expected_index = effect
                .commitment_start
                .checked_add(offset)
                .ok_or_else(|| anyhow!("native memory commitment index overflow"))?;
            if expected_index != leaf_cursor {
                return Err(anyhow!(
                    "native memory action plan drift: expected leaf {} observed {}",
                    expected_index,
                    leaf_cursor
                ));
            }
            planned_commitments.push(*commitment);
            leaf_cursor = leaf_cursor
                .checked_add(1)
                .ok_or_else(|| anyhow!("native memory commitment leaf overflow"))?;
        }
    }
    next_commitment_tree
        .extend(planned_commitments)
        .map_err(|err| anyhow!("append native commitment batch failed: {err}"))?;
    state.commitment_tree = next_commitment_tree;

    for (action, effect) in actions.iter().zip(planned.iter()) {
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

fn append_native_block_commit_index_entries(
    context: &'static str,
    actions: &[PendingAction],
    planned: &[NativePlannedActionEffect],
    commitment_entries: &mut Vec<(u64, [u8; 48])>,
    ciphertext_archive_entries: &mut Vec<(u64, Vec<u8>)>,
    nullifier_entries: &mut Vec<[u8; 48]>,
    bridge_replay_entries: &mut Vec<[u8; 48]>,
    ciphertext_index_entries: &mut Vec<([u8; 48], Vec<u8>)>,
    pending_action_removals: &mut Vec<[u8; 32]>,
    staged_ciphertext_removals: &mut Vec<[u8; 48]>,
) -> Result<()> {
    for (action, effect) in actions.iter().zip(planned.iter()) {
        if action.ciphertext_hashes.len() != action.ciphertext_sizes.len() {
            return Err(anyhow!(
                "{context} ciphertext metadata count mismatch: hashes={} sizes={}",
                action.ciphertext_hashes.len(),
                action.ciphertext_sizes.len()
            ));
        }

        for (offset, commitment) in action.commitments.iter().enumerate() {
            let offset = u64::try_from(offset)
                .map_err(|_| anyhow!("{context} commitment offset overflow"))?;
            let index = effect
                .commitment_start
                .checked_add(offset)
                .ok_or_else(|| anyhow!("{context} commitment index overflow"))?;
            commitment_entries.push((index, *commitment));
        }
        for (offset, bytes) in effect.ciphertexts.iter().enumerate() {
            let offset = u64::try_from(offset)
                .map_err(|_| anyhow!("{context} ciphertext offset overflow"))?;
            let index = effect
                .commitment_start
                .checked_add(offset)
                .ok_or_else(|| anyhow!("{context} ciphertext index overflow"))?;
            ciphertext_archive_entries.push((index, bytes.clone()));
        }

        nullifier_entries.extend(action.nullifiers.iter().copied());
        if let Some(replay_key) = effect.replay_key {
            bridge_replay_entries.push(replay_key);
        }

        for (idx, hash) in action.ciphertext_hashes.iter().enumerate() {
            let size = action.ciphertext_sizes[idx];
            let idx = u64::try_from(idx)
                .map_err(|_| anyhow!("{context} ciphertext row offset overflow"))?;
            let mut value = Vec::with_capacity(32 + 4 + 8);
            value.extend_from_slice(&action.tx_hash);
            value.extend_from_slice(&size.to_le_bytes());
            value.extend_from_slice(&idx.to_le_bytes());
            ciphertext_index_entries.push((*hash, value));
        }

        pending_action_removals.push(action.tx_hash);
        staged_ciphertext_removals.extend(action.ciphertext_hashes.iter().copied());
    }
    Ok(())
}

fn plan_canonical_index_rebuild(
    chain: &[NativeBlockMeta],
    da_ciphertext_tree: &sled::Tree,
    ciphertext_archive_tree: Option<&sled::Tree>,
) -> Result<NativeCanonicalIndexPlan> {
    let mut nullifier_state = NullifierState::default();
    let mut bridge_replay_state = InboundReplayState::default();
    let mut decoded_actions = Vec::new();
    for meta in chain.iter().skip(1) {
        let actions = decode_block_actions(meta)?;
        decoded_actions.extend(actions);
    }
    let wire_steps = decoded_actions
        .iter()
        .map(|action| {
            Ok(NativeActionStreamStep {
                commitment_count: action.commitments.len(),
                ciphertext_count: canonical_ciphertext_count_for_action(action)?,
                nullifiers: action.nullifiers.as_slice(),
                replay_key: bridge_inbound_replay_key_from_action(action)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let stream = evaluate_native_action_stream_effect(
        0,
        wire_steps.iter().copied(),
        &mut nullifier_state,
        &mut bridge_replay_state,
    )
    .map_err(native_action_state_effect_error)?;
    let rebuild_commitment_counts = decoded_actions
        .iter()
        .map(|action| action.commitments.len())
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
    let materialized = materialize_native_action_payloads_at_starts(
        da_ciphertext_tree,
        ciphertext_archive_tree,
        &decoded_actions,
        &stream.planned_starts,
    )?;
    let planned_actions = decoded_actions
        .into_iter()
        .zip(materialized)
        .collect::<Vec<_>>();

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
    ciphertext_archive_tree: Option<&sled::Tree>,
    action: &PendingAction,
    commitment_start: u64,
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
                let bytes = if let Some(bytes) = da_ciphertext_tree.get(hash.as_slice())? {
                    bytes.to_vec()
                } else if let Some(ciphertext_archive_tree) = ciphertext_archive_tree {
                    let offset = u64::try_from(idx)
                        .map_err(|_| anyhow!("canonical DA ciphertext index overflow"))?;
                    let archive_index = commitment_start
                        .checked_add(offset)
                        .ok_or_else(|| anyhow!("canonical DA ciphertext archive index overflow"))?;
                    ciphertext_archive_tree
                        .get(archive_index.to_be_bytes())?
                        .map(|bytes| bytes.to_vec())
                        .ok_or_else(|| {
                            anyhow!(
                                "missing canonical DA ciphertext {} at archived index {}",
                                hex48(hash),
                                archive_index
                            )
                        })?
                } else {
                    return Err(anyhow!("missing canonical DA ciphertext {}", hex48(hash)));
                };
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

fn canonical_ciphertext_count_for_action(action: &PendingAction) -> Result<usize> {
    match (action.family_id, action.action_id) {
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE) => {
            let args: ShieldedTransferInlineArgs =
                decode_scale_exact(&action.public_args, "shielded inline action args")?;
            Ok(args.ciphertexts.len())
        }
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_SIDECAR) => {
            if action.ciphertext_hashes.len() != action.ciphertext_sizes.len() {
                return Err(anyhow!(
                    "canonical DA ciphertext metadata count mismatch: hashes={} sizes={}",
                    action.ciphertext_hashes.len(),
                    action.ciphertext_sizes.len()
                ));
            }
            Ok(action.ciphertext_hashes.len())
        }
        (FAMILY_SHIELDED_POOL, ACTION_MINT_COINBASE) => {
            let _args: MintCoinbaseArgs =
                decode_scale_exact(&action.public_args, "coinbase action args")?;
            Ok(1)
        }
        _ => Ok(0),
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
    revalidate_pending_actions(canonical_state, existing_pending, orphaned_actions, "reorg")
}

fn revalidate_pending_actions_after_state_advance(
    canonical_state: &NativeState,
    existing_pending: BTreeMap<[u8; 32], PendingAction>,
) -> BTreeMap<[u8; 32], PendingAction> {
    revalidate_pending_actions(
        canonical_state,
        existing_pending,
        Vec::new(),
        "state_advance",
    )
}

fn revalidate_pending_actions(
    canonical_state: &NativeState,
    existing_pending: BTreeMap<[u8; 32], PendingAction>,
    orphaned_actions: Vec<PendingAction>,
    context: &'static str,
) -> BTreeMap<[u8; 32], PendingAction> {
    let mut staged_state = NativeState {
        best: canonical_state.best.clone(),
        header_mmr_peaks: canonical_state.header_mmr_peaks.clone(),
        pending_actions: BTreeMap::new(),
        commitment_tree: canonical_state.commitment_tree.clone(),
        nullifiers: canonical_state.nullifiers.clone(),
        consumed_bridge_messages: canonical_state.consumed_bridge_messages.clone(),
        stablecoin_policy_authorizations: canonical_state.stablecoin_policy_authorizations.clone(),
        staged_ciphertexts: canonical_state.staged_ciphertexts.clone(),
        staged_proofs: canonical_state.staged_proofs.clone(),
    };

    for (hash, action) in existing_pending {
        stage_revalidated_pending_action(&mut staged_state, hash, action, "existing", context);
    }
    for action in orphaned_actions {
        let hash = action.tx_hash;
        if staged_state.pending_actions.contains_key(&hash) {
            continue;
        }
        stage_revalidated_pending_action(&mut staged_state, hash, action, "orphaned", context);
    }
    prune_candidate_artifacts_when_transfers_pending(&mut staged_state, context);
    prune_unselected_candidate_artifacts_from_pending(&mut staged_state, context);

    staged_state.pending_actions
}

fn pending_candidate_artifact_hashes(staged_state: &NativeState) -> Vec<[u8; 32]> {
    staged_state
        .pending_actions
        .iter()
        .filter_map(|(hash, action)| is_candidate_artifact_action(action).then_some(*hash))
        .collect()
}

fn prune_candidate_artifacts_when_transfers_pending(
    staged_state: &mut NativeState,
    context: &'static str,
) {
    if !staged_state
        .pending_actions
        .values()
        .any(is_shielded_transfer_action)
    {
        return;
    }
    let dropped = pending_candidate_artifact_hashes(staged_state);
    for hash in dropped {
        debug!(
            tx_hash = %hex32(&hash),
            context,
            "dropping candidate artifact while shielded transfers are pending"
        );
        staged_state.pending_actions.remove(&hash);
    }
}

fn prune_unselected_candidate_artifacts_from_pending(
    staged_state: &mut NativeState,
    context: &'static str,
) {
    if !staged_state
        .pending_actions
        .values()
        .any(is_candidate_artifact_action)
    {
        return;
    }

    let selected_candidates = select_mineable_actions(staged_state)
        .into_iter()
        .filter(is_candidate_artifact_action)
        .map(|action| action.tx_hash)
        .collect::<BTreeSet<_>>();
    let dropped = staged_state
        .pending_actions
        .iter()
        .filter_map(|(hash, action)| {
            (is_candidate_artifact_action(action) && !selected_candidates.contains(hash))
                .then_some(*hash)
        })
        .collect::<Vec<_>>();
    for hash in dropped {
        debug!(
            tx_hash = %hex32(&hash),
            context,
            "dropping unselected candidate artifact during mempool revalidation"
        );
        staged_state.pending_actions.remove(&hash);
    }
}

fn prune_auto_coinbase_actions_from_pending(staged_state: &mut NativeState, context: &'static str) {
    let dropped = staged_state
        .pending_actions
        .iter()
        .filter_map(|(hash, action)| is_coinbase_action(action).then_some(*hash))
        .collect::<Vec<_>>();
    for hash in dropped {
        debug!(
            tx_hash = %hex32(&hash),
            context,
            "dropping persisted coinbase action during auto-coinbase mempool revalidation"
        );
        staged_state.pending_actions.remove(&hash);
    }
}

fn stage_revalidated_pending_action(
    staged_state: &mut NativeState,
    hash: [u8; 32],
    action: PendingAction,
    source: &'static str,
    context: &'static str,
) {
    if staged_state.pending_actions.len() >= MAX_NATIVE_MEMPOOL_ACTIONS {
        debug!(
            tx_hash = %hex32(&hash),
            source,
            context,
            "dropping pending action over mempool action cap during revalidation"
        );
        return;
    }
    if let Err(err) = validate_pending_action_against_mempool_state(staged_state, &action) {
        debug!(
            tx_hash = %hex32(&hash),
            source,
            context,
            error = %err,
            "dropping semantically invalid pending action during mempool revalidation"
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
            context,
            error = %err,
            "dropping over-budget pending action during mempool revalidation"
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
        Err(NativeTxLeafActionBindingAdmissionRejection::Nullifiers)
    } else if !input.commitments_match {
        Err(NativeTxLeafActionBindingAdmissionRejection::Commitments)
    } else if !input.ciphertext_hashes_match {
        Err(NativeTxLeafActionBindingAdmissionRejection::CiphertextHashes)
    } else if !input.input_count_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::InputCount)
    } else if !input.output_count_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::OutputCount)
    } else if !input.version_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::Version)
    } else if !input.fee_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::Fee)
    } else if !input.stablecoin_payload_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::StablecoinPayload)
    } else if !input.balance_tag_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::BalanceTag)
    } else if !input.receipt_statement_hash_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::ReceiptStatementHash)
    } else if !input.public_inputs_digest_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::PublicInputsDigest)
    } else if !input.proof_digest_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::ProofDigest)
    } else if !input.proof_backend_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::ProofBackend)
    } else if !input.ciphertext_payload_hashes_match {
        Err(NativeTxLeafActionBindingAdmissionRejection::CiphertextPayloadHash)
    } else {
        Ok(())
    }
}

fn native_tx_leaf_action_binding_admission_error(
    rejection: NativeTxLeafActionBindingAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeTxLeafActionBindingAdmissionRejection::Nullifiers => {
            anyhow!("native tx-leaf nullifiers mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::Commitments => {
            anyhow!("native tx-leaf commitments mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::CiphertextHashes => {
            anyhow!("native tx-leaf ciphertext hashes mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::InputCount => {
            anyhow!("native tx-leaf input count mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::OutputCount => {
            anyhow!("native tx-leaf output count mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::Version => {
            anyhow!("native tx-leaf version mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::Fee => {
            anyhow!("native tx-leaf fee mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::StablecoinPayload => {
            anyhow!("native tx-leaf stablecoin payload mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::BalanceTag => {
            anyhow!("native tx-leaf balance tag mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::ReceiptStatementHash => {
            anyhow!("native tx-leaf receipt statement hash mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::PublicInputsDigest => {
            anyhow!("native tx-leaf public inputs digest mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::ProofDigest => {
            anyhow!("native tx-leaf proof digest mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::ProofBackend => {
            anyhow!("native tx-leaf proof backend/profile mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::CiphertextPayloadHash => {
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
        Err(NativeCandidateArtifactBindingAdmissionRejection::DaRoot)
    } else if !input.da_chunk_count_matches {
        Err(NativeCandidateArtifactBindingAdmissionRejection::DaChunkCount)
    } else if !input.tx_statements_commitment_matches {
        Err(NativeCandidateArtifactBindingAdmissionRejection::TxStatementCommitment)
    } else if !input.recursive_state_root_matches {
        Err(NativeCandidateArtifactBindingAdmissionRejection::RecursiveStateRoot)
    } else {
        Ok(())
    }
}

fn native_candidate_artifact_binding_admission_error(
    rejection: NativeCandidateArtifactBindingAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeCandidateArtifactBindingAdmissionRejection::DaRoot => {
            anyhow!("candidate artifact DA root mismatch")
        }
        NativeCandidateArtifactBindingAdmissionRejection::DaChunkCount => {
            anyhow!("candidate artifact DA chunk count mismatch")
        }
        NativeCandidateArtifactBindingAdmissionRejection::TxStatementCommitment => {
            anyhow!("candidate artifact tx statement commitment mismatch")
        }
        NativeCandidateArtifactBindingAdmissionRejection::RecursiveStateRoot => {
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

    let materialized = materialize_native_action_payloads_from_state(
        &node.da_ciphertext_tree,
        Some(&node.ciphertext_archive_tree),
        state,
        actions,
    )?;
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
    let da_encoding = consensus::encode_da_blob(&transactions, da_params)
        .map_err(|err| anyhow!("native block DA encoding failed: {err}"))?;
    let computed_da_root = da_encoding.root();
    let computed_da_chunk_count = u32::try_from(da_encoding.chunks().len())
        .map_err(|_| anyhow!("native block DA chunk count exceeds u32"))?;
    if let Err(rejection) = evaluate_native_candidate_artifact_binding_admission(
        NativeCandidateArtifactBindingAdmissionInput {
            da_root_matches: computed_da_root == artifact.da_root,
            da_chunk_count_matches: computed_da_chunk_count == artifact.da_chunk_count,
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
            da_chunk_count_matches: true,
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
        state_root: expected_tree.root(),
        kernel_root: expected_kernel_root,
        nullifier_root: expected_nullifier_root,
        proof_commitment: consensus::types::compute_proof_commitment(&transactions),
        da_root: computed_da_root,
        da_params,
        version_commitment: consensus::types::compute_version_commitment(&transactions),
        tx_count: transactions.len() as u32,
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
            da_chunk_count_matches: true,
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
    preview_pending_roots_with_archive(da_ciphertext_tree, None, state, actions)
}

fn preview_pending_roots_with_archive(
    da_ciphertext_tree: &sled::Tree,
    ciphertext_archive_tree: Option<&sled::Tree>,
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

    let planned = plan_materialized_action_effects_with_archive(
        da_ciphertext_tree,
        ciphertext_archive_tree,
        state,
        actions,
    )?;
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

fn validate_announced_block(
    parent: &NativeBlockMeta,
    meta: &NativeBlockMeta,
    expected_pow_bits: u32,
) -> Result<()> {
    evaluate_native_announced_block_admission(native_announced_block_admission_input(
        parent,
        meta,
        current_time_ms(),
    ))
    .map_err(native_announced_block_admission_error)?;
    verify_native_block_meta_projection(Some(parent), meta, Some(expected_pow_bits))
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

fn verify_native_pow_meta(
    parent: &NativeBlockMeta,
    meta: &NativeBlockMeta,
    expected_pow_bits: u32,
) -> Result<()> {
    verify_native_miner_identity(meta)?;
    if meta.hash != meta.work_hash {
        return Err(anyhow!("native block hash must equal work hash"));
    }
    if meta.pow_bits != expected_pow_bits {
        return Err(anyhow!(
            "native block PoW bits mismatch at height {}: expected {}, got {}",
            meta.height,
            expected_pow_bits,
            meta.pow_bits
        ));
    }
    let header = pow_header_from_meta(meta);
    let work_hash = verify_pow_header_with_expected_bits(
        &checkpoint_from_meta(parent),
        &header,
        expected_pow_bits,
    )
    .map_err(|err| anyhow!("native light-client header verification failed: {err:?}"))?;
    if work_hash != meta.hash {
        return Err(anyhow!("native block work hash mismatch"));
    }
    Ok(())
}

fn verify_native_block_meta_projection(
    parent: Option<&NativeBlockMeta>,
    meta: &NativeBlockMeta,
    expected_pow_bits: Option<u32>,
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
    let expected_pow_bits = expected_pow_bits.ok_or_else(|| {
        anyhow!(
            "missing native expected PoW bits for metadata projection at height {} ({})",
            meta.height,
            hex32(&meta.hash)
        )
    })?;
    verify_native_pow_meta(parent, meta, expected_pow_bits)
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

fn native_expected_child_pow_bits_from_chain(
    chain_to_parent: &[NativeBlockMeta],
    genesis_pow_bits: u32,
) -> Result<u32> {
    let parent = chain_to_parent
        .last()
        .ok_or_else(|| anyhow!("native PoW schedule cannot evaluate an empty parent chain"))?;
    let new_height = parent
        .height
        .checked_add(1)
        .ok_or_else(|| anyhow!("native PoW child height overflow"))?;
    let anchor_timestamp_ms = if let Some(anchor_steps) =
        consensus::pow::pow_retarget_anchor_steps(parent.height, new_height)
    {
        let anchor_steps = usize::try_from(anchor_steps)
            .map_err(|_| anyhow!("native PoW retarget anchor step overflow"))?;
        if anchor_steps >= chain_to_parent.len() {
            return Err(anyhow!(
                "native PoW retarget missing anchor history at parent height {}",
                parent.height
            ));
        }
        let anchor_index = chain_to_parent.len() - 1 - anchor_steps;
        Some(chain_to_parent[anchor_index].timestamp_ms)
    } else {
        None
    };
    consensus::pow::expected_pow_bits_from_schedule(
        genesis_pow_bits,
        parent.pow_bits,
        parent.height,
        new_height,
        parent.timestamp_ms,
        anchor_timestamp_ms,
    )
    .map_err(|err| anyhow!("native PoW bits schedule failed: {err}"))
}

fn native_expected_child_pow_bits_for_chain_index(
    chain: &[NativeBlockMeta],
    parent_index: usize,
    genesis_pow_bits: u32,
) -> Result<u32> {
    let parent_chain = chain
        .get(..=parent_index)
        .ok_or_else(|| anyhow!("native PoW schedule parent index out of range"))?;
    native_expected_child_pow_bits_from_chain(parent_chain, genesis_pow_bits)
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
        "unsafe" => {
            if rpc_external {
                Err(anyhow!(
                    "--rpc-methods=unsafe cannot be combined with --rpc-external; use a loopback listener behind an authenticated tunnel"
                ))
            } else {
                Ok(RpcMethodPolicy::Unsafe)
            }
        }
        "auto" | "" => Ok(RpcMethodPolicy::Safe),
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

fn wallet_page_end(page: NativePagination, total: u64) -> Result<u64> {
    if page.start >= total {
        return Ok(page.start);
    }
    page.start
        .checked_add(page.limit)
        .map(|end| end.min(total))
        .ok_or_else(|| anyhow!("native wallet page range overflow"))
}

fn is_unsafe_rpc_method(method: &str) -> bool {
    matches!(
        method,
        "hegemon_startMining"
            | "hegemon_stopMining"
            | "hegemon_submitAction"
            | "hegemon_peerGraph"
            | "hegemon_peerList"
            | "hegemon_exportBridgeWitness"
            | "system_peers"
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

fn duration_millis_u64(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
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

fn native_available_parallelism() -> u32 {
    std::thread::available_parallelism()
        .ok()
        .and_then(|threads| u32::try_from(threads.get()).ok())
        .unwrap_or(1)
        .max(1)
}

fn effective_native_mining_threads(requested: u32, available_threads: u32) -> u32 {
    let requested = requested.max(1);
    let available = available_threads.max(1);
    let liveness_cap = available
        .saturating_sub(NATIVE_MINING_RESERVED_SERVICE_THREADS)
        .max(1);
    requested
        .min(liveness_cap)
        .min(NATIVE_MINING_BACKGROUND_THREAD_CAP)
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

#[cfg(test)]
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

fn bincode_deserialize_exact_with_limit<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    label: &str,
    max_bytes: usize,
) -> Result<T> {
    if bytes.len() > max_bytes {
        return Err(anyhow!(
            "{label} bytes exceed bincode decode limit: {} > {}",
            bytes.len(),
            max_bytes
        ));
    }
    let mut cursor = Cursor::new(bytes);
    let value: T = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(max_bytes as u64)
        .deserialize_from(&mut cursor)
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

const BINCODE_FIXINT_VEC_LEN_BYTES: usize = 8;
const BINCODE_SERDE_BYTES48_BYTES: usize = BINCODE_FIXINT_VEC_LEN_BYTES + 48;
const NATIVE_BLOCK_META_ACTION_BYTES_OFFSET: usize = 32
    + 32
    + 8
    + 32
    + 32
    + BINCODE_SERDE_BYTES48_BYTES
    + BINCODE_SERDE_BYTES48_BYTES
    + BINCODE_SERDE_BYTES48_BYTES
    + 32
    + BINCODE_SERDE_BYTES48_BYTES
    + 4
    + 32
    + 8
    + 8
    + 4
    + 32
    + 32
    + BINCODE_SERDE_BYTES48_BYTES
    + 16
    + 4;

fn bincode_deserialize_native_block_meta_exact(
    bytes: &[u8],
    label: &str,
) -> Result<NativeBlockMeta> {
    validate_native_block_meta_bincode_budget(bytes, label)?;
    match bincode_deserialize_exact_with_limit::<NativeBlockMeta>(
        bytes,
        label,
        MAX_NATIVE_BLOCK_META_BYTES,
    ) {
        Ok(meta) => Ok(meta),
        Err(current_error) => {
            match bincode_deserialize_exact_with_limit::<LegacyNativeBlockMetaV1>(
                bytes,
                &format!("legacy {label}"),
                MAX_NATIVE_BLOCK_META_BYTES,
            ) {
                Ok(meta) => Ok(meta.into()),
                Err(legacy_error) => Err(anyhow!(
                    "{label} did not decode as current or legacy native metadata: current={current_error}; legacy={legacy_error}"
                )),
            }
        }
    }
}

fn validate_native_block_meta_bincode_budget(bytes: &[u8], label: &str) -> Result<()> {
    validate_native_block_meta_bincode_budget_with_total_limit(
        bytes,
        label,
        MAX_NATIVE_BLOCK_META_BYTES,
    )
}

fn validate_native_block_meta_bincode_budget_with_total_limit(
    bytes: &[u8],
    label: &str,
    max_total_bytes: usize,
) -> Result<()> {
    if bytes.len() > max_total_bytes {
        return Err(anyhow!(
            "{label} bytes exceed native block metadata limit: {} > {}",
            bytes.len(),
            max_total_bytes
        ));
    }
    let Some(action_count) = read_bincode_fixint_len(bytes, NATIVE_BLOCK_META_ACTION_BYTES_OFFSET)?
    else {
        return Ok(());
    };
    if action_count > MAX_NATIVE_BLOCK_ACTIONS {
        return Err(anyhow!(
            "{label} action byte count exceeds limit before bincode decode: {} > {}",
            action_count,
            MAX_NATIVE_BLOCK_ACTIONS
        ));
    }

    let mut cursor = NATIVE_BLOCK_META_ACTION_BYTES_OFFSET + BINCODE_FIXINT_VEC_LEN_BYTES;
    let mut total_action_bytes = 0usize;
    for index in 0..action_count {
        let Some(action_len) = read_bincode_fixint_len(bytes, cursor)? else {
            return Ok(());
        };
        if action_len > MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES {
            return Err(anyhow!(
                "{label} action payload {index} exceeds limit before bincode decode: {} > {}",
                action_len,
                MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES
            ));
        }
        total_action_bytes = total_action_bytes
            .checked_add(action_len)
            .ok_or_else(|| anyhow!("{label} action byte total overflow before bincode decode"))?;
        if total_action_bytes > MAX_NATIVE_BLOCK_ACTION_BYTES {
            return Err(anyhow!(
                "{label} action bytes exceed aggregate limit before bincode decode: {} > {}",
                total_action_bytes,
                MAX_NATIVE_BLOCK_ACTION_BYTES
            ));
        }
        cursor = cursor
            .checked_add(BINCODE_FIXINT_VEC_LEN_BYTES)
            .and_then(|next| next.checked_add(action_len))
            .ok_or_else(|| anyhow!("{label} bincode action-byte cursor overflow"))?;
        if cursor > bytes.len() {
            return Ok(());
        }
    }

    let Some(miner_commitment_len) = read_bincode_fixint_len(bytes, cursor)? else {
        return Ok(());
    };
    if miner_commitment_len > 48 {
        return Err(anyhow!(
            "{label} miner commitment exceeds limit before bincode decode: {} > 48",
            miner_commitment_len
        ));
    }
    let Some(miner_cursor) = cursor
        .checked_add(BINCODE_FIXINT_VEC_LEN_BYTES)
        .and_then(|next| next.checked_add(miner_commitment_len))
    else {
        return Err(anyhow!("{label} bincode miner-field cursor overflow"));
    };
    if miner_cursor > bytes.len() {
        return Ok(());
    }
    let Some(miner_public_key_len) = read_bincode_fixint_len(bytes, miner_cursor)? else {
        return Ok(());
    };
    if miner_public_key_len > ML_DSA_PUBLIC_KEY_LEN {
        return Err(anyhow!(
            "{label} miner public key exceeds limit before bincode decode: {} > {}",
            miner_public_key_len,
            ML_DSA_PUBLIC_KEY_LEN
        ));
    }
    let Some(after_public_key_len) = miner_cursor.checked_add(BINCODE_FIXINT_VEC_LEN_BYTES) else {
        return Err(anyhow!("{label} bincode miner public-key cursor overflow"));
    };
    let Some(signature_cursor) = after_public_key_len.checked_add(miner_public_key_len) else {
        return Err(anyhow!(
            "{label} bincode miner public-key payload cursor overflow"
        ));
    };
    if signature_cursor > bytes.len() {
        return Ok(());
    }
    let Some(miner_signature_len) = read_bincode_fixint_len(bytes, signature_cursor)? else {
        return Ok(());
    };
    if miner_signature_len > ML_DSA_SIGNATURE_LEN {
        return Err(anyhow!(
            "{label} miner signature exceeds limit before bincode decode: {} > {}",
            miner_signature_len,
            ML_DSA_SIGNATURE_LEN
        ));
    }
    Ok(())
}

fn read_bincode_fixint_len(bytes: &[u8], offset: usize) -> Result<Option<usize>> {
    let Some(end) = offset.checked_add(BINCODE_FIXINT_VEC_LEN_BYTES) else {
        return Err(anyhow!("bincode length cursor overflow"));
    };
    if end > bytes.len() {
        return Ok(None);
    }
    let mut raw = [0u8; BINCODE_FIXINT_VEC_LEN_BYTES];
    raw.copy_from_slice(&bytes[offset..end]);
    usize::try_from(u64::from_le_bytes(raw))
        .map(Some)
        .map_err(|_| anyhow!("bincode length does not fit usize"))
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

fn json_response(node: &NativeNode, status: StatusCode, body: Value) -> Response {
    with_cors(node, (status, Json(body)).into_response())
}

fn with_cors(node: &NativeNode, mut response: Response) -> Response {
    let headers = response.headers_mut();
    if let Some(origin) = rpc_cors_origin(node) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("POST, GET, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("content-type, authorization"),
        );
        headers.insert(header::VARY, HeaderValue::from_static("origin"));
    }
    response
}

fn rpc_cors_origin(node: &NativeNode) -> Option<HeaderValue> {
    let cors = node.config.rpc_cors.as_deref()?.trim();
    if cors.is_empty() {
        return None;
    }
    if cors == "*" && node.rpc_policy().ok() == Some(RpcMethodPolicy::Unsafe) {
        warn!("ignoring wildcard RPC CORS while unsafe RPC methods are enabled");
        return None;
    }
    HeaderValue::from_str(cors).ok()
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

fn system_peers_snapshot(node: &NativeNode) -> Value {
    Value::Array(
        node.network_peer_snapshot()
            .into_iter()
            .map(|peer| {
                json!({
                    "peerId": hex32(&peer.peer_id),
                    "roles": "FULL",
                    "protocolVersion": 10u32,
                    "bestHash": null,
                    "bestNumber": null,
                    "endpoint": peer.addr.to_string(),
                    "connected": true,
                })
            })
            .collect(),
    )
}

fn hegemon_peer_list_snapshot(node: &NativeNode) -> Value {
    Value::Array(
        node.network_peer_snapshot()
            .into_iter()
            .map(|peer| {
                json!({
                    "peer_id": hex32(&peer.peer_id),
                    "addr": peer.addr.to_string(),
                    "connected": true,
                    "protocols": [NATIVE_SYNC_PROTOCOL_ID],
                })
            })
            .collect(),
    )
}

fn hegemon_peer_graph_snapshot(node: &NativeNode) -> Value {
    let local_peer_id = node.network_local_peer_id().map(|peer_id| hex32(&peer_id));
    let peers = node.network_peer_snapshot();
    let peer_rows: Vec<Value> = peers
        .iter()
        .map(|peer| {
            json!({
                "peer_id": hex32(&peer.peer_id),
                "addr": peer.addr.to_string(),
                "connected": true,
            })
        })
        .collect();
    let links: Vec<Value> = peers
        .iter()
        .map(|peer| {
            json!({
                "from": local_peer_id.clone().unwrap_or_default(),
                "to": hex32(&peer.peer_id),
                "addr": peer.addr.to_string(),
            })
        })
        .collect();

    json!({
        "local_peer_id": local_peer_id.unwrap_or_default(),
        "peers": peer_rows,
        "links": links,
        "reports": [],
    })
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
    let signal = wait_for_native_shutdown_signal().await;
    info!(signal, "native Hegemon node shutdown signal received");
    node.stop_mining();
    if let Err(err) = flush_native_db_durability_barrier(
        &node.db,
        "native shutdown flush",
        NativeStorageDurabilityOperation::ShutdownFlush,
    ) {
        warn!(error = %err, "failed to flush native db during shutdown");
    }
    record_native_shutdown_complete();
}

fn record_native_shutdown_complete() {
    info!("native Hegemon node shutdown complete");
}

#[cfg(unix)]
async fn wait_for_native_shutdown_signal() -> &'static str {
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(signal) => signal,
        Err(err) => {
            warn!(error = %err, "failed to install SIGTERM handler; falling back to Ctrl-C");
            let _ = tokio::signal::ctrl_c().await;
            return "ctrl_c";
        }
    };

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(err) = result {
                warn!(error = %err, "failed while waiting for Ctrl-C shutdown signal");
            }
            "ctrl_c"
        }
        _ = sigterm.recv() => "sigterm",
    }
}

#[cfg(not(unix))]
async fn wait_for_native_shutdown_signal() -> &'static str {
    if let Err(err) = tokio::signal::ctrl_c().await {
        warn!(error = %err, "failed while waiting for Ctrl-C shutdown signal");
    }
    "ctrl_c"
}

#[cfg(test)]
mod tests;
