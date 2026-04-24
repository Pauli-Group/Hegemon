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
use network::{
    service::DirectedProtocolMessage, GossipRouter, NatTraversalConfig, P2PService, PeerId,
    PeerIdentity, PeerStore, PeerStoreConfig, ProtocolHandle, ProtocolId, ProtocolMessage,
    RelayConfig,
};
use num_bigint::BigUint;
use parking_lot::{Mutex, RwLock};
use protocol_kernel::types::KernelVersionBinding;
use protocol_shielded_pool::family::{
    MintCoinbaseArgs, ShieldedTransferInlineArgs, ShieldedTransferSidecarArgs,
    SubmitCandidateArtifactArgs, ACTION_MINT_COINBASE, ACTION_SHIELDED_TRANSFER_INLINE,
    ACTION_SHIELDED_TRANSFER_SIDECAR, ACTION_SUBMIT_CANDIDATE_ARTIFACT, FAMILY_SHIELDED_POOL,
};
use protocol_shielded_pool::types::{
    BlockProofMode, CandidateArtifact, ProofArtifactKind as PoolProofArtifactKind,
    BLOCK_PROOF_BUNDLE_SCHEMA, MAX_BATCH_SIZE, MAX_CIPHERTEXT_BYTES,
    NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE, RECURSIVE_BLOCK_V1_ARTIFACT_MAX_SIZE,
    RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE,
};
use protocol_shielded_pool::verifier::{ShieldedTransferInputs, StarkVerifier};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
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
const MAX_NATIVE_MEMPOOL_ACTIONS: usize = 10_000;
const NATIVE_SYNC_PROTOCOL_ID: ProtocolId = 0x4847_4e53;
const MAX_NATIVE_SYNC_RESPONSE_BLOCKS: u64 = 512;
const NATIVE_ANNOUNCE_INTERVAL: u64 = 16;
const PQ_IDENTITY_SEED_FILE: &str = "pq-identity.seed";
const PQ_IDENTITY_SEED_LEN: usize = 32;
const MAX_NATIVE_RPC_ACTION_BYTES: usize = 2 * 1024 * 1024;
const MAX_NATIVE_DA_CIPHERTEXT_UPLOADS: usize = 1024;
const MAX_NATIVE_DA_PROOF_UPLOADS: usize = 256;
const MAX_NATIVE_STAGED_CIPHERTEXTS: usize = 100_000;
const MAX_NATIVE_STAGED_PROOFS: usize = 10_000;
const DEFAULT_NATIVE_WALLET_PAGE_LIMIT: u64 = 128;
const MAX_NATIVE_WALLET_PAGE_LIMIT: u64 = 1024;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NativeBlockMeta {
    height: u64,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    state_root: [u8; 48],
    #[serde(with = "serde_array48")]
    nullifier_root: [u8; 48],
    extrinsics_root: [u8; 32],
    timestamp_ms: u64,
    pow_bits: u32,
    nonce: [u8; 32],
    work_hash: [u8; 32],
    #[serde(default)]
    cumulative_work: Vec<u8>,
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
    nullifier_root: [u8; 48],
    extrinsics_root: [u8; 32],
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
    ciphertext_index_tree: sled::Tree,
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
        let ciphertext_index_tree = db.open_tree("shielded_ciphertext_index")?;
        let da_ciphertext_tree = db.open_tree("da_pending_ciphertexts")?;
        let da_proof_tree = db.open_tree("da_pending_proofs")?;

        let best = load_best_or_genesis(&meta_tree, &height_tree, &block_tree, config.pow_bits)?;
        let pending_actions = load_pending_actions(&action_tree)?;
        let nullifiers = load_nullifiers(&nullifier_tree)?;
        let commitment_state = load_commitment_tree(&commitment_tree)?;
        let staged_ciphertexts = load_staged_sizes(&da_ciphertext_tree)?;
        let staged_proofs = load_staged_proofs(&da_proof_tree)?;

        Ok(Arc::new(Self {
            config,
            db,
            meta_tree,
            height_tree,
            block_tree,
            action_tree,
            nullifier_tree,
            commitment_tree,
            ciphertext_index_tree,
            da_ciphertext_tree,
            da_proof_tree,
            state: RwLock::new(NativeState {
                best,
                pending_actions,
                commitment_tree: commitment_state,
                nullifiers,
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
        }))
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

    fn prepare_work(&self) -> NativeWork {
        let state = self.state.read();
        let best = state.best.clone();
        let actions = ordered_pending_actions(&state);
        let (state_root, nullifier_root, extrinsics_root, tx_count) =
            preview_pending_roots(&state, &actions).unwrap_or_else(|err| {
                warn!(error = %err, "failed to preview native pending action roots");
                (
                    best.state_root,
                    best.nullifier_root,
                    empty_extrinsics_root(0),
                    0,
                )
            });
        let timestamp_ms = current_time_ms().max(best.timestamp_ms.saturating_add(1));
        let height = best.height.saturating_add(1);
        let pre_hash = native_pre_hash(
            &best,
            height,
            timestamp_ms,
            self.config.pow_bits,
            &state_root,
            &nullifier_root,
            &extrinsics_root,
        );
        NativeWork {
            height,
            parent_hash: best.hash,
            pre_hash,
            state_root,
            nullifier_root,
            extrinsics_root,
            tx_count,
            timestamp_ms,
            pow_bits: self.config.pow_bits,
        }
    }

    fn import_mined_block(
        &self,
        work: &NativeWork,
        seal: NativeSeal,
    ) -> Result<Option<NativeBlockMeta>> {
        let mut state = self.state.write();
        if state.best.hash != work.parent_hash || state.best.height.saturating_add(1) != work.height
        {
            return Ok(None);
        }

        let actions = if work.tx_count == 0 {
            Vec::new()
        } else {
            ordered_pending_actions(&state)
        };
        if work.tx_count != 0 && actions_extrinsics_root(&actions) != work.extrinsics_root {
            return Ok(None);
        }
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

        let previous_supply = state.best.supply_digest;
        let supply_delta = native_block_supply_delta(&actions, work.height)?;
        let meta = NativeBlockMeta {
            height: work.height,
            hash: seal.work_hash,
            parent_hash: work.parent_hash,
            state_root: work.state_root,
            nullifier_root: work.nullifier_root,
            extrinsics_root: work.extrinsics_root,
            timestamp_ms: work.timestamp_ms,
            pow_bits: work.pow_bits,
            nonce: seal.nonce,
            work_hash: seal.work_hash,
            cumulative_work: cumulative_work_after(&state.best, work.pow_bits)?.to_bytes_be(),
            supply_digest: previous_supply.saturating_add(supply_delta),
            tx_count: work.tx_count,
            action_bytes: actions.iter().map(Encode::encode).collect(),
        };

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

        let parent_state = if parent.hash == state.best.hash {
            NativeState {
                best: state.best.clone(),
                pending_actions: BTreeMap::new(),
                commitment_tree: state.commitment_tree.clone(),
                nullifiers: state.nullifiers.clone(),
                staged_ciphertexts: BTreeMap::new(),
                staged_proofs: BTreeMap::new(),
            }
        } else {
            self.replay_state_to_hash(parent.hash)?
        };
        let actions = decode_block_actions(&meta)?;
        let (state_root, nullifier_root, extrinsics_root, tx_count) =
            preview_pending_roots(&parent_state, &actions)?;
        if tx_count != meta.tx_count {
            return Err(anyhow!("announced block action count mismatch"));
        }
        if state_root != meta.state_root
            || nullifier_root != meta.nullifier_root
            || extrinsics_root != meta.extrinsics_root
        {
            return Err(anyhow!("announced block state transition mismatch"));
        }
        if !actions.is_empty() {
            validate_block_actions_locked(&parent_state, &actions)?;
            validate_coinbase_accounting(&actions, meta.height)?;
            verify_native_block_artifacts_locked(self, &parent_state, &actions)?;
        }
        let expected_supply = parent
            .supply_digest
            .saturating_add(native_block_supply_delta(&actions, meta.height)?);
        if meta.supply_digest != expected_supply {
            return Err(anyhow!("announced block supply digest mismatch"));
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
        let capped_to = to_height
            .min(best_height)
            .min(from_height.saturating_add(MAX_NATIVE_SYNC_RESPONSE_BLOCKS - 1));
        if from_height > capped_to {
            return Ok(Vec::new());
        }
        let mut blocks = Vec::new();
        for height in from_height..=capped_to {
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
        let mut chain = Vec::new();
        let mut cursor = hash;
        loop {
            let meta = self
                .header_by_hash(&cursor)?
                .ok_or_else(|| anyhow!("missing native block {}", hex32(&cursor)))?;
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
            staged_ciphertexts: BTreeMap::new(),
            staged_proofs: BTreeMap::new(),
        };
        for meta in chain.into_iter().skip(1) {
            let actions = decode_block_actions(&meta)?;
            validate_block_actions_locked(&state, &actions)?;
            let (state_root, nullifier_root, extrinsics_root, tx_count) =
                preview_pending_roots(&state, &actions)?;
            if tx_count != meta.tx_count
                || state_root != meta.state_root
                || nullifier_root != meta.nullifier_root
                || extrinsics_root != meta.extrinsics_root
            {
                return Err(anyhow!("native replay state transition mismatch"));
            }
            validate_coinbase_accounting(&actions, meta.height)?;
            let expected_supply = state
                .best
                .supply_digest
                .saturating_add(native_block_supply_delta(&actions, meta.height)?);
            if meta.supply_digest != expected_supply {
                return Err(anyhow!("native replay supply digest mismatch"));
            }
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
        self.ciphertext_index_tree.clear()?;

        for meta in &new_chain {
            self.height_tree
                .insert(height_key(meta.height), meta.hash.as_slice())?;
        }
        rebuild_canonical_indexes(
            &new_chain,
            &self.commitment_tree,
            &self.nullifier_tree,
            &self.ciphertext_index_tree,
        )?;

        let new_action_hashes = action_hashes_from_chain(&new_chain)?;
        let mut pending = state.pending_actions.clone();
        for hash in &new_action_hashes {
            pending.remove(hash);
        }
        for action in orphaned_actions(&old_chain, &new_action_hashes)? {
            if action.action_id == ACTION_SUBMIT_CANDIDATE_ARTIFACT {
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
        self.ciphertext_index_tree.flush()?;

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
        for action in actions {
            let start_index = state.commitment_tree.leaf_count();
            for (offset, commitment) in action.commitments.iter().enumerate() {
                let index = start_index.saturating_add(offset as u64);
                state
                    .commitment_tree
                    .append(*commitment)
                    .map_err(|err| anyhow!("append native commitment failed: {err}"))?;
                self.commitment_tree
                    .insert(index.to_be_bytes(), commitment.as_slice())?;
            }

            for nullifier in &action.nullifiers {
                if !state.nullifiers.insert(*nullifier) {
                    return Err(anyhow!("duplicate nullifier during block import"));
                }
                self.nullifier_tree.insert(nullifier.as_slice(), b"1")?;
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
        self.action_tree.flush()?;
        Ok(())
    }

    fn header_by_hash(&self, hash: &[u8; 32]) -> Result<Option<NativeBlockMeta>> {
        self.block_tree
            .get(hash)?
            .map(|bytes| {
                bincode::deserialize::<NativeBlockMeta>(&bytes).map_err(anyhow::Error::from)
            })
            .transpose()
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

        let chain = self.chain_to_hash(self.best_meta().hash)?;
        let mut entries = Vec::new();
        let mut index = 0u64;
        let end = page.start.saturating_add(page.limit);
        for meta in chain.iter().skip(1) {
            for action in decode_block_actions(meta)? {
                match action.action_id {
                    ACTION_SHIELDED_TRANSFER_INLINE => {
                        let args = ShieldedTransferInlineArgs::decode(&mut &action.public_args[..])
                            .map_err(|err| {
                                anyhow!("decode shielded inline action args failed: {err:?}")
                            })?;
                        for note in &args.ciphertexts {
                            if index >= page.start && index < end {
                                let bytes = encrypted_note_da_bytes(note)?;
                                entries.push(json!({
                                    "index": index,
                                    "ciphertext": base64::engine::general_purpose::STANDARD.encode(bytes),
                                }));
                            }
                            index = index.saturating_add(1);
                        }
                    }
                    ACTION_SHIELDED_TRANSFER_SIDECAR => {
                        let args =
                            ShieldedTransferSidecarArgs::decode(&mut &action.public_args[..])
                                .map_err(|err| {
                                    anyhow!("decode shielded sidecar action args failed: {err:?}")
                                })?;
                        for hash in &args.ciphertext_hashes {
                            if index >= page.start && index < end {
                                let bytes = self
                                    .da_ciphertext_tree
                                    .get(hash.as_slice())?
                                    .ok_or_else(|| {
                                        anyhow!("missing canonical DA ciphertext {}", hex48(hash))
                                    })?;
                                entries.push(json!({
                                    "index": index,
                                    "ciphertext": base64::engine::general_purpose::STANDARD.encode(bytes.as_ref()),
                                }));
                            }
                            index = index.saturating_add(1);
                        }
                    }
                    ACTION_MINT_COINBASE => {
                        let args = MintCoinbaseArgs::decode(&mut &action.public_args[..]).map_err(
                            |err| anyhow!("decode coinbase action args failed: {err:?}"),
                        )?;
                        if index >= page.start && index < end {
                            let bytes = encrypted_note_da_bytes(
                                &args.reward_bundle.miner_note.encrypted_note,
                            )?;
                            entries.push(json!({
                                "index": index,
                                "ciphertext": base64::engine::general_purpose::STANDARD.encode(bytes),
                            }));
                        }
                        index = index.saturating_add(1);
                    }
                    _ => {}
                }
                if index >= end && entries.len() >= page.limit as usize {
                    continue;
                }
            }
        }
        Ok((entries, index))
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
        if request.family_id != FAMILY_SHIELDED_POOL {
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
        let mut pending = match request.action_id {
            ACTION_SHIELDED_TRANSFER_INLINE => {
                let args = ShieldedTransferInlineArgs::decode(&mut &public_args[..])
                    .map_err(|err| anyhow!("decode shielded inline action args failed: {err:?}"))?;
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
            ACTION_SHIELDED_TRANSFER_SIDECAR => {
                let mut args =
                    ShieldedTransferSidecarArgs::decode(&mut &public_args[..]).map_err(|err| {
                        anyhow!("decode shielded sidecar action args failed: {err:?}")
                    })?;
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
            ACTION_SUBMIT_CANDIDATE_ARTIFACT => {
                let args =
                    SubmitCandidateArtifactArgs::decode(&mut &public_args[..]).map_err(|err| {
                        anyhow!("decode candidate artifact action args failed: {err:?}")
                    })?;
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
            ACTION_MINT_COINBASE => {
                let args = MintCoinbaseArgs::decode(&mut &public_args[..])
                    .map_err(|err| anyhow!("decode coinbase action args failed: {err:?}"))?;
                if args.reward_bundle.miner_note.amount == 0 {
                    return Err(anyhow!("coinbase amount must be non-zero"));
                }
                let note = &args.reward_bundle.miner_note.encrypted_note;
                let mut bytes =
                    Vec::with_capacity(note.ciphertext.len() + note.kem_ciphertext.len());
                bytes.extend_from_slice(&note.ciphertext);
                bytes.extend_from_slice(&note.kem_ciphertext);
                PendingAction {
                    tx_hash: [0u8; 32],
                    binding,
                    family_id: request.family_id,
                    action_id: request.action_id,
                    anchor: [0u8; 48],
                    nullifiers: Vec::new(),
                    commitments: vec![args.reward_bundle.miner_note.commitment],
                    ciphertext_hashes: vec![ciphertext_hash_bytes(&bytes)],
                    ciphertext_sizes: vec![u32::try_from(bytes.len()).unwrap_or(u32::MAX)],
                    public_args,
                    fee: 0,
                    candidate_artifact: None,
                    received_ms,
                }
            }
            other => return Err(anyhow!("unsupported native shielded action {other}")),
        };

        self.validate_action_state(&pending)?;
        pending.tx_hash = pending_action_hash(&pending);

        {
            let mut state = self.state.write();
            if state.pending_actions.len() >= MAX_NATIVE_MEMPOOL_ACTIONS {
                return Err(anyhow!("native mempool full"));
            }
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
        if action.action_id == ACTION_SUBMIT_CANDIDATE_ARTIFACT {
            return Ok(());
        }
        if action.action_id == ACTION_MINT_COINBASE {
            if action.commitments.len() != 1
                || action.ciphertext_hashes.len() != 1
                || action.ciphertext_sizes.len() != 1
            {
                return Err(anyhow!("coinbase action must contain one output"));
            }
            let args = MintCoinbaseArgs::decode(&mut &action.public_args[..])
                .map_err(|err| anyhow!("decode coinbase action args failed: {err:?}"))?;
            if args.reward_bundle.miner_note.amount == 0 {
                return Err(anyhow!("coinbase amount must be non-zero"));
            }
            if args.reward_bundle.miner_note.commitment != action.commitments[0] {
                return Err(anyhow!("coinbase commitment mismatch"));
            }
            if action.commitments[0] == [0u8; 48] {
                return Err(anyhow!("zero coinbase commitment rejected"));
            }
            return Ok(());
        }

        validate_transfer_action_payload(action)?;

        let state = self.state.read();
        if !state.commitment_tree.contains_root(&action.anchor) {
            return Err(anyhow!("unknown shielded anchor"));
        }

        let mut seen = BTreeSet::new();
        for nullifier in &action.nullifiers {
            if *nullifier == [0u8; 48] {
                return Err(anyhow!("zero nullifier rejected"));
            }
            if !seen.insert(*nullifier) {
                return Err(anyhow!("duplicate nullifier in action"));
            }
            if state.nullifiers.contains(nullifier) {
                return Err(anyhow!("nullifier already spent"));
            }
            if state
                .pending_actions
                .values()
                .any(|pending| pending.nullifiers.contains(nullifier))
            {
                return Err(anyhow!("nullifier already pending"));
            }
        }

        for commitment in &action.commitments {
            if *commitment == [0u8; 48] {
                return Err(anyhow!("zero commitment rejected"));
            }
        }

        if action.action_id == ACTION_SHIELDED_TRANSFER_SIDECAR {
            for (idx, hash) in action.ciphertext_hashes.iter().enumerate() {
                let observed = state
                    .staged_ciphertexts
                    .get(&hex48(hash))
                    .copied()
                    .ok_or_else(|| anyhow!("missing staged ciphertext {}", hex48(hash)))?;
                let expected = action
                    .ciphertext_sizes
                    .get(idx)
                    .copied()
                    .ok_or_else(|| anyhow!("missing ciphertext size for {}", hex48(hash)))?;
                if observed != expected {
                    return Err(anyhow!(
                        "staged ciphertext size mismatch for {}: expected {}, observed {}",
                        hex48(hash),
                        expected,
                        observed
                    ));
                }
            }
        }

        Ok(())
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
        if ciphertexts.len() > MAX_NATIVE_DA_CIPHERTEXT_UPLOADS {
            return Err(anyhow!(
                "too many ciphertexts in one request: {} > {}",
                ciphertexts.len(),
                MAX_NATIVE_DA_CIPHERTEXT_UPLOADS
            ));
        }
        let mut results = Vec::with_capacity(ciphertexts.len());
        let mut state = self.state.write();
        for ciphertext in ciphertexts {
            let raw = parse_bytes_value(ciphertext)?;
            if raw.len() > MAX_CIPHERTEXT_BYTES {
                return Err(anyhow!(
                    "ciphertext size {} exceeds limit {}",
                    raw.len(),
                    MAX_CIPHERTEXT_BYTES
                ));
            }
            let hash = ciphertext_hash_bytes(&raw);
            let hash_hex = hex48(&hash);
            if !state.staged_ciphertexts.contains_key(&hash_hex)
                && state.staged_ciphertexts.len() >= MAX_NATIVE_STAGED_CIPHERTEXTS
            {
                return Err(anyhow!(
                    "staged ciphertext capacity reached: {}",
                    MAX_NATIVE_STAGED_CIPHERTEXTS
                ));
            }
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
        if proofs.len() > MAX_NATIVE_DA_PROOF_UPLOADS {
            return Err(anyhow!(
                "too many proofs in one request: {} > {}",
                proofs.len(),
                MAX_NATIVE_DA_PROOF_UPLOADS
            ));
        }
        let mut results = Vec::with_capacity(proofs.len());
        let mut state = self.state.write();
        for item in proofs {
            let binding_hash = item
                .get("binding_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("proof item missing binding_hash"))?
                .to_string();
            let binding_hash_bytes =
                parse_hex64(&binding_hash).ok_or_else(|| anyhow!("invalid binding_hash hex"))?;
            let binding_hash_key = hex64(&binding_hash_bytes);
            let proof = parse_bytes_value(
                item.get("proof")
                    .ok_or_else(|| anyhow!("proof item missing proof"))?,
            )?;
            if proof.is_empty() {
                return Err(anyhow!("proof item proof must be non-empty"));
            }
            if proof.len() > NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE {
                return Err(anyhow!(
                    "proof size {} exceeds native tx-leaf artifact limit {}",
                    proof.len(),
                    NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE
                ));
            }
            let proof_hash = hash48_with_parts(&[b"da-proof-v1", binding_hash.as_bytes(), &proof]);
            let proof_hash_hex = hex48(&proof_hash);
            if !state.staged_proofs.contains_key(&binding_hash_key)
                && state.staged_proofs.len() >= MAX_NATIVE_STAGED_PROOFS
            {
                return Err(anyhow!(
                    "staged proof capacity reached: {}",
                    MAX_NATIVE_STAGED_PROOFS
                ));
            }
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
        let sync_msg = match bincode::deserialize::<NativeSyncMessage>(&msg.payload) {
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
    if announced_height <= best_height {
        return;
    }
    let from_height = best_height.saturating_add(1);
    let to_height = announced_height.min(
        best_height
            .saturating_add(MAX_NATIVE_SYNC_RESPONSE_BLOCKS)
            .max(from_height),
    );
    send_sync_message(
        handle,
        peer_id,
        NativeSyncMessage::Request {
            from_height,
            to_height,
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
    bincode::serialize(message).context("encode native sync message")
}

async fn rpc_handler(State(node): State<Arc<NativeNode>>, Json(payload): Json<Value>) -> Response {
    let response = match payload {
        Value::Array(requests) => {
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
        let mut rows = Vec::new();
        for height in 1..=best.height {
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

fn header_json(meta: &NativeBlockMeta) -> Value {
    json!({
        "parentHash": hex32(&meta.parent_hash),
        "number": format!("0x{:x}", meta.height),
        "stateRoot": hex32(&hash32_with_parts(&[b"native-state-root-view", &meta.state_root])),
        "extrinsicsRoot": hex32(&meta.extrinsics_root),
        "digest": {
            "logs": [],
        },
    })
}

async fn mining_loop(node: Arc<NativeNode>) {
    while node.mining.load(Ordering::SeqCst) {
        let work = node.prepare_work();
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
        return bincode::deserialize(&bytes).context("decode native best metadata");
    }

    let genesis = genesis_meta(pow_bits)?;
    persist_block(meta_tree, height_tree, block_tree, &genesis)?;
    meta_tree.insert(META_GENESIS_KEY, genesis.hash.as_slice())?;
    meta_tree.flush()?;
    Ok(genesis)
}

fn genesis_meta(pow_bits: u32) -> Result<NativeBlockMeta> {
    let state_root = CommitmentTreeState::default().root();
    let nullifier_root = nullifier_root_from_set(&BTreeSet::new());
    let timestamp_ms = 0;
    let extrinsics_root = empty_extrinsics_root(0);
    let hash = hash32_with_parts(&[
        b"hegemon-native-genesis-v1",
        &state_root,
        &nullifier_root,
        &extrinsics_root,
        &pow_bits.to_le_bytes(),
    ]);

    Ok(NativeBlockMeta {
        height: 0,
        hash,
        parent_hash: [0u8; 32],
        state_root,
        nullifier_root,
        extrinsics_root,
        timestamp_ms,
        pow_bits,
        nonce: [0u8; 32],
        work_hash: hash,
        cumulative_work: Vec::new(),
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

fn load_staged_sizes(tree: &sled::Tree) -> Result<BTreeMap<String, u32>> {
    let mut entries = BTreeMap::new();
    for item in tree.iter() {
        let (key, value) = item?;
        if key.len() == 48 {
            let mut hash = [0u8; 48];
            hash.copy_from_slice(&key);
            let size = if value.len() == 4 {
                let mut size = [0u8; 4];
                size.copy_from_slice(&value);
                u32::from_le_bytes(size)
            } else {
                u32::try_from(value.len()).unwrap_or(u32::MAX)
            };
            entries.insert(hex48(&hash), size);
        }
    }
    Ok(entries)
}

fn load_staged_proofs(tree: &sled::Tree) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut entries = BTreeMap::new();
    for item in tree.iter() {
        let (key, value) = item?;
        if key.len() == 64 {
            let mut binding_hash = [0u8; 64];
            binding_hash.copy_from_slice(&key);
            entries.insert(hex64(&binding_hash), value.to_vec());
        }
    }
    Ok(entries)
}

fn load_pending_actions(tree: &sled::Tree) -> Result<BTreeMap<[u8; 32], PendingAction>> {
    let mut actions = BTreeMap::new();
    for item in tree.iter() {
        let (key, value) = item?;
        if key.len() != 32 {
            continue;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&key);
        let action = PendingAction::decode(&mut &value[..])
            .map_err(|err| anyhow!("decode pending action failed: {err:?}"))?;
        actions.insert(hash, action);
    }
    Ok(actions)
}

fn load_nullifiers(tree: &sled::Tree) -> Result<BTreeSet<[u8; 48]>> {
    let mut nullifiers = BTreeSet::new();
    for item in tree.iter() {
        let (key, _) = item?;
        if key.len() == 48 {
            let mut nullifier = [0u8; 48];
            nullifier.copy_from_slice(&key);
            nullifiers.insert(nullifier);
        }
    }
    Ok(nullifiers)
}

fn load_commitment_tree(tree: &sled::Tree) -> Result<CommitmentTreeState> {
    let mut commitments = Vec::new();
    for item in tree.iter() {
        let (_, value) = item?;
        if value.len() == 48 {
            let mut commitment = [0u8; 48];
            commitment.copy_from_slice(&value);
            commitments.push(commitment);
        }
    }
    CommitmentTreeState::from_leaves(
        COMMITMENT_TREE_DEPTH,
        consensus::DEFAULT_ROOT_HISTORY_LIMIT,
        commitments,
    )
    .map_err(|err| anyhow!("rebuild native commitment tree failed: {err}"))
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
    if expected != binding_hash {
        return Err(anyhow!("binding hash mismatch"));
    }
    Ok(())
}

fn validate_transfer_action_payload(action: &PendingAction) -> Result<()> {
    if !is_transfer_action(action.action_id) {
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
            let args = ShieldedTransferInlineArgs::decode(&mut &action.public_args[..])
                .map_err(|err| anyhow!("decode shielded inline action args failed: {err:?}"))?;
            if args.proof.is_empty() {
                return Err(anyhow!("shielded inline transfer missing proof"));
            }
            if args.proof.len() > NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE {
                return Err(anyhow!(
                    "shielded inline proof size {} exceeds native tx-leaf artifact limit {}",
                    args.proof.len(),
                    NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE
                ));
            }
            if args.anchor != action.anchor {
                return Err(anyhow!("shielded inline anchor mismatch"));
            }
            if args.commitments != action.commitments {
                return Err(anyhow!("shielded inline commitments mismatch"));
            }
            let ciphertext_hashes = args
                .ciphertexts
                .iter()
                .map(|note| {
                    let total_len = note
                        .ciphertext
                        .len()
                        .saturating_add(note.kem_ciphertext.len());
                    if total_len > MAX_CIPHERTEXT_BYTES {
                        return Err(anyhow!(
                            "inline ciphertext size {} exceeds limit {}",
                            total_len,
                            MAX_CIPHERTEXT_BYTES
                        ));
                    }
                    let mut bytes = Vec::with_capacity(total_len);
                    bytes.extend_from_slice(&note.ciphertext);
                    bytes.extend_from_slice(&note.kem_ciphertext);
                    Ok(ciphertext_hash_bytes(&bytes))
                })
                .collect::<Result<Vec<_>>>()?;
            let ciphertext_sizes = args
                .ciphertexts
                .iter()
                .map(|note| {
                    u32::try_from(note.ciphertext.len() + note.kem_ciphertext.len())
                        .unwrap_or(u32::MAX)
                })
                .collect::<Vec<_>>();
            if ciphertext_hashes != action.ciphertext_hashes {
                return Err(anyhow!("shielded inline ciphertext hashes mismatch"));
            }
            if ciphertext_sizes != action.ciphertext_sizes {
                return Err(anyhow!("shielded inline ciphertext sizes mismatch"));
            }
            validate_binding_hash(
                args.anchor,
                &action.nullifiers,
                &args.commitments,
                &ciphertext_hashes,
                args.balance_slot_asset_ids,
                args.fee,
                args.binding_hash,
                args.stablecoin,
            )?;
            if args.fee != action.fee {
                return Err(anyhow!("shielded inline fee mismatch"));
            }
        }
        ACTION_SHIELDED_TRANSFER_SIDECAR => {
            let args = ShieldedTransferSidecarArgs::decode(&mut &action.public_args[..])
                .map_err(|err| anyhow!("decode shielded sidecar action args failed: {err:?}"))?;
            if args.proof.is_empty() {
                return Err(anyhow!("shielded sidecar transfer missing proof"));
            }
            if args.proof.len() > NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE {
                return Err(anyhow!(
                    "shielded sidecar proof size {} exceeds native tx-leaf artifact limit {}",
                    args.proof.len(),
                    NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE
                ));
            }
            if args.anchor != action.anchor {
                return Err(anyhow!("shielded sidecar anchor mismatch"));
            }
            if args.commitments != action.commitments {
                return Err(anyhow!("shielded sidecar commitments mismatch"));
            }
            if args.ciphertext_hashes != action.ciphertext_hashes {
                return Err(anyhow!("shielded sidecar ciphertext hashes mismatch"));
            }
            if args.ciphertext_sizes != action.ciphertext_sizes {
                return Err(anyhow!("shielded sidecar ciphertext sizes mismatch"));
            }
            validate_binding_hash(
                args.anchor,
                &action.nullifiers,
                &args.commitments,
                &args.ciphertext_hashes,
                args.balance_slot_asset_ids,
                args.fee,
                args.binding_hash,
                args.stablecoin,
            )?;
            if args.fee != action.fee {
                return Err(anyhow!("shielded sidecar fee mismatch"));
            }
        }
        _ => unreachable!("transfer action checked above"),
    }

    Ok(())
}

fn validate_candidate_artifact(artifact: &CandidateArtifact) -> Result<()> {
    if artifact.version != BLOCK_PROOF_BUNDLE_SCHEMA {
        return Err(anyhow!("candidate artifact schema mismatch"));
    }
    if artifact.tx_count == 0 {
        return Err(anyhow!("candidate artifact tx_count must be non-zero"));
    }
    if artifact.tx_count > MAX_BATCH_SIZE {
        return Err(anyhow!(
            "candidate artifact tx_count {} exceeds max {}",
            artifact.tx_count,
            MAX_BATCH_SIZE
        ));
    }
    if artifact.da_chunk_count == 0 {
        return Err(anyhow!("candidate artifact must declare DA chunks"));
    }
    if artifact.proof_mode != BlockProofMode::RecursiveBlock {
        return Err(anyhow!("native cutover requires recursive block artifacts"));
    }
    if !matches!(
        artifact.proof_kind,
        PoolProofArtifactKind::RecursiveBlockV1 | PoolProofArtifactKind::RecursiveBlockV2
    ) {
        return Err(anyhow!("candidate artifact proof kind is not recursive"));
    }
    if !artifact.commitment_proof.data.is_empty() {
        return Err(anyhow!(
            "recursive candidate artifact must not carry commitment proof bytes"
        ));
    }
    let Some(recursive) = artifact.recursive_block.as_ref() else {
        return Err(anyhow!(
            "candidate artifact missing recursive proof payload"
        ));
    };
    if recursive.proof.data.is_empty() {
        return Err(anyhow!("candidate artifact recursive proof is empty"));
    }
    let max_recursive_bytes = match artifact.proof_kind {
        PoolProofArtifactKind::RecursiveBlockV1 => RECURSIVE_BLOCK_V1_ARTIFACT_MAX_SIZE,
        PoolProofArtifactKind::RecursiveBlockV2 => RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE,
        _ => unreachable!("recursive proof kind checked above"),
    };
    if recursive.proof.data.len() > max_recursive_bytes {
        return Err(anyhow!(
            "candidate artifact recursive proof size {} exceeds {}",
            recursive.proof.data.len(),
            max_recursive_bytes
        ));
    }
    Ok(())
}

fn pending_action_hash(action: &PendingAction) -> [u8; 32] {
    let mut canonical = action.clone();
    canonical.tx_hash = [0u8; 32];
    let encoded = canonical.encode();
    hash32_with_parts(&[b"hegemon-native-action-v1", &encoded])
}

fn ordered_pending_actions(state: &NativeState) -> Vec<PendingAction> {
    let mut actions = state.pending_actions.values().cloned().collect::<Vec<_>>();
    actions.sort_by_key(action_order_key);
    actions
}

fn is_transfer_action(action_id: u16) -> bool {
    matches!(
        action_id,
        ACTION_SHIELDED_TRANSFER_INLINE | ACTION_SHIELDED_TRANSFER_SIDECAR
    )
}

fn action_order_key(action: &PendingAction) -> [u8; 32] {
    let mut preimage = Vec::new();
    match action.action_id {
        ACTION_SHIELDED_TRANSFER_INLINE => {
            if let Ok(args) = ShieldedTransferInlineArgs::decode(&mut &action.public_args[..]) {
                preimage.extend_from_slice(&args.binding_hash);
            }
        }
        ACTION_SHIELDED_TRANSFER_SIDECAR => {
            if let Ok(args) = ShieldedTransferSidecarArgs::decode(&mut &action.public_args[..]) {
                preimage.extend_from_slice(&args.binding_hash);
            }
        }
        _ => {
            preimage.extend_from_slice(b"non-transfer");
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

fn decode_block_actions(meta: &NativeBlockMeta) -> Result<Vec<PendingAction>> {
    if meta.action_bytes.len() != meta.tx_count as usize {
        return Err(anyhow!("block action payload count mismatch"));
    }
    meta.action_bytes
        .iter()
        .map(|bytes| {
            PendingAction::decode(&mut &bytes[..])
                .map_err(|err| anyhow!("decode native block action failed: {err:?}"))
        })
        .collect()
}

fn validate_block_actions_locked(state: &NativeState, actions: &[PendingAction]) -> Result<()> {
    let mut seen_nullifiers = BTreeSet::new();
    let mut seen_actions = BTreeSet::new();
    let mut previous_transfer_key: Option<[u8; 32]> = None;
    for action in actions {
        if action.tx_hash != pending_action_hash(action) {
            return Err(anyhow!("block action hash mismatch"));
        }
        if !seen_actions.insert(action.tx_hash) {
            return Err(anyhow!("duplicate action in block"));
        }
        if action.action_id == ACTION_SUBMIT_CANDIDATE_ARTIFACT {
            let Some(artifact) = action.candidate_artifact.as_ref() else {
                return Err(anyhow!("candidate artifact action missing payload"));
            };
            validate_candidate_artifact(artifact)?;
            continue;
        }
        if action.action_id == ACTION_MINT_COINBASE {
            let args = MintCoinbaseArgs::decode(&mut &action.public_args[..])
                .map_err(|err| anyhow!("decode coinbase action args failed: {err:?}"))?;
            if args.reward_bundle.miner_note.amount == 0 {
                return Err(anyhow!("coinbase amount must be non-zero"));
            }
            if action.commitments.len() != 1
                || action.commitments[0] != args.reward_bundle.miner_note.commitment
            {
                return Err(anyhow!("coinbase commitment mismatch"));
            }
            if action.commitments[0] == [0u8; 48] {
                return Err(anyhow!("zero coinbase commitment rejected"));
            }
            if action.ciphertext_hashes.len() != 1 || action.ciphertext_sizes.len() != 1 {
                return Err(anyhow!("coinbase ciphertext metadata mismatch"));
            }
            continue;
        }
        validate_transfer_action_payload(action)?;
        let transfer_key = action_order_key(action);
        if let Some(previous) = previous_transfer_key {
            if transfer_key < previous {
                return Err(anyhow!(
                    "shielded transfer actions are not in canonical order"
                ));
            }
        }
        previous_transfer_key = Some(transfer_key);
        if !state.commitment_tree.contains_root(&action.anchor) {
            return Err(anyhow!("block action references unknown anchor"));
        }
        for nullifier in &action.nullifiers {
            if *nullifier == [0u8; 48] {
                return Err(anyhow!("zero nullifier in block action"));
            }
            if state.nullifiers.contains(nullifier) || !seen_nullifiers.insert(*nullifier) {
                return Err(anyhow!("duplicate nullifier in block action"));
            }
        }
        for commitment in &action.commitments {
            if *commitment == [0u8; 48] {
                return Err(anyhow!("zero commitment in block action"));
            }
        }
        if action.ciphertext_hashes.len() != action.commitments.len()
            || action.ciphertext_sizes.len() != action.commitments.len()
        {
            return Err(anyhow!("block action ciphertext metadata mismatch"));
        }
    }
    Ok(())
}

fn apply_actions_to_memory(state: &mut NativeState, actions: &[PendingAction]) -> Result<()> {
    for action in actions {
        for commitment in &action.commitments {
            state
                .commitment_tree
                .append(*commitment)
                .map_err(|err| anyhow!("append native commitment failed: {err}"))?;
        }
        for nullifier in &action.nullifiers {
            if !state.nullifiers.insert(*nullifier) {
                return Err(anyhow!("duplicate nullifier during replay"));
            }
        }
        state.pending_actions.remove(&action.tx_hash);
    }
    Ok(())
}

fn rebuild_canonical_indexes(
    chain: &[NativeBlockMeta],
    commitment_tree: &sled::Tree,
    nullifier_tree: &sled::Tree,
    ciphertext_index_tree: &sled::Tree,
) -> Result<()> {
    let mut next_commitment_index = 0u64;
    for meta in chain.iter().skip(1) {
        let actions = decode_block_actions(meta)?;
        for action in actions {
            for commitment in &action.commitments {
                commitment_tree
                    .insert(next_commitment_index.to_be_bytes(), commitment.as_slice())?;
                next_commitment_index = next_commitment_index.saturating_add(1);
            }
            for nullifier in &action.nullifiers {
                nullifier_tree.insert(nullifier.as_slice(), b"1")?;
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
    let coinbase_actions = actions
        .iter()
        .filter(|action| action.action_id == ACTION_MINT_COINBASE)
        .collect::<Vec<_>>();
    if coinbase_actions.len() > 1 {
        return Err(anyhow!("block contains multiple coinbase actions"));
    }
    if let Some(action) = coinbase_actions.first() {
        let expected = expected_coinbase_amount(actions, height)?;
        let observed = coinbase_action_amount(action)?;
        if observed != expected {
            return Err(anyhow!(
                "coinbase amount mismatch: expected {expected}, observed {observed}"
            ));
        }
    }
    Ok(())
}

fn native_block_supply_delta(actions: &[PendingAction], height: u64) -> Result<u128> {
    if actions
        .iter()
        .any(|action| action.action_id == ACTION_MINT_COINBASE)
    {
        return expected_coinbase_amount(actions, height).map(u128::from);
    }
    Ok(0)
}

fn expected_coinbase_amount(actions: &[PendingAction], height: u64) -> Result<u64> {
    let fees = actions
        .iter()
        .filter(|action| {
            matches!(
                action.action_id,
                ACTION_SHIELDED_TRANSFER_INLINE | ACTION_SHIELDED_TRANSFER_SIDECAR
            )
        })
        .try_fold(0u64, |acc, action| {
            acc.checked_add(action.fee)
                .ok_or_else(|| anyhow!("block fee total overflow"))
        })?;
    consensus::reward::block_subsidy(height)
        .checked_add(fees)
        .ok_or_else(|| anyhow!("coinbase reward overflow"))
}

fn coinbase_action_amount(action: &PendingAction) -> Result<u64> {
    let args = MintCoinbaseArgs::decode(&mut &action.public_args[..])
        .map_err(|err| anyhow!("decode coinbase action args failed: {err:?}"))?;
    Ok(args.reward_bundle.miner_note.amount)
}

fn verify_native_block_artifacts_locked(
    node: &NativeNode,
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<()> {
    let transfers = actions
        .iter()
        .filter(|action| {
            matches!(
                action.action_id,
                ACTION_SHIELDED_TRANSFER_INLINE | ACTION_SHIELDED_TRANSFER_SIDECAR
            )
        })
        .collect::<Vec<_>>();
    if transfers.is_empty() {
        return Ok(());
    }

    let matching_artifacts = actions
        .iter()
        .filter_map(|action| action.candidate_artifact.as_ref())
        .filter(|artifact| artifact.tx_count as usize == transfers.len())
        .collect::<Vec<_>>();
    let [artifact] = matching_artifacts.as_slice() else {
        return Err(anyhow!(
            "non-empty shielded block requires exactly one matching recursive candidate artifact"
        ));
    };

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
    if computed_da_root != artifact.da_root {
        return Err(anyhow!("candidate artifact DA root mismatch"));
    }

    let claims = consensus::proof::tx_validity_claims_from_tx_artifacts(&transactions, &artifacts)
        .map_err(|err| anyhow!("native tx artifact verification failed: {err}"))?;
    let tx_statements_commitment = consensus::proof::claim_statement_commitment(&claims)
        .map_err(|err| anyhow!("native tx statement commitment failed: {err}"))?;
    if tx_statements_commitment != artifact.tx_statements_commitment {
        return Err(anyhow!(
            "candidate artifact tx statement commitment mismatch"
        ));
    }

    let expected_tree = preview_commitment_tree(&state.commitment_tree, &transfers)?;
    let mut expected_nullifiers = state.nullifiers.clone();
    for action in &transfers {
        for nullifier in &action.nullifiers {
            expected_nullifiers.insert(*nullifier);
        }
    }
    let expected_nullifier_root = nullifier_root_from_set(&expected_nullifiers);
    let header = consensus::BlockHeader {
        version: 1,
        height: state.best.height.saturating_add(1),
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
    if verified_tree.root() != expected_tree.root() {
        return Err(anyhow!("native recursive block state root mismatch"));
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
    if decoded.tx.nullifiers != action.nullifiers {
        return Err(anyhow!("native tx-leaf nullifiers mismatch"));
    }
    if decoded.tx.commitments != action.commitments {
        return Err(anyhow!("native tx-leaf commitments mismatch"));
    }
    if decoded.tx.ciphertext_hashes != action.ciphertext_hashes {
        return Err(anyhow!("native tx-leaf ciphertext hashes mismatch"));
    }
    let action_version: consensus::VersionBinding = action.binding.into();
    if decoded.tx.version != action_version {
        return Err(anyhow!("native tx-leaf version mismatch"));
    }
    let tx = Transaction::new(
        action.nullifiers.clone(),
        action.commitments.clone(),
        decoded.tx.balance_tag,
        action_version,
        ciphertexts,
    );
    if tx.ciphertext_hashes != action.ciphertext_hashes {
        return Err(anyhow!("native tx ciphertext payload hash mismatch"));
    }
    let artifact = consensus::proof::tx_validity_artifact_from_native_tx_leaf_bytes(proof_bytes)
        .map_err(|err| anyhow!("native tx-leaf artifact build failed: {err}"))?;
    Ok((tx, artifact))
}

fn transfer_proof_and_ciphertexts(
    node: &NativeNode,
    action: &PendingAction,
) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    match action.action_id {
        ACTION_SHIELDED_TRANSFER_INLINE => {
            let args = ShieldedTransferInlineArgs::decode(&mut &action.public_args[..])
                .map_err(|err| anyhow!("decode shielded inline action args failed: {err:?}"))?;
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
            let args = ShieldedTransferSidecarArgs::decode(&mut &action.public_args[..])
                .map_err(|err| anyhow!("decode shielded sidecar action args failed: {err:?}"))?;
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

fn actions_extrinsics_root(actions: &[PendingAction]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hegemon-native-extrinsics-v1");
    hasher.update(&(actions.len() as u32).to_le_bytes());
    for action in actions {
        hasher.update(&action.tx_hash);
    }
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
        .filter(|action| {
            matches!(
                action.action_id,
                ACTION_SHIELDED_TRANSFER_INLINE | ACTION_SHIELDED_TRANSFER_SIDECAR
            )
        })
        .count();
    if transfer_count > 0 {
        let has_matching_recursive_artifact = actions.iter().any(|action| {
            action.action_id == ACTION_SUBMIT_CANDIDATE_ARTIFACT
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

    let mut tree = state.commitment_tree.clone();
    let mut nullifiers = state.nullifiers.clone();
    for action in actions {
        for commitment in &action.commitments {
            tree.append(*commitment)
                .map_err(|err| anyhow!("preview commitment append failed: {err}"))?;
        }
        for nullifier in &action.nullifiers {
            if !nullifiers.insert(*nullifier) {
                return Err(anyhow!("preview duplicate nullifier"));
            }
        }
    }
    Ok((
        tree.root(),
        nullifier_root_from_set(&nullifiers),
        actions_extrinsics_root(actions),
        u32::try_from(actions.len()).unwrap_or(u32::MAX),
    ))
}

fn validate_announced_block(parent: &NativeBlockMeta, meta: &NativeBlockMeta) -> Result<()> {
    if meta.height != parent.height.saturating_add(1) {
        return Err(anyhow!("announced block height is not the next height"));
    }
    if meta.parent_hash != parent.hash {
        return Err(anyhow!("announced block parent does not match local best"));
    }
    if meta.timestamp_ms <= parent.timestamp_ms {
        return Err(anyhow!("announced block timestamp did not advance"));
    }
    let future_limit = current_time_ms().saturating_add(consensus::reward::MAX_FUTURE_SKEW_MS);
    if meta.timestamp_ms > future_limit {
        return Err(anyhow!(
            "announced block timestamp exceeds future skew bound"
        ));
    }
    if meta.pow_bits != parent.pow_bits {
        return Err(anyhow!("native difficulty retargeting is not active yet"));
    }
    let expected_work_pre_hash = native_pre_hash(
        parent,
        meta.height,
        meta.timestamp_ms,
        meta.pow_bits,
        &meta.state_root,
        &meta.nullifier_root,
        &meta.extrinsics_root,
    );
    let expected_work_hash = native_pow_work_hash(&expected_work_pre_hash, meta.nonce);
    if expected_work_hash != meta.work_hash || meta.hash != meta.work_hash {
        return Err(anyhow!("announced block work hash mismatch"));
    }
    if !native_seal_meets_target(&meta.work_hash, meta.pow_bits) {
        return Err(anyhow!("announced block does not meet native PoW target"));
    }
    let expected_work = cumulative_work_after(parent, meta.pow_bits)?;
    if meta.cumulative_work != expected_work.to_bytes_be() {
        return Err(anyhow!("announced block cumulative work mismatch"));
    }
    Ok(())
}

fn native_pre_hash(
    parent: &NativeBlockMeta,
    height: u64,
    timestamp_ms: u64,
    pow_bits: u32,
    state_root: &[u8; 48],
    nullifier_root: &[u8; 48],
    extrinsics_root: &[u8; 32],
) -> [u8; 32] {
    hash32_with_parts(&[
        b"hegemon-native-work-v1",
        &parent.hash,
        &height.to_le_bytes(),
        &timestamp_ms.to_le_bytes(),
        state_root,
        nullifier_root,
        extrinsics_root,
        &pow_bits.to_le_bytes(),
    ])
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
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(pre_hash);
    payload[32..].copy_from_slice(&nonce);
    let first = crypto::hashes::sha256(&payload);
    crypto::hashes::sha256(&first)
}

fn native_seal_meets_target(work_hash: &[u8; 32], pow_bits: u32) -> bool {
    let Some(target) = compact_to_biguint(pow_bits) else {
        return false;
    };
    BigUint::from_bytes_be(work_hash) <= target
}

fn native_meta_better_than(candidate: &NativeBlockMeta, current: &NativeBlockMeta) -> bool {
    let candidate_work = cumulative_work_value(candidate);
    let current_work = cumulative_work_value(current);
    if candidate_work != current_work {
        return candidate_work > current_work;
    }
    if candidate.height != current.height {
        return candidate.height > current.height;
    }
    candidate.hash < current.hash
}

fn cumulative_work_value(meta: &NativeBlockMeta) -> BigUint {
    if meta.cumulative_work.is_empty() {
        return BigUint::from(meta.height)
            * block_work_from_bits(meta.pow_bits).unwrap_or_default();
    }
    BigUint::from_bytes_be(&meta.cumulative_work)
}

fn cumulative_work_after(parent: &NativeBlockMeta, pow_bits: u32) -> Result<BigUint> {
    Ok(cumulative_work_value(parent) + block_work_from_bits(pow_bits)?)
}

fn block_work_from_bits(pow_bits: u32) -> Result<BigUint> {
    let target = compact_to_biguint(pow_bits).ok_or_else(|| anyhow!("invalid native pow bits"))?;
    let max = BigUint::from(1u8) << 256u32;
    Ok(max / (target + BigUint::from(1u8)))
}

fn compact_to_biguint(bits: u32) -> Option<BigUint> {
    let exponent = bits >> 24;
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 {
        return None;
    }
    let mut target = BigUint::from(mantissa);
    if exponent > 3 {
        target <<= 8 * (exponent as usize - 3);
    } else {
        target >>= 8 * (3 - exponent as usize);
    }
    Some(target)
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

fn encoded_len_limit(decoded_len_limit: usize) -> usize {
    decoded_len_limit.saturating_mul(4).saturating_add(2) / 3 + 4
}

fn parse_bytes_value(value: &Value) -> Result<Vec<u8>> {
    let raw = value
        .as_str()
        .ok_or_else(|| anyhow!("expected base64 or 0x-prefixed hex string"))?;
    if let Some(hex) = raw.strip_prefix("0x") {
        return hex::decode(hex).context("decode hex bytes");
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .context("decode base64 bytes")
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
            verifier_profile: [7u8; 48],
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

        let work = node.prepare_work();
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

        let canonical_work = node.prepare_work();
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

        let work = node.prepare_work();
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
        let work = node.prepare_work();
        let seal = mine_native_round(work.clone(), 0).expect("first seal");
        node.import_mined_block(&work, seal)
            .expect("first import")
            .expect("first block");

        stage_test_coinbase(&node, consensus::reward::block_subsidy(2), [22u8; 48]);
        let work = node.prepare_work();
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

        let work = node.prepare_work();
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
        let nullifier_root = parent.nullifier_root;
        let extrinsics_root = actions_extrinsics_root(&[]);
        let pre_hash = native_pre_hash(
            parent,
            height,
            timestamp_ms,
            pow_bits,
            &state_root,
            &nullifier_root,
            &extrinsics_root,
        );
        let work = NativeWork {
            height,
            parent_hash: parent.hash,
            pre_hash,
            state_root,
            nullifier_root,
            extrinsics_root,
            tx_count: 0,
            timestamp_ms,
            pow_bits,
        };
        let seal = mine_native_round(work, round).expect("side seal");
        NativeBlockMeta {
            height,
            hash: seal.work_hash,
            parent_hash: parent.hash,
            state_root,
            nullifier_root,
            extrinsics_root,
            timestamp_ms,
            pow_bits,
            nonce: seal.nonce,
            work_hash: seal.work_hash,
            cumulative_work: cumulative_work_after(parent, pow_bits)
                .expect("cumulative work")
                .to_bytes_be(),
            supply_digest: parent.supply_digest,
            tx_count: 0,
            action_bytes: Vec::new(),
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
