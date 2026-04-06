//! Hegemon Substrate Node Service
//!
//! This module provides the core service implementation for the Substrate-based
//! Hegemon node, including:
//! - Partial node components setup with full Substrate client
//! - Full node service initialization
//! - Block import pipeline configuration with SHA-256d PoW
//! - Mining coordination with ProductionChainStateProvider
//! - PQ-secure network transport
//! - Network bridge for block/tx routing
//!
//! This module now supports full Substrate client integration:
//! - `new_partial_with_client()`: Creates full client with TFullClient
//! - `ProductionChainStateProvider`: Real chain state for mining
//! - Runtime API callbacks for difficulty and block queries
//! - Transaction pool integration with sc-transaction-pool
//! - BlockBuilder API for real state execution
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                          Hegemon Node Service                           │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────────────┐ │
//! │  │ Task Manager │   │   Network    │   │       RPC Server             │ │
//! │  │  - spawner   │   │  - PQ-libp2p │   │  - chain_*    - hegemon_*   │ │
//! │  │  - shutdown  │   │  - ML-KEM    │   │  - author_*   - mining_*    │ │
//! │  └──────────────┘   └──────────────┘   └──────────────────────────────┘ │
//! │         │                  │                        │                   │
//! │         └──────────────────┼────────────────────────┘                   │
//! │                            │                                            │
//! │  ┌─────────────────────────▼─────────────────────────────────────────┐  │
//! │  │                    Block Import Pipeline                          │  │
//! │  │  ┌────────────────┐   ┌──────────────────┐   ┌────────────────┐  │  │
//! │  │  │  Import Queue  │──▶│  SHA-256d PoW    │──▶│    Client      │  │  │
//! │  │  │   (verifier)   │   │  Block Import    │   │   (backend)    │  │  │
//! │  │  └────────────────┘   └──────────────────┘   └────────────────┘  │  │
//! │  └───────────────────────────────────────────────────────────────────┘  │
//! │                            │                                            │
//! │  ┌─────────────────────────▼─────────────────────────────────────────┐  │
//! │  │                    Mining Coordinator                             │  │
//! │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐                           │  │
//! │  │  │Thread 0 │  │Thread 1 │  │Thread N │  ...                      │  │
//! │  │  └─────────┘  └─────────┘  └─────────┘                           │  │
//! │  └───────────────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # PQ Network Layer
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     PQ-Secure Transport Layer                           │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────────────────────────────────────────────────────────┐│
//! │  │                   PqNetworkBackend                                  ││
//! │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐ ││
//! │  │  │  Listener   │  │  Dialer     │  │  SubstratePqTransport       │ ││
//! │  │  │  (inbound)  │  │  (outbound) │  │  (PQ handshake)             │ ││
//! │  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘ ││
//! │  └─────────────────────────────────────────────────────────────────────┘│
//! │  ┌─────────────────────────────────────────────────────────────────────┐│
//! │  │                   PQ Handshake Protocol                             ││
//! │  │  ┌─────────────────────────────────────────────────────────────────┐││
//! │  │  │        ML-KEM-1024 Key Encapsulation (post-quantum)              │││
//! │  │  └─────────────────────────────────────────────────────────────────┘││
//! │  │                                    │                                ││
//! │  │                                    ▼                                ││
//! │  │  ┌─────────────────────────────────────────────────────────────────┐││
//! │  │  │        Session Key = HKDF(ML-KEM_SS)                            │││
//! │  │  └─────────────────────────────────────────────────────────────────┘││
//! │  │                                    │                                ││
//! │  │                                    ▼                                ││
//! │  │  ┌─────────────────────────────────────────────────────────────────┐││
//! │  │  │        ML-DSA-65 Signature Authentication                       │││
//! │  │  └─────────────────────────────────────────────────────────────────┘││
//! │  └─────────────────────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Network Bridge
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         Network Bridge                                   │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │  PqNetworkBackend ──────▶ NetworkBridge ──────▶ Block Import            │
//! │        │                       │                     │                  │
//! │        │                       │                     ▼                  │
//! │        ▼                       ▼               ┌─────────────┐          │
//! │  PqNetworkEvent          Decode/Validate       │   Client    │          │
//! │  ::MessageReceived       Block Announce        └─────────────┘          │
//! │        │                       │                                        │
//! │        │                       ▼                                        │
//! │        │                 Transaction Pool                               │
//! │        │                       │                                        │
//! │        ▼                       ▼                                        │
//! │  Transactions ──────────▶ Submit to Pool                                │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Runtime WASM Integration
//!
//! The runtime provides:
//! - `WASM_BINARY`: Compiled WebAssembly runtime for execution
//! - `DifficultyApi`: Runtime API for querying PoW difficulty
//! - `ConsensusApi`: Runtime API for consensus parameters
//!
//! The node uses the WASM executor to run the runtime in a sandboxed environment,
//! ensuring deterministic execution across all nodes.

use crate::pow::{PowConfig, PowHandle};
use crate::substrate::client::{
    FullBackend, HegemonFullClient, HegemonPowBlockImport, HegemonSelectChain,
    HegemonTransactionPool, ProductionChainStateProvider, ProductionConfig, StateExecutionResult,
    DEFAULT_DIFFICULTY_BITS,
};
use crate::substrate::mining_worker::{
    create_production_mining_worker, create_production_mining_worker_mock_broadcast,
    ChainStateProvider, MinedBlockRecord, MiningWorkerConfig,
};
use crate::substrate::network::{PqNetworkConfig, PqNetworkKeypair};
use crate::substrate::network_bridge::NetworkBridgeBuilder;
use crate::substrate::prover_coordinator::{
    BundleMatchKey, PreparedBundle, ProverCoordinator, ProverCoordinatorConfig,
};
use crate::substrate::rpc::{
    BlockApiServer, BlockRpc, DaApiServer, DaRpc, HegemonApiServer, HegemonRpc, NodeConfigSnapshot,
    ProductionRpcService, ProverApiServer, ProverRpc, ShieldedApiServer, ShieldedRpc,
    WalletApiServer, WalletRpc,
};
use crate::substrate::transaction_pool::{
    SubstrateTransactionPoolWrapper, TransactionPoolBridge, TransactionPoolConfig,
};
use block_circuit::{CommitmentBlockProof, CommitmentBlockProver, CommitmentBlockPublicInputs};
use codec::Decode;
use codec::Encode;
use consensus::proof::{
    tx_validity_artifact_from_native_tx_leaf_bytes, tx_validity_artifact_from_proof, HeaderProofExt,
};
use consensus::{ParallelProofVerifier, Sha256dAlgorithm, Sha256dSeal};
use crypto::hashes::blake3_384;
use futures::{FutureExt, StreamExt};
use hyper::http::{header, Method};
use network::{
    BootstrapNode, PeerId, PqNetworkBackend, PqNetworkBackendConfig, PqNetworkEvent,
    PqNetworkHandle, PqPeerIdentity, PqTransportConfig, SubstratePqTransport,
    SubstratePqTransportConfig,
};
use pallet_shielded_pool::family::ShieldedFamilyAction;
use pallet_shielded_pool::family::{
    build_envelope as build_shielded_kernel_envelope, EnableAggregationModeArgs, MintCoinbaseArgs,
    SubmitCandidateArtifactArgs, ACTION_ENABLE_AGGREGATION_MODE, ACTION_MINT_COINBASE,
    ACTION_SUBMIT_CANDIDATE_ARTIFACT,
};
#[cfg(test)]
use pallet_shielded_pool::family::{ShieldedTransferSidecarArgs, ACTION_SHIELDED_TRANSFER_SIDECAR};
use pallet_shielded_pool::types::{BlockFeeBuckets, DIVERSIFIED_ADDRESS_SIZE};
use rand::{rngs::OsRng, RngCore};
use rayon::ThreadPoolBuilder;
use sc_client_api::{Backend as ClientBackend, BlockBackend, BlockchainEvents, HeaderBackend};
use sc_service::{error::Error as ServiceError, Configuration, KeystoreContainer, TaskManager};
use sc_transaction_pool_api::MaintainedTransactionPool;
use sha2::{Digest as ShaDigest, Sha256};
use sp_api::{ApiExt, Core as CoreRuntimeApi, ProvideRuntimeApi, StorageChanges};
use sp_core::H256;
use sp_database::Transaction as DbTransaction;
use sp_inherents::{InherentData, InherentDataProvider};
use sp_runtime::traits::Header as HeaderT;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use superneo_hegemon::{
    native_receipt_root_build_cache_stats, native_receipt_root_mini_root_size,
    NativeReceiptRootBuildCacheStats,
};
use tokio::sync::{oneshot, Mutex};
use tower_http::cors::{AllowOrigin, CorsLayer};
use url::Url;
use wallet::address::ShieldedAddress;

// Import runtime APIs for difficulty queries
use parking_lot::Mutex as ParkingMutex;
use protocol_versioning::DEFAULT_VERSION_BINDING;
use runtime::apis::{ConsensusApi, ShieldedPoolApi};
use state_da::{DaChunkProof, DaEncoding, DaParams, DaRoot};
use transaction_circuit::constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS, NATIVE_ASSET_ID};
use transaction_circuit::hashing_pq::{bytes48_to_felts, ciphertext_hash_bytes, Felt};
use transaction_circuit::proof::{SerializedStarkInputs, TransactionProof};
use transaction_circuit::public_inputs::{
    BalanceSlot, StablecoinPolicyBinding, TransactionPublicInputs,
};
fn miner_recipient_from_env() -> Option<[u8; DIVERSIFIED_ADDRESS_SIZE]> {
    let address = std::env::var("HEGEMON_MINER_ADDRESS").ok()?;
    let decoded = ShieldedAddress::decode(&address).ok()?;
    let mut out = [0u8; DIVERSIFIED_ADDRESS_SIZE];
    out[0] = decoded.version;
    out[1..5].copy_from_slice(&decoded.diversifier_index.to_le_bytes());
    out[5..37].copy_from_slice(&decoded.pk_recipient);
    out[37..69].copy_from_slice(&decoded.pk_auth);
    Some(out)
}

// Import jsonrpsee for RPC server
use jsonrpsee::server::ServerBuilder;

// Import sync service
use crate::substrate::sync::{ChainSyncService, DownloadedBlock};

#[derive(Clone)]
struct TxPoolEssentialSpawner {
    inner: sc_service::SpawnEssentialTaskHandle,
}

impl TxPoolEssentialSpawner {
    fn new(inner: sc_service::SpawnEssentialTaskHandle) -> Self {
        Self { inner }
    }

    fn wrap_task(
        name: &'static str,
        future: futures::future::BoxFuture<'static, ()>,
    ) -> futures::future::BoxFuture<'static, ()> {
        async move {
            future.await;
            if name == "txpool-background" {
                tracing::debug!(
                    task = name,
                    "Transaction-pool background task returned; awaiting service shutdown"
                );
                futures::future::pending::<()>().await;
            }
        }
        .boxed()
    }
}

impl sp_core::traits::SpawnEssentialNamed for TxPoolEssentialSpawner {
    fn spawn_essential_blocking(
        &self,
        name: &'static str,
        group: Option<&'static str>,
        future: futures::future::BoxFuture<'static, ()>,
    ) {
        self.inner
            .spawn_blocking(name, group, Self::wrap_task(name, future));
    }

    fn spawn_essential(
        &self,
        name: &'static str,
        group: Option<&'static str>,
        future: futures::future::BoxFuture<'static, ()>,
    ) {
        self.inner.spawn(name, group, Self::wrap_task(name, future));
    }
}

// =============================================================================
// Storage Changes Cache
// =============================================================================
//
// This module provides a global cache for storing StorageChanges from block
// building so they can be used during block import. This is necessary because:
// 1. StorageChanges is not Clone, so it can't be returned through callbacks
// 2. We need to persist state alongside block headers during import
// 3. Without this, state is discarded via StateAction::Skip

/// Type alias for storage changes in our runtime
pub type HegemonStorageChanges = StorageChanges<runtime::Block>;

const DEFAULT_STORAGE_CHANGES_CACHE_CAPACITY: usize = 64;

/// Counter for generating unique cache keys
static STORAGE_CHANGES_KEY_COUNTER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

struct StorageChangesCache {
    capacity: usize,
    order: VecDeque<u64>,
    entries: HashMap<u64, HegemonStorageChanges>,
}

impl StorageChangesCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    fn insert(&mut self, key: u64, changes: HegemonStorageChanges) {
        if self.capacity == 0 {
            return;
        }

        if let Some(existing) = self.entries.get_mut(&key) {
            *existing = changes;
            self.order.retain(|entry| entry != &key);
            self.order.push_back(key);
            return;
        }

        while self.entries.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
                tracing::warn!(
                    storage_changes_key = oldest,
                    capacity = self.capacity,
                    "StorageChanges cache full; evicted oldest entry"
                );
            } else {
                break;
            }
        }

        self.entries.insert(key, changes);
        self.order.push_back(key);
    }

    fn take(&mut self, key: u64) -> Option<HegemonStorageChanges> {
        let changes = self.entries.remove(&key);
        if changes.is_some() {
            self.order.retain(|entry| entry != &key);
        }
        changes
    }

    fn discard(&mut self, key: u64) {
        if self.entries.remove(&key).is_some() {
            self.order.retain(|entry| entry != &key);
        }
    }
}

fn load_storage_changes_cache_capacity() -> usize {
    let capacity = env_usize("HEGEMON_STORAGE_CHANGES_CACHE_CAPACITY")
        .unwrap_or(DEFAULT_STORAGE_CHANGES_CACHE_CAPACITY);
    if capacity == 0 {
        return DEFAULT_STORAGE_CHANGES_CACHE_CAPACITY;
    }
    capacity
}

/// When a `BlockTemplate` is discarded (reorg, stale work, local shutdown), this guard ensures we
/// don't leak the cached `StorageChanges`.
#[derive(Debug)]
pub struct StorageChangesGuard {
    key: u64,
}

impl StorageChangesGuard {
    pub fn key(&self) -> u64 {
        self.key
    }
}

impl Drop for StorageChangesGuard {
    fn drop(&mut self) {
        discard_storage_changes(self.key);
    }
}

pub type StorageChangesHandle = Arc<StorageChangesGuard>;

/// Global storage changes cache
///
/// This cache stores StorageChanges indexed by a unique key.
/// The changes are inserted during block building and retrieved during block import.
static STORAGE_CHANGES_CACHE: once_cell::sync::Lazy<ParkingMutex<StorageChangesCache>> =
    once_cell::sync::Lazy::new(|| {
        ParkingMutex::new(StorageChangesCache::new(
            load_storage_changes_cache_capacity(),
        ))
    });

fn discard_storage_changes(key: u64) {
    STORAGE_CHANGES_CACHE.lock().discard(key);
}

/// Store storage changes in the cache and return a handle which cleans up on drop.
pub fn cache_storage_changes(changes: HegemonStorageChanges) -> StorageChangesHandle {
    let key = STORAGE_CHANGES_KEY_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    STORAGE_CHANGES_CACHE.lock().insert(key, changes);
    tracing::debug!(key, "Cached storage changes for block import");
    Arc::new(StorageChangesGuard { key })
}

/// Retrieve and remove storage changes from the cache
pub fn take_storage_changes(key: u64) -> Option<HegemonStorageChanges> {
    let changes = STORAGE_CHANGES_CACHE.lock().take(key);
    if changes.is_some() {
        tracing::debug!(key, "Retrieved storage changes from cache");
    } else {
        tracing::warn!(key, "Storage changes not found in cache");
    }
    changes
}

const DEFAULT_DA_CHUNK_SIZE: u32 = 65536;
const DEFAULT_DA_SAMPLE_COUNT: u32 = 80;
const DEFAULT_DA_STORE_CAPACITY: usize = 128;
const DEFAULT_DA_RETENTION_BLOCKS: u64 = 0;
const DEFAULT_PROOF_DA_RETENTION_BLOCKS: u64 = 0;
const DEFAULT_DA_SAMPLE_TIMEOUT_MS: u64 = 5000;
const DEFAULT_COMMITMENT_PROOF_STORE_CAPACITY: usize = 128;
const DEFAULT_PENDING_CIPHERTEXTS_CAPACITY: usize = 4096;
const DEFAULT_PENDING_PROOFS_CAPACITY: usize = 256;
const CIPHERTEXT_COUNT_KEY: &[u8] = b"ciphertext_count";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DaRootKind {
    Ciphertexts = 0,
}

impl DaRootKind {
    fn byte(self) -> u8 {
        self as u8
    }
}

#[derive(Debug)]
pub struct DaChunkStore {
    cache_capacity: usize,
    ciphertext_retention_blocks: u64,
    proof_retention_blocks: u64,
    cache_order: VecDeque<DaRoot>,
    cache_entries: HashMap<DaRoot, DaEncoding>,
    _db: sled::Db,
    encodings: sled::Tree,
    blocks: sled::Tree,
    block_roots: sled::Tree,
    ciphertexts: sled::Tree,
    ciphertext_ranges: sled::Tree,
    meta: sled::Tree,
}

impl DaChunkStore {
    pub fn open(
        path: &Path,
        cache_capacity: usize,
        ciphertext_retention_blocks: u64,
        proof_retention_blocks: u64,
    ) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        let encodings = db.open_tree("da_encodings")?;
        let blocks = db.open_tree("da_blocks")?;
        let block_roots = db.open_tree("da_block_roots")?;
        let ciphertexts = db.open_tree("da_ciphertexts")?;
        let ciphertext_ranges = db.open_tree("da_ciphertext_ranges")?;
        let meta = db.open_tree("da_meta")?;
        Ok(Self {
            cache_capacity,
            ciphertext_retention_blocks,
            proof_retention_blocks,
            cache_order: VecDeque::new(),
            cache_entries: HashMap::new(),
            _db: db,
            encodings,
            blocks,
            block_roots,
            ciphertexts,
            ciphertext_ranges,
            meta,
        })
    }

    fn insert(
        &mut self,
        kind: DaRootKind,
        block_number: u64,
        block_hash: [u8; 32],
        encoding: DaEncoding,
    ) -> Result<(), sled::Error> {
        let root = encoding.root();
        let encoded = encoding.encode();
        self.encodings.insert(root, encoded)?;
        if matches!(kind, DaRootKind::Ciphertexts) {
            self.block_roots.insert(block_hash, &root[..])?;
        }
        let block_key = da_block_key_with_kind(kind, block_number, &block_hash);
        self.blocks.insert(block_key, &root[..])?;
        self.cache_insert(root, encoding);
        self.prune(block_number)?;
        Ok(())
    }

    pub fn get(&mut self, root: &DaRoot) -> Option<&DaEncoding> {
        if self.cache_entries.contains_key(root) {
            self.cache_touch(*root);
            return self.cache_entries.get(root);
        }

        let bytes = self.encodings.get(root).ok().flatten()?;
        let encoding = match DaEncoding::decode(&mut &bytes[..]) {
            Ok(encoding) => encoding,
            Err(err) => {
                tracing::warn!(
                    da_root = %hex::encode(root),
                    error = %err,
                    "Failed to decode persisted DA encoding"
                );
                return None;
            }
        };
        self.cache_insert(*root, encoding);
        self.cache_entries.get(root)
    }

    pub fn append_ciphertexts(
        &mut self,
        block_number: u64,
        block_hash: [u8; 32],
        ciphertexts: &[Vec<u8>],
    ) -> Result<(), sled::Error> {
        if ciphertexts.is_empty() {
            return Ok(());
        }

        let start_index = self.ciphertext_count()?;
        for (offset, ciphertext) in ciphertexts.iter().enumerate() {
            let index = start_index + offset as u64;
            self.ciphertexts
                .insert(index.to_be_bytes(), ciphertext.as_slice())?;
        }

        let new_count = start_index + ciphertexts.len() as u64;
        self.meta
            .insert(CIPHERTEXT_COUNT_KEY, &new_count.to_be_bytes())?;

        let mut range = [0u8; 16];
        range[..8].copy_from_slice(&start_index.to_be_bytes());
        range[8..].copy_from_slice(&(ciphertexts.len() as u64).to_be_bytes());
        let block_key = da_block_key(block_number, &block_hash);
        self.ciphertext_ranges.insert(block_key, &range[..])?;

        Ok(())
    }

    pub fn ciphertext_slice(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<(u64, Vec<u8>)>, sled::Error> {
        let mut out = Vec::new();
        for item in self.ciphertexts.range(start.to_be_bytes()..) {
            let (key, value) = item?;
            if out.len() >= limit {
                break;
            }
            let index_bytes: [u8; 8] = key
                .as_ref()
                .try_into()
                .map_err(|_| sled::Error::Unsupported("invalid ciphertext key".into()))?;
            let index = u64::from_be_bytes(index_bytes);
            out.push((index, value.to_vec()));
        }
        Ok(out)
    }

    pub fn ciphertext_count(&self) -> Result<u64, sled::Error> {
        match self.meta.get(CIPHERTEXT_COUNT_KEY)? {
            Some(value) => {
                let bytes: [u8; 8] = value
                    .as_ref()
                    .try_into()
                    .map_err(|_| sled::Error::Unsupported("invalid ciphertext count".into()))?;
                Ok(u64::from_be_bytes(bytes))
            }
            None => Ok(0),
        }
    }

    fn cache_insert(&mut self, root: DaRoot, encoding: DaEncoding) {
        if self.cache_capacity == 0 {
            return;
        }

        if let Some(existing) = self.cache_entries.get_mut(&root) {
            *existing = encoding;
            self.cache_touch(root);
            return;
        }

        if self.cache_entries.len() >= self.cache_capacity {
            if let Some(evicted) = self.cache_order.pop_front() {
                self.cache_entries.remove(&evicted);
            }
        }

        self.cache_entries.insert(root, encoding);
        self.cache_order.push_back(root);
    }

    fn cache_touch(&mut self, root: DaRoot) {
        self.cache_order.retain(|entry| entry != &root);
        self.cache_order.push_back(root);
    }

    fn cache_remove(&mut self, root: &DaRoot) {
        self.cache_entries.remove(root);
        self.cache_order.retain(|entry| entry != root);
    }

    fn prune(&mut self, latest_block: u64) -> Result<(), sled::Error> {
        let keep_from_ciphertexts = if self.ciphertext_retention_blocks == 0
            || latest_block < self.ciphertext_retention_blocks
        {
            0
        } else {
            latest_block - (self.ciphertext_retention_blocks - 1)
        };

        let keep_from_proofs =
            if self.proof_retention_blocks == 0 || latest_block < self.proof_retention_blocks {
                0
            } else {
                latest_block - (self.proof_retention_blocks - 1)
            };

        let cutoff = keep_from_ciphertexts.max(keep_from_proofs);
        if cutoff == 0 {
            return Ok(());
        }

        let cutoff_bytes = cutoff.to_be_bytes();
        let mut candidates = Vec::new();
        for item in self.blocks.range(..cutoff_bytes.as_slice()) {
            let (key, value) = item?;
            candidates.push((key, value));
        }

        for (key, value) in candidates {
            if key.len() < 8 {
                self.blocks.remove(key)?;
                continue;
            }

            let mut number_bytes = [0u8; 8];
            number_bytes.copy_from_slice(&key[..8]);
            let block_number = u64::from_be_bytes(number_bytes);

            let kind = key
                .get(40)
                .copied()
                .unwrap_or(DaRootKind::Ciphertexts.byte());
            let keep_from = if kind == DaRootKind::Ciphertexts.byte() {
                keep_from_ciphertexts
            } else {
                keep_from_proofs
            };

            if keep_from == 0 || block_number >= keep_from {
                continue;
            }

            let base_key = if key.len() >= 40 {
                &key[..40]
            } else {
                &key[..]
            };

            if let Some(root) = da_root_from_bytes(&value) {
                self.encodings.remove(root)?;
                self.cache_remove(&root);
            }

            if kind == DaRootKind::Ciphertexts.byte() {
                if key.len() >= 8 + 32 {
                    self.block_roots.remove(&key[8..8 + 32])?;
                }
                if let Some(range) = self.ciphertext_ranges.remove(base_key)? {
                    let bytes = range.as_ref();
                    if bytes.len() == 16 {
                        let mut start_bytes = [0u8; 8];
                        let mut count_bytes = [0u8; 8];
                        start_bytes.copy_from_slice(&bytes[..8]);
                        count_bytes.copy_from_slice(&bytes[8..]);
                        let start = u64::from_be_bytes(start_bytes);
                        let count = u64::from_be_bytes(count_bytes);
                        for index in start..start.saturating_add(count) {
                            self.ciphertexts.remove(index.to_be_bytes())?;
                        }
                    }
                }
            }

            self.blocks.remove(key)?;
        }

        Ok(())
    }
}

fn da_block_key(block_number: u64, block_hash: &[u8; 32]) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..8].copy_from_slice(&block_number.to_be_bytes());
    out[8..].copy_from_slice(block_hash);
    out
}

fn da_block_key_with_kind(kind: DaRootKind, block_number: u64, block_hash: &[u8; 32]) -> [u8; 41] {
    let mut out = [0u8; 41];
    out[..8].copy_from_slice(&block_number.to_be_bytes());
    out[8..40].copy_from_slice(block_hash);
    out[40] = kind.byte();
    out
}

fn da_root_from_bytes(bytes: &[u8]) -> Option<DaRoot> {
    if bytes.len() != 48 {
        return None;
    }
    let mut root = [0u8; 48];
    root.copy_from_slice(bytes);
    Some(root)
}

#[derive(Debug)]
pub struct CommitmentBlockProofStore {
    capacity: usize,
    order: VecDeque<H256>,
    entries: HashMap<H256, CommitmentBlockProof>,
}

impl CommitmentBlockProofStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, hash: H256, proof: CommitmentBlockProof) {
        if self.capacity == 0 {
            return;
        }

        if let Some(existing) = self.entries.get_mut(&hash) {
            *existing = proof;
            self.order.retain(|entry| entry != &hash);
            self.order.push_back(hash);
            return;
        }

        if self.entries.len() >= self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.entries.remove(&evicted);
            }
        }

        self.entries.insert(hash, proof);
        self.order.push_back(hash);
    }

    pub fn get(&self, hash: &H256) -> Option<&CommitmentBlockProof> {
        self.entries.get(hash)
    }
}

#[derive(Debug, Clone)]
pub struct PendingCiphertextStore {
    capacity: usize,
    order: VecDeque<[u8; 48]>,
    entries: HashMap<[u8; 48], Vec<u8>>,
}

impl PendingCiphertextStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, hash: [u8; 48], bytes: Vec<u8>) {
        if self.capacity == 0 {
            return;
        }

        if let Some(existing) = self.entries.get_mut(&hash) {
            *existing = bytes;
            self.order.retain(|entry| entry != &hash);
            self.order.push_back(hash);
            return;
        }

        if self.entries.len() >= self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.entries.remove(&evicted);
            }
        }

        self.entries.insert(hash, bytes);
        self.order.push_back(hash);
    }

    pub fn get_many(&self, hashes: &[[u8; 48]]) -> Result<Vec<Vec<u8>>, String> {
        let mut out = Vec::with_capacity(hashes.len());
        for hash in hashes {
            let bytes = self.entries.get(hash).ok_or_else(|| {
                format!("missing ciphertext bytes for hash {}", hex::encode(hash))
            })?;
            out.push(bytes.clone());
        }
        Ok(out)
    }

    pub fn contains(&self, hash: &[u8; 48]) -> bool {
        self.entries.contains_key(hash)
    }

    pub fn contains_all(&self, hashes: &[[u8; 48]]) -> bool {
        hashes.iter().all(|hash| self.contains(hash))
    }

    pub fn remove_many(&mut self, hashes: &[[u8; 48]]) {
        for hash in hashes {
            self.entries.remove(hash);
            self.order.retain(|entry| entry != hash);
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingProofStore {
    capacity: usize,
    order: VecDeque<[u8; 64]>,
    entries: HashMap<[u8; 64], Vec<u8>>,
}

impl PendingProofStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, binding_hash: [u8; 64], bytes: Vec<u8>) {
        if self.capacity == 0 {
            return;
        }

        if let Some(existing) = self.entries.get_mut(&binding_hash) {
            *existing = bytes;
            self.order.retain(|entry| entry != &binding_hash);
            self.order.push_back(binding_hash);
            return;
        }

        if self.entries.len() >= self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.entries.remove(&evicted);
            }
        }

        self.entries.insert(binding_hash, bytes);
        self.order.push_back(binding_hash);
    }

    pub fn get(&self, binding_hash: &[u8; 64]) -> Option<&Vec<u8>> {
        self.entries.get(binding_hash)
    }

    pub fn contains(&self, binding_hash: &[u8; 64]) -> bool {
        self.entries.contains_key(binding_hash)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get_many(&self, binding_hashes: &[[u8; 64]]) -> Result<Vec<Vec<u8>>, String> {
        let mut out = Vec::with_capacity(binding_hashes.len());
        for binding_hash in binding_hashes {
            let bytes = self.entries.get(binding_hash).ok_or_else(|| {
                format!(
                    "missing proof bytes for binding hash {}",
                    hex::encode(binding_hash)
                )
            })?;
            out.push(bytes.clone());
        }
        Ok(out)
    }

    pub fn remove_many(&mut self, binding_hashes: &[[u8; 64]]) {
        for binding_hash in binding_hashes {
            self.entries.remove(binding_hash);
            self.order.retain(|entry| entry != binding_hash);
        }
    }
}

#[derive(Debug, Default)]
struct DaRequestTracker {
    pending: HashMap<(DaRoot, u32), oneshot::Sender<Option<DaChunkProof>>>,
}

impl DaRequestTracker {
    fn register(
        &mut self,
        root: DaRoot,
        indices: &[u32],
    ) -> Vec<oneshot::Receiver<Option<DaChunkProof>>> {
        let mut receivers = Vec::with_capacity(indices.len());
        for &index in indices {
            let (tx, rx) = oneshot::channel();
            self.pending.insert((root, index), tx);
            receivers.push(rx);
        }
        receivers
    }

    fn fulfill_proofs(&mut self, root: DaRoot, proofs: Vec<DaChunkProof>) {
        for proof in proofs {
            if let Some(tx) = self.pending.remove(&(root, proof.chunk.index)) {
                let _ = tx.send(Some(proof));
            }
        }
    }

    fn fulfill_not_found(&mut self, root: DaRoot, indices: Vec<u32>) {
        for index in indices {
            if let Some(tx) = self.pending.remove(&(root, index)) {
                let _ = tx.send(None);
            }
        }
    }

    fn cancel(&mut self, root: DaRoot, indices: &[u32]) {
        for &index in indices {
            self.pending.remove(&(root, index));
        }
    }
}

fn env_u32(name: &str) -> Option<u32> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
}

fn env_usize(name: &str) -> Option<usize> {
    env_u64(name).and_then(|value| usize::try_from(value).ok())
}

fn proof_verification_enabled() -> bool {
    let env_value = std::env::var("HEGEMON_PARALLEL_PROOF_VERIFICATION").ok();
    if cfg!(feature = "production") {
        if let Some(value) = env_value {
            if value == "0" || value.eq_ignore_ascii_case("false") {
                tracing::warn!(
                    "HEGEMON_PARALLEL_PROOF_VERIFICATION disabled but production builds require proof verification; ignoring"
                );
            }
        }
        true
    } else {
        env_value
            .map(|value| value != "0" && !value.eq_ignore_ascii_case("false"))
            .unwrap_or(true)
    }
}

fn chain_property_u32(properties: &sc_chain_spec::Properties, key: &str) -> Option<u32> {
    properties.get(key).and_then(|value| {
        value
            .as_u64()
            .and_then(|num| u32::try_from(num).ok())
            .or_else(|| value.as_str().and_then(|num| num.parse::<u32>().ok()))
    })
}

fn load_da_params(properties: &sc_chain_spec::Properties) -> DaParams {
    let mut chunk_size = env_u32("HEGEMON_DA_CHUNK_SIZE")
        .or_else(|| chain_property_u32(properties, "daChunkSize"))
        .unwrap_or(DEFAULT_DA_CHUNK_SIZE);
    if chunk_size == 0 {
        tracing::warn!(
            "HEGEMON_DA_CHUNK_SIZE is zero; falling back to {}",
            DEFAULT_DA_CHUNK_SIZE
        );
        chunk_size = DEFAULT_DA_CHUNK_SIZE;
    }

    let mut sample_count = env_u32("HEGEMON_DA_SAMPLE_COUNT")
        .or_else(|| chain_property_u32(properties, "daSampleCount"))
        .unwrap_or(DEFAULT_DA_SAMPLE_COUNT);
    if sample_count == 0 {
        tracing::warn!(
            "HEGEMON_DA_SAMPLE_COUNT is zero; falling back to {}",
            DEFAULT_DA_SAMPLE_COUNT
        );
        sample_count = DEFAULT_DA_SAMPLE_COUNT;
    }

    DaParams {
        chunk_size,
        sample_count,
    }
}

fn load_da_store_capacity() -> usize {
    let capacity = env_usize("HEGEMON_DA_STORE_CAPACITY").unwrap_or(DEFAULT_DA_STORE_CAPACITY);
    if capacity == 0 {
        tracing::warn!(
            "HEGEMON_DA_STORE_CAPACITY is zero; falling back to {}",
            DEFAULT_DA_STORE_CAPACITY
        );
        return DEFAULT_DA_STORE_CAPACITY;
    }
    capacity
}

fn load_ciphertext_da_retention_blocks() -> u64 {
    let retention = env_u64("HEGEMON_CIPHERTEXT_DA_RETENTION_BLOCKS")
        .or_else(|| env_u64("HEGEMON_DA_RETENTION_BLOCKS"))
        .unwrap_or(DEFAULT_DA_RETENTION_BLOCKS);
    if retention == 0 {
        tracing::info!("Ciphertext DA retention disabled; keeping all ciphertexts");
    }
    retention
}

fn load_proof_da_retention_blocks() -> u64 {
    let retention =
        env_u64("HEGEMON_PROOF_DA_RETENTION_BLOCKS").unwrap_or(DEFAULT_PROOF_DA_RETENTION_BLOCKS);
    if retention == 0 {
        tracing::info!("Proof DA retention disabled; keeping all proof DA blobs");
    }
    retention
}

fn load_commitment_proof_store_capacity() -> usize {
    let capacity = env_usize("HEGEMON_COMMITMENT_PROOF_STORE_CAPACITY")
        .unwrap_or(DEFAULT_COMMITMENT_PROOF_STORE_CAPACITY);
    if capacity == 0 {
        tracing::warn!(
            "HEGEMON_COMMITMENT_PROOF_STORE_CAPACITY is zero; falling back to {}",
            DEFAULT_COMMITMENT_PROOF_STORE_CAPACITY
        );
        return DEFAULT_COMMITMENT_PROOF_STORE_CAPACITY;
    }
    capacity
}

fn load_pending_ciphertext_capacity() -> usize {
    let capacity = env_usize("HEGEMON_PENDING_CIPHERTEXTS_CAPACITY")
        .unwrap_or(DEFAULT_PENDING_CIPHERTEXTS_CAPACITY);
    if capacity == 0 {
        tracing::warn!(
            "HEGEMON_PENDING_CIPHERTEXTS_CAPACITY is zero; falling back to {}",
            DEFAULT_PENDING_CIPHERTEXTS_CAPACITY
        );
        return DEFAULT_PENDING_CIPHERTEXTS_CAPACITY;
    }
    capacity
}

fn load_pending_proof_capacity() -> usize {
    let capacity =
        env_usize("HEGEMON_PENDING_PROOFS_CAPACITY").unwrap_or(DEFAULT_PENDING_PROOFS_CAPACITY);
    if capacity == 0 {
        tracing::warn!(
            "HEGEMON_PENDING_PROOFS_CAPACITY is zero; falling back to {}",
            DEFAULT_PENDING_PROOFS_CAPACITY
        );
        return DEFAULT_PENDING_PROOFS_CAPACITY;
    }
    capacity
}

fn fetch_da_policy(
    client: &HegemonFullClient,
    at_hash: H256,
) -> pallet_shielded_pool::types::DaAvailabilityPolicy {
    let api = client.runtime_api();
    api.da_policy(at_hash)
        .unwrap_or(pallet_shielded_pool::types::DaAvailabilityPolicy::FullFetch)
}

fn fetch_proof_availability_policy(
    client: &HegemonFullClient,
    at_hash: H256,
) -> Result<pallet_shielded_pool::types::ProofAvailabilityPolicy, String> {
    let api = client.runtime_api();
    api.proof_availability_policy(at_hash)
        .map_err(|e| format!("runtime api error (proof_availability_policy): {e:?}"))
}

fn load_da_sample_timeout() -> Duration {
    let timeout_ms =
        env_u64("HEGEMON_DA_SAMPLE_TIMEOUT_MS").unwrap_or(DEFAULT_DA_SAMPLE_TIMEOUT_MS);
    if timeout_ms == 0 {
        tracing::warn!(
            "HEGEMON_DA_SAMPLE_TIMEOUT_MS is zero; falling back to {}",
            DEFAULT_DA_SAMPLE_TIMEOUT_MS
        );
        return Duration::from_millis(DEFAULT_DA_SAMPLE_TIMEOUT_MS);
    }
    Duration::from_millis(timeout_ms)
}

fn signed_parts_u64(value: i128) -> Result<(u8, u64), String> {
    let magnitude = value.unsigned_abs();
    let magnitude_u64 = u64::try_from(magnitude)
        .map_err(|_| format!("value magnitude out of range: {}", magnitude))?;
    let sign = if value < 0 { 1 } else { 0 };
    Ok((sign, magnitude_u64))
}

fn pad_commitments(
    mut values: Vec<[u8; 48]>,
    max: usize,
    label: &str,
) -> Result<Vec<[u8; 48]>, String> {
    if values.len() > max {
        return Err(format!(
            "{label} exceeds max (got {}, max {})",
            values.len(),
            max
        ));
    }
    values.resize(max, [0u8; 48]);
    Ok(values)
}

fn convert_stablecoin_binding(
    binding: &pallet_shielded_pool::types::StablecoinPolicyBinding,
) -> StablecoinPolicyBinding {
    StablecoinPolicyBinding {
        enabled: true,
        asset_id: binding.asset_id,
        policy_hash: binding.policy_hash,
        oracle_commitment: binding.oracle_commitment,
        attestation_commitment: binding.attestation_commitment,
        issuance_delta: binding.issuance_delta,
        policy_version: binding.policy_version,
    }
}

fn build_stark_inputs(
    input_count: usize,
    output_count: usize,
    anchor: [u8; 48],
    balance_slot_asset_ids: [u64; BALANCE_SLOTS],
    fee: u64,
    value_balance: i128,
    stablecoin: Option<&StablecoinPolicyBinding>,
) -> Result<SerializedStarkInputs, String> {
    if input_count > MAX_INPUTS || output_count > MAX_OUTPUTS {
        return Err(format!(
            "input/output count out of range (inputs {}, outputs {})",
            input_count, output_count
        ));
    }

    let mut input_flags = Vec::with_capacity(MAX_INPUTS);
    input_flags.extend(std::iter::repeat_n(1u8, input_count));
    input_flags.extend(std::iter::repeat_n(0u8, MAX_INPUTS - input_count));

    let mut output_flags = Vec::with_capacity(MAX_OUTPUTS);
    output_flags.extend(std::iter::repeat_n(1u8, output_count));
    output_flags.extend(std::iter::repeat_n(0u8, MAX_OUTPUTS - output_count));

    let (value_balance_sign, value_balance_magnitude) = signed_parts_u64(value_balance)?;

    let (
        stablecoin_enabled,
        stablecoin_asset_id,
        stablecoin_policy_version,
        stablecoin_issuance_sign,
        stablecoin_issuance_magnitude,
        stablecoin_policy_hash,
        stablecoin_oracle_commitment,
        stablecoin_attestation_commitment,
    ) = match stablecoin {
        Some(binding) if binding.enabled => {
            let (issuance_sign, issuance_magnitude) = signed_parts_u64(binding.issuance_delta)?;
            (
                1,
                binding.asset_id,
                binding.policy_version,
                issuance_sign,
                issuance_magnitude,
                binding.policy_hash,
                binding.oracle_commitment,
                binding.attestation_commitment,
            )
        }
        _ => (0, 0, 0, 0, 0, [0u8; 48], [0u8; 48], [0u8; 48]),
    };

    Ok(SerializedStarkInputs {
        input_flags,
        output_flags,
        fee,
        value_balance_sign,
        value_balance_magnitude,
        merkle_root: anchor,
        balance_slot_asset_ids: balance_slot_asset_ids.to_vec(),
        stablecoin_enabled,
        stablecoin_asset_id,
        stablecoin_policy_version,
        stablecoin_issuance_sign,
        stablecoin_issuance_magnitude,
        stablecoin_policy_hash,
        stablecoin_oracle_commitment,
        stablecoin_attestation_commitment,
    })
}

fn canonical_balance_slots(
    balance_slot_asset_ids: [u64; BALANCE_SLOTS],
    fee: u64,
    value_balance: i128,
    stablecoin: &StablecoinPolicyBinding,
) -> Result<Vec<BalanceSlot>, String> {
    if balance_slot_asset_ids[0] != NATIVE_ASSET_ID {
        return Err("balance slot 0 must be the native asset".to_string());
    }

    let mut saw_padding = false;
    let mut prev_asset = NATIVE_ASSET_ID;
    for asset_id in balance_slot_asset_ids.iter().skip(1) {
        if *asset_id == u64::MAX {
            saw_padding = true;
            continue;
        }
        if saw_padding {
            return Err("balance slot asset ids must place padding at the end".to_string());
        }
        if *asset_id == NATIVE_ASSET_ID || *asset_id <= prev_asset {
            return Err(
                "balance slot asset ids must be strictly increasing after slot 0".to_string(),
            );
        }
        prev_asset = *asset_id;
    }

    if stablecoin.enabled && !balance_slot_asset_ids[1..].contains(&stablecoin.asset_id) {
        return Err("stablecoin asset must appear in a non-native balance slot".to_string());
    }

    let native_delta = i128::from(fee) - value_balance;
    Ok(balance_slot_asset_ids
        .into_iter()
        .map(|asset_id| {
            let delta = if asset_id == NATIVE_ASSET_ID {
                native_delta
            } else if stablecoin.enabled && asset_id == stablecoin.asset_id {
                stablecoin.issuance_delta
            } else {
                0
            };
            BalanceSlot { asset_id, delta }
        })
        .collect())
}

struct MaterializedTxPublicInputs {
    padded_nullifiers: Vec<[u8; 48]>,
    padded_commitments: Vec<[u8; 48]>,
    balance_slots: Vec<BalanceSlot>,
    stark_public_inputs: SerializedStarkInputs,
    public_inputs: TransactionPublicInputs,
}

fn materialize_transaction_public_inputs_with_hashes(
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    ciphertext_hashes: Vec<[u8; 48]>,
    anchor: [u8; 48],
    balance_slot_asset_ids: [u64; BALANCE_SLOTS],
    stablecoin: Option<pallet_shielded_pool::types::StablecoinPolicyBinding>,
    fee: u64,
    value_balance: i128,
) -> Result<MaterializedTxPublicInputs, String> {
    let input_count = nullifiers.len();
    let output_count = commitments.len();
    if ciphertext_hashes.len() != output_count {
        return Err("ciphertext hash count does not match commitments".to_string());
    }
    let padded_nullifiers = pad_commitments(nullifiers, MAX_INPUTS, "nullifiers")?;
    let padded_commitments = pad_commitments(commitments, MAX_OUTPUTS, "commitments")?;
    let padded_ciphertext_hashes =
        pad_commitments(ciphertext_hashes, MAX_OUTPUTS, "ciphertext hashes")?;
    let stablecoin_binding = stablecoin
        .as_ref()
        .map(convert_stablecoin_binding)
        .unwrap_or_default();
    let balance_slots = canonical_balance_slots(
        balance_slot_asset_ids,
        fee,
        value_balance,
        &stablecoin_binding,
    )?;
    let stark_public_inputs = build_stark_inputs(
        input_count,
        output_count,
        anchor,
        balance_slot_asset_ids,
        fee,
        value_balance,
        stablecoin.as_ref().map(|_| &stablecoin_binding),
    )?;
    let public_inputs = TransactionPublicInputs::new(
        anchor,
        padded_nullifiers.clone(),
        padded_commitments.clone(),
        padded_ciphertext_hashes,
        balance_slots.clone(),
        fee,
        value_balance,
        stablecoin_binding,
        DEFAULT_VERSION_BINDING,
    )
    .map_err(|err| err.to_string())?;
    Ok(MaterializedTxPublicInputs {
        padded_nullifiers,
        padded_commitments,
        balance_slots,
        stark_public_inputs,
        public_inputs,
    })
}

fn build_transaction_proof(
    proof_bytes: Vec<u8>,
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    ciphertexts: &[Vec<u8>],
    anchor: [u8; 48],
    balance_slot_asset_ids: [u64; BALANCE_SLOTS],
    stablecoin: Option<pallet_shielded_pool::types::StablecoinPolicyBinding>,
    fee: u64,
    value_balance: i128,
) -> Result<TransactionProof, String> {
    if proof_bytes.is_empty() {
        return Err("shielded transfer proof bytes are empty".to_string());
    }
    if ciphertexts.len() != commitments.len() {
        return Err("ciphertext count does not match commitments".to_string());
    }
    let ciphertext_hashes: Vec<[u8; 48]> = ciphertexts
        .iter()
        .map(|ct| ciphertext_hash_bytes(ct))
        .collect();
    let materialized = materialize_transaction_public_inputs_with_hashes(
        nullifiers,
        commitments,
        ciphertext_hashes,
        anchor,
        balance_slot_asset_ids,
        stablecoin,
        fee,
        value_balance,
    )?;

    Ok(TransactionProof {
        public_inputs: materialized.public_inputs,
        nullifiers: materialized.padded_nullifiers,
        commitments: materialized.padded_commitments,
        balance_slots: materialized.balance_slots,
        stark_proof: proof_bytes,
        stark_public_inputs: Some(materialized.stark_public_inputs),
    })
}

fn build_transaction_proof_with_hashes(
    proof_bytes: Vec<u8>,
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    ciphertext_hashes: &[[u8; 48]],
    anchor: [u8; 48],
    balance_slot_asset_ids: [u64; BALANCE_SLOTS],
    stablecoin: Option<pallet_shielded_pool::types::StablecoinPolicyBinding>,
    fee: u64,
    value_balance: i128,
) -> Result<TransactionProof, String> {
    if proof_bytes.is_empty() {
        return Err("shielded transfer proof bytes are empty".to_string());
    }
    let materialized = materialize_transaction_public_inputs_with_hashes(
        nullifiers,
        commitments,
        ciphertext_hashes.to_vec(),
        anchor,
        balance_slot_asset_ids,
        stablecoin,
        fee,
        value_balance,
    )?;

    Ok(TransactionProof {
        public_inputs: materialized.public_inputs,
        nullifiers: materialized.padded_nullifiers,
        commitments: materialized.padded_commitments,
        balance_slots: materialized.balance_slots,
        stark_proof: proof_bytes,
        stark_public_inputs: Some(materialized.stark_public_inputs),
    })
}

fn resolve_sidecar_proof_bytes(
    proof: &pallet_shielded_pool::types::StarkProof,
    binding_hash: &pallet_shielded_pool::types::BindingHash,
    pending_proofs: Option<&PendingProofStore>,
) -> Result<Vec<u8>, String> {
    if !proof.data.is_empty() {
        return Ok(proof.data.clone());
    }
    let pending = pending_proofs.ok_or_else(|| {
        "transaction proof bytes missing from extrinsic and no pending proof store provided"
            .to_string()
    })?;
    pending.get(&binding_hash.data).cloned().ok_or_else(|| {
        format!(
            "missing pending proof bytes for binding hash {}",
            hex::encode(binding_hash.data)
        )
    })
}

fn encrypted_note_bytes(note: &pallet_shielded_pool::types::EncryptedNote) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(note.ciphertext.len() + note.kem_ciphertext.len());
    bytes.extend_from_slice(&note.ciphertext);
    bytes.extend_from_slice(&note.kem_ciphertext);
    bytes
}

struct DaBlobBuild {
    blob: Vec<u8>,
    transactions: Vec<Vec<Vec<u8>>>,
    used_ciphertext_hashes: Vec<[u8; 48]>,
}

struct DaEncodingBuild {
    encoding: DaEncoding,
    transactions: Vec<Vec<Vec<u8>>>,
    used_ciphertext_hashes: Vec<[u8; 48]>,
}

fn validate_ciphertexts_against_hashes(
    ciphertexts: &[Vec<u8>],
    ciphertext_sizes: &[u32],
    hashes: &[[u8; 48]],
) -> Result<(), String> {
    if ciphertext_sizes.len() != hashes.len() || ciphertexts.len() != hashes.len() {
        return Err("ciphertext hashes length mismatch".to_string());
    }
    for ((ciphertext, expected_len), hash) in ciphertexts
        .iter()
        .zip(ciphertext_sizes.iter())
        .zip(hashes.iter())
    {
        if *expected_len as usize != ciphertext.len() {
            return Err(format!(
                "ciphertext size mismatch for hash {}",
                hex::encode(hash)
            ));
        }
        let computed = ciphertext_hash_bytes(ciphertext);
        if &computed != hash {
            return Err(format!(
                "ciphertext hash mismatch for hash {}",
                hex::encode(hash)
            ));
        }
    }
    Ok(())
}

fn build_da_blob_from_extrinsics(
    extrinsics: &[runtime::UncheckedExtrinsic],
    pending_ciphertexts: Option<&PendingCiphertextStore>,
) -> Result<DaBlobBuild, String> {
    let mut transactions: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut used_ciphertext_hashes = Vec::new();

    for extrinsic in extrinsics {
        let Some((_, action)) = shielded_action_from_extrinsic(extrinsic) else {
            continue;
        };

        let ciphertexts = match action {
            ShieldedFamilyAction::TransferInline { args, .. } => Some(
                args.ciphertexts
                    .iter()
                    .map(encrypted_note_bytes)
                    .collect::<Vec<_>>(),
            ),
            ShieldedFamilyAction::BatchTransfer { args, .. } => Some(
                args.ciphertexts
                    .iter()
                    .map(encrypted_note_bytes)
                    .collect::<Vec<_>>(),
            ),
            ShieldedFamilyAction::TransferSidecar { args, .. } => {
                let pending = pending_ciphertexts
                    .ok_or_else(|| "pending ciphertext store missing".to_string())?;
                let hashes = args.ciphertext_hashes.as_slice();
                let ciphertexts = pending.get_many(hashes)?;
                validate_ciphertexts_against_hashes(&ciphertexts, &args.ciphertext_sizes, hashes)?;
                used_ciphertext_hashes.extend_from_slice(hashes);
                Some(ciphertexts)
            }
            _ => None,
        };

        if let Some(ciphertexts) = ciphertexts {
            transactions.push(ciphertexts);
        }
    }

    let mut blob = Vec::new();
    blob.extend_from_slice(&(transactions.len() as u32).to_le_bytes());
    for ciphertexts in &transactions {
        blob.extend_from_slice(&(ciphertexts.len() as u32).to_le_bytes());
        for ciphertext in ciphertexts {
            blob.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
            blob.extend_from_slice(&ciphertext);
        }
    }

    Ok(DaBlobBuild {
        blob,
        transactions,
        used_ciphertext_hashes,
    })
}

fn build_da_encoding_from_extrinsics(
    extrinsics: &[runtime::UncheckedExtrinsic],
    params: DaParams,
    pending_ciphertexts: Option<&PendingCiphertextStore>,
) -> Result<DaEncodingBuild, String> {
    let build = build_da_blob_from_extrinsics(extrinsics, pending_ciphertexts)?;
    let encoding = state_da::encode_da_blob(&build.blob, params)
        .map_err(|err| format!("da encoding failed: {err}"))?;
    Ok(DaEncodingBuild {
        encoding,
        transactions: build.transactions,
        used_ciphertext_hashes: build.used_ciphertext_hashes,
    })
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct LegacyProofDaManifestEntry {
    _binding_hash: [u8; 64],
    proof_len: u32,
    proof_offset: u32,
}

#[cfg(test)]
fn proof_da_blob_len_from_manifest(
    manifest: &[LegacyProofDaManifestEntry],
) -> Result<usize, String> {
    if manifest.is_empty() {
        return Err("proof DA manifest is empty".to_string());
    }

    let mut entries: Vec<&LegacyProofDaManifestEntry> = manifest.iter().collect();
    entries.sort_by_key(|entry| entry.proof_offset);

    const HEADER_BYTES: u64 = 4; // u32 entry count
    const ENTRY_PREFIX_BYTES: u64 = 64 + 4; // binding_hash + proof_len
    let mut expected_offset: u64 = HEADER_BYTES + ENTRY_PREFIX_BYTES;
    let mut blob_len: u64 = 0;

    for entry in entries {
        if entry.proof_len == 0 {
            return Err("proof DA manifest entry has zero proof_len".to_string());
        }
        if entry.proof_offset as u64 != expected_offset {
            return Err("proof DA manifest offsets are not contiguous".to_string());
        }
        blob_len = expected_offset
            .checked_add(entry.proof_len as u64)
            .ok_or_else(|| "proof DA manifest blob length overflow".to_string())?;
        expected_offset = blob_len
            .checked_add(ENTRY_PREFIX_BYTES)
            .ok_or_else(|| "proof DA manifest offset overflow".to_string())?;
    }

    usize::try_from(blob_len).map_err(|_| "proof DA manifest blob length too large".to_string())
}

#[cfg(test)]
fn parse_proof_da_blob(blob: &[u8]) -> Result<(HashMap<[u8; 64], Vec<u8>>, usize), String> {
    fn read_u32(cursor: &mut &[u8]) -> Result<u32, String> {
        if cursor.len() < 4 {
            return Err("proof DA blob truncated".to_string());
        }
        let (head, rest) = cursor.split_at(4);
        *cursor = rest;
        Ok(u32::from_le_bytes(head.try_into().expect("4 bytes")))
    }

    let mut cursor = blob;
    let count = read_u32(&mut cursor)? as usize;
    let mut out = HashMap::with_capacity(count);

    for _ in 0..count {
        if cursor.len() < 64 {
            return Err("proof DA blob truncated".to_string());
        }
        let (bh_bytes, rest) = cursor.split_at(64);
        cursor = rest;
        let mut binding_hash = [0u8; 64];
        binding_hash.copy_from_slice(bh_bytes);

        let len = read_u32(&mut cursor)? as usize;
        if cursor.len() < len {
            return Err("proof DA blob truncated".to_string());
        }
        let (data, rest) = cursor.split_at(len);
        cursor = rest;

        if out.insert(binding_hash, data.to_vec()).is_some() {
            return Err("duplicate binding hash in proof DA blob".to_string());
        }
    }

    let consumed = blob.len().saturating_sub(cursor.len());
    Ok((out, consumed))
}

struct DaTxLayout {
    ciphertext_sizes: Vec<usize>,
}

fn has_sidecar_transfers(extrinsics: &[runtime::UncheckedExtrinsic]) -> bool {
    extrinsics.iter().any(|extrinsic| {
        matches!(
            shielded_action_from_extrinsic(extrinsic),
            Some((_, ShieldedFamilyAction::TransferSidecar { .. }))
        )
    })
}

fn shielded_action_from_runtime_call(
    call: &runtime::RuntimeCall,
) -> Option<(
    protocol_kernel::types::KernelVersionBinding,
    ShieldedFamilyAction,
)> {
    let runtime::RuntimeCall::Kernel(pallet_kernel::Call::submit_action { envelope }) = call else {
        return None;
    };
    let action = ShieldedFamilyAction::decode_envelope(envelope).ok()?;
    Some((envelope.binding, action))
}

fn shielded_action_from_extrinsic(
    extrinsic: &runtime::UncheckedExtrinsic,
) -> Option<(
    protocol_kernel::types::KernelVersionBinding,
    ShieldedFamilyAction,
)> {
    shielded_action_from_runtime_call(&extrinsic.function)
}

fn kernel_shielded_runtime_call(
    action_id: u16,
    new_nullifiers: Vec<[u8; 48]>,
    public_args: Vec<u8>,
) -> runtime::RuntimeCall {
    let envelope = build_shielded_kernel_envelope(
        runtime::manifest::default_version_binding(),
        action_id,
        new_nullifiers,
        public_args,
    );
    runtime::RuntimeCall::Kernel(pallet_kernel::Call::submit_action { envelope })
}

fn kernel_shielded_extrinsic(
    action_id: u16,
    new_nullifiers: Vec<[u8; 48]>,
    public_args: Vec<u8>,
) -> runtime::UncheckedExtrinsic {
    runtime::UncheckedExtrinsic::new_unsigned(kernel_shielded_runtime_call(
        action_id,
        new_nullifiers,
        public_args,
    ))
}

fn da_layout_from_extrinsics(
    extrinsics: &[runtime::UncheckedExtrinsic],
) -> Result<Vec<DaTxLayout>, String> {
    let mut layouts = Vec::new();
    for extrinsic in extrinsics {
        let Some((_, action)) = shielded_action_from_extrinsic(extrinsic) else {
            continue;
        };

        let sizes = match action {
            ShieldedFamilyAction::TransferInline { args, .. } => Some(
                args.ciphertexts
                    .iter()
                    .map(|note| encrypted_note_bytes(note).len())
                    .collect::<Vec<_>>(),
            ),
            ShieldedFamilyAction::BatchTransfer { args, .. } => Some(
                args.ciphertexts
                    .iter()
                    .map(|note| encrypted_note_bytes(note).len())
                    .collect::<Vec<_>>(),
            ),
            ShieldedFamilyAction::TransferSidecar { args, .. } => Some(
                args.ciphertext_sizes
                    .iter()
                    .map(|size| *size as usize)
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        };

        if let Some(ciphertext_sizes) = sizes {
            layouts.push(DaTxLayout { ciphertext_sizes });
        }
    }
    Ok(layouts)
}

fn da_blob_len_from_layouts(layouts: &[DaTxLayout]) -> usize {
    let mut len = 4;
    for layout in layouts {
        len += 4;
        for size in &layout.ciphertext_sizes {
            len += 4 + *size;
        }
    }
    len
}

fn parse_da_blob(blob: &[u8], layouts: &[DaTxLayout]) -> Result<Vec<Vec<Vec<u8>>>, String> {
    fn read_u32(cursor: &mut &[u8]) -> Result<u32, String> {
        if cursor.len() < 4 {
            return Err("DA blob truncated".to_string());
        }
        let (head, rest) = cursor.split_at(4);
        *cursor = rest;
        Ok(u32::from_le_bytes(head.try_into().expect("4 bytes")))
    }

    let mut cursor = blob;
    let tx_count = read_u32(&mut cursor)? as usize;
    if tx_count != layouts.len() {
        return Err(format!(
            "DA blob tx count mismatch (blob {}, expected {})",
            tx_count,
            layouts.len()
        ));
    }

    let mut transactions = Vec::with_capacity(tx_count);
    for layout in layouts {
        let ct_count = read_u32(&mut cursor)? as usize;
        if ct_count != layout.ciphertext_sizes.len() {
            return Err("DA blob ciphertext count mismatch".to_string());
        }
        let mut ciphertexts = Vec::with_capacity(ct_count);
        for expected_len in &layout.ciphertext_sizes {
            let len = read_u32(&mut cursor)? as usize;
            if len != *expected_len {
                return Err("DA blob ciphertext length mismatch".to_string());
            }
            if cursor.len() < len {
                return Err("DA blob ciphertext truncated".to_string());
            }
            let (data, rest) = cursor.split_at(len);
            cursor = rest;
            ciphertexts.push(data.to_vec());
        }
        transactions.push(ciphertexts);
    }

    Ok(transactions)
}

fn flatten_ciphertexts(transactions: &[Vec<Vec<u8>>]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for ciphertexts in transactions {
        for ciphertext in ciphertexts {
            out.push(ciphertext.clone());
        }
    }
    out
}

fn transfer_ciphertexts_from_extrinsics(
    extrinsics: &[runtime::UncheckedExtrinsic],
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for extrinsic in extrinsics {
        let Some((_, action)) = shielded_action_from_extrinsic(extrinsic) else {
            continue;
        };
        match action {
            ShieldedFamilyAction::TransferInline { args, .. } => {
                out.extend(args.ciphertexts.iter().map(encrypted_note_bytes));
            }
            ShieldedFamilyAction::BatchTransfer { args, .. } => {
                out.extend(args.ciphertexts.iter().map(encrypted_note_bytes));
            }
            _ => {}
        }
    }
    out
}

fn coinbase_ciphertexts_from_extrinsics(
    extrinsics: &[runtime::UncheckedExtrinsic],
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for extrinsic in extrinsics {
        let Some((_, action)) = shielded_action_from_extrinsic(extrinsic) else {
            continue;
        };
        let ShieldedFamilyAction::MintCoinbase(args) = action else {
            continue;
        };
        out.push(encrypted_note_bytes(
            &args.reward_bundle.miner_note.encrypted_note,
        ));
    }
    out
}

fn binding_hashes_from_extrinsics(extrinsics: &[runtime::UncheckedExtrinsic]) -> Vec<[u8; 64]> {
    let mut out = Vec::new();
    for extrinsic in extrinsics {
        let Some((_, action)) = shielded_action_from_extrinsic(extrinsic) else {
            continue;
        };
        match action {
            ShieldedFamilyAction::TransferInline { args, .. } => {
                out.push(args.binding_hash);
            }
            ShieldedFamilyAction::TransferSidecar { args, .. } => {
                out.push(args.binding_hash);
            }
            _ => {}
        }
    }
    out
}

fn statement_hash_from_materialized_call(
    anchor: &[u8; 48],
    nullifiers: &[[u8; 48]],
    commitments: &[[u8; 48]],
    ciphertext_hashes: &[[u8; 48]],
    balance_slot_asset_ids: &[u64; BALANCE_SLOTS],
    fee: u64,
    value_balance: i128,
    version: protocol_versioning::VersionBinding,
    stablecoin: Option<&pallet_shielded_pool::types::StablecoinPolicyBinding>,
) -> [u8; 48] {
    let mut message = Vec::new();
    message.extend_from_slice(b"tx-statement-v2");
    message.extend_from_slice(anchor);

    for nf in nullifiers.iter().take(MAX_INPUTS) {
        message.extend_from_slice(nf);
    }
    for _ in nullifiers.len()..MAX_INPUTS {
        message.extend_from_slice(&[0u8; 48]);
    }

    for cm in commitments.iter().take(MAX_OUTPUTS) {
        message.extend_from_slice(cm);
    }
    for _ in commitments.len()..MAX_OUTPUTS {
        message.extend_from_slice(&[0u8; 48]);
    }

    for ct in ciphertext_hashes.iter().take(MAX_OUTPUTS) {
        message.extend_from_slice(ct);
    }
    for _ in ciphertext_hashes.len()..MAX_OUTPUTS {
        message.extend_from_slice(&[0u8; 48]);
    }

    for asset_id in balance_slot_asset_ids {
        message.extend_from_slice(&asset_id.to_le_bytes());
    }
    message.extend_from_slice(&fee.to_le_bytes());
    message.extend_from_slice(&value_balance.to_le_bytes());
    message.extend_from_slice(&version.circuit.to_le_bytes());
    message.extend_from_slice(&version.crypto.to_le_bytes());

    if let Some(stablecoin) = stablecoin {
        message.push(1);
        message.extend_from_slice(&stablecoin.asset_id.to_le_bytes());
        message.extend_from_slice(&stablecoin.policy_hash);
        message.extend_from_slice(&stablecoin.oracle_commitment);
        message.extend_from_slice(&stablecoin.attestation_commitment);
        message.extend_from_slice(&stablecoin.issuance_delta.to_le_bytes());
        message.extend_from_slice(&stablecoin.policy_version.to_le_bytes());
    } else {
        message.push(0);
        message.extend_from_slice(&0u64.to_le_bytes());
        message.extend_from_slice(&[0u8; 48]);
        message.extend_from_slice(&[0u8; 48]);
        message.extend_from_slice(&[0u8; 48]);
        message.extend_from_slice(&0i128.to_le_bytes());
        message.extend_from_slice(&0u32.to_le_bytes());
    }

    blake3_384(&message)
}

fn statement_bindings_from_extrinsics(
    extrinsics: &[runtime::UncheckedExtrinsic],
) -> Result<Vec<consensus::types::TxStatementBinding>, String> {
    let mut bindings = Vec::new();

    for extrinsic in extrinsics {
        let Some((binding_version, action)) = shielded_action_from_extrinsic(extrinsic) else {
            continue;
        };

        let version: protocol_versioning::VersionBinding = binding_version.into();
        let binding = match action {
            ShieldedFamilyAction::TransferInline { nullifiers, args } => {
                let ciphertext_hashes = args
                    .ciphertexts
                    .iter()
                    .map(encrypted_note_bytes)
                    .map(|ciphertext| ciphertext_hash_bytes(&ciphertext))
                    .collect::<Vec<_>>();
                consensus::types::TxStatementBinding {
                    statement_hash: statement_hash_from_materialized_call(
                        &args.anchor,
                        nullifiers.as_slice(),
                        args.commitments.as_slice(),
                        &ciphertext_hashes,
                        &args.balance_slot_asset_ids,
                        args.fee,
                        0,
                        version,
                        args.stablecoin.as_ref(),
                    ),
                    anchor: args.anchor,
                    fee: args.fee,
                    circuit_version: u32::from(version.circuit),
                }
            }
            ShieldedFamilyAction::TransferSidecar { nullifiers, args } => {
                consensus::types::TxStatementBinding {
                    statement_hash: statement_hash_from_materialized_call(
                        &args.anchor,
                        nullifiers.as_slice(),
                        args.commitments.as_slice(),
                        args.ciphertext_hashes.as_slice(),
                        &args.balance_slot_asset_ids,
                        args.fee,
                        0,
                        version,
                        args.stablecoin.as_ref(),
                    ),
                    anchor: args.anchor,
                    fee: args.fee,
                    circuit_version: u32::from(version.circuit),
                }
            }
            ShieldedFamilyAction::BatchTransfer { .. } => {
                return Err(
                    "batch shielded transfers are not supported in block proof generation".into(),
                );
            }
            _ => continue,
        };
        bindings.push(binding);
    }

    Ok(bindings)
}

fn statement_bindings_for_candidate_extrinsics(
    extrinsics: &[runtime::UncheckedExtrinsic],
    resolved_ciphertexts: Option<&[Vec<Vec<u8>>]>,
    pending_proofs: Option<&PendingProofStore>,
    allow_missing_sidecar_proofs: bool,
) -> Result<Vec<consensus::types::TxStatementBinding>, String> {
    let extracted = extract_shielded_transfers_for_parallel_verification(
        extrinsics,
        resolved_ciphertexts,
        pending_proofs,
        allow_missing_sidecar_proofs,
    );

    match extracted {
        Ok((transactions, _proofs, tx_validity_artifacts, _binding_hashes)) => {
            let tx_validity_artifacts = tx_validity_artifacts
                .into_iter()
                .collect::<Option<Vec<_>>>();
            if let Some(tx_artifacts) = tx_validity_artifacts.as_ref() {
                return consensus::tx_statement_bindings_from_tx_artifacts(
                    &transactions,
                    tx_artifacts,
                )
                .map_err(|err| format!("tx statement bindings from tx artifacts failed: {err}"));
            }
            statement_bindings_from_extrinsics(extrinsics)
        }
        Err(error) if allow_missing_sidecar_proofs => {
            tracing::debug!(
                error = %error,
                "falling back to extrinsic-materialized statement bindings for preview candidate"
            );
            statement_bindings_from_extrinsics(extrinsics)
        }
        Err(error) => Err(error),
    }
}

fn missing_proof_binding_hashes(extrinsics: &[runtime::UncheckedExtrinsic]) -> Vec<[u8; 64]> {
    let mut out = Vec::new();
    for extrinsic in extrinsics {
        let Some((_, action)) = shielded_action_from_extrinsic(extrinsic) else {
            continue;
        };
        match action {
            ShieldedFamilyAction::TransferInline { args, .. } => {
                if args.proof.is_empty() {
                    out.push(args.binding_hash);
                }
            }
            ShieldedFamilyAction::TransferSidecar { args, .. } => {
                if args.proof.is_empty() {
                    out.push(args.binding_hash);
                }
            }
            _ => {}
        }
    }
    out
}

fn pending_proof_match_count(
    binding_hashes: &[[u8; 64]],
    pending_proofs: &PendingProofStore,
) -> usize {
    binding_hashes
        .iter()
        .filter(|binding_hash| pending_proofs.contains(binding_hash))
        .count()
}

const DA_MAX_SHARDS: usize = 255;

fn da_data_shards_for_len(len: usize, chunk_size: usize) -> usize {
    let shards = len.div_ceil(chunk_size);
    if shards == 0 {
        1
    } else {
        shards
    }
}

fn da_parity_shards_for_data(data_shards: usize) -> usize {
    let parity = (data_shards + 1) / 2;
    parity.max(1)
}

fn da_shard_counts_for_len(len: usize, params: DaParams) -> Result<(usize, usize), String> {
    let chunk_size = params.chunk_size as usize;
    let data_shards = da_data_shards_for_len(len, chunk_size);
    let parity_shards = da_parity_shards_for_data(data_shards);
    let total_shards = data_shards + parity_shards;
    if total_shards > DA_MAX_SHARDS {
        return Err(format!(
            "DA blob requires {} shards (max {})",
            total_shards, DA_MAX_SHARDS
        ));
    }
    Ok((data_shards, total_shards))
}

async fn request_da_samples(
    peer_id: network::PeerId,
    root: DaRoot,
    indices: &[u32],
    handle: &PqNetworkHandle,
    tracker: &Arc<ParkingMutex<DaRequestTracker>>,
    timeout: Duration,
) -> Result<Vec<DaChunkProof>, String> {
    if indices.is_empty() {
        return Ok(Vec::new());
    }

    let receivers = {
        let mut tracker = tracker.lock();
        tracker.register(root, indices)
    };

    let request = crate::substrate::network_bridge::DaChunkProtocolMessage::Request {
        root,
        indices: indices.to_vec(),
    };
    if let Err(err) = handle
        .send_message(
            peer_id,
            crate::substrate::network_bridge::DA_CHUNKS_PROTOCOL.to_string(),
            request.encode(),
        )
        .await
    {
        let mut tracker = tracker.lock();
        tracker.cancel(root, indices);
        return Err(format!("failed to request DA chunks: {err}"));
    }

    let deadline = Instant::now() + timeout;
    let mut proofs = Vec::with_capacity(indices.len());

    for (&index, rx) in indices.iter().zip(receivers.into_iter()) {
        let now = Instant::now();
        if now >= deadline {
            let mut tracker = tracker.lock();
            tracker.cancel(root, indices);
            return Err(format!("timeout waiting for DA chunk index {}", index));
        }
        let remaining = deadline - now;
        match tokio::time::timeout(remaining, rx).await {
            Ok(Ok(Some(proof))) => proofs.push(proof),
            Ok(Ok(None)) => {
                let mut tracker = tracker.lock();
                tracker.cancel(root, indices);
                return Err(format!("peer missing DA chunk index {}", index));
            }
            Ok(Err(_)) => {
                let mut tracker = tracker.lock();
                tracker.cancel(root, indices);
                return Err(format!("DA chunk channel dropped index {}", index));
            }
            Err(_) => {
                let mut tracker = tracker.lock();
                tracker.cancel(root, indices);
                return Err(format!("timeout waiting for DA chunk index {}", index));
            }
        }
    }

    Ok(proofs)
}

async fn fetch_da_blob_for_block(
    peer_id: network::PeerId,
    da_root: DaRoot,
    layouts: &[DaTxLayout],
    params: DaParams,
    handle: &PqNetworkHandle,
    tracker: &Arc<ParkingMutex<DaRequestTracker>>,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let data_len = da_blob_len_from_layouts(layouts);
    if data_len == 0 {
        return Ok(Vec::new());
    }

    let chunk_size = params.chunk_size as usize;
    let (data_shards, _total_shards) = da_shard_counts_for_len(data_len, params)?;
    let indices: Vec<u32> = (0..data_shards as u32).collect();

    let proofs = request_da_samples(peer_id, da_root, &indices, handle, tracker, timeout).await?;
    if proofs.len() != indices.len() {
        return Err("missing DA chunk proofs".to_string());
    }

    for proof in &proofs {
        state_da::verify_da_chunk(da_root, proof)
            .map_err(|err| format!("invalid DA chunk proof: {err}"))?;
    }

    let mut blob = vec![0u8; data_len];
    for proof in proofs {
        let idx = proof.chunk.index as usize;
        if idx >= data_shards {
            return Err(format!("unexpected parity shard index {}", idx));
        }
        let start = idx.saturating_mul(chunk_size);
        let end = (start + chunk_size).min(data_len);
        let expected_len = end.saturating_sub(start);
        if proof.chunk.data.len() < expected_len {
            return Err("DA chunk truncated".to_string());
        }
        blob[start..end].copy_from_slice(&proof.chunk.data[..expected_len]);
    }

    Ok(blob)
}

async fn fetch_da_for_block(
    peer_id: network::PeerId,
    da_root: DaRoot,
    extrinsics: &[runtime::UncheckedExtrinsic],
    params: DaParams,
    handle: &PqNetworkHandle,
    tracker: &Arc<ParkingMutex<DaRequestTracker>>,
    timeout: Duration,
) -> Result<DaEncodingBuild, String> {
    let layouts = da_layout_from_extrinsics(extrinsics)?;
    let blob =
        fetch_da_blob_for_block(peer_id, da_root, &layouts, params, handle, tracker, timeout)
            .await?;
    let encoding = state_da::encode_da_blob(&blob, params)
        .map_err(|err| format!("da encoding failed: {err}"))?;
    let computed_root = encoding.root();
    if computed_root != da_root {
        return Err("DA root mismatch for fetched blob".to_string());
    }
    let transactions = parse_da_blob(&blob, &layouts)?;
    Ok(DaEncodingBuild {
        encoding,
        transactions,
        used_ciphertext_hashes: Vec::new(),
    })
}

async fn sample_da_for_root(
    peer_id: network::PeerId,
    da_root: DaRoot,
    chunk_count: u32,
    block_hash: [u8; 32],
    node_secret: [u8; 32],
    params: DaParams,
    handle: &PqNetworkHandle,
    tracker: &Arc<ParkingMutex<DaRequestTracker>>,
    timeout: Duration,
) -> Result<(), String> {
    if chunk_count == 0 {
        return Err("DA chunk count is zero".to_string());
    }

    let indices =
        state_da::sample_indices(node_secret, block_hash, chunk_count, params.sample_count);
    tracing::debug!(
        root = %hex::encode(da_root),
        block_hash = %hex::encode(block_hash),
        chunk_count,
        sample_count = params.sample_count,
        indices = ?indices,
        "Sampling DA chunks"
    );
    let proofs = request_da_samples(peer_id, da_root, &indices, handle, tracker, timeout).await?;
    if proofs.len() != indices.len() {
        return Err("missing DA chunk proofs".to_string());
    }

    for proof in &proofs {
        state_da::verify_da_chunk(da_root, proof)
            .map_err(|err| format!("invalid DA chunk proof: {err}"))?;
    }

    Ok(())
}

async fn sample_da_for_block(
    peer_id: network::PeerId,
    block_hash: [u8; 32],
    node_secret: [u8; 32],
    extrinsics: &[runtime::UncheckedExtrinsic],
    params: DaParams,
    handle: &PqNetworkHandle,
    tracker: &Arc<ParkingMutex<DaRequestTracker>>,
    timeout: Duration,
) -> Result<DaEncodingBuild, String> {
    let build = build_da_encoding_from_extrinsics(extrinsics, params, None)?;
    let root = build.encoding.root();
    let chunk_count = build.encoding.chunks().len() as u32;
    sample_da_for_root(
        peer_id,
        root,
        chunk_count,
        block_hash,
        node_secret,
        params,
        handle,
        tracker,
        timeout,
    )
    .await?;

    Ok(build)
}

#[derive(Clone, Debug)]
struct CandidateBlockContext {
    decoded_extrinsics: Vec<runtime::UncheckedExtrinsic>,
    extracted_transactions: Vec<consensus::types::Transaction>,
    tx_validity_artifacts: Option<Vec<consensus::TxValidityArtifact>>,
    missing_proof_bindings: usize,
    statement_bindings: Vec<consensus::types::TxStatementBinding>,
    tx_statements_commitment: [u8; 48],
    da_root: DaRoot,
    da_chunk_count: u32,
    da_blob_bytes: usize,
    resolved_ciphertexts: Vec<Vec<Vec<u8>>>,
}

fn build_candidate_context(
    candidate_txs: &[Vec<u8>],
    da_params: DaParams,
    pending_ciphertexts: &PendingCiphertextStore,
    pending_proofs: &PendingProofStore,
) -> Result<CandidateBlockContext, String> {
    let mut decoded = Vec::with_capacity(candidate_txs.len());
    for ext_bytes in candidate_txs {
        let extrinsic = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..])
            .map_err(|e| format!("failed to decode candidate extrinsic: {e:?}"))?;
        decoded.push(extrinsic);
    }

    let da_blob = build_da_blob_from_extrinsics(&decoded, Some(pending_ciphertexts))
        .map_err(|err| format!("failed to build DA blob for proven batch: {err}"))?;
    let da_blob_bytes = da_blob.blob.len();
    let encoding = state_da::encode_da_blob(&da_blob.blob, da_params)
        .map_err(|err| format!("failed to encode DA blob for proven batch: {err}"))?;
    let da_root = encoding.root();
    let da_chunk_count = encoding.chunks().len() as u32;
    let resolved_ciphertexts = da_blob.transactions;

    let (transactions, proofs, extracted_tx_artifacts, proof_binding_hashes) =
        extract_shielded_transfers_for_parallel_verification(
            &decoded,
            Some(resolved_ciphertexts.as_slice()),
            Some(pending_proofs),
            false,
        )?;
    if proof_binding_hashes.len() != proofs.len() {
        return Err(format!(
            "proof binding hash count mismatch (expected {}, got {})",
            proofs.len(),
            proof_binding_hashes.len()
        ));
    }
    let tx_validity_artifacts = extracted_tx_artifacts
        .into_iter()
        .collect::<Option<Vec<_>>>();
    let statement_bindings = if let Some(ref tx_artifacts) = tx_validity_artifacts {
        consensus::tx_statement_bindings_from_tx_artifacts(&transactions, tx_artifacts)
            .map_err(|err| format!("tx statement bindings from tx artifacts failed: {err}"))?
    } else {
        statement_bindings_from_extrinsics(&decoded)?
    };
    if statement_bindings.len() != transactions.len() {
        return Err(format!(
            "tx statement binding count mismatch (expected {}, got {})",
            transactions.len(),
            statement_bindings.len()
        ));
    }
    let statement_hashes = statement_bindings
        .iter()
        .map(|binding| binding.statement_hash)
        .collect::<Vec<_>>();
    let tx_statements_commitment =
        CommitmentBlockProver::commitment_from_statement_hashes(&statement_hashes)
            .map_err(|err| format!("tx_statements_commitment failed: {err}"))?;
    let missing_proof_bindings = missing_proof_binding_hashes(&decoded).len();

    Ok(CandidateBlockContext {
        decoded_extrinsics: decoded,
        extracted_transactions: transactions,
        tx_validity_artifacts,
        missing_proof_bindings,
        statement_bindings,
        tx_statements_commitment,
        da_root,
        da_chunk_count,
        da_blob_bytes,
        resolved_ciphertexts,
    })
}

fn build_commitment_block_proof_from_materials(
    client: &HegemonFullClient,
    parent_hash: H256,
    statement_hashes: &[[u8; 48]],
    transactions: &[consensus::types::Transaction],
    statement_bindings: &[consensus::types::TxStatementBinding],
    da_root: DaRoot,
) -> Result<Option<CommitmentBlockProof>, String> {
    if transactions.is_empty() {
        return Ok(None);
    }
    if statement_hashes.len() != transactions.len() {
        return Err(format!(
            "tx statement hash count mismatch (expected {}, got {})",
            transactions.len(),
            statement_hashes.len()
        ));
    }
    if statement_bindings.len() != transactions.len() {
        return Err(format!(
            "tx statement binding count mismatch (expected {}, got {})",
            transactions.len(),
            statement_bindings.len()
        ));
    }

    // Use compact runtime snapshots (root/frontier/history) instead of replaying the entire
    // on-chain commitment set for every proving job. This keeps per-job setup bounded as chain
    // height grows.
    let mut tree = load_parent_commitment_tree_state(client, parent_hash)?;
    let starting_root = tree.root();
    for (index, (tx, binding)) in transactions.iter().zip(statement_bindings).enumerate() {
        let anchor = binding.anchor;
        if !tree.contains_root(&anchor) {
            return Err(format!(
                "transaction {index} anchor not found in commitment tree history"
            ));
        }
        for &commitment in tx.commitments.iter().filter(|c| **c != [0u8; 48]) {
            tree.append(commitment)
                .map_err(|err| format!("commitment tree append failed: {err}"))?;
        }
    }
    let ending_root = tree.root();

    let mut nullifiers = Vec::new();
    for tx in transactions {
        nullifiers.extend_from_slice(&tx.nullifiers);
        for _ in tx.nullifiers.len()..MAX_INPUTS {
            nullifiers.push([0u8; 48]);
        }
    }
    let mut sorted_nullifiers = nullifiers.clone();
    sorted_nullifiers.sort_unstable();
    let nullifier_root = nullifier_root_from_list(&nullifiers)?;
    let starting_kernel_root = kernel_root_from_shielded_root(&starting_root);
    let ending_kernel_root = kernel_root_from_shielded_root(&ending_root);

    let prover = CommitmentBlockProver::new();
    let proof = prover
        .prove_from_statement_hashes_with_inputs(
            statement_hashes,
            starting_root,
            ending_root,
            starting_kernel_root,
            ending_kernel_root,
            nullifier_root,
            da_root,
            nullifiers,
            sorted_nullifiers,
        )
        .map_err(|e| format!("commitment block proof failed: {e}"))?;

    Ok(Some(proof))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PreparedArtifactSelector {
    legacy_mode: pallet_shielded_pool::types::BlockProofMode,
    proof_kind: pallet_shielded_pool::types::ProofArtifactKind,
    verifier_profile: pallet_shielded_pool::types::VerifierProfileDigest,
}

impl PreparedArtifactSelector {
    fn from_mode(mode: pallet_shielded_pool::types::BlockProofMode) -> Self {
        let (proof_kind, verifier_profile) =
            crate::substrate::artifact_market::legacy_pallet_artifact_identity(mode);
        Self {
            legacy_mode: mode,
            proof_kind,
            verifier_profile,
        }
    }

    fn receipt_root() -> Self {
        Self::from_mode(pallet_shielded_pool::types::BlockProofMode::ReceiptRoot)
    }
}

fn prepared_artifact_selector_from_env() -> PreparedArtifactSelector {
    let raw = std::env::var("HEGEMON_BLOCK_PROOF_MODE").unwrap_or_default();
    if raw.is_empty()
        || raw.eq_ignore_ascii_case("receipt_root")
        || raw.eq_ignore_ascii_case("receipt-root")
    {
        return PreparedArtifactSelector::receipt_root();
    }
    tracing::warn!(
        mode = raw,
        "legacy or unknown HEGEMON_BLOCK_PROOF_MODE requested; forcing receipt_root on the product path"
    );
    PreparedArtifactSelector::receipt_root()
}

fn truthy_env_var(name: &str) -> bool {
    let Ok(raw) = std::env::var(name) else {
        return false;
    };
    let value = raw.trim();
    if value.is_empty()
        || value.eq_ignore_ascii_case("0")
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("off")
    {
        return false;
    }
    if value.eq_ignore_ascii_case("1")
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("on")
    {
        return true;
    }
    tracing::warn!(
        env = name,
        value,
        "unrecognized boolean environment override; treating as disabled"
    );
    false
}

fn native_only_receipt_root_required_from_env() -> bool {
    truthy_env_var("HEGEMON_REQUIRE_NATIVE")
}

fn ensure_native_only_receipt_root_selector(
    selector: PreparedArtifactSelector,
) -> Result<(), String> {
    if !native_only_receipt_root_required_from_env() {
        return Ok(());
    }
    if selector != PreparedArtifactSelector::receipt_root() {
        return Err(format!(
            "HEGEMON_REQUIRE_NATIVE=1 requires HEGEMON_BLOCK_PROOF_MODE=receipt_root; got legacy_mode {:?}, proof_kind {:?}, verifier_profile {}",
            selector.legacy_mode,
            selector.proof_kind,
            hex::encode(selector.verifier_profile),
        ));
    }
    tracing::info!("native-only receipt_root lane selected");
    Ok(())
}

fn ensure_native_only_receipt_root_outcome(
    outcome: &PreparedAggregationOutcome,
) -> Result<(), String> {
    if !native_only_receipt_root_required_from_env() {
        return Ok(());
    }
    let report = outcome.native_selection_report.as_ref().ok_or_else(|| {
        "HEGEMON_REQUIRE_NATIVE=1 requires a native selection report for receipt_root authoring"
            .to_string()
    })?;
    if !report.used_native_lane {
        return Err(format!(
            "HEGEMON_REQUIRE_NATIVE=1 forbids InlineTx fallback from receipt_root: {} ({})",
            report.fallback_reason_label(),
            report.fallback_detail(),
        ));
    }
    if !matches!(
        outcome.artifacts,
        PreparedAggregationArtifacts::ReceiptRoot(_)
    ) {
        return Err(
            "HEGEMON_REQUIRE_NATIVE=1 expected a receipt_root aggregation artifact but received InlineTx fallback".to_string(),
        );
    }
    Ok(())
}

fn is_canonical_native_receipt_root_payload(
    payload: &pallet_shielded_pool::types::BlockProofBundle,
) -> bool {
    payload.proof_mode == pallet_shielded_pool::types::BlockProofMode::ReceiptRoot
        && payload.proof_kind == pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot
        && payload.verifier_profile
            == consensus::experimental_native_receipt_root_verifier_profile()
        && payload.receipt_root.is_some()
}

fn ensure_product_receipt_root_payload(
    payload: &pallet_shielded_pool::types::BlockProofBundle,
) -> Result<(), String> {
    if !is_canonical_native_receipt_root_payload(payload) {
        return Err(format!(
            "non-empty shielded blocks require canonical native receipt_root artifacts; got proof_mode {:?}, proof_kind {:?}, verifier_profile {}",
            payload.proof_mode,
            payload.proof_kind,
            hex::encode(payload.verifier_profile),
        ));
    }
    Ok(())
}

fn ensure_product_receipt_root_outcome(outcome: &PreparedAggregationOutcome) -> Result<(), String> {
    let report = outcome.native_selection_report.as_ref().ok_or_else(|| {
        "product receipt_root authoring requires a native selection report".to_string()
    })?;
    if !report.used_native_lane {
        return Err(format!(
            "product receipt_root authoring forbids InlineTx fallback: {} ({})",
            report.fallback_reason_label(),
            report.fallback_detail(),
        ));
    }
    if !matches!(
        outcome.artifacts,
        PreparedAggregationArtifacts::ReceiptRoot(_)
    ) {
        return Err(
            "product receipt_root authoring expected a receipt_root aggregation artifact"
                .to_string(),
        );
    }
    Ok(())
}

fn ensure_native_only_receipt_root_payload(
    payload: &pallet_shielded_pool::types::BlockProofBundle,
) -> Result<(), String> {
    if !native_only_receipt_root_required_from_env() {
        return Ok(());
    }
    ensure_product_receipt_root_payload(payload).map_err(|_| {
        format!(
            "HEGEMON_REQUIRE_NATIVE=1 rejects block proof mode {:?}, proof_kind {:?}, verifier_profile {}; canonical native receipt_root is required",
            payload.proof_mode,
            payload.proof_kind,
            hex::encode(payload.verifier_profile),
        )
    })?;
    Ok(())
}

fn receipt_root_lane_requires_embedded_proof_bytes(
    _proof_kind: pallet_shielded_pool::types::ProofArtifactKind,
    missing_proof_bindings: usize,
) -> Result<(), String> {
    if missing_proof_bindings == 0 {
        return Ok(());
    }
    Err(format!(
        "receipt_root requires embedded proof bytes for every shielded transfer; candidate has {missing_proof_bindings} transfers whose proof bytes are available only via local sidecar state"
    ))
}

fn selector_requests_native_receipt_lane(selector: PreparedArtifactSelector) -> bool {
    selector.legacy_mode == pallet_shielded_pool::types::BlockProofMode::ReceiptRoot
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct MiniRootCacheKey([u8; 48]);

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReceiptRootMiniRootPlan {
    leaf_start: u32,
    leaf_count: u32,
    cache_key: MiniRootCacheKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReceiptRootWorkPlan {
    leaf_count: usize,
    mini_root_size: usize,
    mini_root_count: usize,
    chunk_internal_fold_nodes: usize,
    upper_tree_fold_nodes: usize,
    upper_tree_level_widths: Vec<usize>,
    mini_roots: Vec<ReceiptRootMiniRootPlan>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NativeReceiptRootBuildCacheDelta {
    leaf_cache_hits: u64,
    leaf_cache_misses: u64,
    chunk_cache_hits: u64,
    chunk_cache_misses: u64,
}

impl NativeReceiptRootBuildCacheDelta {
    fn between(
        before: NativeReceiptRootBuildCacheStats,
        after: NativeReceiptRootBuildCacheStats,
    ) -> Self {
        Self {
            leaf_cache_hits: after.leaf_cache_hits.saturating_sub(before.leaf_cache_hits),
            leaf_cache_misses: after
                .leaf_cache_misses
                .saturating_sub(before.leaf_cache_misses),
            chunk_cache_hits: after
                .chunk_cache_hits
                .saturating_sub(before.chunk_cache_hits),
            chunk_cache_misses: after
                .chunk_cache_misses
                .saturating_sub(before.chunk_cache_misses),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeReceiptRootBuildReport {
    workers: usize,
    leaf_count: usize,
    mini_root_size: usize,
    mini_root_count: usize,
    chunk_internal_fold_nodes: usize,
    upper_tree_fold_nodes: usize,
    upper_tree_level_widths: Vec<usize>,
    cache_delta: NativeReceiptRootBuildCacheDelta,
}

struct PreparedNativeReceiptRootBuild {
    outcome: PreparedAggregationOutcome,
    work_plan: ReceiptRootWorkPlan,
    build_report: NativeReceiptRootBuildReport,
}

static RECEIPT_ROOT_THREAD_POOLS: once_cell::sync::Lazy<
    ParkingMutex<HashMap<usize, Arc<rayon::ThreadPool>>>,
> = once_cell::sync::Lazy::new(|| ParkingMutex::new(HashMap::new()));

fn load_receipt_root_workers(default_workers: usize) -> usize {
    std::env::var("HEGEMON_RECEIPT_ROOT_WORKERS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .or_else(|| {
            std::env::var("HEGEMON_AGG_STAGE_LOCAL_PARALLELISM")
                .ok()
                .and_then(|raw| raw.parse::<usize>().ok())
        })
        .or_else(|| {
            std::env::var("HEGEMON_PROVER_WORKERS")
                .ok()
                .and_then(|raw| raw.parse::<usize>().ok())
        })
        .unwrap_or(default_workers.max(1))
        .clamp(1, 256)
}

fn receipt_root_thread_pool(workers: usize) -> Result<Arc<rayon::ThreadPool>, String> {
    let workers = workers.max(1);
    let mut guard = RECEIPT_ROOT_THREAD_POOLS.lock();
    if let Some(pool) = guard.get(&workers) {
        return Ok(Arc::clone(pool));
    }
    let pool = ThreadPoolBuilder::new()
        .num_threads(workers)
        .thread_name(move |index| format!("hegemon-receipt-root-{workers}-{index}"))
        .build()
        .map_err(|error| {
            format!("failed to build receipt-root worker pool ({workers} threads): {error}")
        })?;
    let pool = Arc::new(pool);
    guard.insert(workers, Arc::clone(&pool));
    Ok(pool)
}

fn receipt_root_upper_tree_level_widths(mini_root_count: usize) -> Vec<usize> {
    let mut widths = Vec::new();
    let mut current = mini_root_count.max(1);
    loop {
        widths.push(current);
        if current == 1 {
            break;
        }
        current = current.div_ceil(2);
    }
    widths
}

fn make_receipt_root_mini_root_cache_key(child_hashes: &[[u8; 48]]) -> MiniRootCacheKey {
    let mut material = Vec::with_capacity(64 + (child_hashes.len() * 48));
    material.extend_from_slice(b"hegemon.native-receipt-root.chunk.v1");
    material.extend_from_slice(&consensus::experimental_native_receipt_root_params_fingerprint());
    material.extend_from_slice(&(child_hashes.len() as u32).to_le_bytes());
    for child_hash in child_hashes {
        material.extend_from_slice(child_hash);
    }
    MiniRootCacheKey(blake3_384(&material))
}

fn build_receipt_root_work_plan(
    tx_artifacts: &[consensus::TxValidityArtifact],
) -> Result<ReceiptRootWorkPlan, String> {
    if tx_artifacts.is_empty() {
        return Err("candidate tx set has no receipt-root proof material".to_string());
    }

    let mini_root_size = native_receipt_root_mini_root_size();
    let artifact_hashes = tx_artifacts
        .iter()
        .map(|artifact| {
            artifact
                .proof
                .as_ref()
                .map(|proof| blake3_384(&proof.artifact_bytes))
                .ok_or_else(|| {
                    "native receipt_root requires proof envelopes for all txs".to_string()
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mini_roots = artifact_hashes
        .chunks(mini_root_size)
        .enumerate()
        .map(|(index, chunk)| ReceiptRootMiniRootPlan {
            leaf_start: (index * mini_root_size) as u32,
            leaf_count: chunk.len() as u32,
            cache_key: make_receipt_root_mini_root_cache_key(chunk),
        })
        .collect::<Vec<_>>();

    let chunk_internal_fold_nodes = tx_artifacts
        .chunks(mini_root_size)
        .map(|chunk| chunk.len().saturating_sub(1))
        .sum();
    let mini_root_count = mini_roots.len().max(1);

    Ok(ReceiptRootWorkPlan {
        leaf_count: tx_artifacts.len(),
        mini_root_size,
        mini_root_count: mini_roots.len(),
        chunk_internal_fold_nodes,
        upper_tree_fold_nodes: mini_root_count.saturating_sub(1),
        upper_tree_level_widths: receipt_root_upper_tree_level_widths(mini_root_count),
        mini_roots,
    })
}

fn experimental_receipt_root_payload_from_artifact(
    tx_artifacts: &[consensus::TxValidityArtifact],
    built: consensus::ExperimentalReceiptRootArtifact,
) -> pallet_shielded_pool::types::ReceiptRootProofPayload {
    let consensus_receipts = tx_artifacts
        .iter()
        .map(|artifact| artifact.receipt.clone())
        .collect::<Vec<_>>();
    pallet_shielded_pool::types::ReceiptRootProofPayload {
        root_proof: pallet_shielded_pool::types::StarkProof::from_bytes(built.artifact_bytes),
        metadata: pallet_shielded_pool::types::ReceiptRootMetadata {
            relation_id: built.metadata.relation_id,
            shape_digest: built.metadata.shape_digest,
            leaf_count: built.metadata.leaf_count,
            fold_count: built.metadata.fold_count,
        },
        receipts: consensus_receipts
            .into_iter()
            .map(|receipt| pallet_shielded_pool::types::TxValidityReceipt {
                statement_hash: receipt.statement_hash,
                proof_digest: receipt.proof_digest,
                public_inputs_digest: receipt.public_inputs_digest,
                verifier_profile: receipt.verifier_profile,
            })
            .collect(),
    }
}

#[cfg(test)]
fn build_receipt_root_proof_from_materials(
    tx_artifacts: &[consensus::TxValidityArtifact],
) -> Result<pallet_shielded_pool::types::ReceiptRootProofPayload, String> {
    if tx_artifacts.is_empty() {
        return Err("candidate tx set has no receipt-root proof material".to_string());
    }
    if tx_artifacts.iter().any(|artifact| {
        artifact
            .proof
            .as_ref()
            .map(|proof| {
                proof.kind != consensus::ProofArtifactKind::TxLeaf
                    || proof.verifier_profile
                        != consensus::experimental_native_tx_leaf_verifier_profile()
            })
            .unwrap_or(true)
    }) {
        return Err("receipt-root requires native tx-leaf artifacts for every tx".to_string());
    }
    let built = consensus::build_experimental_native_receipt_root_artifact(tx_artifacts)
        .map_err(|err| format!("native receipt-root artifact generation failed: {err}"))?;
    Ok(experimental_receipt_root_payload_from_artifact(
        tx_artifacts,
        built,
    ))
}

fn build_receipt_root_proof_from_materials_with_plan(
    tx_artifacts: &[consensus::TxValidityArtifact],
    work_plan: &ReceiptRootWorkPlan,
    default_workers: usize,
) -> Result<
    (
        pallet_shielded_pool::types::ReceiptRootProofPayload,
        NativeReceiptRootBuildReport,
    ),
    String,
> {
    let workers = load_receipt_root_workers(default_workers);
    let before = native_receipt_root_build_cache_stats();
    let built = if workers <= 1 {
        consensus::build_experimental_native_receipt_root_artifact(tx_artifacts)
    } else {
        receipt_root_thread_pool(workers)?
            .install(|| consensus::build_experimental_native_receipt_root_artifact(tx_artifacts))
    }
    .map_err(|err| format!("native receipt-root artifact generation failed: {err}"))?;
    let after = native_receipt_root_build_cache_stats();

    Ok((
        experimental_receipt_root_payload_from_artifact(tx_artifacts, built),
        NativeReceiptRootBuildReport {
            workers,
            leaf_count: work_plan.leaf_count,
            mini_root_size: work_plan.mini_root_size,
            mini_root_count: work_plan.mini_root_count,
            chunk_internal_fold_nodes: work_plan.chunk_internal_fold_nodes,
            upper_tree_fold_nodes: work_plan.upper_tree_fold_nodes,
            upper_tree_level_widths: work_plan.upper_tree_level_widths.clone(),
            cache_delta: NativeReceiptRootBuildCacheDelta::between(before, after),
        },
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeArtifactFallbackReason {
    ArtifactsUnavailable,
    VerifierProfileMismatch,
}

impl NativeArtifactFallbackReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactsUnavailable => "native_artifacts_unavailable",
            Self::VerifierProfileMismatch => "native_verifier_profile_mismatch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeArtifactSelectionReport {
    used_native_lane: bool,
    fallback_reason: Option<NativeArtifactFallbackReason>,
    fallback_detail: Option<String>,
}

impl NativeArtifactSelectionReport {
    fn native_lane_selected() -> Self {
        Self {
            used_native_lane: true,
            fallback_reason: None,
            fallback_detail: None,
        }
    }

    fn fallback(reason: NativeArtifactFallbackReason, detail: impl Into<String>) -> Self {
        Self {
            used_native_lane: false,
            fallback_reason: Some(reason),
            fallback_detail: Some(detail.into()),
        }
    }

    fn fallback_reason_label(&self) -> &'static str {
        self.fallback_reason
            .map(NativeArtifactFallbackReason::as_str)
            .unwrap_or("none")
    }

    fn fallback_detail(&self) -> &str {
        self.fallback_detail.as_deref().unwrap_or("")
    }
}

fn require_native_tx_leaf_artifacts(
    tx_artifacts: Option<&[consensus::TxValidityArtifact]>,
) -> Result<&[consensus::TxValidityArtifact], NativeArtifactSelectionReport> {
    let expected_profile = consensus::experimental_native_tx_leaf_verifier_profile();
    let Some(tx_artifacts) = tx_artifacts else {
        return Err(NativeArtifactSelectionReport::fallback(
            NativeArtifactFallbackReason::ArtifactsUnavailable,
            "candidate tx set did not materialize native tx-validity artifacts for every transfer",
        ));
    };

    for (index, artifact) in tx_artifacts.iter().enumerate() {
        let Some(proof) = artifact.proof.as_ref() else {
            return Err(NativeArtifactSelectionReport::fallback(
                NativeArtifactFallbackReason::ArtifactsUnavailable,
                format!("tx {index} is missing a tx-validity proof envelope"),
            ));
        };
        if proof.kind != consensus::ProofArtifactKind::TxLeaf {
            return Err(NativeArtifactSelectionReport::fallback(
                NativeArtifactFallbackReason::ArtifactsUnavailable,
                format!(
                    "tx {index} artifact kind {} is not tx_leaf",
                    proof.kind.label()
                ),
            ));
        }
        if proof.verifier_profile != expected_profile {
            return Err(NativeArtifactSelectionReport::fallback(
                NativeArtifactFallbackReason::VerifierProfileMismatch,
                format!(
                    "tx {index} proof verifier profile {} does not match native {}",
                    hex::encode(proof.verifier_profile),
                    hex::encode(expected_profile),
                ),
            ));
        }
        if artifact.receipt.verifier_profile != expected_profile {
            return Err(NativeArtifactSelectionReport::fallback(
                NativeArtifactFallbackReason::VerifierProfileMismatch,
                format!(
                    "tx {index} receipt verifier profile {} does not match native {}",
                    hex::encode(artifact.receipt.verifier_profile),
                    hex::encode(expected_profile),
                ),
            ));
        }
    }

    Ok(tx_artifacts)
}

#[derive(Clone, Debug)]
struct PreparedAggregationOutcome {
    artifacts: PreparedAggregationArtifacts,
    native_selection_report: Option<NativeArtifactSelectionReport>,
}

impl PreparedAggregationOutcome {
    fn new(artifacts: PreparedAggregationArtifacts) -> Self {
        Self {
            artifacts,
            native_selection_report: None,
        }
    }

    fn native(
        artifacts: PreparedAggregationArtifacts,
        report: NativeArtifactSelectionReport,
    ) -> Self {
        Self {
            artifacts,
            native_selection_report: Some(report),
        }
    }
}

#[cfg(test)]
fn prepare_native_receipt_root_artifacts(
    tx_artifacts: Option<&[consensus::TxValidityArtifact]>,
) -> Result<PreparedAggregationOutcome, String> {
    prepare_native_receipt_root_artifacts_with_builder(
        tx_artifacts,
        build_receipt_root_proof_from_materials,
    )
}

fn prepare_native_receipt_root_artifacts_with_work_plan(
    tx_artifacts: Option<&[consensus::TxValidityArtifact]>,
    default_workers: usize,
) -> Result<PreparedNativeReceiptRootBuild, String> {
    let tx_artifacts = require_native_tx_leaf_artifacts(tx_artifacts).map_err(|report| {
        format!(
            "native receipt_root requires canonical native tx_leaf artifacts: {} ({})",
            report.fallback_reason_label(),
            report.fallback_detail(),
        )
    })?;
    let work_plan = build_receipt_root_work_plan(tx_artifacts)?;
    let (payload, build_report) = build_receipt_root_proof_from_materials_with_plan(
        tx_artifacts,
        &work_plan,
        default_workers,
    )
    .map_err(|error| format!("native receipt_root artifact build failed: {error}"))?;
    Ok(PreparedNativeReceiptRootBuild {
        outcome: PreparedAggregationOutcome::native(
            PreparedAggregationArtifacts::ReceiptRoot(payload),
            NativeArtifactSelectionReport::native_lane_selected(),
        ),
        work_plan,
        build_report,
    })
}

#[cfg(test)]
fn prepare_native_receipt_root_artifacts_with_builder<F>(
    tx_artifacts: Option<&[consensus::TxValidityArtifact]>,
    build_receipt_root: F,
) -> Result<PreparedAggregationOutcome, String>
where
    F: FnOnce(
        &[consensus::TxValidityArtifact],
    ) -> Result<pallet_shielded_pool::types::ReceiptRootProofPayload, String>,
{
    let tx_artifacts = require_native_tx_leaf_artifacts(tx_artifacts).map_err(|report| {
        format!(
            "native receipt_root requires canonical native tx_leaf artifacts: {} ({})",
            report.fallback_reason_label(),
            report.fallback_detail(),
        )
    })?;
    let payload = build_receipt_root(tx_artifacts)
        .map_err(|error| format!("native receipt_root artifact build failed: {error}"))?;
    Ok(PreparedAggregationOutcome::native(
        PreparedAggregationArtifacts::ReceiptRoot(payload),
        NativeArtifactSelectionReport::native_lane_selected(),
    ))
}

fn should_store_prove_ahead_aggregation_outcome(
    selector: PreparedArtifactSelector,
    outcome: &PreparedAggregationOutcome,
) -> bool {
    if selector.legacy_mode != pallet_shielded_pool::types::BlockProofMode::ReceiptRoot {
        return true;
    }

    matches!(
        outcome.artifacts,
        PreparedAggregationArtifacts::ReceiptRoot(_)
    ) && outcome
        .native_selection_report
        .as_ref()
        .map(|report| report.used_native_lane)
        .unwrap_or(true)
}

#[derive(Clone, Debug)]
enum PreparedAggregationArtifacts {
    InlineTx,
    ReceiptRoot(pallet_shielded_pool::types::ReceiptRootProofPayload),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ProveAheadAggregationCacheKey {
    selector: PreparedArtifactSelector,
    tx_statements_commitment: [u8; 48],
    tx_count: u32,
    tx_artifact_set_digest: Option<[u8; 48]>,
}

struct ProveAheadAggregationCache {
    capacity: usize,
    order: VecDeque<ProveAheadAggregationCacheKey>,
    entries: HashMap<ProveAheadAggregationCacheKey, Arc<PreparedAggregationOutcome>>,
}

impl ProveAheadAggregationCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    fn touch_key(&mut self, key: ProveAheadAggregationCacheKey) {
        if let Some(position) = self.order.iter().position(|existing| *existing == key) {
            self.order.remove(position);
        }
        self.order.push_back(key);
    }

    fn get(
        &mut self,
        key: ProveAheadAggregationCacheKey,
    ) -> Option<Arc<PreparedAggregationOutcome>> {
        let entry = self.entries.get(&key).cloned();
        if entry.is_some() {
            self.touch_key(key);
        }
        entry
    }

    fn insert(
        &mut self,
        key: ProveAheadAggregationCacheKey,
        artifacts: Arc<PreparedAggregationOutcome>,
    ) {
        self.entries.insert(key, artifacts);
        self.touch_key(key);
        while self.order.len() > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.entries.remove(&evicted);
            }
        }
    }
}

fn load_prove_ahead_aggregation_cache_capacity() -> usize {
    std::env::var("HEGEMON_PROVE_AHEAD_CACHE_CAPACITY")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(8)
        .clamp(1, 256)
}

static PROVE_AHEAD_AGGREGATION_CACHE: once_cell::sync::Lazy<
    ParkingMutex<ProveAheadAggregationCache>,
> = once_cell::sync::Lazy::new(|| {
    ParkingMutex::new(ProveAheadAggregationCache::new(
        load_prove_ahead_aggregation_cache_capacity(),
    ))
});

fn make_prove_ahead_aggregation_cache_key(
    selector: PreparedArtifactSelector,
    tx_statements_commitment: [u8; 48],
    tx_count: u32,
    tx_artifacts: Option<&[consensus::TxValidityArtifact]>,
) -> ProveAheadAggregationCacheKey {
    ProveAheadAggregationCacheKey {
        selector,
        tx_statements_commitment,
        tx_count,
        tx_artifact_set_digest: prove_ahead_tx_artifact_set_digest(selector, tx_artifacts),
    }
}

fn prove_ahead_tx_artifact_set_digest(
    selector: PreparedArtifactSelector,
    tx_artifacts: Option<&[consensus::TxValidityArtifact]>,
) -> Option<[u8; 48]> {
    if selector.legacy_mode != pallet_shielded_pool::types::BlockProofMode::ReceiptRoot {
        return None;
    }

    tx_artifacts.map(digest_tx_validity_artifact_set)
}

fn digest_tx_validity_artifact_set(tx_artifacts: &[consensus::TxValidityArtifact]) -> [u8; 48] {
    let mut material = Vec::with_capacity(64 + tx_artifacts.len() * 196);
    material.extend_from_slice(b"hegemon.prove-ahead.tx-artifact-set.v1");
    material.extend_from_slice(&(tx_artifacts.len() as u32).to_le_bytes());
    for artifact in tx_artifacts {
        material.extend_from_slice(&artifact.receipt.statement_hash);
        material.extend_from_slice(&artifact.receipt.proof_digest);
        material.extend_from_slice(&artifact.receipt.public_inputs_digest);
        material.extend_from_slice(&artifact.receipt.verifier_profile);
        match artifact.proof.as_ref() {
            Some(proof) => {
                material.push(1);
                material.extend_from_slice(proof.kind.label().as_bytes());
                material.push(0);
                material.extend_from_slice(&proof.verifier_profile);
                material.extend_from_slice(&blake3_384(&proof.artifact_bytes));
            }
            None => material.push(0),
        }
    }
    blake3_384(&material)
}

fn lookup_prove_ahead_aggregation_artifacts(
    key: ProveAheadAggregationCacheKey,
) -> Option<PreparedAggregationOutcome> {
    let mut guard = PROVE_AHEAD_AGGREGATION_CACHE.lock();
    guard.get(key).map(|value| value.as_ref().clone())
}

fn store_prove_ahead_aggregation_artifacts(
    key: ProveAheadAggregationCacheKey,
    artifacts: PreparedAggregationOutcome,
) {
    let mut guard = PROVE_AHEAD_AGGREGATION_CACHE.lock();
    guard.insert(key, Arc::new(artifacts));
}

fn block_proof_payload_aggregation_bytes(
    payload: &pallet_shielded_pool::types::BlockProofBundle,
) -> usize {
    match payload.proof_mode {
        pallet_shielded_pool::types::BlockProofMode::InlineTx => 0,
        pallet_shielded_pool::types::BlockProofMode::ReceiptRoot => payload
            .receipt_root
            .as_ref()
            .map(|receipt_root| receipt_root.root_proof.data.len())
            .unwrap_or(0),
    }
}

fn block_proof_payload_aggregation_uncompressed_bytes(
    payload: &pallet_shielded_pool::types::BlockProofBundle,
) -> usize {
    match payload.proof_mode {
        pallet_shielded_pool::types::BlockProofMode::InlineTx => 0,
        pallet_shielded_pool::types::BlockProofMode::ReceiptRoot => payload
            .receipt_root
            .as_ref()
            .map(|receipt_root| receipt_root.root_proof.data.len())
            .unwrap_or(0),
    }
}

fn sync_payload_artifact_identity(payload: &mut pallet_shielded_pool::types::CandidateArtifact) {
    if matches!(
        payload.proof_mode,
        pallet_shielded_pool::types::BlockProofMode::ReceiptRoot
    ) {
        payload.proof_kind = pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot;
        payload.verifier_profile = consensus::experimental_native_receipt_root_verifier_profile();
        return;
    }
    let (proof_kind, verifier_profile) =
        crate::substrate::artifact_market::legacy_pallet_artifact_identity(payload.proof_mode);
    payload.proof_kind = proof_kind;
    payload.verifier_profile = verifier_profile;
}

const MIN_BLOCK_PROOF_BUNDLE_V2_SPEC_VERSION: u32 = 4;
const MIN_BLOCK_PROOF_BUNDLE_V2_TRANSACTION_VERSION: u32 = 2;

fn ensure_runtime_supports_block_proof_bundle_v2(
    client: &HegemonFullClient,
    parent_hash: H256,
) -> Result<(), String> {
    let runtime_version = client.runtime_api().version(parent_hash).map_err(|error| {
        format!("failed to query runtime version for parent {parent_hash:?}: {error:?}")
    })?;

    if runtime_version.spec_version < MIN_BLOCK_PROOF_BUNDLE_V2_SPEC_VERSION
        || runtime_version.transaction_version < MIN_BLOCK_PROOF_BUNDLE_V2_TRANSACTION_VERSION
    {
        return Err(format!(
            "runtime at parent does not support BlockProofBundleV2 (have specVersion={} transactionVersion={}, need specVersion>={} transactionVersion>={}); restart on a fresh V2 runtime chain",
            runtime_version.spec_version,
            runtime_version.transaction_version,
            MIN_BLOCK_PROOF_BUNDLE_V2_SPEC_VERSION,
            MIN_BLOCK_PROOF_BUNDLE_V2_TRANSACTION_VERSION
        ));
    }

    Ok(())
}

fn prepare_block_proof_bundle(
    client: &HegemonFullClient,
    parent_hash: H256,
    block_number: u64,
    candidate_txs: Vec<Vec<u8>>,
    da_params: DaParams,
    pending_ciphertexts: &PendingCiphertextStore,
    pending_proofs: &PendingProofStore,
    commitment_block_fast: bool,
    receipt_root_worker_default: usize,
) -> Result<PreparedBundle, String> {
    let started = Instant::now();
    tracing::info!(
        block_number,
        tx_count = candidate_txs.len(),
        candidate_bytes = candidate_txs.iter().map(Vec::len).sum::<usize>(),
        "prepare_block_proof_bundle: start"
    );
    let context_started = Instant::now();
    let context = build_candidate_context(
        &candidate_txs,
        da_params,
        pending_ciphertexts,
        pending_proofs,
    )?;
    tracing::info!(
        block_number,
        tx_count = context.statement_bindings.len(),
        decoded_extrinsics = context.decoded_extrinsics.len(),
        extracted_transactions = context.extracted_transactions.len(),
        resolved_ciphertext_txs = context.resolved_ciphertexts.len(),
        da_blob_bytes = context.da_blob_bytes,
        da_chunk_count = context.da_chunk_count,
        stage_ms = context_started.elapsed().as_millis(),
        total_ms = started.elapsed().as_millis(),
        "prepare_block_proof_bundle: built shared candidate context"
    );

    let statement_hashes = context
        .statement_bindings
        .iter()
        .map(|binding| binding.statement_hash)
        .collect::<Vec<_>>();
    let tx_statements_commitment = context.tx_statements_commitment;
    let tx_count = statement_hashes.len() as u32;
    if tx_count == 0 {
        return Err("candidate tx set has no shielded transfers".to_string());
    }

    let tx_artifacts_for_batching = context.tx_validity_artifacts.clone();
    let selected_artifact = prepared_artifact_selector_from_env();
    ensure_native_only_receipt_root_selector(selected_artifact)?;
    if selected_artifact.legacy_mode == pallet_shielded_pool::types::BlockProofMode::ReceiptRoot {
        receipt_root_lane_requires_embedded_proof_bytes(
            selected_artifact.proof_kind,
            context.missing_proof_bindings,
        )?;
    }
    let aggregation_cache_key = make_prove_ahead_aggregation_cache_key(
        selected_artifact,
        tx_statements_commitment,
        tx_count,
        context.tx_validity_artifacts.as_deref(),
    );
    let da_root = context.da_root;
    // commitment and aggregation proving operate on independent materials;
    // run both in parallel and keep stage-level attribution explicit.
    let _ = commitment_block_fast;
    let (commitment_join, aggregation_join) = std::thread::scope(|scope| {
        let commitment_statement_hashes = statement_hashes.clone();
        let commitment_transactions = context.extracted_transactions.clone();
        let commitment_bindings = context.statement_bindings.clone();
        let commitment_handle = scope.spawn(move || {
            tracing::info!(
                block_number,
                tx_count,
                "prepare_block_proof_bundle: starting commitment stage"
            );
            let stage_started = Instant::now();
            let stage_result = build_commitment_block_proof_from_materials(
                client,
                parent_hash,
                &commitment_statement_hashes,
                &commitment_transactions,
                &commitment_bindings,
                da_root,
            );
            (stage_result, stage_started.elapsed().as_millis())
        });

        let aggregation_tx_artifacts = tx_artifacts_for_batching.clone();
        let aggregation_handle = scope.spawn(move || {
            tracing::info!(
                block_number,
                tx_count,
                legacy_mode = ?selected_artifact.legacy_mode,
                proof_kind = ?selected_artifact.proof_kind,
                verifier_profile = %hex::encode(selected_artifact.verifier_profile),
                "prepare_block_proof_bundle: starting aggregation stage"
            );
            let stage_started = Instant::now();
            let mut cache_hit = false;
            let mut receipt_root_work_plan = if selected_artifact.legacy_mode
                == pallet_shielded_pool::types::BlockProofMode::ReceiptRoot
            {
                require_native_tx_leaf_artifacts(aggregation_tx_artifacts.as_deref())
                    .ok()
                    .and_then(|artifacts| build_receipt_root_work_plan(artifacts).ok())
            } else {
                None
            };
            let mut native_build_report = None;
            let stage_result = if let Some(cached) =
                lookup_prove_ahead_aggregation_artifacts(aggregation_cache_key)
            {
                cache_hit = true;
                Ok(cached)
            } else {
                let built = match selected_artifact.legacy_mode {
                    pallet_shielded_pool::types::BlockProofMode::InlineTx => Ok(
                        PreparedAggregationOutcome::new(PreparedAggregationArtifacts::InlineTx),
                    ),
                    pallet_shielded_pool::types::BlockProofMode::ReceiptRoot => {
                        prepare_native_receipt_root_artifacts_with_work_plan(
                            aggregation_tx_artifacts.as_deref(),
                            receipt_root_worker_default,
                        )
                        .map(|prepared| {
                            receipt_root_work_plan = Some(prepared.work_plan.clone());
                            native_build_report = Some(prepared.build_report);
                            prepared.outcome
                        })
                    }
                };
                if let Ok(ref artifacts) = built {
                    if should_store_prove_ahead_aggregation_outcome(selected_artifact, artifacts) {
                        store_prove_ahead_aggregation_artifacts(
                            aggregation_cache_key,
                            artifacts.clone(),
                        );
                    }
                }
                built
            };
            (
                stage_result,
                stage_started.elapsed().as_millis(),
                cache_hit,
                receipt_root_work_plan,
                native_build_report,
            )
        });

        (commitment_handle.join(), aggregation_handle.join())
    });

    let (commitment_result, commitment_stage_ms) = match commitment_join {
        Ok(result) => result,
        Err(_) => {
            return Err("prepare_block_proof_bundle: commitment stage panicked".to_string());
        }
    };
    let (
        aggregation_result,
        aggregation_stage_ms,
        aggregation_cache_hit,
        receipt_root_work_plan,
        receipt_root_build_report,
    ) = match aggregation_join {
        Ok(result) => result,
        Err(_) => {
            return Err("prepare_block_proof_bundle: aggregation stage panicked".to_string());
        }
    };
    match &commitment_result {
        Ok(Some(_)) => tracing::info!(
            block_number,
            tx_count,
            commitment_stage_ms,
            "prepare_block_proof_bundle: commitment stage complete"
        ),
        Ok(None) => tracing::warn!(
            block_number,
            tx_count,
            commitment_stage_ms,
            "prepare_block_proof_bundle: commitment stage returned no proof material"
        ),
        Err(error) => tracing::warn!(
            block_number,
            tx_count,
            commitment_stage_ms,
            error = %error,
            "prepare_block_proof_bundle: commitment stage failed"
        ),
    }
    match &aggregation_result {
        Ok(outcome) => {
            if let Some(report) = outcome.native_selection_report.as_ref() {
                if report.used_native_lane {
                    if let Some(work_plan) = receipt_root_work_plan.as_ref() {
                        let build_report = receipt_root_build_report.as_ref();
                        tracing::info!(
                            block_number,
                            tx_count,
                            aggregation_stage_ms,
                            aggregation_cache_hit,
                            used_native_lane = true,
                            requested_native_lane =
                                selector_requests_native_receipt_lane(selected_artifact),
                            fallback_reason = report.fallback_reason_label(),
                            receipt_root_workers = build_report
                                .map(|report| report.workers)
                                .unwrap_or(load_receipt_root_workers(receipt_root_worker_default)),
                            mini_root_size = work_plan.mini_root_size,
                            mini_root_count = work_plan.mini_root_count,
                            chunk_internal_fold_nodes = work_plan.chunk_internal_fold_nodes,
                            upper_tree_fold_nodes = work_plan.upper_tree_fold_nodes,
                            upper_tree_level_widths = ?work_plan.upper_tree_level_widths,
                            leaf_cache_hits = build_report
                                .map(|report| report.cache_delta.leaf_cache_hits)
                                .unwrap_or(0),
                            leaf_cache_misses = build_report
                                .map(|report| report.cache_delta.leaf_cache_misses)
                                .unwrap_or(0),
                            chunk_cache_hits = build_report
                                .map(|report| report.cache_delta.chunk_cache_hits)
                                .unwrap_or(0),
                            chunk_cache_misses = build_report
                                .map(|report| report.cache_delta.chunk_cache_misses)
                                .unwrap_or(0),
                            "prepare_block_proof_bundle: native receipt-backed aggregation lane selected"
                        );
                    } else {
                        tracing::info!(
                            block_number,
                            tx_count,
                            aggregation_stage_ms,
                            aggregation_cache_hit,
                            used_native_lane = true,
                            requested_native_lane =
                                selector_requests_native_receipt_lane(selected_artifact),
                            fallback_reason = report.fallback_reason_label(),
                            "prepare_block_proof_bundle: native receipt-backed aggregation lane selected"
                        );
                    }
                } else {
                    tracing::warn!(
                        block_number,
                        tx_count,
                        aggregation_stage_ms,
                        aggregation_cache_hit,
                        used_native_lane = false,
                        requested_native_lane = selector_requests_native_receipt_lane(selected_artifact),
                        fallback_reason = report.fallback_reason_label(),
                        fallback_detail = %report.fallback_detail(),
                        "prepare_block_proof_bundle: falling back to inline_tx from a native receipt-backed aggregation lane"
                    );
                }
            } else {
                tracing::info!(
                    block_number,
                    tx_count,
                    aggregation_stage_ms,
                    aggregation_cache_hit,
                    "prepare_block_proof_bundle: aggregation stage complete"
                );
            }
        }
        Err(error) => tracing::warn!(
            block_number,
            tx_count,
            aggregation_stage_ms,
            aggregation_cache_hit,
            error = %error,
            "prepare_block_proof_bundle: aggregation stage failed"
        ),
    }
    let commitment_proof = commitment_result?
        .ok_or_else(|| "candidate tx set has no commitment proof material".to_string())?;
    let aggregation_outcome = aggregation_result?;
    ensure_product_receipt_root_outcome(&aggregation_outcome)?;
    ensure_native_only_receipt_root_outcome(&aggregation_outcome)?;
    let native_selection_report = aggregation_outcome.native_selection_report.clone();

    let mut payload = pallet_shielded_pool::types::BlockProofBundle {
        version: pallet_shielded_pool::types::BLOCK_PROOF_BUNDLE_SCHEMA,
        tx_count,
        tx_statements_commitment,
        da_root: context.da_root,
        da_chunk_count: context.da_chunk_count,
        commitment_proof: pallet_shielded_pool::types::StarkProof::from_bytes(
            commitment_proof.proof_bytes.clone(),
        ),
        proof_mode: pallet_shielded_pool::types::BlockProofMode::ReceiptRoot,
        proof_kind: pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot,
        verifier_profile: consensus::experimental_native_receipt_root_verifier_profile(),
        receipt_root: None,
    };
    match aggregation_outcome.artifacts {
        PreparedAggregationArtifacts::InlineTx => {
            return Err(
                "product authoring requires receipt_root aggregation artifacts; received InlineTx"
                    .to_string(),
            );
        }
        PreparedAggregationArtifacts::ReceiptRoot(receipt_root) => {
            payload.proof_mode = pallet_shielded_pool::types::BlockProofMode::ReceiptRoot;
            payload.receipt_root = Some(receipt_root);
        }
    }
    sync_payload_artifact_identity(&mut payload);
    ensure_product_receipt_root_payload(&payload)?;
    ensure_native_only_receipt_root_payload(&payload)?;

    tracing::info!(
        block_number,
        commitment_bytes = commitment_proof.proof_bytes.len(),
        aggregation_bytes = block_proof_payload_aggregation_bytes(&payload),
        da_chunk_count = payload.da_chunk_count,
        proof_mode = ?payload.proof_mode,
        aggregation_cache_hit,
        requested_native_lane = selected_artifact.legacy_mode
            == pallet_shielded_pool::types::BlockProofMode::ReceiptRoot
            && selector_requests_native_receipt_lane(selected_artifact),
        used_native_lane = native_selection_report
            .as_ref()
            .map(|report| report.used_native_lane)
            .unwrap_or(false),
        native_lane_fallback_reason = native_selection_report
            .as_ref()
            .map(|report| report.fallback_reason_label())
            .unwrap_or("not_requested"),
        commitment_stage_ms,
        aggregation_stage_ms,
        total_ms = started.elapsed().as_millis(),
        "prepare_block_proof_bundle: built commitment and bundle proof artifacts"
    );

    let out = PreparedBundle {
        key: BundleMatchKey {
            parent_hash,
            tx_statements_commitment,
            tx_count,
            proof_mode: payload.proof_mode,
            proof_kind: payload.proof_kind,
            verifier_profile: payload.verifier_profile,
            artifact_hash: crate::substrate::artifact_market::candidate_artifact_hash(&payload),
        },
        payload,
        candidate_txs,
        build_ms: started.elapsed().as_millis(),
    };
    tracing::info!(
        block_number,
        tx_count,
        build_ms = out.build_ms,
        "prepare_block_proof_bundle: done"
    );
    Ok(out)
}

#[derive(Clone, Copy, Debug)]
struct SubstrateProofHeader {
    da_params: DaParams,
}

impl HeaderProofExt for SubstrateProofHeader {
    fn proof_commitment(&self) -> consensus::StarkCommitment {
        [0u8; 48]
    }

    fn fee_commitment(&self) -> consensus::FeeCommitment {
        [0u8; 48]
    }

    fn transaction_count(&self) -> u32 {
        0
    }

    fn version_commitment(&self) -> consensus::VersionCommitment {
        [0u8; 48]
    }

    fn da_root(&self) -> consensus::DaRoot {
        [0u8; 48]
    }

    fn da_params(&self) -> consensus::DaParams {
        self.da_params
    }

    fn kernel_root(&self) -> consensus::types::StateRoot {
        [0u8; 48]
    }
}

#[derive(Clone, Debug)]
struct ProvenBatchPayload {
    payload: pallet_shielded_pool::types::BlockProofBundle,
}

fn extract_proven_batch_payload(
    extrinsics: &[runtime::UncheckedExtrinsic],
) -> Result<Option<ProvenBatchPayload>, String> {
    let mut found: Option<ProvenBatchPayload> = None;
    for extrinsic in extrinsics {
        let Some((_, action)) = shielded_action_from_extrinsic(extrinsic) else {
            continue;
        };

        if let ShieldedFamilyAction::SubmitCandidateArtifact(args) = action {
            if found.is_some() {
                return Err("multiple submit_candidate_artifact extrinsics in block".into());
            }
            found = Some(ProvenBatchPayload {
                payload: args.payload,
            });
        }
    }
    Ok(found)
}

fn extract_shielded_transfers_for_parallel_verification(
    extrinsics: &[runtime::UncheckedExtrinsic],
    resolved_ciphertexts: Option<&[Vec<Vec<u8>>]>,
    pending_proofs: Option<&PendingProofStore>,
    allow_missing_sidecar_proofs: bool,
) -> Result<
    (
        Vec<consensus::types::Transaction>,
        Vec<TransactionProof>,
        Vec<Option<consensus::TxValidityArtifact>>,
        Vec<[u8; 64]>,
    ),
    String,
> {
    let mut transactions = Vec::new();
    let mut proofs = Vec::new();
    let mut tx_validity_artifacts = Vec::new();
    let mut proof_binding_hashes = Vec::new();
    let mut ciphertext_cursor = 0usize;

    for extrinsic in extrinsics {
        let Some((binding_version, action)) = shielded_action_from_extrinsic(extrinsic) else {
            continue;
        };
        let version: protocol_versioning::VersionBinding = binding_version.into();

        let mut next_resolved_ciphertexts = || -> Result<Option<Vec<Vec<u8>>>, String> {
            let resolved = match resolved_ciphertexts {
                Some(resolved) => resolved,
                None => return Ok(None),
            };
            if ciphertext_cursor >= resolved.len() {
                return Err("resolved ciphertexts exhausted".to_string());
            }
            let ciphertexts = resolved[ciphertext_cursor].clone();
            ciphertext_cursor += 1;
            Ok(Some(ciphertexts))
        };

        match action {
            ShieldedFamilyAction::MintCoinbase(_) => {
                // Coinbase ciphertexts are stored separately from the DA blob.
            }
            ShieldedFamilyAction::TransferInline { nullifiers, args } => {
                let ciphertexts = match next_resolved_ciphertexts()? {
                    Some(ciphertexts) => ciphertexts,
                    None => args
                        .ciphertexts
                        .iter()
                        .map(encrypted_note_bytes)
                        .collect::<Vec<_>>(),
                };
                let (tx_proof, tx_artifact) = if let Ok(native_artifact) =
                    tx_validity_artifact_from_native_tx_leaf_bytes(args.proof.clone())
                {
                    (None, Some(native_artifact))
                } else {
                    let proof =
                        pallet_shielded_pool::types::StarkProof::from_bytes(args.proof.clone());
                    let binding_hash = pallet_shielded_pool::types::BindingHash {
                        data: args.binding_hash,
                    };
                    let proof_bytes =
                        resolve_sidecar_proof_bytes(&proof, &binding_hash, pending_proofs)?;
                    let materialized = build_transaction_proof(
                        proof_bytes,
                        nullifiers.clone(),
                        args.commitments.clone(),
                        &ciphertexts,
                        args.anchor,
                        args.balance_slot_asset_ids,
                        args.stablecoin.clone(),
                        args.fee,
                        0,
                    )?;
                    (Some(materialized), None)
                };
                let tx_artifact = match (tx_artifact, tx_proof.as_ref()) {
                    (Some(tx_artifact), _) => Some(tx_artifact),
                    (None, Some(tx_proof)) => {
                        Some(tx_validity_artifact_from_proof(tx_proof).map_err(|err| {
                            format!("inline tx artifact derivation failed: {err}")
                        })?)
                    }
                    (None, None) => None,
                };
                let tx = if let Some(ref tx_proof) = tx_proof {
                    crate::transaction::proof_to_transaction(&tx_proof, version, ciphertexts)
                } else {
                    let ciphertext_hashes = ciphertexts
                        .iter()
                        .map(|ciphertext| ciphertext_hash_bytes(ciphertext))
                        .collect::<Vec<_>>();
                    let materialized_public = materialize_transaction_public_inputs_with_hashes(
                        nullifiers.clone(),
                        args.commitments.clone(),
                        ciphertext_hashes,
                        args.anchor,
                        args.balance_slot_asset_ids,
                        args.stablecoin.clone(),
                        args.fee,
                        0,
                    )?;
                    consensus::types::Transaction::new(
                        nullifiers.clone(),
                        args.commitments.clone(),
                        materialized_public.public_inputs.balance_tag,
                        version,
                        ciphertexts,
                    )
                };
                transactions.push(tx);
                tx_validity_artifacts.push(tx_artifact);
                if let Some(tx_proof) = tx_proof {
                    proofs.push(tx_proof);
                    proof_binding_hashes.push(args.binding_hash);
                }
            }
            ShieldedFamilyAction::TransferSidecar { nullifiers, args } => {
                let nullifiers_vec = nullifiers.clone();
                let commitments_vec = args.commitments.clone();
                let hash_vec = args.ciphertext_hashes.clone();
                let maybe_ciphertexts = next_resolved_ciphertexts()?;
                let proof = pallet_shielded_pool::types::StarkProof::from_bytes(args.proof.clone());
                let binding_hash = pallet_shielded_pool::types::BindingHash {
                    data: args.binding_hash,
                };
                let maybe_proof_bytes = match resolve_sidecar_proof_bytes(
                    &proof,
                    &binding_hash,
                    pending_proofs,
                ) {
                    Ok(bytes) => Some(bytes),
                    Err(err) if allow_missing_sidecar_proofs && proof.data.is_empty() => {
                        tracing::debug!(
                            binding_hash = %hex::encode(binding_hash.data),
                            error = %err,
                            "Missing unsigned sidecar proof bytes; continuing with statement-only transaction extraction"
                        );
                        None
                    }
                    Err(err) => return Err(err),
                };
                let mut tx_artifact = None;
                let tx_proof = match (maybe_proof_bytes.as_ref(), maybe_ciphertexts.as_ref()) {
                    (Some(proof_bytes), Some(ciphertexts)) => {
                        validate_ciphertexts_against_hashes(
                            ciphertexts,
                            &args.ciphertext_sizes,
                            &args.ciphertext_hashes,
                        )?;
                        let materialized = build_transaction_proof(
                            proof_bytes.clone(),
                            nullifiers_vec.clone(),
                            commitments_vec.clone(),
                            ciphertexts,
                            args.anchor,
                            args.balance_slot_asset_ids,
                            args.stablecoin.clone(),
                            args.fee,
                            0,
                        )?;
                        if let Ok(native_artifact) =
                            tx_validity_artifact_from_native_tx_leaf_bytes(proof_bytes.clone())
                        {
                            tx_artifact = Some(native_artifact);
                            None
                        } else {
                            tx_artifact =
                                Some(tx_validity_artifact_from_proof(&materialized).map_err(
                                    |err| format!("inline tx artifact derivation failed: {err}"),
                                )?);
                            Some(materialized)
                        }
                    }
                    (Some(proof_bytes), None) => {
                        let materialized = build_transaction_proof_with_hashes(
                            proof_bytes.clone(),
                            nullifiers_vec.clone(),
                            commitments_vec.clone(),
                            &hash_vec,
                            args.anchor,
                            args.balance_slot_asset_ids,
                            args.stablecoin.clone(),
                            args.fee,
                            0,
                        )?;
                        if let Ok(native_artifact) =
                            tx_validity_artifact_from_native_tx_leaf_bytes(proof_bytes.clone())
                        {
                            tx_artifact = Some(native_artifact);
                            None
                        } else {
                            tx_artifact =
                                Some(tx_validity_artifact_from_proof(&materialized).map_err(
                                    |err| format!("inline tx artifact derivation failed: {err}"),
                                )?);
                            Some(materialized)
                        }
                    }
                    (None, Some(ciphertexts)) => {
                        validate_ciphertexts_against_hashes(
                            ciphertexts,
                            &args.ciphertext_sizes,
                            &args.ciphertext_hashes,
                        )?;
                        None
                    }
                    (None, None) => None,
                };
                let materialized_public = materialize_transaction_public_inputs_with_hashes(
                    nullifiers_vec.clone(),
                    commitments_vec.clone(),
                    hash_vec.clone(),
                    args.anchor,
                    args.balance_slot_asset_ids,
                    args.stablecoin.clone(),
                    args.fee,
                    0,
                )?;
                let tx = match (tx_proof.as_ref(), maybe_ciphertexts) {
                    (Some(proof), Some(ciphertexts)) => {
                        crate::transaction::proof_to_transaction(proof, version, ciphertexts)
                    }
                    (Some(proof), None) => consensus::types::Transaction::new_with_hashes(
                        nullifiers_vec,
                        commitments_vec,
                        proof.public_inputs.balance_tag,
                        version,
                        hash_vec,
                    ),
                    (None, Some(ciphertexts)) => consensus::types::Transaction::new(
                        nullifiers_vec,
                        commitments_vec,
                        materialized_public.public_inputs.balance_tag,
                        version,
                        ciphertexts,
                    ),
                    (None, None) => consensus::types::Transaction::new_with_hashes(
                        nullifiers_vec,
                        commitments_vec,
                        materialized_public.public_inputs.balance_tag,
                        version,
                        hash_vec,
                    ),
                };
                transactions.push(tx);
                tx_validity_artifacts.push(tx_artifact);
                if let Some(tx_proof) = tx_proof {
                    proofs.push(tx_proof);
                    proof_binding_hashes.push(args.binding_hash);
                }
            }
            ShieldedFamilyAction::BatchTransfer { .. } => {
                return Err(
                    "batch shielded transfers are not supported in block proof generation".into(),
                );
            }
            _ => {}
        }
    }

    if let Some(resolved) = resolved_ciphertexts {
        if ciphertext_cursor != resolved.len() {
            return Err("resolved ciphertexts count mismatch".to_string());
        }
    }

    if proof_binding_hashes.len() != proofs.len() {
        return Err(format!(
            "proof binding hash count mismatch after extraction (expected {}, got {})",
            proofs.len(),
            proof_binding_hashes.len()
        ));
    }

    Ok((
        transactions,
        proofs,
        tx_validity_artifacts,
        proof_binding_hashes,
    ))
}

fn load_parent_commitment_tree_state(
    client: &HegemonFullClient,
    parent_hash: H256,
) -> Result<consensus::CommitmentTreeState, String> {
    let api = client.runtime_api();
    let tree = api
        .compact_merkle_tree(parent_hash)
        .map_err(|e| format!("runtime api error (compact_merkle_tree): {e:?}"))?;
    let history = api
        .merkle_root_history(parent_hash)
        .map_err(|e| format!("runtime api error (merkle_root_history): {e:?}"))?;

    consensus::CommitmentTreeState::from_compact_parts(
        consensus::COMMITMENT_TREE_DEPTH,
        0,
        tree.leaf_count,
        tree.root,
        tree.frontier,
        history,
    )
    .map_err(|err| format!("commitment tree snapshot invalid: {err}"))
}

fn nullifier_root_from_list(nullifiers: &[[u8; 48]]) -> Result<[u8; 48], String> {
    let mut entries = BTreeSet::new();
    for nf in nullifiers {
        if *nf == [0u8; 48] {
            continue;
        }
        if !entries.insert(*nf) {
            return Err("duplicate nullifier in block".into());
        }
    }

    let mut data = Vec::with_capacity(entries.len() * 48);
    for nf in entries {
        data.extend_from_slice(&nf);
    }

    Ok(blake3_384(&data))
}

fn kernel_root_from_shielded_root(root: &[u8; 48]) -> [u8; 48] {
    protocol_kernel::compute_kernel_global_root(vec![(
        runtime::manifest::FAMILY_SHIELDED_POOL,
        *root,
    )])
}

fn hash_bytes_to_felts(bytes: &[u8; 48]) -> [Felt; 6] {
    let mut felts = [Felt::new(0); 6];
    for (idx, chunk) in bytes.chunks(8).enumerate() {
        let limb = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk"));
        felts[idx] = Felt::new(limb);
    }
    felts
}

fn bytes48_to_felts_checked(label: &str, value: &[u8; 48]) -> Result<[Felt; 6], String> {
    bytes48_to_felts(value).ok_or_else(|| format!("{label} encoding is non-canonical"))
}

fn decode_nullifier_list(label: &str, nullifiers: &[[u8; 48]]) -> Result<Vec<[Felt; 6]>, String> {
    let mut felts = Vec::with_capacity(nullifiers.len());
    for (idx, nf) in nullifiers.iter().enumerate() {
        let value = bytes48_to_felts_checked(&format!("{label}[{idx}]"), nf)?;
        felts.push(value);
    }
    Ok(felts)
}

fn derive_nullifier_challenges(
    starting_state_root: &[u8; 48],
    ending_state_root: &[u8; 48],
    starting_kernel_root: &[u8; 48],
    ending_kernel_root: &[u8; 48],
    nullifier_root: &[u8; 48],
    da_root: &[u8; 48],
    tx_count: u32,
    nullifiers: &[[u8; 48]],
    sorted_nullifiers: &[[u8; 48]],
) -> (Felt, Felt) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"blk-nullifier-perm-v1");
    hasher.update(starting_state_root);
    hasher.update(ending_state_root);
    hasher.update(starting_kernel_root);
    hasher.update(ending_kernel_root);
    hasher.update(nullifier_root);
    hasher.update(da_root);
    hasher.update(&tx_count.to_le_bytes());
    hasher.update(&(nullifiers.len() as u64).to_le_bytes());
    hasher.update(&(sorted_nullifiers.len() as u64).to_le_bytes());
    for nullifier in nullifiers {
        hasher.update(nullifier);
    }
    for nullifier in sorted_nullifiers {
        hasher.update(nullifier);
    }
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    let mut alpha = Felt::new(u64::from_le_bytes(
        bytes[0..8].try_into().expect("8-byte alpha"),
    ));
    let mut beta = Felt::new(u64::from_le_bytes(
        bytes[8..16].try_into().expect("8-byte beta"),
    ));
    if alpha == Felt::new(0) {
        alpha = Felt::new(1);
    }
    if beta == Felt::new(0) {
        beta = Felt::new(2);
    }
    (alpha, beta)
}

fn derive_commitment_block_proof_from_bytes(
    proof_bytes: Vec<u8>,
    transactions: &[consensus::types::Transaction],
    statement_hashes: &[[u8; 48]],
    parent_tree: &consensus::CommitmentTreeState,
    da_params: DaParams,
    da_root_override: Option<DaRoot>,
) -> Result<CommitmentBlockProof, String> {
    let lists = consensus::commitment_nullifier_lists(transactions)
        .map_err(|err| format!("commitment proof nullifier lists: {err}"))?;
    let da_root = match da_root_override {
        Some(root) => root,
        None => consensus::da_root(transactions, da_params)
            .map_err(|err| format!("commitment proof da_root encoding failed: {err}"))?,
    };
    let nullifier_root = nullifier_root_from_list(&lists.nullifiers)?;

    if statement_hashes.len() != transactions.len() {
        return Err(format!(
            "tx statement hash count mismatch (expected {}, got {})",
            transactions.len(),
            statement_hashes.len()
        ));
    }
    let tx_statements_commitment =
        CommitmentBlockProver::commitment_from_statement_hashes(statement_hashes)
            .map_err(|err| format!("tx_statements_commitment failed: {err}"))?;

    let mut tree = parent_tree.clone();
    for tx in transactions {
        for commitment in tx.commitments.iter().copied().filter(|c| *c != [0u8; 48]) {
            tree.append(commitment)
                .map_err(|err| format!("commitment tree append failed: {err}"))?;
        }
    }

    let starting_state_root = parent_tree.root();
    let ending_state_root = tree.root();
    let starting_kernel_root = kernel_root_from_shielded_root(&starting_state_root);
    let ending_kernel_root = kernel_root_from_shielded_root(&ending_state_root);
    let tx_count = transactions.len() as u32;
    let (perm_alpha, perm_beta) = derive_nullifier_challenges(
        &starting_state_root,
        &ending_state_root,
        &starting_kernel_root,
        &ending_kernel_root,
        &nullifier_root,
        &da_root,
        tx_count,
        &lists.nullifiers,
        &lists.sorted_nullifiers,
    );

    let public_inputs = CommitmentBlockPublicInputs {
        tx_statements_commitment: bytes48_to_felts_checked(
            "tx_statements_commitment",
            &tx_statements_commitment,
        )?,
        starting_state_root: bytes48_to_felts_checked("starting_state_root", &starting_state_root)?,
        ending_state_root: bytes48_to_felts_checked("ending_state_root", &ending_state_root)?,
        starting_kernel_root: bytes48_to_felts_checked(
            "starting_kernel_root",
            &starting_kernel_root,
        )?,
        ending_kernel_root: bytes48_to_felts_checked("ending_kernel_root", &ending_kernel_root)?,
        nullifier_root: hash_bytes_to_felts(&nullifier_root),
        da_root: hash_bytes_to_felts(&da_root),
        tx_count,
        perm_alpha,
        perm_beta,
        nullifiers: decode_nullifier_list("nullifiers", &lists.nullifiers)?,
        sorted_nullifiers: decode_nullifier_list("sorted_nullifiers", &lists.sorted_nullifiers)?,
    };

    Ok(CommitmentBlockProof {
        proof_hash: blake3_384(&proof_bytes),
        proof_bytes,
        public_inputs,
    })
}

fn verify_proof_carrying_block(
    verifier: &ParallelProofVerifier,
    client: &HegemonFullClient,
    parent_hash: H256,
    block_number: u64,
    extrinsics: &[runtime::UncheckedExtrinsic],
    da_params: DaParams,
    da_policy: pallet_shielded_pool::types::DaAvailabilityPolicy,
    resolved_ciphertexts: Option<&[Vec<Vec<u8>>]>,
    pending_proofs: Option<&PendingProofStore>,
) -> Result<Option<CommitmentBlockProof>, String> {
    use consensus::ProofVerifier;

    let proven_batch_payload = extract_proven_batch_payload(extrinsics)?;
    ensure_shielded_transfer_ordering(extrinsics)?;
    ensure_forced_inclusions(client, parent_hash, block_number, extrinsics)?;
    let (transactions, tx_proofs, extracted_tx_artifacts, _proof_binding_hashes) =
        extract_shielded_transfers_for_parallel_verification(
            extrinsics,
            resolved_ciphertexts,
            pending_proofs,
            true,
        )?;
    let missing_proof_bindings = missing_proof_binding_hashes(extrinsics);
    let proof_policy = fetch_proof_availability_policy(client, parent_hash)?;
    let aggregation_mode_enabled = extrinsics.iter().any(|extrinsic| {
        matches!(
            shielded_action_from_extrinsic(extrinsic),
            Some((_, ShieldedFamilyAction::EnableAggregationMode))
        )
    });

    if transactions.is_empty() {
        if proven_batch_payload.is_some() {
            return Err("proven batch present for block with no shielded transfers".into());
        }
        return Ok(None);
    }

    if !aggregation_mode_enabled {
        return Err(
            "non-empty shielded blocks require enable_aggregation_mode on the product path"
                .to_string(),
        );
    }
    if !matches!(
        proof_policy,
        pallet_shielded_pool::types::ProofAvailabilityPolicy::SelfContained
    ) {
        return Err(
            "non-empty shielded blocks require ProofAvailabilityPolicy::SelfContained".to_string(),
        );
    }

    let tx_proof_bytes_total: usize = tx_proofs.iter().map(|proof| proof.stark_proof.len()).sum();
    let extracted_tx_artifacts = extracted_tx_artifacts
        .into_iter()
        .collect::<Option<Vec<_>>>();
    let tx_statement_bindings = if let Some(ref tx_artifacts) = extracted_tx_artifacts {
        consensus::tx_statement_bindings_from_tx_artifacts(&transactions, tx_artifacts)
            .map_err(|err| format!("tx statement bindings from tx artifacts failed: {err}"))?
    } else {
        statement_bindings_from_extrinsics(extrinsics)?
    };
    if tx_statement_bindings.len() != transactions.len() {
        return Err(format!(
            "tx statement binding count mismatch (expected {}, got {})",
            transactions.len(),
            tx_statement_bindings.len()
        ));
    }
    let extrinsics_bytes_total: usize = extrinsics.iter().map(|ext| ext.encode().len()).sum();
    let da_blob_bytes_estimate = da_layout_from_extrinsics(extrinsics)
        .map(|layouts| da_blob_len_from_layouts(&layouts))
        .unwrap_or(0);
    let parent_tree = load_parent_commitment_tree_state(client, parent_hash)?;
    let proven_batch_payload = proven_batch_payload.ok_or_else(|| {
        "non-empty shielded blocks require submit_candidate_artifact in the same block".to_string()
    })?;

    let payload = proven_batch_payload.payload;
    if payload.version != pallet_shielded_pool::types::BLOCK_PROOF_BUNDLE_SCHEMA {
        return Err(format!(
            "unsupported proven batch version {}",
            payload.version
        ));
    }
    if payload.tx_count != transactions.len() as u32 {
        return Err("proven batch tx_count mismatch".to_string());
    }
    ensure_product_receipt_root_payload(&payload)?;
    ensure_native_only_receipt_root_payload(&payload)?;
    receipt_root_lane_requires_embedded_proof_bytes(
        payload.proof_kind,
        missing_proof_bindings.len(),
    )?;
    let aggregation_payload_bytes = block_proof_payload_aggregation_bytes(&payload);
    let verification_mode = consensus::types::ProofVerificationMode::SelfContainedAggregation;
    if aggregation_payload_bytes == 0 {
        return Err("self-contained aggregation block is missing aggregation proof".to_string());
    }

    let requires_full_fetch = matches!(
        da_policy,
        pallet_shielded_pool::types::DaAvailabilityPolicy::FullFetch
    );
    if requires_full_fetch {
        if transactions
            .iter()
            .any(|tx| tx.ciphertexts.is_empty() && !tx.ciphertext_hashes.is_empty())
        {
            return Err("full DA policy requires resolved ciphertext bytes".to_string());
        }
        let expected_encoding = consensus::encode_da_blob(&transactions, da_params)
            .map_err(|err| format!("commitment proof da_root encoding failed: {err}"))?;
        let expected_da_root = expected_encoding.root();
        let expected_chunk_count = expected_encoding.chunks().len() as u32;
        if expected_da_root != payload.da_root {
            return Err("commitment proof da_root mismatch".to_string());
        }
        if expected_chunk_count != payload.da_chunk_count {
            return Err("commitment proof da_chunk_count mismatch".to_string());
        }
    } else if payload.da_chunk_count == 0 {
        return Err("commitment proof da_chunk_count missing".to_string());
    }

    let statement_hashes = tx_statement_bindings
        .iter()
        .map(|binding| binding.statement_hash)
        .collect::<Vec<_>>();
    let tx_statements_commitment =
        CommitmentBlockProver::commitment_from_statement_hashes(&statement_hashes)
            .map_err(|err| format!("tx_statements_commitment failed: {err}"))?;
    if payload.tx_statements_commitment != tx_statements_commitment {
        return Err("proven batch tx_statements_commitment mismatch".to_string());
    }
    let commitment_proof = derive_commitment_block_proof_from_bytes(
        payload.commitment_proof.data.clone(),
        &transactions,
        &statement_hashes,
        &parent_tree,
        da_params,
        Some(payload.da_root),
    )?;
    let tx_validity_artifacts = extracted_tx_artifacts.clone();
    let receipt_root = payload
        .receipt_root
        .as_ref()
        .ok_or_else(|| "receipt_root payload missing from canonical native bundle".to_string())?;
    let block_artifact = Some(consensus::ProofEnvelope {
        kind: crate::substrate::artifact_market::consensus_proof_artifact_kind_from_pallet(
            payload.proof_kind,
        ),
        verifier_profile: payload.verifier_profile,
        artifact_bytes: receipt_root.root_proof.data.clone(),
    });

    let proven_batch_bytes = payload.commitment_proof.data.len() + aggregation_payload_bytes;
    tracing::info!(
        target: "node::metrics",
        block_number,
        tx_count = transactions.len(),
        extrinsics_bytes_total,
        da_blob_bytes_estimate,
        tx_proof_bytes_total,
        proven_batch_present = true,
        proven_batch_bytes,
        proven_batch_build_ms = 0u128,
        proven_batch_stale_count = 0u64,
        commitment_proof_bytes = payload.commitment_proof.data.len(),
        aggregation_proof_bytes = aggregation_payload_bytes,
        da_chunk_count = payload.da_chunk_count,
        da_root = %hex::encode(payload.da_root),
        da_policy = ?da_policy,
        proof_policy = ?proof_policy,
        aggregation_mode_enabled,
        verification_mode = ?verification_mode,
        "block_payload_size_metrics"
    );

    let block = consensus::types::Block {
        header: SubstrateProofHeader { da_params },
        transactions,
        coinbase: None,
        proven_batch: Some(consensus::types::ProvenBatch {
            mode: crate::substrate::artifact_market::consensus_proven_batch_mode_from_pallet(
                payload.proof_mode,
            ),
            version: payload.version,
            tx_count: payload.tx_count,
            tx_statements_commitment: payload.tx_statements_commitment,
            da_root: payload.da_root,
            da_chunk_count: payload.da_chunk_count,
            commitment_proof: commitment_proof.clone(),
            proof_kind:
                crate::substrate::artifact_market::consensus_proof_artifact_kind_from_pallet(
                    payload.proof_kind,
                ),
            verifier_profile: payload.verifier_profile,
            receipt_root: Some(consensus::types::ReceiptRootProofPayload {
                root_proof: receipt_root.root_proof.data.clone(),
                metadata: consensus::types::ReceiptRootMetadata {
                    params_fingerprint:
                        consensus::experimental_native_receipt_root_params_fingerprint(),
                    relation_id: receipt_root.metadata.relation_id,
                    shape_digest: receipt_root.metadata.shape_digest,
                    leaf_count: receipt_root.metadata.leaf_count,
                    fold_count: receipt_root.metadata.fold_count,
                },
                receipts: receipt_root
                    .receipts
                    .iter()
                    .cloned()
                    .map(|receipt| consensus::types::TxValidityReceipt {
                        statement_hash: receipt.statement_hash,
                        proof_digest: receipt.proof_digest,
                        public_inputs_digest: receipt.public_inputs_digest,
                        verifier_profile: receipt.verifier_profile,
                    })
                    .collect(),
            }),
        }),
        tx_validity_artifacts,
        block_artifact,
        tx_statement_bindings: Some(tx_statement_bindings.clone()),
        tx_statements_commitment: Some(tx_statements_commitment),
        proof_verification_mode: verification_mode,
    };

    let start_verify = Instant::now();
    verifier
        .verify_block(&block, &parent_tree)
        .map_err(|err| format!("proof verification failed ({err:?}): {err}"))?;
    let verify_ms = start_verify.elapsed().as_millis();
    tracing::info!(
        target: "node::metrics",
        block_number,
        verify_ms,
        proven_batch_present = block.proven_batch.is_some(),
        "block_import_verify_time_ms"
    );

    Ok(Some(commitment_proof))
}

// =============================================================================
// DenyUnsafe RPC Middleware
// =============================================================================
//
// This middleware injects DenyUnsafe extension into RPC requests so that
// Substrate's author RPC can check whether unsafe methods are allowed.

/// RPC middleware that injects DenyUnsafe extension into requests
#[derive(Clone)]
struct DenyUnsafeMiddleware<S> {
    inner: S,
    deny_unsafe: sc_rpc::DenyUnsafe,
}

impl<'a, S> jsonrpsee::server::middleware::rpc::RpcServiceT<'a> for DenyUnsafeMiddleware<S>
where
    S: jsonrpsee::server::middleware::rpc::RpcServiceT<'a> + Send + Sync + Clone + 'static,
{
    type Future = S::Future;

    fn call(&self, mut req: jsonrpsee::types::Request<'a>) -> Self::Future {
        req.extensions_mut().insert(self.deny_unsafe);
        self.inner.call(req)
    }
}

/// Type alias for the inherent data providers creator
///
/// PoW import checks use this to supply timestamp inherent data and to
/// gracefully handle shielded coinbase inherent validation during import.
#[derive(Clone, Copy, Default)]
pub struct ShieldedCoinbaseInherentErrorHandler;

#[async_trait::async_trait]
impl InherentDataProvider for ShieldedCoinbaseInherentErrorHandler {
    async fn provide_inherent_data(
        &self,
        _inherent_data: &mut InherentData,
    ) -> Result<(), sp_inherents::Error> {
        Ok(())
    }

    async fn try_handle_error(
        &self,
        identifier: &sp_inherents::InherentIdentifier,
        _error: &[u8],
    ) -> Option<Result<(), sp_inherents::Error>> {
        if identifier == &pallet_shielded_pool::SHIELDED_COINBASE_INHERENT_IDENTIFIER {
            Some(Ok(()))
        } else {
            None
        }
    }
}

type PowInherentProviders = (
    sp_timestamp::InherentDataProvider,
    ShieldedCoinbaseInherentErrorHandler,
);
type PowInherentDataProviders = fn(
    <runtime::Block as sp_runtime::traits::Block>::Hash,
    (),
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<PowInherentProviders, Box<dyn std::error::Error + Send + Sync>>,
            > + Send,
    >,
>;

/// Concrete type for the PoW block import with timestamp inherent providers
pub type ConcretePowBlockImport = HegemonPowBlockImport<PowInherentDataProviders>;

/// Re-export the runtime WASM binary for node use
#[cfg(feature = "substrate")]
pub use runtime::WASM_BINARY;

/// Check that the WASM binary is available
#[cfg(feature = "substrate")]
pub fn check_wasm() -> Result<(), String> {
    #[cfg(feature = "substrate")]
    {
        if WASM_BINARY.is_none() {
            return Err(
                "WASM binary not available. Build with `cargo build -p runtime --features std`."
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn load_max_shielded_transfers_per_block() -> usize {
    let configured = env_usize("HEGEMON_MAX_SHIELDED_TRANSFERS_PER_BLOCK").unwrap_or(usize::MAX);
    if configured == 0 {
        tracing::warn!(
            "HEGEMON_MAX_SHIELDED_TRANSFERS_PER_BLOCK is zero; no shielded transfers will be included"
        );
    }
    configured
}

fn load_min_ready_proven_batch_txs() -> usize {
    env_usize("HEGEMON_MIN_READY_PROVEN_BATCH_TXS")
        .unwrap_or(1)
        .max(1)
}

fn load_aggregation_proofs_enabled() -> bool {
    std::env::var("HEGEMON_AGGREGATION_PROOFS")
        .ok()
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

fn load_hold_mining_while_proving() -> bool {
    std::env::var("HEGEMON_AGG_HOLD_MINING_WHILE_PROVING")
        .ok()
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

fn load_proofless_ready_wait() -> Duration {
    let wait_ms = env_usize("HEGEMON_PROOFLESS_READY_WAIT_MS")
        .unwrap_or(1_500)
        .min(30_000) as u64;
    Duration::from_millis(wait_ms)
}

fn is_shielded_transfer_call(call: &runtime::RuntimeCall) -> bool {
    matches!(
        shielded_action_from_runtime_call(call),
        Some((_, ShieldedFamilyAction::TransferInline { .. }))
            | Some((_, ShieldedFamilyAction::TransferSidecar { .. }))
            | Some((_, ShieldedFamilyAction::BatchTransfer { .. }))
    )
}

fn is_proofless_shielded_transfer_call(call: &runtime::RuntimeCall) -> bool {
    match shielded_action_from_runtime_call(call) {
        Some((_, ShieldedFamilyAction::TransferInline { args, .. })) => args.proof.is_empty(),
        Some((_, ShieldedFamilyAction::TransferSidecar { args, .. })) => args.proof.is_empty(),
        _ => false,
    }
}

fn is_sidecar_shielded_transfer_call(call: &runtime::RuntimeCall) -> bool {
    matches!(
        shielded_action_from_runtime_call(call),
        Some((_, ShieldedFamilyAction::TransferSidecar { .. }))
    )
}

fn proofless_binding_hash_from_call(call: &runtime::RuntimeCall) -> Option<[u8; 64]> {
    match shielded_action_from_runtime_call(call) {
        Some((_, ShieldedFamilyAction::TransferInline { args, .. })) => {
            args.proof.is_empty().then_some(args.binding_hash)
        }
        Some((_, ShieldedFamilyAction::TransferSidecar { args, .. })) => {
            args.proof.is_empty().then_some(args.binding_hash)
        }
        _ => None,
    }
}

fn sidecar_ciphertext_hashes_from_call(call: &runtime::RuntimeCall) -> Option<Vec<[u8; 48]>> {
    match shielded_action_from_runtime_call(call) {
        Some((_, ShieldedFamilyAction::TransferSidecar { args, .. })) => {
            Some(args.ciphertext_hashes)
        }
        _ => None,
    }
}

fn ready_proofless_binding_hashes_for_preview(
    prover_coordinator: &ProverCoordinator,
    parent_hash: H256,
    preview_extrinsics: &[runtime::UncheckedExtrinsic],
    min_ready_batch_txs: usize,
    lookup_wait: Duration,
) -> Result<BTreeSet<[u8; 64]>, String> {
    let mut candidate = preview_extrinsics.to_vec();

    loop {
        let missing = missing_proof_binding_hashes(&candidate);
        if missing.is_empty() {
            return Ok(BTreeSet::new());
        }

        let statement_bindings =
            statement_bindings_for_candidate_extrinsics(&candidate, None, None, true)?;
        let statement_hashes = statement_bindings
            .iter()
            .map(|binding| binding.statement_hash)
            .collect::<Vec<_>>();
        let shielded_tx_count = statement_hashes.len() as u32;
        if shielded_tx_count == 0 {
            return Ok(BTreeSet::new());
        }
        if shielded_tx_count < min_ready_batch_txs as u32 {
            return Ok(BTreeSet::new());
        }

        let tx_statements_commitment =
            CommitmentBlockProver::commitment_from_statement_hashes(&statement_hashes)
                .map_err(|err| format!("tx_statements_commitment preflight failed: {err}"))?;

        let mut ready = prover_coordinator.lookup_prepared_bundle(
            parent_hash,
            tx_statements_commitment,
            shielded_tx_count,
        );
        if ready.is_none() && !lookup_wait.is_zero() {
            let deadline = Instant::now() + lookup_wait;
            while ready.is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(25));
                ready = prover_coordinator.lookup_prepared_bundle(
                    parent_hash,
                    tx_statements_commitment,
                    shielded_tx_count,
                );
            }
        }
        if ready.is_some() {
            return Ok(missing.into_iter().collect());
        }
        let diagnostics = prover_coordinator.prepared_lookup_diagnostics(
            parent_hash,
            tx_statements_commitment,
            shielded_tx_count,
        );
        tracing::debug!(
            target: "prover::lookup",
            parent_hash = ?parent_hash,
            tx_count = shielded_tx_count,
            tx_statements_commitment = %hex::encode(tx_statements_commitment),
            missing_proof_bindings = missing.len(),
            ?diagnostics,
            "No prepared bundle match for proofless preview candidate"
        );

        let Some(drop_idx) = candidate
            .iter()
            .rposition(|extrinsic| is_proofless_shielded_transfer_call(&extrinsic.function))
        else {
            return Ok(BTreeSet::new());
        };
        candidate.remove(drop_idx);
    }
}

fn mining_pause_reason_for_pending_shielded_batch(
    prover_coordinator: &ProverCoordinator,
    parent_hash: H256,
    candidate_txs: &[Vec<u8>],
    min_ready_batch_txs: usize,
    selector: PreparedArtifactSelector,
) -> Result<Option<String>, String> {
    if candidate_txs.is_empty() {
        return Ok(None);
    }

    let mut decoded = Vec::with_capacity(candidate_txs.len());
    for ext_bytes in candidate_txs {
        let extrinsic = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..])
            .map_err(|e| format!("failed to decode candidate extrinsic: {e:?}"))?;
        decoded.push(extrinsic);
    }

    let statement_bindings =
        statement_bindings_for_candidate_extrinsics(&decoded, None, None, true)?;
    let shielded_tx_count = statement_bindings.len() as u32;
    if shielded_tx_count == 0 || shielded_tx_count < min_ready_batch_txs as u32 {
        return Ok(None);
    }

    let require_ready_bundle = matches!(
        selector.proof_kind,
        pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot
    );
    let missing = missing_proof_binding_hashes(&decoded);
    if !require_ready_bundle && missing.is_empty() {
        return Ok(None);
    }

    let statement_hashes = statement_bindings
        .iter()
        .map(|binding| binding.statement_hash)
        .collect::<Vec<_>>();
    let tx_statements_commitment =
        CommitmentBlockProver::commitment_from_statement_hashes(&statement_hashes)
            .map_err(|err| format!("tx_statements_commitment preflight failed: {err}"))?;

    if prover_coordinator
        .lookup_prepared_bundle(parent_hash, tx_statements_commitment, shielded_tx_count)
        .is_some()
    {
        return Ok(None);
    }

    let reason = match selector.proof_kind {
        pallet_shielded_pool::types::ProofArtifactKind::InlineTx => format!(
            "inline_tx shielded batch waiting for prepared bundle (tx_count={})",
            shielded_tx_count
        ),
        pallet_shielded_pool::types::ProofArtifactKind::TxLeaf => return Ok(None),
        pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot => format!(
            "receipt_root shielded batch waiting for prepared bundle (tx_count={}, missing_bindings={})",
            shielded_tx_count,
            missing.len()
        ),
        pallet_shielded_pool::types::ProofArtifactKind::Custom(_) => return Ok(None),
    };
    Ok(Some(reason))
}

#[derive(Clone, Debug)]
struct ReadyBundleTrace {
    bundle_id: String,
    artifact_hash: [u8; 32],
    tx_statements_commitment: [u8; 48],
    tx_count: u32,
    parent_hash: H256,
    block_number: u64,
}

fn ready_bundle_trace_for_candidate(
    prover_coordinator: &ProverCoordinator,
    parent_hash: H256,
    block_number: u64,
    candidate_txs: &[Vec<u8>],
    min_ready_batch_txs: usize,
    selector: PreparedArtifactSelector,
) -> Result<Option<ReadyBundleTrace>, String> {
    if candidate_txs.is_empty() {
        return Ok(None);
    }

    let mut decoded = Vec::with_capacity(candidate_txs.len());
    for ext_bytes in candidate_txs {
        let extrinsic = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..])
            .map_err(|e| format!("failed to decode candidate extrinsic: {e:?}"))?;
        decoded.push(extrinsic);
    }

    let statement_bindings =
        statement_bindings_for_candidate_extrinsics(&decoded, None, None, true)?;
    let shielded_tx_count = statement_bindings.len() as u32;
    if shielded_tx_count == 0 || shielded_tx_count < min_ready_batch_txs as u32 {
        return Ok(None);
    }

    let require_ready_bundle = matches!(
        selector.proof_kind,
        pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot
    );
    let missing = missing_proof_binding_hashes(&decoded);
    if !require_ready_bundle && missing.is_empty() {
        return Ok(None);
    }

    let statement_hashes = statement_bindings
        .iter()
        .map(|binding| binding.statement_hash)
        .collect::<Vec<_>>();
    let tx_statements_commitment =
        CommitmentBlockProver::commitment_from_statement_hashes(&statement_hashes)
            .map_err(|err| format!("tx_statements_commitment preflight failed: {err}"))?;

    let Some(ready_batch) = prover_coordinator.lookup_prepared_bundle(
        parent_hash,
        tx_statements_commitment,
        shielded_tx_count,
    ) else {
        return Ok(None);
    };

    Ok(Some(ReadyBundleTrace {
        bundle_id: ProverCoordinator::final_bundle_id(
            parent_hash,
            block_number,
            tx_statements_commitment,
            shielded_tx_count,
        ),
        artifact_hash: ready_batch.key.artifact_hash,
        tx_statements_commitment,
        tx_count: shielded_tx_count,
        parent_hash,
        block_number,
    }))
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn shielded_transfer_order_key_material(
    binding_hash: Option<[u8; 64]>,
    nullifiers: &[[u8; 48]],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    if let Some(binding_hash) = binding_hash {
        bytes.extend_from_slice(&binding_hash);
    }
    for nf in nullifiers {
        bytes.extend_from_slice(nf);
    }
    sp_core::hashing::blake2_256(&bytes)
}

fn shielded_transfer_key_from_extrinsic(
    extrinsic: &runtime::UncheckedExtrinsic,
) -> Option<[u8; 32]> {
    match shielded_action_from_extrinsic(extrinsic) {
        Some((_, ShieldedFamilyAction::TransferInline { args, nullifiers })) => Some(
            shielded_transfer_order_key_material(Some(args.binding_hash), &nullifiers),
        ),
        Some((_, ShieldedFamilyAction::TransferSidecar { args, nullifiers })) => Some(
            shielded_transfer_order_key_material(Some(args.binding_hash), &nullifiers),
        ),
        Some((_, ShieldedFamilyAction::BatchTransfer { nullifiers, .. })) => {
            Some(shielded_transfer_order_key_material(None, &nullifiers))
        }
        _ => None,
    }
}

fn parent_shielded_transfer_keys(
    client: &HegemonFullClient,
    parent_hash: H256,
) -> Result<std::collections::HashSet<[u8; 32]>, String> {
    let parent_body = client
        .block_body(parent_hash)
        .map_err(|err| format!("failed to load parent block body: {err}"))?;

    let mut keys = std::collections::HashSet::new();
    if let Some(extrinsics) = parent_body {
        for extrinsic in extrinsics {
            if let Some(key) = shielded_transfer_key_from_extrinsic(&extrinsic) {
                keys.insert(key);
            }
        }
    }
    Ok(keys)
}

fn filter_parent_included_shielded_transfers(
    extrinsics: &[Vec<u8>],
    parent_keys: &std::collections::HashSet<[u8; 32]>,
) -> Result<(Vec<Vec<u8>>, usize), String> {
    if parent_keys.is_empty() {
        return Ok((extrinsics.to_vec(), 0));
    }

    let mut filtered = Vec::with_capacity(extrinsics.len());
    let mut dropped = 0usize;
    for ext_bytes in extrinsics {
        let extrinsic = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..])
            .map_err(|e| format!("failed to decode extrinsic: {e:?}"))?;
        let is_parent_duplicate = shielded_transfer_key_from_extrinsic(&extrinsic)
            .map(|key| parent_keys.contains(&key))
            .unwrap_or(false);
        if is_parent_duplicate {
            dropped = dropped.saturating_add(1);
        } else {
            filtered.push(ext_bytes.clone());
        }
    }
    Ok((filtered, dropped))
}

fn sanitize_coordinator_candidate_extrinsics_for_parent(
    extrinsics: &[Vec<u8>],
    parent_keys: &std::collections::HashSet<[u8; 32]>,
) -> Result<(Vec<Vec<u8>>, ShieldedConflictFilterStats, usize), String> {
    let ordered = reorder_shielded_transfers(extrinsics)?;
    let (filtered, filter_stats) = filter_conflicting_shielded_transfers(&ordered);
    let (filtered, dropped_parent_duplicates) =
        filter_parent_included_shielded_transfers(&filtered, parent_keys)?;
    Ok((filtered, filter_stats, dropped_parent_duplicates))
}

fn ensure_shielded_transfer_ordering(
    extrinsics: &[runtime::UncheckedExtrinsic],
) -> Result<(), String> {
    let mut prev: Option<[u8; 32]> = None;
    for extrinsic in extrinsics {
        let Some(key) = shielded_transfer_key_from_extrinsic(extrinsic) else {
            continue;
        };
        if let Some(prev_key) = prev {
            if key < prev_key {
                return Err("shielded transfer ordering violation".to_string());
            }
        }
        prev = Some(key);
    }
    Ok(())
}

fn ensure_forced_inclusions(
    _client: &HegemonFullClient,
    _parent_hash: H256,
    _block_number: u64,
    _extrinsics: &[runtime::UncheckedExtrinsic],
) -> Result<(), String> {
    Ok(())
}

fn reorder_shielded_transfers(extrinsics: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    let mut shielded = Vec::new();
    let mut is_shielded = Vec::with_capacity(extrinsics.len());

    for ext_bytes in extrinsics {
        let extrinsic = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..])
            .map_err(|e| format!("failed to decode extrinsic: {e:?}"))?;
        if let Some(key) = shielded_transfer_key_from_extrinsic(&extrinsic) {
            shielded.push((key, ext_bytes.clone()));
            is_shielded.push(true);
        } else {
            is_shielded.push(false);
        }
    }

    shielded.sort_by(|a, b| a.0.cmp(&b.0));
    let mut shielded_iter = shielded.into_iter();
    let mut out = Vec::with_capacity(extrinsics.len());
    for (ext_bytes, flagged) in extrinsics.iter().zip(is_shielded.iter()) {
        if *flagged {
            let (_, bytes) = shielded_iter
                .next()
                .ok_or_else(|| "shielded transfer ordering mismatch".to_string())?;
            out.push(bytes);
        } else {
            out.push(ext_bytes.clone());
        }
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, Default)]
struct ShieldedConflictFilterStats {
    total: usize,
    kept: usize,
    dropped_decode_errors: usize,
    dropped_binding_conflicts: usize,
    dropped_nullifier_conflicts: usize,
}

impl ShieldedConflictFilterStats {
    fn dropped_total(&self) -> usize {
        self.dropped_decode_errors
            .saturating_add(self.dropped_binding_conflicts)
            .saturating_add(self.dropped_nullifier_conflicts)
    }
}

fn shielded_conflict_keys_from_action(
    action: &ShieldedFamilyAction,
) -> Option<(Option<[u8; 64]>, Vec<[u8; 48]>)> {
    match action {
        ShieldedFamilyAction::TransferInline { args, nullifiers } => Some((
            Some(args.binding_hash),
            nullifiers
                .iter()
                .copied()
                .filter(|nf| *nf != [0u8; 48])
                .collect(),
        )),
        ShieldedFamilyAction::TransferSidecar { args, nullifiers } => Some((
            Some(args.binding_hash),
            nullifiers
                .iter()
                .copied()
                .filter(|nf| *nf != [0u8; 48])
                .collect(),
        )),
        ShieldedFamilyAction::BatchTransfer { nullifiers, .. } => Some((
            None,
            nullifiers
                .iter()
                .copied()
                .filter(|nf| *nf != [0u8; 48])
                .collect(),
        )),
        _ => None,
    }
}

fn filter_conflicting_shielded_transfers(
    extrinsics: &[Vec<u8>],
) -> (Vec<Vec<u8>>, ShieldedConflictFilterStats) {
    let mut out = Vec::with_capacity(extrinsics.len());
    let mut stats = ShieldedConflictFilterStats {
        total: extrinsics.len(),
        ..Default::default()
    };
    let mut seen_binding_hashes = std::collections::HashSet::<[u8; 64]>::new();

    for ext_bytes in extrinsics {
        let decoded = match runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..]) {
            Ok(extrinsic) => extrinsic,
            Err(_) => {
                stats.dropped_decode_errors = stats.dropped_decode_errors.saturating_add(1);
                continue;
            }
        };

        let mut conflict = false;
        if let Some((_, action)) = shielded_action_from_extrinsic(&decoded) {
            if let Some((binding_hash, nullifiers)) = shielded_conflict_keys_from_action(&action) {
                if let Some(binding_hash) = binding_hash {
                    if !seen_binding_hashes.insert(binding_hash) {
                        stats.dropped_binding_conflicts =
                            stats.dropped_binding_conflicts.saturating_add(1);
                        conflict = true;
                    }
                }
                if !conflict && !nullifiers.is_empty() {
                    tracing::debug!(
                        nullifier_count = nullifiers.len(),
                        "Retaining nullifier-conflicting shielded candidate for runtime selection"
                    );
                }
            }
        }

        if !conflict {
            out.push(ext_bytes.clone());
        }
    }

    stats.kept = out.len();
    (out, stats)
}

fn split_shielded_fee_buckets(extrinsics: &[Vec<u8>]) -> Result<BlockFeeBuckets, String> {
    let mut decoded = Vec::with_capacity(extrinsics.len());
    for ext_bytes in extrinsics {
        let extrinsic = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..])
            .map_err(|e| format!("failed to decode extrinsic: {e:?}"))?;
        decoded.push(extrinsic);
    }
    split_shielded_fee_buckets_from_decoded(&decoded)
}

fn split_shielded_fee_buckets_from_decoded(
    extrinsics: &[runtime::UncheckedExtrinsic],
) -> Result<BlockFeeBuckets, String> {
    let mut buckets = BlockFeeBuckets::default();
    for extrinsic in extrinsics {
        let Some((_, action)) = shielded_action_from_extrinsic(extrinsic) else {
            continue;
        };

        let miner_tip = match action {
            ShieldedFamilyAction::TransferInline { args, .. } => u128::from(args.fee),
            ShieldedFamilyAction::TransferSidecar { args, .. } => u128::from(args.fee),
            ShieldedFamilyAction::BatchTransfer { args, .. } => args.total_fee,
            _ => continue,
        };

        buckets.miner_fees = buckets
            .miner_fees
            .checked_add(miner_tip)
            .ok_or_else(|| "shielded fee total overflowed".to_string())?;
    }
    Ok(buckets)
}

// =============================================================================
// Wire BlockBuilder API with StorageChanges capture
// =============================================================================
//
// This function connects the ProductionChainStateProvider's execute_extrinsics_fn
// callback to use sc_block_builder::BlockBuilder which provides:
// - Block building with proper state execution
// - StorageChanges capture for persisting state during import
//
// The key improvement is using BlockBuilder.build() which returns
// BuiltBlock containing StorageChanges. These changes are cached and later
// used in wire_pow_block_import() with StateAction::ApplyChanges.

/// Wires the BlockBuilder to the ProductionChainStateProvider
///
/// This connects the `execute_extrinsics_fn` callback to use `sc_block_builder::BlockBuilder`
/// for block execution. This is the key fix because BlockBuilder:
///
/// 1. Executes extrinsics against runtime state
/// 2. Computes the correct state_root
/// 3. **Returns StorageChanges** which we cache for block import
///
/// The StorageChanges are stored in a global cache (STORAGE_CHANGES_CACHE) and
/// an RAII handle is returned in StateExecutionResult.storage_changes (so discarded templates
/// do not leak memory).
/// When wire_pow_block_import imports the block, it retrieves the changes
/// and uses StateAction::ApplyChanges instead of StateAction::Skip.
///
/// # Flow
///
/// ```text
/// execute_extrinsics_fn()
///   → BlockBuilder::new(client)
///   → builder.create_inherents(inherent_data)
///   → builder.push(extrinsic) for each tx
///   → builder.build() → BuiltBlock { block, storage_changes, proof }
///   → cache_storage_changes(storage_changes) → handle (contains key)
///   → return StateExecutionResult { ..., storage_changes: Some(handle) }
///
/// wire_pow_block_import()
///   → take_storage_changes(key) → Some(changes)
///   → import_params.state_action = StateAction::ApplyChanges(changes)
///   → client.import_block(import_params) → state persisted!
/// ```
pub fn wire_block_builder_api(
    chain_state: &Arc<ProductionChainStateProvider>,
    client: Arc<HegemonFullClient>,
    pending_ciphertext_store: Arc<ParkingMutex<PendingCiphertextStore>>,
    pending_proof_store: Arc<ParkingMutex<PendingProofStore>>,
    prover_coordinator: Arc<ProverCoordinator>,
    _da_params: DaParams,
    _commitment_block_fast: bool,
) {
    use sc_block_builder::BlockBuilderBuilder;

    let client_for_exec = client;
    let aggregation_proofs_enabled = load_aggregation_proofs_enabled();
    let max_shielded_transfers_per_block = load_max_shielded_transfers_per_block();
    let min_ready_proven_batch_txs = load_min_ready_proven_batch_txs();
    let proofless_ready_wait = load_proofless_ready_wait();

    if min_ready_proven_batch_txs > 1 {
        tracing::info!(
            min_ready_proven_batch_txs,
            "Proofless transfers require a ready proven batch of at least this size before inclusion"
        );
    }
    if !proofless_ready_wait.is_zero() {
        tracing::info!(
            proofless_ready_wait_ms = proofless_ready_wait.as_millis() as u64,
            "Proofless inclusion waits briefly for newly prepared bundles before deferring"
        );
    }

    // Capture the miner's shielded address
    let miner_shielded_address = chain_state.miner_shielded_address();

    // Log coinbase configuration
    if let Some(ref address) = miner_shielded_address {
        tracing::info!(
            address = %address,
            "Shielded coinbase enabled for miner"
        );
    } else {
        tracing::warn!("No shielded miner address configured - coinbase rewards disabled");
    }

    // Parse shielded address once outside the closure
    let parsed_shielded_address = miner_shielded_address.as_ref().and_then(|addr| {
        match crate::shielded_coinbase::parse_shielded_address(addr) {
            Ok(parsed) => Some(parsed),
            Err(e) => {
                tracing::error!(
                    error = ?e,
                    address = %addr,
                    "Failed to parse shielded miner address - coinbase disabled"
                );
                None
            }
        }
    });
    let pending_ciphertext_store_for_exec = Arc::clone(&pending_ciphertext_store);
    let pending_proof_store_for_exec = Arc::clone(&pending_proof_store);

    chain_state.set_execute_extrinsics_fn(move |parent_hash, block_number, extrinsics| {
        // Convert our H256 to the runtime's Hash type
        let parent_substrate_hash: sp_core::H256 = (*parent_hash).into();

        tracing::info!(
            block_number,
            parent = %hex::encode(parent_hash.as_bytes()),
            tx_count = extrinsics.len(),
            "Building block with sc_block_builder"
        );

        // Create inherent data for timestamp
        let mut inherent_data = InherentData::new();
        let timestamp_provider = sp_timestamp::InherentDataProvider::from_system_time();
        if let Err(e) = futures::executor::block_on(
            timestamp_provider.provide_inherent_data(&mut inherent_data)
        ) {
            tracing::warn!(error = ?e, "Failed to provide timestamp inherent data");
        }

        // Coinbase is attached after transfers so the amount can include per-block fees.

        // Create BlockBuilder using the builder pattern
        // This is the sc_block_builder::BlockBuilder, not the runtime API
        let mut block_builder = match BlockBuilderBuilder::new(&*client_for_exec)
            .on_parent_block(parent_substrate_hash)
            .fetch_parent_block_number(&*client_for_exec)
        {
            Ok(stage2) => match stage2.build() {
                Ok(builder) => builder,
                Err(e) => {
                    return Err(format!("Failed to create BlockBuilder: {:?}", e));
                }
            },
            Err(e) => {
                return Err(format!("Failed to fetch parent block number: {:?}", e));
            }
        };

        let block_builder_api_version = client_for_exec
            .runtime_api()
            .api_version::<dyn sp_block_builder::BlockBuilder<runtime::Block>>(parent_substrate_hash)
            .ok()
            .flatten();

        tracing::info!(
            block_number,
            block_builder_api_version = ?block_builder_api_version,
            extrinsic_inclusion_mode = ?block_builder.extrinsic_inclusion_mode(),
            "BlockBuilder created"
        );

        // Create inherent extrinsics (timestamp, coinbase, etc.)
        let inherent_extrinsics = match block_builder.create_inherents(inherent_data.clone()) {
            Ok(exts) => {
                tracing::info!(
                    count = exts.len(),
                    "Created {} inherent extrinsics",
                    exts.len()
                );
                for (i, ext) in exts.iter().enumerate() {
                    let inherent_kind = if matches!(
                        &ext.function,
                        runtime::RuntimeCall::Timestamp(pallet_timestamp::Call::set { .. })
                    ) {
                        "timestamp"
                    } else {
                        "non_timestamp"
                    };
                    let encoded = ext.encode();
                    tracing::info!(
                        index = i,
                        inherent_kind,
                        encoded_len = encoded.len(),
                        first_bytes = %hex::encode(&encoded[..encoded.len().min(20)]),
                        "Inherent extrinsic {}", i
                    );
                }
                exts
            },
            Err(e) => {
                tracing::warn!(error = ?e, "Failed to create inherent extrinsics");
                Vec::new()
            }
        };

        // Push inherent extrinsics
        let mut shielded_transfer_count = 0usize;
        let mut applied = Vec::new();
        let has_timestamp_inherent = inherent_extrinsics.iter().any(|ext| {
            matches!(
                &ext.function,
                runtime::RuntimeCall::Timestamp(pallet_timestamp::Call::set { .. })
            )
        });
        if !has_timestamp_inherent {
            let now = timestamp_provider.timestamp().as_millis();
            let timestamp_ext = runtime::UncheckedExtrinsic::new_unsigned(
                runtime::RuntimeCall::Timestamp(pallet_timestamp::Call::set { now }),
            );
            match block_builder.push(timestamp_ext.clone()) {
                Ok(_) => {
                    applied.push(timestamp_ext.encode());
                    tracing::info!(now, "Injected explicit timestamp inherent");
                }
                Err(e) => {
                    return Err(format!(
                        "Failed to push explicit timestamp inherent: {:?}",
                        e
                    ));
                }
            }
        }
        for inherent_ext in inherent_extrinsics {
            let is_shielded = is_shielded_transfer_call(&inherent_ext.function);
            match block_builder.push(inherent_ext.clone()) {
                Ok(_) => {
                    applied.push(inherent_ext.encode());
                    if is_shielded {
                        shielded_transfer_count = shielded_transfer_count.saturating_add(1);
                    }
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "Failed to push inherent extrinsic");
                }
            }
        }

        // Push user extrinsics
        let mut failed = 0usize;
        let pending_ciphertexts_for_filter = { pending_ciphertext_store_for_exec.lock().clone() };
        tracing::debug!(
            block_number,
            pending_ciphertext_entries = pending_ciphertexts_for_filter.entries.len(),
            "Captured pending sidecar stores for authoring"
        );
        let ordered_extrinsics = reorder_shielded_transfers(&extrinsics)?;
        let (ordered_extrinsics, filter_stats) =
            filter_conflicting_shielded_transfers(&ordered_extrinsics);
        if filter_stats.dropped_total() > 0 {
            tracing::warn!(
                block_number,
                total_candidates = filter_stats.total,
                kept_candidates = filter_stats.kept,
                dropped_decode_errors = filter_stats.dropped_decode_errors,
                dropped_binding_conflicts = filter_stats.dropped_binding_conflicts,
                dropped_nullifier_conflicts = filter_stats.dropped_nullifier_conflicts,
                "Filtered conflicting shielded transfers before block assembly"
            );
        }
        let parent_keys = parent_shielded_transfer_keys(
            client_for_exec.as_ref(),
            parent_substrate_hash,
        )?;
        let (ordered_extrinsics, dropped_parent_duplicates) =
            filter_parent_included_shielded_transfers(&ordered_extrinsics, &parent_keys)?;
        if dropped_parent_duplicates > 0 {
            tracing::info!(
                block_number,
                dropped_parent_duplicates,
                parent_shielded_transfer_count = parent_keys.len(),
                "Dropped shielded transfers already included in parent block"
            );
        }
        let proof_policy =
            fetch_proof_availability_policy(client_for_exec.as_ref(), parent_substrate_hash)?;
        let selected_artifact = prepared_artifact_selector_from_env();
        let prepared_bundle_mode_enabled = matches!(
            selected_artifact.proof_kind,
            pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot
        );
        let mut defer_proofless_until_ready_batch = false;
        let mut aggregation_mode_required_for_block = false;
        let mut ready_proofless_bindings: Option<BTreeSet<[u8; 64]>> = None;
        if aggregation_proofs_enabled && prepared_bundle_mode_enabled {
            let mut preview_extrinsics = Vec::new();
            for ext_bytes in &applied {
                if let Ok(extrinsic) = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..]) {
                    preview_extrinsics.push(extrinsic);
                }
            }
            preview_extrinsics.push(kernel_shielded_extrinsic(
                ACTION_ENABLE_AGGREGATION_MODE,
                Vec::new(),
                EnableAggregationModeArgs.encode(),
            ));

            let mut preview_shielded_count = shielded_transfer_count;
            let mut preview_has_shielded_transfers = false;
            for ext_bytes in &ordered_extrinsics {
                let Ok(extrinsic) = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..]) else {
                    continue;
                };
                let is_shielded = is_shielded_transfer_call(&extrinsic.function);
                if is_shielded && preview_shielded_count >= max_shielded_transfers_per_block {
                    continue;
                }
                preview_extrinsics.push(extrinsic);
                if is_shielded {
                    preview_has_shielded_transfers = true;
                    preview_shielded_count = preview_shielded_count.saturating_add(1);
                }
            }

            if preview_has_shielded_transfers {
                aggregation_mode_required_for_block = true;
            }
            let missing_preview = missing_proof_binding_hashes(&preview_extrinsics);
            if !missing_preview.is_empty() {
                aggregation_mode_required_for_block = true;
                let pending_proofs_snapshot = { pending_proof_store_for_exec.lock().clone() };
                let pending_matches =
                    pending_proof_match_count(&missing_preview, &pending_proofs_snapshot);
                tracing::debug!(
                    block_number,
                    missing_proof_bindings = missing_preview.len(),
                    pending_proof_entries = pending_proofs_snapshot.len(),
                    pending_proof_matches = pending_matches,
                    "Proofless preview coverage against pending proof snapshot"
                );
                if !matches!(
                    proof_policy,
                    pallet_shielded_pool::types::ProofAvailabilityPolicy::SelfContained
                ) {
                    defer_proofless_until_ready_batch = true;
                    tracing::warn!(
                        block_number,
                        missing_proof_bindings = missing_preview.len(),
                        ?proof_policy,
                        "Deferring proofless sidecar transfers: ProofAvailabilityPolicy is not SelfContained"
                    );
                } else {
                    let ready_bindings = ready_proofless_binding_hashes_for_preview(
                        prover_coordinator.as_ref(),
                        parent_substrate_hash,
                        &preview_extrinsics,
                        min_ready_proven_batch_txs,
                        proofless_ready_wait,
                    )?;
                    if ready_bindings.is_empty() {
                        defer_proofless_until_ready_batch = true;
                        tracing::warn!(
                            block_number,
                            missing_proof_bindings = missing_preview.len(),
                            min_ready_proven_batch_txs,
                            "Deferring proofless sidecar transfers until a proven batch is ready (strict mode)"
                        );
                    } else {
                        let deferred = missing_preview.len().saturating_sub(ready_bindings.len());
                        if deferred > 0 {
                            defer_proofless_until_ready_batch = true;
                            tracing::warn!(
                                block_number,
                                ready_proofless_sidecar = ready_bindings.len(),
                                deferred_proofless_sidecar = deferred,
                                min_ready_proven_batch_txs,
                                "Using ready proofless subset while larger proven batch is still building"
                            );
                        } else {
                            tracing::debug!(
                                block_number,
                                ready_proofless_sidecar = ready_bindings.len(),
                                min_ready_proven_batch_txs,
                                "Ready proven batch found for full proofless candidate set"
                            );
                        }
                        ready_proofless_bindings = Some(ready_bindings);
                    }
                }
            }
        }

        if aggregation_proofs_enabled && prepared_bundle_mode_enabled && aggregation_mode_required_for_block {
            let enable_extrinsic = kernel_shielded_extrinsic(
                ACTION_ENABLE_AGGREGATION_MODE,
                Vec::new(),
                EnableAggregationModeArgs.encode(),
            );
            match block_builder.push(enable_extrinsic.clone()) {
                Ok(_) => {
                    applied.push(enable_extrinsic.encode());
                    tracing::info!(
                        block_number,
                        "Aggregation mode enabled (runtime skips per-tx proof verification)"
                    );
                }
                Err(e) => {
                    return Err(format!(
                        "failed to push enable_aggregation_mode extrinsic: {e:?}"
                    ));
                }
            }
        }

        let mut deferred_proofless_sidecar_count = 0usize;
        let mut deferred_missing_ciphertext_sidecar_count = 0usize;
        for ext_bytes in ordered_extrinsics {
            match runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..]) {
                Ok(extrinsic) => {
                    let is_shielded = is_shielded_transfer_call(&extrinsic.function);
                    let is_sidecar_shielded =
                        is_sidecar_shielded_transfer_call(&extrinsic.function);
                    let is_proofless_sidecar =
                        is_proofless_shielded_transfer_call(&extrinsic.function);
                    if let Some(ciphertext_hashes) =
                        sidecar_ciphertext_hashes_from_call(&extrinsic.function)
                    {
                        if !pending_ciphertexts_for_filter.contains_all(&ciphertext_hashes) {
                            deferred_missing_ciphertext_sidecar_count =
                                deferred_missing_ciphertext_sidecar_count.saturating_add(1);
                            tracing::warn!(
                                block_number,
                                missing_ciphertext_hashes = ciphertext_hashes.len(),
                                "Deferring sidecar shielded transfer: ciphertext bytes not available locally"
                            );
                            continue;
                        }
                    }
                    if !aggregation_proofs_enabled
                        && is_proofless_sidecar
                    {
                        tracing::warn!(
                            block_number,
                            "Skipping proofless shielded transfer: HEGEMON_AGGREGATION_PROOFS is disabled"
                        );
                        continue;
                    }
                    if !prepared_bundle_mode_enabled && is_proofless_sidecar {
                        tracing::warn!(
                            block_number,
                            proof_kind = ?selected_artifact.proof_kind,
                            "Skipping proofless shielded transfer: raw inline_tx mode requires canonical inline tx proofs"
                        );
                        continue;
                    }
                    if aggregation_proofs_enabled
                        && prepared_bundle_mode_enabled
                        && defer_proofless_until_ready_batch
                        && is_proofless_sidecar
                    {
                        let allow_ready_subset = ready_proofless_bindings
                            .as_ref()
                            .and_then(|bindings| {
                                proofless_binding_hash_from_call(&extrinsic.function)
                                    .map(|binding_hash| bindings.contains(&binding_hash))
                            })
                            .unwrap_or(false);
                        if allow_ready_subset {
                            tracing::debug!(
                                block_number,
                                "Including proofless shielded transfer from ready subset"
                            );
                        } else {
                        deferred_proofless_sidecar_count =
                            deferred_proofless_sidecar_count.saturating_add(1);
                        tracing::warn!(
                            block_number,
                            "Deferring proofless shielded transfer until proven batch is ready"
                        );
                        continue;
                    }
                    }
                    if is_shielded && shielded_transfer_count >= max_shielded_transfers_per_block {
                        tracing::warn!(
                            block_number,
                            max_shielded_transfers_per_block,
                            "Skipping shielded transfer: block already contains {} (coinbase + transfers)",
                            shielded_transfer_count
                        );
                        continue;
                    }
                    let shielded_key = if is_shielded {
                        shielded_transfer_key_from_extrinsic(&extrinsic).map(hex::encode)
                    } else {
                        None
                    };
                    match block_builder.push(extrinsic) {
                        Ok(_) => {
                            applied.push(ext_bytes.clone());
                            if is_shielded {
                                shielded_transfer_count =
                                    shielded_transfer_count.saturating_add(1);
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                block_number,
                                is_shielded,
                                is_sidecar_shielded,
                                is_proofless_sidecar,
                                shielded_key = shielded_key.as_deref().unwrap_or(""),
                                error = ?e,
                                "Extrinsic push failed during block assembly"
                            );
                            failed += 1;
                        }
                    }
                }
                Err(decode_error) => {
                    tracing::warn!(error = ?decode_error, "Failed to decode extrinsic");
                    failed += 1;
                }
            }
        }

        if aggregation_proofs_enabled && prepared_bundle_mode_enabled && deferred_proofless_sidecar_count > 0 {
            tracing::info!(
                block_number,
                deferred_proofless_sidecar_count,
                included_shielded_transfers = shielded_transfer_count,
                "Deferred proofless sidecar transfers this block"
            );
        }
        if deferred_missing_ciphertext_sidecar_count > 0 {
            tracing::info!(
                block_number,
                deferred_missing_ciphertext_sidecar_count,
                included_shielded_transfers = shielded_transfer_count,
                "Deferred sidecar transfers without local ciphertext bytes"
            );
        }

        let mut decoded_applied = Vec::with_capacity(applied.len());
        for ext_bytes in &applied {
            let extrinsic = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..])
                .map_err(|e| format!("failed to decode extrinsic: {e:?}"))?;
            decoded_applied.push(extrinsic);
        }
        let missing_proof_bindings = missing_proof_binding_hashes(&decoded_applied);
        if !missing_proof_bindings.is_empty() {
            let pending_proofs_snapshot_final = { pending_proof_store_for_exec.lock().clone() };
            let pending_matches =
                pending_proof_match_count(&missing_proof_bindings, &pending_proofs_snapshot_final);
            tracing::debug!(
                block_number,
                missing_proof_bindings = missing_proof_bindings.len(),
                pending_proof_entries = pending_proofs_snapshot_final.len(),
                pending_proof_matches = pending_matches,
                "Final applied block coverage against pending proof snapshot"
            );
        }
        let aggregation_mode_enabled = decoded_applied.iter().any(|extrinsic| {
            matches!(
                shielded_action_from_extrinsic(extrinsic),
                Some((_, ShieldedFamilyAction::EnableAggregationMode))
            )
        });
        if !missing_proof_bindings.is_empty() {
            if !aggregation_mode_enabled {
                return Err(
                    "missing proof bytes are invalid outside aggregation mode".to_string(),
                );
            }
            if !matches!(
                proof_policy,
                pallet_shielded_pool::types::ProofAvailabilityPolicy::SelfContained
            ) {
                return Err(
                    "missing proof bytes require ProofAvailabilityPolicy::SelfContained".to_string(),
                );
            }
        }

        let statement_bindings =
            statement_bindings_for_candidate_extrinsics(&decoded_applied, None, None, false)?;
        let statement_hashes = statement_bindings
            .iter()
            .map(|binding| binding.statement_hash)
            .collect::<Vec<_>>();
        let shielded_tx_count = statement_hashes.len() as u32;
        if shielded_tx_count > 0
            && !matches!(
                proof_policy,
                pallet_shielded_pool::types::ProofAvailabilityPolicy::SelfContained
            )
        {
            return Err(
                "product shielded blocks require ProofAvailabilityPolicy::SelfContained"
                    .to_string(),
            );
        }
        if shielded_tx_count > 0 && !aggregation_mode_enabled {
            return Err(
                "product shielded blocks require enable_aggregation_mode before inclusion"
                    .to_string(),
            );
        }
        let requires_proven_batch = shielded_tx_count > 0;
        let mut template_trace = None;
        if requires_proven_batch {
            let tx_statements_commitment =
                CommitmentBlockProver::commitment_from_statement_hashes(&statement_hashes)
                    .map_err(|err| format!("tx_statements_commitment failed: {err}"))?;
            let ready_batch = prover_coordinator.lookup_prepared_bundle(
                parent_substrate_hash,
                tx_statements_commitment,
                shielded_tx_count,
            );

            if let Some(ready_batch) = ready_batch {
                ensure_runtime_supports_block_proof_bundle_v2(
                    client_for_exec.as_ref(),
                    parent_substrate_hash,
                )?;
                let proof_size = ready_batch.payload.commitment_proof.data.len()
                    + block_proof_payload_aggregation_bytes(&ready_batch.payload);
                let proof_size_uncompressed =
                    block_proof_payload_aggregation_uncompressed_bytes(&ready_batch.payload);
                let proven_batch_extrinsic = kernel_shielded_extrinsic(
                    ACTION_SUBMIT_CANDIDATE_ARTIFACT,
                    Vec::new(),
                    SubmitCandidateArtifactArgs {
                        payload: ready_batch.payload,
                    }
                    .encode(),
                );
                tracing::debug!(
                    block_number,
                    tx_count = shielded_tx_count,
                    proof_size,
                    proof_size_uncompressed,
                    encoded_len = proven_batch_extrinsic.encoded_size(),
                    "Attempting to attach proven batch extrinsic"
                );
                match block_builder.push(proven_batch_extrinsic.clone()) {
                    Ok(_) => {
                        applied.push(proven_batch_extrinsic.encode());
                        tracing::info!(
                            block_number,
                            proof_size,
                            proof_size_uncompressed,
                            proven_batch_build_ms = ready_batch.build_ms,
                            proven_batch_stale_count = prover_coordinator.stale_count(),
                            prepared_parent = ?ready_batch.key.parent_hash,
                            current_parent = ?parent_substrate_hash,
                            "Proven batch extrinsic attached"
                        );
                        template_trace = Some(consensus::MiningWorkTrace {
                            template_id: String::new(),
                            bundle_id: Some(ProverCoordinator::final_bundle_id(
                                parent_substrate_hash,
                                block_number,
                                tx_statements_commitment,
                                shielded_tx_count,
                            )),
                            artifact_hash: Some(hex::encode(ready_batch.key.artifact_hash)),
                            tx_count: shielded_tx_count,
                            tx_statements_commitment: Some(hex::encode(
                                tx_statements_commitment,
                            )),
                        });
                    }
                    Err(e) => {
                        return Err(format!(
                            "failed to push mandatory proven batch extrinsic: {e:?}"
                        ));
                    }
                }
            } else {
                let diagnostics = prover_coordinator.prepared_lookup_diagnostics(
                    parent_substrate_hash,
                    tx_statements_commitment,
                    shielded_tx_count,
                );
                tracing::warn!(
                    block_number,
                    parent_hash = ?parent_substrate_hash,
                    tx_count = shielded_tx_count,
                    tx_statements_commitment = %hex::encode(tx_statements_commitment),
                    ?diagnostics,
                    "Missing prepared receipt_root proven batch for shielded block on the product path"
                );
                return Err(
                    "shielded block requires a ready native receipt_root proven batch on the product path".to_string(),
                );
            }
        }

        let fee_buckets = split_shielded_fee_buckets(&applied)?;

        if let Some(ref address) = parsed_shielded_address {
            let subsidy = pallet_coinbase::block_subsidy(block_number);
            let miner_fees = u64::try_from(fee_buckets.miner_fees)
                .map_err(|_| "miner fee total exceeds u64".to_string())?;
            let miner_amount = subsidy
                .checked_add(miner_fees)
                .ok_or_else(|| "coinbase amount overflowed".to_string())?;

            let mut block_hash_input = [0u8; 40];
            block_hash_input[..32].copy_from_slice(parent_hash.as_bytes());
            block_hash_input[32..40].copy_from_slice(&block_number.to_le_bytes());
            let block_hash: [u8; 32] = blake3::hash(&block_hash_input).into();

            let reward_bundle = crate::shielded_coinbase::encrypt_block_reward_bundle(
                address,
                miner_amount,
                &block_hash,
                block_number,
            )
            .map_err(|e| format!("failed to encrypt block reward bundle: {e}"))?;

            tracing::info!(
                block_number,
                subsidy,
                miner_fees = fee_buckets.miner_fees,
                miner_amount,
                "Encrypting shielded block rewards"
            );
            let coinbase_extrinsic = kernel_shielded_extrinsic(
                ACTION_MINT_COINBASE,
                Vec::new(),
                MintCoinbaseArgs { reward_bundle }.encode(),
            );
            match block_builder.push(coinbase_extrinsic.clone()) {
                Ok(_) => {
                    applied.push(coinbase_extrinsic.encode());
                    tracing::info!(
                        block_number,
                        subsidy,
                        miner_fees = fee_buckets.miner_fees,
                        "Added shielded coinbase extrinsic for block reward"
                    );
                }
                Err(primary_error) => {
                    tracing::warn!(
                        block_number,
                        subsidy,
                        miner_fees = fee_buckets.miner_fees,
                        error = ?primary_error,
                        "Primary shielded coinbase build failed; attempting subsidy-only fallback"
                    );

                    // Keep transaction inclusion live even if fee-derived reward construction
                    // diverges. Try subsidy-only reward first, then continue without coinbase.
                    let fallback_reward_bundle = crate::shielded_coinbase::encrypt_block_reward_bundle(
                        address,
                        subsidy,
                        &block_hash,
                        block_number,
                    )
                    .map_err(|e| format!("failed to encrypt fallback block reward bundle: {e}"))?;

                    let fallback_coinbase = kernel_shielded_extrinsic(
                        ACTION_MINT_COINBASE,
                        Vec::new(),
                        MintCoinbaseArgs {
                            reward_bundle: fallback_reward_bundle,
                        }
                        .encode(),
                    );
                    match block_builder.push(fallback_coinbase.clone()) {
                        Ok(_) => {
                            applied.push(fallback_coinbase.encode());
                            tracing::warn!(
                                block_number,
                                subsidy,
                                "Added subsidy-only fallback shielded coinbase extrinsic"
                            );
                        }
                        Err(fallback_error) => {
                            tracing::warn!(
                                block_number,
                                error = ?fallback_error,
                                "Fallback shielded coinbase also failed; continuing without coinbase for this template"
                            );
                        }
                    }
                }
            }
        }

        // In self-contained aggregation mode, proof sidecar bytes are proposer-local artifacts.
        // They are not published as consensus proof-DA commitments.

        // Build the block - this returns BuiltBlock with StorageChanges!
        let built_block = match block_builder.build() {
            Ok(built) => built,
            Err(e) => {
                return Err(format!("Failed to build block: {:?}", e));
            }
        };

        // Extract the block and header
        // Use the block's header field directly (it's a field, not a method)
        let block = built_block.block;
        let header = &block.header;
        let state_root = *header.state_root();
        let extrinsics_root = *header.extrinsics_root();

        // Cache the StorageChanges for use during import.
        // The returned handle cleans up automatically if the template is discarded.
        let storage_changes = cache_storage_changes(built_block.storage_changes);
        let storage_changes_key = storage_changes.key();

        tracing::info!(
            block_number,
            applied = applied.len(),
            failed,
            state_root = %hex::encode(state_root.as_bytes()),
            extrinsics_root = %hex::encode(extrinsics_root.as_bytes()),
            storage_changes_key,
            "Block built with StorageChanges cached"
        );

        Ok(StateExecutionResult {
            applied_extrinsics: applied,
            state_root,
            extrinsics_root,
            failed_count: failed,
            storage_changes: Some(storage_changes),
            template_trace,
        })
    });

    tracing::info!("BlockBuilder API wired with StorageChanges capture");
}

// =============================================================================
// Wire PoW block import to ProductionChainStateProvider
// =============================================================================
//
// This function wires the PowBlockImport to the chain state provider's
// import_fn callback. When a mined block needs to be imported, the callback
// constructs a proper BlockImportParams and imports through PowBlockImport.
//
// The PowBlockImport verifies the SHA-256d PoW seal before allowing the block
// to be committed to the backend.

use crate::substrate::mining_worker::BlockTemplate;
use sc_consensus::{BlockImport, BlockImportParams, ImportResult};
use sp_consensus::BlockOrigin;
use sp_runtime::generic::Digest;
use sp_runtime::DigestItem;

fn is_retryable_sync_parent_state_error(error: &str) -> bool {
    error.contains("UnknownBlock")
}

fn is_finalized_chain_conflict_error(error: &str) -> bool {
    error.contains("Potential long-range attack: block not in finalized chain")
        || error.contains("NotInFinalizedChain")
}

fn collect_deferred_downloaded_tail<I>(
    current: DownloadedBlock,
    remaining: I,
) -> Vec<DownloadedBlock>
where
    I: IntoIterator<Item = DownloadedBlock>,
{
    let mut deferred = vec![current];
    deferred.extend(remaining);
    deferred
}

fn configure_pow_import_params(
    import_params: &mut BlockImportParams<runtime::Block>,
    seal_item: DigestItem,
    post_hash: <runtime::Block as sp_runtime::traits::Block>::Hash,
) {
    import_params.post_digests.push(seal_item);
    import_params.post_hash = Some(post_hash);

    // Leave fork_choice unset so PowBlockImport applies cumulative-difficulty selection.
    use sc_consensus_pow::{PowIntermediate, INTERMEDIATE_KEY};
    let intermediate = PowIntermediate::<sp_core::U256> { difficulty: None };
    import_params.insert_intermediate(INTERMEDIATE_KEY, intermediate);
}

/// Wire the PoW block import pipeline to a ProductionChainStateProvider.
///
/// This sets the `import_fn` callback on the chain state provider to use
/// the real `PowBlockImport` for importing mined blocks.
///
/// # Implementation
///
/// The import flow:
/// 1. Mining worker finds valid seal via `mine_round()`
/// 2. Calls `chain_state.import_block(template, seal)`
/// 3. `import_fn` callback constructs `BlockImportParams`
/// 4. `PowBlockImport.import_block()` verifies the seal and applies total-difficulty fork choice
/// 5. If valid, block is committed to backend
///
/// # Arguments
///
/// * `chain_state` - The ProductionChainStateProvider to wire
/// * `pow_block_import` - The PowBlockImport wrapper for verified imports
/// * `client` - The full Substrate client for header construction
/// * `da_chunk_store` - Persistent DA chunk store (with in-memory cache) for serving proofs
/// * `pending_ciphertext_store` - Pending sidecar ciphertext pool for block assembly
/// * `pending_proof_store` - Pending sidecar transaction proof pool
/// * `commitment_block_proof_store` - In-memory store for commitment block proofs
/// * `da_params` - DA parameters for encoding chunk data
///
/// # Example
///
/// ```rust,ignore
/// let chain_state = Arc::new(ProductionChainStateProvider::new(config));
/// wire_pow_block_import(
///     &chain_state,
///     pow_block_import,
///     client.clone(),
///     da_chunk_store,
///     pending_ciphertext_store,
///     commitment_block_proof_store,
///     da_params,
/// );
///
/// // Now when mining finds a valid seal:
/// let hash = chain_state.import_block(&template, &seal)?;
/// // Block is imported through PowBlockImport so best-chain selection uses total difficulty
/// ```
///
/// # State Persistence
///
/// This function now retrieves cached StorageChanges from the block building
/// phase and applies them during import using `StateAction::ApplyChanges`.
/// This ensures that runtime state (balances, nonces, etc.) is persisted
/// to the database after block import.
fn wire_pow_block_import(
    chain_state: &Arc<ProductionChainStateProvider>,
    pow_block_import: ConcretePowBlockImport,
    client: Arc<HegemonFullClient>,
    da_chunk_store: Arc<ParkingMutex<DaChunkStore>>,
    pending_ciphertext_store: Arc<ParkingMutex<PendingCiphertextStore>>,
    pending_proof_store: Arc<ParkingMutex<PendingProofStore>>,
    commitment_block_proof_store: Arc<ParkingMutex<CommitmentBlockProofStore>>,
    da_params: DaParams,
) {
    use codec::Encode;
    use sp_runtime::traits::Block as BlockT;

    let block_import = client;
    let pow_block_import = pow_block_import;
    let proof_verification_enabled = proof_verification_enabled();
    let parallel_verifier = ParallelProofVerifier::new();
    chain_state.set_import_fn(move |template: &BlockTemplate, seal: &Sha256dSeal| {
        // Construct the block header from the template
        let parent_hash: sp_core::H256 = template.parent_hash.into();

        // Include the seal in the header's digest for storage
        // Use our custom engine ID "bpow" for SHA-256d PoW
        let seal_bytes = seal.encode();
        let seal_digest = DigestItem::Seal(*b"pow_", seal_bytes);
        let digest = Digest {
            logs: vec![seal_digest],
        };

        let header = <runtime::Header as HeaderT>::new(
            template.number,
            template.extrinsics_root,
            template.state_root,
            parent_hash,
            digest,
        );

        // Get header hash (this is the final block hash including seal)
        let header_hash = header.hash();

        tracing::debug!(
            block_number = template.number,
            block_hash = %hex::encode(header_hash.as_bytes()),
            parent_hash = %hex::encode(parent_hash.as_bytes()),
            "Block import: constructing block"
        );

        // StorageChanges are cached during block building and keyed by a u64. We only `take` them
        // once we know we're ready to import the block; otherwise a failed verification attempt
        // would consume the cache entry and poison subsequent retries for the same template.
        let storage_changes_key = template.storage_changes.as_ref().map(|handle| handle.key());

        // Decode the extrinsics from template
        let encoded_extrinsics: Vec<runtime::UncheckedExtrinsic> = template
            .extrinsics
            .iter()
            .filter_map(|tx_bytes| runtime::UncheckedExtrinsic::decode(&mut &tx_bytes[..]).ok())
            .collect();

        let mut da_build = {
            let pending_guard = pending_ciphertext_store.lock();
            Some(
                build_da_encoding_from_extrinsics(
                    &encoded_extrinsics,
                    da_params,
                    Some(&*pending_guard),
                )
                .map_err(|err| format!("failed to build DA encoding for mined block: {err}"))?,
            )
        };

        let mut commitment_block_proof: Option<CommitmentBlockProof> = None;
        if proof_verification_enabled {
            let da_policy = fetch_da_policy(block_import.as_ref(), template.parent_hash);
            let resolved_ciphertexts = da_build.as_ref().map(|build| build.transactions.as_slice());
            let pending_proofs_snapshot = { pending_proof_store.lock().clone() };
            commitment_block_proof = verify_proof_carrying_block(
                &parallel_verifier,
                block_import.as_ref(),
                template.parent_hash,
                template.number,
                &encoded_extrinsics,
                da_params,
                da_policy,
                resolved_ciphertexts,
                Some(&pending_proofs_snapshot),
            )
            .map_err(|err| format!("mined block proof verification failed: {err}"))?;
        }

        // Construct the block with seal in header so we can derive the final post-seal hash.
        let block = runtime::Block::new(header.clone(), encoded_extrinsics.clone());
        let block_hash = block.hash();
        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes.copy_from_slice(block_hash.as_bytes());

        // PowBlockImport expects the seal in post_digests, not in header.digest().
        let mut header_without_seal = header.clone();
        let seal_item = header_without_seal
            .digest_mut()
            .pop()
            .ok_or_else(|| "mined block header missing PoW seal".to_string())?;

        let mut import_params = BlockImportParams::new(BlockOrigin::Own, header_without_seal);
        import_params.body = Some(encoded_extrinsics);
        configure_pow_import_params(&mut import_params, seal_item, block_hash);

        // Apply StorageChanges if available.
        let storage_changes = match storage_changes_key {
            Some(key) => Some(
                take_storage_changes(key)
                    .ok_or_else(|| format!("StorageChanges not found in cache for key {key}"))?,
            ),
            None => None,
        };
        if let Some(storage_changes) = storage_changes {
            tracing::info!(
                block_number = template.number,
                storage_changes_key,
                "Applying cached StorageChanges during import"
            );
            import_params.state_action = sc_consensus::StateAction::ApplyChanges(
                sc_consensus::StorageChanges::Changes(storage_changes),
            );
        } else {
            // Fallback for blocks built without new mechanism
            tracing::debug!(
                block_number = template.number,
                "No cached StorageChanges on template, using StateAction::Skip"
            );
            import_params.state_action = sc_consensus::StateAction::Skip;
        }

        // Import through PowBlockImport so local mining follows the same seal verification and
        // cumulative-difficulty fork-choice path as network imports.
        //
        // Do not explicitly finalize PoW imports here. Immediate finalization pins the current
        // tip as irreversible and breaks ordinary longest-chain reorg recovery.
        let import_result = futures::executor::block_on(async {
            let import = pow_block_import.clone();
            import.import_block(import_params).await
        });

        match import_result {
            Ok(ImportResult::Imported(_aux)) => {
                let mut store = da_chunk_store.lock();
                let mut ciphertexts = if let Some(build) = da_build.take() {
                    let da_root = build.encoding.root();
                    let da_chunks = build.encoding.chunks().len();
                    let ciphertexts = flatten_ciphertexts(&build.transactions);
                    if let Err(err) = store.insert(
                        DaRootKind::Ciphertexts,
                        template.number,
                        block_hash_bytes,
                        build.encoding,
                    ) {
                        tracing::warn!(
                            block_number = template.number,
                            da_root = %hex::encode(da_root),
                            error = %err,
                            "Failed to persist DA encoding for imported block"
                        );
                    } else {
                        tracing::info!(
                            block_number = template.number,
                            da_root = %hex::encode(da_root),
                            da_chunks,
                            "DA encoding stored for imported block"
                        );
                    }
                    if let Some(mut pending_ciphertexts) = pending_ciphertext_store.try_lock() {
                        pending_ciphertexts.remove_many(&build.used_ciphertext_hashes);
                    } else {
                        tracing::warn!(
                            block_number = template.number,
                            pending_hashes = build.used_ciphertext_hashes.len(),
                            "Pending ciphertext store busy after import; deferring cleanup"
                        );
                    }
                    ciphertexts
                } else {
                    transfer_ciphertexts_from_extrinsics(block.extrinsics())
                };
                ciphertexts.extend(coinbase_ciphertexts_from_extrinsics(block.extrinsics()));
                let ciphertext_count = ciphertexts.len();
                if let Err(err) =
                    store.append_ciphertexts(template.number, block_hash_bytes, &ciphertexts)
                {
                    tracing::warn!(
                        block_number = template.number,
                        error = %err,
                        "Failed to persist ciphertexts for imported block"
                    );
                } else if ciphertext_count > 0 {
                    tracing::info!(
                        block_number = template.number,
                        ciphertext_count,
                        "Ciphertexts stored for imported block"
                    );
                }
                {
                    let binding_hashes = binding_hashes_from_extrinsics(block.extrinsics());
                    if !binding_hashes.is_empty() {
                        if let Some(mut pending_proofs) = pending_proof_store.try_lock() {
                            pending_proofs.remove_many(&binding_hashes);
                        } else {
                            tracing::warn!(
                                block_number = template.number,
                                pending_bindings = binding_hashes.len(),
                                "Pending proof store busy after import; deferring cleanup"
                            );
                        }
                    }
                }
                if let Some(proof) = commitment_block_proof.clone() {
                    let proof_size = proof.proof_bytes.len();
                    let proof_hash = proof.proof_hash;
                    commitment_block_proof_store
                        .lock()
                        .insert(block_hash, proof);
                    tracing::info!(
                        block_number = template.number,
                        block_hash = %hex::encode(block_hash.as_bytes()),
                        proof_size,
                        proof_hash = %hex::encode(proof_hash),
                        "Commitment block proof stored for imported block"
                    );
                }
                tracing::info!(
                    block_hash = %hex::encode(block_hash.as_bytes()),
                    block_number = template.number,
                    "Block imported successfully with state changes applied"
                );
                if let Some(trace) = template.trace.as_ref() {
                    tracing::info!(
                        target: "prover::last_mile",
                        trace_ts_ms = unix_time_ms(),
                        block_hash = %hex::encode(block_hash.as_bytes()),
                        block_number = template.number,
                        parent_hash = %hex::encode(template.parent_hash.as_bytes()),
                        pre_hash = %hex::encode(template.pre_hash.as_bytes()),
                        template_id = %trace.template_id,
                        bundle_id = trace.bundle_id.as_deref().unwrap_or(""),
                        artifact_hash = trace.artifact_hash.as_deref().unwrap_or(""),
                        tx_count = trace.tx_count,
                        tx_statements_commitment = trace
                            .tx_statements_commitment
                            .as_deref()
                            .unwrap_or(""),
                        "block_imported"
                    );
                }
                Ok(block_hash)
            }
            Ok(ImportResult::AlreadyInChain) => {
                let mut store = da_chunk_store.lock();
                let mut ciphertexts = if let Some(build) = da_build.take() {
                    let da_root = build.encoding.root();
                    let da_chunks = build.encoding.chunks().len();
                    let ciphertexts = flatten_ciphertexts(&build.transactions);
                    if let Err(err) = store.insert(
                        DaRootKind::Ciphertexts,
                        template.number,
                        block_hash_bytes,
                        build.encoding,
                    ) {
                        tracing::warn!(
                            block_number = template.number,
                            da_root = %hex::encode(da_root),
                            error = %err,
                            "Failed to persist DA encoding for known block"
                        );
                    } else {
                        tracing::info!(
                            block_number = template.number,
                            da_root = %hex::encode(da_root),
                            da_chunks,
                            "DA encoding stored for known block"
                        );
                    }
                    if let Some(mut pending_ciphertexts) = pending_ciphertext_store.try_lock() {
                        pending_ciphertexts.remove_many(&build.used_ciphertext_hashes);
                    } else {
                        tracing::warn!(
                            block_number = template.number,
                            pending_hashes = build.used_ciphertext_hashes.len(),
                            "Pending ciphertext store busy for known block; deferring cleanup"
                        );
                    }
                    ciphertexts
                } else {
                    transfer_ciphertexts_from_extrinsics(block.extrinsics())
                };
                ciphertexts.extend(coinbase_ciphertexts_from_extrinsics(block.extrinsics()));
                let ciphertext_count = ciphertexts.len();
                if let Err(err) =
                    store.append_ciphertexts(template.number, block_hash_bytes, &ciphertexts)
                {
                    tracing::warn!(
                        block_number = template.number,
                        error = %err,
                        "Failed to persist ciphertexts for known block"
                    );
                } else if ciphertext_count > 0 {
                    tracing::info!(
                        block_number = template.number,
                        ciphertext_count,
                        "Ciphertexts stored for known block"
                    );
                }
                {
                    let binding_hashes = binding_hashes_from_extrinsics(block.extrinsics());
                    if !binding_hashes.is_empty() {
                        if let Some(mut pending_proofs) = pending_proof_store.try_lock() {
                            pending_proofs.remove_many(&binding_hashes);
                        } else {
                            tracing::warn!(
                                block_number = template.number,
                                pending_bindings = binding_hashes.len(),
                                "Pending proof store busy for known block; deferring cleanup"
                            );
                        }
                    }
                }
                if let Some(proof) = commitment_block_proof.clone() {
                    let proof_size = proof.proof_bytes.len();
                    let proof_hash = proof.proof_hash;
                    commitment_block_proof_store
                        .lock()
                        .insert(block_hash, proof);
                    tracing::info!(
                        block_number = template.number,
                        block_hash = %hex::encode(block_hash.as_bytes()),
                        proof_size,
                        proof_hash = %hex::encode(proof_hash),
                        "Commitment block proof stored for known block"
                    );
                }
                tracing::warn!(
                    block_hash = %hex::encode(block_hash.as_bytes()),
                    "Block already in chain"
                );
                Ok(block_hash)
            }
            Ok(ImportResult::KnownBad) => Err(format!(
                "Block {} is known bad",
                hex::encode(block_hash.as_bytes())
            )),
            Ok(ImportResult::UnknownParent) => Err(format!(
                "Unknown parent {} for block {}",
                hex::encode(template.parent_hash.as_bytes()),
                hex::encode(block_hash.as_bytes())
            )),
            Ok(ImportResult::MissingState) => Err(format!(
                "Missing state for parent {}",
                hex::encode(template.parent_hash.as_bytes())
            )),
            Err(e) => Err(format!("Block import failed: {:?}", e)),
        }
    });

    tracing::info!("Block import wired with StorageChanges application");
    tracing::debug!("  - Mined blocks imported with state persistence");
    tracing::debug!("  - SHA-256d seals validated before commit");
}

/// PQ network configuration for the node service
#[derive(Clone, Debug)]
pub struct PqServiceConfig {
    /// Enable verbose PQ handshake logging
    pub verbose_logging: bool,
    /// Listen address for P2P
    pub listen_addr: std::net::SocketAddr,
    /// Bootstrap seeds plus resolved addresses
    pub bootstrap_nodes: Vec<BootstrapNode>,
    /// Maximum peers
    pub max_peers: usize,
}

/// Snapshot of a connected PQ peer for RPC reporting.
#[derive(Clone, Debug)]
pub struct PeerConnectionSnapshot {
    /// Peer identifier (raw 32 bytes).
    pub peer_id: [u8; 32],
    /// Observed socket address.
    pub addr: std::net::SocketAddr,
    /// Whether this connection was outbound.
    pub is_outbound: bool,
    /// Peer's reported best height.
    pub best_height: u64,
    /// Peer's reported best hash.
    pub best_hash: [u8; 32],
    /// Last time we heard from this peer.
    pub last_seen: std::time::Instant,
    /// Total bytes sent on this connection snapshot.
    pub bytes_sent: u64,
    /// Total bytes received on this connection snapshot.
    pub bytes_received: u64,
}

#[derive(Clone, Debug)]
pub struct PeerGraphReport {
    pub reported_at: std::time::Instant,
    pub peers: Vec<crate::substrate::discovery::PeerGraphEntry>,
}

async fn refresh_peer_connection_counters(
    pq_backend: &Arc<PqNetworkBackend>,
    peer_details: &Arc<parking_lot::RwLock<HashMap<PeerId, PeerConnectionSnapshot>>>,
) {
    let infos = pq_backend.peer_info().await;
    if infos.is_empty() {
        return;
    }
    let mut details = peer_details.write();
    for info in infos {
        if let Some(entry) = details.get_mut(&info.peer_id) {
            entry.bytes_sent = info.bytes_sent;
            entry.bytes_received = info.bytes_received;
        }
    }
}

impl Default for PqServiceConfig {
    fn default() -> Self {
        Self {
            verbose_logging: false,
            listen_addr: "0.0.0.0:30333".parse().unwrap(),
            bootstrap_nodes: Vec::new(),
            max_peers: 50,
        }
    }
}

impl PqServiceConfig {
    /// Create from Substrate Configuration with environment variable overrides
    ///
    /// Priority (highest to lowest):
    /// 1. Environment variables (HEGEMON_LISTEN_ADDR, HEGEMON_RPC_PORT, etc.)
    /// 2. Substrate CLI arguments (--port, --rpc-port, etc.)
    /// 3. Defaults
    ///
    /// Environment variables:
    /// - `HEGEMON_PQ_VERBOSE`: Enable verbose logging (default: false)
    /// - `HEGEMON_SEEDS`: Comma-separated list of seed peers (host[:port], defaults to 30333)
    /// - `HEGEMON_LISTEN_ADDR`: Listen address (overrides --port)
    /// - `HEGEMON_MAX_PEERS`: Maximum peers (default: 50)
    pub fn from_config(config: &Configuration) -> Self {
        let verbose = std::env::var("HEGEMON_PQ_VERBOSE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        // Parse bootstrap/seed nodes from environment
        // Supports IP:port, hostname:port, and host/IP without port (defaults to 30333).
        const DEFAULT_P2P_PORT: u16 = 30333;
        let bootstrap_nodes: Vec<BootstrapNode> = std::env::var("HEGEMON_SEEDS")
            .map(|s| {
                let mut nodes = Vec::new();
                for addr in s.split(',') {
                    let addr = addr.trim();
                    if addr.is_empty() {
                        continue;
                    }
                    let normalized_seed =
                        if let Ok(sock_addr) = addr.parse::<std::net::SocketAddr>() {
                            sock_addr.to_string()
                        } else if let Ok(ip_addr) = addr.parse::<std::net::IpAddr>() {
                            std::net::SocketAddr::new(ip_addr, DEFAULT_P2P_PORT).to_string()
                        } else if addr.contains(':') {
                            addr.to_string()
                        } else {
                            format!("{addr}:{DEFAULT_P2P_PORT}")
                        };
                    // First try direct parse (for IP:port)
                    if let Ok(sock_addr) = addr.parse::<std::net::SocketAddr>() {
                        nodes.push(BootstrapNode {
                            seed: normalized_seed,
                            addrs: vec![sock_addr],
                        });
                        continue;
                    }
                    if let Ok(ip_addr) = addr.parse::<std::net::IpAddr>() {
                        nodes.push(BootstrapNode {
                            seed: normalized_seed,
                            addrs: vec![std::net::SocketAddr::new(ip_addr, DEFAULT_P2P_PORT)],
                        });
                        continue;
                    }
                    // If that fails, try DNS resolution (for hostname[:port]). Keep all
                    // resolved addresses so we can fail over between IPv6/IPv4 routes.
                    let resolve_host =
                        |target: &str| -> Result<Vec<std::net::SocketAddr>, std::io::Error> {
                            std::net::ToSocketAddrs::to_socket_addrs(target)
                                .map(|addrs| addrs.collect())
                        };

                    let mut resolved = match resolve_host(addr) {
                        Ok(resolved) if !resolved.is_empty() => resolved,
                        Ok(_) => {
                            tracing::warn!(
                                addr = %addr,
                                "DNS resolved but no addresses returned"
                            );
                            Vec::new()
                        }
                        Err(err) => {
                            if !addr.contains(':') {
                                let with_port = format!("{addr}:{DEFAULT_P2P_PORT}");
                                match resolve_host(&with_port) {
                                    Ok(resolved) if !resolved.is_empty() => {
                                        tracing::info!(
                                            addr = %addr,
                                            resolved_count = resolved.len(),
                                            default_port = DEFAULT_P2P_PORT,
                                            "Resolved seed hostname with default port"
                                        );
                                        resolved
                                    }
                                    Ok(_) => {
                                        tracing::warn!(
                                            addr = %addr,
                                            default_port = DEFAULT_P2P_PORT,
                                            "DNS resolved but no addresses returned"
                                        );
                                        Vec::new()
                                    }
                                    Err(err) => {
                                        tracing::warn!(
                                            addr = %addr,
                                            default_port = DEFAULT_P2P_PORT,
                                            error = %err,
                                            "Failed to resolve seed address"
                                        );
                                        Vec::new()
                                    }
                                }
                            } else {
                                tracing::warn!(
                                    addr = %addr,
                                    error = %err,
                                    "Failed to resolve seed address"
                                );
                                Vec::new()
                            }
                        }
                    };

                    if resolved.is_empty() {
                        continue;
                    }
                    // Prefer IPv4 routes first for environments where IPv6 egress is absent.
                    resolved.sort();
                    resolved.dedup();
                    resolved.sort_by_key(|socket| !socket.ip().is_ipv4());
                    tracing::info!(
                        addr = %addr,
                        resolved = ?resolved,
                        "Resolved seed hostname"
                    );
                    nodes.push(BootstrapNode {
                        seed: normalized_seed,
                        addrs: resolved,
                    });
                }
                nodes
            })
            .unwrap_or_default();

        // Priority: env var > Substrate config > default
        let listen_addr = std::env::var("HEGEMON_LISTEN_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .or_else(|| {
                // Extract port from Substrate network config listen addresses
                // Multiaddr format: /ip4/0.0.0.0/tcp/30333
                config.network.listen_addresses.first().map(|multiaddr| {
                    let s = multiaddr.to_string();
                    // Parse /ip4/X.X.X.X/tcp/PORT or /ip6/.../tcp/PORT
                    let mut ip: std::net::IpAddr =
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
                    let mut port = 30333u16;

                    let parts: Vec<&str> = s.split('/').collect();
                    for i in 0..parts.len() {
                        match parts[i] {
                            "ip4" if i + 1 < parts.len() => {
                                if let Ok(addr) = parts[i + 1].parse::<std::net::Ipv4Addr>() {
                                    ip = std::net::IpAddr::V4(addr);
                                }
                            }
                            "ip6" if i + 1 < parts.len() => {
                                if let Ok(addr) = parts[i + 1].parse::<std::net::Ipv6Addr>() {
                                    ip = std::net::IpAddr::V6(addr);
                                }
                            }
                            "tcp" if i + 1 < parts.len() => {
                                if let Ok(p) = parts[i + 1].parse::<u16>() {
                                    port = p;
                                }
                            }
                            _ => {}
                        }
                    }
                    std::net::SocketAddr::new(ip, port)
                })
            })
            .unwrap_or_else(|| "0.0.0.0:30333".parse().unwrap());

        let max_peers = std::env::var("HEGEMON_MAX_PEERS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                config.network.default_peers_set.in_peers as usize
                    + config.network.default_peers_set.out_peers as usize
            });

        if !bootstrap_nodes.is_empty() {
            tracing::info!(
                seeds = ?bootstrap_nodes,
                "Configured bootstrap nodes from HEGEMON_SEEDS"
            );
        }

        tracing::info!(
            listen_addr = %listen_addr,
            max_peers = max_peers,
            "PQ service config initialized"
        );

        Self {
            verbose_logging: verbose,
            bootstrap_nodes,
            listen_addr,
            max_peers,
        }
    }
}

const PQ_IDENTITY_SEED_ENV: &str = "HEGEMON_PQ_IDENTITY_SEED";
const PQ_IDENTITY_SEED_PATH_ENV: &str = "HEGEMON_PQ_IDENTITY_SEED_PATH";
const PQ_IDENTITY_SEED_FILE: &str = "pq-identity.seed";
const DA_SAMPLING_SECRET_FILE: &str = "da-secret";
const DA_STORE_PATH_ENV: &str = "HEGEMON_DA_STORE_PATH";
const DA_STORE_DIR: &str = "da-store";

fn pq_identity_seed_path(config: &Configuration) -> PathBuf {
    std::env::var(PQ_IDENTITY_SEED_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| config.base_path.path().join(PQ_IDENTITY_SEED_FILE))
}

fn da_sampling_secret_path(config: &Configuration) -> PathBuf {
    config.base_path.path().join(DA_SAMPLING_SECRET_FILE)
}

fn da_store_path(config: &Configuration) -> PathBuf {
    std::env::var(DA_STORE_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| config.base_path.path().join(DA_STORE_DIR))
}

fn parse_pq_identity_seed_hex(value: &str) -> Result<[u8; 32], ServiceError> {
    let trimmed = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    let bytes = hex::decode(trimmed)
        .map_err(|err| ServiceError::Other(format!("invalid PQ identity seed hex: {err}")))?;
    if bytes.len() != 32 {
        return Err(ServiceError::Other(format!(
            "PQ identity seed must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn parse_da_sampling_secret_hex(value: &str) -> Result<[u8; 32], ServiceError> {
    let trimmed = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    let bytes = hex::decode(trimmed)
        .map_err(|err| ServiceError::Other(format!("invalid DA sampling secret hex: {err}")))?;
    if bytes.len() != 32 {
        return Err(ServiceError::Other(format!(
            "DA sampling secret must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes);
    Ok(secret)
}

fn derive_seed(label: &[u8], seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(seed);
    hasher.finalize().into()
}

#[cfg(unix)]
fn warn_if_seed_permissions_loose(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = fs::metadata(path) {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:o}", mode),
                "PQ identity seed permissions are too open; expected 0600"
            );
        }
    }
}

fn load_or_create_pq_identity_seed(config: &Configuration) -> Result<[u8; 32], ServiceError> {
    if let Ok(seed_hex) = std::env::var(PQ_IDENTITY_SEED_ENV) {
        let seed = parse_pq_identity_seed_hex(&seed_hex)?;
        tracing::info!("Using PQ identity seed from HEGEMON_PQ_IDENTITY_SEED");
        return Ok(seed);
    }

    let path = pq_identity_seed_path(config);
    match fs::read_to_string(&path) {
        Ok(contents) => {
            let seed = parse_pq_identity_seed_hex(&contents)?;
            #[cfg(unix)]
            warn_if_seed_permissions_loose(&path);
            tracing::info!(
                path = %path.display(),
                "Loaded PQ identity seed"
            );
            Ok(seed)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    ServiceError::Other(format!(
                        "failed to create PQ identity seed directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }

            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    let encoded = hex::encode(seed);
                    file.write_all(encoded.as_bytes()).map_err(|e| {
                        ServiceError::Other(format!(
                            "failed to write PQ identity seed {}: {e}",
                            path.display()
                        ))
                    })?;
                    file.write_all(b"\n").map_err(|e| {
                        ServiceError::Other(format!(
                            "failed to finalize PQ identity seed {}: {e}",
                            path.display()
                        ))
                    })?;
                    tracing::info!(
                        path = %path.display(),
                        "Generated PQ identity seed"
                    );
                    Ok(seed)
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    let contents = fs::read_to_string(&path).map_err(|e| {
                        ServiceError::Other(format!(
                            "failed to read PQ identity seed {}: {e}",
                            path.display()
                        ))
                    })?;
                    let seed = parse_pq_identity_seed_hex(&contents)?;
                    #[cfg(unix)]
                    warn_if_seed_permissions_loose(&path);
                    Ok(seed)
                }
                Err(err) => Err(ServiceError::Other(format!(
                    "failed to create PQ identity seed {}: {err}",
                    path.display()
                ))),
            }
        }
        Err(err) => Err(ServiceError::Other(format!(
            "failed to read PQ identity seed {}: {err}",
            path.display()
        ))),
    }
}

#[cfg(unix)]
fn warn_if_da_secret_permissions_loose(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = fs::metadata(path) {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:o}", mode),
                "DA sampling secret permissions are too open; expected 0600"
            );
        }
    }
}

fn load_or_create_da_sampling_secret(config: &Configuration) -> Result<[u8; 32], ServiceError> {
    let path = da_sampling_secret_path(config);
    match fs::read_to_string(&path) {
        Ok(contents) => {
            let secret = parse_da_sampling_secret_hex(&contents)?;
            #[cfg(unix)]
            warn_if_da_secret_permissions_loose(&path);
            tracing::info!(
                path = %path.display(),
                "Loaded DA sampling secret"
            );
            Ok(secret)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let secret = state_da::generate_node_secret();
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    ServiceError::Other(format!(
                        "failed to create DA sampling secret directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }

            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    let encoded = hex::encode(secret);
                    file.write_all(encoded.as_bytes()).map_err(|e| {
                        ServiceError::Other(format!(
                            "failed to write DA sampling secret {}: {e}",
                            path.display()
                        ))
                    })?;
                    file.write_all(b"\n").map_err(|e| {
                        ServiceError::Other(format!(
                            "failed to finalize DA sampling secret {}: {e}",
                            path.display()
                        ))
                    })?;
                    tracing::info!(
                        path = %path.display(),
                        "Generated DA sampling secret"
                    );
                    Ok(secret)
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    let contents = fs::read_to_string(&path).map_err(|e| {
                        ServiceError::Other(format!(
                            "failed to read DA sampling secret {}: {e}",
                            path.display()
                        ))
                    })?;
                    let secret = parse_da_sampling_secret_hex(&contents)?;
                    #[cfg(unix)]
                    warn_if_da_secret_permissions_loose(&path);
                    Ok(secret)
                }
                Err(err) => Err(ServiceError::Other(format!(
                    "failed to create DA sampling secret {}: {err}",
                    path.display()
                ))),
            }
        }
        Err(err) => Err(ServiceError::Other(format!(
            "failed to read DA sampling secret {}: {err}",
            path.display()
        ))),
    }
}

const LEGACY_META_COLUMN: u32 = 0;
const LEGACY_DB_NUM_COLUMNS: u32 = 13;
const LEGACY_DB_STATE_COLUMN: u32 = 1;
const LEGACY_DB_STATE_META_COLUMN: u32 = 2;
const LEGACY_DB_HEADER_COLUMN: u32 = 4;
const LEGACY_DB_BODY_COLUMN: u32 = 5;
const LEGACY_DB_JUSTIFICATIONS_COLUMN: u32 = 6;
const LEGACY_DB_TRANSACTION_COLUMN: u32 = 11;
const LEGACY_DB_BODY_INDEX_COLUMN: u32 = 12;
const LEGACY_META_TYPE_KEY: &[u8; 4] = b"type";
const LEGACY_META_BEST_BLOCK_KEY: &[u8; 4] = b"best";
const LEGACY_META_FINALIZED_BLOCK_KEY: &[u8; 5] = b"final";
const LEGACY_META_FINALIZED_STATE_KEY: &[u8; 6] = b"fstate";
const LEGACY_META_GENESIS_HASH_KEY: &[u8; 3] = b"gen";
const LEGACY_DB_TYPE_FULL: &[u8; 4] = b"full";
const LEGACY_STATE_META_LAST_CANONICAL_KEY: &[u8; 14] = b"last_canonical";
const LEGACY_STATE_META_LAST_PRUNED_KEY: &[u8; 11] = b"last_pruned";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LegacyPowTipStateRewind {
    previous_number: u64,
    previous_hash: H256,
    rewound_to_number: u64,
    rewound_to_hash: H256,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LegacyPowRepairOutcome {
    finalized_repair: Option<(u32, H256)>,
    tip_state_rewind: Option<LegacyPowTipStateRewind>,
}

struct LegacyParityDbAdapter(parity_db::Db);

fn maybe_repair_legacy_pow_finality_metadata(config: &Configuration) -> Result<(), ServiceError> {
    let Some(db) = open_legacy_metadata_database(&config.database)? else {
        return Ok(());
    };

    let outcome = repair_legacy_pow_finality_metadata_in_db(db.as_ref())?;

    if let Some((previous_finalized_number, previous_finalized_hash)) = outcome.finalized_repair {
        tracing::warn!(
            previous_finalized_number,
            previous_finalized_hash = %previous_finalized_hash,
            "Downgraded legacy PoW finalized metadata to genesis before backend startup"
        );
    }

    if let Some(rewind) = outcome.tip_state_rewind {
        tracing::warn!(
            previous_number = rewind.previous_number,
            previous_hash = %rewind.previous_hash,
            rewound_to_number = rewind.rewound_to_number,
            rewound_to_hash = %rewind.rewound_to_hash,
            "Rewound legacy PoW state canonical tip by one block before backend startup"
        );
    }

    Ok(())
}

fn open_legacy_metadata_database(
    source: &sc_service::DatabaseSource,
) -> Result<Option<Arc<dyn sp_database::Database<H256>>>, ServiceError> {
    match source {
        sc_service::DatabaseSource::RocksDb { path, .. } => {
            open_legacy_rocksdb_metadata_database(path)
        }
        sc_service::DatabaseSource::ParityDb { path } => {
            open_legacy_paritydb_metadata_database(path)
        }
        sc_service::DatabaseSource::Auto {
            rocksdb_path,
            paritydb_path,
            ..
        } => {
            if let Some(db) = open_legacy_rocksdb_metadata_database(rocksdb_path)? {
                return Ok(Some(db));
            }
            open_legacy_paritydb_metadata_database(paritydb_path)
        }
        sc_service::DatabaseSource::Custom { .. } => Ok(None),
    }
}

fn open_legacy_rocksdb_metadata_database(
    path: &Path,
) -> Result<Option<Arc<dyn sp_database::Database<H256>>>, ServiceError> {
    if !path.exists() {
        return Ok(None);
    }

    let mut config = kvdb_rocksdb::DatabaseConfig::with_columns(LEGACY_DB_NUM_COLUMNS);
    config.create_if_missing = false;
    let db = kvdb_rocksdb::Database::open(&config, path).map_err(|error| {
        ServiceError::Other(format!(
            "failed to open RocksDB metadata for legacy PoW finality repair at {}: {error}",
            path.display()
        ))
    })?;
    Ok(Some(sp_database::as_database(db)))
}

fn open_legacy_paritydb_metadata_database(
    path: &Path,
) -> Result<Option<Arc<dyn sp_database::Database<H256>>>, ServiceError> {
    if !path.exists() {
        return Ok(None);
    }

    let mut config = parity_db::Options::with_columns(path, LEGACY_DB_NUM_COLUMNS as u8);
    for column in [
        LEGACY_DB_STATE_COLUMN,
        LEGACY_DB_HEADER_COLUMN,
        LEGACY_DB_BODY_COLUMN,
        LEGACY_DB_BODY_INDEX_COLUMN,
        LEGACY_DB_TRANSACTION_COLUMN,
        LEGACY_DB_JUSTIFICATIONS_COLUMN,
    ] {
        config.columns[column as usize].compression = parity_db::CompressionType::Lz4;
    }

    let state_column = &mut config.columns[LEGACY_DB_STATE_COLUMN as usize];
    state_column.ref_counted = true;
    state_column.preimage = true;
    state_column.uniform = true;

    let tx_column = &mut config.columns[LEGACY_DB_TRANSACTION_COLUMN as usize];
    tx_column.ref_counted = true;
    tx_column.preimage = true;
    tx_column.uniform = true;

    let db = match parity_db::Db::open(&config) {
        Ok(db) => db,
        Err(parity_db::Error::InvalidConfiguration(_)) => {
            tracing::warn!(
                path = %path.display(),
                "Invalid parity-db metadata during legacy PoW finality repair; attempting metadata rewrite"
            );
            if let Some(metadata) = parity_db::Options::load_metadata(path).map_err(|error| {
                ServiceError::Other(format!(
                    "failed to load parity-db metadata for legacy PoW finality repair at {}: {error}",
                    path.display()
                ))
            })? {
                config
                    .write_metadata_with_version(path, &metadata.salt, Some(metadata.version))
                    .map_err(|error| {
                        ServiceError::Other(format!(
                            "failed to rewrite parity-db metadata for legacy PoW finality repair at {}: {error}",
                            path.display()
                        ))
                    })?;
            }
            parity_db::Db::open(&config).map_err(|error| {
                ServiceError::Other(format!(
                    "failed to reopen parity-db metadata for legacy PoW finality repair at {}: {error}",
                    path.display()
                ))
            })?
        }
        Err(error) => {
            return Err(ServiceError::Other(format!(
                "failed to open parity-db metadata for legacy PoW finality repair at {}: {error}",
                path.display()
            )))
        }
    };

    Ok(Some(Arc::new(LegacyParityDbAdapter(db))))
}

fn repair_legacy_pow_finality_metadata_in_db(
    db: &dyn sp_database::Database<H256>,
) -> Result<LegacyPowRepairOutcome, ServiceError> {
    if let Some(db_type) = db.get(LEGACY_META_COLUMN, LEGACY_META_TYPE_KEY) {
        if db_type.as_slice() != LEGACY_DB_TYPE_FULL {
            return Ok(LegacyPowRepairOutcome::default());
        }
    }

    let Some(genesis_hash_bytes) = db.get(LEGACY_META_COLUMN, LEGACY_META_GENESIS_HASH_KEY) else {
        return Ok(LegacyPowRepairOutcome::default());
    };
    let genesis_hash =
        decode_legacy_meta_hash(&genesis_hash_bytes, "legacy PoW genesis hash metadata")?;
    let genesis_lookup = legacy_lookup_key(0, genesis_hash)?;

    let Some(finalized_lookup) = db.get(LEGACY_META_COLUMN, LEGACY_META_FINALIZED_BLOCK_KEY) else {
        return Ok(LegacyPowRepairOutcome::default());
    };
    let (previous_finalized_number, previous_finalized_hash) =
        decode_legacy_lookup_key(&finalized_lookup, "legacy PoW finalized block metadata")?;

    let finalized_state_lookup = db.get(LEGACY_META_COLUMN, LEGACY_META_FINALIZED_STATE_KEY);
    let finalized_already_at_genesis = finalized_lookup == genesis_lookup;
    let finalized_state_matches_genesis =
        finalized_state_lookup.as_deref() == Some(genesis_lookup.as_slice());
    let mut transaction = DbTransaction::<H256>::new();
    let mut outcome = LegacyPowRepairOutcome::default();

    if !finalized_already_at_genesis || !finalized_state_matches_genesis {
        if db.get(LEGACY_META_COLUMN, LEGACY_META_TYPE_KEY).is_none() {
            transaction.set(
                LEGACY_META_COLUMN,
                LEGACY_META_TYPE_KEY,
                LEGACY_DB_TYPE_FULL,
            );
        }
        transaction.set_from_vec(
            LEGACY_META_COLUMN,
            LEGACY_META_FINALIZED_BLOCK_KEY,
            genesis_lookup.clone(),
        );
        transaction.set_from_vec(
            LEGACY_META_COLUMN,
            LEGACY_META_FINALIZED_STATE_KEY,
            genesis_lookup.clone(),
        );
        outcome.finalized_repair = Some((previous_finalized_number, previous_finalized_hash));
    }

    let finalized_effectively_at_genesis =
        finalized_already_at_genesis || outcome.finalized_repair.is_some();

    if let Some(rewind) =
        maybe_prepare_legacy_pow_tip_state_rewind(db, finalized_effectively_at_genesis)?
    {
        transaction.set_from_vec(
            LEGACY_DB_STATE_META_COLUMN,
            LEGACY_STATE_META_LAST_CANONICAL_KEY,
            encode_legacy_state_last_canonical(rewind.rewound_to_hash, rewind.rewound_to_number),
        );

        if let Some(last_pruned_bytes) = db.get(
            LEGACY_DB_STATE_META_COLUMN,
            LEGACY_STATE_META_LAST_PRUNED_KEY,
        ) {
            let last_pruned = decode_legacy_state_last_pruned(
                &last_pruned_bytes,
                "legacy PoW last pruned state metadata",
            )?;
            if last_pruned > rewind.rewound_to_number {
                transaction.set_from_vec(
                    LEGACY_DB_STATE_META_COLUMN,
                    LEGACY_STATE_META_LAST_PRUNED_KEY,
                    rewind.rewound_to_number.saturating_sub(1).encode(),
                );
            }
        }

        outcome.tip_state_rewind = Some(rewind);
    }

    if outcome == LegacyPowRepairOutcome::default() {
        return Ok(outcome);
    }

    db.commit(transaction).map_err(|error| {
        ServiceError::Other(format!(
            "failed to commit legacy PoW database repair: {error}"
        ))
    })?;

    Ok(outcome)
}

fn maybe_prepare_legacy_pow_tip_state_rewind(
    db: &dyn sp_database::Database<H256>,
    finalized_at_genesis: bool,
) -> Result<Option<LegacyPowTipStateRewind>, ServiceError> {
    if !finalized_at_genesis {
        return Ok(None);
    }

    let Some(best_lookup) = db.get(LEGACY_META_COLUMN, LEGACY_META_BEST_BLOCK_KEY) else {
        return Ok(None);
    };
    let (best_number, best_hash) =
        decode_legacy_lookup_key(&best_lookup, "legacy PoW best block metadata")?;
    if best_number == 0 {
        return Ok(None);
    }

    let Some(last_canonical_bytes) = db.get(
        LEGACY_DB_STATE_META_COLUMN,
        LEGACY_STATE_META_LAST_CANONICAL_KEY,
    ) else {
        return Ok(None);
    };
    let (last_canonical_hash, last_canonical_number) = decode_legacy_state_last_canonical(
        &last_canonical_bytes,
        "legacy PoW last canonical state metadata",
    )?;

    if last_canonical_number != u64::from(best_number) || last_canonical_hash != best_hash {
        return Ok(None);
    }

    let best_lookup_key = legacy_lookup_key(u64::from(best_number), best_hash)?;
    let Some(best_header_bytes) = db.get(LEGACY_DB_HEADER_COLUMN, &best_lookup_key) else {
        return Ok(None);
    };
    let best_header =
        runtime::Header::decode(&mut best_header_bytes.as_slice()).map_err(|error| {
            ServiceError::Other(format!(
                "failed to decode legacy PoW best header for state rewind: {error}"
            ))
        })?;

    let header_number = *best_header.number();
    if header_number != u64::from(best_number) {
        return Err(ServiceError::Other(format!(
            "legacy PoW best header number mismatch during state rewind: metadata #{best_number}, header #{header_number}",
        )));
    }
    let rewound_to_number = u64::from(best_number - 1);
    let rewound_to_hash = *best_header.parent_hash();

    Ok(Some(LegacyPowTipStateRewind {
        previous_number: last_canonical_number,
        previous_hash: last_canonical_hash,
        rewound_to_number,
        rewound_to_hash,
    }))
}

fn decode_legacy_meta_hash(bytes: &[u8], label: &str) -> Result<H256, ServiceError> {
    if bytes.len() != 32 {
        return Err(ServiceError::Other(format!(
            "{label} has invalid length {}; expected 32 bytes",
            bytes.len()
        )));
    }
    Ok(H256::from_slice(bytes))
}

fn decode_legacy_lookup_key(value: &[u8], label: &str) -> Result<(u32, H256), ServiceError> {
    if value.len() != 36 {
        return Err(ServiceError::Other(format!(
            "{label} has invalid length {}; expected 36 bytes",
            value.len()
        )));
    }
    let number = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
    let hash = H256::from_slice(&value[4..]);
    Ok((number, hash))
}

fn decode_legacy_state_last_canonical(
    mut value: &[u8],
    label: &str,
) -> Result<(H256, u64), ServiceError> {
    <(H256, u64)>::decode(&mut value)
        .map_err(|error| ServiceError::Other(format!("failed to decode {label}: {error}")))
}

fn encode_legacy_state_last_canonical(hash: H256, number: u64) -> Vec<u8> {
    (hash, number).encode()
}

fn decode_legacy_state_last_pruned(mut value: &[u8], label: &str) -> Result<u64, ServiceError> {
    u64::decode(&mut value)
        .map_err(|error| ServiceError::Other(format!("failed to decode {label}: {error}")))
}

fn legacy_lookup_key(number: u64, hash: H256) -> Result<Vec<u8>, ServiceError> {
    let number: u32 = number.try_into().map_err(|_| {
        ServiceError::Other(format!(
            "legacy PoW lookup key number {number} does not fit into u32"
        ))
    })?;
    let mut lookup_key = number.to_be_bytes().to_vec();
    lookup_key.extend_from_slice(hash.as_bytes());
    Ok(lookup_key)
}

fn legacy_parity_ref_counted_column(column: u32) -> bool {
    matches!(
        column,
        LEGACY_DB_STATE_COLUMN | LEGACY_DB_TRANSACTION_COLUMN
    )
}

impl<H> sp_database::Database<H> for LegacyParityDbAdapter
where
    H: Clone + AsRef<[u8]>,
{
    fn commit(
        &self,
        transaction: DbTransaction<H>,
    ) -> Result<(), sp_database::error::DatabaseError> {
        let mut invalid_columns = Vec::new();
        self.0
            .commit(transaction.0.into_iter().filter_map(|change| {
                Some(match change {
                    sp_database::Change::Set(column, key, value) => {
                        (column as u8, key, Some(value))
                    }
                    sp_database::Change::Remove(column, key) => (column as u8, key, None),
                    sp_database::Change::Store(column, key, value) => {
                        if legacy_parity_ref_counted_column(column) {
                            (column as u8, key.as_ref().to_vec(), Some(value))
                        } else {
                            if !invalid_columns.contains(&column) {
                                invalid_columns.push(column);
                            }
                            return None;
                        }
                    }
                    sp_database::Change::Reference(column, key) => {
                        if legacy_parity_ref_counted_column(column) {
                            let value =
                                <Self as sp_database::Database<H>>::get(self, column, key.as_ref());
                            (column as u8, key.as_ref().to_vec(), value)
                        } else {
                            if !invalid_columns.contains(&column) {
                                invalid_columns.push(column);
                            }
                            return None;
                        }
                    }
                    sp_database::Change::Release(column, key) => {
                        if legacy_parity_ref_counted_column(column) {
                            (column as u8, key.as_ref().to_vec(), None)
                        } else {
                            if !invalid_columns.contains(&column) {
                                invalid_columns.push(column);
                            }
                            return None;
                        }
                    }
                })
            }))
            .map_err(|error| sp_database::error::DatabaseError(Box::new(error)))?;

        if !invalid_columns.is_empty() {
            return Err(sp_database::error::DatabaseError(Box::new(
                parity_db::Error::InvalidInput(format!(
                    "ref-counted operation on non-ref-counted columns {invalid_columns:?}"
                )),
            )));
        }

        Ok(())
    }

    fn get(&self, column: sp_database::ColumnId, key: &[u8]) -> Option<Vec<u8>> {
        match self.0.get(column as u8, key) {
            Ok(value) => value,
            Err(error) => panic!("critical parity-db read failure during legacy repair: {error:?}"),
        }
    }

    fn contains(&self, column: sp_database::ColumnId, key: &[u8]) -> bool {
        match self.0.get_size(column as u8, key) {
            Ok(value) => value.is_some(),
            Err(error) => {
                panic!("critical parity-db contains failure during legacy repair: {error:?}")
            }
        }
    }

    fn value_size(&self, column: sp_database::ColumnId, key: &[u8]) -> Option<usize> {
        match self.0.get_size(column as u8, key) {
            Ok(value) => value.map(|size| size as usize),
            Err(error) => panic!("critical parity-db size failure during legacy repair: {error:?}"),
        }
    }

    fn supports_ref_counting(&self) -> bool {
        true
    }

    fn sanitize_key(&self, key: &mut Vec<u8>) {
        let hash_len = 32usize;
        if key.len() > hash_len {
            let _ = key.drain(0..key.len() - hash_len);
        }
    }
}

// =============================================================================
// Prior PartialComponents/new_partial() removed in favor of new_full_with_client.
// =============================================================================
// The scaffold mode structs and functions have been removed.
// Use PartialComponentsWithClient and new_partial_with_client() instead.

/// Partial components with full Substrate client (Production Mode)
///
/// This struct contains all components created by `new_partial_with_client()`,
/// including the full Substrate client with WASM executor, database backend,
/// keystore, and PQ network components.
///
/// # Components
///
/// - `client`: Full Substrate client with WASM executor and runtime API access
/// - `backend`: Database backend (RocksDB in production, in-memory for tests)
/// - `keystore`: Keystore container for managing cryptographic keys
///
/// # Usage
///
/// Use `new_partial_with_client()` to create these components. The client
/// provides access to:
/// - Block import and finalization
/// - Runtime API calls (DifficultyApi, BlockBuilder, etc.)
/// - State queries and storage
pub struct PartialComponentsWithClient {
    /// Full Substrate client with WASM executor
    pub client: Arc<HegemonFullClient>,
    /// Backend for state storage
    pub backend: Arc<FullBackend>,
    /// Keystore container for key management
    pub keystore_container: KeystoreContainer,
    /// Substrate transaction pool
    ///
    /// This is the production transaction pool that validates transactions
    /// against the runtime. It replaces MockTransactionPool for full client mode.
    pub transaction_pool: Arc<HegemonTransactionPool>,
    /// Select-chain helper required by `PowBlockImport`.
    ///
    /// Canonical PoW best-chain selection still comes from `PowBlockImport`'s
    /// cumulative-difficulty fork choice when imports leave `fork_choice` unset.
    pub select_chain: HegemonSelectChain,
    /// PoW block import wrapper
    ///
    /// Wraps the client with PoW verification using Sha256dAlgorithm.
    /// All blocks imported through this wrapper are verified for valid PoW.
    pub pow_block_import: ConcretePowBlockImport,
    /// SHA-256d PoW algorithm
    ///
    /// The PoW algorithm implementation used for block verification and mining.
    pub pow_algorithm: Sha256dAlgorithm<HegemonFullClient>,
    /// Task manager for spawning async tasks
    pub task_manager: TaskManager,
    /// PoW mining handle
    pub pow_handle: PowHandle,
    /// PQ network keypair for secure connections
    pub network_keypair: Option<PqNetworkKeypair>,
    /// PQ network configuration
    pub network_config: PqNetworkConfig,
    /// PQ peer identity for transport layer
    pub pq_identity: Option<PqPeerIdentity>,
    /// Substrate PQ transport
    pub pq_transport: Option<SubstratePqTransport>,
    /// PQ service configuration
    pub pq_service_config: PqServiceConfig,
}

/// Creates partial node components with full Substrate client (Production Mode)
///
/// This function uses `sc_service::new_full_parts()` to create the real
/// Substrate client with WASM executor, database backend, and keystore.
///
/// # Components Created
///
/// - `client`: Full client (`TFullClient<Block, RuntimeApi, WasmExecutor>`)
///   - Executes runtime WASM
///   - Provides runtime API access (DifficultyApi, BlockBuilder, etc.)
///   - Manages state and block storage
///
/// - `backend`: Full backend (`TFullBackend<Block>`)
///   - RocksDB or ParityDB for persistent storage
///   - In-memory backend available for testing
///
/// - `keystore_container`: Keystore for cryptographic keys
///   - Managed by sc-service
///   - Used for signing operations
///
/// - `task_manager`: Spawner for async tasks
///   - Created by new_full_parts
///   - Manages node lifecycle
///
/// # Usage
///
/// ```rust,ignore
/// let PartialComponentsWithClient {
///     client,
///     backend,
///     keystore_container,
///     task_manager,
///     pow_handle,
///     ..
/// } = new_partial_with_client(&config)?;
///
/// // Use client for runtime API calls
/// let api = client.runtime_api();
/// let difficulty = api.difficulty_bits(best_hash).unwrap_or(DEFAULT_DIFFICULTY);
/// ```
///
/// # Errors
///
/// Returns error if:
/// - WASM binary is not available
/// - Database initialization fails
/// - Configuration is invalid
pub fn new_partial_with_client(
    config: &Configuration,
) -> Result<PartialComponentsWithClient, ServiceError> {
    // Check WASM binary availability
    #[cfg(feature = "substrate")]
    {
        if runtime::WASM_BINARY.is_none() {
            return Err(ServiceError::Other(
                "WASM binary not available. Build with `cargo build -p runtime --features std`."
                    .to_string(),
            ));
        }
    }

    maybe_repair_legacy_pow_finality_metadata(config)?;

    // Create the WASM executor
    // new_wasm_executor uses default configuration from sc_executor::WasmExecutor
    let executor = sc_service::new_wasm_executor::<sp_io::SubstrateHostFunctions>(&config.executor);

    // Create full Substrate client components using new_full_parts
    // This creates:
    // - TFullClient with WASM executor
    // - TFullBackend with database
    // - KeystoreContainer for key management
    // - TaskManager for async coordination
    let (client, backend, keystore_container, task_manager) =
        sc_service::new_full_parts::<runtime::Block, runtime::RuntimeApi, _>(
            config, None, // telemetry - None for now, can add later
            executor,
        )?;

    let client = Arc::new(client);

    tracing::info!(
        best_number = %client.chain_info().best_number,
        best_hash = %client.chain_info().best_hash,
        "Full Substrate client created"
    );

    // Create Substrate transaction pool
    //
    // The transaction pool validates transactions against the runtime and
    // maintains ready (valid) and future (pending) queues. It uses:
    // - FullChainApi: Provides runtime access for transaction validation
    // - Builder pattern: Configures pool options and prometheus metrics
    //
    // Reference: polkadot-evm/frontier template/node/src/service.rs lines 174-183
    let transaction_pool = Arc::from(
        sc_transaction_pool::Builder::new(
            TxPoolEssentialSpawner::new(task_manager.spawn_essential_handle()),
            client.clone(),
            config.role.is_authority().into(),
        )
        .with_options(config.transaction_pool.clone())
        .with_prometheus(config.prometheus_registry())
        .build(),
    );

    tracing::info!("Full Substrate transaction pool created");

    // Initialize PoW mining coordinator
    //
    // NOTE: Treat HEGEMON_MINE as a boolean flag (HEGEMON_MINE=1/true),
    // not merely "present in the environment", since many scripts set it
    // explicitly to "0" to disable mining.
    let mining_config_for_pow = MiningConfig::from_env();
    let pow_config = if mining_config_for_pow.enabled {
        PowConfig::mining(mining_config_for_pow.threads)
    } else {
        PowConfig::non_mining()
    };

    let (pow_handle, _pow_events) = PowHandle::new(pow_config);

    // ==========================================================================
    // Create PoW block import pipeline
    // ==========================================================================
    //
    // The block import pipeline verifies PoW seals before importing blocks:
    // 1. Create the select-chain helper required by PowBlockImport
    // 2. Create Sha256dAlgorithm with client reference for difficulty queries
    // 3. Wrap client in PowBlockImport for PoW verification
    //
    // Flow: Network → Import Queue → PowBlockImport → Client → Backend

    // PowBlockImport still needs a SelectChain implementation, but best-chain selection comes
    // from PowBlockImport's total-difficulty fork-choice logic when import_params.fork_choice
    // is left unset.
    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    // Create SHA-256d PoW algorithm with client for difficulty queries
    let pow_algorithm = Sha256dAlgorithm::new(client.clone());

    // Create inherent data providers creator
    // Timestamp inherents are required for runtime validation during import.
    // We use a function pointer type for compatibility with PowBlockImport.
    fn create_inherent_data_providers(
        _parent_hash: <runtime::Block as sp_runtime::traits::Block>::Hash,
        _: (),
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<PowInherentProviders, Box<dyn std::error::Error + Send + Sync>>,
                > + Send,
        >,
    > {
        Box::pin(async move {
            Ok((
                sp_timestamp::InherentDataProvider::from_system_time(),
                ShieldedCoinbaseInherentErrorHandler,
            ))
        })
    }

    // Create the PoW block import wrapper
    // This verifies SHA-256d PoW seals before allowing blocks to be imported
    //
    let pow_import_config = crate::substrate::block_import::BlockImportConfig::from_env();

    let pow_block_import = sc_consensus_pow::PowBlockImport::new(
        client.clone(),        // Inner block import (client implements BlockImport)
        client.clone(),        // Client for runtime API queries
        pow_algorithm.clone(), // PoW algorithm for verification
        pow_import_config.check_inherents_after as u64, // enable inherent checks when configured
        select_chain.clone(),  // Chain selection rule
        create_inherent_data_providers as PowInherentDataProviders, // Inherent data providers creator
    );

    tracing::info!("PoW block import pipeline created");
    tracing::debug!("  - Sha256dAlgorithm for PoW verification");
    tracing::debug!("  - LongestChain helper for PowBlockImport");
    tracing::debug!("  - PowBlockImport wrapping full client");

    // Initialize PQ service configuration
    // Uses Substrate config for ports with env var overrides
    let pq_service_config = PqServiceConfig::from_config(config);

    // Initialize PQ network configuration
    let pq_network_config = PqNetworkConfig {
        listen_addresses: vec![format!(
            "/ip4/{}/tcp/{}",
            pq_service_config.listen_addr.ip(),
            pq_service_config.listen_addr.port()
        )],
        bootstrap_nodes: pq_service_config
            .bootstrap_nodes
            .iter()
            .map(|node| node.seed.clone())
            .collect(),
        enable_pq_transport: true,
        max_peers: pq_service_config.max_peers as u32,
        connection_timeout_secs: 30,
        verbose_logging: pq_service_config.verbose_logging,
    };

    // Load or create PQ identity seed and derive independent seeds.
    let identity_seed = load_or_create_pq_identity_seed(config)?;
    let network_seed = derive_seed(b"pq-network-keypair", &identity_seed);
    let transport_seed = derive_seed(b"pq-noise-identity", &identity_seed);

    // Generate PQ network keypair for this node
    let network_keypair = PqNetworkKeypair::from_seed(&network_seed)
        .map_err(|e| ServiceError::Other(format!("PQ network keypair generation failed: {e}")))?;
    tracing::info!(
        peer_id = %network_keypair.peer_id(),
        "Initialized PQ network keypair"
    );

    // Create PQ peer identity and transport

    let pq_transport_config = PqTransportConfig {
        handshake_timeout: std::time::Duration::from_secs(30),
        verbose_logging: pq_service_config.verbose_logging,
    };

    let pq_identity = PqPeerIdentity::new(&transport_seed, pq_transport_config.clone());

    let substrate_transport_config = SubstratePqTransportConfig {
        connection_timeout: std::time::Duration::from_secs(30),
        handshake_timeout: std::time::Duration::from_secs(30),
        verbose_logging: pq_service_config.verbose_logging,
        protocol_id: "/hegemon/pq/1".to_string(),
    };

    let pq_transport = SubstratePqTransport::new(&pq_identity, substrate_transport_config);

    tracing::info!(
        pq_peer_id = %hex::encode(pq_transport.local_peer_id()),
        "Hegemon node with full client initialized"
    );

    Ok(PartialComponentsWithClient {
        client,
        backend,
        keystore_container,
        transaction_pool,
        select_chain,
        pow_block_import,
        pow_algorithm,
        task_manager,
        pow_handle,
        network_keypair: Some(network_keypair),
        network_config: pq_network_config,
        pq_identity: Some(pq_identity),
        pq_transport: Some(pq_transport),
        pq_service_config,
    })
}

// =============================================================================
// Full node service with real Substrate client (Production Mode)
// =============================================================================
//
// This function creates a full node using the Substrate client instead
// of scaffold components. It wires:
// - Substrate client to ProductionChainStateProvider callbacks
// - BlockBuilder API for state execution
// - PowBlockImport for block import with PoW verification
// - Runtime API for difficulty queries

/// Creates a full node service with Substrate client
///
/// This is the production version that uses `new_partial_with_client()` to create
/// a full Substrate client with WASM executor. It wires all callbacks to use
/// the real client for:
///
/// - **Best block queries**: Uses `client.chain_info()` for hash/number
/// - **Difficulty queries**: Uses runtime API `DifficultyApi::difficulty_bits()`
/// - **State execution**: Uses `wire_block_builder_api()` for real runtime execution
/// - **Block import**: Uses `wire_pow_block_import()` with PowBlockImport
///
/// # Differences from `new_full()`
///
/// | Component | `new_full()` (scaffold) | `new_full_with_client()` (production) |
/// |-----------|------------------------|--------------------------------------|
/// | Client | Mock state | Real TFullClient |
/// | State root | Scaffold placeholder | Runtime-computed |
/// | Block import | BlockImportTracker | PowBlockImport |
/// | Tx validation | No validation | Runtime validation |
/// | Difficulty | Constant fallback | Runtime API query |
///
/// # Usage
///
/// ```rust,ignore
/// // Use production mode
/// let task_manager = new_full_with_client(config).await?;
/// ```
pub async fn new_full_with_client(config: Configuration) -> Result<TaskManager, ServiceError> {
    // Create full Substrate client components
    let PartialComponentsWithClient {
        client,
        backend,
        keystore_container: _keystore_container,
        transaction_pool,
        select_chain: _select_chain,
        pow_block_import,
        pow_algorithm: _pow_algorithm,
        task_manager,
        pow_handle,
        network_keypair,
        network_config,
        pq_identity,
        pq_transport,
        pq_service_config,
    } = new_partial_with_client(&config)?;

    let da_sampling_secret = load_or_create_da_sampling_secret(&config)?;

    let chain_name = config.chain_spec.name().to_string();
    let chain_properties = config.chain_spec.properties();
    let chain_type = config.chain_spec.chain_type();
    let role = format!("{:?}", config.role);

    // Track PQ network handle for mining worker
    let mut pq_network_handle: Option<PqNetworkHandle> = None;
    let peer_count = Arc::new(AtomicUsize::new(0));
    let sync_status = Arc::new(AtomicBool::new(false));
    let peer_details = Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));
    let peer_graph_reports = Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));

    tracing::info!(
        chain = %chain_name,
        role = %role,
        best_number = %client.chain_info().best_number,
        best_hash = %client.chain_info().best_hash,
        pq_enabled = %network_config.enable_pq_transport,
        "Hegemon node started with FULL SUBSTRATE CLIENT"
    );

    // Log PQ network configuration
    if let Some(ref keypair) = network_keypair {
        tracing::info!(
            peer_id = %keypair.peer_id(),
            "PQ-secure network transport configured"
        );
    }

    // Log PQ transport configuration
    if let Some(ref transport) = pq_transport {
        tracing::info!(
            transport_peer_id = %hex::encode(transport.local_peer_id()),
            protocol = %transport.config().protocol_id,
            "SubstratePqTransport ready for peer connections"
        );
    }

    // Auto-start mining if HEGEMON_MINE=1 is set
    let mined_block_store = Arc::new(parking_lot::Mutex::new(Vec::<MinedBlockRecord>::new()));
    let mut prover_coordinator_for_rpc: Option<Arc<ProverCoordinator>> = None;
    let prover_coordinator_shared: Arc<parking_lot::RwLock<Option<Arc<ProverCoordinator>>>> =
        Arc::new(parking_lot::RwLock::new(None));
    let mining_config = MiningConfig::from_env();
    if mining_config.enabled {
        pow_handle.start_mining();
        tracing::info!(
            threads = mining_config.threads,
            "Mining enabled and started"
        );
    } else {
        tracing::info!("Mining disabled (set HEGEMON_MINE=1 to enable)");
    }

    // =========================================================================
    // Wire Transaction Pool to Network Bridge
    // =========================================================================
    // Create a wrapper around the Substrate transaction pool that
    // implements our TransactionPool trait. This enables the TransactionPoolBridge
    // to submit transactions to the pool (with runtime validation)
    let pool_config = TransactionPoolConfig::from_env();
    let real_pool_wrapper = Arc::new(SubstrateTransactionPoolWrapper::new(
        transaction_pool.clone(),
        client.clone(),
        pool_config.capacity,
    ));
    let pool_bridge = Arc::new(TransactionPoolBridge::with_max_pending(
        real_pool_wrapper.clone(),
        pool_config.max_pending,
    ));

    tracing::info!(
        pool_capacity = pool_config.capacity,
        max_pending = pool_config.max_pending,
        pool_type = "SubstrateTransactionPoolWrapper (real pool)",
        "Transaction pool bridge wired to Substrate pool"
    );
    tracing::debug!(
        "Real transaction pool: {:?}",
        std::any::type_name_of_val(&*transaction_pool)
    );

    let da_params = load_da_params(&chain_properties);
    let da_store_capacity = load_da_store_capacity();
    let ciphertext_da_retention_blocks = load_ciphertext_da_retention_blocks();
    let proof_da_retention_blocks = load_proof_da_retention_blocks();
    let da_sample_timeout = load_da_sample_timeout();
    let da_store_path = da_store_path(&config);
    let pending_ciphertext_capacity = load_pending_ciphertext_capacity();
    let pending_proof_capacity = load_pending_proof_capacity();
    let commitment_block_proof_store_capacity = load_commitment_proof_store_capacity();
    let da_chunk_store: Arc<ParkingMutex<DaChunkStore>> = Arc::new(ParkingMutex::new(
        DaChunkStore::open(
            &da_store_path,
            da_store_capacity,
            ciphertext_da_retention_blocks,
            proof_da_retention_blocks,
        )
        .map_err(|err| ServiceError::Other(format!("failed to open DA store: {err}")))?,
    ));
    let pending_ciphertext_store: Arc<ParkingMutex<PendingCiphertextStore>> = Arc::new(
        ParkingMutex::new(PendingCiphertextStore::new(pending_ciphertext_capacity)),
    );
    let pending_proof_store: Arc<ParkingMutex<PendingProofStore>> = Arc::new(ParkingMutex::new(
        PendingProofStore::new(pending_proof_capacity),
    ));
    let da_request_tracker: Arc<ParkingMutex<DaRequestTracker>> =
        Arc::new(ParkingMutex::new(DaRequestTracker::default()));
    let commitment_block_proof_store: Arc<ParkingMutex<CommitmentBlockProofStore>> =
        Arc::new(ParkingMutex::new(CommitmentBlockProofStore::new(
            commitment_block_proof_store_capacity,
        )));

    tracing::info!(
        da_chunk_size = da_params.chunk_size,
        da_sample_count = da_params.sample_count,
        da_store_capacity,
        pending_ciphertext_capacity,
        pending_proof_capacity,
        ciphertext_da_retention_blocks,
        proof_da_retention_blocks,
        da_store_path = %da_store_path.display(),
        da_sample_timeout_ms = da_sample_timeout.as_millis() as u64,
        "DA sampling configured"
    );

    tracing::info!(
        commitment_block_proof_store_capacity,
        "Commitment block proof store configured"
    );

    // =========================================================================
    // CRITICAL: Spawn Transaction Pool Maintenance Task
    // =========================================================================
    // The transaction pool's internal ForkAwareTxPool spawns background tasks
    // that require block import/finality notifications to function. Without
    // this maintenance task, those internal tasks will fail because they
    // never receive ChainEvent notifications.
    //
    // This task listens to:
    // - client.import_notification_stream() -> ChainEvent::NewBestBlock
    // - client.finality_notification_stream() -> ChainEvent::Finalized
    //
    // And calls transaction_pool.maintain(event) for each notification,
    // which keeps the pool's internal state synchronized with the chain.
    let client_for_pool_maint = client.clone();
    let transaction_pool_for_maint = transaction_pool.clone();
    task_manager.spawn_essential_handle().spawn(
        "txpool-maintenance",
        Some("transaction-pool"),
        async move {
            let import_stream = client_for_pool_maint
                .import_notification_stream()
                .filter_map(|n| futures::future::ready(n.try_into().ok()))
                .fuse();
            let finality_stream = client_for_pool_maint
                .finality_notification_stream()
                .map(Into::into)
                .fuse();

            tracing::info!("Transaction pool maintenance task started");

            futures::stream::select(import_stream, finality_stream)
                .for_each(|evt| {
                    let pool = transaction_pool_for_maint.clone();
                    async move {
                        pool.maintain(evt).await;
                    }
                })
                .await;

            tracing::info!(
                "Transaction pool maintenance notification streams closed; awaiting shutdown"
            );
            futures::future::pending::<()>().await;
        },
    );
    tracing::info!(
        "CRITICAL: Transaction pool maintenance task spawned - pool will receive block notifications"
    );

    // Capture local peer ID for RPC (will be set inside PQ backend block)
    let mut rpc_peer_id: Option<[u8; 32]> = None;

    // Create and start PQ network backend
    if let Some(ref identity) = pq_identity {
        let backend_config = PqNetworkBackendConfig {
            listen_addr: pq_service_config.listen_addr,
            bootstrap_nodes: pq_service_config.bootstrap_nodes.clone(),
            max_peers: pq_service_config.max_peers,
            connection_timeout: std::time::Duration::from_secs(30),
            verbose_logging: pq_service_config.verbose_logging,
        };

        let mut pq_backend = PqNetworkBackend::new(identity, backend_config);
        let local_peer_id = pq_backend.local_peer_id();
        rpc_peer_id = Some(local_peer_id); // Capture for RPC handler

        // Start the PQ network backend and get the event receiver
        match pq_backend.start().await {
            Ok(mut event_rx) => {
                tracing::info!(
                    listen_addr = %pq_service_config.listen_addr,
                    max_peers = pq_service_config.max_peers,
                    peer_id = %hex::encode(local_peer_id),
                    "PqNetworkBackend started"
                );

                let pq_backend = Arc::new(pq_backend);

                // Get PQ network handle for mining worker broadcasting
                pq_network_handle = Some(pq_backend.handle());
                tracing::info!("PQ network handle captured for mining worker");

                // Create the network bridge for block/tx routing
                let network_bridge = Arc::new(Mutex::new(
                    NetworkBridgeBuilder::new()
                        .verbose(pq_service_config.verbose_logging)
                        .build(),
                ));
                let bridge_clone = Arc::clone(&network_bridge);

                // =======================================================================
                // Peer discovery (address exchange) store
                // =======================================================================
                // Persist learned peer socket addresses under the node base path so nodes
                // that are not in HEGEMON_SEEDS can still reconnect across restarts.
                use network::{PeerStore, PeerStoreConfig};
                let mut peer_store = PeerStore::new(PeerStoreConfig {
                    path: config.base_path.path().join("pq-peers.bin"),
                    ttl: std::time::Duration::from_secs(24 * 60 * 60),
                    max_entries: 2048,
                });
                if let Err(err) = peer_store.load() {
                    tracing::warn!(error = %err, "Failed to load PQ peer discovery store");
                }
                let strict_compatibility = true;
                tracing::info!(
                    "Strict compatibility enabled; skipping cached discovery dials at startup"
                );
                let discovery_listen_port = pq_service_config.listen_addr.port();
                let discovery_max_peers = pq_service_config.max_peers;

                // =======================================================================
                // Create Chain Sync Service
                // =======================================================================
                // The sync service handles:
                // - Responding to sync requests from peers
                // - Managing the sync state machine
                // - Downloading blocks from peers when behind
                let sync_service = Arc::new(Mutex::new(ChainSyncService::new(client.clone())));
                let sync_service_clone = Arc::clone(&sync_service);
                let _sync_service_for_handler = Arc::clone(&sync_service);
                let sync_status_for_events = Arc::clone(&sync_status);

                tracing::info!("Chain sync service created");

                // Clone pool_bridge for use in network event handler
                let pool_bridge_clone = Arc::clone(&pool_bridge);

                // Clone for the transaction processor task
                let pool_bridge_for_processor = Arc::clone(&pool_bridge);
                let process_interval = pool_config.process_interval_ms;
                let pool_verbose = pool_config.verbose;

                // Get handles for sending sync messages
                let pq_handle_for_sync = pq_backend.handle();
                let sync_handle_for_tick = pq_backend.handle();
                let pq_handle_for_status = pq_backend.handle(); // For sending best block on connect
                let pq_handle_for_tx_prop = pq_backend.handle(); // For transaction propagation
                let pq_handle_for_da = pq_backend.handle(); // For DA chunk request/response
                let pq_handle_for_da_import = pq_handle_for_da.clone();

                // Clone client for the network event handler to send our best block
                let client_for_network = client.clone();
                let da_chunk_store_for_handler = Arc::clone(&da_chunk_store);
                let da_request_tracker_for_handler = Arc::clone(&da_request_tracker);
                let prover_coordinator_for_events = Arc::clone(&prover_coordinator_shared);
                let peer_count_for_rpc = Arc::clone(&peer_count);
                let peer_details_for_events = Arc::clone(&peer_details);
                let peer_graph_reports_for_events = Arc::clone(&peer_graph_reports);

                // Spawn the PQ network event handler task with sync integration
                let pq_backend_for_events = Arc::clone(&pq_backend);
                task_manager.spawn_handle().spawn(
                    "pq-network-events",
                    Some("network"),
	                    async move {
	                        use crate::substrate::discovery::{
	                            is_dialable_addr, DiscoveryMessage, DEFAULT_ADDR_LIMIT,
	                            DEFAULT_DIAL_BATCH, DEFAULT_PEER_GRAPH_LIMIT, DISCOVERY_PROTOCOL,
	                        };
	                        use crate::substrate::sync::PeerCompatibility;
	                        use rand::seq::SliceRandom;
	                        use std::collections::HashMap;
	                        use std::collections::HashSet;
	                        use std::net::SocketAddr;
	                        use std::time::{Duration, Instant};
	                        use tokio::time::MissedTickBehavior;

	                        let pq_backend = pq_backend_for_events;
	                        let listen_port = discovery_listen_port;

	                        // Discovery state: observed peer socket address and whether we dialed them.
	                        let mut connected_peers: HashMap<[u8; 32], (SocketAddr, bool)> =
	                            HashMap::new();

	                        // Peer discovery store (persisted).
	                        let mut peer_store = peer_store;

	                        // Track recent dial attempts so we don't spin on unreachable addrs.
	                        let mut recent_dials: HashMap<SocketAddr, Instant> = HashMap::new();
	                        let recent_dial_window = Duration::from_secs(30);

	                        // Periodically refresh discovered peers so early-joining nodes learn about
	                        // peers that connect later (otherwise a node that connects once to a seed
	                        // may never request new addresses again).
	                        let discovery_min_peers = std::env::var("HEGEMON_PQ_DISCOVERY_MIN_PEERS")
	                            .ok()
	                            .and_then(|s| s.parse::<usize>().ok())
	                            .unwrap_or(4)
	                            .max(1)
	                            .min(discovery_max_peers);
	                        let discovery_tick_secs = std::env::var("HEGEMON_PQ_DISCOVERY_TICK_SECS")
	                            .ok()
	                            .and_then(|s| s.parse::<u64>().ok())
	                            .unwrap_or(30)
	                            .max(5);
	                        let mut discovery_tick =
	                            tokio::time::interval(Duration::from_secs(discovery_tick_secs));
	                        discovery_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
	                        let peer_graph_tick_secs = std::env::var("HEGEMON_PQ_PEER_GRAPH_TICK_SECS")
	                            .ok()
	                            .and_then(|s| s.parse::<u64>().ok())
	                            .unwrap_or(30)
	                            .max(5);
	                        let mut peer_graph_tick =
	                            tokio::time::interval(Duration::from_secs(peer_graph_tick_secs));
	                        peer_graph_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
	                        tracing::info!(
	                            min_peers = discovery_min_peers,
	                            tick_secs = discovery_tick_secs,
	                            strict_compatibility,
	                            "PQ discovery enabled (address exchange)"
	                        );

	                        tracing::info!("PQ network event handler started (Full Client Mode + Sync)");

	                        loop {
	                            tokio::select! {
	                                maybe_event = event_rx.recv() => {
	                                    let Some(event) = maybe_event else {
	                                        break;
	                                    };
	                            {
	                                let mut bridge = bridge_clone.lock().await;
	                                bridge.handle_event(event.clone()).await;

	                                // Process transactions
                                let pending_txs = bridge.drain_transactions();
                                if !pending_txs.is_empty() {
                                    pool_bridge_clone.queue_from_bridge(pending_txs).await;
                                }

                                // Note: Block announcements are NOT drained here.
                                // They are drained by the block-import-handler task
                                // which handles both sync state updates and block import.
                            }

                            // Debug: log all events received by the handler
                            tracing::info!(
                                event = ?format!("{:?}", std::mem::discriminant(&event)),
                                "PQ network event received by Full Client handler"
                            );

	                            match event {
                                PqNetworkEvent::PeerConnected { peer_id, addr, is_outbound } => {
                                    tracing::info!(
                                        peer = %hex::encode(peer_id),
                                        addr = %addr,
                                        direction = if is_outbound { "outbound" } else { "inbound" },
                                        "EVENT HANDLER: Processing PeerConnected event"
                                    );

                                    // Update sync service with new peer
                                    {
                                        let mut sync = sync_service_clone.lock().await;
                                        sync.on_peer_connected(peer_id);
                                        peer_count_for_rpc
                                            .store(sync.peer_count(), Ordering::Relaxed);
                                    }

                                    connected_peers.insert(peer_id, (addr, is_outbound));
                                    peer_details_for_events.write().insert(
                                        peer_id,
                                        PeerConnectionSnapshot {
                                            peer_id,
                                            addr,
                                            is_outbound,
                                            best_height: 0,
                                            best_hash: [0u8; 32],
                                            last_seen: Instant::now(),
                                            bytes_sent: 0,
                                            bytes_received: 0,
                                        },
                                    );
                                    // Record dialed addresses so we can share them with others.
                                    if is_outbound && is_dialable_addr(&addr) {
                                        if let Err(err) = peer_store.record_connected(addr) {
                                            tracing::warn!(
                                                peer = %hex::encode(peer_id),
                                                addr = %addr,
                                                error = %err,
                                                "Failed to persist connected peer address"
                                            );
                                        }
                                    }

                                    if !strict_compatibility {
                                        let msg = DiscoveryMessage::GetPeerGraph {
                                            limit: DEFAULT_PEER_GRAPH_LIMIT,
                                        };
                                        if let Ok(encoded) = bincode::serialize(&msg) {
                                            let _ = pq_handle_for_status
                                                .send_message(
                                                    peer_id,
                                                    DISCOVERY_PROTOCOL.to_string(),
                                                    encoded,
                                                )
                                                .await;
                                        }

                                        // Send discovery hello + request addresses.
                                        let hello = DiscoveryMessage::Hello { listen_port };
                                        if let Ok(encoded) = bincode::serialize(&hello) {
                                            let _ = pq_handle_for_status
                                                .send_message(
                                                    peer_id,
                                                    DISCOVERY_PROTOCOL.to_string(),
                                                    encoded,
                                                )
                                                .await;
                                        }

                                        let get_addrs = DiscoveryMessage::GetAddrs {
                                            limit: DEFAULT_ADDR_LIMIT,
                                        };
                                        if let Ok(encoded) = bincode::serialize(&get_addrs) {
                                            let _ = pq_handle_for_status
                                                .send_message(
                                                    peer_id,
                                                    DISCOVERY_PROTOCOL.to_string(),
                                                    encoded,
                                                )
                                                .await;
                                        }
                                    } else {
                                        tracing::debug!(
                                            peer = %hex::encode(peer_id),
                                            "Strict compatibility enabled; delaying discovery exchange until peer is verified"
                                        );
                                    }

                                    // Send our best block to the new peer so they know our chain tip
                                    // This enables the peer to initiate sync if they're behind us
                                    {
                                        use crate::substrate::network_bridge::{BlockAnnounce, BlockState, BLOCK_ANNOUNCE_PROTOCOL};

                                        let info = client_for_network.chain_info();
                                        let best_number: u64 = info.best_number.try_into().unwrap_or(0);
                                        let mut hash_bytes = [0u8; 32];
                                        hash_bytes.copy_from_slice(info.best_hash.as_ref());

                                        tracing::info!(
                                            peer = %hex::encode(peer_id),
                                            best_number = best_number,
                                            "Attempting to send best block to new peer"
                                        );

                                        // Get the best block header
                                        match client_for_network.header(info.best_hash) {
                                            Ok(Some(header)) => {
                                                let header_bytes = header.encode();
                                                let announce = BlockAnnounce::new(
                                                    header_bytes,
                                                    best_number,
                                                    hash_bytes,
                                                    BlockState::Best,
                                                );

                                                let encoded = announce.encode();
                                                if let Err(e) = pq_handle_for_status.send_message(
                                                    peer_id,
                                                    BLOCK_ANNOUNCE_PROTOCOL.to_string(),
                                                    encoded,
                                                ).await {
                                                    tracing::warn!(
                                                        peer = %hex::encode(peer_id),
                                                        error = %e,
                                                        "Failed to send best block to new peer"
                                                    );
                                                } else {
                                                    tracing::info!(
                                                        peer = %hex::encode(peer_id),
                                                        best_number = best_number,
                                                        "Sent our best block to new peer for sync"
                                                    );
                                                }
                                            }
                                            Ok(None) => {
                                                tracing::warn!(
                                                    peer = %hex::encode(peer_id),
                                                    best_hash = ?info.best_hash,
                                                    "Header not found for best block"
                                                );
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    peer = %hex::encode(peer_id),
                                                    error = ?e,
                                                    "Error getting header for best block"
                                                );
                                            }
                                        }
                                    }

                                    tracing::info!(
                                        peer_id = %hex::encode(peer_id),
                                        addr = %addr,
                                        direction = if is_outbound { "outbound" } else { "inbound" },
                                        "PQ peer connected"
                                    );
                                }
	                                PqNetworkEvent::PeerDisconnected { peer_id, reason } => {
                                    // Update sync service
                                    {
                                        let mut sync = sync_service_clone.lock().await;
                                        sync.on_peer_disconnected(&peer_id);
                                        peer_count_for_rpc
                                            .store(sync.peer_count(), Ordering::Relaxed);
                                    }

                                    if let Some((addr, is_outbound)) = connected_peers.remove(&peer_id)
                                    {
                                        if is_outbound && is_dialable_addr(&addr) {
                                            // Keep the peer fresh in the store so reconnect attempts
                                            // prefer it over stale entries.
                                            let _ = peer_store.record_disconnected(addr);
                                        }
                                    }
                                    peer_details_for_events.write().remove(&peer_id);
                                    peer_graph_reports_for_events.write().remove(&peer_id);
                                    tracing::info!(
                                        peer_id = %hex::encode(peer_id),
                                        reason = %reason,
                                        "PQ peer disconnected"
                                    );
                                }
	                                PqNetworkEvent::MessageReceived { peer_id, protocol, data } => {
	                                    // Handle discovery protocol messages
	                                    if protocol == DISCOVERY_PROTOCOL {
	                                        if strict_compatibility {
	                                            let compatibility = {
	                                                let sync = sync_service_clone.lock().await;
	                                                sync.peer_compatibility(&peer_id)
	                                            };
	                                            if !matches!(compatibility, PeerCompatibility::Compatible) {
	                                                tracing::debug!(
	                                                    peer = %hex::encode(peer_id),
	                                                    compatibility = ?compatibility,
	                                                    "Ignoring discovery message from non-compatible peer"
	                                                );
	                                                continue;
	                                            }
	                                        }
	                                        let decoded =
	                                            bincode::deserialize::<DiscoveryMessage>(&data);
	                                        match decoded {
	                                            Ok(DiscoveryMessage::Hello { listen_port }) => {
	                                                if let Some((observed, _)) =
	                                                    connected_peers.get(&peer_id)
	                                                {
	                                                    let candidate =
	                                                        SocketAddr::new(observed.ip(), listen_port);
	                                                    if is_dialable_addr(&candidate) {
	                                                        let _ = peer_store
	                                                            .record_learned([candidate]);
	                                                    }
	                                                }
	                                            }
	                                            Ok(DiscoveryMessage::GetAddrs { limit }) => {
                                                // Basic rate limiting: ignore pathological requests.
                                                let limit = limit.min(DEFAULT_ADDR_LIMIT) as usize;
                                                let mut addrs: Vec<_> = peer_store
                                                    .addresses()
                                                    .into_iter()
                                                    .filter(|addr| is_dialable_addr(addr))
                                                    .collect();
                                                addrs.shuffle(&mut rand::thread_rng());
                                                addrs.truncate(limit);

                                                let msg = DiscoveryMessage::Addrs { addrs };
                                                if let Ok(encoded) = bincode::serialize(&msg) {
                                                    let _ = pq_handle_for_sync
                                                        .send_message(
                                                            peer_id,
                                                            DISCOVERY_PROTOCOL.to_string(),
                                                            encoded,
                                                        )
                                                        .await;
                                                }
                                            }
                                            Ok(DiscoveryMessage::Addrs { addrs }) => {
	                                                // Persist learned addrs.
	                                                let learned: Vec<_> = addrs
	                                                    .into_iter()
	                                                    .filter(|addr| is_dialable_addr(addr))
	                                                    .collect();
	                                                if !learned.is_empty() {
	                                                    let _ = peer_store
	                                                        .record_learned(learned.iter().copied());
	                                                }

	                                                // Opportunistically dial a small batch if we're under the
	                                                // minimum peer target.
	                                                let current_peers = pq_backend.peer_count().await;
	                                                if current_peers < discovery_min_peers {
	                                                    // Exclude addresses we are already connected to (by addr).
	                                                    let connected_addrs: HashSet<_> = pq_backend
	                                                        .peer_info()
	                                                        .await
	                                                        .into_iter()
                                                        .map(|info| info.addr)
                                                        .collect();

                                                    let mut dialed = 0usize;
                                                    for addr in learned {
                                                        if dialed >= DEFAULT_DIAL_BATCH {
                                                            break;
                                                        }
                                                        if connected_addrs.contains(&addr) {
                                                            continue;
                                                        }
                                                        if let Some(last) = recent_dials.get(&addr) {
                                                            if last.elapsed() < recent_dial_window {
                                                                continue;
                                                            }
                                                        }
                                                        recent_dials.insert(addr, Instant::now());

                                                        let pq_backend = Arc::clone(&pq_backend);
                                                        tokio::spawn(async move {
                                                            let _ = pq_backend.connect(addr).await;
                                                        });
                                                        dialed += 1;
                                                    }
                                                }
                                            }
                                            Ok(DiscoveryMessage::GetPeerGraph { limit }) => {
                                                let limit = limit.min(DEFAULT_PEER_GRAPH_LIMIT) as usize;
                                                let mut peers: Vec<_> = connected_peers
                                                    .iter()
                                                    .map(|(peer_id, (addr, _))| {
                                                        crate::substrate::discovery::PeerGraphEntry {
                                                            peer_id: *peer_id,
                                                            addr: *addr,
                                                        }
                                                    })
                                                    .collect();
                                                peers.shuffle(&mut rand::thread_rng());
                                                peers.truncate(limit);
                                                let msg = DiscoveryMessage::PeerGraph { peers };
                                                if let Ok(encoded) = bincode::serialize(&msg) {
                                                    let _ = pq_handle_for_sync
                                                        .send_message(
                                                            peer_id,
                                                            DISCOVERY_PROTOCOL.to_string(),
                                                            encoded,
                                                        )
                                                        .await;
                                                }
                                            }
                                            Ok(DiscoveryMessage::PeerGraph { peers }) => {
                                                let addr = connected_peers
                                                    .get(&peer_id)
                                                    .map(|(addr, _)| *addr);
                                                peer_graph_reports_for_events.write().insert(
                                                    peer_id,
                                                    PeerGraphReport {
                                                        reported_at: Instant::now(),
                                                        peers,
                                                    },
                                                );
                                                if addr.is_none() {
                                                    tracing::debug!(
                                                        peer = %hex::encode(peer_id),
                                                        "Received peer graph from unknown addr"
                                                    );
                                                }
                                            }
                                            Err(err) => {
	                                                tracing::debug!(
	                                                    peer = %hex::encode(peer_id),
	                                                    error = %err,
	                                                    "Failed to decode discovery message"
	                                                );
	                                            }
	                                        }
	                                    }
                                    // Handle sync protocol messages
                                    use crate::substrate::network_bridge::{
                                        ArtifactProtocolMessage, BlockAnnounce, DaChunkProtocolMessage,
                                        ARTIFACTS_PROTOCOL, BLOCK_ANNOUNCE_PROTOCOL, DA_CHUNKS_PROTOCOL,
                                        SYNC_PROTOCOL,
                                    };
                                    use crate::substrate::network_bridge::SyncMessage;
                                    // Handle sync protocol messages
                                    if protocol == SYNC_PROTOCOL {
                                        // Decode using wrapped sync messages with explicit request IDs.
                                        if let Ok(msg) = SyncMessage::decode(&mut &data[..]) {
                                            match msg {
                                                SyncMessage::RequestV2(envelope) => {
                                                    tracing::info!(
                                                        peer = %hex::encode(peer_id),
                                                        request_id = envelope.request_id,
                                                        request = ?envelope.request,
                                                        "Received sync request v2 from peer"
                                                    );
                                                    let mut sync = sync_service_clone.lock().await;
                                                    if let Some(response) = sync.handle_sync_request(
                                                        peer_id,
                                                        Some(envelope.request_id),
                                                        envelope.request,
                                                    ) {
                                                        let msg = SyncMessage::Response(response);
                                                        let encoded = msg.encode();
                                                        tracing::info!(
                                                            peer = %hex::encode(peer_id),
                                                            request_id = envelope.request_id,
                                                            response_len = encoded.len(),
                                                            "Sending sync response to peer"
                                                        );
                                                        if let Err(e) = pq_handle_for_sync
                                                            .send_message(
                                                                peer_id,
                                                                SYNC_PROTOCOL.to_string(),
                                                                encoded,
                                                            )
                                                            .await
                                                        {
                                                            tracing::warn!(
                                                                peer = %hex::encode(peer_id),
                                                                error = %e,
                                                                "Failed to send sync response"
                                                            );
                                                        }
                                                    }
                                                }
                                                SyncMessage::Response(response) => {
                                                    tracing::info!(
                                                        peer = %hex::encode(peer_id),
                                                        response = ?response,
                                                        "🔄 SYNC: Received sync response from peer - calling handle_sync_response"
                                                    );
                                                    let mut sync = sync_service_clone.lock().await;
                                                    sync.handle_sync_response(peer_id, response);
                                                    tracing::info!("🔄 SYNC: handle_sync_response completed");
                                                }
                                            }
                                        } else {
                                            tracing::debug!(
                                                peer = %hex::encode(peer_id),
                                                protocol = %protocol,
                                                data_len = data.len(),
                                                "Failed to decode sync message"
                                            );
                                        }
                                    }
                                    // Handle DA chunk request/response
                                    else if protocol == DA_CHUNKS_PROTOCOL {
                                        match DaChunkProtocolMessage::decode(&mut &data[..]) {
                                            Ok(DaChunkProtocolMessage::Request { root, indices }) => {
                                                let (proofs, missing) = {
                                                    let mut store = da_chunk_store_for_handler.lock();
                                                    match store.get(&root) {
                                                        Some(encoding) => {
                                                            let mut proofs = Vec::new();
                                                            let mut missing = Vec::new();
                                                            for index in indices.iter().copied() {
                                                                match encoding.proof(index) {
                                                                    Ok(proof) => proofs.push(proof),
                                                                    Err(_) => missing.push(index),
                                                                }
                                                            }
                                                            (proofs, missing)
                                                        }
                                                        None => (Vec::new(), indices.clone()),
                                                    }
                                                };

                                                if !proofs.is_empty() {
                                                    let response = DaChunkProtocolMessage::Response {
                                                        root,
                                                        proofs,
                                                    };
                                                    if let Err(e) = pq_handle_for_da
                                                        .send_message(
                                                            peer_id,
                                                            DA_CHUNKS_PROTOCOL.to_string(),
                                                            response.encode(),
                                                        )
                                                        .await
                                                    {
                                                        tracing::warn!(
                                                            peer = %hex::encode(peer_id),
                                                            error = %e,
                                                            "Failed to respond with DA chunk proofs"
                                                        );
                                                    }
                                                }

                                                if !missing.is_empty() {
                                                    let response = DaChunkProtocolMessage::NotFound {
                                                        root,
                                                        indices: missing,
                                                    };
                                                    if let Err(e) = pq_handle_for_da
                                                        .send_message(
                                                            peer_id,
                                                            DA_CHUNKS_PROTOCOL.to_string(),
                                                            response.encode(),
                                                        )
                                                        .await
                                                    {
                                                        tracing::warn!(
                                                            peer = %hex::encode(peer_id),
                                                            error = %e,
                                                            "Failed to respond with DA chunk not-found"
                                                        );
                                                    }
                                                }
                                            }
                                            Ok(DaChunkProtocolMessage::Response { root, proofs }) => {
                                                let mut tracker = da_request_tracker_for_handler.lock();
                                                tracker.fulfill_proofs(root, proofs);
                                            }
                                            Ok(DaChunkProtocolMessage::NotFound { root, indices }) => {
                                                let mut tracker = da_request_tracker_for_handler.lock();
                                                tracker.fulfill_not_found(root, indices);
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    peer = %hex::encode(peer_id),
                                                    protocol = %protocol,
                                                    error = %e,
                                                    data_len = data.len(),
                                                    "Failed to decode DA chunk message"
                                                );
                                            }
                                        }
                                    }
                                    else if protocol == ARTIFACTS_PROTOCOL {
                                        match ArtifactProtocolMessage::decode(&mut &data[..]) {
                                            Ok(ArtifactProtocolMessage::Announcement {
                                                artifact_hash,
                                                ..
                                            }) => {
                                                let coordinator =
                                                    prover_coordinator_for_events.read().clone();
                                                if let Some(coordinator) = coordinator {
                                                    if coordinator
                                                        .lookup_prepared_bundle_by_hash(artifact_hash)
                                                        .is_none()
                                                    {
                                                        let request = ArtifactProtocolMessage::Request {
                                                            artifact_hash,
                                                        };
                                                        let _ = pq_handle_for_status
                                                            .send_message(
                                                                peer_id,
                                                                ARTIFACTS_PROTOCOL.to_string(),
                                                                request.encode(),
                                                            )
                                                            .await;
                                                    }
                                                }
                                            }
                                            Ok(ArtifactProtocolMessage::Request { artifact_hash }) => {
                                                let coordinator =
                                                    prover_coordinator_for_events.read().clone();
                                                if let Some(coordinator) = coordinator {
                                                    let response = if let Some(bundle) =
                                                        coordinator.lookup_prepared_bundle_by_hash(
                                                            artifact_hash,
                                                        )
                                                    {
                                                        ArtifactProtocolMessage::Response {
                                                            artifact_hash,
                                                            payload: bundle.payload,
                                                            candidate_txs: bundle.candidate_txs,
                                                        }
                                                    } else {
                                                        ArtifactProtocolMessage::NotFound {
                                                            artifact_hash,
                                                        }
                                                    };
                                                    let _ = pq_handle_for_status
                                                        .send_message(
                                                            peer_id,
                                                            ARTIFACTS_PROTOCOL.to_string(),
                                                            response.encode(),
                                                        )
                                                        .await;
                                                }
                                            }
                                            Ok(ArtifactProtocolMessage::Response {
                                                artifact_hash: _,
                                                payload,
                                                candidate_txs,
                                            }) => {
                                                let coordinator =
                                                    prover_coordinator_for_events.read().clone();
                                                if let Some(coordinator) = coordinator {
                                                    let parent_hash =
                                                        client_for_network.chain_info().best_hash;
                                                    coordinator.import_network_artifact(
                                                        parent_hash,
                                                        payload,
                                                        candidate_txs,
                                                    );
                                                }
                                            }
                                            Ok(ArtifactProtocolMessage::NotFound { .. }) => {}
                                            Err(e) => {
                                                tracing::debug!(
                                                    peer = %hex::encode(peer_id),
                                                    protocol = %protocol,
                                                    error = %e,
                                                    "Failed to decode artifact protocol message"
                                                );
                                            }
                                        }
                                    }
                                    // Handle block announce messages - update peer's best height
                                    else if protocol == BLOCK_ANNOUNCE_PROTOCOL {
                                        if let Ok(announce) = BlockAnnounce::decode(&mut &data[..]) {
                                            let peer_best = announce.number;
                                            tracing::info!(
                                                peer = %hex::encode(peer_id),
                                                peer_best = peer_best,
                                                peer_hash = %hex::encode(&announce.hash),
                                                "Received block announce from peer"
                                            );

                                            // Update peer's best height in sync service
                                            let mut sync = sync_service_clone.lock().await;
                                            sync.on_block_announce(peer_id, &announce);
                                            sync_status_for_events
                                                .store(sync.is_syncing(), Ordering::Relaxed);
                                            if let Some(entry) =
                                                peer_details_for_events.write().get_mut(&peer_id)
                                            {
                                                if announce.number > entry.best_height {
                                                    entry.best_height = announce.number;
                                                    entry.best_hash = announce.hash;
                                                }
                                                entry.last_seen = Instant::now();
                                            }
                                        }
                                    }
                                }
	                                PqNetworkEvent::Stopped => {
	                                    peer_count_for_rpc.store(0, Ordering::Relaxed);
	                                    tracing::info!("PQ network stopped");
	                                    break;
	                                }
	                                _ => {}
	                            }

                                refresh_peer_connection_counters(
                                    &pq_backend,
                                    &peer_details_for_events,
                                )
                                .await;
	                                }
	                                _ = discovery_tick.tick() => {
                                        refresh_peer_connection_counters(
                                            &pq_backend,
                                            &peer_details_for_events,
                                        )
                                        .await;

	                                    let current_peers = if strict_compatibility {
	                                        let sync = sync_service_clone.lock().await;
	                                        connected_peers
	                                            .keys()
	                                            .filter(|peer_id| {
	                                                matches!(
	                                                    sync.peer_compatibility(peer_id),
	                                                    PeerCompatibility::Compatible
	                                                )
	                                            })
	                                            .count()
	                                    } else {
	                                        pq_backend.peer_count().await
	                                    };
	                                    if current_peers >= discovery_min_peers {
	                                        continue;
	                                    }

	                                    // Ask a random connected peer for addresses.
	                                    let mut peers: Vec<_> = connected_peers.keys().copied().collect();
	                                    if strict_compatibility {
	                                        let sync = sync_service_clone.lock().await;
	                                        peers.retain(|peer_id| {
	                                            matches!(
	                                                sync.peer_compatibility(peer_id),
	                                                PeerCompatibility::Compatible
	                                            )
	                                        });
	                                    }
	                                    peers.shuffle(&mut rand::thread_rng());
	                                    if let Some(peer_id) = peers.first().copied() {
	                                        let get_addrs = DiscoveryMessage::GetAddrs {
	                                            limit: DEFAULT_ADDR_LIMIT,
	                                        };
	                                        if let Ok(encoded) = bincode::serialize(&get_addrs) {
	                                            let _ = pq_handle_for_sync
	                                                .send_message(
	                                                    peer_id,
	                                                    DISCOVERY_PROTOCOL.to_string(),
	                                                    encoded,
	                                                )
	                                                .await;
	                                        }
	                                    }

	                                    if strict_compatibility {
	                                        continue;
	                                    }

	                                    // Dial a small batch of recent peers from the store.
	                                    let connected_addrs: HashSet<_> = pq_backend
	                                        .peer_info()
	                                        .await
	                                        .into_iter()
	                                        .map(|info| info.addr)
	                                        .collect();
	                                    let candidates = match peer_store
	                                        .recent_peers(DEFAULT_DIAL_BATCH * 2, &connected_addrs)
	                                    {
	                                        Ok(candidates) => candidates,
	                                        Err(err) => {
	                                            tracing::debug!(
	                                                error = %err,
	                                                "Failed to select recent peers from discovery store"
	                                            );
	                                            Vec::new()
	                                        }
	                                    };
	                                    let mut dialed = 0usize;
	                                    for addr in candidates {
	                                        if dialed >= DEFAULT_DIAL_BATCH {
	                                            break;
	                                        }
	                                        if !is_dialable_addr(&addr) {
	                                            continue;
	                                        }
	                                        if let Some(last) = recent_dials.get(&addr) {
	                                            if last.elapsed() < recent_dial_window {
	                                                continue;
	                                            }
	                                        }
	                                        recent_dials.insert(addr, Instant::now());
	                                        let pq_backend = Arc::clone(&pq_backend);
	                                        tokio::spawn(async move {
	                                            let _ = pq_backend.connect(addr).await;
	                                        });
	                                        dialed += 1;
	                                    }
	                                }
	                                _ = peer_graph_tick.tick() => {
                                        refresh_peer_connection_counters(
                                            &pq_backend,
                                            &peer_details_for_events,
                                        )
                                        .await;

	                                    let mut peers: Vec<_> = connected_peers.keys().copied().collect();
	                                    if strict_compatibility {
	                                        let sync = sync_service_clone.lock().await;
	                                        peers.retain(|peer_id| {
	                                            matches!(
	                                                sync.peer_compatibility(peer_id),
	                                                PeerCompatibility::Compatible
	                                            )
	                                        });
	                                    }
	                                    if peers.is_empty() {
	                                        continue;
	                                    }
	                                    let get_graph = DiscoveryMessage::GetPeerGraph {
	                                        limit: DEFAULT_PEER_GRAPH_LIMIT,
	                                    };
	                                    if let Ok(encoded) = bincode::serialize(&get_graph) {
	                                        for peer_id in peers {
	                                            let _ = pq_handle_for_sync
	                                                .send_message(
	                                                    peer_id,
	                                                    DISCOVERY_PROTOCOL.to_string(),
	                                                    encoded.clone(),
	                                                )
	                                                .await;
	                                        }
	                                    }
	                                }
	                            }
	                        }
	                    },
	                );

                // =======================================================================
                // Spawn sync state machine tick task
                // =======================================================================
                let sync_service_for_tick = Arc::clone(&sync_service);
                let sync_status_for_tick = Arc::clone(&sync_status);

                task_manager
                    .spawn_handle()
                    .spawn("chain-sync-tick", Some("sync"), async move {
                        use crate::substrate::network_bridge::{
                            SyncMessage, SyncRequestEnvelope, SYNC_PROTOCOL,
                        };

                        let mut interval =
                            tokio::time::interval(tokio::time::Duration::from_secs(1));
                        tracing::info!("Chain sync tick task started");

                        loop {
                            interval.tick().await;

                            let mut sync = sync_service_for_tick.lock().await;
                            let disconnect_incompatible = sync.drain_incompatible_peers();

                            // Tick the sync state machine
                            let next_request = sync.tick();

                            sync_status_for_tick.store(sync.is_syncing(), Ordering::Relaxed);

                            // Log sync status periodically
                            let state = sync.state();
                            if sync.is_syncing() {
                                tracing::debug!(
                                    state = ?state,
                                    peers = sync.peer_count(),
                                    "Sync in progress"
                                );
                            }
                            drop(sync);

                            for peer_id in disconnect_incompatible {
                                sync_handle_for_tick
                                    .disconnect(peer_id, "incompatible chain/protocol")
                                    .await;
                            }

                            if let Some((peer_id, request_id, request)) = next_request {
                                // Send request with explicit correlation id.
                                let msg = SyncMessage::RequestV2(SyncRequestEnvelope {
                                    request_id,
                                    request,
                                });
                                let encoded = msg.encode();
                                if let Err(e) = sync_handle_for_tick
                                    .send_message(peer_id, SYNC_PROTOCOL.to_string(), encoded)
                                    .await
                                {
                                    tracing::warn!(
                                        peer = %hex::encode(peer_id),
                                        error = %e,
                                        "Failed to send sync request"
                                    );
                                }
                            }
                        }
                    });

                // Spawn the transaction pool processing task
                task_manager.spawn_handle().spawn(
                    "tx-pool-processor",
                    Some("txpool"),
                    async move {
                        let interval = tokio::time::Duration::from_millis(process_interval);
                        let mut process_timer = tokio::time::interval(interval);

                        loop {
                            process_timer.tick().await;
                            let submitted = pool_bridge_for_processor.process_pending().await;

                            if submitted > 0 && pool_verbose {
                                tracing::debug!(
                                    submitted = submitted,
                                    "Processed pending transactions"
                                );
                            }
                        }
                    },
                );

                // =======================================================================
                // Spawn transaction propagation task
                // =======================================================================
                // This task broadcasts locally submitted transactions to all connected peers.
                // It polls the transaction pool for new ready transactions and broadcasts
                // any that haven't been broadcast yet.
                let transaction_pool_for_prop = transaction_pool.clone();

                task_manager
                    .spawn_handle()
                    .spawn("tx-propagation", Some("txpool"), async move {
                        use crate::substrate::network_bridge::{
                            TransactionMessage, TRANSACTIONS_PROTOCOL,
                        };
                        use sc_transaction_pool_api::{
                            InPoolTransaction, TransactionPool as ScTransactionPool,
                        };
                        use std::collections::HashSet;

                        // Track transactions we've already broadcast
                        let mut broadcast_txs: HashSet<sp_core::H256> = HashSet::new();
                        let mut interval =
                            tokio::time::interval(tokio::time::Duration::from_millis(500));

                        tracing::info!("Transaction propagation task started");

                        loop {
                            interval.tick().await;

                            // Get ready transactions from pool, plus futures as a fallback.
                            // InlineTx relays are not authoring locally, so a wallet-submitted
                            // transfer that temporarily sits in `future` still needs to reach the
                            // actual mining node instead of waiting forever on the relay.
                            let mut candidate_txs: Vec<(sp_core::H256, Vec<u8>)> =
                                transaction_pool_for_prop
                                    .ready()
                                    .map(|tx| {
                                        let hash: sp_core::H256 = *InPoolTransaction::hash(&*tx);
                                        let data = InPoolTransaction::data(&*tx).encode();
                                        (hash, data)
                                    })
                                    .collect();
                            let mut seen_hashes: std::collections::HashSet<sp_core::H256> =
                                candidate_txs.iter().map(|(hash, _)| *hash).collect();
                            for tx in transaction_pool_for_prop.futures() {
                                let hash: sp_core::H256 = *InPoolTransaction::hash(&tx);
                                if !seen_hashes.insert(hash) {
                                    continue;
                                }
                                let data = InPoolTransaction::data(&tx).encode();
                                candidate_txs.push((hash, data));
                            }

                            // Find transactions we haven't broadcast yet
                            let new_tx_pairs: Vec<(sp_core::H256, Vec<u8>)> = candidate_txs
                                .into_iter()
                                .filter(|(hash, _)| !broadcast_txs.contains(hash))
                                .collect();

                            // Broadcast new transactions. Only mark them as delivered if at least
                            // one connected peer actually received the message; otherwise retry on
                            // the next poll instead of stranding the tx forever.
                            if !new_tx_pairs.is_empty() {
                                let peer_count = pq_handle_for_tx_prop.peer_count().await;
                                if peer_count == 0 {
                                    tracing::debug!(
                                        tx_count = new_tx_pairs.len(),
                                        "Skipping tx propagation tick because no peers are connected"
                                    );
                                    continue;
                                }

                                let new_txs: Vec<Vec<u8>> =
                                    new_tx_pairs.iter().map(|(_, data)| data.clone()).collect();
                                let msg = TransactionMessage::new(new_txs.clone());
                                let encoded = msg.encode();

                                let failed = pq_handle_for_tx_prop
                                    .broadcast_to_all(TRANSACTIONS_PROTOCOL, encoded)
                                    .await;
                                let delivered = peer_count.saturating_sub(failed.len());

                                if delivered > 0 {
                                    for (hash, _) in &new_tx_pairs {
                                        broadcast_txs.insert(*hash);
                                    }
                                }

                                tracing::info!(
                                    tx_count = new_txs.len(),
                                    delivered_peers = delivered,
                                    peer_count,
                                    failed_peers = failed.len(),
                                    "📡 Broadcast transactions to peers"
                                );
                            }

                            // Prune old broadcast hashes to prevent memory growth
                            // Just remove entries older than a threshold since the pool
                            // will evict transactions after a while anyway
                            if broadcast_txs.len() > 10000 {
                                // Simple strategy: clear half the set
                                let to_remove: Vec<_> =
                                    broadcast_txs.iter().take(5000).copied().collect();
                                for h in to_remove {
                                    broadcast_txs.remove(&h);
                                }
                            }
                        }
                    });

                tracing::info!("Transaction propagation task spawned");

                // =======================================================================
                // Spawn block import task for network blocks
                // =======================================================================
                // This task processes:
                // 1. Incoming block announcements from peers (new blocks)
                // 2. Downloaded blocks from the sync service (historical sync)
                // Both go through the PowBlockImport pipeline.
                let block_import_bridge = Arc::clone(&network_bridge);
                let block_import_pow = pow_block_import.clone();
                let block_import_client = client.clone();
                let backend_for_import = backend.clone();
                let sync_service_for_import = Arc::clone(&sync_service);
                let da_chunk_store_for_import = Arc::clone(&da_chunk_store);
                let commitment_block_proof_store_for_import =
                    Arc::clone(&commitment_block_proof_store);
                let da_request_tracker_for_import = Arc::clone(&da_request_tracker);
                let da_params_for_import = da_params;
                let da_sample_timeout_for_import = da_sample_timeout;
                let da_sampling_secret_for_import = da_sampling_secret;
                let pq_handle_for_da_import = pq_handle_for_da_import.clone();
                let peer_details_for_import = Arc::clone(&peer_details);

                task_manager.spawn_handle().spawn(
                    "block-import-handler",
                    Some("consensus"),
                    async move {
                        use sc_consensus::{BlockImport, BlockImportParams};
                        use sp_consensus::BlockOrigin;
                        use sp_runtime::traits::Block as BlockT;

                        tracing::info!("Block import handler started (syncs blocks from network + historical sync)");

                        let proof_verification_enabled = proof_verification_enabled();
                        let parallel_verifier = ParallelProofVerifier::new();

                        let import_interval = tokio::time::Duration::from_millis(100);
                        let mut import_timer = tokio::time::interval(import_interval);

                        let mut blocks_imported: u64 = 0;
                        #[allow(unused_variables, unused_assignments)] // Counter for metrics/monitoring
                        let mut blocks_failed: u64 = 0;
                        let mut sync_blocks_imported: u64 = 0;

                        loop {
                            import_timer.tick().await;

                            // ============================================================
                            // Part 1: Process downloaded blocks from sync service
                            // ============================================================
                            let downloaded_blocks = {
                                let mut sync = sync_service_for_import.lock().await;
                                let blocks = sync.drain_downloaded();
                                if !blocks.is_empty() {
                                    tracing::info!(
                                        count = blocks.len(),
                                        "🔄 IMPORT: Got {} blocks from drain_downloaded to import",
                                        blocks.len()
                                    );
                                }
                                blocks
                            };

                            let mut downloaded_blocks = downloaded_blocks;
                            downloaded_blocks.sort_by_key(|block| block.number);
                            let mut downloaded_iter = downloaded_blocks.into_iter();
                            let mut deferred_downloads: Vec<DownloadedBlock> = Vec::new();
                            let mut reset_sync_after_revert = false;
                            let mut rewind_sync_to_missing_parent: Option<u64> = None;

                            while let Some(downloaded) = downloaded_iter.next() {
                                // Decode the header
                                let mut header = match runtime::Header::decode(&mut &downloaded.header[..]) {
                                    Ok(h) => h,
                                    Err(e) => {
                                        tracing::warn!(
                                            peer = %hex::encode(&downloaded.from_peer),
                                            block_number = downloaded.number,
                                            error = %e,
                                            "Failed to decode synced block header"
                                        );
                                        blocks_failed += 1;
                                        continue;
                                    }
                                };

                                // Decode extrinsics
                                let extrinsics: Vec<runtime::UncheckedExtrinsic> = downloaded.body
                                    .iter()
                                    .filter_map(|ext_bytes| {
                                        runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..]).ok()
                                    })
                                    .collect();

                                let block_number = *header.number();
                                let parent_hash = *header.parent_hash();

                                match block_import_client.header(parent_hash) {
                                    Ok(Some(_)) => {}
                                    Ok(None) => {
                                        deferred_downloads = collect_deferred_downloaded_tail(
                                            downloaded,
                                            downloaded_iter.by_ref(),
                                        );
                                        rewind_sync_to_missing_parent = Some(block_number as u64);
                                        tracing::debug!(
                                            peer = %hex::encode(&deferred_downloads[0].from_peer),
                                            block_number,
                                            parent = %hex::encode(parent_hash.as_bytes()),
                                            deferred = deferred_downloads.len(),
                                            "Deferring synced block tail until parent header becomes visible"
                                        );
                                        break;
                                    }
                                    Err(err) => {
                                        tracing::warn!(
                                            peer = %hex::encode(&downloaded.from_peer),
                                            block_number,
                                            parent = %hex::encode(parent_hash.as_bytes()),
                                            error = %err,
                                            "Failed to query parent header; dropping synced block"
                                        );
                                        continue;
                                    }
                                }

                                let requires_sidecar = has_sidecar_transfers(&extrinsics);
                                let missing_statement_hashes =
                                    missing_proof_binding_hashes(&extrinsics);
                                let needs_self_contained_batch =
                                    requires_sidecar && !missing_statement_hashes.is_empty();
                                let da_policy =
                                    fetch_da_policy(block_import_client.as_ref(), parent_hash);
                                let mut da_build = if needs_self_contained_batch {
                                    let maybe_payload = match extract_proven_batch_payload(&extrinsics)
                                    {
                                        Ok(Some(payload)) => Some(payload.payload),
                                        Ok(None) => {
                                            tracing::warn!(
                                                peer = %hex::encode(&downloaded.from_peer),
                                                block_number,
                                                "Rejecting synced block (missing proven batch for proofless sidecar transfers)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }
                                        Err(err) => {
                                            tracing::warn!(
                                                peer = %hex::encode(&downloaded.from_peer),
                                                block_number,
                                                error = %err,
                                                "Rejecting synced block (failed to parse proven batch payload)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }
                                    };
                                    if let Some(payload) = maybe_payload {
                                        match da_policy {
                                            pallet_shielded_pool::types::DaAvailabilityPolicy::FullFetch => {
                                                match fetch_da_for_block(
                                                    downloaded.from_peer,
                                                    payload.da_root,
                                                    &extrinsics,
                                                    da_params_for_import,
                                                    &pq_handle_for_da_import,
                                                    &da_request_tracker_for_import,
                                                    da_sample_timeout_for_import,
                                                )
                                                .await
                                                {
                                                    Ok(build) => Some(build),
                                                    Err(err) => {
                                                        tracing::warn!(
                                                            peer = %hex::encode(&downloaded.from_peer),
                                                            block_number,
                                                            error = %err,
                                                            "Rejecting synced block (DA fetch failed)"
                                                        );
                                                        blocks_failed += 1;
                                                        continue;
                                                    }
                                                }
                                            }
                                            pallet_shielded_pool::types::DaAvailabilityPolicy::Sampling => {
                                                if let Err(err) = sample_da_for_root(
                                                    downloaded.from_peer,
                                                    payload.da_root,
                                                    payload.da_chunk_count,
                                                    downloaded.hash,
                                                    da_sampling_secret_for_import,
                                                    da_params_for_import,
                                                    &pq_handle_for_da_import,
                                                    &da_request_tracker_for_import,
                                                    da_sample_timeout_for_import,
                                                )
                                                .await
                                                {
                                                    tracing::warn!(
                                                        peer = %hex::encode(&downloaded.from_peer),
                                                        block_number,
                                                        error = %err,
                                                        "Rejecting synced block (DA sampling failed)"
                                                    );
                                                    blocks_failed += 1;
                                                    continue;
                                                }
                                                None
                                            }
                                        }
                                    } else {
                                        None
                                    }
                                } else if requires_sidecar {
                                    // Sidecar extrinsics with inline proofs can be verified from
                                    // statement hashes without a same-block submit_proven_batch.
                                    None
                                } else {
                                    match da_policy {
                                        pallet_shielded_pool::types::DaAvailabilityPolicy::FullFetch => {
                                            match build_da_encoding_from_extrinsics(
                                                &extrinsics,
                                                da_params_for_import,
                                                None,
                                            ) {
                                                Ok(build) => Some(build),
                                                Err(err) => {
                                                    tracing::warn!(
                                                        peer = %hex::encode(&downloaded.from_peer),
                                                        block_number,
                                                        error = %err,
                                                        "Rejecting synced block (DA encoding failed)"
                                                    );
                                                    blocks_failed += 1;
                                                    continue;
                                                }
                                            }
                                        }
                                        pallet_shielded_pool::types::DaAvailabilityPolicy::Sampling => {
                                            match sample_da_for_block(
                                                downloaded.from_peer,
                                                downloaded.hash,
                                                da_sampling_secret_for_import,
                                                &extrinsics,
                                                da_params_for_import,
                                                &pq_handle_for_da_import,
                                                &da_request_tracker_for_import,
                                                da_sample_timeout_for_import,
                                            )
                                            .await
                                            {
                                                Ok(build) => Some(build),
                                                Err(err) => {
                                                    tracing::warn!(
                                                        peer = %hex::encode(&downloaded.from_peer),
                                                        block_number,
                                                        error = %err,
                                                        "Rejecting synced block (DA sampling failed)"
                                                    );
                                                    blocks_failed += 1;
                                                    continue;
                                                }
                                            }
                                        }
                                    }
                                };

                                let mut commitment_block_proof = None;
                                if proof_verification_enabled {
                                    if !missing_statement_hashes.is_empty() {
                                        let policy = match fetch_proof_availability_policy(
                                            block_import_client.as_ref(),
                                            parent_hash,
                                        ) {
                                            Ok(policy) => policy,
                                            Err(err) => {
                                                if is_retryable_sync_parent_state_error(&err) {
                                                    deferred_downloads = collect_deferred_downloaded_tail(
                                                        downloaded,
                                                        downloaded_iter.by_ref(),
                                                    );
                                                    tracing::debug!(
                                                        peer = %hex::encode(&deferred_downloads[0].from_peer),
                                                        block_number,
                                                        parent = %hex::encode(parent_hash.as_bytes()),
                                                        error = %err,
                                                        deferred = deferred_downloads.len(),
                                                        "Deferring synced block tail until parent state is ready for proof availability policy"
                                                    );
                                                    break;
                                                }
                                                tracing::warn!(
                                                    peer = %hex::encode(&downloaded.from_peer),
                                                    block_number,
                                                    error = %err,
                                                    "Rejecting synced block (failed to read proof availability policy)"
                                                );
                                                blocks_failed += 1;
                                                continue;
                                            }
                                        };

                                        if !matches!(
                                            policy,
                                            pallet_shielded_pool::types::ProofAvailabilityPolicy::SelfContained
                                        ) {
                                            tracing::warn!(
                                                peer = %hex::encode(&downloaded.from_peer),
                                                block_number,
                                                policy = ?policy,
                                                "Rejecting synced block (missing proof bytes but policy is not SelfContained)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }
                                    }

                                    let resolved_ciphertexts =
                                        da_build.as_ref().map(|build| build.transactions.as_slice());
                                    commitment_block_proof = match verify_proof_carrying_block(
                                        &parallel_verifier,
                                        block_import_client.as_ref(),
                                        parent_hash,
                                        block_number,
                                        &extrinsics,
                                        da_params_for_import,
                                        da_policy,
                                        resolved_ciphertexts,
                                        None,
                                    ) {
                                        Ok(proof) => proof,
                                        Err(err) => {
                                            if is_retryable_sync_parent_state_error(&err) {
                                                deferred_downloads = collect_deferred_downloaded_tail(
                                                    downloaded,
                                                    downloaded_iter.by_ref(),
                                                );
                                                tracing::debug!(
                                                    peer = %hex::encode(&deferred_downloads[0].from_peer),
                                                    block_number,
                                                    parent = %hex::encode(parent_hash.as_bytes()),
                                                    error = %err,
                                                    deferred = deferred_downloads.len(),
                                                    "Deferring synced block tail until parent state is ready"
                                                );
                                                break;
                                            }
                                            tracing::warn!(
                                                peer = %hex::encode(&downloaded.from_peer),
                                                block_number,
                                                error = %err,
                                                "Rejecting synced block (proof verification failed)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }
                                    };
                                }

                                use sp_runtime::traits::Header as HeaderT;
                                let post_hash = header.hash(); // final block hash (includes seal)
                                let mut block_hash = [0u8; 32];
                                block_hash.copy_from_slice(post_hash.as_bytes());

                                // CRITICAL: Extract the seal from header digest and move to post_digests
                                // PowBlockImport expects the seal in post_digests.last(), not in header.digest()
                                // The seal should be the last digest item with engine ID "pow_"
                                let seal = header.digest_mut().pop();

                                let seal_item = match seal {
                                    Some(item) => {
                                        tracing::debug!(
                                            block_number,
                                            "Extracted seal from header for block import"
                                        );
                                        item
                                    }
                                    None => {
                                        tracing::warn!(
                                            block_number,
                                            "No seal found in header digest, skipping block"
                                        );
                                        blocks_failed += 1;
                                        continue;
                                    }
                                };

                                // Compute pre_hash (hash of header WITHOUT seal)
                                // This is what Sha256dAlgorithm::verify will use to validate the PoW
                                let pre_hash = header.hash();
                                tracing::info!(
                                    block_number,
                                    pre_hash = %hex::encode(pre_hash.as_bytes()),
                                    post_hash = %hex::encode(post_hash.as_bytes()),
                                    digest_logs_after_pop = header.digest().logs().len(),
                                    "🔍 DEBUG: Pre-hash computed after stripping seal"
                                );

                                // Construct BlockImportParams with seal in post_digests
                                let extrinsics_for_ciphertexts = extrinsics.clone();
                                let mut import_params = BlockImportParams::new(BlockOrigin::NetworkInitialSync, header);
                                import_params.body = Some(extrinsics);
                                configure_pow_import_params(&mut import_params, seal_item, post_hash);

                                // Import through PowBlockImport (verifies PoW seal)
                                let import_result = block_import_pow.clone().import_block(import_params).await;

                                match import_result {
                                    Ok(sc_consensus::ImportResult::Imported(_)) => {
                                        blocks_imported += 1;
                                        sync_blocks_imported += 1;
                                        {
                                            let mut store = da_chunk_store_for_import.lock();
                                            let mut ciphertexts = if let Some(build) = da_build.take() {
                                                let da_root = build.encoding.root();
                                                let da_chunks = build.encoding.chunks().len();
                                                let ciphertexts = flatten_ciphertexts(&build.transactions);
                                                if let Err(err) = store.insert(
                                                    DaRootKind::Ciphertexts,
                                                    block_number as u64,
                                                    block_hash,
                                                    build.encoding,
                                                ) {
                                                    tracing::warn!(
                                                        block_number,
                                                        da_root = %hex::encode(da_root),
                                                        error = %err,
                                                        "Failed to persist DA encoding for synced block"
                                                    );
                                                } else {
                                                    tracing::info!(
                                                        block_number,
                                                        da_root = %hex::encode(da_root),
                                                        da_chunks,
                                                        "DA encoding stored for synced block"
                                                    );
                                                }
                                                ciphertexts
                                            } else {
                                                transfer_ciphertexts_from_extrinsics(&extrinsics_for_ciphertexts)
                                            };
                                            ciphertexts.extend(coinbase_ciphertexts_from_extrinsics(
                                                &extrinsics_for_ciphertexts,
                                            ));
                                            let ciphertext_count = ciphertexts.len();
                                            if let Err(err) = store.append_ciphertexts(
                                                block_number as u64,
                                                block_hash,
                                                &ciphertexts,
                                            ) {
                                                tracing::warn!(
                                                    block_number,
                                                    error = %err,
                                                    "Failed to persist ciphertexts for synced block"
                                                );
                                            } else if ciphertext_count > 0 {
                                                tracing::info!(
                                                    block_number,
                                                    ciphertext_count,
                                                    "Ciphertexts stored for synced block"
                                                );
                                            }
                                        }

                                        // Notify sync service of successful import
                                        {
                                            let mut sync = sync_service_for_import.lock().await;
                                            sync.on_block_imported(block_number as u64, block_hash);
                                        }

                                        if let Some(proof) = commitment_block_proof.take() {
                                            let proof_size = proof.proof_bytes.len();
                                            let proof_hash = proof.proof_hash;
                                            commitment_block_proof_store_for_import
                                                .lock()
                                                .insert(post_hash, proof);
                                            tracing::info!(
                                                peer = %hex::encode(&downloaded.from_peer),
                                                block_number,
                                                block_hash = %hex::encode(post_hash.as_bytes()),
                                                proof_size,
                                                proof_hash = %hex::encode(proof_hash),
                                                "Commitment block proof stored for imported block"
                                            );
                                        }

                                        if sync_blocks_imported.is_multiple_of(100) {
                                            tracing::info!(
                                                block_number,
                                                sync_imported = sync_blocks_imported,
                                                total_imported = blocks_imported,
                                                "Sync progress: {} blocks imported",
                                                sync_blocks_imported
                                            );
                                        } else {
                                            tracing::debug!(
                                                block_number,
                                                hash = %hex::encode(&downloaded.hash),
                                                "Synced block imported"
                                            );
                                        }
                                    }
                                    Ok(sc_consensus::ImportResult::AlreadyInChain) => {
                                        // Treat AlreadyInChain as progress for the sync cursor, so a node that
                                        // reconnects after mining on a fork can still advance without stalling.
                                        {
                                            let mut sync = sync_service_for_import.lock().await;
                                            sync.on_block_imported(block_number as u64, block_hash);
                                        }

                                        let mut store = da_chunk_store_for_import.lock();
                                        let mut ciphertexts = if let Some(build) = da_build.take() {
                                            let da_root = build.encoding.root();
                                            let da_chunks = build.encoding.chunks().len();
                                            let ciphertexts = flatten_ciphertexts(&build.transactions);
                                            if let Err(err) = store.insert(
                                                DaRootKind::Ciphertexts,
                                                block_number as u64,
                                                block_hash,
                                                build.encoding,
                                            ) {
                                                tracing::warn!(
                                                    block_number,
                                                    da_root = %hex::encode(da_root),
                                                    error = %err,
                                                    "Failed to persist DA encoding for known synced block"
                                                );
                                            } else {
                                                tracing::info!(
                                                    block_number,
                                                    da_root = %hex::encode(da_root),
                                                    da_chunks,
                                                    "DA encoding stored for known synced block"
                                                );
                                            }
                                            ciphertexts
                                        } else {
                                            transfer_ciphertexts_from_extrinsics(&extrinsics_for_ciphertexts)
                                        };
                                        ciphertexts.extend(coinbase_ciphertexts_from_extrinsics(
                                            &extrinsics_for_ciphertexts,
                                        ));
                                        let ciphertext_count = ciphertexts.len();
                                        if let Err(err) = store.append_ciphertexts(
                                            block_number as u64,
                                            block_hash,
                                            &ciphertexts,
                                        ) {
                                            tracing::warn!(
                                                block_number,
                                                error = %err,
                                                "Failed to persist ciphertexts for known synced block"
                                            );
                                        } else if ciphertext_count > 0 {
                                            tracing::info!(
                                                block_number,
                                                ciphertext_count,
                                                "Ciphertexts stored for known synced block"
                                            );
                                        }
                                        if let Some(proof) = commitment_block_proof.take() {
                                            let proof_size = proof.proof_bytes.len();
                                            let proof_hash = proof.proof_hash;
                                            commitment_block_proof_store_for_import
                                                .lock()
                                                .insert(post_hash, proof);
                                            tracing::info!(
                                                peer = %hex::encode(&downloaded.from_peer),
                                                block_number,
                                                block_hash = %hex::encode(post_hash.as_bytes()),
                                                proof_size,
                                                proof_hash = %hex::encode(proof_hash),
                                                "Commitment block proof stored for known block"
                                            );
                                        }
                                        tracing::trace!(
                                            block_number,
                                            "Synced block already in chain"
                                        );
                                    }
                                    Ok(sc_consensus::ImportResult::KnownBad) => {
                                        blocks_failed += 1;
                                        tracing::warn!(
                                            peer = %hex::encode(&downloaded.from_peer),
                                            block_number,
                                            "Synced block is known bad - PoW invalid"
                                        );
                                    }
                                    Ok(sc_consensus::ImportResult::UnknownParent) => {
                                        deferred_downloads = collect_deferred_downloaded_tail(
                                            downloaded,
                                            downloaded_iter.by_ref(),
                                        );
                                        rewind_sync_to_missing_parent = Some(block_number as u64);
                                        tracing::debug!(
                                            block_number,
                                            parent = %hex::encode(parent_hash.as_bytes()),
                                            deferred = deferred_downloads.len(),
                                            "Deferring synced block tail until parent import completes"
                                        );
                                        break;
                                    }
                                    Ok(sc_consensus::ImportResult::MissingState) => {
                                        deferred_downloads = collect_deferred_downloaded_tail(
                                            downloaded,
                                            downloaded_iter.by_ref(),
                                        );
                                        rewind_sync_to_missing_parent = Some(block_number as u64);
                                        tracing::warn!(
                                            block_number,
                                            deferred = deferred_downloads.len(),
                                            "Deferring synced block tail until parent state becomes available"
                                        );
                                        break;
                                    }
                                    Err(e) => {
                                        let error_text = e.to_string();
                                        if is_finalized_chain_conflict_error(&error_text) {
                                            let info_before = backend_for_import.blockchain().info();
                                            let finalized_before: u64 =
                                                info_before.finalized_number.try_into().unwrap_or(0);
                                            if finalized_before > 0 {
                                                match ClientBackend::revert(
                                                    backend_for_import.as_ref(),
                                                    1u64,
                                                    true,
                                                ) {
                                                    Ok((reverted_blocks, reverted_finalized)) => {
                                                        let reverted_blocks: u64 = reverted_blocks
                                                            .try_into()
                                                            .unwrap_or(0);
                                                        if reverted_blocks > 0 {
                                                            let info_after = backend_for_import
                                                                .blockchain()
                                                                .info();
                                                            let finalized_after: u64 = info_after
                                                                .finalized_number
                                                                .try_into()
                                                                .unwrap_or(0);
                                                            let best_after: u64 = info_after
                                                                .best_number
                                                                .try_into()
                                                                .unwrap_or(0);
                                                            deferred_downloads =
                                                                collect_deferred_downloaded_tail(
                                                                    downloaded,
                                                                    downloaded_iter.by_ref(),
                                                                );
                                                            reset_sync_after_revert = true;
                                                            tracing::warn!(
                                                                peer = %hex::encode(&deferred_downloads[0].from_peer),
                                                                block_number,
                                                                finalized_before,
                                                                finalized_after,
                                                                best_after,
                                                                reverted_blocks,
                                                                reverted_finalized = reverted_finalized.len(),
                                                                deferred = deferred_downloads.len(),
                                                                "Recovered poisoned finalized head after sync import hit NotInFinalizedChain"
                                                            );
                                                            break;
                                                        }
                                                        tracing::warn!(
                                                            peer = %hex::encode(&downloaded.from_peer),
                                                            block_number,
                                                            finalized_before,
                                                            "Unsafe revert returned zero blocks after finalized-chain conflict"
                                                        );
                                                    }
                                                    Err(revert_err) => {
                                                        tracing::warn!(
                                                            peer = %hex::encode(&downloaded.from_peer),
                                                            block_number,
                                                            finalized_before,
                                                            error = %revert_err,
                                                            "Failed to revert poisoned finalized head after sync import conflict"
                                                        );
                                                    }
                                                }
                                            } else {
                                                tracing::warn!(
                                                    peer = %hex::encode(&downloaded.from_peer),
                                                    block_number,
                                                    error = %error_text,
                                                    "Finalized-chain conflict reported at genesis finalized head"
                                                );
                                            }
                                        }
                                        blocks_failed += 1;
                                        tracing::warn!(
                                            peer = %hex::encode(&downloaded.from_peer),
                                            block_number,
                                            error = ?e,
                                            "Synced block import failed"
                                        );
                                    }
                                }
                            }

                            if !deferred_downloads.is_empty() {
                                let deferred_count = deferred_downloads.len();
                                let first_number = deferred_downloads.first().map(|block| block.number).unwrap_or(0);
                                let last_number = deferred_downloads
                                    .last()
                                    .map(|block| block.number)
                                    .unwrap_or(first_number);
                                let mut sync = sync_service_for_import.lock().await;
                                if reset_sync_after_revert {
                                    sync.on_local_revert();
                                }
                                if let Some(child_number) = rewind_sync_to_missing_parent {
                                    sync.on_downloaded_parent_missing(child_number);
                                }
                                sync.requeue_downloaded(deferred_downloads);
                                tracing::info!(
                                    deferred = deferred_count,
                                    first_number,
                                    last_number,
                                    "Deferred synced block tail requeued for retry"
                                );
                            }

                            // ============================================================
                            // Part 2: Process block announcements (new blocks from mining)
                            // ============================================================
                            // Drain pending block announcements from the bridge
	                            let pending_announces = {
	                                let mut bridge = block_import_bridge.lock().await;
	                                bridge.drain_announces()
	                            };
	                            for (peer_id, announce) in pending_announces {
                                // Update sync service with block announcement to track peer's best height
                                // This is critical for triggering historical sync when we're behind
	                                {
	                                    let mut sync = sync_service_for_import.lock().await;
	                                    sync.on_block_announce(peer_id, &announce);
	                                }
	                                if let Some(entry) = peer_details_for_import.write().get_mut(&peer_id) {
	                                    if announce.number > entry.best_height {
	                                        entry.best_height = announce.number;
	                                        entry.best_hash = announce.hash;
	                                    }
	                                    entry.last_seen = Instant::now();
	                                }

	                                let crate::substrate::network_bridge::BlockAnnounce {
	                                    header: announce_header,
	                                    state: _,
	                                    number: announce_number,
	                                    hash: _,
	                                    body,
	                                } = announce;

	                                // Only process blocks that have a body (full blocks)
	                                let body = match body {
	                                    Some(body) => body,
	                                    None => {
	                                        // Header-only announcement - the sync service was already
	                                        // notified above, so it can request the full block
	                                        tracing::trace!(
	                                            peer = %hex::encode(&peer_id),
	                                            block_number = announce_number,
	                                            "Header-only announcement - sync service notified"
	                                        );
	                                        continue;
	                                    }
	                                };

	                                // Decode the header
	                                let header =
	                                    match runtime::Header::decode(&mut &announce_header[..]) {
	                                    Ok(h) => h,
	                                    Err(e) => {
	                                        tracing::warn!(
	                                            peer = %hex::encode(&peer_id),
	                                            error = %e,
                                            "Failed to decode block header"
                                        );
                                        blocks_failed += 1;
	                                        continue;
	                                    }
	                                };

	                                let block_number = *header.number();
	                                let parent_hash = *header.parent_hash();

	                                match block_import_client.header(parent_hash) {
	                                    Ok(Some(_)) => {}
	                                    Ok(None) => {
	                                        tracing::debug!(
	                                            peer = %hex::encode(&peer_id),
	                                            block_number,
	                                            parent = %hex::encode(parent_hash.as_bytes()),
	                                            "Dropping announced full block with unknown parent; sync service will fetch canonical range"
	                                        );
	                                        continue;
	                                    }
	                                    Err(err) => {
	                                        tracing::warn!(
	                                            peer = %hex::encode(&peer_id),
	                                            block_number,
	                                            parent = %hex::encode(parent_hash.as_bytes()),
	                                            error = %err,
	                                            "Failed to query parent header; dropping announced full block"
	                                        );
	                                        continue;
	                                    }
	                                }

	                                // Decode extrinsics
	                                let extrinsics: Vec<runtime::UncheckedExtrinsic> = body
	                                    .iter()
	                                    .filter_map(|ext_bytes| {
	                                        runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..]).ok()
                                    })
                                    .collect();

	                                // Create the block
	                                let block = runtime::Block::new(header.clone(), extrinsics.clone());
	                                let block_hash = block.hash();
	                                let mut block_hash_bytes = [0u8; 32];
	                                block_hash_bytes.copy_from_slice(block_hash.as_bytes());

                                let requires_sidecar = has_sidecar_transfers(&extrinsics);
                                let missing_statement_hashes =
                                    missing_proof_binding_hashes(&extrinsics);
                                let needs_self_contained_batch =
                                    requires_sidecar && !missing_statement_hashes.is_empty();
                                let da_policy =
                                    fetch_da_policy(block_import_client.as_ref(), parent_hash);
                                let mut da_build = if needs_self_contained_batch {
                                    let maybe_payload = match extract_proven_batch_payload(&extrinsics)
                                    {
                                        Ok(Some(payload)) => Some(payload.payload),
                                        Ok(None) => {
                                            tracing::warn!(
                                                peer = %hex::encode(&peer_id),
                                                block_number,
                                                "Rejecting announced block (missing proven batch for proofless sidecar transfers)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }
                                        Err(err) => {
                                            tracing::warn!(
                                                peer = %hex::encode(&peer_id),
                                                block_number,
                                                error = %err,
                                                "Rejecting announced block (failed to parse proven batch payload)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }
                                    };
                                    if let Some(payload) = maybe_payload {
                                        match da_policy {
                                            pallet_shielded_pool::types::DaAvailabilityPolicy::FullFetch => {
                                                match fetch_da_for_block(
                                                    peer_id,
                                                    payload.da_root,
                                                    &extrinsics,
                                                    da_params_for_import,
                                                    &pq_handle_for_da_import,
                                                    &da_request_tracker_for_import,
                                                    da_sample_timeout_for_import,
                                                )
                                                .await
                                                {
                                                    Ok(build) => Some(build),
                                                    Err(err) => {
                                                        tracing::warn!(
                                                            peer = %hex::encode(&peer_id),
                                                            block_number,
                                                            error = %err,
                                                            "Rejecting announced block (DA fetch failed)"
                                                        );
                                                        blocks_failed += 1;
                                                        continue;
                                                    }
                                                }
                                            }
                                            pallet_shielded_pool::types::DaAvailabilityPolicy::Sampling => {
                                                if let Err(err) = sample_da_for_root(
                                                    peer_id,
                                                    payload.da_root,
                                                    payload.da_chunk_count,
                                                    block_hash_bytes,
                                                    da_sampling_secret_for_import,
                                                    da_params_for_import,
                                                    &pq_handle_for_da_import,
                                                    &da_request_tracker_for_import,
                                                    da_sample_timeout_for_import,
                                                )
                                                .await
                                                {
                                                    tracing::warn!(
                                                        peer = %hex::encode(&peer_id),
                                                        block_number,
                                                        error = %err,
                                                        "Rejecting announced block (DA sampling failed)"
                                                    );
                                                    blocks_failed += 1;
                                                    continue;
                                                }
                                                None
                                            }
                                        }
                                    } else {
                                        None
                                    }
                                } else if requires_sidecar {
                                    // Sidecar extrinsics with inline proofs can be verified from
                                    // statement hashes without a same-block submit_proven_batch.
                                    None
                                } else {
                                    match da_policy {
                                        pallet_shielded_pool::types::DaAvailabilityPolicy::FullFetch => {
                                            match build_da_encoding_from_extrinsics(
                                                &extrinsics,
                                                da_params_for_import,
                                                None,
                                            ) {
                                                Ok(build) => Some(build),
                                                Err(err) => {
                                                    tracing::warn!(
                                                        peer = %hex::encode(&peer_id),
                                                        block_number,
                                                        error = %err,
                                                        "Rejecting announced block (DA encoding failed)"
                                                    );
                                                    blocks_failed += 1;
                                                    continue;
                                                }
                                            }
                                        }
                                        pallet_shielded_pool::types::DaAvailabilityPolicy::Sampling => {
                                            match sample_da_for_block(
                                                peer_id,
                                                block_hash_bytes,
                                                da_sampling_secret_for_import,
                                                &extrinsics,
                                                da_params_for_import,
                                                &pq_handle_for_da_import,
                                                &da_request_tracker_for_import,
                                                da_sample_timeout_for_import,
                                            )
                                            .await
                                            {
                                                Ok(build) => Some(build),
                                                Err(err) => {
                                                    tracing::warn!(
                                                        peer = %hex::encode(&peer_id),
                                                        block_number,
                                                        error = %err,
                                                        "Rejecting announced block (DA sampling failed)"
                                                    );
                                                    blocks_failed += 1;
                                                    continue;
                                                }
                                            }
                                        }
                                    }
                                };

                                let mut commitment_block_proof = None;
                                if proof_verification_enabled {
                                    if !missing_statement_hashes.is_empty() {
                                        let policy =
                                            match fetch_proof_availability_policy(
                                                block_import_client.as_ref(),
                                                parent_hash,
                                            ) {
                                                Ok(policy) => policy,
                                                Err(err) => {
                                                    tracing::warn!(
                                                        peer = %hex::encode(&peer_id),
                                                        block_number,
                                                        error = %err,
                                                        "Rejecting announced block (failed to read proof availability policy)"
                                                    );
                                                    blocks_failed += 1;
                                                    continue;
                                                }
                                            };

                                        if !matches!(
                                            policy,
                                            pallet_shielded_pool::types::ProofAvailabilityPolicy::SelfContained
                                        ) {
                                            tracing::warn!(
                                                peer = %hex::encode(&peer_id),
                                                block_number,
                                                policy = ?policy,
                                                "Rejecting announced block (missing proof bytes but policy is not SelfContained)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }
                                    }

                                    let resolved_ciphertexts =
                                        da_build.as_ref().map(|build| build.transactions.as_slice());
                                    commitment_block_proof = match verify_proof_carrying_block(
                                        &parallel_verifier,
                                        block_import_client.as_ref(),
                                        parent_hash,
                                        block_number,
                                        &extrinsics,
                                        da_params_for_import,
                                        da_policy,
                                        resolved_ciphertexts,
                                        None,
                                    ) {
                                        Ok(proof) => proof,
                                        Err(err) => {
                                            tracing::warn!(
                                                peer = %hex::encode(&peer_id),
                                                block_number,
                                                error = %err,
                                                "Rejecting announced block (proof verification failed)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }
                                    };
                                }

                                // Check if we already have this block
                                if block_import_client.chain_info().best_number >= block_number {
                                    // We might already have this block or a better one
                                    tracing::trace!(
                                        block_number,
                                        "Block at or below our best, checking if duplicate"
                                    );
                                }

                                // CRITICAL: Extract the seal from header digest and move to post_digests
                                // PowBlockImport expects the seal in post_digests.last(), not in header.digest()
                                // The seal should be the last digest item with engine ID "pow_"
                                use sp_runtime::traits::Header as HeaderT;
                                let mut header_mut = header.clone();
                                let post_hash = header_mut.hash(); // Hash before removing seal (this is the final block hash)
                                let seal = header_mut.digest_mut().pop();

                                let seal_item = match seal {
                                    Some(item) => item,
                                    None => {
                                        tracing::warn!(
                                            block_number,
                                            "No seal found in announced block header, skipping"
                                        );
                                        blocks_failed += 1;
                                        continue;
                                    }
                                };

                                // Construct BlockImportParams with seal in post_digests
                                let extrinsics_for_ciphertexts = extrinsics.clone();
                                let mut import_params = BlockImportParams::new(BlockOrigin::NetworkBroadcast, header_mut);
                                import_params.body = Some(extrinsics);
                                configure_pow_import_params(&mut import_params, seal_item, post_hash);

                                // Import through PowBlockImport (verifies PoW seal)
                                let import_result = block_import_pow.clone().import_block(import_params).await;

                                match import_result {
                                    Ok(sc_consensus::ImportResult::Imported(_)) => {
                                        blocks_imported += 1;
                                        let mut store = da_chunk_store_for_import.lock();
                                        let mut ciphertexts = if let Some(build) = da_build.take() {
                                            let da_root = build.encoding.root();
                                            let da_chunks = build.encoding.chunks().len();
                                            let ciphertexts = flatten_ciphertexts(&build.transactions);
                                            if let Err(err) = store.insert(
                                                DaRootKind::Ciphertexts,
                                                block_number as u64,
                                                block_hash_bytes,
                                                build.encoding,
                                            ) {
                                                tracing::warn!(
                                                    block_number,
                                                    da_root = %hex::encode(da_root),
                                                    error = %err,
                                                    "Failed to persist DA encoding for announced block"
                                                );
                                            } else {
                                                tracing::info!(
                                                    block_number,
                                                    da_root = %hex::encode(da_root),
                                                    da_chunks,
                                                    "DA encoding stored for announced block"
                                                );
                                            }
                                            ciphertexts
                                        } else {
                                            transfer_ciphertexts_from_extrinsics(&extrinsics_for_ciphertexts)
                                        };
                                        ciphertexts.extend(coinbase_ciphertexts_from_extrinsics(
                                            &extrinsics_for_ciphertexts,
                                        ));
                                        let ciphertext_count = ciphertexts.len();
                                        if let Err(err) = store.append_ciphertexts(
                                            block_number as u64,
                                            block_hash_bytes,
                                            &ciphertexts,
                                        ) {
                                            tracing::warn!(
                                                block_number,
                                                error = %err,
                                                "Failed to persist ciphertexts for announced block"
                                            );
                                        } else if ciphertext_count > 0 {
                                            tracing::info!(
                                                block_number,
                                                ciphertext_count,
                                                "Ciphertexts stored for announced block"
                                            );
                                        }
                                        if let Some(proof) = commitment_block_proof.take() {
                                            let proof_size = proof.proof_bytes.len();
                                            let proof_hash = proof.proof_hash;
                                            commitment_block_proof_store_for_import
                                                .lock()
                                                .insert(block_hash, proof);
                                            tracing::info!(
                                                peer = %hex::encode(&peer_id),
                                                block_number,
                                                block_hash = %hex::encode(block_hash.as_bytes()),
                                                proof_size,
                                                proof_hash = %hex::encode(proof_hash),
                                                "Commitment block proof stored for imported block"
                                            );
                                        }
                                        tracing::info!(
                                            peer = %hex::encode(&peer_id),
                                            block_number,
                                            block_hash = %hex::encode(block_hash.as_bytes()),
                                            total_imported = blocks_imported,
                                            "Block imported from network via PowBlockImport"
                                        );
                                    }
                                    Ok(sc_consensus::ImportResult::AlreadyInChain) => {
                                        let mut store = da_chunk_store_for_import.lock();
                                        let mut ciphertexts = if let Some(build) = da_build.take() {
                                            let da_root = build.encoding.root();
                                            let da_chunks = build.encoding.chunks().len();
                                            let ciphertexts = flatten_ciphertexts(&build.transactions);
                                            if let Err(err) = store.insert(
                                                DaRootKind::Ciphertexts,
                                                block_number as u64,
                                                block_hash_bytes,
                                                build.encoding,
                                            ) {
                                                tracing::warn!(
                                                    block_number,
                                                    da_root = %hex::encode(da_root),
                                                    error = %err,
                                                    "Failed to persist DA encoding for known announced block"
                                                );
                                            } else {
                                                tracing::info!(
                                                    block_number,
                                                    da_root = %hex::encode(da_root),
                                                    da_chunks,
                                                    "DA encoding stored for known announced block"
                                                );
                                            }
                                            ciphertexts
                                        } else {
                                            transfer_ciphertexts_from_extrinsics(&extrinsics_for_ciphertexts)
                                        };
                                        ciphertexts.extend(coinbase_ciphertexts_from_extrinsics(
                                            &extrinsics_for_ciphertexts,
                                        ));
                                        let ciphertext_count = ciphertexts.len();
                                        if let Err(err) = store.append_ciphertexts(
                                            block_number as u64,
                                            block_hash_bytes,
                                            &ciphertexts,
                                        ) {
                                            tracing::warn!(
                                                block_number,
                                                error = %err,
                                                "Failed to persist ciphertexts for known announced block"
                                            );
                                        } else if ciphertext_count > 0 {
                                            tracing::info!(
                                                block_number,
                                                ciphertext_count,
                                                "Ciphertexts stored for known announced block"
                                            );
                                        }
                                        if let Some(proof) = commitment_block_proof.take() {
                                            let proof_size = proof.proof_bytes.len();
                                            let proof_hash = proof.proof_hash;
                                            commitment_block_proof_store_for_import
                                                .lock()
                                                .insert(block_hash, proof);
                                            tracing::info!(
                                                peer = %hex::encode(&peer_id),
                                                block_number,
                                                block_hash = %hex::encode(block_hash.as_bytes()),
                                                proof_size,
                                                proof_hash = %hex::encode(proof_hash),
                                                "Commitment block proof stored for known block"
                                            );
                                        }
                                        tracing::trace!(
                                            block_number,
                                            "Block already in chain"
                                        );
                                    }
                                    Ok(sc_consensus::ImportResult::KnownBad) => {
                                        blocks_failed += 1;
                                        tracing::warn!(
                                            peer = %hex::encode(&peer_id),
                                            block_number,
                                            "Block is known bad - PoW invalid"
                                        );
                                    }
                                    Ok(sc_consensus::ImportResult::UnknownParent) => {
                                        // Parent not found - need to sync more blocks first
                                        tracing::debug!(
                                            block_number,
                                            parent = %hex::encode(parent_hash.as_bytes()),
                                            "Unknown parent - need to sync earlier blocks"
                                        );
                                    }
                                    Ok(sc_consensus::ImportResult::MissingState) => {
                                        blocks_failed += 1;
                                        tracing::warn!(
                                            block_number,
                                            "Missing state for parent"
                                        );
                                    }
                                    Err(e) => {
                                        blocks_failed += 1;
                                        tracing::warn!(
                                            peer = %hex::encode(&peer_id),
                                            block_number,
                                            error = ?e,
                                            "Block import failed"
                                        );
                                    }
                                }
                            }
                        }
                    },
                );

                tracing::info!("Block import handler wired to PowBlockImport for network sync");
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Failed to start PqNetworkBackend - continuing without PQ networking"
                );
            }
        }
    }

    // ==========================================================================
    // Wire client to ProductionChainStateProvider
    // ==========================================================================

    let mining_config = MiningConfig::from_env();
    if mining_config.enabled {
        let worker_config = MiningWorkerConfig::from_env();
        let pow_handle_for_worker = pow_handle.clone();

        // Create production chain state provider
        let production_config = ProductionConfig::from_env();
        let chain_state = Arc::new(ProductionChainStateProvider::new(production_config.clone()));

        // =======================================================================
        // Wire best_block_fn to client
        // =======================================================================
        let client_for_best_block = client.clone();
        chain_state.set_best_block_fn(move || {
            let info = client_for_best_block.chain_info();
            // Convert sp_core::H256 to our H256 (they're the same type)
            (info.best_hash, info.best_number)
        });

        tracing::info!("best_block_fn wired to client.chain_info()");

        // =======================================================================
        // Wire difficulty_fn to runtime API
        // =======================================================================
        // Note: ConsensusApi::difficulty_bits() must be called at the best block
        let client_for_difficulty = client.clone();
        chain_state.set_difficulty_fn(move || {
            let best_hash = client_for_difficulty.chain_info().best_hash;
            let api = client_for_difficulty.runtime_api();

            // Try to query difficulty from runtime's ConsensusApi
            match api.difficulty_bits(best_hash) {
                Ok(difficulty_bits) => difficulty_bits,
                Err(e) => {
                    tracing::warn!(
                        error = ?e,
                        "Failed to query difficulty_bits from runtime, using fallback"
                    );
                    DEFAULT_DIFFICULTY_BITS
                }
            }
        });

        tracing::info!("difficulty_fn wired to runtime ConsensusApi::difficulty_bits()");

        // =======================================================================
        // Build async proven-batch coordinator
        // =======================================================================
        let max_block_txs = production_config.max_block_transactions;
        let coordinator_candidate_overscan_factor =
            env_usize("HEGEMON_BATCH_CANDIDATE_OVERSCAN_FACTOR")
                .unwrap_or(4)
                .max(1);
        let requested_commitment_block_fast = std::env::var("HEGEMON_COMMITMENT_BLOCK_PROOFS_FAST")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let commitment_block_fast = if cfg!(feature = "fast-proofs") {
            requested_commitment_block_fast
        } else {
            if requested_commitment_block_fast {
                tracing::warn!(
                    "HEGEMON_COMMITMENT_BLOCK_PROOFS_FAST set but node not built with --features fast-proofs; ignoring"
                );
            }
            false
        };

        let default_batch_target_txs = env_usize("HEGEMON_BATCH_DEFAULT_TARGET_TXS")
            .unwrap_or(32)
            .max(1);
        let coordinator_default_target_txs = max_block_txs.min(default_batch_target_txs).max(1);
        if std::env::var("HEGEMON_BATCH_TARGET_TXS").is_err()
            && max_block_txs > coordinator_default_target_txs
        {
            tracing::info!(
                max_block_transactions = max_block_txs,
                default_batch_target_txs = coordinator_default_target_txs,
                "No HEGEMON_BATCH_TARGET_TXS override set; capping default proven-batch target to keep preparation latency bounded"
            );
        }
        let coordinator_cfg = ProverCoordinatorConfig::from_env(coordinator_default_target_txs);
        let best_for_coord = {
            let client = client.clone();
            Arc::new(move || {
                let info = client.chain_info();
                (info.best_hash, info.best_number)
            })
        };
        let pending_for_coord = {
            let pool = Arc::clone(&pool_bridge);
            let tx_pool = transaction_pool.clone();
            let client = client.clone();
            let overscan_factor = coordinator_candidate_overscan_factor;
            Arc::new(move |target_txs: usize| {
                use sc_transaction_pool_api::{
                    InPoolTransaction, TransactionPool as ScTransactionPool,
                };

                let fetch_limit = target_txs
                    .saturating_mul(overscan_factor)
                    .max(target_txs)
                    .max(1);
                let mut txs = pool.ready_for_block(fetch_limit);

                // Mining must include locally submitted RPC transactions too; they live in the
                // substrate transaction pool and may not round-trip through the bridge network.
                let mut seen = std::collections::HashSet::with_capacity(txs.len());
                for tx in &txs {
                    seen.insert(sp_core::hashing::blake2_256(tx));
                }

                for tx in tx_pool.ready() {
                    let bytes = InPoolTransaction::data(&*tx).encode();
                    let digest = sp_core::hashing::blake2_256(&bytes);
                    if seen.insert(digest) {
                        txs.push(bytes);
                        if txs.len() >= fetch_limit {
                            break;
                        }
                    }
                }

                if txs.len() < fetch_limit {
                    // Proofless sidecar transfers can sit in the pool's "future" queue until a
                    // matching proven batch is available. The coordinator must consider those
                    // candidates, otherwise it can never prepare the proven batch needed to move
                    // them into ready inclusion.
                    for tx in tx_pool.futures() {
                        let bytes = InPoolTransaction::data(&tx).encode();
                        let digest = sp_core::hashing::blake2_256(&bytes);
                        if seen.insert(digest) {
                            txs.push(bytes);
                            if txs.len() >= fetch_limit {
                                break;
                            }
                        }
                    }
                }
                let parent_hash = client.chain_info().best_hash;
                let parent_keys = match parent_shielded_transfer_keys(client.as_ref(), parent_hash)
                {
                    Ok(parent_keys) => parent_keys,
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            parent_hash = ?parent_hash,
                            candidate_count = txs.len(),
                            "Failed to load parent shielded transfer keys for prover coordinator"
                        );
                        std::collections::HashSet::new()
                    }
                };
                let mut candidates = match sanitize_coordinator_candidate_extrinsics_for_parent(
                    &txs,
                    &parent_keys,
                ) {
                    Ok((filtered, filter_stats, dropped_parent_duplicates)) => {
                        if filter_stats.dropped_total() > 0 || dropped_parent_duplicates > 0 {
                            tracing::info!(
                                target_txs,
                                fetch_limit,
                                total_candidates = filter_stats.total,
                                kept_candidates = filtered.len(),
                                dropped_decode_errors = filter_stats.dropped_decode_errors,
                                dropped_binding_conflicts = filter_stats.dropped_binding_conflicts,
                                dropped_nullifier_conflicts =
                                    filter_stats.dropped_nullifier_conflicts,
                                dropped_parent_duplicates,
                                parent_shielded_transfer_count = parent_keys.len(),
                                "Sanitized shielded transfers for prover candidate set"
                            );
                        }
                        filtered
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            parent_hash = ?parent_hash,
                            candidate_count = txs.len(),
                            "Falling back to unsanitized tx candidate set for prover coordinator"
                        );
                        txs
                    }
                };
                candidates.truncate(target_txs);
                candidates
            })
        };
        let build_for_coord = {
            let client = client.clone();
            let pending_ciphertexts = Arc::clone(&pending_ciphertext_store);
            let pending_proofs = Arc::clone(&pending_proof_store);
            Arc::new(
                move |parent_hash: H256, block_number: u64, candidate_txs: Vec<Vec<u8>>| {
                    let parent_keys = parent_shielded_transfer_keys(client.as_ref(), parent_hash)?;
                    let (filtered, filter_stats, dropped_parent_duplicates) =
                        sanitize_coordinator_candidate_extrinsics_for_parent(
                            &candidate_txs,
                            &parent_keys,
                        )?;
                    if filter_stats.dropped_total() > 0 || dropped_parent_duplicates > 0 {
                        tracing::warn!(
                            block_number,
                            total_candidates = filter_stats.total,
                            kept_candidates = filtered.len(),
                            dropped_decode_errors = filter_stats.dropped_decode_errors,
                            dropped_binding_conflicts = filter_stats.dropped_binding_conflicts,
                            dropped_nullifier_conflicts = filter_stats.dropped_nullifier_conflicts,
                            dropped_parent_duplicates,
                            parent_shielded_transfer_count = parent_keys.len(),
                            "Sanitized shielded transfers before proven-batch preparation"
                        );
                    }
                    // Clone pending sidecar stores up front so we never hold these locks while
                    // generating commitment/aggregation proofs (which can take seconds).
                    let pending_ciphertexts_snapshot = { pending_ciphertexts.lock().clone() };
                    let pending_proofs_snapshot = { pending_proofs.lock().clone() };
                    prepare_block_proof_bundle(
                        client.as_ref(),
                        parent_hash,
                        block_number,
                        filtered,
                        da_params,
                        &pending_ciphertexts_snapshot,
                        &pending_proofs_snapshot,
                        commitment_block_fast,
                        coordinator_cfg.workers.max(1),
                    )
                },
            )
        };
        let prover_coordinator = ProverCoordinator::new(
            coordinator_cfg,
            best_for_coord,
            pending_for_coord,
            build_for_coord,
        );
        prover_coordinator.start();
        prover_coordinator_for_rpc = Some(Arc::clone(&prover_coordinator));
        *prover_coordinator_shared.write() = Some(Arc::clone(&prover_coordinator));
        if let Some(handle) = pq_network_handle.clone() {
            let coordinator_for_broadcast = Arc::clone(&prover_coordinator);
            task_manager.spawn_handle().spawn(
                "artifact-announcement-broadcast",
                Some("network"),
                async move {
                    use crate::substrate::network_bridge::{
                        ArtifactProtocolMessage, ARTIFACTS_PROTOCOL,
                    };
                    use std::collections::HashSet;

                    let mut announced = HashSet::<[u8; 32]>::new();
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                    loop {
                        tick.tick().await;
                        let announcements = coordinator_for_broadcast.list_artifact_announcements();
                        for announcement in announcements {
                            if !announced.insert(announcement.artifact_hash) {
                                continue;
                            }
                            let msg = ArtifactProtocolMessage::Announcement {
                                artifact_hash: announcement.artifact_hash,
                                tx_statements_commitment: announcement.tx_statements_commitment,
                                tx_count: announcement.tx_count,
                                proof_mode: match announcement.proof_mode {
                                    consensus::ProvenBatchMode::InlineTx => {
                                        pallet_shielded_pool::types::BlockProofMode::InlineTx
                                    }
                                    consensus::ProvenBatchMode::ReceiptRoot => {
                                        pallet_shielded_pool::types::BlockProofMode::ReceiptRoot
                                    }
                                },
                                proof_kind: match announcement.proof_kind {
                                    consensus::ProofArtifactKind::InlineTx => {
                                        pallet_shielded_pool::types::ProofArtifactKind::InlineTx
                                    }
                                    consensus::ProofArtifactKind::TxLeaf => {
                                        pallet_shielded_pool::types::ProofArtifactKind::TxLeaf
                                    }
                                    consensus::ProofArtifactKind::ReceiptRoot => {
                                        pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot
                                    }
                                    consensus::ProofArtifactKind::Custom(bytes) => {
                                        pallet_shielded_pool::types::ProofArtifactKind::Custom(
                                            bytes,
                                        )
                                    }
                                },
                                verifier_profile: announcement.verifier_profile,
                            };
                            let _ = handle
                                .broadcast_to_all(ARTIFACTS_PROTOCOL, msg.encode())
                                .await;
                        }
                    }
                },
            );
        }

        // =======================================================================
        // Wire pending_txs_fn to coordinator-selected transaction set
        // =======================================================================
        let coordinator_for_pending = Arc::clone(&prover_coordinator);
        chain_state.set_pending_txs_fn(move || {
            coordinator_for_pending.authoring_transactions(max_block_txs)
        });

        let hold_mining_while_proving = load_hold_mining_while_proving();
        let selected_artifact = prepared_artifact_selector_from_env();
        let prepared_bundle_required_while_proving = matches!(
            selected_artifact.proof_kind,
            pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot
        );
        if prepared_bundle_required_while_proving && hold_mining_while_proving {
            let client_for_mining_pause = client.clone();
            let coordinator_for_mining_pause = Arc::clone(&prover_coordinator);
            let min_ready_batch_txs = load_min_ready_proven_batch_txs();
            let mining_pause_active = Arc::new(ParkingMutex::new(false));
            let mining_pause_active_for_callback = Arc::clone(&mining_pause_active);
            chain_state.set_mining_pause_fn(move || {
                let chain_info = client_for_mining_pause.chain_info();
                let parent_hash = chain_info.best_hash;
                let block_number = chain_info.best_number.saturating_add(1);
                let candidate_txs =
                    coordinator_for_mining_pause.pending_transactions(max_block_txs);
                let reason = match mining_pause_reason_for_pending_shielded_batch(
                    coordinator_for_mining_pause.as_ref(),
                    parent_hash,
                    &candidate_txs,
                    min_ready_batch_txs,
                    selected_artifact,
                ) {
                    Ok(reason) => reason,
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            "Failed to evaluate mining hold state for pending proven batch"
                        );
                        None
                    }
                };
                let ready_trace = if reason.is_none() {
                    match ready_bundle_trace_for_candidate(
                        coordinator_for_mining_pause.as_ref(),
                        parent_hash,
                        block_number,
                        &candidate_txs,
                        min_ready_batch_txs,
                        selected_artifact,
                    ) {
                        Ok(trace) => trace,
                        Err(error) => {
                            tracing::warn!(
                                error = %error,
                                "Failed to derive ready bundle trace for mining handoff"
                            );
                            None
                        }
                    }
                } else {
                    None
                };
                let mut pause_active = mining_pause_active_for_callback.lock();
                match (&reason, ready_trace.as_ref(), *pause_active) {
                    (Some(_), _, false) => {
                        *pause_active = true;
                    }
                    (None, Some(trace), true) => {
                        tracing::info!(
                            target: "prover::last_mile",
                            trace_ts_ms = unix_time_ms(),
                            bundle_id = %trace.bundle_id,
                            artifact_hash = %hex::encode(trace.artifact_hash),
                            parent_hash = ?trace.parent_hash,
                            block_number = trace.block_number,
                            tx_count = trace.tx_count,
                            tx_statements_commitment =
                                %hex::encode(trace.tx_statements_commitment),
                            "mining_unpaused"
                        );
                        *pause_active = false;
                    }
                    (None, _, true) => {
                        *pause_active = false;
                    }
                    _ => {}
                }
                reason
            });
            tracing::info!(
                min_ready_proven_batch_txs = min_ready_batch_txs,
                proof_kind = ?selected_artifact.proof_kind,
                verifier_profile = %hex::encode(selected_artifact.verifier_profile),
                "Mining will pause while shielded batches wait for a ready prepared bundle"
            );
        } else if prepared_bundle_required_while_proving {
            tracing::warn!(
                proof_kind = ?selected_artifact.proof_kind,
                verifier_profile = %hex::encode(selected_artifact.verifier_profile),
                "Mining hold while proving is disabled; parent-bound prepared bundles may churn on stale parents"
            );
        }

        // Wire post-import callback to clear mined transactions
        let pool_for_import = Arc::clone(&pool_bridge);
        let coordinator_for_import = Arc::clone(&prover_coordinator);
        chain_state.set_on_import_success_fn(move |included_txs: &[Vec<u8>]| {
            pool_for_import.clear_included(included_txs);
            coordinator_for_import.clear_on_import_success(included_txs);
        });

        tracing::info!(
            max_block_transactions = max_block_txs,
            prover_candidate_overscan_factor = coordinator_candidate_overscan_factor,
            prover_workers = coordinator_cfg.workers,
            prover_batch_target_txs = coordinator_cfg.target_txs,
            prover_batch_queue_capacity = coordinator_cfg.queue_capacity,
            prover_liveness_lane = coordinator_cfg.liveness_lane,
            prover_adaptive_liveness_timeout_ms =
                coordinator_cfg.adaptive_liveness_timeout.as_millis() as u64,
            prover_batch_job_timeout_ms = coordinator_cfg.job_timeout.as_millis() as u64,
            "Transaction pool wired to chain state provider"
        );

        // =======================================================================
        // Wire BlockBuilder API for real state execution
        // =======================================================================
        wire_block_builder_api(
            &chain_state,
            client.clone(),
            Arc::clone(&pending_ciphertext_store),
            Arc::clone(&pending_proof_store),
            Arc::clone(&prover_coordinator),
            da_params,
            commitment_block_fast,
        );

        tracing::info!("BlockBuilder API wired for real state execution");

        if !chain_state.has_state_execution() && !production_config.allow_mock_execution {
            return Err(ServiceError::Other(
                "state execution is not configured; refuse to start without real execution".into(),
            ));
        }

        // =======================================================================
        // Wire PowBlockImport for real block import
        // =======================================================================
        wire_pow_block_import(
            &chain_state,
            pow_block_import,
            client.clone(),
            Arc::clone(&da_chunk_store),
            Arc::clone(&pending_ciphertext_store),
            Arc::clone(&pending_proof_store),
            Arc::clone(&commitment_block_proof_store),
            da_params,
        );

        tracing::info!("PowBlockImport wired for real block import");

        // Log full configuration
        tracing::info!(
            using_real_client = true,
            difficulty_bits = chain_state.difficulty_bits(),
            best_number = chain_state.best_number(),
            best_hash = %hex::encode(chain_state.best_hash().as_bytes()),
            "FULL PRODUCTION PIPELINE CONFIGURED"
        );

        // Check if we have a PQ network handle for live broadcasting
        if let Some(pq_handle) = pq_network_handle.clone() {
            let sync_status_for_mining = Arc::clone(&sync_status);
            let mined_blocks_for_worker = Arc::clone(&mined_block_store);
            tracing::info!(
                threads = worker_config.threads,
                test_mode = worker_config.test_mode,
                "Spawning PRODUCTION mining worker with real client + PQ broadcasting"
            );

            task_manager.spawn_handle().spawn(
                "hegemon-mining-worker",
                Some("mining"),
                async move {
                    let worker = create_production_mining_worker(
                        pow_handle_for_worker,
                        chain_state,
                        pq_handle,
                        worker_config,
                        mined_blocks_for_worker,
                    )
                    .with_sync_status(sync_status_for_mining);

                    worker.run().await;
                },
            );
        } else {
            let sync_status_for_mining = Arc::clone(&sync_status);
            let mined_blocks_for_worker = Arc::clone(&mined_block_store);
            // Production mode without network broadcasting
            tracing::info!(
                threads = worker_config.threads,
                test_mode = worker_config.test_mode,
                "Spawning production mining worker (no PQ network)"
            );

            task_manager.spawn_handle().spawn(
                "hegemon-mining-worker",
                Some("mining"),
                async move {
                    let worker = create_production_mining_worker_mock_broadcast(
                        pow_handle_for_worker,
                        chain_state,
                        worker_config,
                        mined_blocks_for_worker,
                    )
                    .with_sync_status(sync_status_for_mining);

                    worker.run().await;
                },
            );
        }
    } else {
        tracing::info!("Mining worker not spawned (mining disabled)");
    }

    // =========================================================================
    // Spawn RPC Server with Production Service
    // =========================================================================
    //
    // The RPC server provides HTTP and WebSocket access to:
    // - Chain state queries (chain_*, state_*)
    // - Transaction submission (author_*)
    // - Hegemon-specific RPCs (hegemon_*, wallet RPCs)
    // - Shielded pool RPCs (STARK proofs, encrypted notes)

    // Debug: dump what Substrate actually parsed
    eprintln!("=== RPC CONFIG DEBUG ===");
    eprintln!("config.rpc.addr: {:?}", config.rpc.addr);
    eprintln!("config.rpc.port: {}", config.rpc.port);
    eprintln!("========================");

    // Get RPC listen address from CLI config. The --rpc-port flag populates config.rpc.addr,
    // falling back to config.rpc.port (default 9944) if no explicit endpoints specified.
    let rpc_listen_addr = config
        .rpc
        .addr
        .as_ref()
        .and_then(|endpoints| endpoints.first())
        .map(|e| e.listen_addr)
        .unwrap_or_else(|| std::net::SocketAddr::from(([127, 0, 0, 1], config.rpc.port)));
    let rpc_port = rpc_listen_addr.port();
    let rpc_deny_unsafe = sc_rpc_server::utils::deny_unsafe(&rpc_listen_addr, &config.rpc.methods);

    // Create production RPC service with client access
    let miner_recipient = miner_recipient_from_env();
    let mined_history = Arc::new(parking_lot::Mutex::new(Default::default()));
    let rpc_service = Arc::new(ProductionRpcService::new(
        client.clone(),
        transaction_pool.clone(),
        Arc::clone(&peer_count),
        Arc::clone(&sync_status),
        Arc::clone(&peer_details),
        Arc::clone(&peer_graph_reports),
        rpc_peer_id,
        Arc::clone(&da_chunk_store),
        Arc::clone(&pending_ciphertext_store),
        mined_block_store,
        mined_history,
        miner_recipient,
        pq_network_handle.clone(),
    ));
    // Create RPC module with all extensions
    let rpc_module = {
        use jsonrpsee::RpcModule;
        use sc_rpc::chain::ChainApiServer;
        use sc_rpc::state::{ChildStateApiServer, StateApiServer};
        use sc_rpc::system::{System, SystemApiServer};
        use sc_rpc::SubscriptionTaskExecutor;
        use sc_utils::mpsc::tracing_unbounded;

        let mut module = RpcModule::new(());

        // Register rpc_methods endpoint (required by Polkadot.js Apps)
        // This returns the list of available RPC methods
        module
            .register_method("rpc_methods", |_, _, _| {
                // Return a static list of methods we support
                // Polkadot.js Apps uses this to discover available methods
                let result: Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned> = {
                    let legacy_pool_rpc_enabled = std::env::var("HEGEMON_ENABLE_LEGACY_POOL_RPC")
                        .map(|raw| raw == "1" || raw.eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    let mut methods = vec![
                        "chain_getBlock",
                        "chain_getBlockHash",
                        "chain_getHeader",
                        "chain_getFinalizedHead",
                        "chain_subscribeNewHead",
                        "chain_subscribeFinalizedHeads",
                        "chain_unsubscribeNewHead",
                        "chain_unsubscribeFinalizedHeads",
                        "state_call",
                        "state_getKeys",
                        "state_getKeysPaged",
                        "state_getMetadata",
                        "state_getPairs",
                        "state_getReadProof",
                        "state_getRuntimeVersion",
                        "state_getStorage",
                        "state_getStorageAt",
                        "state_getStorageHash",
                        "state_getStorageHashAt",
                        "state_getStorageSize",
                        "state_getStorageSizeAt",
                        "state_queryStorage",
                        "state_queryStorageAt",
                        "state_subscribeRuntimeVersion",
                        "state_subscribeStorage",
                        "state_unsubscribeRuntimeVersion",
                        "state_unsubscribeStorage",
                        "system_chain",
                        "system_chainType",
                        "system_health",
                        "system_localListenAddresses",
                        "system_localPeerId",
                        "system_name",
                        "system_nodeRoles",
                        "system_peers",
                        "system_properties",
                        "system_version",
                        "block_getCommitmentProof",
                        "da_getChunk",
                        "da_getParams",
                        "prover_listArtifactAnnouncements",
                        "prover_getCandidateArtifact",
                        "rpc_methods",
                        "hegemon_peerList",
                        "hegemon_peerGraph",
                    ];
                    if legacy_pool_rpc_enabled {
                        methods.push("hegemon_poolWork");
                        methods.push("hegemon_submitPoolShare");
                        methods.push("hegemon_poolStatus");
                    }
                    Ok(serde_json::json!({ "methods": methods }))
                };
                result
            })
            .expect("rpc_methods registration should not fail");

        // Create subscription task executor for RPC subscriptions
        let executor: SubscriptionTaskExecutor = Arc::new(task_manager.spawn_handle());

        // =====================================================================
        // Standard Substrate RPCs (chain_*, state_*, system_*)
        // =====================================================================

        // Add Chain RPC (chain_getBlock, chain_getHeader, chain_getBlockHash, etc.)
        let chain_rpc =
            sc_rpc::chain::new_full::<runtime::Block, _>(client.clone(), executor.clone());
        if let Err(e) = module.merge(chain_rpc.into_rpc()) {
            tracing::warn!(error = %e, "Failed to merge Chain RPC");
        } else {
            tracing::info!("Chain RPC wired (chain_getBlock, chain_getHeader, etc.)");
        }

        // Add State RPC (state_getStorage, state_getRuntimeVersion, state_call, etc.)
        // This requires the backend for storage queries
        let (state_rpc, child_state_rpc) = sc_rpc::state::new_full::<FullBackend, _, _>(
            client.clone(),
            executor.clone(),
            None, // execute_block - optional tracing executor
        );
        if let Err(e) = module.merge(state_rpc.into_rpc()) {
            tracing::warn!(error = %e, "Failed to merge State RPC");
        } else {
            tracing::info!("State RPC wired (state_getStorage, state_getRuntimeVersion, etc.)");
        }
        if let Err(e) = module.merge(child_state_rpc.into_rpc()) {
            tracing::warn!(error = %e, "Failed to merge Child State RPC");
        }

        // Add System RPC (system_name, system_version, system_chain, system_health, etc.)
        // SystemInfo provides static node metadata
        let system_info = sc_rpc::system::SystemInfo {
            impl_name: "Hegemon".into(),
            impl_version: env!("CARGO_PKG_VERSION").into(),
            chain_name: chain_name.clone(),
            properties: chain_properties.clone(),
            chain_type: chain_type.clone(),
        };
        // Create a channel for network-dependent system RPC methods
        // Network requests will be handled by a background task
        let (system_rpc_tx, mut system_rpc_rx) = tracing_unbounded::<
            sc_rpc::system::Request<runtime::Block>,
        >("system-rpc-requests", 10_000);
        let system_rpc = System::new(system_info, system_rpc_tx);
        if let Err(e) = module.merge(system_rpc.into_rpc()) {
            tracing::warn!(error = %e, "Failed to merge System RPC");
        } else {
            tracing::info!("System RPC wired (system_name, system_version, system_chain, etc.)");
        }

        // Spawn a task to handle system RPC network requests
        // Captures the real peer ID and PQ network handle for peer count
        let peer_id_for_rpc = rpc_peer_id;
        let p2p_port = pq_service_config.listen_addr.port();
        let pq_handle_for_rpc = pq_network_handle.clone();
        let sync_status_for_rpc = Arc::clone(&sync_status);
        task_manager
            .spawn_handle()
            .spawn("system-rpc-handler", Some("rpc"), async move {
                use sc_rpc::system::{Health, Request};

                // Convert the 32-byte PQ peer ID into a libp2p-compatible identity multihash.
                fn pq_peer_id_to_libp2p(id: &[u8; 32]) -> String {
                    let mut multihash = vec![0x00, 0x20];
                    multihash.extend_from_slice(id);
                    bs58::encode(&multihash).into_string()
                }

                while let Some(request) = system_rpc_rx.next().await {
                    match request {
                        Request::Health(sender) => {
                            // Get real peer count from PQ network handle
                            let peer_count = if let Some(ref handle) = pq_handle_for_rpc {
                                handle.peer_count().await
                            } else {
                                0
                            };
                            let health = Health {
                                peers: peer_count,
                                is_syncing: sync_status_for_rpc.load(Ordering::Relaxed),
                                should_have_peers: true,
                            };
                            let _ = sender.send(health);
                        }
                        Request::LocalPeerId(sender) => {
                            // Return the real PQ peer ID as libp2p-compatible base58 multihash
                            let peer_id_str = if let Some(id) = peer_id_for_rpc {
                                pq_peer_id_to_libp2p(&id)
                            } else {
                                "12D3KooWNotConfigured".to_string()
                            };
                            let _ = sender.send(peer_id_str);
                        }
                        Request::LocalListenAddresses(sender) => {
                            let _ = sender.send(vec![format!("/ip4/127.0.0.1/tcp/{}", p2p_port)]);
                        }
                        Request::Peers(sender) => {
                            // NOTE: system_peers returns empty because PQ network doesn't track
                            // peer metadata (name, roles, etc.) like libp2p does.
                            // Use system_health.peers for the actual peer count instead.
                            let _ = sender.send(vec![]);
                        }
                        Request::NetworkState(sender) => {
                            // DEPRECATED: libp2p network state - not used in PQ network
                            let _ = sender.send(
                                serde_json::json!({"note": "PQ network - use system_health"}),
                            );
                        }
                        Request::NetworkAddReservedPeer(_, sender) => {
                            let _ = sender.send(Ok(()));
                        }
                        Request::NetworkRemoveReservedPeer(_, sender) => {
                            let _ = sender.send(Ok(()));
                        }
                        Request::NetworkReservedPeers(sender) => {
                            let _ = sender.send(vec![]);
                        }
                        Request::NodeRoles(sender) => {
                            use sc_rpc::system::NodeRole;
                            let _ = sender.send(vec![NodeRole::Authority]);
                        }
                        Request::SyncState(sender) => {
                            use sc_rpc::system::SyncState;
                            let _ = sender.send(SyncState {
                                starting_block: 0u32.into(),
                                current_block: 0u32.into(),
                                highest_block: 0u32.into(),
                            });
                        }
                    }
                }
            });

        // =====================================================================
        // Hegemon Custom RPCs
        // =====================================================================

        let config_snapshot = NodeConfigSnapshot {
            node_name: config.network.node_name.clone(),
            chain_spec_id: config.chain_spec.id().to_string(),
            chain_spec_name: config.chain_spec.name().to_string(),
            chain_type: format!("{:?}", config.chain_spec.chain_type()).to_lowercase(),
            base_path: config.base_path.path().display().to_string(),
            p2p_listen_addr: pq_service_config.listen_addr.to_string(),
            rpc_listen_addr: rpc_listen_addr.to_string(),
            rpc_methods: format!("{:?}", config.rpc.methods).to_lowercase(),
            rpc_external: !rpc_listen_addr.ip().is_loopback(),
            bootstrap_nodes: pq_service_config
                .bootstrap_nodes
                .iter()
                .map(|node| node.seed.clone())
                .collect(),
            pq_verbose: pq_service_config.verbose_logging,
            max_peers: pq_service_config.max_peers as u32,
        };

        // Add Hegemon RPC (mining, consensus, telemetry)
        let hegemon_rpc = HegemonRpc::new(
            rpc_service.clone(),
            pow_handle.clone(),
            config_snapshot,
            rpc_deny_unsafe,
        );
        if let Err(e) = module.merge(hegemon_rpc.into_rpc()) {
            tracing::warn!(error = %e, "Failed to merge Hegemon RPC");
        } else {
            tracing::info!(
                "Hegemon RPC wired (hegemon_miningStatus, hegemon_consensusStatus, etc.)"
            );
        }

        // Add Wallet RPC (notes, commitments, proofs)
        let wallet_rpc = WalletRpc::new(rpc_service.clone());
        if let Err(e) = module.merge(wallet_rpc.into_rpc()) {
            tracing::warn!(error = %e, "Failed to merge Wallet RPC");
        } else {
            tracing::info!("Wallet RPC wired (wallet_notes, wallet_commitments, etc.)");
        }

        // Add Shielded Pool RPC (STARK proofs, encrypted notes)
        let shielded_rpc = ShieldedRpc::new(rpc_service.clone());
        if let Err(e) = module.merge(shielded_rpc.into_rpc()) {
            tracing::warn!(error = %e, "Failed to merge Shielded RPC");
        } else {
            tracing::info!("Shielded RPC wired (shielded_submitTransfer, etc.)");
        }

        // Add Block RPC (commitment block proofs)
        let block_rpc = BlockRpc::new(Arc::clone(&commitment_block_proof_store));
        if let Err(e) = module.merge(block_rpc.into_rpc()) {
            tracing::warn!(error = %e, "Failed to merge Block RPC");
        } else {
            tracing::info!("Block RPC wired (block_getCommitmentProof)");
        }

        // Add DA RPC (chunk retrieval + params)
        let da_rpc = DaRpc::new(
            Arc::clone(&da_chunk_store),
            Arc::clone(&pending_ciphertext_store),
            Arc::clone(&pending_proof_store),
            da_params,
        );
        if let Err(e) = module.merge(da_rpc.into_rpc()) {
            tracing::warn!(error = %e, "Failed to merge DA RPC");
        } else {
            tracing::info!("DA RPC wired (da_getChunk, da_getParams)");
        }

        if let Some(coordinator) = prover_coordinator_for_rpc.as_ref() {
            let prover_rpc = ProverRpc::new(Arc::clone(coordinator));
            if let Err(e) = module.merge(prover_rpc.into_rpc()) {
                tracing::warn!(error = %e, "Failed to merge Prover RPC");
            } else {
                tracing::info!(
                    "Prover RPC wired (prover_listArtifactAnnouncements, prover_getCandidateArtifact)"
                );
            }
        } else {
            tracing::info!("Prover RPC disabled (mining coordinator not active)");
        }

        module
    };

    // Spawn RPC server task
    fn build_rpc_cors_layer(cors: &Option<Vec<String>>) -> CorsLayer {
        match cors {
            None => CorsLayer::permissive(),
            Some(origins) if origins.is_empty() => {
                CorsLayer::new().allow_origin(AllowOrigin::predicate(|_, _| false))
            }
            Some(origins) => {
                let allowed = origins.clone();
                let allow_origin = AllowOrigin::predicate(move |origin, _| {
                    let origin_str = match origin.to_str() {
                        Ok(value) => value,
                        Err(_) => return false,
                    };
                    allowed
                        .iter()
                        .any(|pattern| origin_matches(origin_str, pattern))
                });
                CorsLayer::new()
                    .allow_origin(allow_origin)
                    .allow_methods([Method::POST, Method::OPTIONS])
                    .allow_headers([header::CONTENT_TYPE, header::ACCEPT])
            }
        }
    }

    fn origin_matches(origin: &str, pattern: &str) -> bool {
        if pattern == "null" {
            return origin == "null";
        }
        let wildcard_port = pattern.ends_with(":*");
        let parsed_pattern = if wildcard_port {
            let trimmed = pattern.trim_end_matches(":*");
            format!("{trimmed}:0")
        } else {
            pattern.to_string()
        };
        let pattern_url = match Url::parse(&parsed_pattern) {
            Ok(url) => url,
            Err(_) => return false,
        };
        let origin_url = match Url::parse(origin) {
            Ok(url) => url,
            Err(_) => return false,
        };
        if pattern_url.scheme() != origin_url.scheme() {
            return false;
        }
        if pattern_url.host_str() != origin_url.host_str() {
            return false;
        }
        if wildcard_port {
            return true;
        }
        pattern_url.port_or_known_default() == origin_url.port_or_known_default()
    }

    let rpc_cors = config.rpc.cors.clone();
    let rpc_handle = task_manager.spawn_handle();
    rpc_handle.spawn("hegemon-rpc-server", Some("rpc"), async move {
        let addr = rpc_listen_addr;

        // Create HTTP middleware
        // Note: DenyUnsafe is injected via extension middleware below
        let http_middleware = tower::ServiceBuilder::new().layer(build_rpc_cors_layer(&rpc_cors));

        let deny_unsafe = rpc_deny_unsafe;

        // Create a custom RPC middleware that injects DenyUnsafe
        use jsonrpsee::server::middleware::rpc::RpcServiceBuilder;
        let rpc_middleware = RpcServiceBuilder::new().layer_fn(move |svc| DenyUnsafeMiddleware {
            inner: svc,
            deny_unsafe,
        });

        let server = match ServerBuilder::default()
            .set_http_middleware(http_middleware)
            .set_rpc_middleware(rpc_middleware)
            .build(addr)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    addr = %addr,
                    "Failed to build RPC server"
                );
                return;
            }
        };

        tracing::info!(
            addr = %addr,
            "RPC server started"
        );

        let handle = server.start(rpc_module);

        // Keep the server running
        handle.stopped().await;

        tracing::info!("RPC server stopped");
    });

    tracing::info!(
        rpc_addr = %rpc_listen_addr,
        rpc_port = rpc_port,
        "RPC server spawned with production service"
    );

    let has_pq_broadcast = pq_network_handle.is_some();
    tracing::info!("═══════════════════════════════════════════════════════════════");
    tracing::info!("STARTING NODE");
    tracing::info!("═══════════════════════════════════════════════════════════════");
    tracing::info!("  RPC server spawned at {}", rpc_listen_addr);
    tracing::info!("  PQ network broadcasting: {}", has_pq_broadcast);
    tracing::info!("  RPC server: http://{}", rpc_listen_addr);
    tracing::info!("  Set HEGEMON_MINE=1 to enable mining");
    tracing::info!("═══════════════════════════════════════════════════════════════");

    Ok(task_manager)
}

/// Configuration for the PoW mining service
#[derive(Clone, Debug)]
pub struct MiningConfig {
    /// Whether mining is enabled
    pub enabled: bool,
    /// Number of mining threads
    pub threads: usize,
    /// Target block time in milliseconds
    pub target_block_time_ms: u64,
}

impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threads: 1,
            target_block_time_ms: 60_000, // 60 seconds (1 minute)
        }
    }
}

impl MiningConfig {
    /// Create mining config from environment variables
    pub fn from_env() -> Self {
        let enabled = std::env::var("HEGEMON_MINE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        let threads = std::env::var("HEGEMON_MINE_THREADS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let target_block_time_ms = std::env::var("HEGEMON_BLOCK_TIME_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60_000); // 60 seconds (1 minute)

        Self {
            enabled,
            threads,
            target_block_time_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_database::Database as _;
    use sp_database::MemDb;
    use std::sync::MutexGuard as StdMutexGuard;
    use superneo_hegemon::build_native_tx_leaf_artifact_bytes;
    use transaction_circuit::constants::{CIRCUIT_MERKLE_DEPTH, NATIVE_ASSET_ID};
    use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, HashFelt};
    use transaction_circuit::keys::generate_keys;
    use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
    use transaction_circuit::proof::prove;
    use transaction_circuit::witness::TransactionWitness;

    fn dummy_receipt(profile: consensus::VerifierProfileDigest) -> consensus::TxValidityReceipt {
        consensus::TxValidityReceipt {
            statement_hash: [1u8; 48],
            proof_digest: [2u8; 48],
            public_inputs_digest: [3u8; 48],
            verifier_profile: profile,
        }
    }

    fn dummy_native_tx_validity_artifact() -> consensus::TxValidityArtifact {
        consensus::TxValidityArtifact {
            receipt: dummy_receipt(consensus::experimental_native_tx_leaf_verifier_profile()),
            proof: Some(consensus::ProofEnvelope {
                kind: consensus::ProofArtifactKind::TxLeaf,
                verifier_profile: consensus::experimental_native_tx_leaf_verifier_profile(),
                artifact_bytes: vec![42u8; 16],
            }),
        }
    }

    fn dummy_native_tx_validity_artifact_variant(tag: u8) -> consensus::TxValidityArtifact {
        let mut artifact = dummy_native_tx_validity_artifact();
        artifact.receipt.proof_digest = [tag; 48];
        if let Some(proof) = artifact.proof.as_mut() {
            proof.artifact_bytes = vec![tag; 16];
        }
        artifact
    }

    fn test_native_sample_witness(seed: u8) -> TransactionWitness {
        let sk_spend = [seed.wrapping_add(42); 32];
        let pk_auth = transaction_circuit::hashing_pq::spend_auth_key_bytes(&sk_spend);
        let input_note_native = NoteData {
            value: 8,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [seed.wrapping_add(2); 32],
            pk_auth,
            rho: [seed.wrapping_add(3); 32],
            r: [seed.wrapping_add(4); 32],
        };
        let input_note_asset = NoteData {
            value: 5,
            asset_id: u64::from(seed) + 100,
            pk_recipient: [seed.wrapping_add(5); 32],
            pk_auth,
            rho: [seed.wrapping_add(6); 32],
            r: [seed.wrapping_add(7); 32],
        };
        let leaf0 = input_note_native.commitment();
        let leaf1 = input_note_asset.commitment();
        let (merkle_path0, merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

        let output_native = OutputNoteWitness {
            note: NoteData {
                value: 3,
                asset_id: NATIVE_ASSET_ID,
                pk_recipient: [seed.wrapping_add(11); 32],
                pk_auth: [seed.wrapping_add(12); 32],
                rho: [seed.wrapping_add(13); 32],
                r: [seed.wrapping_add(14); 32],
            },
        };
        let output_asset = OutputNoteWitness {
            note: NoteData {
                value: 5,
                asset_id: u64::from(seed) + 100,
                pk_recipient: [seed.wrapping_add(21); 32],
                pk_auth: [seed.wrapping_add(22); 32],
                rho: [seed.wrapping_add(23); 32],
                r: [seed.wrapping_add(24); 32],
            },
        };

        TransactionWitness {
            inputs: vec![
                InputNoteWitness {
                    note: input_note_native,
                    position: 0,
                    rho_seed: [seed.wrapping_add(9); 32],
                    merkle_path: merkle_path0,
                },
                InputNoteWitness {
                    note: input_note_asset,
                    position: 1,
                    rho_seed: [seed.wrapping_add(10); 32],
                    merkle_path: merkle_path1,
                },
            ],
            outputs: vec![output_native, output_asset],
            ciphertext_hashes: vec![[0u8; 48]; 2],
            sk_spend,
            merkle_root: felts_to_bytes48(&merkle_root),
            fee: 5,
            value_balance: 0,
            stablecoin: transaction_circuit::StablecoinPolicyBinding::default(),
            version: TransactionWitness::default_version_binding(),
        }
    }

    fn build_two_leaf_merkle_tree(
        leaf0: HashFelt,
        leaf1: HashFelt,
    ) -> (MerklePath, MerklePath, HashFelt) {
        let mut siblings0 = vec![leaf1];
        let mut siblings1 = vec![leaf0];
        let mut current = merkle_node(leaf0, leaf1);
        for _ in 1..CIRCUIT_MERKLE_DEPTH {
            let zero = [Felt::new(0); 6];
            siblings0.push(zero);
            siblings1.push(zero);
            current = merkle_node(current, zero);
        }
        (
            MerklePath {
                siblings: siblings0,
            },
            MerklePath {
                siblings: siblings1,
            },
            current,
        )
    }

    fn test_inline_transfer_extrinsic_with_proof(
        proof_bytes: Vec<u8>,
        nullifiers: Vec<[u8; 48]>,
        commitments: Vec<[u8; 48]>,
        balance_slot_asset_ids: [u64; 4],
    ) -> runtime::UncheckedExtrinsic {
        kernel_shielded_extrinsic(
            pallet_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
            nullifiers,
            pallet_shielded_pool::family::ShieldedTransferInlineArgs {
                proof: proof_bytes,
                commitments: commitments.clone(),
                ciphertexts: vec![
                    pallet_shielded_pool::types::EncryptedNote::default();
                    commitments.len()
                ],
                anchor: [7u8; 48],
                balance_slot_asset_ids,
                binding_hash: [9u8; 64],
                stablecoin: None,
                fee: 5,
            }
            .encode(),
        )
    }

    fn test_sidecar_transfer_extrinsic_with_proof(
        proof_bytes: Vec<u8>,
        nullifiers: Vec<[u8; 48]>,
        commitments: Vec<[u8; 48]>,
        ciphertext_hashes: Vec<[u8; 48]>,
        balance_slot_asset_ids: [u64; 4],
    ) -> runtime::UncheckedExtrinsic {
        kernel_shielded_extrinsic(
            ACTION_SHIELDED_TRANSFER_SIDECAR,
            nullifiers,
            ShieldedTransferSidecarArgs {
                proof: proof_bytes,
                commitments,
                ciphertext_hashes: ciphertext_hashes.clone(),
                ciphertext_sizes: vec![0u32; ciphertext_hashes.len()],
                anchor: [7u8; 48],
                balance_slot_asset_ids,
                binding_hash: [9u8; 64],
                stablecoin: None,
                fee: 5,
            }
            .encode(),
        )
    }

    fn dummy_receipt_root_payload() -> pallet_shielded_pool::types::ReceiptRootProofPayload {
        pallet_shielded_pool::types::ReceiptRootProofPayload {
            root_proof: pallet_shielded_pool::types::StarkProof::from_bytes(vec![7u8; 8]),
            metadata: pallet_shielded_pool::types::ReceiptRootMetadata {
                relation_id: [9u8; 32],
                shape_digest: [8u8; 32],
                leaf_count: 1,
                fold_count: 0,
            },
            receipts: vec![pallet_shielded_pool::types::TxValidityReceipt {
                statement_hash: [1u8; 48],
                proof_digest: [2u8; 48],
                public_inputs_digest: [3u8; 48],
                verifier_profile: consensus::experimental_native_tx_leaf_verifier_profile(),
            }],
        }
    }

    fn dummy_block_proof_bundle() -> pallet_shielded_pool::types::BlockProofBundle {
        pallet_shielded_pool::types::BlockProofBundle {
            version: pallet_shielded_pool::types::BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count: 1,
            tx_statements_commitment: [6u8; 48],
            da_root: [0u8; 48],
            da_chunk_count: 1,
            commitment_proof: pallet_shielded_pool::types::StarkProof::from_bytes(vec![5u8; 8]),
            proof_mode: pallet_shielded_pool::types::BlockProofMode::InlineTx,
            proof_kind: pallet_shielded_pool::types::ProofArtifactKind::InlineTx,
            verifier_profile: crate::substrate::artifact_market::legacy_pallet_artifact_identity(
                pallet_shielded_pool::types::BlockProofMode::InlineTx,
            )
            .1,
            receipt_root: None,
        }
    }

    struct BlockProofModeGuard {
        previous_mode: Option<String>,
        previous_require_native: Option<String>,
        _guard: StdMutexGuard<'static, ()>,
    }

    impl Drop for BlockProofModeGuard {
        fn drop(&mut self) {
            match self.previous_mode.take() {
                Some(value) => unsafe {
                    std::env::set_var("HEGEMON_BLOCK_PROOF_MODE", value);
                },
                None => unsafe {
                    std::env::remove_var("HEGEMON_BLOCK_PROOF_MODE");
                },
            }
            match self.previous_require_native.take() {
                Some(value) => unsafe {
                    std::env::set_var("HEGEMON_REQUIRE_NATIVE", value);
                },
                None => unsafe {
                    std::env::remove_var("HEGEMON_REQUIRE_NATIVE");
                },
            }
        }
    }

    fn set_block_proof_mode(mode: &str) -> BlockProofModeGuard {
        let guard = crate::substrate::test_env_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let previous_mode = std::env::var("HEGEMON_BLOCK_PROOF_MODE").ok();
        let previous_require_native = std::env::var("HEGEMON_REQUIRE_NATIVE").ok();
        unsafe {
            std::env::set_var("HEGEMON_BLOCK_PROOF_MODE", mode);
        }
        BlockProofModeGuard {
            previous_mode,
            previous_require_native,
            _guard: guard,
        }
    }

    fn set_block_proof_mode_with_require_native(
        mode: &str,
        require_native: &str,
    ) -> BlockProofModeGuard {
        let guard = crate::substrate::test_env_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let previous_mode = std::env::var("HEGEMON_BLOCK_PROOF_MODE").ok();
        let previous_require_native = std::env::var("HEGEMON_REQUIRE_NATIVE").ok();
        unsafe {
            std::env::set_var("HEGEMON_BLOCK_PROOF_MODE", mode);
            std::env::set_var("HEGEMON_REQUIRE_NATIVE", require_native);
        }
        BlockProofModeGuard {
            previous_mode,
            previous_require_native,
            _guard: guard,
        }
    }

    #[test]
    fn receipt_root_mode_is_selected_from_env() {
        let _guard = set_block_proof_mode("receipt_root");
        let selector = prepared_artifact_selector_from_env();
        assert_eq!(
            selector.proof_kind,
            pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot
        );
        assert_eq!(
            selector.verifier_profile,
            consensus::experimental_native_receipt_root_verifier_profile()
        );
    }

    #[test]
    fn legacy_block_proof_mode_is_forced_to_receipt_root() {
        let _guard = set_block_proof_mode_with_require_native("inline_tx", "1");
        let selector = prepared_artifact_selector_from_env();
        ensure_native_only_receipt_root_selector(selector)
            .expect("legacy env modes should be forced onto canonical receipt_root");
        assert_eq!(
            selector.proof_kind,
            pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot
        );
    }

    #[test]
    fn require_native_receipt_root_accepts_canonical_mode() {
        let _guard = set_block_proof_mode_with_require_native("receipt_root", "1");
        ensure_native_only_receipt_root_selector(prepared_artifact_selector_from_env())
            .expect("canonical native receipt_root mode must be accepted");
    }

    #[test]
    fn receipt_root_lane_rejects_local_only_sidecar_proof_material() {
        let err = receipt_root_lane_requires_embedded_proof_bytes(
            pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot,
            2,
        )
        .expect_err("receipt_root must reject proofless sidecar-only material");
        assert!(err.contains("receipt_root requires embedded proof bytes"));
        assert!(err.contains("2 transfers"));
    }

    #[test]
    fn receipt_root_lane_accepts_embedded_proof_bytes() {
        receipt_root_lane_requires_embedded_proof_bytes(
            pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot,
            0,
        )
        .expect("embedded proof bytes should satisfy receipt_root");
    }

    #[test]
    fn receipt_root_prefers_native_lane_when_artifacts_are_native() {
        let artifacts = vec![dummy_native_tx_validity_artifact()];
        let outcome =
            prepare_native_receipt_root_artifacts_with_builder(Some(artifacts.as_slice()), |_| {
                Ok(dummy_receipt_root_payload())
            })
            .expect("native receipt-root preparation succeeds");
        let report = outcome
            .native_selection_report
            .expect("native selection report should be present");
        assert!(report.used_native_lane);
        assert_eq!(report.fallback_reason, None);
        assert!(matches!(
            outcome.artifacts,
            PreparedAggregationArtifacts::ReceiptRoot(_)
        ));
    }

    #[test]
    fn require_native_receipt_root_rejects_inline_fallback_outcome() {
        let _guard = set_block_proof_mode_with_require_native("receipt_root", "1");
        let err = ensure_native_only_receipt_root_outcome(&PreparedAggregationOutcome::native(
            PreparedAggregationArtifacts::InlineTx,
            NativeArtifactSelectionReport::fallback(
                NativeArtifactFallbackReason::ArtifactsUnavailable,
                "synthetic miss",
            ),
        ))
        .expect_err("native-only mode must reject inline fallback outcomes");
        assert!(err.contains("forbids InlineTx fallback"));
        assert!(err.contains("synthetic miss"));
    }

    #[test]
    fn require_native_receipt_root_accepts_native_receipt_root_outcome() {
        let _guard = set_block_proof_mode_with_require_native("receipt_root", "1");
        ensure_native_only_receipt_root_outcome(&PreparedAggregationOutcome::native(
            PreparedAggregationArtifacts::ReceiptRoot(dummy_receipt_root_payload()),
            NativeArtifactSelectionReport::native_lane_selected(),
        ))
        .expect("native-only mode must accept canonical native receipt_root outcomes");
    }

    #[test]
    fn receipt_root_inline_fallback_outcomes_are_not_cacheable() {
        let outcome = PreparedAggregationOutcome::native(
            PreparedAggregationArtifacts::InlineTx,
            NativeArtifactSelectionReport::fallback(
                NativeArtifactFallbackReason::ArtifactsUnavailable,
                "synthetic miss",
            ),
        );
        assert!(!should_store_prove_ahead_aggregation_outcome(
            PreparedArtifactSelector::receipt_root(),
            &outcome,
        ));
    }

    #[test]
    fn receipt_root_native_outcomes_are_cacheable() {
        let outcome = PreparedAggregationOutcome::native(
            PreparedAggregationArtifacts::ReceiptRoot(dummy_receipt_root_payload()),
            NativeArtifactSelectionReport::native_lane_selected(),
        );
        assert!(should_store_prove_ahead_aggregation_outcome(
            PreparedArtifactSelector::receipt_root(),
            &outcome,
        ));
    }

    #[test]
    fn receipt_root_cache_key_binds_tx_artifact_identity() {
        let selector = PreparedArtifactSelector::receipt_root();
        let first_artifacts = vec![dummy_native_tx_validity_artifact_variant(10)];
        let second_artifacts = vec![dummy_native_tx_validity_artifact_variant(11)];
        let first_key = make_prove_ahead_aggregation_cache_key(
            selector,
            [7u8; 48],
            1,
            Some(first_artifacts.as_slice()),
        );
        let second_key = make_prove_ahead_aggregation_cache_key(
            selector,
            [7u8; 48],
            1,
            Some(second_artifacts.as_slice()),
        );
        assert_ne!(first_key, second_key);

        let outcome = Arc::new(PreparedAggregationOutcome::native(
            PreparedAggregationArtifacts::ReceiptRoot(dummy_receipt_root_payload()),
            NativeArtifactSelectionReport::native_lane_selected(),
        ));
        let mut cache = ProveAheadAggregationCache::new(1);
        cache.insert(first_key, outcome);
        assert!(cache.get(first_key).is_some());
        assert!(cache.get(second_key).is_none());
    }

    #[test]
    fn receipt_root_work_plan_splits_into_mini_roots() {
        let artifacts = (0..9u8)
            .map(|tag| dummy_native_tx_validity_artifact_variant(tag.wrapping_add(1)))
            .collect::<Vec<_>>();
        let plan = build_receipt_root_work_plan(&artifacts).expect("work plan");
        assert_eq!(plan.leaf_count, 9);
        assert_eq!(plan.mini_root_size, native_receipt_root_mini_root_size());
        assert_eq!(plan.mini_root_count, 2);
        assert_eq!(plan.chunk_internal_fold_nodes, 7);
        assert_eq!(plan.upper_tree_fold_nodes, 1);
        assert_eq!(plan.upper_tree_level_widths, vec![2, 1]);
        assert_eq!(plan.mini_roots.len(), 2);
        assert_eq!(plan.mini_roots[0].leaf_start, 0);
        assert_eq!(plan.mini_roots[0].leaf_count, 8);
        assert_eq!(plan.mini_roots[1].leaf_start, 8);
        assert_eq!(plan.mini_roots[1].leaf_count, 1);
        assert_ne!(plan.mini_roots[0].cache_key, plan.mini_roots[1].cache_key);
    }

    #[test]
    fn receipt_root_work_plan_rejects_empty_artifact_set() {
        let err = build_receipt_root_work_plan(&[])
            .expect_err("empty candidate set must not produce a receipt-root work plan");
        assert!(err.contains("no receipt-root proof material"));
    }

    #[test]
    fn receipt_root_errors_when_native_artifacts_are_missing() {
        let err = prepare_native_receipt_root_artifacts(None)
            .expect_err("missing native artifacts must fail closed");
        assert!(
            err.contains("native_artifacts_unavailable"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn receipt_root_errors_on_verifier_profile_mismatch() {
        let artifacts = vec![consensus::TxValidityArtifact {
            receipt: dummy_receipt(consensus::experimental_tx_leaf_verifier_profile()),
            proof: Some(consensus::ProofEnvelope {
                kind: consensus::ProofArtifactKind::TxLeaf,
                verifier_profile: consensus::experimental_tx_leaf_verifier_profile(),
                artifact_bytes: vec![9u8; 8],
            }),
        }];
        let err =
            prepare_native_receipt_root_artifacts_with_builder(Some(artifacts.as_slice()), |_| {
                unreachable!("profile mismatch should fail before builder invocation")
            })
            .expect_err("profile mismatch must fail closed");
        assert!(
            err.contains("native_verifier_profile_mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn receipt_root_errors_on_native_artifact_validation_failure() {
        let artifacts = vec![dummy_native_tx_validity_artifact()];
        let err =
            prepare_native_receipt_root_artifacts_with_builder(Some(artifacts.as_slice()), |_| {
                Err("synthetic native artifact validation failure".to_string())
            })
            .expect_err("invalid native artifact must fail closed");
        assert!(
            err.contains("synthetic native artifact validation failure"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn require_native_receipt_root_rejects_inline_payload() {
        let _guard = set_block_proof_mode_with_require_native("receipt_root", "1");
        let payload = dummy_block_proof_bundle();
        let err = ensure_native_only_receipt_root_payload(&payload)
            .expect_err("native-only mode must reject inline payloads on import");
        assert!(err.contains("canonical native receipt_root is required"));
    }

    #[test]
    fn require_native_receipt_root_accepts_canonical_payload() {
        let _guard = set_block_proof_mode_with_require_native("receipt_root", "1");
        let mut payload = dummy_block_proof_bundle();
        payload.proof_mode = pallet_shielded_pool::types::BlockProofMode::ReceiptRoot;
        payload.proof_kind = pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot;
        payload.verifier_profile = consensus::experimental_native_receipt_root_verifier_profile();
        payload.receipt_root = Some(dummy_receipt_root_payload());
        ensure_native_only_receipt_root_payload(&payload)
            .expect("native-only mode must accept canonical native receipt_root payloads");
    }

    fn test_sidecar_transfer_extrinsic(binding_byte: u8, nullifier: [u8; 48]) -> Vec<u8> {
        kernel_shielded_extrinsic(
            ACTION_SHIELDED_TRANSFER_SIDECAR,
            vec![nullifier],
            ShieldedTransferSidecarArgs {
                proof: Vec::new(),
                commitments: vec![[binding_byte; 48]],
                ciphertext_hashes: vec![[binding_byte; 48]],
                ciphertext_sizes: vec![32u32],
                anchor: [7u8; 48],
                balance_slot_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
                binding_hash: [binding_byte; 64],
                stablecoin: None,
                fee: 0,
            }
            .encode(),
        )
        .encode()
    }

    #[test]
    fn extract_inline_transfer_accepts_native_tx_leaf_payload() {
        let witness = test_native_sample_witness(31);
        let built = build_native_tx_leaf_artifact_bytes(&witness).expect("native tx leaf bytes");
        let public_inputs = witness.public_inputs().expect("public inputs");
        let balance_slot_asset_ids: [u64; 4] = witness
            .balance_slots()
            .expect("balance slots")
            .iter()
            .map(|slot| slot.asset_id)
            .collect::<Vec<_>>()
            .try_into()
            .expect("four balance slots");
        let extrinsic = test_inline_transfer_extrinsic_with_proof(
            built.artifact_bytes.clone(),
            public_inputs.nullifiers[..witness.inputs.len()].to_vec(),
            public_inputs.commitments[..witness.outputs.len()].to_vec(),
            balance_slot_asset_ids,
        );

        let (_transactions, proofs, artifacts, _bindings) =
            extract_shielded_transfers_for_parallel_verification(&[extrinsic], None, None, true)
                .expect("native tx-leaf inline payload should extract");

        assert!(
            proofs.is_empty(),
            "native tx leaf payloads should not materialize inline STARK proofs"
        );
        let artifact = artifacts
            .into_iter()
            .next()
            .flatten()
            .expect("native tx-leaf artifact should be present");
        let proof = artifact.proof.expect("proof envelope");
        assert_eq!(proof.kind, consensus::ProofArtifactKind::TxLeaf);
        assert_eq!(
            proof.verifier_profile,
            consensus::experimental_native_tx_leaf_verifier_profile()
        );
    }

    #[test]
    fn candidate_statement_bindings_prefer_native_tx_artifacts() {
        let witness = test_native_sample_witness(41);
        let built = build_native_tx_leaf_artifact_bytes(&witness).expect("native tx leaf bytes");
        let public_inputs = witness.public_inputs().expect("public inputs");
        let balance_slot_asset_ids: [u64; 4] = witness
            .balance_slots()
            .expect("balance slots")
            .iter()
            .map(|slot| slot.asset_id)
            .collect::<Vec<_>>()
            .try_into()
            .expect("four balance slots");
        let decoded = test_sidecar_transfer_extrinsic_with_proof(
            built.artifact_bytes.clone(),
            public_inputs.nullifiers[..witness.inputs.len()].to_vec(),
            public_inputs.commitments[..witness.outputs.len()].to_vec(),
            witness.ciphertext_hashes.clone(),
            balance_slot_asset_ids,
        );

        let preferred = statement_bindings_for_candidate_extrinsics(
            std::slice::from_ref(&decoded),
            None,
            None,
            false,
        )
        .expect("preferred statement bindings");
        let legacy = statement_bindings_from_extrinsics(std::slice::from_ref(&decoded))
            .expect("legacy statement bindings");
        let (transactions, _proofs, artifacts, _bindings) =
            extract_shielded_transfers_for_parallel_verification(&[decoded], None, None, false)
                .expect("extract native tx leaf");
        let tx_artifacts = artifacts
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .expect("native tx artifacts");
        let expected =
            consensus::tx_statement_bindings_from_tx_artifacts(&transactions, &tx_artifacts)
                .expect("artifact-derived bindings");

        assert_eq!(preferred, expected);
        assert_ne!(
            preferred[0].statement_hash,
            legacy[0].statement_hash,
            "native tx artifacts must override legacy materialized statement hashing on the product path"
        );
    }

    #[test]
    fn extract_inline_transfer_accepts_legacy_inline_tx_proof_payload() {
        let witness = test_native_sample_witness(17);
        let (proving_key, _) = generate_keys();
        let proof = prove(&witness, &proving_key).expect("legacy inline proof");
        let public_inputs = witness.public_inputs().expect("public inputs");
        let balance_slot_asset_ids: [u64; 4] = witness
            .balance_slots()
            .expect("balance slots")
            .iter()
            .map(|slot| slot.asset_id)
            .collect::<Vec<_>>()
            .try_into()
            .expect("four balance slots");
        let extrinsic = test_inline_transfer_extrinsic_with_proof(
            bincode::serialize(&proof).expect("serialize legacy proof"),
            public_inputs.nullifiers[..witness.inputs.len()].to_vec(),
            public_inputs.commitments[..witness.outputs.len()].to_vec(),
            balance_slot_asset_ids,
        );

        let (_transactions, proofs, artifacts, _bindings) =
            extract_shielded_transfers_for_parallel_verification(&[extrinsic], None, None, true)
                .expect("legacy inline payload should extract");

        assert_eq!(
            proofs.len(),
            1,
            "legacy inline payload should materialize one proof"
        );
        let extracted_proof = proofs.into_iter().next().expect("inline tx proof");
        assert_eq!(
            extracted_proof.public_inputs.nullifiers[..witness.inputs.len()],
            public_inputs.nullifiers[..witness.inputs.len()],
            "legacy inline extraction should preserve public nullifiers"
        );
        assert_eq!(
            extracted_proof.public_inputs.commitments[..witness.outputs.len()],
            public_inputs.commitments[..witness.outputs.len()],
            "legacy inline extraction should preserve public commitments"
        );
        let artifact = artifacts
            .into_iter()
            .next()
            .flatten()
            .expect("legacy inline artifact should be present");
        let envelope = artifact.proof.expect("legacy proof envelope");
        assert_eq!(envelope.kind, consensus::ProofArtifactKind::InlineTx);
    }

    #[test]
    fn filter_conflicting_shielded_transfers_drops_binding_conflicts_and_keeps_nullifier_overlaps()
    {
        let keep = test_sidecar_transfer_extrinsic(1, [9u8; 48]);
        let keep_nullifier_overlap = test_sidecar_transfer_extrinsic(2, [9u8; 48]);
        let drop_binding = test_sidecar_transfer_extrinsic(1, [8u8; 48]);
        let malformed = vec![1u8, 2, 3];

        let (filtered, stats) = filter_conflicting_shielded_transfers(&[
            keep.clone(),
            keep_nullifier_overlap.clone(),
            drop_binding,
            malformed,
        ]);

        assert_eq!(filtered, vec![keep, keep_nullifier_overlap]);
        assert_eq!(stats.total, 4);
        assert_eq!(stats.kept, 2);
        assert_eq!(stats.dropped_nullifier_conflicts, 0);
        assert_eq!(stats.dropped_binding_conflicts, 1);
        assert_eq!(stats.dropped_decode_errors, 1);
        assert_eq!(stats.dropped_total(), 2);
    }

    #[test]
    fn filter_conflicting_shielded_transfers_ignores_zero_nullifier_padding() {
        let zero = [0u8; 48];
        let first = test_sidecar_transfer_extrinsic(3, zero);
        let second = test_sidecar_transfer_extrinsic(4, zero);

        let (filtered, stats) =
            filter_conflicting_shielded_transfers(&[first.clone(), second.clone()]);

        assert_eq!(filtered, vec![first, second]);
        assert_eq!(stats.total, 2);
        assert_eq!(stats.kept, 2);
        assert_eq!(stats.dropped_total(), 0);
    }

    #[test]
    fn filter_parent_included_shielded_transfers_drops_duplicates() {
        let first = test_sidecar_transfer_extrinsic(7, [7u8; 48]);
        let second = test_sidecar_transfer_extrinsic(8, [8u8; 48]);

        let first_decoded =
            runtime::UncheckedExtrinsic::decode(&mut &first[..]).expect("decode first");
        let first_key =
            shielded_transfer_key_from_extrinsic(&first_decoded).expect("first shielded key");

        let mut parent_keys = std::collections::HashSet::new();
        parent_keys.insert(first_key);

        let (filtered, dropped) = filter_parent_included_shielded_transfers(
            &[first.clone(), second.clone()],
            &parent_keys,
        )
        .expect("filter succeeds");

        assert_eq!(dropped, 1);
        assert_eq!(filtered, vec![second]);
    }

    #[test]
    fn sanitize_coordinator_candidate_extrinsics_drops_parent_duplicates_before_truncation() {
        let first = test_sidecar_transfer_extrinsic(7, [7u8; 48]);
        let second = test_sidecar_transfer_extrinsic(8, [8u8; 48]);
        let first_decoded =
            runtime::UncheckedExtrinsic::decode(&mut &first[..]).expect("decode first");
        let first_key =
            shielded_transfer_key_from_extrinsic(&first_decoded).expect("first shielded key");
        let mut parent_keys = std::collections::HashSet::new();
        parent_keys.insert(first_key);

        let (sanitized, stats, dropped_parent_duplicates) =
            sanitize_coordinator_candidate_extrinsics_for_parent(
                &[first.clone(), second.clone()],
                &parent_keys,
            )
            .expect("sanitize succeeds");

        assert_eq!(
            sanitized,
            vec![second],
            "coordinator candidate sanitization must remove parent duplicates before singleton truncation"
        );
        assert_eq!(stats.dropped_total(), 0);
        assert_eq!(dropped_parent_duplicates, 1);
    }

    #[test]
    fn test_mining_config_default() {
        let config = MiningConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.threads, 1);
        assert_eq!(config.target_block_time_ms, 60_000); // 60 seconds
    }

    #[test]
    fn test_mining_config_from_env() {
        // This test depends on environment, so just verify it doesn't panic
        let _config = MiningConfig::from_env();
    }

    #[test]
    fn test_pq_service_config_default() {
        let config = PqServiceConfig::default();
        assert!(!config.verbose_logging);
        assert_eq!(config.max_peers, 50);
    }

    #[test]
    fn proof_da_blob_parses_with_padding() {
        let binding_hash_a = [1u8; 64];
        let binding_hash_b = [2u8; 64];
        let proof_a = vec![3u8; 10];
        let proof_b = vec![4u8; 5];

        let mut blob = Vec::new();
        blob.extend_from_slice(&2u32.to_le_bytes());

        blob.extend_from_slice(&binding_hash_a);
        blob.extend_from_slice(&(proof_a.len() as u32).to_le_bytes());
        blob.extend_from_slice(&proof_a);

        blob.extend_from_slice(&binding_hash_b);
        blob.extend_from_slice(&(proof_b.len() as u32).to_le_bytes());
        blob.extend_from_slice(&proof_b);

        let mut padded = blob.clone();
        padded.extend_from_slice(&[0u8; 32]);

        let (parsed, consumed) = parse_proof_da_blob(&padded).expect("parse");
        assert_eq!(consumed, blob.len());
        assert_eq!(parsed.get(&binding_hash_a).cloned(), Some(proof_a));
        assert_eq!(parsed.get(&binding_hash_b).cloned(), Some(proof_b));
    }

    #[test]
    fn proof_da_blob_rejects_duplicate_binding_hash() {
        let binding_hash = [9u8; 64];
        let proof = vec![1u8; 3];

        let mut blob = Vec::new();
        blob.extend_from_slice(&2u32.to_le_bytes());
        for _ in 0..2 {
            blob.extend_from_slice(&binding_hash);
            blob.extend_from_slice(&(proof.len() as u32).to_le_bytes());
            blob.extend_from_slice(&proof);
        }

        let err = parse_proof_da_blob(&blob).expect_err("should reject");
        assert!(err.contains("duplicate binding hash"));
    }

    #[test]
    fn proof_da_blob_len_from_manifest_matches_layout() {
        let a = LegacyProofDaManifestEntry {
            _binding_hash: [1u8; 64],
            proof_len: 10,
            proof_offset: 72,
        };
        let b = LegacyProofDaManifestEntry {
            _binding_hash: [2u8; 64],
            proof_len: 5,
            proof_offset: 150,
        };
        let len = proof_da_blob_len_from_manifest(&[a, b]).expect("len");
        assert_eq!(len, 155);
    }

    fn put_legacy_meta_value(db: &MemDb, key: &[u8], value: Vec<u8>) {
        let mut transaction = DbTransaction::<H256>::new();
        transaction.set_from_vec(LEGACY_META_COLUMN, key, value);
        db.commit(transaction).expect("legacy meta write succeeds");
    }

    fn put_legacy_lookup(db: &MemDb, key: &[u8], number: u64, hash: H256) {
        put_legacy_meta_value(
            db,
            key,
            legacy_lookup_key(number, hash).expect("lookup key encodes"),
        );
    }

    fn put_legacy_state_meta_value(db: &MemDb, key: &[u8], value: Vec<u8>) {
        let mut transaction = DbTransaction::<H256>::new();
        transaction.set_from_vec(LEGACY_DB_STATE_META_COLUMN, key, value);
        db.commit(transaction)
            .expect("legacy state meta write succeeds");
    }

    fn put_legacy_header(db: &MemDb, number: u64, hash: H256, parent_hash: H256) {
        let header = runtime::Header::new(
            number,
            H256::repeat_byte(0x55),
            H256::repeat_byte(0x66),
            parent_hash,
            Default::default(),
        );
        let mut transaction = DbTransaction::<H256>::new();
        transaction.set_from_vec(
            LEGACY_DB_HEADER_COLUMN,
            &legacy_lookup_key(number, hash).expect("lookup key encodes"),
            header.encode(),
        );
        db.commit(transaction)
            .expect("legacy header write succeeds");
    }

    fn get_legacy_meta_value(db: &MemDb, key: &[u8]) -> Option<Vec<u8>> {
        <MemDb as sp_database::Database<H256>>::get(db, LEGACY_META_COLUMN, key)
    }

    fn get_legacy_state_meta_value(db: &MemDb, key: &[u8]) -> Option<Vec<u8>> {
        <MemDb as sp_database::Database<H256>>::get(db, LEGACY_DB_STATE_META_COLUMN, key)
    }

    #[test]
    fn legacy_pow_finality_repair_demotes_non_genesis_finalized_head() {
        let db = MemDb::default();
        let genesis_hash = H256::repeat_byte(0x11);
        let poisoned_hash = H256::repeat_byte(0x22);

        put_legacy_meta_value(&db, LEGACY_META_TYPE_KEY, LEGACY_DB_TYPE_FULL.to_vec());
        put_legacy_meta_value(
            &db,
            LEGACY_META_GENESIS_HASH_KEY,
            genesis_hash.as_bytes().to_vec(),
        );
        put_legacy_lookup(&db, LEGACY_META_FINALIZED_BLOCK_KEY, 1199, poisoned_hash);
        put_legacy_lookup(&db, LEGACY_META_FINALIZED_STATE_KEY, 1199, poisoned_hash);

        let outcome =
            repair_legacy_pow_finality_metadata_in_db(&db).expect("legacy repair should succeed");

        assert_eq!(
            outcome,
            LegacyPowRepairOutcome {
                finalized_repair: Some((1199, poisoned_hash)),
                tip_state_rewind: None,
            }
        );
        assert_eq!(
            get_legacy_meta_value(&db, LEGACY_META_FINALIZED_BLOCK_KEY),
            Some(legacy_lookup_key(0, genesis_hash).expect("genesis lookup"))
        );
        assert_eq!(
            get_legacy_meta_value(&db, LEGACY_META_FINALIZED_STATE_KEY),
            Some(legacy_lookup_key(0, genesis_hash).expect("genesis lookup"))
        );
    }

    #[test]
    fn legacy_pow_finality_repair_is_noop_when_metadata_is_already_genesis() {
        let db = MemDb::default();
        let genesis_hash = H256::repeat_byte(0x33);
        let genesis_lookup = legacy_lookup_key(0, genesis_hash).expect("genesis lookup");

        put_legacy_meta_value(&db, LEGACY_META_TYPE_KEY, LEGACY_DB_TYPE_FULL.to_vec());
        put_legacy_meta_value(
            &db,
            LEGACY_META_GENESIS_HASH_KEY,
            genesis_hash.as_bytes().to_vec(),
        );
        put_legacy_meta_value(&db, LEGACY_META_FINALIZED_BLOCK_KEY, genesis_lookup.clone());
        put_legacy_meta_value(&db, LEGACY_META_FINALIZED_STATE_KEY, genesis_lookup);

        let outcome =
            repair_legacy_pow_finality_metadata_in_db(&db).expect("legacy repair should succeed");

        assert_eq!(outcome, LegacyPowRepairOutcome::default());
    }

    #[test]
    fn legacy_pow_finality_repair_rebuilds_missing_finalized_state_at_genesis() {
        let db = MemDb::default();
        let genesis_hash = H256::repeat_byte(0x44);

        put_legacy_meta_value(&db, LEGACY_META_TYPE_KEY, LEGACY_DB_TYPE_FULL.to_vec());
        put_legacy_meta_value(
            &db,
            LEGACY_META_GENESIS_HASH_KEY,
            genesis_hash.as_bytes().to_vec(),
        );
        put_legacy_lookup(&db, LEGACY_META_FINALIZED_BLOCK_KEY, 0, genesis_hash);

        let outcome =
            repair_legacy_pow_finality_metadata_in_db(&db).expect("legacy repair should succeed");

        assert_eq!(
            outcome,
            LegacyPowRepairOutcome {
                finalized_repair: Some((0, genesis_hash)),
                tip_state_rewind: None,
            }
        );
        assert_eq!(
            get_legacy_meta_value(&db, LEGACY_META_FINALIZED_STATE_KEY),
            Some(legacy_lookup_key(0, genesis_hash).expect("genesis lookup"))
        );
    }

    #[test]
    fn legacy_pow_finality_repair_rewinds_poisoned_state_canonical_tip() {
        let db = MemDb::default();
        let genesis_hash = H256::repeat_byte(0x10);
        let parent_hash = H256::repeat_byte(0x20);
        let best_hash = H256::repeat_byte(0x30);

        put_legacy_meta_value(&db, LEGACY_META_TYPE_KEY, LEGACY_DB_TYPE_FULL.to_vec());
        put_legacy_meta_value(
            &db,
            LEGACY_META_GENESIS_HASH_KEY,
            genesis_hash.as_bytes().to_vec(),
        );
        put_legacy_lookup(&db, LEGACY_META_FINALIZED_BLOCK_KEY, 0, genesis_hash);
        put_legacy_lookup(&db, LEGACY_META_FINALIZED_STATE_KEY, 0, genesis_hash);
        put_legacy_lookup(&db, LEGACY_META_BEST_BLOCK_KEY, 1199, best_hash);
        put_legacy_state_meta_value(
            &db,
            LEGACY_STATE_META_LAST_CANONICAL_KEY,
            encode_legacy_state_last_canonical(best_hash, 1199),
        );
        put_legacy_state_meta_value(&db, LEGACY_STATE_META_LAST_PRUNED_KEY, 900u64.encode());
        put_legacy_header(&db, 1199, best_hash, parent_hash);

        let outcome =
            repair_legacy_pow_finality_metadata_in_db(&db).expect("legacy repair should succeed");

        assert_eq!(
            outcome,
            LegacyPowRepairOutcome {
                finalized_repair: None,
                tip_state_rewind: Some(LegacyPowTipStateRewind {
                    previous_number: 1199,
                    previous_hash: best_hash,
                    rewound_to_number: 1198,
                    rewound_to_hash: parent_hash,
                }),
            }
        );
        assert_eq!(
            get_legacy_state_meta_value(&db, LEGACY_STATE_META_LAST_CANONICAL_KEY),
            Some(encode_legacy_state_last_canonical(parent_hash, 1198))
        );
        assert_eq!(
            get_legacy_state_meta_value(&db, LEGACY_STATE_META_LAST_PRUNED_KEY),
            Some(900u64.encode())
        );
    }

    #[test]
    fn mining_pause_reason_requires_ready_bundle_for_proofless_batch() {
        let parent_hash = H256::repeat_byte(0x41);
        let coordinator = ProverCoordinator::new(
            ProverCoordinatorConfig {
                workers: 0,
                target_txs: 1,
                queue_capacity: 1,
                max_inflight_per_level: 1,
                liveness_lane: true,
                adaptive_liveness_timeout: Duration::from_millis(0),
                incremental_upsizing: false,
                poll_interval: Duration::from_millis(50),
                job_timeout: Duration::from_secs(30),
            },
            Arc::new(move || (parent_hash, 7u64)),
            Arc::new(|_max_txs| Vec::new()),
            Arc::new(|_, _, _| Err("unused".to_string())),
        );

        let candidate_txs = vec![test_sidecar_transfer_extrinsic(9, [3u8; 48])];
        let reason = mining_pause_reason_for_pending_shielded_batch(
            coordinator.as_ref(),
            parent_hash,
            &candidate_txs,
            1,
            PreparedArtifactSelector::receipt_root(),
        )
        .expect("pause reason evaluation succeeds");
        assert!(
            reason.is_some(),
            "proofless batch without ready bundle should pause mining"
        );

        let decoded = runtime::UncheckedExtrinsic::decode(&mut &candidate_txs[0][..])
            .expect("candidate decodes");
        let statement_bindings =
            statement_bindings_from_extrinsics(&[decoded]).expect("statement bindings");
        let statement_hashes = statement_bindings
            .iter()
            .map(|binding| binding.statement_hash)
            .collect::<Vec<_>>();
        let tx_statements_commitment =
            CommitmentBlockProver::commitment_from_statement_hashes(&statement_hashes)
                .expect("commitment");
        coordinator.import_network_artifact(
            parent_hash,
            pallet_shielded_pool::types::CandidateArtifact {
                version: pallet_shielded_pool::types::BLOCK_PROOF_BUNDLE_SCHEMA,
                tx_count: 1,
                tx_statements_commitment,
                da_root: [0u8; 48],
                da_chunk_count: 0,
                commitment_proof: pallet_shielded_pool::types::StarkProof::from_bytes(Vec::new()),
                proof_mode: pallet_shielded_pool::types::BlockProofMode::ReceiptRoot,
                proof_kind: pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot,
                verifier_profile:
                    crate::substrate::artifact_market::legacy_pallet_artifact_identity(
                        pallet_shielded_pool::types::BlockProofMode::ReceiptRoot,
                    )
                    .1,
                receipt_root: Some(dummy_receipt_root_payload()),
            },
            candidate_txs.clone(),
        );

        let reason = mining_pause_reason_for_pending_shielded_batch(
            coordinator.as_ref(),
            parent_hash,
            &candidate_txs,
            1,
            PreparedArtifactSelector::receipt_root(),
        )
        .expect("pause reason evaluation succeeds");
        assert!(
            reason.is_none(),
            "mining should resume once the matching prepared bundle exists"
        );
    }

    #[test]
    fn mining_pause_reason_requires_ready_bundle_for_native_receipt_root_batch() {
        let parent_hash = H256::repeat_byte(0x44);
        let coordinator = ProverCoordinator::new(
            ProverCoordinatorConfig {
                workers: 0,
                target_txs: 1,
                queue_capacity: 1,
                max_inflight_per_level: 1,
                liveness_lane: true,
                adaptive_liveness_timeout: Duration::from_millis(0),
                incremental_upsizing: false,
                poll_interval: Duration::from_millis(50),
                job_timeout: Duration::from_secs(30),
            },
            Arc::new(move || (parent_hash, 7u64)),
            Arc::new(|_max_txs| Vec::new()),
            Arc::new(|_, _, _| Err("unused".to_string())),
        );

        let witness = test_native_sample_witness(55);
        let built = build_native_tx_leaf_artifact_bytes(&witness).expect("native tx leaf bytes");
        let public_inputs = witness.public_inputs().expect("public inputs");
        let balance_slot_asset_ids: [u64; 4] = witness
            .balance_slots()
            .expect("balance slots")
            .iter()
            .map(|slot| slot.asset_id)
            .collect::<Vec<_>>()
            .try_into()
            .expect("four balance slots");
        let candidate = test_sidecar_transfer_extrinsic_with_proof(
            built.artifact_bytes,
            public_inputs.nullifiers[..witness.inputs.len()].to_vec(),
            public_inputs.commitments[..witness.outputs.len()].to_vec(),
            witness.ciphertext_hashes.clone(),
            balance_slot_asset_ids,
        )
        .encode();
        let candidate_txs = vec![candidate];

        let reason = mining_pause_reason_for_pending_shielded_batch(
            coordinator.as_ref(),
            parent_hash,
            &candidate_txs,
            1,
            PreparedArtifactSelector::receipt_root(),
        )
        .expect("pause reason evaluation succeeds");
        assert!(
            reason.is_some(),
            "native receipt_root batches should pause mining until the prepared bundle is ready"
        );

        let decoded = runtime::UncheckedExtrinsic::decode(&mut &candidate_txs[0][..])
            .expect("candidate decodes");
        let statement_bindings =
            statement_bindings_for_candidate_extrinsics(&[decoded], None, None, false)
                .expect("statement bindings");
        let statement_hashes = statement_bindings
            .iter()
            .map(|binding| binding.statement_hash)
            .collect::<Vec<_>>();
        let tx_statements_commitment =
            CommitmentBlockProver::commitment_from_statement_hashes(&statement_hashes)
                .expect("commitment");
        coordinator.import_network_artifact(
            parent_hash,
            pallet_shielded_pool::types::CandidateArtifact {
                version: pallet_shielded_pool::types::BLOCK_PROOF_BUNDLE_SCHEMA,
                tx_count: 1,
                tx_statements_commitment,
                da_root: [0u8; 48],
                da_chunk_count: 0,
                commitment_proof: pallet_shielded_pool::types::StarkProof::from_bytes(Vec::new()),
                proof_mode: pallet_shielded_pool::types::BlockProofMode::ReceiptRoot,
                proof_kind: pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot,
                verifier_profile:
                    crate::substrate::artifact_market::legacy_pallet_artifact_identity(
                        pallet_shielded_pool::types::BlockProofMode::ReceiptRoot,
                    )
                    .1,
                receipt_root: Some(dummy_receipt_root_payload()),
            },
            candidate_txs.clone(),
        );

        let reason = mining_pause_reason_for_pending_shielded_batch(
            coordinator.as_ref(),
            parent_hash,
            &candidate_txs,
            1,
            PreparedArtifactSelector::receipt_root(),
        )
        .expect("pause reason evaluation succeeds");
        assert!(
            reason.is_none(),
            "mining should resume once the matching native receipt_root bundle exists"
        );
    }
}

// =============================================================================
// Full Block Import Pipeline
// =============================================================================
//
// This module provides the real block import pipeline integration.
//
// Due to Substrate's complex type system with deeply nested generics,
// we provide:
// 1. A simplified import callback that tracks state
// 2. Documentation for full sc-consensus-pow integration
// 3. Helper types for wiring callbacks
//
// Full PowBlockImport integration requires:
// - Creating the full client via sc_service::new_full_parts
// - Wrapping in sc_consensus_pow::PowBlockImport
// - Setting up import_queue for network imports
//
// These steps are documented below and will be fully wired when
// state execution is complete.

/// Configuration for the full block import
#[derive(Clone, Debug)]
pub struct FullBlockImportConfig {
    /// Whether to enable full block import (vs scaffold mode)
    pub enabled: bool,
    /// Whether to verify PoW seals
    pub verify_pow: bool,
    /// Whether to log verbose import details
    pub verbose: bool,
}

impl Default for FullBlockImportConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            verify_pow: true,
            verbose: false,
        }
    }
}

impl FullBlockImportConfig {
    /// Create from environment variables
    pub fn from_env() -> Self {
        let enabled = std::env::var("HEGEMON_FULL_IMPORT")
            .map(|v| v != "0" && v.to_lowercase() != "false")
            .unwrap_or(true);

        if let Ok(value) = std::env::var("HEGEMON_VERIFY_POW") {
            if value == "0" || value.eq_ignore_ascii_case("false") {
                tracing::warn!(
                    "HEGEMON_VERIFY_POW is ignored; full import tracker always verifies PoW"
                );
            }
        }

        let verbose = std::env::var("HEGEMON_IMPORT_VERBOSE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        Self {
            enabled,
            verify_pow: true,
            verbose,
        }
    }
}

/// Statistics for block imports
#[derive(Clone, Debug, Default)]
pub struct BlockImportStats {
    /// Total blocks imported
    pub blocks_imported: u64,
    /// Last imported block number
    pub last_block_number: u64,
    /// Last imported block hash
    pub last_block_hash: H256,
    /// Blocks rejected due to invalid seal
    pub invalid_seals: u64,
    /// Import errors
    pub import_errors: u64,
}

/// Block import tracker
///
/// This provides a simple way to track block imports and wire them
/// to the ProductionChainStateProvider. Full sc-consensus-pow integration
/// will replace this when Task 11.4 is complete.
pub struct BlockImportTracker {
    /// Import statistics
    stats: Arc<parking_lot::RwLock<BlockImportStats>>,
    /// Best block number
    best_number: Arc<std::sync::atomic::AtomicU64>,
    /// Best block hash
    best_hash: Arc<parking_lot::RwLock<H256>>,
    /// Configuration
    config: FullBlockImportConfig,
}

impl BlockImportTracker {
    /// Create a new block import tracker
    pub fn new(config: FullBlockImportConfig) -> Self {
        Self {
            stats: Arc::new(parking_lot::RwLock::new(BlockImportStats::default())),
            best_number: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            best_hash: Arc::new(parking_lot::RwLock::new(H256::zero())),
            config,
        }
    }

    /// Create with default config
    pub fn with_defaults() -> Self {
        Self::new(FullBlockImportConfig::default())
    }

    /// Create from environment
    pub fn from_env() -> Self {
        Self::new(FullBlockImportConfig::from_env())
    }

    /// Get current statistics
    pub fn stats(&self) -> BlockImportStats {
        self.stats.read().clone()
    }

    /// Get best block number
    pub fn best_number(&self) -> u64 {
        self.best_number.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get best block hash
    pub fn best_hash(&self) -> H256 {
        *self.best_hash.read()
    }

    /// Create an import callback for ProductionChainStateProvider
    ///
    /// This returns a closure that can be passed to `set_import_fn()`.
    pub fn create_import_callback(
        &self,
    ) -> impl Fn(&crate::substrate::mining_worker::BlockTemplate, &Sha256dSeal) -> Result<H256, String>
           + Send
           + Sync
           + 'static {
        let stats = self.stats.clone();
        let best_number = self.best_number.clone();
        let best_hash = self.best_hash.clone();
        let verbose = self.config.verbose;
        let verify_pow = self.config.verify_pow;

        move |template, seal| {
            // Verify the seal if configured
            if verify_pow && !consensus::seal_meets_target(&seal.work, seal.difficulty) {
                let mut s = stats.write();
                s.invalid_seals += 1;
                return Err("Seal does not meet difficulty target".to_string());
            }

            // Compute block hash from the seal work
            let block_hash = H256::from_slice(seal.work.as_bytes());

            // Update best block
            best_number.store(template.number, std::sync::atomic::Ordering::SeqCst);
            *best_hash.write() = block_hash;

            // Update statistics
            {
                let mut s = stats.write();
                s.blocks_imported += 1;
                s.last_block_number = template.number;
                s.last_block_hash = block_hash;
            }

            if verbose {
                tracing::info!(
                    block_number = template.number,
                    block_hash = %hex::encode(block_hash.as_bytes()),
                    nonce = ?seal.nonce,
                    difficulty = seal.difficulty,
                    "Block imported via BlockImportTracker"
                );
            } else {
                tracing::debug!(
                    block_number = template.number,
                    block_hash = %hex::encode(block_hash.as_bytes()),
                    "Block imported"
                );
            }

            Ok(block_hash)
        }
    }

    /// Create a best block callback for ProductionChainStateProvider
    pub fn create_best_block_callback(&self) -> impl Fn() -> (H256, u64) + Send + Sync + 'static {
        let best_number = self.best_number.clone();
        let best_hash = self.best_hash.clone();

        move || {
            let number = best_number.load(std::sync::atomic::Ordering::SeqCst);
            let hash = *best_hash.read();
            (hash, number)
        }
    }
}

/// Wire the block import tracker callbacks to a ProductionChainStateProvider
///
/// This connects the tracker to the provider, enabling:
/// - Real block import tracking
/// - Best block queries from tracker state
///
/// # Example
///
/// ```ignore
/// let tracker = BlockImportTracker::from_env();
/// let provider = Arc::new(ProductionChainStateProvider::new(config));
/// wire_import_tracker(&provider, &tracker);
/// ```
pub fn wire_import_tracker(
    provider: &Arc<ProductionChainStateProvider>,
    tracker: &BlockImportTracker,
) {
    // Wire best block callback
    provider.set_best_block_fn(tracker.create_best_block_callback());

    // Wire block import callback
    provider.set_import_fn(tracker.create_import_callback());

    tracing::info!(
        verify_pow = tracker.config.verify_pow,
        verbose = tracker.config.verbose,
        "Block import tracker wired to ProductionChainStateProvider"
    );
}

#[cfg(test)]
mod import_tests {
    use super::*;
    use crate::substrate::mining_worker::{BlockTemplate, ChainStateProvider};
    use sp_runtime::generic::Digest;
    use sp_runtime::traits::Header as HeaderT;
    use sp_runtime::DigestItem;

    #[test]
    fn test_full_block_import_config_default() {
        let config = FullBlockImportConfig::default();
        assert!(config.enabled);
        assert!(config.verify_pow);
        assert!(!config.verbose);
    }

    #[test]
    fn test_full_block_import_config_from_env() {
        let _config = FullBlockImportConfig::from_env();
    }

    #[test]
    fn test_block_import_tracker_new() {
        let tracker = BlockImportTracker::with_defaults();
        assert_eq!(tracker.best_number(), 0);
        assert_eq!(tracker.best_hash(), H256::zero());

        let stats = tracker.stats();
        assert_eq!(stats.blocks_imported, 0);
    }

    #[test]
    fn test_block_import_tracker_callback() {
        let tracker = BlockImportTracker::new(FullBlockImportConfig {
            enabled: true,
            verify_pow: false, // Disable for test
            verbose: false,
        });

        let callback = tracker.create_import_callback();

        let template = BlockTemplate::new(H256::zero(), 1, DEFAULT_DIFFICULTY_BITS);
        let seal = Sha256dSeal {
            nonce: consensus::counter_to_nonce(12_345),
            difficulty: DEFAULT_DIFFICULTY_BITS,
            work: H256::repeat_byte(0xaa),
        };

        let result = callback(&template, &seal);
        assert!(result.is_ok());

        assert_eq!(tracker.best_number(), 1);
        let stats = tracker.stats();
        assert_eq!(stats.blocks_imported, 1);
    }

    #[test]
    fn test_block_import_tracker_invalid_seal() {
        let tracker = BlockImportTracker::new(FullBlockImportConfig {
            enabled: true,
            verify_pow: true, // Enable verification
            verbose: false,
        });

        let callback = tracker.create_import_callback();

        let template = BlockTemplate::new(H256::zero(), 1, DEFAULT_DIFFICULTY_BITS);
        // Create invalid seal (work doesn't meet target)
        let seal = Sha256dSeal {
            nonce: consensus::counter_to_nonce(0),
            difficulty: 0x0300ffff,        // Very hard
            work: H256::repeat_byte(0xff), // Max value won't meet target
        };

        let result = callback(&template, &seal);
        assert!(result.is_err());

        let stats = tracker.stats();
        assert_eq!(stats.blocks_imported, 0);
        assert_eq!(stats.invalid_seals, 1);
    }

    #[test]
    fn test_wire_import_tracker() {
        let tracker = BlockImportTracker::with_defaults();
        let provider = Arc::new(ProductionChainStateProvider::new(
            ProductionConfig::default(),
        ));

        wire_import_tracker(&provider, &tracker);

        // Provider should now have callbacks
        // Best block should come from tracker
        assert_eq!(provider.best_number(), 0);
        assert_eq!(provider.best_hash(), H256::zero());
    }

    #[test]
    fn test_configure_pow_import_params_preserves_pow_fork_choice() {
        let header = runtime::Header::new(
            1,
            H256::zero(),
            H256::zero(),
            H256::zero(),
            Digest::default(),
        );
        let mut import_params = BlockImportParams::new(BlockOrigin::Own, header);
        let post_hash = H256::repeat_byte(0x42);
        let seal_item = DigestItem::Seal(*b"pow_", vec![1, 2, 3, 4]);

        configure_pow_import_params(&mut import_params, seal_item, post_hash);

        assert!(
            import_params.fork_choice.is_none(),
            "PowBlockImport must supply cumulative-difficulty fork choice"
        );
        assert_eq!(import_params.post_hash, Some(post_hash));
        assert_eq!(import_params.post_digests.len(), 1);
    }

    #[test]
    fn test_retryable_sync_parent_state_error_matches_unknown_block() {
        assert!(is_retryable_sync_parent_state_error(
            "UnknownBlock: parent state not ready"
        ));
        assert!(!is_retryable_sync_parent_state_error(
            "Proof verification failed"
        ));
    }

    #[test]
    fn test_finalized_chain_conflict_error_matches_not_in_finalized_chain() {
        assert!(is_finalized_chain_conflict_error(
            "Potential long-range attack: block not in finalized chain."
        ));
        assert!(is_finalized_chain_conflict_error(
            "ClientImport(NotInFinalizedChain)"
        ));
        assert!(!is_finalized_chain_conflict_error(
            "Proof verification failed"
        ));
    }

    #[test]
    fn test_collect_deferred_downloaded_tail_preserves_order() {
        let current = DownloadedBlock {
            number: 10,
            hash: [0x10; 32],
            header: vec![0x10],
            body: vec![vec![0x10]],
            from_peer: [0x10; 32],
        };
        let remaining = vec![
            DownloadedBlock {
                number: 11,
                hash: [0x11; 32],
                header: vec![0x11],
                body: vec![vec![0x11]],
                from_peer: [0x11; 32],
            },
            DownloadedBlock {
                number: 12,
                hash: [0x12; 32],
                header: vec![0x12],
                body: vec![vec![0x12]],
                from_peer: [0x12; 32],
            },
        ];

        let deferred = collect_deferred_downloaded_tail(current, remaining);
        let numbers: Vec<u64> = deferred.into_iter().map(|block| block.number).collect();
        assert_eq!(numbers, vec![10, 11, 12]);
    }
}
