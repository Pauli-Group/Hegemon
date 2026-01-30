//! Hegemon Substrate Node Service
//!
//! This module provides the core service implementation for the Substrate-based
//! Hegemon node, including:
//! - Partial node components setup with full Substrate client
//! - Full node service initialization
//! - Block import pipeline configuration with Blake3 PoW
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
//! │  │  │  Import Queue  │──▶│  Blake3 PoW      │──▶│    Client      │  │  │
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
//! │  │  │        ML-KEM-768 Key Encapsulation (post-quantum)              │││
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
    ChainStateProvider, MiningWorkerConfig,
};
use crate::substrate::network::{PqNetworkConfig, PqNetworkKeypair};
use crate::substrate::network_bridge::NetworkBridgeBuilder;
use crate::substrate::rpc::{
    ArchiveApiServer, ArchiveRpc, BlockApiServer, BlockRpc, DaApiServer, DaRpc, HegemonApiServer,
    HegemonRpc, NodeConfigSnapshot, ProductionRpcService, ShieldedApiServer, ShieldedRpc,
    WalletApiServer, WalletRpc,
};
use crate::substrate::transaction_pool::{
    SubstrateTransactionPoolWrapper, TransactionPoolBridge, TransactionPoolConfig,
};
use aggregation_circuit::prove_aggregation;
use block_circuit::{CommitmentBlockProof, CommitmentBlockProver, CommitmentBlockPublicInputs};
use codec::Decode;
use codec::Encode;
use consensus::proof::HeaderProofExt;
use consensus::{
    aggregation_proof_uncompressed_len, encode_aggregation_proof_bytes, Blake3Algorithm,
    Blake3Seal, ParallelProofVerifier,
};
use crypto::hashes::blake3_384;
use futures::StreamExt;
use network::{
    PqNetworkBackend, PqNetworkBackendConfig, PqNetworkEvent, PqNetworkHandle, PqPeerIdentity,
    PqTransportConfig, SubstratePqTransport, SubstratePqTransportConfig,
};
use rand::{rngs::OsRng, RngCore};
use sc_client_api::BlockchainEvents;
use sc_service::{error::Error as ServiceError, Configuration, KeystoreContainer, TaskManager};
use sc_transaction_pool_api::MaintainedTransactionPool;
use sha2::{Digest as ShaDigest, Sha256};
use sp_api::{ProvideRuntimeApi, StorageChanges};
use sp_core::H256;
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
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, Mutex};

// Import runtime APIs for difficulty queries
use parking_lot::Mutex as ParkingMutex;
use protocol_versioning::DEFAULT_VERSION_BINDING;
use runtime::apis::{ConsensusApi, ShieldedPoolApi};
use state_da::{DaChunkProof, DaEncoding, DaParams, DaRoot};
use state_merkle::CommitmentTree;
use transaction_circuit::constants::{MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::hashing_pq::{bytes48_to_felts, ciphertext_hash_bytes, Felt};
use transaction_circuit::proof::{SerializedStarkInputs, TransactionProof};
use transaction_circuit::public_inputs::{StablecoinPolicyBinding, TransactionPublicInputs};

type ShieldedPoolCall = pallet_shielded_pool::Call<runtime::Runtime>;

// Import jsonrpsee for RPC server
use jsonrpsee::server::ServerBuilder;

// Import sync service
use crate::substrate::sync::ChainSyncService;

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
const DEFAULT_DA_RETENTION_BLOCKS: u64 = 128;
const DEFAULT_PROOF_DA_RETENTION_BLOCKS: u64 = 16;
const DEFAULT_DA_SAMPLE_TIMEOUT_MS: u64 = 5000;
const DEFAULT_COMMITMENT_PROOF_STORE_CAPACITY: usize = 128;
const DEFAULT_PENDING_CIPHERTEXTS_CAPACITY: usize = 4096;
const DEFAULT_PENDING_PROOFS_CAPACITY: usize = 256;
const CIPHERTEXT_COUNT_KEY: &[u8] = b"ciphertext_count";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DaRootKind {
    Ciphertexts = 0,
    Proofs = 1,
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

#[derive(Debug)]
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

    pub fn remove_many(&mut self, hashes: &[[u8; 48]]) {
        for hash in hashes {
            self.entries.remove(hash);
            self.order.retain(|entry| entry != hash);
        }
    }
}

#[derive(Debug)]
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
        tracing::warn!(
            "Ciphertext DA retention is zero; falling back to {}",
            DEFAULT_DA_RETENTION_BLOCKS
        );
        return DEFAULT_DA_RETENTION_BLOCKS;
    }
    retention
}

fn load_proof_da_retention_blocks() -> u64 {
    let retention =
        env_u64("HEGEMON_PROOF_DA_RETENTION_BLOCKS").unwrap_or(DEFAULT_PROOF_DA_RETENTION_BLOCKS);
    if retention == 0 {
        tracing::warn!(
            "Proof DA retention is zero; falling back to {}",
            DEFAULT_PROOF_DA_RETENTION_BLOCKS
        );
        return DEFAULT_PROOF_DA_RETENTION_BLOCKS;
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

fn build_transaction_proof(
    proof_bytes: Vec<u8>,
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    ciphertexts: &[Vec<u8>],
    anchor: [u8; 48],
    stablecoin: Option<pallet_shielded_pool::types::StablecoinPolicyBinding>,
    fee: u64,
    value_balance: i128,
) -> Result<TransactionProof, String> {
    if proof_bytes.is_empty() {
        return Err("shielded transfer proof bytes are empty".to_string());
    }

    let input_count = nullifiers.len();
    let output_count = commitments.len();
    if ciphertexts.len() != output_count {
        return Err("ciphertext count does not match commitments".to_string());
    }
    let padded_nullifiers = pad_commitments(nullifiers, MAX_INPUTS, "nullifiers")?;
    let padded_commitments = pad_commitments(commitments, MAX_OUTPUTS, "commitments")?;
    let ciphertext_hashes: Vec<[u8; 48]> = ciphertexts
        .iter()
        .map(|ct| ciphertext_hash_bytes(ct))
        .collect();
    let padded_ciphertext_hashes =
        pad_commitments(ciphertext_hashes, MAX_OUTPUTS, "ciphertext hashes")?;

    let stablecoin_binding = stablecoin
        .as_ref()
        .map(convert_stablecoin_binding)
        .unwrap_or_default();
    let stark_public_inputs = build_stark_inputs(
        input_count,
        output_count,
        anchor,
        fee,
        value_balance,
        stablecoin.as_ref().map(|_| &stablecoin_binding),
    )?;

    let mut public_inputs = TransactionPublicInputs::default();
    public_inputs.merkle_root = anchor;
    public_inputs.nullifiers = padded_nullifiers.clone();
    public_inputs.commitments = padded_commitments.clone();
    public_inputs.ciphertext_hashes = padded_ciphertext_hashes.clone();
    public_inputs.native_fee = fee;
    public_inputs.value_balance = value_balance;
    public_inputs.stablecoin = stablecoin_binding;
    public_inputs.circuit_version = DEFAULT_VERSION_BINDING.circuit;
    public_inputs.crypto_suite = DEFAULT_VERSION_BINDING.crypto;

    Ok(TransactionProof {
        public_inputs: public_inputs.clone(),
        nullifiers: padded_nullifiers,
        commitments: padded_commitments,
        balance_slots: public_inputs.balance_slots.clone(),
        stark_proof: proof_bytes,
        stark_public_inputs: Some(stark_public_inputs),
    })
}

fn build_transaction_proof_with_hashes(
    proof_bytes: Vec<u8>,
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    ciphertext_hashes: &[[u8; 48]],
    anchor: [u8; 48],
    stablecoin: Option<pallet_shielded_pool::types::StablecoinPolicyBinding>,
    fee: u64,
    value_balance: i128,
) -> Result<TransactionProof, String> {
    if proof_bytes.is_empty() {
        return Err("shielded transfer proof bytes are empty".to_string());
    }

    let input_count = nullifiers.len();
    let output_count = commitments.len();
    if ciphertext_hashes.len() != output_count {
        return Err("ciphertext hash count does not match commitments".to_string());
    }
    let padded_nullifiers = pad_commitments(nullifiers, MAX_INPUTS, "nullifiers")?;
    let padded_commitments = pad_commitments(commitments, MAX_OUTPUTS, "commitments")?;
    let padded_ciphertext_hashes =
        pad_commitments(ciphertext_hashes.to_vec(), MAX_OUTPUTS, "ciphertext hashes")?;

    let stablecoin_binding = stablecoin
        .as_ref()
        .map(convert_stablecoin_binding)
        .unwrap_or_default();
    let stark_public_inputs = build_stark_inputs(
        input_count,
        output_count,
        anchor,
        fee,
        value_balance,
        stablecoin.as_ref().map(|_| &stablecoin_binding),
    )?;

    let mut public_inputs = TransactionPublicInputs::default();
    public_inputs.merkle_root = anchor;
    public_inputs.nullifiers = padded_nullifiers.clone();
    public_inputs.commitments = padded_commitments.clone();
    public_inputs.ciphertext_hashes = padded_ciphertext_hashes.clone();
    public_inputs.native_fee = fee;
    public_inputs.value_balance = value_balance;
    public_inputs.stablecoin = stablecoin_binding;
    public_inputs.circuit_version = DEFAULT_VERSION_BINDING.circuit;
    public_inputs.crypto_suite = DEFAULT_VERSION_BINDING.crypto;

    Ok(TransactionProof {
        public_inputs: public_inputs.clone(),
        nullifiers: padded_nullifiers,
        commitments: padded_commitments,
        balance_slots: public_inputs.balance_slots.clone(),
        stark_proof: proof_bytes,
        stark_public_inputs: Some(stark_public_inputs),
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

fn extract_transaction_proofs_from_extrinsics(
    extrinsics: &[Vec<u8>],
    resolved_ciphertexts: Option<&[Vec<Vec<u8>>]>,
    pending_proofs: Option<&PendingProofStore>,
) -> Result<Vec<TransactionProof>, String> {
    let mut proofs = Vec::new();
    let mut ciphertext_cursor = 0usize;

    for ext_bytes in extrinsics {
        let extrinsic = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..])
            .map_err(|e| format!("failed to decode extrinsic: {e:?}"))?;
        let runtime::RuntimeCall::ShieldedPool(call) = extrinsic.function else {
            continue;
        };

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

        match call {
            ShieldedPoolCall::mint_coinbase { .. } => {
                // Coinbase ciphertexts are stored separately from the DA blob.
            }
            ShieldedPoolCall::shielded_transfer {
                proof,
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                binding_hash,
                stablecoin,
                fee,
                value_balance,
                ..
            } => {
                let ciphertexts = match next_resolved_ciphertexts()? {
                    Some(ciphertexts) => ciphertexts,
                    None => ciphertexts
                        .iter()
                        .map(encrypted_note_bytes)
                        .collect::<Vec<_>>(),
                };
                let proof_bytes =
                    resolve_sidecar_proof_bytes(&proof, &binding_hash, pending_proofs)?;
                let proof = build_transaction_proof(
                    proof_bytes,
                    nullifiers.iter().copied().collect(),
                    commitments.iter().copied().collect(),
                    &ciphertexts,
                    anchor,
                    stablecoin.clone(),
                    fee,
                    value_balance,
                )?;
                proofs.push(proof);
            }
            ShieldedPoolCall::shielded_transfer_unsigned {
                proof,
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                binding_hash,
                stablecoin,
                fee,
                ..
            } => {
                if stablecoin.is_some() {
                    return Err("unsigned shielded transfer includes stablecoin binding".into());
                }
                let ciphertexts = match next_resolved_ciphertexts()? {
                    Some(ciphertexts) => ciphertexts,
                    None => ciphertexts
                        .iter()
                        .map(encrypted_note_bytes)
                        .collect::<Vec<_>>(),
                };
                let proof_bytes =
                    resolve_sidecar_proof_bytes(&proof, &binding_hash, pending_proofs)?;
                let proof = build_transaction_proof(
                    proof_bytes,
                    nullifiers.iter().copied().collect(),
                    commitments.iter().copied().collect(),
                    &ciphertexts,
                    anchor,
                    None,
                    fee,
                    0,
                )?;
                proofs.push(proof);
            }
            ShieldedPoolCall::shielded_transfer_sidecar {
                proof,
                nullifiers,
                commitments,
                anchor,
                binding_hash,
                stablecoin,
                fee,
                value_balance,
                ciphertext_hashes,
                ciphertext_sizes,
                ..
            } => {
                let maybe_ciphertexts = next_resolved_ciphertexts()?;
                let proof_bytes =
                    resolve_sidecar_proof_bytes(&proof, &binding_hash, pending_proofs)?;
                let proof = match maybe_ciphertexts.as_ref() {
                    Some(ciphertexts) => {
                        validate_ciphertexts_against_hashes(
                            ciphertexts,
                            &ciphertext_sizes,
                            &ciphertext_hashes,
                        )?;
                        build_transaction_proof(
                            proof_bytes,
                            nullifiers.iter().copied().collect(),
                            commitments.iter().copied().collect(),
                            ciphertexts,
                            anchor,
                            stablecoin.clone(),
                            fee,
                            value_balance,
                        )?
                    }
                    None => build_transaction_proof_with_hashes(
                        proof_bytes,
                        nullifiers.iter().copied().collect(),
                        commitments.iter().copied().collect(),
                        &ciphertext_hashes,
                        anchor,
                        stablecoin.clone(),
                        fee,
                        value_balance,
                    )?,
                };
                proofs.push(proof);
            }
            ShieldedPoolCall::shielded_transfer_unsigned_sidecar {
                proof,
                nullifiers,
                commitments,
                anchor,
                binding_hash,
                stablecoin,
                fee,
                ciphertext_hashes,
                ciphertext_sizes,
                ..
            } => {
                if stablecoin.is_some() {
                    return Err("unsigned shielded transfer includes stablecoin binding".into());
                }
                let maybe_ciphertexts = next_resolved_ciphertexts()?;
                let proof_bytes =
                    resolve_sidecar_proof_bytes(&proof, &binding_hash, pending_proofs)?;
                let proof = match maybe_ciphertexts.as_ref() {
                    Some(ciphertexts) => {
                        validate_ciphertexts_against_hashes(
                            ciphertexts,
                            &ciphertext_sizes,
                            &ciphertext_hashes,
                        )?;
                        build_transaction_proof(
                            proof_bytes,
                            nullifiers.iter().copied().collect(),
                            commitments.iter().copied().collect(),
                            ciphertexts,
                            anchor,
                            None,
                            fee,
                            0,
                        )?
                    }
                    None => build_transaction_proof_with_hashes(
                        proof_bytes,
                        nullifiers.iter().copied().collect(),
                        commitments.iter().copied().collect(),
                        &ciphertext_hashes,
                        anchor,
                        None,
                        fee,
                        0,
                    )?,
                };
                proofs.push(proof);
            }
            ShieldedPoolCall::batch_shielded_transfer { .. } => {
                return Err(
                    "batch shielded transfers are not supported in recursive block proofs".into(),
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

    Ok(proofs)
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
        let runtime::RuntimeCall::ShieldedPool(call) = &extrinsic.function else {
            continue;
        };

        let ciphertexts = match call {
            ShieldedPoolCall::shielded_transfer { ciphertexts, .. } => Some(
                ciphertexts
                    .iter()
                    .map(encrypted_note_bytes)
                    .collect::<Vec<_>>(),
            ),
            ShieldedPoolCall::shielded_transfer_unsigned { ciphertexts, .. } => Some(
                ciphertexts
                    .iter()
                    .map(encrypted_note_bytes)
                    .collect::<Vec<_>>(),
            ),
            ShieldedPoolCall::batch_shielded_transfer { ciphertexts, .. } => Some(
                ciphertexts
                    .iter()
                    .map(encrypted_note_bytes)
                    .collect::<Vec<_>>(),
            ),
            ShieldedPoolCall::shielded_transfer_sidecar {
                ciphertext_hashes,
                ciphertext_sizes,
                ..
            }
            | ShieldedPoolCall::shielded_transfer_unsigned_sidecar {
                ciphertext_hashes,
                ciphertext_sizes,
                ..
            } => {
                let pending = pending_ciphertexts
                    .ok_or_else(|| "pending ciphertext store missing".to_string())?;
                let hashes = ciphertext_hashes.as_slice();
                let ciphertexts = pending.get_many(hashes)?;
                validate_ciphertexts_against_hashes(&ciphertexts, ciphertext_sizes, hashes)?;
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

struct ProofDaBlobBuild {
    blob: Vec<u8>,
    manifest: Vec<pallet_shielded_pool::types::ProofDaManifestEntry>,
}

fn build_proof_da_blob_from_extrinsics(
    extrinsics: &[runtime::UncheckedExtrinsic],
    pending_proofs: Option<&PendingProofStore>,
) -> Result<ProofDaBlobBuild, String> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&0u32.to_le_bytes());
    let mut manifest = Vec::new();
    let mut count: u32 = 0;

    for extrinsic in extrinsics {
        let runtime::RuntimeCall::ShieldedPool(call) = &extrinsic.function else {
            continue;
        };

        match call {
            ShieldedPoolCall::shielded_transfer {
                proof,
                binding_hash,
                ..
            }
            | ShieldedPoolCall::shielded_transfer_unsigned {
                proof,
                binding_hash,
                ..
            }
            | ShieldedPoolCall::shielded_transfer_sidecar {
                proof,
                binding_hash,
                ..
            }
            | ShieldedPoolCall::shielded_transfer_unsigned_sidecar {
                proof,
                binding_hash,
                ..
            } => {
                if proof.data.is_empty() {
                    let proof_bytes =
                        resolve_sidecar_proof_bytes(proof, binding_hash, pending_proofs)?;
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| "proof DA entry count overflow".to_string())?;

                    blob.extend_from_slice(&binding_hash.data);
                    let proof_len = u32::try_from(proof_bytes.len())
                        .map_err(|_| "proof DA proof too large".to_string())?;
                    blob.extend_from_slice(&proof_len.to_le_bytes());
                    let proof_offset = u32::try_from(blob.len())
                        .map_err(|_| "proof DA blob offset overflow".to_string())?;
                    blob.extend_from_slice(&proof_bytes);

                    manifest.push(pallet_shielded_pool::types::ProofDaManifestEntry {
                        binding_hash: binding_hash.clone(),
                        proof_hash: blake3_384(&proof_bytes),
                        proof_len,
                        proof_offset,
                    });
                }
            }
            _ => {}
        }
    }

    blob[..4].copy_from_slice(&count.to_le_bytes());
    Ok(ProofDaBlobBuild { blob, manifest })
}

fn proof_da_blob_len_from_manifest(
    manifest: &[pallet_shielded_pool::types::ProofDaManifestEntry],
) -> Result<usize, String> {
    if manifest.is_empty() {
        return Err("proof DA manifest is empty".to_string());
    }

    let mut entries: Vec<&pallet_shielded_pool::types::ProofDaManifestEntry> =
        manifest.iter().collect();
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
        let runtime::RuntimeCall::ShieldedPool(call) = &extrinsic.function else {
            return false;
        };
        matches!(
            call,
            ShieldedPoolCall::shielded_transfer_sidecar { .. }
                | ShieldedPoolCall::shielded_transfer_unsigned_sidecar { .. }
        )
    })
}

fn da_layout_from_extrinsics(
    extrinsics: &[runtime::UncheckedExtrinsic],
) -> Result<Vec<DaTxLayout>, String> {
    let mut layouts = Vec::new();
    for extrinsic in extrinsics {
        let runtime::RuntimeCall::ShieldedPool(call) = &extrinsic.function else {
            continue;
        };

        let sizes = match call {
            ShieldedPoolCall::shielded_transfer { ciphertexts, .. } => Some(
                ciphertexts
                    .iter()
                    .map(|note| encrypted_note_bytes(note).len())
                    .collect::<Vec<_>>(),
            ),
            ShieldedPoolCall::shielded_transfer_unsigned { ciphertexts, .. } => Some(
                ciphertexts
                    .iter()
                    .map(|note| encrypted_note_bytes(note).len())
                    .collect::<Vec<_>>(),
            ),
            ShieldedPoolCall::batch_shielded_transfer { ciphertexts, .. } => Some(
                ciphertexts
                    .iter()
                    .map(|note| encrypted_note_bytes(note).len())
                    .collect::<Vec<_>>(),
            ),
            ShieldedPoolCall::shielded_transfer_sidecar {
                ciphertext_sizes, ..
            }
            | ShieldedPoolCall::shielded_transfer_unsigned_sidecar {
                ciphertext_sizes, ..
            } => Some(
                ciphertext_sizes
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

fn binding_hashes_from_extrinsics(extrinsics: &[runtime::UncheckedExtrinsic]) -> Vec<[u8; 64]> {
    let mut out = Vec::new();
    for extrinsic in extrinsics {
        let runtime::RuntimeCall::ShieldedPool(call) = &extrinsic.function else {
            continue;
        };
        match call {
            ShieldedPoolCall::shielded_transfer { binding_hash, .. }
            | ShieldedPoolCall::shielded_transfer_unsigned { binding_hash, .. }
            | ShieldedPoolCall::shielded_transfer_sidecar { binding_hash, .. }
            | ShieldedPoolCall::shielded_transfer_unsigned_sidecar { binding_hash, .. } => {
                out.push(binding_hash.data);
            }
            _ => {}
        }
    }
    out
}

fn missing_proof_binding_hashes(extrinsics: &[runtime::UncheckedExtrinsic]) -> Vec<[u8; 64]> {
    let mut out = Vec::new();
    for extrinsic in extrinsics {
        let runtime::RuntimeCall::ShieldedPool(call) = &extrinsic.function else {
            continue;
        };
        match call {
            ShieldedPoolCall::shielded_transfer {
                proof,
                binding_hash,
                ..
            }
            | ShieldedPoolCall::shielded_transfer_unsigned {
                proof,
                binding_hash,
                ..
            }
            | ShieldedPoolCall::shielded_transfer_sidecar {
                proof,
                binding_hash,
                ..
            }
            | ShieldedPoolCall::shielded_transfer_unsigned_sidecar {
                proof,
                binding_hash,
                ..
            } => {
                if proof.data.is_empty() {
                    out.push(binding_hash.data);
                }
            }
            _ => {}
        }
    }
    out
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

fn da_data_shards_for_total_shards(total_shards: usize) -> Result<usize, String> {
    if total_shards == 0 {
        return Err("DA shard count is zero".to_string());
    }
    if total_shards > DA_MAX_SHARDS {
        return Err(format!(
            "DA shard count {} exceeds max {}",
            total_shards, DA_MAX_SHARDS
        ));
    }

    for data_shards in 1..=total_shards {
        if data_shards + da_parity_shards_for_data(data_shards) == total_shards {
            return Ok(data_shards);
        }
    }

    Err(format!(
        "invalid DA shard count {} (no matching data/parity split)",
        total_shards
    ))
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

async fn fetch_da_range_with_cache(
    peer_id: network::PeerId,
    da_root: DaRoot,
    chunk_count: u32,
    params: DaParams,
    handle: &PqNetworkHandle,
    tracker: &Arc<ParkingMutex<DaRequestTracker>>,
    timeout: Duration,
    offset: u32,
    len: u32,
    cache: &mut HashMap<u32, DaChunkProof>,
) -> Result<Vec<u8>, String> {
    if len == 0 {
        return Err("DA range length is zero".to_string());
    }
    if chunk_count == 0 {
        return Err("DA chunk count is zero".to_string());
    }

    let total_shards = chunk_count as usize;
    let data_shards = da_data_shards_for_total_shards(total_shards)?;
    let chunk_size = params.chunk_size as u64;

    let start_offset = offset as u64;
    let end_offset = start_offset
        .checked_add(len as u64)
        .ok_or_else(|| "DA range end offset overflow".to_string())?;

    let start_shard = start_offset / chunk_size;
    let end_shard = end_offset.saturating_sub(1) / chunk_size;

    if end_shard >= data_shards as u64 {
        return Err("DA range exceeds data shard length".to_string());
    }

    let indices: Vec<u32> = (start_shard..=end_shard)
        .map(|idx| u32::try_from(idx).expect("shard index fits u32"))
        .collect();

    let mut missing = Vec::new();
    for idx in &indices {
        if !cache.contains_key(idx) {
            missing.push(*idx);
        }
    }

    if !missing.is_empty() {
        let proofs =
            request_da_samples(peer_id, da_root, &missing, handle, tracker, timeout).await?;
        if proofs.len() != missing.len() {
            return Err("missing DA chunk proofs".to_string());
        }
        for (expected_index, proof) in missing.into_iter().zip(proofs.into_iter()) {
            if proof.chunk.index != expected_index {
                return Err("DA chunk response index mismatch".to_string());
            }
            state_da::verify_da_chunk(da_root, &proof)
                .map_err(|err| format!("invalid DA chunk proof: {err}"))?;
            cache.insert(expected_index, proof);
        }
    }

    let mut out = vec![0u8; len as usize];
    let mut out_cursor = 0usize;
    let start_in_shard = (start_offset % chunk_size) as usize;
    let mut shard_cursor = start_shard;

    for index in indices {
        let expected_index = u32::try_from(shard_cursor).expect("shard index fits u32");
        if index != expected_index {
            return Err("DA chunk response index mismatch".to_string());
        }
        let proof = cache
            .get(&index)
            .ok_or_else(|| "missing DA chunk proof".to_string())?;

        let mut take_from = 0usize;
        if shard_cursor == start_shard {
            take_from = start_in_shard;
        }

        let take_to = if shard_cursor == end_shard {
            (end_offset - shard_cursor * chunk_size) as usize
        } else {
            params.chunk_size as usize
        };

        if take_to > proof.chunk.data.len() || take_from > take_to {
            return Err("DA chunk range invalid".to_string());
        }

        let slice = &proof.chunk.data[take_from..take_to];
        let dest_end = out_cursor.saturating_add(slice.len());
        if dest_end > out.len() {
            return Err("DA range reconstruction overflow".to_string());
        }
        out[out_cursor..dest_end].copy_from_slice(slice);
        out_cursor = dest_end;
        shard_cursor = shard_cursor.saturating_add(1);
    }

    if out_cursor != out.len() {
        return Err("DA range reconstruction truncated".to_string());
    }

    Ok(out)
}

async fn fetch_proof_da_entry_with_cache(
    peer_id: network::PeerId,
    da_root: DaRoot,
    chunk_count: u32,
    params: DaParams,
    handle: &PqNetworkHandle,
    tracker: &Arc<ParkingMutex<DaRequestTracker>>,
    timeout: Duration,
    entry: &pallet_shielded_pool::types::ProofDaManifestEntry,
    cache: &mut HashMap<u32, DaChunkProof>,
) -> Result<Vec<u8>, String> {
    let proof_bytes = fetch_da_range_with_cache(
        peer_id,
        da_root,
        chunk_count,
        params,
        handle,
        tracker,
        timeout,
        entry.proof_offset,
        entry.proof_len,
        cache,
    )
    .await?;
    if blake3_384(&proof_bytes) != entry.proof_hash {
        return Err("proof DA entry hash mismatch".to_string());
    }
    Ok(proof_bytes)
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

fn build_commitment_tree_from_chain(
    client: &HegemonFullClient,
    parent_hash: H256,
) -> Result<CommitmentTree, String> {
    let api = client.runtime_api();
    let total = api
        .encrypted_note_count(parent_hash)
        .map_err(|e| format!("runtime api error (encrypted_note_count): {e:?}"))?;
    let expected_root = api
        .merkle_root(parent_hash)
        .map_err(|e| format!("runtime api error (merkle_root): {e:?}"))?;

    let depth = pallet_shielded_pool::types::MERKLE_TREE_DEPTH as usize;
    let mut tree =
        CommitmentTree::new(depth).map_err(|e| format!("commitment tree init failed: {e}"))?;

    if total == 0 {
        if tree.root() != expected_root {
            return Err("commitment tree root mismatch for empty tree".into());
        }
        return Ok(tree);
    }

    let mut expected_index = 0u64;
    while expected_index < total {
        let batch = api
            .get_commitments(parent_hash, expected_index, 256)
            .map_err(|e| format!("runtime api error (get_commitments): {e:?}"))?;
        if batch.is_empty() {
            return Err("commitments batch returned empty before expected count".into());
        }
        for (index, commitment) in batch {
            if index != expected_index {
                return Err(format!(
                    "commitment index mismatch: expected {}, got {}",
                    expected_index, index
                ));
            }
            tree.append(commitment)
                .map_err(|e| format!("commitment tree append failed: {e}"))?;
            expected_index += 1;
        }
    }

    if tree.root() != expected_root {
        return Err(format!(
            "commitment tree root mismatch: expected {}, got {}",
            hex::encode(expected_root),
            hex::encode(tree.root())
        ));
    }

    Ok(tree)
}

fn build_commitment_block_proof(
    client: &HegemonFullClient,
    parent_hash: H256,
    extrinsics: &[Vec<u8>],
    da_params: DaParams,
    da_root_override: Option<DaRoot>,
    resolved_ciphertexts: Option<&[Vec<Vec<u8>>]>,
    pending_proofs: Option<&PendingProofStore>,
    _fast: bool,
) -> Result<Option<CommitmentBlockProof>, String> {
    let proofs = extract_transaction_proofs_from_extrinsics(
        extrinsics,
        resolved_ciphertexts,
        pending_proofs,
    )?;
    if proofs.is_empty() {
        return Ok(None);
    }

    let mut tree = build_commitment_tree_from_chain(client, parent_hash)?;
    let mut decoded = Vec::with_capacity(extrinsics.len());
    for ext_bytes in extrinsics {
        let extrinsic = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..])
            .map_err(|e| format!("failed to decode extrinsic: {e:?}"))?;
        decoded.push(extrinsic);
    }
    let da_root = if let Some(root) = da_root_override {
        root
    } else {
        let DaEncodingBuild { encoding, .. } =
            build_da_encoding_from_extrinsics(&decoded, da_params, None)?;
        encoding.root()
    };

    let prover = CommitmentBlockProver::new();

    let proof = prover
        .prove_block_commitment_with_tree(&mut tree, &proofs, da_root)
        .map_err(|e| format!("commitment block proof failed: {e}"))?;

    Ok(Some(proof))
}

#[derive(Clone, Debug, Default)]
struct AggregationProofOutcome {
    proof_bytes: Option<Vec<u8>>,
    attach_extrinsic: bool,
}

fn build_aggregation_proof(
    extrinsics: &[Vec<u8>],
    resolved_ciphertexts: Option<&[Vec<Vec<u8>>]>,
    pending_proofs: Option<&PendingProofStore>,
) -> Result<AggregationProofOutcome, String> {
    let mut decoded = Vec::with_capacity(extrinsics.len());
    for ext_bytes in extrinsics {
        let extrinsic = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..])
            .map_err(|e| format!("failed to decode extrinsic: {e:?}"))?;
        decoded.push(extrinsic);
    }

    let existing = extract_aggregation_proof_bytes(&decoded)?;
    let (_transactions, proofs) = extract_shielded_transfers_for_parallel_verification(
        &decoded,
        resolved_ciphertexts,
        pending_proofs,
    )?;
    if proofs.is_empty() {
        if existing.is_some() {
            return Err("aggregation proof present for block with no shielded transfers".into());
        }
        return Ok(AggregationProofOutcome::default());
    }

    if let Some(proof_bytes) = existing {
        return Ok(AggregationProofOutcome {
            proof_bytes: Some(maybe_corrupt_aggregation_proof(proof_bytes)),
            attach_extrinsic: false,
        });
    }

    let proof_bytes = prove_aggregation(&proofs)
        .map_err(|err| format!("aggregation proof generation failed: {err}"))?;
    Ok(AggregationProofOutcome {
        proof_bytes: Some(maybe_corrupt_aggregation_proof(proof_bytes)),
        attach_extrinsic: true,
    })
}

fn maybe_corrupt_aggregation_proof(mut proof_bytes: Vec<u8>) -> Vec<u8> {
    let corrupt = std::env::var("HEGEMON_AGGREGATION_PROOF_CORRUPT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !corrupt {
        return proof_bytes;
    }
    if let Some(first) = proof_bytes.first_mut() {
        *first ^= 0x01;
        tracing::warn!("Corrupting aggregation proof bytes for test");
    }
    proof_bytes
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
}

struct CommitmentProofPayload {
    da_root: DaRoot,
    da_chunk_count: u32,
    proof_bytes: Vec<u8>,
}

#[derive(Debug)]
struct ProofDaCommitmentPayload {
    da_root: DaRoot,
    da_chunk_count: u32,
}

#[derive(Debug)]
struct ProofDaManifestPayload {
    manifest: Vec<pallet_shielded_pool::types::ProofDaManifestEntry>,
}

#[derive(Debug)]
struct ValidatedProofDaPayload {
    payload: ProofDaCommitmentPayload,
    manifest_map: HashMap<[u8; 64], pallet_shielded_pool::types::ProofDaManifestEntry>,
    missing_bindings: Vec<[u8; 64]>,
}

fn extract_commitment_proof_payload(
    extrinsics: &[runtime::UncheckedExtrinsic],
) -> Result<Option<CommitmentProofPayload>, String> {
    let mut found: Option<CommitmentProofPayload> = None;
    for extrinsic in extrinsics {
        let runtime::RuntimeCall::ShieldedPool(call) = &extrinsic.function else {
            continue;
        };

        if let ShieldedPoolCall::submit_commitment_proof {
            da_root,
            chunk_count,
            proof,
        } = call
        {
            if found.is_some() {
                return Err("multiple submit_commitment_proof extrinsics in block".into());
            }
            found = Some(CommitmentProofPayload {
                da_root: *da_root,
                da_chunk_count: *chunk_count,
                proof_bytes: proof.data.clone(),
            });
        }
    }
    Ok(found)
}

fn validate_proof_da_payloads(
    extrinsics: &[runtime::UncheckedExtrinsic],
    da_params: DaParams,
) -> Result<Option<ValidatedProofDaPayload>, String> {
    let missing_bindings = missing_proof_binding_hashes(extrinsics);
    let proof_da_payload = extract_proof_da_commitment_payload(extrinsics)?;
    let proof_da_manifest_payload = extract_proof_da_manifest_payload(extrinsics)?;

    if missing_bindings.is_empty() {
        if proof_da_payload.is_some() {
            return Err(
                "submit_proof_da_commitment present but no missing proof bytes".to_string(),
            );
        }
        if proof_da_manifest_payload.is_some() {
            return Err("submit_proof_da_manifest present but no missing proof bytes".to_string());
        }
        return Ok(None);
    }

    let proof_da_payload = proof_da_payload
        .ok_or_else(|| "missing submit_proof_da_commitment extrinsic".to_string())?;
    let manifest = proof_da_manifest_payload
        .ok_or_else(|| "missing submit_proof_da_manifest extrinsic".to_string())?
        .manifest;

    let blob_len = proof_da_blob_len_from_manifest(&manifest)?;
    let (_data_shards, expected_chunk_count) = da_shard_counts_for_len(blob_len, da_params)?;
    let expected_chunk_count = u32::try_from(expected_chunk_count)
        .map_err(|_| "proof DA chunk_count overflow".to_string())?;
    if expected_chunk_count != proof_da_payload.da_chunk_count {
        return Err("proof DA da_chunk_count mismatch".to_string());
    }

    let mut manifest_map = HashMap::new();
    for entry in manifest {
        let pallet_shielded_pool::types::ProofDaManifestEntry {
            binding_hash,
            proof_hash,
            proof_len,
            proof_offset,
        } = entry;
        let key = binding_hash.data;
        let entry = pallet_shielded_pool::types::ProofDaManifestEntry {
            binding_hash,
            proof_hash,
            proof_len,
            proof_offset,
        };
        if manifest_map.insert(key, entry).is_some() {
            return Err("duplicate binding hash in proof DA manifest".to_string());
        }
    }

    if manifest_map.len() != missing_bindings.len() {
        return Err("proof DA manifest entry count mismatch".to_string());
    }
    for binding_hash in &missing_bindings {
        if !manifest_map.contains_key(binding_hash) {
            return Err("proof DA manifest missing binding hash entry".to_string());
        }
    }

    Ok(Some(ValidatedProofDaPayload {
        payload: proof_da_payload,
        manifest_map,
        missing_bindings,
    }))
}

fn extract_proof_da_commitment_payload(
    extrinsics: &[runtime::UncheckedExtrinsic],
) -> Result<Option<ProofDaCommitmentPayload>, String> {
    let mut found: Option<ProofDaCommitmentPayload> = None;
    for extrinsic in extrinsics {
        let runtime::RuntimeCall::ShieldedPool(call) = &extrinsic.function else {
            continue;
        };

        if let ShieldedPoolCall::submit_proof_da_commitment {
            da_root,
            chunk_count,
        } = call
        {
            if found.is_some() {
                return Err("multiple submit_proof_da_commitment extrinsics in block".into());
            }
            found = Some(ProofDaCommitmentPayload {
                da_root: *da_root,
                da_chunk_count: *chunk_count,
            });
        }
    }
    Ok(found)
}

fn extract_proof_da_manifest_payload(
    extrinsics: &[runtime::UncheckedExtrinsic],
) -> Result<Option<ProofDaManifestPayload>, String> {
    let mut found: Option<ProofDaManifestPayload> = None;
    for extrinsic in extrinsics {
        let runtime::RuntimeCall::ShieldedPool(call) = &extrinsic.function else {
            continue;
        };

        if let ShieldedPoolCall::submit_proof_da_manifest { manifest } = call {
            if found.is_some() {
                return Err("multiple submit_proof_da_manifest extrinsics in block".into());
            }
            found = Some(ProofDaManifestPayload {
                manifest: manifest.to_vec(),
            });
        }
    }
    Ok(found)
}

fn extract_aggregation_proof_bytes(
    extrinsics: &[runtime::UncheckedExtrinsic],
) -> Result<Option<Vec<u8>>, String> {
    let mut found: Option<Vec<u8>> = None;
    for extrinsic in extrinsics {
        let runtime::RuntimeCall::ShieldedPool(call) = &extrinsic.function else {
            continue;
        };

        if let ShieldedPoolCall::submit_aggregation_proof { proof } = call {
            if found.is_some() {
                return Err("multiple submit_aggregation_proof extrinsics in block".into());
            }
            found = Some(proof.data.clone());
        }
    }
    Ok(found)
}

fn extract_shielded_transfers_for_parallel_verification(
    extrinsics: &[runtime::UncheckedExtrinsic],
    resolved_ciphertexts: Option<&[Vec<Vec<u8>>]>,
    pending_proofs: Option<&PendingProofStore>,
) -> Result<(Vec<consensus::types::Transaction>, Vec<TransactionProof>), String> {
    let mut transactions = Vec::new();
    let mut proofs = Vec::new();
    let mut ciphertext_cursor = 0usize;

    for extrinsic in extrinsics {
        let runtime::RuntimeCall::ShieldedPool(call) = &extrinsic.function else {
            continue;
        };

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

        match call {
            ShieldedPoolCall::mint_coinbase { .. } => {
                // Coinbase ciphertexts are stored separately from the DA blob.
            }
            ShieldedPoolCall::shielded_transfer {
                proof,
                nullifiers,
                commitments,
                anchor,
                binding_hash,
                stablecoin,
                fee,
                value_balance,
                ciphertexts,
                ..
            } => {
                let ciphertexts = match next_resolved_ciphertexts()? {
                    Some(ciphertexts) => ciphertexts,
                    None => ciphertexts
                        .iter()
                        .map(encrypted_note_bytes)
                        .collect::<Vec<_>>(),
                };
                let proof_bytes = resolve_sidecar_proof_bytes(proof, binding_hash, pending_proofs)?;
                let tx_proof = build_transaction_proof(
                    proof_bytes,
                    nullifiers.iter().copied().collect(),
                    commitments.iter().copied().collect(),
                    &ciphertexts,
                    *anchor,
                    stablecoin.clone(),
                    *fee,
                    *value_balance,
                )?;
                let tx = crate::transaction::proof_to_transaction(
                    &tx_proof,
                    DEFAULT_VERSION_BINDING,
                    ciphertexts,
                );
                transactions.push(tx);
                proofs.push(tx_proof);
            }
            ShieldedPoolCall::shielded_transfer_unsigned {
                proof,
                nullifiers,
                commitments,
                anchor,
                binding_hash,
                stablecoin,
                fee,
                ciphertexts,
                ..
            } => {
                if stablecoin.is_some() {
                    return Err("unsigned shielded transfer includes stablecoin binding".into());
                }
                let ciphertexts = match next_resolved_ciphertexts()? {
                    Some(ciphertexts) => ciphertexts,
                    None => ciphertexts
                        .iter()
                        .map(encrypted_note_bytes)
                        .collect::<Vec<_>>(),
                };
                let proof_bytes = resolve_sidecar_proof_bytes(proof, binding_hash, pending_proofs)?;
                let tx_proof = build_transaction_proof(
                    proof_bytes,
                    nullifiers.iter().copied().collect(),
                    commitments.iter().copied().collect(),
                    &ciphertexts,
                    *anchor,
                    None,
                    *fee,
                    0,
                )?;
                let tx = crate::transaction::proof_to_transaction(
                    &tx_proof,
                    DEFAULT_VERSION_BINDING,
                    ciphertexts,
                );
                transactions.push(tx);
                proofs.push(tx_proof);
            }
            ShieldedPoolCall::shielded_transfer_sidecar {
                proof,
                nullifiers,
                commitments,
                anchor,
                binding_hash,
                stablecoin,
                fee,
                value_balance,
                ciphertext_hashes,
                ciphertext_sizes,
                ..
            } => {
                let nullifiers_vec = nullifiers.iter().copied().collect::<Vec<_>>();
                let commitments_vec = commitments.iter().copied().collect::<Vec<_>>();
                let hash_vec = ciphertext_hashes.to_vec();
                let maybe_ciphertexts = next_resolved_ciphertexts()?;
                let proof_bytes = resolve_sidecar_proof_bytes(proof, binding_hash, pending_proofs)?;
                let tx_proof = match maybe_ciphertexts.as_ref() {
                    Some(ciphertexts) => {
                        validate_ciphertexts_against_hashes(
                            ciphertexts,
                            ciphertext_sizes,
                            ciphertext_hashes,
                        )?;
                        build_transaction_proof(
                            proof_bytes,
                            nullifiers_vec.clone(),
                            commitments_vec.clone(),
                            ciphertexts,
                            *anchor,
                            stablecoin.clone(),
                            *fee,
                            *value_balance,
                        )?
                    }
                    None => build_transaction_proof_with_hashes(
                        proof_bytes,
                        nullifiers_vec.clone(),
                        commitments_vec.clone(),
                        &hash_vec,
                        *anchor,
                        stablecoin.clone(),
                        *fee,
                        *value_balance,
                    )?,
                };
                let tx = match maybe_ciphertexts {
                    Some(ciphertexts) => crate::transaction::proof_to_transaction(
                        &tx_proof,
                        DEFAULT_VERSION_BINDING,
                        ciphertexts,
                    ),
                    None => consensus::types::Transaction::new_with_hashes(
                        nullifiers_vec,
                        commitments_vec,
                        tx_proof.public_inputs.balance_tag,
                        DEFAULT_VERSION_BINDING,
                        hash_vec,
                    ),
                };
                transactions.push(tx);
                proofs.push(tx_proof);
            }
            ShieldedPoolCall::shielded_transfer_unsigned_sidecar {
                proof,
                nullifiers,
                commitments,
                anchor,
                binding_hash,
                stablecoin,
                fee,
                ciphertext_hashes,
                ciphertext_sizes,
                ..
            } => {
                if stablecoin.is_some() {
                    return Err("unsigned shielded transfer includes stablecoin binding".into());
                }
                let nullifiers_vec = nullifiers.iter().copied().collect::<Vec<_>>();
                let commitments_vec = commitments.iter().copied().collect::<Vec<_>>();
                let hash_vec = ciphertext_hashes.to_vec();
                let maybe_ciphertexts = next_resolved_ciphertexts()?;
                let proof_bytes = resolve_sidecar_proof_bytes(proof, binding_hash, pending_proofs)?;
                let tx_proof = match maybe_ciphertexts.as_ref() {
                    Some(ciphertexts) => {
                        validate_ciphertexts_against_hashes(
                            ciphertexts,
                            ciphertext_sizes,
                            ciphertext_hashes,
                        )?;
                        build_transaction_proof(
                            proof_bytes,
                            nullifiers_vec.clone(),
                            commitments_vec.clone(),
                            ciphertexts,
                            *anchor,
                            None,
                            *fee,
                            0,
                        )?
                    }
                    None => build_transaction_proof_with_hashes(
                        proof_bytes,
                        nullifiers_vec.clone(),
                        commitments_vec.clone(),
                        &hash_vec,
                        *anchor,
                        None,
                        *fee,
                        0,
                    )?,
                };
                let tx = match maybe_ciphertexts {
                    Some(ciphertexts) => crate::transaction::proof_to_transaction(
                        &tx_proof,
                        DEFAULT_VERSION_BINDING,
                        ciphertexts,
                    ),
                    None => consensus::types::Transaction::new_with_hashes(
                        nullifiers_vec,
                        commitments_vec,
                        tx_proof.public_inputs.balance_tag,
                        DEFAULT_VERSION_BINDING,
                        hash_vec,
                    ),
                };
                transactions.push(tx);
                proofs.push(tx_proof);
            }
            ShieldedPoolCall::batch_shielded_transfer { .. } => {
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

    Ok((transactions, proofs))
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
    proof_hashes: &[[u8; 48]],
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

    if proof_hashes.len() != transactions.len() {
        return Err(format!(
            "tx proof hash count mismatch (expected {}, got {})",
            transactions.len(),
            proof_hashes.len()
        ));
    }
    let tx_proofs_commitment = CommitmentBlockProver::commitment_from_proof_hashes(proof_hashes)
        .map_err(|err| format!("tx_proofs_commitment failed: {err}"))?;

    let mut tree = parent_tree.clone();
    for tx in transactions {
        for commitment in tx.commitments.iter().copied().filter(|c| *c != [0u8; 48]) {
            tree.append(commitment)
                .map_err(|err| format!("commitment tree append failed: {err}"))?;
        }
    }

    let starting_state_root = parent_tree.root();
    let ending_state_root = tree.root();
    let tx_count = transactions.len() as u32;
    let (perm_alpha, perm_beta) = derive_nullifier_challenges(
        &starting_state_root,
        &ending_state_root,
        &nullifier_root,
        &da_root,
        tx_count,
        &lists.nullifiers,
        &lists.sorted_nullifiers,
    );

    let public_inputs = CommitmentBlockPublicInputs {
        tx_proofs_commitment: bytes48_to_felts_checked(
            "tx_proofs_commitment",
            &tx_proofs_commitment,
        )?,
        starting_state_root: bytes48_to_felts_checked("starting_state_root", &starting_state_root)?,
        ending_state_root: bytes48_to_felts_checked("ending_state_root", &ending_state_root)?,
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

    let commitment_payload = extract_commitment_proof_payload(extrinsics)?;
    let aggregation_proof_bytes = extract_aggregation_proof_bytes(extrinsics)?;
    ensure_shielded_transfer_ordering(extrinsics)?;
    ensure_forced_inclusions(client, parent_hash, block_number, extrinsics)?;
    let (transactions, tx_proofs) = extract_shielded_transfers_for_parallel_verification(
        extrinsics,
        resolved_ciphertexts,
        pending_proofs,
    )?;
    let mut proof_da_payload: Option<ProofDaCommitmentPayload> = None;
    let mut proof_da_manifest_map: HashMap<
        [u8; 64],
        pallet_shielded_pool::types::ProofDaManifestEntry,
    > = HashMap::new();
    let missing_proof_bindings = match validate_proof_da_payloads(extrinsics, da_params)? {
        Some(validated) => {
            proof_da_payload = Some(validated.payload);
            proof_da_manifest_map = validated.manifest_map;
            validated.missing_bindings
        }
        None => Vec::new(),
    };

    if transactions.is_empty() {
        if commitment_payload.is_some() {
            return Err("commitment proof present for block with no shielded transfers".into());
        }
        if aggregation_proof_bytes.is_some() {
            return Err("aggregation proof present for block with no shielded transfers".into());
        }
        return Ok(None);
    }

    let payload = commitment_payload
        .ok_or_else(|| "missing submit_commitment_proof extrinsic".to_string())?;

    {
        let extrinsics_bytes_total: usize = extrinsics.iter().map(|ext| ext.encode().len()).sum();
        let da_blob_bytes_estimate = da_layout_from_extrinsics(extrinsics)
            .map(|layouts| da_blob_len_from_layouts(&layouts))
            .unwrap_or(0);
        let proof_da_blob_bytes_estimate = if missing_proof_bindings.is_empty() {
            0usize
        } else {
            let pending = pending_proofs.ok_or_else(|| {
                "proof bytes missing but pending proof store not provided".to_string()
            })?;
            let mut total = 4usize; // entry count
            for binding_hash in &missing_proof_bindings {
                let proof_bytes = pending.get(binding_hash).ok_or_else(|| {
                    format!(
                        "missing proof bytes for binding hash {}",
                        hex::encode(binding_hash)
                    )
                })?;
                total = total
                    .saturating_add(64) // binding hash bytes
                    .saturating_add(4) // proof len
                    .saturating_add(proof_bytes.len());
            }
            total
        };
        let tx_proof_bytes_total: usize =
            tx_proofs.iter().map(|proof| proof.stark_proof.len()).sum();
        let aggregation_proof_bytes_len = aggregation_proof_bytes
            .as_ref()
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        tracing::info!(
            target: "node::metrics",
            block_number,
            tx_count = transactions.len(),
            extrinsics_bytes_total,
            da_blob_bytes_estimate,
            proof_da_blob_bytes_estimate,
            proof_da_entry_count = missing_proof_bindings.len(),
            tx_proof_bytes_total,
            commitment_proof_bytes = payload.proof_bytes.len(),
            aggregation_proof_bytes = aggregation_proof_bytes_len,
            da_chunk_count = payload.da_chunk_count,
            da_root = %hex::encode(payload.da_root),
            proof_da_chunk_count = proof_da_payload.as_ref().map(|payload| payload.da_chunk_count).unwrap_or(0),
            proof_da_root = %proof_da_payload.as_ref().map(|payload| hex::encode(payload.da_root)).unwrap_or_default(),
            da_policy = ?da_policy,
            "block_payload_size_metrics"
        );
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

    let parent_tree = load_parent_commitment_tree_state(client, parent_hash)?;
    let proof_hashes = {
        let mut hashes = Vec::with_capacity(transactions.len());
        for extrinsic in extrinsics {
            let runtime::RuntimeCall::ShieldedPool(call) = &extrinsic.function else {
                continue;
            };
            match call {
                ShieldedPoolCall::shielded_transfer {
                    proof,
                    binding_hash,
                    ..
                }
                | ShieldedPoolCall::shielded_transfer_unsigned {
                    proof,
                    binding_hash,
                    ..
                }
                | ShieldedPoolCall::shielded_transfer_sidecar {
                    proof,
                    binding_hash,
                    ..
                }
                | ShieldedPoolCall::shielded_transfer_unsigned_sidecar {
                    proof,
                    binding_hash,
                    ..
                } => {
                    if proof.data.is_empty() {
                        let entry =
                            proof_da_manifest_map
                                .get(&binding_hash.data)
                                .ok_or_else(|| {
                                    "missing proof hash entry in proof DA manifest".to_string()
                                })?;
                        hashes.push(entry.proof_hash);
                    } else {
                        hashes.push(blake3_384(&proof.data));
                    }
                }
                _ => {}
            }
        }
        hashes
    };
    let commitment_proof = derive_commitment_block_proof_from_bytes(
        payload.proof_bytes,
        &transactions,
        &proof_hashes,
        &parent_tree,
        da_params,
        Some(payload.da_root),
    )?;

    let block = consensus::types::Block {
        header: SubstrateProofHeader { da_params },
        transactions,
        coinbase: None,
        commitment_proof: Some(commitment_proof.clone()),
        aggregation_proof: aggregation_proof_bytes,
        transaction_proofs: Some(tx_proofs),
    };

    let start_verify = Instant::now();
    verifier
        .verify_block(&block, &parent_tree)
        .map_err(|err| format!("proof verification failed: {err}"))?;
    let verify_ms = start_verify.elapsed().as_millis();
    tracing::info!(
        target: "node::metrics",
        block_number,
        verify_ms,
        aggregation_proof_present = block.aggregation_proof.is_some(),
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

fn is_shielded_transfer_call(call: &runtime::RuntimeCall) -> bool {
    let runtime::RuntimeCall::ShieldedPool(call) = call else {
        return false;
    };

    matches!(
        call,
        ShieldedPoolCall::shielded_transfer { .. }
            | ShieldedPoolCall::shielded_transfer_unsigned { .. }
            | ShieldedPoolCall::shielded_transfer_sidecar { .. }
            | ShieldedPoolCall::shielded_transfer_unsigned_sidecar { .. }
            | ShieldedPoolCall::batch_shielded_transfer { .. }
    )
}

fn shielded_transfer_order_key(call: &ShieldedPoolCall) -> [u8; 32] {
    sp_core::hashing::blake2_256(&call.encode())
}

fn shielded_transfer_key_from_extrinsic(
    extrinsic: &runtime::UncheckedExtrinsic,
) -> Option<[u8; 32]> {
    let runtime::RuntimeCall::ShieldedPool(call) = &extrinsic.function else {
        return None;
    };
    match call {
        ShieldedPoolCall::shielded_transfer { .. }
        | ShieldedPoolCall::shielded_transfer_unsigned { .. }
        | ShieldedPoolCall::shielded_transfer_sidecar { .. }
        | ShieldedPoolCall::shielded_transfer_unsigned_sidecar { .. }
        | ShieldedPoolCall::batch_shielded_transfer { .. } => {
            Some(shielded_transfer_order_key(call))
        }
        _ => None,
    }
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
    client: &HegemonFullClient,
    parent_hash: H256,
    block_number: u64,
    extrinsics: &[runtime::UncheckedExtrinsic],
) -> Result<(), String> {
    let api = client.runtime_api();
    let pending = api
        .forced_inclusions(parent_hash)
        .map_err(|err| format!("forced inclusion query failed: {err}"))?;
    if pending.is_empty() {
        return Ok(());
    }

    let mut included = std::collections::HashSet::new();
    for extrinsic in extrinsics {
        if let Some(key) = shielded_transfer_key_from_extrinsic(extrinsic) {
            included.insert(key);
        }
    }

    for entry in pending {
        if entry.expiry <= block_number && !included.contains(&entry.commitment) {
            return Err("forced inclusion missing in block".to_string());
        }
    }

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

fn total_shielded_fees(extrinsics: &[Vec<u8>]) -> Result<u128, String> {
    let mut total: u128 = 0;
    for ext_bytes in extrinsics {
        let extrinsic = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..])
            .map_err(|e| format!("failed to decode extrinsic: {e:?}"))?;
        let runtime::RuntimeCall::ShieldedPool(call) = extrinsic.function else {
            continue;
        };

        let fee = match call {
            ShieldedPoolCall::shielded_transfer { fee, .. }
            | ShieldedPoolCall::shielded_transfer_unsigned { fee, .. }
            | ShieldedPoolCall::shielded_transfer_sidecar { fee, .. }
            | ShieldedPoolCall::shielded_transfer_unsigned_sidecar { fee, .. } => u128::from(fee),
            ShieldedPoolCall::batch_shielded_transfer { total_fee, .. } => total_fee,
            _ => continue,
        };

        total = total
            .checked_add(fee)
            .ok_or_else(|| "shielded fee total overflowed".to_string())?;
    }
    Ok(total)
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
    da_params: DaParams,
    pending_ciphertext_store: Arc<ParkingMutex<PendingCiphertextStore>>,
    pending_proof_store: Arc<ParkingMutex<PendingProofStore>>,
) {
    use sc_block_builder::BlockBuilderBuilder;

    let client_for_exec = client;
    let commitment_block_proofs_enabled = std::env::var("HEGEMON_COMMITMENT_BLOCK_PROOFS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let aggregation_proofs_enabled = std::env::var("HEGEMON_AGGREGATION_PROOFS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
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
    let max_shielded_transfers_per_block = load_max_shielded_transfers_per_block();

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

        // Create inherent extrinsics (timestamp, coinbase, etc.)
        let inherent_extrinsics = match block_builder.create_inherents(inherent_data.clone()) {
            Ok(exts) => {
                tracing::info!(
                    count = exts.len(),
                    "Created {} inherent extrinsics",
                    exts.len()
                );
                for (i, ext) in exts.iter().enumerate() {
                    let encoded = ext.encode();
                    tracing::info!(
                        index = i,
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
        let ordered_extrinsics = reorder_shielded_transfers(&extrinsics)?;

        if aggregation_proofs_enabled {
            let enable_extrinsic = runtime::UncheckedExtrinsic::new_unsigned(
                runtime::RuntimeCall::ShieldedPool(ShieldedPoolCall::enable_aggregation_mode {}),
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

        for ext_bytes in ordered_extrinsics {
            match runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..]) {
                Ok(extrinsic) => {
                    let is_shielded = is_shielded_transfer_call(&extrinsic.function);
                    if is_shielded && shielded_transfer_count >= max_shielded_transfers_per_block {
                        tracing::warn!(
                            block_number,
                            max_shielded_transfers_per_block,
                            "Skipping shielded transfer: block already contains {} (coinbase + transfers)",
                            shielded_transfer_count
                        );
                        continue;
                    }
                    match block_builder.push(extrinsic) {
                        Ok(_) => {
                            applied.push(ext_bytes.clone());
                            if is_shielded {
                                shielded_transfer_count =
                                    shielded_transfer_count.saturating_add(1);
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = ?e, "Extrinsic push failed");
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

        let total_fees = if parsed_shielded_address.is_some() {
            total_shielded_fees(&applied)?
        } else {
            0
        };

        if let Some(ref address) = parsed_shielded_address {
            let subsidy = pallet_coinbase::block_subsidy(block_number);
            let fee_u64 = u64::try_from(total_fees)
                .map_err(|_| "block fee total exceeds u64".to_string())?;
            let amount = subsidy
                .checked_add(fee_u64)
                .ok_or_else(|| "coinbase amount overflowed".to_string())?;

            let mut block_hash_input = [0u8; 40];
            block_hash_input[..32].copy_from_slice(parent_hash.as_bytes());
            block_hash_input[32..40].copy_from_slice(&block_number.to_le_bytes());
            let block_hash: [u8; 32] = blake3::hash(&block_hash_input).into();

            match crate::shielded_coinbase::encrypt_coinbase_note(
                address,
                amount,
                &block_hash,
                block_number,
            ) {
                Ok(coinbase_data) => {
                    tracing::info!(
                        block_number,
                        subsidy,
                        fees = total_fees,
                        amount,
                        commitment = %hex::encode(&coinbase_data.commitment),
                        "Encrypting shielded coinbase note"
                    );
                    let coinbase_extrinsic = runtime::UncheckedExtrinsic::new_unsigned(
                        runtime::RuntimeCall::ShieldedPool(
                            ShieldedPoolCall::mint_coinbase { coinbase_data },
                        ),
                    );
                    match block_builder.push(coinbase_extrinsic.clone()) {
                        Ok(_) => {
                            applied.push(coinbase_extrinsic.encode());
                            tracing::info!(
                                block_number,
                                subsidy,
                                fees = total_fees,
                                amount,
                                "Added shielded coinbase extrinsic for block reward"
                            );
                        }
                        Err(e) => {
                            return Err(format!(
                                "failed to push shielded coinbase extrinsic: {e:?}"
                            ));
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        error = ?e,
                        block_number,
                        "Failed to encrypt coinbase note - no reward for this block"
                    );
                }
            }
        }

        let mut da_blob_build = None;
        if commitment_block_proofs_enabled || aggregation_proofs_enabled {
            let mut decoded = Vec::with_capacity(applied.len());
            for ext_bytes in &applied {
                let extrinsic = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..])
                    .map_err(|e| format!("failed to decode extrinsic: {e:?}"))?;
                decoded.push(extrinsic);
            }
            let build = {
                let pending_guard = pending_ciphertext_store.lock();
                build_da_blob_from_extrinsics(&decoded, Some(&*pending_guard))
            }
            .map_err(|err| format!("failed to build DA blob for block: {err}"))?;
            da_blob_build = Some(build);
        }

        let resolved_ciphertexts =
            da_blob_build.as_ref().map(|build| build.transactions.as_slice());
        let mut da_chunk_count_override = None;
        let da_root_override = if commitment_block_proofs_enabled {
            if let Some(build) = da_blob_build.as_ref() {
                let encoding = state_da::encode_da_blob(&build.blob, da_params)
                    .map_err(|err| format!("da_root encoding failed: {err}"))?;
                let root = encoding.root();
                da_chunk_count_override = Some(encoding.chunks().len() as u32);
                Some(root)
            } else {
                None
            }
        } else {
            None
        };

        let commitment_proof = if commitment_block_proofs_enabled {
            let da_root_for_commitment = da_root_override
                .ok_or_else(|| "missing da_root for commitment proof".to_string())?;
            let pending_proofs_guard = pending_proof_store.lock();
            match build_commitment_block_proof(
                client_for_exec.as_ref(),
                parent_substrate_hash,
                &applied,
                da_params,
                Some(da_root_for_commitment),
                resolved_ciphertexts,
                Some(&*pending_proofs_guard),
                commitment_block_fast,
            ) {
                Ok(Some(proof)) => {
                    let chunk_count_for_commitment = da_chunk_count_override
                        .ok_or_else(|| "missing da_chunk_count for commitment proof".to_string())?;
                    let commitment_extrinsic = runtime::UncheckedExtrinsic::new_unsigned(
                        runtime::RuntimeCall::ShieldedPool(
                            ShieldedPoolCall::submit_commitment_proof {
                                da_root: da_root_for_commitment,
                                chunk_count: chunk_count_for_commitment,
                                proof: pallet_shielded_pool::types::StarkProof::from_bytes(
                                    proof.proof_bytes.clone(),
                                ),
                            },
                        ),
                    );

                    match block_builder.push(commitment_extrinsic.clone()) {
                        Ok(_) => {
                            applied.push(commitment_extrinsic.encode());
                            tracing::info!(
                                block_number,
                                tx_count = proof.public_inputs.tx_count,
                                proof_size = proof.proof_bytes.len(),
                                proof_hash = %hex::encode(proof.proof_hash),
                                "Commitment proof extrinsic attached"
                            );
                        }
                        Err(e) => {
                            return Err(format!(
                                "failed to push commitment proof extrinsic: {e:?}"
                            ));
                        }
                    }

                    Some(proof)
                }
                Ok(None) => None,
                Err(e) => {
                    return Err(format!("commitment block proof generation failed: {e}"));
                }
            }
        } else {
            None
        };

        let mut aggregation_outcome = if aggregation_proofs_enabled {
            let pending_proofs_guard = pending_proof_store.lock();
            match build_aggregation_proof(
                &applied,
                resolved_ciphertexts,
                Some(&*pending_proofs_guard),
            ) {
                Ok(outcome) => outcome,
                Err(err) => {
                    return Err(format!("aggregation proof generation failed: {err}"));
                }
            }
        } else {
            let mut decoded = Vec::with_capacity(applied.len());
            for ext_bytes in &applied {
                let extrinsic = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..])
                    .map_err(|e| format!("failed to decode extrinsic: {e:?}"))?;
                decoded.push(extrinsic);
            }
            let existing = extract_aggregation_proof_bytes(&decoded)?;
            AggregationProofOutcome {
                proof_bytes: existing,
                attach_extrinsic: false,
            }
        };

        if aggregation_outcome.attach_extrinsic {
            let proof_bytes = aggregation_outcome
                .proof_bytes
                .clone()
                .ok_or_else(|| "aggregation proof bytes missing".to_string())?;
            let encoded_proof_bytes = encode_aggregation_proof_bytes(proof_bytes);
            let proof_size = encoded_proof_bytes.len();
            let proof_size_uncompressed =
                aggregation_proof_uncompressed_len(&encoded_proof_bytes);
            let aggregation_extrinsic = runtime::UncheckedExtrinsic::new_unsigned(
                runtime::RuntimeCall::ShieldedPool(ShieldedPoolCall::submit_aggregation_proof {
                    proof: pallet_shielded_pool::types::StarkProof::from_bytes(
                        encoded_proof_bytes.clone(),
                    ),
                }),
            );
            match block_builder.push(aggregation_extrinsic.clone()) {
                Ok(_) => {
                    applied.push(aggregation_extrinsic.encode());
                    aggregation_outcome.proof_bytes = Some(encoded_proof_bytes);
                    tracing::info!(
                        block_number,
                        proof_size,
                        proof_size_uncompressed,
                        "Aggregation proof extrinsic attached"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        block_number,
                        proof_size,
                        error = ?e,
                        "Aggregation proof extrinsic omitted (block resources exhausted)"
                    );
                    aggregation_outcome.proof_bytes = None;
                    aggregation_outcome.attach_extrinsic = false;
                }
            }
        }

        // If any shielded transfers omitted proof bytes, publish those bytes via a DA commitment.
        let mut decoded_for_proof_da = Vec::with_capacity(applied.len());
        for ext_bytes in &applied {
            let extrinsic = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..])
                .map_err(|e| format!("failed to decode extrinsic: {e:?}"))?;
            decoded_for_proof_da.push(extrinsic);
        }
        let missing_proof_hashes = missing_proof_binding_hashes(&decoded_for_proof_da);
        if !missing_proof_hashes.is_empty() {
            let build = {
                let pending_guard = pending_proof_store.lock();
                build_proof_da_blob_from_extrinsics(&decoded_for_proof_da, Some(&*pending_guard))
            }
            .map_err(|err| format!("failed to build proof DA blob for block: {err}"))?;

            let encoding = state_da::encode_da_blob(&build.blob, da_params)
                .map_err(|err| format!("proof DA encoding failed: {err}"))?;
            let proof_da_root = encoding.root();
            let proof_da_chunk_count = encoding.chunks().len() as u32;

            let proof_da_extrinsic = runtime::UncheckedExtrinsic::new_unsigned(
                runtime::RuntimeCall::ShieldedPool(
                    ShieldedPoolCall::submit_proof_da_commitment {
                        da_root: proof_da_root,
                        chunk_count: proof_da_chunk_count,
                    },
                ),
            );

            match block_builder.push(proof_da_extrinsic.clone()) {
                Ok(_) => {
                    applied.push(proof_da_extrinsic.encode());
                    tracing::info!(
                        block_number,
                        missing_proof_count = missing_proof_hashes.len(),
                        proof_da_chunk_count,
                        proof_da_root = %hex::encode(proof_da_root),
                        "Proof DA commitment extrinsic attached"
                    );
                }
                Err(e) => {
                    return Err(format!(
                        "failed to push proof DA commitment extrinsic: {e:?}"
                    ));
                }
            }

            let manifest: sp_runtime::BoundedVec<
                pallet_shielded_pool::types::ProofDaManifestEntry,
                runtime::MaxProofDaManifestEntries,
            > = build
                .manifest
                .try_into()
                .map_err(|_| "proof DA manifest exceeds MaxProofDaManifestEntries".to_string())?;

            let manifest_extrinsic = runtime::UncheckedExtrinsic::new_unsigned(
                runtime::RuntimeCall::ShieldedPool(ShieldedPoolCall::submit_proof_da_manifest {
                    manifest,
                }),
            );

            match block_builder.push(manifest_extrinsic.clone()) {
                Ok(_) => {
                    applied.push(manifest_extrinsic.encode());
                    tracing::info!(
                        block_number,
                        entry_count = missing_proof_hashes.len(),
                        "Proof DA manifest extrinsic attached"
                    );
                }
                Err(e) => {
                    return Err(format!(
                        "failed to push proof DA manifest extrinsic: {e:?}"
                    ));
                }
            }
        }

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
            commitment_proof,
            aggregation_proof: aggregation_outcome.proof_bytes,
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
// The PowBlockImport verifies the Blake3 PoW seal before allowing the block
// to be committed to the backend.

use crate::substrate::mining_worker::BlockTemplate;
use sc_consensus::{BlockImport, BlockImportParams, ForkChoiceStrategy, ImportResult};
use sp_consensus::BlockOrigin;
use sp_runtime::generic::Digest;
use sp_runtime::DigestItem;

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
/// 4. `PowBlockImport.import_block()` verifies the seal
/// 5. If valid, block is committed to backend
///
/// # Arguments
///
/// * `chain_state` - The ProductionChainStateProvider to wire
/// * `pow_block_import` - The PowBlockImport wrapper for verified imports
/// * `client` - The full Substrate client for header construction
/// * `da_chunk_store` - Persistent DA chunk store (with in-memory cache) for serving proofs
/// * `pending_ciphertext_store` - Pending sidecar ciphertext pool for block assembly
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
/// // Block is imported directly (PoW already verified by mining worker)
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
    _pow_block_import: ConcretePowBlockImport,
    client: Arc<HegemonFullClient>,
    da_chunk_store: Arc<ParkingMutex<DaChunkStore>>,
    pending_ciphertext_store: Arc<ParkingMutex<PendingCiphertextStore>>,
    pending_proof_store: Arc<ParkingMutex<PendingProofStore>>,
    commitment_block_proof_store: Arc<ParkingMutex<CommitmentBlockProofStore>>,
    da_params: DaParams,
) {
    use codec::Encode;
    use sp_runtime::traits::Block as BlockT;

    // Use the client directly for block import
    // The mining worker already verified the PoW, so we don't need PowBlockImport
    // to re-verify (which would fail due to pre_hash computation differences)
    let block_import = client;
    let proof_verification_enabled = proof_verification_enabled();
    let parallel_verifier = ParallelProofVerifier::new();
    chain_state.set_import_fn(move |template: &BlockTemplate, seal: &Blake3Seal| {
        // Construct the block header from the template
        let parent_hash: sp_core::H256 = template.parent_hash.into();

        // Include the seal in the header's digest for storage
        // Use our custom engine ID "bpow" for Blake3 PoW
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

        let missing_proof_hashes = missing_proof_binding_hashes(&encoded_extrinsics);
        let mut proof_da_build: Option<DaEncoding> = None;
        if !missing_proof_hashes.is_empty() {
            let payload = extract_proof_da_commitment_payload(&encoded_extrinsics)?
                .ok_or_else(|| "missing submit_proof_da_commitment extrinsic".to_string())?;
            let manifest_payload = extract_proof_da_manifest_payload(&encoded_extrinsics)?
                .ok_or_else(|| "missing submit_proof_da_manifest extrinsic".to_string())?;
            let pending_proofs_guard = pending_proof_store.lock();
            let build = build_proof_da_blob_from_extrinsics(
                &encoded_extrinsics,
                Some(&*pending_proofs_guard),
            )
            .map_err(|err| format!("failed to build proof DA blob for mined block: {err}"))?;

            let built_binding_hashes: Vec<[u8; 64]> = build
                .manifest
                .iter()
                .map(|entry| entry.binding_hash.data)
                .collect();
            if built_binding_hashes != missing_proof_hashes {
                return Err("proof DA blob missing expected binding hashes".to_string());
            }
            if manifest_payload.manifest != build.manifest {
                return Err("proof DA manifest mismatch for mined block".to_string());
            }

            let encoding = state_da::encode_da_blob(&build.blob, da_params)
                .map_err(|err| format!("proof DA encoding failed: {err}"))?;
            if encoding.root() != payload.da_root {
                return Err("proof DA root mismatch for mined block".to_string());
            }
            if encoding.chunks().len() as u32 != payload.da_chunk_count {
                return Err("proof DA chunk_count mismatch for mined block".to_string());
            }
            proof_da_build = Some(encoding);
        }

        if proof_verification_enabled {
            let da_policy = fetch_da_policy(block_import.as_ref(), template.parent_hash);
            let resolved_ciphertexts = da_build.as_ref().map(|build| build.transactions.as_slice());
            let pending_proofs_guard = pending_proof_store.lock();
            verify_proof_carrying_block(
                &parallel_verifier,
                block_import.as_ref(),
                template.parent_hash,
                template.number,
                &encoded_extrinsics,
                da_params,
                da_policy,
                resolved_ciphertexts,
                Some(&*pending_proofs_guard),
            )
            .map_err(|err| format!("mined block proof verification failed: {err}"))?;
        }

        // Construct the block with seal in header
        let block = runtime::Block::new(header.clone(), encoded_extrinsics);
        let block_hash = block.hash();
        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes.copy_from_slice(block_hash.as_bytes());

        // Construct BlockImportParams for direct client import
        // No post_digests needed since seal is already in header
        let mut import_params = BlockImportParams::new(BlockOrigin::Own, header);
        import_params.body = Some(block.extrinsics().to_vec());
        import_params.fork_choice = Some(ForkChoiceStrategy::LongestChain);

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

        // Import the block directly through the client
        // This bypasses PowBlockImport verification since we already verified locally
        let import_result = futures::executor::block_on(async {
            let import = block_import.clone();
            import.import_block(import_params).await
        });

        match import_result {
            Ok(ImportResult::Imported(_aux)) => {
                if let Some(build) = da_build.take() {
                    let da_root = build.encoding.root();
                    let da_chunks = build.encoding.chunks().len();
                    let mut ciphertexts = flatten_ciphertexts(&build.transactions);
                    let coinbase_ciphertexts = block
                        .extrinsics()
                        .iter()
                        .filter_map(|extrinsic| match &extrinsic.function {
                            runtime::RuntimeCall::ShieldedPool(
                                ShieldedPoolCall::mint_coinbase { coinbase_data },
                            ) => Some(encrypted_note_bytes(&coinbase_data.encrypted_note)),
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                    ciphertexts.extend(coinbase_ciphertexts);
                    let ciphertext_count = ciphertexts.len();
                    let mut store = da_chunk_store.lock();
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
                    pending_ciphertext_store
                        .lock()
                        .remove_many(&build.used_ciphertext_hashes);
                }
                if let Some(encoding) = proof_da_build.take() {
                    let proof_da_root = encoding.root();
                    let proof_da_chunks = encoding.chunks().len();
                    let mut store = da_chunk_store.lock();
                    if let Err(err) = store.insert(
                        DaRootKind::Proofs,
                        template.number,
                        block_hash_bytes,
                        encoding,
                    ) {
                        tracing::warn!(
                            block_number = template.number,
                            da_root = %hex::encode(proof_da_root),
                            error = %err,
                            "Failed to persist proof DA encoding for imported block"
                        );
                    } else {
                        tracing::info!(
                            block_number = template.number,
                            da_root = %hex::encode(proof_da_root),
                            da_chunks = proof_da_chunks,
                            "Proof DA encoding stored for imported block"
                        );
                    }
                }
                {
                    let binding_hashes = binding_hashes_from_extrinsics(block.extrinsics());
                    if !binding_hashes.is_empty() {
                        pending_proof_store.lock().remove_many(&binding_hashes);
                    }
                }
                if let Some(proof) = template.commitment_proof.clone() {
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
                Ok(block_hash)
            }
            Ok(ImportResult::AlreadyInChain) => {
                if let Some(build) = da_build.take() {
                    let da_root = build.encoding.root();
                    let da_chunks = build.encoding.chunks().len();
                    let mut ciphertexts = flatten_ciphertexts(&build.transactions);
                    let coinbase_ciphertexts = block
                        .extrinsics()
                        .iter()
                        .filter_map(|extrinsic| match &extrinsic.function {
                            runtime::RuntimeCall::ShieldedPool(
                                ShieldedPoolCall::mint_coinbase { coinbase_data },
                            ) => Some(encrypted_note_bytes(&coinbase_data.encrypted_note)),
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                    ciphertexts.extend(coinbase_ciphertexts);
                    let ciphertext_count = ciphertexts.len();
                    let mut store = da_chunk_store.lock();
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
                    pending_ciphertext_store
                        .lock()
                        .remove_many(&build.used_ciphertext_hashes);
                }
                if let Some(encoding) = proof_da_build.take() {
                    let proof_da_root = encoding.root();
                    let proof_da_chunks = encoding.chunks().len();
                    let mut store = da_chunk_store.lock();
                    if let Err(err) = store.insert(
                        DaRootKind::Proofs,
                        template.number,
                        block_hash_bytes,
                        encoding,
                    ) {
                        tracing::warn!(
                            block_number = template.number,
                            da_root = %hex::encode(proof_da_root),
                            error = %err,
                            "Failed to persist proof DA encoding for known block"
                        );
                    } else {
                        tracing::info!(
                            block_number = template.number,
                            da_root = %hex::encode(proof_da_root),
                            da_chunks = proof_da_chunks,
                            "Proof DA encoding stored for known block"
                        );
                    }
                }
                {
                    let binding_hashes = binding_hashes_from_extrinsics(block.extrinsics());
                    if !binding_hashes.is_empty() {
                        pending_proof_store.lock().remove_many(&binding_hashes);
                    }
                }
                if let Some(proof) = template.commitment_proof.clone() {
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
    tracing::debug!("  - Blake3 seals validated before commit");
}

/// PQ network configuration for the node service
#[derive(Clone, Debug)]
pub struct PqServiceConfig {
    /// Enable verbose PQ handshake logging
    pub verbose_logging: bool,
    /// Listen address for P2P
    pub listen_addr: std::net::SocketAddr,
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<std::net::SocketAddr>,
    /// Maximum peers
    pub max_peers: usize,
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
        let bootstrap_nodes: Vec<std::net::SocketAddr> = std::env::var("HEGEMON_SEEDS")
            .map(|s| {
                s.split(',')
                    .filter_map(|addr| {
                        let addr = addr.trim();
                        if addr.is_empty() {
                            return None;
                        }
                        // First try direct parse (for IP:port)
                        if let Ok(sock_addr) = addr.parse() {
                            return Some(sock_addr);
                        }
                        if let Ok(ip_addr) = addr.parse::<std::net::IpAddr>() {
                            return Some(std::net::SocketAddr::new(ip_addr, DEFAULT_P2P_PORT));
                        }
                        // If that fails, try DNS resolution (for hostname[:port])
                        let resolve_host = |target: &str| -> Result<
                            Option<std::net::SocketAddr>,
                            std::io::Error,
                        > {
                            std::net::ToSocketAddrs::to_socket_addrs(target)
                                .map(|mut addrs| addrs.next())
                        };

                        match resolve_host(addr) {
                            Ok(Some(resolved)) => {
                                tracing::info!(
                                    addr = %addr,
                                    resolved = %resolved,
                                    "Resolved seed hostname"
                                );
                                Some(resolved)
                            }
                            Ok(None) => {
                                tracing::warn!(
                                    addr = %addr,
                                    "DNS resolved but no addresses returned"
                                );
                                None
                            }
                            Err(err) => {
                                if !addr.contains(':') {
                                    let with_port = format!("{addr}:{DEFAULT_P2P_PORT}");
                                    return match resolve_host(&with_port) {
                                        Ok(Some(resolved)) => {
                                            tracing::info!(
                                                addr = %addr,
                                                resolved = %resolved,
                                                default_port = DEFAULT_P2P_PORT,
                                                "Resolved seed hostname with default port"
                                            );
                                            Some(resolved)
                                        }
                                        Ok(None) => {
                                            tracing::warn!(
                                                addr = %addr,
                                                default_port = DEFAULT_P2P_PORT,
                                                "DNS resolved but no addresses returned"
                                            );
                                            None
                                        }
                                        Err(err) => {
                                            tracing::warn!(
                                                addr = %addr,
                                                default_port = DEFAULT_P2P_PORT,
                                                error = %err,
                                                "Failed to resolve seed address"
                                            );
                                            None
                                        }
                                    };
                                }
                                tracing::warn!(
                                    addr = %addr,
                                    error = %err,
                                    "Failed to resolve seed address"
                                );
                                None
                            }
                        }
                    })
                    .collect()
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
    /// Chain selection rule
    ///
    /// Uses LongestChain which selects the chain with the most blocks.
    /// This is the standard selection rule for PoW chains.
    pub select_chain: HegemonSelectChain,
    /// PoW block import wrapper
    ///
    /// Wraps the client with PoW verification using Blake3Algorithm.
    /// All blocks imported through this wrapper are verified for valid PoW.
    pub pow_block_import: ConcretePowBlockImport,
    /// Blake3 PoW algorithm
    ///
    /// The PoW algorithm implementation used for block verification and mining.
    pub pow_algorithm: Blake3Algorithm<HegemonFullClient>,
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
            task_manager.spawn_essential_handle(),
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
    // 1. Create LongestChain for chain selection (standard PoW rule)
    // 2. Create Blake3Algorithm with client reference for difficulty queries
    // 3. Wrap client in PowBlockImport for PoW verification
    //
    // Flow: Network → Import Queue → PowBlockImport → Client → Backend

    // Create chain selection rule (LongestChain for PoW)
    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    // Create Blake3 PoW algorithm with client for difficulty queries
    let pow_algorithm = Blake3Algorithm::new(client.clone());

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
    // This verifies Blake3 PoW seals before allowing blocks to be imported
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
    tracing::debug!("  - Blake3Algorithm for PoW verification");
    tracing::debug!("  - LongestChain for chain selection");
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
            .map(|addr| format!("/ip4/{}/tcp/{}", addr.ip(), addr.port()))
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
/// | State root | Blake3 hash of extrinsics | Runtime-computed |
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
        backend: _backend,
        keystore_container,
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

            tracing::info!("Transaction pool maintenance task stopped");
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
                // NOTE: Get all handles before pq_backend is moved into the task
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
                let peer_count_for_rpc = Arc::clone(&peer_count);

                // Spawn the PQ network event handler task with sync integration
                task_manager.spawn_handle().spawn(
                    "pq-network-events",
                    Some("network"),
                    async move {
                        let _pq_backend = pq_backend;
                        tracing::info!("PQ network event handler started (Full Client Mode + Sync)");

                        while let Some(event) = event_rx.recv().await {
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
                                    tracing::info!(
                                        peer_id = %hex::encode(peer_id),
                                        reason = %reason,
                                        "PQ peer disconnected"
                                    );
                                }
                                PqNetworkEvent::MessageReceived { peer_id, protocol, data } => {
                                    // Handle sync protocol messages
                                    use crate::substrate::network_bridge::{
                                        BlockAnnounce, DaChunkProtocolMessage, BLOCK_ANNOUNCE_PROTOCOL,
                                        DA_CHUNKS_PROTOCOL, SYNC_PROTOCOL,
                                    };
                                    use crate::substrate::network_bridge::SyncMessage;
                                    // Handle sync protocol messages
                                    if protocol == SYNC_PROTOCOL {
                                        // Decode using SyncMessage wrapper for unambiguous request/response distinction
                                        if let Ok(msg) = SyncMessage::decode(&mut &data[..]) {
                                            match msg {
                                                SyncMessage::Request(request) => {
                                                    tracing::info!(
                                                        peer = %hex::encode(peer_id),
                                                        request = ?request,
                                                        "Received sync request from peer"
                                                    );
                                                    let mut sync = sync_service_clone.lock().await;
                                                    if let Some(response) = sync.handle_sync_request(peer_id, request) {
                                                        // Send response back to peer wrapped in SyncMessage
                                                        let msg = SyncMessage::Response(response);
                                                        let encoded = msg.encode();
                                                        tracing::info!(
                                                            peer = %hex::encode(peer_id),
                                                            response_len = encoded.len(),
                                                            "Sending sync response to peer"
                                                        );
                                                        if let Err(e) = pq_handle_for_sync.send_message(
                                                            peer_id,
                                                            SYNC_PROTOCOL.to_string(),
                                                            encoded,
                                                        ).await {
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
                        use crate::substrate::network_bridge::{SyncMessage, SYNC_PROTOCOL};

                        let mut interval =
                            tokio::time::interval(tokio::time::Duration::from_secs(1));
                        tracing::info!("Chain sync tick task started");

                        loop {
                            interval.tick().await;

                            let mut sync = sync_service_for_tick.lock().await;

                            // Tick the sync state machine
                            if let Some((peer_id, request)) = sync.tick() {
                                // Wrap request in SyncMessage for unambiguous encoding
                                let msg = SyncMessage::Request(request);
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

                            // Get ready transactions from pool
                            let ready_txs: Vec<_> = transaction_pool_for_prop
                                .ready()
                                .map(|tx| {
                                    let hash: sp_core::H256 = *InPoolTransaction::hash(&*tx);
                                    let data = InPoolTransaction::data(&*tx).encode();
                                    (hash, data)
                                })
                                .collect();

                            // Find transactions we haven't broadcast yet
                            let new_tx_pairs: Vec<(sp_core::H256, Vec<u8>)> = ready_txs
                                .into_iter()
                                .filter(|(hash, _)| !broadcast_txs.contains(hash))
                                .collect();

                            // Extract data for broadcast and mark as broadcast
                            let new_txs: Vec<Vec<u8>> = new_tx_pairs
                                .iter()
                                .map(|(hash, data)| {
                                    broadcast_txs.insert(*hash);
                                    data.clone()
                                })
                                .collect();

                            // Broadcast new transactions
                            if !new_txs.is_empty() {
                                let msg = TransactionMessage::new(new_txs.clone());
                                let encoded = msg.encode();

                                let failed = pq_handle_for_tx_prop
                                    .broadcast_to_all(TRANSACTIONS_PROTOCOL, encoded)
                                    .await;

                                tracing::info!(
                                    tx_count = new_txs.len(),
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
                let sync_service_for_import = Arc::clone(&sync_service);
                let da_chunk_store_for_import = Arc::clone(&da_chunk_store);
                let commitment_block_proof_store_for_import =
                    Arc::clone(&commitment_block_proof_store);
                let da_request_tracker_for_import = Arc::clone(&da_request_tracker);
                let da_params_for_import = da_params;
                let da_sample_timeout_for_import = da_sample_timeout;
                let da_sampling_secret_for_import = da_sampling_secret;
                let pq_handle_for_da_import = pq_handle_for_da_import.clone();

                task_manager.spawn_handle().spawn(
                    "block-import-handler",
                    Some("consensus"),
                    async move {
                        use sc_consensus::{BlockImport, BlockImportParams, ForkChoiceStrategy};
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
                            let mut deferred_blocks = Vec::new();

                            for downloaded in downloaded_blocks {
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
                                        tracing::debug!(
                                            peer = %hex::encode(&downloaded.from_peer),
                                            block_number,
                                            parent = %hex::encode(parent_hash.as_bytes()),
                                            "Deferring synced block until parent is available"
                                        );
                                        deferred_blocks.push(downloaded);
                                        continue;
                                    }
                                    Err(err) => {
                                        tracing::warn!(
                                            peer = %hex::encode(&downloaded.from_peer),
                                            block_number,
                                            parent = %hex::encode(parent_hash.as_bytes()),
                                            error = %err,
                                            "Failed to query parent header; deferring block"
                                        );
                                        deferred_blocks.push(downloaded);
                                        continue;
                                    }
                                }

                                let requires_sidecar = has_sidecar_transfers(&extrinsics);
                                let da_policy =
                                    fetch_da_policy(block_import_client.as_ref(), parent_hash);
                                let mut da_build = if requires_sidecar {
                                    let payload = match extract_commitment_proof_payload(&extrinsics) {
                                        Ok(Some(payload)) => payload,
                                        Ok(None) => {
                                            tracing::warn!(
                                                peer = %hex::encode(&downloaded.from_peer),
                                                block_number,
                                                "Rejecting synced block (missing commitment proof)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }
                                        Err(err) => {
                                            tracing::warn!(
                                                peer = %hex::encode(&downloaded.from_peer),
                                                block_number,
                                                error = %err,
                                                "Rejecting synced block (failed to parse commitment proof payload)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }
                                    };
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

                                let missing_proof_hashes = missing_proof_binding_hashes(&extrinsics);
                                let mut proof_da_build: Option<DaEncoding> = None;
                                let mut proof_store: Option<PendingProofStore> = None;

                                let mut commitment_block_proof = None;
                                if proof_verification_enabled {
                                    if !missing_proof_hashes.is_empty() {
                                        let policy = match fetch_proof_availability_policy(
                                            block_import_client.as_ref(),
                                            parent_hash,
                                        ) {
                                            Ok(policy) => policy,
                                            Err(err) => {
                                                if err.contains("UnknownBlock") {
                                                    tracing::debug!(
                                                        peer = %hex::encode(&downloaded.from_peer),
                                                        block_number,
                                                        parent = %hex::encode(parent_hash.as_bytes()),
                                                        error = %err,
                                                        "Deferring synced block (parent state not ready for proof availability policy)"
                                                    );
                                                    deferred_blocks.push(downloaded);
                                                    continue;
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
                                            pallet_shielded_pool::types::ProofAvailabilityPolicy::DaRequired
                                        ) {
                                            tracing::warn!(
                                                peer = %hex::encode(&downloaded.from_peer),
                                                block_number,
                                                policy = ?policy,
                                                "Rejecting synced block (missing proof bytes but proofs not allowed in DA)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }

                                        let payload = match extract_proof_da_commitment_payload(
                                            &extrinsics,
                                        ) {
                                            Ok(Some(payload)) => payload,
                                            Ok(None) => {
                                                tracing::warn!(
                                                    peer = %hex::encode(&downloaded.from_peer),
                                                    block_number,
                                                    "Rejecting synced block (missing submit_proof_da_commitment)"
                                                );
                                                blocks_failed += 1;
                                                continue;
                                            }
                                            Err(err) => {
                                                tracing::warn!(
                                                    peer = %hex::encode(&downloaded.from_peer),
                                                    block_number,
                                                    error = %err,
                                                    "Rejecting synced block (failed to parse submit_proof_da_commitment payload)"
                                                );
                                                blocks_failed += 1;
                                                continue;
                                            }
                                        };

                                        let manifest_payload = match extract_proof_da_manifest_payload(&extrinsics) {
                                            Ok(Some(payload)) => payload,
                                            Ok(None) => {
                                                tracing::warn!(
                                                    peer = %hex::encode(&downloaded.from_peer),
                                                    block_number,
                                                    "Rejecting synced block (missing submit_proof_da_manifest)"
                                                );
                                                blocks_failed += 1;
                                                continue;
                                            }
                                            Err(err) => {
                                                tracing::warn!(
                                                    peer = %hex::encode(&downloaded.from_peer),
                                                    block_number,
                                                    error = %err,
                                                    "Rejecting synced block (failed to parse submit_proof_da_manifest payload)"
                                                );
                                                blocks_failed += 1;
                                                continue;
                                            }
                                        };

                                        let mut manifest_map: HashMap<
                                            [u8; 64],
                                            pallet_shielded_pool::types::ProofDaManifestEntry,
                                        > = HashMap::new();
                                        let mut duplicate = None;
                                        for entry in manifest_payload.manifest {
                                            let binding_hash = entry.binding_hash.data;
                                            if manifest_map
                                                .insert(binding_hash, entry)
                                                .is_some()
                                            {
                                                duplicate = Some(binding_hash);
                                                break;
                                            }
                                        }
                                        if let Some(binding_hash) = duplicate {
                                            tracing::warn!(
                                                peer = %hex::encode(&downloaded.from_peer),
                                                block_number,
                                                binding_hash = %hex::encode(binding_hash),
                                                "Rejecting synced block (duplicate binding hash in proof DA manifest)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }

                                        let mut store =
                                            PendingProofStore::new(missing_proof_hashes.len());
                                        let mut chunk_cache: HashMap<u32, DaChunkProof> =
                                            HashMap::new();
                                        let mut missing = None;
                                        let mut fetch_failed: Option<([u8; 64], String)> = None;
                                        for binding_hash in &missing_proof_hashes {
                                            let entry = match manifest_map.get(binding_hash) {
                                                Some(entry) => entry,
                                                None => {
                                                    missing = Some(*binding_hash);
                                                    break;
                                                }
                                            };

                                            match fetch_proof_da_entry_with_cache(
                                                downloaded.from_peer,
                                                payload.da_root,
                                                payload.da_chunk_count,
                                                da_params_for_import,
                                                &pq_handle_for_da_import,
                                                &da_request_tracker_for_import,
                                                da_sample_timeout_for_import,
                                                entry,
                                                &mut chunk_cache,
                                            )
                                            .await
                                            {
                                                Ok(bytes) => store.insert(*binding_hash, bytes),
                                                Err(err) => {
                                                    fetch_failed = Some((*binding_hash, err));
                                                    break;
                                                }
                                            }
                                        }

                                        if let Some(binding_hash) = missing {
                                            tracing::warn!(
                                                peer = %hex::encode(&downloaded.from_peer),
                                                block_number,
                                                binding_hash = %hex::encode(binding_hash),
                                                "Rejecting synced block (proof DA manifest missing binding hash entry)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }

                                        if let Some((binding_hash, err)) = fetch_failed {
                                            tracing::warn!(
                                                peer = %hex::encode(&downloaded.from_peer),
                                                block_number,
                                                binding_hash = %hex::encode(binding_hash),
                                                error = %err,
                                                "Rejecting synced block (proof DA fetch failed)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }

                                        proof_store = Some(store);
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
                                        proof_store.as_ref(),
                                    ) {
                                        Ok(proof) => proof,
                                        Err(err) => {
                                            if err.contains("UnknownBlock") {
                                                tracing::debug!(
                                                    peer = %hex::encode(&downloaded.from_peer),
                                                    block_number,
                                                    parent = %hex::encode(parent_hash.as_bytes()),
                                                    error = %err,
                                                    "Deferring synced block (parent state not ready)"
                                                );
                                                deferred_blocks.push(downloaded);
                                                continue;
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
                                // This is what Blake3Algorithm::verify will use to validate the PoW
                                let pre_hash = header.hash();
                                tracing::info!(
                                    block_number,
                                    pre_hash = %hex::encode(pre_hash.as_bytes()),
                                    post_hash = %hex::encode(post_hash.as_bytes()),
                                    digest_logs_after_pop = header.digest().logs().len(),
                                    "🔍 DEBUG: Pre-hash computed after stripping seal"
                                );

                                // Construct BlockImportParams with seal in post_digests
                                let mut import_params = BlockImportParams::new(BlockOrigin::NetworkInitialSync, header);
                                import_params.body = Some(extrinsics);
                                import_params.fork_choice = Some(ForkChoiceStrategy::LongestChain);
                                import_params.post_digests.push(seal_item);
                                import_params.post_hash = Some(post_hash);

                                // Add PowIntermediate - difficulty will be computed from parent
                                // PowBlockImport::import_block requires this intermediate with key "pow1"
                                // Setting difficulty to None causes it to be queried from the algorithm
                                use sc_consensus_pow::{PowIntermediate, INTERMEDIATE_KEY};
                                let intermediate = PowIntermediate::<sp_core::U256> {
                                    difficulty: None, // Will be computed by algorithm.difficulty(parent_hash)
                                };
                                import_params.insert_intermediate(INTERMEDIATE_KEY, intermediate);

                                // Import through PowBlockImport (verifies PoW seal)
                                let import_result = block_import_pow.clone().import_block(import_params).await;

                                match import_result {
                                    Ok(sc_consensus::ImportResult::Imported(_)) => {
                                        blocks_imported += 1;
                                        sync_blocks_imported += 1;
                                        if da_build.is_some() || proof_da_build.is_some() {
                                            let mut store = da_chunk_store_for_import.lock();

                                            if let Some(build) = da_build.take() {
                                                let da_root = build.encoding.root();
                                                let da_chunks = build.encoding.chunks().len();
                                                let ciphertexts = flatten_ciphertexts(&build.transactions);
                                                let ciphertext_count = ciphertexts.len();
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

                                            if let Some(encoding) = proof_da_build.take() {
                                                let da_root = encoding.root();
                                                let da_chunks = encoding.chunks().len();
                                                if let Err(err) = store.insert(
                                                    DaRootKind::Proofs,
                                                    block_number as u64,
                                                    block_hash,
                                                    encoding,
                                                ) {
                                                    tracing::warn!(
                                                        block_number,
                                                        da_root = %hex::encode(da_root),
                                                        error = %err,
                                                        "Failed to persist proof DA encoding for synced block"
                                                    );
                                                } else {
                                                    tracing::info!(
                                                        block_number,
                                                        da_root = %hex::encode(da_root),
                                                        da_chunks,
                                                        "Proof DA encoding stored for synced block"
                                                    );
                                                }
                                            }
                                        }

                                        // Notify sync service of successful import
                                        {
                                            let mut sync = sync_service_for_import.lock().await;
                                            sync.on_block_imported(block_number as u64);
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
                                        if da_build.is_some() || proof_da_build.is_some() {
                                            let mut store = da_chunk_store_for_import.lock();

                                            if let Some(build) = da_build.take() {
                                                let da_root = build.encoding.root();
                                                let da_chunks = build.encoding.chunks().len();
                                                let ciphertexts = flatten_ciphertexts(&build.transactions);
                                                let ciphertext_count = ciphertexts.len();
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
                                            }

                                            if let Some(encoding) = proof_da_build.take() {
                                                let da_root = encoding.root();
                                                let da_chunks = encoding.chunks().len();
                                                if let Err(err) = store.insert(
                                                    DaRootKind::Proofs,
                                                    block_number as u64,
                                                    block_hash,
                                                    encoding,
                                                ) {
                                                    tracing::warn!(
                                                        block_number,
                                                        da_root = %hex::encode(da_root),
                                                        error = %err,
                                                        "Failed to persist proof DA encoding for known synced block"
                                                    );
                                                } else {
                                                    tracing::info!(
                                                        block_number,
                                                        da_root = %hex::encode(da_root),
                                                        da_chunks,
                                                        "Proof DA encoding stored for known synced block"
                                                    );
                                                }
                                            }
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
                                        tracing::debug!(
                                            block_number,
                                            parent = %hex::encode(parent_hash.as_bytes()),
                                            "Synced block has unknown parent - out of order?"
                                        );
                                    }
                                    Ok(sc_consensus::ImportResult::MissingState) => {
                                        blocks_failed += 1;
                                        tracing::warn!(
                                            block_number,
                                            "Missing state for synced block parent"
                                        );
                                    }
                                    Err(e) => {
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

                            if !deferred_blocks.is_empty() {
                                let mut sync = sync_service_for_import.lock().await;
                                sync.requeue_downloaded(deferred_blocks);
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

                                // Only process blocks that have a body (full blocks)
                                let body = match &announce.body {
                                    Some(body) => body.clone(),
                                    None => {
                                        // Header-only announcement - the sync service was already
                                        // notified above, so it can request the full block
                                        tracing::trace!(
                                            peer = %hex::encode(&peer_id),
                                            block_number = announce.number,
                                            "Header-only announcement - sync service notified"
                                        );
                                        continue;
                                    }
                                };

                                // Decode the header
                                let header = match runtime::Header::decode(&mut &announce.header[..]) {
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
                                let block_number = *header.number();
                                let parent_hash = *header.parent_hash();
                                let mut block_hash_bytes = [0u8; 32];
                                block_hash_bytes.copy_from_slice(block_hash.as_bytes());

                                let requires_sidecar = has_sidecar_transfers(&extrinsics);
                                let da_policy =
                                    fetch_da_policy(block_import_client.as_ref(), parent_hash);
                                let mut da_build = if requires_sidecar {
                                    let payload = match extract_commitment_proof_payload(&extrinsics) {
                                        Ok(Some(payload)) => payload,
                                        Ok(None) => {
                                            tracing::warn!(
                                                peer = %hex::encode(&peer_id),
                                                block_number,
                                                "Rejecting announced block (missing commitment proof)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }
                                        Err(err) => {
                                            tracing::warn!(
                                                peer = %hex::encode(&peer_id),
                                                block_number,
                                                error = %err,
                                                "Rejecting announced block (failed to parse commitment proof payload)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }
                                    };
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

                                let missing_proof_hashes = missing_proof_binding_hashes(&extrinsics);
                                let mut proof_da_build: Option<DaEncoding> = None;
                                let mut proof_store: Option<PendingProofStore> = None;

                                let mut commitment_block_proof = None;
                                if proof_verification_enabled {
                                    if !missing_proof_hashes.is_empty() {
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
                                            pallet_shielded_pool::types::ProofAvailabilityPolicy::DaRequired
                                        ) {
                                            tracing::warn!(
                                                peer = %hex::encode(&peer_id),
                                                block_number,
                                                policy = ?policy,
                                                "Rejecting announced block (missing proof bytes but proofs not allowed in DA)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }

                                        let payload = match extract_proof_da_commitment_payload(
                                            &extrinsics,
                                        ) {
                                            Ok(Some(payload)) => payload,
                                            Ok(None) => {
                                                tracing::warn!(
                                                    peer = %hex::encode(&peer_id),
                                                    block_number,
                                                    "Rejecting announced block (missing submit_proof_da_commitment)"
                                                );
                                                blocks_failed += 1;
                                                continue;
                                            }
                                            Err(err) => {
                                                tracing::warn!(
                                                    peer = %hex::encode(&peer_id),
                                                    block_number,
                                                    error = %err,
                                                    "Rejecting announced block (failed to parse submit_proof_da_commitment payload)"
                                                );
                                                blocks_failed += 1;
                                                continue;
                                            }
                                        };

                                        let manifest_payload = match extract_proof_da_manifest_payload(&extrinsics) {
                                            Ok(Some(payload)) => payload,
                                            Ok(None) => {
                                                tracing::warn!(
                                                    peer = %hex::encode(&peer_id),
                                                    block_number,
                                                    "Rejecting announced block (missing submit_proof_da_manifest)"
                                                );
                                                blocks_failed += 1;
                                                continue;
                                            }
                                            Err(err) => {
                                                tracing::warn!(
                                                    peer = %hex::encode(&peer_id),
                                                    block_number,
                                                    error = %err,
                                                    "Rejecting announced block (failed to parse submit_proof_da_manifest payload)"
                                                );
                                                blocks_failed += 1;
                                                continue;
                                            }
                                        };

                                        let mut manifest_map: HashMap<
                                            [u8; 64],
                                            pallet_shielded_pool::types::ProofDaManifestEntry,
                                        > = HashMap::new();
                                        let mut duplicate = None;
                                        for entry in manifest_payload.manifest {
                                            let binding_hash = entry.binding_hash.data;
                                            if manifest_map.insert(binding_hash, entry).is_some() {
                                                duplicate = Some(binding_hash);
                                                break;
                                            }
                                        }
                                        if let Some(binding_hash) = duplicate {
                                            tracing::warn!(
                                                peer = %hex::encode(&peer_id),
                                                block_number,
                                                binding_hash = %hex::encode(binding_hash),
                                                "Rejecting announced block (duplicate binding hash in proof DA manifest)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }

                                        let mut store =
                                            PendingProofStore::new(missing_proof_hashes.len());
                                        let mut chunk_cache: HashMap<u32, DaChunkProof> =
                                            HashMap::new();
                                        let mut missing = None;
                                        let mut fetch_failed: Option<([u8; 64], String)> = None;
                                        for binding_hash in &missing_proof_hashes {
                                            let entry = match manifest_map.get(binding_hash) {
                                                Some(entry) => entry,
                                                None => {
                                                    missing = Some(*binding_hash);
                                                    break;
                                                }
                                            };

                                            match fetch_proof_da_entry_with_cache(
                                                peer_id,
                                                payload.da_root,
                                                payload.da_chunk_count,
                                                da_params_for_import,
                                                &pq_handle_for_da_import,
                                                &da_request_tracker_for_import,
                                                da_sample_timeout_for_import,
                                                entry,
                                                &mut chunk_cache,
                                            )
                                            .await
                                            {
                                                Ok(bytes) => store.insert(*binding_hash, bytes),
                                                Err(err) => {
                                                    fetch_failed = Some((*binding_hash, err));
                                                    break;
                                                }
                                            }
                                        }

                                        if let Some(binding_hash) = missing {
                                            tracing::warn!(
                                                peer = %hex::encode(&peer_id),
                                                block_number,
                                                binding_hash = %hex::encode(binding_hash),
                                                "Rejecting announced block (proof DA manifest missing binding hash entry)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }

                                        if let Some((binding_hash, err)) = fetch_failed {
                                            tracing::warn!(
                                                peer = %hex::encode(&peer_id),
                                                block_number,
                                                binding_hash = %hex::encode(binding_hash),
                                                error = %err,
                                                "Rejecting announced block (proof DA fetch failed)"
                                            );
                                            blocks_failed += 1;
                                            continue;
                                        }

                                        proof_store = Some(store);
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
                                        proof_store.as_ref(),
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
                                let mut import_params = BlockImportParams::new(BlockOrigin::NetworkBroadcast, header_mut);
                                import_params.body = Some(extrinsics);
                                import_params.fork_choice = Some(ForkChoiceStrategy::LongestChain);
                                import_params.post_digests.push(seal_item);
                                import_params.post_hash = Some(post_hash);

                                // Add PowIntermediate - difficulty will be computed from parent
                                use sc_consensus_pow::{PowIntermediate, INTERMEDIATE_KEY};
                                let intermediate = PowIntermediate::<sp_core::U256> {
                                    difficulty: None, // Will be computed by algorithm.difficulty(parent_hash)
                                };
                                import_params.insert_intermediate(INTERMEDIATE_KEY, intermediate);

                                // Import through PowBlockImport (verifies PoW seal)
                                let import_result = block_import_pow.clone().import_block(import_params).await;

                                match import_result {
                                    Ok(sc_consensus::ImportResult::Imported(_)) => {
                                        blocks_imported += 1;
                                        if da_build.is_some() || proof_da_build.is_some() {
                                            let mut store = da_chunk_store_for_import.lock();

                                            if let Some(build) = da_build.take() {
                                                let da_root = build.encoding.root();
                                                let da_chunks = build.encoding.chunks().len();
                                                let ciphertexts = flatten_ciphertexts(&build.transactions);
                                                let ciphertext_count = ciphertexts.len();
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
                                            }

                                            if let Some(encoding) = proof_da_build.take() {
                                                let da_root = encoding.root();
                                                let da_chunks = encoding.chunks().len();
                                                if let Err(err) = store.insert(
                                                    DaRootKind::Proofs,
                                                    block_number as u64,
                                                    block_hash_bytes,
                                                    encoding,
                                                ) {
                                                    tracing::warn!(
                                                        block_number,
                                                        da_root = %hex::encode(da_root),
                                                        error = %err,
                                                        "Failed to persist proof DA encoding for announced block"
                                                    );
                                                } else {
                                                    tracing::info!(
                                                        block_number,
                                                        da_root = %hex::encode(da_root),
                                                        da_chunks,
                                                        "Proof DA encoding stored for announced block"
                                                    );
                                                }
                                            }
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
                                        if da_build.is_some() || proof_da_build.is_some() {
                                            let mut store = da_chunk_store_for_import.lock();

                                            if let Some(build) = da_build.take() {
                                                let da_root = build.encoding.root();
                                                let da_chunks = build.encoding.chunks().len();
                                                let ciphertexts = flatten_ciphertexts(&build.transactions);
                                                let ciphertext_count = ciphertexts.len();
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
                                            }

                                            if let Some(encoding) = proof_da_build.take() {
                                                let da_root = encoding.root();
                                                let da_chunks = encoding.chunks().len();
                                                if let Err(err) = store.insert(
                                                    DaRootKind::Proofs,
                                                    block_number as u64,
                                                    block_hash_bytes,
                                                    encoding,
                                                ) {
                                                    tracing::warn!(
                                                        block_number,
                                                        da_root = %hex::encode(da_root),
                                                        error = %err,
                                                        "Failed to persist proof DA encoding for known announced block"
                                                    );
                                                } else {
                                                    tracing::info!(
                                                        block_number,
                                                        da_root = %hex::encode(da_root),
                                                        da_chunks,
                                                        "Proof DA encoding stored for known announced block"
                                                    );
                                                }
                                            }
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
        // Wire pending_txs_fn to transaction pool
        // =======================================================================
        // For now, use the pool bridge which collects from network
        // Full integration would use transaction_pool.ready() directly
        let pool_for_mining = Arc::clone(&pool_bridge);
        let max_block_txs = production_config.max_block_transactions;
        chain_state.set_pending_txs_fn(move || pool_for_mining.ready_for_block(max_block_txs));

        // Wire post-import callback to clear mined transactions
        let pool_for_import = Arc::clone(&pool_bridge);
        chain_state.set_on_import_success_fn(move |included_txs: &[Vec<u8>]| {
            pool_for_import.clear_included(included_txs);
        });

        tracing::info!(
            max_block_transactions = max_block_txs,
            "Transaction pool wired to chain state provider"
        );

        // =======================================================================
        // Wire BlockBuilder API for real state execution
        // =======================================================================
        wire_block_builder_api(
            &chain_state,
            client.clone(),
            da_params,
            Arc::clone(&pending_ciphertext_store),
            Arc::clone(&pending_proof_store),
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
                    )
                    .with_sync_status(sync_status_for_mining);

                    worker.run().await;
                },
            );
        } else {
            let sync_status_for_mining = Arc::clone(&sync_status);
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
    let rpc_service = Arc::new(ProductionRpcService::new(
        client.clone(),
        Arc::clone(&peer_count),
        Arc::clone(&sync_status),
        Arc::clone(&da_chunk_store),
        Arc::clone(&pending_ciphertext_store),
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
                let result: Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned> =
                    Ok(serde_json::json!({
                        "methods": [
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
                            "author_hasKey",
                            "author_hasSessionKeys",
                            "author_insertKey",
                            "author_pendingExtrinsics",
                            "author_rotateKeys",
                            "author_submitAndWatchExtrinsic",
                            "author_submitExtrinsic",
                            "author_unwatchExtrinsic",
                            "block_getCommitmentProof",
                            "da_getChunk",
                            "da_getParams",
                            "archive_listProviders",
                            "archive_getProvider",
                            "archive_providerCount",
                            "archive_listContracts",
                            "archive_getContract",
                            "rpc_methods"
                        ]
                    }));
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

        // =====================================================================
        // Author RPC (author_submitExtrinsic, author_pendingExtrinsics)
        // =====================================================================

        // Add Author RPC for transaction submission
        use sc_rpc::author::{Author, AuthorApiServer};

        let author_rpc = Author::new(
            client.clone(),
            transaction_pool.clone(),
            keystore_container.keystore(),
            executor.clone(),
        );
        if let Err(e) = module.merge(author_rpc.into_rpc()) {
            tracing::warn!(error = %e, "Failed to merge Author RPC");
        } else {
            tracing::info!(
                "Author RPC wired (author_submitExtrinsic, author_pendingExtrinsics, etc.)"
            );
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

                // Convert 32-byte PQ peer ID to libp2p-compatible multihash PeerId
                // Format: 0x00 (identity) + 0x24 (36 bytes: 4-byte prefix + 32-byte key) + data
                // The ed25519 public key multihash prefix is 0x08 0x01 0x12 0x20
                fn pq_peer_id_to_libp2p(id: &[u8; 32]) -> String {
                    // Build multihash: identity(0x00) + length + ed25519-pub prefix + key
                    // Ed25519 public key multicodec: 0xed (in varint = 0xed 0x01)
                    // But libp2p uses protobuf encoding for keys in PeerId
                    // Simpler: use identity multihash with raw 32 bytes
                    // 0x00 = identity hash, 0x20 = 32 bytes length
                    let mut multihash = vec![0x00, 0x24]; // identity + 36 bytes
                                                          // Add ed25519 public key protobuf prefix (type=1, length=32)
                    multihash.extend_from_slice(&[0x08, 0x01, 0x12, 0x20]);
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
                .map(|addr| addr.to_string())
                .collect(),
            pq_verbose: pq_service_config.verbose_logging,
            max_peers: pq_service_config.max_peers as u32,
        };

        // Add Hegemon RPC (mining, consensus, telemetry)
        let hegemon_rpc = HegemonRpc::new(rpc_service.clone(), pow_handle.clone(), config_snapshot);
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

        // Add Archive RPC (provider registry)
        let archive_rpc = ArchiveRpc::new(rpc_service);
        if let Err(e) = module.merge(archive_rpc.into_rpc()) {
            tracing::warn!(error = %e, "Failed to merge Archive RPC");
        } else {
            tracing::info!("Archive RPC wired (archive_listProviders, archive_getProvider)");
        }

        module
    };

    // Spawn RPC server task
    let rpc_handle = task_manager.spawn_handle();
    rpc_handle.spawn("hegemon-rpc-server", Some("rpc"), async move {
        let addr = rpc_listen_addr;

        // Create HTTP middleware
        // Note: DenyUnsafe is injected via extension middleware below
        let http_middleware = tower::ServiceBuilder::new();

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

    fn unsigned_extrinsic(call: ShieldedPoolCall) -> runtime::UncheckedExtrinsic {
        runtime::UncheckedExtrinsic::new_unsigned(runtime::RuntimeCall::ShieldedPool(call))
    }

    fn missing_proof_transfer(binding_hash: [u8; 64]) -> runtime::UncheckedExtrinsic {
        unsigned_extrinsic(ShieldedPoolCall::shielded_transfer_sidecar {
            proof: pallet_shielded_pool::types::StarkProof { data: Vec::new() },
            nullifiers: Default::default(),
            commitments: Default::default(),
            ciphertext_hashes: Default::default(),
            ciphertext_sizes: Default::default(),
            anchor: [0u8; 48],
            binding_hash: pallet_shielded_pool::types::BindingHash { data: binding_hash },
            stablecoin: None,
            fee: 0,
            value_balance: 0,
        })
    }

    fn proof_da_commitment(chunk_count: u32) -> runtime::UncheckedExtrinsic {
        unsigned_extrinsic(ShieldedPoolCall::submit_proof_da_commitment {
            da_root: [9u8; 48],
            chunk_count,
        })
    }

    fn proof_da_manifest(
        entries: Vec<pallet_shielded_pool::types::ProofDaManifestEntry>,
    ) -> runtime::UncheckedExtrinsic {
        let manifest: sp_runtime::BoundedVec<
            pallet_shielded_pool::types::ProofDaManifestEntry,
            runtime::MaxProofDaManifestEntries,
        > = sp_runtime::BoundedVec::truncate_from(entries);
        unsigned_extrinsic(ShieldedPoolCall::submit_proof_da_manifest { manifest })
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
        let a = pallet_shielded_pool::types::ProofDaManifestEntry {
            binding_hash: pallet_shielded_pool::types::BindingHash { data: [1u8; 64] },
            proof_hash: [0u8; 48],
            proof_len: 10,
            proof_offset: 72,
        };
        let b = pallet_shielded_pool::types::ProofDaManifestEntry {
            binding_hash: pallet_shielded_pool::types::BindingHash { data: [2u8; 64] },
            proof_hash: [0u8; 48],
            proof_len: 5,
            proof_offset: 150,
        };
        let len = proof_da_blob_len_from_manifest(&[a, b]).expect("len");
        assert_eq!(len, 155);
    }

    #[test]
    fn validate_proof_da_rejects_commitment_without_missing_proofs() {
        let da_params = DaParams {
            chunk_size: 1024,
            sample_count: 1,
        };
        let err =
            validate_proof_da_payloads(&[proof_da_commitment(2)], da_params).expect_err("reject");
        assert!(err.contains("no missing proof bytes"), "{err}");
    }

    #[test]
    fn validate_proof_da_rejects_missing_commitment() {
        let da_params = DaParams {
            chunk_size: 1024,
            sample_count: 1,
        };
        let binding_hash = [7u8; 64];
        let entry = pallet_shielded_pool::types::ProofDaManifestEntry {
            binding_hash: pallet_shielded_pool::types::BindingHash { data: binding_hash },
            proof_hash: [0u8; 48],
            proof_len: 10,
            proof_offset: 72,
        };
        let extrinsics = vec![
            missing_proof_transfer(binding_hash),
            proof_da_manifest(vec![entry]),
        ];
        let err = validate_proof_da_payloads(&extrinsics, da_params).expect_err("reject");
        assert!(err.contains("missing submit_proof_da_commitment"), "{err}");
    }

    #[test]
    fn validate_proof_da_rejects_missing_manifest() {
        let da_params = DaParams {
            chunk_size: 1024,
            sample_count: 1,
        };
        let binding_hash = [7u8; 64];
        let extrinsics = vec![missing_proof_transfer(binding_hash), proof_da_commitment(2)];
        let err = validate_proof_da_payloads(&extrinsics, da_params).expect_err("reject");
        assert!(err.contains("missing submit_proof_da_manifest"), "{err}");
    }

    #[test]
    fn validate_proof_da_rejects_chunk_count_mismatch() {
        let da_params = DaParams {
            chunk_size: 1024,
            sample_count: 1,
        };
        let binding_hash = [7u8; 64];
        let entry = pallet_shielded_pool::types::ProofDaManifestEntry {
            binding_hash: pallet_shielded_pool::types::BindingHash { data: binding_hash },
            proof_hash: [0u8; 48],
            proof_len: 10,
            proof_offset: 72,
        };
        let extrinsics = vec![
            missing_proof_transfer(binding_hash),
            proof_da_commitment(3),
            proof_da_manifest(vec![entry]),
        ];
        let err = validate_proof_da_payloads(&extrinsics, da_params).expect_err("reject");
        assert!(err.contains("da_chunk_count mismatch"), "{err}");
    }

    #[test]
    fn validate_proof_da_rejects_manifest_missing_binding_hash() {
        let da_params = DaParams {
            chunk_size: 1024,
            sample_count: 1,
        };
        let binding_hash = [7u8; 64];
        let manifest_hash = [8u8; 64];
        let entry = pallet_shielded_pool::types::ProofDaManifestEntry {
            binding_hash: pallet_shielded_pool::types::BindingHash {
                data: manifest_hash,
            },
            proof_hash: [0u8; 48],
            proof_len: 10,
            proof_offset: 72,
        };
        let extrinsics = vec![
            missing_proof_transfer(binding_hash),
            proof_da_commitment(2),
            proof_da_manifest(vec![entry]),
        ];
        let err = validate_proof_da_payloads(&extrinsics, da_params).expect_err("reject");
        assert!(err.contains("manifest missing binding hash entry"), "{err}");
    }

    #[test]
    fn validate_proof_da_rejects_duplicate_manifest_binding_hash() {
        let da_params = DaParams {
            chunk_size: 1024,
            sample_count: 1,
        };
        let binding_hash = [7u8; 64];
        let entry_a = pallet_shielded_pool::types::ProofDaManifestEntry {
            binding_hash: pallet_shielded_pool::types::BindingHash { data: binding_hash },
            proof_hash: [0u8; 48],
            proof_len: 10,
            proof_offset: 72,
        };
        let entry_b = pallet_shielded_pool::types::ProofDaManifestEntry {
            binding_hash: pallet_shielded_pool::types::BindingHash { data: binding_hash },
            proof_hash: [0u8; 48],
            proof_len: 5,
            proof_offset: 150,
        };
        let extrinsics = vec![
            missing_proof_transfer(binding_hash),
            proof_da_commitment(2),
            proof_da_manifest(vec![entry_a, entry_b]),
        ];
        let err = validate_proof_da_payloads(&extrinsics, da_params).expect_err("reject");
        assert!(err.contains("duplicate binding hash"), "{err}");
    }

    #[test]
    fn validate_proof_da_rejects_duplicate_commitment_extrinsic() {
        let da_params = DaParams {
            chunk_size: 1024,
            sample_count: 1,
        };
        let binding_hash = [7u8; 64];
        let entry = pallet_shielded_pool::types::ProofDaManifestEntry {
            binding_hash: pallet_shielded_pool::types::BindingHash { data: binding_hash },
            proof_hash: [0u8; 48],
            proof_len: 10,
            proof_offset: 72,
        };
        let extrinsics = vec![
            missing_proof_transfer(binding_hash),
            proof_da_commitment(2),
            proof_da_commitment(2),
            proof_da_manifest(vec![entry]),
        ];
        let err = validate_proof_da_payloads(&extrinsics, da_params).expect_err("reject");
        assert!(err.contains("multiple submit_proof_da_commitment"), "{err}");
    }

    #[test]
    fn validate_proof_da_rejects_duplicate_manifest_extrinsic() {
        let da_params = DaParams {
            chunk_size: 1024,
            sample_count: 1,
        };
        let binding_hash = [7u8; 64];
        let entry = pallet_shielded_pool::types::ProofDaManifestEntry {
            binding_hash: pallet_shielded_pool::types::BindingHash { data: binding_hash },
            proof_hash: [0u8; 48],
            proof_len: 10,
            proof_offset: 72,
        };
        let extrinsics = vec![
            missing_proof_transfer(binding_hash),
            proof_da_commitment(2),
            proof_da_manifest(vec![entry.clone()]),
            proof_da_manifest(vec![entry]),
        ];
        let err = validate_proof_da_payloads(&extrinsics, da_params).expect_err("reject");
        assert!(err.contains("multiple submit_proof_da_manifest"), "{err}");
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

        let verify_pow = std::env::var("HEGEMON_VERIFY_POW")
            .map(|v| v != "0" && v.to_lowercase() != "false")
            .unwrap_or(true);

        let verbose = std::env::var("HEGEMON_IMPORT_VERBOSE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        Self {
            enabled,
            verify_pow,
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
    ) -> impl Fn(&crate::substrate::mining_worker::BlockTemplate, &Blake3Seal) -> Result<H256, String>
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
                    nonce = seal.nonce,
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
        let seal = Blake3Seal {
            nonce: 12345,
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
        let seal = Blake3Seal {
            nonce: 0,
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
}
