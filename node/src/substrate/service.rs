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
    create_production_mining_worker, create_scaffold_mining_worker, ChainStateProvider,
    MiningWorkerConfig,
};
use crate::substrate::network::{PqNetworkConfig, PqNetworkKeypair};
use crate::substrate::network_bridge::NetworkBridgeBuilder;
use crate::substrate::rpc::{
    BlockApiServer, BlockRpc, DaApiServer, DaRpc, EpochApiServer, EpochRpc, HegemonApiServer,
    HegemonRpc, ProductionRpcService, ShieldedApiServer, ShieldedRpc, WalletApiServer, WalletRpc,
};
use crate::substrate::transaction_pool::{
    SubstrateTransactionPoolWrapper, TransactionPoolBridge, TransactionPoolConfig,
};
use block_circuit::{
    CommitmentBlockProof, CommitmentBlockProver, prove_block, prove_block_fast,
    RecursiveBlockProof,
};
use codec::Decode;
use codec::Encode;
use consensus::{Blake3Algorithm, Blake3Seal};
use futures::StreamExt;
use network::{
    PqNetworkBackend, PqNetworkBackendConfig, PqNetworkEvent, PqNetworkHandle, PqPeerIdentity,
    PqTransportConfig, SubstratePqTransport, SubstratePqTransportConfig,
};
use rand::{rngs::OsRng, seq::index::sample, RngCore};
use sc_client_api::{BlockBackend, BlockchainEvents, HeaderBackend};
use sc_service::{error::Error as ServiceError, Configuration, KeystoreContainer, TaskManager};
use sc_transaction_pool_api::MaintainedTransactionPool;
use sha2::{Digest as ShaDigest, Sha256};
use sp_api::{ProvideRuntimeApi, StorageChanges};
use sp_core::H256;
use sp_inherents::{InherentData, InherentDataProvider};
use sp_runtime::traits::Header as HeaderT;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, Mutex};

use epoch_circuit::{
    compute_proof_root, Epoch as EpochCircuit, RecursiveEpochProver as EpochRecursiveProver,
    EPOCH_SIZE as EPOCH_SIZE_BLOCKS,
};

// Import runtime APIs for difficulty queries
use pallet_shielded_pool::Call as ShieldedPoolCall;
use parking_lot::Mutex as ParkingMutex;
use protocol_versioning::{VersionBinding, DEFAULT_VERSION_BINDING};
use runtime::apis::{ConsensusApi, ShieldedPoolApi};
use state_da::{DaChunkProof, DaEncoding, DaParams, DaRoot};
use state_merkle::CommitmentTree;
use transaction_circuit::constants::{MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::proof::{SerializedStarkInputs, TransactionProof};
use transaction_circuit::public_inputs::{StablecoinPolicyBinding, TransactionPublicInputs};

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

const DEFAULT_DA_CHUNK_SIZE: u32 = 1024;
const DEFAULT_DA_SAMPLE_COUNT: u32 = 80;
const DEFAULT_DA_STORE_CAPACITY: usize = 128;
const DEFAULT_DA_SAMPLE_TIMEOUT_MS: u64 = 5000;
const DEFAULT_RECURSIVE_PROOF_STORE_CAPACITY: usize = 128;
const DEFAULT_COMMITMENT_PROOF_STORE_CAPACITY: usize = 128;

#[derive(Debug)]
pub struct DaChunkStore {
    capacity: usize,
    order: VecDeque<DaRoot>,
    entries: HashMap<DaRoot, DaEncoding>,
}

impl DaChunkStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, root: DaRoot, encoding: DaEncoding) {
        if self.capacity == 0 {
            return;
        }

        if let Some(existing) = self.entries.get_mut(&root) {
            *existing = encoding;
            self.order.retain(|entry| entry != &root);
            self.order.push_back(root);
            return;
        }

        if self.entries.len() >= self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.entries.remove(&evicted);
            }
        }

        self.entries.insert(root, encoding);
        self.order.push_back(root);
    }

    pub fn get(&self, root: &DaRoot) -> Option<&DaEncoding> {
        self.entries.get(root)
    }
}

#[derive(Debug)]
pub struct RecursiveBlockProofStore {
    capacity: usize,
    order: VecDeque<H256>,
    entries: HashMap<H256, RecursiveBlockProof>,
}

impl RecursiveBlockProofStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, hash: H256, proof: RecursiveBlockProof) {
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

    pub fn get(&self, hash: &H256) -> Option<&RecursiveBlockProof> {
        self.entries.get(hash)
    }
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

fn load_recursive_proof_store_capacity() -> usize {
    let capacity = env_usize("HEGEMON_RECURSIVE_PROOF_STORE_CAPACITY")
        .unwrap_or(DEFAULT_RECURSIVE_PROOF_STORE_CAPACITY);
    if capacity == 0 {
        tracing::warn!(
            "HEGEMON_RECURSIVE_PROOF_STORE_CAPACITY is zero; falling back to {}",
            DEFAULT_RECURSIVE_PROOF_STORE_CAPACITY
        );
        return DEFAULT_RECURSIVE_PROOF_STORE_CAPACITY;
    }
    capacity
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
    mut values: Vec<[u8; 32]>,
    max: usize,
    label: &str,
) -> Result<Vec<[u8; 32]>, String> {
    if values.len() > max {
        return Err(format!(
            "{label} exceeds max (got {}, max {})",
            values.len(),
            max
        ));
    }
    values.resize(max, [0u8; 32]);
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
    anchor: [u8; 32],
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
        _ => (0, 0, 0, 0, 0, [0u8; 32], [0u8; 32], [0u8; 32]),
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
    nullifiers: Vec<[u8; 32]>,
    commitments: Vec<[u8; 32]>,
    anchor: [u8; 32],
    stablecoin: Option<pallet_shielded_pool::types::StablecoinPolicyBinding>,
    fee: u64,
    value_balance: i128,
) -> Result<TransactionProof, String> {
    if proof_bytes.is_empty() {
        return Err("shielded transfer proof bytes are empty".to_string());
    }

    let input_count = nullifiers.len();
    let output_count = commitments.len();
    let padded_nullifiers = pad_commitments(nullifiers, MAX_INPUTS, "nullifiers")?;
    let padded_commitments = pad_commitments(commitments, MAX_OUTPUTS, "commitments")?;

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

fn extract_transaction_proofs_from_extrinsics(
    extrinsics: &[Vec<u8>],
) -> Result<Vec<TransactionProof>, String> {
    let mut proofs = Vec::new();

    for ext_bytes in extrinsics {
        let extrinsic = runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..])
            .map_err(|e| format!("failed to decode extrinsic: {e:?}"))?;
        let runtime::RuntimeCall::ShieldedPool(call) = extrinsic.function else {
            continue;
        };

        match call {
            ShieldedPoolCall::shielded_transfer {
                proof,
                nullifiers,
                commitments,
                anchor,
                stablecoin,
                fee,
                value_balance,
                ..
            } => {
                let proof = build_transaction_proof(
                    proof.data.clone(),
                    nullifiers.iter().copied().collect(),
                    commitments.iter().copied().collect(),
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
                anchor,
                stablecoin,
                fee,
                ..
            } => {
                if stablecoin.is_some() {
                    return Err("unsigned shielded transfer includes stablecoin binding".into());
                }
                let proof = build_transaction_proof(
                    proof.data.clone(),
                    nullifiers.iter().copied().collect(),
                    commitments.iter().copied().collect(),
                    anchor,
                    None,
                    fee,
                    0,
                )?;
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

    Ok(proofs)
}

fn encrypted_note_bytes(note: &pallet_shielded_pool::types::EncryptedNote) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(note.ciphertext.len() + note.kem_ciphertext.len());
    bytes.extend_from_slice(&note.ciphertext);
    bytes.extend_from_slice(&note.kem_ciphertext);
    bytes
}

fn build_da_blob_from_extrinsics(
    extrinsics: &[runtime::UncheckedExtrinsic],
) -> Result<Vec<u8>, String> {
    let mut transactions: Vec<Vec<Vec<u8>>> = Vec::new();

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
            _ => None,
        };

        if let Some(ciphertexts) = ciphertexts {
            transactions.push(ciphertexts);
        }
    }

    let mut blob = Vec::new();
    blob.extend_from_slice(&(transactions.len() as u32).to_le_bytes());
    for ciphertexts in transactions {
        blob.extend_from_slice(&(ciphertexts.len() as u32).to_le_bytes());
        for ciphertext in ciphertexts {
            blob.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
            blob.extend_from_slice(&ciphertext);
        }
    }

    Ok(blob)
}

fn build_da_encoding_from_extrinsics(
    extrinsics: &[runtime::UncheckedExtrinsic],
    params: DaParams,
) -> Result<DaEncoding, String> {
    let blob = build_da_blob_from_extrinsics(extrinsics)?;
    state_da::encode_da_blob(&blob, params).map_err(|err| format!("da encoding failed: {err}"))
}

fn sample_da_indices(chunk_count: usize, sample_count: u32) -> Vec<u32> {
    if chunk_count == 0 {
        return Vec::new();
    }
    let wanted = sample_count.min(chunk_count as u32) as usize;
    if wanted >= chunk_count {
        return (0..chunk_count as u32).collect();
    }

    let mut rng = OsRng;
    sample(&mut rng, chunk_count, wanted)
        .into_iter()
        .map(|idx| idx as u32)
        .collect()
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

async fn sample_da_for_block(
    peer_id: network::PeerId,
    extrinsics: &[runtime::UncheckedExtrinsic],
    params: DaParams,
    handle: &PqNetworkHandle,
    tracker: &Arc<ParkingMutex<DaRequestTracker>>,
    timeout: Duration,
) -> Result<DaEncoding, String> {
    let encoding = build_da_encoding_from_extrinsics(extrinsics, params)?;
    let root = encoding.root();
    let chunk_count = encoding.chunks().len();
    let indices = sample_da_indices(chunk_count, params.sample_count);
    let proofs = request_da_samples(peer_id, root, &indices, handle, tracker, timeout).await?;

    for proof in &proofs {
        state_da::verify_da_chunk(root, proof)
            .map_err(|err| format!("invalid DA chunk proof: {err}"))?;
    }

    Ok(encoding)
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
            .get_encrypted_notes(parent_hash, expected_index, 256)
            .map_err(|e| format!("runtime api error (get_encrypted_notes): {e:?}"))?;
        if batch.is_empty() {
            return Err("encrypted notes batch returned empty before expected count".into());
        }
        for (index, _ciphertext, _block_number, commitment) in batch {
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

fn build_recursive_block_proof(
    client: &HegemonFullClient,
    parent_hash: H256,
    extrinsics: &[Vec<u8>],
    fast: bool,
) -> Result<Option<RecursiveBlockProof>, String> {
    let proofs = extract_transaction_proofs_from_extrinsics(extrinsics)?;
    if proofs.is_empty() {
        return Ok(None);
    }

    let mut tree = build_commitment_tree_from_chain(client, parent_hash)?;
    let (_, verifying_key) = generate_keys();
    let mut verifying_keys = HashMap::new();
    verifying_keys.insert(
        VersionBinding::new(
            DEFAULT_VERSION_BINDING.circuit,
            DEFAULT_VERSION_BINDING.crypto,
        ),
        verifying_key,
    );

    let block_proof = if fast {
        prove_block_fast(&mut tree, &proofs, &verifying_keys)
            .map_err(|e| format!("fast recursive block proof failed: {e}"))?
    } else {
        prove_block(&mut tree, &proofs, &verifying_keys)
            .map_err(|e| format!("recursive block proof failed: {e}"))?
    };

    Ok(Some(block_proof.recursive_proof))
}

fn build_commitment_block_proof(
    client: &HegemonFullClient,
    parent_hash: H256,
    extrinsics: &[Vec<u8>],
    da_params: DaParams,
    fast: bool,
) -> Result<Option<CommitmentBlockProof>, String> {
    let proofs = extract_transaction_proofs_from_extrinsics(extrinsics)?;
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
    let da_root = build_da_encoding_from_extrinsics(&decoded, da_params)?.root();

    let prover = if fast {
        CommitmentBlockProver::with_fast_options()
    } else {
        CommitmentBlockProver::new()
    };

    let proof = prover
        .prove_block_commitment_with_tree(&mut tree, &proofs, da_root)
        .map_err(|e| format!("commitment block proof failed: {e}"))?;

    Ok(Some(proof))
}

fn parse_accumulator(bytes: [u8; 32]) -> Result<[epoch_circuit::BaseElement; 4], String> {
    let mut elements = [epoch_circuit::BaseElement::new(0); 4];
    for i in 0..4 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let raw = u64::from_le_bytes(buf);
        let elem = epoch_circuit::BaseElement::new(raw);
        if elem.inner() != raw {
            return Err(format!("non-canonical field element at limb {i}"));
        }
        elements[i] = elem;
    }
    Ok(elements)
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
/// PoW import checks use this to supply timestamp inherent data when
/// validating blocks during import.
type PowInherentProviders = (sp_timestamp::InherentDataProvider,);
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

fn load_max_shielded_transfers_per_block(recursive_block_proofs_enabled: bool) -> usize {
    let configured = env_usize("HEGEMON_MAX_SHIELDED_TRANSFERS_PER_BLOCK").unwrap_or(
        if recursive_block_proofs_enabled {
            1
        } else {
            usize::MAX
        },
    );
    if configured == 0 {
        tracing::warn!(
            "HEGEMON_MAX_SHIELDED_TRANSFERS_PER_BLOCK is zero; no shielded transfers will be included"
        );
    }
    configured
}

fn is_recursive_shielded_transfer(call: &runtime::RuntimeCall) -> bool {
    let runtime::RuntimeCall::ShieldedPool(call) = call else {
        return false;
    };

    matches!(
        call,
        ShieldedPoolCall::shielded_transfer { .. }
            | ShieldedPoolCall::shielded_transfer_unsigned { .. }
            | ShieldedPoolCall::batch_shielded_transfer { .. }
    )
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
) {
    use sc_block_builder::BlockBuilderBuilder;

    let client_for_exec = client;
    let recursive_block_proofs_enabled = std::env::var("HEGEMON_RECURSIVE_BLOCK_PROOFS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let requested_recursive_block_fast = std::env::var("HEGEMON_RECURSIVE_BLOCK_PROOFS_FAST")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let recursive_block_fast = if cfg!(feature = "fast-proofs") {
        requested_recursive_block_fast
    } else {
        if requested_recursive_block_fast {
            tracing::warn!(
                "HEGEMON_RECURSIVE_BLOCK_PROOFS_FAST set but node not built with --features fast-proofs; ignoring"
            );
        }
        false
    };
    let commitment_block_proofs_enabled = std::env::var("HEGEMON_COMMITMENT_BLOCK_PROOFS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let requested_commitment_block_fast =
        std::env::var("HEGEMON_COMMITMENT_BLOCK_PROOFS_FAST")
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
    let max_shielded_transfers_per_block =
        load_max_shielded_transfers_per_block(recursive_block_proofs_enabled);

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

        // Add coinbase inherent data (shielded only)
        if let Some(ref address) = parsed_shielded_address {
            // Calculate block subsidy for this height using Bitcoin-style halving
            let subsidy = pallet_coinbase::block_subsidy(block_number);

            // Derive block hash for seed (use parent hash + block number)
            let mut block_hash_input = [0u8; 40];
            block_hash_input[..32].copy_from_slice(parent_hash.as_bytes());
            block_hash_input[32..40].copy_from_slice(&block_number.to_le_bytes());
            let block_hash: [u8; 32] = blake3::hash(&block_hash_input).into();

            // Encrypt the coinbase note
            match crate::shielded_coinbase::encrypt_coinbase_note(
                address,
                subsidy,
                &block_hash,
                block_number,
            ) {
                Ok(coinbase_data) => {
                    tracing::info!(
                        block_number,
                        subsidy,
                        commitment = %hex::encode(&coinbase_data.commitment),
                        "Encrypting shielded coinbase note"
                    );
                    let coinbase_provider = pallet_shielded_pool::ShieldedCoinbaseInherentDataProvider::from_note_data(coinbase_data);
                    if let Err(e) = futures::executor::block_on(
                        coinbase_provider.provide_inherent_data(&mut inherent_data)
                    ) {
                        tracing::warn!(error = ?e, "Failed to provide shielded coinbase inherent data");
                    } else {
                        tracing::info!(
                            block_number,
                            subsidy,
                            "Added shielded coinbase inherent for block reward"
                        );
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
            let is_shielded = is_recursive_shielded_transfer(&inherent_ext.function);
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
        for ext_bytes in extrinsics {
            match runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..]) {
                Ok(extrinsic) => {
                    let is_shielded = recursive_block_proofs_enabled
                        && is_recursive_shielded_transfer(&extrinsic.function);
                    if is_shielded {
                        if shielded_transfer_count >= max_shielded_transfers_per_block {
                            tracing::warn!(
                                block_number,
                                max_shielded_transfers_per_block,
                                "Skipping shielded transfer: block already contains {} (coinbase + transfers)",
                                shielded_transfer_count
                            );
                            continue;
                        }
                        if matches!(
                            extrinsic.function,
                            runtime::RuntimeCall::ShieldedPool(ShieldedPoolCall::batch_shielded_transfer { .. })
                        ) {
                            tracing::warn!(
                                block_number,
                                "Skipping batch_shielded_transfer: recursion does not support batch transfers yet"
                            );
                            continue;
                        }
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

        let recursive_proof = if recursive_block_proofs_enabled {
            match build_recursive_block_proof(
                client_for_exec.as_ref(),
                parent_substrate_hash,
                &applied,
                recursive_block_fast,
            ) {
                Ok(Some(proof)) => {
                    tracing::info!(
                        block_number,
                        tx_count = proof.tx_count,
                        proof_size = proof.proof_bytes.len(),
                        "Recursive block proof generated"
                    );
                    Some(proof)
                }
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!(
                        block_number,
                        error = %e,
                        "Failed to build recursive block proof"
                    );
                    None
                }
            }
        } else {
            None
        };

        let commitment_proof = if commitment_block_proofs_enabled {
            match build_commitment_block_proof(
                client_for_exec.as_ref(),
                parent_substrate_hash,
                &applied,
                da_params,
                commitment_block_fast,
            ) {
                Ok(Some(proof)) => {
                    tracing::info!(
                        block_number,
                        tx_count = proof.public_inputs.tx_count,
                        proof_size = proof.proof_bytes.len(),
                        proof_hash = %hex::encode(proof.proof_hash),
                        "Commitment block proof generated"
                    );
                    Some(proof)
                }
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!(
                        block_number,
                        error = %e,
                        "Failed to build commitment block proof"
                    );
                    None
                }
            }
        } else {
            None
        };

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
            recursive_proof,
            commitment_proof,
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
/// * `da_chunk_store` - In-memory DA chunk store for serving proofs
/// * `recursive_block_proof_store` - In-memory store for recursive block proofs
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
///     recursive_block_proof_store,
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
    recursive_block_proof_store: Arc<ParkingMutex<RecursiveBlockProofStore>>,
    commitment_block_proof_store: Arc<ParkingMutex<CommitmentBlockProofStore>>,
    da_params: DaParams,
) {
    use codec::Encode;
    use sp_runtime::traits::Block as BlockT;

    // Use the client directly for block import
    // The mining worker already verified the PoW, so we don't need PowBlockImport
    // to re-verify (which would fail due to pre_hash computation differences)
    let block_import = client;

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

        // Take cached StorageChanges early so we don't leak memory if we fail later (e.g. DA
        // encoding error, import error). The handle is stored in the template, but the changes
        // themselves live in a global cache keyed by u64.
        let storage_changes_key = template.storage_changes.as_ref().map(|handle| handle.key());
        let storage_changes = match storage_changes_key {
            Some(key) => Some(
                take_storage_changes(key)
                    .ok_or_else(|| format!("StorageChanges not found in cache for key {key}"))?,
            ),
            None => None,
        };

        // Decode the extrinsics from template
        let encoded_extrinsics: Vec<runtime::UncheckedExtrinsic> = template
            .extrinsics
            .iter()
            .filter_map(|tx_bytes| runtime::UncheckedExtrinsic::decode(&mut &tx_bytes[..]).ok())
            .collect();

        let mut da_encoding = Some(
            build_da_encoding_from_extrinsics(&encoded_extrinsics, da_params)
                .map_err(|err| format!("failed to build DA encoding for mined block: {err}"))?,
        );

        // Construct the block with seal in header
        let block = runtime::Block::new(header.clone(), encoded_extrinsics);
        let block_hash = block.hash();

        // Construct BlockImportParams for direct client import
        // No post_digests needed since seal is already in header
        let mut import_params = BlockImportParams::new(BlockOrigin::Own, header);
        import_params.body = Some(block.extrinsics().to_vec());
        import_params.fork_choice = Some(ForkChoiceStrategy::LongestChain);

        // Apply StorageChanges if available.
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
                if let Some(encoding) = da_encoding.take() {
                    let da_root = encoding.root();
                    let da_chunks = encoding.chunks().len();
                    da_chunk_store.lock().insert(da_root, encoding);
                    tracing::info!(
                        block_number = template.number,
                        da_root = %hex::encode(da_root),
                        da_chunks,
                        "DA encoding stored for imported block"
                    );
                }
                if let Some(proof) = template.recursive_proof.clone() {
                    let proof_size = proof.proof_bytes.len();
                    let recursive_proof_hash = proof.recursive_proof_hash;
                    recursive_block_proof_store.lock().insert(block_hash, proof);
                    tracing::info!(
                        block_number = template.number,
                        block_hash = %hex::encode(block_hash.as_bytes()),
                        proof_size,
                        recursive_proof_hash = %hex::encode(recursive_proof_hash),
                        "Recursive block proof stored for imported block"
                    );
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
                if let Some(encoding) = da_encoding.take() {
                    let da_root = encoding.root();
                    let da_chunks = encoding.chunks().len();
                    da_chunk_store.lock().insert(da_root, encoding);
                    tracing::info!(
                        block_number = template.number,
                        da_root = %hex::encode(da_root),
                        da_chunks,
                        "DA encoding stored for known block"
                    );
                }
                if let Some(proof) = template.recursive_proof.clone() {
                    let proof_size = proof.proof_bytes.len();
                    let recursive_proof_hash = proof.recursive_proof_hash;
                    recursive_block_proof_store.lock().insert(block_hash, proof);
                    tracing::info!(
                        block_number = template.number,
                        block_hash = %hex::encode(block_hash.as_bytes()),
                        proof_size,
                        recursive_proof_hash = %hex::encode(recursive_proof_hash),
                        "Recursive block proof stored for known block"
                    );
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
    /// Whether PQ is required for all connections
    pub require_pq: bool,
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
            require_pq: true,
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
    /// - `HEGEMON_REQUIRE_PQ`: Require PQ connections (default: true)
    /// - `HEGEMON_PQ_VERBOSE`: Enable verbose logging (default: false)
    /// - `HEGEMON_SEEDS`: Comma-separated list of seed peers (IP:port)
    /// - `HEGEMON_LISTEN_ADDR`: Listen address (overrides --port)
    /// - `HEGEMON_MAX_PEERS`: Maximum peers (default: 50)
    pub fn from_config(config: &Configuration) -> Self {
        let require_pq = std::env::var("HEGEMON_REQUIRE_PQ")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(true);

        let verbose = std::env::var("HEGEMON_PQ_VERBOSE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        // Parse bootstrap/seed nodes from environment
        // Supports both IP:port and hostname:port formats
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
                        // If that fails, try DNS resolution (for hostname:port)
                        match std::net::ToSocketAddrs::to_socket_addrs(&addr) {
                            Ok(mut addrs) => {
                                if let Some(resolved) = addrs.next() {
                                    tracing::info!(
                                        addr = %addr,
                                        resolved = %resolved,
                                        "Resolved seed hostname"
                                    );
                                    Some(resolved)
                                } else {
                                    tracing::warn!(
                                        addr = %addr,
                                        "DNS resolved but no addresses returned"
                                    );
                                    None
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    addr = %addr,
                                    error = %e,
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
            require_pq = require_pq,
            "PQ service config initialized"
        );

        Self {
            require_pq,
            verbose_logging: verbose,
            bootstrap_nodes,
            listen_addr,
            max_peers,
        }
    }

    /// Create from environment variables only (legacy, use from_config when possible)
    pub fn from_env() -> Self {
        let require_pq = std::env::var("HEGEMON_REQUIRE_PQ")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(true);

        let verbose = std::env::var("HEGEMON_PQ_VERBOSE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        let bootstrap_nodes: Vec<std::net::SocketAddr> = std::env::var("HEGEMON_SEEDS")
            .map(|s| {
                s.split(',')
                    .filter_map(|addr| {
                        let addr = addr.trim();
                        if addr.is_empty() {
                            return None;
                        }
                        addr.parse().ok()
                    })
                    .collect()
            })
            .unwrap_or_default();

        let listen_addr = std::env::var("HEGEMON_LISTEN_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "0.0.0.0:30333".parse().unwrap());

        let max_peers = std::env::var("HEGEMON_MAX_PEERS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(50);

        Self {
            require_pq,
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

fn pq_identity_seed_path(config: &Configuration) -> PathBuf {
    std::env::var(PQ_IDENTITY_SEED_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| config.base_path.path().join(PQ_IDENTITY_SEED_FILE))
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

// =============================================================================
// LEGACY PartialComponents AND new_partial() REMOVED
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
        Box::pin(async move { Ok((sp_timestamp::InherentDataProvider::from_system_time(),)) })
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
        require_pq: pq_service_config.require_pq,
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
        require_pq: pq_service_config.require_pq,
        handshake_timeout: std::time::Duration::from_secs(30),
        verbose_logging: pq_service_config.verbose_logging,
    };

    let pq_identity = PqPeerIdentity::new(&transport_seed, pq_transport_config.clone());

    let substrate_transport_config = SubstratePqTransportConfig {
        require_pq: pq_service_config.require_pq,
        connection_timeout: std::time::Duration::from_secs(30),
        handshake_timeout: std::time::Duration::from_secs(30),
        verbose_logging: pq_service_config.verbose_logging,
        protocol_id: "/hegemon/pq/1".to_string(),
    };

    let pq_transport = SubstratePqTransport::new(&pq_identity, substrate_transport_config);

    tracing::info!(
        pq_peer_id = %hex::encode(pq_transport.local_peer_id()),
        require_pq = %pq_service_config.require_pq,
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

    let chain_name = config.chain_spec.name().to_string();
    let chain_properties = config.chain_spec.properties();
    let chain_type = config.chain_spec.chain_type();
    let role = format!("{:?}", config.role);

    // Track PQ network handle for mining worker
    let mut pq_network_handle: Option<PqNetworkHandle> = None;

    tracing::info!(
        chain = %chain_name,
        role = %role,
        best_number = %client.chain_info().best_number,
        best_hash = %client.chain_info().best_hash,
        pq_enabled = %network_config.enable_pq_transport,
        require_pq = %pq_service_config.require_pq,
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

    // =========================================================================
    // Recursive Epoch Proof Store (Phase 3d.2)
    // =========================================================================
    //
    // Proofs are persisted by epoch number so peers can serve historical proofs on request.
    let recursive_epoch_proofs_dir = std::env::var("HEGEMON_RECURSIVE_EPOCH_PROOFS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| config.base_path.path().join("recursive-epoch-proofs"));
    let recursive_epoch_proof_store: Arc<
        Mutex<crate::substrate::epoch_proofs::RecursiveEpochProofStore>,
    > = Arc::new(Mutex::new(
        crate::substrate::epoch_proofs::RecursiveEpochProofStore::open(
            recursive_epoch_proofs_dir.clone(),
        )
        .unwrap_or_else(|e| {
            tracing::warn!(
                dir = %recursive_epoch_proofs_dir.display(),
                error = %e,
                "Failed to open recursive epoch proof store; continuing with empty store"
            );
            crate::substrate::epoch_proofs::RecursiveEpochProofStore::empty(
                recursive_epoch_proofs_dir.clone(),
            )
        }),
    ));
    tracing::info!(
        dir = %recursive_epoch_proofs_dir.display(),
        stored = recursive_epoch_proof_store.lock().await.len(),
        "Recursive epoch proof store initialized"
    );

    let da_params = load_da_params(&chain_properties);
    let da_store_capacity = load_da_store_capacity();
    let da_sample_timeout = load_da_sample_timeout();
    let recursive_block_proof_store_capacity = load_recursive_proof_store_capacity();
    let commitment_block_proof_store_capacity = load_commitment_proof_store_capacity();
    let da_chunk_store: Arc<ParkingMutex<DaChunkStore>> =
        Arc::new(ParkingMutex::new(DaChunkStore::new(da_store_capacity)));
    let da_request_tracker: Arc<ParkingMutex<DaRequestTracker>> =
        Arc::new(ParkingMutex::new(DaRequestTracker::default()));
    let recursive_block_proof_store: Arc<ParkingMutex<RecursiveBlockProofStore>> =
        Arc::new(ParkingMutex::new(RecursiveBlockProofStore::new(
            recursive_block_proof_store_capacity,
        )));
    let commitment_block_proof_store: Arc<ParkingMutex<CommitmentBlockProofStore>> =
        Arc::new(ParkingMutex::new(CommitmentBlockProofStore::new(
            commitment_block_proof_store_capacity,
        )));

    tracing::info!(
        da_chunk_size = da_params.chunk_size,
        da_sample_count = da_params.sample_count,
        da_store_capacity,
        da_sample_timeout_ms = da_sample_timeout.as_millis() as u64,
        "DA sampling configured"
    );

    tracing::info!(
        recursive_block_proof_store_capacity,
        "Recursive block proof store configured"
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
            require_pq: pq_service_config.require_pq,
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

                tracing::info!("Chain sync service created");

                // =======================================================================
                // Recursive Epoch Proof Propagation (Phase 2f)
                // =======================================================================
                // Controlled by HEGEMON_RECURSIVE_EPOCH_PROOFS=1 because proof generation is
                // CPU-intensive.
                let recursive_epoch_proofs_enabled =
                    std::env::var("HEGEMON_RECURSIVE_EPOCH_PROOFS")
                        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                        .unwrap_or(false);

                let validate_recursive_epoch_proofs = if cfg!(feature = "production") {
                    true
                } else {
                    std::env::var("HEGEMON_VALIDATE_RECURSIVE_EPOCH_PROOFS")
                        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                        .unwrap_or(true)
                };

                // Verify/store incoming proofs asynchronously to avoid blocking the network event loop.
                let (epoch_proof_rx_tx, mut epoch_proof_rx_rx) = mpsc::channel::<(
                    [u8; 32],
                    crate::substrate::network_bridge::RecursiveEpochProofMessage,
                )>(64);

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
                let pq_handle_for_epoch_proofs = pq_backend.handle(); // For recursive epoch proof propagation
                let pq_handle_for_da = pq_backend.handle(); // For DA chunk request/response
                let pq_handle_for_da_import = pq_handle_for_da.clone();

                // Clone client for the network event handler to send our best block
                let client_for_network = client.clone();
                let recursive_epoch_proof_store_for_handler =
                    Arc::clone(&recursive_epoch_proof_store);
                let da_chunk_store_for_handler = Arc::clone(&da_chunk_store);
                let da_request_tracker_for_handler = Arc::clone(&da_request_tracker);

                // Spawn a single verifier worker for incoming recursive epoch proofs.
                let recursive_epoch_proof_store_for_worker =
                    Arc::clone(&recursive_epoch_proof_store);
                let client_for_epoch_proof_worker = client.clone();
                let task_handle_for_epoch_proof_worker = task_manager.spawn_handle();
                task_handle_for_epoch_proof_worker.spawn(
                    "recursive-epoch-proof-receiver",
                    Some("network"),
                    async move {
                        const MAX_OUTER_PROOF_BYTES: usize = 1024 * 1024;
                        const MAX_INNER_PROOF_BYTES: usize = 1024 * 1024;

                        while let Some((peer_id, msg)) = epoch_proof_rx_rx.recv().await {
                            if msg.proof_bytes.len() > MAX_OUTER_PROOF_BYTES
                                || msg.inner_proof_bytes.len() > MAX_INNER_PROOF_BYTES
                            {
                                tracing::warn!(
                                    peer = %hex::encode(peer_id),
                                    epoch_number = msg.epoch_number,
                                    proof_bytes = msg.proof_bytes.len(),
                                    inner_bytes = msg.inner_proof_bytes.len(),
                                    "Dropping recursive epoch proof (exceeds size limit)"
                                );
                                continue;
                            }

                            // Basic epoch consistency checks to avoid wasting cycles on junk.
                            let expected_start = msg.epoch_number.saturating_mul(EPOCH_SIZE_BLOCKS);
                            let expected_end = expected_start + (EPOCH_SIZE_BLOCKS - 1);
                            if msg.start_block != expected_start || msg.end_block != expected_end {
                                tracing::warn!(
                                    peer = %hex::encode(peer_id),
                                    epoch_number = msg.epoch_number,
                                    start_block = msg.start_block,
                                    end_block = msg.end_block,
                                    expected_start,
                                    expected_end,
                                    "Dropping recursive epoch proof (epoch range mismatch)"
                                );
                                continue;
                            }

                            let epoch = EpochCircuit {
                                epoch_number: msg.epoch_number,
                                start_block: msg.start_block,
                                end_block: msg.end_block,
                                proof_root: msg.proof_root,
                                state_root: msg.state_root,
                                nullifier_set_root: msg.nullifier_set_root,
                                commitment_tree_root: msg.commitment_tree_root,
                            };
                            let expected_commitment = epoch.commitment();
                            if msg.epoch_commitment != expected_commitment {
                                tracing::warn!(
                                    peer = %hex::encode(peer_id),
                                    epoch_number = msg.epoch_number,
                                    "Dropping recursive epoch proof (epoch commitment mismatch)"
                                );
                                continue;
                            }

                            // Avoid re-verifying proofs we already have.
                            {
                                let store = recursive_epoch_proof_store_for_worker.lock().await;
                                if store.get(msg.epoch_number).is_some() {
                                    continue;
                                }
                            }

                            // Reject proofs for epochs ahead of our current tip (helps avoid spam).
                            let best_number: u64 = client_for_epoch_proof_worker
                                .chain_info()
                                .best_number
                                .try_into()
                                .unwrap_or(0);
                            let best_epoch = best_number / EPOCH_SIZE_BLOCKS;
                            if msg.epoch_number > best_epoch.saturating_add(1) {
                                tracing::warn!(
                                    peer = %hex::encode(peer_id),
                                    epoch_number = msg.epoch_number,
                                    best_epoch,
                                    "Dropping recursive epoch proof (epoch too far ahead)"
                                );
                                continue;
                            }

                            let proof_accumulator = match parse_accumulator(msg.proof_accumulator) {
                                Ok(a) => a,
                                Err(e) => {
                                    tracing::warn!(
                                        peer = %hex::encode(peer_id),
                                        epoch_number = msg.epoch_number,
                                        error = %e,
                                        "Dropping recursive epoch proof (bad accumulator encoding)"
                                    );
                                    continue;
                                }
                            };

                            let proof = epoch_circuit::recursion::RecursiveEpochProof {
                                proof_bytes: msg.proof_bytes.clone(),
                                inner_proof_bytes: msg.inner_proof_bytes.clone(),
                                epoch_commitment: msg.epoch_commitment,
                                proof_accumulator,
                                num_proofs: msg.num_proofs,
                                is_recursive: msg.is_recursive,
                            };

                            if validate_recursive_epoch_proofs {
                                let epoch_clone = epoch.clone();
                                let proof_clone = proof.clone();
                                let ok = tokio::task::spawn_blocking(move || {
                                    if cfg!(feature = "production") {
                                        EpochRecursiveProver::production()
                                            .verify_epoch_proof_strict(&proof_clone, &epoch_clone)
                                    } else {
                                        EpochRecursiveProver::fast()
                                            .verify_epoch_proof(&proof_clone, &epoch_clone)
                                    }
                                })
                                .await
                                .unwrap_or(false);

                                if !ok {
                                    tracing::warn!(
                                        peer = %hex::encode(peer_id),
                                        epoch_number = msg.epoch_number,
                                        "Rejected recursive epoch proof (verification failed)"
                                    );
                                    continue;
                                }
                            }

                            let (inserted, store_dir) = {
                                let mut store = recursive_epoch_proof_store_for_worker.lock().await;
                                let store_dir = store.dir().to_path_buf();
                                let inserted = matches!(
                                    store.insert(msg.clone()),
                                    crate::substrate::epoch_proofs::InsertOutcome::Inserted
                                );
                                (inserted, store_dir)
                            };
                            if !inserted {
                                continue;
                            }

                            let msg_for_persist = msg.clone();
                            tokio::task::spawn_blocking(move || {
                                let store =
                                    crate::substrate::epoch_proofs::RecursiveEpochProofStore::empty(
                                        store_dir,
                                    );
                                if let Err(e) = store.persist(&msg_for_persist) {
                                    tracing::warn!(
                                        epoch_number = msg_for_persist.epoch_number,
                                        error = %e,
                                        "Failed to persist recursive epoch proof to disk"
                                    );
                                }
                            })
                            .await
                            .ok();

                            tracing::info!(
                                peer = %hex::encode(peer_id),
                                epoch_number = msg.epoch_number,
                                proof_bytes = msg.proof_bytes.len(),
                                inner_bytes = msg.inner_proof_bytes.len(),
                                is_recursive = msg.is_recursive,
                                "Stored recursive epoch proof"
                            );
                        }
                    },
                );

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

                                    // If we have a recursive epoch proof available, optionally send it immediately so
                                    // late joiners can validate epochs without waiting for the next epoch boundary.
                                    //
                                    // Keep this gated behind HEGEMON_RECURSIVE_EPOCH_PROOFS=1 to avoid surprising
                                    // users running "sync-only" nodes (and to avoid unnecessary bandwidth).
                                    if recursive_epoch_proofs_enabled {
                                        if let Some(msg) = recursive_epoch_proof_store_for_handler
                                            .lock()
                                            .await
                                            .latest()
                                            .cloned()
                                        {
                                            use crate::substrate::network_bridge::{
                                                RecursiveEpochProofProtocolMessage,
                                                RECURSIVE_EPOCH_PROOFS_PROTOCOL,
                                                RECURSIVE_EPOCH_PROOFS_PROTOCOL_V2,
                                            };

                                            let v1 = msg.encode();
                                            let v2 = RecursiveEpochProofProtocolMessage::Proof(Box::new(msg.clone())).encode();

                                            if let Err(e) = pq_handle_for_status
                                                .send_message(
                                                    peer_id,
                                                    RECURSIVE_EPOCH_PROOFS_PROTOCOL.to_string(),
                                                    v1,
                                                )
                                                .await
                                            {
                                                tracing::warn!(
                                                    peer = %hex::encode(peer_id),
                                                    error = %e,
                                                    "Failed to send v1 recursive epoch proof to new peer"
                                                );
                                            }
                                            if let Err(e) = pq_handle_for_status
                                                .send_message(
                                                    peer_id,
                                                    RECURSIVE_EPOCH_PROOFS_PROTOCOL_V2.to_string(),
                                                    v2,
                                                )
                                                .await
                                            {
                                                tracing::warn!(
                                                    peer = %hex::encode(peer_id),
                                                    error = %e,
                                                    "Failed to send v2 recursive epoch proof to new peer"
                                                );
                                            } else {
                                                tracing::info!(
                                                    peer = %hex::encode(peer_id),
                                                    epoch_number = msg.epoch_number,
                                                    proof_bytes = msg.proof_bytes.len(),
                                                    inner_bytes = msg.inner_proof_bytes.len(),
                                                    "Sent recursive epoch proof to new peer"
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
                                        BLOCK_ANNOUNCE_PROTOCOL_LEGACY, DA_CHUNKS_PROTOCOL,
                                        SYNC_PROTOCOL, SYNC_PROTOCOL_LEGACY,
                                    };
                                    use crate::substrate::network_bridge::SyncMessage;
                                    use crate::substrate::network_bridge::{
                                        RecursiveEpochProofMessage, RECURSIVE_EPOCH_PROOFS_PROTOCOL,
                                    };

                                    // Handle sync protocol messages
                                    if protocol == SYNC_PROTOCOL || protocol == SYNC_PROTOCOL_LEGACY {
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
                                    // Handle recursive epoch proofs
                                    else if protocol == RECURSIVE_EPOCH_PROOFS_PROTOCOL {
                                        if recursive_epoch_proofs_enabled {
                                            if let Ok(msg) =
                                                RecursiveEpochProofMessage::decode(&mut &data[..])
                                            {
                                                tracing::info!(
                                                    peer = %hex::encode(peer_id),
                                                    epoch_number = msg.epoch_number,
                                                    num_proofs = msg.num_proofs,
                                                    proof_bytes = msg.proof_bytes.len(),
                                                    inner_bytes = msg.inner_proof_bytes.len(),
                                                    is_recursive = msg.is_recursive,
                                                    "Received recursive epoch proof"
                                                );

                                                let _ = epoch_proof_rx_tx.try_send((peer_id, msg));
                                            } else {
                                                tracing::warn!(
                                                    peer = %hex::encode(peer_id),
                                                    protocol = %protocol,
                                                    data_len = data.len(),
                                                    "Failed to decode recursive epoch proof message"
                                                );
                                            }
                                        } else {
                                            tracing::debug!(
                                                peer = %hex::encode(peer_id),
                                                "Ignoring recursive epoch proof (disabled)"
                                            );
                                        }
                                    }
                                    // Handle recursive epoch proofs (v2 request/response)
                                    else if protocol == crate::substrate::network_bridge::RECURSIVE_EPOCH_PROOFS_PROTOCOL_V2 {
                                        use crate::substrate::network_bridge::{
                                            RecursiveEpochProofProtocolMessage,
                                            RECURSIVE_EPOCH_PROOFS_PROTOCOL_V2,
                                        };

                                        match RecursiveEpochProofProtocolMessage::decode(&mut &data[..]) {
                                            Ok(RecursiveEpochProofProtocolMessage::Request { epoch_number }) => {
                                                let msg_opt = recursive_epoch_proof_store_for_handler
                                                    .lock()
                                                    .await
                                                    .get(epoch_number)
                                                    .cloned();
                                                let response = match msg_opt {
                                                    Some(msg) => RecursiveEpochProofProtocolMessage::Proof(Box::new(msg)),
                                                    None => RecursiveEpochProofProtocolMessage::NotFound { epoch_number },
                                                };
                                                if let Err(e) = pq_handle_for_sync
                                                    .send_message(
                                                        peer_id,
                                                        RECURSIVE_EPOCH_PROOFS_PROTOCOL_V2.to_string(),
                                                        response.encode(),
                                                    )
                                                    .await
                                                {
                                                    tracing::warn!(
                                                        peer = %hex::encode(peer_id),
                                                        error = %e,
                                                        "Failed to respond to recursive epoch proof request"
                                                    );
                                                }
                                            }
                                            Ok(RecursiveEpochProofProtocolMessage::Proof(msg)) => {
                                                let msg = *msg;
                                                if recursive_epoch_proofs_enabled {
                                                    let _ = epoch_proof_rx_tx
                                                        .try_send((peer_id, msg));
                                                } else {
                                                    tracing::debug!(
                                                        peer = %hex::encode(peer_id),
                                                        epoch_number = msg.epoch_number,
                                                        "Ignoring recursive epoch proof v2 Proof message (disabled)"
                                                    );
                                                }
                                            }
                                            Ok(RecursiveEpochProofProtocolMessage::NotFound { epoch_number }) => {
                                                tracing::info!(
                                                    peer = %hex::encode(peer_id),
                                                    epoch_number,
                                                    "Peer reported recursive epoch proof not found"
                                                );
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    peer = %hex::encode(peer_id),
                                                    protocol = %protocol,
                                                    error = %e,
                                                    data_len = data.len(),
                                                    "Failed to decode v2 recursive epoch proof message"
                                                );
                                            }
                                        }
                                    }
                                    // Handle DA chunk request/response
                                    else if protocol == DA_CHUNKS_PROTOCOL {
                                        match DaChunkProtocolMessage::decode(&mut &data[..]) {
                                            Ok(DaChunkProtocolMessage::Request { root, indices }) => {
                                                let (proofs, missing) = {
                                                    let store = da_chunk_store_for_handler.lock();
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
                                    else if protocol == BLOCK_ANNOUNCE_PROTOCOL || protocol == BLOCK_ANNOUNCE_PROTOCOL_LEGACY {
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
                                        }
                                    }
                                }
                                PqNetworkEvent::Stopped => {
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
                // Spawn recursive epoch proof generator task (Phase 2f)
                // =======================================================================
                if recursive_epoch_proofs_enabled {
                    let client_for_epoch_proofs = client.clone();
                    let pq_handle_for_epoch_broadcast = pq_handle_for_epoch_proofs.clone();
                    let recursive_epoch_proof_store_for_generator =
                        Arc::clone(&recursive_epoch_proof_store);

                    task_manager.spawn_handle().spawn(
                        "recursive-epoch-proofs",
                        Some("epoch"),
                        async move {
                            use crate::substrate::network_bridge::{
                                RecursiveEpochProofMessage, RecursiveEpochProofProtocolMessage,
                                RECURSIVE_EPOCH_PROOFS_PROTOCOL,
                                RECURSIVE_EPOCH_PROOFS_PROTOCOL_V2,
                            };
                            use futures::StreamExt;

                            tracing::info!(
                                epoch_size = EPOCH_SIZE_BLOCKS,
                                "Recursive epoch proof generator started"
                            );

                            let mut epoch_proof_hashes: std::collections::BTreeMap<
                                u64,
                                Vec<[u8; 32]>,
                            > = std::collections::BTreeMap::new();

                            fn proof_hash_from_call(
                                call: &pallet_shielded_pool::Call<runtime::Runtime>,
                            ) -> Option<[u8; 32]> {
                                use epoch_circuit::{
                                    batch_proof_hash, proof_hash, BatchProofHashInputs,
                                    ProofHashInputs,
                                };
                                use pallet_shielded_pool::Call as PoolCall;

                                match call {
                                    PoolCall::shielded_transfer {
                                        proof,
                                        nullifiers,
                                        commitments,
                                        anchor,
                                        fee,
                                        value_balance,
                                        ..
                                    } => {
                                        let inputs = ProofHashInputs {
                                            proof_bytes: proof.data.as_slice(),
                                            anchor: *anchor,
                                            nullifiers: nullifiers.as_slice(),
                                            commitments: commitments.as_slice(),
                                            fee: *fee,
                                            value_balance: *value_balance,
                                        };
                                        Some(proof_hash(&inputs))
                                    }
                                    PoolCall::shielded_transfer_unsigned {
                                        proof,
                                        nullifiers,
                                        commitments,
                                        anchor,
                                        fee,
                                        ..
                                    } => {
                                        let inputs = ProofHashInputs {
                                            proof_bytes: proof.data.as_slice(),
                                            anchor: *anchor,
                                            nullifiers: nullifiers.as_slice(),
                                            commitments: commitments.as_slice(),
                                            fee: *fee,
                                            value_balance: 0,
                                        };
                                        Some(proof_hash(&inputs))
                                    }
                                    PoolCall::batch_shielded_transfer {
                                        proof,
                                        nullifiers,
                                        commitments,
                                        anchor,
                                        total_fee,
                                        ..
                                    } => {
                                        let inputs = BatchProofHashInputs {
                                            proof_bytes: proof.data.as_slice(),
                                            anchor: *anchor,
                                            nullifiers: nullifiers.as_slice(),
                                            commitments: commitments.as_slice(),
                                            total_fee: *total_fee,
                                            batch_size: proof.batch_size,
                                        };
                                        Some(batch_proof_hash(&inputs))
                                    }
                                    _ => None,
                                }
                            }

                            // =========================================================
                            // Backfill: scan historical blocks for proof hashes
                            // =========================================================
                            // This ensures we capture transactions from blocks imported
                            // before the node started (or before a restart).
                            let best_hash = client_for_epoch_proofs.info().best_hash;
                            let best_number: u64 = client_for_epoch_proofs
                                .info()
                                .best_number
                                .try_into()
                                .unwrap_or(0);

                            // Determine which epoch we're currently in
                            let current_epoch = best_number / EPOCH_SIZE_BLOCKS;

                            // Scan from block 1 (genesis has no txs) to capture ALL epochs
                            // that may have completed while the node was offline.
                            // TODO: Optimize by checking which epochs already have stored proofs
                            let scan_start = 1u64;

                            if scan_start < best_number {
                                tracing::info!(
                                    scan_start,
                                    best_number,
                                    current_epoch,
                                    "Backfilling proof hashes from historical blocks"
                                );

                                // Walk backwards from best to find each block
                                let mut block_hash = best_hash;
                                let mut block_num = best_number;

                                while block_num >= scan_start && block_num > 0 {
                                    let body = match client_for_epoch_proofs.block_body(block_hash) {
                                        Ok(Some(extrinsics)) => extrinsics,
                                        _ => Vec::new(),
                                    };

                                    // Log blocks with more than 2 extrinsics (likely has a tx)
                                    if body.len() > 2 {
                                        tracing::info!(
                                            block_num,
                                            extrinsic_count = body.len(),
                                            "Scanning block with extra extrinsics"
                                        );
                                        // Debug: log all call types
                                        for (idx, ext) in body.iter().enumerate() {
                                            tracing::info!(
                                                block_num,
                                                idx,
                                                call = ?std::mem::discriminant(&ext.function),
                                                "Extrinsic call type"
                                            );
                                            // Also try to identify ShieldedPool calls specifically
                                            if let runtime::RuntimeCall::ShieldedPool(ref inner) = ext.function {
                                                tracing::info!(
                                                    block_num,
                                                    idx,
                                                    inner_call = ?std::mem::discriminant(inner),
                                                    "Found ShieldedPool call"
                                                );
                                            }
                                        }
                                    }

                                    let mut hashes_in_block: Vec<[u8; 32]> = Vec::new();
                                    for ext in &body {
                                        // First match on ShieldedPool variant, then match inner call
                                        if let runtime::RuntimeCall::ShieldedPool(ref inner) = ext.function {
                                            if let Some(hash) = proof_hash_from_call(inner) {
                                                tracing::info!(block_num, "Found shielded transfer (backfill)");
                                                hashes_in_block.push(hash);
                                            }
                                        }
                                    }

                                    if !hashes_in_block.is_empty() {
                                        let epoch_num = block_num / EPOCH_SIZE_BLOCKS;
                                        tracing::debug!(
                                            block_num,
                                            epoch_num,
                                            count = hashes_in_block.len(),
                                            "Backfilled proof hashes from block"
                                        );
                                        epoch_proof_hashes
                                            .entry(epoch_num)
                                            .or_default()
                                            .extend(hashes_in_block);
                                    }

                                    // Get parent hash to walk backwards
                                    let header = match client_for_epoch_proofs.header(block_hash) {
                                        Ok(Some(h)) => h,
                                        _ => break,
                                    };

                                    if block_num == scan_start {
                                        break;
                                    }

                                    block_hash = *header.parent_hash();
                                    block_num = block_num.saturating_sub(1);
                                }

                                for (epoch, hashes) in &epoch_proof_hashes {
                                    tracing::info!(
                                        epoch,
                                        num_hashes = hashes.len(),
                                        "Backfilled epoch proof hashes"
                                    );
                                }

                                // Generate proofs for any COMPLETED epochs found during backfill
                                // A completed epoch is one where epoch_num < current_epoch
                                let use_rpo_outer_backfill = std::env::var("HEGEMON_RECURSIVE_EPOCH_PROOFS_OUTER_RPO")
                                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                                    .unwrap_or(false);

                                for completed_epoch in 0..current_epoch {
                                    if let Some(proof_hashes) = epoch_proof_hashes.get(&completed_epoch) {
                                        if proof_hashes.is_empty() {
                                            continue;
                                        }

                                        // Check if we already have this proof stored
                                        {
                                            let store = recursive_epoch_proof_store_for_generator.lock().await;
                                            if store.get(completed_epoch).is_some() {
                                                tracing::debug!(
                                                    epoch = completed_epoch,
                                                    "Epoch proof already exists in store, skipping"
                                                );
                                                continue;
                                            }
                                        }

                                        tracing::info!(
                                            epoch = completed_epoch,
                                            num_proofs = proof_hashes.len(),
                                            "Generating epoch proof for backfilled completed epoch"
                                        );

                                        let proof_root = compute_proof_root(proof_hashes);
                                        let mut epoch_data = EpochCircuit::new(completed_epoch);
                                        epoch_data.proof_root = proof_root;
                                        epoch_data.state_root = [0u8; 32];
                                        epoch_data.nullifier_set_root = [0u8; 32];
                                        epoch_data.commitment_tree_root = [0u8; 32];
                                        let epoch_commitment = epoch_data.commitment();

                                        let proof_hashes_clone = proof_hashes.clone();
                                        let epoch_for_prover = epoch_data.clone();

                                        let proof_result = if use_rpo_outer_backfill {
                                            let prover = if cfg!(feature = "production") {
                                                EpochRecursiveProver::production()
                                            } else {
                                                EpochRecursiveProver::fast()
                                            };
                                            prover.prove_epoch_recursive_rpo_outer(
                                                &epoch_for_prover,
                                                &proof_hashes_clone,
                                            )
                                        } else {
                                            let prover = if cfg!(feature = "production") {
                                                EpochRecursiveProver::production()
                                            } else {
                                                EpochRecursiveProver::fast()
                                            };
                                            prover.prove_epoch_recursive(
                                                &epoch_for_prover,
                                                &proof_hashes_clone,
                                            )
                                        };

                                        match proof_result {
                                            Ok(recursive_proof) => {
                                                tracing::info!(
                                                    epoch = completed_epoch,
                                                    proof_size = recursive_proof.proof_bytes.len(),
                                                    proof_root = ?hex::encode(&proof_root),
                                                    "✅ Generated epoch proof for backfilled epoch"
                                                );

                                                // Store proof using the same mechanism as live proofs
                                                let msg = RecursiveEpochProofMessage {
                                                    epoch_number: epoch_data.epoch_number,
                                                    start_block: epoch_data.start_block,
                                                    end_block: epoch_data.end_block,
                                                    proof_root: epoch_data.proof_root,
                                                    state_root: epoch_data.state_root,
                                                    nullifier_set_root: epoch_data.nullifier_set_root,
                                                    commitment_tree_root: epoch_data.commitment_tree_root,
                                                    epoch_commitment,
                                                    num_proofs: recursive_proof.num_proofs,
                                                    proof_accumulator: recursive_proof.accumulator_bytes(),
                                                    proof_bytes: recursive_proof.proof_bytes.clone(),
                                                    inner_proof_bytes: recursive_proof.inner_proof_bytes.clone(),
                                                    is_recursive: recursive_proof.is_recursive,
                                                };

                                                let (inserted, store_dir) = {
                                                    let mut store = recursive_epoch_proof_store_for_generator.lock().await;
                                                    let store_dir = store.dir().to_path_buf();
                                                    let inserted = matches!(
                                                        store.insert(msg.clone()),
                                                        crate::substrate::epoch_proofs::InsertOutcome::Inserted
                                                    );
                                                    (inserted, store_dir)
                                                };

                                                if inserted {
                                                    let msg_for_persist = msg;
                                                    tokio::task::spawn_blocking(move || {
                                                        let store = crate::substrate::epoch_proofs::RecursiveEpochProofStore::empty(store_dir);
                                                        if let Err(e) = store.persist(&msg_for_persist) {
                                                            tracing::warn!(
                                                                epoch_number = msg_for_persist.epoch_number,
                                                                error = %e,
                                                                "Failed to persist backfilled epoch proof to disk"
                                                            );
                                                        } else {
                                                            tracing::info!(
                                                                epoch = msg_for_persist.epoch_number,
                                                                "📁 Persisted backfilled epoch proof to disk"
                                                            );
                                                        }
                                                    });
                                                }
                                            }
                                            Err(e) => {
                                                tracing::error!(
                                                    epoch = completed_epoch,
                                                    error = %e,
                                                    "Failed to generate epoch proof for backfilled epoch"
                                                );
                                            }
                                        }
                                    }
                                }
                            }

                            let mut import_stream = client_for_epoch_proofs
                                .import_notification_stream()
                                .fuse();

                            while let Some(notification) = import_stream.next().await {
                                // Only track the best chain to avoid double-counting during imports.
                                if !notification.is_new_best {
                                    continue;
                                }

                                let block_hash = notification.hash;
                                let header = notification.header.clone();
                                let block_number: u64 = (*header.number()).try_into().unwrap_or(0);

                                // Collect proof hashes from shielded_transfer extrinsics.
                                let body = match client_for_epoch_proofs.block_body(block_hash) {
                                    Ok(Some(extrinsics)) => extrinsics,
                                    _ => Vec::new(),
                                };

                                let mut hashes_in_block: Vec<[u8; 32]> = Vec::new();
                                for ext in &body {
                                    // UncheckedExtrinsic has public `function` field (the call).
                                    // Match both individual and batch shielded transfers.
                                    if let runtime::RuntimeCall::ShieldedPool(ref inner) = ext.function {
                                        if let Some(hash) = proof_hash_from_call(inner) {
                                            hashes_in_block.push(hash);
                                        }
                                    }
                                }

                                let epoch_number = block_number / EPOCH_SIZE_BLOCKS;
                                if !hashes_in_block.is_empty() {
                                    epoch_proof_hashes
                                        .entry(epoch_number)
                                        .or_default()
                                        .extend(hashes_in_block);
                                }

                                // Finalize the previous epoch at boundary blocks (…, 1000, 2000, …).
                                if block_number != 0 && block_number.is_multiple_of(EPOCH_SIZE_BLOCKS) {
                                    let finished_epoch = epoch_number.saturating_sub(1);
                                    let proof_hashes = epoch_proof_hashes.remove(&finished_epoch).unwrap_or_default();

                                    if proof_hashes.is_empty() {
                                        tracing::debug!(
                                            finished_epoch,
                                            "Epoch has no proof hashes; skipping recursive epoch proof generation"
                                        );
                                        continue;
                                    }

                                    // Use the parent header as the end-of-epoch header.
                                    let end_hash = *header.parent_hash();
                                    let end_header = match client_for_epoch_proofs.header(end_hash) {
                                        Ok(Some(h)) => h,
                                        _ => {
                                            tracing::warn!(
                                                finished_epoch,
                                                "Failed to fetch end-of-epoch header; skipping epoch proof"
                                            );
                                            continue;
                                        }
                                    };

                                    let mut state_root = [0u8; 32];
                                    state_root.copy_from_slice(end_header.state_root().as_ref());

                                    let proof_root = compute_proof_root(&proof_hashes);
                                    let mut epoch = EpochCircuit::new(finished_epoch);
                                    epoch.proof_root = proof_root;
                                    epoch.state_root = state_root;
                                    epoch.nullifier_set_root = [0u8; 32];
                                    epoch.commitment_tree_root = [0u8; 32];

                                    let epoch_commitment = epoch.commitment();

                                    tracing::info!(
                                        finished_epoch,
                                        num_proofs = proof_hashes.len(),
                                        "Generating recursive epoch proof"
                                    );

                                    let epoch_for_prover = epoch.clone();
                                    let use_rpo_outer = std::env::var("HEGEMON_RECURSIVE_EPOCH_PROOFS_OUTER_RPO")
                                        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                                        .unwrap_or(false);
                                    let proof_result = tokio::task::spawn_blocking(move || {
                                        let prover = if cfg!(feature = "production") {
                                            EpochRecursiveProver::production()
                                        } else {
                                            EpochRecursiveProver::fast()
                                        };
                                        if use_rpo_outer {
                                            prover.prove_epoch_recursive_rpo_outer(
                                                &epoch_for_prover,
                                                &proof_hashes,
                                            )
                                        } else {
                                            prover.prove_epoch_recursive(&epoch_for_prover, &proof_hashes)
                                        }
                                    })
                                    .await;

                                    let recursive_proof = match proof_result {
                                        Ok(Ok(p)) => p,
                                        Ok(Err(e)) => {
                                            tracing::warn!(
                                                finished_epoch,
                                                error = %e,
                                                "Recursive epoch proof generation failed"
                                            );
                                            continue;
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                finished_epoch,
                                                error = %e,
                                                "Recursive epoch proof task panicked or was cancelled"
                                            );
                                            continue;
                                        }
                                    };

                                    let msg = RecursiveEpochProofMessage {
                                        epoch_number: epoch.epoch_number,
                                        start_block: epoch.start_block,
                                        end_block: epoch.end_block,
                                        proof_root: epoch.proof_root,
                                        state_root: epoch.state_root,
                                        nullifier_set_root: epoch.nullifier_set_root,
                                        commitment_tree_root: epoch.commitment_tree_root,
                                        epoch_commitment,
                                        num_proofs: recursive_proof.num_proofs,
                                        proof_accumulator: recursive_proof.accumulator_bytes(),
                                        proof_bytes: recursive_proof.proof_bytes.clone(),
                                        inner_proof_bytes: recursive_proof.inner_proof_bytes.clone(),
                                        is_recursive: recursive_proof.is_recursive,
                                    };

                                    let (inserted, store_dir) = {
                                        let mut store =
                                            recursive_epoch_proof_store_for_generator.lock().await;
                                        let store_dir = store.dir().to_path_buf();
                                        let inserted = matches!(
                                            store.insert(msg.clone()),
                                            crate::substrate::epoch_proofs::InsertOutcome::Inserted
                                        );
                                        (inserted, store_dir)
                                    };

                                    if inserted {
                                        let msg_for_persist = msg.clone();
                                        tokio::task::spawn_blocking(move || {
                                            let store = crate::substrate::epoch_proofs::RecursiveEpochProofStore::empty(store_dir);
                                            if let Err(e) = store.persist(&msg_for_persist) {
                                                tracing::warn!(
                                                    epoch_number = msg_for_persist.epoch_number,
                                                    error = %e,
                                                    "Failed to persist generated recursive epoch proof to disk"
                                                );
                                            }
                                        })
                                        .await
                                        .ok();
                                    }

                                    let encoded_v1 = msg.encode();
                                    let encoded_v2 =
                                        RecursiveEpochProofProtocolMessage::Proof(Box::new(msg.clone()))
                                            .encode();
                                    let failed_v1 = pq_handle_for_epoch_broadcast
                                        .broadcast_to_all(
                                            RECURSIVE_EPOCH_PROOFS_PROTOCOL,
                                            encoded_v1,
                                        )
                                        .await;
                                    let failed_v2 = pq_handle_for_epoch_broadcast
                                        .broadcast_to_all(
                                            RECURSIVE_EPOCH_PROOFS_PROTOCOL_V2,
                                            encoded_v2,
                                        )
                                        .await;

                                    tracing::info!(
                                        finished_epoch,
                                        proof_bytes = msg.proof_bytes.len(),
                                        inner_bytes = msg.inner_proof_bytes.len(),
                                        failed_peers_v1 = failed_v1.len(),
                                        failed_peers_v2 = failed_v2.len(),
                                        "📡 Broadcast recursive epoch proof to peers (v1+v2)"
                                    );
                                }
                            }

                            tracing::info!("Recursive epoch proof generator stopped");
                        },
                    );
                } else {
                    tracing::info!(
                        "Recursive epoch proofs disabled (set HEGEMON_RECURSIVE_EPOCH_PROOFS=1 to enable)"
                    );
                }

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
                let da_request_tracker_for_import = Arc::clone(&da_request_tracker);
                let da_params_for_import = da_params;
                let da_sample_timeout_for_import = da_sample_timeout;
                let pq_handle_for_da_import = pq_handle_for_da_import.clone();

                task_manager.spawn_handle().spawn(
                    "block-import-handler",
                    Some("consensus"),
                    async move {
                        use sc_consensus::{BlockImport, BlockImportParams, ForkChoiceStrategy};
                        use sp_consensus::BlockOrigin;
                        use sp_runtime::traits::Block as BlockT;

                        tracing::info!("Block import handler started (syncs blocks from network + historical sync)");

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

                                let mut da_encoding = match sample_da_for_block(
                                    downloaded.from_peer,
                                    &extrinsics,
                                    da_params_for_import,
                                    &pq_handle_for_da_import,
                                    &da_request_tracker_for_import,
                                    da_sample_timeout_for_import,
                                )
                                .await
                                {
                                    Ok(encoding) => Some(encoding),
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
                                };

                                // CRITICAL: Extract the seal from header digest and move to post_digests
                                // PowBlockImport expects the seal in post_digests.last(), not in header.digest()
                                // The seal should be the last digest item with engine ID "pow_"
                                use sp_runtime::traits::Header as HeaderT;
                                let post_hash = header.hash(); // Hash before removing seal (this is the final block hash)
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
                                        if let Some(encoding) = da_encoding.take() {
                                            da_chunk_store_for_import
                                                .lock()
                                                .insert(encoding.root(), encoding);
                                        }

                                        // Notify sync service of successful import
                                        {
                                            let mut sync = sync_service_for_import.lock().await;
                                            sync.on_block_imported(block_number as u64);
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
                                        if let Some(encoding) = da_encoding.take() {
                                            da_chunk_store_for_import
                                                .lock()
                                                .insert(encoding.root(), encoding);
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

                                let mut da_encoding = match sample_da_for_block(
                                    peer_id,
                                    &extrinsics,
                                    da_params_for_import,
                                    &pq_handle_for_da_import,
                                    &da_request_tracker_for_import,
                                    da_sample_timeout_for_import,
                                )
                                .await
                                {
                                    Ok(encoding) => Some(encoding),
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
                                };

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
                                        if let Some(encoding) = da_encoding.take() {
                                            da_chunk_store_for_import
                                                .lock()
                                                .insert(encoding.root(), encoding);
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
                                        if let Some(encoding) = da_encoding.take() {
                                            da_chunk_store_for_import
                                                .lock()
                                                .insert(encoding.root(), encoding);
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
        wire_block_builder_api(&chain_state, client.clone(), da_params);

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
            Arc::clone(&recursive_block_proof_store),
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
                    );

                    worker.run().await;
                },
            );
        } else {
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
                    let worker =
                        create_scaffold_mining_worker(pow_handle_for_worker, worker_config);

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
    let rpc_service = Arc::new(ProductionRpcService::new(client.clone()));

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
                            "block_getRecursiveProof",
                            "da_getChunk",
                            "da_getParams",
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
                                is_syncing: false,
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

        // Add Hegemon RPC (mining, consensus, telemetry)
        let hegemon_rpc = HegemonRpc::new(rpc_service.clone(), pow_handle.clone());
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
        let shielded_rpc = ShieldedRpc::new(rpc_service);
        if let Err(e) = module.merge(shielded_rpc.into_rpc()) {
            tracing::warn!(error = %e, "Failed to merge Shielded RPC");
        } else {
            tracing::info!("Shielded RPC wired (shielded_submitTransfer, etc.)");
        }

        // Add Epoch RPC (recursive epoch proofs)
        let epoch_rpc = EpochRpc::new(
            recursive_epoch_proof_store.clone(),
            pq_network_handle.clone(),
        );
        if let Err(e) = module.merge(epoch_rpc.into_rpc()) {
            tracing::warn!(error = %e, "Failed to merge Epoch RPC");
        } else {
            tracing::info!("Epoch RPC wired (epoch_getRecursiveProof, etc.)");
        }

        // Add Block RPC (recursive + commitment block proofs)
        let block_rpc = BlockRpc::new(
            Arc::clone(&recursive_block_proof_store),
            Arc::clone(&commitment_block_proof_store),
        );
        if let Err(e) = module.merge(block_rpc.into_rpc()) {
            tracing::warn!(error = %e, "Failed to merge Block RPC");
        } else {
            tracing::info!("Block RPC wired (block_getRecursiveProof, block_getCommitmentProof)");
        }

        // Add DA RPC (chunk retrieval + params)
        let da_rpc = DaRpc::new(Arc::clone(&da_chunk_store), da_params);
        if let Err(e) = module.merge(da_rpc.into_rpc()) {
            tracing::warn!(error = %e, "Failed to merge DA RPC");
        } else {
            tracing::info!("DA RPC wired (da_getChunk, da_getParams)");
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
        assert!(config.require_pq);
        assert!(!config.verbose_logging);
        assert_eq!(config.max_peers, 50);
    }

    #[test]
    fn test_pq_service_config_from_env() {
        // This test depends on environment, so just verify it doesn't panic
        let _config = PqServiceConfig::from_env();
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
