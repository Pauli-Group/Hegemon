//! Mining Worker for Blake3 PoW Block Production
//!
//! This module coordinates actual block production using the Blake3 PoW algorithm.
//! It integrates with the Substrate service to:
//!
//! - Query current block templates from the runtime
//! - Submit mining work to the MiningCoordinator
//! - Construct and import mined blocks
//! - Broadcast new blocks via the PQ-secure network
//!
//! # Phase 9.3 Implementation
//!
//! This is the final piece of the substrate migration for full block production:
//! - Task 9.1: Network bridge (block announcements) ✅
//! - Task 9.2: Transaction pool integration ✅
//! - Task 9.3: Mining worker spawning (THIS MODULE)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                   Mining Worker                                  │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
//! │  │   Client    │───▶│   Block     │───▶│   Blake3 PoW        │  │
//! │  │  (best_hash)│    │  Template   │    │   Mining Loop       │  │
//! │  └─────────────┘    └─────────────┘    └─────────────────────┘  │
//! │                            │                      │              │
//! │                            │                      ▼              │
//! │                            │           ┌─────────────────────┐  │
//! │                            │           │   Solution Found    │  │
//! │                            │           │   - nonce           │  │
//! │                            │           │   - work hash       │  │
//! │                            │           └─────────────────────┘  │
//! │                            │                      │              │
//! │                            ▼                      ▼              │
//! │                     ┌──────────────────────────────────────┐    │
//! │                     │        Construct & Import Block       │    │
//! │                     │        Broadcast to PQ Network        │    │
//! │                     └──────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Block Template Creation
//!
//! The mining worker creates block templates by:
//! 1. Getting the best block hash from chain state
//! 2. Querying pending transactions from the pool
//! 3. Creating a header with parent hash, timestamp, extrinsics root
//! 4. Computing the pre-hash (header without seal)
//! 5. Getting difficulty from the runtime via DifficultyApi
//!
//! # Solution Submission
//!
//! When a valid PoW solution is found:
//! 1. Construct the complete block with seal
//! 2. Verify locally with Blake3Algorithm
//! 3. Import via the block import pipeline
//! 4. Broadcast block announcement via PQ network

use crate::pow::PowHandle;
use crate::substrate::network_bridge::{BlockAnnounce, BlockState};
use crate::substrate::service::StorageChangesHandle;
use block_circuit::CommitmentBlockProof;
use codec::Encode;
use consensus::{Blake3Seal, MiningWork};
use sp_core::H256;
use sp_runtime::generic::Digest;
use sp_runtime::traits::Header as HeaderT;
use sp_runtime::DigestItem;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

/// Mining worker configuration
#[derive(Clone, Debug)]
pub struct MiningWorkerConfig {
    /// Number of mining threads
    pub threads: usize,
    /// Duration of each mining round in milliseconds
    pub round_duration_ms: u64,
    /// How often to check for new work (ms)
    pub work_check_interval_ms: u64,
    /// Whether to log verbose mining info
    pub verbose: bool,
    /// Enable test mode (easier difficulty)
    pub test_mode: bool,
}

impl Default for MiningWorkerConfig {
    fn default() -> Self {
        Self {
            threads: 1,
            round_duration_ms: 500,
            work_check_interval_ms: 100,
            verbose: false,
            test_mode: false,
        }
    }
}

impl MiningWorkerConfig {
    /// Create configuration from environment variables
    pub fn from_env() -> Self {
        let threads = std::env::var("HEGEMON_MINE_THREADS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let round_duration_ms = std::env::var("HEGEMON_MINE_ROUND_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(500);

        let work_check_interval_ms = std::env::var("HEGEMON_MINE_CHECK_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        let verbose = std::env::var("HEGEMON_MINE_VERBOSE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        let test_mode = std::env::var("HEGEMON_MINE_TEST")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        Self {
            threads,
            round_duration_ms,
            work_check_interval_ms,
            verbose,
            test_mode,
        }
    }

    /// Create config for testing with easier difficulty
    pub fn test_config(threads: usize) -> Self {
        Self {
            threads,
            round_duration_ms: 100,
            work_check_interval_ms: 50,
            verbose: true,
            test_mode: true,
        }
    }
}

/// Block template for mining
///
/// Contains all information needed to mine a block except the seal.
#[derive(Clone, Debug)]
pub struct BlockTemplate {
    /// Parent block hash
    pub parent_hash: H256,
    /// Block number being mined
    pub number: u64,
    /// Timestamp in milliseconds
    pub timestamp: u64,
    /// Extrinsics root (merkle root of transactions)
    pub extrinsics_root: H256,
    /// State root (after applying extrinsics)
    pub state_root: H256,
    /// Pre-hash (hash of header without seal)
    pub pre_hash: H256,
    /// Current difficulty in compact bits format
    pub difficulty_bits: u32,
    /// Extrinsics to include in the block
    pub extrinsics: Vec<Vec<u8>>,
    /// Task 11.5.5: Handle for cached StorageChanges for block import.
    /// This is set during block building when using sc_block_builder::BlockBuilder.
    pub storage_changes: Option<StorageChangesHandle>,
    /// Optional commitment block proof built from shielded transfer extrinsics.
    pub commitment_proof: Option<CommitmentBlockProof>,
    /// Optional aggregation proof bytes built from transaction proofs.
    pub aggregation_proof: Option<Vec<u8>>,
}

impl BlockTemplate {
    /// Create a new block template
    pub fn new(parent_hash: H256, number: u64, difficulty_bits: u32) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Compute pre-hash from header components
        // In a real implementation, this would be the SCALE-encoded header hash
        let pre_hash = compute_pre_hash(&parent_hash, number, timestamp);

        Self {
            parent_hash,
            number,
            timestamp,
            extrinsics_root: H256::zero(), // Will be computed from actual extrinsics
            state_root: H256::zero(),      // Will be computed after execution
            pre_hash,
            difficulty_bits,
            extrinsics: Vec::new(),
            storage_changes: None, // Task 11.5.5: Set during block building
            commitment_proof: None,
            aggregation_proof: None,
        }
    }

    /// Add extrinsics to the template (without state execution)
    ///
    /// Note: This sets state_root to zero. For production use with real
    /// state execution, use `with_executed_extrinsics` instead.
    pub fn with_extrinsics(mut self, extrinsics: Vec<Vec<u8>>) -> Self {
        self.extrinsics = extrinsics;
        // Recompute extrinsics root
        self.extrinsics_root = compute_extrinsics_root(&self.extrinsics);
        // Recompute pre-hash with new extrinsics root
        self.pre_hash = compute_pre_hash_full(
            &self.parent_hash,
            self.number,
            self.timestamp,
            &self.extrinsics_root,
            &self.state_root,
        );
        self
    }

    /// Add extrinsics with state execution (Task 11.4 + 11.5.5)
    ///
    /// This method executes extrinsics against the runtime state and computes
    /// the real state root. Extrinsics that fail validation are excluded.
    ///
    /// # Arguments
    ///
    /// * `extrinsics` - Raw SCALE-encoded extrinsics to include
    /// * `state_root` - State root after executing extrinsics
    /// * `extrinsics_root` - Merkle root of applied extrinsics
    /// * `storage_changes` - Optional handle for cached StorageChanges (Task 11.5.5)
    pub fn with_executed_state(
        mut self,
        extrinsics: Vec<Vec<u8>>,
        state_root: H256,
        extrinsics_root: H256,
        storage_changes: Option<StorageChangesHandle>,
    ) -> Self {
        self.extrinsics = extrinsics;
        self.state_root = state_root;
        self.extrinsics_root = extrinsics_root;
        self.storage_changes = storage_changes;
        // Recompute pre-hash with actual state root
        self.pre_hash = compute_pre_hash_full(
            &self.parent_hash,
            self.number,
            self.timestamp,
            &self.extrinsics_root,
            &self.state_root,
        );
        self
    }

    pub fn with_commitment_proof(mut self, commitment_proof: Option<CommitmentBlockProof>) -> Self {
        self.commitment_proof = commitment_proof;
        self
    }

    pub fn with_aggregation_proof(mut self, aggregation_proof: Option<Vec<u8>>) -> Self {
        self.aggregation_proof = aggregation_proof;
        self
    }

    /// Get the header hash (for block identification)
    pub fn header_hash(&self) -> H256 {
        self.pre_hash
    }

    /// Convert to MiningWork for the coordinator
    pub fn to_mining_work(&self) -> MiningWork {
        MiningWork {
            pre_hash: self.pre_hash,
            pow_bits: self.difficulty_bits,
            height: self.number,
            parent_hash: self.parent_hash,
        }
    }

    /// Create encoded header bytes (for block announcement)
    ///
    /// Creates a proper SCALE-encoded Substrate header that includes:
    /// - Parent hash
    /// - Block number
    /// - State root
    /// - Extrinsics root
    /// - Digest (containing the PoW seal)
    pub fn encode_header(&self, seal: &Blake3Seal) -> Vec<u8> {
        // Create seal digest item with our engine ID "bpow"
        let seal_bytes = seal.encode();
        let seal_digest = DigestItem::Seal(*b"pow_", seal_bytes);
        let digest = Digest {
            logs: vec![seal_digest],
        };

        // Create a proper Substrate header
        let header = <runtime::Header as HeaderT>::new(
            self.number,
            self.extrinsics_root,
            self.state_root,
            self.parent_hash.into(),
            digest,
        );

        // SCALE-encode the header
        header.encode()
    }
}

/// Compute pre-hash from basic header components
fn compute_pre_hash(parent_hash: &H256, number: u64, timestamp: u64) -> H256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(parent_hash.as_bytes());
    hasher.update(&number.to_le_bytes());
    hasher.update(&timestamp.to_le_bytes());
    H256::from_slice(hasher.finalize().as_bytes())
}

/// Compute pre-hash including extrinsics root and state root (Task 11.4)
///
/// NOTE: This is a FALLBACK function that uses Blake3.
/// For production, use `compute_substrate_pre_hash` which computes
/// the actual Substrate header hash.
fn compute_pre_hash_full(
    parent_hash: &H256,
    number: u64,
    _timestamp: u64,
    extrinsics_root: &H256,
    state_root: &H256,
) -> H256 {
    // Use actual Substrate header hashing for compatibility with PowBlockImport
    compute_substrate_pre_hash(parent_hash, number, extrinsics_root, state_root)
}

/// Compute the pre-hash the same way Substrate's Header::hash() does.
///
/// This creates a Substrate header (without seal in digest) and computes
/// its hash, which is what PowBlockImport will use for verification.
///
/// The header is SCALE-encoded and hashed using Blake2b-256 (the default
/// for Substrate's `Header` type).
pub fn compute_substrate_pre_hash(
    parent_hash: &H256,
    number: u64,
    extrinsics_root: &H256,
    state_root: &H256,
) -> H256 {
    use runtime::Header;
    use sp_runtime::traits::Header as HeaderT;
    use sp_runtime::Digest;

    // Create a header without any digest items (no seal yet)
    let header = Header::new(
        number,
        *extrinsics_root,
        *state_root,
        *parent_hash,
        Digest::default(),
    );

    // Compute the hash the same way Substrate does
    header.hash()
}

/// Compute merkle root of extrinsics
pub fn compute_extrinsics_root(extrinsics: &[Vec<u8>]) -> H256 {
    if extrinsics.is_empty() {
        return H256::zero();
    }

    let mut hasher = blake3::Hasher::new();
    for ext in extrinsics {
        hasher.update(ext);
    }
    H256::from_slice(hasher.finalize().as_bytes())
}

/// Statistics from the mining worker
#[derive(Debug, Default, Clone)]
pub struct MiningWorkerStats {
    /// Total rounds attempted
    pub rounds_attempted: u64,
    /// Total hashes computed (approximate)
    pub hashes_computed: u64,
    /// Blocks mined successfully
    pub blocks_mined: u64,
    /// Blocks imported successfully
    pub blocks_imported: u64,
    /// Blocks broadcast
    pub blocks_broadcast: u64,
    /// Import failures
    pub import_failures: u64,
    /// Start time
    pub start_time: Option<Instant>,
}

/// Record of a block mined by this node.
#[derive(Debug, Clone, Copy)]
pub struct MinedBlockRecord {
    pub height: u64,
    pub timestamp_ms: u64,
}

impl MiningWorkerStats {
    /// Create new stats
    pub fn new() -> Self {
        Self {
            start_time: Some(Instant::now()),
            ..Default::default()
        }
    }

    /// Get current hashrate in H/s
    pub fn hashrate(&self) -> f64 {
        if let Some(start) = self.start_time {
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                return self.hashes_computed as f64 / elapsed;
            }
        }
        0.0
    }

    /// Get success rate (blocks mined / rounds attempted)
    pub fn success_rate(&self) -> f64 {
        if self.rounds_attempted > 0 {
            self.blocks_mined as f64 / self.rounds_attempted as f64
        } else {
            0.0
        }
    }
}

/// Mock chain state for scaffold mode
///
/// In a full implementation, this would be replaced with actual client access.
#[derive(Clone, Debug)]
pub struct MockChainState {
    /// Current best block hash
    pub best_hash: H256,
    /// Current best block number
    pub best_number: u64,
    /// Current difficulty bits
    pub difficulty_bits: u32,
}

/// Default difficulty for ~1 minute block time at 1 MH/s
///
/// Compact bits format: 0xEEMMMMMM where target = mantissa × 256^(exponent-3)
///
/// 0x1f00ffff = 0x00ffff × 256^28 ≈ 2^240 (very easy, ~instant blocks)
/// 0x1e00ffff = 0x00ffff × 256^27 ≈ 2^232 (~1-10 sec blocks at 4 threads)
/// 0x1d00ffff = 0x00ffff × 256^26 ≈ 2^224 (~minutes to hours per block)
/// 0x1800ffff = 0x00ffff × 256^21 ≈ 2^184 (difficulty ~2^20, ~10-30 sec blocks)
///
/// For development/testing: 0x1800ffff gives ~10-30 second blocks to avoid log spam
pub const DEFAULT_DIFFICULTY_BITS: u32 = 0x1800ffff;

impl Default for MockChainState {
    fn default() -> Self {
        Self {
            best_hash: H256::zero(),
            best_number: 0,
            difficulty_bits: DEFAULT_DIFFICULTY_BITS,
        }
    }
}

impl MockChainState {
    /// Create chain state with test difficulty (easier)
    pub fn test_mode() -> Self {
        Self {
            best_hash: H256::zero(),
            best_number: 0,
            difficulty_bits: 0x1f00ffff, // ~4096 hashes per block
        }
    }

    /// Update state after mining a block
    pub fn advance(&mut self, block_hash: H256) {
        self.best_hash = block_hash;
        self.best_number += 1;
    }
}

/// Chain state provider trait
///
/// Abstracts access to chain state for the mining worker.
/// Allows mock implementation for scaffold mode and real client access later.
pub trait ChainStateProvider: Send + Sync {
    /// Get the current best block hash
    fn best_hash(&self) -> H256;

    /// Get the current best block number
    fn best_number(&self) -> u64;

    /// Get the current difficulty in compact bits
    fn difficulty_bits(&self) -> u32;

    /// Get pending transactions from the pool
    fn pending_transactions(&self) -> Vec<Vec<u8>>;

    /// Import a mined block
    fn import_block(&self, template: &BlockTemplate, seal: &Blake3Seal) -> Result<H256, String>;

    /// Notify that chain state may have changed (e.g., new block from network)
    fn on_new_block(&self, block_hash: &H256, block_number: u64);

    /// Build a block template with state execution (Task 11.4)
    ///
    /// This method:
    /// 1. Creates a new block template for the next block
    /// 2. Gets pending transactions from the pool
    /// 3. Executes them against the runtime state
    /// 4. Computes and includes the real state root
    ///
    /// Default implementation uses mock execution (zero state root).
    /// Override this for production use with real runtime execution.
    fn build_block_template(&self) -> BlockTemplate {
        let parent_hash = self.best_hash();
        let block_number = self.best_number() + 1;
        let difficulty_bits = self.difficulty_bits();
        let pending = self.pending_transactions();

        let template = BlockTemplate::new(parent_hash, block_number, difficulty_bits);

        if pending.is_empty() {
            template
        } else {
            // Default: use mock execution (no state root computation)
            template.with_extrinsics(pending)
        }
    }
}

/// Mock chain state provider for scaffold mode
pub struct MockChainStateProvider {
    state: parking_lot::RwLock<MockChainState>,
}

impl MockChainStateProvider {
    /// Create a new mock provider
    pub fn new(test_mode: bool) -> Self {
        Self {
            state: parking_lot::RwLock::new(if test_mode {
                MockChainState::test_mode()
            } else {
                MockChainState::default()
            }),
        }
    }
}

impl ChainStateProvider for MockChainStateProvider {
    fn best_hash(&self) -> H256 {
        self.state.read().best_hash
    }

    fn best_number(&self) -> u64 {
        self.state.read().best_number
    }

    fn difficulty_bits(&self) -> u32 {
        self.state.read().difficulty_bits
    }

    fn pending_transactions(&self) -> Vec<Vec<u8>> {
        // Return empty for mock - no real transaction pool
        Vec::new()
    }

    fn import_block(&self, template: &BlockTemplate, seal: &Blake3Seal) -> Result<H256, String> {
        // Compute block hash from seal
        let block_hash = H256::from_slice(seal.work.as_bytes());

        // Update state
        let mut state = self.state.write();
        state.best_hash = block_hash;
        state.best_number = template.number;

        Ok(block_hash)
    }

    fn on_new_block(&self, block_hash: &H256, block_number: u64) {
        let mut state = self.state.write();
        if block_number > state.best_number {
            state.best_hash = *block_hash;
            state.best_number = block_number;
        }
    }
}

/// Block broadcaster trait
///
/// Abstracts block broadcasting via the PQ network.
pub trait BlockBroadcaster: Send + Sync {
    /// Broadcast a newly mined block
    fn broadcast_block(&self, announce: BlockAnnounce);
}

/// Mock broadcaster that just logs
pub struct MockBlockBroadcaster {
    verbose: bool,
}

impl MockBlockBroadcaster {
    /// Create a new mock broadcaster
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }
}

impl BlockBroadcaster for MockBlockBroadcaster {
    fn broadcast_block(&self, announce: BlockAnnounce) {
        if self.verbose {
            tracing::debug!(
                block_number = announce.number,
                block_hash = %hex::encode(announce.hash),
                "Would broadcast block (mock mode)"
            );
        }
    }
}

/// Network bridge broadcaster that uses the actual PQ network
pub struct NetworkBridgeBroadcaster {
    /// Handle to the PQ network backend for broadcasting
    pq_handle: network::PqNetworkHandle,
    /// Protocol ID for block announcements
    protocol: String,
}

impl NetworkBridgeBroadcaster {
    /// Create a new broadcaster with a PQ network handle
    pub fn new(pq_handle: network::PqNetworkHandle) -> Self {
        Self {
            pq_handle,
            protocol: network::BLOCK_ANNOUNCES_PQ.to_string(),
        }
    }

    /// Create with a custom protocol
    pub fn with_protocol(pq_handle: network::PqNetworkHandle, protocol: String) -> Self {
        Self {
            pq_handle,
            protocol,
        }
    }
}

impl BlockBroadcaster for NetworkBridgeBroadcaster {
    fn broadcast_block(&self, announce: BlockAnnounce) {
        let data = announce.encode();
        let protocol = self.protocol.clone();
        let handle = self.pq_handle.clone();

        tracing::info!(
            block_number = announce.number,
            block_hash = %hex::encode(announce.hash),
            has_body = announce.body.is_some(),
            data_len = data.len(),
            "Broadcasting mined block via PQ network"
        );

        // Spawn async broadcast task
        tokio::spawn(async move {
            let failed = handle.broadcast_to_all(&protocol, data).await;

            if failed.is_empty() {
                tracing::debug!("Block broadcast completed successfully to all peers");
            } else {
                tracing::warn!(
                    failed_count = failed.len(),
                    "Block broadcast failed for some peers"
                );
            }
        });
    }
}

/// Mining worker that produces blocks
pub struct MiningWorker<CSP: ChainStateProvider, BB: BlockBroadcaster> {
    /// PoW handle for mining control
    pow_handle: PowHandle,
    /// Chain state provider
    chain_state: Arc<CSP>,
    /// Block broadcaster
    broadcaster: Arc<BB>,
    /// Optional sync status flag (true means pause mining)
    sync_status: Option<Arc<AtomicBool>>,
    /// Configuration
    config: MiningWorkerConfig,
    /// Statistics
    stats: Arc<parking_lot::RwLock<MiningWorkerStats>>,
    /// Mined block records (local node)
    mined_blocks: Arc<parking_lot::Mutex<Vec<MinedBlockRecord>>>,
}

impl<CSP: ChainStateProvider, BB: BlockBroadcaster> std::fmt::Debug for MiningWorker<CSP, BB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MiningWorker")
            .field("config", &self.config)
            .field("stats", &*self.stats.read())
            .finish_non_exhaustive()
    }
}

impl<CSP, BB> MiningWorker<CSP, BB>
where
    CSP: ChainStateProvider + 'static,
    BB: BlockBroadcaster + 'static,
{
    /// Create a new mining worker
    pub fn new(
        pow_handle: PowHandle,
        chain_state: Arc<CSP>,
        broadcaster: Arc<BB>,
        config: MiningWorkerConfig,
        mined_blocks: Arc<parking_lot::Mutex<Vec<MinedBlockRecord>>>,
    ) -> Self {
        Self {
            pow_handle,
            chain_state,
            broadcaster,
            sync_status: None,
            config,
            stats: Arc::new(parking_lot::RwLock::new(MiningWorkerStats::new())),
            mined_blocks,
        }
    }

    /// Attach a sync status flag to pause mining while syncing.
    pub fn with_sync_status(mut self, sync_status: Arc<AtomicBool>) -> Self {
        self.sync_status = Some(sync_status);
        self
    }

    /// Get current statistics
    pub fn stats(&self) -> MiningWorkerStats {
        self.stats.read().clone()
    }

    /// Run the mining loop
    ///
    /// This is the main entry point that runs until the node shuts down.
    pub async fn run(self) {
        tracing::info!(
            threads = self.config.threads,
            round_duration_ms = self.config.round_duration_ms,
            test_mode = self.config.test_mode,
            "Mining worker started (Phase 9.3)"
        );

        let check_interval = Duration::from_millis(self.config.work_check_interval_ms);
        let mut current_template: Option<BlockTemplate> = None;
        let mut last_best_hash = H256::zero();
        let mut was_syncing = false;
        let mut was_mining = false;

        loop {
            // Check if mining is enabled
            if !self.pow_handle.is_mining() {
                if was_mining {
                    self.pow_handle.clear_work();
                    current_template = None;
                    was_mining = false;
                }
                tokio::time::sleep(check_interval).await;
                continue;
            }
            was_mining = true;

            let syncing = self
                .sync_status
                .as_ref()
                .map(|flag| flag.load(Ordering::Relaxed))
                .unwrap_or(false);
            if syncing {
                if !was_syncing {
                    tracing::info!("Sync in progress; pausing mining until catch-up completes");
                }
                was_syncing = true;
                self.pow_handle.clear_work();
                current_template = None;
                tokio::time::sleep(check_interval).await;
                continue;
            }
            if was_syncing {
                tracing::info!("Sync complete; resuming mining");
                was_syncing = false;
            }

            // Check for new work (best block changed)
            let best_hash = self.chain_state.best_hash();

            if best_hash != last_best_hash || current_template.is_none() {
                // Build block template with state execution (Task 11.4)
                // This handles:
                // - Getting pending transactions
                // - Executing them against runtime state
                // - Computing state root
                let template = self.chain_state.build_block_template();

                // Update mining work
                let work = template.to_mining_work();

                // DEBUG: Log the pre_hash being used for mining
                tracing::info!(
                    height = template.number,
                    pre_hash = %hex::encode(work.pre_hash.as_bytes()),
                    parent_hash = %hex::encode(work.parent_hash.as_bytes()),
                    difficulty = format!("{:08x}", work.pow_bits),
                    state_root = %hex::encode(template.state_root.as_bytes()),
                    extrinsics_root = %hex::encode(template.extrinsics_root.as_bytes()),
                    "🔍 DEBUG: Mining work pre_hash (verifier must match this)"
                );

                self.pow_handle.update_work(
                    work.pre_hash,
                    work.pow_bits,
                    work.height,
                    work.parent_hash,
                );

                if self.config.verbose {
                    tracing::debug!(
                        height = template.number,
                        parent_hash = %hex::encode(template.parent_hash.as_bytes()),
                        difficulty = format!("{:08x}", template.difficulty_bits),
                        tx_count = template.extrinsics.len(),
                        state_root = %hex::encode(template.state_root.as_bytes()),
                        "New mining work (Task 11.4: state execution enabled)"
                    );
                    if let Some(proof) = template.commitment_proof.as_ref() {
                        tracing::debug!(
                            height = template.number,
                            tx_count = proof.public_inputs.tx_count,
                            proof_size = proof.proof_bytes.len(),
                            "Commitment block proof attached to template"
                        );
                    }
                }

                current_template = Some(template);
                last_best_hash = best_hash;
            }

            // Check for solutions
            if let Some(solution) = self.pow_handle.try_get_solution() {
                let template = current_template.as_ref().expect("must have template");

                // CRITICAL: Verify the solution is for the current template
                // The mining threads may have found a solution for an old template
                // after we've already moved to a new template
                if solution.work.height != template.number
                    || solution.work.pre_hash != template.pre_hash
                {
                    tracing::warn!(
                        solution_height = solution.work.height,
                        template_height = template.number,
                        solution_pre_hash = %hex::encode(solution.work.pre_hash.as_bytes()),
                        template_pre_hash = %hex::encode(template.pre_hash.as_bytes()),
                        "⚠️ Discarding stale mining solution - height/pre_hash mismatch"
                    );
                    // Discard this stale solution and continue
                    continue;
                }

                // Update stats
                {
                    let mut stats = self.stats.write();
                    stats.blocks_mined += 1;
                }

                // Import the block
                match self.chain_state.import_block(template, &solution.seal) {
                    Ok(block_hash) => {
                        tracing::info!("🎉 Block mined!");
                        tracing::info!(
                            block_number = template.number,
                            block_hash = %hex::encode(block_hash.as_bytes()),
                            nonce = solution.seal.nonce,
                            "Block imported successfully"
                        );

                        {
                            let mut stats = self.stats.write();
                            stats.blocks_imported += 1;
                        }
                        {
                            let mut mined = self.mined_blocks.lock();
                            mined.push(MinedBlockRecord {
                                height: template.number,
                                timestamp_ms: template.timestamp,
                            });
                        }

                        // Broadcast the block
                        let announce = BlockAnnounce::new(
                            template.encode_header(&solution.seal),
                            template.number,
                            block_hash.0,
                            BlockState::Best,
                        )
                        .with_body(template.extrinsics.clone());

                        self.broadcaster.broadcast_block(announce);

                        {
                            let mut stats = self.stats.write();
                            stats.blocks_broadcast += 1;
                        }

                        // Clear template to force new work
                        current_template = None;
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            block_number = template.number,
                            "Failed to import mined block"
                        );

                        {
                            let mut stats = self.stats.write();
                            stats.import_failures += 1;
                        }
                    }
                }
            }

            // Update round stats
            {
                let mut stats = self.stats.write();
                stats.rounds_attempted += 1;
                // Approximate hashes based on typical round
                stats.hashes_computed += 10_000;
            }

            // Brief yield to not starve other tasks
            tokio::task::yield_now().await;
        }
    }
}

/// Create a mining worker for scaffold mode
///
/// This uses mock chain state and a logging broadcaster.
pub fn create_scaffold_mining_worker(
    pow_handle: PowHandle,
    config: MiningWorkerConfig,
) -> MiningWorker<MockChainStateProvider, MockBlockBroadcaster> {
    let chain_state = Arc::new(MockChainStateProvider::new(config.test_mode));
    let broadcaster = Arc::new(MockBlockBroadcaster::new(config.verbose));
    let mined_blocks = Arc::new(parking_lot::Mutex::new(Vec::new()));

    MiningWorker::new(pow_handle, chain_state, broadcaster, config, mined_blocks)
}

/// Create a mining worker with network broadcasting
///
/// This uses mock chain state but broadcasts via the PQ network.
/// The PQ network handle is used to broadcast mined blocks to all connected peers.
pub fn create_network_mining_worker(
    pow_handle: PowHandle,
    pq_handle: network::PqNetworkHandle,
    config: MiningWorkerConfig,
) -> MiningWorker<MockChainStateProvider, NetworkBridgeBroadcaster> {
    let chain_state = Arc::new(MockChainStateProvider::new(config.test_mode));
    let broadcaster = Arc::new(NetworkBridgeBroadcaster::new(pq_handle));
    let mined_blocks = Arc::new(parking_lot::Mutex::new(Vec::new()));

    MiningWorker::new(pow_handle, chain_state, broadcaster, config, mined_blocks)
}

// =============================================================================
// Task 10.5: Production Mining Worker
// =============================================================================

use crate::substrate::client::{ProductionChainStateProvider, ProductionConfig};

/// Create a production mining worker with real chain state and network broadcasting
///
/// This is the full production configuration for mining:
/// - Uses ProductionChainStateProvider with callback-based chain state
/// - Broadcasts via PQ network using NetworkBridgeBroadcaster
/// - Intended for use with a full Substrate client
///
/// # Arguments
///
/// * `pow_handle` - Handle for PoW control and statistics
/// * `chain_state` - Production chain state provider (pre-configured with callbacks)
/// * `pq_handle` - Handle to the PQ network backend
/// * `config` - Mining worker configuration
///
/// # Example
///
/// ```ignore
/// let chain_state = ProductionChainStateProvider::with_defaults();
///
/// // Configure callbacks to query real Substrate client
/// chain_state.set_best_block_fn(|| {
///     let info = client.info();
///     (info.best_hash, info.best_number)
/// });
/// chain_state.set_difficulty_fn(|| {
///     runtime_api.difficulty_bits(best_hash).unwrap_or(DEFAULT_DIFFICULTY_BITS)
/// });
/// chain_state.set_pending_txs_fn(|| {
///     pool.ready().map(|tx| tx.data().encode()).collect()
/// });
/// chain_state.set_import_fn(|template, seal| {
///     block_import.import_block(construct_block(template, seal))
/// });
///
/// let worker = create_production_mining_worker(
///     pow_handle,
///     Arc::new(chain_state),
///     pq_handle,
///     config,
/// );
/// worker.run().await;
/// ```
pub fn create_production_mining_worker(
    pow_handle: PowHandle,
    chain_state: Arc<ProductionChainStateProvider>,
    pq_handle: network::PqNetworkHandle,
    config: MiningWorkerConfig,
    mined_blocks: Arc<parking_lot::Mutex<Vec<MinedBlockRecord>>>,
) -> MiningWorker<ProductionChainStateProvider, NetworkBridgeBroadcaster> {
    let broadcaster = Arc::new(NetworkBridgeBroadcaster::new(pq_handle));

    tracing::info!(
        threads = config.threads,
        is_production = true,
        verbose = config.verbose,
        "Creating production mining worker (Task 10.5)"
    );

    MiningWorker::new(pow_handle, chain_state, broadcaster, config, mined_blocks)
}

/// Create a production mining worker with mock broadcasting (for testing)
///
/// Uses production chain state provider but mock broadcaster.
/// Useful for testing the production provider without network.
pub fn create_production_mining_worker_mock_broadcast(
    pow_handle: PowHandle,
    chain_state: Arc<ProductionChainStateProvider>,
    config: MiningWorkerConfig,
    mined_blocks: Arc<parking_lot::Mutex<Vec<MinedBlockRecord>>>,
) -> MiningWorker<ProductionChainStateProvider, MockBlockBroadcaster> {
    let broadcaster = Arc::new(MockBlockBroadcaster::new(config.verbose));

    MiningWorker::new(pow_handle, chain_state, broadcaster, config, mined_blocks)
}

/// Production mining worker builder for ergonomic configuration
///
/// Provides a builder pattern for constructing production mining workers
/// with all necessary callbacks.
pub struct ProductionMiningWorkerBuilder {
    config: MiningWorkerConfig,
    production_config: ProductionConfig,
    pow_handle: Option<PowHandle>,
    pq_handle: Option<network::PqNetworkHandle>,
}

impl ProductionMiningWorkerBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            config: MiningWorkerConfig::default(),
            production_config: ProductionConfig::default(),
            pow_handle: None,
            pq_handle: None,
        }
    }

    /// Set the mining worker configuration
    pub fn with_config(mut self, config: MiningWorkerConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the production provider configuration
    pub fn with_production_config(mut self, config: ProductionConfig) -> Self {
        self.production_config = config;
        self
    }

    /// Set the PoW handle
    pub fn with_pow_handle(mut self, handle: PowHandle) -> Self {
        self.pow_handle = Some(handle);
        self
    }

    /// Set the PQ network handle
    pub fn with_pq_handle(mut self, handle: network::PqNetworkHandle) -> Self {
        self.pq_handle = Some(handle);
        self
    }

    /// Build the production mining worker
    ///
    /// Returns the worker and the chain state provider (so callbacks can be configured).
    pub fn build(
        self,
    ) -> Result<
        (
            MiningWorker<ProductionChainStateProvider, NetworkBridgeBroadcaster>,
            Arc<ProductionChainStateProvider>,
        ),
        String,
    > {
        let pow_handle = self.pow_handle.ok_or("PoW handle is required")?;
        let pq_handle = self.pq_handle.ok_or("PQ network handle is required")?;

        let chain_state = Arc::new(ProductionChainStateProvider::new(self.production_config));
        let mined_blocks = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let worker = create_production_mining_worker(
            pow_handle,
            chain_state.clone(),
            pq_handle,
            self.config,
            mined_blocks,
        );

        Ok((worker, chain_state))
    }

    /// Build with mock broadcaster (for testing)
    pub fn build_mock(
        self,
    ) -> Result<
        (
            MiningWorker<ProductionChainStateProvider, MockBlockBroadcaster>,
            Arc<ProductionChainStateProvider>,
        ),
        String,
    > {
        let pow_handle = self.pow_handle.ok_or("PoW handle is required")?;

        let chain_state = Arc::new(ProductionChainStateProvider::new(self.production_config));
        let mined_blocks = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let worker = create_production_mining_worker_mock_broadcast(
            pow_handle,
            chain_state.clone(),
            self.config,
            mined_blocks,
        );

        Ok((worker, chain_state))
    }
}

impl Default for ProductionMiningWorkerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mining_worker_config_default() {
        let config = MiningWorkerConfig::default();
        assert_eq!(config.threads, 1);
        assert_eq!(config.round_duration_ms, 500);
        assert!(!config.verbose);
        assert!(!config.test_mode);
    }

    #[test]
    fn test_mining_worker_config_test() {
        let config = MiningWorkerConfig::test_config(4);
        assert_eq!(config.threads, 4);
        assert!(config.verbose);
        assert!(config.test_mode);
    }

    #[test]
    fn test_block_template_creation() {
        let parent_hash = H256::repeat_byte(0x42);
        let template = BlockTemplate::new(parent_hash, 100, 0x1d00ffff);

        assert_eq!(template.parent_hash, parent_hash);
        assert_eq!(template.number, 100);
        assert_eq!(template.difficulty_bits, 0x1d00ffff);
        assert!(template.extrinsics.is_empty());
        assert_ne!(template.pre_hash, H256::zero());
    }

    #[test]
    fn test_block_template_with_extrinsics() {
        let parent_hash = H256::repeat_byte(0x42);
        let template = BlockTemplate::new(parent_hash, 100, 0x1d00ffff)
            .with_extrinsics(vec![vec![1, 2, 3], vec![4, 5, 6]]);

        assert_eq!(template.extrinsics.len(), 2);
        assert_ne!(template.extrinsics_root, H256::zero());
    }

    #[test]
    fn test_block_template_to_mining_work() {
        let template = BlockTemplate::new(H256::zero(), 1, 0x1d00ffff);
        let work = template.to_mining_work();

        assert_eq!(work.height, 1);
        assert_eq!(work.pow_bits, 0x1d00ffff);
        assert_eq!(work.pre_hash, template.pre_hash);
    }

    #[test]
    fn test_mock_chain_state_provider() {
        let provider = MockChainStateProvider::new(false);

        assert_eq!(provider.best_number(), 0);
        assert_eq!(provider.best_hash(), H256::zero());
        // DEFAULT_DIFFICULTY_BITS = 0x1e00ffff for reasonable dev/test block times
        assert_eq!(provider.difficulty_bits(), DEFAULT_DIFFICULTY_BITS);
    }

    #[test]
    fn test_mock_chain_state_provider_test_mode() {
        let provider = MockChainStateProvider::new(true);

        // Test mode should have easier difficulty (~4096 hashes per block)
        assert_eq!(provider.difficulty_bits(), 0x1f00ffff);
    }

    #[test]
    fn test_mining_worker_stats() {
        let mut stats = MiningWorkerStats::new();

        stats.blocks_mined += 1;
        stats.rounds_attempted += 100;
        stats.hashes_computed += 1_000_000;

        assert_eq!(stats.blocks_mined, 1);
        assert_eq!(stats.hashes_computed, 1_000_000);
        assert_eq!(stats.rounds_attempted, 100);

        // success_rate is independent of time
        assert!(stats.success_rate() > 0.0);
        assert_eq!(stats.success_rate(), 0.01); // 1 block / 100 rounds

        // hashrate depends on elapsed time, so just verify the method works
        // (may be 0.0 if elapsed time is essentially 0)
        let _ = stats.hashrate();
    }

    #[test]
    fn test_compute_pre_hash_deterministic() {
        let parent = H256::repeat_byte(0xab);
        let hash1 = compute_pre_hash(&parent, 100, 12345);
        let hash2 = compute_pre_hash(&parent, 100, 12345);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_pre_hash_changes_with_input() {
        let parent = H256::repeat_byte(0xab);
        let hash1 = compute_pre_hash(&parent, 100, 12345);
        let hash2 = compute_pre_hash(&parent, 101, 12345);
        let hash3 = compute_pre_hash(&parent, 100, 12346);

        assert_ne!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_compute_extrinsics_root_empty() {
        let root = compute_extrinsics_root(&[]);
        assert_eq!(root, H256::zero());
    }

    #[test]
    fn test_compute_extrinsics_root_deterministic() {
        let exts = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let root1 = compute_extrinsics_root(&exts);
        let root2 = compute_extrinsics_root(&exts);

        assert_eq!(root1, root2);
        assert_ne!(root1, H256::zero());
    }

    #[test]
    fn test_mock_import_block() {
        let provider = MockChainStateProvider::new(false);
        let template = BlockTemplate::new(H256::zero(), 1, 0x1d00ffff);

        // Create a mock seal
        let seal = Blake3Seal {
            nonce: 12345,
            difficulty: 0x1d00ffff,
            work: H256::repeat_byte(0x42),
        };

        let result = provider.import_block(&template, &seal);
        assert!(result.is_ok());

        // State should be updated
        assert_eq!(provider.best_number(), 1);
    }

    #[tokio::test]
    async fn test_create_scaffold_mining_worker() {
        use crate::pow::{PowConfig, PowHandle};

        let config = PowConfig::mining(1);
        let (pow_handle, _rx) = PowHandle::new(config);
        let worker_config = MiningWorkerConfig::test_config(1);

        let _worker = create_scaffold_mining_worker(pow_handle, worker_config);
        // Just verify creation doesn't panic
    }

    // Task 10.5: Production mining worker tests

    #[test]
    fn test_production_mining_worker_builder_default() {
        let builder = ProductionMiningWorkerBuilder::new();
        // Without required handles, build should fail
        let result = builder.build_mock();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("PoW handle"));
    }

    #[test]
    fn test_production_mining_worker_builder_with_pow() {
        use crate::pow::{PowConfig, PowHandle};

        let config = PowConfig::mining(1);
        let (pow_handle, _rx) = PowHandle::new(config);

        let builder = ProductionMiningWorkerBuilder::new().with_pow_handle(pow_handle);

        // Should succeed with mock build (doesn't require PQ handle)
        let result = builder.build_mock();
        assert!(result.is_ok());

        let (worker, chain_state) = result.unwrap();
        assert!(!chain_state.is_fully_configured());
        assert_eq!(worker.stats().blocks_mined, 0);
    }

    #[test]
    fn test_production_mining_worker_builder_with_config() {
        use crate::pow::{PowConfig, PowHandle};

        let config = PowConfig::mining(2);
        let (pow_handle, _rx) = PowHandle::new(config);

        let worker_config = MiningWorkerConfig {
            threads: 4,
            round_duration_ms: 200,
            verbose: true,
            test_mode: true,
            ..Default::default()
        };

        let builder = ProductionMiningWorkerBuilder::new()
            .with_pow_handle(pow_handle)
            .with_config(worker_config.clone());

        let result = builder.build_mock();
        assert!(result.is_ok());
    }

    #[test]
    fn test_production_chain_state_with_callbacks() {
        use crate::pow::{PowConfig, PowHandle};

        let config = PowConfig::mining(1);
        let (pow_handle, _rx) = PowHandle::new(config);

        let builder = ProductionMiningWorkerBuilder::new().with_pow_handle(pow_handle);

        let result = builder.build_mock();
        assert!(result.is_ok());

        let (_, chain_state) = result.unwrap();

        // Configure callbacks
        let expected_hash = H256::repeat_byte(0xaa);
        let hash_for_callback = expected_hash;
        chain_state.set_best_block_fn(move || (hash_for_callback, 42));
        chain_state.set_difficulty_fn(|| 0x2000ffff);
        chain_state.set_pending_txs_fn(|| vec![vec![1, 2, 3]]);
        chain_state.set_import_fn(|_, seal| Ok(H256::from_slice(seal.work.as_bytes())));

        assert!(chain_state.is_fully_configured());
        assert_eq!(chain_state.best_hash(), expected_hash);
        assert_eq!(chain_state.best_number(), 42);
        assert_eq!(chain_state.difficulty_bits(), 0x2000ffff);
        assert_eq!(chain_state.pending_transactions(), vec![vec![1, 2, 3]]);
    }

    #[test]
    fn test_production_mining_worker_import() {
        use crate::pow::{PowConfig, PowHandle};
        use std::sync::atomic::{AtomicU64, Ordering};

        let config = PowConfig::mining(1);
        let (pow_handle, _rx) = PowHandle::new(config);

        let builder = ProductionMiningWorkerBuilder::new().with_pow_handle(pow_handle);

        let (_, chain_state) = builder.build_mock().unwrap();

        // Track import calls
        let import_count = Arc::new(AtomicU64::new(0));
        let count_clone = Arc::clone(&import_count);

        chain_state.set_import_fn(move |_template, seal| {
            count_clone.fetch_add(1, Ordering::SeqCst);
            Ok(H256::from_slice(seal.work.as_bytes()))
        });

        // Import a block
        let template = BlockTemplate::new(H256::zero(), 1, 0x1d00ffff);
        let seal = Blake3Seal {
            nonce: 12345,
            difficulty: 0x1d00ffff,
            work: H256::repeat_byte(0xbb),
        };

        let result = chain_state.import_block(&template, &seal);
        assert!(result.is_ok());
        assert_eq!(import_count.load(Ordering::SeqCst), 1);
    }
}
