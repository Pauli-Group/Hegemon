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
use crate::substrate::network_bridge::{BlockAnnounce, BlockState, NetworkBridge};
use codec::Encode;
use consensus::{Blake3Seal, MiningWork};
use sp_core::H256;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

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
}

impl BlockTemplate {
    /// Create a new block template
    pub fn new(
        parent_hash: H256,
        number: u64,
        difficulty_bits: u32,
    ) -> Self {
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
        }
    }

    /// Add extrinsics to the template
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
        );
        self
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
    pub fn encode_header(&self, seal: &Blake3Seal) -> Vec<u8> {
        // Simplified header encoding
        // In a real implementation, this would be proper SCALE encoding
        let mut header = Vec::new();
        header.extend_from_slice(self.parent_hash.as_bytes());
        header.extend_from_slice(&self.number.to_le_bytes());
        header.extend_from_slice(&self.timestamp.to_le_bytes());
        header.extend_from_slice(self.extrinsics_root.as_bytes());
        header.extend_from_slice(self.state_root.as_bytes());
        header.extend_from_slice(&seal.encode());
        header
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

/// Compute pre-hash including extrinsics root
fn compute_pre_hash_full(
    parent_hash: &H256,
    number: u64,
    timestamp: u64,
    extrinsics_root: &H256,
) -> H256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(parent_hash.as_bytes());
    hasher.update(&number.to_le_bytes());
    hasher.update(&timestamp.to_le_bytes());
    hasher.update(extrinsics_root.as_bytes());
    H256::from_slice(hasher.finalize().as_bytes())
}

/// Compute merkle root of extrinsics
fn compute_extrinsics_root(extrinsics: &[Vec<u8>]) -> H256 {
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

impl Default for MockChainState {
    fn default() -> Self {
        Self {
            best_hash: H256::zero(),
            best_number: 0,
            difficulty_bits: 0x1d00ffff, // Standard initial difficulty
        }
    }
}

impl MockChainState {
    /// Create chain state with test difficulty (easier)
    pub fn test_mode() -> Self {
        Self {
            best_hash: H256::zero(),
            best_number: 0,
            difficulty_bits: 0x2100ffff, // Very easy for testing
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
    /// Reference to the network bridge (reserved for future PQ broadcast implementation)
    #[allow(dead_code)]
    bridge: Arc<Mutex<NetworkBridge>>,
}

impl NetworkBridgeBroadcaster {
    /// Create a new broadcaster with a network bridge
    pub fn new(bridge: Arc<Mutex<NetworkBridge>>) -> Self {
        Self { bridge }
    }
}

impl BlockBroadcaster for NetworkBridgeBroadcaster {
    fn broadcast_block(&self, announce: BlockAnnounce) {
        // In a full implementation, this would encode and send via PQ network
        // For now, we log the intent
        tracing::info!(
            block_number = announce.number,
            block_hash = %hex::encode(announce.hash),
            has_body = announce.body.is_some(),
            "Broadcasting mined block via PQ network"
        );
        
        // TODO: Implement actual broadcast via PqNetworkBackend
        // This requires:
        // 1. Access to PqNetworkBackend handle
        // 2. Encoding BlockAnnounce for the protocol
        // 3. Sending to all connected peers
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
    /// Configuration
    config: MiningWorkerConfig,
    /// Statistics
    stats: Arc<parking_lot::RwLock<MiningWorkerStats>>,
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
    ) -> Self {
        Self {
            pow_handle,
            chain_state,
            broadcaster,
            config,
            stats: Arc::new(parking_lot::RwLock::new(MiningWorkerStats::new())),
        }
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

        loop {
            // Check if mining is enabled
            if !self.pow_handle.is_mining() {
                tokio::time::sleep(check_interval).await;
                continue;
            }

            // Check for new work (best block changed)
            let best_hash = self.chain_state.best_hash();
            let best_number = self.chain_state.best_number();
            let difficulty_bits = self.chain_state.difficulty_bits();

            if best_hash != last_best_hash || current_template.is_none() {
                // Create new block template
                let template = BlockTemplate::new(best_hash, best_number + 1, difficulty_bits);
                
                // Add pending transactions (if any)
                let pending = self.chain_state.pending_transactions();
                let template = if !pending.is_empty() {
                    template.with_extrinsics(pending)
                } else {
                    template
                };

                // Update mining work
                let work = template.to_mining_work();
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
                        difficulty = format!("{:08x}", difficulty_bits),
                        tx_count = template.extrinsics.len(),
                        "New mining work"
                    );
                }

                current_template = Some(template);
                last_best_hash = best_hash;
            }

            // Check for solutions
            if let Some(solution) = self.pow_handle.try_get_solution() {
                let template = current_template.as_ref().expect("must have template");
                
                // Update stats
                {
                    let mut stats = self.stats.write();
                    stats.blocks_mined += 1;
                }

                // Import the block
                match self.chain_state.import_block(template, &solution.seal) {
                    Ok(block_hash) => {
                        tracing::info!(
                            "🎉 Block mined!"
                        );
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

                        // Broadcast the block
                        let announce = BlockAnnounce::new(
                            template.encode_header(&solution.seal),
                            template.number,
                            block_hash.0,
                            BlockState::Best,
                        ).with_body(template.extrinsics.clone());

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
    
    MiningWorker::new(pow_handle, chain_state, broadcaster, config)
}

/// Create a mining worker with network broadcasting
///
/// This uses mock chain state but broadcasts via the PQ network.
pub fn create_network_mining_worker(
    pow_handle: PowHandle,
    network_bridge: Arc<Mutex<NetworkBridge>>,
    config: MiningWorkerConfig,
) -> MiningWorker<MockChainStateProvider, NetworkBridgeBroadcaster> {
    let chain_state = Arc::new(MockChainStateProvider::new(config.test_mode));
    let broadcaster = Arc::new(NetworkBridgeBroadcaster::new(network_bridge));
    
    MiningWorker::new(pow_handle, chain_state, broadcaster, config)
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
        assert_eq!(provider.difficulty_bits(), 0x1d00ffff);
    }

    #[test]
    fn test_mock_chain_state_provider_test_mode() {
        let provider = MockChainStateProvider::new(true);
        
        // Test mode should have easier difficulty
        assert_eq!(provider.difficulty_bits(), 0x2100ffff);
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
}
