//! PoW Integration for Hegemon Substrate Node
//!
//! This module bridges the consensus crate's PoW implementation with the
//! Substrate node service, providing:
//!
//! - Block import with PoW verification
//! - Mining worker management
//! - Block production coordination
//!
//! # Usage
//!
//! This module is used by the node service to set up the PoW block import
//! pipeline and manage mining operations.

use consensus::{Blake3Seal, MiningCoordinator, MiningSolution, MiningWork};
use sp_core::H256;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// PoW mining configuration
#[derive(Clone, Debug)]
pub struct PowConfig {
    /// Number of mining threads
    pub threads: usize,
    /// Whether to enable mining
    pub enable_mining: bool,
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            threads: 1,
            enable_mining: false,
        }
    }
}

impl PowConfig {
    /// Create config for a mining node
    pub fn mining(threads: usize) -> Self {
        Self {
            threads: threads.max(1),
            enable_mining: true,
        }
    }

    /// Create config for a non-mining node
    pub fn non_mining() -> Self {
        Self {
            threads: 0,
            enable_mining: false,
        }
    }
}

/// Events from the PoW mining system
#[derive(Clone, Debug)]
pub enum PowEvent {
    /// Mining has started
    MiningStarted { threads: usize },
    /// Mining has stopped
    MiningStopped,
    /// A new work template is being mined
    NewWork { height: u64, difficulty: u32 },
    /// A solution was found
    SolutionFound { height: u64, nonce: u64 },
    /// Mining hashrate update
    HashrateUpdate { hashrate: f64 },
}

/// Handle to control mining from the service
pub struct PowHandle {
    /// Mining coordinator
    coordinator: Arc<parking_lot::Mutex<MiningCoordinator>>,
    /// Configuration
    config: PowConfig,
    /// Event sender
    event_tx: mpsc::UnboundedSender<PowEvent>,
}

impl PowHandle {
    /// Create a new PoW handle
    pub fn new(config: PowConfig) -> (Self, mpsc::UnboundedReceiver<PowEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let coordinator = MiningCoordinator::new(config.threads);

        let handle = Self {
            coordinator: Arc::new(parking_lot::Mutex::new(coordinator)),
            config,
            event_tx,
        };

        (handle, event_rx)
    }

    /// Start mining
    pub fn start_mining(&self) {
        if !self.config.enable_mining {
            warn!("Mining not enabled in configuration");
            return;
        }

        let mut coordinator = self.coordinator.lock();
        if coordinator.is_mining() {
            debug!("Mining already running");
            return;
        }

        coordinator.start();
        info!(threads = self.config.threads, "Mining started");

        let _ = self.event_tx.send(PowEvent::MiningStarted {
            threads: self.config.threads,
        });
    }

    /// Stop mining
    pub fn stop_mining(&self) {
        let mut coordinator = self.coordinator.lock();
        if !coordinator.is_mining() {
            debug!("Mining not running");
            return;
        }

        coordinator.stop();
        info!("Mining stopped");

        let _ = self.event_tx.send(PowEvent::MiningStopped);
    }

    /// Update the work template for mining
    pub fn update_work(&self, pre_hash: H256, pow_bits: u32, height: u64, parent_hash: H256) {
        let work = MiningWork {
            pre_hash,
            pow_bits,
            height,
            parent_hash,
        };

        let coordinator = self.coordinator.lock();
        coordinator.update_work(work);

        debug!(height, difficulty = pow_bits, "New mining work");

        let _ = self.event_tx.send(PowEvent::NewWork {
            height,
            difficulty: pow_bits,
        });
    }

    /// Clear current work (e.g., when a new block arrives from the network)
    pub fn clear_work(&self) {
        let coordinator = self.coordinator.lock();
        coordinator.clear_work();
    }

    /// Try to get a mining solution
    pub fn try_get_solution(&self) -> Option<MiningSolution> {
        let coordinator = self.coordinator.lock();
        let solution = coordinator.try_recv_solution();

        if let Some(ref sol) = solution {
            info!(
                height = sol.work.height,
                nonce = sol.seal.nonce,
                "Found PoW solution"
            );

            let _ = self.event_tx.send(PowEvent::SolutionFound {
                height: sol.work.height,
                nonce: sol.seal.nonce,
            });
        }

        solution
    }

    /// Check if mining is active
    pub fn is_mining(&self) -> bool {
        let coordinator = self.coordinator.lock();
        coordinator.is_mining()
    }

    /// Get current hashrate
    pub fn hashrate(&self) -> f64 {
        let coordinator = self.coordinator.lock();
        coordinator.hashrate()
    }

    /// Get number of blocks found
    pub fn blocks_found(&self) -> u64 {
        let coordinator = self.coordinator.lock();
        coordinator.blocks_found()
    }
}

impl Clone for PowHandle {
    fn clone(&self) -> Self {
        Self {
            coordinator: Arc::clone(&self.coordinator),
            config: self.config.clone(),
            event_tx: self.event_tx.clone(),
        }
    }
}

/// Implementation of MiningHandle trait for RPC integration (Phase 11.7)
#[cfg(feature = "substrate")]
impl crate::substrate::rpc::MiningHandle for PowHandle {
    fn is_mining(&self) -> bool {
        let coordinator = self.coordinator.lock();
        coordinator.is_mining()
    }

    fn start_mining(&self, _threads: u32) {
        // Note: Thread count is configured at creation time
        // For now, just start with existing config
        self.start_mining();
    }

    fn stop_mining(&self) {
        PowHandle::stop_mining(self);
    }

    fn hashrate(&self) -> f64 {
        PowHandle::hashrate(self)
    }

    fn blocks_found(&self) -> u64 {
        PowHandle::blocks_found(self)
    }

    fn thread_count(&self) -> u32 {
        self.config.threads as u32
    }
}

/// Block import result for PoW blocks
#[derive(Clone, Debug)]
pub struct PowBlockImportResult {
    /// Whether the block was imported successfully
    pub success: bool,
    /// The block hash
    pub hash: H256,
    /// The block height
    pub height: u64,
    /// Whether this block was mined locally
    pub is_own: bool,
}

/// PoW block verifier for the import pipeline
pub struct PowVerifier {
    /// Expected difficulty (from runtime)
    expected_difficulty: u32,
}

impl PowVerifier {
    /// Create a new PoW verifier
    pub fn new(expected_difficulty: u32) -> Self {
        Self {
            expected_difficulty,
        }
    }

    /// Verify a PoW seal
    pub fn verify(&self, pre_hash: &H256, seal: &Blake3Seal) -> Result<(), PowVerifyError> {
        // Check difficulty matches expected
        if seal.difficulty != self.expected_difficulty {
            return Err(PowVerifyError::DifficultyMismatch {
                expected: self.expected_difficulty,
                got: seal.difficulty,
            });
        }

        // Verify the seal is valid
        if !consensus::verify_seal(pre_hash, seal) {
            return Err(PowVerifyError::InvalidSeal);
        }

        Ok(())
    }

    /// Update expected difficulty
    pub fn set_difficulty(&mut self, difficulty: u32) {
        self.expected_difficulty = difficulty;
    }
}

/// Errors from PoW verification
#[derive(Debug, Clone, thiserror::Error)]
pub enum PowVerifyError {
    #[error("PoW difficulty mismatch: expected {expected}, got {got}")]
    DifficultyMismatch { expected: u32, got: u32 },

    #[error("Invalid PoW seal")]
    InvalidSeal,

    #[error("Seal decode failed")]
    DecodeFailed,
}

/// RPC methods for mining control
pub mod rpc {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// Mining status response
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct MiningStatus {
        pub mining: bool,
        pub threads: usize,
        pub hashrate: f64,
        pub blocks_found: u64,
    }

    /// Start mining request
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct StartMiningRequest {
        pub threads: Option<usize>,
    }

    /// Start mining response
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct StartMiningResponse {
        pub success: bool,
        pub message: String,
    }

    /// Stop mining response
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct StopMiningResponse {
        pub success: bool,
        pub message: String,
    }

    /// RPC handler for mining operations
    pub struct MiningRpc {
        handle: PowHandle,
    }

    impl MiningRpc {
        /// Create a new mining RPC handler
        pub fn new(handle: PowHandle) -> Self {
            Self { handle }
        }

        /// Get mining status
        pub fn status(&self) -> MiningStatus {
            MiningStatus {
                mining: self.handle.is_mining(),
                threads: self.handle.config.threads,
                hashrate: self.handle.hashrate(),
                blocks_found: self.handle.blocks_found(),
            }
        }

        /// Start mining
        pub fn start(&self, _threads: Option<usize>) -> StartMiningResponse {
            self.handle.start_mining();

            StartMiningResponse {
                success: true,
                message: format!(
                    "Mining started with {} thread(s)",
                    self.handle.config.threads
                ),
            }
        }

        /// Stop mining
        pub fn stop(&self) -> StopMiningResponse {
            self.handle.stop_mining();

            StopMiningResponse {
                success: true,
                message: "Mining stopped".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_config_default() {
        let config = PowConfig::default();
        assert_eq!(config.threads, 1);
        assert!(!config.enable_mining);
    }

    #[test]
    fn test_pow_config_mining() {
        let config = PowConfig::mining(4);
        assert_eq!(config.threads, 4);
        assert!(config.enable_mining);
    }

    #[test]
    fn test_pow_config_mining_min_threads() {
        let config = PowConfig::mining(0);
        assert_eq!(config.threads, 1); // Minimum 1 thread
    }

    #[test]
    fn test_pow_verifier() {
        // Use easy difficulty for reliable test completion
        let difficulty = 0x2100ffff; // Very easy (~16 hashes expected)
        let verifier = PowVerifier::new(difficulty);

        // Create a valid seal using the mining function
        let pre_hash = H256::repeat_byte(0xab);
        let seal = consensus::mine_round(&pre_hash, difficulty, 0, 1_000_000)
            .expect("should find seal with easy difficulty");

        assert!(verifier.verify(&pre_hash, &seal).is_ok());
    }

    #[test]
    fn test_pow_verifier_wrong_difficulty() {
        let verifier = PowVerifier::new(0x1d00ffff);
        let pre_hash = H256::repeat_byte(0xab);

        // Create seal with different difficulty
        let seal =
            consensus::mine_round(&pre_hash, 0x2100ffff, 0, 100_000).expect("should find seal");

        let result = verifier.verify(&pre_hash, &seal);
        assert!(matches!(
            result,
            Err(PowVerifyError::DifficultyMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn test_pow_handle_lifecycle() {
        let config = PowConfig::mining(1);
        let (handle, _rx) = PowHandle::new(config);

        assert!(!handle.is_mining());

        handle.start_mining();
        assert!(handle.is_mining());

        handle.stop_mining();
        assert!(!handle.is_mining());
    }
}
