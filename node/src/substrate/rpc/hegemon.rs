//! Hegemon Core RPC Endpoints
//!
//! This module provides the core Hegemon-specific RPC endpoints for:
//! - Mining control (start, stop, status)
//! - Consensus status and metrics
//! - Node telemetry
//!
//! # RPC Methods
//!
//! | Method                    | Description                              |
//! |---------------------------|------------------------------------------|
//! | `hegemon_miningStatus`    | Get current mining status                |
//! | `hegemon_startMining`     | Start mining with specified threads      |
//! | `hegemon_stopMining`      | Stop mining                              |
//! | `hegemon_consensusStatus` | Get consensus layer status               |
//! | `hegemon_telemetry`       | Get node telemetry metrics               |
//! | `hegemon_storageFootprint`| Get storage usage statistics             |

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Mining status response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MiningStatus {
    /// Whether mining is currently active
    pub is_mining: bool,
    /// Number of active mining threads
    pub threads: u32,
    /// Current hash rate (hashes per second)
    pub hash_rate: f64,
    /// Total blocks mined by this node
    pub blocks_found: u64,
    /// Current difficulty target
    pub difficulty: u32,
    /// Current block height
    pub block_height: u64,
}

/// Start mining request parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StartMiningParams {
    /// Number of threads to use for mining (defaults to 1)
    #[serde(default = "default_threads")]
    pub threads: u32,
}

fn default_threads() -> u32 {
    1
}

/// Mining control response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MiningControlResponse {
    /// Whether the operation succeeded
    pub success: bool,
    /// Human-readable status message
    pub message: String,
    /// Current mining status after the operation
    pub status: MiningStatus,
}

/// Consensus status response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusStatus {
    /// Current block height
    pub height: u64,
    /// Best block hash (hex-encoded)
    pub best_hash: String,
    /// State root (hex-encoded)
    pub state_root: String,
    /// Nullifier set root (hex-encoded)
    pub nullifier_root: String,
    /// Total supply digest
    pub supply_digest: u128,
    /// Whether the node is syncing
    pub syncing: bool,
    /// Number of connected peers
    pub peers: u32,
}

/// Telemetry snapshot
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Total transactions processed
    pub tx_count: u64,
    /// Total blocks imported
    pub blocks_imported: u64,
    /// Blocks mined (if mining)
    pub blocks_mined: u64,
    /// Current memory usage in bytes
    pub memory_bytes: u64,
    /// Network bytes received
    pub network_rx_bytes: u64,
    /// Network bytes sent
    pub network_tx_bytes: u64,
}

/// Storage footprint response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageFootprint {
    /// Total database size in bytes
    pub total_bytes: u64,
    /// Block storage size
    pub blocks_bytes: u64,
    /// State storage size
    pub state_bytes: u64,
    /// Transaction storage size
    pub transactions_bytes: u64,
    /// Nullifier set size
    pub nullifiers_bytes: u64,
}

/// Hegemon RPC API trait definition
///
/// This trait defines all the custom RPC endpoints for the Hegemon node.
/// It uses jsonrpsee proc macros to generate the server implementation.
#[rpc(server, client, namespace = "hegemon")]
pub trait HegemonApi {
    /// Get current mining status
    ///
    /// Returns information about the node's mining activity including
    /// whether mining is active, thread count, hash rate, and blocks found.
    #[method(name = "miningStatus")]
    async fn mining_status(&self) -> RpcResult<MiningStatus>;

    /// Start mining
    ///
    /// Activates the mining worker with the specified number of threads.
    /// If mining is already active, returns success with current status.
    ///
    /// # Parameters
    /// - `params`: Optional parameters including thread count
    #[method(name = "startMining")]
    async fn start_mining(&self, params: Option<StartMiningParams>) -> RpcResult<MiningControlResponse>;

    /// Stop mining
    ///
    /// Deactivates the mining worker and stops all mining threads.
    #[method(name = "stopMining")]
    async fn stop_mining(&self) -> RpcResult<MiningControlResponse>;

    /// Get consensus status
    ///
    /// Returns the current consensus layer state including block height,
    /// best block hash, sync status, and peer count.
    #[method(name = "consensusStatus")]
    async fn consensus_status(&self) -> RpcResult<ConsensusStatus>;

    /// Get telemetry snapshot
    ///
    /// Returns current telemetry metrics for the node including
    /// uptime, transaction count, memory usage, and network statistics.
    #[method(name = "telemetry")]
    async fn telemetry(&self) -> RpcResult<TelemetrySnapshot>;

    /// Get storage footprint
    ///
    /// Returns storage usage statistics for different components
    /// of the node's persistent storage.
    #[method(name = "storageFootprint")]
    async fn storage_footprint(&self) -> RpcResult<StorageFootprint>;
}

/// Trait for mining handle operations
///
/// This trait abstracts the mining coordinator to allow for testing
/// and different implementations.
pub trait MiningHandle: Send + Sync {
    /// Check if mining is currently active
    fn is_mining(&self) -> bool;
    /// Start mining with specified thread count
    fn start_mining(&self, threads: u32);
    /// Stop mining
    fn stop_mining(&self);
    /// Get current hash rate
    fn hashrate(&self) -> f64;
    /// Get number of blocks found
    fn blocks_found(&self) -> u64;
    /// Get thread count
    fn thread_count(&self) -> u32;
}

/// Trait for node service operations
///
/// This trait abstracts the node service to allow for testing
/// and different implementations.
pub trait HegemonService: Send + Sync {
    /// Get current consensus status
    fn consensus_status(&self) -> ConsensusStatus;
    /// Get telemetry snapshot
    fn telemetry_snapshot(&self) -> TelemetrySnapshot;
    /// Get storage footprint
    fn storage_footprint(&self) -> Result<StorageFootprint, String>;
    /// Get current difficulty
    fn current_difficulty(&self) -> u32;
    /// Get current block height
    fn current_height(&self) -> u64;
}

/// Hegemon RPC implementation
pub struct HegemonRpc<S, P> {
    service: Arc<S>,
    pow_handle: P,
}

impl<S, P> HegemonRpc<S, P>
where
    S: HegemonService + Send + Sync + 'static,
    P: MiningHandle + Clone + Send + Sync + 'static,
{
    /// Create a new Hegemon RPC handler
    pub fn new(service: Arc<S>, pow_handle: P) -> Self {
        Self { service, pow_handle }
    }
}

#[jsonrpsee::core::async_trait]
impl<S, P> HegemonApiServer for HegemonRpc<S, P>
where
    S: HegemonService + Send + Sync + 'static,
    P: MiningHandle + Clone + Send + Sync + 'static,
{
    async fn mining_status(&self) -> RpcResult<MiningStatus> {
        Ok(MiningStatus {
            is_mining: self.pow_handle.is_mining(),
            threads: self.pow_handle.thread_count(),
            hash_rate: self.pow_handle.hashrate(),
            blocks_found: self.pow_handle.blocks_found(),
            difficulty: self.service.current_difficulty(),
            block_height: self.service.current_height(),
        })
    }

    async fn start_mining(&self, params: Option<StartMiningParams>) -> RpcResult<MiningControlResponse> {
        let threads = params.map(|p| p.threads).unwrap_or(1);
        
        self.pow_handle.start_mining(threads);
        
        let status = MiningStatus {
            is_mining: self.pow_handle.is_mining(),
            threads: self.pow_handle.thread_count(),
            hash_rate: self.pow_handle.hashrate(),
            blocks_found: self.pow_handle.blocks_found(),
            difficulty: self.service.current_difficulty(),
            block_height: self.service.current_height(),
        };
        
        Ok(MiningControlResponse {
            success: true,
            message: format!("Mining started with {} thread(s)", threads),
            status,
        })
    }

    async fn stop_mining(&self) -> RpcResult<MiningControlResponse> {
        self.pow_handle.stop_mining();
        
        let status = MiningStatus {
            is_mining: self.pow_handle.is_mining(),
            threads: self.pow_handle.thread_count(),
            hash_rate: self.pow_handle.hashrate(),
            blocks_found: self.pow_handle.blocks_found(),
            difficulty: self.service.current_difficulty(),
            block_height: self.service.current_height(),
        };
        
        Ok(MiningControlResponse {
            success: true,
            message: "Mining stopped".to_string(),
            status,
        })
    }

    async fn consensus_status(&self) -> RpcResult<ConsensusStatus> {
        Ok(self.service.consensus_status())
    }

    async fn telemetry(&self) -> RpcResult<TelemetrySnapshot> {
        Ok(self.service.telemetry_snapshot())
    }

    async fn storage_footprint(&self) -> RpcResult<StorageFootprint> {
        self.service.storage_footprint().map_err(|e| {
            ErrorObjectOwned::owned(
                jsonrpsee::types::error::INTERNAL_ERROR_CODE,
                e,
                None::<()>,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockMiningHandle {
        mining: std::sync::Arc<std::sync::atomic::AtomicBool>,
        threads: u32,
    }

    impl MockMiningHandle {
        fn new() -> Self {
            Self {
                mining: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                threads: 1,
            }
        }
    }

    impl MiningHandle for MockMiningHandle {
        fn is_mining(&self) -> bool {
            self.mining.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn start_mining(&self, _threads: u32) {
            self.mining.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        fn stop_mining(&self) {
            self.mining.store(false, std::sync::atomic::Ordering::SeqCst);
        }

        fn hashrate(&self) -> f64 {
            if self.is_mining() { 1000.0 } else { 0.0 }
        }

        fn blocks_found(&self) -> u64 {
            0
        }

        fn thread_count(&self) -> u32 {
            self.threads
        }
    }

    struct MockService;

    impl HegemonService for MockService {
        fn consensus_status(&self) -> ConsensusStatus {
            ConsensusStatus {
                height: 100,
                best_hash: "0x1234".to_string(),
                state_root: "0x5678".to_string(),
                nullifier_root: "0x9abc".to_string(),
                supply_digest: 1_000_000,
                syncing: false,
                peers: 5,
            }
        }

        fn telemetry_snapshot(&self) -> TelemetrySnapshot {
            TelemetrySnapshot {
                uptime_secs: 3600,
                tx_count: 1000,
                blocks_imported: 100,
                blocks_mined: 10,
                memory_bytes: 512 * 1024 * 1024,
                network_rx_bytes: 1024 * 1024,
                network_tx_bytes: 512 * 1024,
            }
        }

        fn storage_footprint(&self) -> Result<StorageFootprint, String> {
            Ok(StorageFootprint {
                total_bytes: 1024 * 1024 * 100,
                blocks_bytes: 1024 * 1024 * 50,
                state_bytes: 1024 * 1024 * 30,
                transactions_bytes: 1024 * 1024 * 15,
                nullifiers_bytes: 1024 * 1024 * 5,
            })
        }

        fn current_difficulty(&self) -> u32 {
            0x1d00ffff
        }

        fn current_height(&self) -> u64 {
            100
        }
    }

    #[tokio::test]
    async fn test_mining_status() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle);

        let status = rpc.mining_status().await.unwrap();
        assert!(!status.is_mining);
        assert_eq!(status.block_height, 100);
    }

    #[tokio::test]
    async fn test_start_stop_mining() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle);

        // Start mining
        let result = rpc.start_mining(Some(StartMiningParams { threads: 2 })).await.unwrap();
        assert!(result.success);
        assert!(result.status.is_mining);

        // Stop mining
        let result = rpc.stop_mining().await.unwrap();
        assert!(result.success);
        assert!(!result.status.is_mining);
    }

    #[tokio::test]
    async fn test_consensus_status() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle);

        let status = rpc.consensus_status().await.unwrap();
        assert_eq!(status.height, 100);
        assert!(!status.syncing);
        assert_eq!(status.peers, 5);
    }

    #[tokio::test]
    async fn test_telemetry() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle);

        let snapshot = rpc.telemetry().await.unwrap();
        assert_eq!(snapshot.uptime_secs, 3600);
        assert_eq!(snapshot.tx_count, 1000);
    }

    // ============================================================================
    // Phase 11.7.3: Additional Custom RPC Tests
    // ============================================================================

    #[tokio::test]
    async fn test_storage_footprint() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle);

        let footprint = rpc.storage_footprint().await.unwrap();
        assert_eq!(footprint.total_bytes, 1024 * 1024 * 100);
        assert_eq!(footprint.blocks_bytes, 1024 * 1024 * 50);
        assert_eq!(footprint.state_bytes, 1024 * 1024 * 30);
        assert_eq!(footprint.transactions_bytes, 1024 * 1024 * 15);
        assert_eq!(footprint.nullifiers_bytes, 1024 * 1024 * 5);
    }

    #[tokio::test]
    async fn test_mining_lifecycle() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle);

        // Initial state: not mining
        let status = rpc.mining_status().await.unwrap();
        assert!(!status.is_mining);
        assert_eq!(status.hashrate, 0.0);

        // Start mining
        let start_result = rpc.start_mining(Some(StartMiningParams { threads: 4 })).await.unwrap();
        assert!(start_result.success);
        assert!(start_result.status.is_mining);

        // Status should reflect mining
        let status = rpc.mining_status().await.unwrap();
        assert!(status.is_mining);
        assert!(status.hashrate > 0.0);

        // Stop mining
        let stop_result = rpc.stop_mining().await.unwrap();
        assert!(stop_result.success);
        assert!(!stop_result.status.is_mining);

        // Status should reflect stopped
        let status = rpc.mining_status().await.unwrap();
        assert!(!status.is_mining);
    }

    #[tokio::test]
    async fn test_consensus_status_fields() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle);

        let status = rpc.consensus_status().await.unwrap();
        
        // Verify all fields are populated
        assert_eq!(status.height, 100);
        assert_eq!(status.best_hash, "0x1234");
        assert_eq!(status.state_root, "0x5678");
        assert_eq!(status.nullifier_root, "0x9abc");
        assert_eq!(status.supply_digest, 1_000_000);
        assert!(!status.syncing);
        assert_eq!(status.peers, 5);
    }

    #[tokio::test]
    async fn test_telemetry_fields() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle);

        let snapshot = rpc.telemetry().await.unwrap();
        
        // Verify all telemetry fields
        assert_eq!(snapshot.uptime_secs, 3600);
        assert_eq!(snapshot.tx_count, 1000);
        assert_eq!(snapshot.blocks_imported, 100);
        assert_eq!(snapshot.blocks_mined, 10);
        assert_eq!(snapshot.memory_bytes, 512 * 1024 * 1024);
        assert_eq!(snapshot.network_rx_bytes, 1024 * 1024);
        assert_eq!(snapshot.network_tx_bytes, 512 * 1024);
    }

    #[tokio::test]
    async fn test_start_mining_with_default_threads() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle);

        // Start mining with no params (should use default threads)
        let result = rpc.start_mining(None).await.unwrap();
        assert!(result.success);
        assert!(result.status.is_mining);
    }
}
