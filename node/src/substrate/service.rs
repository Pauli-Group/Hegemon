//! Hegemon Substrate Node Service
//!
//! This module provides the core service implementation for the Substrate-based
//! Hegemon node, including:
//! - Partial node components setup
//! - Full node service initialization
//! - Block import pipeline configuration with Blake3 PoW
//! - Mining coordination
//! - PQ-secure network transport (Phase 3)
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
//! # PQ Network Layer (Phase 3)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     PQ-Secure Transport Layer                           │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────────────────────────────────────────────────────────┐│
//! │  │                   Hybrid Handshake Protocol                         ││
//! │  │  ┌─────────────────┐   ┌──────────────────────────────────────────┐││
//! │  │  │ X25519 ECDH     │ + │ ML-KEM-768 Encapsulation                 │││
//! │  │  │ (classical)     │   │ (post-quantum)                           │││
//! │  │  └─────────────────┘   └──────────────────────────────────────────┘││
//! │  │                                    │                                ││
//! │  │                                    ▼                                ││
//! │  │  ┌─────────────────────────────────────────────────────────────────┐││
//! │  │  │        Combined Key = HKDF(X25519_SS || ML-KEM_SS)              │││
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
//! # Note on Dependency Versions
//!
//! This is Phase 2+3 of the Substrate migration. Full implementation requires
//! aligned Polkadot SDK dependencies. Due to version fragmentation on crates.io,
//! production use should switch to git dependencies from the official
//! polkadot-sdk repository.

use crate::pow::{PowConfig, PowHandle};
use crate::substrate::network::{PqNetworkConfig, PqNetworkKeypair};
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};

/// Node service components after partial initialization
///
/// Full implementation will include:
/// - TFullClient with WasmExecutor
/// - TFullBackend for state storage  
/// - BasicPool for transaction pool
/// - LongestChain for select chain
/// - PowBlockImport for PoW consensus
/// - PQ-secure network keypair
pub struct PartialComponents {
    /// Task manager for spawning async tasks
    pub task_manager: TaskManager,
    /// PoW mining handle
    pub pow_handle: PowHandle,
    /// PQ network keypair for secure connections
    pub network_keypair: Option<PqNetworkKeypair>,
    /// PQ network configuration
    pub network_config: PqNetworkConfig,
}

/// Full node service components
pub struct FullComponents {
    /// Partial components
    pub partial: PartialComponents,
    /// Network handle (placeholder)
    pub network: (),
    /// RPC handle (placeholder)  
    pub rpc: (),
}

/// Creates partial node components.
///
/// This sets up the core components needed before the full service:
/// - Task manager for async coordination
/// - PoW mining coordinator
///
/// # Phase 2 Implementation Notes
///
/// Full implementation requires:
/// 1. Aligned Polkadot SDK dependencies (use git deps from polkadot-sdk)
/// 2. Runtime implementing RuntimeApi trait  
/// 3. WASM binary for runtime execution
/// 4. Blake3Algorithm implementing PowAlgorithm trait
pub fn new_partial(config: &Configuration) -> Result<PartialComponents, ServiceError> {
    // Create basic task manager for CLI commands
    let task_manager = TaskManager::new(config.tokio_handle.clone(), None)
        .map_err(|e| ServiceError::Other(format!("Failed to create task manager: {}", e)))?;

    // Initialize PoW mining coordinator
    // Default to non-mining mode; caller can enable via PowHandle
    let pow_config = if std::env::var("HEGEMON_MINE").is_ok() {
        let threads = std::env::var("HEGEMON_MINE_THREADS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        PowConfig::mining(threads)
    } else {
        PowConfig::non_mining()
    };
    
    let (pow_handle, _pow_events) = PowHandle::new(pow_config);

    // Initialize PQ network configuration (Phase 3)
    let pq_network_config = PqNetworkConfig {
        listen_addresses: vec!["/ip4/0.0.0.0/tcp/30333".to_string()],
        bootstrap_nodes: Vec::new(),
        enable_pq_transport: true,
        hybrid_mode: true, // Use both X25519 and ML-KEM-768
        max_peers: 50,
        connection_timeout_secs: 30,
        require_pq: true, // Require PQ handshake for all connections
        verbose_logging: false,
    };

    // Generate PQ network keypair for this node
    let network_keypair = match PqNetworkKeypair::generate() {
        Ok(keypair) => {
            tracing::info!(
                peer_id = %keypair.peer_id(),
                "Generated PQ network keypair"
            );
            Some(keypair)
        }
        Err(e) => {
            tracing::warn!("Failed to generate PQ network keypair: {}", e);
            None
        }
    };

    tracing::info!(
        "Hegemon node partial components initialized (Phase 2+3 - PoW + PQ ready)"
    );

    Ok(PartialComponents {
        task_manager,
        pow_handle,
        network_keypair,
        network_config: pq_network_config,
    })
}

/// Creates a full node service.
///
/// This starts all node components including:
/// 1. Client with WASM executor (placeholder)
/// 2. Networking with libp2p (placeholder)
/// 3. Transaction pool (placeholder)
/// 4. Block import with Blake3 PoW verification
/// 5. RPC server with mining control endpoints
/// 6. Optional mining worker
///
/// # PoW Block Import Pipeline
///
/// ```text
/// Network ──▶ Import Queue ──▶ PowBlockImport ──▶ Client
///                 │                   │
///                 │                   ▼
///                 │            Blake3Algorithm
///                 │              (verify seal)
///                 │
///                 ▼
///            PowVerifier
///           (decode seal)
/// ```
///
/// # Mining Flow
///
/// ```text
/// 1. Get best block from client
/// 2. Query difficulty from runtime (pow pallet)
/// 3. Create block template
/// 4. Compute pre_hash
/// 5. Send to MiningCoordinator
/// 6. Wait for solution
/// 7. Construct block with seal
/// 8. Import locally
/// 9. Broadcast to network
/// ```
pub fn new_full(config: Configuration) -> Result<TaskManager, ServiceError> {
    let PartialComponents {
        task_manager,
        pow_handle,
        network_keypair,
        network_config,
    } = new_partial(&config)?;

    let chain_name = config.chain_spec.name().to_string();
    let role = format!("{:?}", config.role);

    tracing::info!(
        chain = %chain_name,
        role = %role,
        pq_enabled = %network_config.enable_pq_transport,
        "Hegemon node started (Phase 2+3 - Blake3 PoW + PQ Transport)"
    );

    // Log PQ network configuration
    if let Some(ref keypair) = network_keypair {
        tracing::info!(
            peer_id = %keypair.peer_id(),
            hybrid_mode = %network_config.hybrid_mode,
            "PQ-secure network transport configured"
        );
    }

    // Log PoW configuration
    if pow_handle.is_mining() {
        tracing::info!(
            hashrate = %pow_handle.hashrate(),
            "Mining enabled"
        );
    } else {
        tracing::info!("Mining disabled (set HEGEMON_MINE=1 to enable)");
    }

    // Phase 2 TODO: Full implementation requires:
    // 
    // 1. Client setup:
    //    let executor = WasmExecutor::new(...);
    //    let (client, backend, keystore, task_manager) = 
    //        sc_service::new_full_parts::<Block, RuntimeApi, Executor>(&config)?;
    //
    // 2. PoW block import:
    //    let pow_algorithm = Blake3Algorithm::new(client.clone());
    //    let pow_block_import = PowBlockImport::new(
    //        client.clone(),
    //        client.clone(),
    //        pow_algorithm.clone(),
    //        0, // check_inherents_after
    //        select_chain.clone(),
    //    );
    //
    // 3. Import queue:
    //    let import_queue = sc_consensus_pow::import_queue(
    //        Box::new(pow_block_import.clone()),
    //        None,
    //        pow_algorithm.clone(),
    //        &task_manager.spawn_essential_handle(),
    //        config.prometheus_registry(),
    //    )?;
    //
    // 4. Network:
    //    let (network, system_rpc_tx, network_starter) = 
    //        sc_service::build_network(sc_service::BuildNetworkParams {
    //            config: &config,
    //            client: client.clone(),
    //            transaction_pool: transaction_pool.clone(),
    //            spawn_handle: task_manager.spawn_handle(),
    //            import_queue,
    //            block_announce_validator_builder: None,
    //            warp_sync_params: None,
    //        })?;
    //
    // 5. Mining task (if enabled):
    //    if config.role.is_authority() {
    //        let mining_worker = MiningWorker::new(
    //            client.clone(),
    //            pow_algorithm,
    //            pow_handle.clone(),
    //        );
    //        task_manager.spawn_essential_handle().spawn_blocking(
    //            "hegemon-mining",
    //            Some("mining"),
    //            mining_worker.run(),
    //        );
    //    }
    //
    // 6. RPC:
    //    let rpc_extensions = crate::rpc::create_full(
    //        client.clone(),
    //        transaction_pool.clone(),
    //        pow_handle.clone(),
    //    );

    tracing::info!(
        "Phase 2+3 scaffold complete. Full implementation requires:"
    );
    tracing::info!("  - Aligned polkadot-sdk git dependencies");
    tracing::info!("  - Runtime WASM binary with DifficultyApi");
    tracing::info!("  - sc-consensus-pow block import pipeline");
    tracing::info!("  - PQ transport integration with sc-network");

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
            target_block_time_ms: 10_000, // 10 seconds
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
            .unwrap_or(10_000);

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
        assert_eq!(config.target_block_time_ms, 10_000);
    }

    #[test]
    fn test_mining_config_from_env() {
        // This test depends on environment, so just verify it doesn't panic
        let _config = MiningConfig::from_env();
    }
}

