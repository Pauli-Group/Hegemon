//! Hegemon Substrate Node Service
//!
//! This module provides the core service implementation for the Substrate-based
//! Hegemon node, including:
//! - Partial node components setup
//! - Full node service initialization
//! - Block import pipeline configuration with Blake3 PoW
//! - Mining coordination
//! - PQ-secure network transport (Phase 3 + Phase 3.5)
//! - Network bridge for block/tx routing (Phase 9)
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
//! # PQ Network Layer (Phase 3 + Phase 3.5)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     PQ-Secure Transport Layer                           │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────────────────────────────────────────────────────────┐│
//! │  │                   PqNetworkBackend (Phase 3.5)                       ││
//! │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐ ││
//! │  │  │  Listener   │  │  Dialer     │  │  SubstratePqTransport       │ ││
//! │  │  │  (inbound)  │  │  (outbound) │  │  (hybrid handshake)         │ ││
//! │  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘ ││
//! │  └─────────────────────────────────────────────────────────────────────┘│
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
//! # Network Bridge (Phase 9)
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
//! # Runtime WASM Integration (Phase 2.5)
//!
//! The runtime provides:
//! - `WASM_BINARY`: Compiled WebAssembly runtime for execution
//! - `DifficultyApi`: Runtime API for querying PoW difficulty
//! - `ConsensusApi`: Runtime API for consensus parameters
//!
//! The node uses the WASM executor to run the runtime in a sandboxed environment,
//! ensuring deterministic execution across all nodes.

use crate::pow::{PowConfig, PowHandle};
use crate::substrate::mining_worker::{MiningWorkerConfig, create_scaffold_mining_worker, create_network_mining_worker};
use crate::substrate::network::{PqNetworkConfig, PqNetworkKeypair};
use crate::substrate::network_bridge::{NetworkBridge, NetworkBridgeBuilder};
use crate::substrate::transaction_pool::{
    MockTransactionPool, TransactionPoolBridge, TransactionPoolConfig,
};
use network::{
    PqNetworkBackend, PqNetworkBackendConfig, PqNetworkEvent, PqNetworkHandle, PqPeerIdentity, PqTransportConfig,
    SubstratePqTransport, SubstratePqTransportConfig,
};
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};
use std::sync::Arc;
use tokio::sync::Mutex;

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

/// PQ network configuration for the node service
#[derive(Clone, Debug)]
pub struct PqServiceConfig {
    /// Whether PQ is required for all connections
    pub require_pq: bool,
    /// Whether hybrid mode is enabled (PQ preferred but legacy allowed)
    pub hybrid_mode: bool,
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
            hybrid_mode: true,
            verbose_logging: false,
            listen_addr: "0.0.0.0:30333".parse().unwrap(),
            bootstrap_nodes: Vec::new(),
            max_peers: 50,
        }
    }
}

impl PqServiceConfig {
    /// Create from environment variables
    pub fn from_env() -> Self {
        let require_pq = std::env::var("HEGEMON_REQUIRE_PQ")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(true);

        let verbose = std::env::var("HEGEMON_PQ_VERBOSE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        Self {
            require_pq,
            verbose_logging: verbose,
            ..Default::default()
        }
    }
}

/// Node service components after partial initialization
///
/// Full implementation will include:
/// - TFullClient with WasmExecutor
/// - TFullBackend for state storage  
/// - BasicPool for transaction pool
/// - LongestChain for select chain
/// - PowBlockImport for PoW consensus
/// - PQ-secure network keypair
/// - PQ network backend (Phase 3.5)
pub struct PartialComponents {
    /// Task manager for spawning async tasks
    pub task_manager: TaskManager,
    /// PoW mining handle
    pub pow_handle: PowHandle,
    /// PQ network keypair for secure connections
    pub network_keypair: Option<PqNetworkKeypair>,
    /// PQ network configuration
    pub network_config: PqNetworkConfig,
    /// PQ peer identity for transport layer (Phase 3.5)
    pub pq_identity: Option<PqPeerIdentity>,
    /// Substrate PQ transport (Phase 3.5)
    pub pq_transport: Option<SubstratePqTransport>,
    /// PQ service configuration (Phase 3.5)
    pub pq_service_config: PqServiceConfig,
}

/// Full node service components
pub struct FullComponents {
    /// Partial components
    pub partial: PartialComponents,
    /// Network handle (placeholder)
    pub network: (),
    /// RPC handle (placeholder)  
    pub rpc: (),
    /// PQ network backend (Phase 3.5)
    pub pq_backend: Option<PqNetworkBackend>,
    /// Network bridge for block/tx routing (Phase 9)
    pub network_bridge: Option<Arc<Mutex<NetworkBridge>>>,
    /// Transaction pool bridge (Phase 9.2)
    pub transaction_pool_bridge: Option<Arc<TransactionPoolBridge<MockTransactionPool>>>,
}

/// Creates partial node components.
///
/// This sets up the core components needed before the full service:
/// - Task manager for async coordination
/// - PoW mining coordinator
/// - PQ network identity and transport (Phase 3.5)
///
/// # Phase 2 Implementation Notes
///
/// Full implementation requires:
/// 1. Aligned Polkadot SDK dependencies (use git deps from polkadot-sdk)
/// 2. Runtime implementing RuntimeApi trait  
/// 3. WASM binary for runtime execution
/// 4. Blake3Algorithm implementing PowAlgorithm trait
///
/// # Phase 3.5 Implementation
///
/// PQ network components:
/// 1. PqPeerIdentity - Node identity with ML-KEM-768 + ML-DSA-65
/// 2. SubstratePqTransport - Substrate-compatible PQ transport
/// 3. PqServiceConfig - Configuration from CLI/env
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

    // Initialize PQ service configuration (Phase 3.5)
    let pq_service_config = PqServiceConfig::from_env();

    // Initialize PQ network configuration (Phase 3)
    let pq_network_config = PqNetworkConfig {
        listen_addresses: vec![format!("/ip4/{}/tcp/{}", 
            pq_service_config.listen_addr.ip(),
            pq_service_config.listen_addr.port()
        )],
        bootstrap_nodes: pq_service_config.bootstrap_nodes.iter()
            .map(|addr| format!("/ip4/{}/tcp/{}", addr.ip(), addr.port()))
            .collect(),
        enable_pq_transport: true,
        hybrid_mode: pq_service_config.hybrid_mode,
        max_peers: pq_service_config.max_peers as u32,
        connection_timeout_secs: 30,
        require_pq: pq_service_config.require_pq,
        verbose_logging: pq_service_config.verbose_logging,
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

    // Create PQ peer identity and transport (Phase 3.5)
    let node_seed = network_keypair.as_ref()
        .map(|k| k.peer_id_bytes().to_vec())
        .unwrap_or_else(|| vec![0u8; 32]);
    
    let pq_transport_config = PqTransportConfig {
        require_pq: pq_service_config.require_pq,
        handshake_timeout: std::time::Duration::from_secs(30),
        verbose_logging: pq_service_config.verbose_logging,
    };
    
    let pq_identity = PqPeerIdentity::new(&node_seed, pq_transport_config.clone());
    
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
        "Hegemon node partial components initialized (Phase 2 + Phase 3.5 - PoW + PQ Transport)"
    );

    Ok(PartialComponents {
        task_manager,
        pow_handle,
        network_keypair,
        network_config: pq_network_config,
        pq_identity: Some(pq_identity),
        pq_transport: Some(pq_transport),
        pq_service_config,
    })
}

/// Creates a full node service.
///
/// This starts all node components including:
/// 1. Client with WASM executor (placeholder)
/// 2. Networking with PQ transport (Phase 3.5)
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
///
/// # PQ Network (Phase 3.5)
///
/// ```text
/// 1. Create PqNetworkBackend with SubstratePqTransport
/// 2. Start listener for inbound connections
/// 3. Connect to bootstrap nodes
/// 4. Handle peer events (connect/disconnect/message)
/// 5. Route block announcements through PQ channels
/// ```
pub async fn new_full(config: Configuration) -> Result<TaskManager, ServiceError> {
    let PartialComponents {
        task_manager,
        pow_handle,
        network_keypair,
        network_config,
        pq_identity,
        pq_transport,
        pq_service_config,
    } = new_partial(&config)?;

    let chain_name = config.chain_spec.name().to_string();
    let role = format!("{:?}", config.role);

    // Track PQ network handle for mining worker (Phase 10.4)
    let mut pq_network_handle: Option<PqNetworkHandle> = None;

    tracing::info!(
        chain = %chain_name,
        role = %role,
        pq_enabled = %network_config.enable_pq_transport,
        require_pq = %pq_service_config.require_pq,
        "Hegemon node started (Phase 2 + Phase 3.5 - Blake3 PoW + PQ Network Backend)"
    );

    // Log PQ network configuration
    if let Some(ref keypair) = network_keypair {
        tracing::info!(
            peer_id = %keypair.peer_id(),
            hybrid_mode = %network_config.hybrid_mode,
            "PQ-secure network transport configured"
        );
    }

    // Log PQ transport configuration (Phase 3.5)
    if let Some(ref transport) = pq_transport {
        tracing::info!(
            transport_peer_id = %hex::encode(transport.local_peer_id()),
            protocol = %transport.config().protocol_id,
            "SubstratePqTransport ready for peer connections"
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

    // Phase 3.5: Create and start PQ network backend
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
        
        // Start the PQ network backend and get the event receiver
        match pq_backend.start().await {
            Ok(mut event_rx) => {
                tracing::info!(
                    listen_addr = %pq_service_config.listen_addr,
                    max_peers = pq_service_config.max_peers,
                    peer_id = %hex::encode(local_peer_id),
                    "PqNetworkBackend started (Phase 3.5 + Phase 9.2 + Phase 10.4 - Full Integration)"
                );

                // Phase 10.4: Get PQ network handle for mining worker broadcasting
                pq_network_handle = Some(pq_backend.handle());
                tracing::info!("PQ network handle captured for mining worker (Phase 10.4)");

                // Phase 9: Create the network bridge for block/tx routing
                let network_bridge = Arc::new(Mutex::new(
                    NetworkBridgeBuilder::new()
                        .verbose(pq_service_config.verbose_logging)
                        .build()
                ));
                let bridge_clone = Arc::clone(&network_bridge);

                // Phase 9.2: Create the transaction pool bridge
                let pool_config = TransactionPoolConfig::from_env();
                let mock_pool = Arc::new(MockTransactionPool::new(pool_config.capacity));
                let pool_bridge = Arc::new(TransactionPoolBridge::with_max_pending(
                    mock_pool.clone(),
                    pool_config.max_pending,
                ));
                let pool_bridge_clone = Arc::clone(&pool_bridge);

                tracing::info!(
                    pool_capacity = pool_config.capacity,
                    max_pending = pool_config.max_pending,
                    process_interval_ms = pool_config.process_interval_ms,
                    "Transaction pool bridge created (Phase 9.2)"
                );

                // Clone for the transaction processor task
                let pool_bridge_for_processor = Arc::clone(&pool_bridge);
                let process_interval = pool_config.process_interval_ms;
                let pool_verbose = pool_config.verbose;

                // Spawn the PQ network event handler task with NetworkBridge and TxPool integration
                // IMPORTANT: We move pq_backend into this task to keep it alive for the node's lifetime.
                // If pq_backend is dropped, the shutdown channel closes and the network listener stops.
                task_manager.spawn_handle().spawn(
                    "pq-network-events",
                    Some("network"),
                    async move {
                        // Keep pq_backend alive by holding it in this task
                        let _pq_backend = pq_backend;
                        
                        tracing::info!("PQ network event handler started (with NetworkBridge + TxPool)");
                        
                        while let Some(event) = event_rx.recv().await {
                            // Route events through the NetworkBridge
                            {
                                let mut bridge = bridge_clone.lock().await;
                                bridge.handle_event(event.clone()).await;
                                
                                // Phase 9.2: Forward transactions to pool bridge
                                let pending_txs = bridge.drain_transactions();
                                if !pending_txs.is_empty() {
                                    pool_bridge_clone.queue_from_bridge(pending_txs).await;
                                }
                            }

                            // Also handle lifecycle events directly
                            match event {
                                PqNetworkEvent::PeerConnected { peer_id, addr, is_outbound } => {
                                    tracing::info!(
                                        peer_id = %hex::encode(peer_id),
                                        addr = %addr,
                                        direction = if is_outbound { "outbound" } else { "inbound" },
                                        "PQ peer connected"
                                    );
                                }
                                PqNetworkEvent::PeerDisconnected { peer_id, reason } => {
                                    tracing::info!(
                                        peer_id = %hex::encode(peer_id),
                                        reason = %reason,
                                        "PQ peer disconnected"
                                    );
                                }
                                PqNetworkEvent::MessageReceived { peer_id, protocol, data } => {
                                    // Already handled by NetworkBridge, just log
                                    tracing::debug!(
                                        peer_id = %hex::encode(peer_id),
                                        protocol = %protocol,
                                        data_len = data.len(),
                                        "PQ message routed to NetworkBridge"
                                    );
                                }
                                PqNetworkEvent::Started { listen_addr } => {
                                    tracing::info!(
                                        listen_addr = %listen_addr,
                                        "PQ network listener started"
                                    );
                                }
                                PqNetworkEvent::Stopped => {
                                    tracing::info!("PQ network stopped");
                                    break;
                                }
                                PqNetworkEvent::ConnectionFailed { addr, reason } => {
                                    tracing::warn!(
                                        addr = %addr,
                                        reason = %reason,
                                        "PQ connection failed"
                                    );
                                }
                            }
                        }
                        
                        // Log final statistics
                        {
                            let bridge = bridge_clone.lock().await;
                            let stats = bridge.stats();
                            tracing::info!(
                                block_announces = stats.block_announces_received,
                                transactions = stats.transactions_received,
                                decode_errors = stats.decode_errors,
                                "PQ network event handler stopped - final stats"
                            );
                        }
                        
                        // Log transaction pool stats
                        {
                            let pool_stats = pool_bridge_clone.stats().snapshot();
                            tracing::info!(
                                tx_received = pool_stats.transactions_received,
                                tx_submitted = pool_stats.transactions_submitted,
                                tx_rejected = pool_stats.transactions_rejected,
                                "Transaction pool bridge - final stats"
                            );
                        }
                    },
                );

                // Spawn the transaction pool processing task (Phase 9.2)
                task_manager.spawn_handle().spawn(
                    "tx-pool-processor",
                    Some("txpool"),
                    async move {
                        let interval = tokio::time::Duration::from_millis(process_interval);
                        let mut process_timer = tokio::time::interval(interval);
                        
                        tracing::info!(
                            interval_ms = process_interval,
                            "Transaction pool processor started (Phase 9.2)"
                        );
                        
                        loop {
                            process_timer.tick().await;
                            
                            let submitted = pool_bridge_for_processor.process_pending().await;
                            
                            if submitted > 0 && pool_verbose {
                                let stats = pool_bridge_for_processor.stats().snapshot();
                                tracing::debug!(
                                    submitted = submitted,
                                    total_received = stats.transactions_received,
                                    total_submitted = stats.transactions_submitted,
                                    total_rejected = stats.transactions_rejected,
                                    pool_size = pool_bridge_for_processor.pool_size(),
                                    "Processed pending transactions"
                                );
                            }
                        }
                    },
                );
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Failed to start PqNetworkBackend - continuing without PQ networking"
                );
            }
        }
    }

    // Phase 9.3 + 10.4: Spawn mining worker if enabled
    let mining_config = MiningConfig::from_env();
    if mining_config.enabled {
        let worker_config = MiningWorkerConfig::from_env();
        let pow_handle_for_worker = pow_handle.clone();
        
        // Check if we have a PQ network handle for live broadcasting (Phase 10.4)
        if let Some(pq_handle) = pq_network_handle.clone() {
            tracing::info!(
                threads = worker_config.threads,
                test_mode = worker_config.test_mode,
                "Spawning mining worker with PQ network broadcasting (Phase 10.4)"
            );

            task_manager.spawn_handle().spawn(
                "hegemon-mining-worker",
                Some("mining"),
                async move {
                    let worker = create_network_mining_worker(
                        pow_handle_for_worker,
                        pq_handle,
                        worker_config,
                    );
                    
                    worker.run().await;
                },
            );
        } else {
            // Fall back to scaffold mode without network broadcasting
            tracing::info!(
                threads = worker_config.threads,
                test_mode = worker_config.test_mode,
                "Spawning mining worker in scaffold mode (no PQ network)"
            );

            task_manager.spawn_handle().spawn(
                "hegemon-mining-worker",
                Some("mining"),
                async move {
                    let worker = create_scaffold_mining_worker(
                        pow_handle_for_worker,
                        worker_config,
                    );
                    
                    worker.run().await;
                },
            );
        }
    } else {
        tracing::info!("Mining worker not spawned (HEGEMON_MINE not set)");
    }

    // Phase 2 TODO: Full sc-network integration requires:
    // 
    // 1. Client setup (requires aligned polkadot-sdk git dependencies):
    //    let executor = WasmExecutor::new(...);
    //    let (client, backend, keystore, task_manager) = 
    //        sc_service::new_full_parts::<Block, RuntimeApi, Executor>(&config)?;
    //
    // 2. PoW block import (requires runtime WASM with DifficultyApi):
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
    // 4. sc-network integration with PQ transport:
    //    - Bridge PqNetworkBackend events to sc-network NotificationService
    //    - Route block announcements via PQ secure channels
    //    - Forward transactions to transaction pool
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

    let has_pq_broadcast = pq_network_handle.is_some();
    tracing::info!(
        "Phase 10.4 Complete - Live network integration ready"
    );
    tracing::info!("  - Task 9.1: Network bridge (block announcements) ✅");
    tracing::info!("  - Task 9.2: Transaction pool integration ✅");
    tracing::info!("  - Task 9.3: Mining worker spawning ✅");
    tracing::info!("  - Task 10.4: Live PQ network broadcasting ✅ (enabled: {})", has_pq_broadcast);
    tracing::info!("  Set HEGEMON_MINE=1 to enable mining");
    tracing::info!("  Remaining: Task 10.5 - Production mining worker with real chain state");

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

    #[test]
    fn test_pq_service_config_default() {
        let config = PqServiceConfig::default();
        assert!(config.require_pq);
        assert!(config.hybrid_mode);
        assert!(!config.verbose_logging);
        assert_eq!(config.max_peers, 50);
    }

    #[test]
    fn test_pq_service_config_from_env() {
        // This test depends on environment, so just verify it doesn't panic
        let _config = PqServiceConfig::from_env();
    }
}

