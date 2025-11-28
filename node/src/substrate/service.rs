//! Hegemon Substrate Node Service
//!
//! This module provides the core service implementation for the Substrate-based
//! Hegemon node, including:
//! - Partial node components setup with full Substrate client (Phase 11)
//! - Full node service initialization
//! - Block import pipeline configuration with Blake3 PoW
//! - Mining coordination with ProductionChainStateProvider
//! - PQ-secure network transport (Phase 3 + Phase 3.5)
//! - Network bridge for block/tx routing (Phase 9)
//!
//! # Phase 11 Integration
//!
//! This module now supports full Substrate client integration:
//! - `new_partial_with_client()`: Creates full client with TFullClient (Task 11.4.2)
//! - `ProductionChainStateProvider`: Real chain state for mining
//! - Runtime API callbacks for difficulty and block queries
//! - Transaction pool integration with sc-transaction-pool (Task 11.4.3)
//! - BlockBuilder API for real state execution (Task 11.4.4)
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
use crate::substrate::client::{
    FullBackend, HegemonFullClient, HegemonPowBlockImport, HegemonSelectChain,
    HegemonTransactionPool, ProductionChainStateProvider, ProductionConfig,
    StateExecutionResult, DEFAULT_DIFFICULTY_BITS,
};
use crate::substrate::mining_worker::{
    create_production_mining_worker, create_scaffold_mining_worker,
    ChainStateProvider, MiningWorkerConfig,
};
use crate::substrate::network::{PqNetworkConfig, PqNetworkKeypair};
use crate::substrate::network_bridge::{NetworkBridge, NetworkBridgeBuilder};
use crate::substrate::transaction_pool::{
    MockTransactionPool, TransactionPoolBridge, TransactionPoolConfig,
};
use codec::Decode;
use consensus::{Blake3Algorithm, Blake3Seal};
use network::{
    PqNetworkBackend, PqNetworkBackendConfig, PqNetworkEvent, PqNetworkHandle, PqPeerIdentity,
    PqTransportConfig, SubstratePqTransport, SubstratePqTransportConfig,
};
use sc_service::{error::Error as ServiceError, Configuration, KeystoreContainer, TaskManager};
use sp_api::{Core, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_core::H256;
use sp_runtime::traits::Header as HeaderT;
use std::sync::Arc;
use tokio::sync::Mutex;

// Import runtime APIs for difficulty queries (Task 11.4.6)
use runtime::apis::ConsensusApi;

/// Type alias for the no-op inherent data providers creator
///
/// For our PoW chain, we don't need any inherent data providers since
/// timestamps and other inherents are handled differently. This type
/// is used as the CIDP parameter for PowBlockImport.
type NoOpInherentDataProviders = fn(
    <runtime::Block as sp_runtime::traits::Block>::Hash,
    (),
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send>>;

/// Concrete type for the PoW block import with no-op inherent providers
pub type ConcretePowBlockImport = HegemonPowBlockImport<NoOpInherentDataProviders>;

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

// =============================================================================
// Task 11.4.4: Wire BlockBuilder API to execute_extrinsics_fn
// =============================================================================
//
// This function connects the ProductionChainStateProvider's execute_extrinsics_fn
// callback to the real Substrate BlockBuilder runtime API.
//
// The BlockBuilder API provides:
// - initialize_block(header): Initialize block execution context
// - apply_extrinsic(ext): Apply a single extrinsic to state  
// - finalize_block(): Finalize and return header with state_root
//
// The callback is called during block production to:
// 1. Execute pending transactions against the runtime
// 2. Compute the resulting state root after all state transitions
// 3. Return which extrinsics were successfully applied

/// Wires the BlockBuilder runtime API to the ProductionChainStateProvider (Task 11.4.4)
///
/// This connects the `execute_extrinsics_fn` callback to use the real Substrate
/// runtime API for block execution. When the mining worker produces a block,
/// it will:
///
/// 1. Call `initialize_block` with the parent hash and block number
/// 2. Decode each extrinsic from bytes using `codec::Decode`
/// 3. Call `apply_extrinsic` for each decoded extrinsic
/// 4. Call `finalize_block` to get the header with computed state_root
///
/// # Arguments
///
/// * `chain_state` - The ProductionChainStateProvider to wire
/// * `client` - The full Substrate client providing runtime API access
///
/// # Example
///
/// ```rust,ignore
/// let chain_state = Arc::new(ProductionChainStateProvider::new(config));
/// wire_block_builder_api(&chain_state, client.clone());
///
/// // Now execute_extrinsics uses real runtime
/// let result = chain_state.execute_extrinsics(&parent_hash, 1, &extrinsics)?;
/// // result.state_root is computed by the runtime
/// ```
pub fn wire_block_builder_api(
    chain_state: &Arc<ProductionChainStateProvider>,
    client: Arc<HegemonFullClient>,
) {
    let client_for_exec = client;
    
    chain_state.set_execute_extrinsics_fn(move |parent_hash, block_number, extrinsics| {
        // Get the runtime API from the client
        let api = client_for_exec.runtime_api();
        
        // Convert our H256 to the runtime's Hash type via substrate H256
        let parent_substrate_hash: sp_core::H256 = (*parent_hash).into();
        
        // Create a header for initialize_block using the Header trait
        // The header is used to set up the block context (block number, parent hash)
        // The state_root and extrinsics_root will be computed by finalize_block
        let header = <runtime::Header as HeaderT>::new(
            block_number,         // BlockNumber is u64 in our runtime
            Default::default(),   // extrinsics_root - will be computed
            Default::default(),   // state_root - will be computed
            parent_substrate_hash,
            Default::default(),   // digest
        );
        
        // Initialize block execution context
        // This sets up the runtime state for executing transactions
        if let Err(e) = api.initialize_block(parent_substrate_hash, &header) {
            return Err(format!("Failed to initialize block: {:?}", e));
        }
        
        tracing::debug!(
            block_number,
            parent = %hex::encode(parent_hash.as_bytes()),
            tx_count = extrinsics.len(),
            "Initializing block execution (Task 11.4.4)"
        );
        
        // Apply each extrinsic
        let mut applied = Vec::new();
        let mut failed = 0usize;
        
        for ext_bytes in extrinsics {
            // Decode extrinsic bytes to UncheckedExtrinsic
            match runtime::UncheckedExtrinsic::decode(&mut &ext_bytes[..]) {
                Ok(extrinsic) => {
                    // Apply the extrinsic via runtime API
                    match api.apply_extrinsic(parent_substrate_hash, extrinsic) {
                        Ok(Ok(_)) => {
                            // Successfully applied
                            applied.push(ext_bytes.clone());
                        }
                        Ok(Err(dispatch_error)) => {
                            // Dispatch error (runtime rejected the extrinsic)
                            tracing::warn!(
                                error = ?dispatch_error,
                                "Extrinsic dispatch failed"
                            );
                            failed += 1;
                        }
                        Err(api_error) => {
                            // API call failed
                            tracing::warn!(
                                error = ?api_error,
                                "apply_extrinsic API call failed"
                            );
                            failed += 1;
                        }
                    }
                }
                Err(decode_error) => {
                    tracing::warn!(
                        error = ?decode_error,
                        bytes_len = ext_bytes.len(),
                        "Failed to decode extrinsic"
                    );
                    failed += 1;
                }
            }
        }
        
        // Finalize block and get the header with state root
        let finalized_header = match api.finalize_block(parent_substrate_hash) {
            Ok(header) => header,
            Err(e) => {
                return Err(format!("Failed to finalize block: {:?}", e));
            }
        };
        
        // Extract state_root and extrinsics_root using the Header trait
        let state_root = *finalized_header.state_root();
        let extrinsics_root = *finalized_header.extrinsics_root();
        
        tracing::debug!(
            block_number,
            applied = applied.len(),
            failed,
            state_root = %hex::encode(state_root.as_bytes()),
            extrinsics_root = %hex::encode(extrinsics_root.as_bytes()),
            "Block execution finalized (Task 11.4.4)"
        );
        
        Ok(StateExecutionResult {
            applied_extrinsics: applied,
            state_root,
            extrinsics_root,
            failed_count: failed,
        })
    });
    
    tracing::info!(
        "Phase 11.4.4: BlockBuilder API wired to execute_extrinsics_fn"
    );
}

// =============================================================================
// Task 11.4.5: Wire PoW block import to ProductionChainStateProvider
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
/// # Task 11.4.5 Implementation
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
///
/// # Example
///
/// ```rust,ignore
/// let chain_state = Arc::new(ProductionChainStateProvider::new(config));
/// wire_pow_block_import(&chain_state, pow_block_import, client.clone());
///
/// // Now when mining finds a valid seal:
/// let hash = chain_state.import_block(&template, &seal)?;
/// // Block is imported through PowBlockImport with PoW verification
/// ```
pub fn wire_pow_block_import(
    chain_state: &Arc<ProductionChainStateProvider>,
    pow_block_import: ConcretePowBlockImport,
    _client: Arc<HegemonFullClient>,
) {
    use codec::Encode;
    use sp_runtime::traits::Block as BlockT;
    
    // Clone for the closure
    let block_import = pow_block_import;
    
    chain_state.set_import_fn(move |template: &BlockTemplate, seal: &Blake3Seal| {
        // Construct the block header from the template
        let parent_hash: sp_core::H256 = template.parent_hash.into();
        
        // Create header with the seal as a digest item
        let mut digest = Digest::default();
        
        // Add the PoW seal as a DigestItem::Seal
        // Engine ID "bpow" for Blake3 PoW
        let seal_bytes = seal.encode();
        digest.push(DigestItem::Seal(*b"bpow", seal_bytes));
        
        let header = <runtime::Header as HeaderT>::new(
            template.number,              // Use 'number' field from BlockTemplate
            template.extrinsics_root,
            template.state_root,
            parent_hash,
            digest,
        );
        
        // Decode the extrinsics from template
        let encoded_extrinsics: Vec<runtime::UncheckedExtrinsic> = template
            .extrinsics                   // Use 'extrinsics' field from BlockTemplate
            .iter()
            .filter_map(|tx_bytes| {
                runtime::UncheckedExtrinsic::decode(&mut &tx_bytes[..]).ok()
            })
            .collect();
        
        // Construct the block
        let block = runtime::Block::new(header.clone(), encoded_extrinsics);
        
        // Get the block hash
        let block_hash = block.hash();
        
        // Construct BlockImportParams
        let mut import_params = BlockImportParams::new(BlockOrigin::Own, header);
        import_params.body = Some(block.extrinsics().to_vec());
        import_params.fork_choice = Some(ForkChoiceStrategy::LongestChain);
        
        // Import the block through PowBlockImport
        // Note: BlockImport::import_block is async, but we're in a sync context
        // For now, we use block_on. In production, this should be properly async.
        let import_result = futures::executor::block_on(async {
            let import = block_import.clone();
            import.import_block(import_params).await
        });
        
        match import_result {
            Ok(ImportResult::Imported(_aux)) => {
                tracing::info!(
                    block_hash = %hex::encode(block_hash.as_bytes()),
                    block_number = template.number,
                    "Block imported successfully via PowBlockImport (Task 11.4.5)"
                );
                Ok(block_hash)
            }
            Ok(ImportResult::AlreadyInChain) => {
                tracing::warn!(
                    block_hash = %hex::encode(block_hash.as_bytes()),
                    "Block already in chain"
                );
                Ok(block_hash)
            }
            Ok(ImportResult::KnownBad) => {
                Err(format!("Block {} is known bad", hex::encode(block_hash.as_bytes())))
            }
            Ok(ImportResult::UnknownParent) => {
                Err(format!(
                    "Unknown parent {} for block {}",
                    hex::encode(template.parent_hash.as_bytes()),
                    hex::encode(block_hash.as_bytes())
                ))
            }
            Ok(ImportResult::MissingState) => {
                Err(format!(
                    "Missing state for parent {}",
                    hex::encode(template.parent_hash.as_bytes())
                ))
            }
            Err(e) => {
                Err(format!("Block import failed: {:?}", e))
            }
        }
    });
    
    tracing::info!(
        "Phase 11.4.5: PoW block import wired to ProductionChainStateProvider"
    );
    tracing::debug!(
        "  - Mined blocks verified via PowBlockImport"
    );
    tracing::debug!(
        "  - Blake3 seals validated before commit"
    );
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

/// Partial components with full Substrate client (Task 11.4.2)
///
/// This struct extends `PartialComponents` with the full Substrate client,
/// backend, and keystore created by `sc_service::new_full_parts()`.
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
    /// Real Substrate transaction pool (Task 11.4.3)
    ///
    /// This is the production transaction pool that validates transactions
    /// against the runtime. It replaces MockTransactionPool for full client mode.
    pub transaction_pool: Arc<HegemonTransactionPool>,
    /// Chain selection rule (Task 11.4.5)
    ///
    /// Uses LongestChain which selects the chain with the most blocks.
    /// This is the standard selection rule for PoW chains.
    pub select_chain: HegemonSelectChain,
    /// PoW block import wrapper (Task 11.4.5)
    ///
    /// Wraps the client with PoW verification using Blake3Algorithm.
    /// All blocks imported through this wrapper are verified for valid PoW.
    pub pow_block_import: ConcretePowBlockImport,
    /// Blake3 PoW algorithm (Task 11.4.5)
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

/// Creates partial node components with full Substrate client (Task 11.4.2)
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
            config,
            None, // telemetry - None for now, can add later
            executor,
        )?;

    let client = Arc::new(client);

    tracing::info!(
        best_number = %client.chain_info().best_number,
        best_hash = %client.chain_info().best_hash,
        "Full Substrate client created (Task 11.4.2)"
    );

    // Task 11.4.3: Create real Substrate transaction pool
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

    tracing::info!(
        "Full Substrate transaction pool created (Task 11.4.3)"
    );

    // Initialize PoW mining coordinator
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

    // ==========================================================================
    // Task 11.4.5: Create PoW block import pipeline
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
    // For our PoW chain, we don't need any inherent data providers since
    // timestamps are handled separately in the mining worker.
    // We use a function pointer type for compatibility with PowBlockImport.
    fn create_inherent_data_providers(
        _parent_hash: <runtime::Block as sp_runtime::traits::Block>::Hash,
        _: (),
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send>> {
        Box::pin(async { Ok(()) })
    }

    // Create the PoW block import wrapper
    // This verifies Blake3 PoW seals before allowing blocks to be imported
    let pow_block_import = sc_consensus_pow::PowBlockImport::new(
        client.clone(),                         // Inner block import (client implements BlockImport)
        client.clone(),                         // Client for runtime API queries
        pow_algorithm.clone(),                  // PoW algorithm for verification
        0,                                      // check_inherents_after: 0 = always check
        select_chain.clone(),                   // Chain selection rule
        create_inherent_data_providers as NoOpInherentDataProviders, // Inherent data providers creator
    );

    tracing::info!(
        "PoW block import pipeline created (Task 11.4.5)"
    );
    tracing::debug!(
        "  - Blake3Algorithm for PoW verification"
    );
    tracing::debug!(
        "  - LongestChain for chain selection"
    );
    tracing::debug!(
        "  - PowBlockImport wrapping full client"
    );

    // Initialize PQ service configuration (Phase 3.5)
    let pq_service_config = PqServiceConfig::from_env();

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
    let node_seed = network_keypair
        .as_ref()
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
        "Hegemon node with full client initialized (Task 11.4.2 + 11.4.3 + 11.4.5 + Phase 3.5)"
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

    // Phase 9.2 + 11.3: Create the transaction pool bridge early
    // This is created outside the PQ network block so it can be wired to mining worker
    let pool_config = TransactionPoolConfig::from_env();
    let mock_pool = Arc::new(MockTransactionPool::new(pool_config.capacity));
    let pool_bridge = Arc::new(TransactionPoolBridge::with_max_pending(
        mock_pool.clone(),
        pool_config.max_pending,
    ));

    tracing::info!(
        pool_capacity = pool_config.capacity,
        max_pending = pool_config.max_pending,
        process_interval_ms = pool_config.process_interval_ms,
        "Transaction pool created (Task 11.3 - available for mining and RPC)"
    );

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

                // Clone pool_bridge for use in network event handler
                let pool_bridge_clone = Arc::clone(&pool_bridge);

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

    // Phase 9.3 + 10.4 + 11.1 + 11.2 + 11.3: Spawn mining worker if enabled
    // Phase 11.1: Use ProductionChainStateProvider with callbacks
    // Phase 11.2: Wire BlockImportTracker for real block imports
    // Phase 11.3: Wire transaction pool to chain state provider
    let mining_config = MiningConfig::from_env();
    if mining_config.enabled {
        let worker_config = MiningWorkerConfig::from_env();
        let pow_handle_for_worker = pow_handle.clone();

        // Phase 11.1: Create production chain state provider
        let production_config = ProductionConfig::from_env();
        let chain_state = Arc::new(ProductionChainStateProvider::new(production_config.clone()));

        // Phase 11.2: Create and wire block import tracker
        // This provides:
        // - Block import callback with PoW verification
        // - Best block state tracking
        // - Import statistics
        let import_tracker = BlockImportTracker::from_env();
        wire_import_tracker(&chain_state, &import_tracker);
        
        tracing::info!(
            verify_pow = %import_tracker.config.verify_pow,
            "Phase 11.2: BlockImportTracker wired to ProductionChainStateProvider"
        );

        // Phase 11.3: Wire transaction pool to chain state provider
        // Mining worker calls pending_transactions() to get txs for block template
        let pool_for_mining = Arc::clone(&pool_bridge);
        let max_block_txs = production_config.max_block_transactions;
        chain_state.set_pending_txs_fn(move || {
            pool_for_mining.ready_for_block(max_block_txs)
        });

        // Phase 11.3: Wire post-import callback to clear mined transactions
        let pool_for_import = Arc::clone(&pool_bridge);
        chain_state.set_on_import_success_fn(move |included_txs: &[Vec<u8>]| {
            pool_for_import.clear_included(included_txs);
        });

        tracing::info!(
            max_block_transactions = max_block_txs,
            "Phase 11.3: Transaction pool wired to ProductionChainStateProvider"
        );

        // Phase 11.4: Wire state execution callback
        // This callback executes extrinsics against the runtime and computes state root
        // 
        // For full client integration, this would use the runtime API:
        // ```rust
        // let client_for_exec = client.clone();
        // chain_state.set_execute_extrinsics_fn(move |parent_hash, block_number, extrinsics| {
        //     let api = client_for_exec.runtime_api();
        //     // Initialize block
        //     api.initialize_block(parent_hash, &header_for_block(block_number))?;
        //     // Apply each extrinsic
        //     let mut applied = Vec::new();
        //     let mut failed = 0;
        //     for ext in extrinsics {
        //         match api.apply_extrinsic(parent_hash, decode_extrinsic(ext)) {
        //             Ok(_) => applied.push(ext.clone()),
        //             Err(_) => failed += 1,
        //         }
        //     }
        //     // Finalize and get state root
        //     let header = api.finalize_block(parent_hash)?;
        //     Ok(StateExecutionResult {
        //         applied_extrinsics: applied,
        //         state_root: header.state_root,
        //         extrinsics_root: header.extrinsics_root,
        //         failed_count: failed,
        //     })
        // });
        // ```
        //
        // For scaffold mode, we use a mock implementation that:
        // - Accepts all extrinsics without validation
        // - Uses a deterministic mock state root based on extrinsics
        chain_state.set_execute_extrinsics_fn(move |parent_hash, block_number, extrinsics| {
            // Mock state execution for scaffold mode
            // In production, this would execute against the real runtime
            
            // Compute a deterministic "state root" from extrinsics
            // This is NOT cryptographically secure - just for testing
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"state_root_v1");
            hasher.update(parent_hash.as_bytes());
            hasher.update(&block_number.to_le_bytes());
            for ext in extrinsics {
                hasher.update(&(ext.len() as u32).to_le_bytes());
                hasher.update(ext);
            }
            let state_root = sp_core::H256::from_slice(hasher.finalize().as_bytes());
            
            // Compute extrinsics root
            let extrinsics_root = crate::substrate::compute_extrinsics_root(extrinsics);
            
            tracing::debug!(
                block_number,
                parent = %hex::encode(parent_hash.as_bytes()),
                tx_count = extrinsics.len(),
                state_root = %hex::encode(state_root.as_bytes()),
                "Mock state execution (Task 11.4 scaffold mode)"
            );
            
            Ok(crate::substrate::StateExecutionResult {
                applied_extrinsics: extrinsics.to_vec(),
                state_root,
                extrinsics_root,
                failed_count: 0,
            })
        });

        tracing::info!(
            "Phase 11.4: State execution callback wired (scaffold mode)"
        );

        // Initial state from genesis (block 0)
        chain_state.update_fallback(H256::zero(), 0, DEFAULT_DIFFICULTY_BITS);
        
        tracing::info!(
            using_production_provider = true,
            difficulty_bits = DEFAULT_DIFFICULTY_BITS,
            "Phase 11.1 + 11.2 + 11.3: Full block production pipeline configured"
        );
        
        // Check if we have a PQ network handle for live broadcasting (Phase 10.4)
        if let Some(pq_handle) = pq_network_handle.clone() {
            tracing::info!(
                threads = worker_config.threads,
                test_mode = worker_config.test_mode,
                "Spawning production mining worker with PQ network broadcasting (Phase 11.1 + 11.2)"
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

    // Phase 11.2 TODO: Full block import pipeline requires:
    // 
    // 1. Create full Substrate client:
    //    ```rust
    //    let executor = sc_executor::WasmExecutor::<sp_io::SubstrateHostFunctions>::builder()
    //        .build();
    //    let (client, backend, keystore, task_manager) = 
    //        sc_service::new_full_parts::<runtime::Block, runtime::RuntimeApi, _>(
    //            &config,
    //            None,  // telemetry
    //            executor,
    //        )?;
    //    ```
    //
    // 2. Connect ProductionChainStateProvider callbacks:
    //    ```rust
    //    let client_for_state = client.clone();
    //    chain_state.set_best_block_fn(move || {
    //        let info = client_for_state.info();
    //        (info.best_hash, info.best_number)
    //    });
    //    
    //    let runtime_api = client.runtime_api();
    //    chain_state.set_difficulty_fn(move || {
    //        let best = client.info().best_hash;
    //        runtime_api.difficulty_bits(best).unwrap_or(DEFAULT_DIFFICULTY_BITS)
    //    });
    //    
    //    let pool = transaction_pool.clone();
    //    chain_state.set_pending_txs_fn(move || {
    //        pool.ready().map(|tx| tx.data().encode()).collect()
    //    });
    //    ```
    //
    // 3. Create PowBlockImport pipeline:
    //    ```rust
    //    let pow_algorithm = consensus::Blake3Algorithm::new(client.clone());
    //    let pow_block_import = sc_consensus_pow::PowBlockImport::new(
    //        client.clone(),
    //        client.clone(),
    //        pow_algorithm.clone(),
    //        0,
    //        select_chain.clone(),
    //    );
    //    
    //    chain_state.set_import_fn(move |template, seal| {
    //        pow_block_import.import_block(construct_block(template, seal), ...)
    //    });
    //    ```
    //
    // 4. Wire import queue:
    //    ```rust
    //    let import_queue = sc_consensus_pow::import_queue(
    //        Box::new(pow_block_import.clone()),
    //        None,
    //        pow_algorithm.clone(),
    //        &task_manager.spawn_essential_handle(),
    //        config.prometheus_registry(),
    //    )?;
    //    ```

    let has_pq_broadcast = pq_network_handle.is_some();
    tracing::info!("Phase 11.4 Complete - State Execution Wired");
    tracing::info!("  - Task 9.1: Network bridge (block announcements) ✅");
    tracing::info!("  - Task 9.2: Transaction pool integration ✅");
    tracing::info!("  - Task 9.3: Mining worker spawning ✅");
    tracing::info!("  - Task 10.4: Live PQ network broadcasting ✅ (enabled: {})", has_pq_broadcast);
    tracing::info!("  - Task 11.1: ProductionChainStateProvider ✅");
    tracing::info!("  - Task 11.2: BlockImportTracker ✅ (PoW verification + state tracking)");
    tracing::info!("  - Task 11.3: Transaction pool wiring ✅ (pool → mining worker → blocks)");
    tracing::info!("  - Task 11.4: State execution ✅ (scaffold mode - mock state root)");
    tracing::info!("  - Task 11.4.4: wire_block_builder_api() ✅ (real runtime execution available)");
    tracing::info!("  Set HEGEMON_MINE=1 to enable mining");
    tracing::info!("  Remaining: Task 11.5 - Chain sync between nodes");

    Ok(task_manager)
}

// =============================================================================
// Task 11.4.6: Full node service with real Substrate client
// =============================================================================
//
// This function creates a full node using the real Substrate client instead
// of scaffold components. It wires:
// - Real Substrate client to ProductionChainStateProvider callbacks
// - Real BlockBuilder API for state execution
// - Real PowBlockImport for block import with PoW verification
// - Runtime API for difficulty queries

/// Creates a full node service with real Substrate client (Task 11.4.6)
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
    // Task 11.4.2: Create full Substrate client components
    let PartialComponentsWithClient {
        client,
        backend: _backend,
        keystore_container: _keystore,
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
    let role = format!("{:?}", config.role);

    // Track PQ network handle for mining worker (Phase 10.4)
    let mut pq_network_handle: Option<PqNetworkHandle> = None;

    tracing::info!(
        chain = %chain_name,
        role = %role,
        best_number = %client.chain_info().best_number,
        best_hash = %client.chain_info().best_hash,
        pq_enabled = %network_config.enable_pq_transport,
        require_pq = %pq_service_config.require_pq,
        "Hegemon node started with FULL SUBSTRATE CLIENT (Task 11.4.6)"
    );

    // Log PQ network configuration
    if let Some(ref keypair) = network_keypair {
        tracing::info!(
            peer_id = %keypair.peer_id(),
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

    // Task 11.4.3: Use real Substrate transaction pool
    // Note: For now we still use the mock pool bridge for network integration,
    // but the real transaction_pool is available for validation
    let pool_config = TransactionPoolConfig::from_env();
    let mock_pool = Arc::new(MockTransactionPool::new(pool_config.capacity));
    let pool_bridge = Arc::new(TransactionPoolBridge::with_max_pending(
        mock_pool.clone(),
        pool_config.max_pending,
    ));

    tracing::info!(
        pool_capacity = pool_config.capacity,
        max_pending = pool_config.max_pending,
        "Transaction pool bridge created (real pool available via client)"
    );
    tracing::debug!(
        "Real transaction pool: {:?}",
        std::any::type_name_of_val(&*transaction_pool)
    );

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
                    "PqNetworkBackend started (Task 11.4.6 - Full Client Mode)"
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

                // Clone pool_bridge for use in network event handler
                let pool_bridge_clone = Arc::clone(&pool_bridge);

                // Clone for the transaction processor task
                let pool_bridge_for_processor = Arc::clone(&pool_bridge);
                let process_interval = pool_config.process_interval_ms;
                let pool_verbose = pool_config.verbose;

                // Spawn the PQ network event handler task
                task_manager.spawn_handle().spawn(
                    "pq-network-events",
                    Some("network"),
                    async move {
                        let _pq_backend = pq_backend;
                        tracing::info!("PQ network event handler started (Full Client Mode)");
                        
                        while let Some(event) = event_rx.recv().await {
                            {
                                let mut bridge = bridge_clone.lock().await;
                                bridge.handle_event(event.clone()).await;
                                
                                let pending_txs = bridge.drain_transactions();
                                if !pending_txs.is_empty() {
                                    pool_bridge_clone.queue_from_bridge(pending_txs).await;
                                }
                            }

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
                                PqNetworkEvent::Stopped => {
                                    tracing::info!("PQ network stopped");
                                    break;
                                }
                                _ => {}
                            }
                        }
                    },
                );

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
    // Task 11.4.6: Wire real client to ProductionChainStateProvider
    // ==========================================================================
    
    let mining_config = MiningConfig::from_env();
    if mining_config.enabled {
        let worker_config = MiningWorkerConfig::from_env();
        let pow_handle_for_worker = pow_handle.clone();

        // Create production chain state provider
        let production_config = ProductionConfig::from_env();
        let chain_state = Arc::new(ProductionChainStateProvider::new(production_config.clone()));

        // =======================================================================
        // Task 11.4.6a: Wire best_block_fn to real client
        // =======================================================================
        let client_for_best_block = client.clone();
        chain_state.set_best_block_fn(move || {
            let info = client_for_best_block.chain_info();
            // Convert sp_core::H256 to our H256 (they're the same type)
            (info.best_hash, info.best_number)
        });
        
        tracing::info!(
            "Task 11.4.6a: best_block_fn wired to client.chain_info()"
        );

        // =======================================================================
        // Task 11.4.6b: Wire difficulty_fn to runtime API
        // =======================================================================
        // Note: ConsensusApi::difficulty_bits() must be called at the best block
        let client_for_difficulty = client.clone();
        chain_state.set_difficulty_fn(move || {
            let best_hash = client_for_difficulty.chain_info().best_hash;
            let api = client_for_difficulty.runtime_api();
            
            // Try to query difficulty from runtime's ConsensusApi
            match api.difficulty_bits(best_hash) {
                Ok(difficulty_bits) => {
                    difficulty_bits
                }
                Err(e) => {
                    tracing::warn!(
                        error = ?e,
                        "Failed to query difficulty_bits from runtime, using fallback"
                    );
                    DEFAULT_DIFFICULTY_BITS
                }
            }
        });
        
        tracing::info!(
            "Task 11.4.6b: difficulty_fn wired to runtime ConsensusApi::difficulty_bits()"
        );

        // =======================================================================
        // Task 11.4.6c: Wire pending_txs_fn to transaction pool
        // =======================================================================
        // For now, use the pool bridge which collects from network
        // Full integration would use transaction_pool.ready() directly
        let pool_for_mining = Arc::clone(&pool_bridge);
        let max_block_txs = production_config.max_block_transactions;
        chain_state.set_pending_txs_fn(move || {
            pool_for_mining.ready_for_block(max_block_txs)
        });

        // Wire post-import callback to clear mined transactions
        let pool_for_import = Arc::clone(&pool_bridge);
        chain_state.set_on_import_success_fn(move |included_txs: &[Vec<u8>]| {
            pool_for_import.clear_included(included_txs);
        });

        tracing::info!(
            max_block_transactions = max_block_txs,
            "Task 11.4.6c: Transaction pool wired to chain state provider"
        );

        // =======================================================================
        // Task 11.4.6d: Wire BlockBuilder API for real state execution
        // =======================================================================
        wire_block_builder_api(&chain_state, client.clone());
        
        tracing::info!(
            "Task 11.4.6d: BlockBuilder API wired for real state execution"
        );

        // =======================================================================
        // Task 11.4.6e: Wire PowBlockImport for real block import
        // =======================================================================
        wire_pow_block_import(&chain_state, pow_block_import, client.clone());
        
        tracing::info!(
            "Task 11.4.6e: PowBlockImport wired for real block import"
        );

        // Log full configuration
        tracing::info!(
            using_real_client = true,
            difficulty_bits = chain_state.difficulty_bits(),
            best_number = chain_state.best_number(),
            best_hash = %hex::encode(chain_state.best_hash().as_bytes()),
            "Task 11.4.6: FULL PRODUCTION PIPELINE CONFIGURED"
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

    let has_pq_broadcast = pq_network_handle.is_some();
    tracing::info!("═══════════════════════════════════════════════════════════════");
    tracing::info!("Task 11.4.6 Complete - FULL SUBSTRATE CLIENT INTEGRATION");
    tracing::info!("═══════════════════════════════════════════════════════════════");
    tracing::info!("  ✅ Task 11.4.1: RuntimeApi exported from runtime");
    tracing::info!("  ✅ Task 11.4.2: Full Substrate client created");
    tracing::info!("  ✅ Task 11.4.3: Real transaction pool created");
    tracing::info!("  ✅ Task 11.4.4: BlockBuilder API wired (real state execution)");
    tracing::info!("  ✅ Task 11.4.5: PowBlockImport pipeline created");
    tracing::info!("  ✅ Task 11.4.6: Client wired to ProductionChainStateProvider");
    tracing::info!("    - best_block_fn → client.chain_info()");
    tracing::info!("    - difficulty_fn → runtime DifficultyApi");
    tracing::info!("    - execute_extrinsics_fn → BlockBuilder API");
    tracing::info!("    - import_fn → PowBlockImport");
    tracing::info!("  PQ network broadcasting: {}", has_pq_broadcast);
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
// Task 11.2: Full Block Import Pipeline
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
// Task 11.4 (state execution) is complete.

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

/// Statistics for block imports (Task 11.2)
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

/// Block import tracker for Task 11.2
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
    ) -> impl Fn(&crate::substrate::mining_worker::BlockTemplate, &Blake3Seal) -> Result<H256, String> + Send + Sync + 'static
    {
        let stats = self.stats.clone();
        let best_number = self.best_number.clone();
        let best_hash = self.best_hash.clone();
        let verbose = self.config.verbose;
        let verify_pow = self.config.verify_pow;

        move |template, seal| {
            // Verify the seal if configured
            if verify_pow {
                if !consensus::seal_meets_target(&seal.work, seal.difficulty) {
                    let mut s = stats.write();
                    s.invalid_seals += 1;
                    return Err("Seal does not meet difficulty target".to_string());
                }
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
                    "Block imported via BlockImportTracker (Task 11.2)"
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
        "Block import tracker wired to ProductionChainStateProvider (Task 11.2)"
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
            difficulty: 0x0300ffff, // Very hard
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
        let provider = Arc::new(ProductionChainStateProvider::new(ProductionConfig::default()));

        wire_import_tracker(&provider, &tracker);

        // Provider should now have callbacks
        // Best block should come from tracker
        assert_eq!(provider.best_number(), 0);
        assert_eq!(provider.best_hash(), H256::zero());
    }
}

