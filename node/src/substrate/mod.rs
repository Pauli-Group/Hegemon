//! Substrate integration module for the Hegemon node.
//!
//! This module contains the Substrate-specific implementation including:
//! - Chain specification configuration
//! - Node service setup with Blake3 PoW
//! - RPC extensions
//! - CLI commands
//! - PQ-secure network transport (Phase 3)
//! - Network bridge for block/tx propagation (Phase 9)
//! - Mining worker for block production (Phase 9.3)
//! - Full client integration (Phase 10.2)
//!
//! # Phase 2 Status
//!
//! This phase implements the sc-consensus-pow integration:
//! - Blake3Algorithm for PoW mining and verification
//! - MiningCoordinator for multi-threaded mining
//! - PowBlockImport for the block import pipeline
//! - Mining RPC methods (hegemon_startMining, hegemon_stopMining)
//!
//! # Phase 3 Status
//!
//! This phase implements PQ libp2p integration:
//! - PqNetworkConfig for PQ-secure networking
//! - Hybrid X25519 + ML-KEM-768 handshake
//! - ML-DSA-65 peer authentication
//! - Integration with sc-network (pending aligned polkadot-sdk)
//!
//! # Phase 4 Status
//!
//! This phase implements custom RPC extensions:
//! - hegemon_miningStatus, hegemon_startMining, hegemon_stopMining
//! - hegemon_walletNotes, hegemon_walletCommitments, hegemon_walletCiphertexts
//! - hegemon_generateProof, hegemon_submitTransaction
//! - hegemon_consensusStatus, hegemon_telemetry, hegemon_storageFootprint
//!
//! # Phase 9 Status
//!
//! This phase implements full block production:
//! - Task 9.1: NetworkBridge for routing PQ network events to block import ✅
//! - Task 9.2: Transaction pool integration for tx propagation ✅
//! - Task 9.3: Mining worker spawning for block production ✅
//!
//! # Phase 10 Status
//!
//! This phase implements production readiness:
//! - Task 10.1: Polkadot SDK dependency alignment ✅
//! - Task 10.2: Full client integration (TFullClient, WasmExecutor) ✅
//! - Task 10.3: Block import pipeline (PowBlockImport) ✅
//! - Task 10.4: Live network integration 🔲
//! - Task 10.5: Production mining worker 🔲

pub mod block_import;
pub mod chain_spec;
pub mod client;
pub mod command;
pub mod mining_worker;
pub mod network;
pub mod network_bridge;
pub mod rpc;
pub mod service;
pub mod transaction_pool;

// Re-export common types
pub use block_import::{
    BlockImportConfig, ExtractedSeal, HegemonBlockImport, ImportError, ImportResult, ImportStats,
    MockBlockImport, create_mock_block_import, create_mock_block_import_from_env,
    extract_seal_from_header, verify_pow_seal,
};
pub use chain_spec::ChainSpec;
pub use client::{
    FullBackend, FullClient, FullClientConfig, FullTransactionPool, SubstrateChainStateProvider,
    WasmExecutor, create_chain_state_provider, create_chain_state_provider_with_state,
    DEFAULT_DIFFICULTY_BITS,
};
pub use mining_worker::{
    BlockBroadcaster, BlockTemplate, ChainStateProvider, MiningWorker, MiningWorkerConfig,
    MiningWorkerStats, MockBlockBroadcaster, MockChainStateProvider, NetworkBridgeBroadcaster,
    create_network_mining_worker, create_scaffold_mining_worker,
};
pub use network::{PqNetworkConfig, PqNetworkKeypair};
pub use network_bridge::{
    BlockAnnounce, BlockState, IncomingMessage, NetworkBridge, NetworkBridgeBuilder,
    NetworkBridgeStats, SyncRequest, SyncResponse, TransactionMessage,
    BLOCK_ANNOUNCE_PROTOCOL, SYNC_PROTOCOL, TRANSACTIONS_PROTOCOL,
};
pub use rpc::{HegemonApiServer, WalletApiServer, HegemonService, MiningHandle, WalletService};
pub use service::{
    new_full, new_partial, FullComponents, MiningConfig, PartialComponents,
    BlockImportStats, BlockImportTracker, FullBlockImportConfig, wire_import_tracker,
};
pub use transaction_pool::{
    MockTransactionPool, PoolBridgeStats, PoolError, SubmissionResult,
    TransactionPool as TransactionPoolTrait, TransactionPoolBridge, TransactionPoolConfig,
    TransactionSource,
};
