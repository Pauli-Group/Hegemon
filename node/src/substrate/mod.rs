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
//! This phase implements PQ-Noise networking (NOT libp2p):
//!
//! IMPORTANT: This node uses a custom PQ (post-quantum) network layer.
//! - No libp2p - all references to libp2p are legacy/compatibility stubs
//! - Bootnodes: Use HEGEMON_SEEDS env var with IP:port format
//! - Peer count: Use system_health RPC, NOT system_peers
//! - Peer IDs: 32-byte PQ keys, not libp2p PeerIds
//! - PqNetworkConfig for PQ-secure networking
//! - Pure ML-KEM-768 handshake (no classical ECDH)
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
//!
//! # Phase 11.6 Status
//!
//! Chain synchronization:
//! - Task 11.6.1: Block request handler ✅
//! - Task 11.6.2: Chain sync state machine ✅
//! - Task 11.6.3: Warp sync (optional) 🔲

pub mod block_import;
pub mod chain_spec;
pub mod client;
pub mod command;
pub mod epoch_proofs;
pub mod mining_worker;
pub mod network;
pub mod network_bridge;
pub mod rpc;
pub mod service;
pub mod sync;
pub mod transaction_pool;

// Re-export common types
pub use block_import::{
    create_mock_block_import, create_mock_block_import_from_env, extract_seal_from_header,
    verify_pow_seal, BlockImportConfig, ExtractedSeal, HegemonBlockImport, ImportError,
    ImportResult, ImportStats, MockBlockImport,
};
pub use chain_spec::ChainSpec;
pub use client::{
    create_chain_state_provider, create_chain_state_provider_with_state, FullBackend, FullClient,
    FullClientConfig, FullTransactionPool, StateExecutionResult, SubstrateChainStateProvider,
    WasmExecutor, DEFAULT_DIFFICULTY_BITS,
};
pub use mining_worker::{
    compute_extrinsics_root, create_network_mining_worker, create_scaffold_mining_worker,
    BlockBroadcaster, BlockTemplate, ChainStateProvider, MiningWorker, MiningWorkerConfig,
    MiningWorkerStats, MockBlockBroadcaster, MockChainStateProvider, NetworkBridgeBroadcaster,
};
pub use network::{PqNetworkConfig, PqNetworkKeypair};
pub use network_bridge::{
    BlockAnnounce, BlockState, IncomingMessage, NetworkBridge, NetworkBridgeBuilder,
    NetworkBridgeStats, RecursiveEpochProofMessage, RecursiveEpochProofProtocolMessage,
    SyncRequest, SyncResponse, TransactionMessage, BLOCK_ANNOUNCE_PROTOCOL,
    RECURSIVE_EPOCH_PROOFS_PROTOCOL, RECURSIVE_EPOCH_PROOFS_PROTOCOL_V2, SYNC_PROTOCOL,
    TRANSACTIONS_PROTOCOL,
};
pub use rpc::{HegemonApiServer, HegemonService, MiningHandle, WalletApiServer, WalletService};
pub use service::{
    new_full_with_client, wire_import_tracker, BlockImportStats, BlockImportTracker,
    FullBlockImportConfig, MiningConfig,
};
pub use sync::{
    ChainSyncService, PeerSyncState, SyncHandle, SyncState, SyncStats, HEADER_BATCH,
    MAX_BODIES_PER_RESPONSE, MAX_HEADERS_PER_RESPONSE,
};
pub use transaction_pool::{
    MockTransactionPool, PoolBridgeStats, PoolError, SubmissionResult,
    TransactionPool as TransactionPoolTrait, TransactionPoolBridge, TransactionPoolConfig,
    TransactionSource,
};
