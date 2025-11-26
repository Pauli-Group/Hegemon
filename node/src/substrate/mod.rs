//! Substrate integration module for the Hegemon node.
//!
//! This module contains the Substrate-specific implementation including:
//! - Chain specification configuration
//! - Node service setup with Blake3 PoW
//! - RPC extensions
//! - CLI commands
//! - PQ-secure network transport (Phase 3)
//! - Network bridge for block/tx propagation (Phase 9)
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
//! - NetworkBridge for routing PQ network events to block import
//! - Transaction pool integration for tx propagation
//! - Mining worker spawning for block production
//!
//! Full completion requires aligned polkadot-sdk git dependencies.

pub mod chain_spec;
pub mod command;
pub mod network;
pub mod network_bridge;
pub mod rpc;
pub mod service;

// Re-export common types
pub use chain_spec::ChainSpec;
pub use network::{PqNetworkConfig, PqNetworkKeypair};
pub use network_bridge::{
    BlockAnnounce, BlockState, IncomingMessage, NetworkBridge, NetworkBridgeBuilder,
    NetworkBridgeStats, SyncRequest, SyncResponse, TransactionMessage,
    BLOCK_ANNOUNCE_PROTOCOL, SYNC_PROTOCOL, TRANSACTIONS_PROTOCOL,
};
pub use rpc::{HegemonApiServer, WalletApiServer, HegemonService, MiningHandle, WalletService};
pub use service::{new_full, new_partial, FullComponents, MiningConfig, PartialComponents};
