//! Substrate integration module for the Hegemon node.
//!
//! This module contains the Substrate-specific implementation including:
//! - Chain specification configuration
//! - Node service setup with Blake3 PoW
//! - RPC extensions
//! - CLI commands
//! - PQ-secure network transport (Phase 3)
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
//! Full completion requires aligned polkadot-sdk git dependencies.

pub mod chain_spec;
pub mod command;
pub mod network;
pub mod rpc;
pub mod service;

// Re-export common types
pub use chain_spec::ChainSpec;
pub use network::{PqNetworkConfig, PqNetworkKeypair};
pub use service::{new_full, new_partial, FullComponents, MiningConfig, PartialComponents};
