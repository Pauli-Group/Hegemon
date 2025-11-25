//! Substrate integration module for the Hegemon node.
//!
//! This module contains the Substrate-specific implementation including:
//! - Chain specification configuration
//! - Node service setup with Blake3 PoW
//! - RPC extensions
//! - CLI commands
//!
//! # Phase 2 Status
//!
//! This phase implements the sc-consensus-pow integration:
//! - Blake3Algorithm for PoW mining and verification
//! - MiningCoordinator for multi-threaded mining
//! - PowBlockImport for the block import pipeline
//! - Mining RPC methods (hegemon_startMining, hegemon_stopMining)
//!
//! Full completion requires aligned polkadot-sdk git dependencies.

pub mod chain_spec;
pub mod command;
pub mod rpc;
pub mod service;

// Re-export common types
pub use chain_spec::ChainSpec;
pub use service::{new_full, new_partial, FullComponents, MiningConfig, PartialComponents};
