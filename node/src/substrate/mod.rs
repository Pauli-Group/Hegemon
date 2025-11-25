//! Substrate integration module for the Hegemon node.
//!
//! This module contains the Substrate-specific implementation including:
//! - Chain specification configuration
//! - Node service setup
//! - RPC extensions
//! - CLI commands
//!
//! # Phase 1 Status
//!
//! This is a scaffold for the Substrate migration. Full implementation
//! requires aligned polkadot-sdk dependencies.

pub mod chain_spec;
pub mod command;
pub mod rpc;
pub mod service;

// Re-export common types
pub use chain_spec::ChainSpec;
pub use service::{new_full, new_partial};
