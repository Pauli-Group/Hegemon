//! # Hegemon Node Library
//!
//! This crate provides the Hegemon blockchain node implementation using the Substrate framework.
//!
//! ## Building
//!
//! Build the production node with:
//! ```bash
//! cargo build -p hegemon-node --features substrate --release
//! ```
//!
//! ## Running
//!
//! ```bash
//! ./target/release/hegemon-node --dev
//! ```

pub mod chain_spec;
pub mod config;
pub mod error;
pub mod miner;
pub mod pow;
pub mod telemetry;
pub mod transaction;

/// Shielded coinbase encryption module (only available with substrate feature)
#[cfg(feature = "substrate")]
pub mod shielded_coinbase;

/// Substrate integration module.
///
/// This module contains the Substrate-based node implementation
/// with full blockchain functionality including:
/// - Blake3 PoW consensus
/// - WASM runtime with DifficultyApi
/// - Real transaction pool
/// - State persistence via RocksDB
/// - PQ-secure networking
#[cfg(feature = "substrate")]
pub mod substrate;

pub use pow::{PowConfig, PowEvent, PowHandle, PowVerifier, PowVerifyError};

