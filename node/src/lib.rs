//! # Hegemon Node Library
//!
//! This crate provides the native Hegemon blockchain node implementation.
//!
//! ## Building
//!
//! Build the node with:
//! ```bash
//! cargo build -p hegemon-node --release
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
pub mod native;
pub mod telemetry;
pub mod transaction;
