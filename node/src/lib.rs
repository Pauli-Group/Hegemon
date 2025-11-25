pub mod api;
pub mod bootstrap;
pub mod chain_spec;
pub mod config;
pub mod error;
pub mod mempool;
pub mod miner;
pub mod storage;
pub mod sync;
pub mod telemetry;
pub mod transaction;
pub mod ui;

mod codec;
mod service;

/// Substrate integration module.
///
/// This module contains the Substrate-based node implementation
/// that will replace the custom Axum-based implementation.
#[cfg(feature = "substrate")]
pub mod substrate;

pub use service::{MinerAction, NodeHandle, NodeService};
