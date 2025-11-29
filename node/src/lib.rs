// Legacy (non-substrate) modules - only compiled when NOT using substrate feature
#[cfg(not(feature = "substrate"))]
pub mod api;
#[cfg(not(feature = "substrate"))]
pub mod bootstrap;
pub mod chain_spec;
pub mod config;
pub mod error;
#[cfg(not(feature = "substrate"))]
pub mod mempool;
pub mod miner;
pub mod pow;
#[cfg(not(feature = "substrate"))]
pub mod storage;
#[cfg(not(feature = "substrate"))]
pub mod sync;
pub mod telemetry;
pub mod transaction;
pub mod ui;

#[cfg(not(feature = "substrate"))]
mod codec;
#[cfg(not(feature = "substrate"))]
mod service;

/// Substrate integration module.
///
/// This module contains the Substrate-based node implementation
/// that will replace the custom Axum-based implementation.
#[cfg(feature = "substrate")]
pub mod substrate;

pub use pow::{PowConfig, PowEvent, PowHandle, PowVerifier, PowVerifyError};
#[cfg(not(feature = "substrate"))]
pub use service::{MinerAction, NodeHandle, NodeService};
