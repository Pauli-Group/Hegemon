//! Hegemon Substrate RPC Extensions
//!
//! This module provides custom RPC endpoints for the Hegemon node,
//! complementing the standard Substrate RPC methods.
//!
//! # RPC Endpoint Mapping
//!
//! | Old Axum Endpoint       | New Substrate RPC           | Module   |
//! |-------------------------|----------------------------|----------|
//! | GET `/blocks/latest`    | `chain_getHeader`          | chain    |
//! | GET `/blocks/:hash`     | `chain_getBlock`           | chain    |
//! | POST `/transactions`    | `author_submitExtrinsic`   | author   |
//! | GET `/wallet/notes`     | `hegemon_walletNotes`      | custom   |
//! | GET `/wallet/commitments`| `hegemon_walletCommitments`| custom  |
//! | POST `/wallet/prove`    | `hegemon_generateProof`    | custom   |
//! | GET `/miner/status`     | `hegemon_miningStatus`     | custom   |
//! | POST `/miner/control`   | `hegemon_startMining`      | custom   |
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      RPC Server (jsonrpsee)                      │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
//! │  │  Standard RPCs  │  │  Hegemon RPCs   │  │   Wallet RPCs   │ │
//! │  │  - chain_*      │  │  - mining_*     │  │  - walletNotes  │ │
//! │  │  - author_*     │  │  - consensus_*  │  │  - commitments  │ │
//! │  │  - state_*      │  │  - telemetry_*  │  │  - proof gen    │ │
//! │  │  - system_*     │  │                 │  │                 │ │
//! │  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

pub mod hegemon;
pub mod wallet;

use jsonrpsee::RpcModule;
use std::sync::Arc;

pub use hegemon::{HegemonApiServer, HegemonRpc, HegemonService, MiningHandle};
pub use wallet::{WalletApiServer, WalletRpc, WalletService};

/// Dependency container for RPC handlers.
///
/// This struct holds all the dependencies needed by the RPC handlers
/// to query state and perform actions.
pub struct FullDeps<S, P> {
    /// Service handle for node operations
    pub service: Arc<S>,
    /// PoW mining handle
    pub pow_handle: P,
    /// Whether to deny unsafe RPC calls
    pub deny_unsafe: bool,
}

/// Creates the full RPC extensions for the Hegemon node.
///
/// This merges all RPC modules into a single RpcModule:
/// - Standard Substrate RPCs (when available)
/// - Custom Hegemon RPCs for mining and consensus
/// - Wallet RPCs for note management and proof generation
pub fn create_full<S, P>(
    deps: FullDeps<S, P>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    S: hegemon::HegemonService + wallet::WalletService + Send + Sync + 'static,
    P: hegemon::MiningHandle + Clone + Send + Sync + 'static,
{
    let mut module = RpcModule::new(());

    // Add Hegemon RPC (mining, consensus, telemetry)
    let hegemon_rpc = HegemonRpc::new(deps.service.clone(), deps.pow_handle);
    module.merge(hegemon_rpc.into_rpc())?;

    // Add Wallet RPC (notes, commitments, proofs)
    let wallet_rpc = WalletRpc::new(deps.service);
    module.merge(wallet_rpc.into_rpc())?;

    tracing::info!("RPC extensions initialized (Phase 4)");

    Ok(module)
}

/// Simplified version for initial testing without full service
pub fn create_minimal() -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>> {
    let module = RpcModule::new(());
    
    tracing::info!("RPC module initialized (minimal mode)");
    
    Ok(module)
}
