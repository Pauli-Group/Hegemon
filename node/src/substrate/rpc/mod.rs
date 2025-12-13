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
//! # Shielded Transaction RPCs (Phase 13+)
//!
//! | Method                          | Description                              |
//! |---------------------------------|------------------------------------------|
//! | `hegemon_submitShieldedTransfer`| Submit shielded transfer with STARK proof|
//! | `hegemon_getEncryptedNotes`     | Fetch ML-KEM encrypted notes             |
//! | `hegemon_getMerkleWitness`      | Get Poseidon Merkle path for a note      |
//! | `hegemon_getShieldedPoolStatus` | Get shielded pool statistics             |
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
//! │  ┌─────────────────────────────────────────────────────────────┐│
//! │  │                    Shielded Pool RPCs                       ││
//! │  │  - submitShieldedTransfer (STARK proofs)                    ││
//! │  │  - getEncryptedNotes (ML-KEM)                               ││
//! │  │  - getMerkleWitness (Poseidon)                              ││
//! │  └─────────────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────────────┘
//! ```

pub mod epoch;
pub mod hegemon;
pub mod production_service;
pub mod shielded;
pub mod shielded_service;
pub mod wallet;

use jsonrpsee::RpcModule;
use std::sync::Arc;

pub use epoch::{EpochApiServer, EpochRpc};
pub use hegemon::{HegemonApiServer, HegemonRpc, HegemonService, MiningHandle};
pub use production_service::ProductionRpcService;
pub use shielded::{ShieldedApiServer, ShieldedPoolService, ShieldedRpc};
pub use shielded_service::MockShieldedPoolService;
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
/// - Shielded pool RPCs for STARK-based private transfers
pub fn create_full<S, P>(
    deps: FullDeps<S, P>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    S: hegemon::HegemonService
        + wallet::WalletService
        + shielded::ShieldedPoolService
        + Send
        + Sync
        + 'static,
    P: hegemon::MiningHandle + Clone + Send + Sync + 'static,
{
    let mut module = RpcModule::new(());

    // Add Hegemon RPC (mining, consensus, telemetry)
    let hegemon_rpc = HegemonRpc::new(deps.service.clone(), deps.pow_handle);
    module.merge(hegemon_rpc.into_rpc())?;

    // Add Wallet RPC (notes, commitments, proofs)
    let wallet_rpc = WalletRpc::new(deps.service.clone());
    module.merge(wallet_rpc.into_rpc())?;

    // Add Shielded Pool RPC (STARK proofs, encrypted notes, Merkle witnesses)
    let shielded_rpc = ShieldedRpc::new(deps.service);
    module.merge(shielded_rpc.into_rpc())?;

    tracing::info!("RPC extensions initialized (Phase 13 - Shielded Wallet Integration)");

    Ok(module)
}

/// Simplified version for initial testing without full service
pub fn create_minimal() -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>> {
    let module = RpcModule::new(());

    tracing::info!("RPC module initialized (minimal mode)");

    Ok(module)
}
