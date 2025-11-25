//! Hegemon Substrate Node Service
//!
//! This module provides the core service implementation for the Substrate-based
//! Hegemon node, including:
//! - Partial node components setup
//! - Full node service initialization
//! - Block import pipeline configuration
//!
//! # Note on Dependency Versions
//!
//! This scaffold is designed for Phase 1 of the Substrate migration. Full
//! implementation requires aligned Polkadot SDK dependencies. Due to version
//! fragmentation on crates.io, production use should switch to git dependencies
//! from the official polkadot-sdk repository.

use sc_service::{error::Error as ServiceError, Configuration, TaskManager};

/// Placeholder for partial node components.
///
/// Full implementation will use:
/// - TFullClient with WasmExecutor
/// - TFullBackend for state storage
/// - BasicPool for transaction pool
/// - LongestChain for select chain
///
/// This requires aligned sp-runtime versions between runtime and sc-service.
pub struct PartialComponentsPlaceholder {
    pub task_manager: TaskManager,
}

/// Creates partial node components (scaffold).
///
/// This is a placeholder implementation for Phase 1. Full implementation
/// requires:
/// 1. Aligned Polkadot SDK dependencies (use git deps from polkadot-sdk)
/// 2. Runtime implementing RuntimeApi trait
/// 3. WASM binary for runtime execution
///
/// See `INTEGRATED_RELEASE_EXECPLAN.md` for Phase 2 requirements.
pub fn new_partial(config: &Configuration) -> Result<PartialComponentsPlaceholder, ServiceError> {
    // Create basic task manager for CLI commands
    let task_manager = TaskManager::new(config.tokio_handle.clone(), None)
        .map_err(|e| ServiceError::Other(format!("Failed to create task manager: {}", e)))?;

    tracing::info!(
        "Hegemon node partial components initialized (Phase 1 scaffold)"
    );
    tracing::info!(
        "Full Substrate integration requires aligned polkadot-sdk dependencies"
    );

    Ok(PartialComponentsPlaceholder { task_manager })
}

/// Creates a full node service (scaffold).
///
/// This is a placeholder for Phase 1. Full implementation will:
/// 1. Initialize client with WASM executor
/// 2. Set up networking with libp2p
/// 3. Configure transaction pool
/// 4. Start block import with PoW consensus
/// 5. Launch RPC server
///
/// Implementation order for Phase 2:
/// 1. Add runtime APIs (sp-api, sp-block-builder, etc.)
/// 2. Configure sc-consensus-pow for Blake2b PoW
/// 3. Integrate existing pallet-pow from runtime
/// 4. Port RPC extensions
pub fn new_full(config: Configuration) -> Result<TaskManager, ServiceError> {
    let partial = new_partial(&config)?;

    tracing::info!(
        "Hegemon node started in Phase 1 mode (scaffold only)"
    );
    tracing::info!(
        "Chain spec: {:?}",
        config.chain_spec.name()
    );
    tracing::info!(
        "Node role: {:?}",
        config.role
    );
    tracing::info!(
        "For full functionality, complete Phase 2: polkadot-sdk git dependencies"
    );

    Ok(partial.task_manager)
}
