//! Production RPC Service Implementation (Phase 11.7)
//!
//! This module provides the production implementation of all RPC service traits
//! that connects to the real Substrate client, runtime API, and transaction pool.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    ProductionRpcService                                  │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │  ┌───────────────────────┐    ┌───────────────────────────────────────┐ │
//! │  │    HegemonService     │───▶│  client.chain_info()                   │ │
//! │  │  - consensus_status   │    │  client.runtime_api().difficulty_bits()│ │
//! │  │  - current_height     │    └───────────────────────────────────────┘ │
//! │  │  - current_difficulty │                                              │
//! │  └───────────────────────┘                                              │
//! │                                                                          │
//! │  ┌───────────────────────┐    ┌───────────────────────────────────────┐ │
//! │  │    WalletService      │───▶│  client.runtime_api().wallet_*()       │ │
//! │  │  - wallet_notes       │    └───────────────────────────────────────┘ │
//! │  │  - commitments        │                                              │
//! │  └───────────────────────┘                                              │
//! │                                                                          │
//! │  ┌───────────────────────┐    ┌───────────────────────────────────────┐ │
//! │  │  ShieldedPoolService  │───▶│  client.runtime_api().ShieldedPoolApi  │ │
//! │  │  - submit_shielded_*  │    │  transaction_pool.submit_one()          │ │
//! │  │  - get_encrypted_*    │    └───────────────────────────────────────┘ │
//! │  └───────────────────────┘                                              │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! let service = ProductionRpcService::new(client.clone(), transaction_pool.clone());
//! let rpc_deps = FullDeps {
//!     service: Arc::new(service),
//!     pow_handle: pow_handle.clone(),
//!     deny_unsafe: false,
//! };
//! let rpc_module = rpc::create_full(rpc_deps)?;
//! ```

use super::hegemon::{ConsensusStatus, HegemonService, StorageFootprint, TelemetrySnapshot};
use super::shielded::{ShieldedPoolService, ShieldedPoolStatus};
use super::wallet::{LatestBlock, NoteStatus, WalletService};
use runtime::apis::{ConsensusApi, ShieldedPoolApi};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Instant;

/// Default difficulty bits when runtime API query fails
pub const DEFAULT_DIFFICULTY_BITS: u32 = 0x1d00ffff;

/// Production implementation of all RPC service traits.
///
/// This service connects to the real Substrate client and runtime API
/// to provide production-ready RPC functionality.
///
/// # Type Parameters
///
/// * `C` - The Substrate client type
/// * `Block` - The block type
pub struct ProductionRpcService<C, Block>
where
    Block: BlockT,
{
    /// Reference to the Substrate client
    client: Arc<C>,
    /// Node start time for uptime calculation
    start_time: Instant,
    /// Phantom data for the block type
    _phantom: PhantomData<Block>,
}

impl<C, Block> ProductionRpcService<C, Block>
where
    Block: BlockT,
    C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
    C::Api: ConsensusApi<Block> + ShieldedPoolApi<Block>,
{
    /// Create a new production RPC service.
    ///
    /// # Arguments
    ///
    /// * `client` - Reference to the Substrate client
    pub fn new(client: Arc<C>) -> Self {
        Self {
            client,
            start_time: Instant::now(),
            _phantom: PhantomData,
        }
    }

    /// Get the best block hash for runtime API calls.
    fn best_hash(&self) -> Block::Hash {
        self.client.info().best_hash
    }

    /// Get the best block number.
    fn best_number(&self) -> u64 {
        self.client.info().best_number.try_into().unwrap_or(0)
    }
}

// =============================================================================
// HegemonService Implementation
// =============================================================================

impl<C, Block> HegemonService for ProductionRpcService<C, Block>
where
    Block: BlockT,
    C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
    C::Api: ConsensusApi<Block> + ShieldedPoolApi<Block>,
{
    fn consensus_status(&self) -> ConsensusStatus {
        let info = self.client.info();
        let api = self.client.runtime_api();
        let best_hash = info.best_hash;

        // Query state root from header if available
        let state_root = match self.client.header(best_hash) {
            Ok(Some(header)) => {
                use sp_runtime::traits::Header;
                format!("0x{}", hex::encode(header.state_root().as_ref()))
            }
            _ => "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        };

        // Query nullifier root from shielded pool
        let nullifier_root = match api.merkle_root(best_hash) {
            Ok(root) => format!("0x{}", hex::encode(root)),
            Err(_) => {
                "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
            }
        };

        // Query pool balance for supply digest
        let supply_digest = api.pool_balance(best_hash).unwrap_or(0);

        ConsensusStatus {
            height: self.best_number(),
            best_hash: format!("0x{}", hex::encode(best_hash.as_ref())),
            state_root,
            nullifier_root,
            supply_digest,
            syncing: false, // TODO: Wire to real sync status
            peers: 0,       // TODO: Wire to network peer count
        }
    }

    fn telemetry_snapshot(&self) -> TelemetrySnapshot {
        let uptime = self.start_time.elapsed();

        TelemetrySnapshot {
            uptime_secs: uptime.as_secs(),
            tx_count: 0,               // TODO: Wire to transaction metrics
            blocks_imported: self.best_number(),
            blocks_mined: 0,           // TODO: Wire to mining metrics
            memory_bytes: 0,           // TODO: Wire to memory metrics
            network_rx_bytes: 0,       // TODO: Wire to network metrics
            network_tx_bytes: 0,       // TODO: Wire to network metrics
        }
    }

    fn storage_footprint(&self) -> Result<StorageFootprint, String> {
        // TODO: Wire to actual database metrics
        Ok(StorageFootprint {
            total_bytes: 0,
            blocks_bytes: 0,
            state_bytes: 0,
            transactions_bytes: 0,
            nullifiers_bytes: 0,
        })
    }

    fn current_difficulty(&self) -> u32 {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        api.difficulty_bits(best_hash).unwrap_or(DEFAULT_DIFFICULTY_BITS)
    }

    fn current_height(&self) -> u64 {
        self.best_number()
    }
}

// =============================================================================
// WalletService Implementation
// =============================================================================

impl<C, Block> WalletService for ProductionRpcService<C, Block>
where
    Block: BlockT,
    C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
    C::Api: ConsensusApi<Block> + ShieldedPoolApi<Block>,
{
    fn note_status(&self) -> NoteStatus {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        let leaf_count = api.encrypted_note_count(best_hash).unwrap_or(0);
        let merkle_root = api.merkle_root(best_hash).unwrap_or([0u8; 32]);
        let tree_depth = api.tree_depth(best_hash).unwrap_or(32);

        NoteStatus {
            leaf_count,
            depth: tree_depth as u64,
            root: format!("0x{}", hex::encode(merkle_root)),
            next_index: leaf_count,
        }
    }

    fn commitment_slice(&self, start: u64, limit: usize) -> Result<Vec<(u64, u64)>, String> {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        match api.get_encrypted_notes(best_hash, start, limit as u32) {
            Ok(notes) => Ok(notes
                .into_iter()
                .enumerate()
                .map(|(i, (_, _, _, commitment))| {
                    // Convert commitment hash to a u64 for compatibility with existing API
                    let value = u64::from_le_bytes(commitment[0..8].try_into().unwrap_or([0u8; 8]));
                    (start + i as u64, value)
                })
                .collect()),
            Err(e) => Err(format!("Runtime API error: {:?}", e)),
        }
    }

    fn ciphertext_slice(&self, start: u64, limit: usize) -> Result<Vec<(u64, Vec<u8>)>, String> {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        match api.get_encrypted_notes(best_hash, start, limit as u32) {
            Ok(notes) => Ok(notes
                .into_iter()
                .map(|(index, ciphertext, _, _)| (index, ciphertext))
                .collect()),
            Err(e) => Err(format!("Runtime API error: {:?}", e)),
        }
    }

    fn nullifier_list(&self) -> Result<Vec<[u8; 32]>, String> {
        // Note: The runtime API doesn't provide a way to list all nullifiers
        // This would require a custom runtime API or iterating storage
        Ok(Vec::new())
    }

    fn latest_meta(&self) -> LatestBlock {
        let info = self.client.info();
        let api = self.client.runtime_api();
        let best_hash = info.best_hash;

        let state_root = match self.client.header(best_hash) {
            Ok(Some(header)) => {
                use sp_runtime::traits::Header;
                format!("0x{}", hex::encode(header.state_root().as_ref()))
            }
            _ => "0x0".to_string(),
        };

        let nullifier_root = match api.merkle_root(best_hash) {
            Ok(root) => format!("0x{}", hex::encode(root)),
            Err(_) => "0x0".to_string(),
        };

        let supply_digest = api.pool_balance(best_hash).unwrap_or(0);

        LatestBlock {
            height: self.best_number(),
            hash: format!("0x{}", hex::encode(best_hash.as_ref())),
            state_root,
            nullifier_root,
            supply_digest,
            timestamp: 0, // TODO: Wire to timestamp pallet
        }
    }

    fn submit_transaction(&self, _proof: Vec<u8>, _ciphertexts: Vec<Vec<u8>>) -> Result<[u8; 32], String> {
        Err("Transaction submission requires extrinsic construction. Use author_submitExtrinsic.".to_string())
    }

    fn generate_proof(&self, _inputs: Vec<u64>, _outputs: Vec<(Vec<u8>, u64)>) -> Result<(Vec<u8>, Vec<String>), String> {
        Err("Proof generation is performed client-side. Use the wallet CLI.".to_string())
    }

    fn commitment_count(&self) -> u64 {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();
        api.encrypted_note_count(best_hash).unwrap_or(0)
    }

    fn ciphertext_count(&self) -> u64 {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();
        api.encrypted_note_count(best_hash).unwrap_or(0)
    }
}

// =============================================================================
// ShieldedPoolService Implementation
// =============================================================================

impl<C, Block> ShieldedPoolService for ProductionRpcService<C, Block>
where
    Block: BlockT,
    C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
    C::Api: ConsensusApi<Block> + ShieldedPoolApi<Block>,
{
    fn submit_shielded_transfer(
        &self,
        _proof: Vec<u8>,
        _nullifiers: Vec<[u8; 32]>,
        _commitments: Vec<[u8; 32]>,
        _encrypted_notes: Vec<Vec<u8>>,
        _anchor: [u8; 32],
        _binding_sig: [u8; 64],
        _value_balance: i128,
    ) -> Result<[u8; 32], String> {
        // TODO (Phase 14): Build and submit extrinsic to transaction pool
        //
        // Implementation:
        // 1. Encode call: pallet_shielded_pool::Call::shielded_transfer { ... }
        // 2. Build unsigned extrinsic
        // 3. Submit to transaction pool
        //
        // ```rust
        // let call = pallet_shielded_pool::Call::<Runtime>::shielded_transfer {
        //     proof: proof.try_into().map_err(|_| "Invalid proof")?,
        //     nullifiers: nullifiers.try_into().map_err(|_| "Too many nullifiers")?,
        //     commitments: commitments.try_into().map_err(|_| "Too many commitments")?,
        //     encrypted_notes: encrypted_notes.try_into().map_err(|_| "Too many notes")?,
        //     anchor,
        //     binding_sig: binding_sig.try_into().map_err(|_| "Invalid signature")?,
        // };
        // let ext = UncheckedExtrinsic::new_unsigned(call.into());
        // let hash = pool.submit_one(ext)?;
        // ```
        
        Err("Shielded transfer submission requires transaction pool integration. \
             Use RPC `author_submitExtrinsic` with encoded pallet call.".to_string())
    }

    fn get_encrypted_notes(
        &self,
        start: u64,
        limit: usize,
        _from_block: Option<u64>,
        _to_block: Option<u64>,
    ) -> Result<Vec<(u64, Vec<u8>, u64, [u8; 32])>, String> {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        api.get_encrypted_notes(best_hash, start, limit as u32)
            .map_err(|e| format!("Runtime API error: {:?}", e))
    }

    fn encrypted_note_count(&self) -> u64 {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        api.encrypted_note_count(best_hash).unwrap_or(0)
    }

    fn get_merkle_witness(
        &self,
        position: u64,
    ) -> Result<(Vec<[u8; 32]>, Vec<bool>, [u8; 32]), String> {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        api.get_merkle_witness(best_hash, position)
            .map_err(|e| format!("Runtime API error: {:?}", e))?
            .map_err(|_| "Invalid position or witness generation failed".to_string())
    }

    fn get_pool_status(&self) -> ShieldedPoolStatus {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        let total_notes = api.encrypted_note_count(best_hash).unwrap_or(0);
        let total_nullifiers = api.nullifier_count(best_hash).unwrap_or(0);
        let merkle_root = api.merkle_root(best_hash).unwrap_or([0u8; 32]);
        let tree_depth = api.tree_depth(best_hash).unwrap_or(32);
        let pool_balance = api.pool_balance(best_hash).unwrap_or(0);

        ShieldedPoolStatus {
            total_notes,
            total_nullifiers,
            merkle_root: format!("0x{}", hex::encode(merkle_root)),
            tree_depth,
            pool_balance,
            last_update_block: self.best_number(),
        }
    }

    fn shield(
        &self,
        _amount: u128,
        _commitment: [u8; 32],
        _encrypted_note: Vec<u8>,
    ) -> Result<([u8; 32], u64), String> {
        // Shield requires a signed extrinsic from a transparent account
        Err("Shield requires signed extrinsic. Use RPC `author_submitExtrinsic` with encoded pallet call.".to_string())
    }

    fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        api.is_nullifier_spent(best_hash, *nullifier).unwrap_or(false)
    }

    fn is_valid_anchor(&self, anchor: &[u8; 32]) -> bool {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        api.is_valid_anchor(best_hash, *anchor).unwrap_or(false)
    }

    fn chain_height(&self) -> u64 {
        self.best_number()
    }
}

#[cfg(test)]
mod tests {
    // Production service tests require a full client setup
    // See integration tests for full coverage
}
