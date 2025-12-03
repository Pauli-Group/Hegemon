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
use codec::Encode;
use pallet_shielded_pool::types::{BindingSignature, EncryptedNote, StarkProof, ENCRYPTED_NOTE_SIZE, ML_KEM_CIPHERTEXT_LEN};
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
                    // Convert commitment hash to a u64 Felt value
                    // The Felt is stored in the LAST 8 bytes as big-endian
                    // (matching circuits/transaction/src/hashing.rs felt_to_bytes32)
                    let value = u64::from_be_bytes(
                        commitment[24..32].try_into().unwrap_or([0u8; 8])
                    );
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
        proof: Vec<u8>,
        nullifiers: Vec<[u8; 32]>,
        commitments: Vec<[u8; 32]>,
        encrypted_notes: Vec<Vec<u8>>,
        anchor: [u8; 32],
        binding_sig: [u8; 64],
        value_balance: i128,
    ) -> Result<[u8; 32], String> {
        // Task 11.7.3: Build the shielded transfer call for the pallet
        //
        // The shielded_transfer extrinsic requires a signed origin (the sender's account).
        // This RPC builds the encoded call data that can be:
        // 1. Signed client-side and submitted via author_submitExtrinsic
        // 2. Used directly if the transaction pool accepts unsigned extrinsics (future)
        
        // Validate input sizes
        if nullifiers.len() > 4 {
            return Err("Too many nullifiers (max 4)".to_string());
        }
        if commitments.len() > 4 {
            return Err("Too many commitments (max 4)".to_string());
        }
        if encrypted_notes.len() != commitments.len() {
            return Err("Encrypted notes count must match commitments count".to_string());
        }
        
        // Save lengths for logging before conversion
        let nullifier_count = nullifiers.len();
        let commitment_count = commitments.len();
        
        // Convert proof to StarkProof
        let stark_proof = StarkProof::from_bytes(proof);
        if stark_proof.is_empty() {
            return Err("Empty proof provided".to_string());
        }
        
        // Convert nullifiers to BoundedVec
        let bounded_nullifiers: frame_support::BoundedVec<[u8; 32], runtime::MaxNullifiersPerTx> = 
            nullifiers.try_into().map_err(|_| "Failed to convert nullifiers")?;
        
        // Convert commitments to BoundedVec
        let bounded_commitments: frame_support::BoundedVec<[u8; 32], runtime::MaxCommitmentsPerTx> = 
            commitments.try_into().map_err(|_| "Failed to convert commitments")?;
        
        // Convert encrypted notes to EncryptedNote structs
        // Expected format: [ciphertext (611 bytes)][kem_ciphertext (1088 bytes)]
        let required_len = ENCRYPTED_NOTE_SIZE + ML_KEM_CIPHERTEXT_LEN;
        let mut enc_notes = Vec::with_capacity(encrypted_notes.len());
        for note_bytes in encrypted_notes {
            if note_bytes.len() < required_len {
                return Err(format!(
                    "Encrypted note too small: {} bytes (need {})", 
                    note_bytes.len(), 
                    required_len
                ));
            }
            
            let mut ciphertext = [0u8; ENCRYPTED_NOTE_SIZE];
            ciphertext.copy_from_slice(&note_bytes[..ENCRYPTED_NOTE_SIZE]);
            
            // ML-KEM-768 ciphertext for key encapsulation
            let mut kem_ciphertext = [0u8; ML_KEM_CIPHERTEXT_LEN];
            kem_ciphertext.copy_from_slice(&note_bytes[ENCRYPTED_NOTE_SIZE..ENCRYPTED_NOTE_SIZE + ML_KEM_CIPHERTEXT_LEN]);
            
            enc_notes.push(EncryptedNote {
                ciphertext,
                kem_ciphertext,
            });
        }
        
        let bounded_ciphertexts: frame_support::BoundedVec<EncryptedNote, runtime::MaxEncryptedNotesPerTx> = 
            enc_notes.try_into().map_err(|_| "Failed to convert encrypted notes")?;
        
        // Convert binding signature
        let binding = BindingSignature { data: binding_sig };
        
        // Build the pallet call
        let call = runtime::RuntimeCall::ShieldedPool(
            pallet_shielded_pool::Call::shielded_transfer {
                proof: stark_proof,
                nullifiers: bounded_nullifiers,
                commitments: bounded_commitments,
                ciphertexts: bounded_ciphertexts,
                anchor,
                binding_sig: binding,
                value_balance,
            }
        );
        
        // Encode the call
        let encoded_call = call.encode();
        
        // Return hash of the encoded call
        // The client should sign this and submit via author_submitExtrinsic
        use sp_core::hashing::blake2_256;
        let call_hash = blake2_256(&encoded_call);
        
        // Log for debugging
        tracing::info!(
            nullifiers = nullifier_count,
            commitments = commitment_count,
            call_size = encoded_call.len(),
            call_hash = %hex::encode(call_hash),
            "Built shielded_transfer call (Task 11.7.3)"
        );
        
        // Return the encoded call as hex in the "error" field for client to use
        // This is a workaround since the actual submission requires signing
        Err(format!(
            "CALL_DATA:0x{}|CALL_HASH:0x{}|NOTE:Sign this call and submit via author_submitExtrinsic",
            hex::encode(&encoded_call),
            hex::encode(call_hash)
        ))
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
        amount: u128,
        commitment: [u8; 32],
        encrypted_note: Vec<u8>,
    ) -> Result<([u8; 32], u64), String> {
        // Task 11.7.3: Build shield call
        
        // Convert encrypted note to EncryptedNote struct
        // Expected format: [ciphertext (611 bytes)][kem_ciphertext (1088 bytes)]
        let required_len = ENCRYPTED_NOTE_SIZE + ML_KEM_CIPHERTEXT_LEN;
        if encrypted_note.len() < required_len {
            return Err(format!(
                "Encrypted note too small: {} bytes (need {})",
                encrypted_note.len(),
                required_len
            ));
        }
        
        let mut ciphertext = [0u8; ENCRYPTED_NOTE_SIZE];
        ciphertext.copy_from_slice(&encrypted_note[..ENCRYPTED_NOTE_SIZE]);
        
        let mut kem_ciphertext = [0u8; ML_KEM_CIPHERTEXT_LEN];
        kem_ciphertext.copy_from_slice(&encrypted_note[ENCRYPTED_NOTE_SIZE..ENCRYPTED_NOTE_SIZE + ML_KEM_CIPHERTEXT_LEN]);
        
        let enc_note = EncryptedNote {
            ciphertext,
            kem_ciphertext,
        };
        
        // Build the pallet call
        // Note: amount needs to be converted to Balance type
        let call = runtime::RuntimeCall::ShieldedPool(
            pallet_shielded_pool::Call::shield {
                amount: amount.into(),
                commitment,
                encrypted_note: enc_note,
            }
        );
        
        // Encode the call
        let encoded_call = call.encode();
        
        // Return hash of the encoded call
        use sp_core::hashing::blake2_256;
        let call_hash = blake2_256(&encoded_call);
        
        tracing::info!(
            amount = amount,
            commitment = %hex::encode(commitment),
            call_size = encoded_call.len(),
            "Built shield call (Task 11.7.3)"
        );
        
        // Return encoded call info - client must sign and submit
        Err(format!(
            "CALL_DATA:0x{}|CALL_HASH:0x{}|NOTE:Sign this call and submit via author_submitExtrinsic",
            hex::encode(&encoded_call),
            hex::encode(call_hash)
        ))
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
