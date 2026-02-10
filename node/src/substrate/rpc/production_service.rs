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
//! let service = ProductionRpcService::new(
//!     client.clone(),
//!     peer_count.clone(),
//!     sync_status.clone(),
//!     peer_details.clone(),
//!     da_chunk_store.clone(),
//!     pending_ciphertext_store.clone(),
//!     mined_blocks.clone(),
//!     mined_history.clone(),
//!     miner_recipient,
//! );
//! let rpc_deps = FullDeps {
//!     service: Arc::new(service),
//!     pow_handle: pow_handle.clone(),
//!     node_config,
//!     deny_unsafe: false,
//!     recursive_block_proof_store: recursive_block_proof_store.clone(),
//!     commitment_block_proof_store: commitment_block_proof_store.clone(),
//!     da_chunk_store: da_chunk_store.clone(),
//!     da_params,
//! };
//! let rpc_module = rpc::create_full(rpc_deps)?;
//! ```

use super::archive::ArchiveMarketService;
use super::hegemon::{
    BlockTimestamp, ConsensusStatus, HegemonService, PeerDetail, StorageFootprint, TelemetrySnapshot,
};
use super::shielded::{ShieldedPoolService, ShieldedPoolStatus};
use super::wallet::{LatestBlock, NoteStatus, WalletService};
use codec::{Decode, Encode};
use network::PeerId;
use pallet_shielded_pool::types::{
    BindingHash, EncryptedNote, FeeParameters, FeeProofKind, StablecoinPolicyBinding, StarkProof,
};
use parking_lot::Mutex as ParkingMutex;
use pallet_timestamp;
use runtime::apis::{ArchiveMarketApi, ConsensusApi, ShieldedPoolApi};
use runtime::AccountId;
use sp_api::ProvideRuntimeApi;
use sc_client_api::BlockBackend;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Instant;
use transaction_circuit::hashing_pq::ciphertext_hash_bytes;

use crate::substrate::service::{DaChunkStore, PendingCiphertextStore, PeerConnectionSnapshot};
use pallet_shielded_pool::types::DIVERSIFIED_ADDRESS_SIZE;
use crate::substrate::mining_worker::MinedBlockRecord;

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
    /// DA chunk store for ciphertext retrieval
    da_chunk_store: Arc<ParkingMutex<DaChunkStore>>,
    /// Pending ciphertext store for sidecar submissions
    pending_ciphertext_store: Arc<ParkingMutex<PendingCiphertextStore>>,
    /// Connected peer count snapshot
    peer_count: Arc<AtomicUsize>,
    /// Connected peer detail snapshots
    peer_details: Arc<parking_lot::RwLock<HashMap<PeerId, PeerConnectionSnapshot>>>,
    /// Sync status flag (true means syncing)
    sync_status: Arc<AtomicBool>,
    /// Node start time for uptime calculation
    start_time: Instant,
    /// Mined block records (local node)
    mined_blocks: Arc<ParkingMutex<Vec<MinedBlockRecord>>>,
    /// Cached mined-by-address history (full chain scan)
    mined_history: Arc<ParkingMutex<MinedHistoryCache>>,
    /// Miner recipient address bytes (if configured)
    miner_recipient: Option<[u8; DIVERSIFIED_ADDRESS_SIZE]>,
    /// Phantom data for the block type
    _phantom: PhantomData<Block>,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct MinedHistoryCache {
    last_scanned: Option<u64>,
    timestamps: Vec<BlockTimestamp>,
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
    pub fn new(
        client: Arc<C>,
        peer_count: Arc<AtomicUsize>,
        sync_status: Arc<AtomicBool>,
        peer_details: Arc<parking_lot::RwLock<HashMap<PeerId, PeerConnectionSnapshot>>>,
        da_chunk_store: Arc<ParkingMutex<DaChunkStore>>,
        pending_ciphertext_store: Arc<ParkingMutex<PendingCiphertextStore>>,
        mined_blocks: Arc<ParkingMutex<Vec<MinedBlockRecord>>>,
        mined_history: Arc<ParkingMutex<MinedHistoryCache>>,
        miner_recipient: Option<[u8; DIVERSIFIED_ADDRESS_SIZE]>,
    ) -> Self {
        Self {
            client,
            peer_count,
            sync_status,
            peer_details,
            da_chunk_store,
            pending_ciphertext_store,
            start_time: Instant::now(),
            mined_blocks,
            mined_history,
            miner_recipient,
            _phantom: PhantomData,
        }
    }
}

impl<C, Block> ProductionRpcService<C, Block>
where
    Block: BlockT,
    C: HeaderBackend<Block>,
{
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
    C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + BlockBackend<Block> + Send + Sync + 'static,
    sp_runtime::traits::NumberFor<Block>: From<u64>,
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
            syncing: self.sync_status.load(Ordering::Relaxed),
            peers: self.peer_count.load(Ordering::Relaxed) as u32,
        }
    }

    fn telemetry_snapshot(&self) -> TelemetrySnapshot {
        let uptime = self.start_time.elapsed();
        let blocks_mined = self.mined_blocks.lock().len() as u64;

        TelemetrySnapshot {
            uptime_secs: uptime.as_secs(),
            tx_count: 0, // TODO: Wire to transaction metrics
            blocks_imported: self.best_number(),
            blocks_mined,
            memory_bytes: 0,     // TODO: Wire to memory metrics
            network_rx_bytes: 0, // TODO: Wire to network metrics
            network_tx_bytes: 0, // TODO: Wire to network metrics
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

        api.difficulty_bits(best_hash)
            .unwrap_or(DEFAULT_DIFFICULTY_BITS)
    }

    fn current_height(&self) -> u64 {
        self.best_number()
    }

    fn block_timestamps(&self, start: u64, end: u64) -> Result<Vec<BlockTimestamp>, String> {
        const MAX_RANGE: u64 = 1000;
        if start > end {
            return Err("start must be <= end".to_string());
        }
        let best = self.best_number();
        let clamped_end = end.min(best);
        let count = clamped_end.saturating_sub(start).saturating_add(1);
        if count > MAX_RANGE {
            return Err(format!(
                "range too large (max {MAX_RANGE} blocks per request); requested {count}"
            ));
        }

        let mut out = Vec::with_capacity(count as usize);
        for number in start..=clamped_end {
            let hash = self
                .client
                .hash(sp_runtime::traits::NumberFor::<Block>::from(number))
                .map_err(|e| format!("failed to fetch hash for {number}: {e:?}"))?
                .ok_or_else(|| format!("missing block hash for {number}"))?;
            let block = self
                .client
                .block(hash)
                .map_err(|e| format!("failed to fetch block {number}: {e:?}"))?
                .ok_or_else(|| format!("missing block {number}"))?
                .block;
            let timestamp_ms = extract_block_timestamp(&block);
            out.push(BlockTimestamp {
                height: number,
                timestamp_ms,
            });
        }

        Ok(out)
    }

    fn mined_block_timestamps(&self) -> Result<Vec<BlockTimestamp>, String> {
        let miner_recipient = match self.miner_recipient {
            Some(recipient) => recipient,
            None => return Ok(vec![]),
        };

        let best = self.best_number();
        let start = {
            let cache = self.mined_history.lock();
            cache.last_scanned.map(|value| value.saturating_add(1)).unwrap_or(0)
        };

        if start > best {
            return Ok(self.mined_history.lock().timestamps.clone());
        }

        let mut new_entries = Vec::new();
        for number in start..=best {
            let hash = self
                .client
                .hash(sp_runtime::traits::NumberFor::<Block>::from(number))
                .map_err(|e| format!("failed to fetch hash for {number}: {e:?}"))?
                .ok_or_else(|| format!("missing block hash for {number}"))?;
            let block = self
                .client
                .block(hash)
                .map_err(|e| format!("failed to fetch block {number}: {e:?}"))?
                .ok_or_else(|| format!("missing block {number}"))?
                .block;
            if let Some(recipient) = extract_coinbase_recipient(&block) {
                if recipient == miner_recipient {
                    let timestamp_ms = extract_block_timestamp(&block);
                    new_entries.push(BlockTimestamp {
                        height: number,
                        timestamp_ms,
                    });
                }
            }
        }

        let mut cache = self.mined_history.lock();
        cache.last_scanned = Some(best);
        cache.timestamps.extend(new_entries);
        Ok(cache.timestamps.clone())
    }

    fn peer_list(&self) -> Vec<PeerDetail> {
        let now = Instant::now();
        let peers = self.peer_details.read();
        peers
            .values()
            .map(|peer| PeerDetail {
                peer_id: format!("0x{}", hex::encode(peer.peer_id)),
                address: peer.addr.to_string(),
                direction: if peer.is_outbound {
                    "outbound".to_string()
                } else {
                    "inbound".to_string()
                },
                best_height: peer.best_height,
                best_hash: format!("0x{}", hex::encode(peer.best_hash)),
                last_seen_secs: now.duration_since(peer.last_seen).as_secs(),
            })
            .collect()
    }
}

fn extract_block_timestamp<Block: BlockT>(block: &Block) -> Option<u64> {
    for extrinsic in block.extrinsics().iter() {
        if let Some(timestamp) = try_decode_timestamp::<Block>(extrinsic) {
            return Some(timestamp);
        }
    }
    None
}

fn extract_coinbase_recipient<Block: BlockT>(
    block: &Block,
) -> Option<[u8; DIVERSIFIED_ADDRESS_SIZE]> {
    for extrinsic in block.extrinsics().iter() {
        if let Some(recipient) = try_decode_coinbase_recipient::<Block>(extrinsic) {
            return Some(recipient);
        }
    }
    None
}

fn try_decode_timestamp<Block: BlockT>(extrinsic: &Block::Extrinsic) -> Option<u64> {
    use codec::Decode;
    let bytes = extrinsic.encode();
    let decoded = runtime::UncheckedExtrinsic::decode(&mut bytes.as_slice()).ok()?;
    match decoded.function {
        runtime::RuntimeCall::Timestamp(pallet_timestamp::Call::set { now }) => Some(now),
        _ => None,
    }
}

fn try_decode_coinbase_recipient<Block: BlockT>(
    extrinsic: &Block::Extrinsic,
) -> Option<[u8; DIVERSIFIED_ADDRESS_SIZE]> {
    use codec::Decode;
    let bytes = extrinsic.encode();
    let decoded = runtime::UncheckedExtrinsic::decode(&mut bytes.as_slice()).ok()?;
    match decoded.function {
        runtime::RuntimeCall::ShieldedPool(pallet_shielded_pool::Call::mint_coinbase {
            coinbase_data,
        }) => Some(coinbase_data.recipient_address),
        _ => None,
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
        let ciphertext_next_index = self
            .da_chunk_store
            .lock()
            .ciphertext_count()
            .unwrap_or(leaf_count);
        let merkle_root = api.merkle_root(best_hash).unwrap_or([0u8; 48]);
        let tree_depth = api.tree_depth(best_hash).unwrap_or(32);

        NoteStatus {
            leaf_count,
            depth: tree_depth as u64,
            root: format!("0x{}", hex::encode(merkle_root)),
            // Ciphertexts may be served from sidecar/DA storage and can diverge from the
            // canonical commitment count (e.g., forks, retention gaps). Wallets should scan
            // up to the maximum index that the node can serve and then map decrypted notes
            // back to commitment positions via their commitments.
            next_index: ciphertext_next_index.max(leaf_count),
        }
    }

    fn commitment_slice(&self, start: u64, limit: usize) -> Result<Vec<(u64, [u8; 48])>, String> {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        match api.get_commitments(best_hash, start, limit as u32) {
            Ok(commitments) => Ok(commitments),
            Err(e) => Err(format!("Runtime API error: {:?}", e)),
        }
    }

    fn ciphertext_slice(&self, start: u64, limit: usize) -> Result<Vec<(u64, Vec<u8>)>, String> {
        self.da_chunk_store
            .lock()
            .ciphertext_slice(start, limit)
            .map_err(|e| format!("DA store error: {e:?}"))
    }

    fn nullifier_list(&self) -> Result<Vec<[u8; 48]>, String> {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        match api.list_nullifiers(best_hash) {
            Ok(nullifiers) => Ok(nullifiers),
            Err(e) => Err(format!("Runtime API error: {:?}", e)),
        }
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

    fn submit_transaction(
        &self,
        _proof: Vec<u8>,
        _ciphertexts: Vec<Vec<u8>>,
    ) -> Result<[u8; 32], String> {
        Err(
            "Transaction submission requires extrinsic construction. Use author_submitExtrinsic."
                .to_string(),
        )
    }

    fn generate_proof(
        &self,
        _inputs: Vec<u64>,
        _outputs: Vec<(Vec<u8>, u64)>,
    ) -> Result<(Vec<u8>, Vec<String>), String> {
        Err("Proof generation is performed client-side. Use the wallet CLI.".to_string())
    }

    fn commitment_count(&self) -> u64 {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();
        api.encrypted_note_count(best_hash).unwrap_or(0)
    }

    fn ciphertext_count(&self) -> u64 {
        self.da_chunk_store.lock().ciphertext_count().unwrap_or(0)
    }
}

// =============================================================================
// ShieldedPoolService Implementation
// =============================================================================

impl<C, Block> ShieldedPoolService for ProductionRpcService<C, Block>
where
    Block: BlockT,
    C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
    C::Api: ConsensusApi<Block> + ShieldedPoolApi<Block> + ArchiveMarketApi<Block>,
{
    fn submit_shielded_transfer(
        &self,
        proof: Vec<u8>,
        nullifiers: Vec<[u8; 48]>,
        commitments: Vec<[u8; 48]>,
        encrypted_notes: Vec<Vec<u8>>,
        anchor: [u8; 48],
        binding_hash: [u8; 64],
        stablecoin: Option<StablecoinPolicyBinding>,
        fee: u64,
        value_balance: i128,
    ) -> Result<[u8; 32], String> {
        // Task 11.7.3: Build the shielded transfer call for the pallet
        //
        // The shielded_transfer extrinsic requires a signed origin (the sender's account).
        // This RPC builds the encoded call data that can be:
        // 1. Signed client-side and submitted via author_submitExtrinsic
        // 2. Used directly if the transaction pool accepts unsigned extrinsics (future)

        if value_balance != 0 {
            return Err("Transparent pool disabled: value_balance must be 0".to_string());
        }

        // Validate input sizes
        let max_nullifiers = runtime::MaxNullifiersPerTx::get() as usize;
        let max_commitments = runtime::MaxCommitmentsPerTx::get() as usize;
        if nullifiers.len() > max_nullifiers {
            return Err(format!("Too many nullifiers (max {})", max_nullifiers));
        }
        if commitments.len() > max_commitments {
            return Err(format!("Too many commitments (max {})", max_commitments));
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
        let bounded_nullifiers: frame_support::BoundedVec<[u8; 48], runtime::MaxNullifiersPerTx> =
            nullifiers
                .try_into()
                .map_err(|_| "Failed to convert nullifiers")?;

        // Convert commitments to BoundedVec
        let bounded_commitments: frame_support::BoundedVec<[u8; 48], runtime::MaxCommitmentsPerTx> =
            commitments
                .try_into()
                .map_err(|_| "Failed to convert commitments")?;

        // Convert encrypted notes to ciphertext hashes + sizes for sidecar submission.
        let mut ciphertext_hashes = Vec::with_capacity(encrypted_notes.len());
        let mut ciphertext_sizes = Vec::with_capacity(encrypted_notes.len());
        let mut ciphertext_bytes = Vec::with_capacity(encrypted_notes.len());
        for note_bytes in encrypted_notes {
            let mut cursor = &note_bytes[..];
            let note = EncryptedNote::decode(&mut cursor)
                .map_err(|_| "Invalid encrypted note encoding")?;
            if !cursor.is_empty() {
                return Err("Encrypted note has trailing bytes".to_string());
            }

            let mut bytes = Vec::with_capacity(note.ciphertext.len() + note.kem_ciphertext.len());
            bytes.extend_from_slice(&note.ciphertext);
            bytes.extend_from_slice(note.kem_ciphertext.as_ref());
            if bytes.len() > pallet_shielded_pool::types::MAX_CIPHERTEXT_BYTES {
                return Err("Encrypted note exceeds max ciphertext size".to_string());
            }

            let hash = ciphertext_hash_bytes(&bytes);
            ciphertext_hashes.push(hash);
            ciphertext_sizes.push(bytes.len() as u32);
            ciphertext_bytes.push((hash, bytes));
        }

        let bounded_ciphertext_hashes: frame_support::BoundedVec<
            [u8; 48],
            runtime::MaxCommitmentsPerTx,
        > = ciphertext_hashes
            .try_into()
            .map_err(|_| "Failed to convert ciphertext hashes")?;

        let bounded_ciphertext_sizes: frame_support::BoundedVec<u32, runtime::MaxCommitmentsPerTx> =
            ciphertext_sizes
                .try_into()
                .map_err(|_| "Failed to convert ciphertext sizes")?;

        {
            let mut pending = self.pending_ciphertext_store.lock();
            for (hash, bytes) in ciphertext_bytes {
                pending.insert(hash, bytes);
            }
        }

        // Convert binding hash
        let binding = BindingHash { data: binding_hash };

        // Build the pallet call
        let call = runtime::RuntimeCall::ShieldedPool(
            pallet_shielded_pool::Call::shielded_transfer_sidecar {
                proof: stark_proof,
                nullifiers: bounded_nullifiers,
                commitments: bounded_commitments,
                ciphertext_hashes: bounded_ciphertext_hashes,
                ciphertext_sizes: bounded_ciphertext_sizes,
                anchor,
                binding_hash: binding,
                stablecoin,
                fee,
                value_balance,
            },
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
            "Built shielded_transfer_sidecar call (Task 11.7.3)"
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
    ) -> Result<Vec<(u64, Vec<u8>, u64, [u8; 48])>, String> {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        let ciphertexts = self
            .da_chunk_store
            .lock()
            .ciphertext_slice(start, limit)
            .map_err(|e| format!("DA store error: {e:?}"))?;

        let commitments = api
            .get_commitments(best_hash, start, limit as u32)
            .map_err(|e| format!("Runtime API error: {:?}", e))?;
        let commitment_map: HashMap<u64, [u8; 48]> = commitments.into_iter().collect();

        let block_number = self.best_number();
        let mut notes = Vec::with_capacity(ciphertexts.len());
        for (index, ciphertext) in ciphertexts {
            if let Some(commitment) = commitment_map.get(&index) {
                notes.push((index, ciphertext, block_number, *commitment));
            }
        }

        Ok(notes)
    }

    fn encrypted_note_count(&self) -> u64 {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        api.encrypted_note_count(best_hash).unwrap_or(0)
    }

    fn get_merkle_witness(
        &self,
        position: u64,
    ) -> Result<(Vec<[u8; 48]>, Vec<bool>, [u8; 48]), String> {
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
        let merkle_root = api.merkle_root(best_hash).unwrap_or([0u8; 48]);
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

    fn is_nullifier_spent(&self, nullifier: &[u8; 48]) -> bool {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        api.is_nullifier_spent(best_hash, *nullifier)
            .unwrap_or(false)
    }

    fn is_valid_anchor(&self, anchor: &[u8; 48]) -> bool {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();

        api.is_valid_anchor(best_hash, *anchor).unwrap_or(false)
    }

    fn chain_height(&self) -> u64 {
        self.best_number()
    }

    fn fee_parameters(&self) -> Result<FeeParameters, String> {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();
        api.fee_parameters(best_hash)
            .map_err(|e| format!("Runtime API error: {:?}", e))
    }

    fn fee_quote(&self, ciphertext_bytes: u64, proof_kind: FeeProofKind) -> Result<u128, String> {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();
        api.fee_quote(best_hash, ciphertext_bytes, proof_kind)
            .map_err(|e| format!("Runtime API error: {:?}", e))?
            .map_err(|_| "Fee quote failed".to_string())
    }

    fn forced_inclusions(
        &self,
    ) -> Result<Vec<pallet_shielded_pool::types::ForcedInclusionStatus>, String> {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();
        api.forced_inclusions(best_hash)
            .map_err(|e| format!("Runtime API error: {:?}", e))
    }
}

// =============================================================================
// ArchiveMarketService Implementation
// =============================================================================

impl<C, Block> ArchiveMarketService for ProductionRpcService<C, Block>
where
    Block: BlockT,
    C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
    C::Api: ArchiveMarketApi<Block>,
{
    fn provider_count(&self) -> Result<u32, String> {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();
        api.archive_provider_count(best_hash)
            .map_err(|e| format!("Runtime API error: {:?}", e))
    }

    fn provider(
        &self,
        provider: AccountId,
    ) -> Result<Option<pallet_archive_market::ProviderInfo<runtime::Runtime>>, String> {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();
        api.archive_provider(best_hash, provider)
            .map_err(|e| format!("Runtime API error: {:?}", e))
    }

    fn providers(
        &self,
    ) -> Result<
        Vec<(
            AccountId,
            pallet_archive_market::ProviderInfo<runtime::Runtime>,
        )>,
        String,
    > {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();
        api.archive_providers(best_hash)
            .map_err(|e| format!("Runtime API error: {:?}", e))
    }

    fn contract(
        &self,
        contract_id: u64,
    ) -> Result<Option<pallet_archive_market::ArchiveContract<runtime::Runtime>>, String> {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();
        api.archive_contract(best_hash, contract_id)
            .map_err(|e| format!("Runtime API error: {:?}", e))
    }

    fn contracts(
        &self,
        provider: AccountId,
    ) -> Result<Vec<pallet_archive_market::ArchiveContract<runtime::Runtime>>, String> {
        let api = self.client.runtime_api();
        let best_hash = self.best_hash();
        api.archive_contracts(best_hash, provider)
            .map_err(|e| format!("Runtime API error: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    // Production service tests require a full client setup
    // See integration tests for full coverage
}
