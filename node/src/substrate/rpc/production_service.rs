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
//!     peer_graph_reports.clone(),
//!     local_peer_id,
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

use super::hegemon::{
    BlockTimestamp, ConsensusStatus, HegemonService, PeerDetail, PeerGraphPeer,
    PeerGraphReportSnapshot, PeerGraphSnapshot, StorageFootprint, TelemetrySnapshot,
};
use super::shielded::{ShieldedPoolService, ShieldedPoolStatus};
use super::wallet::{LatestBlock, NoteStatus, WalletService};
use codec::{Decode, Encode};
use network::PeerId;
use network::PqNetworkHandle;
use pallet_shielded_pool::family::{
    build_envelope as build_shielded_kernel_envelope, MintCoinbaseArgs, ShieldedFamilyAction,
    ShieldedTransferInlineArgs, ACTION_SHIELDED_TRANSFER_INLINE, ACTION_SHIELDED_TRANSFER_SIDECAR,
    FAMILY_SHIELDED_POOL,
};
use pallet_shielded_pool::types::{EncryptedNote, StablecoinPolicyBinding};
use pallet_shielded_pool::verifier::{ShieldedTransferInputs, StarkVerifier};
use pallet_timestamp;
use parking_lot::Mutex as ParkingMutex;
use protocol_kernel::types::ActionEnvelope;
use protocol_versioning::VersionBinding;
use runtime::apis::{ConsensusApi, ShieldedPoolApi};
use sc_client_api::BlockBackend;
use sc_transaction_pool_api::TransactionPool;
use sc_transaction_pool_api::TransactionSource;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Instant;

use crate::substrate::client::HegemonTransactionPool;
use crate::substrate::mining_worker::MinedBlockRecord;
use crate::substrate::network_bridge::{TransactionMessage, TRANSACTIONS_PROTOCOL};
use crate::substrate::service::PeerGraphReport;
use crate::substrate::service::{DaChunkStore, PeerConnectionSnapshot, PendingCiphertextStore};
use crate::substrate::transaction_pool::prevalidate_native_shielded_extrinsic;
use consensus::backend_interface::{
    decode_native_tx_leaf_artifact_bytes, transaction_public_inputs_digest_from_serialized,
    verify_native_tx_leaf_artifact_bytes, NativeTxLeafArtifact, SerializedStarkInputs,
    TX_STATEMENT_HASH_DOMAIN,
};
use pallet_shielded_pool::types::DIVERSIFIED_ADDRESS_SIZE;
use transaction_circuit::hashing_pq::{balance_commitment_bytes, ciphertext_hash_bytes};
use transaction_circuit::public_inputs::BalanceSlot;

/// Default difficulty bits when runtime API query fails
pub const DEFAULT_DIFFICULTY_BITS: u32 = 0x1d00ffff;
const MAX_RPC_MERKLE_WITNESS_NOTES: u64 = 65_536;
const NATIVE_TX_CANONICAL_PADDING_ASSET_ID: u64 = 4_294_967_294;

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
    /// Reference to the real Substrate transaction pool
    transaction_pool: Arc<HegemonTransactionPool>,
    /// DA chunk store for ciphertext retrieval
    da_chunk_store: Arc<ParkingMutex<DaChunkStore>>,
    /// Pending ciphertext store for sidecar submissions
    _pending_ciphertext_store: Arc<ParkingMutex<PendingCiphertextStore>>,
    /// Connected peer count snapshot
    peer_count: Arc<AtomicUsize>,
    /// Connected peer detail snapshots
    peer_details: Arc<parking_lot::RwLock<HashMap<PeerId, PeerConnectionSnapshot>>>,
    /// Peer graph reports from connected peers
    peer_graph_reports: Arc<parking_lot::RwLock<HashMap<PeerId, PeerGraphReport>>>,
    /// Local PQ peer id (if configured)
    local_peer_id: Option<PeerId>,
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
    /// PQ network handle for immediate tx relay to connected peers.
    pq_network_handle: Option<PqNetworkHandle>,
    /// Phantom data for the block type
    _phantom: PhantomData<Block>,
}

#[derive(Debug, Default, Clone)]
pub struct MinedHistoryCache {
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
        transaction_pool: Arc<HegemonTransactionPool>,
        peer_count: Arc<AtomicUsize>,
        sync_status: Arc<AtomicBool>,
        peer_details: Arc<parking_lot::RwLock<HashMap<PeerId, PeerConnectionSnapshot>>>,
        peer_graph_reports: Arc<parking_lot::RwLock<HashMap<PeerId, PeerGraphReport>>>,
        local_peer_id: Option<PeerId>,
        da_chunk_store: Arc<ParkingMutex<DaChunkStore>>,
        pending_ciphertext_store: Arc<ParkingMutex<PendingCiphertextStore>>,
        mined_blocks: Arc<ParkingMutex<Vec<MinedBlockRecord>>>,
        mined_history: Arc<ParkingMutex<MinedHistoryCache>>,
        miner_recipient: Option<[u8; DIVERSIFIED_ADDRESS_SIZE]>,
        pq_network_handle: Option<PqNetworkHandle>,
    ) -> Self {
        Self {
            client,
            transaction_pool,
            peer_count,
            sync_status,
            peer_details,
            peer_graph_reports,
            local_peer_id,
            da_chunk_store,
            _pending_ciphertext_store: pending_ciphertext_store,
            start_time: Instant::now(),
            mined_blocks,
            mined_history,
            miner_recipient,
            pq_network_handle,
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

    async fn broadcast_submitted_transaction(&self, tx_hash: [u8; 32], extrinsic: Vec<u8>) {
        let Some(handle) = self.pq_network_handle.clone() else {
            return;
        };

        let peer_count = handle.peer_count().await;
        if peer_count == 0 {
            tracing::warn!(
                tx_hash = %hex::encode(tx_hash),
                "Accepted local tx but skipped immediate relay broadcast because no peers are connected"
            );
            return;
        }

        let encoded = TransactionMessage::new(vec![extrinsic]).encode();
        let failed = handle
            .broadcast_to_all(TRANSACTIONS_PROTOCOL, encoded)
            .await;
        let delivered = peer_count.saturating_sub(failed.len());

        if delivered == 0 {
            tracing::warn!(
                tx_hash = %hex::encode(tx_hash),
                peer_count,
                failed_peers = failed.len(),
                "Accepted local tx but immediate relay broadcast reached no peers"
            );
        } else {
            tracing::info!(
                tx_hash = %hex::encode(tx_hash),
                peer_count,
                delivered_peers = delivered,
                failed_peers = failed.len(),
                "Immediately relayed accepted local tx to connected peers"
            );
        }
    }

    fn submitted_tx_tracking_state(&self, tx_hash: &sp_core::H256) -> (bool, bool) {
        use sc_transaction_pool_api::{InPoolTransaction, TransactionPool as ScTransactionPool};

        let ready = self
            .transaction_pool
            .ready()
            .any(|tx| *InPoolTransaction::hash(&*tx) == *tx_hash);
        let future = self
            .transaction_pool
            .futures()
            .into_iter()
            .any(|tx| *InPoolTransaction::hash(&tx) == *tx_hash);
        (ready, future)
    }

    fn recover_idempotent_local_submission(
        &self,
        extrinsic_bytes: &[u8],
        rejection: &str,
        submission_kind: &str,
    ) -> Option<(sp_core::H256, bool, bool)> {
        if !is_idempotent_local_submission_error(rejection) {
            return None;
        }

        let tx_hash = local_extrinsic_hash(extrinsic_bytes);
        let (tracked_ready, tracked_future) = self.submitted_tx_tracking_state(&tx_hash);
        if !tracked_ready && !tracked_future {
            return None;
        }

        tracing::warn!(
            tx_hash = %hex::encode(tx_hash.as_ref()),
            tracked_ready,
            tracked_future,
            rejection,
            submission_kind,
            "Recovered duplicate local submission as idempotent success"
        );
        Some((tx_hash, tracked_ready, tracked_future))
    }

    async fn submit_kernel_action_inner(&self, envelope: ActionEnvelope) -> Result<[u8; 32], String>
    where
        Block::Hash: Into<sp_core::H256>,
        C: ProvideRuntimeApi<Block> + Send + Sync + 'static,
        C::Api: ConsensusApi<Block> + ShieldedPoolApi<Block>,
    {
        self.log_shielded_kernel_action_diagnostics(&envelope);
        let call = runtime::RuntimeCall::Kernel(pallet_kernel::Call::submit_action { envelope });
        let extrinsic = runtime::UncheckedExtrinsic::new_unsigned(call);
        let extrinsic_bytes = extrinsic.encode();
        prevalidate_native_shielded_extrinsic(&extrinsic)
            .map_err(|err| format!("kernel action prevalidation failed: {err}"))?;
        let at: sp_core::H256 = self.best_hash().into();
        let (tx_hash, tracked_ready, tracked_future) = match self
            .transaction_pool
            .submit_one(at, TransactionSource::Local, extrinsic)
            .await
        {
            Ok(tx_hash) => {
                let (tracked_ready, tracked_future) = self.submitted_tx_tracking_state(&tx_hash);
                (tx_hash, tracked_ready, tracked_future)
            }
            Err(err) => {
                let rejection = format!("{err:?}");
                if let Some((tx_hash, tracked_ready, tracked_future)) = self
                    .recover_idempotent_local_submission(
                        &extrinsic_bytes,
                        &rejection,
                        "kernel action",
                    )
                {
                    (tx_hash, tracked_ready, tracked_future)
                } else {
                    return Err(format!(
                        "transaction pool rejected kernel action: {rejection}"
                    ));
                }
            }
        };
        if !tracked_ready && !tracked_future {
            return Err(format!(
                "kernel action disappeared after local submission (tx_hash=0x{})",
                hex::encode(tx_hash.as_ref())
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(tx_hash.as_ref());
        self.broadcast_submitted_transaction(out, extrinsic_bytes)
            .await;
        tracing::info!(
            tx_hash = %hex::encode(out),
            tracked_ready,
            tracked_future,
            "Submitted kernel action via Hegemon RPC"
        );
        Ok(out)
    }

    fn log_shielded_kernel_action_diagnostics(&self, envelope: &ActionEnvelope)
    where
        C: ProvideRuntimeApi<Block> + Send + Sync + 'static,
        C::Api: ConsensusApi<Block> + ShieldedPoolApi<Block>,
    {
        log_shielded_kernel_action_diagnostics(self, envelope);
    }
}

fn canonicalize_native_balance_slot_asset_id_host(asset_id: u64) -> u64 {
    if asset_id == u64::MAX {
        NATIVE_TX_CANONICAL_PADDING_ASSET_ID
    } else {
        asset_id
    }
}

fn is_idempotent_local_submission_error(rejection: &str) -> bool {
    let lower = rejection.to_ascii_lowercase();
    lower.contains("toolowpriority") || lower.contains("alreadyimported")
}

fn local_extrinsic_hash(extrinsic_bytes: &[u8]) -> sp_core::H256 {
    sp_core::H256(sp_core::hashing::blake2_256(extrinsic_bytes))
}

fn canonical_balance_slots_from_public_args_host(
    balance_slot_asset_ids: [u64; transaction_circuit::constants::BALANCE_SLOTS],
    fee: u64,
    stablecoin: &Option<StablecoinPolicyBinding>,
) -> Result<Vec<BalanceSlot>, String> {
    use transaction_circuit::constants::NATIVE_ASSET_ID;

    let canonical_asset_ids =
        balance_slot_asset_ids.map(canonicalize_native_balance_slot_asset_id_host);

    if canonical_asset_ids[0] != NATIVE_ASSET_ID {
        return Err(format!(
            "slot0 asset {} != native asset {}",
            canonical_asset_ids[0], NATIVE_ASSET_ID
        ));
    }

    let mut saw_padding = false;
    let mut prev_asset = NATIVE_ASSET_ID;
    for asset_id in canonical_asset_ids.iter().skip(1) {
        if *asset_id == NATIVE_TX_CANONICAL_PADDING_ASSET_ID {
            saw_padding = true;
            continue;
        }
        if saw_padding || *asset_id == NATIVE_ASSET_ID || *asset_id <= prev_asset {
            return Err(format!(
                "non-canonical asset ordering prev={} current={} saw_padding={}",
                prev_asset, asset_id, saw_padding
            ));
        }
        prev_asset = *asset_id;
    }

    if let Some(binding) = stablecoin {
        if !canonical_asset_ids[1..].contains(&binding.asset_id) {
            return Err(format!(
                "stablecoin asset {} missing from balance slots {:?}",
                binding.asset_id, canonical_asset_ids
            ));
        }
    }

    Ok(canonical_asset_ids
        .into_iter()
        .map(|asset_id| {
            let delta = match stablecoin {
                Some(binding) if asset_id == binding.asset_id => binding.issuance_delta,
                _ if asset_id == NATIVE_ASSET_ID => i128::from(fee),
                _ => 0,
            };
            BalanceSlot { asset_id, delta }
        })
        .collect())
}

fn stablecoin_matches_artifact(
    artifact: &SerializedStarkInputs,
    stablecoin: &Option<StablecoinPolicyBinding>,
) -> bool {
    match stablecoin {
        Some(binding) => {
            let (issuance_sign, issuance_magnitude) = if binding.issuance_delta < 0 {
                (1u8, binding.issuance_delta.unsigned_abs() as u64)
            } else {
                (0u8, binding.issuance_delta.unsigned_abs() as u64)
            };
            artifact.stablecoin_enabled == 1
                && artifact.stablecoin_asset_id == binding.asset_id
                && artifact.stablecoin_policy_version == binding.policy_version
                && artifact.stablecoin_issuance_sign == issuance_sign
                && artifact.stablecoin_issuance_magnitude == issuance_magnitude
                && artifact.stablecoin_policy_hash == binding.policy_hash
                && artifact.stablecoin_oracle_commitment == binding.oracle_commitment
                && artifact.stablecoin_attestation_commitment == binding.attestation_commitment
        }
        None => {
            artifact.stablecoin_enabled == 0
                && artifact.stablecoin_asset_id == 0
                && artifact.stablecoin_policy_version == 0
                && artifact.stablecoin_issuance_sign == 0
                && artifact.stablecoin_issuance_magnitude == 0
                && artifact.stablecoin_policy_hash == [0u8; 48]
                && artifact.stablecoin_oracle_commitment == [0u8; 48]
                && artifact.stablecoin_attestation_commitment == [0u8; 48]
        }
    }
}

fn first_vector_mismatch<const N: usize>(lhs: &[[u8; N]], rhs: &[[u8; N]]) -> Option<usize> {
    lhs.iter()
        .zip(rhs.iter())
        .position(|(left, right)| left != right)
        .or_else(|| (lhs.len() != rhs.len()).then_some(lhs.len().min(rhs.len())))
}

fn extend_padded_digests_host(
    out: &mut Vec<u8>,
    values: &[[u8; 48]],
    target: usize,
) -> Result<(), String> {
    if values.len() > target {
        return Err(format!(
            "digest count {} exceeds target {}",
            values.len(),
            target
        ));
    }
    for value in values {
        out.extend_from_slice(value);
    }
    for _ in values.len()..target {
        out.extend_from_slice(&[0u8; 48]);
    }
    Ok(())
}

fn blake3_384_bytes_host(bytes: &[u8]) -> [u8; 48] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    let mut output = [0u8; 48];
    hasher.finalize_xof().fill(&mut output);
    output
}

fn decode_signed_magnitude_host(sign: u8, magnitude: u64, label: &str) -> Result<i128, String> {
    if sign > 1 {
        return Err(format!("{label} sign {sign} is not binary"));
    }
    let magnitude = i128::from(magnitude);
    Ok(if sign == 0 { magnitude } else { -magnitude })
}

fn native_statement_hash_from_artifact_host(
    artifact: &NativeTxLeafArtifact,
) -> Result<[u8; 48], String> {
    let mut message = Vec::new();
    message.extend_from_slice(TX_STATEMENT_HASH_DOMAIN);
    message.extend_from_slice(&artifact.stark_public_inputs.merkle_root);
    extend_padded_digests_host(
        &mut message,
        artifact.tx.nullifiers.as_slice(),
        transaction_circuit::constants::MAX_INPUTS,
    )?;
    extend_padded_digests_host(
        &mut message,
        artifact.tx.commitments.as_slice(),
        transaction_circuit::constants::MAX_OUTPUTS,
    )?;
    extend_padded_digests_host(
        &mut message,
        artifact.tx.ciphertext_hashes.as_slice(),
        transaction_circuit::constants::MAX_OUTPUTS,
    )?;
    let value_balance = decode_signed_magnitude_host(
        artifact.stark_public_inputs.value_balance_sign,
        artifact.stark_public_inputs.value_balance_magnitude,
        "value_balance",
    )?;
    let stablecoin_issuance = decode_signed_magnitude_host(
        artifact.stark_public_inputs.stablecoin_issuance_sign,
        artifact.stark_public_inputs.stablecoin_issuance_magnitude,
        "stablecoin_issuance",
    )?;
    message.extend_from_slice(&artifact.stark_public_inputs.fee.to_le_bytes());
    message.extend_from_slice(&value_balance.to_le_bytes());
    message.extend_from_slice(&artifact.tx.balance_tag);
    message.extend_from_slice(&artifact.tx.version.circuit.to_le_bytes());
    message.extend_from_slice(&artifact.tx.version.crypto.to_le_bytes());
    message.push(artifact.stark_public_inputs.stablecoin_enabled);
    message.extend_from_slice(
        &artifact
            .stark_public_inputs
            .stablecoin_asset_id
            .to_le_bytes(),
    );
    message.extend_from_slice(&artifact.stark_public_inputs.stablecoin_policy_hash);
    message.extend_from_slice(&artifact.stark_public_inputs.stablecoin_oracle_commitment);
    message.extend_from_slice(
        &artifact
            .stark_public_inputs
            .stablecoin_attestation_commitment,
    );
    message.extend_from_slice(&stablecoin_issuance.to_le_bytes());
    message.extend_from_slice(
        &artifact
            .stark_public_inputs
            .stablecoin_policy_version
            .to_le_bytes(),
    );
    Ok(blake3_384_bytes_host(&message))
}

fn log_shielded_kernel_action_diagnostics<C, Block>(
    service: &ProductionRpcService<C, Block>,
    envelope: &ActionEnvelope,
) where
    Block: BlockT,
    C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
    C::Api: ConsensusApi<Block> + ShieldedPoolApi<Block>,
{
    let action = match ShieldedFamilyAction::decode_envelope(envelope) {
        Ok(action) => action,
        Err(err) => {
            tracing::warn!(
                target: "kernel",
                family_id = envelope.family_id,
                action_id = envelope.action_id,
                public_args_len = envelope.public_args.len(),
                "host pre-submit shielded envelope decode failed: {err:?}"
            );
            return;
        }
    };

    let (
        action_label,
        nullifiers,
        commitments,
        ciphertext_hashes,
        binding_hash,
        proof_bytes,
        anchor,
        balance_slot_asset_ids,
        stablecoin,
        fee,
    ) = match action {
        ShieldedFamilyAction::TransferInline { nullifiers, args } => {
            let ciphertext_hashes = args
                .ciphertexts
                .iter()
                .map(|ciphertext| {
                    let mut bytes = Vec::with_capacity(
                        ciphertext.ciphertext.len() + ciphertext.kem_ciphertext.len(),
                    );
                    bytes.extend_from_slice(&ciphertext.ciphertext);
                    bytes.extend_from_slice(&ciphertext.kem_ciphertext);
                    ciphertext_hash_bytes(&bytes)
                })
                .collect::<Vec<_>>();
            (
                "inline",
                nullifiers,
                args.commitments,
                ciphertext_hashes,
                args.binding_hash,
                args.proof,
                args.anchor,
                args.balance_slot_asset_ids,
                args.stablecoin,
                args.fee,
            )
        }
        ShieldedFamilyAction::TransferSidecar { nullifiers, args } => (
            "sidecar",
            nullifiers,
            args.commitments,
            args.ciphertext_hashes,
            args.binding_hash,
            args.proof,
            args.anchor,
            args.balance_slot_asset_ids,
            args.stablecoin,
            args.fee,
        ),
        other => {
            tracing::warn!(
                target: "kernel",
                family_id = envelope.family_id,
                action_id = envelope.action_id,
                decoded_action = ?other,
                "host pre-submit shielded diagnostics skipped unsupported action"
            );
            return;
        }
    };

    let artifact = match decode_native_tx_leaf_artifact_bytes(&proof_bytes) {
        Ok(artifact) => artifact,
        Err(err) => {
            tracing::warn!(
                target: "kernel",
                action = action_label,
                proof_bytes = proof_bytes.len(),
                "host pre-submit native tx leaf decode failed: {err}"
            );
            return;
        }
    };

    if let Err(err) =
        verify_native_tx_leaf_artifact_bytes(&artifact.tx, &artifact.receipt, &proof_bytes)
    {
        tracing::warn!(
            target: "kernel",
            action = action_label,
            proof_bytes = proof_bytes.len(),
            "host pre-submit native tx leaf self-verification failed: {err}"
        );
    }

    let canonical_balance_slot_asset_ids =
        balance_slot_asset_ids.map(canonicalize_native_balance_slot_asset_id_host);
    let runtime_api = service.client.runtime_api();
    let best_hash = service.best_hash();
    let runtime_ciphertext_policy = runtime_api.ciphertext_policy(best_hash).ok();
    let runtime_proof_policy = runtime_api.proof_availability_policy(best_hash).ok();
    let runtime_anchor_known = runtime_api.is_valid_anchor(best_hash, anchor).ok();
    let runtime_nullifiers_spent = nullifiers
        .iter()
        .map(|nullifier| runtime_api.is_nullifier_spent(best_hash, *nullifier).ok())
        .collect::<Vec<_>>();
    let zero_nullifier_present = nullifiers.contains(&[0u8; 48]);
    let zero_commitment_present = commitments.contains(&[0u8; 48]);
    let duplicate_nullifier_present = {
        let mut seen = std::collections::BTreeSet::new();
        let mut duplicate = false;
        for nullifier in &nullifiers {
            if !seen.insert(*nullifier) {
                duplicate = true;
                break;
            }
        }
        duplicate
    };
    let runtime_inputs = ShieldedTransferInputs {
        anchor,
        nullifiers: nullifiers.clone(),
        commitments: commitments.clone(),
        ciphertext_hashes: ciphertext_hashes.clone(),
        balance_slot_asset_ids,
        fee,
        value_balance: 0,
        stablecoin: stablecoin.clone(),
    };
    let expected_binding_hash = StarkVerifier::compute_binding_hash(&runtime_inputs).data;
    let binding_hash_match = expected_binding_hash == binding_hash;
    let expected_balance_tag =
        canonical_balance_slots_from_public_args_host(balance_slot_asset_ids, fee, &stablecoin)
            .and_then(|balance_slots| {
                balance_commitment_bytes(i128::from(fee), &balance_slots)
                    .map_err(|err| format!("balance commitment failed: {err:?}"))
            });

    let version: VersionBinding = envelope.binding.into();
    let nullifiers_match = artifact.tx.nullifiers == nullifiers;
    let commitments_match = artifact.tx.commitments == commitments;
    let ciphertext_hashes_match = artifact.tx.ciphertext_hashes == ciphertext_hashes;
    let balance_tag_match = expected_balance_tag
        .as_ref()
        .map(|expected| artifact.tx.balance_tag == *expected)
        .unwrap_or(false);
    let version_match = artifact.tx.version == version;
    let anchor_match = artifact.stark_public_inputs.merkle_root == anchor;
    let fee_match = artifact.stark_public_inputs.fee == fee;
    let balance_slots_match = artifact
        .stark_public_inputs
        .balance_slot_asset_ids
        .as_slice()
        == canonical_balance_slot_asset_ids;
    let stablecoin_match = stablecoin_matches_artifact(&artifact.stark_public_inputs, &stablecoin);
    let expected_statement_hash = native_statement_hash_from_artifact_host(&artifact);
    let statement_hash_match = expected_statement_hash
        .as_ref()
        .map(|expected| *expected == artifact.receipt.statement_hash)
        .unwrap_or(false);
    let expected_public_inputs_digest =
        transaction_public_inputs_digest_from_serialized(&artifact.stark_public_inputs)
            .map_err(|err| err.to_string());
    let public_inputs_digest_match = expected_public_inputs_digest
        .as_ref()
        .map(|expected| *expected == artifact.receipt.public_inputs_digest)
        .unwrap_or(false);
    let nonzero_receipt_fields = artifact.receipt.proof_digest != [0u8; 48]
        && artifact.receipt.verifier_profile != [0u8; 48];

    if nullifiers_match
        && commitments_match
        && ciphertext_hashes_match
        && balance_tag_match
        && version_match
        && anchor_match
        && fee_match
        && balance_slots_match
        && stablecoin_match
        && binding_hash_match
        && statement_hash_match
        && public_inputs_digest_match
        && nonzero_receipt_fields
    {
        tracing::debug!(
            target: "kernel",
            action = action_label,
            proof_bytes = proof_bytes.len(),
            binding_hash_match,
            zero_nullifier_present,
            zero_commitment_present,
            duplicate_nullifier_present,
            runtime_nullifiers_spent = ?runtime_nullifiers_spent,
            runtime_ciphertext_policy = ?runtime_ciphertext_policy,
            runtime_proof_policy = ?runtime_proof_policy,
            runtime_anchor_known = ?runtime_anchor_known,
            "host pre-submit native tx leaf/public args check passed"
        );
        return;
    }

    tracing::warn!(
        target: "kernel",
        action = action_label,
        proof_bytes = proof_bytes.len(),
        nullifiers_match,
        nullifier_mismatch_index = first_vector_mismatch(&artifact.tx.nullifiers, &nullifiers),
        commitments_match,
        commitment_mismatch_index = first_vector_mismatch(&artifact.tx.commitments, &commitments),
        ciphertext_hashes_match,
        ciphertext_hash_mismatch_index = first_vector_mismatch(
            &artifact.tx.ciphertext_hashes,
            &ciphertext_hashes
        ),
        balance_tag_match,
        version_match,
        anchor_match,
        binding_hash_match,
        zero_nullifier_present,
        zero_commitment_present,
        duplicate_nullifier_present,
        fee_match,
        balance_slots_match,
        stablecoin_match,
        statement_hash_match,
        public_inputs_digest_match,
        nonzero_receipt_fields,
        decoded_fee = artifact.stark_public_inputs.fee,
        expected_fee = fee,
        decoded_version_circuit = artifact.tx.version.circuit,
        decoded_version_crypto = artifact.tx.version.crypto,
        expected_version_circuit = version.circuit,
        expected_version_crypto = version.crypto,
        runtime_nullifiers_spent = ?runtime_nullifiers_spent,
        runtime_ciphertext_policy = ?runtime_ciphertext_policy,
        runtime_proof_policy = ?runtime_proof_policy,
        runtime_anchor_known = ?runtime_anchor_known,
        decoded_balance_slot_asset_ids = ?artifact.stark_public_inputs.balance_slot_asset_ids,
        expected_balance_slot_asset_ids = ?canonical_balance_slot_asset_ids,
        balance_tag_error = %expected_balance_tag.as_ref().err().cloned().unwrap_or_default(),
        statement_hash_error = %expected_statement_hash.as_ref().err().cloned().unwrap_or_default(),
        public_inputs_digest_error = %expected_public_inputs_digest.as_ref().err().cloned().unwrap_or_default(),
        "host pre-submit native tx leaf/public args mismatch"
    );
}

// =============================================================================
// HegemonService Implementation
// =============================================================================

impl<C, Block> HegemonService for ProductionRpcService<C, Block>
where
    Block: BlockT,
    C: ProvideRuntimeApi<Block>
        + HeaderBackend<Block>
        + BlockBackend<Block>
        + Send
        + Sync
        + 'static,
    Block::Hash: Into<sp_core::H256>,
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
        let tx_count = self
            .client
            .block(self.best_hash())
            .ok()
            .flatten()
            .map(|signed| signed.block.extrinsics().len() as u64)
            .unwrap_or(0);
        let (network_rx_bytes, network_tx_bytes) = {
            let peers = self.peer_details.read();
            peers.values().fold((0u64, 0u64), |(rx, tx), peer| {
                (
                    rx.saturating_add(peer.bytes_received),
                    tx.saturating_add(peer.bytes_sent),
                )
            })
        };

        TelemetrySnapshot {
            uptime_secs: uptime.as_secs(),
            tx_count,
            blocks_imported: self.best_number(),
            blocks_mined,
            memory_bytes: 0,
            network_rx_bytes,
            network_tx_bytes,
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
            cache
                .last_scanned
                .map(|value| value.saturating_add(1))
                .unwrap_or(0)
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

    fn peer_graph(&self) -> PeerGraphSnapshot {
        let peers = self.peer_list();
        let now = Instant::now();
        let peer_details = self.peer_details.read();
        let reports = self.peer_graph_reports.read();
        let report_entries = reports
            .iter()
            .map(|(peer_id, report)| {
                let reporter_address = peer_details
                    .get(peer_id)
                    .map(|peer| peer.addr.to_string())
                    .unwrap_or_else(|| "--".to_string());
                PeerGraphReportSnapshot {
                    reporter_peer_id: format!("0x{}", hex::encode(peer_id)),
                    reporter_address,
                    reported_at_secs: now.duration_since(report.reported_at).as_secs(),
                    peers: report
                        .peers
                        .iter()
                        .map(|entry| PeerGraphPeer {
                            peer_id: format!("0x{}", hex::encode(entry.peer_id)),
                            address: entry.addr.to_string(),
                        })
                        .collect(),
                }
            })
            .collect();
        PeerGraphSnapshot {
            local_peer_id: self
                .local_peer_id
                .map(|peer_id| format!("0x{}", hex::encode(peer_id)))
                .unwrap_or_else(|| "--".to_string()),
            peers,
            reports: report_entries,
        }
    }

    fn submit_action(&self, envelope: ActionEnvelope) -> Result<[u8; 32], String> {
        if envelope.family_id != FAMILY_SHIELDED_POOL {
            return Err("stage-1 kernel RPC only accepts shielded family actions".to_string());
        }
        match envelope.action_id {
            ACTION_SHIELDED_TRANSFER_INLINE | ACTION_SHIELDED_TRANSFER_SIDECAR => {}
            _ => {
                return Err(format!(
                    "unsupported public shielded kernel action id {}",
                    envelope.action_id
                ));
            }
        }
        futures::executor::block_on(self.submit_kernel_action_inner(envelope))
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
        runtime::RuntimeCall::Kernel(pallet_kernel::Call::submit_action { envelope }) => {
            let action = ShieldedFamilyAction::decode_envelope(&envelope).ok()?;
            match action {
                ShieldedFamilyAction::MintCoinbase(MintCoinbaseArgs { reward_bundle }) => {
                    Some(reward_bundle.miner_note.recipient_address)
                }
                _ => None,
            }
        }
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
        Err("Generic transaction submission is disabled; use Hegemon shielded RPC.".to_string())
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

#[jsonrpsee::core::async_trait]
impl<C, Block> ShieldedPoolService for ProductionRpcService<C, Block>
where
    Block: BlockT,
    C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
    C::Api: ConsensusApi<Block> + ShieldedPoolApi<Block>,
    Block::Hash: Into<sp_core::H256>,
{
    async fn submit_shielded_transfer(
        &self,
        proof: Vec<u8>,
        nullifiers: Vec<[u8; 48]>,
        commitments: Vec<[u8; 48]>,
        encrypted_notes: Vec<Vec<u8>>,
        anchor: [u8; 48],
        balance_slot_asset_ids: [u64; 4],
        binding_hash: [u8; 64],
        stablecoin: Option<StablecoinPolicyBinding>,
        fee: u64,
        value_balance: i128,
    ) -> Result<[u8; 32], String> {
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

        if proof.is_empty() {
            return Err("Empty native tx-leaf artifact provided".to_string());
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

        // Decode the pallet ciphertext container for the shipped unsigned transfer path.
        let mut pallet_ciphertexts = Vec::with_capacity(encrypted_notes.len());
        for note_bytes in encrypted_notes {
            let mut cursor = &note_bytes[..];
            let note = EncryptedNote::decode(&mut cursor)
                .map_err(|_| "Invalid encrypted note encoding")?;
            if !cursor.is_empty() {
                return Err("Encrypted note has trailing bytes".to_string());
            }
            let note_len = note.ciphertext.len() + note.kem_ciphertext.len();
            if note_len > pallet_shielded_pool::types::MAX_CIPHERTEXT_BYTES {
                return Err("Encrypted note exceeds max ciphertext size".to_string());
            }
            pallet_ciphertexts.push(note);
        }

        let bounded_ciphertexts: frame_support::BoundedVec<
            EncryptedNote,
            runtime::MaxEncryptedNotesPerTx,
        > = pallet_ciphertexts
            .try_into()
            .map_err(|_| "Failed to convert encrypted notes")?;

        let public_args = ShieldedTransferInlineArgs {
            proof,
            commitments: bounded_commitments.into_inner(),
            ciphertexts: bounded_ciphertexts.into_inner(),
            anchor,
            balance_slot_asset_ids,
            binding_hash,
            stablecoin,
            fee,
        }
        .encode();

        let envelope = build_shielded_kernel_envelope(
            runtime::manifest::default_version_binding(),
            ACTION_SHIELDED_TRANSFER_INLINE,
            bounded_nullifiers.into_inner(),
            public_args,
        );

        let call = runtime::RuntimeCall::Kernel(pallet_kernel::Call::submit_action { envelope });
        let extrinsic = runtime::UncheckedExtrinsic::new_unsigned(call);
        let extrinsic_bytes = extrinsic.encode();
        prevalidate_native_shielded_extrinsic(&extrinsic)
            .map_err(|err| format!("unsigned shielded transfer prevalidation failed: {err}"))?;
        let at: sp_core::H256 = self.best_hash().into();

        let (tx_hash, tracked_ready, tracked_future) = match self
            .transaction_pool
            .submit_one(at, TransactionSource::Local, extrinsic)
            .await
        {
            Ok(tx_hash) => {
                let (tracked_ready, tracked_future) = self.submitted_tx_tracking_state(&tx_hash);
                (tx_hash, tracked_ready, tracked_future)
            }
            Err(err) => {
                let rejection = format!("{err:?}");
                if let Some((tx_hash, tracked_ready, tracked_future)) = self
                    .recover_idempotent_local_submission(
                        &extrinsic_bytes,
                        &rejection,
                        "unsigned shielded transfer",
                    )
                {
                    (tx_hash, tracked_ready, tracked_future)
                } else {
                    return Err(format!(
                        "transaction pool rejected unsigned shielded transfer: {rejection}"
                    ));
                }
            }
        };
        if !tracked_ready && !tracked_future {
            return Err(format!(
                "unsigned shielded transfer disappeared after local submission (tx_hash=0x{})",
                hex::encode(tx_hash.as_ref())
            ));
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(tx_hash.as_ref());
        self.broadcast_submitted_transaction(out, extrinsic_bytes)
            .await;
        tracing::info!(
            nullifiers = nullifier_count,
            commitments = commitment_count,
            tx_hash = %hex::encode(out),
            tracked_ready,
            tracked_future,
            "Submitted unsigned shielded transfer via Hegemon RPC"
        );
        Ok(out)
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
        let note_count = api
            .encrypted_note_count(best_hash)
            .map_err(|e| format!("Runtime API error: {:?}", e))?;
        if note_count > MAX_RPC_MERKLE_WITNESS_NOTES {
            return Err(format!(
                "merkle witness RPC disabled above {} notes; use indexed witness service",
                MAX_RPC_MERKLE_WITNESS_NOTES
            ));
        }

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

    fn forced_inclusions(
        &self,
    ) -> Result<Vec<pallet_shielded_pool::types::ForcedInclusionStatus>, String> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::hashing::blake2_256;

    fn test_reward_bundle(seed: u8) -> pallet_shielded_pool::types::BlockRewardBundle {
        pallet_shielded_pool::types::BlockRewardBundle {
            miner_note: pallet_shielded_pool::types::CoinbaseNoteData {
                commitment: [seed; 48],
                encrypted_note: EncryptedNote::default(),
                recipient_address: [seed; DIVERSIFIED_ADDRESS_SIZE],
                amount: u64::from(seed) + 1,
                public_seed: [seed.wrapping_add(1); 32],
            },
        }
    }

    #[test]
    fn try_decode_coinbase_recipient_keeps_kernel_coinbase_compatibility() {
        let reward_bundle = test_reward_bundle(9);
        let recipient = reward_bundle.miner_note.recipient_address;
        let envelope = build_shielded_kernel_envelope(
            runtime::manifest::default_version_binding(),
            pallet_shielded_pool::family::ACTION_MINT_COINBASE,
            Vec::new(),
            MintCoinbaseArgs { reward_bundle }.encode(),
        );
        let extrinsic = runtime::UncheckedExtrinsic::new_unsigned(runtime::RuntimeCall::Kernel(
            pallet_kernel::Call::submit_action { envelope },
        ));

        assert_eq!(
            try_decode_coinbase_recipient::<runtime::Block>(&extrinsic),
            Some(recipient)
        );
    }

    #[test]
    fn duplicate_submission_error_classifier_matches_pool_rejections() {
        assert!(is_idempotent_local_submission_error(
            "Pool(TooLowPriority { old: 100, new: 100 })"
        ));
        assert!(is_idempotent_local_submission_error(
            "AlreadyImported(0x1234)"
        ));
        assert!(!is_idempotent_local_submission_error(
            "InvalidTransaction::Custom(3)"
        ));
    }

    #[test]
    fn local_extrinsic_hash_uses_blake2_256() {
        let bytes = b"hegemon-extrinsic";
        assert_eq!(
            local_extrinsic_hash(bytes),
            sp_core::H256(blake2_256(bytes))
        );
    }
}
