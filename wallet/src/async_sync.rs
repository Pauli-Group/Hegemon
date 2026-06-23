//! Async Wallet Sync Engine for native node RPC
//!
//! This module provides an async synchronization engine that syncs wallet state
//! using the Hegemon WebSocket RPC client. It replaces the blocking sync engine
//! for use with async runtimes.
//!
//! # Features
//!
//! - Real-time sync via block subscriptions
//! - Efficient paginated fetching
//! - Automatic note decryption and tracking
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use wallet::{NodeRpcClient, WalletStore};
//! use wallet::async_sync::AsyncWalletSyncEngine;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = Arc::new(NodeRpcClient::connect("ws://127.0.0.1:9944").await?);
//! let store = Arc::new(WalletStore::open("wallet.dat", "password")?);
//! let engine = AsyncWalletSyncEngine::new(client, store);
//! let outcome = engine.sync_once().await?;
//! println!("Synced {} notes", outcome.recovered);
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

// StreamExt is required for Subscription::next()
#[allow(unused_imports)]
use futures::StreamExt;
use tokio::sync::RwLock;

use crate::error::WalletError;
use crate::node_rpc::{CiphertextEntry, NodeRpcClient};
use crate::notes::NoteCiphertext;
use crate::store::WalletStore;
use crate::sync::SyncOutcome;
use crate::viewing::{FullViewingKey, IncomingViewingKey, RecoveredNote};

pub const WALLET_SYNC_EXPECTED_TREE_DEPTH: u64 =
    transaction_circuit::constants::CIRCUIT_MERKLE_DEPTH as u64;
pub const WALLET_SYNC_MAX_SNAPSHOT_GAP: u64 = 1_048_576;

/// Async wallet synchronization engine
///
/// This engine syncs wallet state with a Hegemon node using WebSocket RPC.
/// It supports both one-shot synchronization and continuous sync via subscriptions.
pub struct AsyncWalletSyncEngine {
    /// RPC client for node communication
    client: Arc<NodeRpcClient>,
    /// Wallet store (wrapped for interior mutability)
    store: Arc<WalletStore>,
    /// Page size for fetching commitments/ciphertexts
    page_limit: usize,
    /// Skip genesis hash validation (for --force-rescan)
    skip_genesis_check: bool,
}

impl AsyncWalletSyncEngine {
    /// Create a new async sync engine
    ///
    /// # Arguments
    ///
    /// * `client` - native node RPC client
    /// * `store` - Wallet store
    pub fn new(client: Arc<NodeRpcClient>, store: Arc<WalletStore>) -> Self {
        Self {
            client,
            store,
            page_limit: 256,
            skip_genesis_check: false,
        }
    }

    /// Create with custom page limit
    pub fn with_page_limit(mut self, limit: usize) -> Self {
        self.page_limit = limit;
        self
    }

    /// Skip genesis hash validation (use after manual reset)
    pub fn with_skip_genesis_check(mut self, skip: bool) -> Self {
        self.skip_genesis_check = skip;
        self
    }

    /// Perform a single synchronization pass
    ///
    /// Fetches all new commitments, ciphertexts, and nullifiers from the node
    /// and updates the wallet store.
    pub async fn sync_once(&self) -> Result<SyncOutcome, WalletError> {
        for attempt in 0..=1 {
            let mut outcome = SyncOutcome::default();

            // Validate genesis hash to detect chain resets
            let metadata = self.client.get_chain_metadata().await?;
            if !self.skip_genesis_check {
                // Try to set genesis hash (will fail if mismatched)
                self.store.set_genesis_hash(metadata.genesis_hash)?;
            } else {
                // Force rescan mode: reset if genesis changed, but also ensure we record
                // the genesis hash even if this wallet has never synced before.
                match self.store.genesis_hash()? {
                    None => {
                        self.store.set_genesis_hash(metadata.genesis_hash)?;
                    }
                    Some(existing) if existing != metadata.genesis_hash => {
                        eprintln!(
                            "Chain genesis mismatch detected, resetting wallet sync state..."
                        );
                        self.store.reset_sync_state()?;
                        self.store.set_genesis_hash(metadata.genesis_hash)?;
                    }
                    _ => {}
                }
            }

            // Detect deep rewrites when genesis stays the same but historical blocks changed.
            // Without this check, a wallet can keep stale commitments and build invalid anchors.
            let stored_height = self.store.last_synced_height()?;
            if stored_height > 0 {
                if let Some(stored_hash) = self.store.last_synced_block_hash()? {
                    if let Some(observed_hash) = self.client.block_hash(stored_height).await? {
                        if observed_hash != stored_hash {
                            if attempt == 0 {
                                eprintln!(
                                    "Detected chain rewrite at height {} (wallet={}, node={}); resetting wallet sync state...",
                                    stored_height,
                                    hex::encode(stored_hash),
                                    hex::encode(observed_hash),
                                );
                                self.store.reset_sync_state()?;
                                self.store.set_genesis_hash(metadata.genesis_hash)?;
                                continue;
                            }
                            return Err(WalletError::InvalidState("chain rewrite detected"));
                        }
                    }
                }
            }

            // Get current note status from node
            let note_status = self.client.note_status().await?;
            let mut commitment_cursor = self.store.next_commitment_index()?;
            validate_note_status_snapshot(
                &note_status,
                commitment_cursor,
                self.store.next_ciphertext_index()?,
                WALLET_SYNC_MAX_SNAPSHOT_GAP,
            )?;
            self.store.set_tree_depth(note_status.depth as u32)?;

            // Detect if our cursor is ahead of the chain. This can happen if:
            // - the node state was wiped/restarted (even with the same genesis hash), or
            // - we experienced a reorg that removed commitments we had already scanned.
            //
            // In either case, the safest behavior is to reset and rescan from scratch.
            if commitment_cursor > note_status.leaf_count {
                eprintln!(
                    "Wallet cursor ahead of chain ({} > {}); resetting wallet sync state...",
                    commitment_cursor, note_status.leaf_count
                );
                self.store.reset_sync_state()?;
                self.store.set_genesis_hash(metadata.genesis_hash)?;
                commitment_cursor = 0;
            }

            // Sync commitments
            while commitment_cursor < note_status.leaf_count {
                let entries = self
                    .client
                    .commitments(commitment_cursor, self.page_limit)
                    .await?;
                if entries.is_empty() {
                    break;
                }
                let pairs: Vec<(u64, [u8; 48])> = entries
                    .iter()
                    .map(|entry| (entry.index, entry.value))
                    .collect();
                self.store.append_commitments(&pairs)?;
                commitment_cursor = self.store.next_commitment_index()?;
                outcome.commitments += entries.len();
            }

            if commitment_cursor != note_status.leaf_count {
                if attempt == 0 {
                    eprintln!(
                        "Commitment sync incomplete (wallet_cursor={}, chain_leaf_count={}); resetting wallet sync state...",
                        commitment_cursor, note_status.leaf_count
                    );
                    self.store.reset_sync_state()?;
                    self.store.set_genesis_hash(metadata.genesis_hash)?;
                    continue;
                }
                return Err(WalletError::InvalidState("commitment sync incomplete"));
            }

            let wallet_root = self.store.commitment_tree()?.root();
            let chain_root = parse_hash_48(&note_status.root)?;
            if wallet_root != chain_root {
                if attempt == 0 {
                    eprintln!(
                        "Wallet commitment root mismatch (wallet={}, chain={}); resetting wallet sync state...",
                        hex::encode(wallet_root),
                        hex::encode(chain_root),
                    );
                    self.store.reset_sync_state()?;
                    self.store.set_genesis_hash(metadata.genesis_hash)?;
                    continue;
                }
                return Err(WalletError::InvalidState("wallet commitment root mismatch"));
            }

            if let Err(err) = self.store.validate_notes_against_commitments() {
                if self.store.repair_note_positions().is_ok()
                    && self.store.validate_notes_against_commitments().is_ok()
                {
                    eprintln!("Wallet notes repaired against commitments.");
                } else if attempt == 0 {
                    eprintln!(
                        "Wallet notes out of sync with commitments; resetting wallet sync state..."
                    );
                    self.store.reset_sync_state()?;
                    self.store.set_genesis_hash(metadata.genesis_hash)?;
                    continue;
                } else {
                    return Err(err);
                }
            }

            if let Err(err) = self.store.validate_notes_internal_consistency() {
                if attempt == 0 {
                    eprintln!(
                        "Wallet note witness data is internally inconsistent; resetting wallet sync state..."
                    );
                    self.store.reset_sync_state()?;
                    self.store.set_genesis_hash(metadata.genesis_hash)?;
                    continue;
                }
                return Err(err);
            }

            // Sync ciphertexts and attempt decryption
            let mut ciphertext_cursor = self.store.next_ciphertext_index()?;
            if ciphertext_cursor > note_status.next_index {
                eprintln!(
                    "Wallet ciphertext cursor ahead of chain ({} > {}); resetting wallet sync state...",
                    ciphertext_cursor, note_status.next_index
                );
                self.store.reset_sync_state()?;
                self.store.set_genesis_hash(metadata.genesis_hash)?;
                ciphertext_cursor = 0;
            }
            while ciphertext_cursor < note_status.next_index {
                let mut entries = self
                    .client
                    .ciphertexts(ciphertext_cursor, self.page_limit)
                    .await?;
                cap_ciphertext_page_to_snapshot(&mut entries, note_status.next_index);
                if entries.is_empty() {
                    entries = self
                        .client
                        .archive_ciphertexts(ciphertext_cursor, self.page_limit)
                        .await?;
                    cap_ciphertext_page_to_snapshot(&mut entries, note_status.next_index);
                }

                if !ciphertext_page_is_contiguous(
                    ciphertext_cursor,
                    note_status.next_index,
                    &entries,
                )? {
                    entries = self
                        .client
                        .archive_ciphertexts(ciphertext_cursor, self.page_limit)
                        .await?;
                    cap_ciphertext_page_to_snapshot(&mut entries, note_status.next_index);
                }
                require_ciphertext_page_contiguous(
                    ciphertext_cursor,
                    note_status.next_index,
                    &entries,
                )?;

                let start_index = ciphertext_cursor;
                let mut expected = start_index;
                let mut recovered = Vec::with_capacity(entries.len());
                let ivk = self.store.incoming_key()?;
                let full_viewing_key = self.store.full_viewing_key()?;

                for entry in entries {
                    if entry.index != expected {
                        return Err(WalletError::InvalidState("ciphertext page gap"));
                    }
                    outcome.ciphertexts += 1;

                    // Debug: log ciphertext details vs expected
                    if std::env::var("WALLET_DEBUG_DECRYPT").is_ok() {
                        let material = ivk.address_material(entry.ciphertext.diversifier_index)?;
                        eprintln!(
                            "[DEBUG] Ciphertext #{}: version={} suite={} div_idx={}",
                            entry.index,
                            entry.ciphertext.version,
                            entry.ciphertext.crypto_suite,
                            entry.ciphertext.diversifier_index
                        );
                        eprintln!("  expected version: {}", material.version());
                        eprintln!("  expected suite: {}", material.crypto_suite());
                        eprintln!(
                            "  version match: {}",
                            entry.ciphertext.version == material.version()
                        );
                        eprintln!(
                            "  suite match: {}",
                            entry.ciphertext.crypto_suite == material.crypto_suite()
                        );
                        eprintln!(
                            "  div_idx match: {}",
                            entry.ciphertext.diversifier_index == material.diversifier_index
                        );
                    }

                    recovered.push(
                        match decrypt_recovered_note(
                            full_viewing_key.as_ref(),
                            &ivk,
                            &entry.ciphertext,
                        ) {
                            Ok(note) => Some(note),
                            Err(WalletError::NoteMismatch(reason)) => {
                                // Note not for this wallet, skip
                                if std::env::var("WALLET_DEBUG_DECRYPT").is_ok() {
                                    eprintln!("  -> NoteMismatch: {}", reason);
                                }
                                None
                            }
                            Err(WalletError::DecryptionFailure) => {
                                if std::env::var("WALLET_DEBUG_DECRYPT").is_ok() {
                                    eprintln!("  -> DecryptionFailure (not for this wallet)");
                                }
                                None
                            }
                            Err(err) => return Err(err),
                        },
                    );

                    expected = expected
                        .checked_add(1)
                        .ok_or(WalletError::InvalidState("ciphertext index overflow"))?;
                }

                outcome.recovered += self.store.apply_ciphertext_batch(start_index, recovered)?;
                ciphertext_cursor = self.store.next_ciphertext_index()?;
            }

            // Sync nullifiers
            let nullifier_set = self.client.nullifiers().await?;
            outcome.spent += self.store.mark_nullifiers(&nullifier_set)?;

            // Update pending transactions
            let latest = self.client.latest_block().await?;
            self.store.refresh_pending(latest.height, &nullifier_set)?;
            let latest_hash = parse_hash_32(&latest.hash)?;
            self.store.set_last_synced_block_hash(latest_hash)?;
            self.store.set_last_synced_height(latest.height)?;

            return Ok(outcome);
        }

        Err(WalletError::InvalidState("sync failed after reset"))
    }

    /// Run continuous synchronization with block subscriptions
    ///
    /// Subscribes to new block headers and syncs after each new block.
    /// This runs indefinitely until the subscription fails or is cancelled.
    ///
    /// # Arguments
    ///
    /// * `on_sync` - Callback invoked after each sync with the outcome
    pub async fn run_continuous<F>(&self, mut on_sync: F) -> Result<(), WalletError>
    where
        F: FnMut(SyncOutcome),
    {
        // Initial sync
        let outcome = self.sync_once().await?;
        on_sync(outcome);

        // Subscribe to new blocks
        let mut subscription = self.client.subscribe_new_heads().await?;

        // Sync on each new block
        while let Some(result) = subscription.next().await {
            match result {
                Ok(_header) => {
                    match self.sync_once().await {
                        Ok(outcome) => on_sync(outcome),
                        Err(e) => {
                            // Log error but continue
                            eprintln!("Sync error: {}", e);
                        }
                    }
                }
                Err(e) => {
                    return Err(WalletError::Rpc(format!("Subscription error: {}", e)));
                }
            }
        }

        Ok(())
    }

    /// Run continuous sync with finalized blocks only
    ///
    /// Only syncs when blocks are finalized, providing stronger consistency.
    pub async fn run_continuous_finalized<F>(&self, mut on_sync: F) -> Result<(), WalletError>
    where
        F: FnMut(SyncOutcome),
    {
        // Initial sync
        let outcome = self.sync_once().await?;
        on_sync(outcome);

        // Subscribe to finalized blocks
        let mut subscription = self.client.subscribe_finalized_heads().await?;

        while let Some(result) = subscription.next().await {
            match result {
                Ok(_header) => match self.sync_once().await {
                    Ok(outcome) => on_sync(outcome),
                    Err(e) => {
                        eprintln!("Sync error: {}", e);
                    }
                },
                Err(e) => {
                    return Err(WalletError::Rpc(format!("Subscription error: {}", e)));
                }
            }
        }

        Ok(())
    }
}

fn parse_hash_32(input: &str) -> Result<[u8; 32], WalletError> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    if trimmed.len() != 64 {
        return Err(WalletError::Serialization(format!(
            "invalid hash hex length: expected 64 chars, got {}",
            trimmed.len()
        )));
    }
    let bytes = hex::decode(trimmed)
        .map_err(|e| WalletError::Serialization(format!("Invalid hash hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(WalletError::Serialization(format!(
            "invalid hash length: expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hash_48(input: &str) -> Result<[u8; 48], WalletError> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    if trimmed.len() != 96 {
        return Err(WalletError::Serialization(format!(
            "invalid 48-byte hex length: expected 96 chars, got {}",
            trimmed.len()
        )));
    }
    let bytes = hex::decode(trimmed)
        .map_err(|e| WalletError::Serialization(format!("Invalid 48-byte hex: {e}")))?;
    if bytes.len() != 48 {
        return Err(WalletError::Serialization(format!(
            "invalid 48-byte hash length: expected 48 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn validate_note_status_snapshot(
    note_status: &crate::node_rpc::NoteStatus,
    commitment_cursor: u64,
    ciphertext_cursor: u64,
    max_snapshot_gap: u64,
) -> Result<(), WalletError> {
    if note_status.depth != WALLET_SYNC_EXPECTED_TREE_DEPTH {
        return Err(WalletError::InvalidState(
            "wallet note status depth mismatch",
        ));
    }
    let tree_capacity = 1u128
        .checked_shl(
            u32::try_from(note_status.depth)
                .map_err(|_| WalletError::InvalidState("wallet note status depth too large"))?,
        )
        .ok_or(WalletError::InvalidState(
            "wallet note status capacity overflow",
        ))?;
    if u128::from(note_status.leaf_count) > tree_capacity {
        return Err(WalletError::InvalidState(
            "wallet note status leaf count exceeds tree capacity",
        ));
    }
    if u128::from(note_status.next_index) > tree_capacity {
        return Err(WalletError::InvalidState(
            "wallet note status ciphertext index exceeds tree capacity",
        ));
    }
    if note_status.leaf_count.saturating_sub(commitment_cursor) > max_snapshot_gap {
        return Err(WalletError::InvalidState(
            "wallet note status commitment snapshot too large",
        ));
    }
    if note_status.next_index.saturating_sub(ciphertext_cursor) > max_snapshot_gap {
        return Err(WalletError::InvalidState(
            "wallet note status ciphertext snapshot too large",
        ));
    }
    Ok(())
}

fn ciphertext_page_is_contiguous(
    start: u64,
    next_index: u64,
    entries: &[CiphertextEntry],
) -> Result<bool, WalletError> {
    match require_ciphertext_page_contiguous(start, next_index, entries) {
        Ok(()) => Ok(true),
        Err(WalletError::InvalidState("ciphertext page missing"))
        | Err(WalletError::InvalidState("ciphertext page gap")) => Ok(false),
        Err(err) => Err(err),
    }
}

fn cap_ciphertext_page_to_snapshot(entries: &mut Vec<CiphertextEntry>, next_index: u64) {
    let Some(end) = entries.iter().position(|entry| entry.index >= next_index) else {
        return;
    };
    entries.truncate(end);
}

fn require_ciphertext_page_contiguous(
    start: u64,
    next_index: u64,
    entries: &[CiphertextEntry],
) -> Result<(), WalletError> {
    if start >= next_index {
        return Ok(());
    }
    if entries.is_empty() {
        return Err(WalletError::InvalidState("ciphertext page missing"));
    }

    let mut expected = start;
    for entry in entries {
        if entry.index != expected {
            return Err(WalletError::InvalidState("ciphertext page gap"));
        }
        expected = expected
            .checked_add(1)
            .ok_or(WalletError::InvalidState("ciphertext index overflow"))?;
        if expected > next_index {
            return Err(WalletError::InvalidState(
                "ciphertext page beyond chain tip",
            ));
        }
    }

    Ok(())
}

fn decrypt_recovered_note(
    full_viewing_key: Option<&FullViewingKey>,
    incoming_key: &IncomingViewingKey,
    ciphertext: &NoteCiphertext,
) -> Result<RecoveredNote, WalletError> {
    full_viewing_key
        .map(|fvk| fvk.decrypt_note(ciphertext))
        .unwrap_or_else(|| incoming_key.decrypt_note(ciphertext))
}

/// Sync engine with shared state for concurrent access
///
/// Wraps AsyncWalletSyncEngine with RwLock protection for use
/// in multi-threaded contexts (e.g., with a web server).
pub struct SharedSyncEngine {
    inner: RwLock<AsyncWalletSyncEngine>,
}

impl SharedSyncEngine {
    /// Create a new shared sync engine
    pub fn new(client: Arc<NodeRpcClient>, store: Arc<WalletStore>) -> Self {
        Self {
            inner: RwLock::new(AsyncWalletSyncEngine::new(client, store)),
        }
    }

    /// Perform a single synchronization pass
    pub async fn sync_once(&self) -> Result<SyncOutcome, WalletError> {
        let engine = self.inner.read().await;
        engine.sync_once().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::viewing::{FullViewingKey, IncomingViewingKey};
    use crate::{
        keys::RootSecret,
        notes::{MemoPlaintext, NoteCiphertext, NotePlaintext},
    };
    use rand::{rngs::StdRng, SeedableRng};
    use serde::Deserialize;

    fn sample_ciphertext_entry(index: u64) -> CiphertextEntry {
        let root = RootSecret::from_bytes([index as u8; 32]);
        let keys = root.derive();
        let address = keys.address(0).unwrap().shielded_address();
        let mut rng = StdRng::seed_from_u64(index + 100);
        let note = NotePlaintext::random(1 + index, 0, MemoPlaintext::default(), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        CiphertextEntry { index, ciphertext }
    }

    #[test]
    fn test_sync_outcome_default() {
        let outcome = SyncOutcome::default();
        assert_eq!(outcome.commitments, 0);
        assert_eq!(outcome.ciphertexts, 0);
        assert_eq!(outcome.recovered, 0);
        assert_eq!(outcome.spent, 0);
    }

    #[test]
    fn sync_prefers_full_viewing_key_for_commitment_consistency() {
        let mut rng = StdRng::seed_from_u64(42);
        let root = RootSecret::from_rng(&mut rng);
        let keys = root.derive();
        let material = keys.address(0).expect("derive address");
        let address = material.shielded_address();

        let note = NotePlaintext::random(123, 0, MemoPlaintext::default(), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).expect("encrypt note");

        let ivk = IncomingViewingKey::from_keys(&keys);
        let fvk = FullViewingKey::from_keys(&keys);

        let recovered_full =
            decrypt_recovered_note(Some(&fvk), &ivk, &ciphertext).expect("full key decrypt");
        assert_eq!(recovered_full.note_data.pk_auth, keys.spend.auth_key());

        let recovered_incoming =
            decrypt_recovered_note(None, &ivk, &ciphertext).expect("incoming key decrypt");
        assert_eq!(recovered_incoming.note_data.pk_auth, [0u8; 32]);
    }

    #[test]
    fn ciphertext_page_validation_accepts_contiguous_pages() {
        let entries = vec![sample_ciphertext_entry(0), sample_ciphertext_entry(1)];
        require_ciphertext_page_contiguous(0, 4, &entries).expect("contiguous prefix");
        assert!(ciphertext_page_is_contiguous(0, 4, &entries).expect("classification succeeds"));

        let final_page = vec![sample_ciphertext_entry(3)];
        require_ciphertext_page_contiguous(3, 4, &final_page).expect("contiguous final page");
        require_ciphertext_page_contiguous(4, 4, &[]).expect("empty page past tip");
    }

    #[test]
    fn ciphertext_page_validation_rejects_missing_substituted_and_overrun_pages() {
        let missing = require_ciphertext_page_contiguous(0, 2, &[]).unwrap_err();
        assert!(matches!(
            missing,
            WalletError::InvalidState("ciphertext page missing")
        ));
        assert!(!ciphertext_page_is_contiguous(0, 2, &[]).unwrap());

        let substituted = vec![sample_ciphertext_entry(1)];
        let err = require_ciphertext_page_contiguous(0, 2, &substituted).unwrap_err();
        assert!(matches!(
            err,
            WalletError::InvalidState("ciphertext page gap")
        ));
        assert!(!ciphertext_page_is_contiguous(0, 2, &substituted).unwrap());

        let gapped = vec![sample_ciphertext_entry(0), sample_ciphertext_entry(2)];
        let err = require_ciphertext_page_contiguous(0, 3, &gapped).unwrap_err();
        assert!(matches!(
            err,
            WalletError::InvalidState("ciphertext page gap")
        ));

        let overrun = vec![
            sample_ciphertext_entry(0),
            sample_ciphertext_entry(1),
            sample_ciphertext_entry(2),
        ];
        let err = require_ciphertext_page_contiguous(0, 2, &overrun).unwrap_err();
        assert!(matches!(
            err,
            WalletError::InvalidState("ciphertext page beyond chain tip")
        ));
    }

    #[test]
    fn ciphertext_page_cap_ignores_rows_beyond_sync_snapshot() {
        let mut entries = vec![
            sample_ciphertext_entry(0),
            sample_ciphertext_entry(1),
            sample_ciphertext_entry(2),
        ];

        cap_ciphertext_page_to_snapshot(&mut entries, 2);

        assert_eq!(entries.len(), 2);
        require_ciphertext_page_contiguous(0, 2, &entries).expect("snapshot prefix is complete");
        assert!(ciphertext_page_is_contiguous(0, 2, &entries).expect("classification succeeds"));
    }

    fn sample_note_status(
        leaf_count: u64,
        depth: u64,
        next_index: u64,
    ) -> crate::node_rpc::NoteStatus {
        crate::node_rpc::NoteStatus {
            leaf_count,
            depth,
            root: format!("0x{}", hex::encode([0u8; 48])),
            next_index,
        }
    }

    #[derive(Debug, Deserialize)]
    struct LeanCiphertextArchiveBoundaryVectorFile {
        schema_version: u32,
        wallet_sync_snapshot_admission_cases: Vec<LeanWalletSyncSnapshotAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    struct LeanWalletSyncSnapshotAdmissionCase {
        name: String,
        expected_depth: u64,
        depth: u64,
        leaf_count: u64,
        next_index: u64,
        commitment_cursor: u64,
        ciphertext_cursor: u64,
        max_snapshot_gap: u64,
        expected_valid: bool,
        expected_error: Option<String>,
    }

    fn note_status_snapshot_error_label(err: WalletError) -> &'static str {
        match err {
            WalletError::InvalidState("wallet note status depth mismatch") => "depth_mismatch",
            WalletError::InvalidState("wallet note status leaf count exceeds tree capacity") => {
                "leaf_count_exceeds_tree_capacity"
            }
            WalletError::InvalidState(
                "wallet note status ciphertext index exceeds tree capacity",
            ) => "ciphertext_index_exceeds_tree_capacity",
            WalletError::InvalidState("wallet note status commitment snapshot too large") => {
                "commitment_snapshot_too_large"
            }
            WalletError::InvalidState("wallet note status ciphertext snapshot too large") => {
                "ciphertext_snapshot_too_large"
            }
            other => panic!("unexpected wallet sync snapshot error {other:?}"),
        }
    }

    #[test]
    fn lean_generated_wallet_sync_snapshot_vectors_match_production_helper() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_CIPHERTEXT_ARCHIVE_BOUNDARY_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_CIPHERTEXT_ARCHIVE_BOUNDARY_VECTORS not set; skipping wallet sync snapshot vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean ciphertext archive boundary vectors");
        let vectors: LeanCiphertextArchiveBoundaryVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean wallet sync snapshot vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.wallet_sync_snapshot_admission_cases.is_empty(),
            "Lean wallet sync snapshot admission cases must not be empty"
        );

        for case in &vectors.wallet_sync_snapshot_admission_cases {
            assert_eq!(
                case.expected_depth, WALLET_SYNC_EXPECTED_TREE_DEPTH,
                "{} Lean expected depth drifted from production helper",
                case.name
            );
            let actual = validate_note_status_snapshot(
                &sample_note_status(case.leaf_count, case.depth, case.next_index),
                case.commitment_cursor,
                case.ciphertext_cursor,
                case.max_snapshot_gap,
            );
            let actual_error = actual.err().map(note_status_snapshot_error_label);
            assert_eq!(
                actual_error.is_none(),
                case.expected_valid,
                "{} wallet sync snapshot validity drifted from production helper",
                case.name
            );
            assert_eq!(
                actual_error,
                case.expected_error.as_deref(),
                "{} wallet sync snapshot rejection drifted from production helper",
                case.name
            );
        }
    }

    #[test]
    fn note_status_snapshot_admission_rejects_unbounded_remote_counts() {
        validate_note_status_snapshot(
            &sample_note_status(10, WALLET_SYNC_EXPECTED_TREE_DEPTH, 10),
            0,
            0,
            WALLET_SYNC_MAX_SNAPSHOT_GAP,
        )
        .expect("bounded status accepted");

        let err = validate_note_status_snapshot(
            &sample_note_status(10, WALLET_SYNC_EXPECTED_TREE_DEPTH + 1, 10),
            0,
            0,
            WALLET_SYNC_MAX_SNAPSHOT_GAP,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            WalletError::InvalidState("wallet note status depth mismatch")
        ));

        let over_capacity = 1u64 << WALLET_SYNC_EXPECTED_TREE_DEPTH;
        let err = validate_note_status_snapshot(
            &sample_note_status(
                over_capacity,
                WALLET_SYNC_EXPECTED_TREE_DEPTH,
                over_capacity.saturating_add(1),
            ),
            0,
            0,
            WALLET_SYNC_MAX_SNAPSHOT_GAP,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            WalletError::InvalidState("wallet note status ciphertext index exceeds tree capacity")
        ));

        let err = validate_note_status_snapshot(
            &sample_note_status(
                WALLET_SYNC_MAX_SNAPSHOT_GAP + 2,
                WALLET_SYNC_EXPECTED_TREE_DEPTH,
                10,
            ),
            0,
            0,
            WALLET_SYNC_MAX_SNAPSHOT_GAP,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            WalletError::InvalidState("wallet note status commitment snapshot too large")
        ));

        let err = validate_note_status_snapshot(
            &sample_note_status(
                10,
                WALLET_SYNC_EXPECTED_TREE_DEPTH,
                WALLET_SYNC_MAX_SNAPSHOT_GAP + 2,
            ),
            0,
            0,
            WALLET_SYNC_MAX_SNAPSHOT_GAP,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            WalletError::InvalidState("wallet note status ciphertext snapshot too large")
        ));
    }
}
