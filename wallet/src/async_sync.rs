//! Async Wallet Sync Engine for Substrate RPC
//!
//! This module provides an async synchronization engine that syncs wallet state
//! using the Substrate WebSocket RPC client. It replaces the blocking sync engine
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
//! use wallet::{SubstrateRpcClient, WalletStore};
//! use wallet::async_sync::AsyncWalletSyncEngine;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = Arc::new(SubstrateRpcClient::connect("ws://127.0.0.1:9944").await?);
//! let store = Arc::new(WalletStore::open("wallet.dat", "password")?);
//! let engine = AsyncWalletSyncEngine::new(client, store);
//! let outcome = engine.sync_once().await?;
//! println!("Synced {} notes", outcome.recovered);
//! # Ok(())
//! # }
//! ```

use std::collections::HashSet;
use std::sync::Arc;

// StreamExt is required for Subscription::next()
#[allow(unused_imports)]
use futures::StreamExt;
use tokio::sync::RwLock;

use crate::error::WalletError;
use crate::store::WalletStore;
use crate::substrate_rpc::SubstrateRpcClient;
use crate::sync::SyncOutcome;

/// Async wallet synchronization engine
///
/// This engine syncs wallet state with a Substrate node using WebSocket RPC.
/// It supports both one-shot synchronization and continuous sync via subscriptions.
pub struct AsyncWalletSyncEngine {
    /// RPC client for node communication
    client: Arc<SubstrateRpcClient>,
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
    /// * `client` - Substrate RPC client
    /// * `store` - Wallet store
    pub fn new(client: Arc<SubstrateRpcClient>, store: Arc<WalletStore>) -> Self {
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
        let mut outcome = SyncOutcome::default();

        // Validate genesis hash to detect chain resets
        let metadata = self.client.get_chain_metadata().await?;
        if !self.skip_genesis_check {
            // Try to set genesis hash (will fail if mismatched)
            self.store.set_genesis_hash(metadata.genesis_hash)?;
        } else {
            // Force rescan mode: reset if genesis changed
            if !self.store.check_genesis_hash(&metadata.genesis_hash)? {
                eprintln!("Chain genesis mismatch detected, resetting wallet sync state...");
                self.store.reset_sync_state()?;
                self.store.set_genesis_hash(metadata.genesis_hash)?;
            }
        }

        // Get current note status from node
        let note_status = self.client.note_status().await?;
        self.store.set_tree_depth(note_status.depth as u32)?;

        // Detect if our cursor is ahead of the chain (chain was reset)
        let commitment_cursor = self.store.next_commitment_index()?;
        if commitment_cursor > note_status.leaf_count {
            return Err(WalletError::ChainMismatch {
                expected: format!("chain with >= {} commitments", commitment_cursor),
                actual: format!("chain with {} commitments", note_status.leaf_count),
            });
        }

        // Sync commitments
        let mut commitment_cursor = commitment_cursor;
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

        // Sync ciphertexts and attempt decryption
        let mut ciphertext_cursor = self.store.next_ciphertext_index()?;
        while ciphertext_cursor < note_status.next_index {
            let entries = self
                .client
                .ciphertexts(ciphertext_cursor, self.page_limit)
                .await?;
            if entries.is_empty() {
                break;
            }

            let start_index = ciphertext_cursor;
            let mut expected = start_index;
            let mut recovered = Vec::with_capacity(entries.len());
            let ivk = self.store.incoming_key()?;

            for entry in entries {
                if entry.index != expected {
                    return Err(WalletError::InvalidState("ciphertext index mismatch"));
                }
                outcome.ciphertexts += 1;

                // Debug: log ciphertext details vs expected
                if std::env::var("WALLET_DEBUG_DECRYPT").is_ok() {
                    let material = ivk.address_material(entry.ciphertext.diversifier_index)?;
                    eprintln!(
                        "[DEBUG] Ciphertext #{}: version={} div_idx={}",
                        entry.index, entry.ciphertext.version, entry.ciphertext.diversifier_index
                    );
                    eprintln!("  hint_tag: {}", hex::encode(&entry.ciphertext.hint_tag));
                    eprintln!("  expected addr_tag: {}", hex::encode(&material.addr_tag));
                    eprintln!("  expected version: {}", material.version());
                    eprintln!(
                        "  version match: {}",
                        entry.ciphertext.version == material.version()
                    );
                    eprintln!(
                        "  div_idx match: {}",
                        entry.ciphertext.diversifier_index == material.diversifier_index
                    );
                    eprintln!(
                        "  tag match: {}",
                        entry.ciphertext.hint_tag == material.addr_tag
                    );
                }

                recovered.push(match ivk.decrypt_note(&entry.ciphertext) {
                    Ok(note) => Some(note),
                    Err(WalletError::NoteMismatch(reason)) => {
                        // Note not for this wallet, skip
                        if std::env::var("WALLET_DEBUG_DECRYPT").is_ok() {
                            eprintln!("  -> NoteMismatch: {}", reason);
                        }
                        None
                    }
                    Err(err) => return Err(err),
                });

                expected = expected
                    .checked_add(1)
                    .ok_or(WalletError::InvalidState("ciphertext index overflow"))?;
            }

            outcome.recovered += self.store.apply_ciphertext_batch(start_index, recovered)?;
            ciphertext_cursor = self.store.next_ciphertext_index()?;
        }

        // Sync nullifiers
        let nullifiers = self.client.nullifiers().await?;
        let nullifier_set: HashSet<[u8; 48]> = nullifiers.into_iter().collect();
        outcome.spent += self.store.mark_nullifiers(&nullifier_set)?;

        // Update pending transactions
        let latest = self.client.latest_block().await?;
        self.store.refresh_pending(latest.height, &nullifier_set)?;
        self.store.set_last_synced_height(latest.height)?;

        Ok(outcome)
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

/// Sync engine with shared state for concurrent access
///
/// Wraps AsyncWalletSyncEngine with RwLock protection for use
/// in multi-threaded contexts (e.g., with a web server).
pub struct SharedSyncEngine {
    inner: RwLock<AsyncWalletSyncEngine>,
}

impl SharedSyncEngine {
    /// Create a new shared sync engine
    pub fn new(client: Arc<SubstrateRpcClient>, store: Arc<WalletStore>) -> Self {
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

    #[test]
    fn test_sync_outcome_default() {
        let outcome = SyncOutcome::default();
        assert_eq!(outcome.commitments, 0);
        assert_eq!(outcome.ciphertexts, 0);
        assert_eq!(outcome.recovered, 0);
        assert_eq!(outcome.spent, 0);
    }
}
