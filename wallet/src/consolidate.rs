// wallet/src/consolidate.rs
//
// Consolidation for wallets with too many small notes.
// Simple iterative approach: merge two notes, wait, repeat.

use crate::async_sync::AsyncWalletSyncEngine;
use crate::error::WalletError;
use crate::store::{TransferRecipient, WalletStore};
use crate::substrate_rpc::SubstrateRpcClient;
use crate::tx_builder::build_consolidation_transaction;
use std::sync::Arc;

/// Native asset ID (HGM)
const NATIVE_ASSET_ID: u64 = 0;

/// Maximum number of inputs per transaction (circuit limit)
pub const MAX_INPUTS: usize = 2;

const CONFIRMATION_POLL_SECS: u64 = 3;
const CONFIRMATION_TIMEOUT_SECS: u64 = 600;

const DEFAULT_BUNDLE_BYTES_ESTIMATE: usize = 220_000;
const CONSOLIDATION_MAX_TXS_PER_BATCH: usize = 16;
const CONSOLIDATION_MAX_BATCH_BYTES: usize = 1_500_000;

fn estimate_bundle_bytes(bundle: &crate::rpc::TransactionBundle) -> usize {
    let ciphertext_bytes: usize = bundle.ciphertexts.iter().map(|ct| ct.len()).sum();
    bundle.proof_bytes.len()
        + bundle.nullifiers.len() * 48
        + bundle.commitments.len() * 48
        + ciphertext_bytes
        + 48
        + 64
        + 8
        + 16
}

fn select_notes_for_target(
    notes: &[crate::store::SpendableNote],
    target_value: u64,
    fee_per_tx: u64,
) -> Result<(Vec<crate::store::SpendableNote>, u64, u64), WalletError> {
    let available: u64 = notes.iter().map(|note| note.value()).sum();
    if available < target_value {
        return Err(WalletError::InsufficientFunds {
            needed: target_value,
            available,
        });
    }

    let mut required = target_value;
    let mut last_selected_count: Option<usize> = None;
    for _ in 0..32 {
        let mut selected = Vec::new();
        let mut selected_value = 0u64;
        for note in notes {
            if selected_value >= required {
                break;
            }
            selected.push(note.clone());
            selected_value = selected_value.saturating_add(note.value());
        }

        if selected_value < required {
            return Err(WalletError::InsufficientFunds {
                needed: required,
                available: selected_value,
            });
        }

        let selected_count = selected.len();
        if last_selected_count == Some(selected_count) {
            return Ok((selected, selected_value, required));
        }
        last_selected_count = Some(selected_count);

        let txs_needed = selected_count.saturating_sub(MAX_INPUTS) as u64;
        let fee_budget = txs_needed.saturating_mul(fee_per_tx);
        let next_required = target_value
            .checked_add(fee_budget)
            .ok_or(WalletError::InvalidArgument("fee overflow"))?;
        if next_required <= required {
            return Ok((selected, selected_value, required));
        }
        required = next_required;
    }

    Err(WalletError::InvalidState(
        "failed to converge consolidation selection",
    ))
}

/// A consolidation plan - for display/estimation only
#[derive(Debug, Clone)]
pub struct ConsolidationPlan {
    pub note_count: usize,
    pub txs_needed: usize,
    pub blocks_needed: usize,
}

impl ConsolidationPlan {
    /// Estimate consolidation requirements
    /// Each tx merges 2 notes into 1, reducing count by 1.
    /// To go from N notes to MAX_INPUTS notes: N - MAX_INPUTS transactions.
    pub fn estimate(note_count: usize) -> Self {
        if note_count <= MAX_INPUTS {
            return Self {
                note_count,
                txs_needed: 0,
                blocks_needed: 0,
            };
        }

        let txs_needed = note_count - MAX_INPUTS;
        // We cannot spend newly-created notes in the same block because the transaction
        // membership proof anchors to a prior commitment tree root. That means consolidation
        // happens in "rounds": submit a batch of disjoint 2->1 merges, wait for confirmation,
        // then repeat.
        //
        // Our wallet implementation caps each round by both transaction count and an on-chain
        // block-size budget, so estimate blocks as ceil(txs_needed / txs_per_round).
        let txs_per_round = std::cmp::max(
            1,
            std::cmp::min(
                CONSOLIDATION_MAX_TXS_PER_BATCH,
                CONSOLIDATION_MAX_BATCH_BYTES / DEFAULT_BUNDLE_BYTES_ESTIMATE,
            ),
        );
        let blocks_needed = txs_needed.div_ceil(txs_per_round);

        Self {
            note_count,
            txs_needed,
            blocks_needed,
        }
    }

    /// Returns true if no consolidation is needed
    pub fn is_empty(&self) -> bool {
        self.txs_needed == 0
    }
}

/// Execute targeted consolidation - only merge enough notes to cover target_value
///
/// Algorithm:
/// 1. Sync wallet to get fresh note list
/// 2. Select notes needed to cover target_value
/// 3. If selected_count <= MAX_INPUTS, done
/// 4. Merge first two selected notes
/// 5. Go to step 1
pub async fn execute_consolidation(
    store: Arc<WalletStore>,
    rpc: &Arc<SubstrateRpcClient>,
    target_value: u64,
    fee_per_tx: u64,
    verbose: bool,
) -> Result<(), WalletError> {
    let engine = AsyncWalletSyncEngine::new(rpc.clone(), store.clone());
    let mut iteration: u64 = 0;
    let mut bundle_bytes_estimate = DEFAULT_BUNDLE_BYTES_ESTIMATE;

    loop {
        // Step 1: Fresh sync each iteration
        engine.sync_once().await?;

        // Step 2: Select only notes needed for target_value
        // Sort by value descending - prefer larger notes (including consolidated ones)
        let mut notes = store.spendable_notes(NATIVE_ASSET_ID)?;
        notes.sort_by(|a, b| b.value().cmp(&a.value()));

        let (selected, _selected_value, required_value) =
            select_notes_for_target(&notes, target_value, fee_per_tx)?;

        // Check if done - only need to consolidate selected notes
        if selected.len() <= MAX_INPUTS {
            if verbose && iteration > 0 {
                println!(
                    "Consolidation complete. {} notes cover {} HGM.",
                    selected.len(),
                    target_value as f64 / 100_000_000.0
                );
            }
            return Ok(());
        }

        iteration = iteration.saturating_add(1);
        if verbose && iteration == 1 {
            let txs_needed = selected.len().saturating_sub(MAX_INPUTS);
            println!(
                "Consolidating {} notes to cover {} HGM...",
                selected.len(),
                target_value as f64 / 100_000_000.0
            );
            if required_value > target_value {
                println!(
                    "  (includes ~{} HGM reserved for consolidation fees)",
                    (required_value.saturating_sub(target_value)) as f64 / 100_000_000.0
                );
            }
            println!("  ~{} consolidation transactions needed", txs_needed);
        }

        let pairs_available = selected.len() / 2;
        let mut max_txs = pairs_available.min(CONSOLIDATION_MAX_TXS_PER_BATCH);
        if max_txs == 0 {
            return Err(WalletError::InvalidState(
                "insufficient notes available for consolidation pairing",
            ));
        }

        let max_by_bytes = std::cmp::max(1, CONSOLIDATION_MAX_BATCH_BYTES / bundle_bytes_estimate);
        max_txs = max_txs.min(max_by_bytes);

        if verbose && max_txs > 1 {
            println!(
                "  Submitting up to {} consolidation txs this round (block budget ~{} KiB)",
                max_txs,
                CONSOLIDATION_MAX_BATCH_BYTES / 1024
            );
        }

        let mut batch_nullifiers: Vec<[u8; 48]> = Vec::new();
        let mut batch_bytes = 0usize;

        let mut pair_index = 0usize;
        while pair_index < max_txs {
            if pair_index > 0 && batch_bytes.saturating_add(bundle_bytes_estimate) > CONSOLIDATION_MAX_BATCH_BYTES {
                if verbose {
                    println!("  Stopping batch early to stay under block size budget.");
                }
                break;
            }

            let note_0 = &selected[pair_index * 2];
            let note_1 = &selected[pair_index * 2 + 1];
            let total = note_0.value().saturating_add(note_1.value());
            if total <= fee_per_tx {
                return Err(WalletError::InsufficientFunds {
                    needed: fee_per_tx,
                    available: total,
                });
            }

            if verbose {
                println!(
                    "  [{}/~{}] Merging {} HGM + {} HGM -> {} HGM",
                    pair_index + 1,
                    max_txs,
                    note_0.value() as f64 / 100_000_000.0,
                    note_1.value() as f64 / 100_000_000.0,
                    (total - fee_per_tx) as f64 / 100_000_000.0
                );
            }

            let built = build_consolidation_transaction(&*store, note_0, note_1, fee_per_tx)?;
            let tx_bytes = estimate_bundle_bytes(&built.bundle).max(64 * 1024);

            if pair_index == 0 {
                bundle_bytes_estimate = tx_bytes;
                let adjusted_by_bytes =
                    std::cmp::max(1, CONSOLIDATION_MAX_BATCH_BYTES / bundle_bytes_estimate);
                max_txs = max_txs.min(adjusted_by_bytes);
            }

            if pair_index > 0 && batch_bytes.saturating_add(tx_bytes) > CONSOLIDATION_MAX_BATCH_BYTES {
                if verbose {
                    println!("  Stopping batch early to stay under block size budget.");
                }
                break;
            }

            batch_bytes = batch_bytes.saturating_add(tx_bytes);
            bundle_bytes_estimate = tx_bytes;

            store.mark_notes_pending(&built.spent_note_indexes, true)?;

            let outgoing_disclosures = built.outgoing_disclosures.clone();
            let submit_result = rpc.submit_shielded_transfer_unsigned(&built.bundle).await;

            let hash = match submit_result {
                Ok(hash) => Some(hash),
                Err(WalletError::Rpc(msg))
                    if msg.contains("Priority is too low") || msg.contains("already in the pool") =>
                {
                    if verbose {
                        println!("    Note: tx appears already in pool; waiting for confirmation...");
                    }
                    None
                }
                Err(err) => {
                    store.mark_notes_pending(&built.spent_note_indexes, false)?;
                    if !batch_nullifiers.is_empty() {
                        let _ = wait_for_nullifiers_spent(&engine, rpc, &store, &batch_nullifiers).await;
                    }
                    return Err(err);
                }
            };

            if let Some(hash) = hash {
                if verbose {
                    println!("    Submitted: 0x{}", hex::encode(&hash[..8]));
                }

                if let Some(genesis_hash) = store.genesis_hash()? {
                    store.record_outgoing_disclosures(hash, genesis_hash, outgoing_disclosures)?;
                }

                let recipient_address = store.primary_address()?.encode()?;
                store.record_pending_submission(
                    hash,
                    built.nullifiers.clone(),
                    built.spent_note_indexes.clone(),
                    vec![TransferRecipient {
                        address: recipient_address,
                        value: total.saturating_sub(fee_per_tx),
                        asset_id: NATIVE_ASSET_ID,
                        memo: Some("consolidation".to_string()),
                    }],
                    fee_per_tx,
                )?;
            }

            batch_nullifiers.extend_from_slice(&built.nullifiers);
            pair_index = pair_index.saturating_add(1);
        }

        let confirmed_height = wait_for_nullifiers_spent(&engine, rpc, &store, &batch_nullifiers).await?;
        if verbose {
            println!("  Confirmed round (observed at block {})", confirmed_height);
        }
    }
}

async fn wait_for_nullifiers_spent(
    engine: &AsyncWalletSyncEngine,
    rpc: &Arc<SubstrateRpcClient>,
    store: &Arc<WalletStore>,
    nullifiers: &[[u8; 48]],
) -> Result<u64, WalletError> {
    let start = std::time::Instant::now();
    let timeout = tokio::time::Duration::from_secs(CONFIRMATION_TIMEOUT_SECS);

    loop {
        if start.elapsed() > timeout {
            return Err(WalletError::Rpc(format!(
                "consolidation tx not confirmed within {}s",
                CONFIRMATION_TIMEOUT_SECS
            )));
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(CONFIRMATION_POLL_SECS)).await;
        engine.sync_once().await?;

        let spent = rpc.check_nullifiers_spent(nullifiers).await?;
        if spent.iter().all(|v| *v) {
            return store.last_synced_height();
        }
    }
}

/// Dry-run consolidation - just show what would happen
pub fn consolidation_dry_run(store: &WalletStore) -> Result<ConsolidationPlan, WalletError> {
    let notes = store.spendable_notes(NATIVE_ASSET_ID)?;
    Ok(ConsolidationPlan::estimate(notes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_no_consolidation_needed() {
        let plan = ConsolidationPlan::estimate(2);
        assert!(plan.is_empty());
        assert_eq!(plan.txs_needed, 0);
    }

    #[test]
    fn test_estimate_three_notes() {
        // 3 notes -> 2 notes: 1 tx
        let plan = ConsolidationPlan::estimate(3);
        assert_eq!(plan.txs_needed, 1);
    }

    #[test]
    fn test_estimate_ten_notes() {
        // 10 notes -> 2 notes: 8 txs
        let plan = ConsolidationPlan::estimate(10);
        assert_eq!(plan.txs_needed, 8);
    }

    #[test]
    fn test_estimate_65_notes() {
        // 65 notes -> 2 notes: 63 txs
        let plan = ConsolidationPlan::estimate(65);
        assert_eq!(plan.txs_needed, 63);
    }
}
