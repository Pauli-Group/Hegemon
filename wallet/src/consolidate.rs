// wallet/src/consolidate.rs
//
// Consolidation for wallets with too many small notes.
// Simple iterative approach: merge two notes, wait, repeat.

use crate::async_sync::AsyncWalletSyncEngine;
use crate::error::WalletError;
use crate::notes::MemoPlaintext;
use crate::store::WalletStore;
use crate::substrate_rpc::SubstrateRpcClient;
use crate::tx_builder::{build_transaction, Recipient};
use std::sync::Arc;

/// Native asset ID (HGM)
const NATIVE_ASSET_ID: u64 = 0;

/// Maximum number of inputs per transaction (circuit limit)
pub const MAX_INPUTS: usize = 2;

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
        // Each tx needs ~1 block to confirm before next can use its output
        // But we can submit multiple txs spending different notes in same block
        // Worst case: txs_needed blocks. Best case with parallelism: log2(N) blocks
        // For simplicity, estimate 1 tx per block (sequential submission)
        let blocks_needed = txs_needed;

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
    let mut iteration = 0;

    loop {
        // Step 1: Fresh sync each iteration
        let engine = AsyncWalletSyncEngine::new(rpc.clone(), store.clone());
        engine.sync_once().await?;

        // Step 2: Select only notes needed for target_value
        // Sort by value descending - prefer larger notes (including consolidated ones)
        let mut notes = store.spendable_notes(NATIVE_ASSET_ID)?;
        notes.sort_by(|a, b| b.recovered.note.value.cmp(&a.recovered.note.value));

        let mut selected = Vec::new();
        let mut selected_value = 0u64;
        for note in &notes {
            selected.push(note.clone());
            selected_value += note.recovered.note.value;
            if selected_value >= target_value {
                break;
            }
        }

        if selected_value < target_value {
            return Err(WalletError::InsufficientFunds {
                needed: target_value,
                available: selected_value,
            });
        }

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

        iteration += 1;
        if verbose && iteration == 1 {
            let txs_needed = selected.len() - MAX_INPUTS;
            println!(
                "Consolidating {} notes to cover {} HGM -> ~{} transactions needed",
                selected.len(),
                target_value as f64 / 100_000_000.0,
                txs_needed
            );
        }

        // Step 3: Merge first two selected notes
        let note_0 = &selected[0];
        let note_1 = &selected[1];

        let total = note_0.recovered.note.value + note_1.recovered.note.value;
        if total <= fee_per_tx {
            return Err(WalletError::InsufficientFunds {
                needed: fee_per_tx,
                available: total,
            });
        }

        let self_address = store.primary_address()?;
        let recipient = Recipient {
            address: self_address,
            value: total - fee_per_tx,
            asset_id: NATIVE_ASSET_ID,
            memo: MemoPlaintext::default(),
        };

        if verbose {
            println!(
                "[{}/~{}] Merging {} HGM + {} HGM -> {} HGM",
                iteration,
                selected.len() - MAX_INPUTS,
                note_0.recovered.note.value as f64 / 100_000_000.0,
                note_1.recovered.note.value as f64 / 100_000_000.0,
                (total - fee_per_tx) as f64 / 100_000_000.0
            );
        }

        // Build and submit
        let tx = build_transaction(&*store, &[recipient], fee_per_tx)?;
        let hash = rpc.submit_shielded_transfer_unsigned(&tx.bundle).await?;

        if verbose {
            println!("  Submitted: 0x{}", hex::encode(&hash[..8]));
        }

        // Step 4: Wait for confirmation
        let start_height = rpc.latest_block().await?.height;
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            let current = rpc.latest_block().await?;
            if current.height > start_height {
                if verbose {
                    println!("  Confirmed at block {}", current.height);
                }
                break;
            }
        }

        // Small delay after confirmation to avoid mempool priority collisions
        // (coinbase tx may still be in pool right after block)
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Step 5: Loop back to sync and check again
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
