use std::collections::HashSet;

use crate::error::WalletError;
use crate::rpc::WalletRpcClient;
use crate::store::WalletStore;

pub struct WalletSyncEngine<'a> {
    rpc: &'a WalletRpcClient,
    store: &'a WalletStore,
    page_limit: usize,
}

impl<'a> WalletSyncEngine<'a> {
    pub fn new(rpc: &'a WalletRpcClient, store: &'a WalletStore) -> Self {
        Self {
            rpc,
            store,
            page_limit: 256,
        }
    }

    pub fn sync_once(&self) -> Result<SyncOutcome, WalletError> {
        let mut outcome = SyncOutcome::default();
        let note_status = self.rpc.note_status()?;
        self.store.set_tree_depth(note_status.depth as u32)?;

        let ivk = self.store.incoming_key()?;

        let mut commitment_cursor = self.store.next_commitment_index()?;
        while commitment_cursor < note_status.leaf_count {
            let entries = self.rpc.commitments(commitment_cursor, self.page_limit)?;
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

        let mut ciphertext_cursor = self.store.next_ciphertext_index()?;
        while ciphertext_cursor < note_status.next_index {
            let entries = self.rpc.ciphertexts(ciphertext_cursor, self.page_limit)?;
            if entries.is_empty() {
                break;
            }

            let start_index = ciphertext_cursor;
            let mut expected = start_index;
            let mut recovered = Vec::with_capacity(entries.len());
            for entry in entries {
                if entry.index != expected {
                    return Err(WalletError::InvalidState("ciphertext index mismatch"));
                }
                outcome.ciphertexts += 1;
                recovered.push(match ivk.decrypt_note(&entry.ciphertext) {
                    Ok(note) => Some(note),
                    Err(WalletError::NoteMismatch(_)) => None,
                    Err(err) => return Err(err),
                });
                expected = expected
                    .checked_add(1)
                    .ok_or(WalletError::InvalidState("ciphertext index overflow"))?;
            }

            outcome.recovered += self.store.apply_ciphertext_batch(start_index, recovered)?;
            ciphertext_cursor = self.store.next_ciphertext_index()?;
        }

        let nullifiers = self.rpc.nullifiers()?;
        let nullifier_set: HashSet<[u8; 48]> = nullifiers.into_iter().collect();
        outcome.spent += self.store.mark_nullifiers(&nullifier_set)?;
        let latest = self.rpc.latest_block()?;
        self.store.refresh_pending(latest.height, &nullifier_set)?;
        self.store.set_last_synced_height(latest.height)?;
        Ok(outcome)
    }
}

#[derive(Default, Debug)]
pub struct SyncOutcome {
    pub commitments: usize,
    pub ciphertexts: usize,
    pub recovered: usize,
    pub spent: usize,
}
