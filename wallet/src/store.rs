use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use state_merkle::CommitmentTree;
use transaction_circuit::{hashing_pq::Commitment, note::NoteData};
use zeroize::Zeroize;

use crate::address::ShieldedAddress;
use crate::error::WalletError;
use crate::keys::{DerivedKeys, RootSecret};
use crate::notes::MemoPlaintext;
use crate::viewing::{FullViewingKey, IncomingViewingKey, OutgoingViewingKey, RecoveredNote};

const FILE_VERSION: u32 = 6;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
/// Default tree depth - must match CIRCUIT_MERKLE_DEPTH in transaction-circuit.
const DEFAULT_TREE_DEPTH: u32 = 32;

/// Wallet store - manages encrypted wallet state on disk.
/// The encryption key is zeroized on drop to prevent key material from persisting in memory.
#[derive(Debug)]
pub struct WalletStore {
    path: PathBuf,
    key: [u8; KEY_LEN],
    salt: [u8; SALT_LEN],
    state: Mutex<WalletState>,
}

/// Zeroize the encryption key when the WalletStore is dropped
impl Drop for WalletStore {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl WalletStore {
    pub fn create_full<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Self, WalletError> {
        let mut rng = OsRng;
        let root = RootSecret::from_rng(&mut rng);
        Self::create_from_root(path, passphrase, root)
    }

    pub fn create_from_root<P: AsRef<Path>>(
        path: P,
        passphrase: &str,
        root: RootSecret,
    ) -> Result<Self, WalletError> {
        let derived = root.derive();
        let ivk = IncomingViewingKey::from_keys(&derived);
        let fvk = FullViewingKey::from_keys(&derived);
        let ovk = OutgoingViewingKey::from_keys(&derived);
        let state = WalletState {
            mode: WalletMode::Full,
            tree_depth: DEFAULT_TREE_DEPTH,
            root_secret: Some(root.to_bytes()),
            derived: Some(derived),
            incoming: ivk,
            full_viewing_key: Some(fvk),
            outgoing: Some(ovk),
            next_address_index: 0,
            notes: Vec::new(),
            pending: Vec::new(),
            commitments: Vec::new(),
            next_commitment_index: 0,
            next_ciphertext_index: 0,
            last_synced_height: 0,
            outgoing_disclosures: Vec::new(),
            genesis_hash: None,
        };
        Self::create_with_state(path, passphrase, state)
    }

    pub fn import_viewing_key<P: AsRef<Path>>(
        path: P,
        passphrase: &str,
        ivk: IncomingViewingKey,
    ) -> Result<Self, WalletError> {
        let state = WalletState {
            mode: WalletMode::WatchOnly,
            tree_depth: DEFAULT_TREE_DEPTH,
            root_secret: None,
            derived: None,
            incoming: ivk.clone(),
            full_viewing_key: None,
            outgoing: None,
            next_address_index: 0,
            notes: Vec::new(),
            pending: Vec::new(),
            commitments: Vec::new(),
            next_commitment_index: 0,
            next_ciphertext_index: 0,
            last_synced_height: 0,
            outgoing_disclosures: Vec::new(),
            genesis_hash: None,
        };
        Self::create_with_state(path, passphrase, state)
    }

    fn create_with_state<P: AsRef<Path>>(
        path: P,
        passphrase: &str,
        state: WalletState,
    ) -> Result<Self, WalletError> {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(passphrase, &salt)?;
        let store = WalletStore {
            path: path.as_ref().to_path_buf(),
            key,
            salt,
            state: Mutex::new(state),
        };
        store.write_locked()?;
        Ok(store)
    }

    pub fn open<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Self, WalletError> {
        let bytes = fs::read(path.as_ref())?;
        let file: WalletFile = bincode::deserialize(&bytes)?;
        let key = derive_key(passphrase, &file.salt)?;
        let cipher = ChaCha20Poly1305::new(&key.into());
        let plaintext = cipher
            .decrypt(
                &file.nonce.into(),
                Payload {
                    msg: &file.ciphertext,
                    aad: &file.salt,
                },
            )
            .map_err(|_| WalletError::DecryptionFailure)?;
        let state: WalletState = match file.version {
            FILE_VERSION => bincode::deserialize(&plaintext)?,
            other => {
                return Err(WalletError::Serialization(format!(
                    "unsupported wallet file version {other} (expected {FILE_VERSION})"
                )))
            }
        };
        Ok(WalletStore {
            path: path.as_ref().to_path_buf(),
            key,
            salt: file.salt,
            state: Mutex::new(state),
        })
    }

    pub fn mode(&self) -> Result<WalletMode, WalletError> {
        self.with_state(|state| Ok(state.mode))
    }

    pub fn incoming_key(&self) -> Result<IncomingViewingKey, WalletError> {
        self.with_state(|state| Ok(state.incoming.clone()))
    }

    pub fn full_viewing_key(&self) -> Result<Option<FullViewingKey>, WalletError> {
        self.with_state(|state| Ok(state.full_viewing_key.clone()))
    }

    pub fn derived_keys(&self) -> Result<Option<DerivedKeys>, WalletError> {
        self.with_state(|state| Ok(state.derived.clone()))
    }

    pub fn outgoing_key(&self) -> Result<Option<OutgoingViewingKey>, WalletError> {
        self.with_state(|state| Ok(state.outgoing.clone()))
    }

    /// Returns the primary shielded address (diversifier index 0).
    /// This address is stable and never changes - ideal for mining rewards.
    pub fn primary_address(&self) -> Result<ShieldedAddress, WalletError> {
        self.with_state(|state| {
            let keys = state.derived.as_ref().ok_or(WalletError::WatchOnly)?;
            let material = keys.address(0)?;
            Ok(material.shielded_address())
        })
    }

    pub fn next_address(&self) -> Result<ShieldedAddress, WalletError> {
        self.with_mut(|state| {
            let keys = state.derived.as_ref().ok_or(WalletError::WatchOnly)?;
            let material = keys.address(state.next_address_index)?;
            state.next_address_index = state
                .next_address_index
                .checked_add(1)
                .ok_or(WalletError::InvalidState("address index overflow"))?;
            Ok(material.shielded_address())
        })
    }

    pub fn reserve_internal_address(&self) -> Result<ShieldedAddress, WalletError> {
        self.next_address()
    }

    pub fn next_commitment_index(&self) -> Result<u64, WalletError> {
        self.with_state(|state| Ok(state.next_commitment_index))
    }

    pub fn next_ciphertext_index(&self) -> Result<u64, WalletError> {
        self.with_state(|state| Ok(state.next_ciphertext_index))
    }

    pub fn set_tree_depth(&self, depth: u32) -> Result<(), WalletError> {
        self.with_mut(|state| {
            if state.tree_depth != depth {
                state.tree_depth = depth;
            }
            Ok(())
        })
    }

    pub fn set_last_synced_height(&self, height: u64) -> Result<(), WalletError> {
        self.with_mut(|state| {
            state.last_synced_height = height;
            Ok(())
        })
    }

    pub fn last_synced_height(&self) -> Result<u64, WalletError> {
        self.with_state(|state| Ok(state.last_synced_height))
    }

    /// Get the genesis hash this wallet was synced with, if any.
    pub fn genesis_hash(&self) -> Result<Option<[u8; 32]>, WalletError> {
        self.with_state(|state| Ok(state.genesis_hash))
    }

    /// Set the genesis hash. Only succeeds if not already set, or if matches.
    /// Returns Err(ChainMismatch) if already set to a different value.
    pub fn set_genesis_hash(&self, hash: [u8; 32]) -> Result<(), WalletError> {
        self.with_mut(|state| match state.genesis_hash {
            None => {
                state.genesis_hash = Some(hash);
                Ok(())
            }
            Some(existing) if existing == hash => Ok(()),
            Some(existing) => Err(WalletError::ChainMismatch {
                expected: hex::encode(existing),
                actual: hex::encode(hash),
            }),
        })
    }

    /// Check if genesis hash matches. Returns true if no genesis hash stored yet.
    pub fn check_genesis_hash(&self, hash: &[u8; 32]) -> Result<bool, WalletError> {
        self.with_state(|state| Ok(state.genesis_hash.map(|h| h == *hash).unwrap_or(true)))
    }

    /// Reset all sync state (notes, commitments, pending, cursors).
    /// Preserves keys and addresses. Use when chain has been reset.
    pub fn reset_sync_state(&self) -> Result<(), WalletError> {
        self.with_mut(|state| {
            state.notes.clear();
            state.pending.clear();
            state.commitments.clear();
            state.next_commitment_index = 0;
            state.next_ciphertext_index = 0;
            state.last_synced_height = 0;
            state.genesis_hash = None;
            Ok(())
        })
    }

    /// Advance the ciphertext cursor to a later index (used to skip pruned gaps).
    pub fn advance_ciphertext_cursor(&self, new_index: u64) -> Result<(), WalletError> {
        self.with_mut(|state| {
            if new_index < state.next_ciphertext_index {
                return Err(WalletError::InvalidState("ciphertext index rewind"));
            }
            state.next_ciphertext_index = new_index;
            Ok(())
        })
    }

    /// Repair note positions by re-mapping commitments to indices.
    /// Returns the number of notes whose position was updated.
    pub fn repair_note_positions(&self) -> Result<usize, WalletError> {
        self.with_mut(|state| {
            let mut updated = 0usize;
            for note in &mut state.notes {
                let expected = transaction_circuit::hashing_pq::felts_to_bytes48(
                    &note.note.note_data.commitment(),
                );
                let position = state
                    .commitments
                    .iter()
                    .position(|value| *value == expected)
                    .ok_or(WalletError::InvalidState(
                        "note commitment not found in local commitment list",
                    ))? as u64;
                if note.position != position {
                    note.position = position;
                    updated = updated.saturating_add(1);
                }
            }
            Ok(updated)
        })
    }

    pub fn append_commitments(&self, entries: &[(u64, Commitment)]) -> Result<(), WalletError> {
        if entries.is_empty() {
            return Ok(());
        }
        self.with_mut(|state| {
            let mut expected = state.next_commitment_index;
            for (index, value) in entries {
                if *index != expected {
                    return Err(WalletError::InvalidState("commitment index mismatch"));
                }
                state.commitments.push(*value);
                expected = expected
                    .checked_add(1)
                    .ok_or(WalletError::InvalidState("commitment index overflow"))?;
            }
            state.next_commitment_index = expected;
            Ok(())
        })
    }

    pub fn register_ciphertext_index(&self, index: u64) -> Result<(), WalletError> {
        self.with_mut(|state| {
            if index != state.next_ciphertext_index {
                return Err(WalletError::InvalidState("ciphertext index mismatch"));
            }
            state.next_ciphertext_index = state
                .next_ciphertext_index
                .checked_add(1)
                .ok_or(WalletError::InvalidState("ciphertext index overflow"))?;
            Ok(())
        })
    }

    /// Apply a contiguous batch of ciphertext sync results in one store write.
    ///
    /// This advances the ciphertext cursor and records any decrypted notes.
    /// `start_index` must match the current cursor, and the batch is assumed to
    /// correspond to ciphertext indices `start_index..start_index+len`.
    ///
    /// Returns the number of newly-added notes (deduped by position).
    pub fn apply_ciphertext_batch(
        &self,
        start_index: u64,
        recovered: Vec<Option<RecoveredNote>>,
    ) -> Result<usize, WalletError> {
        if recovered.is_empty() {
            return Ok(0);
        }

        self.with_mut(|state| {
            if state.next_ciphertext_index != start_index {
                return Err(WalletError::InvalidState("ciphertext index mismatch"));
            }

            let mut added = 0usize;
            for (offset, maybe_note) in recovered.into_iter().enumerate() {
                let index = start_index
                    .checked_add(offset as u64)
                    .ok_or(WalletError::InvalidState("ciphertext index overflow"))?;

                if index != state.next_ciphertext_index {
                    return Err(WalletError::InvalidState("ciphertext index mismatch"));
                }

                if let Some(note) = maybe_note {
                    let expected_commitment = transaction_circuit::hashing_pq::felts_to_bytes48(
                        &note.note_data.commitment(),
                    );
                    let position = state
                        .commitments
                        .iter()
                        .position(|value| *value == expected_commitment)
                        .ok_or(WalletError::InvalidState(
                            "note commitment not found in local commitment list",
                        ))? as u64;
                    if !state.notes.iter().any(|n| n.position == position) {
                        let nullifier = state
                            .full_viewing_key
                            .as_ref()
                            .map(|fvk| fvk.compute_nullifier(&note.note.rho, position));
                        state.notes.push(TrackedNote {
                            note,
                            position,
                            ciphertext_index: index,
                            nullifier,
                            spent: false,
                            pending_spend: false,
                        });
                        added = added
                            .checked_add(1)
                            .ok_or(WalletError::InvalidState("note count overflow"))?;
                    }
                }

                state.next_ciphertext_index = state
                    .next_ciphertext_index
                    .checked_add(1)
                    .ok_or(WalletError::InvalidState("ciphertext index overflow"))?;
            }

            Ok(added)
        })
    }

    pub fn record_recovered_note(
        &self,
        note: RecoveredNote,
        position: u64,
        ciphertext_index: u64,
    ) -> Result<bool, WalletError> {
        let mut added = false;
        self.with_mut(|state| {
            if state.notes.iter().any(|n| n.position == position) {
                return Ok(());
            }
            let nullifier = state
                .full_viewing_key
                .as_ref()
                .map(|fvk| fvk.compute_nullifier(&note.note.rho, position));
            state.notes.push(TrackedNote {
                note,
                position,
                ciphertext_index,
                nullifier,
                spent: false,
                pending_spend: false,
            });
            added = true;
            Ok(())
        })?;
        Ok(added)
    }

    pub fn spendable_notes(&self, asset_id: u64) -> Result<Vec<SpendableNote>, WalletError> {
        self.with_state(|state| {
            let mut notes: Vec<SpendableNote> = state
                .notes
                .iter()
                .enumerate()
                .filter(|(_, note)| {
                    note.note.note.asset_id == asset_id && !note.spent && !note.pending_spend
                })
                .map(|(idx, note)| SpendableNote {
                    index: idx,
                    recovered: note.note.clone(),
                    position: note.position,
                })
                .collect();
            notes.sort_by_key(|note| note.position);
            Ok(notes)
        })
    }

    pub fn pending_spend_notes(&self, asset_id: u64) -> Result<Vec<SpendableNote>, WalletError> {
        self.with_state(|state| {
            let mut notes: Vec<SpendableNote> = state
                .notes
                .iter()
                .enumerate()
                .filter(|(_, note)| {
                    note.note.note.asset_id == asset_id && !note.spent && note.pending_spend
                })
                .map(|(idx, note)| SpendableNote {
                    index: idx,
                    recovered: note.note.clone(),
                    position: note.position,
                })
                .collect();
            notes.sort_by_key(|note| note.position);
            Ok(notes)
        })
    }

    pub fn mark_notes_pending(&self, indexes: &[usize], pending: bool) -> Result<(), WalletError> {
        self.with_mut(|state| {
            for &idx in indexes {
                let Some(note) = state.notes.get_mut(idx) else {
                    return Err(WalletError::InvalidState("note index out of range"));
                };
                note.pending_spend = pending;
            }
            Ok(())
        })
    }

    pub fn mark_nullifiers(&self, nullifiers: &HashSet<[u8; 48]>) -> Result<usize, WalletError> {
        let mut updated = 0;
        self.with_mut(|state| {
            for note in &mut state.notes {
                if note.spent {
                    continue;
                }
                if let Some(nullifier) = &note.nullifier {
                    if nullifiers.contains(nullifier) {
                        note.spent = true;
                        note.pending_spend = false;
                        updated += 1;
                    }
                }
            }
            Ok(())
        })?;
        Ok(updated)
    }

    pub fn balances(&self) -> Result<BTreeMap<u64, u64>, WalletError> {
        self.with_state(|state| {
            let mut map: BTreeMap<u64, u64> = BTreeMap::new();
            for note in &state.notes {
                if note.spent || note.pending_spend {
                    continue;
                }
                let entry = map.entry(note.note.note.asset_id).or_default();
                *entry = entry.saturating_add(note.note.note.value);
            }
            Ok(map)
        })
    }

    pub fn pending_balances(&self) -> Result<BTreeMap<u64, u64>, WalletError> {
        self.with_state(|state| {
            let mut map: BTreeMap<u64, u64> = BTreeMap::new();
            for note in &state.notes {
                if note.spent || !note.pending_spend {
                    continue;
                }
                let entry = map.entry(note.note.note.asset_id).or_default();
                *entry = entry.saturating_add(note.note.note.value);
            }
            Ok(map)
        })
    }

    pub fn commitment_tree(&self) -> Result<CommitmentTree, WalletError> {
        self.with_state(|state| {
            let depth = state.tree_depth as usize;
            let mut tree = CommitmentTree::new(depth)
                .map_err(|_| WalletError::InvalidState("invalid tree depth"))?;
            for value in &state.commitments {
                let _ = tree
                    .append(*value)
                    .map_err(|_| WalletError::InvalidState("tree overflow"))?;
            }
            Ok(tree)
        })
    }

    /// Validate that tracked notes match the local commitment list.
    /// Returns an error if any note's commitment cannot be found at its position.
    pub fn validate_notes_against_commitments(&self) -> Result<(), WalletError> {
        self.with_state(|state| {
            for note in &state.notes {
                let idx = note.position as usize;
                let Some(commitment) = state.commitments.get(idx) else {
                    return Err(WalletError::InvalidState(
                        "note position beyond commitment list",
                    ));
                };
                let expected = transaction_circuit::hashing_pq::felts_to_bytes48(
                    &note.note.note_data.commitment(),
                );
                if *commitment != expected {
                    return Err(WalletError::InvalidState(
                        "note commitment mismatch at recorded position",
                    ));
                }
            }
            Ok(())
        })
    }

    pub fn find_commitment_index(
        &self,
        commitment: Commitment,
    ) -> Result<Option<u64>, WalletError> {
        self.with_state(|state| {
            Ok(state
                .commitments
                .iter()
                .position(|value| *value == commitment)
                .map(|idx| idx as u64))
        })
    }

    pub fn pending_transactions(&self) -> Result<Vec<PendingTransaction>, WalletError> {
        self.with_state(|state| Ok(state.pending.clone()))
    }

    pub fn outgoing_disclosures(&self) -> Result<Vec<OutgoingDisclosureRecord>, WalletError> {
        self.with_state(|state| Ok(state.outgoing_disclosures.clone()))
    }

    pub fn find_outgoing_disclosure(
        &self,
        tx_id: &[u8; 32],
        output_index: u32,
    ) -> Result<Option<OutgoingDisclosureRecord>, WalletError> {
        self.with_state(|state| {
            Ok(state
                .outgoing_disclosures
                .iter()
                .find(|record| record.tx_id == *tx_id && record.output_index == output_index)
                .cloned())
        })
    }

    pub fn record_outgoing_disclosures(
        &self,
        tx_id: [u8; 32],
        genesis_hash: [u8; 32],
        outputs: Vec<OutgoingDisclosureDraft>,
    ) -> Result<(), WalletError> {
        let created_at = current_timestamp();
        self.with_mut(|state| {
            for output in outputs {
                let exists = state.outgoing_disclosures.iter().any(|record| {
                    record.tx_id == tx_id && record.output_index == output.output_index
                });
                if exists {
                    continue;
                }
                state.outgoing_disclosures.push(OutgoingDisclosureRecord {
                    tx_id,
                    output_index: output.output_index,
                    recipient_address: output.recipient_address,
                    note: output.note,
                    commitment: output.commitment,
                    memo: output.memo,
                    genesis_hash,
                    created_at,
                });
            }
            Ok(())
        })
    }

    pub fn purge_outgoing_disclosure(
        &self,
        tx_id: &[u8; 32],
        output_index: u32,
    ) -> Result<bool, WalletError> {
        self.with_mut(|state| {
            let original = state.outgoing_disclosures.len();
            state
                .outgoing_disclosures
                .retain(|record| !(record.tx_id == *tx_id && record.output_index == output_index));
            Ok(state.outgoing_disclosures.len() != original)
        })
    }

    pub fn purge_all_outgoing_disclosures(&self) -> Result<usize, WalletError> {
        self.with_mut(|state| {
            let count = state.outgoing_disclosures.len();
            state.outgoing_disclosures.clear();
            Ok(count)
        })
    }

    pub fn record_pending_submission(
        &self,
        tx_id: [u8; 32],
        nullifiers: Vec<[u8; 48]>,
        spent_note_indexes: Vec<usize>,
        recipients: Vec<TransferRecipient>,
        fee: u64,
    ) -> Result<(), WalletError> {
        let submitted_at = current_timestamp();
        self.with_mut(|state| {
            state.pending.push(PendingTransaction {
                tx_id,
                nullifiers,
                spent_note_indexes,
                submitted_at,
                status: PendingStatus::InMempool,
                recipients,
                fee,
            });
            Ok(())
        })
    }

    pub fn refresh_pending(
        &self,
        latest_height: u64,
        nullifiers: &HashSet<[u8; 48]>,
    ) -> Result<(), WalletError> {
        // Pending timeout: keep consolidation transactions around much longer because a large
        // consolidation can legitimately span many blocks.
        const DEFAULT_PENDING_TIMEOUT_SECS: u64 = 300;
        const DEFAULT_CONSOLIDATION_PENDING_TIMEOUT_SECS: u64 = 12 * 60 * 60;
        let now = current_timestamp();

        let pending_timeout_secs = std::env::var("WALLET_PENDING_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_PENDING_TIMEOUT_SECS);
        let consolidation_timeout_secs = std::env::var("WALLET_CONSOLIDATION_PENDING_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_CONSOLIDATION_PENDING_TIMEOUT_SECS);

        self.with_mut(|state| {
            let mut expired_indexes: Vec<usize> = Vec::new();

            // Debug: print chain nullifiers
            if std::env::var("WALLET_DEBUG_PENDING").is_ok() {
                eprintln!(
                    "[DEBUG refresh_pending] chain nullifiers ({}):",
                    nullifiers.len()
                );
                for nf in nullifiers.iter() {
                    eprintln!("  chain: {}", hex::encode(nf));
                }
            }

            for (i, tx) in state.pending.iter_mut().enumerate() {
                if matches!(tx.status, PendingStatus::Mined { .. }) {
                    continue;
                }

                // Debug: print pending tx nullifiers
                if std::env::var("WALLET_DEBUG_PENDING").is_ok() {
                    eprintln!(
                        "[DEBUG refresh_pending] tx {} nullifiers ({}):",
                        hex::encode(&tx.tx_id[..8]),
                        tx.nullifiers.len()
                    );
                    for nf in &tx.nullifiers {
                        let found = nullifiers.contains(nf);
                        eprintln!("  pending: {} (found: {})", hex::encode(nf), found);
                    }
                }

                // Check if transaction was mined (nullifiers on-chain)
                // Skip zero-padded nullifiers when checking
                let real_nullifiers: Vec<&[u8; 48]> = tx
                    .nullifiers
                    .iter()
                    .filter(|nf| **nf != [0u8; 48])
                    .collect();
                if !real_nullifiers.is_empty()
                    && real_nullifiers.iter().all(|nf| nullifiers.contains(*nf))
                {
                    tx.status = PendingStatus::Mined {
                        height: latest_height,
                    };
                    for &idx in &tx.spent_note_indexes {
                        if let Some(note) = state.notes.get_mut(idx) {
                            note.spent = true;
                            note.pending_spend = false;
                        }
                    }
                } else {
                    let is_consolidation = tx
                        .recipients
                        .iter()
                        .any(|recipient| recipient.memo.as_deref() == Some("consolidation"));
                    let timeout_secs = if is_consolidation {
                        consolidation_timeout_secs
                    } else {
                        pending_timeout_secs
                    };
                    if now.saturating_sub(tx.submitted_at) > timeout_secs {
                        // Transaction expired - release locked notes
                        for &idx in &tx.spent_note_indexes {
                            if let Some(note) = state.notes.get_mut(idx) {
                                // Only release if not actually spent on-chain
                                if !note.spent {
                                    note.pending_spend = false;
                                }
                            }
                        }
                        expired_indexes.push(i);
                    }
                }
            }

            // Remove expired transactions (iterate in reverse to preserve indexes)
            for i in expired_indexes.into_iter().rev() {
                state.pending.remove(i);
            }

            // Release any notes marked pending that are not referenced by a pending tx.
            // This can happen if a submit failed or the process crashed before recording.
            let mut referenced: HashSet<usize> = HashSet::new();
            for tx in &state.pending {
                referenced.extend(tx.spent_note_indexes.iter().copied());
            }
            let mut released = 0usize;
            for (idx, note) in state.notes.iter_mut().enumerate() {
                if note.pending_spend && !note.spent && !referenced.contains(&idx) {
                    note.pending_spend = false;
                    released = released.saturating_add(1);
                }
            }
            if released > 0 && std::env::var("WALLET_DEBUG_PENDING").is_ok() {
                eprintln!(
                    "[DEBUG refresh_pending] released {} orphaned pending notes",
                    released
                );
            }

            Ok(())
        })
    }

    fn with_state<F, T>(&self, func: F) -> Result<T, WalletError>
    where
        F: FnOnce(&WalletState) -> Result<T, WalletError>,
    {
        let state = self
            .state
            .lock()
            .map_err(|_| WalletError::InvalidState("wallet poisoned"))?;
        func(&state)
    }

    fn with_mut<F, T>(&self, func: F) -> Result<T, WalletError>
    where
        F: FnOnce(&mut WalletState) -> Result<T, WalletError>,
    {
        let mut state = self
            .state
            .lock()
            .map_err(|_| WalletError::InvalidState("wallet poisoned"))?;
        let result = func(&mut state)?;
        drop(state);
        self.write_locked()?;
        Ok(result)
    }

    fn write_locked(&self) -> Result<(), WalletError> {
        let state = self
            .state
            .lock()
            .map_err(|_| WalletError::InvalidState("wallet poisoned"))?;
        let plaintext = bincode::serialize(&*state)?;
        drop(state);
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plaintext,
                    aad: &self.salt,
                },
            )
            .map_err(|_| WalletError::EncryptionFailure)?;
        let file = WalletFile {
            version: FILE_VERSION,
            salt: self.salt,
            nonce,
            ciphertext,
        };
        let bytes = bincode::serialize(&file)?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut tmp_suffix = [0u8; 8];
        OsRng.fill_bytes(&mut tmp_suffix);
        let tmp_id = u64::from_le_bytes(tmp_suffix);
        let tmp = self.path.with_extension(format!("tmp-{tmp_id:x}"));
        fs::write(&tmp, &bytes)?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalletMode {
    Full,
    WatchOnly,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletState {
    mode: WalletMode,
    tree_depth: u32,
    #[serde(with = "serde_option_bytes32")]
    root_secret: Option<[u8; 32]>,
    derived: Option<DerivedKeys>,
    incoming: IncomingViewingKey,
    full_viewing_key: Option<FullViewingKey>,
    outgoing: Option<OutgoingViewingKey>,
    next_address_index: u32,
    notes: Vec<TrackedNote>,
    pending: Vec<PendingTransaction>,
    #[serde(with = "serde_vec_bytes48")]
    commitments: Vec<Commitment>,
    next_commitment_index: u64,
    next_ciphertext_index: u64,
    last_synced_height: u64,
    #[serde(default)]
    outgoing_disclosures: Vec<OutgoingDisclosureRecord>,
    /// Genesis hash of the chain this wallet was synced with.
    /// Used to detect chain resets/mismatches.
    #[serde(default, with = "serde_option_bytes32")]
    genesis_hash: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TrackedNote {
    note: RecoveredNote,
    position: u64,
    ciphertext_index: u64,
    #[serde(with = "serde_option_bytes48")]
    nullifier: Option<[u8; 48]>,
    spent: bool,
    pending_spend: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingTransaction {
    #[serde(with = "serde_bytes32")]
    pub tx_id: [u8; 32],
    #[serde(with = "serde_vec_bytes48")]
    pub nullifiers: Vec<[u8; 48]>,
    pub spent_note_indexes: Vec<usize>,
    pub submitted_at: u64,
    pub status: PendingStatus,
    #[serde(default)]
    pub recipients: Vec<TransferRecipient>,
    #[serde(default)]
    pub fee: u64,
}

impl PendingTransaction {
    pub fn confirmations(&self, latest_height: u64) -> u64 {
        match self.status {
            PendingStatus::Mined { height } => latest_height.saturating_sub(height) + 1,
            PendingStatus::InMempool => 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PendingStatus {
    InMempool,
    Mined { height: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferRecipient {
    pub address: String,
    pub value: u64,
    pub asset_id: u64,
    pub memo: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutgoingDisclosureDraft {
    pub output_index: u32,
    pub recipient_address: String,
    pub note: NoteData,
    #[serde(with = "serde_bytes48")]
    pub commitment: [u8; 48],
    #[serde(default)]
    pub memo: Option<MemoPlaintext>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutgoingDisclosureRecord {
    #[serde(with = "serde_bytes32")]
    pub tx_id: [u8; 32],
    pub output_index: u32,
    pub recipient_address: String,
    pub note: NoteData,
    #[serde(with = "serde_bytes48")]
    pub commitment: [u8; 48],
    #[serde(default)]
    pub memo: Option<MemoPlaintext>,
    #[serde(with = "serde_bytes32")]
    pub genesis_hash: [u8; 32],
    pub created_at: u64,
}

#[derive(Clone, Debug)]
pub struct SpendableNote {
    pub index: usize,
    pub recovered: RecoveredNote,
    pub position: u64,
}

impl SpendableNote {
    pub fn value(&self) -> u64 {
        self.recovered.note.value
    }

    pub fn asset_id(&self) -> u64 {
        self.recovered.note.asset_id
    }
}

#[derive(Serialize, Deserialize)]
struct WalletFile {
    version: u32,
    #[serde(with = "serde_bytes16")]
    salt: [u8; SALT_LEN],
    #[serde(with = "serde_bytes12")]
    nonce: [u8; NONCE_LEN],
    #[serde(with = "serde_bytes_vec")]
    ciphertext: Vec<u8>,
}

fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN], WalletError> {
    let mut key = [0u8; KEY_LEN];
    let argon2 = Argon2::default();
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|err| WalletError::Serialization(err.to_string()))?;
    Ok(key)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_secs())
        .unwrap_or(0)
}

mod serde_bytes16 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 16 {
            return Err(serde::de::Error::custom("expected 16 bytes"));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod serde_bytes12 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 12], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 12], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 12 {
            return Err(serde::de::Error::custom("expected 12 bytes"));
        }
        let mut out = [0u8; 12];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod serde_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod serde_option_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&serde_bytes::Bytes::new(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = Option::<Vec<u8>>::deserialize(deserializer)?;
        opt.map(|bytes| {
            if bytes.len() != 32 {
                return Err(serde::de::Error::custom("expected 32 bytes"));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(out)
        })
        .transpose()
    }
}

mod serde_bytes48 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 48 {
            return Err(serde::de::Error::custom("expected 48 bytes"));
        }
        let mut out = [0u8; 48];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod serde_option_bytes48 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 48]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&serde_bytes::Bytes::new(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 48]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = Option::<Vec<u8>>::deserialize(deserializer)?;
        opt.map(|bytes| {
            if bytes.len() != 48 {
                return Err(serde::de::Error::custom("expected 48 bytes"));
            }
            let mut out = [0u8; 48];
            out.copy_from_slice(&bytes);
            Ok(out)
        })
        .transpose()
    }
}

mod serde_vec_bytes48 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(values: &[[u8; 48]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let wrapped: Vec<_> = values
            .iter()
            .map(|bytes| serde_bytes::Bytes::new(bytes))
            .collect();
        wrapped.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 48]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wrapped: Vec<serde_bytes::ByteBuf> = Vec::deserialize(deserializer)?;
        Ok(wrapped
            .into_iter()
            .map(|buf| {
                let data = buf.into_vec();
                let mut out = [0u8; 48];
                out.copy_from_slice(&data);
                out
            })
            .collect())
    }
}

mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notes::NotePlaintext;
    use crate::notes::NoteCiphertext;
    use crate::notes::MemoPlaintext;
    use rand::{rngs::StdRng, SeedableRng};
    use tempfile::tempdir;
    use transaction_circuit::hashing_pq::felts_to_bytes48;

    #[test]
    fn create_and_open_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let addr1 = store.next_address().unwrap();
        assert!(addr1.pk_recipient != [0u8; 32]);
        drop(store);
        let reopened = WalletStore::open(&path, "passphrase").unwrap();
        let addr2 = reopened.next_address().unwrap();
        assert_ne!(addr1.pk_recipient, addr2.pk_recipient);
    }

    #[test]
    fn spendable_notes_filters_spent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let ivk = store.incoming_key().unwrap();
        let address = ivk.shielded_address(0).unwrap();
        let mut rng = StdRng::seed_from_u64(9);
        let note = NotePlaintext::random(10, 0, crate::notes::MemoPlaintext::default(), &mut rng);
        let ciphertext = crate::notes::NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        let recovered = ivk.decrypt_note(&ciphertext).unwrap();
        let commitment =
            transaction_circuit::hashing_pq::felts_to_bytes48(&recovered.note_data.commitment());
        store.append_commitments(&[(0, commitment)]).unwrap();
        store.register_ciphertext_index(0).unwrap();
        store
            .record_recovered_note(recovered.clone(), 0, 0)
            .unwrap();
        let notes = store.spendable_notes(0).unwrap();
        assert_eq!(notes.len(), 1);
        store.mark_notes_pending(&[notes[0].index], true).unwrap();
        assert!(store.spendable_notes(0).unwrap().is_empty());
    }

    #[test]
    fn orphaned_pending_notes_are_released() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let ivk = store.incoming_key().unwrap();
        let address = ivk.shielded_address(0).unwrap();
        let mut rng = StdRng::seed_from_u64(42);

        let note1 = NotePlaintext::random(10, 0, MemoPlaintext::default(), &mut rng);
        let ciphertext1 = NoteCiphertext::encrypt(&address, &note1, &mut rng).unwrap();
        let recovered1 = ivk.decrypt_note(&ciphertext1).unwrap();
        let commitment1 = felts_to_bytes48(&recovered1.note_data.commitment());

        let note2 = NotePlaintext::random(20, 0, MemoPlaintext::default(), &mut rng);
        let ciphertext2 = NoteCiphertext::encrypt(&address, &note2, &mut rng).unwrap();
        let recovered2 = ivk.decrypt_note(&ciphertext2).unwrap();
        let commitment2 = felts_to_bytes48(&recovered2.note_data.commitment());

        store
            .append_commitments(&[(0, commitment1), (1, commitment2)])
            .unwrap();
        store.register_ciphertext_index(0).unwrap();
        store.record_recovered_note(recovered1, 0, 0).unwrap();
        store.register_ciphertext_index(1).unwrap();
        store.record_recovered_note(recovered2, 1, 1).unwrap();

        let notes = store.spendable_notes(0).unwrap();
        assert_eq!(notes.len(), 2);
        let idx0 = notes[0].index;
        let idx1 = notes[1].index;

        store.mark_notes_pending(&[idx0, idx1], true).unwrap();
        store
            .record_pending_submission([1u8; 32], vec![[2u8; 48]], vec![idx0], vec![], 0)
            .unwrap();

        store.refresh_pending(1, &HashSet::new()).unwrap();
        let pending = store.pending_spend_notes(0).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].index, idx0);
    }

    #[test]
    fn recovered_note_uses_commitment_index_as_position() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let ivk = store.incoming_key().unwrap();
        let address = ivk.shielded_address(0).unwrap();
        let mut rng = StdRng::seed_from_u64(77);

        let note_a = NotePlaintext::random(10, 0, MemoPlaintext::default(), &mut rng);
        let note_b = NotePlaintext::random(20, 0, MemoPlaintext::default(), &mut rng);
        let ct_a = NoteCiphertext::encrypt(&address, &note_a, &mut rng).unwrap();
        let ct_b = NoteCiphertext::encrypt(&address, &note_b, &mut rng).unwrap();
        let rec_a = ivk.decrypt_note(&ct_a).unwrap();
        let rec_b = ivk.decrypt_note(&ct_b).unwrap();

        let cm_a = felts_to_bytes48(&rec_a.note_data.commitment());
        let cm_b = felts_to_bytes48(&rec_b.note_data.commitment());
        store.append_commitments(&[(0, cm_a), (1, cm_b)]).unwrap();

        let recovered = vec![Some(rec_b), None];
        let added = store.apply_ciphertext_batch(0, recovered).unwrap();
        assert_eq!(added, 1);

        let notes = store.spendable_notes(0).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].position, 1);
    }

    #[test]
    fn repair_note_positions_updates_mismatched_notes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let ivk = store.incoming_key().unwrap();
        let address = ivk.shielded_address(0).unwrap();
        let mut rng = StdRng::seed_from_u64(91);

        let note = NotePlaintext::random(10, 0, MemoPlaintext::default(), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        let recovered = ivk.decrypt_note(&ciphertext).unwrap();
        let commitment = felts_to_bytes48(&recovered.note_data.commitment());

        store.append_commitments(&[(0, commitment)]).unwrap();
        store.register_ciphertext_index(0).unwrap();
        store.record_recovered_note(recovered, 5, 0).unwrap();

        assert!(store.validate_notes_against_commitments().is_err());
        let updated = store.repair_note_positions().unwrap();
        assert_eq!(updated, 1);
        assert!(store.validate_notes_against_commitments().is_ok());
    }
}
