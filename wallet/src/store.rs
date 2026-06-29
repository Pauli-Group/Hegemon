use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write;
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
use transaction_circuit::{
    constants::NATIVE_ASSET_ID, hashing_pq::Commitment, note::NoteData,
    smallwood_accumulator_auth_key_bytes, smallwood_value_lock_auth_key_bytes,
};
use zeroize::Zeroize;

use crate::address::ShieldedAddress;
use crate::error::WalletError;
use crate::keys::{DerivedKeys, RootSecret};
use crate::multisig::{
    create_account_record, signer_tag_from_spend_key, validate_account_record,
    MultisigAccountPublic, MultisigAccountRecord,
};
use crate::notes::MemoPlaintext;
use crate::tx_builder::PreparedMultisigFinalPlan;
use crate::viewing::{FullViewingKey, IncomingViewingKey, OutgoingViewingKey, RecoveredNote};

const FILE_VERSION: u32 = 9;
const LEGACY_FILE_VERSION_V8: u32 = 8;
const LEGACY_FILE_VERSION_V7: u32 = 7;
const LEGACY_FILE_VERSION_V6: u32 = 6;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
/// Default tree depth - must match CIRCUIT_MERKLE_DEPTH in transaction-circuit.
const DEFAULT_TREE_DEPTH: u32 = 32;

fn deserialize_exact<T>(bytes: &[u8]) -> Result<T, WalletError>
where
    T: serde::de::DeserializeOwned,
{
    use std::io::Cursor;

    let mut cursor = Cursor::new(bytes);
    let value: T = bincode::deserialize_from(&mut cursor)
        .map_err(|err| WalletError::Serialization(err.to_string()))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(WalletError::Serialization(
            "trailing bytes after serialized payload".to_string(),
        ));
    }
    Ok(value)
}

/// Wallet store - manages encrypted wallet state on disk.
/// The encryption key is zeroized on drop to prevent key material from persisting in memory.
#[derive(Debug)]
pub struct WalletStore {
    path: PathBuf,
    key: [u8; KEY_LEN],
    salt: [u8; SALT_LEN],
    state: Mutex<WalletState>,
    commitment_tree_cache: Mutex<Option<CommitmentTree>>,
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
            recent: Vec::new(),
            commitments: Vec::new(),
            next_commitment_index: 0,
            next_ciphertext_index: 0,
            last_synced_height: 0,
            last_synced_block_hash: None,
            outgoing_disclosures: Vec::new(),
            genesis_hash: None,
            multisig_accounts: Vec::new(),
            local_note_openings: Vec::new(),
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
            recent: Vec::new(),
            commitments: Vec::new(),
            next_commitment_index: 0,
            next_ciphertext_index: 0,
            last_synced_height: 0,
            last_synced_block_hash: None,
            outgoing_disclosures: Vec::new(),
            genesis_hash: None,
            multisig_accounts: Vec::new(),
            local_note_openings: Vec::new(),
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
            commitment_tree_cache: Mutex::new(None),
        };
        store.write_locked()?;
        Ok(store)
    }

    pub fn open<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Self, WalletError> {
        let bytes = fs::read(path.as_ref())?;
        let file: WalletFile = deserialize_exact(&bytes)?;
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
            FILE_VERSION => deserialize_wallet_state(&plaintext)?,
            LEGACY_FILE_VERSION_V8 => deserialize_wallet_state_v8(&plaintext)?,
            LEGACY_FILE_VERSION_V7 => deserialize_wallet_state_v7(&plaintext)?,
            LEGACY_FILE_VERSION_V6 => deserialize_wallet_state_v6(&plaintext)?,
            other => {
                return Err(WalletError::Serialization(format!(
                    "unsupported wallet file version {other} (expected {FILE_VERSION})"
                )));
            }
        };
        Ok(WalletStore {
            path: path.as_ref().to_path_buf(),
            key,
            salt: file.salt,
            state: Mutex::new(state),
            commitment_tree_cache: Mutex::new(None),
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

    /// Returns the deterministic 32-byte signing seed for account-based extrinsics.
    ///
    /// Full wallets derive this from the stored root secret. Watch-only wallets
    /// cannot provide a signing seed.
    pub fn signing_seed(&self) -> Result<[u8; 32], WalletError> {
        self.with_state(|state| state.root_secret.ok_or(WalletError::WatchOnly))
    }

    pub fn outgoing_key(&self) -> Result<Option<OutgoingViewingKey>, WalletError> {
        self.with_state(|state| Ok(state.outgoing.clone()))
    }

    pub fn local_multisig_signer_tag(
        &self,
    ) -> Result<transaction_circuit::SmallwoodSignerTag, WalletError> {
        self.with_state(|state| {
            let derived = state.derived.as_ref().ok_or(WalletError::WatchOnly)?;
            Ok(signer_tag_from_spend_key(&derived.spend.to_bytes()))
        })
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
                self.invalidate_commitment_tree_cache()?;
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

    pub fn set_last_synced_block_hash(&self, hash: [u8; 32]) -> Result<(), WalletError> {
        self.with_mut(|state| {
            state.last_synced_block_hash = Some(hash);
            Ok(())
        })
    }

    pub fn last_synced_height(&self) -> Result<u64, WalletError> {
        self.with_state(|state| Ok(state.last_synced_height))
    }

    pub fn last_synced_block_hash(&self) -> Result<Option<[u8; 32]>, WalletError> {
        self.with_state(|state| Ok(state.last_synced_block_hash))
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
            state.recent.clear();
            state.commitments.clear();
            state.next_commitment_index = 0;
            state.next_ciphertext_index = 0;
            state.last_synced_height = 0;
            state.last_synced_block_hash = None;
            state.genesis_hash = None;
            self.invalidate_commitment_tree_cache()?;
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
            self.invalidate_commitment_tree_cache()?;
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
    ///
    /// If a ciphertext decrypts successfully, its note commitment must match the local commitment
    /// at the same index. A mismatch means the node/archive served substituted ciphertext bytes for
    /// a commitment that is already bound by the verified chain root, so sync fails closed.
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

                if let Some(mut note) = maybe_note {
                    let commitment_index = usize::try_from(index)
                        .map_err(|_| WalletError::InvalidState("ciphertext index overflow"))?;
                    let Some(chain_commitment) = state.commitments.get(commitment_index) else {
                        return Err(WalletError::InvalidState("ciphertext commitment missing"));
                    };
                    let mut used_local_opening = false;
                    let mut expected_commitment = transaction_circuit::hashing_pq::felts_to_bytes48(
                        &note.note_data.commitment(),
                    );
                    let matching_opening =
                        matching_local_note_opening(state, chain_commitment, &note).cloned();
                    if let Some(local_opening) = matching_opening.as_ref() {
                        if local_opening.uses_private_auth() {
                            note = local_opening.note.clone();
                            expected_commitment = local_opening.commitment;
                            used_local_opening = true;
                        }
                    }
                    if *chain_commitment != expected_commitment {
                        let Some(local_opening) = matching_opening else {
                            return Err(WalletError::InvalidState(
                                "ciphertext commitment mismatch",
                            ));
                        };
                        note = local_opening.note.clone();
                        expected_commitment = local_opening.commitment;
                        used_local_opening = true;
                        if *chain_commitment != expected_commitment {
                            return Err(WalletError::InvalidState(
                                "local note opening commitment mismatch",
                            ));
                        }
                    }

                    let position = index;
                    if !state.notes.iter().any(|n| n.position == position) {
                        let nullifier = if used_local_opening {
                            None
                        } else {
                            state
                                .full_viewing_key
                                .as_ref()
                                .map(|fvk| fvk.compute_nullifier(&note.note.rho, position))
                        };
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
                } else {
                    let commitment_index = usize::try_from(index)
                        .map_err(|_| WalletError::InvalidState("ciphertext index overflow"))?;
                    if let Some(chain_commitment) = state.commitments.get(commitment_index) {
                        if let Some(local_opening) = state
                            .local_note_openings
                            .iter()
                            .find(|opening| opening.commitment == *chain_commitment)
                            .cloned()
                        {
                            let expected_commitment =
                                transaction_circuit::hashing_pq::felts_to_bytes48(
                                    &local_opening.note.note_data.commitment(),
                                );
                            if expected_commitment != local_opening.commitment {
                                return Err(WalletError::InvalidState(
                                    "local note opening commitment mismatch",
                                ));
                            }
                            let position = index;
                            if !state.notes.iter().any(|n| n.position == position) {
                                state.notes.push(TrackedNote {
                                    note: local_opening.note,
                                    position,
                                    ciphertext_index: index,
                                    nullifier: None,
                                    spent: false,
                                    pending_spend: false,
                                });
                                added = added
                                    .checked_add(1)
                                    .ok_or(WalletError::InvalidState("note count overflow"))?;
                            }
                        }
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

    pub fn record_local_note_opening(&self, note: RecoveredNote) -> Result<[u8; 48], WalletError> {
        self.record_local_note_opening_with_multisig(note, None)
    }

    pub fn record_local_note_opening_with_multisig(
        &self,
        note: RecoveredNote,
        multisig_accumulator: Option<LocalMultisigAccumulatorOpening>,
    ) -> Result<[u8; 48], WalletError> {
        let commitment =
            transaction_circuit::hashing_pq::felts_to_bytes48(&note.note_data.commitment());
        let created_at = current_timestamp();
        self.with_mut(|state| {
            if let Some(opening) = state
                .local_note_openings
                .iter()
                .find(|opening| opening.commitment == commitment)
            {
                if opening.multisig_accumulator != multisig_accumulator
                    || opening.multisig_value_lock.is_some()
                {
                    return Err(WalletError::InvalidState(
                        "local note opening metadata mismatch",
                    ));
                }
                return Ok(());
            }
            state.local_note_openings.push(LocalNoteOpeningRecord {
                commitment,
                note,
                multisig_accumulator,
                multisig_value_lock: None,
                created_at,
            });
            Ok(())
        })?;
        Ok(commitment)
    }

    pub fn record_local_note_opening_with_multisig_value_lock(
        &self,
        note: RecoveredNote,
        multisig_value_lock: LocalMultisigValueLockOpening,
    ) -> Result<[u8; 48], WalletError> {
        let commitment =
            transaction_circuit::hashing_pq::felts_to_bytes48(&note.note_data.commitment());
        let created_at = current_timestamp();
        self.with_mut(|state| {
            if let Some(opening) = state
                .local_note_openings
                .iter()
                .find(|opening| opening.commitment == commitment)
            {
                if opening.multisig_value_lock != Some(multisig_value_lock.clone()) {
                    return Err(WalletError::InvalidState(
                        "local note opening metadata mismatch",
                    ));
                }
                return Ok(());
            }
            state.local_note_openings.push(LocalNoteOpeningRecord {
                commitment,
                note,
                multisig_accumulator: None,
                multisig_value_lock: Some(multisig_value_lock),
                created_at,
            });
            Ok(())
        })?;
        Ok(commitment)
    }

    pub fn local_note_openings(&self) -> Result<Vec<LocalNoteOpeningRecord>, WalletError> {
        self.with_state(|state| Ok(state.local_note_openings.clone()))
    }

    pub fn local_note_opening_by_commitment(
        &self,
        commitment: &[u8; 48],
    ) -> Result<Option<LocalNoteOpeningRecord>, WalletError> {
        self.with_state(|state| {
            Ok(state
                .local_note_openings
                .iter()
                .find(|opening| opening.commitment == *commitment)
                .cloned())
        })
    }

    pub fn import_local_note_opening_record(
        &self,
        opening: LocalNoteOpeningRecord,
        position: u64,
        ciphertext_index: u64,
    ) -> Result<[u8; 48], WalletError> {
        let recomputed =
            transaction_circuit::hashing_pq::felts_to_bytes48(&opening.note.note_data.commitment());
        if recomputed != opening.commitment {
            return Err(WalletError::InvalidArgument(
                "local note opening commitment mismatch",
            ));
        }
        let opening_commitment = opening.commitment;
        self.with_mut(|state| {
            validate_imported_local_note_opening(state, &opening)?;
            let commitment_index = usize::try_from(position)
                .map_err(|_| WalletError::InvalidArgument("commitment position overflow"))?;
            match state.commitments.get(commitment_index) {
                Some(commitment) if *commitment == opening.commitment => {}
                Some(_) => {
                    return Err(WalletError::InvalidArgument(
                        "local note opening position commitment mismatch",
                    ));
                }
                None => {
                    return Err(WalletError::InvalidArgument(
                        "local note opening commitment position unavailable",
                    ));
                }
            }
            if let Some(existing) = state
                .local_note_openings
                .iter()
                .find(|existing| existing.commitment == opening.commitment)
            {
                if existing.multisig_accumulator != opening.multisig_accumulator
                    || existing.multisig_value_lock != opening.multisig_value_lock
                {
                    return Err(WalletError::InvalidState(
                        "local note opening metadata mismatch",
                    ));
                }
            } else {
                state.local_note_openings.push(opening.clone());
            }
            if let Some(existing) = state.notes.iter().find(|note| {
                transaction_circuit::hashing_pq::felts_to_bytes48(&note.note.note_data.commitment())
                    == opening.commitment
            }) {
                if existing.position != position || existing.ciphertext_index != ciphertext_index {
                    return Err(WalletError::InvalidState(
                        "local note opening tracked-note mismatch",
                    ));
                }
            } else {
                state.notes.push(TrackedNote {
                    note: opening.note,
                    position,
                    ciphertext_index,
                    nullifier: None,
                    spent: false,
                    pending_spend: false,
                });
            }
            Ok(())
        })?;
        Ok(opening_commitment)
    }

    pub fn spendable_note_by_commitment(
        &self,
        commitment: &[u8; 48],
    ) -> Result<Option<SpendableNote>, WalletError> {
        self.with_state(|state| {
            Ok(state.notes.iter().enumerate().find_map(|(idx, note)| {
                let note_commitment = transaction_circuit::hashing_pq::felts_to_bytes48(
                    &note.note.note_data.commitment(),
                );
                (note_commitment == *commitment && !note.spent && !note.pending_spend).then(|| {
                    SpendableNote {
                        index: idx,
                        recovered: note.note.clone(),
                        position: note.position,
                    }
                })
            }))
        })
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

    pub fn tracked_notes(&self) -> Result<Vec<TrackedNoteView>, WalletError> {
        self.with_state(|state| {
            let mut notes: Vec<TrackedNoteView> = state
                .notes
                .iter()
                .map(|note| TrackedNoteView {
                    note: note.note.clone(),
                    position: note.position,
                    ciphertext_index: note.ciphertext_index,
                    nullifier: note.nullifier,
                    spent: note.spent,
                    pending_spend: note.pending_spend,
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
        if let Some(tree) = self.cached_commitment_tree()? {
            return Ok(tree);
        }

        let tree = self.with_state(Self::build_commitment_tree_from_state)?;
        self.store_commitment_tree_cache(tree.clone())?;
        Ok(tree)
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

    /// Validate that tracked notes are internally self-consistent.
    ///
    /// This catches poisoned local wallet state where the persisted plaintext note fields no
    /// longer match the stored witness data, which can otherwise produce `BadProof` submissions
    /// even when the commitment tree root still matches the chain.
    pub fn validate_notes_internal_consistency(&self) -> Result<(), WalletError> {
        self.with_state(|state| {
            for note in &state.notes {
                let expected_note_data = note.note.note.to_note_data(
                    note.note.note_data.pk_recipient,
                    note.note.note_data.pk_auth,
                );
                if expected_note_data.value != note.note.note_data.value
                    || expected_note_data.asset_id != note.note.note_data.asset_id
                    || expected_note_data.pk_recipient != note.note.note_data.pk_recipient
                    || expected_note_data.pk_auth != note.note.note_data.pk_auth
                    || expected_note_data.rho != note.note.note_data.rho
                    || expected_note_data.r != note.note.note_data.r
                {
                    return Err(WalletError::InvalidState(
                        "tracked note plaintext does not match stored witness data",
                    ));
                }

                if let (Some(fvk), Some(stored_nullifier)) =
                    (state.full_viewing_key.as_ref(), note.nullifier)
                {
                    let expected_nullifier =
                        fvk.compute_nullifier(&note.note.note.rho, note.position);
                    if stored_nullifier != expected_nullifier {
                        return Err(WalletError::InvalidState(
                            "tracked note nullifier does not match stored plaintext",
                        ));
                    }
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
        self.with_state(|state| {
            Ok(state
                .pending
                .iter()
                .filter(|tx| matches!(tx.status, PendingStatus::InMempool))
                .cloned()
                .collect())
        })
    }

    pub fn recent_transactions(&self) -> Result<Vec<RecentTransaction>, WalletError> {
        self.with_state(|state| Ok(state.recent.clone()))
    }

    pub fn outgoing_disclosures(&self) -> Result<Vec<OutgoingDisclosureRecord>, WalletError> {
        self.with_state(|state| Ok(state.outgoing_disclosures.clone()))
    }

    pub fn create_multisig_account(
        &self,
        threshold: u64,
        policy_signer_tags: Vec<transaction_circuit::SmallwoodSignerTag>,
    ) -> Result<MultisigAccountPublic, WalletError> {
        if self.mode()? == WalletMode::WatchOnly {
            return Err(WalletError::WatchOnly);
        }
        let mut rng = OsRng;
        let record =
            create_account_record(threshold, policy_signer_tags, &mut rng, current_timestamp())?;
        let public = record.public.clone();
        self.with_mut(|state| {
            if state
                .multisig_accounts
                .iter()
                .any(|existing| existing.public.account_id == public.account_id)
            {
                return Err(WalletError::InvalidState("multisig account id collision"));
            }
            state.multisig_accounts.push(record);
            Ok(())
        })?;
        Ok(public)
    }

    pub fn import_multisig_account_record(
        &self,
        record: MultisigAccountRecord,
    ) -> Result<MultisigAccountPublic, WalletError> {
        if self.mode()? == WalletMode::WatchOnly {
            return Err(WalletError::WatchOnly);
        }
        validate_account_record(&record)?;
        let public = record.public.clone();
        self.with_mut(|state| {
            if let Some(existing) = state
                .multisig_accounts
                .iter()
                .find(|existing| existing.public.account_id == public.account_id)
            {
                if existing != &record {
                    return Err(WalletError::InvalidState("multisig account id collision"));
                }
                return Ok(());
            }
            state.multisig_accounts.push(record);
            Ok(())
        })?;
        Ok(public)
    }

    pub fn multisig_accounts(&self) -> Result<Vec<MultisigAccountPublic>, WalletError> {
        self.with_state(|state| {
            Ok(state
                .multisig_accounts
                .iter()
                .map(|record| record.public.clone())
                .collect())
        })
    }

    pub fn multisig_account_record(
        &self,
        account_id: &[u8; 32],
    ) -> Result<Option<MultisigAccountRecord>, WalletError> {
        self.with_state(|state| {
            Ok(state
                .multisig_accounts
                .iter()
                .find(|record| record.public.account_id == *account_id)
                .cloned())
        })
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
            let mut mined_indexes: Vec<usize> = Vec::new();

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
                    mined_indexes.push(i);
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
                    mined_indexes.push(i);
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

            const MAX_RECENT_TRANSACTIONS: usize = 128;
            for i in mined_indexes.into_iter().rev() {
                let tx = state.pending.remove(i);
                let PendingStatus::Mined { height } = tx.status else {
                    continue;
                };
                state.recent.push(RecentTransaction {
                    tx_id: tx.tx_id,
                    submitted_at: tx.submitted_at,
                    mined_height: height,
                    recipients: tx.recipients,
                    fee: tx.fee,
                });
            }
            state
                .recent
                .sort_by_key(|tx| std::cmp::Reverse(tx.submitted_at));
            state.recent.truncate(MAX_RECENT_TRANSACTIONS);

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

    fn build_commitment_tree_from_state(
        state: &WalletState,
    ) -> Result<CommitmentTree, WalletError> {
        let depth = state.tree_depth as usize;
        let mut tree = CommitmentTree::new(depth)
            .map_err(|_| WalletError::InvalidState("invalid tree depth"))?;
        for value in &state.commitments {
            let _ = tree
                .append(*value)
                .map_err(|_| WalletError::InvalidState("tree overflow"))?;
        }
        Ok(tree)
    }

    fn cached_commitment_tree(&self) -> Result<Option<CommitmentTree>, WalletError> {
        let cache = self
            .commitment_tree_cache
            .lock()
            .map_err(|_| WalletError::InvalidState("wallet tree cache poisoned"))?;
        Ok(cache.clone())
    }

    fn store_commitment_tree_cache(&self, tree: CommitmentTree) -> Result<(), WalletError> {
        let mut cache = self
            .commitment_tree_cache
            .lock()
            .map_err(|_| WalletError::InvalidState("wallet tree cache poisoned"))?;
        *cache = Some(tree);
        Ok(())
    }

    fn invalidate_commitment_tree_cache(&self) -> Result<(), WalletError> {
        let mut cache = self
            .commitment_tree_cache
            .lock()
            .map_err(|_| WalletError::InvalidState("wallet tree cache poisoned"))?;
        *cache = None;
        Ok(())
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
        write_private_file(&self.path, &bytes)?;
        Ok(())
    }
}

fn matching_local_note_opening<'a>(
    state: &'a WalletState,
    chain_commitment: &[u8; 48],
    decrypted: &RecoveredNote,
) -> Option<&'a LocalNoteOpeningRecord> {
    state.local_note_openings.iter().find(|opening| {
        let recomputed_commitment =
            transaction_circuit::hashing_pq::felts_to_bytes48(&opening.note.note_data.commitment());
        opening.commitment == *chain_commitment
            && recomputed_commitment == *chain_commitment
            && opening.note.diversifier_index == decrypted.diversifier_index
            && opening.note.note == decrypted.note
            && opening.note.note_data.value == decrypted.note_data.value
            && opening.note.note_data.asset_id == decrypted.note_data.asset_id
            && opening.note.note_data.pk_recipient == decrypted.note_data.pk_recipient
            && opening.note.note_data.rho == decrypted.note_data.rho
            && opening.note.note_data.r == decrypted.note_data.r
    })
}

fn validate_imported_local_note_opening(
    state: &WalletState,
    opening: &LocalNoteOpeningRecord,
) -> Result<(), WalletError> {
    match (&opening.multisig_accumulator, &opening.multisig_value_lock) {
        (None, None) => Ok(()),
        (Some(_), Some(_)) => Err(WalletError::InvalidArgument(
            "local note opening cannot be both multisig accumulator and value lock",
        )),
        (Some(meta), None) => {
            let record = state
                .multisig_accounts
                .iter()
                .find(|record| record.public.account_id == meta.account_id)
                .ok_or(WalletError::InvalidArgument(
                    "unknown multisig account for imported accumulator opening",
                ))?;
            if meta.policy_root != record.policy_root
                || meta.threshold != record.threshold
                || meta.signer_count != record.signer_count
            {
                return Err(WalletError::InvalidArgument(
                    "imported accumulator opening does not match local account",
                ));
            }
            if opening.note.note_data.value != 0
                || opening.note.note_data.asset_id != NATIVE_ASSET_ID
            {
                return Err(WalletError::InvalidArgument(
                    "imported accumulator opening must be a zero-value native note",
                ));
            }
            let expected =
                smallwood_accumulator_auth_key_bytes(&meta.to_smallwood()).map_err(|err| {
                    WalletError::InvalidState(Box::leak(err.to_string().into_boxed_str()))
                })?;
            if opening.note.note_data.pk_auth != expected {
                return Err(WalletError::InvalidArgument(
                    "imported accumulator opening auth key mismatch",
                ));
            }
            Ok(())
        }
        (None, Some(meta)) => {
            let record = state
                .multisig_accounts
                .iter()
                .find(|record| record.public.account_id == meta.account_id)
                .ok_or(WalletError::InvalidArgument(
                    "unknown multisig account for imported value-lock opening",
                ))?;
            if meta.policy_root != record.policy_root {
                return Err(WalletError::InvalidArgument(
                    "imported value-lock opening does not match local account",
                ));
            }
            if opening.note.note_data.value == 0
                || opening.note.note_data.asset_id != NATIVE_ASSET_ID
            {
                return Err(WalletError::InvalidArgument(
                    "imported value-lock opening must be a nonzero native note",
                ));
            }
            let expected =
                smallwood_value_lock_auth_key_bytes(&record.policy_root, &meta.intent_digest)
                    .map_err(|err| {
                        WalletError::InvalidState(Box::leak(err.to_string().into_boxed_str()))
                    })?;
            if opening.note.note_data.pk_auth != expected {
                return Err(WalletError::InvalidArgument(
                    "imported value-lock opening auth key mismatch",
                ));
            }
            if let Some(plan_bytes) = meta.final_plan_bytes.as_ref() {
                let plan: PreparedMultisigFinalPlan =
                    serde_json::from_slice(plan_bytes).map_err(|err| {
                        WalletError::Serialization(format!(
                            "deserialize imported multisig final plan: {err}"
                        ))
                    })?;
                if plan.value_note_commitment != opening.commitment
                    || plan.intent_digest != meta.intent_digest
                {
                    return Err(WalletError::InvalidArgument(
                        "imported value-lock final plan does not match opening",
                    ));
                }
            }
            Ok(())
        }
    }
}

/// Write a plaintext or encrypted wallet artifact with private permissions.
///
/// The write is staged through a fresh 0600 temporary file in the same directory
/// and then atomically renamed into place, so replacing an existing permissive
/// file does not leave newly-written secret material world-readable.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), WalletError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut tmp_suffix = [0u8; 8];
    OsRng.fill_bytes(&mut tmp_suffix);
    let tmp_id = u64::from_le_bytes(tmp_suffix);
    let tmp = path.with_extension(format!("tmp-{tmp_id:x}"));
    write_private_new_file(&tmp, bytes)?;
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err.into());
    }
    set_private_file_permissions(path)?;
    Ok(())
}

/// Open a ledger/export append target with private permissions.
pub fn open_private_append_file(path: &Path) -> Result<fs::File, WalletError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        set_private_file_permissions(path)?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        Ok(fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?)
    }
}

fn write_private_new_file(path: &Path, bytes: &[u8]) -> Result<(), WalletError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        set_private_file_permissions(path)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes)?;
        Ok(())
    }
}

fn set_private_file_permissions(path: &Path) -> Result<(), WalletError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn deserialize_wallet_state(bytes: &[u8]) -> Result<WalletState, WalletError> {
    deserialize_exact::<WalletState>(bytes).map_err(|err| match err {
        WalletError::Serialization(message) => {
            WalletError::Serialization(format!("failed to deserialize wallet state: {message}"))
        }
        other => other,
    })
}

fn deserialize_wallet_state_v8(bytes: &[u8]) -> Result<WalletState, WalletError> {
    deserialize_exact::<WalletStateV8>(bytes)
        .map(WalletState::from)
        .map_err(|err| match err {
            WalletError::Serialization(message) => WalletError::Serialization(format!(
                "failed to deserialize legacy wallet state v8: {message}"
            )),
            other => other,
        })
}

fn deserialize_wallet_state_v7(bytes: &[u8]) -> Result<WalletState, WalletError> {
    deserialize_exact::<WalletStateV7>(bytes)
        .map(WalletState::from)
        .map_err(|err| match err {
            WalletError::Serialization(message) => WalletError::Serialization(format!(
                "failed to deserialize legacy wallet state v7: {message}"
            )),
            other => other,
        })
}

fn deserialize_wallet_state_v6(bytes: &[u8]) -> Result<WalletState, WalletError> {
    deserialize_exact::<WalletStateV6>(bytes)
        .map(WalletState::from)
        .map_err(|err| match err {
            WalletError::Serialization(message) => WalletError::Serialization(format!(
                "failed to deserialize legacy wallet state v6: {message}"
            )),
            other => other,
        })
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
    #[serde(default)]
    recent: Vec<RecentTransaction>,
    #[serde(with = "serde_vec_bytes48")]
    commitments: Vec<Commitment>,
    next_commitment_index: u64,
    next_ciphertext_index: u64,
    last_synced_height: u64,
    #[serde(default, with = "serde_option_bytes32")]
    last_synced_block_hash: Option<[u8; 32]>,
    #[serde(default)]
    outgoing_disclosures: Vec<OutgoingDisclosureRecord>,
    /// Genesis hash of the chain this wallet was synced with.
    /// Used to detect chain resets/mismatches.
    #[serde(default, with = "serde_option_bytes32")]
    genesis_hash: Option<[u8; 32]>,
    #[serde(default)]
    multisig_accounts: Vec<MultisigAccountRecord>,
    #[serde(default)]
    local_note_openings: Vec<LocalNoteOpeningRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletStateV8 {
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
    #[serde(default)]
    recent: Vec<RecentTransaction>,
    #[serde(with = "serde_vec_bytes48")]
    commitments: Vec<Commitment>,
    next_commitment_index: u64,
    next_ciphertext_index: u64,
    last_synced_height: u64,
    #[serde(default, with = "serde_option_bytes32")]
    last_synced_block_hash: Option<[u8; 32]>,
    #[serde(default)]
    outgoing_disclosures: Vec<OutgoingDisclosureRecord>,
    #[serde(default, with = "serde_option_bytes32")]
    genesis_hash: Option<[u8; 32]>,
    #[serde(default)]
    multisig_accounts: Vec<MultisigAccountRecordV8>,
    #[serde(default)]
    local_note_openings: Vec<LocalNoteOpeningRecordV8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MultisigAccountRecordV8 {
    public: MultisigAccountPublic,
    #[serde(with = "serde_bytes48")]
    policy_root: [u8; 48],
    threshold: u64,
    policy_signer_tags: [transaction_circuit::SmallwoodSignerTag; 2],
    #[serde(with = "serde_bytes32")]
    policy_commitment_randomness: [u8; 32],
    intents: Vec<MultisigIntentStateV8>,
    created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MultisigIntentStateV8 {
    #[serde(with = "serde_bytes48")]
    intent_digest: [u8; 48],
    #[serde(with = "serde_bytes48")]
    current_accumulator_note: [u8; 48],
    approval_count: u64,
    approved_slots: [u64; 2],
    approvals: Vec<crate::multisig::MultisigStoredApproval>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LocalNoteOpeningRecordV8 {
    #[serde(with = "serde_bytes48")]
    commitment: [u8; 48],
    note: RecoveredNote,
    #[serde(default)]
    multisig_accumulator: Option<LocalMultisigAccumulatorOpeningV8>,
    created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LocalMultisigAccumulatorOpeningV8 {
    #[serde(with = "serde_bytes32")]
    account_id: [u8; 32],
    #[serde(with = "serde_bytes48")]
    policy_root: [u8; 48],
    #[serde(with = "serde_bytes48")]
    intent_digest: [u8; 48],
    threshold: u64,
    approval_count: u64,
    approved_slots: [u64; 2],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletStateV7 {
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
    #[serde(default)]
    recent: Vec<RecentTransaction>,
    #[serde(with = "serde_vec_bytes48")]
    commitments: Vec<Commitment>,
    next_commitment_index: u64,
    next_ciphertext_index: u64,
    last_synced_height: u64,
    #[serde(default, with = "serde_option_bytes32")]
    last_synced_block_hash: Option<[u8; 32]>,
    #[serde(default)]
    outgoing_disclosures: Vec<OutgoingDisclosureRecord>,
    #[serde(default, with = "serde_option_bytes32")]
    genesis_hash: Option<[u8; 32]>,
    #[serde(default)]
    multisig_accounts: Vec<()>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletStateV6 {
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
    #[serde(default)]
    recent: Vec<RecentTransaction>,
    #[serde(with = "serde_vec_bytes48")]
    commitments: Vec<Commitment>,
    next_commitment_index: u64,
    next_ciphertext_index: u64,
    last_synced_height: u64,
    #[serde(default, with = "serde_option_bytes32")]
    last_synced_block_hash: Option<[u8; 32]>,
    #[serde(default)]
    outgoing_disclosures: Vec<OutgoingDisclosureRecord>,
    #[serde(default, with = "serde_option_bytes32")]
    genesis_hash: Option<[u8; 32]>,
}

impl From<WalletStateV6> for WalletState {
    fn from(value: WalletStateV6) -> Self {
        Self {
            mode: value.mode,
            tree_depth: value.tree_depth,
            root_secret: value.root_secret,
            derived: value.derived,
            incoming: value.incoming,
            full_viewing_key: value.full_viewing_key,
            outgoing: value.outgoing,
            next_address_index: value.next_address_index,
            notes: value.notes,
            pending: value.pending,
            recent: value.recent,
            commitments: value.commitments,
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: value.outgoing_disclosures,
            genesis_hash: value.genesis_hash,
            multisig_accounts: Vec::new(),
            local_note_openings: Vec::new(),
        }
    }
}

impl From<WalletStateV8> for WalletState {
    fn from(value: WalletStateV8) -> Self {
        let local_note_openings = value
            .local_note_openings
            .into_iter()
            .filter(|opening| opening.multisig_accumulator.is_none())
            .map(|opening| LocalNoteOpeningRecord {
                commitment: opening.commitment,
                note: opening.note,
                multisig_accumulator: None,
                multisig_value_lock: None,
                created_at: opening.created_at,
            })
            .collect();
        Self {
            mode: value.mode,
            tree_depth: value.tree_depth,
            root_secret: value.root_secret,
            derived: value.derived,
            incoming: value.incoming,
            full_viewing_key: value.full_viewing_key,
            outgoing: value.outgoing,
            next_address_index: value.next_address_index,
            notes: value.notes,
            pending: value.pending,
            recent: value.recent,
            commitments: value.commitments,
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: value.outgoing_disclosures,
            genesis_hash: value.genesis_hash,
            multisig_accounts: Vec::new(),
            local_note_openings,
        }
    }
}

impl From<WalletStateV7> for WalletState {
    fn from(value: WalletStateV7) -> Self {
        Self {
            mode: value.mode,
            tree_depth: value.tree_depth,
            root_secret: value.root_secret,
            derived: value.derived,
            incoming: value.incoming,
            full_viewing_key: value.full_viewing_key,
            outgoing: value.outgoing,
            next_address_index: value.next_address_index,
            notes: value.notes,
            pending: value.pending,
            recent: value.recent,
            commitments: value.commitments,
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: value.outgoing_disclosures,
            genesis_hash: value.genesis_hash,
            multisig_accounts: Vec::new(),
            local_note_openings: Vec::new(),
        }
    }
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
pub struct RecentTransaction {
    #[serde(with = "serde_bytes32")]
    pub tx_id: [u8; 32],
    pub submitted_at: u64,
    pub mined_height: u64,
    #[serde(default)]
    pub recipients: Vec<TransferRecipient>,
    #[serde(default)]
    pub fee: u64,
}

impl RecentTransaction {
    pub fn confirmations(&self, latest_height: u64) -> u64 {
        latest_height.saturating_sub(self.mined_height) + 1
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalNoteOpeningRecord {
    #[serde(with = "serde_bytes48")]
    pub commitment: [u8; 48],
    pub note: RecoveredNote,
    #[serde(default)]
    pub multisig_accumulator: Option<LocalMultisigAccumulatorOpening>,
    #[serde(default)]
    pub multisig_value_lock: Option<LocalMultisigValueLockOpening>,
    pub created_at: u64,
}

impl LocalNoteOpeningRecord {
    fn uses_private_auth(&self) -> bool {
        self.multisig_accumulator.is_some() || self.multisig_value_lock.is_some()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalMultisigValueLockOpening {
    #[serde(with = "serde_bytes32")]
    pub account_id: [u8; 32],
    #[serde(with = "serde_bytes48")]
    pub policy_root: [u8; 48],
    #[serde(with = "serde_bytes48")]
    pub intent_digest: [u8; 48],
    #[serde(default)]
    pub final_plan_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalMultisigAccumulatorOpening {
    #[serde(with = "serde_bytes32")]
    pub account_id: [u8; 32],
    #[serde(with = "serde_bytes48")]
    pub policy_root: [u8; 48],
    #[serde(with = "serde_bytes48")]
    pub intent_digest: [u8; 48],
    pub threshold: u64,
    pub signer_count: u64,
    pub approval_count: u64,
    pub approved_slots: [u64; transaction_circuit::SMALLWOOD_MULTISIG_MAX_SIGNERS],
}

impl LocalMultisigAccumulatorOpening {
    pub fn to_smallwood(&self) -> transaction_circuit::SmallwoodAccumulatorAuthOpening {
        transaction_circuit::SmallwoodAccumulatorAuthOpening {
            policy_root: self.policy_root,
            intent_digest: self.intent_digest,
            threshold: self.threshold,
            signer_count: self.signer_count,
            approval_count: self.approval_count,
            approved_slots: self.approved_slots,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SpendableNote {
    pub index: usize,
    pub recovered: RecoveredNote,
    pub position: u64,
}

#[derive(Clone, Debug)]
pub struct TrackedNoteView {
    pub note: RecoveredNote,
    pub position: u64,
    pub ciphertext_index: u64,
    pub nullifier: Option<[u8; 48]>,
    pub spent: bool,
    pub pending_spend: bool,
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
        wrapped
            .into_iter()
            .map(|buf| {
                let data = buf.into_vec();
                if data.len() != 48 {
                    return Err(serde::de::Error::custom("expected 48 bytes"));
                }
                let mut out = [0u8; 48];
                out.copy_from_slice(&data);
                Ok(out)
            })
            .collect()
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
    use crate::notes::MemoPlaintext;
    use crate::notes::NoteCiphertext;
    use crate::notes::NotePlaintext;
    use rand::{rngs::StdRng, SeedableRng};
    use tempfile::tempdir;
    use transaction_circuit::hashing_pq::{ciphertext_hash_bytes, felts_to_bytes48};

    #[derive(Debug, PartialEq, Eq)]
    struct PublicCiphertextProjection {
        version: u8,
        crypto_suite: u16,
        diversifier_index: u32,
        kem_ciphertext_len: usize,
        note_payload_len: usize,
        memo_payload_len: usize,
        chain_bytes: Vec<u8>,
        da_bytes: Vec<u8>,
        da_hash: [u8; 48],
    }

    fn public_ciphertext_projection(ciphertext: &NoteCiphertext) -> PublicCiphertextProjection {
        let da_bytes = ciphertext.to_da_bytes().unwrap();
        PublicCiphertextProjection {
            version: ciphertext.version,
            crypto_suite: ciphertext.crypto_suite,
            diversifier_index: ciphertext.diversifier_index,
            kem_ciphertext_len: ciphertext.kem_ciphertext.len(),
            note_payload_len: ciphertext.note_payload.len(),
            memo_payload_len: ciphertext.memo_payload.len(),
            chain_bytes: ciphertext.to_chain_bytes().unwrap(),
            da_hash: ciphertext_hash_bytes(&da_bytes),
            da_bytes,
        }
    }

    #[test]
    fn multisig_account_public_projection_hides_policy_shape() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let local_signer = store.local_multisig_signer_tag().unwrap();
        let other_signer = crate::multisig::signer_tag_from_spend_key(&[9u8; 32]);
        let public = store
            .create_multisig_account(2, vec![local_signer, other_signer])
            .unwrap();
        assert_eq!(store.multisig_accounts().unwrap(), vec![public.clone()]);
        let record = store
            .multisig_account_record(&public.account_id)
            .unwrap()
            .unwrap();
        assert_eq!(record.threshold, 2);
        assert_eq!(record.signer_count, 2);
        assert_eq!(
            record.policy_signer_tags.len(),
            transaction_circuit::SMALLWOOD_MULTISIG_MAX_SIGNERS
        );
        assert_eq!(
            record.public.approval_proof_hook,
            crate::multisig::REAL_APPROVAL_PROOF_HOOK
        );

        let public_json = serde_json::to_string(&public).unwrap();
        assert!(!public_json.contains("threshold"));
        assert!(!public_json.contains("signer"));
        assert!(!public_json.contains("policyRoot"));
        assert!(!public_json.contains("approvalCount"));
        assert!(!public_json.contains("approvalNullifier"));
    }

    #[test]
    fn wallet_state_v6_migrates_to_empty_multisig_accounts() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let legacy = store
            .with_state(|state| {
                Ok(WalletStateV6 {
                    mode: state.mode,
                    tree_depth: state.tree_depth,
                    root_secret: state.root_secret,
                    derived: state.derived.clone(),
                    incoming: state.incoming.clone(),
                    full_viewing_key: state.full_viewing_key.clone(),
                    outgoing: state.outgoing.clone(),
                    next_address_index: state.next_address_index,
                    notes: state.notes.clone(),
                    pending: state.pending.clone(),
                    recent: state.recent.clone(),
                    commitments: state.commitments.clone(),
                    next_commitment_index: state.next_commitment_index,
                    next_ciphertext_index: state.next_ciphertext_index,
                    last_synced_height: state.last_synced_height,
                    last_synced_block_hash: state.last_synced_block_hash,
                    outgoing_disclosures: state.outgoing_disclosures.clone(),
                    genesis_hash: state.genesis_hash,
                })
            })
            .unwrap();
        let plaintext = bincode::serialize(&legacy).unwrap();
        let migrated = deserialize_wallet_state_v6(&plaintext).unwrap();
        assert!(migrated.multisig_accounts.is_empty());
    }

    fn accumulator_ciphertext_fixture(
        store: &WalletStore,
        pk_auth: [u8; 32],
        seed: u64,
    ) -> (NoteCiphertext, RecoveredNote, [u8; 48]) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut address = store.primary_address().unwrap();
        address.pk_auth = pk_auth;
        let note = NotePlaintext::random(0, 0, MemoPlaintext::default(), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        let note_data = note.to_note_data(address.pk_recipient, pk_auth);
        let commitment = felts_to_bytes48(&note_data.commitment());
        (
            ciphertext,
            RecoveredNote {
                diversifier_index: address.diversifier_index,
                note,
                note_data,
                address,
            },
            commitment,
        )
    }

    #[test]
    fn local_accumulator_opening_reconciles_exact_chain_commitment_without_wallet_nullifier() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let (ciphertext, opening, commitment) =
            accumulator_ciphertext_fixture(&store, [42u8; 32], 41);
        store.append_commitments(&[(0, commitment)]).unwrap();
        store.record_local_note_opening(opening.clone()).unwrap();
        let decrypted = store
            .full_viewing_key()
            .unwrap()
            .unwrap()
            .decrypt_note(&ciphertext)
            .unwrap();

        assert_eq!(
            store
                .apply_ciphertext_batch(0, vec![Some(decrypted)])
                .unwrap(),
            1
        );
        let notes = store.tracked_notes().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].note.note_data.pk_auth, [42u8; 32]);
        assert_eq!(notes[0].nullifier, None);
    }

    #[test]
    fn local_accumulator_opening_rehydrates_after_rescan_without_decryptable_ciphertext() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let (_ciphertext, opening, commitment) =
            accumulator_ciphertext_fixture(&store, [45u8; 32], 45);
        store.record_local_note_opening(opening).unwrap();
        store.reset_sync_state().unwrap();
        store.append_commitments(&[(0, commitment)]).unwrap();

        assert_eq!(store.apply_ciphertext_batch(0, vec![None]).unwrap(), 1);
        let notes = store.tracked_notes().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].position, 0);
        assert_eq!(notes[0].ciphertext_index, 0);
        assert_eq!(notes[0].note.note_data.pk_auth, [45u8; 32]);
        assert_eq!(notes[0].nullifier, None);
    }

    #[test]
    fn local_accumulator_opening_rejects_wrong_stored_pk_auth_even_if_commitment_field_is_tampered()
    {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let (ciphertext, _correct_opening, commitment) =
            accumulator_ciphertext_fixture(&store, [42u8; 32], 42);
        let (_, wrong_opening, _) = accumulator_ciphertext_fixture(&store, [43u8; 32], 42);
        store.append_commitments(&[(0, commitment)]).unwrap();
        store.record_local_note_opening(wrong_opening).unwrap();
        store
            .with_mut(|state| {
                state.local_note_openings[0].commitment = commitment;
                Ok(())
            })
            .unwrap();
        let decrypted = store
            .full_viewing_key()
            .unwrap()
            .unwrap()
            .decrypt_note(&ciphertext)
            .unwrap();

        let err = store
            .apply_ciphertext_batch(0, vec![Some(decrypted)])
            .unwrap_err();
        assert!(err.to_string().contains("ciphertext commitment mismatch"));
        assert!(store.tracked_notes().unwrap().is_empty());
    }

    #[test]
    fn local_accumulator_opening_rejects_wrong_chain_commitment() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let (ciphertext, opening, mut commitment) =
            accumulator_ciphertext_fixture(&store, [44u8; 32], 43);
        store.record_local_note_opening(opening).unwrap();
        commitment[0] ^= 1;
        store.append_commitments(&[(0, commitment)]).unwrap();
        let decrypted = store
            .full_viewing_key()
            .unwrap()
            .unwrap()
            .decrypt_note(&ciphertext)
            .unwrap();

        let err = store
            .apply_ciphertext_batch(0, vec![Some(decrypted)])
            .unwrap_err();
        assert!(err.to_string().contains("ciphertext commitment mismatch"));
        assert!(store.tracked_notes().unwrap().is_empty());
    }

    #[test]
    fn imported_multisig_opening_rejects_unknown_account_before_tracking() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let (_ciphertext, recovered, commitment) =
            accumulator_ciphertext_fixture(&store, [42u8; 32], 141);
        store.append_commitments(&[(0, commitment)]).unwrap();
        let opening = LocalNoteOpeningRecord {
            commitment,
            note: recovered,
            multisig_accumulator: Some(LocalMultisigAccumulatorOpening {
                account_id: [9u8; 32],
                policy_root: [8u8; 48],
                intent_digest: [7u8; 48],
                threshold: 1,
                signer_count: 1,
                approval_count: 0,
                approved_slots: [0; transaction_circuit::SMALLWOOD_MULTISIG_MAX_SIGNERS],
            }),
            multisig_value_lock: None,
            created_at: 0,
        };

        let err = store
            .import_local_note_opening_record(opening, 0, 0)
            .expect_err("unknown-account multisig opening import must fail");
        assert!(err.to_string().contains("unknown multisig account"));
        assert!(store.local_note_openings().unwrap().is_empty());
        assert!(store.tracked_notes().unwrap().is_empty());
    }

    #[test]
    fn imported_multisig_opening_rejects_wrong_auth_key_before_tracking() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let local_signer = store.local_multisig_signer_tag().unwrap();
        let account = store
            .create_multisig_account(1, vec![local_signer])
            .unwrap();
        let record = store
            .multisig_account_record(&account.account_id)
            .unwrap()
            .unwrap();
        let (_ciphertext, recovered, commitment) =
            accumulator_ciphertext_fixture(&store, [42u8; 32], 142);
        store.append_commitments(&[(0, commitment)]).unwrap();
        let opening = LocalNoteOpeningRecord {
            commitment,
            note: recovered,
            multisig_accumulator: Some(LocalMultisigAccumulatorOpening {
                account_id: record.public.account_id,
                policy_root: record.policy_root,
                intent_digest: [6u8; 48],
                threshold: record.threshold,
                signer_count: record.signer_count,
                approval_count: 0,
                approved_slots: [0; transaction_circuit::SMALLWOOD_MULTISIG_MAX_SIGNERS],
            }),
            multisig_value_lock: None,
            created_at: 0,
        };

        let err = store
            .import_local_note_opening_record(opening, 0, 0)
            .expect_err("wrong-auth multisig opening import must fail");
        assert!(err.to_string().contains("auth key mismatch"));
        assert!(store.local_note_openings().unwrap().is_empty());
        assert!(store.tracked_notes().unwrap().is_empty());
    }

    #[test]
    fn ordinary_note_reconciliation_still_assigns_wallet_nullifier() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let mut rng = StdRng::seed_from_u64(44);
        let address = store.primary_address().unwrap();
        let note = NotePlaintext::random(10, 0, MemoPlaintext::default(), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        let recovered = store
            .full_viewing_key()
            .unwrap()
            .unwrap()
            .decrypt_note(&ciphertext)
            .unwrap();
        let commitment = felts_to_bytes48(&recovered.note_data.commitment());
        store.append_commitments(&[(0, commitment)]).unwrap();

        assert_eq!(
            store
                .apply_ciphertext_batch(0, vec![Some(recovered)])
                .unwrap(),
            1
        );
        let notes = store.tracked_notes().unwrap();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].nullifier.is_some());
        assert_eq!(notes[0].note.note_data.pk_auth, address.pk_auth);
    }

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

    #[cfg(unix)]
    #[test]
    fn wallet_file_is_created_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        drop(store);

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn private_file_writer_replaces_permissive_files_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("secret-export.json");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_private_file(&path, b"new secret").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new secret");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn private_append_file_is_created_private_on_unix() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("credits.jsonl");
        {
            let mut file = open_private_append_file(&path).unwrap();
            writeln!(file, "{{\"ok\":true}}").unwrap();
        }

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn wallet_file_rejects_trailing_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        drop(store);

        let mut bytes = fs::read(&path).unwrap();
        bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        fs::write(&path, bytes).unwrap();

        let err = WalletStore::open(&path, "passphrase")
            .expect_err("wallet file with trailing bytes must fail closed");
        assert!(matches!(err, WalletError::Serialization(_)));
    }

    #[test]
    fn wallet_state_rejects_trailing_bytes() {
        let state = WalletState {
            mode: WalletMode::WatchOnly,
            tree_depth: DEFAULT_TREE_DEPTH,
            root_secret: None,
            derived: None,
            incoming: IncomingViewingKey::from_keys(&RootSecret::from_bytes([7u8; 32]).derive()),
            full_viewing_key: None,
            outgoing: None,
            next_address_index: 0,
            notes: Vec::new(),
            pending: Vec::new(),
            recent: Vec::new(),
            commitments: Vec::new(),
            next_commitment_index: 0,
            next_ciphertext_index: 0,
            last_synced_height: 0,
            last_synced_block_hash: None,
            outgoing_disclosures: Vec::new(),
            genesis_hash: None,
            multisig_accounts: Vec::new(),
            local_note_openings: Vec::new(),
        };
        let mut bytes = bincode::serialize(&state).unwrap();
        bytes.push(0xff);
        let err = deserialize_wallet_state(&bytes)
            .expect_err("wallet state with trailing bytes must fail closed");
        assert!(matches!(err, WalletError::Serialization(_)));
    }

    #[test]
    fn wallet_state_rejects_malformed_commitment_bytes() {
        #[allow(dead_code)]
        #[derive(Debug, Deserialize)]
        struct CommitmentVecProbe(#[serde(with = "serde_vec_bytes48")] Vec<[u8; 48]>);

        let malformed = vec![serde_bytes::ByteBuf::from(vec![0u8; 47])];
        let bytes = bincode::serialize(&malformed).unwrap();
        let err = bincode::deserialize::<CommitmentVecProbe>(&bytes)
            .expect_err("malformed wallet commitments must fail closed");
        assert!(err.to_string().contains("expected 48 bytes"));
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
    fn mined_transactions_move_from_pending_to_recent_history() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let ivk = store.incoming_key().unwrap();
        let address = ivk.shielded_address(0).unwrap();
        let mut rng = StdRng::seed_from_u64(17);

        let note = NotePlaintext::random(25, 0, MemoPlaintext::default(), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        let recovered = ivk.decrypt_note(&ciphertext).unwrap();
        let commitment = felts_to_bytes48(&recovered.note_data.commitment());

        store.append_commitments(&[(0, commitment)]).unwrap();
        store.register_ciphertext_index(0).unwrap();
        store.record_recovered_note(recovered, 0, 0).unwrap();

        let note_index = store.spendable_notes(0).unwrap()[0].index;
        let nullifier = store
            .tracked_notes()
            .unwrap()
            .into_iter()
            .find(|note| note.position == 0)
            .and_then(|note| note.nullifier)
            .expect("tracked note nullifier");

        store.mark_notes_pending(&[note_index], true).unwrap();
        store
            .record_pending_submission(
                [9u8; 32],
                vec![nullifier],
                vec![note_index],
                vec![TransferRecipient {
                    address: "test".to_string(),
                    value: 25,
                    asset_id: 0,
                    memo: None,
                }],
                0,
            )
            .unwrap();

        let mut chain_nullifiers = HashSet::new();
        chain_nullifiers.insert(nullifier);
        store.refresh_pending(7, &chain_nullifiers).unwrap();

        assert!(store.pending_transactions().unwrap().is_empty());
        let recent = store.recent_transactions().unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].tx_id, [9u8; 32]);
        assert_eq!(recent[0].mined_height, 7);
        assert_eq!(recent[0].confirmations(9), 3);
    }

    #[test]
    fn local_wallet_bookkeeping_does_not_change_public_ciphertext_projection() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let ivk = store.incoming_key().unwrap();
        let address = ivk.shielded_address(0).unwrap();
        let mut rng = StdRng::seed_from_u64(73);

        let note = NotePlaintext::random(
            37,
            0,
            MemoPlaintext::new(b"observer projection".to_vec()),
            &mut rng,
        );
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        let recovered = ivk.decrypt_note(&ciphertext).unwrap();
        let commitment = felts_to_bytes48(&recovered.note_data.commitment());
        let before = public_ciphertext_projection(&ciphertext);
        let pre_bookkeeping_bundle = crate::rpc::TransactionBundle::new(
            vec![0xaa],
            vec![],
            vec![commitment],
            std::slice::from_ref(&ciphertext),
            [0x11; 48],
            [0x22; 64],
            [0, u64::MAX, u64::MAX, u64::MAX],
            0,
            0,
            transaction_circuit::StablecoinPolicyBinding::default(),
        )
        .unwrap();

        store.set_last_synced_height(123).unwrap();
        store.set_last_synced_block_hash([0x33; 32]).unwrap();
        store.set_genesis_hash([0x44; 32]).unwrap();
        store.append_commitments(&[(0, commitment)]).unwrap();
        assert_eq!(
            store
                .apply_ciphertext_batch(0, vec![Some(recovered)])
                .unwrap(),
            1
        );
        assert_eq!(
            store.apply_ciphertext_batch(1, vec![None, None]).unwrap(),
            0
        );
        let note_index = store.spendable_notes(0).unwrap()[0].index;
        let nullifier = store.tracked_notes().unwrap()[0]
            .nullifier
            .expect("tracked full wallet note has a nullifier");
        store.mark_notes_pending(&[note_index], true).unwrap();
        store
            .record_pending_submission(
                [0x55; 32],
                vec![nullifier],
                vec![note_index],
                vec![TransferRecipient {
                    address: "local-only recipient label".to_string(),
                    value: 37,
                    asset_id: 0,
                    memo: Some("local-only memo".to_string()),
                }],
                1,
            )
            .unwrap();

        assert_eq!(store.last_synced_height().unwrap(), 123);
        assert_eq!(store.next_ciphertext_index().unwrap(), 3);
        assert_eq!(store.pending_transactions().unwrap().len(), 1);

        let after = public_ciphertext_projection(&ciphertext);
        assert_eq!(after, before);

        let post_bookkeeping_bundle = crate::rpc::TransactionBundle::new(
            vec![0xbb],
            vec![],
            vec![commitment],
            std::slice::from_ref(&ciphertext),
            [0x66; 48],
            [0x77; 64],
            [0, u64::MAX, u64::MAX, u64::MAX],
            1,
            0,
            transaction_circuit::StablecoinPolicyBinding::default(),
        )
        .unwrap();
        assert_eq!(
            pre_bookkeeping_bundle.ciphertexts, post_bookkeeping_bundle.ciphertexts,
            "wallet-local scan cursors, sync metadata, and pending bookkeeping must not enter chain ciphertext bytes"
        );

        let decoded = post_bookkeeping_bundle.decode_notes().unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(public_ciphertext_projection(&decoded[0]), before);
    }

    #[test]
    fn local_address_metadata_does_not_change_public_ciphertext_projection() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let ivk = store.incoming_key().unwrap();
        let address = store.primary_address().unwrap();
        let mut rng = StdRng::seed_from_u64(117);

        let note = NotePlaintext::random(
            41,
            0,
            MemoPlaintext::new(b"address metadata projection".to_vec()),
            &mut rng,
        );
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        let recovered = ivk.decrypt_note(&ciphertext).unwrap();
        let commitment = felts_to_bytes48(&recovered.note_data.commitment());
        let before = public_ciphertext_projection(&ciphertext);
        let pre_address_metadata_bundle = crate::rpc::TransactionBundle::new(
            vec![0x31],
            vec![],
            vec![commitment],
            std::slice::from_ref(&ciphertext),
            [0x32; 48],
            [0x33; 64],
            [0, u64::MAX, u64::MAX, u64::MAX],
            0,
            0,
            transaction_circuit::StablecoinPolicyBinding::default(),
        )
        .unwrap();

        assert_eq!(
            store
                .with_state(|state| Ok(state.next_address_index))
                .unwrap(),
            0
        );
        let external_address = store.next_address().unwrap();
        let internal_address = store.reserve_internal_address().unwrap();
        let next_external_address = store.next_address().unwrap();
        assert_ne!(external_address.pk_recipient, internal_address.pk_recipient);
        assert_ne!(
            internal_address.pk_recipient,
            next_external_address.pk_recipient
        );
        assert_eq!(
            store
                .with_state(|state| Ok(state.next_address_index))
                .unwrap(),
            3
        );

        drop(store);
        let reopened = WalletStore::open(&path, "passphrase").unwrap();
        assert_eq!(
            reopened
                .with_state(|state| Ok(state.next_address_index))
                .unwrap(),
            3
        );
        let post_reopen_address = reopened.next_address().unwrap();
        assert_ne!(
            next_external_address.pk_recipient,
            post_reopen_address.pk_recipient
        );
        assert_eq!(
            reopened
                .with_state(|state| Ok(state.next_address_index))
                .unwrap(),
            4
        );

        let after = public_ciphertext_projection(&ciphertext);
        assert_eq!(after, before);

        let post_address_metadata_bundle = crate::rpc::TransactionBundle::new(
            vec![0x34],
            vec![],
            vec![commitment],
            std::slice::from_ref(&ciphertext),
            [0x35; 48],
            [0x36; 64],
            [0, u64::MAX, u64::MAX, u64::MAX],
            1,
            0,
            transaction_circuit::StablecoinPolicyBinding::default(),
        )
        .unwrap();
        assert_eq!(
            pre_address_metadata_bundle.ciphertexts, post_address_metadata_bundle.ciphertexts,
            "wallet-local address cursor metadata must not enter chain ciphertext bytes"
        );

        let decoded = post_address_metadata_bundle.decode_notes().unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(public_ciphertext_projection(&decoded[0]), before);
    }

    #[test]
    fn recovered_note_uses_ciphertext_index_as_position() {
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

        let recovered = vec![None, Some(rec_b)];
        let added = store.apply_ciphertext_batch(0, recovered).unwrap();
        assert_eq!(added, 1);

        let notes = store.spendable_notes(0).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].position, 1);
    }

    #[test]
    fn apply_ciphertext_batch_rejects_decrypted_note_missing_commitment() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let ivk = store.incoming_key().unwrap();
        let address = ivk.shielded_address(0).unwrap();
        let mut rng = StdRng::seed_from_u64(123);

        let note = NotePlaintext::random(10, 0, MemoPlaintext::default(), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        let recovered = ivk.decrypt_note(&ciphertext).unwrap();

        // No commitment exists at the ciphertext index, so accepting this note would advance past
        // an unverifiable archive row.
        let err = store
            .apply_ciphertext_batch(0, vec![Some(recovered)])
            .unwrap_err();
        assert!(matches!(
            err,
            WalletError::InvalidState("ciphertext commitment missing")
        ));
        assert_eq!(store.next_ciphertext_index().unwrap(), 0);
        assert!(store.spendable_notes(0).unwrap().is_empty());
    }

    #[test]
    fn apply_ciphertext_batch_rejects_substituted_decrypted_note() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let ivk = store.incoming_key().unwrap();
        let address = ivk.shielded_address(0).unwrap();
        let mut rng = StdRng::seed_from_u64(124);

        let note_a = NotePlaintext::random(10, 0, MemoPlaintext::default(), &mut rng);
        let ciphertext_a = NoteCiphertext::encrypt(&address, &note_a, &mut rng).unwrap();
        let recovered_a = ivk.decrypt_note(&ciphertext_a).unwrap();
        let commitment_a = felts_to_bytes48(&recovered_a.note_data.commitment());

        let note_b = NotePlaintext::random(20, 0, MemoPlaintext::default(), &mut rng);
        let ciphertext_b = NoteCiphertext::encrypt(&address, &note_b, &mut rng).unwrap();
        let recovered_b = ivk.decrypt_note(&ciphertext_b).unwrap();
        let commitment_b = felts_to_bytes48(&recovered_b.note_data.commitment());

        store
            .append_commitments(&[(0, commitment_a), (1, commitment_b)])
            .unwrap();

        let err = store
            .apply_ciphertext_batch(0, vec![Some(recovered_b)])
            .unwrap_err();
        assert!(matches!(
            err,
            WalletError::InvalidState("ciphertext commitment mismatch")
        ));
        assert_eq!(store.next_ciphertext_index().unwrap(), 0);
        assert!(store.spendable_notes(0).unwrap().is_empty());
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

    #[test]
    fn validate_notes_internal_consistency_rejects_plaintext_mismatch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let ivk = store.incoming_key().unwrap();
        let address = store.primary_address().unwrap();
        let mut rng = StdRng::seed_from_u64(12);

        let note = NotePlaintext::random(10, 0, MemoPlaintext::default(), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        let recovered = ivk.decrypt_note(&ciphertext).unwrap();
        let commitment = felts_to_bytes48(&recovered.note_data.commitment());

        store.append_commitments(&[(0, commitment)]).unwrap();
        store.register_ciphertext_index(0).unwrap();
        store.record_recovered_note(recovered, 0, 0).unwrap();

        store
            .with_mut(|state| {
                state.notes[0].note.note.rho[0] ^= 1;
                Ok(())
            })
            .unwrap();

        assert!(store.validate_notes_internal_consistency().is_err());
    }
}
