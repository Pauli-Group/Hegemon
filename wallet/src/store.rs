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
use transaction_circuit::hashing::Felt;

use crate::address::ShieldedAddress;
use crate::error::WalletError;
use crate::keys::{DerivedKeys, RootSecret};
use crate::viewing::{FullViewingKey, IncomingViewingKey, OutgoingViewingKey, RecoveredNote};

const FILE_VERSION: u32 = 1;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
/// Default tree depth - must match CIRCUIT_MERKLE_DEPTH in transaction-circuit.
const DEFAULT_TREE_DEPTH: u32 = 8;

#[derive(Debug)]
pub struct WalletStore {
    path: PathBuf,
    key: [u8; KEY_LEN],
    salt: [u8; SALT_LEN],
    state: Mutex<WalletState>,
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
        if file.version != FILE_VERSION {
            return Err(WalletError::Serialization(
                "unsupported wallet file version".into(),
            ));
        }
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
        let state: WalletState = bincode::deserialize(&plaintext)?;
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

    pub fn append_commitments(&self, entries: &[(u64, u64)]) -> Result<(), WalletError> {
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

    pub fn mark_nullifiers(&self, nullifiers: &HashSet<[u8; 32]>) -> Result<usize, WalletError> {
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

    pub fn commitment_tree(&self) -> Result<CommitmentTree, WalletError> {
        self.with_state(|state| {
            let depth = state.tree_depth as usize;
            let mut tree = CommitmentTree::new(depth)
                .map_err(|_| WalletError::InvalidState("invalid tree depth"))?;
            for value in &state.commitments {
                let _ = tree
                    .append(Felt::new(*value))
                    .map_err(|_| WalletError::InvalidState("tree overflow"))?;
            }
            Ok(tree)
        })
    }

    pub fn pending_transactions(&self) -> Result<Vec<PendingTransaction>, WalletError> {
        self.with_state(|state| Ok(state.pending.clone()))
    }

    pub fn record_pending_submission(
        &self,
        tx_id: [u8; 32],
        nullifiers: Vec<[u8; 32]>,
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
        nullifiers: &HashSet<[u8; 32]>,
    ) -> Result<(), WalletError> {
        self.with_mut(|state| {
            for tx in &mut state.pending {
                if matches!(tx.status, PendingStatus::Mined { .. }) {
                    continue;
                }
                if tx.nullifiers.iter().all(|nf| nullifiers.contains(nf)) {
                    tx.status = PendingStatus::Mined {
                        height: latest_height,
                    };
                    for &idx in &tx.spent_note_indexes {
                        if let Some(note) = state.notes.get_mut(idx) {
                            note.spent = true;
                            note.pending_spend = false;
                        }
                    }
                }
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
        let tmp = self.path.with_extension("tmp");
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
    commitments: Vec<u64>,
    next_commitment_index: u64,
    next_ciphertext_index: u64,
    last_synced_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TrackedNote {
    note: RecoveredNote,
    position: u64,
    ciphertext_index: u64,
    #[serde(with = "serde_option_bytes32")]
    nullifier: Option<[u8; 32]>,
    spent: bool,
    pending_spend: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingTransaction {
    #[serde(with = "serde_bytes32")]
    pub tx_id: [u8; 32],
    #[serde(with = "serde_vec_bytes32")]
    pub nullifiers: Vec<[u8; 32]>,
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

mod serde_vec_bytes32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(values: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let wrapped: Vec<_> = values
            .iter()
            .map(|bytes| serde_bytes::Bytes::new(bytes))
            .collect();
        wrapped.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wrapped: Vec<serde_bytes::ByteBuf> = Vec::deserialize(deserializer)?;
        Ok(wrapped
            .into_iter()
            .map(|buf| {
                let data = buf.into_vec();
                let mut out = [0u8; 32];
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
    use rand::{rngs::StdRng, SeedableRng};
    use tempfile::tempdir;

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
        assert_ne!(addr1.address_tag, addr2.address_tag);
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
        store
            .append_commitments(&[(0, recovered.note_data.commitment().as_int())])
            .unwrap();
        store.register_ciphertext_index(0).unwrap();
        store
            .record_recovered_note(recovered.clone(), 0, 0)
            .unwrap();
        let notes = store.spendable_notes(0).unwrap();
        assert_eq!(notes.len(), 1);
        store.mark_notes_pending(&[notes[0].index], true).unwrap();
        assert!(store.spendable_notes(0).unwrap().is_empty());
    }
}
