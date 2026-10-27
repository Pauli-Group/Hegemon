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
use fs2::FileExt;
use hegemon_hash384::ActionId48;
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
use crate::poseidon2_v8_sync::{
    Poseidon2V8CanonicalBlock, Poseidon2V8CanonicalTip, Poseidon2V8OwnedNoteView,
    Poseidon2V8SpendContext, Poseidon2V8SyncDelta, Poseidon2V8WalletState,
};
use crate::submission::ProvisionalActionId48;
use crate::tx_builder::PreparedMultisigFinalPlan;
use crate::viewing::{FullViewingKey, IncomingViewingKey, OutgoingViewingKey, RecoveredNote};

#[path = "asset_recovery_store.rs"]
pub mod asset_recovery_store;

#[path = "asset_spend_store.rs"]
pub mod asset_spend_store;

#[path = "htlc_store.rs"]
pub(crate) mod htlc_store;

#[path = "poseidon2_v8_reservations.rs"]
mod poseidon2_v8_reservations;
#[path = "private_spend_journal.rs"]
pub(crate) mod private_spend_journal;
use poseidon2_v8_reservations::StoredPoseidon2V8Reservation;
pub use poseidon2_v8_reservations::{
    Poseidon2V8ReservationStatus, Poseidon2V8ReservationView, Poseidon2V8SpendReservation,
};
pub use private_spend_journal::{PrivateSpendAttemptStatus, PrivateSpendAttemptView};
#[path = "private_spend_balance.rs"]
mod private_spend_balance;
pub use private_spend_balance::{BalanceAmount, PrivateSpendBalance};

/// V13 added treasury state, V14 added RP06 candidates, and V15 stores private
/// per-output encryption witnesses. Earlier positional bincode schemas remain frozen.
// V20 adds recovery holder records; V18 added reward maturity and V19 controlled-asset
// notes and the submission journal. Older positional codecs remain frozen and
// may only be read or explicitly recovered into a separate fresh wallet.
const FILE_VERSION: u32 = 20;
const LEGACY_FILE_VERSION_V19: u32 = 19;
const LEGACY_FILE_VERSION_V18: u32 = 18;
const LEGACY_FILE_VERSION_V17: u32 = 17;
const LEGACY_FILE_VERSION_V16: u32 = 16;
const LEGACY_FILE_VERSION_V15: u32 = 15;
const LEGACY_FILE_VERSION_V14: u32 = 14;
const LEGACY_FILE_VERSION_V13: u32 = 13;
const LEGACY_FILE_VERSION_V12: u32 = 12;
const LEGACY_FILE_VERSION_V11: u32 = 11;
const LEGACY_FILE_VERSION_V10: u32 = 10;
const LEGACY_FILE_VERSION_V9: u32 = 9;
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
    /// A stable sibling inode: wallet writes replace the encrypted file.
    _file_lock: Option<fs::File>,
    read_only: bool,
    source_file_version: u32,
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
    pub fn launch_context(
        &self,
    ) -> Result<crate::poseidon2_v8_sync::LaunchWalletContext, WalletError> {
        self.with_state(|state| {
            state
                .native_launch_context
                .as_ref()
                .ok_or(WalletError::InvalidState(
                    "wallet launch context is not pinned",
                ))?
                .current_context()
        })
    }
    pub fn launch_chain_id(&self) -> Result<[u8; 32], WalletError> {
        Ok(self.launch_context()?.chain_id())
    }
    pub fn require_launch_context(
        &self,
        context: crate::poseidon2_v8_sync::LaunchWalletContext,
    ) -> Result<(), WalletError> {
        self.with_state(|state| {
            state
                .native_launch_context
                .as_ref()
                .ok_or(WalletError::InvalidState(
                    "wallet launch context is not pinned",
                ))?
                .require_match(context)
        })
    }
    pub fn initialize_pinned_launch_context(
        &self,
        context: crate::poseidon2_v8_sync::LaunchWalletContext,
    ) -> Result<(), WalletError> {
        self.with_poseidon2_v8_mut_and_block(None, Some((context, true)), |_, _| Ok(()))
    }
    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub fn initialize_pinned_launch_context_for_retained_test(
        &self,
        context: crate::poseidon2_v8_sync::LaunchWalletContext,
    ) -> Result<(), WalletError> {
        self.with_poseidon2_v8_mut_and_block(None, Some((context, false)), |_, _| Ok(()))
    }
    pub(crate) fn with_rp06_transfers<T>(
        &self,
        context: crate::poseidon2_v8_sync::LaunchWalletContext,
        read: impl FnOnce(
            &[crate::rp06_transfer_store::StoredRp06TransferCandidate],
        ) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        self.with_state(|state| {
            state
                .native_launch_context
                .as_ref()
                .ok_or(WalletError::InvalidState(
                    "wallet launch context is not pinned",
                ))?
                .require_match(context)?;
            read(&state.native_rp06_transfers)
        })
    }

    pub(crate) fn with_rp06_transfers_mut<T>(
        &self,
        context: crate::poseidon2_v8_sync::LaunchWalletContext,
        mutate: impl FnOnce(
            &mut Vec<crate::rp06_transfer_store::StoredRp06TransferCandidate>,
        ) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        self.ensure_writable()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| WalletError::InvalidState("wallet poisoned"))?;
        state
            .native_launch_context
            .as_ref()
            .ok_or(WalletError::InvalidState(
                "wallet launch context is not pinned",
            ))?
            .require_match(context)?;
        let previous = state.native_rp06_transfers.clone();
        let result = match mutate(&mut state.native_rp06_transfers) {
            Ok(result) => result,
            Err(error) => {
                state.native_rp06_transfers = previous;
                return Err(error);
            }
        };
        if let Err(error) = validate_rp06_candidates(&state.native_rp06_transfers, context)
            .and_then(|()| self.write_state(&state))
        {
            state.native_rp06_transfers = previous;
            return Err(error);
        }
        Ok(result)
    }

    pub(crate) fn with_v8_treasuries<T>(
        &self,
        read: impl FnOnce(
            &[crate::poseidon2_v8_multisig::StoredV8Treasury],
            &Poseidon2V8WalletState,
        ) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        self.with_state(|state| read(&state.poseidon2_v8_treasuries, &state.poseidon2_v8))
    }

    pub(crate) fn with_v8_treasuries_mut<T>(
        &self,
        update: impl FnOnce(
            &mut Vec<crate::poseidon2_v8_multisig::StoredV8Treasury>,
            &Poseidon2V8WalletState,
            &HashSet<[u64; 7]>,
        ) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        self.ensure_writable()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| WalletError::InvalidState("wallet poisoned"))?;
        if state.mode != WalletMode::Full {
            return Err(WalletError::WatchOnly);
        }
        let reserved = state
            .reserved_ordinary_poseidon2_v8_nullifiers()
            .into_iter()
            .chain(state.htlc_reserved_nullifiers())
            .chain(state.private_spend_reserved_nullifiers())
            .chain(state.asset_spend_reserved_nullifiers())
            .chain(state.recovery_reserved_nullifiers())
            .collect();
        let previous = state.poseidon2_v8_treasuries.clone();
        let result = {
            let WalletState {
                poseidon2_v8_treasuries,
                poseidon2_v8,
                ..
            } = &mut *state;
            update(poseidon2_v8_treasuries, poseidon2_v8, &reserved)
        }
        .and_then(|value| {
            self.write_state(&state)?;
            Ok(value)
        });
        if result.is_err() {
            state.poseidon2_v8_treasuries = previous;
        }
        result
    }

    pub fn create_full<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Self, WalletError> {
        let mut rng = OsRng;
        let root = RootSecret::from_rng(&mut rng);
        Self::create_from_root(path, passphrase, root)
    }

    /// Create a new full wallet without replacing a store that already exists.
    /// The existence check is performed while holding the writer lock.
    pub fn create_full_if_missing<P: AsRef<Path>>(
        path: P,
        passphrase: &str,
    ) -> Result<Self, WalletError> {
        let mut rng = OsRng;
        let root = RootSecret::from_rng(&mut rng);
        Self::create_from_root_inner(path, passphrase, root, true)
    }

    pub fn create_from_root<P: AsRef<Path>>(
        path: P,
        passphrase: &str,
        root: RootSecret,
    ) -> Result<Self, WalletError> {
        Self::create_from_root_inner(path, passphrase, root, false)
    }

    fn create_from_root_inner<P: AsRef<Path>>(
        path: P,
        passphrase: &str,
        root: RootSecret,
        fail_if_exists: bool,
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
            commitment_sources: Vec::new(),
            next_commitment_index: 0,
            next_ciphertext_index: 0,
            last_synced_height: 0,
            last_synced_block_hash: None,
            outgoing_disclosures: Vec::new(),
            genesis_hash: None,
            multisig_accounts: Vec::new(),
            local_note_openings: Vec::new(),
            poseidon2_v8: Poseidon2V8WalletState::default(),
            poseidon2_v8_reservations: Vec::new(),
            htlc_swaps: Vec::new(),
            poseidon2_v8_treasuries: Vec::new(),
            native_launch_context: None,
            native_rp06_transfers: Vec::new(),
            private_spend_issued: Default::default(),
            private_spend_notes: Vec::new(),
            private_spend_templates: Vec::new(),
            private_spend_attempts: Vec::new(),
            private_spend_relation_digest: None,
            asset_spend: Default::default(),
            recovery: Default::default(),
        };
        Self::create_with_state(path, passphrase, state, fail_if_exists)
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
            commitment_sources: Vec::new(),
            next_commitment_index: 0,
            next_ciphertext_index: 0,
            last_synced_height: 0,
            last_synced_block_hash: None,
            outgoing_disclosures: Vec::new(),
            genesis_hash: None,
            multisig_accounts: Vec::new(),
            local_note_openings: Vec::new(),
            poseidon2_v8: Poseidon2V8WalletState::default(),
            poseidon2_v8_reservations: Vec::new(),
            htlc_swaps: Vec::new(),
            poseidon2_v8_treasuries: Vec::new(),
            native_launch_context: None,
            native_rp06_transfers: Vec::new(),
            private_spend_issued: Default::default(),
            private_spend_notes: Vec::new(),
            private_spend_templates: Vec::new(),
            private_spend_attempts: Vec::new(),
            private_spend_relation_digest: None,
            asset_spend: Default::default(),
            recovery: Default::default(),
        };
        Self::create_with_state(path, passphrase, state, false)
    }

    fn create_with_state<P: AsRef<Path>>(
        path: P,
        passphrase: &str,
        state: WalletState,
        fail_if_exists: bool,
    ) -> Result<Self, WalletError> {
        let (path, file_lock) = lock_wallet_file(path.as_ref())?;
        if fail_if_exists && path.exists() {
            return Err(WalletError::StoreAlreadyExists);
        }
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(passphrase, &salt)?;
        let store = WalletStore {
            path,
            _file_lock: Some(file_lock),
            read_only: false,
            source_file_version: FILE_VERSION,
            key,
            salt,
            state: Mutex::new(state),
            commitment_tree_cache: Mutex::new(None),
        };
        store.write_locked()?;
        Ok(store)
    }

    pub fn open<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Self, WalletError> {
        Self::open_inner(path.as_ref(), passphrase, false)
    }

    /// Decrypt one coherent atomic disk snapshot while another process owns
    /// the writer. This handle cannot mutate, migrate or recover reservations.
    pub fn open_read_only<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Self, WalletError> {
        Self::open_inner(path.as_ref(), passphrase, true)
    }

    fn open_inner(path: &Path, passphrase: &str, read_only: bool) -> Result<Self, WalletError> {
        let (path, file_lock) = if read_only {
            (path.to_path_buf(), None)
        } else {
            let (path, lock) = lock_wallet_file(path)?;
            (path, Some(lock))
        };
        let bytes = fs::read(&path)?;
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
        let plaintext = zeroize::Zeroizing::new(plaintext);
        let mut state: WalletState = match file.version {
            FILE_VERSION => deserialize_wallet_state(&plaintext)?,
            LEGACY_FILE_VERSION_V19 => deserialize_wallet_state_v19(&plaintext)?,
            LEGACY_FILE_VERSION_V18 => deserialize_wallet_state_v18(&plaintext)?,
            LEGACY_FILE_VERSION_V17 => deserialize_wallet_state_v17(&plaintext)?,
            LEGACY_FILE_VERSION_V16 => deserialize_wallet_state_v16(&plaintext)?,
            LEGACY_FILE_VERSION_V15 => deserialize_wallet_state_v15(&plaintext)?,
            LEGACY_FILE_VERSION_V14 => deserialize_wallet_state_v14(&plaintext)?,
            LEGACY_FILE_VERSION_V13 => deserialize_wallet_state_v13(&plaintext)?,
            LEGACY_FILE_VERSION_V12 => deserialize_wallet_state_v12(&plaintext)?,
            LEGACY_FILE_VERSION_V11 => deserialize_wallet_state_v11(&plaintext)?,
            LEGACY_FILE_VERSION_V10 => deserialize_wallet_state_v10(&plaintext)?,
            LEGACY_FILE_VERSION_V9 => deserialize_wallet_state_v9(&plaintext)?,
            LEGACY_FILE_VERSION_V8 => deserialize_wallet_state_v8(&plaintext)?,
            LEGACY_FILE_VERSION_V7 => deserialize_wallet_state_v7(&plaintext)?,
            LEGACY_FILE_VERSION_V6 => deserialize_wallet_state_v6(&plaintext)?,
            other => {
                return Err(WalletError::Serialization(format!(
                    "unsupported wallet file version {other} (expected {FILE_VERSION})"
                )));
            }
        };
        if file.version < FILE_VERSION && !read_only {
            return Err(WalletError::InvalidState(
                "legacy wallet is read-only; use explicit bootstrap-recover into a fresh destination, then rescan the intended network; original wallet is preserved",
            ));
        }
        if file.version < LEGACY_FILE_VERSION_V16 {
            seed_private_spend_issued_addresses(&mut state)?;
        }
        // Exclusive file ownership proves no live builder can still submit
        // these pre-RPC records. Submitted/uncertain records survive restart.
        let abandoned_proving = state
            .poseidon2_v8_reservations
            .iter()
            .any(|record| record.status == Poseidon2V8ReservationStatus::Proving);
        if !read_only {
            state
                .poseidon2_v8_reservations
                .retain(|record| record.status != Poseidon2V8ReservationStatus::Proving);
        }
        let recovered_htlc = !read_only && state.recover_htlc_proving();
        let recovered_asset = !read_only && state.recover_asset_spend_proving();
        let recovered_recovery = !read_only && state.recover_recovery_proving();
        let store = WalletStore {
            path,
            _file_lock: file_lock,
            read_only,
            source_file_version: file.version,
            key,
            salt: file.salt,
            state: Mutex::new(state),
            commitment_tree_cache: Mutex::new(None),
        };
        if !read_only
            && (abandoned_proving
                || recovered_htlc
                || recovered_asset
                || recovered_recovery
                || file.version != FILE_VERSION)
        {
            store.write_locked()?;
        }
        Ok(store)
    }

    /// A pre-maturity snapshot is available only for historical inspection and
    /// key recovery. It cannot be synchronized or persisted as a current wallet.
    pub fn is_legacy_read_only(&self) -> bool {
        self.read_only && self.source_file_version < FILE_VERSION
    }

    /// Recover the same keys and account registry into a separate encrypted
    /// wallet for an explicit network reset/rescan. The source is read-only and
    /// remains byte-for-byte intact; no old proof, pending submission, root or
    /// note is reinterpreted as current-chain evidence.
    pub fn recover_keys_to_fresh_wallet<P: AsRef<Path>, Q: AsRef<Path>>(
        source: P,
        source_passphrase: &str,
        destination: Q,
        destination_passphrase: &str,
    ) -> Result<Self, WalletError> {
        if destination_passphrase.is_empty() {
            return Err(WalletError::InvalidArgument(
                "new encrypted wallet passphrase must not be empty",
            ));
        }
        // Existing paths, including hard links to the source, are never valid
        // recovery destinations. create_with_state repeats the check under lock.
        if fs::symlink_metadata(destination.as_ref()).is_ok() {
            return Err(WalletError::StoreAlreadyExists);
        }
        let original = Self::open_read_only(source, source_passphrase)?;
        let mut recovered = original.with_state(|state| Ok(state.clone()))?;
        validate_legacy_wallet_key_material(&recovered)?;
        reset_legacy_sync_fields(&mut recovered, true);
        recovered.outgoing_disclosures.clear();
        recovered.local_note_openings.clear();
        recovered.poseidon2_v8 = Poseidon2V8WalletState::default();
        recovered.poseidon2_v8_reservations.clear();
        recovered.htlc_swaps.clear();
        // Descriptors retain their original chain identities. Historical notes,
        // plans and attempts stay solely in the untouched original wallet.
        for treasury in &mut recovered.poseidon2_v8_treasuries {
            treasury.notes.clear();
            treasury.plans.clear();
            treasury.attempts.clear();
        }
        recovered.native_launch_context = None;
        recovered.native_rp06_transfers.clear();
        recovered.private_spend_notes.clear();
        recovered.private_spend_templates.clear();
        recovered.private_spend_attempts.clear();
        recovered.private_spend_relation_digest = None;
        recovered.asset_spend = Default::default();
        recovered.recovery = Default::default();
        validate_wallet_state(&recovered)?;
        Self::create_with_state(destination, destination_passphrase, recovered, true)
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

    /// V8 recipient material for the common private-spend route. The encrypted
    /// registry is written before an address leaves this method.
    pub fn private_spend_address(&self, index: u32) -> Result<ShieldedAddress, WalletError> {
        self.issue_private_spend_address(Some(index))
    }
    pub fn next_private_spend_address(&self) -> Result<ShieldedAddress, WalletError> {
        self.issue_private_spend_address(None)
    }
    fn issue_private_spend_address(
        &self,
        requested: Option<u32>,
    ) -> Result<ShieldedAddress, WalletError> {
        self.ensure_writable()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| WalletError::InvalidState("wallet poisoned"))?;
        let index = requested.unwrap_or(state.next_address_index);
        let next = index
            .checked_add(1)
            .ok_or(WalletError::InvalidState("private address index overflow"))?;
        let address = state
            .derived
            .as_ref()
            .ok_or(WalletError::WatchOnly)?
            .poseidon2_v8_address(index)?
            .shielded_address();
        let previous = state.private_spend_issued.clone();
        let previous_next = state.next_address_index;
        state.private_spend_issued.record_issued(index);
        state.next_address_index = state.next_address_index.max(next);
        if let Err(error) = self.write_state(&state) {
            state.private_spend_issued = previous;
            state.next_address_index = previous_next;
            return Err(error);
        }
        Ok(address)
    }
    pub fn private_spend_notes(
        &self,
    ) -> Result<Vec<crate::private_spend::StoredPrivateSpendNote>, WalletError> {
        self.with_state(|state| Ok(state.private_spend_notes.clone()))
    }

    /// Returns the stable legacy primary shielded address (index 0).
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
            reset_legacy_sync_fields(state, true);
            state.poseidon2_v8.clear();
            state.private_spend_notes.clear();
            state.asset_spend = Default::default();
            state.recovery = Default::default();
            self.invalidate_commitment_tree_cache()?;
            Ok(())
        })
    }

    /// Reset only the historical 48-byte mirror while preserving the V8
    /// canonical journal so a same-genesis reorg can detach exactly.
    pub(crate) fn reset_legacy_sync_state_preserving_v8(&self) -> Result<(), WalletError> {
        self.with_mut(|state| {
            reset_legacy_sync_fields(state, false);
            self.invalidate_commitment_tree_cache()?;
            Ok(())
        })
    }

    /// Atomically pin the launch identity and initialize its exact source-owned roots.
    pub fn ensure_poseidon2_v8_launch_genesis(
        &self,
        context: crate::poseidon2_v8_sync::LaunchWalletContext,
    ) -> Result<(), WalletError> {
        let (stable, note) = context.source_genesis_roots()?;
        self.with_poseidon2_v8_mut_and_block(None, Some((context, true)), |mirror, _| {
            mirror.ensure_launch_genesis(context.genesis_hash(), stable, note)
        })
    }

    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub fn ensure_poseidon2_v8_launch_genesis_for_retained_test(
        &self,
        context: crate::poseidon2_v8_sync::LaunchWalletContext,
        stablecoin_genesis_root: crate::poseidon2_v8_sync::Poseidon2V8Digest,
    ) -> Result<(), WalletError> {
        self.with_poseidon2_v8_mut_and_block(None, Some((context, false)), |mirror, _| {
            mirror.ensure_launch_genesis(
                context.genesis_hash(),
                stablecoin_genesis_root,
                crate::poseidon2_v8_sync::empty_note_root(),
            )
        })
    }

    pub(crate) fn require_rp06_canonical_reference(
        &self,
        context: crate::poseidon2_v8_sync::LaunchWalletContext,
        reference: Poseidon2V8CanonicalTip,
    ) -> Result<u64, WalletError> {
        self.with_state(|state| {
            state
                .native_launch_context
                .as_ref()
                .ok_or(WalletError::InvalidState(
                    "wallet launch context is not pinned",
                ))?
                .require_match(context)?;
            context.require_canonical_reference(&state.poseidon2_v8, reference, false)
        })
    }

    pub fn ensure_poseidon2_v8_genesis(&self, hash: [u8; 32]) -> Result<(), WalletError> {
        self.with_poseidon2_v8_mut(|mirror, _| mirror.ensure_genesis(hash))
    }

    #[cfg(test)]
    pub(crate) fn ensure_poseidon2_v8_genesis_for_test(
        &self,
        hash: [u8; 32],
        stablecoin_root: crate::poseidon2_v8_sync::Poseidon2V8Digest,
    ) -> Result<(), WalletError> {
        self.with_poseidon2_v8_mut(|mirror, _| {
            mirror.ensure_genesis_for_test(hash, stablecoin_root)
        })
    }

    /// Initialize an explicit retained development mirror. This feature-gated
    /// helper neither selects nor installs production proof authority.
    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub fn ensure_poseidon2_v8_genesis_for_retained_test(
        &self,
        context: crate::poseidon2_v8_sync::Poseidon2V8RetainedTestContext,
    ) -> Result<(), WalletError> {
        self.with_poseidon2_v8_mut(|mirror, _| mirror.ensure_genesis_for_retained_test(context))
    }

    pub fn poseidon2_v8_tip(&self) -> Result<Poseidon2V8CanonicalTip, WalletError> {
        self.with_state(|state| state.poseidon2_v8.tip())
    }

    /// Exact canonical block-end checkpoint, independently of append-root history.
    pub fn poseidon2_v8_canonical_tip_at_height(
        &self,
        height: u64,
    ) -> Result<Option<Poseidon2V8CanonicalTip>, WalletError> {
        self.with_state(|state| Ok(state.poseidon2_v8.canonical_tip_at_height(height)))
    }

    pub fn poseidon2_v8_canonical_hash(
        &self,
        height: u64,
    ) -> Result<Option<[u8; 32]>, WalletError> {
        self.with_state(|state| Ok(state.poseidon2_v8.canonical_hash(height)))
    }

    pub fn poseidon2_v8_owned_notes(&self) -> Result<Vec<Poseidon2V8OwnedNoteView>, WalletError> {
        self.with_state(|state| state.poseidon2_v8.owned_notes())
    }

    /// Find every exact position for a commitment in the authenticated current
    /// canonical V8 note mirror. Duplicate commitments remain explicit.
    pub fn poseidon2_v8_canonical_commitment_positions(
        &self,
        commitment: [u64; 7],
    ) -> Result<Vec<u64>, WalletError> {
        self.with_state(|state| {
            state
                .poseidon2_v8
                .canonical_commitment_positions(commitment)
        })
    }

    pub fn poseidon2_v8_spend_context(&self) -> Result<Poseidon2V8SpendContext, WalletError> {
        self.with_state(|state| {
            state
                .poseidon2_v8
                .spend_context(&state.reserved_poseidon2_v8_nullifiers())
        })
    }

    pub fn apply_poseidon2_v8_canonical_block(
        &self,
        block: &Poseidon2V8CanonicalBlock,
    ) -> Result<Poseidon2V8SyncDelta, WalletError> {
        self.with_poseidon2_v8_mut_and_block(Some(block), None, |mirror, keys| {
            mirror.apply_block(block, keys)
        })
    }

    /// Mirror a retained test node's verified canonical actions using an
    /// explicit, bounded development context. No production resolver changes.
    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub fn apply_poseidon2_v8_canonical_block_for_retained_test(
        &self,
        block: &Poseidon2V8CanonicalBlock,
        context: crate::poseidon2_v8_sync::Poseidon2V8RetainedTestContext,
    ) -> Result<Poseidon2V8SyncDelta, WalletError> {
        self.with_poseidon2_v8_mut_and_block(Some(block), None, |mirror, keys| {
            mirror.apply_block_for_retained_test(block, keys, context)
        })
    }

    pub fn apply_poseidon2_v8_launch_canonical_block(
        &self,
        block: &Poseidon2V8CanonicalBlock,
        context: crate::poseidon2_v8_sync::LaunchWalletContext,
    ) -> Result<Poseidon2V8SyncDelta, WalletError> {
        self.with_poseidon2_v8_mut_and_block(Some(block), Some((context, true)), |mirror, keys| {
            mirror.apply_launch_block(block, keys, context)
        })
    }

    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub fn apply_poseidon2_v8_launch_canonical_block_for_retained_test(
        &self,
        block: &Poseidon2V8CanonicalBlock,
        context: crate::poseidon2_v8_sync::LaunchWalletContext,
    ) -> Result<Poseidon2V8SyncDelta, WalletError> {
        self.with_poseidon2_v8_mut_and_block(Some(block), Some((context, false)), |mirror, keys| {
            mirror.apply_launch_block_for_retained_test(block, keys, context)
        })
    }

    pub fn rollback_poseidon2_v8_to(
        &self,
        height: u64,
        block_hash: [u8; 32],
    ) -> Result<(), WalletError> {
        self.with_poseidon2_v8_mut(|mirror, _| mirror.rollback_to(height, block_hash))
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
        let entries: Vec<(u64, Commitment, NoteSource)> = entries
            .iter()
            .map(|(index, commitment)| (*index, *commitment, NoteSource::Unknown))
            .collect();
        self.append_commitments_with_sources(&entries)
    }

    pub fn append_commitments_with_sources(
        &self,
        entries: &[(u64, Commitment, NoteSource)],
    ) -> Result<(), WalletError> {
        if entries.is_empty() {
            return Ok(());
        }
        self.with_mut(|state| {
            ensure_commitment_source_len(state);
            let mut expected = state.next_commitment_index;
            for (index, value, source) in entries {
                if *index != expected {
                    return Err(WalletError::InvalidState("commitment index mismatch"));
                }
                state.commitments.push(*value);
                state.commitment_sources.push(*source);
                expected = expected
                    .checked_add(1)
                    .ok_or(WalletError::InvalidState("commitment index overflow"))?;
            }
            state.next_commitment_index = expected;
            self.invalidate_commitment_tree_cache()?;
            Ok(())
        })
    }

    pub fn backfill_commitment_sources(
        &self,
        entries: &[(u64, NoteSource)],
    ) -> Result<(), WalletError> {
        if entries.is_empty() {
            return Ok(());
        }
        self.with_mut(|state| {
            ensure_commitment_source_len(state);
            for (index, source) in entries {
                if *source == NoteSource::Unknown {
                    continue;
                }
                let commitment_index = usize::try_from(*index)
                    .map_err(|_| WalletError::InvalidState("commitment source index overflow"))?;
                if commitment_index >= state.commitments.len() {
                    continue;
                }
                state.commitment_sources[commitment_index] = *source;
                let commitment = state.commitments[commitment_index];
                let tracked_source = note_source_for_commitment(state, commitment, *source);
                for note in state
                    .notes
                    .iter_mut()
                    .filter(|note| note.position == *index)
                {
                    note.source = tracked_source;
                }
            }
            Ok(())
        })
    }

    pub fn commitment_sources_need_backfill(&self) -> Result<bool, WalletError> {
        self.with_state(|state| {
            Ok(state.commitment_sources.len() < state.commitments.len()
                || state
                    .notes
                    .iter()
                    .any(|note| note.source == NoteSource::Unknown))
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
                            source: note_source_for_position(state, position),
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
                                    source: note_source_for_position(state, position),
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
                source: note_source_for_position(state, position),
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
                    source: note_source_for_position(state, position),
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
                    let commitment = transaction_circuit::hashing_pq::felts_to_bytes48(
                        &note.note.note_data.commitment(),
                    );
                    let uses_private_auth = state.local_note_openings.iter().any(|opening| {
                        opening.commitment == commitment && opening.uses_private_auth()
                    });
                    note.note.note.asset_id == asset_id
                        && !note.spent
                        && !note.pending_spend
                        && !uses_private_auth
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
                    source: note.source,
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
        tx_id: &ActionId48,
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
        tx_id: ActionId48,
        genesis_hash: [u8; 32],
        outputs: Vec<OutgoingDisclosureDraft>,
    ) -> Result<(), WalletError> {
        self.record_outgoing_disclosures_with_id(
            WalletTransactionId::Canonical(tx_id),
            genesis_hash,
            outputs,
        )
    }

    pub fn record_provisional_outgoing_disclosures(
        &self,
        tx_id: ProvisionalActionId48,
        genesis_hash: [u8; 32],
        outputs: Vec<OutgoingDisclosureDraft>,
    ) -> Result<(), WalletError> {
        self.record_outgoing_disclosures_with_id(
            WalletTransactionId::Provisional(tx_id),
            genesis_hash,
            outputs,
        )
    }

    fn record_outgoing_disclosures_with_id(
        &self,
        tx_id: WalletTransactionId,
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
                for note in &mut state.notes {
                    let commitment = transaction_circuit::hashing_pq::felts_to_bytes48(
                        &note.note.note_data.commitment(),
                    );
                    if commitment == output.commitment {
                        note.source = NoteSource::LocalChange;
                    }
                }
            }
            Ok(())
        })
    }

    pub fn purge_outgoing_disclosure(
        &self,
        tx_id: &ActionId48,
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
        tx_id: ActionId48,
        nullifiers: Vec<[u8; 48]>,
        spent_note_indexes: Vec<usize>,
        recipients: Vec<TransferRecipient>,
        fee: u64,
    ) -> Result<(), WalletError> {
        self.record_pending_submission_with_id(
            WalletTransactionId::Canonical(tx_id),
            nullifiers,
            spent_note_indexes,
            recipients,
            fee,
        )
    }

    pub fn record_provisional_pending_submission(
        &self,
        tx_id: ProvisionalActionId48,
        nullifiers: Vec<[u8; 48]>,
        spent_note_indexes: Vec<usize>,
        recipients: Vec<TransferRecipient>,
        fee: u64,
    ) -> Result<(), WalletError> {
        self.record_pending_submission_with_id(
            WalletTransactionId::Provisional(tx_id),
            nullifiers,
            spent_note_indexes,
            recipients,
            fee,
        )
    }

    fn record_pending_submission_with_id(
        &self,
        tx_id: WalletTransactionId,
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

            // Debug output contains counts only, never nullifiers/action ids.
            if std::env::var("WALLET_DEBUG_PENDING").is_ok() {
                eprintln!(
                    "[DEBUG refresh_pending] chain nullifier count={}",
                    nullifiers.len()
                );
            }

            for (i, tx) in state.pending.iter_mut().enumerate() {
                if matches!(tx.status, PendingStatus::Mined { .. }) {
                    mined_indexes.push(i);
                    continue;
                }

                if std::env::var("WALLET_DEBUG_PENDING").is_ok() {
                    eprintln!(
                        "{}",
                        pending_debug_counts(
                            tx.nullifiers.len(),
                            tx.nullifiers
                                .iter()
                                .filter(|nf| nullifiers.contains(*nf))
                                .count(),
                        )
                    );
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
        self.ensure_writable()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| WalletError::InvalidState("wallet poisoned"))?;
        let result = func(&mut state)?;
        drop(state);
        self.write_locked()?;
        Ok(result)
    }

    fn with_poseidon2_v8_mut<F, T>(&self, func: F) -> Result<T, WalletError>
    where
        F: FnOnce(&mut Poseidon2V8WalletState, Option<&DerivedKeys>) -> Result<T, WalletError>,
    {
        self.with_poseidon2_v8_mut_and_block(None, None, func)
    }

    fn with_poseidon2_v8_mut_and_block<F, T>(
        &self,
        block: Option<&Poseidon2V8CanonicalBlock>,
        launch_context: Option<(crate::poseidon2_v8_sync::LaunchWalletContext, bool)>,
        func: F,
    ) -> Result<T, WalletError>
    where
        F: FnOnce(&mut Poseidon2V8WalletState, Option<&DerivedKeys>) -> Result<T, WalletError>,
    {
        self.ensure_writable()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| WalletError::InvalidState("wallet poisoned"))?;
        let previous_context = state.native_launch_context.clone();
        let previous_private_pin = state.private_spend_relation_digest.clone();
        if let Some((context, require_authority)) = launch_context {
            if require_authority {
                context.require_source_authority()?;
            }
            if let Some(genesis) = state.poseidon2_v8.canonical_hash(0) {
                if genesis != context.genesis_hash() {
                    return Err(WalletError::InvalidState(
                        "launch context differs from wallet genesis",
                    ));
                }
            }
            if let Some(stored) = &state.native_launch_context {
                stored.require_match(context)?;
            } else {
                state.native_launch_context = Some(
                    crate::poseidon2_v8_sync::launch_sync::StoredNativeLaunchContext::from_context(
                        context,
                    ),
                );
            }
        }
        if launch_context.is_some() {
            if let Err(error) = state.pin_private_spend_source() {
                state.native_launch_context = previous_context;
                return Err(error);
            }
        }
        let previous = state.poseidon2_v8.clone();
        let previous_private_notes = state.private_spend_notes.clone();
        let previous_asset = state.asset_spend.clone();
        let previous_recovery = state.recovery.clone();
        let previous_private_attempts = state.private_spend_attempts.clone();
        let previous_treasuries = state.poseidon2_v8_treasuries.clone();
        let previous_htlc = state.htlc_swaps.clone();
        let result = {
            let WalletState {
                poseidon2_v8,
                derived,
                ..
            } = &mut *state;
            match func(poseidon2_v8, derived.as_ref()) {
                Ok(result) => result,
                Err(error) => {
                    state.poseidon2_v8 = previous;
                    state.asset_spend = previous_asset;
                    state.recovery = previous_recovery;
                    state.native_launch_context = previous_context;
                    state.private_spend_relation_digest = previous_private_pin;
                    return Err(error);
                }
            }
        };
        let reconcile_and_write = (|| {
            let mut observed_actions = Vec::new();
            if let Some(block) = block {
                let (actions, htlc, rewards) =
                    crate::poseidon2_v8_sync::launch_sync::canonical_launch_observations(block)?;
                if let (Some(keys), Some((context, _))) = (state.derived.as_ref(), launch_context) {
                    let recovered = state.poseidon2_v8.recover_private_spend_block(
                        block,
                        keys,
                        &state.private_spend_issued,
                        context,
                    )?;
                    state.private_spend_notes.extend(recovered);
                    state.recover_asset_spend_block(context, block)?;
                    state.recover_recovery_block(context, block)?;
                }
                observed_actions = actions;
                state.observe_htlc_actions(block.height, block.hash, &htlc)?;
                for opening in rewards {
                    crate::poseidon2_v8_multisig::track_v8_treasury_public_reward(
                        &mut state.poseidon2_v8_treasuries,
                        opening,
                    )?;
                }
            }
            let WalletState {
                poseidon2_v8,
                poseidon2_v8_treasuries,
                ..
            } = &mut *state;
            crate::poseidon2_v8_multisig::reconcile_v8_treasury_attempts(
                poseidon2_v8_treasuries,
                poseidon2_v8,
                &observed_actions,
            )?;
            let WalletState {
                poseidon2_v8,
                private_spend_notes,
                ..
            } = &mut *state;
            private_spend_notes.retain(|note| {
                poseidon2_v8.canonical_hash(note.created_height) == Some(note.created_block_hash)
            });
            for note in private_spend_notes {
                note.spent = poseidon2_v8.has_canonical_nullifier(note.nullifier);
            }
            state.reconcile_private_spend_attempts(&observed_actions)?;
            state.reconcile_asset_spend_state()?;
            state.reconcile_recovery_state()?;
            state.validate_asset_spend_state()?;
            state.validate_recovery_state()?;
            state.validate_htlc_swaps()?;
            if let Some(context) = &state.native_launch_context {
                let pinned = context.current_context()?;
                if state
                    .poseidon2_v8
                    .canonical_hash(0)
                    .is_some_and(|genesis| genesis != pinned.genesis_hash())
                {
                    return Err(WalletError::InvalidState(
                        "wallet mirror genesis differs from pinned launch context",
                    ));
                }
            }
            self.write_state(&state)
        })();
        if let Err(error) = reconcile_and_write {
            state.poseidon2_v8 = previous;
            state.private_spend_notes = previous_private_notes;
            state.asset_spend = previous_asset;
            state.recovery = previous_recovery;
            state.private_spend_attempts = previous_private_attempts;
            state.poseidon2_v8_treasuries = previous_treasuries;
            state.htlc_swaps = previous_htlc;
            state.native_launch_context = previous_context;
            state.private_spend_relation_digest = previous_private_pin;
            return Err(error);
        }
        Ok(result)
    }

    fn write_locked(&self) -> Result<(), WalletError> {
        let state = self
            .state
            .lock()
            .map_err(|_| WalletError::InvalidState("wallet poisoned"))?;
        self.write_state(&state)
    }

    fn write_state(&self, state: &WalletState) -> Result<(), WalletError> {
        self.ensure_writable()?;
        let plaintext = zeroize::Zeroizing::new(bincode::serialize(state)?);
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

    fn ensure_writable(&self) -> Result<(), WalletError> {
        if self.read_only {
            return Err(WalletError::InvalidState("wallet snapshot is read-only"));
        }
        Ok(())
    }
}

fn pending_debug_counts(input_count: usize, canonical_matches: usize) -> String {
    format!("[DEBUG refresh_pending] pending input_count={input_count} canonical_matches={canonical_matches}")
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

fn ensure_commitment_source_len(state: &mut WalletState) {
    if state.commitment_sources.len() < state.commitments.len() {
        state
            .commitment_sources
            .resize(state.commitments.len(), NoteSource::Unknown);
    }
}

fn reset_legacy_sync_fields(state: &mut WalletState, clear_genesis: bool) {
    state.notes.clear();
    state.pending.clear();
    state.recent.clear();
    state.commitments.clear();
    state.commitment_sources.clear();
    state.next_commitment_index = 0;
    state.next_ciphertext_index = 0;
    state.last_synced_height = 0;
    state.last_synced_block_hash = None;
    if clear_genesis {
        state.genesis_hash = None;
    }
}

fn note_source_for_position(state: &WalletState, position: u64) -> NoteSource {
    let Ok(index) = usize::try_from(position) else {
        return NoteSource::Unknown;
    };
    let source = state
        .commitment_sources
        .get(index)
        .copied()
        .unwrap_or(NoteSource::Unknown);
    let Some(commitment) = state.commitments.get(index).copied() else {
        return source;
    };
    note_source_for_commitment(state, commitment, source)
}

fn note_source_for_commitment(
    state: &WalletState,
    commitment: Commitment,
    source: NoteSource,
) -> NoteSource {
    if source == NoteSource::Transfer
        && state
            .outgoing_disclosures
            .iter()
            .any(|record| record.commitment == commitment)
    {
        NoteSource::LocalChange
    } else {
        source
    }
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
    // The reservation must survive a process/OS restart before RPC can run:
    // sync the rename's directory entry, not only the staged file contents.
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::File::open(parent)?.sync_all()?;
    }
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
    let state = deserialize_exact::<WalletState>(bytes).map_err(|err| match err {
        WalletError::Serialization(message) => {
            WalletError::Serialization(format!("failed to deserialize wallet state: {message}"))
        }
        other => other,
    })?;
    validate_wallet_state(&state)?;
    Ok(state)
}

fn validate_wallet_state(state: &WalletState) -> Result<(), WalletError> {
    state.validate_private_spend_source_pin()?;
    state.validate_private_spend_journal()?;
    state.validate_asset_spend_state()?;
    state.validate_recovery_state()?;
    state.poseidon2_v8.validate()?;
    if !state.private_spend_notes.is_empty() && state.native_launch_context.is_none() {
        return Err(WalletError::InvalidState(
            "private notes require pinned launch context",
        ));
    }
    let mut private_positions = std::collections::BTreeSet::new();
    for note in &state.private_spend_notes {
        let payload = note.opening()?;
        if !state.private_spend_issued.contains(payload.recipient_index)
            || state
                .native_launch_context
                .as_ref()
                .map(|ctx| ctx.current_context())
                .transpose()?
                .map(|ctx| ctx.chain_id())
                != Some(note.chain_id)
        {
            return Err(WalletError::InvalidState(
                "private stored chain or issued address mismatch",
            ));
        }
        note.validate(state.derived.as_ref().ok_or(WalletError::WatchOnly)?)?;
        if state
            .poseidon2_v8
            .canonical_note_witness_at(note.commitment, note.position)?
            .is_none()
        {
            return Err(WalletError::InvalidState("private note occurrence missing"));
        }
        if !private_positions.insert(note.position)
            || state.poseidon2_v8.canonical_hash(note.created_height)
                != Some(note.created_block_hash)
            || note.spent != state.poseidon2_v8.has_canonical_nullifier(note.nullifier)
        {
            return Err(WalletError::InvalidState(
                "private note canonical state mismatch",
            ));
        }
    }
    state.validate_poseidon2_v8_reservations()?;
    state.validate_htlc_swaps()?;
    if let Some(context) = &state.native_launch_context {
        let pinned = context.current_context()?;
        if state
            .poseidon2_v8
            .canonical_hash(0)
            .is_some_and(|genesis| genesis != pinned.genesis_hash())
        {
            return Err(WalletError::InvalidState(
                "wallet mirror genesis differs from pinned launch context",
            ));
        }
        validate_rp06_candidates(&state.native_rp06_transfers, pinned)?;
    } else if !state.native_rp06_transfers.is_empty() {
        return Err(WalletError::InvalidState(
            "retained RP06 candidates require pinned launch identity",
        ));
    }
    Ok(())
}

fn validate_rp06_candidates(
    records: &[crate::rp06_transfer_store::StoredRp06TransferCandidate],
    context: crate::poseidon2_v8_sync::LaunchWalletContext,
) -> Result<(), WalletError> {
    let mut identifiers = std::collections::HashSet::new();
    for record in records {
        record.validate(context)?;
        if !identifiers.insert(record.reservation_id) {
            return Err(WalletError::InvalidState(
                "duplicate retained RP06 reservation identity",
            ));
        }
    }
    Ok(())
}

fn deserialize_wallet_state_v13(bytes: &[u8]) -> Result<WalletState, WalletError> {
    let state = WalletState::from(deserialize_exact::<WalletStateV13>(bytes)?);
    validate_legacy_wallet_key_material(&state)?;
    Ok(state)
}

fn deserialize_wallet_state_v14(bytes: &[u8]) -> Result<WalletState, WalletError> {
    let state = WalletState::from(deserialize_exact::<WalletStateV14>(bytes)?);
    validate_legacy_wallet_key_material(&state)?;
    Ok(state)
}

fn deserialize_wallet_state_v12(bytes: &[u8]) -> Result<WalletState, WalletError> {
    let state = WalletState::from(deserialize_exact::<WalletStateV12>(bytes)?);
    validate_legacy_wallet_key_material(&state)?;
    Ok(state)
}

fn deserialize_wallet_state_v11(bytes: &[u8]) -> Result<WalletState, WalletError> {
    let state = WalletState::from(deserialize_exact::<WalletStateV11>(bytes)?);
    validate_legacy_wallet_key_material(&state)?;
    Ok(state)
}

fn lock_wallet_file(path: &Path) -> Result<(PathBuf, fs::File), WalletError> {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(WalletError::InvalidArgument(
            "writable wallet path cannot be a symbolic link",
        ));
    }
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let parent = fs::canonicalize(parent)?;
    let wallet_path = parent.join(
        path.file_name()
            .ok_or(WalletError::InvalidArgument("wallet file has no filename"))?,
    );
    let mut name = path
        .file_name()
        .ok_or(WalletError::InvalidArgument("wallet file has no filename"))?
        .to_os_string();
    name.push(".lock");
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock_path = parent.join(name);
    let file = options.open(&lock_path)?;
    set_private_file_permissions(&lock_path)?;
    file.try_lock_exclusive().map_err(|error| {
        if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
            WalletError::StoreBusy
        } else {
            WalletError::from(error)
        }
    })?;
    Ok((wallet_path, file))
}

fn deserialize_wallet_state_v10(bytes: &[u8]) -> Result<WalletState, WalletError> {
    deserialize_exact::<WalletStateV10>(bytes)
        .map(WalletState::from)
        .map_err(|err| match err {
            WalletError::Serialization(message) => WalletError::Serialization(format!(
                "failed to deserialize legacy wallet state v10: {message}"
            )),
            other => other,
        })
}

fn deserialize_wallet_state_v9(bytes: &[u8]) -> Result<WalletState, WalletError> {
    match deserialize_exact::<WalletStateV9>(bytes) {
        Ok(state) => WalletState::try_from(state),
        Err(current_err) => {
            if let Ok(state) = deserialize_exact::<WalletStateV9BeforeNoteSources>(bytes) {
                return WalletState::try_from(state);
            }
            Err(match current_err {
                WalletError::Serialization(message) => WalletError::Serialization(format!(
                    "failed to deserialize legacy wallet state v9: {message}"
                )),
                other => other,
            })
        }
    }
}

fn deserialize_wallet_state_v8(bytes: &[u8]) -> Result<WalletState, WalletError> {
    deserialize_exact::<WalletStateV8>(bytes)
        .and_then(WalletState::try_from)
        .map_err(|err| match err {
            WalletError::Serialization(message) => WalletError::Serialization(format!(
                "failed to deserialize legacy wallet state v8: {message}"
            )),
            other => other,
        })
}

fn deserialize_wallet_state_v7(bytes: &[u8]) -> Result<WalletState, WalletError> {
    deserialize_exact::<WalletStateV7>(bytes)
        .and_then(WalletState::try_from)
        .map_err(|err| match err {
            WalletError::Serialization(message) => WalletError::Serialization(format!(
                "failed to deserialize legacy wallet state v7: {message}"
            )),
            other => other,
        })
}

fn deserialize_wallet_state_v6(bytes: &[u8]) -> Result<WalletState, WalletError> {
    deserialize_exact::<WalletStateV6>(bytes)
        .and_then(WalletState::try_from)
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

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NoteSource {
    #[default]
    Unknown,
    MiningReward,
    Transfer,
    LocalChange,
}

impl NoteSource {
    pub fn as_str(self) -> &'static str {
        match self {
            NoteSource::Unknown => "unknown",
            NoteSource::MiningReward => "mining_reward",
            NoteSource::Transfer => "transfer",
            NoteSource::LocalChange => "local_change",
        }
    }

    pub fn from_rpc_label(label: &str) -> Self {
        match label {
            "mining_reward" | "coinbase" => NoteSource::MiningReward,
            "transfer" | "shielded_transfer" => NoteSource::Transfer,
            "local_change" | "change" => NoteSource::LocalChange,
            _ => NoteSource::Unknown,
        }
    }
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
    #[serde(default)]
    commitment_sources: Vec<NoteSource>,
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
    poseidon2_v8: Poseidon2V8WalletState,
    poseidon2_v8_reservations: Vec<StoredPoseidon2V8Reservation>,
    htlc_swaps: Vec<htlc_store::StoredHtlcSwap>,
    poseidon2_v8_treasuries: Vec<crate::poseidon2_v8_multisig::StoredV8Treasury>,
    #[serde(default)]
    native_launch_context: Option<crate::poseidon2_v8_sync::launch_sync::StoredNativeLaunchContext>,
    native_rp06_transfers: Vec<crate::rp06_transfer_store::StoredRp06TransferCandidate>,

    private_spend_issued: crate::private_spend::IssuedPrivateSpendAddresses,
    private_spend_notes: Vec<crate::private_spend::StoredPrivateSpendNote>,
    private_spend_templates: Vec<private_spend_journal::StoredPrivateTemplate>,
    private_spend_attempts: Vec<private_spend_journal::StoredPrivateAttempt>,
    private_spend_relation_digest: Option<Vec<u8>>,
    asset_spend: asset_spend_store::AssetWalletState,
    recovery: asset_recovery_store::RecoveryWalletState,
}

// Exact frozen V19 positional codec. No field reordering or automatic writable upgrade.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletStateV19 {
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
    #[serde(default)]
    commitment_sources: Vec<NoteSource>,
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
    poseidon2_v8: Poseidon2V8WalletState,
    poseidon2_v8_reservations: Vec<StoredPoseidon2V8Reservation>,
    htlc_swaps: Vec<htlc_store::StoredHtlcSwap>,
    poseidon2_v8_treasuries: Vec<crate::poseidon2_v8_multisig::StoredV8Treasury>,
    #[serde(default)]
    native_launch_context: Option<crate::poseidon2_v8_sync::launch_sync::StoredNativeLaunchContext>,
    native_rp06_transfers: Vec<crate::rp06_transfer_store::StoredRp06TransferCandidate>,

    private_spend_issued: crate::private_spend::IssuedPrivateSpendAddresses,
    private_spend_notes: Vec<crate::private_spend::StoredPrivateSpendNote>,
    private_spend_templates: Vec<private_spend_journal::StoredPrivateTemplate>,
    private_spend_attempts: Vec<private_spend_journal::StoredPrivateAttempt>,
    private_spend_relation_digest: Option<Vec<u8>>,
    asset_spend: asset_spend_store::AssetWalletState,
}

impl From<WalletStateV19> for WalletState {
    fn from(value: WalletStateV19) -> Self {
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
            commitment_sources: value.commitment_sources,
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: value.outgoing_disclosures,
            genesis_hash: value.genesis_hash,
            multisig_accounts: value.multisig_accounts,
            local_note_openings: value.local_note_openings,
            poseidon2_v8: value.poseidon2_v8,
            poseidon2_v8_reservations: value.poseidon2_v8_reservations,
            htlc_swaps: value.htlc_swaps,
            poseidon2_v8_treasuries: value.poseidon2_v8_treasuries,
            native_launch_context: value.native_launch_context,
            native_rp06_transfers: value.native_rp06_transfers,
            private_spend_issued: value.private_spend_issued,
            private_spend_notes: value.private_spend_notes,
            private_spend_templates: value.private_spend_templates,
            private_spend_attempts: value.private_spend_attempts,
            private_spend_relation_digest: value.private_spend_relation_digest,
            asset_spend: value.asset_spend,
            recovery: Default::default(),
        }
    }
}
fn deserialize_wallet_state_v19(bytes: &[u8]) -> Result<WalletState, WalletError> {
    let state = WalletState::from(deserialize_exact::<WalletStateV19>(bytes)?);
    validate_wallet_state(&state)?;
    Ok(state)
}

// Exact V18 positional payload. Never append or reorder these fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletStateV18 {
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
    #[serde(default)]
    commitment_sources: Vec<NoteSource>,
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
    poseidon2_v8: Poseidon2V8WalletState,
    poseidon2_v8_reservations: Vec<StoredPoseidon2V8Reservation>,
    htlc_swaps: Vec<htlc_store::StoredHtlcSwap>,
    poseidon2_v8_treasuries: Vec<crate::poseidon2_v8_multisig::StoredV8Treasury>,
    #[serde(default)]
    native_launch_context: Option<crate::poseidon2_v8_sync::launch_sync::StoredNativeLaunchContext>,
    native_rp06_transfers: Vec<crate::rp06_transfer_store::StoredRp06TransferCandidate>,

    private_spend_issued: crate::private_spend::IssuedPrivateSpendAddresses,
    private_spend_notes: Vec<crate::private_spend::StoredPrivateSpendNote>,
    private_spend_templates: Vec<private_spend_journal::StoredPrivateTemplate>,
    private_spend_attempts: Vec<private_spend_journal::StoredPrivateAttempt>,
    private_spend_relation_digest: Option<Vec<u8>>,
}
impl From<WalletStateV18> for WalletState {
    fn from(value: WalletStateV18) -> Self {
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
            commitment_sources: value.commitment_sources,
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: value.outgoing_disclosures,
            genesis_hash: value.genesis_hash,
            multisig_accounts: value.multisig_accounts,
            local_note_openings: value.local_note_openings,
            poseidon2_v8: value.poseidon2_v8,
            poseidon2_v8_reservations: value.poseidon2_v8_reservations,
            htlc_swaps: value.htlc_swaps,
            poseidon2_v8_treasuries: value.poseidon2_v8_treasuries,
            native_launch_context: value.native_launch_context,
            native_rp06_transfers: value.native_rp06_transfers,
            private_spend_issued: value.private_spend_issued,
            private_spend_notes: value.private_spend_notes,
            private_spend_templates: value.private_spend_templates,
            private_spend_attempts: value.private_spend_attempts,
            private_spend_relation_digest: value.private_spend_relation_digest,
            asset_spend: Default::default(),
            recovery: Default::default(),
        }
    }
}

fn deserialize_wallet_state_v18(bytes: &[u8]) -> Result<WalletState, WalletError> {
    let state = WalletState::from(deserialize_exact::<WalletStateV18>(bytes)?);
    validate_legacy_wallet_key_material(&state)?;
    Ok(state)
}

// Exact V17 positional payload. Never append or reorder these fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletStateV17 {
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
    #[serde(default)]
    commitment_sources: Vec<NoteSource>,
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
    #[serde(with = "frozen_v17_mirror_codec")]
    poseidon2_v8: Poseidon2V8WalletState,
    poseidon2_v8_reservations: Vec<StoredPoseidon2V8Reservation>,
    htlc_swaps: Vec<htlc_store::StoredHtlcSwap>,
    poseidon2_v8_treasuries: Vec<crate::poseidon2_v8_multisig::StoredV8Treasury>,
    #[serde(default)]
    native_launch_context: Option<crate::poseidon2_v8_sync::launch_sync::StoredNativeLaunchContext>,
    native_rp06_transfers: Vec<crate::rp06_transfer_store::StoredRp06TransferCandidate>,

    private_spend_issued: crate::private_spend::IssuedPrivateSpendAddresses,
    private_spend_notes: Vec<crate::private_spend::StoredPrivateSpendNote>,
    private_spend_templates: Vec<private_spend_journal::StoredPrivateTemplate>,
    private_spend_attempts: Vec<private_spend_journal::StoredPrivateAttempt>,
    private_spend_relation_digest: Option<Vec<u8>>,
}
impl From<WalletStateV17> for WalletState {
    fn from(value: WalletStateV17) -> Self {
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
            commitment_sources: value.commitment_sources,
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: value.outgoing_disclosures,
            genesis_hash: value.genesis_hash,
            multisig_accounts: value.multisig_accounts,
            local_note_openings: value.local_note_openings,
            poseidon2_v8: value.poseidon2_v8,
            poseidon2_v8_reservations: value.poseidon2_v8_reservations,
            htlc_swaps: value.htlc_swaps,
            poseidon2_v8_treasuries: value.poseidon2_v8_treasuries,
            native_launch_context: value.native_launch_context,
            native_rp06_transfers: value.native_rp06_transfers,
            private_spend_issued: value.private_spend_issued,
            private_spend_notes: value.private_spend_notes,
            private_spend_templates: value.private_spend_templates,
            private_spend_attempts: value.private_spend_attempts,
            private_spend_relation_digest: value.private_spend_relation_digest,
            asset_spend: Default::default(),
            recovery: Default::default(),
        }
    }
}

mod frozen_v17_mirror_codec {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        mirror: &Poseidon2V8WalletState,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        mirror
            .to_legacy_v17()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Poseidon2V8WalletState, D::Error> {
        let frozen =
            crate::poseidon2_v8_sync::Poseidon2V8WalletStateV17::deserialize(deserializer)?;
        frozen
            .into_legacy_read_only()
            .map_err(serde::de::Error::custom)
    }
}

fn deserialize_wallet_state_v17(bytes: &[u8]) -> Result<WalletState, WalletError> {
    let state = WalletState::from(deserialize_exact::<WalletStateV17>(bytes)?);
    validate_legacy_wallet_key_material(&state)?;
    Ok(state)
}

fn validate_legacy_wallet_key_material(state: &WalletState) -> Result<(), WalletError> {
    if let Some(root) = state.root_secret {
        let derived = RootSecret::from_bytes(root).derive();
        if state.mode != WalletMode::Full
            || state.derived.as_ref() != Some(&derived)
            || state.incoming != IncomingViewingKey::from_keys(&derived)
            || state.full_viewing_key.as_ref() != Some(&FullViewingKey::from_keys(&derived))
            || state.outgoing.as_ref() != Some(&OutgoingViewingKey::from_keys(&derived))
        {
            return Err(WalletError::InvalidState(
                "legacy wallet key identity mismatch",
            ));
        }
    } else if state.mode == WalletMode::Full {
        return Err(WalletError::InvalidState(
            "full legacy wallet has no root secret",
        ));
    }
    for account in &state.multisig_accounts {
        validate_account_record(account)?;
    }
    Ok(())
}

/// Exact V13 payload. Keep this positional encrypted-wallet shape frozen.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletStateV13 {
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
    #[serde(default)]
    commitment_sources: Vec<NoteSource>,
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
    #[serde(with = "frozen_v17_mirror_codec")]
    poseidon2_v8: Poseidon2V8WalletState,
    poseidon2_v8_reservations: Vec<StoredPoseidon2V8Reservation>,
    htlc_swaps: Vec<htlc_store::StoredHtlcSwap>,
    poseidon2_v8_treasuries: Vec<crate::poseidon2_v8_multisig::StoredV8TreasuryV14>,
    #[serde(default)]
    native_launch_context: Option<crate::poseidon2_v8_sync::launch_sync::StoredNativeLaunchContext>,
}

impl From<WalletStateV13> for WalletState {
    fn from(value: WalletStateV13) -> Self {
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
            commitment_sources: value.commitment_sources,
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: value.outgoing_disclosures,
            genesis_hash: value.genesis_hash,
            multisig_accounts: value.multisig_accounts,
            local_note_openings: value.local_note_openings,
            poseidon2_v8: value.poseidon2_v8,
            poseidon2_v8_reservations: value.poseidon2_v8_reservations,
            htlc_swaps: value.htlc_swaps,
            poseidon2_v8_treasuries: value
                .poseidon2_v8_treasuries
                .into_iter()
                .map(Into::into)
                .collect(),
            native_launch_context: value.native_launch_context,
            native_rp06_transfers: Vec::new(),
            private_spend_issued: Default::default(),
            private_spend_notes: Vec::new(),
            private_spend_templates: Vec::new(),
            private_spend_attempts: Vec::new(),
            private_spend_relation_digest: None,
            asset_spend: Default::default(),
            recovery: Default::default(),
        }
    }
}

/// Exact V14 payload. Keep this positional encrypted-wallet shape frozen.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletStateV14 {
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
    #[serde(default)]
    commitment_sources: Vec<NoteSource>,
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
    multisig_accounts: Vec<MultisigAccountRecord>,
    #[serde(default)]
    local_note_openings: Vec<LocalNoteOpeningRecord>,
    #[serde(with = "frozen_v17_mirror_codec")]
    poseidon2_v8: Poseidon2V8WalletState,
    poseidon2_v8_reservations: Vec<StoredPoseidon2V8Reservation>,
    htlc_swaps: Vec<htlc_store::StoredHtlcSwap>,
    poseidon2_v8_treasuries: Vec<crate::poseidon2_v8_multisig::StoredV8TreasuryV14>,
    #[serde(default)]
    native_launch_context: Option<crate::poseidon2_v8_sync::launch_sync::StoredNativeLaunchContext>,
    native_rp06_transfers: Vec<crate::rp06_transfer_store::StoredRp06TransferCandidate>,
}

impl From<WalletStateV14> for WalletState {
    fn from(value: WalletStateV14) -> Self {
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
            commitment_sources: value.commitment_sources,
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: value.outgoing_disclosures,
            genesis_hash: value.genesis_hash,
            multisig_accounts: value.multisig_accounts,
            local_note_openings: value.local_note_openings,
            poseidon2_v8: value.poseidon2_v8,
            poseidon2_v8_reservations: value.poseidon2_v8_reservations,
            htlc_swaps: value.htlc_swaps,
            poseidon2_v8_treasuries: value
                .poseidon2_v8_treasuries
                .into_iter()
                .map(Into::into)
                .collect(),
            native_launch_context: value.native_launch_context,
            native_rp06_transfers: value.native_rp06_transfers,
            private_spend_issued: Default::default(),
            private_spend_notes: Vec::new(),
            private_spend_templates: Vec::new(),
            private_spend_attempts: Vec::new(),
            private_spend_relation_digest: None,
            asset_spend: Default::default(),
            recovery: Default::default(),
        }
    }
}

/// Exact V12 payload. Keep this positional encrypted-wallet shape frozen.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletStateV12 {
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
    #[serde(default)]
    commitment_sources: Vec<NoteSource>,
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
    #[serde(with = "frozen_v17_mirror_codec")]
    poseidon2_v8: Poseidon2V8WalletState,
    poseidon2_v8_reservations: Vec<StoredPoseidon2V8Reservation>,
}

impl From<WalletStateV12> for WalletState {
    fn from(value: WalletStateV12) -> Self {
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
            commitment_sources: value.commitment_sources,
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: value.outgoing_disclosures,
            genesis_hash: value.genesis_hash,
            multisig_accounts: value.multisig_accounts,
            local_note_openings: value.local_note_openings,
            poseidon2_v8: value.poseidon2_v8,
            poseidon2_v8_reservations: value.poseidon2_v8_reservations,
            htlc_swaps: Vec::new(),
            poseidon2_v8_treasuries: Vec::new(),
            native_launch_context: None,
            native_rp06_transfers: Vec::new(),
            private_spend_issued: Default::default(),
            private_spend_notes: Vec::new(),
            private_spend_templates: Vec::new(),
            private_spend_attempts: Vec::new(),
            private_spend_relation_digest: None,
            asset_spend: Default::default(),
            recovery: Default::default(),
        }
    }
}

/// Exact V11 payload. Do not append fields to this frozen bincode shape.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletStateV11 {
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
    recent: Vec<RecentTransaction>,
    #[serde(with = "serde_vec_bytes48")]
    commitments: Vec<Commitment>,
    commitment_sources: Vec<NoteSource>,
    next_commitment_index: u64,
    next_ciphertext_index: u64,
    last_synced_height: u64,
    #[serde(with = "serde_option_bytes32")]
    last_synced_block_hash: Option<[u8; 32]>,
    outgoing_disclosures: Vec<OutgoingDisclosureRecord>,
    #[serde(with = "serde_option_bytes32")]
    genesis_hash: Option<[u8; 32]>,
    multisig_accounts: Vec<MultisigAccountRecord>,
    local_note_openings: Vec<LocalNoteOpeningRecord>,
    #[serde(with = "frozen_v17_mirror_codec")]
    poseidon2_v8: Poseidon2V8WalletState,
}

impl From<WalletStateV11> for WalletState {
    fn from(value: WalletStateV11) -> Self {
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
            commitment_sources: value.commitment_sources,
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: value.outgoing_disclosures,
            genesis_hash: value.genesis_hash,
            multisig_accounts: value.multisig_accounts,
            local_note_openings: value.local_note_openings,
            poseidon2_v8: value.poseidon2_v8,
            poseidon2_v8_reservations: Vec::new(),
            htlc_swaps: Vec::new(),
            poseidon2_v8_treasuries: Vec::new(),
            native_launch_context: None,
            native_rp06_transfers: Vec::new(),
            private_spend_issued: Default::default(),
            private_spend_notes: Vec::new(),
            private_spend_templates: Vec::new(),
            private_spend_attempts: Vec::new(),
            private_spend_relation_digest: None,
            asset_spend: Default::default(),
            recovery: Default::default(),
        }
    }
}

/// Exact encrypted-wallet V10 payload, before the V8 seven-limb mirror was
/// added. Keep this positional bincode shape frozen for migration.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletStateV10 {
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
    #[serde(default)]
    commitment_sources: Vec<NoteSource>,
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
    multisig_accounts: Vec<MultisigAccountRecord>,
    #[serde(default)]
    local_note_openings: Vec<LocalNoteOpeningRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletStateV9 {
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
    pending: Vec<LegacyPendingTransaction32>,
    #[serde(default)]
    recent: Vec<LegacyRecentTransaction32>,
    #[serde(with = "serde_vec_bytes48")]
    commitments: Vec<Commitment>,
    #[serde(default)]
    commitment_sources: Vec<NoteSource>,
    next_commitment_index: u64,
    next_ciphertext_index: u64,
    last_synced_height: u64,
    #[serde(default, with = "serde_option_bytes32")]
    last_synced_block_hash: Option<[u8; 32]>,
    #[serde(default)]
    outgoing_disclosures: Vec<LegacyOutgoingDisclosureRecord32>,
    #[serde(default, with = "serde_option_bytes32")]
    genesis_hash: Option<[u8; 32]>,
    #[serde(default)]
    multisig_accounts: Vec<MultisigAccountRecord>,
    #[serde(default)]
    local_note_openings: Vec<LocalNoteOpeningRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletStateV9BeforeNoteSources {
    mode: WalletMode,
    tree_depth: u32,
    #[serde(with = "serde_option_bytes32")]
    root_secret: Option<[u8; 32]>,
    derived: Option<DerivedKeys>,
    incoming: IncomingViewingKey,
    full_viewing_key: Option<FullViewingKey>,
    outgoing: Option<OutgoingViewingKey>,
    next_address_index: u32,
    notes: Vec<TrackedNoteBeforeNoteSource>,
    pending: Vec<LegacyPendingTransaction32>,
    #[serde(default)]
    recent: Vec<LegacyRecentTransaction32>,
    #[serde(with = "serde_vec_bytes48")]
    commitments: Vec<Commitment>,
    next_commitment_index: u64,
    next_ciphertext_index: u64,
    last_synced_height: u64,
    #[serde(default, with = "serde_option_bytes32")]
    last_synced_block_hash: Option<[u8; 32]>,
    #[serde(default)]
    outgoing_disclosures: Vec<LegacyOutgoingDisclosureRecord32>,
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
    notes: Vec<TrackedNoteBeforeNoteSource>,
    pending: Vec<LegacyPendingTransaction32>,
    #[serde(default)]
    recent: Vec<LegacyRecentTransaction32>,
    #[serde(with = "serde_vec_bytes48")]
    commitments: Vec<Commitment>,
    next_commitment_index: u64,
    next_ciphertext_index: u64,
    last_synced_height: u64,
    #[serde(default, with = "serde_option_bytes32")]
    last_synced_block_hash: Option<[u8; 32]>,
    #[serde(default)]
    outgoing_disclosures: Vec<LegacyOutgoingDisclosureRecord32>,
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
    notes: Vec<TrackedNoteBeforeNoteSource>,
    pending: Vec<LegacyPendingTransaction32>,
    #[serde(default)]
    recent: Vec<LegacyRecentTransaction32>,
    #[serde(with = "serde_vec_bytes48")]
    commitments: Vec<Commitment>,
    next_commitment_index: u64,
    next_ciphertext_index: u64,
    last_synced_height: u64,
    #[serde(default, with = "serde_option_bytes32")]
    last_synced_block_hash: Option<[u8; 32]>,
    #[serde(default)]
    outgoing_disclosures: Vec<LegacyOutgoingDisclosureRecord32>,
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
    notes: Vec<TrackedNoteBeforeNoteSource>,
    pending: Vec<LegacyPendingTransaction32>,
    #[serde(default)]
    recent: Vec<LegacyRecentTransaction32>,
    #[serde(with = "serde_vec_bytes48")]
    commitments: Vec<Commitment>,
    next_commitment_index: u64,
    next_ciphertext_index: u64,
    last_synced_height: u64,
    #[serde(default, with = "serde_option_bytes32")]
    last_synced_block_hash: Option<[u8; 32]>,
    #[serde(default)]
    outgoing_disclosures: Vec<LegacyOutgoingDisclosureRecord32>,
    #[serde(default, with = "serde_option_bytes32")]
    genesis_hash: Option<[u8; 32]>,
}

fn reject_unrecoverable_legacy_action_ids(
    version: u32,
    pending: usize,
    recent: usize,
    outgoing_disclosures: usize,
) -> Result<(), WalletError> {
    if pending == 0 && recent == 0 && outgoing_disclosures == 0 {
        return Ok(());
    }
    Err(WalletError::Serialization(format!(
        "legacy wallet v{version} contains {pending} pending, {recent} recent, and {outgoing_disclosures} disclosure records with 32-byte transaction ids; canonical 48-byte action ids cannot be recovered"
    )))
}

impl From<WalletStateV10> for WalletState {
    fn from(value: WalletStateV10) -> Self {
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
            commitment_sources: value.commitment_sources,
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: value.outgoing_disclosures,
            genesis_hash: value.genesis_hash,
            multisig_accounts: value.multisig_accounts,
            local_note_openings: value.local_note_openings,
            poseidon2_v8: Poseidon2V8WalletState::default(),
            poseidon2_v8_reservations: Vec::new(),
            htlc_swaps: Vec::new(),
            poseidon2_v8_treasuries: Vec::new(),
            native_launch_context: None,
            native_rp06_transfers: Vec::new(),
            private_spend_issued: Default::default(),
            private_spend_notes: Vec::new(),
            private_spend_templates: Vec::new(),
            private_spend_attempts: Vec::new(),
            private_spend_relation_digest: None,
            asset_spend: Default::default(),
            recovery: Default::default(),
        }
    }
}

impl TryFrom<WalletStateV9> for WalletState {
    type Error = WalletError;

    fn try_from(value: WalletStateV9) -> Result<Self, Self::Error> {
        reject_unrecoverable_legacy_action_ids(
            LEGACY_FILE_VERSION_V9,
            value.pending.len(),
            value.recent.len(),
            value.outgoing_disclosures.len(),
        )?;
        Ok(Self {
            mode: value.mode,
            tree_depth: value.tree_depth,
            root_secret: value.root_secret,
            derived: value.derived,
            incoming: value.incoming,
            full_viewing_key: value.full_viewing_key,
            outgoing: value.outgoing,
            next_address_index: value.next_address_index,
            notes: value.notes,
            pending: Vec::new(),
            recent: Vec::new(),
            commitments: value.commitments,
            commitment_sources: value.commitment_sources,
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: Vec::new(),
            genesis_hash: value.genesis_hash,
            multisig_accounts: value.multisig_accounts,
            local_note_openings: value.local_note_openings,
            poseidon2_v8: Poseidon2V8WalletState::default(),
            poseidon2_v8_reservations: Vec::new(),
            htlc_swaps: Vec::new(),
            poseidon2_v8_treasuries: Vec::new(),
            native_launch_context: None,
            native_rp06_transfers: Vec::new(),
            private_spend_issued: Default::default(),
            private_spend_notes: Vec::new(),
            private_spend_templates: Vec::new(),
            private_spend_attempts: Vec::new(),
            private_spend_relation_digest: None,
            asset_spend: Default::default(),
            recovery: Default::default(),
        })
    }
}

impl TryFrom<WalletStateV9BeforeNoteSources> for WalletState {
    type Error = WalletError;

    fn try_from(value: WalletStateV9BeforeNoteSources) -> Result<Self, Self::Error> {
        reject_unrecoverable_legacy_action_ids(
            LEGACY_FILE_VERSION_V9,
            value.pending.len(),
            value.recent.len(),
            value.outgoing_disclosures.len(),
        )?;
        Ok(Self {
            mode: value.mode,
            tree_depth: value.tree_depth,
            root_secret: value.root_secret,
            derived: value.derived,
            incoming: value.incoming,
            full_viewing_key: value.full_viewing_key,
            outgoing: value.outgoing,
            next_address_index: value.next_address_index,
            notes: value.notes.into_iter().map(TrackedNote::from).collect(),
            pending: Vec::new(),
            recent: Vec::new(),
            commitments: value.commitments,
            commitment_sources: Vec::new(),
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: Vec::new(),
            genesis_hash: value.genesis_hash,
            multisig_accounts: value.multisig_accounts,
            local_note_openings: value.local_note_openings,
            poseidon2_v8: Poseidon2V8WalletState::default(),
            poseidon2_v8_reservations: Vec::new(),
            htlc_swaps: Vec::new(),
            poseidon2_v8_treasuries: Vec::new(),
            native_launch_context: None,
            native_rp06_transfers: Vec::new(),
            private_spend_issued: Default::default(),
            private_spend_notes: Vec::new(),
            private_spend_templates: Vec::new(),
            private_spend_attempts: Vec::new(),
            private_spend_relation_digest: None,
            asset_spend: Default::default(),
            recovery: Default::default(),
        })
    }
}

impl TryFrom<WalletStateV6> for WalletState {
    type Error = WalletError;

    fn try_from(value: WalletStateV6) -> Result<Self, Self::Error> {
        reject_unrecoverable_legacy_action_ids(
            LEGACY_FILE_VERSION_V6,
            value.pending.len(),
            value.recent.len(),
            value.outgoing_disclosures.len(),
        )?;
        Ok(Self {
            mode: value.mode,
            tree_depth: value.tree_depth,
            root_secret: value.root_secret,
            derived: value.derived,
            incoming: value.incoming,
            full_viewing_key: value.full_viewing_key,
            outgoing: value.outgoing,
            next_address_index: value.next_address_index,
            notes: value.notes.into_iter().map(TrackedNote::from).collect(),
            pending: Vec::new(),
            recent: Vec::new(),
            commitments: value.commitments,
            commitment_sources: Vec::new(),
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: Vec::new(),
            genesis_hash: value.genesis_hash,
            multisig_accounts: Vec::new(),
            local_note_openings: Vec::new(),
            poseidon2_v8: Poseidon2V8WalletState::default(),
            poseidon2_v8_reservations: Vec::new(),
            htlc_swaps: Vec::new(),
            poseidon2_v8_treasuries: Vec::new(),
            native_launch_context: None,
            native_rp06_transfers: Vec::new(),
            private_spend_issued: Default::default(),
            private_spend_notes: Vec::new(),
            private_spend_templates: Vec::new(),
            private_spend_attempts: Vec::new(),
            private_spend_relation_digest: None,
            asset_spend: Default::default(),
            recovery: Default::default(),
        })
    }
}

impl TryFrom<WalletStateV8> for WalletState {
    type Error = WalletError;

    fn try_from(value: WalletStateV8) -> Result<Self, Self::Error> {
        reject_unrecoverable_legacy_action_ids(
            LEGACY_FILE_VERSION_V8,
            value.pending.len(),
            value.recent.len(),
            value.outgoing_disclosures.len(),
        )?;
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
        Ok(Self {
            mode: value.mode,
            tree_depth: value.tree_depth,
            root_secret: value.root_secret,
            derived: value.derived,
            incoming: value.incoming,
            full_viewing_key: value.full_viewing_key,
            outgoing: value.outgoing,
            next_address_index: value.next_address_index,
            notes: value.notes.into_iter().map(TrackedNote::from).collect(),
            pending: Vec::new(),
            recent: Vec::new(),
            commitments: value.commitments,
            commitment_sources: Vec::new(),
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: Vec::new(),
            genesis_hash: value.genesis_hash,
            multisig_accounts: Vec::new(),
            local_note_openings,
            poseidon2_v8: Poseidon2V8WalletState::default(),
            poseidon2_v8_reservations: Vec::new(),
            htlc_swaps: Vec::new(),
            poseidon2_v8_treasuries: Vec::new(),
            native_launch_context: None,
            native_rp06_transfers: Vec::new(),
            private_spend_issued: Default::default(),
            private_spend_notes: Vec::new(),
            private_spend_templates: Vec::new(),
            private_spend_attempts: Vec::new(),
            private_spend_relation_digest: None,
            asset_spend: Default::default(),
            recovery: Default::default(),
        })
    }
}

impl TryFrom<WalletStateV7> for WalletState {
    type Error = WalletError;

    fn try_from(value: WalletStateV7) -> Result<Self, Self::Error> {
        reject_unrecoverable_legacy_action_ids(
            LEGACY_FILE_VERSION_V7,
            value.pending.len(),
            value.recent.len(),
            value.outgoing_disclosures.len(),
        )?;
        Ok(Self {
            mode: value.mode,
            tree_depth: value.tree_depth,
            root_secret: value.root_secret,
            derived: value.derived,
            incoming: value.incoming,
            full_viewing_key: value.full_viewing_key,
            outgoing: value.outgoing,
            next_address_index: value.next_address_index,
            notes: value.notes.into_iter().map(TrackedNote::from).collect(),
            pending: Vec::new(),
            recent: Vec::new(),
            commitments: value.commitments,
            commitment_sources: Vec::new(),
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: Vec::new(),
            genesis_hash: value.genesis_hash,
            multisig_accounts: Vec::new(),
            local_note_openings: Vec::new(),
            poseidon2_v8: Poseidon2V8WalletState::default(),
            poseidon2_v8_reservations: Vec::new(),
            htlc_swaps: Vec::new(),
            poseidon2_v8_treasuries: Vec::new(),
            native_launch_context: None,
            native_rp06_transfers: Vec::new(),
            private_spend_issued: Default::default(),
            private_spend_notes: Vec::new(),
            private_spend_templates: Vec::new(),
            private_spend_attempts: Vec::new(),
            private_spend_relation_digest: None,
            asset_spend: Default::default(),
            recovery: Default::default(),
        })
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
    #[serde(default)]
    source: NoteSource,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TrackedNoteBeforeNoteSource {
    note: RecoveredNote,
    position: u64,
    ciphertext_index: u64,
    #[serde(with = "serde_option_bytes48")]
    nullifier: Option<[u8; 48]>,
    spent: bool,
    pending_spend: bool,
}

impl From<TrackedNoteBeforeNoteSource> for TrackedNote {
    fn from(value: TrackedNoteBeforeNoteSource) -> Self {
        Self {
            note: value.note,
            position: value.position,
            ciphertext_index: value.ciphertext_index,
            nullifier: value.nullifier,
            spent: value.spent,
            pending_spend: value.pending_spend,
            source: NoteSource::Unknown,
        }
    }
}

impl From<TrackedNote> for TrackedNoteBeforeNoteSource {
    fn from(value: TrackedNote) -> Self {
        Self {
            note: value.note,
            position: value.position,
            ciphertext_index: value.ciphertext_index,
            nullifier: value.nullifier,
            spent: value.spent,
            pending_spend: value.pending_spend,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LegacyPendingTransaction32 {
    #[serde(with = "serde_bytes32")]
    tx_id: [u8; 32],
    #[serde(with = "serde_vec_bytes48")]
    nullifiers: Vec<[u8; 48]>,
    spent_note_indexes: Vec<usize>,
    submitted_at: u64,
    status: PendingStatus,
    #[serde(default)]
    recipients: Vec<TransferRecipient>,
    #[serde(default)]
    fee: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LegacyRecentTransaction32 {
    #[serde(with = "serde_bytes32")]
    tx_id: [u8; 32],
    submitted_at: u64,
    mined_height: u64,
    #[serde(default)]
    recipients: Vec<TransferRecipient>,
    #[serde(default)]
    fee: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LegacyOutgoingDisclosureRecord32 {
    #[serde(with = "serde_bytes32")]
    tx_id: [u8; 32],
    output_index: u32,
    recipient_address: String,
    note: NoteData,
    #[serde(with = "serde_bytes48")]
    commitment: [u8; 48],
    #[serde(default)]
    memo: Option<MemoPlaintext>,
    #[serde(with = "serde_bytes32")]
    genesis_hash: [u8; 32],
    created_at: u64,
}

/// Wallet-local identity for a submission record.
///
/// A canonical id came from the node's exact 48-byte action response. A
/// provisional id exists only when submission outcome is ambiguous. Keeping
/// the variants distinct prevents a local placeholder from entering methods
/// that require a consensus [`ActionId48`].
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WalletTransactionId {
    Canonical(#[serde(with = "serde_action_id48")] ActionId48),
    Provisional(#[serde(with = "serde_provisional_action_id48")] ProvisionalActionId48),
}

impl WalletTransactionId {
    pub const fn as_bytes(&self) -> &[u8; 48] {
        match self {
            Self::Canonical(value) => value.as_bytes(),
            Self::Provisional(value) => value.as_bytes(),
        }
    }

    pub const fn canonical(self) -> Option<ActionId48> {
        match self {
            Self::Canonical(value) => Some(value),
            Self::Provisional(_) => None,
        }
    }

    pub const fn is_provisional(self) -> bool {
        matches!(self, Self::Provisional(_))
    }

    /// Render an external identifier without allowing a provisional value to
    /// masquerade as canonical hexadecimal input.
    pub fn external_id(self) -> String {
        let encoded = hex::encode(self.as_bytes());
        match self {
            Self::Canonical(_) => encoded,
            Self::Provisional(_) => format!("provisional:{encoded}"),
        }
    }

    /// As [`Self::external_id`], retaining the walletd convention that
    /// canonical identifiers carry an `0x` prefix.
    pub fn external_id_with_0x(self) -> String {
        let encoded = hex::encode(self.as_bytes());
        match self {
            Self::Canonical(_) => format!("0x{encoded}"),
            Self::Provisional(_) => format!("provisional:0x{encoded}"),
        }
    }
}

impl PartialEq<ActionId48> for WalletTransactionId {
    fn eq(&self, other: &ActionId48) -> bool {
        matches!(self, Self::Canonical(value) if value == other)
    }
}

impl PartialEq<WalletTransactionId> for ActionId48 {
    fn eq(&self, other: &WalletTransactionId) -> bool {
        other == self
    }
}

impl PartialEq<ProvisionalActionId48> for WalletTransactionId {
    fn eq(&self, other: &ProvisionalActionId48) -> bool {
        matches!(self, Self::Provisional(value) if value == other)
    }
}

impl PartialEq<WalletTransactionId> for ProvisionalActionId48 {
    fn eq(&self, other: &WalletTransactionId) -> bool {
        other == self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingTransaction {
    pub tx_id: WalletTransactionId,
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
    pub tx_id: WalletTransactionId,
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
    pub tx_id: WalletTransactionId,
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
    pub source: NoteSource,
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

mod serde_action_id48 {
    use hegemon_hash384::ActionId48;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &ActionId48, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value.as_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ActionId48, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        ActionId48::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

mod serde_provisional_action_id48 {
    use crate::submission::ProvisionalActionId48;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &ProvisionalActionId48, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value.as_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ProvisionalActionId48, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let bytes = <[u8; 48]>::try_from(bytes.as_slice())
            .map_err(|_| serde::de::Error::custom("invalid 48-byte provisional action id"))?;
        Ok(ProvisionalActionId48::new(bytes))
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
fn legacy_test_fixture_v11(state: &WalletState) -> WalletStateV11 {
    WalletStateV11 {
        mode: state.mode.clone(),
        tree_depth: state.tree_depth.clone(),
        root_secret: state.root_secret.clone(),
        derived: state.derived.clone(),
        incoming: state.incoming.clone(),
        full_viewing_key: state.full_viewing_key.clone(),
        outgoing: state.outgoing.clone(),
        next_address_index: state.next_address_index.clone(),
        notes: state.notes.clone(),
        pending: state.pending.clone(),
        recent: state.recent.clone(),
        commitments: state.commitments.clone(),
        commitment_sources: state.commitment_sources.clone(),
        next_commitment_index: state.next_commitment_index.clone(),
        next_ciphertext_index: state.next_ciphertext_index.clone(),
        last_synced_height: state.last_synced_height.clone(),
        last_synced_block_hash: state.last_synced_block_hash.clone(),
        outgoing_disclosures: state.outgoing_disclosures.clone(),
        genesis_hash: state.genesis_hash.clone(),
        multisig_accounts: state.multisig_accounts.clone(),
        local_note_openings: state.local_note_openings.clone(),
        poseidon2_v8: state.poseidon2_v8.clone(),
    }
}

#[cfg(test)]
fn legacy_test_fixture_v12(state: &WalletState) -> WalletStateV12 {
    WalletStateV12 {
        mode: state.mode.clone(),
        tree_depth: state.tree_depth.clone(),
        root_secret: state.root_secret.clone(),
        derived: state.derived.clone(),
        incoming: state.incoming.clone(),
        full_viewing_key: state.full_viewing_key.clone(),
        outgoing: state.outgoing.clone(),
        next_address_index: state.next_address_index.clone(),
        notes: state.notes.clone(),
        pending: state.pending.clone(),
        recent: state.recent.clone(),
        commitments: state.commitments.clone(),
        commitment_sources: state.commitment_sources.clone(),
        next_commitment_index: state.next_commitment_index.clone(),
        next_ciphertext_index: state.next_ciphertext_index.clone(),
        last_synced_height: state.last_synced_height.clone(),
        last_synced_block_hash: state.last_synced_block_hash.clone(),
        outgoing_disclosures: state.outgoing_disclosures.clone(),
        genesis_hash: state.genesis_hash.clone(),
        multisig_accounts: state.multisig_accounts.clone(),
        local_note_openings: state.local_note_openings.clone(),
        poseidon2_v8: state.poseidon2_v8.clone(),
        poseidon2_v8_reservations: state.poseidon2_v8_reservations.clone(),
    }
}

#[cfg(test)]
fn legacy_test_fixture_v13(state: &WalletState) -> WalletStateV13 {
    assert!(state.poseidon2_v8_treasuries.is_empty());
    WalletStateV13 {
        mode: state.mode.clone(),
        tree_depth: state.tree_depth.clone(),
        root_secret: state.root_secret.clone(),
        derived: state.derived.clone(),
        incoming: state.incoming.clone(),
        full_viewing_key: state.full_viewing_key.clone(),
        outgoing: state.outgoing.clone(),
        next_address_index: state.next_address_index.clone(),
        notes: state.notes.clone(),
        pending: state.pending.clone(),
        recent: state.recent.clone(),
        commitments: state.commitments.clone(),
        commitment_sources: state.commitment_sources.clone(),
        next_commitment_index: state.next_commitment_index.clone(),
        next_ciphertext_index: state.next_ciphertext_index.clone(),
        last_synced_height: state.last_synced_height.clone(),
        last_synced_block_hash: state.last_synced_block_hash.clone(),
        outgoing_disclosures: state.outgoing_disclosures.clone(),
        genesis_hash: state.genesis_hash.clone(),
        multisig_accounts: state.multisig_accounts.clone(),
        local_note_openings: state.local_note_openings.clone(),
        poseidon2_v8: state.poseidon2_v8.clone(),
        poseidon2_v8_reservations: state.poseidon2_v8_reservations.clone(),
        htlc_swaps: state.htlc_swaps.clone(),
        poseidon2_v8_treasuries: Vec::new(),
        native_launch_context: state.native_launch_context.clone(),
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

    #[test]
    fn v8_reservation_writer_lock_allows_read_only_snapshot_without_mutations() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.dat");
        let writer = WalletStore::create_full(&path, "passphrase").unwrap();
        writer.next_address().unwrap();
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            WalletStore::open(&path, "passphrase"),
            Err(WalletError::StoreBusy)
        ));
        assert!(matches!(
            WalletStore::create_full(&path, "passphrase"),
            Err(WalletError::StoreBusy)
        ));
        let snapshot = WalletStore::open_read_only(&path, "passphrase").unwrap();
        assert_eq!(
            snapshot
                .with_state(|state| Ok(state.next_address_index))
                .unwrap(),
            1
        );
        assert!(snapshot.next_address().is_err());
        assert!(snapshot.reset_sync_state().is_err());
        assert!(snapshot.reserve_poseidon2_v8_spend().is_err());
        assert_eq!(
            snapshot
                .with_state(|state| Ok(state.next_address_index))
                .unwrap(),
            1
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(matches!(
            WalletStore::open_read_only(&path, "wrong password"),
            Err(WalletError::DecryptionFailure)
        ));
        drop(writer);
        let reopened = WalletStore::open(&path, "passphrase").unwrap();
        reopened.next_address().unwrap();
    }

    #[test]
    fn create_full_if_missing_preserves_existing_store_and_respects_writer_lock() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.dat");
        let writer = WalletStore::create_full(&path, "passphrase").unwrap();
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            WalletStore::create_full_if_missing(&path, "passphrase"),
            Err(WalletError::StoreBusy)
        ));
        drop(writer);

        assert!(matches!(
            WalletStore::create_full_if_missing(&path, "passphrase"),
            Err(WalletError::StoreAlreadyExists)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        let reopened = WalletStore::open(&path, "passphrase").unwrap();
        assert!(reopened.next_address().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn v8_reservation_writer_rejects_final_component_symlink_alias() {
        use std::os::unix::fs::symlink;
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.dat");
        let writer = WalletStore::create_full(&path, "passphrase").unwrap();
        let alias = directory.path().join("alias.dat");
        symlink(&path, &alias).unwrap();
        assert!(matches!(
            WalletStore::open(&alias, "passphrase"),
            Err(WalletError::InvalidArgument(_))
        ));
        assert!(fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink());
        let lock_permissions = fs::metadata(directory.path().join("wallet.dat.lock"))
            .unwrap()
            .permissions();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(lock_permissions.mode() & 0o777, 0o600);
        drop(writer);
    }

    #[test]
    fn v14_exact_v13_migration_preserves_launch_identity_and_key_bytes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet-v13");
        let store =
            WalletStore::create_from_root(&path, "passphrase", RootSecret::from_bytes([0x73; 32]))
                .unwrap();
        store.next_address().unwrap();
        let context = crate::poseidon2_v8_sync::LaunchWalletContext::new(
            [0x31; 32], [0x32; 32], [0x33; 64], 1, 100,
        )
        .unwrap();
        store
            .ensure_poseidon2_v8_launch_genesis_for_retained_test(context, [1, 2, 3, 4, 5, 6, 7])
            .unwrap();
        let expected_tip = store.poseidon2_v8_tip().unwrap();
        let legacy = store
            .with_state(|state| Ok(legacy_test_fixture_v13(state)))
            .unwrap();
        let plaintext = bincode::serialize(&legacy).unwrap();
        let migrated = deserialize_wallet_state_v13(&plaintext).unwrap();
        assert_eq!(migrated.next_address_index, 1);
        assert!(migrated.native_rp06_transfers.is_empty());
        assert_eq!(
            migrated
                .native_launch_context
                .unwrap()
                .current_context()
                .unwrap(),
            context
        );
        let mut trailing = plaintext.clone();
        trailing.push(0);
        assert!(deserialize_wallet_state_v13(&trailing).is_err());
        assert!(deserialize_wallet_state(&plaintext).is_err());
        let nonce = [0x27; NONCE_LEN];
        let ciphertext = ChaCha20Poly1305::new(&store.key.into())
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plaintext,
                    aad: &store.salt,
                },
            )
            .unwrap();
        let file = WalletFile {
            version: LEGACY_FILE_VERSION_V13,
            salt: store.salt,
            nonce,
            ciphertext,
        };
        write_private_file(&path, &bincode::serialize(&file).unwrap()).unwrap();
        let before = fs::read(&path).unwrap();
        let snapshot = WalletStore::open_read_only(&path, "passphrase").unwrap();
        assert_eq!(snapshot.launch_context().unwrap(), context);
        assert_eq!(snapshot.signing_seed().unwrap(), [0x73; 32]);
        assert_eq!(fs::read(&path).unwrap(), before);
        drop(snapshot);
        drop(store);
        let reopened = WalletStore::open_read_only(&path, "passphrase").unwrap();
        assert_eq!(reopened.signing_seed().unwrap(), [0x73; 32]);
        assert_eq!(reopened.poseidon2_v8_tip().unwrap(), expected_tip);
        assert_eq!(reopened.launch_context().unwrap(), context);
        assert!(reopened.rp06_transfer_candidate_ids().unwrap().is_empty());
        assert_eq!(
            deserialize_exact::<WalletFile>(&fs::read(path).unwrap())
                .unwrap()
                .version,
            LEGACY_FILE_VERSION_V13
        );
    }

    #[test]
    fn v15_migrates_v14_wallet_payload() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet-v14");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        store.next_address().unwrap();
        let descriptor = crate::poseidon2_v8_multisig::V8TreasuryDescriptor {
            chain_id: [1; 32],
            account_id: [2; 32],
            policy_root: [3; 7],
            policy_nullifier_key: [4; 5],
            signer_tags: [[5; 7]; 6],
            receive_address: crate::address::ShieldedAddress::default(),
        };
        let old_plan = crate::poseidon2_v8_multisig::V8TreasuryPlanV14 {
            account_id: descriptor.account_id,
            source_commitment: [6; 7],
            source_position: 7,
            source_note_words: vec![8; 18],
            recipient_address: crate::address::ShieldedAddress::default(),
            public_words: vec![9; 10],
            output_note_words: [vec![10; 18], vec![11; 18]],
            output_ciphertexts: [Some(vec![12; 13]), Some(vec![14; 15])],
            intent_digest: [16; 7],
        };
        let converted_plan: crate::poseidon2_v8_multisig::V8TreasuryPlan = old_plan.clone().into();
        let old_review_digest = converted_plan.review_digest().unwrap();
        let retained_attempt = crate::poseidon2_v8_multisig::V8TreasuryAttempt {
            review_digest: old_review_digest.to_vec(),
            nullifiers: vec![[17; 7], [18; 7]],
            ordinary_note_refs: vec![([19; 7], 20)],
            policy_note_refs: vec![([21; 7], 22)],
            status: crate::poseidon2_v8_multisig::V8TreasuryAttemptStatus::SubmissionUncertain,
            action_id: Some(vec![23; 48]),
            mined_in: Some((24, [25; 32])),
            material_snapshot: Some(crate::poseidon2_v8_multisig::V8TreasuryMaterialSnapshot {
                public_words: vec![26; 27],
                witness_words: vec![28; 29],
                inline_ciphertext_bytes: vec![30; 31],
            }),
            candidate_inline: Some(vec![32; 33]),
        };
        let old_treasury = crate::poseidon2_v8_multisig::StoredV8TreasuryV14 {
            descriptor: descriptor.clone(),
            notes: vec![crate::poseidon2_v8_multisig::V8TreasuryNote {
                commitment: [34; 7],
                note_words: vec![35; 18],
                kind: crate::poseidon2_v8_multisig::V8TreasuryNoteKind::Value,
            }],
            plans: vec![old_plan],
            attempts: vec![retained_attempt.clone()],
        };
        let expected_treasury: crate::poseidon2_v8_multisig::StoredV8Treasury =
            old_treasury.clone().into();
        let plaintext = store
            .with_state(|state| {
                let legacy = WalletStateV14 {
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
                    commitment_sources: state.commitment_sources.clone(),
                    next_commitment_index: state.next_commitment_index,
                    next_ciphertext_index: state.next_ciphertext_index,
                    last_synced_height: state.last_synced_height,
                    last_synced_block_hash: state.last_synced_block_hash,
                    outgoing_disclosures: state.outgoing_disclosures.clone(),
                    genesis_hash: state.genesis_hash,
                    multisig_accounts: state.multisig_accounts.clone(),
                    local_note_openings: state.local_note_openings.clone(),
                    poseidon2_v8: state.poseidon2_v8.clone(),
                    poseidon2_v8_reservations: state.poseidon2_v8_reservations.clone(),
                    htlc_swaps: state.htlc_swaps.clone(),
                    poseidon2_v8_treasuries: vec![old_treasury],
                    native_launch_context: state.native_launch_context.clone(),
                    native_rp06_transfers: state.native_rp06_transfers.clone(),
                };
                Ok(bincode::serialize(&legacy)?)
            })
            .unwrap();
        let nonce = [0x52; NONCE_LEN];
        let ciphertext = ChaCha20Poly1305::new(&store.key.into())
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plaintext,
                    aad: &store.salt,
                },
            )
            .unwrap();
        let file = WalletFile {
            version: LEGACY_FILE_VERSION_V14,
            salt: store.salt,
            nonce,
            ciphertext,
        };
        write_private_file(&path, &bincode::serialize(&file).unwrap()).unwrap();
        drop(store);
        let migrated = WalletStore::open_read_only(&path, "passphrase").unwrap();
        assert_eq!(
            migrated
                .with_state(|state| Ok(state.next_address_index))
                .unwrap(),
            1
        );
        let records = migrated
            .with_state(|state| Ok(state.poseidon2_v8_treasuries.clone()))
            .unwrap();
        assert_eq!(records, vec![expected_treasury.clone()]);
        assert_eq!(records[0].notes.len(), 1);
        assert_eq!(
            records[0].plans[0].review_digest().unwrap(),
            old_review_digest
        );
        assert_eq!(records[0].attempts, vec![retained_attempt]);
        assert_eq!(records[0].attempts[0].nullifiers, vec![[17; 7], [18; 7]]);
        drop(migrated);
        let reopened = WalletStore::open_read_only(&path, "passphrase").unwrap();
        let persisted = reopened
            .with_state(|state| Ok(state.poseidon2_v8_treasuries.clone()))
            .unwrap();
        assert_eq!(persisted, vec![expected_treasury]);
        assert_eq!(
            deserialize_exact::<WalletFile>(&fs::read(path).unwrap())
                .unwrap()
                .version,
            LEGACY_FILE_VERSION_V14
        );
    }

    #[test]
    fn htlc_v12_migration_preserves_wallet_and_rejects_trailing_payload() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.dat");
        let store =
            WalletStore::create_from_root(&path, "passphrase", RootSecret::from_bytes([0x63; 32]))
                .unwrap();
        store.next_address().unwrap();
        let legacy = store
            .with_state(|state| Ok(legacy_test_fixture_v12(state)))
            .unwrap();
        let plaintext = bincode::serialize(&legacy).unwrap();
        let migrated = deserialize_wallet_state_v12(&plaintext).unwrap();
        assert!(migrated.htlc_swaps.is_empty());
        assert!(migrated.poseidon2_v8_treasuries.is_empty());
        assert_eq!(migrated.next_address_index, 1);
        let mut trailing = plaintext.clone();
        trailing.push(0);
        assert!(deserialize_wallet_state_v12(&trailing).is_err());
        assert!(deserialize_wallet_state(&plaintext).is_err());
        let nonce = [0x24; NONCE_LEN];
        let ciphertext = ChaCha20Poly1305::new(&store.key.into())
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plaintext,
                    aad: &store.salt,
                },
            )
            .unwrap();
        let file = WalletFile {
            version: LEGACY_FILE_VERSION_V12,
            salt: store.salt,
            nonce,
            ciphertext,
        };
        write_private_file(&path, &bincode::serialize(&file).unwrap()).unwrap();
        let original = fs::read(&path).unwrap();
        let snapshot = WalletStore::open_read_only(&path, "passphrase").unwrap();
        assert_eq!(snapshot.signing_seed().unwrap(), [0x63; 32]);
        assert_eq!(fs::read(&path).unwrap(), original);
        drop(snapshot);
        drop(store);
        let reopened = WalletStore::open_read_only(&path, "passphrase").unwrap();
        assert_eq!(reopened.signing_seed().unwrap(), [0x63; 32]);
        assert!(reopened.htlc_swaps().unwrap().is_empty());
        assert_eq!(
            deserialize_exact::<WalletFile>(&fs::read(path).unwrap())
                .unwrap()
                .version,
            LEGACY_FILE_VERSION_V12
        );
    }

    #[test]
    fn v8_reservation_v11_bincode_migration_preserves_mirror_and_key_bytes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.dat");
        let root = RootSecret::from_bytes([0x61; 32]);
        let store = WalletStore::create_from_root(&path, "passphrase", root).unwrap();
        store.next_address().unwrap();
        store
            .ensure_poseidon2_v8_genesis_for_test([0x41; 32], [1, 2, 3, 4, 5, 6, 7])
            .unwrap();
        let tip = store.poseidon2_v8_tip().unwrap();
        let legacy = store
            .with_state(|state| Ok(legacy_test_fixture_v11(state)))
            .unwrap();
        let plaintext = bincode::serialize(&legacy).unwrap();
        assert!(deserialize_wallet_state(&plaintext).is_err());
        let nonce = [0x22; NONCE_LEN];
        let cipher = ChaCha20Poly1305::new(&store.key.into());
        let ciphertext = cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plaintext,
                    aad: &store.salt,
                },
            )
            .unwrap();
        let file = WalletFile {
            version: LEGACY_FILE_VERSION_V11,
            salt: store.salt,
            nonce,
            ciphertext,
        };
        write_private_file(&path, &bincode::serialize(&file).unwrap()).unwrap();
        let old_file = fs::read(&path).unwrap();
        let snapshot = WalletStore::open_read_only(&path, "passphrase").unwrap();
        assert_eq!(snapshot.poseidon2_v8_tip().unwrap(), tip);
        assert_eq!(fs::read(&path).unwrap(), old_file);
        drop(snapshot);
        drop(store);
        let migrated = WalletStore::open_read_only(&path, "passphrase").unwrap();
        assert_eq!(migrated.poseidon2_v8_tip().unwrap(), tip);
        assert_eq!(migrated.signing_seed().unwrap(), [0x61; 32]);
        assert_eq!(
            migrated
                .with_state(|state| Ok(state.next_address_index))
                .unwrap(),
            1
        );
        assert!(migrated.poseidon2_v8_reservations().unwrap().is_empty());
        let file: WalletFile = deserialize_exact(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(file.version, LEGACY_FILE_VERSION_V11);
        let mut trailing = plaintext;
        trailing.push(0xff);
        assert!(deserialize_wallet_state_v11(&trailing).is_err());
    }

    #[test]
    fn pending_debug_format_contains_only_counts() {
        let line = pending_debug_counts(2, 1);
        assert_eq!(
            line,
            "[DEBUG refresh_pending] pending input_count=2 canonical_matches=1"
        );
        for secret_link in [
            hex::encode([0x41; 48]),
            hex::encode([0x42; 48]),
            hex::encode([0x43; 8]),
        ] {
            assert!(!line.contains(&secret_link));
        }
    }

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
                    notes: state
                        .notes
                        .iter()
                        .cloned()
                        .map(TrackedNoteBeforeNoteSource::from)
                        .collect(),
                    pending: Vec::new(),
                    recent: Vec::new(),
                    commitments: state.commitments.clone(),
                    next_commitment_index: state.next_commitment_index,
                    next_ciphertext_index: state.next_ciphertext_index,
                    last_synced_height: state.last_synced_height,
                    last_synced_block_hash: state.last_synced_block_hash,
                    outgoing_disclosures: Vec::new(),
                    genesis_hash: state.genesis_hash,
                })
            })
            .unwrap();
        let plaintext = bincode::serialize(&legacy).unwrap();
        let migrated = deserialize_wallet_state_v6(&plaintext).unwrap();
        assert!(migrated.multisig_accounts.is_empty());
    }

    #[test]
    fn wallet_state_v9_without_note_sources_migrates() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let ivk = store.incoming_key().unwrap();
        let address = store.primary_address().unwrap();
        let mut rng = StdRng::seed_from_u64(101);
        let note = NotePlaintext::random(10, 0, MemoPlaintext::default(), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        let recovered = ivk.decrypt_note(&ciphertext).unwrap();
        let commitment = felts_to_bytes48(&recovered.note_data.commitment());
        store
            .append_commitments_with_sources(&[(0, commitment, NoteSource::MiningReward)])
            .unwrap();
        store.register_ciphertext_index(0).unwrap();
        store.record_recovered_note(recovered, 0, 0).unwrap();
        let legacy = store
            .with_state(|state| {
                Ok(WalletStateV9BeforeNoteSources {
                    mode: state.mode,
                    tree_depth: state.tree_depth,
                    root_secret: state.root_secret,
                    derived: state.derived.clone(),
                    incoming: state.incoming.clone(),
                    full_viewing_key: state.full_viewing_key.clone(),
                    outgoing: state.outgoing.clone(),
                    next_address_index: state.next_address_index,
                    notes: state
                        .notes
                        .iter()
                        .cloned()
                        .map(TrackedNoteBeforeNoteSource::from)
                        .collect(),
                    pending: Vec::new(),
                    recent: Vec::new(),
                    commitments: state.commitments.clone(),
                    next_commitment_index: state.next_commitment_index,
                    next_ciphertext_index: state.next_ciphertext_index,
                    last_synced_height: state.last_synced_height,
                    last_synced_block_hash: state.last_synced_block_hash,
                    outgoing_disclosures: Vec::new(),
                    genesis_hash: state.genesis_hash,
                    multisig_accounts: state.multisig_accounts.clone(),
                    local_note_openings: state.local_note_openings.clone(),
                })
            })
            .unwrap();
        let plaintext = bincode::serialize(&legacy).unwrap();
        let migrated = deserialize_wallet_state_v9(&plaintext).unwrap();
        assert!(migrated.commitment_sources.is_empty());
        assert_eq!(migrated.notes.len(), 1);
        assert_eq!(migrated.notes[0].source, NoteSource::Unknown);
        assert_eq!(migrated.next_commitment_index, legacy.next_commitment_index);
    }

    #[test]
    fn legacy_32_byte_transaction_ids_fail_closed_during_v9_migration() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let legacy = store
            .with_state(|state| {
                Ok(WalletStateV9 {
                    mode: state.mode,
                    tree_depth: state.tree_depth,
                    root_secret: state.root_secret,
                    derived: state.derived.clone(),
                    incoming: state.incoming.clone(),
                    full_viewing_key: state.full_viewing_key.clone(),
                    outgoing: state.outgoing.clone(),
                    next_address_index: state.next_address_index,
                    notes: state.notes.clone(),
                    pending: vec![LegacyPendingTransaction32 {
                        tx_id: [0x5a; 32],
                        nullifiers: vec![[0xa5; 48]],
                        spent_note_indexes: Vec::new(),
                        submitted_at: 1,
                        status: PendingStatus::InMempool,
                        recipients: Vec::new(),
                        fee: 0,
                    }],
                    recent: Vec::new(),
                    commitments: state.commitments.clone(),
                    commitment_sources: state.commitment_sources.clone(),
                    next_commitment_index: state.next_commitment_index,
                    next_ciphertext_index: state.next_ciphertext_index,
                    last_synced_height: state.last_synced_height,
                    last_synced_block_hash: state.last_synced_block_hash,
                    outgoing_disclosures: Vec::new(),
                    genesis_hash: state.genesis_hash,
                    multisig_accounts: state.multisig_accounts.clone(),
                    local_note_openings: state.local_note_openings.clone(),
                })
            })
            .unwrap();

        let plaintext = bincode::serialize(&legacy).unwrap();
        let error = deserialize_wallet_state_v9(&plaintext)
            .expect_err("a 32-byte legacy id cannot become a canonical ActionId48");
        assert!(error.to_string().contains("cannot be recovered"));
    }

    #[test]
    fn action_id48_wallet_roundtrip_preserves_tail_bytes() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let mut action_id_bytes = [0x11; 48];
        action_id_bytes[32..].copy_from_slice(&[0x7e; 16]);
        let action_id = ActionId48::new(action_id_bytes);
        store
            .record_pending_submission(action_id, Vec::new(), Vec::new(), Vec::new(), 0)
            .unwrap();
        drop(store);

        let reopened = WalletStore::open(&path, "passphrase").unwrap();
        let pending = reopened.pending_transactions().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tx_id, action_id);
        assert_eq!(&pending[0].tx_id.as_bytes()[32..], &[0x7e; 16]);
    }

    #[test]
    fn provisional_id_roundtrip_never_becomes_a_canonical_action_id() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let provisional = ProvisionalActionId48::new([0x5a; 48]);
        let equal_bytes_canonical = ActionId48::new([0x5a; 48]);
        store
            .record_provisional_pending_submission(
                provisional,
                vec![[0xa5; 48]],
                Vec::new(),
                Vec::new(),
                0,
            )
            .unwrap();

        let pending = store.pending_transactions().unwrap();
        assert_eq!(pending[0].tx_id, provisional);
        assert_ne!(pending[0].tx_id, equal_bytes_canonical);
        assert!(pending[0].tx_id.is_provisional());
        assert_eq!(pending[0].tx_id.canonical(), None);
        assert!(pending[0].tx_id.external_id().starts_with("provisional:"));
        assert_eq!(
            WalletTransactionId::Canonical(equal_bytes_canonical).external_id(),
            hex::encode(equal_bytes_canonical.as_bytes())
        );
        drop(store);

        let reopened = WalletStore::open(&path, "passphrase").unwrap();
        let pending = reopened.pending_transactions().unwrap();
        assert_eq!(pending[0].tx_id, provisional);
        assert!(pending[0].tx_id.is_provisional());
        assert_eq!(pending[0].tx_id.canonical(), None);
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
    fn tracked_note_records_commitment_source() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.dat");
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        let (_ciphertext, opening, commitment) =
            accumulator_ciphertext_fixture(&store, [43u8; 32], 43);
        store
            .append_commitments_with_sources(&[(0, commitment, NoteSource::MiningReward)])
            .unwrap();
        store.record_local_note_opening(opening).unwrap();

        assert_eq!(store.apply_ciphertext_batch(0, vec![None]).unwrap(), 1);
        let notes = store.tracked_notes().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].source, NoteSource::MiningReward);
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
            commitment_sources: Vec::new(),
            next_commitment_index: 0,
            next_ciphertext_index: 0,
            last_synced_height: 0,
            last_synced_block_hash: None,
            outgoing_disclosures: Vec::new(),
            genesis_hash: None,
            multisig_accounts: Vec::new(),
            local_note_openings: Vec::new(),
            poseidon2_v8: Poseidon2V8WalletState::default(),
            poseidon2_v8_reservations: Vec::new(),
            htlc_swaps: Vec::new(),
            poseidon2_v8_treasuries: Vec::new(),
            native_launch_context: None,
            native_rp06_transfers: Vec::new(),
            private_spend_issued: Default::default(),
            private_spend_notes: Vec::new(),
            private_spend_templates: Vec::new(),
            private_spend_attempts: Vec::new(),
            private_spend_relation_digest: None,
            asset_spend: Default::default(),
            recovery: Default::default(),
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
            .record_pending_submission(
                ActionId48::new([1u8; 48]),
                vec![[2u8; 48]],
                vec![idx0],
                vec![],
                0,
            )
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
                ActionId48::new([9u8; 48]),
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
        assert_eq!(recent[0].tx_id, ActionId48::new([9u8; 48]));
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
                ActionId48::new([0x55; 48]),
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletStateV15 {
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
    #[serde(default)]
    commitment_sources: Vec<NoteSource>,
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
    #[serde(with = "frozen_v17_mirror_codec")]
    poseidon2_v8: Poseidon2V8WalletState,
    poseidon2_v8_reservations: Vec<StoredPoseidon2V8Reservation>,
    htlc_swaps: Vec<htlc_store::StoredHtlcSwap>,
    poseidon2_v8_treasuries: Vec<crate::poseidon2_v8_multisig::StoredV8Treasury>,
    #[serde(default)]
    native_launch_context: Option<crate::poseidon2_v8_sync::launch_sync::StoredNativeLaunchContext>,
    native_rp06_transfers: Vec<crate::rp06_transfer_store::StoredRp06TransferCandidate>,
}
impl From<WalletStateV15> for WalletState {
    fn from(value: WalletStateV15) -> Self {
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
            commitment_sources: value.commitment_sources,
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: value.outgoing_disclosures,
            genesis_hash: value.genesis_hash,
            multisig_accounts: value.multisig_accounts,
            local_note_openings: value.local_note_openings,
            poseidon2_v8: value.poseidon2_v8,
            poseidon2_v8_reservations: value.poseidon2_v8_reservations,
            htlc_swaps: value.htlc_swaps,
            poseidon2_v8_treasuries: value.poseidon2_v8_treasuries,
            native_launch_context: value.native_launch_context,
            native_rp06_transfers: value.native_rp06_transfers,
            private_spend_issued: Default::default(),
            private_spend_notes: Vec::new(),
            private_spend_templates: Vec::new(),
            private_spend_attempts: Vec::new(),
            private_spend_relation_digest: None,
            asset_spend: Default::default(),
            recovery: Default::default(),
        }
    }
}

fn deserialize_wallet_state_v15(bytes: &[u8]) -> Result<WalletState, WalletError> {
    let mut state = WalletState::from(deserialize_exact::<WalletStateV15>(bytes)?);
    seed_private_spend_issued_addresses(&mut state)?;
    validate_legacy_wallet_key_material(&state)?;
    Ok(state)
}

#[cfg(test)]
mod private_spend_store_tests {
    use super::*;
    #[test]
    fn private_address_issuance_survives_restart_and_readonly_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private.wallet");
        let store =
            WalletStore::create_from_root(&path, "test", RootSecret::from_bytes([63; 32])).unwrap();
        let expected = store.private_spend_address(37).unwrap();
        assert!(store
            .with_state(|s| Ok(s.private_spend_issued.contains(37)))
            .unwrap());
        drop(store);
        let reopened = WalletStore::open(&path, "test").unwrap();
        assert_eq!(reopened.private_spend_address(37).unwrap(), expected);
        assert!(reopened
            .with_state(|s| Ok(s.private_spend_issued.contains(37)))
            .unwrap());
        assert_eq!(
            reopened
                .next_private_spend_address()
                .unwrap()
                .diversifier_index,
            38
        );
        drop(reopened);
        let readonly = WalletStore::open_read_only(&path, "test").unwrap();
        assert!(readonly.private_spend_address(99).is_err());
    }
    #[test]
    fn private_store_v15_migration_is_exact_and_retains_old_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.wallet");
        let store =
            WalletStore::create_from_root(&path, "test", RootSecret::from_bytes([64; 32])).unwrap();
        for _ in 0..3 {
            store.next_address().unwrap();
        }
        let old = store
            .with_state(|state| {
                Ok(WalletStateV15 {
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
                    commitment_sources: state.commitment_sources.clone(),
                    next_commitment_index: state.next_commitment_index,
                    next_ciphertext_index: state.next_ciphertext_index,
                    last_synced_height: state.last_synced_height,
                    last_synced_block_hash: state.last_synced_block_hash,
                    outgoing_disclosures: state.outgoing_disclosures.clone(),
                    genesis_hash: state.genesis_hash,
                    multisig_accounts: state.multisig_accounts.clone(),
                    local_note_openings: state.local_note_openings.clone(),
                    poseidon2_v8: state.poseidon2_v8.clone(),
                    poseidon2_v8_reservations: state.poseidon2_v8_reservations.clone(),
                    htlc_swaps: state.htlc_swaps.clone(),
                    poseidon2_v8_treasuries: state.poseidon2_v8_treasuries.clone(),
                    native_launch_context: state.native_launch_context.clone(),
                    native_rp06_transfers: state.native_rp06_transfers.clone(),
                })
            })
            .unwrap();
        let bytes = bincode::serialize(&old).unwrap();
        let migrated = deserialize_wallet_state_v15(&bytes).unwrap();
        assert_eq!(migrated.next_address_index, 3);
        assert!(migrated.private_spend_issued.contains(2));
        assert!(!migrated.private_spend_issued.contains(3));
        assert!(migrated.private_spend_notes.is_empty());
        assert!(migrated.private_spend_issued.contains(0));
        assert!(deserialize_wallet_state(&bytes).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(deserialize_wallet_state_v15(&trailing).is_err());
    }
}

fn seed_private_spend_issued_addresses(state: &mut WalletState) -> Result<(), WalletError> {
    let mut issued = crate::private_spend::IssuedPrivateSpendAddresses::from_legacy_issued_count(
        state.next_address_index,
    );
    if state.poseidon2_v8.canonical_hash(0).is_some() {
        for note in state.poseidon2_v8.owned_notes()? {
            issued.record_issued(note.diversifier_index);
        }
    }
    // These policy addresses are also persisted issuance evidence. Their KEM
    // owner may differ from this wallet; trying an index never grants custody.
    for treasury in &state.poseidon2_v8_treasuries {
        issued.record_issued(treasury.descriptor.receive_address.diversifier_index);
    }
    state.private_spend_issued = issued;
    Ok(())
}

// Exact V16 positional payload; never append fields to this frozen type.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletStateV16 {
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
    #[serde(default)]
    commitment_sources: Vec<NoteSource>,
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
    #[serde(with = "frozen_v17_mirror_codec")]
    poseidon2_v8: Poseidon2V8WalletState,
    poseidon2_v8_reservations: Vec<StoredPoseidon2V8Reservation>,
    htlc_swaps: Vec<htlc_store::StoredHtlcSwap>,
    poseidon2_v8_treasuries: Vec<crate::poseidon2_v8_multisig::StoredV8Treasury>,
    #[serde(default)]
    native_launch_context: Option<crate::poseidon2_v8_sync::launch_sync::StoredNativeLaunchContext>,
    native_rp06_transfers: Vec<crate::rp06_transfer_store::StoredRp06TransferCandidate>,

    private_spend_issued: crate::private_spend::IssuedPrivateSpendAddresses,
    private_spend_notes: Vec<crate::private_spend::StoredPrivateSpendNote>,
}

impl From<WalletStateV16> for WalletState {
    fn from(value: WalletStateV16) -> Self {
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
            commitment_sources: value.commitment_sources,
            next_commitment_index: value.next_commitment_index,
            next_ciphertext_index: value.next_ciphertext_index,
            last_synced_height: value.last_synced_height,
            last_synced_block_hash: value.last_synced_block_hash,
            outgoing_disclosures: value.outgoing_disclosures,
            genesis_hash: value.genesis_hash,
            multisig_accounts: value.multisig_accounts,
            local_note_openings: value.local_note_openings,
            poseidon2_v8: value.poseidon2_v8,
            poseidon2_v8_reservations: value.poseidon2_v8_reservations,
            htlc_swaps: value.htlc_swaps,
            poseidon2_v8_treasuries: value.poseidon2_v8_treasuries,
            native_launch_context: value.native_launch_context,
            native_rp06_transfers: value.native_rp06_transfers,
            private_spend_issued: value.private_spend_issued,
            private_spend_notes: value.private_spend_notes,
            private_spend_templates: Vec::new(),
            private_spend_attempts: Vec::new(),
            private_spend_relation_digest: None,
            asset_spend: Default::default(),
            recovery: Default::default(),
        }
    }
}
fn deserialize_wallet_state_v16(bytes: &[u8]) -> Result<WalletState, WalletError> {
    let state = WalletState::from(deserialize_exact::<WalletStateV16>(bytes)?);
    validate_legacy_wallet_key_material(&state)?;
    Ok(state)
}

#[cfg(test)]
mod private_spend_v17_tests {
    use super::*;
    #[test]
    fn private_spend_v17_migrates_exact_v16_without_reseeding_sparse_issuance() {
        let dir = tempfile::tempdir().unwrap();
        let store = WalletStore::create_from_root(
            dir.path().join("wallet"),
            "test",
            RootSecret::from_bytes([61; 32]),
        )
        .unwrap();
        store.private_spend_address(37).unwrap();
        let old = store
            .with_state(|s| {
                Ok(WalletStateV16 {
                    mode: s.mode.clone(),
                    tree_depth: s.tree_depth.clone(),
                    root_secret: s.root_secret.clone(),
                    derived: s.derived.clone(),
                    incoming: s.incoming.clone(),
                    full_viewing_key: s.full_viewing_key.clone(),
                    outgoing: s.outgoing.clone(),
                    next_address_index: s.next_address_index.clone(),
                    notes: s.notes.clone(),
                    pending: s.pending.clone(),
                    recent: s.recent.clone(),
                    commitments: s.commitments.clone(),
                    commitment_sources: s.commitment_sources.clone(),
                    next_commitment_index: s.next_commitment_index.clone(),
                    next_ciphertext_index: s.next_ciphertext_index.clone(),
                    last_synced_height: s.last_synced_height.clone(),
                    last_synced_block_hash: s.last_synced_block_hash.clone(),
                    outgoing_disclosures: s.outgoing_disclosures.clone(),
                    genesis_hash: s.genesis_hash.clone(),
                    multisig_accounts: s.multisig_accounts.clone(),
                    local_note_openings: s.local_note_openings.clone(),
                    poseidon2_v8: s.poseidon2_v8.clone(),
                    poseidon2_v8_reservations: s.poseidon2_v8_reservations.clone(),
                    htlc_swaps: s.htlc_swaps.clone(),
                    poseidon2_v8_treasuries: s.poseidon2_v8_treasuries.clone(),
                    native_launch_context: s.native_launch_context.clone(),
                    native_rp06_transfers: s.native_rp06_transfers.clone(),
                    private_spend_issued: s.private_spend_issued.clone(),
                    private_spend_notes: s.private_spend_notes.clone(),
                })
            })
            .unwrap();
        let bytes = bincode::serialize(&old).unwrap();
        let migrated = deserialize_wallet_state_v16(&bytes).unwrap();
        assert!(migrated.private_spend_issued.contains(37));
        assert!(migrated.private_spend_templates.is_empty());
        assert!(migrated.private_spend_attempts.is_empty());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(deserialize_wallet_state_v16(&trailing).is_err());
    }
}

impl WalletStore {
    pub fn poseidon2_v8_canonical_note_witness_at(
        &self,
        commitment: [u64; 7],
        position: u64,
    ) -> Result<Option<crate::poseidon2_v8_sync::Poseidon2V8CanonicalNoteWitness>, WalletError>
    {
        self.with_state(|s| {
            s.poseidon2_v8
                .canonical_note_witness_at(commitment, position)
        })
    }
    /// Only an explicitly validated private-only Development token can enter
    /// this route. No retained-test selector or production capability is inferred.
    #[cfg(feature = "private-spend-dev-artifacts")]
    pub fn initialize_private_spend_development_context(
        &self,
        token: &crate::private_spend_rpc::DevelopmentPrivateSpendAuthority,
    ) -> Result<(), WalletError> {
        let context = token.context();
        token.authorize(context, token.activation_height(), 1)?;
        let (stablecoin_root, note_root) = token.genesis_roots();
        self.with_poseidon2_v8_mut_and_block(None, Some((context, false)), |mirror, _| {
            token.authorize(context, token.activation_height(), 1)?;
            mirror.ensure_launch_genesis(context.genesis_hash(), stablecoin_root, note_root)
        })
    }
    #[cfg(feature = "private-spend-dev-artifacts")]
    pub fn apply_private_spend_development_block(
        &self,
        block: &Poseidon2V8CanonicalBlock,
        token: &crate::private_spend_rpc::DevelopmentPrivateSpendAuthority,
    ) -> Result<Poseidon2V8SyncDelta, WalletError> {
        let context = token.context();
        token.authorize(context, block.height, 1)?;
        self.with_poseidon2_v8_mut_and_block(Some(block), Some((context, false)), |mirror, keys| {
            mirror.apply_private_spend_development_block(block, keys, token)
        })
    }
}

impl WalletStore {
    pub fn initialize_private_spend_source_context(
        &self,
        token: &crate::private_spend_rpc::SourcePrivateSpendAuthority,
    ) -> Result<(), WalletError> {
        let context = token.context();
        token.authorize(context, token.activation_height(), 1)?;
        let (stablecoin_root, note_root) = context.source_genesis_roots()?;
        self.with_poseidon2_v8_mut_and_block(None, Some((context, true)), |mirror, _| {
            token.authorize(context, token.activation_height(), 1)?;
            mirror.ensure_launch_genesis(context.genesis_hash(), stablecoin_root, note_root)
        })
    }
    pub fn apply_private_spend_source_block(
        &self,
        block: &Poseidon2V8CanonicalBlock,
        token: &crate::private_spend_rpc::SourcePrivateSpendAuthority,
    ) -> Result<Poseidon2V8SyncDelta, WalletError> {
        let context = token.context();
        token.authorize(context, block.height, 1)?;
        self.with_poseidon2_v8_mut_and_block(Some(block), Some((context, true)), |mirror, keys| {
            mirror.apply_private_spend_source_block(block, keys, context)
        })
    }
}

#[cfg(test)]
mod legacy_v17_recovery_tests {
    use super::*;
    fn frozen_fixture(state: &WalletState) -> WalletStateV17 {
        WalletStateV17 {
            mode: state.mode.clone(),
            tree_depth: state.tree_depth.clone(),
            root_secret: state.root_secret.clone(),
            derived: state.derived.clone(),
            incoming: state.incoming.clone(),
            full_viewing_key: state.full_viewing_key.clone(),
            outgoing: state.outgoing.clone(),
            next_address_index: state.next_address_index.clone(),
            notes: state.notes.clone(),
            pending: state.pending.clone(),
            recent: state.recent.clone(),
            commitments: state.commitments.clone(),
            commitment_sources: state.commitment_sources.clone(),
            next_commitment_index: state.next_commitment_index.clone(),
            next_ciphertext_index: state.next_ciphertext_index.clone(),
            last_synced_height: state.last_synced_height.clone(),
            last_synced_block_hash: state.last_synced_block_hash.clone(),
            outgoing_disclosures: state.outgoing_disclosures.clone(),
            genesis_hash: state.genesis_hash.clone(),
            multisig_accounts: state.multisig_accounts.clone(),
            local_note_openings: state.local_note_openings.clone(),
            poseidon2_v8: state.poseidon2_v8.clone(),
            poseidon2_v8_reservations: state.poseidon2_v8_reservations.clone(),
            htlc_swaps: state.htlc_swaps.clone(),
            poseidon2_v8_treasuries: state.poseidon2_v8_treasuries.clone(),
            native_launch_context: state.native_launch_context.clone(),
            native_rp06_transfers: state.native_rp06_transfers.clone(),
            private_spend_issued: state.private_spend_issued.clone(),
            private_spend_notes: state.private_spend_notes.clone(),
            private_spend_templates: state.private_spend_templates.clone(),
            private_spend_attempts: state.private_spend_attempts.clone(),
            private_spend_relation_digest: state.private_spend_relation_digest.clone(),
        }
    }
    fn write_v17_fixture(store: &WalletStore) {
        let frozen = store.with_state(|state| Ok(frozen_fixture(state))).unwrap();
        let plaintext = zeroize::Zeroizing::new(bincode::serialize(&frozen).unwrap());
        // Typed old payload must roundtrip exactly and reject extra bytes.
        let parsed = deserialize_exact::<WalletStateV17>(&plaintext).unwrap();
        assert_eq!(bincode::serialize(&parsed).unwrap(), plaintext.as_slice());
        let mut trailing = plaintext.to_vec();
        trailing.push(0);
        assert!(deserialize_wallet_state_v17(&trailing).is_err());
        let nonce = [0x6d; NONCE_LEN];
        let ciphertext = ChaCha20Poly1305::new(&store.key.into())
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plaintext,
                    aad: &store.salt,
                },
            )
            .unwrap();
        let file = WalletFile {
            version: LEGACY_FILE_VERSION_V17,
            salt: store.salt,
            nonce,
            ciphertext,
        };
        write_private_file(&store.path, &bincode::serialize(&file).unwrap()).unwrap();
    }
    #[test]
    fn old_v17_read_only_and_recovery_preserve_keys_accounts_and_source_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("historical-wallet");
        let target = dir.path().join("fresh-wallet");
        let store = WalletStore::create_from_root(
            &source,
            "old-test-only",
            RootSecret::from_bytes([0x6b; 32]),
        )
        .unwrap();
        let address = store.private_spend_address(37).unwrap();
        let tags = (1..=3)
            .map(|i| {
                signer_tag_from_spend_key(
                    &RootSecret::from_bytes([i; 32]).derive().spend.to_bytes(),
                )
            })
            .collect();
        let account = store.create_multisig_account(2, tags).unwrap();
        let old_seed = store.signing_seed().unwrap();
        write_v17_fixture(&store);
        drop(store);
        let source_bytes = fs::read(&source).unwrap();
        let readonly = WalletStore::open_read_only(&source, "old-test-only").unwrap();
        assert!(readonly.is_legacy_read_only());
        assert_eq!(readonly.signing_seed().unwrap(), old_seed);
        assert_eq!(readonly.multisig_accounts().unwrap(), vec![account.clone()]);
        assert!(readonly.next_private_spend_address().is_err());
        assert!(WalletStore::open(&source, "old-test-only").is_err());
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
        drop(readonly);
        let recovered = WalletStore::recover_keys_to_fresh_wallet(
            &source,
            "old-test-only",
            &target,
            "new-test-only",
        )
        .unwrap();
        assert!(!recovered.is_legacy_read_only());
        assert_eq!(recovered.signing_seed().unwrap(), old_seed);
        assert_eq!(recovered.private_spend_address(37).unwrap(), address);
        assert_eq!(recovered.multisig_accounts().unwrap(), vec![account]);
        assert_eq!(recovered.genesis_hash().unwrap(), None);
        assert!(recovered.launch_context().is_err());
        assert!(recovered
            .with_state(|state| Ok(state.private_spend_issued.contains(37)))
            .unwrap());
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
        let target_bytes = fs::read(&target).unwrap();
        assert!(WalletStore::recover_keys_to_fresh_wallet(
            &source,
            "old-test-only",
            &target,
            "replacement-test-only"
        )
        .is_err());
        assert!(WalletStore::recover_keys_to_fresh_wallet(
            &source,
            "old-test-only",
            &source,
            "replacement-test-only"
        )
        .is_err());
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
        assert_eq!(fs::read(&target).unwrap(), target_bytes);
    }
    #[cfg(unix)]
    #[test]
    fn recovery_rejects_hardlink_and_symlink_destinations() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        drop(
            WalletStore::create_from_root(&source, "test-only", RootSecret::from_bytes([0x6c; 32]))
                .unwrap(),
        );
        let before = fs::read(&source).unwrap();
        let hardlink = dir.path().join("hardlink");
        fs::hard_link(&source, &hardlink).unwrap();
        assert!(WalletStore::recover_keys_to_fresh_wallet(
            &source,
            "test-only",
            &hardlink,
            "test-only"
        )
        .is_err());
        let symlink = dir.path().join("symlink");
        std::os::unix::fs::symlink(&source, &symlink).unwrap();
        assert!(WalletStore::recover_keys_to_fresh_wallet(
            &source,
            "test-only",
            &symlink,
            "test-only"
        )
        .is_err());
        assert_eq!(fs::read(&source).unwrap(), before);
    }
}

#[cfg(test)]
mod legacy_v18_asset_schema_tests {
    use super::*;

    fn frozen(state: &WalletState) -> WalletStateV18 {
        WalletStateV18 {
            mode: state.mode.clone(),
            tree_depth: state.tree_depth.clone(),
            root_secret: state.root_secret.clone(),
            derived: state.derived.clone(),
            incoming: state.incoming.clone(),
            full_viewing_key: state.full_viewing_key.clone(),
            outgoing: state.outgoing.clone(),
            next_address_index: state.next_address_index.clone(),
            notes: state.notes.clone(),
            pending: state.pending.clone(),
            recent: state.recent.clone(),
            commitments: state.commitments.clone(),
            commitment_sources: state.commitment_sources.clone(),
            next_commitment_index: state.next_commitment_index.clone(),
            next_ciphertext_index: state.next_ciphertext_index.clone(),
            last_synced_height: state.last_synced_height.clone(),
            last_synced_block_hash: state.last_synced_block_hash.clone(),
            outgoing_disclosures: state.outgoing_disclosures.clone(),
            genesis_hash: state.genesis_hash.clone(),
            multisig_accounts: state.multisig_accounts.clone(),
            local_note_openings: state.local_note_openings.clone(),
            poseidon2_v8: state.poseidon2_v8.clone(),
            poseidon2_v8_reservations: state.poseidon2_v8_reservations.clone(),
            htlc_swaps: state.htlc_swaps.clone(),
            poseidon2_v8_treasuries: state.poseidon2_v8_treasuries.clone(),
            native_launch_context: state.native_launch_context.clone(),
            native_rp06_transfers: state.native_rp06_transfers.clone(),
            private_spend_issued: state.private_spend_issued.clone(),
            private_spend_notes: state.private_spend_notes.clone(),
            private_spend_templates: state.private_spend_templates.clone(),
            private_spend_attempts: state.private_spend_attempts.clone(),
            private_spend_relation_digest: state.private_spend_relation_digest.clone(),
        }
    }

    fn write_frozen_v18(store: &WalletStore) {
        let legacy = store.with_state(|state| Ok(frozen(state))).unwrap();
        let plaintext = zeroize::Zeroizing::new(bincode::serialize(&legacy).unwrap());
        let parsed = deserialize_exact::<WalletStateV18>(&plaintext).unwrap();
        assert_eq!(bincode::serialize(&parsed).unwrap(), plaintext.as_slice());
        let mut trailing = plaintext.to_vec();
        trailing.push(0);
        assert!(deserialize_wallet_state_v18(&trailing).is_err());
        assert!(deserialize_wallet_state(&plaintext).is_err());
        store
            .with_state(|state| {
                let current = bincode::serialize(state).unwrap();
                // V18 remains the exact prefix. V19 appended asset state;
                // V20 additionally appends recovery state. Compare the actual
                // positional bytes so a missing, reordered or changed suffix
                // cannot pass through an adjusted length expectation.
                let mut expected = plaintext.to_vec();
                expected.extend(bincode::serialize(&state.asset_spend).unwrap());
                expected.extend(bincode::serialize(&state.recovery).unwrap());
                assert_eq!(current, expected);
                Ok(())
            })
            .unwrap();
        let nonce = [0x6e; NONCE_LEN];
        let ciphertext = ChaCha20Poly1305::new(&store.key.into())
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plaintext,
                    aad: &store.salt,
                },
            )
            .unwrap();
        let file = WalletFile {
            version: LEGACY_FILE_VERSION_V18,
            salt: store.salt,
            nonce,
            ciphertext,
        };
        write_private_file(&store.path, &bincode::serialize(&file).unwrap()).unwrap();
    }

    #[test]
    fn frozen_v18_is_read_only_and_key_recovery_creates_schema20_without_touching_source() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source-v18");
        let destination = directory.path().join("recovered-v20");
        let store = WalletStore::create_from_root(
            &source,
            "old-test-only",
            RootSecret::from_bytes([0x74; 32]),
        )
        .unwrap();
        let address = store.private_spend_address(37).unwrap();
        let seed = store.signing_seed().unwrap();
        write_frozen_v18(&store);
        drop(store);
        let source_bytes = fs::read(&source).unwrap();
        let readonly = WalletStore::open_read_only(&source, "old-test-only").unwrap();
        assert!(readonly.is_legacy_read_only());
        assert_eq!(readonly.source_file_version, LEGACY_FILE_VERSION_V18);
        assert_eq!(readonly.signing_seed().unwrap(), seed);
        assert!(readonly.reset_sync_state().is_err());
        assert!(WalletStore::open(&source, "old-test-only").is_err());
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
        drop(readonly);
        let recovered = WalletStore::recover_keys_to_fresh_wallet(
            &source,
            "old-test-only",
            &destination,
            "new-test-only",
        )
        .unwrap();
        assert!(!recovered.is_legacy_read_only());
        assert_eq!(recovered.signing_seed().unwrap(), seed);
        assert_eq!(recovered.private_spend_address(37).unwrap(), address);
        assert!(recovered.launch_context().is_err());
        assert!(recovered.asset_spend_notes().unwrap().is_empty());
        assert!(recovered.asset_spend_attempts().unwrap().is_empty());
        assert!(recovered.recovery_notes().unwrap().is_empty());
        recovered
            .with_state(|state| {
                // Both recovery notes and attempts must start empty. This also
                // works before a new chain context exists.
                assert_eq!(
                    bincode::serialize(&state.recovery).unwrap(),
                    bincode::serialize(&asset_recovery_store::RecoveryWalletState::default())
                        .unwrap()
                );
                Ok(())
            })
            .unwrap();
        let file = deserialize_exact::<WalletFile>(&fs::read(&destination).unwrap()).unwrap();
        assert_eq!(file.version, 20);
        assert_eq!(recovered.source_file_version, 20);
        drop(recovered);
        let reopened = WalletStore::open(&destination, "new-test-only").unwrap();
        assert!(!reopened.is_legacy_read_only());
        assert_eq!(reopened.source_file_version, 20);
        assert_eq!(reopened.signing_seed().unwrap(), seed);
        assert_eq!(reopened.private_spend_address(37).unwrap(), address);
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
    }
}

#[cfg(test)]
mod recovery_schema20_tests {
    use super::*;
    #[test]
    fn frozen_v19_prefix_and_reader_are_exact_without_writable_upgrade() {
        let d = tempfile::tempdir().unwrap();
        let store = WalletStore::create_from_root(
            d.path().join("schema20"),
            "disposable",
            RootSecret::from_bytes([0x54; 32]),
        )
        .unwrap();
        let state = store.state.lock().unwrap();
        let old = WalletStateV19 {
            mode: state.mode.clone(),
            tree_depth: state.tree_depth.clone(),
            root_secret: state.root_secret.clone(),
            derived: state.derived.clone(),
            incoming: state.incoming.clone(),
            full_viewing_key: state.full_viewing_key.clone(),
            outgoing: state.outgoing.clone(),
            next_address_index: state.next_address_index.clone(),
            notes: state.notes.clone(),
            pending: state.pending.clone(),
            recent: state.recent.clone(),
            commitments: state.commitments.clone(),
            commitment_sources: state.commitment_sources.clone(),
            next_commitment_index: state.next_commitment_index.clone(),
            next_ciphertext_index: state.next_ciphertext_index.clone(),
            last_synced_height: state.last_synced_height.clone(),
            last_synced_block_hash: state.last_synced_block_hash.clone(),
            outgoing_disclosures: state.outgoing_disclosures.clone(),
            genesis_hash: state.genesis_hash.clone(),
            multisig_accounts: state.multisig_accounts.clone(),
            local_note_openings: state.local_note_openings.clone(),
            poseidon2_v8: state.poseidon2_v8.clone(),
            poseidon2_v8_reservations: state.poseidon2_v8_reservations.clone(),
            htlc_swaps: state.htlc_swaps.clone(),
            poseidon2_v8_treasuries: state.poseidon2_v8_treasuries.clone(),
            native_launch_context: state.native_launch_context.clone(),
            native_rp06_transfers: state.native_rp06_transfers.clone(),
            private_spend_issued: state.private_spend_issued.clone(),
            private_spend_notes: state.private_spend_notes.clone(),
            private_spend_templates: state.private_spend_templates.clone(),
            private_spend_attempts: state.private_spend_attempts.clone(),
            private_spend_relation_digest: state.private_spend_relation_digest.clone(),
            asset_spend: state.asset_spend.clone(),
        };
        let v19 = bincode::serialize(&old).unwrap();
        let v20 = bincode::serialize(&*state).unwrap();
        assert_eq!(&v20[..v19.len()], v19.as_slice());
        assert_eq!(v20.len() - v19.len(), 16); // The two empty recovery Vec prefixes.
        assert!(deserialize_wallet_state(&v19).is_err());
        let recovered = deserialize_wallet_state_v19(&v19).unwrap();
        assert!(recovered.recovery.notes_are_empty_for_schema_test());
    }
}
