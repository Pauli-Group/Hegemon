//! Asset notes and submission journal inside the existing encrypted WalletStore.
//! Canonical sync, writer exclusion, atomic replacement and key derivation are
//! shared with native notes. This module never trusts a caller's acceptance flag.
use super::*;
use crate::asset_spend_v1::{recover_wallet_output, RecoveredAssetNotePayload};
use crate::poseidon2_v8_sync::{LaunchWalletContext, Poseidon2V8CanonicalBlock};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use transaction_circuit::{
    asset_spend_v1 as relation,
    private_spend::{BoundedPolicy, Digest, Note, PrivateInput},
};
use zeroize::Zeroize;

fn invalid(s: &'static str) -> WalletError {
    WalletError::InvalidState(s)
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredAssetNote {
    chain: [u8; 32],
    asset: u32,
    commitment: Digest,
    nullifier: Digest,
    position: u64,
    height: u64,
    block: [u8; 32],
    spent: bool,
    payload: Vec<u8>,
}
impl std::fmt::Debug for StoredAssetNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoredAssetNote { [REDACTED] }")
    }
}
impl Drop for StoredAssetNote {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}
impl StoredAssetNote {
    fn opening(&self) -> Result<RecoveredAssetNotePayload, WalletError> {
        use crate::asset_spend_v1::{AssetNotePayload, ScriptAssetNotePayload};
        use synthetic_crypto::asset_note_encryption_v1::AssetNotePlaintext;
        let p = AssetNotePlaintext::from_bytes_exact(&self.payload)
            .map_err(|_| invalid("stored asset payload width"))?;
        match self.payload.get(..4) {
            Some(b"ASN1") => Ok(RecoveredAssetNotePayload::Ordinary(
                AssetNotePayload::decode(&p, self.chain, self.asset)?,
            )),
            Some(b"ASB1") => Ok(RecoveredAssetNotePayload::Script(
                ScriptAssetNotePayload::decode(&p, self.chain, self.asset)?,
            )),
            _ => Err(invalid("stored asset payload codec")),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetSpendAttemptStatus {
    /// No bytes have been exported; exclusive-open recovery may release this.
    Proving,
    /// Exact action bytes are durable and may have left the process.
    Candidate,
    SubmissionUncertain,
    Submitted,
    /// A tombstone; a rollback to the reference parent reserves it again.
    Abandoned,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct AssetAttempt {
    id: [u8; 32],
    parent_height: u64,
    parent_hash: [u8; 32],
    note_root: Digest,
    asset: u32,
    operation: u8,
    fee: u64,
    inputs: Vec<AssetInputIdentity>,
    status: AssetSpendAttemptStatus,
    action: Vec<u8>,
    action_id: Vec<u8>,
    mined_in: Option<(u64, [u8; 32])>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct AssetInputIdentity {
    commitment: Digest,
    nullifier: Digest,
    position: u64,
}
/// Serialized only as a field of the authenticated, encrypted wallet snapshot.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AssetWalletState {
    chain: Option<[u8; 32]>,
    genesis: Option<[u8; 32]>,
    source: Vec<u8>,
    notes: Vec<StoredAssetNote>,
    attempts: Vec<AssetAttempt>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AssetNoteView {
    pub asset_id: u32,
    pub value: u64,
    pub commitment: Digest,
    pub nullifier: Digest,
    pub position: u64,
    pub recipient_index: u32,
    pub script_owned: bool,
    pub spent: bool,
    pub reserved: bool,
    pub created_height: u64,
    pub created_block_hash: [u8; 32],
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct AssetBalance {
    pub asset_id: u32,
    pub available: u128,
    pub reserved: u128,
    pub policy_owned: u128,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AssetSpendAttemptView {
    pub id: [u8; 32],
    pub status: AssetSpendAttemptStatus,
    pub parent_height: u64,
    pub action_id: Vec<u8>,
    pub mined_in: Option<(u64, [u8; 32])>,
    pub inputs_reserved: bool,
}
/// Secret-bearing selection. No Debug/serde; the caller must explicitly choose
/// any policy branch and supply its preimage before constructing the witness.
pub struct AssetSelectedInput {
    pub input: PrivateInput,
    pub nullifier: Digest,
    pub policy: Option<BoundedPolicy>,
}
impl Drop for AssetSelectedInput {
    fn drop(&mut self) {
        self.input.spend_key.zeroize();
        self.input.dummy_secret.zeroize();
        self.input.siblings.zeroize();
        self.input.note.value.zeroize();
        self.input.note.asset_id.zeroize();
        self.input.note.recipient_key.zeroize();
        self.input.note.authorization_key.zeroize();
        self.input.note.rho.zeroize();
        self.input.note.randomness.zeroize();
        if let Some(p) = &mut self.policy {
            p.nullifier_key.zeroize();
            for b in &mut p.branches {
                b.authority.zeroize();
                b.hashlock.zeroize();
                b.enabled.zeroize();
                b.not_before.zeroize();
                b.hash_required.zeroize();
                b.release_secret.zeroize();
            }
        }
    }
}
/// Inputs are durably reserved before this object is returned. A dropped object
/// does not authorize releasing a candidate that may already have been exported.
pub struct AssetSpendSelection {
    pub reservation_id: [u8; 32],
    pub parent_height: u64,
    pub parent_hash: [u8; 32],
    pub note_root: Digest,
    pub asset: Option<AssetSelectedInput>,
    pub native_fee: AssetSelectedInput,
}
fn note_from_native(
    n: transaction_circuit::smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8NoteOpening,
) -> Note {
    Note {
        value: n.value,
        asset_id: n.asset_id,
        recipient_key: n.recipient_key,
        authorization_key: n.authorization_key,
        rho: n.rho,
        randomness: n.randomness,
    }
}
fn policy_of(p: &RecoveredAssetNotePayload) -> Option<BoundedPolicy> {
    match p {
        RecoveredAssetNotePayload::Ordinary(_) => None,
        RecoveredAssetNotePayload::Script(p) => Some(p.policy.clone()),
    }
}
fn encoded_payload(
    p: &RecoveredAssetNotePayload,
    chain: [u8; 32],
    asset: u32,
) -> Result<Vec<u8>, WalletError> {
    Ok(match p {
        RecoveredAssetNotePayload::Ordinary(p) => p.encode(chain, asset)?,
        RecoveredAssetNotePayload::Script(p) => p.encode(chain, asset)?,
    }
    .as_bytes()
    .to_vec())
}
fn local_authority(keys: &DerivedKeys) -> Result<Digest, WalletError> {
    transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_digest(keys.spend.poseidon2_v8_words()?).map_err(|_|invalid("asset spend authority"))
}
fn validate_payload_owner(
    p: &RecoveredAssetNotePayload,
    keys: &DerivedKeys,
) -> Result<(), WalletError> {
    let m = keys.poseidon2_v8_address(p.recipient_index())?;
    let recipient=transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_from_canonical_bytes(m.pk_recipient).map_err(|_|invalid("asset recipient encoding"))?;
    let authority = local_authority(keys)?;
    let authorized = match p {
        RecoveredAssetNotePayload::Ordinary(p) => p.authority == authority,
        RecoveredAssetNotePayload::Script(p) => p
            .policy
            .branches
            .iter()
            .any(|b| b.enabled == 1 && b.authority == authority),
    };
    if p.as_note().recipient_key != recipient || !authorized {
        return Err(invalid("stored asset local owner mismatch"));
    }
    Ok(())
}
fn attempt_active_at(attempt: &AssetAttempt, parent: Option<u64>) -> bool {
    attempt.status != AssetSpendAttemptStatus::Abandoned
        || parent
            .zip(crate::asset_spend_rpc::reference_last_parent(attempt.parent_height).ok())
            .map_or(true, |(parent, last)| parent <= last)
}
fn require_stored_reference(
    s: &WalletState,
    context: LaunchWalletContext,
    height: u64,
    hash: [u8; 32],
    root: Digest,
) -> Result<(), WalletError> {
    let tip = s.poseidon2_v8.tip()?;
    let reference = s
        .poseidon2_v8
        .canonical_tip_at_height(height)
        .ok_or(invalid("asset canonical reference absent"))?;
    if reference.block_hash != hash || reference.anchor != root {
        return Err(invalid("asset canonical reference hash or root differs"));
    }
    crate::asset_spend_rpc::require_reference_window(height, tip.height)?;
    context.require_canonical_parent(context.genesis_hash(), height)?;
    context.require_canonical_parent(context.genesis_hash(), tip.height)?;
    Ok(())
}
impl WalletState {
    fn pin_asset_context(&mut self, context: LaunchWalletContext) -> Result<(), WalletError> {
        self.native_launch_context
            .as_ref()
            .ok_or(invalid("asset wallet context absent"))?
            .require_match(context)?;
        if let Some(chain) = self.asset_spend.chain {
            if chain != context.chain_id()
                || self.asset_spend.genesis != Some(context.genesis_hash())
                || self.asset_spend.source != relation::relation_digest()
            {
                return Err(invalid("asset wallet source or chain differs"));
            }
        } else {
            self.asset_spend.chain = Some(context.chain_id());
            self.asset_spend.genesis = Some(context.genesis_hash());
            self.asset_spend.source = relation::relation_digest().to_vec();
        }
        Ok(())
    }
    pub(super) fn recover_asset_spend_proving(&mut self) -> bool {
        let count = self.asset_spend.attempts.len();
        self.asset_spend
            .attempts
            .retain(|a| a.status != AssetSpendAttemptStatus::Proving);
        count != self.asset_spend.attempts.len()
    }
    pub(super) fn asset_spend_reserved_nullifiers(&self) -> HashSet<Digest> {
        self.asset_spend
            .attempts
            .iter()
            .filter(|a| attempt_active_at(a, self.poseidon2_v8.tip().ok().map(|t| t.height)))
            .flat_map(|a| a.inputs.iter().map(|i| i.nullifier))
            .collect()
    }
    fn other_asset_reservations(&self) -> HashSet<Digest> {
        self.reserved_ordinary_poseidon2_v8_nullifiers()
            .into_iter()
            .chain(self.htlc_reserved_nullifiers())
            .chain(self.private_spend_reserved_nullifiers())
            .chain(self.recovery_reserved_nullifiers())
            .chain(crate::poseidon2_v8_multisig::active_reserved_nullifiers(
                &self.poseidon2_v8_treasuries,
                &self.poseidon2_v8,
            ))
            .collect()
    }
    pub(super) fn reconcile_asset_spend_state(&mut self) -> Result<(), WalletError> {
        self.asset_spend
            .notes
            .retain(|n| self.poseidon2_v8.canonical_hash(n.height) == Some(n.block));
        for n in &mut self.asset_spend.notes {
            n.spent = self.poseidon2_v8.has_canonical_nullifier(n.nullifier);
        }
        for a in &mut self.asset_spend.attempts {
            if a.mined_in
                .is_some_and(|(h, b)| self.poseidon2_v8.canonical_hash(h) != Some(b))
            {
                a.mined_in = None;
            }
        }
        Ok(())
    }
    pub(super) fn validate_asset_spend_state(&self) -> Result<(), WalletError> {
        let a = &self.asset_spend;
        if a.chain.is_none() {
            if a.genesis.is_some()
                || !a.source.is_empty()
                || !a.notes.is_empty()
                || !a.attempts.is_empty()
            {
                return Err(invalid("unbound asset wallet state"));
            }
            return Ok(());
        }
        if a.source != relation::relation_digest() {
            return Err(invalid("asset wallet relation source changed"));
        }
        let context = self
            .native_launch_context
            .as_ref()
            .ok_or(invalid("asset wallet pinned context absent"))?
            .current_context()?;
        if a.chain != Some(context.chain_id()) || a.genesis != Some(context.genesis_hash()) {
            return Err(invalid("asset wallet context mismatch"));
        }
        let keys = self.derived.as_ref().ok_or(WalletError::WatchOnly)?;
        let mut positions = HashSet::new();
        for n in &a.notes {
            let p = n.opening()?;
            validate_payload_owner(&p, keys)?;
            let note = p.as_note();
            let key = match &p {
                RecoveredAssetNotePayload::Ordinary(_) => keys.spend.poseidon2_v8_words()?,
                RecoveredAssetNotePayload::Script(p) => p.policy.nullifier_key,
            };
            if n.chain != context.chain_id()
                || !positions.insert(n.position)
                || !self.private_spend_issued.contains(p.recipient_index())
                || transaction_circuit::private_spend::note_commitment(note).ok()
                    != Some(n.commitment)
                || transaction_circuit::private_spend::real_nullifier(
                    key,
                    u32::try_from(n.position).map_err(|_| invalid("asset note position"))?,
                    note,
                )
                .ok()
                    != Some(n.nullifier)
                || self.poseidon2_v8.canonical_hash(n.height) != Some(n.block)
                || self
                    .poseidon2_v8
                    .canonical_note_witness_at(n.commitment, n.position)?
                    .is_none()
                || n.spent != self.poseidon2_v8.has_canonical_nullifier(n.nullifier)
            {
                return Err(invalid("stored asset canonical opening mismatch"));
            }
        }
        let mut ids = HashSet::new();
        let mut reserved = HashSet::new();
        // Canonical rollback can revive an older exclusion over a newer route's
        // record. Preserve both; selectors and the pre-export guard reject fresh
        // use. Journal validation must not prevent authoritative chain sync.
        for r in &a.attempts {
            if r.id == [0; 32]
                || !ids.insert(r.id)
                || r.asset == 0
                || r.operation > 2
                || r.inputs.len() != if r.operation == relation::MINT { 1 } else { 2 }
                || crate::asset_spend_rpc::reference_last_parent(r.parent_height).is_err()
                || (attempt_active_at(r, self.poseidon2_v8.tip().ok().map(|t| t.height))
                    && r.inputs
                        .iter()
                        .any(|i| !reserved.insert((r.parent_height, r.parent_hash, i.nullifier))))
            {
                return Err(invalid("asset reservation collision or shape"));
            }
            if r.status == AssetSpendAttemptStatus::Proving {
                if !r.action.is_empty() || !r.action_id.is_empty() || r.mined_in.is_some() {
                    return Err(invalid("asset proving record contains exported bytes"));
                }
            } else if !r.action.is_empty() {
                validate_journal_action(context, r, &r.action)?;
            } else {
                return Err(invalid("asset journal action absent"));
            }
            if let Some((h, b)) = r.mined_in {
                if self.poseidon2_v8.canonical_hash(h) != Some(b)
                    || r.inputs
                        .iter()
                        .any(|i| !self.poseidon2_v8.has_canonical_nullifier(i.nullifier))
                {
                    return Err(invalid("asset inclusion differs from canonical inputs"));
                }
            }
        }
        Ok(())
    }
}
fn validate_journal_action(
    context: LaunchWalletContext,
    r: &AssetAttempt,
    body: &[u8],
) -> Result<(), WalletError> {
    let d = transaction_circuit::asset_spend_v1_wire::decode_native_asset_spend_action_v1(body)
        .map_err(|_| invalid("asset journal action framing"))?;
    let p = &d.public;
    if p.chain_id != context.chain_id()
        || p.reference_parent_hash != r.parent_hash
        || p.parent_height != r.parent_height
        || p.note_root != r.note_root
        || p.asset_id != r.asset
        || p.operation != r.operation
        || p.fee != r.fee
        || r.inputs.iter().enumerate().any(|(i, n)| {
            p.nullifiers[if r.operation == relation::MINT { 1 } else { i }] != n.nullifier
        })
    {
        return Err(invalid(
            "asset journal statement differs from reserved inputs",
        ));
    }
    Ok(())
}
impl WalletStore {
    fn with_asset_mut<T>(
        &self,
        context: LaunchWalletContext,
        f: impl FnOnce(&mut WalletState) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        self.ensure_writable()?;
        let mut s = self.state.lock().map_err(|_| invalid("wallet poisoned"))?;
        let previous = s.asset_spend.clone();
        let previous_private = s.private_spend_notes.clone();
        let previous_private_pin = s.private_spend_relation_digest.clone();
        let result = s
            .pin_asset_context(context)
            .and_then(|()| f(&mut s))
            .and_then(|r| {
                s.validate_asset_spend_state()?;
                self.write_state(&s)?;
                Ok(r)
            });
        if result.is_err() {
            s.asset_spend = previous;
            s.private_spend_notes = previous_private;
            s.private_spend_relation_digest = previous_private_pin;
        }
        result
    }
    pub fn asset_spend_notes(&self) -> Result<Vec<AssetNoteView>, WalletError> {
        self.with_state(|s| {
            s.validate_asset_spend_state()?;
            let reserved: HashSet<_> = s
                .asset_spend_reserved_nullifiers()
                .into_iter()
                .chain(s.other_asset_reservations())
                .collect();
            s.asset_spend
                .notes
                .iter()
                .map(|n| {
                    let p = n.opening()?;
                    let note = p.as_note();
                    Ok(AssetNoteView {
                        asset_id: n.asset,
                        value: note.value,
                        commitment: n.commitment,
                        nullifier: n.nullifier,
                        position: n.position,
                        recipient_index: p.recipient_index(),
                        script_owned: matches!(p, RecoveredAssetNotePayload::Script(_)),
                        spent: n.spent,
                        reserved: reserved.contains(&n.nullifier),
                        created_height: n.height,
                        created_block_hash: n.block,
                    })
                })
                .collect()
        })
    }
    /// Asset-route fee change is reported under asset zero; base native balances
    /// remain available through the existing native wallet balance API.
    pub fn asset_spend_balances(&self) -> Result<Vec<AssetBalance>, WalletError> {
        let mut balances = BTreeMap::<u32, AssetBalance>::new();
        for n in self.asset_spend_notes()?.into_iter().filter(|n| !n.spent) {
            let b = balances.entry(n.asset_id).or_insert_with(|| AssetBalance {
                asset_id: n.asset_id,
                ..Default::default()
            });
            if n.reserved {
                b.reserved += u128::from(n.value);
            } else if n.script_owned {
                b.policy_owned += u128::from(n.value);
            } else {
                b.available += u128::from(n.value);
            }
        }
        Ok(balances.into_values().collect())
    }
    pub fn require_asset_spend_reference(
        &self,
        context: LaunchWalletContext,
        reference: transaction_circuit::asset_spend_v1_admission::NativeAssetContextV1,
    ) -> Result<(), WalletError> {
        self.require_launch_context(context)?;
        if reference.chain_id != context.chain_id() {
            return Err(invalid("asset reference chain differs"));
        }
        self.with_state(|s| {
            require_stored_reference(
                s,
                context,
                reference.parent_height,
                reference.reference_parent_hash,
                reference.note_root,
            )
        })
    }
    /// Select exactly one asset input (none for mint) and one actual native fee
    /// input. Ordinary selection is automatic; policy input requires an exact
    /// position so spending conditions are reviewed by the caller.
    pub fn reserve_asset_spend(
        &self,
        context: LaunchWalletContext,
        asset: u32,
        operation: u8,
        needed: u64,
        fee: u64,
        policy_position: Option<u64>,
    ) -> Result<AssetSpendSelection, WalletError> {
        if asset == 0 || operation > 2 || fee >= 1 << 56 || needed >= 1 << 56 {
            return Err(invalid("asset selection request"));
        }
        let mut id = [0; 32];
        OsRng.fill_bytes(&mut id);
        self.with_asset_mut(context, |s| {
            let keys = s.derived.as_ref().ok_or(WalletError::WatchOnly)?;
            let tip = s.poseidon2_v8.tip()?;
            let reserved: HashSet<_> = s
                .other_asset_reservations()
                .into_iter()
                .chain(s.asset_spend_reserved_nullifiers())
                .chain(s.recovery_reserved_nullifiers())
                .collect();
            let mut asset_notes = Vec::new();
            let mut native = Vec::new();
            let mut seen = HashSet::new();
            for n in &s.asset_spend.notes {
                if n.spent || reserved.contains(&n.nullifier) {
                    continue;
                }
                let p = n.opening()?;
                let note = p.as_note();
                let policy = policy_of(&p);
                if n.asset == asset
                    && note.value >= needed
                    && (policy.is_none() && policy_position.is_none()
                        || policy_position == Some(n.position))
                {
                    asset_notes.push((
                        note.value,
                        n.position,
                        selected_input(
                            s,
                            keys,
                            n.commitment,
                            n.nullifier,
                            n.position,
                            note,
                            0,
                            policy,
                        )?,
                    ));
                } else if n.asset == 0
                    && note.value >= fee
                    && policy.is_none()
                    && seen.insert(n.nullifier)
                {
                    native.push((
                        note.value,
                        n.position,
                        selected_input(
                            s,
                            keys,
                            n.commitment,
                            n.nullifier,
                            n.position,
                            note,
                            0,
                            None,
                        )?,
                    ));
                }
            }
            // Matured native coinbase and ordinary transfers use their existing
            // canonical opening and legacy SINGLE-owner interpretation.
            for n in s.poseidon2_v8.owned_notes()? {
                if !n.spent
                    && n.opening.asset_id == 0
                    && n.opening.value >= fee
                    && !reserved.contains(&n.nullifier)
                    && seen.insert(n.nullifier)
                {
                    native.push((
                        n.opening.value,
                        n.position,
                        selected_input(
                            s,
                            keys,
                            n.commitment,
                            n.nullifier,
                            n.position,
                            note_from_native(n.opening),
                            1,
                            None,
                        )?,
                    ));
                }
            }
            for n in &s.private_spend_notes {
                if n.spent || reserved.contains(&n.nullifier) || !seen.insert(n.nullifier) {
                    continue;
                }
                let p = n.opening()?;
                if !matches!(
                    &p.state,
                    synthetic_crypto::private_note_payload::NoteState::Ordinary { .. }
                ) || p.note.asset_id != 0
                    || p.note.value < fee
                {
                    continue;
                }
                let note = Note {
                    value: p.note.value,
                    asset_id: p.note.asset_id,
                    recipient_key: p.note.recipient_key,
                    authorization_key: p.note.authorization_key,
                    rho: p.note.rho,
                    randomness: p.note.randomness,
                };
                native.push((
                    note.value,
                    n.position,
                    selected_input(
                        s,
                        keys,
                        n.commitment,
                        n.nullifier,
                        n.position,
                        note,
                        0,
                        None,
                    )?,
                ));
            }
            asset_notes.sort_by_key(|n| (n.0, n.1));
            native.sort_by_key(|n| (n.0, n.1));
            let asset_input = if operation == relation::MINT {
                None
            } else {
                Some(
                    asset_notes
                        .into_iter()
                        .next()
                        .ok_or(WalletError::InsufficientFunds {
                            needed,
                            available: 0,
                        })?
                        .2,
                )
            };
            let native_fee = native
                .into_iter()
                .next()
                .ok_or(WalletError::InsufficientFunds {
                    needed: fee,
                    available: 0,
                })?
                .2;
            let inputs = asset_input
                .iter()
                .chain(std::iter::once(&native_fee))
                .map(|n| AssetInputIdentity {
                    commitment: transaction_circuit::private_spend::note_commitment(n.input.note)
                        .expect("validated note"),
                    nullifier: n.nullifier,
                    position: u64::from(n.input.position),
                })
                .collect();
            s.asset_spend.attempts.push(AssetAttempt {
                id,
                parent_height: tip.height,
                parent_hash: tip.block_hash,
                note_root: tip.anchor,
                asset,
                operation,
                fee,
                inputs,
                status: AssetSpendAttemptStatus::Proving,
                action: Vec::new(),
                action_id: Vec::new(),
                mined_in: None,
            });
            Ok(AssetSpendSelection {
                reservation_id: id,
                parent_height: tip.height,
                parent_hash: tip.block_hash,
                note_root: tip.anchor,
                asset: asset_input,
                native_fee,
            })
        })
    }
    /// Persist exact, independently verified proof bytes before exporting or
    /// submitting. Candidate reservations survive process restart and rollback.
    pub fn retain_asset_spend_candidate(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
        body: &[u8],
    ) -> Result<(), WalletError> {
        let decoded =
            transaction_circuit::asset_spend_v1_wire::decode_native_asset_spend_action_v1(body)
                .map_err(|_| invalid("asset candidate framing"))?;
        relation::verify_candidate(&decoded.public, decoded.proof)
            .map_err(|_| invalid("asset candidate proof"))?;
        self.with_asset_mut(context, |s| {
            let existing = s
                .asset_spend
                .attempts
                .iter()
                .find(|r| r.id == id)
                .ok_or(invalid("asset reservation absent"))?;
            if existing.status == AssetSpendAttemptStatus::Proving {
                let tip = s.poseidon2_v8.tip()?.height;
                let other: HashSet<_> = s
                    .other_asset_reservations()
                    .into_iter()
                    .chain(
                        s.asset_spend
                            .attempts
                            .iter()
                            .filter(|r| r.id != id && attempt_active_at(r, Some(tip)))
                            .flat_map(|r| r.inputs.iter().map(|i| i.nullifier)),
                    )
                    .collect();
                if existing.inputs.iter().any(|i| {
                    other.contains(&i.nullifier)
                        || s.poseidon2_v8.has_canonical_nullifier(i.nullifier)
                }) {
                    // No body has escaped: retain the Proving hold, fail safely,
                    // and require explicit caller recovery. Never export it.
                    return Err(invalid("asset builder inputs changed before export"));
                }
            }
            let r = s
                .asset_spend
                .attempts
                .iter_mut()
                .find(|r| r.id == id)
                .expect("found above");
            validate_journal_action(context, r, body)?;
            if r.status != AssetSpendAttemptStatus::Proving {
                return if r.action == body {
                    Ok(())
                } else {
                    Err(invalid("asset candidate already differs"))
                };
            }
            r.action = body.to_vec();
            r.status = AssetSpendAttemptStatus::Candidate;
            Ok(())
        })
    }
    /// Call synchronously before the first mutating RPC poll.
    pub fn begin_asset_spend_submission(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
    ) -> Result<Vec<u8>, WalletError> {
        self.with_asset_mut(context, |s| {
            let at = s
                .asset_spend
                .attempts
                .iter()
                .position(|r| r.id == id)
                .ok_or(invalid("asset reservation absent"))?;
            let r = &s.asset_spend.attempts[at];
            if !matches!(
                r.status,
                AssetSpendAttemptStatus::Candidate
                    | AssetSpendAttemptStatus::SubmissionUncertain
                    | AssetSpendAttemptStatus::Submitted
            ) || r.mined_in.is_some()
                || r.inputs
                    .iter()
                    .any(|i| s.poseidon2_v8.has_canonical_nullifier(i.nullifier))
            {
                return Err(invalid("asset candidate reference is stale or not durable"));
            }
            require_stored_reference(s, context, r.parent_height, r.parent_hash, r.note_root)?;
            let r = &mut s.asset_spend.attempts[at];
            r.status = AssetSpendAttemptStatus::SubmissionUncertain;
            Ok(r.action.clone())
        })
    }

    pub fn mark_asset_spend_submitted(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
        action_id: [u8; 48],
    ) -> Result<(), WalletError> {
        self.with_asset_mut(context, |s| {
            let r = s
                .asset_spend
                .attempts
                .iter_mut()
                .find(|r| r.id == id)
                .ok_or(invalid("asset reservation absent"))?;
            if r.status != AssetSpendAttemptStatus::SubmissionUncertain
                || (!r.action_id.is_empty() && r.action_id != action_id)
            {
                return Err(invalid("asset submission state or action ID differs"));
            }
            r.status = AssetSpendAttemptStatus::Submitted;
            r.action_id = action_id.to_vec();
            Ok(())
        })
    }
    pub fn asset_spend_candidate(&self, id: [u8; 32]) -> Result<Vec<u8>, WalletError> {
        self.with_state(|s| {
            s.asset_spend
                .attempts
                .iter()
                .find(|r| r.id == id && !r.action.is_empty())
                .map(|r| r.action.clone())
                .ok_or(invalid("asset candidate absent"))
        })
    }
    pub fn asset_spend_attempts(&self) -> Result<Vec<AssetSpendAttemptView>, WalletError> {
        self.with_state(|s| {
            let reserved = s.asset_spend_reserved_nullifiers();
            Ok(s.asset_spend
                .attempts
                .iter()
                .map(|r| AssetSpendAttemptView {
                    id: r.id,
                    status: r.status,
                    parent_height: r.parent_height,
                    action_id: r.action_id.clone(),
                    mined_in: r.mined_in,
                    inputs_reserved: r.inputs.iter().any(|i| reserved.contains(&i.nullifier)),
                })
                .collect())
        })
    }
    /// Only an unexported builder can be discarded immediately. Exported bytes
    /// require H+12 to have expired; a rollback into that window revives exclusion.
    pub fn abandon_asset_spend(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
    ) -> Result<(), WalletError> {
        self.with_asset_mut(context, |s| {
            let index = s
                .asset_spend
                .attempts
                .iter()
                .position(|r| r.id == id)
                .ok_or(invalid("asset reservation absent"))?;
            if s.asset_spend.attempts[index].status == AssetSpendAttemptStatus::Proving {
                s.asset_spend.attempts.remove(index);
                return Ok(());
            }
            if s.poseidon2_v8.tip()?.height
                <= crate::asset_spend_rpc::reference_last_parent(
                    s.asset_spend.attempts[index].parent_height,
                )?
                || s.asset_spend.attempts[index].mined_in.is_some()
            {
                return Err(invalid("asset candidate may still be accepted"));
            }
            s.asset_spend.attempts[index].status = AssetSpendAttemptStatus::Abandoned;
            Ok(())
        })
    }
    /// The same trusted canonical block body must first be applied to the V8
    /// mirror. Exact native action framing and shared-tree occurrences are then
    /// checked here; neither caller supplied flags nor standalone receipts count.
    pub fn sync_asset_spend_block(
        &self,
        context: LaunchWalletContext,
        block: &Poseidon2V8CanonicalBlock,
    ) -> Result<usize, WalletError> {
        self.with_asset_mut(context, |s| s.recover_asset_spend_block(context, block))
    }
}
fn selected_input(
    s: &WalletState,
    keys: &DerivedKeys,
    commitment: Digest,
    nullifier: Digest,
    position: u64,
    note: Note,
    legacy: u64,
    policy: Option<BoundedPolicy>,
) -> Result<AssetSelectedInput, WalletError> {
    let witness = s
        .poseidon2_v8
        .canonical_note_witness_at(commitment, position)?
        .ok_or(invalid("asset input absent from shared tree"))?;
    let input = PrivateInput {
        occupied: 1,
        legacy_ordinary: legacy,
        note,
        position: u32::try_from(position).map_err(|_| invalid("asset input tree position"))?,
        siblings: witness.path,
        spend_key: keys.spend.poseidon2_v8_words()?,
        dummy_secret: [0; 5],
    };
    if transaction_circuit::private_spend::real_nullifier(
        policy.as_ref().map_or(input.spend_key, |p| p.nullifier_key),
        input.position,
        input.note,
    )
    .ok()
        != Some(nullifier)
    {
        return Err(invalid("asset input nullifier differs from native wallet"));
    }
    Ok(AssetSelectedInput {
        input,
        nullifier,
        policy,
    })
}

impl WalletState {
    /// Called in the same encrypted transaction as canonical mirror updates.
    pub(super) fn recover_asset_spend_block(
        &mut self,
        context: LaunchWalletContext,
        block: &Poseidon2V8CanonicalBlock,
    ) -> Result<usize, WalletError> {
        self.pin_asset_context(context)?;
        let s = self;
        if s.poseidon2_v8.canonical_hash(block.height) != Some(block.hash)
            || block.height == 0
            || s.poseidon2_v8.canonical_hash(block.height - 1) != Some(block.parent_hash)
        {
            return Err(invalid("asset sync block is not canonical"));
        }
        s.reconcile_asset_spend_state()?;
        let start = s
            .poseidon2_v8
            .canonical_block_leaf_count_before(block.height, block.hash)
            .ok_or(invalid("asset sync leaf range"))?;
        let end = s
            .poseidon2_v8
            .canonical_block_leaf_count_after(block.height, block.hash)
            .ok_or(invalid("asset sync leaf range"))?;
        let mut cursor = start;
        let mut recovered = 0;
        for raw in &block.action_bytes {
            let Some((action_id, body)) =
                crate::poseidon2_v8_sync::canonical_asset_action_body(raw)?
            else {
                continue;
            };
            let d = transaction_circuit::asset_spend_v1_wire::decode_native_asset_spend_action_v1(
                &body,
            )
            .map_err(|_| invalid("canonical asset body"))?;
            let reference = s
                .poseidon2_v8
                .canonical_tip_at_height(d.public.parent_height)
                .ok_or(invalid("asset sync canonical reference absent"))?;
            crate::asset_spend_rpc::require_reference_window(
                d.public.parent_height,
                block.height - 1,
            )?;
            if d.public.chain_id != context.chain_id()
                || d.public.reference_parent_hash != reference.block_hash
                || d.public.note_root != reference.anchor
                || d.public
                    .nullifiers
                    .iter()
                    .any(|n| !s.poseidon2_v8.has_canonical_nullifier(*n))
            {
                return Err(invalid("asset sync reference or nullifiers"));
            }
            let mut positions = Vec::new();
            for pos in s
                .poseidon2_v8
                .canonical_commitment_positions(d.public.commitments[0])?
            {
                if pos < cursor || pos.checked_add(2).map_or(true, |last| last >= end) {
                    continue;
                }
                if (1..3).all(|i| {
                    s.poseidon2_v8
                        .canonical_note_witness_at(d.public.commitments[i], pos + i as u64)
                        .ok()
                        .flatten()
                        .is_some()
                }) {
                    positions.push(pos);
                }
            }
            if positions.len() != 1 {
                return Err(invalid("asset output occurrence ambiguous or absent"));
            }
            let first = positions[0];
            cursor = first + 3;
            if let Some(keys) = &s.derived {
                for slot in 0..3 {
                    let Some(p) = recover_wallet_output(
                        keys,
                        &s.private_spend_issued,
                        &d.public,
                        slot as u8,
                        d.ciphertexts[slot],
                    )?
                    else {
                        continue;
                    };
                    let position = first + slot as u64;
                    let note = p.as_note();
                    let key = match &p {
                        RecoveredAssetNotePayload::Ordinary(_) => {
                            keys.spend.poseidon2_v8_words()?
                        }
                        RecoveredAssetNotePayload::Script(p) => p.policy.nullifier_key,
                    };
                    let nullifier = transaction_circuit::private_spend::real_nullifier(
                        key,
                        u32::try_from(position).map_err(|_| invalid("asset output position"))?,
                        note,
                    )
                    .map_err(|_| invalid("asset recovered nullifier"))?;
                    let n = StoredAssetNote {
                        chain: context.chain_id(),
                        asset: u32::try_from(note.asset_id)
                            .map_err(|_| invalid("asset output ID"))?,
                        commitment: d.public.commitments[slot],
                        nullifier,
                        position,
                        height: block.height,
                        block: block.hash,
                        spent: s.poseidon2_v8.has_canonical_nullifier(nullifier),
                        payload: encoded_payload(&p, context.chain_id(), note.asset_id as u32)?,
                    };
                    // Reuse the existing ordinary HGN wallet lifecycle. The
                    // native plaintext codec already permits only asset zero;
                    // this conversion preserves the exact opening and owner.
                    if let RecoveredAssetNotePayload::Ordinary(ordinary) = &p {
                        if n.asset == 0 {
                            let payload = synthetic_crypto::private_note_payload::PrivateNotePayload {
                                recipient_index: ordinary.recipient_index,
                                note: synthetic_crypto::private_note_payload::NoteOpening {
                                    value: note.value, asset_id: 0, recipient_key: note.recipient_key,
                                    authorization_key: note.authorization_key, rho: note.rho,
                                    randomness: note.randomness,
                                },
                                state: synthetic_crypto::private_note_payload::NoteState::Ordinary {
                                    authority: ordinary.authority,
                                },
                            };
                            let mut native = crate::private_spend::StoredPrivateSpendNote::new(
                                crate::private_spend::RecoveredPrivateSpendNote {
                                    address_index: ordinary.recipient_index,
                                    payload,
                                },
                                keys,
                                context.chain_id(),
                                n.commitment,
                                n.position,
                                n.height,
                                n.block,
                            )?;
                            native.spent = n.spent;
                            if let Some(old) = s
                                .private_spend_notes
                                .iter()
                                .find(|old| old.position == n.position)
                            {
                                if old.commitment != native.commitment
                                    || old.nullifier != native.nullifier
                                {
                                    return Err(invalid(
                                        "asset fee change differs from ordinary native occurrence",
                                    ));
                                }
                            } else {
                                s.private_spend_notes.push(native);
                            }
                        }
                    }
                    if let Some(old) = s
                        .asset_spend
                        .notes
                        .iter()
                        .find(|old| old.position == position)
                    {
                        if old.commitment != n.commitment
                            || old.nullifier != n.nullifier
                            || old.payload != n.payload
                        {
                            return Err(invalid("asset occurrence changed"));
                        }
                    } else {
                        s.asset_spend.notes.push(n);
                        recovered += 1;
                    }
                }
            }
            for a in &mut s.asset_spend.attempts {
                if a.action == body {
                    if !a.action_id.is_empty() && a.action_id != action_id {
                        return Err(invalid("asset mined action ID differs"));
                    }
                    a.action_id = action_id.to_vec();
                    a.mined_in = Some((block.height, block.hash));
                    a.status = AssetSpendAttemptStatus::Submitted;
                }
            }
        }
        if !s.private_spend_notes.is_empty() {
            s.pin_private_spend_source()?;
        }
        Ok(recovered)
    }
}

#[cfg(test)]
mod asset_journal_tests {
    use super::*;
    fn attempt(id: u8, status: AssetSpendAttemptStatus) -> AssetAttempt {
        AssetAttempt {
            id: [id; 32],
            parent_height: 7,
            parent_hash: [3; 32],
            note_root: [4; 7],
            asset: 17,
            operation: relation::MINT,
            fee: 10,
            inputs: vec![AssetInputIdentity {
                commitment: [5; 7],
                nullifier: [6; 7],
                position: 0,
            }],
            status,
            action: if status == AssetSpendAttemptStatus::Proving {
                Vec::new()
            } else {
                vec![id; 64]
            },
            action_id: Vec::new(),
            mined_in: None,
        }
    }
    #[test]
    fn serialized_journal_recovery_releases_only_unexported_builders() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("asset-wallet.dat");
        let store = WalletStore::create_from_root(
            &path,
            "private-test-passphrase",
            crate::RootSecret::from_bytes([42; 32]),
        )
        .unwrap();
        // Test recovery independently of acceptance: exported records deliberately
        // contain no proof and cannot pass validate_asset_spend_state/admission.
        let mut state = store.state.lock().unwrap();
        state.asset_spend.attempts = vec![
            attempt(1, AssetSpendAttemptStatus::Proving),
            attempt(2, AssetSpendAttemptStatus::Candidate),
            attempt(3, AssetSpendAttemptStatus::SubmissionUncertain),
            attempt(4, AssetSpendAttemptStatus::Submitted),
            attempt(5, AssetSpendAttemptStatus::Abandoned),
        ];
        let encoded = bincode::serialize(&state.asset_spend).unwrap();
        state.asset_spend = bincode::deserialize(&encoded).unwrap();
        assert!(state.recover_asset_spend_proving());
        assert_eq!(
            state
                .asset_spend
                .attempts
                .iter()
                .map(|a| a.id[0])
                .collect::<Vec<_>>(),
            vec![2, 3, 4, 5]
        );
        assert_eq!(state.asset_spend.attempts[1].action, vec![3; 64]);
        assert!(!state.recover_asset_spend_proving());
    }
    #[test]
    fn abandoned_reservations_reactivate_through_last_parent_after_restart() {
        let original = attempt(8, AssetSpendAttemptStatus::Abandoned);
        let encoded = bincode::serialize(&original).unwrap();
        let restored: AssetAttempt = bincode::deserialize(&encoded).unwrap();
        assert!(!attempt_active_at(&restored, Some(20)));
        for parent in [19, 18, 7] {
            assert!(attempt_active_at(&restored, Some(parent)));
        }
        assert!(attempt_active_at(&restored, None));
        assert_eq!(restored.action, original.action);
        for status in [
            AssetSpendAttemptStatus::Candidate,
            AssetSpendAttemptStatus::SubmissionUncertain,
            AssetSpendAttemptStatus::Submitted,
        ] {
            let retained = attempt(9, status);
            assert!(attempt_active_at(&retained, Some(1000)));
            assert_eq!(retained.action, vec![9; 64]);
        }
    }
    #[test]
    fn rollback_restores_asset_hold_alongside_later_native_record() {
        let directory = tempfile::tempdir().unwrap();
        let store = WalletStore::create_from_root(
            directory.path().join("wallet.dat"),
            "private-test-passphrase",
            crate::RootSecret::from_bytes([44; 32]),
        )
        .unwrap();
        let mut state = store.state.lock().unwrap();
        state
            .poseidon2_v8
            .ensure_genesis_for_test([70; 32], [0; 7])
            .unwrap();
        for height in 1..=20 {
            let parent = state.poseidon2_v8.tip().unwrap();
            state
                .poseidon2_v8
                .apply_block(
                    &Poseidon2V8CanonicalBlock {
                        height,
                        hash: [height as u8; 32],
                        parent_hash: parent.block_hash,
                        action_bytes: vec![],
                    },
                    None,
                )
                .unwrap();
        }
        state
            .asset_spend
            .attempts
            .push(attempt(8, AssetSpendAttemptStatus::Abandoned));
        assert!(!state.asset_spend_reserved_nullifiers().contains(&[6; 7]));
        // A later route has an uncertain exported attempt after H+12 expired.
        // Deserialize its existing exact journal shape; this is not a proof.
        let input = |position, nullifier| {
            serde_json::json!({"commitment":([5;7]),
            "nullifier":nullifier,"position":position,"created_block_hash":([1;32])})
        };
        let later = serde_json::json!({"id":([9;32]),"genesis_hash":([70;32]),
            "parent_height":20,"parent_hash":([20;32]),
            "inputs":[input(0, [6;7]),input(1,[7;7])],"status":"SubmissionUncertain"});
        state
            .poseidon2_v8_reservations
            .push(serde_json::from_value(later).unwrap());
        state.poseidon2_v8.rollback_to(19, [19; 32]).unwrap();
        state.reconcile_asset_spend_state().unwrap();
        state.validate_poseidon2_v8_reservations().unwrap();
        assert!(state.asset_spend_reserved_nullifiers().contains(&[6; 7]));
        // This exact union feeds both fresh native and asset selectors.
        assert!(state.reserved_poseidon2_v8_nullifiers().contains(&[6; 7]));
        assert_eq!(state.asset_spend.attempts[0].action, vec![8; 64]);
        assert_eq!(
            state.asset_spend.attempts[0].status,
            AssetSpendAttemptStatus::Abandoned
        );
    }
    #[test]
    fn default_asset_state_has_no_balance_or_unpinned_reservations() {
        let directory = tempfile::tempdir().unwrap();
        let store = WalletStore::create_from_root(
            directory.path().join("wallet.dat"),
            "private-test-passphrase",
            crate::RootSecret::from_bytes([43; 32]),
        )
        .unwrap();
        assert!(store.asset_spend_notes().unwrap().is_empty());
        assert!(store.asset_spend_balances().unwrap().is_empty());
        assert!(store.asset_spend_attempts().unwrap().is_empty());
    }
}
