//! Recovery holder material and immutable attempts in the encrypted WalletStore.
//! No independent pool, NF set, archive contact, or caller acceptance flag.
use super::*;
use crate::asset_recovery_v1::{
    RecoveryNoteContextV1, RecoveryNoteMaterialV1, RecoveryNotePlaintextV1,
};
use crate::poseidon2_v8_sync::{
    canonical_recovery_action_body, LaunchWalletContext, RECOVERY_SPEND_ACTION_ID,
};
use transaction_circuit::{asset_recovery_spend_v1 as relation, asset_recovery_wire_v1 as wire};
type Digest = [u64; 7];
fn invalid(s: &'static str) -> WalletError {
    WalletError::InvalidState(s)
}
#[derive(Clone, Serialize, Deserialize)]
struct HolderNote {
    chain: [u8; 32],
    asset: u32,
    policy: Digest,
    cm: Digest,
    nf: Digest,
    position: u64,
    height: u64,
    block: [u8; 32],
    recipient_index: u32,
    source: Vec<u8>,
    payload: Vec<u8>,
    spent: bool,
}
impl std::fmt::Debug for HolderNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HolderNote { [REDACTED] }")
    }
}
impl Drop for HolderNote {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}
impl HolderNote {
    fn context(&self) -> RecoveryNoteContextV1 {
        RecoveryNoteContextV1 {
            chain_id: self.chain,
            asset_id: self.asset,
            stable_policy_id: self.policy,
            output_commitment: self.cm,
        }
    }
    fn material(&self) -> Result<RecoveryNoteMaterialV1, WalletError> {
        RecoveryNoteMaterialV1::decode(
            &RecoveryNotePlaintextV1::from_bytes_exact(&self.payload)?,
            &self.context(),
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryAttemptStatus {
    Proving,
    Candidate,
    SubmissionUncertain,
    Submitted,
    Abandoned,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Attempt {
    id: [u8; 32],
    parent_height: u64,
    parent_hash: [u8; 32],
    public_words: Vec<u64>,
    nullifiers: [Digest; 2],
    status: RecoveryAttemptStatus,
    body: Vec<u8>,
    action_id: Vec<u8>,
    mined: Option<(u64, [u8; 32])>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(super) struct RecoveryWalletState {
    notes: Vec<HolderNote>,
    attempts: Vec<Attempt>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecoveryNoteView {
    pub asset_id: u32,
    pub value: u64,
    pub commitment: Digest,
    pub nullifier: Digest,
    pub position: u64,
    pub recipient_index: u32,
    pub spent: bool,
    pub reserved: bool,
    pub created_height: u64,
    pub created_block_hash: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecoveryAttemptView {
    pub id: [u8; 32],
    pub status: RecoveryAttemptStatus,
    pub parent_height: u64,
    pub action_id: Vec<u8>,
    pub mined_in: Option<(u64, [u8; 32])>,
    pub inputs_reserved: bool,
}
fn active(a: &Attempt, tip: Option<u64>) -> bool {
    a.status != RecoveryAttemptStatus::Abandoned
        || tip.map_or(true, |h| {
            h <= a.parent_height.saturating_add(
                protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW,
            )
        })
}
impl WalletState {
    pub(super) fn recovery_reserved_nullifiers(&self) -> HashSet<Digest> {
        let tip = self.poseidon2_v8.tip().ok().map(|t| t.height);
        self.recovery
            .attempts
            .iter()
            .filter(|a| active(a, tip))
            .flat_map(|a| a.nullifiers)
            .collect()
    }
    fn other_recovery_holds(&self) -> HashSet<Digest> {
        self.reserved_ordinary_poseidon2_v8_nullifiers()
            .into_iter()
            .chain(self.htlc_reserved_nullifiers())
            .chain(self.private_spend_reserved_nullifiers())
            .chain(self.asset_spend_reserved_nullifiers())
            .chain(crate::poseidon2_v8_multisig::active_reserved_nullifiers(
                &self.poseidon2_v8_treasuries,
                &self.poseidon2_v8,
            ))
            .collect()
    }
    fn require_recovery_exclusive(&self, id: [u8; 32]) -> Result<(), WalletError> {
        let a = self
            .recovery
            .attempts
            .iter()
            .find(|a| a.id == id)
            .ok_or(invalid("recovery attempt absent"))?;
        let mut other = self.other_recovery_holds();
        let tip = self.poseidon2_v8.tip().ok().map(|t| t.height);
        for b in self
            .recovery
            .attempts
            .iter()
            .filter(|b| b.id != id && active(b, tip))
        {
            other.extend(b.nullifiers);
        }
        if a.nullifiers.iter().any(|n| other.contains(n)) {
            return Err(invalid("recovery input held by another route"));
        }
        Ok(())
    }
    fn require_recovery_reference_and_unspent(&self, id: [u8; 32]) -> Result<(), WalletError> {
        let a = self
            .recovery
            .attempts
            .iter()
            .find(|a| a.id == id)
            .ok_or(invalid("recovery attempt absent"))?;
        let tip = self.poseidon2_v8.tip()?;
        if self.poseidon2_v8.canonical_hash(a.parent_height) != Some(a.parent_hash) {
            return Err(invalid("recovery original reference orphaned"));
        }
        crate::asset_spend_rpc::require_reference_window(a.parent_height, tip.height)?;
        if a.nullifiers
            .iter()
            .any(|n| self.poseidon2_v8.has_canonical_nullifier(*n))
        {
            return Err(invalid("recovery input canonically consumed"));
        }
        Ok(())
    }
    pub(super) fn recover_recovery_proving(&mut self) -> bool {
        let old = self.recovery.attempts.len();
        self.recovery
            .attempts
            .retain(|a| a.status != RecoveryAttemptStatus::Proving);
        old != self.recovery.attempts.len()
    }
    pub(super) fn reconcile_recovery_state(&mut self) -> Result<(), WalletError> {
        self.recovery
            .notes
            .retain(|n| self.poseidon2_v8.canonical_hash(n.height) == Some(n.block));
        for n in &mut self.recovery.notes {
            n.spent = self.poseidon2_v8.has_canonical_nullifier(n.nf);
        }
        for a in &mut self.recovery.attempts {
            if a.mined
                .is_some_and(|(h, b)| self.poseidon2_v8.canonical_hash(h) != Some(b))
            {
                a.mined = None;
            }
        }
        Ok(())
    }
    pub(super) fn validate_recovery_state(&self) -> Result<(), WalletError> {
        let mut positions = HashSet::new();
        let mut ids = HashSet::new();
        let keys = self.derived.as_ref();
        for n in &self.recovery.notes {
            let m = n.material()?;
            let context = self
                .native_launch_context
                .as_ref()
                .ok_or(invalid("recovery pinned context absent"))?
                .current_context()?;
            let keys = keys.ok_or(WalletError::WatchOnly)?;
            let address = keys.poseidon2_v8_address(n.recipient_index)?;
            let authority=transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_digest(keys.spend.poseidon2_v8_words()?).map_err(|_|invalid("recovery local authority"))?;
            let recipient=transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_from_canonical_bytes(address.pk_recipient).map_err(|_|invalid("recovery recipient"))?;
            if n.source != relation::relation_digest()
                || n.chain != context.chain_id()
                || !self.private_spend_issued.contains(n.recipient_index)
                || m.holder_authority != authority
                || m.note.recipient_key != recipient
                || !positions.insert(n.position)
                || m.common_nullifier(
                    &n.context(),
                    u32::try_from(n.position).map_err(|_| invalid("recovery position"))?,
                )? != n.nf
                || self.poseidon2_v8.canonical_hash(n.height) != Some(n.block)
                || self
                    .poseidon2_v8
                    .canonical_note_witness_at(n.cm, n.position)?
                    .is_none()
                || n.spent != self.poseidon2_v8.has_canonical_nullifier(n.nf)
            {
                return Err(invalid("stored recovery note binding"));
            }
        }
        for a in &self.recovery.attempts {
            if a.public_words.len() != relation::PUBLIC_WORDS
                || a.public_words.iter().any(|w| *w >= 0xffff_ffff_0000_0001)
                || !ids.insert(a.id)
                || a.nullifiers[0] == a.nullifiers[1]
                || a.action_id.len() != 0 && a.action_id.len() != 48
            {
                return Err(invalid("recovery attempt identity"));
            }
            if a.status == RecoveryAttemptStatus::Proving {
                if !a.body.is_empty() {
                    return Err(invalid("unexported recovery body"));
                }
            } else {
                let d =
                    wire::decode_spend_ref(&a.body).map_err(|_| invalid("stored recovery body"))?;
                if d.public
                    .words()
                    .map_err(|_| invalid("stored recovery public"))?
                    != a.public_words
                    || d.public.base.nullifiers != a.nullifiers
                {
                    return Err(invalid("stored recovery body changed"));
                }
            }
        }
        Ok(())
    }
    pub(super) fn recover_recovery_block(
        &mut self,
        context: LaunchWalletContext,
        block: &Poseidon2V8CanonicalBlock,
    ) -> Result<usize, WalletError> {
        if self.poseidon2_v8.canonical_hash(block.height) != Some(block.hash)
            || block.height == 0
            || self.poseidon2_v8.canonical_hash(block.height - 1) != Some(block.parent_hash)
        {
            return Err(invalid("recovery block not canonical"));
        }
        self.reconcile_recovery_state()?;
        let start = self
            .poseidon2_v8
            .canonical_block_leaf_count_before(block.height, block.hash)
            .ok_or(invalid("recovery leaf range"))?;
        let end = self
            .poseidon2_v8
            .canonical_block_leaf_count_after(block.height, block.hash)
            .ok_or(invalid("recovery leaf range"))?;
        let mut cursor = start;
        let mut recovered = 0;
        for raw in &block.action_bytes {
            let Some((id, route, body)) = canonical_recovery_action_body(raw)? else {
                continue;
            };
            if route != RECOVERY_SPEND_ACTION_ID {
                continue;
            }
            let d =
                wire::decode_spend_ref(&body).map_err(|_| invalid("canonical recovery body"))?;
            let p = &d.public.base;
            let reference = self
                .poseidon2_v8
                .canonical_tip_at_height(p.parent_height)
                .ok_or(invalid("recovery reference absent"))?;
            crate::asset_spend_rpc::require_reference_window(p.parent_height, block.height - 1)?;
            if p.chain_id != context.chain_id()
                || p.reference_parent_hash != reference.block_hash
                || p.note_root != reference.anchor
                || p.nullifiers
                    .iter()
                    .any(|n| !self.poseidon2_v8.has_canonical_nullifier(*n))
            {
                return Err(invalid("recovery reference or common NF"));
            }
            let positions = self
                .poseidon2_v8
                .canonical_commitment_positions(p.commitments[0])?
                .into_iter()
                .filter(|pos| *pos >= cursor && pos.checked_add(2).is_some_and(|last| last < end))
                .filter(|pos| {
                    (1..3).all(|i| {
                        self.poseidon2_v8
                            .canonical_note_witness_at(p.commitments[i], *pos + i as u64)
                            .ok()
                            .flatten()
                            .is_some()
                    })
                })
                .collect::<Vec<_>>();
            if positions.len() != 1 {
                return Err(invalid("recovery output occurrence ambiguous or absent"));
            }
            let first = positions[0];
            cursor = first + 3;
            if let Some(keys) = &self.derived {
                let authority=transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_digest(keys.spend.poseidon2_v8_words()?).map_err(|_|invalid("recovery local authority"))?;
                for index in self.private_spend_issued.issued_indices() {
                    let address = keys.poseidon2_v8_address(index)?;
                    let recipient=transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_from_canonical_bytes(address.pk_recipient).map_err(|_|invalid("recovery recipient"))?;
                    for slot in 0..2 {
                        let Ok(material) = crate::asset_recovery_build_v1::decrypt_holder_output(
                            &d.public,
                            slot as u8,
                            d.ciphertexts[slot],
                            address.secret_key(),
                            recipient,
                            authority,
                        ) else {
                            continue;
                        };
                        let cm = p.commitments[slot];
                        let position = first + slot as u64;
                        let ctx = RecoveryNoteContextV1 {
                            chain_id: p.chain_id,
                            asset_id: p.asset_id,
                            stable_policy_id: d.public.row.descriptor.stable_policy_id,
                            output_commitment: cm,
                        };
                        let nf = material.common_nullifier(
                            &ctx,
                            u32::try_from(position).map_err(|_| invalid("recovery position32"))?,
                        )?;
                        if let Some(old) =
                            self.recovery.notes.iter().find(|n| n.position == position)
                        {
                            if old.cm != cm || old.nf != nf {
                                return Err(invalid("recovery duplicate occurrence"));
                            }
                            continue;
                        }
                        self.recovery.notes.push(HolderNote {
                            chain: p.chain_id,
                            asset: p.asset_id,
                            policy: ctx.stable_policy_id,
                            cm,
                            nf,
                            position,
                            height: block.height,
                            block: block.hash,
                            recipient_index: index,
                            source: relation::relation_digest().to_vec(),
                            payload: material.encode(&ctx)?.as_bytes().to_vec(),
                            spent: self.poseidon2_v8.has_canonical_nullifier(nf),
                        });
                        recovered += 1;
                    }
                    if let Ok(fee) = crate::asset_recovery_build_v1::decrypt_native_fee_change(
                        &d.public,
                        d.ciphertexts[2],
                        address.secret_key(),
                        index,
                        recipient,
                        authority,
                    ) {
                        self.poseidon2_v8.import_recovery_native_fee(
                            &fee,
                            p.commitments[2],
                            first + 2,
                            block,
                            keys,
                        )?;
                        let n = fee.as_note();
                        let payload = synthetic_crypto::private_note_payload::PrivateNotePayload {
                            recipient_index: fee.recipient_index,
                            note: synthetic_crypto::private_note_payload::NoteOpening {
                                value: n.value,
                                asset_id: n.asset_id,
                                recipient_key: n.recipient_key,
                                authorization_key: n.authorization_key,
                                rho: n.rho,
                                randomness: n.randomness,
                            },
                            state: synthetic_crypto::private_note_payload::NoteState::Ordinary {
                                authority: fee.authority,
                            },
                        };
                        let mut native = crate::private_spend::StoredPrivateSpendNote::new(
                            crate::private_spend::RecoveredPrivateSpendNote {
                                address_index: fee.recipient_index,
                                payload,
                            },
                            keys,
                            p.chain_id,
                            p.commitments[2],
                            first + 2,
                            block.height,
                            block.hash,
                        )?;
                        native.spent = self.poseidon2_v8.has_canonical_nullifier(native.nullifier);
                        if !self.poseidon2_v8.owned_notes()?.iter().any(|n| {
                            n.position == native.position
                                && n.commitment == native.commitment
                                && n.nullifier == native.nullifier
                        }) {
                            return Err(invalid("recovery native fee bridge NF mismatch"));
                        }
                        if let Some(old) = self
                            .private_spend_notes
                            .iter()
                            .find(|n| n.position == native.position)
                        {
                            if old.commitment != native.commitment
                                || old.nullifier != native.nullifier
                            {
                                return Err(invalid("recovery private fee occurrence mismatch"));
                            }
                        } else {
                            self.private_spend_notes.push(native);
                        }
                    }
                }
            }
            for a in &mut self.recovery.attempts {
                if a.body == body {
                    if !a.action_id.is_empty() && a.action_id != id {
                        return Err(invalid("recovery included action identity changed"));
                    }
                    a.action_id = id.to_vec();
                    a.mined = Some((block.height, block.hash));
                }
            }
        }
        Ok(recovered)
    }
}
impl WalletStore {
    fn with_recovery_mut<T>(
        &self,
        f: impl FnOnce(&mut WalletState) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        self.ensure_writable()?;
        let mut s = self.state.lock().map_err(|_| invalid("wallet poisoned"))?;
        let previous = s.recovery.clone();
        let result = (|| {
            let result = f(&mut s)?;
            s.validate_recovery_state()?;
            self.write_state(&s)?;
            Ok(result)
        })();
        if result.is_err() {
            s.recovery = previous;
        }
        result
    }
    pub fn recovery_notes(&self) -> Result<Vec<RecoveryNoteView>, WalletError> {
        self.with_state(|s| {
            let reserved = s.reserved_poseidon2_v8_nullifiers();
            s.recovery
                .notes
                .iter()
                .map(|n| {
                    Ok(RecoveryNoteView {
                        asset_id: n.asset,
                        value: n.material()?.note.value,
                        commitment: n.cm,
                        nullifier: n.nf,
                        position: n.position,
                        recipient_index: n.recipient_index,
                        spent: n.spent,
                        reserved: reserved.contains(&n.nf),
                        created_height: n.height,
                        created_block_hash: n.block,
                    })
                })
                .collect()
        })
    }
    /// Secret material is returned only in memory, with its zeroizing codec type.
    pub fn recovery_note_material(
        &self,
        position: u64,
    ) -> Result<(RecoveryNoteContextV1, RecoveryNoteMaterialV1), WalletError> {
        self.with_state(|s| {
            let n = s
                .recovery
                .notes
                .iter()
                .find(|n| n.position == position)
                .ok_or(invalid("recovery note absent"))?;
            if n.spent {
                return Err(invalid("recovery note spent"));
            }
            Ok((n.context(), n.material()?))
        })
    }
    /// Reserve exact real input occurrences before proving. Mint has one real fee
    /// position; holder/delegate have the recovery input followed by the fee input.
    pub fn reserve_recovery_spend(
        &self,
        context: LaunchWalletContext,
        public: &relation::Public,
        positions: &[u64],
    ) -> Result<[u8; 32], WalletError> {
        self.reserve_recovery_spend_inner(context, public, positions, None)
    }
    /// An archive delegate holds the SAME note NF as its holder. This accepts
    /// recovery material, never archive-key possession as action authority;
    /// current delegate authorization remains the relation/node's obligation.
    /// Exact material and membership are checked before the atomic journal write.
    pub fn reserve_recovery_delegate_spend(
        &self,
        context: LaunchWalletContext,
        public: &relation::Public,
        material: &RecoveryNoteMaterialV1,
        position: u32,
        fee_position: u64,
    ) -> Result<[u8; 32], WalletError> {
        if public.base.operation == transaction_circuit::asset_spend_v1::MINT {
            return Err(invalid("delegate cannot reserve mint"));
        }
        self.reserve_recovery_spend_inner(
            context,
            public,
            &[u64::from(position), fee_position],
            Some((material, position)),
        )
    }
    fn reserve_recovery_spend_inner(
        &self,
        context: LaunchWalletContext,
        public: &relation::Public,
        positions: &[u64],
        external: Option<(&RecoveryNoteMaterialV1, u32)>,
    ) -> Result<[u8; 32], WalletError> {
        public
            .validate_structure()
            .map_err(|_| invalid("recovery public structure"))?;
        self.with_recovery_mut(|s| {
            let p = &public.base;
            let tip = s.poseidon2_v8.tip()?;
            let pinned = s
                .native_launch_context
                .as_ref()
                .ok_or(invalid("recovery context absent"))?;
            pinned.require_match(context)?;
            crate::asset_spend_rpc::require_reference_window(p.parent_height, tip.height)?;
            let reference = s
                .poseidon2_v8
                .canonical_tip_at_height(p.parent_height)
                .ok_or(invalid("recovery reserve reference absent"))?;
            if p.chain_id != context.chain_id()
                || p.reference_parent_hash != reference.block_hash
                || p.note_root != reference.anchor
            {
                return Err(invalid("recovery reserve reference"));
            }
            let mint = p.operation == transaction_circuit::asset_spend_v1::MINT;
            if positions.len() != if mint { 1 } else { 2 } {
                return Err(invalid("recovery reserve real inputs"));
            }
            if let Some((material, position)) = external {
                let cm = transaction_circuit::private_spend::note_commitment(material.as_note())
                    .map_err(|_| invalid("recovery delegate material commitment"))?;
                let material_context = RecoveryNoteContextV1 {
                    chain_id: p.chain_id,
                    asset_id: p.asset_id,
                    stable_policy_id: public.row.descriptor.stable_policy_id,
                    output_commitment: cm,
                };
                material.validate(&material_context)?;
                if positions.first() != Some(&u64::from(position))
                    || material.common_nullifier(&material_context, position)? != p.nullifiers[0]
                    || s.poseidon2_v8
                        .canonical_note_witness_at(cm, u64::from(position))?
                        .is_none()
                {
                    return Err(invalid("recovery delegate canonical material identity"));
                }
            } else if !mint {
                let n = s
                    .recovery
                    .notes
                    .iter()
                    .find(|n| n.position == positions[0] && n.asset == p.asset_id && !n.spent)
                    .ok_or(invalid("recovery holder input absent"))?;
                if n.nf != p.nullifiers[0]
                    || s.poseidon2_v8
                        .canonical_note_witness_at(n.cm, n.position)?
                        .is_none()
                {
                    return Err(invalid("recovery input identity"));
                }
            }
            let fee_pos = *positions.last().ok_or(invalid("recovery fee position"))?;
            if !s.poseidon2_v8.owned_notes()?.iter().any(|n| {
                n.position == fee_pos
                    && n.opening.asset_id == NATIVE_ASSET_ID
                    && !n.spent
                    && n.nullifier == p.nullifiers[1]
            }) {
                return Err(invalid("recovery native fee input absent"));
            }
            let held = s.reserved_poseidon2_v8_nullifiers();
            if p.nullifiers[0] == p.nullifiers[1]
                || p.nullifiers
                    .iter()
                    .any(|n| held.contains(n) || s.poseidon2_v8.has_canonical_nullifier(*n))
            {
                return Err(invalid("recovery input reserved or spent"));
            }
            let mut id = [0; 32];
            OsRng.fill_bytes(&mut id);
            if s.recovery.attempts.iter().any(|a| a.id == id) {
                return Err(invalid("recovery reservation collision"));
            }
            s.recovery.attempts.push(Attempt {
                id,
                parent_height: p.parent_height,
                parent_hash: p.reference_parent_hash,
                public_words: public
                    .words()
                    .map_err(|_| invalid("recovery public words"))?,
                nullifiers: p.nullifiers,
                status: RecoveryAttemptStatus::Proving,
                body: vec![],
                action_id: vec![],
                mined: None,
            });
            Ok(id)
        })
    }
    /// Actual proofs are verified before retention; structurally framed bytes alone
    /// cannot become an exportable candidate. Body and original H are immutable.
    pub fn retain_recovery_spend(&self, id: [u8; 32], body: &[u8]) -> Result<(), WalletError> {
        let d = wire::decode_spend_ref(body).map_err(|_| invalid("recovery candidate framing"))?;
        relation::verify_candidate(&d.public, d.proof)
            .map_err(|_| invalid("recovery candidate proof"))?;
        for c in &d.capsules {
            transaction_circuit::asset_recovery_capsule_v1::verify(&c.public, c.proof)
                .map_err(|_| invalid("recovery capsule proof"))?;
        }
        let words = d
            .public
            .words()
            .map_err(|_| invalid("recovery candidate public"))?;
        self.with_recovery_mut(|s| {
            s.require_recovery_exclusive(id)?;
            s.require_recovery_reference_and_unspent(id)?;
            let a = s
                .recovery
                .attempts
                .iter_mut()
                .find(|a| a.id == id)
                .ok_or(invalid("recovery attempt absent"))?;
            if a.status != RecoveryAttemptStatus::Proving || a.public_words != words {
                return Err(invalid("recovery candidate differs from reservation"));
            }
            a.body = body.to_vec();
            a.status = RecoveryAttemptStatus::Candidate;
            Ok(())
        })
    }
    /// Read the immutable retained public artifact for archival export. This
    /// read does not establish current inclusion or submission eligibility:
    /// recovery_candidate_bytes and begin_recovery_submission keep those gates.
    /// Proving, abandoned, empty or identity-mismatched records are not exposed.
    pub fn recovery_retained_bytes(&self, id: [u8; 32]) -> Result<Vec<u8>, WalletError> {
        self.with_state(|s| {
            let a = s
                .recovery
                .attempts
                .iter()
                .find(|a| a.id == id)
                .ok_or(invalid("recovery attempt absent"))?;
            if !matches!(
                a.status,
                RecoveryAttemptStatus::Candidate
                    | RecoveryAttemptStatus::SubmissionUncertain
                    | RecoveryAttemptStatus::Submitted
            ) || a.body.is_empty()
            {
                return Err(invalid("recovery retained artifact unavailable"));
            }
            let context = s
                .native_launch_context
                .as_ref()
                .ok_or(invalid("recovery pinned context absent"))?
                .current_context()?;
            let decoded = wire::decode_spend_ref(&a.body)
                .map_err(|_| invalid("recovery retained artifact framing"))?;
            if decoded.public.words().map_err(|_| invalid("recovery retained public"))?
                != a.public_words
                || decoded.public.base.nullifiers != a.nullifiers
                || decoded.public.base.chain_id != context.chain_id()
                || decoded.public.base.parent_height != a.parent_height
                || decoded.public.base.reference_parent_hash != a.parent_hash
            {
                return Err(invalid("recovery retained artifact identity"));
            }
            Ok(a.body.clone())
        })
    }
    pub fn recovery_candidate_bytes(&self, id: [u8; 32]) -> Result<Vec<u8>, WalletError> {
        self.with_state(|s| {
            s.require_recovery_exclusive(id)?;
            s.require_recovery_reference_and_unspent(id)?;
            let a = s
                .recovery
                .attempts
                .iter()
                .find(|a| a.id == id)
                .ok_or(invalid("recovery attempt absent"))?;
            if a.status == RecoveryAttemptStatus::Proving
                || a.status == RecoveryAttemptStatus::Abandoned
            {
                return Err(invalid("recovery candidate unavailable"));
            }
            Ok(a.body.clone())
        })
    }
    /// Must precede the first mutating RPC poll. Failure leaves uncertainty durable.
    pub fn begin_recovery_submission(&self, id: [u8; 32]) -> Result<(), WalletError> {
        self.with_recovery_mut(|s| {
            s.require_recovery_exclusive(id)?;
            s.require_recovery_reference_and_unspent(id)?;
            let a = s
                .recovery
                .attempts
                .iter_mut()
                .find(|a| a.id == id)
                .ok_or(invalid("recovery attempt absent"))?;
            if !matches!(
                a.status,
                RecoveryAttemptStatus::Candidate
                    | RecoveryAttemptStatus::SubmissionUncertain
                    | RecoveryAttemptStatus::Submitted
            ) {
                return Err(invalid("recovery cannot submit this status"));
            }
            a.status = RecoveryAttemptStatus::SubmissionUncertain;
            Ok(())
        })
    }
    pub fn mark_recovery_submitted(
        &self,
        id: [u8; 32],
        action_id: [u8; 48],
    ) -> Result<(), WalletError> {
        self.with_recovery_mut(|s| {
            let a = s
                .recovery
                .attempts
                .iter_mut()
                .find(|a| a.id == id)
                .ok_or(invalid("recovery attempt absent"))?;
            if a.status != RecoveryAttemptStatus::SubmissionUncertain
                || !a.action_id.is_empty() && a.action_id != action_id
            {
                return Err(invalid("recovery submission transition"));
            }
            a.action_id = action_id.to_vec();
            a.status = RecoveryAttemptStatus::Submitted;
            Ok(())
        })
    }
    pub fn abandon_recovery_spend(&self, id: [u8; 32]) -> Result<(), WalletError> {
        self.with_recovery_mut(|s| {
            let tip = s.poseidon2_v8.tip()?.height;
            let a = s
                .recovery
                .attempts
                .iter_mut()
                .find(|a| a.id == id)
                .ok_or(invalid("recovery attempt absent"))?;
            if a.status == RecoveryAttemptStatus::Proving {
                return Err(invalid("use cancel for unexported recovery"));
            }
            if tip
                <= a.parent_height.saturating_add(
                    protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW,
                )
            {
                return Err(invalid("recovery reference remains includable"));
            }
            a.status = RecoveryAttemptStatus::Abandoned;
            Ok(())
        })
    }
    pub fn cancel_unexported_recovery_spend(&self, id: [u8; 32]) -> Result<(), WalletError> {
        self.with_recovery_mut(|s| {
            let a = s
                .recovery
                .attempts
                .iter()
                .find(|a| a.id == id)
                .ok_or(invalid("recovery attempt absent"))?;
            if a.status != RecoveryAttemptStatus::Proving {
                return Err(invalid("recovery bytes may have escaped"));
            }
            s.recovery.attempts.retain(|a| a.id != id);
            Ok(())
        })
    }
    pub fn recovery_attempts(&self) -> Result<Vec<RecoveryAttemptView>, WalletError> {
        self.with_state(|s| {
            let tip = s.poseidon2_v8.tip()?.height;
            Ok(s.recovery
                .attempts
                .iter()
                .map(|a| RecoveryAttemptView {
                    id: a.id,
                    status: a.status,
                    parent_height: a.parent_height,
                    action_id: a.action_id.clone(),
                    mined_in: a.mined,
                    inputs_reserved: active(a, Some(tip)),
                })
                .collect())
        })
    }
}

#[cfg(test)]
impl RecoveryWalletState {
    pub(super) fn notes_are_empty_for_schema_test(&self) -> bool {
        self.notes.is_empty() && self.attempts.is_empty()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn attempt(status: RecoveryAttemptStatus) -> Attempt {
        Attempt {
            id: [7; 32],
            parent_height: 40,
            parent_hash: [8; 32],
            public_words: vec![],
            nullifiers: [[41; 7], [42; 7]],
            status,
            body: vec![],
            action_id: vec![],
            mined: None,
        }
    }
    #[test]
    fn abandonment_tombstone_reactivates_across_reference_window_rollback() {
        let a = attempt(RecoveryAttemptStatus::Abandoned);
        let last = 40 + protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW;
        assert!(active(&a, Some(last)));
        assert!(!active(&a, Some(last + 1)));
        assert!(active(&a, Some(40)));
        assert!(active(&a, None));
        assert!(active(
            &attempt(RecoveryAttemptStatus::SubmissionUncertain),
            Some(last + 100)
        ));
    }
    #[test]
    fn recovery_nf_hold_is_visible_in_existing_common_reservation_union() {
        let d = tempfile::tempdir().unwrap();
        let store = WalletStore::create_from_root(
            d.path().join("shared-hold"),
            "disposable",
            RootSecret::from_bytes([0x55; 32]),
        )
        .unwrap();
        let mut state = store.state.lock().unwrap();
        state
            .recovery
            .attempts
            .push(attempt(RecoveryAttemptStatus::Proving));
        assert!(state.reserved_poseidon2_v8_nullifiers().contains(&[41; 7]));
        assert!(state.reserved_poseidon2_v8_nullifiers().contains(&[42; 7]));
        assert!(state.recover_recovery_proving());
        assert!(!state.reserved_poseidon2_v8_nullifiers().contains(&[41; 7]));
    }

    #[cfg(feature = "private-spend-dev-artifacts")]
    mod api_tests {
        use super::*;
        // These fixtures exercise the encrypted journal and canonical mirror, not
        // proof acceptance. Native fees use the existing real coinbase/maturity
        // fixture. A cfg(test)-only mirror hook appends the exact recovery CM.
        struct ApiFixture {
            _dir: tempfile::TempDir,
            path: PathBuf,
            store: WalletStore,
            context: LaunchWalletContext,
            public: relation::Public,
            material: RecoveryNoteMaterialV1,
            material_context: RecoveryNoteContextV1,
            position: u32,
            fees: Vec<Poseidon2V8OwnedNoteView>,
        }
        impl ApiFixture {
            fn new() -> Self {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("delegate-api.wallet");
                let root = RootSecret::from_bytes([0x56; 32]);
                let store =
                    WalletStore::create_from_root(&path, "disposable", root.clone()).unwrap();
                let funded =
                    crate::poseidon2_v8_sync::tests::seed_two_owned_coinbases(&store, &root);
                assert_eq!(funded.height, 121);
                let context =
                    LaunchWalletContext::new([0x62; 32], [0x10; 32], [7; 64], 1, 1000).unwrap();
                store
                    .initialize_pinned_launch_context_for_retained_test(context)
                    .unwrap();
                store.private_spend_address(0).unwrap();
                let keys = root.derive();
                let address = keys.poseidon2_v8_address(0).unwrap();
                let recipient = transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_from_canonical_bytes(address.pk_recipient).unwrap();
                let authority = transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_digest(keys.spend.poseidon2_v8_words().unwrap()).unwrap();
                let (mut public, _) = relation::fixtures::fixture(
                    transaction_circuit::asset_spend_v1::TRANSFER,
                    false,
                )
                .unwrap();
                let material = crate::asset_recovery_build_v1::new_recovery_output_os(
                    context.chain_id(),
                    public.base.asset_id,
                    public.row.descriptor.stable_policy_id,
                    29,
                    recipient,
                    authority,
                )
                .unwrap();
                let cm = transaction_circuit::private_spend::note_commitment(material.as_note())
                    .unwrap();
                let block = Poseidon2V8CanonicalBlock {
                    height: funded.height + 1,
                    hash: [0x58; 32],
                    parent_hash: funded.block_hash,
                    action_bytes: vec![],
                };
                let position = u32::try_from(
                    store
                        .with_poseidon2_v8_mut(|mirror, _| {
                            mirror.append_journal_test_commitment(&block, cm)
                        })
                        .unwrap(),
                )
                .unwrap();
                let tip = store.poseidon2_v8_tip().unwrap();
                let material_context = RecoveryNoteContextV1 {
                    chain_id: context.chain_id(),
                    asset_id: public.base.asset_id,
                    stable_policy_id: public.row.descriptor.stable_policy_id,
                    output_commitment: cm,
                };
                material.validate(&material_context).unwrap();
                assert!(store
                    .poseidon2_v8_canonical_note_witness_at(cm, u64::from(position))
                    .unwrap()
                    .is_some());
                let fees = store.poseidon2_v8_owned_notes().unwrap();
                assert_eq!(fees.len(), 2);
                assert!(fees
                    .iter()
                    .all(|n| n.opening.asset_id == NATIVE_ASSET_ID && !n.spent));
                public.base.chain_id = context.chain_id();
                public.base.parent_height = tip.height;
                public.base.reference_parent_hash = tip.block_hash;
                public.base.note_root = tip.anchor;
                public.base.nullifiers = [
                    material
                        .common_nullifier(&material_context, position)
                        .unwrap(),
                    fees[0].nullifier,
                ];
                public.row.controls.note_freeze_root =
                    transaction_circuit::asset_recovery_v1::freeze_defaults(
                        &public.row.descriptor,
                        context.chain_id(),
                    )
                    .unwrap()[32];
                public.validate_structure().unwrap();
                Self {
                    _dir: dir,
                    path,
                    store,
                    context,
                    public,
                    material,
                    material_context,
                    position,
                    fees,
                }
            }
            fn for_fee(&self, i: usize) -> relation::Public {
                let mut public = self.public.clone();
                public.base.nullifiers[1] = self.fees[i].nullifier;
                public
            }
            fn material_copy(&self) -> RecoveryNoteMaterialV1 {
                RecoveryNoteMaterialV1::decode(
                    &self.material.encode(&self.material_context).unwrap(),
                    &self.material_context,
                )
                .unwrap()
            }
            fn reject_unchanged(&self, f: impl FnOnce() -> Result<[u8; 32], WalletError>) {
                let disk = fs::read(&self.path).unwrap();
                let attempts = self.store.recovery_attempts().unwrap();
                let tip = self.store.poseidon2_v8_tip().unwrap();
                assert!(f().is_err());
                assert_eq!(self.store.recovery_attempts().unwrap(), attempts);
                assert_eq!(self.store.poseidon2_v8_tip().unwrap(), tip);
                assert_eq!(
                    fs::read(&self.path).unwrap(),
                    disk,
                    "rejected reservation must not write the encrypted journal"
                );
            }
            fn install_holder_record(&self) {
                self.store
                    .with_recovery_mut(|state| {
                        state.recovery.notes.push(HolderNote {
                            chain: self.context.chain_id(),
                            asset: self.public.base.asset_id,
                            policy: self.material_context.stable_policy_id,
                            cm: self.material_context.output_commitment,
                            nf: self.public.base.nullifiers[0],
                            position: u64::from(self.position),
                            height: self.public.base.parent_height,
                            block: self.public.base.reference_parent_hash,
                            recipient_index: 0,
                            source: relation::relation_digest().to_vec(),
                            payload: self
                                .material
                                .encode(&self.material_context)?
                                .as_bytes()
                                .to_vec(),
                            spent: false,
                        });
                        Ok(())
                    })
                    .unwrap();
            }
        }
        fn changed(word: u64) -> u64 {
            (word + 1) % 0xffff_ffff_0000_0001
        }
        // Exact codec envelopes only, NEVER cryptographically valid. These are used
        // solely after a real API reservation to test persisted uncertainty, and
        // production retain is explicitly required to reject them.
        fn journal_body_fixture(public: &relation::Public) -> Vec<u8> {
            use transaction_circuit::asset_recovery_capsule_v1 as capsule;
            fn framed(route: u8, source: [u8; 64]) -> Vec<u8> {
                let mut proof = b"SMZR".to_vec();
                proof.extend(1u16.to_le_bytes());
                proof.extend([route, 0]);
                proof.extend(source);
                proof.extend(4u32.to_le_bytes());
                proof.extend([0; 4]);
                proof.extend(b"SMZE");
                proof
            }
            let ciphertexts = [[1; wire::CIPHERTEXT_BYTES]; 3];
            let mut public = public.clone();
            public.base.ciphertext_commitments = ciphertexts
                .each_ref()
                .map(|c| transaction_circuit::hashing_pq::ciphertext_hash_bytes(c));
            let caps: [capsule::AssetRecoveryCapsulePublicV1; 2] =
                core::array::from_fn(|i| capsule::AssetRecoveryCapsulePublicV1 {
                    chain_id: public.base.chain_id,
                    asset_id: public.base.asset_id,
                    stable_policy_id: public.row.descriptor.stable_policy_id,
                    archive_key_commitment: public.row.descriptor.archive_key_commitment,
                    note_commitment: public.base.commitments[i],
                    ciphertext: [i as u8; capsule::CIPHERTEXT_BYTES],
                });
            let mut bundle = b"SMRC".to_vec();
            bundle.extend(1u16.to_le_bytes());
            bundle.extend([2, 0]);
            bundle.extend(84u32.to_le_bytes());
            bundle.extend(84u32.to_le_bytes());
            for i in 0..2 {
                bundle.extend(framed(
                    2,
                    capsule::segment_relation_digest(capsule::relation_digest(), i).unwrap(),
                ));
            }
            wire::encode_spend(
                &public,
                &ciphertexts,
                &framed(1, relation::relation_digest()),
                [(&caps[0], &bundle), (&caps[1], &bundle)],
            )
            .unwrap()
        }
        fn retained_journal_fixture(f: &ApiFixture) -> ([u8; 32], Vec<u8>) {
            let body = journal_body_fixture(&f.public);
            let public = wire::decode_spend_ref(&body).unwrap().public;
            let id = f.store.reserve_recovery_delegate_spend(
                f.context, &public, &f.material, f.position, f.fees[0].position,
            ).unwrap();
            // Framing is NOT proof validity. Production retention must reject;
            // only this existing private cfg(test) journal seam seeds the body.
            assert!(f.store.retain_recovery_spend(id, &body).is_err());
            f.store.with_recovery_mut(|state| {
                let a = state.recovery.attempts.iter_mut().find(|a| a.id == id).unwrap();
                assert_eq!(a.status, RecoveryAttemptStatus::Proving);
                assert!(a.body.is_empty());
                a.body = body.clone();
                a.status = RecoveryAttemptStatus::Candidate;
                Ok(())
            }).unwrap();
            (id, body)
        }
        fn candidate_and_submission_reject_unchanged(
            store: &WalletStore, path: &std::path::Path, id: [u8; 32], expected: &'static str,
        ) {
            let disk = fs::read(path).unwrap();
            let attempts = store.recovery_attempts().unwrap();
            assert!(matches!(store.recovery_candidate_bytes(id),
                Err(WalletError::InvalidState(reason)) if reason == expected));
            assert!(matches!(store.begin_recovery_submission(id),
                Err(WalletError::InvalidState(reason)) if reason == expected));
            assert_eq!(store.recovery_attempts().unwrap(), attempts);
            assert_eq!(fs::read(path).unwrap(), disk);
        }
        #[test]
        fn retained_export_survives_canonical_consumption_and_restart_without_resubmit() {
            let f = ApiFixture::new();
            let (id, body) = retained_journal_fixture(&f);
            f.store.begin_recovery_submission(id).unwrap();
            f.store.mark_recovery_submitted(id, [0x75; 48]).unwrap();
            let tip = f.store.poseidon2_v8_tip().unwrap();
            let included = Poseidon2V8CanonicalBlock {
                height: tip.height + 1, hash: [0x76; 32], parent_hash: tip.block_hash,
                action_bytes: vec![],
            };
            f.store.with_recovery_mut(|state| {
                state.poseidon2_v8.apply_block(&included, None)?;
                // Journal-only canonical-NF fixture. Keep private mirror fields
                // private: serialize the disposable fixture, add matching block
                // rows/owned-fee markers, then run the actual mirror validator.
                // This neither accepts a block/proof nor adds a runtime hook.
                let mut mirror = serde_json::to_value(&state.poseidon2_v8).unwrap();
                for nf in f.public.base.nullifiers {
                    mirror["nullifiers"].as_array_mut().unwrap().push(
                        serde_json::json!({"value":nf,"block_hash":included.hash}));
                    for note in mirror["owned_notes"].as_array_mut().unwrap() {
                        if note["nullifier"] == serde_json::json!(nf) {
                            note["spent_by"] = serde_json::json!(included.hash);
                        }
                    }
                }
                mirror["blocks"].as_array_mut().unwrap().last_mut().unwrap()
                    ["introduced_nullifiers"] = serde_json::json!(f.public.base.nullifiers);
                state.poseidon2_v8 = serde_json::from_value(mirror).unwrap();
                state.poseidon2_v8.validate()?;
                state.recovery.attempts.iter_mut().find(|a| a.id == id).unwrap().mined =
                    Some((included.height, included.hash));
                Ok(())
            }).unwrap();
            assert_eq!(f.store.recovery_retained_bytes(id).unwrap(), body);
            candidate_and_submission_reject_unchanged(
                &f.store, &f.path, id, "recovery input canonically consumed");
            let path = f.path.clone();
            drop(f.store);
            let reopened = WalletStore::open(&path, "disposable").unwrap();
            let disk = fs::read(&path).unwrap();
            assert_eq!(reopened.recovery_retained_bytes(id).unwrap(), body);
            assert_eq!(reopened.recovery_attempts().unwrap()[0].mined_in,
                Some((included.height, included.hash)));
            candidate_and_submission_reject_unchanged(
                &reopened, &path, id, "recovery input canonically consumed");
            assert_eq!(fs::read(&path).unwrap(), disk);
        }
        #[test]
        fn retained_export_survives_expired_and_orphaned_references_without_resubmit() {
            for orphaned in [false, true] {
                let f = ApiFixture::new();
                let (id, body) = retained_journal_fixture(&f);
                if orphaned {
                    f.store.with_recovery_mut(|state| {
                        let height = f.public.base.parent_height - 1;
                        let hash = state.poseidon2_v8.canonical_hash(height).unwrap();
                        state.poseidon2_v8.rollback_to(height, hash)?;
                        Ok(())
                    }).unwrap();
                } else {
                    for step in 0..=protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW {
                        let tip = f.store.poseidon2_v8_tip().unwrap();
                        let block = Poseidon2V8CanonicalBlock {
                            height: tip.height + 1, hash: [0x80 + step as u8; 32],
                            parent_hash: tip.block_hash, action_bytes: vec![],
                        };
                        f.store.with_recovery_mut(|state| {
                            state.poseidon2_v8.apply_block(&block, None)?;
                            Ok(())
                        }).unwrap();
                    }
                }
                let disk = fs::read(&f.path).unwrap();
                assert_eq!(f.store.recovery_retained_bytes(id).unwrap(), body);
                candidate_and_submission_reject_unchanged(&f.store, &f.path, id, if orphaned {
                    "recovery original reference orphaned"
                } else { "asset reference outside canonical window" });
                assert_eq!(fs::read(&f.path).unwrap(), disk);
            }
        }
        #[test]
        fn retained_export_denies_unretained_abandoned_and_mismatched_artifacts_without_writes() {
            let f = ApiFixture::new();
            let (id, body) = retained_journal_fixture(&f);
            assert!(f.store.recovery_retained_bytes([0xff; 32]).is_err());
            let original = f.store.with_state(|state| Ok(state.recovery.attempts[0].clone())).unwrap();
            for case in 0..9 {
                {
                    let mut state = f.store.state.lock().unwrap();
                    let a = &mut state.recovery.attempts[0];
                    *a = original.clone();
                    match case {
                        0 => a.status = RecoveryAttemptStatus::Proving,
                        1 => a.status = RecoveryAttemptStatus::Abandoned,
                        2 => a.body.clear(),
                        3 => { a.body.pop(); },
                        4 => a.public_words[0] = changed(a.public_words[0]),
                        5 => a.nullifiers[0][0] = changed(a.nullifiers[0][0]),
                        6 => a.parent_height += 1,
                        7 => a.parent_hash[0] ^= 1,
                        8 => a.public_words.clear(),
                        _ => unreachable!(),
                    }
                }
                // In-memory corruption exists only in this cfg(test) negative
                // fixture; production persistence validates/rejects these rows.
                let disk = fs::read(&f.path).unwrap();
                assert!(f.store.recovery_retained_bytes(id).is_err());
                assert_eq!(fs::read(&f.path).unwrap(), disk);
            }
            {
                let mut state = f.store.state.lock().unwrap();
                state.recovery.attempts[0] = original;
            }
            assert_eq!(f.store.recovery_retained_bytes(id).unwrap(), body);
        }
        #[test]
        fn delegate_reservation_api_binds_context_material_position_nf_and_atomic_journal() {
            let f = ApiFixture::new();
            let reserve = |context,
                           public: &relation::Public,
                           material: &RecoveryNoteMaterialV1,
                           position,
                           fee_position| {
                f.store.reserve_recovery_delegate_spend(
                    context,
                    public,
                    material,
                    position,
                    fee_position,
                )
            };
            let wrong_context = LaunchWalletContext::new(
                [0x63; 32],
                f.context.genesis_hash(),
                f.context.manifest_digest(),
                1,
                1000,
            )
            .unwrap();
            f.reject_unchanged(|| {
                reserve(
                    wrong_context,
                    &f.public,
                    &f.material,
                    f.position,
                    f.fees[0].position,
                )
            });
            let mut p = f.public.clone();
            p.base.chain_id = [0x63; 32];
            f.reject_unchanged(|| {
                reserve(f.context, &p, &f.material, f.position, f.fees[0].position)
            });
            let mut bad = f.material_copy();
            bad.shared_nf_key[0] = changed(bad.shared_nf_key[0]);
            f.reject_unchanged(|| {
                reserve(f.context, &f.public, &bad, f.position, f.fees[0].position)
            });
            let mut bad = f.material_copy();
            bad.note.rho[0] = changed(bad.note.rho[0]);
            f.reject_unchanged(|| {
                reserve(f.context, &f.public, &bad, f.position, f.fees[0].position)
            });
            let mut p = f.public.clone();
            p.row.descriptor.stable_policy_id[0] = changed(p.row.descriptor.stable_policy_id[0]);
            f.reject_unchanged(|| {
                reserve(f.context, &p, &f.material, f.position, f.fees[0].position)
            });
            let mut p = f.public.clone();
            p.base.nullifiers[0] = f
                .material
                .common_nullifier(&f.material_context, f.position + 1)
                .unwrap();
            f.reject_unchanged(|| {
                reserve(
                    f.context,
                    &p,
                    &f.material,
                    f.position + 1,
                    f.fees[0].position,
                )
            });
            let mut p = f.public.clone();
            p.base.nullifiers[0][0] = changed(p.base.nullifiers[0][0]);
            f.reject_unchanged(|| {
                reserve(f.context, &p, &f.material, f.position, f.fees[0].position)
            });
            let mut p = f.public.clone();
            p.base.nullifiers[1][0] = changed(p.base.nullifiers[1][0]);
            f.reject_unchanged(|| {
                reserve(f.context, &p, &f.material, f.position, f.fees[0].position)
            });
            f.reject_unchanged(|| {
                reserve(
                    f.context,
                    &f.public,
                    &f.material,
                    f.position,
                    f.fees[1].position,
                )
            });
            // The delegate can reserve a canonical occurrence it does not locally own.
            f.reject_unchanged(|| {
                f.store.reserve_recovery_spend(
                    f.context,
                    &f.public,
                    &[u64::from(f.position), f.fees[0].position],
                )
            });
            let id = reserve(
                f.context,
                &f.public,
                &f.material,
                f.position,
                f.fees[0].position,
            )
            .unwrap();
            assert_eq!(f.store.recovery_attempts().unwrap()[0].id, id);
            f.reject_unchanged(|| {
                reserve(
                    f.context,
                    &f.public,
                    &f.material,
                    f.position,
                    f.fees[0].position,
                )
            });
            f.store.cancel_unexported_recovery_spend(id).unwrap();
            assert!(f.store.recovery_attempts().unwrap().is_empty());
            // Reserve the exact framing fixture public statement through the API;
            // never use a fake proof to promote Proving via production retain.
            let body = journal_body_fixture(&f.public);
            let public = wire::decode_spend_ref(&body).unwrap().public;
            let id = reserve(
                f.context,
                &public,
                &f.material,
                f.position,
                f.fees[0].position,
            )
            .unwrap();
            assert!(f.store.retain_recovery_spend(id, &body).is_err());
            assert_eq!(
                f.store.recovery_attempts().unwrap()[0].status,
                RecoveryAttemptStatus::Proving
            );
            f.store
                .with_recovery_mut(|state| {
                    let a = state
                        .recovery
                        .attempts
                        .iter_mut()
                        .find(|a| a.id == id)
                        .unwrap();
                    assert_eq!(a.public_words, public.words().unwrap());
                    a.body = body.clone();
                    a.status = RecoveryAttemptStatus::Candidate;
                    Ok(())
                })
                .unwrap();
            f.store.begin_recovery_submission(id).unwrap();
            assert!(f.store.cancel_unexported_recovery_spend(id).is_err());
            assert!(f.store.abandon_recovery_spend(id).is_err());
            let ApiFixture {
                _dir,
                path,
                store,
                context,
                material,
                position,
                fees,
                ..
            } = f;
            drop(store);
            let reopened = WalletStore::open(&path, "disposable").unwrap();
            let attempts = reopened.recovery_attempts().unwrap();
            assert_eq!(attempts.len(), 1);
            assert_eq!(attempts[0].id, id);
            assert_eq!(
                attempts[0].status,
                RecoveryAttemptStatus::SubmissionUncertain
            );
            assert!(attempts[0].inputs_reserved);
            assert_eq!(reopened.recovery_candidate_bytes(id).unwrap(), body);
            assert!(reopened
                .reserve_recovery_delegate_spend(
                    context,
                    &public,
                    &material,
                    position,
                    fees[0].position
                )
                .is_err());
            reopened
                .with_state(|state| {
                    assert!(public
                        .base
                        .nullifiers
                        .iter()
                        .all(|nf| state.reserved_poseidon2_v8_nullifiers().contains(nf)));
                    Ok(())
                })
                .unwrap();
        }
        #[test]
        fn holder_delegate_reservation_apis_conflict_on_common_nf_in_both_orders() {
            let f = ApiFixture::new();
            f.install_holder_record();
            assert_eq!(f.store.recovery_notes().unwrap().len(), 1);
            for first_is_delegate in [false, true] {
                let holder = f.for_fee(0);
                let delegate = f.for_fee(1);
                let first = if first_is_delegate {
                    f.store.reserve_recovery_delegate_spend(
                        f.context,
                        &delegate,
                        &f.material,
                        f.position,
                        f.fees[1].position,
                    )
                } else {
                    f.store.reserve_recovery_spend(
                        f.context,
                        &holder,
                        &[u64::from(f.position), f.fees[0].position],
                    )
                }
                .unwrap();
                f.reject_unchanged(|| {
                    if first_is_delegate {
                        f.store.reserve_recovery_spend(
                            f.context,
                            &holder,
                            &[u64::from(f.position), f.fees[0].position],
                        )
                    } else {
                        f.store.reserve_recovery_delegate_spend(
                            f.context,
                            &delegate,
                            &f.material,
                            f.position,
                            f.fees[1].position,
                        )
                    }
                });
                assert_eq!(f.store.recovery_attempts().unwrap().len(), 1);
                assert!(f.store.recovery_notes().unwrap()[0].reserved);
                f.store.cancel_unexported_recovery_spend(first).unwrap();
                assert!(!f.store.recovery_notes().unwrap()[0].reserved);
                let second = if first_is_delegate {
                    f.store.reserve_recovery_spend(
                        f.context,
                        &holder,
                        &[u64::from(f.position), f.fees[0].position],
                    )
                } else {
                    f.store.reserve_recovery_delegate_spend(
                        f.context,
                        &delegate,
                        &f.material,
                        f.position,
                        f.fees[1].position,
                    )
                }
                .unwrap();
                f.store.cancel_unexported_recovery_spend(second).unwrap();
            }
        }
    }
}
