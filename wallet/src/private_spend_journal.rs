//! Encrypted V17 journal. WalletStore owns the exclusive process writer lock;
//! every mutation below rolls back memory on failure and uses its atomic fsync.
use super::*;
use crate::poseidon2_v8_sync::LaunchWalletContext;
use crate::private_spend_build::{PreparedPrivateSpend, TreasuryFinalTemplate};
use protocol_shielded_pool::private_spend_transport as transport;
use protocol_versioning::launch_candidate::{self, LaunchProofKind};
use transaction_circuit::private_spend as relation;
use zeroize::Zeroize;
type Digest = [u64; 7];
fn err(s: &'static str) -> WalletError {
    WalletError::InvalidState(s)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivateSpendAttemptStatus {
    Prepared,
    Candidate,
    SubmissionUncertain,
    Submitted,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct StoredPrivateTemplate {
    id: [u8; 32],
    chain: [u8; 32],
    bytes: Vec<u8>,
}
impl std::fmt::Debug for StoredPrivateTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoredPrivateTemplate { [REDACTED] }")
    }
}
impl Drop for StoredPrivateTemplate {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PrivateReservedInput {
    pub(crate) commitment: Digest,
    pub(crate) nullifier: Digest,
    pub(crate) position: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct StoredPrivateAttempt {
    id: [u8; 32],
    chain: [u8; 32],
    genesis: [u8; 32],
    source: Vec<u8>,
    parent_height: u64,
    parent_hash: [u8; 32],
    root: Digest,
    inputs: Vec<PrivateReservedInput>,
    public_binding: Vec<u8>,
    status: PrivateSpendAttemptStatus,
    action: Vec<u8>,
    action_id: Vec<u8>,
    mined_in: Option<(u64, [u8; 32])>,
}
impl std::fmt::Debug for StoredPrivateAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoredPrivateAttempt { [REDACTED] }")
    }
}
#[derive(Clone, Debug)]
pub struct PrivateSpendAttemptView {
    pub id: [u8; 32],
    pub status: PrivateSpendAttemptStatus,
    pub mined_in: Option<(u64, [u8; 32])>,
    pub inputs_consumed: bool,
}
fn authority(
    context: LaunchWalletContext,
    height: u64,
    proof_len: usize,
) -> Result<(), WalletError> {
    launch_candidate::launch_proof_authority(context.request(
        LaunchProofKind::PrivateSpend,
        height,
        proof_len,
    ))
    .ok_or(err(
        "private spend journal has no source-owned launch authority",
    ))?;
    Ok(())
}
fn pinned(state: &WalletState, context: LaunchWalletContext) -> Result<(), WalletError> {
    state
        .native_launch_context
        .as_ref()
        .ok_or(err("private journal context is not pinned"))?
        .require_match(context)
}
fn current_reference(
    s: &WalletState,
    context: LaunchWalletContext,
    height: u64,
    hash: [u8; 32],
    root: Digest,
) -> Result<u64, WalletError> {
    let tip = s.poseidon2_v8.tip()?;
    let reference = s
        .poseidon2_v8
        .canonical_tip_at_height(height)
        .ok_or(err("private canonical reference absent"))?;
    if reference.block_hash != hash || reference.anchor != root {
        return Err(err("private reference hash/root changed"));
    }
    context.require_reference_tip(
        s.poseidon2_v8
            .canonical_hash(0)
            .ok_or(err("private mirror genesis absent"))?,
        tip,
        reference,
        false,
    )
}
fn public_from(p: &transport::PublicStatement) -> relation::PrivateSpendPublic {
    relation::PrivateSpendPublic {
        chain_id: p.chain_id,
        reference_parent_hash: p.reference_parent_hash,
        reference_parent_height: p.reference_parent_height,
        merkle_root: p.merkle_root,
        fee: p.fee,
        nullifiers: p.nullifiers,
        commitments: p.commitments,
        ciphertext_commitments: p.ciphertext_commitments,
        secret_release: p.secret_release,
        released_secret: p.released_secret,
    }
}
fn expected(chain: [u8; 32]) -> Result<transport::ExpectedContext, WalletError> {
    transport::ExpectedContext::new(chain, relation::relation_digest()[..48].try_into().unwrap())
        .map_err(|_| err("private journal transport context"))
}
impl WalletState {
    pub(super) fn validate_private_spend_source_pin(&self) -> Result<(), WalletError> {
        if self
            .private_spend_relation_digest
            .as_ref()
            .is_some_and(|d| d.as_slice() != relation::relation_digest())
        {
            return Err(err(
                "private spend persisted source pin differs from this binary",
            ));
        }
        if (!self.private_spend_templates.is_empty() || !self.private_spend_attempts.is_empty())
            && self.private_spend_relation_digest.is_none()
        {
            return Err(err("private journal lacks explicit source pin"));
        }
        Ok(())
    }
    pub(super) fn pin_private_spend_source(&mut self) -> Result<(), WalletError> {
        self.validate_private_spend_source_pin()?;
        if self.private_spend_relation_digest.is_none() {
            self.private_spend_relation_digest = Some(relation::relation_digest().to_vec());
        }
        Ok(())
    }
    pub(super) fn private_spend_reserved_nullifiers(&self) -> impl Iterator<Item = Digest> + '_ {
        self.private_spend_attempts
            .iter()
            .flat_map(|r| r.inputs.iter().map(|i| i.nullifier))
    }
    /// A rollback can revive another route's abandoned reservation after this
    /// attempt was retained. Validation preserves both immutable bodies; every
    /// new export/submission must instead recheck the active reservation union.
    pub(super) fn require_private_spend_inputs_exclusive(&self, id: [u8; 32]) -> Result<(), WalletError> {
        let record = self.private_spend_attempts.iter().find(|r| r.id == id)
            .ok_or(err("private reservation absent"))?;
        let other_reserved: HashSet<_> = self
            .reserved_ordinary_poseidon2_v8_nullifiers()
            .into_iter()
            .chain(self.htlc_reserved_nullifiers())
            .chain(self.asset_spend_reserved_nullifiers())
            .chain(self.recovery_reserved_nullifiers())
            .chain(crate::poseidon2_v8_multisig::active_reserved_nullifiers(
                &self.poseidon2_v8_treasuries,
                &self.poseidon2_v8,
            ))
            .collect();
        if record.inputs.iter().any(|i| other_reserved.contains(&i.nullifier)
            || self.private_spend_attempts.iter().any(|other| other.id != id
                && other.inputs.iter().any(|input| input.nullifier == i.nullifier))) {
            return Err(err("private spend input reserved by another attempt"));
        }
        Ok(())
    }

    pub(super) fn validate_private_spend_journal(&self) -> Result<(), WalletError> {
        if self.private_spend_templates.is_empty() && self.private_spend_attempts.is_empty() {
            return Ok(());
        }
        let context = self
            .native_launch_context
            .as_ref()
            .ok_or(err("private journal context absent"))?
            .current_context()?;
        // Cross-route overlap is possible after rollback revives a tombstone.
        // Keep retained bodies/reservations; exclusivity is checked on use.
        let mut ids = HashSet::new();
        let mut nullifiers = HashSet::new();
        for t in &self.private_spend_templates {
            if t.chain != context.chain_id()
                || t.id == [0; 32]
                || !ids.insert(t.id)
                || if t.bytes.starts_with(REFUND_HANDOFF_MAGIC) || t.bytes.starts_with(POLICY_HANDOFF_MAGIC) {
                    let kind = if t.bytes.starts_with(POLICY_HANDOFF_MAGIC) { OpeningHandoff::Policy } else { OpeningHandoff::Refund };
                    let (binding, _) = decode_opening_handoff(&t.bytes, t.chain, kind)?;
                    !self
                        .private_spend_attempts
                        .iter()
                        .any(|r| r.id == t.id && r.chain == t.chain && r.public_binding == binding)
                } else {
                    TreasuryFinalTemplate::journal_decode(&t.bytes)?.journal_chain() != t.chain
                }
            {
                return Err(err("invalid private treasury journal template"));
            }
        }
        ids.clear();
        for r in &self.private_spend_attempts {
            if r.chain != context.chain_id()
                || r.genesis != context.genesis_hash()
                || r.id == [0; 32]
                || !ids.insert(r.id)
                || r.chain == [0; 32]
                || r.genesis == [0; 32]
                || r.source != relation::relation_digest()
                || r.inputs.is_empty()
                || r.inputs.len() > 2
                || r.public_binding.len() != relation::PUBLIC_WORDS * 8
                || r.inputs.iter().any(|i| {
                    !nullifiers.insert(i.nullifier)
                        || i.nullifier == [0; 7]
                        || i.position > u32::MAX as u64
                        || i.commitment
                            .iter()
                            .chain(i.nullifier.iter())
                            .any(|x| *x >= transaction_circuit::constants::FIELD_MODULUS_U64)
                })
            {
                return Err(err("invalid or overlapping private spend journal"));
            }
            match r.status {
                PrivateSpendAttemptStatus::Prepared
                    if !r.action.is_empty() || !r.action_id.is_empty() =>
                {
                    return Err(err("prepared private attempt contains exported action"))
                }
                PrivateSpendAttemptStatus::Prepared => (),
                _ => {
                    let (id, args) =
                        crate::poseidon2_v8_sync::launch_sync::private_spend_journal_projection(
                            &r.action,
                        )?;
                    let decoded = transport::decode_exact(expected(r.chain)?, &args)
                        .map_err(|_| err("invalid retained private carrier"))?;
                    if id.as_slice() != r.action_id
                        || public_from(&decoded.public).binding_bytes() != r.public_binding
                    {
                        return Err(err(
                            "private retained action differs from reserved statement",
                        ));
                    }
                }
            }
        }
        Ok(())
    }
    pub(super) fn reconcile_private_spend_attempts(
        &mut self,
        observed: &[([u8; 48], u64, [u8; 32])],
    ) -> Result<(), WalletError> {
        for r in &mut self.private_spend_attempts {
            if r.mined_in
                .is_some_and(|(h, hash)| self.poseidon2_v8.canonical_hash(h) != Some(hash))
            {
                r.mined_in = None;
            }
            if let Some((_, h, hash)) = observed
                .iter()
                .find(|(id, _, _)| id.as_slice() == r.action_id)
            {
                if self.poseidon2_v8.canonical_hash(*h) != Some(*hash)
                    || !r
                        .inputs
                        .iter()
                        .all(|i| self.poseidon2_v8.has_canonical_nullifier(i.nullifier))
                {
                    return Err(err(
                        "private attempt receipt does not match canonical inputs",
                    ));
                }
                r.mined_in = Some((*h, *hash));
            }
        }
        Ok(())
    }
}
impl WalletStore {
    pub fn export_private_htlc_refund_handoff_encrypted(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
        prepared: &PreparedPrivateSpend,
        passphrase: &str,
    ) -> Result<Vec<u8>, WalletError> {
        self.retain_private_htlc_refund_handoff(context, id, prepared)?;
        self.export_stored_private_htlc_refund_handoff_encrypted(context, id, passphrase)
    }
    pub fn retain_private_htlc_refund_handoff(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
        prepared: &PreparedPrivateSpend,
    ) -> Result<(), WalletError> {
        self.retain_private_opening_handoff(context, id, prepared, prepared.refund_handoff_plaintext()?)
    }
    pub fn retain_private_policy_handoff(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
        prepared: &PreparedPrivateSpend,
    ) -> Result<(), WalletError> {
        self.retain_private_opening_handoff(context, id, prepared, prepared.policy_handoff_plaintext()?)
    }
    fn retain_private_opening_handoff(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
        prepared: &PreparedPrivateSpend,
        bytes: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<(), WalletError> {
        self.with_private_journal_mut(|s| {
            pinned(s, context)?;
            let r = s
                .private_spend_attempts
                .iter()
                .find(|r| r.id == id)
                .ok_or(err("lock reservation absent"))?;
            if r.chain != context.chain_id()
                || r.public_binding != prepared.public_statement().binding_bytes()
                || !matches!(
                    r.status,
                    PrivateSpendAttemptStatus::Prepared | PrivateSpendAttemptStatus::Candidate
                )
            {
                return Err(err(
                    "refund handoff does not match unsubmitted lock reservation",
                ));
            }
            if let Some(old) = s.private_spend_templates.iter().find(|t| t.id == id) {
                if old.bytes != bytes.as_slice() {
                    return Err(err("retained refund handoff differs"));
                }
            } else {
                s.private_spend_templates.push(StoredPrivateTemplate {
                    id,
                    chain: context.chain_id(),
                    bytes: bytes.to_vec(),
                });
            }
            Ok(())
        })
    }
    pub fn export_stored_private_htlc_refund_handoff_encrypted(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
        passphrase: &str,
    ) -> Result<Vec<u8>, WalletError> {
        self.export_stored_private_opening_handoff(context, id, passphrase, OpeningHandoff::Refund)
    }
    pub fn export_stored_private_policy_handoff_encrypted(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
        passphrase: &str,
    ) -> Result<Vec<u8>, WalletError> {
        self.export_stored_private_opening_handoff(context, id, passphrase, OpeningHandoff::Policy)
    }
    fn export_stored_private_opening_handoff(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
        passphrase: &str,
        kind: OpeningHandoff,
    ) -> Result<Vec<u8>, WalletError> {
        let bytes = self.with_state(|s| {
            pinned(s, context)?;
            s.validate_private_spend_source_pin()?;
            let t = s
                .private_spend_templates
                .iter()
                .find(|t| {
                    t.id == id
                        && t.chain == context.chain_id()
                        && t.bytes.starts_with(kind.magic())
                })
                .ok_or(err("retained refund handoff absent"))?;
            Ok(zeroize::Zeroizing::new(t.bytes.clone()))
        })?;
        seal_template_handoff(context, &bytes, passphrase)
    }
    pub fn import_private_htlc_refund_handoff_encrypted(
        &self,
        context: LaunchWalletContext,
        bytes: &[u8],
        passphrase: &str,
        refund_index: u32,
        block: &Poseidon2V8CanonicalBlock,
    ) -> Result<Digest, WalletError> {
        self.import_refund_handoff_inner(
            context,
            bytes,
            passphrase,
            refund_index,
            block,
            OpeningHandoff::Refund,
            |mirror, block| mirror.apply_private_spend_source_block(block, None, context).map(|_| ()),
        )
    }
    #[cfg(feature = "private-spend-dev-artifacts")]
    pub fn import_private_htlc_refund_handoff_encrypted_local_candidate(
        &self,
        context: LaunchWalletContext,
        bytes: &[u8],
        passphrase: &str,
        refund_index: u32,
        block: &Poseidon2V8CanonicalBlock,
        token: &crate::private_spend_rpc::DevelopmentPrivateSpendAuthority,
    ) -> Result<Digest, WalletError> {
        token.authorize(context, block.height, 1)?;
        self.import_refund_handoff_inner(
            context,
            bytes,
            passphrase,
            refund_index,
            block,
            OpeningHandoff::Refund,
            |mirror, block| {
                mirror
                    .apply_private_spend_development_block(block, None, token)
                    .map(|_| ())
            },
        )
    }
    pub fn import_private_policy_handoff_encrypted(
        &self,
        context: LaunchWalletContext,
        bytes: &[u8],
        passphrase: &str,
        recipient_index: u32,
        block: &Poseidon2V8CanonicalBlock,
    ) -> Result<Digest, WalletError> {
        self.import_refund_handoff_inner(context, bytes, passphrase, recipient_index, block,
            OpeningHandoff::Policy,
            |mirror, block| mirror.apply_private_spend_source_block(block, None, context).map(|_| ()))
    }
    #[cfg(feature = "private-spend-dev-artifacts")]
    pub fn import_private_policy_handoff_encrypted_local_candidate(
        &self,
        context: LaunchWalletContext,
        bytes: &[u8],
        passphrase: &str,
        recipient_index: u32,
        block: &Poseidon2V8CanonicalBlock,
        token: &crate::private_spend_rpc::DevelopmentPrivateSpendAuthority,
    ) -> Result<Digest, WalletError> {
        token.authorize(context, block.height, 1)?;
        self.import_refund_handoff_inner(context, bytes, passphrase, recipient_index, block,
            OpeningHandoff::Policy,
            |mirror, block| mirror.apply_private_spend_development_block(block, None, token).map(|_| ()))
    }
    fn import_refund_handoff_inner(
        &self,
        context: LaunchWalletContext,
        bytes: &[u8],
        passphrase: &str,
        refund_index: u32,
        block: &Poseidon2V8CanonicalBlock,
        kind: OpeningHandoff,
        replay: impl FnOnce(
            &mut Poseidon2V8WalletState,
            &Poseidon2V8CanonicalBlock,
        ) -> Result<(), WalletError>,
    ) -> Result<Digest, WalletError> {
        self.ensure_writable()?;
        let plaintext = open_template_handoff(context, bytes, passphrase)?;
        let (binding, mut payload) = decode_opening_handoff(&plaintext, context.chain_id(), kind)?;
        payload.recipient_index = refund_index;
        let mut s = self.state.lock().map_err(|_| err("wallet poisoned"))?;
        pinned(&s, context)?;
        s.validate_private_spend_source_pin()?;
        if !s.private_spend_issued.contains(refund_index)
            || s.poseidon2_v8.canonical_hash(block.height) != Some(block.hash)
        {
            return Err(err("refund address unissued or claimed block noncanonical"));
        }
        let keys = s.derived.as_ref().ok_or(WalletError::WatchOnly)?;
        crate::private_spend::validate_stored_payload_owner(&payload, keys)?;
        let local = transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_digest(keys.spend.poseidon2_v8_words()?)
            .map_err(|_| err("invalid refund credential"))?;
        let authorized = match (&payload.state, kind) {
            (synthetic_crypto::private_note_payload::NoteState::Htlc(h), OpeningHandoff::Refund) => local == h.refund_authority,
            (synthetic_crypto::private_note_payload::NoteState::Policy(p), OpeningHandoff::Policy) => p.branches.iter().any(|b| b.enabled == 1 && b.authority == local),
            _ => false,
        };
        if !authorized {
            return Err(err("handoff receiver is not an enabled authority"));
        }
        let n = &payload.note;
        let note = relation::Note {
            value: n.value,
            asset_id: n.asset_id,
            recipient_key: n.recipient_key,
            authorization_key: n.authorization_key,
            rho: n.rho,
            randomness: n.randomness,
        };
        let commitment =
            relation::note_commitment(note).map_err(|_| err("refund note commitment invalid"))?;
        let mut position = s
            .poseidon2_v8
            .canonical_block_leaf_count_before(block.height, block.hash)
            .ok_or(err("refund block occurrence metadata absent"))?;
        let mut found = None;
        for encoded in &block.action_bytes {
            if let Some(_) =
                crate::poseidon2_v8_sync::poseidon2_v8_reward_notes_from_canonical_action(encoded)?
            {
                // Rewards append only at the end of their release block, after
                // ordinary/private actions, and cannot shift this occurrence.
                continue;
            }
            let (_, args) =
                crate::poseidon2_v8_sync::launch_sync::private_spend_journal_projection(encoded)?;
            let decoded = transport::decode_exact(expected(context.chain_id())?, &args)
                .map_err(|_| err("refund action carrier invalid"))?;
            if public_from(&decoded.public).binding_bytes() == binding {
                if found.is_some() || decoded.public.commitments[0] != commitment {
                    return Err(err("refund exact lock occurrence mismatch"));
                }
                relation::verify_candidate(&public_from(&decoded.public), decoded.proof)
                    .map_err(|_| err("refund canonical lock proof invalid"))?;
                found = Some(position);
            }
            position = position
                .checked_add(2)
                .ok_or(err("refund block position overflow"))?;
        }
        let position = found.ok_or(err("refund lock action absent from canonical block"))?;
        if s.poseidon2_v8
            .canonical_note_witness_at(commitment, position)?
            .is_none()
        {
            return Err(err("refund canonical note occurrence absent"));
        }
        let parent_height = block
            .height
            .checked_sub(1)
            .ok_or(err("refund lock cannot be genesis"))?;
        let parent_hash = s
            .poseidon2_v8
            .canonical_hash(parent_height)
            .ok_or(err("refund canonical parent absent"))?;
        let expected_tip = s
            .poseidon2_v8
            .canonical_tip_at_height(block.height)
            .ok_or(err("refund block snapshot absent"))?;
        // Consistency replay against local canonical effects. The supplied body
        // comes from the pinned trusted node; this does not authenticate a body
        // cryptographically to its header hash.
        let mut replayed = s.poseidon2_v8.clone();
        replayed.rollback_to(parent_height, parent_hash)?;
        replay(&mut replayed, block)?;
        if replayed.tip()? != expected_tip {
            return Err(err("refund canonical block body differs from mirror"));
        }
        let recovered = crate::private_spend::RecoveredPrivateSpendNote {
            address_index: refund_index,
            payload,
        };
        let mut stored = crate::private_spend::StoredPrivateSpendNote::new(
            recovered,
            keys,
            context.chain_id(),
            commitment,
            position,
            block.height,
            block.hash,
        )?;
        stored.spent = s.poseidon2_v8.has_canonical_nullifier(stored.nullifier);
        if let Some(old) = s
            .private_spend_notes
            .iter()
            .find(|n| n.position == position)
        {
            if old.commitment != commitment || old.nullifier != stored.nullifier {
                return Err(err("refund note occurrence already differs"));
            }
            return Ok(commitment);
        }
        let previous = s.private_spend_notes.clone();
        let old_pin = s.private_spend_relation_digest.clone();
        s.pin_private_spend_source()?;
        s.private_spend_notes.push(stored);
        if let Err(error) = validate_wallet_state(&s).and_then(|()| self.write_state(&s)) {
            s.private_spend_notes = previous;
            s.private_spend_relation_digest = old_pin;
            return Err(error);
        }
        Ok(commitment)
    }
    fn with_private_journal_mut<T>(
        &self,
        f: impl FnOnce(&mut WalletState) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        self.ensure_writable()?;
        let mut s = self.state.lock().map_err(|_| err("wallet poisoned"))?;
        let previous_pin = s.private_spend_relation_digest.clone();
        s.pin_private_spend_source()?;
        let templates = s.private_spend_templates.clone();
        let attempts = s.private_spend_attempts.clone();
        let result = f(&mut s).and_then(|result| {
            s.validate_private_spend_journal()?;
            self.write_state(&s)?;
            Ok(result)
        });
        if result.is_err() {
            s.private_spend_templates = templates;
            s.private_spend_attempts = attempts;
            s.private_spend_relation_digest = previous_pin;
        }
        result
    }
    /// Pin the private relation separately from the frozen legacy launch context.
    pub fn pin_private_spend_context(
        &self,
        context: LaunchWalletContext,
    ) -> Result<(), WalletError> {
        self.with_private_journal_mut(|s| pinned(s, context))
    }
    /// Persist before displaying/sharing an approval request. Only the encrypted
    /// wallet file receives the template; a later exclusive process can reload it.
    pub fn save_private_treasury_template(
        &self,
        context: LaunchWalletContext,
        template: &TreasuryFinalTemplate,
    ) -> Result<[u8; 32], WalletError> {
        let mut id = [0; 32];
        OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| err("journal entropy unavailable"))?;
        let record = StoredPrivateTemplate {
            id,
            chain: template.journal_chain(),
            bytes: template.journal_encode()?,
        };
        self.with_private_journal_mut(|s| {
            pinned(s, context)?;
            if record.chain != context.chain_id() {
                return Err(err("private template chain mismatch"));
            }
            s.private_spend_templates.push(record);
            Ok(id)
        })
    }
    /// Returns only authenticated encrypted handoff bytes. The caller chooses a
    /// private file destination; no root secret or spend key enters this format.
    pub fn export_private_treasury_template_encrypted(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
        passphrase: &str,
    ) -> Result<Vec<u8>, WalletError> {
        let template = self.load_private_treasury_template(context, id)?;
        let plaintext = zeroize::Zeroizing::new(template.journal_encode()?);
        seal_template_handoff(context, &plaintext, passphrase)
    }
    pub fn import_private_treasury_template_encrypted(
        &self,
        context: LaunchWalletContext,
        bytes: &[u8],
        passphrase: &str,
    ) -> Result<[u8; 32], WalletError> {
        self.ensure_writable()?;
        let plaintext = open_template_handoff(context, bytes, passphrase)?;
        let template = TreasuryFinalTemplate::journal_decode(&plaintext)?;
        self.save_private_treasury_template(context, &template)
    }
    pub fn private_treasury_template_ids(
        &self,
        context: LaunchWalletContext,
    ) -> Result<Vec<[u8; 32]>, WalletError> {
        self.with_state(|s| {
            pinned(s, context)?;
            Ok(s.private_spend_templates
                .iter()
                .filter(|t| {
                    t.chain == context.chain_id() && !t.bytes.starts_with(REFUND_HANDOFF_MAGIC)
                })
                .map(|t| t.id)
                .collect())
        })
    }
    pub fn load_private_treasury_template(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
    ) -> Result<TreasuryFinalTemplate, WalletError> {
        self.with_state(|s| {
            pinned(s, context)?;
            let t = s
                .private_spend_templates
                .iter()
                .find(|t| t.id == id && t.chain == context.chain_id())
                .ok_or(err("private template absent"))?;
            TreasuryFinalTemplate::journal_decode(&t.bytes)
        })
    }
    /// This is a persistent reservation, not a drop guard: restart cannot release
    /// inputs while another signing process is using the retained template.
    pub fn reserve_private_spend(
        &self,
        context: LaunchWalletContext,
        prepared: &PreparedPrivateSpend,
    ) -> Result<[u8; 32], WalletError> {
        let p = prepared.public_statement();
        let inputs = prepared.journal_inputs()?;
        let mut id = [0; 32];
        OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| err("journal entropy unavailable"))?;
        self.with_private_journal_mut(|s| {
            pinned(s, context)?;
            if p.chain_id != context.chain_id() {
                return Err(err("private reservation chain mismatch"));
            }
            current_reference(
                s,
                context,
                p.reference_parent_height,
                p.reference_parent_hash,
                p.merkle_root,
            )?;
            let reserved = s.reserved_poseidon2_v8_nullifiers();
            for i in &inputs {
                if reserved.contains(&i.nullifier)
                    || s.poseidon2_v8.has_canonical_nullifier(i.nullifier)
                    || s.poseidon2_v8
                        .canonical_note_witness_at(i.commitment, i.position)?
                        .is_none()
                {
                    return Err(err("private input unavailable or already reserved"));
                }
            }
            s.private_spend_attempts.push(StoredPrivateAttempt {
                id,
                chain: context.chain_id(),
                genesis: context.genesis_hash(),
                source: relation::relation_digest().to_vec(),
                parent_height: p.reference_parent_height,
                parent_hash: p.reference_parent_hash,
                root: p.merkle_root,
                inputs,
                public_binding: p.binding_bytes(),
                status: PrivateSpendAttemptStatus::Prepared,
                action: Vec::new(),
                action_id: Vec::new(),
                mined_in: None,
            });
            Ok(id)
        })
    }
    pub fn cancel_private_spend_preparation(&self, id: [u8; 32]) -> Result<(), WalletError> {
        self.with_private_journal_mut(|s| {
            let at = s
                .private_spend_attempts
                .iter()
                .position(|r| r.id == id)
                .ok_or(err("private attempt absent"))?;
            if s.private_spend_attempts[at].status != PrivateSpendAttemptStatus::Prepared {
                return Err(err("exportable private action cannot release inputs"));
            }
            s.private_spend_attempts.remove(at);
            s.private_spend_templates
                .retain(|t| !(t.id == id && t.bytes.starts_with(REFUND_HANDOFF_MAGIC)));
            Ok(())
        })
    }
    /// Retain exact complete action bytes. Proof acceptance and source authority
    /// are checked; no caller-supplied transaction hash is trusted.
    pub fn retain_private_spend_action(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
        action: &[u8],
    ) -> Result<(), WalletError> {
        self.retain_private_spend_action_with_authority(context, id, action, authority)
    }
    #[cfg(feature = "private-spend-dev-artifacts")]
    pub fn retain_private_spend_action_local_candidate(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
        action: &[u8],
        token: &crate::private_spend_rpc::DevelopmentPrivateSpendAuthority,
    ) -> Result<(), WalletError> {
        self.retain_private_spend_action_with_authority(context, id, action, |ctx, height, len| {
            token.authorize(ctx, height, len)
        })
    }
    fn retain_private_spend_action_with_authority(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
        action: &[u8],
        authorize: impl Fn(LaunchWalletContext, u64, usize) -> Result<(), WalletError>,
    ) -> Result<(), WalletError> {
        let (action_id, args) =
            crate::poseidon2_v8_sync::launch_sync::private_spend_journal_projection(action)?;
        let decoded = transport::decode_exact(expected(context.chain_id())?, &args)
            .map_err(|_| err("private candidate framing"))?;
        let public = public_from(&decoded.public);
        self.with_state(|s| {
            pinned(s, context)?;
            s.validate_private_spend_source_pin()?;
            let inclusion = current_reference(
                s,
                context,
                public.reference_parent_height,
                public.reference_parent_hash,
                public.merkle_root,
            )?;
            authorize(context, inclusion, decoded.proof.len())?;
            s.require_private_spend_inputs_exclusive(id)?;
            let r = s
                .private_spend_attempts
                .iter()
                .find(|r| r.id == id)
                .ok_or(err("private reservation absent"))?;
            if r.status != PrivateSpendAttemptStatus::Prepared
                || r.public_binding != public.binding_bytes()
                || r.inputs
                    .iter()
                    .any(|i| s.poseidon2_v8.has_canonical_nullifier(i.nullifier))
            {
                return Err(err("private reservation is not currently retainable"));
            }
            Ok(())
        })?;
        relation::verify_candidate(&public, decoded.proof)
            .map_err(|_| err("private retained proof invalid"))?;
        self.with_private_journal_mut(|s| {
            pinned(s, context)?;
            let inclusion = current_reference(
                s,
                context,
                public.reference_parent_height,
                public.reference_parent_hash,
                public.merkle_root,
            )?;
            authorize(context, inclusion, decoded.proof.len())?;
            s.require_private_spend_inputs_exclusive(id)?;
            // Recheck after proving while holding the mutation lock: sync may
            // have consumed an input or revived a conflicting hold meanwhile.
            if s.private_spend_attempts.iter().find(|r| r.id == id)
                .ok_or(err("private reservation absent"))?.inputs.iter()
                .any(|i| s.poseidon2_v8.has_canonical_nullifier(i.nullifier)) {
                return Err(err("private reservation inputs were consumed during proving"));
            }
            let r = s
                .private_spend_attempts
                .iter_mut()
                .find(|r| r.id == id)
                .ok_or(err("private reservation absent"))?;
            if r.status != PrivateSpendAttemptStatus::Prepared
                || r.public_binding != public.binding_bytes()
            {
                return Err(err("private candidate differs from reserved statement"));
            }
            r.action = action.to_vec();
            r.action_id = action_id.to_vec();
            r.status = PrivateSpendAttemptStatus::Candidate;
            Ok(())
        })
    }
    /// Atomic transition happens before bytes leave this method for a mutating
    /// RPC or export. A timeout, rejection or process death keeps the reservation.
    pub fn private_spend_submission_bytes(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
    ) -> Result<Vec<u8>, WalletError> {
        self.private_spend_submission_bytes_with_authority(context, id, authority)
    }
    #[cfg(feature = "private-spend-dev-artifacts")]
    pub fn private_spend_submission_bytes_local_candidate(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
        token: &crate::private_spend_rpc::DevelopmentPrivateSpendAuthority,
    ) -> Result<Vec<u8>, WalletError> {
        self.private_spend_submission_bytes_with_authority(context, id, |ctx, height, len| {
            token.authorize(ctx, height, len)
        })
    }
    fn private_spend_submission_bytes_with_authority(
        &self,
        context: LaunchWalletContext,
        id: [u8; 32],
        authorize: impl Fn(LaunchWalletContext, u64, usize) -> Result<(), WalletError>,
    ) -> Result<Vec<u8>, WalletError> {
        self.with_private_journal_mut(|s| {
            pinned(s, context)?;
            let at = s
                .private_spend_attempts
                .iter()
                .position(|r| r.id == id)
                .ok_or(err("private attempt absent"))?;
            s.require_private_spend_inputs_exclusive(id)?;
            let r = &s.private_spend_attempts[at];
            if r.status == PrivateSpendAttemptStatus::Prepared
                || r.mined_in.is_some()
                || r.inputs
                    .iter()
                    .any(|i| s.poseidon2_v8.has_canonical_nullifier(i.nullifier))
            {
                return Err(err("private candidate is not currently submit-ready"));
            }
            let inclusion = current_reference(s, context, r.parent_height, r.parent_hash, r.root)?;
            let (_, args) =
                crate::poseidon2_v8_sync::launch_sync::private_spend_journal_projection(&r.action)?;
            let decoded = transport::decode_exact(expected(r.chain)?, &args)
                .map_err(|_| err("private retained carrier invalid"))?;
            authorize(context, inclusion, decoded.proof.len())?;
            let r = &mut s.private_spend_attempts[at];
            r.status = PrivateSpendAttemptStatus::SubmissionUncertain;
            Ok(r.action.clone())
        })
    }
    pub fn mark_private_spend_submitted(
        &self,
        id: [u8; 32],
        action_id: [u8; 48],
    ) -> Result<(), WalletError> {
        self.with_private_journal_mut(|s| {
            let r = s
                .private_spend_attempts
                .iter_mut()
                .find(|r| r.id == id)
                .ok_or(err("private attempt absent"))?;
            if r.status != PrivateSpendAttemptStatus::SubmissionUncertain
                || r.action_id != action_id
            {
                return Err(err("private submission acknowledgment differs"));
            }
            r.status = PrivateSpendAttemptStatus::Submitted;
            Ok(())
        })
    }
    pub fn private_spend_attempts(&self) -> Result<Vec<PrivateSpendAttemptView>, WalletError> {
        self.with_state(|s| {
            Ok(s.private_spend_attempts
                .iter()
                .map(|r| PrivateSpendAttemptView {
                    id: r.id,
                    status: r.status,
                    mined_in: r.mined_in,
                    inputs_consumed: r
                        .inputs
                        .iter()
                        .all(|i| s.poseidon2_v8.has_canonical_nullifier(i.nullifier)),
                })
                .collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> LaunchWalletContext {
        LaunchWalletContext::new([1; 32], [9; 32], [7; 64], 1, 1_000).unwrap()
    }
    fn setup(path: &std::path::Path) -> WalletStore {
        let s =
            WalletStore::create_from_root(path, "test", RootSecret::from_bytes([41; 32])).unwrap();
        s.state.lock().unwrap().native_launch_context = Some(
            crate::poseidon2_v8_sync::launch_sync::StoredNativeLaunchContext::from_context(
                context(),
            ),
        );
        s.write_locked().unwrap();
        s
    }
    // Framing-only fixture: never passed through the production retain API and
    // deliberately not a proof-valid candidate. Tests exercise journal durability.
    fn attempt() -> StoredPrivateAttempt {
        let ct = [0u8; transport::CIPHERTEXT_BYTES];
        let public = transport::PublicStatement {
            relation_digest: relation::relation_digest()[..48].try_into().unwrap(),
            chain_id: context().chain_id(),
            reference_parent_hash: [2; 32],
            reference_parent_height: 100,
            merkle_root: [3; 7],
            fee: 1,
            nullifiers: [[5; 7], [6; 7]],
            commitments: [[7; 7], [8; 7]],
            ciphertext_commitments: [transaction_circuit::hashing_pq::ciphertext_hash_bytes(&ct);
                2],
            secret_release: 0,
            released_secret: [0; 32],
        };
        let action =
            crate::poseidon2_v8_sync::launch_sync::private_spend_journal_framing_fixture(&public);
        let (id, _) =
            crate::poseidon2_v8_sync::launch_sync::private_spend_journal_projection(&action)
                .unwrap();
        StoredPrivateAttempt {
            id: [11; 32],
            chain: context().chain_id(),
            genesis: context().genesis_hash(),
            source: relation::relation_digest().to_vec(),
            parent_height: 100,
            parent_hash: [2; 32],
            root: [3; 7],
            inputs: vec![PrivateReservedInput {
                commitment: [4; 7],
                nullifier: [5; 7],
                position: 0,
            }],
            public_binding: public_from(&public).binding_bytes(),
            status: PrivateSpendAttemptStatus::SubmissionUncertain,
            action,
            action_id: id.to_vec(),
            mined_in: None,
        }
    }
    #[test]
    fn private_spend_refund_handoff_rejects_wrong_context_and_unmined_note() {
        let (_, refund, mut payload, _) = crate::private_spend::refund_custody_tests::fixture();
        payload.recipient_index = 9;
        let mut plain = zeroize::Zeroizing::new(REFUND_HANDOFF_MAGIC.to_vec());
        plain.extend(vec![0; relation::PUBLIC_WORDS * 8]);
        plain.extend(payload.encode([1; 32]).unwrap().as_bytes());
        let sealed = seal_template_handoff(context(), &plain, "refund custody passphrase").unwrap();
        let mut changed_source = sealed.clone();
        changed_source[HANDOFF_HEADER - 1] ^= 1;
        assert!(
            open_template_handoff(context(), &changed_source, "refund custody passphrase").is_err()
        );
        let wrong = LaunchWalletContext::new([2; 32], [9; 32], [7; 64], 1, 1_000).unwrap();
        assert!(open_template_handoff(wrong, &sealed, "refund custody passphrase").is_err());
        let dir = tempfile::tempdir().unwrap();
        let store = WalletStore::create_from_root(
            dir.path().join("refund"),
            "test",
            RootSecret::from_bytes([92; 32]),
        )
        .unwrap();
        store.state.lock().unwrap().native_launch_context = Some(
            crate::poseidon2_v8_sync::launch_sync::StoredNativeLaunchContext::from_context(
                context(),
            ),
        );
        store.private_spend_address(9).unwrap();
        assert_eq!(
            store
                .derived_keys()
                .unwrap()
                .unwrap()
                .spend
                .poseidon2_v8_words()
                .unwrap(),
            refund.spend.poseidon2_v8_words().unwrap()
        );
        let block = Poseidon2V8CanonicalBlock {
            height: 101,
            hash: [8; 32],
            parent_hash: [2; 32],
            action_bytes: Vec::new(),
        };
        assert!(store
            .import_private_htlc_refund_handoff_encrypted(
                context(),
                &sealed,
                "refund custody passphrase",
                9,
                &block
            )
            .is_err());
        assert!(store.private_spend_notes().unwrap().is_empty());
    }
    #[test]
    fn private_policy_encrypted_handoff_rejects_type_confusion_and_wrong_chain() {
        use synthetic_crypto::private_note_payload::{NoteState, Policy, PolicyBranch};
        let (_, keys, mut payload, _) = crate::private_spend::refund_custody_tests::fixture();
        let authority = transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_digest(keys.spend.poseidon2_v8_words().unwrap()).unwrap();
        payload.state = NoteState::Policy(Policy {
            nullifier_key: [11, 12, 13, 14, 15],
            branches: [PolicyBranch { enabled: 1, authority, ..Default::default() }, Default::default()],
        });
        let owner = payload.expected_owner([1; 32]).unwrap();
        payload.note.authorization_key.copy_from_slice(&owner[..4]);
        payload.note.randomness[..3].copy_from_slice(&owner[4..]);
        let mut plain = zeroize::Zeroizing::new(POLICY_HANDOFF_MAGIC.to_vec());
        plain.extend(vec![0; relation::PUBLIC_WORDS * 8]);
        plain.extend(payload.encode([1; 32]).unwrap().as_bytes());
        let sealed = seal_template_handoff(context(), &plain, "policy custody passphrase").unwrap();
        let opened = open_template_handoff(context(), &sealed, "policy custody passphrase").unwrap();
        let (_, decoded) = decode_opening_handoff(&opened, [1; 32], OpeningHandoff::Policy).unwrap();
        assert!(matches!(&decoded.state, NoteState::Policy(_)));
        assert!(decode_opening_handoff(&opened, [1; 32], OpeningHandoff::Refund).is_err());
        assert!(decode_opening_handoff(&opened, [2; 32], OpeningHandoff::Policy).is_err());
        let mut mislabeled = plain.to_vec();
        mislabeled[..8].copy_from_slice(REFUND_HANDOFF_MAGIC);
        assert!(decode_opening_handoff(&mislabeled, [1; 32], OpeningHandoff::Refund).is_err());
        let mut altered = sealed;
        *altered.last_mut().unwrap() ^= 1;
        assert!(open_template_handoff(context(), &altered, "policy custody passphrase").is_err());
    }
    #[test]
    fn private_spend_handoff_is_randomized_authenticated_and_context_bound() {
        let template = crate::private_spend_build::tests::journal_template_fixture();
        let plain = zeroize::Zeroizing::new(template.journal_encode().unwrap());
        let a = seal_template_handoff(context(), &plain, "handoff passphrase").unwrap();
        let b = seal_template_handoff(context(), &plain, "handoff passphrase").unwrap();
        assert_ne!(a, b);
        assert_eq!(
            open_template_handoff(context(), &a, "handoff passphrase")
                .unwrap()
                .as_slice(),
            plain.as_slice()
        );
        assert!(open_template_handoff(context(), &a, "wrong").is_err());
        let mut damaged = a.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(open_template_handoff(context(), &damaged, "handoff passphrase").is_err());
        let wrong_chain = LaunchWalletContext::new([2; 32], [9; 32], [7; 64], 1, 1_000).unwrap();
        assert!(open_template_handoff(wrong_chain, &a, "handoff passphrase").is_err());
        let mut trailing = a.clone();
        trailing.push(0);
        assert!(open_template_handoff(context(), &trailing, "handoff passphrase").is_err());
        assert!(
            open_template_handoff(context(), &a[..HANDOFF_HEADER - 1], "handoff passphrase")
                .is_err()
        );
    }
    #[test]
    fn private_spend_encrypted_handoff_moves_exact_template_between_wallets() {
        let dir = tempfile::tempdir().unwrap();
        let first = setup(&dir.path().join("first"));
        let second = setup(&dir.path().join("second"));
        let template = crate::private_spend_build::tests::journal_template_fixture();
        let id = first
            .save_private_treasury_template(context(), &template)
            .unwrap();
        let encrypted = first
            .export_private_treasury_template_encrypted(context(), id, "explicit passphrase")
            .unwrap();
        let imported = second
            .import_private_treasury_template_encrypted(
                context(),
                &encrypted,
                "explicit passphrase",
            )
            .unwrap();
        assert_eq!(
            first
                .load_private_treasury_template(context(), id)
                .unwrap()
                .journal_encode()
                .unwrap(),
            second
                .load_private_treasury_template(context(), imported)
                .unwrap()
                .journal_encode()
                .unwrap()
        );
        assert!(second
            .import_private_treasury_template_encrypted(context(), &encrypted, "wrong")
            .is_err());
        assert_eq!(
            second.private_treasury_template_ids(context()).unwrap(),
            vec![imported]
        );
    }
    #[test]
    fn private_spend_journal_source_pin_rejects_binary_drift_on_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let s = setup(&path);
        s.pin_private_spend_context(context()).unwrap();
        s.state.lock().unwrap().private_spend_relation_digest = Some(vec![0; 64]);
        s.write_locked().unwrap();
        drop(s);
        assert!(WalletStore::open(&path, "test").is_err());
    }
    #[test]
    fn private_spend_journal_template_survives_new_writer_process() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let s = setup(&path);
        let template = crate::private_spend_build::tests::journal_template_fixture();
        let exact = zeroize::Zeroizing::new(template.journal_encode().unwrap());
        let id = s
            .save_private_treasury_template(context(), &template)
            .unwrap();
        assert!(matches!(
            WalletStore::open(&path, "test"),
            Err(WalletError::StoreBusy)
        ));
        drop(s);
        let reopened = WalletStore::open(&path, "test").unwrap();
        assert_eq!(
            reopened.private_treasury_template_ids(context()).unwrap(),
            vec![id]
        );
        let restored = reopened
            .load_private_treasury_template(context(), id)
            .unwrap();
        assert_eq!(
            restored.journal_encode().unwrap().as_slice(),
            exact.as_slice()
        );
        let encrypted = std::fs::read(&path).unwrap();
        assert!(!encrypted
            .windows(exact.len())
            .any(|window| window == exact.as_slice()));
    }
    #[test]
    fn private_spend_journal_ambiguous_restart_keeps_reservation_and_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let s = setup(&path);
        let row = attempt();
        let exact = row.action.clone();
        s.with_private_journal_mut(|state| {
            state.private_spend_attempts.push(row);
            Ok(())
        })
        .unwrap();
        assert!(s.cancel_private_spend_preparation([11; 32]).is_err());
        drop(s);
        let s = WalletStore::open(&path, "test").unwrap();
        s.with_state(|state| {
            assert_eq!(state.private_spend_attempts[0].action, exact);
            assert!(state.reserved_poseidon2_v8_nullifiers().contains(&[5; 7]));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            s.private_spend_attempts().unwrap()[0].status,
            PrivateSpendAttemptStatus::SubmissionUncertain
        );
        assert!(authority(context(), 101, 4).is_err());
    }
    #[test]
    fn private_spend_journal_overlap_rolls_back_and_readonly_cannot_mutate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let s = setup(&path);
        s.with_private_journal_mut(|state| {
            state.private_spend_attempts.push(attempt());
            Ok(())
        })
        .unwrap();
        let mut second = attempt();
        second.id = [12; 32];
        assert!(s
            .with_private_journal_mut(|state| {
                state.private_spend_attempts.push(second);
                Ok(())
            })
            .is_err());
        assert_eq!(s.private_spend_attempts().unwrap().len(), 1);
        let readonly = WalletStore::open_read_only(&path, "test").unwrap();
        assert!(readonly.cancel_private_spend_preparation([11; 32]).is_err());
        drop(readonly);
        drop(s);
        assert_eq!(
            WalletStore::open(&path, "test")
                .unwrap()
                .private_spend_attempts()
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn private_spend_journal_detached_receipt_reinstates_uncertainty_without_release() {
        let dir = tempfile::tempdir().unwrap();
        let s = setup(&dir.path().join("wallet"));
        s.with_private_journal_mut(|state| {
            let mut r = attempt();
            r.mined_in = Some((100, [22; 32]));
            state.private_spend_attempts.push(r);
            state.reconcile_private_spend_attempts(&[])?;
            assert!(state.private_spend_attempts[0].mined_in.is_none());
            assert!(state.reserved_poseidon2_v8_nullifiers().contains(&[5; 7]));
            Ok(())
        })
        .unwrap();
    }
    // This native tombstone is conservatively active without a mirror tip,
    // the same branch used when a rollback reaches its old admission window.
    // Framing-only journal fixtures never claim actual proof acceptance.
    fn conflicting_native_reservation(
        status: crate::store::Poseidon2V8ReservationStatus,
    ) -> crate::store::poseidon2_v8_reservations::StoredPoseidon2V8Reservation {
        serde_json::from_value(serde_json::json!({
            "id": vec![31u8; 32], "genesis_hash": context().genesis_hash(),
            "parent_height": 100, "parent_hash": vec![2u8; 32],
            "inputs": [
                {"commitment": vec![4u64; 7], "nullifier": vec![5u64; 7],
                 "position": 0, "created_block_hash": vec![2u8; 32]},
                {"commitment": vec![8u64; 7], "nullifier": vec![9u64; 7],
                 "position": 1, "created_block_hash": vec![2u8; 32]}
            ], "status": status
        })).unwrap()
    }

    #[test]
    fn private_exported_body_survives_revived_native_hold_and_blocks_resubmission() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let store = setup(&path);
        let exact = attempt().action;
        store.with_private_journal_mut(|state| {
            state.private_spend_attempts.push(attempt());
            state.poseidon2_v8_reservations.push(conflicting_native_reservation(
                crate::store::Poseidon2V8ReservationStatus::Abandoned));
            state.validate_poseidon2_v8_reservations()?;
            state.validate_private_spend_journal()?;
            assert!(state.reserved_ordinary_poseidon2_v8_nullifiers().contains(&[5; 7]));
            assert!(state.reserved_poseidon2_v8_nullifiers().contains(&[9; 7]));
            assert!(state.require_private_spend_inputs_exclusive([11; 32]).is_err());
            assert!(state.require_poseidon2_v8_inputs_exclusive([31; 32]).is_err());
            Ok(())
        }).unwrap();
        let error = store.private_spend_submission_bytes_with_authority(
            context(), [11; 32], |_, _, _| panic!("conflict must reject before authority"));
        assert!(matches!(error, Err(WalletError::InvalidState(
            "private spend input reserved by another attempt"))));
        drop(store);
        let store = WalletStore::open(&path, "test").unwrap();
        store.with_state(|state| {
            assert_eq!(state.private_spend_attempts[0].action, exact);
            assert_eq!(state.private_spend_attempts[0].status,
                PrivateSpendAttemptStatus::SubmissionUncertain);
            assert_eq!(state.poseidon2_v8_reservations.len(), 1);
            assert!(state.reserved_poseidon2_v8_nullifiers().contains(&[5; 7]));
            assert!(state.reserved_poseidon2_v8_nullifiers().contains(&[9; 7]));
            Ok(())
        }).unwrap();
    }

    #[test]
    fn private_prepared_and_native_proving_conflicts_cannot_acquire_export_capability() {
        let dir = tempfile::tempdir().unwrap();
        let store = setup(&dir.path().join("wallet"));
        store.with_private_journal_mut(|state| {
            let mut row = attempt();
            row.status = PrivateSpendAttemptStatus::Prepared;
            row.action.clear(); row.action_id.clear();
            state.private_spend_attempts.push(row);
            state.poseidon2_v8_reservations.push(conflicting_native_reservation(
                crate::store::Poseidon2V8ReservationStatus::Proving));
            state.validate_private_spend_journal()?;
            state.validate_poseidon2_v8_reservations()?;
            assert!(state.require_private_spend_inputs_exclusive([11; 32]).is_err());
            assert!(state.require_poseidon2_v8_inputs_exclusive([31; 32]).is_err());
            assert!(state.private_spend_attempts[0].action.is_empty());
            assert_eq!(state.poseidon2_v8_reservations[0].status,
                crate::store::Poseidon2V8ReservationStatus::Proving);
            // Malformed duplicate inputs are still rejected even in a tombstone.
            let bad = &mut state.poseidon2_v8_reservations[0];
            bad.status = crate::store::Poseidon2V8ReservationStatus::Abandoned;
            let mut encoded = serde_json::to_value(&*bad).unwrap();
            encoded["inputs"][1]["nullifier"] = encoded["inputs"][0]["nullifier"].clone();
            *bad = serde_json::from_value(encoded).unwrap();
            assert!(state.validate_poseidon2_v8_reservations().is_err());
            // No mutation is committed: this row is only a malformed validation fixture.
            state.poseidon2_v8_reservations.clear();
            Ok(())
        }).unwrap();
    }

    #[cfg(feature = "private-spend-dev-artifacts")]
    #[test]
    #[ignore = "offline real-proof wallet qualification; constructed trusted-node mirror, not consensus validation"]
    fn private_spend_distinct_wallet_refund_handoff_roundtrips_real_proofs() {
        use crate::{
            keys::RootSecret,
            poseidon2_v8_sync::Poseidon2V8CanonicalBlock,
            private_spend_build::{
                new_htlc_policy, prepare, OutputRequest, SpendInput, SpendOperation, SpendReference,
            },
            private_spend_rpc::DevelopmentPrivateSpendAuthority,
        };
        use codec::Encode;
        use hegemon_hash384::{blake2b_384_domain_hash, domains};
        use protocol_shielded_pool::{
            family::FAMILY_SHIELDED_POOL, poseidon2_v8_coinbase::MintPoseidon2V8RewardsArgs,
            private_spend_transport as t, types::CandidateArtifact,
        };
        use protocol_versioning::launch_candidate::{
            ALLOCATED_REWARD_ACTION_ID, RP06_VERSION_BINDING,
        };
        use serde::Serialize;
        use serde_json::json;
        use sha2::Digest;

        // The local action wire mirrors poseidon2_v8_sync's canonical PendingActionWire.
        // This fixture exercises trusted-node wallet projection and real proofs only.
        #[derive(Clone, Copy, Encode)]
        struct Binding {
            circuit: u16,
            crypto: u16,
        }
        #[derive(Encode)]
        struct RewardWire {
            tx_hash: [u8; 48],
            binding: Binding,
            family_id: u16,
            action_id: u16,
            anchor: [u8; 48],
            nullifiers: Vec<[u8; 48]>,
            commitments: Vec<[u8; 48]>,
            ciphertext_hashes: Vec<[u8; 48]>,
            ciphertext_sizes: Vec<u32>,
            public_args: Vec<u8>,
            fee: u64,
            candidate_artifact: Option<CandidateArtifact>,
        }
        #[derive(Encode)]
        struct Identity<'a> {
            binding: &'a Binding,
            family_id: u16,
            action_id: u16,
            anchor: &'a [u8; 48],
            nullifiers: &'a Vec<[u8; 48]>,
            commitments: &'a Vec<[u8; 48]>,
            ciphertext_hashes: &'a Vec<[u8; 48]>,
            ciphertext_sizes: &'a Vec<u32>,
            public_args: &'a Vec<u8>,
            fee: u64,
            candidate_artifact: &'a Option<CandidateArtifact>,
        }
        fn reward_action(args: &MintPoseidon2V8RewardsArgs) -> Vec<u8> {
            let notes = core::iter::once(&args.miner_note).chain(args.funding_note.iter());
            let raws: Vec<Vec<u8>> = notes
                .map(|n| {
                    crate::notes::NoteCiphertext::from_chain_bytes(&n.encrypted_note.encode())
                        .unwrap()
                        .to_da_bytes()
                        .unwrap()
                })
                .collect();
            let mut wire = RewardWire {
                tx_hash: [0; 48],
                binding: Binding {
                    circuit: RP06_VERSION_BINDING.circuit,
                    crypto: RP06_VERSION_BINDING.crypto,
                },
                family_id: FAMILY_SHIELDED_POOL,
                action_id: ALLOCATED_REWARD_ACTION_ID,
                anchor: [0; 48],
                nullifiers: vec![],
                commitments: vec![],
                ciphertext_hashes: raws
                    .iter()
                    .map(|b| transaction_circuit::hashing_pq::ciphertext_hash_bytes(b))
                    .collect(),
                ciphertext_sizes: raws.iter().map(|b| b.len() as u32).collect(),
                public_args: args.encode(),
                fee: 0,
                candidate_artifact: None,
            };
            let body = Identity {
                binding: &wire.binding,
                family_id: wire.family_id,
                action_id: wire.action_id,
                anchor: &wire.anchor,
                nullifiers: &wire.nullifiers,
                commitments: &wire.commitments,
                ciphertext_hashes: &wire.ciphertext_hashes,
                ciphertext_sizes: &wire.ciphertext_sizes,
                public_args: &wire.public_args,
                fee: wire.fee,
                candidate_artifact: &wire.candidate_artifact,
            }
            .encode();
            wire.tx_hash = blake2b_384_domain_hash(domains::ACTION_ID_V3, [body.as_slice()]);
            wire.encode()
        }
        #[derive(Serialize)]
        struct Source {
            relation_digest: String,
            transport_identity: [u8; 16],
        }
        #[derive(Serialize)]
        struct Candidate {
            activation_height: u64,
            deactivation_height_exclusive: u64,
            max_proof_actions_per_block: usize,
            max_total_proofs: u64,
            max_proof_bytes: usize,
            stablecoin_genesis_root: [u64; 7],
            note_genesis_root: [u64; 7],
            private_spend_only: bool,
            private_spend_source: Option<Source>,
        }
        #[derive(Serialize)]
        struct Manifest {
            schema: String,
            profile: String,
            genesis_timestamp_ms: u64,
            pow_bits: u32,
            rules_hash: String,
            launch_reference_rules_hash: String,
            funding_address: Option<String>,
            funding_subsidy_numerator: u64,
            funding_subsidy_denominator: u64,
            development_candidate: Option<Candidate>,
        }
        #[allow(deprecated)]
        fn native_hash(parts: &[&[u8]]) -> [u8; 32] {
            synthetic_crypto::hashes::blake3_384(&parts.concat())[..32]
                .try_into()
                .unwrap()
        }
        let sender_root = RootSecret::from_bytes([91; 32]);
        let refund_root = RootSecret::from_bytes([92; 32]);
        let sender_keys = sender_root.derive();
        let refund_keys = refund_root.derive();
        let claim = sender_keys
            .poseidon2_v8_address(7)
            .unwrap()
            .shielded_address();
        let refund = refund_keys
            .poseidon2_v8_address(9)
            .unwrap()
            .shielded_address();
        let rules = consensus_light_client::HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE;
        let window = protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW;
        let reference_rules = native_hash(&[
            b"hegemon.native.launch-reference-rules.v2\0",
            &rules,
            &window.to_le_bytes(),
            &0u64.to_le_bytes(),
            b"block-end-anchor/static-stable-root/actual-inclusion-source/fork-bound-receipt/v1\0",
            protocol_versioning::COINBASE_MATURITY_RULES_ID,
            &protocol_versioning::COINBASE_MATURITY.to_le_bytes(),
            &transaction_circuit::asset_spend_v1::ASSET_REFERENCE_WINDOW.to_le_bytes(),
            b"asset-canonical-block-end-note-and-registry/current-full-registry/expiry-horizon/current-inclusion-accounting-and-nullifiers/v2\0",
        ]);
        let note_root =
            transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_default_note_nodes()
                [32];
        let manifest = Manifest {
            schema: "hegemon.native.network-manifest.v1".into(),
            profile: "development".into(),
            genesis_timestamp_ms: 1,
            pow_bits: 0x207f_ffff,
            rules_hash: format!("0x{}", hex::encode(rules)),
            launch_reference_rules_hash: format!("0x{}", hex::encode(reference_rules)),
            funding_address: Some(refund.encode().unwrap()),
            funding_subsidy_numerator: 1,
            funding_subsidy_denominator: 5,
            development_candidate: Some(Candidate {
                activation_height: 1,
                deactivation_height_exclusive: 100,
                max_proof_actions_per_block: 8,
                max_total_proofs: 128,
                max_proof_bytes: t::MAX_CARRIER_BYTES,
                stablecoin_genesis_root: [0; 7],
                note_genesis_root: note_root,
                private_spend_only: true,
                private_spend_source: Some(Source {
                    relation_digest: hex::encode(relation::relation_digest()),
                    transport_identity: t::IDENTITY,
                }),
            }),
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let chain = native_hash(&[b"hegemon.native.network-id.v1\0", &manifest_bytes]);
        let mut digest = sha2::Sha512::new();
        digest.update(b"hegemon.native.network-manifest.sha512.v1\0");
        digest.update(&manifest_bytes);
        let manifest_digest: [u8; 64] = digest.finalize().into();
        let genesis = [0x91; 32];
        let node = json!({"networkProfile":"development", "chainId":format!("0x{}",hex::encode(chain)),
            "networkManifestDigest":format!("0x{}",hex::encode(manifest_digest)), "networkManifest":manifest});
        let params = json!({"relation_digest":hex::encode(relation::relation_digest()), "action_id":15,
            "public_words":relation::PUBLIC_WORDS, "ciphertext_bytes":t::CIPHERTEXT_BYTES, "production_authorized":false});
        let token = DevelopmentPrivateSpendAuthority::from_verified_node(
            &manifest_bytes,
            genesis,
            genesis,
            &node,
            &params,
            0,
        )
        .unwrap();
        let context = token.context();
        let dir = tempfile::tempdir().unwrap();
        let sender =
            WalletStore::create_from_root(dir.path().join("sender"), "test", sender_root).unwrap();
        let receiver =
            WalletStore::create_from_root(dir.path().join("refund"), "test", refund_root).unwrap();
        sender
            .initialize_private_spend_development_context(&token)
            .unwrap();
        receiver
            .initialize_private_spend_development_context(&token)
            .unwrap();
        sender.private_spend_address(7).unwrap();
        receiver.private_spend_address(9).unwrap();

        // Actual height-one subsidy and immutable 1/5 funding split. Wallet mirror
        // trusts this constructed action as node-projected input; it does not authenticate issuance.
        let subsidy = (21_000_000u64 * 100_000_000 * 60) / (2 * 4 * 31_536_000);
        assert_eq!(subsidy, 499_429_223);
        let funding_amount = subsidy / 5;
        let miner_amount = subsidy - funding_amount;
        let rewards = crate::poseidon2_v8_coinbase::build_poseidon2_v8_rewards_args(
            &claim,
            miner_amount,
            &refund,
            funding_amount,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let reward_block = Poseidon2V8CanonicalBlock {
            height: 1,
            hash: [1; 32],
            parent_hash: genesis,
            action_bytes: vec![reward_action(&rewards)],
        };
        sender
            .apply_private_spend_development_block(&reward_block, &token)
            .unwrap();
        receiver
            .apply_private_spend_development_block(&reward_block, &token)
            .unwrap();
        let source_view = sender
            .poseidon2_v8_owned_notes()
            .unwrap()
            .into_iter()
            .find(|n| n.opening.value == miner_amount)
            .unwrap();
        let tip = sender.poseidon2_v8_tip().unwrap();
        let reference = SpendReference {
            chain_id: context.chain_id(),
            parent_hash: tip.block_hash,
            parent_height: tip.height,
            merkle_root: tip.anchor,
        };
        let source_note = relation::Note {
            value: source_view.opening.value,
            asset_id: source_view.opening.asset_id,
            recipient_key: source_view.opening.recipient_key,
            authorization_key: source_view.opening.authorization_key,
            rho: source_view.opening.rho,
            randomness: source_view.opening.randomness,
        };
        let input = SpendInput::legacy(
            source_note,
            source_view.position as u32,
            source_view.path,
            &sender_keys,
            context.chain_id(),
        )
        .unwrap();
        let policy = new_htlc_policy(reference, &claim, &refund, [0x33; 32], 15).unwrap();
        let locked_value = 1_000u64;
        let lock = prepare(
            reference,
            0,
            [input, SpendInput::dummy().unwrap()],
            [
                OutputRequest {
                    recipient: claim.clone(),
                    value: locked_value,
                },
                OutputRequest {
                    recipient: claim.clone(),
                    value: miner_amount - locked_value,
                },
            ],
            SpendOperation::HtlcLock(policy),
        )
        .unwrap();
        let lock_id = sender.reserve_private_spend(context, &lock).unwrap();
        let lock_carrier = lock.prove_local_candidate().unwrap();
        let expected = t::ExpectedContext::new(
            context.chain_id(),
            relation::relation_digest()[..48].try_into().unwrap(),
        )
        .unwrap();
        let lock_decoded = t::decode_exact(expected, &lock_carrier).unwrap();
        assert_eq!(lock_carrier.len(), 1_931_869);
        assert_eq!(lock_decoded.proof.len(), 1_926_125);
        assert_eq!(
            lock_carrier.len(),
            (t::PREAMBLE_BYTES + 2 * t::CIPHERTEXT_BYTES) + lock_decoded.proof.len()
        );
        let lock_action =
            crate::poseidon2_v8_sync::encode_private_spend_candidate_action(context, &lock_carrier)
                .unwrap();
        sender
            .retain_private_spend_action_local_candidate(context, lock_id, &lock_action, &token)
            .unwrap();
        sender
            .retain_private_htlc_refund_handoff(context, lock_id, &lock)
            .unwrap();
        let passphrase = "temporary refund handoff test";
        let sealed = sender
            .export_private_htlc_refund_handoff_encrypted(context, lock_id, &lock, passphrase)
            .unwrap();
        let lock_block = Poseidon2V8CanonicalBlock {
            height: 2,
            hash: [2; 32],
            parent_hash: [1; 32],
            action_bytes: vec![lock_action],
        };
        let before = receiver.private_spend_notes().unwrap().len();
        assert!(
            receiver
                .import_private_htlc_refund_handoff_encrypted_local_candidate(
                    context,
                    &sealed,
                    passphrase,
                    9,
                    &lock_block,
                    &token
                )
                .is_err(),
            "unmined lock handoff must fail"
        );
        assert_eq!(receiver.private_spend_notes().unwrap().len(), before);
        sender
            .apply_private_spend_development_block(&lock_block, &token)
            .unwrap();
        assert!(receiver
            .import_private_htlc_refund_handoff_encrypted_local_candidate(
                context,
                &sealed,
                "wrong passphrase",
                9,
                &lock_block,
                &token
            )
            .is_err());
        assert_eq!(receiver.private_spend_notes().unwrap().len(), before);
        let sender_before = sender.private_spend_notes().unwrap().len();
        assert!(
            sender
                .import_private_htlc_refund_handoff_encrypted_local_candidate(
                    context,
                    &sealed,
                    passphrase,
                    7,
                    &lock_block,
                    &token
                )
                .is_err(),
            "claim authority cannot satisfy the distinct refund authority"
        );
        assert_eq!(sender.private_spend_notes().unwrap().len(), sender_before);
        receiver
            .apply_private_spend_development_block(&lock_block, &token)
            .unwrap();
        let lock_commitment = receiver
            .import_private_htlc_refund_handoff_encrypted_local_candidate(
                context,
                &sealed,
                passphrase,
                9,
                &lock_block,
                &token,
            )
            .unwrap();
        let stored = receiver
            .private_spend_notes()
            .unwrap()
            .into_iter()
            .find(|n| n.commitment == lock_commitment)
            .unwrap();
        let stored_opening = stored.opening().unwrap();
        let h = match &stored_opening.state {
            synthetic_crypto::private_note_payload::NoteState::Htlc(h) => h,
            _ => panic!("expected HTLC"),
        };
        let early_tip = receiver.poseidon2_v8_tip().unwrap();
        assert_eq!(early_tip.height, 2);
        let early_witness = receiver
            .poseidon2_v8_canonical_note_witness_at(stored.commitment, stored.position)
            .unwrap()
            .unwrap();
        let early_input = SpendInput::stored(&stored, &refund_keys, early_witness.path).unwrap();
        let early_policy = relation::PrivateHtlcOpening {
            nullifier_key: h.nullifier_key,
            hashlock: h.hashlock,
            claim_authority: h.claim_authority,
            refund_authority: h.refund_authority,
            claim_recipient: h.claim_recipient,
            refund_recipient: h.refund_recipient,
            timeout: h.timeout,
            secret: [0; 32],
            release_secret: h.release_secret,
        };
        assert!(
            prepare(
                SpendReference {
                    chain_id: context.chain_id(),
                    parent_hash: early_tip.block_hash,
                    parent_height: early_tip.height,
                    merkle_root: early_tip.anchor
                },
                0,
                [early_input, SpendInput::dummy().unwrap()],
                [
                    OutputRequest {
                        recipient: refund.clone(),
                        value: locked_value
                    },
                    OutputRequest {
                        recipient: refund.clone(),
                        value: 0
                    }
                ],
                SpendOperation::HtlcRefund(early_policy)
            )
            .is_err(),
            "refund before timeout must fail"
        );
        let mut parent_hash = lock_block.hash;
        for height in 3..=15 {
            let hash = [height as u8; 32];
            let block = Poseidon2V8CanonicalBlock {
                height,
                hash,
                parent_hash,
                action_bytes: vec![],
            };
            sender
                .apply_private_spend_development_block(&block, &token)
                .unwrap();
            receiver
                .apply_private_spend_development_block(&block, &token)
                .unwrap();
            parent_hash = hash;
        }
        let witness = receiver
            .poseidon2_v8_canonical_note_witness_at(stored.commitment, stored.position)
            .unwrap()
            .unwrap();
        let refund_input = SpendInput::stored(&stored, &refund_keys, witness.path).unwrap();
        let tip = receiver.poseidon2_v8_tip().unwrap();
        assert_eq!(tip.height, 15);
        let refund_reference = SpendReference {
            chain_id: context.chain_id(),
            parent_hash: tip.block_hash,
            parent_height: tip.height,
            merkle_root: tip.anchor,
        };
        let opening = stored.opening().unwrap();
        let h = match &opening.state {
            synthetic_crypto::private_note_payload::NoteState::Htlc(h) => h,
            _ => panic!("expected HTLC"),
        };
        let refund_policy = relation::PrivateHtlcOpening {
            nullifier_key: h.nullifier_key,
            hashlock: h.hashlock,
            claim_authority: h.claim_authority,
            refund_authority: h.refund_authority,
            claim_recipient: h.claim_recipient,
            refund_recipient: h.refund_recipient,
            timeout: h.timeout,
            secret: [0; 32],
            release_secret: h.release_secret,
        };
        let refund_spend = prepare(
            refund_reference,
            0,
            [refund_input, SpendInput::dummy().unwrap()],
            [
                OutputRequest {
                    recipient: refund.clone(),
                    value: locked_value,
                },
                OutputRequest {
                    recipient: refund.clone(),
                    value: 0,
                },
            ],
            SpendOperation::HtlcRefund(refund_policy),
        )
        .unwrap();
        let refund_carrier = refund_spend.prove_local_candidate().unwrap();
        let refund_decoded = t::decode_exact(expected, &refund_carrier).unwrap();
        assert_eq!(refund_carrier.len(), 1_931_869);
        assert_eq!(refund_decoded.proof.len(), 1_926_125);
        assert_eq!(
            refund_carrier.len(),
            (t::PREAMBLE_BYTES + 2 * t::CIPHERTEXT_BYTES) + refund_decoded.proof.len()
        );
        let refund_action = crate::poseidon2_v8_sync::encode_private_spend_candidate_action(
            context,
            &refund_carrier,
        )
        .unwrap();
        let refund_id = receiver
            .reserve_private_spend(context, &refund_spend)
            .unwrap();
        receiver
            .retain_private_spend_action_local_candidate(context, refund_id, &refund_action, &token)
            .unwrap();
        assert_eq!(
            receiver
                .private_spend_submission_bytes_local_candidate(context, refund_id, &token)
                .unwrap(),
            refund_action
        );
        let refund_block = Poseidon2V8CanonicalBlock {
            height: 16,
            hash: [16; 32],
            parent_hash: tip.block_hash,
            action_bytes: vec![refund_action],
        };
        sender
            .apply_private_spend_development_block(&refund_block, &token)
            .unwrap();
        receiver
            .apply_private_spend_development_block(&refund_block, &token)
            .unwrap();
        assert!(receiver
            .private_spend_notes()
            .unwrap()
            .iter()
            .any(|n| n.commitment == refund_spend.public_statement().commitments[0]));
        let returned = receiver
            .private_spend_notes()
            .unwrap()
            .into_iter()
            .find(|n| n.commitment == refund_spend.public_statement().commitments[0])
            .unwrap();
        assert_eq!(returned.opening().unwrap().note.value, locked_value);
        assert!(
            receiver
                .private_spend_notes()
                .unwrap()
                .iter()
                .find(|n| n.commitment == lock_commitment)
                .unwrap()
                .spent
        );
        let lock_attempt = sender
            .private_spend_attempts()
            .unwrap()
            .into_iter()
            .find(|a| a.id == lock_id)
            .unwrap();
        assert_eq!(lock_attempt.mined_in, Some((2, lock_block.hash)));
        assert_eq!(lock_attempt.status, PrivateSpendAttemptStatus::Candidate);
        assert!(lock_attempt.inputs_consumed);
        let refund_attempt = receiver
            .private_spend_attempts()
            .unwrap()
            .into_iter()
            .find(|a| a.id == refund_id)
            .unwrap();
        assert_eq!(refund_attempt.mined_in, Some((16, refund_block.hash)));
        assert_eq!(
            refund_attempt.status,
            PrivateSpendAttemptStatus::SubmissionUncertain
        );
        assert!(refund_attempt.inputs_consumed);
    }
    #[cfg(feature = "private-spend-dev-artifacts")]
    #[test]
    #[ignore = "offline real-proof distinct-wallet treasury qualification; constructed trusted-node mirror, not consensus validation"]
    fn private_spend_distinct_wallet_treasury_two_of_three_roundtrips_real_proofs() {
        use crate::{
            keys::RootSecret,
            poseidon2_v8_multisig::{
                v8_treasury_signer_tag, V8TreasuryDescriptor, V8TreasuryNoteKind,
            },
            poseidon2_v8_sync::Poseidon2V8CanonicalBlock,
            private_spend_build::{
                prepare, treasury_value_input, OutputRequest, SpendInput, SpendOperation,
                SpendReference, TreasuryFinalTemplate,
            },
            private_spend_rpc::DevelopmentPrivateSpendAuthority,
        };
        use codec::Encode;
        use hegemon_hash384::{blake2b_384_domain_hash, domains};
        use protocol_shielded_pool::{
            family::FAMILY_SHIELDED_POOL, poseidon2_v8_coinbase::MintPoseidon2V8RewardsArgs,
            private_spend_transport as t, types::CandidateArtifact,
        };
        use protocol_versioning::launch_candidate::{
            ALLOCATED_REWARD_ACTION_ID, RP06_VERSION_BINDING,
        };
        use serde::Serialize;
        use serde_json::json;
        use sha2::Digest;

        #[derive(Clone, Copy, Encode)]
        struct Binding {
            circuit: u16,
            crypto: u16,
        }
        #[derive(Encode)]
        struct RewardWire {
            tx_hash: [u8; 48],
            binding: Binding,
            family_id: u16,
            action_id: u16,
            anchor: [u8; 48],
            nullifiers: Vec<[u8; 48]>,
            commitments: Vec<[u8; 48]>,
            ciphertext_hashes: Vec<[u8; 48]>,
            ciphertext_sizes: Vec<u32>,
            public_args: Vec<u8>,
            fee: u64,
            candidate_artifact: Option<CandidateArtifact>,
        }
        #[derive(Encode)]
        struct Identity<'a> {
            binding: &'a Binding,
            family_id: u16,
            action_id: u16,
            anchor: &'a [u8; 48],
            nullifiers: &'a Vec<[u8; 48]>,
            commitments: &'a Vec<[u8; 48]>,
            ciphertext_hashes: &'a Vec<[u8; 48]>,
            ciphertext_sizes: &'a Vec<u32>,
            public_args: &'a Vec<u8>,
            fee: u64,
            candidate_artifact: &'a Option<CandidateArtifact>,
        }
        fn reward_action(args: &MintPoseidon2V8RewardsArgs) -> Vec<u8> {
            let notes = core::iter::once(&args.miner_note).chain(args.funding_note.iter());
            let raws: Vec<Vec<u8>> = notes
                .map(|n| {
                    crate::notes::NoteCiphertext::from_chain_bytes(&n.encrypted_note.encode())
                        .unwrap()
                        .to_da_bytes()
                        .unwrap()
                })
                .collect();
            let mut wire = RewardWire {
                tx_hash: [0; 48],
                binding: Binding {
                    circuit: RP06_VERSION_BINDING.circuit,
                    crypto: RP06_VERSION_BINDING.crypto,
                },
                family_id: FAMILY_SHIELDED_POOL,
                action_id: ALLOCATED_REWARD_ACTION_ID,
                anchor: [0; 48],
                nullifiers: vec![],
                commitments: vec![],
                ciphertext_hashes: raws
                    .iter()
                    .map(|b| transaction_circuit::hashing_pq::ciphertext_hash_bytes(b))
                    .collect(),
                ciphertext_sizes: raws.iter().map(|b| b.len() as u32).collect(),
                public_args: args.encode(),
                fee: 0,
                candidate_artifact: None,
            };
            let body = Identity {
                binding: &wire.binding,
                family_id: wire.family_id,
                action_id: wire.action_id,
                anchor: &wire.anchor,
                nullifiers: &wire.nullifiers,
                commitments: &wire.commitments,
                ciphertext_hashes: &wire.ciphertext_hashes,
                ciphertext_sizes: &wire.ciphertext_sizes,
                public_args: &wire.public_args,
                fee: wire.fee,
                candidate_artifact: &wire.candidate_artifact,
            }
            .encode();
            wire.tx_hash = blake2b_384_domain_hash(domains::ACTION_ID_V3, [body.as_slice()]);
            wire.encode()
        }
        #[derive(Serialize)]
        struct Source {
            relation_digest: String,
            transport_identity: [u8; 16],
        }
        #[derive(Serialize)]
        struct Candidate {
            activation_height: u64,
            deactivation_height_exclusive: u64,
            max_proof_actions_per_block: usize,
            max_total_proofs: u64,
            max_proof_bytes: usize,
            stablecoin_genesis_root: [u64; 7],
            note_genesis_root: [u64; 7],
            private_spend_only: bool,
            private_spend_source: Option<Source>,
        }
        #[derive(Serialize)]
        struct Manifest {
            schema: String,
            profile: String,
            genesis_timestamp_ms: u64,
            pow_bits: u32,
            rules_hash: String,
            launch_reference_rules_hash: String,
            funding_address: Option<String>,
            funding_subsidy_numerator: u64,
            funding_subsidy_denominator: u64,
            development_candidate: Option<Candidate>,
        }
        #[allow(deprecated)]
        fn native_hash(parts: &[&[u8]]) -> [u8; 32] {
            synthetic_crypto::hashes::blake3_384(&parts.concat())[..32]
                .try_into()
                .unwrap()
        }
        let roots = [
            RootSecret::from_bytes([91; 32]),
            RootSecret::from_bytes([92; 32]),
            RootSecret::from_bytes([93; 32]),
        ];
        let initial_keys = roots.each_ref().map(|root| root.derive());
        let initial_tags = initial_keys
            .each_ref()
            .map(|k| v8_treasury_signer_tag(k).unwrap());
        let descriptor = V8TreasuryDescriptor::create(
            &initial_keys[0],
            [0xa1; 32],
            initial_tags,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let rules = consensus_light_client::HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE;
        let window = protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW;
        let reference_rules = native_hash(&[
            b"hegemon.native.launch-reference-rules.v2\0",
            &rules,
            &window.to_le_bytes(),
            &0u64.to_le_bytes(),
            b"block-end-anchor/static-stable-root/actual-inclusion-source/fork-bound-receipt/v1\0",
            protocol_versioning::COINBASE_MATURITY_RULES_ID,
            &protocol_versioning::COINBASE_MATURITY.to_le_bytes(),
            &transaction_circuit::asset_spend_v1::ASSET_REFERENCE_WINDOW.to_le_bytes(),
            b"asset-canonical-block-end-note-and-registry/current-full-registry/expiry-horizon/current-inclusion-accounting-and-nullifiers/v2\0",
        ]);
        let note_root =
            transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_default_note_nodes()
                [32];
        let manifest = Manifest {
            schema: "hegemon.native.network-manifest.v1".into(),
            profile: "development".into(),
            genesis_timestamp_ms: 1,
            pow_bits: 0x207f_ffff,
            rules_hash: format!("0x{}", hex::encode(rules)),
            launch_reference_rules_hash: format!("0x{}", hex::encode(reference_rules)),
            funding_address: Some(descriptor.receive_address.encode().unwrap()),
            funding_subsidy_numerator: 1,
            funding_subsidy_denominator: 5,
            development_candidate: Some(Candidate {
                activation_height: 1,
                deactivation_height_exclusive: 100,
                max_proof_actions_per_block: 8,
                max_total_proofs: 128,
                max_proof_bytes: t::MAX_CARRIER_BYTES,
                stablecoin_genesis_root: [0; 7],
                note_genesis_root: note_root,
                private_spend_only: true,
                private_spend_source: Some(Source {
                    relation_digest: hex::encode(relation::relation_digest()),
                    transport_identity: t::IDENTITY,
                }),
            }),
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let chain = native_hash(&[b"hegemon.native.network-id.v1\0", &manifest_bytes]);
        let mut digest = sha2::Sha512::new();
        digest.update(b"hegemon.native.network-manifest.sha512.v1\0");
        digest.update(&manifest_bytes);
        let manifest_digest: [u8; 64] = digest.finalize().into();
        let genesis = [0x91; 32];
        let node = json!({"networkProfile":"development", "chainId":format!("0x{}",hex::encode(chain)),
            "networkManifestDigest":format!("0x{}",hex::encode(manifest_digest)), "networkManifest":manifest});
        let params = json!({"relation_digest":hex::encode(relation::relation_digest()), "action_id":15,
            "public_words":relation::PUBLIC_WORDS, "ciphertext_bytes":t::CIPHERTEXT_BYTES, "production_authorized":false});
        let token = DevelopmentPrivateSpendAuthority::from_verified_node(
            &manifest_bytes,
            genesis,
            genesis,
            &node,
            &params,
            0,
        )
        .unwrap();
        let context = token.context();
        let order: [usize; 3] = std::array::from_fn(|slot| {
            initial_tags
                .iter()
                .position(|tag| *tag == descriptor.signer_tags[slot])
                .unwrap()
        });
        let keys: [crate::DerivedKeys; 3] =
            std::array::from_fn(|slot| initial_keys[order[slot]].clone());
        let signer_seeds = order.map(|index| [91u8, 92, 93][index]);
        let signers = keys
            .each_ref()
            .map(|k| k.poseidon2_v8_address(7).unwrap().shielded_address());
        let dir = tempfile::tempdir().unwrap();
        let wallets: [WalletStore; 3] = std::array::from_fn(|i| {
            let wallet = WalletStore::create_from_root(
                dir.path().join(format!("signer-{i}")),
                "test",
                RootSecret::from_bytes([signer_seeds[i]; 32]),
            )
            .unwrap();
            wallet
                .initialize_private_spend_development_context(&token)
                .unwrap();
            wallet.private_spend_address(7).unwrap();
            wallet
                .import_v8_treasury_descriptor(descriptor.clone())
                .unwrap();
            wallet
        });
        for wallet in &wallets {
            wallet
                .bind_v8_treasury_network_before_activity(descriptor.account_id, context.chain_id())
                .unwrap();
        }
        let descriptor = wallets[0]
            .v8_treasury_descriptors()
            .unwrap()
            .into_iter()
            .next()
            .unwrap();

        // Source-height-one subsidy is the actual formula result. These constructed
        // allocated-reward actions test trusted-node wallet projection only.
        let subsidy = (21_000_000u64 * 100_000_000 * 60) / (2 * 4 * 31_536_000);
        assert_eq!(subsidy, 499_429_223);
        let funding = subsidy / 5;
        let miner = subsidy - funding;
        let reward1 = crate::poseidon2_v8_coinbase::build_poseidon2_v8_rewards_args(
            &signers[0],
            miner,
            &descriptor.receive_address,
            funding,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let block1 = Poseidon2V8CanonicalBlock {
            height: 1,
            hash: [1; 32],
            parent_hash: genesis,
            action_bytes: vec![reward_action(&reward1)],
        };
        for wallet in &wallets {
            wallet
                .apply_private_spend_development_block(&block1, &token)
                .unwrap();
        }
        let reward2 = crate::poseidon2_v8_coinbase::build_poseidon2_v8_rewards_args(
            &signers[1],
            miner,
            &descriptor.receive_address,
            funding,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let block2 = Poseidon2V8CanonicalBlock {
            height: 2,
            hash: [2; 32],
            parent_hash: block1.hash,
            action_bytes: vec![reward_action(&reward2)],
        };
        for wallet in &wallets {
            wallet
                .apply_private_spend_development_block(&block2, &token)
                .unwrap();
        }
        let tip = wallets[0].poseidon2_v8_tip().unwrap();
        let reference = SpendReference {
            chain_id: context.chain_id(),
            parent_hash: tip.block_hash,
            parent_height: tip.height,
            merkle_root: tip.anchor,
        };

        let treasury_note = wallets[0]
            .v8_treasury_notes(descriptor.account_id)
            .unwrap()
            .into_iter()
            .find(|n| matches!(&n.kind, V8TreasuryNoteKind::Value))
            .unwrap();
        let treasury_position = wallets[0]
            .poseidon2_v8_canonical_commitment_positions(treasury_note.commitment)
            .unwrap()[0];
        let treasury_view = wallets[0]
            .v8_treasury_note_view(
                descriptor.account_id,
                treasury_note.commitment,
                treasury_position,
            )
            .unwrap();
        let (value_input, policy) =
            treasury_value_input(reference, &descriptor, &treasury_view).unwrap();
        let fee = 1_000u64;
        let recipient_value = funding * 3 / 4;
        let change_value = funding - fee - recipient_value;
        let final_template = TreasuryFinalTemplate::prepare(
            reference,
            fee,
            &value_input,
            policy.clone(),
            [
                OutputRequest {
                    recipient: signers[1].clone(),
                    value: recipient_value,
                },
                OutputRequest {
                    recipient: signers[0].clone(),
                    value: change_value,
                },
            ],
        )
        .unwrap();
        let saved_id = wallets[0]
            .save_private_treasury_template(context, &final_template)
            .unwrap();
        let sealed = wallets[0]
            .export_private_treasury_template_encrypted(context, saved_id, "treasury handoff")
            .unwrap();
        let mut imported_ids = [[0u8; 32]; 2];
        for (slot, signer) in [&wallets[1], &wallets[2]].into_iter().enumerate() {
            let before = signer.private_treasury_template_ids(context).unwrap();
            let imported = signer
                .import_private_treasury_template_encrypted(context, &sealed, "treasury handoff")
                .unwrap();
            imported_ids[slot] = imported;
            let imported_template = signer
                .load_private_treasury_template(context, imported)
                .unwrap();
            assert_eq!(
                imported_template.journal_encode().unwrap(),
                final_template.journal_encode().unwrap()
            );
            assert_eq!(
                signer.private_treasury_template_ids(context).unwrap().len(),
                before.len() + 1
            );
        }
        let signer2_templates_before = wallets[2].private_treasury_template_ids(context).unwrap();
        assert!(wallets[2]
            .import_private_treasury_template_encrypted(context, &sealed, "wrong passphrase")
            .is_err());
        assert_eq!(
            wallets[2].private_treasury_template_ids(context).unwrap(),
            signer2_templates_before
        );
        let signer1_template = wallets[1]
            .load_private_treasury_template(context, imported_ids[0])
            .unwrap();
        let signer2_template = wallets[2]
            .load_private_treasury_template(context, imported_ids[1])
            .unwrap();
        assert!(
            signer1_template.approval_policy([1, 0, 0], 0).is_err(),
            "a signer cannot approve twice"
        );

        let miner_input = |wallet: &WalletStore, signer_keys: &crate::DerivedKeys| {
            let view = wallet
                .poseidon2_v8_owned_notes()
                .unwrap()
                .into_iter()
                .find(|n| n.opening.value == miner && !n.spent)
                .unwrap();
            SpendInput::legacy(
                relation::Note {
                    value: view.opening.value,
                    asset_id: view.opening.asset_id,
                    recipient_key: view.opening.recipient_key,
                    authorization_key: view.opening.authorization_key,
                    rho: view.opening.rho,
                    randomness: view.opening.randomness,
                },
                view.position as u32,
                view.path,
                signer_keys,
                context.chain_id(),
            )
            .unwrap()
        };
        let action = |prepared: &crate::private_spend_build::PreparedPrivateSpend,
                      wallet: &WalletStore| {
            let id = wallet.reserve_private_spend(context, prepared).unwrap();
            let carrier = prepared.prove_local_candidate().unwrap();
            let decoded = t::decode_exact(
                t::ExpectedContext::new(
                    context.chain_id(),
                    relation::relation_digest()[..48].try_into().unwrap(),
                )
                .unwrap(),
                &carrier,
            )
            .unwrap();
            assert_eq!(carrier.len(), 1_931_869);
            assert_eq!(decoded.proof.len(), 1_926_125);
            let action =
                crate::poseidon2_v8_sync::encode_private_spend_candidate_action(context, &carrier)
                    .unwrap();
            wallet
                .retain_private_spend_action_local_candidate(context, id, &action, &token)
                .unwrap();
            (action, id)
        };
        let accumulator_input = |wallet: &WalletStore, signer_keys: &crate::DerivedKeys| {
            let note = wallet
                .private_spend_notes()
                .unwrap()
                .into_iter()
                .find(|n| {
                    !n.spent
                        && matches!(
                            n.opening().unwrap().state,
                            synthetic_crypto::private_note_payload::NoteState::TreasuryAccumulator(
                                _
                            )
                        )
                })
                .unwrap();
            let witness = wallet
                .poseidon2_v8_canonical_note_witness_at(note.commitment, note.position)
                .unwrap()
                .unwrap();
            SpendInput::stored(&note, signer_keys, witness.path).unwrap()
        };

        let approval1_policy = signer1_template.approval_policy([0, 0, 0], 0).unwrap();
        let approval1 = prepare(
            reference,
            fee,
            [
                SpendInput::dummy().unwrap(),
                miner_input(&wallets[0], &keys[0]),
            ],
            [
                OutputRequest {
                    recipient: signers[1].clone(),
                    value: 0,
                },
                OutputRequest {
                    recipient: signers[0].clone(),
                    value: miner - fee,
                },
            ],
            SpendOperation::Approval(approval1_policy),
        )
        .unwrap();
        let (approval1_action, approval1_id) = action(&approval1, &wallets[0]);
        assert_eq!(
            wallets[0]
                .private_spend_submission_bytes_local_candidate(context, approval1_id, &token)
                .unwrap(),
            approval1_action
        );
        let block3 = Poseidon2V8CanonicalBlock {
            height: 3,
            hash: [3; 32],
            parent_hash: block2.hash,
            action_bytes: vec![approval1_action],
        };
        for wallet in &wallets {
            wallet
                .apply_private_spend_development_block(&block3, &token)
                .unwrap();
        }

        let ref3 = SpendReference {
            parent_hash: block3.hash,
            parent_height: 3,
            merkle_root: wallets[0].poseidon2_v8_tip().unwrap().anchor,
            ..reference
        };
        let (early_value, _) = treasury_value_input(
            ref3,
            &descriptor,
            &wallets[0]
                .v8_treasury_note_view(
                    descriptor.account_id,
                    treasury_note.commitment,
                    treasury_position,
                )
                .unwrap(),
        )
        .unwrap();
        let early_template = wallets[0]
            .load_private_treasury_template(context, saved_id)
            .unwrap();
        let early_attempts = wallets[0].private_spend_attempts().unwrap().len();
        assert!(
            early_template
                .finalize(
                    ref3,
                    [early_value, accumulator_input(&wallets[1], &keys[1])],
                    [1, 0, 0]
                )
                .is_err(),
            "one approval cannot finalize the reviewed operation"
        );
        assert_eq!(
            wallets[0].private_spend_attempts().unwrap().len(),
            early_attempts
        );
        assert_eq!(
            wallets[0].private_treasury_template_ids(context).unwrap(),
            vec![saved_id]
        );
        let approval2_policy = signer2_template.approval_policy([1, 0, 0], 1).unwrap();
        let approval2 = prepare(
            SpendReference {
                parent_hash: block3.hash,
                parent_height: 3,
                merkle_root: wallets[1].poseidon2_v8_tip().unwrap().anchor,
                ..reference
            },
            fee,
            [
                accumulator_input(&wallets[1], &keys[1]),
                miner_input(&wallets[1], &keys[1]),
            ],
            [
                OutputRequest {
                    recipient: signers[0].clone(),
                    value: 0,
                },
                OutputRequest {
                    recipient: signers[1].clone(),
                    value: miner - fee,
                },
            ],
            SpendOperation::Approval(approval2_policy),
        )
        .unwrap();
        let (approval2_action, approval2_id) = action(&approval2, &wallets[1]);
        assert_eq!(
            wallets[1]
                .private_spend_submission_bytes_local_candidate(context, approval2_id, &token)
                .unwrap(),
            approval2_action
        );
        let block4 = Poseidon2V8CanonicalBlock {
            height: 4,
            hash: [4; 32],
            parent_hash: block3.hash,
            action_bytes: vec![approval2_action],
        };
        for wallet in &wallets {
            wallet
                .apply_private_spend_development_block(&block4, &token)
                .unwrap();
        }

        let final_reference = SpendReference {
            parent_hash: block4.hash,
            parent_height: 4,
            merkle_root: wallets[0].poseidon2_v8_tip().unwrap().anchor,
            ..reference
        };
        let final_value_view = wallets[0]
            .v8_treasury_note_view(
                descriptor.account_id,
                treasury_note.commitment,
                treasury_position,
            )
            .unwrap();
        let (final_value_input, _) =
            treasury_value_input(final_reference, &descriptor, &final_value_view).unwrap();
        let final_template = wallets[0]
            .load_private_treasury_template(context, saved_id)
            .unwrap();
        let expected_final_intent = final_template.approval_policy([1, 1, 0], 2).unwrap().intent;
        let final_spend = final_template
            .finalize(
                final_reference,
                [final_value_input, accumulator_input(&wallets[0], &keys[0])],
                [1, 1, 0],
            )
            .unwrap();
        let final_id = wallets[0]
            .reserve_private_spend(context, &final_spend)
            .unwrap();
        let final_carrier = final_spend.prove_local_candidate().unwrap();
        let final_decoded = t::decode_exact(
            t::ExpectedContext::new(
                context.chain_id(),
                relation::relation_digest()[..48].try_into().unwrap(),
            )
            .unwrap(),
            &final_carrier,
        )
        .unwrap();
        assert_eq!(final_carrier.len(), 1_931_869);
        assert_eq!(final_decoded.proof.len(), 1_926_125);
        assert_eq!(
            final_decoded.public.commitments,
            final_spend.public_statement().commitments
        );
        assert_eq!(
            final_decoded.public.ciphertext_commitments,
            final_spend.public_statement().ciphertext_commitments
        );
        let final_action = crate::poseidon2_v8_sync::encode_private_spend_candidate_action(
            context,
            &final_carrier,
        )
        .unwrap();
        wallets[0]
            .retain_private_spend_action_local_candidate(context, final_id, &final_action, &token)
            .unwrap();
        assert_eq!(
            wallets[0]
                .private_spend_submission_bytes_local_candidate(context, final_id, &token)
                .unwrap(),
            final_action
        );
        let block5 = Poseidon2V8CanonicalBlock {
            height: 5,
            hash: [5; 32],
            parent_hash: block4.hash,
            action_bytes: vec![final_action.clone()],
        };
        for wallet in &wallets {
            wallet
                .apply_private_spend_development_block(&block5, &token)
                .unwrap();
        }
        assert!(wallets[1].private_spend_notes().unwrap().iter().any(|n| n
            .opening()
            .unwrap()
            .note
            .value
            == recipient_value));
        assert!(wallets[0].private_spend_notes().unwrap().iter().any(|n| n
            .opening()
            .unwrap()
            .note
            .value
            == change_value));
        let attempts = wallets[0].private_spend_attempts().unwrap();
        let finalized = attempts.iter().find(|a| a.id == final_id).unwrap();
        assert_eq!(finalized.mined_in, Some((5, block5.hash)));
        assert!(finalized.inputs_consumed);
        assert_eq!(
            attempts
                .iter()
                .find(|a| a.id == approval1_id)
                .unwrap()
                .mined_in,
            Some((3, block3.hash))
        );
        let approval2_receipt = wallets[1]
            .private_spend_attempts()
            .unwrap()
            .into_iter()
            .find(|a| a.id == approval2_id)
            .unwrap();
        assert_eq!(approval2_receipt.mined_in, Some((4, block4.hash)));
        assert!(approval2_receipt.inputs_consumed);
        assert!(
            wallets[0]
                .v8_treasury_note_view(
                    descriptor.account_id,
                    treasury_note.commitment,
                    treasury_position
                )
                .unwrap()
                .spent
        );
        assert!(wallets[0]
            .private_spend_notes()
            .unwrap()
            .iter()
            .any(|n| n.spent
                && matches!(
                    n.opening().unwrap().state,
                    synthetic_crypto::private_note_payload::NoteState::TreasuryAccumulator(_)
                )));
        assert_eq!(
            final_spend.public_statement().intent_words().as_slice(),
            expected_final_intent.as_slice()
        );
    }
}

// Fixed handoff framing. The wallet's existing Argon2 KDF and ChaCha20-Poly1305
// are reused with fresh salt/nonce and a distinct authenticated format domain.
const HANDOFF_MAGIC: &[u8; 8] = b"HGTPH001";
const HANDOFF_HEADER: usize = 8 + SALT_LEN + NONCE_LEN + 32 + 32 + 64 + 64;
const HANDOFF_MAX_PLAIN: usize = 16_384;
fn handoff_identity(context: LaunchWalletContext) -> Vec<u8> {
    [
        context.chain_id().as_slice(),
        context.genesis_hash().as_slice(),
        context.manifest_digest().as_slice(),
        relation::relation_digest().as_slice(),
    ]
    .concat()
}
fn seal_template_handoff(
    context: LaunchWalletContext,
    plaintext: &[u8],
    passphrase: &str,
) -> Result<Vec<u8>, WalletError> {
    if passphrase.is_empty() || plaintext.len() > HANDOFF_MAX_PLAIN {
        return Err(err("invalid treasury handoff passphrase or length"));
    }
    let mut salt = [0; SALT_LEN];
    let mut nonce = [0; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| err("handoff entropy unavailable"))?;
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| err("handoff entropy unavailable"))?;
    let key = zeroize::Zeroizing::new(derive_key(passphrase, &salt)?);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| WalletError::EncryptionFailure)?;
    let mut header = Vec::with_capacity(HANDOFF_HEADER);
    header.extend(HANDOFF_MAGIC);
    header.extend(salt);
    header.extend(nonce);
    header.extend(handoff_identity(context));
    let ciphertext = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| WalletError::EncryptionFailure)?;
    header.extend(ciphertext);
    Ok(header)
}
fn open_template_handoff(
    context: LaunchWalletContext,
    bytes: &[u8],
    passphrase: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>, WalletError> {
    if passphrase.is_empty()
        || bytes.len() < HANDOFF_HEADER + 16
        || bytes.len() > HANDOFF_HEADER + HANDOFF_MAX_PLAIN + 16
        || &bytes[..8] != HANDOFF_MAGIC
    {
        return Err(err("invalid treasury handoff framing"));
    }
    let salt: [u8; SALT_LEN] = bytes[8..8 + SALT_LEN].try_into().unwrap();
    let nonce: [u8; NONCE_LEN] = bytes[8 + SALT_LEN..8 + SALT_LEN + NONCE_LEN]
        .try_into()
        .unwrap();
    if bytes[8 + SALT_LEN + NONCE_LEN..HANDOFF_HEADER] != handoff_identity(context) {
        return Err(err("treasury handoff chain, release or source mismatch"));
    }
    let key = zeroize::Zeroizing::new(derive_key(passphrase, &salt)?);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| WalletError::DecryptionFailure)?;
    cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: &bytes[HANDOFF_HEADER..],
                aad: &bytes[..HANDOFF_HEADER],
            },
        )
        .map(zeroize::Zeroizing::new)
        .map_err(|_| WalletError::DecryptionFailure)
}

const REFUND_HANDOFF_MAGIC: &[u8; 8] = b"HGHRF001";
const POLICY_HANDOFF_MAGIC: &[u8; 8] = b"HGPOL001";
#[derive(Clone, Copy)]
enum OpeningHandoff { Refund, Policy }
impl OpeningHandoff {
    fn magic(self) -> &'static [u8; 8] {
        match self { Self::Refund => REFUND_HANDOFF_MAGIC, Self::Policy => POLICY_HANDOFF_MAGIC }
    }
}
fn decode_opening_handoff(
    bytes: &[u8],
    chain: [u8; 32],
    kind: OpeningHandoff,
) -> Result<(&[u8], synthetic_crypto::private_note_payload::PrivateNotePayload), WalletError> {
    let split = 8 + relation::PUBLIC_WORDS * 8;
    if bytes.len() != split + 1024 || &bytes[..8] != kind.magic() {
        return Err(err("refund handoff framing"));
    }
    let plaintext =
        synthetic_crypto::private_note_encryption::PrivateNotePlaintext::from_bytes_exact(
            &bytes[split..],
        )
        .map_err(|_| err("refund payload length"))?;
    let payload =
        synthetic_crypto::private_note_payload::PrivateNotePayload::decode(&plaintext, chain)
            .map_err(|_| err("refund payload invalid"))?;
    match (&payload.state, kind) {
        (synthetic_crypto::private_note_payload::NoteState::Htlc(h), OpeningHandoff::Refund) if h.secret == [0;32] => (),
        (synthetic_crypto::private_note_payload::NoteState::Policy(_), OpeningHandoff::Policy) => (),
        _ => return Err(err("handoff payload kind or preimage invalid")),
    }
    Ok((&bytes[8..split], payload))
}
