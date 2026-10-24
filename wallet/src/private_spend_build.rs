//! Typed common private-spend construction. This module performs no RPC, file
//! export or submission. Callers must reserve/journal inputs before exporting.
use crate::{
    address::ShieldedAddress, poseidon2_v8_sync::LaunchWalletContext,
    private_spend::StoredPrivateSpendNote, DerivedKeys, WalletError,
};
use protocol_shielded_pool::private_spend_transport as transport;
use protocol_versioning::launch_candidate::{self, LaunchProofKind};
use rand::RngCore;
use synthetic_crypto::{
    private_note_encryption::{PrivateNoteCiphertext, PrivateNoteContext},
    private_note_payload as payload,
};
use transaction_circuit::hashing_pq::ciphertext_hash_bytes;
use transaction_circuit::{
    private_spend as relation,
    smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_from_canonical_bytes,
};
use zeroize::Zeroize;

fn invalid(s: &'static str) -> WalletError {
    WalletError::InvalidState(s)
}
const P: u64 = 0xffff_ffff_0000_0001;
struct OsEntropy(rand::rngs::OsRng);
impl rand_core09::TryRngCore for OsEntropy {
    type Error = rand::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0; 4];
        self.0.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0; 8];
        self.0.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, b: &mut [u8]) -> Result<(), Self::Error> {
        self.0.try_fill_bytes(b)
    }
}
impl rand_core09::TryCryptoRng for OsEntropy {}
fn random_words<const N: usize>(rng: &mut OsEntropy) -> Result<[u64; N], WalletError> {
    let mut out = [0; N];
    for x in &mut out {
        loop {
            let mut b = [0; 8];
            rng.0
                .try_fill_bytes(&mut b)
                .map_err(|_| invalid("OS entropy unavailable"))?;
            let n = u64::from_le_bytes(b);
            if n > 0 && n < P {
                *x = n;
                break;
            }
        }
    }
    Ok(out)
}
fn source_digest() -> [u8; 48] {
    relation::relation_digest()[..48]
        .try_into()
        .expect("digest prefix")
}

/// The two inputs must use membership paths against this same native note root.
#[derive(Clone, Copy)]
pub struct SpendReference {
    pub chain_id: [u8; 32],
    pub parent_hash: [u8; 32],
    pub parent_height: u64,
    pub merkle_root: relation::Digest,
}
/// Secret-bearing typed input. No serde or Debug implementation.
pub struct SpendInput {
    inner: relation::PrivateInput,
    chain_id: Option<[u8; 32]>,
}
impl SpendInput {
    pub fn stored(
        note: &StoredPrivateSpendNote,
        keys: &DerivedKeys,
        siblings: [relation::Digest; 32],
    ) -> Result<Self, WalletError> {
        note.validate(keys)?;
        if note.spent {
            return Err(invalid("private input already spent"));
        }
        let p = note.opening()?;
        let n = &p.note;
        Ok(Self {
            chain_id: Some(note.chain_id),
            inner: relation::PrivateInput {
                occupied: 1,
                legacy_ordinary: 0,
                note: relation::Note {
                    value: n.value,
                    asset_id: n.asset_id,
                    recipient_key: n.recipient_key,
                    authorization_key: n.authorization_key,
                    rho: n.rho,
                    randomness: n.randomness,
                },
                position: note
                    .position
                    .try_into()
                    .map_err(|_| invalid("native note position overflow"))?,
                siblings,
                spend_key: keys.spend.poseidon2_v8_words()?,
                dummy_secret: [0; 5],
            },
        })
    }
    /// Typed legacy native opening, validated by the common relation before proof.
    pub fn legacy(
        note: relation::Note,
        position: u32,
        siblings: [relation::Digest; 32],
        keys: &DerivedKeys,
        chain_id: [u8; 32],
    ) -> Result<Self, WalletError> {
        Ok(Self {
            chain_id: Some(chain_id),
            inner: relation::PrivateInput {
                occupied: 1,
                legacy_ordinary: 1,
                note,
                position,
                siblings,
                spend_key: keys.spend.poseidon2_v8_words()?,
                dummy_secret: [0; 5],
            },
        })
    }
    pub fn dummy() -> Result<Self, WalletError> {
        Ok(Self {
            chain_id: None,
            inner: relation::PrivateInput {
                dummy_secret: random_words(&mut OsEntropy(rand::rngs::OsRng))?,
                ..Default::default()
            },
        })
    }
}
fn wipe_input(i: &mut relation::PrivateInput) {
    i.spend_key.zeroize();
    i.dummy_secret.zeroize();
    i.note.rho.zeroize();
    i.note.randomness.zeroize();
    i.note.authorization_key.zeroize();
    i.note.recipient_key.zeroize();
    i.note.value.zeroize();
    i.note.asset_id.zeroize();
    i.siblings.zeroize();
    i.position.zeroize();
}
impl Drop for SpendInput {
    fn drop(&mut self) {
        wipe_input(&mut self.inner);
    }
}

/// Convert the existing allocated-reward treasury value note using its actual
/// verified mirror path. No commitment, owner, position or nullifier is rewritten.
pub fn treasury_value_input(
    reference: SpendReference,
    descriptor: &crate::poseidon2_v8_multisig::V8TreasuryDescriptor,
    view: &crate::poseidon2_v8_multisig::V8TreasuryNoteView,
) -> Result<(SpendInput, relation::TreasuryOpening), WalletError> {
    use crate::poseidon2_v8_multisig::{note_from_words, V8TreasuryNoteKind};
    use transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_note_tree_compress;
    descriptor.validate()?;
    if descriptor.chain_id != reference.chain_id
        || view.spent
        || view.reserved
        || !matches!(&view.note.kind, V8TreasuryNoteKind::Value)
        || descriptor.signer_tags[3..] != [[0; 7]; 3]
        || view.path.anchor != reference.merkle_root
        || view.path.commitment != view.note.commitment
    {
        return Err(invalid(
            "treasury source is not an available canonical value note",
        ));
    }
    let note = note_from_words(&view.note.note_words)?;
    if descriptor.receive_note(note)?.commitment != view.note.commitment {
        return Err(invalid("treasury descriptor note mismatch"));
    }
    let policy = relation::TreasuryOpening {
        policy_key: descriptor.policy_nullifier_key,
        signer_tags: descriptor.signer_tags[..3]
            .try_into()
            .expect("three signers"),
        approved: [0; 3],
        selected_signer: [0; 3],
        intent: vec![0; relation::INTENT_WORDS],
    };
    if relation::treasury_policy_root(policy.signer_tags)
        .map_err(|_| invalid("treasury policy invalid"))?
        != descriptor.policy_root
    {
        return Err(invalid("treasury policy differs from common relation"));
    }
    let owner =
        relation::treasury_value_owner(&policy).map_err(|_| invalid("treasury owner invalid"))?;
    if note.authorization_key != owner[..4] || note.randomness[..3] != owner[4..] {
        return Err(invalid("treasury value owner differs from common relation"));
    }
    let position: u32 = view
        .path
        .position
        .try_into()
        .map_err(|_| invalid("treasury position overflow"))?;
    let commitment =
        relation::note_commitment(note).map_err(|_| invalid("treasury note invalid"))?;
    if commitment != view.note.commitment
        || relation::real_nullifier(policy.policy_key, position, note)
            .map_err(|_| invalid("treasury nullifier invalid"))?
            != view.nullifier
    {
        return Err(invalid("treasury source commitment or nullifier mismatch"));
    }
    let mut root = commitment;
    for (level, sibling) in view.path.siblings.iter().copied().enumerate() {
        if sibling.iter().any(|w| *w >= P) {
            return Err(invalid("noncanonical treasury path"));
        }
        root = if position >> level & 1 == 0 {
            poseidon2_v8_note_tree_compress(root, sibling)
        } else {
            poseidon2_v8_note_tree_compress(sibling, root)
        };
    }
    if root != reference.merkle_root {
        return Err(invalid("treasury membership path mismatch"));
    }
    Ok((
        SpendInput {
            inner: relation::PrivateInput {
                occupied: 1,
                note,
                position,
                siblings: view.path.siblings,
                ..Default::default()
            },
            chain_id: Some(reference.chain_id),
        },
        policy,
    ))
}
/// Every output, including zero value, has an actual recipient encryption key.
pub struct OutputRequest {
    pub recipient: ShieldedAddress,
    pub value: u64,
}
fn recipient(a: &ShieldedAddress) -> Result<([u64; 4], relation::Digest), WalletError> {
    ShieldedAddress::from_bytes(&a.to_bytes())?;
    if a.version != crate::address::POSEIDON2_V8_ADDRESS_VERSION || a.crypto_suite != 7 {
        return Err(invalid(
            "private spend requires full native recipient authority",
        ));
    }
    let r = poseidon2_v8_words_from_canonical_bytes(a.pk_recipient)
        .map_err(|_| invalid("noncanonical recipient"))?;
    let first = poseidon2_v8_words_from_canonical_bytes(a.pk_auth)
        .map_err(|_| invalid("noncanonical authority"))?;
    let mut auth = [0; 7];
    auth[..4].copy_from_slice(&first);
    for (x, b) in auth[4..]
        .iter_mut()
        .zip(a.pk_auth_extension.chunks_exact(8))
    {
        *x = u64::from_le_bytes(b.try_into().unwrap());
        if *x >= P {
            return Err(invalid("noncanonical authority extension"));
        }
    }
    Ok((r, auth))
}
fn treasury_payload(
    t: &relation::TreasuryOpening,
) -> Result<payload::TreasuryOpening, WalletError> {
    Ok(payload::TreasuryOpening {
        policy_key: t.policy_key,
        signer_tags: t.signer_tags,
        approved: t.approved,
        selected_signer: t.selected_signer,
        intent: t
            .intent
            .as_slice()
            .try_into()
            .map_err(|_| invalid("treasury intent width"))?,
    })
}
fn htlc_payload(h: &relation::PrivateHtlcOpening) -> payload::HtlcOpening {
    payload::HtlcOpening {
        nullifier_key: h.nullifier_key,
        hashlock: h.hashlock,
        claim_authority: h.claim_authority,
        refund_authority: h.refund_authority,
        claim_recipient: h.claim_recipient,
        refund_recipient: h.refund_recipient,
        timeout: h.timeout,
        secret: [0; 32],
        release_secret: h.release_secret,
    }
}
/// Create a new private policy from complete recipient authorities, with an OS
/// generated nullifier key. The hash preimage is supplied only to a later claim.
pub fn new_htlc_policy(
    reference: SpendReference,
    claim: &ShieldedAddress,
    refund: &ShieldedAddress,
    hashlock: [u8; 32],
    timeout: u64,
) -> Result<relation::PrivateHtlcOpening, WalletError> {
    if timeout >= 1 << 48
        || reference
            .parent_height
            .checked_add(14)
            .is_none_or(|h| timeout < h)
    {
        return Err(invalid("HTLC timeout must satisfy the native lock window"));
    }
    let (claim_recipient, claim_authority) = recipient(claim)?;
    let (refund_recipient, refund_authority) = recipient(refund)?;
    Ok(relation::PrivateHtlcOpening {
        nullifier_key: random_words(&mut OsEntropy(rand::rngs::OsRng))?,
        hashlock,
        claim_authority,
        refund_authority,
        claim_recipient,
        refund_recipient,
        timeout,
        secret: [0; 32],
        release_secret: 0,
    })
}

/// Create a bounded two-branch policy with an independent OS-generated
/// nullifier key. The caller supplies public conditions, never that secret key.
pub fn new_bounded_policy(
    reference: SpendReference,
    branches: [relation::PolicyBranch; 2],
) -> Result<relation::BoundedPolicy, WalletError> {
    let policy = relation::BoundedPolicy {
        nullifier_key: random_words(&mut OsEntropy(rand::rngs::OsRng))?,
        branches,
    };
    relation::policy_owner(reference.chain_id, 0, &policy)
        .map_err(|_| invalid("invalid bounded policy"))?;
    Ok(policy)
}

pub fn bounded_policy_from_payload(policy: &payload::Policy) -> relation::BoundedPolicy {
    policy.clone()
}
/// Policy material only: the six-branch relation does not create a treasury value
/// note. Funding requires a separately authorized compatible issuance route.
pub fn new_treasury_policy(
    signers: [&ShieldedAddress; 3],
) -> Result<relation::TreasuryOpening, WalletError> {
    let mut tags = [[0; 7]; 3];
    for (tag, address) in tags.iter_mut().zip(signers) {
        *tag = recipient(address)?.1;
    }
    if tags.iter().any(|t| *t == [0; 7])
        || tags[0] == tags[1]
        || tags[0] == tags[2]
        || tags[1] == tags[2]
    {
        return Err(invalid(
            "treasury requires three distinct nonzero signer authorities",
        ));
    }
    Ok(relation::TreasuryOpening {
        policy_key: random_words(&mut OsEntropy(rand::rngs::OsRng))?,
        signer_tags: tags,
        approved: [0; 3],
        selected_signer: [0; 3],
        intent: vec![0; relation::INTENT_WORDS],
    })
}
/// Private branch selection. It is consumed in memory, never serialized publicly.
pub enum SpendOperation {
    Ordinary,
    Approval(relation::TreasuryOpening),
    HtlcLock(relation::PrivateHtlcOpening),
    HtlcClaim(relation::PrivateHtlcOpening),
    HtlcRefund(relation::PrivateHtlcOpening),
    PolicyLock(relation::BoundedPolicy),
    PolicySpend { policy: relation::BoundedPolicy, branch: usize, secret: [u8; 32] },
}
struct StoredCiphertext([u8; 2608]);
impl StoredCiphertext {
    fn as_bytes(&self) -> &[u8; 2608] {
        &self.0
    }
}
struct Outputs {
    notes: [relation::Note; 2],
    authorities: [relation::Digest; 2],
    ciphertexts: [StoredCiphertext; 2],
    commitments: [relation::Digest; 2],
    bindings: [[u8; 48]; 2],
}
impl Drop for Outputs {
    fn drop(&mut self) {
        for n in &mut self.notes {
            n.rho.zeroize();
            n.randomness.zeroize();
            n.authorization_key.zeroize();
        }
    }
}
fn encrypted_outputs(
    reference: SpendReference,
    requests: [OutputRequest; 2],
    mode: usize,
    treasury: &relation::TreasuryOpening,
    htlc: &relation::PrivateHtlcOpening,
) -> Result<Outputs, WalletError> {
    encrypted_outputs_with_policy(reference, requests, mode, treasury, htlc, &Default::default())
}
fn encrypted_outputs_with_policy(
    reference: SpendReference,
    requests: [OutputRequest; 2],
    mode: usize,
    treasury: &relation::TreasuryOpening,
    htlc: &relation::PrivateHtlcOpening,
    policy: &relation::PrivatePolicyOpening,
) -> Result<Outputs, WalletError> {
    let mut rng = OsEntropy(rand::rngs::OsRng);
    let mut notes = [relation::Note::ZERO; 2];
    let mut authorities = [[0; 7]; 2];
    let mut commitments = [[0; 7]; 2];
    let mut bindings = [[0; 48]; 2];
    let mut ciphertexts = Vec::with_capacity(2);
    for (slot, request) in requests.into_iter().enumerate() {
        let (r, auth) = recipient(&request.recipient)?;
        let state = if slot == 0 && mode == 1 {
            let mut t = treasury_payload(treasury)?;
            for j in 0..3 {
                t.approved[j] = t.approved[j]
                    .checked_add(t.selected_signer[j])
                    .ok_or(invalid("treasury approval overflow"))?;
            }
            t.selected_signer = [0; 3];
            payload::NoteState::TreasuryAccumulator(t)
        } else if slot == 0 && mode == 3 {
            payload::NoteState::Htlc(htlc_payload(htlc))
        } else if slot == 0 && policy.create == 1 {
            if !policy.output.branches.iter().any(|branch| branch.enabled == 1 && branch.authority == auth) {
                return Err(invalid("policy note recipient must control an enabled branch"));
            }
            payload::NoteState::Policy(policy.output.clone())
        } else {
            authorities[slot] = auth;
            payload::NoteState::Ordinary { authority: auth }
        };
        let mut p = payload::PrivateNotePayload {
            recipient_index: request.recipient.diversifier_index,
            note: payload::NoteOpening {
                value: request.value,
                asset_id: 0,
                recipient_key: r,
                authorization_key: [0; 4],
                rho: random_words(&mut rng)?,
                randomness: random_words(&mut rng)?,
            },
            state,
        };
        let owner = p
            .expected_owner(reference.chain_id)
            .map_err(|_| invalid("invalid private output policy"))?;
        p.note.authorization_key.copy_from_slice(&owner[..4]);
        p.note.randomness[..3].copy_from_slice(&owner[4..]);
        notes[slot] = relation::Note {
            value: p.note.value,
            asset_id: 0,
            recipient_key: r,
            authorization_key: p.note.authorization_key,
            rho: p.note.rho,
            randomness: p.note.randomness,
        };
        commitments[slot] =
            relation::note_commitment(notes[slot]).map_err(|_| invalid("invalid output note"))?;
        let mut cb = [0; 56];
        for (b, w) in cb.chunks_exact_mut(8).zip(commitments[slot]) {
            b.copy_from_slice(&w.to_le_bytes());
        }
        let context = PrivateNoteContext::new(source_digest(), reference.chain_id, slot as u8, cb)
            .map_err(|_| invalid("invalid output encryption context"))?;
        let plaintext = p
            .encode(reference.chain_id)
            .map_err(|_| invalid("invalid output payload"))?;
        let ct = PrivateNoteCiphertext::encrypt(
            &request.recipient.pk_enc,
            &context,
            &plaintext,
            &mut rng,
        )
        .map_err(|_| invalid("private output encryption failed"))?;
        bindings[slot] = ciphertext_hash_bytes(ct.as_bytes());
        ciphertexts.push(StoredCiphertext(*ct.as_bytes()));
    }
    Ok(Outputs {
        notes,
        authorities,
        commitments,
        bindings,
        ciphertexts: ciphertexts
            .try_into()
            .map_err(|_| invalid("two encrypted outputs required"))?,
    })
}
fn empty_treasury() -> relation::TreasuryOpening {
    relation::TreasuryOpening {
        intent: vec![0; relation::INTENT_WORDS],
        ..Default::default()
    }
}
fn statement(r: SpendReference, fee: u64, outputs: &Outputs) -> relation::PrivateSpendPublic {
    relation::PrivateSpendPublic {
        chain_id: r.chain_id,
        reference_parent_hash: r.parent_hash,
        reference_parent_height: r.parent_height,
        merkle_root: r.merkle_root,
        fee,
        nullifiers: [[0; 7]; 2],
        commitments: outputs.commitments,
        ciphertext_commitments: outputs.bindings,
        secret_release: 0,
        released_secret: [0; 32],
    }
}
/// Immutable encrypted final outputs and exact 54-word approval intent. Keep this
/// object in the encrypted wallet journal for a multi-process approval workflow.
/// This API does not itself persist it or create/fund a treasury value note.
pub struct TreasuryFinalTemplate {
    outputs: Outputs,
    intent: [u64; relation::INTENT_WORDS],
    policy: relation::TreasuryOpening,
    chain_id: [u8; 32],
    fee: u64,
    value_nullifier: relation::Digest,
}
impl TreasuryFinalTemplate {
    pub fn prepare(
        reference: SpendReference,
        fee: u64,
        value_input: &SpendInput,
        mut policy: relation::TreasuryOpening,
        recipients: [OutputRequest; 2],
    ) -> Result<Self, WalletError> {
        if value_input.inner.occupied != 1 || value_input.chain_id != Some(reference.chain_id) {
            return Err(invalid("treasury value input required on this chain"));
        }
        let n = value_input.inner.note;
        let expected_owner = relation::treasury_value_owner(&policy)
            .map_err(|_| invalid("invalid treasury value owner"))?;
        if reference.chain_id == [0; 32]
            || reference.parent_hash == [0; 32]
            || reference.parent_height >= 1 << 48
            || policy.policy_key[0] == 0
            || policy.signer_tags.iter().any(|t| *t == [0; 7])
            || policy.signer_tags[0] == policy.signer_tags[1]
            || policy.signer_tags[0] == policy.signer_tags[2]
            || policy.signer_tags[1] == policy.signer_tags[2]
            || n.asset_id != 0
            || n.value >= 1 << 56
            || fee >= 1 << 56
            || recipients.iter().any(|r| r.value >= 1 << 56)
            || n.authorization_key != expected_owner[..4]
            || n.randomness[..3] != expected_owner[4..]
        {
            return Err(invalid("invalid treasury value note or final payment"));
        }
        let total = recipients
            .iter()
            .try_fold(fee, |sum, r| sum.checked_add(r.value))
            .ok_or(invalid("treasury final value overflow"))?;
        if total != n.value {
            return Err(invalid("treasury final value is not conserved"));
        }
        let mut root = relation::note_commitment(n)
            .map_err(|_| invalid("invalid treasury value commitment"))?;
        for (level, sibling) in value_input.inner.siblings.iter().copied().enumerate() {
            if sibling.iter().any(|w| *w >= P) {
                return Err(invalid("noncanonical treasury final path"));
            }
            root = if value_input.inner.position >> level & 1 == 0 {
                transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_note_tree_compress(root, sibling)
            } else {
                transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_note_tree_compress(sibling, root)
            };
        }
        if root != reference.merkle_root {
            return Err(invalid("treasury final value membership mismatch"));
        }
        policy.approved = [0; 3];
        policy.selected_signer = [0; 3];
        policy.intent = vec![0; relation::INTENT_WORDS];
        let outputs = encrypted_outputs(reference, recipients, 2, &policy, &Default::default())?;
        let mut p = statement(reference, fee, &outputs);
        let value_nullifier = relation::real_nullifier(
            policy.policy_key,
            value_input.inner.position,
            value_input.inner.note,
        )
        .map_err(|_| invalid("treasury value nullifier"))?;
        p.nullifiers[0] = value_nullifier;
        let intent = p.intent_words();
        policy.intent = intent.to_vec();
        Ok(Self {
            outputs,
            intent,
            policy,
            chain_id: reference.chain_id,
            fee,
            value_nullifier,
        })
    }
    pub fn approval_policy(
        &self,
        approved: [u64; 3],
        signer: usize,
    ) -> Result<relation::TreasuryOpening, WalletError> {
        if signer >= 3 || approved.iter().any(|x| *x > 1) || approved[signer] != 0 {
            return Err(invalid("invalid or repeated treasury signer"));
        }
        let mut t = self.policy.clone();
        t.approved = approved;
        t.selected_signer = [0; 3];
        t.selected_signer[signer] = 1;
        Ok(t)
    }
    pub fn finalize(
        self,
        reference: SpendReference,
        inputs: [SpendInput; 2],
        approved: [u64; 3],
    ) -> Result<PreparedPrivateSpend, WalletError> {
        if reference.chain_id != self.chain_id {
            return Err(invalid("treasury template chain mismatch"));
        }
        let mut t = self.policy;
        t.approved = approved;
        t.selected_signer = [0; 3];
        let result = assemble(
            reference,
            self.fee,
            inputs,
            self.outputs,
            2,
            t,
            Default::default(),
        )?;
        if result.public.intent_words() != self.intent
            || result.public.nullifiers[0] != self.value_nullifier
        {
            return Err(invalid("treasury final intent changed"));
        }
        Ok(result)
    }
}
/// Build ordinary transfer, approval, lock, claim or refund through one graph.
pub fn prepare(
    reference: SpendReference,
    fee: u64,
    inputs: [SpendInput; 2],
    requests: [OutputRequest; 2],
    operation: SpendOperation,
) -> Result<PreparedPrivateSpend, WalletError> {
    let mut policy = relation::PrivatePolicyOpening::default();
    let (mode, treasury, htlc) = match operation {
        SpendOperation::Ordinary => (0, empty_treasury(), Default::default()),
        SpendOperation::Approval(t) => (1, t, Default::default()),
        SpendOperation::HtlcLock(mut h) => {
            h.secret = [0; 32];
            (3, empty_treasury(), h)
        }
        SpendOperation::HtlcClaim(h) => (4, empty_treasury(), h),
        SpendOperation::HtlcRefund(mut h) => {
            h.secret = [0; 32];
            (5, empty_treasury(), h)
        }
        SpendOperation::PolicyLock(output) => {
            policy.create = 1;
            policy.output = output;
            (0, empty_treasury(), Default::default())
        }
        SpendOperation::PolicySpend { policy: input, branch, secret } => {
            if branch >= 2 || input.branches[branch].enabled != 1 {
                return Err(invalid("bounded policy branch is not enabled"));
            }
            policy.spend = 1;
            policy.input = input;
            policy.selected[branch] = 1;
            policy.secret = secret;
            (0, empty_treasury(), Default::default())
        }
    };
    let outputs = encrypted_outputs_with_policy(reference, requests, mode, &treasury, &htlc, &policy)?;
    assemble_with_policy(reference, fee, inputs, outputs, mode, treasury, htlc, policy)
}
fn assemble(
    reference: SpendReference,
    fee: u64,
    inputs: [SpendInput; 2],
    outputs: Outputs,
    mode: usize,
    treasury: relation::TreasuryOpening,
    htlc: relation::PrivateHtlcOpening,
) -> Result<PreparedPrivateSpend, WalletError> {
    assemble_with_policy(reference, fee, inputs, outputs, mode, treasury, htlc, Default::default())
}
fn assemble_with_policy(
    reference: SpendReference,
    fee: u64,
    inputs: [SpendInput; 2],
    outputs: Outputs,
    mode: usize,
    treasury: relation::TreasuryOpening,
    htlc: relation::PrivateHtlcOpening,
    policy: relation::PrivatePolicyOpening,
) -> Result<PreparedPrivateSpend, WalletError> {
    if reference.chain_id == [0; 32] || reference.parent_hash == [0; 32] {
        return Err(invalid("private spend reference identity absent"));
    }
    for i in &inputs {
        if i.chain_id.is_some_and(|c| c != reference.chain_id) {
            return Err(invalid("private input chain mismatch"));
        }
    }
    let mut witness = relation::PrivateSpendWitness {
        selectors: [0; 6],
        inputs: inputs.each_ref().map(|i| i.inner.clone()),
        outputs: outputs.notes,
        output_authorities: outputs.authorities,
        treasury,
        htlc,
        policy,
    };
    witness.selectors[mode] = 1;
    let mut public = statement(reference, fee, &outputs);
    if mode == 4 && witness.htlc.release_secret == 1 {
        public.secret_release = 1;
        public.released_secret = witness.htlc.secret;
    } else if witness.policy.spend == 1 {
        for branch in 0..2 {
            if witness.policy.selected[branch] == 1 && witness.policy.input.branches[branch].release_secret == 1 {
                public.secret_release = 1;
                public.released_secret = witness.policy.secret;
            }
        }
    }
    for slot in 0..2 {
        let i = &mut witness.inputs[slot];
        let policy = (slot == 0 && (mode == 1 || mode == 2)) || (slot == 1 && mode == 2);
        if policy {
            i.spend_key.zeroize();
            i.legacy_ordinary = 0;
        }
        if slot == 0 && (mode == 4 || mode == 5) {
            i.legacy_ordinary = 0;
        }
        public.nullifiers[slot] = if i.occupied == 0 {
            relation::dummy_nullifier(reference.chain_id, i.dummy_secret)
        } else {
            let key = if policy {
                witness.treasury.policy_key
            } else if slot == 0 && (mode == 4 || mode == 5) {
                witness.htlc.nullifier_key
            } else if slot == 0 && witness.policy.spend == 1 {
                witness.policy.input.nullifier_key
            } else {
                i.spend_key
            };
            relation::real_nullifier(key, i.position, i.note)
        }
        .map_err(|_| invalid("private input nullifier failed"))?;
    }
    let prepared = PreparedPrivateSpend {
        public,
        witness,
        outputs,
    };
    // Independently execute the fixed relation before making a candidate available.
    let (adapter, mut packed) = relation::compile(&prepared.public, &prepared.witness)
        .map_err(|_| invalid("private spend relation rejected material"))?;
    packed.zeroize();
    drop(adapter);
    Ok(prepared)
}
/// No secret-bearing field can be read or serialized from this prepared object.
pub struct PreparedPrivateSpend {
    public: relation::PrivateSpendPublic,
    witness: relation::PrivateSpendWitness,
    outputs: Outputs,
}
impl Drop for PreparedPrivateSpend {
    fn drop(&mut self) {
        for i in &mut self.witness.inputs {
            wipe_input(i);
        }
        for n in &mut self.witness.outputs {
            n.rho.zeroize();
            n.randomness.zeroize();
            n.authorization_key.zeroize();
        }
        self.witness.treasury.policy_key.zeroize();
        self.witness.treasury.intent.zeroize();
        self.witness.htlc.nullifier_key.zeroize();
        self.witness.htlc.secret.zeroize();
        self.witness.policy.input.nullifier_key.zeroize();
        self.witness.policy.output.nullifier_key.zeroize();
        self.witness.policy.secret.zeroize();
    }
}
impl PreparedPrivateSpend {
    pub fn public_statement(&self) -> &relation::PrivateSpendPublic {
        &self.public
    }
    fn prove_exact(&self) -> Result<Vec<u8>, WalletError> {
        let proof = relation::prove_candidate(&self.public, &self.witness)
            .map_err(|_| invalid("private spend proving failed"))?;
        relation::verify_candidate(&self.public, &proof)
            .map_err(|_| invalid("private spend proof self-check failed"))?;
        Ok(proof)
    }
    fn carrier(&self, proof: &[u8]) -> Result<Vec<u8>, WalletError> {
        let p = &self.public;
        transport::encode(
            &transport::PublicStatement {
                relation_digest: source_digest(),
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
            },
            self.outputs.ciphertexts.each_ref().map(|c| c.as_bytes()),
            proof,
        )
        .map_err(|_| invalid("private spend exact carrier encoding failed"))
    }
    /// Fresh source registry lookup before proving and again at the actual proof
    /// length. The source registry currently authorizes no private-spend release.
    /// Caller must persist reservations and the returned exact bytes before RPC.
    pub fn prove_authorized(&self, context: LaunchWalletContext) -> Result<Vec<u8>, WalletError> {
        if context.chain_id() != self.public.chain_id {
            return Err(invalid("private spend launch chain mismatch"));
        }
        let height = self
            .public
            .reference_parent_height
            .checked_add(1)
            .ok_or(invalid("reference height overflow"))?;
        let require = |bytes| {
            launch_candidate::launch_proof_authority(context.request(
                LaunchProofKind::PrivateSpend,
                height,
                bytes,
            ))
            .ok_or(invalid(
                "private spend has no exact source-owned launch authority",
            ))
        };
        require(1)?;
        let proof = self.prove_exact()?;
        require(proof.len())?;
        self.carrier(&proof)
    }
    /// Explicitly local qualification path. It grants no release or RPC authority.
    #[cfg(feature = "private-spend-dev-artifacts")]
    pub fn prove_local_candidate(&self) -> Result<Vec<u8>, WalletError> {
        self.carrier(&self.prove_exact()?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keys::RootSecret;
    use synthetic_crypto::private_note_encryption::PrivateNoteCiphertextRef;
    fn keys(tag: u8) -> DerivedKeys {
        RootSecret::from_bytes([tag; 32]).derive()
    }
    fn reference() -> SpendReference {
        SpendReference {
            chain_id: [1; 32],
            parent_hash: [2; 32],
            parent_height: 100,
            merkle_root: [3; 7],
        }
    }
    fn requests(k: &DerivedKeys) -> [OutputRequest; 2] {
        [
            OutputRequest {
                recipient: k.poseidon2_v8_address(7).unwrap().shielded_address(),
                value: 90,
            },
            OutputRequest {
                recipient: k.poseidon2_v8_address(9).unwrap().shielded_address(),
                value: 0,
            },
        ]
    }
    pub(crate) fn journal_template_fixture() -> TreasuryFinalTemplate {
        let ks = [keys(71), keys(72), keys(73)];
        let addresses = ks
            .each_ref()
            .map(|k| k.poseidon2_v8_address(0).unwrap().shielded_address());
        let policy = new_treasury_policy(addresses.each_ref()).unwrap();
        let mut note = relation::Note {
            value: 100,
            asset_id: 0,
            recipient_key: [1; 4],
            authorization_key: [0; 4],
            rho: [2; 4],
            randomness: [0, 0, 0, 3],
        };
        relation::set_note_owner(&mut note, relation::treasury_value_owner(&policy).unwrap());
        let input = SpendInput {
            inner: relation::PrivateInput {
                occupied: 1,
                note,
                ..Default::default()
            },
            chain_id: Some(reference().chain_id),
        };
        let mut r = reference();
        r.merkle_root = relation::note_commitment(note).unwrap();
        for _ in 0..32 {
            r.merkle_root = transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_note_tree_compress(r.merkle_root, [0; 7]);
        }
        TreasuryFinalTemplate::prepare(r, 10, &input, policy, requests(&ks[0])).unwrap()
    }
    #[test]
    fn private_spend_both_slots_are_real_encrypted_outputs_including_zero() {
        let k = keys(21);
        let out = encrypted_outputs(
            reference(),
            requests(&k),
            0,
            &empty_treasury(),
            &Default::default(),
        )
        .unwrap();
        assert_ne!(out.ciphertexts[0].as_bytes(), out.ciphertexts[1].as_bytes());
        for (slot, index) in [7, 9].into_iter().enumerate() {
            let material = k.poseidon2_v8_address(index).unwrap();
            let mut cb = [0; 56];
            for (b, w) in cb.chunks_exact_mut(8).zip(out.commitments[slot]) {
                b.copy_from_slice(&w.to_le_bytes());
            }
            let context =
                PrivateNoteContext::new(source_digest(), reference().chain_id, slot as u8, cb)
                    .unwrap();
            let c = PrivateNoteCiphertextRef::from_bytes_exact(out.ciphertexts[slot].as_bytes())
                .unwrap();
            let plaintext = c.decrypt(material.secret_key(), &context).unwrap();
            let recovered =
                payload::PrivateNotePayload::decode(&plaintext, reference().chain_id).unwrap();
            assert_eq!(recovered.recipient_index, index);
            assert_eq!(recovered.note.value, if slot == 0 { 90 } else { 0 });
            let wrong =
                PrivateNoteContext::new(source_digest(), reference().chain_id, 1 - slot as u8, cb)
                    .unwrap();
            assert!(c.decrypt(material.secret_key(), &wrong).is_err());
        }
    }
    #[test]
    fn private_spend_treasury_approvals_preserve_prepared_final_encryption_and_intent() {
        let ks = [keys(31), keys(32), keys(33)];
        let addresses = ks
            .each_ref()
            .map(|k| k.poseidon2_v8_address(0).unwrap().shielded_address());
        let policy = new_treasury_policy(addresses.each_ref()).unwrap();
        let mut note = relation::Note {
            value: 100,
            asset_id: 0,
            recipient_key: [1; 4],
            authorization_key: [0; 4],
            rho: [2; 4],
            randomness: [0, 0, 0, 3],
        };
        relation::set_note_owner(&mut note, relation::treasury_value_owner(&policy).unwrap());
        let input = SpendInput {
            inner: relation::PrivateInput {
                occupied: 1,
                note,
                ..Default::default()
            },
            chain_id: Some(reference().chain_id),
        };
        let mut canonical_reference = reference();
        canonical_reference.merkle_root = relation::note_commitment(note).unwrap();
        for _ in 0..32 {
            canonical_reference.merkle_root = transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_note_tree_compress(canonical_reference.merkle_root, [0; 7]);
        }
        assert!(TreasuryFinalTemplate::prepare(
            reference(),
            10,
            &input,
            policy.clone(),
            requests(&ks[0])
        )
        .is_err());
        assert!(TreasuryFinalTemplate::prepare(
            canonical_reference,
            11,
            &input,
            policy.clone(),
            requests(&ks[0])
        )
        .is_err());
        let mut wrong_policy = policy.clone();
        wrong_policy.policy_key[0] += 1;
        assert!(TreasuryFinalTemplate::prepare(
            canonical_reference,
            10,
            &input,
            wrong_policy,
            requests(&ks[0])
        )
        .is_err());
        let template = TreasuryFinalTemplate::prepare(
            canonical_reference,
            10,
            &input,
            policy,
            requests(&ks[0]),
        )
        .unwrap();
        let encoded = zeroize::Zeroizing::new(template.journal_encode().unwrap());
        let restored = TreasuryFinalTemplate::journal_decode(&encoded).unwrap();
        assert_eq!(restored.intent, template.intent);
        for slot in 0..2 {
            assert_eq!(
                restored.outputs.ciphertexts[slot].as_bytes(),
                template.outputs.ciphertexts[slot].as_bytes()
            );
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(TreasuryFinalTemplate::journal_decode(&trailing).is_err());
        let a = template.approval_policy([0; 3], 0).unwrap();
        let b = template.approval_policy([1, 0, 0], 1).unwrap();
        assert_eq!(a.intent, b.intent);
        assert_eq!(a.intent.as_slice(), &template.intent);
        assert!(template.approval_policy([1, 0, 0], 0).is_err());
        let p = statement(reference(), 10, &template.outputs);
        let mut intent_p = p;
        intent_p.nullifiers[0] = template.value_nullifier;
        assert_eq!(template.intent, intent_p.intent_words());
        intent_p.fee += 1;
        assert_ne!(template.intent, intent_p.intent_words());
    }
    #[test]
    fn private_spend_existing_allocated_reward_treasury_note_converts_without_rewriting() {
        use crate::poseidon2_v8_multisig::{
            V8TreasuryDescriptor, V8TreasuryNotePath, V8TreasuryNoteView,
        };
        use rand::SeedableRng;
        use transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_note_tree_compress;
        let ks = [keys(51), keys(52), keys(53)];
        let addresses = ks
            .each_ref()
            .map(|k| k.poseidon2_v8_address(0).unwrap().shielded_address());
        let tags = addresses.each_ref().map(|a| recipient(a).unwrap().1);
        let mut rng = rand::rngs::StdRng::seed_from_u64(19);
        let descriptor =
            V8TreasuryDescriptor::create(&ks[0], reference().chain_id, tags, &mut rng).unwrap();
        let (r, owner) = recipient(&descriptor.receive_address).unwrap();
        let mut n = relation::Note {
            value: 100,
            asset_id: 0,
            recipient_key: r,
            authorization_key: [0; 4],
            rho: [7; 4],
            randomness: [0, 0, 0, 9],
        };
        relation::set_note_owner(&mut n, owner);
        let note = descriptor.receive_note(n).unwrap();
        let mut reference = reference();
        reference.merkle_root = note.commitment;
        for _ in 0..32 {
            reference.merkle_root = poseidon2_v8_note_tree_compress(reference.merkle_root, [0; 7]);
        }
        let mut view = V8TreasuryNoteView {
            path: V8TreasuryNotePath {
                commitment: note.commitment,
                position: 0,
                siblings: [[0; 7]; 32],
                anchor: reference.merkle_root,
            },
            note,
            nullifier: relation::real_nullifier(descriptor.policy_nullifier_key, 0, n).unwrap(),
            spent: false,
            reserved: false,
        };
        let (converted, policy) = treasury_value_input(reference, &descriptor, &view).unwrap();
        assert_eq!(converted.inner.note.rho, n.rho);
        assert_eq!(
            relation::note_commitment(converted.inner.note).unwrap(),
            view.note.commitment
        );
        assert_eq!(policy.policy_key, descriptor.policy_nullifier_key);
        view.path.siblings[0][0] = 1;
        assert!(treasury_value_input(reference, &descriptor, &view).is_err());
    }
    #[test]
    fn private_spend_lock_policy_has_real_authorities_and_never_embeds_preimage() {
        let k = keys(42);
        let c = k.poseidon2_v8_address(1).unwrap().shielded_address();
        let r = k.poseidon2_v8_address(2).unwrap().shielded_address();
        let h = new_htlc_policy(reference(), &c, &r, [8; 32], 120).unwrap();
        assert_eq!(h.claim_authority, recipient(&c).unwrap().1);
        assert_eq!(h.refund_recipient, recipient(&r).unwrap().0);
        assert_eq!(h.secret, [0; 32]);
        assert!(new_htlc_policy(reference(), &c, &r, [8; 32], 113).is_err());
        assert!(new_treasury_policy([&c, &c, &r]).is_err());
    }
}

// This codec is only consumed inside the encrypted WalletStore. No public secret
// export API, spend key, input credential or complete witness is serialized.
#[derive(serde::Serialize, serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct TemplateSnapshot {
    version: u32,
    source: Vec<u8>,
    chain: [u8; 32],
    fee: u64,
    value_nullifier: [u64; 7],
    policy_key: [u64; 5],
    tags: [[u64; 7]; 3],
    intent: Vec<u64>,
    notes: [Vec<u64>; 2],
    authorities: [[u64; 7]; 2],
    ciphertexts: [Vec<u8>; 2],
}
impl TreasuryFinalTemplate {
    pub(crate) fn journal_encode(&self) -> Result<Vec<u8>, WalletError> {
        let snapshot = TemplateSnapshot {
            version: 1,
            source: relation::relation_digest().to_vec(),
            chain: self.chain_id,
            fee: self.fee,
            value_nullifier: self.value_nullifier,
            policy_key: self.policy.policy_key,
            tags: self.policy.signer_tags,
            intent: self.intent.to_vec(),
            notes: self
                .outputs
                .notes
                .map(crate::poseidon2_v8_multisig::note_to_words),
            authorities: self.outputs.authorities,
            ciphertexts: self
                .outputs
                .ciphertexts
                .each_ref()
                .map(|c| c.as_bytes().to_vec()),
        };
        Ok(bincode::serialize(&snapshot)?)
    }
    pub(crate) fn journal_decode(bytes: &[u8]) -> Result<Self, WalletError> {
        use bincode::Options;
        if bytes.len() > 16_384 {
            return Err(invalid("private template exceeds fixed codec bound"));
        }
        let s: TemplateSnapshot = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(16_384)
            .reject_trailing_bytes()
            .deserialize(bytes)?;
        if s.version != 1
            || s.source != relation::relation_digest()
            || s.chain == [0; 32]
            || s.fee >= 1 << 56
            || s.policy_key[0] == 0
            || s.intent.len() != relation::INTENT_WORDS
            || s.tags.iter().any(|t| *t == [0; 7])
            || s.tags[0] == s.tags[1]
            || s.tags[0] == s.tags[2]
            || s.tags[1] == s.tags[2]
        {
            return Err(invalid("private template identity or policy changed"));
        }
        let notes = [
            crate::poseidon2_v8_multisig::note_from_words(&s.notes[0])?,
            crate::poseidon2_v8_multisig::note_from_words(&s.notes[1])?,
        ];
        let mut commitments = [[0; 7]; 2];
        let mut bindings = [[0; 48]; 2];
        let mut ciphertexts = Vec::new();
        for i in 0..2 {
            let owner = relation::ordinary_owner(s.authorities[i])
                .map_err(|_| invalid("template recipient invalid"))?;
            if notes[i].asset_id != 0
                || notes[i].value >= 1 << 56
                || notes[i].authorization_key != owner[..4]
                || notes[i].randomness[..3] != owner[4..]
            {
                return Err(invalid("template note owner changed"));
            }
            commitments[i] = relation::note_commitment(notes[i])
                .map_err(|_| invalid("template note invalid"))?;
            let ct: [u8; 2608] = s.ciphertexts[i]
                .as_slice()
                .try_into()
                .map_err(|_| invalid("template ciphertext width"))?;
            bindings[i] = ciphertext_hash_bytes(&ct);
            ciphertexts.push(StoredCiphertext(ct));
        }
        let outputs = Outputs {
            notes,
            authorities: s.authorities,
            commitments,
            bindings,
            ciphertexts: ciphertexts
                .try_into()
                .map_err(|_| invalid("template output count"))?,
        };
        let policy = relation::TreasuryOpening {
            policy_key: s.policy_key,
            signer_tags: s.tags,
            approved: [0; 3],
            selected_signer: [0; 3],
            intent: s.intent.clone(),
        };
        relation::treasury_value_owner(&policy)
            .map_err(|_| invalid("template policy is noncanonical"))?;
        let mut p = statement(
            SpendReference {
                chain_id: s.chain,
                parent_hash: [1; 32],
                parent_height: 0,
                merkle_root: [0; 7],
            },
            s.fee,
            &outputs,
        );
        p.nullifiers[0] = s.value_nullifier;
        let intent = p.intent_words();
        if s.intent != intent {
            return Err(invalid("stored final ciphertext or intent changed"));
        }
        Ok(Self {
            outputs,
            intent,
            policy,
            chain_id: s.chain,
            fee: s.fee,
            value_nullifier: s.value_nullifier,
        })
    }
    pub(crate) fn journal_chain(&self) -> [u8; 32] {
        self.chain_id
    }
}

impl PreparedPrivateSpend {
    pub(crate) fn journal_inputs(
        &self,
    ) -> Result<Vec<crate::store::private_spend_journal::PrivateReservedInput>, WalletError> {
        let mut inputs = Vec::new();
        for (slot, i) in self.witness.inputs.iter().enumerate() {
            if i.occupied == 1 {
                inputs.push(crate::store::private_spend_journal::PrivateReservedInput {
                    commitment: relation::note_commitment(i.note)
                        .map_err(|_| invalid("private input commitment invalid"))?,
                    nullifier: self.public.nullifiers[slot],
                    position: u64::from(i.position),
                });
            }
        }
        Ok(inputs)
    }
}

impl PreparedPrivateSpend {
    /// Exact policy opening for encrypted custody handoff to another enabled
    /// controller. The shared nullifier credential never leaves encryption.
    pub(crate) fn policy_handoff_plaintext(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, WalletError> {
        if self.witness.selectors != [1, 0, 0, 0, 0, 0] || self.witness.policy.create != 1 {
            return Err(invalid("policy handoff requires prepared policy lock"));
        }
        let n = self.witness.outputs[0];
        let p = payload::PrivateNotePayload {
            recipient_index: 0,
            note: payload::NoteOpening {
                value: n.value, asset_id: n.asset_id, recipient_key: n.recipient_key,
                authorization_key: n.authorization_key, rho: n.rho, randomness: n.randomness,
            },
            state: payload::NoteState::Policy(self.witness.policy.output.clone()),
        };
        let plaintext = p.encode(self.public.chain_id).map_err(|_| invalid("policy handoff encoding"))?;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        bytes.extend(b"HGPOL001");
        bytes.extend(self.public.binding_bytes());
        bytes.extend(plaintext.as_bytes());
        Ok(bytes)
    }
    /// Exact generated lock opening, for encrypted custody handoff only. Address
    /// index is local recovery metadata and is normalized by the refund wallet.
    pub(crate) fn refund_handoff_plaintext(
        &self,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, WalletError> {
        if self.witness.selectors != [0, 0, 0, 1, 0, 0] {
            return Err(invalid("refund handoff requires prepared HTLC lock"));
        }
        let n = self.witness.outputs[0];
        let p = payload::PrivateNotePayload {
            recipient_index: 0,
            note: payload::NoteOpening {
                value: n.value,
                asset_id: n.asset_id,
                recipient_key: n.recipient_key,
                authorization_key: n.authorization_key,
                rho: n.rho,
                randomness: n.randomness,
            },
            state: payload::NoteState::Htlc(htlc_payload(&self.witness.htlc)),
        };
        let plaintext = p
            .encode(self.public.chain_id)
            .map_err(|_| invalid("refund handoff policy encoding"))?;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        bytes.extend(b"HGHRF001");
        bytes.extend(self.public.binding_bytes());
        bytes.extend(plaintext.as_bytes());
        Ok(bytes)
    }
}

#[cfg(test)]
mod distinct_refund_relation_tests {
    use super::*;
    #[test]
    fn private_spend_distinct_refund_builds_common_relation_with_local_refund_credential() {
        use transaction_circuit::smallwood_poseidon2_v8_coinbase::{
            poseidon2_v8_note_tree_compress as merkle,
            poseidon2_v8_single_key_authorization_digest as single,
        };
        let (_, refund, mut p, h) = crate::private_spend::refund_custody_tests::fixture();
        p.recipient_index = 9;
        let n = &p.note;
        let lock = relation::Note {
            value: n.value,
            asset_id: n.asset_id,
            recipient_key: n.recipient_key,
            authorization_key: n.authorization_key,
            rho: n.rho,
            randomness: n.randomness,
        };
        let mut fee = relation::Note {
            value: 10,
            asset_id: 0,
            recipient_key: [1; 4],
            authorization_key: [0; 4],
            rho: [7; 4],
            randomness: [0, 0, 0, 8],
        };
        relation::set_note_owner(
            &mut fee,
            single(refund.spend.poseidon2_v8_words().unwrap()).unwrap(),
        );
        let leaves = [
            relation::note_commitment(lock).unwrap(),
            relation::note_commitment(fee).unwrap(),
        ];
        let mut root = merkle(leaves[0], leaves[1]);
        for _ in 1..32 {
            root = merkle(root, [0; 7]);
        }
        let mut paths = [[[0; 7]; 32]; 2];
        paths[0][0] = leaves[1];
        paths[1][0] = leaves[0];
        let stored = crate::private_spend::StoredPrivateSpendNote::new(
            crate::private_spend::RecoveredPrivateSpendNote {
                address_index: 9,
                payload: p,
            },
            &refund,
            [1; 32],
            leaves[0],
            0,
            101,
            [8; 32],
        )
        .unwrap();
        let inputs = [
            SpendInput::stored(&stored, &refund, paths[0]).unwrap(),
            SpendInput::legacy(fee, 1, paths[1], &refund, [1; 32]).unwrap(),
        ];
        let outputs = [
            OutputRequest {
                recipient: refund.poseidon2_v8_address(9).unwrap().shielded_address(),
                value: 100,
            },
            OutputRequest {
                recipient: refund.poseidon2_v8_address(10).unwrap().shielded_address(),
                value: 0,
            },
        ];
        let prepared = prepare(
            SpendReference {
                chain_id: [1; 32],
                parent_hash: [2; 32],
                parent_height: 120,
                merkle_root: root,
            },
            10,
            inputs,
            outputs,
            SpendOperation::HtlcRefund(h),
        )
        .unwrap();
        assert_eq!(prepared.public_statement().nullifiers[0], stored.nullifier);
    }
}

#[cfg(test)]
mod bounded_policy_wallet_tests {
    use super::*;
    use transaction_circuit::smallwood_poseidon2_v8_coinbase::{
        poseidon2_v8_note_tree_compress as merkle,
        poseidon2_v8_single_key_authorization_digest as single,
    };
    fn reference(note: relation::Note, height: u64) -> SpendReference {
        let mut root = relation::note_commitment(note).unwrap();
        for _ in 0..32 { root = merkle(root, [0; 7]); }
        SpendReference { chain_id: [1; 32], parent_hash: [2; 32], parent_height: height, merkle_root: root }
    }
    fn outputs(keys: &DerivedKeys, value: u64) -> [OutputRequest; 2] {
        [OutputRequest { recipient: keys.poseidon2_v8_address(7).unwrap().shielded_address(), value },
         OutputRequest { recipient: keys.poseidon2_v8_address(9).unwrap().shielded_address(), value: 0 }]
    }
    #[test]
    fn private_policy_wallet_lock_handoff_and_releasing_branch_use_exact_relation() {
        use sha2::{Digest as _, Sha256};
        let first = crate::RootSecret::from_bytes([111; 32]).derive();
        let second = crate::RootSecret::from_bytes([112; 32]).derive();
        let secret = [9; 32];
        let branches = [
            relation::PolicyBranch { enabled: 1, authority: single(first.spend.poseidon2_v8_words().unwrap()).unwrap(), not_before: 100, ..Default::default() },
            relation::PolicyBranch { enabled: 1, authority: single(second.spend.poseidon2_v8_words().unwrap()).unwrap(), not_before: 101,
                hash_required: 1, hashlock: Sha256::digest(secret).into(), release_secret: 1 },
        ];
        let mut initial = relation::Note { value: 110, asset_id: 0, recipient_key: [1; 4], authorization_key: [0; 4], rho: [4; 4], randomness: [0, 0, 0, 8] };
        relation::set_note_owner(&mut initial, single(first.spend.poseidon2_v8_words().unwrap()).unwrap());
        let policy = new_bounded_policy(reference(initial, 100), branches).unwrap();
        let lock = prepare(reference(initial, 100), 10,
            [SpendInput::legacy(initial, 0, [[0; 7]; 32], &first, [1; 32]).unwrap(), SpendInput::dummy().unwrap()],
            outputs(&first, 100), SpendOperation::PolicyLock(policy.clone())).unwrap();
        assert_eq!(lock.public_statement().secret_release, 0);
        assert_eq!(lock.public_statement().released_secret, [0; 32]);
        let handoff = lock.policy_handoff_plaintext().unwrap();
        assert_eq!(&handoff[..8], b"HGPOL001");
        let split = 8 + relation::PUBLIC_WORDS * 8;
        assert_eq!(&handoff[8..split], lock.public_statement().binding_bytes());
        let plaintext = synthetic_crypto::private_note_encryption::PrivateNotePlaintext::from_bytes_exact(&handoff[split..]).unwrap();
        let mut payload = payload::PrivateNotePayload::decode(&plaintext, [1; 32]).unwrap();
        assert!(matches!(&payload.state, payload::NoteState::Policy(p) if p == &policy));
        payload.recipient_index = 9;
        let locked = lock.witness.outputs[0];
        let stored = StoredPrivateSpendNote::new(crate::private_spend::RecoveredPrivateSpendNote { address_index: 9, payload },
            &second, [1; 32], relation::note_commitment(locked).unwrap(), 0, 101, [3; 32]).unwrap();
        let spend = |height, preimage| prepare(reference(locked, height), 10,
            [SpendInput::stored(&stored, &second, [[0; 7]; 32]).unwrap(), SpendInput::dummy().unwrap()],
            outputs(&second, 90), SpendOperation::PolicySpend { policy: policy.clone(), branch: 1, secret: preimage });
        assert!(spend(100, secret).is_err());
        assert!(spend(101, [8; 32]).is_err());
        let released = spend(101, secret).unwrap();
        assert_eq!(released.public_statement().nullifiers[0], stored.nullifier);
        assert_eq!(released.public_statement().secret_release, 1);
        assert_eq!(released.public_statement().released_secret, secret);
        assert!(released.policy_handoff_plaintext().is_err());
    }
    #[test]
    fn private_htlc_release_is_opt_in_and_changes_the_committed_owner() {
        let (_, _, payload, mut policy) = crate::private_spend::refund_custody_tests::fixture();
        assert_eq!(policy.release_secret, 0);
        assert_eq!(htlc_payload(&policy).release_secret, 0);
        let old = payload.expected_owner([1; 32]).unwrap();
        policy.release_secret = 1;
        let mut changed = payload;
        changed.state = payload::NoteState::Htlc(htlc_payload(&policy));
        let new_owner = changed.expected_owner([1; 32]).unwrap();
        assert_ne!(old, new_owner);
        changed.note.authorization_key.copy_from_slice(&new_owner[..4]);
        changed.note.randomness[..3].copy_from_slice(&new_owner[4..]);
        let plaintext = changed.encode([1; 32]).unwrap();
        let decoded = payload::PrivateNotePayload::decode(&plaintext, [1; 32]).unwrap();
        assert!(matches!(&decoded.state, payload::NoteState::Htlc(h) if h.release_secret == 1 && h.secret == [0; 32]));
    }
}
