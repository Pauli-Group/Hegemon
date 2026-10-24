//! Explicit opt-in construction and holder-journal orchestration.
//! Callers authenticate the current descriptor/controls/credentials and note
//! reference. Persistent helpers reserve global inputs before any capsule/spend
//! proof, retain exact bytes before export, and preserve uncertain submissions.
//! Delegate/archive construction remains separate from holder-wallet persistence.
//! Archive providers receive note material, never ordinary holder spend keys.
//! Capsule transport is isolated here; encryption/proof privacy and archive
//! availability remain separate, unclosed cryptographic/system obligations.
#![forbid(unsafe_code)]

use crate::{
    asset_recovery_v1::{
        generate_shared_nf_key, RecoveryNoteContextV1, RecoveryNoteMaterialV1,
        RecoveryNotePlaintextV1,
    },
    asset_spend_v1::AssetNotePayload,
    WalletError,
};
use rand::RngCore;
use rand_core09::TryCryptoRng;
use synthetic_crypto::{
    asset_note_encryption_v1::{
        AssetNoteCiphertext, AssetNoteCiphertextRef, AssetNoteContext, AssetNotePlaintext,
    },
    ml_kem::{MlKemPublicKey, MlKemSecretKey},
    private_note_payload::NoteOpening,
};
use transaction_circuit::{
    asset_recovery_capsule_v1 as capsule, asset_recovery_spend_v1 as spend,
    asset_recovery_v1 as recovery, asset_recovery_wire_v1 as wire,
    asset_spend_v1::{AssetCredentialWitness, AssetSpendWitness, MINT},
    hashing_pq::ciphertext_hash_bytes,
    private_spend::{self, Digest, Note, PrivateInput},
};
use zeroize::{Zeroize, Zeroizing};

fn invalid(s: &'static str) -> WalletError {
    WalletError::InvalidState(s)
}
fn source_digest() -> [u8; 48] {
    spend::relation_digest()[..48].try_into().unwrap()
}
fn commitment_bytes(d: Digest) -> [u8; 56] {
    core::array::from_fn(|i| d[i / 8].to_le_bytes()[i % 8])
}
fn context(
    chain: [u8; 32],
    asset: u32,
    policy: Digest,
    note: Note,
) -> Result<RecoveryNoteContextV1, WalletError> {
    Ok(RecoveryNoteContextV1 {
        chain_id: chain,
        asset_id: asset,
        stable_policy_id: policy,
        output_commitment: private_spend::note_commitment(note)
            .map_err(|_| invalid("recovery note commitment"))?,
    })
}
fn encryption_context(public: &spend::Public, slot: u8) -> Result<AssetNoteContext, WalletError> {
    if slot > 2 {
        return Err(invalid("recovery output slot"));
    }
    AssetNoteContext::new(
        source_digest(),
        public.base.chain_id,
        slot,
        commitment_bytes(public.base.commitments[slot as usize]),
    )
    .map_err(|_| invalid("recovery output encryption context"))
}

/// Caller RNG supplies fresh independent rho, remaining randomness and shared
/// nullifier key. No holder spending secret is accepted or derived here.
pub fn new_recovery_output<R: TryCryptoRng + ?Sized>(
    chain: [u8; 32],
    asset: u32,
    policy: Digest,
    value: u64,
    recipient: [u64; 4],
    holder_authority: Digest,
    rng: &mut R,
) -> Result<RecoveryNoteMaterialV1, WalletError> {
    let shared = generate_shared_nf_key(rng)?;
    let rho = random_fields::<4, R>(rng)?;
    let random = random_fields::<1, R>(rng)?;
    let owner = recovery::recovery_owner(chain, asset, policy, holder_authority, *shared)
        .map_err(|_| invalid("recovery output owner"))?;
    let mut material = RecoveryNoteMaterialV1 {
        note: NoteOpening {
            value,
            asset_id: asset as u64,
            recipient_key: recipient,
            authorization_key: owner[..4].try_into().unwrap(),
            rho: *rho,
            randomness: [owner[4], owner[5], owner[6], random[0]],
        },
        holder_authority,
        shared_nf_key: *shared,
        stable_policy_id: policy,
    };
    if let Err(e) =
        context(chain, asset, policy, material.as_note()).and_then(|c| material.validate(&c))
    {
        material.zeroize();
        return Err(e);
    }
    Ok(material)
}
fn random_fields<const N: usize, R: TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<Zeroizing<[u64; N]>, WalletError> {
    let mut words = Zeroizing::new([0; N]);
    for word in words.iter_mut() {
        loop {
            let mut bytes = Zeroizing::new([0u8; 8]);
            rng.try_fill_bytes(&mut bytes[..])
                .map_err(|_| invalid("recovery output entropy unavailable"))?;
            let n = u64::from_le_bytes(*bytes);
            if n < hegemon_field::GOLDILOCKS_MODULUS {
                *word = n;
                break;
            }
        }
    }
    Ok(words)
}

/// Fixed1024 ARN1 payload into the existing2608-byte ML-KEM/AEAD carrier.
/// This authenticates delivery context, not current policy or inclusion.
pub fn encrypt_holder_output<R: TryCryptoRng + ?Sized>(
    public: &spend::Public,
    slot: u8,
    material: &RecoveryNoteMaterialV1,
    recipient: &MlKemPublicKey,
    rng: &mut R,
) -> Result<AssetNoteCiphertext, WalletError> {
    if slot > 1 {
        return Err(invalid("recovery holder output slot"));
    }
    let ctx = RecoveryNoteContextV1 {
        chain_id: public.base.chain_id,
        asset_id: public.base.asset_id,
        stable_policy_id: public.row.descriptor.stable_policy_id,
        output_commitment: public.base.commitments[slot as usize],
    };
    let plain = material.encode(&ctx)?;
    let plain = AssetNotePlaintext::from_bytes_exact(plain.as_bytes())
        .map_err(|_| invalid("recovery plaintext width"))?;
    AssetNoteCiphertext::encrypt(recipient, &encryption_context(public, slot)?, &plain, rng)
        .map_err(|_| invalid("recovery holder encryption failed"))
}
pub fn encrypt_native_fee_change<R: TryCryptoRng + ?Sized>(
    public: &spend::Public,
    material: &AssetNotePayload,
    recipient: &MlKemPublicKey,
    rng: &mut R,
) -> Result<AssetNoteCiphertext, WalletError> {
    if private_spend::note_commitment(material.as_note()).ok() != Some(public.base.commitments[2]) {
        return Err(invalid("recovery native fee output commitment"));
    }
    let plain = material.encode(public.base.chain_id, 0)?;
    AssetNoteCiphertext::encrypt(recipient, &encryption_context(public, 2)?, &plain, rng)
        .map_err(|_| invalid("recovery fee change encryption failed"))
}

/// Provider request intentionally excludes all spend/issuer/delegate secrets.
/// It exposes recoverable material to the explicitly selected archive custodian.
pub struct ArchiveCapsuleRequestV1<'a> {
    pub descriptor: &'a recovery::RecoveryDescriptorV1,
    pub context: RecoveryNoteContextV1,
    pub material: &'a RecoveryNoteMaterialV1,
}
/// Opaque, actually verified capsule. Centralizes the current one-proof format.
/// A future segmented codec must replace this transport and wire atomically.
pub struct CapsuleTransportV1 {
    public: capsule::AssetRecoveryCapsulePublicV1,
    proof: Vec<u8>,
}
fn capsule_matches(
    request: &ArchiveCapsuleRequestV1<'_>,
    public: &capsule::AssetRecoveryCapsulePublicV1,
) -> Result<(), WalletError> {
    request
        .descriptor
        .validate()
        .map_err(|_| invalid("recovery archive descriptor"))?;
    request.material.validate(&request.context)?;
    if public.chain_id != request.context.chain_id
        || public.asset_id != request.context.asset_id
        || public.stable_policy_id != request.context.stable_policy_id
        || public.note_commitment != request.context.output_commitment
        || public.archive_key_commitment != request.descriptor.archive_key_commitment
        || request.descriptor.asset_id != request.context.asset_id
        || request.descriptor.stable_policy_id != request.context.stable_policy_id
    {
        return Err(invalid("recovery archive response binding"));
    }
    Ok(())
}
impl CapsuleTransportV1 {
    pub fn from_untrusted(
        request: &ArchiveCapsuleRequestV1<'_>,
        public: capsule::AssetRecoveryCapsulePublicV1,
        proof: Vec<u8>,
    ) -> Result<Self, WalletError> {
        capsule_matches(request, &public)?;
        capsule::verify(&public, &proof)
            .map_err(|_| invalid("recovery archive capsule proof rejected"))?;
        Ok(Self { public, proof })
    }
    pub fn public_statement(&self) -> &capsule::AssetRecoveryCapsulePublicV1 {
        &self.public
    }
    pub fn proof_bytes(&self) -> &[u8] {
        &self.proof
    }
}
pub trait ArchiveCapsuleProviderV1 {
    fn create_capsule(
        &mut self,
        request: &ArchiveCapsuleRequestV1<'_>,
    ) -> Result<CapsuleTransportV1, WalletError>;
}
pub struct LocalArchiveProviderV1 {
    secret: Zeroizing<[u8; 32]>,
}
impl LocalArchiveProviderV1 {
    pub fn new(secret: Zeroizing<[u8; 32]>) -> Self {
        Self { secret }
    }
}
struct CapsuleWitness(capsule::AssetRecoveryCapsuleWitnessV1);
impl Drop for CapsuleWitness {
    fn drop(&mut self) {
        self.0.archive_secret.zeroize();
        self.0.material.zeroize();
    }
}
impl ArchiveCapsuleProviderV1 for LocalArchiveProviderV1 {
    fn create_capsule(
        &mut self,
        request: &ArchiveCapsuleRequestV1<'_>,
    ) -> Result<CapsuleTransportV1, WalletError> {
        let words = request.material.material_words(&request.context)?;
        let public = capsule::encrypt(
            request.context.chain_id,
            request.context.asset_id,
            request.context.stable_policy_id,
            &self.secret,
            &words,
        )
        .map_err(|_| invalid("recovery archive capsule encryption failed"))?;
        capsule_matches(request, &public)?;
        let witness = CapsuleWitness(capsule::AssetRecoveryCapsuleWitnessV1 {
            archive_secret: *self.secret,
            material: *words,
        });
        let proof = capsule::prove(&public, &witness.0)
            .map_err(|_| invalid("recovery archive capsule proving failed"))?;
        CapsuleTransportV1::from_untrusted(request, public, proof)
    }
}
/// The archive holder can recover material for a currently authorized actor.
/// This does not give the archive key current delegate spending authority.
pub fn decrypt_archive_material(
    public: &capsule::AssetRecoveryCapsulePublicV1,
    secret: &[u8; 32],
) -> Result<RecoveryNoteMaterialV1, WalletError> {
    let words = Zeroizing::new(
        capsule::decrypt(public, secret)
            .map_err(|_| invalid("recovery archive decryption failed"))?,
    );
    RecoveryNoteMaterialV1::from_material_words(
        &words,
        &RecoveryNoteContextV1 {
            chain_id: public.chain_id,
            asset_id: public.asset_id,
            stable_policy_id: public.stable_policy_id,
            output_commitment: public.note_commitment,
        },
    )
}

/// Ownership secrets remain in this authorization value and the local prover.
pub enum RecoveryAuthorizationV1<'a> {
    Mint {
        dummy_secret: Zeroizing<[u64; 5]>,
        issuer_secret: Zeroizing<Digest>,
    },
    Holder {
        material: &'a RecoveryNoteMaterialV1,
        position: u32,
        siblings: [Digest; 32],
        freeze_siblings: [Digest; 32],
        spend_key: Zeroizing<[u64; 5]>,
    },
    Delegate {
        material: &'a RecoveryNoteMaterialV1,
        position: u32,
        siblings: [Digest; 32],
        freeze_siblings: [Digest; 32],
        delegate_secret: Zeroizing<Digest>,
        credential_recipient: [u64; 4],
    },
}
impl Drop for RecoveryAuthorizationV1<'_> {
    fn drop(&mut self) {
        match &mut *self {
            Self::Holder {
                position,
                siblings,
                freeze_siblings,
                ..
            }
            | Self::Delegate {
                position,
                siblings,
                freeze_siblings,
                ..
            } => {
                position.zeroize();
                siblings.zeroize();
                freeze_siblings.zeroize();
            }
            Self::Mint { .. } => {}
        }
        if let Self::Delegate {
            credential_recipient,
            ..
        } = &mut *self
        {
            credential_recipient.zeroize();
        }
        // Key fields are Zeroizing and borrowed material remains caller-owned.
    }
}
pub struct NativeFeeInputV1 {
    input: PrivateInput,
}
impl NativeFeeInputV1 {
    pub fn new(input: PrivateInput) -> Result<Self, WalletError> {
        let value = Self { input };
        if value.input.occupied != 1 || value.input.note.asset_id != 0 {
            return Err(invalid("recovery fee needs real native input"));
        }
        Ok(value)
    }
}
impl Drop for NativeFeeInputV1 {
    fn drop(&mut self) {
        wipe_input(&mut self.input);
    }
}
pub struct RecoverySpendConstructionV1<'a> {
    /// Authenticated current row/reference/registry context; no source authority
    /// is manufactured by accepting this public value in a pure constructor.
    pub public: spend::Public,
    pub authorization: RecoveryAuthorizationV1<'a>,
    pub native_fee_input: NativeFeeInputV1,
    pub outputs: [&'a RecoveryNoteMaterialV1; 2],
    pub native_fee_change: &'a AssetNotePayload,
    /// Current selected-actor, recipient, change paths; depth4 only.
    pub credentials: [AssetCredentialWitness; 3],
}
struct SpendWitness(spend::Witness);
impl Drop for SpendWitness {
    fn drop(&mut self) {
        let w = &mut self.0;
        for input in &mut w.base.inputs {
            wipe_input(input);
        }
        for note in &mut w.base.outputs {
            wipe_note(note);
        }
        w.base.output_authorities.zeroize();
        w.base.issuer_secret.zeroize();
        for c in &mut w.base.credentials {
            c.index.zeroize();
            c.expires_at.zeroize();
            c.siblings.zeroize();
        }
        w.base.policy.create.zeroize();
        w.base.policy.spend.zeroize();
        for p in [&mut w.base.policy.input, &mut w.base.policy.output] {
            p.nullifier_key.zeroize();
            for b in &mut p.branches {
                b.enabled.zeroize();
                b.authority.zeroize();
                b.not_before.zeroize();
                b.hash_required.zeroize();
                b.hashlock.zeroize();
                b.release_secret.zeroize();
            }
        }
        w.base.policy.selected.zeroize();
        w.base.policy.secret.zeroize();
        w.input_holder_authority.zeroize();
        w.input_shared_nf_key.zeroize();
        w.output_shared_nf_keys.zeroize();
        w.delegate_secret.zeroize();
        w.use_delegate.zeroize();
        w.delegate_credential_recipient.zeroize();
        w.note_freeze_siblings.zeroize();
    }
}
fn wipe_input(input: &mut PrivateInput) {
    input.occupied.zeroize();
    input.legacy_ordinary.zeroize();
    input.position.zeroize();
    input.siblings.zeroize();
    input.spend_key.zeroize();
    input.dummy_secret.zeroize();
    wipe_note(&mut input.note);
}
fn wipe_note(note: &mut Note) {
    note.value.zeroize();
    note.asset_id.zeroize();
    note.recipient_key.zeroize();
    note.authorization_key.zeroize();
    note.rho.zeroize();
    note.randomness.zeroize();
}

pub struct PreparedRecoverySpendV1 {
    public: spend::Public,
    witness: SpendWitness,
    ciphertexts: [AssetNoteCiphertext; 3],
    capsules: [CapsuleTransportV1; 2],
}
impl PreparedRecoverySpendV1 {
    pub fn public_statement(&self) -> &spend::Public {
        &self.public
    }
    pub fn ciphertexts(&self) -> &[AssetNoteCiphertext; 3] {
        &self.ciphertexts
    }
    pub fn capsules(&self) -> &[CapsuleTransportV1; 2] {
        &self.capsules
    }
    /// Actual proof and independent verifier, then exact wire encode/readback.
    /// Caller must have durable reservations before exporting the returned body.
    pub fn prove_and_encode(&self) -> Result<RecoverySpendArtifactV1, WalletError> {
        let proof = spend::prove_candidate(&self.public, &self.witness.0)
            .map_err(|_| invalid("recovery spend proving failed"))?;
        spend::verify_candidate(&self.public, &proof)
            .map_err(|_| invalid("recovery spend proof self-check failed"))?;
        let ciphertexts = core::array::from_fn(|i| *self.ciphertexts[i].as_bytes());
        let body = wire::encode_spend(
            &self.public,
            &ciphertexts,
            &proof,
            [
                (&self.capsules[0].public, &self.capsules[0].proof),
                (&self.capsules[1].public, &self.capsules[1].proof),
            ],
        )
        .map_err(|_| invalid("recovery spend wire encoding failed"))?;
        let decoded = wire::decode_spend_ref(&body)
            .map_err(|_| invalid("recovery spend wire readback failed"))?;
        if decoded.public != self.public
            || decoded.proof != proof.as_slice()
            || (0..3).any(|i| decoded.ciphertexts[i] != self.ciphertexts[i].as_bytes())
            || (0..2).any(|i| {
                decoded.capsules[i].public != self.capsules[i].public
                    || decoded.capsules[i].proof != self.capsules[i].proof.as_slice()
            })
        {
            return Err(invalid("recovery spend wire readback mismatch"));
        }
        Ok(RecoverySpendArtifactV1 {
            public: self.public.clone(),
            body,
        })
    }
}
pub struct RecoverySpendArtifactV1 {
    public: spend::Public,
    body: Vec<u8>,
}
impl RecoverySpendArtifactV1 {
    pub fn public_statement(&self) -> &spend::Public {
        &self.public
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.body
    }
}

/// Fully validated local construction before capsule/spend proofs. Secret witness
/// fields remain private and zeroize through SpendWitness on drop. This plan is
/// not a submission artifact or source-authority token.
pub struct RecoverySpendPlanV1<'a> {
    public: spend::Public,
    witness: SpendWitness,
    ciphertexts: [AssetNoteCiphertext; 3],
    outputs: [&'a RecoveryNoteMaterialV1; 2],
}
pub fn prepare_recovery_spend_plan<'a, R: TryCryptoRng + ?Sized>(
    construction: RecoverySpendConstructionV1<'a>,
    recipient_keys: [&MlKemPublicKey; 3],
    rng: &mut R,
) -> Result<RecoverySpendPlanV1<'a>, WalletError> {
    let RecoverySpendConstructionV1 {
        mut public,
        authorization,
        mut native_fee_input,
        outputs,
        native_fee_change,
        mut credentials,
    } = construction;
    public
        .validate_structure()
        .map_err(|_| invalid("recovery construction public profile"))?;
    let mut witness = SpendWitness(spend::Witness {
        base: AssetSpendWitness {
            inputs: core::array::from_fn(|_| PrivateInput::default()),
            outputs: [
                outputs[0].as_note(),
                outputs[1].as_note(),
                native_fee_change.as_note(),
            ],
            output_authorities: [
                outputs[0].holder_authority,
                outputs[1].holder_authority,
                native_fee_change.authority,
            ],
            credentials: core::array::from_fn(|_| AssetCredentialWitness {
                index: 0,
                expires_at: 0,
                siblings: vec![[0; 7]; 4],
            }),
            issuer_secret: [0; 7],
            policy: Default::default(),
        },
        input_holder_authority: [0; 7],
        input_shared_nf_key: [0; 5],
        output_shared_nf_keys: [outputs[0].shared_nf_key, outputs[1].shared_nf_key],
        delegate_secret: [0; 7],
        use_delegate: 0,
        delegate_credential_recipient: [0; 4],
        note_freeze_siblings: [[0; 7]; 32],
    });
    witness.0.base.inputs[1] = std::mem::take(&mut native_fee_input.input);
    match &authorization {
        RecoveryAuthorizationV1::Mint {
            dummy_secret,
            issuer_secret,
        } => {
            if public.base.operation != MINT {
                return Err(invalid("recovery mint authorization mismatch"));
            }
            witness.0.base.inputs[0].dummy_secret = **dummy_secret;
            witness.0.base.issuer_secret = **issuer_secret;
            credentials[0] = AssetCredentialWitness {
                index: 0,
                expires_at: 0,
                siblings: vec![[0; 7]; 4],
            };
            public.base.nullifiers[0] = transaction_circuit::asset_spend_v1::dummy_nullifier(
                public.base.chain_id,
                **dummy_secret,
            )
            .map_err(|_| invalid("recovery dummy nullifier"))?;
        }
        RecoveryAuthorizationV1::Holder {
            material,
            position,
            siblings,
            freeze_siblings,
            ..
        }
        | RecoveryAuthorizationV1::Delegate {
            material,
            position,
            siblings,
            freeze_siblings,
            ..
        } => {
            if public.base.operation == MINT {
                return Err(invalid("recovery real input on mint"));
            }
            let ctx = context(
                public.base.chain_id,
                public.base.asset_id,
                public.row.descriptor.stable_policy_id,
                material.as_note(),
            )?;
            material.validate(&ctx)?;
            witness.0.base.inputs[0] = PrivateInput {
                occupied: 1,
                legacy_ordinary: 0,
                note: material.as_note(),
                position: *position,
                siblings: *siblings,
                spend_key: [0; 5],
                dummy_secret: [0; 5],
            };
            witness.0.input_holder_authority = material.holder_authority;
            witness.0.input_shared_nf_key = material.shared_nf_key;
            witness.0.note_freeze_siblings = *freeze_siblings;
            public.base.nullifiers[0] = material.common_nullifier(&ctx, *position)?;
        }
    }
    match &authorization {
        RecoveryAuthorizationV1::Holder { spend_key, .. } => {
            witness.0.base.inputs[0].spend_key = **spend_key
        }
        RecoveryAuthorizationV1::Delegate {
            delegate_secret,
            credential_recipient,
            ..
        } => {
            witness.0.use_delegate = 1;
            witness.0.delegate_secret = **delegate_secret;
            witness.0.delegate_credential_recipient = *credential_recipient;
        }
        _ => {}
    }
    witness.0.base.credentials = credentials;
    let fee = &witness.0.base.inputs[1];
    public.base.nullifiers[1] =
        private_spend::real_nullifier(fee.spend_key, fee.position, fee.note)
            .map_err(|_| invalid("recovery native fee nullifier"))?;
    for i in 0..3 {
        public.base.commitments[i] = private_spend::note_commitment(witness.0.base.outputs[i])
            .map_err(|_| invalid("recovery output commitment"))?;
    }
    let mut ciphertexts = Vec::with_capacity(3);
    for i in 0..2 {
        let encrypted =
            encrypt_holder_output(&public, i as u8, outputs[i], recipient_keys[i], rng)?;
        public.base.ciphertext_commitments[i] = ciphertext_hash_bytes(encrypted.as_bytes());
        ciphertexts.push(encrypted);
    }
    let encrypted = encrypt_native_fee_change(&public, native_fee_change, recipient_keys[2], rng)?;
    public.base.ciphertext_commitments[2] = ciphertext_hash_bytes(encrypted.as_bytes());
    ciphertexts.push(encrypted);
    let adapter = spend::AssetRecoverySpendAdapter::from_public(&public)
        .map_err(|_| invalid("recovery relation public graph rejected"))?;
    let packed = Zeroizing::new(
        adapter
            .lower(&public, &witness.0)
            .map_err(|_| invalid("recovery relation lowering rejected construction"))?,
    );
    adapter
        .verify_packed_witness(&packed)
        .map_err(|_| invalid("recovery relation rejected construction"))?;
    drop(packed);
    drop(adapter);
    Ok(RecoverySpendPlanV1 {
        public,
        witness,
        ciphertexts: ciphertexts
            .try_into()
            .map_err(|_| invalid("recovery ciphertext count"))?,
        outputs,
    })
}
impl RecoverySpendPlanV1<'_> {
    pub fn public_statement(&self) -> &spend::Public {
        &self.public
    }
    pub fn real_input_positions(&self) -> Vec<u64> {
        let mut positions = Vec::with_capacity(2);
        if self.public.base.operation != MINT {
            positions.push(self.witness.0.base.inputs[0].position as u64);
        }
        positions.push(self.witness.0.base.inputs[1].position as u64);
        positions
    }
    /// External archive/delegate services must durably reserve this plan's exact
    /// public nullifiers in their own journal before calling a capsule provider.
    /// This low-level method grants no wallet/source/descriptor authority.
    pub fn attach_capsules(
        self,
        provider: &mut dyn ArchiveCapsuleProviderV1,
    ) -> Result<PreparedRecoverySpendV1, WalletError> {
        let Self {
            public,
            witness,
            ciphertexts,
            outputs,
        } = self;
        let mut capsules = Vec::with_capacity(2);
        for i in 0..2 {
            let request = ArchiveCapsuleRequestV1 {
                descriptor: &public.row.descriptor,
                context: RecoveryNoteContextV1 {
                    chain_id: public.base.chain_id,
                    asset_id: public.base.asset_id,
                    stable_policy_id: public.row.descriptor.stable_policy_id,
                    output_commitment: public.base.commitments[i],
                },
                material: outputs[i],
            };
            let capsule = provider.create_capsule(&request)?;
            capsule_matches(&request, &capsule.public)?;
            capsules.push(capsule);
        }
        Ok(PreparedRecoverySpendV1 {
            public,
            witness,
            ciphertexts,
            capsules: capsules
                .try_into()
                .map_err(|_| invalid("recovery capsule count"))?,
        })
    }
}

/// Pure holder/delegate/issuer construction with immediate provider work.
/// Persistent external services should use prepare_recovery_spend_plan and
/// reserve its final public inputs before attach_capsules. Holder WalletStore
/// callers should use prepare_and_retain_holder_recovery_spend.
pub fn prepare<R: TryCryptoRng + ?Sized>(
    construction: RecoverySpendConstructionV1<'_>,
    recipient_keys: [&MlKemPublicKey; 3],
    provider: &mut dyn ArchiveCapsuleProviderV1,
    rng: &mut R,
) -> Result<PreparedRecoverySpendV1, WalletError> {
    prepare_recovery_spend_plan(construction, recipient_keys, rng)?.attach_capsules(provider)
}

struct RecoveryOsEntropy(rand::rngs::OsRng);
impl rand_core09::TryRngCore for RecoveryOsEntropy {
    type Error = rand::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.0.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.0.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0.try_fill_bytes(bytes)
    }
}
impl TryCryptoRng for RecoveryOsEntropy {}
/// OS entropy for fresh note material; no caller RNG dependency is required.
pub fn new_recovery_output_os(
    chain: [u8; 32],
    asset: u32,
    policy: Digest,
    value: u64,
    recipient: [u64; 4],
    holder_authority: Digest,
) -> Result<RecoveryNoteMaterialV1, WalletError> {
    new_recovery_output(
        chain,
        asset,
        policy,
        value,
        recipient,
        holder_authority,
        &mut RecoveryOsEntropy(rand::rngs::OsRng),
    )
}
/// OS-backed no-proof phase for holder or separately journaled delegate flows.
pub fn prepare_recovery_spend_plan_os<'a>(
    construction: RecoverySpendConstructionV1<'a>,
    recipient_keys: [&MlKemPublicKey; 3],
) -> Result<RecoverySpendPlanV1<'a>, WalletError> {
    prepare_recovery_spend_plan(
        construction,
        recipient_keys,
        &mut RecoveryOsEntropy(rand::rngs::OsRng),
    )
}
/// OS-backed pure construction, including actual capsule provider proofs.
pub fn prepare_recovery_spend_os(
    construction: RecoverySpendConstructionV1<'_>,
    recipient_keys: [&MlKemPublicKey; 3],
    provider: &mut dyn ArchiveCapsuleProviderV1,
) -> Result<PreparedRecoverySpendV1, WalletError> {
    prepare(
        construction,
        recipient_keys,
        provider,
        &mut RecoveryOsEntropy(rand::rngs::OsRng),
    )
}

/// Error phases reveal no note openings or proof witness data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistentRecoveryBuildStageV1 {
    Construction,
    Reservation,
    Proving,
    Retention,
}
pub struct PersistentRecoveryBuildErrorV1 {
    pub reservation_id: Option<[u8; 32]>,
    pub stage: PersistentRecoveryBuildStageV1,
    error: WalletError,
    cancellation_error: Option<WalletError>,
}
impl PersistentRecoveryBuildErrorV1 {
    pub fn wallet_error(&self) -> &WalletError {
        &self.error
    }
    /// Present when release of a never-exported Proving record could not persist.
    /// The caller must retain the reservation ID and reconcile the durable store.
    pub fn cancellation_error(&self) -> Option<&WalletError> {
        self.cancellation_error.as_ref()
    }
    fn new(stage: PersistentRecoveryBuildStageV1, error: WalletError) -> Self {
        Self {
            reservation_id: None,
            stage,
            error,
            cancellation_error: None,
        }
    }
}
impl std::fmt::Debug for PersistentRecoveryBuildErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistentRecoveryBuildErrorV1")
            .field("stage", &self.stage)
            .field("reservation_id", &self.reservation_id)
            .field("cancellation_failed", &self.cancellation_error.is_some())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for PersistentRecoveryBuildErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "recovery persistent build failed during {:?}",
            self.stage
        )
    }
}
impl std::error::Error for PersistentRecoveryBuildErrorV1 {}

// Private orchestration boundary permits cheap ordering/error tests without
// accepting synthetic proofs through any public construction/retention API.
trait RecoveryBuildJournalV1 {
    fn reserve(
        &self,
        context: crate::poseidon2_v8_sync::LaunchWalletContext,
        public: &spend::Public,
        positions: &[u64],
    ) -> Result<[u8; 32], WalletError>;
    fn retain(&self, id: [u8; 32], body: &[u8]) -> Result<(), WalletError>;
    fn cancel_unexported(&self, id: [u8; 32]) -> Result<(), WalletError>;
}
impl RecoveryBuildJournalV1 for crate::WalletStore {
    fn reserve(
        &self,
        context: crate::poseidon2_v8_sync::LaunchWalletContext,
        public: &spend::Public,
        positions: &[u64],
    ) -> Result<[u8; 32], WalletError> {
        self.reserve_recovery_spend(context, public, positions)
    }
    fn retain(&self, id: [u8; 32], body: &[u8]) -> Result<(), WalletError> {
        self.retain_recovery_spend(id, body)
    }
    fn cancel_unexported(&self, id: [u8; 32]) -> Result<(), WalletError> {
        self.cancel_unexported_recovery_spend(id)
    }
}
fn prove_reserved<J: RecoveryBuildJournalV1>(
    journal: &J,
    context: crate::poseidon2_v8_sync::LaunchWalletContext,
    public: &spend::Public,
    positions: &[u64],
    prove_body: impl FnOnce() -> Result<Vec<u8>, WalletError>,
) -> Result<[u8; 32], PersistentRecoveryBuildErrorV1> {
    use PersistentRecoveryBuildStageV1 as Stage;
    let id = journal
        .reserve(context, public, positions)
        .map_err(|error| PersistentRecoveryBuildErrorV1::new(Stage::Reservation, error))?;
    let body = match prove_body() {
        Ok(body) => body,
        Err(error) => {
            return Err(PersistentRecoveryBuildErrorV1 {
                reservation_id: Some(id),
                stage: Stage::Proving,
                error,
                cancellation_error: journal.cancel_unexported(id).err(),
            })
        }
    };
    // A failed disk write can have uncertain durability. Do not cancel/release
    // after retention was attempted, and never return an unretained body.
    journal
        .retain(id, &body)
        .map_err(|error| PersistentRecoveryBuildErrorV1 {
            reservation_id: Some(id),
            stage: Stage::Retention,
            error,
            cancellation_error: None,
        })?;
    Ok(id)
}

pub struct PersistentRecoveryCandidateV1 {
    reservation_id: [u8; 32],
    context: crate::poseidon2_v8_sync::LaunchWalletContext,
    public: spend::Public,
}
impl PersistentRecoveryCandidateV1 {
    pub fn reservation_id(&self) -> [u8; 32] {
        self.reservation_id
    }
    pub fn public_statement(&self) -> &spend::Public {
        &self.public
    }
    /// Exact immutable body is read from the encrypted journal with current
    /// shared-NF, canonical-reference and cross-route exclusion checks.
    pub fn export(&self, store: &crate::WalletStore) -> Result<Vec<u8>, WalletError> {
        store.require_launch_context(self.context)?;
        let body = store.recovery_candidate_bytes(self.reservation_id)?;
        let decoded = wire::decode_spend_ref(&body)
            .map_err(|_| invalid("recovery retained candidate framing"))?;
        if decoded.public != self.public {
            return Err(invalid("recovery retained candidate identity"));
        }
        Ok(body)
    }
}
/// Holder-wallet mint/holder spend: no capsule provider or spend proof executes
/// until exact final public inputs are durably reserved. Delegate operations
/// must use a separately managed archive/delegate journal; this holder store
/// does not silently claim custody of an unowned recovery input.
pub fn prepare_and_retain_holder_recovery_spend<R: TryCryptoRng + ?Sized>(
    store: &crate::WalletStore,
    context: crate::poseidon2_v8_sync::LaunchWalletContext,
    construction: RecoverySpendConstructionV1<'_>,
    recipient_keys: [&MlKemPublicKey; 3],
    provider: &mut dyn ArchiveCapsuleProviderV1,
    rng: &mut R,
) -> Result<PersistentRecoveryCandidateV1, PersistentRecoveryBuildErrorV1> {
    use PersistentRecoveryBuildStageV1 as Stage;
    if matches!(
        &construction.authorization,
        RecoveryAuthorizationV1::Delegate { .. }
    ) {
        return Err(PersistentRecoveryBuildErrorV1::new(
            Stage::Construction,
            invalid("delegate recovery needs separate archive persistence"),
        ));
    }
    store
        .require_launch_context(context)
        .map_err(|e| PersistentRecoveryBuildErrorV1::new(Stage::Construction, e))?;
    let prepared = prepare_recovery_spend_plan(construction, recipient_keys, rng)
        .map_err(|e| PersistentRecoveryBuildErrorV1::new(Stage::Construction, e))?;
    let public = prepared.public.clone();
    let positions = prepared.real_input_positions();
    let id = prove_reserved(store, context, &public, &positions, || {
        let prepared = prepared.attach_capsules(provider)?;
        Ok(prepared.prove_and_encode()?.body)
    })?;
    Ok(PersistentRecoveryCandidateV1 {
        reservation_id: id,
        context,
        public,
    })
}
pub fn prepare_and_retain_holder_recovery_spend_os(
    store: &crate::WalletStore,
    context: crate::poseidon2_v8_sync::LaunchWalletContext,
    construction: RecoverySpendConstructionV1<'_>,
    recipient_keys: [&MlKemPublicKey; 3],
    provider: &mut dyn ArchiveCapsuleProviderV1,
) -> Result<PersistentRecoveryCandidateV1, PersistentRecoveryBuildErrorV1> {
    prepare_and_retain_holder_recovery_spend(
        store,
        context,
        construction,
        recipient_keys,
        provider,
        &mut RecoveryOsEntropy(rand::rngs::OsRng),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoverySubmissionReceiptV1 {
    pub reservation_id: [u8; 32],
    pub action_id: [u8; 48],
}
/// One submission attempt of exactly retained bytes. Cancellation, connection
/// errors and rejection leave SubmissionUncertain and its global holds intact.
/// Failed acknowledgement persistence never releases the journal/holds. Retry is explicit and
/// reuses this same immutable journal body; no reproof/ref-change/release occurs.
#[cfg(all(feature = "rpc-client", feature = "private-spend-dev-artifacts"))]
pub async fn submit_retained_recovery_spend(
    store: &crate::WalletStore,
    client: &crate::node_rpc::NodeRpcClient,
    authority: &crate::private_spend_rpc::DevelopmentPrivateSpendAuthority,
    id: [u8; 32],
) -> Result<RecoverySubmissionReceiptV1, WalletError> {
    store.require_launch_context(authority.context())?;
    let body = store.recovery_candidate_bytes(id)?;
    let decoded = wire::decode_spend_ref(&body)
        .map_err(|_| invalid("recovery retained submission framing"))?;
    authority.authorize_recovery_public(&decoded.public)?;
    store.begin_recovery_submission(id)?;
    let action_id = client
        .submit_native_recovery_action(
            authority,
            crate::poseidon2_v8_sync::RECOVERY_SPEND_ACTION_ID,
            &body,
        )
        .await?;
    store.mark_recovery_submitted(id, action_id)?;
    Ok(RecoverySubmissionReceiptV1 {
        reservation_id: id,
        action_id,
    })
}

fn decrypt_plain(
    public: &spend::Public,
    slot: u8,
    bytes: &[u8],
    secret: &MlKemSecretKey,
) -> Result<AssetNotePlaintext, WalletError> {
    if slot > 2 {
        return Err(invalid("recovery output slot"));
    }
    let ct = AssetNoteCiphertextRef::from_bytes_exact(bytes)
        .map_err(|_| invalid("recovery ciphertext width"))?;
    if ciphertext_hash_bytes(ct.as_bytes()) != public.base.ciphertext_commitments[slot as usize] {
        return Err(invalid("recovery ciphertext binding mismatch"));
    }
    ct.decrypt(secret, &encryption_context(public, slot)?)
        .map_err(|_| invalid("recovery holder decryption failed"))
}
pub fn decrypt_holder_output(
    public: &spend::Public,
    slot: u8,
    bytes: &[u8],
    secret: &MlKemSecretKey,
    recipient: [u64; 4],
    authority: Digest,
) -> Result<RecoveryNoteMaterialV1, WalletError> {
    if slot > 1 {
        return Err(invalid("recovery holder output slot"));
    }
    let plaintext = decrypt_plain(public, slot, bytes, secret)?;
    let context = RecoveryNoteContextV1 {
        chain_id: public.base.chain_id,
        asset_id: public.base.asset_id,
        stable_policy_id: public.row.descriptor.stable_policy_id,
        output_commitment: public.base.commitments[slot as usize],
    };
    let material = RecoveryNoteMaterialV1::decode(
        &RecoveryNotePlaintextV1::from_bytes_exact(plaintext.as_bytes())?,
        &context,
    )?;
    if material.note.recipient_key != recipient || material.holder_authority != authority {
        return Err(invalid("recovery holder address mismatch"));
    }
    Ok(material)
}
pub fn decrypt_native_fee_change(
    public: &spend::Public,
    bytes: &[u8],
    secret: &MlKemSecretKey,
    recipient_index: u32,
    recipient: [u64; 4],
    authority: Digest,
) -> Result<AssetNotePayload, WalletError> {
    let plaintext = decrypt_plain(public, 2, bytes, secret)?;
    let material = AssetNotePayload::decode(&plaintext, public.base.chain_id, 0)?;
    if material.recipient_index != recipient_index
        || material.note.recipient_key != recipient
        || material.authority != authority
        || private_spend::note_commitment(material.as_note()).ok()
            != Some(public.base.commitments[2])
    {
        return Err(invalid(
            "recovery native fee change address or commitment mismatch",
        ));
    }
    Ok(material)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct DisposableRng(u64);
    impl rand_core09::TryRngCore for DisposableRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.try_next_u64()? as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            Ok(self.0)
        }
        fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in out.chunks_mut(8) {
                let word = self.try_next_u64()?.to_le_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
            Ok(())
        }
    }
    impl TryCryptoRng for DisposableRng {}
    #[test]
    fn generated_material_roundtrip_and_common_nf_with_no_spend_secret_parameter() {
        let mut rng = DisposableRng(71);
        let material =
            new_recovery_output([4; 32], 17, [9; 7], 42, [3; 4], [7; 7], &mut rng).unwrap();
        let ctx = context([4; 32], 17, [9; 7], material.as_note()).unwrap();
        let words = material.material_words(&ctx).unwrap();
        let restored = RecoveryNoteMaterialV1::from_material_words(&words, &ctx).unwrap();
        assert_eq!(*restored.material_words(&ctx).unwrap(), *words);
        assert_eq!(
            restored.common_nullifier(&ctx, 17).unwrap(),
            private_spend::real_nullifier(material.shared_nf_key, 17, material.as_note()).unwrap()
        );
        let second =
            new_recovery_output([4; 32], 17, [9; 7], 42, [3; 4], [7; 7], &mut rng).unwrap();
        assert_ne!(material.shared_nf_key, second.shared_nf_key);
        assert!(new_recovery_output([4; 32], 0, [9; 7], 42, [3; 4], [7; 7], &mut rng).is_err());
        assert!(
            new_recovery_output([4; 32], 17, [9; 7], 1 << 56, [3; 4], [7; 7], &mut rng).is_err()
        );
        let mut bad = *words;
        bad[6] = hegemon_field::GOLDILOCKS_MODULUS;
        assert!(RecoveryNoteMaterialV1::from_material_words(&bad, &ctx).is_err());
        bad.zeroize();
    }
    #[test]
    fn provider_response_must_bind_exact_descriptor_context_and_note() {
        let material = new_recovery_output(
            [4; 32],
            17,
            [9; 7],
            42,
            [3; 4],
            [7; 7],
            &mut DisposableRng(19),
        )
        .unwrap();
        let ctx = context([4; 32], 17, [9; 7], material.as_note()).unwrap();
        let descriptor = recovery::RecoveryDescriptorV1 {
            asset_id: 17,
            stable_policy_id: [9; 7],
            policy_admin_commitment: [8; 7],
            archive_key_commitment: recovery::archive_key_commitment(&[23; 32]).unwrap(),
            maximum_powers: recovery::RecoveryPowersV1 {
                transfer: true,
                burn: true,
            },
        };
        let request = ArchiveCapsuleRequestV1 {
            descriptor: &descriptor,
            context: ctx,
            material: &material,
        };
        let public = capsule::encrypt(
            [4; 32],
            17,
            [9; 7],
            &[23; 32],
            &material.material_words(&ctx).unwrap(),
        )
        .unwrap();
        capsule_matches(&request, &public).unwrap();
        for index in 0..5 {
            let mut bad = public.clone();
            match index {
                0 => bad.chain_id[0] ^= 1,
                1 => bad.asset_id += 1,
                2 => bad.stable_policy_id[0] ^= 1,
                3 => bad.archive_key_commitment[0] ^= 1,
                _ => bad.note_commitment[0] ^= 1,
            }
            assert!(capsule_matches(&request, &bad).is_err());
        }
        assert!(NativeFeeInputV1::new(PrivateInput::default()).is_err());
    }
    #[cfg(feature = "private-spend-dev-artifacts")]
    #[test]
    fn actual_holder_and_native_fee_carriers_roundtrip_with_fresh_relation_aad() {
        use synthetic_crypto::{ml_kem::MlKemKeyPair, traits::KemKeyPair};
        let (mut public, witness) = spend::fixtures::fixture(0, false).unwrap();
        let keys = MlKemKeyPair::generate_deterministic(b"recovery-wallet-disposable-kem-v1");
        let recipient = keys.public_key();
        let mut rng = DisposableRng(17);
        let material = new_recovery_output(
            public.base.chain_id,
            public.base.asset_id,
            public.row.descriptor.stable_policy_id,
            42,
            [3; 4],
            [7; 7],
            &mut rng,
        )
        .unwrap();
        public.base.commitments[0] = private_spend::note_commitment(material.as_note()).unwrap();
        let ct = encrypt_holder_output(&public, 0, &material, &recipient, &mut rng).unwrap();
        public.base.ciphertext_commitments[0] = ciphertext_hash_bytes(ct.as_bytes());
        let restored =
            decrypt_holder_output(&public, 0, ct.as_bytes(), keys.secret_key(), [3; 4], [7; 7])
                .unwrap();
        assert_eq!(restored.note.value, 42);
        assert_eq!(restored.shared_nf_key, material.shared_nf_key);
        assert!(decrypt_holder_output(
            &public,
            1,
            ct.as_bytes(),
            keys.secret_key(),
            [3; 4],
            [7; 7]
        )
        .is_err());
        assert!(decrypt_holder_output(
            &public,
            0,
            ct.as_bytes(),
            keys.secret_key(),
            [4; 4],
            [7; 7]
        )
        .is_err());
        let note = witness.base.outputs[2];
        let fee = AssetNotePayload {
            recipient_index: 7,
            note: NoteOpening {
                value: note.value,
                asset_id: note.asset_id,
                recipient_key: note.recipient_key,
                authorization_key: note.authorization_key,
                rho: note.rho,
                randomness: note.randomness,
            },
            authority: witness.base.output_authorities[2],
        };
        let ct = encrypt_native_fee_change(&public, &fee, &recipient, &mut rng).unwrap();
        public.base.ciphertext_commitments[2] = ciphertext_hash_bytes(ct.as_bytes());
        let restored = decrypt_native_fee_change(
            &public,
            ct.as_bytes(),
            keys.secret_key(),
            7,
            note.recipient_key,
            fee.authority,
        )
        .unwrap();
        assert_eq!(restored.note.value, note.value);
        assert_eq!(restored.note.asset_id, 0);
        assert!(decrypt_native_fee_change(
            &public,
            ct.as_bytes(),
            keys.secret_key(),
            8,
            note.recipient_key,
            fee.authority
        )
        .is_err());
    }
}

#[cfg(all(test, feature = "private-spend-dev-artifacts"))]
mod persistent_orchestration_tests {
    use super::*;
    use crate::poseidon2_v8_sync::LaunchWalletContext;
    use std::cell::RefCell;

    // Tests only the journal/worker ordering, not proof acceptance. The public
    // path supplies real capsule+spend proofs and WalletStore verifies all three.
    struct Journal {
        events: RefCell<Vec<&'static str>>,
        fail_reserve: bool,
        fail_retain: bool,
        fail_cancel: bool,
        retained: RefCell<Vec<u8>>,
    }
    impl Journal {
        fn new() -> Self {
            Self {
                events: RefCell::new(vec![]),
                fail_reserve: false,
                fail_retain: false,
                fail_cancel: false,
                retained: RefCell::new(vec![]),
            }
        }
    }
    impl RecoveryBuildJournalV1 for Journal {
        fn reserve(
            &self,
            context: LaunchWalletContext,
            public: &spend::Public,
            positions: &[u64],
        ) -> Result<[u8; 32], WalletError> {
            assert_eq!(context.chain_id(), public.base.chain_id);
            assert_eq!(positions, &[8, 9]);
            self.events.borrow_mut().push("reserve");
            if self.fail_reserve {
                return Err(invalid("test cross-route hold"));
            }
            Ok([7; 32])
        }
        fn retain(&self, id: [u8; 32], body: &[u8]) -> Result<(), WalletError> {
            assert_eq!(id, [7; 32]);
            self.events.borrow_mut().push("retain");
            if self.fail_retain {
                return Err(invalid("test durability uncertain"));
            }
            *self.retained.borrow_mut() = body.to_vec();
            Ok(())
        }
        fn cancel_unexported(&self, id: [u8; 32]) -> Result<(), WalletError> {
            assert_eq!(id, [7; 32]);
            self.events.borrow_mut().push("cancel");
            if self.fail_cancel {
                return Err(invalid("test cancellation persistence"));
            }
            Ok(())
        }
    }
    fn fixture() -> (spend::Public, LaunchWalletContext) {
        let (public, _) = spend::fixtures::fixture(0, false).unwrap();
        let ctx =
            LaunchWalletContext::new(public.base.chain_id, [2; 32], [3; 64], 1, 10000).unwrap();
        (public, ctx)
    }
    #[test]
    fn cross_route_reservation_failure_never_runs_provider_or_prover() {
        let (public, ctx) = fixture();
        let mut journal = Journal::new();
        journal.fail_reserve = true;
        let failure = prove_reserved(&journal, ctx, &public, &[8, 9], || {
            panic!("provider/prover must not execute without durable reservation")
        })
        .unwrap_err();
        assert_eq!(failure.stage, PersistentRecoveryBuildStageV1::Reservation);
        assert_eq!(failure.reservation_id, None);
        assert_eq!(*journal.events.borrow(), ["reserve"]);
    }
    #[test]
    fn proof_failure_cancels_only_unexported_record_and_reports_failed_cancel() {
        let (public, ctx) = fixture();
        for cancellation_fails in [false, true] {
            let mut journal = Journal::new();
            journal.fail_cancel = cancellation_fails;
            let failure = prove_reserved(&journal, ctx, &public, &[8, 9], || {
                journal.events.borrow_mut().push("prove");
                Err(invalid("test actual prover failed"))
            })
            .unwrap_err();
            assert_eq!(failure.stage, PersistentRecoveryBuildStageV1::Proving);
            assert_eq!(failure.reservation_id, Some([7; 32]));
            assert_eq!(failure.cancellation_error().is_some(), cancellation_fails);
            assert_eq!(*journal.events.borrow(), ["reserve", "prove", "cancel"]);
            assert!(journal.retained.borrow().is_empty());
        }
    }
    #[test]
    fn retention_failure_preserves_hold_and_never_returns_candidate() {
        let (public, ctx) = fixture();
        let mut journal = Journal::new();
        journal.fail_retain = true;
        let failure = prove_reserved(&journal, ctx, &public, &[8, 9], || {
            journal.events.borrow_mut().push("prove");
            Ok(b"private orchestration fixture only".to_vec())
        })
        .unwrap_err();
        assert_eq!(failure.stage, PersistentRecoveryBuildStageV1::Retention);
        assert_eq!(failure.reservation_id, Some([7; 32]));
        assert!(failure.cancellation_error().is_none());
        assert_eq!(*journal.events.borrow(), ["reserve", "prove", "retain"]);
    }
    #[test]
    fn successful_orchestration_returns_id_only_after_exact_body_retention() {
        let (public, ctx) = fixture();
        let journal = Journal::new();
        let body = b"private orchestration fixture only".to_vec();
        let id = prove_reserved(&journal, ctx, &public, &[8, 9], || {
            journal.events.borrow_mut().push("prove");
            Ok(body.clone())
        })
        .unwrap();
        assert_eq!(id, [7; 32]);
        assert_eq!(*journal.retained.borrow(), body);
        assert_eq!(*journal.events.borrow(), ["reserve", "prove", "retain"]);
    }
}
