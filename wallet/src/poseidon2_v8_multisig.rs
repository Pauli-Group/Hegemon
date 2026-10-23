//! Private RP06 two-of-three treasury custody, exact operation review, and note tracking.
//!
//! The descriptor is private coordination material. Knowing its shared note-nullifier key
//! cannot satisfy the source relation's two distinct ledger-proven signer approvals.
//! Long-term signer keys remain in each independently encrypted `WalletStore`.
#![forbid(unsafe_code)]

use crate::{
    address::{ShieldedAddress, POSEIDON2_V8_ADDRESS_VERSION},
    keys::DerivedKeys,
    notes::{MemoPlaintext, NoteCiphertext, NotePlaintext},
    WalletError,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use transaction_circuit::{
    smallwood_poseidon2_v8_coinbase::{
        poseidon2_v8_note_commitment, poseidon2_v8_single_key_authorization_digest,
        poseidon2_v8_words_from_canonical_bytes, poseidon2_v8_words_to_bytes,
    },
    smallwood_poseidon2_v8_rp06::{
        compile_rp06_relation, rp06_accumulator_authorization, rp06_policy_note_nullifier,
        rp06_policy_root, rp06_value_authorization, Rp06PublicStatement,
    },
    smallwood_poseidon2_v8_types::{
        smallwood_poseidon2_v8_ciphertext_commitment, SmallwoodPoseidon2V8AccumulatorOpening,
        SmallwoodPoseidon2V8InlineCiphertexts, SmallwoodPoseidon2V8InputWitness,
        SmallwoodPoseidon2V8NoteOpening, SmallwoodPoseidon2V8OutputWitness,
        SmallwoodPoseidon2V8PrivateAuthWitness, SmallwoodPoseidon2V8PublicStatement,
        SmallwoodPoseidon2V8Witness, SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES,
    },
    SmallwoodPrivateAuthMode,
};

const NATIVE: u64 = transaction_circuit::constants::NATIVE_ASSET_ID;
const MODULUS: u64 = transaction_circuit::constants::FIELD_MODULUS_U64;
fn invalid(reason: &'static str) -> WalletError {
    WalletError::InvalidState(reason)
}
fn surface(error: impl core::fmt::Debug) -> WalletError {
    WalletError::Serialization(format!("RP06 treasury: {error:?}"))
}
fn output_ciphertext_commitment(bytes: &[u8]) -> Result<[u64; 6], WalletError> {
    let exact: &[u8; SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES] = bytes
        .try_into()
        .map_err(|_| invalid("wrong treasury ciphertext length"))?;
    Ok(smallwood_poseidon2_v8_ciphertext_commitment(exact))
}
fn random_words<const N: usize, R: RngCore + ?Sized>(rng: &mut R) -> [u64; N] {
    core::array::from_fn(|_| loop {
        let word = rng.next_u64();
        if word != 0 && word < MODULUS {
            break word;
        }
    })
}

/// Private descriptor. Export only over a private channel to the three named signers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V8TreasuryDescriptor {
    pub chain_id: [u8; 32],
    pub account_id: [u8; 32],
    pub policy_root: [u64; 7],
    pub policy_nullifier_key: [u64; 5],
    pub signer_tags: [[u64; 7]; 6],
    pub receive_address: ShieldedAddress,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum V8TreasuryNoteKind {
    Value,
    Accumulator { opening_words: Vec<u64> },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V8TreasuryNote {
    pub commitment: [u64; 7],
    pub note_words: Vec<u64>,
    pub kind: V8TreasuryNoteKind,
}
/// The exact outputs, ciphertexts, source and fee that all signers review.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V8TreasuryPlan {
    pub account_id: [u8; 32],
    pub source_commitment: [u64; 7],
    pub source_position: u64,
    pub source_note_words: Vec<u64>,
    pub recipient_address: ShieldedAddress,
    pub public_words: Vec<u64>,
    pub output_note_words: [Vec<u64>; 2],
    pub output_ciphertexts: [Option<Vec<u8>>; 2],
    /// Independent private encryption witnesses, persisted in encrypted wallet
    /// state and 0600 private-plan exports. `None` marks a legacy plan that must
    /// be recreated and re-reviewed.
    #[serde(default)]
    output_kem_seeds: Option<[Option<[u8; 32]>; 2]>,
    pub intent_digest: [u64; 7],
}
impl core::fmt::Debug for V8TreasuryPlan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("V8TreasuryPlan")
            .field("account_id", &self.account_id)
            .field("source_commitment", &self.source_commitment)
            .field("source_position", &self.source_position)
            .field("recipient_address", &self.recipient_address)
            .field("public_words", &self.public_words)
            .field("intent_digest", &self.intent_digest)
            .field("output_kem_seeds", &"[REDACTED]")
            .finish()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum V8TreasuryAttemptStatus {
    Prepared,
    SubmissionUncertain,
    Submitted,
    Mined,
    Abandoned,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V8TreasuryAttempt {
    pub review_digest: Vec<u8>,
    pub nullifiers: Vec<[u64; 7]>,
    pub ordinary_note_refs: Vec<([u64; 7], u64)>,
    pub policy_note_refs: Vec<([u64; 7], u64)>,
    pub status: V8TreasuryAttemptStatus,
    pub action_id: Option<Vec<u8>>,
    pub mined_in: Option<(u64, [u8; 32])>,
    pub material_snapshot: Option<V8TreasuryMaterialSnapshot>,
    pub candidate_inline: Option<Vec<u8>>,
}
/// Exact candidate construction persisted before proving. Local signer spend keys are
/// erased from these words and restored only from this encrypted wallet's key owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V8TreasuryMaterialSnapshot {
    pub public_words: Vec<u64>,
    pub witness_words: Vec<u64>,
    pub inline_ciphertext_bytes: Vec<u8>,
}
/// Stored only inside WalletStore's encrypted V15 payload. Abandoned attempts are retained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredV8Treasury {
    pub descriptor: V8TreasuryDescriptor,
    pub notes: Vec<V8TreasuryNote>,
    pub plans: Vec<V8TreasuryPlan>,
    pub attempts: Vec<V8TreasuryAttempt>,
}

/// Frozen V14 plan shape. Old plans have no independent encryption witness, so
/// migration retains them as unreviewable records that require plan recreation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct V8TreasuryPlanV14 {
    pub account_id: [u8; 32],
    pub source_commitment: [u64; 7],
    pub source_position: u64,
    pub source_note_words: Vec<u64>,
    pub recipient_address: ShieldedAddress,
    pub public_words: Vec<u64>,
    pub output_note_words: [Vec<u64>; 2],
    pub output_ciphertexts: [Option<Vec<u8>>; 2],
    pub intent_digest: [u64; 7],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredV8TreasuryV14 {
    pub descriptor: V8TreasuryDescriptor,
    pub notes: Vec<V8TreasuryNote>,
    pub plans: Vec<V8TreasuryPlanV14>,
    pub attempts: Vec<V8TreasuryAttempt>,
}
impl From<V8TreasuryPlanV14> for V8TreasuryPlan {
    fn from(value: V8TreasuryPlanV14) -> Self {
        Self {
            account_id: value.account_id,
            source_commitment: value.source_commitment,
            source_position: value.source_position,
            source_note_words: value.source_note_words,
            recipient_address: value.recipient_address,
            public_words: value.public_words,
            output_note_words: value.output_note_words,
            output_ciphertexts: value.output_ciphertexts,
            output_kem_seeds: None,
            intent_digest: value.intent_digest,
        }
    }
}
impl From<StoredV8TreasuryV14> for StoredV8Treasury {
    fn from(value: StoredV8TreasuryV14) -> Self {
        Self {
            descriptor: value.descriptor,
            notes: value.notes,
            plans: value.plans.into_iter().map(Into::into).collect(),
            attempts: value.attempts,
        }
    }
}
/// Deliberate local review bound to immutable operation bytes. It conveys no chain authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V8TreasuryReviewedPlan {
    account_id: [u8; 32],
    digest: [u8; 64],
}
/// Canonical chain membership must come from the verified wallet mirror at build time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V8TreasuryNotePath {
    pub commitment: [u64; 7],
    pub position: u64,
    pub siblings: [[u64; 7]; 32],
    pub anchor: [u64; 7],
}
#[derive(Clone, Debug)]
pub struct V8TreasurySpendMaterial {
    pub statement: Rp06PublicStatement,
    pub witness: SmallwoodPoseidon2V8Witness,
    pub inline_ciphertexts: SmallwoodPoseidon2V8InlineCiphertexts,
}

impl V8TreasuryMaterialSnapshot {
    fn from_material(material: &V8TreasurySpendMaterial) -> Self {
        let mut witness = material.witness;
        if witness.auth.mode == SmallwoodPrivateAuthMode::ApprovalStep {
            for input in &mut witness.inputs {
                input.spend_key = [0; 5];
            }
        }
        Self {
            public_words: material.statement.to_public_words().to_vec(),
            witness_words: witness.to_witness_words().to_vec(),
            inline_ciphertext_bytes: material.inline_ciphertexts.to_inline_ciphertext_bytes(),
        }
    }
    fn restore(&self, keys: Option<&DerivedKeys>) -> Result<V8TreasurySpendMaterial, WalletError> {
        let statement =
            Rp06PublicStatement::try_from_public_words(&self.public_words).map_err(surface)?;
        let mut witness = SmallwoodPoseidon2V8Witness::try_from_witness_words(&self.witness_words)
            .map_err(surface)?;
        if witness.auth.mode == SmallwoodPrivateAuthMode::ApprovalStep {
            let spend_key = keys
                .ok_or(invalid("recovery requires the local approval signer"))?
                .spend
                .poseidon2_v8_words()?;
            for input in &mut witness.inputs {
                if input.active {
                    input.spend_key = spend_key;
                }
            }
        }
        let inline_ciphertexts =
            SmallwoodPoseidon2V8InlineCiphertexts::try_from_inline_ciphertext_bytes(
                &statement.base,
                &self.inline_ciphertext_bytes,
            )
            .map_err(surface)?;
        compile_rp06_relation(statement, &witness).map_err(surface)?;
        Ok(V8TreasurySpendMaterial {
            statement,
            witness,
            inline_ciphertexts,
        })
    }
}

pub fn v8_treasury_signer_tag(keys: &DerivedKeys) -> Result<[u64; 7], WalletError> {
    poseidon2_v8_single_key_authorization_digest(keys.spend.poseidon2_v8_words()?).map_err(surface)
}
impl V8TreasuryDescriptor {
    pub fn create<R: RngCore + CryptoRng>(
        keeper: &DerivedKeys,
        chain_id: [u8; 32],
        mut signers: [[u64; 7]; 3],
        rng: &mut R,
    ) -> Result<Self, WalletError> {
        signers.sort();
        let signer_tags = [signers[0], signers[1], signers[2], [0; 7], [0; 7], [0; 7]];
        let policy_root = rp06_policy_root(2, 3, signer_tags).map_err(surface)?;
        let policy_nullifier_key = random_words(rng);
        let authorization =
            rp06_value_authorization(policy_root, policy_nullifier_key).map_err(surface)?;
        let mut receive_address = keeper.poseidon2_v8_address(0)?.shielded_address();
        receive_address.pk_auth =
            poseidon2_v8_words_to_bytes(authorization[..4].try_into().expect("four"));
        for (i, word) in authorization[4..].iter().enumerate() {
            receive_address.pk_auth_extension[i * 8..i * 8 + 8]
                .copy_from_slice(&word.to_le_bytes());
        }
        let mut account_id = [0; 32];
        rng.fill_bytes(&mut account_id);
        let result = Self {
            chain_id,
            account_id,
            policy_root,
            policy_nullifier_key,
            signer_tags,
            receive_address,
        };
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<(), WalletError> {
        if self.chain_id == [0; 32]
            || self.account_id == [0; 32]
            || self.signer_tags[0..3]
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.policy_root != rp06_policy_root(2, 3, self.signer_tags).map_err(surface)?
        {
            return Err(invalid("invalid RP06 treasury policy/network"));
        }
        let expected = rp06_value_authorization(self.policy_root, self.policy_nullifier_key)
            .map_err(surface)?;
        if self.receive_address.version != POSEIDON2_V8_ADDRESS_VERSION
            || self.receive_address.crypto_suite != protocol_versioning::CRYPTO_SUITE_ETA
            || address_authorization(&self.receive_address)? != expected
        {
            return Err(invalid(
                "RP06 permanent recipient is not bound to its private policy",
            ));
        }
        ShieldedAddress::from_bytes(&self.receive_address.to_bytes())?;
        Ok(())
    }
    pub fn signer_slot(&self, keys: &DerivedKeys) -> Result<usize, WalletError> {
        let tag = v8_treasury_signer_tag(keys)?;
        self.signer_tags[..3]
            .iter()
            .position(|other| *other == tag)
            .ok_or(invalid("local wallet key is not a treasury signer"))
    }
    pub fn receive_note(
        &self,
        note: SmallwoodPoseidon2V8NoteOpening,
    ) -> Result<V8TreasuryNote, WalletError> {
        self.validate()?;
        if note.value == 0
            || note.asset_id != NATIVE
            || note.recipient_key
                != poseidon2_v8_words_from_canonical_bytes(self.receive_address.pk_recipient)
                    .map_err(surface)?
            || note_authorization(note)
                != rp06_value_authorization(self.policy_root, self.policy_nullifier_key)
                    .map_err(surface)?
        {
            return Err(invalid("opening is not a treasury value note"));
        }
        Ok(V8TreasuryNote {
            commitment: poseidon2_v8_note_commitment(note).map_err(surface)?,
            note_words: note_to_words(note),
            kind: V8TreasuryNoteKind::Value,
        })
    }
}
fn address_authorization(address: &ShieldedAddress) -> Result<[u64; 7], WalletError> {
    let mut digest = [0; 7];
    digest[..4].copy_from_slice(
        &poseidon2_v8_words_from_canonical_bytes(address.pk_auth).map_err(surface)?,
    );
    for i in 0..3 {
        digest[4 + i] = u64::from_le_bytes(
            address.pk_auth_extension[i * 8..i * 8 + 8]
                .try_into()
                .expect("eight"),
        );
    }
    if digest.iter().any(|word| *word >= MODULUS) {
        return Err(invalid("noncanonical treasury address authorization"));
    }
    Ok(digest)
}
fn note_authorization(note: SmallwoodPoseidon2V8NoteOpening) -> [u64; 7] {
    [
        note.authorization_key[0],
        note.authorization_key[1],
        note.authorization_key[2],
        note.authorization_key[3],
        note.randomness[0],
        note.randomness[1],
        note.randomness[2],
    ]
}
fn set_authorization(note: &mut SmallwoodPoseidon2V8NoteOpening, digest: [u64; 7]) {
    note.authorization_key.copy_from_slice(&digest[..4]);
    note.randomness[..3].copy_from_slice(&digest[4..]);
}
pub fn note_to_words(note: SmallwoodPoseidon2V8NoteOpening) -> Vec<u64> {
    let mut words = vec![note.value, note.asset_id];
    words.extend(note.recipient_key);
    words.extend(note.authorization_key);
    words.extend(note.rho);
    words.extend(note.randomness);
    words
}
pub fn note_from_words(words: &[u64]) -> Result<SmallwoodPoseidon2V8NoteOpening, WalletError> {
    if words.len() != 18 || words.iter().any(|word| *word >= MODULUS) {
        return Err(invalid("invalid treasury note word codec"));
    }
    Ok(SmallwoodPoseidon2V8NoteOpening {
        value: words[0],
        asset_id: words[1],
        recipient_key: words[2..6].try_into().expect("four"),
        authorization_key: words[6..10].try_into().expect("four"),
        rho: words[10..14].try_into().expect("four"),
        randomness: words[14..18].try_into().expect("four"),
    })
}
fn accumulator_words(opening: SmallwoodPoseidon2V8AccumulatorOpening) -> Vec<u64> {
    let mut words = Vec::with_capacity(23);
    words.extend(opening.policy_root);
    words.extend(opening.intent_digest);
    words.extend([
        opening.threshold,
        opening.signer_count,
        opening.approval_count,
    ]);
    words.extend(opening.approved_slots.map(u64::from));
    words
}
fn accumulator_from_words(
    words: &[u64],
) -> Result<SmallwoodPoseidon2V8AccumulatorOpening, WalletError> {
    if words.len() != 23 || words[17..].iter().any(|word| *word > 1) {
        return Err(invalid("invalid treasury accumulator codec"));
    }
    Ok(SmallwoodPoseidon2V8AccumulatorOpening {
        policy_root: words[..7].try_into().expect("seven"),
        intent_digest: words[7..14].try_into().expect("seven"),
        threshold: words[14],
        signer_count: words[15],
        approval_count: words[16],
        approved_slots: core::array::from_fn(|i| words[17 + i] == 1),
    })
}
fn encrypt_output<R: RngCore + ?Sized>(
    address: &ShieldedAddress,
    amount: u64,
    rng: &mut R,
) -> Result<(SmallwoodPoseidon2V8NoteOpening, Vec<u8>, [u8; 32]), WalletError> {
    if address.version != POSEIDON2_V8_ADDRESS_VERSION
        || address.crypto_suite != protocol_versioning::CRYPTO_SUITE_ETA
    {
        return Err(invalid("treasury destination requires a V8 address"));
    }
    let mut note = SmallwoodPoseidon2V8NoteOpening {
        value: amount,
        asset_id: NATIVE,
        recipient_key: poseidon2_v8_words_from_canonical_bytes(address.pk_recipient)
            .map_err(surface)?,
        rho: random_words(rng),
        randomness: random_words(rng),
        ..SmallwoodPoseidon2V8NoteOpening::ZERO
    };
    set_authorization(&mut note, address_authorization(address)?);
    let plaintext = NotePlaintext {
        value: amount,
        asset_id: NATIVE,
        rho: poseidon2_v8_words_to_bytes(note.rho),
        r: poseidon2_v8_words_to_bytes(note.randomness),
        memo: MemoPlaintext::default(),
    };
    let mut kem_seed = [0u8; 32];
    rng.fill_bytes(&mut kem_seed);
    let bytes =
        NoteCiphertext::encrypt_with_kem_seed(address, &plaintext, &kem_seed)?.to_da_bytes()?;
    if bytes.len() != SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES {
        return Err(invalid("wrong treasury output ciphertext length"));
    }
    Ok((note, bytes, kem_seed))
}

impl V8TreasuryPlan {
    pub fn create<R: RngCore + CryptoRng>(
        descriptor: &V8TreasuryDescriptor,
        source: &V8TreasuryNote,
        path: V8TreasuryNotePath,
        recipient: &ShieldedAddress,
        amount: u64,
        fee: u64,
        rng: &mut R,
    ) -> Result<Self, WalletError> {
        descriptor.validate()?;
        if source.kind != V8TreasuryNoteKind::Value
            || source.commitment != path.commitment
            || path.position >= 1u64 << 32
        {
            return Err(invalid("treasury source is not a canonical value note"));
        }
        let note = note_from_words(&source.note_words)?;
        descriptor.receive_note(note)?;
        if amount == 0 || amount.checked_add(fee).map_or(true, |sum| sum > note.value) {
            return Err(invalid("treasury amount and fee exceed one value note"));
        }
        let change = note.value - amount - fee;
        let (payment, payment_ct, payment_seed) = encrypt_output(recipient, amount, rng)?;
        let change_output = if change > 0 {
            Some(encrypt_output(&descriptor.receive_address, change, rng)?)
        } else {
            None
        };
        let mut base = SmallwoodPoseidon2V8PublicStatement {
            input_flags: [true, true],
            output_flags: [true, change > 0],
            fee,
            merkle_root: path.anchor,
            ..SmallwoodPoseidon2V8PublicStatement::default()
        };
        base.nullifiers[0] =
            rp06_policy_note_nullifier(descriptor.policy_nullifier_key, path.position, note.rho)
                .map_err(surface)?;
        // The reviewable plan precedes its approvals. This active-slot placeholder
        // satisfies the public codec; the final builder replaces it with the
        // canonical accumulator nullifier. RP06 deliberately omits this slot
        // from the payment intent, so this does not authorize a different spend.
        base.nullifiers[1] = [1; 7];
        let mut output_note_words = [note_to_words(payment), Vec::new()];
        let mut output_ciphertexts = [Some(payment_ct), None];
        let mut output_kem_seeds = [Some(payment_seed), None];
        if let Some((opening, ct, seed)) = change_output {
            output_note_words[1] = note_to_words(opening);
            output_ciphertexts[1] = Some(ct);
            output_kem_seeds[1] = Some(seed);
        }
        for i in 0..2 {
            if let Some(ct) = &output_ciphertexts[i] {
                base.commitments[i] =
                    poseidon2_v8_note_commitment(note_from_words(&output_note_words[i])?)
                        .map_err(surface)?;
                base.ciphertext_commitments[i] = output_ciphertext_commitment(ct)?;
            }
        }
        let statement = Rp06PublicStatement {
            base,
            chain_id: descriptor.chain_id,
        };
        let result = Self {
            account_id: descriptor.account_id,
            source_commitment: source.commitment,
            source_position: path.position,
            source_note_words: source.note_words.clone(),
            recipient_address: recipient.clone(),
            public_words: statement.to_public_words().to_vec(),
            output_note_words,
            output_ciphertexts,
            output_kem_seeds: Some(output_kem_seeds),
            intent_digest: statement.expected_action_intent().map_err(surface)?,
        };
        result.validate(descriptor)?;
        Ok(result)
    }
    pub fn validate(&self, descriptor: &V8TreasuryDescriptor) -> Result<(), WalletError> {
        descriptor.validate()?;
        let statement =
            Rp06PublicStatement::try_from_public_words(&self.public_words).map_err(surface)?;
        let source = note_from_words(&self.source_note_words)?;
        if self.account_id != descriptor.account_id
            || statement.chain_id != descriptor.chain_id
            || statement.base.input_flags != [true, true]
            || poseidon2_v8_note_commitment(source).map_err(surface)? != self.source_commitment
            || descriptor.receive_note(source)?.commitment != self.source_commitment
            || rp06_policy_note_nullifier(
                descriptor.policy_nullifier_key,
                self.source_position,
                source.rho,
            )
            .map_err(surface)?
                != statement.base.nullifiers[0]
            || statement.expected_action_intent().map_err(surface)? != self.intent_digest
        {
            return Err(invalid(
                "treasury plan source, policy or exact intent changed",
            ));
        }
        let kem_seeds = self.output_kem_seeds.as_ref().ok_or(invalid(
            "legacy treasury plan requires recreation and fresh review",
        ))?;
        let mut total = statement.base.fee;
        for i in 0..2 {
            match (&self.output_ciphertexts[i], statement.base.output_flags[i]) {
                (Some(ct), true) => {
                    let opening = note_from_words(&self.output_note_words[i])?;
                    if ct.len() != SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES
                        || opening.value == 0
                        || opening.asset_id != NATIVE
                        || poseidon2_v8_note_commitment(opening).map_err(surface)?
                            != statement.base.commitments[i]
                        || output_ciphertext_commitment(ct)?
                            != statement.base.ciphertext_commitments[i]
                    {
                        return Err(invalid("treasury plan output changed"));
                    }
                    total = total
                        .checked_add(opening.value)
                        .ok_or(invalid("treasury plan balance overflow"))?;
                    if i == 1 {
                        descriptor.receive_note(opening)?;
                    } else if opening.recipient_key
                        != poseidon2_v8_words_from_canonical_bytes(
                            self.recipient_address.pk_recipient,
                        )
                        .map_err(surface)?
                        || note_authorization(opening)
                            != address_authorization(&self.recipient_address)?
                    {
                        return Err(invalid(
                            "treasury payment differs from the reviewed recipient address",
                        ));
                    }
                    let address = if i == 0 {
                        &self.recipient_address
                    } else {
                        &descriptor.receive_address
                    };
                    let seed = kem_seeds[i]
                        .as_ref()
                        .ok_or(invalid("treasury output lacks private encryption witness"))?;
                    let plaintext = NotePlaintext {
                        value: opening.value,
                        asset_id: opening.asset_id,
                        rho: poseidon2_v8_words_to_bytes(opening.rho),
                        r: poseidon2_v8_words_to_bytes(opening.randomness),
                        memo: MemoPlaintext::default(),
                    };
                    if NoteCiphertext::encrypt_with_kem_seed(address, &plaintext, seed)
                        .and_then(|ciphertext| ciphertext.to_da_bytes())
                        .map_err(surface)?
                        != *ct
                    {
                        return Err(invalid(
                            "treasury output ciphertext does not encrypt its reviewed opening to the exact address",
                        ));
                    }
                }
                (None, false) if self.output_note_words[i].is_empty() && kem_seeds[i].is_none() => {
                }
                _ => return Err(invalid("treasury plan ciphertext/activity mismatch")),
            }
        }
        if !statement.base.output_flags[0] || total != source.value {
            return Err(invalid("treasury plan does not conserve value"));
        }
        Ok(())
    }
    pub fn review_digest(&self) -> Result<[u8; 64], WalletError> {
        // Preserve the original digest for migrated V14 records so exact retained
        // attempts remain addressable. This digest cannot authorize new work.
        let encoded = if self.output_kem_seeds.is_none() {
            bincode::serialize(&V8TreasuryPlanV14 {
                account_id: self.account_id,
                source_commitment: self.source_commitment,
                source_position: self.source_position,
                source_note_words: self.source_note_words.clone(),
                recipient_address: self.recipient_address.clone(),
                public_words: self.public_words.clone(),
                output_note_words: self.output_note_words.clone(),
                output_ciphertexts: self.output_ciphertexts.clone(),
                intent_digest: self.intent_digest,
            })
            .map_err(surface)?
        } else {
            bincode::serialize(self).map_err(surface)?
        };
        let mut hash = Sha512::new();
        hash.update(b"hegemon.wallet.rp06.exact-operation-review.v1");
        hash.update(encoded);
        Ok(hash.finalize().into())
    }
    pub fn has_private_output_encryption_witness(&self) -> bool {
        self.output_kem_seeds.is_some()
    }
    /// Call only after the user reviews recipient, amount, fee, network and exact operation.
    pub fn acknowledge_review(
        &self,
        descriptor: &V8TreasuryDescriptor,
    ) -> Result<V8TreasuryReviewedPlan, WalletError> {
        self.validate(descriptor)?;
        Ok(V8TreasuryReviewedPlan {
            account_id: self.account_id,
            digest: self.review_digest()?,
        })
    }
    fn check_review(&self, review: &V8TreasuryReviewedPlan) -> Result<(), WalletError> {
        if review.account_id != self.account_id || review.digest != self.review_digest()? {
            return Err(invalid(
                "explicit review does not authorize these exact operation bytes",
            ));
        }
        Ok(())
    }
    fn outputs(
        &self,
    ) -> Result<
        (
            [SmallwoodPoseidon2V8OutputWitness; 2],
            SmallwoodPoseidon2V8InlineCiphertexts,
        ),
        WalletError,
    > {
        let mut outputs = [SmallwoodPoseidon2V8OutputWitness::ZERO; 2];
        let mut ciphertexts = [None, None];
        for i in 0..2 {
            if let Some(ct) = &self.output_ciphertexts[i] {
                outputs[i] = SmallwoodPoseidon2V8OutputWitness {
                    active: true,
                    note: note_from_words(&self.output_note_words[i])?,
                    balance_slot_selectors: [true, false, false, false],
                };
                ciphertexts[i] = Some(
                    ct.as_slice()
                        .try_into()
                        .map_err(|_| invalid("wrong treasury ciphertext length"))?,
                );
            }
        }
        Ok((
            outputs,
            SmallwoodPoseidon2V8InlineCiphertexts { ciphertexts },
        ))
    }
}
fn checked_note_input(
    note: SmallwoodPoseidon2V8NoteOpening,
    path: V8TreasuryNotePath,
    spend_key: [u64; 5],
) -> Result<SmallwoodPoseidon2V8InputWitness, WalletError> {
    if path.commitment != poseidon2_v8_note_commitment(note).map_err(surface)?
        || path.position >= 1u64 << 32
    {
        return Err(invalid("treasury input path/opening mismatch"));
    }
    Ok(SmallwoodPoseidon2V8InputWitness {
        active: true,
        spend_key,
        note,
        position: path.position,
        siblings: path.siblings,
        balance_slot_selectors: [true, false, false, false],
    })
}
fn checked_accumulator(
    descriptor: &V8TreasuryDescriptor,
    plan: &V8TreasuryPlan,
    note: &V8TreasuryNote,
) -> Result<
    (
        SmallwoodPoseidon2V8NoteOpening,
        SmallwoodPoseidon2V8AccumulatorOpening,
    ),
    WalletError,
> {
    let V8TreasuryNoteKind::Accumulator { opening_words } = &note.kind else {
        return Err(invalid("expected treasury approval accumulator"));
    };
    let opening = accumulator_from_words(opening_words)?;
    let value = note_from_words(&note.note_words)?;
    if opening.policy_root != descriptor.policy_root
        || opening.intent_digest != plan.intent_digest
        || opening.threshold != 2
        || opening.signer_count != 3
        || opening.approval_count
            != opening
                .approved_slots
                .iter()
                .filter(|value| **value)
                .count() as u64
        || opening.approved_slots[3..].iter().any(|value| *value)
        || value.value != 0
        || value.asset_id != NATIVE
        || note.commitment != poseidon2_v8_note_commitment(value).map_err(surface)?
        || note_authorization(value)
            != rp06_accumulator_authorization(opening, descriptor.policy_nullifier_key)
                .map_err(surface)?
    {
        return Err(invalid(
            "approval accumulator belongs to a different operation/policy",
        ));
    }
    Ok((value, opening))
}
/// Each approval consumes a real positive SingleKey capability note belonging to that signer.
/// The source relation proves exactly one new distinct bit; descriptor knowledge is insufficient.
#[allow(clippy::too_many_arguments)]
pub fn build_v8_treasury_approval<R: RngCore + CryptoRng>(
    descriptor: &V8TreasuryDescriptor,
    plan: &V8TreasuryPlan,
    review: &V8TreasuryReviewedPlan,
    signer: &DerivedKeys,
    capability: SmallwoodPoseidon2V8InputWitness,
    capability_address_index: u32,
    current: Option<(&V8TreasuryNote, V8TreasuryNotePath)>,
    anchor: [u64; 7],
    parent_height: u64,
    fee: u64,
    rng: &mut R,
) -> Result<(V8TreasurySpendMaterial, V8TreasuryNote), WalletError> {
    plan.validate(descriptor)?;
    plan.check_review(review)?;
    let slot = descriptor.signer_slot(signer)?;
    let spend = signer.spend.poseidon2_v8_words()?;
    if !capability.active
        || capability.spend_key != spend
        || capability.note.asset_id != NATIVE
        || capability.note.value == 0
        || capability.note.value < fee
        || note_authorization(capability.note) != v8_treasury_signer_tag(signer)?
    {
        return Err(invalid(
            "approval requires a positive capability owned by this signer",
        ));
    }
    let mut inputs = [SmallwoodPoseidon2V8InputWitness::ZERO, capability];
    let mut opening = SmallwoodPoseidon2V8AccumulatorOpening {
        policy_root: descriptor.policy_root,
        intent_digest: plan.intent_digest,
        threshold: 2,
        signer_count: 3,
        ..SmallwoodPoseidon2V8AccumulatorOpening::ZERO
    };
    if let Some((note, path)) = current {
        let (value, existing) = checked_accumulator(descriptor, plan, note)?;
        if path.anchor != anchor || path.position == capability.position {
            return Err(invalid(
                "approval inputs do not share a current canonical anchor",
            ));
        }
        opening = existing;
        inputs[0] = checked_note_input(value, path, spend)?;
    }
    if opening.approved_slots[slot] || opening.approval_count >= 2 {
        return Err(invalid(
            "signer is duplicate or treasury approval is already complete",
        ));
    }
    let mut next = opening;
    next.approved_slots[slot] = true;
    next.approval_count += 1;
    let mut accumulator_address = descriptor.receive_address.clone();
    let digest =
        rp06_accumulator_authorization(next, descriptor.policy_nullifier_key).map_err(surface)?;
    accumulator_address.pk_auth =
        poseidon2_v8_words_to_bytes(digest[..4].try_into().expect("four"));
    for (i, word) in digest[4..].iter().enumerate() {
        accumulator_address.pk_auth_extension[i * 8..i * 8 + 8]
            .copy_from_slice(&word.to_le_bytes());
    }
    let (accumulator, accumulator_ct, _) = encrypt_output(&accumulator_address, 0, rng)?;
    let mut outputs = [
        SmallwoodPoseidon2V8OutputWitness {
            active: true,
            note: accumulator,
            balance_slot_selectors: [true, false, false, false],
        },
        SmallwoodPoseidon2V8OutputWitness::ZERO,
    ];
    let mut ciphertexts = [Some(accumulator_ct), None];
    if capability.note.value > fee {
        let address = signer
            .poseidon2_v8_address(capability_address_index)?
            .shielded_address();
        let (change, ct, _) = encrypt_output(&address, capability.note.value - fee, rng)?;
        outputs[1] = SmallwoodPoseidon2V8OutputWitness {
            active: true,
            note: change,
            balance_slot_selectors: [true, false, false, false],
        };
        ciphertexts[1] = Some(ct);
    }
    let mut base = SmallwoodPoseidon2V8PublicStatement {
        input_flags: [inputs[0].active, true],
        output_flags: outputs.map(|output| output.active),
        fee,
        merkle_root: anchor,
        ..SmallwoodPoseidon2V8PublicStatement::default()
    };
    base.stablecoin.parent_height = parent_height;
    for i in 0..2 {
        if inputs[i].active {
            let key = if i == 0 {
                descriptor.policy_nullifier_key
            } else {
                spend
            };
            base.nullifiers[i] =
                rp06_policy_note_nullifier(key, inputs[i].position, inputs[i].note.rho)
                    .map_err(surface)?;
        }
        if outputs[i].active {
            base.commitments[i] = poseidon2_v8_note_commitment(outputs[i].note).map_err(surface)?;
            base.ciphertext_commitments[i] =
                output_ciphertext_commitment(ciphertexts[i].as_ref().expect("active"))?;
        }
    }
    let witness = SmallwoodPoseidon2V8Witness {
        inputs,
        outputs,
        auth: SmallwoodPoseidon2V8PrivateAuthWitness {
            mode: SmallwoodPrivateAuthMode::ApprovalStep,
            policy_nullifier_key: descriptor.policy_nullifier_key,
            current: opening,
            next,
            policy_signer_tags: descriptor.signer_tags,
        },
        ..SmallwoodPoseidon2V8Witness::default()
    };
    let statement = Rp06PublicStatement {
        base,
        chain_id: descriptor.chain_id,
    };
    compile_rp06_relation(statement, &witness).map_err(surface)?;
    let inline_ciphertexts = SmallwoodPoseidon2V8InlineCiphertexts {
        ciphertexts: core::array::from_fn(|i| {
            ciphertexts[i]
                .as_ref()
                .map(|ct| ct.as_slice().try_into().expect("fixed length"))
        }),
    };
    let tracker = V8TreasuryNote {
        commitment: base.commitments[0],
        note_words: note_to_words(accumulator),
        kind: V8TreasuryNoteKind::Accumulator {
            opening_words: accumulator_words(next),
        },
    };
    Ok((
        V8TreasurySpendMaterial {
            statement,
            witness,
            inline_ciphertexts,
        },
        tracker,
    ))
}
#[allow(clippy::too_many_arguments)]
pub fn build_v8_treasury_final(
    descriptor: &V8TreasuryDescriptor,
    plan: &V8TreasuryPlan,
    review: &V8TreasuryReviewedPlan,
    value_path: V8TreasuryNotePath,
    accumulator: &V8TreasuryNote,
    accumulator_path: V8TreasuryNotePath,
    parent_height: u64,
) -> Result<V8TreasurySpendMaterial, WalletError> {
    plan.validate(descriptor)?;
    plan.check_review(review)?;
    let (accumulator_note, opening) = checked_accumulator(descriptor, plan, accumulator)?;
    if opening.approval_count < 2
        || value_path.anchor != accumulator_path.anchor
        || value_path.position != plan.source_position
        || value_path.commitment != plan.source_commitment
        || value_path.position == accumulator_path.position
    {
        return Err(invalid("final treasury spend requires two canonical distinct approvals and the reviewed source"));
    }
    let mut statement =
        Rp06PublicStatement::try_from_public_words(&plan.public_words).map_err(surface)?;
    statement.base.merkle_root = value_path.anchor;
    statement.base.stablecoin.parent_height = parent_height;
    statement.base.nullifiers[1] = rp06_policy_note_nullifier(
        descriptor.policy_nullifier_key,
        accumulator_path.position,
        accumulator_note.rho,
    )
    .map_err(surface)?;
    let (outputs, inline_ciphertexts) = plan.outputs()?;
    let witness = SmallwoodPoseidon2V8Witness {
        inputs: [
            checked_note_input(
                note_from_words(&plan.source_note_words)?,
                value_path,
                descriptor.policy_nullifier_key,
            )?,
            checked_note_input(
                accumulator_note,
                accumulator_path,
                descriptor.policy_nullifier_key,
            )?,
        ],
        outputs,
        auth: SmallwoodPoseidon2V8PrivateAuthWitness {
            mode: SmallwoodPrivateAuthMode::FinalThresholdSpend,
            policy_nullifier_key: descriptor.policy_nullifier_key,
            current: opening,
            next: SmallwoodPoseidon2V8AccumulatorOpening::ZERO,
            policy_signer_tags: descriptor.signer_tags,
        },
        ..SmallwoodPoseidon2V8Witness::default()
    };
    if statement.expected_action_intent().map_err(surface)? != plan.intent_digest {
        return Err(invalid(
            "final treasury source or payment changed after approval",
        ));
    }
    compile_rp06_relation(statement, &witness).map_err(surface)?;
    Ok(V8TreasurySpendMaterial {
        statement,
        witness,
        inline_ciphertexts,
    })
}
fn attempt_statement(attempt: &V8TreasuryAttempt) -> Result<Rp06PublicStatement, WalletError> {
    Rp06PublicStatement::try_from_public_words(
        &attempt
            .material_snapshot
            .as_ref()
            .ok_or(invalid("treasury attempt lacks its exact reference"))?
            .public_words,
    )
    .map_err(surface)
}
fn reference_attached(
    attempt: &V8TreasuryAttempt,
    mirror: &crate::poseidon2_v8_sync::Poseidon2V8WalletState,
) -> Result<bool, WalletError> {
    use hegemon_field::{Goldilocks, PrimeCharacteristicRing};
    let statement = attempt_statement(attempt)?;
    let Some(reference) = mirror.canonical_tip_at_height(statement.base.stablecoin.parent_height)
    else {
        return Ok(false);
    };
    let tip = mirror.tip()?;
    Ok(reference.anchor == statement.base.merkle_root
        && reference.stablecoin_root.is_some()
        && reference.stablecoin_root == tip.stablecoin_root
        && reference
            .stablecoin_root
            .map(|root| root.map(Goldilocks::from_u64))
            == Some(statement.base.stablecoin.before_root)
        && statement.base.stablecoin.before_root == statement.base.stablecoin.after_root)
}
fn attempt_inputs_available(
    attempt: &V8TreasuryAttempt,
    mirror: &crate::poseidon2_v8_sync::Poseidon2V8WalletState,
) -> Result<bool, WalletError> {
    let statement = attempt_statement(attempt)?;
    let nullifiers: Vec<_> = (0..2)
        .filter(|i| statement.base.input_flags[*i])
        .map(|i| statement.base.nullifiers[i])
        .collect();
    if nullifiers != attempt.nullifiers
        || nullifiers.is_empty()
        || attempt.ordinary_note_refs.len() + attempt.policy_note_refs.len() != nullifiers.len()
        || nullifiers
            .iter()
            .any(|nf| mirror.has_canonical_nullifier(*nf))
    {
        return Ok(false);
    }
    for (commitment, position) in attempt
        .ordinary_note_refs
        .iter()
        .chain(&attempt.policy_note_refs)
    {
        if mirror
            .canonical_note_witness_at(*commitment, *position)?
            .is_none()
        {
            return Ok(false);
        }
    }
    Ok(true)
}
fn attempt_reference_ready(
    attempt: &V8TreasuryAttempt,
    mirror: &crate::poseidon2_v8_sync::Poseidon2V8WalletState,
) -> Result<bool, WalletError> {
    let reference = attempt_statement(attempt)?.base.stablecoin.parent_height;
    Ok(
        protocol_versioning::launch_reference_policy::launch_reference_distance_allowed(
            reference,
            mirror.tip()?.height,
            false,
        ) && reference_attached(attempt, mirror)?
            && attempt_inputs_available(attempt, mirror)?,
    )
}
fn attempt_future_source_available(
    record: &StoredV8Treasury,
    attempt: &V8TreasuryAttempt,
    mirror: &crate::poseidon2_v8_sync::Poseidon2V8WalletState,
) -> Result<bool, WalletError> {
    for plan in &record.plans {
        if plan.review_digest()?.as_slice() == attempt.review_digest.as_slice() {
            plan.validate(&record.descriptor)?;
            let future =
                Rp06PublicStatement::try_from_public_words(&plan.public_words).map_err(surface)?;
            return Ok(mirror
                .canonical_note_witness_at(plan.source_commitment, plan.source_position)?
                .is_some()
                && !mirror.has_canonical_nullifier(future.base.nullifiers[0]));
        }
    }
    Ok(false)
}
fn attempt_abandonment_allowed(
    attempt: &V8TreasuryAttempt,
    mirror: &crate::poseidon2_v8_sync::Poseidon2V8WalletState,
) -> Result<bool, WalletError> {
    let last_parent = attempt_statement(attempt)?
        .base
        .stablecoin
        .parent_height
        .checked_add(protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW)
        .ok_or(invalid("treasury reference window overflow"))?;
    Ok(mirror.tip()?.height > last_parent
        && attempt.status != V8TreasuryAttemptStatus::Mined
        && reference_attached(attempt, mirror)?
        && attempt_inputs_available(attempt, mirror)?)
}
fn attempt_reservation_active(
    attempt: &V8TreasuryAttempt,
    mirror: &crate::poseidon2_v8_sync::Poseidon2V8WalletState,
) -> bool {
    attempt.status != V8TreasuryAttemptStatus::Abandoned
        || attempt_reference_ready(attempt, mirror).unwrap_or(true)
}
/// Retain all records and bytes. Expired Abandoned reservations reactivate only
/// when their exact canonical checkpoint and unspent inputs return within Href+12.
pub(crate) fn active_reserved_nullifiers(
    treasuries: &[StoredV8Treasury],
    mirror: &crate::poseidon2_v8_sync::Poseidon2V8WalletState,
) -> std::collections::HashSet<[u64; 7]> {
    treasuries
        .iter()
        .flat_map(|treasury| treasury.attempts.iter())
        .filter(|attempt| attempt_reservation_active(attempt, mirror))
        .flat_map(|attempt| attempt.nullifiers.iter().copied())
        .collect()
}

impl crate::WalletStore {
    pub fn import_v8_treasury_descriptor(
        &self,
        descriptor: V8TreasuryDescriptor,
    ) -> Result<(), WalletError> {
        descriptor.validate()?;
        let keys = self.derived_keys()?.ok_or(WalletError::WatchOnly)?;
        descriptor.signer_slot(&keys)?;
        self.with_v8_treasuries_mut(|treasuries, _, _| {
            if let Some(existing) = treasuries
                .iter()
                .find(|record| record.descriptor.account_id == descriptor.account_id)
            {
                if existing.descriptor == descriptor {
                    return Ok(());
                }
                return Err(invalid(
                    "treasury account id collides with different private descriptor",
                ));
            }
            treasuries.push(StoredV8Treasury {
                descriptor,
                notes: Vec::new(),
                plans: Vec::new(),
                attempts: Vec::new(),
            });
            Ok(())
        })
    }
    pub fn v8_treasury_descriptors(&self) -> Result<Vec<V8TreasuryDescriptor>, WalletError> {
        self.with_v8_treasuries(|treasuries, _| {
            Ok(treasuries
                .iter()
                .map(|record| record.descriptor.clone())
                .collect())
        })
    }
    pub fn v8_treasury_notes(
        &self,
        account_id: [u8; 32],
    ) -> Result<Vec<V8TreasuryNote>, WalletError> {
        self.with_v8_treasuries(|treasuries, _| {
            Ok(treasuries
                .iter()
                .find(|record| record.descriptor.account_id == account_id)
                .ok_or(invalid("unknown V8 treasury"))?
                .notes
                .clone())
        })
    }
    /// Finish a provisional descriptor's network binding before any receipt or operation.
    /// The permanent address is unchanged; a pinned launch context, when present, must agree.
    pub fn bind_v8_treasury_network_before_activity(
        &self,
        account_id: [u8; 32],
        chain_id: [u8; 32],
    ) -> Result<V8TreasuryDescriptor, WalletError> {
        match self.launch_chain_id() {
            Ok(expected) if expected != chain_id => {
                return Err(invalid(
                    "treasury network differs from the trusted launch context",
                ))
            }
            Ok(_) | Err(WalletError::InvalidState("wallet launch context is not pinned")) => (),
            Err(error) => return Err(error),
        }
        self.with_v8_treasuries_mut(|treasuries, _, _| {
            let record = treasuries
                .iter_mut()
                .find(|record| record.descriptor.account_id == account_id)
                .ok_or(invalid("unknown V8 treasury"))?;
            if !record.notes.is_empty() || !record.plans.is_empty() || !record.attempts.is_empty() {
                return Err(invalid(
                    "treasury network cannot change after receipt or operation activity",
                ));
            }
            let address = record.descriptor.receive_address.clone();
            record.descriptor.chain_id = chain_id;
            record.descriptor.validate()?;
            if record.descriptor.receive_address != address {
                return Err(invalid(
                    "network binding changed the permanent treasury address",
                ));
            }
            Ok(record.descriptor.clone())
        })
    }
    pub fn v8_treasury_plans(
        &self,
        account_id: [u8; 32],
    ) -> Result<Vec<V8TreasuryPlan>, WalletError> {
        self.with_v8_treasuries(|treasuries, _| {
            Ok(treasuries
                .iter()
                .find(|record| record.descriptor.account_id == account_id)
                .ok_or(invalid("unknown V8 treasury"))?
                .plans
                .clone())
        })
    }
    /// Remember a validated opening only after its commitment is present in the verified mirror.
    /// Exact position selection remains mandatory when a commitment has multiple occurrences.
    pub fn track_v8_treasury_note(
        &self,
        account_id: [u8; 32],
        note: V8TreasuryNote,
        position: u64,
    ) -> Result<(), WalletError> {
        self.with_v8_treasuries_mut(|treasuries, mirror, _| {
            let record = treasuries
                .iter_mut()
                .find(|record| record.descriptor.account_id == account_id)
                .ok_or(invalid("unknown V8 treasury"))?;
            let opening = note_from_words(&note.note_words)?;
            if poseidon2_v8_note_commitment(opening).map_err(surface)? != note.commitment {
                return Err(invalid("treasury tracker opening/commitment mismatch"));
            }
            match &note.kind {
                V8TreasuryNoteKind::Value => {
                    record.descriptor.receive_note(opening)?;
                }
                V8TreasuryNoteKind::Accumulator { opening_words } => {
                    let intent = accumulator_from_words(opening_words)?.intent_digest;
                    let plan = record
                        .plans
                        .iter()
                        .find(|plan| plan.intent_digest == intent)
                        .ok_or(invalid("approval note has no reviewed local plan"))?;
                    checked_accumulator(&record.descriptor, plan, &note)?;
                }
            }
            if mirror
                .canonical_note_witness_at(note.commitment, position)?
                .is_none()
            {
                return Err(invalid("treasury note is absent from the canonical mirror"));
            }
            if let Some(previous) = record
                .notes
                .iter()
                .find(|previous| previous.commitment == note.commitment)
            {
                if previous == &note {
                    return Ok(());
                }
                return Err(invalid(
                    "treasury commitment collides with different opening",
                ));
            }
            record.notes.push(note);
            Ok(())
        })
    }
    pub fn persist_v8_treasury_plan(&self, plan: V8TreasuryPlan) -> Result<(), WalletError> {
        self.with_v8_treasuries_mut(|treasuries, mirror, _| {
            let record = treasuries
                .iter_mut()
                .find(|record| record.descriptor.account_id == plan.account_id)
                .ok_or(invalid("unknown V8 treasury"))?;
            plan.validate(&record.descriptor)?;
            if mirror
                .canonical_note_witness_at(plan.source_commitment, plan.source_position)?
                .is_none()
            {
                return Err(invalid(
                    "treasury plan source has detached from the canonical chain",
                ));
            }
            let statement =
                Rp06PublicStatement::try_from_public_words(&plan.public_words).map_err(surface)?;
            if mirror.has_canonical_nullifier(statement.base.nullifiers[0]) {
                return Err(invalid("treasury plan source is already spent"));
            }
            let digest = plan.review_digest()?;
            if let Some(previous) = record
                .plans
                .iter()
                .find(|previous| previous.review_digest().ok() == Some(digest))
            {
                if previous == &plan {
                    return Ok(());
                }
                return Err(invalid("treasury plan review digest collision"));
            }
            record.plans.push(plan);
            Ok(())
        })
    }
    /// Reserve exact proven input references atomically before expensive proof production.
    /// The operation is rejected if any ordinary/HTLC/treasury attempt already owns an input.
    pub fn reserve_v8_treasury_attempt(
        &self,
        account_id: [u8; 32],
        plan: &V8TreasuryPlan,
        material: &V8TreasurySpendMaterial,
    ) -> Result<usize, WalletError> {
        compile_rp06_relation(material.statement, &material.witness).map_err(surface)?;
        if material.statement.chain_id
            != Rp06PublicStatement::try_from_public_words(&plan.public_words)
                .map_err(surface)?
                .chain_id
            || material.witness.auth.current.intent_digest != plan.intent_digest
        {
            return Err(invalid(
                "treasury proof reservation belongs to another operation",
            ));
        }
        self.with_v8_treasuries_mut(|treasuries, mirror, other_reserved| {
            let owned = active_reserved_nullifiers(treasuries, mirror);
            let index = treasuries
                .iter()
                .position(|record| record.descriptor.account_id == account_id)
                .ok_or(invalid("unknown V8 treasury"))?;
            plan.validate(&treasuries[index].descriptor)?;
            let reviewed_statement =
                Rp06PublicStatement::try_from_public_words(&plan.public_words).map_err(surface)?;
            if mirror
                .canonical_note_witness_at(plan.source_commitment, plan.source_position)?
                .is_none()
                || mirror.has_canonical_nullifier(reviewed_statement.base.nullifiers[0])
            {
                return Err(invalid(
                    "reviewed treasury value source is detached or spent",
                ));
            }
            let descriptor = &treasuries[index].descriptor;
            if material.witness.auth.policy_nullifier_key != descriptor.policy_nullifier_key
                || material.witness.auth.policy_signer_tags != descriptor.signer_tags
                || material.witness.auth.current.policy_root != descriptor.policy_root
                || material.witness.auth.current.threshold != 2
                || material.witness.auth.current.signer_count != 3
                || !matches!(
                    material.witness.auth.mode,
                    SmallwoodPrivateAuthMode::ApprovalStep
                        | SmallwoodPrivateAuthMode::FinalThresholdSpend
                )
            {
                return Err(invalid(
                    "treasury reservation policy differs from the reviewed descriptor",
                ));
            }
            material
                .inline_ciphertexts
                .validate_against_statement(&material.statement.base)
                .map_err(surface)?;
            if !treasuries[index].plans.iter().any(|stored| stored == plan) {
                return Err(invalid("treasury attempt plan is not durably stored"));
            }
            if material.statement.base.merkle_root != mirror.tip()?.anchor {
                return Err(invalid(
                    "treasury attempt requires the current canonical anchor",
                ));
            }
            let mut nullifiers = Vec::new();
            let mut ordinary_note_refs = Vec::new();
            let mut policy_note_refs = Vec::new();
            for i in 0..2 {
                let input = material.witness.inputs[i];
                if !input.active {
                    continue;
                }
                let commitment = poseidon2_v8_note_commitment(input.note).map_err(surface)?;
                let current = mirror
                    .canonical_note_witness_at(commitment, input.position)?
                    .ok_or(invalid(
                        "treasury proof input detached from the canonical chain",
                    ))?;
                if current.anchor != material.statement.base.merkle_root
                    || current.path != input.siblings
                {
                    return Err(invalid("treasury proof path is stale"));
                }
                let nullifier = material.statement.base.nullifiers[i];
                if mirror.has_canonical_nullifier(nullifier)
                    || other_reserved.contains(&nullifier)
                    || owned.contains(&nullifier)
                    || nullifiers.contains(&nullifier)
                {
                    return Err(invalid("treasury input is spent or reserved"));
                }
                nullifiers.push(nullifier);
                if material.witness.auth.mode == SmallwoodPrivateAuthMode::ApprovalStep && i == 1 {
                    ordinary_note_refs.push((commitment, input.position));
                } else {
                    policy_note_refs.push((commitment, input.position));
                }
            }
            let record = &mut treasuries[index];
            // Persist exact future policy output openings atomically with the reservation.
            // Pending openings still cannot be spent until found at a canonical position.
            let future = if material.witness.auth.mode == SmallwoodPrivateAuthMode::ApprovalStep {
                Some(V8TreasuryNote {
                    commitment: material.statement.base.commitments[0],
                    note_words: note_to_words(material.witness.outputs[0].note),
                    kind: V8TreasuryNoteKind::Accumulator {
                        opening_words: accumulator_words(material.witness.auth.next),
                    },
                })
            } else if material.witness.outputs[1].active {
                Some(
                    record
                        .descriptor
                        .receive_note(material.witness.outputs[1].note)?,
                )
            } else {
                None
            };
            if let Some(note) = future {
                if let Some(existing) = record
                    .notes
                    .iter()
                    .find(|existing| existing.commitment == note.commitment)
                {
                    if existing != &note {
                        return Err(invalid(
                            "future treasury opening collides with durable state",
                        ));
                    }
                } else {
                    record.notes.push(note);
                }
            }
            record.attempts.push(V8TreasuryAttempt {
                review_digest: plan.review_digest()?.to_vec(),
                nullifiers,
                ordinary_note_refs,
                policy_note_refs,
                status: V8TreasuryAttemptStatus::Prepared,
                action_id: None,
                mined_in: None,
                material_snapshot: Some(V8TreasuryMaterialSnapshot::from_material(material)),
                candidate_inline: None,
            });
            Ok(record.attempts.len() - 1)
        })
    }
    /// Recover a prepared proof job without releasing any reserved input. Before any
    /// carrier exists, paths and parent context may advance while payment bytes stay exact.
    pub fn recover_v8_treasury_attempt_material(
        &self,
        account_id: [u8; 32],
        attempt_index: usize,
        plan: &V8TreasuryPlan,
        review: &V8TreasuryReviewedPlan,
    ) -> Result<V8TreasurySpendMaterial, WalletError> {
        self.recover_v8_treasury_attempt_material_inner(
            account_id,
            attempt_index,
            plan,
            Some(review),
        )
    }

    /// Continue only an already retained V14 proof job. This path binds to the
    /// old exact plan digest and persisted snapshot; it cannot create approvals.
    pub fn recover_v8_treasury_attempt_material_v14(
        &self,
        account_id: [u8; 32],
        attempt_index: usize,
        plan: &V8TreasuryPlan,
    ) -> Result<V8TreasurySpendMaterial, WalletError> {
        if plan.has_private_output_encryption_witness() {
            return Err(invalid("V14 recovery requires a migrated legacy plan"));
        }
        self.recover_v8_treasury_attempt_material_inner(account_id, attempt_index, plan, None)
    }

    fn recover_v8_treasury_attempt_material_inner(
        &self,
        account_id: [u8; 32],
        attempt_index: usize,
        plan: &V8TreasuryPlan,
        review: Option<&V8TreasuryReviewedPlan>,
    ) -> Result<V8TreasurySpendMaterial, WalletError> {
        if plan.has_private_output_encryption_witness() {
            plan.check_review(review.ok_or(invalid("treasury recovery review is missing"))?)?;
        } else if review.is_some() {
            return Err(invalid(
                "legacy plan cannot reuse its old review for new treasury work",
            ));
        }
        let keys = self.derived_keys()?;
        self.with_v8_treasuries_mut(|treasuries, mirror, other_reserved| {
            let record_index = treasuries
                .iter()
                .position(|record| record.descriptor.account_id == account_id)
                .ok_or(invalid("unknown V8 treasury"))?;
            let record = &treasuries[record_index];
            let reviewed_statement =
                Rp06PublicStatement::try_from_public_words(&plan.public_words).map_err(surface)?;
            if plan.has_private_output_encryption_witness() {
                plan.validate(&record.descriptor)?;
            } else if reviewed_statement
                .expected_action_intent()
                .map_err(surface)?
                != plan.intent_digest
            {
                return Err(invalid("legacy retained plan intent changed"));
            }
            if mirror
                .canonical_note_witness_at(plan.source_commitment, plan.source_position)?
                .is_none()
                || mirror.has_canonical_nullifier(reviewed_statement.base.nullifiers[0])
            {
                return Err(invalid(
                    "recovery reviewed value source is detached or spent",
                ));
            }
            let attempt = record
                .attempts
                .get(attempt_index)
                .ok_or(invalid("unknown treasury attempt"))?;
            if !record.plans.iter().any(|stored| stored == plan)
                || attempt.review_digest != plan.review_digest()?.to_vec()
                || attempt.status != V8TreasuryAttemptStatus::Prepared
                || attempt.action_id.is_some()
                || attempt.candidate_inline.is_some()
            {
                return Err(invalid(
                    "only an unexported prepared treasury proof can be regenerated",
                ));
            }
            if !plan.has_private_output_encryption_witness()
                && (attempt.material_snapshot.is_none()
                    || attempt.review_digest != plan.review_digest()?.to_vec())
            {
                return Err(invalid(
                    "legacy plan has no exact retained recovery snapshot",
                ));
            }
            let mut material = attempt
                .material_snapshot
                .as_ref()
                .ok_or(invalid(
                    "treasury attempt has no recoverable proof material",
                ))?
                .restore(keys.as_ref())?;
            if !plan.has_private_output_encryption_witness() {
                match material.witness.auth.mode {
                    SmallwoodPrivateAuthMode::ApprovalStep => {
                        if material.witness.auth.current.intent_digest != plan.intent_digest {
                            return Err(invalid(
                                "legacy retained approval differs from its exact plan intent",
                            ));
                        }
                    }
                    SmallwoodPrivateAuthMode::FinalThresholdSpend => {
                        if material
                            .statement
                            .expected_action_intent()
                            .map_err(surface)?
                            != plan.intent_digest
                        {
                            return Err(invalid(
                                "legacy retained snapshot differs from its exact plan intent",
                            ));
                        }
                    }
                    _ => {
                        return Err(invalid(
                            "legacy retained snapshot has an unsupported authorization mode",
                        ));
                    }
                }
            }
            let tip = mirror.tip()?;
            let mut current_nullifiers = Vec::new();
            for i in 0..2 {
                let input = &mut material.witness.inputs[i];
                if !input.active {
                    continue;
                }
                let commitment = poseidon2_v8_note_commitment(input.note).map_err(surface)?;
                let path = mirror
                    .canonical_note_witness_at(commitment, input.position)?
                    .ok_or(invalid(
                        "recovery input has detached from the canonical chain",
                    ))?;
                let nullifier = material.statement.base.nullifiers[i];
                let owned_elsewhere =
                    treasuries.iter().enumerate().any(|(other_record, record)| {
                        record
                            .attempts
                            .iter()
                            .enumerate()
                            .any(|(other_attempt, attempt)| {
                                (other_record != record_index || other_attempt != attempt_index)
                                    && attempt_reservation_active(attempt, mirror)
                                    && attempt.nullifiers.contains(&nullifier)
                            })
                    });
                if path.anchor != tip.anchor
                    || mirror.has_canonical_nullifier(nullifier)
                    || other_reserved.contains(&nullifier)
                    || owned_elsewhere
                {
                    return Err(invalid(
                        "recovery input is spent, stale, or reserved by another attempt",
                    ));
                }
                input.siblings = path.path;
                current_nullifiers.push(nullifier);
            }
            if current_nullifiers != attempt.nullifiers {
                return Err(invalid(
                    "recovery would change reserved treasury nullifiers",
                ));
            }
            material.statement.base.merkle_root = tip.anchor;
            material.set_current_context(
                tip.height,
                tip.stablecoin_root
                    .ok_or(invalid("recovery mirror lacks current stablecoin root"))?,
            )?;
            if material.witness.auth.current.intent_digest != plan.intent_digest {
                return Err(invalid(
                    "recovered treasury material changed the reviewed operation",
                ));
            }
            treasuries[record_index].attempts[attempt_index].material_snapshot =
                Some(V8TreasuryMaterialSnapshot::from_material(&material));
            Ok(material)
        })
    }

    pub fn v8_treasury_attempt_ready(
        &self,
        account_id: [u8; 32],
        index: usize,
    ) -> Result<bool, WalletError> {
        let context = self.launch_context()?;
        self.with_v8_treasuries(|treasuries, mirror| {
            let record = treasuries
                .iter()
                .find(|record| record.descriptor.account_id == account_id)
                .ok_or(invalid("unknown V8 treasury"))?;
            let attempt = record
                .attempts
                .get(index)
                .ok_or(invalid("unknown treasury attempt"))?;
            let statement = attempt_statement(attempt)?;
            if record.descriptor.chain_id != context.chain_id()
                || statement.chain_id != context.chain_id()
                || matches!(
                    attempt.status,
                    V8TreasuryAttemptStatus::Abandoned | V8TreasuryAttemptStatus::Mined
                )
                || !attempt_reference_ready(attempt, mirror)?
                || !attempt_future_source_available(record, attempt, mirror)?
            {
                return Ok(false);
            }
            let reference = mirror
                .canonical_tip_at_height(statement.base.stablecoin.parent_height)
                .ok_or(invalid("treasury reference detached"))?;
            Ok(context
                .require_canonical_reference(mirror, reference, false)
                .is_ok())
        })
    }
    /// Release only an explicitly abandoned expired attempt's active reservation,
    /// keeping every proof/material/action receipt for automatic reorg protection.
    pub fn abandon_v8_treasury_attempt(
        &self,
        account_id: [u8; 32],
        index: usize,
        expected_tip: crate::Poseidon2V8CanonicalTip,
    ) -> Result<(), WalletError> {
        let context = self.launch_context()?;
        self.with_v8_treasuries_mut(|treasuries, mirror, _| {
            if mirror.tip()? != expected_tip {
                return Err(invalid(
                    "treasury abandonment requires the current canonical tip",
                ));
            }
            let record = treasuries
                .iter_mut()
                .find(|record| record.descriptor.account_id == account_id)
                .ok_or(invalid("unknown V8 treasury"))?;
            let attempt = record
                .attempts
                .get_mut(index)
                .ok_or(invalid("unknown treasury attempt"))?;
            let statement = attempt_statement(attempt)?;
            if record.descriptor.chain_id != context.chain_id()
                || statement.chain_id != context.chain_id()
                || mirror.canonical_hash(0) != Some(context.genesis_hash())
                || !attempt_abandonment_allowed(attempt, mirror)?
            {
                return Err(invalid(
                    "treasury candidate cannot safely be abandoned before canonical expiry",
                ));
            }
            attempt.status = V8TreasuryAttemptStatus::Abandoned;
            Ok(())
        })
    }

    /// Authenticated encrypted-store read of the unchanged candidate saved before export.
    pub fn v8_treasury_attempt_candidate(
        &self,
        account_id: [u8; 32],
        attempt_index: usize,
    ) -> Result<Option<Vec<u8>>, WalletError> {
        self.with_v8_treasuries(|treasuries, _| {
            Ok(treasuries
                .iter()
                .find(|record| record.descriptor.account_id == account_id)
                .and_then(|record| record.attempts.get(attempt_index))
                .ok_or(invalid("unknown treasury attempt"))?
                .candidate_inline
                .clone())
        })
    }

    /// Persist the complete independently verified carrier before exposing any export file.
    /// Once present, recovery may only re-export these exact bytes.
    pub fn record_v8_treasury_candidate_inline(
        &self,
        account_id: [u8; 32],
        attempt_index: usize,
        bytes: Vec<u8>,
    ) -> Result<(), WalletError> {
        use protocol_shielded_pool::rp06_transport::{
            decode_rp06_inline_args_exact, Rp06ExpectedContext,
        };
        use transaction_circuit::smallwood_poseidon2_v8_rp06::{
            rp06_program_digest, verify_rp06_candidate_bytes,
        };
        let (chain_id, snapshot) = self.with_v8_treasuries(|treasuries, _| {
            let record = treasuries
                .iter()
                .find(|record| record.descriptor.account_id == account_id)
                .ok_or(invalid("unknown V8 treasury"))?;
            let attempt = record
                .attempts
                .get(attempt_index)
                .ok_or(invalid("unknown treasury attempt"))?;
            Ok((
                record.descriptor.chain_id,
                attempt
                    .material_snapshot
                    .clone()
                    .ok_or(invalid("treasury attempt has no exact candidate material"))?,
            ))
        })?;
        let context = Rp06ExpectedContext::new(chain_id, rp06_program_digest()).map_err(surface)?;
        let decoded = decode_rp06_inline_args_exact(context, &bytes)
            .map_err(surface)?
            .native_leaf();
        if decoded.public_words().as_slice() != snapshot.public_words.as_slice()
            || decoded
                .ciphertext(0)
                .into_iter()
                .chain(decoded.ciphertext(1))
                .flat_map(|ciphertext| ciphertext.iter().copied())
                .collect::<Vec<_>>()
                != snapshot.inline_ciphertext_bytes
        {
            return Err(invalid(
                "candidate carrier differs from the durably reserved material",
            ));
        }
        verify_rp06_candidate_bytes(
            &snapshot.public_words,
            rp06_program_digest(),
            decoded.proof(),
            chain_id,
        )
        .map_err(surface)?;
        self.with_v8_treasuries_mut(|treasuries, _, _| {
            let attempt = treasuries
                .iter_mut()
                .find(|record| record.descriptor.account_id == account_id)
                .and_then(|record| record.attempts.get_mut(attempt_index))
                .ok_or(invalid("unknown treasury attempt"))?;
            if attempt.material_snapshot.as_ref() != Some(&snapshot) {
                return Err(invalid(
                    "treasury material changed while verifying the candidate",
                ));
            }
            if let Some(previous) = &attempt.candidate_inline {
                if previous == &bytes {
                    return Ok(());
                }
                return Err(invalid("an exported treasury candidate cannot be replaced"));
            }
            if attempt.status != V8TreasuryAttemptStatus::Prepared || attempt.action_id.is_some() {
                return Err(invalid(
                    "candidate persistence requires a prepared treasury attempt",
                ));
            }
            attempt.candidate_inline = Some(bytes);
            Ok(())
        })
    }

    /// Persist SubmissionUncertain before the first mutating RPC so a timeout never releases inputs.
    pub fn mark_v8_treasury_submission_uncertain(
        &self,
        account_id: [u8; 32],
        attempt: usize,
    ) -> Result<(), WalletError> {
        self.with_v8_treasuries_mut(|treasuries, _, _| {
            let value = treasuries
                .iter_mut()
                .find(|record| record.descriptor.account_id == account_id)
                .and_then(|record| record.attempts.get_mut(attempt))
                .ok_or(invalid("unknown treasury attempt"))?;
            if value.status != V8TreasuryAttemptStatus::Prepared {
                return Err(invalid("treasury attempt is not prepared"));
            }
            value.status = V8TreasuryAttemptStatus::SubmissionUncertain;
            Ok(())
        })
    }
    pub fn mark_v8_treasury_submitted(
        &self,
        account_id: [u8; 32],
        attempt: usize,
        action_id: [u8; 48],
    ) -> Result<(), WalletError> {
        self.with_v8_treasuries_mut(|treasuries, _, _| {
            let value = treasuries
                .iter_mut()
                .find(|record| record.descriptor.account_id == account_id)
                .and_then(|record| record.attempts.get_mut(attempt))
                .ok_or(invalid("unknown treasury attempt"))?;
            if value.status != V8TreasuryAttemptStatus::SubmissionUncertain {
                return Err(invalid(
                    "treasury attempt has no durable uncertain-submission record",
                ));
            }
            value.status = V8TreasuryAttemptStatus::Submitted;
            value.action_id = Some(action_id.to_vec());
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::RootSecret;
    fn path(commitments: &[[u64; 7]], position: usize) -> V8TreasuryNotePath {
        use transaction_circuit::smallwood_poseidon2_v8_coinbase::{
            poseidon2_v8_default_note_nodes, poseidon2_v8_note_tree_compress,
        };
        let defaults = poseidon2_v8_default_note_nodes();
        let mut current = commitments.to_vec();
        let mut index = position;
        let mut siblings = [[0; 7]; 32];
        for level in 0..32 {
            siblings[level] = current.get(index ^ 1).copied().unwrap_or(defaults[level]);
            current = current
                .chunks(2)
                .map(|pair| {
                    poseidon2_v8_note_tree_compress(
                        pair[0],
                        pair.get(1).copied().unwrap_or(defaults[level]),
                    )
                })
                .collect();
            index /= 2;
        }
        V8TreasuryNotePath {
            commitment: commitments[position],
            position: position as u64,
            siblings,
            anchor: current[0],
        }
    }
    fn keys() -> [DerivedKeys; 3] {
        core::array::from_fn(|i| RootSecret::from_bytes([i as u8 + 1; 32]).derive())
    }
    fn caps_note(keys: &DerivedKeys) -> SmallwoodPoseidon2V8NoteOpening {
        encrypt_output(
            &keys.poseidon2_v8_address(0).unwrap().shielded_address(),
            10,
            &mut rand::rngs::OsRng,
        )
        .unwrap()
        .0
    }
    #[test]
    fn poseidon2_v8_multisig_all_pairs_preserve_exact_payment_and_distinct_approvals() {
        for pair in [[0, 1], [0, 2], [1, 2]] {
            let keys = keys();
            let mut rng = rand::rngs::OsRng;
            let descriptor = V8TreasuryDescriptor::create(
                &keys[0],
                [37; 32],
                core::array::from_fn(|i| v8_treasury_signer_tag(&keys[i]).unwrap()),
                &mut rng,
            )
            .unwrap();
            let (value, _, _) = encrypt_output(&descriptor.receive_address, 100, &mut rng).unwrap();
            let source = descriptor.receive_note(value).unwrap();
            let caps: Vec<_> = keys
                .iter()
                .map(|key| {
                    encrypt_output(
                        &key.poseidon2_v8_address(0).unwrap().shielded_address(),
                        10,
                        &mut rng,
                    )
                    .unwrap()
                    .0
                })
                .collect();
            let mut commitments = vec![source.commitment];
            commitments.extend(
                caps.iter()
                    .map(|note| poseidon2_v8_note_commitment(*note).unwrap()),
            );
            let recipient = keys[2].poseidon2_v8_address(4).unwrap().shielded_address();
            let recipient_material = keys[2].poseidon2_v8_address(4).unwrap();
            let plan = V8TreasuryPlan::create(
                &descriptor,
                &source,
                path(&commitments, 0),
                &recipient,
                60,
                1,
                &mut rng,
            )
            .unwrap();
            let payment_opening = note_from_words(&plan.output_note_words[0]).unwrap();
            let payment_ciphertext =
                NoteCiphertext::from_da_bytes(plan.output_ciphertexts[0].as_ref().unwrap())
                    .unwrap();
            let payment_plaintext = payment_ciphertext.decrypt(&recipient_material).unwrap();
            assert_eq!(payment_plaintext.value, payment_opening.value);
            assert_eq!(payment_plaintext.asset_id, payment_opening.asset_id);
            assert_eq!(
                payment_plaintext.rho,
                poseidon2_v8_words_to_bytes(payment_opening.rho)
            );
            assert_eq!(
                payment_plaintext.r,
                poseidon2_v8_words_to_bytes(payment_opening.randomness)
            );
            let change_opening = note_from_words(&plan.output_note_words[1]).unwrap();
            let change_ciphertext =
                NoteCiphertext::from_da_bytes(plan.output_ciphertexts[1].as_ref().unwrap())
                    .unwrap();
            let change_plaintext = change_ciphertext
                .decrypt(&keys[0].poseidon2_v8_address(0).unwrap())
                .unwrap();
            assert_eq!(change_plaintext.value, change_opening.value);
            assert_eq!(change_plaintext.asset_id, change_opening.asset_id);
            assert_eq!(
                change_plaintext.rho,
                poseidon2_v8_words_to_bytes(change_opening.rho)
            );
            assert_eq!(
                change_plaintext.r,
                poseidon2_v8_words_to_bytes(change_opening.randomness)
            );
            let reviewed = plan.acknowledge_review(&descriptor).unwrap();
            let first_cap = checked_note_input(
                caps[pair[0]],
                path(&commitments, pair[0] + 1),
                keys[pair[0]].spend.poseidon2_v8_words().unwrap(),
            )
            .unwrap();
            let (first, first_accumulator) = build_v8_treasury_approval(
                &descriptor,
                &plan,
                &reviewed,
                &keys[pair[0]],
                first_cap,
                0,
                None,
                path(&commitments, 0).anchor,
                1,
                1,
                &mut rng,
            )
            .unwrap();
            let first_snapshot = V8TreasuryMaterialSnapshot::from_material(&first);
            let redacted =
                SmallwoodPoseidon2V8Witness::try_from_witness_words(&first_snapshot.witness_words)
                    .unwrap();
            assert!(redacted
                .inputs
                .iter()
                .all(|input| input.spend_key == [0; 5]));
            let restored_first = first_snapshot.restore(Some(&keys[pair[0]])).unwrap();
            assert_eq!(restored_first.statement, first.statement);
            assert_eq!(restored_first.witness, first.witness);
            assert_eq!(restored_first.inline_ciphertexts, first.inline_ciphertexts);
            assert!(first_snapshot.restore(Some(&keys[pair[1]])).is_err());
            assert!(first_snapshot.restore(None).is_err());
            commitments.extend(first.statement.base.commitments);
            let first_path = path(&commitments, 4);
            assert!(build_v8_treasury_final(
                &descriptor,
                &plan,
                &reviewed,
                path(&commitments, 0),
                &first_accumulator,
                first_path,
                2
            )
            .is_err());
            let dup_cap = checked_note_input(
                caps[pair[0]],
                path(&commitments, pair[0] + 1),
                keys[pair[0]].spend.poseidon2_v8_words().unwrap(),
            )
            .unwrap();
            assert!(build_v8_treasury_approval(
                &descriptor,
                &plan,
                &reviewed,
                &keys[pair[0]],
                dup_cap,
                0,
                Some((&first_accumulator, first_path)),
                first_path.anchor,
                2,
                1,
                &mut rng
            )
            .is_err());
            let second_cap = checked_note_input(
                caps[pair[1]],
                path(&commitments, pair[1] + 1),
                keys[pair[1]].spend.poseidon2_v8_words().unwrap(),
            )
            .unwrap();
            let (second, second_accumulator) = build_v8_treasury_approval(
                &descriptor,
                &plan,
                &reviewed,
                &keys[pair[1]],
                second_cap,
                0,
                Some((&first_accumulator, first_path)),
                first_path.anchor,
                2,
                1,
                &mut rng,
            )
            .unwrap();
            commitments.extend(second.statement.base.commitments);
            let mut final_material = build_v8_treasury_final(
                &descriptor,
                &plan,
                &reviewed,
                path(&commitments, 0),
                &second_accumulator,
                path(&commitments, 6),
                17,
            )
            .unwrap();
            assert_eq!(
                final_material.statement.expected_action_intent().unwrap(),
                plan.intent_digest
            );
            assert_eq!(
                final_material.statement.base.commitments,
                Rp06PublicStatement::try_from_public_words(&plan.public_words)
                    .unwrap()
                    .base
                    .commitments
            );
            assert_eq!(
                final_material
                    .inline_ciphertexts
                    .to_inline_ciphertext_bytes(),
                plan.outputs().unwrap().1.to_inline_ciphertext_bytes()
            );
            final_material.set_current_context(19, [55; 7]).unwrap();
            assert_eq!(
                final_material.statement.expected_action_intent().unwrap(),
                plan.intent_digest
            );
            let final_snapshot = V8TreasuryMaterialSnapshot::from_material(&final_material);
            let restored_final = final_snapshot.restore(None).unwrap();
            assert_eq!(restored_final.statement, final_material.statement);
            assert_eq!(restored_final.witness, final_material.witness);
            assert_eq!(
                restored_final.inline_ciphertexts,
                final_material.inline_ciphertexts
            );
            let approved = final_material.witness.auth.current.approved_slots;
            assert!(approved[descriptor.signer_slot(&keys[pair[0]]).unwrap()]);
            assert!(approved[descriptor.signer_slot(&keys[pair[1]]).unwrap()]);
            assert_eq!(approved.iter().filter(|value| **value).count(), 2);
            let mut changed = plan.clone();
            changed.recipient_address = keys[1].poseidon2_v8_address(3).unwrap().shielded_address();
            assert!(changed.validate(&descriptor).is_err());
            assert!(changed.check_review(&reviewed).is_err());
            let mut changed = plan.clone();
            changed.output_ciphertexts[0].as_mut().unwrap()[20] ^= 1;
            assert!(changed.validate(&descriptor).is_err());
            let mut coherent = plan.clone();
            coherent.output_ciphertexts[0].as_mut().unwrap()[20] ^= 1;
            let mut statement =
                Rp06PublicStatement::try_from_public_words(&coherent.public_words).unwrap();
            statement.base.ciphertext_commitments[0] =
                output_ciphertext_commitment(coherent.output_ciphertexts[0].as_ref().unwrap())
                    .unwrap();
            coherent.public_words = statement.to_public_words().to_vec();
            coherent.intent_digest = statement.expected_action_intent().unwrap();
            assert!(coherent.acknowledge_review(&descriptor).is_err());
            let wrong_address = keys[1].poseidon2_v8_address(8).unwrap().shielded_address();
            let wrong_plaintext = NotePlaintext {
                value: payment_opening.value,
                asset_id: payment_opening.asset_id,
                rho: poseidon2_v8_words_to_bytes(payment_opening.rho),
                r: poseidon2_v8_words_to_bytes(payment_opening.randomness),
                memo: MemoPlaintext::default(),
            };
            let wrong_address_ct =
                NoteCiphertext::encrypt(&wrong_address, &wrong_plaintext, &mut rng)
                    .unwrap()
                    .to_da_bytes()
                    .unwrap();
            let mut wrong_address_plan = plan.clone();
            wrong_address_plan.output_ciphertexts[0] = Some(wrong_address_ct);
            let mut statement =
                Rp06PublicStatement::try_from_public_words(&wrong_address_plan.public_words)
                    .unwrap();
            statement.base.ciphertext_commitments[0] = output_ciphertext_commitment(
                wrong_address_plan.output_ciphertexts[0].as_ref().unwrap(),
            )
            .unwrap();
            wrong_address_plan.public_words = statement.to_public_words().to_vec();
            wrong_address_plan.intent_digest = statement.expected_action_intent().unwrap();
            assert!(wrong_address_plan.acknowledge_review(&descriptor).is_err());
            let mut wrong_suite_plan = plan.clone();
            wrong_suite_plan.recipient_address.crypto_suite =
                protocol_versioning::CRYPTO_SUITE_GAMMA;
            assert!(wrong_suite_plan.acknowledge_review(&descriptor).is_err());
            let mut coherent_change = plan.clone();
            coherent_change.output_ciphertexts[1].as_mut().unwrap()[20] ^= 1;
            let mut statement =
                Rp06PublicStatement::try_from_public_words(&coherent_change.public_words).unwrap();
            statement.base.ciphertext_commitments[1] = output_ciphertext_commitment(
                coherent_change.output_ciphertexts[1].as_ref().unwrap(),
            )
            .unwrap();
            coherent_change.public_words = statement.to_public_words().to_vec();
            coherent_change.intent_digest = statement.expected_action_intent().unwrap();
            assert!(coherent_change.acknowledge_review(&descriptor).is_err());
            let mut wrong_seed = plan.clone();
            wrong_seed.output_kem_seeds.as_mut().unwrap()[0]
                .as_mut()
                .unwrap()[0] ^= 1;
            assert!(wrong_seed.validate(&descriptor).is_err());
            let mut wrong_opening = plan.clone();
            let payment = note_from_words(&wrong_opening.output_note_words[0]).unwrap();
            let change = note_from_words(&wrong_opening.output_note_words[1]).unwrap();
            let mut payment = payment;
            let mut change = change;
            payment.value += 1;
            change.value -= 1;
            wrong_opening.output_note_words[0] = note_to_words(payment);
            wrong_opening.output_note_words[1] = note_to_words(change);
            let mut statement =
                Rp06PublicStatement::try_from_public_words(&wrong_opening.public_words).unwrap();
            statement.base.commitments[0] = poseidon2_v8_note_commitment(payment).unwrap();
            statement.base.commitments[1] = poseidon2_v8_note_commitment(change).unwrap();
            wrong_opening.public_words = statement.to_public_words().to_vec();
            wrong_opening.intent_digest = statement.expected_action_intent().unwrap();
            assert!(wrong_opening.acknowledge_review(&descriptor).is_err());
            let mut changed = plan.clone();
            changed.source_position += 1;
            assert!(changed.validate(&descriptor).is_err());
        }
    }

    #[test]
    fn v14_plan_migration_keeps_attempts_but_requires_new_reviewed_plan() {
        let keys = keys();
        let mut rng = rand::rngs::OsRng;
        let descriptor = V8TreasuryDescriptor::create(
            &keys[0],
            [37; 32],
            core::array::from_fn(|i| v8_treasury_signer_tag(&keys[i]).unwrap()),
            &mut rng,
        )
        .unwrap();
        let (source_opening, _, _) =
            encrypt_output(&descriptor.receive_address, 100, &mut rng).unwrap();
        let source = descriptor.receive_note(source_opening).unwrap();
        let recipient = keys[2].poseidon2_v8_address(4).unwrap().shielded_address();
        let plan = V8TreasuryPlan::create(
            &descriptor,
            &source,
            path(&[source.commitment], 0),
            &recipient,
            60,
            1,
            &mut rng,
        )
        .unwrap();
        let old_plan = V8TreasuryPlanV14 {
            account_id: plan.account_id,
            source_commitment: plan.source_commitment,
            source_position: plan.source_position,
            source_note_words: plan.source_note_words.clone(),
            recipient_address: plan.recipient_address.clone(),
            public_words: plan.public_words.clone(),
            output_note_words: plan.output_note_words.clone(),
            output_ciphertexts: plan.output_ciphertexts.clone(),
            intent_digest: plan.intent_digest,
        };
        let mut old_hash = Sha512::new();
        old_hash.update(b"hegemon.wallet.rp06.exact-operation-review.v1");
        old_hash.update(bincode::serialize(&old_plan).unwrap());
        let old_digest: [u8; 64] = old_hash.finalize().into();
        let attempt = V8TreasuryAttempt {
            review_digest: old_digest.to_vec(),
            nullifiers: vec![[3; 7]],
            ordinary_note_refs: Vec::new(),
            policy_note_refs: Vec::new(),
            status: V8TreasuryAttemptStatus::SubmissionUncertain,
            action_id: Some(vec![4; 48]),
            mined_in: None,
            material_snapshot: None,
            candidate_inline: Some(vec![5; 32]),
        };
        let migrated: StoredV8Treasury = StoredV8TreasuryV14 {
            descriptor: descriptor.clone(),
            notes: vec![source],
            plans: vec![old_plan],
            attempts: vec![attempt.clone()],
        }
        .into();
        assert_eq!(migrated.attempts, vec![attempt]);
        assert_eq!(migrated.plans.len(), 1);
        assert_eq!(migrated.plans[0].review_digest().unwrap(), old_digest);
        assert!(migrated.plans[0].acknowledge_review(&descriptor).is_err());
    }

    #[test]
    fn v14_prepared_approval_recovers_by_accumulator_intent_only_for_its_signer() {
        use crate::poseidon2_v8_coinbase::{
            build_poseidon2_v8_coinbase_args, protocol_opening_to_relation,
        };
        use crate::poseidon2_v8_sync::Poseidon2V8CanonicalBlock;
        use codec::Encode;
        use protocol_shielded_pool::{
            family::{ACTION_MINT_POSEIDON2_V8_COINBASE, FAMILY_SHIELDED_POOL},
            poseidon2_v8_coinbase::MintPoseidon2V8CoinbaseArgs,
            types::CandidateArtifact,
        };

        fn coinbase(args: &MintPoseidon2V8CoinbaseArgs) -> Vec<u8> {
            let binding = protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING;
            let binding = (binding.circuit, binding.crypto);
            let raw = NoteCiphertext::from_chain_bytes(&args.miner_note.encrypted_note.encode())
                .unwrap()
                .to_da_bytes()
                .unwrap();
            let anchor = [0u8; 48];
            let nullifiers: Vec<[u8; 48]> = Vec::new();
            let commitments: Vec<[u8; 48]> = Vec::new();
            let hashes = vec![transaction_circuit::hashing_pq::ciphertext_hash_bytes(&raw)];
            let sizes = vec![raw.len() as u32];
            let public = args.encode();
            let artifact: Option<CandidateArtifact> = None;
            let body = (
                binding,
                FAMILY_SHIELDED_POOL,
                ACTION_MINT_POSEIDON2_V8_COINBASE,
                anchor,
                &nullifiers,
                &commitments,
                &hashes,
                &sizes,
                &public,
                0u64,
                &artifact,
            )
                .encode();
            let id = hegemon_hash384::blake2b_384_domain_hash(
                hegemon_hash384::domains::ACTION_ID_V3,
                [body.as_slice()],
            );
            (
                id,
                binding,
                FAMILY_SHIELDED_POOL,
                ACTION_MINT_POSEIDON2_V8_COINBASE,
                anchor,
                nullifiers,
                commitments,
                hashes,
                sizes,
                public,
                0u64,
                artifact,
            )
                .encode()
        }

        let keys = keys();
        let temp = tempfile::tempdir().unwrap();
        let wallet_path = temp.path().join("signer.wallet");
        let store = crate::WalletStore::create_from_root(
            &wallet_path,
            "disposable-fixture-passphrase",
            RootSecret::from_bytes([1; 32]),
        )
        .unwrap();
        let mut rng = rand::rngs::OsRng;
        let descriptor = V8TreasuryDescriptor::create(
            &keys[0],
            [37; 32],
            core::array::from_fn(|i| v8_treasury_signer_tag(&keys[i]).unwrap()),
            &mut rng,
        )
        .unwrap();
        store
            .import_v8_treasury_descriptor(descriptor.clone())
            .unwrap();
        let source_args =
            build_poseidon2_v8_coinbase_args(&descriptor.receive_address, 100, &mut rng).unwrap();
        let cap_args = build_poseidon2_v8_coinbase_args(
            &keys[0].poseidon2_v8_address(0).unwrap().shielded_address(),
            10,
            &mut rng,
        )
        .unwrap();
        let source = descriptor
            .receive_note(protocol_opening_to_relation(source_args.miner_note.opening))
            .unwrap();
        let cap = protocol_opening_to_relation(cap_args.miner_note.opening);
        let commitments = [source.commitment, cap_args.miner_note.commitment];
        store
            .ensure_poseidon2_v8_genesis_for_test([91; 32], [55; 7])
            .unwrap();
        store
            .apply_poseidon2_v8_canonical_block(&Poseidon2V8CanonicalBlock {
                height: 1,
                hash: [1; 32],
                parent_hash: [91; 32],
                action_bytes: vec![coinbase(&source_args), coinbase(&cap_args)],
            })
            .unwrap();
        let plan = V8TreasuryPlan::create(
            &descriptor,
            &source,
            path(&commitments, 0),
            &keys[2].poseidon2_v8_address(4).unwrap().shielded_address(),
            60,
            1,
            &mut rng,
        )
        .unwrap();
        let review = plan.acknowledge_review(&descriptor).unwrap();
        let (mut material, _) = build_v8_treasury_approval(
            &descriptor,
            &plan,
            &review,
            &keys[0],
            checked_note_input(
                cap,
                path(&commitments, 1),
                keys[0].spend.poseidon2_v8_words().unwrap(),
            )
            .unwrap(),
            0,
            None,
            path(&commitments, 0).anchor,
            1,
            1,
            &mut rng,
        )
        .unwrap();
        material.set_current_context(1, [55; 7]).unwrap();
        store.persist_v8_treasury_plan(plan.clone()).unwrap();
        assert_eq!(
            store
                .reserve_v8_treasury_attempt(descriptor.account_id, &plan, &material)
                .unwrap(),
            0
        );

        // Convert the already reserved prepared record into the exact frozen V14 shape.
        let v14 = V8TreasuryPlanV14 {
            account_id: plan.account_id,
            source_commitment: plan.source_commitment,
            source_position: plan.source_position,
            source_note_words: plan.source_note_words.clone(),
            recipient_address: plan.recipient_address.clone(),
            public_words: plan.public_words.clone(),
            output_note_words: plan.output_note_words.clone(),
            output_ciphertexts: plan.output_ciphertexts.clone(),
            intent_digest: plan.intent_digest,
        };
        let mut hash = Sha512::new();
        hash.update(b"hegemon.wallet.rp06.exact-operation-review.v1");
        hash.update(bincode::serialize(&v14).unwrap());
        let v14_digest: [u8; 64] = hash.finalize().into();
        store
            .with_v8_treasuries_mut(|records, _, _| {
                records[0].plans[0] = v14.clone().into();
                records[0].attempts[0].review_digest = v14_digest.to_vec();
                Ok(())
            })
            .unwrap();
        let legacy_plan: V8TreasuryPlan = v14.into();

        let recovered = store
            .recover_v8_treasury_attempt_material_v14(descriptor.account_id, 0, &legacy_plan)
            .unwrap();
        assert_eq!(
            recovered.witness.auth.mode,
            SmallwoodPrivateAuthMode::ApprovalStep
        );
        assert_eq!(
            recovered.witness.auth.current.intent_digest,
            legacy_plan.intent_digest
        );
        assert_ne!(
            recovered.statement.expected_action_intent().unwrap(),
            legacy_plan.intent_digest
        );
        assert_eq!(
            recovered.statement.base.nullifiers,
            material.statement.base.nullifiers
        );
        store
            .with_v8_treasuries(|records, _| {
                assert_eq!(
                    recovered.statement.base.nullifiers[1],
                    records[0].attempts[0].nullifiers[0]
                );
                Ok(())
            })
            .unwrap();

        let mut wrong_intent = legacy_plan.clone();
        wrong_intent.intent_digest[0] ^= 1;
        assert!(store
            .recover_v8_treasury_attempt_material_v14(descriptor.account_id, 0, &wrong_intent)
            .is_err());

        let wrong_path = temp.path().join("wrong-signer.wallet");
        let wrong_signer = crate::WalletStore::create_from_root(
            &wrong_path,
            "disposable-fixture-passphrase",
            RootSecret::from_bytes([2; 32]),
        )
        .unwrap();
        wrong_signer
            .import_v8_treasury_descriptor(descriptor.clone())
            .unwrap();
        wrong_signer
            .ensure_poseidon2_v8_genesis_for_test([91; 32], [55; 7])
            .unwrap();
        wrong_signer
            .apply_poseidon2_v8_canonical_block(&Poseidon2V8CanonicalBlock {
                height: 1,
                hash: [1; 32],
                parent_hash: [91; 32],
                action_bytes: vec![coinbase(&source_args), coinbase(&cap_args)],
            })
            .unwrap();
        let saved_records = store
            .with_v8_treasuries(|records, _| Ok(records.to_vec()))
            .unwrap();
        wrong_signer
            .with_v8_treasuries_mut(|records, _, _| {
                *records = saved_records;
                Ok(())
            })
            .unwrap();
        assert!(wrong_signer
            .recover_v8_treasury_attempt_material_v14(descriptor.account_id, 0, &legacy_plan,)
            .is_err());

        // A snapshot whose statement no longer matches its witness is rejected before recovery.
        store
            .with_v8_treasuries_mut(|records, _, _| {
                records[0].attempts[0]
                    .material_snapshot
                    .as_mut()
                    .unwrap()
                    .public_words = legacy_plan.public_words.clone();
                Ok(())
            })
            .unwrap();
        assert!(store
            .recover_v8_treasury_attempt_material_v14(descriptor.account_id, 0, &legacy_plan)
            .is_err());

        // An exported candidate stays byte-for-byte retained and cannot be regenerated.
        store
            .with_v8_treasuries_mut(|records, _, _| {
                records[0].attempts[0].material_snapshot =
                    Some(V8TreasuryMaterialSnapshot::from_material(&material));
                records[0].attempts[0].candidate_inline = Some(vec![9, 8, 7]);
                Ok(())
            })
            .unwrap();
        assert!(store
            .recover_v8_treasury_attempt_material_v14(descriptor.account_id, 0, &legacy_plan)
            .is_err());
        assert_eq!(
            store
                .v8_treasury_attempt_candidate(descriptor.account_id, 0)
                .unwrap(),
            Some(vec![9, 8, 7])
        );
    }
    #[test]
    fn poseidon2_v8_multisig_reference_window_and_abandoned_reorg_reservations() {
        use crate::poseidon2_v8_coinbase::{
            build_poseidon2_v8_coinbase_args, protocol_opening_to_relation,
        };
        use crate::poseidon2_v8_sync::{Poseidon2V8CanonicalBlock, Poseidon2V8WalletState};
        use codec::Encode;
        use protocol_shielded_pool::{
            family::{ACTION_MINT_POSEIDON2_V8_COINBASE, FAMILY_SHIELDED_POOL},
            poseidon2_v8_coinbase::MintPoseidon2V8CoinbaseArgs,
            types::CandidateArtifact,
        };
        fn coinbase(args: &MintPoseidon2V8CoinbaseArgs) -> Vec<u8> {
            let binding = protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING;
            let binding = (binding.circuit, binding.crypto);
            let raw = NoteCiphertext::from_chain_bytes(&args.miner_note.encrypted_note.encode())
                .unwrap()
                .to_da_bytes()
                .unwrap();
            let anchor = [0u8; 48];
            let nullifiers: Vec<[u8; 48]> = Vec::new();
            let commitments: Vec<[u8; 48]> = Vec::new();
            let hashes = vec![transaction_circuit::hashing_pq::ciphertext_hash_bytes(&raw)];
            let sizes = vec![raw.len() as u32];
            let public = args.encode();
            let artifact: Option<CandidateArtifact> = None;
            let body = (
                binding,
                FAMILY_SHIELDED_POOL,
                ACTION_MINT_POSEIDON2_V8_COINBASE,
                anchor,
                &nullifiers,
                &commitments,
                &hashes,
                &sizes,
                &public,
                0u64,
                &artifact,
            )
                .encode();
            let id = hegemon_hash384::blake2b_384_domain_hash(
                hegemon_hash384::domains::ACTION_ID_V3,
                [body.as_slice()],
            );
            (
                id,
                binding,
                FAMILY_SHIELDED_POOL,
                ACTION_MINT_POSEIDON2_V8_COINBASE,
                anchor,
                nullifiers,
                commitments,
                hashes,
                sizes,
                public,
                0u64,
                artifact,
            )
                .encode()
        }
        let keys = keys();
        let mut rng = rand::rngs::OsRng;
        let descriptor = V8TreasuryDescriptor::create(
            &keys[0],
            [37; 32],
            core::array::from_fn(|i| v8_treasury_signer_tag(&keys[i]).unwrap()),
            &mut rng,
        )
        .unwrap();
        let source_args =
            build_poseidon2_v8_coinbase_args(&descriptor.receive_address, 100, &mut rng).unwrap();
        let cap_args = build_poseidon2_v8_coinbase_args(
            &keys[0].poseidon2_v8_address(0).unwrap().shielded_address(),
            10,
            &mut rng,
        )
        .unwrap();
        let source = descriptor
            .receive_note(protocol_opening_to_relation(source_args.miner_note.opening))
            .unwrap();
        let cap = protocol_opening_to_relation(cap_args.miner_note.opening);
        let commitments = [source.commitment, cap_args.miner_note.commitment];
        let mut mirror = Poseidon2V8WalletState::default();
        mirror.ensure_genesis_for_test([91; 32], [55; 7]).unwrap();
        mirror
            .apply_block(
                &Poseidon2V8CanonicalBlock {
                    height: 1,
                    hash: [1; 32],
                    parent_hash: [91; 32],
                    action_bytes: vec![coinbase(&source_args), coinbase(&cap_args)],
                },
                None,
            )
            .unwrap();
        assert_eq!(mirror.tip().unwrap().anchor, path(&commitments, 0).anchor);
        let plan = V8TreasuryPlan::create(
            &descriptor,
            &source,
            path(&commitments, 0),
            &keys[2].poseidon2_v8_address(4).unwrap().shielded_address(),
            60,
            1,
            &mut rng,
        )
        .unwrap();
        let review = plan.acknowledge_review(&descriptor).unwrap();
        let (mut material, _) = build_v8_treasury_approval(
            &descriptor,
            &plan,
            &review,
            &keys[0],
            checked_note_input(
                cap,
                path(&commitments, 1),
                keys[0].spend.poseidon2_v8_words().unwrap(),
            )
            .unwrap(),
            0,
            None,
            path(&commitments, 0).anchor,
            1,
            1,
            &mut rng,
        )
        .unwrap();
        material.set_current_context(1, [55; 7]).unwrap();
        let mut attempt = V8TreasuryAttempt {
            review_digest: plan.review_digest().unwrap().to_vec(),
            nullifiers: vec![material.statement.base.nullifiers[1]],
            ordinary_note_refs: vec![(commitments[1], 1)],
            policy_note_refs: Vec::new(),
            status: V8TreasuryAttemptStatus::Prepared,
            action_id: Some(vec![13; 48]),
            mined_in: None,
            material_snapshot: Some(V8TreasuryMaterialSnapshot::from_material(&material)),
            candidate_inline: Some(vec![9, 8, 7]),
        };
        assert!(attempt_reference_ready(&attempt, &mirror).unwrap());
        assert!(!attempt_abandonment_allowed(&attempt, &mirror).unwrap());
        let record = StoredV8Treasury {
            descriptor: descriptor.clone(),
            notes: vec![source],
            plans: vec![plan.clone()],
            attempts: vec![attempt.clone()],
        };
        assert!(attempt_future_source_available(&record, &attempt, &mirror).unwrap());
        let mut missing_future = record.clone();
        missing_future.plans.clear();
        assert!(!attempt_future_source_available(&missing_future, &attempt, &mirror).unwrap());
        for height in 2..=13 {
            let parent = mirror.tip().unwrap();
            mirror
                .apply_block(
                    &Poseidon2V8CanonicalBlock {
                        height,
                        hash: [height as u8; 32],
                        parent_hash: parent.block_hash,
                        action_bytes: Vec::new(),
                    },
                    None,
                )
                .unwrap();
        }
        // Href+12 remains usable; Href+13 is the first expired parent.
        assert!(attempt_reference_ready(&attempt, &mirror).unwrap());
        assert!(!attempt_abandonment_allowed(&attempt, &mirror).unwrap());
        let checkpoint = mirror.tip().unwrap();
        mirror
            .apply_block(
                &Poseidon2V8CanonicalBlock {
                    height: 14,
                    hash: [14; 32],
                    parent_hash: checkpoint.block_hash,
                    action_bytes: Vec::new(),
                },
                None,
            )
            .unwrap();
        assert!(!attempt_reference_ready(&attempt, &mirror).unwrap());
        assert!(attempt_abandonment_allowed(&attempt, &mirror).unwrap());
        attempt.status = V8TreasuryAttemptStatus::Abandoned;
        let preserved = attempt.clone();
        assert!(!attempt_reservation_active(&attempt, &mirror));
        mirror.rollback_to(13, checkpoint.block_hash).unwrap();
        assert!(attempt_reservation_active(&attempt, &mirror));
        assert_eq!(attempt, preserved); // No bytes, receipt or tombstone is erased.
        let mut future = attempt.clone();
        let mut statement = attempt_statement(&future).unwrap();
        statement.base.stablecoin.parent_height = 14;
        future.material_snapshot.as_mut().unwrap().public_words =
            statement.to_public_words().to_vec();
        assert!(!attempt_reference_ready(&future, &mirror).unwrap());
        assert!(!attempt_abandonment_allowed(&future, &mirror).unwrap());
        let mut detached = attempt.clone();
        let mut statement = attempt_statement(&detached).unwrap();
        statement.base.merkle_root[0] ^= 1;
        detached.material_snapshot.as_mut().unwrap().public_words =
            statement.to_public_words().to_vec();
        assert!(!attempt_reference_ready(&detached, &mirror).unwrap());
        assert!(!attempt_abandonment_allowed(&detached, &mirror).unwrap());
        let mut wrong_input = attempt.clone();
        wrong_input.ordinary_note_refs[0].1 = 0;
        assert!(!attempt_reference_ready(&wrong_input, &mirror).unwrap());
        let mut missing = attempt.clone();
        missing.material_snapshot = None;
        assert!(attempt_reservation_active(&missing, &mirror));
    }
    #[test]
    fn poseidon2_v8_multisig_encrypted_restore_preserves_private_descriptor_and_independent_keys() {
        let temp = tempfile::tempdir().unwrap();
        let keys = keys();
        let descriptor = V8TreasuryDescriptor::create(
            &keys[0],
            [83; 32],
            core::array::from_fn(|i| v8_treasury_signer_tag(&keys[i]).unwrap()),
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        for i in 0..3 {
            let location = temp.path().join(format!("signer{i}.wallet"));
            let store = crate::WalletStore::create_from_root(
                &location,
                "test-local-restore",
                RootSecret::from_bytes([i as u8 + 1; 32]),
            )
            .unwrap();
            store
                .import_v8_treasury_descriptor(descriptor.clone())
                .unwrap();
            store
                .import_v8_treasury_descriptor(descriptor.clone())
                .unwrap();
            assert_eq!(
                store.v8_treasury_descriptors().unwrap(),
                vec![descriptor.clone()]
            );
            let mut rng = rand::rngs::OsRng;
            let (opening, _, _) =
                encrypt_output(&descriptor.receive_address, 100, &mut rng).unwrap();
            let source = descriptor.receive_note(opening).unwrap();
            store
                .record_pending_v8_treasury_note(descriptor.account_id, source.clone())
                .unwrap();
            let cap_note = caps_note(&keys[i]);
            let commitment_list = [
                source.commitment,
                poseidon2_v8_note_commitment(cap_note).unwrap(),
            ];
            let plan = V8TreasuryPlan::create(
                &descriptor,
                &source,
                path(&commitment_list, 0),
                &keys[2].poseidon2_v8_address(6).unwrap().shielded_address(),
                60,
                1,
                &mut rng,
            )
            .unwrap();
            let cap_input = checked_note_input(
                cap_note,
                path(&commitment_list, 1),
                keys[i].spend.poseidon2_v8_words().unwrap(),
            )
            .unwrap();
            let (material, _) = build_v8_treasury_approval(
                &descriptor,
                &plan,
                &plan.acknowledge_review(&descriptor).unwrap(),
                &keys[i],
                cap_input,
                0,
                None,
                path(&commitment_list, 0).anchor,
                0,
                1,
                &mut rng,
            )
            .unwrap();
            let snapshot = V8TreasuryMaterialSnapshot::from_material(&material);
            let persistence_marker = b"storage-only fixture, never a proof".to_vec();
            // Exercise encrypted V13 payload recovery independently of source/node admission.
            store
                .with_v8_treasuries_mut(|records, _, _| {
                    records[0].plans.push(plan.clone());
                    records[0].attempts.push(V8TreasuryAttempt {
                        review_digest: plan.review_digest()?.to_vec(),
                        nullifiers: vec![
                            Rp06PublicStatement::try_from_public_words(&plan.public_words)
                                .unwrap()
                                .base
                                .nullifiers[0],
                        ],
                        ordinary_note_refs: Vec::new(),
                        policy_note_refs: vec![(source.commitment, 0)],
                        status: V8TreasuryAttemptStatus::SubmissionUncertain,
                        action_id: None,
                        mined_in: None,
                        material_snapshot: Some(snapshot.clone()),
                        candidate_inline: Some(persistence_marker.clone()),
                    });
                    Ok(())
                })
                .unwrap();
            drop(store);
            let disk = std::fs::read(&location).unwrap();
            assert!(!disk.windows(32).any(|bytes| bytes == [i as u8 + 1; 32]));
            let backup = temp.path().join(format!("restore{i}.wallet"));
            std::fs::copy(&location, &backup).unwrap();
            let restored = crate::WalletStore::open(&backup, "test-local-restore").unwrap();
            assert_eq!(
                restored
                    .v8_treasury_attempt_candidate(descriptor.account_id, 0)
                    .unwrap(),
                Some(persistence_marker)
            );
            restored
                .with_v8_treasuries(|records, _| {
                    let saved = records[0].attempts[0].material_snapshot.as_ref().unwrap();
                    assert_eq!(saved, &snapshot);
                    let recovered = saved.restore(Some(&keys[i]))?;
                    assert_eq!(recovered.witness, material.witness);
                    assert_eq!(recovered.inline_ciphertexts, material.inline_ciphertexts);
                    Ok(())
                })
                .unwrap();
            assert_eq!(
                restored.v8_treasury_descriptors().unwrap(),
                vec![descriptor.clone()]
            );
            assert_eq!(
                v8_treasury_signer_tag(&restored.derived_keys().unwrap().unwrap()).unwrap(),
                v8_treasury_signer_tag(&keys[i]).unwrap()
            );
            assert_eq!(
                restored.v8_treasury_notes(descriptor.account_id).unwrap(),
                vec![source]
            );
            assert_eq!(
                restored.v8_treasury_plans(descriptor.account_id).unwrap(),
                vec![plan]
            );
            assert_eq!(
                restored
                    .v8_treasury_attempt_views(descriptor.account_id)
                    .unwrap()[0]
                    .status,
                V8TreasuryAttemptStatus::SubmissionUncertain
            );
            let mut collision = descriptor.clone();
            collision.chain_id[0] ^= 1;
            assert!(restored.import_v8_treasury_descriptor(collision).is_err());
        }
        let mut duplicate = descriptor.signer_tags;
        duplicate[2] = duplicate[0];
        assert!(rp06_policy_root(2, 3, duplicate).is_err());
    }
}

impl V8TreasurySpendMaterial {
    /// Bind the current disabled stable state and parent height without changing human intent.
    /// The supplied paths already determine the note anchor and must be refreshed separately.
    pub fn set_current_context(
        &mut self,
        parent_height: u64,
        stablecoin_root: [u64; 7],
    ) -> Result<(), WalletError> {
        use hegemon_field::{Goldilocks, PrimeCharacteristicRing};
        if stablecoin_root.iter().any(|word| *word >= MODULUS) {
            return Err(invalid("noncanonical current stablecoin root"));
        }
        let previous = self.statement.expected_action_intent().map_err(surface)?;
        self.statement.base.stablecoin.parent_height = parent_height;
        self.statement.base.stablecoin.before_root = stablecoin_root.map(Goldilocks::from_u64);
        self.statement.base.stablecoin.after_root = stablecoin_root.map(Goldilocks::from_u64);
        if self.statement.expected_action_intent().map_err(surface)? != previous {
            return Err(invalid(
                "current chain context changed treasury human intent",
            ));
        }
        compile_rp06_relation(self.statement, &self.witness).map_err(surface)?;
        Ok(())
    }
}
impl crate::WalletStore {
    /// Preserve an exact future output opening before proof generation or submission.
    /// A stored pending opening conveys no authority: every spend still needs its canonical path.
    pub fn record_pending_v8_treasury_note(
        &self,
        account_id: [u8; 32],
        note: V8TreasuryNote,
    ) -> Result<(), WalletError> {
        self.with_v8_treasuries_mut(|treasuries, _, _| {
            let record = treasuries
                .iter_mut()
                .find(|record| record.descriptor.account_id == account_id)
                .ok_or(invalid("unknown V8 treasury"))?;
            let opening = note_from_words(&note.note_words)?;
            if poseidon2_v8_note_commitment(opening).map_err(surface)? != note.commitment {
                return Err(invalid("pending treasury opening/commitment mismatch"));
            }
            match &note.kind {
                V8TreasuryNoteKind::Value => {
                    record.descriptor.receive_note(opening)?;
                }
                V8TreasuryNoteKind::Accumulator { opening_words } => {
                    let intent = accumulator_from_words(opening_words)?.intent_digest;
                    let plan = record
                        .plans
                        .iter()
                        .find(|plan| plan.intent_digest == intent)
                        .ok_or(invalid("pending approval has no durable exact plan"))?;
                    checked_accumulator(&record.descriptor, plan, &note)?;
                }
            }
            if let Some(previous) = record
                .notes
                .iter()
                .find(|previous| previous.commitment == note.commitment)
            {
                if previous == &note {
                    return Ok(());
                }
                return Err(invalid("pending treasury commitment opening collision"));
            }
            record.notes.push(note);
            Ok(())
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V8TreasuryNoteView {
    pub note: V8TreasuryNote,
    pub path: V8TreasuryNotePath,
    pub nullifier: [u64; 7],
    pub spent: bool,
    pub reserved: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V8TreasuryAttemptView {
    pub review_digest: Vec<u8>,
    pub candidate_bytes: Option<usize>,
    pub recoverable: bool,
    pub status: V8TreasuryAttemptStatus,
    pub action_id: Option<Vec<u8>>,
    pub mined_in: Option<(u64, [u8; 32])>,
    pub all_inputs_on_chain: bool,
}
/// Called under WalletStore's mirror update lock only after canonical actions have been verified.
/// The action id authenticates the complete native action, including unchanged proof bytes.
pub(crate) fn reconcile_v8_treasury_attempts(
    treasuries: &mut [StoredV8Treasury],
    mirror: &crate::poseidon2_v8_sync::Poseidon2V8WalletState,
    observed_actions: &[([u8; 48], u64, [u8; 32])],
) -> Result<(), WalletError> {
    for treasury in treasuries {
        treasury.descriptor.validate()?;
        for attempt in &mut treasury.attempts {
            if let Some((height, hash)) = attempt.mined_in {
                if mirror.canonical_hash(height) != Some(hash) {
                    attempt.mined_in = None;
                    attempt.status = if attempt.action_id.is_some() {
                        V8TreasuryAttemptStatus::Submitted
                    } else {
                        V8TreasuryAttemptStatus::SubmissionUncertain
                    };
                }
            }
            if let Some(id) = &attempt.action_id {
                if id.len() != 48 {
                    return Err(invalid("treasury attempt has malformed action id"));
                }
                if let Some((_, height, hash)) = observed_actions
                    .iter()
                    .find(|(observed, _, _)| observed.as_slice() == id.as_slice())
                {
                    if mirror.canonical_hash(*height) != Some(*hash)
                        || !attempt
                            .nullifiers
                            .iter()
                            .all(|nf| mirror.has_canonical_nullifier(*nf))
                    {
                        return Err(invalid(
                            "treasury inclusion receipt differs from canonical action/nullifiers",
                        ));
                    }
                    attempt.status = V8TreasuryAttemptStatus::Mined;
                    attempt.mined_in = Some((*height, *hash));
                }
            }
        }
    }
    Ok(())
}
/// Public reward openings are recoverable even when the miner supplies an undecryptable KEM.
/// Consensus and the verified mirror authenticate the opening/commitment; this hook matches the
/// exact policy recipient and remembers its source opening without deriving an ordinary-key NF.
pub(crate) fn track_v8_treasury_public_reward(
    treasuries: &mut [StoredV8Treasury],
    opening: SmallwoodPoseidon2V8NoteOpening,
) -> Result<usize, WalletError> {
    let mut recovered = 0;
    for treasury in treasuries {
        treasury.descriptor.validate()?;
        let Ok(note) = treasury.descriptor.receive_note(opening) else {
            continue;
        };
        if let Some(previous) = treasury
            .notes
            .iter()
            .find(|previous| previous.commitment == note.commitment)
        {
            if previous != &note {
                return Err(invalid(
                    "treasury reward opening collides with stored commitment",
                ));
            }
        } else {
            treasury.notes.push(note);
            recovered += 1;
        }
    }
    Ok(recovered)
}
impl crate::WalletStore {
    /// Resolve one exact canonical position and derive the policy nullifier from that position.
    /// Detached/unconfirmed notes and duplicate-position ambiguity cannot authorize a spend.
    pub fn v8_treasury_note_view(
        &self,
        account_id: [u8; 32],
        commitment: [u64; 7],
        position: u64,
    ) -> Result<V8TreasuryNoteView, WalletError> {
        self.with_v8_treasuries(|treasuries, mirror| {
            let treasury = treasuries
                .iter()
                .find(|record| record.descriptor.account_id == account_id)
                .ok_or(invalid("unknown V8 treasury"))?;
            treasury.descriptor.validate()?;
            let note = treasury
                .notes
                .iter()
                .find(|note| note.commitment == commitment)
                .ok_or(invalid("treasury has no exact private note opening"))?;
            let membership = mirror
                .canonical_note_witness_at(commitment, position)?
                .ok_or(invalid("treasury note is not at this canonical position"))?;
            let opening = note_from_words(&note.note_words)?;
            let nullifier = rp06_policy_note_nullifier(
                treasury.descriptor.policy_nullifier_key,
                position,
                opening.rho,
            )
            .map_err(surface)?;
            Ok(V8TreasuryNoteView {
                note: note.clone(),
                path: V8TreasuryNotePath {
                    commitment,
                    position,
                    siblings: membership.path,
                    anchor: membership.anchor,
                },
                nullifier,
                spent: mirror.has_canonical_nullifier(nullifier),
                reserved: active_reserved_nullifiers(treasuries, mirror).contains(&nullifier),
            })
        })
    }
    pub fn v8_treasury_attempt_views(
        &self,
        account_id: [u8; 32],
    ) -> Result<Vec<V8TreasuryAttemptView>, WalletError> {
        self.with_v8_treasuries(|treasuries, mirror| {
            let treasury = treasuries
                .iter()
                .find(|record| record.descriptor.account_id == account_id)
                .ok_or(invalid("unknown V8 treasury"))?;
            Ok(treasury
                .attempts
                .iter()
                .map(|attempt| V8TreasuryAttemptView {
                    review_digest: attempt.review_digest.clone(),
                    candidate_bytes: attempt.candidate_inline.as_ref().map(Vec::len),
                    recoverable: attempt.candidate_inline.is_some()
                        || (attempt.status == V8TreasuryAttemptStatus::Prepared
                            && attempt.material_snapshot.is_some()),
                    status: attempt.status.clone(),
                    action_id: attempt.action_id.clone(),
                    mined_in: attempt.mined_in,
                    all_inputs_on_chain: attempt
                        .nullifiers
                        .iter()
                        .all(|nf| mirror.has_canonical_nullifier(*nf)),
                })
                .collect())
        })
    }
}
