//! Asset-spend construction, encrypted note delivery and persistent handoff.
//!
//! The caller supplies authenticated current registry state, credentials and
//! recipient keys. The persistent builder reserves actual WalletStore inputs
//! and journals exact native candidate bytes. Source-owned node admission
//! remains separate; construction grants no production authority.
#![forbid(unsafe_code)]

use crate::WalletError;
use rand_core09::TryCryptoRng;
use synthetic_crypto::{
    asset_note_encryption_v1::{
        AssetNoteCiphertext, AssetNoteCiphertextRef, AssetNoteContext, AssetNotePlaintext,
    },
    ml_kem::{MlKemPublicKey, MlKemSecretKey},
    private_note_payload::NoteOpening,
};
use transaction_circuit::{
    asset_spend_v1 as relation,
    hashing_pq::ciphertext_hash_bytes,
    private_spend::{note_commitment, ordinary_owner, BoundedPolicy, Digest, Note},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const P: u64 = 0xffff_ffff_0000_0001;
const MAGIC: &[u8; 4] = b"ASN1";
fn invalid(message: &'static str) -> WalletError {
    WalletError::InvalidState(message)
}
fn source_digest() -> [u8; 48] {
    relation::relation_digest()[..48]
        .try_into()
        .expect("digest prefix")
}
fn commitment_bytes(commitment: Digest) -> [u8; 56] {
    let mut bytes = [0; 56];
    for (out, word) in bytes.chunks_exact_mut(8).zip(commitment) {
        out.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}
fn note_opening(note: Note) -> NoteOpening {
    NoteOpening {
        value: note.value,
        asset_id: note.asset_id,
        recipient_key: note.recipient_key,
        authorization_key: note.authorization_key,
        rho: note.rho,
        randomness: note.randomness,
    }
}

/// Secret-bearing ordinary opening. Intentionally has no Debug, Clone or serde.
/// A full authority digest is retained to check every owner limb after decrypt.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AssetNotePayload {
    pub recipient_index: u32,
    pub note: NoteOpening,
    pub authority: Digest,
}
impl AssetNotePayload {
    fn validate(&self, expected_asset: u32) -> Result<(), WalletError> {
        if self.note.value >= 1 << 56 || self.note.asset_id != u64::from(expected_asset) {
            return Err(invalid("asset note value or expected asset mismatch"));
        }
        if self
            .note
            .recipient_key
            .iter()
            .chain(self.note.authorization_key.iter())
            .chain(self.note.rho.iter())
            .chain(self.note.randomness.iter())
            .chain(self.authority.iter())
            .any(|word| *word >= P)
        {
            return Err(invalid("asset note noncanonical field"));
        }
        let owner = ordinary_owner(self.authority)
            .map_err(|_| invalid("asset note ordinary owner invalid"))?;
        if self.note.authorization_key != owner[..4] || self.note.randomness[..3] != owner[4..] {
            return Err(invalid("asset note owner embedding mismatch"));
        }
        Ok(())
    }
    pub fn as_note(&self) -> Note {
        Note {
            value: self.note.value,
            asset_id: self.note.asset_id,
            recipient_key: self.note.recipient_key,
            authorization_key: self.note.authorization_key,
            rho: self.note.rho,
            randomness: self.note.randomness,
        }
    }
    /// Fresh fixed-width codec. The explicit expected asset may be zero only
    /// when the caller is decoding the native fee-change output.
    pub fn encode(
        &self,
        chain_id: [u8; 32],
        expected_asset: u32,
    ) -> Result<AssetNotePlaintext, WalletError> {
        self.validate(expected_asset)?;
        let mut bytes = Zeroizing::new([0; 1024]);
        bytes[..4].copy_from_slice(MAGIC);
        bytes[4..36].copy_from_slice(&chain_id);
        bytes[36..40].copy_from_slice(&self.recipient_index.to_le_bytes());
        let mut at = 40;
        let words = Zeroizing::new([
            self.note.value,
            self.note.asset_id,
            self.note.recipient_key[0],
            self.note.recipient_key[1],
            self.note.recipient_key[2],
            self.note.recipient_key[3],
            self.note.rho[0],
            self.note.rho[1],
            self.note.rho[2],
            self.note.rho[3],
            self.note.randomness[0],
            self.note.randomness[1],
            self.note.randomness[2],
            self.note.randomness[3],
            self.note.authorization_key[0],
            self.note.authorization_key[1],
            self.note.authorization_key[2],
            self.note.authorization_key[3],
            self.authority[0],
            self.authority[1],
            self.authority[2],
            self.authority[3],
            self.authority[4],
            self.authority[5],
            self.authority[6],
        ]);
        for word in words.iter() {
            bytes[at..at + 8].copy_from_slice(&word.to_le_bytes());
            at += 8;
        }
        AssetNotePlaintext::from_bytes_exact(&bytes[..])
            .map_err(|_| invalid("asset note plaintext length"))
    }
    pub fn decode(
        plaintext: &AssetNotePlaintext,
        chain_id: [u8; 32],
        expected_asset: u32,
    ) -> Result<Self, WalletError> {
        let bytes = plaintext.as_bytes();
        if &bytes[..4] != MAGIC || bytes[4..36] != chain_id {
            return Err(invalid("asset note codec or chain mismatch"));
        }
        if bytes[240..].iter().any(|byte| *byte != 0) {
            return Err(invalid("asset note nonzero padding"));
        }
        let mut words = Zeroizing::new([0u64; 25]);
        for (word, input) in words.iter_mut().zip(bytes[40..240].chunks_exact(8)) {
            *word = u64::from_le_bytes(input.try_into().expect("eight bytes"));
        }
        let payload = Self {
            recipient_index: u32::from_le_bytes(bytes[36..40].try_into().expect("four bytes")),
            note: NoteOpening {
                value: words[0],
                asset_id: words[1],
                recipient_key: words[2..6].try_into().expect("four words"),
                rho: words[6..10].try_into().expect("four words"),
                randomness: words[10..14].try_into().expect("four words"),
                authorization_key: words[14..18].try_into().expect("four words"),
            },
            authority: words[18..25].try_into().expect("seven words"),
        };
        payload.validate(expected_asset)?;
        Ok(payload)
    }
}

const SCRIPT_MAGIC: &[u8; 4] = b"ASB1";
const SCRIPT_WORDS: usize = 18 + 5 + 39;
const SCRIPT_END: usize = 40 + SCRIPT_WORDS * 8;
fn wipe_policy(policy: &mut BoundedPolicy) {
    policy.nullifier_key.zeroize();
    for branch in &mut policy.branches {
        branch.enabled.zeroize();
        branch.authority.zeroize();
        branch.not_before.zeroize();
        branch.hash_required.zeroize();
        branch.hashlock.zeroize();
        branch.release_secret.zeroize();
    }
}

/// Secret-bearing script opening. Core owns policy validation and owner
/// derivation; this codec adds only exact framing and encrypted delivery.
pub struct ScriptAssetNotePayload {
    pub recipient_index: u32,
    pub note: NoteOpening,
    pub policy: BoundedPolicy,
}
impl Drop for ScriptAssetNotePayload {
    fn drop(&mut self) {
        self.recipient_index.zeroize();
        wipe_policy(&mut self.policy);
    }
}
impl ScriptAssetNotePayload {
    pub fn as_note(&self) -> Note {
        Note {
            value: self.note.value,
            asset_id: self.note.asset_id,
            recipient_key: self.note.recipient_key,
            authorization_key: self.note.authorization_key,
            rho: self.note.rho,
            randomness: self.note.randomness,
        }
    }
    pub fn committed_owner(
        &self,
        chain_id: [u8; 32],
        expected_asset: u32,
    ) -> Result<Digest, WalletError> {
        if expected_asset == 0
            || self.note.asset_id != u64::from(expected_asset)
            || self.note.value >= 1 << 56
        {
            return Err(invalid("script asset note asset or value mismatch"));
        }
        if self
            .note
            .recipient_key
            .iter()
            .chain(self.note.authorization_key.iter())
            .chain(self.note.rho.iter())
            .chain(self.note.randomness.iter())
            .any(|word| *word >= P)
        {
            return Err(invalid("script asset note noncanonical field"));
        }
        let owner = self
            .policy
            .owner(chain_id, u64::from(expected_asset))
            .map_err(|_| invalid("script asset policy invalid"))?;
        if self.note.authorization_key != owner[..4] || self.note.randomness[..3] != owner[4..] {
            return Err(invalid("script asset note owner embedding mismatch"));
        }
        Ok(owner)
    }
    pub fn encode(
        &self,
        chain_id: [u8; 32],
        expected_asset: u32,
    ) -> Result<AssetNotePlaintext, WalletError> {
        self.committed_owner(chain_id, expected_asset)?;
        let mut bytes = Zeroizing::new([0; 1024]);
        bytes[..4].copy_from_slice(SCRIPT_MAGIC);
        bytes[4..36].copy_from_slice(&chain_id);
        bytes[36..40].copy_from_slice(&self.recipient_index.to_le_bytes());
        let note = &self.note;
        let mut words = Zeroizing::new(Vec::with_capacity(SCRIPT_WORDS));
        words.extend([note.value, note.asset_id]);
        words.extend(note.recipient_key);
        words.extend(note.rho);
        words.extend(note.randomness);
        words.extend(note.authorization_key);
        words.extend(self.policy.nullifier_key);
        let policy_words = Zeroizing::new(
            self.policy
                .words()
                .map_err(|_| invalid("script asset policy encoding"))?,
        );
        words.extend_from_slice(&policy_words[..]);
        for (out, word) in bytes[40..SCRIPT_END].chunks_exact_mut(8).zip(words.iter()) {
            out.copy_from_slice(&word.to_le_bytes());
        }
        AssetNotePlaintext::from_bytes_exact(&bytes[..])
            .map_err(|_| invalid("script asset plaintext length"))
    }
    pub fn decode(
        plaintext: &AssetNotePlaintext,
        chain_id: [u8; 32],
        expected_asset: u32,
    ) -> Result<Self, WalletError> {
        let bytes = plaintext.as_bytes();
        if &bytes[..4] != SCRIPT_MAGIC
            || bytes[4..36] != chain_id
            || bytes[SCRIPT_END..].iter().any(|byte| *byte != 0)
        {
            return Err(invalid("script asset codec, chain or padding mismatch"));
        }
        let mut words = Zeroizing::new([0; SCRIPT_WORDS]);
        for (word, input) in words.iter_mut().zip(bytes[40..SCRIPT_END].chunks_exact(8)) {
            *word = u64::from_le_bytes(input.try_into().expect("eight bytes"));
        }
        let policy = BoundedPolicy::from_words(
            words[18..23].try_into().expect("five words"),
            words[23..].try_into().expect("policy words"),
        )
        .map_err(|_| invalid("script asset policy decoding"))?;
        let payload = Self {
            recipient_index: u32::from_le_bytes(bytes[36..40].try_into().expect("four bytes")),
            note: NoteOpening {
                value: words[0],
                asset_id: words[1],
                recipient_key: words[2..6].try_into().expect("four words"),
                rho: words[6..10].try_into().expect("four words"),
                randomness: words[10..14].try_into().expect("four words"),
                authorization_key: words[14..18].try_into().expect("four words"),
            },
            policy,
        };
        payload.committed_owner(chain_id, expected_asset)?;
        Ok(payload)
    }
}

/// Authenticated private payload variants. Neither variant has Debug or serde.
pub enum RecoveredAssetNotePayload {
    Ordinary(AssetNotePayload),
    Script(ScriptAssetNotePayload),
}
impl RecoveredAssetNotePayload {
    pub fn as_note(&self) -> Note {
        match self {
            Self::Ordinary(payload) => payload.as_note(),
            Self::Script(payload) => payload.as_note(),
        }
    }
    pub fn recipient_index(&self) -> u32 {
        match self {
            Self::Ordinary(payload) => payload.recipient_index,
            Self::Script(payload) => payload.recipient_index,
        }
    }
    pub fn committed_owner(
        &self,
        chain_id: [u8; 32],
        expected_asset: u32,
    ) -> Result<Digest, WalletError> {
        match self {
            Self::Ordinary(payload) => {
                payload.validate(expected_asset)?;
                ordinary_owner(payload.authority).map_err(|_| invalid("ordinary asset owner"))
            }
            Self::Script(payload) => payload.committed_owner(chain_id, expected_asset),
        }
    }
}

/// Encrypt all outputs, including zero-value notes, with fresh caller-supplied
/// cryptographic randomness. The caller must use OS entropy outside tests.
/// Commitments/bindings update atomically only after all three encryptions pass.
pub fn encrypt_outputs<R: TryCryptoRng + ?Sized>(
    public: &mut relation::AssetSpendPublic,
    witness: &relation::AssetSpendWitness,
    recipient_public_keys: [&MlKemPublicKey; 3],
    recipient_indices: [u32; 3],
    rng: &mut R,
) -> Result<[AssetNoteCiphertext; 3], WalletError> {
    if public.asset_id == 0 {
        return Err(invalid("asset spend cannot select native HGN"));
    }
    if witness.policy.create > 1 || witness.policy.spend > 1 {
        return Err(invalid("asset policy selectors must be boolean"));
    }
    let mut commitments = [[0; 7]; 3];
    let mut bindings = [[0; 48]; 3];
    let mut ciphertexts = Vec::with_capacity(3);
    for slot in 0..3 {
        let expected_asset = if slot == 2 { 0 } else { public.asset_id };
        let plaintext = if slot == 0 && witness.policy.create == 1 {
            if public.policy_mode != 1 {
                return Err(invalid("script asset output requires combined policy mode"));
            }
            ScriptAssetNotePayload {
                recipient_index: recipient_indices[slot],
                note: note_opening(witness.outputs[slot]),
                policy: witness.policy.output.clone(),
            }
            .encode(public.chain_id, expected_asset)?
        } else {
            AssetNotePayload {
                recipient_index: recipient_indices[slot],
                note: note_opening(witness.outputs[slot]),
                authority: witness.output_authorities[slot],
            }
            .encode(public.chain_id, expected_asset)?
        };
        commitments[slot] = note_commitment(witness.outputs[slot])
            .map_err(|_| invalid("asset output commitment invalid"))?;
        let context = AssetNoteContext::new(
            source_digest(),
            public.chain_id,
            slot as u8,
            commitment_bytes(commitments[slot]),
        )
        .map_err(|_| invalid("asset output context invalid"))?;
        let ciphertext =
            AssetNoteCiphertext::encrypt(recipient_public_keys[slot], &context, &plaintext, rng)
                .map_err(|_| invalid("asset output encryption failed"))?;
        bindings[slot] = ciphertext_hash_bytes(ciphertext.as_bytes());
        ciphertexts.push(ciphertext);
    }
    let ciphertexts = ciphertexts
        .try_into()
        .map_err(|_| invalid("three asset ciphertexts required"))?;
    public.commitments = commitments;
    public.ciphertext_commitments = bindings;
    Ok(ciphertexts)
}

/// Authenticate one exact candidate output and check its ordinary owner,
/// commitment, private recipient index/key/authority and expected asset.
/// Supplying decryption material alone is not a claim of spending authority.
pub fn decrypt_output(
    public: &relation::AssetSpendPublic,
    slot: u8,
    ciphertext: &[u8],
    secret_key: &MlKemSecretKey,
    recipient_index: u32,
    recipient_key: [u64; 4],
    authority: Digest,
) -> Result<AssetNotePayload, WalletError> {
    if slot > 2 || public.asset_id == 0 {
        return Err(invalid("asset output slot or asset invalid"));
    }
    let slot_index = usize::from(slot);
    let ciphertext = AssetNoteCiphertextRef::from_bytes_exact(ciphertext)
        .map_err(|_| invalid("asset ciphertext width"))?;
    if ciphertext_hash_bytes(ciphertext.as_bytes()) != public.ciphertext_commitments[slot_index] {
        return Err(invalid("asset ciphertext binding mismatch"));
    }
    let context = AssetNoteContext::new(
        source_digest(),
        public.chain_id,
        slot,
        commitment_bytes(public.commitments[slot_index]),
    )
    .map_err(|_| invalid("asset output context invalid"))?;
    let plaintext = ciphertext
        .decrypt(secret_key, &context)
        .map_err(|_| invalid("asset note decryption failed"))?;
    let expected_asset = if slot == 2 { 0 } else { public.asset_id };
    let payload = AssetNotePayload::decode(&plaintext, public.chain_id, expected_asset)?;
    if payload.recipient_index != recipient_index
        || payload.note.recipient_key != recipient_key
        || payload.authority != authority
        || note_commitment(payload.as_note()).ok() != Some(public.commitments[slot_index])
    {
        return Err(invalid("asset recipient or commitment mismatch"));
    }
    Ok(payload)
}

/// Decode ordinary or script payloads while authenticating the complete
/// note-committed owner. `committed_owner` is the policy owner for a script,
/// and ordinary_owner(authority) for an ordinary note.
pub fn decrypt_output_any(
    public: &relation::AssetSpendPublic,
    slot: u8,
    ciphertext: &[u8],
    secret_key: &MlKemSecretKey,
    recipient_index: u32,
    recipient_key: [u64; 4],
    committed_owner: Digest,
) -> Result<RecoveredAssetNotePayload, WalletError> {
    if slot > 2 || public.asset_id == 0 {
        return Err(invalid("asset output slot or asset invalid"));
    }
    let index = usize::from(slot);
    let ciphertext = AssetNoteCiphertextRef::from_bytes_exact(ciphertext)
        .map_err(|_| invalid("asset ciphertext width"))?;
    if ciphertext_hash_bytes(ciphertext.as_bytes()) != public.ciphertext_commitments[index] {
        return Err(invalid("asset ciphertext binding mismatch"));
    }
    let context = AssetNoteContext::new(
        source_digest(),
        public.chain_id,
        slot,
        commitment_bytes(public.commitments[index]),
    )
    .map_err(|_| invalid("asset output context invalid"))?;
    let plaintext = ciphertext
        .decrypt(secret_key, &context)
        .map_err(|_| invalid("asset note decryption failed"))?;
    let expected_asset = if slot == 2 { 0 } else { public.asset_id };
    let payload = match &plaintext.as_bytes()[..4] {
        b"ASN1" => RecoveredAssetNotePayload::Ordinary(AssetNotePayload::decode(
            &plaintext,
            public.chain_id,
            expected_asset,
        )?),
        b"ASB1" if slot == 0 && public.policy_mode == 1 => RecoveredAssetNotePayload::Script(
            ScriptAssetNotePayload::decode(&plaintext, public.chain_id, expected_asset)?,
        ),
        _ => return Err(invalid("asset payload codec or policy slot mismatch")),
    };
    let note = payload.as_note();
    if payload.recipient_index() != recipient_index
        || note.recipient_key != recipient_key
        || payload.committed_owner(public.chain_id, expected_asset)? != committed_owner
        || note_commitment(note).ok() != Some(public.commitments[index])
    {
        return Err(invalid(
            "asset recipient, full owner or commitment mismatch",
        ));
    }
    Ok(payload)
}

/// Recover one accepted output using only the finite, durably issued address
/// registry. Decryption alone does not grant policy authority: an ordinary
/// owner, or at least one enabled policy branch, must bind the local spend key.
pub(crate) fn recover_wallet_output(
    keys: &crate::DerivedKeys,
    issued: &crate::private_spend::IssuedPrivateSpendAddresses,
    public: &relation::AssetSpendPublic,
    slot: u8,
    ciphertext: &[u8],
) -> Result<Option<RecoveredAssetNotePayload>, WalletError> {
    use transaction_circuit::smallwood_poseidon2_v8_coinbase::{
        poseidon2_v8_single_key_authorization_digest, poseidon2_v8_words_from_canonical_bytes,
    };
    let index = usize::from(slot);
    if index >= 3 || ciphertext_hash_bytes(ciphertext) != public.ciphertext_commitments[index] {
        return Err(invalid("asset recovery ciphertext binding"));
    }
    let context = AssetNoteContext::new(
        source_digest(),
        public.chain_id,
        slot,
        commitment_bytes(public.commitments[index]),
    )
    .map_err(|_| invalid("asset recovery context"))?;
    let ciphertext = AssetNoteCiphertextRef::from_bytes_exact(ciphertext)
        .map_err(|_| invalid("asset recovery ciphertext width"))?;
    let authority = poseidon2_v8_single_key_authorization_digest(keys.spend.poseidon2_v8_words()?)
        .map_err(|_| invalid("asset local authority"))?;
    let expected_asset = if slot == 2 { 0 } else { public.asset_id };
    for address_index in issued.issued_indices() {
        let material = keys.poseidon2_v8_address(address_index)?;
        let Ok(plaintext) = ciphertext.decrypt(material.secret_key(), &context) else {
            continue;
        };
        let payload = match &plaintext.as_bytes()[..4] {
            b"ASN1" => AssetNotePayload::decode(&plaintext, public.chain_id, expected_asset)
                .map(RecoveredAssetNotePayload::Ordinary),
            b"ASB1" if slot == 0 && public.policy_mode == 1 => {
                ScriptAssetNotePayload::decode(&plaintext, public.chain_id, expected_asset)
                    .map(RecoveredAssetNotePayload::Script)
            }
            _ => continue,
        };
        let Ok(payload) = payload else { continue };
        let note = payload.as_note();
        if payload.recipient_index() != address_index
            || note.recipient_key
                != poseidon2_v8_words_from_canonical_bytes(material.pk_recipient)
                    .map_err(|_| invalid("asset local recipient"))?
            || note_commitment(note).ok() != Some(public.commitments[index])
        {
            continue;
        }
        let owned = match &payload {
            RecoveredAssetNotePayload::Ordinary(p) => p.authority == authority,
            RecoveredAssetNotePayload::Script(p) => p
                .policy
                .branches
                .iter()
                .any(|branch| branch.enabled == 1 && branch.authority == authority),
        };
        if owned {
            return Ok(Some(payload));
        }
    }
    Ok(None)
}

fn wipe_witness(witness: &mut relation::AssetSpendWitness) {
    for input in &mut witness.inputs {
        input.occupied.zeroize();
        input.legacy_ordinary.zeroize();
        input.position.zeroize();
        input.siblings.zeroize();
        input.spend_key.zeroize();
        input.dummy_secret.zeroize();
        wipe_note(&mut input.note);
    }
    for note in &mut witness.outputs {
        wipe_note(note);
    }
    witness.output_authorities.zeroize();
    for credential in &mut witness.credentials {
        credential.index.zeroize();
        credential.expires_at.zeroize();
        credential.siblings.zeroize();
    }
    witness.policy.create.zeroize();
    witness.policy.spend.zeroize();
    wipe_policy(&mut witness.policy.input);
    wipe_policy(&mut witness.policy.output);
    witness.policy.selected.zeroize();
    witness.policy.secret.zeroize();
    witness.issuer_secret.zeroize();
}
fn wipe_note(note: &mut Note) {
    note.value.zeroize();
    note.asset_id.zeroize();
    note.recipient_key.zeroize();
    note.authorization_key.zeroize();
    note.rho.zeroize();
    note.randomness.zeroize();
}

/// Validated construction. Secret witness stays private and is wiped
/// on every return path. There is deliberately no serde, Debug or store API.
pub struct PreparedAssetSpend {
    public: relation::AssetSpendPublic,
    witness: relation::AssetSpendWitness,
    ciphertexts: [AssetNoteCiphertext; 3],
}
impl Drop for PreparedAssetSpend {
    fn drop(&mut self) {
        wipe_witness(&mut self.witness);
    }
}
impl PreparedAssetSpend {
    /// Consumes the exact witness, checks all ciphertexts, then executes the
    /// candidate relation. Current-policy authentication belongs to admission.
    pub fn from_encrypted(
        public: relation::AssetSpendPublic,
        witness: relation::AssetSpendWitness,
        ciphertexts: [AssetNoteCiphertext; 3],
    ) -> Result<Self, WalletError> {
        let prepared = Self {
            public,
            witness,
            ciphertexts,
        };
        for slot in 0..3 {
            if ciphertext_hash_bytes(prepared.ciphertexts[slot].as_bytes())
                != prepared.public.ciphertext_commitments[slot]
            {
                return Err(invalid("prepared asset ciphertext binding mismatch"));
            }
        }
        let (adapter, mut packed) = relation::compile(&prepared.public, &prepared.witness)
            .map_err(|_| invalid("asset relation rejected construction"))?;
        packed.zeroize();
        drop(adapter);
        Ok(prepared)
    }
    pub fn public_statement(&self) -> &relation::AssetSpendPublic {
        &self.public
    }
    pub fn ciphertexts(&self) -> &[AssetNoteCiphertext; 3] {
        &self.ciphertexts
    }
    /// Proves and independently verifies the exact candidate statement. This
    /// grants no production acceptance, submission or release authority.
    pub fn prove_candidate(&self) -> Result<Vec<u8>, WalletError> {
        let proof = relation::prove_candidate(&self.public, &self.witness)
            .map_err(|_| invalid("asset proving failed"))?;
        relation::verify_candidate(&self.public, &proof)
            .map_err(|_| invalid("asset proof self-check failed"))?;
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng};
    use synthetic_crypto::{ml_kem::MlKemKeyPair, traits::KemKeyPair};
    use transaction_circuit::private_spend::set_note_owner;

    struct DisposableRng(rand::rngs::StdRng);
    impl rand_core09::TryRngCore for DisposableRng {
        type Error = rand::Error;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.0.next_u32())
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.0.next_u64())
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.0.try_fill_bytes(dst)
        }
    }
    impl TryCryptoRng for DisposableRng {}
    fn rng() -> DisposableRng {
        DisposableRng(rand::rngs::StdRng::seed_from_u64(9001))
    }
    fn note(asset: u32, value: u64, authority: Digest) -> Note {
        let mut note = Note {
            value,
            asset_id: u64::from(asset),
            recipient_key: [7; 4],
            authorization_key: [0; 4],
            rho: [8; 4],
            randomness: [9; 4],
        };
        set_note_owner(&mut note, ordinary_owner(authority).unwrap());
        note
    }
    fn payload(asset: u32) -> AssetNotePayload {
        AssetNotePayload {
            recipient_index: 19,
            note: note_opening(note(asset, 42, [5; 7])),
            authority: [5; 7],
        }
    }
    fn public() -> relation::AssetSpendPublic {
        relation::AssetSpendPublic {
            chain_id: [1; 32],
            reference_parent_hash: [2; 32],
            parent_height: 12,
            note_root: [3; 7],
            registry_root: [4; 7],
            asset_id: 17,
            policy_version: 1,
            credential_root: [6; 7],
            credential_depth: 4,
            frozen: false,
            mint_enabled: true,
            issuer_commitment: [10; 7],
            operation: relation::TRANSFER,
            magnitude: 0,
            fee: 1,
            nullifiers: [[11; 7], [12; 7]],
            commitments: [[0; 7]; 3],
            ciphertext_commitments: [[0; 48]; 3],
            policy_mode: 0,
            secret_release: 0,
            released_secret: [0; 32],
        }
    }
    fn witness() -> relation::AssetSpendWitness {
        relation::AssetSpendWitness {
            inputs: core::array::from_fn(|_| Default::default()),
            outputs: [
                note(17, 42, [5; 7]),
                note(17, 0, [6; 7]),
                note(0, 12, [7; 7]),
            ],
            output_authorities: [[5; 7], [6; 7], [7; 7]],
            credentials: core::array::from_fn(|_| relation::AssetCredentialWitness::default()),
            issuer_secret: [0; 7],
            policy: Default::default(),
        }
    }
    #[test]
    fn asset_note_codec_roundtrips_assets_chain_and_native_change_explicitly() {
        for asset in [0, 17, u32::MAX] {
            let p = payload(asset);
            let encoded = p.encode([1; 32], asset).unwrap();
            assert_eq!(encoded.as_bytes().len(), 1024);
            let decoded = AssetNotePayload::decode(&encoded, [1; 32], asset).unwrap();
            assert_eq!(decoded.recipient_index, 19);
            assert_eq!(decoded.as_note().value, 42);
            assert_eq!(decoded.as_note().asset_id, u64::from(asset));
            assert_eq!(decoded.authority, [5; 7]);
            assert!(AssetNotePayload::decode(&encoded, [2; 32], asset).is_err());
            assert!(AssetNotePayload::decode(&encoded, [1; 32], asset.wrapping_add(1)).is_err());
        }
        let native = payload(0).encode([1; 32], 0).unwrap();
        assert!(AssetNotePayload::decode(&native, [1; 32], 17).is_err());
    }
    #[test]
    fn asset_note_codec_rejects_versions_padding_ranges_field_aliases_and_owner_limb_changes() {
        let original = payload(17).encode([1; 32], 17).unwrap();
        for (offset, replacement) in [(0, 0), (1023, 1)] {
            let mut bytes = Zeroizing::new(*original.as_bytes());
            bytes[offset] = replacement;
            let plain = AssetNotePlaintext::from_bytes_exact(&bytes[..]).unwrap();
            assert!(AssetNotePayload::decode(&plain, [1; 32], 17).is_err());
        }
        for (word, value) in [
            (0, 1 << 56),
            (1, 1 << 32),
            (2, P),
            (10, P),
            (14, P),
            (18, P),
        ] {
            let mut bytes = Zeroizing::new(*original.as_bytes());
            bytes[40 + word * 8..48 + word * 8].copy_from_slice(&value.to_le_bytes());
            let plain = AssetNotePlaintext::from_bytes_exact(&bytes[..]).unwrap();
            assert!(AssetNotePayload::decode(&plain, [1; 32], 17).is_err());
        }
        for word in (10..13).chain(14..18).chain(18..25) {
            let mut bytes = Zeroizing::new(*original.as_bytes());
            bytes[40 + word * 8] ^= 1;
            let plain = AssetNotePlaintext::from_bytes_exact(&bytes[..]).unwrap();
            assert!(AssetNotePayload::decode(&plain, [1; 32], 17).is_err());
        }
    }
    #[test]
    fn asset_note_native_codec_cannot_be_reinterpreted() {
        let asset = payload(17).encode([1; 32], 17).unwrap();
        let native =
            synthetic_crypto::private_note_encryption::PrivateNotePlaintext::from_bytes_exact(
                asset.as_bytes(),
            )
            .unwrap();
        assert!(
            synthetic_crypto::private_note_payload::PrivateNotePayload::decode(&native, [1; 32])
                .is_err()
        );
    }
    #[test]
    fn asset_outputs_roundtrip_all_slots_and_bind_recipient_asset_chain_slot_and_commitment() {
        let keys = MlKemKeyPair::generate_deterministic(b"disposable-asset-wallet-test-key-v1");
        let pk = keys.public_key();
        let w = witness();
        let mut p = public();
        let ct = encrypt_outputs(&mut p, &w, [&pk; 3], [19, 20, 21], &mut rng()).unwrap();
        for slot in 0..3 {
            let recovered = decrypt_output(
                &p,
                slot as u8,
                ct[slot].as_bytes(),
                keys.secret_key(),
                19 + slot as u32,
                [7; 4],
                w.output_authorities[slot],
            )
            .unwrap();
            assert_eq!(recovered.note.value, w.outputs[slot].value);
            assert_eq!(recovered.note.asset_id, if slot == 2 { 0 } else { 17 });
            assert_eq!(ct[slot].as_bytes().len(), 2608);
            assert!(decrypt_output(
                &p,
                slot as u8,
                ct[slot].as_bytes(),
                keys.secret_key(),
                99,
                [7; 4],
                w.output_authorities[slot]
            )
            .is_err());
            assert!(decrypt_output(
                &p,
                slot as u8,
                ct[slot].as_bytes(),
                keys.secret_key(),
                19 + slot as u32,
                [8; 4],
                w.output_authorities[slot]
            )
            .is_err());
            let mut changed = p.clone();
            changed.chain_id[0] ^= 1;
            assert!(decrypt_output(
                &changed,
                slot as u8,
                ct[slot].as_bytes(),
                keys.secret_key(),
                19 + slot as u32,
                [7; 4],
                w.output_authorities[slot]
            )
            .is_err());
            let mut changed = p.clone();
            changed.commitments[slot][0] ^= 1;
            assert!(decrypt_output(
                &changed,
                slot as u8,
                ct[slot].as_bytes(),
                keys.secret_key(),
                19 + slot as u32,
                [7; 4],
                w.output_authorities[slot]
            )
            .is_err());
            assert!(decrypt_output(
                &p,
                ((slot + 1) % 3) as u8,
                ct[slot].as_bytes(),
                keys.secret_key(),
                19 + slot as u32,
                [7; 4],
                w.output_authorities[slot]
            )
            .is_err());
        }
        let mut changed = p.clone();
        changed.asset_id = 18;
        assert!(decrypt_output(
            &changed,
            0,
            ct[0].as_bytes(),
            keys.secret_key(),
            19,
            [7; 4],
            [5; 7]
        )
        .is_err());
        assert!(decrypt_output(
            &p,
            3,
            ct[0].as_bytes(),
            keys.secret_key(),
            19,
            [7; 4],
            [5; 7]
        )
        .is_err());
    }
    #[test]
    fn asset_encryption_rejects_wrong_asset_and_rng_failure_without_partial_public_mutation() {
        struct FailedRng;
        impl rand_core09::TryRngCore for FailedRng {
            type Error = &'static str;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Err("fixture")
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Err("fixture")
            }
            fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
                Err("fixture")
            }
        }
        impl TryCryptoRng for FailedRng {}
        let keys = MlKemKeyPair::generate_deterministic(b"disposable-asset-wallet-test-key-v1");
        let pk = keys.public_key();
        let mut p = public();
        let original = p.clone();
        assert!(encrypt_outputs(&mut p, &witness(), [&pk; 3], [0; 3], &mut FailedRng).is_err());
        assert_eq!(p, original);
        let mut w = witness();
        w.outputs[2].asset_id = 17;
        assert!(encrypt_outputs(&mut p, &w, [&pk; 3], [0; 3], &mut rng()).is_err());
        assert_eq!(p, original);
        let mut w = witness();
        w.output_authorities[1][6] ^= 1;
        assert!(encrypt_outputs(&mut p, &w, [&pk; 3], [0; 3], &mut rng()).is_err());
        assert_eq!(p, original);
    }
    fn script_payload() -> ScriptAssetNotePayload {
        let policy = BoundedPolicy {
            nullifier_key: [71, 72, 73, 74, 75],
            branches: [
                transaction_circuit::private_spend::PolicyBranch {
                    enabled: 1,
                    authority: [5; 7],
                    not_before: 10,
                    ..Default::default()
                },
                Default::default(),
            ],
        };
        let mut note = note(17, 42, [5; 7]);
        set_note_owner(&mut note, policy.owner([1; 32], 17).unwrap());
        ScriptAssetNotePayload {
            recipient_index: 19,
            note: note_opening(note),
            policy,
        }
    }
    #[test]
    fn script_codec_binds_full_policy_owner_and_rejects_cross_codec_and_padding() {
        let script = script_payload();
        let plain = script.encode([1; 32], 17).unwrap();
        assert_eq!(&plain.as_bytes()[..4], b"ASB1");
        let decoded = ScriptAssetNotePayload::decode(&plain, [1; 32], 17).unwrap();
        assert_eq!(
            decoded.committed_owner([1; 32], 17).unwrap(),
            script.committed_owner([1; 32], 17).unwrap()
        );
        assert!(AssetNotePayload::decode(&plain, [1; 32], 17).is_err());
        assert!(ScriptAssetNotePayload::decode(
            &payload(17).encode([1; 32], 17).unwrap(),
            [1; 32],
            17
        )
        .is_err());
        assert!(ScriptAssetNotePayload::decode(&plain, [2; 32], 17).is_err());
        assert!(ScriptAssetNotePayload::decode(&plain, [1; 32], 18).is_err());
        assert!(script.encode([1; 32], 0).is_err());
        for offset in [
            40 + 10 * 8,
            40 + 14 * 8,
            40 + 18 * 8,
            40 + 23 * 8,
            40 + 25 * 8,
            1023,
        ] {
            let mut changed = Zeroizing::new(*plain.as_bytes());
            changed[offset] ^= 1;
            assert!(ScriptAssetNotePayload::decode(
                &AssetNotePlaintext::from_bytes_exact(&changed[..]).unwrap(),
                [1; 32],
                17
            )
            .is_err());
        }
    }
    #[test]
    fn script_ciphertext_roundtrip_authenticates_owner_and_does_not_enter_ordinary_decoder() {
        let keys = MlKemKeyPair::generate_deterministic(b"disposable-script-asset-key-v1");
        let pk = keys.public_key();
        let script = script_payload();
        let mut w = witness();
        w.policy.create = 1;
        w.policy.output = script.policy.clone();
        w.outputs[0] = script.as_note();
        w.output_authorities[0] = [0; 7];
        let mut p = public();
        p.policy_mode = 1;
        let ciphertexts = encrypt_outputs(&mut p, &w, [&pk; 3], [19, 20, 21], &mut rng()).unwrap();
        let owner = script.committed_owner([1; 32], 17).unwrap();
        let decoded = decrypt_output_any(
            &p,
            0,
            ciphertexts[0].as_bytes(),
            keys.secret_key(),
            19,
            [7; 4],
            owner,
        )
        .unwrap();
        assert!(matches!(decoded, RecoveredAssetNotePayload::Script(_)));
        assert!(decrypt_output(
            &p,
            0,
            ciphertexts[0].as_bytes(),
            keys.secret_key(),
            19,
            [7; 4],
            [5; 7]
        )
        .is_err());
        let mut wrong_owner = owner;
        wrong_owner[6] ^= 1;
        assert!(decrypt_output_any(
            &p,
            0,
            ciphertexts[0].as_bytes(),
            keys.secret_key(),
            19,
            [7; 4],
            wrong_owner
        )
        .is_err());
        let mut ordinary_mode = p.clone();
        ordinary_mode.policy_mode = 0;
        assert!(decrypt_output_any(
            &ordinary_mode,
            0,
            ciphertexts[0].as_bytes(),
            keys.secret_key(),
            19,
            [7; 4],
            owner
        )
        .is_err());
    }
}

/// Issuer/admin supplied credential paths. They are checked by the relation
/// against the current authenticated policy row; this API invents no identity.
pub struct AssetSpendConstruction {
    pub asset_id: u32,
    pub operation: u8,
    pub amount: u64,
    pub fee: u64,
    pub recipient: crate::ShieldedAddress,
    pub asset_change_index: u32,
    pub native_change_index: u32,
    pub credentials: [relation::AssetCredentialWitness; 3],
    pub issuer_secret: Digest,
    pub policy: transaction_circuit::private_spend::PrivatePolicyOpening,
    /// Required for explicitly spending a policy-owned input.
    pub input_position: Option<u64>,
}
impl Drop for AssetSpendConstruction {
    fn drop(&mut self) {
        self.issuer_secret.zeroize();
        self.policy.secret.zeroize();
        self.policy.selected.zeroize();
        wipe_policy(&mut self.policy.input);
        wipe_policy(&mut self.policy.output);
        for c in &mut self.credentials {
            c.index.zeroize();
            c.expires_at.zeroize();
            c.siblings.zeroize();
        }
    }
}
pub struct PersistentPreparedAssetSpend {
    reservation_id: [u8; 32],
    context: crate::poseidon2_v8_sync::LaunchWalletContext,
    prepared: PreparedAssetSpend,
}
struct ConstructionInput(transaction_circuit::private_spend::PrivateInput);
impl Drop for ConstructionInput {
    fn drop(&mut self) {
        self.0.spend_key.zeroize();
        self.0.dummy_secret.zeroize();
        self.0.siblings.zeroize();
        wipe_note(&mut self.0.note);
    }
}
struct ConstructionWitness(Option<relation::AssetSpendWitness>);
impl Drop for ConstructionWitness {
    fn drop(&mut self) {
        if let Some(w) = &mut self.0 {
            wipe_witness(w);
        }
    }
}
impl PersistentPreparedAssetSpend {
    pub fn reservation_id(&self) -> [u8; 32] {
        self.reservation_id
    }
    pub fn public_statement(&self) -> &relation::AssetSpendPublic {
        self.prepared.public_statement()
    }
    /// The proof and its exact native wire bytes are durably retained before
    /// returning exportable bytes. Failure leaves an unexported reservation that
    /// the caller may abandon, or exclusive restart may safely release.
    pub fn prove_and_retain(&self, store: &crate::WalletStore) -> Result<Vec<u8>, WalletError> {
        let proof = self.prepared.prove_candidate()?;
        let c = core::array::from_fn(|i| *self.prepared.ciphertexts()[i].as_bytes());
        let body = transaction_circuit::asset_spend_v1_wire::encode_native_asset_spend_action_v1(
            self.prepared.public_statement(),
            &c,
            &proof,
        )
        .map_err(|_| invalid("native asset proof framing"))?;
        store.retain_asset_spend_candidate(self.context, self.reservation_id, &body)?;
        Ok(body)
    }
}
fn fresh_field<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<u64, WalletError> {
    loop {
        let value = rng
            .try_next_u64()
            .map_err(|_| invalid("asset note entropy unavailable"))?;
        if value < P {
            return Ok(value);
        }
    }
}
fn addressed_note<R: TryCryptoRng + ?Sized>(
    address: &crate::ShieldedAddress,
    value: u64,
    asset: u32,
    owner: Digest,
    rng: &mut R,
) -> Result<Note, WalletError> {
    let mut n=Note{value,asset_id:u64::from(asset),recipient_key:transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_from_canonical_bytes(address.pk_recipient).map_err(|_|invalid("asset address recipient"))?,authorization_key:[0;4],rho:[0;4],randomness:[0;4]};
    for w in n.rho.iter_mut().chain(n.randomness.iter_mut()) {
        *w = fresh_field(rng)?;
    }
    transaction_circuit::private_spend::set_note_owner(&mut n, owner);
    Ok(n)
}
fn address_authority(address: &crate::ShieldedAddress) -> Result<Digest, WalletError> {
    if address.version != crate::address::POSEIDON2_V8_ADDRESS_VERSION {
        return Err(invalid("asset address requires current full authority"));
    }
    let mut authority = [0; 7];
    authority[..4].copy_from_slice(&transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_from_canonical_bytes(address.pk_auth).map_err(|_|invalid("asset address authority"))?);
    for (out, bytes) in authority[4..]
        .iter_mut()
        .zip(address.pk_auth_extension.chunks_exact(8))
    {
        *out = u64::from_le_bytes(bytes.try_into().expect("fixed"));
    }
    if authority.iter().any(|w| *w >= P) {
        return Err(invalid("asset address authority noncanonical"));
    }
    Ok(authority)
}
pub(crate) fn validate_construction_accounting(
    row: &transaction_circuit::asset_registry_v1::AssetPolicyV1,
    chain: [u8; 32],
    height: u64,
    operation: u8,
    amount: u64,
) -> Result<(), WalletError> {
    use transaction_circuit::asset_registry_v1::{AssetOperationV1, AssetRegistryV1};
    let operation = match operation {
        relation::TRANSFER => AssetOperationV1::Transfer,
        relation::MINT => AssetOperationV1::Mint,
        relation::BURN => AssetOperationV1::Burn,
        _ => return Err(invalid("asset operation")),
    };
    // The complete row was authenticated above. A local one-row registry uses
    // the shared accounting implementation without reconstructing other rows.
    let registry = AssetRegistryV1::from_rows(chain, height, &[*row])
        .map_err(|_| invalid("asset accounting row"))?;
    registry
        .prepare_accounting(
            registry.context(),
            row.config.asset_id,
            row.config.policy_version,
            row.credential_root,
            operation,
            if operation == AssetOperationV1::Transfer {
                0
            } else {
                amount
            },
        )
        .map_err(|_| invalid("asset current accounting policy"))?;
    Ok(())
}
fn normalize_construction_credentials(
    credentials: &mut [relation::AssetCredentialWitness; 3],
    operation: u8,
    depth: u8,
) -> Result<(), WalletError> {
    if !matches!(depth, 4 | 8 | 16) {
        return Err(invalid("asset credential depth unsupported"));
    }
    let depth = usize::from(depth);
    for (slot, credential) in credentials.iter().enumerate() {
        if operation == relation::MINT && slot == 0 {
            // The unused input is canonical dummy data, not a membership
            // witness. Accept its compact API spelling or exact padded form.
            if credential.index != 0
                || credential.expires_at != 0
                || (!credential.siblings.is_empty() && credential.siblings.len() != depth)
                || credential.siblings.iter().any(|sibling| *sibling != [0; 7])
            {
                return Err(invalid(
                    "asset mint input credential must be canonical dummy",
                ));
            }
        } else if credential.siblings.len() != depth {
            return Err(invalid("asset credential depth mismatch"));
        }
    }
    if operation == relation::MINT {
        credentials[0].siblings.resize(depth, [0; 7]);
    }
    Ok(())
}
fn validate_credential_horizon(
    credentials: &[relation::AssetCredentialWitness; 3],
    operation: u8,
    height: u64,
) -> Result<(), WalletError> {
    let last = crate::asset_spend_rpc::reference_last_parent(height)?;
    if credentials.iter().enumerate().any(|(slot, credential)| {
        !(operation == relation::MINT && slot == 0) && credential.expires_at < last
    }) {
        return Err(invalid("asset credential expires before reference horizon"));
    }
    Ok(())
}
/// Build with the real encrypted wallet's atomically selected asset/native
/// inputs and canonical membership paths. Caller RNG must obtain OS entropy in
/// production. Recipient credentials and role secrets remain caller supplied.
pub fn prepare_persistent_asset_spend<R: TryCryptoRng + ?Sized>(
    store: &crate::WalletStore,
    node: &crate::asset_spend_rpc::AssetNodeContext,
    authenticated: &crate::asset_spend_rpc::AuthenticatedAssetPolicy,
    mut request: AssetSpendConstruction,
    rng: &mut R,
) -> Result<PersistentPreparedAssetSpend, WalletError> {
    node.require_wallet_tip(store)?;
    authenticated.require_context(node)?;
    let current = node.current();
    let row = authenticated.row();
    if request.asset_id != row.config.asset_id || request.amount >= 1 << 56 || request.operation > 2
    {
        return Err(invalid("asset request current policy or amount"));
    }
    normalize_construction_credentials(
        &mut request.credentials,
        request.operation,
        row.credential_depth,
    )?;
    validate_construction_accounting(
        row,
        current.chain_id,
        node.application().parent_height,
        request.operation,
        request.amount,
    )?;
    validate_credential_horizon(
        &request.credentials,
        request.operation,
        current.parent_height,
    )?;
    transaction_circuit::asset_spend_v1_admission::spend_profile_upper_bound_v1(
        u8::from(request.policy.create == 1 || request.policy.spend == 1),
        row.credential_depth,
    )
    .map_err(|_| invalid("asset native profile is unsupported"))?;
    let recipient_authority = address_authority(&request.recipient)?;
    let asset_change = store.private_spend_address(request.asset_change_index)?;
    let native_change = store.private_spend_address(request.native_change_index)?;
    let change_authority = address_authority(&asset_change)?;
    let native_authority = address_authority(&native_change)?;
    let selection = store.reserve_asset_spend(
        node.launch_context(),
        request.asset_id,
        request.operation,
        request.amount,
        request.fee,
        request.input_position,
    )?;
    let id = selection.reservation_id;
    let result = (|| {
        if selection.parent_height != current.parent_height
            || selection.parent_hash != current.reference_parent_hash
            || selection.note_root != current.note_root
        {
            return Err(invalid("asset selection tip changed"));
        }
        let mut asset_input = ConstructionInput(
            selection
                .asset
                .as_ref()
                .map(|s| s.input.clone())
                .unwrap_or_default(),
        );
        let asset_value = if request.operation == relation::MINT {
            for w in &mut asset_input.0.dummy_secret {
                *w = fresh_field(rng)?;
            }
            request.amount
        } else {
            asset_input.0.note.value
        };
        if let Some(input) = &selection.asset {
            if input.policy.as_ref()
                != if request.policy.spend == 1 {
                    Some(&request.policy.input)
                } else {
                    None
                }
            {
                return Err(invalid(
                    "asset input policy opening differs from stored note",
                ));
            }
        } else if request.policy.spend != 0 {
            return Err(invalid("mint cannot spend asset policy input"));
        }
        let (payment, change) = match request.operation {
            relation::TRANSFER => (request.amount, asset_value.checked_sub(request.amount)),
            relation::MINT => (request.amount, Some(0)),
            relation::BURN => (0, asset_value.checked_sub(request.amount)),
            _ => return Err(invalid("asset operation")),
        };
        let change = change.ok_or(invalid("asset amount exceeds input"))?;
        let owner = if request.policy.create == 1 {
            request
                .policy
                .output
                .owner(current.chain_id, u64::from(request.asset_id))
                .map_err(|_| invalid("asset output policy owner"))?
        } else {
            ordinary_owner(recipient_authority).map_err(|_| invalid("asset recipient owner"))?
        };
        let outputs = [
            addressed_note(&request.recipient, payment, request.asset_id, owner, rng)?,
            addressed_note(
                &asset_change,
                change,
                request.asset_id,
                ordinary_owner(change_authority).map_err(|_| invalid("asset change owner"))?,
                rng,
            )?,
            addressed_note(
                &native_change,
                selection
                    .native_fee
                    .input
                    .note
                    .value
                    .checked_sub(request.fee)
                    .ok_or(invalid("native fee exceeds input"))?,
                0,
                ordinary_owner(native_authority).map_err(|_| invalid("native change owner"))?,
                rng,
            )?,
        ];
        let nullifier0 = if request.operation == relation::MINT {
            relation::dummy_nullifier(current.chain_id, asset_input.0.dummy_secret)
                .map_err(|_| invalid("asset mint dummy nullifier"))?
        } else {
            selection.asset.as_ref().expect("selected asset").nullifier
        };
        let mut guarded_witness = ConstructionWitness(Some(relation::AssetSpendWitness {
            inputs: [asset_input.0.clone(), selection.native_fee.input.clone()],
            outputs,
            output_authorities: [
                if request.policy.create == 1 {
                    [0; 7]
                } else {
                    recipient_authority
                },
                change_authority,
                native_authority,
            ],
            credentials: request.credentials.clone(),
            issuer_secret: request.issuer_secret,
            policy: request.policy.clone(),
        }));
        let mut public = relation::AssetSpendPublic {
            chain_id: current.chain_id,
            reference_parent_hash: current.reference_parent_hash,
            parent_height: current.parent_height,
            note_root: current.note_root,
            registry_root: current.registry_root,
            asset_id: request.asset_id,
            policy_version: row.config.policy_version,
            credential_root: row.credential_root.map(|w| w.as_canonical_u64()),
            credential_depth: row.credential_depth,
            frozen: row.frozen,
            mint_enabled: row.mint_enabled,
            issuer_commitment: row.config.issuer_commitment.map(|w| w.as_canonical_u64()),
            operation: request.operation,
            magnitude: if request.operation == relation::TRANSFER {
                0
            } else {
                request.amount
            },
            fee: request.fee,
            nullifiers: [nullifier0, selection.native_fee.nullifier],
            commitments: [[0; 7]; 3],
            ciphertext_commitments: [[0; 48]; 3],
            policy_mode: u8::from(request.policy.create == 1 || request.policy.spend == 1),
            secret_release: 0,
            released_secret: [0; 32],
        };
        if request.policy.spend == 1 {
            let branch = request
                .policy
                .selected
                .iter()
                .position(|s| *s == 1)
                .ok_or(invalid("asset policy branch unselected"))?;
            if request.policy.input.branches[branch].release_secret == 1 {
                public.secret_release = 1;
                public.released_secret = request.policy.secret;
            }
        }
        let ciphertexts = encrypt_outputs(
            &mut public,
            guarded_witness.0.as_ref().expect("construction witness"),
            [
                &request.recipient.pk_enc,
                &asset_change.pk_enc,
                &native_change.pk_enc,
            ],
            [
                request.recipient.diversifier_index,
                asset_change.diversifier_index,
                native_change.diversifier_index,
            ],
            rng,
        )?;
        let prepared = PreparedAssetSpend::from_encrypted(
            public,
            guarded_witness.0.take().expect("construction witness"),
            ciphertexts,
        )?;
        Ok(PersistentPreparedAssetSpend {
            reservation_id: id,
            context: node.launch_context(),
            prepared,
        })
    })();
    if result.is_err() {
        store.abandon_asset_spend(node.launch_context(), id)?;
    }
    result
}

struct AssetOsEntropy(rand::rngs::OsRng);
impl rand_core09::TryRngCore for AssetOsEntropy {
    type Error = rand::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        use rand::RngCore;
        let mut bytes = [0; 4];
        self.0.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        use rand::RngCore;
        let mut bytes = [0; 8];
        self.0.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        use rand::RngCore;
        self.0.try_fill_bytes(dst)
    }
}
impl TryCryptoRng for AssetOsEntropy {}
/// Production-shaped entry point: all note randomness and KEM coins come from
/// the operating system. The deterministic runner remains separately gated.
pub fn prepare_persistent_asset_spend_os(
    store: &crate::WalletStore,
    node: &crate::asset_spend_rpc::AssetNodeContext,
    policy: &crate::asset_spend_rpc::AuthenticatedAssetPolicy,
    request: AssetSpendConstruction,
) -> Result<PersistentPreparedAssetSpend, WalletError> {
    prepare_persistent_asset_spend(
        store,
        node,
        policy,
        request,
        &mut AssetOsEntropy(rand::rngs::OsRng),
    )
}

#[cfg(all(test, feature = "private-spend-dev-artifacts"))]
mod persistent_recovery_tests {
    use super::*;
    use crate::{
        asset_spend_v1_fixture::DisposableAssetFixtureV1,
        private_spend::IssuedPrivateSpendAddresses, RootSecret,
    };
    #[test]
    fn compact_mint_input_credential_prepares_the_real_relation() {
        let mut fixture = DisposableAssetFixtureV1::build(relation::MINT, 4).unwrap();
        fixture.witness.credentials[0].siblings.clear();
        let payment = fixture.witness.credentials[1].clone();
        let change = fixture.witness.credentials[2].clone();
        normalize_construction_credentials(&mut fixture.witness.credentials, relation::MINT, 4)
            .unwrap();
        assert_eq!(fixture.witness.credentials[0].siblings, vec![[0; 7]; 4]);
        for (actual, expected) in fixture.witness.credentials[1..]
            .iter()
            .zip([payment, change])
        {
            assert_eq!(actual.index, expected.index);
            assert_eq!(actual.expires_at, expected.expires_at);
            assert_eq!(actual.siblings, expected.siblings);
        }
        fixture
            .encrypt_and_check(&mut AssetOsEntropy(rand::rngs::OsRng))
            .unwrap();
        let (adapter, mut packed) = relation::compile(&fixture.public, &fixture.witness).unwrap();
        let result = adapter.verify_packed_witness(&packed);
        packed.zeroize();
        result.unwrap();
    }
    #[test]
    fn mint_dummy_normalization_never_repairs_real_credentials_or_nonzero_padding() {
        for depth in [4, 8, 16] {
            let fixture = DisposableAssetFixtureV1::build(relation::MINT, depth).unwrap();
            let mut compact = fixture.witness.credentials.clone();
            compact[0].siblings.clear();
            normalize_construction_credentials(&mut compact, relation::MINT, depth).unwrap();
            assert_eq!(compact[0].siblings, vec![[0; 7]; usize::from(depth)]);
            for field in 0..5 {
                let mut invalid = compact.clone();
                match field {
                    0 => invalid[0].index = 1,
                    1 => invalid[0].expires_at = 1,
                    2 => invalid[0].siblings[0][0] = 1,
                    3 => invalid[1].siblings.clear(),
                    _ => invalid[2].siblings.clear(),
                }
                assert!(
                    normalize_construction_credentials(&mut invalid, relation::MINT, depth)
                        .is_err()
                );
            }
            let mut transfer = compact;
            transfer[0].siblings.clear();
            assert!(
                normalize_construction_credentials(&mut transfer, relation::TRANSFER, depth)
                    .is_err()
            );
            assert!(
                normalize_construction_credentials(&mut transfer, relation::BURN, depth).is_err()
            );
        }
    }
    #[test]
    fn inactive_mint_policy_does_not_trap_transfer_or_burn() {
        let fixture = DisposableAssetFixtureV1::build(relation::TRANSFER, 4).unwrap();
        let original = *fixture.registry.row(17).unwrap();
        let mut inactive = original;
        inactive.config.active = false;
        let mut future = original;
        future.config.enabled_at = fixture.public.parent_height + 1;
        future.config.retired_at = None;
        let mut retired = original;
        retired.config.retired_at = Some(fixture.public.parent_height);
        for row in [inactive, future, retired] {
            assert!(validate_construction_accounting(
                &row,
                fixture.public.chain_id,
                fixture.public.parent_height,
                relation::TRANSFER,
                20
            )
            .is_ok());
            assert!(validate_construction_accounting(
                &row,
                fixture.public.chain_id,
                fixture.public.parent_height,
                relation::BURN,
                20
            )
            .is_ok());
            assert!(validate_construction_accounting(
                &row,
                fixture.public.chain_id,
                fixture.public.parent_height,
                relation::MINT,
                20
            )
            .is_err());
        }
        let mut frozen = original;
        frozen.frozen = true;
        for operation in [relation::TRANSFER, relation::MINT, relation::BURN] {
            assert!(validate_construction_accounting(
                &frozen,
                fixture.public.chain_id,
                fixture.public.parent_height,
                operation,
                20
            )
            .is_err());
        }
    }
    #[test]
    fn durable_address_scope_recovers_all_three_outputs_including_native_fee_change() {
        let mut fixture = DisposableAssetFixtureV1::build(relation::TRANSFER, 4).unwrap();
        let ciphertexts = fixture
            .encrypt_and_check(&mut AssetOsEntropy(rand::rngs::OsRng))
            .unwrap();
        let keys = RootSecret::from_bytes([0xa5; 32]).derive();
        let mut issued = IssuedPrivateSpendAddresses::default();
        for slot in 0..3 {
            assert!(recover_wallet_output(
                &keys,
                &issued,
                &fixture.public,
                slot,
                ciphertexts[slot as usize].as_bytes()
            )
            .unwrap()
            .is_none());
        }
        issued.record_issued(7);
        for slot in 0..2 {
            let p = recover_wallet_output(
                &keys,
                &issued,
                &fixture.public,
                slot,
                ciphertexts[slot as usize].as_bytes(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(p.as_note().asset_id, 17);
        }
        assert!(recover_wallet_output(
            &keys,
            &issued,
            &fixture.public,
            2,
            ciphertexts[2].as_bytes()
        )
        .unwrap()
        .is_none());
        issued.record_issued(9);
        let p = recover_wallet_output(
            &keys,
            &issued,
            &fixture.public,
            2,
            ciphertexts[2].as_bytes(),
        )
        .unwrap()
        .unwrap();
        assert_eq!((p.as_note().asset_id, p.as_note().value), (0, 990));
        let wrong = RootSecret::from_bytes([0xa6; 32]).derive();
        assert!(recover_wallet_output(
            &wrong,
            &issued,
            &fixture.public,
            2,
            ciphertexts[2].as_bytes()
        )
        .unwrap()
        .is_none());
    }
}

#[cfg(test)]
mod credential_horizon_tests {
    use super::*;
    #[test]
    fn every_active_credential_covers_entire_reference_window() {
        let credential = relation::AssetCredentialWitness {
            index: 0,
            expires_at: 112,
            siblings: vec![[0; 7]; 4],
        };
        let mut credentials = [credential.clone(), credential.clone(), credential];
        assert!(validate_credential_horizon(&credentials, relation::TRANSFER, 100).is_ok());
        for slot in 0..3 {
            credentials[slot].expires_at = 111;
            assert!(validate_credential_horizon(&credentials, relation::TRANSFER, 100).is_err());
            credentials[slot].expires_at = 112;
        }
        credentials[0].expires_at = 0;
        assert!(validate_credential_horizon(&credentials, relation::MINT, 100).is_ok());
        credentials[1].expires_at = 111;
        assert!(validate_credential_horizon(&credentials, relation::MINT, 100).is_err());
        assert!(validate_credential_horizon(&credentials, relation::MINT, u64::MAX).is_err());
    }
}
