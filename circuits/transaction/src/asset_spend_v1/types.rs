//! Exact candidate statement and private witness. Secret-bearing types have no Debug or serde.

pub type Digest = [u64; 7];
pub type Note = crate::private_spend::Note;
pub type AssetInput = crate::private_spend::PrivateInput;
pub const PUBLIC_WORDS: usize = 134;
/// Maximum age of the authenticated reference parent at native admission.
/// Active credentials must remain valid through this entire parent window.
pub const ASSET_REFERENCE_WINDOW: u64 = 12;

/// Exact integer credential horizon; reject both u64 overflow and 48-bit wrap.
pub fn credential_validity_horizon(
    parent_height: u64,
) -> Result<u64, crate::TransactionCircuitError> {
    parent_height
        .checked_add(ASSET_REFERENCE_WINDOW)
        .filter(|horizon| *horizon < (1u64 << 48))
        .ok_or_else(|| super::error("asset credential horizon exceeds 48 bits"))
}

pub const RELATION_ID: &str = "Hegemon.AssetSpend.BoundedPolicy.Credentials.CompFF01.v3";
pub const PRODUCTION_AUTHORIZED: bool = false;
pub const SOURCE_LOWERING_CERTIFICATE_COMPLETE: bool = false;
pub const TRANSFER: u8 = 0;
pub const MINT: u8 = 1;
pub const BURN: u8 = 2;
pub const CREDENTIAL_LEAF_DOMAIN: u64 = 0x4153_4352_4544_0001;
pub const CREDENTIAL_NODE_DOMAIN: u64 = 0x4153_4352_4e44_0000;
pub const DUMMY_NULLIFIER_DOMAIN: u64 = 0x4153_4455_4d59_0001;

pub(crate) const HEIGHT: usize = 16;
pub(crate) const NOTE_ROOT: usize = 17;
pub(crate) const REGISTRY_ROOT: usize = 24;
pub(crate) const ASSET: usize = 31;
pub(crate) const POLICY_VERSION: usize = 32;
pub(crate) const CREDENTIAL_ROOT: usize = 33;
pub(crate) const CREDENTIAL_DEPTH: usize = 40;
pub(crate) const FROZEN: usize = 41;
pub(crate) const MINT_ENABLED: usize = 42;
pub(crate) const ISSUER: usize = 43;
pub(crate) const OPERATION: usize = 50;
pub(crate) const MAGNITUDE: usize = 51;
pub(crate) const FEE: usize = 52;
pub(crate) const NULLIFIERS: usize = 53;
pub(crate) const COMMITMENTS: usize = 67;
pub(crate) const CIPHERTEXTS: usize = 88;
pub(crate) const POLICY_MODE: usize = 124;
pub(crate) const SECRET_RELEASE: usize = 125;
pub(crate) const RELEASED_SECRET: usize = 126;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetSpendPublic {
    pub chain_id: [u8; 32],
    pub reference_parent_hash: [u8; 32],
    pub parent_height: u64,
    pub note_root: Digest,
    pub registry_root: Digest,
    pub asset_id: u32,
    pub policy_version: u32,
    pub credential_root: Digest,
    pub credential_depth: u8,
    pub frozen: bool,
    pub mint_enabled: bool,
    pub issuer_commitment: Digest,
    pub operation: u8,
    pub magnitude: u64,
    pub fee: u64,
    pub nullifiers: [Digest; 2],
    pub commitments: [Digest; 3],
    pub ciphertext_commitments: [[u8; 48]; 3],
    /// Public geometry choice:0 ordinary-only,1 bounded two-branch policies.
    pub policy_mode: u8,
    pub secret_release: u64,
    pub released_secret: [u8; 32],
}

pub(crate) fn append_bytes(out: &mut Vec<u64>, bytes: &[u8]) {
    for chunk in bytes.chunks_exact(4) {
        out.push(u32::from_le_bytes(chunk.try_into().expect("four bytes")) as u64);
    }
}
impl AssetSpendPublic {
    pub fn words(&self) -> [u64; PUBLIC_WORDS] {
        let mut words = Vec::with_capacity(PUBLIC_WORDS);
        append_bytes(&mut words, &self.chain_id);
        append_bytes(&mut words, &self.reference_parent_hash);
        words.push(self.parent_height);
        words.extend(self.note_root);
        words.extend(self.registry_root);
        words.extend([u64::from(self.asset_id), u64::from(self.policy_version)]);
        words.extend(self.credential_root);
        words.extend([
            u64::from(self.credential_depth),
            u64::from(self.frozen),
            u64::from(self.mint_enabled),
        ]);
        words.extend(self.issuer_commitment);
        words.extend([u64::from(self.operation), self.magnitude, self.fee]);
        words.extend(self.nullifiers.into_iter().flatten());
        words.extend(self.commitments.into_iter().flatten());
        for digest in self.ciphertext_commitments {
            append_bytes(&mut words, &digest);
        }
        words.extend([u64::from(self.policy_mode), self.secret_release]);
        append_bytes(&mut words, &self.released_secret);
        words.try_into().expect("fixed asset public schema")
    }
    pub fn binding_bytes(&self) -> Vec<u8> {
        self.words()
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect()
    }
    pub fn validate_structure(&self) -> Result<(), crate::TransactionCircuitError> {
        credential_validity_horizon(self.parent_height)?;
        if self.chain_id == [0; 32]
            || self.reference_parent_hash == [0; 32]
            || self.asset_id == 0
            || !matches!(self.credential_depth, 4 | 8 | 16)
            || self.policy_mode > 1
            || self.secret_release > 1
            || (self.secret_release == 0 && self.released_secret != [0; 32])
            || (self.policy_mode == 0 && self.secret_release != 0)
            || self.operation > BURN
            || self.fee >= 1 << 56
            || self.magnitude >= 1 << 56
            || self.nullifiers[0] == self.nullifiers[1]
            || self
                .words()
                .iter()
                .any(|word| *word >= hegemon_field::GOLDILOCKS_MODULUS)
        {
            return Err(super::error("asset spend public shape"));
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct AssetCredentialWitness {
    pub index: u32,
    pub expires_at: u64,
    pub siblings: Vec<Digest>,
}

#[derive(Clone)]
pub struct AssetSpendWitness {
    /// Slot0 is the asset note (canonical dummy only for mint); slot1 is real native fee funding.
    pub inputs: [AssetInput; 2],
    /// Asset payment, asset change, native change; all three notes are committed.
    pub outputs: [Note; 3],
    pub output_authorities: [Digest; 3],
    /// In order: asset input, asset payment, asset change. Mint input proof is canonical zero.
    pub credentials: [AssetCredentialWitness; 3],
    pub issuer_secret: Digest,
    /// Exact shared native descriptor/evaluator; only input0 and output0 may be scripted.
    pub policy: crate::private_spend::PrivatePolicyOpening,
}
pub(crate) fn note_words(note: Note) -> [u64; 18] {
    [
        note.value,
        note.asset_id,
        note.recipient_key[0],
        note.recipient_key[1],
        note.recipient_key[2],
        note.recipient_key[3],
        note.rho[0],
        note.rho[1],
        note.rho[2],
        note.rho[3],
        note.randomness[0],
        note.randomness[1],
        note.randomness[2],
        note.randomness[3],
        note.authorization_key[0],
        note.authorization_key[1],
        note.authorization_key[2],
        note.authorization_key[3],
    ]
}
impl AssetSpendWitness {
    pub(crate) fn words(
        &self,
        public: &AssetSpendPublic,
    ) -> Result<Vec<u64>, crate::TransactionCircuitError> {
        let mut words = (0..=BURN)
            .map(|op| u64::from(op == public.operation))
            .collect::<Vec<_>>();
        for input in &self.inputs {
            words.extend([input.occupied, input.legacy_ordinary]);
            words.extend(note_words(input.note));
            words.push(u64::from(input.position));
            words.extend(input.siblings.into_iter().flatten());
            words.extend(input.spend_key);
            words.extend(input.dummy_secret);
        }
        for note in self.outputs {
            words.extend(note_words(note));
        }
        words.extend(self.output_authorities.into_iter().flatten());
        for credential in &self.credentials {
            if credential.siblings.len() != usize::from(public.credential_depth) {
                return Err(super::error("asset credential depth mismatch"));
            }
            words.extend([u64::from(credential.index), credential.expires_at]);
            words.extend(credential.siblings.iter().flatten().copied());
        }
        words.extend(self.issuer_secret);
        let chosen = self.issuer_secret.iter().position(|word| *word != 0);
        words.extend(
            (0..7).map(|index| u64::from(public.operation == MINT && chosen == Some(index))),
        );
        if public.policy_mode == 0 {
            if self.policy.create != 0
                || self.policy.spend != 0
                || self.policy.input != crate::private_spend::BoundedPolicy::default()
                || self.policy.output != crate::private_spend::BoundedPolicy::default()
                || self.policy.selected != [0; 2]
                || self.policy.secret != [0; 32]
            {
                return Err(super::error(
                    "ordinary asset graph requires zero policy witness",
                ));
            }
        } else {
            self.policy.append_words(&mut words);
        }
        Ok(words)
    }
}
