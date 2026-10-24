//! Recovery material only: no encryption, delivery proof or spending authority.
//! Caller keys must be generated independently of ordinary spending secrets.
#![forbid(unsafe_code)]
use crate::WalletError;
use rand_core09::TryCryptoRng;
use synthetic_crypto::private_note_payload::NoteOpening;
use transaction_circuit::{
    asset_recovery_v1 as core,
    private_spend::{note_commitment, Digest, Note},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Host-only helpers for the explicit Development operator. Reuse the wallet's
/// existing dependencies without changing Cargo.lock or any proof identity.
#[cfg(feature = "private-spend-dev-artifacts")]
pub mod operator {
    pub use synthetic_crypto::private_note_payload::NoteOpening;
    pub use zeroize::{Zeroize, Zeroizing};
    /// Independent OS randomness, rejection-sampled without field reduction.
    pub fn fresh_canonical_fields<const N: usize>() -> [u64; N] {
        use rand::RngCore;
        let mut words = [0; N];
        for word in &mut words {
            loop {
                let value = rand::rngs::OsRng.next_u64();
                if value < hegemon_field::GOLDILOCKS_MODULUS {
                    *word = value;
                    break;
                }
            }
        }
        words
    }
}

pub const RECOVERY_PLAINTEXT_BYTES_V1: usize = 1024;
const MAGIC: &[u8; 4] = b"ARN1";
const P: u64 = 0xffff_ffff_0000_0001;
const HEADER: usize = 152;
const END: usize = HEADER + 30 * 8;
fn invalid(s: &'static str) -> WalletError {
    WalletError::InvalidState(s)
}
fn canonical(words: &[u64]) -> bool {
    words.iter().all(|w| *w < P)
}

/// Public, exact delivery context; changing any field requires a new encoding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RecoveryNoteContextV1 {
    pub chain_id: [u8; 32],
    pub asset_id: u32,
    pub stable_policy_id: Digest,
    pub output_commitment: Digest,
}
impl RecoveryNoteContextV1 {
    pub fn validate(&self) -> Result<(), WalletError> {
        if self.chain_id == [0; 32]
            || self.asset_id == 0
            || !canonical(&self.stable_policy_id)
            || self.stable_policy_id == [0; 7]
            || !canonical(&self.output_commitment)
            || self.output_commitment == [0; 7]
        {
            return Err(invalid("recovery note context invalid"));
        }
        Ok(())
    }
}

/// Secret-bearing fixed-width bytes. No Debug, Clone or serde implementation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryNotePlaintextV1([u8; RECOVERY_PLAINTEXT_BYTES_V1]);
impl RecoveryNotePlaintextV1 {
    /// Shape conversion only; use RecoveryNoteMaterialV1::decode to authenticate.
    pub fn from_bytes_exact(bytes: &[u8]) -> Result<Self, WalletError> {
        if bytes.len() != RECOVERY_PLAINTEXT_BYTES_V1 {
            return Err(invalid("recovery plaintext width"));
        }
        let mut result = Self([0; RECOVERY_PLAINTEXT_BYTES_V1]);
        result.0.copy_from_slice(bytes);
        Ok(result)
    }
    pub fn as_bytes(&self) -> &[u8; RECOVERY_PLAINTEXT_BYTES_V1] {
        &self.0
    }
}

/// Everything a recovery prover needs once the canonical note position is known.
/// holder_authority is public-key material, never an ordinary spending secret.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryNoteMaterialV1 {
    pub note: NoteOpening,
    pub holder_authority: Digest,
    pub shared_nf_key: [u64; 5],
    pub stable_policy_id: Digest,
}
impl RecoveryNoteMaterialV1 {
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
    fn words(&self) -> Zeroizing<[u64; 30]> {
        let mut words = Zeroizing::new([0; 30]);
        words[0] = self.note.value;
        words[1] = self.note.asset_id;
        words[2..6].copy_from_slice(&self.note.recipient_key);
        words[6..10].copy_from_slice(&self.note.rho);
        words[10..14].copy_from_slice(&self.note.randomness);
        words[14..18].copy_from_slice(&self.note.authorization_key);
        words[18..25].copy_from_slice(&self.holder_authority);
        words[25..30].copy_from_slice(&self.shared_nf_key);
        words
    }
    /// Validated copy for the capsule prover. Temporary words zeroize on drop;
    /// no ordinary holder spending secret is part of this material schema.
    pub fn material_words(
        &self,
        context: &RecoveryNoteContextV1,
    ) -> Result<Zeroizing<[u64; 30]>, WalletError> {
        self.validate(context)?;
        Ok(self.words())
    }
    /// Strict reconstruction for archive decryption; no modular reduction or
    /// inferred owner bytes. Caller retains ownership/erasure of the input.
    pub fn from_material_words(
        w: &[u64; 30],
        context: &RecoveryNoteContextV1,
    ) -> Result<Self, WalletError> {
        let result = Self {
            note: NoteOpening {
                value: w[0],
                asset_id: w[1],
                recipient_key: w[2..6].try_into().unwrap(),
                rho: w[6..10].try_into().unwrap(),
                randomness: w[10..14].try_into().unwrap(),
                authorization_key: w[14..18].try_into().unwrap(),
            },
            holder_authority: w[18..25].try_into().unwrap(),
            shared_nf_key: w[25..30].try_into().unwrap(),
            stable_policy_id: context.stable_policy_id,
        };
        result.validate(context)?;
        Ok(result)
    }
    pub fn validate(&self, context: &RecoveryNoteContextV1) -> Result<(), WalletError> {
        context.validate()?;
        if self.note.asset_id != u64::from(context.asset_id)
            || self.note.value >= 1 << 56
            || self.stable_policy_id != context.stable_policy_id
            || !canonical(&self.words()[..])
        {
            return Err(invalid("recovery note fields or expected context mismatch"));
        }
        let owner = core::recovery_owner(
            context.chain_id,
            context.asset_id,
            self.stable_policy_id,
            self.holder_authority,
            self.shared_nf_key,
        )
        .map_err(|_| invalid("recovery note owner invalid"))?;
        if self.note.authorization_key != owner[..4] || self.note.randomness[..3] != owner[4..] {
            return Err(invalid("recovery note owner embedding mismatch"));
        }
        if note_commitment(self.as_note())
            .map_err(|_| invalid("recovery note commitment invalid"))?
            != context.output_commitment
        {
            return Err(invalid("recovery note commitment mismatch"));
        }
        Ok(())
    }
    pub fn common_nullifier(
        &self,
        context: &RecoveryNoteContextV1,
        position: u32,
    ) -> Result<Digest, WalletError> {
        self.validate(context)?;
        core::recovery_nullifier(self.shared_nf_key, position, self.note.rho)
            .map_err(|_| invalid("recovery note nullifier invalid"))
    }
    pub fn encode(
        &self,
        context: &RecoveryNoteContextV1,
    ) -> Result<RecoveryNotePlaintextV1, WalletError> {
        self.validate(context)?;
        let mut out = RecoveryNotePlaintextV1([0; RECOVERY_PLAINTEXT_BYTES_V1]);
        out.0[..4].copy_from_slice(MAGIC);
        out.0[4..36].copy_from_slice(&context.chain_id);
        out.0[36..40].copy_from_slice(&context.asset_id.to_le_bytes());
        for (chunk, word) in out.0[40..96]
            .chunks_exact_mut(8)
            .zip(context.stable_policy_id)
        {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        for (chunk, word) in out.0[96..HEADER]
            .chunks_exact_mut(8)
            .zip(context.output_commitment)
        {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        for (chunk, word) in out.0[HEADER..END]
            .chunks_exact_mut(8)
            .zip(self.words().iter())
        {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        Ok(out)
    }
    pub fn decode(
        plaintext: &RecoveryNotePlaintextV1,
        expected: &RecoveryNoteContextV1,
    ) -> Result<Self, WalletError> {
        expected.validate()?;
        let bytes = plaintext.as_bytes();
        if &bytes[..4] != MAGIC
            || bytes[4..36] != expected.chain_id
            || bytes[36..40] != expected.asset_id.to_le_bytes()
            || bytes[END..].iter().any(|b| *b != 0)
        {
            return Err(invalid("recovery plaintext codec context or padding"));
        }
        let read7 = |raw: &[u8]| -> Digest {
            std::array::from_fn(|i| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap()))
        };
        if read7(&bytes[40..96]) != expected.stable_policy_id
            || read7(&bytes[96..HEADER]) != expected.output_commitment
        {
            return Err(invalid("recovery plaintext policy or commitment context"));
        }
        let mut w = Zeroizing::new([0u64; 30]);
        for (word, chunk) in w.iter_mut().zip(bytes[HEADER..END].chunks_exact(8)) {
            *word = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        let result = Self {
            note: NoteOpening {
                value: w[0],
                asset_id: w[1],
                recipient_key: w[2..6].try_into().unwrap(),
                rho: w[6..10].try_into().unwrap(),
                randomness: w[10..14].try_into().unwrap(),
                authorization_key: w[14..18].try_into().unwrap(),
            },
            holder_authority: w[18..25].try_into().unwrap(),
            shared_nf_key: w[25..30].try_into().unwrap(),
            stable_policy_id: expected.stable_policy_id,
        };
        result.validate(expected)?;
        Ok(result)
    }
}

/// Honest-construction sampler, independent caller RNG; not a proof of randomness.
pub fn generate_shared_nf_key<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<Zeroizing<[u64; 5]>, WalletError> {
    let mut key = Zeroizing::new([0; 5]);
    for word in key.iter_mut() {
        loop {
            let mut bytes = Zeroizing::new([0; 8]);
            rng.try_fill_bytes(&mut bytes[..])
                .map_err(|_| invalid("recovery key entropy unavailable"))?;
            let candidate = u64::from_le_bytes(*bytes);
            if candidate > 0 && candidate < P {
                *word = candidate;
                break;
            }
        }
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (RecoveryNoteMaterialV1, RecoveryNoteContextV1) {
        let mut material = RecoveryNoteMaterialV1 {
            note: NoteOpening {
                value: 100,
                asset_id: 17,
                recipient_key: [2; 4],
                rho: [3; 4],
                randomness: [4; 4],
                authorization_key: [0; 4],
            },
            holder_authority: [5; 7],
            shared_nf_key: [6; 5],
            stable_policy_id: [7; 7],
        };
        let owner = core::recovery_owner(
            [8; 32],
            17,
            material.stable_policy_id,
            material.holder_authority,
            material.shared_nf_key,
        )
        .unwrap();
        material.note.authorization_key.copy_from_slice(&owner[..4]);
        material.note.randomness[..3].copy_from_slice(&owner[4..]);
        let context = RecoveryNoteContextV1 {
            chain_id: [8; 32],
            asset_id: 17,
            stable_policy_id: material.stable_policy_id,
            output_commitment: note_commitment(material.as_note()).unwrap(),
        };
        (material, context)
    }
    #[test]
    fn roundtrip_preserves_full_opening_and_common_nullifier() {
        let (material, context) = fixture();
        let plain = material.encode(&context).unwrap();
        let recovered = RecoveryNoteMaterialV1::decode(&plain, &context).unwrap();
        assert!(recovered.words()[..] == material.words()[..]);
        assert!(recovered.stable_policy_id == material.stable_policy_id);
        let nf = recovered.common_nullifier(&context, 19).unwrap();
        assert!(
            nf == transaction_circuit::private_spend::real_nullifier(
                material.shared_nf_key,
                19,
                material.as_note()
            )
            .unwrap()
        );
        assert!(nf != recovered.common_nullifier(&context, 20).unwrap());
        assert!(plain.as_bytes()[END..].iter().all(|b| *b == 0));
    }
    #[test]
    fn wrong_context_and_native_asset_reject() {
        let (material, context) = fixture();
        let plain = material.encode(&context).unwrap();
        for mutation in 0..5 {
            let mut wrong = context;
            match mutation {
                0 => wrong.chain_id[0] ^= 1,
                1 => wrong.asset_id = 18,
                2 => wrong.stable_policy_id[0] ^= 1,
                3 => wrong.output_commitment[6] ^= 1,
                _ => wrong.asset_id = 0,
            }
            assert!(RecoveryNoteMaterialV1::decode(&plain, &wrong).is_err());
        }
    }
    #[test]
    fn tampering_shape_padding_and_old_namespaces_reject() {
        let (material, context) = fixture();
        let plain = material.encode(&context).unwrap();
        assert!(RecoveryNotePlaintextV1::from_bytes_exact(&plain.as_bytes()[..1023]).is_err());
        for offset in [
            0,
            4,
            36,
            40,
            96,
            HEADER,
            HEADER + 2 * 8,
            HEADER + 6 * 8,
            HEADER + 10 * 8,
            HEADER + 14 * 8,
            HEADER + 18 * 8,
            HEADER + 25 * 8,
            END,
            1023,
        ] {
            let mut changed = RecoveryNotePlaintextV1::from_bytes_exact(plain.as_bytes()).unwrap();
            changed.0[offset] ^= 1;
            assert!(RecoveryNoteMaterialV1::decode(&changed, &context).is_err());
        }
        for magic in [b"ASN1", b"ASB1"] {
            let mut changed = RecoveryNotePlaintextV1::from_bytes_exact(plain.as_bytes()).unwrap();
            changed.0[..4].copy_from_slice(magic);
            assert!(RecoveryNoteMaterialV1::decode(&changed, &context).is_err());
        }
    }
    #[test]
    fn value_canonical_owner_and_zero_shared_key_reject() {
        for mutation in 0..5 {
            let (mut material, context) = fixture();
            match mutation {
                0 => material.note.value = 1 << 56,
                1 => material.note.recipient_key[0] = P,
                2 => material.note.authorization_key[3] ^= 1,
                3 => material.shared_nf_key = [0; 5],
                _ => material.note.asset_id = 0,
            }
            assert!(material.encode(&context).is_err());
        }
    }
    #[test]
    fn validated_material_word_bridge_checks_exact_context_and_owner() {
        let (material, context) = fixture();
        let words = material.material_words(&context).unwrap();
        let restored = RecoveryNoteMaterialV1::from_material_words(&words, &context).unwrap();
        assert_eq!(*restored.material_words(&context).unwrap(), *words);
        let mut wrong = context;
        wrong.stable_policy_id[0] ^= 1;
        assert!(RecoveryNoteMaterialV1::from_material_words(&words, &wrong).is_err());
        for index in [1, 14, 18, 25] {
            let mut bad = Zeroizing::new(*words);
            bad[index] ^= 1;
            assert!(RecoveryNoteMaterialV1::from_material_words(&bad, &context).is_err());
        }
    }
}
