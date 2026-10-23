//! Fixed-size opaque encryption for the common private-spend note payload.
//!
//! This module frames bytes and authenticates context; wallet/circuit callers own
//! note semantics and canonical commitment validation. Every plaintext, including
//! a zero-value note, uses the same encryption path. There is no clear recipient
//! hint, mode, suite, length field, or dummy sentinel in the ciphertext.

use alloc::vec::Vec;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::{
    deterministic::expand_to_length,
    ml_kem::{MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, MlKemSharedSecret},
    traits::KemPublicKey,
};

pub const PRIVATE_NOTE_PLAINTEXT_BYTES: usize = 1024;
pub const PRIVATE_NOTE_KEM_BYTES: usize = 1568;
pub const PRIVATE_NOTE_SEALED_BYTES: usize = PRIVATE_NOTE_PLAINTEXT_BYTES + 16;
pub const PRIVATE_NOTE_CIPHERTEXT_BYTES: usize = PRIVATE_NOTE_KEM_BYTES + PRIVATE_NOTE_SEALED_BYTES;
const KEM_RANDOMNESS_BYTES: usize = 32;
const AEAD_KEY_BYTES: usize = 32;
const AEAD_NONCE_BYTES: usize = 12;
const AAD_DOMAIN: &[u8] = b"HegemonPrivateSpendNoteAAD\x01";
const KDF_LABEL: &[u8] = b"private-spend-note/v1/ml-kem-1024/chacha20poly1305";
pub const PRIVATE_NOTE_AAD_BYTES: usize = AAD_DOMAIN.len() + 48 + 32 + 1 + 56;
const _: () = assert!(PRIVATE_NOTE_KEM_BYTES == crate::ml_kem::ML_KEM_CIPHERTEXT_LEN);
const _: () = assert!(PRIVATE_NOTE_CIPHERTEXT_BYTES == 2608);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateNoteError {
    InvalidSlot,
    InvalidLength { expected: usize, actual: usize },
    RandomnessFailure,
    EncryptionFailure,
    DecryptionFailure,
}

impl core::fmt::Display for PrivateNoteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSlot => f.write_str("private note output slot must be 0 or 1"),
            Self::InvalidLength { expected, actual } => {
                write!(f, "private note length: expected {expected}, got {actual}")
            }
            Self::RandomnessFailure => f.write_str("private note randomness failed"),
            Self::EncryptionFailure => f.write_str("private note encryption failed"),
            Self::DecryptionFailure => f.write_str("private note decryption failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrivateNoteError {}

/// Public context authenticated by the ciphertext, never a recipient hint.
/// The caller supplies the canonical 56-byte commitment encoding; this module
/// deliberately does not interpret field elements or validate note semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateNoteContext {
    relation_digest: [u8; 48],
    chain_id: [u8; 32],
    output_slot: u8,
    commitment: [u8; 56],
}

impl PrivateNoteContext {
    pub fn new(
        relation_digest: [u8; 48],
        chain_id: [u8; 32],
        output_slot: u8,
        commitment: [u8; 56],
    ) -> Result<Self, PrivateNoteError> {
        if output_slot > 1 {
            return Err(PrivateNoteError::InvalidSlot);
        }
        Ok(Self {
            relation_digest,
            chain_id,
            output_slot,
            commitment,
        })
    }

    /// Fixed-width, version-domain-separated framing. Ciphertext hashes are
    /// excluded because authenticating this ciphertext's own hash is circular.
    pub fn aad_bytes(&self) -> [u8; PRIVATE_NOTE_AAD_BYTES] {
        let mut aad = [0; PRIVATE_NOTE_AAD_BYTES];
        let mut at = AAD_DOMAIN.len();
        aad[..at].copy_from_slice(AAD_DOMAIN);
        aad[at..at + 48].copy_from_slice(&self.relation_digest);
        at += 48;
        aad[at..at + 32].copy_from_slice(&self.chain_id);
        at += 32;
        aad[at] = self.output_slot;
        at += 1;
        aad[at..].copy_from_slice(&self.commitment);
        aad
    }
}

/// Secret bytes zeroized on drop. Intentionally has no Debug, Clone, or serde API.
pub struct PrivateNotePlaintext(Zeroizing<[u8; PRIVATE_NOTE_PLAINTEXT_BYTES]>);

impl PrivateNotePlaintext {
    pub fn from_bytes_exact(bytes: &[u8]) -> Result<Self, PrivateNoteError> {
        if bytes.len() != PRIVATE_NOTE_PLAINTEXT_BYTES {
            return Err(PrivateNoteError::InvalidLength {
                expected: PRIVATE_NOTE_PLAINTEXT_BYTES,
                actual: bytes.len(),
            });
        }
        let mut plaintext = Zeroizing::new([0; PRIVATE_NOTE_PLAINTEXT_BYTES]);
        plaintext.copy_from_slice(bytes);
        Ok(Self(plaintext))
    }

    pub fn as_bytes(&self) -> &[u8; PRIVATE_NOTE_PLAINTEXT_BYTES] {
        &self.0
    }
}

/// Owned public carrier bytes: KEM ciphertext followed by one sealed payload.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateNoteCiphertext([u8; PRIVATE_NOTE_CIPHERTEXT_BYTES]);

impl PrivateNoteCiphertext {
    /// Requests new encapsulation randomness on every call. Callers must supply
    /// a cryptographic RNG with fresh state; deterministic RNGs are for tests.
    pub fn encrypt<R: TryCryptoRng + ?Sized>(
        recipient: &MlKemPublicKey,
        context: &PrivateNoteContext,
        plaintext: &PrivateNotePlaintext,
        rng: &mut R,
    ) -> Result<Self, PrivateNoteError> {
        let mut randomness = Zeroizing::new([0; KEM_RANDOMNESS_BYTES]);
        rng.try_fill_bytes(&mut randomness[..])
            .map_err(|_| PrivateNoteError::RandomnessFailure)?;
        let (kem, shared) = recipient.encapsulate(&randomness[..]);
        let material = aead_material(&shared);
        let cipher = ChaCha20Poly1305::new_from_slice(&material[..AEAD_KEY_BYTES])
            .map_err(|_| PrivateNoteError::EncryptionFailure)?;
        let aad = context.aad_bytes();
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&material[AEAD_KEY_BYTES..]),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| PrivateNoteError::EncryptionFailure)?;
        if sealed.len() != PRIVATE_NOTE_SEALED_BYTES
            || kem.as_bytes().len() != PRIVATE_NOTE_KEM_BYTES
        {
            return Err(PrivateNoteError::EncryptionFailure);
        }
        let mut bytes = [0; PRIVATE_NOTE_CIPHERTEXT_BYTES];
        bytes[..PRIVATE_NOTE_KEM_BYTES].copy_from_slice(kem.as_bytes());
        bytes[PRIVATE_NOTE_KEM_BYTES..].copy_from_slice(&sealed);
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; PRIVATE_NOTE_CIPHERTEXT_BYTES] {
        &self.0
    }

    pub fn as_ref(&self) -> PrivateNoteCiphertextRef<'_> {
        PrivateNoteCiphertextRef(&self.0)
    }

    pub fn decrypt(
        &self,
        recipient: &MlKemSecretKey,
        context: &PrivateNoteContext,
    ) -> Result<PrivateNotePlaintext, PrivateNoteError> {
        self.as_ref().decrypt(recipient, context)
    }
}

/// Exact-length borrowed carrier. Parsing establishes framing only, not valid
/// encryption or note semantics. Authentication happens in decrypt.
#[derive(Clone, Copy)]
pub struct PrivateNoteCiphertextRef<'a>(&'a [u8; PRIVATE_NOTE_CIPHERTEXT_BYTES]);

impl<'a> PrivateNoteCiphertextRef<'a> {
    pub fn from_bytes_exact(bytes: &'a [u8]) -> Result<Self, PrivateNoteError> {
        let bytes = bytes
            .try_into()
            .map_err(|_| PrivateNoteError::InvalidLength {
                expected: PRIVATE_NOTE_CIPHERTEXT_BYTES,
                actual: bytes.len(),
            })?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(self) -> &'a [u8; PRIVATE_NOTE_CIPHERTEXT_BYTES] {
        self.0
    }

    pub fn decrypt(
        self,
        recipient: &MlKemSecretKey,
        context: &PrivateNoteContext,
    ) -> Result<PrivateNotePlaintext, PrivateNoteError> {
        let kem = MlKemCiphertext::from_bytes(&self.0[..PRIVATE_NOTE_KEM_BYTES])
            .map_err(|_| PrivateNoteError::DecryptionFailure)?;
        let shared = recipient
            .decapsulate(&kem)
            .map_err(|_| PrivateNoteError::DecryptionFailure)?;
        let material = aead_material(&shared);
        let cipher = ChaCha20Poly1305::new_from_slice(&material[..AEAD_KEY_BYTES])
            .map_err(|_| PrivateNoteError::DecryptionFailure)?;
        let aad = context.aad_bytes();
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&material[AEAD_KEY_BYTES..]),
                    Payload {
                        msg: &self.0[PRIVATE_NOTE_KEM_BYTES..],
                        aad: &aad,
                    },
                )
                .map_err(|_| PrivateNoteError::DecryptionFailure)?,
        );
        PrivateNotePlaintext::from_bytes_exact(&plaintext)
    }
}

fn aead_material(shared: &MlKemSharedSecret) -> Zeroizing<Vec<u8>> {
    let mut input = Zeroizing::new(Vec::with_capacity(
        shared.as_bytes().len() + KDF_LABEL.len(),
    ));
    input.extend_from_slice(shared.as_bytes());
    input.extend_from_slice(KDF_LABEL);
    // Same expansion construction as note_encryption, with a new versioned,
    // suite-specific label. The derived secret material is zeroized on drop.
    Zeroizing::new(expand_to_length(
        b"wallet-aead",
        &input,
        AEAD_KEY_BYTES + AEAD_NONCE_BYTES,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ml_kem::MlKemKeyPair, traits::KemKeyPair};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn context(slot: u8) -> PrivateNoteContext {
        PrivateNoteContext::new([3; 48], [4; 32], slot, [5; 56]).unwrap()
    }
    fn keys() -> MlKemKeyPair {
        MlKemKeyPair::generate_deterministic(b"private-note-disposable-test-key-v1")
    }
    fn plaintext() -> PrivateNotePlaintext {
        PrivateNotePlaintext::from_bytes_exact(&core::array::from_fn::<_, 1024, _>(|i| {
            (i % 251) as u8
        }))
        .unwrap()
    }
    fn encrypt(context: &PrivateNoteContext) -> PrivateNoteCiphertext {
        PrivateNoteCiphertext::encrypt(
            &keys().public_key(),
            context,
            &plaintext(),
            &mut ChaCha20Rng::from_seed([7; 32]),
        )
        .unwrap()
    }

    #[test]
    fn private_note_roundtrip_both_slots_and_exact_borrow() {
        for slot in 0..2 {
            let ct = encrypt(&context(slot));
            assert_eq!(ct.as_bytes().len(), 2608);
            let borrowed = PrivateNoteCiphertextRef::from_bytes_exact(ct.as_bytes()).unwrap();
            assert!(core::ptr::eq(
                borrowed.as_bytes().as_ptr(),
                ct.as_bytes().as_ptr()
            ));
            let decoded = borrowed
                .decrypt(keys().secret_key(), &context(slot))
                .unwrap();
            assert_eq!(decoded.as_bytes(), plaintext().as_bytes());
        }
    }

    #[test]
    fn private_note_zero_payload_uses_real_encryption() {
        let zero = PrivateNotePlaintext::from_bytes_exact(&[0; 1024]).unwrap();
        let ct = PrivateNoteCiphertext::encrypt(
            &keys().public_key(),
            &context(0),
            &zero,
            &mut ChaCha20Rng::from_seed([8; 32]),
        )
        .unwrap();
        assert!(ct.as_bytes()[..1568].iter().any(|b| *b != 0));
        assert_eq!(
            ct.decrypt(keys().secret_key(), &context(0))
                .unwrap()
                .as_bytes(),
            &[0; 1024]
        );
    }

    #[test]
    fn private_note_authenticates_each_context_field() {
        let ct = encrypt(&context(0));
        let mut variants = [context(0); 4];
        variants[0].relation_digest[0] ^= 1;
        variants[1].chain_id[31] ^= 1;
        variants[2].output_slot = 1;
        variants[3].commitment[55] ^= 1;
        for changed in variants {
            assert!(matches!(
                ct.decrypt(keys().secret_key(), &changed),
                Err(PrivateNoteError::DecryptionFailure)
            ));
        }
    }

    #[test]
    fn private_note_rejects_wrong_recipient_and_corruption() {
        let ct = encrypt(&context(0));
        let other = MlKemKeyPair::generate_deterministic(b"other-disposable-private-note-test-key");
        assert!(matches!(
            ct.decrypt(other.secret_key(), &context(0)),
            Err(PrivateNoteError::DecryptionFailure)
        ));
        for offset in [0, 1567, 1568, 2591, 2607] {
            let mut changed = ct.clone();
            changed.0[offset] ^= 1;
            assert!(matches!(
                changed.decrypt(keys().secret_key(), &context(0)),
                Err(PrivateNoteError::DecryptionFailure)
            ));
        }
    }

    #[test]
    fn private_note_rejects_short_trailing_and_oversized_inputs() {
        let bytes = [0; 2609];
        for len in [0, 1, 1568, 2607, 2609] {
            assert!(
                matches!(PrivateNoteCiphertextRef::from_bytes_exact(&bytes[..len]),
                Err(PrivateNoteError::InvalidLength { expected: 2608, actual }) if actual == len)
            );
        }
        let bytes = [0; 1025];
        for len in [0, 1023, 1025] {
            assert!(
                matches!(PrivateNotePlaintext::from_bytes_exact(&bytes[..len]),
                Err(PrivateNoteError::InvalidLength { expected: 1024, actual }) if actual == len)
            );
        }
        for slot in [2, u8::MAX] {
            assert_eq!(
                PrivateNoteContext::new([0; 48], [0; 32], slot, [0; 56]),
                Err(PrivateNoteError::InvalidSlot)
            );
        }
    }

    #[test]
    fn private_note_fresh_randomness_changes_both_ciphertext_parts() {
        let mut rng = ChaCha20Rng::from_seed([9; 32]);
        let pk = keys().public_key();
        let a = PrivateNoteCiphertext::encrypt(&pk, &context(0), &plaintext(), &mut rng).unwrap();
        let b = PrivateNoteCiphertext::encrypt(&pk, &context(0), &plaintext(), &mut rng).unwrap();
        assert_ne!(&a.as_bytes()[..1568], &b.as_bytes()[..1568]);
        assert_ne!(&a.as_bytes()[1568..], &b.as_bytes()[1568..]);
        assert_eq!(
            a.decrypt(keys().secret_key(), &context(0))
                .unwrap()
                .as_bytes(),
            plaintext().as_bytes()
        );
        assert_eq!(
            b.decrypt(keys().secret_key(), &context(0))
                .unwrap()
                .as_bytes(),
            plaintext().as_bytes()
        );
    }

    #[test]
    fn private_note_rng_failure_is_not_a_ciphertext() {
        struct FailedRng;
        impl rand_core::TryRngCore for FailedRng {
            type Error = &'static str;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Err("test failure")
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Err("test failure")
            }
            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                // Exercise failure even after a partial write of RNG material.
                if let Some(first) = dst.first_mut() {
                    *first = 42;
                }
                Err("test failure")
            }
        }
        impl rand_core::TryCryptoRng for FailedRng {}
        assert!(matches!(
            PrivateNoteCiphertext::encrypt(
                &keys().public_key(),
                &context(0),
                &plaintext(),
                &mut FailedRng
            ),
            Err(PrivateNoteError::RandomnessFailure)
        ));
    }

    #[test]
    fn private_note_aad_layout_is_fixed_and_domain_separated() {
        let aad = context(1).aad_bytes();
        let n = AAD_DOMAIN.len();
        assert_eq!(&aad[..n], b"HegemonPrivateSpendNoteAAD\x01");
        assert_eq!(&aad[n..n + 48], &[3; 48]);
        assert_eq!(&aad[n + 48..n + 80], &[4; 32]);
        assert_eq!(aad[n + 80], 1);
        assert_eq!(&aad[n + 81..], &[5; 56]);
        assert_ne!(KDF_LABEL, b"note-aead");
        assert_ne!(KDF_LABEL, b"memo-aead");
    }
}
