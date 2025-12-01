//! Note encryption for shielded transactions
//!
//! This module provides ML-KEM + ChaCha20Poly1305 encryption for notes.
//! It is used by both the wallet (for regular transactions) and the node
//! (for coinbase note encryption).
//!
//! The encryption scheme:
//! 1. Encapsulate a shared secret to recipient's pk_enc using ML-KEM
//! 2. Derive AEAD key and nonce from shared secret + label
//! 3. Encrypt note payload with ChaCha20Poly1305
//! 4. Encrypt memo separately with same scheme

use alloc::vec::Vec;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit,
};

use crate::{
    deterministic::expand_to_length,
    ml_kem::{MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, MlKemSharedSecret},
    traits::KemPublicKey,
    CryptoError,
};

const AEAD_KEY_SIZE: usize = 32;
const AEAD_NONCE_SIZE: usize = 12;

/// Note plaintext data
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotePlaintext {
    pub value: u64,
    pub asset_id: u64,
    pub rho: [u8; 32],
    pub r: [u8; 32],
    pub memo: Vec<u8>,
}

impl NotePlaintext {
    /// Create a new note with the given values
    pub fn new(value: u64, asset_id: u64, rho: [u8; 32], r: [u8; 32], memo: Vec<u8>) -> Self {
        Self {
            value,
            asset_id,
            rho,
            r,
            memo,
        }
    }

    /// Create a coinbase note with deterministic rho/r derived from seed
    pub fn coinbase(value: u64, seed: &[u8; 32]) -> Self {
        let rho = derive_coinbase_rho(seed);
        let r = derive_coinbase_r(seed);
        Self {
            value,
            asset_id: 0, // Native asset
            rho,
            r,
            memo: Vec::new(),
        }
    }
}

/// Derive rho for coinbase from seed
pub fn derive_coinbase_rho(seed: &[u8; 32]) -> [u8; 32] {
    let bytes = expand_to_length(b"coinbase-rho", seed, 32);
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&bytes);
    rho
}

/// Derive r for coinbase from seed
pub fn derive_coinbase_r(seed: &[u8; 32]) -> [u8; 32] {
    let bytes = expand_to_length(b"coinbase-r", seed, 32);
    let mut r = [0u8; 32];
    r.copy_from_slice(&bytes);
    r
}

/// Encrypted note ciphertext
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteCiphertext {
    pub version: u8,
    pub diversifier_index: u32,
    pub kem_ciphertext: Vec<u8>,
    pub note_payload: Vec<u8>,
    pub memo_payload: Vec<u8>,
    pub hint_tag: [u8; 32],
}

/// Internal payload structure for serialization
#[derive(Clone, Debug)]
struct NotePayload {
    value: u64,
    asset_id: u64,
    rho: [u8; 32],
    r: [u8; 32],
    pk_recipient: [u8; 32],
}

impl NotePayload {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 8 + 32 + 32 + 32);
        out.extend_from_slice(&self.value.to_le_bytes());
        out.extend_from_slice(&self.asset_id.to_le_bytes());
        out.extend_from_slice(&self.rho);
        out.extend_from_slice(&self.r);
        out.extend_from_slice(&self.pk_recipient);
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 8 + 8 + 32 + 32 + 32 {
            return Err(CryptoError::InvalidLength {
                expected: 8 + 8 + 32 + 32 + 32,
                actual: bytes.len(),
            });
        }
        let value = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let asset_id = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&bytes[16..48]);
        let mut r = [0u8; 32];
        r.copy_from_slice(&bytes[48..80]);
        let mut pk_recipient = [0u8; 32];
        pk_recipient.copy_from_slice(&bytes[80..112]);
        Ok(Self {
            value,
            asset_id,
            rho,
            r,
            pk_recipient,
        })
    }
}

impl NoteCiphertext {
    /// Encrypt a note to a recipient's public key
    ///
    /// # Arguments
    /// * `pk_enc` - Recipient's ML-KEM public key
    /// * `pk_recipient` - Recipient's 32-byte recipient key (for commitment)
    /// * `version` - Address version byte
    /// * `diversifier_index` - Address diversifier index
    /// * `address_tag` - Address hint tag (32 bytes)
    /// * `note` - Note plaintext to encrypt
    /// * `kem_randomness` - 32 bytes of randomness for KEM encapsulation
    pub fn encrypt(
        pk_enc: &MlKemPublicKey,
        pk_recipient: [u8; 32],
        version: u8,
        diversifier_index: u32,
        address_tag: [u8; 32],
        note: &NotePlaintext,
        kem_randomness: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        // Encapsulate shared secret
        let (kem_ct, shared) = pk_enc.encapsulate(kem_randomness);

        // Build payload
        let payload = NotePayload {
            value: note.value,
            asset_id: note.asset_id,
            rho: note.rho,
            r: note.r,
            pk_recipient,
        };
        let payload_bytes = payload.to_bytes();

        // Build AAD
        let aad = build_aad(version, diversifier_index, &address_tag);

        // Encrypt note payload
        let note_payload = encrypt_payload(&shared, b"note-aead", &payload_bytes, &aad)?;

        // Encrypt memo
        let memo_payload = encrypt_payload(&shared, b"memo-aead", &note.memo, &aad)?;

        Ok(Self {
            version,
            diversifier_index,
            kem_ciphertext: kem_ct.to_bytes().to_vec(),
            note_payload,
            memo_payload,
            hint_tag: address_tag,
        })
    }

    /// Decrypt a note using the recipient's secret key
    ///
    /// # Arguments
    /// * `sk_enc` - Recipient's ML-KEM secret key
    /// * `expected_pk_recipient` - Expected pk_recipient to verify against
    /// * `expected_diversifier_index` - Expected diversifier index
    /// * `expected_tag` - Expected address tag
    pub fn decrypt(
        &self,
        sk_enc: &MlKemSecretKey,
        expected_pk_recipient: [u8; 32],
        expected_diversifier_index: u32,
        expected_tag: [u8; 32],
    ) -> Result<NotePlaintext, CryptoError> {
        // Verify hint tag matches
        if self.hint_tag != expected_tag {
            return Err(CryptoError::DecryptionFailed(
                "address tag mismatch".into(),
            ));
        }

        // Verify diversifier index
        if self.diversifier_index != expected_diversifier_index {
            return Err(CryptoError::DecryptionFailed(
                "diversifier index mismatch".into(),
            ));
        }

        // Decapsulate shared secret
        let kem_ct = MlKemCiphertext::from_bytes(&self.kem_ciphertext)?;
        let shared = sk_enc.decapsulate(&kem_ct)?;

        // Build AAD
        let aad = build_aad(self.version, self.diversifier_index, &self.hint_tag);

        // Decrypt note payload
        let payload_bytes = decrypt_payload(&shared, b"note-aead", &self.note_payload, &aad)?;
        let payload = NotePayload::from_bytes(&payload_bytes)?;

        // Verify pk_recipient
        if payload.pk_recipient != expected_pk_recipient {
            return Err(CryptoError::DecryptionFailed(
                "pk_recipient mismatch".into(),
            ));
        }

        // Decrypt memo
        let memo = decrypt_payload(&shared, b"memo-aead", &self.memo_payload, &aad)?;

        Ok(NotePlaintext {
            value: payload.value,
            asset_id: payload.asset_id,
            rho: payload.rho,
            r: payload.r,
            memo,
        })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        out.extend_from_slice(&self.diversifier_index.to_le_bytes());
        out.extend_from_slice(&(self.kem_ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.kem_ciphertext);
        out.extend_from_slice(&(self.note_payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.note_payload);
        out.extend_from_slice(&(self.memo_payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.memo_payload);
        out.extend_from_slice(&self.hint_tag);
        out
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 1 + 4 + 4 + 4 + 4 + 32 {
            return Err(CryptoError::InvalidLength {
                expected: 1 + 4 + 4 + 4 + 4 + 32,
                actual: bytes.len(),
            });
        }

        let version = bytes[0];
        let diversifier_index = u32::from_le_bytes(bytes[1..5].try_into().unwrap());

        let mut offset = 5;

        let kem_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if bytes.len() < offset + kem_len {
            return Err(CryptoError::InvalidLength {
                expected: offset + kem_len,
                actual: bytes.len(),
            });
        }
        let kem_ciphertext = bytes[offset..offset + kem_len].to_vec();
        offset += kem_len;

        let note_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if bytes.len() < offset + note_len {
            return Err(CryptoError::InvalidLength {
                expected: offset + note_len,
                actual: bytes.len(),
            });
        }
        let note_payload = bytes[offset..offset + note_len].to_vec();
        offset += note_len;

        let memo_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if bytes.len() < offset + memo_len {
            return Err(CryptoError::InvalidLength {
                expected: offset + memo_len,
                actual: bytes.len(),
            });
        }
        let memo_payload = bytes[offset..offset + memo_len].to_vec();
        offset += memo_len;

        if bytes.len() < offset + 32 {
            return Err(CryptoError::InvalidLength {
                expected: offset + 32,
                actual: bytes.len(),
            });
        }
        let mut hint_tag = [0u8; 32];
        hint_tag.copy_from_slice(&bytes[offset..offset + 32]);

        Ok(Self {
            version,
            diversifier_index,
            kem_ciphertext,
            note_payload,
            memo_payload,
            hint_tag,
        })
    }
}

fn encrypt_payload(
    shared: &MlKemSharedSecret,
    label: &[u8],
    data: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (key, nonce) = derive_aead_material(shared, label);
    let cipher = ChaCha20Poly1305::new(&key.into());
    cipher
        .encrypt(&nonce.into(), Payload { msg: data, aad })
        .map_err(|_| CryptoError::EncryptionFailed)
}

fn decrypt_payload(
    shared: &MlKemSharedSecret,
    label: &[u8],
    data: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (key, nonce) = derive_aead_material(shared, label);
    let cipher = ChaCha20Poly1305::new(&key.into());
    cipher
        .decrypt(&nonce.into(), Payload { msg: data, aad })
        .map_err(|_| CryptoError::DecryptionFailed("AEAD decryption failed".into()))
}

fn derive_aead_material(
    shared: &MlKemSharedSecret,
    label: &[u8],
) -> ([u8; AEAD_KEY_SIZE], [u8; AEAD_NONCE_SIZE]) {
    let mut material = Vec::with_capacity(shared.as_bytes().len() + label.len());
    material.extend_from_slice(shared.as_bytes());
    material.extend_from_slice(label);
    let bytes = expand_to_length(b"wallet-aead", &material, AEAD_KEY_SIZE + AEAD_NONCE_SIZE);
    let mut key = [0u8; AEAD_KEY_SIZE];
    let mut nonce = [0u8; AEAD_NONCE_SIZE];
    key.copy_from_slice(&bytes[..AEAD_KEY_SIZE]);
    nonce.copy_from_slice(&bytes[AEAD_KEY_SIZE..]);
    (key, nonce)
}

fn build_aad(version: u8, index: u32, tag: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 4 + 32);
    aad.push(version);
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(tag);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_kem::MlKemKeyPair;
    use crate::traits::KemKeyPair;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let keypair = MlKemKeyPair::generate_deterministic(b"test-keypair-seed-1234");
        let pk_enc = keypair.public_key();
        let sk_enc = keypair.secret_key();

        let pk_recipient = [42u8; 32];
        let version = 1u8;
        let diversifier_index = 0u32;
        let address_tag = [7u8; 32];

        let note = NotePlaintext::new(
            1000,
            0,
            [1u8; 32],
            [2u8; 32],
            b"test memo".to_vec(),
        );

        let kem_randomness = [99u8; 32];

        let ciphertext = NoteCiphertext::encrypt(
            &pk_enc,
            pk_recipient,
            version,
            diversifier_index,
            address_tag,
            &note,
            &kem_randomness,
        )
        .unwrap();

        let decrypted = ciphertext
            .decrypt(&sk_enc, pk_recipient, diversifier_index, address_tag)
            .unwrap();

        assert_eq!(decrypted.value, note.value);
        assert_eq!(decrypted.asset_id, note.asset_id);
        assert_eq!(decrypted.rho, note.rho);
        assert_eq!(decrypted.r, note.r);
        assert_eq!(decrypted.memo, note.memo);
    }

    #[test]
    fn test_coinbase_note() {
        let seed = [123u8; 32];
        let note = NotePlaintext::coinbase(5_000_000_000, &seed);

        assert_eq!(note.value, 5_000_000_000);
        assert_eq!(note.asset_id, 0);
        assert_eq!(note.rho, derive_coinbase_rho(&seed));
        assert_eq!(note.r, derive_coinbase_r(&seed));
        assert!(note.memo.is_empty());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let keypair = MlKemKeyPair::generate_deterministic(b"test-keypair-seed-5678");
        let pk_enc = keypair.public_key();

        let note = NotePlaintext::new(500, 1, [3u8; 32], [4u8; 32], b"memo".to_vec());

        let ciphertext = NoteCiphertext::encrypt(
            &pk_enc,
            [5u8; 32],
            1,
            0,
            [6u8; 32],
            &note,
            &[7u8; 32],
        )
        .unwrap();

        let bytes = ciphertext.to_bytes();
        let recovered = NoteCiphertext::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.version, ciphertext.version);
        assert_eq!(recovered.diversifier_index, ciphertext.diversifier_index);
        assert_eq!(recovered.kem_ciphertext, ciphertext.kem_ciphertext);
        assert_eq!(recovered.note_payload, ciphertext.note_payload);
        assert_eq!(recovered.memo_payload, ciphertext.memo_payload);
        assert_eq!(recovered.hint_tag, ciphertext.hint_tag);
    }
}
