//! Note encryption for wallet
//!
//! This module wraps the crypto crate's note_encryption for wallet-specific types.

use rand::RngCore;
use serde::{Deserialize, Serialize};

use synthetic_crypto::note_encryption::{
    NoteCiphertext as CryptoNoteCiphertext, NotePlaintext as CryptoNotePlaintext,
};
use transaction_circuit::note::NoteData;

use crate::{address::ShieldedAddress, error::WalletError, keys::AddressKeyMaterial};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MemoPlaintext(#[serde(with = "serde_bytes_vec")] pub Vec<u8>);

impl MemoPlaintext {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotePlaintext {
    pub value: u64,
    pub asset_id: u64,
    #[serde(with = "serde_bytes32")]
    pub rho: [u8; 32],
    #[serde(with = "serde_bytes32")]
    pub r: [u8; 32],
    #[serde(default)]
    pub memo: MemoPlaintext,
}

impl NotePlaintext {
    pub fn random<R: RngCore + ?Sized>(
        value: u64,
        asset_id: u64,
        memo: MemoPlaintext,
        rng: &mut R,
    ) -> Self {
        let mut rho = [0u8; 32];
        let mut r = [0u8; 32];
        rng.fill_bytes(&mut rho);
        rng.fill_bytes(&mut r);
        Self {
            value,
            asset_id,
            rho,
            r,
            memo,
        }
    }

    /// Create a coinbase note with deterministic rho/r from seed
    pub fn coinbase(value: u64, seed: &[u8; 32]) -> Self {
        Self {
            value,
            asset_id: 0,
            rho: derive_coinbase_rho(seed),
            r: derive_coinbase_r(seed),
            memo: MemoPlaintext::default(),
        }
    }

    pub fn to_note_data(&self, pk_recipient: [u8; 32]) -> NoteData {
        NoteData {
            value: self.value,
            asset_id: self.asset_id,
            pk_recipient,
            rho: self.rho,
            r: self.r,
        }
    }

    fn to_crypto(&self) -> CryptoNotePlaintext {
        CryptoNotePlaintext::new(
            self.value,
            self.asset_id,
            self.rho,
            self.r,
            self.memo.0.clone(),
        )
    }

    fn from_crypto(crypto: CryptoNotePlaintext) -> Self {
        Self {
            value: crypto.value,
            asset_id: crypto.asset_id,
            rho: crypto.rho,
            r: crypto.r,
            memo: MemoPlaintext::new(crypto.memo),
        }
    }
}

/// Size of the ciphertext portion in pallet format
const PALLET_CIPHERTEXT_SIZE: usize = 611;
/// Size of the ML-KEM ciphertext
const PALLET_KEM_CIPHERTEXT_SIZE: usize = 1088;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NoteCiphertext {
    pub version: u8,
    pub diversifier_index: u32,
    #[serde(with = "serde_bytes_vec")]
    pub kem_ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes_vec")]
    pub note_payload: Vec<u8>,
    #[serde(with = "serde_bytes_vec")]
    pub memo_payload: Vec<u8>,
    #[serde(with = "serde_bytes32")]
    pub hint_tag: [u8; 32],
}

impl NoteCiphertext {
    /// Create an empty/dummy ciphertext for padding.
    /// Used when the proof has more output slots than actual recipients.
    pub fn empty() -> Self {
        Self {
            version: 0,
            diversifier_index: 0,
            kem_ciphertext: vec![0u8; PALLET_KEM_CIPHERTEXT_SIZE],
            note_payload: vec![],
            memo_payload: vec![],
            hint_tag: [0u8; 32],
        }
    }

    /// Convert to pallet-compatible format (611 + 1088 = 1699 bytes)
    ///
    /// The pallet's EncryptedNote type uses fixed-size arrays:
    /// - ciphertext: [u8; 611] containing version, diversifier_index, note/memo payloads, hint_tag
    /// - kem_ciphertext: [u8; 1088] for ML-KEM
    pub fn to_pallet_bytes(&self) -> Result<Vec<u8>, WalletError> {
        if self.kem_ciphertext.len() != PALLET_KEM_CIPHERTEXT_SIZE {
            return Err(WalletError::Serialization(format!(
                "Invalid KEM ciphertext length: expected {}, got {}",
                PALLET_KEM_CIPHERTEXT_SIZE,
                self.kem_ciphertext.len()
            )));
        }

        // Build the 611-byte ciphertext portion
        let mut ciphertext = [0u8; PALLET_CIPHERTEXT_SIZE];
        let mut offset = 0;

        // Version (1 byte)
        ciphertext[offset] = self.version;
        offset += 1;

        // Diversifier index (4 bytes, little-endian)
        ciphertext[offset..offset + 4].copy_from_slice(&self.diversifier_index.to_le_bytes());
        offset += 4;

        // Note + memo payloads must fit before the trailing 32-byte hint tag.
        let note_len = self.note_payload.len();
        let memo_len = self.memo_payload.len();
        let max_payload = PALLET_CIPHERTEXT_SIZE - 32 - 5 - 8; // hint + version/diversifier + 2 length fields
        if note_len + memo_len > max_payload {
            return Err(WalletError::Serialization(format!(
                "Encrypted note payloads too large: note={} memo={} max_total={}",
                note_len, memo_len, max_payload
            )));
        }

        let note_len_u32 = u32::try_from(note_len).map_err(|_| {
            WalletError::Serialization("note payload length overflow".into())
        })?;
        let memo_len_u32 = u32::try_from(memo_len).map_err(|_| {
            WalletError::Serialization("memo payload length overflow".into())
        })?;

        // Note payload length (4 bytes) and data
        ciphertext[offset..offset + 4].copy_from_slice(&note_len_u32.to_le_bytes());
        offset += 4;
        ciphertext[offset..offset + note_len]
            .copy_from_slice(&self.note_payload[..note_len]);
        offset += note_len;

        // Memo payload length (4 bytes) and data
        ciphertext[offset..offset + 4].copy_from_slice(&memo_len_u32.to_le_bytes());
        offset += 4;
        if memo_len > 0 {
            ciphertext[offset..offset + memo_len]
                .copy_from_slice(&self.memo_payload[..memo_len]);
        }

        // Hint tag at the end (last 32 bytes)
        let hint_start = PALLET_CIPHERTEXT_SIZE - 32;
        ciphertext[hint_start..].copy_from_slice(&self.hint_tag);

        // Combine ciphertext + kem_ciphertext
        let mut result = Vec::with_capacity(PALLET_CIPHERTEXT_SIZE + PALLET_KEM_CIPHERTEXT_SIZE);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&self.kem_ciphertext);

        Ok(result)
    }

    /// Parse from pallet-compatible format (611 + 1088 = 1699 bytes)
    pub fn from_pallet_bytes(bytes: &[u8]) -> Result<Self, WalletError> {
        const EXPECTED_SIZE: usize = PALLET_CIPHERTEXT_SIZE + PALLET_KEM_CIPHERTEXT_SIZE;

        if bytes.len() != EXPECTED_SIZE {
            return Err(WalletError::Serialization(format!(
                "Invalid encrypted note size: expected {}, got {}",
                EXPECTED_SIZE,
                bytes.len()
            )));
        }

        let ciphertext_bytes = &bytes[..PALLET_CIPHERTEXT_SIZE];
        let kem_ciphertext = bytes[PALLET_CIPHERTEXT_SIZE..].to_vec();

        // Parse the ciphertext portion
        let version = ciphertext_bytes[0];
        let diversifier_index = u32::from_le_bytes(
            ciphertext_bytes[1..5]
                .try_into()
                .map_err(|_| WalletError::Serialization("diversifier parse failed".into()))?,
        );

        let mut offset = 5;

        // Note payload length and data
        let note_len = u32::from_le_bytes(
            ciphertext_bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| WalletError::Serialization("note_len parse failed".into()))?,
        ) as usize;
        offset += 4;

        if offset + note_len > PALLET_CIPHERTEXT_SIZE - 32 {
            return Err(WalletError::Serialization(format!(
                "Note payload too large: {} bytes at offset {}",
                note_len, offset
            )));
        }
        let note_payload = ciphertext_bytes[offset..offset + note_len].to_vec();
        offset += note_len;

        // Memo payload length and data
        let memo_len = u32::from_le_bytes(
            ciphertext_bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| WalletError::Serialization("memo_len parse failed".into()))?,
        ) as usize;
        offset += 4;

        let memo_payload = if memo_len > 0 && offset + memo_len <= PALLET_CIPHERTEXT_SIZE - 32 {
            ciphertext_bytes[offset..offset + memo_len].to_vec()
        } else {
            Vec::new()
        };

        // Hint tag is at the end (last 32 bytes)
        let hint_tag_start = PALLET_CIPHERTEXT_SIZE - 32;
        let mut hint_tag = [0u8; 32];
        hint_tag.copy_from_slice(&ciphertext_bytes[hint_tag_start..]);

        Ok(Self {
            version,
            diversifier_index,
            kem_ciphertext,
            note_payload,
            memo_payload,
            hint_tag,
        })
    }

    pub fn encrypt<R: RngCore + ?Sized>(
        address: &ShieldedAddress,
        note: &NotePlaintext,
        rng: &mut R,
    ) -> Result<Self, WalletError> {
        let mut kem_seed = [0u8; 32];
        rng.fill_bytes(&mut kem_seed);

        let crypto_note = note.to_crypto();
        let crypto_ct = CryptoNoteCiphertext::encrypt(
            &address.pk_enc,
            address.pk_recipient,
            address.version,
            address.diversifier_index,
            address.address_tag,
            &crypto_note,
            &kem_seed,
        )
        .map_err(|_e| WalletError::EncryptionFailure)?;

        Ok(Self::from_crypto(crypto_ct))
    }

    pub fn decrypt(&self, material: &AddressKeyMaterial) -> Result<NotePlaintext, WalletError> {
        if self.version != material.version() {
            return Err(WalletError::NoteMismatch("note version mismatch"));
        }
        if material.diversifier_index != self.diversifier_index {
            return Err(WalletError::NoteMismatch("diversifier index mismatch"));
        }
        if material.addr_tag != self.hint_tag {
            return Err(WalletError::NoteMismatch("address tag mismatch"));
        }

        let crypto_ct = self.to_crypto();
        let crypto_note = crypto_ct
            .decrypt(
                material.secret_key(),
                material.pk_recipient,
                material.diversifier_index,
                material.addr_tag,
            )
            .map_err(|_| WalletError::DecryptionFailure)?;

        Ok(NotePlaintext::from_crypto(crypto_note))
    }

    /// Serialize to bytes (for on-chain storage)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_crypto().to_bytes()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WalletError> {
        let crypto_ct =
            CryptoNoteCiphertext::from_bytes(bytes).map_err(|_| WalletError::DecryptionFailure)?;
        Ok(Self::from_crypto(crypto_ct))
    }

    fn to_crypto(&self) -> CryptoNoteCiphertext {
        CryptoNoteCiphertext {
            version: self.version,
            diversifier_index: self.diversifier_index,
            kem_ciphertext: self.kem_ciphertext.clone(),
            note_payload: self.note_payload.clone(),
            memo_payload: self.memo_payload.clone(),
            hint_tag: self.hint_tag,
        }
    }

    fn from_crypto(crypto: CryptoNoteCiphertext) -> Self {
        Self {
            version: crypto.version,
            diversifier_index: crypto.diversifier_index,
            kem_ciphertext: crypto.kem_ciphertext,
            note_payload: crypto.note_payload,
            memo_payload: crypto.memo_payload,
            hint_tag: crypto.hint_tag,
        }
    }
}

// Re-export crypto functions for coinbase
pub use synthetic_crypto::note_encryption::{derive_coinbase_r, derive_coinbase_rho};

mod serde_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::<u8>::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use crate::keys::RootSecret;

    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let mut rng = StdRng::seed_from_u64(123);
        let root = RootSecret::from_rng(&mut rng);
        let keys = root.derive();
        let material = keys.address(0).unwrap();
        let address = material.shielded_address();
        let note = NotePlaintext::random(42, 7, MemoPlaintext::new(b"memo".to_vec()), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        let recovered = ciphertext.decrypt(&material).unwrap();
        assert_eq!(recovered.value, note.value);
        assert_eq!(recovered.asset_id, note.asset_id);
        assert_eq!(recovered.memo.as_bytes(), note.memo.as_bytes());
    }

    #[test]
    fn coinbase_note_deterministic() {
        let seed = [42u8; 32];
        let note1 = NotePlaintext::coinbase(5_000_000_000, &seed);
        let note2 = NotePlaintext::coinbase(5_000_000_000, &seed);
        assert_eq!(note1.rho, note2.rho);
        assert_eq!(note1.r, note2.r);
        assert_eq!(note1.value, 5_000_000_000);
        assert_eq!(note1.asset_id, 0);
    }

    #[test]
    fn serialization_round_trip() {
        let mut rng = StdRng::seed_from_u64(456);
        let root = RootSecret::from_rng(&mut rng);
        let keys = root.derive();
        let material = keys.address(0).unwrap();
        let address = material.shielded_address();
        let note = NotePlaintext::random(100, 0, MemoPlaintext::new(b"test".to_vec()), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();

        let bytes = ciphertext.to_bytes();
        let recovered = NoteCiphertext::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.version, ciphertext.version);
        assert_eq!(recovered.hint_tag, ciphertext.hint_tag);
    }

    #[test]
    fn to_pallet_bytes_rejects_oversize_memo() {
        let mut rng = StdRng::seed_from_u64(789);
        let root = RootSecret::from_rng(&mut rng);
        let keys = root.derive();
        let material = keys.address(0).unwrap();
        let address = material.shielded_address();
        let memo = vec![0u8; 600];
        let note = NotePlaintext::random(1, 0, MemoPlaintext::new(memo), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        assert!(ciphertext.to_pallet_bytes().is_err());
    }
}
