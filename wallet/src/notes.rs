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

    pub fn to_note_data(&self, pk_recipient: [u8; 32], pk_auth: [u8; 32]) -> NoteData {
        NoteData {
            value: self.value,
            asset_id: self.asset_id,
            pk_recipient,
            pk_auth,
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

/// Size of the ciphertext portion in chain format
pub const CHAIN_CIPHERTEXT_SIZE: usize = 579;
const NOTE_ENCRYPTION_VERSION: u8 = 3;
pub const NOTE_CIPHERTEXT_KEM_RANDOMNESS_LEN: usize = 32;
pub const NOTE_CIPHERTEXT_AEAD_KEY_LEN: usize = 32;
pub const NOTE_CIPHERTEXT_AEAD_NONCE_LEN: usize = 12;
pub const NOTE_CIPHERTEXT_AEAD_TAG_LEN: usize = 16;
pub const NOTE_CIPHERTEXT_PLAINTEXT_PAYLOAD_LEN: usize = 112;
pub const NOTE_CIPHERTEXT_METADATA_AAD_LEN: usize = 7;
pub const NOTE_CIPHERTEXT_AEAD_KDF_DOMAIN: &[u8] = b"wallet-aead";
pub const NOTE_CIPHERTEXT_NOTE_AEAD_LABEL: &[u8] = b"note-aead";
pub const NOTE_CIPHERTEXT_MEMO_AEAD_LABEL: &[u8] = b"memo-aead";

pub fn note_ciphertext_aad_bytes(
    version: u8,
    crypto_suite: u16,
    diversifier_index: u32,
) -> [u8; NOTE_CIPHERTEXT_METADATA_AAD_LEN] {
    let mut aad = [0u8; NOTE_CIPHERTEXT_METADATA_AAD_LEN];
    aad[0] = version;
    aad[1..3].copy_from_slice(&crypto_suite.to_le_bytes());
    aad[3..7].copy_from_slice(&diversifier_index.to_le_bytes());
    aad
}

fn validate_note_ciphertext_version(version: u8) -> Result<(), WalletError> {
    if version != NOTE_ENCRYPTION_VERSION {
        return Err(WalletError::Serialization(format!(
            "Unsupported note ciphertext version: expected {}, got {}",
            NOTE_ENCRYPTION_VERSION, version
        )));
    }
    Ok(())
}

pub(crate) fn expected_kem_ciphertext_len(crypto_suite: u16) -> Result<usize, WalletError> {
    match crypto_suite {
        protocol_versioning::CRYPTO_SUITE_GAMMA => {
            Ok(synthetic_crypto::ml_kem::ML_KEM_CIPHERTEXT_LEN)
        }
        _ => Err(WalletError::Serialization(format!(
            "Unsupported crypto suite: {}",
            crypto_suite
        ))),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NoteCiphertext {
    pub version: u8,
    pub crypto_suite: u16,
    pub diversifier_index: u32,
    #[serde(with = "serde_bytes_vec")]
    pub kem_ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes_vec")]
    pub note_payload: Vec<u8>,
    #[serde(with = "serde_bytes_vec")]
    pub memo_payload: Vec<u8>,
}

impl NoteCiphertext {
    fn parse_ciphertext_container(ciphertext_bytes: &[u8]) -> Result<Self, WalletError> {
        if ciphertext_bytes.len() != CHAIN_CIPHERTEXT_SIZE {
            return Err(WalletError::Serialization(format!(
                "Invalid encrypted note container size: expected {}, got {}",
                CHAIN_CIPHERTEXT_SIZE,
                ciphertext_bytes.len()
            )));
        }

        let version = ciphertext_bytes[0];
        validate_note_ciphertext_version(version)?;
        let crypto_suite = u16::from_le_bytes(
            ciphertext_bytes[1..3]
                .try_into()
                .map_err(|_| WalletError::Serialization("crypto suite parse failed".into()))?,
        );
        let diversifier_index = u32::from_le_bytes(
            ciphertext_bytes[3..7]
                .try_into()
                .map_err(|_| WalletError::Serialization("diversifier parse failed".into()))?,
        );

        let mut offset = 7;
        let note_len = u32::from_le_bytes(
            ciphertext_bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| WalletError::Serialization("note_len parse failed".into()))?,
        ) as usize;
        offset += 4;

        let note_end = offset
            .checked_add(note_len)
            .ok_or_else(|| WalletError::Serialization("note payload length overflow".into()))?;
        let memo_len_end = note_end
            .checked_add(4)
            .ok_or_else(|| WalletError::Serialization("memo length offset overflow".into()))?;
        if memo_len_end > CHAIN_CIPHERTEXT_SIZE {
            return Err(WalletError::Serialization(format!(
                "Note payload too large: {} bytes at offset {}",
                note_len, offset
            )));
        }
        let note_payload = ciphertext_bytes[offset..note_end].to_vec();
        offset = note_end;

        let memo_len = u32::from_le_bytes(
            ciphertext_bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| WalletError::Serialization("memo_len parse failed".into()))?,
        ) as usize;
        offset += 4;

        let memo_end = offset
            .checked_add(memo_len)
            .ok_or_else(|| WalletError::Serialization("memo payload length overflow".into()))?;
        if memo_end > CHAIN_CIPHERTEXT_SIZE {
            return Err(WalletError::Serialization(format!(
                "Memo payload too large: {} bytes at offset {}",
                memo_len, offset
            )));
        }
        let memo_payload = ciphertext_bytes[offset..memo_end].to_vec();
        offset = memo_end;

        if ciphertext_bytes[offset..].iter().any(|&byte| byte != 0) {
            return Err(WalletError::Serialization(
                "Encrypted note container has nonzero trailing padding".into(),
            ));
        }

        Ok(Self {
            version,
            crypto_suite,
            diversifier_index,
            kem_ciphertext: Vec::new(),
            note_payload,
            memo_payload,
        })
    }

    /// Create an empty/dummy ciphertext for padding.
    /// Used when the proof has more output slots than actual recipients.
    pub fn empty() -> Self {
        Self {
            version: NOTE_ENCRYPTION_VERSION,
            crypto_suite: protocol_versioning::CRYPTO_SUITE_GAMMA,
            diversifier_index: 0,
            kem_ciphertext: vec![0u8; synthetic_crypto::ml_kem::ML_KEM_CIPHERTEXT_LEN],
            note_payload: vec![],
            memo_payload: vec![],
        }
    }

    fn build_ciphertext_container(&self) -> Result<[u8; CHAIN_CIPHERTEXT_SIZE], WalletError> {
        validate_note_ciphertext_version(self.version)?;

        let mut ciphertext = [0u8; CHAIN_CIPHERTEXT_SIZE];
        let mut offset = 0;

        // Version (1 byte)
        ciphertext[offset] = self.version;
        offset += 1;

        // Crypto suite (2 bytes, little-endian)
        ciphertext[offset..offset + 2].copy_from_slice(&self.crypto_suite.to_le_bytes());
        offset += 2;

        // Diversifier index (4 bytes, little-endian)
        ciphertext[offset..offset + 4].copy_from_slice(&self.diversifier_index.to_le_bytes());
        offset += 4;

        // Note + memo payloads must fit in the ciphertext container.
        let note_len = self.note_payload.len();
        let memo_len = self.memo_payload.len();
        let max_payload = CHAIN_CIPHERTEXT_SIZE - 7 - 8; // version/crypto_suite/diversifier + 2 length fields
        if note_len + memo_len > max_payload {
            return Err(WalletError::Serialization(format!(
                "Encrypted note payloads too large: note={} memo={} max_total={}",
                note_len, memo_len, max_payload
            )));
        }

        let note_len_u32 = u32::try_from(note_len)
            .map_err(|_| WalletError::Serialization("note payload length overflow".into()))?;
        let memo_len_u32 = u32::try_from(memo_len)
            .map_err(|_| WalletError::Serialization("memo payload length overflow".into()))?;

        // Note payload length (4 bytes) and data
        ciphertext[offset..offset + 4].copy_from_slice(&note_len_u32.to_le_bytes());
        offset += 4;
        ciphertext[offset..offset + note_len].copy_from_slice(&self.note_payload[..note_len]);
        offset += note_len;

        // Memo payload length (4 bytes) and data
        ciphertext[offset..offset + 4].copy_from_slice(&memo_len_u32.to_le_bytes());
        offset += 4;
        if memo_len > 0 {
            ciphertext[offset..offset + memo_len].copy_from_slice(&self.memo_payload[..memo_len]);
        }

        Ok(ciphertext)
    }

    /// Convert to SCALE-compatible format (ciphertext + SCALE length-prefixed KEM ciphertext)
    ///
    /// The protocol EncryptedNote type uses:
    /// - ciphertext: [u8; 579] containing version, crypto_suite, diversifier_index, note/memo payloads
    /// - kem_ciphertext: BoundedVec<u8, _> for ML-KEM ciphertext bytes
    pub fn to_chain_bytes(&self) -> Result<Vec<u8>, WalletError> {
        let expected_kem_len = expected_kem_ciphertext_len(self.crypto_suite)?;
        if self.kem_ciphertext.len() != expected_kem_len {
            return Err(WalletError::Serialization(format!(
                "Invalid KEM ciphertext length: expected {}, got {}",
                expected_kem_len,
                self.kem_ciphertext.len()
            )));
        }

        let ciphertext = self.build_ciphertext_container()?;

        // Combine ciphertext + SCALE-encoded kem_ciphertext
        let mut result = Vec::with_capacity(CHAIN_CIPHERTEXT_SIZE + 5 + self.kem_ciphertext.len());
        result.extend_from_slice(&ciphertext);
        encode_compact_len(self.kem_ciphertext.len(), &mut result);
        result.extend_from_slice(&self.kem_ciphertext);

        Ok(result)
    }

    pub fn to_da_bytes(&self) -> Result<Vec<u8>, WalletError> {
        let expected_kem_len = expected_kem_ciphertext_len(self.crypto_suite)?;
        if self.kem_ciphertext.len() != expected_kem_len {
            return Err(WalletError::Serialization(format!(
                "Invalid KEM ciphertext length: expected {}, got {}",
                expected_kem_len,
                self.kem_ciphertext.len()
            )));
        }

        let ciphertext = self.build_ciphertext_container()?;
        let mut result = Vec::with_capacity(CHAIN_CIPHERTEXT_SIZE + self.kem_ciphertext.len());
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&self.kem_ciphertext);
        Ok(result)
    }

    /// Parse from SCALE-compatible format (ciphertext + SCALE length-prefixed KEM ciphertext)
    pub fn from_chain_bytes(bytes: &[u8]) -> Result<Self, WalletError> {
        if bytes.len() < CHAIN_CIPHERTEXT_SIZE + 1 {
            return Err(WalletError::Serialization(format!(
                "Invalid encrypted note size: expected at least {}, got {}",
                CHAIN_CIPHERTEXT_SIZE + 1,
                bytes.len()
            )));
        }

        let ciphertext_bytes = &bytes[..CHAIN_CIPHERTEXT_SIZE];
        let mut parsed = Self::parse_ciphertext_container(ciphertext_bytes)?;

        let (kem_len, kem_len_bytes) = decode_compact_len(&bytes[CHAIN_CIPHERTEXT_SIZE..])?;
        let expected_kem_len = expected_kem_ciphertext_len(parsed.crypto_suite)?;
        if kem_len != expected_kem_len {
            return Err(WalletError::Serialization(format!(
                "Invalid KEM ciphertext length: expected {}, got {}",
                expected_kem_len, kem_len
            )));
        }

        let kem_start = CHAIN_CIPHERTEXT_SIZE + kem_len_bytes;
        let kem_end = kem_start
            .checked_add(kem_len)
            .ok_or_else(|| WalletError::Serialization("KEM ciphertext length overflow".into()))?;
        if bytes.len() != kem_end {
            return Err(WalletError::Serialization(format!(
                "Invalid encrypted note size: expected {}, got {}",
                kem_end,
                bytes.len()
            )));
        }
        parsed.kem_ciphertext = bytes[kem_start..kem_end].to_vec();
        Ok(parsed)
    }

    /// Parse from the DA sidecar format (ciphertext container + raw KEM ciphertext).
    pub fn from_da_bytes(bytes: &[u8]) -> Result<Self, WalletError> {
        if bytes.len() < CHAIN_CIPHERTEXT_SIZE {
            return Err(WalletError::Serialization(format!(
                "Invalid DA encrypted note size: expected at least {}, got {}",
                CHAIN_CIPHERTEXT_SIZE,
                bytes.len()
            )));
        }

        let mut parsed = Self::parse_ciphertext_container(&bytes[..CHAIN_CIPHERTEXT_SIZE])?;
        let expected_kem_len = expected_kem_ciphertext_len(parsed.crypto_suite)?;
        let expected_size = CHAIN_CIPHERTEXT_SIZE
            .checked_add(expected_kem_len)
            .ok_or_else(|| {
                WalletError::Serialization("DA KEM ciphertext length overflow".into())
            })?;
        if bytes.len() != expected_size {
            return Err(WalletError::Serialization(format!(
                "Invalid DA encrypted note size: expected {}, got {}",
                expected_size,
                bytes.len()
            )));
        }
        parsed.kem_ciphertext = bytes[CHAIN_CIPHERTEXT_SIZE..expected_size].to_vec();
        Ok(parsed)
    }

    pub fn encrypt<R: RngCore + ?Sized>(
        address: &ShieldedAddress,
        note: &NotePlaintext,
        rng: &mut R,
    ) -> Result<Self, WalletError> {
        let mut kem_seed = [0u8; NOTE_CIPHERTEXT_KEM_RANDOMNESS_LEN];
        rng.fill_bytes(&mut kem_seed);

        let crypto_note = note.to_crypto();
        let crypto_ct = CryptoNoteCiphertext::encrypt(
            &address.pk_enc,
            address.pk_recipient,
            address.version,
            address.crypto_suite,
            address.diversifier_index,
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
        if self.crypto_suite != material.crypto_suite() {
            return Err(WalletError::NoteMismatch("note crypto suite mismatch"));
        }
        if material.diversifier_index != self.diversifier_index {
            return Err(WalletError::NoteMismatch("diversifier index mismatch"));
        }

        let crypto_ct = self.to_crypto();
        let crypto_note = crypto_ct
            .decrypt(
                material.secret_key(),
                material.pk_recipient,
                material.diversifier_index,
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
        let ciphertext = Self::from_crypto(crypto_ct);
        validate_note_ciphertext_version(ciphertext.version)?;
        Ok(ciphertext)
    }

    fn to_crypto(&self) -> CryptoNoteCiphertext {
        CryptoNoteCiphertext {
            version: self.version,
            crypto_suite: self.crypto_suite,
            diversifier_index: self.diversifier_index,
            kem_ciphertext: self.kem_ciphertext.clone(),
            note_payload: self.note_payload.clone(),
            memo_payload: self.memo_payload.clone(),
        }
    }

    fn from_crypto(crypto: CryptoNoteCiphertext) -> Self {
        Self {
            version: crypto.version,
            crypto_suite: crypto.crypto_suite,
            diversifier_index: crypto.diversifier_index,
            kem_ciphertext: crypto.kem_ciphertext,
            note_payload: crypto.note_payload,
            memo_payload: crypto.memo_payload,
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

fn encode_compact_len(value: usize, out: &mut Vec<u8>) {
    encode_compact_u64(value as u64, out);
}

fn encode_compact_u64(value: u64, out: &mut Vec<u8>) {
    if value < 0x40 {
        out.push((value as u8) << 2);
    } else if value < 0x4000 {
        let v = ((value as u16) << 2) | 0x01;
        out.extend_from_slice(&v.to_le_bytes());
    } else if value < 0x4000_0000 {
        let v = ((value as u32) << 2) | 0x02;
        out.extend_from_slice(&v.to_le_bytes());
    } else {
        let bytes_needed = (64 - value.leading_zeros()).div_ceil(8) as u8;
        out.push(((bytes_needed - 4) << 2) | 0x03);
        let value_bytes = value.to_le_bytes();
        out.extend_from_slice(&value_bytes[..bytes_needed as usize]);
    }
}

fn decode_compact_len(data: &[u8]) -> Result<(usize, usize), WalletError> {
    if data.is_empty() {
        return Err(WalletError::Serialization("compact length missing".into()));
    }
    let flag = data[0] & 0x03;
    match flag {
        0 => Ok(((data[0] >> 2) as usize, 1)),
        1 => {
            if data.len() < 2 {
                return Err(WalletError::Serialization(
                    "compact length short (2-byte)".into(),
                ));
            }
            let raw = u16::from_le_bytes([data[0], data[1]]);
            let value = (raw >> 2) as usize;
            if value < 0x40 {
                return Err(WalletError::Serialization(
                    "non-canonical compact length".into(),
                ));
            }
            Ok((value, 2))
        }
        2 => {
            if data.len() < 4 {
                return Err(WalletError::Serialization(
                    "compact length short (4-byte)".into(),
                ));
            }
            let raw = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let value = (raw >> 2) as usize;
            if value < 0x4000 {
                return Err(WalletError::Serialization(
                    "non-canonical compact length".into(),
                ));
            }
            Ok((value, 4))
        }
        _ => {
            let bytes_needed = (data[0] >> 2) as usize + 4;
            if data.len() < 1 + bytes_needed {
                return Err(WalletError::Serialization(
                    "compact length short (big-int)".into(),
                ));
            }
            if bytes_needed > 8 {
                return Err(WalletError::Serialization(
                    "compact length too large".into(),
                ));
            }
            let mut buf = [0u8; 8];
            buf[..bytes_needed].copy_from_slice(&data[1..1 + bytes_needed]);
            let value = u64::from_le_bytes(buf) as usize;
            if value < 0x4000_0000 || data[bytes_needed] == 0 {
                return Err(WalletError::Serialization(
                    "non-canonical compact length".into(),
                ));
            }
            Ok((value, 1 + bytes_needed))
        }
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
    use p3_field::PrimeField64;
    use rand::{rngs::StdRng, SeedableRng};
    use serde::Deserialize;
    use std::collections::BTreeSet;

    use crate::keys::{AddressKeyMaterial, RootSecret};

    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanNoteCommitmentInputVectorFile {
        schema_version: u32,
        note_domain_tag: u64,
        note_commitment_input_cases: Vec<LeanNoteCommitmentInputCase>,
        asset_id_cases: Vec<LeanAssetIdCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanNoteCommitmentInputCase {
        name: String,
        value: u64,
        asset_id: u64,
        pk_recipient: Vec<u8>,
        pk_auth: Vec<u8>,
        rho: Vec<u8>,
        r: Vec<u8>,
        expected_inputs: Vec<u64>,
        expected_input_count: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanAssetIdCase {
        name: String,
        asset_id: u64,
        expected_canonical: bool,
    }

    fn sample_material_note_ciphertext(
        seed: u64,
        memo: &[u8],
    ) -> (AddressKeyMaterial, NotePlaintext, NoteCiphertext) {
        let mut rng = StdRng::seed_from_u64(seed);
        let root = RootSecret::from_rng(&mut rng);
        let keys = root.derive();
        let material = keys.address(0).unwrap();
        let address = material.shielded_address();
        let note = NotePlaintext::random(100, 0, MemoPlaintext::new(memo.to_vec()), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        (material, note, ciphertext)
    }

    fn sample_ciphertext(seed: u64, memo: &[u8]) -> NoteCiphertext {
        sample_material_note_ciphertext(seed, memo).2
    }

    fn assert_note_mismatch(result: Result<NotePlaintext, WalletError>, expected: &'static str) {
        match result {
            Err(WalletError::NoteMismatch(actual)) => assert_eq!(actual, expected),
            other => panic!("expected NoteMismatch({expected:?}), got {other:?}"),
        }
    }

    fn assert_decryption_failure(result: Result<NotePlaintext, WalletError>) {
        match result {
            Err(WalletError::DecryptionFailure) => {}
            other => panic!("expected DecryptionFailure, got {other:?}"),
        }
    }

    fn assert_unsupported_note_ciphertext_version<T: std::fmt::Debug>(
        result: Result<T, WalletError>,
    ) {
        match result {
            Err(WalletError::Serialization(message)) => {
                assert!(
                    message.contains("Unsupported note ciphertext version"),
                    "unexpected unsupported-version message: {message}"
                );
            }
            other => panic!("expected unsupported note ciphertext version, got {other:?}"),
        }
    }

    fn payload_offsets(chain_bytes: &[u8]) -> (usize, usize, usize, usize) {
        let note_len = u32::from_le_bytes(chain_bytes[7..11].try_into().unwrap()) as usize;
        let note_start = 11;
        let memo_len_offset = note_start + note_len;
        let memo_len = u32::from_le_bytes(
            chain_bytes[memo_len_offset..memo_len_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let memo_start = memo_len_offset + 4;
        (
            note_start,
            memo_len_offset,
            memo_start,
            memo_start + memo_len,
        )
    }

    fn same_plaintext_reencryptions() -> (
        AddressKeyMaterial,
        NotePlaintext,
        NoteCiphertext,
        NoteCiphertext,
    ) {
        let mut setup_rng = StdRng::seed_from_u64(124);
        let root = RootSecret::from_rng(&mut setup_rng);
        let keys = root.derive();
        let material = keys.address(0).unwrap();
        let address = material.shielded_address();
        let note = NotePlaintext::random(
            42,
            7,
            MemoPlaintext::new(b"same plaintext memo".to_vec()),
            &mut setup_rng,
        );

        let mut left_rng = StdRng::seed_from_u64(125);
        let mut right_rng = StdRng::seed_from_u64(126);
        let left = NoteCiphertext::encrypt(&address, &note, &mut left_rng).unwrap();
        let right = NoteCiphertext::encrypt(&address, &note, &mut right_rng).unwrap();
        (material, note, left, right)
    }

    fn assert_public_ciphertext_summary_shape_eq(left: &NoteCiphertext, right: &NoteCiphertext) {
        assert_eq!(left.version, right.version);
        assert_eq!(left.crypto_suite, right.crypto_suite);
        assert_eq!(left.diversifier_index, right.diversifier_index);
        assert_eq!(left.kem_ciphertext.len(), right.kem_ciphertext.len());
        assert_eq!(left.note_payload.len(), right.note_payload.len());
        assert_eq!(left.memo_payload.len(), right.memo_payload.len());
    }

    fn encoded_note_payload_plaintext(
        value: u64,
        asset_id: u64,
        rho: [u8; 32],
        r: [u8; 32],
        pk_recipient: [u8; 32],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(NOTE_CIPHERTEXT_PLAINTEXT_PAYLOAD_LEN);
        out.extend_from_slice(&value.to_le_bytes());
        out.extend_from_slice(&asset_id.to_le_bytes());
        out.extend_from_slice(&rho);
        out.extend_from_slice(&r);
        out.extend_from_slice(&pk_recipient);
        assert_eq!(out.len(), NOTE_CIPHERTEXT_PLAINTEXT_PAYLOAD_LEN);
        out
    }

    fn bytes32(name: &str, field: &str, bytes: &[u8]) -> [u8; 32] {
        bytes.try_into().unwrap_or_else(|_| {
            panic!(
                "{name} {field} length drifted from wallet/circuit note plaintext width: {}",
                bytes.len()
            )
        })
    }

    fn verify_lean_wallet_note_commitment_case(case: &LeanNoteCommitmentInputCase) {
        let pk_recipient = bytes32(&case.name, "pk_recipient", &case.pk_recipient);
        let pk_auth = bytes32(&case.name, "pk_auth", &case.pk_auth);
        let rho = bytes32(&case.name, "rho", &case.rho);
        let r = bytes32(&case.name, "r", &case.r);
        let plaintext = NotePlaintext {
            value: case.value,
            asset_id: case.asset_id,
            rho,
            r,
            memo: MemoPlaintext::new(b"wallet-local memo must not enter commitment".to_vec()),
        };

        let note_data = plaintext.to_note_data(pk_recipient, pk_auth);
        assert_eq!(
            note_data.value, case.value,
            "{} wallet value export",
            case.name
        );
        assert_eq!(
            note_data.asset_id, case.asset_id,
            "{} wallet asset export",
            case.name
        );
        assert_eq!(
            note_data.pk_recipient, pk_recipient,
            "{} wallet recipient export",
            case.name
        );
        assert_eq!(
            note_data.pk_auth, pk_auth,
            "{} wallet auth export",
            case.name
        );
        assert_eq!(note_data.rho, rho, "{} wallet rho export", case.name);
        assert_eq!(note_data.r, r, "{} wallet randomness export", case.name);

        let actual = transaction_circuit::hashing_pq::note_commitment_inputs(
            note_data.value,
            note_data.asset_id,
            &note_data.pk_recipient,
            &note_data.rho,
            &note_data.r,
            &note_data.pk_auth,
        )
        .iter()
        .map(|felt| felt.as_canonical_u64())
        .collect::<Vec<_>>();
        assert_eq!(
            actual.len(),
            case.expected_input_count,
            "{} wallet note-commitment input count drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual, case.expected_inputs,
            "{} wallet note plaintext/material export no longer feeds Lean-specified commitment limbs",
            case.name
        );

        let direct = transaction_circuit::hashing_pq::note_commitment(
            case.value,
            case.asset_id,
            &case.pk_recipient,
            &case.pk_auth,
            &case.rho,
            &case.r,
        );
        assert_eq!(
            note_data.commitment(),
            direct,
            "{} wallet NoteData commitment must use the same exported plaintext fields",
            case.name
        );
    }

    #[test]
    fn lean_generated_note_commitment_input_vectors_match_wallet_plaintext_note_data() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_NOTE_COMMITMENT_INPUT_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_NOTE_COMMITMENT_INPUT_VECTORS not set; skipping wallet note plaintext vector check"
            );
            return;
        };
        let raw =
            std::fs::read_to_string(&path).expect("read generated Lean note-commitment vectors");
        let vectors: LeanNoteCommitmentInputVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean note-commitment vectors");
        assert_eq!(vectors.schema_version, 1);
        assert_eq!(
            vectors.note_domain_tag,
            transaction_circuit::constants::NOTE_DOMAIN_TAG
        );
        assert!(
            !vectors.note_commitment_input_cases.is_empty(),
            "Lean note-commitment input cases must not be empty"
        );
        assert!(
            !vectors.asset_id_cases.is_empty(),
            "Lean asset-id cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.note_commitment_input_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_wallet_note_commitment_case(case);
        }

        let mut names = BTreeSet::new();
        for case in &vectors.asset_id_cases {
            assert!(names.insert(case.name.clone()));
            let note = NotePlaintext {
                value: 1,
                asset_id: case.asset_id,
                rho: [3u8; 32],
                r: [4u8; 32],
                memo: MemoPlaintext::default(),
            };
            let note_data = note.to_note_data([1u8; 32], [2u8; 32]);
            assert_eq!(
                note_data.validate().is_ok(),
                case.expected_canonical,
                "{} wallet-exported NoteData asset canonicality drifted from Lean spec",
                case.name
            );
        }
    }

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
    fn production_note_ciphertext_profile_constants_are_pinned() {
        assert_eq!(NOTE_CIPHERTEXT_KEM_RANDOMNESS_LEN, 32);
        assert_eq!(NOTE_CIPHERTEXT_AEAD_KEY_LEN, 32);
        assert_eq!(NOTE_CIPHERTEXT_AEAD_NONCE_LEN, 12);
        assert_eq!(NOTE_CIPHERTEXT_AEAD_TAG_LEN, 16);
        assert_eq!(NOTE_CIPHERTEXT_PLAINTEXT_PAYLOAD_LEN, 112);
        assert_eq!(NOTE_CIPHERTEXT_METADATA_AAD_LEN, 7);
        assert_eq!(NOTE_CIPHERTEXT_AEAD_KDF_DOMAIN, b"wallet-aead");
        assert_eq!(NOTE_CIPHERTEXT_NOTE_AEAD_LABEL, b"note-aead");
        assert_eq!(NOTE_CIPHERTEXT_MEMO_AEAD_LABEL, b"memo-aead");
        assert_ne!(
            NOTE_CIPHERTEXT_NOTE_AEAD_LABEL,
            NOTE_CIPHERTEXT_MEMO_AEAD_LABEL
        );
        assert_eq!(
            note_ciphertext_aad_bytes(3, protocol_versioning::CRYPTO_SUITE_GAMMA, 7),
            [3, 3, 0, 7, 0, 0, 0]
        );
    }

    #[test]
    fn crypto_aad_authenticates_version_and_suite_metadata() {
        let (material, _, ciphertext) = sample_material_note_ciphertext(875, b"aad");
        let crypto = ciphertext.to_crypto();

        let mut version_tampered = crypto.clone();
        version_tampered.version = version_tampered.version.wrapping_add(1);
        assert!(
            version_tampered
                .decrypt(
                    material.secret_key(),
                    material.pk_recipient,
                    material.diversifier_index
                )
                .is_err(),
            "crypto payload AAD must authenticate note ciphertext version"
        );

        let mut suite_tampered = crypto;
        suite_tampered.crypto_suite = suite_tampered.crypto_suite.wrapping_add(1);
        assert!(
            suite_tampered
                .decrypt(
                    material.secret_key(),
                    material.pk_recipient,
                    material.diversifier_index
                )
                .is_err(),
            "crypto payload AAD/KDF material must authenticate crypto suite"
        );
    }

    #[test]
    fn decrypt_rejects_same_length_note_memo_payload_swap() {
        let mut rng = StdRng::seed_from_u64(876);
        let root = RootSecret::from_rng(&mut rng);
        let keys = root.derive();
        let material = keys.address(0).unwrap();
        let address = material.shielded_address();
        let note = NotePlaintext::random(
            42,
            7,
            MemoPlaintext::new(encoded_note_payload_plaintext(
                900,
                2,
                [17u8; 32],
                [18u8; 32],
                material.pk_recipient,
            )),
            &mut rng,
        );
        let mut ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        assert_eq!(
            ciphertext.note_payload.len(),
            ciphertext.memo_payload.len(),
            "fixture must make note and memo AEAD payloads equal length"
        );

        std::mem::swap(&mut ciphertext.note_payload, &mut ciphertext.memo_payload);
        assert_decryption_failure(ciphertext.decrypt(&material));
    }

    #[test]
    fn encrypt_same_plaintext_to_same_address_uses_fresh_kem_randomness() {
        let (material, note, left, right) = same_plaintext_reencryptions();
        let left_chain_bytes = left.to_chain_bytes().unwrap();
        let right_chain_bytes = right.to_chain_bytes().unwrap();
        let left_da_bytes = left.to_da_bytes().unwrap();
        let right_da_bytes = right.to_da_bytes().unwrap();

        assert_ne!(
            left.kem_ciphertext, right.kem_ciphertext,
            "fresh KEM randomness must unlink repeated plaintext encryption"
        );
        assert_ne!(
            left_chain_bytes, right_chain_bytes,
            "chain wire bytes must not deterministically identify repeated plaintexts"
        );
        assert_ne!(
            left_da_bytes, right_da_bytes,
            "DA wire bytes must not deterministically identify repeated plaintexts"
        );
        assert_ne!(
            transaction_circuit::hashing_pq::ciphertext_hash_bytes(&left_da_bytes),
            transaction_circuit::hashing_pq::ciphertext_hash_bytes(&right_da_bytes),
            "public ciphertext hashes must remain bound to the randomized DA wire"
        );

        let recovered_left = left.decrypt(&material).unwrap();
        let recovered_right = right.decrypt(&material).unwrap();
        assert_eq!(recovered_left, note);
        assert_eq!(recovered_right, note);
    }

    #[test]
    fn reencryption_preserves_public_ciphertext_summary_shape() {
        let (material, note, left, right) = same_plaintext_reencryptions();
        let left_chain_bytes = left.to_chain_bytes().unwrap();
        let right_chain_bytes = right.to_chain_bytes().unwrap();
        let left_da_bytes = left.to_da_bytes().unwrap();
        let right_da_bytes = right.to_da_bytes().unwrap();

        assert_ne!(
            left_chain_bytes, right_chain_bytes,
            "fresh encryption must change raw chain wire bytes"
        );
        assert_ne!(
            left_da_bytes, right_da_bytes,
            "fresh encryption must change raw DA wire bytes"
        );
        assert_eq!(left_chain_bytes.len(), right_chain_bytes.len());
        assert_eq!(left_da_bytes.len(), right_da_bytes.len());

        let left_parsed = NoteCiphertext::from_chain_bytes(&left_chain_bytes).unwrap();
        let right_parsed = NoteCiphertext::from_chain_bytes(&right_chain_bytes).unwrap();
        let left_da_parsed = NoteCiphertext::from_da_bytes(&left_da_bytes).unwrap();
        let right_da_parsed = NoteCiphertext::from_da_bytes(&right_da_bytes).unwrap();
        assert_public_ciphertext_summary_shape_eq(&left, &right);
        assert_public_ciphertext_summary_shape_eq(&left_parsed, &right_parsed);
        assert_public_ciphertext_summary_shape_eq(&left_da_parsed, &right_da_parsed);

        let recovered_left = left.decrypt(&material).unwrap();
        let recovered_right = right.decrypt(&material).unwrap();
        assert_eq!(recovered_left, note);
        assert_eq!(recovered_right, note);
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
        assert_eq!(recovered.crypto_suite, ciphertext.crypto_suite);
        assert_eq!(recovered.diversifier_index, ciphertext.diversifier_index);
        assert_eq!(recovered.kem_ciphertext, ciphertext.kem_ciphertext);
        assert_eq!(recovered.note_payload, ciphertext.note_payload);
        assert_eq!(recovered.memo_payload, ciphertext.memo_payload);
    }

    #[test]
    fn chain_serialization_round_trip() {
        let ciphertext = sample_ciphertext(457, b"chain memo");
        let bytes = ciphertext.to_chain_bytes().unwrap();
        let recovered = NoteCiphertext::from_chain_bytes(&bytes).unwrap();

        assert_eq!(recovered.version, ciphertext.version);
        assert_eq!(recovered.crypto_suite, ciphertext.crypto_suite);
        assert_eq!(recovered.diversifier_index, ciphertext.diversifier_index);
        assert_eq!(recovered.kem_ciphertext, ciphertext.kem_ciphertext);
        assert_eq!(recovered.note_payload, ciphertext.note_payload);
        assert_eq!(recovered.memo_payload, ciphertext.memo_payload);
    }

    #[test]
    fn da_serialization_round_trip() {
        let ciphertext = sample_ciphertext(458, b"da memo");
        let bytes = ciphertext.to_da_bytes().unwrap();
        let recovered = NoteCiphertext::from_da_bytes(&bytes).unwrap();

        assert_eq!(recovered.version, ciphertext.version);
        assert_eq!(recovered.crypto_suite, ciphertext.crypto_suite);
        assert_eq!(recovered.diversifier_index, ciphertext.diversifier_index);
        assert_eq!(recovered.kem_ciphertext, ciphertext.kem_ciphertext);
        assert_eq!(recovered.note_payload, ciphertext.note_payload);
        assert_eq!(recovered.memo_payload, ciphertext.memo_payload);
    }

    #[test]
    fn to_chain_bytes_rejects_oversize_memo() {
        let mut rng = StdRng::seed_from_u64(789);
        let root = RootSecret::from_rng(&mut rng);
        let keys = root.derive();
        let material = keys.address(0).unwrap();
        let address = material.shielded_address();
        let memo = vec![0u8; 600];
        let note = NotePlaintext::random(1, 0, MemoPlaintext::new(memo), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        assert!(ciphertext.to_chain_bytes().is_err());
    }

    #[test]
    fn empty_ciphertext_uses_current_version() {
        let empty = NoteCiphertext::empty();
        assert_eq!(empty.version, NOTE_ENCRYPTION_VERSION);
    }

    #[test]
    fn note_ciphertext_version_gate_rejects_unsupported_wire_and_crypto_formats() {
        let mut ciphertext = sample_ciphertext(799, b"version-gate");
        let unsupported_version = NOTE_ENCRYPTION_VERSION.wrapping_add(1);

        let mut chain_bytes = ciphertext.to_chain_bytes().unwrap();
        chain_bytes[0] = unsupported_version;
        assert_unsupported_note_ciphertext_version(NoteCiphertext::from_chain_bytes(&chain_bytes));

        let mut da_bytes = ciphertext.to_da_bytes().unwrap();
        da_bytes[0] = unsupported_version;
        assert_unsupported_note_ciphertext_version(NoteCiphertext::from_da_bytes(&da_bytes));

        let mut crypto_bytes = ciphertext.to_bytes();
        crypto_bytes[0] = unsupported_version;
        assert_unsupported_note_ciphertext_version(NoteCiphertext::from_bytes(&crypto_bytes));

        ciphertext.version = unsupported_version;
        assert_unsupported_note_ciphertext_version(ciphertext.to_chain_bytes());
        assert_unsupported_note_ciphertext_version(ciphertext.to_da_bytes());
    }

    #[test]
    fn decrypt_rejects_wrong_version_metadata() {
        let (material, _, mut ciphertext) = sample_material_note_ciphertext(800, b"memo");
        ciphertext.version = ciphertext.version.wrapping_add(1);

        assert_note_mismatch(ciphertext.decrypt(&material), "note version mismatch");
    }

    #[test]
    fn decrypt_rejects_wrong_crypto_suite_metadata() {
        let (material, _, mut ciphertext) = sample_material_note_ciphertext(801, b"memo");
        ciphertext.crypto_suite = ciphertext.crypto_suite.wrapping_add(1);

        assert_note_mismatch(ciphertext.decrypt(&material), "note crypto suite mismatch");
    }

    #[test]
    fn decrypt_rejects_wrong_diversifier_metadata() {
        let (material, _, mut ciphertext) = sample_material_note_ciphertext(802, b"memo");
        ciphertext.diversifier_index = ciphertext.diversifier_index.wrapping_add(1);

        assert_note_mismatch(ciphertext.decrypt(&material), "diversifier index mismatch");
    }

    #[test]
    fn decrypt_rejects_wrong_recipient_key() {
        let (_, _, ciphertext) = sample_material_note_ciphertext(803, b"memo");
        let mut rng = StdRng::seed_from_u64(804);
        let wrong_root = RootSecret::from_rng(&mut rng);
        let wrong_material = wrong_root.derive().address(0).unwrap();

        assert_decryption_failure(ciphertext.decrypt(&wrong_material));
    }

    #[test]
    fn decrypt_rejects_malleated_kem_ciphertext() {
        let (material, _, mut ciphertext) = sample_material_note_ciphertext(805, b"memo");
        ciphertext.kem_ciphertext[0] ^= 0x01;

        assert_decryption_failure(ciphertext.decrypt(&material));
    }

    #[test]
    fn decrypt_rejects_malleated_note_payload() {
        let (material, _, mut ciphertext) = sample_material_note_ciphertext(806, b"memo");
        assert!(!ciphertext.note_payload.is_empty());
        ciphertext.note_payload[0] ^= 0x01;

        assert_decryption_failure(ciphertext.decrypt(&material));
    }

    #[test]
    fn decrypt_rejects_malleated_memo_payload() {
        let (material, _, mut ciphertext) = sample_material_note_ciphertext(807, b"memo");
        assert!(!ciphertext.memo_payload.is_empty());
        ciphertext.memo_payload[0] ^= 0x01;

        assert_decryption_failure(ciphertext.decrypt(&material));
    }

    #[test]
    fn from_chain_bytes_rejects_memo_overrun() {
        let ciphertext = sample_ciphertext(790, b"memo");
        let mut bytes = ciphertext.to_chain_bytes().unwrap();
        let (_, memo_len_offset, memo_start, _) = payload_offsets(&bytes);
        let overrun_len = CHAIN_CIPHERTEXT_SIZE - memo_start + 1;
        bytes[memo_len_offset..memo_len_offset + 4]
            .copy_from_slice(&(overrun_len as u32).to_le_bytes());

        assert!(NoteCiphertext::from_chain_bytes(&bytes).is_err());
    }

    #[test]
    fn from_da_bytes_rejects_memo_overrun() {
        let ciphertext = sample_ciphertext(795, b"memo");
        let mut bytes = ciphertext.to_da_bytes().unwrap();
        let (_, memo_len_offset, memo_start, _) = payload_offsets(&bytes);
        let overrun_len = CHAIN_CIPHERTEXT_SIZE - memo_start + 1;
        bytes[memo_len_offset..memo_len_offset + 4]
            .copy_from_slice(&(overrun_len as u32).to_le_bytes());

        assert!(NoteCiphertext::from_da_bytes(&bytes).is_err());
    }

    #[test]
    fn from_chain_bytes_rejects_nonzero_container_padding() {
        let ciphertext = sample_ciphertext(791, b"memo");
        let mut bytes = ciphertext.to_chain_bytes().unwrap();
        let (_, _, _, payload_end) = payload_offsets(&bytes);
        assert!(payload_end < CHAIN_CIPHERTEXT_SIZE);
        bytes[payload_end] = 0xaa;

        assert!(NoteCiphertext::from_chain_bytes(&bytes).is_err());
    }

    #[test]
    fn from_da_bytes_rejects_nonzero_container_padding() {
        let ciphertext = sample_ciphertext(796, b"memo");
        let mut bytes = ciphertext.to_da_bytes().unwrap();
        let (_, _, _, payload_end) = payload_offsets(&bytes);
        assert!(payload_end < CHAIN_CIPHERTEXT_SIZE);
        bytes[payload_end] = 0xaa;

        assert!(NoteCiphertext::from_da_bytes(&bytes).is_err());
    }

    #[test]
    fn from_chain_bytes_rejects_trailing_bytes_after_kem() {
        let ciphertext = sample_ciphertext(792, b"memo");
        let mut bytes = ciphertext.to_chain_bytes().unwrap();
        bytes.push(0x99);

        assert!(NoteCiphertext::from_chain_bytes(&bytes).is_err());
    }

    #[test]
    fn from_da_bytes_rejects_trailing_bytes_after_kem() {
        let ciphertext = sample_ciphertext(797, b"memo");
        let mut bytes = ciphertext.to_da_bytes().unwrap();
        bytes.push(0x99);

        assert!(NoteCiphertext::from_da_bytes(&bytes).is_err());
    }

    #[test]
    fn from_chain_bytes_rejects_noncanonical_compact_kem_length() {
        let ciphertext = sample_ciphertext(793, b"memo");
        let bytes = ciphertext.to_chain_bytes().unwrap();
        let mut noncanonical = Vec::with_capacity(bytes.len() + 2);
        noncanonical.extend_from_slice(&bytes[..CHAIN_CIPHERTEXT_SIZE]);
        let raw = ((synthetic_crypto::ml_kem::ML_KEM_CIPHERTEXT_LEN as u32) << 2) | 0x02;
        noncanonical.extend_from_slice(&raw.to_le_bytes());
        noncanonical.extend_from_slice(&bytes[CHAIN_CIPHERTEXT_SIZE + 2..]);

        assert!(NoteCiphertext::from_chain_bytes(&noncanonical).is_err());
    }

    #[test]
    fn from_chain_bytes_rejects_truncated_prefixes_without_panic() {
        let ciphertext = sample_ciphertext(794, b"memo");
        let bytes = ciphertext.to_chain_bytes().unwrap();

        for len in 0..bytes.len() {
            let result =
                std::panic::catch_unwind(|| NoteCiphertext::from_chain_bytes(&bytes[..len]));
            assert!(
                result.is_ok(),
                "from_chain_bytes panicked on prefix length {len}"
            );
            assert!(
                result.unwrap().is_err(),
                "truncated prefix length {len} unexpectedly decoded"
            );
        }
    }

    #[test]
    fn from_da_bytes_rejects_truncated_prefixes_without_panic() {
        let ciphertext = sample_ciphertext(798, b"memo");
        let bytes = ciphertext.to_da_bytes().unwrap();

        for len in 0..bytes.len() {
            let result = std::panic::catch_unwind(|| NoteCiphertext::from_da_bytes(&bytes[..len]));
            assert!(
                result.is_ok(),
                "from_da_bytes panicked on prefix length {len}"
            );
            assert!(
                result.unwrap().is_err(),
                "truncated DA prefix length {len} unexpectedly decoded"
            );
        }
    }
}
