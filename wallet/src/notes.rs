use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use synthetic_crypto::{
    deterministic::expand_to_length,
    ml_kem::{MlKemCiphertext, MlKemSharedSecret},
    traits::KemPublicKey,
};
use transaction_circuit::note::NoteData;

use crate::{address::ShieldedAddress, error::WalletError, keys::AddressKeyMaterial};

const AEAD_KEY_SIZE: usize = 32;
const AEAD_NONCE_SIZE: usize = 12;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoPlaintext(#[serde(with = "serde_bytes_vec")] pub Vec<u8>);

impl MemoPlaintext {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Default for MemoPlaintext {
    fn default() -> Self {
        Self(Vec::new())
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

    pub fn to_note_data(&self, pk_recipient: [u8; 32]) -> NoteData {
        NoteData {
            value: self.value,
            asset_id: self.asset_id,
            pk_recipient,
            rho: self.rho,
            r: self.r,
        }
    }
}

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
    pub fn encrypt<R: RngCore + ?Sized>(
        address: &ShieldedAddress,
        note: &NotePlaintext,
        rng: &mut R,
    ) -> Result<Self, WalletError> {
        let mut kem_seed = [0u8; 32];
        rng.fill_bytes(&mut kem_seed);
        let (kem_ct, shared) = address.pk_enc.encapsulate(&kem_seed);
        let payload = NotePayload {
            value: note.value,
            asset_id: note.asset_id,
            rho: note.rho,
            r: note.r,
            pk_recipient: address.pk_recipient,
        };
        let payload_bytes = bincode::serialize(&payload)?;
        let aad = aad(
            address.version,
            address.diversifier_index,
            &address.address_tag,
        );
        let note_payload = encrypt_payload(&shared, b"note-aead", &payload_bytes, &aad)?;
        let memo_payload = encrypt_payload(&shared, b"memo-aead", note.memo.as_bytes(), &aad)?;
        Ok(Self {
            version: address.version,
            diversifier_index: address.diversifier_index,
            kem_ciphertext: kem_ct.to_bytes().to_vec(),
            note_payload,
            memo_payload,
            hint_tag: address.address_tag,
        })
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
        let kem = MlKemCiphertext::from_bytes(&self.kem_ciphertext)?;
        let shared = material.decapsulate(&kem)?;
        let aad = aad(self.version, self.diversifier_index, &self.hint_tag);
        let payload_bytes = decrypt_payload(&shared, b"note-aead", &self.note_payload, &aad)?;
        let payload: NotePayload = bincode::deserialize(&payload_bytes)?;
        if payload.pk_recipient != material.pk_recipient {
            return Err(WalletError::NoteMismatch("pk_recipient mismatch"));
        }
        let memo_bytes = decrypt_payload(&shared, b"memo-aead", &self.memo_payload, &aad)?;
        Ok(NotePlaintext {
            value: payload.value,
            asset_id: payload.asset_id,
            rho: payload.rho,
            r: payload.r,
            memo: MemoPlaintext::new(memo_bytes),
        })
    }
}

fn encrypt_payload(
    shared: &MlKemSharedSecret,
    label: &[u8],
    data: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, WalletError> {
    let (key, nonce) = derive_aead_material(shared, label);
    let cipher = ChaCha20Poly1305::new(&key.into());
    cipher
        .encrypt(&nonce.into(), Payload { msg: data, aad })
        .map_err(|_| WalletError::EncryptionFailure)
}

fn decrypt_payload(
    shared: &MlKemSharedSecret,
    label: &[u8],
    data: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, WalletError> {
    let (key, nonce) = derive_aead_material(shared, label);
    let cipher = ChaCha20Poly1305::new(&key.into());
    cipher
        .decrypt(&nonce.into(), Payload { msg: data, aad })
        .map_err(|_| WalletError::DecryptionFailure)
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

fn aad(version: u8, index: u32, tag: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 4 + 32);
    aad.push(version);
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(tag);
    aad
}

#[derive(Serialize, Deserialize)]
struct NotePayload {
    value: u64,
    asset_id: u64,
    #[serde(with = "serde_bytes32")]
    rho: [u8; 32],
    #[serde(with = "serde_bytes32")]
    r: [u8; 32],
    #[serde(with = "serde_bytes32")]
    pk_recipient: [u8; 32],
}

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

    pub fn serialize<S>(value: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
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
}
