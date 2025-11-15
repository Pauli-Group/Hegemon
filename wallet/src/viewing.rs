use serde::{Deserialize, Serialize};

use synthetic_crypto::hashes::derive_nullifier;
use transaction_circuit::note::{InputNoteWitness, NoteData};

use crate::{
    address::ShieldedAddress,
    error::WalletError,
    keys::{AddressKeyMaterial, DerivedKeys, DiversifierKey, EncryptionSeed, ViewKey},
    notes::{NoteCiphertext, NotePlaintext},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncomingViewingKey {
    pub view_key: ViewKey,
    pub encryption_seed: EncryptionSeed,
    pub diversifier_key: DiversifierKey,
}

impl IncomingViewingKey {
    pub fn from_keys(keys: &DerivedKeys) -> Self {
        Self {
            view_key: keys.view.clone(),
            encryption_seed: keys.encryption.clone(),
            diversifier_key: keys.diversifier.clone(),
        }
    }

    pub fn address_material(&self, index: u32) -> Result<AddressKeyMaterial, WalletError> {
        AddressKeyMaterial::derive_with_components(
            index,
            &self.view_key,
            &self.encryption_seed,
            &self.diversifier_key,
        )
    }

    pub fn shielded_address(&self, index: u32) -> Result<ShieldedAddress, WalletError> {
        Ok(self.address_material(index)?.shielded_address())
    }

    pub fn decrypt_note(&self, ciphertext: &NoteCiphertext) -> Result<RecoveredNote, WalletError> {
        let material = self.address_material(ciphertext.diversifier_index)?;
        let plaintext = ciphertext.decrypt(&material)?;
        let note_data = plaintext.to_note_data(material.pk_recipient);
        let address = material.shielded_address();
        Ok(RecoveredNote {
            diversifier_index: ciphertext.diversifier_index,
            note: plaintext,
            note_data,
            address,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FullViewingKey {
    pub incoming: IncomingViewingKey,
    #[serde(with = "serde_bytes32")]
    nullifier_key: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutgoingViewingKey {
    pub view_key: ViewKey,
    pub diversifier_key: DiversifierKey,
}

impl OutgoingViewingKey {
    pub fn from_keys(keys: &DerivedKeys) -> Self {
        Self {
            view_key: keys.view.clone(),
            diversifier_key: keys.diversifier.clone(),
        }
    }

    pub fn address_tag(&self, index: u32) -> [u8; 32] {
        self.view_key.address_tag(index)
    }

    pub fn pk_recipient(&self, index: u32) -> [u8; 32] {
        let diversifier = self.diversifier_key.derive(index);
        self.view_key.pk_recipient(&diversifier)
    }
}

impl FullViewingKey {
    pub fn from_keys(keys: &DerivedKeys) -> Self {
        Self {
            incoming: IncomingViewingKey::from_keys(keys),
            nullifier_key: keys.spend.nullifier_key(),
        }
    }

    pub fn incoming(&self) -> &IncomingViewingKey {
        &self.incoming
    }

    pub fn decrypt_note(&self, ciphertext: &NoteCiphertext) -> Result<RecoveredNote, WalletError> {
        self.incoming.decrypt_note(ciphertext)
    }

    pub fn compute_nullifier(&self, rho: &[u8; 32], position: u64) -> [u8; 32] {
        derive_nullifier(&self.nullifier_key, position, rho)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveredNote {
    pub diversifier_index: u32,
    pub note: NotePlaintext,
    pub note_data: NoteData,
    pub address: ShieldedAddress,
}

impl RecoveredNote {
    pub fn to_input_witness(&self, position: u64) -> InputNoteWitness {
        InputNoteWitness {
            note: self.note_data.clone(),
            position,
            rho_seed: self.note.rho,
        }
    }
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

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{keys::RootSecret, notes::MemoPlaintext};

    use super::*;

    #[test]
    fn viewing_key_scans_note() {
        let mut rng = StdRng::seed_from_u64(55);
        let root = RootSecret::from_rng(&mut rng);
        let keys = root.derive();
        let material = keys.address(1).unwrap();
        let address = material.shielded_address();
        let note = NotePlaintext::random(100, 1, MemoPlaintext::new(Vec::from("hello")), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        let ivk = IncomingViewingKey::from_keys(&keys);
        let recovered = ivk.decrypt_note(&ciphertext).unwrap();
        assert_eq!(recovered.note.value, note.value);
        let fvk = FullViewingKey::from_keys(&keys);
        let nullifier = fvk.compute_nullifier(&recovered.note.rho, 5);
        let again = fvk.compute_nullifier(&note.rho, 5);
        assert_eq!(nullifier, again);
        let ovk = OutgoingViewingKey::from_keys(&keys);
        assert_eq!(
            ovk.address_tag(recovered.diversifier_index),
            recovered.address.address_tag
        );
    }
}
