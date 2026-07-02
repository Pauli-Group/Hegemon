use serde::{Deserialize, Serialize};

use transaction_circuit::hashing_pq::{nullifier_bytes, prf_key as compute_prf_key};
use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData};

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
        AddressKeyMaterial::derive_view_only(
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
        let note_data = plaintext.to_note_data(material.pk_recipient, material.pk_auth);
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
    #[serde(default, with = "serde_bytes32")]
    pk_auth: [u8; 32],
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

    pub fn pk_recipient(&self, index: u32) -> [u8; 32] {
        let diversifier = self.diversifier_key.derive(index);
        self.view_key.pk_recipient(&diversifier)
    }
}

impl FullViewingKey {
    pub fn from_keys(keys: &DerivedKeys) -> Self {
        let incoming = IncomingViewingKey::from_keys(keys);
        let mut nullifier_key = [0u8; 32];
        let prf = compute_prf_key(&keys.spend.to_bytes());
        let encoded = transaction_circuit::hashing_pq::felts_to_bytes48(&[prf; 6]);
        nullifier_key[..8].copy_from_slice(&encoded[..8]);
        Self {
            incoming,
            nullifier_key,
            pk_auth: keys.spend.auth_key(),
        }
    }

    pub fn incoming(&self) -> &IncomingViewingKey {
        &self.incoming
    }

    pub fn decrypt_note(&self, ciphertext: &NoteCiphertext) -> Result<RecoveredNote, WalletError> {
        let mut recovered = self.incoming.decrypt_note(ciphertext)?;
        recovered.note_data.pk_auth = self.pk_auth;
        recovered.address.pk_auth = self.pk_auth;
        Ok(recovered)
    }

    pub fn compute_nullifier(&self, rho: &[u8; 32], position: u64) -> [u8; 48] {
        let mut encoded = [0u8; 48];
        encoded[..8].copy_from_slice(&self.nullifier_key[..8]);
        let prf = transaction_circuit::hashing_pq::bytes48_to_felts(&encoded)
            .map(|limbs| limbs[0])
            .unwrap_or_else(|| compute_prf_key(&self.nullifier_key));
        nullifier_bytes(prf, rho, position)
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
            merkle_path: MerklePath::default(), // Filled in by tx builder from tree
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
    use transaction_circuit::hashing_pq::felts_to_bytes48;
    use transaction_circuit::note::OutputNoteWitness;

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
            ovk.pk_recipient(recovered.diversifier_index),
            recovered.address.pk_recipient
        );
    }

    #[test]
    fn full_view_decrypt_binds_plaintext_note_data_commitment_and_witness() {
        let mut rng = StdRng::seed_from_u64(56);
        let root = RootSecret::from_rng(&mut rng);
        let keys = root.derive();
        let material = keys.address(3).unwrap();
        let address = material.shielded_address();
        let note = NotePlaintext::random(
            42_000,
            9,
            MemoPlaintext::new(Vec::from("commitment binding")),
            &mut rng,
        );
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();

        let incoming = IncomingViewingKey::from_keys(&keys)
            .decrypt_note(&ciphertext)
            .unwrap();
        assert_eq!(incoming.note_data.pk_auth, [0u8; 32]);

        let recovered = FullViewingKey::from_keys(&keys)
            .decrypt_note(&ciphertext)
            .unwrap();
        let expected_note_data = note.to_note_data(material.pk_recipient, keys.spend.auth_key());
        assert_eq!(recovered.note, note);
        assert_eq!(recovered.note_data.value, expected_note_data.value);
        assert_eq!(recovered.note_data.asset_id, expected_note_data.asset_id);
        assert_eq!(
            recovered.note_data.pk_recipient,
            expected_note_data.pk_recipient
        );
        assert_eq!(recovered.note_data.pk_auth, expected_note_data.pk_auth);
        assert_eq!(recovered.note_data.rho, expected_note_data.rho);
        assert_eq!(recovered.note_data.r, expected_note_data.r);

        let recovered_commitment = felts_to_bytes48(&recovered.note_data.commitment());
        let plaintext_commitment = felts_to_bytes48(&expected_note_data.commitment());
        assert_eq!(recovered_commitment, plaintext_commitment);

        let input_witness = recovered.to_input_witness(11);
        assert_eq!(
            felts_to_bytes48(&input_witness.note.commitment()),
            plaintext_commitment
        );
        assert_eq!(input_witness.rho_seed, note.rho);

        let output_witness = OutputNoteWitness {
            note: expected_note_data,
        };
        assert_eq!(
            felts_to_bytes48(&output_witness.note.commitment()),
            plaintext_commitment
        );
    }
}
