use serde::{Deserialize, Serialize};

use crate::{
    constants::MAX_NOTE_VALUE,
    error::TransactionCircuitError,
    hashing::{note_commitment, Felt},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteData {
    pub value: u64,
    pub asset_id: u64,
    #[serde(with = "crate::note::serde_bytes32")]
    pub pk_recipient: [u8; 32],
    #[serde(with = "crate::note::serde_bytes32")]
    pub rho: [u8; 32],
    #[serde(with = "crate::note::serde_bytes32")]
    pub r: [u8; 32],
}

impl NoteData {
    pub fn validate(&self) -> Result<(), TransactionCircuitError> {
        if self.value as u128 > MAX_NOTE_VALUE {
            return Err(TransactionCircuitError::ValueOutOfRange(self.value as u128));
        }
        Ok(())
    }

    pub fn commitment(&self) -> Felt {
        note_commitment(
            self.value,
            self.asset_id,
            &self.pk_recipient,
            &self.rho,
            &self.r,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputNoteWitness {
    #[serde(flatten)]
    pub note: NoteData,
    pub position: u64,
    #[serde(with = "crate::note::serde_bytes32")]
    pub rho_seed: [u8; 32],
}

impl InputNoteWitness {
    pub fn validate(&self) -> Result<(), TransactionCircuitError> {
        self.note.validate()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputNoteWitness {
    #[serde(flatten)]
    pub note: NoteData,
}

impl OutputNoteWitness {
    pub fn validate(&self) -> Result<(), TransactionCircuitError> {
        self.note.validate()
    }
}

pub(crate) mod serde_bytes32 {
    use serde::{Deserializer, Serializer};

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
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    use serde::Deserialize;
}
