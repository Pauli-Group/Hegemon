use serde::{Deserialize, Serialize};
use winterfell::math::FieldElement;

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

/// Merkle tree depth for the note commitment tree.
pub const MERKLE_TREE_DEPTH: usize = 32;

/// A Merkle authentication path: siblings from leaf to root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePath {
    /// Sibling hashes from leaf to root (length = MERKLE_TREE_DEPTH).
    #[serde(with = "crate::note::serde_merkle_path")]
    pub siblings: Vec<crate::hashing::Felt>,
}

impl Default for MerklePath {
    fn default() -> Self {
        Self {
            siblings: vec![crate::hashing::Felt::ZERO; MERKLE_TREE_DEPTH],
        }
    }
}

impl MerklePath {
    /// Verify this path connects leaf_hash at position to the given root.
    pub fn verify(&self, leaf_hash: crate::hashing::Felt, position: u64, root: crate::hashing::Felt) -> bool {
        use crate::hashing::merkle_node;
        
        let mut current = leaf_hash;
        let mut pos = position;
        
        for sibling in &self.siblings {
            current = if pos & 1 == 0 {
                merkle_node(current, *sibling)
            } else {
                merkle_node(*sibling, current)
            };
            pos >>= 1;
        }
        
        current == root
    }
}

pub(crate) mod serde_merkle_path {
    use super::*;
    use serde::{Deserializer, Serializer, ser::SerializeSeq, de::SeqAccess, de::Visitor};
    use winterfell::math::FieldElement;
    
    pub fn serialize<S>(value: &Vec<crate::hashing::Felt>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for elem in value {
            seq.serialize_element(&elem.as_int())?;
        }
        seq.end()
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<crate::hashing::Felt>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FeltVecVisitor;
        impl<'de> Visitor<'de> for FeltVecVisitor {
            type Value = Vec<crate::hashing::Felt>;
            
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence of u64 field elements")
            }
            
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(val) = seq.next_element::<u64>()? {
                    vec.push(crate::hashing::Felt::new(val));
                }
                Ok(vec)
            }
        }
        deserializer.deserialize_seq(FeltVecVisitor)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputNoteWitness {
    #[serde(flatten)]
    pub note: NoteData,
    pub position: u64,
    #[serde(with = "crate::note::serde_bytes32")]
    pub rho_seed: [u8; 32],
    /// Merkle authentication path proving note is in the tree.
    #[serde(default)]
    pub merkle_path: MerklePath,
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
