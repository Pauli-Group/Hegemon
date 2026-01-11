use serde::{Deserialize, Serialize};
use transaction_circuit::StablecoinPolicyBinding;

use crate::error::WalletError;
use crate::notes::NoteCiphertext;

/// Transaction bundle for submission to the node.
///
/// This contains all data needed to submit a shielded transfer to the chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionBundle {
    /// STARK proof bytes (serialized Plonky3 proof).
    #[serde(with = "serde_bytes_vec")]
    pub proof_bytes: Vec<u8>,
    /// Nullifiers (48 bytes each, left-padded field elements).
    #[serde(with = "crate::serde_bytes48::vec_bytes48")]
    pub nullifiers: Vec<[u8; 48]>,
    /// Commitments (48 bytes each, left-padded field elements).
    #[serde(with = "crate::serde_bytes48::vec_bytes48")]
    pub commitments: Vec<[u8; 48]>,
    /// Encrypted note ciphertexts.
    #[serde(with = "serde_ciphertexts")]
    pub ciphertexts: Vec<Vec<u8>>,
    /// Merkle tree anchor (root hash).
    #[serde(with = "crate::serde_bytes48::bytes48")]
    pub anchor: [u8; 48],
    /// Binding hash commitment.
    #[serde(with = "serde_bytes_64")]
    pub binding_hash: [u8; 64],
    /// Native fee encoded in the proof.
    pub fee: u64,
    /// Value balance (must be 0 when no transparent pool is enabled).
    pub value_balance: i128,
    /// Optional stablecoin policy binding (disabled by default).
    #[serde(default)]
    pub stablecoin: StablecoinPolicyBinding,
}

impl TransactionBundle {
    /// Create a new transaction bundle from proof components.
    pub fn new(
        proof_bytes: Vec<u8>,
        nullifiers: Vec<[u8; 48]>,
        commitments: Vec<[u8; 48]>,
        ciphertexts: &[NoteCiphertext],
        anchor: [u8; 48],
        binding_hash: [u8; 64],
        fee: u64,
        value_balance: i128,
        stablecoin: StablecoinPolicyBinding,
    ) -> Result<Self, WalletError> {
        if commitments.len() != ciphertexts.len() {
            return Err(WalletError::InvalidState(
                "ciphertexts count must match commitments count",
            ));
        }
        let mut encoded = Vec::with_capacity(ciphertexts.len());
        for ct in ciphertexts {
            // Use pallet-compatible format instead of bincode
            encoded.push(ct.to_pallet_bytes()?);
        }
        Ok(Self {
            proof_bytes,
            nullifiers,
            commitments,
            ciphertexts: encoded,
            anchor,
            binding_hash,
            fee,
            value_balance,
            stablecoin,
        })
    }

    pub fn decode_notes(&self) -> Result<Vec<NoteCiphertext>, WalletError> {
        let mut notes = Vec::with_capacity(self.ciphertexts.len());
        for bytes in &self.ciphertexts {
            // Decode from pallet format
            notes.push(NoteCiphertext::from_pallet_bytes(bytes)?);
        }
        Ok(notes)
    }
}

mod serde_ciphertexts {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(values: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let wrappers: Vec<_> = values
            .iter()
            .map(|value| serde_bytes::Bytes::new(value))
            .collect();
        wrappers.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wrappers: Vec<serde_bytes::ByteBuf> = Vec::deserialize(deserializer)?;
        Ok(wrappers.into_iter().map(|buf| buf.into_vec()).collect())
    }
}

mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::Bytes::new(value).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let buf: serde_bytes::ByteBuf = serde_bytes::ByteBuf::deserialize(deserializer)?;
        Ok(buf.into_vec())
    }
}

mod serde_bytes_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::Bytes::new(value).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let buf: serde_bytes::ByteBuf = serde_bytes::ByteBuf::deserialize(deserializer)?;
        let vec = buf.into_vec();
        if vec.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                vec.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}
