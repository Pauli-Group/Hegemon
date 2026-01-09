//! Core shared types.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceSlot {
    pub asset_id: u64,
    pub delta: i128,
}

pub type Commitment48 = [u8; 48];
pub type Nullifier48 = [u8; 48];
pub type MerkleRoot48 = [u8; 48];

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StablecoinPolicyBinding {
    pub enabled: bool,
    pub asset_id: u64,
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes48"))]
    pub policy_hash: Commitment48,
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes48"))]
    pub oracle_commitment: Commitment48,
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes48"))]
    pub attestation_commitment: Commitment48,
    pub issuance_delta: i128,
    pub policy_version: u32,
}

#[cfg(feature = "serde")]
mod serde_bytes48 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 48 {
            return Err(serde::de::Error::custom("expected 48 bytes"));
        }
        let mut out = [0u8; 48];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}
