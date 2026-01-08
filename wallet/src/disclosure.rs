use serde::{Deserialize, Serialize};

use crate::error::WalletError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisclosureChainInfo {
    #[serde(with = "serde_hex_32")]
    pub genesis_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisclosureClaim {
    pub recipient_address: String,
    #[serde(with = "serde_hex_32")]
    pub pk_recipient: [u8; 32],
    pub value: u64,
    pub asset_id: u64,
    #[serde(with = "serde_hex_48")]
    pub commitment: [u8; 48],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisclosureConfirmation {
    #[serde(with = "serde_hex_48")]
    pub anchor: [u8; 48],
    pub leaf_index: u64,
    #[serde(with = "serde_vec_hex_48")]
    pub siblings: Vec<[u8; 48]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisclosureProof {
    #[serde(with = "serde_hex_32")]
    pub air_hash: [u8; 32],
    pub bytes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisclosurePackage {
    pub version: u32,
    pub chain: DisclosureChainInfo,
    pub claim: DisclosureClaim,
    pub confirmation: DisclosureConfirmation,
    pub proof: DisclosureProof,
    #[serde(default)]
    pub disclosed_memo: Option<String>,
}

impl DisclosurePackage {
    pub fn to_pretty_json(&self) -> Result<String, WalletError> {
        serde_json::to_string_pretty(self).map_err(|e| WalletError::Serialization(e.to_string()))
    }

    pub fn from_json_str(input: &str) -> Result<Self, WalletError> {
        serde_json::from_str(input).map_err(|e| WalletError::Serialization(e.to_string()))
    }
}

pub fn encode_hex_32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub fn decode_hex_32(input: &str) -> Result<[u8; 32], WalletError> {
    let trimmed = input
        .strip_prefix("0x")
        .ok_or_else(|| WalletError::Serialization("hex string must start with 0x".into()))?;
    let bytes = hex::decode(trimmed)
        .map_err(|e| WalletError::Serialization(format!("invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(WalletError::Serialization("expected 32-byte hex".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn encode_hex_48(bytes: &[u8; 48]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub fn decode_hex_48(input: &str) -> Result<[u8; 48], WalletError> {
    let trimmed = input
        .strip_prefix("0x")
        .ok_or_else(|| WalletError::Serialization("hex string must start with 0x".into()))?;
    let bytes = hex::decode(trimmed)
        .map_err(|e| WalletError::Serialization(format!("invalid hex: {e}")))?;
    if bytes.len() != 48 {
        return Err(WalletError::Serialization("expected 48-byte hex".into()));
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn decode_base64(input: &str) -> Result<Vec<u8>, WalletError> {
    base64::decode(input).map_err(|e| WalletError::Serialization(format!("invalid base64: {e}")))
}

pub fn encode_base64(bytes: &[u8]) -> String {
    base64::encode(bytes)
}

mod serde_hex_32 {
    use super::{decode_hex_32, encode_hex_32};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex_32(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = String::deserialize(deserializer)?;
        decode_hex_32(&input).map_err(serde::de::Error::custom)
    }
}

mod serde_vec_hex_32 {
    use super::{decode_hex_32, encode_hex_32};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(values: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: Vec<String> = values.iter().map(|v| encode_hex_32(v)).collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: Vec<String> = Vec::<String>::deserialize(deserializer)?;
        encoded
            .into_iter()
            .map(|value| decode_hex_32(&value).map_err(serde::de::Error::custom))
            .collect()
    }
}

mod serde_hex_48 {
    use super::{decode_hex_48, encode_hex_48};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex_48(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = String::deserialize(deserializer)?;
        decode_hex_48(&input).map_err(serde::de::Error::custom)
    }
}

mod serde_vec_hex_48 {
    use super::{decode_hex_48, encode_hex_48};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(values: &[[u8; 48]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: Vec<String> = values.iter().map(|v| encode_hex_48(v)).collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 48]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: Vec<String> = Vec::<String>::deserialize(deserializer)?;
        encoded
            .into_iter()
            .map(|value| decode_hex_48(&value).map_err(serde::de::Error::custom))
            .collect()
    }
}
