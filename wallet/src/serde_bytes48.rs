use serde::{Deserialize, Deserializer, Serializer};

pub mod bytes48 {
    use super::{Deserialize, Deserializer, Serializer};

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

pub mod vec_bytes48 {
    use super::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(values: &[[u8; 48]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::with_capacity(values.len() * 48);
        for value in values {
            bytes.extend_from_slice(value);
        }
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 48]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if !bytes.len().is_multiple_of(48) {
            return Err(serde::de::Error::custom("invalid 48-byte encoding"));
        }
        Ok(bytes
            .chunks(48)
            .map(|chunk| <[u8; 48]>::try_from(chunk).expect("48-byte chunk"))
            .collect())
    }
}
