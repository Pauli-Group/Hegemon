use bech32::{self, FromBase32, ToBase32, Variant};
use serde::{Deserialize, Serialize};

use synthetic_crypto::{
    ml_kem::{MlKemPublicKey, ML_KEM_PUBLIC_KEY_LEN},
    traits::KemPublicKey,
};

use crate::error::WalletError;

const ADDRESS_HRP: &str = "shca";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedAddress {
    pub version: u8,
    pub diversifier_index: u32,
    #[serde(with = "serde_bytes32")]
    pub pk_recipient: [u8; 32],
    #[serde(with = "serde_mlkem_pk")]
    pub pk_enc: MlKemPublicKey,
    #[serde(with = "serde_bytes32")]
    pub address_tag: [u8; 32],
}

impl ShieldedAddress {
    pub fn encode(&self) -> Result<String, WalletError> {
        let payload = self.to_bytes();
        bech32::encode(ADDRESS_HRP, payload.to_base32(), Variant::Bech32m)
            .map_err(|err| WalletError::AddressEncoding(err.to_string()))
    }

    pub fn decode(address: &str) -> Result<Self, WalletError> {
        let (hrp, data, variant) =
            bech32::decode(address).map_err(|err| WalletError::AddressEncoding(err.to_string()))?;
        if hrp != ADDRESS_HRP {
            return Err(WalletError::AddressEncoding(format!(
                "invalid HRP: expected {ADDRESS_HRP}, got {hrp}"
            )));
        }
        if variant != Variant::Bech32m {
            return Err(WalletError::AddressEncoding("unsupported variant".into()));
        }
        let bytes = Vec::<u8>::from_base32(&data)
            .map_err(|err| WalletError::AddressEncoding(err.to_string()))?;
        Self::from_bytes(&bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 4 + 32 + ML_KEM_PUBLIC_KEY_LEN + 32);
        out.push(self.version);
        out.extend_from_slice(&self.diversifier_index.to_le_bytes());
        out.extend_from_slice(&self.pk_recipient);
        out.extend_from_slice(self.pk_enc.as_bytes());
        out.extend_from_slice(&self.address_tag);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WalletError> {
        if bytes.len() != 1 + 4 + 32 + ML_KEM_PUBLIC_KEY_LEN + 32 {
            return Err(WalletError::AddressEncoding(
                "invalid address length".into(),
            ));
        }
        let version = bytes[0];
        let mut index_bytes = [0u8; 4];
        index_bytes.copy_from_slice(&bytes[1..5]);
        let diversifier_index = u32::from_le_bytes(index_bytes);
        let mut pk_recipient = [0u8; 32];
        pk_recipient.copy_from_slice(&bytes[5..37]);
        let pk_start = 37;
        let pk_end = pk_start + ML_KEM_PUBLIC_KEY_LEN;
        let pk_enc = MlKemPublicKey::from_bytes(&bytes[pk_start..pk_end])
            .map_err(|err| WalletError::AddressEncoding(err.to_string()))?;
        let mut address_tag = [0u8; 32];
        address_tag.copy_from_slice(&bytes[pk_end..]);
        Ok(Self {
            version,
            diversifier_index,
            pk_recipient,
            pk_enc,
            address_tag,
        })
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

mod serde_mlkem_pk {
    use serde::{Deserialize, Deserializer, Serializer};

    use synthetic_crypto::{
        ml_kem::{MlKemPublicKey, ML_KEM_PUBLIC_KEY_LEN},
        traits::KemPublicKey,
    };

    pub fn serialize<S>(value: &MlKemPublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value.as_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<MlKemPublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::<u8>::deserialize(deserializer)?;
        if bytes.len() != ML_KEM_PUBLIC_KEY_LEN {
            return Err(serde::de::Error::custom("invalid ML-KEM pk length"));
        }
        MlKemPublicKey::from_bytes(&bytes)
            .map_err(|_| serde::de::Error::custom("invalid ML-KEM key"))
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use crate::keys::RootSecret;

    #[test]
    fn encode_decode_round_trip() {
        let mut rng = StdRng::seed_from_u64(99);
        let keys = RootSecret::from_rng(&mut rng).derive();
        let address = keys.address(7).unwrap().shielded_address();
        let encoded = address.encode().unwrap();
        let decoded = crate::address::ShieldedAddress::decode(&encoded).unwrap();
        assert_eq!(address, decoded);
    }
}
