use bech32::{self, FromBase32, ToBase32, Variant};
use serde::{Deserialize, Serialize};

use protocol_versioning::{CRYPTO_SUITE_ETA, CRYPTO_SUITE_GAMMA};
use synthetic_crypto::{
    ml_kem::{MlKemKeyPair, MlKemPublicKey, ML_KEM_PUBLIC_KEY_LEN},
    traits::{KemKeyPair, KemPublicKey},
};

use crate::error::WalletError;

const ADDRESS_HRP: &str = "shca";
pub const LEGACY_ADDRESS_VERSION: u8 = 3;
// Version 4 did not carry the full authorization commitment. Never reinterpret it.
pub const POSEIDON2_V8_ADDRESS_VERSION: u8 = 5;
pub const POSEIDON2_V8_AUTH_EXTENSION_LEN: usize = 24;

const fn supported_address_identity(version: u8, crypto_suite: u16) -> bool {
    matches!(
        (version, crypto_suite),
        (LEGACY_ADDRESS_VERSION, CRYPTO_SUITE_GAMMA)
            | (POSEIDON2_V8_ADDRESS_VERSION, CRYPTO_SUITE_ETA)
    )
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedAddress {
    pub version: u8,
    pub crypto_suite: u16,
    pub diversifier_index: u32,
    #[serde(with = "serde_bytes32")]
    pub pk_recipient: [u8; 32],
    #[serde(with = "serde_bytes32")]
    pub pk_auth: [u8; 32],
    #[serde(default, with = "serde_bytes24")]
    pub pk_auth_extension: [u8; POSEIDON2_V8_AUTH_EXTENSION_LEN],
    #[serde(with = "serde_mlkem_pk")]
    pub pk_enc: MlKemPublicKey,
}

impl Default for ShieldedAddress {
    fn default() -> Self {
        // Generate a dummy address for testing purposes
        let keypair = MlKemKeyPair::generate_deterministic(b"test-default-address");
        Self {
            version: LEGACY_ADDRESS_VERSION,
            crypto_suite: CRYPTO_SUITE_GAMMA,
            diversifier_index: 0,
            pk_recipient: [0u8; 32],
            pk_auth: [0u8; 32],
            pk_auth_extension: [0u8; POSEIDON2_V8_AUTH_EXTENSION_LEN],
            pk_enc: keypair.public_key(),
        }
    }
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
        let extension_len = if self.version == POSEIDON2_V8_ADDRESS_VERSION {
            POSEIDON2_V8_AUTH_EXTENSION_LEN
        } else {
            0
        };
        let mut out = Vec::with_capacity(1 + 2 + 4 + 32 + 32 + extension_len + ML_KEM_PUBLIC_KEY_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.crypto_suite.to_le_bytes());
        out.extend_from_slice(&self.diversifier_index.to_le_bytes());
        out.extend_from_slice(&self.pk_recipient);
        out.extend_from_slice(&self.pk_auth);
        if self.version == POSEIDON2_V8_ADDRESS_VERSION {
            out.extend_from_slice(&self.pk_auth_extension);
        }
        out.extend_from_slice(self.pk_enc.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WalletError> {
        let version = *bytes.first().ok_or_else(|| {
            WalletError::AddressEncoding("empty address payload".into())
        })?;
        let extension_len = if version == POSEIDON2_V8_ADDRESS_VERSION {
            POSEIDON2_V8_AUTH_EXTENSION_LEN
        } else {
            0
        };
        let expected_len = 1 + 2 + 4 + 32 + 32 + extension_len + ML_KEM_PUBLIC_KEY_LEN;
        if bytes.len() != expected_len {
            return Err(WalletError::AddressEncoding(format!(
                "invalid address length: expected {} bytes, got {}",
                expected_len,
                bytes.len()
            )));
        }
        let crypto_suite = u16::from_le_bytes(
            bytes[1..3]
                .try_into()
                .map_err(|_| WalletError::AddressEncoding("crypto suite parse failed".into()))?,
        );
        if !supported_address_identity(version, crypto_suite) {
            return Err(WalletError::AddressEncoding(format!(
                "unsupported address version/crypto suite: {version}/{crypto_suite}"
            )));
        }
        let mut index_bytes = [0u8; 4];
        index_bytes.copy_from_slice(&bytes[3..7]);
        let diversifier_index = u32::from_le_bytes(index_bytes);
        let mut pk_recipient = [0u8; 32];
        pk_recipient.copy_from_slice(&bytes[7..39]);
        let mut pk_auth = [0u8; 32];
        pk_auth.copy_from_slice(&bytes[39..71]);
        let mut pk_auth_extension = [0u8; POSEIDON2_V8_AUTH_EXTENSION_LEN];
        if version == POSEIDON2_V8_ADDRESS_VERSION {
            pk_auth_extension.copy_from_slice(&bytes[71..71 + POSEIDON2_V8_AUTH_EXTENSION_LEN]);
        }
        if version == POSEIDON2_V8_ADDRESS_VERSION {
            let recipient = transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_from_canonical_bytes(pk_recipient)
                .map_err(|_| WalletError::AddressEncoding("non-canonical V8 recipient key".into()))?;
            let authorization = transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_from_canonical_bytes(pk_auth)
                .map_err(|_| WalletError::AddressEncoding("non-canonical V8 authorization key".into()))?;
            for chunk in pk_auth_extension.chunks_exact(8) {
                let word = u64::from_le_bytes(chunk.try_into().expect("eight-byte auth-extension limb"));
                if word >= transaction_circuit::constants::FIELD_MODULUS_U64 {
                    return Err(WalletError::AddressEncoding(
                        "non-canonical V8 authorization extension".into(),
                    ));
                }
            }
            if recipient == [0; 4] || authorization == [0; 4] {
                return Err(WalletError::AddressEncoding(
                    "zero V8 recipient or authorization key".into(),
                ));
            }
        }
        let pk_start = 71 + extension_len;
        let pk_end = pk_start + ML_KEM_PUBLIC_KEY_LEN;
        let pk_enc = MlKemPublicKey::from_bytes(&bytes[pk_start..pk_end])
            .map_err(|err| WalletError::AddressEncoding(err.to_string()))?;
        Ok(Self {
            version,
            crypto_suite,
            diversifier_index,
            pk_recipient,
            pk_auth,
            pk_auth_extension,
            pk_enc,
        })
    }
}

mod serde_bytes24 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 24], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 24], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::<u8>::deserialize(deserializer)?;
        if bytes.len() != 24 {
            return Err(serde::de::Error::custom("expected 24 bytes"));
        }
        let mut out = [0u8; 24];
        out.copy_from_slice(&bytes);
        Ok(out)
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

    #[test]
    fn decode_rejects_unknown_crypto_suite() {
        let mut rng = StdRng::seed_from_u64(42);
        let keys = RootSecret::from_rng(&mut rng).derive();
        let address = keys.address(1).unwrap().shielded_address();
        let mut bytes = address.to_bytes();
        let mut suite = u16::from_le_bytes([bytes[1], bytes[2]]);
        suite = suite.wrapping_add(1);
        bytes[1..3].copy_from_slice(&suite.to_le_bytes());
        let result = crate::address::ShieldedAddress::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn repaired_address_round_trips_and_rejects_old_identity() {
        let mut rng = StdRng::seed_from_u64(101);
        let keys = RootSecret::from_rng(&mut rng).derive();
        let address = keys.poseidon2_v8_address(7).unwrap().shielded_address();
        let bytes = address.to_bytes();
        assert_eq!(super::ShieldedAddress::from_bytes(&bytes).unwrap(), address);
        let mut old_identity = bytes.clone();
        old_identity[0] = 4;
        assert!(super::ShieldedAddress::from_bytes(&old_identity).is_err());
        old_identity.drain(71..95);
        assert!(super::ShieldedAddress::from_bytes(&old_identity).is_err());
        let mut noncanonical = bytes;
        noncanonical[71..79].copy_from_slice(
            &transaction_circuit::constants::FIELD_MODULUS_U64.to_le_bytes(),
        );
        assert!(super::ShieldedAddress::from_bytes(&noncanonical).is_err());
    }
}
