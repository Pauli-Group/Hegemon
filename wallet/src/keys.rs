use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use hegemon_hash384::{blake2b_384_domain_hash, domains};
use protocol_versioning::{CRYPTO_SUITE_ETA, CRYPTO_SUITE_GAMMA};
use synthetic_crypto::{
    deterministic::expand_to_length,
    ml_dsa::MlDsaSecretKey,
    ml_kem::{MlKemCiphertext, MlKemKeyPair, MlKemPublicKey, MlKemSecretKey, MlKemSharedSecret},
    traits::{KemKeyPair, SigningKey, VerifyKey},
};
use transaction_circuit::hashing_pq::spend_auth_key_bytes;

use crate::{
    address::{ShieldedAddress, POSEIDON2_V8_ADDRESS_VERSION},
    error::WalletError,
};

const KEY_SIZE: usize = 32;
const ADDRESS_VERSION: u8 = 3;
const ADDRESS_CRYPTO_SUITE: u16 = CRYPTO_SUITE_GAMMA;
const POSEIDON2_V8_ADDRESS_CRYPTO_SUITE: u16 = CRYPTO_SUITE_ETA;

/// Derive the legacy 32-byte account id from a deterministic ML-DSA seed.
pub fn ml_dsa_account_id_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let signing_key = MlDsaSecretKey::generate_deterministic(seed);
    let public_key = signing_key.verify_key();
    blake2_256_hash(&public_key.to_bytes())
}

fn blake2_256_hash(data: &[u8]) -> [u8; 32] {
    use blake2::digest::{Update as BlakeUpdate, VariableOutput};
    use blake2::Blake2bVar;

    let mut hasher = Blake2bVar::new(32).expect("valid blake2 output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("output size matches");
    out
}

/// Root secret key - the master seed for the wallet.
/// This is zeroized on drop to prevent key material from persisting in memory.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RootSecret(#[serde(with = "serde_bytes32")] [u8; KEY_SIZE]);

impl RootSecret {
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn from_rng<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0u8; KEY_SIZE];
        rng.fill_bytes(&mut bytes);
        let root = Self(bytes);
        bytes.zeroize();
        root
    }

    pub fn to_bytes(&self) -> [u8; KEY_SIZE] {
        self.0
    }

    pub fn derive(&self) -> DerivedKeys {
        DerivedKeys {
            spend: SpendKey(derive_subkey(b"spend", &self.0)),
            view: ViewKey(derive_subkey(b"view", &self.0)),
            encryption: EncryptionSeed(derive_subkey(b"enc", &self.0)),
            diversifier: DiversifierKey(derive_subkey(b"derive", &self.0)),
        }
    }
}

/// Derived keys from the root secret.
/// All sensitive key material is zeroized on drop.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeys {
    pub spend: SpendKey,
    pub view: ViewKey,
    pub encryption: EncryptionSeed,
    pub diversifier: DiversifierKey,
}

impl DerivedKeys {
    pub fn address(&self, index: u32) -> Result<AddressKeyMaterial, WalletError> {
        AddressKeyMaterial::derive_with_spend(
            index,
            &self.view,
            &self.encryption,
            &self.diversifier,
            &self.spend,
        )
    }

    pub fn poseidon2_v8_address(&self, index: u32) -> Result<AddressKeyMaterial, WalletError> {
        AddressKeyMaterial::derive_poseidon2_v8_with_spend(
            index,
            &self.view,
            &self.encryption,
            &self.diversifier,
            &self.spend,
        )
    }
}

/// Spend key - used for authorizing transactions.
/// Zeroized on drop to prevent key material from persisting in memory.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SpendKey(#[serde(with = "serde_bytes32")] [u8; KEY_SIZE]);

impl SpendKey {
    pub fn to_bytes(&self) -> [u8; KEY_SIZE] {
        self.0
    }

    pub fn auth_key(&self) -> [u8; KEY_SIZE] {
        spend_auth_key_bytes(&self.0)
    }

    pub fn poseidon2_v8_words(&self) -> Result<[u64; 5], WalletError> {
        transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_spend_key_words(self.0)
            .map_err(|error| {
                WalletError::Serialization(format!(
                    "V8 spend-key field derivation failed: {error:?}"
                ))
            })
    }

    pub fn nullifier_key(&self) -> [u8; KEY_SIZE] {
        wallet_kdf_v3(domains::WALLET_SPEND_NULLIFIER_KEY_V3, &[&self.0])
    }
}

/// View key - used for deriving addresses and decrypting incoming notes.
/// Zeroized on drop to prevent key material from persisting in memory.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ViewKey(#[serde(with = "serde_bytes32")] [u8; KEY_SIZE]);

impl ViewKey {
    pub fn to_bytes(&self) -> [u8; KEY_SIZE] {
        self.0
    }

    pub fn nullifier_key(&self) -> [u8; KEY_SIZE] {
        wallet_kdf_v3(domains::WALLET_VIEW_NULLIFIER_KEY_V3, &[&self.0])
    }

    pub fn pk_recipient(&self, diversifier: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
        wallet_kdf_v3(domains::WALLET_RECIPIENT_KEY_V3, &[&self.0, diversifier])
    }
}

/// Encryption seed - used for deriving ML-KEM keypairs.
/// Zeroized on drop to prevent key material from persisting in memory.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionSeed(#[serde(with = "serde_bytes32")] [u8; KEY_SIZE]);

impl EncryptionSeed {
    pub fn derive_keypair(&self, diversifier: &[u8; KEY_SIZE], index: u32) -> MlKemKeyPair {
        let mut seed_material =
            Zeroizing::new(Vec::with_capacity(2 * KEY_SIZE + 4 + b"addr-seed".len()));
        seed_material.extend_from_slice(b"addr-seed");
        seed_material.extend_from_slice(&self.0);
        seed_material.extend_from_slice(diversifier);
        seed_material.extend_from_slice(&index.to_le_bytes());
        MlKemKeyPair::generate_deterministic(&seed_material)
    }
}

/// Diversifier key - used for deriving unique addresses.
/// Zeroized on drop to prevent key material from persisting in memory.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DiversifierKey(#[serde(with = "serde_bytes32")] [u8; KEY_SIZE]);

impl DiversifierKey {
    pub fn derive(&self, index: u32) -> [u8; KEY_SIZE] {
        let mut hasher = Sha256::new();
        hasher.update(b"diversifier");
        hasher.update(self.0);
        hasher.update(index.to_le_bytes());
        hasher.finalize().into()
    }
}

#[derive(Clone, Debug)]
pub struct AddressKeyMaterial {
    version: u8,
    crypto_suite: u16,
    pub diversifier_index: u32,
    diversifier: [u8; KEY_SIZE],
    pub pk_recipient: [u8; KEY_SIZE],
    pub pk_auth: [u8; KEY_SIZE],
    pub pk_auth_extension: [u8; 24],
    keypair: MlKemKeyPair,
}

impl AddressKeyMaterial {
    pub fn derive_with_spend(
        index: u32,
        view: &ViewKey,
        encryption: &EncryptionSeed,
        diversifier_key: &DiversifierKey,
        spend: &SpendKey,
    ) -> Result<Self, WalletError> {
        Self::derive_with_components(index, view, encryption, diversifier_key, spend.auth_key())
    }

    pub fn derive_poseidon2_v8_with_spend(
        index: u32,
        view: &ViewKey,
        encryption: &EncryptionSeed,
        diversifier_key: &DiversifierKey,
        spend: &SpendKey,
    ) -> Result<Self, WalletError> {
        let diversifier = diversifier_key.derive(index);
        let recipient_words =
            transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_recipient_key_words(
                view.pk_recipient(&diversifier),
            )
            .map_err(|error| {
                WalletError::Serialization(format!(
                    "V8 recipient-key field derivation failed: {error:?}"
                ))
            })?;
        let spend_words = spend.poseidon2_v8_words()?;
        let authorization_digest = transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_digest(spend_words)
            .map_err(|error| WalletError::Serialization(format!("V8 authorization key derivation failed: {error:?}")))?;
        let authorization_words: [u64; 4] = authorization_digest[..4]
            .try_into()
            .expect("the V8 authorization prefix has four limbs");
        let mut pk_auth_extension = [0u8; 24];
        for (limb, word) in authorization_digest[4..].iter().copied().enumerate() {
            pk_auth_extension[limb * 8..(limb + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        let keypair = encryption.derive_keypair(&diversifier, index);
        Ok(Self {
            version: POSEIDON2_V8_ADDRESS_VERSION,
            crypto_suite: POSEIDON2_V8_ADDRESS_CRYPTO_SUITE,
            diversifier_index: index,
            diversifier,
            pk_recipient:
                transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_to_bytes(
                    recipient_words,
                ),
            pk_auth:
                transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_to_bytes(
                    authorization_words,
                ),
            pk_auth_extension,
            keypair,
        })
    }

    pub fn derive_with_components(
        index: u32,
        view: &ViewKey,
        encryption: &EncryptionSeed,
        diversifier_key: &DiversifierKey,
        pk_auth: [u8; KEY_SIZE],
    ) -> Result<Self, WalletError> {
        let diversifier = diversifier_key.derive(index);
        let pk_recipient = view.pk_recipient(&diversifier);
        let keypair = encryption.derive_keypair(&diversifier, index);
        Ok(Self {
            version: ADDRESS_VERSION,
            crypto_suite: ADDRESS_CRYPTO_SUITE,
            diversifier_index: index,
            diversifier,
            pk_recipient,
            pk_auth,
            pk_auth_extension: [0u8; 24],
            keypair,
        })
    }

    pub fn derive_view_only(
        index: u32,
        view: &ViewKey,
        encryption: &EncryptionSeed,
        diversifier_key: &DiversifierKey,
    ) -> Result<Self, WalletError> {
        Self::derive_with_components(index, view, encryption, diversifier_key, [0u8; KEY_SIZE])
    }

    pub fn shielded_address(&self) -> ShieldedAddress {
        ShieldedAddress {
            version: self.version,
            crypto_suite: self.crypto_suite,
            diversifier_index: self.diversifier_index,
            pk_recipient: self.pk_recipient,
            pk_auth: self.pk_auth,
            pk_auth_extension: self.pk_auth_extension,
            pk_enc: self.keypair.public_key(),
        }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn crypto_suite(&self) -> u16 {
        self.crypto_suite
    }

    pub fn secret_key(&self) -> &MlKemSecretKey {
        self.keypair.secret_key()
    }

    pub fn public_key(&self) -> MlKemPublicKey {
        self.keypair.public_key()
    }

    pub fn diversifier(&self) -> [u8; KEY_SIZE] {
        self.diversifier
    }

    pub fn poseidon2_v8_authorization_extension_words(&self) -> Result<[u64; 3], WalletError> {
        let mut words = [0u64; 3];
        for (limb, chunk) in self.pk_auth_extension.chunks_exact(8).enumerate() {
            let word = u64::from_le_bytes(chunk.try_into().expect("eight-byte auth-extension limb"));
            if word >= transaction_circuit::constants::FIELD_MODULUS_U64 {
                return Err(WalletError::AddressEncoding(
                    "non-canonical V8 authorization extension".into(),
                ));
            }
            words[limb] = word;
        }
        Ok(words)
    }

    pub fn decapsulate(
        &self,
        ciphertext: &MlKemCiphertext,
    ) -> Result<MlKemSharedSecret, WalletError> {
        self.keypair
            .decapsulate(ciphertext)
            .map_err(WalletError::from)
    }
}

fn derive_subkey(label: &[u8], root: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    let mut material = Zeroizing::new(Vec::with_capacity(label.len() + root.len()));
    material.extend_from_slice(label);
    material.extend_from_slice(root);
    let derived = expand_to_length(b"wallet-hkdf", &material, KEY_SIZE);
    let mut out = [0u8; KEY_SIZE];
    out.copy_from_slice(&derived);
    out
}

/// Fresh-chain V3 wallet KDF profile.
///
/// The consensus-wide BLAKE2b-384 frame supplies domain/part separation. Key
/// consumers require 32 bytes, so this explicitly takes the leading 32 bytes;
/// that retains a 128-bit generic quantum preimage floor. It is not presented
/// as a collision-binding 384-bit consensus identity.
fn wallet_kdf_v3(domain: &[u8], parts: &[&[u8]]) -> [u8; KEY_SIZE] {
    let digest = blake2b_384_domain_hash(domain, parts.iter().copied());
    let mut out = [0u8; KEY_SIZE];
    out.copy_from_slice(&digest[..KEY_SIZE]);
    out
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

    use super::*;

    #[test]
    fn derived_keys_deterministic() {
        let mut rng = StdRng::seed_from_u64(42);
        let root = RootSecret::from_rng(&mut rng);
        let keys_a = root.derive();
        let keys_b = root.derive();
        assert_eq!(keys_a, keys_b);
    }

    #[test]
    fn address_material_round_trip() {
        let mut rng = StdRng::seed_from_u64(7);
        let root = RootSecret::from_rng(&mut rng);
        let keys = root.derive();
        let addr = keys.address(5).unwrap();
        let shield = addr.shielded_address();
        assert_eq!(shield.diversifier_index, 5);
        assert_eq!(shield.pk_recipient, addr.pk_recipient);
        assert_eq!(shield.pk_auth, addr.pk_auth);
    }

    #[test]
    fn poseidon2_v8_address_binds_relation_authorization_key() {
        let root = RootSecret::from_bytes([0x31; 32]);
        let keys = root.derive();
        let material = keys.poseidon2_v8_address(7).unwrap();
        let address = material.shielded_address();
        assert_eq!(address.version, POSEIDON2_V8_ADDRESS_VERSION);
        assert_eq!(address.crypto_suite, CRYPTO_SUITE_ETA);
        let spend_words = keys.spend.poseidon2_v8_words().unwrap();
        let expected = transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_key(spend_words).unwrap();
        assert_eq!(
            transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_from_canonical_bytes(address.pk_auth).unwrap(),
            expected
        );
        assert_eq!(
            ShieldedAddress::decode(&address.encode().unwrap()).unwrap(),
            address
        );
    }

    #[test]
    fn wallet_v3_kdf_bytes_and_domains_are_pinned() {
        let spend = SpendKey([0x11; KEY_SIZE]);
        let view = ViewKey([0x22; KEY_SIZE]);
        let diversifier = [0x33; KEY_SIZE];
        let spend_nullifier = hex::encode(spend.nullifier_key());
        let view_nullifier = hex::encode(view.nullifier_key());
        let recipient = hex::encode(view.pk_recipient(&diversifier));
        assert_eq!(
            spend_nullifier,
            "7835f812c65740582accb38200b4d07cbd4af58811368899f2bce89f85cc7d3b"
        );
        assert_eq!(
            view_nullifier,
            "7fac260d87b37c3b87426809cf222723d935f563a014565def10282648e2fc85"
        );
        assert_eq!(
            recipient,
            "1daed41a0b305bb68ab6e04ddc3e745fdae332aa5c4c171338e12df5dddc837b"
        );

        let same_key_material = [0x44; KEY_SIZE];
        assert_ne!(
            wallet_kdf_v3(
                domains::WALLET_SPEND_NULLIFIER_KEY_V3,
                &[&same_key_material]
            ),
            wallet_kdf_v3(domains::WALLET_VIEW_NULLIFIER_KEY_V3, &[&same_key_material])
        );
        assert_ne!(
            wallet_kdf_v3(
                domains::WALLET_SPEND_NULLIFIER_KEY_V3,
                &[&same_key_material]
            ),
            wallet_kdf_v3(
                domains::WALLET_RECIPIENT_KEY_V3,
                &[&same_key_material, &same_key_material]
            )
        );
    }
}
