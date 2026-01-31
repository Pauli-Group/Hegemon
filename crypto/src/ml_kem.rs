//! ML-KEM-1024 (FIPS 203) - REAL Post-Quantum Key Encapsulation
//!
//! This module provides a wrapper around the `ml-kem` crate which implements
//! the NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism.
//!
//! Security: This is REAL lattice-based cryptography, not a placeholder.

use crate::error::CryptoError;
use crate::traits::{KemKeyPair, KemPublicKey};
use alloc::vec::Vec;

// Re-export the real ML-KEM-1024 types from the ml-kem crate
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, DecapsulationKey, EncapsulationKey};
use ml_kem::{EncodedSizeUser, MlKem1024Params};

/// ML-KEM-1024 parameter sizes (FIPS 203)
pub const ML_KEM_PUBLIC_KEY_LEN: usize = 1568;
pub const ML_KEM_SECRET_KEY_LEN: usize = 3168;
pub const ML_KEM_CIPHERTEXT_LEN: usize = 1568;
pub const ML_KEM_SHARED_SECRET_LEN: usize = 32;

/// Ciphertext from ML-KEM encapsulation
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemCiphertext {
    bytes: [u8; ML_KEM_CIPHERTEXT_LEN],
}

impl MlKemCiphertext {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_KEM_CIPHERTEXT_LEN {
            return Err(CryptoError::InvalidLength {
                expected: ML_KEM_CIPHERTEXT_LEN,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; ML_KEM_CIPHERTEXT_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    pub fn to_bytes(&self) -> [u8; ML_KEM_CIPHERTEXT_LEN] {
        self.bytes
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Shared secret from ML-KEM encapsulation/decapsulation
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemSharedSecret {
    bytes: [u8; ML_KEM_SHARED_SECRET_LEN],
}

impl MlKemSharedSecret {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_KEM_SHARED_SECRET_LEN {
            return Err(CryptoError::InvalidLength {
                expected: ML_KEM_SHARED_SECRET_LEN,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; ML_KEM_SHARED_SECRET_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    pub fn to_bytes(&self) -> [u8; ML_KEM_SHARED_SECRET_LEN] {
        self.bytes
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// ML-KEM-1024 Public Key (encapsulation key)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemPublicKey {
    bytes: [u8; ML_KEM_PUBLIC_KEY_LEN],
}

impl MlKemPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn to_inner(&self) -> EncapsulationKey<MlKem1024Params> {
        let arr: Array<u8, _> = Array::try_from(self.bytes.as_slice()).expect("size mismatch");
        EncapsulationKey::<MlKem1024Params>::from_bytes(&arr)
            .expect("invalid ML-KEM public key bytes")
    }
}

impl KemPublicKey for MlKemPublicKey {
    type Ciphertext = MlKemCiphertext;
    type SharedSecret = MlKemSharedSecret;

    fn encapsulate(&self, seed: &[u8]) -> (Self::Ciphertext, Self::SharedSecret) {
        // REAL ML-KEM encapsulation using lattice operations
        // Use deterministic encapsulation with the provided seed
        use ml_kem::EncapsulateDeterministic;
        use sha2::{Digest, Sha256};

        // Derive 32-byte randomness from the seed
        let mut hasher = Sha256::new();
        hasher.update(b"ml-kem-1024-encapsulate");
        hasher.update(seed);
        let m: [u8; 32] = hasher.finalize().into();
        let m_array: Array<u8, _> = Array::try_from(m.as_slice()).expect("size mismatch");

        let ek = self.to_inner();
        let (ct, ss) = ek
            .encapsulate_deterministic(&m_array)
            .expect("encapsulation failed");

        let mut ct_bytes = [0u8; ML_KEM_CIPHERTEXT_LEN];
        ct_bytes.copy_from_slice(ct.as_ref());

        let mut ss_bytes = [0u8; ML_KEM_SHARED_SECRET_LEN];
        ss_bytes.copy_from_slice(ss.as_ref());

        (
            MlKemCiphertext { bytes: ct_bytes },
            MlKemSharedSecret { bytes: ss_bytes },
        )
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_KEM_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: ML_KEM_PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; ML_KEM_PUBLIC_KEY_LEN];
        arr.copy_from_slice(bytes);
        let arr_checked: Array<u8, _> = Array::try_from(arr.as_slice()).expect("size mismatch");
        EncapsulationKey::<MlKem1024Params>::from_bytes(&arr_checked)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { bytes: arr })
    }
}

/// ML-KEM-1024 Secret Key (decapsulation key)
#[derive(Clone)]
pub struct MlKemSecretKey {
    bytes: [u8; ML_KEM_SECRET_KEY_LEN],
}

impl MlKemSecretKey {
    pub fn public_key(&self) -> MlKemPublicKey {
        let dk = self.to_inner();
        let ek = dk.encapsulation_key();
        let ek_bytes = ek.to_bytes();
        let mut pk_bytes = [0u8; ML_KEM_PUBLIC_KEY_LEN];
        pk_bytes.copy_from_slice(ek_bytes.as_ref());
        MlKemPublicKey { bytes: pk_bytes }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_KEM_SECRET_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: ML_KEM_SECRET_KEY_LEN,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; ML_KEM_SECRET_KEY_LEN];
        arr.copy_from_slice(bytes);
        let arr_checked: Array<u8, _> = Array::try_from(arr.as_slice()).expect("size mismatch");
        DecapsulationKey::<MlKem1024Params>::from_bytes(&arr_checked)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { bytes: arr })
    }

    fn to_inner(&self) -> DecapsulationKey<MlKem1024Params> {
        let arr: Array<u8, _> = Array::try_from(self.bytes.as_slice()).expect("size mismatch");
        DecapsulationKey::<MlKem1024Params>::from_bytes(&arr)
            .expect("invalid ML-KEM secret key bytes")
    }

    /// REAL ML-KEM decapsulation using lattice operations
    pub fn decapsulate(
        &self,
        ciphertext: &MlKemCiphertext,
    ) -> Result<MlKemSharedSecret, CryptoError> {
        let dk = self.to_inner();
        let ct: Array<u8, _> = Array::try_from(ciphertext.bytes.as_slice()).expect("size mismatch");
        let ss = dk
            .decapsulate(&ct)
            .map_err(|_| CryptoError::DecapsulationFailed)?;

        let mut ss_bytes = [0u8; ML_KEM_SHARED_SECRET_LEN];
        ss_bytes.copy_from_slice(ss.as_ref());
        Ok(MlKemSharedSecret { bytes: ss_bytes })
    }
}

impl core::fmt::Debug for MlKemSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MlKemSecretKey").finish_non_exhaustive()
    }
}

impl PartialEq for MlKemSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for MlKemSecretKey {}

/// ML-KEM-1024 Key Pair
#[derive(Clone)]
pub struct MlKemKeyPair {
    secret: MlKemSecretKey,
}

const ML_KEM_KEYPAIR_BYTES: usize = ML_KEM_SECRET_KEY_LEN + ML_KEM_PUBLIC_KEY_LEN;

impl MlKemKeyPair {
    pub fn secret_key(&self) -> &MlKemSecretKey {
        &self.secret
    }
}

impl core::fmt::Debug for MlKemKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MlKemKeyPair").finish_non_exhaustive()
    }
}

impl PartialEq for MlKemKeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.secret == other.secret
    }
}

impl Eq for MlKemKeyPair {}

impl KemKeyPair for MlKemKeyPair {
    type PublicKey = MlKemPublicKey;
    type Ciphertext = MlKemCiphertext;
    type SharedSecret = MlKemSharedSecret;

    fn generate_deterministic(seed: &[u8]) -> Self {
        // Use seed to create deterministic key generation
        use sha2::{Digest, Sha256};

        // Create 64-byte seed for ML-KEM (d || z)
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];

        let mut hasher = Sha256::new();
        hasher.update(b"ml-kem-1024-d");
        hasher.update(seed);
        d.copy_from_slice(&hasher.finalize());

        let mut hasher = Sha256::new();
        hasher.update(b"ml-kem-1024-z");
        hasher.update(seed);
        z.copy_from_slice(&hasher.finalize());

        // Construct the 64-byte seed
        let mut full_seed = [0u8; 64];
        full_seed[..32].copy_from_slice(&d);
        full_seed[32..].copy_from_slice(&z);
        let seed_array: ml_kem::Seed =
            Array::try_from(full_seed.as_slice()).expect("size mismatch");

        // REAL ML-KEM key generation using lattice operations
        let dk = DecapsulationKey::<MlKem1024Params>::from(seed_array);
        let dk_bytes = dk.to_bytes();

        let mut secret_bytes = [0u8; ML_KEM_SECRET_KEY_LEN];
        secret_bytes.copy_from_slice(dk_bytes.as_ref());

        Self {
            secret: MlKemSecretKey {
                bytes: secret_bytes,
            },
        }
    }

    fn encapsulate(&self, seed: &[u8]) -> (Self::Ciphertext, Self::SharedSecret) {
        self.secret.public_key().encapsulate(seed)
    }

    fn decapsulate(
        &self,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, CryptoError> {
        self.secret.decapsulate(ciphertext)
    }

    fn public_key(&self) -> Self::PublicKey {
        self.secret.public_key()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let pk = self.secret.public_key();
        let mut out = Vec::with_capacity(ML_KEM_KEYPAIR_BYTES);
        out.extend_from_slice(&self.secret.bytes);
        out.extend_from_slice(&pk.bytes);
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_KEM_KEYPAIR_BYTES {
            return Err(CryptoError::InvalidLength {
                expected: ML_KEM_KEYPAIR_BYTES,
                actual: bytes.len(),
            });
        }
        let (sk_bytes, _pk_bytes) = bytes.split_at(ML_KEM_SECRET_KEY_LEN);
        let secret = MlKemSecretKey::from_bytes(sk_bytes)?;
        Ok(Self { secret })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_roundtrip() {
        // Generate keypair
        let seed = b"test seed for ml-kem key generation";
        let keypair = MlKemKeyPair::generate_deterministic(seed);

        // Encapsulate
        let encap_seed = b"encapsulation randomness";
        let (ciphertext, shared_secret_enc) = keypair.encapsulate(encap_seed);

        // Decapsulate
        let shared_secret_dec = keypair.decapsulate(&ciphertext).expect("decapsulation");

        // Shared secrets must match - THIS IS REAL CRYPTO
        assert_eq!(shared_secret_enc.as_bytes(), shared_secret_dec.as_bytes());
    }

    #[test]
    fn test_parameter_sizes() {
        // Verify FIPS 203 ML-KEM-1024 parameter sizes
        assert_eq!(ML_KEM_PUBLIC_KEY_LEN, 1568);
        assert_eq!(ML_KEM_SECRET_KEY_LEN, 3168);
        assert_eq!(ML_KEM_CIPHERTEXT_LEN, 1568);
        assert_eq!(ML_KEM_SHARED_SECRET_LEN, 32);
    }

    #[test]
    fn test_deterministic_keygen() {
        // Same seed should produce same keypair
        let seed = b"deterministic test seed";
        let kp1 = MlKemKeyPair::generate_deterministic(seed);
        let kp2 = MlKemKeyPair::generate_deterministic(seed);
        assert_eq!(kp1.public_key().as_bytes(), kp2.public_key().as_bytes());
    }
}
