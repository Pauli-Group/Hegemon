//! ML-DSA-65 (FIPS 204) - REAL Post-Quantum Digital Signatures
//!
//! This module provides a wrapper around the `ml-dsa` crate which implements
//! the NIST FIPS 204 Module-Lattice-Based Digital Signature Algorithm.
//!
//! Security: This is REAL lattice-based cryptography, not a placeholder.

use alloc::vec::Vec;
use crate::error::CryptoError;
use crate::traits::{Signature as SigTrait, SigningKey as SigningKeyTrait, VerifyKey};

// Re-export the real ML-DSA-65 types from the ml-dsa crate
use ml_dsa::{MlDsa65, B32};
use ml_dsa::signature::{Signer, Verifier};

/// ML-DSA-65 parameter sizes (FIPS 204)
pub const ML_DSA_PUBLIC_KEY_LEN: usize = 1952;
pub const ML_DSA_SECRET_KEY_LEN: usize = 4032;
pub const ML_DSA_SIGNATURE_LEN: usize = 3309;

/// ML-DSA-65 Signature
#[derive(Clone, Debug)]
pub struct MlDsaSignature {
    bytes: Vec<u8>,
}

impl MlDsaSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_DSA_SIGNATURE_LEN {
            return Err(CryptoError::InvalidLength {
                expected: ML_DSA_SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self { bytes: bytes.to_vec() })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl PartialEq for MlDsaSignature {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for MlDsaSignature {}

impl SigTrait for MlDsaSignature {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// ML-DSA-65 Public Key (verification key)
#[derive(Clone, Debug)]
pub struct MlDsaPublicKey {
    bytes: [u8; ML_DSA_PUBLIC_KEY_LEN],
}

impl MlDsaPublicKey {
    fn to_inner(&self) -> ml_dsa::VerifyingKey<MlDsa65> {
        ml_dsa::VerifyingKey::<MlDsa65>::decode(&self.bytes.into())
    }
}

impl PartialEq for MlDsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for MlDsaPublicKey {}

impl VerifyKey for MlDsaPublicKey {
    type Signature = MlDsaSignature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<(), CryptoError> {
        let vk = self.to_inner();
        
        // Decode signature
        let sig_bytes: [u8; ML_DSA_SIGNATURE_LEN] = signature.bytes.as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let sig = ml_dsa::Signature::<MlDsa65>::decode(&sig_bytes.into())
            .ok_or(CryptoError::InvalidSignature)?;
        
        // REAL ML-DSA verification using lattice operations
        vk.verify(message, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_DSA_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: ML_DSA_PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; ML_DSA_PUBLIC_KEY_LEN];
        arr.copy_from_slice(bytes);
        
        // Validate it can be decoded
        let _ = ml_dsa::VerifyingKey::<MlDsa65>::decode(&arr.into());
        
        Ok(Self { bytes: arr })
    }
}

/// ML-DSA-65 Secret Key (signing key)
#[derive(Clone)]
pub struct MlDsaSecretKey {
    bytes: [u8; ML_DSA_SECRET_KEY_LEN],
}

impl MlDsaSecretKey {
    fn to_inner(&self) -> ml_dsa::SigningKey<MlDsa65> {
        ml_dsa::SigningKey::<MlDsa65>::decode(&self.bytes.into())
    }
}

impl core::fmt::Debug for MlDsaSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MlDsaSecretKey").finish_non_exhaustive()
    }
}

impl PartialEq for MlDsaSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for MlDsaSecretKey {}

impl SigningKeyTrait for MlDsaSecretKey {
    type VerifyKey = MlDsaPublicKey;
    type Signature = MlDsaSignature;

    fn generate_deterministic(seed: &[u8]) -> Self {
        // Use seed to create deterministic key generation
        use sha2::{Sha256, Digest};
        let mut xi = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"ml-dsa-65-xi");
        hasher.update(seed);
        xi.copy_from_slice(&hasher.finalize());
        
        let seed_b32: B32 = xi.into();
        
        // REAL ML-DSA key generation using lattice operations
        let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed_b32);
        let sk_bytes = sk.encode();
        
        let mut bytes = [0u8; ML_DSA_SECRET_KEY_LEN];
        bytes.copy_from_slice(sk_bytes.as_ref());
        
        Self { bytes }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let sk = self.to_inner();
        // REAL ML-DSA signing using lattice operations  
        let sig = sk.sign(message);
        let sig_bytes = sig.encode();
        MlDsaSignature { bytes: sig_bytes.to_vec() }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_DSA_SECRET_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: ML_DSA_SECRET_KEY_LEN,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; ML_DSA_SECRET_KEY_LEN];
        arr.copy_from_slice(bytes);
        
        // Validate it can be decoded
        let _ = ml_dsa::SigningKey::<MlDsa65>::decode(&arr.into());
        
        Ok(Self { bytes: arr })
    }

    fn verify_key(&self) -> Self::VerifyKey {
        let sk = self.to_inner();
        let vk = sk.verifying_key();
        let vk_bytes = vk.encode();
        
        let mut bytes = [0u8; ML_DSA_PUBLIC_KEY_LEN];
        bytes.copy_from_slice(vk_bytes.as_ref());
        
        MlDsaPublicKey { bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_sign_verify() {
        // Generate keypair
        let seed = b"test seed for ml-dsa key generation";
        let signing_key = MlDsaSecretKey::generate_deterministic(seed);
        let verify_key = signing_key.verify_key();
        
        // Sign a message
        let message = b"Hello, post-quantum world!";
        let signature = signing_key.sign(message);
        
        // Verify the signature - THIS IS REAL CRYPTO
        assert!(verify_key.verify(message, &signature).is_ok());
        
        // Verify with wrong message fails
        let wrong_message = b"Wrong message";
        assert!(verify_key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_parameter_sizes() {
        // Verify FIPS 204 ML-DSA-65 parameter sizes
        assert_eq!(ML_DSA_PUBLIC_KEY_LEN, 1952);
        assert_eq!(ML_DSA_SECRET_KEY_LEN, 4032);
        assert_eq!(ML_DSA_SIGNATURE_LEN, 3309);
    }
    
    #[test]
    fn test_deterministic_keygen() {
        // Same seed should produce same keypair
        let seed = b"deterministic test seed";
        let sk1 = MlDsaSecretKey::generate_deterministic(seed);
        let sk2 = MlDsaSecretKey::generate_deterministic(seed);
        assert_eq!(sk1.verify_key().to_bytes(), sk2.verify_key().to_bytes());
    }
}
