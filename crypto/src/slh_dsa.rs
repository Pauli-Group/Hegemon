//! Real SLH-DSA (FIPS 205) implementation using the slh-dsa crate.
//! Uses Shake128f parameter set: 32-byte public key, 64-byte secret key, 17088-byte signatures.

use alloc::vec::Vec;
use crate::error::CryptoError;
use crate::traits::{Signature, SigningKey, VerifyKey};
use slh_dsa::Shake128f;
use slh_dsa::signature::{Keypair, Signer, Verifier};

// Re-export rand_core from slh-dsa for compatible RNG traits
use slh_dsa::signature::rand_core as slh_rand_core;

/// Public key length for SLH-DSA-SHAKE-128f (FIPS 205)
pub const SLH_DSA_PUBLIC_KEY_LEN: usize = 32;
/// Secret key length for SLH-DSA-SHAKE-128f (FIPS 205)
pub const SLH_DSA_SECRET_KEY_LEN: usize = 64;
/// Signature length for SLH-DSA-SHAKE-128f (FIPS 205)
pub const SLH_DSA_SIGNATURE_LEN: usize = 17088;

/// A deterministic RNG compatible with slh-dsa's rand_core version.
/// Uses SHA-256 in counter mode, seeded via domain-separated hashing.
struct SlhCompatibleRng {
    state: [u8; 32],
    counter: u64,
}

impl SlhCompatibleRng {
    fn from_seed(seed: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"slh-dsa-deterministic-rng");
        hasher.update(seed);
        let digest = hasher.finalize();
        let mut state = [0u8; 32];
        state.copy_from_slice(&digest);
        Self { state, counter: 0 }
    }

    fn fill_bytes_internal(&mut self, dest: &mut [u8]) {
        use sha2::{Sha256, Digest};
        let mut offset = 0;
        while offset < dest.len() {
            let mut hasher = Sha256::new();
            hasher.update(&self.state);
            hasher.update(&self.counter.to_le_bytes());
            let block = hasher.finalize();
            let to_copy = core::cmp::min(dest.len() - offset, 32);
            dest[offset..offset + to_copy].copy_from_slice(&block[..to_copy]);
            offset += to_copy;
            self.counter = self.counter.wrapping_add(1);
        }
    }
}

impl slh_rand_core::RngCore for SlhCompatibleRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes_internal(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes_internal(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill_bytes_internal(dest);
    }
}

// Mark as cryptographically secure (it uses SHA-256 which is safe for this purpose)
impl slh_rand_core::CryptoRng for SlhCompatibleRng {}

/// SLH-DSA signature wrapper
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlhDsaSignature {
    inner: slh_dsa::Signature<Shake128f>,
    // Cache the bytes for as_bytes() to return a reference
    bytes: Vec<u8>,
}

impl SlhDsaSignature {
    /// Parse a signature from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != SLH_DSA_SIGNATURE_LEN {
            return Err(CryptoError::InvalidLength {
                expected: SLH_DSA_SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        // slh_dsa::Signature implements TryFrom<&[u8]>
        let inner = slh_dsa::Signature::<Shake128f>::try_from(bytes)
            .map_err(|_| CryptoError::InvalidLength {
                expected: SLH_DSA_SIGNATURE_LEN,
                actual: bytes.len(),
            })?;
        Ok(Self { 
            inner,
            bytes: bytes.to_vec(),
        })
    }

    /// Serialize signature to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Create from inner slh_dsa Signature
    fn from_inner(inner: slh_dsa::Signature<Shake128f>) -> Self {
        let bytes = inner.to_bytes().to_vec();
        Self { inner, bytes }
    }
}

impl Signature for SlhDsaSignature {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// SLH-DSA public key wrapper
#[derive(Clone, Debug)]
pub struct SlhDsaPublicKey {
    inner: slh_dsa::VerifyingKey<Shake128f>,
}

impl PartialEq for SlhDsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.to_bytes() == other.inner.to_bytes()
    }
}

impl Eq for SlhDsaPublicKey {}

impl VerifyKey for SlhDsaPublicKey {
    type Signature = SlhDsaSignature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<(), CryptoError> {
        self.inner
            .verify(message, &signature.inner)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != SLH_DSA_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: SLH_DSA_PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        // slh_dsa::VerifyingKey implements TryFrom<&[u8]>
        let inner = slh_dsa::VerifyingKey::<Shake128f>::try_from(bytes)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { inner })
    }
}

/// SLH-DSA secret key wrapper
#[derive(Clone)]
pub struct SlhDsaSecretKey {
    inner: slh_dsa::SigningKey<Shake128f>,
}

impl core::fmt::Debug for SlhDsaSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SlhDsaSecretKey").finish_non_exhaustive()
    }
}

impl PartialEq for SlhDsaSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.to_bytes() == other.inner.to_bytes()
    }
}

impl Eq for SlhDsaSecretKey {}

impl SigningKey for SlhDsaSecretKey {
    type VerifyKey = SlhDsaPublicKey;
    type Signature = SlhDsaSignature;

    fn generate_deterministic(seed: &[u8]) -> Self {
        // Use our SHA-256 based deterministic RNG compatible with slh-dsa's rand_core
        let mut rng = SlhCompatibleRng::from_seed(seed);
        let inner = slh_dsa::SigningKey::<Shake128f>::new(&mut rng);
        Self { inner }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        // Use deterministic signing (no additional randomness)
        let inner = self.inner.sign(message);
        SlhDsaSignature::from_inner(inner)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != SLH_DSA_SECRET_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: SLH_DSA_SECRET_KEY_LEN,
                actual: bytes.len(),
            });
        }
        // slh_dsa::SigningKey implements TryFrom<&[u8]>
        let inner = slh_dsa::SigningKey::<Shake128f>::try_from(bytes)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { inner })
    }

    fn verify_key(&self) -> Self::VerifyKey {
        SlhDsaPublicKey {
            inner: self.inner.verifying_key().clone(),
        }
    }
}
