use crate::deterministic::{expand_to_length, DeterministicRng};
use crate::error::CryptoError;
use crate::traits::{Signature, SigningKey, VerifyKey};

pub const SLH_DSA_PUBLIC_KEY_LEN: usize = 32;
pub const SLH_DSA_SECRET_KEY_LEN: usize = 64;
pub const SLH_DSA_SIGNATURE_LEN: usize = 17088;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlhDsaSignature {
    bytes: Vec<u8>,
}

impl SlhDsaSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != SLH_DSA_SIGNATURE_LEN {
            return Err(CryptoError::InvalidLength {
                expected: SLH_DSA_SIGNATURE_LEN,
                found: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl Signature for SlhDsaSignature {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlhDsaPublicKey {
    bytes: [u8; SLH_DSA_PUBLIC_KEY_LEN],
}

impl SlhDsaPublicKey {
    fn from_secret_bytes(secret: &[u8]) -> Self {
        let derived = expand_to_length(b"slh-dsa-pk", secret, SLH_DSA_PUBLIC_KEY_LEN);
        let mut bytes = [0u8; SLH_DSA_PUBLIC_KEY_LEN];
        bytes.copy_from_slice(&derived);
        Self { bytes }
    }
}

impl VerifyKey for SlhDsaPublicKey {
    type Signature = SlhDsaSignature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<(), CryptoError> {
        let expected = expand_to_length(
            b"slh-dsa-signature",
            &[self.bytes.as_slice(), message].concat(),
            SLH_DSA_SIGNATURE_LEN,
        );
        if expected.as_slice() == signature.as_bytes() {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != SLH_DSA_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: SLH_DSA_PUBLIC_KEY_LEN,
                found: bytes.len(),
            });
        }
        let mut arr = [0u8; SLH_DSA_PUBLIC_KEY_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlhDsaSecretKey {
    bytes: [u8; SLH_DSA_SECRET_KEY_LEN],
}

impl SlhDsaSecretKey {
    fn new(bytes: [u8; SLH_DSA_SECRET_KEY_LEN]) -> Self {
        Self { bytes }
    }
}

impl SigningKey for SlhDsaSecretKey {
    type VerifyKey = SlhDsaPublicKey;
    type Signature = SlhDsaSignature;

    fn generate_deterministic(seed: &[u8]) -> Self {
        let mut rng = DeterministicRng::from_seed(seed);
        let mut bytes = [0u8; SLH_DSA_SECRET_KEY_LEN];
        rng.fill_bytes(&mut bytes);
        Self::new(bytes)
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let pk = self.verify_key();
        let derived = expand_to_length(
            b"slh-dsa-signature",
            &[pk.bytes.as_slice(), message].concat(),
            SLH_DSA_SIGNATURE_LEN,
        );
        SlhDsaSignature::from_bytes(&derived).expect("length checked")
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != SLH_DSA_SECRET_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: SLH_DSA_SECRET_KEY_LEN,
                found: bytes.len(),
            });
        }
        let mut arr = [0u8; SLH_DSA_SECRET_KEY_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self::new(arr))
    }

    fn verify_key(&self) -> Self::VerifyKey {
        SlhDsaPublicKey::from_secret_bytes(&self.bytes)
    }
}
