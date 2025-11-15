use crate::deterministic::{expand_to_length, DeterministicRng};
use crate::error::CryptoError;
use crate::traits::{Signature, SigningKey, VerifyKey};

pub const ML_DSA_PUBLIC_KEY_LEN: usize = 1952;
pub const ML_DSA_SECRET_KEY_LEN: usize = 4000;
pub const ML_DSA_SIGNATURE_LEN: usize = 3293;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaSignature {
    bytes: [u8; ML_DSA_SIGNATURE_LEN],
}

impl MlDsaSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_DSA_SIGNATURE_LEN {
            return Err(CryptoError::InvalidLength {
                expected: ML_DSA_SIGNATURE_LEN,
                found: bytes.len(),
            });
        }
        let mut arr = [0u8; ML_DSA_SIGNATURE_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    pub fn to_bytes(&self) -> [u8; ML_DSA_SIGNATURE_LEN] {
        self.bytes
    }
}

impl Signature for MlDsaSignature {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaPublicKey {
    bytes: [u8; ML_DSA_PUBLIC_KEY_LEN],
}

impl MlDsaPublicKey {
    fn from_secret_bytes(secret: &[u8]) -> Self {
        let derived = expand_to_length(b"ml-dsa-pk", secret, ML_DSA_PUBLIC_KEY_LEN);
        let mut bytes = [0u8; ML_DSA_PUBLIC_KEY_LEN];
        bytes.copy_from_slice(&derived);
        Self { bytes }
    }
}

impl VerifyKey for MlDsaPublicKey {
    type Signature = MlDsaSignature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<(), CryptoError> {
        let expected = expand_to_length(
            b"ml-dsa-signature",
            &[self.bytes.as_slice(), message].concat(),
            ML_DSA_SIGNATURE_LEN,
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
        if bytes.len() != ML_DSA_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: ML_DSA_PUBLIC_KEY_LEN,
                found: bytes.len(),
            });
        }
        let mut arr = [0u8; ML_DSA_PUBLIC_KEY_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaSecretKey {
    bytes: [u8; ML_DSA_SECRET_KEY_LEN],
}

impl MlDsaSecretKey {
    fn new(bytes: [u8; ML_DSA_SECRET_KEY_LEN]) -> Self {
        Self { bytes }
    }
}

impl SigningKey for MlDsaSecretKey {
    type VerifyKey = MlDsaPublicKey;
    type Signature = MlDsaSignature;

    fn generate_deterministic(seed: &[u8]) -> Self {
        let mut rng = DeterministicRng::from_seed(seed);
        let mut bytes = [0u8; ML_DSA_SECRET_KEY_LEN];
        rng.fill_bytes(&mut bytes);
        Self::new(bytes)
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let pk = self.verify_key();
        let derived = expand_to_length(
            b"ml-dsa-signature",
            &[pk.bytes.as_slice(), message].concat(),
            ML_DSA_SIGNATURE_LEN,
        );
        MlDsaSignature::from_bytes(&derived).expect("length checked")
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_DSA_SECRET_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: ML_DSA_SECRET_KEY_LEN,
                found: bytes.len(),
            });
        }
        let mut arr = [0u8; ML_DSA_SECRET_KEY_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self::new(arr))
    }

    fn verify_key(&self) -> Self::VerifyKey {
        MlDsaPublicKey::from_secret_bytes(&self.bytes)
    }
}
