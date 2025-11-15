use crate::deterministic::{expand_to_length, DeterministicRng};
use crate::error::CryptoError;
use crate::traits::{KemKeyPair, KemPublicKey};

pub const ML_KEM_PUBLIC_KEY_LEN: usize = 1184;
pub const ML_KEM_SECRET_KEY_LEN: usize = 2400;
pub const ML_KEM_CIPHERTEXT_LEN: usize = 1088;
pub const ML_KEM_SHARED_SECRET_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemCiphertext {
    bytes: [u8; ML_KEM_CIPHERTEXT_LEN],
}

impl MlKemCiphertext {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_KEM_CIPHERTEXT_LEN {
            return Err(CryptoError::InvalidLength {
                expected: ML_KEM_CIPHERTEXT_LEN,
                found: bytes.len(),
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemSharedSecret {
    bytes: [u8; ML_KEM_SHARED_SECRET_LEN],
}

impl MlKemSharedSecret {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_KEM_SHARED_SECRET_LEN {
            return Err(CryptoError::InvalidLength {
                expected: ML_KEM_SHARED_SECRET_LEN,
                found: bytes.len(),
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemPublicKey {
    bytes: [u8; ML_KEM_PUBLIC_KEY_LEN],
}

impl MlKemPublicKey {
    fn from_secret_bytes(secret: &[u8]) -> Self {
        let derived = expand_to_length(b"ml-kem-pk", secret, ML_KEM_PUBLIC_KEY_LEN);
        let mut bytes = [0u8; ML_KEM_PUBLIC_KEY_LEN];
        bytes.copy_from_slice(&derived);
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl KemPublicKey for MlKemPublicKey {
    type Ciphertext = MlKemCiphertext;
    type SharedSecret = MlKemSharedSecret;

    fn encapsulate(&self, seed: &[u8]) -> (Self::Ciphertext, Self::SharedSecret) {
        let seed_material = [self.bytes.as_slice(), seed].concat();
        let ct = expand_to_length(b"ml-kem-ct", &seed_material, ML_KEM_CIPHERTEXT_LEN);
        let ss = expand_to_length(
            b"ml-kem-ss",
            &[self.bytes.as_slice(), ct.as_slice()].concat(),
            ML_KEM_SHARED_SECRET_LEN,
        );
        let ciphertext = MlKemCiphertext::from_bytes(&ct).expect("length checked");
        let shared_secret = MlKemSharedSecret::from_bytes(&ss).expect("length checked");
        (ciphertext, shared_secret)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_KEM_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: ML_KEM_PUBLIC_KEY_LEN,
                found: bytes.len(),
            });
        }
        let mut arr = [0u8; ML_KEM_PUBLIC_KEY_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemSecretKey {
    bytes: [u8; ML_KEM_SECRET_KEY_LEN],
    public: MlKemPublicKey,
}

impl MlKemSecretKey {
    fn new(bytes: [u8; ML_KEM_SECRET_KEY_LEN]) -> Self {
        let public = MlKemPublicKey::from_secret_bytes(&bytes);
        Self { bytes, public }
    }

    pub fn public_key(&self) -> &MlKemPublicKey {
        &self.public
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_KEM_SECRET_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: ML_KEM_SECRET_KEY_LEN,
                found: bytes.len(),
            });
        }
        let mut arr = [0u8; ML_KEM_SECRET_KEY_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self::new(arr))
    }

    fn decapsulate(&self, ciphertext: &MlKemCiphertext) -> MlKemSharedSecret {
        let ss = expand_to_length(
            b"ml-kem-ss",
            &[self.public.bytes.as_slice(), ciphertext.as_bytes()].concat(),
            ML_KEM_SHARED_SECRET_LEN,
        );
        MlKemSharedSecret::from_bytes(&ss).expect("length checked")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemKeyPair {
    secret: MlKemSecretKey,
}

const ML_KEM_KEYPAIR_BYTES: usize = ML_KEM_SECRET_KEY_LEN + ML_KEM_PUBLIC_KEY_LEN;

impl MlKemKeyPair {
    pub fn secret_key(&self) -> &MlKemSecretKey {
        &self.secret
    }
}

impl KemKeyPair for MlKemKeyPair {
    type PublicKey = MlKemPublicKey;
    type Ciphertext = MlKemCiphertext;
    type SharedSecret = MlKemSharedSecret;

    fn generate_deterministic(seed: &[u8]) -> Self {
        let mut rng = DeterministicRng::from_seed(seed);
        let mut secret_bytes = [0u8; ML_KEM_SECRET_KEY_LEN];
        rng.fill_bytes(&mut secret_bytes);
        let secret = MlKemSecretKey::new(secret_bytes);
        Self { secret }
    }

    fn encapsulate(&self, seed: &[u8]) -> (Self::Ciphertext, Self::SharedSecret) {
        self.secret.public.encapsulate(seed)
    }

    fn decapsulate(
        &self,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, CryptoError> {
        Ok(self.secret.decapsulate(ciphertext))
    }

    fn public_key(&self) -> Self::PublicKey {
        self.secret.public.clone()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ML_KEM_KEYPAIR_BYTES);
        out.extend_from_slice(&self.secret.bytes);
        out.extend_from_slice(&self.secret.public.bytes);
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_KEM_KEYPAIR_BYTES {
            return Err(CryptoError::InvalidLength {
                expected: ML_KEM_KEYPAIR_BYTES,
                found: bytes.len(),
            });
        }
        let (sk_bytes, pk_bytes) = bytes.split_at(ML_KEM_SECRET_KEY_LEN);
        let mut secret_array = [0u8; ML_KEM_SECRET_KEY_LEN];
        secret_array.copy_from_slice(sk_bytes);
        let mut public_array = [0u8; ML_KEM_PUBLIC_KEY_LEN];
        public_array.copy_from_slice(pk_bytes);
        let public = MlKemPublicKey {
            bytes: public_array,
        };
        let secret = MlKemSecretKey {
            bytes: secret_array,
            public,
        };
        Ok(Self { secret })
    }
}
