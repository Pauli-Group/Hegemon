use alloc::vec::Vec;
use crate::error::CryptoError;

pub trait Signature: Sized + Clone {
    fn as_bytes(&self) -> &[u8];
    fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

pub trait SigningKey: Sized {
    type VerifyKey: VerifyKey<Signature = Self::Signature>;
    type Signature: Signature;

    fn generate_deterministic(seed: &[u8]) -> Self;
    fn sign(&self, message: &[u8]) -> Self::Signature;
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>;
    fn verify_key(&self) -> Self::VerifyKey;
}

pub trait VerifyKey: Sized + Clone {
    type Signature: Signature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<(), CryptoError>;
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>;
}

pub trait KemPublicKey: Sized + Clone {
    type Ciphertext: Sized + Clone;
    type SharedSecret: Sized + Clone;

    fn encapsulate(&self, seed: &[u8]) -> (Self::Ciphertext, Self::SharedSecret);
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>;
}

pub trait KemKeyPair: Sized {
    type PublicKey: KemPublicKey<Ciphertext = Self::Ciphertext, SharedSecret = Self::SharedSecret>;
    type Ciphertext: Sized + Clone;
    type SharedSecret: Sized + Clone;

    fn generate_deterministic(seed: &[u8]) -> Self;
    fn encapsulate(&self, seed: &[u8]) -> (Self::Ciphertext, Self::SharedSecret);
    fn decapsulate(&self, ciphertext: &Self::Ciphertext)
        -> Result<Self::SharedSecret, CryptoError>;
    fn public_key(&self) -> Self::PublicKey;
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>;
}
