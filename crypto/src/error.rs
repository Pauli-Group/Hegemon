#[cfg(feature = "std")]
use thiserror::Error;

use alloc::string::String;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum CryptoError {
    #[cfg_attr(
        feature = "std",
        error("invalid length: expected {expected} bytes, found {actual}")
    )]
    InvalidLength { expected: usize, actual: usize },

    #[cfg_attr(feature = "std", error("verification failed"))]
    VerificationFailed,

    #[cfg_attr(feature = "std", error("decapsulation failed"))]
    DecapsulationFailed,

    #[cfg_attr(feature = "std", error("invalid key"))]
    InvalidKey,

    #[cfg_attr(feature = "std", error("invalid signature"))]
    InvalidSignature,

    #[cfg_attr(feature = "std", error("encryption failed"))]
    EncryptionFailed,

    #[cfg_attr(feature = "std", error("decryption failed: {0}"))]
    DecryptionFailed(String),
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid length: expected {} bytes, found {}",
                    expected, actual
                )
            }
            CryptoError::VerificationFailed => write!(f, "verification failed"),
            CryptoError::DecapsulationFailed => write!(f, "decapsulation failed"),
            CryptoError::InvalidKey => write!(f, "invalid key"),
            CryptoError::InvalidSignature => write!(f, "invalid signature"),
            CryptoError::EncryptionFailed => write!(f, "encryption failed"),
            CryptoError::DecryptionFailed(msg) => write!(f, "decryption failed: {}", msg),
        }
    }
}
