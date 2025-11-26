#[cfg(feature = "std")]
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum CryptoError {
    #[cfg_attr(feature = "std", error("invalid length: expected {expected} bytes, found {found}"))]
    InvalidLength { expected: usize, found: usize },

    #[cfg_attr(feature = "std", error("verification failed"))]
    VerificationFailed,

    #[cfg_attr(feature = "std", error("decapsulation failed"))]
    DecapsulationFailed,
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::InvalidLength { expected, found } => {
                write!(f, "invalid length: expected {} bytes, found {}", expected, found)
            }
            CryptoError::VerificationFailed => write!(f, "verification failed"),
            CryptoError::DecapsulationFailed => write!(f, "decapsulation failed"),
        }
    }
}
