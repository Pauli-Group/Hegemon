use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid length: expected {expected} bytes, found {found}")]
    InvalidLength { expected: usize, found: usize },

    #[error("verification failed")]
    VerificationFailed,

    #[error("decapsulation failed")]
    DecapsulationFailed,
}
