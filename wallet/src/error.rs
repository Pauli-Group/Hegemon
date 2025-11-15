use thiserror::Error;

use synthetic_crypto::CryptoError;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("invalid address encoding: {0}")]
    AddressEncoding(String),

    #[error("unknown diversifier index {0}")]
    UnknownDiversifier(u32),

    #[error("cryptography error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("encryption failure")]
    EncryptionFailure,

    #[error("decryption failure")]
    DecryptionFailure,

    #[error("mismatched note metadata: {0}")]
    NoteMismatch(&'static str),

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<bincode::Error> for WalletError {
    fn from(err: bincode::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}
