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

    #[error("http error: {0}")]
    Http(String),

    #[error("rpc error: {0}")]
    Rpc(String),

    #[error("wallet is watch-only")]
    WatchOnly,

    #[error("invalid wallet state: {0}")]
    InvalidState(&'static str),

    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),

    #[error("insufficient funds (needed {needed}, available {available})")]
    InsufficientFunds { needed: u64, available: u64 },

    #[error("chain mismatch: wallet was created for chain {expected}, but connected to {actual}. Use --force-rescan to reset wallet state.")]
    ChainMismatch { expected: String, actual: String },
}

impl From<bincode::Error> for WalletError {
    fn from(err: bincode::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

impl From<reqwest::Error> for WalletError {
    fn from(err: reqwest::Error) -> Self {
        Self::Http(err.to_string())
    }
}

impl From<std::io::Error> for WalletError {
    fn from(err: std::io::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}
