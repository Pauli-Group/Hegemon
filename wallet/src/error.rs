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

    #[error("nullifier already spent: note at index {note_index} was already consumed on-chain")]
    NullifierSpent { note_index: usize },

    #[error("too many inputs required: need {needed} notes but max is {max}. Use --auto-consolidate to merge notes first.")]
    TooManyInputs { needed: usize, max: usize },
}

impl WalletError {
    /// Returns a user-friendly message for display
    pub fn user_message(&self) -> String {
        match self {
            Self::NullifierSpent { note_index } => {
                format!("Note #{} was already spent on-chain", note_index)
            }
            Self::InsufficientFunds { needed, available } => {
                format!(
                    "Insufficient funds: have {} HGM, need {} HGM",
                    *available as f64 / 100_000_000.0,
                    *needed as f64 / 100_000_000.0
                )
            }
            Self::TooManyInputs { needed, max } => {
                format!(
                    "Need {} notes but max is {} per transaction",
                    needed, max
                )
            }
            Self::ChainMismatch { .. } => {
                "Wallet was synced to a different chain (genesis hash mismatch)".to_string()
            }
            _ => self.to_string(),
        }
    }

    /// Returns a suggested action for the user
    pub fn suggested_action(&self) -> Option<String> {
        match self {
            Self::NullifierSpent { .. } => Some(
                "Run: wallet substrate-sync --force-rescan to resync wallet state".to_string(),
            ),
            Self::ChainMismatch { .. } => Some(
                "Run: wallet substrate-sync --force-rescan to reset wallet for new chain".to_string(),
            ),
            Self::TooManyInputs { .. } => {
                Some("Add --auto-consolidate flag to automatically merge notes first".to_string())
            }
            _ => None,
        }
    }
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
