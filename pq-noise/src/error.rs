//! Error types for the PQ Noise protocol

use thiserror::Error;

/// Errors that can occur during PQ Noise protocol operations
#[derive(Debug, Error)]
pub enum PqNoiseError {
    /// Cryptographic operation failed
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),

    /// Handshake protocol error
    #[error("handshake error: {0}")]
    Handshake(HandshakeError),

    /// I/O error during communication
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    /// Encryption/decryption error
    #[error("encryption error: {0}")]
    Encryption(String),

    /// Invalid peer configuration
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// Session error
    #[error("session error: {0}")]
    Session(String),

    /// Timeout during operation
    #[error("operation timed out")]
    Timeout,

    /// Peer rejected during handshake
    #[error("peer rejected: {0}")]
    PeerRejected(String),
}

/// Specific handshake errors
#[derive(Debug, Error)]
pub enum HandshakeError {
    /// Invalid signature from peer
    #[error("invalid signature")]
    InvalidSignature,

    /// Unexpected message type received
    #[error("unexpected message type: expected {expected}, got {got}")]
    UnexpectedMessage {
        expected: &'static str,
        got: &'static str,
    },

    /// Invalid public key
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid ciphertext
    #[error("invalid ciphertext")]
    InvalidCiphertext,

    /// Protocol version mismatch
    #[error("protocol version mismatch: local={local}, remote={remote}")]
    VersionMismatch { local: u8, remote: u8 },

    /// Peer doesn't support PQ
    #[error("peer does not support post-quantum handshake")]
    NoPqSupport,

    /// Connection closed during handshake
    #[error("connection closed during handshake")]
    ConnectionClosed,

    /// Invalid handshake state
    #[error("invalid handshake state")]
    InvalidState,

    /// Key derivation failed
    #[error("key derivation failed")]
    KeyDerivation,
}

impl From<HandshakeError> for PqNoiseError {
    fn from(e: HandshakeError) -> Self {
        PqNoiseError::Handshake(e)
    }
}

/// Result type for PQ Noise operations
pub type Result<T> = std::result::Result<T, PqNoiseError>;
