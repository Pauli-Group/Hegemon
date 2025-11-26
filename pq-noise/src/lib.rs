//! Post-Quantum Noise Protocol Extension
//!
//! This crate implements a hybrid key exchange protocol combining:
//! - Classical X25519 ECDH (for immediate security)
//! - ML-KEM-768 encapsulation (for post-quantum security)
//!
//! # Security Properties
//!
//! The hybrid approach ensures:
//! 1. If X25519 is broken but ML-KEM is secure → connection remains secure
//! 2. If ML-KEM is broken but X25519 is secure → connection remains secure
//! 3. Both must be broken simultaneously to compromise security
//!
//! # Protocol Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Hybrid Handshake                        │
//! ├─────────────────────────────────────────────────────────────┤
//! │  1. X25519 ECDH        │  Classical fallback (always run)  │
//! │  2. ML-KEM-768 Encaps  │  PQ encapsulation (if supported)  │
//! │  3. Combined Key       │  HKDF(x25519_ss || mlkem_ss)      │
//! │  4. ML-DSA-65 Sign     │  Authenticate peer identity       │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use pq_noise::{PqNoiseConfig, PqHandshake};
//!
//! // Create configuration
//! let config = PqNoiseConfig::new(identity_keypair, true);
//!
//! // Perform handshake (initiator side)
//! let (session, peer_id) = PqHandshake::initiator(&config, stream).await?;
//!
//! // Use session for encrypted communication
//! session.send(b"Hello, quantum world!").await?;
//! ```

pub mod config;
pub mod error;
pub mod handshake;
pub mod noise;
pub mod session;
pub mod transport;
pub mod types;

pub use config::PqNoiseConfig;
pub use error::PqNoiseError;
pub use handshake::PqHandshake;
pub use session::SecureSession;
pub use transport::PqTransport;
pub use types::{HandshakeMessage, PeerId, SessionKeys};
