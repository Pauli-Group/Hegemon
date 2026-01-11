//! Post-Quantum Noise Protocol Extension
//!
//! This crate implements a post-quantum key exchange protocol using:
//! - ML-KEM-768 encapsulation (FIPS 203, lattice-based)
//!
//! # Security Properties
//!
//! ML-KEM provides IND-CCA2 security against quantum adversaries.
//! All key exchange is based on lattice problems (Module-LWE).
//!
//! # Protocol Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     PQ Handshake                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │  1. ML-KEM-768 Encaps  │  PQ key encapsulation              │
//! │  2. Shared Secret      │  HKDF(mlkem_ss)                    │
//! │  3. ML-DSA-65 Sign     │  Authenticate peer identity        │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use pq_noise::{PqNoiseConfig, PqHandshake};
//!
//! // Create configuration
//! let config = PqNoiseConfig::new(identity_keypair);
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
