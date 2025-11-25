//! Type definitions for the PQ Noise protocol

use crypto::ml_dsa::{MlDsaPublicKey, MlDsaSecretKey};
use crypto::ml_kem::{MlKemKeyPair, MlKemPublicKey};
use serde::{Deserialize, Serialize};

/// Peer identifier derived from the ML-DSA-65 public key
pub type PeerId = [u8; 32];

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: u8 = 1;

/// Protocol identifier string
pub const PROTOCOL_ID: &str = "/hegemon/pq-noise/1.0.0";

/// Handshake message types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HandshakeMessage {
    /// Initiator's first message
    /// Contains X25519 ephemeral public key and optionally ML-KEM public key
    InitHello(InitHelloMessage),

    /// Responder's reply
    /// Contains X25519 ephemeral, ML-KEM public key, ciphertext, and signature
    RespHello(RespHelloMessage),

    /// Final confirmation from initiator
    /// Contains ciphertext to responder and signature
    Finish(FinishMessage),
}

/// Initiator's hello message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitHelloMessage {
    /// Protocol version
    pub version: u8,
    /// X25519 ephemeral public key (32 bytes)
    pub x25519_ephemeral: [u8; 32],
    /// Initiator's ML-KEM-768 public key (1184 bytes)
    pub mlkem_public_key: Vec<u8>,
    /// Initiator's identity public key (ML-DSA-65)
    pub identity_key: Vec<u8>,
    /// Nonce for replay protection
    pub nonce: u64,
    /// Signature over the message (ML-DSA-65)
    pub signature: Vec<u8>,
}

/// Responder's hello message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RespHelloMessage {
    /// Protocol version
    pub version: u8,
    /// X25519 ephemeral public key (32 bytes)
    pub x25519_ephemeral: [u8; 32],
    /// Responder's ML-KEM-768 public key (1184 bytes)
    pub mlkem_public_key: Vec<u8>,
    /// ML-KEM ciphertext encapsulated to initiator's public key (1088 bytes)
    pub mlkem_ciphertext: Vec<u8>,
    /// Responder's identity public key (ML-DSA-65)
    pub identity_key: Vec<u8>,
    /// Nonce for replay protection
    pub nonce: u64,
    /// Signature over the message (ML-DSA-65)
    pub signature: Vec<u8>,
}

/// Initiator's finish message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinishMessage {
    /// ML-KEM ciphertext encapsulated to responder's public key (1088 bytes)
    pub mlkem_ciphertext: Vec<u8>,
    /// Nonce for replay protection
    pub nonce: u64,
    /// Signature over the message (ML-DSA-65)
    pub signature: Vec<u8>,
}

impl HandshakeMessage {
    /// Get the message type name for debugging
    pub fn message_type(&self) -> &'static str {
        match self {
            HandshakeMessage::InitHello(_) => "InitHello",
            HandshakeMessage::RespHello(_) => "RespHello",
            HandshakeMessage::Finish(_) => "Finish",
        }
    }
}

/// Session keys derived from the handshake
#[derive(Clone)]
pub struct SessionKeys {
    /// Key for initiator → responder encryption
    pub initiator_to_responder: [u8; 32],
    /// Key for responder → initiator encryption
    pub responder_to_initiator: [u8; 32],
    /// Additional authenticated data for the session
    pub session_aad: [u8; 32],
}

impl SessionKeys {
    /// Create session keys from the combined key material
    pub fn derive(
        transcript: &[u8],
        x25519_shared: &[u8; 32],
        mlkem_shared_1: &[u8; 32],
        mlkem_shared_2: &[u8; 32],
    ) -> Self {
        use hkdf::Hkdf;
        use sha2::Sha256;

        // Combine all shared secrets
        let mut combined = Vec::with_capacity(32 * 3);
        combined.extend_from_slice(x25519_shared);
        combined.extend_from_slice(mlkem_shared_1);
        combined.extend_from_slice(mlkem_shared_2);

        // Derive keys using HKDF
        let hk = Hkdf::<Sha256>::new(Some(transcript), &combined);

        let mut initiator_to_responder = [0u8; 32];
        let mut responder_to_initiator = [0u8; 32];
        let mut session_aad = [0u8; 32];

        hk.expand(b"hegemon-pq-noise-v1-i2r", &mut initiator_to_responder)
            .expect("valid length");
        hk.expand(b"hegemon-pq-noise-v1-r2i", &mut responder_to_initiator)
            .expect("valid length");
        hk.expand(b"hegemon-pq-noise-v1-aad", &mut session_aad)
            .expect("valid length");

        Self {
            initiator_to_responder,
            responder_to_initiator,
            session_aad,
        }
    }
}

/// Local identity for a node participating in the PQ Noise protocol
#[derive(Clone)]
pub struct LocalIdentity {
    /// ML-DSA-65 signing key
    pub signing_key: MlDsaSecretKey,
    /// ML-DSA-65 verification key
    pub verify_key: MlDsaPublicKey,
    /// ML-KEM-768 key pair for encapsulation
    pub kem_keypair: MlKemKeyPair,
}

impl LocalIdentity {
    /// Generate a new identity from a seed
    pub fn generate(seed: &[u8]) -> Self {
        use crypto::hashes::sha256;
        use crypto::traits::{KemKeyPair, SigningKey};

        // Derive signing key
        let signing_key = MlDsaSecretKey::generate_deterministic(seed);
        let verify_key = signing_key.verify_key();

        // Derive KEM key pair
        let kem_seed = sha256(&[seed, b"kem"].concat());
        let kem_keypair = MlKemKeyPair::generate_deterministic(&kem_seed);

        Self {
            signing_key,
            verify_key,
            kem_keypair,
        }
    }

    /// Get the peer ID for this identity
    pub fn peer_id(&self) -> PeerId {
        use crypto::hashes::sha256;
        use crypto::traits::VerifyKey;
        sha256(&self.verify_key.to_bytes())
    }
}

/// Remote peer information learned during handshake
#[derive(Clone, Debug)]
pub struct RemotePeer {
    /// Peer's identity public key
    pub identity_key: MlDsaPublicKey,
    /// Peer's KEM public key
    pub kem_public_key: MlKemPublicKey,
    /// Derived peer ID
    pub peer_id: PeerId,
}

impl RemotePeer {
    /// Create from handshake message data
    pub fn from_handshake(identity_bytes: &[u8], kem_bytes: &[u8]) -> crate::error::Result<Self> {
        use crypto::hashes::sha256;
        use crypto::traits::{KemPublicKey, VerifyKey};

        let identity_key = MlDsaPublicKey::from_bytes(identity_bytes)?;
        let kem_public_key = MlKemPublicKey::from_bytes(kem_bytes)?;
        let peer_id = sha256(&identity_key.to_bytes());

        Ok(Self {
            identity_key,
            kem_public_key,
            peer_id,
        })
    }
}
