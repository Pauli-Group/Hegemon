//! Substrate Network Integration with PQ Transport
//!
//! This module provides integration between the pq-noise transport layer
//! and Substrate's sc-network for post-quantum secure peer connections.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                  Substrate Network Layer                        │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────────────────────────────────────────────────┐│
//! │  │                   sc-network                                ││
//! │  │  ┌─────────────────┐   ┌──────────────────────────────────┐ ││
//! │  │  │   Protocols     │   │     Notification Protocols       │ ││
//! │  │  │  - sync         │   │  - /hegemon/block-announces/1    │ ││
//! │  │  │  - transactions │   │  - /hegemon/transactions/1       │ ││
//! │  │  └─────────────────┘   └──────────────────────────────────┘ ││
//! │  └─────────────────────────────────────────────────────────────┘│
//! │                            │                                    │
//! │  ┌─────────────────────────▼─────────────────────────────────┐  │
//! │  │                   PQ Transport Layer                       │  │
//! │  │  ┌──────────────────────────────────────────────────────┐ │  │
//! │  │  │              Hybrid Handshake                         │ │  │
//! │  │  │  X25519 ECDH + ML-KEM-768 Encapsulation              │ │  │
//! │  │  │  ML-DSA-65 Signature Authentication                  │ │  │
//! │  │  └──────────────────────────────────────────────────────┘ │  │
//! │  │  ┌──────────────────────────────────────────────────────┐ │  │
//! │  │  │              Encrypted Session                        │ │  │
//! │  │  │  AES-256-GCM with hybrid-derived keys                │ │  │
//! │  │  └──────────────────────────────────────────────────────┘ │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! │                            │                                    │
//! │  ┌─────────────────────────▼─────────────────────────────────┐  │
//! │  │                   TCP Transport                            │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Phase 3 Status
//!
//! This module implements PQ libp2p integration:
//! - PqNetworkConfig: Configuration for PQ-secure networking
//! - Protocol definitions for Substrate integration
//! - Notification handlers for block and transaction gossip
//!
//! Full sc-network integration requires aligned Polkadot SDK dependencies.

use std::time::Duration;
use crypto::ml_kem::MlKemKeyPair;
use crypto::ml_dsa::MlDsaSecretKey;
use crypto::traits::{KemKeyPair, KemPublicKey, SigningKey, VerifyKey, Signature};

/// Network protocol identifiers for Hegemon
pub mod protocols {
    /// Block announcement protocol
    pub const BLOCK_ANNOUNCES: &str = "/hegemon/block-announces/1";
    /// Transaction propagation protocol  
    pub const TRANSACTIONS: &str = "/hegemon/transactions/1";
    /// PQ handshake negotiation protocol
    pub const PQ_HANDSHAKE: &str = "/hegemon/pq-handshake/1";
    /// Sync protocol
    pub const SYNC: &str = "/hegemon/sync/1";
}

/// Configuration for PQ-secure Substrate networking
#[derive(Clone, Debug)]
pub struct PqNetworkConfig {
    /// Listen addresses (multiaddrs)
    pub listen_addresses: Vec<String>,
    /// Bootstrap nodes (multiaddrs)
    pub bootstrap_nodes: Vec<String>,
    /// Whether PQ transport is enabled
    pub enable_pq_transport: bool,
    /// Whether to use hybrid mode (X25519 + ML-KEM)
    pub hybrid_mode: bool,
    /// Maximum peers
    pub max_peers: u32,
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    /// Whether to require PQ handshake for all peers
    pub require_pq: bool,
    /// Enable verbose handshake logging
    pub verbose_logging: bool,
}

impl Default for PqNetworkConfig {
    fn default() -> Self {
        Self {
            listen_addresses: vec!["/ip4/0.0.0.0/tcp/30333".to_string()],
            bootstrap_nodes: Vec::new(),
            enable_pq_transport: true,
            hybrid_mode: true,
            max_peers: 50,
            connection_timeout_secs: 30,
            require_pq: true,
            verbose_logging: false,
        }
    }
}

impl PqNetworkConfig {
    /// Create a development configuration
    pub fn development() -> Self {
        Self {
            listen_addresses: vec!["/ip4/127.0.0.1/tcp/30333".to_string()],
            bootstrap_nodes: Vec::new(),
            enable_pq_transport: true,
            hybrid_mode: true,
            max_peers: 25,
            connection_timeout_secs: 30,
            require_pq: false,
            verbose_logging: true,
        }
    }

    /// Create a testnet configuration
    pub fn testnet() -> Self {
        Self {
            listen_addresses: vec!["/ip4/0.0.0.0/tcp/30333".to_string()],
            bootstrap_nodes: Vec::new(),
            enable_pq_transport: true,
            hybrid_mode: true,
            max_peers: 50,
            connection_timeout_secs: 30,
            require_pq: true,
            verbose_logging: false,
        }
    }

    /// Create a mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            listen_addresses: vec!["/ip4/0.0.0.0/tcp/30333".to_string()],
            bootstrap_nodes: Vec::new(),
            enable_pq_transport: true,
            hybrid_mode: true,
            max_peers: 100,
            connection_timeout_secs: 60,
            require_pq: true,
            verbose_logging: false,
        }
    }

    /// Add bootstrap nodes
    pub fn with_bootstrap_nodes(mut self, nodes: Vec<String>) -> Self {
        self.bootstrap_nodes = nodes;
        self
    }

    /// Set maximum peers
    pub fn with_max_peers(mut self, max_peers: u32) -> Self {
        self.max_peers = max_peers;
        self
    }

    /// Set listen addresses
    pub fn with_listen_addresses(mut self, addresses: Vec<String>) -> Self {
        self.listen_addresses = addresses;
        self
    }

    /// Get handshake timeout duration
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.connection_timeout_secs)
    }
}

/// PQ-secure network keypair
/// 
/// Contains the cryptographic material for PQ-secure peer communication:
/// - ML-KEM-768 keypair for post-quantum key encapsulation
/// - ML-DSA-65 keypair for post-quantum signatures
/// - Derived peer ID for node identification
pub struct PqNetworkKeypair {
    /// ML-KEM-768 keypair
    kem_keypair: MlKemKeyPair,
    /// ML-DSA-65 signing key
    dsa_signing_key: MlDsaSecretKey,
    /// Peer ID derived from public keys
    peer_id_bytes: [u8; 32],
}

impl PqNetworkKeypair {
    /// Generate a new keypair using the given seed
    pub fn generate() -> Result<Self, String> {
        use sha2::{Sha256, Digest};
        use rand::RngCore;
        
        // Generate random seed
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        
        Self::from_seed(&seed)
    }

    /// Generate a keypair from a seed (deterministic)
    pub fn from_seed(seed: &[u8]) -> Result<Self, String> {
        use sha2::{Sha256, Digest};
        
        // Derive key material from seed
        let mut kem_seed_hasher = Sha256::new();
        kem_seed_hasher.update(b"hegemon-kem");
        kem_seed_hasher.update(seed);
        let kem_seed: [u8; 32] = kem_seed_hasher.finalize().into();
        
        let mut dsa_seed_hasher = Sha256::new();
        dsa_seed_hasher.update(b"hegemon-dsa");
        dsa_seed_hasher.update(seed);
        let dsa_seed: [u8; 32] = dsa_seed_hasher.finalize().into();
        
        // Generate ML-KEM-768 keypair from seed
        let kem_keypair = MlKemKeyPair::generate_deterministic(&kem_seed);
        
        // Generate ML-DSA-65 signing key from seed
        let dsa_signing_key = MlDsaSecretKey::generate_deterministic(&dsa_seed);
        
        // Derive peer ID from public keys
        let kem_pk = kem_keypair.public_key();
        let dsa_pk = dsa_signing_key.verify_key();
        
        let mut hasher = Sha256::new();
        hasher.update(&kem_pk.to_bytes());
        hasher.update(&dsa_pk.to_bytes());
        let peer_id_bytes: [u8; 32] = hasher.finalize().into();
        
        Ok(Self {
            kem_keypair,
            dsa_signing_key,
            peer_id_bytes,
        })
    }

    /// Get the peer ID as bytes
    pub fn peer_id_bytes(&self) -> &[u8; 32] {
        &self.peer_id_bytes
    }
    
    /// Get the peer ID as a hex string
    pub fn peer_id(&self) -> String {
        hex::encode(self.peer_id_bytes)
    }

    /// Get the ML-KEM public key bytes
    pub fn kem_public_key(&self) -> Vec<u8> {
        self.kem_keypair.public_key().to_bytes()
    }

    /// Get the ML-DSA public key bytes
    pub fn dsa_public_key(&self) -> Vec<u8> {
        self.dsa_signing_key.verify_key().to_bytes()
    }

    /// Sign a message with ML-DSA-65
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.dsa_signing_key.sign(message).to_vec()
    }

    /// Decapsulate a ciphertext to recover the shared secret
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        use crypto::ml_kem::MlKemCiphertext;
        
        let ct = MlKemCiphertext::from_bytes(ciphertext)
            .map_err(|e| format!("Invalid ciphertext: {:?}", e))?;
        
        let shared_secret = self.kem_keypair.decapsulate(&ct)
            .map_err(|e| format!("Decapsulation failed: {:?}", e))?;
        
        Ok(shared_secret.as_bytes().to_vec())
    }

    /// Get a reference to the KEM keypair
    pub fn kem_keypair(&self) -> &MlKemKeyPair {
        &self.kem_keypair
    }
}

/// Notification protocol configuration
#[derive(Clone, Debug)]
pub struct NotificationConfig {
    /// Protocol name
    pub name: String,
    /// Fallback names for compatibility
    pub fallback_names: Vec<String>,
    /// Maximum notification size in bytes
    pub max_size: u64,
    /// Handshake message (optional)
    pub handshake: Option<Vec<u8>>,
}

impl NotificationConfig {
    /// Create configuration for block announcements
    pub fn block_announces() -> Self {
        Self {
            name: protocols::BLOCK_ANNOUNCES.to_string(),
            fallback_names: Vec::new(),
            max_size: 1024 * 1024, // 1 MB
            handshake: None,
        }
    }

    /// Create configuration for transactions
    pub fn transactions() -> Self {
        Self {
            name: protocols::TRANSACTIONS.to_string(),
            fallback_names: Vec::new(),
            max_size: 16 * 1024 * 1024, // 16 MB
            handshake: None,
        }
    }
}

/// Build notification protocol configurations for Hegemon
pub fn build_notification_protocols() -> Vec<NotificationConfig> {
    vec![
        NotificationConfig::block_announces(),
        NotificationConfig::transactions(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_network_config() {
        let dev = PqNetworkConfig::development();
        assert!(!dev.require_pq);
        assert!(dev.verbose_logging);

        let testnet = PqNetworkConfig::testnet();
        assert!(testnet.require_pq);
        assert!(!testnet.verbose_logging);

        let mainnet = PqNetworkConfig::mainnet();
        assert!(mainnet.require_pq);
        assert_eq!(mainnet.max_peers, 100);
    }

    #[test]
    fn test_pq_network_keypair() {
        let keypair = PqNetworkKeypair::from_seed(b"test-seed").unwrap();
        
        // Peer ID should be deterministic
        let keypair2 = PqNetworkKeypair::from_seed(b"test-seed").unwrap();
        assert_eq!(keypair.peer_id_bytes, keypair2.peer_id_bytes);
        
        // Different seed should produce different peer ID
        let keypair3 = PqNetworkKeypair::from_seed(b"different-seed").unwrap();
        assert_ne!(keypair.peer_id_bytes, keypair3.peer_id_bytes);
    }

    #[test]
    fn test_keypair_operations() {
        let keypair = PqNetworkKeypair::from_seed(b"test-seed-123").unwrap();
        
        // Test signing
        let message = b"test message";
        let signature = keypair.sign(message);
        assert!(!signature.is_empty());
        
        // Test peer ID format
        let peer_id = keypair.peer_id();
        assert_eq!(peer_id.len(), 64); // 32 bytes as hex
    }

    #[test]
    fn test_notification_configs() {
        let configs = build_notification_protocols();
        assert_eq!(configs.len(), 2);
        
        let block_config = &configs[0];
        assert_eq!(block_config.name, protocols::BLOCK_ANNOUNCES);
        
        let tx_config = &configs[1];
        assert_eq!(tx_config.name, protocols::TRANSACTIONS);
    }
}
