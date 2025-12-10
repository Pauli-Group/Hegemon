//! Configuration for the PQ Noise protocol

use crate::types::LocalIdentity;
use std::time::Duration;

/// Configuration for PQ Noise handshakes
#[derive(Clone)]
pub struct PqNoiseConfig {
    /// Local identity for signing and key exchange
    pub identity: LocalIdentity,

    /// Whether to require post-quantum handshake
    /// If true, reject peers that don't support PQ
    pub require_pq: bool,

    /// Handshake timeout
    pub handshake_timeout: Duration,

    /// Maximum message size during handshake
    pub max_handshake_message_size: usize,

    /// Whether to log detailed handshake information
    pub verbose_logging: bool,
}

impl PqNoiseConfig {
    /// Create a new configuration
    pub fn new(identity: LocalIdentity, require_pq: bool) -> Self {
        Self {
            identity,
            require_pq,
            handshake_timeout: Duration::from_secs(30),
            max_handshake_message_size: 16 * 1024, // 16 KB
            verbose_logging: false,
        }
    }

    /// Create a development configuration (less strict)
    pub fn development(seed: &[u8]) -> Self {
        Self::new(LocalIdentity::generate(seed), false)
    }

    /// Create a production configuration (requires PQ)
    pub fn production(seed: &[u8]) -> Self {
        Self::new(LocalIdentity::generate(seed), true)
    }

    /// Set the handshake timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Enable verbose logging
    pub fn with_verbose_logging(mut self) -> Self {
        self.verbose_logging = true;
        self
    }

    /// Get the local peer ID
    pub fn local_peer_id(&self) -> crate::types::PeerId {
        self.identity.peer_id()
    }
}

/// Builder for PqNoiseConfig
pub struct PqNoiseConfigBuilder {
    identity: Option<LocalIdentity>,
    require_pq: bool,
    handshake_timeout: Duration,
    max_handshake_message_size: usize,
    verbose_logging: bool,
}

impl Default for PqNoiseConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PqNoiseConfigBuilder {
    /// Create a new builder with defaults
    pub fn new() -> Self {
        Self {
            identity: None,
            require_pq: true, // Default to secure
            handshake_timeout: Duration::from_secs(30),
            max_handshake_message_size: 16 * 1024,
            verbose_logging: false,
        }
    }

    /// Set the local identity
    pub fn identity(mut self, identity: LocalIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Set whether PQ is required
    pub fn require_pq(mut self, require: bool) -> Self {
        self.require_pq = require;
        self
    }

    /// Set the handshake timeout
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Set maximum handshake message size
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.max_handshake_message_size = size;
        self
    }

    /// Enable verbose logging
    pub fn verbose(mut self) -> Self {
        self.verbose_logging = true;
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<PqNoiseConfig, &'static str> {
        let identity = self.identity.ok_or("identity is required")?;

        Ok(PqNoiseConfig {
            identity,
            require_pq: self.require_pq,
            handshake_timeout: self.handshake_timeout,
            max_handshake_message_size: self.max_handshake_message_size,
            verbose_logging: self.verbose_logging,
        })
    }
}
