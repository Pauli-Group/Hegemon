//! PQ Protocol Negotiation
//!
//! Handles version negotiation for PQ-secured connections.
//!
//! # Phase 3.5 Implementation
//!
//! This module implements Task 3.5.4 of the substrate migration plan:
//! - PQ protocol version negotiation
//! - Protocol identification for PQ peers
//! - Notification protocol configuration
//!
//! # Protocol Versioning
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Protocol Negotiation                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Security (ML-KEM-768 + ML-DSA-65 only):                        │
//! │  1. /hegemon/pq/1 - Full PQ (ML-KEM-768 + ML-DSA-65)            │
//! │                                                                  │
//! │  No classical/ECC fallbacks - pure post-quantum only.           │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use std::fmt;

/// Protocol version for PQ-secured connections (full PQ)
pub const PQ_PROTOCOL_V1: &str = "/hegemon/pq/1";

/// Block announcement protocol (PQ version)
pub const BLOCK_ANNOUNCES_PQ: &str = "/hegemon/block-announces/pq/1";

/// Transaction propagation protocol (PQ version)
pub const TRANSACTIONS_PQ: &str = "/hegemon/transactions/pq/1";

/// Sync protocol (PQ version)
pub const SYNC_PQ: &str = "/hegemon/sync/pq/1";

/// State request protocol
pub const STATE_REQUEST: &str = "/hegemon/state/1";

/// Light client protocol
pub const LIGHT_CLIENT: &str = "/hegemon/light/1";

/// Protocol security level (PQ-only network - no classical fallbacks)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolSecurityLevel {
    /// Full PQ security (post-quantum only)
    PostQuantum = 2,
}

impl ProtocolSecurityLevel {
    /// Check if this level meets or exceeds the required level
    pub fn meets_requirement(&self, required: ProtocolSecurityLevel) -> bool {
        *self >= required
    }

    /// Get the protocol identifier for this security level
    pub fn protocol_id(&self) -> &'static str {
        match self {
            ProtocolSecurityLevel::PostQuantum => PQ_PROTOCOL_V1,
        }
    }
}

impl fmt::Display for ProtocolSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolSecurityLevel::PostQuantum => write!(f, "PQ (ML-KEM-768 + ML-DSA-65)"),
        }
    }
}

/// Protocol type for categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    /// Block announcements
    BlockAnnounces,
    /// Transaction propagation
    Transactions,
    /// Chain synchronization
    Sync,
    /// State requests
    StateRequest,
    /// Light client protocol
    LightClient,
    /// Handshake/authentication
    Handshake,
    /// Unknown protocol
    Unknown,
}

impl ProtocolType {
    /// Get the PQ version of this protocol
    pub fn pq_protocol(&self) -> Option<&'static str> {
        match self {
            ProtocolType::BlockAnnounces => Some(BLOCK_ANNOUNCES_PQ),
            ProtocolType::Transactions => Some(TRANSACTIONS_PQ),
            ProtocolType::Sync => Some(SYNC_PQ),
            ProtocolType::Handshake => Some(PQ_PROTOCOL_V1),
            ProtocolType::StateRequest => Some(STATE_REQUEST),
            ProtocolType::LightClient => Some(LIGHT_CLIENT),
            _ => None,
        }
    }
}

/// Get the list of supported protocols (PQ-only)
pub fn supported_protocols() -> Vec<&'static str> {
    vec![PQ_PROTOCOL_V1]
}

/// Check if a protocol identifier is PQ-secure
pub fn is_pq_protocol(protocol: &str) -> bool {
    protocol.contains("/pq/") || protocol == PQ_PROTOCOL_V1
}

/// Get the security level of a protocol identifier
pub fn protocol_security_level(_protocol: &str) -> ProtocolSecurityLevel {
    // All protocols in this PQ-only network are PostQuantum
    ProtocolSecurityLevel::PostQuantum
}

/// Get the protocol type from a protocol identifier
pub fn protocol_type(protocol: &str) -> ProtocolType {
    if protocol.contains("block-announce") {
        ProtocolType::BlockAnnounces
    } else if protocol.contains("transaction") {
        ProtocolType::Transactions
    } else if protocol.contains("sync") {
        ProtocolType::Sync
    } else if protocol.contains("state") {
        ProtocolType::StateRequest
    } else if protocol.contains("light") {
        ProtocolType::LightClient
    } else if protocol.contains("/pq/") {
        ProtocolType::Handshake
    } else {
        ProtocolType::Unknown
    }
}

/// Negotiate the best protocol between local and remote supported protocols
/// (PQ-only network - only PQ is accepted)
pub fn negotiate_protocol(
    local_supported: &[&str],
    remote_supported: &[&str],
) -> Option<&'static str> {
    // PQ-only network - only accept PQ protocol
    if local_supported.contains(&PQ_PROTOCOL_V1) && remote_supported.contains(&PQ_PROTOCOL_V1) {
        return Some(PQ_PROTOCOL_V1);
    }
    None
}

/// Protocol negotiation result
#[derive(Debug, Clone)]
pub struct NegotiationResult {
    /// The negotiated protocol
    pub protocol: String,
    /// Security level of the negotiated protocol
    pub security_level: ProtocolSecurityLevel,
    /// Whether the peer supports PQ
    pub peer_supports_pq: bool,
    /// Whether the connection meets PQ requirements
    pub meets_pq_requirement: bool,
}

impl NegotiationResult {
    /// Create a new negotiation result
    pub fn new(protocol: &str) -> Self {
        let security_level = protocol_security_level(protocol);
        let peer_supports_pq = is_pq_protocol(protocol);

        Self {
            protocol: protocol.to_string(),
            security_level,
            peer_supports_pq,
            meets_pq_requirement: peer_supports_pq, // PQ required in this network
        }
    }
}

/// Configuration for protocol negotiation (PQ-only network)
#[derive(Debug, Clone)]
pub struct ProtocolNegotiationConfig {
    /// Preferred security level (always PostQuantum)
    pub preferred_level: ProtocolSecurityLevel,
    /// Locally supported protocols (PQ only)
    pub supported_protocols: Vec<String>,
}

impl Default for ProtocolNegotiationConfig {
    fn default() -> Self {
        Self {
            preferred_level: ProtocolSecurityLevel::PostQuantum,
            supported_protocols: vec![PQ_PROTOCOL_V1.to_string()],
        }
    }
}

impl ProtocolNegotiationConfig {
    /// Create a configuration (PQ required by default)
    pub fn pq_required() -> Self {
        Self::default()
    }
}

/// Notification protocol configuration for block announcements
pub fn block_announces_config() -> NotificationProtocolConfig {
    NotificationProtocolConfig {
        name: BLOCK_ANNOUNCES_PQ.to_string(),
        fallback_names: vec![],
        max_notification_size: 1024 * 1024, // 1 MB
        handshake: None,
    }
}

/// Notification protocol configuration for transactions
pub fn transactions_config() -> NotificationProtocolConfig {
    NotificationProtocolConfig {
        name: TRANSACTIONS_PQ.to_string(),
        fallback_names: vec![],
        max_notification_size: 16 * 1024 * 1024, // 16 MB
        handshake: None,
    }
}

/// Configuration for a notification protocol
#[derive(Debug, Clone)]
pub struct NotificationProtocolConfig {
    /// Primary protocol name
    pub name: String,
    /// Fallback names for compatibility
    pub fallback_names: Vec<String>,
    /// Maximum notification size in bytes
    pub max_notification_size: u64,
    /// Handshake data (optional)
    pub handshake: Option<Vec<u8>>,
}

/// Build notification protocol configurations for the node (PQ-only)
pub fn build_notification_configs() -> Vec<NotificationProtocolConfig> {
    vec![
        block_announces_config(),
        transactions_config(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_security_levels() {
        assert!(ProtocolSecurityLevel::PostQuantum.meets_requirement(ProtocolSecurityLevel::PostQuantum));
    }

    #[test]
    fn test_is_pq_protocol() {
        assert!(is_pq_protocol(PQ_PROTOCOL_V1));
        assert!(is_pq_protocol(BLOCK_ANNOUNCES_PQ));
        assert!(is_pq_protocol(TRANSACTIONS_PQ));
    }

    #[test]
    fn test_protocol_type() {
        assert_eq!(protocol_type(BLOCK_ANNOUNCES_PQ), ProtocolType::BlockAnnounces);
        assert_eq!(protocol_type(TRANSACTIONS_PQ), ProtocolType::Transactions);
        assert_eq!(protocol_type(SYNC_PQ), ProtocolType::Sync);
        assert_eq!(protocol_type(PQ_PROTOCOL_V1), ProtocolType::Handshake);
        assert_eq!(protocol_type("/unknown/protocol"), ProtocolType::Unknown);
    }

    #[test]
    fn test_negotiate_protocol() {
        // Both support PQ
        let local = vec![PQ_PROTOCOL_V1];
        let remote = vec![PQ_PROTOCOL_V1];
        assert_eq!(negotiate_protocol(&local, &remote), Some(PQ_PROTOCOL_V1));

        // Remote doesn't support PQ - should fail
        let local = vec![PQ_PROTOCOL_V1];
        let remote: Vec<&str> = vec![];
        assert_eq!(negotiate_protocol(&local, &remote), None);
    }

    #[test]
    fn test_negotiation_result() {
        let result = NegotiationResult::new(PQ_PROTOCOL_V1);
        assert_eq!(result.security_level, ProtocolSecurityLevel::PostQuantum);
        assert!(result.peer_supports_pq);
        assert!(result.meets_pq_requirement);
    }

    #[test]
    fn test_notification_configs() {
        let configs = build_notification_configs();
        assert_eq!(configs.len(), 2);
        assert!(configs[0].name.contains("/pq/"));
        assert!(configs[1].name.contains("/pq/"));
    }

    #[test]
    fn test_protocol_negotiation_config() {
        let pq_required = ProtocolNegotiationConfig::pq_required();
        assert_eq!(pq_required.preferred_level, ProtocolSecurityLevel::PostQuantum);
    }
}
