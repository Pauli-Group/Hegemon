//! PQ Protocol Negotiation
//!
//! Handles version negotiation between PQ and non-PQ peers.
//!
//! # Phase 3.5 Implementation
//!
//! This module implements Task 3.5.4 of the substrate migration plan:
//! - PQ protocol version negotiation
//! - Protocol identification for PQ-aware vs legacy peers
//! - Notification protocol configuration
//!
//! # Protocol Versioning
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Protocol Negotiation                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Priority Order (highest first):                                 │
//! │  1. /hegemon/pq/1        - Full PQ (ML-KEM-768 + ML-DSA-65)    │
//! │  2. /hegemon/hybrid/1    - Hybrid (X25519 + ML-KEM-768)        │
//! │  3. /hegemon/legacy/1    - Legacy (X25519 only) [if allowed]   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use std::fmt;

/// Protocol version for PQ-secured connections (full PQ)
pub const PQ_PROTOCOL_V1: &str = "/hegemon/pq/1";

/// Protocol version for hybrid connections (classical + PQ)
pub const HYBRID_PROTOCOL_V1: &str = "/hegemon/hybrid/1";

/// Protocol version for legacy connections (classical only)
pub const LEGACY_PROTOCOL_V1: &str = "/hegemon/legacy/1";

/// Block announcement protocol (PQ version)
pub const BLOCK_ANNOUNCES_PQ: &str = "/hegemon/block-announces/pq/1";

/// Block announcement protocol (legacy version)
pub const BLOCK_ANNOUNCES_LEGACY: &str = "/hegemon/block-announces/1";

/// Transaction propagation protocol (PQ version)
pub const TRANSACTIONS_PQ: &str = "/hegemon/transactions/pq/1";

/// Transaction propagation protocol (legacy version)
pub const TRANSACTIONS_LEGACY: &str = "/hegemon/transactions/1";

/// Sync protocol (PQ version)
pub const SYNC_PQ: &str = "/hegemon/sync/pq/1";

/// Sync protocol (legacy version)
pub const SYNC_LEGACY: &str = "/hegemon/sync/1";

/// State request protocol
pub const STATE_REQUEST: &str = "/hegemon/state/1";

/// Light client protocol
pub const LIGHT_CLIENT: &str = "/hegemon/light/1";

/// Protocol security level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolSecurityLevel {
    /// Legacy security (classical cryptography only)
    Legacy = 0,
    /// Hybrid security (classical + post-quantum)
    Hybrid = 1,
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
            ProtocolSecurityLevel::Legacy => LEGACY_PROTOCOL_V1,
            ProtocolSecurityLevel::Hybrid => HYBRID_PROTOCOL_V1,
            ProtocolSecurityLevel::PostQuantum => PQ_PROTOCOL_V1,
        }
    }
}

impl fmt::Display for ProtocolSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolSecurityLevel::Legacy => write!(f, "Legacy (X25519)"),
            ProtocolSecurityLevel::Hybrid => write!(f, "Hybrid (X25519 + ML-KEM-768)"),
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
            _ => None,
        }
    }

    /// Get the legacy version of this protocol
    pub fn legacy_protocol(&self) -> Option<&'static str> {
        match self {
            ProtocolType::BlockAnnounces => Some(BLOCK_ANNOUNCES_LEGACY),
            ProtocolType::Transactions => Some(TRANSACTIONS_LEGACY),
            ProtocolType::Sync => Some(SYNC_LEGACY),
            ProtocolType::Handshake => Some(LEGACY_PROTOCOL_V1),
            ProtocolType::StateRequest => Some(STATE_REQUEST),
            ProtocolType::LightClient => Some(LIGHT_CLIENT),
            _ => None,
        }
    }
}

/// Get the list of supported protocols in order of preference
pub fn supported_protocols(require_pq: bool) -> Vec<&'static str> {
    if require_pq {
        vec![PQ_PROTOCOL_V1, HYBRID_PROTOCOL_V1]
    } else {
        vec![PQ_PROTOCOL_V1, HYBRID_PROTOCOL_V1, LEGACY_PROTOCOL_V1]
    }
}

/// Check if a protocol identifier is PQ-secure
pub fn is_pq_protocol(protocol: &str) -> bool {
    protocol.contains("/pq/") || protocol == PQ_PROTOCOL_V1
}

/// Check if a protocol identifier is hybrid
pub fn is_hybrid_protocol(protocol: &str) -> bool {
    protocol.contains("/hybrid/") || protocol == HYBRID_PROTOCOL_V1
}

/// Check if a protocol identifier is legacy
pub fn is_legacy_protocol(protocol: &str) -> bool {
    !is_pq_protocol(protocol) && !is_hybrid_protocol(protocol)
}

/// Get the security level of a protocol identifier
pub fn protocol_security_level(protocol: &str) -> ProtocolSecurityLevel {
    if is_pq_protocol(protocol) {
        ProtocolSecurityLevel::PostQuantum
    } else if is_hybrid_protocol(protocol) {
        ProtocolSecurityLevel::Hybrid
    } else {
        ProtocolSecurityLevel::Legacy
    }
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
    } else if protocol.contains("/pq/") || protocol.contains("/hybrid/") || protocol.contains("/legacy/") {
        ProtocolType::Handshake
    } else {
        ProtocolType::Unknown
    }
}

/// Negotiate the best protocol between local and remote supported protocols
pub fn negotiate_protocol(
    local_supported: &[&str],
    remote_supported: &[&str],
    require_pq: bool,
) -> Option<&'static str> {
    // Priority order: PQ > Hybrid > Legacy
    let priority_order = if require_pq {
        vec![PQ_PROTOCOL_V1, HYBRID_PROTOCOL_V1]
    } else {
        vec![PQ_PROTOCOL_V1, HYBRID_PROTOCOL_V1, LEGACY_PROTOCOL_V1]
    };

    for protocol in priority_order {
        if local_supported.contains(&protocol) && remote_supported.contains(&protocol) {
            return Some(protocol);
        }
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
    pub fn new(
        protocol: &str,
        require_pq: bool,
    ) -> Self {
        let security_level = protocol_security_level(protocol);
        let peer_supports_pq = security_level >= ProtocolSecurityLevel::Hybrid;
        let meets_pq_requirement = !require_pq || peer_supports_pq;

        Self {
            protocol: protocol.to_string(),
            security_level,
            peer_supports_pq,
            meets_pq_requirement,
        }
    }
}

/// Configuration for protocol negotiation
#[derive(Debug, Clone)]
pub struct ProtocolNegotiationConfig {
    /// Whether to require PQ for all connections
    pub require_pq: bool,
    /// Preferred security level
    pub preferred_level: ProtocolSecurityLevel,
    /// Minimum acceptable security level
    pub minimum_level: ProtocolSecurityLevel,
    /// Locally supported protocols
    pub supported_protocols: Vec<String>,
}

impl Default for ProtocolNegotiationConfig {
    fn default() -> Self {
        Self {
            require_pq: true,
            preferred_level: ProtocolSecurityLevel::PostQuantum,
            minimum_level: ProtocolSecurityLevel::Hybrid,
            supported_protocols: vec![
                PQ_PROTOCOL_V1.to_string(),
                HYBRID_PROTOCOL_V1.to_string(),
            ],
        }
    }
}

impl ProtocolNegotiationConfig {
    /// Create a configuration that requires PQ
    pub fn pq_required() -> Self {
        Self::default()
    }

    /// Create a configuration that allows hybrid
    pub fn hybrid_allowed() -> Self {
        Self {
            require_pq: false,
            preferred_level: ProtocolSecurityLevel::PostQuantum,
            minimum_level: ProtocolSecurityLevel::Hybrid,
            supported_protocols: vec![
                PQ_PROTOCOL_V1.to_string(),
                HYBRID_PROTOCOL_V1.to_string(),
            ],
        }
    }

    /// Create a configuration that allows legacy (development only)
    pub fn legacy_allowed() -> Self {
        Self {
            require_pq: false,
            preferred_level: ProtocolSecurityLevel::PostQuantum,
            minimum_level: ProtocolSecurityLevel::Legacy,
            supported_protocols: vec![
                PQ_PROTOCOL_V1.to_string(),
                HYBRID_PROTOCOL_V1.to_string(),
                LEGACY_PROTOCOL_V1.to_string(),
            ],
        }
    }
}

/// Notification protocol configuration for block announcements
pub fn block_announces_config(pq_enabled: bool) -> NotificationProtocolConfig {
    NotificationProtocolConfig {
        name: if pq_enabled {
            BLOCK_ANNOUNCES_PQ.to_string()
        } else {
            BLOCK_ANNOUNCES_LEGACY.to_string()
        },
        fallback_names: if pq_enabled {
            vec![BLOCK_ANNOUNCES_LEGACY.to_string()]
        } else {
            vec![]
        },
        max_notification_size: 1024 * 1024, // 1 MB
        handshake: None,
    }
}

/// Notification protocol configuration for transactions
pub fn transactions_config(pq_enabled: bool) -> NotificationProtocolConfig {
    NotificationProtocolConfig {
        name: if pq_enabled {
            TRANSACTIONS_PQ.to_string()
        } else {
            TRANSACTIONS_LEGACY.to_string()
        },
        fallback_names: if pq_enabled {
            vec![TRANSACTIONS_LEGACY.to_string()]
        } else {
            vec![]
        },
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

/// Build notification protocol configurations for the node
pub fn build_notification_configs(pq_enabled: bool) -> Vec<NotificationProtocolConfig> {
    vec![
        block_announces_config(pq_enabled),
        transactions_config(pq_enabled),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_security_levels() {
        assert!(ProtocolSecurityLevel::PostQuantum > ProtocolSecurityLevel::Hybrid);
        assert!(ProtocolSecurityLevel::Hybrid > ProtocolSecurityLevel::Legacy);
        
        assert!(ProtocolSecurityLevel::PostQuantum.meets_requirement(ProtocolSecurityLevel::Legacy));
        assert!(ProtocolSecurityLevel::PostQuantum.meets_requirement(ProtocolSecurityLevel::Hybrid));
        assert!(ProtocolSecurityLevel::PostQuantum.meets_requirement(ProtocolSecurityLevel::PostQuantum));
        
        assert!(!ProtocolSecurityLevel::Legacy.meets_requirement(ProtocolSecurityLevel::Hybrid));
    }

    #[test]
    fn test_is_pq_protocol() {
        assert!(is_pq_protocol(PQ_PROTOCOL_V1));
        assert!(is_pq_protocol(BLOCK_ANNOUNCES_PQ));
        assert!(is_pq_protocol(TRANSACTIONS_PQ));
        
        assert!(!is_pq_protocol(LEGACY_PROTOCOL_V1));
        assert!(!is_pq_protocol(BLOCK_ANNOUNCES_LEGACY));
    }

    #[test]
    fn test_is_hybrid_protocol() {
        assert!(is_hybrid_protocol(HYBRID_PROTOCOL_V1));
        assert!(is_hybrid_protocol("/hegemon/hybrid/2"));
        
        assert!(!is_hybrid_protocol(PQ_PROTOCOL_V1));
        assert!(!is_hybrid_protocol(LEGACY_PROTOCOL_V1));
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
        let local = vec![PQ_PROTOCOL_V1, HYBRID_PROTOCOL_V1];
        let remote = vec![PQ_PROTOCOL_V1, HYBRID_PROTOCOL_V1];
        assert_eq!(negotiate_protocol(&local, &remote, true), Some(PQ_PROTOCOL_V1));

        // Remote only supports Hybrid
        let remote = vec![HYBRID_PROTOCOL_V1];
        assert_eq!(negotiate_protocol(&local, &remote, true), Some(HYBRID_PROTOCOL_V1));

        // Remote only supports Legacy
        let remote = vec![LEGACY_PROTOCOL_V1];
        assert_eq!(negotiate_protocol(&local, &remote, true), None);

        // Legacy allowed
        let local = vec![PQ_PROTOCOL_V1, HYBRID_PROTOCOL_V1, LEGACY_PROTOCOL_V1];
        let remote = vec![LEGACY_PROTOCOL_V1];
        assert_eq!(negotiate_protocol(&local, &remote, false), Some(LEGACY_PROTOCOL_V1));
    }

    #[test]
    fn test_negotiation_result() {
        let result = NegotiationResult::new(PQ_PROTOCOL_V1, true);
        assert_eq!(result.security_level, ProtocolSecurityLevel::PostQuantum);
        assert!(result.peer_supports_pq);
        assert!(result.meets_pq_requirement);

        let result = NegotiationResult::new(LEGACY_PROTOCOL_V1, true);
        assert_eq!(result.security_level, ProtocolSecurityLevel::Legacy);
        assert!(!result.peer_supports_pq);
        assert!(!result.meets_pq_requirement);

        let result = NegotiationResult::new(LEGACY_PROTOCOL_V1, false);
        assert!(result.meets_pq_requirement);
    }

    #[test]
    fn test_notification_configs() {
        let configs = build_notification_configs(true);
        assert_eq!(configs.len(), 2);
        assert!(configs[0].name.contains("/pq/"));
        assert!(configs[1].name.contains("/pq/"));
        assert!(!configs[0].fallback_names.is_empty());
    }

    #[test]
    fn test_protocol_negotiation_config() {
        let pq_required = ProtocolNegotiationConfig::pq_required();
        assert!(pq_required.require_pq);
        assert_eq!(pq_required.minimum_level, ProtocolSecurityLevel::Hybrid);

        let legacy_allowed = ProtocolNegotiationConfig::legacy_allowed();
        assert!(!legacy_allowed.require_pq);
        assert_eq!(legacy_allowed.minimum_level, ProtocolSecurityLevel::Legacy);
    }
}
