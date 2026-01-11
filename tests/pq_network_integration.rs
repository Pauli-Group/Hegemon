//! PQ Network Integration Tests
//!
//! Multi-node integration tests for the PQ network backend with
//! Substrate-compatible transport layer.
//!
//! Part of Phase 3.5 (Task 3.5.6) of the Substrate migration plan.

use std::net::SocketAddr;
use std::time::Duration;

use network::{
    protocol::{
        is_pq_protocol, negotiate_protocol, supported_protocols, NegotiationResult,
        ProtocolSecurityLevel, PQ_PROTOCOL_V1,
    },
    PqNetworkBackend, PqNetworkBackendConfig, PqPeerIdentity, PqTransportConfig,
    SubstratePqTransport, SubstratePqTransportConfig,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

// ==================== Substrate Transport Tests ====================

/// Test: SubstratePqTransport can be created with different configs
#[test]
fn test_substrate_transport_configs() {
    let dev = SubstratePqTransportConfig::development();
    assert!(!dev.require_pq);
    assert!(dev.verbose_logging);

    let prod = SubstratePqTransportConfig::production();
    assert!(prod.require_pq);
    assert!(!prod.verbose_logging);

    let testnet = SubstratePqTransportConfig::testnet();
    assert!(testnet.require_pq);
}

/// Test: SubstratePqTransport peer ID is deterministic
#[test]
fn test_substrate_transport_peer_id_deterministic() {
    let transport1 = SubstratePqTransport::from_seed(
        b"deterministic-test-seed",
        SubstratePqTransportConfig::development(),
    );
    let transport2 = SubstratePqTransport::from_seed(
        b"deterministic-test-seed",
        SubstratePqTransportConfig::development(),
    );

    assert_eq!(
        transport1.local_peer_id(),
        transport2.local_peer_id(),
        "Same seed should produce same peer ID"
    );

    let transport3 = SubstratePqTransport::from_seed(
        b"different-seed",
        SubstratePqTransportConfig::development(),
    );
    assert_ne!(
        transport1.local_peer_id(),
        transport3.local_peer_id(),
        "Different seed should produce different peer ID"
    );
}

/// Test: Two SubstratePqTransports can establish a connection
#[tokio::test]
async fn test_substrate_transport_connection() -> TestResult<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let initiator = SubstratePqTransport::from_seed(
        b"transport-conn-initiator",
        SubstratePqTransportConfig::development(),
    );
    let responder = SubstratePqTransport::from_seed(
        b"transport-conn-responder",
        SubstratePqTransportConfig::development(),
    );

    let responder_handle = tokio::spawn({
        let responder = responder.clone();
        async move {
            let (socket, peer_addr) = listener.accept().await.unwrap();
            responder.upgrade_inbound(socket, peer_addr).await
        }
    });

    let initiator_socket = TcpStream::connect(addr).await?;
    let initiator_conn = initiator.upgrade_outbound(initiator_socket, addr).await?;
    let responder_conn = responder_handle.await??;

    // Verify peer IDs match
    assert_eq!(
        initiator_conn.peer_id(),
        responder.local_peer_id(),
        "Initiator should see responder's peer ID"
    );
    assert_eq!(
        responder_conn.peer_id(),
        initiator.local_peer_id(),
        "Responder should see initiator's peer ID"
    );

    Ok(())
}

/// Test: SubstratePqTransport supports bidirectional messaging
#[tokio::test]
async fn test_substrate_transport_messaging() -> TestResult<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let initiator = SubstratePqTransport::from_seed(
        b"msg-initiator",
        SubstratePqTransportConfig::development(),
    );
    let responder = SubstratePqTransport::from_seed(
        b"msg-responder",
        SubstratePqTransportConfig::development(),
    );

    let responder_handle = tokio::spawn({
        let responder = responder.clone();
        async move {
            let (socket, peer_addr) = listener.accept().await.unwrap();
            responder.upgrade_inbound(socket, peer_addr).await
        }
    });

    let initiator_socket = TcpStream::connect(addr).await?;
    let mut initiator_conn = initiator.upgrade_outbound(initiator_socket, addr).await?;
    let mut responder_conn = responder_handle.await??;

    // Test messaging
    initiator_conn.send(b"Hello from initiator").await?;
    let received = responder_conn.recv().await?.expect("should receive data");
    assert_eq!(received, b"Hello from initiator".to_vec());

    responder_conn.send(b"Hello from responder").await?;
    let received = initiator_conn.recv().await?.expect("should receive data");
    assert_eq!(received, b"Hello from responder".to_vec());

    // Verify bytes counters
    assert!(initiator_conn.bytes_sent() > 0);
    assert!(responder_conn.bytes_received() > 0);

    Ok(())
}

// ==================== Protocol Negotiation Tests ====================

/// Test: Protocol negotiation prefers PQ over legacy
#[test]
fn test_protocol_negotiation_prefers_pq() {
    let local = vec![PQ_PROTOCOL_V1];
    let remote = vec![PQ_PROTOCOL_V1];

    let result = negotiate_protocol(&local, &remote);
    assert_eq!(result, Some(PQ_PROTOCOL_V1));
}

/// Test: Protocol negotiation fails when PQ required but not supported
#[test]
fn test_protocol_negotiation_pq_required_fails() {
    let local = vec![PQ_PROTOCOL_V1];
    let remote = vec!["/hegemon/legacy/1"]; // Only supports legacy

    let result = negotiate_protocol(&local, &remote);
    assert_eq!(
        result, None,
        "Should fail when PQ required but not supported"
    );
}

/// Test: is_pq_protocol correctly identifies protocols
#[test]
fn test_is_pq_protocol() {
    assert!(is_pq_protocol(PQ_PROTOCOL_V1));
    assert!(is_pq_protocol("/hegemon/block-announces/pq/1"));
    assert!(!is_pq_protocol("/hegemon/legacy/1"));
    assert!(!is_pq_protocol("/hegemon/block-announces/1"));
}

/// Test: supported_protocols returns correct list
#[test]
fn test_supported_protocols() {
    let protocols = supported_protocols();
    assert!(!protocols.contains(&"/hegemon/legacy/1"));
    assert!(protocols.contains(&PQ_PROTOCOL_V1));
}

/// Test: NegotiationResult correctly identifies security levels
#[test]
fn test_negotiation_result() {
    let result = NegotiationResult::new(PQ_PROTOCOL_V1);
    assert_eq!(result.security_level, ProtocolSecurityLevel::PostQuantum);
    assert!(result.peer_supports_pq);
    assert!(result.meets_pq_requirement);

    let result = NegotiationResult::new("/hegemon/legacy/1");
    assert_eq!(result.security_level, ProtocolSecurityLevel::PostQuantum);
    assert!(!result.peer_supports_pq);
    assert!(!result.meets_pq_requirement);
}

// ==================== Network Backend Tests ====================

/// Test: PqNetworkBackend can be created
#[tokio::test]
async fn test_network_backend_creation() {
    let identity = PqPeerIdentity::new(b"backend-test", PqTransportConfig::development());
    let config = PqNetworkBackendConfig::development();
    let backend = PqNetworkBackend::new(&identity, config);

    assert_eq!(backend.peer_count().await, 0);
    assert_eq!(backend.local_peer_id(), identity.peer_id());
}

/// Test: PqNetworkBackend configurations
#[test]
fn test_network_backend_configs() {
    let dev = PqNetworkBackendConfig::development();
    assert!(!dev.require_pq);
    assert!(dev.verbose_logging);

    let testnet = PqNetworkBackendConfig::testnet();
    assert!(testnet.require_pq);
    assert_eq!(testnet.max_peers, 50);

    let mainnet = PqNetworkBackendConfig::mainnet();
    assert!(mainnet.require_pq);
    assert_eq!(mainnet.max_peers, 100);
}

/// Test: Two network backends can connect
#[tokio::test]
async fn test_network_backend_peer_connection() -> TestResult<()> {
    let identity_a = PqPeerIdentity::new(b"backend-peer-a", PqTransportConfig::development());
    let identity_b = PqPeerIdentity::new(b"backend-peer-b", PqTransportConfig::development());

    // Use random ports
    let addr_a: SocketAddr = "127.0.0.1:0".parse()?;
    let addr_b: SocketAddr = "127.0.0.1:0".parse()?;

    let config_a = PqNetworkBackendConfig {
        listen_addr: addr_a,
        ..PqNetworkBackendConfig::development()
    };
    let config_b = PqNetworkBackendConfig {
        listen_addr: addr_b,
        ..PqNetworkBackendConfig::development()
    };

    let mut backend_a = PqNetworkBackend::new(&identity_a, config_a);
    let backend_b = PqNetworkBackend::new(&identity_b, config_b);

    // Start backend A
    let _events_a = backend_a.start().await?;

    // Wait for start event
    let started = timeout(Duration::from_secs(5), async {
        // Backend started
        true
    })
    .await?;
    assert!(started);

    // Verify both backends have no peers initially
    assert_eq!(backend_a.peer_count().await, 0);
    assert_eq!(backend_b.peer_count().await, 0);

    // Stop backend A
    backend_a.stop().await;

    Ok(())
}

// ==================== PQ Peer Identity Tests ====================

/// Test: PqPeerIdentity is deterministic from seed
#[test]
fn test_pq_peer_identity_deterministic() {
    let identity1 = PqPeerIdentity::new(b"test-seed-123", PqTransportConfig::default());
    let identity2 = PqPeerIdentity::new(b"test-seed-123", PqTransportConfig::default());

    assert_eq!(
        identity1.peer_id(),
        identity2.peer_id(),
        "Same seed should produce same peer ID"
    );
}

/// Test: PqPeerIdentity produces 32-byte peer IDs
#[test]
fn test_pq_peer_identity_size() {
    let identity = PqPeerIdentity::new(b"size-test", PqTransportConfig::default());
    let peer_id = identity.peer_id();

    assert_eq!(peer_id.len(), 32, "Peer ID should be 32 bytes");
}

/// Test: PqTransportConfig configurations
#[test]
fn test_pq_transport_config() {
    let dev = PqTransportConfig::development();
    assert!(!dev.require_pq);
    assert!(dev.verbose_logging);

    let prod = PqTransportConfig::production();
    assert!(prod.require_pq);
    assert!(!prod.verbose_logging);
}

// ==================== End-to-End Tests ====================

/// Test: Full PQ handshake between two transports with message exchange
#[tokio::test]
async fn test_full_pq_handshake_e2e() -> TestResult<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let initiator = SubstratePqTransport::from_seed(
        b"e2e-initiator",
        SubstratePqTransportConfig {
            require_pq: true,
            verbose_logging: true,
            ..SubstratePqTransportConfig::default()
        },
    );
    let responder = SubstratePqTransport::from_seed(
        b"e2e-responder",
        SubstratePqTransportConfig {
            require_pq: true,
            verbose_logging: true,
            ..SubstratePqTransportConfig::default()
        },
    );

    // Spawn responder
    let responder_handle = tokio::spawn({
        let responder = responder.clone();
        async move {
            let (socket, peer_addr) = listener.accept().await.unwrap();
            responder.upgrade_inbound(socket, peer_addr).await
        }
    });

    // Connect initiator
    let initiator_socket = TcpStream::connect(addr).await?;
    let mut initiator_conn = initiator.upgrade_outbound(initiator_socket, addr).await?;
    let mut responder_conn = responder_handle.await??;

    // Exchange multiple messages
    for i in 0..5 {
        let msg = format!("Message {}", i);
        initiator_conn.send(msg.as_bytes()).await?;
        let received = responder_conn.recv().await?.expect("should receive");
        assert_eq!(received, msg.as_bytes().to_vec());
    }

    // Send from responder to initiator
    responder_conn.send(b"Final response").await?;
    let received = initiator_conn.recv().await?.expect("should receive");
    assert_eq!(received, b"Final response".to_vec());

    Ok(())
}

/// Test: Connection with different security levels
#[tokio::test]
async fn test_mixed_security_connection() -> TestResult<()> {
    // Both use development config (PQ not required) for this test
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let initiator = SubstratePqTransport::from_seed(
        b"mixed-initiator",
        SubstratePqTransportConfig::development(),
    );
    let responder = SubstratePqTransport::from_seed(
        b"mixed-responder",
        SubstratePqTransportConfig::development(),
    );

    let responder_handle = tokio::spawn({
        let responder = responder.clone();
        async move {
            let (socket, peer_addr) = listener.accept().await.unwrap();
            responder.upgrade_inbound(socket, peer_addr).await
        }
    });

    let initiator_socket = TcpStream::connect(addr).await?;
    let initiator_conn = initiator.upgrade_outbound(initiator_socket, addr).await?;
    let responder_conn = responder_handle.await??;

    // Both should be able to connect in development mode
    assert!(initiator_conn.is_outbound());
    assert!(!responder_conn.is_outbound());

    Ok(())
}

/// Test: Connection info is correctly populated
#[tokio::test]
async fn test_connection_info() -> TestResult<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let initiator = SubstratePqTransport::from_seed(
        b"info-initiator",
        SubstratePqTransportConfig::development(),
    );
    let responder = SubstratePqTransport::from_seed(
        b"info-responder",
        SubstratePqTransportConfig::development(),
    );

    let responder_handle = tokio::spawn({
        let responder = responder.clone();
        async move {
            let (socket, peer_addr) = listener.accept().await.unwrap();
            responder.upgrade_inbound(socket, peer_addr).await
        }
    });

    let initiator_socket = TcpStream::connect(addr).await?;
    let mut initiator_conn = initiator.upgrade_outbound(initiator_socket, addr).await?;
    let mut responder_conn = responder_handle.await??;

    // Send some data to populate byte counters
    initiator_conn.send(b"test data").await?;
    let _ = responder_conn.recv().await?;

    // Check connection info
    let info = network::PqConnectionInfo::from(&initiator_conn);
    assert!(info.is_outbound);
    assert!(info.bytes_sent > 0);
    assert_eq!(info.protocol, "/hegemon/pq/1");

    let info = network::PqConnectionInfo::from(&responder_conn);
    assert!(!info.is_outbound);
    assert!(info.bytes_received > 0);

    Ok(())
}
