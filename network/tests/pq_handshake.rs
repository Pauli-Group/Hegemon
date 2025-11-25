//! PQ P2P Integration Tests
//!
//! Tests for the post-quantum secure peer-to-peer communication layer.

use network::{
    ConnectionMode, PqPeerIdentity, PqTransportConfig,
    upgrade_inbound, upgrade_outbound,
};
use network::p2p::WireMessage;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

/// Test that two nodes can establish a PQ-secure connection
#[tokio::test]
async fn test_pq_handshake_succeeds() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let node1_identity = PqPeerIdentity::new(
        b"test-node-1-seed",
        PqTransportConfig::development(),
    );
    let node2_identity = PqPeerIdentity::new(
        b"test-node-2-seed",
        PqTransportConfig::development(),
    );

    // Record expected peer IDs
    let expected_node1_peer_id = node1_identity.peer_id();
    let expected_node2_peer_id = node2_identity.peer_id();

    // Spawn responder
    let responder_handle = tokio::spawn(async move {
        let (socket, peer_addr) = listener.accept().await.unwrap();
        upgrade_inbound(&node2_identity, socket, peer_addr).await
    });

    // Connect as initiator
    let socket = TcpStream::connect(addr).await.unwrap();
    let mut initiator_conn = upgrade_outbound(&node1_identity, socket, addr)
        .await
        .expect("initiator handshake should succeed");

    // Wait for responder
    let mut responder_conn = responder_handle
        .await
        .expect("task should complete")
        .expect("responder handshake should succeed");

    // Verify peer IDs
    assert_eq!(initiator_conn.peer_id(), expected_node2_peer_id);
    assert_eq!(responder_conn.peer_id(), expected_node1_peer_id);

    // Verify the connection works
    initiator_conn.send(WireMessage::Ping).await.unwrap();
    match responder_conn.recv().await.unwrap() {
        Some(WireMessage::Ping) => {}
        other => panic!("expected Ping, got {:?}", other),
    }
}

/// Test bidirectional message exchange after handshake
#[tokio::test]
async fn test_pq_bidirectional_communication() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let node1 = PqPeerIdentity::new(b"bidir-node-1", PqTransportConfig::development());
    let node2 = PqPeerIdentity::new(b"bidir-node-2", PqTransportConfig::development());

    let responder_handle = tokio::spawn(async move {
        let (socket, peer_addr) = listener.accept().await.unwrap();
        upgrade_inbound(&node2, socket, peer_addr).await
    });

    let socket = TcpStream::connect(addr).await.unwrap();
    let mut conn1 = upgrade_outbound(&node1, socket, addr).await.unwrap();
    let mut conn2 = responder_handle.await.unwrap().unwrap();

    // Send multiple messages in both directions
    for i in 0..5 {
        // Node 1 → Node 2
        conn1.send(WireMessage::Ping).await.unwrap();
        match conn2.recv().await.unwrap() {
            Some(WireMessage::Ping) => {}
            other => panic!("expected Ping, got {:?}", other),
        }

        // Node 2 → Node 1
        conn2.send(WireMessage::Pong).await.unwrap();
        match conn1.recv().await.unwrap() {
            Some(WireMessage::Pong) => {}
            other => panic!("expected Pong, got {:?}", other),
        }
    }

    // Verify stats
    assert!(conn1.bytes_sent() > 0);
    assert!(conn1.bytes_received() > 0);
    assert!(conn2.bytes_sent() > 0);
    assert!(conn2.bytes_received() > 0);
}

/// Test that PQ handshake works with production config
#[tokio::test]
async fn test_pq_handshake_production_config() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let node1 = PqPeerIdentity::new(b"prod-node-1", PqTransportConfig::production());
    let node2 = PqPeerIdentity::new(b"prod-node-2", PqTransportConfig::production());

    assert!(node1.requires_pq());
    assert!(node2.requires_pq());

    let responder_handle = tokio::spawn(async move {
        let (socket, peer_addr) = listener.accept().await.unwrap();
        upgrade_inbound(&node2, socket, peer_addr).await
    });

    let socket = TcpStream::connect(addr).await.unwrap();
    let conn1 = upgrade_outbound(&node1, socket, addr).await;
    let conn2 = responder_handle.await.unwrap();

    // Both should succeed since both support PQ
    assert!(conn1.is_ok());
    assert!(conn2.is_ok());
}

/// Test concurrent connections from multiple peers
#[tokio::test]
async fn test_pq_concurrent_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_identity = PqPeerIdentity::new(b"server-node", PqTransportConfig::development());
    let server_peer_id = server_identity.peer_id();

    // Spawn server that accepts multiple connections
    let server_handle = tokio::spawn(async move {
        let mut connections = Vec::new();
        for _ in 0..3 {
            let (socket, peer_addr) = listener.accept().await.unwrap();
            match upgrade_inbound(&server_identity, socket, peer_addr).await {
                Ok(conn) => connections.push(conn),
                Err(e) => panic!("server handshake failed: {:?}", e),
            }
        }
        connections
    });

    // Connect 3 clients concurrently
    let mut client_handles = Vec::new();
    for i in 0..3 {
        let addr = addr.clone();
        let seed = format!("client-node-{}", i);
        client_handles.push(tokio::spawn(async move {
            let identity = PqPeerIdentity::new(seed.as_bytes(), PqTransportConfig::development());
            let socket = TcpStream::connect(addr).await.unwrap();
            upgrade_outbound(&identity, socket, addr).await
        }));
    }

    // Collect all client connections
    let mut client_connections = Vec::new();
    for handle in client_handles {
        let conn = handle.await.unwrap().expect("client handshake should succeed");
        assert_eq!(conn.peer_id(), server_peer_id);
        client_connections.push(conn);
    }

    // Collect server connections
    let server_connections = server_handle.await.unwrap();
    assert_eq!(server_connections.len(), 3);
}

/// Test deterministic peer ID generation
#[test]
fn test_peer_id_deterministic() {
    let seed = b"deterministic-seed";
    
    let identity1 = PqPeerIdentity::new(seed, PqTransportConfig::default());
    let identity2 = PqPeerIdentity::new(seed, PqTransportConfig::default());
    
    // Same seed should produce same peer ID
    assert_eq!(identity1.peer_id(), identity2.peer_id());
    
    // Different seed should produce different peer ID
    let identity3 = PqPeerIdentity::new(b"different-seed", PqTransportConfig::default());
    assert_ne!(identity1.peer_id(), identity3.peer_id());
}

/// Test transport configuration options
#[test]
fn test_transport_config_options() {
    let default_config = PqTransportConfig::default();
    assert!(default_config.require_pq);
    assert_eq!(default_config.handshake_timeout, Duration::from_secs(30));

    let dev_config = PqTransportConfig::development();
    assert!(!dev_config.require_pq);
    assert!(dev_config.verbose_logging);

    let prod_config = PqTransportConfig::production();
    assert!(prod_config.require_pq);
    assert!(!prod_config.verbose_logging);
}

/// Test ConnectionMode enum
#[test]
fn test_connection_mode() {
    assert_eq!(ConnectionMode::default(), ConnectionMode::Hybrid);
    
    // Verify all modes exist
    let _legacy = ConnectionMode::Legacy;
    let _pq = ConnectionMode::PqSecure;
    let _hybrid = ConnectionMode::Hybrid;
}
