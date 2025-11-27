//! PQ Network Backend for Substrate
//!
//! Custom network backend that integrates PQ-secure transport with
//! Substrate's sc-network infrastructure.
//!
//! # Phase 3.5 Implementation
//!
//! This module implements Task 3.5.2 of the substrate migration plan:
//! - Custom NetworkBackend with PQ transport
//! - Connection manager with PQ handshake
//! - Peer management with PQ identity verification
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                   PqNetworkBackend                               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────────────────────────────────────────────────┐│
//! │  │              Connection Manager                              ││
//! │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ ││
//! │  │  │  Listener   │  │  Dialer     │  │  Connection Pool    │ ││
//! │  │  │  (inbound)  │  │  (outbound) │  │  (active conns)     │ ││
//! │  │  └─────────────┘  └─────────────┘  └─────────────────────┘ ││
//! │  └─────────────────────────────────────────────────────────────┘│
//! │                            │                                    │
//! │  ┌─────────────────────────▼─────────────────────────────────┐  │
//! │  │              PQ Transport Layer                            │  │
//! │  │  ┌─────────────────────────────────────────────────────┐  │  │
//! │  │  │  SubstratePqTransport (hybrid handshake)            │  │  │
//! │  │  └─────────────────────────────────────────────────────┘  │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! │                            │                                    │
//! │  ┌─────────────────────────▼─────────────────────────────────┐  │
//! │  │              Protocol Handlers                             │  │
//! │  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  │  │
//! │  │  │ Block Announce│  │ Transactions  │  │ Sync Protocol │  │  │
//! │  │  └───────────────┘  └───────────────┘  └───────────────┘  │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use crate::substrate_transport::{
    PqConnectionInfo, SubstratePqConnection, SubstratePqTransport, SubstratePqTransportConfig,
};
use crate::pq_transport::PqPeerIdentity;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio::time::timeout;

/// PQ Network Backend configuration
#[derive(Clone, Debug)]
pub struct PqNetworkBackendConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// Bootstrap nodes to connect to
    pub bootstrap_nodes: Vec<SocketAddr>,
    /// Maximum number of peers
    pub max_peers: usize,
    /// Whether to require PQ handshake
    pub require_pq: bool,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Enable verbose logging
    pub verbose_logging: bool,
}

impl Default for PqNetworkBackendConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:30333".parse().unwrap(),
            bootstrap_nodes: Vec::new(),
            max_peers: 50,
            require_pq: true,
            connection_timeout: Duration::from_secs(30),
            verbose_logging: false,
        }
    }
}

impl PqNetworkBackendConfig {
    /// Create development configuration
    pub fn development() -> Self {
        Self {
            listen_addr: "127.0.0.1:30333".parse().unwrap(),
            bootstrap_nodes: Vec::new(),
            max_peers: 25,
            require_pq: false,
            connection_timeout: Duration::from_secs(30),
            verbose_logging: true,
        }
    }

    /// Create testnet configuration
    pub fn testnet() -> Self {
        Self {
            listen_addr: "0.0.0.0:30333".parse().unwrap(),
            bootstrap_nodes: Vec::new(),
            max_peers: 50,
            require_pq: true,
            connection_timeout: Duration::from_secs(30),
            verbose_logging: false,
        }
    }

    /// Create mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            listen_addr: "0.0.0.0:30333".parse().unwrap(),
            bootstrap_nodes: Vec::new(),
            max_peers: 100,
            require_pq: true,
            connection_timeout: Duration::from_secs(60),
            verbose_logging: false,
        }
    }
}

/// Events emitted by the network backend
#[derive(Debug, Clone)]
pub enum PqNetworkEvent {
    /// A new peer connected
    PeerConnected {
        peer_id: [u8; 32],
        addr: SocketAddr,
        is_outbound: bool,
    },
    /// A peer disconnected
    PeerDisconnected {
        peer_id: [u8; 32],
        reason: String,
    },
    /// A message was received from a peer
    MessageReceived {
        peer_id: [u8; 32],
        protocol: String,
        data: Vec<u8>,
    },
    /// Network started
    Started {
        listen_addr: SocketAddr,
    },
    /// Network stopped
    Stopped,
    /// Connection failed
    ConnectionFailed {
        addr: SocketAddr,
        reason: String,
    },
}

/// Active peer connection state
struct PeerConnection {
    /// The secure connection
    connection: SubstratePqConnection,
    /// Connection info
    info: PqConnectionInfo,
    /// Message sender for this peer (reserved for message routing)
    #[allow(dead_code)]
    msg_tx: mpsc::Sender<Vec<u8>>,
}

/// PQ Network Backend
///
/// Manages PQ-secure peer connections for Substrate networking.
pub struct PqNetworkBackend {
    /// Transport for establishing connections
    transport: SubstratePqTransport,
    /// Configuration
    config: PqNetworkBackendConfig,
    /// Active peer connections
    peers: Arc<RwLock<HashMap<[u8; 32], PeerConnection>>>,
    /// Event sender
    event_tx: mpsc::Sender<PqNetworkEvent>,
    /// Event receiver (for external consumers)
    /// Note: Consumed by start() which returns a new receiver for the caller
    #[allow(dead_code)]
    event_rx: mpsc::Receiver<PqNetworkEvent>,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// Local peer ID
    local_peer_id: [u8; 32],
}

impl PqNetworkBackend {
    /// Create a new PQ network backend
    pub fn new(identity: &PqPeerIdentity, config: PqNetworkBackendConfig) -> Self {
        let transport_config = SubstratePqTransportConfig {
            require_pq: config.require_pq,
            connection_timeout: config.connection_timeout,
            handshake_timeout: Duration::from_secs(30),
            verbose_logging: config.verbose_logging,
            protocol_id: "/hegemon/pq/1".to_string(),
        };

        let transport = SubstratePqTransport::new(identity, transport_config);
        let local_peer_id = transport.local_peer_id();
        let (event_tx, event_rx) = mpsc::channel(1024);

        Self {
            transport,
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            event_rx,
            shutdown_tx: None,
            local_peer_id,
        }
    }

    /// Get the local peer ID
    pub fn local_peer_id(&self) -> [u8; 32] {
        self.local_peer_id
    }

    /// Get the number of connected peers
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get connected peer IDs
    pub async fn connected_peers(&self) -> Vec<[u8; 32]> {
        self.peers.read().await.keys().copied().collect()
    }

    /// Get connection info for all peers
    pub async fn peer_info(&self) -> Vec<PqConnectionInfo> {
        self.peers
            .read()
            .await
            .values()
            .map(|p| p.info.clone())
            .collect()
    }

    /// Start the network backend
    ///
    /// Returns a receiver for network events.
    pub async fn start(&mut self) -> Result<mpsc::Receiver<PqNetworkEvent>, std::io::Error> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Start listener
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        let actual_addr = listener.local_addr()?;

        tracing::info!(
            addr = %actual_addr,
            peer_id = %hex::encode(self.local_peer_id),
            "PQ network backend started"
        );

        let _ = self.event_tx.send(PqNetworkEvent::Started {
            listen_addr: actual_addr,
        }).await;

        // Spawn listener task
        let transport = self.transport.clone();
        let peers = self.peers.clone();
        let event_tx = self.event_tx.clone();
        let max_peers = self.config.max_peers;
        let verbose_logging = self.config.verbose_logging;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((socket, addr)) => {
                                let peers_guard = peers.read().await;
                                if peers_guard.len() >= max_peers {
                                    if verbose_logging {
                                        tracing::debug!(
                                            addr = %addr,
                                            "Rejecting inbound connection: max peers reached"
                                        );
                                    }
                                    drop(peers_guard);
                                    continue;
                                }
                                drop(peers_guard);

                                let transport = transport.clone();
                                let peers = peers.clone();
                                let event_tx = event_tx.clone();

                                tokio::spawn(async move {
                                    match transport.upgrade_inbound(socket, addr).await {
                                        Ok(conn) => {
                                            let peer_id = conn.peer_id();
                                            let info = PqConnectionInfo::from(&conn);
                                            let (msg_tx, _msg_rx) = mpsc::channel(256);

                                            peers.write().await.insert(peer_id, PeerConnection {
                                                connection: conn,
                                                info: info.clone(),
                                                msg_tx,
                                            });

                                            let _ = event_tx.send(PqNetworkEvent::PeerConnected {
                                                peer_id,
                                                addr,
                                                is_outbound: false,
                                            }).await;

                                            tracing::info!(
                                                peer_id = %hex::encode(peer_id),
                                                addr = %addr,
                                                "Inbound peer connected via PQ handshake"
                                            );
                                        }
                                        Err(e) => {
                                            let _ = event_tx.send(PqNetworkEvent::ConnectionFailed {
                                                addr,
                                                reason: e.to_string(),
                                            }).await;
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::warn!("Accept error: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::info!("PQ network backend shutting down");
                        break;
                    }
                }
            }
        });

        // Connect to bootstrap nodes
        for addr in &self.config.bootstrap_nodes {
            if let Err(e) = self.connect(*addr).await {
                tracing::warn!(
                    addr = %addr,
                    error = %e,
                    "Failed to connect to bootstrap node"
                );
            }
        }

        // Take ownership of the event receiver and return it to the caller.
        // The caller will receive all events sent via self.event_tx.
        // We replace with a dummy receiver to satisfy the struct's field requirement.
        let (dummy_tx, dummy_rx) = mpsc::channel(1);
        drop(dummy_tx); // Drop immediately, we don't need it
        let event_rx = std::mem::replace(&mut self.event_rx, dummy_rx);
        
        Ok(event_rx)
    }

    /// Connect to a peer
    pub async fn connect(&self, addr: SocketAddr) -> Result<[u8; 32], String> {
        // Check if we're at max peers
        if self.peers.read().await.len() >= self.config.max_peers {
            return Err("Max peers reached".to_string());
        }

        // Connect with timeout
        let socket = timeout(self.config.connection_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| "Connection timeout")?
            .map_err(|e| e.to_string())?;

        // Upgrade connection
        let conn = self
            .transport
            .upgrade_outbound(socket, addr)
            .await
            .map_err(|e| e.to_string())?;

        let peer_id = conn.peer_id();
        let info = PqConnectionInfo::from(&conn);
        let (msg_tx, _msg_rx) = mpsc::channel(256);

        self.peers.write().await.insert(peer_id, PeerConnection {
            connection: conn,
            info: info.clone(),
            msg_tx,
        });

        let _ = self.event_tx.send(PqNetworkEvent::PeerConnected {
            peer_id,
            addr,
            is_outbound: true,
        }).await;

        tracing::info!(
            peer_id = %hex::encode(peer_id),
            addr = %addr,
            "Outbound peer connected via PQ handshake"
        );

        Ok(peer_id)
    }

    /// Disconnect from a peer
    pub async fn disconnect(&self, peer_id: [u8; 32], reason: &str) {
        if self.peers.write().await.remove(&peer_id).is_some() {
            let _ = self.event_tx.send(PqNetworkEvent::PeerDisconnected {
                peer_id,
                reason: reason.to_string(),
            }).await;

            tracing::info!(
                peer_id = %hex::encode(peer_id),
                reason = reason,
                "Peer disconnected"
            );
        }
    }

    /// Send a message to a specific peer
    pub async fn send_to_peer(&self, peer_id: [u8; 32], data: Vec<u8>) -> Result<(), String> {
        let mut peers = self.peers.write().await;
        
        if let Some(peer) = peers.get_mut(&peer_id) {
            peer.connection
                .send(&data)
                .await
                .map_err(|e| e.to_string())?;
            Ok(())
        } else {
            Err("Peer not found".to_string())
        }
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast(&self, data: Vec<u8>) -> Vec<[u8; 32]> {
        let mut failed = Vec::new();
        let mut peers = self.peers.write().await;
        
        for (peer_id, peer) in peers.iter_mut() {
            if peer.connection.send(&data).await.is_err() {
                failed.push(*peer_id);
            }
        }
        
        // Remove failed peers
        for peer_id in &failed {
            peers.remove(peer_id);
            let _ = self.event_tx.send(PqNetworkEvent::PeerDisconnected {
                peer_id: *peer_id,
                reason: "Send failed".to_string(),
            }).await;
        }
        
        failed
    }

    /// Stop the network backend
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
        
        // Disconnect all peers
        let peer_ids: Vec<_> = self.peers.read().await.keys().copied().collect();
        for peer_id in peer_ids {
            self.disconnect(peer_id, "Shutdown").await;
        }
        
        let _ = self.event_tx.send(PqNetworkEvent::Stopped).await;
    }

    /// Create a handle to the network backend
    ///
    /// The handle can be shared across tasks and used to broadcast messages
    /// and query peer state without access to the full backend.
    pub fn handle(&self) -> PqNetworkHandle {
        PqNetworkHandle {
            local_peer_id: self.local_peer_id,
            peers: self.peers.clone(),
            event_tx: self.event_tx.clone(),
        }
    }
}

/// Handle to the PQ network backend for use in service contexts
#[derive(Clone)]
pub struct PqNetworkHandle {
    /// Local peer ID
    local_peer_id: [u8; 32],
    /// Peers reference
    peers: Arc<RwLock<HashMap<[u8; 32], PeerConnection>>>,
    /// Event sender for sending custom events
    event_tx: mpsc::Sender<PqNetworkEvent>,
}

impl PqNetworkHandle {
    /// Get the local peer ID
    pub fn local_peer_id(&self) -> [u8; 32] {
        self.local_peer_id
    }

    /// Get number of connected peers
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get connected peer IDs
    pub async fn connected_peers(&self) -> Vec<[u8; 32]> {
        self.peers.read().await.keys().copied().collect()
    }

    /// Broadcast data to all connected peers
    ///
    /// This is used by the mining worker to broadcast newly mined blocks
    /// and by the transaction pool to propagate transactions.
    ///
    /// Returns a list of peer IDs that failed to receive the message.
    pub async fn broadcast_to_all(&self, protocol: &str, data: Vec<u8>) -> Vec<[u8; 32]> {
        let mut failed = Vec::new();
        let mut peers = self.peers.write().await;
        
        for (peer_id, peer) in peers.iter_mut() {
            if let Err(e) = peer.connection.send(&data).await {
                tracing::debug!(
                    peer_id = %hex::encode(peer_id),
                    protocol = %protocol,
                    error = %e,
                    "Failed to send message to peer"
                );
                failed.push(*peer_id);
            }
        }
        
        // Remove failed peers
        for peer_id in &failed {
            if let Some(_) = peers.remove(peer_id) {
                // Send disconnect event
                let _ = self.event_tx.send(PqNetworkEvent::PeerDisconnected {
                    peer_id: *peer_id,
                    reason: "Send failed during broadcast".to_string(),
                }).await;
            }
        }
        
        if !failed.is_empty() {
            tracing::warn!(
                failed_count = failed.len(),
                protocol = %protocol,
                "Some peers failed during broadcast"
            );
        }
        
        failed
    }

    /// Send data to a specific peer
    ///
    /// Returns Ok(()) on success, or an error message on failure.
    pub async fn send_to_peer(&self, peer_id: [u8; 32], data: Vec<u8>) -> Result<(), String> {
        let mut peers = self.peers.write().await;
        
        if let Some(peer) = peers.get_mut(&peer_id) {
            peer.connection
                .send(&data)
                .await
                .map_err(|e| e.to_string())?;
            Ok(())
        } else {
            Err("Peer not found".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_transport::PqTransportConfig;

    #[tokio::test]
    async fn test_network_backend_config() {
        let dev = PqNetworkBackendConfig::development();
        assert!(!dev.require_pq);
        assert!(dev.verbose_logging);

        let testnet = PqNetworkBackendConfig::testnet();
        assert!(testnet.require_pq);

        let mainnet = PqNetworkBackendConfig::mainnet();
        assert_eq!(mainnet.max_peers, 100);
    }

    #[tokio::test]
    async fn test_network_backend_creation() {
        let identity = PqPeerIdentity::new(b"test-backend", PqTransportConfig::development());
        let config = PqNetworkBackendConfig::development();
        let backend = PqNetworkBackend::new(&identity, config);

        assert_eq!(backend.peer_count().await, 0);
        assert_eq!(backend.local_peer_id(), identity.peer_id());
    }

    #[tokio::test]
    async fn test_network_backend_peer_connection() {
        // Create two backends
        let identity_a = PqPeerIdentity::new(b"backend-a", PqTransportConfig::development());
        let identity_b = PqPeerIdentity::new(b"backend-b", PqTransportConfig::development());

        let config_a = PqNetworkBackendConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..PqNetworkBackendConfig::development()
        };
        let config_b = PqNetworkBackendConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..PqNetworkBackendConfig::development()
        };

        let mut backend_a = PqNetworkBackend::new(&identity_a, config_a);
        let mut backend_b = PqNetworkBackend::new(&identity_b, config_b);

        // Start backend A
        let _ = backend_a.start().await.unwrap();
        
        // Get actual listen address - this is a bit hacky for testing
        // In production, the start() method would return the actual address
        
        // For now, just verify both backends can be created and started
        assert_eq!(backend_a.peer_count().await, 0);
        assert_eq!(backend_b.peer_count().await, 0);

        backend_a.stop().await;
    }

    #[tokio::test]
    async fn test_network_backend_handle() {
        let identity = PqPeerIdentity::new(b"test-handle", PqTransportConfig::development());
        let config = PqNetworkBackendConfig::development();
        let backend = PqNetworkBackend::new(&identity, config);

        // Get handle
        let handle = backend.handle();
        
        // Handle should have same peer ID
        assert_eq!(handle.local_peer_id(), backend.local_peer_id());
        
        // Both should report 0 peers
        assert_eq!(handle.peer_count().await, 0);
        assert_eq!(backend.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_network_handle_broadcast_empty() {
        let identity = PqPeerIdentity::new(b"test-broadcast", PqTransportConfig::development());
        let config = PqNetworkBackendConfig::development();
        let backend = PqNetworkBackend::new(&identity, config);
        let handle = backend.handle();

        // Broadcast to empty peer set should succeed with no failures
        let failed = handle.broadcast_to_all("/test/protocol", vec![1, 2, 3]).await;
        assert!(failed.is_empty(), "Broadcast to empty set should have no failures");
    }

    #[tokio::test]
    async fn test_network_handle_send_to_nonexistent_peer() {
        let identity = PqPeerIdentity::new(b"test-send", PqTransportConfig::development());
        let config = PqNetworkBackendConfig::development();
        let backend = PqNetworkBackend::new(&identity, config);
        let handle = backend.handle();

        // Send to non-existent peer should fail
        let result = handle.send_to_peer([99u8; 32], vec![1, 2, 3]).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Peer not found");
    }
}
