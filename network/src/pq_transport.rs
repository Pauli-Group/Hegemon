//! PQ Transport integration for the network layer
//!
//! This module provides integration between the pq-noise crate and the
//! network layer, enabling post-quantum secure peer connections.

use crate::p2p::WireMessage;
use crate::{NetworkError, PeerId, PeerIdentity};
use pq_noise::{PqNoiseConfig, PqTransport, SecureSession};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

/// Configuration for PQ-secure transport
#[derive(Clone, Debug)]
pub struct PqTransportConfig {
    /// Handshake timeout
    pub handshake_timeout: Duration,
    /// Enable verbose logging of handshake details
    pub verbose_logging: bool,
}

impl Default for PqTransportConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(30),
            verbose_logging: false,
        }
    }
}

impl PqTransportConfig {
    /// Create a development configuration (less strict)
    pub fn development() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(30),
            verbose_logging: true,
        }
    }

    /// Create a production configuration (requires PQ)
    pub fn production() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(30),
            verbose_logging: false,
        }
    }
}

/// PQ peer identity for post-quantum handshakes
pub struct PqPeerIdentity {
    /// Local identity for peer ID derivation
    identity: PeerIdentity,
    /// PQ noise configuration
    pq_config: PqNoiseConfig,
    /// Transport configuration
    transport_config: PqTransportConfig,
}

impl PqPeerIdentity {
    /// Create a new PQ peer identity from a seed
    pub fn new(seed: &[u8], transport_config: PqTransportConfig) -> Self {
        let identity = PeerIdentity::generate(seed);
        let local_identity = pq_noise::types::LocalIdentity::generate(seed);

        let pq_config =
            PqNoiseConfig::new(local_identity).with_timeout(transport_config.handshake_timeout);

        Self {
            identity,
            pq_config: if transport_config.verbose_logging {
                pq_config.with_verbose_logging()
            } else {
                pq_config
            },
            transport_config,
        }
    }

    /// Get the peer ID
    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    /// Create a PQ transport from this identity
    pub fn transport(&self) -> PqTransport {
        PqTransport::new(self.pq_config.clone())
    }

    pub fn transport_config(&self) -> &PqTransportConfig {
        &self.transport_config
    }
}

/// Upgrade a TCP connection with PQ-secure handshake (as initiator)
pub async fn upgrade_outbound(
    identity: &PqPeerIdentity,
    socket: TcpStream,
    addr: SocketAddr,
) -> Result<PqSecureConnection, NetworkError> {
    let transport = identity.transport();

    match transport.upgrade_outbound(socket).await {
        Ok((session, peer_id)) => {
            tracing::info!(
                peer_id = %hex::encode(peer_id),
                addr = %addr,
                "PQ handshake complete with ML-KEM-1024"
            );
            Ok(PqSecureConnection::new(session, peer_id, addr))
        }
        Err(e) => {
            tracing::warn!(
                addr = %addr,
                error = %e,
                "PQ handshake failed"
            );
            Err(NetworkError::Handshake("PQ handshake failed"))
        }
    }
}

/// Upgrade a TCP connection with PQ-secure handshake (as responder)
pub async fn upgrade_inbound(
    identity: &PqPeerIdentity,
    socket: TcpStream,
    addr: SocketAddr,
) -> Result<PqSecureConnection, NetworkError> {
    let transport = identity.transport();

    match transport.upgrade_inbound(socket).await {
        Ok((session, peer_id)) => {
            tracing::info!(
                peer_id = %hex::encode(peer_id),
                addr = %addr,
                "PQ handshake complete with ML-KEM-1024"
            );
            Ok(PqSecureConnection::new(session, peer_id, addr))
        }
        Err(e) => {
            tracing::warn!(
                addr = %addr,
                error = %e,
                "PQ handshake failed"
            );
            Err(NetworkError::Handshake("PQ handshake failed"))
        }
    }
}

/// A PQ-secure connection wrapping a SecureSession
pub struct PqSecureConnection {
    session: SecureSession<TcpStream>,
    peer_id: PeerId,
    addr: SocketAddr,
}

impl PqSecureConnection {
    fn new(session: SecureSession<TcpStream>, peer_id: PeerId, addr: SocketAddr) -> Self {
        Self {
            session,
            peer_id,
            addr,
        }
    }

    /// Get the remote peer ID
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Get the remote address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Send a wire message
    pub async fn send(&mut self, msg: WireMessage) -> Result<(), NetworkError> {
        let bytes = bincode::serialize(&msg)?;
        self.session
            .send(&bytes)
            .await
            .map_err(|e| NetworkError::Io(std::io::Error::other(e.to_string())))
    }

    /// Receive a wire message
    pub async fn recv(&mut self) -> Result<Option<WireMessage>, NetworkError> {
        match self.session.recv().await {
            Ok(Some(data)) => {
                let msg = bincode::deserialize(&data)?;
                Ok(Some(msg))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(NetworkError::Io(std::io::Error::other(e.to_string()))),
        }
    }

    /// Get bytes sent
    pub fn bytes_sent(&self) -> u64 {
        self.session.bytes_sent()
    }

    /// Get bytes received
    pub fn bytes_received(&self) -> u64 {
        self.session.bytes_received()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_pq_connection_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let initiator_identity =
            PqPeerIdentity::new(b"test-initiator", PqTransportConfig::development());
        let responder_identity =
            PqPeerIdentity::new(b"test-responder", PqTransportConfig::development());

        let responder_handle = tokio::spawn(async move {
            let (socket, peer_addr) = listener.accept().await.unwrap();
            upgrade_inbound(&responder_identity, socket, peer_addr).await
        });

        let initiator_socket = TcpStream::connect(addr).await.unwrap();
        let mut initiator_conn = upgrade_outbound(&initiator_identity, initiator_socket, addr)
            .await
            .unwrap();

        let mut responder_conn = responder_handle.await.unwrap().unwrap();

        // Test message exchange
        initiator_conn.send(WireMessage::Ping).await.unwrap();

        match responder_conn.recv().await.unwrap() {
            Some(WireMessage::Ping) => {}
            other => panic!("Expected Ping, got {:?}", other),
        }

        responder_conn.send(WireMessage::Pong).await.unwrap();

        match initiator_conn.recv().await.unwrap() {
            Some(WireMessage::Pong) => {}
            other => panic!("Expected Pong, got {:?}", other),
        }
    }

    #[test]
    fn test_pq_peer_identity() {
        let identity = PqPeerIdentity::new(b"test-seed", PqTransportConfig::default());

        // Peer ID should be consistent
        let id1 = identity.peer_id();
        let id2 = identity.peer_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_transport_config() {
        let dev = PqTransportConfig::development();
        assert!(dev.verbose_logging);

        let prod = PqTransportConfig::production();
        assert!(!prod.verbose_logging);
    }
}
