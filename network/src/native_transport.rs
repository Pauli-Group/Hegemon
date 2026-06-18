//! Native PQ Transport
//!
//! Wraps the PQ-noise handshake for native Hegemon TCP peers.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Hegemon Native Networking                    │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌───────────────────────────────────────────────────────────┐  │
//! │  │                NativePqTransport                        │  │
//! │  │  ┌─────────────────────────────────────────────────────┐  │  │
//! │  │  │  PQ-noise upgrade over TCP streams                  │  │  │
//! │  │  └─────────────────────────────────────────────────────┘  │  │
//! │  │                          │                                 │  │
//! │  │                          ▼                                 │  │
//! │  │  ┌─────────────────────────────────────────────────────┐  │  │
//! │  │  │              PqNoiseUpgrade                          │  │  │
//! │  │  │  InboundConnectionUpgrade + OutboundConnectionUpgrade│  │  │
//! │  │  └─────────────────────────────────────────────────────┘  │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! │                          │                                      │
//! │                          ▼                                      │
//! │  ┌───────────────────────────────────────────────────────────┐  │
//! │  │                    TCP Transport                           │  │
//! │  │                 (tokio TcpStream)                          │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! This module exposes the low-level TCP upgrade used by the native peer
//! service and integration tests.

use crate::pq_transport::{PqPeerIdentity, PqTransportConfig};
use pq_noise::{PqTransport as PqNoiseTransport, SecureSession};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Result type for native transport operations
pub type Result<T> = std::result::Result<T, NativeTransportError>;

/// Errors that can occur during native transport operations
#[derive(Debug, thiserror::Error)]
pub enum NativeTransportError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Handshake failed: {0}")]
    Handshake(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Connection timeout")]
    Timeout,
    #[error("PQ required but peer doesn't support it")]
    PqRequired,
    #[error("Protocol negotiation failed: {0}")]
    ProtocolNegotiation(String),
}

/// Native PQ transport builder.
#[derive(Clone)]
pub struct NativePqTransport {
    /// PQ noise transport
    inner: Arc<PqNoiseTransport>,
    /// Transport configuration
    config: NativePqTransportConfig,
}

/// Configuration for native PQ transport.
#[derive(Clone, Debug)]
pub struct NativePqTransportConfig {
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Handshake timeout
    pub handshake_timeout: Duration,
    /// Enable verbose logging
    pub verbose_logging: bool,
    /// Reject any connection that does not complete the PQ handshake.
    pub require_pq: bool,
    /// Protocol ID for PQ-secured connections
    pub protocol_id: String,
}

impl Default for NativePqTransportConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(30),
            verbose_logging: false,
            require_pq: true,
            protocol_id: "/hegemon/pq/1".to_string(),
        }
    }
}

impl NativePqTransportConfig {
    /// Create development configuration (verbose logging)
    pub fn development() -> Self {
        Self {
            connection_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(30),
            verbose_logging: true,
            require_pq: false,
            protocol_id: "/hegemon/pq/1".to_string(),
        }
    }

    /// Create production configuration (requires PQ)
    pub fn production() -> Self {
        Self {
            connection_timeout: Duration::from_secs(60),
            handshake_timeout: Duration::from_secs(30),
            verbose_logging: false,
            require_pq: true,
            protocol_id: "/hegemon/pq/1".to_string(),
        }
    }

    /// Create testnet configuration
    pub fn testnet() -> Self {
        Self {
            connection_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(30),
            verbose_logging: false,
            require_pq: true,
            protocol_id: "/hegemon/pq/1".to_string(),
        }
    }
}

impl NativePqTransport {
    /// Create a new native PQ transport.
    pub fn new(identity: &PqPeerIdentity, config: NativePqTransportConfig) -> Self {
        let inner = Arc::new(identity.transport());
        Self { inner, config }
    }

    /// Build from identity seed
    pub fn from_seed(seed: &[u8], config: NativePqTransportConfig) -> Self {
        let pq_config = PqTransportConfig {
            handshake_timeout: config.handshake_timeout,
            verbose_logging: config.verbose_logging,
        };
        let identity = PqPeerIdentity::new(seed, pq_config);
        Self::new(&identity, config)
    }

    /// Get the local peer ID
    pub fn local_peer_id(&self) -> [u8; 32] {
        self.inner.local_peer_id()
    }

    /// Get the configuration
    pub fn config(&self) -> &NativePqTransportConfig {
        &self.config
    }

    /// Upgrade an outbound TCP connection with PQ handshake
    pub async fn upgrade_outbound(
        &self,
        socket: TcpStream,
        addr: SocketAddr,
    ) -> Result<NativePqConnection> {
        let (session, peer_id) = self
            .inner
            .upgrade_outbound(socket)
            .await
            .map_err(|e| NativeTransportError::Handshake(e.to_string()))?;

        if self.config.verbose_logging {
            tracing::info!(
                peer_id = %hex::encode(peer_id),
                addr = %addr,
                "Native PQ outbound handshake complete"
            );
        }

        Ok(NativePqConnection::new(session, peer_id, addr, true))
    }

    /// Upgrade an inbound TCP connection with PQ handshake
    pub async fn upgrade_inbound(
        &self,
        socket: TcpStream,
        addr: SocketAddr,
    ) -> Result<NativePqConnection> {
        let (session, peer_id) = self
            .inner
            .upgrade_inbound(socket)
            .await
            .map_err(|e| NativeTransportError::Handshake(e.to_string()))?;

        if self.config.verbose_logging {
            tracing::info!(
                peer_id = %hex::encode(peer_id),
                addr = %addr,
                "Native PQ inbound handshake complete"
            );
        }

        Ok(NativePqConnection::new(session, peer_id, addr, false))
    }
}

/// A PQ-secured connection for native networking.
///
/// Wraps a SecureSession and exposes direct async send/receive helpers.
pub struct NativePqConnection {
    /// The underlying secure session
    session: SecureSession<TcpStream>,
    /// Remote peer ID
    peer_id: [u8; 32],
    /// Remote address
    addr: SocketAddr,
    /// Whether this was an outbound connection
    is_outbound: bool,
    /// Read buffer for partial reads
    read_buffer: Vec<u8>,
    /// Current position in read buffer
    read_pos: usize,
}

impl NativePqConnection {
    fn new(
        session: SecureSession<TcpStream>,
        peer_id: [u8; 32],
        addr: SocketAddr,
        is_outbound: bool,
    ) -> Self {
        Self {
            session,
            peer_id,
            addr,
            is_outbound,
            read_buffer: Vec::new(),
            read_pos: 0,
        }
    }

    /// Get the remote peer ID
    pub fn peer_id(&self) -> [u8; 32] {
        self.peer_id
    }

    /// Get the remote address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Whether this was an outbound connection
    pub fn is_outbound(&self) -> bool {
        self.is_outbound
    }

    /// Get bytes sent
    pub fn bytes_sent(&self) -> u64 {
        self.session.bytes_sent()
    }

    /// Get bytes received
    pub fn bytes_received(&self) -> u64 {
        self.session.bytes_received()
    }

    /// Send raw data over the secure channel
    pub async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.session
            .send(data)
            .await
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// Receive raw data from the secure channel
    pub async fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.session
            .recv()
            .await
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

impl AsyncRead for NativePqConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // If we have buffered data, return it first
        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;

            // Clear buffer if fully consumed
            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_pos = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // For now, return Pending since we can't poll async methods in poll_read
        // The caller should use the async recv() method directly for receiving data,
        // then this can read from the buffer.
        //
        // In practice, higher-level code should:
        // 1. Call recv() to get data
        // 2. Use AsyncRead to read from the buffer
        //
        // This is a limitation of the current design - the SecureSession recv() is async
        // and can't be easily polled in a non-async context without restructuring.
        //
        // For full integration, consider:
        // - Using a background task to recv() and fill the buffer
        // - Or restructuring SecureSession to support poll-based IO
        Poll::Pending
    }
}

impl AsyncWrite for NativePqConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // For now, return Pending - the caller should use async send() directly
        // This is a limitation similar to poll_read
        //
        // In practice, higher-level code should use the async send() method.
        // For full AsyncWrite support, we would need to restructure SecureSession
        // to support poll-based IO.
        let _ = buf;
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // SecureSession handles flushing internally
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // SecureSession handles shutdown internally
        Poll::Ready(Ok(()))
    }
}

/// Connection info for a PQ-secured peer
#[derive(Clone, Debug)]
pub struct PqConnectionInfo {
    /// Remote peer ID (32 bytes)
    pub peer_id: [u8; 32],
    /// Remote address
    pub addr: SocketAddr,
    /// Whether connection is outbound
    pub is_outbound: bool,
    /// Bytes sent on this connection
    pub bytes_sent: u64,
    /// Bytes received on this connection
    pub bytes_received: u64,
    /// Protocol used
    pub protocol: String,
}

impl From<&NativePqConnection> for PqConnectionInfo {
    fn from(conn: &NativePqConnection) -> Self {
        Self {
            peer_id: conn.peer_id,
            addr: conn.addr,
            is_outbound: conn.is_outbound,
            bytes_sent: conn.bytes_sent(),
            bytes_received: conn.bytes_received(),
            protocol: "/hegemon/pq/1".to_string(),
        }
    }
}

/// PQ upgrade result containing the peer ID and connection
pub struct PqUpgradeOutput {
    /// The secured connection
    pub connection: NativePqConnection,
    /// Remote peer ID as hex string
    pub peer_id_hex: String,
}

impl PqUpgradeOutput {
    /// Create a new upgrade output
    pub fn new(connection: NativePqConnection) -> Self {
        let peer_id_hex = hex::encode(connection.peer_id());
        Self {
            connection,
            peer_id_hex,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use tokio::net::TcpListener;

    #[derive(Deserialize)]
    struct LeanPqWrapperVectorFile {
        schema_version: u32,
        wrapper_completion_cases: Vec<LeanPqWrapperCompletionCase>,
    }

    #[derive(Deserialize)]
    struct LeanPqWrapperCompletionCase {
        name: String,
        wrapper_kind: String,
        local_role: String,
        peer_role: String,
        expected_completed: bool,
        expected_local_is_initiator: bool,
        expected_peer_is_initiator: bool,
        expected_roles_distinct: bool,
        expected_local_send_slot: String,
        expected_local_recv_slot: String,
        expected_peer_send_slot: String,
        expected_peer_recv_slot: String,
        expected_local_send_matches_peer_recv: bool,
        expected_local_recv_matches_peer_send: bool,
        expected_initial_local_bytes_sent: String,
        expected_initial_local_bytes_received: String,
        expected_initial_peer_bytes_sent: String,
        expected_initial_peer_bytes_received: String,
        expected_first_frame_payload_bytes: String,
        expected_first_frame_tag_bytes: String,
        expected_first_frame_wire_bytes: String,
        expected_after_first_local_bytes_sent: String,
        expected_after_first_peer_bytes_received: String,
        plaintext_hex: String,
    }

    fn read_pq_wrapper_vectors() -> Option<LeanPqWrapperVectorFile> {
        let Ok(path) = std::env::var("HEGEMON_LEAN_PQ_NOISE_VECTORS") else {
            eprintln!("skipping Lean PQ wrapper vectors; env var not set");
            return None;
        };
        let contents = std::fs::read_to_string(path).expect("read Lean PQ Noise vectors");
        Some(serde_json::from_str(&contents).expect("parse Lean PQ Noise vectors"))
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        hex::decode(trimmed).expect("hex vector")
    }

    fn parse_u64(value: &str) -> u64 {
        value.parse::<u64>().expect("u64 vector value")
    }

    fn role_is_initiator(value: &str) -> bool {
        match value {
            "initiator" => true,
            "responder" => false,
            other => panic!("unknown role {other}"),
        }
    }

    fn role_slot_names(is_initiator: bool) -> (&'static str, &'static str) {
        if is_initiator {
            ("initiator_to_responder", "responder_to_initiator")
        } else {
            ("responder_to_initiator", "initiator_to_responder")
        }
    }

    #[tokio::test]
    async fn test_native_transport_config() {
        let dev = NativePqTransportConfig::development();
        assert!(dev.verbose_logging);

        let prod = NativePqTransportConfig::production();
        assert!(!prod.verbose_logging);

        let testnet = NativePqTransportConfig::testnet();
        assert!(!testnet.verbose_logging);
    }

    #[tokio::test]
    async fn test_native_transport_upgrade() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let initiator = NativePqTransport::from_seed(
            b"native-test-initiator",
            NativePqTransportConfig::development(),
        );
        let responder = NativePqTransport::from_seed(
            b"native-test-responder",
            NativePqTransportConfig::development(),
        );

        let responder_handle = tokio::spawn({
            let responder = responder.clone();
            async move {
                let (socket, peer_addr) = listener.accept().await.unwrap();
                responder.upgrade_inbound(socket, peer_addr).await
            }
        });

        let initiator_socket = TcpStream::connect(addr).await.unwrap();
        let initiator_conn = initiator
            .upgrade_outbound(initiator_socket, addr)
            .await
            .unwrap();
        let responder_conn = responder_handle.await.unwrap().unwrap();

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
    }

    #[tokio::test]
    async fn lean_generated_pq_wrapper_completion_vectors_match_native_transport() {
        let Some(vectors) = read_pq_wrapper_vectors() else {
            return;
        };
        assert_eq!(vectors.schema_version, 4);

        let mut matched_cases = 0usize;
        for case in vectors
            .wrapper_completion_cases
            .iter()
            .filter(|case| case.wrapper_kind == "native_pq_transport")
        {
            matched_cases += 1;
            assert!(case.expected_completed, "{} completion", case.name);

            let local_is_initiator = role_is_initiator(&case.local_role);
            let peer_is_initiator = role_is_initiator(&case.peer_role);
            assert_eq!(
                local_is_initiator, case.expected_local_is_initiator,
                "{} local role",
                case.name
            );
            assert_eq!(
                peer_is_initiator, case.expected_peer_is_initiator,
                "{} peer role",
                case.name
            );
            assert_eq!(
                local_is_initiator != peer_is_initiator,
                case.expected_roles_distinct,
                "{} role distinctness",
                case.name
            );

            let (local_send_slot, local_recv_slot) = role_slot_names(local_is_initiator);
            let (peer_send_slot, peer_recv_slot) = role_slot_names(peer_is_initiator);
            assert_eq!(
                local_send_slot, case.expected_local_send_slot,
                "{} local send slot",
                case.name
            );
            assert_eq!(
                local_recv_slot, case.expected_local_recv_slot,
                "{} local recv slot",
                case.name
            );
            assert_eq!(
                peer_send_slot, case.expected_peer_send_slot,
                "{} peer send slot",
                case.name
            );
            assert_eq!(
                peer_recv_slot, case.expected_peer_recv_slot,
                "{} peer recv slot",
                case.name
            );
            assert_eq!(
                local_send_slot == peer_recv_slot,
                case.expected_local_send_matches_peer_recv,
                "{} local-send peer-recv match",
                case.name
            );
            assert_eq!(
                local_recv_slot == peer_send_slot,
                case.expected_local_recv_matches_peer_send,
                "{} local-recv peer-send match",
                case.name
            );

            let plaintext = decode_hex(&case.plaintext_hex);
            let payload_bytes = parse_u64(&case.expected_first_frame_payload_bytes);
            let tag_bytes = parse_u64(&case.expected_first_frame_tag_bytes);
            let wire_bytes = parse_u64(&case.expected_first_frame_wire_bytes);
            assert_eq!(
                plaintext.len() as u64,
                payload_bytes,
                "{} payload",
                case.name
            );
            assert_eq!(
                payload_bytes + tag_bytes,
                wire_bytes,
                "{} first-frame wire accounting",
                case.name
            );

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let local_transport = NativePqTransport::from_seed(
                format!("{}-native-local", case.name).as_bytes(),
                NativePqTransportConfig::development(),
            );
            let peer_transport = NativePqTransport::from_seed(
                format!("{}-native-peer", case.name).as_bytes(),
                NativePqTransportConfig::development(),
            );
            let local_peer_id = local_transport.local_peer_id();
            let remote_peer_id = peer_transport.local_peer_id();

            let responder_handle = tokio::spawn({
                let peer_transport = peer_transport.clone();
                async move {
                    let (socket, peer_addr) = listener.accept().await.unwrap();
                    peer_transport.upgrade_inbound(socket, peer_addr).await
                }
            });

            let local_socket = TcpStream::connect(addr).await.unwrap();
            let mut local_conn = local_transport
                .upgrade_outbound(local_socket, addr)
                .await
                .unwrap();
            let mut peer_conn = responder_handle.await.unwrap().unwrap();

            assert_eq!(
                local_conn.peer_id(),
                remote_peer_id,
                "{} local observed remote peer id",
                case.name
            );
            assert_eq!(
                peer_conn.peer_id(),
                local_peer_id,
                "{} peer observed local peer id",
                case.name
            );
            assert!(
                local_conn.is_outbound(),
                "{} local outbound flag",
                case.name
            );
            assert!(!peer_conn.is_outbound(), "{} peer inbound flag", case.name);
            assert_eq!(
                local_conn.session.is_initiator(),
                case.expected_local_is_initiator,
                "{} local session role flag",
                case.name
            );
            assert_eq!(
                peer_conn.session.is_initiator(),
                case.expected_peer_is_initiator,
                "{} peer session role flag",
                case.name
            );

            assert_eq!(
                local_conn.bytes_sent(),
                parse_u64(&case.expected_initial_local_bytes_sent),
                "{} initial local bytes sent",
                case.name
            );
            assert_eq!(
                local_conn.bytes_received(),
                parse_u64(&case.expected_initial_local_bytes_received),
                "{} initial local bytes received",
                case.name
            );
            assert_eq!(
                peer_conn.bytes_sent(),
                parse_u64(&case.expected_initial_peer_bytes_sent),
                "{} initial peer bytes sent",
                case.name
            );
            assert_eq!(
                peer_conn.bytes_received(),
                parse_u64(&case.expected_initial_peer_bytes_received),
                "{} initial peer bytes received",
                case.name
            );

            let (send_result, recv_result) =
                tokio::join!(local_conn.send(&plaintext), peer_conn.recv());
            send_result.unwrap_or_else(|err| panic!("{} native wrapper send: {err}", case.name));
            let opened = recv_result
                .unwrap_or_else(|err| panic!("{} native wrapper recv: {err}", case.name))
                .unwrap_or_else(|| panic!("{} native wrapper EOF", case.name));
            assert_eq!(opened, plaintext, "{} peer receives first frame", case.name);
            assert_eq!(
                local_conn.bytes_sent(),
                parse_u64(&case.expected_after_first_local_bytes_sent),
                "{} local bytes sent after first frame",
                case.name
            );
            assert_eq!(
                peer_conn.bytes_received(),
                parse_u64(&case.expected_after_first_peer_bytes_received),
                "{} peer bytes received after first frame",
                case.name
            );
        }

        assert!(
            matched_cases > 0,
            "Lean PQ wrapper vectors must include native_pq_transport"
        );
    }

    #[tokio::test]
    async fn test_native_transport_messaging() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let initiator = NativePqTransport::from_seed(
            b"msg-test-initiator",
            NativePqTransportConfig::development(),
        );
        let responder = NativePqTransport::from_seed(
            b"msg-test-responder",
            NativePqTransportConfig::development(),
        );

        let responder_handle = tokio::spawn({
            let responder = responder.clone();
            async move {
                let (socket, peer_addr) = listener.accept().await.unwrap();
                responder.upgrade_inbound(socket, peer_addr).await
            }
        });

        let initiator_socket = TcpStream::connect(addr).await.unwrap();
        let mut initiator_conn = initiator
            .upgrade_outbound(initiator_socket, addr)
            .await
            .unwrap();
        let mut responder_conn = responder_handle.await.unwrap().unwrap();

        // Test messaging
        initiator_conn.send(b"Hello from initiator").await.unwrap();
        let received = responder_conn.recv().await.unwrap().unwrap();
        assert_eq!(received, b"Hello from initiator".to_vec());

        responder_conn.send(b"Hello from responder").await.unwrap();
        let received = initiator_conn.recv().await.unwrap().unwrap();
        assert_eq!(received, b"Hello from responder".to_vec());
    }

    #[test]
    fn test_connection_info() {
        // Just verify the struct compiles correctly
        let info = PqConnectionInfo {
            peer_id: [0u8; 32],
            addr: "127.0.0.1:8080".parse().unwrap(),
            is_outbound: true,
            bytes_sent: 1000,
            bytes_received: 2000,
            protocol: "/hegemon/pq/1".to_string(),
        };

        assert!(info.is_outbound);
        assert_eq!(info.bytes_sent, 1000);
    }

    #[test]
    fn connection_info_metadata_does_not_change_wire_message_encoding() {
        let first = PqConnectionInfo {
            peer_id: [1u8; 32],
            addr: "127.0.0.1:30333".parse().unwrap(),
            is_outbound: true,
            bytes_sent: 1000,
            bytes_received: 2000,
            protocol: "/hegemon/pq/1".to_string(),
        };
        let second = PqConnectionInfo {
            peer_id: [2u8; 32],
            addr: "[::1]:40444".parse().unwrap(),
            is_outbound: false,
            bytes_sent: 9000,
            bytes_received: 12000,
            protocol: "/hegemon/pq/1/local-test".to_string(),
        };
        assert_ne!(first.peer_id, second.peer_id);
        assert_ne!(first.addr, second.addr);
        assert_ne!(first.is_outbound, second.is_outbound);
        assert_ne!(first.bytes_sent, second.bytes_sent);
        assert_ne!(first.bytes_received, second.bytes_received);
        assert_ne!(first.protocol, second.protocol);

        let payload = crate::p2p::WireMessage::Proto(crate::ProtocolMessage {
            protocol: 7,
            payload: b"shielded-transfer-announcement".to_vec(),
        });
        let encoded_first = crate::wire::encode(&payload, crate::wire::MAX_WIRE_FRAME_LEN).unwrap();
        let encoded_second =
            crate::wire::encode(&payload, crate::wire::MAX_WIRE_FRAME_LEN).unwrap();

        assert_eq!(encoded_first, encoded_second);
        let decoded: crate::p2p::WireMessage =
            crate::wire::decode(&encoded_first, crate::wire::MAX_WIRE_FRAME_LEN).unwrap();
        match decoded {
            crate::p2p::WireMessage::Proto(message) => {
                assert_eq!(message.protocol, 7);
                assert_eq!(message.payload, b"shielded-transfer-announcement".to_vec());
            }
            other => panic!("decoded unexpected wire message: {other:?}"),
        }
    }
}
