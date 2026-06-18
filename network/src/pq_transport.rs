//! PQ Transport integration for the network layer
//!
//! This module provides integration between the pq-noise crate and the
//! network layer, enabling post-quantum secure peer connections.

use crate::p2p::WireMessage;
use crate::wire;
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
        let bytes = wire::encode(&msg, wire::MAX_WIRE_FRAME_LEN)?;
        self.session
            .send(&bytes)
            .await
            .map_err(|e| NetworkError::Io(std::io::Error::other(e.to_string())))
    }

    /// Receive a wire message
    pub async fn recv(&mut self) -> Result<Option<WireMessage>, NetworkError> {
        match self.session.recv().await {
            Ok(Some(data)) => {
                let msg = wire::decode(&data, wire::MAX_WIRE_FRAME_LEN)?;
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

    #[tokio::test]
    async fn lean_generated_pq_wrapper_completion_vectors_match_network_transport() {
        let Some(vectors) = read_pq_wrapper_vectors() else {
            return;
        };
        assert_eq!(vectors.schema_version, 4);

        let mut matched_cases = 0usize;
        for case in vectors
            .wrapper_completion_cases
            .iter()
            .filter(|case| case.wrapper_kind == "network_pq_transport")
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
            let local_identity = PqPeerIdentity::new(
                format!("{}-network-local", case.name).as_bytes(),
                PqTransportConfig::development(),
            );
            let peer_identity = PqPeerIdentity::new(
                format!("{}-network-peer", case.name).as_bytes(),
                PqTransportConfig::development(),
            );
            let local_peer_id = local_identity.peer_id();
            let remote_peer_id = peer_identity.peer_id();

            let responder_handle = tokio::spawn(async move {
                let (socket, peer_addr) = listener.accept().await.unwrap();
                upgrade_inbound(&peer_identity, socket, peer_addr).await
            });

            let local_socket = TcpStream::connect(addr).await.unwrap();
            let mut local_conn = upgrade_outbound(&local_identity, local_socket, addr)
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

            let (send_result, recv_result) = tokio::join!(
                local_conn.session.send(&plaintext),
                peer_conn.session.recv()
            );
            send_result.unwrap_or_else(|err| panic!("{} network wrapper send: {err}", case.name));
            let opened = recv_result
                .unwrap_or_else(|err| panic!("{} network wrapper recv: {err}", case.name))
                .unwrap_or_else(|| panic!("{} network wrapper EOF", case.name));
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
            "Lean PQ wrapper vectors must include network_pq_transport"
        );
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
