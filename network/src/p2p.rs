use crate::{
    GossipMessage, HandshakeAcceptance, HandshakeConfirmation, HandshakeOffer, NetworkError,
    PeerId, PeerIdentity, ProtocolMessage, SecureChannel, wire,
};
use crypto::hashes::sha256;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::bytes::Bytes;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

fn length_delimited_codec(max_frame_len: usize) -> LengthDelimitedCodec {
    let mut codec = LengthDelimitedCodec::new();
    codec.set_max_frame_length(max_frame_len);
    codec
}

fn handshake_codec() -> LengthDelimitedCodec {
    length_delimited_codec(wire::MAX_HANDSHAKE_FRAME_LEN)
}

fn identity_finalize_handshake_for_connection(
    identity: &PeerIdentity,
    offer: &HandshakeOffer,
    acceptance: &HandshakeAcceptance,
    offer_bytes: &[u8],
    acceptance_bytes: &[u8],
) -> Result<(SecureChannel, HandshakeConfirmation, Vec<u8>), NetworkError> {
    identity.finalize_handshake(offer, acceptance, offer_bytes, acceptance_bytes)
}

fn identity_complete_handshake_for_connection(
    identity: &PeerIdentity,
    offer: &HandshakeOffer,
    acceptance: &HandshakeAcceptance,
    confirmation: &HandshakeConfirmation,
    offer_bytes: &[u8],
    acceptance_bytes: &[u8],
    confirmation_bytes: &[u8],
    responder_secret: crate::MlKemSharedSecret,
) -> Result<SecureChannel, NetworkError> {
    identity.complete_handshake(
        offer,
        acceptance,
        confirmation,
        offer_bytes,
        acceptance_bytes,
        confirmation_bytes,
        responder_secret,
    )
}

fn encrypt_connection_frame(
    channel: &mut SecureChannel,
    plaintext: &[u8],
) -> Result<Vec<u8>, NetworkError> {
    channel.encrypt(plaintext)
}

fn decrypt_connection_frame(
    channel: &mut SecureChannel,
    ciphertext: &[u8],
) -> Result<Vec<u8>, NetworkError> {
    channel.decrypt(ciphertext)
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum CompactAddress {
    V4 { ip: [u8; 4], port: u16 },
    V6 { ip: [u8; 16], port: u16 },
}

impl From<SocketAddr> for CompactAddress {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::V4 {
                ip: v4.ip().octets(),
                port: v4.port(),
            },
            SocketAddr::V6(v6) => Self::V6 {
                ip: v6.ip().octets(),
                port: v6.port(),
            },
        }
    }
}

impl CompactAddress {
    pub fn to_socket_addr(&self) -> SocketAddr {
        match self {
            CompactAddress::V4 { ip, port } => SocketAddr::from((Ipv4Addr::from(*ip), *port)),
            CompactAddress::V6 { ip, port } => SocketAddr::from((Ipv6Addr::from(*ip), *port)),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CoordinationMessage {
    GetAddr {
        limit: u16,
    },
    Addr {
        addrs: Vec<CompactAddress>,
    },
    PunchRequest {
        target: PeerId,
        requester_addr: CompactAddress,
    },
    PunchResponse {
        target: PeerId,
        responder_addr: CompactAddress,
    },
    RelayRegistration {
        reachable: Vec<CompactAddress>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WireMessage {
    Ping,
    Pong,
    Gossip(GossipMessage),
    Proto(ProtocolMessage),
    AddrExchange(Vec<CompactAddress>),
    Coordinate(CoordinationMessage),
}

pub struct Connection<S> {
    stream: Framed<S, LengthDelimitedCodec>,
    channel: Option<SecureChannel>,
}

impl<S> Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(socket: S) -> Self {
        Self {
            stream: Framed::new(socket, handshake_codec()),
            channel: None,
        }
    }

    fn promote_to_secure_wire_codec(&mut self) {
        self.stream
            .codec_mut()
            .set_max_frame_length(wire::MAX_WIRE_FRAME_LEN);
    }

    pub async fn handshake_initiator(
        &mut self,
        identity: &PeerIdentity,
    ) -> Result<PeerId, NetworkError> {
        // 1. Create and send offer
        let offer = identity.create_offer()?;
        let offer_bytes = wire::encode(&offer, wire::MAX_HANDSHAKE_FRAME_LEN)?;
        self.send_raw(&offer_bytes).await?;

        // 2. Receive acceptance
        let acceptance_bytes = self.recv_raw().await?;
        let acceptance: HandshakeAcceptance =
            wire::decode(&acceptance_bytes, wire::MAX_HANDSHAKE_FRAME_LEN)?;

        // 3. Finalize handshake
        let (channel, _confirmation, confirmation_bytes) =
            identity_finalize_handshake_for_connection(
                identity,
                &offer,
                &acceptance,
                &offer_bytes,
                &acceptance_bytes,
            )?;

        let peer_id = sha256(&acceptance.identity_key);

        // 4. Send confirmation
        self.send_raw(&confirmation_bytes).await?;

        // 5. Set channel
        self.promote_to_secure_wire_codec();
        self.channel = Some(channel);

        Ok(peer_id)
    }

    pub async fn handshake_responder(
        &mut self,
        identity: &PeerIdentity,
    ) -> Result<PeerId, NetworkError> {
        // 1. Receive offer
        let offer_bytes = self.recv_raw().await?;
        let offer: HandshakeOffer = wire::decode(&offer_bytes, wire::MAX_HANDSHAKE_FRAME_LEN)?;

        // 2. Accept offer
        let (acceptance, responder_secret, acceptance_bytes) = identity.accept_offer(&offer)?;
        self.send_raw(&acceptance_bytes).await?;

        // 3. Receive confirmation
        let confirmation_bytes = self.recv_raw().await?;
        let confirmation: HandshakeConfirmation =
            wire::decode(&confirmation_bytes, wire::MAX_HANDSHAKE_FRAME_LEN)?;

        // 4. Complete handshake
        let offer_bytes = wire::encode(&offer, wire::MAX_HANDSHAKE_FRAME_LEN)?;
        let channel = identity_complete_handshake_for_connection(
            identity,
            &offer,
            &acceptance,
            &confirmation,
            &offer_bytes,
            &acceptance_bytes,
            &confirmation_bytes,
            responder_secret,
        )?;

        let peer_id = sha256(&offer.identity_key);

        // 5. Set channel
        self.promote_to_secure_wire_codec();
        self.channel = Some(channel);

        Ok(peer_id)
    }

    pub async fn send(&mut self, msg: WireMessage) -> Result<(), NetworkError> {
        let bytes = wire::encode(&msg, wire::MAX_WIRE_FRAME_LEN)?;
        if bytes.len() > wire::MAX_WIRE_FRAME_LEN {
            return Err(NetworkError::Handshake("wire message too large"));
        }
        if let Some(channel) = &mut self.channel {
            let encrypted = encrypt_connection_frame(channel, &bytes)?;
            if encrypted.len() > wire::MAX_WIRE_FRAME_LEN {
                return Err(NetworkError::Handshake("encrypted frame too large"));
            }
            self.stream.send(Bytes::copy_from_slice(&encrypted)).await?;
        } else {
            return Err(NetworkError::Handshake("connection not encrypted"));
        }
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Option<WireMessage>, NetworkError> {
        let frame = match self.stream.next().await {
            Some(Ok(frame)) => frame,
            Some(Err(e)) => return Err(e.into()),
            None => return Ok(None),
        };

        if let Some(channel) = &mut self.channel {
            let decrypted = decrypt_connection_frame(channel, &frame)?;
            let msg = wire::decode(&decrypted, wire::MAX_WIRE_FRAME_LEN)?;
            Ok(Some(msg))
        } else {
            Err(NetworkError::Handshake("connection not encrypted"))
        }
    }

    async fn send_raw(&mut self, bytes: &[u8]) -> Result<(), NetworkError> {
        if bytes.len() > wire::MAX_HANDSHAKE_FRAME_LEN {
            return Err(NetworkError::Handshake("handshake frame too large"));
        }
        self.stream.send(Bytes::copy_from_slice(bytes)).await?;
        Ok(())
    }

    async fn recv_raw(&mut self) -> Result<Vec<u8>, NetworkError> {
        match self.stream.next().await {
            Some(Ok(bytes)) => {
                if bytes.len() > wire::MAX_HANDSHAKE_FRAME_LEN {
                    return Err(NetworkError::Handshake("handshake frame too large"));
                }
                Ok(bytes.to_vec())
            }
            Some(Err(e)) => Err(e.into()),
            None => Err(NetworkError::Handshake("connection closed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PqConnectionInfo, RelayConfig};
    use tokio::io::duplex;
    use tokio::net::TcpListener;
    use tokio::net::TcpStream;
    use tokio::task;

    #[test]
    fn compact_address_roundtrip() {
        let ipv4: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let ipv6: SocketAddr = "[::1]:9001".parse().unwrap();

        assert_eq!(CompactAddress::from(ipv4).to_socket_addr(), ipv4);
        assert_eq!(CompactAddress::from(ipv6).to_socket_addr(), ipv6);
    }

    #[test]
    fn pq_connection_info_and_relay_config_do_not_change_wire_or_consensus_payload_projection() {
        fn proto_wire_and_payload_projection(
            _connection: &PqConnectionInfo,
            _relay: &RelayConfig,
            msg: &ProtocolMessage,
        ) -> (Vec<u8>, Vec<u8>) {
            let encoded = wire::encode(&WireMessage::Proto(msg.clone()), wire::MAX_WIRE_FRAME_LEN)
                .expect("encode proto wire message");
            let decoded: WireMessage = wire::decode(&encoded, wire::MAX_WIRE_FRAME_LEN)
                .expect("decode proto wire message");
            let payload = match decoded {
                WireMessage::Proto(proto) => proto.payload,
                other => panic!("expected proto wire message, got {other:?}"),
            };
            (encoded, payload)
        }

        fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
            !needle.is_empty()
                && haystack
                    .windows(needle.len())
                    .any(|window| window == needle)
        }

        let consensus_payload = b"consensus-payload-v1".to_vec();
        let msg = ProtocolMessage {
            protocol: 0x4847_0001,
            payload: consensus_payload.clone(),
        };
        let connection_a = PqConnectionInfo {
            peer_id: [0xa5; 32],
            addr: "10.254.0.11:30333".parse().unwrap(),
            is_outbound: true,
            bytes_sent: 0x1111_2222_3333_4444,
            bytes_received: 0x5555_6666_7777_8888,
            protocol: "local-pq-relay-alpha-sentinel".to_string(),
        };
        let relay_a = RelayConfig {
            allow_relay: true,
            relays: vec!["relay-alpha-sentinel.invalid:30333".to_string()],
        };
        let connection_b = PqConnectionInfo {
            peer_id: [0x5a; 32],
            addr: "10.254.0.22:40444".parse().unwrap(),
            is_outbound: false,
            bytes_sent: 0x9999_aaaa_bbbb_cccc,
            bytes_received: 0xdddd_eeee_ffff_0001,
            protocol: "local-pq-relay-beta-sentinel".to_string(),
        };
        let relay_b = RelayConfig {
            allow_relay: false,
            relays: vec!["relay-beta-sentinel.invalid:40444".to_string()],
        };

        let (wire_a, payload_a) = proto_wire_and_payload_projection(&connection_a, &relay_a, &msg);
        let (wire_b, payload_b) = proto_wire_and_payload_projection(&connection_b, &relay_b, &msg);

        assert_eq!(wire_a, wire_b);
        assert_eq!(payload_a, consensus_payload);
        assert_eq!(payload_b, consensus_payload);

        for forbidden in [
            &connection_a.peer_id[..],
            connection_a.protocol.as_bytes(),
            relay_a.relays[0].as_bytes(),
            &connection_b.peer_id[..],
            connection_b.protocol.as_bytes(),
            relay_b.relays[0].as_bytes(),
        ] {
            assert!(!contains_subslice(&wire_a, forbidden));
            assert!(!contains_subslice(&wire_b, forbidden));
            assert!(!contains_subslice(&payload_a, forbidden));
            assert!(!contains_subslice(&payload_b, forbidden));
        }
    }

    #[tokio::test]
    async fn connection_handshake_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let initiator = PeerIdentity::generate(b"handshake-initiator");
        let responder = PeerIdentity::generate(b"handshake-responder");

        let responder_task = task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut connection = Connection::new(socket);
            connection
                .handshake_responder(&responder)
                .await
                .expect("handshake responder");
            connection
        });

        let mut initiator_conn = {
            let socket = TcpStream::connect(addr).await.expect("connect");
            let mut connection = Connection::new(socket);
            connection
                .handshake_initiator(&initiator)
                .await
                .expect("handshake initiator");
            connection
        };

        let mut responder_conn = responder_task.await.expect("responder task");

        initiator_conn
            .send(WireMessage::Ping)
            .await
            .expect("send ping");
        match responder_conn.recv().await.expect("receive message") {
            Some(WireMessage::Ping) => {}
            other => panic!("unexpected message: {:?}", other),
        }
    }

    #[tokio::test]
    async fn pq_handshake_works_over_mock_streams() {
        let initiator_identity = PeerIdentity::generate(b"mock-initiator");
        let responder_identity = PeerIdentity::generate(b"mock-responder");
        let (initiator_stream, responder_stream) = duplex(2048);

        let (initiator_peer, responder_peer) = tokio::try_join!(
            async {
                let mut conn = Connection::new(initiator_stream);
                conn.handshake_initiator(&initiator_identity).await
            },
            async {
                let mut conn = Connection::new(responder_stream);
                conn.handshake_responder(&responder_identity).await
            }
        )
        .expect("handshakes should succeed");

        assert_eq!(initiator_peer, responder_identity.peer_id());
        assert_eq!(responder_peer, initiator_identity.peer_id());
    }

    #[tokio::test]
    async fn oversized_handshake_frame_is_rejected() {
        let responder_identity = PeerIdentity::generate(b"oversized-handshake-responder");
        let (client_stream, responder_stream) = duplex(wire::MAX_HANDSHAKE_FRAME_LEN * 2);

        let responder_task = task::spawn(async move {
            let mut conn = Connection::new(responder_stream);
            conn.handshake_responder(&responder_identity).await
        });

        let mut raw = Framed::new(
            client_stream,
            length_delimited_codec(wire::MAX_HANDSHAKE_FRAME_LEN + 1),
        );
        raw.send(Bytes::from(vec![0u8; wire::MAX_HANDSHAKE_FRAME_LEN + 1]))
            .await
            .expect("send oversized handshake frame");

        let err = responder_task
            .await
            .expect("responder task")
            .expect_err("oversized handshake should fail");
        let err = err.to_string();
        assert!(
            err.contains("handshake frame too large") || err.contains("frame"),
            "unexpected handshake rejection: {err}"
        );
    }

    #[tokio::test]
    async fn encrypted_frames_round_trip_after_handshake() {
        let initiator_identity = PeerIdentity::generate(b"encrypted-initiator");
        let responder_identity = PeerIdentity::generate(b"encrypted-responder");
        let (initiator_stream, responder_stream) = duplex(4096);

        let mut initiator_conn = Connection::new(initiator_stream);
        let mut responder_conn = Connection::new(responder_stream);

        tokio::try_join!(
            initiator_conn.handshake_initiator(&initiator_identity),
            responder_conn.handshake_responder(&responder_identity)
        )
        .expect("handshakes should succeed");

        initiator_conn
            .send(WireMessage::Ping)
            .await
            .expect("encrypted ping send");
        responder_conn
            .send(WireMessage::Pong)
            .await
            .expect("encrypted pong send");

        match responder_conn.recv().await.expect("responder decrypt") {
            Some(WireMessage::Ping) => {}
            other => panic!("expected ping, got {:?}", other),
        }

        match initiator_conn.recv().await.expect("initiator decrypt") {
            Some(WireMessage::Pong) => {}
            other => panic!("expected pong, got {:?}", other),
        }
    }
}
