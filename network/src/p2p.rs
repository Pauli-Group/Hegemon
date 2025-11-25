use crate::{
    GossipMessage, HandshakeAcceptance, HandshakeConfirmation, HandshakeOffer, NetworkError,
    PeerId, PeerIdentity, ProtocolMessage, SecureChannel,
};
use crypto::hashes::sha256;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::bytes::Bytes;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

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
            stream: Framed::new(socket, LengthDelimitedCodec::new()),
            channel: None,
        }
    }

    pub async fn handshake_initiator(
        &mut self,
        identity: &PeerIdentity,
    ) -> Result<PeerId, NetworkError> {
        // 1. Create and send offer
        let offer = identity.create_offer()?;
        let offer_bytes = bincode::serialize(&offer)?;
        self.send_raw(&offer_bytes).await?;

        // 2. Receive acceptance
        let acceptance_bytes = self.recv_raw().await?;
        let acceptance: HandshakeAcceptance = bincode::deserialize(&acceptance_bytes)?;

        // 3. Finalize handshake
        let (channel, _confirmation, confirmation_bytes) =
            identity.finalize_handshake(&offer, &acceptance, &offer_bytes, &acceptance_bytes)?;

        let peer_id = sha256(&acceptance.identity_key);

        // 4. Send confirmation
        self.send_raw(&confirmation_bytes).await?;

        // 5. Set channel
        self.channel = Some(channel);

        Ok(peer_id)
    }

    pub async fn handshake_responder(
        &mut self,
        identity: &PeerIdentity,
    ) -> Result<PeerId, NetworkError> {
        // 1. Receive offer
        let offer_bytes = self.recv_raw().await?;
        let offer: HandshakeOffer = bincode::deserialize(&offer_bytes)?;

        // 2. Accept offer
        let (_acceptance, responder_secret, acceptance_bytes) = identity.accept_offer(&offer)?;
        self.send_raw(&acceptance_bytes).await?;

        // 3. Receive confirmation
        let confirmation_bytes = self.recv_raw().await?;
        let confirmation: HandshakeConfirmation = bincode::deserialize(&confirmation_bytes)?;

        // 4. Complete handshake
        let offer_bytes = bincode::serialize(&offer)?;
        let channel = identity.complete_handshake(
            &offer,
            &confirmation,
            &offer_bytes,
            &acceptance_bytes,
            &confirmation_bytes,
            responder_secret,
        )?;

        let peer_id = sha256(&offer.identity_key);

        // 5. Set channel
        self.channel = Some(channel);

        Ok(peer_id)
    }

    pub async fn send(&mut self, msg: WireMessage) -> Result<(), NetworkError> {
        let bytes = bincode::serialize(&msg)?;
        if let Some(channel) = &mut self.channel {
            let encrypted = channel.encrypt(&bytes)?;
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
            let decrypted = channel.decrypt(&frame)?;
            let msg = bincode::deserialize(&decrypted)?;
            Ok(Some(msg))
        } else {
            Err(NetworkError::Handshake("connection not encrypted"))
        }
    }

    async fn send_raw(&mut self, bytes: &[u8]) -> Result<(), NetworkError> {
        self.stream.send(Bytes::copy_from_slice(bytes)).await?;
        Ok(())
    }

    async fn recv_raw(&mut self) -> Result<Vec<u8>, NetworkError> {
        match self.stream.next().await {
            Some(Ok(bytes)) => Ok(bytes.to_vec()),
            Some(Err(e)) => Err(e.into()),
            None => Err(NetworkError::Handshake("connection closed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
