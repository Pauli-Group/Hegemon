use crate::{
    GossipMessage, HandshakeAcceptance, HandshakeConfirmation, HandshakeOffer, NetworkError,
    PeerId, PeerIdentity, ProtocolMessage, SecureChannel,
};
use crypto::hashes::sha256;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_util::bytes::Bytes;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WireMessage {
    Ping,
    Pong,
    Gossip(GossipMessage),
    Proto(ProtocolMessage),
}

pub struct Connection {
    stream: Framed<TcpStream, LengthDelimitedCodec>,
    channel: Option<SecureChannel>,
}

impl Connection {
    pub fn new(socket: TcpStream) -> Self {
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
    use tokio::net::TcpListener;
    use tokio::task;

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
}
