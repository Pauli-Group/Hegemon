//! Secure session for encrypted communication

use crate::error::{PqNoiseError, Result};
use crate::noise::NoiseCipher;
use crate::types::{PeerId, RemotePeer, SessionKeys};
use bincode::Options;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

const SESSION_MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

fn session_bincode() -> impl Options {
    bincode::DefaultOptions::new().with_limit(SESSION_MAX_FRAME_LEN as u64)
}

/// A secure, encrypted session established after a successful PQ handshake
pub struct SecureSession<S> {
    /// The underlying framed stream
    stream: Framed<S, LengthDelimitedCodec>,
    /// Noise cipher for encryption/decryption
    cipher: NoiseCipher,
    /// Remote peer information
    remote_peer: RemotePeer,
    /// Whether this side was the initiator
    is_initiator: bool,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes received
    bytes_received: u64,
}

impl<S> SecureSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new secure session from handshake results
    pub fn new(
        socket: S,
        keys: SessionKeys,
        remote_peer: RemotePeer,
        is_initiator: bool,
    ) -> Result<Self> {
        let mut codec = LengthDelimitedCodec::new();
        codec.set_max_frame_length(SESSION_MAX_FRAME_LEN); // 16 MB max frame

        let stream = Framed::new(socket, codec);
        let cipher = NoiseCipher::new(&keys, is_initiator)?;

        Ok(Self {
            stream,
            cipher,
            remote_peer,
            is_initiator,
            bytes_sent: 0,
            bytes_received: 0,
        })
    }

    /// Get the remote peer's ID
    pub fn remote_peer_id(&self) -> PeerId {
        self.remote_peer.peer_id
    }

    /// Get the remote peer info
    pub fn remote_peer(&self) -> &RemotePeer {
        &self.remote_peer
    }

    /// Check if this side was the initiator
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Get bytes sent
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Get bytes received
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Send an encrypted message
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        let encrypted = self.cipher.encrypt(data)?;
        self.bytes_sent += encrypted.len() as u64;
        self.stream
            .send(Bytes::from(encrypted))
            .await
            .map_err(PqNoiseError::from)
    }

    /// Receive and decrypt a message
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        match self.stream.next().await {
            Some(Ok(frame)) => {
                self.bytes_received += frame.len() as u64;
                let decrypted = self.cipher.decrypt(&frame)?;
                Ok(Some(decrypted))
            }
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    /// Send a serializable message
    pub async fn send_message<M: serde::Serialize>(&mut self, message: &M) -> Result<()> {
        let data = session_bincode().serialize(message)?;
        self.send(&data).await
    }

    /// Receive and deserialize a message
    pub async fn recv_message<M: serde::de::DeserializeOwned>(&mut self) -> Result<Option<M>> {
        match self.recv().await? {
            Some(data) => {
                let message = session_bincode().deserialize(&data)?;
                Ok(Some(message))
            }
            None => Ok(None),
        }
    }

    /// Close the session gracefully
    pub async fn close(mut self) -> Result<()> {
        self.stream.close().await.map_err(PqNoiseError::from)
    }

    /// Get the underlying stream (consumes the session)
    pub fn into_inner(self) -> Framed<S, LengthDelimitedCodec> {
        self.stream
    }
}

/// Statistics about a secure session
#[derive(Clone, Debug, Default)]
pub struct SessionStats {
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
    /// Session duration in milliseconds
    pub duration_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PqNoiseConfig;
    use crate::handshake::PqHandshake;
    use crate::types::LocalIdentity;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_secure_session_round_trip() {
        let initiator_identity = LocalIdentity::generate(b"session-test-initiator");
        let responder_identity = LocalIdentity::generate(b"session-test-responder");

        let initiator_config = PqNoiseConfig::new(initiator_identity.clone());
        let responder_config = PqNoiseConfig::new(responder_identity.clone());

        // Perform handshake
        let mut initiator_hs = PqHandshake::new(initiator_config);
        let mut responder_hs = PqHandshake::new(responder_config);

        let init_hello = match initiator_hs.initiator_hello().unwrap() {
            crate::types::HandshakeMessage::InitHello(msg) => msg,
            _ => panic!("Expected InitHello"),
        };

        let resp_hello = match responder_hs
            .responder_process_init_hello(init_hello)
            .unwrap()
        {
            crate::types::HandshakeMessage::RespHello(msg) => msg,
            _ => panic!("Expected RespHello"),
        };

        let finish = match initiator_hs
            .initiator_process_resp_hello(resp_hello)
            .unwrap()
        {
            crate::types::HandshakeMessage::Finish(msg) => msg,
            _ => panic!("Expected Finish"),
        };

        let responder_keys = responder_hs.responder_process_finish(finish).unwrap();
        let initiator_keys = initiator_hs.initiator_complete().unwrap();

        // Create mock streams
        let (initiator_stream, responder_stream) = duplex(8192);

        let initiator_remote = responder_hs.remote_peer().unwrap().clone();
        let responder_remote = initiator_hs.remote_peer().unwrap().clone();

        let mut initiator_session =
            SecureSession::new(initiator_stream, initiator_keys, initiator_remote, true).unwrap();
        let mut responder_session =
            SecureSession::new(responder_stream, responder_keys, responder_remote, false).unwrap();

        // Test message exchange
        let test_message = b"Hello, quantum-secure world!";

        let (send_result, recv_result) = tokio::join!(
            initiator_session.send(test_message),
            responder_session.recv()
        );

        send_result.unwrap();
        let received = recv_result.unwrap().unwrap();
        assert_eq!(received, test_message.to_vec());

        // Test reverse direction
        let response = b"Response from responder";

        let (send_result, recv_result) =
            tokio::join!(responder_session.send(response), initiator_session.recv());

        send_result.unwrap();
        let received = recv_result.unwrap().unwrap();
        assert_eq!(received, response.to_vec());
    }

    #[tokio::test]
    async fn test_session_stats() {
        let identity1 = LocalIdentity::generate(b"stats-test-1");
        let identity2 = LocalIdentity::generate(b"stats-test-2");

        let config1 = PqNoiseConfig::new(identity1.clone());
        let config2 = PqNoiseConfig::new(identity2.clone());

        // Quick handshake
        let mut hs1 = PqHandshake::new(config1);
        let mut hs2 = PqHandshake::new(config2);

        let init = match hs1.initiator_hello().unwrap() {
            crate::types::HandshakeMessage::InitHello(m) => m,
            _ => panic!(),
        };
        let resp = match hs2.responder_process_init_hello(init).unwrap() {
            crate::types::HandshakeMessage::RespHello(m) => m,
            _ => panic!(),
        };
        let fin = match hs1.initiator_process_resp_hello(resp).unwrap() {
            crate::types::HandshakeMessage::Finish(m) => m,
            _ => panic!(),
        };
        let keys2 = hs2.responder_process_finish(fin).unwrap();
        let keys1 = hs1.initiator_complete().unwrap();

        let (s1, s2) = duplex(8192);
        let remote1 = hs2.remote_peer().unwrap().clone();
        let remote2 = hs1.remote_peer().unwrap().clone();

        let mut session1 = SecureSession::new(s1, keys1, remote1, true).unwrap();
        let mut session2 = SecureSession::new(s2, keys2, remote2, false).unwrap();

        // Send some data
        let data = vec![0u8; 1000];
        session1.send(&data).await.unwrap();
        session2.recv().await.unwrap();

        // Check stats
        assert!(session1.bytes_sent() > 0);
        assert!(session2.bytes_received() > 0);
    }
}
