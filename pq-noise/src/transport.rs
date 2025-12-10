//! PQ-secure transport layer

use crate::config::PqNoiseConfig;
use crate::error::{HandshakeError, PqNoiseError, Result};
use crate::handshake::PqHandshake;
use crate::session::SecureSession;
use crate::types::{HandshakeMessage, PeerId};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// PQ-secure transport layer for establishing secure connections
pub struct PqTransport {
    config: PqNoiseConfig,
}

impl PqTransport {
    /// Create a new PQ transport with the given configuration
    pub fn new(config: PqNoiseConfig) -> Self {
        Self { config }
    }

    /// Get the local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.config.local_peer_id()
    }

    /// Upgrade a socket connection as the initiator
    ///
    /// Returns a secure session and the remote peer ID
    pub async fn upgrade_outbound<S>(&self, socket: S) -> Result<(SecureSession<S>, PeerId)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let handshake_timeout = self.config.handshake_timeout;
        timeout(handshake_timeout, self.do_initiator_handshake(socket))
            .await
            .map_err(|_| PqNoiseError::Timeout)?
    }

    /// Upgrade a socket connection as the responder
    ///
    /// Returns a secure session and the remote peer ID
    pub async fn upgrade_inbound<S>(&self, socket: S) -> Result<(SecureSession<S>, PeerId)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let handshake_timeout = self.config.handshake_timeout;
        timeout(handshake_timeout, self.do_responder_handshake(socket))
            .await
            .map_err(|_| PqNoiseError::Timeout)?
    }

    async fn do_initiator_handshake<S>(&self, socket: S) -> Result<(SecureSession<S>, PeerId)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut framed = Framed::new(socket, LengthDelimitedCodec::new());
        let mut handshake = PqHandshake::new(self.config.clone());

        // Step 1: Send InitHello
        let init_hello = handshake.initiator_hello()?;
        let init_bytes = bincode::serialize(&init_hello)?;
        framed.send(Bytes::from(init_bytes)).await?;

        if self.config.verbose_logging {
            tracing::debug!("Sent InitHello");
        }

        // Step 2: Receive RespHello
        let resp_frame = framed
            .next()
            .await
            .ok_or(HandshakeError::ConnectionClosed)??;
        let resp_hello: HandshakeMessage = bincode::deserialize(&resp_frame)?;
        let resp_hello_msg = match resp_hello {
            HandshakeMessage::RespHello(msg) => msg,
            other => {
                return Err(HandshakeError::UnexpectedMessage {
                    expected: "RespHello",
                    got: other.message_type(),
                }
                .into())
            }
        };

        if self.config.verbose_logging {
            tracing::debug!("Received RespHello");
        }

        // Step 3: Process RespHello and send Finish
        let finish = handshake.initiator_process_resp_hello(resp_hello_msg)?;
        let finish_bytes = bincode::serialize(&finish)?;
        framed.send(Bytes::from(finish_bytes)).await?;

        if self.config.verbose_logging {
            tracing::debug!("Sent Finish");
        }

        // Step 4: Complete handshake
        let session_keys = handshake.initiator_complete()?;
        let remote_peer = handshake
            .remote_peer()
            .cloned()
            .ok_or(HandshakeError::InvalidState)?;
        let peer_id = remote_peer.peer_id;

        if self.config.verbose_logging {
            tracing::info!(
                peer_id = %hex::encode(peer_id),
                "PQ handshake complete with ML-KEM-768"
            );
        }

        // Convert framed stream back to raw socket
        let socket = framed.into_inner();
        let session = SecureSession::new(socket, session_keys, remote_peer, true)?;

        Ok((session, peer_id))
    }

    async fn do_responder_handshake<S>(&self, socket: S) -> Result<(SecureSession<S>, PeerId)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut framed = Framed::new(socket, LengthDelimitedCodec::new());
        let mut handshake = PqHandshake::new(self.config.clone());

        // Step 1: Receive InitHello
        let init_frame = framed
            .next()
            .await
            .ok_or(HandshakeError::ConnectionClosed)??;
        let init_hello: HandshakeMessage = bincode::deserialize(&init_frame)?;
        let init_hello_msg = match init_hello {
            HandshakeMessage::InitHello(msg) => msg,
            other => {
                return Err(HandshakeError::UnexpectedMessage {
                    expected: "InitHello",
                    got: other.message_type(),
                }
                .into())
            }
        };

        if self.config.verbose_logging {
            tracing::debug!("Received InitHello");
        }

        // Step 2: Process InitHello and send RespHello
        let resp_hello = handshake.responder_process_init_hello(init_hello_msg)?;
        let resp_bytes = bincode::serialize(&resp_hello)?;
        framed.send(Bytes::from(resp_bytes)).await?;

        if self.config.verbose_logging {
            tracing::debug!("Sent RespHello");
        }

        // Step 3: Receive Finish
        let finish_frame = framed
            .next()
            .await
            .ok_or(HandshakeError::ConnectionClosed)??;
        let finish: HandshakeMessage = bincode::deserialize(&finish_frame)?;
        let finish_msg = match finish {
            HandshakeMessage::Finish(msg) => msg,
            other => {
                return Err(HandshakeError::UnexpectedMessage {
                    expected: "Finish",
                    got: other.message_type(),
                }
                .into())
            }
        };

        if self.config.verbose_logging {
            tracing::debug!("Received Finish");
        }

        // Step 4: Complete handshake
        let session_keys = handshake.responder_process_finish(finish_msg)?;
        let remote_peer = handshake
            .remote_peer()
            .cloned()
            .ok_or(HandshakeError::InvalidState)?;
        let peer_id = remote_peer.peer_id;

        if self.config.verbose_logging {
            tracing::info!(
                peer_id = %hex::encode(peer_id),
                "PQ handshake complete with ML-KEM-768"
            );
        }

        // Convert framed stream back to raw socket
        let socket = framed.into_inner();
        let session = SecureSession::new(socket, session_keys, remote_peer, false)?;

        Ok((session, peer_id))
    }
}

/// Transport configuration builder
pub struct PqTransportBuilder {
    identity_seed: Option<Vec<u8>>,
    require_pq: bool,
    handshake_timeout: Duration,
    verbose_logging: bool,
}

impl Default for PqTransportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PqTransportBuilder {
    /// Create a new transport builder
    pub fn new() -> Self {
        Self {
            identity_seed: None,
            require_pq: true,
            handshake_timeout: Duration::from_secs(30),
            verbose_logging: false,
        }
    }

    /// Set the identity seed
    pub fn identity_seed(mut self, seed: impl Into<Vec<u8>>) -> Self {
        self.identity_seed = Some(seed.into());
        self
    }

    /// Set whether PQ is required
    pub fn require_pq(mut self, require: bool) -> Self {
        self.require_pq = require;
        self
    }

    /// Set the handshake timeout
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Enable verbose logging
    pub fn verbose(mut self) -> Self {
        self.verbose_logging = true;
        self
    }

    /// Build the transport
    pub fn build(self) -> Result<PqTransport> {
        let seed = self
            .identity_seed
            .ok_or_else(|| PqNoiseError::InvalidConfig("identity seed is required".to_string()))?;

        let identity = crate::types::LocalIdentity::generate(&seed);
        let config = PqNoiseConfig {
            identity,
            require_pq: self.require_pq,
            handshake_timeout: self.handshake_timeout,
            max_handshake_message_size: 16 * 1024,
            verbose_logging: self.verbose_logging,
        };

        Ok(PqTransport::new(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::LocalIdentity;
    use tokio::io::duplex;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn test_transport_upgrade_duplex() {
        let initiator_identity = LocalIdentity::generate(b"transport-test-initiator");
        let responder_identity = LocalIdentity::generate(b"transport-test-responder");

        let initiator_config = PqNoiseConfig::new(initiator_identity, false);
        let responder_config = PqNoiseConfig::new(responder_identity, false);

        let initiator_transport = PqTransport::new(initiator_config);
        let responder_transport = PqTransport::new(responder_config);

        let (initiator_stream, responder_stream) = duplex(8192);

        let (initiator_result, responder_result) = tokio::join!(
            initiator_transport.upgrade_outbound(initiator_stream),
            responder_transport.upgrade_inbound(responder_stream)
        );

        let (mut initiator_session, initiator_peer_id) = initiator_result.unwrap();
        let (mut responder_session, responder_peer_id) = responder_result.unwrap();

        // Verify peer IDs
        assert_eq!(initiator_peer_id, responder_transport.local_peer_id());
        assert_eq!(responder_peer_id, initiator_transport.local_peer_id());

        // Test communication
        let message = b"Test message via transport";

        let (send_result, recv_result) =
            tokio::join!(initiator_session.send(message), responder_session.recv());

        send_result.unwrap();
        let received = recv_result.unwrap().unwrap();
        assert_eq!(received, message.to_vec());
    }

    #[tokio::test]
    async fn test_transport_upgrade_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let initiator_identity = LocalIdentity::generate(b"tcp-test-initiator");
        let responder_identity = LocalIdentity::generate(b"tcp-test-responder");

        let initiator_config = PqNoiseConfig::new(initiator_identity, false);
        let responder_config = PqNoiseConfig::new(responder_identity, false);

        let initiator_transport = PqTransport::new(initiator_config);
        let responder_transport = PqTransport::new(responder_config);

        let responder_handle = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            responder_transport.upgrade_inbound(socket).await
        });

        let initiator_socket = TcpStream::connect(addr).await.unwrap();
        let initiator_result = initiator_transport.upgrade_outbound(initiator_socket).await;

        let (mut initiator_session, _) = initiator_result.unwrap();
        let (mut responder_session, _) = responder_handle.await.unwrap().unwrap();

        // Test bidirectional communication
        initiator_session.send(b"ping").await.unwrap();
        let received = responder_session.recv().await.unwrap().unwrap();
        assert_eq!(received, b"ping".to_vec());

        responder_session.send(b"pong").await.unwrap();
        let received = initiator_session.recv().await.unwrap().unwrap();
        assert_eq!(received, b"pong".to_vec());
    }

    #[tokio::test]
    async fn test_transport_builder() {
        let transport = PqTransportBuilder::new()
            .identity_seed(b"builder-test-seed")
            .require_pq(false)
            .handshake_timeout(Duration::from_secs(10))
            .verbose()
            .build()
            .unwrap();

        // Just verify it was built successfully
        let _peer_id = transport.local_peer_id();
    }

    #[tokio::test]
    async fn test_transport_timeout() {
        use std::io;
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use tokio::io::{AsyncRead, AsyncWrite};

        // A stream that never completes reads or writes (simulates network hang)
        struct HangingStream;

        impl AsyncRead for HangingStream {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending // Never completes
            }
        }

        impl AsyncWrite for HangingStream {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                // Accept writes but never complete reads, which will stall the handshake
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let identity = LocalIdentity::generate(b"timeout-test");
        let config = PqNoiseConfig::new(identity, false).with_timeout(Duration::from_millis(50));

        let transport = PqTransport::new(config);

        // Use hanging stream that never returns reads
        let result = transport.upgrade_outbound(HangingStream).await;

        assert!(matches!(result, Err(PqNoiseError::Timeout)));
    }
}
