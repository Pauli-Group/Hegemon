use bincode::deserialize;
use futures::{SinkExt, StreamExt};
use network::{
    p2p::{Connection, WireMessage},
    HandshakeAcceptance, HandshakeConfirmation, HandshakeOffer, NetworkError, PeerIdentity,
};
use sha2::{Digest, Sha256};
use tokio::io::duplex;
use tokio::time::timeout;
use tokio_util::bytes::Bytes;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

fn expected_nonce(label: &[u8], key: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(key);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

#[tokio::test]
async fn duplex_stream_handshake_succeeds_and_rejects_tampering() {
    let initiator = PeerIdentity::generate(b"duplex-initiator");
    let responder = PeerIdentity::generate(b"duplex-responder");

    let (a, b) = duplex(1 << 20);
    let mut initiator_stream = Framed::new(a, LengthDelimitedCodec::new());
    let mut responder_stream = Framed::new(b, LengthDelimitedCodec::new());

    // Initiator -> Responder: offer
    let offer = initiator.create_offer().expect("offer");
    assert_eq!(
        offer.nonce,
        expected_nonce(b"offer", &offer.identity_key),
        "offer nonce should be deterministic",
    );
    let offer_bytes = bincode::serialize(&offer).expect("offer bytes");
    initiator_stream
        .send(Bytes::copy_from_slice(&offer_bytes))
        .await
        .expect("send offer");

    // Responder -> Initiator: acceptance
    let acceptance_bytes = timeout(std::time::Duration::from_secs(1), responder_stream.next())
        .await
        .expect("offer frame")
        .expect("offer received")
        .expect("offer bytes")
        .to_vec();
    let offer_rx: HandshakeOffer = deserialize(&acceptance_bytes).expect("deserialize offer");
    let (acceptance, responder_secret, acceptance_bytes) =
        responder.accept_offer(&offer_rx).expect("acceptance");
    assert_eq!(
        acceptance.nonce,
        expected_nonce(b"accept", &acceptance.identity_key),
        "acceptance nonce should be deterministic",
    );
    responder_stream
        .send(Bytes::copy_from_slice(&acceptance_bytes))
        .await
        .expect("send acceptance");

    // Initiator -> Responder: confirmation
    let acceptance_rx = timeout(std::time::Duration::from_secs(1), initiator_stream.next())
        .await
        .expect("acceptance frame")
        .expect("acceptance received")
        .expect("acceptance bytes")
        .to_vec();
    let acceptance_parsed: HandshakeAcceptance =
        deserialize(&acceptance_rx).expect("deserialize acceptance");
    let (mut initiator_channel, confirmation, confirmation_bytes) = initiator
        .finalize_handshake(&offer, &acceptance_parsed, &offer_bytes, &acceptance_rx)
        .expect("finalize handshake");
    assert_eq!(
        confirmation.nonce,
        expected_nonce(b"confirm", &offer.identity_key),
        "confirmation nonce should be deterministic",
    );
    initiator_stream
        .send(Bytes::copy_from_slice(&confirmation_bytes))
        .await
        .expect("send confirmation");

    // Responder completes the handshake and establishes the session keys.
    let confirmation_rx = timeout(std::time::Duration::from_secs(1), responder_stream.next())
        .await
        .expect("confirmation frame")
        .expect("confirmation received")
        .expect("confirmation bytes")
        .to_vec();
    let confirmation_parsed: HandshakeConfirmation =
        deserialize(&confirmation_rx).expect("deserialize confirmation");
    let mut responder_channel = responder
        .complete_handshake(
            &offer_rx,
            &confirmation_parsed,
            &offer_bytes,
            &acceptance_bytes,
            &confirmation_rx,
            responder_secret,
        )
        .expect("complete handshake");

    // AES-GCM channel round-trip succeeds.
    let payload = b"post-quantum hello";
    let ciphertext = initiator_channel.encrypt(payload).expect("encrypt");
    let decrypted = responder_channel.decrypt(&ciphertext).expect("decrypt");
    assert_eq!(decrypted, payload);

    // Session AAD must match between peers; tampering should fail cleanly.
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 0x80;
    let err = responder_channel
        .decrypt(&tampered)
        .expect_err("tampering should fail");
    assert!(matches!(err, NetworkError::Encryption));

    // Tamper with the confirmation signature to ensure ML-DSA validation rejects it.
    let (offer, offer_bytes) = {
        let offer = initiator.create_offer().expect("offer");
        let offer_bytes = bincode::serialize(&offer).expect("offer bytes");
        (offer, offer_bytes)
    };
    let (acceptance, responder_secret, acceptance_bytes) =
        responder.accept_offer(&offer).expect("accept");
    let mut tampered_acceptance = acceptance.clone();
    tampered_acceptance.signature[0] ^= 0x01;
    let tampered_acceptance_bytes =
        bincode::serialize(&tampered_acceptance).expect("tampered acceptance bytes");

    // Initiator receives the tampered acceptance and should reject the signature.
    let err = initiator.finalize_handshake(
        &offer,
        &tampered_acceptance,
        &offer_bytes,
        &tampered_acceptance_bytes,
    );
    assert!(matches!(
        err,
        Err(NetworkError::InvalidSignature | NetworkError::Crypto(_))
    ));

    // Responder should also reject a tampered confirmation.
    let (channel, confirmation, _confirmation_bytes) = initiator
        .finalize_handshake(&offer, &acceptance, &offer_bytes, &acceptance_bytes)
        .expect("finalize handshake");
    let mut tampered_confirmation = confirmation.clone();
    tampered_confirmation.signature = vec![0u8; tampered_confirmation.signature.len()];
    let tampered_confirmation_bytes =
        bincode::serialize(&tampered_confirmation).expect("tampered confirmation bytes");
    let err = responder.complete_handshake(
        &offer,
        &tampered_confirmation,
        &offer_bytes,
        &acceptance_bytes,
        &tampered_confirmation_bytes,
        responder_secret,
    );
    assert!(err.is_err(), "confirmation tamper unexpectedly succeeded");
    drop(channel);
    assert!(matches!(
        err,
        Err(NetworkError::InvalidSignature | NetworkError::Crypto(_))
    ));
}

#[tokio::test]
async fn connection_round_trip_and_encryption_over_duplex() {
    let initiator_identity = PeerIdentity::generate(b"conn-initiator");
    let responder_identity = PeerIdentity::generate(b"conn-responder");

    let (initiator_stream, responder_stream) = duplex(1 << 12);
    let (mut initiator_conn, mut responder_conn) = (
        Connection::new(initiator_stream),
        Connection::new(responder_stream),
    );

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

#[tokio::test]
async fn initiator_rejects_tampered_acceptance() {
    let initiator_identity = PeerIdentity::generate(b"tamper-initiator");
    let responder_identity = PeerIdentity::generate(b"tamper-responder");

    let (initiator_stream, responder_stream) = duplex(1 << 12);

    let tamper_task = tokio::spawn(async move {
        let mut framed = Framed::new(responder_stream, LengthDelimitedCodec::new());
        let offer_bytes = framed
            .next()
            .await
            .expect("offer frame")
            .expect("offer bytes")
            .to_vec();
        let offer: HandshakeOffer = deserialize(&offer_bytes).expect("deserialize offer");
        let (acceptance, _secret, _acceptance_bytes) =
            responder_identity.accept_offer(&offer).expect("accept offer");
        let mut tampered = acceptance.clone();
        if let Some(first) = tampered.signature.first_mut() {
            *first ^= 0xAA;
        }
        let tampered_bytes = bincode::serialize(&tampered).expect("serialize tampered");
        framed
            .send(Bytes::copy_from_slice(&tampered_bytes))
            .await
            .expect("send tampered acceptance");
    });

    let mut initiator_conn = Connection::new(initiator_stream);
    let result = initiator_conn.handshake_initiator(&initiator_identity).await;
    assert!(matches!(
        result,
        Err(NetworkError::InvalidSignature | NetworkError::Crypto(_))
    ));

    tamper_task.await.expect("tamper task completes");
}
