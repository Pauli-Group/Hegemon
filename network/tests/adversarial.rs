use proptest::prelude::*;

use network::{NetworkError, PeerIdentity, establish_secure_channel, wire};

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 48,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]
    #[test]
    fn tampered_acceptance_is_rejected(initiator_seed in any::<u64>(), responder_seed in any::<u64>()) {
        let initiator = PeerIdentity::generate(&initiator_seed.to_le_bytes());
        let responder = PeerIdentity::generate(&responder_seed.to_le_bytes());
        let offer = initiator.create_offer().expect("offer");
        let offer_bytes = wire::encode(&offer, wire::MAX_HANDSHAKE_FRAME_LEN).expect("offer bytes");
        let (acceptance, _, _) = responder.accept_offer(&offer).expect("acceptance");
        let mut tampered = acceptance.clone();
        if !tampered.signature.is_empty() {
            tampered.signature[0] ^= 0x01;
        }
        let tampered_bytes = wire::encode(&tampered, wire::MAX_HANDSHAKE_FRAME_LEN).expect("serialize tampered");
        let result = initiator.finalize_handshake(&offer, &tampered, &offer_bytes, &tampered_bytes);
        match result {
            Ok(_) => prop_assert!(false, "tampering must fail"),
            Err(err) => prop_assert!(matches!(err, NetworkError::InvalidSignature | NetworkError::Crypto(_))),
        }
    }
}

#[test]
fn ciphertext_tampering_is_detected() {
    let initiator = PeerIdentity::generate(b"initiator-seed");
    let responder = PeerIdentity::generate(b"responder-seed");
    let (mut channel_a, mut channel_b) =
        establish_secure_channel(&initiator, &responder).expect("secure channel");
    let mut ciphertext = channel_a.encrypt(b"sensitive payload").expect("encrypt");
    ciphertext[0] ^= 0xAA;
    let err = channel_b
        .decrypt(&ciphertext)
        .expect_err("tamper should fail");
    assert!(matches!(err, NetworkError::Encryption));
}

#[test]
fn repeated_legacy_handshakes_rekey_the_first_channel_nonce() {
    let initiator = PeerIdentity::generate(b"rekey-initiator");
    let responder = PeerIdentity::generate(b"rekey-responder");

    let (mut first_a, _) =
        establish_secure_channel(&initiator, &responder).expect("first secure channel");
    let (mut second_a, _) =
        establish_secure_channel(&initiator, &responder).expect("second secure channel");

    let first_ciphertext = first_a.encrypt(b"same first plaintext").expect("encrypt 1");
    let second_ciphertext = second_a
        .encrypt(b"same first plaintext")
        .expect("encrypt 2");

    assert_ne!(
        first_ciphertext, second_ciphertext,
        "reconnecting static peers must not reuse the same AES-GCM key and first nonce"
    );
}

#[test]
fn legacy_channel_uses_directional_keys_for_first_nonce() {
    let initiator = PeerIdentity::generate(b"directional-initiator");
    let responder = PeerIdentity::generate(b"directional-responder");

    let (mut initiator_channel, mut responder_channel) =
        establish_secure_channel(&initiator, &responder).expect("secure channel");

    let initiator_first = initiator_channel
        .encrypt(b"same first plaintext")
        .expect("initiator encrypt");
    let responder_first = responder_channel
        .encrypt(b"same first plaintext")
        .expect("responder encrypt");

    assert_ne!(
        initiator_first, responder_first,
        "opposite directions must not share the same AES-GCM key with nonce zero"
    );
}
