//! Post-Quantum Noise Protocol Extension
//!
//! This crate implements a post-quantum key exchange protocol using:
//! - ML-KEM-1024 encapsulation (FIPS 203, lattice-based)
//!
//! # Security Properties
//!
//! ML-KEM provides IND-CCA2 security against quantum adversaries.
//! All key exchange is based on lattice problems (Module-LWE).
//!
//! # Protocol Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     PQ Handshake                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │  1. ML-KEM-1024 Encaps  │  PQ key encapsulation              │
//! │  2. Shared Secret      │  HKDF(mlkem_ss)                    │
//! │  3. ML-DSA-65 Sign     │  Authenticate peer identity        │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use pq_noise::{PqNoiseConfig, PqHandshake};
//!
//! // Create configuration
//! let config = PqNoiseConfig::new(identity_keypair);
//!
//! // Perform handshake (initiator side)
//! let (session, peer_id) = PqHandshake::initiator(&config, stream).await?;
//!
//! // Use session for encrypted communication
//! session.send(b"Hello, quantum world!").await?;
//! ```

mod codec;
pub mod config;
pub mod error;
pub mod handshake;
pub mod noise;
pub mod session;
pub mod transport;
pub mod types;

pub use config::PqNoiseConfig;
pub use error::PqNoiseError;
pub use handshake::PqHandshake;
pub use session::SecureSession;
pub use transport::PqTransport;
pub use types::{HandshakeMessage, PeerId, SessionKeys};

#[cfg(test)]
mod formal_vectors {
    use super::*;
    use crate::codec::{HANDSHAKE_MAGIC, HANDSHAKE_MAX_FRAME_LEN, SESSION_MAGIC};
    use crate::handshake::{
        finish_signing_data, finish_signing_preimage, init_hello_signing_data,
        init_hello_signing_preimage, random_encapsulation_seed, resp_hello_signing_data,
        resp_hello_signing_preimage, signing_digest,
    };
    use crate::noise::{nonce_from_counter, nonce_step, NoiseCipher};
    use crate::types::{
        select_session_key, session_key_expand_info, session_key_material, session_key_slots,
        LocalIdentity, RemotePeer, SessionKeySlot, PQ_NOISE_AAD_INFO, PQ_NOISE_I2R_INFO,
        PQ_NOISE_R2I_INFO,
    };
    use aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use bytes::Bytes;
    use crypto::traits::{KemKeyPair, KemPublicKey, VerifyKey};
    use futures::{SinkExt, StreamExt};
    use serde::Deserialize;
    use tokio::io::duplex;
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    #[derive(Deserialize)]
    struct LeanPqNoiseVectorFile {
        schema_version: u32,
        kem_rng_source_cases: Vec<LeanKemRngSourceCase>,
        session_key_cases: Vec<LeanSessionKeyCase>,
        role_cases: Vec<LeanRoleCase>,
        nonce_cases: Vec<LeanNonceCase>,
        frame_sequence_cases: Vec<LeanFrameSequenceCase>,
        replay_admission_cases: Vec<LeanReplayAdmissionCase>,
        role_misbind_cases: Vec<LeanRoleMisbindCase>,
        transport_completion_cases: Vec<LeanTransportCompletionCase>,
        production_channel_certificate_cases: Vec<LeanProductionChannelCertificateCase>,
        init_signing_cases: Vec<LeanInitSigningCase>,
        resp_signing_cases: Vec<LeanRespSigningCase>,
        finish_signing_cases: Vec<LeanFinishSigningCase>,
    }

    #[derive(Deserialize)]
    struct LeanKemRngSourceCase {
        name: String,
        use_kind: String,
        expected_source: String,
        expected_seed_byte_length: String,
        expected_consumed_by_mlkem_encapsulate: bool,
        expected_public_transcript_derived: bool,
    }

    #[derive(Deserialize)]
    struct LeanSessionKeyCase {
        name: String,
        transcript_hash_hex: String,
        shared_1_hex: String,
        shared_2_hex: String,
        expected_salt_hex: String,
        expected_ikm_hex: String,
        i2r_info_hex: String,
        r2i_info_hex: String,
        aad_info_hex: String,
        expected_i2r_equals_r2i_info: bool,
        expected_i2r_equals_aad_info: bool,
    }

    #[derive(Deserialize)]
    struct LeanRoleCase {
        role: String,
        expected_send_slot: String,
        expected_recv_slot: String,
        expected_send_recv_distinct: bool,
    }

    #[derive(Deserialize)]
    struct LeanNonceCase {
        name: String,
        counter: String,
        expected_nonce_hex: String,
        expected_valid: bool,
        expected_next_counter: Option<String>,
    }

    #[derive(Deserialize)]
    struct LeanFrameSequenceCase {
        name: String,
        role: String,
        peer_role: String,
        sequence_length: String,
        frames: Vec<LeanFrameCase>,
    }

    #[derive(Deserialize)]
    struct LeanFrameCase {
        frame_index: String,
        expected_protect_slot: String,
        expected_peer_open_slot: String,
        expected_nonce_hex: String,
        expected_protected_next_send_counter: String,
        expected_peer_next_recv_counter: String,
        expected_protected_slot_matches_peer_open: bool,
        expected_aad_distinct_from_key_info: bool,
        plaintext_hex: String,
    }

    #[derive(Deserialize)]
    struct LeanReplayAdmissionCase {
        name: String,
        scenario_kind: String,
        role: String,
        peer_role: String,
        expected_sender_slot: String,
        expected_peer_open_slot: String,
        expected_sender_slot_matches_peer_open: bool,
        preaccepted_frame_index: Option<String>,
        #[serde(default)]
        preaccepted_frame_indices: Vec<String>,
        rejected_frame_index: String,
        recovery_frame_index: String,
        expected_rejected_valid: bool,
        expected_reject_preserves_recv_counter: bool,
        expected_recv_counter_before_reject: String,
        expected_recv_counter_after_reject: String,
        expected_recovery_next_recv_counter: String,
        rejected_nonce_hex: String,
        expected_open_nonce_before_reject_hex: String,
        recovery_nonce_hex: String,
        preaccepted_plaintext_hex: Option<String>,
        #[serde(default)]
        preaccepted_plaintexts_hex: Vec<String>,
        rejected_plaintext_hex: Option<String>,
        recovery_plaintext_hex: Option<String>,
    }

    #[derive(Deserialize)]
    struct LeanRoleMisbindCase {
        name: String,
        role: String,
        expected_sender_slot: String,
        expected_same_role_open_slot: String,
        expected_sender_slot_matches_same_role_open: bool,
        frame_index: String,
        expected_nonce_hex: String,
        expected_rejected_valid: bool,
        expected_reject_preserves_recv_counter: bool,
        expected_recv_counter_after_reject: String,
        plaintext_hex: String,
    }

    #[derive(Deserialize)]
    struct LeanTransportCompletionCase {
        name: String,
        local_role: String,
        peer_role: String,
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
        expected_first_frame_wire_bytes: String,
        plaintext_hex: String,
    }

    #[derive(Deserialize)]
    struct LeanProductionChannelCertificateCase {
        name: String,
        local_role: String,
        peer_role: String,
        sequence_length: String,
        frame_index: String,
        expected_frame_in_sequence: bool,
        expected_sequence_within_counter_domain: bool,
        expected_responder_seed_use: String,
        expected_initiator_seed_use: String,
        expected_responder_seed_source: String,
        expected_initiator_seed_source: String,
        expected_seed_byte_length: String,
        expected_public_transcript_seed_source: bool,
        expected_transcript_only_hkdf_salt: bool,
        expected_kem_ikm_ordered: bool,
        expected_i2r_r2i_aad_separated: bool,
        expected_local_send_slot: String,
        expected_peer_recv_slot: String,
        expected_local_send_matches_peer_recv: bool,
        expected_nonce_hex: String,
        expected_duplicate_frame_rejected: bool,
        expected_future_frame_rejected: bool,
        expected_indexed_stale_frame_rejected: bool,
        expected_same_role_misbind_rejected: bool,
        expected_reject_preserves_recv_counter: bool,
        expected_handshake_wire_kind: String,
        expected_handshake_magic_hex: String,
        expected_handshake_max_frame_len: String,
        expected_handshake_marker_matches: bool,
        expected_handshake_postcard_decodes: bool,
        expected_handshake_postcard_consumes_all: bool,
        expected_session_wire_kind: String,
        expected_session_magic_hex: String,
        expected_session_max_plaintext_len: String,
        expected_session_marker_matches: bool,
        expected_session_postcard_decodes: bool,
        expected_session_postcard_consumes_all: bool,
        expected_wrapper_completed: bool,
        expected_first_frame_payload_bytes: String,
        expected_first_frame_tag_bytes: String,
        expected_first_frame_wire_bytes: String,
    }

    #[derive(Deserialize)]
    struct LeanInitSigningCase {
        name: String,
        version: u8,
        mlkem_public_key_hex: String,
        identity_key_hex: String,
        nonce: String,
        expected_preimage_hex: String,
    }

    #[derive(Deserialize)]
    struct LeanRespSigningCase {
        name: String,
        version: u8,
        mlkem_public_key_hex: String,
        mlkem_ciphertext_hex: String,
        identity_key_hex: String,
        nonce: String,
        transcript_hash_hex: String,
        expected_preimage_hex: String,
    }

    #[derive(Deserialize)]
    struct LeanFinishSigningCase {
        name: String,
        mlkem_ciphertext_hex: String,
        nonce: String,
        transcript_hash_hex: String,
        expected_preimage_hex: String,
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        hex::decode(trimmed).expect("hex vector")
    }

    fn decode_array_32(value: &str) -> [u8; 32] {
        let bytes = decode_hex(value);
        bytes
            .try_into()
            .unwrap_or_else(|bytes: Vec<u8>| panic!("expected 32 bytes, got {}", bytes.len()))
    }

    fn slot_name(slot: SessionKeySlot) -> &'static str {
        match slot {
            SessionKeySlot::InitiatorToResponder => "initiator_to_responder",
            SessionKeySlot::ResponderToInitiator => "responder_to_initiator",
        }
    }

    fn parse_role(value: &str) -> bool {
        match value {
            "initiator" => true,
            "responder" => false,
            other => panic!("unknown role {other}"),
        }
    }

    fn vector_session_keys(vectors: &LeanPqNoiseVectorFile) -> SessionKeys {
        let case = vectors
            .session_key_cases
            .first()
            .expect("at least one session key case");
        let transcript_hash = decode_array_32(&case.transcript_hash_hex);
        let shared_1 = decode_array_32(&case.shared_1_hex);
        let shared_2 = decode_array_32(&case.shared_2_hex);
        SessionKeys::derive(&transcript_hash, &shared_1, &shared_2)
    }

    fn test_remote_peer(seed: &[u8]) -> RemotePeer {
        let identity = LocalIdentity::generate(seed);
        RemotePeer::from_handshake(
            &identity.verify_key.to_bytes(),
            &identity.kem_keypair.public_key().to_bytes(),
        )
        .expect("remote peer")
    }

    fn expected_ciphertext(
        keys: &SessionKeys,
        slot: SessionKeySlot,
        nonce_bytes: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        assert_eq!(nonce_bytes.len(), 12, "AES-GCM nonce length");
        let key = select_session_key(keys, slot);
        let cipher = Aes256Gcm::new_from_slice(&key).expect("AES-256 key");
        cipher
            .encrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &keys.session_aad,
                },
            )
            .expect("expected ciphertext")
    }

    fn session_codec() -> LengthDelimitedCodec {
        let mut codec = LengthDelimitedCodec::new();
        codec.set_max_frame_length(session::SESSION_MAX_FRAME_LEN);
        codec
    }

    #[tokio::test]
    async fn lean_generated_pq_noise_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_PQ_NOISE_VECTORS") else {
            eprintln!("skipping Lean PQ Noise vectors; env var not set");
            return;
        };
        let contents = std::fs::read_to_string(path).expect("read Lean PQ Noise vectors");
        let vectors: LeanPqNoiseVectorFile =
            serde_json::from_str(&contents).expect("parse Lean PQ Noise vectors");
        assert_eq!(vectors.schema_version, 8);
        let frame_keys = vector_session_keys(&vectors);

        for case in &vectors.kem_rng_source_cases {
            assert!(
                matches!(
                    case.use_kind.as_str(),
                    "responder_encapsulates_to_initiator" | "initiator_encapsulates_to_responder"
                ),
                "{} use kind",
                case.name
            );
            assert_eq!(
                case.expected_source, "os_rng_32",
                "{} seed source",
                case.name
            );
            assert_eq!(
                random_encapsulation_seed().len(),
                case.expected_seed_byte_length
                    .parse::<usize>()
                    .expect("seed length"),
                "{} seed length",
                case.name
            );
            assert!(
                case.expected_consumed_by_mlkem_encapsulate,
                "{} seed consumed by encapsulate",
                case.name
            );
            assert!(
                !case.expected_public_transcript_derived,
                "{} not public transcript derived",
                case.name
            );
        }

        for case in &vectors.session_key_cases {
            let transcript_hash = decode_array_32(&case.transcript_hash_hex);
            let shared_1 = decode_array_32(&case.shared_1_hex);
            let shared_2 = decode_array_32(&case.shared_2_hex);
            assert_eq!(
                transcript_hash.to_vec(),
                decode_hex(&case.expected_salt_hex),
                "{} salt",
                case.name
            );
            assert_eq!(
                session_key_material(&shared_1, &shared_2),
                decode_hex(&case.expected_ikm_hex),
                "{} ikm",
                case.name
            );
            assert_eq!(decode_hex(&case.i2r_info_hex), PQ_NOISE_I2R_INFO);
            assert_eq!(decode_hex(&case.r2i_info_hex), PQ_NOISE_R2I_INFO);
            assert_eq!(decode_hex(&case.aad_info_hex), PQ_NOISE_AAD_INFO);
            assert_eq!(
                session_key_expand_info(SessionKeySlot::InitiatorToResponder),
                PQ_NOISE_I2R_INFO
            );
            assert_eq!(
                session_key_expand_info(SessionKeySlot::ResponderToInitiator),
                PQ_NOISE_R2I_INFO
            );
            assert_eq!(
                PQ_NOISE_I2R_INFO == PQ_NOISE_R2I_INFO,
                case.expected_i2r_equals_r2i_info
            );
            assert_eq!(
                PQ_NOISE_I2R_INFO == PQ_NOISE_AAD_INFO,
                case.expected_i2r_equals_aad_info
            );

            let keys = SessionKeys::derive(&transcript_hash, &shared_1, &shared_2);
            assert_eq!(
                select_session_key(&keys, SessionKeySlot::InitiatorToResponder),
                keys.initiator_to_responder
            );
            assert_eq!(
                select_session_key(&keys, SessionKeySlot::ResponderToInitiator),
                keys.responder_to_initiator
            );
            assert_ne!(keys.initiator_to_responder, keys.responder_to_initiator);
            assert_ne!(keys.initiator_to_responder, keys.session_aad);
        }

        assert!(
            !vectors.production_channel_certificate_cases.is_empty(),
            "Lean PQ Noise vectors must include v8 production channel certificate cases"
        );
        for case in &vectors.production_channel_certificate_cases {
            let sequence_length = case
                .sequence_length
                .parse::<u64>()
                .expect("sequence length u64");
            let frame_index = case.frame_index.parse::<u64>().expect("frame index u64");
            assert_eq!(
                frame_index < sequence_length,
                case.expected_frame_in_sequence,
                "{} frame sequence admission",
                case.name
            );
            assert!(
                case.expected_sequence_within_counter_domain,
                "{} sequence counter-domain admission",
                case.name
            );
            assert_eq!(
                case.expected_responder_seed_use, "responder_encapsulates_to_initiator",
                "{} responder KEM use",
                case.name
            );
            assert_eq!(
                case.expected_initiator_seed_use, "initiator_encapsulates_to_responder",
                "{} initiator KEM use",
                case.name
            );
            assert_eq!(
                case.expected_responder_seed_source, "os_rng_32",
                "{} responder seed source",
                case.name
            );
            assert_eq!(
                case.expected_initiator_seed_source, "os_rng_32",
                "{} initiator seed source",
                case.name
            );
            assert_eq!(
                random_encapsulation_seed().len(),
                case.expected_seed_byte_length
                    .parse::<usize>()
                    .expect("seed byte length"),
                "{} OS RNG encapsulation seed length",
                case.name
            );
            assert!(
                !case.expected_public_transcript_seed_source,
                "{} seed source is not public-transcript-derived",
                case.name
            );
            assert!(
                case.expected_transcript_only_hkdf_salt,
                "{} transcript is HKDF salt boundary",
                case.name
            );
            assert!(case.expected_kem_ikm_ordered, "{} KEM IKM order", case.name);
            assert!(
                case.expected_i2r_r2i_aad_separated,
                "{} PQ Noise HKDF/AAD label separation",
                case.name
            );
            assert_ne!(
                PQ_NOISE_I2R_INFO, PQ_NOISE_R2I_INFO,
                "{} i2r/r2i",
                case.name
            );
            assert_ne!(
                PQ_NOISE_AAD_INFO, PQ_NOISE_I2R_INFO,
                "{} aad/i2r",
                case.name
            );
            assert_ne!(
                PQ_NOISE_AAD_INFO, PQ_NOISE_R2I_INFO,
                "{} aad/r2i",
                case.name
            );

            let local_is_initiator = parse_role(&case.local_role);
            let peer_is_initiator = parse_role(&case.peer_role);
            assert_ne!(
                local_is_initiator, peer_is_initiator,
                "{} peer role is opposite",
                case.name
            );
            let (local_send_slot, _) = session_key_slots(local_is_initiator);
            let (_, peer_recv_slot) = session_key_slots(peer_is_initiator);
            assert_eq!(
                slot_name(local_send_slot),
                case.expected_local_send_slot,
                "{} local send slot",
                case.name
            );
            assert_eq!(
                slot_name(peer_recv_slot),
                case.expected_peer_recv_slot,
                "{} peer recv slot",
                case.name
            );
            assert_eq!(
                local_send_slot == peer_recv_slot,
                case.expected_local_send_matches_peer_recv,
                "{} local send/peer recv binding",
                case.name
            );
            assert_eq!(
                nonce_from_counter(frame_index).to_vec(),
                decode_hex(&case.expected_nonce_hex),
                "{} frame nonce",
                case.name
            );
            assert!(
                case.expected_duplicate_frame_rejected,
                "{} duplicate replay",
                case.name
            );
            assert!(
                case.expected_future_frame_rejected,
                "{} future replay",
                case.name
            );
            assert!(
                case.expected_indexed_stale_frame_rejected,
                "{} indexed stale replay",
                case.name
            );
            assert!(
                case.expected_same_role_misbind_rejected,
                "{} same-role misbind",
                case.name
            );
            assert!(
                case.expected_reject_preserves_recv_counter,
                "{} failed open preserves counter",
                case.name
            );

            assert_eq!(
                case.expected_handshake_wire_kind, "pq_handshake",
                "{} handshake wire kind",
                case.name
            );
            assert_eq!(
                decode_hex(&case.expected_handshake_magic_hex),
                HANDSHAKE_MAGIC,
                "{} handshake magic",
                case.name
            );
            assert_eq!(
                case.expected_handshake_max_frame_len
                    .parse::<usize>()
                    .expect("handshake max len"),
                HANDSHAKE_MAX_FRAME_LEN,
                "{} handshake max len",
                case.name
            );
            assert!(
                case.expected_handshake_marker_matches,
                "{} handshake marker",
                case.name
            );
            assert!(
                case.expected_handshake_postcard_decodes,
                "{} handshake postcard decode",
                case.name
            );
            assert!(
                case.expected_handshake_postcard_consumes_all,
                "{} handshake exact consumption",
                case.name
            );
            assert_eq!(
                case.expected_session_wire_kind, "pq_session_plaintext",
                "{} session wire kind",
                case.name
            );
            assert_eq!(
                decode_hex(&case.expected_session_magic_hex),
                SESSION_MAGIC,
                "{} session magic",
                case.name
            );
            assert_eq!(
                case.expected_session_max_plaintext_len
                    .parse::<usize>()
                    .expect("session max plaintext len"),
                session::SESSION_MAX_PLAINTEXT_LEN,
                "{} session plaintext max len",
                case.name
            );
            assert!(
                case.expected_session_marker_matches,
                "{} session marker",
                case.name
            );
            assert!(
                case.expected_session_postcard_decodes,
                "{} session postcard decode",
                case.name
            );
            assert!(
                case.expected_session_postcard_consumes_all,
                "{} session exact consumption",
                case.name
            );
            assert!(
                case.expected_wrapper_completed,
                "{} wrapper completion",
                case.name
            );
            let payload_bytes = case
                .expected_first_frame_payload_bytes
                .parse::<usize>()
                .expect("payload bytes");
            let tag_bytes = case
                .expected_first_frame_tag_bytes
                .parse::<usize>()
                .expect("tag bytes");
            let wire_bytes = case
                .expected_first_frame_wire_bytes
                .parse::<usize>()
                .expect("wire bytes");
            assert_eq!(tag_bytes, 16, "{} AEAD tag bytes", case.name);
            assert_eq!(
                payload_bytes + tag_bytes,
                wire_bytes,
                "{} first frame wire accounting",
                case.name
            );
        }

        for case in &vectors.role_cases {
            let is_initiator = parse_role(&case.role);
            let (send_slot, recv_slot) = session_key_slots(is_initiator);
            assert_eq!(slot_name(send_slot), case.expected_send_slot);
            assert_eq!(slot_name(recv_slot), case.expected_recv_slot);
            assert_eq!(send_slot != recv_slot, case.expected_send_recv_distinct);
        }

        for case in &vectors.nonce_cases {
            let counter = case.counter.parse::<u64>().expect("counter u64");
            assert_eq!(
                nonce_from_counter(counter).to_vec(),
                decode_hex(&case.expected_nonce_hex),
                "{} nonce",
                case.name
            );
            let step = nonce_step(counter);
            assert_eq!(step.is_ok(), case.expected_valid, "{} validity", case.name);
            match (step.ok(), case.expected_next_counter.clone()) {
                (Some((_, next)), Some(expected)) => {
                    assert_eq!(next, expected.parse::<u64>().expect("next counter u64"));
                }
                (None, None) => {}
                other => panic!("{} counter mismatch: {other:?}", case.name),
            }
        }

        for case in &vectors.frame_sequence_cases {
            let sender_is_initiator = parse_role(&case.role);
            let peer_is_initiator = parse_role(&case.peer_role);
            assert_ne!(
                sender_is_initiator, peer_is_initiator,
                "{} peer role is opposite",
                case.name
            );
            let sequence_length = case
                .sequence_length
                .parse::<u64>()
                .expect("sequence length u64");
            assert_eq!(
                case.frames.len() as u64,
                sequence_length,
                "{} frame count",
                case.name
            );

            let (sender_slot, _) = session_key_slots(sender_is_initiator);
            let (_, peer_recv_slot) = session_key_slots(peer_is_initiator);
            let (sender_stream, peer_stream) = duplex(64 * 1024);
            let mut sender = SecureSession::new(
                sender_stream,
                frame_keys.clone(),
                test_remote_peer(format!("{}-sender", case.name).as_bytes()),
                sender_is_initiator,
            )
            .unwrap_or_else(|err| panic!("{} sender session: {err}", case.name));
            let mut peer = SecureSession::new(
                peer_stream,
                frame_keys.clone(),
                test_remote_peer(format!("{}-peer", case.name).as_bytes()),
                peer_is_initiator,
            )
            .unwrap_or_else(|err| panic!("{} peer session: {err}", case.name));
            let mut expected_sent_bytes = 0u64;
            let mut expected_received_bytes = 0u64;

            for frame in &case.frames {
                let frame_index = frame.frame_index.parse::<u64>().expect("frame index u64");
                let expected_next = frame_index.checked_add(1).expect("bounded frame index");
                assert_eq!(
                    frame
                        .expected_protected_next_send_counter
                        .parse::<u64>()
                        .expect("next send counter u64"),
                    expected_next,
                    "{} protected next send counter at frame {frame_index}",
                    case.name
                );
                assert_eq!(
                    frame
                        .expected_peer_next_recv_counter
                        .parse::<u64>()
                        .expect("next recv counter u64"),
                    expected_next,
                    "{} peer next recv counter at frame {frame_index}",
                    case.name
                );
                assert_eq!(
                    slot_name(sender_slot),
                    frame.expected_protect_slot,
                    "{} protect slot at frame {frame_index}",
                    case.name
                );
                assert_eq!(
                    slot_name(peer_recv_slot),
                    frame.expected_peer_open_slot,
                    "{} peer open slot at frame {frame_index}",
                    case.name
                );
                assert_eq!(
                    sender_slot == peer_recv_slot,
                    frame.expected_protected_slot_matches_peer_open,
                    "{} slot matching at frame {frame_index}",
                    case.name
                );
                assert_eq!(
                    nonce_from_counter(frame_index).to_vec(),
                    decode_hex(&frame.expected_nonce_hex),
                    "{} nonce at frame {frame_index}",
                    case.name
                );
                assert_eq!(
                    PQ_NOISE_AAD_INFO != session_key_expand_info(sender_slot),
                    frame.expected_aad_distinct_from_key_info,
                    "{} AAD separation at frame {frame_index}",
                    case.name
                );
                let nonce = decode_hex(&frame.expected_nonce_hex);
                let plaintext = decode_hex(&frame.plaintext_hex);
                let expected = expected_ciphertext(&frame_keys, sender_slot, &nonce, &plaintext);
                expected_sent_bytes = expected_sent_bytes.saturating_add(expected.len() as u64);
                expected_received_bytes =
                    expected_received_bytes.saturating_add(expected.len() as u64);

                let (send_result, recv_result) = tokio::join!(sender.send(&plaintext), peer.recv());
                send_result.unwrap_or_else(|err| {
                    panic!("{} session send frame {frame_index}: {err}", case.name)
                });
                let decrypted = recv_result
                    .unwrap_or_else(|err| {
                        panic!("{} session recv frame {frame_index}: {err}", case.name)
                    })
                    .unwrap_or_else(|| panic!("{} session EOF at frame {frame_index}", case.name));
                assert_eq!(
                    decrypted, plaintext,
                    "{} peer receives frame {frame_index}",
                    case.name
                );
                assert_eq!(
                    sender.bytes_sent(),
                    expected_sent_bytes,
                    "{} sender byte count at frame {frame_index}",
                    case.name
                );
                assert_eq!(
                    peer.bytes_received(),
                    expected_received_bytes,
                    "{} peer byte count at frame {frame_index}",
                    case.name
                );
            }

            let (raw_sender_stream, raw_peer_stream) = duplex(64 * 1024);
            let mut raw_sender = SecureSession::new(
                raw_sender_stream,
                frame_keys.clone(),
                test_remote_peer(format!("{}-raw-sender", case.name).as_bytes()),
                sender_is_initiator,
            )
            .unwrap_or_else(|err| panic!("{} raw sender session: {err}", case.name));
            let mut raw_peer = Framed::new(raw_peer_stream, session_codec());
            for frame in &case.frames {
                let frame_index = frame.frame_index.parse::<u64>().expect("frame index u64");
                let nonce = decode_hex(&frame.expected_nonce_hex);
                let plaintext = decode_hex(&frame.plaintext_hex);
                let expected = expected_ciphertext(&frame_keys, sender_slot, &nonce, &plaintext);

                let (send_result, raw_result) =
                    tokio::join!(raw_sender.send(&plaintext), raw_peer.next());
                send_result.unwrap_or_else(|err| {
                    panic!("{} raw session send frame {frame_index}: {err}", case.name)
                });
                let raw_frame = raw_result
                    .unwrap_or_else(|| panic!("{} raw EOF at frame {frame_index}", case.name))
                    .unwrap_or_else(|err| {
                        panic!("{} raw frame read at frame {frame_index}: {err}", case.name)
                    })
                    .to_vec();
                assert_eq!(
                    raw_frame, expected,
                    "{} raw ciphertext at frame {frame_index}",
                    case.name
                );
            }

            let (raw_open_stream, open_session_stream) = duplex(64 * 1024);
            let mut raw_open = Framed::new(raw_open_stream, session_codec());
            let mut open_session = SecureSession::new(
                open_session_stream,
                frame_keys.clone(),
                test_remote_peer(format!("{}-open-peer", case.name).as_bytes()),
                peer_is_initiator,
            )
            .unwrap_or_else(|err| panic!("{} open session: {err}", case.name));
            for frame in &case.frames {
                let frame_index = frame.frame_index.parse::<u64>().expect("frame index u64");
                let nonce = decode_hex(&frame.expected_nonce_hex);
                let plaintext = decode_hex(&frame.plaintext_hex);
                let ciphertext = expected_ciphertext(&frame_keys, sender_slot, &nonce, &plaintext);

                let (write_result, recv_result) =
                    tokio::join!(raw_open.send(Bytes::from(ciphertext)), open_session.recv());
                write_result.unwrap_or_else(|err| {
                    panic!("{} raw open write frame {frame_index}: {err}", case.name)
                });
                let opened = recv_result
                    .unwrap_or_else(|err| {
                        panic!("{} active open frame {frame_index}: {err}", case.name)
                    })
                    .unwrap_or_else(|| {
                        panic!("{} active open EOF at frame {frame_index}", case.name)
                    });
                assert_eq!(
                    opened, plaintext,
                    "{} active open at frame {frame_index}",
                    case.name
                );
            }
        }

        for case in &vectors.replay_admission_cases {
            let sender_is_initiator = parse_role(&case.role);
            let peer_is_initiator = parse_role(&case.peer_role);
            assert_ne!(
                sender_is_initiator, peer_is_initiator,
                "{} peer role is opposite",
                case.name
            );
            let (sender_slot, _) = session_key_slots(sender_is_initiator);
            let (_, peer_recv_slot) = session_key_slots(peer_is_initiator);
            assert_eq!(
                slot_name(sender_slot),
                case.expected_sender_slot,
                "{} sender slot",
                case.name
            );
            assert_eq!(
                slot_name(peer_recv_slot),
                case.expected_peer_open_slot,
                "{} peer open slot",
                case.name
            );
            assert_eq!(
                sender_slot == peer_recv_slot,
                case.expected_sender_slot_matches_peer_open,
                "{} sender slot matches peer open slot",
                case.name
            );

            let rejected_frame_index = case
                .rejected_frame_index
                .parse::<u64>()
                .expect("rejected frame index");
            let recovery_frame_index = case
                .recovery_frame_index
                .parse::<u64>()
                .expect("recovery frame index");
            let expected_recv_before = case
                .expected_recv_counter_before_reject
                .parse::<u64>()
                .expect("recv counter before reject");
            let expected_recv_after = case
                .expected_recv_counter_after_reject
                .parse::<u64>()
                .expect("recv counter after reject");
            let expected_recovery_next = case
                .expected_recovery_next_recv_counter
                .parse::<u64>()
                .expect("recovery next recv counter");

            assert_eq!(
                nonce_from_counter(rejected_frame_index).to_vec(),
                decode_hex(&case.rejected_nonce_hex),
                "{} rejected nonce",
                case.name
            );
            assert_eq!(
                nonce_from_counter(expected_recv_before).to_vec(),
                decode_hex(&case.expected_open_nonce_before_reject_hex),
                "{} expected open nonce before reject",
                case.name
            );
            assert_eq!(
                nonce_from_counter(recovery_frame_index).to_vec(),
                decode_hex(&case.recovery_nonce_hex),
                "{} recovery nonce",
                case.name
            );

            let mut peer_cipher = NoiseCipher::new(&frame_keys, peer_is_initiator)
                .unwrap_or_else(|err| panic!("{} peer cipher: {err}", case.name));

            match case.scenario_kind.as_str() {
                "duplicate_after_first" => {
                    let preaccepted_index = case
                        .preaccepted_frame_index
                        .as_ref()
                        .expect("duplicate preaccepted frame index")
                        .parse::<u64>()
                        .expect("preaccepted frame index");
                    let preaccepted_plaintext = decode_hex(
                        case.preaccepted_plaintext_hex
                            .as_deref()
                            .expect("duplicate preaccepted plaintext"),
                    );
                    let preaccepted_ciphertext = expected_ciphertext(
                        &frame_keys,
                        sender_slot,
                        &nonce_from_counter(preaccepted_index),
                        &preaccepted_plaintext,
                    );
                    let opened =
                        peer_cipher
                            .decrypt(&preaccepted_ciphertext)
                            .unwrap_or_else(|err| {
                                panic!("{} preaccepted frame decrypt: {err}", case.name)
                            });
                    assert_eq!(opened, preaccepted_plaintext, "{} preaccepted", case.name);
                }
                "future_before_current" => {
                    assert!(
                        case.preaccepted_frame_index.is_none(),
                        "{} no preaccepted frame",
                        case.name
                    );
                    assert!(
                        case.preaccepted_plaintext_hex.is_none(),
                        "{} no preaccepted plaintext",
                        case.name
                    );
                }
                "stale_after_three" => {
                    assert_eq!(
                        case.preaccepted_frame_indices.len(),
                        case.preaccepted_plaintexts_hex.len(),
                        "{} preaccepted frame/plaintext count",
                        case.name
                    );
                    assert!(
                        !case.preaccepted_frame_indices.is_empty(),
                        "{} has preaccepted frames",
                        case.name
                    );
                    for (index_hex, plaintext_hex) in case
                        .preaccepted_frame_indices
                        .iter()
                        .zip(case.preaccepted_plaintexts_hex.iter())
                    {
                        let preaccepted_index =
                            index_hex.parse::<u64>().expect("preaccepted frame index");
                        assert_eq!(
                            peer_cipher.recv_nonce(),
                            preaccepted_index,
                            "{} recv counter before preaccepted frame {preaccepted_index}",
                            case.name
                        );
                        let preaccepted_plaintext = decode_hex(plaintext_hex);
                        let preaccepted_ciphertext = expected_ciphertext(
                            &frame_keys,
                            sender_slot,
                            &nonce_from_counter(preaccepted_index),
                            &preaccepted_plaintext,
                        );
                        let opened = match peer_cipher.decrypt(&preaccepted_ciphertext) {
                            Ok(opened) => opened,
                            Err(err) => panic!(
                                "{} preaccepted stale setup frame {preaccepted_index}: {err}",
                                case.name
                            ),
                        };
                        assert_eq!(
                            opened, preaccepted_plaintext,
                            "{} preaccepted stale setup frame {preaccepted_index}",
                            case.name
                        );
                    }
                }
                other => panic!("{} unknown scenario {other}", case.name),
            }

            assert_eq!(
                peer_cipher.recv_nonce(),
                expected_recv_before,
                "{} recv counter before rejection",
                case.name
            );

            let rejected_plaintext = decode_hex(
                case.rejected_plaintext_hex
                    .as_deref()
                    .expect("rejected plaintext"),
            );
            let rejected_ciphertext = expected_ciphertext(
                &frame_keys,
                sender_slot,
                &nonce_from_counter(rejected_frame_index),
                &rejected_plaintext,
            );
            let rejected = peer_cipher.decrypt(&rejected_ciphertext);
            assert_eq!(
                rejected.is_ok(),
                case.expected_rejected_valid,
                "{} rejected validity",
                case.name
            );
            assert!(
                rejected.is_err(),
                "{} rejected frame must fail authentication",
                case.name
            );
            if case.expected_reject_preserves_recv_counter {
                assert_eq!(
                    peer_cipher.recv_nonce(),
                    expected_recv_after,
                    "{} rejected frame preserves recv counter",
                    case.name
                );
            }

            let recovery_plaintext = decode_hex(
                case.recovery_plaintext_hex
                    .as_deref()
                    .expect("recovery plaintext"),
            );
            let recovery_ciphertext = expected_ciphertext(
                &frame_keys,
                sender_slot,
                &nonce_from_counter(recovery_frame_index),
                &recovery_plaintext,
            );
            let recovered = peer_cipher
                .decrypt(&recovery_ciphertext)
                .unwrap_or_else(|err| {
                    panic!("{} recovery frame after rejection: {err}", case.name)
                });
            assert_eq!(recovered, recovery_plaintext, "{} recovery", case.name);
            assert_eq!(
                peer_cipher.recv_nonce(),
                expected_recovery_next,
                "{} recovery advances recv counter",
                case.name
            );
        }

        for case in &vectors.role_misbind_cases {
            let is_initiator = parse_role(&case.role);
            let (sender_slot, same_role_recv_slot) = session_key_slots(is_initiator);
            assert_eq!(
                slot_name(sender_slot),
                case.expected_sender_slot,
                "{} sender slot",
                case.name
            );
            assert_eq!(
                slot_name(same_role_recv_slot),
                case.expected_same_role_open_slot,
                "{} same-role open slot",
                case.name
            );
            assert_eq!(
                sender_slot == same_role_recv_slot,
                case.expected_sender_slot_matches_same_role_open,
                "{} same-role slot mismatch",
                case.name
            );

            let frame_index = case.frame_index.parse::<u64>().expect("frame index u64");
            let nonce = nonce_from_counter(frame_index);
            assert_eq!(
                nonce.to_vec(),
                decode_hex(&case.expected_nonce_hex),
                "{} nonce",
                case.name
            );

            let plaintext = decode_hex(&case.plaintext_hex);
            let ciphertext = expected_ciphertext(&frame_keys, sender_slot, &nonce, &plaintext);
            let mut same_role_opener = NoiseCipher::new(&frame_keys, is_initiator)
                .unwrap_or_else(|err| panic!("{} same-role opener: {err}", case.name));
            let rejected = same_role_opener.decrypt(&ciphertext);
            assert_eq!(
                rejected.is_ok(),
                case.expected_rejected_valid,
                "{} same-role rejected validity",
                case.name
            );
            assert!(
                rejected.is_err(),
                "{} same-role frame must fail authentication",
                case.name
            );
            if case.expected_reject_preserves_recv_counter {
                assert_eq!(
                    same_role_opener.recv_nonce(),
                    case.expected_recv_counter_after_reject
                        .parse::<u64>()
                        .expect("recv counter after reject"),
                    "{} same-role reject preserves recv counter",
                    case.name
                );
            }
        }

        for case in &vectors.transport_completion_cases {
            let local_is_initiator = parse_role(&case.local_role);
            let peer_is_initiator = parse_role(&case.peer_role);
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

            let local_identity =
                LocalIdentity::generate(format!("{}-local-identity", case.name).as_bytes());
            let peer_identity =
                LocalIdentity::generate(format!("{}-peer-identity", case.name).as_bytes());
            let local_peer_id = local_identity.peer_id();
            let peer_peer_id = peer_identity.peer_id();
            let local_transport = PqTransport::new(PqNoiseConfig::new(local_identity));
            let peer_transport = PqTransport::new(PqNoiseConfig::new(peer_identity));
            let (local_stream, peer_stream) = duplex(64 * 1024);

            let (local_result, peer_result) = if local_is_initiator {
                tokio::join!(
                    local_transport.upgrade_outbound(local_stream),
                    peer_transport.upgrade_inbound(peer_stream)
                )
            } else {
                tokio::join!(
                    local_transport.upgrade_inbound(local_stream),
                    peer_transport.upgrade_outbound(peer_stream)
                )
            };

            let (mut local_session, local_observed_peer_id) = local_result
                .unwrap_or_else(|err| panic!("{} local transport upgrade: {err}", case.name));
            let (mut peer_session, peer_observed_peer_id) = peer_result
                .unwrap_or_else(|err| panic!("{} peer transport upgrade: {err}", case.name));

            assert_eq!(
                local_observed_peer_id, peer_peer_id,
                "{} local observed remote peer id",
                case.name
            );
            assert_eq!(
                peer_observed_peer_id, local_peer_id,
                "{} peer observed remote peer id",
                case.name
            );
            assert_eq!(
                local_session.remote_peer_id(),
                peer_peer_id,
                "{} local session remote peer id",
                case.name
            );
            assert_eq!(
                peer_session.remote_peer_id(),
                local_peer_id,
                "{} peer session remote peer id",
                case.name
            );
            assert_eq!(
                local_session.is_initiator(),
                case.expected_local_is_initiator,
                "{} local session role flag",
                case.name
            );
            assert_eq!(
                peer_session.is_initiator(),
                case.expected_peer_is_initiator,
                "{} peer session role flag",
                case.name
            );

            let (local_send_slot, local_recv_slot) =
                session_key_slots(local_session.is_initiator());
            let (peer_send_slot, peer_recv_slot) = session_key_slots(peer_session.is_initiator());
            assert_eq!(
                slot_name(local_send_slot),
                case.expected_local_send_slot,
                "{} local send slot",
                case.name
            );
            assert_eq!(
                slot_name(local_recv_slot),
                case.expected_local_recv_slot,
                "{} local recv slot",
                case.name
            );
            assert_eq!(
                slot_name(peer_send_slot),
                case.expected_peer_send_slot,
                "{} peer send slot",
                case.name
            );
            assert_eq!(
                slot_name(peer_recv_slot),
                case.expected_peer_recv_slot,
                "{} peer recv slot",
                case.name
            );
            assert_eq!(
                local_send_slot == peer_recv_slot,
                case.expected_local_send_matches_peer_recv,
                "{} local-send peer-recv slot match",
                case.name
            );
            assert_eq!(
                local_recv_slot == peer_send_slot,
                case.expected_local_recv_matches_peer_send,
                "{} local-recv peer-send slot match",
                case.name
            );

            assert_eq!(
                local_session.bytes_sent(),
                case.expected_initial_local_bytes_sent
                    .parse::<u64>()
                    .expect("initial local bytes sent"),
                "{} initial local bytes sent",
                case.name
            );
            assert_eq!(
                local_session.bytes_received(),
                case.expected_initial_local_bytes_received
                    .parse::<u64>()
                    .expect("initial local bytes received"),
                "{} initial local bytes received",
                case.name
            );
            assert_eq!(
                peer_session.bytes_sent(),
                case.expected_initial_peer_bytes_sent
                    .parse::<u64>()
                    .expect("initial peer bytes sent"),
                "{} initial peer bytes sent",
                case.name
            );
            assert_eq!(
                peer_session.bytes_received(),
                case.expected_initial_peer_bytes_received
                    .parse::<u64>()
                    .expect("initial peer bytes received"),
                "{} initial peer bytes received",
                case.name
            );

            let plaintext = decode_hex(&case.plaintext_hex);
            let expected_wire_bytes = case
                .expected_first_frame_wire_bytes
                .parse::<u64>()
                .expect("first frame wire bytes");
            assert_eq!(
                expected_wire_bytes,
                plaintext.len() as u64 + 16,
                "{} first frame wire accounting",
                case.name
            );
            let (send_result, recv_result) =
                tokio::join!(local_session.send(&plaintext), peer_session.recv());
            send_result
                .unwrap_or_else(|err| panic!("{} local transport session send: {err}", case.name));
            let opened = recv_result
                .unwrap_or_else(|err| panic!("{} peer transport session recv: {err}", case.name))
                .unwrap_or_else(|| panic!("{} peer transport session EOF", case.name));
            assert_eq!(opened, plaintext, "{} peer receives local frame", case.name);
            assert_eq!(
                local_session.bytes_sent(),
                expected_wire_bytes,
                "{} local bytes sent after first frame",
                case.name
            );
            assert_eq!(
                peer_session.bytes_received(),
                expected_wire_bytes,
                "{} peer bytes received after first frame",
                case.name
            );
        }

        for case in &vectors.init_signing_cases {
            let msg = types::InitHelloMessage {
                version: case.version,
                mlkem_public_key: decode_hex(&case.mlkem_public_key_hex),
                identity_key: decode_hex(&case.identity_key_hex),
                nonce: case.nonce.parse::<u64>().expect("nonce u64"),
                signature: Vec::new(),
            };
            let preimage = init_hello_signing_preimage(&msg);
            assert_eq!(
                preimage,
                decode_hex(&case.expected_preimage_hex),
                "{} init preimage",
                case.name
            );
            assert_eq!(init_hello_signing_data(&msg), signing_digest(&preimage));
            assert_eq!(init_hello_signing_data(&msg).len(), 32);
        }

        for case in &vectors.resp_signing_cases {
            let transcript_hash = decode_array_32(&case.transcript_hash_hex);
            let msg = types::RespHelloMessage {
                version: case.version,
                mlkem_public_key: decode_hex(&case.mlkem_public_key_hex),
                mlkem_ciphertext: decode_hex(&case.mlkem_ciphertext_hex),
                identity_key: decode_hex(&case.identity_key_hex),
                nonce: case.nonce.parse::<u64>().expect("nonce u64"),
                signature: Vec::new(),
            };
            let preimage = resp_hello_signing_preimage(&msg, &transcript_hash);
            assert_eq!(
                preimage,
                decode_hex(&case.expected_preimage_hex),
                "{} resp preimage",
                case.name
            );
            assert_eq!(
                resp_hello_signing_data(&msg, &transcript_hash),
                signing_digest(&preimage)
            );
            assert_eq!(resp_hello_signing_data(&msg, &transcript_hash).len(), 32);
        }

        for case in &vectors.finish_signing_cases {
            let transcript_hash = decode_array_32(&case.transcript_hash_hex);
            let msg = types::FinishMessage {
                mlkem_ciphertext: decode_hex(&case.mlkem_ciphertext_hex),
                nonce: case.nonce.parse::<u64>().expect("nonce u64"),
                signature: Vec::new(),
            };
            let preimage = finish_signing_preimage(&msg, &transcript_hash);
            assert_eq!(
                preimage,
                decode_hex(&case.expected_preimage_hex),
                "{} finish preimage",
                case.name
            );
            assert_eq!(
                finish_signing_data(&msg, &transcript_hash),
                signing_digest(&preimage)
            );
            assert_eq!(finish_signing_data(&msg, &transcript_hash).len(), 32);
        }
    }
}
