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
    use crate::handshake::{
        finish_signing_data, finish_signing_preimage, init_hello_signing_data,
        init_hello_signing_preimage, resp_hello_signing_data, resp_hello_signing_preimage,
        signing_digest,
    };
    use crate::noise::{nonce_from_counter, nonce_step};
    use crate::types::{
        select_session_key, session_key_expand_info, session_key_material, session_key_slots,
        SessionKeySlot, PQ_NOISE_AAD_INFO, PQ_NOISE_I2R_INFO, PQ_NOISE_R2I_INFO,
    };
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct LeanPqNoiseVectorFile {
        schema_version: u32,
        session_key_cases: Vec<LeanSessionKeyCase>,
        role_cases: Vec<LeanRoleCase>,
        nonce_cases: Vec<LeanNonceCase>,
        init_signing_cases: Vec<LeanInitSigningCase>,
        resp_signing_cases: Vec<LeanRespSigningCase>,
        finish_signing_cases: Vec<LeanFinishSigningCase>,
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

    #[test]
    fn lean_generated_pq_noise_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_PQ_NOISE_VECTORS") else {
            eprintln!("skipping Lean PQ Noise vectors; env var not set");
            return;
        };
        let contents = std::fs::read_to_string(path).expect("read Lean PQ Noise vectors");
        let vectors: LeanPqNoiseVectorFile =
            serde_json::from_str(&contents).expect("parse Lean PQ Noise vectors");
        assert_eq!(vectors.schema_version, 1);

        for case in vectors.session_key_cases {
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

        for case in vectors.role_cases {
            let is_initiator = parse_role(&case.role);
            let (send_slot, recv_slot) = session_key_slots(is_initiator);
            assert_eq!(slot_name(send_slot), case.expected_send_slot);
            assert_eq!(slot_name(recv_slot), case.expected_recv_slot);
            assert_eq!(send_slot != recv_slot, case.expected_send_recv_distinct);
        }

        for case in vectors.nonce_cases {
            let counter = case.counter.parse::<u64>().expect("counter u64");
            assert_eq!(
                nonce_from_counter(counter).to_vec(),
                decode_hex(&case.expected_nonce_hex),
                "{} nonce",
                case.name
            );
            let step = nonce_step(counter);
            assert_eq!(step.is_ok(), case.expected_valid, "{} validity", case.name);
            match (step.ok(), case.expected_next_counter) {
                (Some((_, next)), Some(expected)) => {
                    assert_eq!(next, expected.parse::<u64>().expect("next counter u64"));
                }
                (None, None) => {}
                other => panic!("{} counter mismatch: {other:?}", case.name),
            }
        }

        for case in vectors.init_signing_cases {
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

        for case in vectors.resp_signing_cases {
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

        for case in vectors.finish_signing_cases {
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
