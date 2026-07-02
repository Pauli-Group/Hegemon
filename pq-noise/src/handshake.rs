//! Pure ML-KEM-1024 handshake implementation (no classical ECDH)

use crypto::ml_dsa::{MlDsaPublicKey, MlDsaSignature};
use crypto::ml_kem::{MlKemCiphertext, MlKemKeyPair, MlKemPublicKey, MlKemSharedSecret};
use crypto::traits::{KemKeyPair, KemPublicKey, SigningKey, VerifyKey};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::codec;
use crate::config::PqNoiseConfig;
use crate::error::{HandshakeError, Result};
use crate::noise::Transcript;
use crate::types::{
    FinishMessage, HandshakeMessage, InitHelloMessage, PeerId, RemotePeer, RespHelloMessage,
    SessionKeys, PROTOCOL_VERSION,
};

/// Handshake state machine
pub struct PqHandshake {
    config: PqNoiseConfig,
    transcript: Transcript,
    remote_peer: Option<RemotePeer>,
    local_ephemeral_kem: Option<MlKemKeyPair>,
    mlkem_shared_1: Option<MlKemSharedSecret>,
    mlkem_shared_2: Option<MlKemSharedSecret>,
}

impl PqHandshake {
    /// Create a new handshake instance
    pub fn new(config: PqNoiseConfig) -> Self {
        Self {
            config,
            transcript: Transcript::new(),
            remote_peer: None,
            local_ephemeral_kem: None,
            mlkem_shared_1: None,
            mlkem_shared_2: None,
        }
    }

    /// Generate the initiator's hello message
    pub fn initiator_hello(&mut self) -> Result<HandshakeMessage> {
        // Get our identity key and a fresh per-session KEM public key.
        let identity_key = self.config.identity.verify_key.to_bytes();
        let local_ephemeral_kem = random_kem_keypair();
        let mlkem_public_key = local_ephemeral_kem.public_key().to_bytes();
        self.local_ephemeral_kem = Some(local_ephemeral_kem);

        let nonce = random_nonce();

        // Create message (without signature first)
        let message = InitHelloMessage {
            version: PROTOCOL_VERSION,
            mlkem_public_key: mlkem_public_key.clone(),
            identity_key: identity_key.clone(),
            nonce,
            signature: Vec::new(), // Placeholder
        };

        // Sign the message
        let signing_data = self.compute_init_hello_signing_data(&message);
        let signature = self.config.identity.signing_key.sign(&signing_data);

        let signed_message = InitHelloMessage {
            signature: signature.to_bytes().to_vec(),
            ..message
        };

        // Update transcript
        let serialized = codec::encode_transcript(&signed_message)?;
        self.transcript.update(&serialized);

        if self.config.verbose_logging {
            tracing::debug!(
                peer_id = %hex::encode(self.config.identity.peer_id()),
                "Generated InitHello message"
            );
        }

        Ok(HandshakeMessage::InitHello(signed_message))
    }

    /// Process the initiator's hello and generate responder's hello
    pub fn responder_process_init_hello(
        &mut self,
        init_hello: InitHelloMessage,
    ) -> Result<HandshakeMessage> {
        // Verify protocol version
        if init_hello.version != PROTOCOL_VERSION {
            return Err(HandshakeError::VersionMismatch {
                local: PROTOCOL_VERSION,
                remote: init_hello.version,
            }
            .into());
        }

        // Verify initiator's signature
        let initiator_pk = MlDsaPublicKey::from_bytes(&init_hello.identity_key)?;
        let signing_data = self.compute_init_hello_signing_data(&init_hello);
        let signature = MlDsaSignature::from_bytes(&init_hello.signature)?;
        initiator_pk
            .verify(&signing_data, &signature)
            .map_err(|_| HandshakeError::InvalidSignature)?;

        // Update transcript with received message
        let serialized = codec::encode_transcript(&init_hello)?;
        self.transcript.update(&serialized);

        // Store remote peer info
        let remote_peer =
            RemotePeer::from_handshake(&init_hello.identity_key, &init_hello.mlkem_public_key)?;
        self.remote_peer = Some(remote_peer.clone());

        // Encapsulate to initiator's ML-KEM public key
        let initiator_mlkem_pk = MlKemPublicKey::from_bytes(&init_hello.mlkem_public_key)?;
        let encap_seed = random_encapsulation_seed();
        let (ciphertext, shared_secret) = encapsulate_with_seed(&initiator_mlkem_pk, &encap_seed);
        self.mlkem_shared_1 = Some(shared_secret);

        // Get our identity key and a fresh per-session KEM public key.
        let identity_key = self.config.identity.verify_key.to_bytes();
        let local_ephemeral_kem = random_kem_keypair();
        let mlkem_public_key = local_ephemeral_kem.public_key().to_bytes();
        self.local_ephemeral_kem = Some(local_ephemeral_kem);

        let nonce = random_nonce();

        // Create message (without signature)
        let message = RespHelloMessage {
            version: PROTOCOL_VERSION,
            mlkem_public_key: mlkem_public_key.clone(),
            mlkem_ciphertext: ciphertext.to_bytes().to_vec(),
            identity_key: identity_key.clone(),
            nonce,
            signature: Vec::new(),
        };

        // Sign the message
        let signing_data = self.compute_resp_hello_signing_data(&message);
        let signature = self.config.identity.signing_key.sign(&signing_data);

        let signed_message = RespHelloMessage {
            signature: signature.to_bytes().to_vec(),
            ..message
        };

        // Update transcript
        let serialized = codec::encode_transcript(&signed_message)?;
        self.transcript.update(&serialized);

        if self.config.verbose_logging {
            tracing::debug!(
                peer_id = %hex::encode(remote_peer.peer_id),
                "Generated RespHello message"
            );
        }

        Ok(HandshakeMessage::RespHello(signed_message))
    }

    /// Process the responder's hello and generate finish message
    pub fn initiator_process_resp_hello(
        &mut self,
        resp_hello: RespHelloMessage,
    ) -> Result<HandshakeMessage> {
        // Verify protocol version
        if resp_hello.version != PROTOCOL_VERSION {
            return Err(HandshakeError::VersionMismatch {
                local: PROTOCOL_VERSION,
                remote: resp_hello.version,
            }
            .into());
        }

        // Verify responder's signature
        let responder_pk = MlDsaPublicKey::from_bytes(&resp_hello.identity_key)?;
        let signing_data = self.compute_resp_hello_signing_data(&resp_hello);
        let signature = MlDsaSignature::from_bytes(&resp_hello.signature)?;
        responder_pk
            .verify(&signing_data, &signature)
            .map_err(|_| HandshakeError::InvalidSignature)?;

        // Update transcript
        let serialized = codec::encode_transcript(&resp_hello)?;
        self.transcript.update(&serialized);

        // Store remote peer info
        let remote_peer =
            RemotePeer::from_handshake(&resp_hello.identity_key, &resp_hello.mlkem_public_key)?;
        self.remote_peer = Some(remote_peer.clone());

        // Decapsulate the ciphertext from responder
        let ciphertext = MlKemCiphertext::from_bytes(&resp_hello.mlkem_ciphertext)?;
        let shared_secret_1 = self
            .local_ephemeral_kem
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?
            .decapsulate(&ciphertext)?;
        self.local_ephemeral_kem = None;
        self.mlkem_shared_1 = Some(shared_secret_1);

        // Encapsulate to responder's ML-KEM public key
        let responder_mlkem_pk = MlKemPublicKey::from_bytes(&resp_hello.mlkem_public_key)?;
        let encap_seed = random_encapsulation_seed();
        let (ciphertext, shared_secret_2) = encapsulate_with_seed(&responder_mlkem_pk, &encap_seed);
        self.mlkem_shared_2 = Some(shared_secret_2);

        let nonce = random_nonce();

        // Create finish message (without signature)
        let message = FinishMessage {
            mlkem_ciphertext: ciphertext.to_bytes().to_vec(),
            nonce,
            signature: Vec::new(),
        };

        // Sign the message
        let signing_data = self.compute_finish_signing_data(&message);
        let signature = self.config.identity.signing_key.sign(&signing_data);

        let signed_message = FinishMessage {
            signature: signature.to_bytes().to_vec(),
            ..message
        };

        // Update transcript
        let serialized = codec::encode_transcript(&signed_message)?;
        self.transcript.update(&serialized);

        if self.config.verbose_logging {
            tracing::debug!(
                peer_id = %hex::encode(remote_peer.peer_id),
                "Generated Finish message"
            );
        }

        Ok(HandshakeMessage::Finish(signed_message))
    }

    /// Process the finish message and complete the handshake (responder side)
    pub fn responder_process_finish(&mut self, finish: FinishMessage) -> Result<SessionKeys> {
        // Get stored remote peer (from init hello)
        let remote_peer = self
            .remote_peer
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?;

        // Verify initiator's signature
        let signing_data = self.compute_finish_signing_data(&finish);
        let signature = MlDsaSignature::from_bytes(&finish.signature)?;
        remote_peer
            .identity_key
            .verify(&signing_data, &signature)
            .map_err(|_| HandshakeError::InvalidSignature)?;

        // Update transcript
        let serialized = codec::encode_transcript(&finish)?;
        self.transcript.update(&serialized);

        // Decapsulate the ciphertext from initiator
        let ciphertext = MlKemCiphertext::from_bytes(&finish.mlkem_ciphertext)?;
        let shared_secret_2 = self
            .local_ephemeral_kem
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?
            .decapsulate(&ciphertext)?;
        self.local_ephemeral_kem = None;
        self.mlkem_shared_2 = Some(shared_secret_2);

        // Derive session keys
        self.derive_session_keys()
    }

    /// Complete the handshake and derive session keys (initiator side)
    pub fn initiator_complete(&self) -> Result<SessionKeys> {
        self.derive_session_keys()
    }

    /// Derive session keys from handshake state
    fn derive_session_keys(&self) -> Result<SessionKeys> {
        let mlkem_shared_1 = self
            .mlkem_shared_1
            .as_ref()
            .ok_or(HandshakeError::KeyDerivation)?;
        let mlkem_shared_2 = self
            .mlkem_shared_2
            .as_ref()
            .ok_or(HandshakeError::KeyDerivation)?;

        // Convert MlKemSharedSecret to [u8; 32]
        let mut ss1 = [0u8; 32];
        let mut ss2 = [0u8; 32];
        ss1.copy_from_slice(mlkem_shared_1.as_bytes());
        ss2.copy_from_slice(mlkem_shared_2.as_bytes());

        let transcript_hash = self.transcript.hash();
        let keys = SessionKeys::derive(&transcript_hash, &ss1, &ss2);

        if self.config.verbose_logging {
            tracing::info!("PQ handshake complete with ML-KEM-1024 (pure post-quantum)");
        }

        Ok(keys)
    }

    /// Get the remote peer info (after handshake)
    pub fn remote_peer(&self) -> Option<&RemotePeer> {
        self.remote_peer.as_ref()
    }

    /// Get the remote peer ID (after handshake)
    pub fn remote_peer_id(&self) -> Option<PeerId> {
        self.remote_peer.as_ref().map(|p| p.peer_id)
    }

    // Helper methods to compute signing data

    fn compute_init_hello_signing_data(&self, msg: &InitHelloMessage) -> Vec<u8> {
        init_hello_signing_data(msg)
    }

    fn compute_resp_hello_signing_data(&self, msg: &RespHelloMessage) -> Vec<u8> {
        let transcript_hash = self.transcript.hash();
        resp_hello_signing_data(msg, &transcript_hash)
    }

    fn compute_finish_signing_data(&self, msg: &FinishMessage) -> Vec<u8> {
        let transcript_hash = self.transcript.hash();
        finish_signing_data(msg, &transcript_hash)
    }
}

pub(crate) fn init_hello_signing_preimage(msg: &InitHelloMessage) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(
        b"init-hello".len() + 1 + msg.mlkem_public_key.len() + msg.identity_key.len() + 8,
    );
    preimage.extend_from_slice(b"init-hello");
    preimage.push(msg.version);
    preimage.extend_from_slice(&msg.mlkem_public_key);
    preimage.extend_from_slice(&msg.identity_key);
    preimage.extend_from_slice(&msg.nonce.to_be_bytes());
    preimage
}

pub(crate) fn resp_hello_signing_preimage(
    msg: &RespHelloMessage,
    transcript_hash: &[u8; 32],
) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(
        b"resp-hello".len()
            + 1
            + msg.mlkem_public_key.len()
            + msg.mlkem_ciphertext.len()
            + msg.identity_key.len()
            + 8
            + transcript_hash.len(),
    );
    preimage.extend_from_slice(b"resp-hello");
    preimage.push(msg.version);
    preimage.extend_from_slice(&msg.mlkem_public_key);
    preimage.extend_from_slice(&msg.mlkem_ciphertext);
    preimage.extend_from_slice(&msg.identity_key);
    preimage.extend_from_slice(&msg.nonce.to_be_bytes());
    preimage.extend_from_slice(transcript_hash);
    preimage
}

pub(crate) fn finish_signing_preimage(msg: &FinishMessage, transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(
        b"finish".len() + msg.mlkem_ciphertext.len() + 8 + transcript_hash.len(),
    );
    preimage.extend_from_slice(b"finish");
    preimage.extend_from_slice(&msg.mlkem_ciphertext);
    preimage.extend_from_slice(&msg.nonce.to_be_bytes());
    preimage.extend_from_slice(transcript_hash);
    preimage
}

pub(crate) fn signing_digest(preimage: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    hasher.finalize().to_vec()
}

pub(crate) fn init_hello_signing_data(msg: &InitHelloMessage) -> Vec<u8> {
    signing_digest(&init_hello_signing_preimage(msg))
}

pub(crate) fn resp_hello_signing_data(
    msg: &RespHelloMessage,
    transcript_hash: &[u8; 32],
) -> Vec<u8> {
    signing_digest(&resp_hello_signing_preimage(msg, transcript_hash))
}

pub(crate) fn finish_signing_data(msg: &FinishMessage, transcript_hash: &[u8; 32]) -> Vec<u8> {
    signing_digest(&finish_signing_preimage(msg, transcript_hash))
}

fn random_nonce() -> u64 {
    OsRng.next_u64()
}

fn random_kem_keypair() -> MlKemKeyPair {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let keypair = MlKemKeyPair::generate_deterministic(&seed);
    seed.fill(0);
    keypair
}

pub(crate) fn random_encapsulation_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

pub(crate) fn encapsulate_with_seed(
    public_key: &MlKemPublicKey,
    seed: &[u8; 32],
) -> (MlKemCiphertext, MlKemSharedSecret) {
    public_key.encapsulate(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PqNoiseConfig;
    use crate::error::PqNoiseError;
    use crate::noise::Transcript;
    use crate::types::LocalIdentity;
    use crypto::hashes::sha256;

    #[test]
    fn test_full_handshake() {
        let initiator_identity = LocalIdentity::generate(b"test-initiator-seed");
        let responder_identity = LocalIdentity::generate(b"test-responder-seed");

        let initiator_config = PqNoiseConfig::new(initiator_identity.clone());
        let responder_config = PqNoiseConfig::new(responder_identity.clone());

        // Step 1: Initiator creates InitHello
        let mut initiator = PqHandshake::new(initiator_config);
        let init_hello = initiator.initiator_hello().unwrap();
        let init_hello_msg = match init_hello {
            HandshakeMessage::InitHello(msg) => msg,
            _ => panic!("Expected InitHello"),
        };

        // Step 2: Responder processes InitHello, creates RespHello
        let mut responder = PqHandshake::new(responder_config);
        let resp_hello = responder
            .responder_process_init_hello(init_hello_msg)
            .unwrap();
        let resp_hello_msg = match resp_hello {
            HandshakeMessage::RespHello(msg) => msg,
            _ => panic!("Expected RespHello"),
        };

        // Step 3: Initiator processes RespHello, creates Finish
        let finish = initiator
            .initiator_process_resp_hello(resp_hello_msg)
            .unwrap();
        let finish_msg = match finish {
            HandshakeMessage::Finish(msg) => msg,
            _ => panic!("Expected Finish"),
        };

        // Step 4: Responder processes Finish, derives keys
        let responder_keys = responder.responder_process_finish(finish_msg).unwrap();

        // Step 5: Initiator derives keys
        let initiator_keys = initiator.initiator_complete().unwrap();

        // Verify keys match
        assert_eq!(
            initiator_keys.initiator_to_responder,
            responder_keys.initiator_to_responder
        );
        assert_eq!(
            initiator_keys.responder_to_initiator,
            responder_keys.responder_to_initiator
        );
        assert_eq!(initiator_keys.session_aad, responder_keys.session_aad);

        // Verify peer IDs are correct
        assert_eq!(
            initiator.remote_peer_id().unwrap(),
            responder_identity.peer_id()
        );
        assert_eq!(
            responder.remote_peer_id().unwrap(),
            initiator_identity.peer_id()
        );
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let initiator_identity = LocalIdentity::generate(b"test-initiator-2");
        let responder_identity = LocalIdentity::generate(b"test-responder-2");

        let initiator_config = PqNoiseConfig::new(initiator_identity);
        let responder_config = PqNoiseConfig::new(responder_identity);

        let mut initiator = PqHandshake::new(initiator_config);
        let init_hello = initiator.initiator_hello().unwrap();
        let mut init_hello_msg = match init_hello {
            HandshakeMessage::InitHello(msg) => msg,
            _ => panic!("Expected InitHello"),
        };

        // Tamper with the signature
        init_hello_msg.signature[0] ^= 0xFF;

        let mut responder = PqHandshake::new(responder_config);
        let result = responder.responder_process_init_hello(init_hello_msg);

        assert!(matches!(
            result,
            Err(PqNoiseError::Handshake(HandshakeError::InvalidSignature))
        ));
    }

    #[test]
    fn test_version_mismatch() {
        let initiator_identity = LocalIdentity::generate(b"test-initiator-3");
        let responder_identity = LocalIdentity::generate(b"test-responder-3");

        let initiator_config = PqNoiseConfig::new(initiator_identity);
        let responder_config = PqNoiseConfig::new(responder_identity);

        let mut initiator = PqHandshake::new(initiator_config);
        let init_hello = initiator.initiator_hello().unwrap();
        let mut init_hello_msg = match init_hello {
            HandshakeMessage::InitHello(msg) => msg,
            _ => panic!("Expected InitHello"),
        };

        // Change version
        init_hello_msg.version = 99;

        let mut responder = PqHandshake::new(responder_config);
        let result = responder.responder_process_init_hello(init_hello_msg);

        assert!(matches!(
            result,
            Err(PqNoiseError::Handshake(
                HandshakeError::VersionMismatch { .. }
            ))
        ));
    }

    #[test]
    fn handshake_does_not_use_public_transcript_as_kem_seed() {
        let initiator_identity = LocalIdentity::generate(b"public-seed-check-initiator");
        let responder_identity = LocalIdentity::generate(b"public-seed-check-responder");

        let initiator_config = PqNoiseConfig::new(initiator_identity);
        let responder_config = PqNoiseConfig::new(responder_identity);

        let mut initiator = PqHandshake::new(initiator_config);
        let init_hello = initiator.initiator_hello().unwrap();
        let init_hello_msg = match init_hello {
            HandshakeMessage::InitHello(msg) => msg,
            _ => panic!("Expected InitHello"),
        };

        let mut public_transcript = Transcript::new();
        public_transcript.update(&codec::encode_transcript(&init_hello_msg).unwrap());

        let old_public_seed_1 = sha256(&[&public_transcript.hash()[..], b"encap1"].concat());
        let initiator_mlkem_pk =
            MlKemPublicKey::from_bytes(&init_hello_msg.mlkem_public_key).unwrap();
        let (old_public_ct_1, _) = initiator_mlkem_pk.encapsulate(&old_public_seed_1);

        let mut responder = PqHandshake::new(responder_config);
        let resp_hello = responder
            .responder_process_init_hello(init_hello_msg)
            .unwrap();
        let resp_hello_msg = match resp_hello {
            HandshakeMessage::RespHello(msg) => msg,
            _ => panic!("Expected RespHello"),
        };

        assert_ne!(
            old_public_ct_1.to_bytes().to_vec(),
            resp_hello_msg.mlkem_ciphertext,
            "ML-KEM response ciphertext must not be reproducible from public transcript bytes"
        );

        public_transcript.update(&codec::encode_transcript(&resp_hello_msg).unwrap());
        let old_public_seed_2 = sha256(&[&public_transcript.hash()[..], b"encap2"].concat());
        let responder_mlkem_pk =
            MlKemPublicKey::from_bytes(&resp_hello_msg.mlkem_public_key).unwrap();
        let (old_public_ct_2, _) = responder_mlkem_pk.encapsulate(&old_public_seed_2);

        let finish = initiator
            .initiator_process_resp_hello(resp_hello_msg)
            .unwrap();
        let finish_msg = match finish {
            HandshakeMessage::Finish(msg) => msg,
            _ => panic!("Expected Finish"),
        };

        assert_ne!(
            old_public_ct_2.to_bytes().to_vec(),
            finish_msg.mlkem_ciphertext,
            "ML-KEM finish ciphertext must not be reproducible from public transcript bytes"
        );
    }

    #[test]
    fn handshake_advertises_signed_ephemeral_kem_keys() {
        let initiator_identity = LocalIdentity::generate(b"ephemeral-kem-initiator");
        let responder_identity = LocalIdentity::generate(b"ephemeral-kem-responder");

        let initiator_static_kem = initiator_identity.kem_keypair.public_key().to_bytes();
        let responder_static_kem = responder_identity.kem_keypair.public_key().to_bytes();

        let mut initiator = PqHandshake::new(PqNoiseConfig::new(initiator_identity));
        let init_hello = match initiator.initiator_hello().unwrap() {
            HandshakeMessage::InitHello(msg) => msg,
            _ => panic!("Expected InitHello"),
        };
        assert_ne!(
            init_hello.mlkem_public_key, initiator_static_kem,
            "initiator must advertise a per-session KEM key, not its static identity KEM key"
        );

        let mut responder = PqHandshake::new(PqNoiseConfig::new(responder_identity));
        let resp_hello = match responder.responder_process_init_hello(init_hello).unwrap() {
            HandshakeMessage::RespHello(msg) => msg,
            _ => panic!("Expected RespHello"),
        };
        assert_ne!(
            resp_hello.mlkem_public_key, responder_static_kem,
            "responder must advertise a per-session KEM key, not its static identity KEM key"
        );
    }

    #[test]
    fn encapsulate_with_seed_consumes_supplied_seed() {
        let identity = LocalIdentity::generate(b"encapsulation-seed-binding");
        let public_key = identity.kem_keypair.public_key();
        let seed = [17u8; 32];

        let (ciphertext, shared_secret) = encapsulate_with_seed(&public_key, &seed);
        let (expected_ciphertext, expected_shared_secret) = public_key.encapsulate(&seed);

        assert_eq!(ciphertext.to_bytes(), expected_ciphertext.to_bytes());
        assert_eq!(shared_secret.as_bytes(), expected_shared_secret.as_bytes());
    }
}
