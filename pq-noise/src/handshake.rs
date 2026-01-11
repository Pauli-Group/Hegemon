//! Pure ML-KEM-768 handshake implementation (no classical ECDH)

use crypto::hashes::sha256;
use crypto::ml_dsa::{MlDsaPublicKey, MlDsaSignature};
use crypto::ml_kem::{MlKemCiphertext, MlKemPublicKey, MlKemSharedSecret};
use crypto::traits::{KemKeyPair, KemPublicKey, SigningKey, VerifyKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

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
            mlkem_shared_1: None,
            mlkem_shared_2: None,
        }
    }

    /// Generate the initiator's hello message
    pub fn initiator_hello(&mut self) -> Result<HandshakeMessage> {
        let mut rng = rand::thread_rng();

        // Get our identity and KEM public keys
        let identity_key = self.config.identity.verify_key.to_bytes();
        let mlkem_public_key = self.config.identity.kem_keypair.public_key().to_bytes();

        // Generate nonce
        let mut nonce_bytes = [0u8; 8];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = u64::from_be_bytes(nonce_bytes);

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
        let serialized = bincode::serialize(&signed_message)?;
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
        let serialized = bincode::serialize(&init_hello)?;
        self.transcript.update(&serialized);

        // Store remote peer info
        let remote_peer =
            RemotePeer::from_handshake(&init_hello.identity_key, &init_hello.mlkem_public_key)?;
        self.remote_peer = Some(remote_peer.clone());

        let mut rng = rand::thread_rng();

        // Encapsulate to initiator's ML-KEM public key
        let initiator_mlkem_pk = MlKemPublicKey::from_bytes(&init_hello.mlkem_public_key)?;
        let encap_seed = sha256(&[&self.transcript.hash()[..], b"encap1"].concat());
        let (ciphertext, shared_secret) = initiator_mlkem_pk.encapsulate(&encap_seed);
        self.mlkem_shared_1 = Some(shared_secret);

        // Get our identity and KEM public keys
        let identity_key = self.config.identity.verify_key.to_bytes();
        let mlkem_public_key = self.config.identity.kem_keypair.public_key().to_bytes();

        // Generate nonce
        let mut nonce_bytes = [0u8; 8];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = u64::from_be_bytes(nonce_bytes);

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
        let serialized = bincode::serialize(&signed_message)?;
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
        let serialized = bincode::serialize(&resp_hello)?;
        self.transcript.update(&serialized);

        // Store remote peer info
        let remote_peer =
            RemotePeer::from_handshake(&resp_hello.identity_key, &resp_hello.mlkem_public_key)?;
        self.remote_peer = Some(remote_peer.clone());

        // Decapsulate the ciphertext from responder
        let ciphertext = MlKemCiphertext::from_bytes(&resp_hello.mlkem_ciphertext)?;
        let shared_secret_1 = self.config.identity.kem_keypair.decapsulate(&ciphertext)?;
        self.mlkem_shared_1 = Some(shared_secret_1);

        // Encapsulate to responder's ML-KEM public key
        let responder_mlkem_pk = MlKemPublicKey::from_bytes(&resp_hello.mlkem_public_key)?;
        let encap_seed = sha256(&[&self.transcript.hash()[..], b"encap2"].concat());
        let (ciphertext, shared_secret_2) = responder_mlkem_pk.encapsulate(&encap_seed);
        self.mlkem_shared_2 = Some(shared_secret_2);

        let mut rng = rand::thread_rng();

        // Generate nonce
        let mut nonce_bytes = [0u8; 8];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = u64::from_be_bytes(nonce_bytes);

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
        let serialized = bincode::serialize(&signed_message)?;
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
        let serialized = bincode::serialize(&finish)?;
        self.transcript.update(&serialized);

        // Decapsulate the ciphertext from initiator
        let ciphertext = MlKemCiphertext::from_bytes(&finish.mlkem_ciphertext)?;
        let shared_secret_2 = self.config.identity.kem_keypair.decapsulate(&ciphertext)?;
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
            tracing::info!("PQ handshake complete with ML-KEM-768 (pure post-quantum)");
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
        let mut hasher = Sha256::new();
        hasher.update(b"init-hello");
        hasher.update([msg.version]);
        hasher.update(&msg.mlkem_public_key);
        hasher.update(&msg.identity_key);
        hasher.update(msg.nonce.to_be_bytes());
        hasher.finalize().to_vec()
    }

    fn compute_resp_hello_signing_data(&self, msg: &RespHelloMessage) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"resp-hello");
        hasher.update([msg.version]);
        hasher.update(&msg.mlkem_public_key);
        hasher.update(&msg.mlkem_ciphertext);
        hasher.update(&msg.identity_key);
        hasher.update(msg.nonce.to_be_bytes());
        hasher.update(self.transcript.hash());
        hasher.finalize().to_vec()
    }

    fn compute_finish_signing_data(&self, msg: &FinishMessage) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"finish");
        hasher.update(&msg.mlkem_ciphertext);
        hasher.update(msg.nonce.to_be_bytes());
        hasher.update(self.transcript.hash());
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PqNoiseConfig;
    use crate::error::PqNoiseError;
    use crate::types::LocalIdentity;

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
}
