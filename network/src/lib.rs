use aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use crypto::error::CryptoError;
use crypto::hashes::sha256;
use crypto::ml_dsa::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
use crypto::ml_kem::{MlKemCiphertext, MlKemKeyPair, MlKemPublicKey, MlKemSharedSecret};
use crypto::traits::{KemKeyPair, KemPublicKey, SigningKey, VerifyKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use thiserror::Error;
use tokio::sync::broadcast;

pub mod nat;
pub mod native_transport;
pub mod network_backend;
pub mod p2p;
pub mod peer_manager;
pub mod peer_store;
pub mod pq_transport;
pub mod protocol;
pub mod service;
pub mod wire;

pub use nat::{NatProtocol, NatTraversal, NatTraversalConfig, NatTraversalResult};
pub use native_transport::{
    NativePqConnection, NativePqTransport, NativePqTransportConfig, NativeTransportError,
    PqConnectionInfo, PqUpgradeOutput,
};
pub use network_backend::{
    BootstrapNode, PqNetworkBackend, PqNetworkBackendConfig, PqNetworkEvent, PqNetworkHandle,
};
pub use peer_store::{PeerStore, PeerStoreConfig};
pub use pq_transport::{
    PqPeerIdentity, PqSecureConnection, PqTransportConfig, upgrade_inbound, upgrade_outbound,
};
pub use protocol::{
    BLOCK_ANNOUNCES_PQ, NegotiationResult, NotificationProtocolConfig, PQ_PROTOCOL_V1,
    ProtocolNegotiationConfig, ProtocolSecurityLevel, ProtocolType, SYNC_PQ, TRANSACTIONS_PQ,
    is_pq_protocol, negotiate_protocol, protocol_security_level, protocol_type,
    supported_protocols,
};
pub use service::RelayConfig;
pub use service::{P2PService, ProtocolHandle};

pub type PeerId = [u8; 32];
pub type ProtocolId = u32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolMessage {
    pub protocol: ProtocolId,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("handshake error: {0}")]
    Handshake(&'static str),
    #[error("encryption error")]
    Encryption,
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeOffer {
    pub identity_key: Vec<u8>,
    pub kem_public: Vec<u8>,
    pub signature: Vec<u8>,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeAcceptance {
    pub identity_key: Vec<u8>,
    pub kem_public: Vec<u8>,
    pub ciphertext_to_initiator: Vec<u8>,
    pub signature: Vec<u8>,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeConfirmation {
    pub ciphertext_to_responder: Vec<u8>,
    pub signature: Vec<u8>,
    pub nonce: u64,
}

#[derive(Clone)]
pub struct PeerIdentity {
    signing: MlDsaSecretKey,
    verify: MlDsaPublicKey,
    kem: MlKemKeyPair,
}

impl PeerIdentity {
    pub fn generate(seed: &[u8]) -> Self {
        let signing = MlDsaSecretKey::generate_deterministic(seed);
        let verify = signing.verify_key();
        let kem_seed = sha256(&[seed, b"kem"].concat());
        let kem = MlKemKeyPair::generate_deterministic(&kem_seed);
        Self {
            signing,
            verify,
            kem,
        }
    }

    pub fn identity_key(&self) -> &MlDsaPublicKey {
        &self.verify
    }

    pub fn peer_id(&self) -> PeerId {
        sha256(&self.verify.to_bytes())
    }

    pub fn identity_fingerprint(&self) -> PeerId {
        self.peer_id()
    }

    pub fn create_offer(&self) -> Result<HandshakeOffer, NetworkError> {
        let kem_public = self.kem.public_key().to_bytes();
        let nonce = random_nonce();
        let preimage = offer_preimage(&self.verify.to_bytes(), &kem_public, nonce);
        let signature = self.signing.sign(&preimage);
        Ok(HandshakeOffer {
            identity_key: self.verify.to_bytes(),
            kem_public,
            signature: signature.to_bytes().to_vec(),
            nonce,
        })
    }

    pub fn accept_offer(
        &self,
        offer: &HandshakeOffer,
    ) -> Result<(HandshakeAcceptance, MlKemSharedSecret, Vec<u8>), NetworkError> {
        let initiator_pk = MlDsaPublicKey::from_bytes(&offer.identity_key)?;
        let preimage = offer_preimage(&offer.identity_key, &offer.kem_public, offer.nonce);
        let signature = MlDsaSignature::from_bytes(&offer.signature)?;
        initiator_pk
            .verify(&preimage, &signature)
            .map_err(|_| NetworkError::InvalidSignature)?;

        let seed_material = random_encapsulation_seed();
        let kem_pk = MlKemPublicKey::from_bytes(&offer.kem_public)?;
        let (ciphertext, shared_secret) = kem_pk.encapsulate(&seed_material);
        let ciphertext_bytes = ciphertext.to_bytes().to_vec();
        let nonce = random_nonce();
        let acceptance_preimage = acceptance_preimage(
            &self.verify.to_bytes(),
            &self.kem.public_key().to_bytes(),
            &ciphertext_bytes,
            nonce,
        );
        let signature = self.signing.sign(&acceptance_preimage);
        let acceptance = HandshakeAcceptance {
            identity_key: self.verify.to_bytes(),
            kem_public: self.kem.public_key().to_bytes(),
            ciphertext_to_initiator: ciphertext_bytes,
            signature: signature.to_bytes().to_vec(),
            nonce,
        };
        let encoded = wire::encode(&acceptance, wire::MAX_HANDSHAKE_FRAME_LEN)?;
        Ok((acceptance, shared_secret, encoded))
    }

    pub fn finalize_handshake(
        &self,
        _offer: &HandshakeOffer,
        acceptance: &HandshakeAcceptance,
        offer_bytes: &[u8],
        acceptance_bytes: &[u8],
    ) -> Result<(SecureChannel, HandshakeConfirmation, Vec<u8>), NetworkError> {
        let responder_pk = MlDsaPublicKey::from_bytes(&acceptance.identity_key)?;
        let acceptance_preimage = acceptance_preimage(
            &acceptance.identity_key,
            &acceptance.kem_public,
            &acceptance.ciphertext_to_initiator,
            acceptance.nonce,
        );
        let acceptance_sig = MlDsaSignature::from_bytes(&acceptance.signature)?;
        responder_pk
            .verify(&acceptance_preimage, &acceptance_sig)
            .map_err(|_| NetworkError::InvalidSignature)?;

        let ciphertext = MlKemCiphertext::from_bytes(&acceptance.ciphertext_to_initiator)?;
        let responder_secret = self.kem.decapsulate(&ciphertext)?;
        let responder_kem = MlKemPublicKey::from_bytes(&acceptance.kem_public)?;
        let seed_material = random_encapsulation_seed();
        let (ciphertext_to_responder, initiator_secret) = responder_kem.encapsulate(&seed_material);
        let cipher_bytes = ciphertext_to_responder.to_bytes().to_vec();
        let nonce = random_nonce();
        let confirmation_preimage = confirmation_preimage(&cipher_bytes, nonce);
        let signature = self.signing.sign(&confirmation_preimage);
        let confirmation = HandshakeConfirmation {
            ciphertext_to_responder: cipher_bytes,
            signature: signature.to_bytes().to_vec(),
            nonce,
        };
        let confirmation_bytes = wire::encode(&confirmation, wire::MAX_HANDSHAKE_FRAME_LEN)?;
        let channel = secure_channel_from_transcript(
            offer_bytes,
            acceptance_bytes,
            &confirmation_bytes,
            responder_secret.as_bytes(),
            initiator_secret.as_bytes(),
            ChannelRole::Initiator,
        )?;
        Ok((channel, confirmation, confirmation_bytes))
    }

    pub fn complete_handshake(
        &self,
        offer: &HandshakeOffer,
        confirmation: &HandshakeConfirmation,
        offer_bytes: &[u8],
        acceptance_bytes: &[u8],
        confirmation_bytes: &[u8],
        responder_secret: MlKemSharedSecret,
    ) -> Result<SecureChannel, NetworkError> {
        let confirmation_preimage =
            confirmation_preimage(&confirmation.ciphertext_to_responder, confirmation.nonce);
        let confirmation_sig = MlDsaSignature::from_bytes(&confirmation.signature)?;
        let initiator_pk = MlDsaPublicKey::from_bytes(&offer.identity_key)?;
        initiator_pk
            .verify(&confirmation_preimage, &confirmation_sig)
            .map_err(|_| NetworkError::InvalidSignature)?;

        let ciphertext = MlKemCiphertext::from_bytes(&confirmation.ciphertext_to_responder)?;
        let initiator_secret = self.kem.decapsulate(&ciphertext)?;
        secure_channel_from_transcript(
            offer_bytes,
            acceptance_bytes,
            confirmation_bytes,
            responder_secret.as_bytes(),
            initiator_secret.as_bytes(),
            ChannelRole::Responder,
        )
    }
}

pub fn establish_secure_channel(
    initiator: &PeerIdentity,
    responder: &PeerIdentity,
) -> Result<(SecureChannel, SecureChannel), NetworkError> {
    let offer = initiator.create_offer()?;
    let offer_bytes = wire::encode(&offer, wire::MAX_HANDSHAKE_FRAME_LEN)?;
    let (acceptance, responder_secret, acceptance_bytes) = responder.accept_offer(&offer)?;
    let (initiator_channel, confirmation, confirmation_bytes) =
        initiator.finalize_handshake(&offer, &acceptance, &offer_bytes, &acceptance_bytes)?;
    let responder_channel = responder.complete_handshake(
        &offer,
        &confirmation,
        &offer_bytes,
        &acceptance_bytes,
        &confirmation_bytes,
        responder_secret,
    )?;
    Ok((initiator_channel, responder_channel))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GossipMessage {
    Transaction(Vec<u8>),
    Block(Vec<u8>),
    Evidence(Vec<u8>),
    Addresses(Vec<SocketAddr>),
}

#[derive(Clone)]
pub struct GossipRouter {
    sender: broadcast::Sender<GossipMessage>,
}

impl GossipRouter {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn handle(&self) -> GossipHandle {
        GossipHandle {
            sender: self.sender.clone(),
        }
    }
}

#[derive(Clone)]
pub struct GossipHandle {
    sender: broadcast::Sender<GossipMessage>,
}

impl GossipHandle {
    pub fn broadcast_transaction(&self, payload: Vec<u8>) -> Result<(), NetworkError> {
        self.sender
            .send(GossipMessage::Transaction(payload))
            .map(|_| ())
            .map_err(|_| NetworkError::Handshake("gossip send failed"))
    }

    pub fn broadcast_block(&self, payload: Vec<u8>) -> Result<(), NetworkError> {
        self.sender
            .send(GossipMessage::Block(payload))
            .map(|_| ())
            .map_err(|_| NetworkError::Handshake("gossip send failed"))
    }

    pub fn broadcast_evidence(&self, payload: Vec<u8>) -> Result<(), NetworkError> {
        self.sender
            .send(GossipMessage::Evidence(payload))
            .map(|_| ())
            .map_err(|_| NetworkError::Handshake("gossip send failed"))
    }

    pub fn broadcast_addresses(&self, addrs: Vec<SocketAddr>) -> Result<(), NetworkError> {
        self.sender
            .send(GossipMessage::Addresses(addrs))
            .map(|_| ())
            .map_err(|_| NetworkError::Handshake("gossip send failed"))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<GossipMessage> {
        self.sender.subscribe()
    }
}

#[derive(Clone)]
pub struct SecureChannel {
    send_cipher: Aes256Gcm,
    recv_cipher: Aes256Gcm,
    aad: [u8; 32],
    send_nonce: u64,
    recv_nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChannelRole {
    Initiator,
    Responder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChannelKeySlot {
    InitiatorToResponder,
    ResponderToInitiator,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SessionMaterial {
    initiator_to_responder: [u8; 32],
    responder_to_initiator: [u8; 32],
    aad: [u8; 32],
}

impl SecureChannel {
    fn new(material: SessionMaterial, role: ChannelRole) -> Result<Self, NetworkError> {
        let (send_slot, recv_slot) = channel_key_slots(role);
        let send_key = material_key(&material, send_slot);
        let recv_key = material_key(&material, recv_slot);
        let send_cipher =
            Aes256Gcm::new_from_slice(&send_key).map_err(|_| NetworkError::Encryption)?;
        let recv_cipher =
            Aes256Gcm::new_from_slice(&recv_key).map_err(|_| NetworkError::Encryption)?;
        Ok(Self {
            send_cipher,
            recv_cipher,
            aad: material.aad,
            send_nonce: 0,
            recv_nonce: 0,
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NetworkError> {
        let (nonce_bytes, next_nonce) =
            nonce_step(self.send_nonce).ok_or(NetworkError::Encryption)?;
        self.send_nonce = next_nonce;
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.send_cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| NetworkError::Encryption)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NetworkError> {
        let (nonce_bytes, next_nonce) =
            nonce_step(self.recv_nonce).ok_or(NetworkError::Encryption)?;
        self.recv_nonce = next_nonce;
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.recv_cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| NetworkError::Encryption)
    }
}

fn channel_key_slots(role: ChannelRole) -> (ChannelKeySlot, ChannelKeySlot) {
    match role {
        ChannelRole::Initiator => (
            ChannelKeySlot::InitiatorToResponder,
            ChannelKeySlot::ResponderToInitiator,
        ),
        ChannelRole::Responder => (
            ChannelKeySlot::ResponderToInitiator,
            ChannelKeySlot::InitiatorToResponder,
        ),
    }
}

fn material_key(material: &SessionMaterial, slot: ChannelKeySlot) -> [u8; 32] {
    match slot {
        ChannelKeySlot::InitiatorToResponder => material.initiator_to_responder,
        ChannelKeySlot::ResponderToInitiator => material.responder_to_initiator,
    }
}

fn offer_preimage(identity: &[u8], kem: &[u8], nonce: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"offer");
    hasher.update(identity);
    hasher.update(kem);
    hasher.update(nonce.to_be_bytes());
    hasher.finalize().to_vec()
}

fn acceptance_preimage(identity: &[u8], kem: &[u8], ciphertext: &[u8], nonce: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"accept");
    hasher.update(identity);
    hasher.update(kem);
    hasher.update(ciphertext);
    hasher.update(nonce.to_be_bytes());
    hasher.finalize().to_vec()
}

fn confirmation_preimage(ciphertext: &[u8], nonce: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"confirm");
    hasher.update(ciphertext);
    hasher.update(nonce.to_be_bytes());
    hasher.finalize().to_vec()
}

fn random_nonce() -> u64 {
    OsRng.next_u64()
}

fn random_encapsulation_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

fn secure_channel_from_transcript(
    offer: &[u8],
    acceptance: &[u8],
    confirmation: &[u8],
    secret_a: &[u8],
    secret_b: &[u8],
    role: ChannelRole,
) -> Result<SecureChannel, NetworkError> {
    let material = derive_session_material(offer, acceptance, confirmation, secret_a, secret_b);
    SecureChannel::new(material, role)
}

fn derive_session_material(
    offer: &[u8],
    acceptance: &[u8],
    confirmation: &[u8],
    secret_a: &[u8],
    secret_b: &[u8],
) -> SessionMaterial {
    let initiator_to_responder = derive_session_key(
        b"hegemon-network-v2-i2r",
        offer,
        acceptance,
        confirmation,
        secret_a,
        secret_b,
    );
    let responder_to_initiator = derive_session_key(
        b"hegemon-network-v2-r2i",
        offer,
        acceptance,
        confirmation,
        secret_a,
        secret_b,
    );
    let aad = derive_session_key(
        b"hegemon-network-v2-aad",
        offer,
        acceptance,
        confirmation,
        secret_a,
        secret_b,
    );

    SessionMaterial {
        initiator_to_responder,
        responder_to_initiator,
        aad,
    }
}

fn derive_session_key(
    label: &[u8],
    offer: &[u8],
    acceptance: &[u8],
    confirmation: &[u8],
    secret_a: &[u8],
    secret_b: &[u8],
) -> [u8; 32] {
    let preimage = session_key_preimage(label, offer, acceptance, confirmation, secret_a, secret_b);
    let mut hasher = Sha256::new();
    hasher.update(&preimage);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn session_key_preimage(
    label: &[u8],
    offer: &[u8],
    acceptance: &[u8],
    confirmation: &[u8],
    secret_a: &[u8],
    secret_b: &[u8],
) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(
        b"hegemon-network-secure-channel-v2".len()
            + label.len()
            + offer.len()
            + acceptance.len()
            + confirmation.len()
            + secret_a.len()
            + secret_b.len(),
    );
    preimage.extend_from_slice(b"hegemon-network-secure-channel-v2");
    preimage.extend_from_slice(label);
    preimage.extend_from_slice(offer);
    preimage.extend_from_slice(acceptance);
    preimage.extend_from_slice(confirmation);
    preimage.extend_from_slice(secret_a);
    preimage.extend_from_slice(secret_b);
    preimage
}

fn nonce_from_u64(counter: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[4..].copy_from_slice(&counter.to_be_bytes());
    out
}

fn nonce_step(counter: u64) -> Option<([u8; 12], u64)> {
    let nonce = nonce_from_u64(counter);
    counter.checked_add(1).map(|next| (nonce, next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct LeanNetworkSecureChannelVectorFile {
        schema_version: u32,
        key_schedule_cases: Vec<LeanKeyScheduleCase>,
        role_cases: Vec<LeanRoleCase>,
        nonce_cases: Vec<LeanNonceCase>,
    }

    #[derive(Deserialize)]
    struct LeanKeyScheduleCase {
        name: String,
        offer_hex: String,
        acceptance_hex: String,
        confirmation_hex: String,
        secret_a_hex: String,
        secret_b_hex: String,
        domain_hex: String,
        i2r_label_hex: String,
        r2i_label_hex: String,
        aad_label_hex: String,
        i2r_preimage_hex: String,
        r2i_preimage_hex: String,
        aad_preimage_hex: String,
        expected_i2r_equals_r2i: bool,
        expected_i2r_equals_aad: bool,
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

    fn decode_hex(value: &str) -> Vec<u8> {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        hex::decode(trimmed).expect("hex vector")
    }

    fn role_from_str(value: &str) -> ChannelRole {
        match value {
            "initiator" => ChannelRole::Initiator,
            "responder" => ChannelRole::Responder,
            other => panic!("unknown role {other}"),
        }
    }

    fn slot_name(slot: ChannelKeySlot) -> &'static str {
        match slot {
            ChannelKeySlot::InitiatorToResponder => "initiator_to_responder",
            ChannelKeySlot::ResponderToInitiator => "responder_to_initiator",
        }
    }

    #[test]
    fn lean_generated_secure_channel_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_NETWORK_SECURE_CHANNEL_VECTORS") else {
            eprintln!("skipping Lean network secure-channel vectors; env var not set");
            return;
        };
        let contents = std::fs::read_to_string(path).expect("read Lean network vectors");
        let vectors: LeanNetworkSecureChannelVectorFile =
            serde_json::from_str(&contents).expect("parse Lean network vectors");
        assert_eq!(vectors.schema_version, 1);

        for case in vectors.key_schedule_cases {
            let offer = decode_hex(&case.offer_hex);
            let acceptance = decode_hex(&case.acceptance_hex);
            let confirmation = decode_hex(&case.confirmation_hex);
            let secret_a = decode_hex(&case.secret_a_hex);
            let secret_b = decode_hex(&case.secret_b_hex);
            assert_eq!(
                decode_hex(&case.domain_hex),
                b"hegemon-network-secure-channel-v2"
            );
            assert_eq!(decode_hex(&case.i2r_label_hex), b"hegemon-network-v2-i2r");
            assert_eq!(decode_hex(&case.r2i_label_hex), b"hegemon-network-v2-r2i");
            assert_eq!(decode_hex(&case.aad_label_hex), b"hegemon-network-v2-aad");

            let i2r_preimage = session_key_preimage(
                b"hegemon-network-v2-i2r",
                &offer,
                &acceptance,
                &confirmation,
                &secret_a,
                &secret_b,
            );
            let r2i_preimage = session_key_preimage(
                b"hegemon-network-v2-r2i",
                &offer,
                &acceptance,
                &confirmation,
                &secret_a,
                &secret_b,
            );
            let aad_preimage = session_key_preimage(
                b"hegemon-network-v2-aad",
                &offer,
                &acceptance,
                &confirmation,
                &secret_a,
                &secret_b,
            );
            assert_eq!(
                i2r_preimage,
                decode_hex(&case.i2r_preimage_hex),
                "{} i2r preimage",
                case.name
            );
            assert_eq!(
                r2i_preimage,
                decode_hex(&case.r2i_preimage_hex),
                "{} r2i preimage",
                case.name
            );
            assert_eq!(
                aad_preimage,
                decode_hex(&case.aad_preimage_hex),
                "{} aad preimage",
                case.name
            );
            assert_eq!(i2r_preimage == r2i_preimage, case.expected_i2r_equals_r2i);
            assert_eq!(i2r_preimage == aad_preimage, case.expected_i2r_equals_aad);

            let material =
                derive_session_material(&offer, &acceptance, &confirmation, &secret_a, &secret_b);
            assert_eq!(
                material.initiator_to_responder,
                derive_session_key(
                    b"hegemon-network-v2-i2r",
                    &offer,
                    &acceptance,
                    &confirmation,
                    &secret_a,
                    &secret_b,
                )
            );
            assert_eq!(
                material.responder_to_initiator,
                derive_session_key(
                    b"hegemon-network-v2-r2i",
                    &offer,
                    &acceptance,
                    &confirmation,
                    &secret_a,
                    &secret_b,
                )
            );
            assert_eq!(
                material.aad,
                derive_session_key(
                    b"hegemon-network-v2-aad",
                    &offer,
                    &acceptance,
                    &confirmation,
                    &secret_a,
                    &secret_b,
                )
            );
            assert_ne!(
                material.initiator_to_responder,
                material.responder_to_initiator
            );
            assert_ne!(material.initiator_to_responder, material.aad);
        }

        for case in vectors.role_cases {
            let role = role_from_str(&case.role);
            let (send_slot, recv_slot) = channel_key_slots(role);
            assert_eq!(slot_name(send_slot), case.expected_send_slot);
            assert_eq!(slot_name(recv_slot), case.expected_recv_slot);
            assert_eq!(send_slot != recv_slot, case.expected_send_recv_distinct);
        }

        for case in vectors.nonce_cases {
            let counter = case.counter.parse::<u64>().expect("counter u64");
            assert_eq!(
                nonce_from_u64(counter).to_vec(),
                decode_hex(&case.expected_nonce_hex),
                "{} nonce",
                case.name
            );
            let step = nonce_step(counter);
            assert_eq!(
                step.is_some(),
                case.expected_valid,
                "{} validity",
                case.name
            );
            match (step, case.expected_next_counter) {
                (Some((_, next)), Some(expected)) => {
                    assert_eq!(next, expected.parse::<u64>().expect("next counter u64"));
                }
                (None, None) => {}
                other => panic!("{} counter mismatch: {other:?}", case.name),
            }
        }
    }
}
