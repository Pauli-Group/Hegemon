use aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use crypto::error::CryptoError;
use crypto::hashes::sha256;
use crypto::ml_dsa::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
use crypto::ml_kem::{MlKemCiphertext, MlKemKeyPair, MlKemPublicKey, MlKemSharedSecret};
use crypto::traits::{KemKeyPair, KemPublicKey, SigningKey, VerifyKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::broadcast;

pub mod p2p;
pub mod peer_manager;
pub mod service;

pub use service::P2PService;

pub type PeerId = [u8; 32];

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
    Serialization(#[from] bincode::Error),
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
        let nonce = derive_nonce(b"offer", &self.verify.to_bytes());
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

        let seed_material = sha256(&[self.verify.to_bytes(), offer.identity_key.clone()].concat());
        let kem_pk = MlKemPublicKey::from_bytes(&offer.kem_public)?;
        let (ciphertext, shared_secret) = kem_pk.encapsulate(&seed_material);
        let ciphertext_bytes = ciphertext.to_bytes().to_vec();
        let nonce = derive_nonce(b"accept", &self.verify.to_bytes());
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
        let encoded = bincode::serialize(&acceptance)?;
        Ok((acceptance, shared_secret, encoded))
    }

    pub fn finalize_handshake(
        &self,
        offer: &HandshakeOffer,
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
        let seed_material =
            sha256(&[offer.identity_key.clone(), acceptance.identity_key.clone()].concat());
        let (ciphertext_to_responder, initiator_secret) = responder_kem.encapsulate(&seed_material);
        let cipher_bytes = ciphertext_to_responder.to_bytes().to_vec();
        let nonce = derive_nonce(b"confirm", &self.verify.to_bytes());
        let confirmation_preimage = confirmation_preimage(&cipher_bytes, nonce);
        let signature = self.signing.sign(&confirmation_preimage);
        let confirmation = HandshakeConfirmation {
            ciphertext_to_responder: cipher_bytes,
            signature: signature.to_bytes().to_vec(),
            nonce,
        };
        let confirmation_bytes = bincode::serialize(&confirmation)?;
        let (key, aad) = derive_session_material(
            offer_bytes,
            acceptance_bytes,
            &confirmation_bytes,
            responder_secret.as_bytes(),
            initiator_secret.as_bytes(),
        );
        let channel = SecureChannel::new(key, aad)?;
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
        let (key, aad) = derive_session_material(
            offer_bytes,
            acceptance_bytes,
            confirmation_bytes,
            responder_secret.as_bytes(),
            initiator_secret.as_bytes(),
        );
        SecureChannel::new(key, aad)
    }
}

pub fn establish_secure_channel(
    initiator: &PeerIdentity,
    responder: &PeerIdentity,
) -> Result<(SecureChannel, SecureChannel), NetworkError> {
    let offer = initiator.create_offer()?;
    let offer_bytes = bincode::serialize(&offer)?;
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

    pub fn subscribe(&self) -> broadcast::Receiver<GossipMessage> {
        self.sender.subscribe()
    }
}

#[derive(Clone)]
pub struct SecureChannel {
    cipher: Aes256Gcm,
    aad: [u8; 32],
    send_nonce: u64,
    recv_nonce: u64,
}

impl SecureChannel {
    fn new(key: [u8; 32], aad: [u8; 32]) -> Result<Self, NetworkError> {
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| NetworkError::Encryption)?;
        Ok(Self {
            cipher,
            aad,
            send_nonce: 0,
            recv_nonce: 0,
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NetworkError> {
        let nonce_bytes = nonce_from_u64(self.send_nonce);
        self.send_nonce = self
            .send_nonce
            .checked_add(1)
            .ok_or(NetworkError::Encryption)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.cipher
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
        let nonce_bytes = nonce_from_u64(self.recv_nonce);
        self.recv_nonce = self
            .recv_nonce
            .checked_add(1)
            .ok_or(NetworkError::Encryption)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.cipher
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

fn derive_nonce(label: &[u8], key: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(key);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

fn derive_session_material(
    offer: &[u8],
    acceptance: &[u8],
    confirmation: &[u8],
    secret_a: &[u8],
    secret_b: &[u8],
) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Sha256::new();
    hasher.update(offer);
    hasher.update(acceptance);
    hasher.update(confirmation);
    hasher.update(secret_a);
    hasher.update(secret_b);
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    let mut aad_hasher = Sha256::new();
    aad_hasher.update(offer);
    aad_hasher.update(acceptance);
    aad_hasher.update(confirmation);
    let mut aad = [0u8; 32];
    aad.copy_from_slice(&aad_hasher.finalize());
    (key, aad)
}

fn nonce_from_u64(counter: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[4..].copy_from_slice(&counter.to_be_bytes());
    out
}
