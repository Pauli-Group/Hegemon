//! Noise-like encryption primitives for secure sessions

use aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::error::{PqNoiseError, Result};
use crate::types::SessionKeys;

/// AES-256-GCM cipher wrapper for secure communication
pub struct NoiseCipher {
    /// Cipher for sending (initiator → responder or vice versa)
    send_cipher: Aes256Gcm,
    /// Cipher for receiving
    recv_cipher: Aes256Gcm,
    /// Additional authenticated data
    aad: [u8; 32],
    /// Send nonce counter
    send_nonce: u64,
    /// Receive nonce counter
    recv_nonce: u64,
}

impl NoiseCipher {
    /// Create a new cipher pair from session keys
    ///
    /// The `is_initiator` flag determines which key is used for sending vs receiving
    pub fn new(keys: &SessionKeys, is_initiator: bool) -> Result<Self> {
        let (send_key, recv_key) = if is_initiator {
            (keys.initiator_to_responder, keys.responder_to_initiator)
        } else {
            (keys.responder_to_initiator, keys.initiator_to_responder)
        };

        let send_cipher = Aes256Gcm::new_from_slice(&send_key)
            .map_err(|e| PqNoiseError::Encryption(format!("failed to create send cipher: {}", e)))?;
        let recv_cipher = Aes256Gcm::new_from_slice(&recv_key)
            .map_err(|e| PqNoiseError::Encryption(format!("failed to create recv cipher: {}", e)))?;

        Ok(Self {
            send_cipher,
            recv_cipher,
            aad: keys.session_aad,
            send_nonce: 0,
            recv_nonce: 0,
        })
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = nonce_from_counter(self.send_nonce);
        self.send_nonce = self
            .send_nonce
            .checked_add(1)
            .ok_or_else(|| PqNoiseError::Encryption("nonce overflow".to_string()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: plaintext,
            aad: &self.aad,
        };

        self.send_cipher
            .encrypt(nonce, payload)
            .map_err(|e| PqNoiseError::Encryption(format!("encryption failed: {}", e)))
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = nonce_from_counter(self.recv_nonce);
        self.recv_nonce = self
            .recv_nonce
            .checked_add(1)
            .ok_or_else(|| PqNoiseError::Encryption("nonce overflow".to_string()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: ciphertext,
            aad: &self.aad,
        };

        self.recv_cipher
            .decrypt(nonce, payload)
            .map_err(|e| PqNoiseError::Encryption(format!("decryption failed: {}", e)))
    }

    /// Get the current send nonce (for debugging/testing)
    pub fn send_nonce(&self) -> u64 {
        self.send_nonce
    }

    /// Get the current receive nonce (for debugging/testing)
    pub fn recv_nonce(&self) -> u64 {
        self.recv_nonce
    }
}

/// Convert a u64 counter to a 12-byte nonce for AES-GCM
fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    // Put counter in the last 8 bytes (big-endian)
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Transcript hash for the handshake
pub struct Transcript {
    hasher: sha2::Sha256,
}

impl Transcript {
    /// Create a new transcript
    pub fn new() -> Self {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        // Initialize with protocol ID
        hasher.update(crate::types::PROTOCOL_ID.as_bytes());
        Self { hasher }
    }

    /// Add data to the transcript
    pub fn update(&mut self, data: &[u8]) {
        use sha2::Digest;
        self.hasher.update(data);
    }

    /// Get the current transcript hash
    pub fn hash(&self) -> [u8; 32] {
        use sha2::Digest;
        let hasher = self.hasher.clone();
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Finalize and consume the transcript
    pub fn finalize(self) -> [u8; 32] {
        use sha2::Digest;
        let result = self.hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_from_counter() {
        let nonce = nonce_from_counter(0);
        assert_eq!(nonce, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let nonce = nonce_from_counter(1);
        assert_eq!(nonce, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let nonce = nonce_from_counter(0x0102030405060708);
        assert_eq!(nonce, [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_transcript() {
        let mut transcript = Transcript::new();
        transcript.update(b"hello");
        let hash1 = transcript.hash();
        transcript.update(b"world");
        let hash2 = transcript.hash();
        
        // Hashes should be different
        assert_ne!(hash1, hash2);
        
        // Finalize should match hash
        assert_eq!(hash2, transcript.finalize());
    }

    #[test]
    fn test_cipher_roundtrip() {
        let keys = SessionKeys {
            initiator_to_responder: [1u8; 32],
            responder_to_initiator: [2u8; 32],
            session_aad: [3u8; 32],
        };

        let mut initiator_cipher = NoiseCipher::new(&keys, true).unwrap();
        let mut responder_cipher = NoiseCipher::new(&keys, false).unwrap();

        // Initiator sends to responder
        let plaintext = b"Hello, quantum world!";
        let ciphertext = initiator_cipher.encrypt(plaintext).unwrap();
        let decrypted = responder_cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        // Responder sends to initiator
        let response = b"Hello from the other side!";
        let ciphertext = responder_cipher.encrypt(response).unwrap();
        let decrypted = initiator_cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(response.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_nonce_increment() {
        let keys = SessionKeys {
            initiator_to_responder: [1u8; 32],
            responder_to_initiator: [2u8; 32],
            session_aad: [3u8; 32],
        };

        let mut cipher = NoiseCipher::new(&keys, true).unwrap();
        assert_eq!(cipher.send_nonce(), 0);

        cipher.encrypt(b"message 1").unwrap();
        assert_eq!(cipher.send_nonce(), 1);

        cipher.encrypt(b"message 2").unwrap();
        assert_eq!(cipher.send_nonce(), 2);
    }
}
