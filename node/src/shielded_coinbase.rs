//! Shielded Coinbase Encryption
//!
//! This module handles encryption of coinbase notes for shielded mining rewards.
//! It bridges between the wallet address format and the pallet's on-chain format.

use rand::RngCore;
use wallet::address::ShieldedAddress;

use crypto::{
    note_encryption::{NoteCiphertext, NotePlaintext},
};

use pallet_shielded_pool::{
    commitment::coinbase_commitment as pallet_coinbase_commitment,
    types::{
        CoinbaseNoteData, EncryptedNote, DIVERSIFIED_ADDRESS_SIZE, ENCRYPTED_NOTE_SIZE,
        ML_KEM_CIPHERTEXT_LEN,
    },
};

/// Error type for coinbase encryption
#[derive(Debug, thiserror::Error)]
pub enum CoinbaseEncryptionError {
    #[error("Invalid miner address: {0}")]
    InvalidAddress(String),
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Invalid address format: expected {expected} bytes, got {actual}")]
    InvalidAddressLength { expected: usize, actual: usize },
}

/// Encrypt a coinbase note for the given shielded address
///
/// # Arguments
/// * `address` - The miner's shielded address (Bech32m encoded)
/// * `amount` - The coinbase amount in base units
/// * `block_hash` - Current block hash (for seed derivation)
/// * `block_number` - Current block number (for seed derivation)
///
/// # Returns
/// The full coinbase note data including encrypted note and audit data
pub fn encrypt_coinbase_note(
    address: &ShieldedAddress,
    amount: u64,
    block_hash: &[u8; 32],
    block_number: u64,
) -> Result<CoinbaseNoteData, CoinbaseEncryptionError> {
    // Generate deterministic public seed from block data
    let public_seed = derive_public_seed(block_hash, block_number);
    
    // Create coinbase note plaintext with deterministic rho/r
    let note = NotePlaintext::coinbase(amount, &public_seed);
    
    // Generate random KEM encapsulation randomness
    let mut kem_randomness = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut kem_randomness);
    
    // Encrypt the note
    let ciphertext = NoteCiphertext::encrypt(
        &address.pk_enc,
        address.pk_recipient,
        address.version,
        address.diversifier_index,
        address.address_tag,
        &note,
        &kem_randomness,
    )
    .map_err(|e| CoinbaseEncryptionError::EncryptionFailed(format!("{:?}", e)))?;
    
    // Convert to pallet format
    let encrypted_note = convert_to_pallet_format(&ciphertext)?;
    
    // Extract recipient address in the format the pallet expects
    let recipient_address = extract_recipient_address(address)?;
    
    // Compute commitment using pallet's commitment function
    let commitment = compute_coinbase_commitment(&recipient_address, amount, &public_seed);
    
    Ok(CoinbaseNoteData {
        commitment,
        encrypted_note,
        recipient_address,
        amount,
        public_seed,
    })
}

/// Derive the public seed from block data
///
/// seed = Blake3("coinbase_seed" || block_hash || block_height)
fn derive_public_seed(block_hash: &[u8; 32], block_number: u64) -> [u8; 32] {
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(b"coinbase_seed");
    hasher.update(block_hash);
    hasher.update(&block_number.to_le_bytes());
    let result = hasher.finalize();
    *result.as_bytes()
}

/// Convert NoteCiphertext to pallet's EncryptedNote format
///
/// The pallet uses fixed-size arrays while NoteCiphertext uses variable-length Vec.
/// We need to pad/truncate as needed.
fn convert_to_pallet_format(
    ciphertext: &NoteCiphertext,
) -> Result<EncryptedNote, CoinbaseEncryptionError> {
    // The pallet format is:
    // ciphertext: [u8; 611] - concatenation of note_payload + memo_payload + metadata
    // kem_ciphertext: [u8; 1088] - ML-KEM ciphertext
    
    // Build the main ciphertext field
    let mut ciphertext_bytes = [0u8; ENCRYPTED_NOTE_SIZE];
    
    // Layout: version(1) + diversifier_index(4) + note_payload_len(4) + note_payload + 
    //         memo_payload_len(4) + memo_payload + hint_tag(32)
    let mut offset = 0;
    
    ciphertext_bytes[offset] = ciphertext.version;
    offset += 1;
    
    ciphertext_bytes[offset..offset + 4].copy_from_slice(&ciphertext.diversifier_index.to_le_bytes());
    offset += 4;
    
    // Note payload length and data
    let note_len = ciphertext.note_payload.len().min(400) as u32;
    ciphertext_bytes[offset..offset + 4].copy_from_slice(&note_len.to_le_bytes());
    offset += 4;
    ciphertext_bytes[offset..offset + note_len as usize]
        .copy_from_slice(&ciphertext.note_payload[..note_len as usize]);
    offset += note_len as usize;
    
    // Memo payload length and data
    let memo_len = ciphertext.memo_payload.len().min(100) as u32;
    ciphertext_bytes[offset..offset + 4].copy_from_slice(&memo_len.to_le_bytes());
    offset += 4;
    if memo_len > 0 {
        ciphertext_bytes[offset..offset + memo_len as usize]
            .copy_from_slice(&ciphertext.memo_payload[..memo_len as usize]);
    }
    
    // Hint tag at the end
    let hint_start = ENCRYPTED_NOTE_SIZE - 32;
    ciphertext_bytes[hint_start..].copy_from_slice(&ciphertext.hint_tag);
    
    // KEM ciphertext
    let mut kem_ciphertext = [0u8; ML_KEM_CIPHERTEXT_LEN];
    if ciphertext.kem_ciphertext.len() != ML_KEM_CIPHERTEXT_LEN {
        return Err(CoinbaseEncryptionError::EncryptionFailed(format!(
            "Invalid KEM ciphertext length: expected {}, got {}",
            ML_KEM_CIPHERTEXT_LEN,
            ciphertext.kem_ciphertext.len()
        )));
    }
    kem_ciphertext.copy_from_slice(&ciphertext.kem_ciphertext);
    
    Ok(EncryptedNote {
        ciphertext: ciphertext_bytes,
        kem_ciphertext,
    })
}

/// Extract the recipient address in the format the pallet expects
///
/// This is a 43-byte diversified address format used in the commitment
fn extract_recipient_address(address: &ShieldedAddress) -> Result<[u8; DIVERSIFIED_ADDRESS_SIZE], CoinbaseEncryptionError> {
    let mut recipient = [0u8; DIVERSIFIED_ADDRESS_SIZE];
    
    // Layout: version(1) + diversifier_index(4) + pk_recipient(32) + first 6 bytes of address_tag
    recipient[0] = address.version;
    recipient[1..5].copy_from_slice(&address.diversifier_index.to_le_bytes());
    recipient[5..37].copy_from_slice(&address.pk_recipient);
    recipient[37..43].copy_from_slice(&address.address_tag[0..6]);
    
    Ok(recipient)
}

/// Compute coinbase commitment using the pallet's Poseidon-based algorithm
///
/// This delegates to the pallet's commitment::coinbase_commitment function
/// to ensure the commitment matches what the pallet expects during verification.
fn compute_coinbase_commitment(
    recipient: &[u8; DIVERSIFIED_ADDRESS_SIZE],
    amount: u64,
    public_seed: &[u8; 32],
) -> [u8; 32] {
    // Use the pallet's commitment function directly
    pallet_coinbase_commitment(recipient, amount, public_seed)
}

/// Parse a shielded address from Bech32m string
pub fn parse_shielded_address(address_str: &str) -> Result<ShieldedAddress, CoinbaseEncryptionError> {
    ShieldedAddress::decode(address_str)
        .map_err(|e| CoinbaseEncryptionError::InvalidAddress(format!("{:?}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use synthetic_crypto::ml_kem::MlKemKeyPair;
    use synthetic_crypto::traits::KemKeyPair;

    #[test]
    fn test_derive_public_seed() {
        let block_hash = [1u8; 32];
        let block_number = 100;
        let seed1 = derive_public_seed(&block_hash, block_number);
        let seed2 = derive_public_seed(&block_hash, block_number);
        assert_eq!(seed1, seed2, "Seed derivation should be deterministic");
        
        let seed3 = derive_public_seed(&block_hash, 101);
        assert_ne!(seed1, seed3, "Different block numbers should give different seeds");
    }

    #[test]
    fn test_encrypt_coinbase_note() {
        // Generate a test address
        let keypair = MlKemKeyPair::generate_deterministic(b"test-miner-address");
        let address = ShieldedAddress {
            version: 1,
            diversifier_index: 0,
            pk_recipient: [0u8; 32],
            pk_enc: keypair.public_key(),
            address_tag: [0u8; 32],
        };
        
        let block_hash = [1u8; 32];
        let block_number = 100;
        let amount = 50 * 100_000_000; // 50 coins
        
        let result = encrypt_coinbase_note(&address, amount, &block_hash, block_number);
        assert!(result.is_ok(), "Encryption should succeed: {:?}", result.err());
        
        let note_data = result.unwrap();
        assert_eq!(note_data.amount, amount);
        assert_eq!(note_data.commitment.len(), 32);
    }
}
