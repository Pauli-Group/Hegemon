//! Note commitment scheme for the shielded pool.
//!
//! Implements Sapling-style note commitments using Poseidon hash.
//! The commitment scheme ensures:
//! - Hiding: commitment reveals nothing about the note contents
//! - Binding: cannot find another note with the same commitment
//!
//! IMPORTANT: This module contains TWO commitment schemes:
//! 1. Legacy `note_commitment` - Blake2-wrapped Poseidon (deprecated)
//! 2. Circuit-compatible `circuit_note_commitment` - matches ZK circuit exactly

use sp_core::blake2_256;
use sp_std::vec::Vec;

use crate::types::{Note, DIVERSIFIED_ADDRESS_SIZE, MEMO_SIZE};

/// Domain separator for note commitments.
const NOTE_COMMITMENT_DOMAIN: &[u8] = b"Hegemon_NoteCommitment_v1";

/// Domain separator for nullifiers.
const NULLIFIER_DOMAIN: &[u8] = b"Hegemon_Nullifier_v1";

/// Domain separator for PRF key derivation.
const PRF_KEY_DOMAIN: &[u8] = b"Hegemon_PrfKey_v1";

/// Poseidon hash parameters (shared with the circuit).
const POSEIDON_ROUNDS: usize = transaction_core::constants::POSEIDON_ROUNDS;
const POSEIDON_WIDTH: usize = transaction_core::constants::POSEIDON_WIDTH;

/// Field modulus for Poseidon (Goldilocks prime).
const FIELD_MODULUS: u128 = transaction_core::constants::FIELD_MODULUS;

/// A field element for Poseidon operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement(u64);

impl FieldElement {
    /// Create zero element.
    pub fn zero() -> Self {
        Self(0)
    }

    /// Create from u64.
    pub fn from_u64(value: u64) -> Self {
        Self((value as u128 % FIELD_MODULUS) as u64)
    }

    /// Create from bytes (big-endian).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut acc = 0u128;
        for &b in bytes {
            acc = ((acc << 8) + b as u128) % FIELD_MODULUS;
        }
        Self(acc as u64)
    }

    /// Convert to bytes (big-endian).
    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Field addition.
    fn add(self, other: Self) -> Self {
        let sum = (self.0 as u128 + other.0 as u128) % FIELD_MODULUS;
        Self(sum as u64)
    }

    /// Field multiplication.
    fn mul(self, other: Self) -> Self {
        let product = (self.0 as u128 * other.0 as u128) % FIELD_MODULUS;
        Self(product as u64)
    }

    /// x^5 for S-box.
    fn pow5(self) -> Self {
        let sq = self.mul(self);
        let fourth = sq.mul(sq);
        fourth.mul(self)
    }

    /// Get inner value.
    pub fn inner(self) -> u64 {
        self.0
    }
}

// ================================================================================================
// CIRCUIT-COMPATIBLE HASHING (matches circuits/transaction-core hashing)
// ================================================================================================

/// Compute note commitment exactly as the ZK circuit does.
pub fn circuit_note_commitment(
    value: u64,
    asset_id: u64,
    pk_recipient: &[u8; 32],
    rho: &[u8; 32],
    r: &[u8; 32],
) -> [u8; 32] {
    transaction_core::hashing::note_commitment_bytes(value, asset_id, pk_recipient, rho, r)
}

/// Compute nullifier exactly as the ZK circuit does.
///
/// This matches `circuits/transaction/src/hashing.rs::nullifier` exactly.
pub fn circuit_nullifier(prf_key: u64, rho: &[u8; 32], position: u64) -> [u8; 32] {
    transaction_core::hashing::nullifier_bytes(transaction_core::Felt::new(prf_key), rho, position)
}

/// Compute PRF key exactly as the ZK circuit does.
///
/// This matches `circuits/transaction/src/hashing.rs::prf_key` exactly.
pub fn circuit_prf_key(sk_spend: &[u8; 32]) -> u64 {
    transaction_core::hashing::prf_key(sk_spend).as_int()
}

/// Convert a circuit Felt (u64) to a 32-byte commitment.
/// The Felt is stored in the last 8 bytes as big-endian.
pub fn felt_to_commitment(felt: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&felt.to_be_bytes());
    out
}

/// Extract a circuit Felt (u64) from a 32-byte commitment.
/// The Felt is stored in the last 8 bytes as big-endian.
pub fn commitment_to_felt(commitment: &[u8; 32]) -> u64 {
    u64::from_be_bytes([
        commitment[24],
        commitment[25],
        commitment[26],
        commitment[27],
        commitment[28],
        commitment[29],
        commitment[30],
        commitment[31],
    ])
}

// ================================================================================================
// RUNTIME POSEIDON IMPLEMENTATION (matches circuit constants)
// ================================================================================================

/// Generate round constants for Poseidon.
fn poseidon_round_constants() -> [[FieldElement; POSEIDON_WIDTH]; POSEIDON_ROUNDS] {
    let mut constants = [[FieldElement::zero(); POSEIDON_WIDTH]; POSEIDON_ROUNDS];
    for (round, round_constants) in constants.iter_mut().enumerate() {
        for (idx, constant) in round_constants.iter_mut().enumerate() {
            let value = transaction_core::poseidon_constants::ROUND_CONSTANTS[round][idx];
            *constant = FieldElement::from_u64(value);
        }
    }
    constants
}

/// MDS mixing matrix application.
fn poseidon_mix(state: &mut [FieldElement; POSEIDON_WIDTH]) {
    let mut new_state = [FieldElement::zero(); POSEIDON_WIDTH];
    for (row_idx, new_slot) in new_state.iter_mut().enumerate() {
        let mut acc = FieldElement::zero();
        for (col_idx, value) in state.iter().enumerate() {
            let coeff = transaction_core::poseidon_constants::MDS_MATRIX[row_idx][col_idx];
            acc = acc.add(value.mul(FieldElement::from_u64(coeff)));
        }
        *new_slot = acc;
    }
    *state = new_state;
}

/// Poseidon hash function.
///
/// This is a simplified implementation for the pallet runtime.
/// The ZK circuits use the full algebraic Poseidon over the Goldilocks field (2^64 - 2^32 + 1).
/// Poseidon is STARK-friendly and uses only field arithmetic.
pub fn poseidon_hash(inputs: &[FieldElement]) -> FieldElement {
    let constants = poseidon_round_constants();
    let mut state = [
        FieldElement::from_u64(1),
        FieldElement::from_u64(inputs.len() as u64),
        FieldElement::zero(),
    ];

    for input in inputs {
        state[0] = state[0].add(*input);
        for round_constants in constants.iter() {
            for (state_slot, constant) in state.iter_mut().zip(round_constants.iter()) {
                *state_slot = state_slot.add(*constant);
            }
            for state_slot in &mut state {
                *state_slot = state_slot.pow5();
            }
            poseidon_mix(&mut state);
        }
    }

    state[0]
}

/// Compute note commitment.
///
/// commitment = Poseidon(domain || recipient || value || rcm)
///
/// This produces a 32-byte commitment that hides the note contents
/// but is binding (cannot find a different note with the same commitment).
pub fn note_commitment(note: &Note) -> [u8; 32] {
    // Convert note fields to field elements
    let mut inputs = Vec::new();

    // Domain separator
    let domain_hash = blake2_256(NOTE_COMMITMENT_DOMAIN);
    inputs.push(FieldElement::from_bytes(&domain_hash[..8]));

    // Recipient address (split into chunks)
    for chunk in note.recipient.chunks(8) {
        inputs.push(FieldElement::from_bytes(chunk));
    }

    // Value
    inputs.push(FieldElement::from_u64(note.value));

    // Randomness (split into chunks)
    for chunk in note.rcm.chunks(8) {
        inputs.push(FieldElement::from_bytes(chunk));
    }

    // Compute Poseidon hash
    let hash = poseidon_hash(&inputs);

    // Expand to 32 bytes using Blake2b
    let hash_bytes = hash.to_bytes();
    blake2_256(&[NOTE_COMMITMENT_DOMAIN, &hash_bytes].concat())
}

/// Compute note commitment from raw components.
///
/// This is useful when you have the components separately rather than a full Note.
pub fn note_commitment_from_parts(
    recipient: &[u8; DIVERSIFIED_ADDRESS_SIZE],
    value: u64,
    rcm: &[u8; 32],
) -> [u8; 32] {
    let note = Note {
        recipient: *recipient,
        value,
        rcm: *rcm,
        memo: [0u8; MEMO_SIZE],
    };
    note_commitment(&note)
}

/// Domain separator for coinbase rho derivation.
/// MUST match crypto/src/note_encryption.rs::derive_coinbase_rho
const COINBASE_RHO_DOMAIN: &[u8] = b"coinbase-rho";

/// Domain separator for coinbase r derivation.
/// MUST match crypto/src/note_encryption.rs::derive_coinbase_r
const COINBASE_R_DOMAIN: &[u8] = b"coinbase-r";

/// Derive deterministic rho for coinbase notes.
///
/// MUST match crypto/src/note_encryption.rs::derive_coinbase_rho
/// Uses SHA256 for compatibility with the crypto library.
///
/// Since the seed is public, anyone can verify rho. Privacy comes from
/// the nullifier requiring the secret nullifier key (nk).
pub fn derive_coinbase_rho(public_seed: &[u8; 32]) -> [u8; 32] {
    // Match crypto::deterministic::expand_to_length with counter=0
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(COINBASE_RHO_DOMAIN);
    hasher.update(0u32.to_be_bytes());
    hasher.update(public_seed);
    let digest = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    result
}

/// Derive deterministic r (commitment randomness) for coinbase notes.
///
/// MUST match crypto/src/note_encryption.rs::derive_coinbase_r
/// Uses SHA256 for compatibility with the crypto library.
pub fn derive_coinbase_r(public_seed: &[u8; 32]) -> [u8; 32] {
    // Match crypto::deterministic::expand_to_length with counter=0
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(COINBASE_R_DOMAIN);
    hasher.update(0u32.to_be_bytes());
    hasher.update(public_seed);
    let digest = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    result
}

/// Compute coinbase note commitment (LEGACY - uses Blake2-wrapped hash).
///
/// This is a specialized commitment for coinbase notes that uses the
/// deterministic rho/r derived from the public seed.
///
/// commitment = note_commitment(recipient, value, r)
/// where r = derive_coinbase_r(public_seed)
#[deprecated(
    since = "0.2.0",
    note = "Use circuit_coinbase_commitment for ZK-compatible commitments"
)]
pub fn coinbase_commitment(
    recipient: &[u8; DIVERSIFIED_ADDRESS_SIZE],
    value: u64,
    public_seed: &[u8; 32],
) -> [u8; 32] {
    // Extract pk_recipient from the 43-byte recipient format
    // Layout: version(1) + diversifier_index(4) + pk_recipient(32) + tag(6)
    let mut pk_recipient = [0u8; 32];
    pk_recipient.copy_from_slice(&recipient[5..37]);

    // Use circuit-compatible commitment
    circuit_coinbase_commitment(&pk_recipient, value, public_seed, 0)
}

/// Compute coinbase note commitment (CIRCUIT-COMPATIBLE).
///
/// This computes the commitment exactly as the ZK circuit does.
/// The commitment matches `circuits/transaction/src/hashing.rs::note_commitment`.
///
/// Arguments:
/// - pk_recipient: 32-byte recipient public key (extracted from shielded address)
/// - value: Note value in atomic units
/// - public_seed: 32-byte seed used to derive rho and r
/// - asset_id: Asset identifier (0 for native)
///
/// Returns: 32-byte commitment encoding (4 x 64-bit limbs)
pub fn circuit_coinbase_commitment(
    pk_recipient: &[u8; 32],
    value: u64,
    public_seed: &[u8; 32],
    asset_id: u64,
) -> [u8; 32] {
    // Derive rho and r from public seed
    let rho = derive_coinbase_rho(public_seed);
    let r = derive_coinbase_r(public_seed);

    circuit_note_commitment(value, asset_id, pk_recipient, &rho, &r)
}

/// Derive PRF key from spending key.
///
/// prf_key = Blake2b(domain || sk_spend)
///
/// The PRF key is used to derive nullifiers for spent notes.
pub fn derive_prf_key(sk_spend: &[u8; 32]) -> [u8; 32] {
    blake2_256(&[PRF_KEY_DOMAIN, sk_spend.as_slice()].concat())
}

/// Compute nullifier for a note.
///
/// nullifier = Poseidon(domain || prf_key || position || cm)
///
/// The nullifier uniquely identifies a spent note without revealing which note it is.
/// Only the owner (who knows prf_key) can compute the nullifier.
pub fn compute_nullifier(prf_key: &[u8; 32], position: u32, cm: &[u8; 32]) -> [u8; 32] {
    let mut inputs = Vec::new();

    // Domain separator
    let domain_hash = blake2_256(NULLIFIER_DOMAIN);
    inputs.push(FieldElement::from_bytes(&domain_hash[..8]));

    // PRF key (split into chunks)
    for chunk in prf_key.chunks(8) {
        inputs.push(FieldElement::from_bytes(chunk));
    }

    // Position
    inputs.push(FieldElement::from_u64(position as u64));

    // Commitment (split into chunks)
    for chunk in cm.chunks(8) {
        inputs.push(FieldElement::from_bytes(chunk));
    }

    // Compute Poseidon hash
    let hash = poseidon_hash(&inputs);

    // Expand to 32 bytes
    let hash_bytes = hash.to_bytes();
    blake2_256(&[NULLIFIER_DOMAIN, &hash_bytes].concat())
}

/// Verify that a commitment matches a note.
///
/// Returns true if note_commitment(note) == commitment.
pub fn verify_commitment(note: &Note, commitment: &[u8; 32]) -> bool {
    note_commitment(note) == *commitment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_commitment_is_deterministic() {
        let recipient = [1u8; DIVERSIFIED_ADDRESS_SIZE];
        let value = 1000u64;
        let rcm = [2u8; 32];

        let note = Note::with_empty_memo(recipient, value, rcm);
        let cm1 = note_commitment(&note);
        let cm2 = note_commitment(&note);

        assert_eq!(cm1, cm2);
    }

    #[test]
    fn note_commitment_is_binding() {
        let recipient = [1u8; DIVERSIFIED_ADDRESS_SIZE];
        let value = 1000u64;
        let rcm1 = [2u8; 32];
        let rcm2 = [3u8; 32];

        let note1 = Note::with_empty_memo(recipient, value, rcm1);
        let note2 = Note::with_empty_memo(recipient, value, rcm2);

        assert_ne!(note_commitment(&note1), note_commitment(&note2));
    }

    #[test]
    fn note_commitment_from_parts_matches_full_note() {
        let recipient = [1u8; DIVERSIFIED_ADDRESS_SIZE];
        let value = 1000u64;
        let rcm = [2u8; 32];

        let note = Note::with_empty_memo(recipient, value, rcm);
        let cm1 = note_commitment(&note);
        let cm2 = note_commitment_from_parts(&recipient, value, &rcm);

        assert_eq!(cm1, cm2);
    }

    #[test]
    fn nullifier_is_deterministic() {
        let prf_key = [1u8; 32];
        let position = 42u32;
        let cm = [2u8; 32];

        let nf1 = compute_nullifier(&prf_key, position, &cm);
        let nf2 = compute_nullifier(&prf_key, position, &cm);

        assert_eq!(nf1, nf2);
    }

    #[test]
    fn nullifier_uniquely_identifies_note() {
        let prf_key = [1u8; 32];
        let cm = [2u8; 32];

        let nf1 = compute_nullifier(&prf_key, 0, &cm);
        let nf2 = compute_nullifier(&prf_key, 1, &cm);

        assert_ne!(nf1, nf2);
    }

    #[test]
    fn different_prf_keys_produce_different_nullifiers() {
        let prf_key1 = [1u8; 32];
        let prf_key2 = [2u8; 32];
        let position = 0u32;
        let cm = [3u8; 32];

        let nf1 = compute_nullifier(&prf_key1, position, &cm);
        let nf2 = compute_nullifier(&prf_key2, position, &cm);

        assert_ne!(nf1, nf2);
    }

    #[test]
    fn prf_key_derivation_works() {
        let sk_spend = [1u8; 32];
        let prf_key = derive_prf_key(&sk_spend);

        // PRF key should be deterministic
        assert_eq!(prf_key, derive_prf_key(&sk_spend));

        // Different spending keys should produce different PRF keys
        let sk_spend2 = [2u8; 32];
        assert_ne!(prf_key, derive_prf_key(&sk_spend2));
    }

    #[test]
    fn verify_commitment_works() {
        let recipient = [1u8; DIVERSIFIED_ADDRESS_SIZE];
        let value = 1000u64;
        let rcm = [2u8; 32];

        let note = Note::with_empty_memo(recipient, value, rcm);
        let cm = note_commitment(&note);

        assert!(verify_commitment(&note, &cm));

        // Wrong commitment should fail
        let wrong_cm = [0u8; 32];
        assert!(!verify_commitment(&note, &wrong_cm));
    }

    #[test]
    fn poseidon_basic_works() {
        let inputs = [
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
        ];
        let hash = poseidon_hash(&inputs);

        // Hash should be non-zero
        assert_ne!(hash.inner(), 0);

        // Hash should be deterministic
        assert_eq!(hash, poseidon_hash(&inputs));
    }
}
