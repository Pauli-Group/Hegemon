//! Note commitment scheme for the shielded pool.
//!
//! Implements Sapling-style note commitments using Poseidon hash.
//! The commitment scheme ensures:
//! - Hiding: commitment reveals nothing about the note contents
//! - Binding: cannot find another note with the same commitment
//!
//! IMPORTANT: Legacy Blake2-wrapped Poseidon helpers are available only with the
//! `legacy-commitment` feature. Production uses circuit-compatible hashing.

#[cfg(feature = "legacy-commitment")]
use sp_core::blake2_256;
#[cfg(feature = "legacy-commitment")]
use sp_std::vec::Vec;

use crate::types::DIVERSIFIED_ADDRESS_SIZE;
#[cfg(feature = "legacy-commitment")]
use crate::types::{Note, MEMO_SIZE};

/// Domain separator for legacy note commitments.
#[cfg(feature = "legacy-commitment")]
const NOTE_COMMITMENT_DOMAIN: &[u8] = b"Hegemon_NoteCommitment_v1";

/// Domain separator for legacy nullifiers.
#[cfg(feature = "legacy-commitment")]
const NULLIFIER_DOMAIN: &[u8] = b"Hegemon_Nullifier_v1";

/// Domain separator for legacy PRF key derivation.
#[cfg(feature = "legacy-commitment")]
const PRF_KEY_DOMAIN: &[u8] = b"Hegemon_PrfKey_v1";

/// Poseidon hash parameters (shared with the circuit).
#[cfg(feature = "legacy-commitment")]
const POSEIDON_ROUNDS: usize = transaction_core::constants::POSEIDON_ROUNDS;
#[cfg(feature = "legacy-commitment")]
const POSEIDON_WIDTH: usize = transaction_core::constants::POSEIDON_WIDTH;

/// Field modulus for legacy Poseidon (Goldilocks prime).
#[cfg(feature = "legacy-commitment")]
const FIELD_MODULUS: u128 = transaction_core::constants::FIELD_MODULUS;

/// A field element for legacy Poseidon operations.
#[cfg(feature = "legacy-commitment")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement(u64);

#[cfg(feature = "legacy-commitment")]
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
) -> [u8; 48] {
    transaction_core::hashing_pq::note_commitment_bytes(value, asset_id, pk_recipient, rho, r)
}

/// Compute nullifier exactly as the ZK circuit does.
///
/// This matches `circuits/transaction/src/hashing.rs::nullifier` exactly.
pub fn circuit_nullifier(prf_key: u64, rho: &[u8; 32], position: u64) -> [u8; 48] {
    let felt = transaction_core::hashing_pq::Felt::from_u64(prf_key);
    transaction_core::hashing_pq::nullifier_bytes(felt, rho, position)
}

/// Compute PRF key exactly as the ZK circuit does.
///
/// This matches `circuits/transaction/src/hashing.rs::prf_key` exactly.
pub fn circuit_prf_key(sk_spend: &[u8; 32]) -> u64 {
    transaction_core::hashing_pq::prf_key(sk_spend).as_canonical_u64()
}

/// Convert a circuit Felt (u64) to a 32-byte commitment.
/// The Felt is stored in the last 8 bytes as big-endian.
pub fn felt_to_commitment(felt: u64) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[40..48].copy_from_slice(&felt.to_be_bytes());
    out
}

/// Extract a circuit Felt (u64) from a 32-byte commitment.
/// The Felt is stored in the last 8 bytes as big-endian.
pub fn commitment_to_felt(commitment: &[u8; 48]) -> u64 {
    u64::from_be_bytes([
        commitment[40],
        commitment[41],
        commitment[42],
        commitment[43],
        commitment[44],
        commitment[45],
        commitment[46],
        commitment[47],
    ])
}

// ================================================================================================
// LEGACY POSEIDON IMPLEMENTATION (feature-gated; not used in production)
// ================================================================================================

/// Generate round constants for legacy Poseidon.
#[cfg(feature = "legacy-commitment")]
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

/// MDS mixing matrix application (legacy).
#[cfg(feature = "legacy-commitment")]
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

/// Legacy Poseidon hash (feature-gated).
#[cfg(feature = "legacy-commitment")]
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

/// Compute legacy note commitment (feature-gated).
#[cfg(feature = "legacy-commitment")]
pub fn note_commitment(note: &Note) -> [u8; 32] {
    let mut inputs = Vec::new();
    let domain_hash = blake2_256(NOTE_COMMITMENT_DOMAIN);
    inputs.push(FieldElement::from_bytes(&domain_hash[..8]));
    for chunk in note.recipient.chunks(8) {
        inputs.push(FieldElement::from_bytes(chunk));
    }
    inputs.push(FieldElement::from_u64(note.value));
    for chunk in note.rcm.chunks(8) {
        inputs.push(FieldElement::from_bytes(chunk));
    }
    let hash = poseidon_hash(&inputs);
    let hash_bytes = hash.to_bytes();
    blake2_256(&[NOTE_COMMITMENT_DOMAIN, &hash_bytes].concat())
}

/// Compute legacy note commitment from raw components (feature-gated).
#[cfg(feature = "legacy-commitment")]
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
/// commitment = circuit_note_commitment(recipient, value, rho, r)
/// where rho/r are derived from the public seed
#[deprecated(
    since = "0.2.0",
    note = "Use circuit_coinbase_commitment for ZK-compatible commitments"
)]
pub fn coinbase_commitment(
    recipient: &[u8; DIVERSIFIED_ADDRESS_SIZE],
    value: u64,
    public_seed: &[u8; 32],
) -> [u8; 48] {
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
/// Returns: 48-byte commitment encoding (6 x 64-bit limbs)
pub fn circuit_coinbase_commitment(
    pk_recipient: &[u8; 32],
    value: u64,
    public_seed: &[u8; 32],
    asset_id: u64,
) -> [u8; 48] {
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
#[cfg(feature = "legacy-commitment")]
pub fn derive_prf_key(sk_spend: &[u8; 32]) -> [u8; 32] {
    blake2_256(&[PRF_KEY_DOMAIN, sk_spend.as_slice()].concat())
}

/// Compute nullifier for a note.
///
/// nullifier = Poseidon(domain || prf_key || position || cm)
///
/// The nullifier uniquely identifies a spent note without revealing which note it is.
/// Only the owner (who knows prf_key) can compute the nullifier.
#[cfg(feature = "legacy-commitment")]
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
#[cfg(feature = "legacy-commitment")]
pub fn verify_commitment(note: &Note, commitment: &[u8; 32]) -> bool {
    note_commitment(note) == *commitment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_commitment_is_deterministic() {
        let pk_recipient = [1u8; 32];
        let rho = [2u8; 32];
        let r = [3u8; 32];
        let value = 1000u64;
        let asset_id = 0u64;

        let cm1 = circuit_note_commitment(value, asset_id, &pk_recipient, &rho, &r);
        let cm2 = circuit_note_commitment(value, asset_id, &pk_recipient, &rho, &r);
        assert_eq!(cm1, cm2);
    }

    #[test]
    fn note_commitment_is_binding() {
        let pk_recipient = [1u8; 32];
        let rho = [2u8; 32];
        let value = 1000u64;
        let asset_id = 0u64;
        let r1 = [3u8; 32];
        let r2 = [4u8; 32];

        let cm1 = circuit_note_commitment(value, asset_id, &pk_recipient, &rho, &r1);
        let cm2 = circuit_note_commitment(value, asset_id, &pk_recipient, &rho, &r2);
        assert_ne!(cm1, cm2);
    }

    #[test]
    fn nullifier_is_deterministic() {
        let prf_key = 42u64;
        let position = 42u64;
        let rho = [9u8; 32];

        let nf1 = circuit_nullifier(prf_key, &rho, position);
        let nf2 = circuit_nullifier(prf_key, &rho, position);

        assert_eq!(nf1, nf2);
    }

    #[test]
    fn nullifier_uniquely_identifies_note() {
        let prf_key = 1u64;
        let rho = [2u8; 32];

        let nf1 = circuit_nullifier(prf_key, &rho, 0);
        let nf2 = circuit_nullifier(prf_key, &rho, 1);

        assert_ne!(nf1, nf2);
    }

    #[test]
    fn different_prf_keys_produce_different_nullifiers() {
        let prf_key1 = 1u64;
        let prf_key2 = 2u64;
        let position = 0u64;
        let rho = [3u8; 32];

        let nf1 = circuit_nullifier(prf_key1, &rho, position);
        let nf2 = circuit_nullifier(prf_key2, &rho, position);

        assert_ne!(nf1, nf2);
    }

    #[test]
    fn prf_key_derivation_works() {
        let sk_spend = [1u8; 32];
        let prf_key = circuit_prf_key(&sk_spend);

        // PRF key should be deterministic
        assert_eq!(prf_key, circuit_prf_key(&sk_spend));

        // Different spending keys should produce different PRF keys
        let sk_spend2 = [2u8; 32];
        assert_ne!(prf_key, circuit_prf_key(&sk_spend2));
    }

    #[test]
    fn coinbase_commitment_matches_circuit_form() {
        let pk_recipient = [9u8; 32];
        let value = 500u64;
        let seed = [7u8; 32];

        let rho = derive_coinbase_rho(&seed);
        let r = derive_coinbase_r(&seed);
        let direct = circuit_note_commitment(value, 0, &pk_recipient, &rho, &r);
        let via_coinbase = circuit_coinbase_commitment(&pk_recipient, value, &seed, 0);

        assert_eq!(direct, via_coinbase);
    }
}
