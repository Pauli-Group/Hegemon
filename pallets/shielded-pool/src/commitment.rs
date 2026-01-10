//! Note commitment scheme for the shielded pool.
//!
//! Implements circuit-compatible Poseidon2 hashing for commitments and nullifiers.

use p3_field::{PrimeCharacteristicRing, PrimeField64};

use crate::types::DIVERSIFIED_ADDRESS_SIZE;

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

/// Convert a circuit Felt (u64) to a 48-byte commitment.
/// The Felt is stored in the last 8 bytes as big-endian.
pub fn felt_to_commitment(felt: u64) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[40..48].copy_from_slice(&felt.to_be_bytes());
    out
}

/// Extract a circuit Felt (u64) from a 48-byte commitment.
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

/// Extract recipient public key from a diversified address.
///
/// Layout: version(1) + diversifier_index(4) + pk_recipient(32) + tag(6)
pub fn pk_recipient_from_address(recipient: &[u8; DIVERSIFIED_ADDRESS_SIZE]) -> [u8; 32] {
    let mut pk_recipient = [0u8; 32];
    pk_recipient.copy_from_slice(&recipient[5..37]);
    pk_recipient
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
