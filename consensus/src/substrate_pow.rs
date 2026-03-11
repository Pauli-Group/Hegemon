//! SHA-256d-based Proof of Work Algorithm for Substrate
//!
//! This module implements the `PowAlgorithm` trait from `sc-consensus-pow` for
//! integration with the Substrate block import pipeline. It uses compact-target
//! PoW with a 32-byte nonce and a double-SHA-256 work function.
//!
//! # Architecture
//!
//! The PoW algorithm works as follows:
//! 1. Compute `hash = sha256d(pre_hash || nonce)`
//! 2. Compare `hash` to `target = MAX_U256 / difficulty`
//! 3. If `hash <= target`, the seal is valid
//!
//! Difficulty is managed by the runtime's `pow` pallet and queried via the
//! `DifficultyApi` runtime API.

use codec::{Decode, Encode};
use crypto::hashes::sha256;
use sp_core::{H256, U256};
use std::sync::Arc;

/// Compact-target PoW seal data stored in block headers.
#[derive(Clone, PartialEq, Eq, Encode, Decode, Debug)]
pub struct Sha256dSeal {
    /// The nonce that produces a valid hash.
    pub nonce: [u8; 32],
    /// The difficulty (compact bits) at which this block was mined.
    pub difficulty: u32,
    /// The resulting work hash (`sha256d(pre_hash || nonce)`).
    pub work: H256,
}

/// SHA-256d-based Proof of Work algorithm for Hegemon.
pub struct Sha256dAlgorithm<C> {
    client: Arc<C>,
}

impl<C> Sha256dAlgorithm<C> {
    /// Create a new SHA-256d PoW algorithm with the given client.
    pub fn new(client: Arc<C>) -> Self {
        Self { client }
    }
}

impl<C> Clone for Sha256dAlgorithm<C> {
    fn clone(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
        }
    }
}

/// Convert compact bits representation to a target U256.
///
/// The compact format is: `[exponent: 8 bits][mantissa: 24 bits]`
/// `target = mantissa * 2^(8 * (exponent - 3))`
pub fn compact_to_target(bits: u32) -> Option<U256> {
    let exponent = bits >> 24;
    let mantissa = bits & 0x00ff_ffff;

    if mantissa == 0 {
        return None;
    }

    if exponent > 32 {
        return Some(U256::MAX);
    }

    let mut target = U256::from(mantissa);
    if exponent > 3 {
        target <<= 8 * (exponent as usize - 3);
    } else {
        target >>= 8 * (3 - exponent as usize);
    }
    Some(target)
}

/// Convert a target U256 to compact bits representation.
pub fn target_to_compact(target: U256) -> u32 {
    if target.is_zero() {
        return 0;
    }

    let bytes = u256_to_be_bytes(target);
    let mut exponent = 32u32;

    for (i, &byte) in bytes.iter().enumerate() {
        if byte != 0 {
            exponent = (32 - i) as u32;
            break;
        }
    }

    let start = 32 - exponent as usize;
    let mantissa = ((bytes[start] as u32) << 16)
        | ((bytes.get(start + 1).copied().unwrap_or(0) as u32) << 8)
        | (bytes.get(start + 2).copied().unwrap_or(0) as u32);

    (exponent << 24) | (mantissa & 0x00ff_ffff)
}

fn u256_to_be_bytes(value: U256) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, limb) in value.0.iter().rev().enumerate() {
        let limb_bytes = limb.to_be_bytes();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
    }
    bytes
}

/// Convert a round counter into the canonical 32-byte little-endian nonce encoding.
pub fn counter_to_nonce(counter: u64) -> [u8; 32] {
    let mut nonce = [0u8; 32];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Recover the low 64-bit counter prefix from a canonical nonce.
pub fn nonce_counter_prefix(nonce: &[u8; 32]) -> u64 {
    u64::from_le_bytes(nonce[..8].try_into().expect("nonce prefix is 8 bytes"))
}

/// Compute work for mining: `sha256d(pre_hash || nonce)`.
pub fn compute_work(pre_hash: &H256, nonce: [u8; 32]) -> H256 {
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(pre_hash.as_bytes());
    payload[32..].copy_from_slice(&nonce);
    let first = sha256(&payload);
    let second = sha256(&first);
    let result = H256::from_slice(&second);

    tracing::trace!(
        pre_hash_bytes = ?pre_hash.as_bytes(),
        nonce = ?nonce,
        result = ?result,
        "compute_work inputs and output"
    );

    result
}

/// Check if a work hash meets the target difficulty.
pub fn seal_meets_target(work: &H256, pow_bits: u32) -> bool {
    if let Some(target) = compact_to_target(pow_bits) {
        let work_value = U256::from_big_endian(work.as_bytes());
        work_value <= target
    } else {
        false
    }
}

/// Verify a seal is valid for the given pre-hash and difficulty.
pub fn verify_seal(pre_hash: &H256, seal: &Sha256dSeal) -> bool {
    let computed_work = compute_work(pre_hash, seal.nonce);
    if computed_work != seal.work {
        return false;
    }
    seal_meets_target(&seal.work, seal.difficulty)
}

/// Mine a block by searching for a valid nonce within one round.
pub fn mine_round(
    pre_hash: &H256,
    pow_bits: u32,
    round: u32,
    nonces_per_round: u64,
) -> Option<Sha256dSeal> {
    let target = compact_to_target(pow_bits)?;
    let start_counter = (round as u64).saturating_mul(nonces_per_round);
    let end_counter = start_counter.saturating_add(nonces_per_round);

    if round == 0 {
        let first_nonce = counter_to_nonce(start_counter);
        let first_work = compute_work(pre_hash, first_nonce);
        let first_work_value = U256::from_big_endian(first_work.as_bytes());
        tracing::info!(
            pow_bits = format!("{:08x}", pow_bits),
            target = %format!("{:x}", target),
            first_work_value = %format!("{:x}", first_work_value),
            passes = first_work_value <= target,
            first_nonce = ?first_nonce,
            "mine_round: checking difficulty"
        );
    }

    for counter in start_counter..end_counter {
        let nonce = counter_to_nonce(counter);
        let work = compute_work(pre_hash, nonce);
        let work_value = U256::from_big_endian(work.as_bytes());
        if work_value <= target {
            return Some(Sha256dSeal {
                nonce,
                difficulty: pow_bits,
                work,
            });
        }
    }

    None
}

#[cfg(feature = "substrate")]
mod substrate_impl {
    use super::*;
    use sc_consensus_pow::{Error as PowError, PowAlgorithm};
    use sp_api::ProvideRuntimeApi;
    use sp_consensus_pow::Seal;
    use sp_runtime::generic::BlockId;
    use sp_runtime::traits::Block as BlockT;

    use runtime::apis::DifficultyApi;

    impl<B, C> PowAlgorithm<B> for Sha256dAlgorithm<C>
    where
        B: BlockT<Hash = H256>,
        C: ProvideRuntimeApi<B> + Send + Sync,
        C::Api: DifficultyApi<B>,
    {
        type Difficulty = U256;

        fn difficulty(&self, parent: B::Hash) -> Result<Self::Difficulty, PowError<B>> {
            self.client
                .runtime_api()
                .difficulty(parent)
                .map_err(|e| PowError::Environment(format!("Difficulty fetch failed: {:?}", e)))
        }

        fn verify(
            &self,
            _parent: &BlockId<B>,
            pre_hash: &B::Hash,
            _pre_digest: Option<&[u8]>,
            seal: &Seal,
            difficulty: Self::Difficulty,
        ) -> Result<bool, PowError<B>> {
            let pow_seal = Sha256dSeal::decode(&mut &seal[..]).map_err(PowError::Codec)?;
            let expected_bits = target_to_compact(U256::MAX / difficulty);

            tracing::debug!(
                seal_nonce = ?pow_seal.nonce,
                seal_difficulty_bits = pow_seal.difficulty,
                expected_difficulty_bits = expected_bits,
                "Verifying PoW seal"
            );

            if pow_seal.difficulty != expected_bits {
                let seal_target = compact_to_target(pow_seal.difficulty).unwrap_or(U256::zero());
                let expected_target = U256::MAX / difficulty;
                let diff = if seal_target > expected_target {
                    seal_target - expected_target
                } else {
                    expected_target - seal_target
                };

                if diff > expected_target / U256::from(1000u32) {
                    tracing::warn!(
                        seal_difficulty = pow_seal.difficulty,
                        expected_difficulty = expected_bits,
                        "Difficulty mismatch in PoW seal"
                    );
                    return Ok(false);
                }
            }

            let pre_hash_bytes: [u8; 32] = pre_hash.as_ref().try_into().unwrap_or([0u8; 32]);
            let pre_hash_h256 = H256::from(pre_hash_bytes);
            let computed_work = compute_work(&pre_hash_h256, pow_seal.nonce);
            let work_matches = computed_work == pow_seal.work;

            tracing::info!(
                pre_hash = ?pre_hash,
                nonce = ?pow_seal.nonce,
                computed_work = ?computed_work,
                stored_work = ?pow_seal.work,
                work_matches,
                "PoW seal verification details"
            );

            let result = verify_seal(&pre_hash_h256, &pow_seal);
            if !result {
                tracing::warn!(
                    pre_hash = ?pre_hash,
                    nonce = ?pow_seal.nonce,
                    work_matches,
                    "PoW seal verification FAILED"
                );
            }

            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_to_target_basic() {
        let bits = 0x1d00ffff;
        let target = compact_to_target(bits).unwrap();
        assert!(!target.is_zero());
    }

    #[test]
    fn test_compact_to_target_zero_mantissa() {
        let bits = 0x1d000000;
        assert!(compact_to_target(bits).is_none());
    }

    #[test]
    fn test_compact_roundtrip() {
        let original_bits = 0x1d00ffff;
        let target = compact_to_target(original_bits).unwrap();
        let recovered_bits = target_to_compact(target);
        let recovered_target = compact_to_target(recovered_bits).unwrap();
        assert_eq!(target, recovered_target);
    }

    #[test]
    fn test_counter_nonce_roundtrip() {
        let counter = 0x1234_5678_9abc_def0;
        let nonce = counter_to_nonce(counter);
        assert_eq!(nonce_counter_prefix(&nonce), counter);
        assert!(nonce[8..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn test_compute_work_deterministic() {
        let pre_hash = H256::repeat_byte(0x42);
        let nonce = counter_to_nonce(12_345);
        assert_eq!(
            compute_work(&pre_hash, nonce),
            compute_work(&pre_hash, nonce)
        );
    }

    #[test]
    fn test_compute_work_different_nonces() {
        let pre_hash = H256::repeat_byte(0x42);
        let work1 = compute_work(&pre_hash, counter_to_nonce(1));
        let work2 = compute_work(&pre_hash, counter_to_nonce(2));
        assert_ne!(work1, work2);
    }

    #[test]
    fn test_seal_meets_target_easy_difficulty() {
        let easy_bits = 0x2100ffff;
        assert!(seal_meets_target(&H256::zero(), easy_bits));
    }

    #[test]
    fn test_seal_meets_target_hard_difficulty() {
        let hard_bits = 0x0300ffff;
        assert!(!seal_meets_target(&H256::repeat_byte(0xff), hard_bits));
    }

    #[test]
    fn test_verify_seal_valid() {
        let pre_hash = H256::repeat_byte(0x01);
        let pow_bits = 0x2100ffff;
        let seal = mine_round(&pre_hash, pow_bits, 0, 100_000).expect("should find seal");
        assert!(verify_seal(&pre_hash, &seal));
    }

    #[test]
    fn test_verify_seal_wrong_nonce() {
        let pre_hash = H256::repeat_byte(0x01);
        let pow_bits = 0x2100ffff;
        let valid_seal = mine_round(&pre_hash, pow_bits, 0, 100_000).expect("should find seal");
        let invalid_seal = Sha256dSeal {
            nonce: counter_to_nonce(nonce_counter_prefix(&valid_seal.nonce).wrapping_add(1)),
            difficulty: valid_seal.difficulty,
            work: valid_seal.work,
        };
        assert!(!verify_seal(&pre_hash, &invalid_seal));
    }

    #[test]
    fn test_mine_round_finds_solution() {
        let pre_hash = H256::repeat_byte(0xab);
        let pow_bits = 0x2100ffff;
        let mut found = false;
        for round in 0..100 {
            if mine_round(&pre_hash, pow_bits, round, 10_000).is_some() {
                found = true;
                break;
            }
        }
        assert!(found, "should find solution with easy difficulty");
    }

    #[test]
    fn test_sha256d_seal_encoding() {
        let seal = Sha256dSeal {
            nonce: counter_to_nonce(0x1234_5678_9abc_def0),
            difficulty: 0x1d00ffff,
            work: H256::repeat_byte(0x55),
        };
        let encoded = seal.encode();
        let decoded = Sha256dSeal::decode(&mut &encoded[..]).unwrap();
        assert_eq!(seal, decoded);
    }
}
