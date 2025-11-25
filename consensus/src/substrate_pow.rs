//! Blake3-based Proof of Work Algorithm for Substrate
//!
//! This module implements the `PowAlgorithm` trait from `sc-consensus-pow` for
//! integration with the Substrate block import pipeline. It uses Blake3 hashing
//! for high performance while maintaining the existing PoW difficulty scheme.
//!
//! # Architecture
//!
//! The PoW algorithm works as follows:
//! 1. Compute `hash = blake3(pre_hash || nonce)`
//! 2. Compare `hash` to `target = MAX_U256 / difficulty`
//! 3. If `hash <= target`, the seal is valid
//!
//! Difficulty is managed by the runtime's `pow` pallet and queried via
//! the `DifficultyApi` runtime API.

use codec::{Decode, Encode};
use sp_core::{H256, U256};
use std::sync::Arc;

/// Blake3-based seal data stored in block headers
#[derive(Clone, PartialEq, Eq, Encode, Decode, Debug)]
pub struct Blake3Seal {
    /// The nonce that produces a valid hash
    pub nonce: u64,
    /// The difficulty (compact bits) at which this block was mined
    pub difficulty: u32,
    /// The resulting work hash (blake3(pre_hash || nonce))
    pub work: H256,
}

/// Blake3-based Proof of Work algorithm for Hegemon
///
/// This struct implements the Substrate `PowAlgorithm` trait, providing:
/// - Difficulty queries from the runtime
/// - Seal verification
/// - Mining (finding valid nonces)
pub struct Blake3Algorithm<C> {
    client: Arc<C>,
}

impl<C> Blake3Algorithm<C> {
    /// Create a new Blake3 PoW algorithm with the given client
    pub fn new(client: Arc<C>) -> Self {
        Self { client }
    }
}

impl<C> Clone for Blake3Algorithm<C> {
    fn clone(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
        }
    }
}

/// Convert compact bits representation to a target U256
///
/// The compact format is: `[exponent: 8 bits][mantissa: 24 bits]`
/// Target = mantissa * 2^(8 * (exponent - 3))
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

/// Convert a target U256 to compact bits representation
pub fn target_to_compact(target: U256) -> u32 {
    if target.is_zero() {
        return 0;
    }
    
    // Convert to big-endian bytes
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

/// Helper to convert U256 to big-endian bytes
fn u256_to_be_bytes(value: U256) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    // U256 internally stores as 4 u64 limbs in little-endian order
    // limb[0] is the least significant
    for (i, limb) in value.0.iter().rev().enumerate() {
        let limb_bytes = limb.to_be_bytes();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
    }
    bytes
}

/// Compute work for mining: blake3(pre_hash || nonce)
pub fn compute_work(pre_hash: &H256, nonce: u64) -> H256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(pre_hash.as_bytes());
    hasher.update(&nonce.to_le_bytes());
    H256::from_slice(hasher.finalize().as_bytes())
}

/// Check if a work hash meets the target difficulty
pub fn seal_meets_target(work: &H256, pow_bits: u32) -> bool {
    if let Some(target) = compact_to_target(pow_bits) {
        let work_value = U256::from_big_endian(work.as_bytes());
        work_value <= target
    } else {
        false
    }
}

/// Verify a seal is valid for the given pre-hash and difficulty
pub fn verify_seal(pre_hash: &H256, seal: &Blake3Seal) -> bool {
    let computed_work = compute_work(pre_hash, seal.nonce);
    
    // Verify the work matches what's in the seal
    if computed_work != seal.work {
        return false;
    }
    
    // Verify the work meets the difficulty target
    seal_meets_target(&seal.work, seal.difficulty)
}

/// Mine a block by searching for a valid nonce
///
/// This function searches for a nonce that produces a hash meeting the
/// target difficulty. It searches in rounds to allow for cooperative
/// cancellation.
///
/// # Arguments
/// * `pre_hash` - The block header hash before the seal
/// * `pow_bits` - The difficulty in compact bits format
/// * `round` - The current round number (for distributing work)
/// * `nonces_per_round` - Number of nonces to try per round
///
/// # Returns
/// * `Some(Blake3Seal)` if a valid seal was found
/// * `None` if no valid seal was found in this round
pub fn mine_round(
    pre_hash: &H256,
    pow_bits: u32,
    round: u32,
    nonces_per_round: u64,
) -> Option<Blake3Seal> {
    let target = compact_to_target(pow_bits)?;
    let start_nonce = (round as u64).saturating_mul(nonces_per_round);
    let end_nonce = start_nonce.saturating_add(nonces_per_round);
    
    for nonce in start_nonce..end_nonce {
        let work = compute_work(pre_hash, nonce);
        let work_value = U256::from_big_endian(work.as_bytes());
        
        if work_value <= target {
            return Some(Blake3Seal {
                nonce,
                difficulty: pow_bits,
                work,
            });
        }
    }
    
    None
}

// ============================================================================
// Substrate PowAlgorithm Implementation
// ============================================================================
// 
// The following implementation is gated behind the "substrate" feature flag
// as it requires sc-consensus-pow which has complex dependency requirements.
// 
// To enable, add to consensus/Cargo.toml:
// [features]
// substrate = ["sc-consensus-pow", "sp-consensus-pow"]

#[cfg(feature = "substrate")]
mod substrate_impl {
    use super::*;
    use sc_consensus_pow::{Error as PowError, PowAlgorithm};
    use sp_api::ProvideRuntimeApi;
    use sp_consensus_pow::Seal;
    use sp_runtime::traits::Block as BlockT;

    /// Runtime API for querying PoW difficulty
    ///
    /// The runtime must implement this API to provide difficulty values
    /// to the consensus engine.
    sp_api::decl_runtime_apis! {
        pub trait DifficultyApi {
            /// Get the current PoW difficulty in compact bits format
            fn difficulty() -> u32;
        }
    }

    impl<B, C> PowAlgorithm<B> for Blake3Algorithm<C>
    where
        B: BlockT<Hash = H256>,
        C: ProvideRuntimeApi<B> + Send + Sync,
        C::Api: DifficultyApi<B>,
    {
        type Difficulty = u32;

        fn difficulty(&self, parent: B::Hash) -> Result<Self::Difficulty, PowError<B>> {
            self.client
                .runtime_api()
                .difficulty(parent)
                .map_err(|e| PowError::Environment(format!("Difficulty fetch failed: {:?}", e)))
        }

        fn verify(
            &self,
            _parent: &B::Hash,
            pre_hash: &H256,
            _pre_digest: Option<&[u8]>,
            seal: &Seal,
            difficulty: Self::Difficulty,
        ) -> Result<bool, PowError<B>> {
            let blake3_seal = Blake3Seal::decode(&mut &seal[..])
                .map_err(|_| PowError::FailedToDecode)?;
            
            // Verify the difficulty matches
            if blake3_seal.difficulty != difficulty {
                return Ok(false);
            }
            
            // Verify the seal
            Ok(verify_seal(pre_hash, &blake3_seal))
        }

        fn mine(
            &self,
            _parent: &B::Hash,
            pre_hash: &H256,
            difficulty: Self::Difficulty,
            round: u32,
        ) -> Result<Option<Seal>, PowError<B>> {
            const NONCES_PER_ROUND: u64 = 10_000;
            
            match mine_round(pre_hash, difficulty, round, NONCES_PER_ROUND) {
                Some(seal) => Ok(Some(seal.encode())),
                None => Ok(None),
            }
        }
    }
}

#[cfg(feature = "substrate")]
pub use substrate_impl::*;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_to_target_basic() {
        // 0x1d00ffff is approximately the Bitcoin genesis difficulty
        let bits = 0x1d00ffff;
        let target = compact_to_target(bits).unwrap();
        assert!(!target.is_zero());
    }

    #[test]
    fn test_compact_to_target_zero_mantissa() {
        let bits = 0x1d000000; // Zero mantissa
        assert!(compact_to_target(bits).is_none());
    }

    #[test]
    fn test_compact_roundtrip() {
        let original_bits = 0x1d00ffff;
        let target = compact_to_target(original_bits).unwrap();
        let recovered_bits = target_to_compact(target);
        
        // May not be exactly equal due to precision, but should be close
        let recovered_target = compact_to_target(recovered_bits).unwrap();
        assert_eq!(target, recovered_target);
    }

    #[test]
    fn test_compute_work_deterministic() {
        let pre_hash = H256::repeat_byte(0x42);
        let nonce = 12345u64;
        
        let work1 = compute_work(&pre_hash, nonce);
        let work2 = compute_work(&pre_hash, nonce);
        
        assert_eq!(work1, work2);
    }

    #[test]
    fn test_compute_work_different_nonces() {
        let pre_hash = H256::repeat_byte(0x42);
        
        let work1 = compute_work(&pre_hash, 1);
        let work2 = compute_work(&pre_hash, 2);
        
        assert_ne!(work1, work2);
    }

    #[test]
    fn test_seal_meets_target_easy_difficulty() {
        // Very easy difficulty (high target)
        let easy_bits = 0x2100ffff;
        let work = H256::zero(); // Zero is always below any non-zero target
        assert!(seal_meets_target(&work, easy_bits));
    }

    #[test]
    fn test_seal_meets_target_hard_difficulty() {
        // Very hard difficulty (low target)
        let hard_bits = 0x0300ffff;
        let work = H256::repeat_byte(0xff); // Max value, won't meet hard target
        assert!(!seal_meets_target(&work, hard_bits));
    }

    #[test]
    fn test_verify_seal_valid() {
        let pre_hash = H256::repeat_byte(0x01);
        // Very easy difficulty for testing
        let pow_bits = 0x2100ffff;
        
        // Find a valid seal
        let seal = mine_round(&pre_hash, pow_bits, 0, 100_000)
            .expect("should find seal with easy difficulty");
        
        assert!(verify_seal(&pre_hash, &seal));
    }

    #[test]
    fn test_verify_seal_wrong_nonce() {
        let pre_hash = H256::repeat_byte(0x01);
        let pow_bits = 0x2100ffff;
        
        let valid_seal = mine_round(&pre_hash, pow_bits, 0, 100_000)
            .expect("should find seal");
        
        // Modify the nonce but keep the same work (should fail)
        let invalid_seal = Blake3Seal {
            nonce: valid_seal.nonce.wrapping_add(1),
            difficulty: valid_seal.difficulty,
            work: valid_seal.work, // Work won't match new nonce
        };
        
        assert!(!verify_seal(&pre_hash, &invalid_seal));
    }

    #[test]
    fn test_mine_round_finds_solution() {
        let pre_hash = H256::repeat_byte(0xab);
        // Easy difficulty
        let pow_bits = 0x2100ffff;
        
        // Should find a solution within reasonable rounds
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
    fn test_blake3_seal_encoding() {
        let seal = Blake3Seal {
            nonce: 0x123456789abcdef0,
            difficulty: 0x1d00ffff,
            work: H256::repeat_byte(0x55),
        };
        
        let encoded = seal.encode();
        let decoded = Blake3Seal::decode(&mut &encoded[..]).unwrap();
        
        assert_eq!(seal, decoded);
    }
}
