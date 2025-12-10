use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::types::SupplyDigest;

// =============================================================================
// CHAIN PARAMETERS - SINGLE SOURCE OF TRUTH
// All other crates should import from here or from runtime re-exports.
// See TOKENOMICS_CALCULATION.md for the derivation of these parameters.
// =============================================================================

pub const COIN: u64 = 100_000_000;

/// Seconds in a year (365 × 24 × 3,600)
pub const T_YEAR: u64 = 31_536_000;

/// Target block time in seconds (60 seconds / 1 minute)
pub const T_BLOCK_SECONDS: u64 = 60;

/// Duration of one issuance epoch in years
pub const Y_EPOCH: u64 = 4;

/// Epoch duration in seconds (Y_EPOCH × T_YEAR)
pub const T_EPOCH_SECONDS: u64 = Y_EPOCH * T_YEAR;

/// Blocks per epoch (4 years of 60s blocks = 2,102,400 blocks)
pub const BLOCKS_PER_EPOCH: u64 = T_EPOCH_SECONDS / T_BLOCK_SECONDS;

/// Maximum supply: 21 million coins
pub const MAX_SUPPLY: u64 = 21_000_000 * COIN;

/// Initial block reward R0 = (S_MAX × t_block) / (2 × Y_EPOCH × T_YEAR)
/// For 60s blocks: R0 = (21,000,000 × 60) / (2 × 4 × 31,536,000) ≈ 4.98 HEG
/// In base units: ~498,287,671 (~4.98 coins)
pub const INITIAL_SUBSIDY: u64 = (MAX_SUPPLY as u128 * T_BLOCK_SECONDS as u128
    / (2 * Y_EPOCH as u128 * T_YEAR as u128)) as u64;

/// Legacy halving interval - now derived from BLOCKS_PER_EPOCH
pub const HALVING_INTERVAL: u64 = BLOCKS_PER_EPOCH;

/// Target block time in milliseconds (60 seconds / 1 minute).
pub const TARGET_BLOCK_INTERVAL_MS: u64 = 60_000;

/// Number of blocks between difficulty adjustments.
/// At 60s blocks, 10 blocks = 10 minutes between adjustments.
pub const RETARGET_WINDOW: u64 = 10;

/// Expected total time for RETARGET_WINDOW blocks (10 * 60s = 600s = 10 minutes).
pub const RETARGET_TIMESPAN_MS: u64 = RETARGET_WINDOW * TARGET_BLOCK_INTERVAL_MS;

/// Maximum adjustment factor per retarget (4x up or down).
pub const MAX_ADJUSTMENT_FACTOR: u64 = 4;

/// Genesis difficulty: ~100 kH/s * 60 seconds = 6,000,000 expected hashes per block.
pub const GENESIS_DIFFICULTY: u128 = 6_000_000;

/// Genesis compact bits: 0x1e218def encodes target = MAX_U256 / 500,000.
pub const GENESIS_BITS: u32 = 0x1e21_8def;

/// Minimum difficulty to prevent divide-by-zero.
pub const MIN_DIFFICULTY: u128 = 1;

pub const MEDIAN_TIME_WINDOW: usize = 11;

/// Maximum timestamp drift allowed (90 seconds for 60s blocks).
pub const MAX_FUTURE_SKEW_MS: u64 = 90_000;

pub fn block_subsidy(height: u64) -> u64 {
    if height == 0 {
        return 0;
    }
    let halvings = (height - 1) / HALVING_INTERVAL;
    let shift = halvings.min(63);
    INITIAL_SUBSIDY >> shift
}

pub fn adjusted_timespan(actual_ms: u64) -> u64 {
    let min = RETARGET_TIMESPAN_MS / 4;
    let max = RETARGET_TIMESPAN_MS * 4;
    actual_ms.clamp(min, max)
}

pub fn retarget_target(prev_target: &BigUint, actual_timespan_ms: u64) -> BigUint {
    if prev_target.is_zero() {
        return BigUint::zero();
    }
    let actual = BigUint::from(adjusted_timespan(actual_timespan_ms));
    let expected = BigUint::from(RETARGET_TIMESPAN_MS);
    let mut target = prev_target * actual;
    if target.is_zero() {
        return target;
    }
    target /= expected;
    if target.is_zero() {
        BigUint::one()
    } else {
        target
    }
}

pub fn update_supply_digest(parent: SupplyDigest, delta: i128) -> Option<SupplyDigest> {
    if delta >= 0 {
        parent.checked_add(delta as u128)
    } else {
        let magnitude = (-delta) as u128;
        parent.checked_sub(magnitude)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn halving_schedule_matches_expectations() {
        assert_eq!(block_subsidy(0), 0);
        assert_eq!(block_subsidy(1), INITIAL_SUBSIDY);
        assert_eq!(block_subsidy(HALVING_INTERVAL), INITIAL_SUBSIDY);
        assert_eq!(block_subsidy(HALVING_INTERVAL + 1), INITIAL_SUBSIDY / 2);
    }

    #[test]
    fn timespan_is_clamped() {
        assert_eq!(adjusted_timespan(0), RETARGET_TIMESPAN_MS / 4);
        assert_eq!(
            adjusted_timespan(RETARGET_TIMESPAN_MS * 10),
            RETARGET_TIMESPAN_MS * 4
        );
    }

    #[test]
    fn supply_digest_handles_signed_delta() {
        let parent: SupplyDigest = 100;
        assert_eq!(update_supply_digest(parent, 25), Some(125));
        assert_eq!(update_supply_digest(parent, -50), Some(50));
        assert_eq!(update_supply_digest(parent, -150), None);
    }

    #[test]
    fn total_minted_is_bounded_by_max_supply() {
        let mut subsidy = INITIAL_SUBSIDY as u128;
        let mut total: u128 = 0;

        while subsidy > 0 {
            total += subsidy * HALVING_INTERVAL as u128;
            subsidy >>= 1;
        }

        assert!(total <= MAX_SUPPLY as u128);
        assert!(total >= (MAX_SUPPLY as u128) - (COIN as u128));
    }
}
