use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::types::SupplyDigest;

pub const COIN: u64 = 100_000_000;
pub const INITIAL_SUBSIDY: u64 = 50 * COIN;
pub const HALVING_INTERVAL: u64 = 210_000;
pub const MAX_SUPPLY: u64 = 21_000_000 * COIN;
pub const RETARGET_WINDOW: u64 = 120;
pub const TARGET_BLOCK_INTERVAL_MS: u64 = 20_000;
pub const RETARGET_TIMESPAN_MS: u64 = RETARGET_WINDOW * TARGET_BLOCK_INTERVAL_MS;
pub const MEDIAN_TIME_WINDOW: usize = 11;
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
