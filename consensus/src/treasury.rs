//! Exact scheduled treasury entitlement, independent of whether a miner claims.
//!
//! Activation never re-accrues historical blocks. The first complete batch is
//! activation..=activation+59. A fresh genesis uses activation 1. Since every
//! accepted active block accrues its scheduled share, height and the immutable
//! activation policy completely determine branch-local pending entitlement;
//! neither cumulative issued rewards nor miner-selected actions are inputs.

pub const TREASURY_PAYOUT_BLOCKS: u64 = 60;
pub const TREASURY_BATCH_RULES_ID: &[u8] =
    b"hegemon-treasury-exact-per-height-1of5-60-blocks-independent-miner-claim-v1";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TreasuryRewardPolicy {
    activation_height: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreasuryEntitlement {
    pub batch_start: u64,
    pub payout_height: Option<u64>,
    pub accrued_this_block: u64,
    /// Outstanding entitlement after this block's mandatory payout, if any.
    pub pending_after: u64,
    /// Exact amount due now; zero means no treasury output is permitted.
    pub payout: u64,
}

impl TreasuryRewardPolicy {
    pub const fn disabled() -> Self {
        Self {
            activation_height: None,
        }
    }

    /// Explicit injectable policy. Zero is invalid: genesis earns no subsidy.
    pub const fn at(activation_height: u64) -> Option<Self> {
        if activation_height == 0 {
            None
        } else {
            Some(Self {
                activation_height: Some(activation_height),
            })
        }
    }

    pub const fn from_genesis() -> Self {
        Self {
            activation_height: Some(1),
        }
    }

    pub const fn activation_height(self) -> Option<u64> {
        self.activation_height
    }

    pub const fn active_at(self, height: u64) -> bool {
        match self.activation_height {
            Some(activation) => height >= activation,
            None => false,
        }
    }

    pub fn entitlement(self, height: u64) -> Option<TreasuryEntitlement> {
        self.entitlement_with(height, crate::reward::block_subsidy)
    }

    /// Checked bounded summation preserves per-height rounding and exhaustion.
    /// None means inactive or an unrepresentable accumulated amount.
    pub fn entitlement_with(
        self,
        height: u64,
        subsidy: impl Fn(u64) -> u64,
    ) -> Option<TreasuryEntitlement> {
        let activation = self.activation_height?;
        let offset = height.checked_sub(activation)?;
        let batch_start = height - offset % TREASURY_PAYOUT_BLOCKS;
        let last_offset = TREASURY_PAYOUT_BLOCKS - 1;
        let payout_height = batch_start.checked_add(last_offset);
        let mut accrued = 0u64;
        for current in batch_start..=height {
            accrued = accrued.checked_add(subsidy(current) / 5)?;
        }
        let boundary = offset % TREASURY_PAYOUT_BLOCKS == last_offset;
        Some(TreasuryEntitlement {
            batch_start,
            payout_height,
            accrued_this_block: subsidy(height) / 5,
            pending_after: if boundary { 0 } else { accrued },
            payout: if boundary { accrued } else { 0 },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_and_fresh_genesis_boundaries_do_not_reaccrue_history() {
        let policy = TreasuryRewardPolicy::at(120).unwrap();
        assert!(policy.entitlement(119).is_none());
        assert_eq!(policy.entitlement(120).unwrap().pending_after, 100_000_000);
        assert_eq!(
            policy.entitlement(178).unwrap().pending_after,
            5_900_000_000
        );
        assert_eq!(policy.entitlement(179).unwrap().payout, 6_000_000_000);
        assert_eq!(policy.entitlement(180).unwrap().pending_after, 100_000_000);
        let fresh = TreasuryRewardPolicy::from_genesis();
        for height in [1, 59, 61] {
            assert_eq!(fresh.entitlement(height).unwrap().payout, 0);
        }
        for height in [60, 120] {
            assert_eq!(fresh.entitlement(height).unwrap().payout, 6_000_000_000);
        }
        assert!(fresh.entitlement(0).is_none());
        assert!(TreasuryRewardPolicy::at(0).is_none());
    }

    #[test]
    fn exact_rounding_crosses_halving_and_pays_final_residual() {
        let policy = TreasuryRewardPolicy::from_genesis();
        let subsidy = |height| {
            if height <= 23 {
                9
            } else if height <= 43 {
                5
            } else {
                0
            }
        };
        assert_eq!(
            policy.entitlement_with(59, subsidy).unwrap().pending_after,
            43
        );
        assert_eq!(policy.entitlement_with(60, subsidy).unwrap().payout, 43);
        assert_eq!(policy.entitlement_with(120, subsidy).unwrap().payout, 0);
        let start = crate::reward::HALVING_INTERVAL - 19;
        let crossing = TreasuryRewardPolicy::at(start).unwrap();
        let payout = crossing.entitlement(start + 59).unwrap().payout;
        let independently_summed: u64 = (start..=start + 59)
            .map(|h| crate::reward::block_subsidy(h) / 5)
            .sum();
        assert_eq!(payout, independently_summed);
        assert_ne!(payout, crate::reward::block_subsidy(start + 59) / 5 * 60);
        // A 60-block payout remains strictly below the unchanged 61-bit note range.
        assert!(6_000_000_000u128 < 1u128 << 61);
    }

    #[test]
    fn checked_bounds_and_branch_height_reconstruction() {
        let policy = TreasuryRewardPolicy::from_genesis();
        assert!(policy.entitlement_with(60, |_| u64::MAX).is_none());
        let before = policy.entitlement(59).unwrap();
        let paid = policy.entitlement(60).unwrap();
        // Detach boundary, restart or independently replay: immutable height is
        // sufficient; no miner omission can change the branch's entitlement.
        assert_eq!(policy.entitlement(59).unwrap(), before);
        assert_eq!(policy.entitlement(60).unwrap(), paid);
        assert_eq!(paid.pending_after, 0);
        assert_eq!(
            TreasuryRewardPolicy::at(u64::MAX)
                .unwrap()
                .entitlement(u64::MAX)
                .unwrap()
                .payout_height,
            None
        );
    }
}
