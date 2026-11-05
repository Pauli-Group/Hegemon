use crate::{RewardAccountsError as Error, ISSUANCE_ERA_BLOCKS, MAX_SUPPLY};
use codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Earning epochs start at block one. Genesis is outside reward epochs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct RewardEpochSchedule {
    blocks: u64,
}
impl RewardEpochSchedule {
    pub fn new(blocks: u64) -> Result<Self, Error> {
        if blocks == 0 {
            return Err(Error::InvalidEpoch);
        }
        Ok(Self { blocks })
    }
    pub fn blocks(self) -> u64 {
        self.blocks
    }
    pub fn epoch_at(self, height: u64) -> Result<u64, Error> {
        if self.blocks == 0 {
            return Err(Error::InvalidEpoch);
        }
        Ok(height.checked_sub(1).ok_or(Error::InvalidEpoch)? / self.blocks)
    }
    pub fn release_height(self, earning_epoch: u64) -> Result<u64, Error> {
        if self.blocks == 0 {
            return Err(Error::InvalidEpoch);
        }
        earning_epoch
            .checked_add(2)
            .and_then(|e| e.checked_mul(self.blocks))
            .and_then(|h| h.checked_add(1))
            .ok_or(Error::Overflow)
    }
    pub fn reward_release_height(self, height: u64) -> Result<u64, Error> {
        self.release_height(self.epoch_at(height)?)
    }
}

/// Exact legacy curve shape, funded only by the post-genesis remainder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuanceSchedule {
    mining_budget: u64,
}
impl IssuanceSchedule {
    pub fn new(genesis_allocated: u64) -> Result<Self, Error> {
        Ok(Self {
            mining_budget: MAX_SUPPLY
                .checked_sub(genesis_allocated)
                .ok_or(Error::InvalidAllocation)?,
        })
    }
    pub fn mining_budget(self) -> u64 {
        self.mining_budget
    }
    pub fn remaining(self, era: u64) -> u64 {
        if era >= 64 {
            0
        } else {
            self.mining_budget >> era
        }
    }
    pub fn era_budget(self, era: u64) -> u64 {
        if era >= 64 {
            0
        } else {
            self.remaining(era) - self.remaining(era + 1)
        }
    }
    pub fn subsidy(self, height: u64) -> u64 {
        if height == 0 {
            return 0;
        }
        let era = (height - 1) / ISSUANCE_ERA_BLOCKS;
        let slot = (height - 1) % ISSUANCE_ERA_BLOCKS;
        let b = self.era_budget(era) as u128;
        let l = ISSUANCE_ERA_BLOCKS as u128;
        (((slot as u128 + 1) * b / l) - (slot as u128 * b / l)) as u64
    }
    pub fn issued_through(self, height: u64) -> u64 {
        let era = height / ISSUANCE_ERA_BLOCKS;
        let slot = height % ISSUANCE_ERA_BLOCKS;
        self.mining_budget - self.remaining(era)
            + (slot as u128 * self.era_budget(era) as u128 / ISSUANCE_ERA_BLOCKS as u128) as u64
    }
}

pub fn reward_split(subsidy: u64, total_miner_fee: u64) -> Result<(u64, u64), Error> {
    let treasury = (subsidy as u128 * crate::TREASURY_SUBSIDY_NUMERATOR as u128
        / crate::TREASURY_SUBSIDY_DENOMINATOR as u128) as u64;
    let miner = subsidy
        .checked_sub(treasury)
        .and_then(|s| s.checked_add(total_miner_fee))
        .ok_or(Error::Overflow)?;
    Ok((miner, treasury))
}
