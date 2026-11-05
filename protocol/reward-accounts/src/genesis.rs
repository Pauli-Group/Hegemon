use crate::*;
use codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub const REWARD_GENESIS_SCHEMA: &str = "hegemon.reward-accounts.genesis.v1";

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisAllocation {
    pub account: AccountPolicyId48,
    pub amount: u64,
}

/// Network class/discriminator are independent of the final genesis digest.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewardAccountsGenesis {
    pub network: AddressNetwork,
    pub reward_epoch_blocks: u64,
    pub treasury_policy: AccountPolicy,
    #[serde(default)]
    pub allocations: BoundedVec<GenesisAllocation, MAX_GENESIS_ALLOCATIONS>,
}
impl RewardAccountsGenesis {
    pub fn validate(&self) -> Result<u64, RewardAccountsError> {
        self.network.validate()?;
        RewardEpochSchedule::new(self.reward_epoch_blocks)?.release_height(0)?;
        self.treasury_policy.validate()?;
        if self
            .allocations
            .windows(2)
            .any(|a| a[0].account >= a[1].account)
        {
            return Err(RewardAccountsError::NoncanonicalAllocation);
        }
        self.allocations.iter().try_fold(0u64, |sum, row| {
            if row.amount == 0 || row.account == AccountPolicyId48::ZERO {
                return Err(RewardAccountsError::InvalidAllocation);
            }
            sum.checked_add(row.amount)
                .filter(|n| *n <= MAX_SUPPLY)
                .ok_or(RewardAccountsError::InvalidAllocation)
        })
    }
    pub fn treasury_account(&self) -> Result<AccountPolicyId48, RewardAccountsError> {
        self.treasury_policy.validate()?;
        Ok(protocol_treasury_account_id())
    }
    pub fn issuance(&self) -> Result<IssuanceSchedule, RewardAccountsError> {
        IssuanceSchedule::new(self.validate()?)
    }
    pub fn epochs(&self) -> Result<RewardEpochSchedule, RewardAccountsError> {
        self.validate()?;
        RewardEpochSchedule::new(self.reward_epoch_blocks)
    }
    pub fn commitment(&self) -> Result<[u8; 48], RewardAccountsError> {
        self.validate()?;
        Ok(crypto::hash384::blake2b_384_domain_hash(
            b"hegemon.reward-accounts.genesis-commitment.v1",
            [
                REWARD_GENESIS_SCHEMA.as_bytes(),
                REWARD_ACCOUNTS_RULES_ID,
                &(
                    MAX_SUPPLY,
                    ISSUANCE_ERA_BLOCKS,
                    TREASURY_SUBSIDY_NUMERATOR,
                    TREASURY_SUBSIDY_DENOMINATOR,
                )
                    .encode(),
                self.encode().as_slice(),
            ],
        ))
    }
    /// One canonical SCALE payload; bounded nested decoders reject before allocation.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, RewardAccountsError> {
        let mut cursor = bytes;
        let value =
            Self::decode(&mut cursor).map_err(|_| RewardAccountsError::InvalidAllocation)?;
        if !cursor.is_empty() || value.encode() != bytes {
            return Err(RewardAccountsError::NoncanonicalAllocation);
        }
        value.validate()?;
        Ok(value)
    }
}
