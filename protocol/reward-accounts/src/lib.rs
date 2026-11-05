//! Fresh-genesis reward accounts. These rules do not activate a node route.
#![forbid(unsafe_code)]

mod account_tree;
mod address;
mod bounded;
mod genesis;
mod governance;
mod ledger;
mod policy;
mod schedule;

pub use address::*;
pub use bounded::BoundedVec;
pub use crypto::hash384::{AccountKeyHash48, AccountPolicyId48, RewardAccountsRoot48};
pub use genesis::*;
pub use governance::*;
pub use ledger::*;
pub use policy::*;
pub use protocol_versioning::{
    NATIVE_COIN as COIN, NATIVE_ISSUANCE_ERA_BLOCKS as ISSUANCE_ERA_BLOCKS,
    NATIVE_MAX_SUPPLY as MAX_SUPPLY,
};
pub use schedule::*;

pub const DEFAULT_REWARD_EPOCH_BLOCKS: u64 = 1_440;
pub const MAX_ACCOUNT_SIGNERS: usize = 16;
pub const MAX_GENESIS_ALLOCATIONS: usize = 65_536;
pub const MAX_PUBLIC_MEMO_BYTES: usize = 256;
pub const TREASURY_SUBSIDY_NUMERATOR: u64 = 1;
pub const TREASURY_SUBSIDY_DENOMINATOR: u64 = 5;
pub const REWARD_ACCOUNTS_RULES_ID: &[u8] =
    b"hegemon.reward-accounts.epoch-n-plus-two.policy-hash.genesis-budget.v1";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RewardAccountsError {
    #[error("invalid account authorization policy")]
    InvalidPolicy,
    #[error("invalid or insufficient distinct signer approvals")]
    InvalidApprovals,
    #[error("invalid genesis allocation or native supply budget")]
    InvalidAllocation,
    #[error("noncanonical or unsorted genesis allocation")]
    NoncanonicalAllocation,
    #[error("reward epoch must contain at least one block")]
    InvalidEpoch,
    #[error("height or monetary arithmetic overflow")]
    Overflow,
    #[error("invalid network class or zero network discriminator")]
    InvalidNetwork,
    #[error("invalid block height, chain context, or noncanonical account operation")]
    InvalidContext,
    #[error("claim sequence or treasury policy generation is stale")]
    StaleClaim,
    #[error("insufficient available account balance")]
    InsufficientBalance,
    #[error("reward account proof verification failed")]
    InvalidProof,
    #[error("account ledger failed conservation or structural validation")]
    InvalidState,
    #[error("invalid, occupied, stale or unadopted treasury hard fork")]
    InvalidTreasuryFork,
    #[error("address encoding: {0}")]
    Address(String),
    #[error("address belongs to another network or address family")]
    WrongAddressNetworkOrKind,
}

pub(crate) fn hash48(domain: &[u8], body: &[u8]) -> [u8; 48] {
    crypto::hash384::blake2b_384_domain_hash(domain, [body])
}
