//! Core shared types.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceSlot {
    pub asset_id: u64,
    pub delta: i128,
}

pub type Commitment48 = [u8; 48];
pub type Nullifier48 = [u8; 48];
pub type MerkleRoot48 = [u8; 48];

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StablecoinPolicyBinding {
    pub enabled: bool,
    pub asset_id: u64,
    pub policy_hash: Commitment48,
    pub oracle_commitment: Commitment48,
    pub attestation_commitment: Commitment48,
    pub issuance_delta: i128,
    pub policy_version: u32,
}
