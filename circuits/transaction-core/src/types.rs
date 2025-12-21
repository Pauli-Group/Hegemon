//! Core shared types.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceSlot {
    pub asset_id: u64,
    pub delta: i128,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StablecoinPolicyBinding {
    pub enabled: bool,
    pub asset_id: u64,
    pub policy_hash: [u8; 32],
    pub oracle_commitment: [u8; 32],
    pub attestation_commitment: [u8; 32],
    pub issuance_delta: i128,
    pub policy_version: u32,
}
