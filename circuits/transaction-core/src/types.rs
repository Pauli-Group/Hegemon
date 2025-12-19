//! Core shared types.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceSlot {
    pub asset_id: u64,
    pub delta: i128,
}
