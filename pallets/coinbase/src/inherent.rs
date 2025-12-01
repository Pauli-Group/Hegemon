//! Coinbase Inherent Data Provider
//!
//! This module provides the client-side inherent data provider that mining nodes
//! use to specify the coinbase recipient and amount.
//!
//! # Usage
//!
//! ```ignore
//! // In mining node setup:
//! let coinbase_provider = CoinbaseInherentDataProvider::new(
//!     miner_account_id.encode(),
//!     block_subsidy(next_height),
//! );
//!
//! // When building block:
//! inherent_data_providers.register_provider(coinbase_provider);
//! ```

use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_inherents::{InherentData, InherentIdentifier};

/// The inherent identifier for coinbase data
pub const COINBASE_INHERENT_IDENTIFIER: InherentIdentifier = *b"coinbase";

/// Coinbase inherent data - passed from mining node to runtime
#[derive(Clone, Debug, Encode, Decode, TypeInfo, PartialEq, Eq)]
pub struct CoinbaseInherentData {
    /// Encoded recipient account ID (will be decoded by runtime)
    pub recipient: sp_std::vec::Vec<u8>,
    /// Amount to mint (should be <= block_subsidy for the height)
    pub amount: u64,
}

impl CoinbaseInherentData {
    /// Create new coinbase inherent data
    pub fn new(recipient: sp_std::vec::Vec<u8>, amount: u64) -> Self {
        Self { recipient, amount }
    }
}

/// Client-side inherent data provider for coinbase rewards
///
/// Mining nodes create this provider with their desired recipient address
/// and the block reward amount. It's then registered with the block builder's
/// inherent data providers.
#[cfg(feature = "std")]
pub struct CoinbaseInherentDataProvider {
    /// Encoded recipient account
    recipient: Vec<u8>,
    /// Amount to mint
    amount: u64,
}

#[cfg(feature = "std")]
impl CoinbaseInherentDataProvider {
    /// Create a new coinbase inherent data provider
    ///
    /// # Arguments
    /// * `recipient` - SCALE-encoded account ID of the reward recipient
    /// * `amount` - Amount to mint (should match block_subsidy for height)
    pub fn new(recipient: Vec<u8>, amount: u64) -> Self {
        Self { recipient, amount }
    }

    /// Create from an account that implements Encode
    pub fn from_account<A: Encode>(account: &A, amount: u64) -> Self {
        Self {
            recipient: account.encode(),
            amount,
        }
    }
}

#[cfg(feature = "std")]
#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for CoinbaseInherentDataProvider {
    async fn provide_inherent_data(
        &self,
        inherent_data: &mut InherentData,
    ) -> Result<(), sp_inherents::Error> {
        let data = CoinbaseInherentData {
            recipient: self.recipient.clone(),
            amount: self.amount,
        };
        inherent_data.put_data(COINBASE_INHERENT_IDENTIFIER, &data)
    }

    async fn try_handle_error(
        &self,
        identifier: &InherentIdentifier,
        _error: &[u8],
    ) -> Option<Result<(), sp_inherents::Error>> {
        if identifier == &COINBASE_INHERENT_IDENTIFIER {
            // Log the error but don't fail block production
            log::warn!(target: "coinbase", "Coinbase inherent error occurred");
            Some(Ok(()))
        } else {
            None
        }
    }
}

// Re-export for external use
pub use sp_std;
