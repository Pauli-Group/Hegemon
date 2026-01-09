//! Shielded Coinbase Inherent Data Provider
//!
//! This module provides the client-side inherent data provider that mining nodes
//! use to specify shielded coinbase rewards.
//!
//! # Usage
//!
//! ```ignore
//! // In mining node setup:
//! let coinbase_provider = ShieldedCoinbaseInherentDataProvider::new(
//!     encrypted_note,
//!     recipient_address,
//!     amount,
//!     public_seed,
//!     commitment,
//! );
//!
//! // When building block:
//! inherent_data_providers.register_provider(coinbase_provider);
//! ```

use codec::{Decode, Encode};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use sp_inherents::InherentData;
use sp_inherents::InherentIdentifier;

use crate::types::{CoinbaseNoteData, Commitment, EncryptedNote, DIVERSIFIED_ADDRESS_SIZE};

/// The inherent identifier for shielded coinbase data
pub const SHIELDED_COINBASE_INHERENT_IDENTIFIER: InherentIdentifier = *b"shldcoin";

/// Shielded coinbase inherent data - passed from mining node to runtime
///
/// This contains all data needed to mint a shielded coinbase note:
/// - The encrypted note (only miner can decrypt)
/// - The commitment (verified against plaintext data)
/// - Plaintext audit data (recipient address, amount)
/// - Public seed for deterministic rho/r verification
#[derive(Clone, Debug, Encode, Decode, TypeInfo, PartialEq, Eq)]
pub struct ShieldedCoinbaseInherentData {
    /// The coinbase note data
    pub note_data: CoinbaseNoteData,
}

impl ShieldedCoinbaseInherentData {
    /// Create new shielded coinbase inherent data
    pub fn new(
        commitment: Commitment,
        encrypted_note: EncryptedNote,
        recipient_address: [u8; DIVERSIFIED_ADDRESS_SIZE],
        amount: u64,
        public_seed: [u8; 32],
    ) -> Self {
        Self {
            note_data: CoinbaseNoteData {
                commitment,
                encrypted_note,
                recipient_address,
                amount,
                public_seed,
            },
        }
    }

    /// Create from a CoinbaseNoteData
    pub fn from_note_data(note_data: CoinbaseNoteData) -> Self {
        Self { note_data }
    }
}

/// Client-side inherent data provider for shielded coinbase rewards
///
/// Mining nodes create this provider with their encrypted coinbase note
/// and the public audit data. It's then registered with the block builder's
/// inherent data providers.
#[cfg(feature = "std")]
pub struct ShieldedCoinbaseInherentDataProvider {
    /// The coinbase note data
    note_data: CoinbaseNoteData,
}

#[cfg(feature = "std")]
impl ShieldedCoinbaseInherentDataProvider {
    /// Create a new shielded coinbase inherent data provider
    pub fn new(
        commitment: Commitment,
        encrypted_note: EncryptedNote,
        recipient_address: [u8; DIVERSIFIED_ADDRESS_SIZE],
        amount: u64,
        public_seed: [u8; 32],
    ) -> Self {
        Self {
            note_data: CoinbaseNoteData {
                commitment,
                encrypted_note,
                recipient_address,
                amount,
                public_seed,
            },
        }
    }

    /// Create from a CoinbaseNoteData
    pub fn from_note_data(note_data: CoinbaseNoteData) -> Self {
        Self { note_data }
    }
}

#[cfg(feature = "std")]
#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for ShieldedCoinbaseInherentDataProvider {
    async fn provide_inherent_data(
        &self,
        inherent_data: &mut InherentData,
    ) -> Result<(), sp_inherents::Error> {
        let data = ShieldedCoinbaseInherentData {
            note_data: self.note_data.clone(),
        };
        inherent_data.put_data(SHIELDED_COINBASE_INHERENT_IDENTIFIER, &data)
    }

    async fn try_handle_error(
        &self,
        identifier: &InherentIdentifier,
        _error: &[u8],
    ) -> Option<Result<(), sp_inherents::Error>> {
        if identifier == &SHIELDED_COINBASE_INHERENT_IDENTIFIER {
            // Log the error but don't fail block production
            log::warn!(target: "shielded-pool", "Shielded coinbase inherent error occurred");
            Some(Ok(()))
        } else {
            None
        }
    }
}

// Re-export for external use
pub use sp_std;
