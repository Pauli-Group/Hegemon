//! Coinbase Pallet
//!
//! Implements Bitcoin-style mining rewards via Substrate's inherent mechanism.
//!
//! # Overview
//!
//! In Bitcoin, each block contains a coinbase transaction that:
//! 1. Has no inputs (creates new coins from nothing)
//! 2. Pays to an address chosen by the miner
//! 3. Amount is limited to block_subsidy + transaction fees
//! 4. Is committed to via the merkle root in the block header
//! 5. Is covered by the PoW hash
//!
//! In Substrate, we achieve the same with an inherent extrinsic:
//! 1. Mining node provides coinbase recipient via InherentDataProvider
//! 2. Runtime's create_inherent() produces the mint_reward extrinsic
//! 3. Extrinsic is included in block body (covered by extrinsics_root)
//! 4. Block header (including extrinsics_root) is covered by PoW hash
//! 5. Runtime executes the inherent, minting coins to the recipient
//!
//! # Security Model
//!
//! - Only ONE coinbase inherent per block (enforced by is_inherent_required)
//! - Amount is validated against block_subsidy(height)
//! - Recipient is committed to in block data before PoW
//! - Changing recipient invalidates the PoW seal
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Block Production Flow                        │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  Miner Node                    Runtime                          │
//! │  ──────────                    ───────                          │
//! │                                                                 │
//! │  1. CoinbaseInherentData  ───► create_inherent()               │
//! │     { recipient, amount }           │                           │
//! │                                     ▼                           │
//! │                              Call::mint_reward                  │
//! │                              { recipient, amount }              │
//! │                                     │                           │
//! │  2. Build block with               │                           │
//! │     inherent in body               ▼                           │
//! │           │                  apply_extrinsic()                 │
//! │           │                        │                           │
//! │           ▼                        ▼                           │
//! │  3. Mine PoW seal ◄────── extrinsics_root in header            │
//! │           │                                                     │
//! │           ▼                                                     │
//! │  4. Broadcast block                                            │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;
pub use inherent::*;

mod inherent;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_support::traits::Currency;
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::SaturatedConversion;

    // =========================================================================
    // CHAIN PARAMETERS - Bitcoin-style halving schedule
    // =========================================================================

    /// One coin = 100 million base units (like satoshis)
    pub const COIN: u64 = 100_000_000;

    /// Initial block subsidy: 50 coins
    pub const INITIAL_SUBSIDY: u64 = 50 * COIN;

    /// Halving interval: every 210,000 blocks (~4 years at 10 min blocks)
    /// At 5 second blocks: 210,000 blocks = ~12 days
    /// For mainnet, consider 4,200,000 blocks for ~8 months between halvings
    pub const HALVING_INTERVAL: u64 = 210_000;

    /// Maximum supply: 21 million coins
    pub const MAX_SUPPLY: u64 = 21_000_000 * COIN;

    /// Calculate block subsidy for a given height (Bitcoin-style halving)
    pub fn block_subsidy(height: u64) -> u64 {
        if height == 0 {
            return 0; // Genesis block has no reward
        }
        let halvings = (height - 1) / HALVING_INTERVAL;
        let shift = halvings.min(63); // Prevent overflow
        INITIAL_SUBSIDY >> shift
    }

    // =========================================================================
    // PALLET DEFINITION
    // =========================================================================

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        /// Currency type for minting rewards
        type Currency: Currency<Self::AccountId>;

        /// Maximum allowed subsidy per block (safety limit)
        /// This should be >= INITIAL_SUBSIDY to allow early blocks
        #[pallet::constant]
        type MaxSubsidy: Get<u64>;
    }

    // =========================================================================
    // STORAGE
    // =========================================================================

    /// Total coins minted via coinbase (for supply tracking)
    #[pallet::storage]
    #[pallet::getter(fn total_minted)]
    pub type TotalMinted<T> = StorageValue<_, u64, ValueQuery>;

    /// Block author for the current block (set by inherent, used by on_finalize if needed)
    #[pallet::storage]
    #[pallet::getter(fn block_author)]
    pub type BlockAuthor<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

    /// Whether coinbase was already processed this block (prevents double-mint)
    #[pallet::storage]
    pub type CoinbaseProcessed<T> = StorageValue<_, bool, ValueQuery>;

    // =========================================================================
    // EVENTS
    // =========================================================================

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Coinbase reward minted to miner
        CoinbaseMinted {
            /// Recipient of the reward
            recipient: T::AccountId,
            /// Amount minted
            amount: u64,
            /// Block height
            block_number: BlockNumberFor<T>,
        },
    }

    // =========================================================================
    // ERRORS
    // =========================================================================

    #[pallet::error]
    pub enum Error<T> {
        /// Coinbase already processed for this block
        AlreadyProcessed,
        /// Subsidy amount exceeds allowed maximum for this height
        SubsidyExceedsLimit,
        /// Invalid recipient (zero address)
        InvalidRecipient,
    }

    // =========================================================================
    // HOOKS
    // =========================================================================

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            // Reset processed flag at start of each block
            CoinbaseProcessed::<T>::kill();
            BlockAuthor::<T>::kill();
            Weight::from_parts(1_000, 0)
        }
    }

    // =========================================================================
    // CALLS (Extrinsics)
    // =========================================================================

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Mint coinbase reward to the block author.
        ///
        /// This is an inherent extrinsic - it can only be included by the block
        /// author and is created from InherentData provided by the mining node.
        ///
        /// # Arguments
        /// * `recipient` - Account to receive the block reward
        /// * `amount` - Amount to mint (must be <= block_subsidy(height))
        ///
        /// # Security
        /// - Can only be called once per block (CoinbaseProcessed flag)
        /// - Amount is validated against block_subsidy for current height
        /// - Recipient is stored for potential slashing/audit purposes
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn mint_reward(
            origin: OriginFor<T>,
            recipient: T::AccountId,
            amount: u64,
        ) -> DispatchResult {
            // Inherent extrinsics use None origin
            ensure_none(origin)?;

            // Ensure not already processed this block
            ensure!(!CoinbaseProcessed::<T>::get(), Error::<T>::AlreadyProcessed);

            // Get current block number
            let block_number = frame_system::Pallet::<T>::block_number();
            let height: u64 = block_number.try_into().unwrap_or(0);

            // Validate subsidy amount
            let max_subsidy = block_subsidy(height);
            ensure!(amount <= max_subsidy, Error::<T>::SubsidyExceedsLimit);
            ensure!(amount <= T::MaxSubsidy::get(), Error::<T>::SubsidyExceedsLimit);

            // Mint the reward
            // Convert u64 to Balance type using saturated conversion
            let amount_balance = amount.saturated_into();
            let _imbalance = T::Currency::deposit_creating(&recipient, amount_balance);

            // Update state
            CoinbaseProcessed::<T>::put(true);
            BlockAuthor::<T>::put(recipient.clone());
            TotalMinted::<T>::mutate(|total| *total = total.saturating_add(amount));

            // Emit event
            Self::deposit_event(Event::CoinbaseMinted {
                recipient,
                amount,
                block_number,
            });

            log::info!(
                target: "coinbase",
                "💰 Minted {} to block author at height {}",
                amount,
                height
            );

            Ok(())
        }
    }

    // =========================================================================
    // INHERENT PROVIDER IMPLEMENTATION
    // =========================================================================

    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        type Call = Call<T>;
        type Error = sp_inherents::MakeFatalError<()>;
        const INHERENT_IDENTIFIER: [u8; 8] = *b"coinbase";

        fn create_inherent(data: &sp_inherents::InherentData) -> Option<Self::Call> {
            // Extract coinbase data from inherent data
            let coinbase_data: Option<crate::inherent::CoinbaseInherentData> = data
                .get_data(&Self::INHERENT_IDENTIFIER)
                .ok()
                .flatten();

            coinbase_data.map(|cb| {
                // Decode recipient from bytes
                let recipient = T::AccountId::decode(&mut &cb.recipient[..])
                    .expect("Invalid recipient encoding in coinbase inherent");
                
                Call::mint_reward {
                    recipient,
                    amount: cb.amount,
                }
            })
        }

        fn is_inherent(call: &Self::Call) -> bool {
            matches!(call, Call::mint_reward { .. })
        }

        fn check_inherent(call: &Self::Call, _data: &sp_inherents::InherentData) -> Result<(), Self::Error> {
            // Validate the inherent call
            if let Call::mint_reward { amount, .. } = call {
                // We could add additional validation here
                // For now, just ensure amount is reasonable
                if *amount > INITIAL_SUBSIDY * 2 {
                    return Err(sp_inherents::MakeFatalError::from(()));
                }
            }
            Ok(())
        }

        fn is_inherent_required(_data: &sp_inherents::InherentData) -> Result<Option<Self::Error>, Self::Error> {
            // Coinbase is NOT strictly required - blocks without rewards are valid
            // (though economically pointless for miners)
            // This allows for flexibility in testing and edge cases
            Ok(None)
        }
    }
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pallet::{block_subsidy, COIN, HALVING_INTERVAL, INITIAL_SUBSIDY};

    #[test]
    fn subsidy_schedule_is_correct() {
        // Genesis has no reward
        assert_eq!(block_subsidy(0), 0);
        
        // First block through first halving
        assert_eq!(block_subsidy(1), INITIAL_SUBSIDY);
        assert_eq!(block_subsidy(1), 50 * COIN);
        assert_eq!(block_subsidy(HALVING_INTERVAL), INITIAL_SUBSIDY);
        
        // After first halving
        assert_eq!(block_subsidy(HALVING_INTERVAL + 1), INITIAL_SUBSIDY / 2);
        assert_eq!(block_subsidy(HALVING_INTERVAL + 1), 25 * COIN);
        
        // After second halving
        assert_eq!(block_subsidy(2 * HALVING_INTERVAL + 1), INITIAL_SUBSIDY / 4);
        assert_eq!(block_subsidy(2 * HALVING_INTERVAL + 1), 12_50000000); // 12.5 COIN
        
        // After third halving
        assert_eq!(block_subsidy(3 * HALVING_INTERVAL + 1), INITIAL_SUBSIDY / 8);
        
        // Eventually goes to zero
        assert_eq!(block_subsidy(64 * HALVING_INTERVAL + 1), 0);
    }

    #[test]
    fn total_supply_converges_to_max() {
        let mut total: u64 = 0;
        let mut height: u64 = 1;
        
        // Sum up all possible rewards
        loop {
            let subsidy = block_subsidy(height);
            if subsidy == 0 {
                break;
            }
            // Approximate: assume all blocks in each epoch pay full subsidy
            let blocks_in_epoch = if height == 1 { HALVING_INTERVAL } else { HALVING_INTERVAL };
            total = total.saturating_add(subsidy.saturating_mul(blocks_in_epoch));
            height += HALVING_INTERVAL;
        }
        
        // Total should be close to 21 million coins
        // (Slightly less due to integer division in halving)
        assert!(total <= 21_000_000 * COIN);
        assert!(total >= 20_000_000 * COIN); // At least 20 million
    }
}
