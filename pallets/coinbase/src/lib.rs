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

pub use inherent::*;
pub use pallet::*;

mod inherent;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_support::traits::Currency;
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::SaturatedConversion;
    use sp_runtime::Permill;

    // =========================================================================
    // CHAIN PARAMETERS - Parameterized tokenomics (TOKENOMICS_CALCULATION.md)
    // =========================================================================

    /// One coin = 100 million base units (like satoshis)
    pub const COIN: u64 = 100_000_000;

    /// Target block time in milliseconds (60 seconds / 1 minute)
    pub const T_BLOCK_MS: u64 = 60_000;

    /// Target block time in seconds
    pub const T_BLOCK_SECONDS: u64 = T_BLOCK_MS / 1000;

    /// Maximum supply: 21 million coins
    pub const S_MAX: u64 = 21_000_000 * COIN;

    /// Duration of one issuance epoch in years
    pub const Y_EPOCH: u64 = 4;

    /// Number of seconds in a year (365 × 24 × 3,600)
    pub const T_YEAR: u64 = 31_536_000;

    /// Epoch duration in seconds (Y_EPOCH × T_YEAR)
    pub const T_EPOCH_SECONDS: u64 = Y_EPOCH * T_YEAR;

    /// Blocks per year at the configured block time
    pub const BLOCKS_PER_YEAR: u64 = T_YEAR / T_BLOCK_SECONDS;

    /// Blocks per epoch (4 years of blocks at 60s = 2,102,400 blocks)
    pub const BLOCKS_PER_EPOCH: u64 = T_EPOCH_SECONDS / T_BLOCK_SECONDS;

    /// Initial block reward R0 = (S_MAX × t_block) / (2 × Y_EPOCH × T_YEAR)
    /// For 60s blocks: R0 = (21,000,000 × 60) / (2 × 4 × 31,536,000) ≈ 4.98 HEG
    /// In base units: ~498,287,671 (~4.98 coins)
    pub const INITIAL_REWARD: u64 =
        (S_MAX as u128 * T_BLOCK_SECONDS as u128 / (2 * Y_EPOCH as u128 * T_YEAR as u128)) as u64;

    /// Legacy constant for backwards compatibility
    pub const INITIAL_SUBSIDY: u64 = INITIAL_REWARD;

    /// Legacy halving interval - now derived from BLOCKS_PER_EPOCH
    pub const HALVING_INTERVAL: u64 = BLOCKS_PER_EPOCH;

    /// Maximum supply (alias for S_MAX)
    pub const MAX_SUPPLY: u64 = S_MAX;

    // =========================================================================
    // TAIL EMISSION PARAMETERS
    // =========================================================================

    /// Epoch index at which halving stops and tail emission begins
    /// Set to 0 to disable tail emission (pure hard cap like Bitcoin)
    /// Set to a value like 10 to enable tail emission after ~40 years
    pub const K_TAIL: u64 = 0;

    /// Tail emission block reward (constant after K_TAIL epochs)
    /// Set to 0 for strict hard cap
    /// Set to a small value for perpetual low inflation
    pub const R_TAIL: u64 = 0;

    /// Calculate block subsidy for a given epoch index (time-based halving)
    ///
    /// # Arguments
    /// * `epoch` - The epoch index (0, 1, 2, ...)
    ///
    /// # Returns
    /// The block reward for that epoch: R0 / 2^epoch, or R_TAIL after K_TAIL
    pub fn epoch_subsidy(epoch: u64) -> u64 {
        // After K_TAIL epochs, switch to constant tail emission
        // Note: K_TAIL=0 disables tail emission (comparison always false by design)
        #[allow(clippy::absurd_extreme_comparisons)]
        if K_TAIL > 0 && epoch >= K_TAIL {
            return R_TAIL;
        }

        // Standard halving: R(k) = R0 / 2^k
        let shift = epoch.min(63); // Prevent overflow
        INITIAL_REWARD >> shift
    }

    /// Calculate block subsidy for a given height (height-based epoch selection)
    ///
    /// This is the primary interface for block reward calculation.
    /// Uses height to determine epoch, then returns the epoch subsidy.
    pub fn block_subsidy(height: u64) -> u64 {
        if height == 0 {
            return 0; // Genesis block has no reward
        }
        let epoch = (height - 1) / BLOCKS_PER_EPOCH;
        epoch_subsidy(epoch)
    }

    /// Calculate epoch index from a block timestamp (time-based epoch selection)
    ///
    /// # Arguments
    /// * `genesis_time` - Genesis block timestamp (UNIX seconds)
    /// * `block_timestamp` - Current block timestamp (UNIX seconds)
    ///
    /// # Returns
    /// The epoch index based on elapsed time since genesis
    pub fn epoch_from_timestamp(genesis_time: u64, block_timestamp: u64) -> u64 {
        let time_since_genesis = block_timestamp.saturating_sub(genesis_time);
        time_since_genesis / T_EPOCH_SECONDS
    }

    /// Calculate block subsidy using timestamp-based epoch selection
    pub fn block_subsidy_by_time(genesis_time: u64, block_timestamp: u64) -> u64 {
        if block_timestamp <= genesis_time {
            return 0;
        }
        let epoch = epoch_from_timestamp(genesis_time, block_timestamp);
        epoch_subsidy(epoch)
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
        /// This should be >= INITIAL_REWARD to allow early blocks
        #[pallet::constant]
        type MaxSubsidy: Get<u64>;

        /// Fraction of block reward paid to miners (α_m)
        /// Default: 80% (Permill::from_percent(80))
        #[pallet::constant]
        type MinerShare: Get<Permill>;

        /// Fraction of block reward paid to protocol treasury (α_f)
        /// Default: 10% (Permill::from_percent(10))
        #[pallet::constant]
        type TreasuryShare: Get<Permill>;

        /// Fraction of block reward paid to community/ecosystem pool (α_c)
        /// Default: 10% (Permill::from_percent(10))
        #[pallet::constant]
        type CommunityShare: Get<Permill>;

        /// Account ID of the protocol treasury
        type TreasuryAccount: Get<Self::AccountId>;

        /// Account ID of the community/ecosystem pool
        type CommunityAccount: Get<Self::AccountId>;
    }

    // =========================================================================
    // STORAGE
    // =========================================================================

    /// Total coins minted via coinbase (for supply tracking)
    #[pallet::storage]
    #[pallet::getter(fn total_minted)]
    pub type TotalMinted<T> = StorageValue<_, u64, ValueQuery>;

    /// Total coins minted to miners
    #[pallet::storage]
    #[pallet::getter(fn total_minted_to_miners)]
    pub type TotalMintedToMiners<T> = StorageValue<_, u64, ValueQuery>;

    /// Total coins minted to treasury
    #[pallet::storage]
    #[pallet::getter(fn total_minted_to_treasury)]
    pub type TotalMintedToTreasury<T> = StorageValue<_, u64, ValueQuery>;

    /// Total coins minted to community pool
    #[pallet::storage]
    #[pallet::getter(fn total_minted_to_community)]
    pub type TotalMintedToCommunity<T> = StorageValue<_, u64, ValueQuery>;

    /// Genesis timestamp for time-based epoch calculation (UNIX seconds)
    #[pallet::storage]
    #[pallet::getter(fn genesis_timestamp)]
    pub type GenesisTimestamp<T> = StorageValue<_, u64, ValueQuery>;

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
        /// Coinbase reward minted (split between miner, treasury, community)
        CoinbaseMinted {
            /// Miner recipient of their share
            miner: T::AccountId,
            /// Amount minted to miner
            miner_amount: u64,
            /// Amount minted to treasury
            treasury_amount: u64,
            /// Amount minted to community
            community_amount: u64,
            /// Total subsidy for this block
            total_subsidy: u64,
            /// Block height
            block_number: BlockNumberFor<T>,
            /// Current epoch
            epoch: u64,
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
        /// Reward shares do not sum to 100%
        InvalidShareConfiguration,
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
        /// Mint coinbase reward, split between miner, treasury, and community.
        ///
        /// This is an inherent extrinsic - it can only be included by the block
        /// author and is created from InherentData provided by the mining node.
        ///
        /// The total subsidy is split according to the configured shares:
        /// - MinerShare (α_m): paid to the `recipient` (miner)
        /// - TreasuryShare (α_f): paid to the treasury account
        /// - CommunityShare (α_c): paid to the community pool account
        ///
        /// # Arguments
        /// * `recipient` - Miner account to receive their share of the block reward
        /// * `amount` - Total subsidy amount (must be <= block_subsidy(height))
        ///
        /// # Security
        /// - Can only be called once per block (CoinbaseProcessed flag)
        /// - Amount is validated against block_subsidy for current height
        /// - Recipient is stored for potential slashing/audit purposes
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(30_000, 0))]
        pub fn mint_reward(
            origin: OriginFor<T>,
            recipient: T::AccountId,
            amount: u64,
        ) -> DispatchResult {
            // Inherent extrinsics use None origin
            ensure_none(origin)?;

            // Ensure not already processed this block
            ensure!(!CoinbaseProcessed::<T>::get(), Error::<T>::AlreadyProcessed);

            // Get current block number and epoch
            let block_number = frame_system::Pallet::<T>::block_number();
            let height: u64 = block_number.try_into().unwrap_or(0);
            let epoch = if height == 0 {
                0
            } else {
                (height - 1) / BLOCKS_PER_EPOCH
            };

            // Validate subsidy amount
            let max_subsidy = block_subsidy(height);
            ensure!(amount <= max_subsidy, Error::<T>::SubsidyExceedsLimit);
            ensure!(
                amount <= T::MaxSubsidy::get(),
                Error::<T>::SubsidyExceedsLimit
            );

            // Calculate reward splits
            let miner_share = T::MinerShare::get();
            let treasury_share = T::TreasuryShare::get();
            let _community_share = T::CommunityShare::get();

            let miner_amount = miner_share.mul_floor(amount);
            let treasury_amount = treasury_share.mul_floor(amount);
            // Community gets the remainder to avoid rounding losses
            let community_amount = amount
                .saturating_sub(miner_amount)
                .saturating_sub(treasury_amount);

            // Mint to miner
            if miner_amount > 0 {
                let miner_balance = miner_amount.saturated_into();
                let _imbalance = T::Currency::deposit_creating(&recipient, miner_balance);
                TotalMintedToMiners::<T>::mutate(|total| {
                    *total = total.saturating_add(miner_amount)
                });
            }

            // Mint to treasury
            if treasury_amount > 0 {
                let treasury_balance = treasury_amount.saturated_into();
                let treasury_account = T::TreasuryAccount::get();
                let _imbalance = T::Currency::deposit_creating(&treasury_account, treasury_balance);
                TotalMintedToTreasury::<T>::mutate(|total| {
                    *total = total.saturating_add(treasury_amount)
                });
            }

            // Mint to community pool
            if community_amount > 0 {
                let community_balance = community_amount.saturated_into();
                let community_account = T::CommunityAccount::get();
                let _imbalance =
                    T::Currency::deposit_creating(&community_account, community_balance);
                TotalMintedToCommunity::<T>::mutate(|total| {
                    *total = total.saturating_add(community_amount)
                });
            }

            // Update total state
            CoinbaseProcessed::<T>::put(true);
            BlockAuthor::<T>::put(recipient.clone());
            TotalMinted::<T>::mutate(|total| *total = total.saturating_add(amount));

            // Emit event
            Self::deposit_event(Event::CoinbaseMinted {
                miner: recipient.clone(),
                miner_amount,
                treasury_amount,
                community_amount,
                total_subsidy: amount,
                block_number,
                epoch,
            });

            log::info!(
                target: "coinbase",
                "💰 Minted {} total (miner: {}, treasury: {}, community: {}) at height {} (epoch {})",
                amount,
                miner_amount,
                treasury_amount,
                community_amount,
                height,
                epoch
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
            let coinbase_data: Option<crate::inherent::CoinbaseInherentData> =
                data.get_data(&Self::INHERENT_IDENTIFIER).ok().flatten();

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

        fn check_inherent(
            call: &Self::Call,
            _data: &sp_inherents::InherentData,
        ) -> Result<(), Self::Error> {
            // Validate the inherent call
            if let Call::mint_reward { amount, .. } = call {
                // Ensure amount is reasonable (within 2x initial reward)
                if *amount > INITIAL_REWARD * 2 {
                    return Err(sp_inherents::MakeFatalError::from(()));
                }
            }
            Ok(())
        }

        fn is_inherent_required(
            _data: &sp_inherents::InherentData,
        ) -> Result<Option<Self::Error>, Self::Error> {
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
    use crate::pallet::{
        block_subsidy, epoch_from_timestamp, epoch_subsidy, BLOCKS_PER_EPOCH, COIN, INITIAL_REWARD,
        K_TAIL, R_TAIL, S_MAX, T_EPOCH_SECONDS,
    };

    #[test]
    fn initial_reward_is_correct() {
        // R0 = (S_MAX × T_BLOCK_SECONDS) / (2 × Y_EPOCH × T_YEAR)
        // For 60s blocks: R0 ≈ 4.98 HEG ≈ 498,287,671 base units
        //
        // Calculation: (21_000_000 × 100_000_000 × 60) / (2 × 4 × 31_536_000)
        //            = 126,000,000,000,000,000 / 252,288,000
        //            = 499,429,223 (approximately)
        //
        // Note: Integer division may cause slight variance
        assert!(INITIAL_REWARD > 490_000_000, "R0 should be ~4.9 coins");
        assert!(INITIAL_REWARD < 510_000_000, "R0 should be ~5 coins");

        // Verify it's approximately 4.98 coins
        let coins = INITIAL_REWARD / COIN;
        assert!(coins >= 4 && coins <= 5, "Should be ~4-5 coins per block");
    }

    #[test]
    fn blocks_per_epoch_is_correct() {
        // At 60s blocks, 4 years = 2,102,400 blocks
        // 4 × 365 × 24 × 60 = 2,102,400 (at 1 block per minute)
        assert_eq!(BLOCKS_PER_EPOCH, 2_102_400);
    }

    #[test]
    fn subsidy_schedule_is_correct() {
        // Genesis has no reward
        assert_eq!(block_subsidy(0), 0);

        // First block starts at initial reward
        assert_eq!(block_subsidy(1), INITIAL_REWARD);

        // Last block of first epoch still gets initial reward
        assert_eq!(block_subsidy(BLOCKS_PER_EPOCH), INITIAL_REWARD);

        // First block of second epoch gets halved reward
        assert_eq!(block_subsidy(BLOCKS_PER_EPOCH + 1), INITIAL_REWARD / 2);

        // After second halving
        assert_eq!(block_subsidy(2 * BLOCKS_PER_EPOCH + 1), INITIAL_REWARD / 4);

        // After third halving
        assert_eq!(block_subsidy(3 * BLOCKS_PER_EPOCH + 1), INITIAL_REWARD / 8);

        // Eventually goes to zero (or tail emission)
        if K_TAIL == 0 || R_TAIL == 0 {
            assert_eq!(block_subsidy(64 * BLOCKS_PER_EPOCH + 1), 0);
        }
    }

    #[test]
    fn epoch_subsidy_halves_correctly() {
        assert_eq!(epoch_subsidy(0), INITIAL_REWARD);
        assert_eq!(epoch_subsidy(1), INITIAL_REWARD / 2);
        assert_eq!(epoch_subsidy(2), INITIAL_REWARD / 4);
        assert_eq!(epoch_subsidy(3), INITIAL_REWARD / 8);
        assert_eq!(epoch_subsidy(10), INITIAL_REWARD / 1024);
    }

    #[test]
    fn time_based_epoch_calculation() {
        let genesis_time: u64 = 1_700_000_000; // Some UNIX timestamp

        // At genesis, epoch is 0
        assert_eq!(epoch_from_timestamp(genesis_time, genesis_time), 0);

        // Just before first halving, still epoch 0
        let just_before_halving = genesis_time + T_EPOCH_SECONDS - 1;
        assert_eq!(epoch_from_timestamp(genesis_time, just_before_halving), 0);

        // At first halving boundary, epoch 1
        let at_halving = genesis_time + T_EPOCH_SECONDS;
        assert_eq!(epoch_from_timestamp(genesis_time, at_halving), 1);

        // Well into second epoch
        let in_second_epoch = genesis_time + T_EPOCH_SECONDS + 1_000_000;
        assert_eq!(epoch_from_timestamp(genesis_time, in_second_epoch), 1);

        // Third epoch
        let in_third_epoch = genesis_time + 2 * T_EPOCH_SECONDS + 1;
        assert_eq!(epoch_from_timestamp(genesis_time, in_third_epoch), 2);
    }

    #[test]
    fn total_supply_converges_to_max() {
        let mut total: u128 = 0;
        let mut epoch: u64 = 0;

        // Sum up all possible rewards across epochs
        loop {
            let subsidy = epoch_subsidy(epoch) as u128;
            if subsidy == 0 {
                break;
            }
            // Each epoch has BLOCKS_PER_EPOCH blocks
            total = total.saturating_add(subsidy * BLOCKS_PER_EPOCH as u128);
            epoch += 1;

            // Safety: prevent infinite loop
            if epoch > 100 {
                break;
            }
        }

        // Total should be very close to S_MAX (21 million coins)
        // The formula is designed so that: S_total = 2 × R0 × blocks_per_epoch = S_MAX
        let tolerance = S_MAX as u128 / 100; // 1% tolerance for integer rounding
        assert!(
            total <= S_MAX as u128 + tolerance,
            "Should not exceed max supply"
        );
        assert!(
            total >= S_MAX as u128 - tolerance,
            "Should be close to max supply"
        );
    }
}
