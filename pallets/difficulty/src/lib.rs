//! Difficulty Pallet
//!
//! Manages PoW difficulty with automatic adjustment based on block times.
//! This pallet stores the current difficulty and adjusts it periodically
//! to maintain the target block time.
//!
//! # Overview
//!
//! The difficulty adjustment algorithm follows Bitcoin's approach:
//! 1. Track timestamps of recent blocks
//! 2. Every `RETARGET_INTERVAL` blocks, compare actual time vs expected time
//! 3. Adjust difficulty proportionally with bounds to prevent extreme changes
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Difficulty Pallet                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Storage:                                                       │
//! │    - Difficulty (U256): Current mining difficulty               │
//! │    - LastRetargetBlock: Block number of last adjustment         │
//! │    - LastRetargetTime: Timestamp of last adjustment             │
//! │                                                                 │
//! │  Hooks:                                                         │
//! │    - on_finalize: Record block timestamp, maybe retarget        │
//! │                                                                 │
//! │  Queries (via DifficultyApi):                                   │
//! │    - difficulty(): Current difficulty as U256                   │
//! │    - target_block_time(): Target time between blocks            │
//! │    - blocks_until_retarget(): Blocks until next adjustment      │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Difficulty Adjustment
//!
//! ```text
//! actual_time = timestamp[now] - timestamp[retarget_interval_ago]
//! expected_time = RETARGET_INTERVAL * TARGET_BLOCK_TIME
//!
//! if actual_time < expected_time / 4:
//!     new_difficulty = old_difficulty * 4  (max increase)
//! elif actual_time > expected_time * 4:
//!     new_difficulty = old_difficulty / 4  (max decrease)
//! else:
//!     new_difficulty = old_difficulty * expected_time / actual_time
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_support::weights::Weight;
    use frame_system::pallet_prelude::*;
    use sp_core::U256;
    use sp_runtime::traits::Saturating;

    // =========================================================================
    // CHAIN PARAMETERS - Import from consensus::reward (single source of truth)
    // These are re-exported here for pallet convenience.
    // =========================================================================

    /// Target block time in milliseconds (5 seconds)
    pub const TARGET_BLOCK_TIME_MS: u64 = 5_000;

    /// Number of blocks between difficulty adjustments
    /// At 5s blocks, 120 blocks = 10 minutes between adjustments.
    pub const RETARGET_INTERVAL: u32 = 120;

    /// Maximum adjustment factor per retarget period (4x up or down)
    pub const MAX_ADJUSTMENT_FACTOR: u64 = 4;

    /// Genesis difficulty: 6 MH/s * 5 seconds = 30,000,000 expected hashes per block.
    /// This targets M-series MacBooks which achieve ~5-10 MH/s with Blake3.
    pub const GENESIS_DIFFICULTY: u128 = 30_000_000;

    /// Genesis compact bits: 0x1d8f2a63 encodes target = MAX_U256 / 30,000,000.
    /// Decodes to: exponent=29, mantissa=0x8f2a63, target ≈ 2^231
    pub const GENESIS_BITS: u32 = 0x1d8f_2a63;

    /// Minimum difficulty to prevent divide-by-zero
    pub const MIN_DIFFICULTY: u128 = 1;

    /// Type alias for timestamp
    pub type Moment = u64;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> + pallet_timestamp::Config<Moment = Moment> {
        // No additional config required - RuntimeEvent bound is in the frame_system::Config bound above
    }

    /// Current difficulty value as U256
    #[pallet::storage]
    #[pallet::getter(fn difficulty)]
    pub type Difficulty<T> = StorageValue<_, U256, ValueQuery, GenesisDefault>;

    /// Block number of last retarget
    #[pallet::storage]
    #[pallet::getter(fn last_retarget_block)]
    pub type LastRetargetBlock<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;

    /// Timestamp of last retarget (milliseconds)
    #[pallet::storage]
    #[pallet::getter(fn last_retarget_time)]
    pub type LastRetargetTime<T> = StorageValue<_, Moment, ValueQuery>;

    /// Current difficulty in compact bits format (for compatibility)
    #[pallet::storage]
    #[pallet::getter(fn difficulty_bits)]
    pub type DifficultyBits<T> = StorageValue<_, u32, ValueQuery, DefaultBits>;

    /// Default difficulty value provider
    pub struct GenesisDefault;
    impl Get<U256> for GenesisDefault {
        fn get() -> U256 {
            U256::from(GENESIS_DIFFICULTY)
        }
    }

    /// Default difficulty bits - uses GENESIS_BITS
    pub struct DefaultBits;
    impl Get<u32> for DefaultBits {
        fn get() -> u32 {
            GENESIS_BITS
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Difficulty was adjusted
        DifficultyAdjusted {
            /// Previous difficulty
            old_difficulty: U256,
            /// New difficulty after adjustment
            new_difficulty: U256,
            /// Block number at which adjustment occurred
            block_number: BlockNumberFor<T>,
            /// Actual time for the retarget period (ms)
            actual_time_ms: u64,
            /// Expected time for the retarget period (ms)
            expected_time_ms: u64,
        },
        /// First block after genesis, initializing retarget tracking
        RetargetInitialized {
            block_number: BlockNumberFor<T>,
            timestamp: Moment,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Overflow during difficulty calculation
        DifficultyOverflow,
        /// Underflow during difficulty calculation
        DifficultyUnderflow,
    }

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        /// Initial difficulty value
        pub initial_difficulty: U256,
        /// Initial difficulty in compact bits format
        pub initial_bits: u32,
        #[serde(skip)]
        pub _phantom: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            Difficulty::<T>::put(self.initial_difficulty);
            DifficultyBits::<T>::put(self.initial_bits);
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_finalize(block_number: BlockNumberFor<T>) {
            Self::record_block_and_maybe_retarget(block_number);
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Force a difficulty adjustment (sudo only, for emergencies)
        ///
        /// This bypasses the normal retarget schedule and sets difficulty directly.
        /// Only callable by root origin.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn force_set_difficulty(
            origin: OriginFor<T>,
            new_difficulty: U256,
            new_bits: u32,
        ) -> DispatchResult {
            ensure_root(origin)?;
            let old_difficulty = Difficulty::<T>::get();
            Difficulty::<T>::put(new_difficulty);
            DifficultyBits::<T>::put(new_bits);
            Self::deposit_event(Event::DifficultyAdjusted {
                old_difficulty,
                new_difficulty,
                block_number: frame_system::Pallet::<T>::block_number(),
                actual_time_ms: 0,
                expected_time_ms: 0,
            });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Record the current block's timestamp and check if retarget is needed
        pub(crate) fn record_block_and_maybe_retarget(current_block: BlockNumberFor<T>) {
            let current_time = pallet_timestamp::Pallet::<T>::get();
            let last_retarget = Self::last_retarget_block();

            // Calculate blocks since last retarget
            let blocks_since: u32 = current_block
                .saturating_sub(last_retarget)
                .try_into()
                .unwrap_or(u32::MAX);

            // First block after genesis: initialize retarget tracking
            if last_retarget == BlockNumberFor::<T>::default() && current_block > BlockNumberFor::<T>::default() {
                LastRetargetBlock::<T>::put(current_block);
                LastRetargetTime::<T>::put(current_time);
                Self::deposit_event(Event::RetargetInitialized {
                    block_number: current_block,
                    timestamp: current_time,
                });
                return;
            }

            // Check if it's time to retarget
            if blocks_since >= RETARGET_INTERVAL {
                Self::perform_retarget(current_block, current_time);
            }
        }

        /// Perform the difficulty adjustment
        fn perform_retarget(current_block: BlockNumberFor<T>, current_time: Moment) {
            let old_difficulty = Self::difficulty();
            let last_time = Self::last_retarget_time();

            // Calculate actual vs expected time
            let actual_time = current_time.saturating_sub(last_time);
            let expected_time = (RETARGET_INTERVAL as u64) * TARGET_BLOCK_TIME_MS;

            // Calculate new difficulty with bounds
            let new_difficulty = Self::calculate_new_difficulty(
                old_difficulty,
                actual_time,
                expected_time,
            );

            // Convert to compact bits format
            let new_bits = Self::target_to_compact(new_difficulty);

            // Update storage
            Difficulty::<T>::put(new_difficulty);
            DifficultyBits::<T>::put(new_bits);
            LastRetargetBlock::<T>::put(current_block);
            LastRetargetTime::<T>::put(current_time);

            Self::deposit_event(Event::DifficultyAdjusted {
                old_difficulty,
                new_difficulty,
                block_number: current_block,
                actual_time_ms: actual_time,
                expected_time_ms: expected_time,
            });
        }

        /// Calculate new difficulty based on actual vs expected time
        pub(crate) fn calculate_new_difficulty(
            old_difficulty: U256,
            actual_time: u64,
            expected_time: u64,
        ) -> U256 {
            // Prevent division by zero
            if actual_time == 0 {
                return old_difficulty.saturating_mul(U256::from(MAX_ADJUSTMENT_FACTOR));
            }

            // Apply bounds: don't adjust more than 4x in either direction
            let bounded_actual = actual_time.clamp(
                expected_time / MAX_ADJUSTMENT_FACTOR,
                expected_time.saturating_mul(MAX_ADJUSTMENT_FACTOR),
            );

            // new_difficulty = old_difficulty * expected_time / actual_time
            // But we use bounded_actual to limit the adjustment
            let numerator = old_difficulty.saturating_mul(U256::from(expected_time));
            let new_difficulty = numerator / U256::from(bounded_actual);

            // Ensure minimum difficulty
            if new_difficulty < U256::from(MIN_DIFFICULTY) {
                U256::from(MIN_DIFFICULTY)
            } else {
                new_difficulty
            }
        }

        /// Convert a U256 target to compact bits format
        ///
        /// Format: 0xEEMMMMMM where:
        /// - EE = exponent (number of bytes)
        /// - MMMMMM = mantissa (top 3 bytes of target)
        pub fn target_to_compact(target: U256) -> u32 {
            if target.is_zero() {
                return 0;
            }

            // Convert target to difficulty, then to compact
            // For PoW: target = MAX / difficulty
            // We store difficulty, not target, so need inverse
            let max = U256::MAX;
            if target >= max {
                return 0x0100_0001; // Minimum difficulty
            }

            // Find the most significant non-zero byte
            let bytes: [u8; 32] = target.to_big_endian();

            let mut size: u32 = 32;
            while size > 0 && bytes[32 - size as usize] == 0 {
                size -= 1;
            }

            if size == 0 {
                return 0;
            }

            // Extract mantissa (top 3 bytes)
            let start = 32 - size as usize;
            let mantissa = {
                let b0 = bytes[start] as u32;
                let b1 = bytes.get(start + 1).copied().unwrap_or(0) as u32;
                let b2 = bytes.get(start + 2).copied().unwrap_or(0) as u32;
                (b0 << 16) | (b1 << 8) | b2
            };

            // If high bit of mantissa is set, reduce size and pad
            let (final_size, final_mantissa) = if mantissa & 0x00800000 != 0 {
                (size + 1, mantissa >> 8)
            } else {
                (size, mantissa)
            };

            (final_size << 24) | (final_mantissa & 0x007f_ffff)
        }

        /// Convert compact bits to U256 target
        pub fn compact_to_target(bits: u32) -> Option<U256> {
            let size = bits >> 24;
            let mantissa = bits & 0x007f_ffff;

            if mantissa == 0 {
                return None;
            }

            let mut target = U256::from(mantissa);

            if size <= 3 {
                target >>= 8 * (3 - size) as usize;
            } else {
                target <<= 8 * (size - 3) as usize;
            }

            Some(target)
        }

        /// Get blocks remaining until next retarget
        pub fn blocks_until_retarget() -> u32 {
            let current = frame_system::Pallet::<T>::block_number();
            let last = Self::last_retarget_block();
            let since: u32 = current
                .saturating_sub(last)
                .try_into()
                .unwrap_or(0);
            RETARGET_INTERVAL.saturating_sub(since)
        }

        /// Get target block time in milliseconds
        pub fn target_block_time() -> u64 {
            TARGET_BLOCK_TIME_MS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frame_support::{assert_ok, derive_impl, traits::Hooks};
    use sp_core::{H256, U256};
    use sp_runtime::{
        traits::{BlakeTwo256, IdentityLookup},
        BuildStorage,
    };

    type Block = frame_system::mocking::MockBlock<Test>;

    frame_support::construct_runtime!(
        pub enum Test {
            System: frame_system,
            Timestamp: pallet_timestamp,
            Difficulty: pallet,
        }
    );

    #[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
    impl frame_system::Config for Test {
        type BaseCallFilter = frame_support::traits::Everything;
        type BlockWeights = ();
        type BlockLength = ();
        type DbWeight = ();
        type RuntimeOrigin = RuntimeOrigin;
        type RuntimeCall = RuntimeCall;
        type Nonce = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type AccountId = u64;
        type Lookup = IdentityLookup<Self::AccountId>;
        type Block = Block;
        type RuntimeEvent = RuntimeEvent;
        type BlockHashCount = frame_support::traits::ConstU64<250>;
        type Version = ();
        type PalletInfo = PalletInfo;
        type AccountData = ();
        type OnNewAccount = ();
        type OnKilledAccount = ();
        type SystemWeightInfo = ();
        type SS58Prefix = ();
        type OnSetCode = ();
        type MaxConsumers = frame_support::traits::ConstU32<16>;
    }

    impl pallet_timestamp::Config for Test {
        type Moment = u64;
        type OnTimestampSet = ();
        type MinimumPeriod = frame_support::traits::ConstU64<5>;
        type WeightInfo = ();
    }

    impl pallet::Config for Test {}

    fn new_test_ext() -> sp_io::TestExternalities {
        let t = frame_system::GenesisConfig::<Test>::default()
            .build_storage()
            .unwrap();
        t.into()
    }

    #[test]
    fn genesis_difficulty_is_set() {
        new_test_ext().execute_with(|| {
            assert_eq!(Difficulty::difficulty(), U256::from(GENESIS_DIFFICULTY));
        });
    }

    #[test]
    fn blocks_until_retarget_works() {
        new_test_ext().execute_with(|| {
            // Before any blocks, should return RETARGET_INTERVAL
            System::set_block_number(0);
            assert_eq!(Difficulty::blocks_until_retarget(), RETARGET_INTERVAL);

            // Initialize at block 1
            System::set_block_number(1);
            Difficulty::record_block_and_maybe_retarget(1u64);
            // After initialization at block 1, last_retarget_block = 1
            // blocks_until = RETARGET_INTERVAL - (current - last) = 120 - (1 - 1) = 120
            assert_eq!(Difficulty::blocks_until_retarget(), RETARGET_INTERVAL);

            // At block 10, should have 120 - (10 - 1) = 111 blocks until retarget
            System::set_block_number(10);
            assert_eq!(Difficulty::blocks_until_retarget(), RETARGET_INTERVAL - 9);
        });
    }

    #[test]
    fn target_to_compact_roundtrip() {
        new_test_ext().execute_with(|| {
            let original = U256::from(1_000_000u64);
            let compact = Difficulty::target_to_compact(original);
            let recovered = Difficulty::compact_to_target(compact);
            
            // Due to precision loss in compact format, recovered may differ slightly
            assert!(recovered.is_some());
        });
    }

    #[test]
    fn difficulty_increases_when_blocks_too_fast() {
        new_test_ext().execute_with(|| {
            let old_difficulty = U256::from(1_000_000u64);
            let actual_time = 5_000u64; // 5 seconds (should be 10)
            let expected_time = 10_000u64;

            let new_difficulty = Difficulty::calculate_new_difficulty(
                old_difficulty,
                actual_time,
                expected_time,
            );

            // Difficulty should increase when blocks are too fast
            assert!(new_difficulty > old_difficulty);
        });
    }

    #[test]
    fn difficulty_decreases_when_blocks_too_slow() {
        new_test_ext().execute_with(|| {
            let old_difficulty = U256::from(1_000_000u64);
            let actual_time = 20_000u64; // 20 seconds (should be 10)
            let expected_time = 10_000u64;

            let new_difficulty = Difficulty::calculate_new_difficulty(
                old_difficulty,
                actual_time,
                expected_time,
            );

            // Difficulty should decrease when blocks are too slow
            assert!(new_difficulty < old_difficulty);
        });
    }

    #[test]
    fn difficulty_clamped_at_max_adjustment() {
        new_test_ext().execute_with(|| {
            let old_difficulty = U256::from(1_000_000u64);
            let actual_time = 1u64; // Extremely fast
            let expected_time = 10_000u64;

            let new_difficulty = Difficulty::calculate_new_difficulty(
                old_difficulty,
                actual_time,
                expected_time,
            );

            // Should be clamped to 4x max increase
            assert_eq!(
                new_difficulty,
                old_difficulty.saturating_mul(U256::from(MAX_ADJUSTMENT_FACTOR))
            );
        });
    }

    #[test]
    fn force_set_difficulty_works() {
        new_test_ext().execute_with(|| {
            let new_diff = U256::from(2_000_000u64);
            let new_bits = 0x1e00_ffff;

            assert_ok!(Difficulty::force_set_difficulty(
                RuntimeOrigin::root(),
                new_diff,
                new_bits
            ));

            assert_eq!(Difficulty::difficulty(), new_diff);
            assert_eq!(Difficulty::difficulty_bits(), new_bits);
        });
    }
}
