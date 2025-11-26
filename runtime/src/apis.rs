//! Runtime API trait definitions for Hegemon
//!
//! These traits define the interface between the node and runtime
//! for PoW difficulty queries and other consensus operations.
//!
//! # Usage
//!
//! The node's Blake3Pow algorithm uses these APIs to:
//! 1. Query current difficulty for block validation
//! 2. Query difficulty for mining target calculation
//! 3. Check consensus parameters
//!
//! # Example
//!
//! ```ignore
//! // In node code:
//! let difficulty = runtime_api.difficulty(parent_hash)?;
//! let target = U256::MAX / difficulty;
//! ```

// Note: no_std is handled by the parent crate (runtime/src/lib.rs)

use sp_api::decl_runtime_apis;
use sp_core::U256;

decl_runtime_apis! {
    /// API for PoW difficulty queries
    ///
    /// The node's Blake3Pow algorithm calls this to get the current
    /// difficulty target for block validation and mining.
    ///
    /// # Implementation
    ///
    /// This is implemented by the runtime via `impl_runtime_apis!` macro,
    /// delegating to the `pallet-difficulty` storage.
    pub trait DifficultyApi {
        /// Get the current PoW difficulty.
        ///
        /// Returns the difficulty as U256 where:
        /// - Higher value = harder to mine
        /// - Target = U256::MAX / difficulty
        ///
        /// The difficulty is stored in the Difficulty pallet and adjusted
        /// periodically based on actual vs expected block times.
        fn difficulty() -> U256;
    }

    /// API for consensus-related queries
    ///
    /// Provides information about consensus parameters that the node
    /// may need for coordination, logging, or external queries.
    pub trait ConsensusApi {
        /// Get the target block time in milliseconds.
        ///
        /// This is the expected time between blocks. The difficulty
        /// adjustment algorithm aims to maintain this block time.
        fn target_block_time() -> u64;

        /// Get blocks until next difficulty adjustment.
        ///
        /// Returns the number of blocks remaining before the next
        /// difficulty retarget occurs.
        fn blocks_until_retarget() -> u32;

        /// Get the current difficulty as compact bits format.
        ///
        /// Returns the difficulty in Bitcoin-style compact format:
        /// - Upper byte: exponent
        /// - Lower 3 bytes: mantissa
        fn difficulty_bits() -> u32;
    }
}
