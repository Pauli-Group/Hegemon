//! Runtime API trait definitions for Hegemon
//!
//! These traits define the interface between the node and runtime
//! for PoW difficulty queries, shielded pool operations, and other
//! consensus operations.
//!
//! # Usage
//!
//! The node's Blake3Pow algorithm uses these APIs to:
//! 1. Query current difficulty for block validation
//! 2. Query difficulty for mining target calculation
//! 3. Check consensus parameters
//!
//! The shielded pool RPC uses ShieldedPoolApi to:
//! 1. Query encrypted notes for wallet scanning
//! 2. Get Merkle witnesses for spending notes
//! 3. Check nullifier status and pool statistics
//!
//! # Example
//!
//! ```ignore
//! // In node code:
//! let difficulty = runtime_api.difficulty(parent_hash)?;
//! let target = U256::MAX / difficulty;
//!
//! // Query shielded notes:
//! let notes = runtime_api.get_encrypted_notes(0, 100)?;
//! ```

// Note: no_std is handled by the parent crate (runtime/src/lib.rs)

use sp_api::decl_runtime_apis;
use sp_core::U256;
use sp_std::vec::Vec;
use pallet_shielded_pool::merkle::CompactMerkleTree;

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

    /// API for shielded pool queries
    ///
    /// Provides access to shielded pool state for RPC endpoints:
    /// - Encrypted notes for wallet scanning
    /// - Merkle witnesses for spending
    /// - Nullifier status checks
    /// - Pool statistics
    ///
    /// # Security
    ///
    /// All operations use post-quantum cryptography:
    /// - ML-KEM-768 for note encryption
    /// - STARK proofs for transaction verification
    /// - Poseidon hash for Merkle tree
    pub trait ShieldedPoolApi {
        /// Get encrypted notes in a range.
        ///
        /// Returns tuples of (index, ciphertext, block_number, commitment).
        /// Wallets trial-decrypt these using their viewing keys.
        ///
        /// # Parameters
        /// - `start`: Starting note index
        /// - `limit`: Maximum notes to return
        fn get_encrypted_notes(
            start: u64,
            limit: u32,
        ) -> Vec<(u64, Vec<u8>, u64, [u8; 32])>;

        /// Get total number of encrypted notes.
        fn encrypted_note_count() -> u64;

        /// Get Merkle witness for a note position.
        ///
        /// Returns (siblings, indices, root) where:
        /// - siblings: 32 sibling hashes from leaf to root
        /// - indices: position bits (true = right child)
        /// - root: current Merkle root
        #[allow(clippy::type_complexity, clippy::result_unit_err)]
        fn get_merkle_witness(
            position: u64,
        ) -> Result<(Vec<[u8; 32]>, Vec<bool>, [u8; 32]), ()>;

        /// Check if a nullifier has been spent.
        fn is_nullifier_spent(nullifier: [u8; 32]) -> bool;

        /// Check if an anchor (Merkle root) is valid.
        fn is_valid_anchor(anchor: [u8; 32]) -> bool;

        /// Get shielded pool balance.
        fn pool_balance() -> u128;

        /// Get current Merkle root.
        fn merkle_root() -> [u8; 32];

        /// Get Merkle tree depth.
        fn tree_depth() -> u32;

        /// Get total nullifier count (spent notes).
        fn nullifier_count() -> u64;

        /// List all spent nullifiers.
        ///
        /// Returns all nullifiers currently in the spent set.
        /// Used by wallets to detect which of their notes have been spent.
        fn list_nullifiers() -> Vec<[u8; 32]>;

        /// Fetch the compact Merkle tree state used for commitment-root computation.
        ///
        /// This is used by the node during block import to derive the expected commitment tree
        /// roots without replaying all historical commitments.
        fn compact_merkle_tree() -> CompactMerkleTree;

        /// Fetch the current anchor root history window.
        ///
        /// This mirrors `pallet_shielded_pool::MerkleRootHistory` and is used by the node to
        /// validate transaction anchors during block import.
        fn merkle_root_history() -> Vec<[u8; 32]>;
    }
}
