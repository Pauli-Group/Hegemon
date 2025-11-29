//! Block Import Pipeline (Task 10.3)
//!
//! This module implements the block import pipeline for the Hegemon node,
//! integrating sc-consensus-pow with our Blake3 PoW algorithm.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     Block Import Pipeline                                │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │  Network ────▶ Import Queue ────▶ PowBlockImport ────▶ Client           │
//! │     │               │                    │                │             │
//! │     │               │                    │                ▼             │
//! │     │               │                    │          ┌──────────┐        │
//! │     │               │                    │          │ Backend  │        │
//! │     │               │                    │          │ (RocksDB)│        │
//! │     │               │                    │          └──────────┘        │
//! │     │               │                    ▼                              │
//! │     │               │            Blake3Algorithm                        │
//! │     │               │              (verify seal)                        │
//! │     │               │                    │                              │
//! │     │               ▼                    ▼                              │
//! │     │          PowVerifier ◀────────────┘                               │
//! │     │          (decode seal)                                            │
//! │     │                                                                   │
//! │     ▼                                                                   │
//! │  Mining Worker ────────────────────────────────────────────────────────▶│
//! │     (produce blocks)                    │                               │
//! │                                         ▼                               │
//! │                                    PowBlockImport                       │
//! │                                    (import mined block)                 │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Components
//!
//! 1. **PowBlockImport**: Wraps the client to add PoW verification on import
//! 2. **Blake3Algorithm**: Implements sc-consensus-pow::PowAlgorithm
//! 3. **Import Queue**: Manages concurrent block imports from network/mining
//! 4. **Verifier**: Decodes and validates PoW seals before full import
//!
//! # Usage
//!
//! ```ignore
//! // Create the block import pipeline in new_partial():
//! let (pow_block_import, import_queue, pow_algorithm) = create_pow_import_pipeline(
//!     &config,
//!     client.clone(),
//!     select_chain.clone(),
//!     &task_manager,
//! )?;
//! ```

use consensus::{Blake3Seal, compute_work, seal_meets_target, compact_to_target};
use codec::Decode;
use sp_core::{H256, U256};
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;
use std::sync::Arc;

/// Error type for block import operations
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("Failed to decode seal: {0}")]
    SealDecode(String),
    #[error("Seal verification failed: {0}")]
    SealVerification(String),
    #[error("Block import failed: {0}")]
    Import(String),
    #[error("Difficulty query failed: {0}")]
    DifficultyQuery(String),
    #[error("Client error: {0}")]
    Client(String),
}

/// Result type for block import operations
pub type ImportResult<T> = Result<T, ImportError>;

/// Block import pipeline configuration
#[derive(Clone, Debug)]
pub struct BlockImportConfig {
    /// Number of blocks before checking inherents
    /// Set to 0 to always check, u32::MAX to never check
    pub check_inherents_after: u32,
    /// Whether to verify PoW seals (should always be true except for testing)
    pub verify_pow: bool,
    /// Maximum time to wait for a seal to be verified (ms)
    pub verification_timeout_ms: u64,
}

impl Default for BlockImportConfig {
    fn default() -> Self {
        Self {
            check_inherents_after: 0,
            verify_pow: true,
            verification_timeout_ms: 5000,
        }
    }
}

impl BlockImportConfig {
    /// Create config for development (relaxed settings)
    pub fn development() -> Self {
        Self {
            check_inherents_after: u32::MAX,
            verify_pow: true,
            verification_timeout_ms: 10000,
        }
    }

    /// Create config for production (strict settings)
    pub fn production() -> Self {
        Self::default()
    }

    /// Create from environment variables
    pub fn from_env() -> Self {
        let check_after = std::env::var("HEGEMON_CHECK_INHERENTS_AFTER")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let verify = std::env::var("HEGEMON_VERIFY_POW")
            .map(|v| v != "0" && v.to_lowercase() != "false")
            .unwrap_or(true);

        let timeout = std::env::var("HEGEMON_VERIFICATION_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5000);

        Self {
            check_inherents_after: check_after,
            verify_pow: verify,
            verification_timeout_ms: timeout,
        }
    }
}

/// Statistics for block imports
#[derive(Clone, Debug, Default)]
pub struct ImportStats {
    /// Total blocks imported
    pub blocks_imported: u64,
    /// Blocks rejected due to invalid seal
    pub invalid_seals: u64,
    /// Blocks rejected due to difficulty mismatch
    pub difficulty_mismatches: u64,
    /// Average verification time (ms)
    pub avg_verification_time_ms: u64,
    /// Last imported block number
    pub last_block_number: u64,
    /// Last imported block hash
    pub last_block_hash: H256,
}

impl ImportStats {
    /// Record a successful import
    pub fn record_import(&mut self, block_number: u64, block_hash: H256, verification_time_ms: u64) {
        self.blocks_imported += 1;
        self.last_block_number = block_number;
        self.last_block_hash = block_hash;
        
        // Update rolling average
        if self.blocks_imported == 1 {
            self.avg_verification_time_ms = verification_time_ms;
        } else {
            // Simple exponential moving average
            self.avg_verification_time_ms = 
                (self.avg_verification_time_ms * 9 + verification_time_ms) / 10;
        }
    }

    /// Record a rejection
    pub fn record_rejection(&mut self, invalid_seal: bool, difficulty_mismatch: bool) {
        if invalid_seal {
            self.invalid_seals += 1;
        }
        if difficulty_mismatch {
            self.difficulty_mismatches += 1;
        }
    }
}

/// Seal data extracted from a block for verification
#[derive(Clone, Debug)]
pub struct ExtractedSeal {
    /// The Blake3 seal containing nonce, difficulty, and work
    pub seal: Blake3Seal,
    /// The pre-hash of the block (header hash before seal)
    pub pre_hash: H256,
    /// The full header hash (after seal)
    pub header_hash: H256,
}

/// Extract and decode a seal from block header digest
///
/// The seal is expected to be in the last digest item with the consensus engine ID "pow0"
pub fn extract_seal_from_header<Block: BlockT<Hash = H256>>(
    header: &Block::Header,
) -> ImportResult<ExtractedSeal> {
    use sp_runtime::traits::Header;
    use sp_runtime::DigestItem;

    // Find the seal in the digest
    let seal_item = header
        .digest()
        .logs()
        .iter()
        .find_map(|item| {
            if let DigestItem::Seal(engine_id, data) = item {
                // Our engine ID for Blake3 PoW
                if engine_id == b"pow_" || engine_id == b"pow0" || engine_id == b"bpow" {
                    return Some(data.clone());
                }
            }
            None
        })
        .ok_or_else(|| ImportError::SealDecode("No PoW seal found in header".into()))?;

    // Decode the seal
    let seal = Blake3Seal::decode(&mut &seal_item[..])
        .map_err(|e| ImportError::SealDecode(format!("Failed to decode Blake3Seal: {:?}", e)))?;

    // Compute pre-hash (header hash without the seal)
    let header_hash = header.hash();
    
    // For pre-hash, we need to remove the seal and hash the remaining header
    // This is a simplified approach - in production, the seal should be properly stripped
    let pre_hash = header_hash; // TODO: Proper pre-hash calculation

    Ok(ExtractedSeal {
        seal,
        pre_hash,
        header_hash,
    })
}

/// Verify a PoW seal against the claimed difficulty
///
/// Returns true if:
/// 1. The work hash matches blake3(pre_hash || nonce)
/// 2. The work meets the difficulty target
/// 3. The difficulty matches the expected difficulty
pub fn verify_pow_seal(
    extracted: &ExtractedSeal,
    expected_difficulty_bits: u32,
    tolerance: u32,
) -> ImportResult<bool> {
    let seal = &extracted.seal;
    
    // 1. Verify work computation
    let computed_work = compute_work(&extracted.pre_hash, seal.nonce);
    if computed_work != seal.work {
        return Err(ImportError::SealVerification(
            "Work hash does not match computed value".into(),
        ));
    }

    // 2. Verify work meets target
    if !seal_meets_target(&seal.work, seal.difficulty) {
        return Err(ImportError::SealVerification(
            "Work does not meet difficulty target".into(),
        ));
    }

    // 3. Verify difficulty matches expected (with tolerance)
    let diff_match = if seal.difficulty == expected_difficulty_bits {
        true
    } else {
        // Allow some tolerance for rounding in compact bits representation
        let seal_target = compact_to_target(seal.difficulty).unwrap_or(U256::zero());
        let expected_target = compact_to_target(expected_difficulty_bits).unwrap_or(U256::MAX);
        
        let diff = if seal_target > expected_target {
            seal_target - expected_target
        } else {
            expected_target - seal_target
        };
        
        // Allow tolerance% difference
        let tolerance_threshold = expected_target / U256::from(1000u32 / tolerance.max(1));
        diff <= tolerance_threshold
    };

    if !diff_match {
        return Err(ImportError::SealVerification(format!(
            "Difficulty mismatch: seal has {:#x}, expected {:#x}",
            seal.difficulty, expected_difficulty_bits
        )));
    }

    Ok(true)
}

/// Hegemon-specific block import wrapper
///
/// This wraps the inner block import (typically sc-consensus-pow::PowBlockImport)
/// with additional Hegemon-specific logic:
/// - Statistics tracking
/// - Logging
/// - Custom verification options
pub struct HegemonBlockImport<Block, Inner, Client> {
    /// The inner block import (PowBlockImport or raw client)
    inner: Inner,
    /// Client for querying state
    client: Arc<Client>,
    /// Configuration
    config: BlockImportConfig,
    /// Import statistics (wrapped in mutex for interior mutability)
    stats: parking_lot::RwLock<ImportStats>,
    /// Phantom data for block type
    _phantom: PhantomData<Block>,
}

impl<Block, Inner, Client> HegemonBlockImport<Block, Inner, Client>
where
    Block: BlockT<Hash = H256>,
{
    /// Create a new Hegemon block import wrapper
    pub fn new(inner: Inner, client: Arc<Client>, config: BlockImportConfig) -> Self {
        Self {
            inner,
            client,
            config,
            stats: parking_lot::RwLock::new(ImportStats::default()),
            _phantom: PhantomData,
        }
    }

    /// Get a snapshot of the import statistics
    pub fn stats(&self) -> ImportStats {
        self.stats.read().clone()
    }

    /// Get the configuration
    pub fn config(&self) -> &BlockImportConfig {
        &self.config
    }
}

impl<Block, Inner, Client> Clone for HegemonBlockImport<Block, Inner, Client>
where
    Inner: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            client: Arc::clone(&self.client),
            config: self.config.clone(),
            stats: parking_lot::RwLock::new(self.stats.read().clone()),
            _phantom: PhantomData,
        }
    }
}

// ============================================================================
// Mock implementation for scaffold mode
// ============================================================================

/// Mock block import for testing and scaffold mode
///
/// This implements a simple in-memory block import that:
/// - Validates seals using Blake3
/// - Tracks import statistics
/// - Does not require a full Substrate client
#[derive(Clone)]
pub struct MockBlockImport {
    /// Current best block number
    best_number: Arc<parking_lot::RwLock<u64>>,
    /// Current best block hash
    best_hash: Arc<parking_lot::RwLock<H256>>,
    /// Import statistics
    stats: Arc<parking_lot::RwLock<ImportStats>>,
    /// Configuration
    config: BlockImportConfig,
}

impl MockBlockImport {
    /// Create a new mock block import
    pub fn new(config: BlockImportConfig) -> Self {
        Self {
            best_number: Arc::new(parking_lot::RwLock::new(0)),
            best_hash: Arc::new(parking_lot::RwLock::new(H256::zero())),
            stats: Arc::new(parking_lot::RwLock::new(ImportStats::default())),
            config,
        }
    }

    /// Import a block with the given seal
    pub fn import_block(
        &self,
        block_number: u64,
        parent_hash: H256,
        seal: &Blake3Seal,
    ) -> ImportResult<H256> {
        let start = std::time::Instant::now();

        // Verify the seal
        if self.config.verify_pow {
            // For mock, use the seal's difficulty
            if !seal_meets_target(&seal.work, seal.difficulty) {
                self.stats.write().record_rejection(true, false);
                return Err(ImportError::SealVerification(
                    "Seal does not meet difficulty target".into(),
                ));
            }
        }

        // "Import" the block by updating state
        let block_hash = seal.work; // Use work as block hash for simplicity
        
        {
            let mut best_num = self.best_number.write();
            let mut best_hash = self.best_hash.write();
            
            *best_num = block_number;
            *best_hash = block_hash;
        }

        let verification_time = start.elapsed().as_millis() as u64;
        self.stats.write().record_import(block_number, block_hash, verification_time);

        tracing::info!(
            block_number = block_number,
            block_hash = %hex::encode(block_hash.as_bytes()),
            parent_hash = %hex::encode(parent_hash.as_bytes()),
            nonce = seal.nonce,
            verification_ms = verification_time,
            "MockBlockImport: Block imported"
        );

        Ok(block_hash)
    }

    /// Get the current best block number
    pub fn best_number(&self) -> u64 {
        *self.best_number.read()
    }

    /// Get the current best block hash
    pub fn best_hash(&self) -> H256 {
        *self.best_hash.read()
    }

    /// Get import statistics
    pub fn stats(&self) -> ImportStats {
        self.stats.read().clone()
    }
}

impl Default for MockBlockImport {
    fn default() -> Self {
        Self::new(BlockImportConfig::default())
    }
}

// ============================================================================
// Factory functions
// ============================================================================

/// Create a mock block import for scaffold mode
pub fn create_mock_block_import(config: BlockImportConfig) -> MockBlockImport {
    MockBlockImport::new(config)
}

/// Create a mock block import from environment
pub fn create_mock_block_import_from_env() -> MockBlockImport {
    MockBlockImport::new(BlockImportConfig::from_env())
}

// ============================================================================
// Full Substrate integration (requires aligned polkadot-sdk)
// ============================================================================

/// Create the full block import pipeline with PowBlockImport
///
/// This is the production implementation that requires:
/// - Full Substrate client (TFullClient)
/// - WASM executor
/// - Blake3Algorithm implementing PowAlgorithm
///
/// # Task 10.3 Implementation Notes
///
/// The full implementation flow:
/// 1. Create Blake3Algorithm with client reference
/// 2. Wrap client in PowBlockImport
/// 3. Create import queue with PowVerifier
/// 4. Return components for service integration
///
/// ```ignore
/// use sc_consensus_pow::{PowBlockImport, PowVerifier, import_queue};
///
/// // Create the PoW algorithm
/// let pow_algorithm = Blake3Algorithm::new(client.clone());
///
/// // Create the block import
/// let pow_block_import = PowBlockImport::new(
///     client.clone(),     // Inner block import
///     client.clone(),     // Select chain
///     pow_algorithm.clone(),
///     config.check_inherents_after,
///     select_chain.clone(),
/// );
///
/// // Create the import queue
/// let import_queue = import_queue(
///     Box::new(pow_block_import.clone()),
///     None,  // justification_import
///     pow_algorithm.clone(),
///     &task_manager.spawn_essential_handle(),
///     config.prometheus_registry(),
/// )?;
/// ```
///
/// # Note
///
/// The actual integration is gated behind the `substrate` feature and requires
/// proper type bounds. Due to complex trait requirements in sc-consensus-pow,
/// the integration is provided as documentation and template code rather than
/// a fully generic implementation. Users should adapt this to their specific
/// client types in service.rs.
#[cfg(feature = "substrate")]
pub mod substrate_integration {
    //! Substrate integration helpers for block import pipeline.
    //!
    //! This module provides the types and documentation needed for integrating
    //! the block import pipeline with sc-consensus-pow. The actual instantiation
    //! should happen in service.rs where the concrete client type is known.

    /// Template for creating the PoW block import in service.rs
    ///
    /// Copy and adapt this code to your service.rs:
    ///
    /// ```ignore
    /// // In new_partial() after creating the client:
    /// let pow_algorithm = consensus::Blake3Algorithm::new(client.clone());
    ///
    /// // Use the client directly as it implements BlockImport
    /// let pow_block_import = sc_consensus_pow::PowBlockImport::new(
    ///     client.clone(),  // Inner block import (Client implements BlockImport)
    ///     client.clone(),  // For querying runtime API
    ///     pow_algorithm.clone(),
    ///     0,  // check_inherents_after
    ///     select_chain.clone(),
    /// );
    ///
    /// // Create import queue
    /// let import_queue = sc_consensus_pow::import_queue(
    ///     Box::new(pow_block_import.clone()),
    ///     None,
    ///     pow_algorithm.clone(),
    ///     &task_manager.spawn_essential_handle(),
    ///     config.prometheus_registry(),
    /// )?;
    ///
    /// // Return in PartialComponents.other
    /// ```
    pub const POW_ENGINE_ID: &[u8; 4] = b"pow0";
    pub const BLAKE3_ENGINE_ID: &[u8; 4] = b"bpow";

    /// Default check_inherents_after value
    /// Set to 0 to check inherents from the start
    pub const DEFAULT_CHECK_INHERENTS_AFTER: u32 = 0;

    /// Marker type for documenting the expected client trait bounds
    ///
    /// The actual client type used in service.rs should implement:
    /// - `sc_client_api::backend::Backend<Block>`
    /// - `sp_api::ProvideRuntimeApi<Block>`
    /// - `sc_consensus::BlockImport<Block>`
    /// - `Send + Sync + 'static`
    ///
    /// Where `Block::Api` implements:
    /// - `runtime::apis::DifficultyApi<Block>`
    pub struct ClientRequirements;

    /// Marker type for documenting the expected select_chain trait bounds
    ///
    /// The select_chain should implement:
    /// - `sp_consensus::SelectChain<Block>`
    /// - `Clone + 'static`
    pub struct SelectChainRequirements;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_import_config_default() {
        let config = BlockImportConfig::default();
        assert_eq!(config.check_inherents_after, 0);
        assert!(config.verify_pow);
        assert_eq!(config.verification_timeout_ms, 5000);
    }

    #[test]
    fn test_block_import_config_development() {
        let config = BlockImportConfig::development();
        assert_eq!(config.check_inherents_after, u32::MAX);
        assert!(config.verify_pow);
    }

    #[test]
    fn test_block_import_config_from_env() {
        // Just verify it doesn't panic
        let _config = BlockImportConfig::from_env();
    }

    #[test]
    fn test_import_stats_record() {
        let mut stats = ImportStats::default();
        
        stats.record_import(1, H256::repeat_byte(0x01), 100);
        assert_eq!(stats.blocks_imported, 1);
        assert_eq!(stats.last_block_number, 1);
        assert_eq!(stats.avg_verification_time_ms, 100);

        stats.record_import(2, H256::repeat_byte(0x02), 200);
        assert_eq!(stats.blocks_imported, 2);
        assert_eq!(stats.last_block_number, 2);
        // EMA: (100 * 9 + 200) / 10 = 110
        assert_eq!(stats.avg_verification_time_ms, 110);
    }

    #[test]
    fn test_import_stats_rejection() {
        let mut stats = ImportStats::default();
        
        stats.record_rejection(true, false);
        assert_eq!(stats.invalid_seals, 1);
        assert_eq!(stats.difficulty_mismatches, 0);

        stats.record_rejection(false, true);
        assert_eq!(stats.invalid_seals, 1);
        assert_eq!(stats.difficulty_mismatches, 1);

        stats.record_rejection(true, true);
        assert_eq!(stats.invalid_seals, 2);
        assert_eq!(stats.difficulty_mismatches, 2);
    }

    #[test]
    fn test_mock_block_import_creation() {
        let import = MockBlockImport::default();
        assert_eq!(import.best_number(), 0);
        assert_eq!(import.best_hash(), H256::zero());
    }

    #[test]
    fn test_mock_block_import_successful() {
        let import = MockBlockImport::new(BlockImportConfig {
            verify_pow: true,
            ..Default::default()
        });

        // Create a valid seal (easy difficulty for testing)
        let pre_hash = H256::repeat_byte(0x42);
        let pow_bits = 0x2100ffff; // Very easy
        
        // Find a valid nonce
        let seal = consensus::mine_round(&pre_hash, pow_bits, 0, 100_000)
            .expect("Should find valid seal with easy difficulty");

        let result = import.import_block(1, H256::zero(), &seal);
        assert!(result.is_ok());
        
        assert_eq!(import.best_number(), 1);
        
        let stats = import.stats();
        assert_eq!(stats.blocks_imported, 1);
    }

    #[test]
    fn test_mock_block_import_invalid_seal() {
        let import = MockBlockImport::new(BlockImportConfig {
            verify_pow: true,
            ..Default::default()
        });

        // Create an invalid seal (work doesn't meet target)
        let invalid_seal = Blake3Seal {
            nonce: 0,
            difficulty: 0x0300ffff, // Very hard
            work: H256::repeat_byte(0xff), // Max value won't meet hard target
        };

        let result = import.import_block(1, H256::zero(), &invalid_seal);
        assert!(result.is_err());
        
        let stats = import.stats();
        assert_eq!(stats.blocks_imported, 0);
        assert_eq!(stats.invalid_seals, 1);
    }

    #[test]
    fn test_mock_block_import_no_verification() {
        let import = MockBlockImport::new(BlockImportConfig {
            verify_pow: false, // Disable verification
            ..Default::default()
        });

        // Even an invalid seal should be accepted
        let invalid_seal = Blake3Seal {
            nonce: 0,
            difficulty: 0x0300ffff,
            work: H256::repeat_byte(0xff),
        };

        let result = import.import_block(1, H256::zero(), &invalid_seal);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_pow_seal_valid() {
        let pre_hash = H256::repeat_byte(0x11);
        let pow_bits = 0x2100ffff;

        // Mine a valid seal
        let seal = consensus::mine_round(&pre_hash, pow_bits, 0, 100_000)
            .expect("Should find seal");

        let extracted = ExtractedSeal {
            seal,
            pre_hash,
            header_hash: pre_hash, // Simplified for test
        };

        let result = verify_pow_seal(&extracted, pow_bits, 10);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_pow_seal_wrong_difficulty() {
        let pre_hash = H256::repeat_byte(0x22);
        let pow_bits = 0x2100ffff;

        let seal = consensus::mine_round(&pre_hash, pow_bits, 0, 100_000)
            .expect("Should find seal");

        let extracted = ExtractedSeal {
            seal,
            pre_hash,
            header_hash: pre_hash,
        };

        // Check with different expected difficulty (outside tolerance)
        let result = verify_pow_seal(&extracted, 0x1a00ffff, 1); // Very different difficulty
        assert!(result.is_err());
    }

    #[test]
    fn test_create_mock_from_env() {
        let import = create_mock_block_import_from_env();
        assert_eq!(import.best_number(), 0);
    }
}
