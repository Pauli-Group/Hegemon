//! Full Substrate Client Integration (Task 10.2)
//!
//! This module provides the full Substrate client integration for the Hegemon node,
//! replacing the scaffold mode mock implementations with real Substrate components:
//!
//! - `TFullClient`: Full client with WASM executor for block execution
//! - `TFullBackend`: Database backend for state storage (RocksDB/ParityDB)
//! - `BasicPool`: Full transaction pool with validation
//! - `LongestChain`: Chain selection rule
//! - `SubstrateChainStateProvider`: Real chain state for mining
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    Full Substrate Client                                │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │  ┌──────────────────────────────────────────────────────────────────┐  │
//! │  │                        TFullClient                                │  │
//! │  │  ┌────────────┐  ┌────────────┐  ┌──────────────────────────┐    │  │
//! │  │  │  Backend   │  │  Executor  │  │       Runtime API        │    │  │
//! │  │  │ (RocksDB)  │  │  (WASM)    │  │  - DifficultyApi         │    │  │
//! │  │  └────────────┘  └────────────┘  │  - BlockBuilder          │    │  │
//! │  │                                   │  - TaggedTransactionQueue│    │  │
//! │  │                                   └──────────────────────────┘    │  │
//! │  └──────────────────────────────────────────────────────────────────┘  │
//! │                                  │                                      │
//! │  ┌───────────────────────────────▼──────────────────────────────────┐  │
//! │  │                    Transaction Pool                               │  │
//! │  │  ┌────────────┐  ┌────────────┐  ┌──────────────────────────┐    │  │
//! │  │  │  Ready Q   │  │  Future Q  │  │   Validation             │    │  │
//! │  │  │  (valid)   │  │  (pending) │  │   (runtime check)        │    │  │
//! │  │  └────────────┘  └────────────┘  └──────────────────────────┘    │  │
//! │  └──────────────────────────────────────────────────────────────────┘  │
//! │                                  │                                      │
//! │  ┌───────────────────────────────▼──────────────────────────────────┐  │
//! │  │               SubstrateChainStateProvider                         │  │
//! │  │  - best_hash()          → client.info().best_hash                 │  │
//! │  │  - difficulty_bits()    → runtime_api.difficulty_bits()           │  │
//! │  │  - pending_transactions() → pool.ready()                          │  │
//! │  │  - import_block()       → block_import.import_block()             │  │
//! │  └──────────────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Implementation Status
//!
//! Task 10.2 provides the type definitions and trait implementations needed for
//! full client integration. The actual instantiation of these types requires:
//! - Task 10.3: Block import pipeline with PowBlockImport
//! - sc-service::Configuration from CLI parsing
//!
//! The `SubstrateChainStateProvider` is designed to work with the concrete client
//! types that will be instantiated in service.rs once the full pipeline is ready.

use crate::substrate::mining_worker::{BlockTemplate, ChainStateProvider};
use consensus::Blake3Seal;
use sp_core::H256;
use std::sync::Arc;

/// Type alias for the full backend
pub type FullBackend = sc_service::TFullBackend<runtime::Block>;

/// Type alias for the WASM executor with standard host functions
pub type WasmExecutor = sc_executor::WasmExecutor<
    sp_io::SubstrateHostFunctions
>;

/// Type alias for the full Substrate client
/// 
/// RuntimeApi is the generated API type from impl_runtime_apis!
/// For hegemon, this includes DifficultyApi and ConsensusApi.
pub type FullClient<RuntimeApi> = sc_service::TFullClient<
    runtime::Block,
    RuntimeApi,
    WasmExecutor,
>;

/// Type alias for the basic transaction pool
/// 
/// Uses the basic authorship pool which validates transactions
/// against the runtime.
pub type FullTransactionPool<Client> = sc_transaction_pool::BasicPool<
    sc_transaction_pool::FullChainApi<Client, runtime::Block>,
    runtime::Block,
>;

/// Default difficulty bits if runtime query fails
pub const DEFAULT_DIFFICULTY_BITS: u32 = 0x1d00ffff;

/// Configuration for creating full Substrate components
#[derive(Clone)]
pub struct FullClientConfig {
    /// Whether to use in-memory database (for testing)
    pub in_memory: bool,
    /// Database path (if not in-memory)
    pub db_path: Option<std::path::PathBuf>,
    /// Chain specification name
    pub chain_spec: String,
}

impl Default for FullClientConfig {
    fn default() -> Self {
        Self {
            in_memory: true,
            db_path: None,
            chain_spec: "dev".to_string(),
        }
    }
}

impl FullClientConfig {
    /// Create config for development (in-memory)
    pub fn development() -> Self {
        Self {
            in_memory: true,
            db_path: None,
            chain_spec: "dev".to_string(),
        }
    }

    /// Create config for testnet
    pub fn testnet(db_path: std::path::PathBuf) -> Self {
        Self {
            in_memory: false,
            db_path: Some(db_path),
            chain_spec: "testnet".to_string(),
        }
    }

    /// Create config for production
    pub fn production(db_path: std::path::PathBuf) -> Self {
        Self {
            in_memory: false,
            db_path: Some(db_path),
            chain_spec: "mainnet".to_string(),
        }
    }
}

/// Concrete chain state provider using the Hegemon client
///
/// This is a wrapper around the client and transaction pool that implements
/// the `ChainStateProvider` trait for the mining worker.
///
/// # Type Parameters
///
/// This struct is intentionally NOT generic - it uses concrete types for
/// the Hegemon runtime. This avoids complex trait bound issues that arise
/// from generic implementations with Substrate's deeply nested types.
///
/// # Usage
///
/// ```ignore
/// // Created in service.rs after new_full_parts():
/// let provider = SubstrateChainStateProvider::new(client.clone(), pool.clone());
/// let mining_worker = MiningWorker::new(
///     pow_handle,
///     Arc::new(provider),
///     broadcaster,
///     config,
/// );
/// ```
pub struct SubstrateChainStateProvider {
    /// Best block hash
    best_hash: parking_lot::RwLock<H256>,
    /// Best block number
    best_number: parking_lot::RwLock<u64>,
    /// Current difficulty bits
    difficulty_bits: parking_lot::RwLock<u32>,
    /// Pending transaction bytes
    pending_txs: parking_lot::RwLock<Vec<Vec<u8>>>,
}

impl SubstrateChainStateProvider {
    /// Create a new chain state provider
    ///
    /// Initially set to genesis state. The provider should be updated
    /// via `update_from_client()` as blocks are imported.
    pub fn new() -> Self {
        Self {
            best_hash: parking_lot::RwLock::new(H256::zero()),
            best_number: parking_lot::RwLock::new(0),
            difficulty_bits: parking_lot::RwLock::new(DEFAULT_DIFFICULTY_BITS),
            pending_txs: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Create with initial state
    pub fn with_state(hash: H256, number: u64, difficulty: u32) -> Self {
        Self {
            best_hash: parking_lot::RwLock::new(hash),
            best_number: parking_lot::RwLock::new(number),
            difficulty_bits: parking_lot::RwLock::new(difficulty),
            pending_txs: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Update state from client info
    ///
    /// This should be called periodically or on block import to keep
    /// the provider in sync with the actual chain state.
    ///
    /// # Task 10.3 Implementation
    ///
    /// When the full client is available, this will query:
    /// - `client.info().best_hash`
    /// - `client.info().best_number`
    /// - `runtime_api.difficulty_bits(best)`
    /// - `pool.ready()`
    pub fn update_state(&self, hash: H256, number: u64, difficulty: u32, pending: Vec<Vec<u8>>) {
        *self.best_hash.write() = hash;
        *self.best_number.write() = number;
        *self.difficulty_bits.write() = difficulty;
        *self.pending_txs.write() = pending;
    }

    /// Update best block info
    pub fn update_best(&self, hash: H256, number: u64) {
        *self.best_hash.write() = hash;
        *self.best_number.write() = number;
    }

    /// Update difficulty
    pub fn update_difficulty(&self, bits: u32) {
        *self.difficulty_bits.write() = bits;
    }

    /// Add pending transaction
    pub fn add_pending_tx(&self, tx: Vec<u8>) {
        self.pending_txs.write().push(tx);
    }

    /// Clear pending transactions (after block is mined)
    pub fn clear_pending_txs(&self) {
        self.pending_txs.write().clear();
    }
}

impl Default for SubstrateChainStateProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainStateProvider for SubstrateChainStateProvider {
    fn best_hash(&self) -> H256 {
        *self.best_hash.read()
    }

    fn best_number(&self) -> u64 {
        *self.best_number.read()
    }

    fn difficulty_bits(&self) -> u32 {
        *self.difficulty_bits.read()
    }

    fn pending_transactions(&self) -> Vec<Vec<u8>> {
        self.pending_txs.read().clone()
    }

    fn import_block(&self, template: &BlockTemplate, seal: &Blake3Seal) -> Result<H256, String> {
        // Compute block hash from seal work
        let block_hash = H256::from_slice(seal.work.as_bytes());
        
        // Update our state
        self.update_best(block_hash, template.number);
        self.clear_pending_txs();
        
        tracing::info!(
            block_number = template.number,
            block_hash = %hex::encode(block_hash.as_bytes()),
            nonce = seal.nonce,
            "Block imported to SubstrateChainStateProvider (full import via PowBlockImport pending - Task 10.3)"
        );
        
        Ok(block_hash)
    }

    fn on_new_block(&self, block_hash: &H256, block_number: u64) {
        // Update if this is a newer block
        let current = self.best_number();
        if block_number > current {
            self.update_best(*block_hash, block_number);
            tracing::debug!(
                block_hash = %hex::encode(block_hash.as_bytes()),
                block_number = block_number,
                "SubstrateChainStateProvider updated from network block"
            );
        }
    }
}

/// Create a chain state provider for the mining worker
///
/// Returns a provider that can be updated as blocks are imported.
/// This is the bridge between the Substrate client and the mining worker.
pub fn create_chain_state_provider() -> Arc<SubstrateChainStateProvider> {
    Arc::new(SubstrateChainStateProvider::new())
}

/// Create a chain state provider with initial state
pub fn create_chain_state_provider_with_state(
    hash: H256,
    number: u64,
    difficulty: u32,
) -> Arc<SubstrateChainStateProvider> {
    Arc::new(SubstrateChainStateProvider::with_state(hash, number, difficulty))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_client_config_default() {
        let config = FullClientConfig::default();
        assert!(config.in_memory);
        assert!(config.db_path.is_none());
        assert_eq!(config.chain_spec, "dev");
    }

    #[test]
    fn test_full_client_config_development() {
        let config = FullClientConfig::development();
        assert!(config.in_memory);
    }

    #[test]
    fn test_full_client_config_testnet() {
        let path = std::path::PathBuf::from("/tmp/testnet");
        let config = FullClientConfig::testnet(path.clone());
        assert!(!config.in_memory);
        assert_eq!(config.db_path.unwrap(), path);
        assert_eq!(config.chain_spec, "testnet");
    }

    #[test]
    fn test_full_client_config_production() {
        let path = std::path::PathBuf::from("/var/lib/hegemon");
        let config = FullClientConfig::production(path.clone());
        assert!(!config.in_memory);
        assert_eq!(config.db_path.unwrap(), path);
        assert_eq!(config.chain_spec, "mainnet");
    }

    #[test]
    fn test_default_difficulty_bits() {
        assert_eq!(DEFAULT_DIFFICULTY_BITS, 0x1d00ffff);
    }

    #[test]
    fn test_chain_state_provider_new() {
        let provider = SubstrateChainStateProvider::new();
        assert_eq!(provider.best_hash(), H256::zero());
        assert_eq!(provider.best_number(), 0);
        assert_eq!(provider.difficulty_bits(), DEFAULT_DIFFICULTY_BITS);
        assert!(provider.pending_transactions().is_empty());
    }

    #[test]
    fn test_chain_state_provider_with_state() {
        let hash = H256::repeat_byte(0x42);
        let provider = SubstrateChainStateProvider::with_state(hash, 100, 0x2000ffff);
        assert_eq!(provider.best_hash(), hash);
        assert_eq!(provider.best_number(), 100);
        assert_eq!(provider.difficulty_bits(), 0x2000ffff);
    }

    #[test]
    fn test_chain_state_provider_update() {
        let provider = SubstrateChainStateProvider::new();
        
        let hash = H256::repeat_byte(0xab);
        let pending = vec![vec![1, 2, 3], vec![4, 5, 6]];
        provider.update_state(hash, 50, 0x1f00ffff, pending.clone());
        
        assert_eq!(provider.best_hash(), hash);
        assert_eq!(provider.best_number(), 50);
        assert_eq!(provider.difficulty_bits(), 0x1f00ffff);
        assert_eq!(provider.pending_transactions(), pending);
    }

    #[test]
    fn test_chain_state_provider_on_new_block() {
        let provider = SubstrateChainStateProvider::with_state(H256::zero(), 10, DEFAULT_DIFFICULTY_BITS);
        
        // Newer block should update
        let hash = H256::repeat_byte(0x11);
        provider.on_new_block(&hash, 15);
        assert_eq!(provider.best_hash(), hash);
        assert_eq!(provider.best_number(), 15);
        
        // Older block should not update
        let old_hash = H256::repeat_byte(0x22);
        provider.on_new_block(&old_hash, 5);
        assert_eq!(provider.best_hash(), hash); // Still the newer one
        assert_eq!(provider.best_number(), 15);
    }

    #[test]
    fn test_chain_state_provider_import_block() {
        let provider = SubstrateChainStateProvider::new();
        provider.add_pending_tx(vec![1, 2, 3]);
        
        let template = BlockTemplate::new(H256::zero(), 1, DEFAULT_DIFFICULTY_BITS);
        let seal = Blake3Seal {
            nonce: 12345,
            difficulty: DEFAULT_DIFFICULTY_BITS,
            work: H256::repeat_byte(0xaa),
        };
        
        let result = provider.import_block(&template, &seal);
        assert!(result.is_ok());
        
        // State should be updated
        assert_eq!(provider.best_number(), 1);
        assert!(provider.pending_transactions().is_empty()); // Cleared
    }
}
