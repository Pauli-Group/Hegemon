//! Transaction Pool Integration (Phase 9 - Task 9.2)
//!
//! Bridges the PQ network layer to Substrate's transaction pool, handling:
//! - Transaction decoding from network messages
//! - Validation and submission to the pool
//! - Error handling and reporting
//! - Statistics and monitoring
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    Transaction Pool Integration                          │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │  NetworkBridge ─────▶ TransactionPoolBridge ─────▶ TransactionPool      │
//! │       │                        │                         │              │
//! │       ▼                        ▼                         ▼              │
//! │  drain_transactions()    validate_and_submit()      pool.submit_one()   │
//! │       │                        │                         │              │
//! │       │                        ▼                         │              │
//! │       │               ┌─────────────────┐                │              │
//! │       │               │ Transaction     │                │              │
//! │       │               │ Decoder         │                │              │
//! │       │               │ (SCALE decode)  │                │              │
//! │       │               └─────────────────┘                │              │
//! │       │                        │                         │              │
//! │       │                        ▼                         ▼              │
//! │       └────────────────▶ SubmissionResult ◀──────────────┘              │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! // Create pool bridge
//! let pool_bridge = TransactionPoolBridge::new(pool.clone(), client.clone());
//!
//! // In the event loop, periodically drain and submit transactions
//! let transactions = network_bridge.drain_transactions();
//! for (peer_id, tx_data) in transactions {
//!     match pool_bridge.submit_transaction(&tx_data, Some(&peer_id)).await {
//!         Ok(hash) => tracing::debug!(tx_hash = %hash, "Transaction submitted"),
//!         Err(e) => tracing::warn!(error = %e, "Failed to submit transaction"),
//!     }
//! }
//! ```

use network::PeerId;
use parking_lot::Mutex as ParkingMutex;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Transaction submission result
#[derive(Debug, Clone)]
pub struct SubmissionResult {
    /// Transaction hash (blake2_256 of encoded tx)
    pub hash: [u8; 32],
    /// Whether submission succeeded
    pub accepted: bool,
    /// Error message if rejected
    pub error: Option<String>,
    /// Priority assigned (if available)
    pub priority: Option<u64>,
}

impl SubmissionResult {
    /// Create a successful result
    pub fn success(hash: [u8; 32], priority: Option<u64>) -> Self {
        Self {
            hash,
            accepted: true,
            error: None,
            priority,
        }
    }

    /// Create a failure result
    pub fn failure(hash: [u8; 32], error: impl Into<String>) -> Self {
        Self {
            hash,
            accepted: false,
            error: Some(error.into()),
            priority: None,
        }
    }
}

/// Transaction pool statistics
#[derive(Debug, Default)]
pub struct PoolBridgeStats {
    /// Total transactions received from network
    pub transactions_received: AtomicU64,
    /// Transactions successfully submitted to pool
    pub transactions_submitted: AtomicU64,
    /// Transactions rejected (invalid/duplicate)
    pub transactions_rejected: AtomicU64,
    /// Decode errors
    pub decode_errors: AtomicU64,
    /// Pool full rejections
    pub pool_full_rejections: AtomicU64,
}

impl PoolBridgeStats {
    /// Create new statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of current stats
    pub fn snapshot(&self) -> PoolBridgeStatsSnapshot {
        PoolBridgeStatsSnapshot {
            transactions_received: self.transactions_received.load(Ordering::Relaxed),
            transactions_submitted: self.transactions_submitted.load(Ordering::Relaxed),
            transactions_rejected: self.transactions_rejected.load(Ordering::Relaxed),
            decode_errors: self.decode_errors.load(Ordering::Relaxed),
            pool_full_rejections: self.pool_full_rejections.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of pool bridge statistics
#[derive(Debug, Clone, Copy)]
pub struct PoolBridgeStatsSnapshot {
    pub transactions_received: u64,
    pub transactions_submitted: u64,
    pub transactions_rejected: u64,
    pub decode_errors: u64,
    pub pool_full_rejections: u64,
}

/// Transaction source for priority/validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionSource {
    /// Transaction from external peer
    External,
    /// Transaction from local RPC
    Local,
    /// Transaction from internal process (e.g., inherent)
    InBlock,
}

impl Default for TransactionSource {
    fn default() -> Self {
        Self::External
    }
}

/// Error types for transaction pool operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum PoolError {
    /// Transaction decode failed
    #[error("Failed to decode transaction: {0}")]
    DecodeError(String),

    /// Transaction validation failed
    #[error("Transaction invalid: {0}")]
    InvalidTransaction(String),

    /// Duplicate transaction
    #[error("Transaction already in pool: {0}")]
    AlreadyInPool(String),

    /// Pool is full
    #[error("Transaction pool is full")]
    PoolFull,

    /// Unknown error
    #[error("Unknown error: {0}")]
    Unknown(String),
}

#[derive(Debug, Clone)]
enum ExternalVerificationVerdict {
    Valid,
    Invalid(String),
}

#[derive(Debug, Default)]
struct ExternalVerificationCache {
    order: VecDeque<[u8; 32]>,
    verdicts: HashMap<[u8; 32], ExternalVerificationVerdict>,
}

impl ExternalVerificationCache {
    fn get(&self, hash: &[u8; 32]) -> Option<ExternalVerificationVerdict> {
        self.verdicts.get(hash).cloned()
    }

    fn insert(&mut self, capacity: usize, hash: [u8; 32], verdict: ExternalVerificationVerdict) {
        if self.verdicts.contains_key(&hash) {
            self.verdicts.insert(hash, verdict);
            return;
        }
        self.order.push_back(hash);
        self.verdicts.insert(hash, verdict);
        while self.order.len() > capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.verdicts.remove(&evicted);
            }
        }
    }
}

/// Pending transaction entry
#[derive(Debug, Clone)]
pub struct PendingTransaction {
    /// Transaction data (SCALE-encoded)
    pub data: Vec<u8>,
    /// Peer that sent this transaction
    pub peer_id: Option<PeerId>,
    /// Timestamp when received
    pub received_at: std::time::Instant,
    /// Transaction source
    pub source: TransactionSource,
}

/// Trait for transaction pool backends
///
/// This abstraction allows swapping between:
/// - MockTransactionPool (for testing/scaffold mode)
/// - SubstrateTransactionPool (wrapping sc-transaction-pool)
#[async_trait::async_trait]
pub trait TransactionPool: Send + Sync {
    /// Submit a transaction to the pool
    async fn submit(
        &self,
        tx: &[u8],
        source: TransactionSource,
    ) -> Result<SubmissionResult, PoolError>;

    /// Check if a transaction is already in the pool
    fn contains(&self, hash: &[u8; 32]) -> bool;

    /// Get the current pool size
    fn pool_size(&self) -> usize;

    /// Get the pool capacity
    fn pool_capacity(&self) -> usize;

    /// Remove a transaction by hash (for reorgs/invalidation)
    fn remove(&self, hash: &[u8; 32]) -> bool;

    /// Get all ready transactions for block production (Task 11.3)
    ///
    /// Returns encoded transactions that are ready to be included in a block.
    /// For MockTransactionPool, this returns all pooled transactions.
    /// For a real pool, this would return transactions from the "ready" queue.
    fn ready_transactions(&self) -> Vec<Vec<u8>>;

    /// Clear transactions that were included in a block (Task 11.3)
    ///
    /// Called after a block is mined to remove included transactions.
    /// This prevents transactions from being included twice.
    fn clear_transactions(&self, hashes: &[[u8; 32]]);
}

/// Mock transaction pool for scaffold mode
///
/// Stores transactions in memory and validates basic structure.
/// Used until full Substrate pool integration is complete.
pub struct MockTransactionPool {
    /// Stored transactions by hash
    transactions: Arc<Mutex<HashMap<[u8; 32], Vec<u8>>>>,
    /// Maximum pool size
    capacity: usize,
    /// Statistics
    stats: Arc<PoolBridgeStats>,
}

impl MockTransactionPool {
    /// Create a new mock pool with given capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            transactions: Arc::new(Mutex::new(HashMap::new())),
            capacity,
            stats: Arc::new(PoolBridgeStats::new()),
        }
    }

    /// Get statistics
    pub fn stats(&self) -> Arc<PoolBridgeStats> {
        Arc::clone(&self.stats)
    }

    /// Compute transaction hash (blake2_256)
    fn compute_hash(data: &[u8]) -> [u8; 32] {
        use sp_core::hashing::blake2_256;
        blake2_256(data)
    }
}

#[async_trait::async_trait]
impl TransactionPool for MockTransactionPool {
    async fn submit(
        &self,
        tx: &[u8],
        _source: TransactionSource,
    ) -> Result<SubmissionResult, PoolError> {
        let hash = Self::compute_hash(tx);

        // Basic validation: non-empty, reasonable size
        if tx.is_empty() {
            return Err(PoolError::InvalidTransaction("Empty transaction".into()));
        }
        if tx.len() > 1024 * 1024 {
            return Err(PoolError::InvalidTransaction(
                "Transaction too large".into(),
            ));
        }

        let mut pool = self.transactions.lock().await;

        // Check if already present
        if pool.contains_key(&hash) {
            return Err(PoolError::AlreadyInPool(hex::encode(hash)));
        }

        // Check capacity
        if pool.len() >= self.capacity {
            self.stats
                .pool_full_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Err(PoolError::PoolFull);
        }

        // Add to pool
        pool.insert(hash, tx.to_vec());
        self.stats
            .transactions_submitted
            .fetch_add(1, Ordering::Relaxed);

        tracing::debug!(
            tx_hash = %hex::encode(hash),
            pool_size = pool.len(),
            "Transaction added to mock pool"
        );

        Ok(SubmissionResult::success(hash, Some(0)))
    }

    fn contains(&self, hash: &[u8; 32]) -> bool {
        // Use try_lock to avoid blocking in sync context
        match self.transactions.try_lock() {
            Ok(pool) => pool.contains_key(hash),
            Err(_) => false, // Assume not present if can't check
        }
    }

    fn pool_size(&self) -> usize {
        match self.transactions.try_lock() {
            Ok(pool) => pool.len(),
            Err(_) => 0,
        }
    }

    fn pool_capacity(&self) -> usize {
        self.capacity
    }

    fn remove(&self, hash: &[u8; 32]) -> bool {
        match self.transactions.try_lock() {
            Ok(mut pool) => pool.remove(hash).is_some(),
            Err(_) => false,
        }
    }

    fn ready_transactions(&self) -> Vec<Vec<u8>> {
        match self.transactions.try_lock() {
            Ok(pool) => pool.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    fn clear_transactions(&self, hashes: &[[u8; 32]]) {
        if let Ok(mut pool) = self.transactions.try_lock() {
            for hash in hashes {
                pool.remove(hash);
            }
        }
    }
}

// =============================================================================
// Task 11.5.2: Real Substrate Transaction Pool Wrapper
// =============================================================================
//
// This wrapper implements our TransactionPool trait for the real Substrate
// sc_transaction_pool, enabling the TransactionPoolBridge to work with either
// MockTransactionPool (for testing) or the real pool (for production).

use crate::substrate::client::{HegemonFullClient, HegemonTransactionPool};
use codec::{Decode, Encode};
use pallet_shielded_pool::family::ShieldedFamilyAction;
use sc_client_api::HeaderBackend;
use sc_transaction_pool_api::{InPoolTransaction, TransactionPool as ScTransactionPool};
use superneo_hegemon::{
    decode_native_tx_leaf_artifact_bytes, verify_native_tx_leaf_artifact_bytes,
};

/// Wrapper around the real Substrate transaction pool (Task 11.5.2)
///
/// This implements our simplified `TransactionPool` trait for the real
/// `sc_transaction_pool::TransactionPoolHandle`, bridging between our
/// network layer and Substrate's transaction pool.
pub struct SubstrateTransactionPoolWrapper {
    /// The real Substrate transaction pool
    pool: Arc<HegemonTransactionPool>,
    /// Client for querying chain info (best block hash)
    client: Arc<HegemonFullClient>,
    /// Pool capacity (informational, actual limit is in Substrate pool config)
    capacity: usize,
    /// Cache full-verification verdicts for external gossip so duplicates do not
    /// repeatedly burn native verifier CPU before pool admission.
    external_verification_cache: Arc<ParkingMutex<ExternalVerificationCache>>,
    /// Maximum cached external-verification verdicts.
    external_verification_cache_capacity: usize,
}

impl SubstrateTransactionPoolWrapper {
    /// Create a new wrapper around the real Substrate pool
    pub fn new(
        pool: Arc<HegemonTransactionPool>,
        client: Arc<HegemonFullClient>,
        capacity: usize,
    ) -> Self {
        Self {
            pool,
            client,
            capacity,
            external_verification_cache: Arc::new(ParkingMutex::new(
                ExternalVerificationCache::default(),
            )),
            external_verification_cache_capacity: capacity.max(1024),
        }
    }

    /// Get a reference to the underlying Substrate pool
    pub fn inner(&self) -> &Arc<HegemonTransactionPool> {
        &self.pool
    }

    /// Compute transaction hash (blake2_256)
    fn compute_hash(data: &[u8]) -> [u8; 32] {
        use sp_core::hashing::blake2_256;
        blake2_256(data)
    }

    fn cached_external_verification(&self, hash: &[u8; 32]) -> Option<Result<(), PoolError>> {
        let cache = self.external_verification_cache.lock();
        cache.get(hash).map(|verdict| match verdict {
            ExternalVerificationVerdict::Valid => Ok(()),
            ExternalVerificationVerdict::Invalid(error) => {
                Err(PoolError::InvalidTransaction(error))
            }
        })
    }

    fn record_external_verification(&self, hash: [u8; 32], verdict: ExternalVerificationVerdict) {
        let mut cache = self.external_verification_cache.lock();
        cache.insert(self.external_verification_cache_capacity, hash, verdict);
    }
}

fn prevalidate_external_gossip_extrinsic(
    extrinsic: &runtime::UncheckedExtrinsic,
) -> Result<(), PoolError> {
    let runtime::RuntimeCall::Kernel(pallet_kernel::Call::submit_action { envelope }) =
        &extrinsic.function
    else {
        return Ok(());
    };

    if envelope.family_id != pallet_shielded_pool::family::FAMILY_SHIELDED_POOL {
        return Ok(());
    }

    let action = pallet_shielded_pool::family::ShieldedFamilyAction::decode_envelope(envelope)
        .map_err(|err| {
            PoolError::InvalidTransaction(format!(
                "failed to decode shielded kernel envelope: {err:?}"
            ))
        })?;

    match action {
        ShieldedFamilyAction::TransferInline { args, .. } => {
            prevalidate_native_tx_leaf_artifact(&args.proof)
        }
        ShieldedFamilyAction::TransferSidecar { args, .. } => {
            prevalidate_native_tx_leaf_artifact(&args.proof)
        }
        _ => Ok(()),
    }
}

fn prevalidate_native_tx_leaf_artifact(proof_bytes: &[u8]) -> Result<(), PoolError> {
    let artifact = decode_native_tx_leaf_artifact_bytes(proof_bytes).map_err(|err| {
        PoolError::InvalidTransaction(format!(
            "external native tx-leaf decode failed before pool admission: {err}"
        ))
    })?;
    verify_native_tx_leaf_artifact_bytes(&artifact.tx, &artifact.receipt, proof_bytes).map_err(
        |err| {
            PoolError::InvalidTransaction(format!(
                "external native tx-leaf verification failed before pool admission: {err}"
            ))
        },
    )?;
    Ok(())
}

#[async_trait::async_trait]
impl TransactionPool for SubstrateTransactionPoolWrapper {
    async fn submit(
        &self,
        tx: &[u8],
        source: TransactionSource,
    ) -> Result<SubmissionResult, PoolError> {
        let hash = Self::compute_hash(tx);

        if matches!(source, TransactionSource::External) {
            if let Some(cached) = self.cached_external_verification(&hash) {
                cached?;
            } else if self.contains(&hash) {
                return Err(PoolError::AlreadyInPool(hex::encode(hash)));
            }
        }

        // Basic validation
        if tx.is_empty() {
            return Err(PoolError::InvalidTransaction("Empty transaction".into()));
        }
        if tx.len() > 5 * 1024 * 1024 {
            return Err(PoolError::InvalidTransaction(
                "Transaction too large (>5MB)".into(),
            ));
        }

        // Decode the transaction bytes into an UncheckedExtrinsic
        let extrinsic = match <runtime::UncheckedExtrinsic as Decode>::decode(&mut &tx[..]) {
            Ok(ext) => ext,
            Err(e) => {
                return Err(PoolError::InvalidTransaction(format!(
                    "Failed to decode extrinsic: {:?}",
                    e
                )));
            }
        };

        if extrinsic.is_signed() {
            return Err(PoolError::InvalidTransaction(
                "Signed extrinsics are disabled; submit unsigned kernel actions".into(),
            ));
        }

        if matches!(source, TransactionSource::External) {
            match prevalidate_external_gossip_extrinsic(&extrinsic) {
                Ok(()) => {
                    self.record_external_verification(hash, ExternalVerificationVerdict::Valid);
                }
                Err(err) => {
                    let error = err.to_string();
                    self.record_external_verification(
                        hash,
                        ExternalVerificationVerdict::Invalid(error.clone()),
                    );
                    return Err(PoolError::InvalidTransaction(error));
                }
            }
        }

        // Convert our TransactionSource to Substrate's
        let sc_source = match source {
            TransactionSource::External => sc_transaction_pool_api::TransactionSource::External,
            TransactionSource::Local => sc_transaction_pool_api::TransactionSource::Local,
            TransactionSource::InBlock => sc_transaction_pool_api::TransactionSource::InBlock,
        };

        // Get the best block hash from the client
        let at = self.client.info().best_hash;

        // Submit to the real Substrate pool
        // The pool will validate against the runtime
        match self.pool.submit_one(at, sc_source, extrinsic).await {
            Ok(tx_hash) => {
                tracing::info!(
                    tx_hash = %tx_hash,
                    source = ?source,
                    "Transaction submitted to Substrate pool (Task 11.5.2)"
                );
                Ok(SubmissionResult::success(hash, None))
            }
            Err(e) => {
                let error_msg = format!("{:?}", e);
                tracing::warn!(
                    tx_hash = %hex::encode(hash),
                    source = ?source,
                    error = %error_msg,
                    "Transaction rejected by Substrate pool"
                );

                // Map Substrate pool errors to our PoolError
                if error_msg.contains("already in pool") || error_msg.contains("Already imported") {
                    Err(PoolError::AlreadyInPool(hex::encode(hash)))
                } else if error_msg.contains("full") {
                    Err(PoolError::PoolFull)
                } else {
                    Err(PoolError::InvalidTransaction(error_msg))
                }
            }
        }
    }

    fn contains(&self, hash: &[u8; 32]) -> bool {
        // Convert our hash to Substrate's H256
        let h256 = sp_core::H256::from_slice(hash);
        // Check if transaction is in the pool by looking at ready transactions
        self.pool.ready().any(|tx| {
            let tx_hash: sp_core::H256 = *InPoolTransaction::hash(&*tx);
            tx_hash == h256
        })
    }

    fn pool_size(&self) -> usize {
        let status = self.pool.status();
        status.ready + status.future
    }

    fn pool_capacity(&self) -> usize {
        self.capacity
    }

    fn remove(&self, _hash: &[u8; 32]) -> bool {
        // The real Substrate pool doesn't expose a direct remove method.
        // Transactions are removed when:
        // 1. Included in a block (via maintain())
        // 2. Become stale (via prune())
        // For now, we just return false to indicate removal isn't directly supported
        false
    }

    fn ready_transactions(&self) -> Vec<Vec<u8>> {
        // Get all ready transactions from the pool
        self.pool
            .ready()
            .map(|tx| InPoolTransaction::data(&*tx).encode())
            .collect()
    }

    fn clear_transactions(&self, _hashes: &[[u8; 32]]) {
        // The real pool clears transactions automatically when:
        // 1. maintain() is called with new block notifications
        // 2. Transactions become stale
        //
        // We don't need to manually clear - the maintenance task handles this.
        // See the txpool-maintenance task in service.rs
        tracing::debug!(
            "clear_transactions called on SubstrateTransactionPoolWrapper - handled by maintenance task"
        );
    }
}

/// Bridge between NetworkBridge and TransactionPool
///
/// Handles the flow of transactions from the network to the pool:
/// 1. Receives raw transaction bytes from NetworkBridge
/// 2. Decodes and validates basic structure
/// 3. Submits to the transaction pool
/// 4. Tracks statistics and handles errors
pub struct TransactionPoolBridge<P: TransactionPool> {
    /// The underlying transaction pool
    pool: Arc<P>,
    /// Pending transactions queue (for batch processing)
    pending: Arc<Mutex<VecDeque<PendingTransaction>>>,
    /// Statistics
    stats: Arc<PoolBridgeStats>,
    /// Maximum pending queue size
    max_pending: usize,
}

impl<P: TransactionPool> TransactionPoolBridge<P> {
    /// Create a new pool bridge
    pub fn new(pool: Arc<P>) -> Self {
        Self {
            pool,
            pending: Arc::new(Mutex::new(VecDeque::new())),
            stats: Arc::new(PoolBridgeStats::new()),
            max_pending: 1000,
        }
    }

    /// Create with custom pending queue size
    pub fn with_max_pending(pool: Arc<P>, max_pending: usize) -> Self {
        Self {
            pool,
            pending: Arc::new(Mutex::new(VecDeque::new())),
            stats: Arc::new(PoolBridgeStats::new()),
            max_pending,
        }
    }

    /// Get statistics
    pub fn stats(&self) -> Arc<PoolBridgeStats> {
        Arc::clone(&self.stats)
    }

    /// Queue a transaction for submission
    pub async fn queue_transaction(&self, data: Vec<u8>, peer_id: Option<PeerId>) {
        self.stats
            .transactions_received
            .fetch_add(1, Ordering::Relaxed);

        let mut pending = self.pending.lock().await;

        // Drop oldest if queue is full
        if pending.len() >= self.max_pending {
            pending.pop_front();
            tracing::warn!("Pending transaction queue full, dropping oldest");
        }

        pending.push_back(PendingTransaction {
            data,
            peer_id,
            received_at: std::time::Instant::now(),
            source: TransactionSource::External,
        });
    }

    /// Queue transactions from network bridge
    pub async fn queue_from_bridge(&self, transactions: Vec<(PeerId, Vec<u8>)>) {
        for (peer_id, data) in transactions {
            self.queue_transaction(data, Some(peer_id)).await;
        }
    }

    /// Submit a single transaction directly
    pub async fn submit_transaction(
        &self,
        data: &[u8],
        peer_id: Option<&PeerId>,
    ) -> Result<SubmissionResult, PoolError> {
        self.stats
            .transactions_received
            .fetch_add(1, Ordering::Relaxed);

        match self.pool.submit(data, TransactionSource::External).await {
            Ok(result) => {
                self.stats
                    .transactions_submitted
                    .fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    tx_hash = %hex::encode(result.hash),
                    peer = peer_id.map(|p| hex::encode(p)).unwrap_or_else(|| "local".to_string()),
                    "Transaction submitted to pool"
                );
                Ok(result)
            }
            Err(e) => {
                self.stats
                    .transactions_rejected
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    tx_hash = %hex::encode(sp_core::hashing::blake2_256(data)),
                    error = %e,
                    peer = peer_id.map(|p| hex::encode(p)).unwrap_or_else(|| "local".to_string()),
                    "Transaction rejected"
                );
                Err(e)
            }
        }
    }

    /// Process all pending transactions
    ///
    /// Returns the number of successfully submitted transactions
    pub async fn process_pending(&self) -> usize {
        let mut pending = self.pending.lock().await;
        let mut submitted = 0;

        while let Some(tx) = pending.pop_front() {
            match self.pool.submit(&tx.data, tx.source).await {
                Ok(result) if result.accepted => {
                    submitted += 1;
                    tracing::info!(
                        tx_hash = %hex::encode(result.hash),
                        peer = tx
                            .peer_id
                            .map(hex::encode)
                            .unwrap_or_else(|| "unknown".to_string()),
                        source = ?tx.source,
                        latency_ms = tx.received_at.elapsed().as_millis(),
                        "Pending transaction submitted"
                    );
                }
                Ok(result) => {
                    tracing::warn!(
                        tx_hash = %hex::encode(result.hash),
                        peer = tx
                            .peer_id
                            .map(hex::encode)
                            .unwrap_or_else(|| "unknown".to_string()),
                        source = ?tx.source,
                        error = result.error.as_deref().unwrap_or("unknown"),
                        "Pending transaction rejected"
                    );
                    self.stats
                        .transactions_rejected
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::warn!(
                        tx_hash = %hex::encode(sp_core::hashing::blake2_256(&tx.data)),
                        peer = tx
                            .peer_id
                            .map(hex::encode)
                            .unwrap_or_else(|| "unknown".to_string()),
                        source = ?tx.source,
                        error = %e,
                        "Failed to submit pending transaction"
                    );
                    self.stats
                        .transactions_rejected
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        submitted
    }

    /// Get current pending count
    pub async fn pending_count(&self) -> usize {
        self.pending.lock().await.len()
    }

    /// Get pool size
    pub fn pool_size(&self) -> usize {
        self.pool.pool_size()
    }

    /// Get pool capacity
    pub fn pool_capacity(&self) -> usize {
        self.pool.pool_capacity()
    }

    /// Get ready transactions for block production (Task 11.3)
    ///
    /// Returns all transactions that are ready to be included in a block.
    /// This is called by the mining worker to populate block templates.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // In mining worker:
    /// let txs = pool_bridge.ready_for_block(100);
    /// let template = BlockTemplate::new(parent_hash, block_number, difficulty)
    ///     .with_extrinsics(txs);
    /// ```
    pub fn ready_for_block(&self, max_txs: usize) -> Vec<Vec<u8>> {
        let mut txs = self.pool.ready_transactions();
        txs.truncate(max_txs);
        txs
    }

    /// Clear transactions after block is mined (Task 11.3)
    ///
    /// Removes transactions that were included in a mined block.
    /// Called by the mining worker after successful block import.
    pub fn clear_included(&self, txs: &[Vec<u8>]) {
        let hashes: Vec<[u8; 32]> = txs
            .iter()
            .map(|tx| sp_core::hashing::blake2_256(tx))
            .collect();
        self.pool.clear_transactions(&hashes);

        tracing::debug!(
            cleared_count = hashes.len(),
            pool_size = self.pool_size(),
            "Cleared included transactions from pool (Task 11.3)"
        );
    }

    /// Get a reference to the underlying pool
    pub fn pool(&self) -> &Arc<P> {
        &self.pool
    }
}

/// Configuration for transaction pool bridge
#[derive(Debug, Clone)]
pub struct TransactionPoolConfig {
    /// Maximum pool capacity
    pub capacity: usize,
    /// Maximum pending queue size
    pub max_pending: usize,
    /// Processing interval in milliseconds
    pub process_interval_ms: u64,
    /// Enable verbose logging
    pub verbose: bool,
}

impl Default for TransactionPoolConfig {
    fn default() -> Self {
        Self {
            capacity: 4096,
            max_pending: 1000,
            process_interval_ms: 100,
            verbose: false,
        }
    }
}

impl TransactionPoolConfig {
    /// Create from environment variables
    pub fn from_env() -> Self {
        let capacity = std::env::var("HEGEMON_POOL_CAPACITY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(4096);

        let max_pending = std::env::var("HEGEMON_POOL_MAX_PENDING")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000);

        let process_interval_ms = std::env::var("HEGEMON_POOL_INTERVAL_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        let verbose = std::env::var("HEGEMON_POOL_VERBOSE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        Self {
            capacity,
            max_pending,
            process_interval_ms,
            verbose,
        }
    }
}

/// Spawn the transaction pool processing task
///
/// This task periodically:
/// 1. Drains transactions from the NetworkBridge
/// 2. Queues them in the TransactionPoolBridge
/// 3. Processes pending transactions
pub async fn spawn_pool_processor<P: TransactionPool + 'static>(
    pool_bridge: Arc<TransactionPoolBridge<P>>,
    mut rx: tokio::sync::mpsc::Receiver<Vec<(PeerId, Vec<u8>)>>,
    config: TransactionPoolConfig,
) {
    let interval = tokio::time::Duration::from_millis(config.process_interval_ms);
    let mut process_timer = tokio::time::interval(interval);

    tracing::info!(
        capacity = config.capacity,
        max_pending = config.max_pending,
        interval_ms = config.process_interval_ms,
        "Transaction pool processor started"
    );

    loop {
        tokio::select! {
            // Receive transactions from network bridge
            Some(transactions) = rx.recv() => {
                pool_bridge.queue_from_bridge(transactions).await;

                if config.verbose {
                    tracing::debug!(
                        pending = pool_bridge.pending_count().await,
                        "Queued transactions from network"
                    );
                }
            }

            // Periodic processing
            _ = process_timer.tick() => {
                let submitted = pool_bridge.process_pending().await;

                if submitted > 0 && config.verbose {
                    let stats = pool_bridge.stats().snapshot();
                    tracing::debug!(
                        submitted = submitted,
                        total_received = stats.transactions_received,
                        total_submitted = stats.transactions_submitted,
                        total_rejected = stats.transactions_rejected,
                        pool_size = pool_bridge.pool_size(),
                        "Processed pending transactions"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Encode;
    use superneo_hegemon::{
        build_native_tx_leaf_artifact_bytes, decode_native_tx_leaf_artifact_bytes,
        encode_native_tx_leaf_artifact_bytes,
    };
    use transaction_circuit::constants::{CIRCUIT_MERKLE_DEPTH, NATIVE_ASSET_ID};
    use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, HashFelt};
    use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
    use transaction_circuit::witness::TransactionWitness;

    #[tokio::test]
    async fn test_mock_pool_submit() {
        let pool = MockTransactionPool::new(100);

        let tx = vec![1, 2, 3, 4, 5];
        let result = pool.submit(&tx, TransactionSource::External).await.unwrap();

        assert!(result.accepted);
        assert_eq!(pool.pool_size(), 1);
    }

    #[tokio::test]
    async fn test_mock_pool_duplicate() {
        let pool = MockTransactionPool::new(100);

        let tx = vec![1, 2, 3, 4, 5];
        pool.submit(&tx, TransactionSource::External).await.unwrap();

        // Submit same transaction again
        let result = pool.submit(&tx, TransactionSource::External).await;
        assert!(matches!(result, Err(PoolError::AlreadyInPool(_))));
    }

    #[tokio::test]
    async fn test_mock_pool_capacity() {
        let pool = MockTransactionPool::new(2);

        pool.submit(&[1, 2, 3], TransactionSource::External)
            .await
            .unwrap();
        pool.submit(&[4, 5, 6], TransactionSource::External)
            .await
            .unwrap();

        // Third should fail
        let result = pool.submit(&[7, 8, 9], TransactionSource::External).await;
        assert!(matches!(result, Err(PoolError::PoolFull)));
    }

    #[tokio::test]
    async fn test_mock_pool_empty_tx() {
        let pool = MockTransactionPool::new(100);

        let result = pool.submit(&[], TransactionSource::External).await;
        assert!(matches!(result, Err(PoolError::InvalidTransaction(_))));
    }

    #[tokio::test]
    async fn test_pool_bridge_queue() {
        let pool = Arc::new(MockTransactionPool::new(100));
        let bridge = TransactionPoolBridge::new(pool);

        bridge.queue_transaction(vec![1, 2, 3], None).await;
        bridge.queue_transaction(vec![4, 5, 6], None).await;

        assert_eq!(bridge.pending_count().await, 2);

        let submitted = bridge.process_pending().await;
        assert_eq!(submitted, 2);
        assert_eq!(bridge.pending_count().await, 0);
        assert_eq!(bridge.pool_size(), 2);
    }

    #[tokio::test]
    async fn test_pool_bridge_submit_direct() {
        let pool = Arc::new(MockTransactionPool::new(100));
        let bridge = TransactionPoolBridge::new(pool);

        let result = bridge.submit_transaction(&[1, 2, 3], None).await.unwrap();
        assert!(result.accepted);
        assert_eq!(bridge.pool_size(), 1);
    }

    #[tokio::test]
    async fn test_pool_bridge_stats() {
        let pool = Arc::new(MockTransactionPool::new(100));
        let bridge = TransactionPoolBridge::new(pool);

        bridge.submit_transaction(&[1, 2, 3], None).await.unwrap();
        bridge.submit_transaction(&[4, 5, 6], None).await.unwrap();

        // Submit duplicate
        let _ = bridge.submit_transaction(&[1, 2, 3], None).await;

        let stats = bridge.stats().snapshot();
        assert_eq!(stats.transactions_received, 3);
        assert_eq!(stats.transactions_submitted, 2);
        assert_eq!(stats.transactions_rejected, 1);
    }

    #[test]
    fn test_submission_result() {
        let hash = [42u8; 32];

        let success = SubmissionResult::success(hash, Some(100));
        assert!(success.accepted);
        assert!(success.error.is_none());
        assert_eq!(success.priority, Some(100));

        let failure = SubmissionResult::failure(hash, "invalid nonce");
        assert!(!failure.accepted);
        assert_eq!(failure.error, Some("invalid nonce".to_string()));
    }

    #[test]
    fn test_config_default() {
        let config = TransactionPoolConfig::default();
        assert_eq!(config.capacity, 4096);
        assert_eq!(config.max_pending, 1000);
        assert_eq!(config.process_interval_ms, 100);
        assert!(!config.verbose);
    }

    // Task 11.3: Transaction pool wiring tests

    #[tokio::test]
    async fn test_pool_ready_transactions() {
        let pool = MockTransactionPool::new(100);

        // Submit transactions
        pool.submit(&[1, 2, 3], TransactionSource::External)
            .await
            .unwrap();
        pool.submit(&[4, 5, 6], TransactionSource::External)
            .await
            .unwrap();
        pool.submit(&[7, 8, 9], TransactionSource::External)
            .await
            .unwrap();

        // Get ready transactions
        let ready = pool.ready_transactions();
        assert_eq!(ready.len(), 3);

        // All submitted transactions should be ready
        assert!(ready.iter().any(|tx| tx == &[1, 2, 3]));
        assert!(ready.iter().any(|tx| tx == &[4, 5, 6]));
        assert!(ready.iter().any(|tx| tx == &[7, 8, 9]));
    }

    #[tokio::test]
    async fn test_pool_clear_transactions() {
        let pool = MockTransactionPool::new(100);

        // Submit transactions
        pool.submit(&[1, 2, 3], TransactionSource::External)
            .await
            .unwrap();
        pool.submit(&[4, 5, 6], TransactionSource::External)
            .await
            .unwrap();
        pool.submit(&[7, 8, 9], TransactionSource::External)
            .await
            .unwrap();

        assert_eq!(pool.pool_size(), 3);

        // Clear some transactions
        let hash1 = sp_core::hashing::blake2_256(&[1, 2, 3]);
        let hash2 = sp_core::hashing::blake2_256(&[4, 5, 6]);
        pool.clear_transactions(&[hash1, hash2]);

        assert_eq!(pool.pool_size(), 1);

        // Only the third transaction should remain
        let ready = pool.ready_transactions();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], vec![7, 8, 9]);
    }

    #[tokio::test]
    async fn test_bridge_ready_for_block() {
        let pool = Arc::new(MockTransactionPool::new(100));
        let bridge = TransactionPoolBridge::new(pool);

        // Submit transactions directly to pool
        bridge.submit_transaction(&[1, 2, 3], None).await.unwrap();
        bridge.submit_transaction(&[4, 5, 6], None).await.unwrap();
        bridge.submit_transaction(&[7, 8, 9], None).await.unwrap();

        // Get ready transactions with limit
        let ready = bridge.ready_for_block(2);
        assert_eq!(ready.len(), 2);

        // Get all ready
        let ready_all = bridge.ready_for_block(100);
        assert_eq!(ready_all.len(), 3);
    }

    #[tokio::test]
    async fn test_bridge_clear_included() {
        let pool = Arc::new(MockTransactionPool::new(100));
        let bridge = TransactionPoolBridge::new(pool);

        // Submit transactions
        let tx1 = vec![1, 2, 3];
        let tx2 = vec![4, 5, 6];
        let tx3 = vec![7, 8, 9];

        bridge.submit_transaction(&tx1, None).await.unwrap();
        bridge.submit_transaction(&tx2, None).await.unwrap();
        bridge.submit_transaction(&tx3, None).await.unwrap();

        assert_eq!(bridge.pool_size(), 3);

        // Simulate mining: clear included transactions
        bridge.clear_included(&[tx1.clone(), tx2.clone()]);

        assert_eq!(bridge.pool_size(), 1);

        // Only tx3 should remain
        let ready = bridge.ready_for_block(100);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], tx3);
    }

    #[tokio::test]
    async fn test_mining_with_pool_transactions() {
        // Simulate the full mining flow with transaction pool
        let pool = Arc::new(MockTransactionPool::new(100));
        let bridge = TransactionPoolBridge::new(pool);

        // 1. Submit transactions (simulating RPC submission)
        bridge
            .submit_transaction(&[0xaa, 0xbb, 0xcc], None)
            .await
            .unwrap();
        bridge
            .submit_transaction(&[0xdd, 0xee, 0xff], None)
            .await
            .unwrap();

        // 2. Mining worker gets ready transactions
        let ready = bridge.ready_for_block(100);
        assert_eq!(ready.len(), 2);

        // 3. Mining worker would create block template with these transactions
        // and mine a block...

        // 4. After successful mining, clear included transactions
        bridge.clear_included(&ready);

        // 5. Pool should now be empty
        assert_eq!(bridge.pool_size(), 0);
        assert_eq!(bridge.ready_for_block(100).len(), 0);
    }

    #[test]
    fn external_kernel_transfer_requires_valid_native_tx_leaf_artifact() {
        let witness = sample_witness(31);
        let built = build_native_tx_leaf_artifact_bytes(&witness).expect("native tx leaf bytes");
        let extrinsic = kernel_transfer_extrinsic_with_proof(built.artifact_bytes);
        assert!(prevalidate_external_gossip_extrinsic(&extrinsic).is_ok());
    }

    #[test]
    fn external_kernel_transfer_rejects_invalid_native_tx_leaf_artifact() {
        let witness = sample_witness(32);
        let built = build_native_tx_leaf_artifact_bytes(&witness).expect("native tx leaf bytes");
        let mut artifact =
            decode_native_tx_leaf_artifact_bytes(&built.artifact_bytes).expect("decode artifact");
        artifact.stark_proof[0] ^= 0x5a;
        let tampered =
            encode_native_tx_leaf_artifact_bytes(&artifact).expect("encode tampered artifact");
        let extrinsic = kernel_transfer_extrinsic_with_proof(tampered);
        assert!(matches!(
            prevalidate_external_gossip_extrinsic(&extrinsic),
            Err(PoolError::InvalidTransaction(_))
        ));
    }

    fn kernel_transfer_extrinsic_with_proof(proof_bytes: Vec<u8>) -> runtime::UncheckedExtrinsic {
        let decoded = decode_native_tx_leaf_artifact_bytes(&proof_bytes).expect("decode tx leaf");
        let args = pallet_shielded_pool::family::ShieldedTransferInlineArgs {
            proof: proof_bytes,
            commitments: decoded.tx.commitments.clone(),
            ciphertexts: vec![
                pallet_shielded_pool::types::EncryptedNote::default();
                decoded.tx.commitments.len()
            ],
            anchor: [7u8; 48],
            balance_slot_asset_ids: [NATIVE_ASSET_ID, u64::MAX, u64::MAX, u64::MAX],
            binding_hash: [9u8; 64],
            stablecoin: None,
            fee: 5,
        };
        let envelope = pallet_shielded_pool::family::build_envelope(
            runtime::manifest::default_version_binding(),
            pallet_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
            decoded.tx.nullifiers,
            args.encode(),
        );
        runtime::UncheckedExtrinsic::new_unsigned(runtime::RuntimeCall::Kernel(
            pallet_kernel::Call::submit_action { envelope },
        ))
    }

    fn sample_witness(seed: u8) -> TransactionWitness {
        let sk_spend = [seed.wrapping_add(42); 32];
        let pk_auth = transaction_circuit::hashing_pq::spend_auth_key_bytes(&sk_spend);
        let input_note_native = NoteData {
            value: 8,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [seed.wrapping_add(2); 32],
            pk_auth,
            rho: [seed.wrapping_add(3); 32],
            r: [seed.wrapping_add(4); 32],
        };
        let input_note_asset = NoteData {
            value: 5,
            asset_id: u64::from(seed) + 100,
            pk_recipient: [seed.wrapping_add(5); 32],
            pk_auth,
            rho: [seed.wrapping_add(6); 32],
            r: [seed.wrapping_add(7); 32],
        };
        let leaf0 = input_note_native.commitment();
        let leaf1 = input_note_asset.commitment();
        let (merkle_path0, merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

        let output_native = OutputNoteWitness {
            note: NoteData {
                value: 3,
                asset_id: NATIVE_ASSET_ID,
                pk_recipient: [seed.wrapping_add(11); 32],
                pk_auth: [seed.wrapping_add(12); 32],
                rho: [seed.wrapping_add(13); 32],
                r: [seed.wrapping_add(14); 32],
            },
        };
        let output_asset = OutputNoteWitness {
            note: NoteData {
                value: 5,
                asset_id: u64::from(seed) + 100,
                pk_recipient: [seed.wrapping_add(21); 32],
                pk_auth: [seed.wrapping_add(22); 32],
                rho: [seed.wrapping_add(23); 32],
                r: [seed.wrapping_add(24); 32],
            },
        };

        TransactionWitness {
            inputs: vec![
                InputNoteWitness {
                    note: input_note_native,
                    position: 0,
                    rho_seed: [seed.wrapping_add(9); 32],
                    merkle_path: merkle_path0,
                },
                InputNoteWitness {
                    note: input_note_asset,
                    position: 1,
                    rho_seed: [seed.wrapping_add(10); 32],
                    merkle_path: merkle_path1,
                },
            ],
            outputs: vec![output_native, output_asset],
            ciphertext_hashes: vec![[0u8; 48]; 2],
            sk_spend,
            merkle_root: felts_to_bytes48(&merkle_root),
            fee: 5,
            value_balance: 0,
            stablecoin: transaction_circuit::StablecoinPolicyBinding::default(),
            version: TransactionWitness::default_version_binding(),
        }
    }

    fn build_two_leaf_merkle_tree(
        leaf0: HashFelt,
        leaf1: HashFelt,
    ) -> (MerklePath, MerklePath, HashFelt) {
        let mut siblings0 = vec![leaf1];
        let mut siblings1 = vec![leaf0];
        let mut current = merkle_node(leaf0, leaf1);
        for _ in 1..CIRCUIT_MERKLE_DEPTH {
            let zero = [transaction_circuit::hashing_pq::Felt::new(0); 6];
            siblings0.push(zero);
            siblings1.push(zero);
            current = merkle_node(current, zero);
        }
        (
            MerklePath {
                siblings: siblings0,
            },
            MerklePath {
                siblings: siblings1,
            },
            current,
        )
    }
}
