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
    async fn submit(&self, tx: &[u8], source: TransactionSource) -> Result<SubmissionResult, PoolError>;
    
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
    async fn submit(&self, tx: &[u8], _source: TransactionSource) -> Result<SubmissionResult, PoolError> {
        let hash = Self::compute_hash(tx);
        
        // Basic validation: non-empty, reasonable size
        if tx.is_empty() {
            return Err(PoolError::InvalidTransaction("Empty transaction".into()));
        }
        if tx.len() > 1024 * 1024 {
            return Err(PoolError::InvalidTransaction("Transaction too large".into()));
        }

        let mut pool = self.transactions.lock().await;
        
        // Check if already present
        if pool.contains_key(&hash) {
            return Err(PoolError::AlreadyInPool(hex::encode(hash)));
        }
        
        // Check capacity
        if pool.len() >= self.capacity {
            self.stats.pool_full_rejections.fetch_add(1, Ordering::Relaxed);
            return Err(PoolError::PoolFull);
        }
        
        // Add to pool
        pool.insert(hash, tx.to_vec());
        self.stats.transactions_submitted.fetch_add(1, Ordering::Relaxed);
        
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
        self.stats.transactions_received.fetch_add(1, Ordering::Relaxed);
        
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
        self.stats.transactions_received.fetch_add(1, Ordering::Relaxed);
        
        match self.pool.submit(data, TransactionSource::External).await {
            Ok(result) => {
                self.stats.transactions_submitted.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    tx_hash = %hex::encode(result.hash),
                    peer = peer_id.map(|p| hex::encode(p)).unwrap_or_else(|| "local".to_string()),
                    "Transaction submitted to pool"
                );
                Ok(result)
            }
            Err(e) => {
                self.stats.transactions_rejected.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
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
                    tracing::debug!(
                        tx_hash = %hex::encode(result.hash),
                        latency_ms = tx.received_at.elapsed().as_millis(),
                        "Pending transaction submitted"
                    );
                }
                Ok(result) => {
                    tracing::debug!(
                        tx_hash = %hex::encode(result.hash),
                        error = result.error.as_deref().unwrap_or("unknown"),
                        "Pending transaction rejected"
                    );
                    self.stats.transactions_rejected.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        "Failed to submit pending transaction"
                    );
                    self.stats.transactions_rejected.fetch_add(1, Ordering::Relaxed);
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
        let hashes: Vec<[u8; 32]> = txs.iter()
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
        
        pool.submit(&[1, 2, 3], TransactionSource::External).await.unwrap();
        pool.submit(&[4, 5, 6], TransactionSource::External).await.unwrap();
        
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
        pool.submit(&[1, 2, 3], TransactionSource::External).await.unwrap();
        pool.submit(&[4, 5, 6], TransactionSource::External).await.unwrap();
        pool.submit(&[7, 8, 9], TransactionSource::External).await.unwrap();
        
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
        pool.submit(&[1, 2, 3], TransactionSource::External).await.unwrap();
        pool.submit(&[4, 5, 6], TransactionSource::External).await.unwrap();
        pool.submit(&[7, 8, 9], TransactionSource::External).await.unwrap();
        
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
        bridge.submit_transaction(&[0xaa, 0xbb, 0xcc], None).await.unwrap();
        bridge.submit_transaction(&[0xdd, 0xee, 0xff], None).await.unwrap();
        
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
}
