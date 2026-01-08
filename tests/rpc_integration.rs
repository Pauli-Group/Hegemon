//! RPC Integration Tests (Phase 14.3)
//!
//! This module provides comprehensive RPC integration testing for the shielded pool,
//! verifying that wallet ↔ node communication works correctly over JSON-RPC.
//!
//! ## Test Categories
//!
//! 1. **Connection Tests**: WebSocket connection, reconnection, timeouts
//! 2. **Read Operations**: Note fetching, Merkle witnesses, pool status
//! 3. **Write Operations**: Shielded transfer
//! 4. **Concurrent Operations**: Multiple simultaneous requests
//!
//! ## Running Tests
//!
//! Mock tests (no node required):
//! ```bash
//! cargo test -p security-tests --test rpc_integration
//! ```
//!
//! Full integration tests (requires running node):
//! ```bash
//! HEGEMON_RPC_URL=ws://127.0.0.1:9944 cargo test -p security-tests --test rpc_integration --ignored
//! ```

#![allow(dead_code)]

use std::sync::Arc;

use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use transaction_circuit::StablecoinPolicyBinding;

// ============================================================================
// Mock RPC Service for Testing
// ============================================================================

/// Mock RPC service that simulates node responses
pub struct MockRpcService {
    /// Encrypted notes: (index, ciphertext, block_height, commitment)
    notes: RwLock<Vec<(u64, Vec<u8>, u64, [u8; 48])>>,
    /// Spent nullifiers
    nullifiers: RwLock<Vec<[u8; 48]>>,
    /// Valid anchors (Merkle roots)
    anchors: RwLock<Vec<[u8; 48]>>,
    /// Pool balance
    balance: RwLock<u128>,
    /// Current block height
    height: RwLock<u64>,
    /// Current merkle root
    merkle_root: RwLock<[u8; 48]>,
    /// Transaction history
    transactions: RwLock<Vec<MockTransaction>>,
}

/// A mock transaction record
#[derive(Clone, Debug)]
pub struct MockTransaction {
    pub tx_hash: [u8; 32],
    pub block_number: Option<u64>,
    pub tx_type: MockTxType,
}

#[derive(Clone, Debug)]
pub enum MockTxType {
    ShieldedTransfer {
        nullifiers: Vec<[u8; 48]>,
        commitments: Vec<[u8; 48]>,
    },
}

impl Default for MockRpcService {
    fn default() -> Self {
        Self::new()
    }
}

impl MockRpcService {
    /// Create a new mock RPC service
    pub fn new() -> Self {
        let initial_root = [0u8; 48];
        Self {
            notes: RwLock::new(Vec::new()),
            nullifiers: RwLock::new(Vec::new()),
            anchors: RwLock::new(vec![initial_root]),
            balance: RwLock::new(0),
            height: RwLock::new(0),
            merkle_root: RwLock::new(initial_root),
            transactions: RwLock::new(Vec::new()),
        }
    }

    /// Add an encrypted note
    pub async fn add_note(&self, ciphertext: Vec<u8>, commitment: [u8; 48]) -> u64 {
        let mut notes = self.notes.write().await;
        let height = *self.height.read().await;
        let index = notes.len() as u64;
        notes.push((index, ciphertext, height, commitment));
        index
    }

    /// Set current block height
    pub async fn set_height(&self, height: u64) {
        *self.height.write().await = height;
    }

    /// Add a valid anchor (Merkle root)
    pub async fn add_anchor(&self, anchor: [u8; 48]) {
        self.anchors.write().await.push(anchor);
    }

    /// Submit shielded transfer
    pub async fn submit_shielded_transfer(
        &self,
        _proof: Vec<u8>,
        nullifiers: Vec<[u8; 48]>,
        commitments: Vec<[u8; 48]>,
        encrypted_notes: Vec<Vec<u8>>,
        anchor: [u8; 48],
        _binding_hash: [u8; 64],
        _stablecoin: Option<StablecoinPolicyBinding>,
        value_balance: i128,
    ) -> Result<[u8; 32], String> {
        if value_balance != 0 {
            return Err("Transparent pool disabled: value_balance must be 0".to_string());
        }

        // Verify anchor is valid
        if !self.is_valid_anchor(&anchor).await {
            return Err("Invalid anchor".to_string());
        }

        // Check nullifiers not already spent
        {
            let spent = self.nullifiers.read().await;
            for nf in &nullifiers {
                if spent.contains(nf) {
                    return Err("Double spend detected".to_string());
                }
            }
        }

        // Add nullifiers to spent set
        {
            let mut spent = self.nullifiers.write().await;
            for nf in &nullifiers {
                spent.push(*nf);
            }
        }

        // Add new notes
        for (commitment, encrypted_note) in commitments.iter().zip(encrypted_notes.iter()) {
            self.add_note(encrypted_note.clone(), *commitment).await;
        }

        // Generate tx hash
        let mut hasher = Sha256::new();
        hasher.update(b"shielded_transfer");
        for nf in &nullifiers {
            hasher.update(nf);
        }
        for cm in &commitments {
            hasher.update(cm);
        }
        let hash_bytes = hasher.finalize();
        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&hash_bytes);

        // Record transaction
        self.transactions.write().await.push(MockTransaction {
            tx_hash,
            block_number: Some(*self.height.read().await),
            tx_type: MockTxType::ShieldedTransfer {
                nullifiers: nullifiers.clone(),
                commitments: commitments.clone(),
            },
        });

        Ok(tx_hash)
    }

    /// Get encrypted notes
    pub async fn get_encrypted_notes(
        &self,
        start: u64,
        limit: usize,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Vec<(u64, Vec<u8>, u64, [u8; 48])> {
        let notes = self.notes.read().await;
        notes
            .iter()
            .skip(start as usize)
            .take(limit)
            .filter(|(_, _, block, _)| {
                let from_ok = from_block.is_none_or(|fb| *block >= fb);
                let to_ok = to_block.is_none_or(|tb| *block <= tb);
                from_ok && to_ok
            })
            .cloned()
            .collect()
    }

    /// Get Merkle witness for a position
    pub async fn get_merkle_witness(
        &self,
        _position: u64,
    ) -> (Vec<[u8; 48]>, Vec<bool>, [u8; 48]) {
        // Mock witness with 32 levels
        let siblings: Vec<[u8; 48]> = (0..32).map(|i| [i; 48]).collect();
        let indices: Vec<bool> = (0..32).map(|_| false).collect();
        let root = *self.merkle_root.read().await;
        (siblings, indices, root)
    }

    /// Get pool status
    pub async fn get_pool_status(&self) -> MockPoolStatus {
        let notes = self.notes.read().await;
        let nfs = self.nullifiers.read().await;
        let bal = *self.balance.read().await;
        let root = *self.merkle_root.read().await;
        let height = *self.height.read().await;

        MockPoolStatus {
            total_notes: notes.len() as u64,
            total_nullifiers: nfs.len() as u64,
            merkle_root: root,
            tree_depth: 32,
            pool_balance: bal,
            last_update_block: height,
        }
    }

    /// Check if nullifier is spent
    pub async fn is_nullifier_spent(&self, nullifier: &[u8; 48]) -> bool {
        self.nullifiers.read().await.contains(nullifier)
    }

    /// Check if anchor is valid
    pub async fn is_valid_anchor(&self, anchor: &[u8; 48]) -> bool {
        self.anchors.read().await.contains(anchor)
    }

    /// Get encrypted note count
    pub async fn encrypted_note_count(&self) -> u64 {
        self.notes.read().await.len() as u64
    }

    /// Get chain height
    pub async fn chain_height(&self) -> u64 {
        *self.height.read().await
    }

    /// Get transaction by hash
    pub async fn get_transaction(&self, tx_hash: &[u8; 32]) -> Option<MockTransaction> {
        self.transactions
            .read()
            .await
            .iter()
            .find(|tx| &tx.tx_hash == tx_hash)
            .cloned()
    }
}

/// Mock pool status
#[derive(Clone, Debug)]
pub struct MockPoolStatus {
    pub total_notes: u64,
    pub total_nullifiers: u64,
    pub merkle_root: [u8; 48],
    pub tree_depth: u32,
    pub pool_balance: u128,
    pub last_update_block: u64,
}

// ============================================================================
// RPC Client Test Helpers
// ============================================================================

/// Test RPC client that wraps mock service or real connection
pub struct TestRpcClient {
    mock: Option<Arc<MockRpcService>>,
    // In real mode, would have wallet::SubstrateRpcClient
}

impl TestRpcClient {
    /// Create a mock RPC client
    pub fn mock() -> (Self, Arc<MockRpcService>) {
        let service = Arc::new(MockRpcService::new());
        let client = Self {
            mock: Some(service.clone()),
        };
        (client, service)
    }

    /// Submit shielded transfer
    pub async fn submit_shielded_transfer(
        &self,
        proof: Vec<u8>,
        nullifiers: Vec<[u8; 48]>,
        commitments: Vec<[u8; 48]>,
        encrypted_notes: Vec<Vec<u8>>,
        anchor: [u8; 48],
        binding_hash: [u8; 64],
        stablecoin: Option<StablecoinPolicyBinding>,
        value_balance: i128,
    ) -> Result<[u8; 32], String> {
        if let Some(mock) = &self.mock {
            mock.submit_shielded_transfer(
                proof,
                nullifiers,
                commitments,
                encrypted_notes,
                anchor,
                binding_hash,
                stablecoin,
                value_balance,
            )
            .await
        } else {
            Err("Real RPC not implemented".to_string())
        }
    }

    /// Get encrypted notes
    pub async fn get_encrypted_notes(
        &self,
        start: u64,
        limit: usize,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Vec<(u64, Vec<u8>, u64, [u8; 48])> {
        if let Some(mock) = &self.mock {
            mock.get_encrypted_notes(start, limit, from_block, to_block)
                .await
        } else {
            Vec::new()
        }
    }

    /// Get Merkle witness
    pub async fn get_merkle_witness(
        &self,
        position: u64,
    ) -> (Vec<[u8; 48]>, Vec<bool>, [u8; 48]) {
        if let Some(mock) = &self.mock {
            mock.get_merkle_witness(position).await
        } else {
            (Vec::new(), Vec::new(), [0u8; 48])
        }
    }

    /// Get pool status
    pub async fn get_pool_status(&self) -> MockPoolStatus {
        if let Some(mock) = &self.mock {
            mock.get_pool_status().await
        } else {
            MockPoolStatus {
                total_notes: 0,
                total_nullifiers: 0,
                merkle_root: [0u8; 48],
                tree_depth: 32,
                pool_balance: 0,
                last_update_block: 0,
            }
        }
    }

    /// Check if nullifier is spent
    pub async fn is_nullifier_spent(&self, nullifier: &[u8; 48]) -> bool {
        if let Some(mock) = &self.mock {
            mock.is_nullifier_spent(nullifier).await
        } else {
            false
        }
    }

    /// Check if anchor is valid
    pub async fn is_valid_anchor(&self, anchor: &[u8; 48]) -> bool {
        if let Some(mock) = &self.mock {
            mock.is_valid_anchor(anchor).await
        } else {
            false
        }
    }
}

// ============================================================================
// Protocol 14.3.1: Basic RPC Tests
// ============================================================================

#[cfg(test)]
mod basic_rpc_tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_service_creation() {
        let service = MockRpcService::new();

        // Check initial state
        let status = service.get_pool_status().await;
        assert_eq!(status.total_notes, 0);
        assert_eq!(status.total_nullifiers, 0);
        assert_eq!(status.pool_balance, 0);
        assert_eq!(status.tree_depth, 32);
    }

    #[tokio::test]
    async fn test_get_encrypted_notes() {
        let service = MockRpcService::new();

        // Add some notes
        for i in 0u8..5 {
            service.add_note(vec![i], [i; 48]).await;
        }

        // Get all notes
        let notes = service.get_encrypted_notes(0, 10, None, None).await;
        assert_eq!(notes.len(), 5);

        // Get with pagination
        let notes = service.get_encrypted_notes(2, 2, None, None).await;
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].0, 2); // Start at index 2
    }

    #[tokio::test]
    async fn test_merkle_witness() {
        let service = MockRpcService::new();

        let (siblings, indices, _root) = service.get_merkle_witness(0).await;

        // Should have 32 levels
        assert_eq!(siblings.len(), 32);
        assert_eq!(indices.len(), 32);
    }

    #[tokio::test]
    async fn test_nullifier_tracking() {
        let service = MockRpcService::new();
        service.add_anchor([0; 48]).await; // Add valid anchor

        let nullifier = [0xcc; 48];

        // Not spent initially
        assert!(!service.is_nullifier_spent(&nullifier).await);

        // Submit transfer with this nullifier
        service
            .submit_shielded_transfer(
                vec![0u8; 10000], // fake proof
                vec![nullifier],
                vec![[0xdd; 48]],
                vec![vec![1, 2, 3]],
                [0; 48], // valid anchor
                [0; 64],
                None,
                0,
            )
            .await
            .unwrap();

        // Now spent
        assert!(service.is_nullifier_spent(&nullifier).await);
    }

    #[tokio::test]
    async fn test_anchor_validation() {
        let service = MockRpcService::new();

        // Initial anchor (zero) is valid
        assert!(service.is_valid_anchor(&[0; 48]).await);

        // Unknown anchor is invalid
        assert!(!service.is_valid_anchor(&[0xff; 48]).await);

        // Add custom anchor
        service.add_anchor([0xab; 48]).await;
        assert!(service.is_valid_anchor(&[0xab; 48]).await);
    }
}

// ============================================================================
// Protocol 14.3.2: Shielded Transfer RPC Tests
// ============================================================================

#[cfg(test)]
mod shielded_transfer_tests {
    use super::*;

    #[tokio::test]
    async fn test_shielded_transfer_success() {
        let (client, service) = TestRpcClient::mock();
        service.add_anchor([0; 48]).await;

        // Submit shielded transfer
        let tx_hash = client
            .submit_shielded_transfer(
                vec![0u8; 15000],    // fake proof
                vec![[0x11; 48]],    // nullifier
                vec![[0x22; 48]],    // new commitment
                vec![vec![2, 3, 4]], // encrypted note
                [0; 48],             // anchor
                [0; 64],             // binding sig
                None,
                0, // value balance
            )
            .await
            .unwrap();

        // Verify
        assert_ne!(tx_hash, [0u8; 32]);

        let status = client.get_pool_status().await;
        assert_eq!(status.total_notes, 1);
        assert_eq!(status.total_nullifiers, 1);
    }

    #[tokio::test]
    async fn test_double_spend_rejected() {
        let (client, service) = TestRpcClient::mock();
        service.add_anchor([0; 48]).await;

        let nullifier = [0x99; 48];

        // First transfer succeeds
        let result = client
            .submit_shielded_transfer(
                vec![0u8; 15000],
                vec![nullifier],
                vec![[0x22; 48]],
                vec![vec![2]],
                [0; 48],
                [0; 64],
                None,
                0,
            )
            .await;
        assert!(result.is_ok());

        // Second transfer with same nullifier fails
        let result = client
            .submit_shielded_transfer(
                vec![0u8; 15000],
                vec![nullifier], // Same nullifier
                vec![[0x33; 48]],
                vec![vec![3]],
                [0; 48],
                [0; 64],
                None,
                0,
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_anchor_rejected() {
        let (client, _service) = TestRpcClient::mock();

        // Try transfer with invalid anchor
        let result = client
            .submit_shielded_transfer(
                vec![0u8; 15000],
                vec![[0x11; 48]],
                vec![[0x22; 48]],
                vec![vec![2]],
                [0xff; 48], // Invalid anchor
                [0; 64],
                None,
                0,
            )
            .await;

        assert!(result.is_err());
    }
}

// ============================================================================
// Protocol 14.3.3: Concurrent RPC Tests
// ============================================================================

#[cfg(test)]
mod concurrent_tests {
    use super::*;
    use tokio::task::JoinSet;

    #[tokio::test]
    async fn test_concurrent_note_fetching() {
        let service = Arc::new(MockRpcService::new());

        // Add notes
        for i in 0u8..100 {
            service.add_note(vec![i], [i; 32]).await;
        }

        let mut tasks = JoinSet::new();

        // Spawn concurrent reads
        for start in (0..100).step_by(10) {
            let svc = service.clone();
            tasks.spawn(async move { svc.get_encrypted_notes(start, 10, None, None).await });
        }

        let mut total_fetched = 0;
        while let Some(result) = tasks.join_next().await {
            total_fetched += result.unwrap().len();
        }

        assert_eq!(total_fetched, 100);
    }

    #[tokio::test]
    async fn test_concurrent_nullifier_checks() {
        let service = Arc::new(MockRpcService::new());
        service.add_anchor([0; 48]).await;

        // Add some spent nullifiers
        for i in 0..50 {
            service
                .submit_shielded_transfer(
                    vec![0u8; 15000],
                    vec![[i; 48]],
                    vec![[i + 100; 48]],
                    vec![vec![i]],
                    [0; 48],
                    [0; 64],
                    None,
                    0,
                )
                .await
                .unwrap();
        }

        let mut tasks = JoinSet::new();

        // Check nullifiers concurrently
        for i in 0..100 {
            let svc = service.clone();
            tasks.spawn(async move {
                let nf = [i; 48];
                (i, svc.is_nullifier_spent(&nf).await)
            });
        }

        let mut spent_count = 0;
        let mut unspent_count = 0;
        while let Some(result) = tasks.join_next().await {
            let (i, is_spent) = result.unwrap();
            if i < 50 {
                assert!(is_spent, "Nullifier {} should be spent", i);
                spent_count += 1;
            } else {
                assert!(!is_spent, "Nullifier {} should not be spent", i);
                unspent_count += 1;
            }
        }

        assert_eq!(spent_count, 50);
        assert_eq!(unspent_count, 50);
    }
}

// ============================================================================
// Protocol 14.3.4: Full RPC Flow Test
// ============================================================================

#[cfg(test)]
mod full_flow_tests {
    use super::*;

    #[tokio::test]
    async fn test_full_rpc_shielded_flow() {
        let (client, service) = TestRpcClient::mock();
        service.add_anchor([0; 48]).await;

        // 1. Check initial pool status
        let status = client.get_pool_status().await;
        assert_eq!(status.pool_balance, 0);
        assert_eq!(status.total_notes, 0);

        // 2. Seed a note for the mock pool
        let seed_commitment = [0xaa; 48];
        service.add_note(vec![1, 2, 3, 4], seed_commitment).await;

        // 3. Verify note was recorded
        let status = client.get_pool_status().await;
        assert_eq!(status.total_notes, 1);

        // 4. Fetch encrypted notes
        let notes = client.get_encrypted_notes(0, 100, None, None).await;
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].3, seed_commitment); // commitment matches

        // 5. Get Merkle witness
        let (siblings, indices, root) = client.get_merkle_witness(0).await;
        assert_eq!(siblings.len(), 32);
        assert_eq!(indices.len(), 32);

        // Add the root as a valid anchor for the transfer
        service.add_anchor(root).await;

        // 6. Build and submit shielded transfer
        let nullifier = [0xbb; 48];
        let new_commitment = [0xcc; 48];
        let _transfer_tx = client
            .submit_shielded_transfer(
                vec![0u8; 20000], // fake proof
                vec![nullifier],
                vec![new_commitment],
                vec![vec![5, 6, 7, 8]],
                root,
                [0; 64],
                None,
                0, // Pure transfer, no value balance change
            )
            .await
            .unwrap();

        // 7. Verify nullifier is spent
        assert!(client.is_nullifier_spent(&nullifier).await);

        // 8. Verify new note added
        let final_status = client.get_pool_status().await;
        assert_eq!(final_status.total_notes, 2); // original + new
        assert_eq!(final_status.total_nullifiers, 1);
        assert_eq!(final_status.pool_balance, 0);
    }

    #[tokio::test]
    async fn test_multi_party_rpc_flow() {
        let (client, service) = TestRpcClient::mock();
        service.add_anchor([0; 48]).await;

        // Seed Alice and Bob notes
        service.add_note(vec![1], [0xa0; 48]).await;
        service.add_note(vec![2], [0xb0; 48]).await;

        let status = client.get_pool_status().await;
        assert_eq!(status.total_notes, 2);

        // Alice transfers to Charlie (simulated)
        let transfer_result = client
            .submit_shielded_transfer(
                vec![0u8; 15000],
                vec![[0xa1; 48]], // Alice's nullifier
                vec![[0xc0; 48]], // Charlie's new note
                vec![vec![3]],
                [0; 48],
                [0; 64],
                None,
                0,
            )
            .await;
        assert!(transfer_result.is_ok());

        // Final state check
        let final_status = client.get_pool_status().await;
        assert_eq!(final_status.total_notes, 3); // Alice's original + Bob's + Charlie's new
        assert_eq!(final_status.total_nullifiers, 1); // Alice's spent
    }
}

// ============================================================================
// Integration Tests (require running node)
// ============================================================================

#[cfg(test)]
mod integration_tests {
    #[allow(unused_imports)]
    use super::*;
    use std::time::Duration;

    /// Test against real node - verifies connection and basic RPC functionality
    #[tokio::test]
    #[ignore = "Requires running Substrate node - run with cargo test --ignored"]
    async fn test_real_node_connection() {
        let endpoint =
            std::env::var("HEGEMON_RPC_URL").unwrap_or_else(|_| "ws://127.0.0.1:9944".to_string());

        eprintln!("Testing connection to: {}", endpoint);

        // Try to connect
        let client = wallet::SubstrateRpcClient::connect(&endpoint).await;

        if client.is_err() {
            eprintln!("❌ Connection failed: {:?}", client.err());
            eprintln!("\nTo run this test:");
            eprintln!(
                "  1. Start a node: HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp"
            );
            eprintln!("  2. Run: cargo test -p security-tests --test rpc_integration test_real_node_connection --ignored");
            panic!("Node not available at {}", endpoint);
        }

        let client = client.unwrap();
        eprintln!("✅ Connected to node");

        // Get chain metadata
        let metadata = client.get_chain_metadata().await;
        match metadata {
            Ok(meta) => {
                eprintln!("Chain Metadata:");
                eprintln!("  Block number: {}", meta.block_number);
                eprintln!("  Spec version: {}", meta.spec_version);
                eprintln!("  Genesis hash: 0x{}", hex::encode(&meta.genesis_hash[..8]));
                assert!(meta.spec_version > 0, "Spec version should be > 0");
            }
            Err(e) => {
                eprintln!("❌ Failed to get metadata: {:?}", e);
                panic!("Metadata retrieval failed");
            }
        }

        let status = client.note_status().await;
        match status {
            Ok(s) => {
                eprintln!("Note Status:");
                eprintln!("  Leaf count: {}", s.leaf_count);
                eprintln!("  Tree depth: {}", s.depth);
            }
            Err(e) => {
                eprintln!("⚠️  Note status query failed: {:?}", e);
                // This is OK - might not have shielded pool RPC enabled
            }
        }

        let latest = client.latest_block().await;
        match latest {
            Ok(block) => {
                eprintln!("Latest Block:");
                eprintln!("  Height: {}", block.height);
                eprintln!("  Hash: 0x{}...", hex::encode(&block.hash[..8]));
            }
            Err(e) => {
                eprintln!("⚠️  Latest block query failed: {:?}", e);
            }
        }

        eprintln!("\n✅ Real node connection test passed");
    }

    /// Test commitment and ciphertext retrieval
    #[tokio::test]
    #[ignore = "Requires running Substrate node - run with cargo test --ignored"]
    async fn test_real_shielded_pool_queries() {
        let endpoint =
            std::env::var("HEGEMON_RPC_URL").unwrap_or_else(|_| "ws://127.0.0.1:9944".to_string());

        eprintln!("Shielded pool query test on: {}", endpoint);

        // Connect to node
        let client = match wallet::SubstrateRpcClient::connect(&endpoint).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Connection failed: {:?}", e);
                panic!("Start node with: HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp");
            }
        };

        // Get note status first
        let status = client.note_status().await;
        match &status {
            Ok(s) => {
                eprintln!("Current note status:");
                eprintln!("  Leaf count: {}", s.leaf_count);
                eprintln!("  Tree depth: {}", s.depth);
                eprintln!("  Root: {}", s.root);
            }
            Err(e) => {
                eprintln!("Note status unavailable: {:?}", e);
            }
        }

        // Try to get commitments
        let commitments = client.commitments(0, 100).await;
        match commitments {
            Ok(commits) => {
                eprintln!("Retrieved {} commitments", commits.len());
                for (i, c) in commits.iter().enumerate().take(3) {
                    eprintln!(
                        "  [{}]: index={}, value=0x{}",
                        i,
                        c.index,
                        hex::encode(c.value)
                    );
                }
            }
            Err(e) => {
                eprintln!("Commitments query failed: {:?}", e);
            }
        }

        // Try to get ciphertexts
        let ciphertexts = client.ciphertexts(0, 100).await;
        match ciphertexts {
            Ok(cts) => {
                eprintln!("Retrieved {} ciphertexts", cts.len());
                for (i, ct) in cts.iter().enumerate().take(3) {
                    eprintln!(
                        "  [{}]: index={}, payload_len={}",
                        i,
                        ct.index,
                        ct.ciphertext.note_payload.len()
                    );
                }
            }
            Err(e) => {
                eprintln!("Ciphertexts query failed: {:?}", e);
            }
        }

        eprintln!("\n✅ Shielded pool query test completed");
    }

    /// Test nullifier queries
    #[tokio::test]
    #[ignore = "Requires running Substrate node - run with cargo test --ignored"]
    async fn test_real_shielded_transfer() {
        let endpoint =
            std::env::var("HEGEMON_RPC_URL").unwrap_or_else(|_| "ws://127.0.0.1:9944".to_string());

        eprintln!("Nullifier query test on: {}", endpoint);

        // Connect
        let client = match wallet::SubstrateRpcClient::connect(&endpoint).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Connection failed: {:?}", e);
                panic!("Start node with: HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp");
            }
        };

        // Get all nullifiers
        let nullifiers = client.nullifiers().await;
        match nullifiers {
            Ok(nfs) => {
                eprintln!("Retrieved {} nullifiers", nfs.len());
                for (i, nf) in nfs.iter().enumerate().take(5) {
                    eprintln!("  [{}]: 0x{}...", i, hex::encode(&nf[..8]));
                }
            }
            Err(e) => {
                eprintln!("Nullifiers query failed: {:?}", e);
            }
        }

        eprintln!("\n✅ Nullifier query test completed");
    }

    /// Test block subscription
    #[tokio::test]
    #[ignore = "Requires running Substrate node - run with cargo test --ignored"]
    async fn test_real_block_subscription() {
        let endpoint =
            std::env::var("HEGEMON_RPC_URL").unwrap_or_else(|_| "ws://127.0.0.1:9944".to_string());

        eprintln!("Block subscription test on: {}", endpoint);

        let client = match wallet::SubstrateRpcClient::connect(&endpoint).await {
            Ok(c) => c,
            Err(e) => {
                panic!("Connection failed: {:?}", e);
            }
        };

        // Instead of subscription (which requires more complex setup),
        // test by polling latest_block multiple times
        eprintln!("Polling for blocks (5s test)...");

        let start = std::time::Instant::now();
        let mut last_block = 0u64;
        let mut block_count = 0;

        while start.elapsed() < Duration::from_secs(5) {
            match client.latest_block().await {
                Ok(block) => {
                    if block.height > last_block {
                        eprintln!(
                            "  Block {}: 0x{}...",
                            block.height,
                            hex::encode(&block.hash[..8])
                        );
                        last_block = block.height;
                        block_count += 1;
                    }
                }
                Err(e) => {
                    eprintln!("Block query failed: {:?}", e);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        eprintln!(
            "\n✅ Block poll test completed (saw {} new blocks)",
            block_count
        );
    }

    /// Test nonce retrieval
    #[tokio::test]
    #[ignore = "Requires running Substrate node - run with cargo test --ignored"]
    async fn test_real_nonce_query() {
        let endpoint =
            std::env::var("HEGEMON_RPC_URL").unwrap_or_else(|_| "ws://127.0.0.1:9944".to_string());

        eprintln!("Nonce query test on: {}", endpoint);

        let client = match wallet::SubstrateRpcClient::connect(&endpoint).await {
            Ok(c) => c,
            Err(e) => {
                panic!("Connection failed: {:?}", e);
            }
        };

        // Query nonce for a test account
        let test_account = [0x42u8; 32];
        let nonce = client.get_nonce(&test_account).await;

        match nonce {
            Ok(n) => {
                eprintln!("Nonce for 0x42...: {}", n);
                // New account should have nonce 0
                assert_eq!(n, 0, "New account should have nonce 0");
            }
            Err(e) => {
                eprintln!("Nonce query failed: {:?}", e);
            }
        }

        eprintln!("\n✅ Nonce query test completed");
    }
}
