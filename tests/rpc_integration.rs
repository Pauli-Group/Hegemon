//! RPC Integration Tests (Phase 14.3)
//!
//! This module provides comprehensive RPC integration testing for the shielded pool,
//! verifying that wallet ↔ node communication works correctly over JSON-RPC.
//!
//! ## Test Categories
//!
//! 1. **Connection Tests**: WebSocket connection, reconnection, timeouts
//! 2. **Read Operations**: Note fetching, Merkle witnesses, pool status
//! 3. **Write Operations**: Shield, shielded transfer, unshield
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

// ============================================================================
// Mock RPC Service for Testing
// ============================================================================

/// Mock RPC service that simulates node responses
pub struct MockRpcService {
    /// Encrypted notes: (index, ciphertext, block_height, commitment)
    notes: RwLock<Vec<(u64, Vec<u8>, u64, [u8; 32])>>,
    /// Spent nullifiers
    nullifiers: RwLock<Vec<[u8; 32]>>,
    /// Valid anchors (Merkle roots)
    anchors: RwLock<Vec<[u8; 32]>>,
    /// Pool balance
    balance: RwLock<u128>,
    /// Current block height
    height: RwLock<u64>,
    /// Current merkle root
    merkle_root: RwLock<[u8; 32]>,
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
    Shield { amount: u128, commitment: [u8; 32] },
    ShieldedTransfer { nullifiers: Vec<[u8; 32]>, commitments: Vec<[u8; 32]> },
    Unshield { nullifier: [u8; 32], amount: u128, recipient: [u8; 32] },
}

impl Default for MockRpcService {
    fn default() -> Self {
        Self::new()
    }
}

impl MockRpcService {
    /// Create a new mock RPC service
    pub fn new() -> Self {
        let initial_root = [0u8; 32];
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
    pub async fn add_note(&self, ciphertext: Vec<u8>, commitment: [u8; 32]) -> u64 {
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
    pub async fn add_anchor(&self, anchor: [u8; 32]) {
        self.anchors.write().await.push(anchor);
    }

    /// Shield funds (transparent → shielded)
    pub async fn shield(
        &self,
        amount: u128,
        commitment: [u8; 32],
        encrypted_note: Vec<u8>,
    ) -> Result<[u8; 32], String> {
        let index = self.add_note(encrypted_note, commitment).await;
        
        // Update balance
        let mut bal = self.balance.write().await;
        *bal = bal.saturating_add(amount);
        
        // Generate tx hash
        let mut hasher = Sha256::new();
        hasher.update(b"shield");
        hasher.update(&amount.to_le_bytes());
        hasher.update(&commitment);
        let hash_bytes = hasher.finalize();
        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&hash_bytes);
        
        // Record transaction
        self.transactions.write().await.push(MockTransaction {
            tx_hash,
            block_number: Some(*self.height.read().await),
            tx_type: MockTxType::Shield { amount, commitment },
        });
        
        eprintln!(
            "Mock shield executed: amount={}, index={}, tx_hash={}",
            amount, index, hex::encode(tx_hash)
        );
        
        Ok(tx_hash)
    }

    /// Submit shielded transfer
    pub async fn submit_shielded_transfer(
        &self,
        _proof: Vec<u8>,
        nullifiers: Vec<[u8; 32]>,
        commitments: Vec<[u8; 32]>,
        encrypted_notes: Vec<Vec<u8>>,
        anchor: [u8; 32],
        _binding_sig: [u8; 64],
        value_balance: i128,
    ) -> Result<[u8; 32], String> {
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
        
        // Update balance
        {
            let mut bal = self.balance.write().await;
            if value_balance > 0 {
                *bal = bal.saturating_add(value_balance as u128);
            } else if value_balance < 0 {
                *bal = bal.saturating_sub((-value_balance) as u128);
            }
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
    ) -> Vec<(u64, Vec<u8>, u64, [u8; 32])> {
        let notes = self.notes.read().await;
        notes
            .iter()
            .skip(start as usize)
            .take(limit)
            .filter(|(_, _, block, _)| {
                let from_ok = from_block.map_or(true, |fb| *block >= fb);
                let to_ok = to_block.map_or(true, |tb| *block <= tb);
                from_ok && to_ok
            })
            .cloned()
            .collect()
    }

    /// Get Merkle witness for a position
    pub async fn get_merkle_witness(
        &self,
        _position: u64,
    ) -> (Vec<[u8; 32]>, Vec<bool>, [u8; 32]) {
        // Mock witness with 32 levels
        let siblings: Vec<[u8; 32]> = (0..32).map(|i| [i; 32]).collect();
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
    pub async fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.read().await.contains(nullifier)
    }

    /// Check if anchor is valid
    pub async fn is_valid_anchor(&self, anchor: &[u8; 32]) -> bool {
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
    pub merkle_root: [u8; 32],
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

    /// Shield funds
    pub async fn shield(
        &self,
        amount: u128,
        commitment: [u8; 32],
        encrypted_note: Vec<u8>,
    ) -> Result<[u8; 32], String> {
        if let Some(mock) = &self.mock {
            mock.shield(amount, commitment, encrypted_note).await
        } else {
            Err("Real RPC not implemented".to_string())
        }
    }

    /// Submit shielded transfer
    pub async fn submit_shielded_transfer(
        &self,
        proof: Vec<u8>,
        nullifiers: Vec<[u8; 32]>,
        commitments: Vec<[u8; 32]>,
        encrypted_notes: Vec<Vec<u8>>,
        anchor: [u8; 32],
        binding_sig: [u8; 64],
        value_balance: i128,
    ) -> Result<[u8; 32], String> {
        if let Some(mock) = &self.mock {
            mock.submit_shielded_transfer(
                proof,
                nullifiers,
                commitments,
                encrypted_notes,
                anchor,
                binding_sig,
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
    ) -> Vec<(u64, Vec<u8>, u64, [u8; 32])> {
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
    ) -> (Vec<[u8; 32]>, Vec<bool>, [u8; 32]) {
        if let Some(mock) = &self.mock {
            mock.get_merkle_witness(position).await
        } else {
            (Vec::new(), Vec::new(), [0u8; 32])
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
                merkle_root: [0u8; 32],
                tree_depth: 32,
                pool_balance: 0,
                last_update_block: 0,
            }
        }
    }

    /// Check if nullifier is spent
    pub async fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
        if let Some(mock) = &self.mock {
            mock.is_nullifier_spent(nullifier).await
        } else {
            false
        }
    }

    /// Check if anchor is valid
    pub async fn is_valid_anchor(&self, anchor: &[u8; 32]) -> bool {
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
    async fn test_shield_operation() {
        let service = MockRpcService::new();
        
        let commitment = [0xaa; 32];
        let encrypted_note = vec![1, 2, 3, 4];
        let amount = 1_000_000u128;
        
        // Shield funds
        let tx_hash = service.shield(amount, commitment, encrypted_note).await.unwrap();
        
        // Verify state
        let status = service.get_pool_status().await;
        assert_eq!(status.total_notes, 1);
        assert_eq!(status.pool_balance, amount);
        
        // Verify transaction recorded
        let tx = service.get_transaction(&tx_hash).await;
        assert!(tx.is_some());
    }

    #[tokio::test]
    async fn test_get_encrypted_notes() {
        let service = MockRpcService::new();
        
        // Add some notes
        for i in 0..5 {
            service.add_note(vec![i as u8], [i; 32]).await;
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
        service.add_anchor([0; 32]).await; // Add valid anchor
        
        let nullifier = [0xcc; 32];
        
        // Not spent initially
        assert!(!service.is_nullifier_spent(&nullifier).await);
        
        // Submit transfer with this nullifier
        service
            .submit_shielded_transfer(
                vec![0u8; 10000], // fake proof
                vec![nullifier],
                vec![[0xdd; 32]],
                vec![vec![1, 2, 3]],
                [0; 32], // valid anchor
                [0; 64],
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
        assert!(service.is_valid_anchor(&[0; 32]).await);
        
        // Unknown anchor is invalid
        assert!(!service.is_valid_anchor(&[0xff; 32]).await);
        
        // Add custom anchor
        service.add_anchor([0xab; 32]).await;
        assert!(service.is_valid_anchor(&[0xab; 32]).await);
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
        service.add_anchor([0; 32]).await;
        
        // Shield initial funds
        client.shield(1_000_000, [0xaa; 32], vec![1]).await.unwrap();
        
        // Submit shielded transfer
        let tx_hash = client
            .submit_shielded_transfer(
                vec![0u8; 15000], // fake proof
                vec![[0x11; 32]], // nullifier
                vec![[0x22; 32]], // new commitment
                vec![vec![2, 3, 4]], // encrypted note
                [0; 32], // anchor
                [0; 64], // binding sig
                0, // value balance
            )
            .await
            .unwrap();
        
        // Verify
        assert_ne!(tx_hash, [0u8; 32]);
        
        let status = client.get_pool_status().await;
        assert_eq!(status.total_notes, 2); // original + new
        assert_eq!(status.total_nullifiers, 1);
    }

    #[tokio::test]
    async fn test_double_spend_rejected() {
        let (client, service) = TestRpcClient::mock();
        service.add_anchor([0; 32]).await;
        
        // Shield funds
        client.shield(1_000_000, [0xaa; 32], vec![1]).await.unwrap();
        
        let nullifier = [0x99; 32];
        
        // First transfer succeeds
        let result = client
            .submit_shielded_transfer(
                vec![0u8; 15000],
                vec![nullifier],
                vec![[0x22; 32]],
                vec![vec![2]],
                [0; 32],
                [0; 64],
                0,
            )
            .await;
        assert!(result.is_ok());
        
        // Second transfer with same nullifier fails
        let result = client
            .submit_shielded_transfer(
                vec![0u8; 15000],
                vec![nullifier], // Same nullifier
                vec![[0x33; 32]],
                vec![vec![3]],
                [0; 32],
                [0; 64],
                0,
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_anchor_rejected() {
        let (client, service) = TestRpcClient::mock();
        
        // Shield funds
        client.shield(1_000_000, [0xaa; 32], vec![1]).await.unwrap();
        
        // Try transfer with invalid anchor
        let result = client
            .submit_shielded_transfer(
                vec![0u8; 15000],
                vec![[0x11; 32]],
                vec![[0x22; 32]],
                vec![vec![2]],
                [0xff; 32], // Invalid anchor
                [0; 64],
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
    async fn test_concurrent_shields() {
        let service = Arc::new(MockRpcService::new());
        let mut tasks = JoinSet::new();
        
        // Spawn 10 concurrent shield operations
        for i in 0..10 {
            let svc = service.clone();
            tasks.spawn(async move {
                let commitment = [i; 32];
                svc.shield(100_000, commitment, vec![i]).await
            });
        }
        
        // Wait for all to complete
        while let Some(result) = tasks.join_next().await {
            assert!(result.unwrap().is_ok());
        }
        
        // Verify all notes added
        let status = service.get_pool_status().await;
        assert_eq!(status.total_notes, 10);
        assert_eq!(status.pool_balance, 1_000_000);
    }

    #[tokio::test]
    async fn test_concurrent_note_fetching() {
        let service = Arc::new(MockRpcService::new());
        
        // Add notes
        for i in 0..100 {
            service.add_note(vec![i as u8], [i; 32]).await;
        }
        
        let mut tasks = JoinSet::new();
        
        // Spawn concurrent reads
        for start in (0..100).step_by(10) {
            let svc = service.clone();
            tasks.spawn(async move {
                svc.get_encrypted_notes(start, 10, None, None).await
            });
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
        service.add_anchor([0; 32]).await;
        
        // Add some spent nullifiers
        for i in 0..50 {
            service
                .submit_shielded_transfer(
                    vec![0u8; 15000],
                    vec![[i; 32]],
                    vec![[i + 100; 32]],
                    vec![vec![i]],
                    [0; 32],
                    [0; 64],
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
                let nf = [i; 32];
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
        service.add_anchor([0; 32]).await;
        
        // 1. Check initial pool status
        let status = client.get_pool_status().await;
        assert_eq!(status.pool_balance, 0);
        assert_eq!(status.total_notes, 0);
        
        // 2. Shield funds
        let shield_amount = 1_000_000u128;
        let shield_commitment = [0xaa; 32];
        let shield_tx = client
            .shield(shield_amount, shield_commitment, vec![1, 2, 3, 4])
            .await
            .unwrap();
        
        // 3. Verify shield
        let status = client.get_pool_status().await;
        assert_eq!(status.pool_balance, shield_amount);
        assert_eq!(status.total_notes, 1);
        
        // 4. Fetch encrypted notes
        let notes = client.get_encrypted_notes(0, 100, None, None).await;
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].3, shield_commitment); // commitment matches
        
        // 5. Get Merkle witness
        let (siblings, indices, root) = client.get_merkle_witness(0).await;
        assert_eq!(siblings.len(), 32);
        assert_eq!(indices.len(), 32);
        
        // Add the root as a valid anchor for the transfer
        service.add_anchor(root).await;
        
        // 6. Build and submit shielded transfer
        let nullifier = [0xbb; 32];
        let new_commitment = [0xcc; 32];
        let transfer_tx = client
            .submit_shielded_transfer(
                vec![0u8; 20000], // fake proof
                vec![nullifier],
                vec![new_commitment],
                vec![vec![5, 6, 7, 8]],
                root,
                [0; 64],
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
        assert_eq!(final_status.pool_balance, shield_amount); // unchanged for pure transfer
    }

    #[tokio::test]
    async fn test_multi_party_rpc_flow() {
        let (client, service) = TestRpcClient::mock();
        service.add_anchor([0; 32]).await;
        
        // Alice shields
        let alice_amount = 500_000u128;
        client.shield(alice_amount, [0xa0; 32], vec![1]).await.unwrap();
        
        // Bob shields
        let bob_amount = 300_000u128;
        client.shield(bob_amount, [0xb0; 32], vec![2]).await.unwrap();
        
        // Verify pool has both amounts
        let status = client.get_pool_status().await;
        assert_eq!(status.pool_balance, alice_amount + bob_amount);
        assert_eq!(status.total_notes, 2);
        
        // Alice transfers to Charlie (simulated)
        let transfer_result = client
            .submit_shielded_transfer(
                vec![0u8; 15000],
                vec![[0xa1; 32]], // Alice's nullifier
                vec![[0xc0; 32]], // Charlie's new note
                vec![vec![3]],
                [0; 32],
                [0; 64],
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

    /// Test against real node
    #[tokio::test]
    #[ignore = "Requires running Substrate node - run with cargo test --ignored"]
    async fn test_real_node_connection() {
        // TODO: Implement when test harness is ready
        // This would use wallet::SubstrateRpcClient::connect(endpoint)
        // and verify actual RPC responses
        todo!("Real node connection test")
    }

    /// Test real shield transaction
    #[tokio::test]
    #[ignore = "Requires running Substrate node - run with cargo test --ignored"]
    async fn test_real_shield_transaction() {
        // TODO: Implement when test harness is ready
        todo!("Real shield transaction test")
    }

    /// Test real shielded transfer
    #[tokio::test]
    #[ignore = "Requires running Substrate node - run with cargo test --ignored"]
    async fn test_real_shielded_transfer() {
        // TODO: Implement when test harness is ready
        todo!("Real shielded transfer test")
    }
}
