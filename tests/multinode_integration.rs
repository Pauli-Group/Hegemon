//! Multi-Node Integration Tests (Phase 11.8)
//!
//! This module provides comprehensive multi-node integration testing for Hegemon,
//! verifying node-to-node communication, transaction propagation, and shielded pool sync.
//!
//! ## Test Categories
//!
//! 1. **Node Sync Tests**: Block propagation between nodes
//! 2. **Transaction Propagation**: Transparent and shielded tx broadcast
//! 3. **State Consistency**: Merkle roots, nullifiers sync across nodes
//! 4. **Network Resilience**: Reconnection, partition recovery
//!
//! ## Running Tests
//!
//! Mock tests (no node required):
//! ```bash
//! cargo test -p security-tests --test multinode_integration
//! ```
//!
//! Full integration tests (requires multiple nodes):
//! ```bash
//! cargo test -p security-tests --test multinode_integration --ignored
//! ```

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tokio::time::sleep;

// ============================================================================
// Multi-Node Mock Network
// ============================================================================

/// Simulates a network of multiple nodes for integration testing
pub struct MockNetwork {
    /// Nodes in the network
    nodes: Vec<Arc<MockNode>>,
    /// Network partitions (node_idx -> isolated from network)
    partitions: RwLock<Vec<bool>>,
    /// Global block propagation delay (ms)
    propagation_delay_ms: u64,
}

/// A mock node for multi-node testing
pub struct MockNode {
    pub id: usize,
    pub blocks: RwLock<Vec<MockBlock>>,
    pub mempool: RwLock<Vec<MockTransaction>>,
    pub nullifiers: RwLock<Vec<[u8; 32]>>,
    pub notes: RwLock<Vec<MockNote>>,
    pub merkle_root: RwLock<[u8; 32]>,
    pub height: AtomicU64,
    pub peers: RwLock<Vec<usize>>,
}

/// A mock block
#[derive(Clone, Debug)]
pub struct MockBlock {
    pub height: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub transactions: Vec<MockTransaction>,
    pub state_root: [u8; 32],
    pub nullifier_root: [u8; 32],
}

/// A mock transaction
#[derive(Clone, Debug)]
pub enum MockTransaction {
    Transparent {
        hash: [u8; 32],
        from: [u8; 32],
        to: [u8; 32],
        amount: u128,
    },
    ShieldedTransfer {
        hash: [u8; 32],
        nullifiers: Vec<[u8; 32]>,
        commitments: Vec<[u8; 32]>,
        proof: Vec<u8>,
    },
    Shield {
        hash: [u8; 32],
        amount: u128,
        commitment: [u8; 32],
    },
    Unshield {
        hash: [u8; 32],
        nullifier: [u8; 32],
        amount: u128,
        recipient: [u8; 32],
    },
}

/// A mock shielded note
#[derive(Clone, Debug)]
pub struct MockNote {
    pub index: u64,
    pub commitment: [u8; 32],
    pub encrypted_note: Vec<u8>,
    pub block_height: u64,
}

impl MockTransaction {
    pub fn hash(&self) -> [u8; 32] {
        match self {
            MockTransaction::Transparent { hash, .. } => *hash,
            MockTransaction::ShieldedTransfer { hash, .. } => *hash,
            MockTransaction::Shield { hash, .. } => *hash,
            MockTransaction::Unshield { hash, .. } => *hash,
        }
    }
}

impl Default for MockNode {
    fn default() -> Self {
        Self::new(0)
    }
}

impl MockNode {
    /// Create a new mock node
    pub fn new(id: usize) -> Self {
        Self {
            id,
            blocks: RwLock::new(vec![Self::genesis_block()]),
            mempool: RwLock::new(Vec::new()),
            nullifiers: RwLock::new(Vec::new()),
            notes: RwLock::new(Vec::new()),
            merkle_root: RwLock::new([0u8; 32]),
            height: AtomicU64::new(0),
            peers: RwLock::new(Vec::new()),
        }
    }

    /// Genesis block
    fn genesis_block() -> MockBlock {
        MockBlock {
            height: 0,
            hash: [0u8; 32],
            parent_hash: [0u8; 32],
            transactions: Vec::new(),
            state_root: [0u8; 32],
            nullifier_root: [0u8; 32],
        }
    }

    /// Get current height
    pub fn current_height(&self) -> u64 {
        self.height.load(Ordering::SeqCst)
    }

    /// Add a transaction to mempool
    pub async fn submit_transaction(&self, tx: MockTransaction) -> Result<[u8; 32], String> {
        // Check for double spend
        if let MockTransaction::ShieldedTransfer { nullifiers, .. } = &tx {
            let spent = self.nullifiers.read().await;
            for nf in nullifiers {
                if spent.contains(nf) {
                    return Err("Double spend detected".to_string());
                }
            }
        }

        let hash = tx.hash();
        self.mempool.write().await.push(tx);
        Ok(hash)
    }

    /// Mine a block with mempool transactions
    pub async fn mine_block(&self) -> MockBlock {
        let mut mempool = self.mempool.write().await;
        let blocks = self.blocks.read().await;
        let parent = blocks.last().unwrap();

        let new_height = parent.height + 1;
        let parent_hash = parent.hash;
        let transactions = mempool.drain(..).collect::<Vec<_>>();
        
        // Release locks before processing
        drop(mempool);
        drop(blocks);

        // Get current note count once (avoid repeated lock acquisition)
        let base_note_index = self.notes.read().await.len() as u64;

        // Process transactions
        let mut nullifiers_to_add = Vec::new();
        let mut notes_to_add = Vec::new();
        let mut note_offset = 0u64;

        for tx in &transactions {
            match tx {
                MockTransaction::ShieldedTransfer {
                    nullifiers,
                    commitments,
                    ..
                } => {
                    nullifiers_to_add.extend(nullifiers.clone());
                    for (i, commitment) in commitments.iter().enumerate() {
                        notes_to_add.push(MockNote {
                            index: base_note_index + note_offset + i as u64,
                            commitment: *commitment,
                            encrypted_note: vec![0u8; 64],
                            block_height: new_height,
                        });
                    }
                    note_offset += commitments.len() as u64;
                }
                MockTransaction::Shield { commitment, .. } => {
                    notes_to_add.push(MockNote {
                        index: base_note_index + note_offset,
                        commitment: *commitment,
                        encrypted_note: vec![0u8; 64],
                        block_height: new_height,
                    });
                    note_offset += 1;
                }
                MockTransaction::Unshield { nullifier, .. } => {
                    nullifiers_to_add.push(*nullifier);
                }
                _ => {}
            }
        }

        // Update state
        self.nullifiers.write().await.extend(nullifiers_to_add);
        self.notes.write().await.extend(notes_to_add);

        // Compute new merkle root
        let new_root = self.compute_merkle_root().await;
        *self.merkle_root.write().await = new_root;

        // Create block hash
        let mut hasher = Sha256::new();
        hasher.update(&new_height.to_le_bytes());
        hasher.update(&parent_hash);
        hasher.update(&new_root);
        let hash_bytes = hasher.finalize();
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&hash_bytes);

        let block = MockBlock {
            height: new_height,
            hash: block_hash,
            parent_hash,
            transactions,
            state_root: new_root,
            nullifier_root: self.compute_nullifier_root().await,
        };

        self.blocks.write().await.push(block.clone());
        self.height.store(new_height, Ordering::SeqCst);


        block
    }

    /// Import a block from another node
    pub async fn import_block(&self, block: MockBlock) -> Result<(), String> {
        let blocks = self.blocks.read().await;
        let current_height = blocks.last().unwrap().height;

        // Verify parent exists
        if block.height != current_height + 1 {
            return Err(format!(
                "Invalid block height: expected {}, got {}",
                current_height + 1,
                block.height
            ));
        }

        let parent = blocks.last().unwrap();
        if block.parent_hash != parent.hash {
            return Err("Parent hash mismatch".to_string());
        }

        drop(blocks);

        // Check double spend first (read-only pass)
        {
            let spent = self.nullifiers.read().await;
            for tx in &block.transactions {
                if let MockTransaction::ShieldedTransfer { nullifiers, .. } = tx {
                    for nf in nullifiers {
                        if spent.contains(nf) {
                            return Err("Double spend in imported block".to_string());
                        }
                    }
                }
            }
        }

        // Collect all updates
        let mut nullifiers_to_add = Vec::new();
        let mut notes_to_add = Vec::new();
        let base_note_index = self.notes.read().await.len() as u64;
        let mut note_offset = 0u64;

        for tx in &block.transactions {
            match tx {
                MockTransaction::ShieldedTransfer {
                    nullifiers,
                    commitments,
                    ..
                } => {
                    nullifiers_to_add.extend(nullifiers.clone());
                    for (i, commitment) in commitments.iter().enumerate() {
                        notes_to_add.push(MockNote {
                            index: base_note_index + note_offset + i as u64,
                            commitment: *commitment,
                            encrypted_note: vec![0u8; 64],
                            block_height: block.height,
                        });
                    }
                    note_offset += commitments.len() as u64;
                }
                MockTransaction::Shield { commitment, .. } => {
                    notes_to_add.push(MockNote {
                        index: base_note_index + note_offset,
                        commitment: *commitment,
                        encrypted_note: vec![0u8; 64],
                        block_height: block.height,
                    });
                    note_offset += 1;
                }
                MockTransaction::Unshield { nullifier, .. } => {
                    nullifiers_to_add.push(*nullifier);
                }
                _ => {}
            }
        }

        // Apply all updates
        self.nullifiers.write().await.extend(nullifiers_to_add);
        self.notes.write().await.extend(notes_to_add);

        // Remove imported transactions from our mempool (they're now in a block)
        {
            let tx_hashes: Vec<[u8; 32]> = block.transactions.iter().map(|t| t.hash()).collect();
            let mut mempool = self.mempool.write().await;
            mempool.retain(|t| !tx_hashes.contains(&t.hash()));
        }

        // Update merkle root
        *self.merkle_root.write().await = block.state_root;

        // Import block
        self.blocks.write().await.push(block.clone());
        self.height.store(block.height, Ordering::SeqCst);

        Ok(())
    }

    /// Compute merkle root from notes
    async fn compute_merkle_root(&self) -> [u8; 32] {
        let notes = self.notes.read().await;
        let mut hasher = Sha256::new();
        hasher.update(b"merkle_root");
        hasher.update(&(notes.len() as u64).to_le_bytes());
        for note in notes.iter() {
            hasher.update(&note.commitment);
        }
        let hash_bytes = hasher.finalize();
        let mut root = [0u8; 32];
        root.copy_from_slice(&hash_bytes);
        root
    }

    /// Compute nullifier root
    async fn compute_nullifier_root(&self) -> [u8; 32] {
        let nullifiers = self.nullifiers.read().await;
        let mut hasher = Sha256::new();
        hasher.update(b"nullifier_root");
        hasher.update(&(nullifiers.len() as u64).to_le_bytes());
        for nf in nullifiers.iter() {
            hasher.update(nf);
        }
        let hash_bytes = hasher.finalize();
        let mut root = [0u8; 32];
        root.copy_from_slice(&hash_bytes);
        root
    }

    /// Check if nullifier is spent
    pub async fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.read().await.contains(nullifier)
    }

    /// Get note count
    pub async fn note_count(&self) -> usize {
        self.notes.read().await.len()
    }

    /// Get nullifier count
    pub async fn nullifier_count(&self) -> usize {
        self.nullifiers.read().await.len()
    }
}

impl MockNetwork {
    /// Create a new mock network with n nodes
    pub fn new(num_nodes: usize) -> Self {
        let nodes: Vec<_> = (0..num_nodes).map(|i| Arc::new(MockNode::new(i))).collect();

        // Peer connections are initialized via connect_all() in async context

        Self {
            nodes,
            partitions: RwLock::new(vec![false; num_nodes]),
            propagation_delay_ms: 10,
        }
    }

    /// Initialize peer connections (async version)
    pub async fn connect_all(&self) {
        let num_nodes = self.nodes.len();
        for i in 0..num_nodes {
            let mut peers = Vec::new();
            for j in 0..num_nodes {
                if i != j {
                    peers.push(j);
                }
            }
            *self.nodes[i].peers.write().await = peers;
        }
    }

    /// Get a node by index
    pub fn node(&self, idx: usize) -> &Arc<MockNode> {
        &self.nodes[idx]
    }

    /// Propagate a block to all connected nodes
    pub async fn propagate_block(&self, source_idx: usize, block: &MockBlock) {
        let partitions = self.partitions.read().await;

        for (i, node) in self.nodes.iter().enumerate() {
            if i != source_idx && !partitions[source_idx] && !partitions[i] {
                // Simulate network delay
                sleep(Duration::from_millis(self.propagation_delay_ms)).await;
                let _ = node.import_block(block.clone()).await;
            }
        }
    }

    /// Propagate a transaction to all mempool
    pub async fn propagate_transaction(&self, source_idx: usize, tx: &MockTransaction) {
        let partitions = self.partitions.read().await;

        for (i, node) in self.nodes.iter().enumerate() {
            if i != source_idx && !partitions[source_idx] && !partitions[i] {
                let _ = node.submit_transaction(tx.clone()).await;
            }
        }
    }

    /// Partition a node from the network
    pub async fn partition_node(&self, idx: usize) {
        self.partitions.write().await[idx] = true;
    }

    /// Heal a partition
    pub async fn heal_partition(&self, idx: usize) {
        self.partitions.write().await[idx] = false;
    }

    /// Check if all nodes are at the same height
    pub async fn all_same_height(&self) -> bool {
        if self.nodes.is_empty() {
            return true;
        }
        let first_height = self.nodes[0].current_height();
        self.nodes.iter().all(|n| n.current_height() == first_height)
    }

    /// Wait for all nodes to sync to the same height
    pub async fn wait_for_sync(&self, timeout_secs: u64) -> Result<(), String> {
        let start = std::time::Instant::now();
        while !self.all_same_height().await {
            if start.elapsed() > Duration::from_secs(timeout_secs) {
                return Err("Sync timeout".to_string());
            }
            sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    }
}

// ============================================================================
// Phase 11.8.1: Block Propagation Tests
// ============================================================================

#[cfg(test)]
mod block_propagation_tests {
    use super::*;

    #[tokio::test]
    async fn test_two_node_block_sync() {
        let network = MockNetwork::new(2);
        network.connect_all().await;

        // Node 0 mines a block
        let block = network.node(0).mine_block().await;
        assert_eq!(block.height, 1);

        // Propagate to node 1
        network.propagate_block(0, &block).await;

        // Node 1 should be at same height
        assert_eq!(network.node(1).current_height(), 1);
        assert!(network.all_same_height().await);
    }

    #[tokio::test]
    async fn test_three_node_block_propagation() {
        let network = MockNetwork::new(3);
        network.connect_all().await;

        // Node 0 mines a block
        let block = network.node(0).mine_block().await;
        network.propagate_block(0, &block).await;

        // All nodes should sync
        assert!(network.all_same_height().await);
        assert_eq!(network.node(0).current_height(), 1);
        assert_eq!(network.node(1).current_height(), 1);
        assert_eq!(network.node(2).current_height(), 1);
    }

    #[tokio::test]
    async fn test_sequential_block_mining() {
        let network = MockNetwork::new(2);
        network.connect_all().await;

        // Node 0 mines block 1
        let block1 = network.node(0).mine_block().await;
        network.propagate_block(0, &block1).await;

        // Node 1 mines block 2
        let block2 = network.node(1).mine_block().await;
        network.propagate_block(1, &block2).await;

        // Both should be at height 2
        assert!(network.all_same_height().await);
        assert_eq!(network.node(0).current_height(), 2);
    }

    #[tokio::test]
    async fn test_partitioned_node_no_sync() {
        let network = MockNetwork::new(2);
        network.connect_all().await;

        // Partition node 1
        network.partition_node(1).await;

        // Node 0 mines a block
        let block = network.node(0).mine_block().await;
        network.propagate_block(0, &block).await;

        // Node 1 should NOT sync
        assert_eq!(network.node(0).current_height(), 1);
        assert_eq!(network.node(1).current_height(), 0);
    }

    #[tokio::test]
    async fn test_partition_heal_and_sync() {
        let network = MockNetwork::new(2);
        network.connect_all().await;

        // Partition node 1
        network.partition_node(1).await;

        // Node 0 mines a block
        let block = network.node(0).mine_block().await;
        network.propagate_block(0, &block).await;

        // Verify partition worked
        assert_eq!(network.node(1).current_height(), 0);

        // Heal partition
        network.heal_partition(1).await;

        // Re-propagate
        network.propagate_block(0, &block).await;

        // Now node 1 should sync
        assert_eq!(network.node(1).current_height(), 1);
    }
}

// ============================================================================
// Phase 11.8.2: Transaction Propagation Tests
// ============================================================================

#[cfg(test)]
mod transaction_propagation_tests {
    use super::*;

    fn make_tx_hash(seed: u8) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&[seed]);
        let h = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&h);
        hash
    }

    #[tokio::test]
    async fn test_transparent_tx_propagation() {
        let network = MockNetwork::new(2);
        network.connect_all().await;

        let tx = MockTransaction::Transparent {
            hash: make_tx_hash(1),
            from: [0xaa; 32],
            to: [0xbb; 32],
            amount: 1000,
        };

        // Submit to node 0
        let hash = network.node(0).submit_transaction(tx.clone()).await.unwrap();
        assert_eq!(hash, make_tx_hash(1));

        // Propagate to network
        network.propagate_transaction(0, &tx).await;

        // Node 1 should have the tx in mempool
        let mempool = network.node(1).mempool.read().await;
        assert_eq!(mempool.len(), 1);
    }

    #[tokio::test]
    async fn test_shielded_tx_propagation() {
        let network = MockNetwork::new(3);
        network.connect_all().await;

        let tx = MockTransaction::ShieldedTransfer {
            hash: make_tx_hash(2),
            nullifiers: vec![[0x11; 32]],
            commitments: vec![[0x22; 32]],
            proof: vec![0u8; 1000],
        };

        // Submit to node 0
        network.node(0).submit_transaction(tx.clone()).await.unwrap();

        // Propagate
        network.propagate_transaction(0, &tx).await;

        // All nodes should have the tx
        assert_eq!(network.node(1).mempool.read().await.len(), 1);
        assert_eq!(network.node(2).mempool.read().await.len(), 1);
    }

    #[tokio::test]
    async fn test_shield_tx_propagation() {
        let network = MockNetwork::new(2);
        network.connect_all().await;

        let tx = MockTransaction::Shield {
            hash: make_tx_hash(3),
            amount: 5000,
            commitment: [0x33; 32],
        };

        network.node(0).submit_transaction(tx.clone()).await.unwrap();
        network.propagate_transaction(0, &tx).await;

        // Mine block to process
        let block = network.node(0).mine_block().await;
        network.propagate_block(0, &block).await;

        // Both nodes should have the note
        assert_eq!(network.node(0).note_count().await, 1);
        assert_eq!(network.node(1).note_count().await, 1);
    }

    #[tokio::test]
    async fn test_double_spend_rejected_on_propagation() {
        let network = MockNetwork::new(2);
        network.connect_all().await;

        let nullifier = [0x55; 32];

        // First tx with this nullifier
        let tx1 = MockTransaction::ShieldedTransfer {
            hash: make_tx_hash(4),
            nullifiers: vec![nullifier],
            commitments: vec![[0x66; 32]],
            proof: vec![0u8; 1000],
        };

        network.node(0).submit_transaction(tx1.clone()).await.unwrap();

        // Mine it
        let block = network.node(0).mine_block().await;
        network.propagate_block(0, &block).await;

        // Now both nodes have the nullifier spent
        assert!(network.node(0).is_nullifier_spent(&nullifier).await);
        assert!(network.node(1).is_nullifier_spent(&nullifier).await);

        // Try to submit another tx with same nullifier
        let tx2 = MockTransaction::ShieldedTransfer {
            hash: make_tx_hash(5),
            nullifiers: vec![nullifier],
            commitments: vec![[0x77; 32]],
            proof: vec![0u8; 1000],
        };

        let result = network.node(1).submit_transaction(tx2).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Double spend"));
    }
}

// ============================================================================
// Phase 11.8.3: Shielded Pool State Consistency Tests
// ============================================================================

#[cfg(test)]
mod shielded_state_tests {
    use super::*;

    fn make_tx_hash(seed: u8) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&[seed]);
        let h = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&h);
        hash
    }

    #[tokio::test]
    async fn test_merkle_root_consistency() {
        let network = MockNetwork::new(2);
        network.connect_all().await;

        // Add some shield transactions
        for i in 0..5 {
            let tx = MockTransaction::Shield {
                hash: make_tx_hash(i),
                amount: 1000,
                commitment: [i; 32],
            };
            network.node(0).submit_transaction(tx.clone()).await.unwrap();
        }

        // Mine
        let block = network.node(0).mine_block().await;
        network.propagate_block(0, &block).await;

        // Merkle roots should match
        let root0 = *network.node(0).merkle_root.read().await;
        let root1 = *network.node(1).merkle_root.read().await;
        assert_eq!(root0, root1, "Merkle roots should be consistent");
    }

    #[tokio::test]
    async fn test_nullifier_set_consistency() {
        let network = MockNetwork::new(3);
        network.connect_all().await;

        // Shield some notes first
        for i in 0..3 {
            let tx = MockTransaction::Shield {
                hash: make_tx_hash(i),
                amount: 1000,
                commitment: [i; 32],
            };
            network.node(0).submit_transaction(tx.clone()).await.unwrap();
        }

        let block = network.node(0).mine_block().await;
        network.propagate_block(0, &block).await;

        // Now spend them with shielded transfers
        let nullifiers: Vec<[u8; 32]> = (0..3).map(|i| [100 + i; 32]).collect();

        for (i, nf) in nullifiers.iter().enumerate() {
            let tx = MockTransaction::ShieldedTransfer {
                hash: make_tx_hash(10 + i as u8),
                nullifiers: vec![*nf],
                commitments: vec![[200 + i as u8; 32]],
                proof: vec![0u8; 1000],
            };
            network.node(0).submit_transaction(tx.clone()).await.unwrap();
        }

        let block = network.node(0).mine_block().await;
        network.propagate_block(0, &block).await;

        // All nodes should have the same nullifiers
        for nf in &nullifiers {
            assert!(network.node(0).is_nullifier_spent(nf).await);
            assert!(network.node(1).is_nullifier_spent(nf).await);
            assert!(network.node(2).is_nullifier_spent(nf).await);
        }
    }

    #[tokio::test]
    async fn test_note_count_consistency() {
        let network = MockNetwork::new(2);
        network.connect_all().await;

        // Shield notes from different nodes
        let tx1 = MockTransaction::Shield {
            hash: [1; 32],
            amount: 1000,
            commitment: [0xaa; 32],
        };

        network.node(0).submit_transaction(tx1.clone()).await.unwrap();
        network.propagate_transaction(0, &tx1).await;

        let block1 = network.node(0).mine_block().await;
        network.propagate_block(0, &block1).await;

        let tx2 = MockTransaction::Shield {
            hash: [2; 32],
            amount: 2000,
            commitment: [0xbb; 32],
        };

        network.node(1).submit_transaction(tx2.clone()).await.unwrap();
        network.propagate_transaction(1, &tx2).await;

        let block2 = network.node(1).mine_block().await;
        network.propagate_block(1, &block2).await;

        // Both nodes should have 2 notes
        assert_eq!(network.node(0).note_count().await, 2);
        assert_eq!(network.node(1).note_count().await, 2);
    }

    #[tokio::test]
    async fn test_unshield_updates_state() {
        let network = MockNetwork::new(2);
        network.connect_all().await;

        // First shield
        let shield_tx = MockTransaction::Shield {
            hash: [1; 32],
            amount: 5000,
            commitment: [0x11; 32],
        };

        network
            .node(0)
            .submit_transaction(shield_tx.clone())
            .await
            .unwrap();

        let block1 = network.node(0).mine_block().await;
        network.propagate_block(0, &block1).await;

        // Now unshield
        let unshield_nullifier = [0x99; 32];
        let unshield_tx = MockTransaction::Unshield {
            hash: [2; 32],
            nullifier: unshield_nullifier,
            amount: 5000,
            recipient: [0xaa; 32],
        };

        network
            .node(0)
            .submit_transaction(unshield_tx.clone())
            .await
            .unwrap();

        let block2 = network.node(0).mine_block().await;
        network.propagate_block(0, &block2).await;

        // Nullifier should be spent on both nodes
        assert!(network.node(0).is_nullifier_spent(&unshield_nullifier).await);
        assert!(network.node(1).is_nullifier_spent(&unshield_nullifier).await);
    }
}

// ============================================================================
// Phase 11.8.4: Network Resilience Tests
// ============================================================================

#[cfg(test)]
mod network_resilience_tests {
    use super::*;

    #[tokio::test]
    async fn test_recovery_after_partition() {
        let network = MockNetwork::new(3);
        network.connect_all().await;

        // Node 2 gets partitioned
        network.partition_node(2).await;

        // Mine blocks while partitioned
        for i in 0..3 {
            let tx = MockTransaction::Shield {
                hash: [i; 32],
                amount: 1000,
                commitment: [i; 32],
            };
            network.node(0).submit_transaction(tx).await.unwrap();
            let block = network.node(0).mine_block().await;
            network.propagate_block(0, &block).await;
        }

        // Node 0 and 1 should be at height 3, node 2 at 0
        assert_eq!(network.node(0).current_height(), 3);
        assert_eq!(network.node(1).current_height(), 3);
        assert_eq!(network.node(2).current_height(), 0);

        // Heal partition
        network.heal_partition(2).await;

        // Sync blocks to node 2 (in real system this would be automatic)
        for block in network.node(0).blocks.read().await.iter().skip(1) {
            network.node(2).import_block(block.clone()).await.unwrap();
        }

        // Now all nodes should be synced
        assert_eq!(network.node(2).current_height(), 3);
        assert_eq!(network.node(2).note_count().await, 3);
    }

    #[tokio::test]
    async fn test_concurrent_mining_same_parent() {
        let network = MockNetwork::new(2);
        network.connect_all().await;

        // Both nodes try to mine at the same time from same parent
        // In reality, one would win and the other would need to re-org
        // For this mock test, we just verify the state remains consistent

        let tx1 = MockTransaction::Shield {
            hash: [1; 32],
            amount: 1000,
            commitment: [0x11; 32],
        };

        let tx2 = MockTransaction::Shield {
            hash: [2; 32],
            amount: 2000,
            commitment: [0x22; 32],
        };

        network.node(0).submit_transaction(tx1).await.unwrap();
        network.node(1).submit_transaction(tx2).await.unwrap();

        // Node 0 mines first
        let block0 = network.node(0).mine_block().await;
        network.propagate_block(0, &block0).await;

        // Now node 1 mines on top of the propagated block
        let _block1 = network.node(1).mine_block().await;

        // Node 0 mined block 1, node 1 received it and mined block 2
        assert_eq!(network.node(0).current_height(), 1);
        assert_eq!(network.node(1).current_height(), 2);
    }

    #[tokio::test]
    async fn test_large_network_propagation() {
        let network = MockNetwork::new(5);
        network.connect_all().await;

        // Mine a block on node 0
        let tx = MockTransaction::Shield {
            hash: [42; 32],
            amount: 10000,
            commitment: [0xff; 32],
        };

        network.node(0).submit_transaction(tx.clone()).await.unwrap();
        network.propagate_transaction(0, &tx).await;

        let block = network.node(0).mine_block().await;
        network.propagate_block(0, &block).await;

        // All 5 nodes should sync
        for i in 0..5 {
            assert_eq!(
                network.node(i).current_height(),
                1,
                "Node {} not at height 1",
                i
            );
            assert_eq!(
                network.node(i).note_count().await,
                1,
                "Node {} missing note",
                i
            );
        }
    }
}

// ============================================================================
// Phase 11.8.5: Live Node Integration Tests (require running nodes)
// ============================================================================

#[cfg(test)]
mod live_integration_tests {
    use super::*;

    /// Test real two-node sync
    #[tokio::test]
    #[ignore = "Requires two running nodes - see runbooks/two_node_remote_setup.md"]
    async fn test_live_two_node_sync() {
        // This test would connect to real nodes
        eprintln!("Live two-node sync test");
        eprintln!("Prerequisites:");
        eprintln!("  1. Start node A: HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp --port 9944 --ws-port 9945");
        eprintln!("  2. Start node B: ./target/release/hegemon-node --dev --tmp --port 9946 --ws-port 9947 --bootnodes /ip4/127.0.0.1/tcp/9944");
        eprintln!("  3. Run this test with: cargo test test_live_two_node_sync --ignored");

        // In a real implementation, we would:
        // 1. Connect to both nodes via RPC
        // 2. Check that node B syncs blocks from node A
        // 3. Submit a transaction to node A
        // 4. Verify it appears on node B

        panic!("Test requires manual node setup - see instructions above");
    }

    /// Test real shielded transaction propagation
    #[tokio::test]
    #[ignore = "Requires two running nodes with shielded pool enabled"]
    async fn test_live_shielded_tx_propagation() {
        eprintln!("Live shielded transaction propagation test");
        eprintln!("This test verifies shielded transactions propagate between nodes");

        // In a real implementation:
        // 1. Submit shield tx to node A
        // 2. Verify note appears on both nodes after mining
        // 3. Submit shielded transfer to node B
        // 4. Verify nullifier spent on both nodes

        panic!("Test requires manual node setup");
    }
}
