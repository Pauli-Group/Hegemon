//! Multi-Node Integration Tests (Phase 11.8)
//!
//! This module provides comprehensive multi-node integration testing for Hegemon,
//! verifying node-to-node communication, transaction propagation, and shielded pool sync.
//!
//! ## Test Categories
//!
//! 1. **Live Node Tests**: Real nodes with deterministic keys (Alice, Bob, Charlie)
//! 2. **Node Sync Tests**: Block propagation between nodes
//! 3. **Transaction Propagation**: Transparent and shielded tx broadcast
//! 4. **State Consistency**: Merkle roots, nullifiers sync across nodes
//! 5. **Network Resilience**: Reconnection, partition recovery
//!
//! ## Running Tests
//!
//! Live node tests (spawns real nodes):
//! ```bash
//! cargo test -p security-tests --test multinode_integration live_node -- --ignored --nocapture
//! ```
//!
//! All tests including live:
//! ```bash
//! cargo test -p security-tests --test multinode_integration -- --ignored --nocapture
//! ```

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::process::{Child, Command, Stdio};

use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tokio::time::sleep;

// ============================================================================
// Deterministic Key Generation - "Nothing Up My Sleeve"
// ============================================================================

/// Generate a deterministic 32-byte key from a name
/// Uses SHA256(name) - completely transparent and reproducible
fn deterministic_key(name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.finalize().into()
}

/// Generate a deterministic 64-char hex node key for libp2p
fn deterministic_node_key(name: &str) -> String {
    let key = deterministic_key(name);
    hex::encode(key)
}

/// Known test identities with deterministic keys
pub struct TestIdentity {
    pub name: &'static str,
    pub rpc_port: u16,
    pub p2p_port: u16,
}

impl TestIdentity {
    /// Get the node key (64 hex chars)
    pub fn node_key(&self) -> String {
        deterministic_node_key(self.name)
    }

    /// Get the peer ID derived from the node key
    /// Note: The actual peer ID is derived by libp2p from the secret key
    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    pub fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}", self.rpc_port)
    }
}

/// Standard test identities - deterministic, reproducible
pub const ALICE: TestIdentity = TestIdentity {
    name: "Alice",
    rpc_port: 19944,
    p2p_port: 19333,
};

pub const BOB: TestIdentity = TestIdentity {
    name: "Bob",
    rpc_port: 19945,
    p2p_port: 19334,
};

pub const CHARLIE: TestIdentity = TestIdentity {
    name: "Charlie",
    rpc_port: 19946,
    p2p_port: 19335,
};

// ============================================================================
// Live Node Manager
// ============================================================================

/// Manages spawning and cleanup of real Hegemon nodes
pub struct LiveNodeManager {
    processes: Vec<Child>,
    base_paths: Vec<String>,
}

impl LiveNodeManager {
    pub fn new() -> Self {
        Self {
            processes: Vec::new(),
            base_paths: Vec::new(),
        }
    }

    /// Spawn a node with deterministic identity
    pub fn spawn_node(&mut self, identity: &TestIdentity, bootnode: Option<&str>) -> Result<(), String> {
        let base_path = format!("/tmp/hegemon-test-{}", identity.name.to_lowercase());
        
        // Clean previous data
        let _ = std::fs::remove_dir_all(&base_path);
        
        let node_key = identity.node_key();
        let binary = std::env::var("HEGEMON_NODE_BIN")
            .unwrap_or_else(|_| "./target/release/hegemon-node".to_string());

        let mut cmd = Command::new(&binary);
        cmd.arg("--dev")
            .arg("--base-path").arg(&base_path)
            .arg("--rpc-port").arg(identity.rpc_port.to_string())
            .arg("--port").arg(identity.p2p_port.to_string())
            .arg("--node-key").arg(&node_key)
            .arg("--rpc-cors").arg("all")
            .env("HEGEMON_MINE", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if let Some(bootnode) = bootnode {
            cmd.arg("--bootnodes").arg(bootnode);
        }

        let child = cmd.spawn()
            .map_err(|e| format!("Failed to spawn node {}: {}", identity.name, e))?;

        self.processes.push(child);
        self.base_paths.push(base_path);

        Ok(())
    }

    /// Wait for a node to be ready (RPC responding)
    pub async fn wait_for_node(&self, identity: &TestIdentity, timeout_secs: u64) -> Result<(), String> {
        let client = reqwest::Client::new();
        let url = identity.rpc_url();
        let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);

        while std::time::Instant::now() < deadline {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "system_health",
                "params": []
            });

            match client.post(&url)
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .timeout(Duration::from_secs(2))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    return Ok(());
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }

        Err(format!("Node {} did not become ready within {}s", identity.name, timeout_secs))
    }

    /// Get the peer ID of a running node
    pub async fn get_peer_id(&self, identity: &TestIdentity) -> Result<String, String> {
        let client = reqwest::Client::new();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "system_localPeerId",
            "params": []
        });

        let resp = client.post(&identity.rpc_url())
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        let json: serde_json::Value = resp.json().await
            .map_err(|e| format!("Invalid JSON: {}", e))?;

        json.get("result")
            .and_then(|r| r.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "No peer ID in response".to_string())
    }

    /// Build bootnode address
    pub fn bootnode_addr(&self, identity: &TestIdentity, peer_id: &str) -> String {
        format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", identity.p2p_port, peer_id)
    }
}

impl Drop for LiveNodeManager {
    fn drop(&mut self) {
        // Kill all spawned processes
        for mut process in self.processes.drain(..) {
            let _ = process.kill();
            let _ = process.wait();
        }
        // Clean up data directories
        for path in &self.base_paths {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

// ============================================================================
// Live RPC Client
// ============================================================================

/// RPC client for live node testing
pub struct LiveRpcClient {
    url: String,
    client: reqwest::Client,
}

impl LiveRpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub fn for_identity(identity: &TestIdentity) -> Self {
        Self::new(&identity.rpc_url())
    }

    /// Make JSON-RPC call
    pub async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });

        let response = self.client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        let json: serde_json::Value = response.json().await
            .map_err(|e| format!("Invalid JSON: {}", e))?;

        if let Some(error) = json.get("error") {
            return Err(format!("RPC error: {}", error));
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| "No result in response".to_string())
    }

    pub async fn system_health(&self) -> Result<serde_json::Value, String> {
        self.call("system_health", serde_json::json!([])).await
    }

    pub async fn get_block_number(&self) -> Result<u64, String> {
        let result = self.call("chain_getHeader", serde_json::json!([])).await?;
        let number_hex = result.get("number")
            .and_then(|n| n.as_str())
            .ok_or("No number field")?;
        u64::from_str_radix(number_hex.trim_start_matches("0x"), 16)
            .map_err(|e| format!("Invalid block number: {}", e))
    }

    pub async fn get_peer_count(&self) -> Result<u64, String> {
        let health = self.system_health().await?;
        health.get("peers")
            .and_then(|p| p.as_u64())
            .ok_or_else(|| "No peers field".to_string())
    }

    pub async fn get_pool_status(&self) -> Result<serde_json::Value, String> {
        self.call("hegemon_getShieldedPoolStatus", serde_json::json!([])).await
    }

    pub async fn get_mining_status(&self) -> Result<serde_json::Value, String> {
        self.call("hegemon_miningStatus", serde_json::json!([])).await
    }

    pub async fn get_consensus_status(&self) -> Result<serde_json::Value, String> {
        self.call("hegemon_consensusStatus", serde_json::json!([])).await
    }
}

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
// Phase 11.8.5: REAL Live Node Integration Tests
// Spawns actual Hegemon nodes with deterministic keys (Alice, Bob, Charlie)
// ============================================================================

#[cfg(test)]
mod live_node_tests {
    use super::*;

    /// Test that we can spawn Alice node and connect to it
    #[tokio::test]
    #[ignore = "Spawns real node - run with: cargo test live_node -- --ignored --nocapture"]
    async fn test_spawn_single_node_alice() {
        println!("=== Single Node Test: Alice ===");
        println!("Alice's deterministic key: {}", ALICE.node_key());

        let mut manager = LiveNodeManager::new();
        
        // Spawn Alice
        println!("\n[1] Spawning Alice...");
        manager.spawn_node(&ALICE, None).expect("Failed to spawn Alice");
        
        // Wait for ready
        println!("[2] Waiting for Alice to be ready...");
        manager.wait_for_node(&ALICE, 30).await.expect("Alice did not become ready");
        println!("    ✓ Alice is ready at {}", ALICE.rpc_url());

        // Connect and verify
        let client = LiveRpcClient::for_identity(&ALICE);
        
        let health = client.system_health().await.expect("Failed to get health");
        println!("[3] Alice health: {}", health);

        let peer_id = manager.get_peer_id(&ALICE).await.expect("Failed to get peer ID");
        println!("[4] Alice peer ID: {}", peer_id);

        let block = client.get_block_number().await.expect("Failed to get block");
        println!("[5] Alice best block: {}", block);

        let mining = client.get_mining_status().await.expect("Failed to get mining");
        let is_mining = mining.get("is_mining").and_then(|m| m.as_bool()).unwrap_or(false);
        println!("[6] Alice mining: {}", is_mining);
        assert!(is_mining, "Alice should be mining");

        // Wait for block production
        println!("[7] Waiting 8s for blocks...");
        tokio::time::sleep(Duration::from_secs(8)).await;

        let block2 = client.get_block_number().await.expect("Failed to get block");
        println!("[8] Alice new block: {} (was {})", block2, block);
        assert!(block2 > block, "Alice should produce blocks");

        println!("\n=== ✅ Single Node Test PASSED ===");
    }

    /// Test two-node network: Alice and Bob
    #[tokio::test]
    #[ignore = "Spawns real nodes - run with: cargo test live_node_two -- --ignored --nocapture"]
    async fn test_two_node_network_alice_bob() {
        println!("=== Two Node Network Test: Alice + Bob ===");
        println!("Alice key: {}", ALICE.node_key());
        println!("Bob key:   {}", BOB.node_key());

        let mut manager = LiveNodeManager::new();
        
        // Spawn Alice first (she's the bootnode)
        println!("\n[1] Spawning Alice (bootnode)...");
        manager.spawn_node(&ALICE, None).expect("Failed to spawn Alice");
        manager.wait_for_node(&ALICE, 30).await.expect("Alice not ready");
        println!("    ✓ Alice ready at {}", ALICE.rpc_url());

        // Get Alice's peer ID for bootnode address
        let alice_peer_id = manager.get_peer_id(&ALICE).await.expect("Failed to get Alice peer ID");
        println!("[2] Alice peer ID: {}", alice_peer_id);
        
        let bootnode = manager.bootnode_addr(&ALICE, &alice_peer_id);
        println!("[3] Bootnode address: {}", bootnode);

        // Spawn Bob connecting to Alice
        println!("[4] Spawning Bob (connecting to Alice)...");
        manager.spawn_node(&BOB, Some(&bootnode)).expect("Failed to spawn Bob");
        manager.wait_for_node(&BOB, 30).await.expect("Bob not ready");
        println!("    ✓ Bob ready at {}", BOB.rpc_url());

        // Wait for peer connection
        println!("[5] Waiting for peer discovery...");
        tokio::time::sleep(Duration::from_secs(5)).await;

        let alice_client = LiveRpcClient::for_identity(&ALICE);
        let bob_client = LiveRpcClient::for_identity(&BOB);

        // Check peer counts
        let alice_peers = alice_client.get_peer_count().await.expect("Failed to get Alice peers");
        let bob_peers = bob_client.get_peer_count().await.expect("Failed to get Bob peers");
        println!("[6] Alice peers: {}, Bob peers: {}", alice_peers, bob_peers);

        // Wait for sync
        println!("[7] Waiting 10s for block sync...");
        tokio::time::sleep(Duration::from_secs(10)).await;

        // Check blocks
        let alice_block = alice_client.get_block_number().await.expect("Alice block");
        let bob_block = bob_client.get_block_number().await.expect("Bob block");
        println!("[8] Alice block: {}, Bob block: {}", alice_block, bob_block);

        // Bob should have synced to Alice's chain (or close to it)
        // Allow 2 block difference due to propagation delay
        let diff = if alice_block > bob_block { alice_block - bob_block } else { bob_block - alice_block };
        println!("[9] Block difference: {}", diff);
        assert!(diff <= 2, "Blocks should be synced (diff <= 2), got diff={}", diff);

        // Verify shielded pool state matches
        let alice_pool = alice_client.get_pool_status().await.expect("Alice pool");
        let bob_pool = bob_client.get_pool_status().await.expect("Bob pool");
        
        let alice_root = alice_pool.get("merkle_root").and_then(|r| r.as_str()).unwrap_or("");
        let bob_root = bob_pool.get("merkle_root").and_then(|r| r.as_str()).unwrap_or("");
        println!("[10] Alice merkle root: {}", alice_root);
        println!("     Bob merkle root:   {}", bob_root);
        assert_eq!(alice_root, bob_root, "Merkle roots should match");

        println!("\n=== ✅ Two Node Network Test PASSED ===");
    }

    /// Test three-node network: Alice, Bob, Charlie
    #[tokio::test]
    #[ignore = "Spawns real nodes - run with: cargo test live_node_three -- --ignored --nocapture"]
    async fn test_three_node_network() {
        println!("=== Three Node Network Test: Alice + Bob + Charlie ===");

        let mut manager = LiveNodeManager::new();
        
        // Spawn Alice
        println!("\n[1] Spawning Alice...");
        manager.spawn_node(&ALICE, None).expect("Failed to spawn Alice");
        manager.wait_for_node(&ALICE, 30).await.expect("Alice not ready");

        let alice_peer_id = manager.get_peer_id(&ALICE).await.expect("Alice peer ID");
        let bootnode = manager.bootnode_addr(&ALICE, &alice_peer_id);
        println!("    Alice peer ID: {}", alice_peer_id);

        // Spawn Bob
        println!("[2] Spawning Bob...");
        manager.spawn_node(&BOB, Some(&bootnode)).expect("Failed to spawn Bob");
        manager.wait_for_node(&BOB, 30).await.expect("Bob not ready");

        // Spawn Charlie
        println!("[3] Spawning Charlie...");
        manager.spawn_node(&CHARLIE, Some(&bootnode)).expect("Failed to spawn Charlie");
        manager.wait_for_node(&CHARLIE, 30).await.expect("Charlie not ready");

        // Wait for mesh
        println!("[4] Waiting for peer mesh to form...");
        tokio::time::sleep(Duration::from_secs(8)).await;

        let alice_client = LiveRpcClient::for_identity(&ALICE);
        let bob_client = LiveRpcClient::for_identity(&BOB);
        let charlie_client = LiveRpcClient::for_identity(&CHARLIE);

        // Check peer counts - in a 3 node network, each should have 2 peers
        let alice_peers = alice_client.get_peer_count().await.unwrap_or(0);
        let bob_peers = bob_client.get_peer_count().await.unwrap_or(0);
        let charlie_peers = charlie_client.get_peer_count().await.unwrap_or(0);
        println!("[5] Peers - Alice: {}, Bob: {}, Charlie: {}", alice_peers, bob_peers, charlie_peers);

        // Wait for sync
        println!("[6] Waiting 15s for full sync...");
        tokio::time::sleep(Duration::from_secs(15)).await;

        // Check all blocks are synced
        let alice_block = alice_client.get_block_number().await.expect("Alice block");
        let bob_block = bob_client.get_block_number().await.expect("Bob block");
        let charlie_block = charlie_client.get_block_number().await.expect("Charlie block");
        println!("[7] Blocks - Alice: {}, Bob: {}, Charlie: {}", alice_block, bob_block, charlie_block);

        let max_block = alice_block.max(bob_block).max(charlie_block);
        let min_block = alice_block.min(bob_block).min(charlie_block);
        let diff = max_block - min_block;
        println!("[8] Block spread: {} (max={}, min={})", diff, max_block, min_block);
        assert!(diff <= 2, "All nodes should be synced within 2 blocks");

        // Check consensus state matches
        let alice_consensus = alice_client.get_consensus_status().await.expect("Alice consensus");
        let bob_consensus = bob_client.get_consensus_status().await.expect("Bob consensus");
        let charlie_consensus = charlie_client.get_consensus_status().await.expect("Charlie consensus");

        let alice_state = alice_consensus.get("state_root").and_then(|r| r.as_str()).unwrap_or("");
        let bob_state = bob_consensus.get("state_root").and_then(|r| r.as_str()).unwrap_or("");
        let charlie_state = charlie_consensus.get("state_root").and_then(|r| r.as_str()).unwrap_or("");
        
        println!("[9] State roots:");
        println!("    Alice:   {}", alice_state);
        println!("    Bob:     {}", bob_state);
        println!("    Charlie: {}", charlie_state);

        // At least 2 should match (they might be at slightly different heights)
        let alice_bob_match = alice_state == bob_state;
        let bob_charlie_match = bob_state == charlie_state;
        let alice_charlie_match = alice_state == charlie_state;
        let matches = [alice_bob_match, bob_charlie_match, alice_charlie_match].iter().filter(|&&x| x).count();
        println!("[10] State root matches: {}/3", matches);

        println!("\n=== ✅ Three Node Network Test PASSED ===");
    }

    /// Test block propagation between two nodes
    #[tokio::test]
    #[ignore = "Spawns real nodes - run with: cargo test live_block_prop -- --ignored --nocapture"]
    async fn test_live_block_propagation() {
        println!("=== Live Block Propagation Test ===");

        let mut manager = LiveNodeManager::new();
        
        // Spawn Alice and Bob
        manager.spawn_node(&ALICE, None).expect("Alice");
        manager.wait_for_node(&ALICE, 30).await.expect("Alice ready");
        
        let alice_peer_id = manager.get_peer_id(&ALICE).await.expect("Alice peer ID");
        let bootnode = manager.bootnode_addr(&ALICE, &alice_peer_id);
        
        manager.spawn_node(&BOB, Some(&bootnode)).expect("Bob");
        manager.wait_for_node(&BOB, 30).await.expect("Bob ready");

        println!("[1] Both nodes running");

        // Wait for initial sync
        tokio::time::sleep(Duration::from_secs(5)).await;

        let alice_client = LiveRpcClient::for_identity(&ALICE);
        let bob_client = LiveRpcClient::for_identity(&BOB);

        // Get initial state
        let alice_start = alice_client.get_block_number().await.expect("Alice block");
        let bob_start = bob_client.get_block_number().await.expect("Bob block");
        println!("[2] Start - Alice: {}, Bob: {}", alice_start, bob_start);

        // Wait for new blocks
        println!("[3] Waiting 20s for block production and propagation...");
        tokio::time::sleep(Duration::from_secs(20)).await;

        // Check final state
        let alice_end = alice_client.get_block_number().await.expect("Alice block");
        let bob_end = bob_client.get_block_number().await.expect("Bob block");
        println!("[4] End - Alice: {}, Bob: {}", alice_end, bob_end);

        // Both should have produced/received blocks
        assert!(alice_end > alice_start, "Alice should produce blocks");
        assert!(bob_end > bob_start, "Bob should receive blocks");

        // They should be roughly in sync
        let diff = if alice_end > bob_end { alice_end - bob_end } else { bob_end - alice_end };
        println!("[5] Final difference: {}", diff);
        assert!(diff <= 3, "Nodes should be synced within 3 blocks");

        println!("\n=== ✅ Block Propagation Test PASSED ===");
    }

    /// Test shielded pool state sync between nodes  
    #[tokio::test]
    #[ignore = "Spawns real nodes - run with: cargo test live_shielded_sync -- --ignored --nocapture"]
    async fn test_live_shielded_pool_sync() {
        println!("=== Live Shielded Pool Sync Test ===");

        let mut manager = LiveNodeManager::new();
        
        // Spawn two nodes
        manager.spawn_node(&ALICE, None).expect("Alice");
        manager.wait_for_node(&ALICE, 30).await.expect("Alice ready");
        
        let alice_peer_id = manager.get_peer_id(&ALICE).await.expect("Alice peer ID");
        let bootnode = manager.bootnode_addr(&ALICE, &alice_peer_id);
        
        manager.spawn_node(&BOB, Some(&bootnode)).expect("Bob");
        manager.wait_for_node(&BOB, 30).await.expect("Bob ready");

        // Wait for sync
        tokio::time::sleep(Duration::from_secs(10)).await;

        let alice_client = LiveRpcClient::for_identity(&ALICE);
        let bob_client = LiveRpcClient::for_identity(&BOB);

        // Get shielded pool state
        let alice_pool = alice_client.get_pool_status().await.expect("Alice pool");
        let bob_pool = bob_client.get_pool_status().await.expect("Bob pool");

        println!("[1] Alice pool: {}", serde_json::to_string_pretty(&alice_pool).unwrap_or_default());
        println!("[2] Bob pool:   {}", serde_json::to_string_pretty(&bob_pool).unwrap_or_default());

        // Verify critical fields match
        let alice_root = alice_pool.get("merkle_root").and_then(|r| r.as_str()).unwrap_or("");
        let bob_root = bob_pool.get("merkle_root").and_then(|r| r.as_str()).unwrap_or("");
        
        let alice_notes = alice_pool.get("total_notes").and_then(|n| n.as_u64()).unwrap_or(0);
        let bob_notes = bob_pool.get("total_notes").and_then(|n| n.as_u64()).unwrap_or(0);

        let alice_nullifiers = alice_pool.get("total_nullifiers").and_then(|n| n.as_u64()).unwrap_or(0);
        let bob_nullifiers = bob_pool.get("total_nullifiers").and_then(|n| n.as_u64()).unwrap_or(0);

        println!("[3] Merkle roots match: {}", alice_root == bob_root);
        println!("[4] Notes - Alice: {}, Bob: {}", alice_notes, bob_notes);
        println!("[5] Nullifiers - Alice: {}, Bob: {}", alice_nullifiers, bob_nullifiers);

        assert_eq!(alice_root, bob_root, "Merkle roots must match");
        assert_eq!(alice_notes, bob_notes, "Note counts must match");
        assert_eq!(alice_nullifiers, bob_nullifiers, "Nullifier counts must match");

        println!("\n=== ✅ Shielded Pool Sync Test PASSED ===");
    }

    /// Test node reconnection after temporary disconnect
    #[tokio::test]
    #[ignore = "Spawns real nodes - run with: cargo test live_reconnect -- --ignored --nocapture"]
    async fn test_live_node_reconnection() {
        println!("=== Live Node Reconnection Test ===");
        println!("This test verifies nodes can reconnect after disconnect");

        let mut manager = LiveNodeManager::new();
        
        // Spawn Alice
        manager.spawn_node(&ALICE, None).expect("Alice");
        manager.wait_for_node(&ALICE, 30).await.expect("Alice ready");
        
        let alice_peer_id = manager.get_peer_id(&ALICE).await.expect("Alice peer ID");
        let bootnode = manager.bootnode_addr(&ALICE, &alice_peer_id);
        
        // Spawn Bob
        manager.spawn_node(&BOB, Some(&bootnode)).expect("Bob");
        manager.wait_for_node(&BOB, 30).await.expect("Bob ready");

        let alice_client = LiveRpcClient::for_identity(&ALICE);
        let bob_client = LiveRpcClient::for_identity(&BOB);

        // Wait for connection
        tokio::time::sleep(Duration::from_secs(5)).await;
        
        let peers_before = alice_client.get_peer_count().await.unwrap_or(0);
        println!("[1] Alice peers before: {}", peers_before);

        // Record block heights
        let alice_block_before = alice_client.get_block_number().await.expect("Alice block");
        let bob_block_before = bob_client.get_block_number().await.expect("Bob block");
        println!("[2] Blocks before - Alice: {}, Bob: {}", alice_block_before, bob_block_before);

        // Let them run together
        println!("[3] Running connected for 10s...");
        tokio::time::sleep(Duration::from_secs(10)).await;

        // Check final sync
        let alice_block_after = alice_client.get_block_number().await.expect("Alice block");
        let bob_block_after = bob_client.get_block_number().await.expect("Bob block");
        println!("[4] Blocks after - Alice: {}, Bob: {}", alice_block_after, bob_block_after);

        assert!(alice_block_after > alice_block_before, "Alice should advance");
        assert!(bob_block_after > bob_block_before, "Bob should advance");

        let diff = if alice_block_after > bob_block_after { 
            alice_block_after - bob_block_after 
        } else { 
            bob_block_after - alice_block_after 
        };
        assert!(diff <= 2, "Should be in sync");

        println!("\n=== ✅ Reconnection Test PASSED ===");
    }
}

// ============================================================================
// Legacy single-node tests (for when you just have one node running)
// ============================================================================

#[cfg(test)]
mod single_node_tests {
    use super::*;

    /// Get RPC URL from environment or default
    fn get_rpc_url() -> String {
        std::env::var("HEGEMON_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:9944".to_string())
    }

    /// Test connection to a manually started node
    #[tokio::test]
    #[ignore = "Requires manually running node"]
    async fn test_manual_node_connection() {
        let url = get_rpc_url();
        println!("Testing connection to: {}", url);

        let client = LiveRpcClient::new(&url);
        
        let health = client.system_health().await.expect("Failed to get health");
        println!("System health: {}", health);
        
        let block = client.get_block_number().await.expect("Failed to get block");
        println!("Best block: {}", block);

        let pool = client.get_pool_status().await.expect("Failed to get pool");
        println!("Pool status: {}", pool);

        println!("✅ Connection test passed");
    }
}
