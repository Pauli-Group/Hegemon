//! Production ShieldedPoolService Implementation
//!
//! This module implements the `ShieldedPoolService` trait for both:
//! - Production use with runtime API calls
//! - Testing with in-memory mock storage
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    RPC Server                               │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │              ShieldedRpc                             │   │
//! │  │  - submit_shielded_transfer()                        │   │
//! │  │  - get_encrypted_notes()                             │   │
//! │  │  - get_merkle_witness()                              │   │
//! │  └───────────────────────┬─────────────────────────────┘   │
//! │                          │                                  │
//! │  ┌───────────────────────▼─────────────────────────────┐   │
//! │  │  ShieldedPoolServiceImpl (production)                │   │
//! │  │  - Queries runtime via ShieldedPoolApi               │   │
//! │  │  - Submits extrinsics through transaction pool       │   │
//! │  ├─────────────────────────────────────────────────────┤   │
//! │  │  MockShieldedPoolService (testing)                   │   │
//! │  │  - In-memory storage for testing                     │   │
//! │  │  - Full trait implementation                         │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Production Implementation
//!
//! The `ShieldedPoolServiceImpl` uses runtime API calls to query the
//! `pallet-shielded-pool` storage:
//! - `ShieldedPoolApi::get_encrypted_notes()` for note fetching
//! - `ShieldedPoolApi::get_merkle_witness()` for Merkle proofs
//! - `ShieldedPoolApi::is_nullifier_spent()` for double-spend checks
//! - Extrinsic submission for shielded transfers

use super::shielded::{ShieldedPoolService, ShieldedPoolStatus};
use std::sync::{Arc, RwLock};

/// Mock implementation for testing without a real client
///
/// Uses std::sync::RwLock instead of tokio::sync::RwLock to avoid
/// nested runtime issues when called from synchronous trait methods.
pub struct MockShieldedPoolService {
    /// Notes storage: (index, ciphertext, block_height, commitment)
    notes: RwLock<Vec<(u64, Vec<u8>, u64, [u8; 32])>>,
    /// Spent nullifiers
    nullifiers: RwLock<Vec<[u8; 32]>>,
    /// Valid anchors (Merkle roots)
    anchors: RwLock<Vec<[u8; 32]>>,
    /// Pool balance
    balance: RwLock<u128>,
    /// Mock height
    height: RwLock<u64>,
    /// Current merkle root
    merkle_root: RwLock<[u8; 32]>,
}

impl Default for MockShieldedPoolService {
    fn default() -> Self {
        Self::new()
    }
}

impl MockShieldedPoolService {
    /// Create a new mock service
    pub fn new() -> Self {
        let initial_root = [0u8; 32];
        Self {
            notes: RwLock::new(Vec::new()),
            nullifiers: RwLock::new(Vec::new()),
            anchors: RwLock::new(vec![initial_root]),
            balance: RwLock::new(0),
            height: RwLock::new(0),
            merkle_root: RwLock::new(initial_root),
        }
    }

    /// Add a mock note for testing (synchronous)
    pub fn add_note(&self, ciphertext: Vec<u8>, commitment: [u8; 32]) {
        let mut notes = self.notes.write().expect("notes lock poisoned");
        let height = *self.height.read().expect("height lock poisoned");
        let index = notes.len() as u64;
        notes.push((index, ciphertext, height, commitment));
    }

    /// Set mock height (synchronous)
    pub fn set_height(&self, height: u64) {
        *self.height.write().expect("height lock poisoned") = height;
    }

    /// Add a valid anchor (synchronous)
    pub fn add_anchor(&self, anchor: [u8; 32]) {
        let mut anchors = self.anchors.write().expect("anchors lock poisoned");
        anchors.push(anchor);
    }
}

impl ShieldedPoolService for MockShieldedPoolService {
    fn submit_shielded_transfer(
        &self,
        _proof: Vec<u8>,
        nullifiers: Vec<[u8; 32]>,
        commitments: Vec<[u8; 32]>,
        encrypted_notes: Vec<Vec<u8>>,
        _anchor: [u8; 32],
        _binding_sig: [u8; 64],
        value_balance: i128,
    ) -> Result<[u8; 32], String> {
        let nullifier_count = nullifiers.len();
        let commitment_count = commitments.len();

        // Add nullifiers to spent set
        {
            let mut nfs = self.nullifiers.write().expect("nullifiers lock poisoned");
            for nf in nullifiers {
                nfs.push(nf);
            }
        }

        // Add new notes
        {
            let mut notes = self.notes.write().expect("notes lock poisoned");
            let height = *self.height.read().expect("height lock poisoned");
            for (commitment, encrypted_note) in commitments.iter().zip(encrypted_notes.iter()) {
                let index = notes.len() as u64;
                notes.push((index, encrypted_note.clone(), height, *commitment));
            }
        }

        // Update balance
        {
            let mut bal = self.balance.write().expect("balance lock poisoned");
            if value_balance > 0 {
                *bal = bal.saturating_add(value_balance as u128);
            } else if value_balance < 0 {
                *bal = bal.saturating_sub((-value_balance) as u128);
            }
        }

        // Return mock tx hash
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = 0xab;
        tx_hash[31] = (commitment_count as u8).wrapping_add(nullifier_count as u8);

        tracing::info!(
            nullifiers = nullifier_count,
            commitments = commitment_count,
            value_balance = value_balance,
            tx_hash = %hex::encode(tx_hash),
            "Mock shielded transfer submitted"
        );

        Ok(tx_hash)
    }

    fn get_encrypted_notes(
        &self,
        start: u64,
        limit: usize,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<(u64, Vec<u8>, u64, [u8; 32])>, String> {
        let notes = self.notes.read().expect("notes lock poisoned");
        Ok(notes
            .iter()
            .skip(start as usize)
            .take(limit)
            .filter(|(_, _, block, _)| {
                let from_ok = from_block.map_or(true, |fb| *block >= fb);
                let to_ok = to_block.map_or(true, |tb| *block <= tb);
                from_ok && to_ok
            })
            .cloned()
            .collect())
    }

    fn encrypted_note_count(&self) -> u64 {
        self.notes.read().expect("notes lock poisoned").len() as u64
    }

    fn get_merkle_witness(
        &self,
        _position: u64,
    ) -> Result<(Vec<[u8; 32]>, Vec<bool>, [u8; 32]), String> {
        // Return mock witness with 32 levels
        let siblings: Vec<[u8; 32]> = (0..32).map(|i| [i; 32]).collect();
        let indices: Vec<bool> = (0..32).map(|_| false).collect();
        let root = *self.merkle_root.read().expect("merkle_root lock poisoned");

        Ok((siblings, indices, root))
    }

    fn get_pool_status(&self) -> ShieldedPoolStatus {
        let notes = self.notes.read().expect("notes lock poisoned");
        let nfs = self.nullifiers.read().expect("nullifiers lock poisoned");
        let bal = *self.balance.read().expect("balance lock poisoned");
        let h = *self.height.read().expect("height lock poisoned");
        let root = *self.merkle_root.read().expect("merkle_root lock poisoned");

        ShieldedPoolStatus {
            total_notes: notes.len() as u64,
            total_nullifiers: nfs.len() as u64,
            merkle_root: format!("0x{}", hex::encode(root)),
            tree_depth: 32,
            pool_balance: bal,
            last_update_block: h,
        }
    }

    fn shield(
        &self,
        amount: u128,
        commitment: [u8; 32],
        encrypted_note: Vec<u8>,
    ) -> Result<([u8; 32], u64), String> {
        let note_index = {
            let mut notes = self.notes.write().expect("notes lock poisoned");
            let mut bal = self.balance.write().expect("balance lock poisoned");
            let height = *self.height.read().expect("height lock poisoned");

            let index = notes.len() as u64;
            notes.push((index, encrypted_note, height, commitment));
            *bal = bal.saturating_add(amount);

            index
        };

        // Mock tx hash
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = 0xcd;
        tx_hash[1..17].copy_from_slice(&amount.to_le_bytes());

        tracing::info!(
            amount = amount,
            commitment = %hex::encode(commitment),
            note_index = note_index,
            "Mock shield operation"
        );

        Ok((tx_hash, note_index))
    }

    fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
        let nfs = self.nullifiers.read().expect("nullifiers lock poisoned");
        nfs.contains(nullifier)
    }

    fn is_valid_anchor(&self, anchor: &[u8; 32]) -> bool {
        let anchors = self.anchors.read().expect("anchors lock poisoned");
        anchors.contains(anchor)
    }

    fn chain_height(&self) -> u64 {
        *self.height.read().expect("height lock poisoned")
    }
}

/// Thread-safe wrapper for testing
pub type SharedMockShieldedPoolService = Arc<MockShieldedPoolService>;

// =============================================================================
// Production Implementation (using Runtime API)
// =============================================================================

use codec::Codec;
use runtime::apis::ShieldedPoolApi;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;

/// Production implementation using Substrate client and runtime API.
///
/// This service queries the runtime's `ShieldedPoolApi` for all read operations
/// and submits extrinsics through the transaction pool for write operations.
///
/// # Type Parameters
///
/// * `C` - The client type implementing `ProvideRuntimeApi` and `HeaderBackend`
/// * `Block` - The block type
pub struct ShieldedPoolServiceImpl<C, Block>
where
    Block: BlockT,
{
    /// Reference to the Substrate client
    client: Arc<C>,
    /// Phantom data for the block type
    _phantom: PhantomData<Block>,
}

impl<C, Block> ShieldedPoolServiceImpl<C, Block>
where
    Block: BlockT,
    C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
    C::Api: runtime::apis::ShieldedPoolApi<Block>,
{
    /// Create a new production shielded pool service.
    pub fn new(client: Arc<C>) -> Self {
        Self {
            client,
            _phantom: PhantomData,
        }
    }

    /// Get the best block hash for runtime API calls.
    fn best_hash(&self) -> Block::Hash {
        self.client.info().best_hash
    }
}

impl<C, Block> ShieldedPoolService for ShieldedPoolServiceImpl<C, Block>
where
    Block: BlockT,
    C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
    C::Api: runtime::apis::ShieldedPoolApi<Block>,
    Block::Hash: Codec,
{
    fn submit_shielded_transfer(
        &self,
        _proof: Vec<u8>,
        _nullifiers: Vec<[u8; 32]>,
        _commitments: Vec<[u8; 32]>,
        _encrypted_notes: Vec<Vec<u8>>,
        _anchor: [u8; 32],
        _binding_sig: [u8; 64],
        _value_balance: i128,
    ) -> Result<[u8; 32], String> {
        // Transaction submission requires building an extrinsic and submitting
        // to the transaction pool. This will be implemented when full extrinsic
        // construction is wired up.
        //
        // For now, return an error indicating this is not yet implemented.
        Err("Production extrinsic submission not yet implemented. Use RPC `author_submitExtrinsic` directly.".to_string())
    }

    fn get_encrypted_notes(
        &self,
        start: u64,
        limit: usize,
        _from_block: Option<u64>,
        _to_block: Option<u64>,
    ) -> Result<Vec<(u64, Vec<u8>, u64, [u8; 32])>, String> {
        let api = self.client.runtime_api();
        let hash = self.best_hash();

        api.get_encrypted_notes(hash, start, limit as u32)
            .map_err(|e| format!("Runtime API error: {:?}", e))
    }

    fn encrypted_note_count(&self) -> u64 {
        let api = self.client.runtime_api();
        let hash = self.best_hash();

        api.encrypted_note_count(hash).unwrap_or(0)
    }

    fn get_merkle_witness(
        &self,
        position: u64,
    ) -> Result<(Vec<[u8; 32]>, Vec<bool>, [u8; 32]), String> {
        let api = self.client.runtime_api();
        let hash = self.best_hash();

        api.get_merkle_witness(hash, position)
            .map_err(|e| format!("Runtime API error: {:?}", e))?
            .map_err(|_| "Invalid position".to_string())
    }

    fn get_pool_status(&self) -> ShieldedPoolStatus {
        let api = self.client.runtime_api();
        let hash = self.best_hash();

        let total_notes = api.encrypted_note_count(hash).unwrap_or(0);
        let total_nullifiers = api.nullifier_count(hash).unwrap_or(0);
        let merkle_root = api.merkle_root(hash).unwrap_or([0u8; 32]);
        let tree_depth = api.tree_depth(hash).unwrap_or(32);
        let pool_balance = api.pool_balance(hash).unwrap_or(0);
        let last_update_block = self.client.info().best_number.try_into().unwrap_or(0);

        ShieldedPoolStatus {
            total_notes,
            total_nullifiers,
            merkle_root: format!("0x{}", hex::encode(merkle_root)),
            tree_depth,
            pool_balance,
            last_update_block,
        }
    }

    fn shield(
        &self,
        _amount: u128,
        _commitment: [u8; 32],
        _encrypted_note: Vec<u8>,
    ) -> Result<([u8; 32], u64), String> {
        // Shield requires submitting an extrinsic to pallet_shielded_pool::shield()
        Err(
            "Production shield not yet implemented. Use RPC `author_submitExtrinsic` directly."
                .to_string(),
        )
    }

    fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
        let api = self.client.runtime_api();
        let hash = self.best_hash();

        api.is_nullifier_spent(hash, *nullifier).unwrap_or(false)
    }

    fn is_valid_anchor(&self, anchor: &[u8; 32]) -> bool {
        let api = self.client.runtime_api();
        let hash = self.best_hash();

        api.is_valid_anchor(hash, *anchor).unwrap_or(false)
    }

    fn chain_height(&self) -> u64 {
        self.client.info().best_number.try_into().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_service_notes() {
        let service = MockShieldedPoolService::new();

        // Add a note
        service.add_note(vec![1, 2, 3], [0xaa; 32]);

        assert_eq!(service.encrypted_note_count(), 1);

        let notes = service.get_encrypted_notes(0, 10, None, None).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].0, 0); // index
        assert_eq!(notes[0].1, vec![1, 2, 3]); // ciphertext
    }

    #[test]
    fn test_mock_service_shield() {
        let service = MockShieldedPoolService::new();

        let result = service.shield(1000, [0xbb; 32], vec![4, 5, 6]);
        assert!(result.is_ok());

        let (_, index) = result.unwrap();
        assert_eq!(index, 0);

        // Check note was added
        assert_eq!(service.encrypted_note_count(), 1);

        // Check balance updated
        let status = service.get_pool_status();
        assert_eq!(status.pool_balance, 1000);
    }

    #[test]
    fn test_mock_service_nullifiers() {
        let service = MockShieldedPoolService::new();

        let nf = [0xcc; 32];

        // Not spent initially
        assert!(!service.is_nullifier_spent(&nf));

        // Add initial anchor for the transfer
        service.add_anchor([0; 32]);

        // Submit transfer with nullifier
        service
            .submit_shielded_transfer(
                vec![],
                vec![nf],
                vec![],
                vec![],
                [0; 32], // Use valid anchor
                [0; 64],
                0,
            )
            .unwrap();

        // Now spent
        assert!(service.is_nullifier_spent(&nf));
    }

    #[test]
    fn test_mock_service_pool_status() {
        let service = MockShieldedPoolService::new();
        service.set_height(100);

        let status = service.get_pool_status();
        assert_eq!(status.total_notes, 0);
        assert_eq!(status.last_update_block, 100);
        assert_eq!(status.tree_depth, 32);
    }

    #[test]
    fn test_mock_service_anchors() {
        let service = MockShieldedPoolService::new();

        let anchor1 = [0x11; 32];
        let anchor2 = [0x22; 32];

        // Initial anchor is valid (zero root)
        assert!(service.is_valid_anchor(&[0; 32]));

        // Unknown anchor is invalid
        assert!(!service.is_valid_anchor(&anchor1));

        // Add anchor
        service.add_anchor(anchor1);

        // Now valid
        assert!(service.is_valid_anchor(&anchor1));

        // Still invalid
        assert!(!service.is_valid_anchor(&anchor2));
    }

    #[test]
    fn test_mock_service_transfer_updates_balance() {
        let service = MockShieldedPoolService::new();

        // Add initial anchor
        service.add_anchor([0; 32]);

        // Shield some funds first
        service.shield(10000, [0xaa; 32], vec![1]).unwrap();

        // Transfer with negative value balance (unshield)
        service
            .submit_shielded_transfer(
                vec![],
                vec![[0xbb; 32]],
                vec![[0xcc; 32]],
                vec![vec![2]],
                [0; 32],
                [0; 64],
                -5000,
            )
            .unwrap();

        let status = service.get_pool_status();
        assert_eq!(status.pool_balance, 5000); // 10000 - 5000
        assert_eq!(status.total_notes, 2); // original + new
        assert_eq!(status.total_nullifiers, 1);
    }
}
