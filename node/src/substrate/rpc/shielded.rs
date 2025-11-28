//! Shielded Transaction RPC Endpoints
//!
//! This module provides RPC endpoints for shielded transactions:
//! - Submit shielded transfers with STARK proofs
//! - Get encrypted notes for scanning
//! - Get Merkle witnesses for note spending
//!
//! # RPC Methods
//!
//! | Method                          | Description                              |
//! |---------------------------------|------------------------------------------|
//! | `hegemon_submitShieldedTransfer`| Submit a shielded transfer with STARK proof |
//! | `hegemon_getEncryptedNotes`     | Fetch ML-KEM encrypted notes             |
//! | `hegemon_getMerkleWitness`      | Get Poseidon Merkle path for a note      |
//! | `hegemon_getShieldedPoolStatus` | Get shielded pool statistics             |
//!
//! # Post-Quantum Security
//!
//! All operations use post-quantum cryptography:
//! - **STARK proofs**: Hash-based, transparent setup
//! - **ML-KEM-768**: Lattice-based note encryption
//! - **Poseidon hash**: STARK-friendly Merkle tree

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Shielded transfer request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedTransferRequest {
    /// STARK proof (base64 encoded)
    pub proof: String,
    /// Nullifiers for spent notes (hex encoded)
    pub nullifiers: Vec<String>,
    /// New note commitments (hex encoded)
    pub commitments: Vec<String>,
    /// Encrypted notes for recipients (base64 encoded)
    pub encrypted_notes: Vec<String>,
    /// Merkle root anchor (hex encoded)
    pub anchor: String,
    /// Binding signature (hex encoded)
    pub binding_sig: String,
    /// Value balance (positive = shielding, negative = unshielding)
    pub value_balance: i128,
}

/// Shielded transfer response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedTransferResponse {
    /// Whether submission succeeded
    pub success: bool,
    /// Transaction hash if successful (hex encoded)
    pub tx_hash: Option<String>,
    /// Block number if already included
    pub block_number: Option<u64>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Encrypted note entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedNoteEntry {
    /// Note index in the commitment tree
    pub index: u64,
    /// Encrypted note ciphertext (base64 encoded)
    pub ciphertext: String,
    /// Block number where this note was added
    pub block_number: u64,
    /// Note commitment (hex encoded)
    pub commitment: String,
}

/// Encrypted notes request parameters
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct EncryptedNotesParams {
    /// Starting index
    #[serde(default)]
    pub start: u64,
    /// Maximum number of notes to return
    #[serde(default = "default_notes_limit")]
    pub limit: u64,
    /// Optional filter by block range (start)
    pub from_block: Option<u64>,
    /// Optional filter by block range (end)
    pub to_block: Option<u64>,
}

fn default_notes_limit() -> u64 {
    256
}

/// Encrypted notes response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedNotesResponse {
    /// Encrypted notes
    pub notes: Vec<EncryptedNoteEntry>,
    /// Total count available
    pub total: u64,
    /// Whether there are more notes
    pub has_more: bool,
    /// Current chain tip height
    pub chain_height: u64,
}

/// Merkle witness for a note
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleWitnessResponse {
    /// Sibling hashes from leaf to root (hex encoded)
    pub siblings: Vec<String>,
    /// Position bits (true = right child)
    pub indices: Vec<bool>,
    /// Leaf position
    pub position: u64,
    /// Current Merkle root (hex encoded)
    pub root: String,
}

/// Shielded pool status
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedPoolStatus {
    /// Total notes in the pool
    pub total_notes: u64,
    /// Total nullifiers (spent notes)
    pub total_nullifiers: u64,
    /// Current Merkle root (hex encoded)
    pub merkle_root: String,
    /// Merkle tree depth
    pub tree_depth: u32,
    /// Pool balance (in atomic units)
    pub pool_balance: u128,
    /// Last update block
    pub last_update_block: u64,
}

/// Shield request (transparent -> shielded)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldRequest {
    /// Amount to shield
    pub amount: u128,
    /// Note commitment (hex encoded)
    pub commitment: String,
    /// Encrypted note (base64 encoded)
    pub encrypted_note: String,
}

/// Shield response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldResponse {
    /// Whether shielding succeeded
    pub success: bool,
    /// Transaction hash if successful (hex encoded)
    pub tx_hash: Option<String>,
    /// Note index in the commitment tree
    pub note_index: Option<u64>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Shielded Transaction RPC API
#[rpc(server, client, namespace = "hegemon")]
pub trait ShieldedApi {
    /// Submit a shielded transfer with STARK proof
    ///
    /// This is the main entry point for private transactions.
    /// The proof verifies the transaction validity without revealing details.
    ///
    /// # Parameters
    /// - `request`: Shielded transfer request with proof and encrypted notes
    #[method(name = "submitShieldedTransfer")]
    async fn submit_shielded_transfer(
        &self,
        request: ShieldedTransferRequest,
    ) -> RpcResult<ShieldedTransferResponse>;

    /// Get encrypted notes for wallet scanning
    ///
    /// Returns encrypted notes that wallets can trial-decrypt
    /// using their viewing keys.
    ///
    /// # Parameters
    /// - `params`: Optional pagination and filter parameters
    #[method(name = "getEncryptedNotes")]
    async fn get_encrypted_notes(
        &self,
        params: Option<EncryptedNotesParams>,
    ) -> RpcResult<EncryptedNotesResponse>;

    /// Get Merkle witness for spending a note
    ///
    /// Returns the authentication path needed to prove
    /// membership in the commitment tree.
    ///
    /// # Parameters
    /// - `position`: Note position in the commitment tree
    #[method(name = "getMerkleWitness")]
    async fn get_merkle_witness(&self, position: u64) -> RpcResult<MerkleWitnessResponse>;

    /// Get shielded pool status
    ///
    /// Returns statistics about the shielded pool including
    /// note count, nullifier count, and pool balance.
    #[method(name = "getShieldedPoolStatus")]
    async fn get_shielded_pool_status(&self) -> RpcResult<ShieldedPoolStatus>;

    /// Shield transparent funds
    ///
    /// Deposits transparent funds into the shielded pool,
    /// creating a new shielded note.
    ///
    /// # Parameters
    /// - `request`: Shield request with amount and commitment
    #[method(name = "shield")]
    async fn shield(&self, request: ShieldRequest) -> RpcResult<ShieldResponse>;

    /// Check if a nullifier has been spent
    ///
    /// # Parameters
    /// - `nullifier`: Nullifier to check (hex encoded)
    #[method(name = "isNullifierSpent")]
    async fn is_nullifier_spent(&self, nullifier: String) -> RpcResult<bool>;

    /// Check if an anchor (Merkle root) is valid
    ///
    /// # Parameters
    /// - `anchor`: Merkle root to check (hex encoded)
    #[method(name = "isValidAnchor")]
    async fn is_valid_anchor(&self, anchor: String) -> RpcResult<bool>;
}

/// Trait for shielded pool service operations
pub trait ShieldedPoolService: Send + Sync {
    /// Submit a shielded transfer
    fn submit_shielded_transfer(
        &self,
        proof: Vec<u8>,
        nullifiers: Vec<[u8; 32]>,
        commitments: Vec<[u8; 32]>,
        encrypted_notes: Vec<Vec<u8>>,
        anchor: [u8; 32],
        binding_sig: [u8; 64],
        value_balance: i128,
    ) -> Result<[u8; 32], String>;

    /// Get encrypted notes
    fn get_encrypted_notes(
        &self,
        start: u64,
        limit: usize,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<(u64, Vec<u8>, u64, [u8; 32])>, String>;

    /// Get total encrypted note count
    fn encrypted_note_count(&self) -> u64;

    /// Get Merkle witness for a position
    fn get_merkle_witness(&self, position: u64) -> Result<(Vec<[u8; 32]>, Vec<bool>, [u8; 32]), String>;

    /// Get shielded pool status
    fn get_pool_status(&self) -> ShieldedPoolStatus;

    /// Shield transparent funds
    fn shield(
        &self,
        amount: u128,
        commitment: [u8; 32],
        encrypted_note: Vec<u8>,
    ) -> Result<([u8; 32], u64), String>;

    /// Check if nullifier is spent
    fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool;

    /// Check if anchor is valid
    fn is_valid_anchor(&self, anchor: &[u8; 32]) -> bool;

    /// Get current chain height
    fn chain_height(&self) -> u64;
}

/// Shielded RPC implementation
pub struct ShieldedRpc<S> {
    service: Arc<S>,
}

impl<S> ShieldedRpc<S>
where
    S: ShieldedPoolService + Send + Sync + 'static,
{
    /// Create a new Shielded RPC handler
    pub fn new(service: Arc<S>) -> Self {
        Self { service }
    }
}

#[jsonrpsee::core::async_trait]
impl<S> ShieldedApiServer for ShieldedRpc<S>
where
    S: ShieldedPoolService + Send + Sync + 'static,
{
    async fn submit_shielded_transfer(
        &self,
        request: ShieldedTransferRequest,
    ) -> RpcResult<ShieldedTransferResponse> {
        // Decode proof
        let proof = match base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &request.proof,
        ) {
            Ok(p) => p,
            Err(e) => {
                return Ok(ShieldedTransferResponse {
                    success: false,
                    tx_hash: None,
                    block_number: None,
                    error: Some(format!("Invalid proof encoding: {}", e)),
                });
            }
        };

        // Decode nullifiers
        let nullifiers: Result<Vec<[u8; 32]>, _> = request
            .nullifiers
            .iter()
            .map(|n| hex_to_array32(n))
            .collect();
        let nullifiers = match nullifiers {
            Ok(n) => n,
            Err(e) => {
                return Ok(ShieldedTransferResponse {
                    success: false,
                    tx_hash: None,
                    block_number: None,
                    error: Some(format!("Invalid nullifier: {}", e)),
                });
            }
        };

        // Decode commitments
        let commitments: Result<Vec<[u8; 32]>, _> = request
            .commitments
            .iter()
            .map(|c| hex_to_array32(c))
            .collect();
        let commitments = match commitments {
            Ok(c) => c,
            Err(e) => {
                return Ok(ShieldedTransferResponse {
                    success: false,
                    tx_hash: None,
                    block_number: None,
                    error: Some(format!("Invalid commitment: {}", e)),
                });
            }
        };

        // Decode encrypted notes
        let encrypted_notes: Result<Vec<Vec<u8>>, _> = request
            .encrypted_notes
            .iter()
            .map(|n| {
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, n)
                    .map_err(|e| e.to_string())
            })
            .collect();
        let encrypted_notes = match encrypted_notes {
            Ok(n) => n,
            Err(e) => {
                return Ok(ShieldedTransferResponse {
                    success: false,
                    tx_hash: None,
                    block_number: None,
                    error: Some(format!("Invalid encrypted note: {}", e)),
                });
            }
        };

        // Decode anchor
        let anchor = match hex_to_array32(&request.anchor) {
            Ok(a) => a,
            Err(e) => {
                return Ok(ShieldedTransferResponse {
                    success: false,
                    tx_hash: None,
                    block_number: None,
                    error: Some(format!("Invalid anchor: {}", e)),
                });
            }
        };

        // Decode binding signature
        let binding_sig = match hex_to_array64(&request.binding_sig) {
            Ok(s) => s,
            Err(e) => {
                return Ok(ShieldedTransferResponse {
                    success: false,
                    tx_hash: None,
                    block_number: None,
                    error: Some(format!("Invalid binding signature: {}", e)),
                });
            }
        };

        // Submit to service
        match self.service.submit_shielded_transfer(
            proof,
            nullifiers,
            commitments,
            encrypted_notes,
            anchor,
            binding_sig,
            request.value_balance,
        ) {
            Ok(tx_hash) => Ok(ShieldedTransferResponse {
                success: true,
                tx_hash: Some(hex::encode(tx_hash)),
                block_number: None,
                error: None,
            }),
            Err(e) => Ok(ShieldedTransferResponse {
                success: false,
                tx_hash: None,
                block_number: None,
                error: Some(e),
            }),
        }
    }

    async fn get_encrypted_notes(
        &self,
        params: Option<EncryptedNotesParams>,
    ) -> RpcResult<EncryptedNotesResponse> {
        let params = params.unwrap_or_default();
        let limit = params.limit.min(1024) as usize;

        let notes = self
            .service
            .get_encrypted_notes(params.start, limit, params.from_block, params.to_block)
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    jsonrpsee::types::error::INTERNAL_ERROR_CODE,
                    e,
                    None::<()>,
                )
            })?;

        let total = self.service.encrypted_note_count();
        let has_more = (params.start + notes.len() as u64) < total;

        Ok(EncryptedNotesResponse {
            notes: notes
                .into_iter()
                .map(|(index, ciphertext, block, commitment)| EncryptedNoteEntry {
                    index,
                    ciphertext: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &ciphertext,
                    ),
                    block_number: block,
                    commitment: hex::encode(commitment),
                })
                .collect(),
            total,
            has_more,
            chain_height: self.service.chain_height(),
        })
    }

    async fn get_merkle_witness(&self, position: u64) -> RpcResult<MerkleWitnessResponse> {
        let (siblings, indices, root) = self.service.get_merkle_witness(position).map_err(|e| {
            ErrorObjectOwned::owned(
                jsonrpsee::types::error::INTERNAL_ERROR_CODE,
                e,
                None::<()>,
            )
        })?;

        Ok(MerkleWitnessResponse {
            siblings: siblings.into_iter().map(hex::encode).collect(),
            indices,
            position,
            root: hex::encode(root),
        })
    }

    async fn get_shielded_pool_status(&self) -> RpcResult<ShieldedPoolStatus> {
        Ok(self.service.get_pool_status())
    }

    async fn shield(&self, request: ShieldRequest) -> RpcResult<ShieldResponse> {
        // Decode commitment
        let commitment = match hex_to_array32(&request.commitment) {
            Ok(c) => c,
            Err(e) => {
                return Ok(ShieldResponse {
                    success: false,
                    tx_hash: None,
                    note_index: None,
                    error: Some(format!("Invalid commitment: {}", e)),
                });
            }
        };

        // Decode encrypted note
        let encrypted_note = match base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &request.encrypted_note,
        ) {
            Ok(n) => n,
            Err(e) => {
                return Ok(ShieldResponse {
                    success: false,
                    tx_hash: None,
                    note_index: None,
                    error: Some(format!("Invalid encrypted note: {}", e)),
                });
            }
        };

        match self.service.shield(request.amount, commitment, encrypted_note) {
            Ok((tx_hash, note_index)) => Ok(ShieldResponse {
                success: true,
                tx_hash: Some(hex::encode(tx_hash)),
                note_index: Some(note_index),
                error: None,
            }),
            Err(e) => Ok(ShieldResponse {
                success: false,
                tx_hash: None,
                note_index: None,
                error: Some(e),
            }),
        }
    }

    async fn is_nullifier_spent(&self, nullifier: String) -> RpcResult<bool> {
        let nf = hex_to_array32(&nullifier).map_err(|e| {
            ErrorObjectOwned::owned(
                jsonrpsee::types::error::INVALID_PARAMS_CODE,
                format!("Invalid nullifier: {}", e),
                None::<()>,
            )
        })?;
        Ok(self.service.is_nullifier_spent(&nf))
    }

    async fn is_valid_anchor(&self, anchor: String) -> RpcResult<bool> {
        let a = hex_to_array32(&anchor).map_err(|e| {
            ErrorObjectOwned::owned(
                jsonrpsee::types::error::INVALID_PARAMS_CODE,
                format!("Invalid anchor: {}", e),
                None::<()>,
            )
        })?;
        Ok(self.service.is_valid_anchor(&a))
    }
}

fn hex_to_array32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_to_array64(hex_str: &str) -> Result<[u8; 64], String> {
    let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
    if bytes.len() != 64 {
        return Err(format!("expected 64 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockShieldedService;

    impl ShieldedPoolService for MockShieldedService {
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
            Ok([0xab; 32])
        }

        fn get_encrypted_notes(
            &self,
            start: u64,
            limit: usize,
            _from_block: Option<u64>,
            _to_block: Option<u64>,
        ) -> Result<Vec<(u64, Vec<u8>, u64, [u8; 32])>, String> {
            let notes: Vec<_> = (start..start + limit as u64)
                .take(10)
                .map(|i| (i, vec![i as u8; 32], 100 + i, [i as u8; 32]))
                .collect();
            Ok(notes)
        }

        fn encrypted_note_count(&self) -> u64 {
            1000
        }

        fn get_merkle_witness(&self, position: u64) -> Result<(Vec<[u8; 32]>, Vec<bool>, [u8; 32]), String> {
            let siblings: Vec<[u8; 32]> = (0..32).map(|i| [i; 32]).collect();
            let indices: Vec<bool> = (0..32).map(|i| i % 2 == 0).collect();
            let root = [0x12; 32];
            Ok((siblings, indices, root))
        }

        fn get_pool_status(&self) -> ShieldedPoolStatus {
            ShieldedPoolStatus {
                total_notes: 1000,
                total_nullifiers: 500,
                merkle_root: "0x1234".to_string(),
                tree_depth: 32,
                pool_balance: 1_000_000_000,
                last_update_block: 100,
            }
        }

        fn shield(
            &self,
            _amount: u128,
            _commitment: [u8; 32],
            _encrypted_note: Vec<u8>,
        ) -> Result<([u8; 32], u64), String> {
            Ok(([0xcd; 32], 1001))
        }

        fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
            nullifier[0] == 0
        }

        fn is_valid_anchor(&self, anchor: &[u8; 32]) -> bool {
            anchor[0] != 0
        }

        fn chain_height(&self) -> u64 {
            100
        }
    }

    #[tokio::test]
    async fn test_get_pool_status() {
        let service = Arc::new(MockShieldedService);
        let rpc = ShieldedRpc::new(service);

        let status = rpc.get_shielded_pool_status().await.unwrap();
        assert_eq!(status.total_notes, 1000);
        assert_eq!(status.total_nullifiers, 500);
    }

    #[tokio::test]
    async fn test_is_nullifier_spent() {
        let service = Arc::new(MockShieldedService);
        let rpc = ShieldedRpc::new(service);

        // Nullifier starting with 0 is "spent"
        let spent = rpc
            .is_nullifier_spent(hex::encode([0u8; 32]))
            .await
            .unwrap();
        assert!(spent);

        // Nullifier starting with 1 is not spent
        let mut nf = [0u8; 32];
        nf[0] = 1;
        let not_spent = rpc.is_nullifier_spent(hex::encode(nf)).await.unwrap();
        assert!(!not_spent);
    }

    #[tokio::test]
    async fn test_is_valid_anchor() {
        let service = Arc::new(MockShieldedService);
        let rpc = ShieldedRpc::new(service);

        // Anchor starting with non-zero is valid
        let mut anchor = [0u8; 32];
        anchor[0] = 1;
        let valid = rpc.is_valid_anchor(hex::encode(anchor)).await.unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn test_get_merkle_witness() {
        let service = Arc::new(MockShieldedService);
        let rpc = ShieldedRpc::new(service);

        let witness = rpc.get_merkle_witness(5).await.unwrap();
        assert_eq!(witness.siblings.len(), 32);
        assert_eq!(witness.indices.len(), 32);
        assert_eq!(witness.position, 5);
    }
}
