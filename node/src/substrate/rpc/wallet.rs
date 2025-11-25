//! Hegemon Wallet RPC Endpoints
//!
//! This module provides wallet-specific RPC endpoints for:
//! - Note management (query notes, commitments, nullifiers)
//! - ZK proof generation
//! - Transaction submission
//!
//! # RPC Methods
//!
//! | Method                       | Description                              |
//! |------------------------------|------------------------------------------|
//! | `hegemon_walletNotes`        | Get wallet note status                   |
//! | `hegemon_walletCommitments`  | Get commitment tree entries              |
//! | `hegemon_walletCiphertexts`  | Get encrypted note ciphertexts           |
//! | `hegemon_walletNullifiers`   | Get spent nullifier set                  |
//! | `hegemon_generateProof`      | Generate ZK transaction proof            |
//! | `hegemon_submitTransaction`  | Submit a transaction bundle              |
//! | `hegemon_latestBlock`        | Get latest block info                    |
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       Wallet RPC Layer                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
//! │  │  Note Queries   │  │  Proof Gen      │  │  TX Submit      │ │
//! │  │  - notes status │  │  - ZK circuit   │  │  - validation   │ │
//! │  │  - commitments  │  │  - witness gen  │  │  - broadcast    │ │
//! │  │  - ciphertexts  │  │                 │  │                 │ │
//! │  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Note status response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteStatus {
    /// Total number of commitment leaves
    pub leaf_count: u64,
    /// Merkle tree depth
    pub depth: u64,
    /// Current Merkle root
    pub root: String,
    /// Next available index
    pub next_index: u64,
}

/// Commitment entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentEntry {
    /// Index in the commitment tree
    pub index: u64,
    /// Commitment value (field element)
    pub value: u64,
}

/// Paginated commitment response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentResponse {
    /// Commitment entries
    pub entries: Vec<CommitmentEntry>,
    /// Total count
    pub total: u64,
    /// Whether there are more entries
    pub has_more: bool,
}

/// Ciphertext entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CiphertextEntry {
    /// Index in the ciphertext list
    pub index: u64,
    /// Encrypted note ciphertext (base64 encoded)
    pub ciphertext: String,
}

/// Paginated ciphertext response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CiphertextResponse {
    /// Ciphertext entries
    pub entries: Vec<CiphertextEntry>,
    /// Total count
    pub total: u64,
    /// Whether there are more entries
    pub has_more: bool,
}

/// Nullifier response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullifierResponse {
    /// List of nullifiers (hex encoded)
    pub nullifiers: Vec<String>,
    /// Total count
    pub count: u64,
}

/// Latest block info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LatestBlock {
    /// Block height
    pub height: u64,
    /// Block hash (hex encoded)
    pub hash: String,
    /// State root (hex encoded)
    pub state_root: String,
    /// Nullifier root (hex encoded)
    pub nullifier_root: String,
    /// Total supply digest
    pub supply_digest: u128,
    /// Block timestamp
    pub timestamp: u64,
}

/// Pagination parameters
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PaginationParams {
    /// Starting index
    #[serde(default)]
    pub start: u64,
    /// Maximum number of entries to return
    #[serde(default = "default_limit")]
    pub limit: u64,
}

fn default_limit() -> u64 {
    128
}

/// Proof generation request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofRequest {
    /// Inputs for the transaction (note indices)
    pub inputs: Vec<u64>,
    /// Output recipients
    pub outputs: Vec<OutputSpec>,
    /// Optional memo
    pub memo: Option<String>,
}

/// Output specification for proof generation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputSpec {
    /// Recipient public key (hex encoded)
    pub recipient: String,
    /// Amount to send
    pub amount: u64,
}

/// Proof generation response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofResponse {
    /// Whether proof generation succeeded
    pub success: bool,
    /// Generated proof (base64 encoded) if successful
    pub proof: Option<String>,
    /// Public inputs for the proof
    pub public_inputs: Option<Vec<String>>,
    /// Error message if failed
    pub error: Option<String>,
    /// Time taken to generate proof in milliseconds
    pub generation_time_ms: u64,
}

/// Transaction bundle for submission
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionBundle {
    /// ZK proof (base64 encoded)
    pub proof: String,
    /// Encrypted note ciphertexts (base64 encoded)
    pub ciphertexts: Vec<String>,
}

/// Transaction submission response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionResponse {
    /// Whether submission succeeded
    pub success: bool,
    /// Transaction ID (hex encoded) if successful
    pub tx_id: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Wallet RPC API trait definition
#[rpc(server, client, namespace = "hegemon")]
pub trait WalletApi {
    /// Get wallet note status
    ///
    /// Returns information about the note commitment tree including
    /// leaf count, depth, current root, and next available index.
    #[method(name = "walletNotes")]
    async fn wallet_notes(&self) -> RpcResult<NoteStatus>;

    /// Get wallet commitments
    ///
    /// Returns a paginated list of commitment tree entries.
    ///
    /// # Parameters
    /// - `params`: Pagination parameters (start, limit)
    #[method(name = "walletCommitments")]
    async fn wallet_commitments(&self, params: Option<PaginationParams>) -> RpcResult<CommitmentResponse>;

    /// Get wallet ciphertexts
    ///
    /// Returns a paginated list of encrypted note ciphertexts.
    ///
    /// # Parameters
    /// - `params`: Pagination parameters (start, limit)
    #[method(name = "walletCiphertexts")]
    async fn wallet_ciphertexts(&self, params: Option<PaginationParams>) -> RpcResult<CiphertextResponse>;

    /// Get wallet nullifiers
    ///
    /// Returns the list of spent nullifiers.
    #[method(name = "walletNullifiers")]
    async fn wallet_nullifiers(&self) -> RpcResult<NullifierResponse>;

    /// Generate a ZK transaction proof
    ///
    /// Creates a zero-knowledge proof for a transaction spending
    /// the specified input notes and creating the specified outputs.
    ///
    /// # Parameters
    /// - `request`: Proof generation request with inputs and outputs
    #[method(name = "generateProof")]
    async fn generate_proof(&self, request: ProofRequest) -> RpcResult<ProofResponse>;

    /// Submit a transaction
    ///
    /// Submits a signed transaction bundle containing the proof
    /// and encrypted note ciphertexts.
    ///
    /// # Parameters
    /// - `bundle`: Transaction bundle with proof and ciphertexts
    #[method(name = "submitTransaction")]
    async fn submit_transaction(&self, bundle: TransactionBundle) -> RpcResult<TransactionResponse>;

    /// Get latest block info
    ///
    /// Returns information about the most recent block.
    #[method(name = "latestBlock")]
    async fn latest_block(&self) -> RpcResult<LatestBlock>;
}

/// Trait for wallet service operations
pub trait WalletService: Send + Sync {
    /// Get note status
    fn note_status(&self) -> NoteStatus;
    
    /// Get commitment entries
    fn commitment_slice(&self, start: u64, limit: usize) -> Result<Vec<(u64, u64)>, String>;
    
    /// Get ciphertext entries
    fn ciphertext_slice(&self, start: u64, limit: usize) -> Result<Vec<(u64, Vec<u8>)>, String>;
    
    /// Get all nullifiers
    fn nullifier_list(&self) -> Result<Vec<[u8; 32]>, String>;
    
    /// Get latest block metadata
    fn latest_meta(&self) -> LatestBlock;
    
    /// Submit transaction
    fn submit_transaction(&self, proof: Vec<u8>, ciphertexts: Vec<Vec<u8>>) -> Result<[u8; 32], String>;
    
    /// Generate proof (async)
    fn generate_proof(&self, inputs: Vec<u64>, outputs: Vec<(Vec<u8>, u64)>) -> Result<(Vec<u8>, Vec<String>), String>;
    
    /// Get total commitment count
    fn commitment_count(&self) -> u64;
    
    /// Get total ciphertext count
    fn ciphertext_count(&self) -> u64;
}

/// Wallet RPC implementation
pub struct WalletRpc<S> {
    service: Arc<S>,
}

impl<S> WalletRpc<S>
where
    S: WalletService + Send + Sync + 'static,
{
    /// Create a new Wallet RPC handler
    pub fn new(service: Arc<S>) -> Self {
        Self { service }
    }
}

#[jsonrpsee::core::async_trait]
impl<S> WalletApiServer for WalletRpc<S>
where
    S: WalletService + Send + Sync + 'static,
{
    async fn wallet_notes(&self) -> RpcResult<NoteStatus> {
        Ok(self.service.note_status())
    }

    async fn wallet_commitments(&self, params: Option<PaginationParams>) -> RpcResult<CommitmentResponse> {
        let params = params.unwrap_or_default();
        let limit = params.limit.min(1024) as usize;
        
        let entries = self.service.commitment_slice(params.start, limit)
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    jsonrpsee::types::error::INTERNAL_ERROR_CODE,
                    e,
                    None::<()>,
                )
            })?;
        
        let total = self.service.commitment_count();
        let has_more = (params.start + entries.len() as u64) < total;
        
        Ok(CommitmentResponse {
            entries: entries.into_iter().map(|(index, value)| CommitmentEntry { index, value }).collect(),
            total,
            has_more,
        })
    }

    async fn wallet_ciphertexts(&self, params: Option<PaginationParams>) -> RpcResult<CiphertextResponse> {
        let params = params.unwrap_or_default();
        let limit = params.limit.min(1024) as usize;
        
        let entries = self.service.ciphertext_slice(params.start, limit)
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    jsonrpsee::types::error::INTERNAL_ERROR_CODE,
                    e,
                    None::<()>,
                )
            })?;
        
        let total = self.service.ciphertext_count();
        let has_more = (params.start + entries.len() as u64) < total;
        
        Ok(CiphertextResponse {
            entries: entries.into_iter().map(|(index, ct)| {
                CiphertextEntry {
                    index,
                    ciphertext: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ct),
                }
            }).collect(),
            total,
            has_more,
        })
    }

    async fn wallet_nullifiers(&self) -> RpcResult<NullifierResponse> {
        let nullifiers = self.service.nullifier_list()
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    jsonrpsee::types::error::INTERNAL_ERROR_CODE,
                    e,
                    None::<()>,
                )
            })?;
        
        Ok(NullifierResponse {
            count: nullifiers.len() as u64,
            nullifiers: nullifiers.into_iter().map(hex::encode).collect(),
        })
    }

    async fn generate_proof(&self, request: ProofRequest) -> RpcResult<ProofResponse> {
        let start = std::time::Instant::now();
        
        // Parse outputs
        let outputs: Result<Vec<_>, _> = request.outputs.iter()
            .map(|o| {
                hex::decode(&o.recipient)
                    .map(|pk| (pk, o.amount))
                    .map_err(|e| e.to_string())
            })
            .collect();
        
        let outputs = match outputs {
            Ok(o) => o,
            Err(e) => {
                return Ok(ProofResponse {
                    success: false,
                    proof: None,
                    public_inputs: None,
                    error: Some(format!("Invalid recipient: {}", e)),
                    generation_time_ms: start.elapsed().as_millis() as u64,
                });
            }
        };
        
        match self.service.generate_proof(request.inputs, outputs) {
            Ok((proof, public_inputs)) => {
                Ok(ProofResponse {
                    success: true,
                    proof: Some(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &proof)),
                    public_inputs: Some(public_inputs),
                    error: None,
                    generation_time_ms: start.elapsed().as_millis() as u64,
                })
            }
            Err(e) => {
                Ok(ProofResponse {
                    success: false,
                    proof: None,
                    public_inputs: None,
                    error: Some(e),
                    generation_time_ms: start.elapsed().as_millis() as u64,
                })
            }
        }
    }

    async fn submit_transaction(&self, bundle: TransactionBundle) -> RpcResult<TransactionResponse> {
        // Decode proof
        let proof = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &bundle.proof) {
            Ok(p) => p,
            Err(e) => {
                return Ok(TransactionResponse {
                    success: false,
                    tx_id: None,
                    error: Some(format!("Invalid proof encoding: {}", e)),
                });
            }
        };
        
        // Decode ciphertexts
        let ciphertexts: Result<Vec<_>, _> = bundle.ciphertexts.iter()
            .map(|ct| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ct))
            .collect();
        
        let ciphertexts = match ciphertexts {
            Ok(c) => c,
            Err(e) => {
                return Ok(TransactionResponse {
                    success: false,
                    tx_id: None,
                    error: Some(format!("Invalid ciphertext encoding: {}", e)),
                });
            }
        };
        
        match self.service.submit_transaction(proof, ciphertexts) {
            Ok(tx_id) => {
                Ok(TransactionResponse {
                    success: true,
                    tx_id: Some(hex::encode(tx_id)),
                    error: None,
                })
            }
            Err(e) => {
                Ok(TransactionResponse {
                    success: false,
                    tx_id: None,
                    error: Some(e),
                })
            }
        }
    }

    async fn latest_block(&self) -> RpcResult<LatestBlock> {
        Ok(self.service.latest_meta())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockWalletService;

    impl WalletService for MockWalletService {
        fn note_status(&self) -> NoteStatus {
            NoteStatus {
                leaf_count: 1000,
                depth: 32,
                root: "0x1234567890abcdef".to_string(),
                next_index: 1000,
            }
        }

        fn commitment_slice(&self, start: u64, limit: usize) -> Result<Vec<(u64, u64)>, String> {
            let entries: Vec<_> = (start..start + limit as u64)
                .take(100)
                .map(|i| (i, i * 2))
                .collect();
            Ok(entries)
        }

        fn ciphertext_slice(&self, start: u64, limit: usize) -> Result<Vec<(u64, Vec<u8>)>, String> {
            let entries: Vec<_> = (start..start + limit as u64)
                .take(100)
                .map(|i| (i, vec![i as u8; 32]))
                .collect();
            Ok(entries)
        }

        fn nullifier_list(&self) -> Result<Vec<[u8; 32]>, String> {
            Ok(vec![[0u8; 32], [1u8; 32], [2u8; 32]])
        }

        fn latest_meta(&self) -> LatestBlock {
            LatestBlock {
                height: 100,
                hash: "0xabcd".to_string(),
                state_root: "0x1234".to_string(),
                nullifier_root: "0x5678".to_string(),
                supply_digest: 1_000_000,
                timestamp: 1700000000,
            }
        }

        fn submit_transaction(&self, _proof: Vec<u8>, _ciphertexts: Vec<Vec<u8>>) -> Result<[u8; 32], String> {
            Ok([0xab; 32])
        }

        fn generate_proof(&self, _inputs: Vec<u64>, _outputs: Vec<(Vec<u8>, u64)>) -> Result<(Vec<u8>, Vec<String>), String> {
            Ok((vec![0u8; 128], vec!["0x1234".to_string()]))
        }

        fn commitment_count(&self) -> u64 {
            1000
        }

        fn ciphertext_count(&self) -> u64 {
            1000
        }
    }

    #[tokio::test]
    async fn test_wallet_notes() {
        let service = Arc::new(MockWalletService);
        let rpc = WalletRpc::new(service);

        let status = rpc.wallet_notes().await.unwrap();
        assert_eq!(status.leaf_count, 1000);
        assert_eq!(status.depth, 32);
    }

    #[tokio::test]
    async fn test_wallet_commitments() {
        let service = Arc::new(MockWalletService);
        let rpc = WalletRpc::new(service);

        let response = rpc.wallet_commitments(Some(PaginationParams { start: 0, limit: 10 })).await.unwrap();
        assert_eq!(response.entries.len(), 10);
        assert!(response.has_more);
    }

    #[tokio::test]
    async fn test_wallet_nullifiers() {
        let service = Arc::new(MockWalletService);
        let rpc = WalletRpc::new(service);

        let response = rpc.wallet_nullifiers().await.unwrap();
        assert_eq!(response.count, 3);
        assert_eq!(response.nullifiers.len(), 3);
    }

    #[tokio::test]
    async fn test_latest_block() {
        let service = Arc::new(MockWalletService);
        let rpc = WalletRpc::new(service);

        let block = rpc.latest_block().await.unwrap();
        assert_eq!(block.height, 100);
    }

    #[tokio::test]
    async fn test_submit_transaction() {
        use base64::Engine;
        
        let service = Arc::new(MockWalletService);
        let rpc = WalletRpc::new(service);

        let bundle = TransactionBundle {
            proof: base64::engine::general_purpose::STANDARD.encode(&[0u8; 64]),
            ciphertexts: vec![base64::engine::general_purpose::STANDARD.encode(&[1u8; 32])],
        };

        let response = rpc.submit_transaction(bundle).await.unwrap();
        assert!(response.success);
        assert!(response.tx_id.is_some());
    }
}
