//! Substrate RPC Client for Wallet
//!
//! This module provides a WebSocket-based RPC client that connects to Substrate
//! nodes using the jsonrpsee library. It implements the wallet-specific RPC methods
//! defined in the `hegemon_*` namespace.
//!
//! # Migration from HTTP
//!
//! This replaces the previous HTTP-based `WalletRpcClient` with a WebSocket client
//! that supports:
//! - Persistent connections with automatic reconnection
//! - Block subscriptions for real-time sync
//! - Full async/await support
//!
//! # Example
//!
//! ```no_run
//! use wallet::substrate_rpc::SubstrateRpcClient;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = SubstrateRpcClient::connect("ws://127.0.0.1:9944").await?;
//! let status = client.note_status().await?;
//! println!("Tree has {} leaves", status.leaf_count);
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;
use std::time::Duration;

use jsonrpsee::core::client::{ClientT, SubscriptionClientT};
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::WalletError;
use crate::notes::NoteCiphertext;
use crate::rpc::TransactionBundle;

/// Configuration for the Substrate RPC client
#[derive(Clone, Debug)]
pub struct SubstrateRpcConfig {
    /// WebSocket endpoint URL (e.g., "ws://127.0.0.1:9944")
    pub endpoint: String,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Request timeout
    pub request_timeout: Duration,
    /// Maximum number of reconnection attempts
    pub max_reconnect_attempts: u32,
    /// Delay between reconnection attempts
    pub reconnect_delay: Duration,
}

impl Default for SubstrateRpcConfig {
    fn default() -> Self {
        Self {
            endpoint: "ws://127.0.0.1:9944".to_string(),
            connection_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(60),
            max_reconnect_attempts: 5,
            reconnect_delay: Duration::from_secs(2),
        }
    }
}

impl SubstrateRpcConfig {
    /// Create config with custom endpoint
    pub fn with_endpoint(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            ..Default::default()
        }
    }
}

/// Note status response from the node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteStatus {
    /// Total number of commitment leaves
    pub leaf_count: u64,
    /// Merkle tree depth
    pub depth: u64,
    /// Current Merkle root (hex encoded)
    pub root: String,
    /// Next available index
    pub next_index: u64,
}

/// Commitment entry from the commitment tree
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

/// Ciphertext entry from the node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CiphertextEntryWire {
    /// Index in the ciphertext list
    pub index: u64,
    /// Encrypted note ciphertext (base64 encoded)
    pub ciphertext: String,
}

/// Paginated ciphertext response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CiphertextResponse {
    /// Ciphertext entries
    pub entries: Vec<CiphertextEntryWire>,
    /// Total count
    pub total: u64,
    /// Whether there are more entries
    pub has_more: bool,
}

/// Nullifier response from the node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullifierResponse {
    /// List of nullifiers (hex encoded)
    pub nullifiers: Vec<String>,
    /// Total count
    pub count: u64,
}

/// Latest block information
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
    /// Block timestamp (unix seconds)
    #[serde(default)]
    pub timestamp: u64,
}

/// Pagination parameters for RPC calls
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaginationParams {
    /// Starting index
    #[serde(default)]
    pub start: u64,
    /// Maximum number of entries to return
    #[serde(default = "default_limit")]
    pub limit: u64,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            start: 0,
            limit: default_limit(),
        }
    }
}

fn default_limit() -> u64 {
    128
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

/// Ciphertext entry with decoded content
#[derive(Clone, Debug)]
pub struct CiphertextEntry {
    /// Index in the ciphertext list
    pub index: u64,
    /// Decoded note ciphertext
    pub ciphertext: NoteCiphertext,
}

/// Substrate WebSocket RPC client for wallet operations
///
/// This client connects to a Substrate node via WebSocket and provides
/// methods to interact with the wallet-specific RPC endpoints.
pub struct SubstrateRpcClient {
    /// The underlying WebSocket client
    client: Arc<RwLock<WsClient>>,
    /// Client configuration
    config: SubstrateRpcConfig,
}

impl SubstrateRpcClient {
    /// Connect to a Substrate node
    ///
    /// # Arguments
    ///
    /// * `endpoint` - WebSocket endpoint URL (e.g., "ws://127.0.0.1:9944")
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use wallet::substrate_rpc::SubstrateRpcClient;
    /// let client = SubstrateRpcClient::connect("ws://127.0.0.1:9944").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(endpoint: &str) -> Result<Self, WalletError> {
        let config = SubstrateRpcConfig::with_endpoint(endpoint);
        Self::connect_with_config(config).await
    }

    /// Connect with custom configuration
    pub async fn connect_with_config(config: SubstrateRpcConfig) -> Result<Self, WalletError> {
        let client = Self::build_client(&config).await?;
        Ok(Self {
            client: Arc::new(RwLock::new(client)),
            config,
        })
    }

    async fn build_client(config: &SubstrateRpcConfig) -> Result<WsClient, WalletError> {
        WsClientBuilder::default()
            .connection_timeout(config.connection_timeout)
            .request_timeout(config.request_timeout)
            .build(&config.endpoint)
            .await
            .map_err(|e| WalletError::Rpc(format!("Failed to connect to {}: {}", config.endpoint, e)))
    }

    /// Ensure connection is alive, reconnect if needed
    async fn ensure_connected(&self) -> Result<(), WalletError> {
        let client = self.client.read().await;
        if client.is_connected() {
            return Ok(());
        }
        drop(client);

        // Attempt reconnection
        let mut attempts = 0;
        loop {
            attempts += 1;
            match Self::build_client(&self.config).await {
                Ok(new_client) => {
                    let mut client = self.client.write().await;
                    *client = new_client;
                    return Ok(());
                }
                Err(e) => {
                    if attempts >= self.config.max_reconnect_attempts {
                        return Err(e);
                    }
                    tokio::time::sleep(self.config.reconnect_delay).await;
                }
            }
        }
    }

    /// Get wallet note status (commitment tree info)
    ///
    /// Returns information about the note commitment tree including
    /// leaf count, depth, current root, and next available index.
    pub async fn note_status(&self) -> Result<NoteStatus, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;
        client
            .request("hegemon_walletNotes", rpc_params![])
            .await
            .map_err(|e| WalletError::Rpc(format!("hegemon_walletNotes failed: {}", e)))
    }

    /// Get commitment entries from the tree
    ///
    /// Returns a paginated list of commitment tree entries.
    ///
    /// # Arguments
    ///
    /// * `start` - Starting index
    /// * `limit` - Maximum number of entries to return
    pub async fn commitments(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<CommitmentEntry>, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;
        
        let params = PaginationParams {
            start,
            limit: limit as u64,
        };
        
        let response: CommitmentResponse = client
            .request("hegemon_walletCommitments", rpc_params![params])
            .await
            .map_err(|e| WalletError::Rpc(format!("hegemon_walletCommitments failed: {}", e)))?;
        
        Ok(response.entries)
    }

    /// Get ciphertext entries
    ///
    /// Returns a paginated list of encrypted note ciphertexts.
    ///
    /// # Arguments
    ///
    /// * `start` - Starting index
    /// * `limit` - Maximum number of entries to return
    pub async fn ciphertexts(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<CiphertextEntry>, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;
        
        let params = PaginationParams {
            start,
            limit: limit as u64,
        };
        
        let response: CiphertextResponse = client
            .request("hegemon_walletCiphertexts", rpc_params![params])
            .await
            .map_err(|e| WalletError::Rpc(format!("hegemon_walletCiphertexts failed: {}", e)))?;
        
        // Decode base64 ciphertexts
        let mut entries = Vec::with_capacity(response.entries.len());
        for entry in response.entries {
            let bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &entry.ciphertext,
            )
            .map_err(|e| WalletError::Serialization(format!("Invalid base64 ciphertext: {}", e)))?;
            
            let ciphertext: NoteCiphertext = bincode::deserialize(&bytes)?;
            entries.push(CiphertextEntry {
                index: entry.index,
                ciphertext,
            });
        }
        
        Ok(entries)
    }

    /// Get all spent nullifiers
    ///
    /// Returns the list of spent nullifiers from the node.
    pub async fn nullifiers(&self) -> Result<Vec<[u8; 32]>, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;
        
        let response: NullifierResponse = client
            .request("hegemon_walletNullifiers", rpc_params![])
            .await
            .map_err(|e| WalletError::Rpc(format!("hegemon_walletNullifiers failed: {}", e)))?;
        
        response
            .nullifiers
            .iter()
            .map(|hex| {
                let bytes = hex::decode(hex)
                    .map_err(|e| WalletError::Serialization(format!("Invalid hex nullifier: {}", e)))?;
                if bytes.len() != 32 {
                    return Err(WalletError::Serialization(
                        "invalid nullifier length".into(),
                    ));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Ok(out)
            })
            .collect()
    }

    /// Get latest block information
    ///
    /// Returns information about the most recent block.
    pub async fn latest_block(&self) -> Result<LatestBlock, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;
        client
            .request("hegemon_latestBlock", rpc_params![])
            .await
            .map_err(|e| WalletError::Rpc(format!("hegemon_latestBlock failed: {}", e)))
    }

    /// Submit a shielded transaction to the network
    ///
    /// Submits a signed transaction bundle containing the STARK proof,
    /// nullifiers, commitments, encrypted notes, anchor, and binding signature.
    /// This calls the `hegemon_submitShieldedTransfer` RPC which verifies
    /// the STARK proof and submits the transaction to the shielded pool.
    ///
    /// # Arguments
    ///
    /// * `bundle` - Transaction bundle with proof and all components
    ///
    /// # Returns
    ///
    /// The transaction hash (32 bytes) if successful.
    pub async fn submit_transaction(
        &self,
        bundle: &TransactionBundle,
    ) -> Result<[u8; 32], WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;
        
        // Convert to ShieldedTransferRequest wire format
        let request = ShieldedTransferRequest::from_bundle(bundle)?;
        
        let response: ShieldedTransferResponse = client
            .request("hegemon_submitShieldedTransfer", rpc_params![request])
            .await
            .map_err(|e| WalletError::Rpc(format!("hegemon_submitShieldedTransfer failed: {}", e)))?;
        
        if !response.success {
            return Err(WalletError::Http(format!(
                "Shielded transfer failed: {}",
                response.error.unwrap_or_else(|| "unknown error".to_string())
            )));
        }
        
        let tx_hash = response
            .tx_hash
            .ok_or_else(|| WalletError::Rpc("Missing tx_hash in response".to_string()))?;
        
        hex_to_array(&tx_hash)
    }

    /// Check if connected to the node
    pub async fn is_connected(&self) -> bool {
        let client = self.client.read().await;
        client.is_connected()
    }

    /// Get the endpoint URL
    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    /// Subscribe to new block headers
    ///
    /// Returns a subscription that yields new block headers as they are produced.
    /// This is useful for real-time wallet synchronization.
    pub async fn subscribe_new_heads(
        &self,
    ) -> Result<jsonrpsee::core::client::Subscription<serde_json::Value>, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;
        client
            .subscribe(
                "chain_subscribeNewHeads",
                rpc_params![],
                "chain_unsubscribeNewHeads",
            )
            .await
            .map_err(|e| WalletError::Rpc(format!("Failed to subscribe to new heads: {}", e)))
    }

    /// Subscribe to finalized block headers
    ///
    /// Returns a subscription that yields finalized block headers.
    pub async fn subscribe_finalized_heads(
        &self,
    ) -> Result<jsonrpsee::core::client::Subscription<serde_json::Value>, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;
        client
            .subscribe(
                "chain_subscribeFinalizedHeads",
                rpc_params![],
                "chain_unsubscribeFinalizedHeads",
            )
            .await
            .map_err(|e| WalletError::Rpc(format!("Failed to subscribe to finalized heads: {}", e)))
    }

    /// Get chain metadata required for extrinsic construction
    ///
    /// Returns genesis hash, current block hash/number, and runtime versions.
    pub async fn get_chain_metadata(&self) -> Result<crate::extrinsic::ChainMetadata, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;
        
        // Get genesis hash
        let genesis_hash: String = client
            .request("chain_getBlockHash", rpc_params![0u32])
            .await
            .map_err(|e| WalletError::Rpc(format!("chain_getBlockHash(0) failed: {}", e)))?;
        let genesis_hash = hex_to_array(&genesis_hash.trim_start_matches("0x"))?;
        
        // Get current block header
        let header: serde_json::Value = client
            .request("chain_getHeader", rpc_params![])
            .await
            .map_err(|e| WalletError::Rpc(format!("chain_getHeader failed: {}", e)))?;
        
        let block_number = header["number"]
            .as_str()
            .ok_or_else(|| WalletError::Rpc("Missing block number".into()))?;
        let block_number = u64::from_str_radix(block_number.trim_start_matches("0x"), 16)
            .map_err(|e| WalletError::Rpc(format!("Invalid block number: {}", e)))?;
        
        // Get current block hash
        let block_hash: String = client
            .request("chain_getBlockHash", rpc_params![])
            .await
            .map_err(|e| WalletError::Rpc(format!("chain_getBlockHash failed: {}", e)))?;
        let block_hash = hex_to_array(&block_hash.trim_start_matches("0x"))?;
        
        // Get runtime version
        let version: serde_json::Value = client
            .request("state_getRuntimeVersion", rpc_params![])
            .await
            .map_err(|e| WalletError::Rpc(format!("state_getRuntimeVersion failed: {}", e)))?;
        
        let spec_version = version["specVersion"]
            .as_u64()
            .ok_or_else(|| WalletError::Rpc("Missing specVersion".into()))? as u32;
        let tx_version = version["transactionVersion"]
            .as_u64()
            .ok_or_else(|| WalletError::Rpc("Missing transactionVersion".into()))? as u32;
        
        Ok(crate::extrinsic::ChainMetadata {
            genesis_hash,
            block_hash,
            block_number,
            spec_version,
            tx_version,
        })
    }

    /// Get account nonce for replay protection
    pub async fn get_nonce(&self, account_id: &[u8; 32]) -> Result<u32, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;
        
        let account_hex = format!("0x{}", hex::encode(account_id));
        let nonce: u32 = client
            .request("system_accountNextIndex", rpc_params![account_hex])
            .await
            .map_err(|e| WalletError::Rpc(format!("system_accountNextIndex failed: {}", e)))?;
        
        Ok(nonce)
    }

    /// Submit a signed extrinsic to the network
    ///
    /// This is the proper Substrate way to submit transactions.
    /// The extrinsic should be SCALE-encoded and signed.
    ///
    /// # Arguments
    ///
    /// * `extrinsic` - SCALE-encoded signed extrinsic bytes
    ///
    /// # Returns
    ///
    /// The transaction hash (32 bytes) if accepted into the pool.
    pub async fn submit_extrinsic(&self, extrinsic: &[u8]) -> Result<[u8; 32], WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;
        
        // Encode as hex with 0x prefix
        let extrinsic_hex = format!("0x{}", hex::encode(extrinsic));
        
        let tx_hash: String = client
            .request("author_submitExtrinsic", rpc_params![extrinsic_hex])
            .await
            .map_err(|e| WalletError::Rpc(format!("author_submitExtrinsic failed: {}", e)))?;
        
        hex_to_array(&tx_hash.trim_start_matches("0x"))
    }

    /// Submit a shielded transfer using proper Substrate extrinsic signing
    ///
    /// This is the full E2E path:
    /// 1. Build the shielded_transfer call
    /// 2. Fetch chain metadata (genesis, block hash, versions)
    /// 3. Get account nonce
    /// 4. Construct and sign extrinsic with ML-DSA
    /// 5. Submit via author_submitExtrinsic
    ///
    /// # Arguments
    ///
    /// * `bundle` - Transaction bundle with STARK proof and components
    /// * `signing_seed` - 32-byte seed for ML-DSA key derivation
    ///
    /// # Returns
    ///
    /// The transaction hash (32 bytes) if accepted into the pool.
    pub async fn submit_shielded_transfer_signed(
        &self,
        bundle: &TransactionBundle,
        signing_seed: &[u8; 32],
    ) -> Result<[u8; 32], WalletError> {
        use crate::extrinsic::{Era, ExtrinsicBuilder, ShieldedTransferCall};
        
        // 1. Create extrinsic builder from seed
        let builder = ExtrinsicBuilder::from_seed(signing_seed);
        
        // 2. Get chain metadata
        let metadata = self.get_chain_metadata().await?;
        
        // 3. Get account nonce
        let nonce = self.get_nonce(&builder.account_id()).await?;
        
        // 4. Build the call
        let call = ShieldedTransferCall::from_bundle(bundle);
        
        // 5. Build mortal era (64 block validity)
        let era = Era::mortal(64, metadata.block_number.saturating_sub(1));
        
        // 6. Build and sign the extrinsic
        let extrinsic = builder.build_shielded_transfer(
            &call,
            nonce,
            era,
            0, // tip
            &metadata,
        )?;
        
        // 7. Submit
        self.submit_extrinsic(&extrinsic).await
    }
}

/// Shielded transfer request matching `hegemon_submitShieldedTransfer` RPC
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ShieldedTransferRequest {
    /// STARK proof (base64 encoded)
    proof: String,
    /// Nullifiers for spent notes (hex encoded)
    nullifiers: Vec<String>,
    /// New note commitments (hex encoded)
    commitments: Vec<String>,
    /// Encrypted notes for recipients (base64 encoded)
    encrypted_notes: Vec<String>,
    /// Merkle root anchor (hex encoded)
    anchor: String,
    /// Binding signature (hex encoded)
    binding_sig: String,
    /// Value balance (positive = shielding, negative = unshielding)
    value_balance: i128,
}

impl ShieldedTransferRequest {
    fn from_bundle(bundle: &TransactionBundle) -> Result<Self, WalletError> {
        use base64::Engine;
        
        // Proof bytes are already serialized, just base64 encode
        let proof = base64::engine::general_purpose::STANDARD.encode(&bundle.proof_bytes);
        
        // Encode nullifiers as hex
        let nullifiers = bundle
            .nullifiers
            .iter()
            .map(|nf| hex::encode(nf))
            .collect();
        
        // Encode commitments as hex
        let commitments = bundle
            .commitments
            .iter()
            .map(|cm| hex::encode(cm))
            .collect();
        
        // Encode each ciphertext as base64
        let encrypted_notes = bundle
            .ciphertexts
            .iter()
            .map(|ct| base64::engine::general_purpose::STANDARD.encode(ct))
            .collect();
        
        // Encode anchor and binding sig
        let anchor = hex::encode(bundle.anchor);
        let binding_sig = hex::encode(bundle.binding_sig);
        
        Ok(Self { 
            proof, 
            nullifiers,
            commitments,
            encrypted_notes,
            anchor,
            binding_sig,
            value_balance: bundle.value_balance,
        })
    }
}

/// Shielded transfer response matching `hegemon_submitShieldedTransfer` RPC
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ShieldedTransferResponse {
    /// Whether submission succeeded
    success: bool,
    /// Transaction hash if successful (hex encoded)
    tx_hash: Option<String>,
    /// Block number if already included
    block_number: Option<u64>,
    /// Error message if failed
    error: Option<String>,
}

fn hex_to_array(hex_str: &str) -> Result<[u8; 32], WalletError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| WalletError::Serialization(format!("Invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(WalletError::Serialization("expected 32-byte hash".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Blocking wrapper for SubstrateRpcClient
///
/// Provides a blocking API for use in synchronous contexts,
/// compatible with the existing WalletRpcClient interface.
#[derive(Clone)]
pub struct BlockingSubstrateRpcClient {
    inner: Arc<SubstrateRpcClient>,
    runtime: Arc<tokio::runtime::Runtime>,
}

impl BlockingSubstrateRpcClient {
    /// Connect to a Substrate node (blocking)
    pub fn connect(endpoint: &str) -> Result<Self, WalletError> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| WalletError::Rpc(format!("Failed to create runtime: {}", e)))?;
        
        let inner = runtime.block_on(SubstrateRpcClient::connect(endpoint))?;
        
        Ok(Self {
            inner: Arc::new(inner),
            runtime: Arc::new(runtime),
        })
    }

    /// Connect with custom configuration (blocking)
    pub fn connect_with_config(config: SubstrateRpcConfig) -> Result<Self, WalletError> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| WalletError::Rpc(format!("Failed to create runtime: {}", e)))?;
        
        let inner = runtime.block_on(SubstrateRpcClient::connect_with_config(config))?;
        
        Ok(Self {
            inner: Arc::new(inner),
            runtime: Arc::new(runtime),
        })
    }

    /// Get latest block information
    pub fn latest_block(&self) -> Result<LatestBlock, WalletError> {
        self.runtime.block_on(self.inner.latest_block())
    }

    /// Get note status
    pub fn note_status(&self) -> Result<NoteStatus, WalletError> {
        self.runtime.block_on(self.inner.note_status())
    }

    /// Get commitment entries
    pub fn commitments(&self, start: u64, limit: usize) -> Result<Vec<CommitmentEntry>, WalletError> {
        self.runtime.block_on(self.inner.commitments(start, limit))
    }

    /// Get ciphertext entries
    pub fn ciphertexts(&self, start: u64, limit: usize) -> Result<Vec<CiphertextEntry>, WalletError> {
        self.runtime.block_on(self.inner.ciphertexts(start, limit))
    }

    /// Get nullifiers
    pub fn nullifiers(&self) -> Result<Vec<[u8; 32]>, WalletError> {
        self.runtime.block_on(self.inner.nullifiers())
    }

    /// Submit transaction
    pub fn submit_transaction(&self, bundle: &TransactionBundle) -> Result<[u8; 32], WalletError> {
        self.runtime.block_on(self.inner.submit_transaction(bundle))
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.runtime.block_on(self.inner.is_connected())
    }

    /// Get endpoint URL
    pub fn endpoint(&self) -> &str {
        self.inner.endpoint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = SubstrateRpcConfig::default();
        assert_eq!(config.endpoint, "ws://127.0.0.1:9944");
        assert_eq!(config.max_reconnect_attempts, 5);
    }

    #[test]
    fn test_config_with_endpoint() {
        let config = SubstrateRpcConfig::with_endpoint("ws://localhost:9955");
        assert_eq!(config.endpoint, "ws://localhost:9955");
    }

    #[test]
    fn test_pagination_defaults() {
        let params = PaginationParams::default();
        assert_eq!(params.start, 0);
        assert_eq!(params.limit, 128);
    }

    #[test]
    fn test_hex_to_array_valid() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let result = hex_to_array(hex).unwrap();
        assert_eq!(result[31], 1);
    }

    #[test]
    fn test_hex_to_array_invalid_length() {
        let hex = "0001";
        let result = hex_to_array(hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_to_array_invalid_hex() {
        let hex = "gg00";
        let result = hex_to_array(hex);
        assert!(result.is_err());
    }
}
