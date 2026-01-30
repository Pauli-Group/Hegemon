//! Substrate RPC Client for Wallet
//!
//! This module provides a WebSocket-based RPC client that connects to Substrate
//! nodes using the jsonrpsee library. It implements the wallet-specific RPC methods
//! defined in the `hegemon_*` namespace.
//!
//! # WebSocket RPC
//!
//! The client uses WebSocket RPC for wallet-specific methods and supports:
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

use codec::{Decode, Encode};
use jsonrpsee::core::client::{ClientT, SubscriptionClientT};
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::WalletError;
use crate::metadata::{lookup_shielded_pool_call_indices, ShieldedPoolCallIndices};
use crate::notes::NoteCiphertext;
use crate::rpc::TransactionBundle;
use transaction_circuit::StablecoinPolicyBinding;

/// Configuration for the Substrate RPC client
#[derive(Clone, Debug)]
pub struct SubstrateRpcConfig {
    /// WebSocket endpoint URL (e.g., "ws://127.0.0.1:9944")
    pub endpoint: String,
    /// Optional archive provider endpoint (WebSocket URL)
    pub archive_endpoint: Option<String>,
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
            archive_endpoint: None,
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
    /// Commitment value (48-byte encoding)
    #[serde(with = "crate::serde_bytes48::bytes48")]
    pub value: [u8; 48],
}

/// Paginated commitment response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentResponse {
    /// Commitment entries
    pub entries: Vec<CommitmentWireEntry>,
    /// Total count
    pub total: u64,
    /// Whether there are more entries
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentWireEntry {
    /// Index in the commitment tree
    pub index: u64,
    /// Commitment value (hex encoded)
    pub value: String,
}

/// Archive provider entry from archive RPC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchiveProviderEntry {
    pub provider: String,
    pub bond: u128,
    pub price_per_byte_block: u128,
    pub min_duration_blocks: u64,
    pub endpoint: String,
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

/// Parse a NoteCiphertext from the pallet's on-chain format.
///
/// The runtime API returns:
/// - ciphertext[579]: version(1) + crypto_suite(2) + diversifier_index(4) + note_len(4) +
///                    note_payload + memo_len(4) + memo_payload + padding
/// - kem_ciphertext: raw ML-KEM ciphertext bytes (length implied by crypto_suite)
fn parse_pallet_encrypted_note(bytes: &[u8]) -> Result<NoteCiphertext, WalletError> {
    const CIPHERTEXT_SIZE: usize = crate::notes::PALLET_CIPHERTEXT_SIZE;
    if bytes.len() < CIPHERTEXT_SIZE {
        return Err(WalletError::Serialization(format!(
            "Invalid encrypted note size: expected at least {}, got {}",
            CIPHERTEXT_SIZE,
            bytes.len()
        )));
    }

    let ciphertext_bytes = &bytes[..CIPHERTEXT_SIZE];

    // Parse the ciphertext portion
    let version = ciphertext_bytes[0];
    let crypto_suite = u16::from_le_bytes(
        ciphertext_bytes[1..3]
            .try_into()
            .map_err(|_| WalletError::Serialization("crypto suite parse failed".into()))?,
    );
    let diversifier_index = u32::from_le_bytes(
        ciphertext_bytes[3..7]
            .try_into()
            .map_err(|_| WalletError::Serialization("diversifier parse failed".into()))?,
    );

    let mut offset = 7;

    // Note payload length and data
    let note_len = u32::from_le_bytes(
        ciphertext_bytes[offset..offset + 4]
            .try_into()
            .map_err(|_| WalletError::Serialization("note_len parse failed".into()))?,
    ) as usize;
    offset += 4;

    if offset + note_len + 4 > CIPHERTEXT_SIZE {
        return Err(WalletError::Serialization(format!(
            "Note payload too large: {} bytes at offset {}",
            note_len, offset
        )));
    }
    let note_payload = ciphertext_bytes[offset..offset + note_len].to_vec();
    offset += note_len;

    // Memo payload length and data
    let memo_len = u32::from_le_bytes(
        ciphertext_bytes[offset..offset + 4]
            .try_into()
            .map_err(|_| WalletError::Serialization("memo_len parse failed".into()))?,
    ) as usize;
    offset += 4;

    let memo_payload = if memo_len > 0 && offset + memo_len <= CIPHERTEXT_SIZE {
        ciphertext_bytes[offset..offset + memo_len].to_vec()
    } else {
        Vec::new()
    };

    let expected_kem_len = crate::notes::expected_kem_ciphertext_len(crypto_suite)?;
    let expected_size = CIPHERTEXT_SIZE + expected_kem_len;
    if bytes.len() != expected_size {
        return Err(WalletError::Serialization(format!(
            "Invalid encrypted note size: expected {}, got {}",
            expected_size,
            bytes.len()
        )));
    }
    let kem_ciphertext = bytes[CIPHERTEXT_SIZE..expected_size].to_vec();

    Ok(NoteCiphertext {
        version,
        crypto_suite,
        diversifier_index,
        kem_ciphertext,
        note_payload,
        memo_payload,
    })
}

/// Ciphertext entry with decoded content
#[derive(Clone, Debug)]
pub struct CiphertextEntry {
    /// Index in the ciphertext list
    pub index: u64,
    /// Decoded note ciphertext
    pub ciphertext: NoteCiphertext,
}

fn decode_ciphertext_entries(
    entries: Vec<CiphertextEntryWire>,
) -> Result<Vec<CiphertextEntry>, WalletError> {
    let mut decoded = Vec::with_capacity(entries.len());
    for entry in entries {
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &entry.ciphertext,
        )
        .map_err(|e| WalletError::Serialization(format!("Invalid base64 ciphertext: {}", e)))?;

        let ciphertext = parse_pallet_encrypted_note(&bytes)?;
        decoded.push(CiphertextEntry {
            index: entry.index,
            ciphertext,
        });
    }
    Ok(decoded)
}

/// Substrate WebSocket RPC client for wallet operations
///
/// This client connects to a Substrate node via WebSocket and provides
/// methods to interact with the wallet-specific RPC endpoints.
pub struct SubstrateRpcClient {
    /// The underlying WebSocket client
    client: Arc<RwLock<WsClient>>,
    /// Optional archive provider WebSocket client
    archive_client: Arc<RwLock<Option<ArchiveRpcState>>>,
    /// Client configuration
    config: SubstrateRpcConfig,
}

#[derive(Debug)]
struct ArchiveRpcState {
    endpoint: String,
    client: WsClient,
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
        let mut config = SubstrateRpcConfig::with_endpoint(endpoint);
        if config.archive_endpoint.is_none() {
            config.archive_endpoint = std::env::var("HEGEMON_WALLET_ARCHIVE_WS_URL").ok();
        }
        Self::connect_with_config(config).await
    }

    /// Connect with custom configuration
    pub async fn connect_with_config(mut config: SubstrateRpcConfig) -> Result<Self, WalletError> {
        if config.archive_endpoint.is_none() {
            config.archive_endpoint = std::env::var("HEGEMON_WALLET_ARCHIVE_WS_URL").ok();
        }
        let client = Self::build_client(&config).await?;
        Ok(Self {
            client: Arc::new(RwLock::new(client)),
            archive_client: Arc::new(RwLock::new(None)),
            config,
        })
    }

    async fn build_client(config: &SubstrateRpcConfig) -> Result<WsClient, WalletError> {
        Self::build_client_for_endpoint(&config.endpoint, config).await
    }

    async fn build_client_for_endpoint(
        endpoint: &str,
        config: &SubstrateRpcConfig,
    ) -> Result<WsClient, WalletError> {
        WsClientBuilder::default()
            .connection_timeout(config.connection_timeout)
            .request_timeout(config.request_timeout)
            .build(endpoint)
            .await
            .map_err(|e| WalletError::Rpc(format!("Failed to connect to {}: {}", endpoint, e)))
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

    async fn ensure_archive_connected(&self) -> Result<Option<()>, WalletError> {
        {
            let guard = self.archive_client.read().await;
            if let Some(state) = guard.as_ref() {
                if state.client.is_connected() {
                    return Ok(Some(()));
                }
            }
        }

        let mut endpoint = {
            let guard = self.archive_client.read().await;
            guard.as_ref().map(|state| state.endpoint.clone())
        };

        if endpoint.is_none() {
            endpoint = self.config.archive_endpoint.clone();
        }

        if endpoint.is_none() {
            endpoint = self.discover_archive_endpoint().await?;
        }

        let Some(endpoint) = endpoint else {
            return Ok(None);
        };

        let client = Self::build_client_for_endpoint(&endpoint, &self.config).await?;
        let mut guard = self.archive_client.write().await;
        *guard = Some(ArchiveRpcState { endpoint, client });
        Ok(Some(()))
    }

    async fn discover_archive_endpoint(&self) -> Result<Option<String>, WalletError> {
        let providers = self.archive_providers().await?;
        let endpoint = providers
            .into_iter()
            .map(|provider| provider.endpoint)
            .find(|endpoint| endpoint.trim_start().starts_with("ws"));
        Ok(endpoint)
    }

    /// List archive providers from the chain.
    pub async fn archive_providers(&self) -> Result<Vec<ArchiveProviderEntry>, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;
        client
            .request("archive_listProviders", rpc_params![])
            .await
            .map_err(|e| WalletError::Rpc(format!("archive_listProviders failed: {}", e)))
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

        response
            .entries
            .into_iter()
            .map(|entry| {
                let value = hex_to_array48(&entry.value)?;
                Ok(CommitmentEntry {
                    index: entry.index,
                    value,
                })
            })
            .collect()
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

        decode_ciphertext_entries(response.entries)
    }

    /// Get ciphertext entries from archive provider (if configured or discoverable).
    pub async fn archive_ciphertexts(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<CiphertextEntry>, WalletError> {
        if self.ensure_archive_connected().await?.is_none() {
            return Err(WalletError::Rpc(
                "archive provider unavailable; configure HEGEMON_WALLET_ARCHIVE_WS_URL or register a provider".to_string(),
            ));
        }

        let guard = self.archive_client.read().await;
        let Some(state) = guard.as_ref() else {
            return Err(WalletError::Rpc(
                "archive provider unavailable; no client".to_string(),
            ));
        };

        let params = PaginationParams {
            start,
            limit: limit as u64,
        };

        let response: CiphertextResponse = state
            .client
            .request("hegemon_walletCiphertexts", rpc_params![params])
            .await
            .map_err(|e| WalletError::Rpc(format!("archive walletCiphertexts failed: {}", e)))?;

        decode_ciphertext_entries(response.entries)
    }

    /// Get all spent nullifiers
    ///
    /// Returns the list of spent nullifiers from the node.
    pub async fn nullifiers(&self) -> Result<Vec<[u8; 48]>, WalletError> {
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
                let bytes = hex::decode(hex).map_err(|e| {
                    WalletError::Serialization(format!("Invalid hex nullifier: {}", e))
                })?;
                if bytes.len() != 48 {
                    return Err(WalletError::Serialization(
                        "invalid nullifier length".into(),
                    ));
                }
                let mut out = [0u8; 48];
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
    /// nullifiers, commitments, encrypted notes, anchor, and binding hash.
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
            .map_err(|e| {
                WalletError::Rpc(format!("hegemon_submitShieldedTransfer failed: {}", e))
            })?;

        if !response.success {
            return Err(WalletError::Http(format!(
                "Shielded transfer failed: {}",
                response
                    .error
                    .unwrap_or_else(|| "unknown error".to_string())
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
            .ok_or_else(|| WalletError::Rpc("Missing specVersion".into()))?
            as u32;
        let tx_version = version["transactionVersion"]
            .as_u64()
            .ok_or_else(|| WalletError::Rpc("Missing transactionVersion".into()))?
            as u32;

        Ok(crate::extrinsic::ChainMetadata {
            genesis_hash,
            block_hash,
            block_number,
            spec_version,
            tx_version,
        })
    }

    async fn get_runtime_metadata_bytes(&self) -> Result<Vec<u8>, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;

        let metadata_hex: String = client
            .request("state_getMetadata", rpc_params![])
            .await
            .map_err(|e| WalletError::Rpc(format!("state_getMetadata failed: {}", e)))?;

        hex::decode(metadata_hex.trim_start_matches("0x")).map_err(|e| {
            WalletError::Serialization(format!("failed to decode runtime metadata hex: {}", e))
        })
    }

    async fn get_shielded_pool_call_indices(&self) -> Result<ShieldedPoolCallIndices, WalletError> {
        let metadata_bytes = self.get_runtime_metadata_bytes().await?;
        lookup_shielded_pool_call_indices(&metadata_bytes)
    }

    /// Get account nonce for replay protection
    ///
    /// Queries the System.Account storage to get the nonce for the account.
    /// Uses state_getStorage RPC with the proper storage key construction.
    pub async fn get_nonce(&self, account_id: &[u8; 32]) -> Result<u32, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;

        // Build storage key for System.Account(account_id)
        // Key = twox_128("System") ++ twox_128("Account") ++ blake2_128_concat(account_id)
        let storage_key = build_system_account_key(account_id);
        let storage_key_hex = format!("0x{}", hex::encode(&storage_key));

        // Query storage
        let result: Option<String> = client
            .request("state_getStorage", rpc_params![storage_key_hex])
            .await
            .map_err(|e| WalletError::Rpc(format!("state_getStorage failed: {}", e)))?;

        // If account doesn't exist, nonce is 0
        let Some(data_hex) = result else {
            return Ok(0);
        };

        // Decode AccountInfo: { nonce: u32, consumers: u32, providers: u32, sufficients: u32, data: AccountData }
        // Nonce is the first u32 (4 bytes)
        let data = hex::decode(data_hex.trim_start_matches("0x"))
            .map_err(|e| WalletError::Rpc(format!("failed to decode storage: {}", e)))?;

        if data.len() < 4 {
            return Err(WalletError::Rpc("invalid AccountInfo data".into()));
        }

        let nonce = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        Ok(nonce)
    }

    /// Query transparent account balance
    ///
    /// Queries the System.Account storage to get the free balance for an account.
    /// Uses state_getStorage RPC with the proper storage key construction.
    ///
    /// # Arguments
    ///
    /// * `account_id` - 32-byte account identifier
    ///
    /// # Returns
    ///
    /// The free balance in smallest units. Returns 0 if account doesn't exist.
    pub async fn query_balance(&self, account_id: &[u8; 32]) -> Result<u128, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;

        // Build storage key for System.Account(account_id)
        // Key = twox_128("System") ++ twox_128("Account") ++ blake2_128_concat(account_id)
        let storage_key = build_system_account_key(account_id);
        let storage_key_hex = format!("0x{}", hex::encode(&storage_key));

        // Query storage
        let result: Option<String> = client
            .request("state_getStorage", rpc_params![storage_key_hex])
            .await
            .map_err(|e| WalletError::Rpc(format!("state_getStorage failed: {}", e)))?;

        // If account doesn't exist, balance is 0
        let Some(data_hex) = result else {
            return Ok(0);
        };

        // Decode AccountInfo: { nonce: u32, consumers: u32, providers: u32, sufficients: u32, data: AccountData }
        // AccountData: { free: u128, reserved: u128, misc_frozen: u128, fee_frozen: u128 }
        // Layout: nonce(4) + consumers(4) + providers(4) + sufficients(4) = 16 bytes, then free(16 bytes)
        let data = hex::decode(data_hex.trim_start_matches("0x"))
            .map_err(|e| WalletError::Rpc(format!("failed to decode storage: {}", e)))?;

        if data.len() < 32 {
            // Not enough data for free balance
            return Err(WalletError::Rpc(
                "invalid AccountInfo data (too short)".into(),
            ));
        }

        // Free balance starts at offset 16 (after nonce, consumers, providers, sufficients)
        let free_balance = u128::from_le_bytes(
            data[16..32]
                .try_into()
                .map_err(|_| WalletError::Rpc("invalid balance bytes".into()))?,
        );

        Ok(free_balance)
    }

    /// Fetch asset registry metadata for an asset id.
    pub async fn asset_metadata(&self, asset_id: u64) -> Result<Option<String>, WalletError> {
        let asset_id: u32 = asset_id
            .try_into()
            .map_err(|_| WalletError::InvalidArgument("asset id out of range"))?;
        let details = self.fetch_asset_details(asset_id).await?;
        let Some(details) = details else {
            return Ok(None);
        };
        if details.metadata.is_empty() {
            return Ok(None);
        }
        let metadata = match String::from_utf8(details.metadata.clone()) {
            Ok(text) => text,
            Err(_) => format!("0x{}", hex::encode(details.metadata)),
        };
        Ok(Some(metadata))
    }

    /// Build a stablecoin policy binding from on-chain state.
    pub async fn stablecoin_policy_binding(
        &self,
        asset_id: u64,
        issuance_delta: i128,
    ) -> Result<StablecoinPolicyBinding, WalletError> {
        if issuance_delta == 0 {
            return Err(WalletError::InvalidArgument(
                "stablecoin issuance delta must be non-zero",
            ));
        }
        let magnitude = issuance_delta.unsigned_abs();
        if magnitude > u64::MAX as u128 {
            return Err(WalletError::InvalidArgument(
                "stablecoin issuance delta exceeds u64 range",
            ));
        }

        let asset_id_u32: u32 = asset_id
            .try_into()
            .map_err(|_| WalletError::InvalidArgument("asset id out of range"))?;

        let policy = self
            .fetch_stablecoin_policy(asset_id_u32)
            .await?
            .ok_or(WalletError::InvalidArgument("stablecoin policy missing"))?;

        if policy.asset_id != asset_id_u32 {
            return Err(WalletError::InvalidArgument(
                "stablecoin policy asset id mismatch",
            ));
        }
        if !policy.active {
            return Err(WalletError::InvalidArgument("stablecoin policy inactive"));
        }
        if policy.oracle_feeds.len() != 1 {
            return Err(WalletError::InvalidArgument(
                "stablecoin policy requires exactly one oracle feed",
            ));
        }

        let policy_hash = self
            .fetch_stablecoin_policy_hash(asset_id_u32)
            .await?
            .ok_or(WalletError::InvalidArgument(
                "stablecoin policy hash missing",
            ))?;

        let oracle_feed = policy.oracle_feeds[0];
        let oracle = self.fetch_oracle_commitment(oracle_feed).await?.ok_or(
            WalletError::InvalidArgument("stablecoin oracle commitment missing"),
        )?;

        let metadata = self.get_chain_metadata().await?;
        let age = metadata.block_number.saturating_sub(oracle.submitted_at);
        if age > policy.oracle_max_age {
            return Err(WalletError::InvalidArgument(
                "stablecoin oracle commitment is stale",
            ));
        }

        let attestation = self
            .fetch_attestation_commitment(policy.attestation_id)
            .await?
            .ok_or(WalletError::InvalidArgument(
                "stablecoin attestation missing",
            ))?;
        if attestation.disputed {
            return Err(WalletError::InvalidArgument(
                "stablecoin attestation is disputed",
            ));
        }

        Ok(StablecoinPolicyBinding {
            enabled: true,
            asset_id,
            policy_hash,
            oracle_commitment: oracle.commitment,
            attestation_commitment: attestation.commitment,
            issuance_delta,
            policy_version: policy.policy_version,
        })
    }

    /// Check if a nullifier has been spent on-chain
    ///
    /// Queries the ShieldedPool.Nullifiers storage to check if a nullifier exists.
    /// Uses state_getStorage RPC with proper storage key construction.
    ///
    /// # Arguments
    ///
    /// * `nullifier` - 48-byte nullifier to check
    ///
    /// # Returns
    ///
    /// `true` if the nullifier is in the spent set, `false` otherwise.
    pub async fn is_nullifier_spent(&self, nullifier: &[u8; 48]) -> Result<bool, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;

        // Build storage key for ShieldedPool.Nullifiers(nullifier)
        // Key = twox_128("ShieldedPool") ++ twox_128("Nullifiers") ++ blake2_128_concat(nullifier)
        let storage_key = build_nullifier_storage_key(nullifier);
        let storage_key_hex = format!("0x{}", hex::encode(&storage_key));

        // Query storage - if key exists, nullifier is spent
        let result: Option<String> = client
            .request("state_getStorage", rpc_params![storage_key_hex])
            .await
            .map_err(|e| WalletError::Rpc(format!("state_getStorage failed: {}", e)))?;

        // Nullifiers storage is a map to (), so any non-None result means it exists
        Ok(result.is_some())
    }

    /// Check multiple nullifiers for spent status
    ///
    /// Batch version of is_nullifier_spent for efficiency.
    ///
    /// # Arguments
    ///
    /// * `nullifiers` - Slice of 48-byte nullifiers to check
    ///
    /// # Returns
    ///
    /// Vector of booleans, one per nullifier. `true` means spent.
    pub async fn check_nullifiers_spent(
        &self,
        nullifiers: &[[u8; 48]],
    ) -> Result<Vec<bool>, WalletError> {
        let mut results = Vec::with_capacity(nullifiers.len());
        for nullifier in nullifiers {
            results.push(self.is_nullifier_spent(nullifier).await?);
        }
        Ok(results)
    }

    /// Check if an anchor is valid according to the chain.
    ///
    /// Calls the `hegemon_isValidAnchor` RPC.
    pub async fn is_valid_anchor(&self, anchor: &[u8; 48]) -> Result<bool, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;
        // `hegemon_isValidAnchor` expects hex without a 0x prefix.
        let anchor_hex = hex::encode(anchor);
        let result: bool = client
            .request("hegemon_isValidAnchor", rpc_params![anchor_hex])
            .await
            .map_err(|e| WalletError::Rpc(format!("hegemon_isValidAnchor failed: {}", e)))?;
        Ok(result)
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

        if bundle.value_balance != 0 {
            return Err(WalletError::InvalidArgument(
                "transparent pool disabled: value_balance must be 0",
            ));
        }

        // 1. Create extrinsic builder from seed
        let builder = ExtrinsicBuilder::from_seed(signing_seed);

        // 2. Get chain metadata
        let metadata = self.get_chain_metadata().await?;
        let call_indices = self.get_shielded_pool_call_indices().await?;

        // 3. Get account nonce
        let nonce = self.get_nonce(&builder.account_id()).await?;

        // 4. Build the call
        let call = ShieldedTransferCall::from_bundle(bundle);

        // Debug: print encrypted note sizes
        // eprintln!("DEBUG: Number of encrypted notes: {}", call.encrypted_notes.len());
        for (_i, _note) in call.encrypted_notes.iter().enumerate() {
            // eprintln!("DEBUG: Encrypted note {} size: {} bytes", i, note.len());
        }
        // eprintln!("DEBUG: Spec version: {}, TX version: {}", metadata.spec_version, metadata.tx_version);
        // eprintln!("DEBUG: Nonce: {}", nonce);

        // 5. Build mortal era (64 block validity)
        // Use current block number directly - block_hash is the hash of this block
        let era = Era::mortal(64, metadata.block_number);

        // 6. Build and sign the extrinsic
        let extrinsic = builder.build_shielded_transfer(
            &call,
            call_indices.shielded_transfer,
            nonce,
            era,
            0, // tip
            &metadata,
        )?;

        // Debug: print extrinsic size and first bytes
        // eprintln!("DEBUG: Extrinsic size: {} bytes", extrinsic.len());
        // eprintln!("DEBUG: Extrinsic first 100 bytes: {}", hex::encode(&extrinsic[..100.min(extrinsic.len())]));

        // 7. Submit
        self.submit_extrinsic(&extrinsic).await
    }

    /// Submit a pure shielded-to-shielded transfer (unsigned)
    ///
    /// This is for transfers where value_balance = 0 (no value entering or
    /// leaving the shielded pool). The ZK proof authenticates the spend,
    /// so no external signature or transparent account is needed.
    ///
    /// This follows the Zcash model where shielded transfers are inherently
    /// authenticated by the zero-knowledge proof itself.
    ///
    /// # Arguments
    ///
    /// * `bundle` - The transaction bundle containing proof and encrypted notes
    ///
    /// # Returns
    ///
    /// The transaction hash (32 bytes) if accepted into the pool.
    pub async fn submit_shielded_transfer_unsigned(
        &self,
        bundle: &TransactionBundle,
    ) -> Result<[u8; 32], WalletError> {
        use crate::extrinsic::{build_unsigned_shielded_transfer, ShieldedTransferCall};

        // Build the call from the bundle
        let call = ShieldedTransferCall::from_bundle(bundle);
        let call_indices = self.get_shielded_pool_call_indices().await?;

        // Verify this is a pure shielded transfer (value_balance = 0)
        if bundle.value_balance != 0 {
            return Err(WalletError::InvalidArgument(
                "Unsigned shielded transfers require value_balance = 0",
            ));
        }

        // Debug output
        // eprintln!("DEBUG: Building unsigned shielded transfer");
        // eprintln!("DEBUG: Number of nullifiers: {}", call.nullifiers.len());
        // eprintln!("DEBUG: Number of commitments: {}", call.commitments.len());
        // eprintln!("DEBUG: Number of encrypted notes: {}", call.encrypted_notes.len());

        // Build the unsigned extrinsic
        let extrinsic =
            build_unsigned_shielded_transfer(&call, call_indices.shielded_transfer_unsigned)?;

        // eprintln!("DEBUG: Unsigned extrinsic size: {} bytes", extrinsic.len());

        // Submit
        self.submit_extrinsic(&extrinsic).await
    }

    /// Submit a pure shielded-to-shielded transfer (unsigned, DA sidecar variant).
    ///
    /// This stages ciphertext bytes in the node's pending sidecar pool via
    /// `da_submitCiphertexts`, then submits `shielded_transfer_unsigned_sidecar`
    /// (hashes + sizes only) via `author_submitExtrinsic`.
    pub async fn submit_shielded_transfer_unsigned_sidecar(
        &self,
        bundle: &TransactionBundle,
    ) -> Result<[u8; 32], WalletError> {
        use crate::extrinsic::{
            build_unsigned_shielded_transfer_sidecar, ShieldedTransferSidecarCall,
        };
        use base64::Engine;
        use transaction_circuit::hashing_pq::ciphertext_hash_bytes;

        // Verify this is a pure shielded transfer (value_balance = 0).
        if bundle.value_balance != 0 {
            return Err(WalletError::InvalidArgument(
                "Unsigned shielded transfers require value_balance = 0",
            ));
        }
        if bundle.stablecoin.enabled {
            return Err(WalletError::InvalidArgument(
                "stablecoin binding not allowed in unsigned transfers",
            ));
        }

        let notes = bundle.decode_notes()?;
        if notes.len() != bundle.commitments.len() {
            return Err(WalletError::InvalidState(
                "ciphertexts count must match commitments count",
            ));
        }

        let mut ciphertext_payloads = Vec::with_capacity(notes.len());
        let mut ciphertext_hashes = Vec::with_capacity(notes.len());
        let mut ciphertext_sizes = Vec::with_capacity(notes.len());
        for note in &notes {
            let bytes = note.to_da_bytes()?;
            ciphertext_payloads.push(base64::engine::general_purpose::STANDARD.encode(&bytes));
            ciphertext_hashes.push(ciphertext_hash_bytes(&bytes));
            ciphertext_sizes.push(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
        }

        self.ensure_connected().await?;
        let client = self.client.read().await;
        let uploaded: Vec<DaSubmitCiphertextsEntry> = client
            .request(
                "da_submitCiphertexts",
                rpc_params![DaSubmitCiphertextsRequest {
                    ciphertexts: ciphertext_payloads,
                }],
            )
            .await
            .map_err(|e| WalletError::Rpc(format!("da_submitCiphertexts failed: {}", e)))?;

        if uploaded.len() != ciphertext_hashes.len() {
            return Err(WalletError::Rpc(format!(
                "da_submitCiphertexts returned {} entries (expected {})",
                uploaded.len(),
                ciphertext_hashes.len()
            )));
        }
        for (index, (entry, expected_hash)) in uploaded.iter().zip(&ciphertext_hashes).enumerate() {
            let observed_hash = hex_to_array48(&entry.hash)?;
            if &observed_hash != expected_hash {
                return Err(WalletError::Rpc(format!(
                    "da_submitCiphertexts hash mismatch at index {index}"
                )));
            }
            if entry.size != ciphertext_sizes[index] {
                return Err(WalletError::Rpc(format!(
                    "da_submitCiphertexts size mismatch at index {index}"
                )));
            }
        }

        let use_proof_sidecar = std::env::var("HEGEMON_WALLET_PROOF_SIDECAR")
            .ok()
            .map(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);

        let mut proof_bytes = bundle.proof_bytes.clone();
        if use_proof_sidecar {
            let binding_hash_hex = format!("0x{}", hex::encode(bundle.binding_hash));
            let proof_payload =
                base64::engine::general_purpose::STANDARD.encode(&bundle.proof_bytes);

            let uploaded: Vec<DaSubmitProofsEntry> = client
                .request(
                    "da_submitProofs",
                    rpc_params![DaSubmitProofsRequest {
                        proofs: vec![DaSubmitProofsItem {
                            binding_hash: binding_hash_hex.clone(),
                            proof: proof_payload,
                        }],
                    }],
                )
                .await
                .map_err(|e| WalletError::Rpc(format!("da_submitProofs failed: {}", e)))?;

            if uploaded.len() != 1 {
                return Err(WalletError::Rpc(format!(
                    "da_submitProofs returned {} entries (expected 1)",
                    uploaded.len()
                )));
            }
            let entry = &uploaded[0];
            let observed_binding = hex_to_array64(&entry.binding_hash)?;
            if observed_binding != bundle.binding_hash {
                return Err(WalletError::Rpc(
                    "da_submitProofs binding hash mismatch".to_string(),
                ));
            }
            if entry.size != u32::try_from(bundle.proof_bytes.len()).unwrap_or(u32::MAX) {
                return Err(WalletError::Rpc(
                    "da_submitProofs size mismatch".to_string(),
                ));
            }

            proof_bytes = Vec::new();
        }

        let call_indices = self.get_shielded_pool_call_indices().await?;
        let call = ShieldedTransferSidecarCall {
            proof: proof_bytes,
            nullifiers: bundle.nullifiers.clone(),
            commitments: bundle.commitments.clone(),
            ciphertext_hashes,
            ciphertext_sizes,
            anchor: bundle.anchor,
            binding_hash: bundle.binding_hash,
            stablecoin: None,
            fee: bundle.fee,
        };

        let extrinsic = build_unsigned_shielded_transfer_sidecar(
            &call,
            call_indices.shielded_transfer_unsigned_sidecar,
        )?;
        self.submit_extrinsic(&extrinsic).await
    }

    /// Submit a batch of shielded transfers with a single proof
    ///
    /// This submits multiple shielded transactions aggregated into a single
    /// batch proof, providing ~Nx size and verification time savings where
    /// N is the batch size.
    ///
    /// # Arguments
    ///
    /// * `batch_size` - Number of transactions in batch (2, 4, 8, or 16)
    /// * `nullifiers` - All nullifiers from all transactions
    /// * `commitments` - All commitments from all transactions
    /// * `ciphertexts` - All encrypted notes from all transactions
    /// * `anchor` - Shared Merkle anchor for all transactions
    /// * `total_fee` - Total fee for entire batch
    ///
    /// # Returns
    ///
    /// The transaction hash (32 bytes) if accepted into the pool.
    pub async fn submit_batch_shielded_transfer(
        &self,
        batch_size: u32,
        nullifiers: Vec<[u8; 48]>,
        commitments: Vec<[u8; 48]>,
        ciphertexts: Vec<Vec<u8>>,
        anchor: [u8; 48],
        total_fee: u128,
    ) -> Result<[u8; 32], WalletError> {
        use crate::extrinsic::{build_unsigned_batch_shielded_transfer, BatchShieldedTransferCall};

        // Validate batch size
        if !batch_size.is_power_of_two() || !(2..=16).contains(&batch_size) {
            return Err(WalletError::InvalidArgument(
                "Batch size must be 2, 4, 8, or 16",
            ));
        }

        let call_indices = self.get_shielded_pool_call_indices().await?;

        // Build the call
        let call = BatchShieldedTransferCall {
            batch_size,
            nullifiers,
            commitments,
            encrypted_notes: ciphertexts,
            anchor,
            total_fee,
        };

        // Build the unsigned extrinsic
        let extrinsic =
            build_unsigned_batch_shielded_transfer(&call, call_indices.batch_shielded_transfer)?;

        // Submit
        self.submit_extrinsic(&extrinsic).await
    }

    async fn storage_value(&self, storage_key: Vec<u8>) -> Result<Option<Vec<u8>>, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;
        let storage_key_hex = format!("0x{}", hex::encode(&storage_key));
        let result: Option<String> = client
            .request("state_getStorage", rpc_params![storage_key_hex])
            .await
            .map_err(|e| WalletError::Rpc(format!("state_getStorage failed: {}", e)))?;

        let Some(data_hex) = result else {
            return Ok(None);
        };

        let data = hex::decode(data_hex.trim_start_matches("0x"))
            .map_err(|e| WalletError::Rpc(format!("failed to decode storage: {}", e)))?;
        Ok(Some(data))
    }

    async fn fetch_stablecoin_policy(
        &self,
        asset_id: u32,
    ) -> Result<Option<StablecoinPolicyStorage>, WalletError> {
        let key = build_storage_map_key(b"StablecoinPolicy", b"Policies", &asset_id.encode());
        let Some(data) = self.storage_value(key).await? else {
            return Ok(None);
        };
        StablecoinPolicyStorage::decode(&mut &data[..])
            .map(Some)
            .map_err(|e| WalletError::Rpc(format!("stablecoin policy decode failed: {}", e)))
    }

    async fn fetch_stablecoin_policy_hash(
        &self,
        asset_id: u32,
    ) -> Result<Option<[u8; 48]>, WalletError> {
        let key = build_storage_map_key(b"StablecoinPolicy", b"PolicyHashes", &asset_id.encode());
        let Some(data) = self.storage_value(key).await? else {
            return Ok(None);
        };
        <[u8; 48]>::decode(&mut &data[..])
            .map(Some)
            .map_err(|e| WalletError::Rpc(format!("policy hash decode failed: {}", e)))
    }

    async fn fetch_oracle_commitment(
        &self,
        feed_id: u32,
    ) -> Result<Option<OracleCommitmentSnapshot>, WalletError> {
        let key = build_storage_map_key(b"Oracles", b"Feeds", &feed_id.encode());
        let Some(data) = self.storage_value(key).await? else {
            return Ok(None);
        };
        let feed = OracleFeedDetails::decode(&mut &data[..])
            .map_err(|e| WalletError::Rpc(format!("oracle feed decode failed: {}", e)))?;
        let record = match feed.latest_commitment {
            Some(record) => record,
            None => return Ok(None),
        };
        let commitment = bytes48_from_vec(record.commitment, "oracle commitment")?;
        Ok(Some(OracleCommitmentSnapshot {
            commitment,
            submitted_at: record.submitted_at,
        }))
    }

    async fn fetch_attestation_commitment(
        &self,
        commitment_id: u64,
    ) -> Result<Option<AttestationCommitmentSnapshot>, WalletError> {
        let key = build_storage_map_key(b"Attestations", b"Commitments", &commitment_id.encode());
        let Some(data) = self.storage_value(key).await? else {
            return Ok(None);
        };
        let record = AttestationCommitmentRecord::decode(&mut &data[..]).map_err(|e| {
            WalletError::Rpc(format!("attestation commitment decode failed: {}", e))
        })?;
        let commitment = bytes48_from_vec(record.root, "attestation commitment")?;
        let disputed = record.dispute != DisputeStatus::None;
        Ok(Some(AttestationCommitmentSnapshot {
            commitment,
            disputed,
            created_at: record.created,
        }))
    }

    async fn fetch_asset_details(
        &self,
        asset_id: u32,
    ) -> Result<Option<AssetDetailsStorage>, WalletError> {
        let key = build_storage_map_key(b"AssetRegistry", b"Assets", &asset_id.encode());
        let Some(data) = self.storage_value(key).await? else {
            return Ok(None);
        };
        AssetDetailsStorage::decode(&mut &data[..])
            .map(Some)
            .map_err(|e| WalletError::Rpc(format!("asset details decode failed: {}", e)))
    }
}

#[derive(Clone, Debug, Serialize)]
struct DaSubmitCiphertextsRequest {
    ciphertexts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct DaSubmitCiphertextsEntry {
    hash: String,
    size: u32,
}

#[derive(Clone, Debug, Serialize)]
struct DaSubmitProofsRequest {
    proofs: Vec<DaSubmitProofsItem>,
}

#[derive(Clone, Debug, Serialize)]
struct DaSubmitProofsItem {
    binding_hash: String,
    proof: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DaSubmitProofsEntry {
    binding_hash: String,
    size: u32,
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
    binding_hash: String,
    /// Native fee encoded in the proof
    fee: u64,
    /// Value balance (must be 0 when no transparent pool is enabled)
    value_balance: i128,
    /// Optional stablecoin policy binding
    #[serde(skip_serializing_if = "Option::is_none")]
    stablecoin: Option<StablecoinPolicyBindingRequest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StablecoinPolicyBindingRequest {
    asset_id: u64,
    policy_hash: String,
    oracle_commitment: String,
    attestation_commitment: String,
    issuance_delta: i128,
    policy_version: u32,
}

impl ShieldedTransferRequest {
    fn from_bundle(bundle: &TransactionBundle) -> Result<Self, WalletError> {
        use base64::Engine;

        // Proof bytes are already serialized, just base64 encode
        let proof = base64::engine::general_purpose::STANDARD.encode(&bundle.proof_bytes);

        // Encode nullifiers as hex
        let nullifiers = bundle.nullifiers.iter().map(|nf| hex::encode(nf)).collect();

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
        let binding_hash = hex::encode(bundle.binding_hash);
        let stablecoin = if bundle.stablecoin.enabled {
            Some(StablecoinPolicyBindingRequest {
                asset_id: bundle.stablecoin.asset_id,
                policy_hash: hex::encode(bundle.stablecoin.policy_hash),
                oracle_commitment: hex::encode(bundle.stablecoin.oracle_commitment),
                attestation_commitment: hex::encode(bundle.stablecoin.attestation_commitment),
                issuance_delta: bundle.stablecoin.issuance_delta,
                policy_version: bundle.stablecoin.policy_version,
            })
        } else {
            None
        };

        Ok(Self {
            proof,
            nullifiers,
            commitments,
            encrypted_notes,
            anchor,
            binding_hash,
            fee: bundle.fee,
            value_balance: bundle.value_balance,
            stablecoin,
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
    let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(trimmed)
        .map_err(|e| WalletError::Serialization(format!("Invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(WalletError::Serialization("expected 32-byte hash".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_to_array48(hex_str: &str) -> Result<[u8; 48], WalletError> {
    let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(trimmed)
        .map_err(|e| WalletError::Serialization(format!("Invalid hex: {}", e)))?;
    if bytes.len() != 48 {
        return Err(WalletError::Serialization("expected 48-byte hash".into()));
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_to_array64(hex_str: &str) -> Result<[u8; 64], WalletError> {
    let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(trimmed)
        .map_err(|e| WalletError::Serialization(format!("Invalid hex: {}", e)))?;
    if bytes.len() != 64 {
        return Err(WalletError::Serialization("expected 64-byte hash".into()));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn bytes48_from_vec(bytes: Vec<u8>, label: &'static str) -> Result<[u8; 48], WalletError> {
    if bytes.len() != 48 {
        return Err(WalletError::Rpc(format!(
            "{} length {} != 48",
            label,
            bytes.len()
        )));
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[allow(dead_code)]
#[derive(Clone, Debug, Decode)]
struct StablecoinPolicyStorage {
    asset_id: u32,
    oracle_feeds: Vec<u32>,
    attestation_id: u64,
    min_collateral_ratio_ppm: u128,
    max_mint_per_epoch: u128,
    oracle_max_age: u64,
    policy_version: u32,
    active: bool,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Decode)]
struct OracleSubmissionRules {
    min_interval: u64,
    max_size: u32,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Decode)]
struct OracleCommitmentRecord {
    commitment: Vec<u8>,
    attestation: Option<u64>,
    submitted_by: [u8; 32],
    submitted_at: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Decode)]
struct OracleFeedDetails {
    owner: [u8; 32],
    name: Vec<u8>,
    endpoint: Vec<u8>,
    rules: OracleSubmissionRules,
    latest_commitment: Option<OracleCommitmentRecord>,
    last_ingestion: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Decode, PartialEq, Eq)]
enum RootKind {
    Hash,
    Merkle,
    Stark,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Decode, PartialEq, Eq)]
enum DisputeStatus {
    None,
    Pending,
    Escalated,
    RolledBack,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Decode)]
struct AttestationCommitmentRecord {
    root_kind: RootKind,
    root: Vec<u8>,
    issuer: Option<u64>,
    verification_key: Option<Vec<u8>>,
    dispute: DisputeStatus,
    created: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Decode)]
struct AssetDetailsStorage {
    creator: [u8; 32],
    metadata: Vec<u8>,
    regulatory_tags: Vec<Vec<u8>>,
    provenance: Vec<u64>,
    updated: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct OracleCommitmentSnapshot {
    commitment: [u8; 48],
    submitted_at: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct AttestationCommitmentSnapshot {
    commitment: [u8; 48],
    disputed: bool,
    created_at: u64,
}

/// Blocking wrapper for SubstrateRpcClient
///
/// Provides a blocking API for use in synchronous contexts.
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
    pub fn commitments(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<CommitmentEntry>, WalletError> {
        self.runtime.block_on(self.inner.commitments(start, limit))
    }

    /// Get ciphertext entries
    pub fn ciphertexts(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<CiphertextEntry>, WalletError> {
        self.runtime.block_on(self.inner.ciphertexts(start, limit))
    }

    /// Get nullifiers
    pub fn nullifiers(&self) -> Result<Vec<[u8; 48]>, WalletError> {
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

/// Build the storage key for System.Account(account_id)
///
/// Key format: twox_128("System") ++ twox_128("Account") ++ blake2_128_concat(account_id)
fn build_system_account_key(account_id: &[u8; 32]) -> Vec<u8> {
    // twox_128("System")
    let system_hash = twox_128(b"System");

    // twox_128("Account")
    let account_hash = twox_128(b"Account");

    // blake2_128_concat(account_id) = blake2_128(account_id) ++ account_id
    let blake2_hash = blake2_128(account_id);

    // Concatenate all parts
    let mut key = Vec::with_capacity(16 + 16 + 16 + 32);
    key.extend_from_slice(&system_hash);
    key.extend_from_slice(&account_hash);
    key.extend_from_slice(&blake2_hash);
    key.extend_from_slice(account_id);

    key
}

/// Build the storage key for ShieldedPool.Nullifiers(nullifier)
///
/// Key format: twox_128("ShieldedPool") ++ twox_128("Nullifiers") ++ blake2_128_concat(nullifier)
fn build_nullifier_storage_key(nullifier: &[u8; 48]) -> Vec<u8> {
    // twox_128("ShieldedPool")
    let pallet_hash = twox_128(b"ShieldedPool");

    // twox_128("Nullifiers")
    let storage_hash = twox_128(b"Nullifiers");

    // blake2_128_concat(nullifier) = blake2_128(nullifier) ++ nullifier
    let blake2_hash = blake2_128(nullifier);

    // Concatenate all parts
    let mut key = Vec::with_capacity(16 + 16 + 16 + 48);
    key.extend_from_slice(&pallet_hash);
    key.extend_from_slice(&storage_hash);
    key.extend_from_slice(&blake2_hash);
    key.extend_from_slice(nullifier);

    key
}

/// Build the storage key for a map with Blake2_128Concat keys.
fn build_storage_map_key(pallet: &[u8], storage: &[u8], key: &[u8]) -> Vec<u8> {
    let pallet_hash = twox_128(pallet);
    let storage_hash = twox_128(storage);
    let blake2_hash = blake2_128(key);

    let mut out = Vec::with_capacity(16 + 16 + 16 + key.len());
    out.extend_from_slice(&pallet_hash);
    out.extend_from_slice(&storage_hash);
    out.extend_from_slice(&blake2_hash);
    out.extend_from_slice(key);
    out
}

/// xxHash 128-bit (two rounds of xxHash64)
fn twox_128(data: &[u8]) -> [u8; 16] {
    use std::hash::Hasher;
    use twox_hash::XxHash64;

    let mut h0 = XxHash64::with_seed(0);
    let mut h1 = XxHash64::with_seed(1);
    h0.write(data);
    h1.write(data);

    let r0 = h0.finish();
    let r1 = h1.finish();

    let mut result = [0u8; 16];
    result[..8].copy_from_slice(&r0.to_le_bytes());
    result[8..].copy_from_slice(&r1.to_le_bytes());
    result
}

/// Blake2b-128 hash
fn blake2_128(data: &[u8]) -> [u8; 16] {
    use blake2::digest::consts::U16;
    use blake2::{Blake2b, Digest};

    type Blake2b128 = Blake2b<U16>;
    let hash = Blake2b128::digest(data);
    let mut result = [0u8; 16];
    result.copy_from_slice(&hash);
    result
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
