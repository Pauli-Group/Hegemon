//! Native node RPC client for Wallet
//!
//! This module provides a JSON-RPC client for the native Hegemon
//! node. It implements the wallet-specific JSON-RPC methods defined in the
//! `hegemon_*`, `da_*`, `archive_*`, and compatibility namespaces.
//!
//! # RPC transports
//!
//! One-shot wallet operations support HTTP and WebSocket JSON-RPC. Streaming
//! sync operations still require WebSocket subscriptions.
//!
//! The client supports:
//! - Persistent connections with automatic reconnection
//! - Block subscriptions for real-time sync
//! - Full async/await support
//!
//! # Example
//!
//! ```no_run
//! use wallet::node_rpc::NodeRpcClient;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = NodeRpcClient::connect("ws://127.0.0.1:9944").await?;
//! let status = client.note_status().await?;
//! println!("Tree has {} leaves", status.leaf_count);
//! # Ok(())
//! # }
//! ```

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use codec::{Decode, Encode};
use jsonrpsee_core::client::{ClientT, Error as RpcError, Subscription, SubscriptionClientT};
use jsonrpsee_core::rpc_params;
use jsonrpsee_core::traits::ToRpcParams;
use jsonrpsee_http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee_ws_client::{WsClient, WsClientBuilder};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::WalletError;
use crate::notes::NoteCiphertext;
use crate::rpc::TransactionBundle;
use transaction_circuit::StablecoinPolicyBinding;

fn is_method_unavailable(error: &WalletError, method: &str) -> bool {
    let WalletError::Rpc(message) = error else {
        return false;
    };
    let lower = message.to_ascii_lowercase();
    let method = method.to_ascii_lowercase();
    (lower.contains("method not found")
        || lower.contains("unknown method")
        || lower.contains("unsupported method")
        || lower.contains("not supported"))
        && lower.contains(&method)
}

/// Configuration for the native node RPC client.
#[derive(Clone, Debug)]
pub struct NodeRpcConfig {
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

/// Chain metadata returned by the node compatibility RPC surface.
#[derive(Clone, Debug)]
pub struct ChainMetadata {
    pub genesis_hash: [u8; 32],
    pub block_hash: [u8; 32],
    pub block_number: u64,
    pub spec_version: u32,
    pub tx_version: u32,
}

impl Default for NodeRpcConfig {
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

impl NodeRpcConfig {
    /// Create config with custom endpoint
    pub fn with_endpoint(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            ..Default::default()
        }
    }

    /// Apply optional timeout/reconnect overrides from env.
    ///
    /// Supported variables:
    /// - HEGEMON_WALLET_RPC_CONNECT_TIMEOUT_SECS
    /// - HEGEMON_WALLET_RPC_REQUEST_TIMEOUT_SECS
    /// - HEGEMON_WALLET_RPC_RECONNECT_ATTEMPTS
    /// - HEGEMON_WALLET_RPC_RECONNECT_DELAY_SECS
    pub fn apply_env_overrides(&mut self) {
        if let Some(secs) = env_u64("HEGEMON_WALLET_RPC_CONNECT_TIMEOUT_SECS") {
            self.connection_timeout = Duration::from_secs(secs.max(1));
        }
        if let Some(secs) = env_u64("HEGEMON_WALLET_RPC_REQUEST_TIMEOUT_SECS") {
            self.request_timeout = Duration::from_secs(secs.max(1));
        }
        if let Some(attempts) = env_u64("HEGEMON_WALLET_RPC_RECONNECT_ATTEMPTS") {
            self.max_reconnect_attempts = attempts.max(1) as u32;
        }
        if let Some(secs) = env_u64("HEGEMON_WALLET_RPC_RECONNECT_DELAY_SECS") {
            self.reconnect_delay = Duration::from_secs(secs.max(1));
        }
    }
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
}

const NULLIFIER_PAGE_LIMIT: u64 = 1024;
const DEFAULT_MAX_NULLIFIERS: u64 = 1_000_000;
const MAX_RPC_STORAGE_VALUE_BYTES: usize = 64 * 1024;

fn max_nullifier_fetch() -> u64 {
    env_u64("HEGEMON_WALLET_MAX_NULLIFIERS")
        .map(|value| value.max(1))
        .unwrap_or(DEFAULT_MAX_NULLIFIERS)
}

fn note_ciphertext_da_wire_bytes() -> Result<usize, WalletError> {
    NoteCiphertext::empty()
        .to_da_bytes()
        .map(|bytes| bytes.len())
}

fn ensure_base64_encoded_max_bytes(
    input: &str,
    max_decoded_bytes: usize,
    label: &'static str,
) -> Result<(), WalletError> {
    let max_encoded_len = max_decoded_bytes.saturating_add(2) / 3 * 4;
    if input.len() > max_encoded_len {
        return Err(WalletError::Serialization(format!(
            "{label} base64 length {} exceeds encoded limit {} for {max_decoded_bytes} decoded bytes",
            input.len(),
            max_encoded_len
        )));
    }
    Ok(())
}

fn ensure_hex_encoded_exact_bytes(
    input: &str,
    expected_bytes: usize,
    label: &'static str,
) -> Result<(), WalletError> {
    let expected_len = expected_bytes.saturating_mul(2);
    if input.len() != expected_len {
        return Err(WalletError::Serialization(format!(
            "{label} hex length {} != {expected_len} for {expected_bytes} decoded bytes",
            input.len()
        )));
    }
    Ok(())
}

fn ensure_hex_encoded_max_bytes(
    input: &str,
    max_decoded_bytes: usize,
    label: &'static str,
) -> Result<(), WalletError> {
    if !input.len().is_multiple_of(2) {
        return Err(WalletError::Serialization(format!(
            "{label} hex length must be even"
        )));
    }
    let max_encoded_len = max_decoded_bytes.saturating_mul(2);
    if input.len() > max_encoded_len {
        return Err(WalletError::Serialization(format!(
            "{label} hex length {} exceeds encoded limit {max_encoded_len} for {max_decoded_bytes} decoded bytes",
            input.len()
        )));
    }
    Ok(())
}

fn ensure_wallet_page_within_requested_limit(
    method: &str,
    returned_entries: usize,
    requested_limit: usize,
) -> Result<(), WalletError> {
    if returned_entries > requested_limit {
        return Err(WalletError::Rpc(format!(
            "{method} returned {returned_entries} entries in one page (limit {requested_limit})"
        )));
    }
    Ok(())
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
    /// Next ciphertext index the node can serve. This can differ from `leaf_count` when ciphertext
    /// bytes are served from sidecar/DA storage and forks/retention introduce gaps.
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
    pub total: u64,
    /// Whether there are more entries
    pub has_more: bool,
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

fn decode_ciphertext_entries(
    entries: Vec<CiphertextEntryWire>,
) -> Result<Vec<CiphertextEntry>, WalletError> {
    let mut decoded = Vec::with_capacity(entries.len());
    let max_ciphertext_bytes = note_ciphertext_da_wire_bytes()?;
    for entry in entries {
        ensure_base64_encoded_max_bytes(
            &entry.ciphertext,
            max_ciphertext_bytes,
            "note ciphertext",
        )?;
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &entry.ciphertext,
        )
        .map_err(|e| WalletError::Serialization(format!("Invalid base64 ciphertext: {}", e)))?;

        let ciphertext = NoteCiphertext::from_da_bytes(&bytes)?;
        decoded.push(CiphertextEntry {
            index: entry.index,
            ciphertext,
        });
    }
    Ok(decoded)
}

/// JSON-RPC client for wallet operations.
///
/// This client connects to a Hegemon node over HTTP or WebSocket and provides
/// methods to interact with the wallet-specific RPC endpoints.
pub struct NodeRpcClient {
    /// The underlying JSON-RPC client
    client: Arc<RwLock<RpcTransport>>,
    /// Optional archive provider JSON-RPC client
    archive_client: Arc<RwLock<Option<ArchiveRpcState>>>,
    /// Client configuration
    config: NodeRpcConfig,
}

#[derive(Debug)]
struct ArchiveRpcState {
    endpoint: String,
    client: RpcTransport,
}

#[derive(Debug)]
enum RpcTransport {
    Http(Box<HttpClient>),
    Ws(Box<WsClient>),
}

impl RpcTransport {
    fn is_connected(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::Ws(client) => client.is_connected(),
        }
    }

    async fn request<R, Params>(&self, method: &str, params: Params) -> Result<R, RpcError>
    where
        R: DeserializeOwned,
        Params: ToRpcParams + Send,
    {
        match self {
            Self::Http(client) => client.request(method, params).await,
            Self::Ws(client) => client.request(method, params).await,
        }
    }

    async fn subscribe<Notif, Params>(
        &self,
        subscribe_method: &str,
        params: Params,
        unsubscribe_method: &str,
    ) -> Result<Subscription<Notif>, RpcError>
    where
        Notif: DeserializeOwned,
        Params: ToRpcParams + Send,
    {
        match self {
            Self::Ws(client) => {
                client
                    .subscribe(subscribe_method, params, unsubscribe_method)
                    .await
            }
            Self::Http(_) => Err(RpcError::Custom(
                "subscriptions require a ws:// RPC endpoint".to_string(),
            )),
        }
    }
}

impl NodeRpcClient {
    /// Connect to a Hegemon node.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - RPC endpoint URL (e.g., "http://127.0.0.1:9944" or "ws://127.0.0.1:9944")
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use wallet::node_rpc::NodeRpcClient;
    /// let client = NodeRpcClient::connect("ws://127.0.0.1:9944").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(endpoint: &str) -> Result<Self, WalletError> {
        let mut config = NodeRpcConfig::with_endpoint(endpoint);
        if config.archive_endpoint.is_none() {
            config.archive_endpoint = std::env::var("HEGEMON_WALLET_ARCHIVE_WS_URL").ok();
        }
        config.apply_env_overrides();
        Self::connect_with_config(config).await
    }

    /// Connect with custom configuration
    pub async fn connect_with_config(mut config: NodeRpcConfig) -> Result<Self, WalletError> {
        if config.archive_endpoint.is_none() {
            config.archive_endpoint = std::env::var("HEGEMON_WALLET_ARCHIVE_WS_URL").ok();
        }
        config.apply_env_overrides();
        let client = Self::build_client(&config).await?;
        Ok(Self {
            client: Arc::new(RwLock::new(client)),
            archive_client: Arc::new(RwLock::new(None)),
            config,
        })
    }

    async fn build_client(config: &NodeRpcConfig) -> Result<RpcTransport, WalletError> {
        Self::build_client_for_endpoint(&config.endpoint, config).await
    }

    async fn build_client_for_endpoint(
        endpoint: &str,
        config: &NodeRpcConfig,
    ) -> Result<RpcTransport, WalletError> {
        if endpoint.starts_with("https://") || endpoint.starts_with("wss://") {
            return Err(WalletError::Rpc(format!(
                "TLS RPC endpoint not supported by PQ-only wallet build: {}",
                endpoint
            )));
        }

        if endpoint.starts_with("http://") {
            return HttpClientBuilder::default()
                .request_timeout(config.request_timeout)
                .build(endpoint)
                .map(|client| RpcTransport::Http(Box::new(client)))
                .map_err(|e| {
                    WalletError::Rpc(format!("Failed to connect to {}: {}", endpoint, e))
                });
        }

        WsClientBuilder::default()
            .connection_timeout(config.connection_timeout)
            .request_timeout(config.request_timeout)
            .build(endpoint)
            .await
            .map(|client| RpcTransport::Ws(Box::new(client)))
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
        Ok(Vec::new())
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
        ensure_wallet_page_within_requested_limit(
            "hegemon_walletCommitments",
            response.entries.len(),
            limit,
        )?;

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
        ensure_wallet_page_within_requested_limit(
            "hegemon_walletCiphertexts",
            response.entries.len(),
            limit,
        )?;

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
        ensure_wallet_page_within_requested_limit(
            "archive walletCiphertexts",
            response.entries.len(),
            limit,
        )?;

        decode_ciphertext_entries(response.entries)
    }

    /// Get the spent nullifier set from the node, paged to avoid whole-state materialization.
    pub async fn nullifiers(&self) -> Result<HashSet<[u8; 48]>, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;
        let mut start = 0u64;
        let mut pages = 0u64;
        let mut nullifiers = HashSet::new();
        let max_nullifiers = max_nullifier_fetch();
        let max_pages =
            max_nullifiers.saturating_add(NULLIFIER_PAGE_LIMIT - 1) / NULLIFIER_PAGE_LIMIT;

        loop {
            let response: NullifierResponse = client
                .request(
                    "hegemon_walletNullifiers",
                    rpc_params![PaginationParams {
                        start,
                        limit: NULLIFIER_PAGE_LIMIT,
                    }],
                )
                .await
                .map_err(|e| WalletError::Rpc(format!("hegemon_walletNullifiers failed: {}", e)))?;

            let batch_len = response.nullifiers.len();
            let batch_len_u64 = batch_len as u64;

            if response.total > max_nullifiers {
                return Err(WalletError::Rpc(format!(
                    "node reports {} nullifiers which exceeds local safety cap {} (set HEGEMON_WALLET_MAX_NULLIFIERS to override)",
                    response.total, max_nullifiers
                )));
            }
            if batch_len_u64 > NULLIFIER_PAGE_LIMIT {
                return Err(WalletError::Rpc(format!(
                    "node returned {} nullifiers in one page (limit {})",
                    batch_len_u64, NULLIFIER_PAGE_LIMIT
                )));
            }

            let batch_end = start
                .checked_add(batch_len_u64)
                .ok_or(WalletError::InvalidState("nullifier pagination overflow"))?;
            if batch_end > response.total {
                return Err(WalletError::Rpc(format!(
                    "node returned inconsistent nullifier page: end {} exceeds total {}",
                    batch_end, response.total
                )));
            }

            for hex in response.nullifiers {
                nullifiers.insert(hex_to_array48(&hex).map_err(|err| {
                    WalletError::Serialization(format!("Invalid hex nullifier: {err}"))
                })?);
            }

            if !response.has_more {
                if batch_end < response.total {
                    return Err(WalletError::Rpc(format!(
                        "node ended nullifier pagination early at {} of {}",
                        batch_end, response.total
                    )));
                }
                break;
            }
            if batch_len == 0 {
                return Err(WalletError::Rpc(
                    "node reported more nullifier pages but returned an empty page".to_string(),
                ));
            }
            if batch_end >= response.total {
                return Err(WalletError::Rpc(format!(
                    "node reported more nullifier pages past declared total {}",
                    response.total
                )));
            }

            pages = pages.saturating_add(1);
            if pages > max_pages {
                return Err(WalletError::Rpc(format!(
                    "nullifier pagination exceeded safety page cap {} (set HEGEMON_WALLET_MAX_NULLIFIERS to override)",
                    max_pages
                )));
            }

            start = batch_end;
        }

        Ok(nullifiers)
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

    /// Get the block hash at a specific height.
    ///
    /// Returns `Ok(None)` when the node does not have a hash for that height.
    pub async fn block_hash(&self, height: u64) -> Result<Option<[u8; 32]>, WalletError> {
        self.ensure_connected().await?;
        let client = self.client.read().await;

        let response: Option<String> = client
            .request("chain_getBlockHash", rpc_params![height])
            .await
            .map_err(|e| WalletError::Rpc(format!("chain_getBlockHash({height}) failed: {e}")))?;

        response.map(|hash| hex_to_array(&hash)).transpose()
    }

    /// Submit a shielded transaction to the network
    ///
    /// This builds a kernel action envelope and submits it through
    /// `hegemon_submitAction`.
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

        let request = SubmitActionRequest::from_bundle(bundle)?;

        let response: SubmitActionResponse = client
            .request("hegemon_submitAction", rpc_params![request])
            .await
            .map_err(|e| WalletError::Rpc(format!("hegemon_submitAction failed: {}", e)))?;

        if !response.success {
            return Err(WalletError::Http(format!(
                "Kernel action submission failed: {}",
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

    async fn submit_shielded_transfer_via_rpc(
        &self,
        bundle: &TransactionBundle,
    ) -> Result<[u8; 32], WalletError> {
        self.submit_transaction(bundle).await
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
    ) -> Result<Subscription<serde_json::Value>, WalletError> {
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
    ) -> Result<Subscription<serde_json::Value>, WalletError> {
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

    /// Get chain metadata required for wallet sync and policy freshness checks.
    ///
    /// Returns genesis hash, current block hash/number, and runtime versions.
    pub async fn get_chain_metadata(&self) -> Result<ChainMetadata, WalletError> {
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

        Ok(ChainMetadata {
            genesis_hash,
            block_hash,
            block_number,
            spec_version,
            tx_version,
        })
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
        let trimmed = data_hex.trim_start_matches("0x");
        ensure_hex_encoded_max_bytes(trimmed, MAX_RPC_STORAGE_VALUE_BYTES, "account storage")
            .map_err(|e| WalletError::Rpc(e.to_string()))?;
        let data = hex::decode(trimmed)
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
        let trimmed = data_hex.trim_start_matches("0x");
        ensure_hex_encoded_max_bytes(trimmed, MAX_RPC_STORAGE_VALUE_BYTES, "account storage")
            .map_err(|e| WalletError::Rpc(e.to_string()))?;
        let data = hex::decode(trimmed)
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

        stablecoin_policy_binding_from_admitted_state(
            asset_id,
            asset_id_u32,
            issuance_delta,
            policy,
            policy_hash,
            oracle,
            attestation,
            metadata.block_number,
        )
    }

    /// Check if a nullifier has been spent on-chain.
    ///
    /// Native 0.10 nodes expose the spent set through `hegemon_walletNullifiers`.
    /// Legacy/Substrate-compatible nodes may still answer `state_getStorage`, so
    /// use that only when the native wallet method is not available.
    pub async fn is_nullifier_spent(&self, nullifier: &[u8; 48]) -> Result<bool, WalletError> {
        match self.nullifiers().await {
            Ok(spent) => return Ok(spent.contains(nullifier)),
            Err(err) if is_method_unavailable(&err, "hegemon_walletNullifiers") => {}
            Err(err) => return Err(err),
        }
        self.is_nullifier_spent_via_storage(nullifier).await
    }

    async fn is_nullifier_spent_via_storage(
        &self,
        nullifier: &[u8; 48],
    ) -> Result<bool, WalletError> {
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

    /// Check multiple nullifiers for spent status.
    pub async fn check_nullifiers_spent(
        &self,
        nullifiers: &[[u8; 48]],
    ) -> Result<Vec<bool>, WalletError> {
        match self.nullifiers().await {
            Ok(spent) => {
                return Ok(nullifiers
                    .iter()
                    .map(|nullifier| spent.contains(nullifier))
                    .collect())
            }
            Err(err) if is_method_unavailable(&err, "hegemon_walletNullifiers") => {}
            Err(err) => return Err(err),
        }
        let mut results = Vec::with_capacity(nullifiers.len());
        for nullifier in nullifiers {
            results.push(self.is_nullifier_spent_via_storage(nullifier).await?);
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

    /// Submit generic opaque transaction bytes to the network.
    ///
    /// Generic author submission is disabled in the native proof build.
    ///
    /// # Arguments
    ///
    /// * `_payload` - opaque transaction bytes
    ///
    /// # Returns
    ///
    /// The transaction hash (32 bytes) if accepted into the pool.
    pub async fn submit_opaque_transaction(
        &self,
        _payload: &[u8],
    ) -> Result<[u8; 32], WalletError> {
        Err(WalletError::Rpc(
            "generic author submission removed; use Hegemon shielded RPC".to_string(),
        ))
    }

    /// Submit a shielded transfer through the proof-native RPC path.
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
        _signing_seed: &[u8; 32],
    ) -> Result<[u8; 32], WalletError> {
        self.submit_shielded_transfer_via_rpc(bundle).await
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
    /// * `bundle` - The transaction bundle containing native tx-leaf artifact bytes and encrypted notes
    ///
    /// # Returns
    ///
    /// The transaction hash (32 bytes) if accepted into the pool.
    pub async fn submit_shielded_transfer_unsigned(
        &self,
        bundle: &TransactionBundle,
    ) -> Result<[u8; 32], WalletError> {
        self.submit_shielded_transfer_via_rpc(bundle).await
    }

    /// Submit a pure shielded-to-shielded transfer (unsigned, DA sidecar variant).
    ///
    /// This stages ciphertext bytes in the node's pending sidecar pool via
    /// `da_submitCiphertexts`, then submits the corresponding sidecar-flavored
    /// kernel action through `hegemon_submitAction`. The shipped proof bytes
    /// remain native tx-leaf artifact bytes even when ciphertext transport moves
    /// to the sidecar path. The DA staging RPC is unsafe-only; this flow is for
    /// a trusted local or proposer node running with `--rpc-methods=unsafe`.
    pub async fn submit_shielded_transfer_unsigned_sidecar(
        &self,
        bundle: &TransactionBundle,
    ) -> Result<[u8; 32], WalletError> {
        self.submit_shielded_transfer_unsigned_sidecar_with_proof_mode(bundle, None)
            .await
    }

    /// Submit a sidecar-flavored shielded transfer through the proof-native RPC path.
    pub async fn submit_shielded_transfer_unsigned_sidecar_with_proof_mode(
        &self,
        bundle: &TransactionBundle,
        force_proof_sidecar: Option<bool>,
    ) -> Result<[u8; 32], WalletError> {
        use base64::Engine;

        self.ensure_connected().await?;
        let client = self.client.read().await;

        let decoded_notes = bundle.decode_notes()?;
        let mut da_ciphertexts = Vec::with_capacity(decoded_notes.len());
        for note in &decoded_notes {
            da_ciphertexts
                .push(base64::engine::general_purpose::STANDARD.encode(note.to_da_bytes()?));
        }

        let da_response: Vec<DaSubmitCiphertextsEntry> = client
            .request(
                "da_submitCiphertexts",
                rpc_params![DaSubmitCiphertextsRequest {
                    ciphertexts: da_ciphertexts,
                }],
            )
            .await
            .map_err(|e| {
                WalletError::Rpc(format!(
                    "da_submitCiphertexts failed: {e} (requires trusted node with --rpc-methods=unsafe)"
                ))
            })?;

        if da_response.len() != bundle.commitments.len() {
            return Err(WalletError::Rpc(
                "DA sidecar response count did not match commitments count".to_string(),
            ));
        }

        let mut ciphertext_hashes = Vec::with_capacity(da_response.len());
        let mut ciphertext_sizes = Vec::with_capacity(da_response.len());
        for entry in &da_response {
            ciphertext_hashes.push(hex_to_array48(&entry.hash)?);
            ciphertext_sizes.push(entry.size);
        }

        let proof_sidecar = force_proof_sidecar.unwrap_or(false);
        let proof = if proof_sidecar {
            let proof_response: serde_json::Value = client
                .request(
                    "da_submitProofs",
                    rpc_params![DaSubmitProofsRequest {
                        proofs: vec![DaSubmitProofsItem {
                            binding_hash: format!("0x{}", hex::encode(bundle.binding_hash)),
                            proof: base64::engine::general_purpose::STANDARD
                                .encode(&bundle.proof_bytes),
                        }],
                    }],
                )
                .await
                .map_err(|e| {
                    WalletError::Rpc(format!(
                        "da_submitProofs failed: {e} (requires trusted node with --rpc-methods=unsafe)"
                    ))
                })?;

            let staged = proof_response
                .as_array()
                .map(|items| !items.is_empty())
                .unwrap_or(false);
            if !staged {
                return Err(WalletError::Rpc(
                    "da_submitProofs returned no staged proofs".to_string(),
                ));
            }
            Vec::new()
        } else {
            bundle.proof_bytes.clone()
        };

        let args = protocol_shielded_pool::family::ShieldedTransferSidecarArgs {
            proof,
            commitments: bundle.commitments.clone(),
            ciphertext_hashes,
            ciphertext_sizes,
            anchor: bundle.anchor,
            balance_slot_asset_ids: bundle.balance_slot_asset_ids,
            binding_hash: bundle.binding_hash,
            stablecoin: if bundle.stablecoin.enabled {
                Some(protocol_shielded_pool::types::StablecoinPolicyBinding {
                    asset_id: bundle.stablecoin.asset_id,
                    policy_hash: bundle.stablecoin.policy_hash,
                    oracle_commitment: bundle.stablecoin.oracle_commitment,
                    attestation_commitment: bundle.stablecoin.attestation_commitment,
                    issuance_delta: bundle.stablecoin.issuance_delta,
                    policy_version: bundle.stablecoin.policy_version,
                })
            } else {
                None
            },
            fee: bundle.fee,
        };

        let envelope = build_shielded_envelope(
            protocol_versioning::DEFAULT_VERSION_BINDING,
            protocol_shielded_pool::family::ACTION_SHIELDED_TRANSFER_SIDECAR,
            bundle.nullifiers.clone(),
            args.encode(),
        );
        let request = SubmitActionRequest::from_envelope(&envelope)?;
        let response: SubmitActionResponse = client
            .request("hegemon_submitAction", rpc_params![request])
            .await
            .map_err(|e| WalletError::Rpc(format!("hegemon_submitAction failed: {}", e)))?;

        if !response.success {
            return Err(WalletError::Http(format!(
                "Kernel action submission failed: {}",
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

    /// Batch shielded transfer submission is not currently exposed through the
    /// wallet RPC client.
    ///
    /// # Arguments
    ///
    /// * `batch_size` - Number of transactions in batch (2, 4, 8, 16, or 32)
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
        let _ = (
            batch_size,
            nullifiers,
            commitments,
            ciphertexts,
            anchor,
            total_fee,
        );
        Err(WalletError::Rpc(
            "batch shielded submission is not exposed through Hegemon RPC in this build"
                .to_string(),
        ))
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

        let trimmed = data_hex.trim_start_matches("0x");
        ensure_hex_encoded_max_bytes(trimmed, MAX_RPC_STORAGE_VALUE_BYTES, "storage value")
            .map_err(|e| WalletError::Rpc(e.to_string()))?;
        let data = hex::decode(trimmed)
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SubmitActionRequest {
    binding_circuit: u16,
    binding_crypto: u16,
    family_id: u16,
    action_id: u16,
    object_refs: Vec<SubmitActionObjectRef>,
    new_nullifiers: Vec<String>,
    public_args: String,
    authorization_proof: Option<String>,
    authorization_signatures: Vec<SubmitActionSignature>,
    aux_data: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SubmitActionObjectRef {
    family_id: u16,
    object_id: String,
    expected_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SubmitActionSignature {
    key_id: String,
    signature_scheme: u16,
    signature_bytes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SubmitActionResponse {
    success: bool,
    tx_hash: Option<String>,
    error: Option<String>,
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

impl SubmitActionRequest {
    fn from_bundle(bundle: &TransactionBundle) -> Result<Self, WalletError> {
        let ciphertexts = bundle
            .decode_notes()?
            .into_iter()
            .map(|note| {
                let bytes = note.to_chain_bytes()?;
                protocol_shielded_pool::types::EncryptedNote::decode(&mut &bytes[..]).map_err(|e| {
                    WalletError::Serialization(format!(
                        "failed to decode chain encrypted note: {e:?}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, WalletError>>()?;

        let args = protocol_shielded_pool::family::ShieldedTransferInlineArgs {
            proof: bundle.proof_bytes.clone(),
            commitments: bundle.commitments.clone(),
            ciphertexts,
            anchor: bundle.anchor,
            balance_slot_asset_ids: bundle.balance_slot_asset_ids,
            binding_hash: bundle.binding_hash,
            stablecoin: if bundle.stablecoin.enabled {
                Some(protocol_shielded_pool::types::StablecoinPolicyBinding {
                    asset_id: bundle.stablecoin.asset_id,
                    policy_hash: bundle.stablecoin.policy_hash,
                    oracle_commitment: bundle.stablecoin.oracle_commitment,
                    attestation_commitment: bundle.stablecoin.attestation_commitment,
                    issuance_delta: bundle.stablecoin.issuance_delta,
                    policy_version: bundle.stablecoin.policy_version,
                })
            } else {
                None
            },
            fee: bundle.fee,
        };

        let envelope = build_shielded_envelope(
            protocol_versioning::DEFAULT_VERSION_BINDING,
            protocol_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
            bundle.nullifiers.clone(),
            args.encode(),
        );

        Self::from_envelope(&envelope)
    }

    fn from_envelope(
        envelope: &protocol_kernel::types::ActionEnvelope,
    ) -> Result<Self, WalletError> {
        use base64::Engine;

        Ok(Self {
            binding_circuit: envelope.binding.circuit,
            binding_crypto: envelope.binding.crypto,
            family_id: envelope.family_id,
            action_id: envelope.action_id,
            object_refs: envelope
                .object_refs
                .iter()
                .map(|object_ref| SubmitActionObjectRef {
                    family_id: object_ref.family_id,
                    object_id: hex::encode(object_ref.object_id),
                    expected_root: hex::encode(object_ref.expected_root),
                })
                .collect(),
            new_nullifiers: envelope.new_nullifiers.iter().map(hex::encode).collect(),
            public_args: base64::engine::general_purpose::STANDARD.encode(&envelope.public_args),
            authorization_proof: (!envelope.authorization.proof_bytes.is_empty()).then(|| {
                base64::engine::general_purpose::STANDARD
                    .encode(&envelope.authorization.proof_bytes)
            }),
            authorization_signatures: envelope
                .authorization
                .signatures
                .iter()
                .map(|sig| SubmitActionSignature {
                    key_id: hex::encode(sig.key_id),
                    signature_scheme: sig.signature_scheme,
                    signature_bytes: base64::engine::general_purpose::STANDARD
                        .encode(&sig.signature_bytes),
                })
                .collect(),
            aux_data: (!envelope.aux_data.is_empty())
                .then(|| base64::engine::general_purpose::STANDARD.encode(&envelope.aux_data)),
        })
    }
}

fn build_shielded_envelope(
    binding: protocol_versioning::VersionBinding,
    action_id: protocol_shielded_pool::family::ActionId,
    new_nullifiers: Vec<[u8; 48]>,
    public_args: Vec<u8>,
) -> protocol_kernel::types::ActionEnvelope {
    protocol_kernel::types::ActionEnvelope {
        binding: protocol_kernel::types::KernelVersionBinding::from(binding),
        family_id: protocol_shielded_pool::family::FAMILY_SHIELDED_POOL,
        action_id,
        object_refs: Vec::new(),
        new_nullifiers,
        public_args,
        authorization: protocol_kernel::types::AuthorizationBundle {
            proof_bytes: Vec::new(),
            signatures: Vec::new(),
        },
        aux_data: Vec::new(),
    }
}

fn hex_to_array(hex_str: &str) -> Result<[u8; 32], WalletError> {
    let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    ensure_hex_encoded_exact_bytes(trimmed, 32, "hash")?;
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
    ensure_hex_encoded_exact_bytes(trimmed, 48, "hash")?;
    let bytes = hex::decode(trimmed)
        .map_err(|e| WalletError::Serialization(format!("Invalid hex: {}", e)))?;
    if bytes.len() != 48 {
        return Err(WalletError::Serialization("expected 48-byte hash".into()));
    }
    let mut out = [0u8; 48];
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

fn stablecoin_policy_binding_from_admitted_state(
    asset_id: u64,
    asset_id_u32: u32,
    issuance_delta: i128,
    policy: StablecoinPolicyStorage,
    policy_hash: [u8; 48],
    oracle: OracleCommitmentSnapshot,
    attestation: AttestationCommitmentSnapshot,
    current_block: u64,
) -> Result<StablecoinPolicyBinding, WalletError> {
    if issuance_delta == 0 {
        return Err(WalletError::InvalidArgument(
            "stablecoin issuance delta must be non-zero",
        ));
    }
    if issuance_delta.unsigned_abs() > u64::MAX as u128 {
        return Err(WalletError::InvalidArgument(
            "stablecoin issuance delta exceeds u64 range",
        ));
    }
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
    let age = current_block.saturating_sub(oracle.submitted_at);
    if age > policy.oracle_max_age {
        return Err(WalletError::InvalidArgument(
            "stablecoin oracle commitment is stale",
        ));
    }
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

/// Blocking wrapper for NodeRpcClient
///
/// Provides a blocking API for use in synchronous contexts.
#[derive(Clone)]
pub struct BlockingNodeRpcClient {
    inner: Arc<NodeRpcClient>,
    runtime: Arc<tokio::runtime::Runtime>,
}

impl BlockingNodeRpcClient {
    /// Connect to a Hegemon node (blocking).
    pub fn connect(endpoint: &str) -> Result<Self, WalletError> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| WalletError::Rpc(format!("Failed to create runtime: {}", e)))?;

        let inner = runtime.block_on(NodeRpcClient::connect(endpoint))?;

        Ok(Self {
            inner: Arc::new(inner),
            runtime: Arc::new(runtime),
        })
    }

    /// Connect with custom configuration (blocking)
    pub fn connect_with_config(config: NodeRpcConfig) -> Result<Self, WalletError> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| WalletError::Rpc(format!("Failed to create runtime: {}", e)))?;

        let inner = runtime.block_on(NodeRpcClient::connect_with_config(config))?;

        Ok(Self {
            inner: Arc::new(inner),
            runtime: Arc::new(runtime),
        })
    }

    /// Get latest block information
    pub fn latest_block(&self) -> Result<LatestBlock, WalletError> {
        self.runtime.block_on(self.inner.latest_block())
    }

    /// Get block hash at a specific height.
    pub fn block_hash(&self, height: u64) -> Result<Option<[u8; 32]>, WalletError> {
        self.runtime.block_on(self.inner.block_hash(height))
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
    pub fn nullifiers(&self) -> Result<HashSet<[u8; 48]>, WalletError> {
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
    let module_hash = twox_128(b"ShieldedPool");

    // twox_128("Nullifiers")
    let storage_hash = twox_128(b"Nullifiers");

    // blake2_128_concat(nullifier) = blake2_128(nullifier) ++ nullifier
    let blake2_hash = blake2_128(nullifier);

    // Concatenate all parts
    let mut key = Vec::with_capacity(16 + 16 + 16 + 48);
    key.extend_from_slice(&module_hash);
    key.extend_from_slice(&storage_hash);
    key.extend_from_slice(&blake2_hash);
    key.extend_from_slice(nullifier);

    key
}

/// Build the storage key for a map with Blake2_128Concat keys.
fn build_storage_map_key(module: &[u8], storage: &[u8], key: &[u8]) -> Vec<u8> {
    let module_hash = twox_128(module);
    let storage_hash = twox_128(storage);
    let blake2_hash = blake2_128(key);

    let mut out = Vec::with_capacity(16 + 16 + 16 + key.len());
    out.extend_from_slice(&module_hash);
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
    use base64::Engine;
    use codec::{Decode, Encode};

    #[test]
    fn test_config_defaults() {
        let config = NodeRpcConfig::default();
        assert_eq!(config.endpoint, "ws://127.0.0.1:9944");
        assert_eq!(config.max_reconnect_attempts, 5);
    }

    #[test]
    fn test_config_with_endpoint() {
        let config = NodeRpcConfig::with_endpoint("ws://localhost:9955");
        assert_eq!(config.endpoint, "ws://localhost:9955");
    }

    #[tokio::test]
    async fn rejects_tls_rpc_endpoints() {
        for endpoint in ["https://127.0.0.1:9944", "wss://127.0.0.1:9944"] {
            let config = NodeRpcConfig::with_endpoint(endpoint);
            let result = NodeRpcClient::build_client_for_endpoint(endpoint, &config).await;
            let err = match result {
                Ok(_) => panic!("TLS endpoint must be rejected"),
                Err(err) => err,
            };
            assert!(matches!(
                err,
                WalletError::Rpc(message)
                    if message.contains("TLS RPC endpoint not supported by PQ-only wallet build")
            ));
        }
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

    #[test]
    fn test_hex_to_array48_accepts_prefixed_nullifier() {
        let bare = "11".repeat(48);
        let prefixed = format!("0x{bare}");
        assert_eq!(hex_to_array48(&prefixed).unwrap(), [0x11; 48]);
        assert_eq!(hex_to_array48(&bare).unwrap(), [0x11; 48]);
    }

    fn sample_stablecoin_policy(asset_id: u32) -> StablecoinPolicyStorage {
        StablecoinPolicyStorage {
            asset_id,
            oracle_feeds: vec![77],
            attestation_id: 88,
            min_collateral_ratio_ppm: 1_500_000,
            max_mint_per_epoch: 1_000_000,
            oracle_max_age: 10,
            policy_version: 9,
            active: true,
        }
    }

    fn sample_oracle(submitted_at: u64) -> OracleCommitmentSnapshot {
        OracleCommitmentSnapshot {
            commitment: [0x22; 48],
            submitted_at,
        }
    }

    fn sample_attestation(disputed: bool) -> AttestationCommitmentSnapshot {
        AttestationCommitmentSnapshot {
            commitment: [0x33; 48],
            disputed,
            created_at: 12,
        }
    }

    fn expect_invalid_argument<T: core::fmt::Debug>(
        result: Result<T, WalletError>,
        message: &'static str,
    ) {
        assert_eq!(
            result
                .expect_err("stablecoin admission should reject")
                .to_string(),
            format!("invalid argument: {message}")
        );
    }

    #[test]
    fn stablecoin_policy_admission_binds_exact_lookup_payload() {
        let binding = stablecoin_policy_binding_from_admitted_state(
            1001,
            1001,
            -42,
            sample_stablecoin_policy(1001),
            [0x11; 48],
            sample_oracle(15),
            sample_attestation(false),
            20,
        )
        .expect("admitted stablecoin policy binding");

        assert!(binding.enabled);
        assert_eq!(binding.asset_id, 1001);
        assert_eq!(binding.policy_hash, [0x11; 48]);
        assert_eq!(binding.oracle_commitment, [0x22; 48]);
        assert_eq!(binding.attestation_commitment, [0x33; 48]);
        assert_eq!(binding.issuance_delta, -42);
        assert_eq!(binding.policy_version, 9);
    }

    #[test]
    fn stablecoin_policy_admission_rejects_invalid_lookup_records() {
        expect_invalid_argument(
            stablecoin_policy_binding_from_admitted_state(
                1001,
                1001,
                0,
                sample_stablecoin_policy(1001),
                [0x11; 48],
                sample_oracle(15),
                sample_attestation(false),
                20,
            ),
            "stablecoin issuance delta must be non-zero",
        );

        expect_invalid_argument(
            stablecoin_policy_binding_from_admitted_state(
                1001,
                1001,
                42,
                StablecoinPolicyStorage {
                    active: false,
                    ..sample_stablecoin_policy(1001)
                },
                [0x11; 48],
                sample_oracle(15),
                sample_attestation(false),
                20,
            ),
            "stablecoin policy inactive",
        );

        expect_invalid_argument(
            stablecoin_policy_binding_from_admitted_state(
                1001,
                1001,
                42,
                StablecoinPolicyStorage {
                    oracle_feeds: vec![77, 78],
                    ..sample_stablecoin_policy(1001)
                },
                [0x11; 48],
                sample_oracle(15),
                sample_attestation(false),
                20,
            ),
            "stablecoin policy requires exactly one oracle feed",
        );

        expect_invalid_argument(
            stablecoin_policy_binding_from_admitted_state(
                1001,
                1001,
                42,
                sample_stablecoin_policy(1001),
                [0x11; 48],
                sample_oracle(9),
                sample_attestation(false),
                20,
            ),
            "stablecoin oracle commitment is stale",
        );

        expect_invalid_argument(
            stablecoin_policy_binding_from_admitted_state(
                1001,
                1001,
                42,
                sample_stablecoin_policy(1001),
                [0x11; 48],
                sample_oracle(15),
                sample_attestation(true),
                20,
            ),
            "stablecoin attestation is disputed",
        );
    }

    fn ciphertext_entry_for_bytes(index: u64, bytes: &[u8]) -> CiphertextEntryWire {
        CiphertextEntryWire {
            index,
            ciphertext: base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    }

    fn memo_offsets_for_container(bytes: &[u8]) -> (usize, usize, usize) {
        let note_len = u32::from_le_bytes(bytes[7..11].try_into().unwrap()) as usize;
        let memo_len_offset = 11 + note_len;
        let memo_start = memo_len_offset + 4;
        let memo_len = u32::from_le_bytes(
            bytes[memo_len_offset..memo_len_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        (memo_len_offset, memo_start, memo_start + memo_len)
    }

    #[test]
    fn decode_ciphertext_entries_accepts_strict_da_ciphertext() {
        let note = NoteCiphertext::empty();
        let bytes = note.to_da_bytes().expect("DA bytes");
        let decoded =
            decode_ciphertext_entries(vec![ciphertext_entry_for_bytes(7, &bytes)]).unwrap();

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].index, 7);
        assert_eq!(decoded[0].ciphertext, note);
    }

    #[test]
    fn decode_ciphertext_entries_rejects_da_memo_overrun() {
        let mut bytes = NoteCiphertext::empty().to_da_bytes().expect("DA bytes");
        let (memo_len_offset, memo_start, _) = memo_offsets_for_container(&bytes);
        let overrun_len = crate::notes::CHAIN_CIPHERTEXT_SIZE - memo_start + 1;
        bytes[memo_len_offset..memo_len_offset + 4]
            .copy_from_slice(&(overrun_len as u32).to_le_bytes());

        assert!(
            decode_ciphertext_entries(vec![ciphertext_entry_for_bytes(0, &bytes)]).is_err(),
            "DA ciphertext memo overrun must not be silently treated as an empty memo"
        );
    }

    #[test]
    fn decode_ciphertext_entries_rejects_da_nonzero_padding() {
        let mut bytes = NoteCiphertext::empty().to_da_bytes().expect("DA bytes");
        let (_, _, payload_end) = memo_offsets_for_container(&bytes);
        assert!(payload_end < crate::notes::CHAIN_CIPHERTEXT_SIZE);
        bytes[payload_end] = 0xaa;

        assert!(
            decode_ciphertext_entries(vec![ciphertext_entry_for_bytes(0, &bytes)]).is_err(),
            "DA ciphertext parser must reject nonzero container padding"
        );
    }

    #[test]
    fn wallet_rpc_page_limit_rejects_oversized_pages_before_decoding() {
        ensure_wallet_page_within_requested_limit("hegemon_walletCommitments", 128, 128)
            .expect("exact page limit is valid");
        ensure_wallet_page_within_requested_limit("hegemon_walletCiphertexts", 0, 0)
            .expect("empty zero-limit response is valid");

        let err = ensure_wallet_page_within_requested_limit("hegemon_walletCiphertexts", 129, 128)
            .expect_err("oversized wallet page must reject");
        assert!(err
            .to_string()
            .contains("hegemon_walletCiphertexts returned 129 entries in one page (limit 128)"));
    }

    #[derive(Debug, Deserialize)]
    struct LeanCiphertextArchiveBoundaryVectorFile {
        schema_version: u32,
        wallet_page_admission_cases: Vec<LeanWalletPageAdmissionCase>,
        wallet_sync_snapshot_admission_cases: Vec<LeanWalletSyncSnapshotAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    struct LeanWalletPageAdmissionCase {
        name: String,
        requested_limit: usize,
        returned_entries: usize,
        expected_valid: bool,
        expected_error: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct LeanWalletSyncSnapshotAdmissionCase {
        name: String,
        expected_depth: u64,
        depth: u64,
        leaf_count: u64,
        next_index: u64,
        commitment_cursor: u64,
        ciphertext_cursor: u64,
        tree_capacity: u128,
        max_snapshot_gap: u64,
        expected_valid: bool,
        expected_error: Option<String>,
    }

    #[test]
    fn lean_generated_wallet_page_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_CIPHERTEXT_ARCHIVE_BOUNDARY_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_CIPHERTEXT_ARCHIVE_BOUNDARY_VECTORS not set; skipping wallet page admission vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean ciphertext archive boundary vectors");
        let vectors: LeanCiphertextArchiveBoundaryVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean wallet page vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.wallet_page_admission_cases.is_empty(),
            "Lean wallet page admission cases must not be empty"
        );
        assert!(
            !vectors.wallet_sync_snapshot_admission_cases.is_empty(),
            "Lean wallet sync snapshot admission cases must not be empty"
        );

        for case in &vectors.wallet_page_admission_cases {
            let actual = ensure_wallet_page_within_requested_limit(
                "hegemon_walletCiphertexts",
                case.returned_entries,
                case.requested_limit,
            );
            assert_eq!(
                actual.is_ok(),
                case.expected_valid,
                "{} wallet page admission validity drifted from Lean spec",
                case.name
            );
            match case.expected_error.as_deref() {
                None => assert!(actual.is_ok(), "{} should be accepted", case.name),
                Some("page_too_large") => assert!(
                    actual
                        .expect_err("oversized Lean page case must reject")
                        .to_string()
                        .contains("returned"),
                    "{} oversized page rejection drifted from production",
                    case.name
                ),
                other => panic!("{} unexpected Lean wallet page error {other:?}", case.name),
            }
        }

        for case in &vectors.wallet_sync_snapshot_admission_cases {
            let actual_error = if case.depth != case.expected_depth {
                Some("depth_mismatch")
            } else if case.tree_capacity < u128::from(case.leaf_count) {
                Some("leaf_count_exceeds_tree_capacity")
            } else if case.tree_capacity < u128::from(case.next_index) {
                Some("ciphertext_index_exceeds_tree_capacity")
            } else if case.max_snapshot_gap < case.leaf_count.saturating_sub(case.commitment_cursor)
            {
                Some("commitment_snapshot_too_large")
            } else if case.max_snapshot_gap < case.next_index.saturating_sub(case.ciphertext_cursor)
            {
                Some("ciphertext_snapshot_too_large")
            } else {
                None
            };
            assert_eq!(
                actual_error.is_none(),
                case.expected_valid,
                "{} wallet sync snapshot admission validity drifted from Lean spec",
                case.name
            );
            assert_eq!(
                actual_error,
                case.expected_error.as_deref(),
                "{} wallet sync snapshot admission rejection drifted from Lean spec",
                case.name
            );
        }
    }

    #[test]
    fn test_sidecar_submit_action_request_roundtrip() {
        let args = protocol_shielded_pool::family::ShieldedTransferSidecarArgs {
            proof: Vec::new(),
            commitments: vec![[0x11u8; 48]],
            ciphertext_hashes: vec![[0x22u8; 48]],
            ciphertext_sizes: vec![1234],
            anchor: [0x33u8; 48],
            balance_slot_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
            binding_hash: [0x44u8; 64],
            stablecoin: None,
            fee: 7,
        };
        let envelope = build_shielded_envelope(
            protocol_versioning::DEFAULT_VERSION_BINDING,
            protocol_shielded_pool::family::ACTION_SHIELDED_TRANSFER_SIDECAR,
            vec![[0x55u8; 48]],
            args.encode(),
        );
        let request = SubmitActionRequest::from_envelope(&envelope).expect("request");
        let public_args = base64::engine::general_purpose::STANDARD
            .decode(request.public_args)
            .expect("public args decode");
        let decoded = protocol_shielded_pool::family::ShieldedTransferSidecarArgs::decode(
            &mut &public_args[..],
        )
        .expect("sidecar args decode");
        assert_eq!(decoded, args);
    }
}
