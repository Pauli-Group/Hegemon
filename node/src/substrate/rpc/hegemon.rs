//! Hegemon Core RPC Endpoints
//!
//! This module provides the core Hegemon-specific RPC endpoints for:
//! - Mining control (start, stop, status)
//! - Consensus status and metrics
//! - Node telemetry
//!
//! # RPC Methods
//!
//! | Method                    | Description                              |
//! |---------------------------|------------------------------------------|
//! | `hegemon_miningStatus`    | Get current mining status                |
//! | `hegemon_startMining`     | Start mining with specified threads      |
//! | `hegemon_stopMining`      | Stop mining                              |
//! | `hegemon_consensusStatus` | Get consensus layer status               |
//! | `hegemon_telemetry`       | Get node telemetry metrics               |
//! | `hegemon_storageFootprint`| Get storage usage statistics             |
//! | `hegemon_nodeConfig`      | Get node config snapshot                 |

use crate::substrate::template_builder::compact_job_from_work;
use consensus::{compute_work, seal_meets_target, MiningSolution, MiningWork, Sha256dSeal};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
use jsonrpsee::types::ErrorObjectOwned;
use parking_lot::Mutex;
use protocol_kernel::types::{ActionEnvelope, AuthorizationBundle, ObjectRef, SignatureEnvelope};
use serde::{Deserialize, Serialize};
use sp_core::H256;
use std::collections::HashMap;
use std::sync::Arc;

/// Mining status response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MiningStatus {
    /// Whether mining is currently active
    pub is_mining: bool,
    /// Number of active mining threads
    pub threads: u32,
    /// Current hash rate (hashes per second)
    pub hash_rate: f64,
    /// Total blocks mined by this node
    pub blocks_found: u64,
    /// Current difficulty target
    pub difficulty: u32,
    /// Current block height
    pub block_height: u64,
}

/// Start mining request parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StartMiningParams {
    /// Number of threads to use for mining (defaults to 1)
    #[serde(default = "default_threads")]
    pub threads: u32,
    /// Optional shared secret for mining-control RPCs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

fn default_threads() -> u32 {
    1
}

/// Optional authentication parameters for mining-control RPCs.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MiningControlAuthParams {
    /// Optional shared secret for mining-control RPCs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

/// Mining control response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MiningControlResponse {
    /// Whether the operation succeeded
    pub success: bool,
    /// Human-readable status message
    pub message: String,
    /// Current mining status after the operation
    pub status: MiningStatus,
}

/// Consensus status response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusStatus {
    /// Current block height
    pub height: u64,
    /// Best block hash (hex-encoded)
    pub best_hash: String,
    /// State root (hex-encoded)
    pub state_root: String,
    /// Nullifier set root (hex-encoded)
    pub nullifier_root: String,
    /// Total supply digest
    pub supply_digest: u128,
    /// Whether the node is syncing
    pub syncing: bool,
    /// Number of connected peers
    pub peers: u32,
}

/// Telemetry snapshot
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Total transactions processed
    pub tx_count: u64,
    /// Total blocks imported
    pub blocks_imported: u64,
    /// Blocks mined (if mining)
    pub blocks_mined: u64,
    /// Current memory usage in bytes
    pub memory_bytes: u64,
    /// Network bytes received
    pub network_rx_bytes: u64,
    /// Network bytes sent
    pub network_tx_bytes: u64,
}

/// Connected peer detail snapshot (PQ network)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerDetail {
    /// Peer identifier (hex-encoded)
    pub peer_id: String,
    /// Observed socket address
    pub address: String,
    /// Connection direction ("inbound" or "outbound")
    pub direction: String,
    /// Peer's reported best height
    pub best_height: u64,
    /// Peer's reported best hash (hex-encoded)
    pub best_hash: String,
    /// Seconds since we last heard from the peer
    pub last_seen_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerGraphPeer {
    pub peer_id: String,
    pub address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerGraphReportSnapshot {
    pub reporter_peer_id: String,
    pub reporter_address: String,
    pub reported_at_secs: u64,
    pub peers: Vec<PeerGraphPeer>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerGraphSnapshot {
    pub local_peer_id: String,
    pub peers: Vec<PeerDetail>,
    pub reports: Vec<PeerGraphReportSnapshot>,
}

/// Storage footprint response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageFootprint {
    /// Total database size in bytes
    pub total_bytes: u64,
    /// Block storage size
    pub blocks_bytes: u64,
    /// State storage size
    pub state_bytes: u64,
    /// Transaction storage size
    pub transactions_bytes: u64,
    /// Nullifier set size
    pub nullifiers_bytes: u64,
}

/// Block timestamp response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockTimestamp {
    /// Block height
    pub height: u64,
    /// Timestamp in milliseconds since epoch (None if not present)
    pub timestamp_ms: Option<u64>,
}

/// Node config snapshot
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeConfigSnapshot {
    /// Node name (if configured)
    pub node_name: String,
    /// Chain spec identifier
    pub chain_spec_id: String,
    /// Chain spec name
    pub chain_spec_name: String,
    /// Chain type (dev, local, live, custom)
    pub chain_type: String,
    /// Base path for node data
    pub base_path: String,
    /// P2P listen address
    pub p2p_listen_addr: String,
    /// RPC listen address
    pub rpc_listen_addr: String,
    /// RPC methods setting (safe/unsafe/auto)
    pub rpc_methods: String,
    /// Whether RPC is exposed beyond localhost
    pub rpc_external: bool,
    /// PQ bootstrap nodes (ip:port)
    pub bootstrap_nodes: Vec<String>,
    /// PQ handshake verbose logging enabled
    pub pq_verbose: bool,
    /// Maximum peers allowed
    pub max_peers: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionObjectRefRequest {
    pub family_id: u16,
    pub object_id: String,
    pub expected_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionSignatureRequest {
    pub key_id: String,
    pub signature_scheme: u16,
    pub signature_bytes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitActionRequest {
    pub binding_circuit: u16,
    pub binding_crypto: u16,
    pub family_id: u16,
    pub action_id: u16,
    #[serde(default)]
    pub object_refs: Vec<ActionObjectRefRequest>,
    #[serde(default)]
    pub new_nullifiers: Vec<String>,
    pub public_args: String,
    #[serde(default)]
    pub authorization_proof: Option<String>,
    #[serde(default)]
    pub authorization_signatures: Vec<ActionSignatureRequest>,
    #[serde(default)]
    pub aux_data: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitActionResponse {
    pub success: bool,
    pub tx_hash: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PoolAuthParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolWorkResponse {
    pub available: bool,
    pub height: Option<u64>,
    pub pre_hash: Option<String>,
    pub parent_hash: Option<String>,
    pub network_difficulty: Option<u32>,
    pub share_difficulty: Option<u32>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactJobResponse {
    pub available: bool,
    pub job_id: Option<String>,
    pub height: Option<u64>,
    pub pre_hash: Option<String>,
    pub parent_hash: Option<String>,
    pub network_bits: Option<u32>,
    pub share_bits: Option<u32>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitPoolShareRequest {
    pub worker_name: String,
    pub nonce: String,
    pub pre_hash: String,
    pub parent_hash: String,
    pub height: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitCompactSolutionRequest {
    pub worker_name: String,
    pub job_id: String,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitPoolShareResponse {
    pub accepted: bool,
    pub block_candidate: bool,
    pub network_target_met: bool,
    pub error: Option<String>,
    pub accepted_shares: u64,
    pub rejected_shares: u64,
    pub worker_accepted_shares: u64,
    pub worker_rejected_shares: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolStatusResponse {
    pub available: bool,
    pub network_difficulty: Option<u32>,
    pub share_difficulty: Option<u32>,
    pub accepted_shares: u64,
    pub rejected_shares: u64,
    pub worker_count: usize,
    pub workers: Vec<PoolWorkerStatusEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolWorkerStatusEntry {
    pub worker_name: String,
    pub accepted_shares: u64,
    pub rejected_shares: u64,
    pub block_candidates: u64,
    pub payout_fraction_ppm: u64,
    pub last_share_at_ms: Option<u64>,
}

#[derive(Default)]
struct WorkerShareStats {
    accepted: u64,
    rejected: u64,
    block_candidates: u64,
    last_share_at_ms: Option<u64>,
}

#[derive(Default)]
struct PoolShareStats {
    accepted: u64,
    rejected: u64,
    workers: HashMap<String, WorkerShareStats>,
}

/// Hegemon RPC API trait definition
///
/// This trait defines all the custom RPC endpoints for the Hegemon node.
/// It uses jsonrpsee proc macros to generate the server implementation.
#[rpc(server, client, namespace = "hegemon")]
pub trait HegemonApi {
    /// Get current mining status
    ///
    /// Returns information about the node's mining activity including
    /// whether mining is active, thread count, hash rate, and blocks found.
    #[method(name = "miningStatus")]
    async fn mining_status(&self) -> RpcResult<MiningStatus>;

    /// Start mining
    ///
    /// Activates the mining worker with the specified number of threads.
    /// If mining is already active, returns success with current status.
    ///
    /// # Parameters
    /// - `params`: Optional parameters including thread count
    #[method(name = "startMining")]
    async fn start_mining(
        &self,
        params: Option<StartMiningParams>,
    ) -> RpcResult<MiningControlResponse>;

    /// Stop mining
    ///
    /// Deactivates the mining worker and stops all mining threads.
    #[method(name = "stopMining")]
    async fn stop_mining(
        &self,
        params: Option<MiningControlAuthParams>,
    ) -> RpcResult<MiningControlResponse>;

    /// Get consensus status
    ///
    /// Returns the current consensus layer state including block height,
    /// best block hash, sync status, and peer count.
    #[method(name = "consensusStatus")]
    async fn consensus_status(&self) -> RpcResult<ConsensusStatus>;

    /// Get telemetry snapshot
    ///
    /// Returns current telemetry metrics for the node including
    /// uptime, transaction count, memory usage, and network statistics.
    #[method(name = "telemetry")]
    async fn telemetry(&self) -> RpcResult<TelemetrySnapshot>;

    /// Get storage footprint
    ///
    /// Returns storage usage statistics for different components
    /// of the node's persistent storage.
    #[method(name = "storageFootprint")]
    async fn storage_footprint(&self) -> RpcResult<StorageFootprint>;

    /// Get node configuration snapshot
    ///
    /// Returns the effective node configuration the process is running with,
    /// including chain spec identity, base path, listen addresses, and PQ settings.
    #[method(name = "nodeConfig")]
    async fn node_config(&self) -> RpcResult<NodeConfigSnapshot>;

    /// Get block timestamps for a height range (inclusive).
    ///
    /// Returns an entry for each block height in the range. Timestamps are
    /// extracted from the timestamp inherent when present.
    #[method(name = "blockTimestamps")]
    async fn block_timestamps(&self, start: u64, end: u64) -> RpcResult<Vec<BlockTimestamp>>;

    /// Get timestamps for blocks mined by this node.
    #[method(name = "minedBlockTimestamps")]
    async fn mined_block_timestamps(&self) -> RpcResult<Vec<BlockTimestamp>>;

    /// Get connected peer details (PQ network snapshot).
    #[method(name = "peerList")]
    async fn peer_list(&self) -> RpcResult<Vec<PeerDetail>>;

    /// Get peer graph details (direct peers + reported peers).
    #[method(name = "peerGraph")]
    async fn peer_graph(&self) -> RpcResult<PeerGraphSnapshot>;

    /// Submit a kernel action envelope.
    #[method(name = "submitAction")]
    async fn submit_action(&self, request: SubmitActionRequest) -> RpcResult<SubmitActionResponse>;

    /// Get the current authoring work template for pool workers.
    #[method(name = "poolWork")]
    async fn pool_work(&self, params: Option<PoolAuthParams>) -> RpcResult<PoolWorkResponse>;

    /// Get the current compact mining job.
    #[method(name = "compactJob")]
    async fn compact_job(&self, params: Option<PoolAuthParams>) -> RpcResult<CompactJobResponse>;

    /// Submit a pool share or full-target solution for the current template.
    #[method(name = "submitPoolShare")]
    async fn submit_pool_share(
        &self,
        request: SubmitPoolShareRequest,
    ) -> RpcResult<SubmitPoolShareResponse>;

    /// Submit a compact-job solution using an explicit `job_id` and 32-byte nonce.
    #[method(name = "submitCompactSolution")]
    async fn submit_compact_solution(
        &self,
        request: SubmitCompactSolutionRequest,
    ) -> RpcResult<SubmitPoolShareResponse>;

    /// Get aggregate share status for the current process.
    #[method(name = "poolStatus")]
    async fn pool_status(&self, params: Option<PoolAuthParams>) -> RpcResult<PoolStatusResponse>;
}

/// Trait for mining handle operations
///
/// This trait abstracts the mining coordinator to allow for testing
/// and different implementations.
pub trait MiningHandle: Send + Sync {
    /// Check if mining is currently active
    fn is_mining(&self) -> bool;
    /// Start mining with specified thread count
    fn start_mining(&self, threads: u32);
    /// Stop mining
    fn stop_mining(&self);
    /// Get current hash rate
    fn hashrate(&self) -> f64;
    /// Get number of blocks found
    fn blocks_found(&self) -> u64;
    /// Get thread count
    fn thread_count(&self) -> u32;
    /// Snapshot the current work template, if one exists.
    fn current_work(&self) -> Option<MiningWork>;
    /// Submit an externally discovered solution.
    fn submit_solution(&self, solution: MiningSolution) -> Result<(), String>;
}

/// Trait for node service operations
///
/// This trait abstracts the node service to allow for testing
/// and different implementations.
pub trait HegemonService: Send + Sync {
    /// Get current consensus status
    fn consensus_status(&self) -> ConsensusStatus;
    /// Get telemetry snapshot
    fn telemetry_snapshot(&self) -> TelemetrySnapshot;
    /// Get storage footprint
    fn storage_footprint(&self) -> Result<StorageFootprint, String>;
    /// Get current difficulty
    fn current_difficulty(&self) -> u32;
    /// Get current block height
    fn current_height(&self) -> u64;
    /// Get block timestamps for a height range (inclusive).
    fn block_timestamps(&self, start: u64, end: u64) -> Result<Vec<BlockTimestamp>, String>;
    /// Get timestamps for blocks mined by this node.
    fn mined_block_timestamps(&self) -> Result<Vec<BlockTimestamp>, String>;
    /// Get connected peer details (PQ network snapshot).
    fn peer_list(&self) -> Vec<PeerDetail>;
    /// Get peer graph details (direct peers + reported peers).
    fn peer_graph(&self) -> PeerGraphSnapshot;
    /// Submit a generic kernel action.
    fn submit_action(&self, envelope: ActionEnvelope) -> Result<[u8; 32], String>;
}

/// Hegemon RPC implementation
pub struct HegemonRpc<S, P> {
    service: Arc<S>,
    pow_handle: P,
    config_snapshot: NodeConfigSnapshot,
    deny_unsafe: sc_rpc::DenyUnsafe,
    mining_control_auth_token: Option<String>,
    pool_auth_token: Option<String>,
    legacy_pool_rpc_enabled: bool,
    pool_share_stats: Arc<Mutex<PoolShareStats>>,
}

impl<S, P> HegemonRpc<S, P>
where
    S: HegemonService + Send + Sync + 'static,
    P: MiningHandle + Clone + Send + Sync + 'static,
{
    /// Create a new Hegemon RPC handler
    pub fn new(
        service: Arc<S>,
        pow_handle: P,
        config_snapshot: NodeConfigSnapshot,
        deny_unsafe: sc_rpc::DenyUnsafe,
    ) -> Self {
        let mining_control_auth_token = std::env::var("HEGEMON_MINING_RPC_TOKEN")
            .ok()
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty());
        let pool_auth_token = std::env::var("HEGEMON_POOL_RPC_TOKEN")
            .ok()
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty());
        let legacy_pool_rpc_enabled = std::env::var("HEGEMON_ENABLE_LEGACY_POOL_RPC")
            .map(|raw| raw == "1" || raw.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self {
            service,
            pow_handle,
            config_snapshot,
            deny_unsafe,
            mining_control_auth_token,
            pool_auth_token,
            legacy_pool_rpc_enabled,
            pool_share_stats: Arc::new(Mutex::new(PoolShareStats::default())),
        }
    }

    fn ensure_mining_control_allowed(&self, provided_token: Option<&str>) -> RpcResult<()> {
        if matches!(self.deny_unsafe, sc_rpc::DenyUnsafe::Yes) {
            return Err(ErrorObjectOwned::owned(
                INVALID_PARAMS_CODE,
                "mining control RPC is unsafe; run node with --rpc-methods=unsafe to enable",
                None::<()>,
            ));
        }

        if let Some(expected) = self.mining_control_auth_token.as_deref() {
            let provided = provided_token.unwrap_or_default().trim();
            if provided.is_empty() || provided != expected {
                return Err(ErrorObjectOwned::owned(
                    INVALID_PARAMS_CODE,
                    "invalid or missing mining control auth token",
                    None::<()>,
                ));
            }
        }

        Ok(())
    }

    fn ensure_pool_access_allowed(&self, provided_token: Option<&str>) -> RpcResult<()> {
        if let Some(expected) = self.pool_auth_token.as_deref() {
            let provided = provided_token.unwrap_or_default().trim();
            if provided.is_empty() || provided != expected {
                return Err(ErrorObjectOwned::owned(
                    INVALID_PARAMS_CODE,
                    "invalid or missing pool auth token",
                    None::<()>,
                ));
            }
        }

        Ok(())
    }

    fn ensure_legacy_pool_rpc_enabled(&self) -> RpcResult<()> {
        if self.legacy_pool_rpc_enabled {
            return Ok(());
        }
        Err(ErrorObjectOwned::owned(
            INVALID_PARAMS_CODE,
            "legacy pool RPC is disabled; use hegemon_compactJob/hegemon_submitCompactSolution or set HEGEMON_ENABLE_LEGACY_POOL_RPC=1",
            None::<()>,
        ))
    }

    fn pool_share_bits_for_work(&self, work: &MiningWork) -> u32 {
        std::env::var("HEGEMON_POOL_SHARE_BITS")
            .ok()
            .and_then(|raw| {
                let trimmed = raw.trim();
                if let Some(hex) = trimmed.strip_prefix("0x") {
                    u32::from_str_radix(hex, 16).ok()
                } else {
                    trimmed.parse::<u32>().ok()
                }
            })
            .filter(|bits| *bits != 0)
            .unwrap_or(work.pow_bits)
    }

    fn submit_share_for_work(
        &self,
        worker_name: &str,
        work: &MiningWork,
        nonce: [u8; 32],
    ) -> RpcResult<SubmitPoolShareResponse> {
        let seal = Sha256dSeal {
            nonce,
            difficulty: work.pow_bits,
            work: compute_work(&work.pre_hash, nonce),
        };
        let share_bits = self.pool_share_bits_for_work(work);
        let share_target_met = seal_meets_target(&seal.work, share_bits);
        let network_target_met = seal_meets_target(&seal.work, work.pow_bits);

        let mut stats = self.pool_share_stats.lock();
        if !share_target_met {
            stats.rejected = stats.rejected.saturating_add(1);
            let (worker_accepted_shares, worker_rejected_shares) = {
                let worker_stats = stats.workers.entry(worker_name.to_string()).or_default();
                worker_stats.rejected = worker_stats.rejected.saturating_add(1);
                worker_stats.last_share_at_ms = Some(current_time_ms());
                (worker_stats.accepted, worker_stats.rejected)
            };
            let accepted_shares = stats.accepted;
            let rejected_shares = stats.rejected;
            return Ok(SubmitPoolShareResponse {
                accepted: false,
                block_candidate: false,
                network_target_met: false,
                error: Some("share does not meet configured pool target".to_string()),
                accepted_shares,
                rejected_shares,
                worker_accepted_shares,
                worker_rejected_shares,
            });
        }

        stats.accepted = stats.accepted.saturating_add(1);
        let (worker_accepted_shares, worker_rejected_shares) = {
            let worker_stats = stats.workers.entry(worker_name.to_string()).or_default();
            worker_stats.accepted = worker_stats.accepted.saturating_add(1);
            if network_target_met {
                worker_stats.block_candidates = worker_stats.block_candidates.saturating_add(1);
            }
            worker_stats.last_share_at_ms = Some(current_time_ms());
            (worker_stats.accepted, worker_stats.rejected)
        };
        let accepted_shares = stats.accepted;
        let rejected_shares = stats.rejected;
        drop(stats);

        if network_target_met {
            let solution = MiningSolution {
                seal,
                work: work.clone(),
            };
            self.pow_handle.submit_solution(solution).map_err(|err| {
                ErrorObjectOwned::owned(
                    jsonrpsee::types::error::INTERNAL_ERROR_CODE,
                    format!("failed to forward full-difficulty solution: {err}"),
                    None::<()>,
                )
            })?;
        }

        Ok(SubmitPoolShareResponse {
            accepted: true,
            block_candidate: network_target_met,
            network_target_met,
            error: None,
            accepted_shares,
            rejected_shares,
            worker_accepted_shares,
            worker_rejected_shares,
        })
    }
}

#[jsonrpsee::core::async_trait]
impl<S, P> HegemonApiServer for HegemonRpc<S, P>
where
    S: HegemonService + Send + Sync + 'static,
    P: MiningHandle + Clone + Send + Sync + 'static,
{
    async fn mining_status(&self) -> RpcResult<MiningStatus> {
        Ok(MiningStatus {
            is_mining: self.pow_handle.is_mining(),
            threads: self.pow_handle.thread_count(),
            hash_rate: self.pow_handle.hashrate(),
            blocks_found: self.pow_handle.blocks_found(),
            difficulty: self.service.current_difficulty(),
            block_height: self.service.current_height(),
        })
    }

    async fn start_mining(
        &self,
        params: Option<StartMiningParams>,
    ) -> RpcResult<MiningControlResponse> {
        let (threads, auth_token) = params
            .map(|p| (p.threads, p.auth_token))
            .unwrap_or((1, None));
        self.ensure_mining_control_allowed(auth_token.as_deref())?;

        self.pow_handle.start_mining(threads);

        let status = MiningStatus {
            is_mining: self.pow_handle.is_mining(),
            threads: self.pow_handle.thread_count(),
            hash_rate: self.pow_handle.hashrate(),
            blocks_found: self.pow_handle.blocks_found(),
            difficulty: self.service.current_difficulty(),
            block_height: self.service.current_height(),
        };

        Ok(MiningControlResponse {
            success: true,
            message: format!("Mining started with {} thread(s)", threads),
            status,
        })
    }

    async fn stop_mining(
        &self,
        params: Option<MiningControlAuthParams>,
    ) -> RpcResult<MiningControlResponse> {
        self.ensure_mining_control_allowed(
            params
                .as_ref()
                .and_then(|value| value.auth_token.as_deref()),
        )?;
        self.pow_handle.stop_mining();

        let status = MiningStatus {
            is_mining: self.pow_handle.is_mining(),
            threads: self.pow_handle.thread_count(),
            hash_rate: self.pow_handle.hashrate(),
            blocks_found: self.pow_handle.blocks_found(),
            difficulty: self.service.current_difficulty(),
            block_height: self.service.current_height(),
        };

        Ok(MiningControlResponse {
            success: true,
            message: "Mining stopped".to_string(),
            status,
        })
    }

    async fn consensus_status(&self) -> RpcResult<ConsensusStatus> {
        Ok(self.service.consensus_status())
    }

    async fn telemetry(&self) -> RpcResult<TelemetrySnapshot> {
        Ok(self.service.telemetry_snapshot())
    }

    async fn storage_footprint(&self) -> RpcResult<StorageFootprint> {
        self.service.storage_footprint().map_err(|e| {
            ErrorObjectOwned::owned(jsonrpsee::types::error::INTERNAL_ERROR_CODE, e, None::<()>)
        })
    }

    async fn node_config(&self) -> RpcResult<NodeConfigSnapshot> {
        Ok(self.config_snapshot.clone())
    }

    async fn block_timestamps(&self, start: u64, end: u64) -> RpcResult<Vec<BlockTimestamp>> {
        self.service.block_timestamps(start, end).map_err(|e| {
            ErrorObjectOwned::owned(jsonrpsee::types::error::INTERNAL_ERROR_CODE, e, None::<()>)
        })
    }

    async fn mined_block_timestamps(&self) -> RpcResult<Vec<BlockTimestamp>> {
        self.service.mined_block_timestamps().map_err(|e| {
            ErrorObjectOwned::owned(jsonrpsee::types::error::INTERNAL_ERROR_CODE, e, None::<()>)
        })
    }

    async fn peer_list(&self) -> RpcResult<Vec<PeerDetail>> {
        Ok(self.service.peer_list())
    }

    async fn peer_graph(&self) -> RpcResult<PeerGraphSnapshot> {
        Ok(self.service.peer_graph())
    }

    async fn submit_action(&self, request: SubmitActionRequest) -> RpcResult<SubmitActionResponse> {
        let object_refs = request
            .object_refs
            .into_iter()
            .map(|item| {
                Ok(ObjectRef {
                    family_id: item.family_id,
                    object_id: hex_to_array32(&item.object_id)?,
                    expected_root: hex_to_array48(&item.expected_root)?,
                })
            })
            .collect::<Result<Vec<_>, String>>();
        let object_refs = match object_refs {
            Ok(value) => value,
            Err(err) => {
                return Ok(SubmitActionResponse {
                    success: false,
                    tx_hash: None,
                    error: Some(err),
                })
            }
        };

        let new_nullifiers = request
            .new_nullifiers
            .into_iter()
            .map(|value| hex_to_array48(&value))
            .collect::<Result<Vec<_>, _>>();
        let new_nullifiers = match new_nullifiers {
            Ok(value) => value,
            Err(err) => {
                return Ok(SubmitActionResponse {
                    success: false,
                    tx_hash: None,
                    error: Some(err),
                })
            }
        };

        let public_args = match base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &request.public_args,
        ) {
            Ok(value) => value,
            Err(err) => {
                return Ok(SubmitActionResponse {
                    success: false,
                    tx_hash: None,
                    error: Some(format!("invalid public_args encoding: {err}")),
                })
            }
        };

        let proof_bytes = match request.authorization_proof {
            Some(value) => {
                match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &value) {
                    Ok(decoded) => decoded,
                    Err(err) => {
                        return Ok(SubmitActionResponse {
                            success: false,
                            tx_hash: None,
                            error: Some(format!("invalid authorization_proof encoding: {err}")),
                        })
                    }
                }
            }
            None => Vec::new(),
        };

        let signatures = request
            .authorization_signatures
            .into_iter()
            .map(|sig| {
                Ok(SignatureEnvelope {
                    key_id: hex_to_array32(&sig.key_id)?,
                    signature_scheme: sig.signature_scheme,
                    signature_bytes: base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        &sig.signature_bytes,
                    )
                    .map_err(|e| format!("invalid signature_bytes encoding: {e}"))?,
                })
            })
            .collect::<Result<Vec<_>, String>>();
        let signatures = match signatures {
            Ok(value) => value,
            Err(err) => {
                return Ok(SubmitActionResponse {
                    success: false,
                    tx_hash: None,
                    error: Some(err),
                })
            }
        };

        let aux_data = match request.aux_data {
            Some(value) => {
                match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &value) {
                    Ok(decoded) => decoded,
                    Err(err) => {
                        return Ok(SubmitActionResponse {
                            success: false,
                            tx_hash: None,
                            error: Some(format!("invalid aux_data encoding: {err}")),
                        })
                    }
                }
            }
            None => Vec::new(),
        };

        let envelope = ActionEnvelope {
            binding: protocol_kernel::types::KernelVersionBinding {
                circuit: request.binding_circuit,
                crypto: request.binding_crypto,
            },
            family_id: request.family_id,
            action_id: request.action_id,
            object_refs,
            new_nullifiers,
            public_args,
            authorization: AuthorizationBundle {
                proof_bytes,
                signatures,
            },
            aux_data,
        };

        match self.service.submit_action(envelope) {
            Ok(tx_hash) => Ok(SubmitActionResponse {
                success: true,
                tx_hash: Some(format!("0x{}", hex::encode(tx_hash))),
                error: None,
            }),
            Err(err) => Ok(SubmitActionResponse {
                success: false,
                tx_hash: None,
                error: Some(err),
            }),
        }
    }

    async fn pool_work(&self, params: Option<PoolAuthParams>) -> RpcResult<PoolWorkResponse> {
        self.ensure_legacy_pool_rpc_enabled()?;
        self.ensure_pool_access_allowed(
            params
                .as_ref()
                .and_then(|value| value.auth_token.as_deref()),
        )?;

        let Some(work) = self.pow_handle.current_work() else {
            return Ok(PoolWorkResponse {
                available: false,
                height: None,
                pre_hash: None,
                parent_hash: None,
                network_difficulty: None,
                share_difficulty: None,
                reason: Some("no active mining work template".to_string()),
            });
        };

        Ok(PoolWorkResponse {
            available: true,
            height: Some(work.height),
            pre_hash: Some(format!("0x{}", hex::encode(work.pre_hash.as_bytes()))),
            parent_hash: Some(format!("0x{}", hex::encode(work.parent_hash.as_bytes()))),
            network_difficulty: Some(work.pow_bits),
            share_difficulty: Some(self.pool_share_bits_for_work(&work)),
            reason: None,
        })
    }

    async fn compact_job(&self, params: Option<PoolAuthParams>) -> RpcResult<CompactJobResponse> {
        self.ensure_pool_access_allowed(
            params
                .as_ref()
                .and_then(|value| value.auth_token.as_deref()),
        )?;

        let Some(work) = self.pow_handle.current_work() else {
            return Ok(CompactJobResponse {
                available: false,
                job_id: None,
                height: None,
                pre_hash: None,
                parent_hash: None,
                network_bits: None,
                share_bits: None,
                reason: Some("no active mining work template".to_string()),
            });
        };

        let job = compact_job_from_work(&work, self.pool_share_bits_for_work(&work));
        Ok(CompactJobResponse {
            available: true,
            job_id: Some(format!("0x{}", hex::encode(job.job_id))),
            height: Some(job.height),
            pre_hash: Some(format!("0x{}", hex::encode(job.pre_hash.as_bytes()))),
            parent_hash: Some(format!("0x{}", hex::encode(job.parent_hash.as_bytes()))),
            network_bits: Some(job.network_bits),
            share_bits: Some(job.share_bits),
            reason: None,
        })
    }

    async fn submit_pool_share(
        &self,
        request: SubmitPoolShareRequest,
    ) -> RpcResult<SubmitPoolShareResponse> {
        self.ensure_legacy_pool_rpc_enabled()?;
        self.ensure_pool_access_allowed(request.auth_token.as_deref())?;

        let worker_name = request.worker_name.trim();
        if worker_name.is_empty() {
            return Err(ErrorObjectOwned::owned(
                INVALID_PARAMS_CODE,
                "worker_name is required",
                None::<()>,
            ));
        }

        let Some(work) = self.pow_handle.current_work() else {
            return Ok(SubmitPoolShareResponse {
                accepted: false,
                block_candidate: false,
                network_target_met: false,
                error: Some("no active mining work template".to_string()),
                accepted_shares: 0,
                rejected_shares: 0,
                worker_accepted_shares: 0,
                worker_rejected_shares: 0,
            });
        };

        let requested_pre_hash = H256::from(
            hex_to_array32(&request.pre_hash)
                .map_err(|err| ErrorObjectOwned::owned(INVALID_PARAMS_CODE, err, None::<()>))?,
        );
        let requested_parent_hash = H256::from(
            hex_to_array32(&request.parent_hash)
                .map_err(|err| ErrorObjectOwned::owned(INVALID_PARAMS_CODE, err, None::<()>))?,
        );
        if request.height != work.height
            || requested_pre_hash != work.pre_hash
            || requested_parent_hash != work.parent_hash
        {
            let mut stats = self.pool_share_stats.lock();
            stats.rejected = stats.rejected.saturating_add(1);
            let (worker_accepted_shares, worker_rejected_shares) = {
                let worker_stats = stats.workers.entry(worker_name.to_string()).or_default();
                worker_stats.rejected = worker_stats.rejected.saturating_add(1);
                worker_stats.last_share_at_ms = Some(current_time_ms());
                (worker_stats.accepted, worker_stats.rejected)
            };
            let accepted_shares = stats.accepted;
            let rejected_shares = stats.rejected;
            return Ok(SubmitPoolShareResponse {
                accepted: false,
                block_candidate: false,
                network_target_met: false,
                error: Some("stale or mismatched work submission".to_string()),
                accepted_shares,
                rejected_shares,
                worker_accepted_shares,
                worker_rejected_shares,
            });
        }

        let nonce = hex_to_array32(&request.nonce)
            .map_err(|err| ErrorObjectOwned::owned(INVALID_PARAMS_CODE, err, None::<()>))?;
        self.submit_share_for_work(worker_name, &work, nonce)
    }

    async fn submit_compact_solution(
        &self,
        request: SubmitCompactSolutionRequest,
    ) -> RpcResult<SubmitPoolShareResponse> {
        self.ensure_pool_access_allowed(request.auth_token.as_deref())?;

        let worker_name = request.worker_name.trim();
        if worker_name.is_empty() {
            return Err(ErrorObjectOwned::owned(
                INVALID_PARAMS_CODE,
                "worker_name is required",
                None::<()>,
            ));
        }

        let Some(work) = self.pow_handle.current_work() else {
            return Ok(SubmitPoolShareResponse {
                accepted: false,
                block_candidate: false,
                network_target_met: false,
                error: Some("no active mining work template".to_string()),
                accepted_shares: 0,
                rejected_shares: 0,
                worker_accepted_shares: 0,
                worker_rejected_shares: 0,
            });
        };

        let job = compact_job_from_work(&work, self.pool_share_bits_for_work(&work));
        let requested_job_id = hex_to_array32(&request.job_id)
            .map_err(|err| ErrorObjectOwned::owned(INVALID_PARAMS_CODE, err, None::<()>))?;
        if requested_job_id != job.job_id {
            return Ok(SubmitPoolShareResponse {
                accepted: false,
                block_candidate: false,
                network_target_met: false,
                error: Some("stale or mismatched compact job".to_string()),
                accepted_shares: self.pool_share_stats.lock().accepted,
                rejected_shares: self.pool_share_stats.lock().rejected,
                worker_accepted_shares: 0,
                worker_rejected_shares: 0,
            });
        }

        let nonce = hex_to_array32(&request.nonce)
            .map_err(|err| ErrorObjectOwned::owned(INVALID_PARAMS_CODE, err, None::<()>))?;
        self.submit_share_for_work(worker_name, &work, nonce)
    }

    async fn pool_status(&self, params: Option<PoolAuthParams>) -> RpcResult<PoolStatusResponse> {
        self.ensure_legacy_pool_rpc_enabled()?;
        self.ensure_pool_access_allowed(
            params
                .as_ref()
                .and_then(|value| value.auth_token.as_deref()),
        )?;

        let current_work = self.pow_handle.current_work();
        let stats = self.pool_share_stats.lock();
        let accepted_total = stats.accepted.max(1);
        let mut workers = stats
            .workers
            .iter()
            .map(|(worker_name, worker)| PoolWorkerStatusEntry {
                worker_name: worker_name.clone(),
                accepted_shares: worker.accepted,
                rejected_shares: worker.rejected,
                block_candidates: worker.block_candidates,
                payout_fraction_ppm: ((worker.accepted as u128) * 1_000_000u128
                    / accepted_total as u128) as u64,
                last_share_at_ms: worker.last_share_at_ms,
            })
            .collect::<Vec<_>>();
        workers.sort_by(|left, right| {
            right
                .accepted_shares
                .cmp(&left.accepted_shares)
                .then_with(|| left.worker_name.cmp(&right.worker_name))
        });
        Ok(PoolStatusResponse {
            available: current_work.is_some(),
            network_difficulty: current_work.as_ref().map(|work| work.pow_bits),
            share_difficulty: current_work
                .as_ref()
                .map(|work| self.pool_share_bits_for_work(work)),
            accepted_shares: stats.accepted,
            rejected_shares: stats.rejected,
            worker_count: stats.workers.len(),
            workers,
        })
    }
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn hex_to_array32(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value.trim_start_matches("0x")).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_to_array48(value: &str) -> Result<[u8; 48], String> {
    let bytes = hex::decode(value.trim_start_matches("0x")).map_err(|e| e.to_string())?;
    if bytes.len() != 48 {
        return Err(format!("expected 48 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::counter_to_nonce;

    #[derive(Clone)]
    struct MockMiningHandle {
        mining: std::sync::Arc<std::sync::atomic::AtomicBool>,
        threads: u32,
    }

    impl MockMiningHandle {
        fn new() -> Self {
            Self {
                mining: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                threads: 1,
            }
        }
    }

    impl MiningHandle for MockMiningHandle {
        fn is_mining(&self) -> bool {
            self.mining.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn start_mining(&self, _threads: u32) {
            self.mining.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        fn stop_mining(&self) {
            self.mining
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }

        fn hashrate(&self) -> f64 {
            if self.is_mining() {
                1000.0
            } else {
                0.0
            }
        }

        fn blocks_found(&self) -> u64 {
            0
        }

        fn thread_count(&self) -> u32 {
            self.threads
        }

        fn current_work(&self) -> Option<MiningWork> {
            Some(MiningWork {
                pre_hash: H256::repeat_byte(0x11),
                pow_bits: 0x207fffff,
                height: 42,
                parent_hash: H256::repeat_byte(0x22),
            })
        }

        fn submit_solution(&self, _solution: MiningSolution) -> Result<(), String> {
            Ok(())
        }
    }

    struct MockService;

    impl HegemonService for MockService {
        fn consensus_status(&self) -> ConsensusStatus {
            ConsensusStatus {
                height: 100,
                best_hash: "0x1234".to_string(),
                state_root: "0x5678".to_string(),
                nullifier_root: "0x9abc".to_string(),
                supply_digest: 1_000_000,
                syncing: false,
                peers: 5,
            }
        }

        fn telemetry_snapshot(&self) -> TelemetrySnapshot {
            TelemetrySnapshot {
                uptime_secs: 3600,
                tx_count: 1000,
                blocks_imported: 100,
                blocks_mined: 10,
                memory_bytes: 512 * 1024 * 1024,
                network_rx_bytes: 1024 * 1024,
                network_tx_bytes: 512 * 1024,
            }
        }

        fn storage_footprint(&self) -> Result<StorageFootprint, String> {
            Ok(StorageFootprint {
                total_bytes: 1024 * 1024 * 100,
                blocks_bytes: 1024 * 1024 * 50,
                state_bytes: 1024 * 1024 * 30,
                transactions_bytes: 1024 * 1024 * 15,
                nullifiers_bytes: 1024 * 1024 * 5,
            })
        }

        fn current_difficulty(&self) -> u32 {
            0x1d00ffff
        }

        fn current_height(&self) -> u64 {
            100
        }

        fn block_timestamps(&self, start: u64, end: u64) -> Result<Vec<BlockTimestamp>, String> {
            if start > end {
                return Err("start must be <= end".to_string());
            }
            Ok((start..=end)
                .map(|height| BlockTimestamp {
                    height,
                    timestamp_ms: Some(1_700_000_000_000 + height),
                })
                .collect())
        }

        fn mined_block_timestamps(&self) -> Result<Vec<BlockTimestamp>, String> {
            Ok(vec![BlockTimestamp {
                height: 99,
                timestamp_ms: Some(1_700_000_000_123),
            }])
        }

        fn peer_list(&self) -> Vec<PeerDetail> {
            vec![PeerDetail {
                peer_id: "0xdeadbeef".to_string(),
                address: "127.0.0.1:30333".to_string(),
                direction: "outbound".to_string(),
                best_height: 120,
                best_hash: "0xabcdef".to_string(),
                last_seen_secs: 3,
            }]
        }

        fn peer_graph(&self) -> PeerGraphSnapshot {
            PeerGraphSnapshot {
                local_peer_id: "0xlocal".to_string(),
                peers: self.peer_list(),
                reports: vec![PeerGraphReportSnapshot {
                    reporter_peer_id: "0xdeadbeef".to_string(),
                    reporter_address: "127.0.0.1:30333".to_string(),
                    reported_at_secs: 5,
                    peers: vec![PeerGraphPeer {
                        peer_id: "0xbeadfeed".to_string(),
                        address: "10.0.0.5:30333".to_string(),
                    }],
                }],
            }
        }

        fn submit_action(&self, _envelope: ActionEnvelope) -> Result<[u8; 32], String> {
            Ok([0xabu8; 32])
        }
    }

    fn mock_config() -> NodeConfigSnapshot {
        NodeConfigSnapshot {
            node_name: "MockNode".to_string(),
            chain_spec_id: "dev".to_string(),
            chain_spec_name: "Development".to_string(),
            chain_type: "dev".to_string(),
            base_path: "/tmp/hegemon-node".to_string(),
            p2p_listen_addr: "0.0.0.0:30333".to_string(),
            rpc_listen_addr: "127.0.0.1:9944".to_string(),
            rpc_methods: "safe".to_string(),
            rpc_external: false,
            bootstrap_nodes: vec!["1.2.3.4:30333".to_string()],
            pq_verbose: false,
            max_peers: 50,
        }
    }

    #[tokio::test]
    async fn test_mining_status() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle, mock_config(), sc_rpc::DenyUnsafe::No);

        let status = rpc.mining_status().await.unwrap();
        assert!(!status.is_mining);
        assert_eq!(status.block_height, 100);
    }

    #[tokio::test]
    async fn test_start_stop_mining() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle, mock_config(), sc_rpc::DenyUnsafe::No);

        // Start mining
        let result = rpc
            .start_mining(Some(StartMiningParams {
                threads: 2,
                auth_token: None,
            }))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.status.is_mining);

        // Stop mining
        let result = rpc.stop_mining(None).await.unwrap();
        assert!(result.success);
        assert!(!result.status.is_mining);
    }

    #[tokio::test]
    async fn test_consensus_status() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle, mock_config(), sc_rpc::DenyUnsafe::No);

        let status = rpc.consensus_status().await.unwrap();
        assert_eq!(status.height, 100);
        assert!(!status.syncing);
        assert_eq!(status.peers, 5);
    }

    #[tokio::test]
    async fn test_telemetry() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle, mock_config(), sc_rpc::DenyUnsafe::No);

        let snapshot = rpc.telemetry().await.unwrap();
        assert_eq!(snapshot.uptime_secs, 3600);
        assert_eq!(snapshot.tx_count, 1000);
    }

    #[tokio::test]
    async fn test_node_config_snapshot() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle, mock_config(), sc_rpc::DenyUnsafe::No);

        let config = rpc.node_config().await.unwrap();
        assert_eq!(config.node_name, "MockNode");
        assert_eq!(config.chain_spec_id, "dev");
        assert_eq!(config.rpc_methods, "safe");
        assert!(!config.rpc_external);
        assert_eq!(config.bootstrap_nodes.len(), 1);
    }

    // ============================================================================
    // Phase 11.7.3: Additional Custom RPC Tests
    // ============================================================================

    #[tokio::test]
    async fn test_storage_footprint() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle, mock_config(), sc_rpc::DenyUnsafe::No);

        let footprint = rpc.storage_footprint().await.unwrap();
        assert_eq!(footprint.total_bytes, 1024 * 1024 * 100);
        assert_eq!(footprint.blocks_bytes, 1024 * 1024 * 50);
        assert_eq!(footprint.state_bytes, 1024 * 1024 * 30);
        assert_eq!(footprint.transactions_bytes, 1024 * 1024 * 15);
        assert_eq!(footprint.nullifiers_bytes, 1024 * 1024 * 5);
    }

    #[tokio::test]
    async fn test_mining_lifecycle() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle, mock_config(), sc_rpc::DenyUnsafe::No);

        // Initial state: not mining
        let status = rpc.mining_status().await.unwrap();
        assert!(!status.is_mining);
        assert_eq!(status.hash_rate, 0.0);

        // Start mining
        let start_result = rpc
            .start_mining(Some(StartMiningParams {
                threads: 4,
                auth_token: None,
            }))
            .await
            .unwrap();
        assert!(start_result.success);
        assert!(start_result.status.is_mining);

        // Status should reflect mining
        let status = rpc.mining_status().await.unwrap();
        assert!(status.is_mining);
        assert!(status.hash_rate > 0.0);

        // Stop mining
        let stop_result = rpc.stop_mining(None).await.unwrap();
        assert!(stop_result.success);
        assert!(!stop_result.status.is_mining);

        // Status should reflect stopped
        let status = rpc.mining_status().await.unwrap();
        assert!(!status.is_mining);
    }

    #[tokio::test]
    async fn test_consensus_status_fields() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle, mock_config(), sc_rpc::DenyUnsafe::No);

        let status = rpc.consensus_status().await.unwrap();

        // Verify all fields are populated
        assert_eq!(status.height, 100);
        assert_eq!(status.best_hash, "0x1234");
        assert_eq!(status.state_root, "0x5678");
        assert_eq!(status.nullifier_root, "0x9abc");
        assert_eq!(status.supply_digest, 1_000_000);
        assert!(!status.syncing);
        assert_eq!(status.peers, 5);
    }

    #[tokio::test]
    async fn test_telemetry_fields() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle, mock_config(), sc_rpc::DenyUnsafe::No);

        let snapshot = rpc.telemetry().await.unwrap();

        // Verify all telemetry fields
        assert_eq!(snapshot.uptime_secs, 3600);
        assert_eq!(snapshot.tx_count, 1000);
        assert_eq!(snapshot.blocks_imported, 100);
        assert_eq!(snapshot.blocks_mined, 10);
        assert_eq!(snapshot.memory_bytes, 512 * 1024 * 1024);
        assert_eq!(snapshot.network_rx_bytes, 1024 * 1024);
        assert_eq!(snapshot.network_tx_bytes, 512 * 1024);
    }

    #[tokio::test]
    async fn test_start_mining_with_default_threads() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle, mock_config(), sc_rpc::DenyUnsafe::No);

        // Start mining with no params (should use default threads)
        let result = rpc.start_mining(None).await.unwrap();
        assert!(result.success);
        assert!(result.status.is_mining);
    }

    #[tokio::test]
    async fn test_start_mining_rejected_when_unsafe_rpc_disabled() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle, mock_config(), sc_rpc::DenyUnsafe::Yes);

        let err = rpc
            .start_mining(None)
            .await
            .expect_err("unsafe mining control should be denied");
        assert!(
            err.message().contains("--rpc-methods=unsafe"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_pool_work_exposes_current_template() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle, mock_config(), sc_rpc::DenyUnsafe::No);

        let work = rpc.pool_work(None).await.unwrap();
        assert!(work.available);
        assert_eq!(work.height, Some(42));
        assert_eq!(work.network_difficulty, Some(0x207fffff));
        assert_eq!(work.share_difficulty, Some(0x207fffff));
    }

    #[tokio::test]
    async fn test_compact_job_exposes_current_template() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle, mock_config(), sc_rpc::DenyUnsafe::No);

        let job = rpc.compact_job(None).await.unwrap();
        assert!(job.available);
        assert!(job.job_id.is_some());
        assert_eq!(job.height, Some(42));
        assert_eq!(job.network_bits, Some(0x207fffff));
        assert_eq!(job.share_bits, Some(0x207fffff));
    }

    #[tokio::test]
    async fn test_submit_pool_share_accepts_full_target_solution() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(
            service,
            handle.clone(),
            mock_config(),
            sc_rpc::DenyUnsafe::No,
        );
        let work = handle.current_work().expect("mock work");
        let nonce = (0..u64::MAX)
            .map(counter_to_nonce)
            .find(|nonce| seal_meets_target(&compute_work(&work.pre_hash, *nonce), work.pow_bits))
            .expect("mock work should admit a valid nonce");

        let response = rpc
            .submit_pool_share(SubmitPoolShareRequest {
                worker_name: "alpha".to_string(),
                nonce: format!("0x{}", hex::encode(nonce)),
                pre_hash: format!("0x{}", hex::encode(work.pre_hash.as_bytes())),
                parent_hash: format!("0x{}", hex::encode(work.parent_hash.as_bytes())),
                height: work.height,
                auth_token: None,
            })
            .await
            .unwrap();

        assert!(response.accepted);
        assert!(response.block_candidate);
        assert!(response.network_target_met);
        assert_eq!(response.accepted_shares, 1);
        assert_eq!(response.worker_accepted_shares, 1);
    }

    #[tokio::test]
    async fn test_submit_pool_share_rejects_stale_work() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(service, handle, mock_config(), sc_rpc::DenyUnsafe::No);

        let response = rpc
            .submit_pool_share(SubmitPoolShareRequest {
                worker_name: "alpha".to_string(),
                nonce: format!("0x{}", hex::encode(counter_to_nonce(0))),
                pre_hash: format!("0x{}", hex::encode([0u8; 32])),
                parent_hash: format!("0x{}", hex::encode([0u8; 32])),
                height: 7,
                auth_token: None,
            })
            .await
            .unwrap();

        assert!(!response.accepted);
        assert!(response.error.unwrap_or_default().contains("stale"));
        assert_eq!(response.rejected_shares, 1);
        assert_eq!(response.worker_rejected_shares, 1);
    }

    #[tokio::test]
    async fn test_submit_compact_solution_accepts_full_target_solution() {
        let service = Arc::new(MockService);
        let handle = MockMiningHandle::new();
        let rpc = HegemonRpc::new(
            service,
            handle.clone(),
            mock_config(),
            sc_rpc::DenyUnsafe::No,
        );
        let work = handle.current_work().expect("mock work");
        let nonce = (0..u64::MAX)
            .map(counter_to_nonce)
            .find(|nonce| seal_meets_target(&compute_work(&work.pre_hash, *nonce), work.pow_bits))
            .expect("mock work should admit a valid nonce");
        let job = rpc.compact_job(None).await.unwrap();

        let response = rpc
            .submit_compact_solution(SubmitCompactSolutionRequest {
                worker_name: "alpha".to_string(),
                job_id: job.job_id.expect("job id"),
                nonce: format!("0x{}", hex::encode(nonce)),
                auth_token: None,
            })
            .await
            .unwrap();

        assert!(response.accepted);
        assert!(response.block_candidate);
        assert!(response.network_target_met);
    }
}
