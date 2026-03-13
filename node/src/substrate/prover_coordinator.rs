use parking_lot::Mutex;
use sp_core::H256;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use transaction_circuit::proof::TransactionProof;
use block_circuit::CommitmentBlockProver;
use consensus::encode_aggregation_proof_bytes;
use crypto::hashes::blake3_384;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BundleMatchKey {
    pub parent_hash: H256,
    pub tx_statements_commitment: [u8; 48],
    pub tx_count: u32,
    pub proof_mode: pallet_shielded_pool::types::BlockProofMode,
    pub artifact_hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct PreparedBundle {
    pub key: BundleMatchKey,
    pub payload: pallet_shielded_pool::types::CandidateArtifact,
    pub candidate_txs: Vec<Vec<u8>>,
    pub build_ms: u128,
}

#[derive(Clone, Debug, Default)]
pub struct PreparedLookupDiagnostics {
    pub prepared_total: usize,
    pub same_parent: usize,
    pub same_statement: usize,
    pub same_tx_count: usize,
    pub same_parent_and_statement: usize,
    pub same_parent_and_tx_count: usize,
    pub same_statement_and_tx_count: usize,
    pub sample_same_parent_commitment: Option<[u8; 48]>,
    pub sample_same_statement_parent: Option<H256>,
    pub sample_same_parent_tx_count: Option<u32>,
}

fn block_proof_bundle_payload_bytes(
    payload: &pallet_shielded_pool::types::CandidateArtifact,
) -> usize {
    let aggregation_bytes = match payload.proof_mode {
        pallet_shielded_pool::types::BlockProofMode::FlatBatches => payload
            .flat_batches
            .iter()
            .map(|item| item.proof.data.len())
            .sum::<usize>(),
        pallet_shielded_pool::types::BlockProofMode::MergeRoot => payload
            .merge_root
            .as_ref()
            .map(|merge| merge.root_proof.data.len())
            .unwrap_or(0),
    };
    payload.commitment_proof.data.len() + aggregation_bytes
}

#[derive(Clone, Debug)]
pub struct WorkPackage {
    pub package_id: String,
    pub parent_hash: H256,
    pub block_number: u64,
    pub candidate_set_id: String,
    pub chunk_start_tx_index: u32,
    pub chunk_tx_count: u16,
    pub expected_chunks: u16,
    pub stage_type: String,
    pub level: u16,
    pub arity: u16,
    pub shape_id: [u8; 32],
    pub dependencies: Vec<String>,
    pub tx_count: u32,
    pub candidate_txs: Vec<Vec<u8>>,
    pub leaf_batch_payload: Option<LeafBatchWorkData>,
    pub merge_node_payload: Option<MergeNodeWorkData>,
    pub root_finalize_payload: Option<RootFinalizeWorkData>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug)]
pub struct LeafBatchWorkData {
    pub statement_hashes: Vec<[u8; 48]>,
    pub tx_proofs: Vec<TransactionProof>,
    pub tx_statements_commitment: [u8; 48],
    pub tree_levels: u16,
    pub root_level: u16,
}

#[derive(Clone, Debug)]
pub struct MergeNodeWorkData {
    pub child_proof_payloads: Vec<Vec<u8>>,
    pub tx_statements_commitment: [u8; 48],
    pub tree_levels: u16,
    pub root_level: u16,
}

#[derive(Clone, Debug)]
pub struct RootFinalizeWorkData {
    pub statement_hashes: Vec<[u8; 48]>,
    pub tx_proofs: Vec<TransactionProof>,
    pub tx_statements_commitment: [u8; 48],
    pub da_root: [u8; 48],
    pub da_chunk_count: u32,
    pub starting_state_root: [u8; 48],
    pub ending_state_root: [u8; 48],
    pub starting_kernel_root: [u8; 48],
    pub ending_kernel_root: [u8; 48],
    pub nullifier_root: [u8; 48],
    pub nullifiers: Vec<[u8; 48]>,
    pub sorted_nullifiers: Vec<[u8; 48]>,
}

#[derive(Clone, Debug)]
pub enum WorkStatus {
    Pending,
    Accepted,
    Rejected(String),
    Expired,
}

#[derive(Clone, Debug)]
pub struct StageQueueStatus {
    pub stage_type: String,
    pub level: u16,
    pub queued_jobs: usize,
    pub inflight_jobs: usize,
}

#[derive(Clone, Debug)]
pub struct StagePlanStatus {
    pub generation: u64,
    pub current_parent: Option<H256>,
    pub queued_jobs: usize,
    pub inflight_jobs: usize,
    pub prepared_bundles: usize,
    pub latest_work_package: Option<String>,
    pub stage_queue: Vec<StageQueueStatus>,
}

#[derive(Clone, Copy, Debug)]
pub struct ProverMarketParams {
    pub package_ttl_ms: u64,
    pub max_submissions_per_package: u32,
    pub max_submissions_per_source: u32,
    pub max_payload_bytes: usize,
}

#[allow(deprecated)]
#[deprecated(note = "Use BundleMatchKey instead.")]
pub type ReadyBatchKey = BundleMatchKey;

#[allow(deprecated)]
#[deprecated(note = "Use PreparedBundle instead.")]
pub type ReadyBatch = PreparedBundle;

pub type BestBlockFn = dyn Fn() -> (H256, u64) + Send + Sync + 'static;
pub type PendingTxsFn = dyn Fn(usize) -> Vec<Vec<u8>> + Send + Sync + 'static;
pub type PrepareBundleFn =
    dyn Fn(H256, u64, Vec<Vec<u8>>) -> Result<PreparedBundle, String> + Send + Sync + 'static;
pub type BuildRootFinalizeWorkFn = dyn Fn(H256, u64, Vec<Vec<u8>>) -> Result<Option<RootFinalizeWorkData>, String>
    + Send
    + Sync
    + 'static;

#[allow(deprecated)]
#[deprecated(note = "Use PrepareBundleFn instead.")]
pub type BuildBatchFn = PrepareBundleFn;

#[derive(Clone, Debug)]
struct QueuedJob {
    id: u64,
    package_id: String,
    candidate_set_id: String,
    generation: u64,
    parent_hash: H256,
    block_number: u64,
    stage_type: String,
    level: u16,
    arity: u16,
    shape_id: [u8; 32],
    dependencies: Vec<String>,
    enqueued_at: Instant,
    candidate_txs: Vec<Vec<u8>>,
    leaf_batch_payload: Option<LeafBatchWorkData>,
    merge_node_payload: Option<MergeNodeWorkData>,
}

#[derive(Debug)]
enum WorkerOutcome {
    StageResult(Box<Result<Vec<u8>, String>>),
    Bundle(Box<Result<PreparedBundle, String>>),
    Panicked(String),
}

#[derive(Debug)]
struct WorkerJobResult {
    job: QueuedJob,
    queue_depth_after_pop: usize,
    build_elapsed_ms: u128,
    outcome: WorkerOutcome,
}

enum WorkerCommand {
    Run {
        job: QueuedJob,
        queue_depth_after_pop: usize,
    },
    Stop,
}

struct WorkerPool {
    senders: Vec<Sender<WorkerCommand>>,
    results_rx: Mutex<Receiver<WorkerJobResult>>,
}

impl WorkerPool {
    fn new(workers: usize, prepare_bundle_fn: Arc<PrepareBundleFn>) -> Self {
        let (results_tx, results_rx) = mpsc::channel();
        let (prewarm_tx, prewarm_rx) = mpsc::channel();
        let mut senders = Vec::with_capacity(workers);
        for worker_index in 0..workers {
            let (worker_tx, worker_rx) = mpsc::channel();
            let worker_results_tx = results_tx.clone();
            let worker_prepare_bundle_fn = Arc::clone(&prepare_bundle_fn);
            let worker_prewarm_tx = prewarm_tx.clone();
            let worker_name = format!("hegemon-prover-worker-{worker_index}");
            let _ = std::thread::Builder::new()
                .name(worker_name)
                .spawn(move || {
                    let prewarm_result =
                        aggregation_circuit::prewarm_thread_local_aggregation_cache_from_env();
                    let _ = worker_prewarm_tx.send(
                        prewarm_result
                            .as_ref()
                            .map(|_| ())
                            .map_err(|error| error.to_string()),
                    );
                    if let Err(error) = prewarm_result {
                        tracing::warn!(
                            worker_index,
                            error = %error,
                            "Failed to prewarm aggregation prover cache on worker thread"
                        );
                    }
                    while let Ok(command) = worker_rx.recv() {
                        let WorkerCommand::Run {
                            job,
                            queue_depth_after_pop,
                        } = command
                        else {
                            break;
                        };
                        let build_started = Instant::now();
                        let outcome = match job.stage_type.as_str() {
                            "leaf_batch_prove" => {
                                let payload = job.leaf_batch_payload.clone();
                                match panic::catch_unwind(AssertUnwindSafe(move || {
                                    let payload = payload
                                        .ok_or_else(|| "missing leaf batch payload".to_string())?;
                                    aggregation_circuit::prove_leaf_aggregation(
                                        &payload.tx_proofs,
                                        &payload.statement_hashes,
                                        payload.tree_levels,
                                        payload.root_level,
                                    )
                                    .map_err(|err| err.to_string())
                                })) {
                                    Ok(result) => WorkerOutcome::StageResult(Box::new(result)),
                                    Err(panic_payload) => {
                                        let message = if let Some(as_str) =
                                            panic_payload.downcast_ref::<&'static str>()
                                        {
                                            (*as_str).to_string()
                                        } else if let Some(as_string) =
                                            panic_payload.downcast_ref::<String>()
                                        {
                                            as_string.clone()
                                        } else {
                                            "unknown panic payload".to_string()
                                        };
                                        WorkerOutcome::Panicked(message)
                                    }
                                }
                            }
                            "merge_node_prove" => {
                                let payload = job.merge_node_payload.clone();
                                match panic::catch_unwind(AssertUnwindSafe(move || {
                                    let payload = payload
                                        .ok_or_else(|| "missing merge node payload".to_string())?;
                                    aggregation_circuit::prove_merge_aggregation(
                                        &payload.child_proof_payloads,
                                        payload.tx_statements_commitment,
                                        payload.tree_levels,
                                        payload.root_level,
                                    )
                                    .map_err(|err| err.to_string())
                                })) {
                                    Ok(result) => WorkerOutcome::StageResult(Box::new(result)),
                                    Err(panic_payload) => {
                                        let message = if let Some(as_str) =
                                            panic_payload.downcast_ref::<&'static str>()
                                        {
                                            (*as_str).to_string()
                                        } else if let Some(as_string) =
                                            panic_payload.downcast_ref::<String>()
                                        {
                                            as_string.clone()
                                        } else {
                                            "unknown panic payload".to_string()
                                        };
                                        WorkerOutcome::Panicked(message)
                                    }
                                }
                            }
                            _ => {
                                let parent_hash = job.parent_hash;
                                let block_number = job.block_number;
                                let candidate_txs = job.candidate_txs.clone();
                                match panic::catch_unwind(AssertUnwindSafe(|| {
                                    worker_prepare_bundle_fn(parent_hash, block_number, candidate_txs)
                                })) {
                                    Ok(result) => WorkerOutcome::Bundle(Box::new(result)),
                                    Err(panic_payload) => {
                                        let message = if let Some(as_str) =
                                            panic_payload.downcast_ref::<&'static str>()
                                        {
                                            (*as_str).to_string()
                                        } else if let Some(as_string) =
                                            panic_payload.downcast_ref::<String>()
                                        {
                                            as_string.clone()
                                        } else {
                                            "unknown panic payload".to_string()
                                        };
                                        WorkerOutcome::Panicked(message)
                                    }
                                }
                            }
                        };
                        let build_elapsed_ms = build_started.elapsed().as_millis();
                        let _ = worker_results_tx.send(WorkerJobResult {
                            job,
                            queue_depth_after_pop,
                            build_elapsed_ms,
                            outcome,
                        });
                    }
                });
            senders.push(worker_tx);
        }
        drop(prewarm_tx);

        if should_block_on_worker_prewarm() {
            let timeout = worker_prewarm_timeout();
            for worker_index in 0..workers {
                match prewarm_rx.recv_timeout(timeout) {
                    Ok(Ok(())) => {
                        tracing::info!(
                            worker_index,
                            timeout_secs = timeout.as_secs(),
                            "Aggregation prover worker prewarm complete"
                        );
                    }
                    Ok(Err(error)) => {
                        tracing::warn!(
                            worker_index,
                            error = %error,
                            timeout_secs = timeout.as_secs(),
                            "Aggregation prover worker prewarm failed during startup"
                        );
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        tracing::warn!(
                            worker_index,
                            timeout_secs = timeout.as_secs(),
                            "Timed out waiting for aggregation prover worker prewarm"
                        );
                        break;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        }
        Self {
            senders,
            results_rx: Mutex::new(results_rx),
        }
    }

    fn dispatch(&self, worker_index: usize, job: QueuedJob, queue_depth_after_pop: usize) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        self.senders
            .get(worker_index % self.senders.len())
            .and_then(|sender| {
                sender
                    .send(WorkerCommand::Run {
                        job,
                        queue_depth_after_pop,
                    })
                    .ok()
            })
            .is_some()
    }

    fn try_recv(&self) -> Result<WorkerJobResult, TryRecvError> {
        self.results_rx.lock().try_recv()
    }

    fn worker_count(&self) -> usize {
        self.senders.len()
    }
}

fn should_block_on_worker_prewarm() -> bool {
    std::env::var("HEGEMON_AGG_PREWARM_BLOCKING")
        .ok()
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn worker_prewarm_timeout() -> Duration {
    Duration::from_secs(
        std::env::var("HEGEMON_AGG_PREWARM_TIMEOUT_SECS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(900)
            .max(1),
    )
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        for sender in &self.senders {
            let _ = sender.send(WorkerCommand::Stop);
        }
    }
}

#[derive(Clone)]
pub struct ProverCoordinator {
    state: Arc<Mutex<CoordinatorState>>,
    config: ProverCoordinatorConfig,
    best_block_fn: Arc<BestBlockFn>,
    pending_txs_fn: Arc<PendingTxsFn>,
    worker_pool: Arc<WorkerPool>,
    build_root_finalize_work_fn: Option<Arc<BuildRootFinalizeWorkFn>>,
}

#[derive(Clone, Copy, Debug)]
pub struct ProverCoordinatorConfig {
    pub workers: usize,
    pub target_txs: usize,
    pub queue_capacity: usize,
    pub max_inflight_per_level: usize,
    pub liveness_lane: bool,
    pub adaptive_liveness_timeout: Duration,
    pub incremental_upsizing: bool,
    pub poll_interval: Duration,
    pub job_timeout: Duration,
    pub work_package_ttl: Duration,
    pub max_submissions_per_package: u32,
    pub max_submissions_per_source: u32,
    pub max_payload_bytes: usize,
}

impl ProverCoordinatorConfig {
    pub fn from_env(default_target_txs: usize) -> Self {
        let default_workers = std::thread::available_parallelism()
            .map(|threads| threads.get().min(2))
            .unwrap_or(1usize)
            .max(1);
        let workers = std::env::var("HEGEMON_AGG_STAGE_LOCAL_PARALLELISM")
            .ok()
            .and_then(|v| v.parse().ok())
            .or_else(|| {
                std::env::var("HEGEMON_PROVER_WORKERS")
                    .ok()
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or(default_workers);
        let target_txs = std::env::var("HEGEMON_BATCH_TARGET_TXS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_target_txs)
            .max(1);
        let queue_capacity = std::env::var("HEGEMON_AGG_STAGE_QUEUE_DEPTH")
            .ok()
            .and_then(|v| v.parse().ok())
            .or_else(|| {
                std::env::var("HEGEMON_BATCH_QUEUE_CAPACITY")
                    .ok()
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or(4usize)
            .max(1);
        let max_inflight_per_level = std::env::var("HEGEMON_PROVER_STAGE_MAX_INFLIGHT_PER_LEVEL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(workers.max(1))
            .max(1);
        let liveness_lane = std::env::var("HEGEMON_PROVER_LIVENESS_LANE")
            .ok()
            .map(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(true);
        let adaptive_liveness_timeout_ms = std::env::var("HEGEMON_PROVER_ADAPTIVE_LIVENESS_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            // Default to disabled so throughput mode remains deadline-driven:
            // do not silently downshift to singleton lanes unless explicitly
            // configured by operators.
            .unwrap_or(0u64);
        let incremental_upsizing = std::env::var("HEGEMON_BATCH_INCREMENTAL_UPSIZE")
            .ok()
            .map(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        let job_timeout_ms = std::env::var("HEGEMON_BATCH_JOB_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            // Default above nominal 60s block time so heavy proving jobs can finish
            // under typical load instead of being cut off too aggressively.
            .unwrap_or(180_000u64);
        let work_package_ttl_ms = std::env::var("HEGEMON_PROVER_WORK_PACKAGE_TTL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(job_timeout_ms);
        let max_submissions_per_package =
            std::env::var("HEGEMON_PROVER_MAX_SUBMISSIONS_PER_PACKAGE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(16u32)
                .max(1);
        let max_submissions_per_source = std::env::var("HEGEMON_PROVER_MAX_SUBMISSIONS_PER_SOURCE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(32u32)
            .max(1);
        let max_payload_bytes = std::env::var("HEGEMON_PROVER_MAX_PAYLOAD_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(pallet_shielded_pool::types::STARK_PROOF_MAX_SIZE * 2);
        Self {
            workers,
            target_txs,
            queue_capacity,
            max_inflight_per_level,
            liveness_lane,
            adaptive_liveness_timeout: Duration::from_millis(adaptive_liveness_timeout_ms),
            incremental_upsizing,
            poll_interval: Duration::from_millis(250),
            job_timeout: Duration::from_millis(job_timeout_ms),
            work_package_ttl: Duration::from_millis(work_package_ttl_ms),
            max_submissions_per_package,
            max_submissions_per_source,
            max_payload_bytes,
        }
    }
}

#[derive(Clone, Debug)]
struct WorkPackageRecord {
    package: WorkPackage,
    submissions: u32,
}

#[derive(Clone, Debug)]
struct ChunkPlan {
    package_id: String,
    start_tx_index: u32,
    tx_count: u16,
}

#[derive(Clone, Debug)]
struct FanoutAssemblyState {
    parent_hash: H256,
    block_number: u64,
    candidate_txs: Vec<Vec<u8>>,
    expected_chunks: u16,
    chunks: Vec<ChunkPlan>,
    received: HashMap<String, pallet_shielded_pool::types::CandidateArtifact>,
}

#[derive(Clone, Debug)]
struct RecursiveTreeAssemblyState {
    parent_hash: H256,
    block_number: u64,
    candidate_txs: Vec<Vec<u8>>,
    root_finalize_payload: RootFinalizeWorkData,
    leaf_chunks: Vec<ChunkPlan>,
    leaf_results: HashMap<String, Vec<u8>>,
    merge_package_id: Option<String>,
}

#[derive(Default)]
struct CoordinatorState {
    current_parent: Option<H256>,
    generation: u64,
    target_batch_scheduled_at_ms: Option<u64>,
    adaptive_liveness_fired_generation: Option<u64>,
    selected_txs: Vec<Vec<u8>>,
    prepared: HashMap<BundleMatchKey, PreparedBundle>,
    work_packages: HashMap<String, WorkPackageRecord>,
    work_package_queue: VecDeque<String>,
    stage_work_package_queue: VecDeque<String>,
    latest_work_package: Option<String>,
    latest_stage_work_package: Option<String>,
    fanout_assemblies: HashMap<String, FanoutAssemblyState>,
    recursive_assemblies: HashMap<String, RecursiveTreeAssemblyState>,
    work_status: HashMap<String, WorkStatus>,
    source_submissions: HashMap<String, u32>,
    pending_jobs: VecDeque<QueuedJob>,
    inflight_jobs: HashMap<u64, u64>,
    inflight_stage_meta: HashMap<u64, (String, u16)>,
    inflight_candidates: HashMap<u64, Vec<Vec<u8>>>,
    next_job_id: u64,
    stale_count: u64,
    last_build_ms: u128,
}

impl ProverCoordinator {
    const DEFAULT_LEAF_FAN_IN: usize = 4;
    const DEFAULT_MERGE_FAN_IN: usize = 8;

    fn aggregation_tree_arity() -> u16 {
        std::env::var("HEGEMON_AGG_TREE_ARITY")
            .ok()
            .and_then(|raw| raw.parse::<u16>().ok())
            .map(|value| value.max(2))
            .unwrap_or(8)
    }

    fn tree_levels_for_tx_count(tx_count: usize, arity: u16) -> u16 {
        if tx_count <= 1 {
            return 1;
        }
        let mut levels = 1u16;
        let mut width = tx_count;
        let radix = arity.max(2) as usize;
        while width > 1 {
            width = width.div_ceil(radix);
            levels = levels.saturating_add(1);
        }
        levels
    }

    fn candidate_digest(candidate_txs: &[Vec<u8>]) -> [u8; 32] {
        let mut bytes = Vec::new();
        for tx in candidate_txs {
            bytes.extend_from_slice(&(tx.len() as u64).to_le_bytes());
            bytes.extend_from_slice(tx);
        }
        sp_core::hashing::blake2_256(&bytes)
    }

    fn work_package_shape_id(
        parent_hash: H256,
        block_number: u64,
        stage_type: &str,
        level: u16,
        stage_index: u32,
        arity: u16,
        tx_count: u32,
        candidate_digest: [u8; 32],
    ) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(parent_hash.as_bytes());
        bytes.extend_from_slice(&block_number.to_le_bytes());
        bytes.extend_from_slice(stage_type.as_bytes());
        bytes.extend_from_slice(&level.to_le_bytes());
        bytes.extend_from_slice(&stage_index.to_le_bytes());
        bytes.extend_from_slice(&arity.to_le_bytes());
        bytes.extend_from_slice(&tx_count.to_le_bytes());
        bytes.extend_from_slice(&candidate_digest);
        sp_core::hashing::blake2_256(&bytes)
    }

    fn stage_work_id(
        parent_hash: H256,
        block_number: u64,
        stage_type: &str,
        level: u16,
        stage_index: u32,
        arity: u16,
        tx_count: u32,
        candidate_digest: [u8; 32],
    ) -> String {
        hex::encode(Self::work_package_shape_id(
            parent_hash,
            block_number,
            stage_type,
            level,
            stage_index,
            arity,
            tx_count,
            candidate_digest,
        ))
    }

    fn root_stage_metadata(
        parent_hash: H256,
        block_number: u64,
        candidate_txs: &[Vec<u8>],
        arity: u16,
    ) -> (u16, [u8; 32], Vec<String>) {
        let tx_count = candidate_txs.len().max(1) as u32;
        let candidate_digest = Self::candidate_digest(candidate_txs);
        let radix = arity.max(2) as usize;

        let mut level_widths = vec![tx_count as usize];
        while level_widths.last().copied().unwrap_or(1) > 1 {
            let next = level_widths.last().copied().unwrap_or(1).div_ceil(radix);
            level_widths.push(next);
        }

        let root_level = level_widths.len().saturating_sub(1) as u16;
        debug_assert_eq!(
            root_level.saturating_add(1),
            Self::tree_levels_for_tx_count(tx_count as usize, arity)
        );
        let root_shape_id = Self::work_package_shape_id(
            parent_hash,
            block_number,
            "root_finalize",
            root_level,
            0,
            arity,
            tx_count,
            candidate_digest,
        );

        let dependencies = if root_level == 0 {
            Vec::new()
        } else {
            let parent_level = root_level.saturating_sub(1) as usize;
            let parent_stage = if parent_level == 0 {
                "leaf_verify"
            } else {
                "merge"
            };
            let parent_width = level_widths[parent_level];
            (0..parent_width)
                .map(|idx| {
                    Self::stage_work_id(
                        parent_hash,
                        block_number,
                        parent_stage,
                        parent_level as u16,
                        idx as u32,
                        arity,
                        tx_count,
                        candidate_digest,
                    )
                })
                .collect()
        };

        (root_level, root_shape_id, dependencies)
    }

    fn stage_mem_budget_mb() -> usize {
        std::env::var("HEGEMON_PROVER_STAGE_MEM_BUDGET_MB")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(4096)
            .max(256)
    }

    fn inflight_current_generation_count(state: &CoordinatorState) -> usize {
        state
            .inflight_jobs
            .values()
            .filter(|generation| **generation == state.generation)
            .count()
    }

    fn inflight_current_generation_count_for_level(state: &CoordinatorState, level: u16) -> usize {
        state
            .inflight_jobs
            .iter()
            .filter(|(_, generation)| **generation == state.generation)
            .filter(|(job_id, _)| {
                state
                    .inflight_stage_meta
                    .get(job_id)
                    .map(|(_, inflight_level)| *inflight_level == level)
                    .unwrap_or(false)
            })
            .count()
    }

    fn inflight_total_cap(&self) -> usize {
        // Allow one extra generation overlap so parent changes do not starve
        // scheduling when proving is slower than block production.
        self.config.workers.saturating_mul(2).max(1)
    }

    pub fn new(
        config: ProverCoordinatorConfig,
        best_block_fn: Arc<BestBlockFn>,
        pending_txs_fn: Arc<PendingTxsFn>,
        prepare_bundle_fn: Arc<PrepareBundleFn>,
    ) -> Arc<Self> {
        Self::new_with_root_finalize_builder(
            config,
            best_block_fn,
            pending_txs_fn,
            prepare_bundle_fn,
            None,
        )
    }

    pub fn new_with_root_finalize_builder(
        config: ProverCoordinatorConfig,
        best_block_fn: Arc<BestBlockFn>,
        pending_txs_fn: Arc<PendingTxsFn>,
        prepare_bundle_fn: Arc<PrepareBundleFn>,
        build_root_finalize_work_fn: Option<Arc<BuildRootFinalizeWorkFn>>,
    ) -> Arc<Self> {
        let worker_pool = Arc::new(WorkerPool::new(
            config.workers,
            Arc::clone(&prepare_bundle_fn),
        ));
        Arc::new(Self {
            state: Arc::new(Mutex::new(CoordinatorState::default())),
            config,
            best_block_fn,
            pending_txs_fn,
            worker_pool,
            build_root_finalize_work_fn,
        })
    }

    pub fn start(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                this.tick().await;
                tokio::time::sleep(this.config.poll_interval).await;
            }
        });
    }

    pub fn pending_transactions(&self, max_txs: usize) -> Vec<Vec<u8>> {
        let state = self.state.lock();
        // Prefer candidates that already have a prepared proof bundle for the
        // current parent. This is the liveness lane used when larger batches
        // are still proving.
        let mut txs = if let Some(prepared) = Self::best_prepared_candidate_locked(&state) {
            prepared
        } else if state.selected_txs.is_empty() {
            Self::best_pending_candidate_locked(&state).unwrap_or_default()
        } else {
            state.selected_txs.clone()
        };
        txs.truncate(max_txs);
        txs
    }

    pub fn lookup_prepared_bundle(
        &self,
        parent_hash: H256,
        tx_statements_commitment: [u8; 48],
        tx_count: u32,
    ) -> Option<PreparedBundle> {
        let state = self.state.lock();
        state
            .prepared
            .values()
            .filter(|bundle| {
                bundle.key.parent_hash == parent_hash
                    && bundle.key.tx_statements_commitment == tx_statements_commitment
                    && bundle.key.tx_count == tx_count
            })
            .max_by(|left, right| compare_prepared_bundles(left, right))
            .cloned()
    }

    pub fn lookup_prepared_bundle_any_parent(
        &self,
        tx_statements_commitment: [u8; 48],
        tx_count: u32,
    ) -> Option<PreparedBundle> {
        let state = self.state.lock();
        Self::best_prepared_bundle_for_statement_locked(&state, tx_statements_commitment, tx_count)
            .cloned()
    }

    pub fn lookup_candidate_artifact_any_parent(
        &self,
        tx_statements_commitment: [u8; 48],
        tx_count: u32,
    ) -> Option<pallet_shielded_pool::types::CandidateArtifact> {
        self.lookup_prepared_bundle_any_parent(tx_statements_commitment, tx_count)
            .map(|bundle| bundle.payload)
    }

    pub fn lookup_candidate_artifact_by_hash(
        &self,
        artifact_hash: [u8; 32],
    ) -> Option<pallet_shielded_pool::types::CandidateArtifact> {
        self.lookup_prepared_bundle_by_hash(artifact_hash)
            .map(|bundle| bundle.payload)
    }

    pub fn lookup_prepared_bundle_by_hash(
        &self,
        artifact_hash: [u8; 32],
    ) -> Option<PreparedBundle> {
        let state = self.state.lock();
        state
            .prepared
            .values()
            .find(|bundle| {
                crate::substrate::artifact_market::candidate_artifact_hash(&bundle.payload)
                    == artifact_hash
            })
            .cloned()
    }

    pub fn import_network_artifact(
        &self,
        parent_hash: H256,
        payload: pallet_shielded_pool::types::CandidateArtifact,
        candidate_txs: Vec<Vec<u8>>,
    ) {
        let mut state = self.state.lock();
        let key = candidate_bundle_key(parent_hash, &payload);
        let incoming = PreparedBundle {
            key: key.clone(),
            payload,
            candidate_txs,
            build_ms: 0,
        };
        let should_replace = match state.prepared.get(&key) {
            Some(existing) => compare_prepared_bundles(&incoming, existing).is_gt(),
            None => true,
        };
        if should_replace {
            state.prepared.insert(key, incoming);
        }
    }

    pub fn list_artifact_announcements(&self) -> Vec<consensus::ArtifactAnnouncement> {
        let state = self.state.lock();
        let mut announcements = state
            .prepared
            .values()
            .map(|bundle| crate::substrate::artifact_market::artifact_announcement(&bundle.payload))
            .collect::<Vec<_>>();
        announcements.sort_by(|left, right| {
            left.tx_statements_commitment
                .cmp(&right.tx_statements_commitment)
                .then_with(|| left.tx_count.cmp(&right.tx_count))
        });
        announcements
    }

    #[allow(deprecated)]
    #[deprecated(note = "Use lookup_prepared_bundle instead.")]
    pub fn lookup_ready_batch(
        &self,
        parent_hash: H256,
        tx_statements_commitment: [u8; 48],
        tx_count: u32,
    ) -> Option<PreparedBundle> {
        self.lookup_prepared_bundle(parent_hash, tx_statements_commitment, tx_count)
    }

    pub fn clear_on_import_success(self: &Arc<Self>, included_txs: &[Vec<u8>]) {
        self.drain_worker_results();
        {
            let mut state = self.state.lock();
            if state.selected_txs == included_txs {
                state.selected_txs.clear();
            }
            state.target_batch_scheduled_at_ms = None;
            state.adaptive_liveness_fired_generation = None;
            state.prepared.clear();
            state.work_packages.clear();
            state.work_package_queue.clear();
            state.stage_work_package_queue.clear();
            state.latest_work_package = None;
            state.latest_stage_work_package = None;
            state.fanout_assemblies.clear();
            state.recursive_assemblies.clear();
            state.work_status.clear();
            state.source_submissions.clear();
            state.pending_jobs.clear();
            state.inflight_stage_meta.clear();
            state.inflight_candidates.clear();
        }

        // Kick N+1 prove-ahead scheduling immediately on import success
        // instead of waiting for the periodic coordinator tick.
        let (parent_hash, best_number) = (self.best_block_fn)();
        {
            let mut state = self.state.lock();
            if state.current_parent != Some(parent_hash) {
                state.current_parent = Some(parent_hash);
                state.generation = state.generation.wrapping_add(1);
                state.target_batch_scheduled_at_ms = None;
                state.adaptive_liveness_fired_generation = None;
                state.selected_txs.clear();
                state.work_packages.clear();
                state.work_package_queue.clear();
                state.stage_work_package_queue.clear();
                state.latest_work_package = None;
                state.latest_stage_work_package = None;
                state.fanout_assemblies.clear();
                state.recursive_assemblies.clear();
                state.work_status.clear();
                state.source_submissions.clear();
                state.pending_jobs.clear();
                state.inflight_stage_meta.clear();
                state.inflight_candidates.clear();
            }
        }
        self.ensure_job_queue(parent_hash, best_number);
        self.dispatch_jobs();
    }

    pub fn stale_count(&self) -> u64 {
        self.state.lock().stale_count
    }

    pub fn prepared_lookup_diagnostics(
        &self,
        parent_hash: H256,
        tx_statements_commitment: [u8; 48],
        tx_count: u32,
    ) -> PreparedLookupDiagnostics {
        let state = self.state.lock();
        let mut diagnostics = PreparedLookupDiagnostics {
            prepared_total: state.prepared.len(),
            ..PreparedLookupDiagnostics::default()
        };
        for key in state.prepared.keys() {
            if key.parent_hash == parent_hash {
                diagnostics.same_parent = diagnostics.same_parent.saturating_add(1);
                diagnostics
                    .sample_same_parent_commitment
                    .get_or_insert(key.tx_statements_commitment);
                diagnostics
                    .sample_same_parent_tx_count
                    .get_or_insert(key.tx_count);
            }
            if key.tx_statements_commitment == tx_statements_commitment {
                diagnostics.same_statement = diagnostics.same_statement.saturating_add(1);
                diagnostics
                    .sample_same_statement_parent
                    .get_or_insert(key.parent_hash);
            }
            if key.tx_count == tx_count {
                diagnostics.same_tx_count = diagnostics.same_tx_count.saturating_add(1);
            }
            if key.parent_hash == parent_hash
                && key.tx_statements_commitment == tx_statements_commitment
            {
                diagnostics.same_parent_and_statement =
                    diagnostics.same_parent_and_statement.saturating_add(1);
            }
            if key.parent_hash == parent_hash && key.tx_count == tx_count {
                diagnostics.same_parent_and_tx_count =
                    diagnostics.same_parent_and_tx_count.saturating_add(1);
            }
            if key.tx_statements_commitment == tx_statements_commitment && key.tx_count == tx_count
            {
                diagnostics.same_statement_and_tx_count =
                    diagnostics.same_statement_and_tx_count.saturating_add(1);
            }
        }
        diagnostics
    }

    pub fn last_build_ms(&self) -> u128 {
        self.state.lock().last_build_ms
    }

    pub fn active_jobs(&self) -> usize {
        self.state.lock().inflight_jobs.len()
    }

    pub fn queued_jobs(&self) -> usize {
        self.state.lock().pending_jobs.len()
    }

    pub fn stage_plan_status(&self) -> StagePlanStatus {
        let state = self.state.lock();
        let mut per_stage: BTreeMap<(String, u16), StageQueueStatus> = BTreeMap::new();

        for job in state
            .pending_jobs
            .iter()
            .filter(|job| job.generation == state.generation)
        {
            let key = (job.stage_type.clone(), job.level);
            let entry = per_stage.entry(key.clone()).or_insert(StageQueueStatus {
                stage_type: key.0.clone(),
                level: key.1,
                queued_jobs: 0,
                inflight_jobs: 0,
            });
            entry.queued_jobs = entry.queued_jobs.saturating_add(1);
        }

        for (job_id, generation) in state.inflight_jobs.iter() {
            if *generation != state.generation {
                continue;
            }
            if let Some((stage_type, level)) = state.inflight_stage_meta.get(job_id) {
                let key = (stage_type.clone(), *level);
                let entry = per_stage.entry(key.clone()).or_insert(StageQueueStatus {
                    stage_type: key.0.clone(),
                    level: key.1,
                    queued_jobs: 0,
                    inflight_jobs: 0,
                });
                entry.inflight_jobs = entry.inflight_jobs.saturating_add(1);
            }
        }

        StagePlanStatus {
            generation: state.generation,
            current_parent: state.current_parent,
            queued_jobs: state.pending_jobs.len(),
            inflight_jobs: state.inflight_jobs.len(),
            prepared_bundles: state.prepared.len(),
            latest_work_package: state
                .latest_stage_work_package
                .clone()
                .or_else(|| state.latest_work_package.clone()),
            stage_queue: per_stage.into_values().collect(),
        }
    }

    pub fn market_params(&self) -> ProverMarketParams {
        ProverMarketParams {
            package_ttl_ms: self.config.work_package_ttl.as_millis() as u64,
            max_submissions_per_package: self.config.max_submissions_per_package,
            max_submissions_per_source: self.config.max_submissions_per_source,
            max_payload_bytes: self.config.max_payload_bytes,
        }
    }

    pub fn get_work_package(&self) -> Option<WorkPackage> {
        let mut state = self.state.lock();
        Self::expire_work_packages_locked(&mut state);
        let queue_len = state.work_package_queue.len();
        for _ in 0..queue_len {
            let Some(package_id) = state.work_package_queue.pop_front() else {
                break;
            };
            let Some(record) = state.work_packages.get(&package_id) else {
                continue;
            };
            if record.submissions >= self.config.max_submissions_per_package {
                continue;
            }
            let package = record.package.clone();
            state.work_package_queue.push_back(package_id.clone());
            state.latest_work_package = Some(package_id.clone());
            state
                .work_status
                .entry(package_id.clone())
                .or_insert(WorkStatus::Pending);
            return Some(package);
        }
        state.latest_work_package = None;
        None
    }

    pub fn get_stage_work_package(&self) -> Option<WorkPackage> {
        let mut state = self.state.lock();
        Self::expire_work_packages_locked(&mut state);
        let queue_len = state.stage_work_package_queue.len();
        for _ in 0..queue_len {
            let Some(package_id) = state.stage_work_package_queue.pop_front() else {
                break;
            };
            let Some(record) = state.work_packages.get(&package_id) else {
                continue;
            };
            if record.submissions >= self.config.max_submissions_per_package {
                continue;
            }
            let package = record.package.clone();
            state.stage_work_package_queue.push_back(package_id.clone());
            state.latest_stage_work_package = Some(package_id.clone());
            state
                .work_status
                .entry(package_id.clone())
                .or_insert(WorkStatus::Pending);
            return Some(package);
        }
        state.latest_stage_work_package = None;
        None
    }

    pub fn submit_external_work_result(
        &self,
        source: &str,
        package_id: &str,
        payload: pallet_shielded_pool::types::CandidateArtifact,
    ) -> Result<(), String> {
        let mut state = self.state.lock();
        Self::expire_work_packages_locked(&mut state);

        let source_key = source.trim().to_owned();
        if source_key.is_empty() {
            return Err("source is required".to_string());
        }
        let source_count = *state.source_submissions.get(&source_key).unwrap_or(&0);
        if source_count >= self.config.max_submissions_per_source {
            return Err("source submission rate limit exceeded".to_string());
        }

        let Some(record) = state.work_packages.get(package_id) else {
            return Err("unknown or expired work package".to_string());
        };
        let package = record.package.clone();
        let existing_submissions = record.submissions;
        if payload.version != pallet_shielded_pool::types::BLOCK_PROOF_BUNDLE_SCHEMA {
            state.work_status.insert(
                package_id.to_string(),
                WorkStatus::Rejected("unsupported bundle version".into()),
            );
            return Err("work result bundle version mismatch".to_string());
        }
        if payload.tx_count == 0 {
            state.work_status.insert(
                package_id.to_string(),
                WorkStatus::Rejected("tx_count must be non-zero".into()),
            );
            return Err("work result tx_count must be non-zero".to_string());
        }
        if existing_submissions >= self.config.max_submissions_per_package {
            state.work_status.insert(
                package_id.to_string(),
                WorkStatus::Rejected("package saturated".into()),
            );
            return Err("work package submission limit exceeded".to_string());
        }
        if payload.tx_count != package.tx_count {
            state.work_status.insert(
                package_id.to_string(),
                WorkStatus::Rejected("tx_count mismatch".into()),
            );
            return Err("work result tx_count mismatch".to_string());
        }

        if block_proof_bundle_payload_bytes(&payload) > self.config.max_payload_bytes {
            state.work_status.insert(
                package_id.to_string(),
                WorkStatus::Rejected("payload too large".into()),
            );
            return Err("work result payload exceeds max size".to_string());
        }

        if let Some(record) = state.work_packages.get_mut(package_id) {
            record.submissions = record.submissions.saturating_add(1);
        }
        state
            .source_submissions
            .insert(source_key, source_count.saturating_add(1));

        if package.stage_type == "leaf_batch_prove" {
            let maybe_bundle =
                Self::register_chunk_result_and_maybe_assemble(&mut state, &package, payload)?;
            state
                .work_status
                .insert(package_id.to_string(), WorkStatus::Accepted);
            if let Some(incoming) = maybe_bundle {
                let key = incoming.key.clone();
                let should_replace = match state.prepared.get(&key) {
                    Some(existing) => incoming.payload.tx_count > existing.payload.tx_count,
                    None => true,
                };
                if should_replace {
                    tracing::info!(
                        block_number = package.block_number,
                        tx_count = incoming.payload.tx_count,
                        flat_batches = incoming.payload.flat_batches.len(),
                        candidate_set_id = %package.candidate_set_id,
                        "Assembled fan-out external chunk proofs into prepared bundle"
                    );
                    state.prepared.insert(key, incoming);
                }
            }
            Ok(())
        } else {
            let key = candidate_bundle_key(package.parent_hash, &payload);
            let incoming = PreparedBundle {
                key: key.clone(),
                payload,
                candidate_txs: package.candidate_txs,
                build_ms: 0,
            };

            let should_replace = match state.prepared.get(&key) {
                Some(existing) => incoming.payload.tx_count > existing.payload.tx_count,
                None => true,
            };

            if should_replace {
                state.prepared.insert(key, incoming);
                state
                    .work_status
                    .insert(package_id.to_string(), WorkStatus::Accepted);
                Ok(())
            } else {
                state.work_status.insert(
                    package_id.to_string(),
                    WorkStatus::Rejected("existing prepared bundle is better".into()),
                );
                Err("submission not selected".to_string())
            }
        }
    }

    pub fn submit_external_stage_result(
        &self,
        source: &str,
        package_id: &str,
        payload_bytes: Vec<u8>,
    ) -> Result<(), String> {
        let mut state = self.state.lock();
        Self::expire_work_packages_locked(&mut state);

        let source_key = source.trim().to_owned();
        if source_key.is_empty() {
            return Err("source is required".to_string());
        }
        let source_count = *state.source_submissions.get(&source_key).unwrap_or(&0);
        if source_count >= self.config.max_submissions_per_source {
            return Err("source submission rate limit exceeded".to_string());
        }
        let Some(record) = state.work_packages.get(package_id) else {
            return Err("unknown or expired work package".to_string());
        };
        let package = record.package.clone();
        if record.submissions >= self.config.max_submissions_per_package {
            state.work_status.insert(
                package_id.to_string(),
                WorkStatus::Rejected("package saturated".into()),
            );
            return Err("work package submission limit exceeded".to_string());
        }
        if payload_bytes.len() > self.config.max_payload_bytes {
            state.work_status.insert(
                package_id.to_string(),
                WorkStatus::Rejected("payload too large".into()),
            );
            return Err("work result payload exceeds max size".to_string());
        }
        match package.stage_type.as_str() {
            "leaf_batch_prove" => {
                let leaf_payload = package
                    .leaf_batch_payload
                    .as_ref()
                    .ok_or_else(|| "missing leaf batch payload".to_string())?;
                consensus::verify_aggregation_proof(
                    &payload_bytes,
                    leaf_payload.tx_proofs.len(),
                    &leaf_payload.tx_statements_commitment,
                )
                .map_err(|err| format!("leaf stage proof verification failed: {err}"))?;
            }
            "merge_node_prove" => {
                let merge_payload = package
                    .merge_node_payload
                    .as_ref()
                    .ok_or_else(|| "missing merge payload".to_string())?;
                consensus::verify_aggregation_proof(
                    &payload_bytes,
                    package.tx_count as usize,
                    &merge_payload.tx_statements_commitment,
                )
                .map_err(|err| format!("merge stage proof verification failed: {err}"))?;
            }
            _ => {
                return Err("package is not a recursive stage package".to_string());
            }
        }

        if let Some(record) = state.work_packages.get_mut(package_id) {
            record.submissions = record.submissions.saturating_add(1);
        }
        state
            .source_submissions
            .insert(source_key, source_count.saturating_add(1));

        let maybe_prepared = self.apply_recursive_stage_result_locked(
            &mut state,
            package_id,
            &package.candidate_set_id,
            package.parent_hash,
            payload_bytes,
        )?;
        state
            .work_status
            .insert(package_id.to_string(), WorkStatus::Accepted);
        if let Some(bundle) = maybe_prepared {
            let key = bundle.key.clone();
            state.prepared.insert(key, bundle);
        }
        Ok(())
    }

    fn register_chunk_result_and_maybe_assemble(
        state: &mut CoordinatorState,
        package: &WorkPackage,
        payload: pallet_shielded_pool::types::CandidateArtifact,
    ) -> Result<Option<PreparedBundle>, String> {
        if payload.proof_mode != pallet_shielded_pool::types::BlockProofMode::FlatBatches {
            return Err("fan-out chunk payload must use FlatBatches mode".to_string());
        }
        if payload.flat_batches.is_empty() {
            return Err("fan-out chunk payload must include at least one batch proof".to_string());
        }
        let candidate_set_id = package.candidate_set_id.clone();
        let (parent_hash, candidate_txs, assembled_payload) = {
            let Some(assembly) = state.fanout_assemblies.get_mut(&candidate_set_id) else {
                return Err("missing fan-out assembly state for work package".to_string());
            };
            if assembly.parent_hash != package.parent_hash
                || assembly.block_number != package.block_number
            {
                return Err(
                    "fan-out assembly state does not match package parent/block".to_string()
                );
            }
            let expected_ids = assembly
                .chunks
                .iter()
                .map(|chunk| chunk.package_id.as_str())
                .collect::<HashSet<_>>();
            if !expected_ids.contains(package.package_id.as_str()) {
                return Err("work package is not part of active fan-out chunk plan".to_string());
            }

            assembly
                .received
                .insert(package.package_id.clone(), payload);
            if assembly.received.len() < assembly.expected_chunks as usize {
                return Ok(None);
            }

            let assembled_payload = Self::assemble_fanout_payload(assembly)?;
            (
                assembly.parent_hash,
                assembly.candidate_txs.clone(),
                assembled_payload,
            )
        };
        state.fanout_assemblies.remove(&candidate_set_id);

        let key = candidate_bundle_key(parent_hash, &assembled_payload);
        Ok(Some(PreparedBundle {
            key,
            payload: assembled_payload,
            candidate_txs,
            build_ms: 0,
        }))
    }

    fn assemble_fanout_payload(
        assembly: &FanoutAssemblyState,
    ) -> Result<pallet_shielded_pool::types::CandidateArtifact, String> {
        let mut chunk_specs = assembly.chunks.clone();
        chunk_specs.sort_by_key(|chunk| chunk.start_tx_index);
        let Some(first_spec) = chunk_specs.first() else {
            return Err("fan-out assembly has no chunk specifications".to_string());
        };
        let Some(anchor_payload) = assembly.received.get(&first_spec.package_id) else {
            return Err("fan-out assembly missing first chunk payload".to_string());
        };
        if anchor_payload.proof_mode != pallet_shielded_pool::types::BlockProofMode::FlatBatches {
            return Err("fan-out assembly anchor payload is not FlatBatches".to_string());
        }
        if anchor_payload.flat_batches.is_empty() {
            return Err("fan-out assembly anchor payload has no batch proofs".to_string());
        }

        let mut expected_start = 0u32;
        let mut covered = 0u32;
        let mut seen_ranges = HashSet::new();
        let mut flat_batches = Vec::with_capacity(chunk_specs.len());
        for chunk in chunk_specs {
            if !seen_ranges.insert((chunk.start_tx_index, chunk.tx_count)) {
                return Err("fan-out assembly has duplicate chunk range".to_string());
            }
            if chunk.start_tx_index != expected_start {
                return Err("fan-out chunk coverage is non-contiguous".to_string());
            }
            let Some(chunk_payload) = assembly.received.get(&chunk.package_id) else {
                return Err("fan-out assembly missing chunk payload".to_string());
            };
            if chunk_payload.proof_mode != pallet_shielded_pool::types::BlockProofMode::FlatBatches
            {
                return Err("fan-out chunk payload is not FlatBatches".to_string());
            }
            if chunk_payload.flat_batches.is_empty() {
                return Err("fan-out chunk payload has no batch proofs".to_string());
            }
            if chunk_payload.tx_statements_commitment != anchor_payload.tx_statements_commitment {
                return Err(
                    "fan-out chunk payload tx_statements_commitment mismatch across chunks"
                        .to_string(),
                );
            }
            if chunk_payload.da_root != anchor_payload.da_root
                || chunk_payload.da_chunk_count != anchor_payload.da_chunk_count
            {
                return Err("fan-out chunk payload DA metadata mismatch across chunks".to_string());
            }
            if chunk_payload.commitment_proof.data != anchor_payload.commitment_proof.data {
                return Err(
                    "fan-out chunk payload commitment proof mismatch across chunks".to_string(),
                );
            }
            let chunk_batch = chunk_payload
                .flat_batches
                .first()
                .ok_or_else(|| "fan-out chunk payload missing first batch proof".to_string())?;
            if chunk_batch.tx_count != chunk.tx_count {
                return Err("fan-out chunk payload tx_count mismatch".to_string());
            }
            flat_batches.push(pallet_shielded_pool::types::BatchProofItem {
                start_tx_index: chunk.start_tx_index,
                tx_count: chunk.tx_count,
                proof_format: chunk_batch.proof_format,
                proof: chunk_batch.proof.clone(),
            });
            expected_start = expected_start.saturating_add(chunk.tx_count as u32);
            covered = covered.saturating_add(chunk.tx_count as u32);
        }

        if covered != assembly.candidate_txs.len() as u32 {
            return Err("fan-out chunk coverage does not match candidate tx count".to_string());
        }

        Ok(pallet_shielded_pool::types::CandidateArtifact {
            version: pallet_shielded_pool::types::BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count: covered,
            tx_statements_commitment: anchor_payload.tx_statements_commitment,
            da_root: anchor_payload.da_root,
            da_chunk_count: anchor_payload.da_chunk_count,
            commitment_proof: anchor_payload.commitment_proof.clone(),
            proof_mode: pallet_shielded_pool::types::BlockProofMode::FlatBatches,
            flat_batches,
            merge_root: None,
            artifact_claim: anchor_payload.artifact_claim.clone(),
        })
    }

    pub fn get_work_status(&self, package_id: &str) -> Option<WorkStatus> {
        let mut state = self.state.lock();
        Self::expire_work_packages_locked(&mut state);
        state.work_status.get(package_id).cloned()
    }

    async fn tick(self: &Arc<Self>) {
        self.drain_worker_results();
        let (parent_hash, best_number) = (self.best_block_fn)();
        {
            let mut state = self.state.lock();
            if state.current_parent != Some(parent_hash) {
                state.current_parent = Some(parent_hash);
                state.generation = state.generation.wrapping_add(1);
                state.target_batch_scheduled_at_ms = None;
                state.adaptive_liveness_fired_generation = None;
                state.selected_txs.clear();
                state.work_packages.clear();
                state.work_package_queue.clear();
                state.stage_work_package_queue.clear();
                state.latest_work_package = None;
                state.latest_stage_work_package = None;
                state.fanout_assemblies.clear();
                state.recursive_assemblies.clear();
                state.work_status.clear();
                state.source_submissions.clear();
                state.pending_jobs.clear();
                state.inflight_stage_meta.clear();
                state.inflight_candidates.clear();
            }
        }

        self.ensure_job_queue(parent_hash, best_number);
        self.dispatch_jobs();
    }

    fn ensure_job_queue(&self, parent_hash: H256, best_number: u64) {
        let mut candidate = (self.pending_txs_fn)(self.config.target_txs);
        candidate.truncate(self.config.target_txs);

        let mut state = self.state.lock();
        if state.current_parent != Some(parent_hash) {
            return;
        }

        let mut existing_best = Self::best_candidate_len_locked(&state);
        if candidate.is_empty() {
            if existing_best == 0 {
                state.target_batch_scheduled_at_ms = None;
                state.adaptive_liveness_fired_generation = None;
                state.selected_txs.clear();
                state.work_packages.clear();
                state.work_package_queue.clear();
                state.stage_work_package_queue.clear();
                state.latest_work_package = None;
                state.latest_stage_work_package = None;
                state.fanout_assemblies.clear();
                state.work_status.clear();
                state.source_submissions.clear();
            }
            return;
        }

        // Throughput-first mode: when the liveness lane is disabled, wait for
        // a full target batch before scheduling expensive proving work.
        if !self.config.liveness_lane && candidate.len() < self.config.target_txs {
            return;
        }

        // Allow upsizing on the same parent as more pool transactions arrive.
        if candidate.len() <= existing_best {
            self.maybe_schedule_adaptive_liveness_lane(
                &mut state,
                parent_hash,
                best_number,
                &candidate,
                existing_best,
            );
            return;
        }

        // If a larger candidate arrives while current-generation jobs are still
        // proving, rotate generation so scheduler can dispatch the larger batch
        // immediately instead of waiting for stale low-tx jobs to finish.
        let inflight_current = Self::inflight_current_generation_count(&state);
        let full_target_ready = candidate.len() >= self.config.target_txs;
        let full_target_not_yet_scheduled = existing_best < self.config.target_txs;
        if inflight_current > 0 && full_target_ready && full_target_not_yet_scheduled {
            let dropped_inflight = state.inflight_jobs.len();
            tracing::info!(
                block_number = best_number.saturating_add(1),
                existing_best_tx_count = existing_best,
                candidate_tx_count = candidate.len(),
                inflight_current,
                dropped_inflight,
                target_txs = self.config.target_txs,
                generation = state.generation,
                "Preempting in-flight proven-batch jobs for larger candidate set"
            );
            state.generation = state.generation.wrapping_add(1);
            state.target_batch_scheduled_at_ms = None;
            state.adaptive_liveness_fired_generation = None;
            state.selected_txs.clear();
            state.pending_jobs.clear();
            // Stop counting stale jobs against scheduler capacity. They will
            // still finish in the background and be ignored by generation.
            state.inflight_jobs.clear();
            state.inflight_stage_meta.clear();
            state.inflight_candidates.clear();
            state.work_packages.clear();
            state.work_package_queue.clear();
            state.latest_work_package = None;
            state.fanout_assemblies.clear();
            state.recursive_assemblies.clear();
            state.work_status.clear();
            state.source_submissions.clear();
            existing_best = Self::best_candidate_len_locked(&state);
            if candidate.len() <= existing_best {
                return;
            }
        }

        // In checkpoint mode, candidate upsizing follows a deterministic ladder derived
        // from target_txs instead of every +1 mempool increment. This prevents building
        // a new heavy recursion shape for each intermediate tx_count.
        let plan_total_txs = if self.config.incremental_upsizing
            || !self.config.liveness_lane
            || self.config.queue_capacity <= 1
        {
            candidate.len()
        } else {
            self.config.target_txs.max(candidate.len())
        };
        let mut variant_tx_counts = Self::candidate_variant_tx_counts(
            plan_total_txs,
            self.config.queue_capacity,
            self.config.liveness_lane,
        );
        if plan_total_txs != candidate.len() {
            variant_tx_counts.retain(|count| *count <= candidate.len());
        }
        variant_tx_counts.retain(|count| *count > existing_best);
        if variant_tx_counts.is_empty() {
            return;
        }

        let mut candidate_variants = VecDeque::with_capacity(variant_tx_counts.len());
        for tx_count in variant_tx_counts.iter().copied() {
            candidate_variants.push_back(candidate[..tx_count].to_vec());
        }

        tracing::debug!(
            block_number = best_number.saturating_add(1),
            existing_best_tx_count = existing_best,
            candidate_tx_count = candidate.len(),
            plan_total_txs,
            variant_tx_counts = ?variant_tx_counts,
            incremental_upsizing = self.config.incremental_upsizing,
            "Scheduling proven-batch candidate variants"
        );

        // Keep local block assembly on a liveness lane first so mining does not
        // stall while larger candidates are still proving.
        if state.selected_txs.is_empty() {
            if let Some(liveness_candidate) = candidate_variants.front().cloned() {
                state.selected_txs = liveness_candidate;
            }
        }

        // Publish the largest candidate either as recursive leaf/merge work for
        // MergeRoot mode or as legacy fan-out work for FlatBatches.
        if let Some(primary_candidate) = candidate_variants.back().cloned() {
            if primary_candidate.len() >= self.config.target_txs {
                state.target_batch_scheduled_at_ms = Some(Self::now_ms());
                state.adaptive_liveness_fired_generation = None;
            }
            let block_number = best_number.saturating_add(1);
            let candidate_set_id =
                Self::work_package_id(parent_hash, block_number, &primary_candidate);
            state.work_packages.clear();
            state.work_package_queue.clear();
            state.stage_work_package_queue.clear();
            state.latest_work_package = None;
            state.latest_stage_work_package = None;
            state.work_status.clear();
            state.source_submissions.clear();
            state.fanout_assemblies.clear();
            state.recursive_assemblies.clear();

            let mut handled_recursive = false;
            if let Some(builder) = self.build_root_finalize_work_fn.as_ref() {
                match builder(parent_hash, block_number, primary_candidate.clone()) {
                    Ok(Some(root_payload)) => {
                        handled_recursive = true;
                        candidate_variants.pop_back();
                        let tree_levels =
                            Self::recursive_tree_levels_for_tx_count(primary_candidate.len());
                        let leaf_fan_in = Self::leaf_fan_in();
                        let expected_chunks =
                            primary_candidate.len().div_ceil(leaf_fan_in).min(u16::MAX as usize)
                                as u16;
                        let mut chunk_plans = Vec::new();
                        for (chunk_index, (proof_chunk, hash_chunk)) in root_payload
                            .tx_proofs
                            .chunks(leaf_fan_in)
                            .zip(root_payload.statement_hashes.chunks(leaf_fan_in))
                            .enumerate()
                        {
                            let start = (chunk_index * leaf_fan_in) as u32;
                            let end = (start as usize + proof_chunk.len()).min(primary_candidate.len());
                            let leaf_payload = LeafBatchWorkData {
                                statement_hashes: hash_chunk.to_vec(),
                                tx_proofs: proof_chunk.to_vec(),
                                tx_statements_commitment: root_payload.tx_statements_commitment,
                                tree_levels,
                                root_level: 0,
                            };
                            let package = Self::build_leaf_stage_work_package(
                                parent_hash,
                                block_number,
                                candidate_set_id.clone(),
                                primary_candidate[start as usize..end].to_vec(),
                                start,
                                expected_chunks,
                                primary_candidate.len(),
                                self.config.work_package_ttl,
                                leaf_payload.clone(),
                            );
                            let package_id = package.package_id.clone();
                            chunk_plans.push(ChunkPlan {
                                package_id: package_id.clone(),
                                start_tx_index: package.chunk_start_tx_index,
                                tx_count: package.chunk_tx_count,
                            });
                            state.latest_stage_work_package = Some(package_id.clone());
                            state.stage_work_package_queue.push_back(package_id.clone());
                            state.work_packages.insert(
                                package_id.clone(),
                                WorkPackageRecord {
                                    package: package.clone(),
                                    submissions: 0,
                                },
                            );
                            state.work_status.insert(package_id.clone(), WorkStatus::Pending);
                            if self.worker_pool.worker_count() > 0 {
                                let job = QueuedJob {
                                    id: state.next_job_id,
                                    package_id: package_id.clone(),
                                    candidate_set_id: candidate_set_id.clone(),
                                    generation: state.generation,
                                    parent_hash,
                                    block_number,
                                    stage_type: "leaf_batch_prove".to_string(),
                                    level: 0,
                                    arity: Self::merge_fan_in() as u16,
                                    shape_id: package.shape_id,
                                    dependencies: Vec::new(),
                                    enqueued_at: Instant::now(),
                                    candidate_txs: package.candidate_txs.clone(),
                                    leaf_batch_payload: Some(leaf_payload),
                                    merge_node_payload: None,
                                };
                                state.next_job_id = state.next_job_id.wrapping_add(1);
                                state.pending_jobs.push_back(job);
                            }
                        }
                        state.recursive_assemblies.insert(
                            candidate_set_id.clone(),
                            RecursiveTreeAssemblyState {
                                parent_hash,
                                block_number,
                                candidate_txs: primary_candidate.clone(),
                                root_finalize_payload: root_payload,
                                leaf_chunks: chunk_plans,
                                leaf_results: HashMap::new(),
                                merge_package_id: None,
                            },
                        );
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::warn!(
                            block_number,
                            tx_count = primary_candidate.len(),
                            error = %error,
                            "Failed to build recursive stage payloads; falling back to legacy path"
                        );
                    }
                }
            }

            if !handled_recursive {
                let slot_txs = Self::batch_slot_txs();
                let chunks = Self::split_candidate_into_chunks(&primary_candidate, slot_txs);
                let expected_chunks = chunks.len().min(u16::MAX as usize) as u16;

                let mut chunk_plans = Vec::with_capacity(chunks.len());
                for (chunk_start_tx_index, chunk_txs) in chunks {
                    let package = Self::build_work_package(
                        parent_hash,
                        block_number,
                        candidate_set_id.clone(),
                        chunk_txs,
                        chunk_start_tx_index,
                        expected_chunks,
                        self.config.work_package_ttl,
                    );
                    let package_id = package.package_id.clone();
                    chunk_plans.push(ChunkPlan {
                        package_id: package_id.clone(),
                        start_tx_index: package.chunk_start_tx_index,
                        tx_count: package.chunk_tx_count,
                    });
                    state.latest_work_package = Some(package_id.clone());
                    state.work_package_queue.push_back(package_id.clone());
                    state.work_packages.insert(
                        package_id.clone(),
                        WorkPackageRecord {
                            package,
                            submissions: 0,
                        },
                    );
                    state.work_status.insert(package_id, WorkStatus::Pending);
                }

                if let Some(builder) = self.build_root_finalize_work_fn.as_ref() {
                    match builder(parent_hash, block_number, primary_candidate.clone()) {
                        Ok(Some(root_payload)) => {
                            let package = Self::build_root_finalize_work_package(
                                parent_hash,
                                block_number,
                                candidate_set_id.clone(),
                                primary_candidate.clone(),
                                self.config.work_package_ttl,
                                root_payload,
                            );
                            let package_id = package.package_id.clone();
                            state.latest_stage_work_package = Some(package_id.clone());
                            state.stage_work_package_queue.push_back(package_id.clone());
                            state.work_packages.insert(
                                package_id.clone(),
                                WorkPackageRecord {
                                    package,
                                    submissions: 0,
                                },
                            );
                            state.work_status.insert(package_id, WorkStatus::Pending);
                        }
                        Ok(None) => {}
                        Err(error) => {
                            tracing::warn!(
                                block_number,
                                tx_count = primary_candidate.len(),
                                error = %error,
                                "Failed to publish root-finalize stage work package"
                            );
                        }
                    }
                }

                state.fanout_assemblies.insert(
                    candidate_set_id,
                    FanoutAssemblyState {
                        parent_hash,
                        block_number,
                        candidate_txs: primary_candidate,
                        expected_chunks,
                        chunks: chunk_plans,
                        received: HashMap::new(),
                    },
                );
            }
        }

        while let Some(candidate_txs) = candidate_variants.pop_front() {
            let arity = Self::aggregation_tree_arity();
            let (level, shape_id, dependencies) = Self::root_stage_metadata(
                parent_hash,
                best_number.saturating_add(1),
                &candidate_txs,
                arity,
            );
            let stage_type = "root_finalize".to_string();
            let job = QueuedJob {
                id: state.next_job_id,
                package_id: Self::work_package_id(
                    parent_hash,
                    best_number.saturating_add(1),
                    &candidate_txs,
                ),
                candidate_set_id: Self::work_package_id(
                    parent_hash,
                    best_number.saturating_add(1),
                    &candidate_txs,
                ),
                generation: state.generation,
                parent_hash,
                block_number: best_number.saturating_add(1),
                stage_type,
                level,
                arity,
                shape_id,
                dependencies,
                enqueued_at: Instant::now(),
                candidate_txs,
                leaf_batch_payload: None,
                merge_node_payload: None,
            };
            state.next_job_id = state.next_job_id.wrapping_add(1);
            state.pending_jobs.push_back(job);
        }
    }

    fn maybe_schedule_adaptive_liveness_lane(
        &self,
        state: &mut CoordinatorState,
        parent_hash: H256,
        best_number: u64,
        candidate: &[Vec<u8>],
        existing_best: usize,
    ) {
        if self.config.liveness_lane || self.config.adaptive_liveness_timeout.is_zero() {
            return;
        }
        if candidate.is_empty() || existing_best < self.config.target_txs {
            return;
        }
        if Self::best_prepared_candidate_locked(state).is_some() {
            return;
        }
        if state.adaptive_liveness_fired_generation == Some(state.generation) {
            return;
        }
        let Some(target_scheduled_at_ms) = state.target_batch_scheduled_at_ms else {
            return;
        };
        let now_ms = Self::now_ms();
        if now_ms <= target_scheduled_at_ms {
            return;
        }
        let elapsed_ms = now_ms - target_scheduled_at_ms;
        if elapsed_ms < self.config.adaptive_liveness_timeout.as_millis() as u64 {
            return;
        }

        let singleton_candidate = vec![candidate[0].clone()];
        let singleton_queued = state.pending_jobs.iter().any(|job| {
            job.generation == state.generation
                && job.parent_hash == parent_hash
                && job.candidate_txs.len() == 1
        });
        let singleton_inflight = state.inflight_candidates.values().any(|txs| txs.len() == 1);
        if singleton_queued || singleton_inflight {
            state.adaptive_liveness_fired_generation = Some(state.generation);
            return;
        }

        if state.selected_txs.is_empty() || state.selected_txs.len() > 1 {
            state.selected_txs = singleton_candidate.clone();
        }
        let arity = Self::aggregation_tree_arity();
        let (level, shape_id, dependencies) = Self::root_stage_metadata(
            parent_hash,
            best_number.saturating_add(1),
            &singleton_candidate,
            arity,
        );
        let job = QueuedJob {
            id: state.next_job_id,
            package_id: Self::work_package_id(
                parent_hash,
                best_number.saturating_add(1),
                &singleton_candidate,
            ),
            candidate_set_id: Self::work_package_id(
                parent_hash,
                best_number.saturating_add(1),
                &singleton_candidate,
            ),
            generation: state.generation,
            parent_hash,
            block_number: best_number.saturating_add(1),
            stage_type: "root_finalize".to_string(),
            level,
            arity,
            shape_id,
            dependencies,
            enqueued_at: Instant::now(),
            candidate_txs: singleton_candidate,
            leaf_batch_payload: None,
            merge_node_payload: None,
        };
        state.next_job_id = state.next_job_id.wrapping_add(1);
        state.pending_jobs.push_front(job);
        state.adaptive_liveness_fired_generation = Some(state.generation);

        tracing::warn!(
            block_number = best_number.saturating_add(1),
            target_txs = self.config.target_txs,
            elapsed_ms,
            adaptive_liveness_timeout_ms = self.config.adaptive_liveness_timeout.as_millis() as u64,
            generation = state.generation,
            "Scheduling adaptive singleton liveness lane while target-batch proving remains cold"
        );
    }

    fn best_candidate_len_locked(state: &CoordinatorState) -> usize {
        Self::best_candidate_len_for_parent_locked(state, state.current_parent)
    }

    fn best_candidate_len_for_parent_locked(
        state: &CoordinatorState,
        parent_hash: Option<H256>,
    ) -> usize {
        let selected = state.selected_txs.len();
        let prepared = state
            .prepared
            .values()
            .filter(|bundle| Some(bundle.key.parent_hash) == parent_hash)
            .map(|bundle| bundle.candidate_txs.len())
            .max()
            .unwrap_or(0);
        let pending = state
            .pending_jobs
            .iter()
            .filter(|job| {
                job.generation == state.generation && Some(job.parent_hash) == parent_hash
            })
            .map(|job| job.candidate_txs.len())
            .max()
            .unwrap_or(0);
        let inflight = state
            .inflight_candidates
            .iter()
            .filter_map(|(job_id, candidate_txs)| {
                if state.inflight_jobs.get(job_id).copied() == Some(state.generation) {
                    Some(candidate_txs.len())
                } else {
                    None
                }
            })
            .max()
            .unwrap_or(0);
        selected.max(prepared).max(pending).max(inflight)
    }

    fn candidate_variant_tx_counts(
        total_txs: usize,
        queue_capacity: usize,
        liveness_lane: bool,
    ) -> Vec<usize> {
        if total_txs == 0 {
            return Vec::new();
        }
        if !liveness_lane {
            return vec![total_txs];
        }
        let capacity = queue_capacity.max(1);
        if capacity == 1 || total_txs == 1 {
            return vec![total_txs];
        }

        // Take the largest geometric trims first, then always include a
        // singleton liveness lane so local authoring can keep progressing even
        // under heavy proving load.
        let mut counts = Vec::with_capacity(capacity);
        let mut next = total_txs;
        counts.push(next);
        while counts.len() < capacity.saturating_sub(1) && next > 1 {
            next = next.div_ceil(2);
            counts.push(next);
        }
        counts.push(1);
        counts.sort_unstable();
        counts.dedup();
        counts
    }

    fn batch_slot_txs() -> usize {
        std::env::var("HEGEMON_BATCH_SLOT_TXS")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(16)
            .max(1)
    }

    fn leaf_fan_in() -> usize {
        std::env::var("HEGEMON_AGG_LEAF_FANIN")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(Self::DEFAULT_LEAF_FAN_IN)
            .max(1)
    }

    fn merge_fan_in() -> usize {
        std::env::var("HEGEMON_AGG_MERGE_FANIN")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(Self::DEFAULT_MERGE_FAN_IN)
            .max(1)
    }

    fn recursive_tree_levels_for_tx_count(tx_count: usize) -> u16 {
        if tx_count <= Self::leaf_fan_in() {
            1
        } else {
            2
        }
    }

    fn split_candidate_into_chunks(
        candidate_txs: &[Vec<u8>],
        slot_txs: usize,
    ) -> Vec<(u32, Vec<Vec<u8>>)> {
        let mut chunks = Vec::new();
        if candidate_txs.is_empty() {
            return chunks;
        }
        let chunk_size = slot_txs.max(1);
        let mut start = 0usize;
        while start < candidate_txs.len() {
            let end = (start + chunk_size).min(candidate_txs.len());
            let chunk = candidate_txs[start..end].to_vec();
            chunks.push((start as u32, chunk));
            start = end;
        }
        chunks
    }

    fn chunk_work_package_id(
        parent_hash: H256,
        block_number: u64,
        candidate_set_id: &str,
        chunk_start_tx_index: u32,
        chunk_tx_count: u16,
    ) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(parent_hash.as_bytes());
        bytes.extend_from_slice(&block_number.to_le_bytes());
        bytes.extend_from_slice(candidate_set_id.as_bytes());
        bytes.extend_from_slice(&chunk_start_tx_index.to_le_bytes());
        bytes.extend_from_slice(&chunk_tx_count.to_le_bytes());
        hex::encode(sp_core::hashing::blake2_256(&bytes))
    }

    fn build_leaf_stage_work_package(
        parent_hash: H256,
        block_number: u64,
        candidate_set_id: String,
        candidate_txs: Vec<Vec<u8>>,
        chunk_start_tx_index: u32,
        expected_chunks: u16,
        total_candidate_txs: usize,
        ttl: Duration,
        payload: LeafBatchWorkData,
    ) -> WorkPackage {
        let created_at_ms = Self::now_ms();
        let expires_at_ms = created_at_ms.saturating_add(ttl.as_millis() as u64);
        let chunk_tx_count = payload.tx_proofs.len().min(u16::MAX as usize) as u16;
        let candidate_digest = Self::candidate_digest(&candidate_txs);
        let stage_type = "leaf_batch_prove".to_string();
        let stage_index = chunk_start_tx_index / Self::leaf_fan_in().max(1) as u32;
        let shape_id = Self::work_package_shape_id(
            parent_hash,
            block_number,
            &stage_type,
            0,
            stage_index,
            Self::merge_fan_in() as u16,
            total_candidate_txs as u32,
            candidate_digest,
        );
        let package_id = Self::chunk_work_package_id(
            parent_hash,
            block_number,
            &candidate_set_id,
            chunk_start_tx_index,
            chunk_tx_count,
        );
        WorkPackage {
            package_id,
            parent_hash,
            block_number,
            candidate_set_id,
            chunk_start_tx_index,
            chunk_tx_count,
            expected_chunks,
            stage_type,
            level: 0,
            arity: Self::merge_fan_in() as u16,
            shape_id,
            dependencies: Vec::new(),
            tx_count: chunk_tx_count as u32,
            candidate_txs,
            leaf_batch_payload: Some(payload),
            merge_node_payload: None,
            root_finalize_payload: None,
            created_at_ms,
            expires_at_ms,
        }
    }

    fn build_merge_stage_work_package(
        parent_hash: H256,
        block_number: u64,
        candidate_set_id: String,
        candidate_txs: Vec<Vec<u8>>,
        dependencies: Vec<String>,
        ttl: Duration,
        payload: MergeNodeWorkData,
    ) -> WorkPackage {
        let created_at_ms = Self::now_ms();
        let expires_at_ms = created_at_ms.saturating_add(ttl.as_millis() as u64);
        let candidate_digest = Self::candidate_digest(&candidate_txs);
        let tx_count = candidate_txs.len() as u32;
        let package_id = Self::stage_work_id(
            parent_hash,
            block_number,
            "merge_node_prove",
            1,
            0,
            Self::merge_fan_in() as u16,
            tx_count,
            candidate_digest,
        );
        let shape_id = Self::work_package_shape_id(
            parent_hash,
            block_number,
            "merge_node_prove",
            1,
            0,
            Self::merge_fan_in() as u16,
            tx_count,
            candidate_digest,
        );
        WorkPackage {
            package_id,
            parent_hash,
            block_number,
            candidate_set_id,
            chunk_start_tx_index: 0,
            chunk_tx_count: dependencies.len().min(u16::MAX as usize) as u16,
            expected_chunks: 1,
            stage_type: "merge_node_prove".to_string(),
            level: 1,
            arity: Self::merge_fan_in() as u16,
            shape_id,
            dependencies,
            tx_count,
            candidate_txs,
            leaf_batch_payload: None,
            merge_node_payload: Some(payload),
            root_finalize_payload: None,
            created_at_ms,
            expires_at_ms,
        }
    }

    fn build_work_package(
        parent_hash: H256,
        block_number: u64,
        candidate_set_id: String,
        candidate_txs: Vec<Vec<u8>>,
        chunk_start_tx_index: u32,
        expected_chunks: u16,
        ttl: Duration,
    ) -> WorkPackage {
        let created_at_ms = Self::now_ms();
        let expires_at_ms = created_at_ms.saturating_add(ttl.as_millis() as u64);
        let tx_count = candidate_txs.len() as u32;
        let chunk_tx_count = tx_count.min(u16::MAX as u32) as u16;
        let arity = Self::aggregation_tree_arity();
        let candidate_digest = Self::candidate_digest(&candidate_txs);
        let stage_type = "leaf_batch_prove".to_string();
        let stage_index = chunk_start_tx_index / Self::batch_slot_txs().max(1) as u32;
        let shape_id = Self::work_package_shape_id(
            parent_hash,
            block_number,
            &stage_type,
            0,
            stage_index,
            arity,
            tx_count,
            candidate_digest,
        );
        let dependencies = Vec::new();
        let package_id = Self::chunk_work_package_id(
            parent_hash,
            block_number,
            &candidate_set_id,
            chunk_start_tx_index,
            chunk_tx_count,
        );
        WorkPackage {
            package_id,
            parent_hash,
            block_number,
            candidate_set_id,
            chunk_start_tx_index,
            chunk_tx_count,
            expected_chunks,
            stage_type,
            level: 0,
            arity,
            shape_id,
            dependencies,
            tx_count,
            candidate_txs,
            leaf_batch_payload: None,
            merge_node_payload: None,
            root_finalize_payload: None,
            created_at_ms,
            expires_at_ms,
        }
    }

    fn build_root_finalize_work_package(
        parent_hash: H256,
        block_number: u64,
        candidate_set_id: String,
        candidate_txs: Vec<Vec<u8>>,
        ttl: Duration,
        payload: RootFinalizeWorkData,
    ) -> WorkPackage {
        let created_at_ms = Self::now_ms();
        let expires_at_ms = created_at_ms.saturating_add(ttl.as_millis() as u64);
        let tx_count = candidate_txs.len() as u32;
        let arity = Self::aggregation_tree_arity();
        let candidate_digest = Self::candidate_digest(&candidate_txs);
        let (level, shape_id, dependencies) =
            Self::root_stage_metadata(parent_hash, block_number, &candidate_txs, arity);
        let package_id = Self::stage_work_id(
            parent_hash,
            block_number,
            "root_finalize",
            level,
            0,
            arity,
            tx_count,
            candidate_digest,
        );
        WorkPackage {
            package_id,
            parent_hash,
            block_number,
            candidate_set_id,
            chunk_start_tx_index: 0,
            chunk_tx_count: tx_count.min(u16::MAX as u32) as u16,
            expected_chunks: 1,
            stage_type: "root_finalize".to_string(),
            level,
            arity,
            shape_id,
            dependencies,
            tx_count,
            candidate_txs,
            leaf_batch_payload: None,
            merge_node_payload: None,
            root_finalize_payload: Some(payload),
            created_at_ms,
            expires_at_ms,
        }
    }

    fn work_package_id(parent_hash: H256, block_number: u64, candidate_txs: &[Vec<u8>]) -> String {
        let mut bytes =
            Vec::with_capacity(32 + 8 + candidate_txs.iter().map(Vec::len).sum::<usize>());
        bytes.extend_from_slice(parent_hash.as_bytes());
        bytes.extend_from_slice(&block_number.to_le_bytes());
        for tx in candidate_txs {
            bytes.extend_from_slice(tx);
        }
        let digest = sp_core::hashing::blake2_256(&bytes);
        hex::encode(digest)
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn retire_package_locked(state: &mut CoordinatorState, package_id: &str) {
        state.work_packages.remove(package_id);
        state
            .work_package_queue
            .retain(|queued_id| queued_id != package_id);
        state
            .stage_work_package_queue
            .retain(|queued_id| queued_id != package_id);
    }

    fn leaf_manifest_commitment(statement_hashes: &[[u8; 48]]) -> Result<[u8; 48], String> {
        let leaf_fan_in = Self::leaf_fan_in();
        let mut manifest_material = Vec::new();
        manifest_material.extend_from_slice(b"agg-leaf-manifest-v1");
        manifest_material.extend_from_slice(&(leaf_fan_in as u16).to_le_bytes());
        manifest_material.extend_from_slice(&(statement_hashes.len() as u32).to_le_bytes());
        for (leaf_index, chunk) in statement_hashes.chunks(leaf_fan_in).enumerate() {
            let leaf_commitment = CommitmentBlockProver::commitment_from_statement_hashes(chunk)
                .map_err(|err| format!("leaf commitment derivation failed: {err}"))?;
            let mut descriptor = Vec::new();
            descriptor.extend_from_slice(b"agg-leaf-v1");
            descriptor.extend_from_slice(&(leaf_index as u32).to_le_bytes());
            descriptor.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
            descriptor.extend_from_slice(&leaf_commitment);
            manifest_material.extend_from_slice(&blake3_384(&descriptor));
        }
        Ok(blake3_384(&manifest_material))
    }

    fn assemble_recursive_prepared_bundle(
        parent_hash: H256,
        candidate_txs: Vec<Vec<u8>>,
        root_payload: RootFinalizeWorkData,
        root_aggregation_proof: Vec<u8>,
    ) -> Result<PreparedBundle, String> {
        let commitment_proof = CommitmentBlockProver::new()
            .prove_from_statement_hashes_with_inputs(
                &root_payload.statement_hashes,
                root_payload.starting_state_root,
                root_payload.ending_state_root,
                root_payload.starting_kernel_root,
                root_payload.ending_kernel_root,
                root_payload.nullifier_root,
                root_payload.da_root,
                root_payload.nullifiers.clone(),
                root_payload.sorted_nullifiers.clone(),
            )
            .map_err(|err| format!("commitment proof generation failed: {err}"))?;
        let tree_levels = Self::recursive_tree_levels_for_tx_count(candidate_txs.len());
        let leaf_count = candidate_txs.len().div_ceil(Self::leaf_fan_in()) as u32;
        let leaf_manifest_commitment = Self::leaf_manifest_commitment(&root_payload.statement_hashes)?;
        let merge_root = pallet_shielded_pool::types::MergeRootProofPayload {
            root_proof: pallet_shielded_pool::types::StarkProof::from_bytes(
                encode_aggregation_proof_bytes(root_aggregation_proof),
            ),
            metadata: pallet_shielded_pool::types::MergeRootMetadata {
                tree_arity: Self::merge_fan_in() as u16,
                tree_levels,
                leaf_count,
                leaf_manifest_commitment,
            },
            diagnostics_leaf_proofs: Vec::new(),
        };
        let payload = pallet_shielded_pool::types::CandidateArtifact {
            version: pallet_shielded_pool::types::BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count: candidate_txs.len() as u32,
            tx_statements_commitment: root_payload.tx_statements_commitment,
            da_root: root_payload.da_root,
            da_chunk_count: root_payload.da_chunk_count,
            commitment_proof: pallet_shielded_pool::types::StarkProof::from_bytes(
                commitment_proof.proof_bytes,
            ),
            proof_mode: pallet_shielded_pool::types::BlockProofMode::MergeRoot,
            flat_batches: Vec::new(),
            merge_root: Some(merge_root),
            artifact_claim: None,
        };
        let key = candidate_bundle_key(parent_hash, &payload);
        Ok(PreparedBundle {
            key,
            payload,
            candidate_txs,
            build_ms: 0,
        })
    }

    fn expire_work_packages_locked(state: &mut CoordinatorState) {
        let now_ms = Self::now_ms();
        let expired_ids = state
            .work_packages
            .iter()
            .filter_map(|(id, record)| {
                if record.package.expires_at_ms <= now_ms {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for package_id in expired_ids {
            state.work_packages.remove(&package_id);
            state.work_status.insert(package_id, WorkStatus::Expired);
        }
        state
            .work_package_queue
            .retain(|package_id| state.work_packages.contains_key(package_id));
        state
            .stage_work_package_queue
            .retain(|package_id| state.work_packages.contains_key(package_id));
        state.fanout_assemblies.retain(|_, assembly| {
            assembly
                .chunks
                .iter()
                .any(|chunk| state.work_packages.contains_key(&chunk.package_id))
        });
        state.recursive_assemblies.retain(|_, assembly| {
            assembly
                .leaf_chunks
                .iter()
                .any(|chunk| state.work_packages.contains_key(&chunk.package_id))
                || assembly
                    .merge_package_id
                    .as_ref()
                    .is_some_and(|package_id| state.work_packages.contains_key(package_id))
        });
        if let Some(latest) = state.latest_work_package.as_ref() {
            if !state.work_packages.contains_key(latest) {
                state.latest_work_package = None;
            }
        }
        if let Some(latest) = state.latest_stage_work_package.as_ref() {
            if !state.work_packages.contains_key(latest) {
                state.latest_stage_work_package = None;
            }
        }
    }

    fn drain_worker_results(&self) {
        loop {
            let result = match self.worker_pool.try_recv() {
                Ok(result) => result,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            };
            self.handle_worker_result(result);
        }
    }

    fn apply_recursive_stage_result_locked(
        &self,
        state: &mut CoordinatorState,
        package_id: &str,
        candidate_set_id: &str,
        parent_hash: H256,
        proof_bytes: Vec<u8>,
    ) -> Result<Option<PreparedBundle>, String> {
        Self::retire_package_locked(state, package_id);
        if let Some(assembly) = state.recursive_assemblies.get_mut(candidate_set_id) {
            if assembly.parent_hash != parent_hash {
                return Ok(None);
            }
            if assembly
                .leaf_chunks
                .iter()
                .any(|chunk| chunk.package_id == package_id)
            {
                assembly.leaf_results.insert(package_id.to_string(), proof_bytes);
                if assembly.leaf_results.len() < assembly.leaf_chunks.len() {
                    return Ok(None);
                }
                if assembly.leaf_chunks.len() == 1 {
                    let final_proof = assembly
                        .leaf_chunks
                        .first()
                        .and_then(|chunk| assembly.leaf_results.get(&chunk.package_id))
                        .cloned()
                        .ok_or_else(|| "missing completed leaf proof".to_string())?;
                    let candidate_txs = assembly.candidate_txs.clone();
                    let root_payload = assembly.root_finalize_payload.clone();
                    state.recursive_assemblies.remove(candidate_set_id);
                    return Self::assemble_recursive_prepared_bundle(
                        parent_hash,
                        candidate_txs,
                        root_payload,
                        final_proof,
                    )
                    .map(Some);
                }
                if assembly.merge_package_id.is_none() {
                    let dependencies = assembly
                        .leaf_chunks
                        .iter()
                        .map(|chunk| chunk.package_id.clone())
                        .collect::<Vec<_>>();
                    let mut child_proof_payloads = Vec::with_capacity(assembly.leaf_chunks.len());
                    for chunk in &assembly.leaf_chunks {
                        let child = assembly
                            .leaf_results
                            .get(&chunk.package_id)
                            .cloned()
                            .ok_or_else(|| "missing leaf proof for merge stage".to_string())?;
                        child_proof_payloads.push(child);
                    }
                    let merge_payload = MergeNodeWorkData {
                        child_proof_payloads,
                        tx_statements_commitment: assembly
                            .root_finalize_payload
                            .tx_statements_commitment,
                        tree_levels: Self::recursive_tree_levels_for_tx_count(
                            assembly.candidate_txs.len(),
                        ),
                        root_level: 1,
                    };
                    let package = Self::build_merge_stage_work_package(
                        assembly.parent_hash,
                        assembly.block_number,
                        candidate_set_id.to_string(),
                        assembly.candidate_txs.clone(),
                        dependencies,
                        self.config.work_package_ttl,
                        merge_payload.clone(),
                    );
                    let merge_package_id = package.package_id.clone();
                    state.latest_stage_work_package = Some(merge_package_id.clone());
                    state.stage_work_package_queue.push_back(merge_package_id.clone());
                    state.work_packages.insert(
                        merge_package_id.clone(),
                        WorkPackageRecord {
                            package: package.clone(),
                            submissions: 0,
                        },
                    );
                    state
                        .work_status
                        .insert(merge_package_id.clone(), WorkStatus::Pending);
                    assembly.merge_package_id = Some(merge_package_id.clone());
                    if self.worker_pool.worker_count() > 0 {
                        let job = QueuedJob {
                            id: state.next_job_id,
                            package_id: merge_package_id,
                            candidate_set_id: candidate_set_id.to_string(),
                            generation: state.generation,
                            parent_hash: assembly.parent_hash,
                            block_number: assembly.block_number,
                            stage_type: "merge_node_prove".to_string(),
                            level: 1,
                            arity: Self::merge_fan_in() as u16,
                            shape_id: package.shape_id,
                            dependencies: package.dependencies.clone(),
                            enqueued_at: Instant::now(),
                            candidate_txs: package.candidate_txs.clone(),
                            leaf_batch_payload: None,
                            merge_node_payload: Some(merge_payload),
                        };
                        state.next_job_id = state.next_job_id.wrapping_add(1);
                        state.pending_jobs.push_back(job);
                    }
                }
                return Ok(None);
            }
            if assembly
                .merge_package_id
                .as_ref()
                .is_some_and(|merge_id| merge_id == package_id)
            {
                let candidate_txs = assembly.candidate_txs.clone();
                let root_payload = assembly.root_finalize_payload.clone();
                state.recursive_assemblies.remove(candidate_set_id);
                return Self::assemble_recursive_prepared_bundle(
                    parent_hash,
                    candidate_txs,
                    root_payload,
                    proof_bytes,
                )
                .map(Some);
            }
        }
        Ok(None)
    }

    fn handle_worker_result(&self, result: WorkerJobResult) {
        let WorkerJobResult {
            job:
                QueuedJob {
                    id,
                    package_id,
                    candidate_set_id,
                    generation,
                    parent_hash,
                    block_number,
                    stage_type,
                    level,
                    arity,
                    shape_id,
                    dependencies,
                    enqueued_at,
                    candidate_txs,
                    leaf_batch_payload: _,
                    merge_node_payload: _,
                },
            queue_depth_after_pop,
            build_elapsed_ms,
            outcome,
        } = result;

        let queue_wait_ms = enqueued_at.elapsed().as_millis();
        let candidate_tx_count = candidate_txs.len();
        let candidate_bytes = candidate_txs.iter().map(Vec::len).sum::<usize>();
        let job_package_id = package_id.clone();
        let timeout = self.config.job_timeout;
        let target_txs = self.config.target_txs;
        let stage_max_inflight_per_level = self.config.max_inflight_per_level;

        let mut guard = self.state.lock();
        guard.inflight_jobs.remove(&id);
        guard.inflight_stage_meta.remove(&id);
        guard.inflight_candidates.remove(&id);

        let stale_parent = guard.current_parent != Some(parent_hash);
        let stale_generation = guard.generation != generation;
        let is_stale = stale_parent || stale_generation;
        if is_stale {
            guard.stale_count = guard.stale_count.saturating_add(1);
        }

        if build_elapsed_ms > timeout.as_millis() {
            tracing::warn!(
                job_id = id,
                block_number,
                stage_type = %stage_type,
                level,
                arity,
                tx_count = candidate_tx_count,
                candidate_bytes,
                elapsed_ms = build_elapsed_ms as u64,
                timeout_ms = timeout.as_millis() as u64,
                package_id = %job_package_id,
                "Prover coordinator job exceeded timeout budget while preparing proven batch"
            );
        }

        match outcome {
            WorkerOutcome::StageResult(result) => match *result {
                Ok(stage_payload) => {
                    let maybe_prepared = if !is_stale {
                        self.apply_recursive_stage_result_locked(
                            &mut guard,
                            &package_id,
                            &candidate_set_id,
                            parent_hash,
                            stage_payload,
                        )
                    } else {
                        Ok(None)
                    };
                    match maybe_prepared {
                        Ok(Some(bundle)) => {
                            let key = bundle.key.clone();
                            tracing::info!(
                                block_number,
                                tx_count = bundle.key.tx_count,
                                proof_mode = ?bundle.key.proof_mode,
                                artifact_hash = %hex::encode(bundle.key.artifact_hash),
                                build_ms = bundle.build_ms,
                                stage_type = %stage_type,
                                level,
                                package_id = %job_package_id,
                                "Prepared recursive proven batch is ready"
                            );
                            guard.prepared.insert(key, bundle);
                        }
                        Ok(None) => {}
                        Err(error) => {
                            tracing::warn!(
                                job_id = id,
                                block_number,
                                stage_type = %stage_type,
                                level,
                                arity,
                                tx_count = candidate_tx_count,
                                candidate_bytes,
                                package_id = %job_package_id,
                                error = %error,
                                "Failed to apply recursive stage result"
                            );
                        }
                    }
                    tracing::info!(
                        target: "prover::stage_metrics",
                        job_id = id,
                        block_number,
                        stage_type = %stage_type,
                        level,
                        arity,
                        shape_id = %hex::encode(shape_id),
                        dependencies = dependencies.len(),
                        queue_depth = queue_depth_after_pop,
                        queue_wait_ms,
                        stage_mem_budget_mb = Self::stage_mem_budget_mb(),
                        stage_max_inflight_per_level,
                        tx_count = candidate_tx_count,
                        candidate_bytes,
                        build_ms = build_elapsed_ms,
                        package_id = %job_package_id,
                        stale_parent,
                        stale_generation,
                        "Completed recursive stage"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        job_id = id,
                        block_number,
                        stage_type = %stage_type,
                        level,
                        arity,
                        tx_count = candidate_tx_count,
                        candidate_bytes,
                        package_id = %job_package_id,
                        error = %error,
                        "Recursive stage proving failed"
                    );
                }
            },
            WorkerOutcome::Bundle(result) => match *result {
                Ok(bundle) => {
                    let candidate_len = bundle.candidate_txs.len();
                    guard.last_build_ms = bundle.build_ms;
                    if !is_stale && candidate_len > guard.selected_txs.len() {
                        guard.selected_txs = bundle.candidate_txs.clone();
                    }
                    if !is_stale && candidate_len >= target_txs {
                        guard.pending_jobs.clear();
                    }
                    tracing::info!(
                        target: "prover::stage_metrics",
                        job_id = id,
                        block_number,
                        key_parent_hash = ?bundle.key.parent_hash,
                        key_tx_statements_commitment = %hex::encode(bundle.key.tx_statements_commitment),
                        key_tx_count = bundle.key.tx_count,
                        stage_type = %stage_type,
                        level,
                        arity,
                        shape_id = %hex::encode(shape_id),
                        dependencies = dependencies.len(),
                        queue_depth = queue_depth_after_pop,
                        queue_wait_ms,
                        stage_mem_budget_mb = Self::stage_mem_budget_mb(),
                        stage_max_inflight_per_level,
                        tx_count = candidate_len,
                        candidate_bytes,
                        build_ms = bundle.build_ms,
                        package_id = %job_package_id,
                        stale_parent,
                        stale_generation,
                        "Prepared proven batch candidate"
                    );
                    guard.prepared.insert(bundle.key.clone(), bundle);
                }
                Err(error) => {
                    tracing::warn!(
                        job_id = id,
                        block_number,
                        stage_type = %stage_type,
                        level,
                        arity,
                        tx_count = candidate_tx_count,
                        candidate_bytes,
                        package_id = %job_package_id,
                        error = %error,
                        "Failed to prepare proven batch candidate"
                    );
                }
            },
            WorkerOutcome::Panicked(error) => {
                tracing::warn!(
                    job_id = id,
                    block_number,
                    stage_type = %stage_type,
                    level,
                    arity,
                    tx_count = candidate_tx_count,
                    candidate_bytes,
                    package_id = %job_package_id,
                    error = %error,
                    "Prover coordinator job panicked while preparing proven batch"
                );
                guard.stale_count = guard.stale_count.saturating_add(1);
            }
        }
    }

    fn dispatch_jobs(self: &Arc<Self>) {
        if self.worker_pool.worker_count() == 0 {
            return;
        }

        loop {
            let (job, queue_depth_after_pop, worker_index) = {
                let mut state = self.state.lock();
                let inflight_current = Self::inflight_current_generation_count(&state);
                if inflight_current >= self.config.workers {
                    return;
                }
                if state.inflight_jobs.len() >= self.inflight_total_cap() {
                    tracing::debug!(
                        inflight_total = state.inflight_jobs.len(),
                        inflight_current,
                        inflight_cap = self.inflight_total_cap(),
                        workers = self.config.workers,
                        generation = state.generation,
                        "Deferring prover job dispatch: inflight cap reached"
                    );
                    return;
                }
                let Some(job_index) = state.pending_jobs.iter().position(|job| {
                    Self::inflight_current_generation_count_for_level(&state, job.level)
                        < self.config.max_inflight_per_level
                }) else {
                    return;
                };
                let Some(job) = state.pending_jobs.remove(job_index) else {
                    return;
                };
                let queue_depth_after_pop = state.pending_jobs.len();
                state.inflight_jobs.insert(job.id, job.generation);
                state
                    .inflight_stage_meta
                    .insert(job.id, (job.stage_type.clone(), job.level));
                state
                    .inflight_candidates
                    .insert(job.id, job.candidate_txs.clone());
                let hash_prefix =
                    u64::from_le_bytes(job.shape_id[..8].try_into().unwrap_or([0u8; 8]));
                let worker_index = hash_prefix as usize % self.worker_pool.worker_count();
                (job, queue_depth_after_pop, worker_index)
            };

            if !self
                .worker_pool
                .dispatch(worker_index, job.clone(), queue_depth_after_pop)
            {
                let mut state = self.state.lock();
                state.inflight_jobs.remove(&job.id);
                state.inflight_stage_meta.remove(&job.id);
                state.inflight_candidates.remove(&job.id);
                state.stale_count = state.stale_count.saturating_add(1);
                tracing::warn!(
                    job_id = job.id,
                    stage_type = %job.stage_type,
                    level = job.level,
                    tx_count = job.candidate_txs.len(),
                    worker_index,
                    "Failed to dispatch proven-batch job to worker"
                );
            }
        }
    }

    fn best_pending_candidate_locked(state: &CoordinatorState) -> Option<Vec<Vec<u8>>> {
        let mut best: Option<&Vec<Vec<u8>>> = None;
        for job in &state.pending_jobs {
            if job.generation != state.generation {
                continue;
            }
            if best.is_none_or(|current| job.candidate_txs.len() > current.len()) {
                best = Some(&job.candidate_txs);
            }
        }

        for (job_id, candidate_txs) in &state.inflight_candidates {
            if state.inflight_jobs.get(job_id).copied() != Some(state.generation) {
                continue;
            }
            if best.is_none_or(|current| candidate_txs.len() > current.len()) {
                best = Some(candidate_txs);
            }
        }

        best.cloned()
    }

    fn best_prepared_candidate_locked(state: &CoordinatorState) -> Option<Vec<Vec<u8>>> {
        let current_parent = state.current_parent;
        let mut best_current_parent: Option<&PreparedBundle> = None;
        let mut best_any_parent: Option<&PreparedBundle> = None;
        for bundle in state.prepared.values() {
            if best_any_parent
                .is_none_or(|current| bundle.candidate_txs.len() > current.candidate_txs.len())
            {
                best_any_parent = Some(bundle);
            }
            if Some(bundle.key.parent_hash) == current_parent
                && best_current_parent
                    .is_none_or(|current| bundle.candidate_txs.len() > current.candidate_txs.len())
            {
                best_current_parent = Some(bundle);
            }
        }

        best_current_parent
            .or(best_any_parent)
            .map(|bundle| bundle.candidate_txs.clone())
    }

    fn best_prepared_bundle_for_statement_locked(
        state: &CoordinatorState,
        tx_statements_commitment: [u8; 48],
        tx_count: u32,
    ) -> Option<&PreparedBundle> {
        state
            .prepared
            .values()
            .filter(|bundle| {
                bundle.key.tx_statements_commitment == tx_statements_commitment
                    && bundle.key.tx_count == tx_count
            })
            .max_by(|left, right| compare_prepared_bundles(left, right))
    }
}

fn proof_mode_rank(mode: pallet_shielded_pool::types::BlockProofMode) -> u8 {
    match mode {
        pallet_shielded_pool::types::BlockProofMode::FlatBatches => 0,
        pallet_shielded_pool::types::BlockProofMode::MergeRoot => 1,
    }
}

fn candidate_bundle_key(
    parent_hash: H256,
    payload: &pallet_shielded_pool::types::CandidateArtifact,
) -> BundleMatchKey {
    BundleMatchKey {
        parent_hash,
        tx_statements_commitment: payload.tx_statements_commitment,
        tx_count: payload.tx_count,
        proof_mode: payload.proof_mode,
        artifact_hash: crate::substrate::artifact_market::candidate_artifact_hash(payload),
    }
}

fn claim_amount(bundle: &PreparedBundle) -> u64 {
    bundle
        .payload
        .artifact_claim
        .as_ref()
        .map(|claim| claim.prover_amount)
        .unwrap_or(0)
}

fn compare_prepared_bundles(left: &PreparedBundle, right: &PreparedBundle) -> std::cmp::Ordering {
    left.key
        .tx_count
        .cmp(&right.key.tx_count)
        .then_with(|| {
            proof_mode_rank(left.payload.proof_mode).cmp(&proof_mode_rank(right.payload.proof_mode))
        })
        .then_with(|| claim_amount(right).cmp(&claim_amount(left)))
        .then_with(|| {
            crate::substrate::artifact_market::candidate_artifact_hash(&right.payload).cmp(
                &crate::substrate::artifact_market::candidate_artifact_hash(&left.payload),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use block_circuit::CommitmentBlockProver;
    use p3_field::PrimeCharacteristicRing;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use transaction_circuit::constants::CIRCUIT_MERKLE_DEPTH;
    use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, Felt, HashFelt};
    use transaction_circuit::keys::generate_keys;
    use transaction_circuit::note::{MerklePath, NoteData, OutputNoteWitness};
    use transaction_circuit::{
        InputNoteWitness, StablecoinPolicyBinding, TransactionWitness,
    };

    fn test_config() -> ProverCoordinatorConfig {
        ProverCoordinatorConfig {
            workers: 1,
            target_txs: 1,
            queue_capacity: 1,
            max_inflight_per_level: 1,
            liveness_lane: true,
            adaptive_liveness_timeout: Duration::from_millis(0),
            incremental_upsizing: false,
            poll_interval: Duration::from_millis(10),
            job_timeout: Duration::from_secs(2),
            work_package_ttl: Duration::from_secs(2),
            max_submissions_per_package: 8,
            max_submissions_per_source: 8,
            max_payload_bytes: 8 * 1024 * 1024,
        }
    }

    fn ready_payload(
        tx_count: u32,
        commitment: [u8; 48],
    ) -> pallet_shielded_pool::types::CandidateArtifact {
        pallet_shielded_pool::types::CandidateArtifact {
            version: pallet_shielded_pool::types::BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count,
            tx_statements_commitment: commitment,
            da_root: [7u8; 48],
            da_chunk_count: 1,
            commitment_proof: pallet_shielded_pool::types::StarkProof::from_bytes(vec![1, 2, 3]),
            proof_mode: pallet_shielded_pool::types::BlockProofMode::FlatBatches,
            flat_batches: vec![pallet_shielded_pool::types::BatchProofItem {
                start_tx_index: 0,
                tx_count: tx_count.min(u16::MAX as u32) as u16,
                proof_format: pallet_shielded_pool::types::BLOCK_PROOF_FORMAT_ID_V5,
                proof: pallet_shielded_pool::types::StarkProof::from_bytes(vec![4, 5, 6]),
            }],
            merge_root: None,
            artifact_claim: None,
        }
    }

    fn compute_merkle_root(leaf: HashFelt, position: u64, path: &[HashFelt]) -> HashFelt {
        let mut current = leaf;
        let mut pos = position;
        for sibling in path.iter().take(CIRCUIT_MERKLE_DEPTH) {
            current = if pos & 1 == 0 {
                merkle_node(current, *sibling)
            } else {
                merkle_node(*sibling, current)
            };
            pos >>= 1;
        }
        current
    }

    fn build_two_leaf_merkle_tree(
        leaf0: HashFelt,
        leaf1: HashFelt,
    ) -> (MerklePath, MerklePath, HashFelt) {
        let mut siblings0 = vec![leaf1];
        let mut siblings1 = vec![leaf0];
        let mut current = merkle_node(leaf0, leaf1);

        for _ in 1..CIRCUIT_MERKLE_DEPTH {
            let zero = [Felt::ZERO; 6];
            siblings0.push(zero);
            siblings1.push(zero);
            current = merkle_node(current, zero);
        }

        (
            MerklePath { siblings: siblings0 },
            MerklePath { siblings: siblings1 },
            current,
        )
    }

    fn sample_witness() -> TransactionWitness {
        let sk_spend = [42u8; 32];
        let pk_auth = transaction_circuit::hashing_pq::spend_auth_key_bytes(&sk_spend);
        let input_note_native = NoteData {
            value: 8,
            asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
            pk_recipient: [2u8; 32],
            pk_auth,
            rho: [3u8; 32],
            r: [4u8; 32],
        };
        let input_note_asset = NoteData {
            value: 5,
            asset_id: 1,
            pk_recipient: [5u8; 32],
            pk_auth,
            rho: [6u8; 32],
            r: [7u8; 32],
        };

        let leaf0 = input_note_native.commitment();
        let leaf1 = input_note_asset.commitment();
        let (merkle_path0, merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);
        assert_eq!(
            compute_merkle_root(leaf0, 0, &merkle_path0.siblings),
            merkle_root
        );
        assert_eq!(
            compute_merkle_root(leaf1, 1, &merkle_path1.siblings),
            merkle_root
        );

        let output_native = OutputNoteWitness {
            note: NoteData {
                value: 3,
                asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
                pk_recipient: [11u8; 32],
                pk_auth: [111u8; 32],
                rho: [12u8; 32],
                r: [13u8; 32],
            },
        };
        let output_asset = OutputNoteWitness {
            note: NoteData {
                value: 5,
                asset_id: 1,
                pk_recipient: [21u8; 32],
                pk_auth: [121u8; 32],
                rho: [22u8; 32],
                r: [23u8; 32],
            },
        };

        TransactionWitness {
            inputs: vec![
                InputNoteWitness {
                    note: input_note_native,
                    position: 0,
                    rho_seed: [9u8; 32],
                    merkle_path: merkle_path0,
                },
                InputNoteWitness {
                    note: input_note_asset,
                    position: 1,
                    rho_seed: [8u8; 32],
                    merkle_path: merkle_path1,
                },
            ],
            outputs: vec![output_native, output_asset],
            ciphertext_hashes: vec![[0u8; 48]; 2],
            sk_spend,
            merkle_root: felts_to_bytes48(&merkle_root),
            fee: 5,
            value_balance: 0,
            stablecoin: StablecoinPolicyBinding::default(),
            version: TransactionWitness::default_version_binding(),
        }
    }

    fn sample_transaction_proof() -> TransactionProof {
        use std::sync::OnceLock;
        static SAMPLE_TX_PROOF: OnceLock<TransactionProof> = OnceLock::new();
        SAMPLE_TX_PROOF
            .get_or_init(|| {
                let witness = sample_witness();
                let (proving_key, _) = generate_keys();
                transaction_circuit::proof::prove(&witness, &proving_key)
                    .expect("sample tx proof")
            })
            .clone()
    }

    fn statement_hash_from_proof(proof: &TransactionProof) -> [u8; 48] {
        let public = &proof.public_inputs;
        let mut message = Vec::new();
        message.extend_from_slice(b"tx-statement-v1");
        message.extend_from_slice(&public.merkle_root);
        for nf in &public.nullifiers {
            message.extend_from_slice(nf);
        }
        for cm in &public.commitments {
            message.extend_from_slice(cm);
        }
        for ct in &public.ciphertext_hashes {
            message.extend_from_slice(ct);
        }
        message.extend_from_slice(&public.native_fee.to_le_bytes());
        message.extend_from_slice(&public.value_balance.to_le_bytes());
        message.extend_from_slice(&public.balance_tag);
        message.extend_from_slice(&public.circuit_version.to_le_bytes());
        message.extend_from_slice(&public.crypto_suite.to_le_bytes());
        message.push(public.stablecoin.enabled as u8);
        message.extend_from_slice(&public.stablecoin.asset_id.to_le_bytes());
        message.extend_from_slice(&public.stablecoin.policy_hash);
        message.extend_from_slice(&public.stablecoin.oracle_commitment);
        message.extend_from_slice(&public.stablecoin.attestation_commitment);
        message.extend_from_slice(&public.stablecoin.issuance_delta.to_le_bytes());
        message.extend_from_slice(&public.stablecoin.policy_version.to_le_bytes());
        crypto::hashes::blake3_384(&message)
    }

    fn synthetic_root_finalize_work_data(tx_count: usize) -> RootFinalizeWorkData {
        let proof = sample_transaction_proof();
        let statement_hash = statement_hash_from_proof(&proof);
        let tx_proofs = vec![proof; tx_count];
        let statement_hashes = vec![statement_hash; tx_count];
        let tx_statements_commitment =
            CommitmentBlockProver::commitment_from_statement_hashes(&statement_hashes)
                .expect("statement commitment");
        let mut nullifiers = Vec::new();
        for proof in &tx_proofs {
            nullifiers.extend_from_slice(&proof.nullifiers);
        }
        let mut sorted_nullifiers = nullifiers.clone();
        sorted_nullifiers.sort_unstable();
        RootFinalizeWorkData {
            statement_hashes,
            tx_proofs,
            tx_statements_commitment,
            da_root: [0u8; 48],
            da_chunk_count: 1,
            starting_state_root: [0u8; 48],
            ending_state_root: [1u8; 48],
            starting_kernel_root: [2u8; 48],
            ending_kernel_root: [3u8; 48],
            nullifier_root: [4u8; 48],
            nullifiers,
            sorted_nullifiers,
        }
    }

    async fn measure_recursive_prepared_latency(
        tx_count: usize,
        workers: usize,
    ) -> Result<u128, u128> {
        unsafe {
            std::env::set_var("HEGEMON_AGG_PREWARM_BLOCKING", "0");
            std::env::set_var("HEGEMON_AGG_PREWARM_MAX_TXS", "0");
            std::env::set_var("HEGEMON_AGG_LEAF_FANIN", "8");
            std::env::set_var("HEGEMON_AGG_MERGE_FANIN", "8");
            std::env::set_var("HEGEMON_AGG_PROVER_THREADS", "1");
            std::env::set_var("HEGEMON_AGG_LEVEL_PARALLELISM", "1");
            std::env::set_var("HEGEMON_AGG_COMMON_LOOKUP_THREADS", "1");
        }

        let parent_hash = H256::repeat_byte((tx_count as u8).wrapping_add(workers as u8));
        let txs = (0..tx_count)
            .map(|idx| vec![idx as u8, (idx >> 8) as u8])
            .collect::<Vec<_>>();
        let work_data = Arc::new(synthetic_root_finalize_work_data(tx_count));
        let expected_commitment = work_data.tx_statements_commitment;

        let config = ProverCoordinatorConfig {
            workers,
            target_txs: tx_count,
            queue_capacity: 1,
            max_inflight_per_level: workers.max(1),
            liveness_lane: false,
            adaptive_liveness_timeout: Duration::from_millis(0),
            incremental_upsizing: false,
            poll_interval: Duration::from_millis(10),
            job_timeout: Duration::from_secs(1800),
            work_package_ttl: Duration::from_secs(1800),
            max_submissions_per_package: 8,
            max_submissions_per_source: 8,
            max_payload_bytes: 64 * 1024 * 1024,
        };
        let best = Arc::new(move || (parent_hash, 42u64));
        let pending_txs = txs.clone();
        let pending = Arc::new(move |_max_txs: usize| pending_txs.clone());
        let build = Arc::new(
            move |_parent: H256, _number: u64, _candidate_txs: Vec<Vec<u8>>| {
                Err("legacy local bundle builder disabled in recursive benchmark".to_string())
            },
        );
        let root_finalize = {
            let work_data = Arc::clone(&work_data);
            Arc::new(
                move |_parent: H256, _number: u64, _candidate_txs: Vec<Vec<u8>>| {
                    Ok(Some((*work_data).clone()))
                },
            )
        };

        let coordinator = ProverCoordinator::new_with_root_finalize_builder(
            config,
            best,
            pending,
            build,
            Some(root_finalize),
        );
        coordinator.start();

        let started = Instant::now();
        let mut last_report = Instant::now();
        let timeout_secs = std::env::var("HEGEMON_RECURSIVE_BENCH_TIMEOUT_SECS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(900)
            .max(1);
        loop {
            if coordinator
                .lookup_prepared_bundle(parent_hash, expected_commitment, tx_count as u32)
                .is_some()
            {
                break;
            }
            if last_report.elapsed() >= Duration::from_secs(10) {
                let status = coordinator.stage_plan_status();
                eprintln!(
                    "recursive_scaling_progress tx_count={} workers={} queued={} inflight={} prepared={} latest_stage={:?}",
                    tx_count,
                    workers,
                    status.queued_jobs,
                    status.inflight_jobs,
                    status.prepared_bundles,
                    status.latest_work_package,
                );
                last_report = Instant::now();
            }
            if started.elapsed() >= Duration::from_secs(timeout_secs) {
                return Err(started.elapsed().as_millis());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Ok(started.elapsed().as_millis())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ready_batch_lookup_uses_parent_commitment_and_tx_count() {
        let parent_hash = H256::repeat_byte(11);
        let mut config = test_config();
        config.target_txs = 2;
        let best = Arc::new(move || (parent_hash, 9u64));
        let pending = Arc::new(move |_max_txs: usize| vec![vec![1u8], vec![2u8]]);
        let build = Arc::new(
            move |parent: H256, _number: u64, candidate_txs: Vec<Vec<u8>>| {
                let tx_count = candidate_txs.len() as u32;
                let commitment = [tx_count as u8; 48];
                let payload = ready_payload(tx_count, commitment);
                Ok(PreparedBundle {
                    key: candidate_bundle_key(parent, &payload),
                    payload,
                    candidate_txs,
                    build_ms: 1,
                })
            },
        );

        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();
        tokio::time::sleep(Duration::from_millis(120)).await;

        let commitment = [2u8; 48];
        let looked_up = coordinator.lookup_prepared_bundle(parent_hash, commitment, 2);
        assert!(looked_up.is_some());
        assert_eq!(coordinator.pending_transactions(8).len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_parent_results_are_preserved_for_reuse() {
        let first_parent = H256::repeat_byte(21);
        let second_parent = H256::repeat_byte(22);
        let best_state = Arc::new(Mutex::new((first_parent, 12u64)));
        let config = test_config();
        let best = {
            let state = Arc::clone(&best_state);
            Arc::new(move || {
                let guard = state.lock();
                (guard.0, guard.1)
            })
        };
        let pending = Arc::new(move |_max_txs: usize| vec![vec![9u8]]);
        let build = Arc::new(
            move |parent: H256, _number: u64, candidate_txs: Vec<Vec<u8>>| {
                std::thread::sleep(Duration::from_millis(150));
                let commitment = [1u8; 48];
                let payload = ready_payload(1, commitment);
                Ok(PreparedBundle {
                    key: candidate_bundle_key(parent, &payload),
                    payload,
                    candidate_txs,
                    build_ms: 150,
                })
            },
        );

        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();
        tokio::time::sleep(Duration::from_millis(40)).await;
        {
            let mut guard = best_state.lock();
            guard.0 = second_parent;
            guard.1 = 13;
        }
        tokio::time::sleep(Duration::from_millis(260)).await;

        let stale_lookup = coordinator.lookup_prepared_bundle(first_parent, [1u8; 48], 1);
        assert!(stale_lookup.is_some());
        let any_parent_lookup = coordinator.lookup_prepared_bundle_any_parent([1u8; 48], 1);
        assert!(any_parent_lookup.is_some());
        assert!(coordinator.stale_count() > 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parent_rollover_still_schedules_new_work_package() {
        let first_parent = H256::repeat_byte(23);
        let second_parent = H256::repeat_byte(24);
        let best_state = Arc::new(Mutex::new((first_parent, 20u64)));
        let config = test_config();
        let best = {
            let state = Arc::clone(&best_state);
            Arc::new(move || {
                let guard = state.lock();
                (guard.0, guard.1)
            })
        };
        let pending = Arc::new(move |_max_txs: usize| vec![vec![0xAAu8]]);
        let build = Arc::new(
            move |parent: H256, _number: u64, candidate_txs: Vec<Vec<u8>>| {
                std::thread::sleep(Duration::from_millis(40));
                let commitment = [1u8; 48];
                let payload = ready_payload(1, commitment);
                Ok(PreparedBundle {
                    key: candidate_bundle_key(parent, &payload),
                    payload,
                    candidate_txs,
                    build_ms: 40,
                })
            },
        );

        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();

        tokio::time::sleep(Duration::from_millis(100)).await;
        let first_package = coordinator
            .get_work_package()
            .expect("work package should exist for first parent");
        assert_eq!(first_package.parent_hash, first_parent);
        assert_eq!(first_package.tx_count, 1);

        {
            let mut guard = best_state.lock();
            guard.0 = second_parent;
            guard.1 = 21;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        let second_package = coordinator
            .get_work_package()
            .expect("work package should be republished for new parent");
        assert_eq!(second_package.parent_hash, second_parent);
        assert_eq!(second_package.tx_count, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_jobs_release_worker_slots() {
        let parent_hash = H256::repeat_byte(31);
        let pending_calls = Arc::new(AtomicUsize::new(0));
        let mut config = test_config();
        config.poll_interval = Duration::from_millis(25);
        config.job_timeout = Duration::from_secs(1);
        let best = Arc::new(move || (parent_hash, 2u64));
        let pending = {
            let calls = Arc::clone(&pending_calls);
            Arc::new(move |_max_txs: usize| {
                let call_idx = calls.fetch_add(1, Ordering::SeqCst);
                if call_idx == 0 {
                    vec![vec![4u8]]
                } else {
                    Vec::new()
                }
            })
        };
        let build = Arc::new(
            move |_parent: H256, _number: u64, _candidate_txs: Vec<Vec<u8>>| {
                Err("simulated failure".to_string())
            },
        );

        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();
        tokio::time::sleep(Duration::from_millis(120)).await;

        assert_eq!(coordinator.active_jobs(), 0);
        assert_eq!(coordinator.queued_jobs(), 0);
        // Keep a liveness candidate visible even after a failed build so local
        // block assembly can continue attempting inclusion.
        assert_eq!(coordinator.pending_transactions(8), vec![vec![4u8]]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn external_work_submission_is_accepted_and_visible() {
        let parent_hash = H256::repeat_byte(41);
        let config = test_config();
        let best = Arc::new(move || (parent_hash, 5u64));
        let pending = Arc::new(move |_max_txs: usize| vec![vec![7u8]]);
        let build = Arc::new(
            move |_parent: H256, _number: u64, _candidate_txs: Vec<Vec<u8>>| {
                Err("local builder disabled for test".to_string())
            },
        );

        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();
        tokio::time::sleep(Duration::from_millis(60)).await;

        let package = coordinator
            .get_work_package()
            .expect("work package should be published");
        let commitment = [13u8; 48];
        let payload = ready_payload(package.tx_count, commitment);
        coordinator
            .submit_external_work_result("alice", &package.package_id, payload)
            .expect("external result should be accepted");

        let looked_up =
            coordinator.lookup_prepared_bundle(parent_hash, commitment, package.tx_count);
        assert!(looked_up.is_some());
        let status = coordinator
            .get_work_status(&package.package_id)
            .expect("status should exist");
        assert!(matches!(status, WorkStatus::Accepted));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn external_work_fanout_assembles_multi_chunk_flat_batches() {
        let parent_hash = H256::repeat_byte(42);
        let mut config = test_config();
        config.target_txs = 17;
        config.queue_capacity = 1;
        config.workers = 0;
        let best = Arc::new(move || (parent_hash, 8u64));
        let pending = Arc::new(move |_max_txs: usize| {
            (0..17usize)
                .map(|idx| vec![(idx as u8).saturating_add(1)])
                .collect()
        });
        let build = Arc::new(
            move |_parent: H256, _number: u64, _candidate_txs: Vec<Vec<u8>>| {
                Err("local builder disabled for fanout test".to_string())
            },
        );

        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();
        tokio::time::sleep(Duration::from_millis(80)).await;

        let mut packages = std::collections::HashMap::new();
        let mut attempts = 0usize;
        while packages.len() < 2 && attempts < 16 {
            attempts = attempts.saturating_add(1);
            let package = coordinator
                .get_work_package()
                .expect("fan-out package should be published");
            packages.insert(package.package_id.clone(), package);
        }
        assert_eq!(packages.len(), 2, "expected two chunk work packages");
        let expected_chunks = packages
            .values()
            .next()
            .map(|package| package.expected_chunks)
            .unwrap_or(0);
        assert_eq!(expected_chunks, 2);

        let commitment = [17u8; 48];
        for package in packages.values() {
            let payload = ready_payload(package.tx_count, commitment);
            coordinator
                .submit_external_work_result("fanout-worker", &package.package_id, payload)
                .expect("chunk result should be accepted");
        }

        let assembled = coordinator
            .lookup_prepared_bundle(parent_hash, commitment, 17)
            .expect("assembled full fan-out bundle should be available");
        assert_eq!(
            assembled.payload.proof_mode,
            pallet_shielded_pool::types::BlockProofMode::FlatBatches
        );
        assert_eq!(assembled.payload.flat_batches.len(), 2);
        assert_eq!(assembled.payload.flat_batches[0].start_tx_index, 0);
        assert_eq!(assembled.payload.flat_batches[0].tx_count, 16);
        assert_eq!(assembled.payload.flat_batches[1].start_tx_index, 16);
        assert_eq!(assembled.payload.flat_batches[1].tx_count, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn external_submission_limits_are_enforced() {
        let parent_hash = H256::repeat_byte(51);
        let mut config = test_config();
        config.max_submissions_per_source = 1;
        config.max_submissions_per_package = 1;
        let best = Arc::new(move || (parent_hash, 6u64));
        let pending = Arc::new(move |_max_txs: usize| vec![vec![8u8]]);
        let build = Arc::new(
            move |_parent: H256, _number: u64, _candidate_txs: Vec<Vec<u8>>| {
                Err("local builder disabled for test".to_string())
            },
        );

        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();
        tokio::time::sleep(Duration::from_millis(60)).await;

        let package = coordinator
            .get_work_package()
            .expect("work package should be published");
        let payload = ready_payload(package.tx_count, [14u8; 48]);
        coordinator
            .submit_external_work_result("alice", &package.package_id, payload.clone())
            .expect("first submission should be accepted");

        let source_err = coordinator
            .submit_external_work_result("alice", &package.package_id, payload.clone())
            .expect_err("second source submission should fail");
        assert!(source_err.contains("rate limit"));

        let package_err = coordinator
            .submit_external_work_result("bob", &package.package_id, payload)
            .expect_err("package should be saturated");
        assert!(package_err.contains("submission limit"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn external_submission_rejects_payloads_over_cap() {
        let parent_hash = H256::repeat_byte(61);
        let mut config = test_config();
        config.max_payload_bytes = 2;
        let best = Arc::new(move || (parent_hash, 7u64));
        let pending = Arc::new(move |_max_txs: usize| vec![vec![9u8]]);
        let build = Arc::new(
            move |_parent: H256, _number: u64, _candidate_txs: Vec<Vec<u8>>| {
                Err("local builder disabled for test".to_string())
            },
        );

        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();
        tokio::time::sleep(Duration::from_millis(60)).await;

        let package = coordinator
            .get_work_package()
            .expect("work package should be published");
        let oversized = ready_payload(package.tx_count, [15u8; 48]);
        let err = coordinator
            .submit_external_work_result("alice", &package.package_id, oversized)
            .expect_err("oversized payload should fail");
        assert!(err.contains("max size"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_transactions_expose_liveness_lane_before_bundle_ready() {
        let parent_hash = H256::repeat_byte(71);
        let mut config = test_config();
        config.target_txs = 4;
        config.queue_capacity = 2;
        config.workers = 1;
        config.poll_interval = Duration::from_millis(10);
        let best = Arc::new(move || (parent_hash, 9u64));
        let pending =
            Arc::new(move |_max_txs: usize| vec![vec![1u8], vec![2u8], vec![3u8], vec![4u8]]);
        let build = Arc::new(
            move |parent: H256, _number: u64, candidate_txs: Vec<Vec<u8>>| {
                std::thread::sleep(Duration::from_millis(140));
                let tx_count = candidate_txs.len() as u32;
                let commitment = [tx_count as u8; 48];
                let payload = ready_payload(tx_count, commitment);
                Ok(PreparedBundle {
                    key: candidate_bundle_key(parent, &payload),
                    payload,
                    candidate_txs,
                    build_ms: 140,
                })
            },
        );

        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Before any bundle is ready, the selected candidate stays on the
        // singleton liveness lane.
        assert_eq!(coordinator.pending_transactions(8).len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_transactions_prefer_ready_liveness_bundle_then_scale_up() {
        let parent_hash = H256::repeat_byte(72);
        let mut config = test_config();
        config.target_txs = 8;
        config.queue_capacity = 2;
        config.workers = 1;
        config.poll_interval = Duration::from_millis(10);
        let best = Arc::new(move || (parent_hash, 11u64));
        let pending = Arc::new(move |_max_txs: usize| {
            vec![
                vec![1u8],
                vec![2u8],
                vec![3u8],
                vec![4u8],
                vec![5u8],
                vec![6u8],
                vec![7u8],
                vec![8u8],
            ]
        });
        let build = Arc::new(
            move |parent: H256, _number: u64, candidate_txs: Vec<Vec<u8>>| {
                let tx_count = candidate_txs.len() as u32;
                let sleep_ms = if tx_count == 1 { 20 } else { 260 };
                std::thread::sleep(Duration::from_millis(sleep_ms));
                let commitment = [tx_count as u8; 48];
                let payload = ready_payload(tx_count, commitment);
                Ok(PreparedBundle {
                    key: candidate_bundle_key(parent, &payload),
                    payload,
                    candidate_txs,
                    build_ms: sleep_ms as u128,
                })
            },
        );

        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();

        // First ready candidate should be the singleton liveness lane.
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(coordinator.pending_transactions(8).len(), 1);

        // Once the larger candidate finishes proving, selection scales up.
        tokio::time::sleep(Duration::from_millis(320)).await;
        assert_eq!(coordinator.pending_transactions(8).len(), 8);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn work_package_upsizes_while_smaller_job_is_inflight() {
        let parent_hash = H256::repeat_byte(73);
        let mut config = test_config();
        config.target_txs = 8;
        config.queue_capacity = 1;
        config.liveness_lane = true;
        config.workers = 1;
        config.poll_interval = Duration::from_millis(10);
        config.job_timeout = Duration::from_secs(2);

        let pending_size = Arc::new(AtomicUsize::new(1));
        let best = Arc::new(move || (parent_hash, 12u64));
        let pending = {
            let pending_size = Arc::clone(&pending_size);
            Arc::new(move |_max_txs: usize| {
                let size = pending_size.load(Ordering::SeqCst);
                (0..size).map(|idx| vec![(idx + 1) as u8]).collect()
            })
        };
        let build = Arc::new(
            move |parent: H256, _number: u64, candidate_txs: Vec<Vec<u8>>| {
                let tx_count = candidate_txs.len() as u32;
                let sleep_ms = if tx_count == 1 { 300 } else { 20 };
                std::thread::sleep(Duration::from_millis(sleep_ms));
                let commitment = [tx_count as u8; 48];
                let payload = ready_payload(tx_count, commitment);
                Ok(PreparedBundle {
                    key: candidate_bundle_key(parent, &payload),
                    payload,
                    candidate_txs,
                    build_ms: sleep_ms as u128,
                })
            },
        );

        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();
        tokio::time::sleep(Duration::from_millis(60)).await;

        let first = coordinator
            .get_work_package()
            .expect("initial work package should exist");
        assert_eq!(first.tx_count, 1);

        pending_size.store(8, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(80)).await;

        let upsized = coordinator
            .get_work_package()
            .expect("upsized work package should exist");
        assert_eq!(upsized.tx_count, 8);
        assert_ne!(upsized.package_id, first.package_id);
        assert_eq!(upsized.stage_type, "leaf_batch_prove");
        assert_eq!(upsized.level, 0);
        assert_eq!(upsized.dependencies.len(), 0);
        assert_eq!(upsized.chunk_start_tx_index, 0);
        assert_eq!(upsized.expected_chunks, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn throughput_mode_defers_until_target_batch_is_available() {
        let parent_hash = H256::repeat_byte(74);
        let mut config = test_config();
        config.target_txs = 4;
        config.queue_capacity = 1;
        config.liveness_lane = false;
        config.adaptive_liveness_timeout = Duration::from_millis(0);
        config.workers = 1;
        config.poll_interval = Duration::from_millis(10);

        let pending_size = Arc::new(AtomicUsize::new(1));
        let best = Arc::new(move || (parent_hash, 13u64));
        let pending = {
            let pending_size = Arc::clone(&pending_size);
            Arc::new(move |_max_txs: usize| {
                let size = pending_size.load(Ordering::SeqCst);
                (0..size).map(|idx| vec![(idx + 1) as u8]).collect()
            })
        };
        let build = Arc::new(
            move |parent: H256, _number: u64, candidate_txs: Vec<Vec<u8>>| {
                let tx_count = candidate_txs.len() as u32;
                let commitment = [tx_count as u8; 48];
                let payload = ready_payload(tx_count, commitment);
                Ok(PreparedBundle {
                    key: candidate_bundle_key(parent, &payload),
                    payload,
                    candidate_txs,
                    build_ms: 1,
                })
            },
        );

        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();
        tokio::time::sleep(Duration::from_millis(80)).await;

        assert!(coordinator.get_work_package().is_none());
        assert_eq!(coordinator.pending_transactions(8).len(), 0);

        pending_size.store(4, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(80)).await;

        let package = coordinator
            .get_work_package()
            .expect("target-sized work package should exist");
        assert_eq!(package.tx_count, 4);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "expensive recursive aggregation throughput benchmark; run manually"]
    async fn recursive_parallelism_scaling_smoke() {
        let worker_counts = [1usize, 2, 4];
        for tx_count in [32usize, 64usize] {
            let mut results = Vec::new();
            for workers in worker_counts {
                eprintln!(
                    "recursive_scaling_start tx_count={} workers={}",
                    tx_count, workers
                );
                match measure_recursive_prepared_latency(tx_count, workers).await {
                    Ok(elapsed_ms) => {
                        eprintln!(
                            "recursive_scaling tx_count={} workers={} prepared_ms={}",
                            tx_count, workers, elapsed_ms
                        );
                        results.push((workers, elapsed_ms));
                    }
                    Err(elapsed_ms) => {
                        eprintln!(
                            "recursive_scaling_timeout tx_count={} workers={} elapsed_ms={}",
                            tx_count, workers, elapsed_ms
                        );
                        results.push((workers, elapsed_ms));
                    }
                }
            }
            eprintln!("recursive_scaling_summary tx_count={} results={:?}", tx_count, results);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "single-case recursive aggregation benchmark; run manually"]
    async fn recursive_parallelism_single_case() {
        let tx_count = std::env::var("HEGEMON_RECURSIVE_BENCH_TX_COUNT")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(32);
        let workers = std::env::var("HEGEMON_RECURSIVE_BENCH_WORKERS")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(1);
        eprintln!(
            "recursive_single_start tx_count={} workers={}",
            tx_count, workers
        );
        match measure_recursive_prepared_latency(tx_count, workers).await {
            Ok(elapsed_ms) => {
                eprintln!(
                    "recursive_single_result tx_count={} workers={} prepared_ms={}",
                    tx_count, workers, elapsed_ms
                );
            }
            Err(elapsed_ms) => {
                eprintln!(
                    "recursive_single_timeout tx_count={} workers={} elapsed_ms={}",
                    tx_count, workers, elapsed_ms
                );
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn throughput_mode_adaptive_liveness_unjams_cold_target_batches() {
        let parent_hash = H256::repeat_byte(77);
        let mut config = test_config();
        config.target_txs = 4;
        config.queue_capacity = 1;
        config.liveness_lane = false;
        config.adaptive_liveness_timeout = Duration::from_millis(40);
        config.workers = 2;
        config.poll_interval = Duration::from_millis(10);

        let best = Arc::new(move || (parent_hash, 16u64));
        let pending =
            Arc::new(move |_max_txs: usize| vec![vec![1u8], vec![2u8], vec![3u8], vec![4u8]]);
        let build = Arc::new(
            move |parent: H256, _number: u64, candidate_txs: Vec<Vec<u8>>| {
                let tx_count = candidate_txs.len() as u32;
                let sleep_ms = if tx_count == 1 { 20 } else { 260 };
                std::thread::sleep(Duration::from_millis(sleep_ms));
                let commitment = [tx_count as u8; 48];
                let payload = ready_payload(tx_count, commitment);
                Ok(PreparedBundle {
                    key: candidate_bundle_key(parent, &payload),
                    payload,
                    candidate_txs,
                    build_ms: sleep_ms as u128,
                })
            },
        );

        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();

        tokio::time::sleep(Duration::from_millis(140)).await;
        // Target proving is still cold; adaptive singleton lane should be
        // prepared and visible for local block assembly.
        assert_eq!(coordinator.pending_transactions(8).len(), 1);
    }

    #[test]
    fn root_stage_metadata_uses_leaf_dependencies_for_two_level_tree() {
        let parent_hash = H256::repeat_byte(78);
        let block_number = 17u64;
        let arity = 8u16;
        let candidate_txs = vec![vec![1u8], vec![2u8], vec![3u8]];
        let tx_count = candidate_txs.len() as u32;
        let candidate_digest = ProverCoordinator::candidate_digest(&candidate_txs);

        let (level, shape_id, dependencies) = ProverCoordinator::root_stage_metadata(
            parent_hash,
            block_number,
            &candidate_txs,
            arity,
        );

        assert_eq!(level, 1);
        assert_ne!(shape_id, [0u8; 32]);
        assert_eq!(dependencies.len(), 3);

        let expected = (0..3u32)
            .map(|idx| {
                ProverCoordinator::stage_work_id(
                    parent_hash,
                    block_number,
                    "leaf_verify",
                    0,
                    idx,
                    arity,
                    tx_count,
                    candidate_digest,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(dependencies, expected);
    }

    #[test]
    fn root_stage_metadata_uses_merge_dependencies_for_multi_level_tree() {
        let parent_hash = H256::repeat_byte(79);
        let block_number = 18u64;
        let arity = 8u16;
        let candidate_txs = (0..20u8).map(|v| vec![v]).collect::<Vec<_>>();
        let tx_count = candidate_txs.len() as u32;
        let candidate_digest = ProverCoordinator::candidate_digest(&candidate_txs);

        let (level, _shape_id, dependencies) = ProverCoordinator::root_stage_metadata(
            parent_hash,
            block_number,
            &candidate_txs,
            arity,
        );

        assert_eq!(level, 2);
        assert_eq!(dependencies.len(), 3);

        let expected = (0..3u32)
            .map(|idx| {
                ProverCoordinator::stage_work_id(
                    parent_hash,
                    block_number,
                    "merge",
                    1,
                    idx,
                    arity,
                    tx_count,
                    candidate_digest,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(dependencies, expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn checkpoint_upsizing_uses_planned_ladder_by_default() {
        let parent_hash = H256::repeat_byte(75);
        let mut config = test_config();
        config.target_txs = 8;
        config.queue_capacity = 4;
        config.liveness_lane = true;
        config.incremental_upsizing = false;
        config.workers = 1;
        config.poll_interval = Duration::from_millis(10);

        let pending_size = Arc::new(AtomicUsize::new(1));
        let best = Arc::new(move || (parent_hash, 14u64));
        let pending = {
            let pending_size = Arc::clone(&pending_size);
            Arc::new(move |_max_txs: usize| {
                let size = pending_size.load(Ordering::SeqCst);
                (0..size).map(|idx| vec![(idx + 1) as u8]).collect()
            })
        };
        let build = Arc::new(
            move |parent: H256, _number: u64, candidate_txs: Vec<Vec<u8>>| {
                let tx_count = candidate_txs.len() as u32;
                let commitment = [tx_count as u8; 48];
                let payload = ready_payload(tx_count, commitment);
                Ok(PreparedBundle {
                    key: candidate_bundle_key(parent, &payload),
                    payload,
                    candidate_txs,
                    build_ms: 1,
                })
            },
        );

        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            coordinator
                .get_work_package()
                .expect("initial work package should exist")
                .tx_count,
            1
        );

        pending_size.store(3, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(80)).await;
        // Ladder for target=8, queue=4 is [1,2,4,8], so size 3 snaps to 2.
        assert_eq!(
            coordinator
                .get_work_package()
                .expect("ladder work package should exist")
                .tx_count,
            2
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn incremental_upsizing_can_restore_per_step_growth() {
        let parent_hash = H256::repeat_byte(76);
        let mut config = test_config();
        config.target_txs = 8;
        config.queue_capacity = 4;
        config.liveness_lane = true;
        config.incremental_upsizing = true;
        config.workers = 1;
        config.poll_interval = Duration::from_millis(10);

        let pending_size = Arc::new(AtomicUsize::new(1));
        let best = Arc::new(move || (parent_hash, 15u64));
        let pending = {
            let pending_size = Arc::clone(&pending_size);
            Arc::new(move |_max_txs: usize| {
                let size = pending_size.load(Ordering::SeqCst);
                (0..size).map(|idx| vec![(idx + 1) as u8]).collect()
            })
        };
        let build = Arc::new(
            move |parent: H256, _number: u64, candidate_txs: Vec<Vec<u8>>| {
                let tx_count = candidate_txs.len() as u32;
                let commitment = [tx_count as u8; 48];
                let payload = ready_payload(tx_count, commitment);
                Ok(PreparedBundle {
                    key: candidate_bundle_key(parent, &payload),
                    payload,
                    candidate_txs,
                    build_ms: 1,
                })
            },
        );

        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            coordinator
                .get_work_package()
                .expect("initial work package should exist")
                .tx_count,
            1
        );

        pending_size.store(3, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            coordinator
                .get_work_package()
                .expect("incremental work package should exist")
                .tx_count,
            3
        );
    }

    #[test]
    fn checkpoint_mode_reduces_unique_batch_shapes_during_ramp() {
        fn scheduled_best_counts(
            target_txs: usize,
            queue_capacity: usize,
            liveness_lane: bool,
            incremental_upsizing: bool,
        ) -> Vec<usize> {
            let mut existing_best = 0usize;
            let mut out = Vec::new();
            for candidate_len in 1..=target_txs {
                let plan_total_txs =
                    if incremental_upsizing || !liveness_lane || queue_capacity <= 1 {
                        candidate_len
                    } else {
                        target_txs.max(candidate_len)
                    };
                let mut variant_tx_counts = ProverCoordinator::candidate_variant_tx_counts(
                    plan_total_txs,
                    queue_capacity,
                    liveness_lane,
                );
                if plan_total_txs != candidate_len {
                    variant_tx_counts.retain(|count| *count <= candidate_len);
                }
                variant_tx_counts.retain(|count| *count > existing_best);
                if variant_tx_counts.is_empty() {
                    continue;
                }
                let best = variant_tx_counts.into_iter().max().unwrap_or(existing_best);
                existing_best = best;
                out.push(best);
            }
            out
        }

        let checkpoint = scheduled_best_counts(8, 4, true, false);
        let incremental = scheduled_best_counts(8, 4, true, true);

        assert_eq!(checkpoint, vec![1, 2, 4, 8]);
        assert_eq!(incremental, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(checkpoint.len() < incremental.len());
    }

    #[test]
    fn candidate_variant_tx_counts_keep_liveness_lane() {
        assert_eq!(
            ProverCoordinator::candidate_variant_tx_counts(1000, 1, true),
            vec![1000]
        );
        assert_eq!(
            ProverCoordinator::candidate_variant_tx_counts(1000, 2, true),
            vec![1, 1000]
        );
        assert_eq!(
            ProverCoordinator::candidate_variant_tx_counts(1000, 3, true),
            vec![1, 500, 1000]
        );
        assert_eq!(
            ProverCoordinator::candidate_variant_tx_counts(1000, 4, true),
            vec![1, 250, 500, 1000]
        );
        assert_eq!(
            ProverCoordinator::candidate_variant_tx_counts(3, 4, true),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn candidate_variant_tx_counts_can_disable_liveness_lane() {
        assert_eq!(
            ProverCoordinator::candidate_variant_tx_counts(1000, 4, false),
            vec![1000]
        );
        assert_eq!(
            ProverCoordinator::candidate_variant_tx_counts(3, 4, false),
            vec![3]
        );
    }
}
