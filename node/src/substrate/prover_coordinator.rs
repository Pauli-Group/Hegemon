use parking_lot::Mutex;
use sp_core::H256;
use std::collections::{HashMap, VecDeque};
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BundleMatchKey {
    pub parent_hash: H256,
    pub tx_statements_commitment: [u8; 48],
    pub tx_count: u32,
    pub proof_mode: pallet_shielded_pool::types::BlockProofMode,
    pub proof_kind: pallet_shielded_pool::types::ProofArtifactKind,
    pub verifier_profile: pallet_shielded_pool::types::VerifierProfileDigest,
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

#[allow(deprecated)]
#[deprecated(note = "Use PrepareBundleFn instead.")]
pub type BuildBatchFn = PrepareBundleFn;

#[derive(Clone, Debug)]
struct QueuedJob {
    id: u64,
    generation: u64,
    parent_hash: H256,
    block_number: u64,
    enqueued_at: Instant,
    candidate_txs: Vec<Vec<u8>>,
}

#[derive(Debug)]
enum WorkerOutcome {
    Bundle(Box<Result<PreparedBundle, String>>),
    Panicked(String),
}

#[derive(Debug)]
struct WorkerJobResult {
    job: QueuedJob,
    queue_depth_after_pop: usize,
    enqueue_to_start_ms: u128,
    dispatch_to_start_ms: u128,
    build_elapsed_ms: u128,
    outcome: WorkerOutcome,
}

enum WorkerCommand {
    Run {
        job: QueuedJob,
        queue_depth_after_pop: usize,
        dispatched_at: Instant,
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
        let mut senders = Vec::with_capacity(workers);
        for worker_index in 0..workers {
            let (worker_tx, worker_rx) = mpsc::channel();
            let worker_results_tx = results_tx.clone();
            let worker_prepare_bundle_fn = Arc::clone(&prepare_bundle_fn);
            let worker_name = format!("hegemon-artifact-worker-{worker_index}");
            let _ = std::thread::Builder::new()
                .name(worker_name)
                .spawn(move || {
                    while let Ok(command) = worker_rx.recv() {
                        let WorkerCommand::Run {
                            job,
                            queue_depth_after_pop,
                            dispatched_at,
                        } = command
                        else {
                            break;
                        };
                        let build_started = Instant::now();
                        let enqueue_to_start_ms =
                            build_started.duration_since(job.enqueued_at).as_millis();
                        let dispatch_to_start_ms =
                            build_started.duration_since(dispatched_at).as_millis();
                        let parent_hash = job.parent_hash;
                        let block_number = job.block_number;
                        let candidate_txs = job.candidate_txs.clone();
                        let outcome = match panic::catch_unwind(AssertUnwindSafe(|| {
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
                        };
                        let build_elapsed_ms = build_started.elapsed().as_millis();
                        let _ = worker_results_tx.send(WorkerJobResult {
                            job,
                            queue_depth_after_pop,
                            enqueue_to_start_ms,
                            dispatch_to_start_ms,
                            build_elapsed_ms,
                            outcome,
                        });
                    }
                });
            senders.push(worker_tx);
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
        let dispatched_at = Instant::now();
        self.senders
            .get(worker_index % self.senders.len())
            .and_then(|sender| {
                sender
                    .send(WorkerCommand::Run {
                        job,
                        queue_depth_after_pop,
                        dispatched_at,
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
}

impl ProverCoordinatorConfig {
    pub fn from_env(default_target_txs: usize) -> Self {
        let default_workers = std::thread::available_parallelism()
            .map(|threads| threads.get().min(2))
            .unwrap_or(1usize)
            .max(1);
        let configured_workers = std::env::var("HEGEMON_AGG_STAGE_LOCAL_PARALLELISM")
            .ok()
            .and_then(|v| v.parse().ok())
            .or_else(|| {
                std::env::var("HEGEMON_PROVER_WORKERS")
                    .ok()
                    .and_then(|v| v.parse().ok())
            });
        let mining_enabled = std::env::var("HEGEMON_MINE")
            .ok()
            .map(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        let requires_prepared_bundles = ProverCoordinator::proof_mode_requires_prepared_bundles(
            ProverCoordinator::prepared_proof_mode_from_env(),
        );
        let workers = match configured_workers {
            Some(0) if mining_enabled && requires_prepared_bundles => {
                tracing::warn!(
                    mining_enabled,
                    ?requires_prepared_bundles,
                    configured_workers = 0,
                    "Configured prover workers=0 would deadlock prepared-bundle authoring; clamping to 1"
                );
                1
            }
            Some(workers) => workers,
            None => default_workers,
        };
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
            .unwrap_or(180_000u64);
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
        }
    }
}

#[derive(Default)]
struct CoordinatorState {
    current_parent: Option<H256>,
    generation: u64,
    target_batch_scheduled_at_ms: Option<u64>,
    adaptive_liveness_fired_generation: Option<u64>,
    selected_txs: Vec<Vec<u8>>,
    prepared: HashMap<BundleMatchKey, PreparedBundle>,
    pending_jobs: VecDeque<QueuedJob>,
    inflight_jobs: HashMap<u64, u64>,
    inflight_candidates: HashMap<u64, Vec<Vec<u8>>>,
    next_job_id: u64,
    stale_count: u64,
    last_build_ms: u128,
}

impl ProverCoordinator {
    pub(crate) fn final_bundle_id(
        parent_hash: H256,
        block_number: u64,
        tx_statements_commitment: [u8; 48],
        tx_count: u32,
    ) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(parent_hash.as_bytes());
        bytes.extend_from_slice(&block_number.to_le_bytes());
        bytes.extend_from_slice(&tx_statements_commitment);
        bytes.extend_from_slice(&tx_count.to_le_bytes());
        hex::encode(sp_core::hashing::blake2_256(&bytes))
    }

    pub fn new(
        config: ProverCoordinatorConfig,
        best_block_fn: Arc<BestBlockFn>,
        pending_txs_fn: Arc<PendingTxsFn>,
        prepare_bundle_fn: Arc<PrepareBundleFn>,
    ) -> Arc<Self> {
        let worker_pool = Arc::new(WorkerPool::new(config.workers, prepare_bundle_fn));
        Arc::new(Self {
            state: Arc::new(Mutex::new(CoordinatorState::default())),
            config,
            best_block_fn,
            pending_txs_fn,
            worker_pool,
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
        let proof_mode = Self::prepared_proof_mode_from_env();
        let mut txs = if Self::proof_mode_requires_prepared_bundles(proof_mode) {
            if let Some(prepared) = Self::best_prepared_candidate_locked(&state) {
                prepared
            } else {
                Self::selected_or_pending_candidate_locked(&state)
            }
        } else {
            Self::selected_or_pending_candidate_locked(&state)
        };
        txs.truncate(max_txs);
        txs
    }

    pub fn authoring_transactions(&self, max_txs: usize) -> Vec<Vec<u8>> {
        let state = self.state.lock();
        let proof_mode = Self::prepared_proof_mode_from_env();
        let mut txs = if Self::proof_mode_requires_prepared_bundles(proof_mode) {
            Self::best_prepared_candidate_locked(&state).unwrap_or_default()
        } else {
            Self::selected_or_pending_candidate_locked(&state)
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
            state.pending_jobs.clear();
            state.inflight_jobs.clear();
            state.inflight_candidates.clear();
        }

        let (parent_hash, best_number) = (self.best_block_fn)();
        {
            let mut state = self.state.lock();
            if state.current_parent != Some(parent_hash) {
                state.current_parent = Some(parent_hash);
                state.generation = state.generation.wrapping_add(1);
                state.target_batch_scheduled_at_ms = None;
                state.adaptive_liveness_fired_generation = None;
                state.selected_txs.clear();
                state.pending_jobs.clear();
                state.inflight_jobs.clear();
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
                state.pending_jobs.clear();
                state.inflight_jobs.clear();
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

        let selected_mode = Self::prepared_proof_mode_from_env();
        if !Self::proof_mode_requires_prepared_bundles(selected_mode) {
            state.selected_txs = candidate;
            state.target_batch_scheduled_at_ms = None;
            state.adaptive_liveness_fired_generation = None;
            state.pending_jobs.clear();
            state.inflight_jobs.clear();
            state.inflight_candidates.clear();
            return;
        }

        let mut existing_best = Self::best_candidate_len_locked(&state);
        if candidate.is_empty() {
            if existing_best == 0 {
                state.target_batch_scheduled_at_ms = None;
                state.adaptive_liveness_fired_generation = None;
                state.selected_txs.clear();
                state.pending_jobs.clear();
                state.inflight_jobs.clear();
                state.inflight_candidates.clear();
            }
            return;
        }

        if !self.config.liveness_lane && candidate.len() < self.config.target_txs {
            return;
        }

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
            state.inflight_jobs.clear();
            state.inflight_candidates.clear();
            existing_best = Self::best_candidate_len_locked(&state);
            if candidate.len() <= existing_best {
                return;
            }
        }

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

        if state.selected_txs.is_empty() {
            if let Some(liveness_candidate) = candidate_variants.front().cloned() {
                state.selected_txs = liveness_candidate;
            }
        }

        if let Some(primary_candidate) = candidate_variants.back().cloned() {
            if primary_candidate.len() >= self.config.target_txs {
                state.target_batch_scheduled_at_ms = Some(Self::now_ms());
                state.adaptive_liveness_fired_generation = None;
            }
        }

        while let Some(candidate_txs) = candidate_variants.pop_front() {
            let job = QueuedJob {
                id: state.next_job_id,
                generation: state.generation,
                parent_hash,
                block_number: best_number.saturating_add(1),
                enqueued_at: Instant::now(),
                candidate_txs,
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
        let job = QueuedJob {
            id: state.next_job_id,
            generation: state.generation,
            parent_hash,
            block_number: best_number.saturating_add(1),
            enqueued_at: Instant::now(),
            candidate_txs: singleton_candidate,
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

    fn inflight_current_generation_count(state: &CoordinatorState) -> usize {
        state
            .inflight_jobs
            .values()
            .filter(|generation| **generation == state.generation)
            .count()
    }

    fn inflight_total_cap(&self) -> usize {
        self.config.workers.saturating_mul(2).max(1)
    }

    fn dispatch_jobs(self: &Arc<Self>) {
        if self.worker_pool.worker_count() == 0 {
            return;
        }

        loop {
            let (job, queue_depth_after_pop, worker_index) = {
                let mut state = self.state.lock();
                let inflight_current = Self::inflight_current_generation_count(&state);
                let inflight_cap = self
                    .config
                    .workers
                    .min(self.config.max_inflight_per_level.max(1));
                if inflight_current >= inflight_cap {
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
                let Some(job) = state.pending_jobs.pop_front() else {
                    return;
                };
                let queue_depth_after_pop = state.pending_jobs.len();
                state.inflight_jobs.insert(job.id, job.generation);
                state
                    .inflight_candidates
                    .insert(job.id, job.candidate_txs.clone());
                let candidate_digest = Self::candidate_digest(&job.candidate_txs);
                let hash_prefix =
                    u64::from_le_bytes(candidate_digest[..8].try_into().unwrap_or([0u8; 8]));
                let worker_index = hash_prefix as usize % self.worker_pool.worker_count();
                (job, queue_depth_after_pop, worker_index)
            };

            if !self
                .worker_pool
                .dispatch(worker_index, job.clone(), queue_depth_after_pop)
            {
                let mut state = self.state.lock();
                state.inflight_jobs.remove(&job.id);
                state.inflight_candidates.remove(&job.id);
                state.stale_count = state.stale_count.saturating_add(1);
                tracing::warn!(
                    job_id = job.id,
                    tx_count = job.candidate_txs.len(),
                    worker_index,
                    "Failed to dispatch proven-batch job to worker"
                );
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

    fn handle_worker_result(&self, result: WorkerJobResult) {
        let WorkerJobResult {
            job:
                QueuedJob {
                    id,
                    generation,
                    parent_hash,
                    block_number,
                    enqueued_at,
                    candidate_txs,
                },
            queue_depth_after_pop,
            enqueue_to_start_ms,
            dispatch_to_start_ms,
            build_elapsed_ms,
            outcome,
        } = result;

        let total_job_age_ms = enqueued_at.elapsed().as_millis();
        let candidate_tx_count = candidate_txs.len();
        let candidate_bytes = candidate_txs.iter().map(Vec::len).sum::<usize>();
        let timeout = self.config.job_timeout;
        let target_txs = self.config.target_txs;

        let mut guard = self.state.lock();
        guard.inflight_jobs.remove(&id);
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
                tx_count = candidate_tx_count,
                candidate_bytes,
                elapsed_ms = build_elapsed_ms as u64,
                timeout_ms = timeout.as_millis() as u64,
                "Prover coordinator job exceeded timeout budget while preparing proven batch"
            );
        }

        match outcome {
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
                        target: "prover::last_mile",
                        trace_ts_ms = Self::now_ms(),
                        bundle_id = %Self::final_bundle_id(
                            bundle.key.parent_hash,
                            block_number,
                            bundle.key.tx_statements_commitment,
                            bundle.key.tx_count,
                        ),
                        artifact_hash = %hex::encode(bundle.key.artifact_hash),
                        parent_hash = ?bundle.key.parent_hash,
                        block_number,
                        tx_count = bundle.key.tx_count,
                        tx_statements_commitment = %hex::encode(bundle.key.tx_statements_commitment),
                        build_ms = bundle.build_ms,
                        total_job_age_ms,
                        "prepared_bundle_ready"
                    );
                    tracing::info!(
                        job_id = id,
                        block_number,
                        tx_count = candidate_len,
                        candidate_bytes,
                        queue_depth = queue_depth_after_pop,
                        queue_wait_ms = enqueue_to_start_ms,
                        dispatch_wait_ms = dispatch_to_start_ms,
                        total_job_age_ms,
                        build_ms = bundle.build_ms,
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
                        tx_count = candidate_tx_count,
                        candidate_bytes,
                        error = %error,
                        "Failed to prepare proven batch candidate"
                    );
                }
            },
            WorkerOutcome::Panicked(error) => {
                tracing::warn!(
                    job_id = id,
                    block_number,
                    tx_count = candidate_tx_count,
                    candidate_bytes,
                    error = %error,
                    "Prover coordinator job panicked while preparing proven batch"
                );
                guard.stale_count = guard.stale_count.saturating_add(1);
            }
        }
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

    fn selected_or_pending_candidate_locked(state: &CoordinatorState) -> Vec<Vec<u8>> {
        if state.selected_txs.is_empty() {
            Self::best_pending_candidate_locked(state).unwrap_or_default()
        } else {
            state.selected_txs.clone()
        }
    }

    fn best_prepared_candidate_locked(state: &CoordinatorState) -> Option<Vec<Vec<u8>>> {
        let current_parent = state.current_parent;
        let mut best_current_parent: Option<&PreparedBundle> = None;
        for bundle in state.prepared.values() {
            if Some(bundle.key.parent_hash) == current_parent
                && best_current_parent
                    .is_none_or(|current| bundle.candidate_txs.len() > current.candidate_txs.len())
            {
                best_current_parent = Some(bundle);
            }
        }

        best_current_parent.map(|bundle| bundle.candidate_txs.clone())
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

    fn prepared_proof_mode_from_env() -> pallet_shielded_pool::types::BlockProofMode {
        let raw = std::env::var("HEGEMON_BLOCK_PROOF_MODE").unwrap_or_default();
        if raw.is_empty()
            || raw.eq_ignore_ascii_case("receipt_root")
            || raw.eq_ignore_ascii_case("receipt-root")
        {
            return pallet_shielded_pool::types::BlockProofMode::ReceiptRoot;
        }
        tracing::warn!(
            mode = raw,
            "legacy or unknown HEGEMON_BLOCK_PROOF_MODE requested; forcing receipt_root on the product path"
        );
        pallet_shielded_pool::types::BlockProofMode::ReceiptRoot
    }

    fn proof_mode_requires_prepared_bundles(
        mode: pallet_shielded_pool::types::BlockProofMode,
    ) -> bool {
        matches!(
            mode,
            pallet_shielded_pool::types::BlockProofMode::ReceiptRoot
        )
    }

    fn candidate_digest(candidate_txs: &[Vec<u8>]) -> [u8; 32] {
        let mut bytes = Vec::new();
        for tx in candidate_txs {
            bytes.extend_from_slice(&(tx.len() as u64).to_le_bytes());
            bytes.extend_from_slice(tx);
        }
        sp_core::hashing::blake2_256(&bytes)
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

fn proof_mode_rank(mode: pallet_shielded_pool::types::BlockProofMode) -> u8 {
    match mode {
        pallet_shielded_pool::types::BlockProofMode::ReceiptRoot => 0,
        pallet_shielded_pool::types::BlockProofMode::InlineTx => 1,
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
        proof_kind: payload.proof_kind,
        verifier_profile: payload.verifier_profile,
        artifact_hash: crate::substrate::artifact_market::candidate_artifact_hash(payload),
    }
}

fn compare_prepared_bundles(left: &PreparedBundle, right: &PreparedBundle) -> std::cmp::Ordering {
    left.key
        .tx_count
        .cmp(&right.key.tx_count)
        .then_with(|| {
            proof_mode_rank(left.payload.proof_mode).cmp(&proof_mode_rank(right.payload.proof_mode))
        })
        .then_with(|| {
            crate::substrate::artifact_market::candidate_artifact_hash(&right.payload).cmp(
                &crate::substrate::artifact_market::candidate_artifact_hash(&left.payload),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::MutexGuard as StdMutexGuard;

    struct BlockProofModeGuard {
        previous: Option<String>,
        _guard: StdMutexGuard<'static, ()>,
    }

    impl Drop for BlockProofModeGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => unsafe {
                    std::env::set_var("HEGEMON_BLOCK_PROOF_MODE", value);
                },
                None => unsafe {
                    std::env::remove_var("HEGEMON_BLOCK_PROOF_MODE");
                },
            }
        }
    }

    fn set_block_proof_mode(mode: &str) -> BlockProofModeGuard {
        let guard = crate::substrate::test_env_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let previous = std::env::var("HEGEMON_BLOCK_PROOF_MODE").ok();
        unsafe {
            std::env::set_var("HEGEMON_BLOCK_PROOF_MODE", mode);
        }
        BlockProofModeGuard {
            previous,
            _guard: guard,
        }
    }

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
            proof_mode: pallet_shielded_pool::types::BlockProofMode::ReceiptRoot,
            proof_kind: pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot,
            verifier_profile: crate::substrate::artifact_market::legacy_pallet_artifact_identity(
                pallet_shielded_pool::types::BlockProofMode::ReceiptRoot,
            )
            .1,
            receipt_root: Some(pallet_shielded_pool::types::ReceiptRootProofPayload {
                root_proof: pallet_shielded_pool::types::StarkProof::from_bytes(vec![4, 5, 6]),
                metadata: pallet_shielded_pool::types::ReceiptRootMetadata {
                    relation_id: [9u8; 32],
                    shape_digest: [10u8; 32],
                    leaf_count: tx_count,
                    fold_count: 0,
                },
                receipts: Vec::new(),
            }),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ready_batch_lookup_uses_parent_commitment_and_tx_count() {
        let _mode = set_block_proof_mode("receipt_root");
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
        let _mode = set_block_proof_mode("receipt_root");
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
    async fn pending_transactions_do_not_fallback_to_stale_prepared_parent() {
        let _mode = set_block_proof_mode("receipt_root");
        let first_parent = H256::repeat_byte(91);
        let second_parent = H256::repeat_byte(92);
        let best_state = Arc::new(Mutex::new((first_parent, 30u64)));
        let include_pending = Arc::new(AtomicBool::new(true));
        let config = test_config();
        let best = {
            let state = Arc::clone(&best_state);
            Arc::new(move || {
                let guard = state.lock();
                (guard.0, guard.1)
            })
        };
        let pending = {
            let include_pending = Arc::clone(&include_pending);
            Arc::new(move |_max_txs: usize| {
                if include_pending.load(Ordering::SeqCst) {
                    vec![vec![0xABu8]]
                } else {
                    Vec::new()
                }
            })
        };
        let build = Arc::new(
            move |parent: H256, _number: u64, candidate_txs: Vec<Vec<u8>>| {
                std::thread::sleep(Duration::from_millis(150));
                let commitment = [candidate_txs.len() as u8; 48];
                let payload = ready_payload(candidate_txs.len() as u32, commitment);
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

        include_pending.store(false, Ordering::SeqCst);
        {
            let mut guard = best_state.lock();
            guard.0 = second_parent;
            guard.1 = 31;
        }
        tokio::time::sleep(Duration::from_millis(260)).await;

        assert!(coordinator
            .lookup_prepared_bundle(first_parent, [1u8; 48], 1)
            .is_some());
        assert!(coordinator
            .lookup_prepared_bundle_any_parent([1u8; 48], 1)
            .is_some());
        assert!(coordinator.pending_transactions(8).is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parent_rollover_still_schedules_new_work_package() {
        let _mode = set_block_proof_mode("receipt_root");
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
        assert!(coordinator
            .lookup_prepared_bundle(first_parent, [1u8; 48], 1)
            .is_some());

        {
            let mut guard = best_state.lock();
            guard.0 = second_parent;
            guard.1 = 21;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(coordinator
            .lookup_prepared_bundle(second_parent, [1u8; 48], 1)
            .is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_jobs_release_worker_slots() {
        let _mode = set_block_proof_mode("receipt_root");
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
        assert_eq!(coordinator.pending_transactions(8), vec![vec![4u8]]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn throughput_mode_defers_until_target_batch_is_available() {
        let _mode = set_block_proof_mode("receipt_root");
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

        assert!(coordinator
            .lookup_prepared_bundle(parent_hash, [1u8; 48], 1)
            .is_none());
        assert_eq!(coordinator.pending_transactions(8).len(), 0);

        pending_size.store(4, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(80)).await;

        assert_eq!(coordinator.pending_transactions(8).len(), 4);
        assert!(coordinator
            .lookup_prepared_bundle(parent_hash, [4u8; 48], 4)
            .is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn work_package_upsizes_while_smaller_job_is_inflight() {
        let _mode = set_block_proof_mode("receipt_root");
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

        assert_eq!(coordinator.pending_transactions(8).len(), 1);

        pending_size.store(8, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(80)).await;

        assert_eq!(coordinator.pending_transactions(8).len(), 8);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn throughput_mode_adaptive_liveness_unjams_cold_target_batches() {
        let _mode = set_block_proof_mode("receipt_root");
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
        assert_eq!(coordinator.pending_transactions(8).len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn checkpoint_upsizing_uses_planned_ladder_by_default() {
        let _mode = set_block_proof_mode("receipt_root");
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
        assert_eq!(coordinator.pending_transactions(8).len(), 1);

        pending_size.store(3, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(coordinator.pending_transactions(8).len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn incremental_upsizing_can_restore_per_step_growth() {
        let _mode = set_block_proof_mode("receipt_root");
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
        assert_eq!(coordinator.pending_transactions(8).len(), 1);

        pending_size.store(3, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(coordinator.pending_transactions(8).len(), 3);
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
    fn candidate_variant_tx_counts_disable_liveness_when_requested() {
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
