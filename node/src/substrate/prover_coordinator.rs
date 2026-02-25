use parking_lot::Mutex;
use sp_core::H256;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BundleMatchKey {
    pub parent_hash: H256,
    pub tx_statements_commitment: [u8; 48],
    pub tx_count: u32,
}

#[derive(Clone, Debug)]
pub struct PreparedBundle {
    pub key: BundleMatchKey,
    pub payload: pallet_shielded_pool::types::BlockProofBundle,
    pub candidate_txs: Vec<Vec<u8>>,
    pub build_ms: u128,
}

#[derive(Clone, Debug)]
pub struct WorkPackage {
    pub package_id: String,
    pub parent_hash: H256,
    pub block_number: u64,
    pub tx_count: u32,
    pub candidate_txs: Vec<Vec<u8>>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug)]
pub enum WorkStatus {
    Pending,
    Accepted,
    Rejected(String),
    Expired,
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

#[allow(deprecated)]
#[deprecated(note = "Use PrepareBundleFn instead.")]
pub type BuildBatchFn = PrepareBundleFn;

#[derive(Clone, Debug)]
struct QueuedJob {
    id: u64,
    generation: u64,
    parent_hash: H256,
    block_number: u64,
    candidate_txs: Vec<Vec<u8>>,
}

#[derive(Clone)]
pub struct ProverCoordinator {
    state: Arc<Mutex<CoordinatorState>>,
    config: ProverCoordinatorConfig,
    best_block_fn: Arc<BestBlockFn>,
    pending_txs_fn: Arc<PendingTxsFn>,
    prepare_bundle_fn: Arc<PrepareBundleFn>,
}

#[derive(Clone, Copy, Debug)]
pub struct ProverCoordinatorConfig {
    pub workers: usize,
    pub target_txs: usize,
    pub queue_capacity: usize,
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
        let workers = std::env::var("HEGEMON_PROVER_WORKERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_workers)
            .max(1);
        let target_txs = std::env::var("HEGEMON_BATCH_TARGET_TXS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_target_txs)
            .max(1);
        let queue_capacity = std::env::var("HEGEMON_BATCH_QUEUE_CAPACITY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4usize)
            .max(1);
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

#[derive(Default)]
struct CoordinatorState {
    current_parent: Option<H256>,
    generation: u64,
    selected_txs: Vec<Vec<u8>>,
    prepared: HashMap<BundleMatchKey, PreparedBundle>,
    work_packages: HashMap<String, WorkPackageRecord>,
    latest_work_package: Option<String>,
    work_status: HashMap<String, WorkStatus>,
    source_submissions: HashMap<String, u32>,
    pending_jobs: VecDeque<QueuedJob>,
    inflight_jobs: HashSet<u64>,
    next_job_id: u64,
    stale_count: u64,
    last_build_ms: u128,
}

impl ProverCoordinator {
    pub fn new(
        config: ProverCoordinatorConfig,
        best_block_fn: Arc<BestBlockFn>,
        pending_txs_fn: Arc<PendingTxsFn>,
        prepare_bundle_fn: Arc<PrepareBundleFn>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new(Mutex::new(CoordinatorState::default())),
            config,
            best_block_fn,
            pending_txs_fn,
            prepare_bundle_fn,
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
        let mut txs = state.selected_txs.clone();
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
        let key = BundleMatchKey {
            parent_hash,
            tx_statements_commitment,
            tx_count,
        };
        state.prepared.get(&key).cloned()
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

    pub fn clear_on_import_success(&self, included_txs: &[Vec<u8>]) {
        let mut state = self.state.lock();
        if state.selected_txs == included_txs {
            state.selected_txs.clear();
        }
        state.prepared.clear();
        state.work_packages.clear();
        state.latest_work_package = None;
        state.work_status.clear();
        state.source_submissions.clear();
        state.pending_jobs.clear();
    }

    pub fn stale_count(&self) -> u64 {
        self.state.lock().stale_count
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
        let package_id = state.latest_work_package.clone()?;
        let package = state.work_packages.get(&package_id)?.package.clone();
        state
            .work_status
            .entry(package_id)
            .or_insert(WorkStatus::Pending);
        Some(package)
    }

    pub fn submit_external_work_result(
        &self,
        source: &str,
        package_id: &str,
        payload: pallet_shielded_pool::types::BlockProofBundle,
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
        if record.submissions >= self.config.max_submissions_per_package {
            state.work_status.insert(
                package_id.to_string(),
                WorkStatus::Rejected("package saturated".into()),
            );
            return Err("work package submission limit exceeded".to_string());
        }
        if payload.tx_count != record.package.tx_count {
            state.work_status.insert(
                package_id.to_string(),
                WorkStatus::Rejected("tx_count mismatch".into()),
            );
            return Err("work result tx_count mismatch".to_string());
        }

        if payload.commitment_proof.data.len() > self.config.max_payload_bytes
            || payload.aggregation_proof.data.len() > self.config.max_payload_bytes
        {
            state.work_status.insert(
                package_id.to_string(),
                WorkStatus::Rejected("payload too large".into()),
            );
            return Err("work result payload exceeds max size".to_string());
        }

        let package_parent = record.package.parent_hash;
        let package_candidate_txs = record.package.candidate_txs.clone();
        let key = BundleMatchKey {
            parent_hash: package_parent,
            tx_statements_commitment: payload.tx_statements_commitment,
            tx_count: payload.tx_count,
        };
        let incoming = PreparedBundle {
            key: key.clone(),
            payload,
            candidate_txs: package_candidate_txs,
            build_ms: 0,
        };

        let should_replace = match state.prepared.get(&key) {
            Some(existing) => incoming.payload.tx_count > existing.payload.tx_count,
            None => true,
        };

        if let Some(record) = state.work_packages.get_mut(package_id) {
            record.submissions = record.submissions.saturating_add(1);
        }
        state
            .source_submissions
            .insert(source_key, source_count.saturating_add(1));

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

    pub fn get_work_status(&self, package_id: &str) -> Option<WorkStatus> {
        let mut state = self.state.lock();
        Self::expire_work_packages_locked(&mut state);
        state.work_status.get(package_id).cloned()
    }

    async fn tick(self: &Arc<Self>) {
        let (parent_hash, best_number) = (self.best_block_fn)();
        {
            let mut state = self.state.lock();
            if state.current_parent != Some(parent_hash) {
                state.current_parent = Some(parent_hash);
                state.generation = state.generation.wrapping_add(1);
                state.selected_txs.clear();
                state.prepared.clear();
                state.work_packages.clear();
                state.latest_work_package = None;
                state.work_status.clear();
                state.source_submissions.clear();
                state.pending_jobs.clear();
            }
        }

        self.ensure_job_queue(parent_hash, best_number);
        self.dispatch_jobs();
    }

    fn ensure_job_queue(&self, parent_hash: H256, best_number: u64) {
        let needs_jobs = {
            let state = self.state.lock();
            state.prepared.is_empty()
                && state.pending_jobs.is_empty()
                && state.inflight_jobs.is_empty()
        };
        if !needs_jobs {
            return;
        }

        let mut candidate = (self.pending_txs_fn)(self.config.target_txs);
        candidate.truncate(self.config.target_txs);
        if candidate.is_empty() {
            return;
        }

        let variant_tx_counts =
            Self::candidate_variant_tx_counts(candidate.len(), self.config.queue_capacity);
        if variant_tx_counts.is_empty() {
            return;
        }
        let mut candidate_variants = VecDeque::with_capacity(variant_tx_counts.len());
        for tx_count in variant_tx_counts.iter().copied() {
            candidate_variants.push_back(candidate[..tx_count].to_vec());
        }

        let mut state = self.state.lock();
        if state.current_parent != Some(parent_hash)
            || !state.prepared.is_empty()
            || !state.pending_jobs.is_empty()
            || !state.inflight_jobs.is_empty()
        {
            return;
        }

        tracing::debug!(
            block_number = best_number.saturating_add(1),
            candidate_tx_count = candidate.len(),
            variant_tx_counts = ?variant_tx_counts,
            "Scheduling proven-batch candidate variants"
        );

        // Publish the largest candidate as the work package while local workers run
        // liveness-first variants in parallel.
        if let Some(primary_candidate) = candidate_variants.back().cloned() {
            let package = Self::build_work_package(
                parent_hash,
                best_number.saturating_add(1),
                primary_candidate,
                self.config.work_package_ttl,
            );
            let package_id = package.package_id.clone();
            state.latest_work_package = Some(package_id.clone());
            state.work_packages.insert(
                package_id.clone(),
                WorkPackageRecord {
                    package,
                    submissions: 0,
                },
            );
            state.work_status.insert(package_id, WorkStatus::Pending);
        }

        while let Some(candidate_txs) = candidate_variants.pop_front() {
            let job = QueuedJob {
                id: state.next_job_id,
                generation: state.generation,
                parent_hash,
                block_number: best_number.saturating_add(1),
                candidate_txs,
            };
            state.next_job_id = state.next_job_id.wrapping_add(1);
            state.pending_jobs.push_back(job);
        }
    }

    fn candidate_variant_tx_counts(total_txs: usize, queue_capacity: usize) -> Vec<usize> {
        if total_txs == 0 {
            return Vec::new();
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

    fn build_work_package(
        parent_hash: H256,
        block_number: u64,
        candidate_txs: Vec<Vec<u8>>,
        ttl: Duration,
    ) -> WorkPackage {
        let created_at_ms = Self::now_ms();
        let expires_at_ms = created_at_ms.saturating_add(ttl.as_millis() as u64);
        let tx_count = candidate_txs.len() as u32;
        let package_id = Self::work_package_id(parent_hash, block_number, &candidate_txs);
        WorkPackage {
            package_id,
            parent_hash,
            block_number,
            tx_count,
            candidate_txs,
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
        if let Some(latest) = state.latest_work_package.as_ref() {
            if !state.work_packages.contains_key(latest) {
                state.latest_work_package = None;
            }
        }
    }

    fn dispatch_jobs(self: &Arc<Self>) {
        loop {
            let job = {
                let mut state = self.state.lock();
                if state.inflight_jobs.len() >= self.config.workers {
                    return;
                }
                let Some(job) = state.pending_jobs.pop_front() else {
                    return;
                };
                state.inflight_jobs.insert(job.id);
                job
            };

            let prepare_bundle_fn = Arc::clone(&self.prepare_bundle_fn);
            let timeout = self.config.job_timeout;
            let state = Arc::clone(&self.state);
            let target_txs = self.config.target_txs;
            tokio::spawn(async move {
                let QueuedJob {
                    id,
                    generation,
                    parent_hash,
                    block_number,
                    candidate_txs,
                } = job;
                let candidate_tx_count = candidate_txs.len();
                let candidate_bytes = candidate_txs.iter().map(Vec::len).sum::<usize>();
                let job_package_id =
                    Self::work_package_id(parent_hash, block_number, &candidate_txs);

                let build = tokio::time::timeout(
                    timeout,
                    tokio::task::spawn_blocking(move || {
                        prepare_bundle_fn(parent_hash, block_number, candidate_txs)
                    }),
                )
                .await;

                let mut guard = state.lock();
                guard.inflight_jobs.remove(&id);

                if guard.current_parent != Some(parent_hash) || guard.generation != generation {
                    tracing::debug!(
                        job_id = id,
                        block_number,
                        tx_count = candidate_tx_count,
                        package_id = %job_package_id,
                        current_parent = ?guard.current_parent,
                        expected_parent = ?Some(parent_hash),
                        current_generation = guard.generation,
                        expected_generation = generation,
                        "Dropping stale proven-batch build result"
                    );
                    guard.stale_count = guard.stale_count.saturating_add(1);
                    return;
                }

                let built = match build {
                    Ok(join) => match join {
                        Ok(result) => result,
                        Err(err) => {
                            tracing::warn!(
                                job_id = id,
                                block_number,
                                tx_count = candidate_tx_count,
                                candidate_bytes,
                                package_id = %job_package_id,
                                error = ?err,
                                "Prover coordinator job panicked while preparing proven batch"
                            );
                            guard.stale_count = guard.stale_count.saturating_add(1);
                            if guard.prepared.is_empty() {
                                guard.selected_txs.clear();
                            }
                            return;
                        }
                    },
                    Err(_) => {
                        tracing::warn!(
                            job_id = id,
                            block_number,
                            tx_count = candidate_tx_count,
                            candidate_bytes,
                            timeout_ms = timeout.as_millis() as u64,
                            package_id = %job_package_id,
                            "Prover coordinator job timed out while preparing proven batch"
                        );
                        guard.stale_count = guard.stale_count.saturating_add(1);
                        if guard.prepared.is_empty() {
                            guard.selected_txs.clear();
                        }
                        return;
                    }
                };

                match built {
                    Ok(bundle) => {
                        let candidate_len = bundle.candidate_txs.len();
                        guard.last_build_ms = bundle.build_ms;
                        if candidate_len > guard.selected_txs.len() {
                            guard.selected_txs = bundle.candidate_txs.clone();
                        }
                        if candidate_len >= target_txs {
                            guard.pending_jobs.clear();
                        }
                        tracing::info!(
                            job_id = id,
                            block_number,
                            tx_count = candidate_len,
                            candidate_bytes,
                            build_ms = bundle.build_ms,
                            package_id = %job_package_id,
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
                            package_id = %job_package_id,
                            error = %error,
                            "Failed to prepare proven batch candidate"
                        );
                        if guard.prepared.is_empty() {
                            guard.selected_txs.clear();
                        }
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_config() -> ProverCoordinatorConfig {
        ProverCoordinatorConfig {
            workers: 1,
            target_txs: 1,
            queue_capacity: 1,
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
    ) -> pallet_shielded_pool::types::BlockProofBundle {
        pallet_shielded_pool::types::BlockProofBundle {
            version: pallet_shielded_pool::types::BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count,
            tx_statements_commitment: commitment,
            da_root: [7u8; 48],
            da_chunk_count: 1,
            commitment_proof: pallet_shielded_pool::types::StarkProof::from_bytes(vec![1, 2, 3]),
            aggregation_proof: pallet_shielded_pool::types::StarkProof::from_bytes(vec![4, 5, 6]),
            prover_claim: None,
        }
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
                Ok(PreparedBundle {
                    key: BundleMatchKey {
                        parent_hash: parent,
                        tx_statements_commitment: commitment,
                        tx_count,
                    },
                    payload: ready_payload(tx_count, commitment),
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
    async fn stale_parent_results_are_discarded() {
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
                Ok(PreparedBundle {
                    key: BundleMatchKey {
                        parent_hash: parent,
                        tx_statements_commitment: commitment,
                        tx_count: 1,
                    },
                    payload: ready_payload(1, commitment),
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
        assert!(stale_lookup.is_none());
        assert!(coordinator.stale_count() > 0);
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
        assert!(coordinator.pending_transactions(8).is_empty());
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

    #[test]
    fn candidate_variant_tx_counts_keep_liveness_lane() {
        assert_eq!(
            ProverCoordinator::candidate_variant_tx_counts(1000, 1),
            vec![1000]
        );
        assert_eq!(
            ProverCoordinator::candidate_variant_tx_counts(1000, 2),
            vec![1, 1000]
        );
        assert_eq!(
            ProverCoordinator::candidate_variant_tx_counts(1000, 3),
            vec![1, 500, 1000]
        );
        assert_eq!(
            ProverCoordinator::candidate_variant_tx_counts(1000, 4),
            vec![1, 250, 500, 1000]
        );
        assert_eq!(
            ProverCoordinator::candidate_variant_tx_counts(3, 4),
            vec![1, 2, 3]
        );
    }
}
