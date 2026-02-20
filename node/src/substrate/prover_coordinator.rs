use parking_lot::Mutex;
use sp_core::H256;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReadyBatchKey {
    pub parent_hash: H256,
    pub tx_statements_commitment: [u8; 48],
    pub tx_count: u32,
}

#[derive(Clone, Debug)]
pub struct ReadyBatch {
    pub key: ReadyBatchKey,
    pub payload: pallet_shielded_pool::types::ProvenBatchV1,
    pub candidate_txs: Vec<Vec<u8>>,
    pub build_ms: u128,
}

pub type BestBlockFn = dyn Fn() -> (H256, u64) + Send + Sync + 'static;
pub type PendingTxsFn = dyn Fn(usize) -> Vec<Vec<u8>> + Send + Sync + 'static;
pub type BuildBatchFn =
    dyn Fn(H256, u64, Vec<Vec<u8>>) -> Result<ReadyBatch, String> + Send + Sync + 'static;

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
    build_batch_fn: Arc<BuildBatchFn>,
}

#[derive(Clone, Copy, Debug)]
pub struct ProverCoordinatorConfig {
    pub workers: usize,
    pub target_txs: usize,
    pub queue_capacity: usize,
    pub poll_interval: Duration,
    pub job_timeout: Duration,
}

impl ProverCoordinatorConfig {
    pub fn from_env(default_target_txs: usize) -> Self {
        let workers = std::env::var("HEGEMON_PROVER_WORKERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1usize)
            .max(1);
        let target_txs = std::env::var("HEGEMON_BATCH_TARGET_TXS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_target_txs)
            .max(1);
        let queue_capacity = std::env::var("HEGEMON_BATCH_QUEUE_CAPACITY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2usize)
            .max(1);
        let job_timeout_ms = std::env::var("HEGEMON_BATCH_JOB_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(55_000u64);
        Self {
            workers,
            target_txs,
            queue_capacity,
            poll_interval: Duration::from_millis(250),
            job_timeout: Duration::from_millis(job_timeout_ms),
        }
    }
}

#[derive(Default)]
struct CoordinatorState {
    current_parent: Option<H256>,
    generation: u64,
    selected_txs: Vec<Vec<u8>>,
    ready: HashMap<ReadyBatchKey, ReadyBatch>,
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
        build_batch_fn: Arc<BuildBatchFn>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new(Mutex::new(CoordinatorState::default())),
            config,
            best_block_fn,
            pending_txs_fn,
            build_batch_fn,
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

    pub fn lookup_ready_batch(
        &self,
        parent_hash: H256,
        tx_statements_commitment: [u8; 48],
        tx_count: u32,
    ) -> Option<ReadyBatch> {
        let state = self.state.lock();
        let key = ReadyBatchKey {
            parent_hash,
            tx_statements_commitment,
            tx_count,
        };
        state.ready.get(&key).cloned()
    }

    pub fn clear_on_import_success(&self, included_txs: &[Vec<u8>]) {
        let mut state = self.state.lock();
        if state.selected_txs == included_txs {
            state.selected_txs.clear();
        }
        state.ready.clear();
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

    async fn tick(self: &Arc<Self>) {
        let (parent_hash, best_number) = (self.best_block_fn)();
        {
            let mut state = self.state.lock();
            if state.current_parent != Some(parent_hash) {
                state.current_parent = Some(parent_hash);
                state.generation = state.generation.wrapping_add(1);
                state.selected_txs.clear();
                state.ready.clear();
                state.pending_jobs.clear();
            }
        }

        self.ensure_job_queue(parent_hash, best_number);
        self.dispatch_jobs();
    }

    fn ensure_job_queue(&self, parent_hash: H256, best_number: u64) {
        let needs_jobs = {
            let state = self.state.lock();
            state.ready.is_empty()
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

        let queue_capacity = self.config.queue_capacity.max(1);
        let mut candidate_variants = VecDeque::new();
        for trim in 0..queue_capacity {
            let tx_count = candidate.len().saturating_sub(trim);
            if tx_count == 0 {
                break;
            }
            candidate_variants.push_back(candidate[..tx_count].to_vec());
        }
        if candidate_variants.is_empty() {
            return;
        }

        let mut state = self.state.lock();
        if state.current_parent != Some(parent_hash)
            || !state.ready.is_empty()
            || !state.pending_jobs.is_empty()
            || !state.inflight_jobs.is_empty()
        {
            return;
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

            let build_fn = Arc::clone(&self.build_batch_fn);
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

                let build = tokio::time::timeout(
                    timeout,
                    tokio::task::spawn_blocking(move || {
                        build_fn(parent_hash, block_number, candidate_txs)
                    }),
                )
                .await;

                let mut guard = state.lock();
                guard.inflight_jobs.remove(&id);

                if guard.current_parent != Some(parent_hash) || guard.generation != generation {
                    guard.stale_count = guard.stale_count.saturating_add(1);
                    return;
                }

                let built = match build {
                    Ok(join) => match join {
                        Ok(result) => result,
                        Err(_) => {
                            guard.stale_count = guard.stale_count.saturating_add(1);
                            if guard.ready.is_empty() {
                                guard.selected_txs.clear();
                            }
                            return;
                        }
                    },
                    Err(_) => {
                        guard.stale_count = guard.stale_count.saturating_add(1);
                        if guard.ready.is_empty() {
                            guard.selected_txs.clear();
                        }
                        return;
                    }
                };

                match built {
                    Ok(batch) => {
                        let candidate_len = batch.candidate_txs.len();
                        guard.last_build_ms = batch.build_ms;
                        if candidate_len > guard.selected_txs.len() {
                            guard.selected_txs = batch.candidate_txs.clone();
                        }
                        if candidate_len >= target_txs {
                            guard.pending_jobs.clear();
                        }
                        guard.ready.insert(batch.key.clone(), batch);
                    }
                    Err(_) => {
                        if guard.ready.is_empty() {
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

    fn ready_payload(
        tx_count: u32,
        commitment: [u8; 48],
    ) -> pallet_shielded_pool::types::ProvenBatchV1 {
        pallet_shielded_pool::types::ProvenBatchV1 {
            version: pallet_shielded_pool::types::PROVEN_BATCH_V1_VERSION,
            tx_count,
            tx_statements_commitment: commitment,
            da_root: [7u8; 48],
            da_chunk_count: 1,
            commitment_proof: pallet_shielded_pool::types::StarkProof::from_bytes(vec![1, 2, 3]),
            aggregation_proof: pallet_shielded_pool::types::StarkProof::from_bytes(vec![4, 5, 6]),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ready_batch_lookup_uses_parent_commitment_and_tx_count() {
        let parent_hash = H256::repeat_byte(11);
        let config = ProverCoordinatorConfig {
            workers: 1,
            target_txs: 2,
            queue_capacity: 1,
            poll_interval: Duration::from_millis(10),
            job_timeout: Duration::from_secs(2),
        };
        let best = Arc::new(move || (parent_hash, 9u64));
        let pending = Arc::new(move |_max_txs: usize| vec![vec![1u8], vec![2u8]]);
        let build = Arc::new(
            move |parent: H256, _number: u64, candidate_txs: Vec<Vec<u8>>| {
                let tx_count = candidate_txs.len() as u32;
                let commitment = [tx_count as u8; 48];
                Ok(ReadyBatch {
                    key: ReadyBatchKey {
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
        let looked_up = coordinator.lookup_ready_batch(parent_hash, commitment, 2);
        assert!(looked_up.is_some());
        assert_eq!(coordinator.pending_transactions(8).len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_parent_results_are_discarded() {
        let first_parent = H256::repeat_byte(21);
        let second_parent = H256::repeat_byte(22);
        let best_state = Arc::new(Mutex::new((first_parent, 12u64)));
        let config = ProverCoordinatorConfig {
            workers: 1,
            target_txs: 1,
            queue_capacity: 1,
            poll_interval: Duration::from_millis(10),
            job_timeout: Duration::from_secs(2),
        };
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
                Ok(ReadyBatch {
                    key: ReadyBatchKey {
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

        let stale_lookup = coordinator.lookup_ready_batch(first_parent, [1u8; 48], 1);
        assert!(stale_lookup.is_none());
        assert!(coordinator.stale_count() > 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_jobs_release_worker_slots() {
        let parent_hash = H256::repeat_byte(31);
        let pending_calls = Arc::new(AtomicUsize::new(0));
        let config = ProverCoordinatorConfig {
            workers: 1,
            target_txs: 1,
            queue_capacity: 1,
            poll_interval: Duration::from_millis(25),
            job_timeout: Duration::from_secs(1),
        };
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
}
