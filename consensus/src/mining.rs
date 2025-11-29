//! PoW Mining Worker for Substrate Integration
//!
//! This module provides the mining worker implementation that integrates with
//! the Substrate block production pipeline. It handles:
//!
//! - Mining thread management
//! - Work coordination between threads
//! - Block template updates
//! - Solution submission
//!
//! # Architecture
//!
//! The mining worker spawns multiple threads that cooperatively search for
//! valid PoW solutions. Each thread works on a different nonce range to
//! avoid duplicate work.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     Mining Coordinator                          │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
//! │  │  Thread 0   │  │  Thread 1   │  │  Thread N   │             │
//! │  │ nonces 0-N  │  │ nonces N-2N │  │ nonces...   │  ...        │
//! │  └─────────────┘  └─────────────┘  └─────────────┘             │
//! │         │                │                │                     │
//! │         └────────────────┼────────────────┘                     │
//! │                          │                                      │
//! │                    ┌─────▼─────┐                                │
//! │                    │  Solution │                                │
//! │                    │ Submitter │                                │
//! │                    └───────────┘                                │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use crate::substrate_pow::{Blake3Seal, mine_round};
use sp_core::H256;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Mining statistics
#[derive(Debug, Default)]
pub struct MiningStats {
    /// Total hashes computed
    pub total_hashes: AtomicU64,
    /// Blocks found
    pub blocks_found: AtomicU64,
    /// Start time (for hashrate calculation)
    start_time: Option<Instant>,
}

impl MiningStats {
    /// Create new mining statistics
    pub fn new() -> Self {
        Self {
            total_hashes: AtomicU64::new(0),
            blocks_found: AtomicU64::new(0),
            start_time: Some(Instant::now()),
        }
    }

    /// Add hashes to the counter
    pub fn add_hashes(&self, count: u64) {
        self.total_hashes.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment blocks found
    pub fn add_block(&self) {
        self.blocks_found.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current hashrate in H/s
    pub fn hashrate(&self) -> f64 {
        if let Some(start) = self.start_time {
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                return self.total_hashes.load(Ordering::Relaxed) as f64 / elapsed;
            }
        }
        0.0
    }

    /// Get total hashes
    pub fn total(&self) -> u64 {
        self.total_hashes.load(Ordering::Relaxed)
    }

    /// Get blocks found
    pub fn blocks(&self) -> u64 {
        self.blocks_found.load(Ordering::Relaxed)
    }
}

/// Mining work template
#[derive(Clone, Debug)]
pub struct MiningWork {
    /// Block pre-hash (header hash before seal)
    pub pre_hash: H256,
    /// Current difficulty in compact bits
    pub pow_bits: u32,
    /// Block height being mined
    pub height: u64,
    /// Parent block hash
    pub parent_hash: H256,
}

/// Result of a mining attempt
#[derive(Clone, Debug)]
pub struct MiningSolution {
    /// The valid seal found
    pub seal: Blake3Seal,
    /// The work this solution is for
    pub work: MiningWork,
}

/// Mining worker that coordinates mining threads
pub struct MiningWorker {
    /// Number of mining threads
    thread_count: usize,
    /// Thread handles
    threads: Vec<JoinHandle<()>>,
    /// Shared stop flag
    stop_flag: Arc<AtomicBool>,
    /// Current work being mined
    current_work: Arc<parking_lot::RwLock<Option<MiningWork>>>,
    /// Solution channel sender
    solution_tx: crossbeam_channel::Sender<MiningSolution>,
    /// Solution channel receiver
    solution_rx: crossbeam_channel::Receiver<MiningSolution>,
    /// Mining statistics
    stats: Arc<MiningStats>,
}

impl MiningWorker {
    /// Create a new mining worker with the specified number of threads
    pub fn new(thread_count: usize) -> Self {
        let (solution_tx, solution_rx) = crossbeam_channel::unbounded();
        
        Self {
            thread_count,
            threads: Vec::new(),
            stop_flag: Arc::new(AtomicBool::new(false)),
            current_work: Arc::new(parking_lot::RwLock::new(None)),
            solution_tx,
            solution_rx,
            stats: Arc::new(MiningStats::new()),
        }
    }

    /// Start mining threads
    pub fn start(&mut self) {
        self.stop_flag.store(false, Ordering::SeqCst);
        
        for thread_id in 0..self.thread_count {
            let stop_flag = Arc::clone(&self.stop_flag);
            let current_work = Arc::clone(&self.current_work);
            let solution_tx = self.solution_tx.clone();
            let stats = Arc::clone(&self.stats);
            
            let handle = thread::Builder::new()
                .name(format!("hegemon-miner-{}", thread_id))
                .spawn(move || {
                    mining_thread_loop(
                        thread_id,
                        stop_flag,
                        current_work,
                        solution_tx,
                        stats,
                    );
                })
                .expect("failed to spawn mining thread");
            
            self.threads.push(handle);
        }
        
        tracing::info!(
            "Started {} mining thread(s)",
            self.thread_count
        );
    }

    /// Stop all mining threads
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        
        // Wait for all threads to finish
        while let Some(handle) = self.threads.pop() {
            let _ = handle.join();
        }
        
        tracing::info!("Stopped mining threads");
    }

    /// Update the work being mined
    pub fn update_work(&self, work: MiningWork) {
        let mut current = self.current_work.write();
        *current = Some(work);
    }

    /// Clear current work (e.g., when a block is found by network)
    pub fn clear_work(&self) {
        let mut current = self.current_work.write();
        *current = None;
    }

    /// Try to receive a solution (non-blocking)
    pub fn try_recv_solution(&self) -> Option<MiningSolution> {
        self.solution_rx.try_recv().ok()
    }

    /// Receive a solution (blocking with timeout)
    pub fn recv_solution_timeout(&self, timeout: Duration) -> Option<MiningSolution> {
        self.solution_rx.recv_timeout(timeout).ok()
    }

    /// Get mining statistics
    pub fn stats(&self) -> &Arc<MiningStats> {
        &self.stats
    }

    /// Check if mining is active
    pub fn is_mining(&self) -> bool {
        !self.threads.is_empty() && !self.stop_flag.load(Ordering::SeqCst)
    }
}

impl Drop for MiningWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Main loop for a mining thread
fn mining_thread_loop(
    thread_id: usize,
    stop_flag: Arc<AtomicBool>,
    current_work: Arc<parking_lot::RwLock<Option<MiningWork>>>,
    solution_tx: crossbeam_channel::Sender<MiningSolution>,
    stats: Arc<MiningStats>,
) {
    const NONCES_PER_ROUND: u64 = 10_000;
    const ROUNDS_PER_THREAD: u32 = 100;
    
    let mut round_offset = 0u32;
    
    tracing::debug!(thread_id, "Mining thread starting");
    
    while !stop_flag.load(Ordering::Relaxed) {
        // Get current work
        let work = {
            let lock = current_work.read();
            lock.clone()
        };
        
        let Some(work) = work else {
            // No work available, sleep briefly
            if round_offset == 0 {
                tracing::debug!(thread_id, "Mining thread waiting for work");
            }
            thread::sleep(Duration::from_millis(100));
            continue;
        };
        
        if round_offset == 0 {
            tracing::info!(
                thread_id,
                pre_hash = %format!("{:?}", work.pre_hash),
                pow_bits = format!("{:08x}", work.pow_bits),
                height = work.height,
                "Mining thread got work, starting to mine"
            );
        }
        
        // Calculate round number for this thread
        // Distribute work: thread 0 does rounds 0, N, 2N, ...
        //                  thread 1 does rounds 1, N+1, 2N+1, ...
        let round = (round_offset * ROUNDS_PER_THREAD) + thread_id as u32;
        
        // Try to find a solution
        if let Some(seal) = mine_round(&work.pre_hash, work.pow_bits, round, NONCES_PER_ROUND) {
            // Found a solution!
            tracing::info!(
                thread_id,
                nonce = seal.nonce,
                round,
                "🎯 Mining thread found solution!"
            );
            
            let solution = MiningSolution {
                seal,
                work: work.clone(),
            };
            
            stats.add_block();
            
            if solution_tx.send(solution).is_err() {
                // Receiver dropped, stop mining
                break;
            }
        }
        
        // Update stats
        stats.add_hashes(NONCES_PER_ROUND);
        
        // Move to next round
        round_offset = round_offset.wrapping_add(1);
    }
}

/// Simple mining coordinator for the Substrate service
///
/// This provides a higher-level interface for the node service to control
/// mining without managing threads directly.
pub struct MiningCoordinator {
    worker: Option<MiningWorker>,
    thread_count: usize,
}

impl MiningCoordinator {
    /// Create a new mining coordinator
    pub fn new(thread_count: usize) -> Self {
        Self {
            worker: None,
            thread_count,
        }
    }

    /// Start mining
    pub fn start(&mut self) {
        if self.worker.is_some() {
            return; // Already running
        }
        
        let mut worker = MiningWorker::new(self.thread_count);
        worker.start();
        self.worker = Some(worker);
    }

    /// Stop mining
    pub fn stop(&mut self) {
        if let Some(mut worker) = self.worker.take() {
            worker.stop();
        }
    }

    /// Update work template
    pub fn update_work(&self, work: MiningWork) {
        if let Some(ref worker) = self.worker {
            worker.update_work(work);
        }
    }

    /// Clear current work
    pub fn clear_work(&self) {
        if let Some(ref worker) = self.worker {
            worker.clear_work();
        }
    }

    /// Try to get a solution
    pub fn try_recv_solution(&self) -> Option<MiningSolution> {
        self.worker.as_ref().and_then(|w| w.try_recv_solution())
    }

    /// Check if mining is active
    pub fn is_mining(&self) -> bool {
        self.worker.as_ref().map_or(false, |w| w.is_mining())
    }

    /// Get hashrate
    pub fn hashrate(&self) -> f64 {
        self.worker.as_ref().map_or(0.0, |w| w.stats().hashrate())
    }

    /// Get blocks found
    pub fn blocks_found(&self) -> u64 {
        self.worker.as_ref().map_or(0, |w| w.stats().blocks())
    }
}

impl Drop for MiningCoordinator {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mining_stats() {
        let stats = MiningStats::new();
        
        stats.add_hashes(1000);
        assert_eq!(stats.total(), 1000);
        
        stats.add_hashes(500);
        assert_eq!(stats.total(), 1500);
        
        stats.add_block();
        assert_eq!(stats.blocks(), 1);
    }

    #[test]
    fn test_mining_work_clone() {
        let work = MiningWork {
            pre_hash: H256::repeat_byte(0x42),
            pow_bits: 0x1d00ffff,
            height: 100,
            parent_hash: H256::repeat_byte(0x01),
        };
        
        let cloned = work.clone();
        assert_eq!(work.pre_hash, cloned.pre_hash);
        assert_eq!(work.pow_bits, cloned.pow_bits);
        assert_eq!(work.height, cloned.height);
    }

    #[test]
    fn test_mining_coordinator_lifecycle() {
        let mut coordinator = MiningCoordinator::new(1);
        
        assert!(!coordinator.is_mining());
        
        coordinator.start();
        assert!(coordinator.is_mining());
        
        coordinator.stop();
        assert!(!coordinator.is_mining());
    }

    #[test]
    fn test_mining_finds_solution_with_easy_difficulty() {
        let mut worker = MiningWorker::new(1);
        worker.start();
        
        // Very easy difficulty
        let work = MiningWork {
            pre_hash: H256::repeat_byte(0xab),
            pow_bits: 0x2100ffff, // Very easy
            height: 1,
            parent_hash: H256::zero(),
        };
        
        worker.update_work(work.clone());
        
        // Should find solution quickly
        let solution = worker.recv_solution_timeout(Duration::from_secs(10));
        worker.stop();
        
        assert!(solution.is_some(), "should find solution with easy difficulty");
        let solution = solution.unwrap();
        assert_eq!(solution.work.height, 1);
    }
}
