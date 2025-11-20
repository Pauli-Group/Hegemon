use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use consensus::types::ConsensusBlock;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use tokio::sync::{mpsc, watch};

use crate::telemetry::Telemetry;

#[derive(Clone, Debug)]
pub struct BlockTemplate {
    pub block: ConsensusBlock,
}

pub fn spawn_miners(
    workers: usize,
    template_rx: watch::Receiver<Option<BlockTemplate>>,
    result_tx: mpsc::Sender<ConsensusBlock>,
    telemetry: Telemetry,
    target_hash_rate: Arc<AtomicU64>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let result_tx = Arc::new(result_tx);
    (0..workers)
        .map(|_| {
            let rx = template_rx.clone();
            let tx = result_tx.clone();
            let telemetry = telemetry.clone();
            let target = target_hash_rate.clone();
            tokio::spawn(async move {
                run_worker(rx, tx, telemetry, target).await;
            })
        })
        .collect()
}

async fn run_worker(
    mut rx: watch::Receiver<Option<BlockTemplate>>,
    tx: Arc<mpsc::Sender<ConsensusBlock>>,
    telemetry: Telemetry,
    target_hash_rate: Arc<AtomicU64>,
) {
    const BATCH_SIZE: u64 = 128;
    loop {
        let template = loop {
            if let Some(tpl) = rx.borrow().clone() {
                break tpl;
            }
            if rx.changed().await.is_err() {
                return;
            }
        };
        let Some(pow) = template.block.header.pow.clone() else {
            if rx.changed().await.is_err() {
                return;
            }
            continue;
        };
        let target = compact_to_target(pow.pow_bits);
        if target.is_zero() {
            if rx.changed().await.is_err() {
                return;
            }
            continue;
        }
        let mut counter: u64 = 0;
        loop {
            if let Ok(true) = rx.has_changed() {
                let _ = rx.borrow_and_update();
                break;
            }
            
            let start = Instant::now();
            for _ in 0..BATCH_SIZE {
                let mut candidate = template.block.clone();
                if let Some(seal) = candidate.header.pow.as_mut() {
                    seal.nonce = counter_to_nonce(counter);
                }
                telemetry.record_hashes(1);
                match candidate.header.hash() {
                    Ok(hash) => {
                        let value = BigUint::from_bytes_be(&hash);
                        if value <= target {
                            telemetry.record_share(true);
                            if tx.send(candidate).await.is_err() {
                                return;
                            }
                            break;
                        }
                    }
                    Err(_) => break,
                }
                counter = counter.wrapping_add(1);
            }

            let elapsed = start.elapsed();
            let target_rate = target_hash_rate.load(Ordering::Relaxed);
            
            if target_rate > 0 {
                let expected_duration = Duration::from_secs_f64(BATCH_SIZE as f64 / target_rate as f64);
                if let Some(sleep_time) = expected_duration.checked_sub(elapsed) {
                    tokio::time::sleep(sleep_time).await;
                } else {
                    tokio::task::yield_now().await;
                }
            } else {
                tokio::task::yield_now().await;
            }
        }
    }
}

fn counter_to_nonce(counter: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&counter.to_le_bytes());
    out
}

fn compact_to_target(bits: u32) -> BigUint {
    let exponent = bits >> 24;
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 {
        return BigUint::zero();
    }
    let mut target = BigUint::from(mantissa);
    if exponent > 3 {
        target <<= 8 * (exponent - 3);
    } else {
        target >>= 8 * (3 - exponent);
    }
    if target.is_zero() {
        BigUint::one()
    } else {
        target
    }
}
