use std::sync::Arc;
use std::time::Instant;

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
) -> Vec<tokio::task::JoinHandle<()>> {
    let result_tx = Arc::new(result_tx);
    (0..workers)
        .map(|_| {
            let rx = template_rx.clone();
            let tx = result_tx.clone();
            let telemetry = telemetry.clone();
            tokio::spawn(async move {
                run_worker(rx, tx, telemetry).await;
            })
        })
        .collect()
}

async fn run_worker(
    mut rx: watch::Receiver<Option<BlockTemplate>>,
    tx: Arc<mpsc::Sender<ConsensusBlock>>,
    telemetry: Telemetry,
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

            let _start = Instant::now();
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
                            // Stop mining this template to avoid producing sibling blocks
                            let _ = rx.changed().await;
                            break;
                        }
                    }
                    Err(_) => break,
                }
                counter = counter.wrapping_add(1);
            }

            // No throttling — run as fast as possible while yielding to the runtime.
            tokio::task::yield_now().await;
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
