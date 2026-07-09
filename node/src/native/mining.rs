//! Native PoW mining loop and round search.

use super::*;

pub(crate) async fn mining_loop(node: Arc<NativeNode>) {
    while node.mining.load(Ordering::SeqCst) {
        node.refresh_mining_sync_gate();
        if !node.mining_sync_gate_allows_work() {
            tokio::time::sleep(Duration::from_millis(250)).await;
            continue;
        }
        let work = match node.prepare_work() {
            Ok(work) => work,
            Err(err) => {
                warn!(error = %err, "failed to prepare native mining work");
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
        };
        let start_round = node
            .mining_round
            .fetch_add(MINING_ROUNDS_PER_WORK, Ordering::Relaxed);
        let work_for_task = work.clone();

        let mined = tokio::task::spawn_blocking(move || {
            mine_native_rounds(work_for_task, start_round, MINING_ROUNDS_PER_WORK)
        })
        .await;

        match mined {
            Ok(result) => {
                node.mining_hashes
                    .fetch_add(result.hashes, Ordering::Relaxed);
                let Some(seal) = result.seal else {
                    continue;
                };
                if let Err(err) = node.import_mined_block(&work, seal) {
                    warn!(error = %err, "failed to import native mined block");
                }
            }
            Err(err) => {
                warn!(error = %err, "native mining task failed");
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn mine_native_round(work: NativeWork, round: u64) -> Option<NativeSeal> {
    mine_native_rounds(work, round, 1).seal
}

pub(crate) fn mine_native_rounds(
    work: NativeWork,
    start_round: u64,
    rounds: u64,
) -> NativeMiningRoundResult {
    let rounds = rounds.max(1);
    let mut hashes = 0u64;
    for offset in 0..rounds {
        let round = start_round.saturating_add(offset);
        if let Some(seal) = mine_native_round_inner(&work, round, &mut hashes) {
            return NativeMiningRoundResult {
                seal: Some(seal),
                hashes,
            };
        }
    }
    NativeMiningRoundResult { seal: None, hashes }
}

pub(crate) fn mine_native_round_inner(
    work: &NativeWork,
    round: u64,
    hashes: &mut u64,
) -> Option<NativeSeal> {
    let start = round.saturating_mul(HASHES_PER_ROUND);
    let end = start.saturating_add(HASHES_PER_ROUND);
    for counter in start..end {
        let nonce = nonce_from_counter(counter);
        let work_hash = native_pow_work_hash(&work.pre_hash, nonce);
        *hashes = (*hashes).saturating_add(1);
        if native_seal_meets_target(&work_hash, work.pow_bits) {
            debug!(height = work.height, counter, "native PoW seal found");
            return Some(NativeSeal { nonce, work_hash });
        }
    }
    None
}
