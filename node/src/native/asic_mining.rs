//! Exact Bitcoin 80-byte work templates for an external ASIC miner.
//!
//! A job retains the complete native work snapshot. The ASIC searches only
//! the four-byte header nonce and 28-byte coinbase extranonce; the node
//! reconstructs the consensus header and imports the same snapshot that its
//! own CPU miner uses.

use super::*;
use consensus_light_client::{
    bitcoin80_coinbase_prefix, bitcoin80_header_with_version, bitcoin80_work_hash_with_version,
    BITCOIN80_COINBASE_SUFFIX,
};

const BITCOIN_ASIC_JOB_TTL: Duration = Duration::from_secs(120);
const MAX_BITCOIN_ASIC_JOBS: usize = 64;
const BITCOIN80_VERSION: u32 = 0x2000_0000;

impl BitcoinAsicJobCache {
    fn prune(&mut self) {
        self.jobs
            .retain(|_, job| job.created_at.elapsed() < BITCOIN_ASIC_JOB_TTL);
        self.order.retain(|id| self.jobs.contains_key(id));
    }

    pub(crate) fn insert(&mut self, id: String, job: BitcoinAsicJob) {
        self.prune();
        while self.jobs.len() >= MAX_BITCOIN_ASIC_JOBS {
            if let Some(oldest) = self.order.pop_front() {
                self.jobs.remove(&oldest);
            } else {
                break;
            }
        }
        self.order.push_back(id.clone());
        self.jobs.insert(id, job);
    }
}

fn asic_job_valid_for_tip(job: &BitcoinAsicJob, state: &NativeState) -> bool {
    job.work.parent_hash == state.best.hash
        && state.best.height.checked_add(1) == Some(job.work.height)
        && job
            .work
            .prepared_actions
            .as_ref()
            .is_some_and(|actions| prepared_mining_actions_match_state(state, actions))
}

fn parse_hex_field<const N: usize>(request: &Value, name: &str) -> Result<[u8; N]> {
    let raw = request
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing ASIC {name}"))?;
    if raw.len() != N * 2
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(anyhow!(
            "ASIC {name} must be exactly {} lowercase hexadecimal characters",
            N * 2
        ));
    }
    let bytes = hex::decode(raw).map_err(|_| anyhow!("invalid ASIC {name}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("invalid ASIC {name} length"))
}

fn parse_u32_field(request: &Value, name: &str) -> Result<u32> {
    Ok(u32::from_be_bytes(parse_hex_field::<4>(request, name)?))
}

fn job_response(
    job_id: &str,
    job: &BitcoinAsicJob,
    parent_timestamp_ms: u64,
    now_ms: u64,
) -> Result<Value> {
    let work = &job.work;
    let time_rolling =
        consensus_light_client::native_time_rolling_active(&job.chain_id, work.height);
    let ntime = u32::try_from(work.timestamp_ms / 1_000)
        .map_err(|_| anyhow!("ASIC work timestamp exceeds 32-bit nTime"))?;
    let (minimum, maximum) = if time_rolling {
        native_ntime_bounds(parent_timestamp_ms, now_ms)?
    } else {
        validate_native_fresh_timestamp_at(work.timestamp_ms, now_ms)?;
        (ntime, ntime)
    };
    let header = bitcoin80_header_with_version(
        &work.pre_hash,
        &work.parent_hash,
        work.timestamp_ms,
        work.pow_bits,
        [0u8; 32],
        work.mining_version,
    )
    .map_err(|err| anyhow!("ASIC work header construction failed: {err:?}"))?;
    let target = consensus_light_client::compact_to_target(work.pow_bits)
        .map_err(|err| anyhow!("ASIC work target invalid: {err:?}"))?;
    Ok(json!({
        "available": true,
        "algorithm": "sha256d-bitcoin80",
        "job_id": job_id,
        "height": work.height,
        "parent_hash": hex32(&work.parent_hash),
        "version": format!("{:08x}", work.mining_version),
        "version_rolling_mask": format!("{:08x}", if native_mining_version_rolling_active(
            &job.chain_id, work.height
        ) { consensus_light_client::BITCOIN80_VERSION_ROLLING_MASK } else { 0 }),
        "ntime": format!("{ntime:08x}"),
        "ntime_rolling": time_rolling,
        "ntime_activation_height": consensus_light_client::native_time_rolling_activation_height(&job.chain_id),
        "min_ntime": format!("{minimum:08x}"),
        "max_ntime": format!("{maximum:08x}"),
        "server_time": format!("{:08x}", u32::try_from(now_ms / 1_000).unwrap_or(u32::MAX)),
        "max_future_skew_seconds": consensus::reward::MAX_FUTURE_SKEW_MS / 1_000,
        "nbits": format!("{:08x}", work.pow_bits),
        "target": hex32(&target),
        "pre_hash": hex32(&work.pre_hash),
        "coinbase_prefix": hex::encode(bitcoin80_coinbase_prefix(&work.pre_hash)),
        "coinbase_suffix": hex::encode(BITCOIN80_COINBASE_SUFFIX),
        "extranonce_bytes": 28,
        "header80": hex::encode(header),
        "expires_in": BITCOIN_ASIC_JOB_TTL.saturating_sub(job.created_at.elapsed()).as_secs().max(1),
    }))
}

impl NativeNode {
    pub(crate) fn bitcoin_asic_work(&self) -> Result<Value> {
        self.ensure_native_storage_healthy()?;
        self.refresh_mining_sync_gate();
        if !self.mining_sync_gate_allows_work() {
            return Ok(json!({"available": false, "reason": "mining sync gate is closed"}));
        }

        // Polling does not replace a job merely because the CPU miner refreshed
        // its own one-second template. A changed pending-action epoch produces
        // a new job, while previously issued snapshots remain submit-able.
        let pending_generation = self.pending_action_generation.load(Ordering::Acquire);
        let prior = {
            let mut cache = self.bitcoin_asic_jobs.lock();
            cache.prune();
            cache
                .order
                .back()
                .and_then(|id| cache.jobs.get(id).cloned().map(|job| (id.clone(), job)))
        };
        if let Some((id, job)) = prior {
            let state = self.state.read();
            if job.pending_generation == pending_generation && asic_job_valid_for_tip(&job, &state)
            {
                match job_response(
                    &id,
                    &job,
                    state.best.timestamp_ms,
                    native_admission_time_ms(),
                ) {
                    Ok(response) => return Ok(response),
                    Err(error) if error.downcast_ref::<NativeFutureTimestamp>().is_some() => {}
                    Err(error) => return Err(error),
                }
            }
        }

        let (work, pending_generation) = match self.prepare_asic_work() {
            Ok(prepared) => prepared,
            Err(error) if error.downcast_ref::<NativeFutureTimestamp>().is_some() => {
                // Retain original jobs and expiries during a clock rollback.
                // No future-dated job is newly issued; the adapter may retain
                // an already found same-parent solution until it is timely.
                let retained_jobs = {
                    let mut cache = self.bitcoin_asic_jobs.lock();
                    cache.prune();
                    cache
                        .jobs
                        .iter()
                        .map(|(id, job)| (id.clone(), job.clone()))
                        .collect::<Vec<_>>()
                };
                let state = self.state.read();
                let retained_job_ids = retained_jobs
                    .into_iter()
                    .filter(|(_, job)| {
                        job.chain_id == self.config.chain_id()
                            && asic_job_valid_for_tip(job, &state)
                    })
                    .map(|(id, _)| id)
                    .collect::<Vec<_>>();
                return Ok(json!({
                    "available": false,
                    "reason": NATIVE_TEMPORARY_FUTURE_WORK_REASON,
                    "reason_code": "future_timestamp",
                    "parent_hash": hex32(&state.best.hash),
                    "retained_job_ids": retained_job_ids,
                }));
            }
            Err(error) => return Err(error),
        };
        if self.pending_action_generation.load(Ordering::Acquire) != pending_generation {
            return Err(anyhow!(
                "ASIC work pending-action state changed before issuance; retry"
            ));
        }
        let parent_timestamp_ms = {
            let state = self.state.read();
            if !asic_job_valid_for_tip(
                &BitcoinAsicJob {
                    chain_id: self.config.chain_id(),
                    work: work.clone(),
                    created_at: Instant::now(),
                    pending_generation,
                },
                &state,
            ) {
                return Err(anyhow!("ASIC work became stale during preparation"));
            }
            state.best.timestamp_ms
        };
        let mut random_id = [0u8; 16];
        OsRng.fill_bytes(&mut random_id);
        let id = hex::encode(random_id);
        let job = BitcoinAsicJob {
            chain_id: self.config.chain_id(),
            work,
            created_at: Instant::now(),
            pending_generation,
        };
        let response = job_response(&id, &job, parent_timestamp_ms, native_admission_time_ms())?;
        self.bitcoin_asic_jobs.lock().insert(id, job);
        Ok(response)
    }

    pub(crate) fn bitcoin_asic_submit(&self, params: Value) -> Result<Value> {
        self.ensure_native_storage_healthy()?;
        self.refresh_mining_sync_gate();
        if !self.mining_sync_gate_allows_work() {
            return Err(anyhow!(
                "ASIC solution rejected: mining sync gate is closed"
            ));
        }
        let request = params
            .as_object()
            .ok_or_else(|| anyhow!("ASIC solution must be an object"))?;
        let id = request
            .get("job_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing ASIC job_id"))?;
        if id.len() != 32
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(anyhow!(
                "ASIC job_id must be 32 lowercase hexadecimal characters"
            ));
        }
        let nonce_number = parse_u32_field(&params, "nonce")?;
        let extranonce = parse_hex_field::<28>(&params, "extranonce")?;
        let job = {
            let mut cache = self.bitcoin_asic_jobs.lock();
            cache.prune();
            cache.jobs.get(id).cloned()
        }
        .ok_or_else(|| anyhow!("unknown or expired ASIC job"))?;
        let job_ntime = u32::try_from(job.work.timestamp_ms / 1_000)
            .map_err(|_| anyhow!("ASIC job timestamp exceeds 32-bit nTime"))?;
        let ntime = if request.contains_key("ntime") {
            parse_u32_field(&params, "ntime")?
        } else {
            job_ntime
        };
        let time_rolling =
            consensus_light_client::native_time_rolling_active(&job.chain_id, job.work.height);
        if !time_rolling && ntime != job_ntime {
            return Err(anyhow!("ASIC solution ntime differs from job template"));
        }
        let timestamp_ms = if time_rolling {
            u64::from(ntime) * 1_000
        } else {
            job.work.timestamp_ms
        };
        let mut nonce = [0u8; 32];
        nonce[..4].copy_from_slice(&nonce_number.to_le_bytes());
        nonce[4..].copy_from_slice(&extranonce);

        {
            let state = self.state.read();
            if !asic_job_valid_for_tip(&job, &state) {
                return Err(anyhow!(
                    "stale ASIC job: canonical tip or prepared actions changed"
                ));
            }
            validate_native_rolling_timestamp(
                &job.chain_id,
                job.work.height,
                state.best.timestamp_ms,
                timestamp_ms,
            )?;
            // Evaluate the submitted time against a new node-clock snapshot,
            // never against the job's suggestion or issuance-time horizon.
            validate_native_fresh_timestamp_at(timestamp_ms, native_admission_time_ms())
                .map_err(|_| anyhow!(NATIVE_ASIC_FUTURE_SOLUTION_MESSAGE))?;
        }
        let mining_version = if request.contains_key("mining_version") {
            parse_u32_field(&params, "mining_version")?
        } else {
            BITCOIN80_VERSION
        };
        consensus_light_client::bitcoin80_validate_mining_version(
            mining_version,
            native_mining_version_rolling_active(&job.chain_id, job.work.height),
        )
        .map_err(|err| anyhow!("ASIC mining version invalid: {err:?}"))?;
        let work_hash = bitcoin80_work_hash_with_version(
            &job.work.pre_hash,
            &job.work.parent_hash,
            timestamp_ms,
            job.work.pow_bits,
            nonce,
            mining_version,
        )
        .map_err(|err| anyhow!("ASIC solution header invalid: {err:?}"))?;
        if !native_seal_meets_target(&work_hash, job.work.pow_bits) {
            return Err(anyhow!("ASIC solution does not meet network target"));
        }
        // Both CPU and ASIC solutions enter the same complete proof, action,
        // PoW, and persistence path. The semaphore bounds concurrent imports.
        let _permit = self
            .block_import_semaphore
            .try_acquire()
            .map_err(|_| anyhow!("ASIC block import busy; retry solution"))?;
        let mut submitted_work = job.work.clone();
        submitted_work.mining_version = mining_version;
        submitted_work.timestamp_ms = timestamp_ms;
        let imported = self
            .import_mined_block(&submitted_work, NativeSeal { nonce, work_hash })
            .map_err(|error| {
                if error.downcast_ref::<NativeFutureTimestamp>().is_some() {
                    anyhow!(NATIVE_ASIC_FUTURE_SOLUTION_MESSAGE)
                } else {
                    error
                }
            })?;
        let Some(meta) = imported else {
            return Err(anyhow!("ASIC solution became stale during block import"));
        };
        self.bitcoin_asic_jobs.lock().prune();
        Ok(json!({
            "accepted": true,
            "block_candidate": true,
            "network_target_met": true,
            "height": meta.height,
            "block_hash": hex32(&meta.hash),
            "accepted_shares": 1u64,
            "rejected_shares": 0u64,
        }))
    }

    pub(crate) fn bitcoin_asic_status(&self) -> Value {
        let mut cache = self.bitcoin_asic_jobs.lock();
        cache.prune();
        json!({
            "available": self.mining_sync_gate_allows_work() && !self.native_storage_poisoned.load(Ordering::SeqCst),
            "algorithm": "sha256d-bitcoin80",
            "active_jobs": cache.jobs.len(),
            "job_ttl_seconds": BITCOIN_ASIC_JOB_TTL.as_secs(),
            "max_jobs": MAX_BITCOIN_ASIC_JOBS,
            "network_difficulty": self.best_pow_bits(),
        })
    }
}
