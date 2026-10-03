//! Exact Bitcoin 80-byte work templates for an external ASIC miner.
//!
//! A job retains the complete native work snapshot. The ASIC searches only
//! the four-byte header nonce and 28-byte coinbase extranonce; the node
//! reconstructs the consensus header and imports the same snapshot that its
//! own CPU miner uses.

use super::*;
use consensus_light_client::{
    bitcoin80_coinbase_prefix, bitcoin80_header, bitcoin80_work_hash, BITCOIN80_COINBASE_SUFFIX,
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

fn job_response(job_id: &str, job: &BitcoinAsicJob) -> Result<Value> {
    let work = &job.work;
    let header = bitcoin80_header(
        &work.pre_hash,
        &work.parent_hash,
        work.timestamp_ms,
        work.pow_bits,
        [0u8; 32],
    )
    .map_err(|err| anyhow!("ASIC work header construction failed: {err:?}"))?;
    let target = consensus_light_client::compact_to_target(work.pow_bits)
        .map_err(|err| anyhow!("ASIC work target invalid: {err:?}"))?;
    let ntime = u32::try_from(work.timestamp_ms / 1_000)
        .map_err(|_| anyhow!("ASIC work timestamp exceeds 32-bit nTime"))?;
    Ok(json!({
        "available": true,
        "algorithm": "sha256d-bitcoin80",
        "job_id": job_id,
        "height": work.height,
        "parent_hash": hex32(&work.parent_hash),
        "version": format!("{BITCOIN80_VERSION:08x}"),
        "ntime": format!("{ntime:08x}"),
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
                return job_response(&id, &job);
            }
        }

        let (work, pending_generation) = self.prepare_asic_work()?;
        if self.pending_action_generation.load(Ordering::Acquire) != pending_generation {
            return Err(anyhow!(
                "ASIC work pending-action state changed before issuance; retry"
            ));
        }
        {
            let state = self.state.read();
            if !asic_job_valid_for_tip(
                &BitcoinAsicJob {
                    work: work.clone(),
                    created_at: Instant::now(),
                    pending_generation,
                },
                &state,
            ) {
                return Err(anyhow!("ASIC work became stale during preparation"));
            }
        }
        let mut random_id = [0u8; 16];
        OsRng.fill_bytes(&mut random_id);
        let id = hex::encode(random_id);
        let job = BitcoinAsicJob {
            work,
            created_at: Instant::now(),
            pending_generation,
        };
        let response = job_response(&id, &job)?;
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
        let ntime = u32::try_from(job.work.timestamp_ms / 1_000)
            .map_err(|_| anyhow!("ASIC job timestamp exceeds 32-bit nTime"))?;
        if let Some(raw) = request.get("ntime") {
            if !raw.is_string() || parse_u32_field(&params, "ntime")? != ntime {
                return Err(anyhow!("ASIC solution ntime differs from job template"));
            }
        }
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
        }
        let work_hash = bitcoin80_work_hash(
            &job.work.pre_hash,
            &job.work.parent_hash,
            job.work.timestamp_ms,
            job.work.pow_bits,
            nonce,
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
        let imported = self.import_mined_block(&job.work, NativeSeal { nonce, work_hash })?;
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
