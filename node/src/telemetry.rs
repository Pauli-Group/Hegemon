use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::Serialize;
use std::sync::Arc;

#[derive(Clone, Debug, Default, Serialize)]
pub struct TelemetryPosture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tor_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpn_overlay: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposure_scope: Option<String>,
}

#[derive(Debug)]
struct TelemetryInner {
    start: Instant,
    hashes: AtomicU64,
    stale_shares: AtomicU64,
    accepted_shares: AtomicU64,
    best_height: AtomicU64,
    mempool_depth: AtomicU64,
    difficulty: AtomicU64,
    posture: RwLock<TelemetryPosture>,
}

#[derive(Debug, Clone)]
pub struct Telemetry {
    inner: Arc<TelemetryInner>,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl Telemetry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(TelemetryInner {
                start: Instant::now(),
                hashes: AtomicU64::new(0),
                stale_shares: AtomicU64::new(0),
                accepted_shares: AtomicU64::new(0),
                best_height: AtomicU64::new(0),
                mempool_depth: AtomicU64::new(0),
                difficulty: AtomicU64::new(0),
                posture: RwLock::new(TelemetryPosture::default()),
            }),
        }
    }

    pub fn record_hashes(&self, count: u64) {
        self.inner.hashes.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_share(&self, accepted: bool) {
        if accepted {
            self.inner.accepted_shares.fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner.stale_shares.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn set_height(&self, height: u64) {
        self.inner.best_height.store(height, Ordering::Relaxed);
    }

    pub fn set_mempool_depth(&self, depth: usize) {
        self.inner.mempool_depth.store(depth as u64, Ordering::Relaxed);
    }

    pub fn set_difficulty(&self, bits: u32) {
        self.inner.difficulty.store(bits as u64, Ordering::Relaxed);
    }

    pub fn set_privacy_posture(&self, posture: TelemetryPosture) {
        *self.inner.posture.write() = posture;
    }

    pub fn snapshot(&self) -> TelemetrySnapshot {
        let elapsed = self.inner.start.elapsed();
        let hashes = self.inner.hashes.load(Ordering::Relaxed);
        let hash_rate = if elapsed > Duration::from_secs(0) {
            hashes as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let accepted = self.inner.accepted_shares.load(Ordering::Relaxed) as f64;
        let stale = self.inner.stale_shares.load(Ordering::Relaxed) as f64;
        let total_shares = accepted + stale;
        let stale_rate = if total_shares > 0.0 {
            stale / total_shares
        } else {
            0.0
        };
        let posture = self.inner.posture.read().clone();
        TelemetrySnapshot {
            hash_rate,
            total_hashes: hashes,
            best_height: self.inner.best_height.load(Ordering::Relaxed),
            mempool_depth: self.inner.mempool_depth.load(Ordering::Relaxed),
            difficulty_bits: self.inner.difficulty.load(Ordering::Relaxed) as u32,
            stale_share_rate: stale_rate,
            tls_enabled: posture.tls_enabled,
            mtls_enabled: posture.mtls_enabled,
            tor_enabled: posture.tor_enabled,
            vpn_overlay: posture.vpn_overlay,
            exposure_scope: posture.exposure_scope,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TelemetrySnapshot {
    pub hash_rate: f64,
    pub total_hashes: u64,
    pub best_height: u64,
    pub mempool_depth: u64,
    pub difficulty_bits: u32,
    pub stale_share_rate: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tor_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpn_overlay: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposure_scope: Option<String>,
}
