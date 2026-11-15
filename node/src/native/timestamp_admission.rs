//! Clock-dependent checks for fresh admission, separate from historical replay.

use super::*;

pub(crate) const NATIVE_TEMPORARY_FUTURE_WORK_REASON: &str =
    "timestamp is temporarily ahead of local clock";
pub(crate) const NATIVE_ASIC_FUTURE_SOLUTION_MESSAGE: &str =
    "ASIC solution temporarily future-dated; retry solution";

#[derive(Debug)]
pub(crate) struct NativeFutureTimestamp;

impl std::fmt::Display for NativeFutureTimestamp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "native block timestamp exceeds future skew bound (future_skew); retry when timely",
        )
    }
}

impl std::error::Error for NativeFutureTimestamp {}

pub(crate) fn validate_native_fresh_timestamp_at(timestamp_ms: u64, now_ms: u64) -> Result<()> {
    if timestamp_ms > native_announced_future_limit(now_ms, consensus::reward::MAX_FUTURE_SKEW_MS) {
        return Err(NativeFutureTimestamp.into());
    }
    Ok(())
}

pub(crate) fn native_next_work_timestamp_ms(parent_ms: u64, now_ms: u64) -> Result<u64> {
    let minimum = parent_ms
        .checked_add(1)
        .ok_or_else(|| anyhow!("native work timestamp cannot advance past u64::MAX"))?;
    let timestamp_ms = now_ms.max(minimum);
    validate_native_fresh_timestamp_at(timestamp_ms, now_ms)?;
    Ok(timestamp_ms)
}

/// A clock snapshot for an immutable job. The lower bound is determined by
/// canonical parent ordering; the upper bound moves with fresh admission time.
pub(crate) fn native_ntime_bounds(parent_ms: u64, now_ms: u64) -> Result<(u32, u32)> {
    let minimum = (parent_ms / 1_000)
        .checked_add(1)
        .and_then(|seconds| u32::try_from(seconds).ok())
        .ok_or_else(|| anyhow!("native nTime cannot advance beyond 32-bit seconds"))?;
    let maximum = u32::try_from(
        native_announced_future_limit(now_ms, consensus::reward::MAX_FUTURE_SKEW_MS) / 1_000,
    )
    .unwrap_or(u32::MAX);
    if minimum > maximum {
        return Err(NativeFutureTimestamp.into());
    }
    Ok((minimum, maximum))
}

pub(crate) fn native_next_work_timestamp_ms_at_height(
    chain_id: &[u8; 32],
    height: u64,
    parent_ms: u64,
    now_ms: u64,
) -> Result<u64> {
    if !consensus_light_client::native_time_rolling_active(chain_id, height) {
        return native_next_work_timestamp_ms(parent_ms, now_ms);
    }
    let (minimum, maximum) = native_ntime_bounds(parent_ms, now_ms)?;
    let seconds = u32::try_from(now_ms / 1_000)
        .unwrap_or(u32::MAX)
        .clamp(minimum, maximum);
    Ok(u64::from(seconds) * 1_000)
}

pub(crate) fn validate_native_rolling_timestamp(
    chain_id: &[u8; 32],
    height: u64,
    parent_ms: u64,
    timestamp_ms: u64,
) -> Result<()> {
    if consensus_light_client::native_time_rolling_active(chain_id, height) {
        if timestamp_ms % 1_000 != 0 || u32::try_from(timestamp_ms / 1_000).is_err() {
            return Err(anyhow!(
                "native rolling timestamp must be exact 32-bit nTime seconds"
            ));
        }
        if timestamp_ms <= parent_ms {
            return Err(anyhow!(
                "native rolling timestamp must be greater than its parent"
            ));
        }
    }
    Ok(())
}

pub(crate) fn native_admission_time_ms() -> u64 {
    #[cfg(test)]
    if let Some(now_ms) = TEST_ADMISSION_TIME_MS.with(std::cell::Cell::get) {
        return now_ms;
    }
    current_time_ms()
}

#[cfg(test)]
thread_local! {
    static TEST_ADMISSION_TIME_MS: std::cell::Cell<Option<u64>> = const {
        std::cell::Cell::new(None)
    };
}

/// Thread-scoped clock injection never changes another node test or production.
#[cfg(test)]
pub(crate) fn with_native_admission_time<T>(now_ms: u64, action: impl FnOnce() -> T) -> T {
    struct Restore(Option<u64>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_ADMISSION_TIME_MS.with(|time| time.set(self.0));
        }
    }
    let _restore = Restore(TEST_ADMISSION_TIME_MS.with(|time| time.replace(Some(now_ms))));
    action()
}
