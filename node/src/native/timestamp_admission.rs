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
