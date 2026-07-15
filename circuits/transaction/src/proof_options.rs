use protocol_versioning::VersionBinding;

/// Resource hints retained for API compatibility with transaction proof callers.
///
/// SmallWood selects its verifier profile from the version-bound arithmetization,
/// so these values cannot select or weaken the deployed proof backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionProofParams {
    pub log_blowup: usize,
    pub num_queries: usize,
}

impl TransactionProofParams {
    pub const fn production() -> Self {
        Self {
            log_blowup: 4,
            num_queries: 32,
        }
    }

    pub const fn production_for_version(_version: VersionBinding) -> Self {
        Self::production()
    }

    pub const fn release_for_version(_version: VersionBinding) -> Self {
        Self::production()
    }

    pub fn recursion() -> Self {
        Self {
            log_blowup: std::env::var("HEGEMON_TX_RECURSION_LOG_BLOWUP")
                .ok()
                .and_then(|raw| raw.parse::<usize>().ok())
                .unwrap_or(3)
                .max(1),
            num_queries: std::env::var("HEGEMON_TX_RECURSION_NUM_QUERIES")
                .ok()
                .and_then(|raw| raw.parse::<usize>().ok())
                .unwrap_or(8)
                .max(1),
        }
    }
}

impl Default for TransactionProofParams {
    fn default() -> Self {
        Self::production()
    }
}
