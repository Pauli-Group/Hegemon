use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::collections::BTreeMap;

pub type CircuitVersion = u16;
pub type CryptoSuiteId = u16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VersionBinding {
    pub circuit: CircuitVersion,
    pub crypto: CryptoSuiteId,
}

impl VersionBinding {
    pub const fn new(circuit: CircuitVersion, crypto: CryptoSuiteId) -> Self {
        Self { circuit, crypto }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionMatrix {
    counts: BTreeMap<VersionBinding, u32>,
}

impl VersionMatrix {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, binding: VersionBinding) {
        self.observe_n(binding, 1);
    }

    pub fn extend<I>(&mut self, bindings: I)
    where
        I: IntoIterator<Item = VersionBinding>,
    {
        for binding in bindings {
            self.observe(binding);
        }
    }

    pub fn observe_n(&mut self, binding: VersionBinding, count: u32) {
        if count == 0 {
            return;
        }
        *self.counts.entry(binding).or_default() += count;
    }

    pub fn from_counts<I>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (VersionBinding, u32)>,
    {
        let mut matrix = VersionMatrix::new();
        for (binding, count) in pairs {
            matrix.observe_n(binding, count);
        }
        matrix
    }

    pub fn counts(&self) -> &BTreeMap<VersionBinding, u32> {
        &self.counts
    }

    pub fn commitment(&self) -> [u8; 48] {
        compute_version_commitment(
            self.counts
                .iter()
                .map(|(binding, count)| (*binding, *count)),
        )
    }
}

pub fn compute_version_commitment<I>(pairs: I) -> [u8; 48]
where
    I: IntoIterator<Item = (VersionBinding, u32)>,
{
    let mut hasher = Sha384::new();
    for (binding, count) in pairs.into_iter() {
        hasher.update(binding.circuit.to_le_bytes());
        hasher.update(binding.crypto.to_le_bytes());
        hasher.update(count.to_le_bytes());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 48];
    out.copy_from_slice(&digest);
    out
}

pub const CIRCUIT_V1: CircuitVersion = 1;
pub const CIRCUIT_V2: CircuitVersion = 2;

pub const CRYPTO_SUITE_ALPHA: CryptoSuiteId = 1;
pub const CRYPTO_SUITE_BETA: CryptoSuiteId = 2;
pub const CRYPTO_SUITE_GAMMA: CryptoSuiteId = 3;

pub const DEFAULT_VERSION_BINDING: VersionBinding = VersionBinding {
    circuit: CIRCUIT_V2,
    crypto: CRYPTO_SUITE_GAMMA,
};
