#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::collections::BTreeMap;
use codec::Encode;
use core::iter::IntoIterator;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

pub type CircuitVersion = u16;
pub type CryptoSuiteId = u16;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Encode,
)]
#[repr(u8)]
pub enum TxProofBackend {
    Plonky3Fri = 1,
    SmallwoodCandidate = 2,
}

impl TxProofBackend {
    pub const fn wire_id(self) -> u8 {
        self as u8
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Plonky3Fri => "plonky3_fri",
            Self::SmallwoodCandidate => "smallwood_candidate",
        }
    }
}

impl Default for TxProofBackend {
    fn default() -> Self {
        DEFAULT_TX_PROOF_BACKEND
    }
}

impl TryFrom<u8> for TxProofBackend {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Plonky3Fri),
            2 => Ok(Self::SmallwoodCandidate),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Encode)]
pub struct TxFriProfile {
    pub log_blowup: u8,
    pub num_queries: u8,
    pub query_pow_bits: u8,
}

impl TxFriProfile {
    pub const fn new(log_blowup: u8, num_queries: u8, query_pow_bits: u8) -> Self {
        Self {
            log_blowup,
            num_queries,
            query_pow_bits,
        }
    }

    pub const fn log_blowup_usize(self) -> usize {
        self.log_blowup as usize
    }

    pub const fn num_queries_usize(self) -> usize {
        self.num_queries as usize
    }

    pub const fn query_pow_bits_usize(self) -> usize {
        self.query_pow_bits as usize
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Encode,
)]
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

pub const SMALLWOOD_CANDIDATE_VERSION_BINDING: VersionBinding = VersionBinding {
    circuit: CIRCUIT_V2,
    crypto: CRYPTO_SUITE_BETA,
};
pub const LEGACY_PLONKY3_FRI_VERSION_BINDING: VersionBinding = VersionBinding {
    circuit: CIRCUIT_V2,
    crypto: CRYPTO_SUITE_GAMMA,
};
pub const DEFAULT_VERSION_BINDING: VersionBinding = SMALLWOOD_CANDIDATE_VERSION_BINDING;

pub const DEFAULT_TX_PROOF_BACKEND: TxProofBackend = TxProofBackend::SmallwoodCandidate;
pub const DEFAULT_TX_FRI_PROFILE: TxFriProfile = TxFriProfile::new(4, 32, 0);

pub const fn tx_proof_backend_for_version(version: VersionBinding) -> Option<TxProofBackend> {
    match (version.circuit, version.crypto) {
        (CIRCUIT_V2, CRYPTO_SUITE_BETA) => Some(TxProofBackend::SmallwoodCandidate),
        (CIRCUIT_V2, CRYPTO_SUITE_GAMMA) => Some(TxProofBackend::Plonky3Fri),
        _ => None,
    }
}

pub const fn tx_fri_profile_for_version(version: VersionBinding) -> Option<TxFriProfile> {
    match (version.circuit, version.crypto) {
        (CIRCUIT_V2, CRYPTO_SUITE_GAMMA) => Some(DEFAULT_TX_FRI_PROFILE),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_binding_uses_smallwood_candidate_backend() {
        assert_eq!(DEFAULT_VERSION_BINDING, SMALLWOOD_CANDIDATE_VERSION_BINDING);
        assert_eq!(DEFAULT_TX_PROOF_BACKEND, TxProofBackend::SmallwoodCandidate);
        assert_eq!(
            tx_proof_backend_for_version(DEFAULT_VERSION_BINDING),
            Some(TxProofBackend::SmallwoodCandidate)
        );
        assert_eq!(tx_fri_profile_for_version(DEFAULT_VERSION_BINDING), None);
    }

    #[test]
    fn legacy_plonky3_binding_still_maps_to_fri_profile() {
        assert_eq!(
            tx_proof_backend_for_version(LEGACY_PLONKY3_FRI_VERSION_BINDING),
            Some(TxProofBackend::Plonky3Fri)
        );
        assert_eq!(
            tx_fri_profile_for_version(LEGACY_PLONKY3_FRI_VERSION_BINDING),
            Some(DEFAULT_TX_FRI_PROFILE)
        );
    }
}
