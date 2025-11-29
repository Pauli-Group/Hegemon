use alloc::vec::Vec;
use core::cmp::min;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

/// Deterministic RNG seeded via SHA-256 over a domain separated label.
#[derive(Clone)]
pub struct DeterministicRng {
    inner: ChaCha20Rng,
}

impl DeterministicRng {
    /// Create a deterministic RNG from arbitrary seed material.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"synthetic-drg");
        hasher.update(seed);
        let digest = hasher.finalize();
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(&digest);
        let inner = ChaCha20Rng::from_seed(seed_bytes);
        Self { inner }
    }

    /// Fill the provided buffer with pseudo-random bytes.
    pub fn fill_bytes(&mut self, buffer: &mut [u8]) {
        rand_core::RngCore::fill_bytes(&mut self.inner, buffer);
    }
}

/// Expand the provided input into a deterministic byte vector of the requested length.
pub fn expand_to_length(domain: &[u8], input: &[u8], length: usize) -> Vec<u8> {
    let mut counter = 0u32;
    let mut output = Vec::with_capacity(length);
    while output.len() < length {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(counter.to_be_bytes());
        hasher.update(input);
        let digest = hasher.finalize();
        let take = min(length - output.len(), digest.len());
        output.extend_from_slice(&digest[..take]);
        counter = counter.checked_add(1).expect("counter overflow");
    }
    output
}
