use std::collections::BTreeSet;

use crate::error::ConsensusError;
use crate::types::Nullifier;
use crypto::hashes::blake3_384;

#[derive(Clone, Debug)]
pub struct NullifierSet {
    entries: BTreeSet<[u8; 48]>,
}

impl NullifierSet {
    pub fn new() -> Self {
        Self {
            entries: BTreeSet::new(),
        }
    }

    pub fn contains(&self, nf: &Nullifier) -> bool {
        self.entries.contains(nf)
    }

    pub fn insert(&mut self, nf: Nullifier) -> Result<(), ConsensusError> {
        if !self.entries.insert(nf) {
            return Err(ConsensusError::DuplicateNullifier(nf));
        }
        Ok(())
    }

    pub fn extend<I>(&mut self, nullifiers: I) -> Result<(), ConsensusError>
    where
        I: IntoIterator<Item = Nullifier>,
    {
        for nf in nullifiers {
            self.insert(nf)?;
        }
        Ok(())
    }

    pub fn commitment(&self) -> [u8; 48] {
        let mut data = Vec::with_capacity(self.entries.len() * 48);
        for nf in &self.entries {
            data.extend_from_slice(nf);
        }
        blake3_384(&data)
    }
}

impl Default for NullifierSet {
    fn default() -> Self {
        Self::new()
    }
}
