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
        let nullifiers = nullifiers.into_iter().collect::<Vec<_>>();
        let mut seen = BTreeSet::new();
        for nf in &nullifiers {
            if self.entries.contains(nf) || !seen.insert(*nf) {
                return Err(ConsensusError::DuplicateNullifier(*nf));
            }
        }
        self.entries.extend(nullifiers);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn patterned_nullifier(seed: u8) -> Nullifier {
        let mut out = [0u8; 48];
        for (idx, byte) in out.iter_mut().enumerate() {
            *byte = seed.wrapping_mul(37).wrapping_add(idx as u8);
        }
        out
    }

    fn sorted_commitment_oracle(entries: &[Nullifier]) -> [u8; 48] {
        let mut unique = entries.to_vec();
        unique.sort();
        unique.dedup();

        let mut preimage = Vec::with_capacity(unique.len() * 48);
        for entry in unique {
            preimage.extend_from_slice(&entry);
        }
        blake3_384(&preimage)
    }

    #[test]
    fn nullifier_set_matches_sorted_unique_commitment_oracle_and_rejects_duplicates() {
        let insertion_order = [9u8, 1, 7, 2, 12, 3, 10, 4, 11, 5, 8, 6];
        let mut set = NullifierSet::new();
        let mut oracle_entries = Vec::new();

        assert_eq!(set.commitment(), sorted_commitment_oracle(&oracle_entries));

        for seed in insertion_order {
            let nullifier = patterned_nullifier(seed);
            set.insert(nullifier).expect("fresh nullifier inserts");
            oracle_entries.push(nullifier);
            assert!(
                set.contains(&nullifier),
                "inserted nullifier seed {seed} must be present"
            );
            assert_eq!(
                set.commitment(),
                sorted_commitment_oracle(&oracle_entries),
                "commitment drift after inserting seed {seed}"
            );
        }

        let before_duplicate_commitment = set.commitment();
        let duplicate = patterned_nullifier(7);
        let err = set
            .insert(duplicate)
            .expect_err("duplicate nullifier must reject");
        assert!(matches!(err, ConsensusError::DuplicateNullifier(value) if value == duplicate));
        assert_eq!(
            set.commitment(),
            before_duplicate_commitment,
            "duplicate insert must not mutate the commitment"
        );

        let new_before_duplicate = patterned_nullifier(31);
        let before_extend_commitment = set.commitment();
        let err = set
            .extend([new_before_duplicate, duplicate])
            .expect_err("extend must reject the duplicate suffix");
        assert!(matches!(err, ConsensusError::DuplicateNullifier(value) if value == duplicate));
        assert!(
            !set.contains(&new_before_duplicate),
            "extend must reject atomically without inserting a fresh prefix before a duplicate suffix"
        );
        assert_eq!(
            set.commitment(),
            before_extend_commitment,
            "failed extend must not mutate the commitment"
        );
    }
}
