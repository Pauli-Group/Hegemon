//! Nullifier tracking for the shielded pool.
//!
//! The nullifier set prevents double-spending of notes.
//! When a note is spent, its nullifier is added to the set.
//! Any attempt to spend the same note again will fail because
//! the nullifier is already present.

use sp_std::vec::Vec;

/// Nullifier storage interface.
///
/// This trait abstracts the nullifier storage so the pallet
/// can be tested without full storage.
pub trait NullifierStore {
    /// Check if a nullifier exists in the set.
    fn contains(&self, nullifier: &[u8; 32]) -> bool;

    /// Insert a nullifier into the set.
    fn insert(&mut self, nullifier: [u8; 32]);

    /// Check if all nullifiers in a list are new (not in the set).
    fn all_new(&self, nullifiers: &[[u8; 32]]) -> bool {
        nullifiers.iter().all(|nf| !self.contains(nf))
    }

    /// Insert multiple nullifiers atomically.
    fn insert_batch(&mut self, nullifiers: &[[u8; 32]]) {
        for nf in nullifiers {
            self.insert(*nf);
        }
    }
}

/// In-memory nullifier store for testing.
#[derive(Clone, Debug, Default)]
pub struct MemoryNullifierStore {
    nullifiers: Vec<[u8; 32]>,
}

impl MemoryNullifierStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of nullifiers in the store.
    pub fn len(&self) -> usize {
        self.nullifiers.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.nullifiers.is_empty()
    }
}

impl NullifierStore for MemoryNullifierStore {
    fn contains(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.contains(nullifier)
    }

    fn insert(&mut self, nullifier: [u8; 32]) {
        if !self.contains(&nullifier) {
            self.nullifiers.push(nullifier);
        }
    }
}

/// Result of nullifier validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NullifierValidation {
    /// All nullifiers are new and valid.
    Valid,
    /// One or more nullifiers are already spent.
    AlreadySpent(Vec<[u8; 32]>),
    /// Duplicate nullifiers in the same transaction.
    DuplicateInTx(Vec<[u8; 32]>),
}

/// Validate a list of nullifiers.
///
/// Checks:
/// 1. No duplicates within the list
/// 2. None already exist in the store
pub fn validate_nullifiers<S: NullifierStore>(
    store: &S,
    nullifiers: &[[u8; 32]],
) -> NullifierValidation {
    // Check for duplicates within the list
    let mut seen = Vec::new();
    let mut duplicates = Vec::new();

    for nf in nullifiers {
        if seen.contains(nf) {
            duplicates.push(*nf);
        } else {
            seen.push(*nf);
        }
    }

    if !duplicates.is_empty() {
        return NullifierValidation::DuplicateInTx(duplicates);
    }

    // Check if any are already spent
    let already_spent: Vec<_> = nullifiers.iter().filter(|nf| store.contains(nf)).copied().collect();

    if !already_spent.is_empty() {
        return NullifierValidation::AlreadySpent(already_spent);
    }

    NullifierValidation::Valid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_insert_and_contains() {
        let mut store = MemoryNullifierStore::new();
        let nf = [1u8; 32];

        assert!(!store.contains(&nf));

        store.insert(nf);

        assert!(store.contains(&nf));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn memory_store_no_duplicates() {
        let mut store = MemoryNullifierStore::new();
        let nf = [1u8; 32];

        store.insert(nf);
        store.insert(nf);

        assert_eq!(store.len(), 1);
    }

    #[test]
    fn all_new_returns_true_for_new_nullifiers() {
        let store = MemoryNullifierStore::new();
        let nullifiers = [[1u8; 32], [2u8; 32], [3u8; 32]];

        assert!(store.all_new(&nullifiers));
    }

    #[test]
    fn all_new_returns_false_for_existing() {
        let mut store = MemoryNullifierStore::new();
        let nf1 = [1u8; 32];
        let nf2 = [2u8; 32];

        store.insert(nf1);

        assert!(!store.all_new(&[nf1, nf2]));
    }

    #[test]
    fn insert_batch_works() {
        let mut store = MemoryNullifierStore::new();
        let nullifiers = [[1u8; 32], [2u8; 32], [3u8; 32]];

        store.insert_batch(&nullifiers);

        assert_eq!(store.len(), 3);
        for nf in &nullifiers {
            assert!(store.contains(nf));
        }
    }

    #[test]
    fn validate_nullifiers_valid() {
        let store = MemoryNullifierStore::new();
        let nullifiers = [[1u8; 32], [2u8; 32]];

        assert_eq!(
            validate_nullifiers(&store, &nullifiers),
            NullifierValidation::Valid
        );
    }

    #[test]
    fn validate_nullifiers_already_spent() {
        let mut store = MemoryNullifierStore::new();
        let nf1 = [1u8; 32];
        let nf2 = [2u8; 32];

        store.insert(nf1);

        match validate_nullifiers(&store, &[nf1, nf2]) {
            NullifierValidation::AlreadySpent(spent) => {
                assert_eq!(spent.len(), 1);
                assert_eq!(spent[0], nf1);
            }
            _ => panic!("Expected AlreadySpent"),
        }
    }

    #[test]
    fn validate_nullifiers_duplicate_in_tx() {
        let store = MemoryNullifierStore::new();
        let nf = [1u8; 32];

        match validate_nullifiers(&store, &[nf, nf]) {
            NullifierValidation::DuplicateInTx(dups) => {
                assert_eq!(dups.len(), 1);
                assert_eq!(dups[0], nf);
            }
            _ => panic!("Expected DuplicateInTx"),
        }
    }
}
