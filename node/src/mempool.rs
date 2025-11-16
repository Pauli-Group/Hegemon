use std::collections::{BTreeMap, BTreeSet};

use parking_lot::Mutex;

use crate::error::{NodeError, NodeResult};
use crate::transaction::ValidatedTransaction;

#[derive(Debug)]
pub struct Mempool {
    inner: Mutex<MempoolState>,
    max_size: usize,
}

#[derive(Debug, Default)]
struct MempoolState {
    entries: BTreeMap<[u8; 32], ValidatedTransaction>,
    nullifiers: BTreeSet<[u8; 32]>,
}

impl Mempool {
    pub fn new(max_size: usize) -> Self {
        Self {
            inner: Mutex::new(MempoolState::default()),
            max_size,
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains_nullifier(&self, nf: &[u8; 32]) -> bool {
        self.inner.lock().nullifiers.contains(nf)
    }

    pub fn insert(&self, tx: ValidatedTransaction) -> NodeResult<()> {
        let mut guard = self.inner.lock();
        if guard.entries.contains_key(&tx.id) {
            return Err(NodeError::Invalid("transaction already exists"));
        }
        if guard.entries.len() == self.max_size {
            return Err(NodeError::Invalid("mempool full"));
        }
        for nf in &tx.nullifiers {
            if guard.nullifiers.contains(nf) {
                return Err(NodeError::Invalid("duplicate nullifier"));
            }
        }
        for nf in &tx.nullifiers {
            guard.nullifiers.insert(*nf);
        }
        guard.entries.insert(tx.id, tx);
        Ok(())
    }

    pub fn prune(&self, ids: &[[u8; 32]]) {
        let mut guard = self.inner.lock();
        for id in ids {
            if let Some(entry) = guard.entries.remove(id) {
                for nf in entry.nullifiers {
                    guard.nullifiers.remove(&nf);
                }
            }
        }
    }

    pub fn collect(&self, limit: usize) -> Vec<ValidatedTransaction> {
        let guard = self.inner.lock();
        guard.entries.values().take(limit).cloned().collect()
    }
}
