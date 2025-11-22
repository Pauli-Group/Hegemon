use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::transaction::ValidatedTransaction;

use parking_lot::Mutex;

use crate::error::{NodeError, NodeResult};

#[derive(Clone, Debug)]
pub struct QueuedTransaction {
    pub transaction: ValidatedTransaction,
    pub weight: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct PoolKey {
    fee_per_weight: u128,
    timestamp_ms: u128,
    tx_id: [u8; 32],
}

impl PoolKey {
    fn new(tx: &QueuedTransaction) -> Self {
        let fee_per_weight = if tx.weight == 0 {
            0
        } else {
            (tx.transaction.fee as u128 * 1_000_000u128) / tx.weight as u128
        };
        let timestamp_ms = tx.transaction.timestamp.elapsed().as_millis();
        Self {
            fee_per_weight,
            timestamp_ms,
            tx_id: tx.transaction.id,
        }
    }
}

impl Ord for PoolKey {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .fee_per_weight
            .cmp(&self.fee_per_weight)
            .then_with(|| other.timestamp_ms.cmp(&self.timestamp_ms))
            .then_with(|| self.tx_id.cmp(&other.tx_id))
    }
}

impl PartialOrd for PoolKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
pub struct Mempool {
    inner: Mutex<MempoolState>,
    max_size: usize,
    max_weight: u64,
}

#[derive(Debug, Default)]
struct MempoolState {
    entries: BTreeMap<PoolKey, QueuedTransaction>,
    index: HashMap<[u8; 32], PoolKey>,
    nullifiers: BTreeSet<[u8; 32]>,
    total_weight: u64,
}

impl Mempool {
    pub fn new(max_size: usize, max_weight: u64) -> Self {
        Self {
            inner: Mutex::new(MempoolState::default()),
            max_size,
            max_weight,
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

    pub fn insert(&self, tx: ValidatedTransaction, weight: u64) -> NodeResult<()> {
        let mut guard = self.inner.lock();
        if guard.index.contains_key(&tx.id) {
            return Err(NodeError::Invalid("transaction already exists"));
        }
        if guard.entries.len() == self.max_size {
            return Err(NodeError::Invalid("mempool full"));
        }
        if guard.total_weight.saturating_add(weight) > self.max_weight {
            return Err(NodeError::Invalid("mempool weight limit"));
        }
        for nf in &tx.nullifiers {
            if guard.nullifiers.contains(nf) {
                return Err(NodeError::Invalid("duplicate nullifier"));
            }
        }
        let queued = QueuedTransaction {
            transaction: tx,
            weight,
        };
        let key = PoolKey::new(&queued);
        for nf in &queued.transaction.nullifiers {
            guard.nullifiers.insert(*nf);
        }
        guard.total_weight = guard.total_weight.saturating_add(weight);
        guard.index.insert(queued.transaction.id, key.clone());
        guard.entries.insert(key, queued);
        Ok(())
    }

    pub fn prune(&self, ids: &[[u8; 32]]) {
        let mut guard = self.inner.lock();
        for id in ids {
            if let Some(key) = guard.index.remove(id)
                && let Some(entry) = guard.entries.remove(&key)
            {
                guard.total_weight = guard.total_weight.saturating_sub(entry.weight);
                for nf in entry.transaction.nullifiers {
                    guard.nullifiers.remove(&nf);
                }
            }
        }
    }

    pub fn collect(&self, limit: usize, max_weight: u64) -> Vec<QueuedTransaction> {
        let guard = self.inner.lock();
        let mut used_weight = 0u64;
        guard
            .entries
            .values()
            .filter(|entry| {
                let next_weight = used_weight.saturating_add(entry.weight);
                if next_weight > max_weight {
                    return false;
                }
                used_weight = next_weight;
                true
            })
            .take(limit)
            .cloned()
            .collect()
    }
}
