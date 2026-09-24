use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};
use core::{fmt, iter::FromIterator, mem};

/// An immutable, structurally shared set for fixed-width protocol keys.
///
/// The representation is a compressed, most-significant-bit-first Patricia
/// trie. Every key is stored in exactly one leaf and every internal node is a
/// real distinguishing bit, so a set with `n` keys has exactly `2n - 1` live
/// trie nodes. Cloning the set only clones its root `Arc`; insertion and removal
/// path-copy at most `KEY_BYTES * 8` internal nodes.
#[derive(Clone)]
pub struct PersistentKeySet<const KEY_BYTES: usize> {
    root: Option<Arc<PatriciaNode<KEY_BYTES>>>,
    len: usize,
}

enum PatriciaNode<const KEY_BYTES: usize> {
    Leaf([u8; KEY_BYTES]),
    Branch {
        bit: u16,
        zero: Arc<PatriciaNode<KEY_BYTES>>,
        one: Arc<PatriciaNode<KEY_BYTES>>,
    },
}

pub type PersistentKeySet48 = PersistentKeySet<48>;
pub type PersistentKeySet56 = PersistentKeySet<56>;

impl<const KEY_BYTES: usize> Default for PersistentKeySet<KEY_BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const KEY_BYTES: usize> PersistentKeySet<KEY_BYTES> {
    pub const KEY_BITS: usize = KEY_BYTES * 8;

    pub const fn new() -> Self {
        assert!(KEY_BYTES > 0);
        assert!(KEY_BYTES * 8 <= u16::MAX as usize);
        Self { root: None, len: 0 }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn contains(&self, key: &[u8; KEY_BYTES]) -> bool {
        let Some(mut node) = self.root.as_deref() else {
            return false;
        };
        loop {
            match node {
                PatriciaNode::Leaf(existing) => return existing == key,
                PatriciaNode::Branch { bit, zero, one } => {
                    node = if key_bit(key, usize::from(*bit)) {
                        one.as_ref()
                    } else {
                        zero.as_ref()
                    };
                }
            }
        }
    }

    /// Inserts `key`, returning whether it was absent.
    pub fn insert(&mut self, key: [u8; KEY_BYTES]) -> bool {
        self.insert_measured(key).0
    }

    /// Removes `key`, returning whether it was present.
    pub fn remove(&mut self, key: &[u8; KEY_BYTES]) -> bool {
        let Some(root) = self.root.as_ref() else {
            return false;
        };
        let (next, removed) = remove_node(root, key);
        if removed {
            self.root = next;
            self.len -= 1;
        }
        removed
    }

    pub fn iter(&self) -> PersistentKeySetIter<'_, KEY_BYTES> {
        PersistentKeySetIter::new(self.root.as_deref())
    }

    /// Number of live Patricia nodes reachable from this root.
    ///
    /// This is intended for diagnostics and performance regression tests. For
    /// every non-empty valid set it is exactly `2 * len - 1`.
    pub fn node_count(&self) -> usize {
        count_nodes(self.root.as_deref())
    }

    /// Conservative payload estimate for the live Arc-backed trie nodes.
    /// Allocator bookkeeping is intentionally excluded.
    pub fn estimated_live_node_bytes(&self) -> usize {
        self.node_count()
            .saturating_mul(mem::size_of::<PatriciaNode<KEY_BYTES>>() + 2 * mem::size_of::<usize>())
    }

    /// Returns true when both snapshots point at the identical immutable root.
    pub fn shares_root_with(&self, other: &Self) -> bool {
        match (&self.root, &other.root) {
            (None, None) => true,
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    fn insert_measured(&mut self, key: [u8; KEY_BYTES]) -> (bool, InsertWork) {
        let Some(root) = self.root.as_ref() else {
            self.root = Some(Arc::new(PatriciaNode::Leaf(key)));
            self.len = 1;
            return (
                true,
                InsertWork {
                    visited_nodes: 0,
                    allocated_nodes: 1,
                },
            );
        };

        let (existing, lookup_nodes) = terminal_key(root, &key);
        let Some(differing_bit) = first_differing_bit(existing, &key) else {
            return (
                false,
                InsertWork {
                    visited_nodes: lookup_nodes,
                    allocated_nodes: 0,
                },
            );
        };
        let (next, rebuilt_nodes) = insert_node(root, key, differing_bit);
        self.root = Some(next);
        self.len += 1;
        (
            true,
            InsertWork {
                visited_nodes: lookup_nodes + rebuilt_nodes,
                allocated_nodes: rebuilt_nodes + 2,
            },
        )
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct InsertWork {
    visited_nodes: usize,
    allocated_nodes: usize,
}

fn terminal_key<'a, const KEY_BYTES: usize>(
    root: &'a Arc<PatriciaNode<KEY_BYTES>>,
    key: &[u8; KEY_BYTES],
) -> (&'a [u8; KEY_BYTES], usize) {
    let mut node = root.as_ref();
    let mut visited = 0usize;
    loop {
        visited += 1;
        match node {
            PatriciaNode::Leaf(existing) => return (existing, visited),
            PatriciaNode::Branch { bit, zero, one } => {
                node = if key_bit(key, usize::from(*bit)) {
                    one.as_ref()
                } else {
                    zero.as_ref()
                };
            }
        }
    }
}

fn insert_node<const KEY_BYTES: usize>(
    node: &Arc<PatriciaNode<KEY_BYTES>>,
    key: [u8; KEY_BYTES],
    differing_bit: usize,
) -> (Arc<PatriciaNode<KEY_BYTES>>, usize) {
    match node.as_ref() {
        PatriciaNode::Branch { bit, zero, one } if usize::from(*bit) < differing_bit => {
            if key_bit(&key, usize::from(*bit)) {
                let (next, rebuilt) = insert_node(one, key, differing_bit);
                (
                    Arc::new(PatriciaNode::Branch {
                        bit: *bit,
                        zero: Arc::clone(zero),
                        one: next,
                    }),
                    rebuilt + 1,
                )
            } else {
                let (next, rebuilt) = insert_node(zero, key, differing_bit);
                (
                    Arc::new(PatriciaNode::Branch {
                        bit: *bit,
                        zero: next,
                        one: Arc::clone(one),
                    }),
                    rebuilt + 1,
                )
            }
        }
        _ => {
            let leaf = Arc::new(PatriciaNode::Leaf(key));
            let bit =
                u16::try_from(differing_bit).expect("validated Patricia bit index fits in u16");
            let branch = if key_bit(&key, differing_bit) {
                PatriciaNode::Branch {
                    bit,
                    zero: Arc::clone(node),
                    one: leaf,
                }
            } else {
                PatriciaNode::Branch {
                    bit,
                    zero: leaf,
                    one: Arc::clone(node),
                }
            };
            (Arc::new(branch), 0)
        }
    }
}

fn remove_node<const KEY_BYTES: usize>(
    node: &Arc<PatriciaNode<KEY_BYTES>>,
    key: &[u8; KEY_BYTES],
) -> (Option<Arc<PatriciaNode<KEY_BYTES>>>, bool) {
    match node.as_ref() {
        PatriciaNode::Leaf(existing) => {
            if existing == key {
                (None, true)
            } else {
                (Some(Arc::clone(node)), false)
            }
        }
        PatriciaNode::Branch { bit, zero, one } => {
            if key_bit(key, usize::from(*bit)) {
                let (next_one, removed) = remove_node(one, key);
                if !removed {
                    return (Some(Arc::clone(node)), false);
                }
                match next_one {
                    Some(next_one) => (
                        Some(Arc::new(PatriciaNode::Branch {
                            bit: *bit,
                            zero: Arc::clone(zero),
                            one: next_one,
                        })),
                        true,
                    ),
                    None => (Some(Arc::clone(zero)), true),
                }
            } else {
                let (next_zero, removed) = remove_node(zero, key);
                if !removed {
                    return (Some(Arc::clone(node)), false);
                }
                match next_zero {
                    Some(next_zero) => (
                        Some(Arc::new(PatriciaNode::Branch {
                            bit: *bit,
                            zero: next_zero,
                            one: Arc::clone(one),
                        })),
                        true,
                    ),
                    None => (Some(Arc::clone(one)), true),
                }
            }
        }
    }
}

fn first_differing_bit<const KEY_BYTES: usize>(
    left: &[u8; KEY_BYTES],
    right: &[u8; KEY_BYTES],
) -> Option<usize> {
    left.iter()
        .zip(right)
        .enumerate()
        .find_map(|(byte_index, (left, right))| {
            let difference = left ^ right;
            (difference != 0).then(|| byte_index * 8 + difference.leading_zeros() as usize)
        })
}

fn key_bit<const KEY_BYTES: usize>(key: &[u8; KEY_BYTES], bit: usize) -> bool {
    debug_assert!(bit < PersistentKeySet::<KEY_BYTES>::KEY_BITS);
    key[bit / 8] & (1 << (7 - bit % 8)) != 0
}

fn count_nodes<const KEY_BYTES: usize>(root: Option<&PatriciaNode<KEY_BYTES>>) -> usize {
    let Some(root) = root else {
        return 0;
    };
    let mut count = 0usize;
    let mut stack = Vec::from([root]);
    while let Some(node) = stack.pop() {
        count += 1;
        if let PatriciaNode::Branch { zero, one, .. } = node {
            stack.push(one.as_ref());
            stack.push(zero.as_ref());
        }
    }
    count
}

pub struct PersistentKeySetIter<'a, const KEY_BYTES: usize> {
    stack: Vec<&'a PatriciaNode<KEY_BYTES>>,
}

pub type PersistentKeySet48Iter<'a> = PersistentKeySetIter<'a, 48>;
pub type PersistentKeySet56Iter<'a> = PersistentKeySetIter<'a, 56>;

impl<'a, const KEY_BYTES: usize> PersistentKeySetIter<'a, KEY_BYTES> {
    fn new(root: Option<&'a PatriciaNode<KEY_BYTES>>) -> Self {
        let mut stack = Vec::new();
        if let Some(root) = root {
            stack.push(root);
        }
        Self { stack }
    }
}

impl<'a, const KEY_BYTES: usize> Iterator for PersistentKeySetIter<'a, KEY_BYTES> {
    type Item = &'a [u8; KEY_BYTES];

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.stack.pop() {
            match node {
                PatriciaNode::Leaf(key) => return Some(key),
                PatriciaNode::Branch { zero, one, .. } => {
                    self.stack.push(one.as_ref());
                    self.stack.push(zero.as_ref());
                }
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

impl<'a, const KEY_BYTES: usize> IntoIterator for &'a PersistentKeySet<KEY_BYTES> {
    type Item = &'a [u8; KEY_BYTES];
    type IntoIter = PersistentKeySetIter<'a, KEY_BYTES>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<const KEY_BYTES: usize> FromIterator<[u8; KEY_BYTES]> for PersistentKeySet<KEY_BYTES> {
    fn from_iter<T: IntoIterator<Item = [u8; KEY_BYTES]>>(iter: T) -> Self {
        let mut set = Self::new();
        set.extend(iter);
        set
    }
}

impl<const KEY_BYTES: usize> Extend<[u8; KEY_BYTES]> for PersistentKeySet<KEY_BYTES> {
    fn extend<T: IntoIterator<Item = [u8; KEY_BYTES]>>(&mut self, iter: T) {
        for key in iter {
            self.insert(key);
        }
    }
}

impl<const KEY_BYTES: usize, const N: usize> From<[[u8; KEY_BYTES]; N]>
    for PersistentKeySet<KEY_BYTES>
{
    fn from(keys: [[u8; KEY_BYTES]; N]) -> Self {
        keys.into_iter().collect()
    }
}

impl<const KEY_BYTES: usize> From<BTreeSet<[u8; KEY_BYTES]>> for PersistentKeySet<KEY_BYTES> {
    fn from(keys: BTreeSet<[u8; KEY_BYTES]>) -> Self {
        keys.into_iter().collect()
    }
}

impl<const KEY_BYTES: usize> From<&BTreeSet<[u8; KEY_BYTES]>> for PersistentKeySet<KEY_BYTES> {
    fn from(keys: &BTreeSet<[u8; KEY_BYTES]>) -> Self {
        keys.iter().copied().collect()
    }
}

impl<const KEY_BYTES: usize> From<PersistentKeySet<KEY_BYTES>> for BTreeSet<[u8; KEY_BYTES]> {
    fn from(keys: PersistentKeySet<KEY_BYTES>) -> Self {
        keys.iter().copied().collect()
    }
}

impl<const KEY_BYTES: usize> PartialEq for PersistentKeySet<KEY_BYTES> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.iter().eq(other.iter())
    }
}

impl<const KEY_BYTES: usize> Eq for PersistentKeySet<KEY_BYTES> {}

impl<const KEY_BYTES: usize> PartialEq<BTreeSet<[u8; KEY_BYTES]>> for PersistentKeySet<KEY_BYTES> {
    fn eq(&self, other: &BTreeSet<[u8; KEY_BYTES]>) -> bool {
        self.len == other.len() && self.iter().eq(other.iter())
    }
}

impl<const KEY_BYTES: usize> PartialEq<PersistentKeySet<KEY_BYTES>> for BTreeSet<[u8; KEY_BYTES]> {
    fn eq(&self, other: &PersistentKeySet<KEY_BYTES>) -> bool {
        other == self
    }
}

impl<const KEY_BYTES: usize> fmt::Debug for PersistentKeySet<KEY_BYTES> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_set().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn differential_membership_iteration_and_removal_match_btree_set() {
        let keys = deterministic_keys(4_096);
        let mut persistent = PersistentKeySet48::new();
        let mut oracle = BTreeSet::new();
        for (index, key) in keys.iter().copied().enumerate() {
            assert_eq!(persistent.insert(key), oracle.insert(key));
            if index % 127 == 0 {
                assert_eq!(
                    persistent.iter().copied().collect::<Vec<_>>(),
                    oracle.iter().copied().collect::<Vec<_>>()
                );
            }
        }
        assert_eq!(persistent, oracle);
        for key in keys.iter().step_by(3) {
            assert_eq!(persistent.remove(key), oracle.remove(key));
        }
        assert_eq!(persistent, oracle);
        validate_invariants(&persistent);
        for key in &keys {
            assert_eq!(persistent.contains(key), oracle.contains(key));
        }
    }

    #[test]
    fn clone_is_constant_work_and_subsequent_mutation_is_structurally_shared() {
        let keys = deterministic_keys(8_192);
        let mut original: PersistentKeySet48 = keys.iter().copied().collect();
        let root_references_before =
            Arc::strong_count(original.root.as_ref().expect("non-empty set has a root"));
        let snapshot = original.clone();
        assert!(original.shares_root_with(&snapshot));
        assert_eq!(
            Arc::strong_count(original.root.as_ref().expect("root remains present")),
            root_references_before + 1,
            "snapshot clone must allocate no trie nodes and clone exactly one root Arc"
        );
        assert_eq!(original.node_count(), 2 * original.len() - 1);
        let original_nodes = original.node_count();

        let distinct = [0xff; 48];
        assert!(!original.contains(&distinct));
        let (inserted, work) = original.insert_measured(distinct);
        assert!(inserted);
        assert!(!original.shares_root_with(&snapshot));
        assert!(!snapshot.contains(&distinct));
        assert!(original.contains(&distinct));
        assert_eq!(snapshot.node_count(), original_nodes);
        assert!(work.allocated_nodes <= PersistentKeySet48::KEY_BITS + 2);
        assert!(work.visited_nodes <= 2 * PersistentKeySet48::KEY_BITS + 1);

        let before_remove = original.clone();
        assert!(original.remove(&keys[0]));
        assert!(before_remove.contains(&keys[0]));
        assert!(!original.contains(&keys[0]));
        assert!(!original.shares_root_with(&before_remove));
        validate_invariants(&original);
        validate_invariants(&before_remove);
    }

    #[test]
    fn compressed_shape_is_linear_at_realistic_size() {
        let keys = deterministic_keys(65_536);
        let set: PersistentKeySet48 = keys.into_iter().collect();
        assert_eq!(set.len(), 65_536);
        assert_eq!(set.node_count(), 2 * set.len() - 1);
        assert_eq!(
            set.estimated_live_node_bytes(),
            set.node_count()
                .saturating_mul(mem::size_of::<PatriciaNode<48>>() + 2 * mem::size_of::<usize>())
        );
        assert!(
            set.estimated_live_node_bytes()
                <= set.len().saturating_mul(
                    2 * (mem::size_of::<PatriciaNode<48>>() + 2 * mem::size_of::<usize>())
                )
        );
        assert!(set.node_count() < set.len() * 3);
    }

    #[test]
    fn shared_prefix_keys_preserve_full_key_equality_and_branch_invariants() {
        let mut keys = Vec::new();
        for bit in 0..PersistentKeySet48::KEY_BITS {
            let mut key = [0u8; 48];
            key[bit / 8] = 1 << (7 - bit % 8);
            keys.push(key);
        }
        keys.push([0u8; 48]);
        let set: PersistentKeySet48 = keys.iter().rev().copied().collect();
        assert_eq!(set.len(), keys.len());
        for key in &keys {
            assert!(set.contains(key));
        }
        validate_invariants(&set);
    }

    #[test]
    fn insertion_order_does_not_change_membership_iteration_or_shape() {
        let keys = deterministic_keys(2_048);
        let forward: PersistentKeySet48 = keys.iter().copied().collect();
        let reverse: PersistentKeySet48 = keys.iter().rev().copied().collect();
        let interleaved: PersistentKeySet48 = keys
            .iter()
            .step_by(2)
            .chain(keys.iter().skip(1).step_by(2))
            .copied()
            .collect();
        assert_eq!(forward, reverse);
        assert_eq!(forward, interleaved);
        assert_eq!(forward.node_count(), reverse.node_count());
        validate_invariants(&forward);
        validate_invariants(&reverse);
        validate_invariants(&interleaved);
    }

    #[test]
    fn fifty_six_byte_keys_preserve_exactness_shape_and_sharing() {
        let keys = deterministic_keys_56(4_096);
        let forward: PersistentKeySet56 = keys.iter().copied().collect();
        let reverse: PersistentKeySet56 = keys.iter().rev().copied().collect();
        assert_eq!(forward, reverse);
        assert_eq!(forward.node_count(), 2 * forward.len() - 1);
        let mut changed = forward.clone();
        assert!(changed.shares_root_with(&forward));
        assert!(changed.remove(&keys[0]));
        assert!(!changed.shares_root_with(&forward));
        assert!(forward.contains(&keys[0]));
        assert!(!changed.contains(&keys[0]));
        validate_invariants(&forward);
        validate_invariants(&changed);
    }

    fn validate_invariants<const KEY_BYTES: usize>(set: &PersistentKeySet<KEY_BYTES>) {
        let Some(root) = set.root.as_deref() else {
            assert_eq!(set.len(), 0);
            return;
        };
        let mut leaves = 0usize;
        let mut stack = Vec::from([(root, None::<usize>, Vec::<(usize, bool)>::new())]);
        while let Some((node, parent_bit, path)) = stack.pop() {
            match node {
                PatriciaNode::Leaf(key) => {
                    leaves += 1;
                    for (bit, expected) in path {
                        assert_eq!(key_bit(key, bit), expected);
                    }
                }
                PatriciaNode::Branch { bit, zero, one } => {
                    let bit = usize::from(*bit);
                    assert!(bit < PersistentKeySet::<KEY_BYTES>::KEY_BITS);
                    assert!(parent_bit.map_or(true, |parent| parent < bit));
                    let mut zero_path = path.clone();
                    zero_path.push((bit, false));
                    let mut one_path = path;
                    one_path.push((bit, true));
                    stack.push((one.as_ref(), Some(bit), one_path));
                    stack.push((zero.as_ref(), Some(bit), zero_path));
                }
            }
        }
        assert_eq!(leaves, set.len());
        assert_eq!(set.node_count(), 2 * leaves - 1);
    }

    fn deterministic_keys(count: usize) -> Vec<[u8; 48]> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut keys = Vec::with_capacity(count);
        for index in 0..count {
            let mut key = [0u8; 48];
            for chunk in key.chunks_exact_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state = state.wrapping_add(index as u64 | 1);
                chunk.copy_from_slice(&state.to_le_bytes());
            }
            keys.push(key);
        }
        keys
    }

    fn deterministic_keys_56(count: usize) -> Vec<[u8; 56]> {
        let mut state = 0xd1b5_4a32_d192_ed03u64;
        let mut keys = Vec::with_capacity(count);
        for index in 0..count {
            let mut key = [0u8; 56];
            for chunk in key.chunks_exact_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state = state.wrapping_add(index as u64 | 1);
                chunk.copy_from_slice(&state.to_le_bytes());
            }
            keys.push(key);
        }
        keys
    }
}
