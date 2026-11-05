//! Persistent, compressed binary trie of 384-bit account identifiers. Cloning
//! a candidate shares all untouched nodes. Each update hashes at most 384
//! branches and caches the exact aggregate value; block validation need not
//! scan every historical account. Snapshot encoding remains sorted and flat.
use crate::{hash48, AccountPolicyId48, RewardAccount, RewardAccountsError as Error};
use codec::{Compact, Decode, Encode, Input, Output};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    Leaf {
        key: AccountPolicyId48,
        account: RewardAccount,
        hash: [u8; 48],
        total: u64,
    },
    Branch {
        bit: u16,
        first: AccountPolicyId48,
        left: Arc<Node>,
        right: Arc<Node>,
        hash: [u8; 48],
        total: u64,
    },
}
impl Node {
    fn first(&self) -> AccountPolicyId48 {
        match self {
            Self::Leaf { key, .. } => *key,
            Self::Branch { first, .. } => *first,
        }
    }
    fn hash(&self) -> [u8; 48] {
        match self {
            Self::Leaf { hash, .. } | Self::Branch { hash, .. } => *hash,
        }
    }
    fn total(&self) -> u64 {
        match self {
            Self::Leaf { total, .. } | Self::Branch { total, .. } => *total,
        }
    }
    fn branch(bit: u16, left: Arc<Node>, right: Arc<Node>) -> Result<Arc<Self>, Error> {
        let total = left
            .total()
            .checked_add(right.total())
            .ok_or(Error::Overflow)?;
        let hash = hash48(
            b"hegemon.reward-accounts.trie-branch.v1",
            &(bit, left.hash(), right.hash()).encode(),
        );
        Ok(Arc::new(Self::Branch {
            bit,
            first: left.first(),
            left,
            right,
            hash,
            total,
        }))
    }
}
fn side(key: AccountPolicyId48, bit: u16) -> bool {
    key.as_bytes()[bit as usize / 8] & (0x80 >> (bit % 8)) != 0
}
fn difference(a: AccountPolicyId48, b: AccountPolicyId48) -> Option<u16> {
    a.as_bytes()
        .iter()
        .zip(b.as_bytes())
        .enumerate()
        .find_map(|(i, (a, b))| {
            let d = a ^ b;
            (d != 0).then(|| i as u16 * 8 + d.leading_zeros() as u16)
        })
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AccountTree {
    root: Option<Arc<Node>>,
    len: u64,
}
impl AccountTree {
    pub fn root_hash(&self) -> [u8; 48] {
        self.root.as_ref().map_or_else(
            || hash48(b"hegemon.reward-accounts.trie-empty.v1", &[]),
            |n| n.hash(),
        )
    }
    pub fn total(&self) -> u64 {
        self.root.as_ref().map_or(0, |n| n.total())
    }
    pub fn get(&self, key: &AccountPolicyId48) -> Option<&RewardAccount> {
        let mut node = self.root.as_deref()?;
        loop {
            match node {
                Node::Leaf {
                    key: k, account, ..
                } => return (k == key).then_some(account),
                Node::Branch {
                    bit, left, right, ..
                } => node = if side(*key, *bit) { right } else { left },
            }
        }
    }
    pub fn contains_key(&self, key: &AccountPolicyId48) -> bool {
        self.get(key).is_some()
    }
    pub fn insert(&mut self, key: AccountPolicyId48, account: RewardAccount) -> Result<(), Error> {
        if key == AccountPolicyId48::ZERO {
            return Err(Error::InvalidState);
        }
        let new_leaf = Arc::new(Node::Leaf {
            key,
            hash: hash48(
                b"hegemon.reward-accounts.trie-leaf.v1",
                &(key, &account).encode(),
            ),
            total: account.total()?,
            account,
        });
        let existed = self.contains_key(&key);
        fn put(old: &Arc<Node>, new: &Arc<Node>) -> Result<Arc<Node>, Error> {
            let differing = difference(old.first(), new.first());
            if let Some(bit) = differing {
                if matches!(old.as_ref(), Node::Leaf { .. })
                    || matches!(old.as_ref(),Node::Branch{bit:old_bit,..} if bit<*old_bit)
                {
                    return if side(new.first(), bit) {
                        Node::branch(bit, old.clone(), new.clone())
                    } else {
                        Node::branch(bit, new.clone(), old.clone())
                    };
                }
            }
            match old.as_ref() {
                Node::Leaf { .. } => Ok(new.clone()),
                Node::Branch {
                    bit, left, right, ..
                } => {
                    if side(new.first(), *bit) {
                        Node::branch(*bit, left.clone(), put(right, new)?)
                    } else {
                        Node::branch(*bit, put(left, new)?, right.clone())
                    }
                }
            }
        }
        let root = match &self.root {
            None => new_leaf,
            Some(old) => put(old, &new_leaf)?,
        };
        self.root = Some(root);
        if !existed {
            self.len = self.len.checked_add(1).ok_or(Error::Overflow)?;
        }
        Ok(())
    }
    pub fn remove(&mut self, key: &AccountPolicyId48) -> Option<RewardAccount> {
        let prior = self.get(key)?.clone();
        fn erase(old: &Arc<Node>, key: AccountPolicyId48) -> Option<Arc<Node>> {
            match old.as_ref() {
                Node::Leaf { .. } => None,
                Node::Branch {
                    bit, left, right, ..
                } => {
                    let (left, right) = if side(key, *bit) {
                        (Some(left.clone()), erase(right, key))
                    } else {
                        (erase(left, key), Some(right.clone()))
                    };
                    match (left, right) {
                        (Some(l), Some(r)) => {
                            Some(Node::branch(*bit, l, r).expect("removal cannot overflow"))
                        }
                        (Some(n), None) | (None, Some(n)) => Some(n),
                        (None, None) => None,
                    }
                }
            }
        }
        self.root = erase(self.root.as_ref().unwrap(), *key);
        self.len -= 1;
        Some(prior)
    }
    pub fn iter(&self) -> AccountTreeIter<'_> {
        AccountTreeIter {
            stack: self.root.as_deref().into_iter().collect(),
        }
    }
}
pub(crate) struct AccountTreeIter<'a> {
    stack: Vec<&'a Node>,
}
impl<'a> Iterator for AccountTreeIter<'a> {
    type Item = (&'a AccountPolicyId48, &'a RewardAccount);
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.stack.pop() {
            match node {
                Node::Leaf { key, account, .. } => return Some((key, account)),
                Node::Branch { left, right, .. } => {
                    self.stack.push(right);
                    self.stack.push(left);
                }
            }
        }
        None
    }
}
impl Encode for AccountTree {
    fn encode_to<T: Output + ?Sized>(&self, out: &mut T) {
        Compact(self.len).encode_to(out);
        for (key, account) in self.iter() {
            key.encode_to(out);
            account.encode_to(out);
        }
    }
}
impl Decode for AccountTree {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let len = Compact::<u64>::decode(input)?.0;
        let mut result = Self::default();
        let mut previous = None;
        for _ in 0..len {
            let key = AccountPolicyId48::decode(input)?;
            let account = RewardAccount::decode(input)?;
            if previous.is_some_and(|p| p >= key) {
                return Err("noncanonical account snapshot order".into());
            }
            result
                .insert(key, account)
                .map_err(|_| codec::Error::from("invalid account snapshot"))?;
            previous = Some(key);
        }
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reward_accounts_trie_matches_ordered_map_and_retains_parent() {
        use std::collections::BTreeMap;
        let mut trie = AccountTree::default();
        let mut map = BTreeMap::new();
        let empty = trie.clone();
        for i in 0..250u64 {
            let key = AccountPolicyId48::new(hash48(b"tree test", &i.to_le_bytes()));
            let value = RewardAccount {
                available: i + 1,
                ..Default::default()
            };
            trie.insert(key, value.clone()).unwrap();
            map.insert(key, value);
        }
        assert_eq!(empty.total(), 0);
        assert_eq!(trie.total(), 250 * 251 / 2);
        assert_eq!(
            trie.iter().collect::<Vec<_>>(),
            map.iter().collect::<Vec<_>>()
        );
        let mut backwards = AccountTree::default();
        for (k, v) in map.iter().rev() {
            backwards.insert(*k, v.clone()).unwrap();
        }
        assert_eq!(trie.root_hash(), backwards.root_hash());
        let parent = trie.clone();
        let original = parent.root_hash();
        for k in map.keys().step_by(2) {
            assert_eq!(trie.remove(k).as_ref(), map.get(k));
            assert!(trie.get(k).is_none());
        }
        assert_eq!(parent.root_hash(), original);
        assert_eq!(parent.total(), 250 * 251 / 2);
        let bytes = trie.encode();
        let decoded = AccountTree::decode(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded, trie);
    }
}
