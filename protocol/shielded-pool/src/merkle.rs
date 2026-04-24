use alloc::vec::Vec;

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use transaction_core::hashing_pq::{merkle_node_bytes, Commitment};

use crate::types::MERKLE_TREE_DEPTH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleTreeError {
    TreeFull,
}

pub fn merkle_hash(left: &Commitment, right: &Commitment) -> Commitment {
    merkle_node_bytes(left, right).expect("canonical merkle node")
}

pub fn default_hash_for_level(level: u32) -> [u8; 48] {
    if level == 0 {
        [0u8; 48]
    } else {
        let child = default_hash_for_level(level - 1);
        merkle_hash(&child, &child)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct DefaultHashes {
    pub hashes: Vec<[u8; 48]>,
}

impl DefaultHashes {
    pub fn new(depth: u32) -> Self {
        let mut hashes = Vec::with_capacity(depth as usize + 1);
        for level in 0..=depth {
            hashes.push(default_hash_for_level(level));
        }
        Self { hashes }
    }

    pub fn at_level(&self, level: u32) -> [u8; 48] {
        self.hashes
            .get(level as usize)
            .copied()
            .unwrap_or([0u8; 48])
    }
}

impl Default for DefaultHashes {
    fn default() -> Self {
        Self::new(MERKLE_TREE_DEPTH)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct CompactMerkleTree {
    #[codec(compact)]
    pub leaf_count: u64,
    pub root: [u8; 48],
    pub frontier: Vec<[u8; 48]>,
}

impl MaxEncodedLen for CompactMerkleTree {
    fn max_encoded_len() -> usize {
        9 + 48 + 4 + (33 * 48)
    }
}

impl CompactMerkleTree {
    pub fn new() -> Self {
        let defaults = DefaultHashes::new(MERKLE_TREE_DEPTH);
        Self {
            leaf_count: 0,
            root: defaults.at_level(MERKLE_TREE_DEPTH),
            frontier: Vec::new(),
        }
    }

    pub fn root(&self) -> [u8; 48] {
        self.root
    }

    pub fn len(&self) -> u64 {
        self.leaf_count
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }

    pub fn is_full(&self) -> bool {
        self.leaf_count >= (1u64 << MERKLE_TREE_DEPTH)
    }

    pub fn append(&mut self, leaf: [u8; 48]) -> Result<[u8; 48], MerkleTreeError> {
        if self.is_full() {
            return Err(MerkleTreeError::TreeFull);
        }

        let defaults = DefaultHashes::new(MERKLE_TREE_DEPTH);
        let position = self.leaf_count;

        while self.frontier.len() <= MERKLE_TREE_DEPTH as usize {
            self.frontier.push([0u8; 48]);
        }

        let mut current = leaf;
        let mut level_position = position;

        for level in 0..MERKLE_TREE_DEPTH {
            if level_position & 1 == 0 {
                self.frontier[level as usize] = current;
                current = merkle_hash(&current, &defaults.at_level(level));
            } else {
                let left = self.frontier[level as usize];
                current = merkle_hash(&left, &current);
            }
            level_position >>= 1;
        }

        self.root = current;
        self.leaf_count += 1;

        Ok(self.root)
    }
}

impl Default for CompactMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}
