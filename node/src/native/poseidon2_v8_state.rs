//! Durable canonical stablecoin-root state for the SmallWood/Poseidon2 V8 lane.
//!
//! This module deliberately does not know the V8 native-leaf byte offsets.
//! The transaction circuit owns that grammar.  Instead, the node passes every
//! exact V8 native leaf in canonical block order to an exact proof verifier.
//! Only the public before/after root returned by a successful verification can
//! reach the storage transaction below.
//!
//! The seven-limb root has a fresh magic and fixed codec.  It is never decoded
//! as, converted from, or compared through the historical BLAKE2b stablecoin
//! root types.

#![allow(dead_code)]

use protocol_shielded_pool::poseidon2_production_transport::{
    preflight_poseidon2_production_smza_native_leaf_exact,
    POSEIDON2_PRODUCTION_MAX_NATIVE_LEAF_BYTES, POSEIDON2_PRODUCTION_SMZA_MAX_NATIVE_LEAF_BYTES,
};
use sha2::{Digest, Sha512};
use sled::transaction::{
    ConflictableTransactionError, ConflictableTransactionResult, TransactionError,
    TransactionalTree,
};
use std::collections::{BTreeSet, VecDeque};
use transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_default_note_nodes as source_poseidon2_v8_default_note_nodes;
use transaction_core::{
    constants::{CIRCUIT_MERKLE_DEPTH, MERKLE_DOMAIN_TAG},
    poseidon2_width16::{
        poseidon2_width16_compress14, Felt, POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER,
    },
};

use super::{
    launch_reference::{
        CanonicalAssetRegistryRoot, CanonicalLaunchCheckpoint, CanonicalLaunchReferences,
        CheckedLaunchReference, LaunchReferenceContext, LaunchReferenceRoute,
    },
    smallwood_v8_lifetime::{SmallwoodV8ProofLifetimeCount, SmallwoodV8ProofLifetimeError},
    MAX_NATIVE_BLOCK_ACTION_BYTES, MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK,
};

pub(crate) const POSEIDON2_V8_STATE_TREE_NAME: &[u8] = b"poseidon2_v8_stablecoin_state";
pub(crate) const POSEIDON2_V8_GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
/// Largest integer that the V8 relation admits injectively for general scalar
/// fields, including authenticated parent and child heights.
pub(crate) const POSEIDON2_V8_MAX_SCALAR: u64 = (1u64 << 63) - 1;
pub(crate) const POSEIDON2_V8_ROOT_LIMBS: usize = 7;
pub(crate) const POSEIDON2_V8_ROOT_CODEC_BYTES: usize = 8 + 8 + 8 * POSEIDON2_V8_ROOT_LIMBS;
pub(crate) const POSEIDON2_V8_DIGEST_BYTES: usize = 8 * POSEIDON2_V8_ROOT_LIMBS;
pub(crate) const POSEIDON2_V8_NOTE_ROOT_HISTORY_LIMIT: usize = 100;

// Persisted roots and frontiers belong to one compression mode. Predecessor
// codecs are rejected; their stored limbs are never reinterpreted or rewritten.
const ROOT_MAGIC: &[u8; 8] = b"P2V8RT02";
const CHECKPOINT_MAGIC: &[u8; 8] = b"P2V8CP01";
const RECORD_MAGIC: &[u8; 8] = b"P2V8BR03";
const GENESIS_KEY: &[u8] = b"canonical_genesis_v1";
const TIP_KEY: &[u8] = b"canonical_tip_v1";
const NOTE_TIP_KEY: &[u8] = b"canonical_note_tip_v1";
const PROOF_LIFETIME_TIP_KEY: &[u8] = b"canonical_proof_lifetime_tip_v1";
// These rows exist only on an explicit asset-enabled genesis. Historical
// checkpoint, note, proof-lifetime and block record bytes stay unchanged.
const ASSET_GENESIS_KEY: &[u8] = b"canonical_asset_genesis_v1";
const ASSET_TIP_KEY: &[u8] = b"canonical_asset_tip_v1";
const ASSET_RECORD_KEY_PREFIX: &[u8] = b"canonical_asset_block_v1/";
const HEIGHT_KEY_PREFIX: &[u8] = b"canonical_height_v1/";
const RECORD_KEY_PREFIX: &[u8] = b"canonical_block_v1/";
const NULLIFIER_KEY_PREFIX: &[u8] = b"canonical_nullifier_v1/";
const LEAF_SEQUENCE_DOMAIN: &[u8] =
    b"hegemon.native.poseidon2-v8.stablecoin-leaf-sequence.sha512.v1\0";
const BLOCK_RECORD_DOMAIN: &[u8] =
    b"hegemon.native.poseidon2-v8.stablecoin-block-record.sha512.v2\0";
const NOTE_STATE_MAGIC: &[u8; 8] = b"P2V8NT04";
const MAX_PENDING_REWARD_BLOCKS: usize = consensus::reward::COINBASE_MATURITY as usize - 1;
const PENDING_REWARD_CODEC_BYTES: usize = 8 + 32 + 1 + 2 * POSEIDON2_V8_DIGEST_BYTES;

const CHECKPOINT_CODEC_BYTES: usize = 8 + 8 + 32 + POSEIDON2_V8_ROOT_CODEC_BYTES;
const BLOCK_RECORD_CODEC_BYTES: usize = 8
    + 8
    + 32
    + 8
    + 32
    + POSEIDON2_V8_ROOT_CODEC_BYTES
    + POSEIDON2_V8_ROOT_CODEC_BYTES
    + 8
    + 8
    + 4
    + 8
    + 64
    + 64;

macro_rules! field_digest_type {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub(crate) struct $name([u64; POSEIDON2_V8_ROOT_LIMBS]);

        impl $name {
            pub(crate) fn new(
                limbs: [u64; POSEIDON2_V8_ROOT_LIMBS],
            ) -> Result<Self, Poseidon2V8StateError> {
                validate_digest_limbs($label, &limbs)?;
                Ok(Self(limbs))
            }

            pub(crate) const fn limbs(self) -> [u64; POSEIDON2_V8_ROOT_LIMBS] {
                self.0
            }

            fn encode(self) -> [u8; POSEIDON2_V8_DIGEST_BYTES] {
                encode_digest_limbs(self.0)
            }

            fn decode_exact(bytes: &[u8]) -> Result<Self, Poseidon2V8StateError> {
                Self::new(decode_digest_limbs(bytes, $label)?)
            }
        }
    };
}

field_digest_type!(Poseidon2V8NoteRoot, "V8 note root");
field_digest_type!(Poseidon2V8Nullifier, "V8 nullifier");
field_digest_type!(Poseidon2V8Commitment, "V8 commitment");

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Poseidon2V8Root([u64; POSEIDON2_V8_ROOT_LIMBS]);

impl Poseidon2V8Root {
    pub(crate) fn new(
        limbs: [u64; POSEIDON2_V8_ROOT_LIMBS],
    ) -> Result<Self, Poseidon2V8StateError> {
        for (index, limb) in limbs.iter().copied().enumerate() {
            if limb >= POSEIDON2_V8_GOLDILOCKS_MODULUS {
                return Err(Poseidon2V8StateError::NonCanonicalRootLimb { index, limb });
            }
        }
        Ok(Self(limbs))
    }

    pub(crate) const fn limbs(self) -> [u64; POSEIDON2_V8_ROOT_LIMBS] {
        self.0
    }

    pub(crate) fn encode(self) -> [u8; POSEIDON2_V8_ROOT_CODEC_BYTES] {
        let mut encoded = [0u8; POSEIDON2_V8_ROOT_CODEC_BYTES];
        encoded[..ROOT_MAGIC.len()].copy_from_slice(ROOT_MAGIC);
        encoded[ROOT_MAGIC.len()..ROOT_MAGIC.len() + 8]
            .copy_from_slice(&POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER.to_le_bytes());
        for (index, limb) in self.0.iter().copied().enumerate() {
            let start = ROOT_MAGIC.len() + 8 + index * 8;
            encoded[start..start + 8].copy_from_slice(&limb.to_le_bytes());
        }
        encoded
    }

    pub(crate) fn decode_exact(bytes: &[u8]) -> Result<Self, Poseidon2V8StateError> {
        if bytes.get(..ROOT_MAGIC.len()) != Some(ROOT_MAGIC.as_slice()) {
            return Err(Poseidon2V8StateError::CodecMagic("V8 stablecoin root"));
        }
        if bytes.len() != POSEIDON2_V8_ROOT_CODEC_BYTES {
            return Err(Poseidon2V8StateError::CodecLength {
                label: "V8 stablecoin root",
                expected: POSEIDON2_V8_ROOT_CODEC_BYTES,
                observed: bytes.len(),
            });
        }
        let mut mode = &bytes[ROOT_MAGIC.len()..ROOT_MAGIC.len() + 8];
        expect_compression_mode(&mut mode, "V8 stablecoin root")?;
        let mut limbs = [0u64; POSEIDON2_V8_ROOT_LIMBS];
        for (index, limb) in limbs.iter_mut().enumerate() {
            let start = ROOT_MAGIC.len() + 8 + index * 8;
            *limb = u64::from_le_bytes(
                bytes[start..start + 8]
                    .try_into()
                    .expect("fixed V8 root limb is eight bytes"),
            );
        }
        Self::new(limbs)
    }
}

/// A consensus-validated issuance that has no spendable tree position yet.
/// Keeping this in each authenticated block snapshot makes fork rollback restore
/// both pending issuance and already admitted commitments atomically.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingPoseidon2V8Rewards {
    origin_height: u64,
    origin_hash: [u8; 32],
    miner: Poseidon2V8Commitment,
    funding: Option<Poseidon2V8Commitment>,
}

impl PendingPoseidon2V8Rewards {
    fn admission_height(&self) -> Result<u64, Poseidon2V8StateError> {
        consensus::reward::coinbase_release_height(self.origin_height)
            .ok_or(Poseidon2V8StateError::HeightOverflow)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Poseidon2V8NoteTreeState {
    leaf_count: u64,
    root: Poseidon2V8NoteRoot,
    frontier: Vec<Poseidon2V8NoteRoot>,
    default_nodes: Vec<Poseidon2V8NoteRoot>,
    root_history: VecDeque<Poseidon2V8NoteRoot>,
    pending_rewards: VecDeque<PendingPoseidon2V8Rewards>,
}

impl Poseidon2V8NoteTreeState {
    pub(crate) fn new_empty() -> Result<Self, Poseidon2V8StateError> {
        let default_nodes = poseidon2_v8_default_note_nodes()?;
        let root = *default_nodes
            .last()
            .ok_or(Poseidon2V8StateError::InvalidNoteTreeDepth)?;
        let frontier = default_nodes[..CIRCUIT_MERKLE_DEPTH].to_vec();
        let mut root_history = VecDeque::new();
        root_history.push_back(root);
        Ok(Self {
            leaf_count: 0,
            root,
            frontier,
            default_nodes,
            root_history,
            pending_rewards: VecDeque::new(),
        })
    }

    pub(crate) const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    pub(crate) const fn root(&self) -> Poseidon2V8NoteRoot {
        self.root
    }

    pub(crate) fn contains_root(&self, root: Poseidon2V8NoteRoot) -> bool {
        self.root_history.iter().any(|candidate| *candidate == root)
    }

    pub(crate) fn append(
        &mut self,
        commitment: Poseidon2V8Commitment,
    ) -> Result<Poseidon2V8NoteRoot, Poseidon2V8StateError> {
        let capacity = 1u64
            .checked_shl(CIRCUIT_MERKLE_DEPTH as u32)
            .unwrap_or(u64::MAX);
        if self.leaf_count >= capacity {
            return Err(Poseidon2V8StateError::NoteTreeFull);
        }
        let mut current = Poseidon2V8NoteRoot::new(commitment.limbs())?;
        let mut position = self.leaf_count;
        for level in 0..CIRCUIT_MERKLE_DEPTH {
            current = if position & 1 == 0 {
                self.frontier[level] = current;
                compress_note_roots(current, self.default_nodes[level])?
            } else {
                compress_note_roots(self.frontier[level], current)?
            };
            position >>= 1;
        }
        self.leaf_count = self
            .leaf_count
            .checked_add(1)
            .ok_or(Poseidon2V8StateError::NoteTreeFull)?;
        self.root = current;
        if self.root_history.back().copied() != Some(current) {
            while self.root_history.len() >= POSEIDON2_V8_NOTE_ROOT_HISTORY_LIMIT {
                self.root_history.pop_front();
            }
            self.root_history.push_back(current);
        }
        Ok(current)
    }

    /// Admit due rewards after ordinary outputs, then retain this block's public
    /// issuance. Membership references are fixed before this call. Inserting at
    /// h+119 therefore makes the earliest spending block exactly h+120.
    fn finish_block_rewards(
        &mut self,
        height: u64,
        block_hash: [u8; 32],
        rewards: [Option<Poseidon2V8Commitment>; 2],
    ) -> Result<(), Poseidon2V8StateError> {
        let parent = height
            .checked_sub(1)
            .ok_or(Poseidon2V8StateError::CorruptPendingRewards)?;
        self.validate_pending_at_height(parent)?;
        if block_hash == [0; 32]
            || (rewards[1].is_some() && (rewards[0].is_none() || rewards[0] == rewards[1]))
        {
            return Err(Poseidon2V8StateError::CorruptPendingRewards);
        }
        while self
            .pending_rewards
            .front()
            .is_some_and(|row| row.admission_height() == Ok(height))
        {
            let row = self
                .pending_rewards
                .pop_front()
                .ok_or(Poseidon2V8StateError::CorruptPendingRewards)?;
            self.append(row.miner)?;
            if let Some(funding) = row.funding {
                self.append(funding)?;
            }
        }
        if let Some(miner) = rewards[0] {
            self.pending_rewards.push_back(PendingPoseidon2V8Rewards {
                origin_height: height,
                origin_hash: block_hash,
                miner,
                funding: rewards[1],
            });
        }
        self.validate_pending_at_height(height)
    }

    #[cfg(test)]
    pub(super) fn test_finish_block_rewards(
        &mut self,
        height: u64,
        block_hash: [u8; 32],
        rewards: [Option<Poseidon2V8Commitment>; 2],
    ) -> Result<(), Poseidon2V8StateError> {
        self.finish_block_rewards(height, block_hash, rewards)
    }

    fn validate_pending_shape(&self) -> Result<(), Poseidon2V8StateError> {
        if self.pending_rewards.len() > MAX_PENDING_REWARD_BLOCKS {
            return Err(Poseidon2V8StateError::CorruptPendingRewards);
        }
        let mut previous = 0;
        let mut hashes = BTreeSet::new();
        for row in &self.pending_rewards {
            if row.origin_height <= previous
                || row.origin_hash == [0; 32]
                || !hashes.insert(row.origin_hash)
                || row.funding == Some(row.miner)
            {
                return Err(Poseidon2V8StateError::CorruptPendingRewards);
            }
            row.admission_height()?;
            previous = row.origin_height;
        }
        Ok(())
    }

    fn validate_pending_at_height(&self, height: u64) -> Result<(), Poseidon2V8StateError> {
        self.validate_pending_shape()?;
        for row in &self.pending_rewards {
            if row.origin_height > height || row.admission_height()? <= height {
                return Err(Poseidon2V8StateError::CorruptPendingRewards);
            }
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, Poseidon2V8StateError> {
        if self.frontier.len() != CIRCUIT_MERKLE_DEPTH
            || self.default_nodes.len() != CIRCUIT_MERKLE_DEPTH + 1
            || self.root_history.is_empty()
            || self.root_history.len() > POSEIDON2_V8_NOTE_ROOT_HISTORY_LIMIT
            || self.root_history.back().copied() != Some(self.root)
        {
            return Err(Poseidon2V8StateError::CorruptNoteTreeState);
        }
        self.validate_pending_shape()?;
        let history_len = u16::try_from(self.root_history.len())
            .map_err(|_| Poseidon2V8StateError::CorruptNoteTreeState)?;
        let capacity = NOTE_STATE_MAGIC.len()
            + 8 // compression mode
            + 8
            + POSEIDON2_V8_DIGEST_BYTES
            + 2
            + CIRCUIT_MERKLE_DEPTH * POSEIDON2_V8_DIGEST_BYTES
            + self.root_history.len() * POSEIDON2_V8_DIGEST_BYTES
            + 2
            + self.pending_rewards.len() * PENDING_REWARD_CODEC_BYTES;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(capacity)
            .map_err(|_| Poseidon2V8StateError::AllocationFailed(capacity))?;
        encoded.extend_from_slice(NOTE_STATE_MAGIC);
        encoded.extend_from_slice(&POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER.to_le_bytes());
        encoded.extend_from_slice(&self.leaf_count.to_le_bytes());
        encoded.extend_from_slice(&self.root.encode());
        encoded.extend_from_slice(&history_len.to_le_bytes());
        for node in &self.frontier {
            encoded.extend_from_slice(&node.encode());
        }
        for root in &self.root_history {
            encoded.extend_from_slice(&root.encode());
        }
        encoded.extend_from_slice(&(self.pending_rewards.len() as u16).to_le_bytes());
        for row in &self.pending_rewards {
            encoded.extend_from_slice(&row.origin_height.to_le_bytes());
            encoded.extend_from_slice(&row.origin_hash);
            encoded.push(u8::from(row.funding.is_some()));
            encoded.extend_from_slice(&row.miner.encode());
            encoded.extend_from_slice(
                &row.funding
                    .map_or([0; POSEIDON2_V8_DIGEST_BYTES], |v| v.encode()),
            );
        }
        Ok(encoded)
    }

    fn decode_exact(bytes: &[u8]) -> Result<Self, Poseidon2V8StateError> {
        if bytes.get(..NOTE_STATE_MAGIC.len()) != Some(NOTE_STATE_MAGIC.as_slice()) {
            return Err(Poseidon2V8StateError::CodecMagic("V8 note-tree state"));
        }
        let minimum = NOTE_STATE_MAGIC.len()
            + 8 // compression mode
            + 8
            + POSEIDON2_V8_DIGEST_BYTES
            + 2
            + CIRCUIT_MERKLE_DEPTH * POSEIDON2_V8_DIGEST_BYTES
            + POSEIDON2_V8_DIGEST_BYTES
            + 2;
        let maximum = minimum
            + (POSEIDON2_V8_NOTE_ROOT_HISTORY_LIMIT - 1) * POSEIDON2_V8_DIGEST_BYTES
            + MAX_PENDING_REWARD_BLOCKS * PENDING_REWARD_CODEC_BYTES;
        if bytes.len() < minimum || bytes.len() > maximum {
            return Err(Poseidon2V8StateError::CodecLength {
                label: "V8 note-tree state",
                expected: minimum,
                observed: bytes.len(),
            });
        }
        let mut cursor = bytes;
        expect_magic(&mut cursor, NOTE_STATE_MAGIC, "V8 note-tree state")?;
        expect_compression_mode(&mut cursor, "V8 note-tree state")?;
        let leaf_count = take_u64(&mut cursor, "V8 note-tree leaf count")?;
        let root = Poseidon2V8NoteRoot::decode_exact(take(
            &mut cursor,
            POSEIDON2_V8_DIGEST_BYTES,
            "V8 note-tree root",
        )?)?;
        let history_len = usize::from(u16::from_le_bytes(take_array(
            &mut cursor,
            "V8 note-tree history length",
        )?));
        if history_len == 0 || history_len > POSEIDON2_V8_NOTE_ROOT_HISTORY_LIMIT {
            return Err(Poseidon2V8StateError::CorruptNoteTreeState);
        }
        let expected_remaining = CIRCUIT_MERKLE_DEPTH
            .checked_add(history_len)
            .and_then(|count| count.checked_mul(POSEIDON2_V8_DIGEST_BYTES))
            .ok_or(Poseidon2V8StateError::CorruptNoteTreeState)?;
        if cursor.len() < expected_remaining + 2 {
            return Err(Poseidon2V8StateError::CodecLength {
                label: "V8 note-tree state rows",
                expected: expected_remaining,
                observed: cursor.len(),
            });
        }
        let mut frontier = Vec::with_capacity(CIRCUIT_MERKLE_DEPTH);
        for _ in 0..CIRCUIT_MERKLE_DEPTH {
            frontier.push(Poseidon2V8NoteRoot::decode_exact(take(
                &mut cursor,
                POSEIDON2_V8_DIGEST_BYTES,
                "V8 note-tree frontier",
            )?)?);
        }
        let mut root_history = VecDeque::with_capacity(history_len);
        for _ in 0..history_len {
            root_history.push_back(Poseidon2V8NoteRoot::decode_exact(take(
                &mut cursor,
                POSEIDON2_V8_DIGEST_BYTES,
                "V8 note-tree root history",
            )?)?);
        }
        let pending_len = usize::from(u16::from_le_bytes(take_array(
            &mut cursor,
            "V8 pending reward count",
        )?));
        if pending_len > MAX_PENDING_REWARD_BLOCKS
            || cursor.len() != pending_len * PENDING_REWARD_CODEC_BYTES
        {
            return Err(Poseidon2V8StateError::CorruptPendingRewards);
        }
        let mut pending_rewards = VecDeque::with_capacity(pending_len);
        for _ in 0..pending_len {
            let origin_height = take_u64(&mut cursor, "V8 reward origin height")?;
            let origin_hash = take_array(&mut cursor, "V8 reward origin hash")?;
            let funding_flag = take(&mut cursor, 1, "V8 reward funding flag")?[0];
            let miner = Poseidon2V8Commitment::decode_exact(take(
                &mut cursor,
                POSEIDON2_V8_DIGEST_BYTES,
                "V8 pending miner",
            )?)?;
            let funding_bytes = take(&mut cursor, POSEIDON2_V8_DIGEST_BYTES, "V8 pending funding")?;
            let funding = match funding_flag {
                0 if funding_bytes == [0; POSEIDON2_V8_DIGEST_BYTES] => None,
                1 => Some(Poseidon2V8Commitment::decode_exact(funding_bytes)?),
                _ => return Err(Poseidon2V8StateError::CorruptPendingRewards),
            };
            pending_rewards.push_back(PendingPoseidon2V8Rewards {
                origin_height,
                origin_hash,
                miner,
                funding,
            });
        }
        if !cursor.is_empty() || root_history.back().copied() != Some(root) {
            return Err(Poseidon2V8StateError::CorruptNoteTreeState);
        }
        let default_nodes = poseidon2_v8_default_note_nodes()?;
        let state = Self {
            leaf_count,
            root,
            frontier,
            default_nodes,
            root_history,
            pending_rewards,
        };
        state.validate_frontier_shape()?;
        state.validate_pending_shape()?;
        Ok(state)
    }

    fn validate_frontier_shape(&self) -> Result<(), Poseidon2V8StateError> {
        let capacity = 1u64
            .checked_shl(CIRCUIT_MERKLE_DEPTH as u32)
            .unwrap_or(u64::MAX);
        if self.leaf_count > capacity {
            return Err(Poseidon2V8StateError::CorruptNoteTreeState);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Poseidon2V8Checkpoint {
    height: u64,
    block_hash: [u8; 32],
    root: Poseidon2V8Root,
}

impl Poseidon2V8Checkpoint {
    pub(crate) const fn new(height: u64, block_hash: [u8; 32], root: Poseidon2V8Root) -> Self {
        Self {
            height,
            block_hash,
            root,
        }
    }

    pub(crate) const fn height(self) -> u64 {
        self.height
    }

    pub(crate) const fn block_hash(self) -> [u8; 32] {
        self.block_hash
    }

    pub(crate) const fn root(self) -> Poseidon2V8Root {
        self.root
    }

    fn encode(self) -> [u8; CHECKPOINT_CODEC_BYTES] {
        let mut encoded = [0u8; CHECKPOINT_CODEC_BYTES];
        let mut cursor = 0usize;
        put(&mut encoded, &mut cursor, CHECKPOINT_MAGIC);
        put(&mut encoded, &mut cursor, &self.height.to_le_bytes());
        put(&mut encoded, &mut cursor, &self.block_hash);
        put(&mut encoded, &mut cursor, &self.root.encode());
        debug_assert_eq!(cursor, encoded.len());
        encoded
    }

    fn decode_exact(bytes: &[u8]) -> Result<Self, Poseidon2V8StateError> {
        if bytes.len() != CHECKPOINT_CODEC_BYTES {
            return Err(Poseidon2V8StateError::CodecLength {
                label: "V8 stablecoin checkpoint",
                expected: CHECKPOINT_CODEC_BYTES,
                observed: bytes.len(),
            });
        }
        let mut cursor = bytes;
        expect_magic(&mut cursor, CHECKPOINT_MAGIC, "V8 stablecoin checkpoint")?;
        let height = take_u64(&mut cursor, "V8 stablecoin checkpoint height")?;
        validate_relation_height(height)?;
        let block_hash = take_array::<32>(&mut cursor, "V8 stablecoin checkpoint block hash")?;
        let root = Poseidon2V8Root::decode_exact(take(
            &mut cursor,
            POSEIDON2_V8_ROOT_CODEC_BYTES,
            "V8 stablecoin checkpoint root",
        )?)?;
        if !cursor.is_empty() {
            return Err(Poseidon2V8StateError::CodecTrailing(
                "V8 stablecoin checkpoint",
            ));
        }
        Ok(Self {
            height,
            block_hash,
            root,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Poseidon2V8BlockContext {
    parent_height: u64,
    parent_hash: [u8; 32],
    height: u64,
    block_hash: [u8; 32],
}

impl Poseidon2V8BlockContext {
    pub(crate) fn new(
        parent_height: u64,
        parent_hash: [u8; 32],
        height: u64,
        block_hash: [u8; 32],
    ) -> Result<Self, Poseidon2V8StateError> {
        validate_relation_height(parent_height)?;
        validate_relation_height(height)?;
        let expected_height = parent_height
            .checked_add(1)
            .ok_or(Poseidon2V8StateError::HeightOverflow)?;
        if height != expected_height {
            return Err(Poseidon2V8StateError::NonContiguousHeight {
                expected: expected_height,
                observed: height,
            });
        }
        if block_hash == parent_hash {
            return Err(Poseidon2V8StateError::BlockEqualsParent);
        }
        Ok(Self {
            parent_height,
            parent_hash,
            height,
            block_hash,
        })
    }

    pub(crate) const fn parent_height(self) -> u64 {
        self.parent_height
    }

    pub(crate) const fn parent_hash(self) -> [u8; 32] {
        self.parent_hash
    }

    pub(crate) const fn height(self) -> u64 {
        self.height
    }

    pub(crate) const fn block_hash(self) -> [u8; 32] {
        self.block_hash
    }
}

/// Public stablecoin fields extracted only after exact V8 proof verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Poseidon2V8StablecoinEffect {
    /// The exact verified statement carried the canonical all-zero disabled
    /// stablecoin surface.  No stablecoin counter or root write is authorized.
    DisabledNoWrite,
    Mint,
    Burn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Poseidon2V8PublicTransition {
    parent_height: u64,
    application_parent_hint: Option<u64>,
    checked_launch_reference: Option<CheckedLaunchReference>,
    before_root: Poseidon2V8Root,
    after_root: Poseidon2V8Root,
    stablecoin_effect: Poseidon2V8StablecoinEffect,
    note_anchor: Poseidon2V8NoteRoot,
    nullifiers: [Option<Poseidon2V8Nullifier>; 2],
    commitments: [Option<Poseidon2V8Commitment>; 2],
    third_commitment: Option<Poseidon2V8Commitment>,
}

impl Poseidon2V8PublicTransition {
    #[cfg(test)]
    pub(crate) fn new(
        parent_height: u64,
        before_root: Poseidon2V8Root,
        after_root: Poseidon2V8Root,
    ) -> Self {
        let note_anchor = Poseidon2V8NoteTreeState::new_empty()
            .expect("canonical V8 empty note tree")
            .root();
        Self::new_with_shielded_state_and_stablecoin_effect(
            parent_height,
            before_root,
            after_root,
            Poseidon2V8StablecoinEffect::Mint,
            note_anchor,
            [None, None],
            [None, None],
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_stablecoin_effect(
        parent_height: u64,
        before_root: Poseidon2V8Root,
        after_root: Poseidon2V8Root,
        stablecoin_effect: Poseidon2V8StablecoinEffect,
    ) -> Self {
        let note_anchor = Poseidon2V8NoteTreeState::new_empty()
            .expect("canonical V8 empty note tree")
            .root();
        Self::new_with_shielded_state_and_stablecoin_effect(
            parent_height,
            before_root,
            after_root,
            stablecoin_effect,
            note_anchor,
            [None, None],
            [None, None],
        )
    }

    pub(crate) const fn new_with_shielded_state(
        parent_height: u64,
        before_root: Poseidon2V8Root,
        after_root: Poseidon2V8Root,
        note_anchor: Poseidon2V8NoteRoot,
        nullifiers: [Option<Poseidon2V8Nullifier>; 2],
        commitments: [Option<Poseidon2V8Commitment>; 2],
    ) -> Self {
        Self::new_with_shielded_state_and_stablecoin_effect(
            parent_height,
            before_root,
            after_root,
            Poseidon2V8StablecoinEffect::Mint,
            note_anchor,
            nullifiers,
            commitments,
        )
    }

    pub(crate) const fn new_with_shielded_state_and_stablecoin_effect(
        parent_height: u64,
        before_root: Poseidon2V8Root,
        after_root: Poseidon2V8Root,
        stablecoin_effect: Poseidon2V8StablecoinEffect,
        note_anchor: Poseidon2V8NoteRoot,
        nullifiers: [Option<Poseidon2V8Nullifier>; 2],
        commitments: [Option<Poseidon2V8Commitment>; 2],
    ) -> Self {
        Self {
            parent_height,
            application_parent_hint: None,
            checked_launch_reference: None,
            before_root,
            after_root,
            stablecoin_effect,
            note_anchor,
            nullifiers,
            commitments,
            third_commitment: None,
        }
    }

    /// Exact asset proof verification supplies all three outputs to the same pool.
    pub(crate) const fn new_with_asset_shielded_state(
        parent_height: u64,
        static_root: Poseidon2V8Root,
        note_anchor: Poseidon2V8NoteRoot,
        nullifiers: [Option<Poseidon2V8Nullifier>; 2],
        commitments: [Option<Poseidon2V8Commitment>; 3],
    ) -> Self {
        Self {
            parent_height,
            application_parent_hint: None,
            checked_launch_reference: None,
            before_root: static_root,
            after_root: static_root,
            stablecoin_effect: Poseidon2V8StablecoinEffect::DisabledNoWrite,
            note_anchor,
            nullifiers,
            commitments: [commitments[0], commitments[1]],
            third_commitment: commitments[2],
        }
    }

    pub(crate) const fn all_commitments(self) -> [Option<Poseidon2V8Commitment>; 3] {
        [
            self.commitments[0],
            self.commitments[1],
            self.third_commitment,
        ]
    }

    pub(crate) const fn parent_height(self) -> u64 {
        self.parent_height
    }

    /// Scheduling metadata only. The original proof-public parent is unchanged.
    pub(crate) fn with_launch_application_hint(mut self, parent: u64) -> Self {
        self.application_parent_hint = Some(parent);
        self
    }
    pub(crate) const fn application_parent_height(self) -> u64 {
        match self.checked_launch_reference {
            Some(checked) => checked.application_parent_height(),
            None => match self.application_parent_hint {
                Some(hint) => hint,
                None => self.parent_height,
            },
        }
    }
    pub(crate) const fn checked_launch_reference(self) -> Option<CheckedLaunchReference> {
        self.checked_launch_reference
    }
    pub(crate) fn with_checked_launch_reference(
        mut self,
        checked: CheckedLaunchReference,
    ) -> Result<Self, String> {
        if self.parent_height != checked.reference_height()
            || self.note_anchor != checked.note_anchor()
            || self.before_root != checked.static_stable_root()
            || self.after_root != checked.static_stable_root()
            || self.stablecoin_effect != Poseidon2V8StablecoinEffect::DisabledNoWrite
            || self
                .application_parent_hint
                .is_some_and(|hint| hint != checked.application_parent_height())
        {
            return Err("checked launch reference differs from original proof transition".into());
        }
        self.checked_launch_reference = Some(checked);
        Ok(self)
    }

    pub(crate) const fn before_root(self) -> Poseidon2V8Root {
        self.before_root
    }

    pub(crate) const fn after_root(self) -> Poseidon2V8Root {
        self.after_root
    }

    pub(crate) const fn stablecoin_effect(self) -> Poseidon2V8StablecoinEffect {
        self.stablecoin_effect
    }

    /// The verified effect classification must agree with the public roots it
    /// authorizes. Disabled statements are source-canonical no-writes; Mint
    /// and Burn statements are state writes and therefore must change the
    /// authenticated stablecoin root.
    pub(crate) fn stablecoin_effect_matches_roots(self) -> bool {
        match self.stablecoin_effect {
            Poseidon2V8StablecoinEffect::DisabledNoWrite => self.before_root == self.after_root,
            Poseidon2V8StablecoinEffect::Mint | Poseidon2V8StablecoinEffect::Burn => {
                self.before_root != self.after_root
            }
        }
    }

    pub(crate) const fn note_anchor(self) -> Poseidon2V8NoteRoot {
        self.note_anchor
    }

    pub(crate) const fn nullifiers(self) -> [Option<Poseidon2V8Nullifier>; 2] {
        self.nullifiers
    }

    pub(crate) const fn commitments(self) -> [Option<Poseidon2V8Commitment>; 2] {
        self.commitments
    }
}

/// Closed source-owned leaf ceilings. Even a custom test verifier can only
/// select a supported ceiling; it cannot supply an arbitrary byte allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Poseidon2V8NativeLeafProfile {
    Smz9,
    Smza,
    /// Closed launch and opt-in recovery frames, with each exact source cap.
    LaunchMixed,
}

impl Poseidon2V8NativeLeafProfile {
    const fn max_native_leaf_bytes(self) -> usize {
        match self {
            Self::Smz9 => POSEIDON2_PRODUCTION_MAX_NATIVE_LEAF_BYTES,
            Self::Smza => POSEIDON2_PRODUCTION_SMZA_MAX_NATIVE_LEAF_BYTES,
            Self::LaunchMixed => {
                let rp06 =
                    protocol_shielded_pool::rp06_transport::RP06_CANDIDATE_MAX_NATIVE_LEAF_BYTES;
                let htlc =
                    transaction_circuit::smallwood_htlc_transport::MAX_CANDIDATE_CARRIER_BYTES;
                let private = protocol_shielded_pool::private_spend_transport::MAX_CARRIER_BYTES;
                let asset = transaction_circuit::asset_spend_v1_wire::NATIVE_ASSET_SPEND_MAX_ACTION_BYTES_V1;
                let admin = transaction_circuit::asset_spend_v1_wire::NATIVE_ASSET_ADMIN_MAX_ACTION_BYTES_V1;
                let historical = if rp06 > htlc { rp06 } else { htlc };
                let native = if private > historical {
                    private
                } else {
                    historical
                };
                let asset = if asset > admin { asset } else { admin };
                let legacy = if native > asset { native } else { asset };
                let recovery_spend = transaction_circuit::asset_recovery_wire_v1::MAX_SPEND_ACTION_BYTES;
                let recovery_admin = transaction_circuit::asset_recovery_wire_v1::MAX_ADMIN_ACTION_BYTES;
                let recovery = if recovery_spend > recovery_admin {
                    recovery_spend
                } else {
                    recovery_admin
                };
                if legacy > recovery { legacy } else { recovery }
            }
        }
    }
}

/// This bound is local scheduling, not protocol geometry: state consumes one
/// window before any later window can enter proof verification.
pub(crate) const POSEIDON2_V8_PROOF_VERIFICATION_WINDOW: usize = 4;

/// The production implementation must parse and verify the exact canonical
/// native leaf, then return the proof-public stablecoin transition. Returning
/// `Ok` is the only capability that can create a durable forward transition.
pub(crate) trait Poseidon2V8ExactLeafVerifier {
    /// Closed source profiles, never a caller-supplied allocation ceiling.
    /// Every implementation must select or forward its profile explicitly;
    /// wrappers must not silently fall back to a historical profile.
    fn native_leaf_profile(&self) -> Poseidon2V8NativeLeafProfile;

    /// Actual independent proof candidates, not carrier count. The shared pool
    /// cross-checks this value against the closed exact recovery grammar.
    fn exact_leaf_proof_units(&self, _exact_native_leaf: &[u8]) -> Result<usize, String> {
        Ok(1)
    }

    /// Bounded launch profiles retain their exact source-owned lifetime quota.
    /// An absent quota grants no authority without the separate ongoing HGN gate.
    fn launch_proof_lifetime_limit(&self) -> Option<u64> {
        None
    }
    fn launch_has_ongoing_hgn_authority(&self) -> bool {
        false
    }
    fn launch_proof_action_limit(&self) -> Option<usize> {
        None
    }

    fn launch_reference_context(&self) -> Option<LaunchReferenceContext> {
        None
    }
    fn set_launch_references(
        &mut self,
        _references: CanonicalLaunchReferences,
    ) -> Result<(), String> {
        Err("this verifier does not accept launch reference checkpoints".into())
    }

    /// Classify only a closed, fresh asset/admin carrier namespace. Malformed
    /// carriers in that namespace must still classify here and fail verification.
    fn is_asset_native_leaf(&self, _leaf: &[u8]) -> bool {
        false
    }

    /// The returned snapshot contains registry/accounting, recovery controls
    /// and recovery-output indices, and canonical admin action IDs. This shared
    /// store owns the note tree and global nullifiers. `next_position` is the
    /// actual append cursor; `is_spent` includes the replacement suffix already
    /// staged in this plan and excludes only nullifiers detached by this reorg.
    fn verify_exact_asset_leaf(
        &mut self,
        _block: Poseidon2V8BlockContext,
        _leaf_index: usize,
        _exact_native_leaf: &[u8],
        _current_asset: &[u8],
        _parent_note_root: Poseidon2V8NoteRoot,
        _next_position: u32,
        _is_spent: &mut dyn FnMut([u64; 7]) -> Result<bool, String>,
    ) -> Result<(Poseidon2V8PublicTransition, Vec<u8>), String> {
        Err("asset verification is not supported by this source verifier".into())
    }

    /// Source-owned canonical codec validates and advances height on every
    /// block, including reward-only blocks. No arbitrary root setter exists.
    fn advance_asset_state(
        &mut self,
        _block: Poseidon2V8BlockContext,
        _current_asset: &[u8],
    ) -> Result<Vec<u8>, String> {
        Err("asset state advancement is not supported by this source verifier".into())
    }

    fn verify_exact_v8_leaf(
        &mut self,
        block: Poseidon2V8BlockContext,
        leaf_index: usize,
        exact_native_leaf: &[u8],
    ) -> Result<Poseidon2V8PublicTransition, String>;

    /// Optional read-only verification of one already bounded window. Results
    /// must have the same cardinality/order as leaves and bind the supplied
    /// context plus absolute leaf index. Stateful verifiers retain their exact
    /// original call/early-stop behavior through the default sequential path.
    fn verify_exact_v8_leaf_window(
        &mut self,
        _block: Poseidon2V8BlockContext,
        _first_leaf_index: usize,
        _exact_native_leaves: &[&[u8]],
    ) -> Option<Vec<Result<Poseidon2V8PublicTransition, String>>> {
        None
    }

    /// Recording wrappers observe a successful window result only when state
    /// consumes that leaf in canonical order, at the same point as the single
    /// leaf path. This cannot authorize a leaf or mutate durable state.
    fn record_window_verified_transition(&mut self, _transition: Poseidon2V8PublicTransition) {}
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Poseidon2V8UnverifiedBlock<'a> {
    context: Poseidon2V8BlockContext,
    exact_native_leaves: &'a [&'a [u8]],
    /// Exact, already-validated public issuance. The commitment remains pending
    /// until its consensus maturity admission block; it is not a same-block leaf.
    trailing_coinbase_commitment: Option<Poseidon2V8Commitment>,
    trailing_funding_commitment: Option<Poseidon2V8Commitment>,
}

impl<'a> Poseidon2V8UnverifiedBlock<'a> {
    pub(crate) fn new(
        context: Poseidon2V8BlockContext,
        exact_native_leaves: &'a [&'a [u8]],
    ) -> Result<Self, Poseidon2V8StateError> {
        validate_leaf_batch(exact_native_leaves)?;
        Ok(Self {
            context,
            exact_native_leaves,
            trailing_coinbase_commitment: None,
            trailing_funding_commitment: None,
        })
    }

    pub(crate) fn new_with_trailing_coinbase(
        context: Poseidon2V8BlockContext,
        exact_native_leaves: &'a [&'a [u8]],
        trailing_coinbase_commitment: Option<Poseidon2V8Commitment>,
    ) -> Result<Self, Poseidon2V8StateError> {
        validate_block_proof_authority_action_count(
            exact_native_leaves.len(),
            trailing_coinbase_commitment.is_some(),
        )?;
        validate_leaf_batch(exact_native_leaves)?;
        Ok(Self {
            context,
            exact_native_leaves,
            trailing_coinbase_commitment,
            trailing_funding_commitment: None,
        })
    }

    pub(crate) fn new_with_trailing_rewards(
        context: Poseidon2V8BlockContext,
        exact_native_leaves: &'a [&'a [u8]],
        commitments: [Option<Poseidon2V8Commitment>; 2],
    ) -> Result<Self, Poseidon2V8StateError> {
        if commitments[1].is_some()
            && (commitments[0].is_none() || commitments[0] == commitments[1])
        {
            return Err(Poseidon2V8StateError::CorruptNoteTreeState);
        }
        let mut block =
            Self::new_with_trailing_coinbase(context, exact_native_leaves, commitments[0])?;
        // The second note belongs to the same final reward action and is not a
        // second action or proof lifetime charge.
        block.trailing_funding_commitment = commitments[1];
        Ok(block)
    }

    pub(crate) const fn context(self) -> Poseidon2V8BlockContext {
        self.context
    }

    pub(crate) const fn exact_native_leaves(self) -> &'a [&'a [u8]] {
        self.exact_native_leaves
    }

    pub(crate) const fn trailing_coinbase_commitment(self) -> Option<Poseidon2V8Commitment> {
        self.trailing_coinbase_commitment
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Poseidon2V8StateStore {
    tree: sled::Tree,
}

/// Fully verified, read-only canonical mutation plan.  The proof engine and
/// every seven-limb state check run before this value exists.  Native block
/// commit code can then apply these exact rows to the V8 tree inside the same
/// sled transaction as the block pointer and legacy state, avoiding a second
/// independently durable state transition.
#[derive(Clone, Debug)]
pub(crate) struct Poseidon2V8CanonicalPlan {
    initial_tip: Poseidon2V8Checkpoint,
    attach_parent: Poseidon2V8Checkpoint,
    initial_tip_bytes: Vec<u8>,
    initial_note_bytes: Vec<u8>,
    initial_asset_bytes: Option<Vec<u8>>,
    final_asset_bytes: Option<Vec<u8>>,
    initial_proof_lifetime: SmallwoodV8ProofLifetimeCount,
    initial_proof_lifetime_bytes: [u8; 8],
    detached_rows: Vec<Poseidon2V8CanonicalRow>,
    attached_rows: Vec<Poseidon2V8CanonicalRow>,
    final_tip: Poseidon2V8Checkpoint,
    final_tip_bytes: Vec<u8>,
    final_note: Poseidon2V8NoteTreeState,
    final_note_bytes: Vec<u8>,
    final_proof_lifetime: SmallwoodV8ProofLifetimeCount,
    final_proof_lifetime_bytes: [u8; 8],
}

impl Poseidon2V8CanonicalPlan {
    pub(crate) const fn attach_parent(&self) -> Poseidon2V8Checkpoint {
        self.attach_parent
    }

    pub(crate) const fn final_tip(&self) -> Poseidon2V8Checkpoint {
        self.final_tip
    }
}

#[derive(Clone, Debug)]
struct Poseidon2V8CanonicalRow {
    record_key: Vec<u8>,
    height_key: Vec<u8>,
    block_hash: [u8; 32],
    record: Vec<u8>,
    nullifiers: Vec<Poseidon2V8Nullifier>,
    asset_snapshot: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Poseidon2V8BlockRecord {
    before: Poseidon2V8Checkpoint,
    after: Poseidon2V8Checkpoint,
    before_proof_lifetime: SmallwoodV8ProofLifetimeCount,
    after_proof_lifetime: SmallwoodV8ProofLifetimeCount,
    after_note_state: Poseidon2V8NoteTreeState,
    // Stored in a separate typed row; excluded from historical record encoding.
    after_asset_state: Option<Vec<u8>>,
    introduced_nullifiers: Vec<Poseidon2V8Nullifier>,
    leaf_count: u32,
    leaf_total_bytes: u64,
    leaf_sequence_digest: [u8; 64],
    record_digest: [u8; 64],
}

impl Poseidon2V8BlockRecord {
    fn encode(&self) -> Result<Vec<u8>, Poseidon2V8StateError> {
        validate_record_proof_lifetime(self.before_proof_lifetime, self.after_proof_lifetime, self.leaf_count)?;
        let note_state = self.after_note_state.encode()?;
        let note_len = u32::try_from(note_state.len())
            .map_err(|_| Poseidon2V8StateError::CorruptRecordBounds)?;
        let nullifier_count = u32::try_from(self.introduced_nullifiers.len())
            .map_err(|_| Poseidon2V8StateError::CorruptRecordBounds)?;
        let maximum_nullifiers = usize::try_from(self.leaf_count)
            .unwrap_or(usize::MAX)
            .saturating_mul(2);
        if self.introduced_nullifiers.len() > maximum_nullifiers {
            return Err(Poseidon2V8StateError::CorruptRecordBounds);
        }
        let capacity = BLOCK_RECORD_CODEC_BYTES
            .checked_add(8)
            .and_then(|bytes| bytes.checked_add(note_state.len()))
            .and_then(|bytes| {
                bytes.checked_add(self.introduced_nullifiers.len() * POSEIDON2_V8_DIGEST_BYTES)
            })
            .ok_or(Poseidon2V8StateError::CorruptRecordBounds)?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(capacity)
            .map_err(|_| Poseidon2V8StateError::AllocationFailed(capacity))?;
        encoded.extend_from_slice(RECORD_MAGIC);
        encoded.extend_from_slice(&self.before.height.to_le_bytes());
        encoded.extend_from_slice(&self.before.block_hash);
        encoded.extend_from_slice(&self.after.height.to_le_bytes());
        encoded.extend_from_slice(&self.after.block_hash);
        encoded.extend_from_slice(&self.before.root.encode());
        encoded.extend_from_slice(&self.after.root.encode());
        encoded.extend_from_slice(&self.before_proof_lifetime.encode());
        encoded.extend_from_slice(&self.after_proof_lifetime.encode());
        encoded.extend_from_slice(&self.leaf_count.to_le_bytes());
        encoded.extend_from_slice(&self.leaf_total_bytes.to_le_bytes());
        encoded.extend_from_slice(&self.leaf_sequence_digest);
        encoded.extend_from_slice(&note_len.to_le_bytes());
        encoded.extend_from_slice(&note_state);
        encoded.extend_from_slice(&nullifier_count.to_le_bytes());
        for nullifier in &self.introduced_nullifiers {
            encoded.extend_from_slice(&nullifier.encode());
        }
        encoded.extend_from_slice(&self.record_digest);
        Ok(encoded)
    }

    fn decode_exact(bytes: &[u8]) -> Result<Self, Poseidon2V8StateError> {
        if bytes.len() < BLOCK_RECORD_CODEC_BYTES + 8 + POSEIDON2_V8_DIGEST_BYTES {
            return Err(Poseidon2V8StateError::CodecLength {
                label: "V8 stablecoin block record",
                expected: BLOCK_RECORD_CODEC_BYTES + 8 + POSEIDON2_V8_DIGEST_BYTES,
                observed: bytes.len(),
            });
        }
        let mut cursor = bytes;
        expect_magic(&mut cursor, RECORD_MAGIC, "V8 stablecoin block record")?;
        let before_height = take_u64(&mut cursor, "V8 record parent height")?;
        let before_hash = take_array::<32>(&mut cursor, "V8 record parent hash")?;
        let after_height = take_u64(&mut cursor, "V8 record block height")?;
        validate_relation_height(before_height)?;
        validate_relation_height(after_height)?;
        let after_hash = take_array::<32>(&mut cursor, "V8 record block hash")?;
        let before_root = Poseidon2V8Root::decode_exact(take(
            &mut cursor,
            POSEIDON2_V8_ROOT_CODEC_BYTES,
            "V8 record before root",
        )?)?;
        let after_root = Poseidon2V8Root::decode_exact(take(
            &mut cursor,
            POSEIDON2_V8_ROOT_CODEC_BYTES,
            "V8 record after root",
        )?)?;
        let before_proof_lifetime = SmallwoodV8ProofLifetimeCount::decode_exact(take(
            &mut cursor,
            8,
            "V8 record before proof lifetime",
        )?)?;
        let after_proof_lifetime = SmallwoodV8ProofLifetimeCount::decode_exact(take(
            &mut cursor,
            8,
            "V8 record after proof lifetime",
        )?)?;
        let leaf_count = take_u32(&mut cursor, "V8 record leaf count")?;
        let leaf_total_bytes = take_u64(&mut cursor, "V8 record leaf bytes")?;
        let leaf_sequence_digest = take_array::<64>(&mut cursor, "V8 record leaf digest")?;
        let note_len = usize::try_from(take_u32(&mut cursor, "V8 record note-state length")?)
            .map_err(|_| Poseidon2V8StateError::CorruptRecordBounds)?;
        let after_note_state = Poseidon2V8NoteTreeState::decode_exact(take(
            &mut cursor,
            note_len,
            "V8 record note-tree state",
        )?)?;
        after_note_state.validate_pending_at_height(after_height)?;
        let nullifier_count = usize::try_from(take_u32(&mut cursor, "V8 record nullifier count")?)
            .map_err(|_| Poseidon2V8StateError::CorruptRecordBounds)?;
        let maximum_nullifiers = usize::try_from(leaf_count)
            .unwrap_or(usize::MAX)
            .saturating_mul(2);
        if nullifier_count > maximum_nullifiers {
            return Err(Poseidon2V8StateError::CorruptRecordBounds);
        }
        let nullifier_bytes = nullifier_count
            .checked_mul(POSEIDON2_V8_DIGEST_BYTES)
            .ok_or(Poseidon2V8StateError::CorruptRecordBounds)?;
        if cursor.len() != nullifier_bytes + 64 {
            return Err(Poseidon2V8StateError::CodecLength {
                label: "V8 record nullifiers and digest",
                expected: nullifier_bytes + 64,
                observed: cursor.len(),
            });
        }
        let mut introduced_nullifiers = Vec::with_capacity(nullifier_count);
        for _ in 0..nullifier_count {
            introduced_nullifiers.push(Poseidon2V8Nullifier::decode_exact(take(
                &mut cursor,
                POSEIDON2_V8_DIGEST_BYTES,
                "V8 record nullifier",
            )?)?);
        }
        let record_digest = take_array::<64>(&mut cursor, "V8 record integrity digest")?;
        if !cursor.is_empty() {
            return Err(Poseidon2V8StateError::CodecTrailing(
                "V8 stablecoin block record",
            ));
        }
        let expected_height = before_height
            .checked_add(1)
            .ok_or(Poseidon2V8StateError::HeightOverflow)?;
        if after_height != expected_height {
            return Err(Poseidon2V8StateError::NonContiguousHeight {
                expected: expected_height,
                observed: after_height,
            });
        }
        if usize::try_from(leaf_count).unwrap_or(usize::MAX) > MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK
            || usize::try_from(leaf_total_bytes).unwrap_or(usize::MAX)
                > MAX_NATIVE_BLOCK_ACTION_BYTES
        {
            return Err(Poseidon2V8StateError::CorruptRecordBounds);
        }
        validate_record_proof_lifetime(before_proof_lifetime, after_proof_lifetime, leaf_count)?;
        let record = Self {
            before: Poseidon2V8Checkpoint::new(before_height, before_hash, before_root),
            after: Poseidon2V8Checkpoint::new(after_height, after_hash, after_root),
            before_proof_lifetime,
            after_proof_lifetime,
            after_note_state,
            after_asset_state: None,
            introduced_nullifiers,
            leaf_count,
            leaf_total_bytes,
            leaf_sequence_digest,
            record_digest,
        };
        if record.record_digest != block_record_digest(&record)? {
            return Err(Poseidon2V8StateError::CorruptRecordDigest);
        }
        Ok(record)
    }
}

impl Poseidon2V8StateStore {
    pub(crate) const fn tree(&self) -> &sled::Tree {
        &self.tree
    }

    /// Open or initialize the V8 state tree with the release-owned genesis
    /// checkpoint.  Reopening with any other genesis tuple fails closed.
    pub(crate) fn open(
        database: &sled::Db,
        genesis: Poseidon2V8Checkpoint,
        note_genesis_root: Poseidon2V8NoteRoot,
    ) -> Result<Self, Poseidon2V8StateError> {
        Self::open_with_assets(database, genesis, note_genesis_root, None)
    }

    /// Asset genesis bytes must come from the selected, validated network
    /// manifest's canonical registry codec. They are immutable identity input.
    pub(crate) fn open_with_assets(
        database: &sled::Db,
        genesis: Poseidon2V8Checkpoint,
        note_genesis_root: Poseidon2V8NoteRoot,
        asset_genesis: Option<&[u8]>,
    ) -> Result<Self, Poseidon2V8StateError> {
        if asset_genesis.is_some_and(|bytes| bytes.is_empty()) {
            return Err(Poseidon2V8StateError::ProofRejected(
                "empty asset genesis codec".into(),
            ));
        }
        if let Some(bytes) = asset_genesis {
            validate_asset_snapshot(bytes, genesis.height)?;
        }
        validate_relation_height(genesis.height)?;
        let empty_note_state = Poseidon2V8NoteTreeState::new_empty()?;
        let expected_note_genesis_root = empty_note_state.root();
        if note_genesis_root != expected_note_genesis_root {
            return Err(Poseidon2V8StateError::UnsupportedNoteGenesisRoot {
                expected: expected_note_genesis_root,
                observed: note_genesis_root,
            });
        }
        let tree = database.open_tree(POSEIDON2_V8_STATE_TREE_NAME)?;
        let expected_tip = genesis.encode();
        let expected_note_tip = empty_note_state.encode()?;
        let expected_proof_lifetime = SmallwoodV8ProofLifetimeCount::genesis().encode();
        let genesis_height_key = height_key(genesis.height);
        let outcome: Result<(), TransactionError<String>> = tree.transaction(|tree| {
            match tree.get(GENESIS_KEY)? {
                None => {
                    if tree.get(TIP_KEY)?.is_some()
                        || tree.get(NOTE_TIP_KEY)?.is_some()
                        || tree.get(PROOF_LIFETIME_TIP_KEY)?.is_some()
                        || tree.get(genesis_height_key.as_slice())?.is_some()
                    {
                        return Err(ConflictableTransactionError::Abort(
                            "partial V8 stablecoin genesis initialization".to_owned(),
                        ));
                    }
                    if tree.get(ASSET_GENESIS_KEY)?.is_some() || tree.get(ASSET_TIP_KEY)?.is_some()
                    {
                        return Err(ConflictableTransactionError::Abort(
                            "partial asset genesis initialization".into(),
                        ));
                    }
                    if let Some(bytes) = asset_genesis {
                        tree.insert(ASSET_GENESIS_KEY, bytes)?;
                        tree.insert(ASSET_TIP_KEY, bytes)?;
                    }
                    tree.insert(GENESIS_KEY, expected_tip.as_slice())?;
                    tree.insert(TIP_KEY, expected_tip.as_slice())?;
                    tree.insert(NOTE_TIP_KEY, expected_note_tip.as_slice())?;
                    tree.insert(PROOF_LIFETIME_TIP_KEY, expected_proof_lifetime.as_slice())?;
                    tree.insert(genesis_height_key.as_slice(), genesis.block_hash.as_slice())?;
                }
                Some(observed) if observed.as_ref() == expected_tip.as_slice() => {
                    let stored_asset_genesis = tree.get(ASSET_GENESIS_KEY)?;
                    if stored_asset_genesis.as_deref() != asset_genesis
                        || tree.get(ASSET_TIP_KEY)?.is_some() != asset_genesis.is_some()
                    {
                        return Err(ConflictableTransactionError::Abort(
                            "asset genesis identity mismatch".into(),
                        ));
                    }
                    if tree.get(TIP_KEY)?.is_none() {
                        return Err(ConflictableTransactionError::Abort(
                            "stored V8 stablecoin canonical tip is missing".to_owned(),
                        ));
                    }
                    if tree.get(NOTE_TIP_KEY)?.is_none() {
                        return Err(ConflictableTransactionError::Abort(
                            "stored V8 note-tree canonical tip is missing".to_owned(),
                        ));
                    }
                    if tree.get(PROOF_LIFETIME_TIP_KEY)?.is_none() {
                        return Err(ConflictableTransactionError::Abort(
                            "stored V8 proof lifetime canonical tip is missing".to_owned(),
                        ));
                    }
                    match tree.get(genesis_height_key.as_slice())? {
                        Some(mapped) if mapped.as_ref() == genesis.block_hash.as_slice() => {}
                        _ => {
                            return Err(ConflictableTransactionError::Abort(
                                "stored V8 stablecoin genesis height mapping mismatch".to_owned(),
                            ));
                        }
                    }
                }
                Some(_) => {
                    return Err(ConflictableTransactionError::Abort(
                        "stored V8 stablecoin genesis checkpoint mismatch".to_owned(),
                    ));
                }
            }
            Ok(())
        });
        map_transaction(outcome)?;
        flush_durable(&tree)?;
        let store = Self { tree };
        let tip = store.tip()?;
        let note_tip = store.note_tip()?;
        let proof_lifetime = store.proof_lifetime_count()?;
        let mapped_tip = store
            .tree
            .get(height_key(tip.height))?
            .ok_or(Poseidon2V8StateError::MissingHeightRecord(tip.height))?;
        if mapped_tip.as_ref() != tip.block_hash.as_slice() {
            return Err(Poseidon2V8StateError::CorruptRecordLink);
        }
        if tip != genesis {
            let record = store.load_record(tip.block_hash)?;
            if record.after != tip
                || record.after_note_state != note_tip
                || record.after_proof_lifetime != proof_lifetime
                || record.after_asset_state != store.asset_tip()?
            {
                return Err(Poseidon2V8StateError::CorruptRecordLink);
            }
        } else if note_tip != Poseidon2V8NoteTreeState::new_empty()?
            || proof_lifetime != SmallwoodV8ProofLifetimeCount::genesis()
            || store.asset_tip()?.as_deref() != asset_genesis
        {
            return Err(Poseidon2V8StateError::CorruptRecordLink);
        }
        Ok(store)
    }

    pub(crate) fn tip(&self) -> Result<Poseidon2V8Checkpoint, Poseidon2V8StateError> {
        let bytes = self
            .tree
            .get(TIP_KEY)?
            .ok_or(Poseidon2V8StateError::MissingTip)?;
        Poseidon2V8Checkpoint::decode_exact(bytes.as_ref())
    }

    pub(crate) fn note_tip(&self) -> Result<Poseidon2V8NoteTreeState, Poseidon2V8StateError> {
        let bytes = self
            .tree
            .get(NOTE_TIP_KEY)?
            .ok_or(Poseidon2V8StateError::MissingNoteTip)?;
        Poseidon2V8NoteTreeState::decode_exact(bytes.as_ref())
    }

    pub(crate) fn asset_tip(&self) -> Result<Option<Vec<u8>>, Poseidon2V8StateError> {
        let bytes = self.tree.get(ASSET_TIP_KEY)?.map(|bytes| bytes.to_vec());
        let genesis = self.tree.get(ASSET_GENESIS_KEY)?;
        match (bytes.as_deref(), genesis.as_deref()) {
            (None, None) => {}
            (Some(bytes), Some(genesis)) => {
                let chain = validate_asset_snapshot(bytes, self.tip()?.height)?;
                if chain != validate_asset_snapshot(genesis, self.genesis()?.height)? {
                    return Err(Poseidon2V8StateError::CorruptRecordLink);
                }
            }
            _ => return Err(Poseidon2V8StateError::CorruptRecordLink),
        }
        Ok(bytes)
    }

    fn asset_state_at_checkpoint(
        &self,
        checkpoint: Poseidon2V8Checkpoint,
    ) -> Result<Option<Vec<u8>>, Poseidon2V8StateError> {
        let enabled = self.tree.contains_key(ASSET_GENESIS_KEY)?;
        let key = if checkpoint == self.genesis()? {
            ASSET_GENESIS_KEY.to_vec()
        } else {
            asset_record_key(checkpoint.block_hash)
        };
        let bytes = self.tree.get(key)?.map(|bytes| bytes.to_vec());
        if bytes.is_some() != enabled {
            return Err(Poseidon2V8StateError::CorruptRecordLink);
        }
        if let Some(bytes) = bytes.as_deref() {
            let chain = validate_asset_snapshot(bytes, checkpoint.height)?;
            let genesis = self
                .tree
                .get(ASSET_GENESIS_KEY)?
                .ok_or(Poseidon2V8StateError::CorruptRecordLink)?;
            if chain != validate_asset_snapshot(genesis.as_ref(), self.genesis()?.height)? {
                return Err(Poseidon2V8StateError::CorruptRecordLink);
            }
        }
        Ok(bytes)
    }

    /// Resolve a retained reference only through digest-checked canonical ancestry.
    /// Caller must keep/recheck the selected canonical tip for a coherent RPC view.
    pub(crate) fn asset_reference_snapshot(
        &self, hash: [u8; 32],
    ) -> Result<(Poseidon2V8Checkpoint, Poseidon2V8NoteRoot, Vec<u8>), Poseidon2V8StateError> {
        let mut cursor = self.tip()?;
        for _ in 0..=super::launch_reference::LAUNCH_REFERENCE_WINDOW {
            if cursor.block_hash == hash {
                let assets = self.asset_state_at_checkpoint(cursor)?
                    .ok_or_else(|| Poseidon2V8StateError::ProofRejected("asset reference snapshot missing".into()))?;
                if cursor.height != 0 {
                    let record = self.load_record(cursor.block_hash)?;
                    if record.after != cursor || record.after_asset_state.as_deref() != Some(assets.as_slice()) {
                        return Err(Poseidon2V8StateError::CorruptRecordLink);
                    }
                }
                let note = self.note_state_at_checkpoint(cursor)?.root();
                return Ok((cursor, note, assets));
            }
            if cursor.height == 0 { break; }
            let record = self.load_record(cursor.block_hash)?;
            if record.after != cursor { return Err(Poseidon2V8StateError::CorruptRecordLink); }
            cursor = record.before;
        }
        Err(Poseidon2V8StateError::ProofRejected("asset reference is orphaned or outside the finite window".into()))
    }

    pub(crate) fn canonical_launch_references(
        &self, context: LaunchReferenceContext,
    ) -> Result<CanonicalLaunchReferences, Poseidon2V8StateError> {
        let tip = self.tip()?;
        let note = self.note_tip()?;
        let rows = self.collect_launch_checkpoints(context, tip, &note)?;
        CanonicalLaunchReferences::from_validated_chain(context, tip.block_hash, tip.height, rows.into())
            .map_err(Poseidon2V8StateError::ProofRejected)
    }

    pub(crate) fn proof_lifetime_count(
        &self,
    ) -> Result<SmallwoodV8ProofLifetimeCount, Poseidon2V8StateError> {
        let bytes = self
            .tree
            .get(PROOF_LIFETIME_TIP_KEY)?
            .ok_or(Poseidon2V8StateError::MissingProofLifetimeTip)?;
        Ok(SmallwoodV8ProofLifetimeCount::decode_exact(bytes.as_ref())?)
    }

    pub(crate) fn is_nullifier_spent(
        &self,
        nullifier: Poseidon2V8Nullifier,
    ) -> Result<bool, Poseidon2V8StateError> {
        Ok(self.tree.contains_key(nullifier_key(nullifier))?)
    }

    /// Shared canonical nullifier view for a prospective replacement suffix.
    /// An attached spend takes precedence even if that nullifier was detached.
    fn is_nullifier_spent_for_replay(
        &self,
        limbs: [u64; 7],
        detached: &BTreeSet<Poseidon2V8Nullifier>,
        attached: &BTreeSet<Poseidon2V8Nullifier>,
    ) -> Result<bool, String> {
        let nullifier = Poseidon2V8Nullifier::new(limbs).map_err(|error| error.to_string())?;
        if attached.contains(&nullifier) {
            return Ok(true);
        }
        if detached.contains(&nullifier) {
            return Ok(false);
        }
        self.is_nullifier_spent(nullifier).map_err(|error| error.to_string())
    }

    /// Compare every canonical V8 row byte-for-byte. Startup uses this only
    /// after rebuilding `verified` from genesis through the source-owned exact
    /// leaf verifier, so persisted checkpoints, note state, nullifiers, and
    /// record digests cannot act as a proof cache.
    pub(crate) fn exact_rows_equal(&self, verified: &Self) -> Result<bool, Poseidon2V8StateError> {
        let mut observed = self.tree.iter();
        let mut expected = verified.tree.iter();
        loop {
            match (observed.next(), expected.next()) {
                (None, None) => return Ok(true),
                (Some(observed), Some(expected)) => {
                    let (observed_key, observed_value) = observed?;
                    let (expected_key, expected_value) = expected?;
                    if observed_key != expected_key || observed_value != expected_value {
                        return Ok(false);
                    }
                }
                _ => return Ok(false),
            }
        }
    }

    /// Verify and atomically append one canonical block.  `exact_native_leaves`
    /// must contain every V8 leaf in canonical action order and no other leaf.
    pub(crate) fn apply_verified_block<V: Poseidon2V8ExactLeafVerifier + ?Sized>(
        &self,
        block: Poseidon2V8UnverifiedBlock<'_>,
        verifier: &mut V,
    ) -> Result<Poseidon2V8Checkpoint, Poseidon2V8StateError> {
        self.reorganize_verified(&[], &[block], verifier)
    }

    /// Disconnect exactly the current canonical tip and restore its persisted
    /// parent checkpoint.  Genesis has no block record and cannot be detached.
    pub(crate) fn disconnect_tip(
        &self,
        expected_tip_hash: [u8; 32],
    ) -> Result<Poseidon2V8Checkpoint, Poseidon2V8StateError> {
        let initial_tip = self.tip()?;
        let initial_note = self.note_tip()?;
        let initial_proof_lifetime = self.proof_lifetime_count()?;
        let (detached, ancestor, ancestor_note, ancestor_proof_lifetime, _) = self.plan_detach(
            initial_tip,
            initial_note.clone(),
            initial_proof_lifetime,
            &[expected_tip_hash],
        )?;
        let plan = Self::canonical_plan(
            initial_tip,
            ancestor,
            &initial_note,
            initial_proof_lifetime,
            self.asset_tip()?,
            self.asset_state_at_checkpoint(ancestor)?,
            &detached,
            &[],
            ancestor,
            &ancestor_note,
            ancestor_proof_lifetime,
        )?;
        self.apply_verified_canonical_plan(&plan)
    }

    /// Verify an entire replacement suffix before atomically swapping it into
    /// canonical storage.  `detach_tip_first` is ordered from the current tip
    /// backwards; `attach_parent_first` is ordered from the common ancestor
    /// forwards.  No root or height changes if any replacement proof rejects.
    pub(crate) fn reorganize_verified<V: Poseidon2V8ExactLeafVerifier + ?Sized>(
        &self,
        detach_tip_first: &[[u8; 32]],
        attach_parent_first: &[Poseidon2V8UnverifiedBlock<'_>],
        verifier: &mut V,
    ) -> Result<Poseidon2V8Checkpoint, Poseidon2V8StateError> {
        let plan =
            self.plan_verified_reorganization(detach_tip_first, attach_parent_first, verifier)?;
        self.apply_verified_canonical_plan(&plan)
    }

    /// Apply a fully verified immutable plan to this store. Callers that need
    /// additional checks over verifier-returned public transitions can build
    /// the plan, perform those checks, and only then enter this atomic write.
    pub(crate) fn apply_verified_canonical_plan(
        &self,
        plan: &Poseidon2V8CanonicalPlan,
    ) -> Result<Poseidon2V8Checkpoint, Poseidon2V8StateError> {
        if plan.detached_rows.is_empty() && plan.attached_rows.is_empty() {
            return Ok(plan.initial_tip);
        }
        let outcome: Result<(), TransactionError<String>> = self
            .tree
            .transaction(|tree| Self::apply_canonical_plan_in_transaction(tree, &plan));
        map_transaction(outcome)?;
        flush_durable(&self.tree)?;
        self.verify_canonical_plan_readback(&plan)
    }

    /// Sync and fresh-node replay use the same proof-verifying append path as
    /// ordinary block import, with one transaction for the supplied suffix.
    pub(crate) fn replay_verified_suffix<V: Poseidon2V8ExactLeafVerifier + ?Sized>(
        &self,
        blocks: &[Poseidon2V8UnverifiedBlock<'_>],
        verifier: &mut V,
    ) -> Result<Poseidon2V8Checkpoint, Poseidon2V8StateError> {
        self.reorganize_verified(&[], blocks, verifier)
    }

    /// Verify a candidate block against the durable typed tip without writing
    /// any row. Mempool, relay, and mining preflight use this path; canonical
    /// import must instead apply the returned plan in its main sled
    /// transaction.
    pub(crate) fn verify_uncommitted_block<V: Poseidon2V8ExactLeafVerifier + ?Sized>(
        &self,
        block: Poseidon2V8UnverifiedBlock<'_>,
        verifier: &mut V,
    ) -> Result<Poseidon2V8Checkpoint, Poseidon2V8StateError> {
        Ok(self
            .plan_verified_reorganization(&[], &[block], verifier)?
            .final_tip)
    }

    /// Construct an immutable V8 row plan only after the full replacement
    /// suffix and every exact proof have verified. No storage mutation occurs.
    pub(crate) fn plan_verified_reorganization<V: Poseidon2V8ExactLeafVerifier + ?Sized>(
        &self,
        detach_tip_first: &[[u8; 32]],
        attach_parent_first: &[Poseidon2V8UnverifiedBlock<'_>],
        verifier: &mut V,
    ) -> Result<Poseidon2V8CanonicalPlan, Poseidon2V8StateError> {
        let initial_tip = self.tip()?;
        let initial_note = self.note_tip()?;
        let initial_proof_lifetime = self.proof_lifetime_count()?;
        validate_proof_lifetime_authority(initial_proof_lifetime, verifier)?;
        let (detached, ancestor, ancestor_note, ancestor_proof_lifetime, detached_nullifiers) =
            self.plan_detach(
                initial_tip,
                initial_note.clone(),
                initial_proof_lifetime,
                detach_tip_first,
            )?;
        let (attached, final_tip, final_note, final_proof_lifetime, final_asset) = self
            .verify_attach(
                ancestor,
                ancestor_note,
                ancestor_proof_lifetime,
                self.asset_state_at_checkpoint(ancestor)?,
                &detached_nullifiers,
                attach_parent_first,
                verifier,
            )?;
        Self::canonical_plan(
            initial_tip,
            ancestor,
            &initial_note,
            initial_proof_lifetime,
            self.asset_tip()?,
            final_asset,
            &detached,
            &attached,
            final_tip,
            &final_note,
            final_proof_lifetime,
        )
    }

    /// Apply a previously verified row plan to a transactional view of the V8
    /// tree. This function performs only compare-and-swap style row checks and
    /// writes; it never invokes a parser, semantic checker, or proof engine.
    pub(crate) fn apply_canonical_plan_in_transaction(
        tree: &TransactionalTree,
        plan: &Poseidon2V8CanonicalPlan,
    ) -> ConflictableTransactionResult<(), String> {
        let observed_tip = tree.get(TIP_KEY)?.ok_or_else(|| {
            ConflictableTransactionError::Abort(
                "V8 stablecoin canonical tip disappeared".to_owned(),
            )
        })?;
        if observed_tip.as_ref() != plan.initial_tip_bytes.as_slice() {
            return ::core::result::Result::Err(ConflictableTransactionError::Abort(
                "V8 stablecoin canonical tip changed during verification".to_owned(),
            ));
        }
        let observed_note = tree.get(NOTE_TIP_KEY)?.ok_or_else(|| {
            ConflictableTransactionError::Abort("V8 note-tree canonical tip disappeared".to_owned())
        })?;
        if observed_note.as_ref() != plan.initial_note_bytes.as_slice() {
            return ::core::result::Result::Err(ConflictableTransactionError::Abort(
                "V8 note-tree canonical tip changed during verification".to_owned(),
            ));
        }
        let observed_proof_lifetime = tree.get(PROOF_LIFETIME_TIP_KEY)?.ok_or_else(|| {
            ConflictableTransactionError::Abort(
                "V8 proof lifetime canonical tip disappeared".to_owned(),
            )
        })?;
        if observed_proof_lifetime.as_ref() != plan.initial_proof_lifetime_bytes.as_slice() {
            return ::core::result::Result::Err(ConflictableTransactionError::Abort(
                "V8 proof lifetime canonical tip changed during verification".to_owned(),
            ));
        }

        if tree.get(ASSET_TIP_KEY)?.as_deref() != plan.initial_asset_bytes.as_deref() {
            return Err(ConflictableTransactionError::Abort(
                "asset state changed during verification".into(),
            ));
        }

        for row in &plan.detached_rows {
            let observed_record = tree.get(row.record_key.as_slice())?.ok_or_else(|| {
                ConflictableTransactionError::Abort(
                    "V8 stablecoin detached block record disappeared".to_owned(),
                )
            })?;
            if observed_record.as_ref() != row.record.as_slice() {
                return ::core::result::Result::Err(ConflictableTransactionError::Abort(
                    "V8 stablecoin detached block record changed".to_owned(),
                ));
            }
            let observed_height = tree.get(row.height_key.as_slice())?.ok_or_else(|| {
                ConflictableTransactionError::Abort(
                    "V8 stablecoin detached height row disappeared".to_owned(),
                )
            })?;
            if observed_height.as_ref() != row.block_hash.as_slice() {
                return ::core::result::Result::Err(ConflictableTransactionError::Abort(
                    "V8 stablecoin detached height row changed".to_owned(),
                ));
            }
            let asset_key = asset_record_key(row.block_hash);
            if tree.get(asset_key.as_slice())?.as_deref() != row.asset_snapshot.as_deref() {
                return Err(ConflictableTransactionError::Abort(
                    "detached asset snapshot changed".into(),
                ));
            }
            if row.asset_snapshot.is_some() {
                tree.remove(asset_key)?;
            }
            tree.remove(row.record_key.as_slice())?;
            tree.remove(row.height_key.as_slice())?;
            for nullifier in &row.nullifiers {
                let key = nullifier_key(*nullifier);
                let owner = tree.get(key.as_slice())?.ok_or_else(|| {
                    ConflictableTransactionError::Abort(
                        "V8 detached nullifier row disappeared".to_owned(),
                    )
                })?;
                if owner.as_ref() != row.block_hash.as_slice() {
                    return ::core::result::Result::Err(ConflictableTransactionError::Abort(
                        "V8 detached nullifier owner changed".to_owned(),
                    ));
                }
                tree.remove(key)?;
            }
        }

        for row in &plan.attached_rows {
            if tree.get(row.record_key.as_slice())?.is_some() {
                return ::core::result::Result::Err(ConflictableTransactionError::Abort(
                    "V8 stablecoin block was already applied".to_owned(),
                ));
            }
            if tree.get(row.height_key.as_slice())?.is_some() {
                return ::core::result::Result::Err(ConflictableTransactionError::Abort(
                    "V8 stablecoin height already has a canonical block".to_owned(),
                ));
            }
            let asset_key = asset_record_key(row.block_hash);
            if tree.get(asset_key.as_slice())?.is_some() {
                return Err(ConflictableTransactionError::Abort(
                    "asset block snapshot already exists".into(),
                ));
            }
            if let Some(bytes) = &row.asset_snapshot {
                tree.insert(asset_key, bytes.as_slice())?;
            }
            tree.insert(row.record_key.as_slice(), row.record.as_slice())?;
            tree.insert(row.height_key.as_slice(), row.block_hash.as_slice())?;
            for nullifier in &row.nullifiers {
                let key = nullifier_key(*nullifier);
                if tree.get(key.as_slice())?.is_some() {
                    return ::core::result::Result::Err(ConflictableTransactionError::Abort(
                        "V8 attached nullifier is already spent".to_owned(),
                    ));
                }
                tree.insert(key, row.block_hash.as_slice())?;
            }
        }
        if let Some(bytes) = &plan.final_asset_bytes {
            tree.insert(ASSET_TIP_KEY, bytes.as_slice())?;
        }
        tree.insert(TIP_KEY, plan.final_tip_bytes.as_slice())?;
        tree.insert(NOTE_TIP_KEY, plan.final_note_bytes.as_slice())?;
        tree.insert(
            PROOF_LIFETIME_TIP_KEY,
            plan.final_proof_lifetime_bytes.as_slice(),
        )?;
        ::core::result::Result::Ok(())
    }

    /// Confirm that a shared canonical transaction published exactly the V8
    /// tip and note-tree state named by its verified plan.
    pub(crate) fn verify_canonical_plan_readback(
        &self,
        plan: &Poseidon2V8CanonicalPlan,
    ) -> Result<Poseidon2V8Checkpoint, Poseidon2V8StateError> {
        let observed = self.tip()?;
        let observed_note = self.note_tip()?;
        let observed_proof_lifetime = self.proof_lifetime_count()?;
        if observed != plan.final_tip
            || observed_note != plan.final_note
            || observed_proof_lifetime != plan.final_proof_lifetime
            || self.asset_tip()? != plan.final_asset_bytes
        {
            return Err(Poseidon2V8StateError::StorageConflict(
                "V8 stablecoin tip readback mismatch after shared canonical commit".to_owned(),
            ));
        }
        Ok(observed)
    }

    fn canonical_plan(
        initial_tip: Poseidon2V8Checkpoint,
        attach_parent: Poseidon2V8Checkpoint,
        initial_note: &Poseidon2V8NoteTreeState,
        initial_proof_lifetime: SmallwoodV8ProofLifetimeCount,
        initial_asset_bytes: Option<Vec<u8>>,
        final_asset_bytes: Option<Vec<u8>>,
        detached: &[Poseidon2V8BlockRecord],
        attached: &[Poseidon2V8BlockRecord],
        final_tip: Poseidon2V8Checkpoint,
        final_note: &Poseidon2V8NoteTreeState,
        final_proof_lifetime: SmallwoodV8ProofLifetimeCount,
    ) -> Result<Poseidon2V8CanonicalPlan, Poseidon2V8StateError> {
        if initial_asset_bytes.is_some() != final_asset_bytes.is_some() {
            return Err(Poseidon2V8StateError::CorruptRecordLink);
        }
        let rows = |records: &[Poseidon2V8BlockRecord]| {
            records
                .iter()
                .map(|record| {
                    Ok(Poseidon2V8CanonicalRow {
                        record_key: record_key(record.after.block_hash),
                        height_key: height_key(record.after.height),
                        block_hash: record.after.block_hash,
                        record: record.encode()?,
                        nullifiers: record.introduced_nullifiers.clone(),
                        asset_snapshot: record.after_asset_state.clone(),
                    })
                })
                .collect::<Result<Vec<_>, Poseidon2V8StateError>>()
        };
        Ok(Poseidon2V8CanonicalPlan {
            initial_tip,
            attach_parent,
            initial_tip_bytes: initial_tip.encode().to_vec(),
            initial_note_bytes: initial_note.encode()?,
            initial_asset_bytes,
            final_asset_bytes,
            initial_proof_lifetime,
            initial_proof_lifetime_bytes: initial_proof_lifetime.encode(),
            detached_rows: rows(detached)?,
            attached_rows: rows(attached)?,
            final_tip,
            final_tip_bytes: final_tip.encode().to_vec(),
            final_note: final_note.clone(),
            final_note_bytes: final_note.encode()?,
            final_proof_lifetime,
            final_proof_lifetime_bytes: final_proof_lifetime.encode(),
        })
    }

    fn plan_detach(
        &self,
        initial_tip: Poseidon2V8Checkpoint,
        initial_note: Poseidon2V8NoteTreeState,
        initial_proof_lifetime: SmallwoodV8ProofLifetimeCount,
        detach_tip_first: &[[u8; 32]],
    ) -> Result<
        (
            Vec<Poseidon2V8BlockRecord>,
            Poseidon2V8Checkpoint,
            Poseidon2V8NoteTreeState,
            SmallwoodV8ProofLifetimeCount,
            BTreeSet<Poseidon2V8Nullifier>,
        ),
        Poseidon2V8StateError,
    > {
        let mut cursor = initial_tip;
        let mut note_cursor = initial_note;
        let mut proof_lifetime_cursor = initial_proof_lifetime;
        let mut asset_cursor = self.asset_tip()?;
        let mut records = Vec::with_capacity(detach_tip_first.len());
        let mut detached_nullifiers = BTreeSet::new();
        for expected_hash in detach_tip_first {
            if cursor.block_hash != *expected_hash {
                return Err(Poseidon2V8StateError::DisconnectTipMismatch {
                    expected: *expected_hash,
                    observed: cursor.block_hash,
                });
            }
            let record = self.load_record(*expected_hash)?;
            if record.after != cursor
                || record.after_note_state != note_cursor
                || record.after_proof_lifetime != proof_lifetime_cursor
                || record.after_asset_state != asset_cursor
            {
                return Err(Poseidon2V8StateError::CorruptRecordLink);
            }
            for nullifier in &record.introduced_nullifiers {
                if !detached_nullifiers.insert(*nullifier) {
                    return Err(Poseidon2V8StateError::CorruptRecordLink);
                }
            }
            cursor = record.before;
            proof_lifetime_cursor = record.before_proof_lifetime;
            note_cursor = self.note_state_at_checkpoint(cursor)?;
            asset_cursor = self.asset_state_at_checkpoint(cursor)?;
            records.push(record);
        }
        Ok((
            records,
            cursor,
            note_cursor,
            proof_lifetime_cursor,
            detached_nullifiers,
        ))
    }

    fn verify_attach<V: Poseidon2V8ExactLeafVerifier + ?Sized>(
        &self,
        ancestor: Poseidon2V8Checkpoint,
        mut note_state: Poseidon2V8NoteTreeState,
        mut proof_lifetime: SmallwoodV8ProofLifetimeCount,
        mut asset_state: Option<Vec<u8>>,
        detached_nullifiers: &BTreeSet<Poseidon2V8Nullifier>,
        blocks: &[Poseidon2V8UnverifiedBlock<'_>],
        verifier: &mut V,
    ) -> Result<
        (
            Vec<Poseidon2V8BlockRecord>,
            Poseidon2V8Checkpoint,
            Poseidon2V8NoteTreeState,
            SmallwoodV8ProofLifetimeCount,
            Option<Vec<u8>>,
        ),
        Poseidon2V8StateError,
    > {
        note_state.validate_pending_at_height(ancestor.height)?;
        let mut cursor = ancestor;
        let mut records = Vec::with_capacity(blocks.len());
        let mut block_hashes = BTreeSet::new();
        let mut heights = BTreeSet::new();
        let mut attached_nullifiers = BTreeSet::new();
        let launch_context =
            if verifier.native_leaf_profile() == Poseidon2V8NativeLeafProfile::LaunchMixed {
                Some(verifier.launch_reference_context().ok_or_else(|| {
                    Poseidon2V8StateError::ProofRejected(
                        "launch verifier lacks immutable reference context".into(),
                    )
                })?)
            } else {
                None
            };
        if let Some(context) = launch_context {
            let genesis = self.genesis()?;
            context
                .require_genesis(genesis.block_hash, genesis.root)
                .map_err(Poseidon2V8StateError::ProofRejected)?;
        }
        // Empty/reward-only canonical replay is valid before activation and
        // after retirement. Seed only snapshots that can serve a future proof;
        // actual proof blocks below still pass the exact finite inclusion gate.
        let mut launch_checkpoints = if let Some(context) =
            launch_context.filter(|context| context.permits_launch_after_parent(ancestor.height))
        {
            self.collect_launch_checkpoints(context, ancestor, &note_state)?
        } else {
            VecDeque::new()
        };
        for block in blocks {
            validate_leaf_batch_for_profile(
                block.exact_native_leaves,
                Some(verifier.native_leaf_profile()),
            )?;
            let mut proof_units = 0usize;
            let mut recovery_actions = 0usize;
            for leaf in block.exact_native_leaves {
                if leaf.starts_with(&transaction_circuit::asset_recovery_wire_v1::MAGIC) {
                    recovery_actions += 1;
                    if recovery_actions > 1 {
                        return Err(Poseidon2V8StateError::ProofRejected(
                            "at most one recovery action per block".into(),
                        ));
                    }
                }
                let expected = if transaction_circuit::asset_recovery_wire_v1::decode_spend_ref(leaf).is_ok() {
                    transaction_circuit::asset_recovery_wire_v1::PROOF_UNITS
                } else { 1 };
                let observed = verifier.exact_leaf_proof_units(leaf)
                    .map_err(Poseidon2V8StateError::ProofRejected)?;
                if observed != expected {
                    return Err(Poseidon2V8StateError::ProofRejected(
                        "proof-unit cost differs from exact native leaf grammar".into(),
                    ));
                }
                proof_units = proof_units.checked_add(observed)
                    .ok_or(Poseidon2V8StateError::TooManyLeaves)?;
            }
            validate_block_proof_authority_action_count(
                proof_units,
                block.trailing_coinbase_commitment.is_some(),
            )?;
            let ongoing_hgn = validate_proof_lifetime_authority(proof_lifetime, verifier)?;
            let next_proof_lifetime = if ongoing_hgn {
                proof_lifetime.checked_accept_audit_block(proof_units)?
            } else {
                proof_lifetime.checked_accept_block(proof_units)?
            };
            if verifier.native_leaf_profile() == Poseidon2V8NativeLeafProfile::LaunchMixed {
                let action_limit = verifier
                    .launch_proof_action_limit()
                    .filter(|limit| *limit > 0 && *limit <= 512)
                    .ok_or_else(|| {
                        Poseidon2V8StateError::ProofRejected(
                            "launch verifier lacks a source action budget".into(),
                        )
                    })?;
                let actions = proof_units
                    .checked_add(usize::from(block.trailing_coinbase_commitment.is_some()))
                    .ok_or(Poseidon2V8StateError::TooManyLeaves)?;
                if actions > action_limit || verifier.launch_proof_lifetime_limit()
                    .is_some_and(|limit| next_proof_lifetime.get() > limit)
                {
                    return Err(Poseidon2V8StateError::ProofRejected(
                        "launch source action/lifetime budget exceeded".into(),
                    ));
                }
            }
            let context = block.context;
            if context.parent_height != cursor.height || context.parent_hash != cursor.block_hash {
                return Err(Poseidon2V8StateError::ParentCheckpointMismatch {
                    expected_height: cursor.height,
                    observed_height: context.parent_height,
                    expected_hash: cursor.block_hash,
                    observed_hash: context.parent_hash,
                });
            }
            let expected_height = cursor
                .height
                .checked_add(1)
                .ok_or(Poseidon2V8StateError::HeightOverflow)?;
            if context.height != expected_height {
                return Err(Poseidon2V8StateError::NonContiguousHeight {
                    expected: expected_height,
                    observed: context.height,
                });
            }
            if !block_hashes.insert(context.block_hash) {
                return Err(Poseidon2V8StateError::DuplicateAttachBlock(
                    context.block_hash,
                ));
            }
            if !heights.insert(context.height) {
                return Err(Poseidon2V8StateError::DuplicateAttachHeight(context.height));
            }

            if let Some(reference_context) = launch_context {
                if verifier.native_leaf_profile() != Poseidon2V8NativeLeafProfile::LaunchMixed
                    || verifier.launch_reference_context() != Some(reference_context)
                {
                    return Err(Poseidon2V8StateError::ProofRejected(
                        "launch verifier reference identity changed within validation".into(),
                    ));
                }
                if !block.exact_native_leaves.is_empty() {
                    let references = CanonicalLaunchReferences::from_validated_chain(
                        reference_context,
                        context.parent_hash,
                        context.parent_height,
                        launch_checkpoints.iter().copied().collect(),
                    )
                    .map_err(Poseidon2V8StateError::ProofRejected)?;
                    verifier
                        .set_launch_references(references)
                        .map_err(Poseidon2V8StateError::ProofRejected)?;
                }
            }
            let before = cursor;
            // Every membership proof in this block must anchor in history
            // already canonical at the parent. Outputs appended below may
            // become anchors only after this block is mined and synced; they
            // cannot be spent by a later action in the same block.
            let pre_block_note_roots = note_state
                .root_history
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            let inclusion_parent_note_root = note_state.root();
            let mut asset_action_count = 0usize;
            let mut asset_spend_count = 0usize;
            let mut current_root = cursor.root;
            let mut block_nullifiers = Vec::new();
            for (window_index, leaves) in block
                .exact_native_leaves
                .chunks(POSEIDON2_V8_PROOF_VERIFICATION_WINDOW)
                .enumerate()
            {
                let first_leaf_index = window_index * POSEIDON2_V8_PROOF_VERIFICATION_WINDOW;
                // Asset authorization depends on the preceding canonical registry
                // snapshot. Never speculate its state in a proof worker window.
                let prepared = if leaves
                    .iter()
                    .any(|leaf| verifier.is_asset_native_leaf(leaf))
                {
                    None
                } else {
                    verifier.verify_exact_v8_leaf_window(context, first_leaf_index, leaves)
                };
                if prepared
                    .as_ref()
                    .is_some_and(|results| results.len() != leaves.len())
                {
                    return Err(Poseidon2V8StateError::ProofRejected(
                        "V8 verifier returned a mismatched proof window".to_owned(),
                    ));
                }
                let mut prepared = prepared.map(Vec::into_iter);
                for (offset, leaf) in leaves.iter().copied().enumerate() {
                    let leaf_index = first_leaf_index + offset;
                    let is_asset = verifier.is_asset_native_leaf(leaf);
                    let public = if is_asset {
                        asset_action_count += 1;
                        if asset_action_count > 1 {
                            return Err(Poseidon2V8StateError::ProofRejected(
                                "at most one asset action per block".into(),
                            ));
                        }
                        let current = asset_state.as_deref().ok_or_else(|| {
                            Poseidon2V8StateError::ProofRejected(
                                "asset leaf on a network without asset genesis".into(),
                            )
                        })?;
                        let next_position = u32::try_from(note_state.leaf_count()).map_err(|_| {
                            Poseidon2V8StateError::ProofRejected(
                                "asset append cursor exceeds the depth-32 position domain".into(),
                            )
                        })?;
                        let mut is_spent = |limbs| {
                            self.is_nullifier_spent_for_replay(
                                limbs,
                                detached_nullifiers,
                                &attached_nullifiers,
                            )
                        };
                        let (public, next) = verifier
                            .verify_exact_asset_leaf(
                                context,
                                leaf_index,
                                leaf,
                                current,
                                inclusion_parent_note_root,
                                next_position,
                                &mut is_spent,
                            )
                            .map_err(Poseidon2V8StateError::ProofRejected)?;
                        if validate_asset_snapshot(&next, context.parent_height)?
                            != validate_asset_snapshot(current, context.parent_height)?
                        {
                            return Err(Poseidon2V8StateError::CorruptRecordLink);
                        }
                        let all_outputs = public.all_commitments();
                        let is_spend = public.nullifiers.iter().all(Option::is_some)
                            && all_outputs.iter().all(Option::is_some);
                        let is_admin = public.nullifiers.iter().all(Option::is_none)
                            && all_outputs.iter().all(Option::is_none);
                        if !is_spend && !is_admin {
                            return Err(Poseidon2V8StateError::ProofRejected(
                                "asset effect must carry exactly two nullifiers and three outputs, or no pool effect".into(),
                            ));
                        }
                        if is_spend {
                            asset_spend_count += 1;
                            if asset_spend_count > 1 {
                                return Err(Poseidon2V8StateError::ProofRejected(
                                    "at most one asset spend per block".into(),
                                ));
                            }
                        }
                        if public.before_root != current_root
                            || public.after_root != current_root
                            || public.stablecoin_effect != Poseidon2V8StablecoinEffect::DisabledNoWrite
                        {
                            return Err(Poseidon2V8StateError::ProofRejected("asset transition changes native static state".into()));
                        }
                        if launch_context.is_some() {
                            let checked = public.checked_launch_reference.ok_or_else(||
                                Poseidon2V8StateError::ProofRejected("asset proof lacks authenticated reference receipt".into()))?;
                            let expected_route = if is_spend { LaunchReferenceRoute::AssetSpend } else { LaunchReferenceRoute::AssetAdmin };
                            if checked.route() != expected_route
                                || checked.asset_registry_root() != asset_registry_root(Some(current))?
                                || checked.asset_registry_root().is_none()
                            {
                                return Err(Poseidon2V8StateError::ProofRejected("asset receipt differs from CURRENT registry or action role".into()));
                            }
                        } else if public.parent_height != context.parent_height
                            || public.note_anchor != inclusion_parent_note_root
                            || public.checked_launch_reference.is_some()
                            || public.application_parent_hint.is_some()
                        {
                            return Err(Poseidon2V8StateError::ProofRejected("historical asset fixture context mismatch".into()));
                        }
                        asset_state = Some(next);
                        public
                    } else if let Some(results) = prepared.as_mut() {
                        let public = results
                            .next()
                            .expect("checked proof window cardinality")
                            .map_err(Poseidon2V8StateError::ProofRejected)?;
                        verifier.record_window_verified_transition(public);
                        public
                    } else {
                        verifier
                            .verify_exact_v8_leaf(context, leaf_index, leaf)
                            .map_err(Poseidon2V8StateError::ProofRejected)?
                    };
                    if !public.stablecoin_effect_matches_roots() {
                        return Err(Poseidon2V8StateError::StablecoinEffectMismatch {
                            leaf_index,
                            effect: public.stablecoin_effect,
                            before_root: public.before_root,
                            after_root: public.after_root,
                        });
                    }
                    if launch_context.is_some() {
                        let checked = public.checked_launch_reference.ok_or_else(|| Poseidon2V8StateError::ProofRejected(
                            "launch transition lacks checked canonical reference; ordering hints cannot authorize state".into()
                        ))?;
                        let canonical = launch_checkpoints
                            .iter()
                            .find(|row| row.height() == checked.reference_height())
                            .ok_or_else(|| {
                                Poseidon2V8StateError::ProofRejected(
                                    "launch receipt has no canonical/staged checkpoint".into(),
                                )
                            })?;
                        if canonical.hash() != checked.reference_hash()
                            || canonical.note_anchor() != checked.note_anchor()
                            || canonical.static_stable_root() != checked.static_stable_root()
                            || (is_asset && canonical.asset_registry_root() != checked.asset_registry_root())
                            || (!is_asset && checked.asset_registry_root().is_some())
                            || checked.application_parent_height() != context.parent_height
                            || checked.application_parent_hash() != context.parent_hash
                            || checked.application_height() != context.height
                            || checked.reference_height() != public.parent_height
                            || checked.note_anchor() != public.note_anchor
                            || checked.static_stable_root() != public.before_root
                            || checked.static_stable_root() != public.after_root
                            || public.stablecoin_effect
                                != Poseidon2V8StablecoinEffect::DisabledNoWrite
                        {
                            return Err(Poseidon2V8StateError::ProofRejected("launch receipt differs from original reference or application parent".into()));
                        }
                    } else {
                        if public.checked_launch_reference.is_some()
                            || public.application_parent_hint.is_some()
                        {
                            return Err(Poseidon2V8StateError::ProofRejected(
                                "historical transition cannot carry launch reference metadata"
                                    .into(),
                            ));
                        }
                        if public.parent_height != context.parent_height {
                            return Err(Poseidon2V8StateError::ProofParentHeightMismatch {
                                expected: context.parent_height,
                                observed: public.parent_height,
                            });
                        }
                    }
                    if public.before_root != current_root {
                        return Err(Poseidon2V8StateError::ProofBeforeRootMismatch {
                            expected: current_root,
                            observed: public.before_root,
                        });
                    }
                    if launch_context.is_none()
                        && !pre_block_note_roots.contains(&public.note_anchor)
                    {
                        return Err(Poseidon2V8StateError::UnknownNoteAnchor {
                            observed: public.note_anchor,
                        });
                    }
                    for nullifier in public.nullifiers.into_iter().flatten() {
                        if !attached_nullifiers.insert(nullifier) {
                            return Err(Poseidon2V8StateError::DuplicateNullifier(nullifier));
                        }
                        let persisted = self.tree.get(nullifier_key(nullifier))?.is_some();
                        if persisted && !detached_nullifiers.contains(&nullifier) {
                            return Err(Poseidon2V8StateError::SpentNullifier(nullifier));
                        }
                        block_nullifiers.push(nullifier);
                    }
                    for commitment in public.all_commitments().into_iter().flatten() {
                        note_state.append(commitment)?;
                    }
                    current_root = public.after_root;
                }
            }
            // Public issuance has already passed subsidy, fee and opening
            // validation. It becomes a membership leaf only at the end of
            // origin+119; this block's immutable pre-state references exclude
            // those new leaves, enforcing spend_height >= origin+120.
            note_state.finish_block_rewards(
                context.height,
                context.block_hash,
                [
                    block.trailing_coinbase_commitment,
                    block.trailing_funding_commitment,
                ],
            )?;
            if let Some(reference_context) = launch_context {
                if reference_context.permits_launch_after_parent(context.height) {
                    launch_checkpoints.push_back(
                        CanonicalLaunchCheckpoint::new(
                            context.block_hash,
                            context.parent_hash,
                            context.height,
                            note_state.root(),
                            current_root,
                        )
                        .map_err(Poseidon2V8StateError::ProofRejected)?
                        .with_asset_registry_root(asset_registry_root(asset_state.as_deref())?),
                    );
                    while launch_checkpoints.len() > 13 {
                        launch_checkpoints.pop_front();
                    }
                } else {
                    // There is no future authorized inclusion at this parent.
                    // Continue ordinary state/reward replay without snapshots.
                    launch_checkpoints.clear();
                }
                if verifier.launch_reference_context() != Some(reference_context) {
                    return Err(Poseidon2V8StateError::ProofRejected(
                        "launch reference identity changed after verification".into(),
                    ));
                }
            }
            if let Some(current) = asset_state.as_deref() {
                let next = verifier
                    .advance_asset_state(context, current)
                    .map_err(Poseidon2V8StateError::ProofRejected)?;
                if validate_asset_snapshot(&next, context.height)?
                    != validate_asset_snapshot(current, context.parent_height)?
                {
                    return Err(Poseidon2V8StateError::CorruptRecordLink);
                }
                asset_state = Some(next);
            }
            cursor = Poseidon2V8Checkpoint::new(context.height, context.block_hash, current_root);
            let (leaf_count, leaf_total_bytes, leaf_sequence_digest) =
                leaf_sequence_commitment(block.exact_native_leaves)?;
            let mut record = Poseidon2V8BlockRecord {
                before,
                after: cursor,
                before_proof_lifetime: proof_lifetime,
                after_proof_lifetime: next_proof_lifetime,
                after_note_state: note_state.clone(),
                after_asset_state: asset_state.clone(),
                introduced_nullifiers: block_nullifiers,
                leaf_count,
                leaf_total_bytes,
                leaf_sequence_digest,
                record_digest: [0u8; 64],
            };
            record.record_digest = block_record_digest(&record)?;
            records.push(record);
            proof_lifetime = next_proof_lifetime;
        }
        Ok((records, cursor, note_state, proof_lifetime, asset_state))
    }

    /// Load only canonical, digest-checked ancestry; never a hash-indexed orphan.
    /// The first note snapshot is the validated ancestor returned by plan_detach.
    fn collect_launch_checkpoints(
        &self,
        context: LaunchReferenceContext,
        ancestor: Poseidon2V8Checkpoint,
        ancestor_note: &Poseidon2V8NoteTreeState,
    ) -> Result<VecDeque<CanonicalLaunchCheckpoint>, Poseidon2V8StateError> {
        let first = context
            .first_reference_parent(ancestor.height)
            .map_err(Poseidon2V8StateError::ProofRejected)?;
        let genesis = self.genesis()?;
        context
            .require_genesis(genesis.block_hash, genesis.root)
            .map_err(Poseidon2V8StateError::ProofRejected)?;
        let mut cursor = ancestor;
        let mut reverse = Vec::new();
        loop {
            if reverse.len() >= 13 {
                return Err(Poseidon2V8StateError::CorruptRecordLink);
            }
            if cursor.height == 0 {
                let empty = Poseidon2V8NoteTreeState::new_empty()?;
                if cursor != genesis || (cursor == ancestor && *ancestor_note != empty) {
                    return Err(Poseidon2V8StateError::CorruptRecordLink);
                }
                reverse.push(
                    CanonicalLaunchCheckpoint::new(
                        cursor.block_hash,
                        [0; 32],
                        0,
                        empty.root(),
                        cursor.root,
                    )
                    .map_err(Poseidon2V8StateError::ProofRejected)?
                    .with_asset_registry_root(asset_registry_root(
                        self.asset_state_at_checkpoint(cursor)?.as_deref())?),
                );
            } else {
                let record = self.load_record(cursor.block_hash)?;
                if record.after != cursor
                    || (cursor == ancestor && record.after_note_state != *ancestor_note)
                {
                    return Err(Poseidon2V8StateError::CorruptRecordLink);
                }
                let persisted_assets = self.asset_state_at_checkpoint(cursor)?;
                if persisted_assets != record.after_asset_state {
                    return Err(Poseidon2V8StateError::CorruptRecordLink);
                }
                reverse.push(
                    CanonicalLaunchCheckpoint::new(
                        cursor.block_hash,
                        record.before.block_hash,
                        cursor.height,
                        record.after_note_state.root(),
                        cursor.root,
                    )
                    .map_err(Poseidon2V8StateError::ProofRejected)?
                    .with_asset_registry_root(asset_registry_root(
                        persisted_assets.as_deref())?),
                );
                cursor = record.before;
            }
            if reverse.last().is_some_and(|row| row.height() == first) {
                break;
            }
        }
        reverse.reverse();
        // Validate full shape and selected source tuple before exposing snapshots.
        CanonicalLaunchReferences::from_validated_chain(
            context,
            ancestor.block_hash,
            ancestor.height,
            reverse.clone(),
        )
        .map_err(Poseidon2V8StateError::ProofRejected)?;
        Ok(reverse.into())
    }

    fn note_state_at_checkpoint(
        &self,
        checkpoint: Poseidon2V8Checkpoint,
    ) -> Result<Poseidon2V8NoteTreeState, Poseidon2V8StateError> {
        let genesis = self.genesis()?;
        if checkpoint == genesis {
            return Poseidon2V8NoteTreeState::new_empty();
        }
        let record = self.load_record(checkpoint.block_hash)?;
        if record.after != checkpoint {
            return Err(Poseidon2V8StateError::CorruptRecordLink);
        }
        Ok(record.after_note_state)
    }

    fn genesis(&self) -> Result<Poseidon2V8Checkpoint, Poseidon2V8StateError> {
        let bytes = self
            .tree
            .get(GENESIS_KEY)?
            .ok_or(Poseidon2V8StateError::MissingGenesis)?;
        Poseidon2V8Checkpoint::decode_exact(bytes.as_ref())
    }

    fn load_record(
        &self,
        block_hash: [u8; 32],
    ) -> Result<Poseidon2V8BlockRecord, Poseidon2V8StateError> {
        let bytes = self
            .tree
            .get(record_key(block_hash))?
            .ok_or(Poseidon2V8StateError::MissingBlockRecord(block_hash))?;
        let mut record = Poseidon2V8BlockRecord::decode_exact(bytes.as_ref())?;
        record.after_asset_state = self.asset_state_at_checkpoint(record.after)?;
        if record.after.block_hash != block_hash {
            return Err(Poseidon2V8StateError::CorruptRecordLink);
        }
        let height_hash = self.tree.get(height_key(record.after.height))?.ok_or(
            Poseidon2V8StateError::MissingHeightRecord(record.after.height),
        )?;
        if height_hash.as_ref() != block_hash.as_slice() {
            return Err(Poseidon2V8StateError::CorruptRecordLink);
        }
        Ok(record)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum Poseidon2V8StateError {
    #[error("V8 stablecoin root limb {index} is not a canonical Goldilocks element: {limb}")]
    NonCanonicalRootLimb { index: usize, limb: u64 },
    #[error("{label} limb {index} is not a canonical Goldilocks element: {limb}")]
    NonCanonicalDigestLimb {
        label: &'static str,
        index: usize,
        limb: u64,
    },
    #[error("{label} has wrong length: expected {expected}, observed {observed}")]
    CodecLength {
        label: &'static str,
        expected: usize,
        observed: usize,
    },
    #[error("{0} has the wrong codec magic")]
    CodecMagic(&'static str),
    #[error("{label} uses compression mode {observed:#018x}; expected {expected:#018x}")]
    CodecCompressionMode {
        label: &'static str,
        expected: u64,
        observed: u64,
    },
    #[error("{0} has trailing bytes")]
    CodecTrailing(&'static str),
    #[error("V8 stablecoin height overflow")]
    HeightOverflow,
    #[error("V8 stablecoin height {height} exceeds the relation scalar maximum")]
    HeightExceedsRelationScalar { height: u64 },
    #[error("V8 stablecoin height is not contiguous: expected {expected}, observed {observed}")]
    NonContiguousHeight { expected: u64, observed: u64 },
    #[error("V8 stablecoin child block hash equals its parent hash")]
    BlockEqualsParent,
    #[error("V8 stablecoin native leaf batch exceeds the native action count cap")]
    TooManyLeaves,
    #[error("V8 stablecoin native leaf {index} is empty")]
    EmptyLeaf { index: usize },
    #[error("V8 stablecoin native leaf {index} exceeds its hard cap: {observed} > {maximum}")]
    LeafTooLarge {
        index: usize,
        observed: usize,
        maximum: usize,
    },
    #[error("V8 stablecoin native leaf batch bytes exceed the native block cap")]
    LeafBatchTooLarge,
    #[error("V8 note tree depth is invalid")]
    InvalidNoteTreeDepth,
    #[error("V8 note tree is full")]
    NoteTreeFull,
    #[error("corrupt V8 note-tree state")]
    CorruptNoteTreeState,
    #[error("corrupt or out-of-height V8 pending reward queue")]
    CorruptPendingRewards,
    #[error("V8 note genesis root is unsupported without an exact leaf-count/frontier snapshot")]
    UnsupportedNoteGenesisRoot {
        expected: Poseidon2V8NoteRoot,
        observed: Poseidon2V8NoteRoot,
    },
    #[error("V8 note anchor is not in retained canonical history")]
    UnknownNoteAnchor { observed: Poseidon2V8NoteRoot },
    #[error("V8 nullifier is duplicated in the replacement suffix")]
    DuplicateNullifier(Poseidon2V8Nullifier),
    #[error("V8 nullifier is already spent")]
    SpentNullifier(Poseidon2V8Nullifier),
    #[error("V8 stablecoin proof rejected: {0}")]
    ProofRejected(String),
    #[error("V8 verifier-returned stablecoin effect disagrees with its public roots")]
    StablecoinEffectMismatch {
        leaf_index: usize,
        effect: Poseidon2V8StablecoinEffect,
        before_root: Poseidon2V8Root,
        after_root: Poseidon2V8Root,
    },
    #[error("V8 proof parent height mismatch: expected {expected}, observed {observed}")]
    ProofParentHeightMismatch { expected: u64, observed: u64 },
    #[error("V8 proof before root does not equal verifier-owned current root")]
    ProofBeforeRootMismatch {
        expected: Poseidon2V8Root,
        observed: Poseidon2V8Root,
    },
    #[error("V8 block parent checkpoint mismatch")]
    ParentCheckpointMismatch {
        expected_height: u64,
        observed_height: u64,
        expected_hash: [u8; 32],
        observed_hash: [u8; 32],
    },
    #[error("V8 disconnect tip mismatch")]
    DisconnectTipMismatch {
        expected: [u8; 32],
        observed: [u8; 32],
    },
    #[error("V8 replacement suffix repeats a block hash")]
    DuplicateAttachBlock([u8; 32]),
    #[error("V8 replacement suffix repeats height {0}")]
    DuplicateAttachHeight(u64),
    #[error("missing V8 stablecoin canonical tip")]
    MissingTip,
    #[error("missing V8 canonical note-tree tip")]
    MissingNoteTip,
    #[error("missing V8 proof lifetime canonical tip")]
    MissingProofLifetimeTip,
    #[error("missing V8 stablecoin genesis checkpoint")]
    MissingGenesis,
    #[error("missing V8 stablecoin block record")]
    MissingBlockRecord([u8; 32]),
    #[error("missing V8 stablecoin height record at {0}")]
    MissingHeightRecord(u64),
    #[error("corrupt V8 stablecoin block record bounds")]
    CorruptRecordBounds,
    #[error("corrupt V8 stablecoin block record link")]
    CorruptRecordLink,
    #[error("corrupt V8 proof lifetime block record link")]
    CorruptProofLifetimeLink,
    #[error("corrupt V8 stablecoin block record integrity digest")]
    CorruptRecordDigest,
    #[error("V8 stablecoin storage conflict: {0}")]
    StorageConflict(String),
    #[error("V8 stablecoin sled error: {0}")]
    Sled(String),
    #[error("V8 stablecoin durability barrier failed after mutation: {0}")]
    DurabilityUncertain(String),
    #[error("V8 state allocation failed for {0} bytes")]
    AllocationFailed(usize),
    #[error(transparent)]
    ProofLifetime(#[from] SmallwoodV8ProofLifetimeError),
}

impl From<sled::Error> for Poseidon2V8StateError {
    fn from(error: sled::Error) -> Self {
        Self::Sled(error.to_string())
    }
}

fn validate_leaf_batch(leaves: &[&[u8]]) -> Result<usize, Poseidon2V8StateError> {
    validate_leaf_batch_for_profile(leaves, None)
}

fn validate_leaf_batch_for_profile(
    leaves: &[&[u8]],
    selected_profile: Option<Poseidon2V8NativeLeafProfile>,
) -> Result<usize, Poseidon2V8StateError> {
    if leaves.len() > MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK {
        return Err(Poseidon2V8StateError::TooManyLeaves);
    }
    let mut total = 0usize;
    for (index, leaf) in leaves.iter().copied().enumerate() {
        if leaf.is_empty() {
            return Err(Poseidon2V8StateError::EmptyLeaf { index });
        }
        // A larger structural ceiling requires an exact source-owned frame.
        // Its decoder binds canonical fields, source and nested proof magic;
        // this framing check does not grant proof acceptance. The final min
        // below preserves each ordinary route's cap despite the larger recovery
        // envelope, and the complete batch still shares the 64 MiB budget.
        let launch_cap =
            if transaction_circuit::asset_recovery_wire_v1::decode_spend_ref(leaf).is_ok() {
                Some(transaction_circuit::asset_recovery_wire_v1::MAX_SPEND_ACTION_BYTES)
            } else if transaction_circuit::asset_recovery_wire_v1::decode_admin_ref(leaf).is_ok() {
                Some(transaction_circuit::asset_recovery_wire_v1::MAX_ADMIN_ACTION_BYTES)
            } else if transaction_circuit::asset_spend_v1_wire::decode_native_asset_spend_action_v1(leaf)
                .is_ok()
            {
                Some(transaction_circuit::asset_spend_v1_wire::NATIVE_ASSET_SPEND_MAX_ACTION_BYTES_V1)
            } else if transaction_circuit::asset_spend_v1_wire::decode_native_asset_admin_action_v1(
                leaf,
            )
            .is_ok()
            {
                Some(transaction_circuit::asset_spend_v1_wire::NATIVE_ASSET_ADMIN_MAX_ACTION_BYTES_V1)
            } else if protocol_shielded_pool::rp06_transport::preflight_rp06_native_leaf_exact(leaf)
                .is_ok()
            {
                Some(protocol_shielded_pool::rp06_transport::RP06_CANDIDATE_MAX_NATIVE_LEAF_BYTES)
            } else if super::native_proof_binding::preflight_private_spend_args(leaf).is_ok() {
                Some(protocol_shielded_pool::private_spend_transport::MAX_CARRIER_BYTES)
            } else if transaction_circuit::smallwood_htlc_transport::decode_candidate_exact(leaf)
                .is_ok()
            {
                Some(transaction_circuit::smallwood_htlc_transport::MAX_CANDIDATE_CARRIER_BYTES)
            } else {
                None
            };
        let framing_profile = if launch_cap.is_some() {
            Poseidon2V8NativeLeafProfile::LaunchMixed
        } else if preflight_poseidon2_production_smza_native_leaf_exact(leaf).is_ok() {
            Poseidon2V8NativeLeafProfile::Smza
        } else {
            Poseidon2V8NativeLeafProfile::Smz9
        };
        if selected_profile.is_some_and(|selected| {
            (selected == Poseidon2V8NativeLeafProfile::LaunchMixed)
                != (framing_profile == Poseidon2V8NativeLeafProfile::LaunchMixed)
        }) {
            return Err(Poseidon2V8StateError::ProofRejected(
                "native leaf belongs to a different closed source profile".into(),
            ));
        }
        let maximum = selected_profile
            .unwrap_or(framing_profile)
            .max_native_leaf_bytes()
            .min(launch_cap.unwrap_or_else(|| framing_profile.max_native_leaf_bytes()));
        if leaf.len() > maximum {
            return Err(Poseidon2V8StateError::LeafTooLarge {
                index,
                observed: leaf.len(),
                maximum,
            });
        }
        total = total
            .checked_add(leaf.len())
            .ok_or(Poseidon2V8StateError::LeafBatchTooLarge)?;
        if total > MAX_NATIVE_BLOCK_ACTION_BYTES {
            return Err(Poseidon2V8StateError::LeafBatchTooLarge);
        }
    }
    Ok(total)
}

/// Historical records keep their exact codec and one unit per leaf. The only
/// new increment is the four segmented capsule proofs on one recovery spend.
/// The exact wire grammar owns that cost. This structural
/// link is not a proof cache: startup re-verifies exact leaves and compares all
/// rebuilt rows, including these source-derived lifetime counters.
fn validate_record_proof_lifetime(
    before: SmallwoodV8ProofLifetimeCount,
    after: SmallwoodV8ProofLifetimeCount,
    leaf_count: u32,
) -> Result<(), Poseidon2V8StateError> {
    let units = after.get().checked_sub(before.get())
        .ok_or(Poseidon2V8StateError::CorruptProofLifetimeLink)?;
    let leaves = u64::from(leaf_count);
    let recovery_extra = (transaction_circuit::asset_recovery_wire_v1::PROOF_UNITS - 1) as u64;
    if units != leaves && !(leaves > 0 && units == leaves + recovery_extra) {
        return Err(Poseidon2V8StateError::CorruptProofLifetimeLink);
    }
    // Records preserve exact u64 audit deltas; source-specific lifetime policy
    // belongs to verified planning, which also runs during startup replay.
    if before.checked_accept_audit_block(usize::try_from(units)
        .map_err(|_| Poseidon2V8StateError::CorruptRecordBounds)?)? != after {
        return Err(Poseidon2V8StateError::CorruptProofLifetimeLink);
    }
    Ok(())
}

/// Codec/record checks carry no network authority. Reapply the selected policy
/// before planning any canonical append or replacement, even an empty suffix.
/// Only the exact ongoing HGN launch profile may omit a cumulative quota.
fn validate_proof_lifetime_authority<V: Poseidon2V8ExactLeafVerifier + ?Sized>(
    count: SmallwoodV8ProofLifetimeCount,
    verifier: &V,
) -> Result<bool, Poseidon2V8StateError> {
    if verifier.native_leaf_profile() == Poseidon2V8NativeLeafProfile::LaunchMixed {
        match verifier.launch_proof_lifetime_limit() {
            None if verifier.launch_has_ongoing_hgn_authority() => return Ok(true),
            Some(limit) if limit > 0 => {
                if count.get() > limit {
                    return Err(Poseidon2V8StateError::ProofRejected(
                        "launch source action/lifetime budget exceeded".into(),
                    ));
                }
            }
            _ => {
                return Err(Poseidon2V8StateError::ProofRejected(
                    "launch verifier lacks a source lifetime budget".into(),
                ))
            }
        }
    }
    SmallwoodV8ProofLifetimeCount::new(count.get())?;
    Ok(false)
}

fn validate_block_proof_authority_action_count(
    transaction_proofs: usize,
    has_v8_coinbase: bool,
) -> Result<(), Poseidon2V8StateError> {
    let action_count = transaction_proofs
        .checked_add(usize::from(has_v8_coinbase))
        .ok_or(Poseidon2V8StateError::TooManyLeaves)?;
    if action_count > MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK {
        return Err(Poseidon2V8StateError::TooManyLeaves);
    }
    Ok(())
}

fn validate_relation_height(height: u64) -> Result<(), Poseidon2V8StateError> {
    if height > POSEIDON2_V8_MAX_SCALAR {
        return Err(Poseidon2V8StateError::HeightExceedsRelationScalar { height });
    }
    Ok(())
}

fn leaf_sequence_commitment(
    leaves: &[&[u8]],
) -> Result<(u32, u64, [u8; 64]), Poseidon2V8StateError> {
    let total = validate_leaf_batch(leaves)?;
    let count = u32::try_from(leaves.len()).map_err(|_| Poseidon2V8StateError::TooManyLeaves)?;
    let total = u64::try_from(total).map_err(|_| Poseidon2V8StateError::LeafBatchTooLarge)?;
    let mut hasher = Sha512::new();
    hasher.update(LEAF_SEQUENCE_DOMAIN);
    hasher.update(count.to_le_bytes());
    for leaf in leaves {
        let len =
            u32::try_from(leaf.len()).map_err(|_| Poseidon2V8StateError::LeafBatchTooLarge)?;
        hasher.update(len.to_le_bytes());
        hasher.update(leaf);
    }
    Ok((count, total, hasher.finalize().into()))
}

fn validate_digest_limbs(
    label: &'static str,
    limbs: &[u64; POSEIDON2_V8_ROOT_LIMBS],
) -> Result<(), Poseidon2V8StateError> {
    for (index, limb) in limbs.iter().copied().enumerate() {
        if limb >= POSEIDON2_V8_GOLDILOCKS_MODULUS {
            return Err(Poseidon2V8StateError::NonCanonicalDigestLimb { label, index, limb });
        }
    }
    Ok(())
}

fn encode_digest_limbs(limbs: [u64; POSEIDON2_V8_ROOT_LIMBS]) -> [u8; POSEIDON2_V8_DIGEST_BYTES] {
    let mut encoded = [0u8; POSEIDON2_V8_DIGEST_BYTES];
    for (index, limb) in limbs.into_iter().enumerate() {
        let start = index * 8;
        encoded[start..start + 8].copy_from_slice(&limb.to_le_bytes());
    }
    encoded
}

fn decode_digest_limbs(
    bytes: &[u8],
    label: &'static str,
) -> Result<[u64; POSEIDON2_V8_ROOT_LIMBS], Poseidon2V8StateError> {
    if bytes.len() != POSEIDON2_V8_DIGEST_BYTES {
        return Err(Poseidon2V8StateError::CodecLength {
            label,
            expected: POSEIDON2_V8_DIGEST_BYTES,
            observed: bytes.len(),
        });
    }
    let limbs = core::array::from_fn(|index| {
        let start = index * 8;
        u64::from_le_bytes(
            bytes[start..start + 8]
                .try_into()
                .expect("fixed V8 digest limb is eight bytes"),
        )
    });
    validate_digest_limbs(label, &limbs)?;
    Ok(limbs)
}

fn compress_note_roots(
    left: Poseidon2V8NoteRoot,
    right: Poseidon2V8NoteRoot,
) -> Result<Poseidon2V8NoteRoot, Poseidon2V8StateError> {
    let left = left.limbs().map(Felt::from_u64);
    let right = right.limbs().map(Felt::from_u64);
    Poseidon2V8NoteRoot::new(
        poseidon2_width16_compress14(MERKLE_DOMAIN_TAG, &left, &right)
            .map(|value| value.as_canonical_u64()),
    )
}

fn poseidon2_v8_default_note_nodes() -> Result<Vec<Poseidon2V8NoteRoot>, Poseidon2V8StateError> {
    let source_nodes = source_poseidon2_v8_default_note_nodes();
    if source_nodes.len() != CIRCUIT_MERKLE_DEPTH + 1 {
        return Err(Poseidon2V8StateError::InvalidNoteTreeDepth);
    }
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(source_nodes.len())
        .map_err(|_| Poseidon2V8StateError::AllocationFailed(source_nodes.len()))?;
    for limbs in source_nodes {
        nodes.push(Poseidon2V8NoteRoot::new(limbs)?);
    }
    Ok(nodes)
}

fn nullifier_key(nullifier: Poseidon2V8Nullifier) -> Vec<u8> {
    let encoded = nullifier.encode();
    let mut key = Vec::with_capacity(NULLIFIER_KEY_PREFIX.len() + encoded.len());
    key.extend_from_slice(NULLIFIER_KEY_PREFIX);
    key.extend_from_slice(&encoded);
    key
}

fn block_record_digest(record: &Poseidon2V8BlockRecord) -> Result<[u8; 64], Poseidon2V8StateError> {
    let mut canonical = record.clone();
    canonical.record_digest = [0u8; 64];
    let mut hasher = Sha512::new();
    hasher.update(BLOCK_RECORD_DOMAIN);
    hasher.update(canonical.encode()?);
    Ok(hasher.finalize().into())
}

fn flush_durable(tree: &sled::Tree) -> Result<(), Poseidon2V8StateError> {
    tree.flush()
        .map(|_| ())
        .map_err(|error| Poseidon2V8StateError::DurabilityUncertain(error.to_string()))
}

fn map_transaction(
    result: Result<(), TransactionError<String>>,
) -> Result<(), Poseidon2V8StateError> {
    match result {
        Ok(()) => Ok(()),
        Err(TransactionError::Abort(message)) => {
            Err(Poseidon2V8StateError::StorageConflict(message))
        }
        Err(TransactionError::Storage(error)) => Err(Poseidon2V8StateError::from(error)),
    }
}

fn asset_registry_root(bytes: Option<&[u8]>) -> Result<Option<CanonicalAssetRegistryRoot>, Poseidon2V8StateError> {
    bytes.map(|bytes| {
        let state = super::asset_state::AssetRegistryStateV1::decode_exact(bytes)
            .map_err(|error| Poseidon2V8StateError::ProofRejected(error.to_string()))?;
        CanonicalAssetRegistryRoot::new(state.registry().root().map(|word| word.as_canonical_u64()))
            .map_err(Poseidon2V8StateError::ProofRejected)
    }).transpose()
}

fn validate_asset_snapshot(
    bytes: &[u8],
    expected_height: u64,
) -> Result<[u8; 32], Poseidon2V8StateError> {
    let state = super::asset_state::AssetRegistryStateV1::decode_exact(bytes)
        .map_err(|error| Poseidon2V8StateError::ProofRejected(error.to_string()))?;
    if state.registry().context().parent_height != expected_height {
        return Err(Poseidon2V8StateError::CorruptRecordLink);
    }
    Ok(state.registry().context().chain_id)
}

fn asset_record_key(block_hash: [u8; 32]) -> Vec<u8> {
    let mut key = ASSET_RECORD_KEY_PREFIX.to_vec();
    key.extend_from_slice(&block_hash);
    key
}

fn record_key(block_hash: [u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(RECORD_KEY_PREFIX.len() + block_hash.len());
    key.extend_from_slice(RECORD_KEY_PREFIX);
    key.extend_from_slice(&block_hash);
    key
}

fn height_key(height: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(HEIGHT_KEY_PREFIX.len() + 8);
    key.extend_from_slice(HEIGHT_KEY_PREFIX);
    key.extend_from_slice(&height.to_be_bytes());
    key
}

fn put<const N: usize>(output: &mut [u8; N], cursor: &mut usize, bytes: &[u8]) {
    let end = *cursor + bytes.len();
    output[*cursor..end].copy_from_slice(bytes);
    *cursor = end;
}

fn take<'a>(
    cursor: &mut &'a [u8],
    len: usize,
    label: &'static str,
) -> Result<&'a [u8], Poseidon2V8StateError> {
    if cursor.len() < len {
        return Err(Poseidon2V8StateError::CodecLength {
            label,
            expected: len,
            observed: cursor.len(),
        });
    }
    let (head, tail) = cursor.split_at(len);
    *cursor = tail;
    Ok(head)
}

fn take_array<const N: usize>(
    cursor: &mut &[u8],
    label: &'static str,
) -> Result<[u8; N], Poseidon2V8StateError> {
    Ok(take(cursor, N, label)?
        .try_into()
        .expect("fixed-width slice length was checked"))
}

fn take_u32(cursor: &mut &[u8], label: &'static str) -> Result<u32, Poseidon2V8StateError> {
    Ok(u32::from_le_bytes(take_array(cursor, label)?))
}

fn take_u64(cursor: &mut &[u8], label: &'static str) -> Result<u64, Poseidon2V8StateError> {
    Ok(u64::from_le_bytes(take_array(cursor, label)?))
}

fn expect_magic(
    cursor: &mut &[u8],
    magic: &[u8],
    label: &'static str,
) -> Result<(), Poseidon2V8StateError> {
    if take(cursor, magic.len(), label)? != magic {
        return Err(Poseidon2V8StateError::CodecMagic(label));
    }
    Ok(())
}

fn expect_compression_mode(
    cursor: &mut &[u8],
    label: &'static str,
) -> Result<(), Poseidon2V8StateError> {
    let observed = take_u64(cursor, label)?;
    if observed != POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER {
        return Err(Poseidon2V8StateError::CodecCompressionMode {
            label,
            expected: POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER,
            observed,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn native_leaf_caps_follow_exact_framing_and_selected_profile() {
        use protocol_shielded_pool::poseidon2_production_transport::{
            encode_poseidon2_production_smza_native_leaf, Poseidon2ProductionExpectedContext,
            POSEIDON2_PRODUCTION_SMZA_MAX_PROOF_BYTES,
        };
        let expected = Poseidon2ProductionExpectedContext::new(17, [0x42; 48]).unwrap();
        let mut proof = vec![0xa5; POSEIDON2_PRODUCTION_SMZA_MAX_PROOF_BYTES];
        proof[..4].copy_from_slice(b"SMZA");
        let leaf = encode_poseidon2_production_smza_native_leaf(
            expected,
            &[0; 120],
            &[0; 7],
            [None, None],
            &proof,
        )
        .unwrap();
        assert!(leaf.len() > POSEIDON2_PRODUCTION_MAX_NATIVE_LEAF_BYTES);
        assert_eq!(
            Poseidon2V8NativeLeafProfile::Smz9.max_native_leaf_bytes(),
            131_072
        );
        assert_eq!(
            Poseidon2V8NativeLeafProfile::Smza.max_native_leaf_bytes(),
            169_511
        );
        let leaves = [leaf.as_slice()];
        assert_eq!(validate_leaf_batch(&leaves).unwrap(), leaf.len());
        assert_eq!(
            leaf_sequence_commitment(&leaves).unwrap().1,
            leaf.len() as u64
        );
        validate_leaf_batch_for_profile(&leaves, Some(Poseidon2V8NativeLeafProfile::Smza)).unwrap();
        assert!(matches!(
            validate_leaf_batch_for_profile(&leaves, Some(Poseidon2V8NativeLeafProfile::Smz9)),
            Err(Poseidon2V8StateError::LeafTooLarge {
                maximum: 131_072,
                ..
            })
        ));
        let oversized = vec![0; POSEIDON2_PRODUCTION_SMZA_MAX_NATIVE_LEAF_BYTES + 1];
        assert!(matches!(
            validate_leaf_batch_for_profile(
                &[&oversized],
                Some(Poseidon2V8NativeLeafProfile::Smza)
            ),
            Err(Poseidon2V8StateError::LeafTooLarge { .. })
        ));
        let over_count = vec![leaf.as_slice(); MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK + 1];
        assert!(matches!(
            validate_leaf_batch(&over_count),
            Err(Poseidon2V8StateError::TooManyLeaves)
        ));
        let over_bytes = vec![leaf.as_slice(); MAX_NATIVE_BLOCK_ACTION_BYTES / leaf.len() + 1];
        assert!(matches!(
            validate_leaf_batch(&over_bytes),
            Err(Poseidon2V8StateError::LeafBatchTooLarge)
        ));
        let mut historical_magic = leaf;
        historical_magic[..8].copy_from_slice(b"HGV8TX02");
        assert!(matches!(
            validate_leaf_batch(&[&historical_magic]),
            Err(Poseidon2V8StateError::LeafTooLarge {
                maximum: 131_072,
                ..
            })
        ));
    }

    #[test]
    fn recovery_ceiling_does_not_grant_malformed_or_ordinary_frames_more_bytes() {
        use transaction_circuit::asset_recovery_wire_v1::{
            MAGIC, MAX_ADMIN_ACTION_BYTES, MAX_SPEND_ACTION_BYTES,
        };
        assert!(MAX_SPEND_ACTION_BYTES > MAX_ADMIN_ACTION_BYTES);
        assert!(MAX_SPEND_ACTION_BYTES < MAX_NATIVE_BLOCK_ACTION_BYTES);
        assert!(Poseidon2V8NativeLeafProfile::LaunchMixed.max_native_leaf_bytes()
            >= MAX_SPEND_ACTION_BYTES);
        assert_eq!(Poseidon2V8NativeLeafProfile::Smz9.max_native_leaf_bytes(), 131_072);
        assert_eq!(Poseidon2V8NativeLeafProfile::Smza.max_native_leaf_bytes(), 169_511);
        let mut malformed = vec![0; MAX_SPEND_ACTION_BYTES];
        malformed[..8].copy_from_slice(&MAGIC);
        assert!(matches!(validate_leaf_batch(&[&malformed]),
            Err(Poseidon2V8StateError::LeafTooLarge { maximum: 131_072, .. })));
        assert!(matches!(validate_leaf_batch_for_profile(
            &[&malformed], Some(Poseidon2V8NativeLeafProfile::LaunchMixed)),
            Err(Poseidon2V8StateError::ProofRejected(_))));
    }

    use super::*;
    use crate::native::{
        apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction, NativeAtomicCommitKind,
        NativeAtomicCommitManifestAdmissionInput,
    };
    use sled::transaction::Transactional;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use transaction_circuit::{
        smallwood_poseidon2_v8_coinbase::{
            poseidon2_v8_note_commitment, poseidon2_v8_single_key_authorization_key,
        },
        smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8NoteOpening,
    };

    fn root(seed: u64) -> Poseidon2V8Root {
        Poseidon2V8Root::new([
            seed,
            seed + 1,
            seed + 2,
            seed + 3,
            seed + 4,
            seed + 5,
            seed + 6,
        ])
        .unwrap()
    }

    fn hash(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn context(parent: Poseidon2V8Checkpoint, child_seed: u8) -> Poseidon2V8BlockContext {
        Poseidon2V8BlockContext::new(
            parent.height(),
            parent.block_hash(),
            parent.height() + 1,
            hash(child_seed),
        )
        .unwrap()
    }

    // These are typed storage/refinement checks. The fixture verifier supplies
    // already verified effects; genuine proof acceptance is exercised by the
    // node's separate end-to-end lifecycle, never inferred from these tests.
    struct AssetStorageFixtureVerifier {
        anchor: Poseidon2V8NoteRoot,
        static_root: Poseidon2V8Root,
        bad_advance: bool,
        observed_asset_inputs: Vec<(u32, bool)>,
    }
    impl Poseidon2V8ExactLeafVerifier for AssetStorageFixtureVerifier {
        fn native_leaf_profile(&self) -> Poseidon2V8NativeLeafProfile {
            Poseidon2V8NativeLeafProfile::Smz9
        }
        fn is_asset_native_leaf(&self, leaf: &[u8]) -> bool {
            leaf == b"fixture-asset"
        }
        fn verify_exact_v8_leaf(
            &mut self,
            block: Poseidon2V8BlockContext,
            _: usize,
            leaf: &[u8],
        ) -> Result<Poseidon2V8PublicTransition, String> {
            if leaf != b"fixture-native-before-asset" {
                return Err("fixture native leaf rejected".into());
            }
            Ok(Poseidon2V8PublicTransition::new_with_shielded_state_and_stablecoin_effect(
                block.parent_height(), self.static_root, self.static_root,
                Poseidon2V8StablecoinEffect::DisabledNoWrite, self.anchor,
                [Some(nullifier(301)), None], [Some(commitment(311)), None],
            ))
        }
        fn verify_exact_asset_leaf(
            &mut self,
            block: Poseidon2V8BlockContext,
            _: usize,
            _: &[u8],
            current: &[u8],
            _parent_note_root: Poseidon2V8NoteRoot,
            next_position: u32,
            is_spent: &mut dyn FnMut([u64; 7]) -> Result<bool, String>,
        ) -> Result<(Poseidon2V8PublicTransition, Vec<u8>), String> {
            self.observed_asset_inputs.push((next_position, is_spent(nullifier(301).limbs())?));
            Ok((
                Poseidon2V8PublicTransition::new_with_asset_shielded_state(
                    block.parent_height(),
                    self.static_root,
                    self.anchor,
                    [Some(nullifier(91)), Some(nullifier(101))],
                    [
                        Some(commitment(111)),
                        Some(commitment(121)),
                        Some(commitment(131)),
                    ],
                ),
                current.to_vec(),
            ))
        }
        fn advance_asset_state(
            &mut self,
            block: Poseidon2V8BlockContext,
            current: &[u8],
        ) -> Result<Vec<u8>, String> {
            if self.bad_advance {
                return Ok(current.to_vec());
            }
            let state = super::super::asset_state::AssetRegistryStateV1::decode_exact(current)
                .map_err(|error| error.to_string())?;
            let plan = state
                .plan_verified_block(
                    super::super::asset_state::AssetCanonicalContextV1 {
                        chain_id: state.registry().context().chain_id,
                        reference_parent_hash: block.parent_hash(),
                        parent_height: block.parent_height(),
                        note_root: self.anchor.limbs(),
                    },
                    &[],
                    |_| Ok(false),
                )
                .map_err(|error| error.to_string())?;
            Ok(plan.after_bytes().to_vec())
        }
    }
    fn asset_storage_fixture() -> (
        sled::Db,
        Poseidon2V8StateStore,
        Poseidon2V8Checkpoint,
        Vec<u8>,
        AssetStorageFixtureVerifier,
    ) {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(60), root(70));
        let state =
            super::super::asset_state::AssetRegistryStateV1::from_genesis_rows(hash(61), &[])
                .unwrap()
                .encode_exact()
                .unwrap();
        let anchor = empty_note_genesis_root();
        let store =
            Poseidon2V8StateStore::open_with_assets(&db, genesis, anchor, Some(&state)).unwrap();
        let verifier = AssetStorageFixtureVerifier {
            anchor,
            static_root: genesis.root(),
            bad_advance: false,
            observed_asset_inputs: Vec::new(),
        };
        (db, store, genesis, state, verifier)
    }

    #[test]
    fn asset_snapshots_share_global_pool_restart_detach_and_fresh_replay() {
        let (db, store, genesis, genesis_asset, mut verifier) = asset_storage_fixture();
        let bytes: &[u8] = b"fixture-asset";
        let leaves = [bytes];
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 62), &leaves).unwrap();
        let tip = store.apply_verified_block(block, &mut verifier).unwrap();
        assert_eq!(store.note_tip().unwrap().leaf_count(), 3);
        assert!(store.is_nullifier_spent(nullifier(91)).unwrap());
        assert!(store.is_nullifier_spent(nullifier(101)).unwrap());
        let final_asset = store.asset_tip().unwrap();
        assert_ne!(final_asset.as_deref(), Some(genesis_asset.as_slice()));
        assert!(Poseidon2V8StateStore::open(&db, genesis, verifier.anchor).is_err());
        let reopened = Poseidon2V8StateStore::open_with_assets(
            &db,
            genesis,
            verifier.anchor,
            Some(&genesis_asset),
        )
        .unwrap();
        assert!(store.exact_rows_equal(&reopened).unwrap());
        assert_eq!(store.disconnect_tip(tip.block_hash()).unwrap(), genesis);
        assert_eq!(
            store.asset_tip().unwrap().as_deref(),
            Some(genesis_asset.as_slice())
        );
        assert_eq!(store.note_tip().unwrap().leaf_count(), 0);
        assert!(!store.is_nullifier_spent(nullifier(91)).unwrap());
        assert_eq!(
            store.apply_verified_block(block, &mut verifier).unwrap(),
            tip
        );
        assert_eq!(store.asset_tip().unwrap(), final_asset);
        let (_, fresh, _, _, mut fresh_verifier) = asset_storage_fixture();
        fresh
            .replay_verified_suffix(&[block], &mut fresh_verifier)
            .unwrap();
        assert!(store.exact_rows_equal(&fresh).unwrap());
    }

    #[test]
    fn asset_verifier_receives_actual_append_cursor_and_earlier_native_nullifier() {
        let (_, store, genesis, _, mut verifier) = asset_storage_fixture();
        let leaves: [&[u8]; 2] = [b"fixture-native-before-asset", b"fixture-asset"];
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 62), &leaves).unwrap();
        store.apply_verified_block(block, &mut verifier).unwrap();
        assert_eq!(verifier.observed_asset_inputs, vec![(1, true)]);
        assert_eq!(store.note_tip().unwrap().leaf_count(), 4);
        assert!(store.is_nullifier_spent(nullifier(301)).unwrap());
    }

    #[test]
    fn recovery_nullifier_callback_uses_global_persisted_detached_and_staged_union() {
        let (_, store, genesis, _, mut verifier) = asset_storage_fixture();
        let spent = nullifier(91);
        let unrelated = nullifier(201);
        let empty = BTreeSet::new();
        assert!(!store.is_nullifier_spent_for_replay(spent.limbs(), &empty, &empty).unwrap());
        let leaves: [&[u8]; 1] = [b"fixture-asset"];
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 62), &leaves).unwrap();
        let tip = store.apply_verified_block(block, &mut verifier).unwrap();
        assert!(store.is_nullifier_spent_for_replay(spent.limbs(), &empty, &empty).unwrap());
        let detached = BTreeSet::from([spent]);
        assert!(!store.is_nullifier_spent_for_replay(spent.limbs(), &detached, &empty).unwrap());
        let staged = BTreeSet::from([spent, unrelated]);
        assert!(store.is_nullifier_spent_for_replay(spent.limbs(), &detached, &staged).unwrap());
        assert!(store.is_nullifier_spent_for_replay(unrelated.limbs(), &empty, &staged).unwrap());
        assert!(store.is_nullifier_spent_for_replay(
            [POSEIDON2_V8_GOLDILOCKS_MODULUS; 7], &empty, &empty).is_err());
        // The callback is read-only; a rejected plan cannot release persisted NFs.
        assert_eq!(store.tip().unwrap(), tip);
        assert!(store.is_nullifier_spent(spent).unwrap());
    }

    #[test]
    fn asset_reference_snapshots_use_bounded_canonical_ancestry_and_exact_rows() {
        let (_, store, genesis, _, mut verifier) = asset_storage_fixture();
        let mut checkpoints = vec![genesis];
        for height in 1..=14 {
            let parent = *checkpoints.last().unwrap();
            let block = Poseidon2V8UnverifiedBlock::new(context(parent, 100 + height), &[]).unwrap();
            checkpoints.push(store.apply_verified_block(block, &mut verifier).unwrap());
        }
        let (reference, note, bytes) = store.asset_reference_snapshot(checkpoints[2].block_hash()).unwrap();
        assert_eq!(reference, checkpoints[2]);
        assert_eq!(note, empty_note_genesis_root());
        assert_eq!(super::super::asset_state::AssetRegistryStateV1::decode_exact(&bytes).unwrap().registry().context().parent_height, 2);
        assert!(store.asset_reference_snapshot(checkpoints[1].block_hash()).is_err());
        assert!(store.asset_reference_snapshot(hash(200)).is_err());
        store.disconnect_tip(checkpoints[14].block_hash()).unwrap();
        assert!(store.asset_reference_snapshot(checkpoints[14].block_hash()).is_err());
        assert_eq!(store.asset_reference_snapshot(checkpoints[1].block_hash()).unwrap().0, checkpoints[1]);
        // A structurally valid row from a different chain is never a
        // reference for this source-owned canonical genesis.
        let selected = checkpoints[2];
        let original = store.tree.get(asset_record_key(selected.block_hash())).unwrap().unwrap();
        let forged = super::super::asset_state::AssetRegistryStateV1::from_genesis_rows(hash(201), &[]).unwrap();
        let mut forged = forged;
        for height in 1..=2 { forged = forged.advance_parent(height).unwrap(); }
        store.tree.insert(asset_record_key(selected.block_hash()), forged.encode_exact().unwrap()).unwrap();
        assert!(matches!(store.asset_reference_snapshot(selected.block_hash()), Err(Poseidon2V8StateError::CorruptRecordLink)));
        store.tree.insert(asset_record_key(selected.block_hash()), original).unwrap();
        assert_eq!(store.asset_reference_snapshot(selected.block_hash()).unwrap().0, selected);
    }

    #[test]
    fn asset_snapshot_and_all_three_outputs_abort_with_shared_outer_transaction() {
        let (_, store, genesis, genesis_asset, mut verifier) = asset_storage_fixture();
        let leaves: [&[u8]; 1] = [b"fixture-asset"];
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 62), &leaves).unwrap();
        let plan = store
            .plan_verified_reorganization(&[], &[block], &mut verifier)
            .unwrap();
        let result: Result<(), TransactionError<String>> = store.tree.transaction(|tree| {
            Poseidon2V8StateStore::apply_canonical_plan_in_transaction(tree, &plan)?;
            Err(ConflictableTransactionError::Abort(
                "outer canonical abort".into(),
            ))
        });
        assert!(result.is_err());
        assert_eq!(store.tip().unwrap(), genesis);
        assert_eq!(
            store.asset_tip().unwrap().as_deref(),
            Some(genesis_asset.as_slice())
        );
        assert_eq!(store.note_tip().unwrap().leaf_count(), 0);
        assert!(!store.is_nullifier_spent(nullifier(91)).unwrap());
        assert!(store
            .tree
            .get(asset_record_key(block.context().block_hash()))
            .unwrap()
            .is_none());
    }

    #[test]
    fn asset_exact_parent_anchor_height_advance_and_one_action_limits_fail_atomically() {
        let (_, store, genesis, genesis_asset, mut verifier) = asset_storage_fixture();
        let leaves: [&[u8]; 1] = [b"fixture-asset"];
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 62), &leaves).unwrap();
        verifier.anchor = note_root(900);
        assert!(store.apply_verified_block(block, &mut verifier).is_err());
        verifier.anchor = empty_note_genesis_root();
        verifier.bad_advance = true;
        assert!(store.apply_verified_block(block, &mut verifier).is_err());
        verifier.bad_advance = false;
        let duplicate_leaves: [&[u8]; 2] = [b"fixture-asset", b"fixture-asset"];
        let duplicate_block =
            Poseidon2V8UnverifiedBlock::new(context(genesis, 62), &duplicate_leaves).unwrap();
        assert!(
            matches!(store.apply_verified_block(duplicate_block, &mut verifier), Err(Poseidon2V8StateError::ProofRejected(message)) if message == "at most one asset action per block")
        );
        assert_eq!(store.tip().unwrap(), genesis);
        assert_eq!(store.note_tip().unwrap().leaf_count(), 0);
        assert_eq!(
            store.asset_tip().unwrap().as_deref(),
            Some(genesis_asset.as_slice())
        );
        assert!(!store.is_nullifier_spent(nullifier(91)).unwrap());
    }

    #[test]
    fn record_lifetime_charges_five_proofs_for_one_segmented_recovery_spend() {
        let before = SmallwoodV8ProofLifetimeCount::genesis();
        let count = |n| SmallwoodV8ProofLifetimeCount::new(n).unwrap();
        assert_eq!(transaction_circuit::asset_recovery_wire_v1::PROOF_UNITS, 5);
        assert!(validate_record_proof_lifetime(before, count(0), 0).is_ok());
        assert!(validate_record_proof_lifetime(before, count(1), 1).is_ok());
        assert!(validate_record_proof_lifetime(before, count(5), 1).is_ok());
        assert!(validate_record_proof_lifetime(before, count(8), 4).is_ok());
        // No empty-block surcharge, obsolete three-proof cost, arbitrary
        // increment, or two recovery surcharges can pass the record link.
        for (leaves, units) in [(0, 4), (1, 2), (1, 3), (1, 4), (1, 6), (2, 10)] {
            assert!(validate_record_proof_lifetime(before, count(units), leaves).is_err());
        }
        assert!(validate_record_proof_lifetime(count(2), count(1), 1).is_err());
        let limit = MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK as u64;
        assert!(validate_record_proof_lifetime(before, count(limit),
            (limit - 4) as u32).is_ok());
        assert!(validate_record_proof_lifetime(before, count(limit + 1),
            (limit - 3) as u32).is_err());
    }

    #[test]
    fn replay_state_reserves_one_of_512_action_slots_for_v8_coinbase() {
        assert!(validate_block_proof_authority_action_count(
            MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK,
            false,
        )
        .is_ok());
        assert!(validate_block_proof_authority_action_count(
            MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK - 1,
            true,
        )
        .is_ok());
        assert_eq!(
            validate_block_proof_authority_action_count(MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK, true,),
            Err(Poseidon2V8StateError::TooManyLeaves)
        );
    }

    struct FixtureVerifier {
        calls: AtomicUsize,
        reject: bool,
    }

    struct ScriptedVerifier {
        transitions: VecDeque<Poseidon2V8PublicTransition>,
    }

    impl ScriptedVerifier {
        fn new(transitions: impl IntoIterator<Item = Poseidon2V8PublicTransition>) -> Self {
            Self {
                transitions: transitions.into_iter().collect(),
            }
        }
    }

    impl Poseidon2V8ExactLeafVerifier for ScriptedVerifier {
        fn native_leaf_profile(&self) -> Poseidon2V8NativeLeafProfile {
            Poseidon2V8NativeLeafProfile::Smz9
        }

        fn verify_exact_v8_leaf(
            &mut self,
            _block: Poseidon2V8BlockContext,
            _leaf_index: usize,
            _exact_native_leaf: &[u8],
        ) -> Result<Poseidon2V8PublicTransition, String> {
            self.transitions
                .pop_front()
                .ok_or_else(|| "missing scripted V8 transition".to_owned())
        }
    }

    fn note_root(seed: u64) -> Poseidon2V8NoteRoot {
        Poseidon2V8NoteRoot::new(core::array::from_fn(|index| seed + index as u64)).unwrap()
    }

    fn nullifier(seed: u64) -> Poseidon2V8Nullifier {
        Poseidon2V8Nullifier::new(core::array::from_fn(|index| seed + index as u64)).unwrap()
    }

    fn commitment(seed: u64) -> Poseidon2V8Commitment {
        Poseidon2V8Commitment::new(core::array::from_fn(|index| seed + index as u64)).unwrap()
    }

    fn shielded_transition(
        parent_height: u64,
        before: u64,
        after: u64,
        anchor: Poseidon2V8NoteRoot,
        nullifiers: [Option<Poseidon2V8Nullifier>; 2],
        commitments: [Option<Poseidon2V8Commitment>; 2],
    ) -> Poseidon2V8PublicTransition {
        Poseidon2V8PublicTransition::new_with_shielded_state(
            parent_height,
            root(before),
            root(after),
            anchor,
            nullifiers,
            commitments,
        )
    }

    impl FixtureVerifier {
        fn accepting() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                reject: false,
            }
        }

        fn rejecting() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                reject: true,
            }
        }
    }

    impl Poseidon2V8ExactLeafVerifier for FixtureVerifier {
        fn native_leaf_profile(&self) -> Poseidon2V8NativeLeafProfile {
            Poseidon2V8NativeLeafProfile::Smz9
        }

        fn verify_exact_v8_leaf(
            &mut self,
            block: Poseidon2V8BlockContext,
            _leaf_index: usize,
            exact_native_leaf: &[u8],
        ) -> Result<Poseidon2V8PublicTransition, String> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.reject {
                return Err("fixture proof rejection".to_owned());
            }
            if exact_native_leaf.len() != 2 {
                return Err("fixture leaf must encode before/after seed".to_owned());
            }
            Ok(Poseidon2V8PublicTransition::new(
                block.parent_height(),
                root(u64::from(exact_native_leaf[0])),
                root(u64::from(exact_native_leaf[1])),
            ))
        }
    }

    fn open_store(
        directory: &std::path::Path,
        genesis: Poseidon2V8Checkpoint,
    ) -> (sled::Db, Poseidon2V8StateStore) {
        let database = sled::open(directory).unwrap();
        let store =
            Poseidon2V8StateStore::open(&database, genesis, empty_note_genesis_root()).unwrap();
        (database, store)
    }

    fn empty_note_genesis_root() -> Poseidon2V8NoteRoot {
        Poseidon2V8NoteTreeState::new_empty().unwrap().root()
    }

    struct WindowTestVerifier {
        results: Vec<Result<Poseidon2V8PublicTransition, String>>,
        parallel: bool,
        verified: Vec<usize>,
        observed: Vec<Poseidon2V8PublicTransition>,
        windows: Vec<(usize, usize)>,
    }

    impl Poseidon2V8ExactLeafVerifier for WindowTestVerifier {
        fn native_leaf_profile(&self) -> Poseidon2V8NativeLeafProfile {
            Poseidon2V8NativeLeafProfile::Smz9
        }

        fn verify_exact_v8_leaf(
            &mut self,
            _block: Poseidon2V8BlockContext,
            leaf_index: usize,
            _exact_native_leaf: &[u8],
        ) -> Result<Poseidon2V8PublicTransition, String> {
            self.verified.push(leaf_index);
            let public = self.results[leaf_index].clone()?;
            self.observed.push(public);
            Ok(public)
        }

        fn verify_exact_v8_leaf_window(
            &mut self,
            _block: Poseidon2V8BlockContext,
            first: usize,
            leaves: &[&[u8]],
        ) -> Option<Vec<Result<Poseidon2V8PublicTransition, String>>> {
            if !self.parallel {
                return None;
            }
            assert!(leaves.len() <= POSEIDON2_V8_PROOF_VERIFICATION_WINDOW);
            self.windows.push((first, leaves.len()));
            // Deliberately compute in reverse order while returning indexed
            // results, modeling workers that finish out of order.
            self.verified.extend((first..first + leaves.len()).rev());
            Some(self.results[first..first + leaves.len()].to_vec())
        }

        fn record_window_verified_transition(&mut self, public: Poseidon2V8PublicTransition) {
            self.observed.push(public);
        }
    }

    fn window_test_verifier(
        count: usize,
        parallel: bool,
        state_failure: Option<usize>,
        proof_failures: &[usize],
    ) -> WindowTestVerifier {
        let results = (0..count)
            .map(|index| {
                if proof_failures.contains(&index) {
                    return Err(format!("fixture proof rejection at {index}"));
                }
                let stable_root = if state_failure == Some(index) {
                    root(11)
                } else {
                    root(10)
                };
                Ok(
                    Poseidon2V8PublicTransition::new_with_shielded_state_and_stablecoin_effect(
                        0,
                        stable_root,
                        stable_root,
                        Poseidon2V8StablecoinEffect::DisabledNoWrite,
                        empty_note_genesis_root(),
                        [Some(nullifier(1_000 + index as u64 * 64)), None],
                        [Some(commitment(50_000 + index as u64 * 128)), None],
                    ),
                )
            })
            .collect();
        WindowTestVerifier {
            results,
            parallel,
            verified: Vec::new(),
            observed: Vec::new(),
            windows: Vec::new(),
        }
    }

    #[test]
    fn bounded_proof_windows_match_serial_state_and_durable_rows() {
        for count in [0, 1, 2, 4, 5, 9] {
            let leaves = (0..count)
                .map(|index| vec![index as u8 + 1])
                .collect::<Vec<_>>();
            let leaf_refs = leaves.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(10));
            let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaf_refs).unwrap();
            let serial_directory = tempfile::tempdir().unwrap();
            let parallel_directory = tempfile::tempdir().unwrap();
            let (_serial_database, serial) = open_store(serial_directory.path(), genesis);
            let (_parallel_database, parallel) = open_store(parallel_directory.path(), genesis);
            let mut serial_verifier = window_test_verifier(count, false, None, &[]);
            let mut parallel_verifier = window_test_verifier(count, true, None, &[]);
            assert_eq!(
                serial
                    .apply_verified_block(block, &mut serial_verifier)
                    .unwrap(),
                parallel
                    .apply_verified_block(block, &mut parallel_verifier)
                    .unwrap()
            );
            assert_eq!(serial.note_tip().unwrap(), parallel.note_tip().unwrap());
            assert_eq!(serial_verifier.observed, parallel_verifier.observed);
            let rows = |store: &Poseidon2V8StateStore| {
                store
                    .tree
                    .iter()
                    .map(|row| {
                        let (key, value) = row.unwrap();
                        (key.to_vec(), value.to_vec())
                    })
                    .collect::<Vec<_>>()
            };
            assert_eq!(rows(&serial), rows(&parallel));
            assert_eq!(serial_verifier.verified, (0..count).collect::<Vec<_>>());
            assert!(parallel_verifier
                .windows
                .iter()
                .all(|(_, len)| *len <= POSEIDON2_V8_PROOF_VERIFICATION_WINDOW));
        }
    }

    #[test]
    fn bounded_proof_windows_preserve_first_proof_or_state_failure_and_stop_lookahead() {
        let count = 9;
        let leaves = (0..count)
            .map(|index| vec![index as u8 + 1])
            .collect::<Vec<_>>();
        let leaf_refs = leaves.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(10));
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaf_refs).unwrap();
        for first in [0, 1, 3, 4, 5, 8] {
            let cases = [
                (None, vec![first, 8]),
                (Some(first), vec![]),
                (
                    Some(first),
                    if first < 8 { vec![first + 1] } else { vec![] },
                ),
                (Some((first + 1).min(8)), vec![first]),
                (Some(first), vec![first]),
            ];
            for (state_failure, proof_failures) in cases {
                let serial_directory = tempfile::tempdir().unwrap();
                let parallel_directory = tempfile::tempdir().unwrap();
                let (_serial_database, serial) = open_store(serial_directory.path(), genesis);
                let (_parallel_database, parallel) = open_store(parallel_directory.path(), genesis);
                let mut serial_verifier =
                    window_test_verifier(count, false, state_failure, &proof_failures);
                let mut parallel_verifier =
                    window_test_verifier(count, true, state_failure, &proof_failures);
                let serial_error = serial
                    .apply_verified_block(block, &mut serial_verifier)
                    .unwrap_err();
                let parallel_error = parallel
                    .apply_verified_block(block, &mut parallel_verifier)
                    .unwrap_err();
                assert_eq!(serial_error, parallel_error);
                assert_eq!(serial_verifier.observed, parallel_verifier.observed);
                assert_eq!(serial.tip().unwrap(), genesis);
                assert_eq!(parallel.tip().unwrap(), genesis);
                assert_eq!(parallel.note_tip().unwrap().leaf_count(), 0);
                assert!(parallel.tree.get(record_key(hash(2))).unwrap().is_none());
                assert!(parallel_verifier.windows.iter().all(|(start, _)| *start
                    <= first / POSEIDON2_V8_PROOF_VERIFICATION_WINDOW
                        * POSEIDON2_V8_PROOF_VERIFICATION_WINDOW));
                assert!(
                    parallel_verifier.verified.len()
                        <= (first / POSEIDON2_V8_PROOF_VERIFICATION_WINDOW + 1)
                            * POSEIDON2_V8_PROOF_VERIFICATION_WINDOW
                );
            }
        }
    }

    #[test]
    fn bounded_proof_windows_reject_parent_and_leaf_caps_before_worker_dispatch() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(10));
        let (_database, store) = open_store(directory.path(), genesis);
        let leaves: [&[u8]; 2] = [&[1], &[2]];
        let wrong_parent = Poseidon2V8Checkpoint::new(0, hash(7), root(10));
        let block = Poseidon2V8UnverifiedBlock::new(context(wrong_parent, 2), &leaves).unwrap();
        let mut verifier = window_test_verifier(2, true, None, &[]);
        assert!(matches!(
            store.verify_uncommitted_block(block, &mut verifier),
            Err(Poseidon2V8StateError::ParentCheckpointMismatch { .. })
        ));
        assert!(verifier.windows.is_empty());
        assert!(verifier.verified.is_empty());
        let oversized = vec![0; POSEIDON2_PRODUCTION_MAX_NATIVE_LEAF_BYTES + 1];
        assert!(matches!(
            Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &[&oversized]),
            Err(Poseidon2V8StateError::LeafTooLarge { .. })
        ));
        let too_many = vec![&[1][..]; MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK + 1];
        assert!(matches!(
            Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &too_many),
            Err(Poseidon2V8StateError::TooManyLeaves)
        ));
    }

    fn reopen_store(
        directory: &std::path::Path,
        genesis: Poseidon2V8Checkpoint,
    ) -> (sled::Db, Poseidon2V8StateStore) {
        const MAX_ATTEMPTS: usize = 100;
        for attempt in 0..MAX_ATTEMPTS {
            match sled::open(directory) {
                Ok(database) => {
                    let store =
                        Poseidon2V8StateStore::open(&database, genesis, empty_note_genesis_root())
                            .unwrap();
                    return (database, store);
                }
                Err(error)
                    if attempt + 1 < MAX_ATTEMPTS
                        && error.to_string().contains("could not acquire lock") =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(error) => panic!("reopen V8 stablecoin state store failed: {error}"),
            }
        }
        unreachable!("bounded V8 state-store reopen loop always returns")
    }

    #[test]
    fn v8_root_codec_is_fresh_exact_and_canonical() {
        let candidate =
            Poseidon2V8Root::new([0, 1, 2, 3, 4, 5, POSEIDON2_V8_GOLDILOCKS_MODULUS - 1]).unwrap();
        let encoded = candidate.encode();
        assert_eq!(&encoded[..8], ROOT_MAGIC);
        assert_eq!(
            &encoded[8..16],
            &POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER.to_le_bytes()
        );
        assert_eq!(encoded.len(), 72);
        assert_eq!(Poseidon2V8Root::decode_exact(&encoded).unwrap(), candidate);

        let mut wrong_magic = encoded;
        wrong_magic[0] ^= 1;
        assert!(matches!(
            Poseidon2V8Root::decode_exact(&wrong_magic),
            Err(Poseidon2V8StateError::CodecMagic(_))
        ));
        assert!(matches!(
            Poseidon2V8Root::new([0, 1, 2, 3, 4, 5, POSEIDON2_V8_GOLDILOCKS_MODULUS]),
            Err(Poseidon2V8StateError::NonCanonicalRootLimb { index: 6, .. })
        ));
        assert!(Poseidon2V8Root::decode_exact(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn root_codec_rejects_predecessor_bytes_and_wrong_compression_mode() {
        let encoded = root(7).encode();
        let mut predecessor = [0u8; 64];
        predecessor[..8].copy_from_slice(b"P2V8RT01");
        predecessor[8..].copy_from_slice(&encoded[16..]);
        assert!(matches!(
            Poseidon2V8Root::decode_exact(&predecessor),
            Err(Poseidon2V8StateError::CodecMagic("V8 stablecoin root"))
        ));
        let mut wrong_mode = encoded;
        wrong_mode[8] ^= 1;
        assert!(matches!(
            Poseidon2V8Root::decode_exact(&wrong_mode),
            Err(Poseidon2V8StateError::CodecCompressionMode {
                label: "V8 stablecoin root",
                ..
            })
        ));
    }

    #[test]
    fn note_state_v3_codec_roundtrips_canonical_empty_defaults_exactly() {
        let state = Poseidon2V8NoteTreeState::new_empty().unwrap();
        assert_eq!(
            state.frontier.as_slice(),
            &state.default_nodes[..CIRCUIT_MERKLE_DEPTH]
        );

        let encoded = state.encode().unwrap();
        assert_eq!(&encoded[..NOTE_STATE_MAGIC.len()], NOTE_STATE_MAGIC);
        assert_eq!(
            &encoded[8..16],
            &POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER.to_le_bytes()
        );
        assert_eq!(
            Poseidon2V8NoteTreeState::decode_exact(&encoded).unwrap(),
            state
        );
    }

    #[test]
    fn persisted_note_state_v2_and_wrong_mode_are_rejected_before_frontier_decode() {
        let mut state = Poseidon2V8NoteTreeState::new_empty().unwrap();
        state.append(commitment(700)).unwrap();
        let encoded = state.encode().unwrap();
        let mut predecessor = Vec::with_capacity(encoded.len() - 8);
        predecessor.extend_from_slice(b"P2V8NT02");
        predecessor.extend_from_slice(&encoded[16..]);
        assert!(matches!(
            Poseidon2V8NoteTreeState::decode_exact(&predecessor),
            Err(Poseidon2V8StateError::CodecMagic("V8 note-tree state"))
        ));
        let mut wrong_mode = encoded;
        wrong_mode[8] ^= 1;
        assert!(matches!(
            Poseidon2V8NoteTreeState::decode_exact(&wrong_mode),
            Err(Poseidon2V8StateError::CodecCompressionMode {
                label: "V8 note-tree state",
                ..
            })
        ));
    }

    #[test]
    fn opening_predecessor_root_or_frontier_preserves_stored_bytes() {
        for old_root in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let database = sled::open(directory.path()).unwrap();
            let tree = database.open_tree(POSEIDON2_V8_STATE_TREE_NAME).unwrap();
            let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(1));
            let encoded = genesis.encode();
            let mut predecessor_checkpoint = Vec::with_capacity(encoded.len() - 8);
            predecessor_checkpoint.extend_from_slice(&encoded[..48]);
            predecessor_checkpoint.extend_from_slice(b"P2V8RT01");
            predecessor_checkpoint.extend_from_slice(&encoded[64..]);
            let checkpoint = if old_root {
                predecessor_checkpoint.as_slice()
            } else {
                encoded.as_slice()
            };
            let note_state = Poseidon2V8NoteTreeState::new_empty()
                .unwrap()
                .encode()
                .unwrap();
            let mut predecessor_note_state = Vec::with_capacity(note_state.len() - 8);
            predecessor_note_state.extend_from_slice(b"P2V8NT02");
            predecessor_note_state.extend_from_slice(&note_state[16..]);
            tree.insert(GENESIS_KEY, checkpoint).unwrap();
            tree.insert(TIP_KEY, checkpoint).unwrap();
            tree.insert(NOTE_TIP_KEY, predecessor_note_state.as_slice())
                .unwrap();
            tree.insert(
                PROOF_LIFETIME_TIP_KEY,
                SmallwoodV8ProofLifetimeCount::genesis().encode().as_slice(),
            )
            .unwrap();
            tree.insert(height_key(0), genesis.block_hash.as_slice())
                .unwrap();
            tree.flush().unwrap();
            let before = tree.iter().collect::<Result<Vec<_>, _>>().unwrap();
            let error = Poseidon2V8StateStore::open(&database, genesis, empty_note_genesis_root())
                .err()
                .expect("predecessor state must fail closed");
            if old_root {
                assert!(
                    matches!(error, Poseidon2V8StateError::StorageConflict(ref message)
                    if message == "stored V8 stablecoin genesis checkpoint mismatch")
                );
            } else {
                assert!(matches!(
                    error,
                    Poseidon2V8StateError::CodecMagic("V8 note-tree state")
                ));
            }
            assert_eq!(tree.iter().collect::<Result<Vec<_>, _>>().unwrap(), before);
        }
    }

    #[test]
    fn persisted_note_state_v1_magic_is_rejected_after_default_leaf_migration() {
        let mut legacy = Poseidon2V8NoteTreeState::new_empty()
            .unwrap()
            .encode()
            .unwrap();
        legacy[..NOTE_STATE_MAGIC.len()].copy_from_slice(b"P2V8NT01");

        assert!(matches!(
            Poseidon2V8NoteTreeState::decode_exact(&legacy),
            Err(Poseidon2V8StateError::CodecMagic("V8 note-tree state"))
        ));
    }

    #[test]
    fn decoded_note_state_continues_append_identically_after_restart() {
        let mut uninterrupted = Poseidon2V8NoteTreeState::new_empty().unwrap();
        uninterrupted.append(commitment(700)).unwrap();
        uninterrupted.append(commitment(800)).unwrap();

        let persisted = uninterrupted.encode().unwrap();
        let mut restarted = Poseidon2V8NoteTreeState::decode_exact(&persisted).unwrap();
        assert_eq!(restarted, uninterrupted);

        let expected_root = uninterrupted.append(commitment(900)).unwrap();
        let restarted_root = restarted.append(commitment(900)).unwrap();
        assert_eq!(restarted_root, expected_root);
        assert_eq!(restarted, uninterrupted);
    }

    #[test]
    fn note_genesis_is_explicit_source_derived_empty_root_only() {
        let expected = empty_note_genesis_root();
        assert_eq!(
            expected.limbs(),
            protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NOTE_GENESIS_ROOT
        );
        // Historical suite-marker/raw-output empty root is rejected.
        assert_ne!(
            expected.limbs(),
            [
                17_350_853_413_121_414_251,
                11_311_714_906_264_832_276,
                5_494_323_263_975_105_675,
                16_684_950_828_932_818_263,
                7_241_422_828_316_666_478,
                13_669_884_728_521_486_080,
                15_137_873_680_347_988_554,
            ]
        );

        let directory = tempfile::tempdir().unwrap();
        let database = sled::open(directory.path()).unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(1));
        let unsupported = Poseidon2V8NoteRoot::new([1, 2, 3, 4, 5, 6, 7]).unwrap();
        assert!(matches!(
            Poseidon2V8StateStore::open(&database, genesis, unsupported),
            Err(Poseidon2V8StateError::UnsupportedNoteGenesisRoot {
                expected: observed_expected,
                observed,
            }) if observed_expected == expected && observed == unsupported
        ));
        assert!(!database
            .tree_names()
            .iter()
            .any(|name| name.as_ref() == POSEIDON2_V8_STATE_TREE_NAME));

        let store = Poseidon2V8StateStore::open(&database, genesis, expected).unwrap();
        assert_eq!(store.note_tip().unwrap().root(), expected);
    }

    #[test]
    fn context_and_store_reject_heights_outside_the_v8_relation() {
        assert!(matches!(
            Poseidon2V8BlockContext::new(
                POSEIDON2_V8_MAX_SCALAR,
                hash(1),
                POSEIDON2_V8_MAX_SCALAR.saturating_add(1),
                hash(2),
            ),
            Err(Poseidon2V8StateError::HeightExceedsRelationScalar { .. })
        ));

        let directory = tempfile::tempdir().unwrap();
        let database = sled::open(directory.path()).unwrap();
        assert!(matches!(
            Poseidon2V8StateStore::open(
                &database,
                Poseidon2V8Checkpoint::new(
                    POSEIDON2_V8_MAX_SCALAR.saturating_add(1),
                    hash(1),
                    root(1),
                ),
                empty_note_genesis_root(),
            ),
            Err(Poseidon2V8StateError::HeightExceedsRelationScalar { .. })
        ));
        assert!(!database
            .tree_names()
            .iter()
            .any(|name| name.as_ref() == POSEIDON2_V8_STATE_TREE_NAME));
    }

    #[test]
    fn rejected_proof_cannot_change_or_persist_state() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(10));
        let (_database, store) = open_store(directory.path(), genesis);
        let leaves: [&[u8]; 1] = [&[10, 11]];
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaves).unwrap();
        let mut verifier = FixtureVerifier::rejecting();
        assert!(matches!(
            store.apply_verified_block(block, &mut verifier),
            Err(Poseidon2V8StateError::ProofRejected(_))
        ));
        assert_eq!(verifier.calls.load(Ordering::Relaxed), 1);
        assert_eq!(store.tip().unwrap(), genesis);
        assert!(store.tree.get(record_key(hash(2))).unwrap().is_none());
    }

    #[test]
    fn verified_leaf_with_wrong_public_before_root_cannot_commit() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(10));
        let (_database, store) = open_store(directory.path(), genesis);
        let leaves: [&[u8]; 1] = [&[99, 100]];
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaves).unwrap();
        let mut verifier = FixtureVerifier::accepting();
        assert!(matches!(
            store.apply_verified_block(block, &mut verifier),
            Err(Poseidon2V8StateError::ProofBeforeRootMismatch { .. })
        ));
        assert_eq!(verifier.calls.load(Ordering::Relaxed), 1);
        assert_eq!(store.tip().unwrap(), genesis);
        assert!(store.tree.get(record_key(hash(2))).unwrap().is_none());
    }

    #[test]
    fn verifier_returned_stablecoin_effect_must_match_public_roots_before_state_writes() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(10));
        let (_database, store) = open_store(directory.path(), genesis);
        let empty_note = Poseidon2V8NoteTreeState::new_empty().unwrap();
        let leaves: [&[u8]; 1] = [&[0x51]];
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaves).unwrap();
        let forged_transitions = [
            Poseidon2V8PublicTransition::new_with_shielded_state_and_stablecoin_effect(
                0,
                root(10),
                root(11),
                Poseidon2V8StablecoinEffect::DisabledNoWrite,
                empty_note.root(),
                [None, None],
                [None, None],
            ),
            Poseidon2V8PublicTransition::new_with_shielded_state_and_stablecoin_effect(
                0,
                root(10),
                root(10),
                Poseidon2V8StablecoinEffect::Mint,
                empty_note.root(),
                [None, None],
                [None, None],
            ),
        ];

        for transition in forged_transitions {
            assert!(matches!(
                store.verify_uncommitted_block(block, &mut ScriptedVerifier::new([transition]),),
                Err(Poseidon2V8StateError::StablecoinEffectMismatch { .. })
            ));
            assert_eq!(store.tip().unwrap(), genesis);
            assert!(store.tree.get(record_key(hash(2))).unwrap().is_none());
        }
    }

    #[test]
    fn block_apply_chains_all_leaf_roots_and_rejects_double_or_same_parent_apply() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(10));
        let (_database, store) = open_store(directory.path(), genesis);
        let leaves: [&[u8]; 2] = [&[10, 11], &[11, 12]];
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaves).unwrap();
        let mut verifier = FixtureVerifier::accepting();
        let tip = store.apply_verified_block(block, &mut verifier).unwrap();
        assert_eq!(tip, Poseidon2V8Checkpoint::new(1, hash(2), root(12)));
        assert_eq!(verifier.calls.load(Ordering::Relaxed), 2);

        let calls_before = verifier.calls.load(Ordering::Relaxed);
        assert!(matches!(
            store.apply_verified_block(block, &mut verifier),
            Err(Poseidon2V8StateError::ParentCheckpointMismatch { .. })
        ));
        let sibling = Poseidon2V8UnverifiedBlock::new(context(genesis, 3), &leaves).unwrap();
        assert!(matches!(
            store.apply_verified_block(sibling, &mut verifier),
            Err(Poseidon2V8StateError::ParentCheckpointMismatch { .. })
        ));
        assert_eq!(verifier.calls.load(Ordering::Relaxed), calls_before);
        assert_eq!(store.tip().unwrap(), tip);
    }

    #[test]
    fn restart_reloads_exact_persisted_tip_and_rejects_other_genesis() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(20));
        let expected_tip = {
            let (database, store) = open_store(directory.path(), genesis);
            let leaves: [&[u8]; 1] = [&[20, 21]];
            let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaves).unwrap();
            let mut verifier = FixtureVerifier::accepting();
            let tip = store.apply_verified_block(block, &mut verifier).unwrap();
            drop(store);
            drop(database);
            tip
        };
        let (database, reopened) = reopen_store(directory.path(), genesis);
        assert_eq!(reopened.tip().unwrap(), expected_tip);
        assert!(matches!(
            Poseidon2V8StateStore::open(
                &database,
                Poseidon2V8Checkpoint::new(0, hash(9), root(20)),
                empty_note_genesis_root(),
            ),
            Err(Poseidon2V8StateError::StorageConflict(_))
        ));
    }

    #[test]
    fn disconnect_and_atomic_reorg_restore_then_replace_the_root() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(30));
        let (_database, store) = open_store(directory.path(), genesis);
        let a1_leaves: [&[u8]; 1] = [&[30, 31]];
        let a1 = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &a1_leaves).unwrap();
        let a1_tip = Poseidon2V8Checkpoint::new(1, hash(2), root(31));
        let a2_leaves: [&[u8]; 1] = [&[31, 32]];
        let a2 = Poseidon2V8UnverifiedBlock::new(context(a1_tip, 3), &a2_leaves).unwrap();
        let mut verifier = FixtureVerifier::accepting();
        store
            .replay_verified_suffix(&[a1, a2], &mut verifier)
            .unwrap();

        let b1_leaves: [&[u8]; 1] = [&[30, 40]];
        let b1 = Poseidon2V8UnverifiedBlock::new(context(genesis, 4), &b1_leaves).unwrap();
        let b1_tip = Poseidon2V8Checkpoint::new(1, hash(4), root(40));
        let b2_leaves: [&[u8]; 1] = [&[40, 41]];
        let b2 = Poseidon2V8UnverifiedBlock::new(context(b1_tip, 5), &b2_leaves).unwrap();
        let plan = store
            .plan_verified_reorganization(&[hash(3), hash(2)], &[b1, b2], &mut verifier)
            .unwrap();
        assert_eq!(plan.attach_parent(), genesis);
        assert_eq!(
            store.tip().unwrap(),
            Poseidon2V8Checkpoint::new(2, hash(3), root(32))
        );
        let tip = store.apply_verified_canonical_plan(&plan).unwrap();
        assert_eq!(tip, Poseidon2V8Checkpoint::new(2, hash(5), root(41)));
        assert!(store.tree.get(record_key(hash(2))).unwrap().is_none());
        assert!(store.tree.get(record_key(hash(3))).unwrap().is_none());
        assert!(store.tree.get(record_key(hash(4))).unwrap().is_some());
        assert!(store.tree.get(record_key(hash(5))).unwrap().is_some());

        assert_eq!(store.disconnect_tip(hash(5)).unwrap(), b1_tip);
        assert_eq!(store.disconnect_tip(hash(4)).unwrap(), genesis);
    }

    #[test]
    fn corrupted_durable_block_record_fails_closed_before_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(45));
        let (_database, store) = open_store(directory.path(), genesis);
        let leaves: [&[u8]; 1] = [&[45, 46]];
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaves).unwrap();
        let mut verifier = FixtureVerifier::accepting();
        let tip = store.apply_verified_block(block, &mut verifier).unwrap();

        let key = record_key(hash(2));
        let mut encoded = store.tree.get(&key).unwrap().unwrap().to_vec();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        store.tree.insert(&key, encoded).unwrap();
        store.tree.flush().unwrap();
        assert!(matches!(
            store.disconnect_tip(hash(2)),
            Err(Poseidon2V8StateError::CorruptRecordDigest)
        ));
        assert_eq!(store.tip().unwrap(), tip);
    }

    #[test]
    fn replacement_suffix_is_fully_verified_before_atomic_commit() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(50));
        let (_database, store) = open_store(directory.path(), genesis);
        let a_leaves: [&[u8]; 1] = [&[50, 51]];
        let a = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &a_leaves).unwrap();
        let mut accepting = FixtureVerifier::accepting();
        let old_tip = store.apply_verified_block(a, &mut accepting).unwrap();

        let b_leaves: [&[u8]; 1] = [&[50, 60]];
        let b = Poseidon2V8UnverifiedBlock::new(context(genesis, 3), &b_leaves).unwrap();
        let mut rejecting = FixtureVerifier::rejecting();
        assert!(matches!(
            store.reorganize_verified(&[hash(2)], &[b], &mut rejecting),
            Err(Poseidon2V8StateError::ProofRejected(_))
        ));
        assert_eq!(store.tip().unwrap(), old_tip);
        assert!(store.tree.get(record_key(hash(2))).unwrap().is_some());
        assert!(store.tree.get(record_key(hash(3))).unwrap().is_none());
    }

    #[test]
    fn fresh_node_sync_replay_converges_on_identical_checkpoint() {
        let first_directory = tempfile::tempdir().unwrap();
        let fresh_directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(70));
        let (_first_database, first) = open_store(first_directory.path(), genesis);
        let (_fresh_database, fresh) = open_store(fresh_directory.path(), genesis);
        let leaves1: [&[u8]; 1] = [&[70, 71]];
        let block1 = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaves1).unwrap();
        let tip1 = Poseidon2V8Checkpoint::new(1, hash(2), root(71));
        let empty: [&[u8]; 0] = [];
        let block2 = Poseidon2V8UnverifiedBlock::new(context(tip1, 3), &empty).unwrap();
        let blocks = [block1, block2];
        let mut first_verifier = FixtureVerifier::accepting();
        let first_tip = first
            .replay_verified_suffix(&blocks, &mut first_verifier)
            .unwrap();
        let mut fresh_verifier = FixtureVerifier::accepting();
        let fresh_tip = fresh
            .replay_verified_suffix(&blocks, &mut fresh_verifier)
            .unwrap();
        assert_eq!(first_tip, fresh_tip);
        assert_eq!(fresh_tip, Poseidon2V8Checkpoint::new(2, hash(3), root(71)));
    }

    #[test]
    fn proof_lifetime_count_is_atomic_persistent_and_reorg_replay_deterministic() {
        let canonical_directory = tempfile::tempdir().unwrap();
        let fresh_directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(100));
        let a_leaves: [&[u8]; 2] = [&[100, 101], &[101, 102]];
        let a = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &a_leaves).unwrap();
        let a_tip = Poseidon2V8Checkpoint::new(1, hash(2), root(102));

        {
            let (database, store) = open_store(canonical_directory.path(), genesis);
            assert_eq!(store.proof_lifetime_count().unwrap().get(), 0);
            store
                .apply_verified_block(a, &mut FixtureVerifier::accepting())
                .unwrap();
            assert_eq!(store.proof_lifetime_count().unwrap().get(), 2);
            drop(store);
            drop(database);
        }

        let (_database, canonical) = reopen_store(canonical_directory.path(), genesis);
        assert_eq!(canonical.tip().unwrap(), a_tip);
        assert_eq!(canonical.proof_lifetime_count().unwrap().get(), 2);

        let b_leaves: [&[u8]; 1] = [&[102, 103]];
        let b = Poseidon2V8UnverifiedBlock::new(context(a_tip, 3), &b_leaves).unwrap();
        canonical
            .verify_uncommitted_block(b, &mut FixtureVerifier::accepting())
            .unwrap();
        assert_eq!(
            canonical.proof_lifetime_count().unwrap().get(),
            2,
            "verification without canonical commit changed the durable counter"
        );
        canonical
            .apply_verified_block(b, &mut FixtureVerifier::accepting())
            .unwrap();
        assert_eq!(canonical.proof_lifetime_count().unwrap().get(), 3);

        let replacement_leaves: [&[u8]; 2] = [&[102, 110], &[110, 111]];
        let replacement =
            Poseidon2V8UnverifiedBlock::new(context(a_tip, 4), &replacement_leaves).unwrap();
        canonical
            .reorganize_verified(
                &[hash(3)],
                &[replacement],
                &mut FixtureVerifier::accepting(),
            )
            .unwrap();
        assert_eq!(canonical.proof_lifetime_count().unwrap().get(), 4);

        let (_fresh_database, fresh) = open_store(fresh_directory.path(), genesis);
        fresh
            .replay_verified_suffix(&[a, replacement], &mut FixtureVerifier::accepting())
            .unwrap();
        assert_eq!(fresh.proof_lifetime_count().unwrap().get(), 4);
        assert!(canonical.exact_rows_equal(&fresh).unwrap());
    }

    // Host-only storage fixture: effects are supplied after the same framing,
    // reference and accounting gates. This does not verify a cryptographic proof.
    struct LifetimeLaunchFixture {
        context: LaunchReferenceContext,
        references: Option<CanonicalLaunchReferences>,
        limit: Option<u64>,
        ongoing: bool,
        actions: Option<usize>,
        proof_calls: usize,
    }

    impl Poseidon2V8ExactLeafVerifier for LifetimeLaunchFixture {
        fn native_leaf_profile(&self) -> Poseidon2V8NativeLeafProfile {
            Poseidon2V8NativeLeafProfile::LaunchMixed
        }
        fn launch_proof_lifetime_limit(&self) -> Option<u64> {
            self.limit
        }
        fn launch_has_ongoing_hgn_authority(&self) -> bool {
            self.ongoing
        }
        fn launch_proof_action_limit(&self) -> Option<usize> {
            self.actions
        }
        fn launch_reference_context(&self) -> Option<LaunchReferenceContext> {
            Some(self.context)
        }
        fn set_launch_references(
            &mut self,
            references: CanonicalLaunchReferences,
        ) -> Result<(), String> {
            if references.context() != self.context {
                return Err("wrong audit fixture context".into());
            }
            self.references = Some(references);
            Ok(())
        }
        fn verify_exact_v8_leaf(
            &mut self,
            block: Poseidon2V8BlockContext,
            _: usize,
            _: &[u8],
        ) -> Result<Poseidon2V8PublicTransition, String> {
            self.proof_calls += 1;
            let references = self
                .references
                .as_ref()
                .ok_or("missing audit fixture references")?;
            let mut base = transaction_circuit::smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8PublicStatement::default();
            base.stablecoin.parent_height = block.parent_height();
            base.merkle_root = references.parent_note_anchor().limbs();
            let public = transaction_circuit::smallwood_poseidon2_v8_rp06::Rp06PublicStatement {
                base,
                chain_id: self.context_chain_id(),
            };
            let checked = references.validate_rp06(&public, block)?;
            Poseidon2V8PublicTransition::new_with_shielded_state_and_stablecoin_effect(
                block.parent_height(),
                root_zero(),
                root_zero(),
                Poseidon2V8StablecoinEffect::DisabledNoWrite,
                references.parent_note_anchor(),
                [None; 2],
                [None; 2],
            )
            .with_checked_launch_reference(checked)
        }
    }

    impl LifetimeLaunchFixture {
        fn context_chain_id(&self) -> [u8; 32] {
            // Same inert identity used to construct the checked test context.
            crate::native::network_profile::NativeNetworkIdentity::development().chain_id()
        }
    }

    fn root_zero() -> Poseidon2V8Root {
        Poseidon2V8Root::new([0; 7]).unwrap()
    }

    fn ongoing_lifetime_fixture() -> (
        crate::native::launch_v8_verifier::LaunchStartup,
        LifetimeLaunchFixture,
    ) {
        let startup =
            crate::native::launch_v8_verifier::LaunchStartup::qualification_ongoing_hgn_for_test(
                &crate::native::network_profile::NativeNetworkIdentity::development(),
                [2; 32],
                root_zero(),
            )
            .unwrap();
        let verifier = LifetimeLaunchFixture {
            context: LaunchReferenceContext::from_startup(startup).unwrap(),
            references: None,
            limit: None,
            ongoing: true,
            actions: Some(512),
            proof_calls: 0,
        };
        (startup, verifier)
    }

    fn seed_synthetic_audit_anchor(store: &Poseidon2V8StateStore, count: u64) {
        // Deliberately seed an audited-prefix count instead of constructing
        // hundreds of millions of proofs. Only recurrence/storage is tested.
        store
            .tree
            .insert(PROOF_LIFETIME_TIP_KEY, count.to_le_bytes().as_slice())
            .unwrap();
    }

    #[test]
    fn ongoing_hgn_audit_crosses_old_quota_with_restart_reorg_and_replay() {
        let directory = tempfile::tempdir().unwrap();
        let fresh_directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, [2; 32], root_zero());
        let baseline = super::super::smallwood_v8_lifetime::SMALLWOOD_V8_CONDITIONAL_MAX_TOTAL_PROOFS_AT_128_BITS - 1;
        let (startup, mut verifier) = ongoing_lifetime_fixture();
        let leaf = launch_shape_only_leaf(startup);
        let one = [leaf.as_slice()];
        let two = [leaf.as_slice(); 2];
        let three = [leaf.as_slice(); 3];
        let a = Poseidon2V8UnverifiedBlock::new(context(genesis, 3), &one).unwrap();
        let a_tip = Poseidon2V8Checkpoint::new(1, hash(3), root_zero());
        let b = Poseidon2V8UnverifiedBlock::new(context(a_tip, 4), &two).unwrap();
        let replacement = Poseidon2V8UnverifiedBlock::new(context(a_tip, 5), &three).unwrap();
        {
            let (database, store) = open_store(directory.path(), genesis);
            seed_synthetic_audit_anchor(&store, baseline);
            store
                .replay_verified_suffix(&[a, b], &mut verifier)
                .unwrap();
            assert_eq!(store.proof_lifetime_count().unwrap().get(), baseline + 3);
            let record = store.load_record(hash(4)).unwrap();
            assert_eq!(record.after_proof_lifetime.get(), baseline + 3);
            assert_eq!(
                Poseidon2V8BlockRecord::decode_exact(&record.encode().unwrap()).unwrap(),
                record
            );
            drop(store);
            drop(database);
        }
        let (_database, store) = reopen_store(directory.path(), genesis);
        assert_eq!(store.proof_lifetime_count().unwrap().get(), baseline + 3);
        store
            .reorganize_verified(
                &[hash(4)],
                &[replacement],
                &mut ongoing_lifetime_fixture().1,
            )
            .unwrap();
        assert_eq!(store.proof_lifetime_count().unwrap().get(), baseline + 4);
        let (_fresh_database, fresh) = open_store(fresh_directory.path(), genesis);
        seed_synthetic_audit_anchor(&fresh, baseline);
        fresh
            .replay_verified_suffix(&[a, replacement], &mut ongoing_lifetime_fixture().1)
            .unwrap();
        assert_eq!(fresh.proof_lifetime_count().unwrap().get(), baseline + 4);
        assert!(store.exact_rows_equal(&fresh).unwrap());
        store.disconnect_tip(hash(5)).unwrap();
        assert_eq!(store.proof_lifetime_count().unwrap().get(), baseline + 1);
    }

    #[test]
    fn ongoing_hgn_accounting_requires_explicit_authority_and_preserves_old_source_quotas() {
        let genesis = Poseidon2V8Checkpoint::new(0, [2; 32], root_zero());
        let (startup, _) = ongoing_lifetime_fixture();
        let leaf = launch_shape_only_leaf(startup);
        let leaves = [leaf.as_slice(); 2];
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 3), &leaves).unwrap();
        for (limit, ongoing, actions, expected) in [
            (None, false, Some(512), "source lifetime budget"),
            (Some(0), true, Some(512), "source lifetime budget"),
            (
                Some(1),
                false,
                Some(512),
                "source action/lifetime budget exceeded",
            ),
            (
                Some(1),
                true,
                Some(512),
                "source action/lifetime budget exceeded",
            ),
            (None, true, None, "source action budget"),
            (None, true, Some(513), "source action budget"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let (_db, store) = open_store(directory.path(), genesis);
            let mut verifier = ongoing_lifetime_fixture().1;
            verifier.limit = limit;
            verifier.ongoing = ongoing;
            verifier.actions = actions;
            assert!(matches!(store.apply_verified_block(block, &mut verifier),
                Err(Poseidon2V8StateError::ProofRejected(message)) if message.contains(expected)));
            assert_eq!(verifier.proof_calls, 0);
            assert_eq!(store.tip().unwrap(), genesis);
            assert_eq!(store.proof_lifetime_count().unwrap().get(), 0);
        }
        // Full-width codec admission does not reopen bounded historical source
        // authority, even for an empty replay/reorganization suffix.
        let directory = tempfile::tempdir().unwrap();
        let (_db, store) = open_store(directory.path(), genesis);
        let beyond = super::super::smallwood_v8_lifetime::SMALLWOOD_V8_CONDITIONAL_MAX_TOTAL_PROOFS_AT_128_BITS + 1;
        seed_synthetic_audit_anchor(&store, beyond);
        assert!(matches!(
            store.plan_verified_reorganization(&[], &[], &mut FixtureVerifier::accepting()),
            Err(Poseidon2V8StateError::ProofLifetime(
                SmallwoodV8ProofLifetimeError::PersistedCountExceedsConditionalMaximum { .. }
            ))
        ));
        let mut bounded = ongoing_lifetime_fixture().1;
        bounded.limit = Some(100);
        bounded.ongoing = false;
        assert!(
            matches!(store.plan_verified_reorganization(&[], &[], &mut bounded),
            Err(Poseidon2V8StateError::ProofRejected(message)) if message.contains("source action/lifetime budget exceeded"))
        );
        assert_eq!(store.proof_lifetime_count().unwrap().get(), beyond);
    }

    #[test]
    fn ongoing_hgn_preserves_u64_overflow_and_reward_action_limits() {
        let genesis = Poseidon2V8Checkpoint::new(0, [2; 32], root_zero());
        let (startup, _) = ongoing_lifetime_fixture();
        let leaf = launch_shape_only_leaf(startup);
        let leaves = [leaf.as_slice()];
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 3), &leaves).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let (_db, store) = open_store(directory.path(), genesis);
        seed_synthetic_audit_anchor(&store, u64::MAX);
        let mut verifier = ongoing_lifetime_fixture().1;
        assert!(matches!(
            store.apply_verified_block(block, &mut verifier),
            Err(Poseidon2V8StateError::ProofLifetime(
                SmallwoodV8ProofLifetimeError::CountOverflow
            ))
        ));
        assert_eq!(verifier.proof_calls, 0);
        assert_eq!(store.proof_lifetime_count().unwrap().get(), u64::MAX);
        let directory2 = tempfile::tempdir().unwrap();
        let (_db2, rewards) = open_store(directory2.path(), genesis);
        let reward_block = Poseidon2V8UnverifiedBlock::new_with_trailing_rewards(
            context(genesis, 3),
            &leaves,
            [Some(commitment(3)), Some(commitment(4))],
        )
        .unwrap();
        let mut verifier = ongoing_lifetime_fixture().1;
        verifier.actions = Some(1);
        assert!(
            matches!(rewards.apply_verified_block(reward_block, &mut verifier),
            Err(Poseidon2V8StateError::ProofRejected(message)) if message.contains("source action/lifetime budget exceeded"))
        );
        assert_eq!(verifier.proof_calls, 0);
        assert_eq!(rewards.proof_lifetime_count().unwrap().get(), 0);
        assert!(matches!(
            validate_block_proof_authority_action_count(512, true),
            Err(Poseidon2V8StateError::TooManyLeaves)
        ));
        assert!(validate_block_proof_authority_action_count(511, true).is_ok());
    }

    #[test]
    fn malformed_persisted_proof_lifetime_count_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(115));
        let (_database, store) = open_store(directory.path(), genesis);
        store.tree.insert(PROOF_LIFETIME_TIP_KEY, &[0u8; 7]).unwrap();
        assert!(matches!(store.proof_lifetime_count(),
            Err(Poseidon2V8StateError::ProofLifetime(
                SmallwoodV8ProofLifetimeError::CodecLength { .. }
            ))));
    }

    #[test]
    fn empty_block_advances_exact_checkpoint_without_invoking_leaf_verifier() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(75));
        let expected = Poseidon2V8Checkpoint::new(1, hash(2), root(75));
        {
            let (database, store) = open_store(directory.path(), genesis);
            let leaves: [&[u8]; 0] = [];
            let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaves).unwrap();
            let mut verifier = FixtureVerifier::rejecting();
            assert_eq!(
                store.apply_verified_block(block, &mut verifier).unwrap(),
                expected
            );
            assert_eq!(verifier.calls.load(Ordering::Relaxed), 0);
            assert!(store.tree.get(record_key(hash(2))).unwrap().is_some());
            drop(store);
            drop(database);
        }
        let (_database, reopened) = reopen_store(directory.path(), genesis);
        assert_eq!(reopened.tip().unwrap(), expected);
        assert_eq!(
            reopened.note_tip().unwrap(),
            Poseidon2V8NoteTreeState::new_empty().unwrap()
        );
    }

    #[test]
    fn side_branch_suffix_is_verified_from_common_ancestor_not_current_tip() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(90));
        let (_database, store) = open_store(directory.path(), genesis);
        let a1_leaves: [&[u8]; 1] = [&[90, 91]];
        let a1 = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &a1_leaves).unwrap();
        let a1_tip = Poseidon2V8Checkpoint::new(1, hash(2), root(91));
        let a2_leaves: [&[u8]; 1] = [&[91, 92]];
        let a2 = Poseidon2V8UnverifiedBlock::new(context(a1_tip, 3), &a2_leaves).unwrap();
        let mut canonical_verifier = FixtureVerifier::accepting();
        store
            .replay_verified_suffix(&[a1, a2], &mut canonical_verifier)
            .unwrap();
        let old_tip = Poseidon2V8Checkpoint::new(2, hash(3), root(92));
        assert_eq!(store.tip().unwrap(), old_tip);

        let side2_leaves: [&[u8]; 1] = [&[91, 100]];
        let side2 = Poseidon2V8UnverifiedBlock::new(context(a1_tip, 4), &side2_leaves).unwrap();
        let side2_tip = Poseidon2V8Checkpoint::new(2, hash(4), root(100));
        let side3_leaves: [&[u8]; 1] = [&[100, 101]];
        let side3 = Poseidon2V8UnverifiedBlock::new(context(side2_tip, 5), &side3_leaves).unwrap();
        let mut branch_verifier = FixtureVerifier::accepting();
        let plan = store
            .plan_verified_reorganization(&[hash(3)], &[side2, side3], &mut branch_verifier)
            .unwrap();
        assert_eq!(branch_verifier.calls.load(Ordering::Relaxed), 2);
        assert_eq!(plan.attach_parent(), a1_tip);
        assert_eq!(
            plan.final_tip(),
            Poseidon2V8Checkpoint::new(3, hash(5), root(101))
        );
        assert_eq!(
            store.tip().unwrap(),
            old_tip,
            "read-only branch verification mutated state"
        );
        assert_eq!(
            store.apply_verified_canonical_plan(&plan).unwrap(),
            plan.final_tip()
        );
    }

    #[test]
    fn atomic_reorg_rows_survive_immediate_drop_and_restart_readback() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(600));
        let empty_note = Poseidon2V8NoteTreeState::new_empty().unwrap();
        let detached_spend = nullifier(610);
        let detached_output = commitment(620);
        let attached_spend = nullifier(630);
        let attached_output = commitment(640);
        let expected_tip = Poseidon2V8Checkpoint::new(1, hash(3), root(602));
        let expected_note = {
            let mut note = empty_note.clone();
            note.append(attached_output).unwrap();
            note
        };
        {
            let (database, store) = open_store(directory.path(), genesis);
            let leaves: [&[u8]; 1] = [&[1]];
            let canonical = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaves).unwrap();
            let canonical_transition = shielded_transition(
                0,
                600,
                601,
                empty_note.root(),
                [Some(detached_spend), None],
                [Some(detached_output), None],
            );
            store
                .apply_verified_block(
                    canonical,
                    &mut ScriptedVerifier::new([canonical_transition]),
                )
                .unwrap();

            let replacement =
                Poseidon2V8UnverifiedBlock::new(context(genesis, 3), &leaves).unwrap();
            let replacement_transition = shielded_transition(
                0,
                600,
                602,
                empty_note.root(),
                [Some(attached_spend), None],
                [Some(attached_output), None],
            );
            let plan = store
                .plan_verified_reorganization(
                    &[hash(2)],
                    &[replacement],
                    &mut ScriptedVerifier::new([replacement_transition]),
                )
                .unwrap();
            assert_eq!(
                store.apply_verified_canonical_plan(&plan).unwrap(),
                expected_tip
            );
            assert_eq!(
                store.verify_canonical_plan_readback(&plan).unwrap(),
                expected_tip
            );
            drop(store);
            drop(database);
        }

        let (_database, reopened) = reopen_store(directory.path(), genesis);
        assert_eq!(reopened.tip().unwrap(), expected_tip);
        assert_eq!(reopened.note_tip().unwrap(), expected_note);
        assert!(!reopened.is_nullifier_spent(detached_spend).unwrap());
        assert!(reopened.is_nullifier_spent(attached_spend).unwrap());
        assert!(reopened.tree.get(record_key(hash(2))).unwrap().is_none());
        assert!(reopened.tree.get(record_key(hash(3))).unwrap().is_some());
    }

    #[test]
    fn outer_transaction_abort_rolls_back_shared_sentinel_and_typed_v8_plan() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(130));
        let (database, store) = open_store(directory.path(), genesis);
        let legacy = database.open_tree("v8_outer_transaction_sentinel").unwrap();
        let leaves: [&[u8]; 1] = [&[130, 131]];
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaves).unwrap();
        let mut verifier = FixtureVerifier::accepting();
        let plan = store
            .plan_verified_reorganization(&[], &[block], &mut verifier)
            .unwrap();

        let outcome: Result<(), TransactionError<String>> =
            (&legacy, &store.tree).transaction(|(legacy_tree, v8_tree)| {
                legacy_tree.insert(b"sentinel".to_vec(), b"written".to_vec())?;
                Poseidon2V8StateStore::apply_canonical_plan_in_transaction(v8_tree, &plan)?;
                Err(ConflictableTransactionError::Abort(
                    "injected outer transaction abort".to_owned(),
                ))
            });
        assert!(matches!(outcome, Err(TransactionError::Abort(_))));
        assert!(legacy.get(b"sentinel").unwrap().is_none());
        assert_eq!(store.tip().unwrap(), genesis);
        assert!(store.tree.get(record_key(hash(2))).unwrap().is_none());
    }

    fn mined_manifest_with_expected_v8_plan_count(
        source_poseidon2_v8_plan_count: usize,
    ) -> NativeAtomicCommitManifestAdmissionInput {
        NativeAtomicCommitManifestAdmissionInput {
            kind: NativeAtomicCommitKind::MinedBlockCommit,
            action_count: 0,
            planned_action_count: 0,
            chain_block_count: 0,
            height_entry_count: 0,
            pending_entry_count: 0,
            source_commitment_count: 0,
            source_nullifier_count: 0,
            source_bridge_replay_count: 0,
            source_ciphertext_index_count: 0,
            source_ciphertext_archive_count: 0,
            source_staged_ciphertext_removal_count: 0,
            source_poseidon2_v8_plan_count,
            block_record_writes: 1,
            height_index_writes: 1,
            best_pointer_writes: 1,
            canonical_index_cleared: false,
            pending_tree_cleared: false,
            pending_action_removals: 0,
            pending_action_writes: 0,
            commitment_writes: 0,
            nullifier_writes: 0,
            bridge_replay_writes: 0,
            ciphertext_index_writes: 0,
            ciphertext_archive_writes: 0,
            staged_ciphertext_removals: 0,
            // The transaction-local helper overwrites this with the count it
            // obtains only after the typed apply succeeds.
            poseidon2_v8_plan_application_count: source_poseidon2_v8_plan_count,
        }
    }

    fn one_leaf_plan(
        store: &Poseidon2V8StateStore,
        genesis: Poseidon2V8Checkpoint,
    ) -> Poseidon2V8CanonicalPlan {
        let leaves: [&[u8]; 1] = [&[130, 131]];
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaves).unwrap();
        store
            .plan_verified_reorganization(&[], &[block], &mut FixtureVerifier::accepting())
            .unwrap()
    }

    #[test]
    fn transaction_local_manifest_counts_only_successful_typed_v8_applications() {
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(130));

        // Expected Some: the helper applies exactly once and the shared row
        // commits with it.
        {
            let directory = tempfile::tempdir().unwrap();
            let (database, store) = open_store(directory.path(), genesis);
            let legacy = database.open_tree("v8_actual_count_some").unwrap();
            let plan = one_leaf_plan(&store, genesis);
            let outcome: Result<usize, TransactionError<String>> = (&legacy, &store.tree)
                .transaction(|(legacy_tree, v8_tree)| {
                    let actual = apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction(
                        v8_tree,
                        Some(&plan),
                        mined_manifest_with_expected_v8_plan_count(1),
                        "test expected V8 plan",
                    )?;
                    legacy_tree.insert(b"sentinel".to_vec(), b"written".to_vec())?;
                    Ok(actual)
                });
            assert_eq!(outcome.unwrap(), 1);
            assert_eq!(
                legacy.get(b"sentinel").unwrap().as_deref(),
                Some(b"written".as_slice())
            );
            let expected_tip = plan.final_tip();
            assert_eq!(store.tip().unwrap(), expected_tip);
            database.flush().unwrap();
            drop(legacy);
            drop(store);
            drop(database);

            let (_database, reopened) = reopen_store(directory.path(), genesis);
            assert_eq!(reopened.tip().unwrap(), expected_tip);
            assert!(reopened.tree.get(record_key(hash(2))).unwrap().is_some());
        }

        // Expected None: zero is admitted and no typed row changes.
        {
            let directory = tempfile::tempdir().unwrap();
            let (database, store) = open_store(directory.path(), genesis);
            let legacy = database.open_tree("v8_actual_count_none").unwrap();
            let outcome: Result<usize, TransactionError<String>> = (&legacy, &store.tree)
                .transaction(|(legacy_tree, v8_tree)| {
                    let actual = apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction(
                        v8_tree,
                        None,
                        mined_manifest_with_expected_v8_plan_count(0),
                        "test absent V8 plan",
                    )?;
                    legacy_tree.insert(b"sentinel".to_vec(), b"written".to_vec())?;
                    Ok(actual)
                });
            assert_eq!(outcome.unwrap(), 0);
            assert_eq!(store.tip().unwrap(), genesis);
            assert_eq!(
                legacy.get(b"sentinel").unwrap().as_deref(),
                Some(b"written".as_slice())
            );
        }

        // Missing actual application: expected one but supplied None. The
        // helper aborts before any shared row can commit.
        {
            let directory = tempfile::tempdir().unwrap();
            let (database, store) = open_store(directory.path(), genesis);
            let legacy = database.open_tree("v8_actual_count_missing").unwrap();
            let outcome: Result<(), TransactionError<String>> =
                (&legacy, &store.tree).transaction(|(legacy_tree, v8_tree)| {
                    apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction(
                        v8_tree,
                        None,
                        mined_manifest_with_expected_v8_plan_count(1),
                        "test missing V8 apply",
                    )?;
                    legacy_tree.insert(b"sentinel".to_vec(), b"written".to_vec())?;
                    Ok(())
                });
            assert!(matches!(outcome, Err(TransactionError::Abort(_))));
            assert!(legacy.get(b"sentinel").unwrap().is_none());
            assert_eq!(store.tip().unwrap(), genesis);
        }

        // Extra actual application: the typed writes happen in the attempt,
        // but the mismatch abort rolls them back with every shared row.
        {
            let directory = tempfile::tempdir().unwrap();
            let (database, store) = open_store(directory.path(), genesis);
            let legacy = database.open_tree("v8_actual_count_extra").unwrap();
            let plan = one_leaf_plan(&store, genesis);
            let outcome: Result<(), TransactionError<String>> =
                (&legacy, &store.tree).transaction(|(legacy_tree, v8_tree)| {
                    apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction(
                        v8_tree,
                        Some(&plan),
                        mined_manifest_with_expected_v8_plan_count(0),
                        "test extra V8 apply",
                    )?;
                    legacy_tree.insert(b"sentinel".to_vec(), b"written".to_vec())?;
                    Ok(())
                });
            assert!(matches!(outcome, Err(TransactionError::Abort(_))));
            assert!(legacy.get(b"sentinel").unwrap().is_none());
            assert_eq!(store.tip().unwrap(), genesis);
            assert!(store.tree.get(record_key(hash(2))).unwrap().is_none());
        }

        // Raw typed-plan failure propagates as a transaction abort before any
        // shared row or attached typed row can commit.
        {
            let directory = tempfile::tempdir().unwrap();
            let (database, store) = open_store(directory.path(), genesis);
            let legacy = database
                .open_tree("v8_actual_count_raw_apply_abort")
                .unwrap();
            let plan = one_leaf_plan(&store, genesis);
            let changed_tip = Poseidon2V8Checkpoint::new(0, hash(9), root(900));
            store
                .tree
                .insert(TIP_KEY, changed_tip.encode().as_slice())
                .unwrap();
            let outcome: Result<(), TransactionError<String>> =
                (&legacy, &store.tree).transaction(|(legacy_tree, v8_tree)| {
                    apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction(
                        v8_tree,
                        Some(&plan),
                        mined_manifest_with_expected_v8_plan_count(1),
                        "test raw V8 apply failure",
                    )?;
                    legacy_tree.insert(b"sentinel".to_vec(), b"written".to_vec())?;
                    Ok(())
                });
            assert!(matches!(outcome, Err(TransactionError::Abort(_))));
            assert!(legacy.get(b"sentinel").unwrap().is_none());
            assert!(store.tree.get(record_key(hash(2))).unwrap().is_none());
        }
    }

    #[test]
    fn exact_56_byte_nullifier_and_note_state_reject_duplicates_wrong_roots_and_survive_restart() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(80));
        let empty_note = Poseidon2V8NoteTreeState::new_empty().unwrap();
        let spend = nullifier(100);
        let output = commitment(200);
        let expected_note = {
            let mut state = empty_note.clone();
            state.append(output).unwrap();
            state
        };
        {
            let (database, store) = open_store(directory.path(), genesis);
            let leaves: [&[u8]; 1] = [&[1]];
            let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaves).unwrap();
            let transition = shielded_transition(
                0,
                80,
                81,
                empty_note.root(),
                [Some(spend), None],
                [Some(output), None],
            );
            store
                .apply_verified_block(block, &mut ScriptedVerifier::new([transition]))
                .unwrap();
            assert_eq!(store.note_tip().unwrap(), expected_note);
            assert!(store.is_nullifier_spent(spend).unwrap());

            let tip = store.tip().unwrap();
            let duplicate = Poseidon2V8UnverifiedBlock::new(context(tip, 3), &leaves).unwrap();
            let duplicate_transition = shielded_transition(
                1,
                81,
                82,
                expected_note.root(),
                [Some(spend), None],
                [None, None],
            );
            assert!(matches!(
                store.apply_verified_block(
                    duplicate,
                    &mut ScriptedVerifier::new([duplicate_transition])
                ),
                Err(Poseidon2V8StateError::SpentNullifier(observed)) if observed == spend
            ));

            let wrong_anchor = Poseidon2V8UnverifiedBlock::new(context(tip, 4), &leaves).unwrap();
            let wrong_anchor_transition = shielded_transition(
                1,
                81,
                82,
                note_root(900),
                [Some(nullifier(300)), None],
                [None, None],
            );
            assert!(matches!(
                store.apply_verified_block(
                    wrong_anchor,
                    &mut ScriptedVerifier::new([wrong_anchor_transition])
                ),
                Err(Poseidon2V8StateError::UnknownNoteAnchor { .. })
            ));
            assert_eq!(store.tip().unwrap(), tip);
            drop(store);
            drop(database);
        }

        let (_database, reopened) = reopen_store(directory.path(), genesis);
        assert_eq!(reopened.note_tip().unwrap(), expected_note);
        assert!(reopened.is_nullifier_spent(spend).unwrap());
    }

    #[test]
    fn block_rejects_spending_an_output_created_earlier_in_the_same_block() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(80));
        let empty_note = Poseidon2V8NoteTreeState::new_empty().unwrap();
        let first_output = commitment(210);
        let first_spend = nullifier(220);
        let second_spend = nullifier(230);
        let same_block_anchor = {
            let mut state = empty_note.clone();
            state.append(first_output).unwrap();
            state.root()
        };
        let (_database, store) = open_store(directory.path(), genesis);
        let leaves: [&[u8]; 2] = [&[1], &[2]];
        let block = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaves).unwrap();
        let transitions = [
            shielded_transition(
                0,
                80,
                81,
                empty_note.root(),
                [Some(first_spend), None],
                [Some(first_output), None],
            ),
            shielded_transition(
                0,
                81,
                82,
                same_block_anchor,
                [Some(second_spend), None],
                [None, None],
            ),
        ];

        assert!(matches!(
            store.apply_verified_block(block, &mut ScriptedVerifier::new(transitions)),
            Err(Poseidon2V8StateError::UnknownNoteAnchor { observed })
                if observed == same_block_anchor
        ));
        assert_eq!(store.tip().unwrap(), genesis);
        assert_eq!(store.note_tip().unwrap(), empty_note);
        assert!(!store.is_nullifier_spent(first_spend).unwrap());
        assert!(!store.is_nullifier_spent(second_spend).unwrap());
    }

    #[test]
    fn typed_v8_reorg_and_fresh_replay_restore_exact_note_and_nullifier_state() {
        let first_directory = tempfile::tempdir().unwrap();
        let fresh_directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(500));
        let empty_note = Poseidon2V8NoteTreeState::new_empty().unwrap();
        let spend_a = nullifier(510);
        let spend_b = nullifier(520);
        let output_a = commitment(530);
        let output_b = commitment(540);

        let (_first_database, first) = open_store(first_directory.path(), genesis);
        let leaves: [&[u8]; 1] = [&[1]];
        let a = Poseidon2V8UnverifiedBlock::new(context(genesis, 2), &leaves).unwrap();
        let transition_a = shielded_transition(
            0,
            500,
            501,
            empty_note.root(),
            [Some(spend_a), None],
            [Some(output_a), None],
        );
        first
            .apply_verified_block(a, &mut ScriptedVerifier::new([transition_a]))
            .unwrap();
        let a_note = first.note_tip().unwrap();

        let b = Poseidon2V8UnverifiedBlock::new(context(genesis, 3), &leaves).unwrap();
        let transition_b = shielded_transition(
            0,
            500,
            502,
            empty_note.root(),
            [Some(spend_a), Some(spend_b)],
            [Some(output_b), None],
        );
        first
            .reorganize_verified(&[hash(2)], &[b], &mut ScriptedVerifier::new([transition_b]))
            .unwrap();
        let branch_note = first.note_tip().unwrap();
        assert_ne!(branch_note, a_note);
        assert!(first.is_nullifier_spent(spend_a).unwrap());
        assert!(first.is_nullifier_spent(spend_b).unwrap());

        let (_fresh_database, fresh) = open_store(fresh_directory.path(), genesis);
        let fresh_b = Poseidon2V8UnverifiedBlock::new(context(genesis, 3), &leaves).unwrap();
        fresh
            .replay_verified_suffix(&[fresh_b], &mut ScriptedVerifier::new([transition_b]))
            .unwrap();
        assert_eq!(fresh.tip().unwrap(), first.tip().unwrap());
        assert_eq!(fresh.note_tip().unwrap(), branch_note);
        assert!(fresh.is_nullifier_spent(spend_a).unwrap());
        assert!(fresh.is_nullifier_spent(spend_b).unwrap());

        first.disconnect_tip(hash(3)).unwrap();
        assert_eq!(first.note_tip().unwrap(), empty_note);
        assert!(!first.is_nullifier_spent(spend_a).unwrap());
        assert!(!first.is_nullifier_spent(spend_b).unwrap());
    }

    #[test]
    fn trailing_rewards_preserve_order_through_restart_reorg_and_fresh_replay() {
        let directory = tempfile::tempdir().unwrap();
        let fresh_directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(700));
        let empty = Poseidon2V8NoteTreeState::new_empty().unwrap();
        let miner = commitment(710);
        let funding = commitment(720);
        let second_miner = commitment(730);
        let second_funding = commitment(740);
        let replacement_miner = commitment(750);
        let replacement_funding = commitment(760);
        let leaves: [&[u8]; 0] = [];
        assert!(Poseidon2V8UnverifiedBlock::new_with_trailing_rewards(
            context(genesis, 2),
            &leaves,
            [None, Some(funding)]
        )
        .is_err());
        assert!(Poseidon2V8UnverifiedBlock::new_with_trailing_rewards(
            context(genesis, 2),
            &leaves,
            [Some(miner), Some(miner)]
        )
        .is_err());
        let block1 = Poseidon2V8UnverifiedBlock::new_with_trailing_rewards(
            context(genesis, 2),
            &leaves,
            [Some(miner), Some(funding)],
        )
        .unwrap();
        let (database, store) = open_store(directory.path(), genesis);
        store
            .apply_verified_block(block1, &mut ScriptedVerifier::new([]))
            .unwrap();
        let tip1 = store.tip().unwrap();
        let mut expected = empty;
        expected
            .finish_block_rewards(1, hash(2), [Some(miner), Some(funding)])
            .unwrap();
        assert_eq!(store.note_tip().unwrap(), expected);
        let block2 = Poseidon2V8UnverifiedBlock::new_with_trailing_rewards(
            context(tip1, 3),
            &leaves,
            [Some(second_miner), Some(second_funding)],
        )
        .unwrap();
        store
            .apply_verified_block(block2, &mut ScriptedVerifier::new([]))
            .unwrap();
        expected
            .finish_block_rewards(2, hash(3), [Some(second_miner), Some(second_funding)])
            .unwrap();
        assert_eq!(store.note_tip().unwrap(), expected);
        drop(store);
        drop(database);
        let (database, reopened) = reopen_store(directory.path(), genesis);
        assert_eq!(reopened.note_tip().unwrap(), expected);
        let replacement = Poseidon2V8UnverifiedBlock::new_with_trailing_rewards(
            context(tip1, 4),
            &leaves,
            [Some(replacement_miner), Some(replacement_funding)],
        )
        .unwrap();
        reopened
            .reorganize_verified(&[hash(3)], &[replacement], &mut ScriptedVerifier::new([]))
            .unwrap();
        let mut expected = Poseidon2V8NoteTreeState::new_empty().unwrap();
        expected
            .finish_block_rewards(1, hash(2), [Some(miner), Some(funding)])
            .unwrap();
        expected
            .finish_block_rewards(
                2,
                hash(4),
                [Some(replacement_miner), Some(replacement_funding)],
            )
            .unwrap();
        assert_eq!(reopened.note_tip().unwrap(), expected);
        assert_eq!(expected.leaf_count(), 0);
        assert_eq!(expected.pending_rewards.len(), 2);
        let (_fresh_db, fresh) = open_store(fresh_directory.path(), genesis);
        fresh
            .replay_verified_suffix(&[block1, replacement], &mut ScriptedVerifier::new([]))
            .unwrap();
        assert_eq!(fresh.note_tip().unwrap(), expected);
        assert_eq!(fresh.tip().unwrap(), reopened.tip().unwrap());
        drop(reopened);
        drop(database);
    }

    #[test]
    fn pending_coinbase_preserves_hash_kat_outputs_restart_reorg_and_fresh_replay() {
        let canonical_directory = tempfile::tempdir().unwrap();
        let fresh_directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(700));
        let empty_note = Poseidon2V8NoteTreeState::new_empty().unwrap();
        let authorization_key = poseidon2_v8_single_key_authorization_key([
            12_387_129_418_859_519_852,
            3_275_605_879_553_790_158,
            18_179_312_849_545_706_498,
            6_480_565_605_584_441_507,
            5,
        ])
        .unwrap();
        let first_opening = SmallwoodPoseidon2V8NoteOpening {
            value: 499_429_223,
            asset_id: 0,
            recipient_key: [
                14_132_942_956_216_209_493,
                7_685_267_610_787_277_800,
                16_563_171_182_421_170_277,
                17_300_113_818_709_955_652,
            ],
            authorization_key,
            rho: [31, 32, 33, 34],
            randomness: [41, 42, 43, 44],
        };
        let second_opening = SmallwoodPoseidon2V8NoteOpening {
            rho: [51, 52, 53, 54],
            randomness: [61, 62, 63, 64],
            ..first_opening
        };
        let first_coinbase =
            Poseidon2V8Commitment::new(poseidon2_v8_note_commitment(first_opening).unwrap())
                .unwrap();
        let second_coinbase =
            Poseidon2V8Commitment::new(poseidon2_v8_note_commitment(second_opening).unwrap())
                .unwrap();
        let transaction_output = commitment(710);
        let third_coinbase = commitment(720);
        let replacement_coinbase = commitment(730);
        let expected_two_coinbase_note = {
            let mut note = empty_note.clone();
            note.append(first_coinbase).unwrap();
            note.append(second_coinbase).unwrap();
            note
        };
        assert_eq!(expected_two_coinbase_note.leaf_count(), 2);
        // Independently derived with the integer reference: unchanged five-key
        // sponge and note openings, then32 COMPFF01 left-feed-forward parents.
        assert_eq!(
            expected_two_coinbase_note.root().limbs(),
            [
                15_519_458_555_448_439_984,
                14_574_235_406_076_283_429,
                14_207_661_605_506_384_500,
                2_483_040_761_675_354_935,
                17_094_054_638_981_972_303,
                1_479_868_517_305_255_134,
                11_464_620_107_021_758_590,
            ]
        );
        // Historical suite-marker/raw-output root is a negative control only.
        assert_ne!(
            expected_two_coinbase_note.root().limbs(),
            [
                3_496_020_133_485_408_353,
                6_323_288_766_055_009_434,
                1_653_801_494_447_388_160,
                7_619_428_438_967_260_413,
                7_182_046_660_320_870_797,
                6_119_682_970_708_401_865,
                4_756_272_899_888_538_475,
            ]
        );
        let expected_pending_two = {
            let mut note = empty_note.clone();
            note.finish_block_rewards(1, hash(2), [Some(first_coinbase), None])
                .unwrap();
            note.finish_block_rewards(2, hash(3), [Some(second_coinbase), None])
                .unwrap();
            note
        };
        let expected_canonical_note = {
            let mut note = expected_pending_two.clone();
            note.append(transaction_output).unwrap();
            note.finish_block_rewards(3, hash(4), [Some(third_coinbase), None])
                .unwrap();
            note
        };

        let (database, store) = open_store(canonical_directory.path(), genesis);
        let no_leaves: [&[u8]; 0] = [];
        let block1 = Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
            context(genesis, 2),
            &no_leaves,
            Some(first_coinbase),
        )
        .unwrap();
        store
            .apply_verified_block(block1, &mut ScriptedVerifier::new([]))
            .unwrap();
        let tip1 = store.tip().unwrap();
        let block2 = Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
            context(tip1, 3),
            &no_leaves,
            Some(second_coinbase),
        )
        .unwrap();
        store
            .apply_verified_block(block2, &mut ScriptedVerifier::new([]))
            .unwrap();
        let tip2 = store.tip().unwrap();
        assert_eq!(store.note_tip().unwrap(), expected_pending_two);

        let leaves: [&[u8]; 1] = [&[1]];
        let canonical = Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
            context(tip2, 4),
            &leaves,
            Some(third_coinbase),
        )
        .unwrap();
        let transition = shielded_transition(
            2,
            700,
            701,
            expected_pending_two.root(),
            [None, None],
            [Some(transaction_output), None],
        );
        store
            .apply_verified_block(canonical, &mut ScriptedVerifier::new([transition]))
            .unwrap();
        assert_eq!(store.note_tip().unwrap(), expected_canonical_note);
        assert_eq!(store.note_tip().unwrap().leaf_count(), 1);
        drop(store);
        drop(database);

        let (database, reopened) = reopen_store(canonical_directory.path(), genesis);
        assert_eq!(reopened.note_tip().unwrap(), expected_canonical_note);

        let replacement = Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
            context(tip2, 5),
            &no_leaves,
            Some(replacement_coinbase),
        )
        .unwrap();
        reopened
            .reorganize_verified(&[hash(4)], &[replacement], &mut ScriptedVerifier::new([]))
            .unwrap();
        let expected_replacement_note = {
            let mut note = expected_pending_two.clone();
            note.finish_block_rewards(3, hash(5), [Some(replacement_coinbase), None])
                .unwrap();
            note
        };
        assert_eq!(reopened.note_tip().unwrap(), expected_replacement_note);
        drop(reopened);
        drop(database);

        let (_fresh_database, fresh) = open_store(fresh_directory.path(), genesis);
        let fresh_block1 = Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
            context(genesis, 2),
            &no_leaves,
            Some(first_coinbase),
        )
        .unwrap();
        let fresh_tip1 = Poseidon2V8Checkpoint::new(1, hash(2), root(700));
        let fresh_block2 = Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
            context(fresh_tip1, 3),
            &no_leaves,
            Some(second_coinbase),
        )
        .unwrap();
        let fresh_replacement = Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
            context(tip2, 5),
            &no_leaves,
            Some(replacement_coinbase),
        )
        .unwrap();
        fresh
            .replay_verified_suffix(
                &[fresh_block1, fresh_block2, fresh_replacement],
                &mut ScriptedVerifier::new([]),
            )
            .unwrap();
        assert_eq!(fresh.note_tip().unwrap(), expected_replacement_note);
        fresh.disconnect_tip(hash(5)).unwrap();
        assert_eq!(fresh.note_tip().unwrap(), expected_pending_two);
    }
    #[test]
    fn reward_maturity_excludes_both_roles_until_h_plus_120_and_reorgs_release() {
        let directory = tempfile::tempdir().unwrap();
        let fresh_directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, hash(1), root(700));
        let miner = commitment(710);
        let funding = commitment(720);
        let ordinary = commitment(730);
        let no_leaves: [&[u8]; 0] = [];
        let prefix = (1..120u64)
            .map(|height| {
                Poseidon2V8UnverifiedBlock::new_with_trailing_rewards(
                    Poseidon2V8BlockContext::new(
                        height - 1,
                        hash(height as u8),
                        height,
                        hash(height as u8 + 1),
                    )
                    .unwrap(),
                    &no_leaves,
                    if height == 1 {
                        [Some(miner), Some(funding)]
                    } else {
                        [None; 2]
                    },
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let (database, store) = open_store(directory.path(), genesis);
        store
            .replay_verified_suffix(&prefix, &mut ScriptedVerifier::new([]))
            .unwrap();
        assert_eq!(store.tip().unwrap().height(), 119);
        let pending = store.note_tip().unwrap();
        assert_eq!(pending.leaf_count(), 0);
        assert_eq!(pending.pending_rewards.len(), 1);
        let leaves: [&[u8]; 1] = [&[1]];
        let release =
            Poseidon2V8UnverifiedBlock::new(context(store.tip().unwrap(), 121), &leaves).unwrap();
        // Both the miner-only and miner+treasury membership trees are unknown
        // before the release block. These are host-admission negative controls,
        // not replacements for the unchanged relation's membership proof.
        let mut premature = Poseidon2V8NoteTreeState::new_empty().unwrap();
        for reward in [miner, funding] {
            premature.append(reward).unwrap();
            let transition =
                Poseidon2V8PublicTransition::new_with_shielded_state_and_stablecoin_effect(
                    119,
                    root(700),
                    root(700),
                    Poseidon2V8StablecoinEffect::DisabledNoWrite,
                    premature.root(),
                    [None; 2],
                    [None; 2],
                );
            let error = store
                .verify_uncommitted_block(release, &mut ScriptedVerifier::new([transition]))
                .expect_err("immature reward membership must fail before release");
            assert!(
                matches!(error, Poseidon2V8StateError::UnknownNoteAnchor { .. }),
                "unexpected immature-spend rejection: {error:?}"
            );
            assert_eq!(store.note_tip().unwrap(), pending);
        }
        // Ordinary outputs remain immediately appended; mature issuance follows
        // them, with miner before treasury, without a new proof relation.
        let output_transition =
            Poseidon2V8PublicTransition::new_with_shielded_state_and_stablecoin_effect(
                119,
                root(700),
                root(700),
                Poseidon2V8StablecoinEffect::DisabledNoWrite,
                pending.root(),
                [None; 2],
                [Some(ordinary), None],
            );
        store
            .apply_verified_block(release, &mut ScriptedVerifier::new([output_transition]))
            .unwrap();
        let mut expected = Poseidon2V8NoteTreeState::new_empty().unwrap();
        for value in [ordinary, miner, funding] {
            expected.append(value).unwrap();
        }
        assert_eq!(store.note_tip().unwrap(), expected);
        let release_tip = store.tip().unwrap();
        drop(store);
        drop(database);
        let (database, reopened) = reopen_store(directory.path(), genesis);
        assert_eq!(reopened.note_tip().unwrap(), expected);
        let spend = Poseidon2V8UnverifiedBlock::new(context(release_tip, 122), &leaves).unwrap();
        assert_eq!(
            spend.context.height,
            1 + consensus::reward::COINBASE_MATURITY
        );
        let nullifiers = [Some(nullifier(810)), Some(nullifier(820))];
        let spend_transition =
            Poseidon2V8PublicTransition::new_with_shielded_state_and_stablecoin_effect(
                120,
                root(700),
                root(700),
                Poseidon2V8StablecoinEffect::DisabledNoWrite,
                expected.root(),
                nullifiers,
                [None; 2],
            );
        reopened
            .apply_verified_block(spend, &mut ScriptedVerifier::new([spend_transition]))
            .unwrap();
        assert!(reopened.is_nullifier_spent(nullifier(810)).unwrap());
        assert!(reopened.is_nullifier_spent(nullifier(820)).unwrap());
        let replacement = Poseidon2V8UnverifiedBlock::new(
            context(Poseidon2V8Checkpoint::new(119, hash(120), root(700)), 200),
            &no_leaves,
        )
        .unwrap();
        reopened
            .reorganize_verified(
                &[hash(122), hash(121)],
                &[replacement],
                &mut ScriptedVerifier::new([]),
            )
            .unwrap();
        let mut replacement_expected = Poseidon2V8NoteTreeState::new_empty().unwrap();
        replacement_expected.append(miner).unwrap();
        replacement_expected.append(funding).unwrap();
        assert_eq!(reopened.note_tip().unwrap(), replacement_expected);
        assert!(!reopened.is_nullifier_spent(nullifier(810)).unwrap());
        assert!(!reopened.is_nullifier_spent(nullifier(820)).unwrap());
        let (_fresh_database, fresh) = open_store(fresh_directory.path(), genesis);
        let mut fresh_chain = prefix;
        fresh_chain.push(replacement);
        fresh
            .replay_verified_suffix(&fresh_chain, &mut ScriptedVerifier::new([]))
            .unwrap();
        assert_eq!(fresh.note_tip().unwrap(), reopened.note_tip().unwrap());
        // Disconnecting a release restores the original pending issuance.
        reopened.disconnect_tip(hash(200)).unwrap();
        assert_eq!(reopened.note_tip().unwrap(), pending);
        drop(reopened);
        drop(database);
    }

    #[test]
    fn pending_reward_codec_rejects_malformed_or_out_of_height_rows() {
        let mut state = Poseidon2V8NoteTreeState::new_empty().unwrap();
        state
            .finish_block_rewards(1, hash(2), [Some(commitment(710)), Some(commitment(720))])
            .unwrap();
        let encoded = state.encode().unwrap();
        assert_eq!(
            Poseidon2V8NoteTreeState::decode_exact(&encoded).unwrap(),
            state
        );
        let count_offset = encoded.len() - 2 - PENDING_REWARD_CODEC_BYTES;
        let row_offset = count_offset + 2;
        for (offset, replacement) in [
            (row_offset, vec![0; 8]),
            (row_offset + 8, vec![0; 32]),
            (row_offset + 40, vec![2]),
            (count_offset, (120u16).to_le_bytes().to_vec()),
            (row_offset, u64::MAX.to_le_bytes().to_vec()),
        ] {
            let mut corrupt = encoded.clone();
            corrupt[offset..offset + replacement.len()].copy_from_slice(&replacement);
            assert!(Poseidon2V8NoteTreeState::decode_exact(&corrupt).is_err());
        }
        let mut absent_funding_with_bytes = encoded.clone();
        absent_funding_with_bytes[row_offset + 40] = 0;
        assert!(Poseidon2V8NoteTreeState::decode_exact(&absent_funding_with_bytes).is_err());
        let mut duplicate = encoded.clone();
        let miner_start = row_offset + 41;
        duplicate
            [miner_start + POSEIDON2_V8_DIGEST_BYTES..miner_start + 2 * POSEIDON2_V8_DIGEST_BYTES]
            .copy_from_slice(&encoded[miner_start..miner_start + POSEIDON2_V8_DIGEST_BYTES]);
        assert!(Poseidon2V8NoteTreeState::decode_exact(&duplicate).is_err());
        assert!(state.validate_pending_at_height(0).is_err());
        assert!(state.validate_pending_at_height(119).is_ok());
        assert!(state.validate_pending_at_height(120).is_err());
        let mut old = encoded;
        old[..8].copy_from_slice(b"P2V8NT03");
        assert!(matches!(
            Poseidon2V8NoteTreeState::decode_exact(&old),
            Err(Poseidon2V8StateError::CodecMagic(_))
        ));
        let mut out_of_order = state.clone();
        out_of_order
            .pending_rewards
            .push_back(state.pending_rewards[0].clone());
        assert!(out_of_order.encode().is_err());
    }

    fn launch_shape_only_leaf(
        startup: crate::native::launch_v8_verifier::LaunchStartup,
    ) -> Vec<u8> {
        use protocol_shielded_pool::rp06_transport::{self, Rp06ExpectedContext};
        use transaction_circuit::{smallwood_poseidon2_v8_rp06, smallwood_poseidon2_v8_types};
        let mut base = smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8PublicStatement::default();
        base.merkle_root = startup.note_genesis_root().limbs();
        let statement = smallwood_poseidon2_v8_rp06::Rp06PublicStatement {
            base,
            chain_id: startup.chain_id(),
        };
        let preamble = smallwood_poseidon2_v8_rp06::rp06_transcript_bytes(&statement)
            .unwrap()
            .try_into()
            .unwrap();
        rp06_transport::encode_rp06_candidate_native_leaf(
            Rp06ExpectedContext::new(
                startup.chain_id(),
                smallwood_poseidon2_v8_rp06::rp06_program_digest(),
            )
            .unwrap(),
            &preamble,
            [None, None],
            b"SMZB\0",
        )
        .unwrap()
    }
    // Host-only fail-closed components; these tests do not qualify a proof.
    #[test]
    fn launch_ordering_hint_cannot_create_checked_reference_metadata() {
        let zero = Poseidon2V8Root::new([0; 7]).unwrap();
        let anchor = empty_note_genesis_root();
        let transition = Poseidon2V8PublicTransition::new_with_shielded_state_and_stablecoin_effect(
            0,
            zero,
            zero,
            Poseidon2V8StablecoinEffect::DisabledNoWrite,
            anchor,
            [None; 2],
            [None; 2],
        );
        let hinted = transition.with_launch_application_hint(12);
        assert_eq!(hinted.parent_height(), 0);
        assert_eq!(hinted.application_parent_height(), 12);
        assert!(hinted.checked_launch_reference().is_none());
    }
    #[test]
    fn launch_profile_without_reference_context_fails_before_state_or_proof_calls() {
        struct NoContext;
        impl Poseidon2V8ExactLeafVerifier for NoContext {
            fn native_leaf_profile(&self) -> Poseidon2V8NativeLeafProfile {
                Poseidon2V8NativeLeafProfile::LaunchMixed
            }
            fn launch_proof_lifetime_limit(&self) -> Option<u64> {
                Some(100)
            }
            fn verify_exact_v8_leaf(
                &mut self,
                _: Poseidon2V8BlockContext,
                _: usize,
                _: &[u8],
            ) -> Result<Poseidon2V8PublicTransition, String> {
                panic!("missing context must reject before any proof call")
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, [2; 32], Poseidon2V8Root::new([0; 7]).unwrap());
        let (_db, store) = open_store(directory.path(), genesis);
        let block = Poseidon2V8UnverifiedBlock::new(
            Poseidon2V8BlockContext::new(0, [2; 32], 1, [21; 32]).unwrap(),
            &[],
        )
        .unwrap();
        assert!(
            matches!(store.verify_uncommitted_block(block, &mut NoContext), Err(Poseidon2V8StateError::ProofRejected(message)) if message.contains("immutable reference context"))
        );
        assert_eq!(store.tip().unwrap(), genesis);
    }
    #[test]
    fn staged_launch_snapshots_exclude_pending_rewards_before_rejecting_shape_only_proof() {
        use crate::native::{
            launch_v8_verifier::LaunchStartup, network_profile::NativeNetworkIdentity,
        };
        struct ReferenceOnly {
            context: LaunchReferenceContext,
            seen: Vec<CanonicalLaunchReferences>,
        }
        impl Poseidon2V8ExactLeafVerifier for ReferenceOnly {
            fn native_leaf_profile(&self) -> Poseidon2V8NativeLeafProfile {
                Poseidon2V8NativeLeafProfile::LaunchMixed
            }
            fn launch_reference_context(&self) -> Option<LaunchReferenceContext> {
                Some(self.context)
            }
            fn launch_proof_lifetime_limit(&self) -> Option<u64> {
                Some(100)
            }
            fn launch_proof_action_limit(&self) -> Option<usize> {
                Some(512)
            }
            fn set_launch_references(
                &mut self,
                refs: CanonicalLaunchReferences,
            ) -> Result<(), String> {
                if refs.context() != self.context {
                    return Err("wrong test context".into());
                }
                self.seen.push(refs);
                Ok(())
            }
            fn verify_exact_v8_leaf(
                &mut self,
                _: Poseidon2V8BlockContext,
                _: usize,
                _: &[u8],
            ) -> Result<Poseidon2V8PublicTransition, String> {
                Err("this host-only fixture cannot verify a proof".into())
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let zero = Poseidon2V8Root::new([0; 7]).unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, [2; 32], zero);
        let (_db, store) = open_store(directory.path(), genesis);
        let startup = LaunchStartup::qualification_for_test(
            &NativeNetworkIdentity::development(),
            [2; 32],
            zero,
            1,
            100,
            100,
        )
        .unwrap();
        let context = LaunchReferenceContext::from_startup(startup).unwrap();
        let first = Poseidon2V8UnverifiedBlock::new_with_trailing_rewards(
            Poseidon2V8BlockContext::new(0, [2; 32], 1, [21; 32]).unwrap(),
            &[],
            [Some(commitment(3)), Some(commitment(4))],
        )
        .unwrap();
        let second_context = Poseidon2V8BlockContext::new(1, [21; 32], 2, [22; 32]).unwrap();
        let shape_leaf = launch_shape_only_leaf(startup);
        let shape_leaves = [shape_leaf.as_slice()];
        let second = Poseidon2V8UnverifiedBlock::new(second_context, &shape_leaves).unwrap();
        let mut verifier = ReferenceOnly {
            context,
            seen: Vec::new(),
        };
        assert!(store
            .plan_verified_reorganization(&[], &[first, second], &mut verifier)
            .is_err());
        assert_eq!(store.tip().unwrap(), genesis);
        assert_eq!(verifier.seen.len(), 1);
        let expected_note = Poseidon2V8NoteTreeState::new_empty().unwrap();
        let mut base = transaction_circuit::smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8PublicStatement::default();
        base.stablecoin.parent_height = 1;
        base.merkle_root = expected_note.root().limbs();
        let statement = transaction_circuit::smallwood_poseidon2_v8_rp06::Rp06PublicStatement {
            base,
            chain_id: startup.chain_id(),
        };
        assert!(verifier.seen[0]
            .validate_rp06(&statement, second_context)
            .is_ok());
        let mut wrong = statement;
        let mut premature = expected_note;
        premature.append(commitment(3)).unwrap();
        premature.append(commitment(4)).unwrap();
        wrong.base.merkle_root = premature.root().limbs();
        assert!(verifier.seen[0]
            .validate_rp06(&wrong, second_context)
            .is_err());
    }
    #[test]
    fn launch_empty_replay_crosses_activation_and_retirement_but_proofs_reject_outside() {
        use crate::native::{
            launch_v8_verifier::LaunchStartup, network_profile::NativeNetworkIdentity,
        };
        struct BoundaryVerifier {
            context: LaunchReferenceContext,
            proof_calls: usize,
        }
        impl Poseidon2V8ExactLeafVerifier for BoundaryVerifier {
            fn native_leaf_profile(&self) -> Poseidon2V8NativeLeafProfile {
                Poseidon2V8NativeLeafProfile::LaunchMixed
            }
            fn launch_reference_context(&self) -> Option<LaunchReferenceContext> {
                Some(self.context)
            }
            fn launch_proof_lifetime_limit(&self) -> Option<u64> {
                Some(100)
            }
            fn launch_proof_action_limit(&self) -> Option<usize> {
                Some(512)
            }
            fn set_launch_references(
                &mut self,
                _: CanonicalLaunchReferences,
            ) -> Result<(), String> {
                Ok(())
            }
            fn verify_exact_v8_leaf(
                &mut self,
                _: Poseidon2V8BlockContext,
                _: usize,
                _: &[u8],
            ) -> Result<Poseidon2V8PublicTransition, String> {
                self.proof_calls += 1;
                Err("shape-only proof cannot verify".into())
            }
        }
        let zero = Poseidon2V8Root::new([0; 7]).unwrap();
        let genesis = Poseidon2V8Checkpoint::new(0, [2; 32], zero);
        let startup = LaunchStartup::qualification_for_test(
            &NativeNetworkIdentity::development(),
            [2; 32],
            zero,
            3,
            5,
            100,
        )
        .unwrap();
        let context = LaunchReferenceContext::from_startup(startup).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let (_db, store) = open_store(directory.path(), genesis);
        let empty_blocks = (1..=5)
            .map(|height| {
                Poseidon2V8UnverifiedBlock::new_with_trailing_rewards(
                    Poseidon2V8BlockContext::new(
                        height - 1,
                        if height == 1 {
                            [2; 32]
                        } else {
                            [height as u8 + 19; 32]
                        },
                        height,
                        [height as u8 + 20; 32],
                    )
                    .unwrap(),
                    &[],
                    if height == 1 || height == 5 {
                        [Some(commitment(height)), Some(commitment(height + 10))]
                    } else {
                        [None, None]
                    },
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let mut verifier = BoundaryVerifier {
            context,
            proof_calls: 0,
        };
        store
            .replay_verified_suffix(&empty_blocks, &mut verifier)
            .unwrap();
        assert_eq!(store.tip().unwrap().height, 5);
        assert_eq!(verifier.proof_calls, 0);
        let wrong_directory = tempfile::tempdir().unwrap();
        let wrong_genesis = Poseidon2V8Checkpoint::new(0, [3; 32], zero);
        let (_wrong_db, wrong_store) = open_store(wrong_directory.path(), wrong_genesis);
        let wrong_block = Poseidon2V8UnverifiedBlock::new(
            Poseidon2V8BlockContext::new(0, [3; 32], 1, [21; 32]).unwrap(),
            &[],
        )
        .unwrap();
        assert!(
            matches!(wrong_store.verify_uncommitted_block(wrong_block, &mut verifier),
            Err(Poseidon2V8StateError::ProofRejected(message)) if message.contains("storage genesis differs"))
        );
        let shape_leaf = launch_shape_only_leaf(startup);
        let shape_leaves = [shape_leaf.as_slice()];
        let directory2 = tempfile::tempdir().unwrap();
        let (_db2, fresh) = open_store(directory2.path(), genesis);
        let early =
            Poseidon2V8UnverifiedBlock::new(empty_blocks[0].context, &shape_leaves).unwrap();
        assert!(
            matches!(fresh.verify_uncommitted_block(early, &mut verifier), Err(Poseidon2V8StateError::ProofRejected(message)) if message.contains("outside source lifetime"))
        );
        fresh
            .replay_verified_suffix(&empty_blocks[..4], &mut verifier)
            .unwrap();
        let late = Poseidon2V8UnverifiedBlock::new(empty_blocks[4].context, &shape_leaves).unwrap();
        assert!(
            matches!(fresh.verify_uncommitted_block(late, &mut verifier), Err(Poseidon2V8StateError::ProofRejected(message)) if message.contains("outside source lifetime"))
        );
        assert_eq!(verifier.proof_calls, 0);
        assert_eq!(fresh.tip().unwrap().height, 4);
    }
}
