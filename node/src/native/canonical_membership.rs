//! Disk-authoritative exact membership for canonical 48-byte protocol keys.
//!
//! The compacted base and the active WAL are both exact paired indexes.  A
//! canonical view binds one base generation, at most one sealed WAL
//! generation, and one process epoch.  Point reads consult the WAL first and
//! then the base, checking the epoch before and after I/O.  Consequently an
//! inactive/incomplete WAL is invisible, and a view that escapes across the
//! atomic active-WAL flip fails stale instead of observing a mixed state.

use super::reorg_wal::{
    NATIVE_REORG_WAL_ACTIVE_KEY_V3, NATIVE_REORG_WAL_MANIFEST_TREE_V3,
    NATIVE_REORG_WAL_SEALED_PREFIX_V3,
};
use codec::{Decode, DecodeWithMemLimit, DecodeWithMemTracking, Encode};
use crypto::hash384::{domains, Blake2b384DomainHasher, BridgeReplayKey48, Nullifier48};
use parking_lot::Mutex;
use protocol_shielded_pool::PersistentKeySet48;
use sled::transaction::{
    ConflictableTransactionError, ConflictableTransactionResult, Transactional, TransactionalTree,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::mem;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;

pub(crate) const NULLIFIER_BASE_BY_KEY_TREE_V3: &[u8] = b"shielded_nullifiers_v3_by_key";
pub(crate) const NULLIFIER_BASE_BY_INDEX_TREE_V3: &[u8] = b"shielded_nullifiers_v3_by_index";
pub(crate) const BRIDGE_BASE_BY_KEY_TREE_V3: &[u8] = b"bridge_inbound_messages_v3_by_key";
pub(crate) const BRIDGE_BASE_BY_INDEX_TREE_V3: &[u8] = b"bridge_inbound_messages_v3_by_index";
pub(crate) const CANONICAL_MEMBERSHIP_WAL_BY_KEY_TREE_V3: &[u8] =
    b"canonical_membership_v3_wal_by_key";
pub(crate) const CANONICAL_MEMBERSHIP_WAL_BY_INDEX_TREE_V3: &[u8] =
    b"canonical_membership_v3_wal_by_index";
pub(crate) const CANONICAL_MEMBERSHIP_WAL_ORDER_TREE_V3: &[u8] =
    b"canonical_membership_v3_wal_order";
pub(crate) const CANONICAL_MEMBERSHIP_TREE_NAMES_V3: [&[u8]; 7] = [
    NULLIFIER_BASE_BY_KEY_TREE_V3,
    NULLIFIER_BASE_BY_INDEX_TREE_V3,
    BRIDGE_BASE_BY_KEY_TREE_V3,
    BRIDGE_BASE_BY_INDEX_TREE_V3,
    CANONICAL_MEMBERSHIP_WAL_BY_KEY_TREE_V3,
    CANONICAL_MEMBERSHIP_WAL_BY_INDEX_TREE_V3,
    CANONICAL_MEMBERSHIP_WAL_ORDER_TREE_V3,
];

pub(crate) const CANONICAL_MEMBERSHIP_SNAPSHOT_SCHEMA_V3: u16 = 3;
pub(crate) const CANONICAL_MEMBERSHIP_WAL_CODEC_V1: u8 = 1;
pub(crate) const MAX_CANONICAL_MEMBERSHIP_CACHE_KEYS: usize = 65_536;
pub(crate) const MAX_CANONICAL_MEMBERSHIP_WAL_CLEANUP_BATCH_ROWS: usize = 65_536;
pub(crate) const CANONICAL_MEMBERSHIP_SNAPSHOT_INACTIVE_BYTES: usize = 100;
pub(crate) const CANONICAL_MEMBERSHIP_SNAPSHOT_ACTIVE_BYTES: usize = 156;

const GENERATION_BYTES: usize = 8;
const ORDINAL_BYTES: usize = 8;
const KEY_BYTES: usize = 48;
const FAMILY_BYTES: usize = 1;
const SEQUENCE_BYTES: usize = 8;
const BASE_FORWARD_KEY_BYTES: usize = GENERATION_BYTES + KEY_BYTES;
const BASE_REVERSE_KEY_BYTES: usize = GENERATION_BYTES + ORDINAL_BYTES;
const WAL_FORWARD_KEY_BYTES: usize = GENERATION_BYTES + FAMILY_BYTES + KEY_BYTES;
const WAL_REVERSE_KEY_BYTES: usize = GENERATION_BYTES + FAMILY_BYTES + ORDINAL_BYTES;
const WAL_ORDER_KEY_BYTES: usize = GENERATION_BYTES + SEQUENCE_BYTES;
const WAL_BY_KEY_VALUE_BYTES: usize = 1 + SEQUENCE_BYTES + 2 * (1 + ORDINAL_BYTES);
const WAL_BY_INDEX_VALUE_BYTES: usize = 1 + 2 * (1 + KEY_BYTES + SEQUENCE_BYTES);
const WAL_ORDER_VALUE_BYTES: usize = 1 + FAMILY_BYTES + KEY_BYTES + 2 * (1 + ORDINAL_BYTES);
const WAL_DIGEST_COMPONENT_V3: &[u8] = b"canonical-membership-v3";
const WAL_DIGEST_ORDER_ROW_TAG: &[u8] = b"order";
const WAL_DIGEST_BY_KEY_ROW_TAG: &[u8] = b"by-key";
const WAL_DIGEST_BY_INDEX_ROW_TAG: &[u8] = b"by-index";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum CanonicalMembershipFamily48 {
    Nullifier = 0x01,
    ConsumedBridgeMessage = 0x02,
}

impl CanonicalMembershipFamily48 {
    fn from_tag(tag: u8) -> Result<Self, CanonicalMembershipError> {
        match tag {
            0x01 => Ok(Self::Nullifier),
            0x02 => Ok(Self::ConsumedBridgeMessage),
            _ => Err(CanonicalMembershipError::InvalidFamilyTag(tag)),
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    const fn rejects_zero(self) -> bool {
        matches!(self, Self::Nullifier)
    }

    const fn base_tree_names(self) -> (&'static [u8], &'static [u8]) {
        match self {
            Self::Nullifier => (
                NULLIFIER_BASE_BY_KEY_TREE_V3,
                NULLIFIER_BASE_BY_INDEX_TREE_V3,
            ),
            Self::ConsumedBridgeMessage => {
                (BRIDGE_BASE_BY_KEY_TREE_V3, BRIDGE_BASE_BY_INDEX_TREE_V3)
            }
        }
    }
}

impl fmt::Display for CanonicalMembershipFamily48 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nullifier => formatter.write_str("nullifier"),
            Self::ConsumedBridgeMessage => formatter.write_str("consumed bridge message"),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum CanonicalMembershipError {
    #[error("canonical membership storage error: {0}")]
    Storage(#[from] sled::Error),
    #[error("canonical membership tree mismatch: expected {expected}, observed {observed}")]
    TreeNameMismatch { expected: String, observed: String },
    #[error("canonical membership epoch {0} is not stable/even")]
    UnstableEpoch(u64),
    #[error("canonical membership epoch overflow")]
    EpochOverflow,
    #[error("canonical membership view is stale: expected epoch {expected}, observed {observed}")]
    StaleView { expected: u64, observed: u64 },
    #[error("canonical membership mutation raced: expected epoch {expected}, observed {observed}")]
    EpochConflict { expected: u64, observed: u64 },
    #[error("canonical membership cache capacity {0} exceeds the hard bound")]
    CacheCapacityExceeded(usize),
    #[error("canonical membership overlay capacity must be nonzero")]
    ZeroOverlayCapacity,
    #[error("canonical membership overlay exceeds its {capacity}-key bound")]
    OverlayCapacityExceeded { capacity: usize },
    #[error("all-zero {0} key is invalid")]
    ZeroKey(CanonicalMembershipFamily48),
    #[error("invalid canonical membership family tag 0x{0:02x}")]
    InvalidFamilyTag(u8),
    #[error(
        "invalid canonical membership {what} length: expected {expected}, observed {observed}"
    )]
    InvalidLength {
        what: &'static str,
        expected: usize,
        observed: usize,
    },
    #[error("invalid canonical membership option tag 0x{0:02x}")]
    InvalidOptionTag(u8),
    #[error("non-canonical bytes in absent canonical membership option")]
    NonCanonicalAbsentOption,
    #[error("canonical membership WAL codec version {0} is unsupported")]
    UnsupportedWalCodec(u8),
    #[error("canonical membership WAL mutation is empty or a no-op")]
    EmptyWalMutation,
    #[error("canonical membership generation zero is reserved for the compacted base")]
    ZeroWalGeneration,
    #[error("canonical membership WAL sequence overflow")]
    WalSequenceOverflow,
    #[error("canonical membership ordinal overflow")]
    OrdinalOverflow,
    #[error("canonical membership count does not match its suffix delta")]
    DeltaCountMismatch,
    #[error("canonical membership suffix ordinals are not contiguous")]
    NonContiguousDelta,
    #[error("canonical membership suffix contains a duplicate key")]
    DuplicateDeltaKey,
    #[error("canonical membership delta epoch mismatch")]
    DeltaEpochMismatch,
    #[error("canonical membership planner requires no active WAL")]
    ActiveWalMustBeFinalized,
    #[error("canonical membership cannot discard the active WAL generation")]
    CannotDiscardActiveWal,
    #[error("canonical membership cannot discard a sealed WAL generation")]
    CannotDiscardSealedWal,
    #[error("canonical membership active WAL pointer is malformed")]
    InvalidActiveWalPointer,
    #[error("canonical membership bounded batch size must be nonzero")]
    ZeroBatchLimit,
    #[error("canonical membership WAL cleanup batch exceeds {0} rows")]
    CleanupBatchLimitExceeded(usize),
    #[error("canonical membership key expected for removal is absent")]
    MissingRemovalKey,
    #[error("canonical membership key expected for insertion is already present")]
    DuplicateInsertionKey,
    #[error("canonical membership view count does not match the delta base")]
    DeltaBaseCountMismatch,
    #[error(
        "canonical membership ordinal lookup is unavailable on an uncommitted in-memory overlay"
    )]
    OrdinalLookupWithOverlay,
    #[error("canonical membership WAL row conflicts with an existing staged row")]
    WalStageConflict,
    #[error("canonical membership WAL row is missing or cross-binding is invalid")]
    WalCrossBindingMismatch,
    #[error("canonical membership WAL order is not contiguous")]
    WalOrderGap,
    #[error("canonical membership index is not an exact bijection")]
    IndexBijectionMismatch,
    #[error("canonical membership snapshot is invalid: {0}")]
    InvalidSnapshot(&'static str),
    #[error("canonical membership SCALE decode failed: {0}")]
    Decode(String),
    #[error("canonical membership encoded value is non-canonical or has trailing bytes")]
    NonCanonicalEncoding,
    #[error("canonical membership bounded decode exceeds {0} rows")]
    DecodeRowLimitExceeded(usize),
    #[error("canonical membership publication rebase is invalid: {0}")]
    InvalidRebase(&'static str),
}

fn validate_key(
    family: CanonicalMembershipFamily48,
    key: &[u8; KEY_BYTES],
) -> Result<(), CanonicalMembershipError> {
    if family.rejects_zero() && key == &[0u8; KEY_BYTES] {
        return Err(CanonicalMembershipError::ZeroKey(family));
    }
    Ok(())
}

fn expect_len(
    bytes: &[u8],
    expected: usize,
    what: &'static str,
) -> Result<(), CanonicalMembershipError> {
    if bytes.len() != expected {
        return Err(CanonicalMembershipError::InvalidLength {
            what,
            expected,
            observed: bytes.len(),
        });
    }
    Ok(())
}

fn read_array<const N: usize>(
    bytes: &[u8],
    what: &'static str,
) -> Result<[u8; N], CanonicalMembershipError> {
    expect_len(bytes, N, what)?;
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn encode_generation(generation: u64) -> [u8; GENERATION_BYTES] {
    generation.to_be_bytes()
}

fn encode_ordinal(ordinal: u64) -> [u8; ORDINAL_BYTES] {
    ordinal.to_be_bytes()
}

fn decode_ordinal(bytes: &[u8], what: &'static str) -> Result<u64, CanonicalMembershipError> {
    Ok(u64::from_be_bytes(read_array(bytes, what)?))
}

pub(crate) fn encode_membership_base_forward_key(
    generation: u64,
    key: &[u8; KEY_BYTES],
) -> [u8; BASE_FORWARD_KEY_BYTES] {
    let mut out = [0u8; BASE_FORWARD_KEY_BYTES];
    out[..GENERATION_BYTES].copy_from_slice(&encode_generation(generation));
    out[GENERATION_BYTES..].copy_from_slice(key);
    out
}

pub(crate) fn encode_membership_base_reverse_key(
    generation: u64,
    ordinal: u64,
) -> [u8; BASE_REVERSE_KEY_BYTES] {
    let mut out = [0u8; BASE_REVERSE_KEY_BYTES];
    out[..GENERATION_BYTES].copy_from_slice(&encode_generation(generation));
    out[GENERATION_BYTES..].copy_from_slice(&encode_ordinal(ordinal));
    out
}

fn decode_base_forward_key(
    bytes: &[u8],
) -> Result<(u64, [u8; KEY_BYTES]), CanonicalMembershipError> {
    expect_len(bytes, BASE_FORWARD_KEY_BYTES, "base forward key")?;
    let generation = decode_ordinal(&bytes[..GENERATION_BYTES], "base generation")?;
    let key = read_array(&bytes[GENERATION_BYTES..], "base member key")?;
    Ok((generation, key))
}

fn decode_base_reverse_key(bytes: &[u8]) -> Result<(u64, u64), CanonicalMembershipError> {
    expect_len(bytes, BASE_REVERSE_KEY_BYTES, "base reverse key")?;
    let generation = decode_ordinal(&bytes[..GENERATION_BYTES], "base generation")?;
    let ordinal = decode_ordinal(&bytes[GENERATION_BYTES..], "base ordinal")?;
    Ok((generation, ordinal))
}

fn encode_wal_forward_key(
    generation: u64,
    family: CanonicalMembershipFamily48,
    key: &[u8; KEY_BYTES],
) -> [u8; WAL_FORWARD_KEY_BYTES] {
    let mut out = [0u8; WAL_FORWARD_KEY_BYTES];
    out[..GENERATION_BYTES].copy_from_slice(&encode_generation(generation));
    out[GENERATION_BYTES] = family.tag();
    out[GENERATION_BYTES + FAMILY_BYTES..].copy_from_slice(key);
    out
}

fn decode_wal_forward_key(
    bytes: &[u8],
) -> Result<(u64, CanonicalMembershipFamily48, [u8; KEY_BYTES]), CanonicalMembershipError> {
    expect_len(bytes, WAL_FORWARD_KEY_BYTES, "WAL forward key")?;
    let generation = decode_ordinal(&bytes[..GENERATION_BYTES], "WAL generation")?;
    let family = CanonicalMembershipFamily48::from_tag(bytes[GENERATION_BYTES])?;
    let key = read_array(&bytes[GENERATION_BYTES + FAMILY_BYTES..], "WAL member key")?;
    validate_key(family, &key)?;
    Ok((generation, family, key))
}

fn encode_wal_reverse_key(
    generation: u64,
    family: CanonicalMembershipFamily48,
    ordinal: u64,
) -> [u8; WAL_REVERSE_KEY_BYTES] {
    let mut out = [0u8; WAL_REVERSE_KEY_BYTES];
    out[..GENERATION_BYTES].copy_from_slice(&encode_generation(generation));
    out[GENERATION_BYTES] = family.tag();
    out[GENERATION_BYTES + FAMILY_BYTES..].copy_from_slice(&encode_ordinal(ordinal));
    out
}

fn decode_wal_reverse_key(
    bytes: &[u8],
) -> Result<(u64, CanonicalMembershipFamily48, u64), CanonicalMembershipError> {
    expect_len(bytes, WAL_REVERSE_KEY_BYTES, "WAL reverse key")?;
    let generation = decode_ordinal(&bytes[..GENERATION_BYTES], "WAL generation")?;
    let family = CanonicalMembershipFamily48::from_tag(bytes[GENERATION_BYTES])?;
    let ordinal = decode_ordinal(&bytes[GENERATION_BYTES + FAMILY_BYTES..], "WAL ordinal")?;
    Ok((generation, family, ordinal))
}

fn encode_wal_order_key(generation: u64, sequence: u64) -> [u8; WAL_ORDER_KEY_BYTES] {
    let mut out = [0u8; WAL_ORDER_KEY_BYTES];
    out[..GENERATION_BYTES].copy_from_slice(&encode_generation(generation));
    out[GENERATION_BYTES..].copy_from_slice(&sequence.to_be_bytes());
    out
}

fn decode_wal_order_key(bytes: &[u8]) -> Result<(u64, u64), CanonicalMembershipError> {
    expect_len(bytes, WAL_ORDER_KEY_BYTES, "WAL order key")?;
    let generation = decode_ordinal(&bytes[..GENERATION_BYTES], "WAL generation")?;
    let sequence = decode_ordinal(&bytes[GENERATION_BYTES..], "WAL sequence")?;
    Ok((generation, sequence))
}

fn write_option_ordinal(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => {
            out.push(0);
            out.extend_from_slice(&[0u8; ORDINAL_BYTES]);
        }
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn read_option_ordinal(bytes: &[u8]) -> Result<Option<u64>, CanonicalMembershipError> {
    expect_len(bytes, 1 + ORDINAL_BYTES, "optional ordinal")?;
    match bytes[0] {
        0 => {
            if bytes[1..].iter().any(|byte| *byte != 0) {
                return Err(CanonicalMembershipError::NonCanonicalAbsentOption);
            }
            Ok(None)
        }
        1 => Ok(Some(decode_ordinal(&bytes[1..], "optional ordinal")?)),
        tag => Err(CanonicalMembershipError::InvalidOptionTag(tag)),
    }
}

fn write_option_key_sequence(out: &mut Vec<u8>, value: Option<([u8; KEY_BYTES], u64)>) {
    match value {
        None => {
            out.push(0);
            out.extend_from_slice(&[0u8; KEY_BYTES + SEQUENCE_BYTES]);
        }
        Some((key, sequence)) => {
            out.push(1);
            out.extend_from_slice(&key);
            out.extend_from_slice(&sequence.to_be_bytes());
        }
    }
}

fn read_option_key_sequence(
    bytes: &[u8],
) -> Result<Option<([u8; KEY_BYTES], u64)>, CanonicalMembershipError> {
    expect_len(
        bytes,
        1 + KEY_BYTES + SEQUENCE_BYTES,
        "optional key/sequence",
    )?;
    match bytes[0] {
        0 => {
            if bytes[1..].iter().any(|byte| *byte != 0) {
                return Err(CanonicalMembershipError::NonCanonicalAbsentOption);
            }
            Ok(None)
        }
        1 => {
            let key = read_array(&bytes[1..1 + KEY_BYTES], "optional member key")?;
            let sequence = decode_ordinal(&bytes[1 + KEY_BYTES..], "optional WAL sequence")?;
            Ok(Some((key, sequence)))
        }
        tag => Err(CanonicalMembershipError::InvalidOptionTag(tag)),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalMembershipWalOrderRecord48 {
    pub(crate) sequence: u64,
    pub(crate) family: CanonicalMembershipFamily48,
    pub(crate) key: [u8; KEY_BYTES],
    pub(crate) expected_ordinal: Option<u64>,
    pub(crate) replacement_ordinal: Option<u64>,
}

impl CanonicalMembershipWalOrderRecord48 {
    fn validate(&self) -> Result<(), CanonicalMembershipError> {
        validate_key(self.family, &self.key)?;
        if self.expected_ordinal == self.replacement_ordinal {
            return Err(CanonicalMembershipError::EmptyWalMutation);
        }
        Ok(())
    }

    fn encode_value(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WAL_ORDER_VALUE_BYTES);
        out.push(CANONICAL_MEMBERSHIP_WAL_CODEC_V1);
        out.push(self.family.tag());
        out.extend_from_slice(&self.key);
        write_option_ordinal(&mut out, self.expected_ordinal);
        write_option_ordinal(&mut out, self.replacement_ordinal);
        debug_assert_eq!(out.len(), WAL_ORDER_VALUE_BYTES);
        out
    }

    fn decode_value(sequence: u64, bytes: &[u8]) -> Result<Self, CanonicalMembershipError> {
        expect_len(bytes, WAL_ORDER_VALUE_BYTES, "WAL order value")?;
        if bytes[0] != CANONICAL_MEMBERSHIP_WAL_CODEC_V1 {
            return Err(CanonicalMembershipError::UnsupportedWalCodec(bytes[0]));
        }
        let family = CanonicalMembershipFamily48::from_tag(bytes[1])?;
        let key = read_array(&bytes[2..2 + KEY_BYTES], "WAL order member key")?;
        let expected_start = 2 + KEY_BYTES;
        let expected_ordinal =
            read_option_ordinal(&bytes[expected_start..expected_start + 1 + ORDINAL_BYTES])?;
        let replacement_ordinal =
            read_option_ordinal(&bytes[expected_start + 1 + ORDINAL_BYTES..])?;
        let record = Self {
            sequence,
            family,
            key,
            expected_ordinal,
            replacement_ordinal,
        };
        record.validate()?;
        Ok(record)
    }

    fn encode_by_key_value(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WAL_BY_KEY_VALUE_BYTES);
        out.push(CANONICAL_MEMBERSHIP_WAL_CODEC_V1);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        write_option_ordinal(&mut out, self.expected_ordinal);
        write_option_ordinal(&mut out, self.replacement_ordinal);
        debug_assert_eq!(out.len(), WAL_BY_KEY_VALUE_BYTES);
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WalByKeyValue48 {
    sequence: u64,
    expected_ordinal: Option<u64>,
    replacement_ordinal: Option<u64>,
}

impl WalByKeyValue48 {
    fn decode(bytes: &[u8]) -> Result<Self, CanonicalMembershipError> {
        expect_len(bytes, WAL_BY_KEY_VALUE_BYTES, "WAL by-key value")?;
        if bytes[0] != CANONICAL_MEMBERSHIP_WAL_CODEC_V1 {
            return Err(CanonicalMembershipError::UnsupportedWalCodec(bytes[0]));
        }
        let sequence = decode_ordinal(&bytes[1..1 + SEQUENCE_BYTES], "WAL sequence")?;
        let expected_start = 1 + SEQUENCE_BYTES;
        let expected_ordinal =
            read_option_ordinal(&bytes[expected_start..expected_start + 1 + ORDINAL_BYTES])?;
        let replacement_ordinal =
            read_option_ordinal(&bytes[expected_start + 1 + ORDINAL_BYTES..])?;
        if expected_ordinal == replacement_ordinal {
            return Err(CanonicalMembershipError::EmptyWalMutation);
        }
        Ok(Self {
            sequence,
            expected_ordinal,
            replacement_ordinal,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalMembershipWalByIndexRecord48 {
    pub(crate) family: CanonicalMembershipFamily48,
    pub(crate) ordinal: u64,
    pub(crate) expected: Option<([u8; KEY_BYTES], u64)>,
    pub(crate) replacement: Option<([u8; KEY_BYTES], u64)>,
}

impl CanonicalMembershipWalByIndexRecord48 {
    fn validate(&self) -> Result<(), CanonicalMembershipError> {
        if self.expected == self.replacement {
            return Err(CanonicalMembershipError::EmptyWalMutation);
        }
        for (key, _) in self.expected.into_iter().chain(self.replacement) {
            validate_key(self.family, &key)?;
        }
        Ok(())
    }

    fn encode_value(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WAL_BY_INDEX_VALUE_BYTES);
        out.push(CANONICAL_MEMBERSHIP_WAL_CODEC_V1);
        write_option_key_sequence(&mut out, self.expected);
        write_option_key_sequence(&mut out, self.replacement);
        debug_assert_eq!(out.len(), WAL_BY_INDEX_VALUE_BYTES);
        out
    }

    fn decode_value(
        family: CanonicalMembershipFamily48,
        ordinal: u64,
        bytes: &[u8],
    ) -> Result<Self, CanonicalMembershipError> {
        expect_len(bytes, WAL_BY_INDEX_VALUE_BYTES, "WAL by-index value")?;
        if bytes[0] != CANONICAL_MEMBERSHIP_WAL_CODEC_V1 {
            return Err(CanonicalMembershipError::UnsupportedWalCodec(bytes[0]));
        }
        let option_bytes = 1 + KEY_BYTES + SEQUENCE_BYTES;
        let expected = read_option_key_sequence(&bytes[1..1 + option_bytes])?;
        let replacement = read_option_key_sequence(&bytes[1 + option_bytes..])?;
        let record = Self {
            family,
            ordinal,
            expected,
            replacement,
        };
        record.validate()?;
        Ok(record)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking)]
pub(crate) struct CanonicalMembershipIndexedRow48 {
    pub(crate) ordinal: u64,
    pub(crate) key: [u8; KEY_BYTES],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalNullifierIndexedRowV3 {
    pub(crate) ordinal: u64,
    pub(crate) key: Nullifier48,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalBridgeIndexedRowV3 {
    pub(crate) ordinal: u64,
    pub(crate) key: BridgeReplayKey48,
}

#[derive(Debug, PartialEq, Eq, Encode)]
pub(crate) struct CanonicalMembershipStoreDelta48 {
    family: CanonicalMembershipFamily48Wire,
    base_count: u64,
    final_count: u64,
    removed: Vec<CanonicalMembershipIndexedRow48>,
    inserted: Vec<CanonicalMembershipIndexedRow48>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking)]
struct CanonicalMembershipFamily48Wire(u8);

impl CanonicalMembershipStoreDelta48 {
    fn new(
        family: CanonicalMembershipFamily48,
        base_count: u64,
        final_count: u64,
        removed: Vec<CanonicalMembershipIndexedRow48>,
        inserted: Vec<CanonicalMembershipIndexedRow48>,
    ) -> Result<Self, CanonicalMembershipError> {
        let delta = Self {
            family: CanonicalMembershipFamily48Wire(family.tag()),
            base_count,
            final_count,
            removed,
            inserted,
        };
        delta.validate()?;
        Ok(delta)
    }

    pub(crate) fn nullifiers_v3(
        base_count: u64,
        final_count: u64,
        removed: Vec<CanonicalNullifierIndexedRowV3>,
        inserted: Vec<CanonicalNullifierIndexedRowV3>,
    ) -> Result<Self, CanonicalMembershipError> {
        Self::new(
            CanonicalMembershipFamily48::Nullifier,
            base_count,
            final_count,
            removed
                .into_iter()
                .map(|row| CanonicalMembershipIndexedRow48 {
                    ordinal: row.ordinal,
                    key: row.key.into_bytes(),
                })
                .collect(),
            inserted
                .into_iter()
                .map(|row| CanonicalMembershipIndexedRow48 {
                    ordinal: row.ordinal,
                    key: row.key.into_bytes(),
                })
                .collect(),
        )
    }

    pub(crate) fn bridge_messages_v3(
        base_count: u64,
        final_count: u64,
        removed: Vec<CanonicalBridgeIndexedRowV3>,
        inserted: Vec<CanonicalBridgeIndexedRowV3>,
    ) -> Result<Self, CanonicalMembershipError> {
        Self::new(
            CanonicalMembershipFamily48::ConsumedBridgeMessage,
            base_count,
            final_count,
            removed
                .into_iter()
                .map(|row| CanonicalMembershipIndexedRow48 {
                    ordinal: row.ordinal,
                    key: row.key.into_bytes(),
                })
                .collect(),
            inserted
                .into_iter()
                .map(|row| CanonicalMembershipIndexedRow48 {
                    ordinal: row.ordinal,
                    key: row.key.into_bytes(),
                })
                .collect(),
        )
    }

    pub(crate) fn family(&self) -> CanonicalMembershipFamily48 {
        // Constructors and bounded decode validate this byte once.
        CanonicalMembershipFamily48::from_tag(self.family.0)
            .expect("validated canonical membership family")
    }

    pub(crate) const fn base_count(&self) -> u64 {
        self.base_count
    }

    pub(crate) const fn final_count(&self) -> u64 {
        self.final_count
    }

    pub(crate) fn removed(&self) -> &[CanonicalMembershipIndexedRow48] {
        &self.removed
    }

    pub(crate) fn inserted(&self) -> &[CanonicalMembershipIndexedRow48] {
        &self.inserted
    }

    pub(crate) fn row_count(&self) -> usize {
        self.removed.len().saturating_add(self.inserted.len())
    }

    fn validate(&self) -> Result<(), CanonicalMembershipError> {
        let family = CanonicalMembershipFamily48::from_tag(self.family.0)?;
        let removed_len = u64::try_from(self.removed.len())
            .map_err(|_| CanonicalMembershipError::OrdinalOverflow)?;
        let inserted_len = u64::try_from(self.inserted.len())
            .map_err(|_| CanonicalMembershipError::OrdinalOverflow)?;
        let common_count = self
            .base_count
            .checked_sub(removed_len)
            .ok_or(CanonicalMembershipError::DeltaCountMismatch)?;
        if common_count
            .checked_add(inserted_len)
            .ok_or(CanonicalMembershipError::OrdinalOverflow)?
            != self.final_count
        {
            return Err(CanonicalMembershipError::DeltaCountMismatch);
        }

        let mut removed_keys = BTreeSet::new();
        for (offset, row) in self.removed.iter().enumerate() {
            let offset =
                u64::try_from(offset).map_err(|_| CanonicalMembershipError::OrdinalOverflow)?;
            if row.ordinal != common_count + offset {
                return Err(CanonicalMembershipError::NonContiguousDelta);
            }
            validate_key(family, &row.key)?;
            if !removed_keys.insert(row.key) {
                return Err(CanonicalMembershipError::DuplicateDeltaKey);
            }
        }

        let mut inserted_keys = BTreeSet::new();
        for (offset, row) in self.inserted.iter().enumerate() {
            let offset =
                u64::try_from(offset).map_err(|_| CanonicalMembershipError::OrdinalOverflow)?;
            if row.ordinal != common_count + offset {
                return Err(CanonicalMembershipError::NonContiguousDelta);
            }
            validate_key(family, &row.key)?;
            if !inserted_keys.insert(row.key) {
                return Err(CanonicalMembershipError::DuplicateDeltaKey);
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Encode)]
pub(crate) struct CanonicalMembershipDelta48 {
    schema_version: u16,
    base_epoch: u64,
    next_epoch: u64,
    nullifiers: CanonicalMembershipStoreDelta48,
    bridge_messages: CanonicalMembershipStoreDelta48,
}

#[derive(Decode, DecodeWithMemTracking)]
struct CanonicalMembershipStoreDelta48Wire {
    family: CanonicalMembershipFamily48Wire,
    base_count: u64,
    final_count: u64,
    removed: Vec<CanonicalMembershipIndexedRow48>,
    inserted: Vec<CanonicalMembershipIndexedRow48>,
}

#[derive(Decode, DecodeWithMemTracking)]
struct CanonicalMembershipDelta48Wire {
    schema_version: u16,
    base_epoch: u64,
    next_epoch: u64,
    nullifiers: CanonicalMembershipStoreDelta48Wire,
    bridge_messages: CanonicalMembershipStoreDelta48Wire,
}

impl CanonicalMembershipDelta48 {
    pub(crate) fn new(
        base_epoch: u64,
        next_epoch: u64,
        nullifiers: CanonicalMembershipStoreDelta48,
        bridge_messages: CanonicalMembershipStoreDelta48,
    ) -> Result<Self, CanonicalMembershipError> {
        let delta = Self {
            schema_version: CANONICAL_MEMBERSHIP_SNAPSHOT_SCHEMA_V3,
            base_epoch,
            next_epoch,
            nullifiers,
            bridge_messages,
        };
        delta.validate()?;
        Ok(delta)
    }

    pub(crate) const fn base_epoch(&self) -> u64 {
        self.base_epoch
    }

    pub(crate) const fn next_epoch(&self) -> u64 {
        self.next_epoch
    }

    pub(crate) const fn nullifiers(&self) -> &CanonicalMembershipStoreDelta48 {
        &self.nullifiers
    }

    pub(crate) const fn bridge_messages(&self) -> &CanonicalMembershipStoreDelta48 {
        &self.bridge_messages
    }

    pub(crate) fn row_count(&self) -> usize {
        self.nullifiers
            .row_count()
            .saturating_add(self.bridge_messages.row_count())
    }

    fn validate(&self) -> Result<(), CanonicalMembershipError> {
        if self.schema_version != CANONICAL_MEMBERSHIP_SNAPSHOT_SCHEMA_V3
            || self.base_epoch & 1 != 0
            || self.next_epoch
                != self
                    .base_epoch
                    .checked_add(2)
                    .ok_or(CanonicalMembershipError::EpochOverflow)?
            || self.nullifiers.family() != CanonicalMembershipFamily48::Nullifier
            || self.bridge_messages.family() != CanonicalMembershipFamily48::ConsumedBridgeMessage
        {
            return Err(CanonicalMembershipError::DeltaEpochMismatch);
        }
        self.nullifiers.validate()?;
        self.bridge_messages.validate()?;
        Ok(())
    }

    pub(crate) fn decode_exact_bounded(
        bytes: &[u8],
        max_rows: usize,
    ) -> Result<Self, CanonicalMembershipError> {
        let fixed_slack = 4096usize;
        let max_encoded = max_rows
            .checked_mul(mem::size_of::<CanonicalMembershipIndexedRow48>() + 8)
            .and_then(|bytes| bytes.checked_add(fixed_slack))
            .ok_or(CanonicalMembershipError::DecodeRowLimitExceeded(max_rows))?;
        if bytes.len() > max_encoded {
            return Err(CanonicalMembershipError::DecodeRowLimitExceeded(max_rows));
        }
        let mut cursor = bytes;
        let mem_limit = max_rows
            .checked_mul(mem::size_of::<CanonicalMembershipIndexedRow48>())
            .and_then(|bytes| bytes.checked_add(fixed_slack))
            .ok_or(CanonicalMembershipError::DecodeRowLimitExceeded(max_rows))?;
        let wire = CanonicalMembershipDelta48Wire::decode_with_mem_limit(&mut cursor, mem_limit)
            .map_err(|error| CanonicalMembershipError::Decode(format!("{error:?}")))?;
        if !cursor.is_empty() {
            return Err(CanonicalMembershipError::NonCanonicalEncoding);
        }
        let nullifiers = CanonicalMembershipStoreDelta48::new(
            CanonicalMembershipFamily48::from_tag(wire.nullifiers.family.0)?,
            wire.nullifiers.base_count,
            wire.nullifiers.final_count,
            wire.nullifiers.removed,
            wire.nullifiers.inserted,
        )?;
        let bridge_messages = CanonicalMembershipStoreDelta48::new(
            CanonicalMembershipFamily48::from_tag(wire.bridge_messages.family.0)?,
            wire.bridge_messages.base_count,
            wire.bridge_messages.final_count,
            wire.bridge_messages.removed,
            wire.bridge_messages.inserted,
        )?;
        let value = Self {
            schema_version: wire.schema_version,
            base_epoch: wire.base_epoch,
            next_epoch: wire.next_epoch,
            nullifiers,
            bridge_messages,
        };
        value.validate()?;
        if value.row_count() > max_rows {
            return Err(CanonicalMembershipError::DecodeRowLimitExceeded(max_rows));
        }
        if value.encode().as_slice() != bytes {
            return Err(CanonicalMembershipError::NonCanonicalEncoding);
        }
        Ok(value)
    }
}

#[derive(Debug)]
pub(crate) struct CanonicalMembershipWalPlan48 {
    generation: u64,
    order_records: Vec<CanonicalMembershipWalOrderRecord48>,
    by_index_records: Vec<CanonicalMembershipWalByIndexRecord48>,
    encoded_bytes: u64,
}

fn membership_wal_digest_hasher(
    generation: u64,
    order_rows: u64,
    by_index_rows: u64,
) -> Blake2b384DomainHasher {
    let mut hasher = Blake2b384DomainHasher::new(domains::NATIVE_REORG_WAL_MANIFEST_V3);
    hasher.update_part(WAL_DIGEST_COMPONENT_V3);
    hasher.update_part(&generation.to_be_bytes());
    hasher.update_part(&order_rows.to_be_bytes());
    hasher.update_part(&by_index_rows.to_be_bytes());
    hasher
}

fn update_membership_wal_digest_row(
    hasher: &mut Blake2b384DomainHasher,
    row_tag: &[u8],
    key: &[u8],
    value: &[u8],
) {
    hasher.update_part(row_tag);
    hasher.update_part(key);
    hasher.update_part(value);
}

impl CanonicalMembershipWalPlan48 {
    pub(crate) fn from_delta(
        generation: u64,
        active_wal_generation: Option<u64>,
        delta: &CanonicalMembershipDelta48,
    ) -> Result<Self, CanonicalMembershipError> {
        if generation == 0 {
            return Err(CanonicalMembershipError::ZeroWalGeneration);
        }
        if active_wal_generation.is_some() {
            return Err(CanonicalMembershipError::ActiveWalMustBeFinalized);
        }
        delta.validate()?;

        let mut mutations = Vec::new();
        append_store_mutations(&mut mutations, &delta.nullifiers)?;
        append_store_mutations(&mut mutations, &delta.bridge_messages)?;
        mutations.sort_by_key(|mutation| (mutation.family, mutation.key));

        let mut order_records = Vec::with_capacity(mutations.len());
        for (offset, mutation) in mutations.into_iter().enumerate() {
            let sequence =
                u64::try_from(offset).map_err(|_| CanonicalMembershipError::WalSequenceOverflow)?;
            let record = CanonicalMembershipWalOrderRecord48 {
                sequence,
                family: mutation.family,
                key: mutation.key,
                expected_ordinal: mutation.expected_ordinal,
                replacement_ordinal: mutation.replacement_ordinal,
            };
            record.validate()?;
            order_records.push(record);
        }

        let mut index_mutations = BTreeMap::<
            (CanonicalMembershipFamily48, u64),
            CanonicalMembershipWalByIndexRecord48,
        >::new();
        for record in &order_records {
            if let Some(ordinal) = record.expected_ordinal {
                let entry = index_mutations.entry((record.family, ordinal)).or_insert(
                    CanonicalMembershipWalByIndexRecord48 {
                        family: record.family,
                        ordinal,
                        expected: None,
                        replacement: None,
                    },
                );
                if entry
                    .expected
                    .replace((record.key, record.sequence))
                    .is_some()
                {
                    return Err(CanonicalMembershipError::DuplicateDeltaKey);
                }
            }
            if let Some(ordinal) = record.replacement_ordinal {
                let entry = index_mutations.entry((record.family, ordinal)).or_insert(
                    CanonicalMembershipWalByIndexRecord48 {
                        family: record.family,
                        ordinal,
                        expected: None,
                        replacement: None,
                    },
                );
                if entry
                    .replacement
                    .replace((record.key, record.sequence))
                    .is_some()
                {
                    return Err(CanonicalMembershipError::DuplicateDeltaKey);
                }
            }
        }
        let mut by_index_records = Vec::with_capacity(index_mutations.len());
        for (_, record) in index_mutations {
            if record.expected != record.replacement {
                record.validate()?;
                by_index_records.push(record);
            }
        }

        let order_count = u64::try_from(order_records.len())
            .map_err(|_| CanonicalMembershipError::WalSequenceOverflow)?;
        let index_count = u64::try_from(by_index_records.len())
            .map_err(|_| CanonicalMembershipError::WalSequenceOverflow)?;
        let order_row_bytes = u64::try_from(WAL_ORDER_KEY_BYTES + WAL_ORDER_VALUE_BYTES)
            .map_err(|_| CanonicalMembershipError::WalSequenceOverflow)?;
        let key_row_bytes = u64::try_from(WAL_FORWARD_KEY_BYTES + WAL_BY_KEY_VALUE_BYTES)
            .map_err(|_| CanonicalMembershipError::WalSequenceOverflow)?;
        let index_row_bytes = u64::try_from(WAL_REVERSE_KEY_BYTES + WAL_BY_INDEX_VALUE_BYTES)
            .map_err(|_| CanonicalMembershipError::WalSequenceOverflow)?;
        let encoded_bytes = order_count
            .checked_mul(order_row_bytes + key_row_bytes)
            .and_then(|bytes| {
                index_count
                    .checked_mul(index_row_bytes)
                    .and_then(|index_bytes| bytes.checked_add(index_bytes))
            })
            .ok_or(CanonicalMembershipError::WalSequenceOverflow)?;

        Ok(Self {
            generation,
            order_records,
            by_index_records,
            encoded_bytes,
        })
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn order_records(&self) -> &[CanonicalMembershipWalOrderRecord48] {
        &self.order_records
    }

    pub(crate) fn by_index_records(&self) -> &[CanonicalMembershipWalByIndexRecord48] {
        &self.by_index_records
    }

    pub(crate) fn order_count(&self) -> u64 {
        u64::try_from(self.order_records.len()).unwrap_or(u64::MAX)
    }

    pub(crate) fn by_index_count(&self) -> u64 {
        u64::try_from(self.by_index_records.len()).unwrap_or(u64::MAX)
    }

    pub(crate) const fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }

    /// Digest the exact canonical rows before staging.  Restart recomputes
    /// the same stream directly from the three WAL trees before trusting a
    /// sealed manifest or publishing its active pointer.
    pub(crate) fn sealed_digest(&self) -> [u8; KEY_BYTES] {
        let mut hasher = membership_wal_digest_hasher(
            self.generation,
            self.order_count(),
            self.by_index_count(),
        );
        for record in &self.order_records {
            let key = encode_wal_order_key(self.generation, record.sequence);
            let value = record.encode_value();
            update_membership_wal_digest_row(&mut hasher, WAL_DIGEST_ORDER_ROW_TAG, &key, &value);
        }
        for record in &self.order_records {
            let key = encode_wal_forward_key(self.generation, record.family, &record.key);
            let value = record.encode_by_key_value();
            update_membership_wal_digest_row(&mut hasher, WAL_DIGEST_BY_KEY_ROW_TAG, &key, &value);
        }
        for record in &self.by_index_records {
            let key = encode_wal_reverse_key(self.generation, record.family, record.ordinal);
            let value = record.encode_value();
            update_membership_wal_digest_row(
                &mut hasher,
                WAL_DIGEST_BY_INDEX_ROW_TAG,
                &key,
                &value,
            );
        }
        hasher.finalize()
    }

    pub(crate) fn encoded_order_row(
        &self,
        offset: usize,
    ) -> Option<([u8; WAL_ORDER_KEY_BYTES], Vec<u8>)> {
        self.order_records.get(offset).map(|record| {
            (
                encode_wal_order_key(self.generation, record.sequence),
                record.encode_value(),
            )
        })
    }

    pub(crate) fn encoded_by_key_row(
        &self,
        offset: usize,
    ) -> Option<([u8; WAL_FORWARD_KEY_BYTES], Vec<u8>)> {
        self.order_records.get(offset).map(|record| {
            (
                encode_wal_forward_key(self.generation, record.family, &record.key),
                record.encode_by_key_value(),
            )
        })
    }

    pub(crate) fn encoded_by_index_row(
        &self,
        offset: usize,
    ) -> Option<([u8; WAL_REVERSE_KEY_BYTES], Vec<u8>)> {
        self.by_index_records.get(offset).map(|record| {
            (
                encode_wal_reverse_key(self.generation, record.family, record.ordinal),
                record.encode_value(),
            )
        })
    }

    /// Idempotently stage a bounded order/by-key slice.  Partial staging is
    /// safe because this generation remains invisible until the outer sealed
    /// manifest and active-pointer transaction succeeds.
    pub(crate) fn stage_order_batch(
        &self,
        wal_by_key: &sled::Tree,
        wal_order: &sled::Tree,
        range: Range<usize>,
    ) -> Result<CanonicalMembershipWalStageWork, CanonicalMembershipError> {
        require_tree_name(wal_by_key, CANONICAL_MEMBERSHIP_WAL_BY_KEY_TREE_V3)?;
        require_tree_name(wal_order, CANONICAL_MEMBERSHIP_WAL_ORDER_TREE_V3)?;
        if range.start > range.end || range.end > self.order_records.len() {
            return Err(CanonicalMembershipError::WalOrderGap);
        }
        let mut work = CanonicalMembershipWalStageWork::default();
        for offset in range {
            let (order_key, order_value) = self
                .encoded_order_row(offset)
                .ok_or(CanonicalMembershipError::WalOrderGap)?;
            let (forward_key, forward_value) = self
                .encoded_by_key_row(offset)
                .ok_or(CanonicalMembershipError::WalOrderGap)?;
            insert_staged_row_idempotent(wal_order, &order_key, &order_value)?;
            insert_staged_row_idempotent(wal_by_key, &forward_key, &forward_value)?;
            work.rows = work.rows.saturating_add(2);
            work.bytes = work
                .bytes
                .saturating_add(order_key.len() + order_value.len())
                .saturating_add(forward_key.len() + forward_value.len());
        }
        Ok(work)
    }

    /// Idempotently stage a bounded by-index slice for this inactive WAL.
    pub(crate) fn stage_index_batch(
        &self,
        wal_by_index: &sled::Tree,
        range: Range<usize>,
    ) -> Result<CanonicalMembershipWalStageWork, CanonicalMembershipError> {
        require_tree_name(wal_by_index, CANONICAL_MEMBERSHIP_WAL_BY_INDEX_TREE_V3)?;
        if range.start > range.end || range.end > self.by_index_records.len() {
            return Err(CanonicalMembershipError::WalOrderGap);
        }
        let mut work = CanonicalMembershipWalStageWork::default();
        for offset in range {
            let (key, value) = self
                .encoded_by_index_row(offset)
                .ok_or(CanonicalMembershipError::WalOrderGap)?;
            insert_staged_row_idempotent(wal_by_index, &key, &value)?;
            work.rows = work.rows.saturating_add(1);
            work.bytes = work.bytes.saturating_add(key.len() + value.len());
        }
        Ok(work)
    }
}

#[derive(Clone, Copy, Debug)]
struct UnsequencedWalMutation48 {
    family: CanonicalMembershipFamily48,
    key: [u8; KEY_BYTES],
    expected_ordinal: Option<u64>,
    replacement_ordinal: Option<u64>,
}

fn append_store_mutations(
    out: &mut Vec<UnsequencedWalMutation48>,
    delta: &CanonicalMembershipStoreDelta48,
) -> Result<(), CanonicalMembershipError> {
    delta.validate()?;
    let family = delta.family();
    let mut by_key = BTreeMap::<[u8; KEY_BYTES], (Option<u64>, Option<u64>)>::new();
    for row in &delta.removed {
        if by_key.insert(row.key, (Some(row.ordinal), None)).is_some() {
            return Err(CanonicalMembershipError::DuplicateDeltaKey);
        }
    }
    for row in &delta.inserted {
        let entry = by_key.entry(row.key).or_insert((None, None));
        if entry.1.replace(row.ordinal).is_some() {
            return Err(CanonicalMembershipError::DuplicateDeltaKey);
        }
    }
    for (key, (expected_ordinal, replacement_ordinal)) in by_key {
        if expected_ordinal != replacement_ordinal {
            out.push(UnsequencedWalMutation48 {
                family,
                key,
                expected_ordinal,
                replacement_ordinal,
            });
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CanonicalMembershipWalStageWork {
    pub(crate) rows: usize,
    pub(crate) bytes: usize,
}

fn insert_staged_row_idempotent(
    tree: &sled::Tree,
    key: &[u8],
    value: &[u8],
) -> Result<(), CanonicalMembershipError> {
    match tree.compare_and_swap(key, None as Option<&[u8]>, Some(value))? {
        Ok(()) => Ok(()),
        Err(conflict) if conflict.current.as_deref() == Some(value) => Ok(()),
        Err(_) => Err(CanonicalMembershipError::WalStageConflict),
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CanonicalMembershipWalDiscardWork {
    pub(crate) removed_rows: usize,
    pub(crate) removed_bytes: usize,
    pub(crate) generation_empty: bool,
}

fn native_reorg_wal_sealed_key(generation: u64) -> [u8; 15] {
    let mut key = [0u8; 15];
    key[..NATIVE_REORG_WAL_SEALED_PREFIX_V3.len()]
        .copy_from_slice(NATIVE_REORG_WAL_SEALED_PREFIX_V3);
    key[NATIVE_REORG_WAL_SEALED_PREFIX_V3.len()..].copy_from_slice(&generation.to_be_bytes());
    key
}

#[derive(Clone, Copy)]
enum WalCleanupTree48 {
    ByKey,
    ByIndex,
    Order,
}

#[derive(Clone, Copy, Debug)]
enum WalCleanupAbort48 {
    Active,
    Sealed,
    InvalidActivePointer,
}

/// Recoverably delete an unsealed/inactive generation in bounded memory.
/// Every bounded deletion batch atomically checks the authoritative active
/// pointer and the target's sealed-manifest row in the outer manifest tree.
/// The outer reorg-WAL mutex also serializes stage/seal/cleanup/flip; the
/// transactional checks preserve fail-closed recovery after restart.
pub(crate) fn discard_inactive_membership_wal_batch(
    manifest: &sled::Tree,
    wal_by_key: &sled::Tree,
    wal_by_index: &sled::Tree,
    wal_order: &sled::Tree,
    generation: u64,
    max_rows: usize,
) -> Result<CanonicalMembershipWalDiscardWork, CanonicalMembershipError> {
    if generation == 0 {
        return Err(CanonicalMembershipError::ZeroWalGeneration);
    }
    if max_rows == 0 {
        return Err(CanonicalMembershipError::ZeroBatchLimit);
    }
    if max_rows > MAX_CANONICAL_MEMBERSHIP_WAL_CLEANUP_BATCH_ROWS {
        return Err(CanonicalMembershipError::CleanupBatchLimitExceeded(
            MAX_CANONICAL_MEMBERSHIP_WAL_CLEANUP_BATCH_ROWS,
        ));
    }
    require_tree_name(manifest, NATIVE_REORG_WAL_MANIFEST_TREE_V3)?;
    require_tree_name(wal_by_key, CANONICAL_MEMBERSHIP_WAL_BY_KEY_TREE_V3)?;
    require_tree_name(wal_by_index, CANONICAL_MEMBERSHIP_WAL_BY_INDEX_TREE_V3)?;
    require_tree_name(wal_order, CANONICAL_MEMBERSHIP_WAL_ORDER_TREE_V3)?;
    let prefix = generation.to_be_bytes();
    let mut candidates = Vec::with_capacity(max_rows);
    for (slot, tree) in [
        (WalCleanupTree48::ByKey, wal_by_key),
        (WalCleanupTree48::ByIndex, wal_by_index),
        (WalCleanupTree48::Order, wal_order),
    ] {
        let remaining = max_rows.saturating_sub(candidates.len());
        if remaining == 0 {
            break;
        }
        let keys = tree
            .scan_prefix(prefix)
            .keys()
            .take(remaining)
            .collect::<Result<Vec<_>, _>>()?;
        for key in keys {
            candidates.push((slot, key));
        }
    }

    let sealed_key = native_reorg_wal_sealed_key(generation);
    let transaction_result = (manifest, wal_by_key, wal_by_index, wal_order).transaction(
        |(manifest, wal_by_key, wal_by_index, wal_order)| {
            if let Some(encoded) = manifest.get(NATIVE_REORG_WAL_ACTIVE_KEY_V3)? {
                let bytes = encoded.as_ref();
                if bytes.len() != GENERATION_BYTES {
                    return Err(ConflictableTransactionError::Abort(
                        WalCleanupAbort48::InvalidActivePointer,
                    ));
                }
                let mut generation_bytes = [0u8; GENERATION_BYTES];
                generation_bytes.copy_from_slice(bytes);
                let active_generation = u64::from_be_bytes(generation_bytes);
                if active_generation == 0 {
                    return Err(ConflictableTransactionError::Abort(
                        WalCleanupAbort48::InvalidActivePointer,
                    ));
                }
                if active_generation == generation {
                    return Err(ConflictableTransactionError::Abort(
                        WalCleanupAbort48::Active,
                    ));
                }
            }
            if manifest.get(sealed_key.as_slice())?.is_some() {
                return Err(ConflictableTransactionError::Abort(
                    WalCleanupAbort48::Sealed,
                ));
            }

            let mut removed_rows = 0usize;
            let mut removed_bytes = 0usize;
            for (slot, key) in &candidates {
                let removed = match slot {
                    WalCleanupTree48::ByKey => wal_by_key.remove(key.as_ref())?,
                    WalCleanupTree48::ByIndex => wal_by_index.remove(key.as_ref())?,
                    WalCleanupTree48::Order => wal_order.remove(key.as_ref())?,
                };
                if let Some(value) = removed {
                    removed_rows = removed_rows.saturating_add(1);
                    removed_bytes = removed_bytes
                        .saturating_add(key.len())
                        .saturating_add(value.len());
                }
            }
            Ok((removed_rows, removed_bytes))
        },
    );
    let (removed_rows, removed_bytes) = match transaction_result {
        Ok(work) => work,
        Err(sled::transaction::TransactionError::Abort(WalCleanupAbort48::Active)) => {
            return Err(CanonicalMembershipError::CannotDiscardActiveWal);
        }
        Err(sled::transaction::TransactionError::Abort(WalCleanupAbort48::Sealed)) => {
            return Err(CanonicalMembershipError::CannotDiscardSealedWal);
        }
        Err(sled::transaction::TransactionError::Abort(
            WalCleanupAbort48::InvalidActivePointer,
        )) => return Err(CanonicalMembershipError::InvalidActiveWalPointer),
        Err(sled::transaction::TransactionError::Storage(error)) => return Err(error.into()),
    };
    let mut work = CanonicalMembershipWalDiscardWork {
        removed_rows,
        removed_bytes,
        generation_empty: false,
    };
    work.generation_empty = [wal_by_key, wal_by_index, wal_order]
        .iter()
        .all(|tree| tree.scan_prefix(prefix).next().is_none());
    Ok(work)
}

fn require_tree_name(tree: &sled::Tree, expected: &[u8]) -> Result<(), CanonicalMembershipError> {
    let observed = tree.name();
    if observed.as_ref() != expected {
        return Err(CanonicalMembershipError::TreeNameMismatch {
            expected: String::from_utf8_lossy(expected).into_owned(),
            observed: String::from_utf8_lossy(observed.as_ref()).into_owned(),
        });
    }
    Ok(())
}

/// Process-local seqlock coordinated with the persisted compact snapshot.
/// Stable epochs are even; odd means a storage flip may have committed and no
/// view is permitted to answer.  An uncertain guard deliberately leaves the
/// epoch odd on drop, which is fail-closed after a panic between sled commit
/// and in-memory publication.
#[derive(Clone, Debug)]
pub(crate) struct CanonicalMembershipEpoch {
    value: Arc<AtomicU64>,
}

impl CanonicalMembershipEpoch {
    pub(crate) fn new(stable_epoch: u64) -> Result<Self, CanonicalMembershipError> {
        if stable_epoch & 1 != 0 {
            return Err(CanonicalMembershipError::UnstableEpoch(stable_epoch));
        }
        stable_epoch
            .checked_add(2)
            .ok_or(CanonicalMembershipError::EpochOverflow)?;
        Ok(Self {
            value: Arc::new(AtomicU64::new(stable_epoch)),
        })
    }

    pub(crate) fn load(&self) -> u64 {
        self.value.load(Ordering::Acquire)
    }

    pub(crate) fn verify_stable(&self, expected: u64) -> Result<(), CanonicalMembershipError> {
        let observed = self.load();
        if observed != expected || observed & 1 != 0 {
            return Err(CanonicalMembershipError::StaleView { expected, observed });
        }
        Ok(())
    }

    pub(crate) fn begin_mutation(
        &self,
        expected: u64,
        target_snapshot: &CanonicalMembershipSnapshotV3,
    ) -> Result<CanonicalMembershipPreparedMutation, CanonicalMembershipError> {
        if expected & 1 != 0 {
            return Err(CanonicalMembershipError::UnstableEpoch(expected));
        }
        let odd = expected
            .checked_add(1)
            .ok_or(CanonicalMembershipError::EpochOverflow)?;
        let next = expected
            .checked_add(2)
            .ok_or(CanonicalMembershipError::EpochOverflow)?;
        target_snapshot.validate()?;
        if target_snapshot.stable_epoch != next {
            return Err(CanonicalMembershipError::InvalidRebase(
                "target snapshot is not the next stable epoch",
            ));
        }
        self.value
            .compare_exchange(expected, odd, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|observed| CanonicalMembershipError::EpochConflict { expected, observed })?;
        Ok(CanonicalMembershipPreparedMutation {
            epoch: self.clone(),
            previous: expected,
            next,
            target_snapshot: target_snapshot.clone(),
            restore_on_drop: true,
        })
    }
}

pub(crate) struct CanonicalMembershipPreparedMutation {
    epoch: CanonicalMembershipEpoch,
    previous: u64,
    next: u64,
    target_snapshot: CanonicalMembershipSnapshotV3,
    restore_on_drop: bool,
}

impl CanonicalMembershipPreparedMutation {
    /// Call immediately before entering the sled transaction which may flip
    /// the active WAL pointer.  Dropping the returned uncertain guard leaves
    /// the epoch odd; the caller must explicitly confirm abort or commit.
    pub(crate) fn storage_may_commit(mut self) -> CanonicalMembershipUncertainMutation {
        self.restore_on_drop = false;
        CanonicalMembershipUncertainMutation {
            epoch: self.epoch.clone(),
            previous: self.previous,
            next: self.next,
            target_snapshot: self.target_snapshot.clone(),
        }
    }
}

impl Drop for CanonicalMembershipPreparedMutation {
    fn drop(&mut self) {
        if self.restore_on_drop {
            self.epoch.value.store(self.previous, Ordering::Release);
        }
    }
}

#[must_use = "a storage outcome must be confirmed so the membership epoch cannot remain poisoned"]
pub(crate) struct CanonicalMembershipUncertainMutation {
    epoch: CanonicalMembershipEpoch,
    previous: u64,
    next: u64,
    target_snapshot: CanonicalMembershipSnapshotV3,
}

impl CanonicalMembershipUncertainMutation {
    pub(crate) fn abort_confirmed(self) {
        self.epoch.value.store(self.previous, Ordering::Release);
    }

    pub(crate) fn commit_confirmed(self) -> CanonicalMembershipCommittedEpoch {
        self.epoch.value.store(self.next, Ordering::Release);
        CanonicalMembershipCommittedEpoch {
            epoch: self.epoch,
            previous: self.previous,
            next: self.next,
            target_snapshot: self.target_snapshot,
        }
    }
}

#[must_use = "the committed membership epoch must be consumed by paired view publication"]
#[derive(Debug)]
pub(crate) struct CanonicalMembershipCommittedEpoch {
    epoch: CanonicalMembershipEpoch,
    previous: u64,
    next: u64,
    target_snapshot: CanonicalMembershipSnapshotV3,
}

impl CanonicalMembershipCommittedEpoch {
    pub(crate) const fn previous(&self) -> u64 {
        self.previous
    }

    pub(crate) const fn next(&self) -> u64 {
        self.next
    }

    pub(crate) const fn target_snapshot(&self) -> &CanonicalMembershipSnapshotV3 {
        &self.target_snapshot
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode)]
pub(crate) struct CanonicalMembershipSnapshotV3 {
    schema_version: u16,
    stable_epoch: u64,
    base_generation: u64,
    active_wal_generation: Option<u64>,
    canonical_tip_binding: [u8; KEY_BYTES],
    base_nullifier_count: u64,
    nullifier_count: u64,
    base_bridge_count: u64,
    bridge_count: u64,
    active_wal_sealed_digest: Option<[u8; KEY_BYTES]>,
}

#[derive(Decode, DecodeWithMemTracking)]
struct CanonicalMembershipSnapshotV3Wire {
    schema_version: u16,
    stable_epoch: u64,
    base_generation: u64,
    active_wal_generation: Option<u64>,
    canonical_tip_binding: [u8; KEY_BYTES],
    base_nullifier_count: u64,
    nullifier_count: u64,
    base_bridge_count: u64,
    bridge_count: u64,
    active_wal_sealed_digest: Option<[u8; KEY_BYTES]>,
}

impl Decode for CanonicalMembershipSnapshotV3 {
    fn decode<I: codec::Input>(input: &mut I) -> Result<Self, codec::Error> {
        let wire = CanonicalMembershipSnapshotV3Wire::decode(input)?;
        Self::from_wire(wire)
            .map_err(|_| codec::Error::from("invalid canonical membership snapshot"))
    }
}

impl DecodeWithMemTracking for CanonicalMembershipSnapshotV3 {}

impl CanonicalMembershipSnapshotV3 {
    fn from_wire(
        wire: CanonicalMembershipSnapshotV3Wire,
    ) -> Result<Self, CanonicalMembershipError> {
        let snapshot = Self {
            schema_version: wire.schema_version,
            stable_epoch: wire.stable_epoch,
            base_generation: wire.base_generation,
            active_wal_generation: wire.active_wal_generation,
            canonical_tip_binding: wire.canonical_tip_binding,
            base_nullifier_count: wire.base_nullifier_count,
            nullifier_count: wire.nullifier_count,
            base_bridge_count: wire.base_bridge_count,
            bridge_count: wire.bridge_count,
            active_wal_sealed_digest: wire.active_wal_sealed_digest,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub(crate) fn new(
        stable_epoch: u64,
        base_generation: u64,
        active_wal_generation: Option<u64>,
        canonical_tip_binding: [u8; KEY_BYTES],
        base_nullifier_count: u64,
        nullifier_count: u64,
        base_bridge_count: u64,
        bridge_count: u64,
        active_wal_sealed_digest: Option<[u8; KEY_BYTES]>,
    ) -> Result<Self, CanonicalMembershipError> {
        let snapshot = Self {
            schema_version: CANONICAL_MEMBERSHIP_SNAPSHOT_SCHEMA_V3,
            stable_epoch,
            base_generation,
            active_wal_generation,
            canonical_tip_binding,
            base_nullifier_count,
            nullifier_count,
            base_bridge_count,
            bridge_count,
            active_wal_sealed_digest,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn validate(&self) -> Result<(), CanonicalMembershipError> {
        if self.schema_version != CANONICAL_MEMBERSHIP_SNAPSHOT_SCHEMA_V3 {
            return Err(CanonicalMembershipError::InvalidSnapshot(
                "unsupported schema",
            ));
        }
        if self.stable_epoch & 1 != 0 {
            return Err(CanonicalMembershipError::InvalidSnapshot(
                "odd membership epoch",
            ));
        }
        match (self.active_wal_generation, self.active_wal_sealed_digest) {
            (None, None)
                if self.base_nullifier_count == self.nullifier_count
                    && self.base_bridge_count == self.bridge_count => {}
            (Some(generation), Some(_)) if generation != 0 => {}
            (None, None) => {
                return Err(CanonicalMembershipError::InvalidSnapshot(
                    "base/final counts differ without an active WAL",
                ));
            }
            _ => {
                return Err(CanonicalMembershipError::InvalidSnapshot(
                    "active WAL generation/digest pairing",
                ));
            }
        }
        Ok(())
    }

    pub(crate) const fn stable_epoch(&self) -> u64 {
        self.stable_epoch
    }

    pub(crate) const fn base_generation(&self) -> u64 {
        self.base_generation
    }

    pub(crate) const fn active_wal_generation(&self) -> Option<u64> {
        self.active_wal_generation
    }

    pub(crate) const fn nullifier_count(&self) -> u64 {
        self.nullifier_count
    }

    pub(crate) const fn bridge_count(&self) -> u64 {
        self.bridge_count
    }

    pub(crate) const fn base_nullifier_count(&self) -> u64 {
        self.base_nullifier_count
    }

    pub(crate) const fn base_bridge_count(&self) -> u64 {
        self.base_bridge_count
    }

    pub(crate) const fn canonical_tip_binding(&self) -> &[u8; KEY_BYTES] {
        &self.canonical_tip_binding
    }

    pub(crate) const fn active_wal_sealed_digest(&self) -> Option<[u8; KEY_BYTES]> {
        self.active_wal_sealed_digest
    }

    pub(crate) fn decode_exact(bytes: &[u8]) -> Result<Self, CanonicalMembershipError> {
        // The snapshot contains no variable-size collection, so a small fixed
        // memory bound also rejects any future allocation-bearing drift.
        let mut cursor = bytes;
        let wire = CanonicalMembershipSnapshotV3Wire::decode_with_mem_limit(&mut cursor, 1024)
            .map_err(|error| CanonicalMembershipError::Decode(format!("{error:?}")))?;
        if !cursor.is_empty() {
            return Err(CanonicalMembershipError::NonCanonicalEncoding);
        }
        let snapshot = Self::from_wire(wire)?;
        if snapshot.encode().as_slice() != bytes {
            return Err(CanonicalMembershipError::NonCanonicalEncoding);
        }
        Ok(snapshot)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CanonicalMembershipReadBinding {
    stable_epoch: u64,
    base_generation: u64,
    active_wal_generation: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
struct CacheEntry48 {
    binding: CanonicalMembershipReadBinding,
    ordinal: Option<u64>,
    sequence: u64,
}

#[derive(Debug)]
struct ExactMembershipCache48 {
    capacity: usize,
    binding: Option<CanonicalMembershipReadBinding>,
    next_sequence: u64,
    entries: BTreeMap<[u8; KEY_BYTES], CacheEntry48>,
    order: VecDeque<([u8; KEY_BYTES], u64)>,
}

impl ExactMembershipCache48 {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            binding: None,
            next_sequence: 0,
            entries: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(
        &self,
        binding: CanonicalMembershipReadBinding,
        key: &[u8; KEY_BYTES],
    ) -> Option<Option<u64>> {
        self.entries
            .get(key)
            .filter(|entry| entry.binding == binding)
            .map(|entry| entry.ordinal)
    }

    fn insert(
        &mut self,
        binding: CanonicalMembershipReadBinding,
        key: [u8; KEY_BYTES],
        ordinal: Option<u64>,
    ) {
        if self.capacity == 0 {
            return;
        }
        if self.binding != Some(binding) {
            self.entries.clear();
            self.order.clear();
            self.binding = Some(binding);
        }
        if self.next_sequence == u64::MAX {
            self.entries.clear();
            self.order.clear();
            self.next_sequence = 0;
        }
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.entries.insert(
            key,
            CacheEntry48 {
                binding,
                ordinal,
                sequence,
            },
        );
        self.order.push_back((key, sequence));
        while self.entries.len() > self.capacity {
            let Some((old_key, old_sequence)) = self.order.pop_front() else {
                break;
            };
            if self
                .entries
                .get(&old_key)
                .is_some_and(|entry| entry.sequence == old_sequence)
            {
                self.entries.remove(&old_key);
            }
        }
        while self.order.len() > self.capacity.saturating_mul(4).max(self.capacity) {
            let Some((old_key, old_sequence)) = self.order.pop_front() else {
                break;
            };
            if self
                .entries
                .get(&old_key)
                .is_some_and(|entry| entry.sequence == old_sequence)
            {
                self.entries.remove(&old_key);
            }
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Debug, Default)]
struct CanonicalMembershipIndexMetrics {
    disk_point_reads: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    stale_rejections: AtomicU64,
}

fn increment_metric(metric: &AtomicU64) {
    let _ = metric.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CanonicalMembershipPointReadMetrics {
    pub(crate) disk_point_reads: u64,
    pub(crate) cache_hits: u64,
    pub(crate) cache_misses: u64,
    pub(crate) stale_rejections: u64,
    pub(crate) cache_entries: usize,
    pub(crate) cache_capacity: usize,
}

struct CanonicalMembershipIndexInner48 {
    family: CanonicalMembershipFamily48,
    base_by_key: sled::Tree,
    base_by_index: sled::Tree,
    wal_by_key: sled::Tree,
    wal_by_index: sled::Tree,
    epoch: CanonicalMembershipEpoch,
    cache: Mutex<ExactMembershipCache48>,
    metrics: CanonicalMembershipIndexMetrics,
}

#[derive(Clone)]
pub(crate) struct CanonicalMembershipIndex48 {
    inner: Arc<CanonicalMembershipIndexInner48>,
}

impl fmt::Debug for CanonicalMembershipIndex48 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalMembershipIndex48")
            .field("family", &self.inner.family)
            .field("base_by_key", &self.inner.base_by_key.name())
            .field("base_by_index", &self.inner.base_by_index.name())
            .finish_non_exhaustive()
    }
}

impl CanonicalMembershipIndex48 {
    pub(crate) fn from_open_trees(
        family: CanonicalMembershipFamily48,
        base_by_key: sled::Tree,
        base_by_index: sled::Tree,
        wal_by_key: sled::Tree,
        wal_by_index: sled::Tree,
        wal_order: sled::Tree,
        epoch: CanonicalMembershipEpoch,
        cache_capacity: usize,
    ) -> Result<Self, CanonicalMembershipError> {
        if cache_capacity > MAX_CANONICAL_MEMBERSHIP_CACHE_KEYS {
            return Err(CanonicalMembershipError::CacheCapacityExceeded(
                cache_capacity,
            ));
        }
        let (expected_key_name, expected_index_name) = family.base_tree_names();
        require_tree_name(&base_by_key, expected_key_name)?;
        require_tree_name(&base_by_index, expected_index_name)?;
        require_tree_name(&wal_by_key, CANONICAL_MEMBERSHIP_WAL_BY_KEY_TREE_V3)?;
        require_tree_name(&wal_by_index, CANONICAL_MEMBERSHIP_WAL_BY_INDEX_TREE_V3)?;
        require_tree_name(&wal_order, CANONICAL_MEMBERSHIP_WAL_ORDER_TREE_V3)?;
        Ok(Self {
            inner: Arc::new(CanonicalMembershipIndexInner48 {
                family,
                base_by_key,
                base_by_index,
                wal_by_key,
                wal_by_index,
                epoch,
                cache: Mutex::new(ExactMembershipCache48::new(cache_capacity)),
                metrics: CanonicalMembershipIndexMetrics::default(),
            }),
        })
    }

    pub(crate) fn family(&self) -> CanonicalMembershipFamily48 {
        self.inner.family
    }

    fn verify_epoch(
        &self,
        binding: CanonicalMembershipReadBinding,
    ) -> Result<(), CanonicalMembershipError> {
        match self.inner.epoch.verify_stable(binding.stable_epoch) {
            Ok(()) => Ok(()),
            Err(error) => {
                increment_metric(&self.inner.metrics.stale_rejections);
                Err(error)
            }
        }
    }

    fn ordinal_of_key(
        &self,
        binding: CanonicalMembershipReadBinding,
        key: &[u8; KEY_BYTES],
    ) -> Result<Option<u64>, CanonicalMembershipError> {
        validate_key(self.inner.family, key)?;
        self.verify_epoch(binding)?;
        if let Some(cached) = self.inner.cache.lock().get(binding, key) {
            increment_metric(&self.inner.metrics.cache_hits);
            self.verify_epoch(binding)?;
            return Ok(cached);
        }
        increment_metric(&self.inner.metrics.cache_misses);
        let ordinal = if let Some(wal_generation) = binding.active_wal_generation {
            let wal_key = encode_wal_forward_key(wal_generation, self.inner.family, key);
            increment_metric(&self.inner.metrics.disk_point_reads);
            match self.inner.wal_by_key.get(wal_key)? {
                Some(encoded) => WalByKeyValue48::decode(encoded.as_ref())?.replacement_ordinal,
                None => self.base_ordinal(binding.base_generation, key)?,
            }
        } else {
            self.base_ordinal(binding.base_generation, key)?
        };
        self.verify_epoch(binding)?;
        self.inner.cache.lock().insert(binding, *key, ordinal);
        Ok(ordinal)
    }

    fn base_ordinal(
        &self,
        base_generation: u64,
        key: &[u8; KEY_BYTES],
    ) -> Result<Option<u64>, CanonicalMembershipError> {
        let base_key = encode_membership_base_forward_key(base_generation, key);
        increment_metric(&self.inner.metrics.disk_point_reads);
        self.inner
            .base_by_key
            .get(base_key)?
            .map(|encoded| decode_ordinal(encoded.as_ref(), "base forward ordinal"))
            .transpose()
    }

    fn key_at_ordinal(
        &self,
        binding: CanonicalMembershipReadBinding,
        ordinal: u64,
    ) -> Result<Option<[u8; KEY_BYTES]>, CanonicalMembershipError> {
        self.verify_epoch(binding)?;
        let key = if let Some(wal_generation) = binding.active_wal_generation {
            let wal_key = encode_wal_reverse_key(wal_generation, self.inner.family, ordinal);
            increment_metric(&self.inner.metrics.disk_point_reads);
            match self.inner.wal_by_index.get(wal_key)? {
                Some(encoded) => CanonicalMembershipWalByIndexRecord48::decode_value(
                    self.inner.family,
                    ordinal,
                    encoded.as_ref(),
                )?
                .replacement
                .map(|(key, _)| key),
                None => self.base_key(binding.base_generation, ordinal)?,
            }
        } else {
            self.base_key(binding.base_generation, ordinal)?
        };
        if let Some(key) = key {
            validate_key(self.inner.family, &key)?;
        }
        self.verify_epoch(binding)?;
        Ok(key)
    }

    fn base_key(
        &self,
        base_generation: u64,
        ordinal: u64,
    ) -> Result<Option<[u8; KEY_BYTES]>, CanonicalMembershipError> {
        let base_key = encode_membership_base_reverse_key(base_generation, ordinal);
        increment_metric(&self.inner.metrics.disk_point_reads);
        self.inner
            .base_by_index
            .get(base_key)?
            .map(|encoded| read_array(encoded.as_ref(), "base reverse member key"))
            .transpose()
    }

    pub(crate) fn point_read_metrics(&self) -> CanonicalMembershipPointReadMetrics {
        let cache = self.inner.cache.lock();
        CanonicalMembershipPointReadMetrics {
            disk_point_reads: self.inner.metrics.disk_point_reads.load(Ordering::Relaxed),
            cache_hits: self.inner.metrics.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.inner.metrics.cache_misses.load(Ordering::Relaxed),
            stale_rejections: self.inner.metrics.stale_rejections.load(Ordering::Relaxed),
            cache_entries: cache.len(),
            cache_capacity: cache.capacity,
        }
    }
}

/// Constructs the two family indexes from one explicit seven-tree handle set.
/// Outer startup performs namespace preflight before opening these handles;
/// this constructor only validates names and never creates a tree.
#[derive(Clone, Debug)]
pub(crate) struct CanonicalMembershipIndexes48 {
    nullifiers: CanonicalMembershipIndex48,
    bridge_messages: CanonicalMembershipIndex48,
}

impl CanonicalMembershipIndexes48 {
    pub(crate) fn from_open_trees(
        nullifier_base_by_key: sled::Tree,
        nullifier_base_by_index: sled::Tree,
        bridge_base_by_key: sled::Tree,
        bridge_base_by_index: sled::Tree,
        wal_by_key: sled::Tree,
        wal_by_index: sled::Tree,
        wal_order: sled::Tree,
        epoch: CanonicalMembershipEpoch,
        cache_capacity: usize,
    ) -> Result<Self, CanonicalMembershipError> {
        let nullifiers = CanonicalMembershipIndex48::from_open_trees(
            CanonicalMembershipFamily48::Nullifier,
            nullifier_base_by_key,
            nullifier_base_by_index,
            wal_by_key.clone(),
            wal_by_index.clone(),
            wal_order.clone(),
            epoch.clone(),
            cache_capacity,
        )?;
        let bridge_messages = CanonicalMembershipIndex48::from_open_trees(
            CanonicalMembershipFamily48::ConsumedBridgeMessage,
            bridge_base_by_key,
            bridge_base_by_index,
            wal_by_key,
            wal_by_index,
            wal_order,
            epoch,
            cache_capacity,
        )?;
        Ok(Self {
            nullifiers,
            bridge_messages,
        })
    }

    pub(crate) fn views_from_snapshot(
        self,
        snapshot: &CanonicalMembershipSnapshotV3,
        overlay_capacity: usize,
    ) -> Result<CanonicalMembershipViews48, CanonicalMembershipError> {
        CanonicalMembershipViews48::from_snapshot(
            self.nullifiers,
            self.bridge_messages,
            snapshot,
            overlay_capacity,
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CanonicalMembershipView48 {
    index: CanonicalMembershipIndex48,
    binding: CanonicalMembershipReadBinding,
    logical_count: u64,
    inserted: PersistentKeySet48,
    removed: PersistentKeySet48,
    overlay_capacity: usize,
}

impl CanonicalMembershipView48 {
    fn new(
        index: CanonicalMembershipIndex48,
        stable_epoch: u64,
        base_generation: u64,
        active_wal_generation: Option<u64>,
        logical_count: u64,
        overlay_capacity: usize,
    ) -> Result<Self, CanonicalMembershipError> {
        if overlay_capacity == 0 {
            return Err(CanonicalMembershipError::ZeroOverlayCapacity);
        }
        index.inner.epoch.verify_stable(stable_epoch)?;
        Ok(Self {
            index,
            binding: CanonicalMembershipReadBinding {
                stable_epoch,
                base_generation,
                active_wal_generation,
            },
            logical_count,
            inserted: PersistentKeySet48::new(),
            removed: PersistentKeySet48::new(),
            overlay_capacity,
        })
    }

    pub(crate) fn family(&self) -> CanonicalMembershipFamily48 {
        self.index.family()
    }

    pub(crate) const fn logical_count(&self) -> u64 {
        self.logical_count
    }

    pub(crate) const fn stable_epoch(&self) -> u64 {
        self.binding.stable_epoch
    }

    pub(crate) const fn base_generation(&self) -> u64 {
        self.binding.base_generation
    }

    pub(crate) const fn active_wal_generation(&self) -> Option<u64> {
        self.binding.active_wal_generation
    }

    pub(crate) fn contains(&self, key: &[u8; KEY_BYTES]) -> Result<bool, CanonicalMembershipError> {
        validate_key(self.family(), key)?;
        self.index.verify_epoch(self.binding)?;
        let answer = if self.removed.contains(key) {
            false
        } else if self.inserted.contains(key) {
            true
        } else {
            self.index.ordinal_of_key(self.binding, key)?.is_some()
        };
        self.index.verify_epoch(self.binding)?;
        Ok(answer)
    }

    pub(crate) fn ordinal_of_key(
        &self,
        key: &[u8; KEY_BYTES],
    ) -> Result<Option<u64>, CanonicalMembershipError> {
        if !self.inserted.is_empty() || !self.removed.is_empty() {
            return Err(CanonicalMembershipError::OrdinalLookupWithOverlay);
        }
        self.index.ordinal_of_key(self.binding, key)
    }

    pub(crate) fn key_at_ordinal(
        &self,
        ordinal: u64,
    ) -> Result<Option<[u8; KEY_BYTES]>, CanonicalMembershipError> {
        if !self.inserted.is_empty() || !self.removed.is_empty() {
            return Err(CanonicalMembershipError::OrdinalLookupWithOverlay);
        }
        self.index.key_at_ordinal(self.binding, ordinal)
    }

    fn apply_store_delta(
        &mut self,
        delta: &CanonicalMembershipStoreDelta48,
    ) -> Result<(), CanonicalMembershipError> {
        delta.validate()?;
        if delta.family() != self.family() {
            return Err(CanonicalMembershipError::DeltaEpochMismatch);
        }
        if delta.base_count != self.logical_count {
            return Err(CanonicalMembershipError::DeltaBaseCountMismatch);
        }
        let mut candidate = self.clone();
        for row in &delta.removed {
            if !candidate.contains(&row.key)? {
                return Err(CanonicalMembershipError::MissingRemovalKey);
            }
            if !candidate.inserted.remove(&row.key) {
                candidate.removed.insert(row.key);
            }
            candidate.enforce_overlay_capacity()?;
        }
        for row in &delta.inserted {
            if candidate.contains(&row.key)? {
                return Err(CanonicalMembershipError::DuplicateInsertionKey);
            }
            if !candidate.removed.remove(&row.key) {
                candidate.inserted.insert(row.key);
            }
            candidate.enforce_overlay_capacity()?;
        }
        candidate.logical_count = delta.final_count;
        *self = candidate;
        Ok(())
    }

    fn enforce_overlay_capacity(&self) -> Result<(), CanonicalMembershipError> {
        if self.inserted.len().saturating_add(self.removed.len()) > self.overlay_capacity {
            return Err(CanonicalMembershipError::OverlayCapacityExceeded {
                capacity: self.overlay_capacity,
            });
        }
        Ok(())
    }

    /// Pure, allocation-free publication after the active-pointer storage
    /// transaction.  The view already carries the final logical count from
    /// `apply_delta`; disk point reads are deliberately impossible here.
    fn rebase_validated(
        &mut self,
        stable_epoch: u64,
        base_generation: u64,
        active_wal_generation: Option<u64>,
    ) {
        self.binding = CanonicalMembershipReadBinding {
            stable_epoch,
            base_generation,
            active_wal_generation,
        };
        self.inserted = PersistentKeySet48::new();
        self.removed = PersistentKeySet48::new();
    }

    pub(crate) fn resident_instrumentation(&self) -> CanonicalMembershipResidentInstrumentation {
        let point = self.index.point_read_metrics();
        let overlay_nodes = self
            .inserted
            .node_count()
            .saturating_add(self.removed.node_count());
        let overlay_estimated_bytes = self
            .inserted
            .estimated_live_node_bytes()
            .saturating_add(self.removed.estimated_live_node_bytes());
        let cache_payload_bytes = point.cache_entries.saturating_mul(
            mem::size_of::<[u8; KEY_BYTES]>()
                + mem::size_of::<CacheEntry48>()
                + mem::size_of::<([u8; KEY_BYTES], u64)>(),
        );
        CanonicalMembershipResidentInstrumentation {
            logical_count: self.logical_count,
            inserted_keys: self.inserted.len(),
            removed_keys: self.removed.len(),
            overlay_nodes,
            overlay_capacity: self.overlay_capacity,
            overlay_estimated_payload_bytes: overlay_estimated_bytes,
            cache_entries: point.cache_entries,
            cache_capacity: point.cache_capacity,
            cache_estimated_payload_bytes: cache_payload_bytes,
            disk_point_reads: point.disk_point_reads,
            cache_hits: point.cache_hits,
            cache_misses: point.cache_misses,
            stale_rejections: point.stale_rejections,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalMembershipWalAuditWork {
    pub(crate) order_rows: u64,
    pub(crate) by_key_rows: u64,
    pub(crate) by_index_rows: u64,
    pub(crate) cross_binding_point_checks: u64,
    pub(crate) max_buffered_records: usize,
    pub(crate) sealed_digest: [u8; KEY_BYTES],
}

impl Default for CanonicalMembershipWalAuditWork {
    fn default() -> Self {
        Self {
            order_rows: 0,
            by_key_rows: 0,
            by_index_rows: 0,
            cross_binding_point_checks: 0,
            max_buffered_records: 0,
            sealed_digest: [0u8; KEY_BYTES],
        }
    }
}

/// Stream-validate a staged or active WAL generation without materializing
/// its mutation set.  The caller supplies sealed manifest counts; extra,
/// missing, reordered, malformed, or cross-family rows fail closed.
pub(crate) fn audit_membership_wal_generation(
    wal_by_key: &sled::Tree,
    wal_by_index: &sled::Tree,
    wal_order: &sled::Tree,
    generation: u64,
    expected_order_rows: u64,
    expected_index_rows: u64,
) -> Result<CanonicalMembershipWalAuditWork, CanonicalMembershipError> {
    if generation == 0 {
        return Err(CanonicalMembershipError::ZeroWalGeneration);
    }
    require_tree_name(wal_by_key, CANONICAL_MEMBERSHIP_WAL_BY_KEY_TREE_V3)?;
    require_tree_name(wal_by_index, CANONICAL_MEMBERSHIP_WAL_BY_INDEX_TREE_V3)?;
    require_tree_name(wal_order, CANONICAL_MEMBERSHIP_WAL_ORDER_TREE_V3)?;
    let prefix = generation.to_be_bytes();
    let mut work = CanonicalMembershipWalAuditWork::default();
    let mut digest =
        membership_wal_digest_hasher(generation, expected_order_rows, expected_index_rows);

    for row in wal_order.scan_prefix(prefix) {
        let (encoded_key, encoded_value) = row?;
        let (observed_generation, sequence) = decode_wal_order_key(encoded_key.as_ref())?;
        if observed_generation != generation || sequence != work.order_rows {
            return Err(CanonicalMembershipError::WalOrderGap);
        }
        let record =
            CanonicalMembershipWalOrderRecord48::decode_value(sequence, encoded_value.as_ref())?;
        let forward_key = encode_wal_forward_key(generation, record.family, &record.key);
        let forward_value = wal_by_key
            .get(forward_key)?
            .ok_or(CanonicalMembershipError::WalCrossBindingMismatch)?;
        let decoded_forward = WalByKeyValue48::decode(forward_value.as_ref())?;
        if decoded_forward.sequence != sequence
            || decoded_forward.expected_ordinal != record.expected_ordinal
            || decoded_forward.replacement_ordinal != record.replacement_ordinal
        {
            return Err(CanonicalMembershipError::WalCrossBindingMismatch);
        }
        update_membership_wal_digest_row(
            &mut digest,
            WAL_DIGEST_ORDER_ROW_TAG,
            encoded_key.as_ref(),
            encoded_value.as_ref(),
        );
        work.cross_binding_point_checks = work.cross_binding_point_checks.saturating_add(1);

        if let Some(ordinal) = record.expected_ordinal {
            let reverse_key = encode_wal_reverse_key(generation, record.family, ordinal);
            let reverse_value = wal_by_index
                .get(reverse_key)?
                .ok_or(CanonicalMembershipError::WalCrossBindingMismatch)?;
            let decoded_reverse = CanonicalMembershipWalByIndexRecord48::decode_value(
                record.family,
                ordinal,
                reverse_value.as_ref(),
            )?;
            if decoded_reverse.expected != Some((record.key, sequence)) {
                return Err(CanonicalMembershipError::WalCrossBindingMismatch);
            }
            work.cross_binding_point_checks = work.cross_binding_point_checks.saturating_add(1);
        }
        if let Some(ordinal) = record.replacement_ordinal {
            let reverse_key = encode_wal_reverse_key(generation, record.family, ordinal);
            let reverse_value = wal_by_index
                .get(reverse_key)?
                .ok_or(CanonicalMembershipError::WalCrossBindingMismatch)?;
            let decoded_reverse = CanonicalMembershipWalByIndexRecord48::decode_value(
                record.family,
                ordinal,
                reverse_value.as_ref(),
            )?;
            if decoded_reverse.replacement != Some((record.key, sequence)) {
                return Err(CanonicalMembershipError::WalCrossBindingMismatch);
            }
            work.cross_binding_point_checks = work.cross_binding_point_checks.saturating_add(1);
        }
        work.order_rows = work.order_rows.saturating_add(1);
        work.max_buffered_records = 1;
    }
    if work.order_rows != expected_order_rows {
        return Err(CanonicalMembershipError::WalOrderGap);
    }

    for row in wal_by_key.scan_prefix(prefix) {
        let (encoded_key, encoded_value) = row?;
        let (observed_generation, family, key) = decode_wal_forward_key(encoded_key.as_ref())?;
        if observed_generation != generation {
            return Err(CanonicalMembershipError::WalCrossBindingMismatch);
        }
        let value = WalByKeyValue48::decode(encoded_value.as_ref())?;
        let order_key = encode_wal_order_key(generation, value.sequence);
        let order_value = wal_order
            .get(order_key)?
            .ok_or(CanonicalMembershipError::WalCrossBindingMismatch)?;
        let record = CanonicalMembershipWalOrderRecord48::decode_value(
            value.sequence,
            order_value.as_ref(),
        )?;
        if record.family != family
            || record.key != key
            || record.expected_ordinal != value.expected_ordinal
            || record.replacement_ordinal != value.replacement_ordinal
        {
            return Err(CanonicalMembershipError::WalCrossBindingMismatch);
        }
        update_membership_wal_digest_row(
            &mut digest,
            WAL_DIGEST_BY_KEY_ROW_TAG,
            encoded_key.as_ref(),
            encoded_value.as_ref(),
        );
        work.by_key_rows = work.by_key_rows.saturating_add(1);
        work.cross_binding_point_checks = work.cross_binding_point_checks.saturating_add(1);
    }
    if work.by_key_rows != expected_order_rows {
        return Err(CanonicalMembershipError::WalCrossBindingMismatch);
    }

    for row in wal_by_index.scan_prefix(prefix) {
        let (encoded_key, encoded_value) = row?;
        let (observed_generation, family, ordinal) = decode_wal_reverse_key(encoded_key.as_ref())?;
        if observed_generation != generation {
            return Err(CanonicalMembershipError::WalCrossBindingMismatch);
        }
        let value = CanonicalMembershipWalByIndexRecord48::decode_value(
            family,
            ordinal,
            encoded_value.as_ref(),
        )?;
        for (key, sequence) in value.expected.into_iter().chain(value.replacement) {
            let order_key = encode_wal_order_key(generation, sequence);
            let order_value = wal_order
                .get(order_key)?
                .ok_or(CanonicalMembershipError::WalCrossBindingMismatch)?;
            let record =
                CanonicalMembershipWalOrderRecord48::decode_value(sequence, order_value.as_ref())?;
            let expected_half =
                value.expected == Some((key, sequence)) && record.expected_ordinal == Some(ordinal);
            let replacement_half = value.replacement == Some((key, sequence))
                && record.replacement_ordinal == Some(ordinal);
            if record.family != family || record.key != key || (!expected_half && !replacement_half)
            {
                return Err(CanonicalMembershipError::WalCrossBindingMismatch);
            }
            work.cross_binding_point_checks = work.cross_binding_point_checks.saturating_add(1);
        }
        update_membership_wal_digest_row(
            &mut digest,
            WAL_DIGEST_BY_INDEX_ROW_TAG,
            encoded_key.as_ref(),
            encoded_value.as_ref(),
        );
        work.by_index_rows = work.by_index_rows.saturating_add(1);
    }
    if work.by_index_rows != expected_index_rows {
        return Err(CanonicalMembershipError::WalCrossBindingMismatch);
    }
    work.sealed_digest = digest.finalize();
    Ok(work)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CanonicalMembershipWalStreamWork {
    pub(crate) visited_rows: u64,
    pub(crate) cross_binding_point_checks: u64,
    pub(crate) max_buffered_records: usize,
}

/// Validate the sealed active WAL, then stream its unapplied ordered suffix
/// with O(1) resident records.  Euler's external-tree normalizer consumes
/// this stream together with a new effective-view delta: it carries every
/// old record not superseded by the new delta and rewrites superseded records
/// against the current compacted base.  The caller binds generation, seal,
/// progress, base generation, and epoch in the eventual flip CAS.
pub(crate) fn stream_remaining_membership_wal_records<F>(
    wal_by_key: &sled::Tree,
    wal_by_index: &sled::Tree,
    wal_order: &sled::Tree,
    generation: u64,
    applied_order_rows: u64,
    expected_order_rows: u64,
    expected_index_rows: u64,
    expected_sealed_digest: [u8; KEY_BYTES],
    mut visit: F,
) -> Result<CanonicalMembershipWalStreamWork, CanonicalMembershipError>
where
    F: FnMut(CanonicalMembershipWalOrderRecord48) -> Result<(), CanonicalMembershipError>,
{
    if applied_order_rows > expected_order_rows {
        return Err(CanonicalMembershipError::WalOrderGap);
    }
    let audit = audit_membership_wal_generation(
        wal_by_key,
        wal_by_index,
        wal_order,
        generation,
        expected_order_rows,
        expected_index_rows,
    )?;
    if audit.sealed_digest != expected_sealed_digest {
        return Err(CanonicalMembershipError::WalCrossBindingMismatch);
    }

    let start = encode_wal_order_key(generation, applied_order_rows);
    let mut expected_sequence = applied_order_rows;
    let mut work = CanonicalMembershipWalStreamWork::default();
    for row in wal_order.range(start.as_slice()..) {
        let (encoded_key, encoded_value) = row?;
        let (observed_generation, sequence) = decode_wal_order_key(encoded_key.as_ref())?;
        if observed_generation != generation {
            break;
        }
        if sequence != expected_sequence || sequence >= expected_order_rows {
            return Err(CanonicalMembershipError::WalOrderGap);
        }
        let record =
            CanonicalMembershipWalOrderRecord48::decode_value(sequence, encoded_value.as_ref())?;
        let forward_key = encode_wal_forward_key(generation, record.family, &record.key);
        let forward = wal_by_key
            .get(forward_key)?
            .ok_or(CanonicalMembershipError::WalCrossBindingMismatch)?;
        let forward = WalByKeyValue48::decode(forward.as_ref())?;
        if forward.sequence != sequence
            || forward.expected_ordinal != record.expected_ordinal
            || forward.replacement_ordinal != record.replacement_ordinal
        {
            return Err(CanonicalMembershipError::WalCrossBindingMismatch);
        }
        work.cross_binding_point_checks = work.cross_binding_point_checks.saturating_add(1);
        visit(record)?;
        work.visited_rows = work.visited_rows.saturating_add(1);
        work.max_buffered_records = 1;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(CanonicalMembershipError::WalSequenceOverflow)?;
    }
    if expected_sequence != expected_order_rows {
        return Err(CanonicalMembershipError::WalOrderGap);
    }
    Ok(work)
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(crate) enum CanonicalMembershipTransactionAbort {
    #[error("canonical membership WAL order row is missing or invalid")]
    InvalidOrderRow,
    #[error("canonical membership WAL by-key cross-binding is invalid")]
    InvalidForwardWalRow,
    #[error("canonical membership WAL by-index cross-binding is invalid")]
    InvalidReverseWalRow,
    #[error("canonical membership compacted forward row differs from expected base")]
    UnexpectedBaseForwardRow,
    #[error("canonical membership compacted reverse row differs from the WAL transition")]
    UnexpectedBaseReverseRow,
    #[error("canonical membership direct delta requires no active WAL")]
    ActiveWal,
    #[error("canonical membership direct delta row differs from compacted base")]
    DirectDeltaMismatch,
}

fn transaction_abort<T>(
    error: CanonicalMembershipTransactionAbort,
) -> ConflictableTransactionResult<T, CanonicalMembershipTransactionAbort> {
    Err(ConflictableTransactionError::Abort(error))
}

fn transaction_decode_order_record(
    generation: u64,
    sequence: u64,
    wal_order: &TransactionalTree,
) -> ConflictableTransactionResult<
    CanonicalMembershipWalOrderRecord48,
    CanonicalMembershipTransactionAbort,
> {
    let key = encode_wal_order_key(generation, sequence);
    let Some(value) = wal_order.get(key.as_slice())? else {
        return transaction_abort(CanonicalMembershipTransactionAbort::InvalidOrderRow);
    };
    CanonicalMembershipWalOrderRecord48::decode_value(sequence, value.as_ref()).map_err(|_| {
        ConflictableTransactionError::Abort(CanonicalMembershipTransactionAbort::InvalidOrderRow)
    })
}

fn apply_store_delta_transactionally(
    base_by_key: &TransactionalTree,
    base_by_index: &TransactionalTree,
    base_generation: u64,
    delta: &CanonicalMembershipStoreDelta48,
) -> ConflictableTransactionResult<(), CanonicalMembershipTransactionAbort> {
    for row in &delta.removed {
        let forward_key = encode_membership_base_forward_key(base_generation, &row.key);
        let reverse_key = encode_membership_base_reverse_key(base_generation, row.ordinal);
        if base_by_key.get(forward_key.as_slice())?.as_deref()
            != Some(row.ordinal.to_be_bytes().as_slice())
            || base_by_index.get(reverse_key.as_slice())?.as_deref() != Some(row.key.as_slice())
        {
            return transaction_abort(CanonicalMembershipTransactionAbort::DirectDeltaMismatch);
        }
    }
    for row in &delta.removed {
        let forward_key = encode_membership_base_forward_key(base_generation, &row.key);
        let reverse_key = encode_membership_base_reverse_key(base_generation, row.ordinal);
        base_by_key.remove(forward_key.as_slice())?;
        base_by_index.remove(reverse_key.as_slice())?;
    }
    for row in &delta.inserted {
        let forward_key = encode_membership_base_forward_key(base_generation, &row.key);
        let reverse_key = encode_membership_base_reverse_key(base_generation, row.ordinal);
        if base_by_key.get(forward_key.as_slice())?.is_some()
            || base_by_index.get(reverse_key.as_slice())?.is_some()
        {
            return transaction_abort(CanonicalMembershipTransactionAbort::DirectDeltaMismatch);
        }
        base_by_key.insert(forward_key.as_slice(), &row.ordinal.to_be_bytes())?;
        base_by_index.insert(reverse_key.as_slice(), row.key.as_slice())?;
    }
    Ok(())
}

/// Apply a small mined/import delta directly to both paired compacted
/// families inside the caller's single canonical transaction.  Reorg-sized
/// work uses the inactive WAL path instead.  This helper checks every old row
/// before deletion and every destination before insertion, so a late bridge
/// conflict rolls back earlier nullifier writes with the enclosing sled
/// transaction.
pub(crate) fn apply_membership_delta_transactionally(
    nullifier_base_by_key: &TransactionalTree,
    nullifier_base_by_index: &TransactionalTree,
    bridge_base_by_key: &TransactionalTree,
    bridge_base_by_index: &TransactionalTree,
    base_generation: u64,
    active_wal_generation: Option<u64>,
    delta: &CanonicalMembershipDelta48,
) -> ConflictableTransactionResult<(), CanonicalMembershipTransactionAbort> {
    if active_wal_generation.is_some() {
        return transaction_abort(CanonicalMembershipTransactionAbort::ActiveWal);
    }
    apply_store_delta_transactionally(
        nullifier_base_by_key,
        nullifier_base_by_index,
        base_generation,
        &delta.nullifiers,
    )?;
    apply_store_delta_transactionally(
        bridge_base_by_key,
        bridge_base_by_index,
        base_generation,
        &delta.bridge_messages,
    )?;
    Ok(())
}

fn reverse_value_before_sequence(
    record: &CanonicalMembershipWalByIndexRecord48,
    sequence: u64,
) -> Option<[u8; KEY_BYTES]> {
    if let Some((replacement, replacement_sequence)) = record.replacement {
        if replacement_sequence < sequence {
            return Some(replacement);
        }
    }
    if record
        .expected
        .is_some_and(|(_, expected_sequence)| expected_sequence < sequence)
    {
        return None;
    }
    record.expected.map(|(key, _)| key)
}

/// Apply one sealed ordered WAL record to the compacted base.  The caller
/// advances its persisted cursor in the same sled transaction.  The active
/// WAL remains authoritative throughout bounded-batch finalization, so a
/// temporary compacted reverse-index cycle is safe; every observed reverse
/// value must still be one of the sealed row's exact expected/replacement
/// endpoints.
pub(crate) fn apply_membership_wal_record_transactionally(
    nullifier_base_by_key: &TransactionalTree,
    nullifier_base_by_index: &TransactionalTree,
    bridge_base_by_key: &TransactionalTree,
    bridge_base_by_index: &TransactionalTree,
    wal_by_key: &TransactionalTree,
    wal_by_index: &TransactionalTree,
    wal_order: &TransactionalTree,
    base_generation: u64,
    wal_generation: u64,
    sequence: u64,
) -> ConflictableTransactionResult<
    CanonicalMembershipWalOrderRecord48,
    CanonicalMembershipTransactionAbort,
> {
    let record = transaction_decode_order_record(wal_generation, sequence, wal_order)?;
    let forward_wal_key = encode_wal_forward_key(wal_generation, record.family, &record.key);
    let Some(forward_wal_value) = wal_by_key.get(forward_wal_key.as_slice())? else {
        return transaction_abort(CanonicalMembershipTransactionAbort::InvalidForwardWalRow);
    };
    let forward = WalByKeyValue48::decode(forward_wal_value.as_ref()).map_err(|_| {
        ConflictableTransactionError::Abort(
            CanonicalMembershipTransactionAbort::InvalidForwardWalRow,
        )
    })?;
    if forward.sequence != sequence
        || forward.expected_ordinal != record.expected_ordinal
        || forward.replacement_ordinal != record.replacement_ordinal
    {
        return transaction_abort(CanonicalMembershipTransactionAbort::InvalidForwardWalRow);
    }

    let (base_by_key, base_by_index) = match record.family {
        CanonicalMembershipFamily48::Nullifier => (nullifier_base_by_key, nullifier_base_by_index),
        CanonicalMembershipFamily48::ConsumedBridgeMessage => {
            (bridge_base_by_key, bridge_base_by_index)
        }
    };
    let base_forward_key = encode_membership_base_forward_key(base_generation, &record.key);
    let observed_forward = base_by_key.get(base_forward_key.as_slice())?;
    let expected_forward = record.expected_ordinal.map(|ordinal| ordinal.to_be_bytes());
    if observed_forward.as_deref() != expected_forward.as_ref().map(<[u8; 8]>::as_slice) {
        return transaction_abort(CanonicalMembershipTransactionAbort::UnexpectedBaseForwardRow);
    }

    let mut checked_reverse = BTreeSet::new();
    for ordinal in record
        .expected_ordinal
        .into_iter()
        .chain(record.replacement_ordinal)
    {
        if !checked_reverse.insert(ordinal) {
            continue;
        }
        let reverse_wal_key = encode_wal_reverse_key(wal_generation, record.family, ordinal);
        let Some(reverse_wal_value) = wal_by_index.get(reverse_wal_key.as_slice())? else {
            return transaction_abort(CanonicalMembershipTransactionAbort::InvalidReverseWalRow);
        };
        let reverse = CanonicalMembershipWalByIndexRecord48::decode_value(
            record.family,
            ordinal,
            reverse_wal_value.as_ref(),
        )
        .map_err(|_| {
            ConflictableTransactionError::Abort(
                CanonicalMembershipTransactionAbort::InvalidReverseWalRow,
            )
        })?;
        let correct_expected_half = record.expected_ordinal == Some(ordinal)
            && reverse.expected == Some((record.key, sequence));
        let correct_replacement_half = record.replacement_ordinal == Some(ordinal)
            && reverse.replacement == Some((record.key, sequence));
        if (!correct_expected_half && record.expected_ordinal == Some(ordinal))
            || (!correct_replacement_half && record.replacement_ordinal == Some(ordinal))
        {
            return transaction_abort(CanonicalMembershipTransactionAbort::InvalidReverseWalRow);
        }
        let base_reverse_key = encode_membership_base_reverse_key(base_generation, ordinal);
        let observed_reverse = base_by_index.get(base_reverse_key.as_slice())?;
        let observed_key = observed_reverse
            .as_deref()
            .map(|bytes| read_array::<KEY_BYTES>(bytes, "transaction base reverse key"))
            .transpose()
            .map_err(|_| {
                ConflictableTransactionError::Abort(
                    CanonicalMembershipTransactionAbort::UnexpectedBaseReverseRow,
                )
            })?;
        if observed_key != reverse_value_before_sequence(&reverse, sequence) {
            return transaction_abort(
                CanonicalMembershipTransactionAbort::UnexpectedBaseReverseRow,
            );
        }
    }

    match record.replacement_ordinal {
        Some(ordinal) => {
            base_by_key.insert(base_forward_key.as_slice(), &ordinal.to_be_bytes())?;
        }
        None => {
            base_by_key.remove(base_forward_key.as_slice())?;
        }
    }
    if let Some(old_ordinal) = record.expected_ordinal {
        let old_reverse_key = encode_membership_base_reverse_key(base_generation, old_ordinal);
        if base_by_index.get(old_reverse_key.as_slice())?.as_deref() == Some(record.key.as_slice())
        {
            base_by_index.remove(old_reverse_key.as_slice())?;
        }
    }
    if let Some(new_ordinal) = record.replacement_ordinal {
        let new_reverse_key = encode_membership_base_reverse_key(base_generation, new_ordinal);
        base_by_index.insert(new_reverse_key.as_slice(), record.key.as_slice())?;
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Encode;
    use tempfile::TempDir;

    struct TestStorage {
        _directory: TempDir,
        _db: sled::Db,
        nullifier_by_key: sled::Tree,
        nullifier_by_index: sled::Tree,
        bridge_by_key: sled::Tree,
        bridge_by_index: sled::Tree,
        wal_by_key: sled::Tree,
        wal_by_index: sled::Tree,
        wal_order: sled::Tree,
        reorg_wal_manifest: sled::Tree,
    }

    impl TestStorage {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("create membership test directory");
            let db = sled::open(directory.path()).expect("open membership test database");
            Self {
                nullifier_by_key: db
                    .open_tree(NULLIFIER_BASE_BY_KEY_TREE_V3)
                    .expect("open nullifier by-key tree"),
                nullifier_by_index: db
                    .open_tree(NULLIFIER_BASE_BY_INDEX_TREE_V3)
                    .expect("open nullifier by-index tree"),
                bridge_by_key: db
                    .open_tree(BRIDGE_BASE_BY_KEY_TREE_V3)
                    .expect("open bridge by-key tree"),
                bridge_by_index: db
                    .open_tree(BRIDGE_BASE_BY_INDEX_TREE_V3)
                    .expect("open bridge by-index tree"),
                wal_by_key: db
                    .open_tree(CANONICAL_MEMBERSHIP_WAL_BY_KEY_TREE_V3)
                    .expect("open WAL by-key tree"),
                wal_by_index: db
                    .open_tree(CANONICAL_MEMBERSHIP_WAL_BY_INDEX_TREE_V3)
                    .expect("open WAL by-index tree"),
                wal_order: db
                    .open_tree(CANONICAL_MEMBERSHIP_WAL_ORDER_TREE_V3)
                    .expect("open WAL order tree"),
                reorg_wal_manifest: db
                    .open_tree(NATIVE_REORG_WAL_MANIFEST_TREE_V3)
                    .expect("open reorg WAL manifest tree"),
                _db: db,
                _directory: directory,
            }
        }

        fn base_trees(&self, family: CanonicalMembershipFamily48) -> (&sled::Tree, &sled::Tree) {
            match family {
                CanonicalMembershipFamily48::Nullifier => {
                    (&self.nullifier_by_key, &self.nullifier_by_index)
                }
                CanonicalMembershipFamily48::ConsumedBridgeMessage => {
                    (&self.bridge_by_key, &self.bridge_by_index)
                }
            }
        }

        fn seed_base(
            &self,
            family: CanonicalMembershipFamily48,
            generation: u64,
            keys: &[[u8; KEY_BYTES]],
        ) {
            let (by_key, by_index) = self.base_trees(family);
            let mut forward_batch = sled::Batch::default();
            let mut reverse_batch = sled::Batch::default();
            for (offset, key) in keys.iter().enumerate() {
                let ordinal = u64::try_from(offset).expect("test ordinal fits u64");
                forward_batch.insert(
                    encode_membership_base_forward_key(generation, key).to_vec(),
                    ordinal.to_be_bytes().to_vec(),
                );
                reverse_batch.insert(
                    encode_membership_base_reverse_key(generation, ordinal).to_vec(),
                    key.to_vec(),
                );
            }
            by_key
                .apply_batch(forward_batch)
                .expect("seed membership forward base");
            by_index
                .apply_batch(reverse_batch)
                .expect("seed membership reverse base");
        }

        fn indexes(
            &self,
            epoch: &CanonicalMembershipEpoch,
            cache_capacity: usize,
        ) -> CanonicalMembershipIndexes48 {
            CanonicalMembershipIndexes48::from_open_trees(
                self.nullifier_by_key.clone(),
                self.nullifier_by_index.clone(),
                self.bridge_by_key.clone(),
                self.bridge_by_index.clone(),
                self.wal_by_key.clone(),
                self.wal_by_index.clone(),
                self.wal_order.clone(),
                epoch.clone(),
                cache_capacity,
            )
            .expect("construct paired membership indexes")
        }

        fn stage_plan(&self, plan: &CanonicalMembershipWalPlan48) {
            plan.stage_order_batch(
                &self.wal_by_key,
                &self.wal_order,
                0..plan.order_records.len(),
            )
            .expect("stage WAL order/by-key rows");
            plan.stage_index_batch(&self.wal_by_index, 0..plan.by_index_records.len())
                .expect("stage WAL by-index rows");
        }

        fn snapshot_rows(&self) -> Vec<(Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>)> {
            CANONICAL_MEMBERSHIP_TREE_NAMES_V3
                .iter()
                .map(|name| {
                    let tree = self._db.open_tree(name).expect("open snapshot tree");
                    let rows = tree
                        .iter()
                        .map(|row| {
                            let (key, value) = row.expect("read snapshot row");
                            (key.to_vec(), value.to_vec())
                        })
                        .collect();
                    (name.to_vec(), rows)
                })
                .collect()
        }
    }

    fn key(id: u64) -> [u8; KEY_BYTES] {
        let mut key = [0u8; KEY_BYTES];
        key[0] = 0x80;
        key[KEY_BYTES - 8..].copy_from_slice(&id.to_be_bytes());
        key
    }

    fn rows(keys: &[[u8; KEY_BYTES]], start: u64) -> Vec<CanonicalMembershipIndexedRow48> {
        keys.iter()
            .enumerate()
            .map(|(offset, key)| CanonicalMembershipIndexedRow48 {
                ordinal: start + u64::try_from(offset).expect("test row offset fits u64"),
                key: *key,
            })
            .collect()
    }

    fn no_change(
        family: CanonicalMembershipFamily48,
        count: u64,
    ) -> CanonicalMembershipStoreDelta48 {
        CanonicalMembershipStoreDelta48::new(family, count, count, Vec::new(), Vec::new())
            .expect("construct no-change membership delta")
    }

    fn snapshot(
        epoch: u64,
        base_generation: u64,
        active_wal_generation: Option<u64>,
        base_nullifier_count: u64,
        nullifier_count: u64,
        base_bridge_count: u64,
        bridge_count: u64,
    ) -> CanonicalMembershipSnapshotV3 {
        CanonicalMembershipSnapshotV3::new(
            epoch,
            base_generation,
            active_wal_generation,
            key(9_999_999),
            base_nullifier_count,
            nullifier_count,
            base_bridge_count,
            bridge_count,
            active_wal_generation.map(|generation| key(generation + 1_000_000)),
        )
        .expect("construct membership snapshot")
    }

    #[test]
    fn snapshot_and_delta_codecs_are_exact_bounded_and_versioned() {
        let inactive = snapshot(0, 4, None, 3, 3, 2, 2);
        assert_eq!(inactive.stable_epoch(), 0);
        assert_eq!(inactive.base_generation(), 4);
        assert_eq!(inactive.active_wal_generation(), None);
        assert_eq!(inactive.base_nullifier_count(), 3);
        assert_eq!(inactive.nullifier_count(), 3);
        assert_eq!(inactive.base_bridge_count(), 2);
        assert_eq!(inactive.bridge_count(), 2);
        assert_eq!(inactive.canonical_tip_binding(), &key(9_999_999));
        assert_eq!(inactive.active_wal_sealed_digest(), None);
        let encoded = inactive.encode();
        assert_eq!(encoded.len(), CANONICAL_MEMBERSHIP_SNAPSHOT_INACTIVE_BYTES);
        assert_eq!(
            CanonicalMembershipSnapshotV3::decode_exact(&encoded).expect("decode snapshot"),
            inactive
        );
        let active = snapshot(2, 4, Some(9), 3, 4, 2, 1);
        let active_encoded = active.encode();
        assert_eq!(
            active_encoded.len(),
            CANONICAL_MEMBERSHIP_SNAPSHOT_ACTIVE_BYTES
        );
        assert_eq!(
            CanonicalMembershipSnapshotV3::decode_exact(&active_encoded)
                .expect("decode active snapshot"),
            active
        );
        let mut nested_cursor = active_encoded.as_slice();
        let nested = CanonicalMembershipSnapshotV3::decode_with_mem_limit(
            &mut nested_cursor,
            CANONICAL_MEMBERSHIP_SNAPSHOT_ACTIVE_BYTES,
        )
        .expect("decode bounded nested snapshot");
        assert!(nested_cursor.is_empty());
        assert_eq!(nested, active);
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            CanonicalMembershipSnapshotV3::decode_exact(&trailing),
            Err(CanonicalMembershipError::NonCanonicalEncoding)
        ));
        let mut legacy = encoded;
        legacy[0..2].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            CanonicalMembershipSnapshotV3::decode_exact(&legacy),
            Err(CanonicalMembershipError::InvalidSnapshot(
                "unsupported schema"
            ))
        ));

        let nullifiers = CanonicalMembershipStoreDelta48::new(
            CanonicalMembershipFamily48::Nullifier,
            3,
            3,
            rows(&[key(2), key(3)], 1),
            rows(&[key(4), key(5)], 1),
        )
        .expect("construct nullifier delta");
        let delta = CanonicalMembershipDelta48::new(
            0,
            2,
            nullifiers,
            no_change(CanonicalMembershipFamily48::ConsumedBridgeMessage, 2),
        )
        .expect("construct membership delta");
        assert_eq!(delta.base_epoch(), 0);
        assert_eq!(delta.next_epoch(), 2);
        assert_eq!(delta.nullifiers().base_count(), 3);
        assert_eq!(delta.nullifiers().final_count(), 3);
        assert_eq!(delta.nullifiers().removed().len(), 2);
        assert_eq!(delta.nullifiers().inserted().len(), 2);
        assert_eq!(delta.bridge_messages().base_count(), 2);
        let encoded = delta.encode();
        let decoded = CanonicalMembershipDelta48::decode_exact_bounded(&encoded, 4)
            .expect("decode bounded membership delta");
        assert_eq!(decoded, delta);
        assert!(matches!(
            CanonicalMembershipDelta48::decode_exact_bounded(&encoded, 3),
            Err(CanonicalMembershipError::DecodeRowLimitExceeded(3))
        ));
        assert!(matches!(
            CanonicalMembershipStoreDelta48::new(
                CanonicalMembershipFamily48::Nullifier,
                0,
                1,
                Vec::new(),
                vec![CanonicalMembershipIndexedRow48 {
                    ordinal: 0,
                    key: [0u8; KEY_BYTES],
                }],
            ),
            Err(CanonicalMembershipError::ZeroKey(
                CanonicalMembershipFamily48::Nullifier
            ))
        ));
    }

    #[test]
    fn staged_wal_is_invisible_until_epoch_flip_and_then_exact() {
        let storage = TestStorage::new();
        let base_nullifiers = [key(1), key(2), key(3)];
        let base_bridge = [key(101)];
        storage.seed_base(CanonicalMembershipFamily48::Nullifier, 0, &base_nullifiers);
        storage.seed_base(
            CanonicalMembershipFamily48::ConsumedBridgeMessage,
            0,
            &base_bridge,
        );
        let epoch = CanonicalMembershipEpoch::new(0).expect("construct epoch");
        let indexes = storage.indexes(&epoch, 16);
        let mut views = indexes
            .views_from_snapshot(&snapshot(0, 0, None, 3, 3, 1, 1), 32)
            .expect("construct membership views");

        let nullifiers = CanonicalMembershipStoreDelta48::new(
            CanonicalMembershipFamily48::Nullifier,
            3,
            3,
            rows(&base_nullifiers[1..], 1),
            rows(&[key(4), key(5)], 1),
        )
        .expect("construct nullifier reorg delta");
        let bridge = CanonicalMembershipStoreDelta48::new(
            CanonicalMembershipFamily48::ConsumedBridgeMessage,
            1,
            1,
            rows(&base_bridge, 0),
            rows(&[[0u8; KEY_BYTES]], 0),
        )
        .expect("construct bridge reorg delta");
        let delta = CanonicalMembershipDelta48::new(0, 2, nullifiers, bridge)
            .expect("construct paired delta");
        let plan =
            CanonicalMembershipWalPlan48::from_delta(7, None, &delta).expect("plan membership WAL");
        assert_eq!(plan.generation(), 7);
        assert_eq!(plan.order_records().len(), plan.order_count() as usize);
        assert_eq!(
            plan.by_index_records().len(),
            plan.by_index_count() as usize
        );
        assert!(plan.encoded_bytes() > 0);
        storage.stage_plan(&plan);
        let audit = audit_membership_wal_generation(
            &storage.wal_by_key,
            &storage.wal_by_index,
            &storage.wal_order,
            7,
            plan.order_count(),
            plan.by_index_count(),
        )
        .expect("audit staged membership WAL");
        assert_eq!(audit.sealed_digest, plan.sealed_digest());

        assert!(views.nullifiers.contains(&key(2)).expect("base lookup"));
        assert!(!views.nullifiers.contains(&key(4)).expect("base lookup"));
        views.apply_delta(&delta).expect("apply in-memory delta");
        assert!(!views.nullifiers.contains(&key(2)).expect("overlay lookup"));
        assert!(views.nullifiers.contains(&key(4)).expect("overlay lookup"));
        assert!(views
            .bridge_messages
            .contains(&[0u8; KEY_BYTES])
            .expect("bridge permits exact zero key"));

        let target_snapshot = snapshot(2, 0, Some(7), 3, 3, 1, 1);
        let prepared = epoch
            .begin_mutation(0, &target_snapshot)
            .expect("begin membership flip");
        assert!(matches!(
            views.nullifiers.contains(&key(1)),
            Err(CanonicalMembershipError::StaleView { .. })
        ));
        let committed = prepared.storage_may_commit().commit_confirmed();
        views
            .rebase_after_commit(committed)
            .expect("publish active membership WAL");
        assert_eq!(views.nullifiers.base_generation(), 0);
        assert_eq!(views.nullifiers.active_wal_generation(), Some(7));
        assert!(!views
            .nullifiers
            .contains(&key(2))
            .expect("active WAL lookup"));
        assert!(views
            .nullifiers
            .contains(&key(4))
            .expect("active WAL lookup"));
        assert_eq!(
            views.nullifiers.key_at_ordinal(1).expect("reverse lookup"),
            Some(key(4))
        );
        assert_eq!(
            views
                .nullifiers
                .audit_effective_view()
                .expect("audit active membership view")
                .effective_rows,
            3
        );
    }

    #[test]
    fn finalizer_handles_suffix_key_reordering_while_wal_remains_authoritative() {
        let storage = TestStorage::new();
        storage.seed_base(CanonicalMembershipFamily48::Nullifier, 0, &[key(1), key(2)]);
        let epoch = CanonicalMembershipEpoch::new(0).expect("construct epoch");
        let indexes = storage.indexes(&epoch, 8);
        let mut views = indexes
            .views_from_snapshot(&snapshot(0, 0, None, 2, 2, 0, 0), 8)
            .expect("construct membership views");
        let delta = CanonicalMembershipDelta48::new(
            0,
            2,
            CanonicalMembershipStoreDelta48::new(
                CanonicalMembershipFamily48::Nullifier,
                2,
                2,
                rows(&[key(1), key(2)], 0),
                rows(&[key(2), key(1)], 0),
            )
            .expect("construct reordered nullifier delta"),
            no_change(CanonicalMembershipFamily48::ConsumedBridgeMessage, 0),
        )
        .expect("construct paired reordered delta");
        let plan = CanonicalMembershipWalPlan48::from_delta(9, None, &delta)
            .expect("plan reordered membership WAL");
        storage.stage_plan(&plan);
        views.apply_delta(&delta).expect("apply reordered overlay");
        let active_snapshot = snapshot(2, 0, Some(9), 2, 2, 0, 0);
        let committed = epoch
            .begin_mutation(0, &active_snapshot)
            .expect("begin active WAL flip")
            .storage_may_commit()
            .commit_confirmed();
        views
            .rebase_after_commit(committed)
            .expect("publish reordered active membership WAL");

        for sequence in 0..plan.order_count() {
            let result = (
                &storage.nullifier_by_key,
                &storage.nullifier_by_index,
                &storage.bridge_by_key,
                &storage.bridge_by_index,
                &storage.wal_by_key,
                &storage.wal_by_index,
                &storage.wal_order,
            )
                .transaction(
                    |(
                        nullifier_by_key,
                        nullifier_by_index,
                        bridge_by_key,
                        bridge_by_index,
                        wal_by_key,
                        wal_by_index,
                        wal_order,
                    )| {
                        apply_membership_wal_record_transactionally(
                            nullifier_by_key,
                            nullifier_by_index,
                            bridge_by_key,
                            bridge_by_index,
                            wal_by_key,
                            wal_by_index,
                            wal_order,
                            0,
                            9,
                            sequence,
                        )?;
                        Ok(())
                    },
                );
            result.expect("finalize one reordered WAL record");
            assert_eq!(
                views.nullifiers.key_at_ordinal(0).expect("active view"),
                Some(key(2))
            );
            assert_eq!(
                views.nullifiers.key_at_ordinal(1).expect("active view"),
                Some(key(1))
            );
        }

        let compacted_snapshot = snapshot(4, 0, None, 2, 2, 0, 0);
        let committed = epoch
            .begin_mutation(2, &compacted_snapshot)
            .expect("begin WAL-clear flip")
            .storage_may_commit()
            .commit_confirmed();
        views
            .rebase_after_commit(committed)
            .expect("publish compacted membership base");
        assert_eq!(
            views.nullifiers.key_at_ordinal(0).expect("compacted view"),
            Some(key(2))
        );
        assert_eq!(
            views.nullifiers.key_at_ordinal(1).expect("compacted view"),
            Some(key(1))
        );
        views
            .nullifiers
            .audit_effective_view()
            .expect("audit finalized reordered view");
    }

    #[test]
    fn btree_set_differential_and_overlay_clone_stay_exact() {
        let storage = TestStorage::new();
        let mut ordered = (1..=128).map(key).collect::<Vec<_>>();
        storage.seed_base(CanonicalMembershipFamily48::Nullifier, 0, &ordered);
        let epoch = CanonicalMembershipEpoch::new(0).expect("construct epoch");
        let indexes = storage.indexes(&epoch, 64);
        let mut views = indexes
            .views_from_snapshot(&snapshot(0, 0, None, 128, 128, 0, 0), 4_096)
            .expect("construct differential views");
        let mut model = ordered.iter().copied().collect::<BTreeSet<_>>();

        for round in 0..96u64 {
            let remove_count = usize::try_from(round % 4 + 1).expect("small remove count");
            let common = ordered.len() - remove_count;
            let removed = ordered[common..].to_vec();
            let mut inserted = (0..remove_count)
                .map(|offset| key(10_000 + round * 8 + u64::try_from(offset).expect("offset")))
                .collect::<Vec<_>>();
            if round % 3 == 0 {
                inserted[remove_count - 1] = removed[0];
            }
            let base_count = u64::try_from(ordered.len()).expect("model count");
            let common_count = u64::try_from(common).expect("common count");
            let final_count = common_count
                .checked_add(u64::try_from(inserted.len()).expect("insert count"))
                .expect("final count");
            let delta = CanonicalMembershipDelta48::new(
                0,
                2,
                CanonicalMembershipStoreDelta48::new(
                    CanonicalMembershipFamily48::Nullifier,
                    base_count,
                    final_count,
                    rows(&removed, common_count),
                    rows(&inserted, common_count),
                )
                .expect("construct differential store delta"),
                no_change(CanonicalMembershipFamily48::ConsumedBridgeMessage, 0),
            )
            .expect("construct differential delta");
            views.apply_delta(&delta).expect("apply differential delta");
            for old in &removed {
                model.remove(old);
            }
            for new in &inserted {
                assert!(model.insert(*new));
            }
            ordered.truncate(common);
            ordered.extend_from_slice(&inserted);
            assert_eq!(views.nullifiers.logical_count(), final_count);
            for member in &model {
                assert!(views
                    .nullifiers
                    .contains(member)
                    .expect("model member lookup"));
            }
            for absent in [key(500_000 + round), key(600_000 + round)] {
                assert!(!views.nullifiers.contains(&absent).expect("absent lookup"));
            }
        }
        let clone = views.nullifiers.clone();
        assert!(clone.inserted.shares_root_with(&views.nullifiers.inserted));
        assert!(clone.removed.shares_root_with(&views.nullifiers.removed));
        let instrumentation = views.nullifiers.resident_instrumentation();
        assert_eq!(instrumentation.logical_count, model.len() as u64);
        assert!(instrumentation.inserted_keys + instrumentation.removed_keys <= 4_096);
        assert!(matches!(
            views.nullifiers.ordinal_of_key(&ordered[0]),
            Err(CanonicalMembershipError::OrdinalLookupWithOverlay)
        ));
    }

    #[test]
    fn overlay_capacity_failure_is_atomic() {
        let storage = TestStorage::new();
        storage.seed_base(CanonicalMembershipFamily48::Nullifier, 0, &[key(1), key(2)]);
        let epoch = CanonicalMembershipEpoch::new(0).expect("construct epoch");
        let indexes = storage.indexes(&epoch, 0);
        let mut views = indexes
            .views_from_snapshot(&snapshot(0, 0, None, 2, 2, 0, 0), 1)
            .expect("construct capacity views");
        let delta = CanonicalMembershipDelta48::new(
            0,
            2,
            CanonicalMembershipStoreDelta48::new(
                CanonicalMembershipFamily48::Nullifier,
                2,
                0,
                rows(&[key(1), key(2)], 0),
                Vec::new(),
            )
            .expect("construct over-capacity delta"),
            no_change(CanonicalMembershipFamily48::ConsumedBridgeMessage, 0),
        )
        .expect("construct paired over-capacity delta");
        assert!(matches!(
            views.apply_delta(&delta),
            Err(CanonicalMembershipError::OverlayCapacityExceeded { capacity: 1 })
        ));
        assert_eq!(views.nullifiers.logical_count(), 2);
        assert!(views
            .nullifiers
            .contains(&key(1))
            .expect("unchanged key one"));
        assert!(views
            .nullifiers
            .contains(&key(2))
            .expect("unchanged key two"));
        assert!(views.nullifiers.inserted.is_empty());
        assert!(views.nullifiers.removed.is_empty());
    }

    #[test]
    fn direct_paired_delta_rolls_back_on_late_family_conflict() {
        let storage = TestStorage::new();
        storage.seed_base(CanonicalMembershipFamily48::Nullifier, 0, &[key(1)]);
        storage.seed_base(
            CanonicalMembershipFamily48::ConsumedBridgeMessage,
            0,
            &[key(101)],
        );
        let conflicting = CanonicalMembershipDelta48::new(
            0,
            2,
            CanonicalMembershipStoreDelta48::new(
                CanonicalMembershipFamily48::Nullifier,
                1,
                2,
                Vec::new(),
                rows(&[key(2)], 1),
            )
            .expect("construct direct nullifier append"),
            CanonicalMembershipStoreDelta48::new(
                CanonicalMembershipFamily48::ConsumedBridgeMessage,
                1,
                2,
                Vec::new(),
                rows(&[key(101)], 1),
            )
            .expect("construct conflicting direct bridge append"),
        )
        .expect("construct conflicting paired direct delta");
        let before = storage.snapshot_rows();
        let result = (
            &storage.nullifier_by_key,
            &storage.nullifier_by_index,
            &storage.bridge_by_key,
            &storage.bridge_by_index,
        )
            .transaction(
                |(nullifier_by_key, nullifier_by_index, bridge_by_key, bridge_by_index)| {
                    apply_membership_delta_transactionally(
                        nullifier_by_key,
                        nullifier_by_index,
                        bridge_by_key,
                        bridge_by_index,
                        0,
                        None,
                        &conflicting,
                    )
                },
            );
        assert!(matches!(
            result,
            Err(sled::transaction::TransactionError::Abort(
                CanonicalMembershipTransactionAbort::DirectDeltaMismatch
            ))
        ));
        assert_eq!(storage.snapshot_rows(), before);

        let blocked = (
            &storage.nullifier_by_key,
            &storage.nullifier_by_index,
            &storage.bridge_by_key,
            &storage.bridge_by_index,
        )
            .transaction(
                |(nullifier_by_key, nullifier_by_index, bridge_by_key, bridge_by_index)| {
                    apply_membership_delta_transactionally(
                        nullifier_by_key,
                        nullifier_by_index,
                        bridge_by_key,
                        bridge_by_index,
                        0,
                        Some(8),
                        &conflicting,
                    )
                },
            );
        assert!(matches!(
            blocked,
            Err(sled::transaction::TransactionError::Abort(
                CanonicalMembershipTransactionAbort::ActiveWal
            ))
        ));
        assert_eq!(storage.snapshot_rows(), before);
    }

    #[test]
    fn epoch_and_cache_are_fail_closed_across_commit_and_uncertainty() {
        let storage = TestStorage::new();
        let epoch = CanonicalMembershipEpoch::new(0).expect("construct epoch");
        let indexes = storage.indexes(&epoch, 4);
        let mut views = indexes
            .views_from_snapshot(&snapshot(0, 0, None, 0, 0, 0, 0), 4)
            .expect("construct empty views");
        assert!(!views.nullifiers.contains(&key(1)).expect("cache negative"));
        assert!(matches!(
            epoch.begin_mutation(0, &snapshot(4, 0, None, 0, 0, 0, 0)),
            Err(CanonicalMembershipError::InvalidRebase(
                "target snapshot is not the next stable epoch"
            ))
        ));
        assert_eq!(epoch.load(), 0);
        let empty_target = snapshot(2, 0, None, 0, 0, 0, 0);
        let prepared = epoch
            .begin_mutation(0, &empty_target)
            .expect("begin aborted mutation");
        assert!(views.nullifiers.contains(&key(1)).is_err());
        drop(prepared);
        assert!(!views.nullifiers.contains(&key(1)).expect("restored epoch"));
        epoch
            .begin_mutation(0, &empty_target)
            .expect("begin confirmed abort")
            .storage_may_commit()
            .abort_confirmed();
        assert_eq!(epoch.load(), 0);

        let committed_target = snapshot(2, 0, None, 1, 1, 0, 0);
        let uncertain = epoch
            .begin_mutation(0, &committed_target)
            .expect("begin committed mutation")
            .storage_may_commit();
        storage
            .nullifier_by_key
            .insert(
                encode_membership_base_forward_key(0, &key(1)).to_vec(),
                &0u64.to_be_bytes(),
            )
            .expect("insert committed forward row");
        storage
            .nullifier_by_index
            .insert(
                encode_membership_base_reverse_key(0, 0).to_vec(),
                key(1).to_vec(),
            )
            .expect("insert committed reverse row");
        let committed = uncertain.commit_confirmed();
        assert!(views.nullifiers.contains(&key(1)).is_err());
        views.nullifiers.logical_count = 1;
        views.bridge_messages.logical_count = 0;
        views
            .rebase_after_commit(committed)
            .expect("publish membership epoch");
        assert!(views
            .nullifiers
            .contains(&key(1))
            .expect("new epoch bypasses stale negative cache"));

        let poisoned = CanonicalMembershipEpoch::new(10).expect("construct poison epoch");
        let poison_target = snapshot(12, 0, None, 0, 0, 0, 0);
        let uncertain = poisoned
            .begin_mutation(10, &poison_target)
            .expect("begin uncertain mutation")
            .storage_may_commit();
        drop(uncertain);
        assert_eq!(poisoned.load(), 11);
        assert!(matches!(
            poisoned.verify_stable(10),
            Err(CanonicalMembershipError::StaleView {
                expected: 10,
                observed: 11
            })
        ));
    }

    #[test]
    fn cache_epoch_churn_retains_the_current_working_set_without_orphans() {
        let mut cache = ExactMembershipCache48::new(8);
        for epoch in (0..=160u64).step_by(2) {
            let binding = CanonicalMembershipReadBinding {
                stable_epoch: epoch,
                base_generation: epoch / 2,
                active_wal_generation: None,
            };
            for offset in 0..8u64 {
                let member = key(epoch * 16 + offset + 1);
                cache.insert(binding, member, Some(offset));
            }
            assert_eq!(cache.len(), 8);
            for offset in 0..8u64 {
                let member = key(epoch * 16 + offset + 1);
                assert_eq!(cache.get(binding, &member), Some(Some(offset)));
            }
            assert!(cache.order.len() <= cache.capacity.saturating_mul(4));
        }
    }

    #[test]
    fn rebase_rejects_stale_clone_and_foreign_epoch_token_in_release_logic() {
        let storage = TestStorage::new();
        let epoch = CanonicalMembershipEpoch::new(0).expect("construct membership epoch");
        let indexes = storage.indexes(&epoch, 4);
        let mut current = indexes
            .views_from_snapshot(&snapshot(0, 0, None, 0, 0, 0, 0), 8)
            .expect("construct current membership views");
        let mut stale = current.clone();
        let delta = CanonicalMembershipDelta48::new(
            0,
            2,
            CanonicalMembershipStoreDelta48::new(
                CanonicalMembershipFamily48::Nullifier,
                0,
                1,
                Vec::new(),
                rows(&[key(1)], 0),
            )
            .expect("construct nullifier append"),
            no_change(CanonicalMembershipFamily48::ConsumedBridgeMessage, 0),
        )
        .expect("construct paired append");
        current.apply_delta(&delta).expect("apply current delta");
        let target = snapshot(2, 0, None, 1, 1, 0, 0);
        let committed = epoch
            .begin_mutation(0, &target)
            .expect("begin publication")
            .storage_may_commit()
            .commit_confirmed();
        assert!(matches!(
            stale.rebase_after_commit(committed),
            Err(CanonicalMembershipError::InvalidRebase(
                "view counts do not match committed snapshot"
            ))
        ));

        let storage = TestStorage::new();
        let view_epoch = CanonicalMembershipEpoch::new(0).expect("construct view epoch");
        let indexes = storage.indexes(&view_epoch, 4);
        let mut views = indexes
            .views_from_snapshot(&snapshot(0, 0, None, 0, 0, 0, 0), 8)
            .expect("construct foreign-token views");
        let foreign_epoch = CanonicalMembershipEpoch::new(0).expect("construct foreign epoch");
        let foreign_target = snapshot(2, 0, None, 0, 0, 0, 0);
        let foreign = foreign_epoch
            .begin_mutation(0, &foreign_target)
            .expect("begin foreign publication")
            .storage_may_commit()
            .commit_confirmed();
        assert!(matches!(
            views.rebase_after_commit(foreign),
            Err(CanonicalMembershipError::InvalidRebase(
                "committed epoch belongs to a different membership index"
            ))
        ));
    }

    #[test]
    fn streaming_audits_detect_corruption_without_mutation() {
        let storage = TestStorage::new();
        let keys = [key(1), key(2), key(3), key(4)];
        storage.seed_base(CanonicalMembershipFamily48::Nullifier, 5, &keys);
        storage.seed_base(
            CanonicalMembershipFamily48::ConsumedBridgeMessage,
            5,
            &[[0u8; KEY_BYTES]],
        );
        let epoch = CanonicalMembershipEpoch::new(0).expect("construct epoch");
        let indexes = storage.indexes(&epoch, 8);
        let views = indexes
            .views_from_snapshot(&snapshot(0, 5, None, 4, 4, 1, 1), 8)
            .expect("construct audit views");
        let work = views
            .nullifiers
            .audit_effective_view()
            .expect("audit valid nullifier base");
        assert_eq!(work.effective_rows, 4);
        assert_eq!(work.max_buffered_keys, 1);
        assert!(views
            .bridge_messages
            .contains(&[0u8; KEY_BYTES])
            .expect("bridge zero key remains exact"));

        storage
            .nullifier_by_index
            .insert(
                encode_membership_base_reverse_key(5, 2).to_vec(),
                key(99).to_vec(),
            )
            .expect("corrupt reverse row");
        let before = storage.snapshot_rows();
        assert!(matches!(
            views.nullifiers.audit_effective_view(),
            Err(CanonicalMembershipError::IndexBijectionMismatch)
        ));
        assert_eq!(storage.snapshot_rows(), before);
        storage
            .nullifier_by_index
            .insert(
                encode_membership_base_reverse_key(5, 2).to_vec(),
                key(3).to_vec(),
            )
            .expect("restore reverse row");
        storage
            .nullifier_by_key
            .insert(
                encode_membership_base_forward_key(5, &key(3)).to_vec(),
                &[1u8],
            )
            .expect("corrupt forward value");
        let before = storage.snapshot_rows();
        let fresh_epoch = CanonicalMembershipEpoch::new(0).expect("construct fresh audit epoch");
        let fresh_indexes = storage.indexes(&fresh_epoch, 0);
        let fresh_views = fresh_indexes
            .views_from_snapshot(&snapshot(0, 5, None, 4, 4, 1, 1), 8)
            .expect("construct uncached corruption view");
        assert!(fresh_views.nullifiers.contains(&key(3)).is_err());
        assert_eq!(storage.snapshot_rows(), before);
    }

    #[test]
    fn wal_cross_binding_mutation_and_inactive_cleanup_fail_closed() {
        let storage = TestStorage::new();
        storage.seed_base(CanonicalMembershipFamily48::Nullifier, 0, &[key(1), key(2)]);
        let delta = CanonicalMembershipDelta48::new(
            0,
            2,
            CanonicalMembershipStoreDelta48::new(
                CanonicalMembershipFamily48::Nullifier,
                2,
                2,
                rows(&[key(2)], 1),
                rows(&[key(3)], 1),
            )
            .expect("construct WAL audit delta"),
            no_change(CanonicalMembershipFamily48::ConsumedBridgeMessage, 0),
        )
        .expect("construct paired WAL audit delta");
        let plan = CanonicalMembershipWalPlan48::from_delta(12, None, &delta)
            .expect("plan WAL audit generation");
        storage.stage_plan(&plan);
        let initial_audit = audit_membership_wal_generation(
            &storage.wal_by_key,
            &storage.wal_by_index,
            &storage.wal_order,
            12,
            plan.order_count(),
            plan.by_index_count(),
        )
        .expect("audit valid WAL generation");
        assert_eq!(initial_audit.sealed_digest, plan.sealed_digest());
        let first = plan.order_records[0];
        let key = encode_wal_forward_key(12, first.family, &first.key);
        let mut value = storage
            .wal_by_key
            .get(key)
            .expect("read WAL row")
            .expect("WAL row exists")
            .to_vec();
        value[1 + SEQUENCE_BYTES + 1 + ORDINAL_BYTES + 1] ^= 1;
        storage
            .wal_by_key
            .insert(key, value)
            .expect("corrupt WAL cross-binding");
        let before = storage.snapshot_rows();
        assert!(audit_membership_wal_generation(
            &storage.wal_by_key,
            &storage.wal_by_index,
            &storage.wal_order,
            12,
            plan.order_count(),
            plan.by_index_count(),
        )
        .is_err());
        assert_eq!(storage.snapshot_rows(), before);
        assert!(matches!(
            discard_inactive_membership_wal_batch(
                &storage.reorg_wal_manifest,
                &storage.wal_by_key,
                &storage.wal_by_index,
                &storage.wal_order,
                12,
                MAX_CANONICAL_MEMBERSHIP_WAL_CLEANUP_BATCH_ROWS + 1,
            ),
            Err(CanonicalMembershipError::CleanupBatchLimitExceeded(
                MAX_CANONICAL_MEMBERSHIP_WAL_CLEANUP_BATCH_ROWS
            ))
        ));
        assert_eq!(storage.snapshot_rows(), before);
        storage
            .reorg_wal_manifest
            .insert(
                NATIVE_REORG_WAL_ACTIVE_KEY_V3,
                12u64.to_be_bytes().as_slice(),
            )
            .expect("activate WAL generation");
        assert!(matches!(
            discard_inactive_membership_wal_batch(
                &storage.reorg_wal_manifest,
                &storage.wal_by_key,
                &storage.wal_by_index,
                &storage.wal_order,
                12,
                1,
            ),
            Err(CanonicalMembershipError::CannotDiscardActiveWal)
        ));
        storage
            .reorg_wal_manifest
            .remove(NATIVE_REORG_WAL_ACTIVE_KEY_V3)
            .expect("deactivate WAL generation");
        let sealed_key = native_reorg_wal_sealed_key(12);
        storage
            .reorg_wal_manifest
            .insert(sealed_key, b"sealed")
            .expect("seal WAL generation");
        assert!(matches!(
            discard_inactive_membership_wal_batch(
                &storage.reorg_wal_manifest,
                &storage.wal_by_key,
                &storage.wal_by_index,
                &storage.wal_order,
                12,
                1,
            ),
            Err(CanonicalMembershipError::CannotDiscardSealedWal)
        ));
        storage
            .reorg_wal_manifest
            .remove(sealed_key)
            .expect("unseal WAL generation");
        loop {
            let work = discard_inactive_membership_wal_batch(
                &storage.reorg_wal_manifest,
                &storage.wal_by_key,
                &storage.wal_by_index,
                &storage.wal_order,
                12,
                2,
            )
            .expect("discard inactive WAL batch");
            assert!(work.removed_rows <= 2);
            if work.generation_empty {
                break;
            }
        }
        assert!(storage.wal_by_key.is_empty());
        assert!(storage.wal_by_index.is_empty());
        assert!(storage.wal_order.is_empty());
    }

    #[test]
    fn typed_hash48_delta_and_remaining_wal_stream_are_exact_and_bounded() {
        let storage = TestStorage::new();
        storage.seed_base(CanonicalMembershipFamily48::Nullifier, 0, &[key(1), key(2)]);
        storage.seed_base(
            CanonicalMembershipFamily48::ConsumedBridgeMessage,
            0,
            &[key(101)],
        );
        let nullifiers = CanonicalMembershipStoreDelta48::nullifiers_v3(
            2,
            2,
            vec![CanonicalNullifierIndexedRowV3 {
                ordinal: 1,
                key: Nullifier48::new(key(2)),
            }],
            vec![CanonicalNullifierIndexedRowV3 {
                ordinal: 1,
                key: Nullifier48::new(key(3)),
            }],
        )
        .expect("construct typed nullifier delta");
        let bridge = CanonicalMembershipStoreDelta48::bridge_messages_v3(
            1,
            1,
            vec![CanonicalBridgeIndexedRowV3 {
                ordinal: 0,
                key: BridgeReplayKey48::new(key(101)),
            }],
            vec![CanonicalBridgeIndexedRowV3 {
                ordinal: 0,
                key: BridgeReplayKey48::new(key(102)),
            }],
        )
        .expect("construct typed bridge delta");
        let delta = CanonicalMembershipDelta48::new(0, 2, nullifiers, bridge)
            .expect("construct typed paired delta");
        let plan = CanonicalMembershipWalPlan48::from_delta(44, None, &delta)
            .expect("plan typed membership WAL");
        storage.stage_plan(&plan);
        let seal = plan.sealed_digest();

        let mut visited = Vec::new();
        let work = stream_remaining_membership_wal_records(
            &storage.wal_by_key,
            &storage.wal_by_index,
            &storage.wal_order,
            44,
            1,
            plan.order_count(),
            plan.by_index_count(),
            seal,
            |record| {
                visited.push(record.sequence);
                Ok(())
            },
        )
        .expect("stream remaining sealed WAL");
        assert_eq!(work.visited_rows, plan.order_count() - 1);
        assert_eq!(
            work.max_buffered_records,
            usize::from(work.visited_rows != 0)
        );
        assert_eq!(visited, (1..plan.order_count()).collect::<Vec<_>>());

        let mut wrong_seal = seal;
        wrong_seal[0] ^= 1;
        let mut invoked = false;
        assert!(stream_remaining_membership_wal_records(
            &storage.wal_by_key,
            &storage.wal_by_index,
            &storage.wal_order,
            44,
            1,
            plan.order_count(),
            plan.by_index_count(),
            wrong_seal,
            |_| {
                invoked = true;
                Ok(())
            },
        )
        .is_err());
        assert!(!invoked, "seal mismatch invoked the composition callback");

        assert!(CanonicalMembershipStoreDelta48::nullifiers_v3(
            0,
            1,
            Vec::new(),
            vec![CanonicalNullifierIndexedRowV3 {
                ordinal: 0,
                key: Nullifier48::ZERO,
            }],
        )
        .is_err());
    }

    #[test]
    fn resident_state_is_bounded_independently_of_large_disk_history() {
        let storage = TestStorage::new();
        let keys = (1..=65_536).map(key).collect::<Vec<_>>();
        storage.seed_base(CanonicalMembershipFamily48::Nullifier, 3, &keys);
        let epoch = CanonicalMembershipEpoch::new(0).expect("construct epoch");
        let indexes = storage.indexes(&epoch, 128);
        let views = indexes
            .views_from_snapshot(&snapshot(0, 3, None, 65_536, 65_536, 0, 0), 1_024)
            .expect("construct large-history view");
        for id in 1..=512 {
            assert!(views
                .nullifiers
                .contains(&key(id))
                .expect("large-history point lookup"));
        }
        let instrumentation = views.nullifiers.resident_instrumentation();
        assert_eq!(instrumentation.logical_count, 65_536);
        assert_eq!(instrumentation.inserted_keys, 0);
        assert_eq!(instrumentation.removed_keys, 0);
        assert_eq!(instrumentation.overlay_nodes, 0);
        assert_eq!(instrumentation.cache_entries, 128);
        assert!(instrumentation.cache_entries <= instrumentation.cache_capacity);
        assert!(instrumentation.cache_estimated_payload_bytes < 64 * 1024);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CanonicalMembershipResidentInstrumentation {
    pub(crate) logical_count: u64,
    pub(crate) inserted_keys: usize,
    pub(crate) removed_keys: usize,
    pub(crate) overlay_nodes: usize,
    pub(crate) overlay_capacity: usize,
    pub(crate) overlay_estimated_payload_bytes: usize,
    pub(crate) cache_entries: usize,
    pub(crate) cache_capacity: usize,
    pub(crate) cache_estimated_payload_bytes: usize,
    pub(crate) disk_point_reads: u64,
    pub(crate) cache_hits: u64,
    pub(crate) cache_misses: u64,
    pub(crate) stale_rejections: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct CanonicalMembershipViews48 {
    nullifiers: CanonicalMembershipView48,
    bridge_messages: CanonicalMembershipView48,
}

impl CanonicalMembershipViews48 {
    pub(crate) fn from_snapshot(
        nullifier_index: CanonicalMembershipIndex48,
        bridge_index: CanonicalMembershipIndex48,
        snapshot: &CanonicalMembershipSnapshotV3,
        overlay_capacity: usize,
    ) -> Result<Self, CanonicalMembershipError> {
        snapshot.validate()?;
        if nullifier_index.family() != CanonicalMembershipFamily48::Nullifier
            || bridge_index.family() != CanonicalMembershipFamily48::ConsumedBridgeMessage
            || !Arc::ptr_eq(
                &nullifier_index.inner.epoch.value,
                &bridge_index.inner.epoch.value,
            )
        {
            return Err(CanonicalMembershipError::InvalidSnapshot(
                "membership indexes do not share the snapshot epoch",
            ));
        }
        Ok(Self {
            nullifiers: CanonicalMembershipView48::new(
                nullifier_index,
                snapshot.stable_epoch,
                snapshot.base_generation,
                snapshot.active_wal_generation,
                snapshot.nullifier_count,
                overlay_capacity,
            )?,
            bridge_messages: CanonicalMembershipView48::new(
                bridge_index,
                snapshot.stable_epoch,
                snapshot.base_generation,
                snapshot.active_wal_generation,
                snapshot.bridge_count,
                overlay_capacity,
            )?,
        })
    }

    /// Applies both family deltas atomically in memory.  Disk lookups happen
    /// only against cloned candidates; either both views publish or neither.
    pub(crate) fn apply_delta(
        &mut self,
        delta: &CanonicalMembershipDelta48,
    ) -> Result<(), CanonicalMembershipError> {
        delta.validate()?;
        if self.nullifiers.stable_epoch() != delta.base_epoch
            || self.bridge_messages.stable_epoch() != delta.base_epoch
        {
            return Err(CanonicalMembershipError::DeltaEpochMismatch);
        }
        let mut candidate = self.clone();
        candidate.nullifiers.apply_store_delta(&delta.nullifiers)?;
        candidate
            .bridge_messages
            .apply_store_delta(&delta.bridge_messages)?;
        *self = candidate;
        Ok(())
    }

    pub(crate) fn contains_nullifier_v3(
        &self,
        key: &Nullifier48,
    ) -> Result<bool, CanonicalMembershipError> {
        self.nullifiers.contains(key.as_bytes())
    }

    pub(crate) fn contains_bridge_message_v3(
        &self,
        key: &BridgeReplayKey48,
    ) -> Result<bool, CanonicalMembershipError> {
        self.bridge_messages.contains(key.as_bytes())
    }

    pub(crate) fn nullifier_at_ordinal_v3(
        &self,
        ordinal: u64,
    ) -> Result<Option<Nullifier48>, CanonicalMembershipError> {
        self.nullifiers
            .key_at_ordinal(ordinal)
            .map(|key| key.map(Nullifier48::new))
    }

    pub(crate) fn bridge_message_at_ordinal_v3(
        &self,
        ordinal: u64,
    ) -> Result<Option<BridgeReplayKey48>, CanonicalMembershipError> {
        self.bridge_messages
            .key_at_ordinal(ordinal)
            .map(|key| key.map(BridgeReplayKey48::new))
    }

    pub(crate) fn rebase_after_commit(
        &mut self,
        committed: CanonicalMembershipCommittedEpoch,
    ) -> Result<(), CanonicalMembershipError> {
        let snapshot = committed.target_snapshot();
        snapshot.validate()?;
        if !Arc::ptr_eq(
            &committed.epoch.value,
            &self.nullifiers.index.inner.epoch.value,
        ) || !Arc::ptr_eq(
            &committed.epoch.value,
            &self.bridge_messages.index.inner.epoch.value,
        ) {
            return Err(CanonicalMembershipError::InvalidRebase(
                "committed epoch belongs to a different membership index",
            ));
        }
        committed.epoch.verify_stable(committed.next())?;
        if snapshot.stable_epoch != committed.next() {
            return Err(CanonicalMembershipError::InvalidRebase(
                "snapshot epoch does not match committed epoch",
            ));
        }
        let nullifier_binding = self.nullifiers.binding;
        let bridge_binding = self.bridge_messages.binding;
        if nullifier_binding != bridge_binding
            || nullifier_binding.stable_epoch != committed.previous()
        {
            return Err(CanonicalMembershipError::InvalidRebase(
                "views do not share the committed prior binding",
            ));
        }
        if self.nullifiers.logical_count != snapshot.nullifier_count
            || self.bridge_messages.logical_count != snapshot.bridge_count
        {
            return Err(CanonicalMembershipError::InvalidRebase(
                "view counts do not match committed snapshot",
            ));
        }
        self.nullifiers.rebase_validated(
            snapshot.stable_epoch,
            snapshot.base_generation,
            snapshot.active_wal_generation,
        );
        self.bridge_messages.rebase_validated(
            snapshot.stable_epoch,
            snapshot.base_generation,
            snapshot.active_wal_generation,
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CanonicalMembershipAuditWork {
    pub(crate) effective_rows: u64,
    pub(crate) base_forward_rows_scanned: u64,
    pub(crate) base_reverse_rows_scanned: u64,
    pub(crate) wal_forward_rows_scanned: u64,
    pub(crate) wal_reverse_rows_scanned: u64,
    pub(crate) order_rows_scanned: u64,
    pub(crate) forward_point_checks: u64,
    pub(crate) reverse_point_checks: u64,
    pub(crate) max_buffered_keys: usize,
}

impl CanonicalMembershipView48 {
    /// O(1)-memory exact audit of the effective base+active-WAL bijection.
    /// This is suitable for full startup validation, repair, and forensics.
    /// A fast-open path may skip this history-sized scan only under the
    /// explicit host-and-disk-integrity TCB of the atomically persisted compact
    /// marker.  The sealed digest authenticates exact WAL rows, not compacted
    /// base rows, and is not a substitute for this audit outside that TCB.
    pub(crate) fn audit_effective_view(
        &self,
    ) -> Result<CanonicalMembershipAuditWork, CanonicalMembershipError> {
        if !self.inserted.is_empty() || !self.removed.is_empty() {
            return Err(CanonicalMembershipError::OrdinalLookupWithOverlay);
        }
        self.index.verify_epoch(self.binding)?;
        let mut work = CanonicalMembershipAuditWork {
            max_buffered_keys: usize::from(self.logical_count != 0),
            ..CanonicalMembershipAuditWork::default()
        };
        for ordinal in 0..self.logical_count {
            let key = self
                .index
                .key_at_ordinal(self.binding, ordinal)?
                .ok_or(CanonicalMembershipError::IndexBijectionMismatch)?;
            work.reverse_point_checks = work.reverse_point_checks.saturating_add(1);
            if self.index.ordinal_of_key(self.binding, &key)? != Some(ordinal) {
                return Err(CanonicalMembershipError::IndexBijectionMismatch);
            }
            work.forward_point_checks = work.forward_point_checks.saturating_add(1);
            work.effective_rows = work.effective_rows.saturating_add(1);
        }

        let base_prefix = encode_generation(self.binding.base_generation);
        for row in self.index.inner.base_by_key.scan_prefix(base_prefix) {
            let (encoded_key, encoded_value) = row?;
            let (generation, key) = decode_base_forward_key(encoded_key.as_ref())?;
            if generation != self.binding.base_generation {
                return Err(CanonicalMembershipError::IndexBijectionMismatch);
            }
            validate_key(self.family(), &key)?;
            decode_ordinal(encoded_value.as_ref(), "base forward ordinal")?;
            if let Some(ordinal) = self.index.ordinal_of_key(self.binding, &key)? {
                if ordinal >= self.logical_count
                    || self.index.key_at_ordinal(self.binding, ordinal)? != Some(key)
                {
                    return Err(CanonicalMembershipError::IndexBijectionMismatch);
                }
            }
            work.base_forward_rows_scanned = work.base_forward_rows_scanned.saturating_add(1);
        }
        for row in self.index.inner.base_by_index.scan_prefix(base_prefix) {
            let (encoded_key, encoded_value) = row?;
            let (generation, ordinal) = decode_base_reverse_key(encoded_key.as_ref())?;
            if generation != self.binding.base_generation {
                return Err(CanonicalMembershipError::IndexBijectionMismatch);
            }
            let key = read_array(encoded_value.as_ref(), "base reverse member key")?;
            validate_key(self.family(), &key)?;
            if ordinal >= self.logical_count
                && self.index.key_at_ordinal(self.binding, ordinal)?.is_some()
            {
                return Err(CanonicalMembershipError::IndexBijectionMismatch);
            }
            work.base_reverse_rows_scanned = work.base_reverse_rows_scanned.saturating_add(1);
        }

        if let Some(generation) = self.binding.active_wal_generation {
            let mut wal_prefix = Vec::with_capacity(GENERATION_BYTES + FAMILY_BYTES);
            wal_prefix.extend_from_slice(&generation.to_be_bytes());
            wal_prefix.push(self.family().tag());
            for row in self.index.inner.wal_by_key.scan_prefix(&wal_prefix) {
                let (encoded_key, encoded_value) = row?;
                let (observed_generation, family, key) =
                    decode_wal_forward_key(encoded_key.as_ref())?;
                if observed_generation != generation || family != self.family() {
                    return Err(CanonicalMembershipError::WalCrossBindingMismatch);
                }
                let value = WalByKeyValue48::decode(encoded_value.as_ref())?;
                if let Some(ordinal) = value.replacement_ordinal {
                    if ordinal >= self.logical_count
                        || self.index.key_at_ordinal(self.binding, ordinal)? != Some(key)
                    {
                        return Err(CanonicalMembershipError::IndexBijectionMismatch);
                    }
                }
                work.wal_forward_rows_scanned = work.wal_forward_rows_scanned.saturating_add(1);
            }
            for row in self.index.inner.wal_by_index.scan_prefix(&wal_prefix) {
                let (encoded_key, encoded_value) = row?;
                let (observed_generation, family, ordinal) =
                    decode_wal_reverse_key(encoded_key.as_ref())?;
                if observed_generation != generation || family != self.family() {
                    return Err(CanonicalMembershipError::WalCrossBindingMismatch);
                }
                let value = CanonicalMembershipWalByIndexRecord48::decode_value(
                    family,
                    ordinal,
                    encoded_value.as_ref(),
                )?;
                if value.replacement.is_some() && ordinal >= self.logical_count {
                    return Err(CanonicalMembershipError::IndexBijectionMismatch);
                }
                work.wal_reverse_rows_scanned = work.wal_reverse_rows_scanned.saturating_add(1);
            }
        }
        self.index.verify_epoch(self.binding)?;
        Ok(work)
    }
}
