//! Bounded streaming V3 canonical-reorg WAL primitives.
//!
//! Reorg planning emits only small normalized mutations. Large self-contained
//! block action bodies live in the content-addressed V3 block store; WAL values
//! refer to them by typed fixed-size records. Inactive rows are invisible.
//! After an atomic active-generation flip, point reads consult the by-key WAL
//! before the compacted base, while a resumable cursor applies the ordered
//! stream one exact row per transaction. This keeps memory and writer-lock
//! duration independent of the 128-block body byte total.

use super::*;
use codec::{DecodeWithMemLimit, DecodeWithMemTracking};
use crypto::hash384::{
    ActionBodyHash48, ActionId48, Blake2b384DomainHasher, BlockId48, CheckpointDigest48,
    ReorgWalValueHash48,
};
use sled::transaction::{ConflictableTransactionError, Transactional};

pub(crate) const NATIVE_REORG_WAL_MANIFEST_TREE_V3: &[u8] = b"native_reorg_wal_manifests_v3";
pub(crate) const NATIVE_REORG_WAL_OP_TREE_V3: &[u8] = b"native_reorg_wal_ops_v3";
pub(crate) const NATIVE_REORG_WAL_BY_KEY_TREE_V3: &[u8] = b"native_reorg_wal_by_key_v3";
pub(crate) const NATIVE_REORG_WAL_TREE_NAMES_V3: [&[u8]; 3] = [
    NATIVE_REORG_WAL_MANIFEST_TREE_V3,
    NATIVE_REORG_WAL_OP_TREE_V3,
    NATIVE_REORG_WAL_BY_KEY_TREE_V3,
];

pub(crate) const NATIVE_REORG_WAL_ACTIVE_KEY_V3: &[u8] = b"active";
pub(crate) const NATIVE_REORG_WAL_SEALED_PREFIX_V3: &[u8] = b"sealed/";
pub(crate) const NATIVE_REORG_WAL_INTENT_PREFIX_V3: &[u8] = b"intent/";
pub(crate) const NATIVE_REORG_WAL_PROGRESS_PREFIX_V3: &[u8] = b"progress/";

const NATIVE_REORG_WAL_OP_SCHEMA_V3: u16 = 3;
const NATIVE_REORG_WAL_BY_KEY_CODEC_V1: u8 = 1;
const REORG_WAL_GENERATION_BYTES: usize = 8;
const REORG_WAL_SEQUENCE_BYTES: usize = 8;
const REORG_WAL_DIGEST_BYTES: usize = 48;
const REORG_WAL_BY_KEY_VALUE_BYTES: usize = 1 + REORG_WAL_SEQUENCE_BYTES + REORG_WAL_DIGEST_BYTES;
const MAX_NATIVE_REORG_WAL_KEY_BYTES: usize = 128;
const MAX_NATIVE_REORG_WAL_VALUE_BYTES: usize = 4 * 1024;
const MAX_NATIVE_REORG_WAL_ENCODED_OP_BYTES: usize =
    512 + MAX_NATIVE_REORG_WAL_KEY_BYTES + 2 * MAX_NATIVE_REORG_WAL_VALUE_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[repr(u8)]
pub(crate) enum NativeReorgWalTreeV3 {
    Meta = 0x01,
    Height = 0x02,
    Commitment = 0x03,
    CiphertextIndex = 0x04,
    CiphertextArchive = 0x05,
    PendingAction = 0x06,
    BlockMeta = 0x07,
    DaCiphertext = 0x08,
    CanonicalUndo = 0x09,
    CanonicalCheckpoint = 0x0a,
    NoncanonicalFork = 0x0b,
}

impl DecodeWithMemTracking for NativeReorgWalTreeV3 {}

impl NativeReorgWalTreeV3 {
    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            0x01 => Ok(Self::Meta),
            0x02 => Ok(Self::Height),
            0x03 => Ok(Self::Commitment),
            0x04 => Ok(Self::CiphertextIndex),
            0x05 => Ok(Self::CiphertextArchive),
            0x06 => Ok(Self::PendingAction),
            0x07 => Ok(Self::BlockMeta),
            0x08 => Ok(Self::DaCiphertext),
            0x09 => Ok(Self::CanonicalUndo),
            0x0a => Ok(Self::CanonicalCheckpoint),
            0x0b => Ok(Self::NoncanonicalFork),
            _ => Err(anyhow!(
                "unsupported native V3 reorg WAL tree tag 0x{tag:02x}"
            )),
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }
}

fn native_reorg_wal_value_hash_v3(bytes: &[u8]) -> Result<(u64, ReorgWalValueHash48)> {
    let len = u64::try_from(bytes.len())
        .map_err(|_| anyhow!("native V3 reorg WAL value length exceeds u64"))?;
    let hash = ReorgWalValueHash48::new(crypto::hash384::blake2b_384_domain_hash(
        crypto::hash384::domains::NATIVE_REORG_WAL_VALUE_V3,
        [bytes],
    ));
    Ok((len, hash))
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking)]
pub(crate) enum NativeReorgWalExpectedV3 {
    Absent,
    Inline(Vec<u8>),
    HashLen { len: u64, hash: ReorgWalValueHash48 },
}

impl NativeReorgWalExpectedV3 {
    fn from_observed(value: Option<&[u8]>) -> Result<Self> {
        let Some(value) = value else {
            return Ok(Self::Absent);
        };
        if value.len() <= MAX_NATIVE_REORG_WAL_VALUE_BYTES {
            return Ok(Self::Inline(value.to_vec()));
        }
        let (len, hash) = native_reorg_wal_value_hash_v3(value)?;
        Ok(Self::HashLen { len, hash })
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Absent => Ok(()),
            Self::Inline(value) if value.len() <= MAX_NATIVE_REORG_WAL_VALUE_BYTES => Ok(()),
            Self::Inline(_) => Err(anyhow!(
                "native V3 reorg WAL inline expected value exceeds bound"
            )),
            Self::HashLen { len, .. }
                if *len > u64::try_from(MAX_NATIVE_REORG_WAL_VALUE_BYTES).unwrap_or(u64::MAX) =>
            {
                Ok(())
            }
            Self::HashLen { .. } => Err(anyhow!(
                "native V3 reorg WAL hash/length expected value is not canonically large"
            )),
        }
    }

    fn matches(&self, observed: Option<&[u8]>) -> Result<bool> {
        Ok(match (self, observed) {
            (Self::Absent, None) => true,
            (Self::Inline(expected), Some(observed)) => expected.as_slice() == observed,
            (Self::HashLen { len, hash }, Some(observed)) => {
                native_reorg_wal_value_hash_v3(observed)? == (*len, *hash)
            }
            _ => false,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking)]
pub(crate) struct NativeReorgWalActionRefV3 {
    pub(crate) action_body_hash: ActionBodyHash48,
    pub(crate) block_hash: BlockId48,
    pub(crate) action_index: u32,
    pub(crate) action_id: ActionId48,
    pub(crate) encoded_len: u64,
    pub(crate) encoded_hash: ReorgWalValueHash48,
}

impl NativeReorgWalActionRefV3 {
    fn validate(&self) -> Result<()> {
        if usize::try_from(self.action_index)
            .ok()
            .is_none_or(|index| index >= MAX_NATIVE_BLOCK_ACTIONS)
            || self.encoded_len
                <= u64::try_from(MAX_NATIVE_REORG_WAL_VALUE_BYTES).unwrap_or(u64::MAX)
            || self.encoded_len
                > u64::try_from(MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES).unwrap_or(u64::MAX)
        {
            return Err(anyhow!(
                "native V3 reorg WAL action reference bounds are invalid"
            ));
        }
        Ok(())
    }

    fn validate_resolved(&self, bytes: &[u8]) -> Result<()> {
        self.validate()?;
        if native_reorg_wal_value_hash_v3(bytes)? != (self.encoded_len, self.encoded_hash) {
            return Err(anyhow!(
                "native V3 reorg WAL action reference hash/length mismatch"
            ));
        }
        let action =
            decode_pending_action_v3_exact(bytes, "native V3 reorg WAL referenced action")?;
        let (action_id, _) = validate_pending_action_identity(&action)?;
        if action_id != self.action_id {
            return Err(anyhow!(
                "native V3 reorg WAL action reference identity mismatch"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking)]
pub(crate) enum NativeReorgWalReplacementV3 {
    Absent,
    Inline(Vec<u8>),
    ActionRef(NativeReorgWalActionRefV3),
}

impl NativeReorgWalReplacementV3 {
    fn from_value(value: Option<Vec<u8>>) -> Result<Self> {
        match value {
            None => Ok(Self::Absent),
            Some(value) if value.len() <= MAX_NATIVE_REORG_WAL_VALUE_BYTES => {
                Ok(Self::Inline(value))
            }
            Some(_) => Err(anyhow!(
                "large native V3 reorg WAL replacements require a typed action-body reference"
            )),
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Absent => Ok(()),
            Self::Inline(value) if value.len() <= MAX_NATIVE_REORG_WAL_VALUE_BYTES => Ok(()),
            Self::Inline(_) => Err(anyhow!(
                "native V3 reorg WAL inline replacement exceeds bound"
            )),
            Self::ActionRef(reference) => reference.validate(),
        }
    }

    fn value_identity(&self) -> Option<(u64, ReorgWalValueHash48)> {
        match self {
            Self::ActionRef(reference) => Some((reference.encoded_len, reference.encoded_hash)),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking)]
pub(crate) struct NativeReorgWalOpV3 {
    schema_version: u16,
    pub(crate) sequence: u64,
    pub(crate) tree: NativeReorgWalTreeV3,
    pub(crate) key: Vec<u8>,
    pub(crate) expected: NativeReorgWalExpectedV3,
    pub(crate) replacement: NativeReorgWalReplacementV3,
    pub(crate) op_digest: CheckpointDigest48,
}

impl NativeReorgWalOpV3 {
    pub(crate) fn new(
        sequence: u64,
        tree: NativeReorgWalTreeV3,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        replacement: Option<Vec<u8>>,
    ) -> Result<Self> {
        Self::new_described(
            sequence,
            tree,
            key,
            NativeReorgWalExpectedV3::from_observed(expected.as_deref())?,
            NativeReorgWalReplacementV3::from_value(replacement)?,
        )
    }

    pub(crate) fn new_described(
        sequence: u64,
        tree: NativeReorgWalTreeV3,
        key: Vec<u8>,
        expected: NativeReorgWalExpectedV3,
        replacement: NativeReorgWalReplacementV3,
    ) -> Result<Self> {
        let mut op = Self {
            schema_version: NATIVE_REORG_WAL_OP_SCHEMA_V3,
            sequence,
            tree,
            key,
            expected,
            replacement,
            op_digest: CheckpointDigest48::ZERO,
        };
        op.validate_without_digest()?;
        op.op_digest = native_reorg_wal_op_digest_v3(&op);
        Ok(op)
    }

    fn validate_without_digest(&self) -> Result<()> {
        if self.schema_version != NATIVE_REORG_WAL_OP_SCHEMA_V3 {
            return Err(anyhow!("native V3 reorg WAL op schema mismatch"));
        }
        if self.key.is_empty() || self.key.len() > MAX_NATIVE_REORG_WAL_KEY_BYTES {
            return Err(anyhow!("native V3 reorg WAL op key length is invalid"));
        }
        self.expected.validate()?;
        self.replacement.validate()?;
        let identity_noop = self
            .expected_identity()
            .zip(self.replacement.value_identity())
            .is_some_and(|(expected, replacement)| expected == replacement);
        let direct_noop = matches!(
            (&self.expected, &self.replacement),
            (
                NativeReorgWalExpectedV3::Absent,
                NativeReorgWalReplacementV3::Absent
            )
        ) || matches!(
            (&self.expected, &self.replacement),
            (NativeReorgWalExpectedV3::Inline(expected), NativeReorgWalReplacementV3::Inline(replacement))
                if expected == replacement
        ) || identity_noop;
        if direct_noop {
            return Err(anyhow!("native V3 reorg WAL op is empty or a no-op"));
        }
        Ok(())
    }

    fn expected_identity(&self) -> Option<(u64, ReorgWalValueHash48)> {
        match self.expected {
            NativeReorgWalExpectedV3::HashLen { len, hash } => Some((len, hash)),
            _ => None,
        }
    }

    fn validate(&self) -> Result<()> {
        self.validate_without_digest()?;
        if self.op_digest != native_reorg_wal_op_digest_v3(self) {
            return Err(anyhow!("native V3 reorg WAL op digest mismatch"));
        }
        Ok(())
    }

    fn decode_exact_bounded(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_NATIVE_REORG_WAL_ENCODED_OP_BYTES {
            return Err(anyhow!("native V3 reorg WAL encoded op exceeds bound"));
        }
        let mut cursor = bytes;
        let op = Self::decode_with_mem_limit(&mut cursor, MAX_NATIVE_REORG_WAL_ENCODED_OP_BYTES)
            .map_err(|err| anyhow!("decode native V3 reorg WAL op failed: {err:?}"))?;
        if !cursor.is_empty() || op.encode().as_slice() != bytes {
            return Err(anyhow!(
                "native V3 reorg WAL op is noncanonical or has trailing bytes"
            ));
        }
        op.validate()?;
        Ok(op)
    }

    fn prepare_for_base<F>(
        &self,
        observed: Option<Vec<u8>>,
        resolve_action: F,
    ) -> Result<PreparedNativeReorgWalOpV3>
    where
        F: FnOnce(&NativeReorgWalActionRefV3) -> Result<Vec<u8>>,
    {
        self.validate()?;
        if !self.expected.matches(observed.as_deref())? {
            return Err(anyhow!(
                "native V3 reorg WAL compacted base differs from expected"
            ));
        }
        let replacement = match &self.replacement {
            NativeReorgWalReplacementV3::Absent => None,
            NativeReorgWalReplacementV3::Inline(value) => Some(value.clone()),
            NativeReorgWalReplacementV3::ActionRef(reference) => {
                let value = resolve_action(reference)?;
                reference.validate_resolved(&value)?;
                Some(value)
            }
        };
        Ok(PreparedNativeReorgWalOpV3 {
            op_digest: self.op_digest,
            expected: observed,
            replacement,
        })
    }
}

/// One-row bounded preparation token. Large value hashing, action-body lookup,
/// SCALE decoding, and ActionId48 validation finish before the sled
/// transaction; the transaction performs only exact byte CAS and mutation.
#[derive(Clone, Debug)]
pub(crate) struct PreparedNativeReorgWalOpV3 {
    op_digest: CheckpointDigest48,
    expected: Option<Vec<u8>>,
    replacement: Option<Vec<u8>>,
}

fn native_reorg_wal_op_digest_v3(op: &NativeReorgWalOpV3) -> CheckpointDigest48 {
    let mut canonical = op.clone();
    canonical.op_digest = CheckpointDigest48::ZERO;
    CheckpointDigest48::new(crypto::hash384::blake2b_384_domain_hash(
        crypto::hash384::domains::NATIVE_REORG_WAL_OP_V3,
        [canonical.encode().as_slice()],
    ))
}

fn require_tree_name(tree: &sled::Tree, expected: &[u8]) -> Result<()> {
    if tree.name().as_ref() != expected {
        return Err(anyhow!(
            "native V3 reorg WAL tree mismatch: expected {}, observed {}",
            String::from_utf8_lossy(expected),
            String::from_utf8_lossy(tree.name().as_ref())
        ));
    }
    Ok(())
}

fn native_reorg_wal_order_key(generation: u64, sequence: u64) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&generation.to_be_bytes());
    key[8..].copy_from_slice(&sequence.to_be_bytes());
    key
}

fn decode_native_reorg_wal_order_key(bytes: &[u8]) -> Result<(u64, u64)> {
    let bytes = <[u8; 16]>::try_from(bytes)
        .map_err(|_| anyhow!("native V3 reorg WAL order key is not 16 bytes"))?;
    let generation = u64::from_be_bytes(bytes[..8].try_into().expect("fixed prefix"));
    let sequence = u64::from_be_bytes(bytes[8..].try_into().expect("fixed suffix"));
    if generation == 0 {
        return Err(anyhow!("native V3 reorg WAL generation zero is reserved"));
    }
    Ok((generation, sequence))
}

fn native_reorg_wal_by_key_key(
    generation: u64,
    tree: NativeReorgWalTreeV3,
    key: &[u8],
) -> Result<Vec<u8>> {
    if generation == 0 || key.is_empty() || key.len() > MAX_NATIVE_REORG_WAL_KEY_BYTES {
        return Err(anyhow!("invalid native V3 reorg WAL by-key identity"));
    }
    let mut encoded = Vec::with_capacity(9 + key.len());
    encoded.extend_from_slice(&generation.to_be_bytes());
    encoded.push(tree.tag());
    encoded.extend_from_slice(key);
    Ok(encoded)
}

fn decode_native_reorg_wal_by_key_key(bytes: &[u8]) -> Result<(u64, NativeReorgWalTreeV3, &[u8])> {
    if bytes.len() < 10 || bytes.len() > 9 + MAX_NATIVE_REORG_WAL_KEY_BYTES {
        return Err(anyhow!("invalid native V3 reorg WAL by-key key length"));
    }
    let generation = u64::from_be_bytes(bytes[..8].try_into().expect("checked prefix"));
    if generation == 0 {
        return Err(anyhow!("native V3 reorg WAL generation zero is reserved"));
    }
    let tree = NativeReorgWalTreeV3::from_tag(bytes[8])?;
    Ok((generation, tree, &bytes[9..]))
}

fn native_reorg_wal_by_key_value(op: &NativeReorgWalOpV3) -> [u8; 57] {
    let mut value = [0u8; REORG_WAL_BY_KEY_VALUE_BYTES];
    value[0] = NATIVE_REORG_WAL_BY_KEY_CODEC_V1;
    value[1..9].copy_from_slice(&op.sequence.to_be_bytes());
    value[9..].copy_from_slice(op.op_digest.as_bytes());
    value
}

fn decode_native_reorg_wal_by_key_value(bytes: &[u8]) -> Result<(u64, CheckpointDigest48)> {
    let bytes = <[u8; REORG_WAL_BY_KEY_VALUE_BYTES]>::try_from(bytes)
        .map_err(|_| anyhow!("invalid native V3 reorg WAL by-key value length"))?;
    if bytes[0] != NATIVE_REORG_WAL_BY_KEY_CODEC_V1 {
        return Err(anyhow!("unsupported native V3 reorg WAL by-key codec"));
    }
    let sequence = u64::from_be_bytes(bytes[1..9].try_into().expect("fixed sequence"));
    let digest = CheckpointDigest48::try_from(&bytes[9..])
        .map_err(|err| anyhow!("invalid native V3 reorg WAL op digest: {err}"))?;
    Ok((sequence, digest))
}

pub(crate) fn native_reorg_wal_sealed_key_v3(generation: u64) -> Result<[u8; 15]> {
    if generation == 0 {
        return Err(anyhow!("native V3 reorg WAL generation zero is reserved"));
    }
    let mut key = [0u8; 15];
    key[..7].copy_from_slice(NATIVE_REORG_WAL_SEALED_PREFIX_V3);
    key[7..].copy_from_slice(&generation.to_be_bytes());
    Ok(key)
}

pub(crate) fn native_reorg_wal_progress_key_v3(generation: u64) -> Result<[u8; 17]> {
    if generation == 0 {
        return Err(anyhow!("native V3 reorg WAL generation zero is reserved"));
    }
    let mut key = [0u8; 17];
    key[..9].copy_from_slice(NATIVE_REORG_WAL_PROGRESS_PREFIX_V3);
    key[9..].copy_from_slice(&generation.to_be_bytes());
    Ok(key)
}

pub(crate) fn load_native_reorg_wal_active_generation_v3(
    manifest_tree: &sled::Tree,
) -> Result<Option<u64>> {
    require_tree_name(manifest_tree, NATIVE_REORG_WAL_MANIFEST_TREE_V3)?;
    manifest_tree
        .get(NATIVE_REORG_WAL_ACTIVE_KEY_V3)?
        .map(|bytes| {
            let bytes = <[u8; 8]>::try_from(bytes.as_ref())
                .map_err(|_| anyhow!("native V3 reorg WAL active pointer is malformed"))?;
            let generation = u64::from_be_bytes(bytes);
            if generation == 0 {
                return Err(anyhow!("native V3 reorg WAL active generation is zero"));
            }
            Ok(generation)
        })
        .transpose()
}

/// Idempotently stage one normalized order/by-key pair. The generation is
/// inactive, so this transaction never changes the canonical read view.
pub(crate) fn stage_native_reorg_wal_op_v3(
    op_tree: &sled::Tree,
    by_key_tree: &sled::Tree,
    generation: u64,
    op: &NativeReorgWalOpV3,
) -> Result<()> {
    require_tree_name(op_tree, NATIVE_REORG_WAL_OP_TREE_V3)?;
    require_tree_name(by_key_tree, NATIVE_REORG_WAL_BY_KEY_TREE_V3)?;
    if generation == 0 {
        return Err(anyhow!("native V3 reorg WAL generation zero is reserved"));
    }
    op.validate()?;
    let order_key = native_reorg_wal_order_key(generation, op.sequence);
    let order_value = op.encode();
    let by_key_key = native_reorg_wal_by_key_key(generation, op.tree, &op.key)?;
    let by_key_value = native_reorg_wal_by_key_value(op);
    let result: sled::transaction::TransactionResult<(), String> = (op_tree, by_key_tree)
        .transaction(|(op_tree, by_key_tree)| {
            match op_tree.get(order_key.as_slice())? {
                Some(observed) if observed.as_ref() == order_value.as_slice() => {}
                Some(_) => {
                    return Err(ConflictableTransactionError::Abort(
                        "native V3 reorg WAL order row collision".to_owned(),
                    ));
                }
                None => {
                    op_tree.insert(order_key.as_slice(), order_value.clone())?;
                }
            }
            match by_key_tree.get(by_key_key.as_slice())? {
                Some(observed) if observed.as_ref() == by_key_value.as_slice() => {}
                Some(_) => {
                    return Err(ConflictableTransactionError::Abort(
                        "native V3 reorg WAL logical key appears more than once".to_owned(),
                    ));
                }
                None => {
                    by_key_tree.insert(by_key_key.as_slice(), by_key_value.as_slice())?;
                }
            }
            Ok(())
        });
    result.map_err(|err| anyhow!("stage native V3 reorg WAL op failed: {err}"))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeReorgWalAuditWorkV3 {
    pub(crate) order_rows: u64,
    pub(crate) by_key_rows: u64,
    pub(crate) point_checks: u64,
    pub(crate) max_buffered_ops: usize,
    pub(crate) digest: CheckpointDigest48,
}

/// Stream-audit a staged generation with O(1) live op buffers.
pub(crate) fn audit_native_reorg_wal_generation_v3(
    op_tree: &sled::Tree,
    by_key_tree: &sled::Tree,
    generation: u64,
    expected_count: u64,
    expected_digest: CheckpointDigest48,
) -> Result<NativeReorgWalAuditWorkV3> {
    require_tree_name(op_tree, NATIVE_REORG_WAL_OP_TREE_V3)?;
    require_tree_name(by_key_tree, NATIVE_REORG_WAL_BY_KEY_TREE_V3)?;
    if generation == 0 {
        return Err(anyhow!("native V3 reorg WAL generation zero is reserved"));
    }
    let prefix = generation.to_be_bytes();
    let mut hasher = Blake2b384DomainHasher::new(crypto::hash384::domains::NATIVE_REORG_WAL_OP_V3);
    let mut work = NativeReorgWalAuditWorkV3::default();
    for row in op_tree.scan_prefix(prefix) {
        let (key, value) = row?;
        let (observed_generation, sequence) = decode_native_reorg_wal_order_key(key.as_ref())?;
        if observed_generation != generation || sequence != work.order_rows {
            return Err(anyhow!("native V3 reorg WAL order has a gap"));
        }
        let op = NativeReorgWalOpV3::decode_exact_bounded(value.as_ref())?;
        if op.sequence != sequence {
            return Err(anyhow!("native V3 reorg WAL sequence mismatch"));
        }
        let by_key_key = native_reorg_wal_by_key_key(generation, op.tree, &op.key)?;
        let by_key_value = by_key_tree
            .get(by_key_key)?
            .ok_or_else(|| anyhow!("native V3 reorg WAL by-key row is missing"))?;
        let (by_key_sequence, by_key_digest) =
            decode_native_reorg_wal_by_key_value(by_key_value.as_ref())?;
        if by_key_sequence != sequence || by_key_digest != op.op_digest {
            return Err(anyhow!("native V3 reorg WAL by-key cross-binding mismatch"));
        }
        hasher.update_part(value.as_ref());
        work.order_rows = work.order_rows.saturating_add(1);
        work.point_checks = work.point_checks.saturating_add(1);
        work.max_buffered_ops = 1;
    }
    for row in by_key_tree.scan_prefix(prefix) {
        let (key, value) = row?;
        let (observed_generation, tree, logical_key) =
            decode_native_reorg_wal_by_key_key(key.as_ref())?;
        if observed_generation != generation {
            return Err(anyhow!("native V3 reorg WAL by-key generation mismatch"));
        }
        let (sequence, digest) = decode_native_reorg_wal_by_key_value(value.as_ref())?;
        let op_value = op_tree
            .get(native_reorg_wal_order_key(generation, sequence))?
            .ok_or_else(|| anyhow!("native V3 reorg WAL order row is missing"))?;
        let op = NativeReorgWalOpV3::decode_exact_bounded(op_value.as_ref())?;
        if op.tree != tree || op.key.as_slice() != logical_key || op.op_digest != digest {
            return Err(anyhow!(
                "native V3 reorg WAL reverse cross-binding mismatch"
            ));
        }
        work.by_key_rows = work.by_key_rows.saturating_add(1);
        work.point_checks = work.point_checks.saturating_add(1);
    }
    work.digest = CheckpointDigest48::new(hasher.finalize());
    if work.order_rows != expected_count
        || work.by_key_rows != expected_count
        || work.digest != expected_digest
    {
        return Err(anyhow!("native V3 reorg WAL sealed count/digest mismatch"));
    }
    Ok(work)
}

pub(crate) fn native_reorg_wal_ops_digest_v3<'a>(
    ops: impl IntoIterator<Item = &'a NativeReorgWalOpV3>,
) -> Result<CheckpointDigest48> {
    let mut hasher = Blake2b384DomainHasher::new(crypto::hash384::domains::NATIVE_REORG_WAL_OP_V3);
    let mut expected_sequence = 0u64;
    for op in ops {
        op.validate()?;
        if op.sequence != expected_sequence {
            return Err(anyhow!("native V3 reorg WAL plan sequence has a gap"));
        }
        hasher.update_part(&op.encode());
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("native V3 reorg WAL sequence overflow"))?;
    }
    Ok(CheckpointDigest48::new(hasher.finalize()))
}

/// Exact overlay point read. The active pointer is checked before and after
/// the base/WAL I/O so a flip or clear races fail stale instead of returning a
/// mixed-generation value.
pub(crate) fn native_reorg_wal_effective_get_v3(
    manifest_tree: &sled::Tree,
    op_tree: &sled::Tree,
    by_key_tree: &sled::Tree,
    base_tree: &sled::Tree,
    expected_active_generation: Option<u64>,
    tree: NativeReorgWalTreeV3,
    key: &[u8],
) -> Result<Option<Vec<u8>>> {
    native_reorg_wal_effective_get_with_action_resolver_v3(
        manifest_tree,
        op_tree,
        by_key_tree,
        base_tree,
        expected_active_generation,
        tree,
        key,
        |_| {
            Err(anyhow!(
                "native V3 reorg WAL action reference requires content-store resolver"
            ))
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn native_reorg_wal_effective_get_with_action_resolver_v3<F>(
    manifest_tree: &sled::Tree,
    op_tree: &sled::Tree,
    by_key_tree: &sled::Tree,
    base_tree: &sled::Tree,
    expected_active_generation: Option<u64>,
    tree: NativeReorgWalTreeV3,
    key: &[u8],
    resolve_action: F,
) -> Result<Option<Vec<u8>>>
where
    F: Fn(&NativeReorgWalActionRefV3) -> Result<Vec<u8>>,
{
    require_tree_name(manifest_tree, NATIVE_REORG_WAL_MANIFEST_TREE_V3)?;
    require_tree_name(op_tree, NATIVE_REORG_WAL_OP_TREE_V3)?;
    require_tree_name(by_key_tree, NATIVE_REORG_WAL_BY_KEY_TREE_V3)?;
    if load_native_reorg_wal_active_generation_v3(manifest_tree)? != expected_active_generation {
        return Err(anyhow!("native V3 reorg WAL read binding is stale"));
    }
    let value = if let Some(generation) = expected_active_generation {
        let by_key_key = native_reorg_wal_by_key_key(generation, tree, key)?;
        match by_key_tree.get(by_key_key)? {
            Some(binding) => {
                let (sequence, digest) = decode_native_reorg_wal_by_key_value(binding.as_ref())?;
                let op_value = op_tree
                    .get(native_reorg_wal_order_key(generation, sequence))?
                    .ok_or_else(|| anyhow!("active native V3 reorg WAL op is missing"))?;
                let op = NativeReorgWalOpV3::decode_exact_bounded(op_value.as_ref())?;
                if op.tree != tree || op.key.as_slice() != key || op.op_digest != digest {
                    return Err(anyhow!("active native V3 reorg WAL binding mismatch"));
                }
                match &op.replacement {
                    NativeReorgWalReplacementV3::Absent => None,
                    NativeReorgWalReplacementV3::Inline(value) => Some(value.clone()),
                    NativeReorgWalReplacementV3::ActionRef(reference) => {
                        let value = resolve_action(reference)?;
                        reference.validate_resolved(&value)?;
                        Some(value)
                    }
                }
            }
            None => base_tree.get(key)?.map(|bytes| bytes.to_vec()),
        }
    } else {
        base_tree.get(key)?.map(|bytes| bytes.to_vec())
    };
    if load_native_reorg_wal_active_generation_v3(manifest_tree)? != expected_active_generation {
        return Err(anyhow!("native V3 reorg WAL read changed generation"));
    }
    Ok(value)
}

/// Apply one active ordered op and advance its exact cursor in the same
/// transaction. Callers dispatch the op's typed tree tag to the matching base
/// handle before invoking this helper.
pub(crate) fn apply_native_reorg_wal_op_transactionally_v3(
    manifest_tree: &sled::transaction::TransactionalTree,
    op_tree: &sled::transaction::TransactionalTree,
    by_key_tree: &sled::transaction::TransactionalTree,
    base_tree: &sled::transaction::TransactionalTree,
    generation: u64,
    sequence: u64,
    expected_tree: NativeReorgWalTreeV3,
    prepared: &PreparedNativeReorgWalOpV3,
) -> sled::transaction::ConflictableTransactionResult<(), String> {
    let abort = |message: &str| ConflictableTransactionError::Abort(message.to_owned());
    if manifest_tree
        .get(NATIVE_REORG_WAL_ACTIVE_KEY_V3)?
        .as_deref()
        != Some(generation.to_be_bytes().as_slice())
    {
        return Err(abort("native V3 reorg WAL active pointer changed"));
    }
    let progress_key =
        native_reorg_wal_progress_key_v3(generation).map_err(|err| abort(&err.to_string()))?;
    if manifest_tree.get(progress_key.as_slice())?.as_deref()
        != Some(sequence.to_be_bytes().as_slice())
    {
        return Err(abort("native V3 reorg WAL progress cursor changed"));
    }
    let order_key = native_reorg_wal_order_key(generation, sequence);
    let op_value = op_tree
        .get(order_key.as_slice())?
        .ok_or_else(|| abort("native V3 reorg WAL order row is missing"))?;
    let op = NativeReorgWalOpV3::decode_exact_bounded(op_value.as_ref())
        .map_err(|err| abort(&err.to_string()))?;
    if op.sequence != sequence || op.tree != expected_tree {
        return Err(abort("native V3 reorg WAL finalizer dispatch mismatch"));
    }
    if prepared.op_digest != op.op_digest {
        return Err(abort("native V3 reorg WAL prepared op binding mismatch"));
    }
    let by_key_key = native_reorg_wal_by_key_key(generation, op.tree, &op.key)
        .map_err(|err| abort(&err.to_string()))?;
    let binding = by_key_tree
        .get(by_key_key.as_slice())?
        .ok_or_else(|| abort("native V3 reorg WAL by-key row is missing"))?;
    if binding.as_ref() != native_reorg_wal_by_key_value(&op).as_slice() {
        return Err(abort("native V3 reorg WAL by-key finalizer mismatch"));
    }
    if base_tree
        .get(op.key.as_slice())?
        .map(|bytes| bytes.to_vec())
        != prepared.expected
    {
        return Err(abort(
            "native V3 reorg WAL compacted base differs from expected",
        ));
    }
    match &prepared.replacement {
        Some(replacement) => {
            base_tree.insert(op.key.as_slice(), replacement.as_slice())?;
        }
        None => {
            base_tree.remove(op.key.as_slice())?;
        }
    }
    let next = sequence
        .checked_add(1)
        .ok_or_else(|| abort("native V3 reorg WAL progress overflow"))?;
    manifest_tree.insert(progress_key.as_slice(), &next.to_be_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestTrees {
        _dir: tempfile::TempDir,
        _db: sled::Db,
        manifest: sled::Tree,
        ops: sled::Tree,
        by_key: sled::Tree,
        base: sled::Tree,
    }

    impl TestTrees {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let db = sled::open(dir.path()).expect("open test sled");
            let manifest = db
                .open_tree(NATIVE_REORG_WAL_MANIFEST_TREE_V3)
                .expect("manifest tree");
            let ops = db.open_tree(NATIVE_REORG_WAL_OP_TREE_V3).expect("op tree");
            let by_key = db
                .open_tree(NATIVE_REORG_WAL_BY_KEY_TREE_V3)
                .expect("by-key tree");
            let base = db.open_tree("test_reorg_base").expect("base tree");
            Self {
                _dir: dir,
                _db: db,
                manifest,
                ops,
                by_key,
                base,
            }
        }

        fn activate(&self, generation: u64) {
            self.manifest
                .insert(
                    NATIVE_REORG_WAL_ACTIVE_KEY_V3,
                    generation.to_be_bytes().as_slice(),
                )
                .expect("set active pointer");
            self.manifest
                .insert(
                    native_reorg_wal_progress_key_v3(generation).expect("progress key"),
                    0u64.to_be_bytes().as_slice(),
                )
                .expect("initialize progress");
        }

        fn apply(&self, generation: u64, sequence: u64) -> Result<()> {
            let op_value = self
                .ops
                .get(native_reorg_wal_order_key(generation, sequence))?
                .ok_or_else(|| anyhow!("test reorg WAL op missing"))?;
            let op = NativeReorgWalOpV3::decode_exact_bounded(op_value.as_ref())?;
            let observed = self
                .base
                .get(op.key.as_slice())?
                .map(|bytes| bytes.to_vec());
            let prepared = op.prepare_for_base(observed, |_| {
                Err(anyhow!("test has no content-addressed action resolver"))
            })?;
            let result: sled::transaction::TransactionResult<(), String> =
                (&self.manifest, &self.ops, &self.by_key, &self.base).transaction(
                    |(manifest, ops, by_key, base)| {
                        apply_native_reorg_wal_op_transactionally_v3(
                            manifest,
                            ops,
                            by_key,
                            base,
                            generation,
                            sequence,
                            NativeReorgWalTreeV3::Meta,
                            &prepared,
                        )
                    },
                );
            result.map_err(|err| anyhow!("apply test reorg WAL op failed: {err}"))
        }
    }

    fn op(
        sequence: u64,
        key: &[u8],
        expected: Option<&[u8]>,
        replacement: Option<&[u8]>,
    ) -> NativeReorgWalOpV3 {
        NativeReorgWalOpV3::new(
            sequence,
            NativeReorgWalTreeV3::Meta,
            key.to_vec(),
            expected.map(<[u8]>::to_vec),
            replacement.map(<[u8]>::to_vec),
        )
        .expect("construct test WAL op")
    }

    #[test]
    fn staged_stream_is_idempotent_exact_and_constant_buffered() {
        let trees = TestTrees::new();
        let generation = 7;
        let ops = [
            op(0, b"a", Some(b"old-a"), Some(b"new-a")),
            op(1, b"b", None, Some(b"new-b")),
            op(2, b"c", Some(b"old-c"), None),
        ];
        for op in &ops {
            stage_native_reorg_wal_op_v3(&trees.ops, &trees.by_key, generation, op)
                .expect("stage op");
            stage_native_reorg_wal_op_v3(&trees.ops, &trees.by_key, generation, op)
                .expect("idempotent restage");
        }
        let digest = native_reorg_wal_ops_digest_v3(&ops).expect("plan digest");
        let work =
            audit_native_reorg_wal_generation_v3(&trees.ops, &trees.by_key, generation, 3, digest)
                .expect("audit staged WAL");
        assert_eq!(work.order_rows, 3);
        assert_eq!(work.by_key_rows, 3);
        assert_eq!(work.max_buffered_ops, 1);

        let duplicate_key = op(3, b"a", Some(b"new-a"), Some(b"later-a"));
        assert!(stage_native_reorg_wal_op_v3(
            &trees.ops,
            &trees.by_key,
            generation,
            &duplicate_key,
        )
        .is_err());
        assert_eq!(
            trees.ops.len(),
            3,
            "collision transaction adds no order row"
        );
    }

    #[test]
    fn active_overlay_stays_exact_during_resumable_finalization() {
        let trees = TestTrees::new();
        let generation = 9;
        trees.base.insert(b"a", b"old-a").unwrap();
        trees.base.insert(b"c", b"old-c").unwrap();
        trees.base.insert(b"untouched", b"base").unwrap();
        let ops = [
            op(0, b"a", Some(b"old-a"), Some(b"new-a")),
            op(1, b"b", None, Some(b"new-b")),
            op(2, b"c", Some(b"old-c"), None),
        ];
        for op in &ops {
            stage_native_reorg_wal_op_v3(&trees.ops, &trees.by_key, generation, op).unwrap();
        }
        trees.activate(generation);

        let get = |key: &[u8]| {
            native_reorg_wal_effective_get_v3(
                &trees.manifest,
                &trees.ops,
                &trees.by_key,
                &trees.base,
                Some(generation),
                NativeReorgWalTreeV3::Meta,
                key,
            )
            .expect("active overlay read")
        };
        assert_eq!(get(b"a"), Some(b"new-a".to_vec()));
        assert_eq!(get(b"b"), Some(b"new-b".to_vec()));
        assert_eq!(get(b"c"), None);
        assert_eq!(get(b"untouched"), Some(b"base".to_vec()));

        for sequence in 0..3 {
            trees.apply(generation, sequence).expect("apply one op");
            assert_eq!(get(b"a"), Some(b"new-a".to_vec()));
            assert_eq!(get(b"b"), Some(b"new-b".to_vec()));
            assert_eq!(get(b"c"), None);
        }
        let progress = trees
            .manifest
            .get(native_reorg_wal_progress_key_v3(generation).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(progress.as_ref(), 3u64.to_be_bytes().as_slice());

        trees
            .manifest
            .remove(NATIVE_REORG_WAL_ACTIVE_KEY_V3)
            .unwrap();
        assert_eq!(
            native_reorg_wal_effective_get_v3(
                &trees.manifest,
                &trees.ops,
                &trees.by_key,
                &trees.base,
                None,
                NativeReorgWalTreeV3::Meta,
                b"a",
            )
            .unwrap(),
            Some(b"new-a".to_vec())
        );
    }

    #[test]
    fn base_conflict_aborts_without_advancing_cursor_or_partial_write() {
        let trees = TestTrees::new();
        let generation = 11;
        trees.base.insert(b"a", b"observed").unwrap();
        let conflict = op(0, b"a", Some(b"expected"), Some(b"replacement"));
        stage_native_reorg_wal_op_v3(&trees.ops, &trees.by_key, generation, &conflict).unwrap();
        trees.activate(generation);
        let before = trees.base.get(b"a").unwrap().unwrap();
        assert!(trees.apply(generation, 0).is_err());
        assert_eq!(trees.base.get(b"a").unwrap().unwrap(), before);
        let progress = trees
            .manifest
            .get(native_reorg_wal_progress_key_v3(generation).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(progress.as_ref(), 0u64.to_be_bytes().as_slice());
        assert!(native_reorg_wal_effective_get_v3(
            &trees.manifest,
            &trees.ops,
            &trees.by_key,
            &trees.base,
            None,
            NativeReorgWalTreeV3::Meta,
            b"a",
        )
        .is_err());
    }

    #[test]
    fn audit_rejects_tampered_order_or_cross_binding_rows() {
        let trees = TestTrees::new();
        let generation = 13;
        let op = op(0, b"a", None, Some(b"value"));
        stage_native_reorg_wal_op_v3(&trees.ops, &trees.by_key, generation, &op).unwrap();
        let digest = native_reorg_wal_ops_digest_v3([&op]).unwrap();
        let key = native_reorg_wal_order_key(generation, 0);
        let mut value = trees.ops.get(key).unwrap().unwrap().to_vec();
        *value.last_mut().expect("encoded digest byte") ^= 1;
        trees.ops.insert(key, value).unwrap();
        assert!(audit_native_reorg_wal_generation_v3(
            &trees.ops,
            &trees.by_key,
            generation,
            1,
            digest,
        )
        .is_err());
    }

    #[test]
    fn op_codec_rejects_short_and_trailing_rows_exactly() {
        let op = op(0, b"a", None, Some(b"value"));
        let encoded = op.encode();
        assert_eq!(
            NativeReorgWalOpV3::decode_exact_bounded(&encoded).unwrap(),
            op
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(NativeReorgWalOpV3::decode_exact_bounded(&trailing).is_err());
        assert!(NativeReorgWalOpV3::decode_exact_bounded(&encoded[..encoded.len() - 1]).is_err());
    }
}
