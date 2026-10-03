//! Content-addressed V3 block storage and bounded noncanonical retention.
//!
//! The network/canonical block body remains self-contained. Sled stores one
//! canonical SCALE slim row per block and one canonical SCALE action-body blob
//! per distinct `ActionBodyHash48`. Refcounts, slim rows, fork records, and
//! retention removals change in one transaction. `CheckpointDigest48` below is
//! only a storage-integrity checksum; it is never proof-validity authority.

use super::fork_retention::{
    plan_native_noncanonical_fork_retention_v3, NativeForkRetentionPlanV3,
    NativeForkRetentionRecordV3, MAX_NATIVE_NONCANONICAL_FORK_BLOCKS,
    MAX_NATIVE_NONCANONICAL_FORK_BYTES, MAX_NATIVE_NONCANONICAL_FORK_DEPTH,
};
use super::reorg_wal::NativeReorgWalActionRefV3;
use super::*;
use crypto::hash384::{ActionBodyHash48, BlockId48, CheckpointDigest48};
use sled::transaction::{ConflictableTransactionError, Transactional};

pub(crate) const NATIVE_BLOCK_META_TREE_V3: &[u8] = b"native_block_meta_v3_by_hash";
pub(crate) const NATIVE_ACTION_BODY_TREE_V3: &[u8] = b"native_action_bodies_v3";
pub(crate) const NATIVE_ACTION_BODY_REFCOUNT_TREE_V3: &[u8] = b"native_action_body_refcounts_v3";
pub(crate) const NATIVE_ACTION_BODY_OWNER_TREE_V3: &[u8] = b"native_action_body_owners_v3";
pub(crate) const NATIVE_NONCANONICAL_FORK_TREE_V3: &[u8] = b"native_noncanonical_forks_v3";
pub(crate) const NATIVE_BLOCK_STORE_TREE_NAMES_V3: [&[u8]; 5] = [
    NATIVE_BLOCK_META_TREE_V3,
    NATIVE_ACTION_BODY_TREE_V3,
    NATIVE_ACTION_BODY_REFCOUNT_TREE_V3,
    NATIVE_ACTION_BODY_OWNER_TREE_V3,
    NATIVE_NONCANONICAL_FORK_TREE_V3,
];

const NATIVE_NONCANONICAL_FORK_RECORD_SCHEMA_V3: u16 = 3;
const META_NONCANONICAL_FORK_NEXT_SEQUENCE_V3: &[u8] = b"native_noncanonical_fork_next_sequence_v3";
const META_BLOCK_STORE_REPAIR_IN_PROGRESS_V3: &[u8] = b"native_block_store_v3_repair_in_progress";
const BLOCK_STORE_REPAIR_MARKER_V3: &[u8] = b"schema-v3";

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct NativeStoredNoncanonicalForkRecordV3 {
    pub(crate) schema_version: u16,
    pub(crate) rules_hash: RulesHash48,
    pub(crate) block_hash: BlockId48,
    pub(crate) parent_hash: BlockId48,
    pub(crate) height: u64,
    pub(crate) cumulative_work: Work64,
    pub(crate) body_hash: BodyHash48,
    pub(crate) body_len: u64,
    pub(crate) action_body_hash: ActionBodyHash48,
    pub(crate) action_body_len: u64,
    pub(crate) first_seen_sequence: u64,
    pub(crate) record_digest: CheckpointDigest48,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeBlockStorePersistOutcomeV3 {
    pub(crate) retained: bool,
    /// Rows that existed before this call and were atomically pruned.
    pub(crate) pruned_persisted: BTreeSet<BlockId48>,
    /// True when the supplied candidate itself did not fit and therefore was
    /// never persisted. This is deliberately distinct from stored removals.
    pub(crate) candidate_rejected_by_retention: bool,
    pub(crate) distinct_action_body_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeBlockStoreAuditV3 {
    pub(crate) block_rows: u64,
    pub(crate) fork_rows: u64,
    pub(crate) action_body_rows: u64,
    pub(crate) owner_rows: u64,
    pub(crate) distinct_action_body_bytes: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeBlockStoreRepairV3 {
    pub(crate) owner_rows_repaired: u64,
    pub(crate) owner_rows_removed: u64,
    pub(crate) refcount_rows_repaired: u64,
    pub(crate) orphan_rows_removed: u64,
}

/// Expensive, immutable output of verified V3 body canonicalization. Build it
/// before acquiring `block_store_persistence_lock`; the persistence phase only
/// scans small records and exact-compares/writes this prepared artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedNativeNoncanonicalBlockV3 {
    stored: StoredNativeBlockMetaV3,
    stored_bytes: Vec<u8>,
    action_body: EncodedNativeActionBodyV3,
}

fn decode_u64_be(bytes: &[u8], context: &'static str) -> Result<u64> {
    let bytes = <[u8; 8]>::try_from(bytes)
        .map_err(|_| anyhow!("{context} is not an exact u64 big-endian value"))?;
    Ok(u64::from_be_bytes(bytes))
}

fn increment_audit_counter(counter: &mut u64, context: &'static str) -> Result<()> {
    *counter = counter
        .checked_add(1)
        .ok_or_else(|| anyhow!("{context} overflow"))?;
    Ok(())
}

fn native_action_body_owner_key_v3(
    action_body_hash: ActionBodyHash48,
    block_hash: BlockId48,
) -> [u8; 96] {
    let mut key = [0u8; 96];
    key[..48].copy_from_slice(action_body_hash.as_bytes());
    key[48..].copy_from_slice(block_hash.as_bytes());
    key
}

fn decode_native_action_body_owner_key_v3(bytes: &[u8]) -> Result<(ActionBodyHash48, BlockId48)> {
    let bytes = <&[u8; 96]>::try_from(bytes)
        .map_err(|_| anyhow!("native V3 action-body owner key is not exactly 96 bytes"))?;
    let body_hash = ActionBodyHash48::try_from(&bytes[..48])
        .map_err(|err| anyhow!("invalid native V3 action-body owner hash: {err}"))?;
    let block_hash = BlockId48::try_from(&bytes[48..])
        .map_err(|err| anyhow!("invalid native V3 action-body owner block: {err}"))?;
    Ok((body_hash, block_hash))
}

fn native_noncanonical_fork_record_digest_v3(
    record: &NativeStoredNoncanonicalForkRecordV3,
) -> CheckpointDigest48 {
    let mut canonical = record.clone();
    canonical.record_digest = CheckpointDigest48::ZERO;
    CheckpointDigest48::new(crypto::hash384::blake2b_384_domain_hash(
        crypto::hash384::domains::NATIVE_NONCANONICAL_FORK_RECORD_V3,
        [canonical.encode().as_slice()],
    ))
}

fn native_noncanonical_fork_record_v3(
    stored: &StoredNativeBlockMetaV3,
    first_seen_sequence: u64,
) -> NativeStoredNoncanonicalForkRecordV3 {
    let mut record = NativeStoredNoncanonicalForkRecordV3 {
        schema_version: NATIVE_NONCANONICAL_FORK_RECORD_SCHEMA_V3,
        rules_hash: stored.rules_hash,
        block_hash: stored.hash,
        parent_hash: stored.parent_hash,
        height: stored.height,
        cumulative_work: stored.cumulative_work,
        body_hash: stored.body_hash,
        body_len: stored.body_len,
        action_body_hash: stored.action_body_hash,
        action_body_len: stored.action_body_len,
        first_seen_sequence,
        record_digest: CheckpointDigest48::ZERO,
    };
    record.record_digest = native_noncanonical_fork_record_digest_v3(&record);
    record
}

fn validate_native_noncanonical_fork_record_v3(
    record: &NativeStoredNoncanonicalForkRecordV3,
    stored: Option<&StoredNativeBlockMetaV3>,
) -> Result<()> {
    if record.schema_version != NATIVE_NONCANONICAL_FORK_RECORD_SCHEMA_V3
        || record.body_len == 0
        || record.body_len > u64::try_from(MAX_NATIVE_BLOCK_META_BYTES).unwrap_or(u64::MAX)
        || record.action_body_len == 0
        || record.action_body_len
            > u64::try_from(MAX_NATIVE_ACTION_BODY_V3_BYTES).unwrap_or(u64::MAX)
        || record.record_digest != native_noncanonical_fork_record_digest_v3(record)
    {
        return Err(anyhow!(
            "native V3 noncanonical fork record schema/length/digest mismatch"
        ));
    }
    if let Some(stored) = stored {
        if stored.schema_version != NATIVE_STORED_BLOCK_META_SCHEMA_V3
            || record.rules_hash != stored.rules_hash
            || record.block_hash != stored.hash
            || record.parent_hash != stored.parent_hash
            || record.height != stored.height
            || record.cumulative_work != stored.cumulative_work
            || record.body_hash != stored.body_hash
            || record.body_len != stored.body_len
            || record.action_body_hash != stored.action_body_hash
            || record.action_body_len != stored.action_body_len
        {
            return Err(anyhow!(
                "native V3 noncanonical fork record does not bind its slim block row"
            ));
        }
    }
    Ok(())
}

impl From<&NativeStoredNoncanonicalForkRecordV3> for NativeForkRetentionRecordV3 {
    fn from(record: &NativeStoredNoncanonicalForkRecordV3) -> Self {
        Self {
            block_hash: record.block_hash,
            parent_hash: record.parent_hash,
            height: record.height,
            cumulative_work: record.cumulative_work,
            action_body_hash: record.action_body_hash,
            action_body_len: record.action_body_len,
            first_seen_sequence: record.first_seen_sequence,
        }
    }
}

fn load_native_noncanonical_fork_records_v3(
    block_meta_tree: &sled::Tree,
    action_body_owner_tree: &sled::Tree,
    fork_tree: &sled::Tree,
) -> Result<
    BTreeMap<
        BlockId48,
        (
            NativeStoredNoncanonicalForkRecordV3,
            Vec<u8>,
            StoredNativeBlockMetaV3,
            Vec<u8>,
        ),
    >,
> {
    let mut records = BTreeMap::new();
    for row in fork_tree.iter() {
        let (key, value) = row.context("read native V3 noncanonical fork record")?;
        let block_hash = BlockId48::try_from(key.as_ref())
            .map_err(|err| anyhow!("invalid native V3 fork record key: {err}"))?;
        let record = decode_scale_exact::<NativeStoredNoncanonicalForkRecordV3>(
            value.as_ref(),
            "native V3 noncanonical fork record",
        )?;
        if record.block_hash != block_hash {
            return Err(anyhow!(
                "native V3 noncanonical fork key/value identity mismatch"
            ));
        }
        let stored_bytes = block_meta_tree
            .get(block_hash.as_ref())?
            .ok_or_else(|| anyhow!("native V3 fork record has no slim block row"))?;
        let stored = decode_scale_exact::<StoredNativeBlockMetaV3>(
            stored_bytes.as_ref(),
            "stored native V3 block metadata",
        )?;
        validate_native_noncanonical_fork_record_v3(&record, Some(&stored))?;
        let owner_key = native_action_body_owner_key_v3(stored.action_body_hash, stored.hash);
        if action_body_owner_tree.get(owner_key)?.as_deref() != Some(&[]) {
            return Err(anyhow!(
                "native V3 fork slim row has no exact action-body owner row"
            ));
        }
        if records
            .insert(
                block_hash,
                (record, value.to_vec(), stored, stored_bytes.to_vec()),
            )
            .is_some()
        {
            return Err(anyhow!("duplicate native V3 noncanonical fork record"));
        }
    }
    Ok(records)
}

pub(crate) fn load_native_block_meta_v3_from_content_store(
    block_meta_tree: &sled::Tree,
    action_body_tree: &sled::Tree,
    action_body_refcount_tree: &sled::Tree,
    action_body_owner_tree: &sled::Tree,
    block_hash: BlockId48,
) -> Result<Option<NativeBlockMetaV3>> {
    let Some(stored_bytes) = block_meta_tree.get(block_hash.as_ref())? else {
        return Ok(None);
    };
    let stored = decode_scale_exact::<StoredNativeBlockMetaV3>(
        stored_bytes.as_ref(),
        "stored native V3 block metadata",
    )?;
    if stored.hash != block_hash {
        return Err(anyhow!(
            "stored native V3 block key/value identity mismatch"
        ));
    }
    let owner_key = native_action_body_owner_key_v3(stored.action_body_hash, stored.hash);
    let owner = action_body_owner_tree
        .get(owner_key)?
        .ok_or_else(|| anyhow!("stored native V3 block action body has no owner row"))?;
    if !owner.is_empty() {
        return Err(anyhow!(
            "stored native V3 block action-body owner value is not empty"
        ));
    }
    let refcount = action_body_refcount_tree
        .get(stored.action_body_hash.as_ref())?
        .ok_or_else(|| anyhow!("stored native V3 block action body has no refcount"))?;
    if decode_u64_be(refcount.as_ref(), "native V3 action-body refcount")? == 0 {
        return Err(anyhow!("stored native V3 action-body refcount is zero"));
    }
    let body = action_body_tree
        .get(stored.action_body_hash.as_ref())?
        .ok_or_else(|| anyhow!("stored native V3 block action body is missing"))?;
    let restored = restore_native_block_meta_v3(&stored, body.as_ref())?;
    if restored.hash != block_hash {
        return Err(anyhow!("restored native V3 block identity mismatch"));
    }
    Ok(Some(restored))
}

/// Resolve one WAL action reference without decoding or allocating sibling
/// actions. The caller subsequently validates the referenced action's exact
/// length/hash and embedded `ActionId48` through the WAL preparation token.
pub(crate) fn resolve_native_reorg_wal_action_ref_v3(
    block_meta_tree: &sled::Tree,
    action_body_tree: &sled::Tree,
    action_body_owner_tree: &sled::Tree,
    reference: &NativeReorgWalActionRefV3,
) -> Result<Vec<u8>> {
    let stored_bytes = block_meta_tree
        .get(reference.block_hash.as_ref())?
        .ok_or_else(|| anyhow!("native V3 reorg WAL action block is missing"))?;
    let stored = decode_scale_exact::<StoredNativeBlockMetaV3>(
        stored_bytes.as_ref(),
        "stored native V3 block metadata",
    )?;
    if stored.hash != reference.block_hash || stored.action_body_hash != reference.action_body_hash
    {
        return Err(anyhow!(
            "native V3 reorg WAL action reference does not bind its slim block row"
        ));
    }
    let owner_key = native_action_body_owner_key_v3(stored.action_body_hash, stored.hash);
    if action_body_owner_tree.get(owner_key)?.as_deref() != Some(&[]) {
        return Err(anyhow!(
            "native V3 reorg WAL action reference has no exact owner row"
        ));
    }
    let body = action_body_tree
        .get(stored.action_body_hash.as_ref())?
        .ok_or_else(|| anyhow!("native V3 reorg WAL action body is missing"))?;
    Ok(native_action_body_v3_action_at(body.as_ref(), reference.action_index)?.to_vec())
}

fn audit_native_action_body_owner_group_v3(
    action_body_tree: &sled::Tree,
    action_body_refcount_tree: &sled::Tree,
    body_hash: ActionBodyHash48,
    owner_count: u64,
) -> Result<u64> {
    if owner_count == 0 {
        return Err(anyhow!("native V3 action-body owner group is empty"));
    }
    let refcount = action_body_refcount_tree
        .get(body_hash.as_ref())?
        .ok_or_else(|| anyhow!("native V3 action-body owner group has no refcount"))?;
    let refcount = decode_u64_be(refcount.as_ref(), "native V3 action-body refcount")?;
    if refcount != owner_count {
        return Err(anyhow!(
            "native V3 action-body owner/refcount mismatch: owners {owner_count}, refcount {refcount}"
        ));
    }
    let body = action_body_tree
        .get(body_hash.as_ref())?
        .ok_or_else(|| anyhow!("native V3 action-body owner group has no blob"))?;
    u64::try_from(body.len()).map_err(|_| anyhow!("native V3 action-body blob length exceeds u64"))
}

/// Stream and cross-check the complete V3 content-addressed namespace.
///
/// The audit owns at most one decoded action body and one reconstructed full
/// body at a time. It proves the exact bijection
/// `slim row <-> owner row`, owner cardinality equals the persisted refcount,
/// and every blob/refcount is referenced. Every slim row is reconstructed so
/// its action root and full `BodyHash48` are revalidated before authority.
#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_native_block_content_store_v3(
    block_meta_tree: &sled::Tree,
    action_body_tree: &sled::Tree,
    action_body_refcount_tree: &sled::Tree,
    action_body_owner_tree: &sled::Tree,
    fork_tree: &sled::Tree,
) -> Result<NativeBlockStoreAuditV3> {
    let mut block_rows = 0u64;
    for row in block_meta_tree.iter() {
        let (key, stored_bytes) = row.context("read native V3 slim block row")?;
        let block_hash = BlockId48::try_from(key.as_ref())
            .map_err(|err| anyhow!("invalid native V3 slim block key: {err}"))?;
        let stored = decode_scale_exact::<StoredNativeBlockMetaV3>(
            stored_bytes.as_ref(),
            "stored native V3 block metadata",
        )?;
        if stored.schema_version != NATIVE_STORED_BLOCK_META_SCHEMA_V3 || stored.hash != block_hash
        {
            return Err(anyhow!(
                "native V3 slim block schema/key/value identity mismatch"
            ));
        }
        let owner_key = native_action_body_owner_key_v3(stored.action_body_hash, block_hash);
        let owner = action_body_owner_tree
            .get(owner_key)?
            .ok_or_else(|| anyhow!("native V3 slim block has no action-body owner"))?;
        if !owner.is_empty() {
            return Err(anyhow!(
                "native V3 action-body owner value is not exactly empty"
            ));
        }
        let refcount = action_body_refcount_tree
            .get(stored.action_body_hash.as_ref())?
            .ok_or_else(|| anyhow!("native V3 slim block has no action-body refcount"))?;
        if decode_u64_be(refcount.as_ref(), "native V3 action-body refcount")? == 0 {
            return Err(anyhow!(
                "native V3 slim block has zero action-body refcount"
            ));
        }
        let action_body = action_body_tree
            .get(stored.action_body_hash.as_ref())?
            .ok_or_else(|| anyhow!("native V3 slim block has no action-body blob"))?;
        // This exact reconstruction validates action-body hash/length/count,
        // ActionRoot48, and the once-committed full BodyHash48/length.
        let restored = restore_native_block_meta_v3(&stored, action_body.as_ref())?;
        if restored.hash != block_hash {
            return Err(anyhow!("native V3 reconstructed block identity mismatch"));
        }
        block_rows = block_rows
            .checked_add(1)
            .ok_or_else(|| anyhow!("native V3 slim block row count overflow"))?;
    }

    let mut owner_rows = 0u64;
    let mut owner_body_groups = 0u64;
    let mut distinct_action_body_bytes = 0u64;
    let mut group_hash = None::<ActionBodyHash48>;
    let mut group_count = 0u64;
    for row in action_body_owner_tree.iter() {
        let (key, value) = row.context("read native V3 action-body owner row")?;
        if !value.is_empty() {
            return Err(anyhow!(
                "native V3 action-body owner value is not exactly empty"
            ));
        }
        let (body_hash, block_hash) = decode_native_action_body_owner_key_v3(key.as_ref())?;
        if group_hash != Some(body_hash) {
            if let Some(previous_hash) = group_hash {
                distinct_action_body_bytes = distinct_action_body_bytes
                    .checked_add(audit_native_action_body_owner_group_v3(
                        action_body_tree,
                        action_body_refcount_tree,
                        previous_hash,
                        group_count,
                    )?)
                    .ok_or_else(|| anyhow!("native V3 distinct action-body bytes overflow"))?;
                owner_body_groups = owner_body_groups
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("native V3 owner body-group count overflow"))?;
            }
            group_hash = Some(body_hash);
            group_count = 0;
        }
        let stored_bytes = block_meta_tree
            .get(block_hash.as_ref())?
            .ok_or_else(|| anyhow!("native V3 action-body owner has no slim block row"))?;
        let stored = decode_scale_exact::<StoredNativeBlockMetaV3>(
            stored_bytes.as_ref(),
            "stored native V3 block metadata",
        )?;
        if stored.hash != block_hash || stored.action_body_hash != body_hash {
            return Err(anyhow!(
                "native V3 action-body owner does not bind its slim block row"
            ));
        }
        group_count = group_count
            .checked_add(1)
            .ok_or_else(|| anyhow!("native V3 action-body owner group count overflow"))?;
        owner_rows = owner_rows
            .checked_add(1)
            .ok_or_else(|| anyhow!("native V3 action-body owner row count overflow"))?;
    }
    if let Some(previous_hash) = group_hash {
        distinct_action_body_bytes = distinct_action_body_bytes
            .checked_add(audit_native_action_body_owner_group_v3(
                action_body_tree,
                action_body_refcount_tree,
                previous_hash,
                group_count,
            )?)
            .ok_or_else(|| anyhow!("native V3 distinct action-body bytes overflow"))?;
        owner_body_groups = owner_body_groups
            .checked_add(1)
            .ok_or_else(|| anyhow!("native V3 owner body-group count overflow"))?;
    }
    if owner_rows != block_rows {
        return Err(anyhow!(
            "native V3 slim/owner row-count mismatch: slim {block_rows}, owners {owner_rows}"
        ));
    }

    let mut refcount_rows = 0u64;
    for row in action_body_refcount_tree.iter() {
        let (key, value) = row.context("read native V3 action-body refcount row")?;
        let body_hash = ActionBodyHash48::try_from(key.as_ref())
            .map_err(|err| anyhow!("invalid native V3 action-body refcount key: {err}"))?;
        if decode_u64_be(value.as_ref(), "native V3 action-body refcount")? == 0 {
            return Err(anyhow!("native V3 action-body refcount is zero"));
        }
        if action_body_tree.get(body_hash.as_ref())?.is_none()
            || action_body_owner_tree
                .scan_prefix(body_hash.as_ref())
                .next()
                .transpose()?
                .is_none()
        {
            return Err(anyhow!(
                "native V3 action-body refcount has no blob or owner"
            ));
        }
        refcount_rows = refcount_rows
            .checked_add(1)
            .ok_or_else(|| anyhow!("native V3 action-body refcount row count overflow"))?;
    }

    let mut action_body_rows = 0u64;
    for row in action_body_tree.iter() {
        let (key, body) = row.context("read native V3 action-body blob row")?;
        let body_hash = ActionBodyHash48::try_from(key.as_ref())
            .map_err(|err| anyhow!("invalid native V3 action-body blob key: {err}"))?;
        let observed_hash = ActionBodyHash48::new(crypto::hash384::blake2b_384_domain_hash(
            crypto::hash384::domains::NATIVE_ACTION_BODY_V3,
            [body.as_ref()],
        ));
        if observed_hash != body_hash {
            return Err(anyhow!("native V3 action-body blob hash mismatch"));
        }
        // The bounded preflight plus exact SCALE decoder rejects short,
        // noncanonical, and trailing-byte encodings before this row is used.
        decode_native_action_body_v3(body.as_ref())?;
        if action_body_refcount_tree.get(body_hash.as_ref())?.is_none()
            || action_body_owner_tree
                .scan_prefix(body_hash.as_ref())
                .next()
                .transpose()?
                .is_none()
        {
            return Err(anyhow!("native V3 action-body blob is orphaned"));
        }
        action_body_rows = action_body_rows
            .checked_add(1)
            .ok_or_else(|| anyhow!("native V3 action-body blob row count overflow"))?;
    }
    if action_body_rows != owner_body_groups || refcount_rows != owner_body_groups {
        return Err(anyhow!(
            "native V3 body/refcount/owner-group row-count mismatch: bodies {action_body_rows}, refcounts {refcount_rows}, owner_groups {owner_body_groups}"
        ));
    }

    let mut fork_rows = 0u64;
    for row in fork_tree.iter() {
        let (key, value) = row.context("read native V3 noncanonical fork record")?;
        let block_hash = BlockId48::try_from(key.as_ref())
            .map_err(|err| anyhow!("invalid native V3 fork record key: {err}"))?;
        let record = decode_scale_exact::<NativeStoredNoncanonicalForkRecordV3>(
            value.as_ref(),
            "native V3 noncanonical fork record",
        )?;
        let stored_bytes = block_meta_tree
            .get(block_hash.as_ref())?
            .ok_or_else(|| anyhow!("native V3 fork record has no slim block row"))?;
        let stored = decode_scale_exact::<StoredNativeBlockMetaV3>(
            stored_bytes.as_ref(),
            "stored native V3 block metadata",
        )?;
        if record.block_hash != block_hash {
            return Err(anyhow!(
                "native V3 noncanonical fork key/value identity mismatch"
            ));
        }
        validate_native_noncanonical_fork_record_v3(&record, Some(&stored))?;
        fork_rows = fork_rows
            .checked_add(1)
            .ok_or_else(|| anyhow!("native V3 fork row count overflow"))?;
    }

    Ok(NativeBlockStoreAuditV3 {
        block_rows,
        fork_rows,
        action_body_rows,
        owner_rows,
        distinct_action_body_bytes,
    })
}

/// Rebuild only derivable V3 owner/refcount rows and delete exact unreferenced
/// blobs. The marker makes interruption fail closed and the passes are
/// idempotent, so startup can resume after a crash without loading the
/// namespace into memory.
///
/// Callers must hold the block-store persistence epoch and must not expose the
/// content store as authoritative until this function returns and a full audit
/// succeeds. Missing or hash-invalid referenced blobs are not repairable and
/// fail closed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn repair_native_block_content_store_v3(
    meta_tree: &sled::Tree,
    block_meta_tree: &sled::Tree,
    action_body_tree: &sled::Tree,
    action_body_refcount_tree: &sled::Tree,
    action_body_owner_tree: &sled::Tree,
    fork_tree: &sled::Tree,
) -> Result<NativeBlockStoreRepairV3> {
    meta_tree.insert(
        META_BLOCK_STORE_REPAIR_IN_PROGRESS_V3,
        BLOCK_STORE_REPAIR_MARKER_V3,
    )?;
    meta_tree
        .flush()
        .context("persist native V3 block-store repair marker")?;

    let mut work = NativeBlockStoreRepairV3::default();

    // First validate every authority-bearing slim/blob pair, then recreate its
    // one deterministic owner row. No digest-corrupt content is synthesized.
    for row in block_meta_tree.iter() {
        let (key, stored_bytes) = row.context("read native V3 slim row during repair")?;
        let block_hash = BlockId48::try_from(key.as_ref())
            .map_err(|err| anyhow!("invalid native V3 slim key during repair: {err}"))?;
        let stored = decode_scale_exact::<StoredNativeBlockMetaV3>(
            stored_bytes.as_ref(),
            "stored native V3 block metadata",
        )?;
        if stored.schema_version != NATIVE_STORED_BLOCK_META_SCHEMA_V3 || stored.hash != block_hash
        {
            return Err(anyhow!(
                "native V3 slim schema/key/value mismatch during repair"
            ));
        }
        let body = action_body_tree
            .get(stored.action_body_hash.as_ref())?
            .ok_or_else(|| anyhow!("native V3 repair cannot recover a missing referenced blob"))?;
        restore_native_block_meta_v3(&stored, body.as_ref())?;
        let owner_key = native_action_body_owner_key_v3(stored.action_body_hash, block_hash);
        if action_body_owner_tree.get(owner_key)?.as_deref() != Some(&[]) {
            action_body_owner_tree.insert(owner_key, b"")?;
            increment_audit_counter(
                &mut work.owner_rows_repaired,
                "native V3 repaired-owner count",
            )?;
        }
    }

    // Remove malformed or unbound owner rows. Valid rows are normalized to an
    // exact empty value, the sole owner-value codec.
    for row in action_body_owner_tree.iter() {
        let (key, value) = row.context("read native V3 owner row during repair")?;
        let binding = decode_native_action_body_owner_key_v3(key.as_ref()).ok();
        let valid = if let Some((body_hash, block_hash)) = binding {
            match block_meta_tree.get(block_hash.as_ref())? {
                Some(stored_bytes) => {
                    let stored = decode_scale_exact::<StoredNativeBlockMetaV3>(
                        stored_bytes.as_ref(),
                        "stored native V3 block metadata",
                    )?;
                    stored.hash == block_hash && stored.action_body_hash == body_hash
                }
                None => false,
            }
        } else {
            false
        };
        if !valid {
            action_body_owner_tree.remove(key.as_ref())?;
            increment_audit_counter(
                &mut work.owner_rows_removed,
                "native V3 removed-owner count",
            )?;
        } else if !value.is_empty() {
            action_body_owner_tree.insert(key.as_ref(), b"")?;
            increment_audit_counter(
                &mut work.owner_rows_repaired,
                "native V3 repaired-owner count",
            )?;
        }
    }

    // Recompute each refcount from the sorted reverse-owner index using only
    // one group counter. Validate the referenced blob before publishing it.
    let mut group_hash = None::<ActionBodyHash48>;
    let mut group_count = 0u64;
    let write_group_refcount = |body_hash: ActionBodyHash48,
                                owner_count: u64,
                                work: &mut NativeBlockStoreRepairV3|
     -> Result<()> {
        let body = action_body_tree
            .get(body_hash.as_ref())?
            .ok_or_else(|| anyhow!("native V3 repair cannot recover a missing owned blob"))?;
        let observed_hash = ActionBodyHash48::new(crypto::hash384::blake2b_384_domain_hash(
            crypto::hash384::domains::NATIVE_ACTION_BODY_V3,
            [body.as_ref()],
        ));
        if observed_hash != body_hash {
            return Err(anyhow!(
                "native V3 repair refuses an action-body hash mismatch"
            ));
        }
        decode_native_action_body_v3(body.as_ref())?;
        let expected = owner_count.to_be_bytes();
        if action_body_refcount_tree
            .get(body_hash.as_ref())?
            .as_deref()
            != Some(expected.as_slice())
        {
            action_body_refcount_tree.insert(body_hash.as_ref(), expected.as_slice())?;
            increment_audit_counter(
                &mut work.refcount_rows_repaired,
                "native V3 repaired-refcount count",
            )?;
        }
        Ok(())
    };
    for row in action_body_owner_tree.iter() {
        let (key, value) = row.context("read native V3 owner row for refcount repair")?;
        if !value.is_empty() {
            return Err(anyhow!(
                "native V3 owner value changed during refcount repair"
            ));
        }
        let (body_hash, _) = decode_native_action_body_owner_key_v3(key.as_ref())?;
        if group_hash != Some(body_hash) {
            if let Some(previous_hash) = group_hash {
                write_group_refcount(previous_hash, group_count, &mut work)?;
            }
            group_hash = Some(body_hash);
            group_count = 0;
        }
        group_count = group_count
            .checked_add(1)
            .ok_or_else(|| anyhow!("native V3 repaired owner group count overflow"))?;
    }
    if let Some(previous_hash) = group_hash {
        write_group_refcount(previous_hash, group_count, &mut work)?;
    }

    // Any refcount/body without an owner is non-authoritative garbage. Delete
    // it deterministically; referenced malformed rows have already failed.
    for row in action_body_refcount_tree.iter() {
        let (key, _) = row.context("read native V3 refcount row during orphan repair")?;
        let body_hash = ActionBodyHash48::try_from(key.as_ref()).ok();
        let has_owner = if let Some(body_hash) = body_hash {
            action_body_owner_tree
                .scan_prefix(body_hash.as_ref())
                .next()
                .transpose()?
                .is_some()
        } else {
            false
        };
        if !has_owner {
            action_body_refcount_tree.remove(key.as_ref())?;
            increment_audit_counter(
                &mut work.orphan_rows_removed,
                "native V3 removed-orphan count",
            )?;
        }
    }
    for row in action_body_tree.iter() {
        let (key, _) = row.context("read native V3 body row during orphan repair")?;
        let body_hash = ActionBodyHash48::try_from(key.as_ref()).ok();
        let has_owner = if let Some(body_hash) = body_hash {
            action_body_owner_tree
                .scan_prefix(body_hash.as_ref())
                .next()
                .transpose()?
                .is_some()
        } else {
            false
        };
        if !has_owner {
            action_body_tree.remove(key.as_ref())?;
            if let Some(body_hash) = body_hash {
                action_body_refcount_tree.remove(body_hash.as_ref())?;
            }
            increment_audit_counter(
                &mut work.orphan_rows_removed,
                "native V3 removed-orphan count",
            )?;
        }
    }

    meta_tree
        .flush()
        .context("persist native V3 block-store repair passes")?;
    audit_native_block_content_store_v3(
        block_meta_tree,
        action_body_tree,
        action_body_refcount_tree,
        action_body_owner_tree,
        fork_tree,
    )?;
    meta_tree.remove(META_BLOCK_STORE_REPAIR_IN_PROGRESS_V3)?;
    meta_tree
        .flush()
        .context("clear native V3 block-store repair marker")?;
    Ok(work)
}

fn map_refcount_transaction_error(
    err: sled::transaction::TransactionError<String>,
) -> anyhow::Error {
    anyhow!("atomic native V3 content-addressed block update failed: {err}")
}

/// Canonicalize and hash one already-verified V3 body outside every persistence
/// epoch. Callers that already own the exact transport body should use the
/// sibling prepared-body constructor so its full bincode serialization/hash is
/// reused rather than recomputed.
pub(crate) fn prepare_verified_noncanonical_block_v3(
    meta: &NativeBlockMetaV3,
) -> Result<PreparedNativeNoncanonicalBlockV3> {
    let (stored, action_body, canonical_body) = store_native_block_meta_v3(meta)?;
    let canonical_body_hash = canonical_body.hash();
    let canonical_body_len = canonical_body.len();
    // Only the typed identity enters sled; transport retains/shares the full
    // canonical body when needed. Drop this large allocation before the epoch.
    drop(canonical_body);
    if stored.body_hash != canonical_body_hash || stored.body_len != canonical_body_len {
        return Err(anyhow!(
            "native V3 slim row lost its once-computed full body binding"
        ));
    }
    let stored_bytes = stored.encode();
    Ok(PreparedNativeNoncanonicalBlockV3 {
        stored,
        stored_bytes,
        action_body,
    })
}

/// Prepare from the exact canonical body already produced by transport or
/// verification. This reuses the full serialization and its `BodyHash48`
/// binding while still independently checking every fixed field and action
/// identity through the storage codec.
pub(crate) fn prepare_verified_noncanonical_block_v3_with_canonical_body(
    meta: &NativeBlockMetaV3,
    canonical_body: &EncodedNativeBlockBodyV3,
) -> Result<PreparedNativeNoncanonicalBlockV3> {
    let (stored, action_body) =
        store_native_block_meta_v3_with_canonical_body(meta, canonical_body)?;
    let stored_bytes = stored.encode();
    Ok(PreparedNativeNoncanonicalBlockV3 {
        stored,
        stored_bytes,
        action_body,
    })
}

/// Persist one prepared noncanonical V3 block and apply the complete bounded
/// retention plan in one transaction.
///
/// Preparation must finish before the caller acquires
/// `block_store_persistence_lock`. No canonical/state guard may be held across
/// this transaction or the following durability barrier. `protected_tips`
/// contains any branch whose complete ancestry must survive this exact
/// decision (for example, an imminent winning promotion).
#[allow(clippy::too_many_arguments)]
pub(crate) fn persist_prepared_verified_noncanonical_block_v3(
    meta_tree: &sled::Tree,
    block_meta_tree: &sled::Tree,
    action_body_tree: &sled::Tree,
    action_body_refcount_tree: &sled::Tree,
    action_body_owner_tree: &sled::Tree,
    fork_tree: &sled::Tree,
    canonical_hashes: &BTreeMap<u64, BlockId48>,
    canonical_best_height: u64,
    protected_tips: &BTreeSet<BlockId48>,
    prepared: &PreparedNativeNoncanonicalBlockV3,
) -> Result<NativeBlockStorePersistOutcomeV3> {
    let stored = &prepared.stored;
    let stored_bytes = &prepared.stored_bytes;
    let action_body = &prepared.action_body;
    let current = load_native_noncanonical_fork_records_v3(
        block_meta_tree,
        action_body_owner_tree,
        fork_tree,
    )?;
    let current_sequence_bytes = meta_tree
        .get(META_NONCANONICAL_FORK_NEXT_SEQUENCE_V3)?
        .map(|bytes| bytes.to_vec());
    let current_sequence = current_sequence_bytes
        .as_deref()
        .map(|bytes| decode_u64_be(bytes, "native V3 fork insertion sequence"))
        .transpose()?
        .unwrap_or(0);

    let existing = current.get(&stored.hash);
    let candidate_record = if let Some((record, _, existing_stored, _)) = existing {
        validate_native_noncanonical_fork_record_v3(record, Some(stored))?;
        if existing_stored != stored {
            return Err(anyhow!(
                "native V3 block identity collides with different slim metadata"
            ));
        }
        record.clone()
    } else {
        native_noncanonical_fork_record_v3(stored, current_sequence)
    };

    let mut all_records = current
        .values()
        .map(|(record, _, _, _)| NativeForkRetentionRecordV3::from(record))
        .collect::<Vec<_>>();
    if existing.is_none() {
        all_records.push(NativeForkRetentionRecordV3::from(&candidate_record));
    }
    let NativeForkRetentionPlanV3 {
        retained,
        pruned,
        distinct_action_body_bytes,
        ..
    } = plan_native_noncanonical_fork_retention_v3(
        all_records,
        canonical_hashes,
        canonical_best_height,
        protected_tips,
        MAX_NATIVE_NONCANONICAL_FORK_DEPTH,
        MAX_NATIVE_NONCANONICAL_FORK_BLOCKS,
        MAX_NATIVE_NONCANONICAL_FORK_BYTES,
    )?;
    let retain_candidate = retained.contains(&stored.hash);
    let candidate_is_new = existing.is_none() && retain_candidate;
    let candidate_fork_bytes = candidate_record.encode();
    let next_sequence = candidate_is_new
        .then(|| {
            current_sequence
                .checked_add(1)
                .ok_or_else(|| anyhow!("native V3 fork insertion sequence overflow"))
        })
        .transpose()?;

    let pruned_existing = pruned
        .iter()
        .filter_map(|hash| current.get(hash).map(|row| (*hash, row.clone())))
        .collect::<Vec<_>>();
    let pruned_persisted = pruned_existing
        .iter()
        .map(|(hash, _)| *hash)
        .collect::<BTreeSet<_>>();
    let candidate_block_row_bytes = block_meta_tree
        .get(stored.hash.as_ref())?
        .map(|bytes| bytes.to_vec());
    let candidate_block_row_exists = candidate_block_row_bytes.is_some();
    let candidate_owner_key = native_action_body_owner_key_v3(stored.action_body_hash, stored.hash);
    let candidate_owner_bytes = action_body_owner_tree
        .get(candidate_owner_key)?
        .map(|bytes| bytes.to_vec());
    if candidate_block_row_exists {
        if candidate_block_row_bytes.as_deref() != Some(stored_bytes.as_slice())
            || candidate_owner_bytes.as_deref() != Some(&[])
        {
            return Err(anyhow!(
                "native V3 preexisting slim row/owner binding mismatch"
            ));
        }
    } else if candidate_owner_bytes.is_some() {
        return Err(anyhow!(
            "native V3 action-body owner exists without its slim row"
        ));
    }
    let mut refcount_deltas = BTreeMap::<ActionBodyHash48, i64>::new();
    if candidate_is_new && !candidate_block_row_exists {
        *refcount_deltas.entry(stored.action_body_hash).or_default() += 1;
    }
    for (_, (record, _, _, _)) in &pruned_existing {
        *refcount_deltas.entry(record.action_body_hash).or_default() -= 1;
    }

    let transaction_result: sled::transaction::TransactionResult<(), String> = (
        meta_tree,
        block_meta_tree,
        action_body_tree,
        action_body_refcount_tree,
        action_body_owner_tree,
        fork_tree,
    )
        .transaction(
            |(
                meta_tree,
                block_meta_tree,
                action_body_tree,
                action_body_refcount_tree,
                action_body_owner_tree,
                fork_tree,
            )| {
                let abort =
                    |message: &str| ConflictableTransactionError::Abort(message.to_string());
                if meta_tree
                    .get(META_NONCANONICAL_FORK_NEXT_SEQUENCE_V3)?
                    .map(|bytes| bytes.to_vec())
                    != current_sequence_bytes
                {
                    return Err(abort("native V3 fork insertion sequence changed"));
                }
                if block_meta_tree
                    .get(stored.hash.as_ref())?
                    .map(|bytes| bytes.to_vec())
                    != candidate_block_row_bytes
                    || action_body_owner_tree
                        .get(candidate_owner_key.as_slice())?
                        .map(|bytes| bytes.to_vec())
                        != candidate_owner_bytes
                {
                    return Err(abort("native V3 candidate slim row/owner changed"));
                }

                for (hash, (record, expected_fork, _, expected_stored)) in &pruned_existing {
                    let owner_key = native_action_body_owner_key_v3(record.action_body_hash, *hash);
                    if fork_tree.get(hash.as_ref())?.as_deref() != Some(expected_fork.as_slice())
                        || block_meta_tree.get(hash.as_ref())?.as_deref()
                            != Some(expected_stored.as_slice())
                        || action_body_owner_tree.get(owner_key.as_slice())?.as_deref() != Some(&[])
                    {
                        return Err(abort("native V3 fork rows changed before retention prune"));
                    }
                    fork_tree.remove(hash.as_bytes().to_vec())?;
                    block_meta_tree.remove(hash.as_bytes().to_vec())?;
                    action_body_owner_tree.remove(owner_key.as_slice())?;
                }

                if let Some(next_sequence) = next_sequence {
                    match block_meta_tree.get(stored.hash.as_ref())? {
                        Some(observed) if observed.as_ref() == stored_bytes.as_slice() => {}
                        Some(_) => return Err(abort("native V3 block slim row collision")),
                        None => {
                            block_meta_tree
                                .insert(stored.hash.as_bytes().to_vec(), stored_bytes.as_slice())?;
                            action_body_owner_tree.insert(candidate_owner_key.as_slice(), &[])?;
                        }
                    }
                    match fork_tree.get(stored.hash.as_ref())? {
                        Some(observed) if observed.as_ref() == candidate_fork_bytes.as_slice() => {}
                        Some(_) => return Err(abort("native V3 fork record collision")),
                        None => {
                            fork_tree.insert(
                                stored.hash.as_bytes().to_vec(),
                                candidate_fork_bytes.clone(),
                            )?;
                        }
                    }
                    meta_tree.insert(
                        META_NONCANONICAL_FORK_NEXT_SEQUENCE_V3.to_vec(),
                        next_sequence.to_be_bytes().to_vec(),
                    )?;
                }

                if retain_candidate {
                    let observed_body = action_body_tree.get(action_body.hash.as_ref())?;
                    match observed_body {
                        Some(bytes) if bytes.as_ref() == action_body.bytes.as_slice() => {}
                        Some(_) => return Err(abort("native V3 action-body hash collision")),
                        None if candidate_is_new && !candidate_block_row_exists => {}
                        None => return Err(abort("native V3 referenced action body is missing")),
                    }
                    if !candidate_is_new || candidate_block_row_exists {
                        let observed_refcount = action_body_refcount_tree
                            .get(action_body.hash.as_ref())?
                            .ok_or_else(|| {
                                abort("native V3 referenced action-body refcount is missing")
                            })?;
                        if decode_u64_be(
                            observed_refcount.as_ref(),
                            "native V3 action-body refcount",
                        )
                        .map_err(|err| abort(&err.to_string()))?
                            == 0
                        {
                            return Err(abort("native V3 referenced action-body refcount is zero"));
                        }
                    }
                }

                for (body_hash, delta) in &refcount_deltas {
                    if *delta == 0 {
                        continue;
                    }
                    let observed_refcount = action_body_refcount_tree
                        .get(body_hash.as_ref())?
                        .map(|bytes| {
                            decode_u64_be(bytes.as_ref(), "native V3 action-body refcount")
                                .map_err(|err| abort(&err.to_string()))
                        })
                        .transpose()?;
                    let next_refcount = if *delta > 0 {
                        observed_refcount
                            .unwrap_or(0)
                            .checked_add(u64::try_from(*delta).map_err(|_| {
                                abort("native V3 positive refcount delta exceeds u64")
                            })?)
                            .ok_or_else(|| abort("native V3 action-body refcount overflow"))?
                    } else {
                        let decrement = delta.unsigned_abs();
                        observed_refcount
                            .ok_or_else(|| abort("native V3 action-body refcount is missing"))?
                            .checked_sub(decrement)
                            .ok_or_else(|| abort("native V3 action-body refcount underflow"))?
                    };
                    let observed_body = action_body_tree.get(body_hash.as_ref())?;
                    if *body_hash == action_body.hash {
                        match &observed_body {
                            Some(bytes) if bytes.as_ref() == action_body.bytes.as_slice() => {}
                            Some(_) => return Err(abort("native V3 action-body hash collision")),
                            None if observed_refcount.unwrap_or(0) == 0 && next_refcount > 0 => {
                                action_body_tree.insert(
                                    body_hash.as_bytes().to_vec(),
                                    action_body.bytes.as_slice(),
                                )?;
                            }
                            None => {
                                return Err(abort("native V3 referenced action body is missing"));
                            }
                        }
                    } else if observed_body.is_none() {
                        return Err(abort("native V3 referenced action body is missing"));
                    }
                    if next_refcount == 0 {
                        action_body_refcount_tree.remove(body_hash.as_bytes().to_vec())?;
                        action_body_tree.remove(body_hash.as_bytes().to_vec())?;
                    } else {
                        action_body_refcount_tree.insert(
                            body_hash.as_bytes().to_vec(),
                            next_refcount.to_be_bytes().to_vec(),
                        )?;
                    }
                }
                Ok(())
            },
        );
    transaction_result.map_err(map_refcount_transaction_error)?;

    Ok(NativeBlockStorePersistOutcomeV3 {
        retained: retain_candidate,
        pruned_persisted,
        candidate_rejected_by_retention: !retain_candidate,
        distinct_action_body_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_id(value: u64) -> BlockId48 {
        let mut bytes = [0u8; 48];
        bytes[40..].copy_from_slice(&value.to_be_bytes());
        BlockId48::new(bytes)
    }

    fn work(value: u64) -> Work64 {
        let mut bytes = [0u8; 64];
        bytes[56..].copy_from_slice(&value.to_be_bytes());
        Work64::new(bytes)
    }

    fn meta(id: u64, parent: u64, height: u64) -> NativeBlockMetaV3 {
        NativeBlockMetaV3 {
            chain_id: [0x11; 32],
            rules_hash: RulesHash48::new([0x22; 48]),
            height,
            hash: block_id(id),
            parent_hash: block_id(parent),
            state_root: StateRoot48::new([0x31; 48]),
            kernel_root: KernelRoot48::new([0x32; 48]),
            nullifier_root: NullifierAccumulatorRoot48::new([0x33; 48]),
            proof_commitment: ProofCommitment48::new([0x38; 48]),
            extrinsics_root: native_action_root_v3(&[]).expect("empty action root"),
            tx_statements_commitment: TransactionStatementsCommitment48::new([0x39; 48]),
            version_commitment: VersionCommitment48::new([0x3a; 48]),
            fee_commitment: FeeCommitment48::new([0x3b; 48]),
            message_root: BridgeMessageRoot48::new([0x34; 48]),
            message_count: 0,
            header_mmr_root: HeaderMmrHash48::new([0x35; 48]),
            header_mmr_len: height + 1,
            timestamp_ms: height,
            pow_bits: 0x207f_ffff,
            nonce: [0u8; 32],
            work_hash: WorkHash48::new([0x36; 48]),
            cumulative_work: work(height),
            supply_digest: 0,
            tx_count: 0,
            action_bytes: Vec::new(),
            da_root: DaRoot48::new([0x37; 48]),
            da_chunk_size: MIN_NATIVE_DA_CHUNK_SIZE,
            da_sample_count: DEFAULT_DA_SAMPLE_COUNT,
            da_blob_len: 0,
            da_chunk_count: 0,
        }
    }

    struct TestTrees {
        db: sled::Db,
        meta: sled::Tree,
        blocks: sled::Tree,
        bodies: sled::Tree,
        refcounts: sled::Tree,
        owners: sled::Tree,
        forks: sled::Tree,
    }

    fn open_test_trees(path: &Path) -> TestTrees {
        let db = sled::open(path).expect("open test sled");
        let meta = db.open_tree("meta").expect("meta tree");
        let blocks = db.open_tree(NATIVE_BLOCK_META_TREE_V3).expect("block tree");
        let bodies = db.open_tree(NATIVE_ACTION_BODY_TREE_V3).expect("body tree");
        let refcounts = db
            .open_tree(NATIVE_ACTION_BODY_REFCOUNT_TREE_V3)
            .expect("refcount tree");
        let owners = db
            .open_tree(NATIVE_ACTION_BODY_OWNER_TREE_V3)
            .expect("owner tree");
        let forks = db
            .open_tree(NATIVE_NONCANONICAL_FORK_TREE_V3)
            .expect("fork tree");
        TestTrees {
            db,
            meta,
            blocks,
            bodies,
            refcounts,
            owners,
            forks,
        }
    }

    fn persist(
        trees: &TestTrees,
        meta: &NativeBlockMetaV3,
    ) -> Result<NativeBlockStorePersistOutcomeV3> {
        let prepared = prepare_verified_noncanonical_block_v3(meta)?;
        persist_prepared_verified_noncanonical_block_v3(
            &trees.meta,
            &trees.blocks,
            &trees.bodies,
            &trees.refcounts,
            &trees.owners,
            &trees.forks,
            &BTreeMap::from([(0, block_id(0))]),
            0,
            &BTreeSet::new(),
            &prepared,
        )
    }

    #[test]
    fn same_action_body_is_deduplicated_refcounted_and_exact_after_restart() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let first = meta(1, 0, 1);
        let second = meta(2, 0, 1);
        let action_body_hash;
        {
            let trees = open_test_trees(tmp.path());
            let first_outcome = persist(&trees, &first).expect("persist first sibling");
            let second_outcome = persist(&trees, &second).expect("persist second sibling");
            assert!(first_outcome.retained && second_outcome.retained);
            assert_eq!(trees.blocks.len(), 2);
            assert_eq!(trees.forks.len(), 2);
            assert_eq!(
                trees.bodies.len(),
                1,
                "same action body must be stored once"
            );
            assert_eq!(trees.refcounts.len(), 1);
            assert_eq!(trees.owners.len(), 2);
            action_body_hash = store_native_block_meta_v3(&first)
                .expect("encode first")
                .1
                .hash;
            let refcount = trees
                .refcounts
                .get(action_body_hash.as_ref())
                .expect("read refcount")
                .expect("refcount exists");
            assert_eq!(
                decode_u64_be(refcount.as_ref(), "test refcount").unwrap(),
                2
            );
            let audit = audit_native_block_content_store_v3(
                &trees.blocks,
                &trees.bodies,
                &trees.refcounts,
                &trees.owners,
                &trees.forks,
            )
            .expect("audit exact content store");
            assert_eq!(audit.block_rows, 2);
            assert_eq!(audit.fork_rows, 2);
            assert_eq!(audit.action_body_rows, 1);
            assert_eq!(audit.owner_rows, 2);
            trees.db.flush().expect("durability barrier");
        }
        {
            let trees = open_test_trees(tmp.path());
            assert_eq!(trees.bodies.len(), 1);
            let restored_first = load_native_block_meta_v3_from_content_store(
                &trees.blocks,
                &trees.bodies,
                &trees.refcounts,
                &trees.owners,
                first.hash,
            )
            .expect("load first")
            .expect("first exists");
            let restored_second = load_native_block_meta_v3_from_content_store(
                &trees.blocks,
                &trees.bodies,
                &trees.refcounts,
                &trees.owners,
                second.hash,
            )
            .expect("load second")
            .expect("second exists");
            assert_eq!(restored_first, first);
            assert_eq!(restored_second, second);
            assert!(trees
                .bodies
                .contains_key(action_body_hash.as_ref())
                .unwrap());
        }
    }

    #[test]
    fn transaction_failure_publishes_no_slim_fork_or_refcount_rows() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let trees = open_test_trees(tmp.path());
        let candidate = meta(1, 0, 1);
        let action_body_hash = store_native_block_meta_v3(&candidate)
            .expect("encode candidate")
            .1
            .hash;
        trees
            .bodies
            .insert(action_body_hash.as_ref(), b"corrupt-collision".as_slice())
            .expect("inject conflicting body row");
        let err = persist(&trees, &candidate).expect_err("body collision must abort transaction");
        assert!(err.to_string().contains("action-body hash collision"));
        assert!(trees.blocks.is_empty());
        assert!(trees.forks.is_empty());
        assert!(trees.refcounts.is_empty());
        assert!(trees.owners.is_empty());
        assert!(trees
            .meta
            .get(META_NONCANONICAL_FORK_NEXT_SEQUENCE_V3)
            .unwrap()
            .is_none());
        assert_eq!(
            trees.bodies.len(),
            1,
            "preexisting corrupt row is untouched"
        );
    }

    #[test]
    fn over_horizon_prune_removes_exact_rows_and_zero_refcount_blob_atomically() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let trees = open_test_trees(tmp.path());
        for height in 1..=MAX_NATIVE_NONCANONICAL_FORK_DEPTH {
            let outcome = persist(&trees, &meta(height, height - 1, height))
                .expect("persist in-horizon suffix block");
            assert!(outcome.retained);
        }
        assert_eq!(trees.blocks.len(), 128);
        assert_eq!(trees.forks.len(), 128);
        assert_eq!(trees.bodies.len(), 1);
        assert_eq!(trees.owners.len(), 128);
        let refcount = trees.refcounts.iter().next().unwrap().unwrap().1;
        assert_eq!(
            decode_u64_be(refcount.as_ref(), "test refcount").unwrap(),
            128
        );

        let outcome = persist(&trees, &meta(129, 128, 129))
            .expect("unprotected over-horizon branch is pruned atomically");
        assert!(!outcome.retained);
        assert!(outcome.candidate_rejected_by_retention);
        assert_eq!(outcome.pruned_persisted.len(), 128);
        assert!(trees.blocks.is_empty());
        assert!(trees.forks.is_empty());
        assert!(trees.refcounts.is_empty());
        assert!(trees.owners.is_empty());
        assert!(trees.bodies.is_empty());
    }

    #[test]
    fn audit_rejects_short_trailing_and_orphaned_content_rows() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let trees = open_test_trees(tmp.path());
        let candidate = meta(1, 0, 1);
        persist(&trees, &candidate).expect("persist baseline");
        let stored_bytes = trees
            .blocks
            .get(candidate.hash.as_ref())
            .unwrap()
            .unwrap()
            .to_vec();
        let stored = decode_scale_exact::<StoredNativeBlockMetaV3>(
            &stored_bytes,
            "test stored native V3 block metadata",
        )
        .unwrap();
        let fork_bytes = trees
            .forks
            .get(candidate.hash.as_ref())
            .unwrap()
            .unwrap()
            .to_vec();
        let body_bytes = trees
            .bodies
            .get(stored.action_body_hash.as_ref())
            .unwrap()
            .unwrap()
            .to_vec();
        let refcount_bytes = trees
            .refcounts
            .get(stored.action_body_hash.as_ref())
            .unwrap()
            .unwrap()
            .to_vec();
        let owner_key = native_action_body_owner_key_v3(stored.action_body_hash, stored.hash);

        let mut trailing = stored_bytes.clone();
        trailing.push(0);
        trees
            .blocks
            .insert(candidate.hash.as_ref(), trailing)
            .unwrap();
        assert!(audit_native_block_content_store_v3(
            &trees.blocks,
            &trees.bodies,
            &trees.refcounts,
            &trees.owners,
            &trees.forks,
        )
        .is_err());
        trees
            .blocks
            .insert(candidate.hash.as_ref(), stored_bytes.as_slice())
            .unwrap();

        let mut trailing = fork_bytes.clone();
        trailing.push(0);
        trees
            .forks
            .insert(candidate.hash.as_ref(), trailing)
            .unwrap();
        assert!(audit_native_block_content_store_v3(
            &trees.blocks,
            &trees.bodies,
            &trees.refcounts,
            &trees.owners,
            &trees.forks,
        )
        .is_err());
        trees
            .forks
            .insert(candidate.hash.as_ref(), fork_bytes.as_slice())
            .unwrap();

        let mut trailing = refcount_bytes.clone();
        trailing.push(0);
        trees
            .refcounts
            .insert(stored.action_body_hash.as_ref(), trailing)
            .unwrap();
        assert!(audit_native_block_content_store_v3(
            &trees.blocks,
            &trees.bodies,
            &trees.refcounts,
            &trees.owners,
            &trees.forks,
        )
        .is_err());
        trees
            .refcounts
            .insert(stored.action_body_hash.as_ref(), refcount_bytes)
            .unwrap();

        trees.owners.insert(owner_key, b"x".as_slice()).unwrap();
        assert!(audit_native_block_content_store_v3(
            &trees.blocks,
            &trees.bodies,
            &trees.refcounts,
            &trees.owners,
            &trees.forks,
        )
        .is_err());
        trees.owners.insert(owner_key, b"".as_slice()).unwrap();
        trees.owners.insert([0u8; 95].as_slice(), b"").unwrap();
        assert!(audit_native_block_content_store_v3(
            &trees.blocks,
            &trees.bodies,
            &trees.refcounts,
            &trees.owners,
            &trees.forks,
        )
        .is_err());
        trees.owners.remove([0u8; 95].as_slice()).unwrap();

        let mut trailing_body = body_bytes.clone();
        trailing_body.push(0);
        assert!(decode_native_action_body_v3(&trailing_body).is_err());
        assert!(decode_native_action_body_v3(&[]).is_err());

        trees.owners.remove(owner_key).unwrap();
        assert!(audit_native_block_content_store_v3(
            &trees.blocks,
            &trees.bodies,
            &trees.refcounts,
            &trees.owners,
            &trees.forks,
        )
        .is_err());
    }

    #[test]
    fn interrupted_repair_resumes_streaming_and_restores_exact_refcounts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let trees = open_test_trees(tmp.path());
        let first = meta(1, 0, 1);
        let second = meta(2, 0, 1);
        persist(&trees, &first).expect("persist first sibling");
        persist(&trees, &second).expect("persist second sibling");
        let action_body_hash = store_native_block_meta_v3(&first).unwrap().1.hash;
        let first_owner = native_action_body_owner_key_v3(action_body_hash, first.hash);

        // Model an interrupted older repair: a derivable owner is absent, the
        // count is corrupt, and unreferenced rows remain. The durable marker
        // forces the same idempotent repair path after restart.
        trees.owners.remove(first_owner).unwrap();
        trees
            .refcounts
            .insert(action_body_hash.as_ref(), vec![0x7fu8])
            .unwrap();
        trees.owners.insert([0xabu8; 95], b"").unwrap();
        let orphan = encode_native_action_body_v3(&[vec![0x55]]).unwrap();
        trees
            .bodies
            .insert(orphan.hash.as_ref(), orphan.bytes.as_slice())
            .unwrap();
        trees
            .refcounts
            .insert(orphan.hash.as_ref(), 9u64.to_be_bytes().as_slice())
            .unwrap();
        trees
            .meta
            .insert(META_BLOCK_STORE_REPAIR_IN_PROGRESS_V3, b"interrupted")
            .unwrap();
        trees.db.flush().unwrap();

        let work = repair_native_block_content_store_v3(
            &trees.meta,
            &trees.blocks,
            &trees.bodies,
            &trees.refcounts,
            &trees.owners,
            &trees.forks,
        )
        .expect("resume exact V3 content-store repair");
        assert!(work.owner_rows_repaired >= 1);
        assert!(work.owner_rows_removed >= 1);
        assert!(work.refcount_rows_repaired >= 1);
        assert!(work.orphan_rows_removed >= 2);
        assert!(trees
            .meta
            .get(META_BLOCK_STORE_REPAIR_IN_PROGRESS_V3)
            .unwrap()
            .is_none());
        assert!(trees.bodies.get(orphan.hash.as_ref()).unwrap().is_none());
        assert!(trees.refcounts.get(orphan.hash.as_ref()).unwrap().is_none());
        let repaired_refcount = trees
            .refcounts
            .get(action_body_hash.as_ref())
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_u64_be(repaired_refcount.as_ref(), "repaired test refcount").unwrap(),
            2
        );
        let audit = audit_native_block_content_store_v3(
            &trees.blocks,
            &trees.bodies,
            &trees.refcounts,
            &trees.owners,
            &trees.forks,
        )
        .unwrap();
        assert_eq!(audit.block_rows, 2);
        assert_eq!(audit.owner_rows, 2);
        assert_eq!(audit.action_body_rows, 1);
    }
}
