//! Deterministic bounded retention planning for verified noncanonical V3 blocks.

use super::*;
use crypto::hash384::{ActionBodyHash48, BlockId48, Work64};

pub(crate) const MAX_NATIVE_NONCANONICAL_FORK_BLOCKS: usize = 1_024;
// This V3 storage-policy constant is pinned independently of transport tuning.
// Peers advertise an exact 128-block fork backfill horizon, so durable
// retention must never silently drift below it.
pub(crate) const MAX_NATIVE_NONCANONICAL_FORK_DEPTH: u64 = 128;
pub(crate) const MAX_NATIVE_NONCANONICAL_FORK_BYTES: u64 =
    match (MAX_NATIVE_BLOCK_META_BYTES as u64).checked_mul(MAX_NATIVE_NONCANONICAL_FORK_DEPTH) {
        Some(bytes) => bytes,
        None => panic!("native noncanonical fork byte cap overflows u64"),
    };
const _: () = assert!(MAX_NATIVE_BLOCK_META_BYTES == 68_477_440);
const _: () = assert!(MAX_NATIVE_NONCANONICAL_FORK_BYTES == 8_765_112_320);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeForkRetentionRecordV3 {
    pub(crate) block_hash: BlockId48,
    pub(crate) parent_hash: BlockId48,
    pub(crate) height: u64,
    pub(crate) cumulative_work: Work64,
    pub(crate) action_body_hash: ActionBodyHash48,
    pub(crate) action_body_len: u64,
    /// Monotonic local insertion sequence persisted with the fork record.
    pub(crate) first_seen_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeForkRetentionPlanV3 {
    pub(crate) retained: BTreeSet<BlockId48>,
    pub(crate) pruned: BTreeSet<BlockId48>,
    pub(crate) distinct_action_body_bytes: u64,
    /// Exact number of branch-path records examined during greedy selection.
    /// This makes the admission scaling bound regression-testable without a
    /// wall-clock assertion.
    pub(crate) selection_path_records_examined: u64,
}

#[derive(Clone, Debug)]
struct NativeForkBranchV3 {
    tip: NativeForkRetentionRecordV3,
    path: Vec<BlockId48>,
    protected: bool,
}

fn native_fork_branch_is_better(left: &NativeForkBranchV3, right: &NativeForkBranchV3) -> bool {
    left.protected
        .cmp(&right.protected)
        .then_with(|| left.tip.cumulative_work.cmp(&right.tip.cumulative_work))
        .then_with(|| left.tip.height.cmp(&right.tip.height))
        // Older equal-work/equal-height branches win. This prevents a stream
        // of equal-quality nonce siblings from churning the retained set and
        // its content-addressed refcounts.
        .then_with(|| {
            right
                .tip
                .first_seen_sequence
                .cmp(&left.tip.first_seen_sequence)
        })
        // Lower block identity is the exact final tie-break. Reverse it here
        // because the caller sorts best-to-worst with this predicate.
        .then_with(|| right.tip.block_hash.cmp(&left.tip.block_hash))
        .is_gt()
}

fn native_fork_path_to_canonical_anchor(
    records: &BTreeMap<BlockId48, NativeForkRetentionRecordV3>,
    canonical_hashes: &BTreeMap<u64, BlockId48>,
    tip: &NativeForkRetentionRecordV3,
) -> Result<(u64, Vec<BlockId48>)> {
    let mut cursor = tip;
    let mut reversed = Vec::new();
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(cursor.block_hash) {
            return Err(anyhow!("native V3 fork retention graph contains a cycle"));
        }
        reversed.push(cursor.block_hash);
        let parent_height = cursor
            .height
            .checked_sub(1)
            .ok_or_else(|| anyhow!("native V3 noncanonical genesis is forbidden"))?;
        if canonical_hashes.get(&parent_height) == Some(&cursor.parent_hash) {
            reversed.reverse();
            return Ok((parent_height, reversed));
        }
        let parent = records.get(&cursor.parent_hash).ok_or_else(|| {
            anyhow!(
                "native V3 fork record at height {} has neither retained nor canonical parent",
                cursor.height
            )
        })?;
        if parent.height != parent_height {
            return Err(anyhow!(
                "native V3 fork retention parent height is not contiguous"
            ));
        }
        cursor = parent;
    }
}

fn native_fork_retained_body_bytes(
    retained: &BTreeSet<BlockId48>,
    records: &BTreeMap<BlockId48, NativeForkRetentionRecordV3>,
) -> Result<u64> {
    let mut bodies = BTreeMap::<ActionBodyHash48, u64>::new();
    for hash in retained {
        let record = records
            .get(hash)
            .ok_or_else(|| anyhow!("native V3 retained fork record disappeared"))?;
        match bodies.insert(record.action_body_hash, record.action_body_len) {
            Some(previous) if previous != record.action_body_len => {
                return Err(anyhow!(
                    "native V3 action-body hash is associated with conflicting lengths"
                ));
            }
            _ => {}
        }
    }
    bodies.values().try_fold(0u64, |total, len| {
        total
            .checked_add(*len)
            .ok_or_else(|| anyhow!("native V3 retained action-body byte total overflow"))
    })
}

/// Plan a complete, ancestor-closed noncanonical fork set.
///
/// Branch tips are retained in descending `(protected, cumulative_work,
/// height, oldest-first_seen_sequence)` order with the lexicographically lower
/// block identity as the exact tie-break. A branch is admitted atomically with all
/// of its noncanonical ancestors; a skipped branch can never leave an orphan.
pub(crate) fn plan_native_noncanonical_fork_retention_v3(
    records: impl IntoIterator<Item = NativeForkRetentionRecordV3>,
    canonical_hashes: &BTreeMap<u64, BlockId48>,
    canonical_best_height: u64,
    protected_tips: &BTreeSet<BlockId48>,
    max_depth: u64,
    max_blocks: usize,
    max_distinct_action_body_bytes: u64,
) -> Result<NativeForkRetentionPlanV3> {
    let mut by_hash = BTreeMap::new();
    let mut body_lengths = BTreeMap::<ActionBodyHash48, u64>::new();
    for record in records {
        let block_hash = record.block_hash;
        let action_body_hash = record.action_body_hash;
        let action_body_len = record.action_body_len;
        if record.action_body_len == 0
            || record.action_body_len
                > u64::try_from(MAX_NATIVE_ACTION_BODY_V3_BYTES).unwrap_or(u64::MAX)
            || canonical_hashes.get(&record.height) == Some(&record.block_hash)
        {
            return Err(anyhow!(
                "native V3 fork retention input has an invalid body length or duplicate block"
            ));
        }
        match body_lengths.insert(action_body_hash, action_body_len) {
            Some(previous) if previous != action_body_len => {
                return Err(anyhow!(
                    "native V3 action-body hash is associated with conflicting lengths"
                ));
            }
            _ => {}
        }
        if by_hash.insert(block_hash, record).is_some() {
            return Err(anyhow!(
                "native V3 fork retention input has a duplicate block"
            ));
        }
    }
    if by_hash.is_empty() {
        return Ok(NativeForkRetentionPlanV3 {
            retained: BTreeSet::new(),
            pruned: BTreeSet::new(),
            distinct_action_body_bytes: 0,
            selection_path_records_examined: 0,
        });
    }

    let parents = by_hash
        .values()
        .filter_map(|record| {
            by_hash
                .contains_key(&record.parent_hash)
                .then_some(record.parent_hash)
        })
        .collect::<BTreeSet<_>>();
    let mut branches = Vec::new();
    let mut covered = BTreeSet::new();
    for tip in by_hash
        .values()
        .filter(|record| !parents.contains(&record.block_hash))
    {
        let (anchor_height, path) =
            native_fork_path_to_canonical_anchor(&by_hash, canonical_hashes, tip)?;
        let old_depth = canonical_best_height
            .checked_sub(anchor_height)
            .ok_or_else(|| anyhow!("native V3 fork anchor is above the canonical best height"))?;
        let new_depth = tip
            .height
            .checked_sub(anchor_height)
            .ok_or_else(|| anyhow!("native V3 fork tip precedes its canonical anchor"))?;
        let protected = protected_tips.contains(&tip.block_hash);
        covered.extend(path.iter().copied());
        if old_depth > max_depth || new_depth > max_depth {
            if protected {
                return Err(anyhow!(
                    "protected native V3 fork exceeds the advertised retention horizon"
                ));
            }
            continue;
        }
        branches.push(NativeForkBranchV3 {
            tip: tip.clone(),
            path,
            protected,
        });
    }
    if covered.len() != by_hash.len() {
        return Err(anyhow!(
            "native V3 fork retention graph has no complete tip-to-canonical path"
        ));
    }
    for protected in protected_tips {
        if !branches
            .iter()
            .any(|branch| branch.tip.block_hash == *protected)
        {
            return Err(anyhow!(
                "protected native V3 fork is not an eligible retained branch tip"
            ));
        }
    }
    branches.sort_by(|left, right| {
        if native_fork_branch_is_better(left, right) {
            std::cmp::Ordering::Less
        } else if native_fork_branch_is_better(right, left) {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });

    let mut retained = BTreeSet::new();
    let mut retained_body_refs = BTreeMap::<ActionBodyHash48, u64>::new();
    let mut distinct_action_body_bytes = 0u64;
    let mut selection_path_records_examined = 0u64;
    for branch in branches {
        selection_path_records_examined = selection_path_records_examined
            .checked_add(u64::try_from(branch.path.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| anyhow!("native V3 fork selection work counter overflow"))?;
        let additions = branch
            .path
            .iter()
            .filter(|hash| !retained.contains(*hash))
            .copied()
            .collect::<Vec<_>>();
        let next_block_count = retained
            .len()
            .checked_add(additions.len())
            .ok_or_else(|| anyhow!("native V3 retained fork block count overflow"))?;
        let mut added_body_refs = BTreeMap::<ActionBodyHash48, u64>::new();
        let mut added_distinct_bytes = 0u64;
        for hash in &additions {
            let record = by_hash
                .get(hash)
                .ok_or_else(|| anyhow!("native V3 branch path record disappeared"))?;
            if !retained_body_refs.contains_key(&record.action_body_hash)
                && !added_body_refs.contains_key(&record.action_body_hash)
            {
                added_distinct_bytes = added_distinct_bytes
                    .checked_add(record.action_body_len)
                    .ok_or_else(|| anyhow!("native V3 retained body byte total overflow"))?;
            }
            *added_body_refs.entry(record.action_body_hash).or_default() += 1;
        }
        let next_body_bytes = distinct_action_body_bytes
            .checked_add(added_distinct_bytes)
            .ok_or_else(|| anyhow!("native V3 retained body byte total overflow"))?;
        let fits =
            next_block_count <= max_blocks && next_body_bytes <= max_distinct_action_body_bytes;
        if fits {
            retained.extend(additions);
            for (body_hash, refs) in added_body_refs {
                *retained_body_refs.entry(body_hash).or_default() += refs;
            }
            distinct_action_body_bytes = next_body_bytes;
        } else if branch.protected {
            return Err(anyhow!(
                "protected native V3 fork cannot fit the frozen retention caps"
            ));
        }
    }

    let pruned = by_hash
        .keys()
        .filter(|hash| !retained.contains(*hash))
        .copied()
        .collect::<BTreeSet<_>>();
    debug_assert_eq!(
        distinct_action_body_bytes,
        native_fork_retained_body_bytes(&retained, &by_hash)?
    );
    Ok(NativeForkRetentionPlanV3 {
        retained,
        pruned,
        distinct_action_body_bytes,
        selection_path_records_examined,
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

    fn body_id(value: u64) -> ActionBodyHash48 {
        let mut bytes = [0u8; 48];
        bytes[40..].copy_from_slice(&value.to_be_bytes());
        ActionBodyHash48::new(bytes)
    }

    fn work(value: u64) -> Work64 {
        let mut bytes = [0u8; 64];
        bytes[56..].copy_from_slice(&value.to_be_bytes());
        Work64::new(bytes)
    }

    fn record(
        id: u64,
        parent: u64,
        height: u64,
        body: u64,
        body_len: u64,
        first_seen_sequence: u64,
    ) -> NativeForkRetentionRecordV3 {
        NativeForkRetentionRecordV3 {
            block_hash: block_id(id),
            parent_hash: block_id(parent),
            height,
            cumulative_work: work(height),
            action_body_hash: body_id(body),
            action_body_len: body_len,
            first_seen_sequence,
        }
    }

    fn genesis() -> BTreeMap<u64, BlockId48> {
        BTreeMap::from([(0, block_id(0))])
    }

    #[test]
    fn max_body_depth_boundary_is_exact_and_ancestor_closed() {
        let max_body = u64::try_from(MAX_NATIVE_ACTION_BODY_V3_BYTES).expect("body cap fits u64");
        let records = (1..=MAX_NATIVE_NONCANONICAL_FORK_DEPTH)
            .map(|height| record(height, height - 1, height, height, max_body, height))
            .collect::<Vec<_>>();
        let plan = plan_native_noncanonical_fork_retention_v3(
            records,
            &genesis(),
            0,
            &BTreeSet::new(),
            MAX_NATIVE_NONCANONICAL_FORK_DEPTH,
            MAX_NATIVE_NONCANONICAL_FORK_BLOCKS,
            MAX_NATIVE_NONCANONICAL_FORK_BYTES,
        )
        .expect("exact advertised horizon fits");
        assert_eq!(plan.retained.len(), 128);
        assert!(plan.pruned.is_empty());
        assert_eq!(plan.distinct_action_body_bytes, max_body * 128);

        let too_deep = (1..=MAX_NATIVE_NONCANONICAL_FORK_DEPTH + 1)
            .map(|height| record(height, height - 1, height, height, 1, height))
            .collect::<Vec<_>>();
        let plan = plan_native_noncanonical_fork_retention_v3(
            too_deep,
            &genesis(),
            0,
            &BTreeSet::new(),
            MAX_NATIVE_NONCANONICAL_FORK_DEPTH,
            MAX_NATIVE_NONCANONICAL_FORK_BLOCKS,
            MAX_NATIVE_NONCANONICAL_FORK_BYTES,
        )
        .expect("unprotected over-horizon branch is deterministically pruned");
        assert!(plan.retained.is_empty());
        assert_eq!(plan.pruned.len(), 129);
    }

    #[test]
    fn same_body_nonce_siblings_count_once_and_oldest_survive_global_cap() {
        let records = (1..=1_025u64)
            .map(|id| record(id, 0, 1, 7, 67_000_000, id - 1))
            .collect::<Vec<_>>();
        let plan = plan_native_noncanonical_fork_retention_v3(
            records,
            &genesis(),
            0,
            &BTreeSet::new(),
            MAX_NATIVE_NONCANONICAL_FORK_DEPTH,
            MAX_NATIVE_NONCANONICAL_FORK_BLOCKS,
            MAX_NATIVE_NONCANONICAL_FORK_BYTES,
        )
        .expect("same-body sibling plan");
        assert_eq!(plan.retained.len(), 1_024);
        assert_eq!(plan.distinct_action_body_bytes, 67_000_000);
        assert_eq!(plan.pruned, BTreeSet::from([block_id(1_025)]));
        assert_eq!(
            plan.selection_path_records_examined, 1_025,
            "same-parent admission work must stay linear in branch count"
        );
    }

    #[test]
    fn protected_winner_keeps_complete_path_and_evicts_only_whole_branches() {
        let mut records = (1..=1_023u64)
            .map(|id| record(id, 0, 1, 1, 1, id))
            .collect::<Vec<_>>();
        records.push(record(10_001, 0, 1, 2, 1, 10_001));
        records.push(record(10_002, 10_001, 2, 3, 1, 10_002));
        let protected = BTreeSet::from([block_id(10_002)]);
        let plan = plan_native_noncanonical_fork_retention_v3(
            records,
            &genesis(),
            0,
            &protected,
            MAX_NATIVE_NONCANONICAL_FORK_DEPTH,
            MAX_NATIVE_NONCANONICAL_FORK_BLOCKS,
            MAX_NATIVE_NONCANONICAL_FORK_BYTES,
        )
        .expect("protected path fits after one whole sibling eviction");
        assert_eq!(plan.retained.len(), 1_024);
        assert!(plan.retained.contains(&block_id(10_001)));
        assert!(plan.retained.contains(&block_id(10_002)));
        assert_eq!(plan.pruned.len(), 1);
        assert!(!plan.pruned.contains(&block_id(10_001)));
    }

    #[test]
    fn malformed_cycle_and_conflicting_body_lengths_fail_closed() {
        let cycle = vec![record(1, 2, 2, 1, 1, 0), record(2, 1, 1, 2, 1, 1)];
        assert!(plan_native_noncanonical_fork_retention_v3(
            cycle,
            &genesis(),
            0,
            &BTreeSet::new(),
            MAX_NATIVE_NONCANONICAL_FORK_DEPTH,
            MAX_NATIVE_NONCANONICAL_FORK_BLOCKS,
            MAX_NATIVE_NONCANONICAL_FORK_BYTES,
        )
        .is_err());

        let conflicting = vec![record(1, 0, 1, 9, 1, 0), record(2, 0, 1, 9, 2, 1)];
        assert!(plan_native_noncanonical_fork_retention_v3(
            conflicting,
            &genesis(),
            0,
            &BTreeSet::new(),
            MAX_NATIVE_NONCANONICAL_FORK_DEPTH,
            MAX_NATIVE_NONCANONICAL_FORK_BLOCKS,
            MAX_NATIVE_NONCANONICAL_FORK_BYTES,
        )
        .is_err());
    }
}
