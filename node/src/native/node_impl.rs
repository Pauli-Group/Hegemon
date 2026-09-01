//! NativeNode implementation: startup, state access, import, template preparation.

use super::*;
use rayon::prelude::*;

// Pin the external sled crate inside this module. A crate-root alias named
// `sled` must not be able to redirect the atomic V8 application surface to a
// user-defined trait that can skip or defer the closure.
extern crate sled as __hegemon_pinned_sled;

const META_CANONICAL_UNDO_PREFIX: &[u8] = b"canonical_undo_v1/";
const META_NONCANONICAL_FORK_PREFIX: &[u8] = b"noncanonical_fork_v1/";
const NATIVE_CANONICAL_UNDO_SCHEMA_V1: u16 = 1;
const NATIVE_NONCANONICAL_FORK_SCHEMA_V1: u16 = 1;
const NATIVE_CIPHERTEXT_INDEX_VALUE_BYTES: usize =
    core::mem::size_of::<ActionId48>() + core::mem::size_of::<u32>() + core::mem::size_of::<u64>();

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct NativeCiphertextIndexUndoV1 {
    hash: [u8; 48],
    previous: Option<Vec<u8>>,
}

#[cfg(test)]
mod poseidon2_v8_throughput_tests {
    use super::*;

    fn action(seed: u8, v8: bool) -> PendingAction {
        PendingAction {
            tx_hash: ActionId48::new([seed; 48]),
            binding: if v8 {
                protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into()
            } else {
                protocol_versioning::DEFAULT_VERSION_BINDING.into()
            },
            family_id: FAMILY_SHIELDED_POOL,
            action_id: if v8 {
                ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE
            } else {
                ACTION_MINT_COINBASE
            },
            anchor: [0; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: Vec::new(),
            ciphertext_sizes: Vec::new(),
            public_args: vec![seed; usize::from(seed)],
            fee: 0,
            candidate_artifact: None,
        }
    }

    #[test]
    fn planner_order_replaces_only_v8_slots_without_copying_other_actions() {
        let high = action(90, true);
        let middle = action(7, false);
        let low = action(10, true);
        let high_args = high.public_args.clone();
        let middle_args = middle.public_args.clone();
        let low_args = low.public_args.clone();
        let mut actions = vec![high, middle, low];

        reorder_poseidon2_v8_action_slots(
            &mut actions,
            &[ActionId48::new([10; 48]), ActionId48::new([90; 48])],
        )
        .unwrap();

        assert_eq!(actions[0].public_args, low_args);
        assert_eq!(actions[1].public_args, middle_args);
        assert_eq!(actions[2].public_args, high_args);
        assert!(!is_poseidon2_v8_action(&actions[1]));
    }

    #[test]
    fn mixed_capacity_selection_never_skips_a_v8_prefix_action_for_its_descendant() {
        let ancestor = action(90, true);
        let descendant = action(10, true);
        let cap = descendant.encoded_size();
        assert!(ancestor.encoded_size() > cap);

        let generic = select_native_da_capacity_prefix(
            &[ancestor.clone(), descendant.clone()],
            usize::MAX,
            2,
            cap,
            0,
            0,
            |_| false,
            |_| None,
            PendingAction::encoded_size,
        )
        .unwrap();
        assert_eq!(generic.selected_indices, vec![1]);

        assert!(retain_capacity_selected_v8_prefix(
            &[ancestor, descendant],
            &generic.selected_indices,
        )
        .is_empty());
    }

    #[test]
    fn mining_selection_reserves_the_v8_coinbase_inside_the_512_action_budget() {
        let actions = (0..MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK)
            .map(|index| action((index % usize::from(u8::MAX)) as u8, true))
            .collect::<Vec<_>>();
        let all_indices = (0..actions.len()).collect::<Vec<_>>();

        let without_coinbase =
            retain_selected_v8_proof_action_budget(&actions, &all_indices, 0).unwrap();
        assert_eq!(without_coinbase.len(), MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK);

        let with_coinbase =
            retain_selected_v8_proof_action_budget(&actions, &all_indices, 1).unwrap();
        assert_eq!(with_coinbase.len(), MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK - 1);
        assert_eq!(with_coinbase, all_indices[..with_coinbase.len()]);

        assert!(retain_selected_v8_proof_action_budget(
            &actions,
            &all_indices,
            MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK + 1,
        )
        .is_err());
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct NativeCanonicalUndoV1 {
    schema_version: u16,
    rules_hash: [u8; 32],
    height: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    block_body_digest: [u8; 48],
    commitment_start: u64,
    commitment_count: u64,
    nullifier_start: u64,
    nullifier_count: u64,
    ciphertext_index_undo: Vec<NativeCiphertextIndexUndoV1>,
    record_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct NativeNoncanonicalForkRecordV1 {
    schema_version: u16,
    rules_hash: [u8; 32],
    height: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    cumulative_work: [u8; 48],
    body_len: u64,
    block_body_digest: [u8; 48],
    record_digest: [u8; 48],
}

#[derive(Clone, Debug)]
struct NativeCanonicalBlockDelta {
    meta: NativeBlockMeta,
    encoded: Vec<u8>,
    actions: Vec<PendingAction>,
    commitment_start: u64,
    commitment_entries: Vec<(u64, [u8; 48])>,
    ciphertext_archive_entries: Vec<(u64, Vec<u8>)>,
    nullifier_append: NullifierIndexedAppend,
    bridge_replay_entries: Vec<[u8; 48]>,
    ciphertext_index_entries: Vec<([u8; 48], Vec<u8>)>,
}

#[derive(Clone, Debug)]
struct NativeCiphertextIndexMutation {
    hash: [u8; 48],
    expected: Option<Vec<u8>>,
    replacement: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct NativeReorgSuffixCommitPlan {
    old_blocks: Vec<NativeCanonicalBlockDelta>,
    new_blocks: Vec<NativeCanonicalBlockDelta>,
    old_undos: Vec<NativeCanonicalUndoV1>,
    new_undos: Vec<NativeCanonicalUndoV1>,
    ciphertext_index_mutations: Vec<NativeCiphertextIndexMutation>,
    pending_removals: Vec<(ActionId48, Vec<u8>)>,
    pending_upserts: Vec<(ActionId48, Vec<u8>)>,
    tip_action_removals: Vec<ActionId48>,
    staged_ciphertext_removals: Vec<[u8; 48]>,
    checkpoint_rows: Vec<NativeCanonicalCheckpointRows>,
}

fn native_canonical_suffix_reorg_commit_manifest(
    plan: &NativeReorgSuffixCommitPlan,
    poseidon2_v8_plan: Option<&poseidon2_v8_state::Poseidon2V8CanonicalPlan>,
) -> Result<NativeAtomicCommitManifestAdmissionInput> {
    let mut commitment_count = 0usize;
    let mut nullifier_count = 0usize;
    let mut bridge_replay_count = 0usize;
    let mut ciphertext_archive_count = 0usize;
    for delta in &plan.new_blocks {
        commitment_count = commitment_count
            .checked_add(delta.commitment_entries.len())
            .ok_or_else(|| anyhow!("native suffix manifest commitment count overflow"))?;
        nullifier_count = nullifier_count
            .checked_add(delta.nullifier_append.rows.len())
            .ok_or_else(|| anyhow!("native suffix manifest nullifier count overflow"))?;
        bridge_replay_count = bridge_replay_count
            .checked_add(delta.bridge_replay_entries.len())
            .ok_or_else(|| anyhow!("native suffix manifest bridge count overflow"))?;
        ciphertext_archive_count = ciphertext_archive_count
            .checked_add(delta.ciphertext_archive_entries.len())
            .ok_or_else(|| anyhow!("native suffix manifest ciphertext count overflow"))?;
    }
    let poseidon2_v8_plan_count = usize::from(poseidon2_v8_plan.is_some());
    Ok(NativeAtomicCommitManifestAdmissionInput {
        kind: NativeAtomicCommitKind::CanonicalSuffixReorgCommit,
        action_count: plan.pending_removals.len(),
        planned_action_count: 0,
        chain_block_count: plan.new_blocks.len(),
        height_entry_count: plan.new_blocks.len(),
        pending_entry_count: plan.pending_upserts.len(),
        source_commitment_count: commitment_count,
        source_nullifier_count: nullifier_count,
        source_bridge_replay_count: bridge_replay_count,
        // The suffix algorithm applies an exact expected/replacement mutation
        // for each hash; this count includes removals as well as insertions.
        source_ciphertext_index_count: plan.ciphertext_index_mutations.len(),
        source_ciphertext_archive_count: ciphertext_archive_count,
        source_staged_ciphertext_removal_count: plan.staged_ciphertext_removals.len(),
        source_poseidon2_v8_plan_count: poseidon2_v8_plan_count,
        // Every replacement row is independently verified and durably
        // prestored before canonical adoption. The canonical transaction may
        // compare those bytes, but must never write a block record.
        block_record_writes: 0,
        height_index_writes: plan.new_blocks.len(),
        best_pointer_writes: 1,
        canonical_index_cleared: false,
        pending_tree_cleared: false,
        pending_action_removals: plan.pending_removals.len(),
        pending_action_writes: plan.pending_upserts.len(),
        commitment_writes: commitment_count,
        nullifier_writes: nullifier_count,
        bridge_replay_writes: bridge_replay_count,
        ciphertext_index_writes: plan.ciphertext_index_mutations.len(),
        ciphertext_archive_writes: ciphertext_archive_count,
        staged_ciphertext_removals: plan.staged_ciphertext_removals.len(),
        // Deliberately invalid until the shared-sled transaction helper has
        // applied (or observed the absence of) the exact typed plan.
        poseidon2_v8_plan_application_count: UNOBSERVED_POSEIDON2_V8_PLAN_APPLICATION_COUNT,
    })
}

fn native_tip_extension_batch_commit_manifest(
    plan: &NativeReorgSuffixCommitPlan,
    poseidon2_v8_plan: Option<&poseidon2_v8_state::Poseidon2V8CanonicalPlan>,
) -> Result<NativeAtomicCommitManifestAdmissionInput> {
    if !plan.old_blocks.is_empty()
        || !plan.pending_removals.is_empty()
        || !plan.pending_upserts.is_empty()
    {
        return Err(anyhow!(
            "native tip-extension batch commit plan contains reorg-only mutations"
        ));
    }
    let base = native_canonical_suffix_reorg_commit_manifest(plan, poseidon2_v8_plan)?;
    let action_count = plan
        .new_blocks
        .iter()
        .try_fold(0usize, |count, delta| {
            count.checked_add(delta.actions.len())
        })
        .ok_or_else(|| anyhow!("native tip-extension action count overflow"))?;
    if plan.tip_action_removals.len() != action_count {
        return Err(anyhow!(
            "native tip-extension removal count does not match decoded action count"
        ));
    }
    Ok(NativeAtomicCommitManifestAdmissionInput {
        kind: NativeAtomicCommitKind::TipExtensionBatchCommit,
        action_count,
        planned_action_count: action_count,
        pending_entry_count: 0,
        block_record_writes: plan.new_blocks.len(),
        pending_action_removals: plan.tip_action_removals.len(),
        pending_action_writes: 0,
        ..base
    })
}

#[cfg(test)]
pub(crate) fn empty_canonical_suffix_manifest_before_v8_observation(
) -> NativeAtomicCommitManifestAdmissionInput {
    native_canonical_suffix_reorg_commit_manifest(
        &NativeReorgSuffixCommitPlan {
            old_blocks: Vec::new(),
            new_blocks: Vec::new(),
            old_undos: Vec::new(),
            new_undos: Vec::new(),
            ciphertext_index_mutations: Vec::new(),
            pending_removals: Vec::new(),
            pending_upserts: Vec::new(),
            tip_action_removals: Vec::new(),
            staged_ciphertext_removals: Vec::new(),
            checkpoint_rows: Vec::new(),
        },
        None,
    )
    .expect("empty suffix manifest counts cannot overflow")
}

/// Apply the exact typed V8 plan, then admit the manifest using the number of
/// applications that actually completed in this transaction attempt.
///
/// This helper must remain the first operation in every shared canonical sled
/// transaction that can carry a V8 plan.  A caller cannot satisfy the manifest
/// by copying `plan.is_some()` into both counters: the application count is
/// produced only after `apply_canonical_plan_in_transaction` succeeds.  Any
/// later transaction failure rolls these rows back together with the legacy
/// canonical rows.
pub(crate) fn apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction(
    poseidon2_v8_tree: &self::__hegemon_pinned_sled::transaction::TransactionalTree,
    plan: Option<&super::poseidon2_v8_state::Poseidon2V8CanonicalPlan>,
    manifest: super::NativeAtomicCommitManifestAdmissionInput,
    context: &'static str,
) -> self::__hegemon_pinned_sled::transaction::ConflictableTransactionResult<usize, String> {
    let actual_application_count = match plan {
        Some(plan) => {
            super::poseidon2_v8_state::Poseidon2V8StateStore::apply_canonical_plan_in_transaction(
                poseidon2_v8_tree,
                plan,
            )?;
            1
        }
        None => 0,
    };
    let observed = super::NativeAtomicCommitManifestAdmissionInput {
        poseidon2_v8_plan_application_count: actual_application_count,
        ..manifest
    };
    super::block_flow::evaluate_native_atomic_commit_manifest_admission(observed).map_err(
        |rejection| {
            self::__hegemon_pinned_sled::transaction::ConflictableTransactionError::Abort(format!(
                "{context}: {}",
                rejection.label()
            ))
        },
    )?;
    Ok(actual_application_count)
}

/// Records only transitions returned by the exact source verifier. The typed
/// pending/order planner therefore never consumes a host-parsed statement as
/// proof of validity, and the expensive SMZ9 verifier still runs exactly once.
struct RecordingPoseidon2V8Verifier<V> {
    inner: V,
    transitions: Vec<poseidon2_v8_state::Poseidon2V8PublicTransition>,
}

impl<V> RecordingPoseidon2V8Verifier<V> {
    fn new(inner: V) -> Self {
        Self {
            inner,
            transitions: Vec::new(),
        }
    }

    fn transitions(&self) -> &[poseidon2_v8_state::Poseidon2V8PublicTransition] {
        &self.transitions
    }
}

impl<V: poseidon2_v8_state::Poseidon2V8ExactLeafVerifier>
    poseidon2_v8_state::Poseidon2V8ExactLeafVerifier for RecordingPoseidon2V8Verifier<V>
{
    fn verify_exact_v8_leaf(
        &mut self,
        block: poseidon2_v8_state::Poseidon2V8BlockContext,
        leaf_index: usize,
        exact_native_leaf: &[u8],
    ) -> std::result::Result<poseidon2_v8_state::Poseidon2V8PublicTransition, String> {
        let transition = self
            .inner
            .verify_exact_v8_leaf(block, leaf_index, exact_native_leaf)?;
        self.transitions.push(transition);
        Ok(transition)
    }
}

fn recorded_poseidon2_v8_actions(
    actions: &[&PendingAction],
    exact_native_leaves: &[&[u8]],
    transitions: &[poseidon2_v8_state::Poseidon2V8PublicTransition],
) -> Result<Vec<poseidon2_v8_pending::Poseidon2V8PendingAction>> {
    if actions.len() != exact_native_leaves.len() || actions.len() != transitions.len() {
        return Err(anyhow!(
            "native V8 verified transition cardinality mismatch: actions={} leaves={} transitions={}",
            actions.len(),
            exact_native_leaves.len(),
            transitions.len()
        ));
    }
    Ok(actions
        .iter()
        .zip(exact_native_leaves.iter())
        .zip(transitions.iter().copied())
        .map(|((action, exact_native_leaf), transition)| {
            poseidon2_v8_pending::Poseidon2V8PendingAction::new(
                action.tx_hash,
                action.encoded_size(),
                exact_native_leaf,
                transition,
            )
        })
        .collect())
}

fn verify_recorded_poseidon2_v8_block_order(
    checkpoint: poseidon2_v8_state::Poseidon2V8Checkpoint,
    actions: &[&PendingAction],
    exact_native_leaves: &[&[u8]],
    transitions: &[poseidon2_v8_state::Poseidon2V8PublicTransition],
    context: &str,
) -> Result<poseidon2_v8_state::Poseidon2V8Root> {
    let recorded = recorded_poseidon2_v8_actions(actions, exact_native_leaves, transitions)?;
    poseidon2_v8_pending::verify_poseidon2_v8_block_order(checkpoint, &recorded)
        .map_err(|error| anyhow!("{context}: {error}"))
}

/// Replace only the V8 positions in a mixed native action list with the exact
/// source-verified planner order. Non-V8 relative order and positions remain
/// unchanged, and proof/public-argument buffers move rather than being copied.
fn reorder_poseidon2_v8_action_slots(
    actions: &mut [PendingAction],
    ordered_action_ids: &[ActionId48],
) -> Result<()> {
    let v8_positions = actions
        .iter()
        .enumerate()
        .filter_map(|(index, action)| is_poseidon2_v8_action(action).then_some(index))
        .collect::<Vec<_>>();
    if v8_positions.len() != ordered_action_ids.len() {
        return Err(anyhow!(
            "native V8 template order cardinality mismatch: slots={} ordered={}",
            v8_positions.len(),
            ordered_action_ids.len()
        ));
    }
    let mut positions_by_id = BTreeMap::new();
    for position in v8_positions.iter().copied() {
        if positions_by_id
            .insert(actions[position].tx_hash, position)
            .is_some()
        {
            return Err(anyhow!(
                "duplicate native V8 action id during template ordering"
            ));
        }
    }
    for (target_position, desired_id) in v8_positions
        .iter()
        .copied()
        .zip(ordered_action_ids.iter().copied())
    {
        let current_position = positions_by_id
            .get(&desired_id)
            .copied()
            .ok_or_else(|| anyhow!("native V8 template order references an absent action id"))?;
        if current_position == target_position {
            continue;
        }
        let displaced_id = actions[target_position].tx_hash;
        actions.swap(target_position, current_position);
        positions_by_id.insert(desired_id, target_position);
        positions_by_id.insert(displaced_id, current_position);
    }
    if actions
        .iter()
        .filter(|action| is_poseidon2_v8_action(action))
        .map(|action| action.tx_hash)
        .ne(ordered_action_ids.iter().copied())
    {
        return Err(anyhow!(
            "native V8 template slot replacement failed exact order readback"
        ));
    }
    Ok(())
}

fn action_uses_poseidon2_v8_state(action: &PendingAction) -> bool {
    is_poseidon2_v8_proof_authority_action(action)
}

fn poseidon2_v8_coinbase_commitment_for_actions(
    actions: &[PendingAction],
) -> Result<Option<poseidon2_v8_state::Poseidon2V8Commitment>> {
    let mut coinbases = actions
        .iter()
        .filter(|action| is_poseidon2_v8_coinbase_action(action));
    let commitment = coinbases
        .next()
        .map(admitted_poseidon2_v8_coinbase_commitment)
        .transpose()?;
    if coinbases.next().is_some() {
        return Err(anyhow!(
            "native block contains multiple Poseidon2 V8 coinbase outputs"
        ));
    }
    Ok(commitment)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeStoredBlockPromotionOutcome {
    Promoted,
    AlreadyCanonical,
    NotBetter,
}

fn native_verified_block_record_key(hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(META_VERIFIED_BLOCK_RECORD_PREFIX.len() + hash.len());
    key.extend_from_slice(META_VERIFIED_BLOCK_RECORD_PREFIX);
    key.extend_from_slice(hash);
    key
}

fn native_canonical_state_checkpoint_key(hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(META_CANONICAL_STATE_CHECKPOINT_PREFIX.len() + hash.len());
    key.extend_from_slice(META_CANONICAL_STATE_CHECKPOINT_PREFIX);
    key.extend_from_slice(hash);
    key
}

fn native_canonical_undo_key(hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(META_CANONICAL_UNDO_PREFIX.len() + hash.len());
    key.extend_from_slice(META_CANONICAL_UNDO_PREFIX);
    key.extend_from_slice(hash);
    key
}

fn native_noncanonical_fork_key(hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(META_NONCANONICAL_FORK_PREFIX.len() + hash.len());
    key.extend_from_slice(META_NONCANONICAL_FORK_PREFIX);
    key.extend_from_slice(hash);
    key
}

fn native_canonical_undo_digest(record: &NativeCanonicalUndoV1) -> [u8; 48] {
    let mut canonical = record.clone();
    canonical.record_digest = [0u8; 48];
    crypto::hashes::blake2b_384_domain_hash(
        b"hegemon-native-canonical-undo-v1",
        [canonical.encode().as_slice()],
    )
}

fn native_noncanonical_fork_digest(record: &NativeNoncanonicalForkRecordV1) -> [u8; 48] {
    let mut canonical = record.clone();
    canonical.record_digest = [0u8; 48];
    crypto::hashes::blake2b_384_domain_hash(
        b"hegemon-native-noncanonical-fork-v1",
        [canonical.encode().as_slice()],
    )
}

fn native_noncanonical_fork_record(
    meta: &NativeBlockMeta,
    encoded: &[u8],
) -> Result<NativeNoncanonicalForkRecordV1> {
    let body_len = u64::try_from(encoded.len())
        .map_err(|_| anyhow!("native noncanonical block body length exceeds u64"))?;
    let mut record = NativeNoncanonicalForkRecordV1 {
        schema_version: NATIVE_NONCANONICAL_FORK_SCHEMA_V1,
        rules_hash: meta.rules_hash,
        height: meta.height,
        block_hash: meta.hash,
        parent_hash: meta.parent_hash,
        cumulative_work: meta.cumulative_work,
        body_len,
        block_body_digest: native_in_process_verified_block_body_digest_from_encoded(encoded)?,
        record_digest: [0u8; 48],
    };
    record.record_digest = native_noncanonical_fork_digest(&record);
    Ok(record)
}

fn validate_native_noncanonical_fork_record(
    record: &NativeNoncanonicalForkRecordV1,
    meta: &NativeBlockMeta,
    encoded: &[u8],
) -> Result<()> {
    validate_native_noncanonical_fork_record_summary(record, &meta.hash)?;
    if record.rules_hash != meta.rules_hash
        || record.height != meta.height
        || record.parent_hash != meta.parent_hash
        || record.cumulative_work != meta.cumulative_work
        || record.body_len != u64::try_from(encoded.len()).unwrap_or(u64::MAX)
        || record.block_body_digest
            != native_in_process_verified_block_body_digest_from_encoded(encoded)?
    {
        return Err(anyhow!(
            "native noncanonical fork record identity/digest mismatch at height {} ({})",
            meta.height,
            hex32(&meta.hash)
        ));
    }
    Ok(())
}

fn validate_native_noncanonical_fork_record_summary(
    record: &NativeNoncanonicalForkRecordV1,
    expected_hash: &[u8; 32],
) -> Result<()> {
    if record.schema_version != NATIVE_NONCANONICAL_FORK_SCHEMA_V1
        || record.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE
        || &record.block_hash != expected_hash
        || record.body_len > u64::try_from(MAX_NATIVE_BLOCK_META_BYTES).unwrap_or(u64::MAX)
        || record.record_digest != native_noncanonical_fork_digest(record)
    {
        return Err(anyhow!(
            "native noncanonical fork summary identity/digest mismatch at height {} ({})",
            record.height,
            hex32(expected_hash)
        ));
    }
    Ok(())
}

pub(crate) fn native_verified_block_body_digest(meta: &NativeBlockMeta) -> Result<[u8; 32]> {
    let encoded = bincode::serialize(meta).context("encode verified native block body")?;
    native_verified_block_body_digest_from_encoded(&encoded)
}

fn native_verified_block_body_digest_from_encoded(encoded: &[u8]) -> Result<[u8; 32]> {
    let encoded_len = u64::try_from(encoded.len())
        .map_err(|_| anyhow!("verified native block body length exceeds u64"))?;
    Ok(hash32_with_parts(&[
        b"hegemon-native-verified-block-record-v1",
        &encoded_len.to_le_bytes(),
        encoded,
    ]))
}

fn native_in_process_verified_block_body_digest(meta: &NativeBlockMeta) -> Result<[u8; 48]> {
    let encoded =
        bincode::serialize(meta).context("encode in-process verified native block body")?;
    native_in_process_verified_block_body_digest_from_encoded(&encoded)
}

fn native_in_process_verified_block_body_digest_from_encoded(encoded: &[u8]) -> Result<[u8; 48]> {
    let encoded_len = u64::try_from(encoded.len())
        .map_err(|_| anyhow!("in-process verified native block body length exceeds u64"))?;
    Ok(crypto::hashes::blake2b_384_domain_hash(
        b"hegemon-native-in-process-verified-block-v1",
        [&encoded_len.to_le_bytes()[..], encoded],
    ))
}

pub(crate) fn native_canonical_state_checkpoint_digest(
    checkpoint: &NativeCanonicalStateCheckpointV1,
) -> [u8; 32] {
    let mut canonical = checkpoint.clone();
    canonical.checkpoint_digest = [0u8; 32];
    hash32_with_parts(&[
        b"hegemon-native-canonical-state-checkpoint-v1",
        &canonical.encode(),
    ])
}

pub(crate) fn native_canonical_state_checkpoint(
    meta: &NativeBlockMeta,
    commitment_tree: &CommitmentTreeState,
    nullifier_accumulator: &NullifierAccumulator,
    header_mmr_peaks: &[Hash32],
) -> Result<NativeCanonicalStateCheckpointV1> {
    let mut checkpoint = NativeCanonicalStateCheckpointV1 {
        schema_version: NATIVE_CANONICAL_STATE_CHECKPOINT_SCHEMA_V1,
        rules_hash: meta.rules_hash,
        height: meta.height,
        block_hash: meta.hash,
        block_body_digest: native_verified_block_body_digest(meta)?,
        commitment_depth: u32::try_from(commitment_tree.depth())
            .map_err(|_| anyhow!("commitment checkpoint depth exceeds u32"))?,
        commitment_history_limit: u32::try_from(commitment_tree.history_limit())
            .map_err(|_| anyhow!("commitment checkpoint history limit exceeds u32"))?,
        commitment_leaf_count: commitment_tree.leaf_count(),
        commitment_root: commitment_tree.root(),
        commitment_frontier: commitment_tree.compact_frontier().to_vec(),
        commitment_root_history: commitment_tree.root_history().copied().collect(),
        nullifier_accumulator: nullifier_accumulator
            .encode()
            .map_err(|err| anyhow!("encode checkpoint nullifier accumulator failed: {err}"))?,
        header_mmr_peaks: header_mmr_peaks.to_vec(),
        checkpoint_digest: [0u8; 32],
    };
    checkpoint.checkpoint_digest = native_canonical_state_checkpoint_digest(&checkpoint);
    Ok(checkpoint)
}

pub(crate) fn validate_native_canonical_state_checkpoint(
    checkpoint: &NativeCanonicalStateCheckpointV1,
    meta: &NativeBlockMeta,
) -> Result<(CommitmentTreeState, NullifierAccumulator, Vec<Hash32>)> {
    if checkpoint.schema_version != NATIVE_CANONICAL_STATE_CHECKPOINT_SCHEMA_V1
        || checkpoint.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE
        || checkpoint.rules_hash != meta.rules_hash
        || checkpoint.height != meta.height
        || checkpoint.block_hash != meta.hash
        || checkpoint.block_body_digest != native_verified_block_body_digest(meta)?
        || checkpoint.checkpoint_digest != native_canonical_state_checkpoint_digest(checkpoint)
    {
        return Err(anyhow!(
            "native canonical state checkpoint identity/digest mismatch at height {}",
            meta.height
        ));
    }
    let commitment_depth = usize::try_from(checkpoint.commitment_depth)
        .map_err(|_| anyhow!("checkpoint commitment depth exceeds usize"))?;
    let history_limit = usize::try_from(checkpoint.commitment_history_limit)
        .map_err(|_| anyhow!("checkpoint history limit exceeds usize"))?;
    let commitment_tree = CommitmentTreeState::from_compact_parts(
        commitment_depth,
        history_limit,
        checkpoint.commitment_leaf_count,
        checkpoint.commitment_root,
        checkpoint.commitment_frontier.clone(),
        checkpoint.commitment_root_history.clone(),
    )
    .map_err(|err| anyhow!("decode commitment checkpoint failed: {err}"))?;
    if commitment_depth != COMMITMENT_TREE_DEPTH
        || commitment_tree.root() != meta.state_root
        || commitment_tree.root() != checkpoint.commitment_root
    {
        return Err(anyhow!(
            "native canonical commitment checkpoint mismatch at height {}",
            meta.height
        ));
    }
    let nullifier_accumulator = NullifierAccumulator::decode(&checkpoint.nullifier_accumulator)
        .map_err(|err| anyhow!("decode checkpoint nullifier accumulator failed: {err}"))?;
    if nullifier_accumulator.root() != meta.nullifier_root {
        return Err(anyhow!(
            "native canonical nullifier checkpoint mismatch at height {}",
            meta.height
        ));
    }
    let checkpoint_leaf_count = meta
        .height
        .checked_add(1)
        .ok_or_else(|| anyhow!("native canonical header checkpoint height overflow"))?;
    // `meta.header_mmr_*` commits the history *before* `meta`; the checkpoint
    // carries the in-memory peak state *after* appending `meta.hash`.  Shape is
    // checked here, while authority to consume these post-state peaks is kept
    // strictly process-local (a persisted checkpoint is never a proof-validity
    // or state-validity trust anchor).
    if meta.header_mmr_len != meta.height
        || checkpoint.header_mmr_peaks.len() != checkpoint_leaf_count.count_ones() as usize
    {
        return Err(anyhow!(
            "native canonical header checkpoint peak shape mismatch at height {}",
            meta.height
        ));
    }
    Ok((
        commitment_tree,
        nullifier_accumulator,
        checkpoint.header_mmr_peaks.clone(),
    ))
}

pub(crate) fn native_retarget_anchor_timestamp_from_parent<F>(
    parent: &NativeBlockMeta,
    new_height: u64,
    mut load_by_hash: F,
) -> Result<Option<u64>>
where
    F: FnMut([u8; 32]) -> Result<Option<NativeBlockMeta>>,
{
    let Some(anchor_steps) = consensus::pow::pow_retarget_anchor_steps(parent.height, new_height)
    else {
        return Ok(None);
    };
    let mut cursor = parent.clone();
    for _ in 0..anchor_steps {
        let expected_height = cursor
            .height
            .checked_sub(1)
            .ok_or_else(|| anyhow!("native PoW retarget history underflow"))?;
        let expected_hash = cursor.parent_hash;
        let ancestor = load_by_hash(expected_hash)?.ok_or_else(|| {
            anyhow!(
                "missing native PoW retarget ancestor {} below height {}",
                hex32(&expected_hash),
                cursor.height
            )
        })?;
        if ancestor.hash != expected_hash
            || ancestor.height != expected_height
            || ancestor.chain_id != parent.chain_id
            || ancestor.rules_hash != parent.rules_hash
            || ancestor.hash != ancestor.work_hash
        {
            return Err(anyhow!(
                "invalid native PoW retarget ancestor at height {} ({})",
                ancestor.height,
                hex32(&ancestor.hash)
            ));
        }
        cursor = ancestor;
    }
    Ok(Some(cursor.timestamp_ms))
}

fn native_outbound_sync_response_matches_request(
    request: &NativeOutboundSyncRequest,
    response_range: Option<NativeSyncRange>,
) -> bool {
    response_range.is_none_or(|range| {
        range.from_height == request.range.from_height
            && range.to_height >= range.from_height
            && range.to_height <= request.range.to_height
    })
}

#[derive(Debug)]
pub(crate) struct NativeIndependentProofPreflightFailure {
    error: anyhow::Error,
    deterministic: bool,
}

#[derive(Clone)]
struct NativeVerifiedDaEncoding {
    transfer_hashes: Vec<ActionId48>,
    params: state_da::DaParams,
    encoding: Arc<state_da::DaEncoding>,
}

struct NativeIndependentProofPreflightSuccess {
    verified_da_encoding: Option<NativeVerifiedDaEncoding>,
    canonical_poseidon2_v8_action_ids: Vec<ActionId48>,
}

impl NativeIndependentProofPreflightFailure {
    fn deterministic(error: impl Into<anyhow::Error>) -> Self {
        Self {
            error: error.into(),
            deterministic: true,
        }
    }

    fn transient(error: impl Into<anyhow::Error>) -> Self {
        Self {
            error: error.into(),
            deterministic: false,
        }
    }

    pub(crate) fn is_deterministic(&self) -> bool {
        self.deterministic
    }

    pub(crate) fn into_anyhow(self) -> anyhow::Error {
        self.error
    }
}

pub(crate) fn native_proof_error_is_deterministic(error: &consensus::error::ProofError) -> bool {
    !matches!(
        error,
        consensus::error::ProofError::InvalidAnchor { .. }
            | consensus::error::ProofError::CommitmentTree(_)
            | consensus::error::ProofError::Internal(_)
            | consensus::error::ProofError::VerifierPanicked(_)
    )
}

pub(crate) struct NativePendingProofAdmissionGuard {
    in_flight: Arc<Mutex<BTreeSet<ActionSemanticId48>>>,
    key: ActionSemanticId48,
}

impl NativePendingProofAdmissionGuard {
    pub(crate) fn semantic_id(&self) -> ActionSemanticId48 {
        self.key
    }
}

impl Drop for NativePendingProofAdmissionGuard {
    fn drop(&mut self) {
        self.in_flight.lock().remove(&self.key);
    }
}

struct NativePendingActionGroupLeaderGuard<'a> {
    group: &'a NativePendingActionGroupCommit,
}

impl Drop for NativePendingActionGroupLeaderGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.group.state.lock();
        state.active = false;
        self.group.wake.notify_all();
    }
}

impl Drop for NativePendingActionCommitRequest {
    fn drop(&mut self) {
        let mut result = self.completion.result.lock();
        if result.is_none() {
            *result = Some(Err(
                "native pending-action group request dropped before completion".to_owned(),
            ));
        }
    }
}

struct NativePendingActionBatchCompletionGuard {
    batch: Vec<NativePendingActionCommitRequest>,
    completed: bool,
}

impl Drop for NativePendingActionBatchCompletionGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        for request in &self.batch {
            let mut result = request.completion.result.lock();
            if result.is_none() {
                *result = Some(Err(
                    "native pending-action group leader aborted before completion".to_owned(),
                ));
            }
        }
    }
}

impl RejectedPendingActionCache {
    fn purge_expired(&mut self, now: Instant) {
        while let Some((hash, inserted_at)) = self.order.front().copied() {
            if now.saturating_duration_since(inserted_at) < NATIVE_REJECTED_PENDING_ACTION_TTL {
                break;
            }
            self.order.pop_front();
            if self.entries.get(&hash).copied() == Some(inserted_at) {
                self.entries.remove(&hash);
            }
        }
    }

    pub(crate) fn contains_at(&mut self, key: &NativePendingRejectionKey, now: Instant) -> bool {
        self.purge_expired(now);
        self.entries.contains_key(key)
    }

    pub(crate) fn insert_at(&mut self, key: NativePendingRejectionKey, now: Instant) {
        self.purge_expired(now);
        self.entries.insert(key, now);
        self.order.push_back((key, now));
        while self.entries.len() > MAX_NATIVE_REJECTED_PENDING_ACTIONS {
            let Some((oldest_hash, oldest_at)) = self.order.pop_front() else {
                break;
            };
            if self.entries.get(&oldest_hash).copied() == Some(oldest_at) {
                self.entries.remove(&oldest_hash);
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct NativeDaActionSelection {
    pub(crate) selected: Vec<PendingAction>,
    pub(crate) individually_unencodable: Vec<PendingAction>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NativeDaCapacitySelection {
    pub(crate) selected_indices: Vec<usize>,
    pub(crate) individually_unencodable_indices: Vec<usize>,
    pub(crate) deferred_indices: Vec<usize>,
    pub(crate) blob_bytes: usize,
    pub(crate) stopped_at_index: Option<usize>,
    pub(crate) count_stopped_at_index: Option<usize>,
    pub(crate) selected_action_count: usize,
    pub(crate) selected_action_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeDaCapacitySelectionError {
    ReservedActionCount,
    ReservedActionBytes,
}

pub(crate) fn native_da_transfer_blob_contribution(
    ciphertext_sizes: impl IntoIterator<Item = usize>,
) -> Option<usize> {
    ciphertext_sizes
        .into_iter()
        .try_fold(std::mem::size_of::<u32>(), |total, size| {
            total
                .checked_add(std::mem::size_of::<u32>())
                .and_then(|value| value.checked_add(size))
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeDaSingleTransferDecision {
    ContributionOverflow,
    IndividuallyTooLarge { contribution: usize },
    Admissible { contribution: usize },
}

pub(crate) fn classify_native_da_single_transfer(
    max_blob_bytes: usize,
    contribution: Option<usize>,
) -> NativeDaSingleTransferDecision {
    let Some(contribution) = contribution else {
        return NativeDaSingleTransferDecision::ContributionOverflow;
    };
    let single_tx_blob_bytes = std::mem::size_of::<u32>()
        .checked_add(contribution)
        .unwrap_or(usize::MAX);
    if single_tx_blob_bytes > max_blob_bytes {
        NativeDaSingleTransferDecision::IndividuallyTooLarge { contribution }
    } else {
        NativeDaSingleTransferDecision::Admissible { contribution }
    }
}

pub(crate) fn select_native_da_capacity_prefix<T>(
    actions: &[T],
    max_blob_bytes: usize,
    max_action_count: usize,
    max_action_bytes: usize,
    reserved_action_count: usize,
    reserved_action_bytes: usize,
    is_transfer: impl Fn(&T) -> bool,
    transfer_contribution: impl Fn(&T) -> Option<usize>,
    encoded_action_bytes: impl Fn(&T) -> usize,
) -> std::result::Result<NativeDaCapacitySelection, NativeDaCapacitySelectionError> {
    if reserved_action_count > max_action_count {
        return Err(NativeDaCapacitySelectionError::ReservedActionCount);
    }
    if reserved_action_bytes > max_action_bytes {
        return Err(NativeDaCapacitySelectionError::ReservedActionBytes);
    }
    let mut blob_bytes = std::mem::size_of::<u32>();
    let mut selected_indices = Vec::new();
    let mut individually_unencodable_indices = Vec::new();
    let mut deferred_indices = Vec::new();
    let mut stopped_at_index = None;
    let mut count_stopped_at_index = None;
    let mut transfer_capacity_exhausted = false;
    let mut selected_action_count = reserved_action_count;
    let mut selected_action_bytes = reserved_action_bytes;

    for (index, action) in actions.iter().enumerate() {
        let transfer_contribution = if is_transfer(action) {
            match classify_native_da_single_transfer(max_blob_bytes, transfer_contribution(action))
            {
                NativeDaSingleTransferDecision::ContributionOverflow
                | NativeDaSingleTransferDecision::IndividuallyTooLarge { .. } => {
                    individually_unencodable_indices.push(index);
                    continue;
                }
                NativeDaSingleTransferDecision::Admissible { contribution } => Some(contribution),
            }
        } else {
            None
        };
        if transfer_contribution.is_some() && transfer_capacity_exhausted {
            deferred_indices.push(index);
            continue;
        }
        let next_blob_bytes = if let Some(contribution) = transfer_contribution {
            match blob_bytes.checked_add(contribution) {
                Some(value) if value <= max_blob_bytes => value,
                _ => {
                    stopped_at_index = Some(index);
                    transfer_capacity_exhausted = true;
                    deferred_indices.push(index);
                    continue;
                }
            }
        } else {
            blob_bytes
        };
        if selected_action_count == max_action_count {
            count_stopped_at_index = Some(index);
            deferred_indices.extend(index..actions.len());
            break;
        }
        let action_bytes = encoded_action_bytes(action);
        let Some(next_action_bytes) = selected_action_bytes.checked_add(action_bytes) else {
            deferred_indices.push(index);
            continue;
        };
        if next_action_bytes > max_action_bytes {
            deferred_indices.push(index);
            continue;
        }
        blob_bytes = next_blob_bytes;
        selected_action_count += 1;
        selected_action_bytes = next_action_bytes;
        selected_indices.push(index);
    }

    Ok(NativeDaCapacitySelection {
        selected_indices,
        individually_unencodable_indices,
        deferred_indices,
        blob_bytes,
        stopped_at_index,
        count_stopped_at_index,
        selected_action_count,
        selected_action_bytes,
    })
}

#[cfg(test)]
pub(crate) fn select_native_da_action_prefix(
    actions: &[PendingAction],
) -> Result<NativeDaActionSelection> {
    select_native_da_action_prefix_with_reservation(actions, 0, 0, 0)
}

pub(crate) fn select_native_da_action_prefix_with_reservation(
    actions: &[PendingAction],
    reserved_action_count: usize,
    reserved_action_bytes: usize,
    reserved_v8_proof_actions: usize,
) -> Result<NativeDaActionSelection> {
    let max_blob_bytes = state_da::max_da_blob_bytes(max_native_da_params())
        .map_err(|err| anyhow!("derive native DA blob capacity failed: {err}"))?;
    let capacity_selection = select_native_da_capacity_prefix(
        actions,
        max_blob_bytes,
        MAX_NATIVE_BLOCK_ACTIONS,
        MAX_NATIVE_BLOCK_ACTION_BYTES,
        reserved_action_count,
        reserved_action_bytes,
        is_legacy_shielded_transfer_action,
        |action| {
            native_da_transfer_blob_contribution(
                action.ciphertext_sizes.iter().map(|size| *size as usize),
            )
        },
        PendingAction::encoded_size,
    )
    .map_err(|rejection| match rejection {
        NativeDaCapacitySelectionError::ReservedActionCount => anyhow!(
            "native reserved block action count {reserved_action_count} exceeds {MAX_NATIVE_BLOCK_ACTIONS}"
        ),
        NativeDaCapacitySelectionError::ReservedActionBytes => anyhow!(
            "native reserved block action bytes {reserved_action_bytes} exceeds {MAX_NATIVE_BLOCK_ACTION_BYTES}"
        ),
    })?;
    let selected_indices =
        retain_capacity_selected_v8_prefix(actions, &capacity_selection.selected_indices);
    let selected_indices = retain_selected_v8_proof_action_budget(
        actions,
        &selected_indices,
        reserved_v8_proof_actions,
    )?;
    let selected = selected_indices
        .into_iter()
        .map(|index| actions[index].clone())
        .collect();
    let individually_unencodable = capacity_selection
        .individually_unencodable_indices
        .into_iter()
        .map(|index| actions[index].clone())
        .collect();

    Ok(NativeDaActionSelection {
        selected,
        individually_unencodable,
    })
}

fn retain_selected_v8_proof_action_budget(
    actions: &[PendingAction],
    selected_indices: &[usize],
    reserved_v8_proof_actions: usize,
) -> Result<Vec<usize>> {
    let maximum_transactions = MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK
        .checked_sub(reserved_v8_proof_actions)
        .ok_or_else(|| {
            anyhow!(
                "native reserved V8 proof-authority action count {reserved_v8_proof_actions} exceeds {MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK}"
            )
        })?;
    let mut selected_transactions = 0usize;
    Ok(selected_indices
        .iter()
        .copied()
        .filter(|index| {
            if !is_poseidon2_v8_action(&actions[*index]) {
                return true;
            }
            selected_transactions += 1;
            selected_transactions <= maximum_transactions
        })
        .collect())
}

fn retain_capacity_selected_v8_prefix(
    actions: &[PendingAction],
    capacity_selected_indices: &[usize],
) -> Vec<usize> {
    let capacity_selected = capacity_selected_indices
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    // V8 actions have already been placed in canonical root-dependency order
    // by the source-bound pending planner. The generic mixed-action capacity
    // selector may skip an action that does not fit and continue with a later,
    // smaller action. That is valid for independent routes, but a later V8
    // action may depend on the skipped transition. Retain only the contiguous
    // selected V8 prefix while leaving non-V8 selection unchanged.
    let mut v8_prefix_open = true;
    actions
        .iter()
        .enumerate()
        .filter_map(|(index, action)| {
            let selected = capacity_selected.contains(&index);
            if is_poseidon2_v8_action(action) {
                if !v8_prefix_open {
                    return None;
                }
                if !selected {
                    v8_prefix_open = false;
                    return None;
                }
            }
            selected.then_some(index)
        })
        .collect()
}

pub(crate) fn validate_poseidon2_v8_replay_window(
    production: poseidon2_v8_verifier::Poseidon2V8ProductionBinding,
    height: u64,
    actions: &[PendingAction],
) -> Result<()> {
    if actions.iter().any(action_uses_poseidon2_v8_state) && !production.active_at(height) {
        return Err(anyhow!(
            "native V8 replay carries a proof-bearing action outside the source-authorized lifetime at height {height}"
        ));
    }
    Ok(())
}

/// Borrowed prefix of `NativeSyncMessage`. The `Response` discriminant and
/// field order are identical to the owned wire enum, so size accounting does
/// not clone block bodies or allocate a second response frame.
#[derive(Serialize)]
enum BorrowedNativeSyncResponse<'a> {
    Announce(&'a NativeBlockMeta),
    Request {
        from_height: u64,
        to_height: u64,
    },
    Response {
        best_height: u64,
        blocks: &'a [NativeBlockMeta],
    },
}

#[derive(Clone, Copy, Debug)]
struct NativeSyncResponseWireSizer {
    inner_fixed_bytes: usize,
    outer_fixed_bytes: usize,
    block_count: usize,
    block_body_bytes: usize,
}

impl NativeSyncResponseWireSizer {
    fn new(best_height: u64) -> Result<Self> {
        let empty_response = BorrowedNativeSyncResponse::Response {
            best_height,
            blocks: &[],
        };
        let empty_payload_bytes = wire::encoded_len(&empty_response, MAX_NATIVE_SYNC_MESSAGE_BYTES)
            .context("measure empty borrowed native sync response")?;
        let inner_fixed_bytes = empty_payload_bytes
            .checked_sub(postcard_varint_usize_bytes(0))
            .ok_or_else(|| anyhow!("native sync response fixed length underflow"))?;
        let empty_wire_message = WireMessage::Proto(ProtocolMessage {
            protocol: NATIVE_SYNC_PROTOCOL_ID,
            payload: Vec::new(),
        });
        let empty_frame_bytes = wire::encoded_len(&empty_wire_message, wire::MAX_WIRE_FRAME_LEN)
            .context("measure native sync protocol wire envelope")?;
        let outer_fixed_bytes = empty_frame_bytes
            .checked_sub(postcard_varint_usize_bytes(0))
            .ok_or_else(|| anyhow!("native sync protocol fixed length underflow"))?;
        Ok(Self {
            inner_fixed_bytes,
            outer_fixed_bytes,
            block_count: 0,
            block_body_bytes: 0,
        })
    }

    fn try_push_block(&mut self, block: &NativeBlockMeta) -> Result<Option<usize>> {
        let framed_block_bytes =
            wire::encoded_len(block, usize::MAX).context("measure native sync response block")?;
        let block_body_bytes = framed_block_bytes
            .checked_sub(wire::NETWORK_WIRE_MAGIC.len())
            .ok_or_else(|| anyhow!("native sync response block length underflow"))?;
        let next_count = self
            .block_count
            .checked_add(1)
            .ok_or_else(|| anyhow!("native sync response block count overflow"))?;
        let next_body_bytes = self
            .block_body_bytes
            .checked_add(block_body_bytes)
            .ok_or_else(|| anyhow!("native sync response body length overflow"))?;
        let payload_bytes = self
            .inner_fixed_bytes
            .checked_add(postcard_varint_usize_bytes(next_count))
            .and_then(|bytes| bytes.checked_add(next_body_bytes))
            .ok_or_else(|| anyhow!("native sync response payload length overflow"))?;
        if payload_bytes > MAX_NATIVE_SYNC_MESSAGE_BYTES {
            return Ok(None);
        }
        let frame_bytes = self
            .outer_fixed_bytes
            .checked_add(postcard_varint_usize_bytes(payload_bytes))
            .and_then(|bytes| bytes.checked_add(payload_bytes))
            .ok_or_else(|| anyhow!("native sync protocol wire length overflow"))?;
        let encrypted_bytes = frame_bytes
            .checked_add(AES_GCM_TAG_BYTES)
            .ok_or_else(|| anyhow!("native sync encrypted frame length overflow"))?;
        if encrypted_bytes > wire::MAX_WIRE_FRAME_LEN {
            return Ok(None);
        }
        self.block_count = next_count;
        self.block_body_bytes = next_body_bytes;
        Ok(Some(encrypted_bytes))
    }
}

fn postcard_varint_usize_bytes(mut value: usize) -> usize {
    let mut bytes = 1usize;
    while value >= 128 {
        value >>= 7;
        bytes = bytes.saturating_add(1);
    }
    bytes
}

pub(crate) fn load_native_sync_response_prefix_with<F>(
    best_height: u64,
    range: NativeSyncRange,
    initial_parent_hash: Option<[u8; 32]>,
    mut load_block: F,
) -> Result<(Vec<NativeBlockMeta>, bool, Option<NativeSyncChunkOffer>)>
where
    F: FnMut(u64) -> Result<NativeBlockMeta>,
{
    let mut blocks = Vec::new();
    let mut wire_sizer = NativeSyncResponseWireSizer::new(best_height)?;
    let mut expected_parent_hash = initial_parent_hash;
    let mut previous_parent_anchor_verified = range.from_height == 0;
    let mut oversized_first_block = None;

    for height in range.from_height..=range.to_height {
        let meta = load_block(height)?;
        if let Some(expected_parent_hash) = expected_parent_hash {
            if meta.parent_hash != expected_parent_hash {
                return Err(anyhow!(
                    "canonical native block parent mismatch at height {}: expected {}, got {}",
                    height,
                    hex32(&expected_parent_hash),
                    hex32(&meta.parent_hash)
                ));
            }
            if height == range.from_height {
                previous_parent_anchor_verified = true;
            }
        }

        let wire_bytes = match wire_sizer.try_push_block(&meta)? {
            Some(wire_bytes) => wire_bytes,
            None => {
                if blocks.is_empty() {
                    oversized_first_block = Some(NativeSyncChunkOffer {
                        height: meta.height,
                        block_hash: meta.hash,
                    });
                }
                break;
            }
        };
        if wire_bytes > MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES && !blocks.is_empty() {
            break;
        }
        expected_parent_hash = Some(meta.hash);
        blocks.push(meta);
        if wire_bytes > MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES {
            // Preserve the historical guarantee that a single publishable
            // block can cross the soft response target. The hard encrypted
            // transport cap was already checked by `try_push_block`.
            break;
        }
    }

    Ok((
        blocks,
        previous_parent_anchor_verified,
        oversized_first_block,
    ))
}

#[derive(Debug, Deserialize)]
struct NativeStoredPowPrefix<'a> {
    chain_id: [u8; 32],
    rules_hash: [u8; 32],
    height: u64,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    #[serde(borrow, with = "serde_bytes")]
    state_root: &'a [u8; 48],
    #[serde(borrow, with = "serde_bytes")]
    kernel_root: &'a [u8; 48],
    #[serde(borrow, with = "serde_bytes")]
    nullifier_root: &'a [u8; 48],
    extrinsics_root: [u8; 32],
    #[serde(borrow, with = "serde_bytes")]
    message_root: &'a [u8; 48],
    message_count: u32,
    header_mmr_root: [u8; 32],
    header_mmr_len: u64,
    timestamp_ms: u64,
    pow_bits: u32,
    nonce: [u8; 32],
    work_hash: [u8; 32],
    #[serde(borrow, with = "serde_bytes")]
    cumulative_work: &'a [u8; 48],
    supply_digest: u128,
    tx_count: u32,
}

impl NativeStoredPowPrefix<'_> {
    fn matches(&self, meta: &NativeBlockMeta) -> bool {
        self.chain_id == meta.chain_id
            && self.rules_hash == meta.rules_hash
            && self.height == meta.height
            && self.hash == meta.hash
            && self.parent_hash == meta.parent_hash
            && *self.state_root == meta.state_root
            && *self.kernel_root == meta.kernel_root
            && *self.nullifier_root == meta.nullifier_root
            && self.extrinsics_root == meta.extrinsics_root
            && *self.message_root == meta.message_root
            && self.message_count == meta.message_count
            && self.header_mmr_root == meta.header_mmr_root
            && self.header_mmr_len == meta.header_mmr_len
            && self.timestamp_ms == meta.timestamp_ms
            && self.pow_bits == meta.pow_bits
            && self.nonce == meta.nonce
            && self.work_hash == meta.work_hash
            && *self.cumulative_work == meta.cumulative_work
            && self.supply_digest == meta.supply_digest
            && self.tx_count == meta.tx_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativePowMetaProjection {
    chain_id: [u8; 32],
    rules_hash: [u8; 32],
    height: u64,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    timestamp_ms: u64,
    pow_bits: u32,
    work_hash: [u8; 32],
    cumulative_work: [u8; 48],
}

impl From<&NativeBlockMeta> for NativePowMetaProjection {
    fn from(meta: &NativeBlockMeta) -> Self {
        Self {
            chain_id: meta.chain_id,
            rules_hash: meta.rules_hash,
            height: meta.height,
            hash: meta.hash,
            parent_hash: meta.parent_hash,
            timestamp_ms: meta.timestamp_ms,
            pow_bits: meta.pow_bits,
            work_hash: meta.work_hash,
            cumulative_work: meta.cumulative_work,
        }
    }
}

#[cfg(test)]
struct NativeStreamingStoredMetaDecodeGuard<'a> {
    node: &'a NativeNode,
}

#[cfg(test)]
impl Drop for NativeStreamingStoredMetaDecodeGuard<'_> {
    fn drop(&mut self) {
        let previous = self
            .node
            .streaming_replay_live_stored_meta_count
            .fetch_sub(1, Ordering::Relaxed);
        debug_assert!(
            previous > 0,
            "streaming replay stored-meta counter underflow"
        );
    }
}

fn required_bincode_len(
    bytes: &[u8],
    cursor: &mut usize,
    label: &str,
    field: &str,
) -> Result<usize> {
    let len = read_bincode_fixint_len(bytes, *cursor)?
        .ok_or_else(|| anyhow!("{label} is truncated before {field} length"))?;
    *cursor = cursor
        .checked_add(BINCODE_FIXINT_VEC_LEN_BYTES)
        .ok_or_else(|| anyhow!("{label} {field} length cursor overflow"))?;
    Ok(len)
}

fn required_bincode_bytes<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
    label: &str,
    field: &str,
) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| anyhow!("{label} {field} payload cursor overflow"))?;
    if end > bytes.len() {
        return Err(anyhow!(
            "{label} is truncated in {field} payload: need {end} bytes, got {}",
            bytes.len()
        ));
    }
    let payload = &bytes[*cursor..end];
    *cursor = end;
    Ok(payload)
}

fn required_bincode_u32(bytes: &[u8], cursor: &mut usize, label: &str, field: &str) -> Result<u32> {
    let raw: [u8; 4] = required_bincode_bytes(bytes, cursor, 4, label, field)?
        .try_into()
        .expect("four-byte bincode u32 slice");
    Ok(u32::from_le_bytes(raw))
}

fn required_bincode_u64(bytes: &[u8], cursor: &mut usize, label: &str, field: &str) -> Result<u64> {
    let raw: [u8; 8] = required_bincode_bytes(bytes, cursor, 8, label, field)?
        .try_into()
        .expect("eight-byte bincode u64 slice");
    Ok(u64::from_le_bytes(raw))
}

fn inspect_native_pow_metadata_bincode_exact(
    bytes: &[u8],
    expected: Option<&NativeBlockMeta>,
    label: &str,
) -> Result<(NativePowMetaProjection, bool)> {
    validate_native_block_meta_bincode_budget(bytes, label)?;
    let prefix_bytes = bytes
        .get(..NATIVE_BLOCK_META_ACTION_BYTES_OFFSET)
        .ok_or_else(|| anyhow!("{label} is truncated before its action byte count"))?;
    let prefix: NativeStoredPowPrefix<'_> = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(NATIVE_BLOCK_META_ACTION_BYTES_OFFSET as u64)
        .deserialize(prefix_bytes)
        .map_err(|err| anyhow!("decode {label} PoW metadata prefix failed: {err}"))?;
    let projection = NativePowMetaProjection {
        chain_id: prefix.chain_id,
        rules_hash: prefix.rules_hash,
        height: prefix.height,
        hash: prefix.hash,
        parent_hash: prefix.parent_hash,
        timestamp_ms: prefix.timestamp_ms,
        pow_bits: prefix.pow_bits,
        work_hash: prefix.work_hash,
        cumulative_work: *prefix.cumulative_work,
    };
    let mut exact_match = expected.is_none_or(|meta| prefix.matches(meta));
    let mut cursor = NATIVE_BLOCK_META_ACTION_BYTES_OFFSET;
    let action_count = required_bincode_len(bytes, &mut cursor, label, "action byte count")?;
    if action_count > MAX_NATIVE_BLOCK_ACTIONS {
        return Err(anyhow!(
            "{label} action byte count exceeds limit: {action_count} > {MAX_NATIVE_BLOCK_ACTIONS}"
        ));
    }
    if let Some(meta) = expected {
        exact_match &= action_count == meta.action_bytes.len();
    }
    let mut total_action_bytes = 0usize;
    for index in 0..action_count {
        let action_len = required_bincode_len(bytes, &mut cursor, label, "action byte payload")?;
        if action_len > MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES {
            return Err(anyhow!(
                "{label} action payload {index} exceeds limit: {action_len} > {MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES}"
            ));
        }
        total_action_bytes = total_action_bytes
            .checked_add(action_len)
            .ok_or_else(|| anyhow!("{label} action byte total overflow"))?;
        if total_action_bytes > MAX_NATIVE_BLOCK_ACTION_BYTES {
            return Err(anyhow!(
                "{label} action bytes exceed aggregate limit: {total_action_bytes} > {MAX_NATIVE_BLOCK_ACTION_BYTES}"
            ));
        }
        let action =
            required_bincode_bytes(bytes, &mut cursor, action_len, label, "action byte payload")?;
        if let Some(meta) = expected {
            exact_match &= meta
                .action_bytes
                .get(index)
                .is_some_and(|expected_action| expected_action.as_slice() == action);
        }
    }

    let da_root_len = required_bincode_len(bytes, &mut cursor, label, "DA root")?;
    if da_root_len != 48 {
        return Err(anyhow!(
            "{label} DA root has invalid length {da_root_len}, expected 48"
        ));
    }
    let da_root = required_bincode_bytes(bytes, &mut cursor, da_root_len, label, "DA root")?;
    let da_chunk_size = required_bincode_u32(bytes, &mut cursor, label, "DA chunk size")?;
    let da_sample_count = required_bincode_u32(bytes, &mut cursor, label, "DA sample count")?;
    let da_blob_len = required_bincode_u64(bytes, &mut cursor, label, "DA blob length")?;
    let da_chunk_count = required_bincode_u32(bytes, &mut cursor, label, "DA chunk count")?;
    if cursor != bytes.len() {
        return Err(anyhow!(
            "{label} has {} trailing bytes after native metadata",
            bytes.len().saturating_sub(cursor)
        ));
    }
    if let Some(meta) = expected {
        exact_match &= meta.da_root.as_slice() == da_root
            && meta.da_chunk_size == da_chunk_size
            && meta.da_sample_count == da_sample_count
            && meta.da_blob_len == da_blob_len
            && meta.da_chunk_count == da_chunk_count;
    }
    Ok((projection, exact_match))
}

impl NativeNode {
    pub fn open(config: NativeConfig) -> Result<Arc<Self>> {
        let startup_started = Instant::now();
        info!(
            base_path = %config.base_path.display(),
            db_path = %config.db_path.display(),
            "opening native Hegemon node storage"
        );
        fs::create_dir_all(&config.base_path)
            .with_context(|| format!("create native base path {}", config.base_path.display()))?;
        let db_open_started = Instant::now();
        let db = sled::open(&config.db_path)
            .with_context(|| format!("open native sled db {}", config.db_path.display()))?;
        info!(
            db_open_elapsed_ms = db_open_started.elapsed().as_millis(),
            "native sled database opened"
        );
        validate_native_tree_namespace_before_open(&db)?;
        let meta_tree = db.open_tree("meta")?;
        let height_tree = db.open_tree("block_hash_by_height")?;
        let block_tree = db.open_tree("block_meta_by_hash")?;
        let action_tree = db.open_tree("mempool_actions")?;
        let nullifier_tree = db.open_tree("shielded_nullifiers")?;
        let commitment_tree = db.open_tree("shielded_commitments")?;
        let bridge_inbound_tree = db.open_tree("bridge_inbound_messages")?;
        let ciphertext_index_tree = db.open_tree("shielded_ciphertext_index")?;
        let ciphertext_archive_tree = db.open_tree("shielded_ciphertexts_by_index")?;
        let da_ciphertext_tree = db.open_tree("da_pending_ciphertexts")?;
        let da_proof_tree = db.open_tree("da_pending_proofs")?;
        // The tree exists on every fresh node, but remains empty while the
        // single release capability is absent. This permits a later reviewed
        // activation to include typed V8 rows in the existing canonical sled
        // transaction without a namespace race or legacy-width migration.
        let poseidon2_v8_tree = db.open_tree(poseidon2_v8_state::POSEIDON2_V8_STATE_TREE_NAME)?;

        let best =
            load_best_or_genesis(&db, &meta_tree, &height_tree, &block_tree, config.pow_bits)?;
        let canonical_chain = validate_loaded_block_indexes(
            &best,
            &meta_tree,
            &height_tree,
            &block_tree,
            config.pow_bits,
        )?;
        let pending_actions = load_pending_actions(&action_tree)?;
        let loaded_nullifiers = load_nullifiers(&nullifier_tree, &meta_tree)?;
        let commitment_state = load_commitment_tree(&commitment_tree)?;
        validate_loaded_canonical_state(
            &best,
            &commitment_state,
            &loaded_nullifiers.nullifiers,
            &loaded_nullifiers.accumulator,
        )?;
        let consumed_bridge_messages: PersistentKeySet48 =
            load_consumed_bridge_messages(&bridge_inbound_tree)?.into();
        validate_loaded_bridge_replay_state(&canonical_chain, &consumed_bridge_messages)?;
        let staged_ciphertexts = load_staged_sizes(&db, &da_ciphertext_tree)?;
        let staged_proofs = load_staged_proofs(&db, &da_proof_tree)?;
        let header_mmr_peaks = load_header_mmr_peaks_for_best(&canonical_chain, &best)?;
        let startup_state = build_validated_startup_state(
            &db,
            &action_tree,
            best,
            header_mmr_peaks,
            pending_actions,
            commitment_state,
            loaded_nullifiers.nullifiers,
            loaded_nullifiers.accumulator,
            consumed_bridge_messages,
            staged_ciphertexts,
            staged_proofs,
            true,
        )?;
        info!(
            startup_reload_elapsed_ms = startup_started.elapsed().as_millis(),
            "native Hegemon node storage reload completed"
        );

        let initial_mining_sync_gate_open = config.bootstrap_mining_authoring
            || (config.seeds.is_empty() && config.permits_empty_seed_authoring());
        let node = Arc::new(Self {
            config,
            db,
            meta_tree,
            height_tree,
            block_tree,
            action_tree,
            nullifier_tree,
            commitment_tree,
            bridge_inbound_tree,
            ciphertext_index_tree,
            ciphertext_archive_tree,
            da_ciphertext_tree,
            da_proof_tree,
            poseidon2_v8_tree,
            state: RwLock::new(startup_state),
            start_instant: Instant::now(),
            mining: AtomicBool::new(false),
            mining_threads: AtomicU32::new(0),
            mining_round: AtomicU64::new(0),
            mining_hashes: AtomicU64::new(0),
            blocks_found: AtomicU64::new(0),
            canonical_state_generation: AtomicU64::new(0),
            last_announce_height: AtomicU64::new(0),
            pending_action_rebroadcast_cursor: AtomicU64::new(0),
            sync_target_height: AtomicU64::new(0),
            sync_target_observed: AtomicBool::new(initial_mining_sync_gate_open),
            sync_target_peer: Mutex::new(None),
            sync_target_hash: Mutex::new(None),
            sync_target_unverified_peer_hint: AtomicBool::new(false),
            sync_unverified_target_deferred_during_import: Mutex::new(None),
            sync_unverified_target_cooldowns: Mutex::new(BTreeMap::new()),
            sync_reorg_backfill_blocks: AtomicU64::new(NATIVE_SYNC_REORG_BACKFILL_BLOCKS),
            mining_sync_gate_open: AtomicBool::new(initial_mining_sync_gate_open),
            sync_import_in_flight: AtomicBool::new(false),
            network_peer_count: Arc::new(AtomicUsize::new(0)),
            network_local_peer_id: Arc::new(StdRwLock::new(None)),
            network_peer_snapshot: Arc::new(StdRwLock::new(Vec::new())),
            sync_request_rate_limits: Mutex::new(BTreeMap::new()),
            outbound_sync_request_rate_limits: Mutex::new(BTreeMap::new()),
            sync_response_in_flight_peers: Mutex::new(BTreeMap::new()),
            outbound_sync_requests: Mutex::new(BTreeMap::new()),
            sync_recovery_cursor: Mutex::new(None),
            sync_chunk_sessions: Mutex::new(NativeSyncChunkSessions::default()),
            sync_chunk_receive_in_flight_peers: Mutex::new(BTreeSet::new()),
            mining_tasks: Mutex::new(Vec::new()),
            sync_tx: Mutex::new(None),
            pending_proof_admission_semaphore: Arc::new(Semaphore::new(
                MAX_NATIVE_PENDING_PROOF_ADMISSIONS_IN_FLIGHT,
            )),
            peer_pending_proof_admission_semaphore: Arc::new(Semaphore::new(
                MAX_NATIVE_PEER_PENDING_PROOF_ADMISSIONS_IN_FLIGHT,
            )),
            local_pending_proof_admission_semaphore: Arc::new(Semaphore::new(
                MAX_NATIVE_LOCAL_PENDING_PROOF_ADMISSIONS_IN_FLIGHT,
            )),
            work_template_proof_semaphore: Arc::new(Semaphore::new(
                MAX_NATIVE_WORK_TEMPLATE_PROOFS_IN_FLIGHT,
            )),
            block_import_semaphore: Arc::new(Semaphore::new(MAX_NATIVE_BLOCK_IMPORTS_IN_FLIGHT)),
            canonical_import_lock: Mutex::new(()),
            pending_action_persistence_lock: Mutex::new(()),
            block_store_persistence_lock: Mutex::new(()),
            pending_action_generation: AtomicU64::new(0),
            native_storage_poisoned: AtomicBool::new(false),
            work_template_build_lock: Mutex::new(()),
            work_template_cache: Mutex::new(None),
            pending_action_group_commit: NativePendingActionGroupCommit::default(),
            pending_proof_admissions_in_flight: Arc::new(Mutex::new(BTreeSet::new())),
            rejected_pending_actions: Mutex::new(RejectedPendingActionCache::default()),
            block_body_send_cache: Mutex::new(NativeBlockBodySendCache::default()),
            da_encoding_cache: Mutex::new(NativeDaEncodingCache::default()),
            da_encoding_build_lock: Mutex::new(()),
            in_process_verified_blocks: Mutex::new(NativeVerifiedBlockCache::default()),
            in_process_canonical_checkpoints: Mutex::new(NativeCanonicalCheckpointCache::default()),
            #[cfg(test)]
            best_meta_clone_invocations: AtomicU64::new(0),
            #[cfg(test)]
            full_block_body_load_invocations: AtomicU64::new(0),
            #[cfg(test)]
            independent_proof_backend_invocations: AtomicU64::new(0),
            #[cfg(test)]
            work_template_build_invocations: AtomicU64::new(0),
            #[cfg(test)]
            pending_action_group_commit_test: NativePendingActionGroupCommitTestControl::default(),
            #[cfg(test)]
            header_history_rebuild_invocations: AtomicU64::new(0),
            #[cfg(test)]
            historical_block_proof_replay_invocations: AtomicU64::new(0),
            #[cfg(test)]
            fail_next_canonical_readback: AtomicBool::new(false),
            #[cfg(test)]
            reorg_suffix_blocks_examined: AtomicU64::new(0),
            #[cfg(test)]
            reorg_suffix_body_bytes_examined: AtomicU64::new(0),
            #[cfg(test)]
            reorg_index_mutations: AtomicU64::new(0),
            #[cfg(test)]
            block_meta_load_count: AtomicU64::new(0),
            #[cfg(test)]
            block_meta_decode_count: AtomicU64::new(0),
            #[cfg(test)]
            chain_reconstruction_count: AtomicU64::new(0),
            #[cfg(test)]
            streaming_replay_live_stored_meta_count: AtomicU64::new(0),
            #[cfg(test)]
            streaming_replay_peak_stored_meta_count: AtomicU64::new(0),
            #[cfg(test)]
            sync_chunk_record_load_count: AtomicU64::new(0),
            #[cfg(test)]
            sync_chunk_record_decode_count: AtomicU64::new(0),
        });
        Self::ensure_ciphertext_archive_index(&node, &canonical_chain)?;
        node.sanitize_persisted_pending_smallwood_actions()?;
        // Apply repairable metadata only after every canonical PoW, miner,
        // state, bridge, index, pending-action, and proof startup gate above
        // has succeeded. A rejected open must not repair the genesis marker.
        apply_native_block_index_reload_repairs(
            &node.db,
            &node.meta_tree,
            node.config.pow_bits,
            canonical_chain.block_index_reload_admission(),
        )?;
        node.ensure_current_canonical_checkpoint()?;
        drop(canonical_chain);
        Ok(node)
    }

    #[cfg(test)]
    pub(crate) fn reopen_after_sled_release_for_test(config: NativeConfig) -> Result<Arc<Self>> {
        const MAX_ATTEMPTS: usize = 100;
        for attempt in 0..MAX_ATTEMPTS {
            match Self::open(config.clone()) {
                Ok(node) => return Ok(node),
                Err(err)
                    if attempt + 1 < MAX_ATTEMPTS
                        && err
                            .chain()
                            .any(|cause| cause.to_string().contains("could not acquire lock")) =>
                {
                    // sled releases its advisory file lock asynchronously on
                    // macOS once enough databases have churned in one process.
                    // Retry only that transient OS-lock error; every validation
                    // or corruption error remains immediate and unchanged.
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(err) => return Err(err),
            }
        }
        unreachable!("bounded native test reopen loop always returns")
    }

    fn ensure_native_storage_healthy(&self) -> Result<()> {
        if self.native_storage_poisoned.load(Ordering::Acquire) {
            return Err(anyhow!(
                "native storage is fail-stop poisoned after a durability uncertainty; restart the node to reload canonical state"
            ));
        }
        Ok(())
    }

    fn poison_native_storage(&self) {
        self.native_storage_poisoned.store(true, Ordering::Release);
    }

    pub(crate) fn set_sync_sender(&self, sync_tx: ProtocolSender) {
        *self.sync_tx.lock() = Some(sync_tx);
    }

    pub(crate) fn network_peer_count(&self) -> u32 {
        let count = self.network_peer_count.load(Ordering::Relaxed);
        count.min(u32::MAX as usize) as u32
    }

    pub(crate) fn set_network_local_peer_id(&self, peer_id: PeerId) {
        if let Ok(mut current) = self.network_local_peer_id.write() {
            *current = Some(peer_id);
        }
    }

    pub(crate) fn network_local_peer_id(&self) -> Option<PeerId> {
        self.network_local_peer_id
            .read()
            .ok()
            .and_then(|current| *current)
    }

    pub(crate) fn network_peer_snapshot(&self) -> Vec<ConnectedPeerSnapshot> {
        self.network_peer_snapshot
            .read()
            .map(|snapshot| snapshot.clone())
            .unwrap_or_default()
    }

    fn prune_native_sync_unverified_target_cooldowns(
        cooldowns: &mut BTreeMap<PeerId, Instant>,
        now: Instant,
    ) {
        cooldowns.retain(|_, expires_at| *expires_at > now);
    }

    fn native_sync_peer_has_unverified_target_cooldown(&self, peer_id: PeerId) -> bool {
        let now = Instant::now();
        let mut cooldowns = self.sync_unverified_target_cooldowns.lock();
        Self::prune_native_sync_unverified_target_cooldowns(&mut cooldowns, now);
        cooldowns.contains_key(&peer_id)
    }

    fn quarantine_native_sync_unverified_target_peer(&self, peer_id: PeerId, now: Instant) {
        let mut cooldowns = self.sync_unverified_target_cooldowns.lock();
        Self::prune_native_sync_unverified_target_cooldowns(&mut cooldowns, now);
        if MAX_NATIVE_SYNC_UNVERIFIED_TARGET_COOLDOWNS == 0 {
            return;
        }
        if cooldowns.len() >= MAX_NATIVE_SYNC_UNVERIFIED_TARGET_COOLDOWNS
            && !cooldowns.contains_key(&peer_id)
        {
            if let Some(evicted_peer) = cooldowns
                .iter()
                .min_by_key(|(_, expires_at)| **expires_at)
                .map(|(peer_id, _)| *peer_id)
            {
                cooldowns.remove(&evicted_peer);
            }
        }
        cooldowns.insert(
            peer_id,
            now.checked_add(NATIVE_SYNC_UNVERIFIED_TARGET_COOLDOWN)
                .unwrap_or(now),
        );
    }

    fn native_sync_outbound_request_is_fresh(
        request: &NativeOutboundSyncRequest,
        now: Instant,
    ) -> bool {
        request.state == NativeOutboundSyncRequestState::ChunkFallback
            || (matches!(
                request.state,
                NativeOutboundSyncRequestState::InFlight | NativeOutboundSyncRequestState::Paced
            ) && now.saturating_duration_since(request.requested_at)
                <= NATIVE_SYNC_REQUEST_RETRY_AFTER)
    }

    fn native_sync_target_peer_has_fresh_request(&self, peer_id: PeerId) -> bool {
        let now = Instant::now();
        self.outbound_sync_requests
            .lock()
            .get(&Some(peer_id))
            .is_some_and(|request| Self::native_sync_outbound_request_is_fresh(request, now))
    }

    pub(crate) fn outbound_sync_request_target_tip(
        &self,
        peer_id: PeerId,
    ) -> Option<(u64, [u8; 32])> {
        let requests = self.outbound_sync_requests.lock();
        [Some(peer_id), None].into_iter().find_map(|target| {
            requests
                .get(&target)
                .and_then(|request| request.context.target_tip)
        })
    }

    fn rebind_native_sync_target_peer_state(
        &self,
        previous_peer: PeerId,
        next_peer: PeerId,
        target_height: u64,
        target_hash: [u8; 32],
    ) {
        // A request authorized for the previous peer must not keep suppressing
        // an exact-target retry after that peer has timed out. A late response
        // from the previous peer will consequently fail request matching.
        self.outbound_sync_requests
            .lock()
            .remove(&Some(previous_peer));

        let mut cursor = self.sync_recovery_cursor.lock();
        let Some(current) = cursor.as_mut() else {
            return;
        };
        if current.peer_id == Some(previous_peer)
            && current.target_height == target_height
            && current.target_hash == Some(target_hash)
        {
            // The exact target hash commits the same recovery branch, so the
            // range and expected-parent binding remain valid for the new peer.
            current.peer_id = Some(next_peer);
        } else {
            // Never carry a peer-bound cursor across a different target tuple.
            *cursor = None;
        }
    }

    pub(crate) fn observe_verified_sync_peer_height(&self, peer_best_height: u64) {
        self.observe_verified_sync_peer_tip(None, peer_best_height, None);
    }

    pub(crate) fn observe_verified_sync_peer_tip(
        &self,
        peer_id: Option<PeerId>,
        peer_best_height: u64,
        peer_best_hash: Option<[u8; 32]>,
    ) {
        let best_height = self.state.read().best.height;
        let target_before = self.sync_target_height.load(Ordering::Relaxed);
        let mut target_peer_rebind = None;
        if peer_best_height > target_before {
            let mut target_hash = self.sync_target_hash.lock();
            let mut target_peer = self.sync_target_peer.lock();
            let current_target_height = self.sync_target_height.load(Ordering::Relaxed);
            if peer_best_height <= current_target_height {
                if peer_best_height == current_target_height {
                    if let Some(peer_best_hash) = peer_best_hash {
                        if target_hash.is_none_or(|current_hash| current_hash == peer_best_hash) {
                            let newly_anchored = target_hash.is_none();
                            let previous_peer = *target_peer;
                            self.mining_sync_gate_open.store(false, Ordering::SeqCst);
                            *target_hash = Some(peer_best_hash);
                            *target_peer = peer_id;
                            self.sync_target_unverified_peer_hint
                                .store(false, Ordering::Relaxed);
                            if let (Some(previous_peer), Some(next_peer)) = (previous_peer, peer_id)
                            {
                                if previous_peer != next_peer {
                                    self.rebind_native_sync_target_peer_state(
                                        previous_peer,
                                        next_peer,
                                        current_target_height,
                                        peer_best_hash,
                                    );
                                }
                            } else if newly_anchored || previous_peer != peer_id {
                                self.clear_sync_recovery_cursor();
                            }
                            drop(target_peer);
                            drop(target_hash);
                            self.sync_target_observed.store(true, Ordering::SeqCst);
                            self.refresh_mining_sync_gate();
                        }
                    }
                }
                return;
            }
            self.mining_sync_gate_open.store(false, Ordering::SeqCst);
            self.sync_target_height
                .store(peer_best_height, Ordering::Relaxed);
            self.sync_target_unverified_peer_hint
                .store(false, Ordering::Relaxed);
            // A verified height without that height's hash is still useful
            // progress evidence, but it must become an unanchored tuple.  In
            // particular, never carry the prior height's hash or peer forward.
            *target_hash = peer_best_hash;
            *target_peer = peer_best_hash.and(peer_id);
            self.clear_sync_recovery_cursor();
            drop(target_peer);
            drop(target_hash);
        } else if peer_best_height == target_before {
            if let Some(peer_best_hash) = peer_best_hash {
                let mut target_hash = self.sync_target_hash.lock();
                let mut target_peer = self.sync_target_peer.lock();
                if self.sync_target_height.load(Ordering::Relaxed) != target_before {
                    return;
                }
                if target_hash.is_some_and(|current_hash| current_hash != peer_best_hash) {
                    drop(target_peer);
                    drop(target_hash);
                    self.refresh_mining_sync_gate();
                    return;
                }
                if let (Some(current_peer), Some(observed_peer), Some(current_hash)) =
                    (*target_peer, peer_id, *target_hash)
                {
                    if current_peer != observed_peer {
                        debug_assert_eq!(current_hash, peer_best_hash);
                        target_peer_rebind = Some((
                            current_peer,
                            observed_peer,
                            peer_best_height,
                            peer_best_hash,
                        ));
                    }
                }
                self.mining_sync_gate_open.store(false, Ordering::SeqCst);
                self.sync_target_unverified_peer_hint
                    .store(false, Ordering::Relaxed);
                *target_hash = Some(peer_best_hash);
                *target_peer = peer_id;
                if let Some((previous_peer, next_peer, target_height, target_hash)) =
                    target_peer_rebind
                {
                    self.rebind_native_sync_target_peer_state(
                        previous_peer,
                        next_peer,
                        target_height,
                        target_hash,
                    );
                }
            }
        } else if peer_best_height <= best_height {
            self.clear_unanchored_sync_target_to_local_tip(
                peer_best_height,
                "verified local-tip sync evidence",
            );
        }
        if peer_best_height <= best_height {
            let mut target_hash = self.sync_target_hash.lock();
            let mut target_peer = self.sync_target_peer.lock();
            let target = self.sync_target_height.load(Ordering::Relaxed);
            if target <= best_height {
                *target_hash = None;
                *target_peer = None;
                self.sync_target_unverified_peer_hint
                    .store(false, Ordering::Relaxed);
                self.clear_sync_recovery_cursor();
                drop(target_peer);
                drop(target_hash);
            }
        }
        self.sync_target_observed.store(true, Ordering::SeqCst);
        self.refresh_mining_sync_gate();
    }

    pub(crate) fn clear_unanchored_sync_target_to_local_tip(
        &self,
        evidence_peer_height: u64,
        reason: &'static str,
    ) -> bool {
        let best_height = self.state.read().best.height;
        let target_hash = self.sync_target_hash.lock();
        let mut target_peer = self.sync_target_peer.lock();
        let target = self.sync_target_height.load(Ordering::Relaxed);
        if target <= best_height {
            return false;
        }
        if target_hash.is_some() {
            return false;
        }
        self.mining_sync_gate_open.store(false, Ordering::SeqCst);
        self.sync_target_height
            .store(best_height, Ordering::Relaxed);
        *target_peer = None;
        self.sync_target_unverified_peer_hint
            .store(false, Ordering::Relaxed);
        self.clear_sync_recovery_cursor();
        drop(target_peer);
        drop(target_hash);
        info!(
            target,
            local_height = best_height,
            evidence_peer_height,
            reason,
            "cleared unanchored native sync target"
        );
        true
    }

    pub(crate) fn clear_hash_anchored_sync_target_to_local_tip(
        &self,
        evidence_peer_height: u64,
        evidence_hash: [u8; 32],
        reason: &'static str,
    ) -> bool {
        let best_height = self.state.read().best.height;
        let mut target_hash = self.sync_target_hash.lock();
        let mut target_peer = self.sync_target_peer.lock();
        let target = self.sync_target_height.load(Ordering::Relaxed);
        if target < best_height {
            return false;
        }
        let Some(observed_target_hash) = *target_hash else {
            return false;
        };
        if observed_target_hash != evidence_hash {
            return false;
        }
        self.mining_sync_gate_open.store(false, Ordering::SeqCst);
        self.sync_target_height
            .store(best_height, Ordering::Relaxed);
        *target_peer = None;
        *target_hash = None;
        self.sync_target_unverified_peer_hint
            .store(false, Ordering::Relaxed);
        self.clear_sync_recovery_cursor();
        drop(target_peer);
        drop(target_hash);
        self.refresh_mining_sync_gate();
        info!(
            target,
            local_height = best_height,
            evidence_peer_height,
            evidence_hash = %hex32(&evidence_hash),
            reason,
            "cleared hash-anchored native sync target"
        );
        true
    }

    pub(crate) fn clear_stored_nonwinning_sync_target_to_local_tip(
        &self,
        peer_best_height: u64,
        expected_target: (u64, [u8; 32]),
    ) -> Result<bool> {
        // The response copy is untrusted until import has completed. Reload the
        // exact durable row so forged cumulative work or other supplied fields
        // can never resolve a target or reopen mining.
        let Some(target_meta) = self.header_by_hash(&expected_target.1)? else {
            return Ok(false);
        };
        if target_meta.height != expected_target.0 {
            return Err(anyhow!(
                "stored native sync target height mismatch for {}: expected {}, observed {}",
                hex32(&expected_target.1),
                expected_target.0,
                target_meta.height
            ));
        }

        let state = self.state.read();
        if native_meta_better_than(&target_meta, &state.best) {
            return Ok(false);
        }
        let best_height = state.best.height;
        let mut target_hash = self.sync_target_hash.lock();
        let mut target_peer = self.sync_target_peer.lock();
        let target_height = self.sync_target_height.load(Ordering::Relaxed);
        if target_height != expected_target.0 || *target_hash != Some(expected_target.1) {
            return Ok(false);
        }

        self.mining_sync_gate_open.store(false, Ordering::SeqCst);
        self.sync_target_height
            .store(best_height, Ordering::Relaxed);
        *target_peer = None;
        *target_hash = None;
        self.sync_target_unverified_peer_hint
            .store(false, Ordering::Relaxed);
        self.clear_sync_recovery_cursor();
        drop(target_peer);
        drop(target_hash);
        drop(state);
        self.refresh_mining_sync_gate();
        info!(
            target = expected_target.0,
            local_height = best_height,
            evidence_peer_height = peer_best_height,
            evidence_hash = %hex32(&expected_target.1),
            "cleared hash-anchored native sync target from validated durable non-winning evidence"
        );
        Ok(true)
    }

    #[cfg(test)]
    pub(crate) fn observe_pending_sync_peer_height(&self, peer_best_height: u64) {
        self.observe_pending_sync_peer_tip(None, peer_best_height, None);
    }

    pub(crate) fn observe_pending_sync_peer_tip(
        &self,
        peer_id: Option<PeerId>,
        peer_best_height: u64,
        peer_best_hash: Option<[u8; 32]>,
    ) -> bool {
        self.observe_pending_sync_peer_tip_with_provenance(
            peer_id,
            peer_best_height,
            peer_best_hash,
            peer_id.is_some() && peer_best_hash.is_some(),
        )
    }

    pub(crate) fn observe_scheduled_sync_peer_tip(
        &self,
        peer_id: Option<PeerId>,
        peer_best_height: u64,
        peer_best_hash: Option<[u8; 32]>,
    ) -> bool {
        // Scheduling another page cannot upgrade an unverified target. Only
        // exact imported/stored evidence may do that through the verified path.
        self.observe_pending_sync_peer_tip_with_provenance(
            peer_id,
            peer_best_height,
            peer_best_hash,
            false,
        )
    }

    fn observe_pending_sync_peer_tip_with_provenance(
        &self,
        peer_id: Option<PeerId>,
        peer_best_height: u64,
        peer_best_hash: Option<[u8; 32]>,
        unverified_peer_hint: bool,
    ) -> bool {
        if unverified_peer_hint
            && peer_id.is_some_and(|peer_id| {
                self.native_sync_peer_has_unverified_target_cooldown(peer_id)
            })
        {
            return false;
        }
        let (best_height, best_hash) = {
            let state = self.state.read();
            (state.best.height, state.best.hash)
        };
        let unresolved_equal_height_tip =
            peer_best_height == best_height && peer_best_hash.is_some_and(|hash| hash != best_hash);
        if peer_best_height < best_height
            || (peer_best_height == best_height && !unresolved_equal_height_tip)
        {
            return false;
        }
        let mut target_hash = self.sync_target_hash.lock();
        let mut target_peer = self.sync_target_peer.lock();
        if unverified_peer_hint
            && peer_id.is_some_and(|peer_id| {
                self.native_sync_peer_has_unverified_target_cooldown(peer_id)
            })
        {
            return false;
        }
        let target_before = self.sync_target_height.load(Ordering::Relaxed);
        let target_was_anchored = target_hash.is_some();
        let target_was_unverified = self
            .sync_target_unverified_peer_hint
            .load(Ordering::Relaxed);
        let mut target_peer_rebind = None;

        if peer_best_height < target_before {
            return false;
        }
        if unverified_peer_hint && peer_best_height > target_before {
            if let (Some(current_peer), Some(observed_peer)) = (*target_peer, peer_id) {
                if current_peer != observed_peer
                    && target_hash.is_some()
                    && self.native_sync_target_peer_has_fresh_request(current_peer)
                {
                    // Do not let a second unauthenticated hint supersede an
                    // exact target while its current peer is making progress.
                    return false;
                }
            }
        }
        if peer_best_height == target_before {
            if let (Some(current_hash), Some(observed_hash)) = (*target_hash, peer_best_hash) {
                if current_hash != observed_hash {
                    return false;
                }
            }
            if let (Some(current_peer), Some(observed_peer)) = (*target_peer, peer_id) {
                if current_peer != observed_peer && target_hash.is_some() {
                    let exact_same_target = peer_best_hash
                        .zip(*target_hash)
                        .is_some_and(|(observed_hash, current_hash)| observed_hash == current_hash);
                    if !exact_same_target
                        || self.native_sync_target_peer_has_fresh_request(current_peer)
                    {
                        return false;
                    }
                    target_peer_rebind = Some((
                        current_peer,
                        observed_peer,
                        peer_best_height,
                        peer_best_hash.expect("checked exact native sync target hash"),
                    ));
                }
            }
        } else if peer_best_hash.is_none() && target_hash.is_some() {
            // A height-only response cannot move a hash-anchored target: doing
            // so would pair the new height with the previous height's hash.
            return false;
        }

        let next_target_peer = if peer_best_height > target_before {
            peer_id
        } else {
            peer_id.or(*target_peer)
        };
        let target_peer_changed = *target_peer != next_target_peer;

        self.sync_target_observed.store(true, Ordering::SeqCst);
        self.mining_sync_gate_open.store(false, Ordering::SeqCst);
        self.sync_target_height
            .store(peer_best_height, Ordering::Relaxed);
        let next_unverified_peer_hint = if peer_best_height > target_before
            || (!target_was_anchored && peer_best_hash.is_some())
        {
            unverified_peer_hint
        } else {
            target_was_unverified
        };
        self.sync_target_unverified_peer_hint
            .store(next_unverified_peer_hint, Ordering::Relaxed);
        if peer_best_height > target_before {
            // Replace a growing target as one coherent evidence tuple.  In
            // particular, do not retain the prior height's peer or hash when
            // the new observation did not provide one.
            *target_peer = peer_id;
            *target_hash = peer_best_hash;
        } else {
            if let Some(peer_id) = peer_id {
                *target_peer = Some(peer_id);
            }
            if let Some(peer_best_hash) = peer_best_hash {
                *target_hash = Some(peer_best_hash);
            }
        }
        if let Some((previous_peer, next_peer, target_height, target_hash)) = target_peer_rebind {
            self.rebind_native_sync_target_peer_state(
                previous_peer,
                next_peer,
                target_height,
                target_hash,
            );
        } else if target_peer_changed {
            self.clear_sync_recovery_cursor();
        }
        drop(target_peer);
        drop(target_hash);
        true
    }

    pub(crate) fn sync_target_tip_snapshot(&self) -> (u64, Option<PeerId>, Option<[u8; 32]>) {
        let snapshot = self.sync_target_evidence_snapshot();
        (snapshot.height, snapshot.peer_id, snapshot.hash)
    }

    pub(crate) fn sync_target_evidence_snapshot(&self) -> NativeSyncTargetSnapshot {
        // Use the writer's lock order and load the height while both tuple
        // fields are stable, so readers cannot combine two observations.
        let target_hash = self.sync_target_hash.lock();
        let target_peer = self.sync_target_peer.lock();
        let target_height = self.sync_target_height.load(Ordering::Relaxed);
        let unverified_peer_hint = self
            .sync_target_unverified_peer_hint
            .load(Ordering::Relaxed);
        NativeSyncTargetSnapshot {
            height: target_height,
            peer_id: *target_peer,
            hash: *target_hash,
            unverified_peer_hint,
        }
    }

    pub(crate) fn defer_unverified_sync_target_during_import(
        &self,
        peer_id: PeerId,
        target_height: u64,
        target_hash: [u8; 32],
    ) -> bool {
        let snapshot = self.sync_target_evidence_snapshot();
        let expected = NativeSyncTargetSnapshot {
            height: target_height,
            peer_id: Some(peer_id),
            hash: Some(target_hash),
            unverified_peer_hint: true,
        };
        if snapshot != expected {
            return false;
        }
        *self.sync_unverified_target_deferred_during_import.lock() = Some(snapshot);
        true
    }

    fn consume_exact_deferred_unverified_sync_target(
        &self,
        current: NativeSyncTargetSnapshot,
    ) -> bool {
        let mut deferred = self.sync_unverified_target_deferred_during_import.lock();
        let matches = deferred
            .as_ref()
            .is_some_and(|deferred| *deferred == current);
        // The grace is deliberately one-shot. If scheduling cannot establish
        // a fresh request on this tick, ordinary expiry evicts on the next.
        *deferred = None;
        matches
    }

    fn evict_unverified_sync_target_exact(
        &self,
        peer_id: PeerId,
        expected_target: (u64, [u8; 32]),
        only_if_request_not_fresh: bool,
        reason: &'static str,
    ) -> bool {
        let best_height = self.state.read().best.height;
        let mut target_hash = self.sync_target_hash.lock();
        let mut target_peer = self.sync_target_peer.lock();
        let target_height = self.sync_target_height.load(Ordering::Relaxed);
        let current_snapshot = NativeSyncTargetSnapshot {
            height: target_height,
            peer_id: *target_peer,
            hash: *target_hash,
            unverified_peer_hint: self
                .sync_target_unverified_peer_hint
                .load(Ordering::Relaxed),
        };
        if current_snapshot
            != (NativeSyncTargetSnapshot {
                height: expected_target.0,
                peer_id: Some(peer_id),
                hash: Some(expected_target.1),
                unverified_peer_hint: true,
            })
        {
            return false;
        }

        let now = Instant::now();
        let mut requests = self.outbound_sync_requests.lock();
        if only_if_request_not_fresh
            && requests
                .get(&Some(peer_id))
                .is_some_and(|request| Self::native_sync_outbound_request_is_fresh(request, now))
        {
            return false;
        }

        // Keep the gate closed throughout eviction. A failed peer is not
        // evidence that the local tip has resolved the advertised target.
        self.mining_sync_gate_open.store(false, Ordering::SeqCst);
        requests.remove(&Some(peer_id));
        if requests
            .get(&None)
            .is_some_and(|request| request.context.target_tip == Some(expected_target))
        {
            requests.remove(&None);
        }
        let mut cursor = self.sync_recovery_cursor.lock();
        if cursor
            .as_ref()
            .is_some_and(|cursor| cursor.peer_id == Some(peer_id))
        {
            *cursor = None;
        }
        self.quarantine_native_sync_unverified_target_peer(peer_id, now);

        self.sync_target_height
            .store(best_height, Ordering::Relaxed);
        *target_peer = None;
        *target_hash = None;
        self.sync_target_unverified_peer_hint
            .store(false, Ordering::Relaxed);
        self.sync_target_observed.store(false, Ordering::SeqCst);

        drop(cursor);
        drop(requests);
        drop(target_peer);
        drop(target_hash);
        info!(
            peer = %hex32(&peer_id),
            target_height,
            target_hash = %hex32(&expected_target.1),
            local_height = best_height,
            reason,
            "evicted unverified native sync target"
        );
        true
    }

    pub(crate) fn evict_unverified_sync_target_after_terminal_failure(
        &self,
        peer_id: PeerId,
        expected_target: (u64, [u8; 32]),
        reason: &'static str,
    ) -> bool {
        self.evict_unverified_sync_target_exact(peer_id, expected_target, false, reason)
    }

    pub(crate) fn expire_unverified_sync_target(&self) -> bool {
        if self.sync_import_in_flight() {
            return false;
        }
        let snapshot = self.sync_target_evidence_snapshot();
        let deferred_during_import = self.consume_exact_deferred_unverified_sync_target(snapshot);
        let (Some(peer_id), Some(target_hash)) = (snapshot.peer_id, snapshot.hash) else {
            return false;
        };
        if !snapshot.unverified_peer_hint {
            return false;
        }
        if deferred_during_import {
            return false;
        }
        self.evict_unverified_sync_target_exact(
            peer_id,
            (snapshot.height, target_hash),
            true,
            "unverified target request/session expired",
        )
    }

    pub(crate) fn has_verified_header_hash(&self, hash: &[u8; 32]) -> Result<bool> {
        Ok(self
            .inspect_stored_pow_metadata(hash, None, "native stored header presence")?
            .is_some())
    }

    pub(crate) fn begin_sync_import(&self) -> bool {
        self.sync_import_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn end_sync_import(&self) {
        self.sync_import_in_flight.store(false, Ordering::Release);
    }

    pub(crate) fn sync_import_in_flight(&self) -> bool {
        self.sync_import_in_flight.load(Ordering::Acquire)
    }

    pub(crate) fn begin_sync_response_for_peer(
        &self,
        peer_id: PeerId,
        range: NativeSyncRange,
    ) -> NativeSyncResponseStart {
        let mut responses = self.sync_response_in_flight_peers.lock();
        if let Some(in_flight_range) = responses.get(&peer_id) {
            return if *in_flight_range == range {
                NativeSyncResponseStart::DuplicateRange
            } else {
                NativeSyncResponseStart::AtCapacity
            };
        }
        if responses.len() >= MAX_NATIVE_SYNC_RESPONSE_WORKERS {
            return NativeSyncResponseStart::AtCapacity;
        }
        responses.insert(peer_id, range);
        NativeSyncResponseStart::Started
    }

    pub(crate) fn end_sync_response_for_peer(&self, peer_id: PeerId, range: NativeSyncRange) {
        let mut responses = self.sync_response_in_flight_peers.lock();
        if responses
            .get(&peer_id)
            .is_some_and(|active| *active == range)
        {
            responses.remove(&peer_id);
        }
    }

    #[cfg(test)]
    pub(crate) fn begin_outbound_sync_request(
        &self,
        peer_id: Option<PeerId>,
        range: NativeSyncRange,
    ) -> bool {
        self.begin_outbound_sync_request_with_context(
            peer_id,
            range,
            NativeOutboundSyncRequestContext::default(),
        )
    }

    pub(crate) fn begin_outbound_sync_request_with_context(
        &self,
        peer_id: Option<PeerId>,
        range: NativeSyncRange,
        context: NativeOutboundSyncRequestContext,
    ) -> bool {
        let now = Instant::now();
        let mut requests = self.outbound_sync_requests.lock();
        requests.retain(|_, request| {
            request.state == NativeOutboundSyncRequestState::ChunkFallback
                || now.saturating_duration_since(request.requested_at)
                    <= NATIVE_SYNC_REQUEST_RETRY_AFTER
        });
        let paced_at = match requests.get(&peer_id) {
            Some(request) if request.state == NativeOutboundSyncRequestState::Paced => {
                Some(request.requested_at)
            }
            Some(_) => return false,
            None => None,
        };
        if requests.iter().any(|(target, request)| {
            *target != peer_id && native_sync_ranges_overlap(request.range, range)
        }) {
            return false;
        }
        // In steady pagination the fifth request is discovered only after the
        // fourth response completes. The server therefore received page four
        // before this timestamp. Holding a full server window from `paced_at`
        // is robust to client/server window phase and request-latency skew.
        if let Some(paced_at) = paced_at.filter(|paced_at| {
            now.saturating_duration_since(*paced_at) < NATIVE_SYNC_REQUEST_RATE_WINDOW
        }) {
            requests.insert(
                peer_id,
                NativeOutboundSyncRequest {
                    range,
                    requested_at: paced_at,
                    state: NativeOutboundSyncRequestState::Paced,
                    context,
                },
            );
            return false;
        }
        if let Some(peer_id) = peer_id {
            let admitted = {
                let mut limits = self.outbound_sync_request_rate_limits.lock();
                Self::admit_sync_request_rate_state(
                    &mut limits,
                    peer_id,
                    now,
                    NATIVE_SYNC_REQUEST_RATE_WINDOW,
                )
                .is_ok()
            };
            if !admitted {
                requests.insert(
                    Some(peer_id),
                    NativeOutboundSyncRequest {
                        range,
                        requested_at: paced_at.unwrap_or(now),
                        state: NativeOutboundSyncRequestState::Paced,
                        context,
                    },
                );
                return false;
            }
        }
        requests.insert(
            peer_id,
            NativeOutboundSyncRequest {
                range,
                requested_at: now,
                state: NativeOutboundSyncRequestState::InFlight,
                context,
            },
        );
        true
    }

    pub(crate) fn complete_outbound_sync_request(&self, peer_id: PeerId) {
        let mut requests = self.outbound_sync_requests.lock();
        requests.remove(&Some(peer_id));
        requests.remove(&None);
    }

    pub(crate) fn outbound_sync_request_is_paced(
        &self,
        peer_id: Option<PeerId>,
        range: NativeSyncRange,
    ) -> bool {
        self.outbound_sync_requests
            .lock()
            .get(&peer_id)
            .is_some_and(|request| {
                request.state == NativeOutboundSyncRequestState::Paced && request.range == range
            })
    }

    pub(crate) fn charge_authorized_broadcast_sync_request_rate_slot(
        &self,
        _locked_requests: &BTreeMap<Option<PeerId>, NativeOutboundSyncRequest>,
        request_target: Option<PeerId>,
        peer_id: PeerId,
        now: Instant,
    ) {
        if request_target.is_some() {
            return;
        }
        // The broadcast destination was unknowable at send time, but the
        // authorized winner proves this peer consumed one server admission
        // slot. Callers retain the outbound-request lock so every path keeps
        // the request -> outbound-rate lock order.
        let mut limits = self.outbound_sync_request_rate_limits.lock();
        let _ = Self::admit_sync_request_rate_state(
            &mut limits,
            peer_id,
            now,
            NATIVE_SYNC_REQUEST_RATE_WINDOW,
        );
    }

    pub(crate) fn complete_outbound_sync_response(
        &self,
        peer_id: PeerId,
        response_range: Option<NativeSyncRange>,
    ) -> Option<NativeCompletedSyncRequest> {
        let mut requests = self.outbound_sync_requests.lock();
        let target = [Some(peer_id), None].into_iter().find(|target| {
            requests.get(target).is_some_and(|request| {
                request.state == NativeOutboundSyncRequestState::InFlight
                    && response_range.is_none_or(|range| {
                        range.from_height == request.range.from_height
                            && range.from_height <= range.to_height
                            && range.to_height <= request.range.to_height
                    })
            })
        })?;
        let request = requests.remove(&target)?;
        self.charge_authorized_broadcast_sync_request_rate_slot(
            &requests,
            target,
            peer_id,
            Instant::now(),
        );
        Some(NativeCompletedSyncRequest {
            request_target: target,
            range: request.range,
            context: request.context,
        })
    }

    pub(crate) fn complete_outbound_sync_request_target(&self, peer_id: Option<PeerId>) {
        self.outbound_sync_requests.lock().remove(&peer_id);
    }

    pub(crate) fn defer_outbound_sync_request_retry(
        &self,
        peer_id: Option<PeerId>,
        range: NativeSyncRange,
    ) {
        let now = Instant::now();
        let mut requests = self.outbound_sync_requests.lock();
        requests.retain(|_, request| {
            request.state == NativeOutboundSyncRequestState::ChunkFallback
                || now.saturating_duration_since(request.requested_at)
                    <= NATIVE_SYNC_REQUEST_RETRY_AFTER
        });
        requests.insert(
            peer_id,
            NativeOutboundSyncRequest {
                range,
                requested_at: now,
                state: NativeOutboundSyncRequestState::Cooldown,
                context: NativeOutboundSyncRequestContext::default(),
            },
        );
    }

    pub(crate) fn set_sync_recovery_cursor(
        &self,
        peer_id: Option<PeerId>,
        target_height: u64,
        target_hash: Option<[u8; 32]>,
        range: NativeSyncRange,
        expected_parent_hash: Option<[u8; 32]>,
    ) {
        *self.sync_recovery_cursor.lock() = Some(NativeSyncRecoveryCursor {
            peer_id,
            target_height,
            target_hash,
            range,
            expected_parent_hash,
        });
    }

    pub(crate) fn sync_recovery_cursor_for_target(
        &self,
        peer_id: Option<PeerId>,
        target_height: u64,
        target_hash: Option<[u8; 32]>,
    ) -> Option<NativeSyncRecoveryCursor> {
        let mut cursor = self.sync_recovery_cursor.lock();
        let compatible = cursor.as_ref().is_some_and(|cursor| {
            (peer_id.is_none() || cursor.peer_id == peer_id)
                && target_height >= cursor.target_height
                && (target_height > cursor.target_height || cursor.target_hash == target_hash)
        });
        if !compatible {
            *cursor = None;
            return None;
        }
        let cursor = cursor
            .as_mut()
            .expect("checked native sync recovery cursor");
        if target_height > cursor.target_height {
            cursor.target_height = target_height;
            cursor.target_hash = target_hash;
        }
        Some(*cursor)
    }

    pub(crate) fn clear_sync_recovery_cursor(&self) {
        *self.sync_recovery_cursor.lock() = None;
    }

    pub(crate) fn sync_reorg_backfill_blocks(&self) -> u64 {
        self.sync_reorg_backfill_blocks
            .load(Ordering::Relaxed)
            .clamp(
                NATIVE_SYNC_REORG_BACKFILL_BLOCKS,
                NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS,
            )
    }

    pub(crate) fn reset_sync_reorg_backfill(&self) {
        self.sync_reorg_backfill_blocks
            .store(NATIVE_SYNC_REORG_BACKFILL_BLOCKS, Ordering::Relaxed);
        self.clear_sync_recovery_cursor();
    }

    pub(crate) fn escalate_sync_reorg_backfill(&self) -> u64 {
        let mut current = self.sync_reorg_backfill_blocks();
        loop {
            let next = current
                .saturating_mul(2)
                .max(NATIVE_SYNC_REORG_BACKFILL_BLOCKS.saturating_add(1))
                .min(NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS);
            match self.sync_reorg_backfill_blocks.compare_exchange(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return next,
                Err(observed) => {
                    current = observed.clamp(
                        NATIVE_SYNC_REORG_BACKFILL_BLOCKS,
                        NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS,
                    );
                    if current >= NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS {
                        return current;
                    }
                }
            }
        }
    }

    pub(crate) fn admit_sync_request_from_peer(
        &self,
        peer_id: PeerId,
    ) -> Result<(), NativeSyncAdmissionRejection> {
        let now = Instant::now();
        let mut limits = self.sync_request_rate_limits.lock();
        Self::admit_sync_request_rate_state(
            &mut limits,
            peer_id,
            now,
            NATIVE_SYNC_REQUEST_RATE_WINDOW,
        )
    }

    fn admit_sync_request_rate_state(
        limits: &mut BTreeMap<PeerId, NativeSyncRequestRateState>,
        peer_id: PeerId,
        now: Instant,
        rate_window: Duration,
    ) -> Result<(), NativeSyncAdmissionRejection> {
        let window_ms = duration_millis_u64(rate_window);
        Self::prune_sync_request_rate_limits(limits, now);
        debug_assert!(
            Self::sync_request_rate_limit_entries_after_insert(
                limits.len(),
                MAX_NATIVE_SYNC_REQUEST_RATE_LIMIT_PEERS
            ) <= MAX_NATIVE_SYNC_REQUEST_RATE_LIMIT_PEERS
        );
        let state = limits.entry(peer_id).or_insert(NativeSyncRequestRateState {
            window_start: now,
            requests: 0,
        });
        let elapsed_ms = duration_millis_u64(now.saturating_duration_since(state.window_start));
        evaluate_native_sync_request_rate_admission(NativeSyncRequestRateAdmissionInput {
            requests_in_window: state.requests,
            max_requests: MAX_NATIVE_SYNC_REQUESTS_PER_WINDOW,
            window_elapsed_ms: elapsed_ms,
            window_ms,
        })?;
        if elapsed_ms >= window_ms {
            state.window_start = now;
            state.requests = 1;
        } else {
            state.requests = state.requests.saturating_add(1);
        }
        Ok(())
    }

    pub(crate) fn prune_sync_request_rate_limits(
        limits: &mut BTreeMap<PeerId, NativeSyncRequestRateState>,
        now: Instant,
    ) {
        limits.retain(|_, state| {
            now.saturating_duration_since(state.window_start)
                <= NATIVE_SYNC_REQUEST_RATE_LIMIT_STATE_TTL
        });
        let retained_before_insert = Self::sync_request_rate_limit_entries_before_insert(
            limits.len(),
            MAX_NATIVE_SYNC_REQUEST_RATE_LIMIT_PEERS,
        );
        if limits.len() <= retained_before_insert {
            return;
        }

        let evict_count = limits.len().saturating_sub(retained_before_insert);
        let mut oldest: Vec<_> = limits
            .iter()
            .map(|(peer_id, state)| (*peer_id, state.window_start))
            .collect();
        oldest.sort_by_key(|(_, window_start)| *window_start);
        for (peer_id, _) in oldest.into_iter().take(evict_count) {
            limits.remove(&peer_id);
        }
    }

    pub(crate) fn sync_request_rate_limit_entries_before_insert(
        current_entries: usize,
        max_entries: usize,
    ) -> usize {
        if max_entries == 0 {
            0
        } else {
            current_entries.min(max_entries.saturating_sub(1))
        }
    }

    pub(crate) fn sync_request_rate_limit_entries_after_insert(
        current_entries: usize,
        max_entries: usize,
    ) -> usize {
        if max_entries == 0 {
            0
        } else {
            Self::sync_request_rate_limit_entries_before_insert(current_entries, max_entries)
                .saturating_add(1)
        }
    }

    pub(crate) fn refresh_mining_sync_gate(&self) {
        if self.config.seeds.is_empty() {
            self.mining_sync_gate_open
                .store(self.config.permits_empty_seed_authoring(), Ordering::SeqCst);
            return;
        }
        if !self.sync_target_observed.load(Ordering::SeqCst) {
            return;
        }
        let state = self.state.read();
        let snapshot = self.sync_target_evidence_snapshot();
        let resolved = !snapshot.unverified_peer_hint
            && self.sync_target_resolved_against_best(&state.best, snapshot.height, snapshot.hash);
        if !self.publish_mining_sync_gate_for_target_snapshot(snapshot, resolved) {
            // A moving target is unresolved by definition until a later poll
            // can evaluate one coherent tuple. Closing is conservative and
            // avoids spinning under an adversarial announce stream.
            self.mining_sync_gate_open.store(false, Ordering::SeqCst);
        }
    }

    pub(crate) fn publish_mining_sync_gate_for_target_snapshot(
        &self,
        snapshot: NativeSyncTargetSnapshot,
        resolved: bool,
    ) -> bool {
        // Reacquire the tuple locks in the writer order before publishing the
        // decision. Resolution may read storage, so the target can change
        // after the first snapshot; a stale resolved decision must neither
        // open mining nor erase a newly rebound peer.
        let target_hash = self.sync_target_hash.lock();
        let mut target_peer = self.sync_target_peer.lock();
        let target_height = self.sync_target_height.load(Ordering::Relaxed);
        let current_snapshot = NativeSyncTargetSnapshot {
            height: target_height,
            peer_id: *target_peer,
            hash: *target_hash,
            unverified_peer_hint: self
                .sync_target_unverified_peer_hint
                .load(Ordering::Relaxed),
        };
        if current_snapshot != snapshot {
            return false;
        }
        let resolved = resolved && !snapshot.unverified_peer_hint;
        self.mining_sync_gate_open.store(resolved, Ordering::SeqCst);
        if resolved {
            *target_peer = None;
        }
        true
    }

    pub(crate) fn sync_target_resolved_against_best(
        &self,
        best: &NativeBlockMeta,
        target: u64,
        target_hash: Option<[u8; 32]>,
    ) -> bool {
        if best.height < target {
            return false;
        }
        let Some(target_hash) = target_hash else {
            return true;
        };
        if best.hash == target_hash {
            return true;
        }
        if best.height > target {
            return true;
        }
        match self.inspect_stored_pow_metadata(&target_hash, None, "native sync target metadata") {
            Ok(Some((target_meta, _))) => !consensus::fork_choice::fork_choice_prefers_candidate(
                compare_work(&target_meta.cumulative_work, &best.cumulative_work),
                target_meta.height,
                best.height,
                &target_meta.hash,
                &best.hash,
            ),
            Ok(None) => false,
            Err(err) => {
                warn!(
                    target,
                    target_hash = %hex32(&target_hash),
                    error = %err,
                    "failed to resolve native sync target hash"
                );
                false
            }
        }
    }

    pub(crate) fn mining_sync_gate_allows_work(&self) -> bool {
        native_mining_gate_allows_work(NativeMiningGateInput {
            has_seeds: !self.config.seeds.is_empty(),
            dev: self.config.dev,
            bootstrap_mining_authoring: self.config.bootstrap_mining_authoring,
            observed_gate_open: self.mining_sync_gate_open.load(Ordering::SeqCst),
        })
    }

    pub(crate) fn sync_status_fields(&self) -> (bool, u64) {
        let snapshot = self.sync_target_evidence_snapshot();
        let observed = self.sync_target_observed.load(Ordering::SeqCst);
        let state = self.state.read();
        let target_resolved = !snapshot.unverified_peer_hint
            && self.sync_target_resolved_against_best(&state.best, snapshot.height, snapshot.hash);
        let syncing = !self.config.seeds.is_empty()
            && (!observed
                || !self.mining_sync_gate_open.load(Ordering::SeqCst)
                || !target_resolved);
        (syncing, snapshot.height)
    }

    pub(crate) fn catching_up_to_sync_target(&self) -> Option<(u64, u64)> {
        native_sync_catch_up_target(
            self.state.read().best.height,
            self.sync_target_observed.load(Ordering::SeqCst),
            self.sync_target_height.load(Ordering::Relaxed),
        )
    }

    pub(crate) fn start_mining(self: &Arc<Self>, threads: u32) {
        let requested_threads = threads.max(1);
        let available_threads = native_available_parallelism();
        let threads = effective_native_mining_threads(requested_threads, available_threads);
        if threads < requested_threads {
            warn!(
                requested_threads,
                effective_threads = threads,
                available_threads,
                background_thread_cap = NATIVE_MINING_BACKGROUND_THREAD_CAP,
                reserved_service_threads = NATIVE_MINING_RESERVED_SERVICE_THREADS,
                "capped native mining threads to preserve sync and RPC liveness"
            );
        }
        self.mining.store(true, Ordering::SeqCst);

        let mut tasks = self.mining_tasks.lock();
        tasks.retain(|task| !task.is_finished());
        if tasks.len() == threads as usize {
            self.mining_threads.store(threads, Ordering::Relaxed);
            return;
        }
        for task in tasks.drain(..) {
            task.abort();
        }
        self.mining_threads.store(threads, Ordering::Relaxed);
        for _ in 0..threads {
            let node = Arc::clone(self);
            tasks.push(tokio::spawn(async move {
                mining_loop(node).await;
            }));
        }
    }

    pub(crate) fn stop_mining(&self) {
        self.mining.store(false, Ordering::SeqCst);
        self.mining_threads.store(0, Ordering::Relaxed);
        let mut tasks = self.mining_tasks.lock();
        for task in tasks.drain(..) {
            task.abort();
        }
    }

    pub(crate) fn append_auto_coinbase_action(
        &self,
        height: u64,
        actions: &mut Vec<PendingAction>,
    ) -> Result<Option<PendingAction>> {
        let Some(action) = self.auto_coinbase_action(height, actions)? else {
            return Ok(None);
        };
        actions.push(action.clone());
        Ok(Some(action))
    }

    pub(crate) fn auto_coinbase_action(
        &self,
        height: u64,
        actions: &[PendingAction],
    ) -> Result<Option<PendingAction>> {
        #[cfg(test)]
        if let Some(action) = poseidon2_v8_verifier::poseidon2_v8_test_coinbase() {
            if actions.iter().any(is_coinbase_action) {
                return Ok(None);
            }
            if !poseidon2_v8_verifier::poseidon2_v8_test_binding_authorizes_route(
                height,
                action.binding,
                action.family_id,
                action.action_id,
            ) {
                return Err(anyhow!(
                    "test-scoped Poseidon2 V8 coinbase is outside its exact binding"
                ));
            }
            validate_coinbase_action_payload(&action)?;
            let expected = expected_coinbase_amount(actions, height)?;
            if coinbase_action_amount(&action)? != expected {
                return Err(anyhow!(
                    "test-scoped Poseidon2 V8 coinbase amount mismatch at height {height}"
                ));
            }
            let mut accounting_actions = actions.to_vec();
            accounting_actions.push(action.clone());
            validate_coinbase_accounting(&accounting_actions, height)?;
            return Ok(Some(action));
        }
        if self.config.miner_address.is_none() {
            return Ok(None);
        }
        if actions.iter().any(is_coinbase_action) {
            return Ok(None);
        }
        let amount = expected_coinbase_amount(actions, height)?;
        if amount == 0 {
            return Ok(None);
        }
        let Some(production) = self.fresh_coinbase_authority_at_height(height)? else {
            // Fresh V4/Gamma minting is retired. Mining may still author an
            // empty, subsidy-forfeiting block while the V8 capability is absent.
            return Ok(None);
        };

        let action = self.build_auto_coinbase_action(height, amount, production)?;
        let mut accounting_actions = actions.to_vec();
        accounting_actions.push(action.clone());
        validate_coinbase_accounting(&accounting_actions, height)?;
        Ok(Some(action))
    }

    pub(crate) fn auto_coinbase_action_reservation_bytes(&self) -> Result<usize> {
        #[cfg(test)]
        if poseidon2_v8_verifier::poseidon2_v8_test_coinbase().is_some() {
            let height = self
                .best_meta()
                .height
                .checked_add(1)
                .ok_or_else(|| anyhow!("native coinbase reservation height overflow"))?;
            return self.auto_coinbase_action_reservation_bytes_at_height(height);
        }
        if self.config.miner_address.is_none() {
            return Ok(0);
        }
        let height = self
            .best_meta()
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow!("native coinbase reservation height overflow"))?;
        self.auto_coinbase_action_reservation_bytes_at_height(height)
    }

    fn auto_coinbase_action_reservation_bytes_at_height(&self, height: u64) -> Result<usize> {
        #[cfg(test)]
        if let Some(action) = poseidon2_v8_verifier::poseidon2_v8_test_coinbase() {
            if !poseidon2_v8_verifier::poseidon2_v8_test_binding_authorizes_route(
                height,
                action.binding,
                action.family_id,
                action.action_id,
            ) {
                return Err(anyhow!(
                    "test-scoped Poseidon2 V8 coinbase reservation is outside its exact binding"
                ));
            }
            return Ok(action.encoded_size());
        }
        if self.config.miner_address.is_none() {
            return Ok(0);
        }
        let Some(production) = self.fresh_coinbase_authority_at_height(height)? else {
            return Ok(0);
        };
        Ok(self
            .build_auto_coinbase_action(height, 1, production)?
            .encoded_size())
    }

    fn fresh_coinbase_authority_at_height(
        &self,
        height: u64,
    ) -> Result<Option<poseidon2_v8_verifier::Poseidon2V8ProductionBinding>> {
        let decision = kernel_manifest().proof_authority_decision(
            protocol_versioning::ProofAuthorityOperation::Authoring,
            protocol_versioning::HEGEMON_PROOF_NETWORK_ID,
            height,
            protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            ACTION_MINT_POSEIDON2_V8_COINBASE,
            protocol_versioning::ProofAuthorityClass::MintSource,
            None,
        );
        if !matches!(
            decision,
            protocol_versioning::ProofAuthorityDecision::Fresh(_)
        ) {
            return Ok(None);
        }
        poseidon2_v8_verifier::Poseidon2V8ProductionBinding::require_source_at(height)
            .map(Some)
            .map_err(|error| anyhow!("native coinbase source connector rejected: {error}"))
    }

    fn build_auto_coinbase_action(
        &self,
        height: u64,
        amount: u64,
        production: poseidon2_v8_verifier::Poseidon2V8ProductionBinding,
    ) -> Result<PendingAction> {
        let miner_address = self
            .config
            .miner_address
            .as_deref()
            .ok_or_else(|| anyhow!("native coinbase reservation requires a miner address"))?;
        let recipient = ShieldedAddress::decode(miner_address)
            .with_context(|| "decode HEGEMON_MINER_ADDRESS for native coinbase")?;
        if !production.active_at(height) {
            return Err(anyhow!(
                "native V8 coinbase authority is inactive at height {height}"
            ));
        }
        let genesis = self.load_canonical_block_at_height_unverified(0)?;
        if genesis.hash != production.activation_genesis_hash() {
            return Err(anyhow!(
                "native V8 coinbase activation genesis does not match this chain"
            ));
        }
        self.build_poseidon2_v8_auto_coinbase_action(&recipient, amount)
    }

    fn build_poseidon2_v8_auto_coinbase_action(
        &self,
        recipient: &ShieldedAddress,
        amount: u64,
    ) -> Result<PendingAction> {
        let mut rng = OsRng;
        let args = wallet::poseidon2_v8_coinbase::build_poseidon2_v8_coinbase_args(
            recipient, amount, &mut rng,
        )
        .with_context(|| "construct Poseidon2 V8 native coinbase note")?;
        let (raw_len, metadata) = coinbase_ciphertext_metadata(&args.miner_note.encrypted_note);
        if raw_len != POSEIDON2_V8_COINBASE_RAW_CIPHERTEXT_BYTES {
            return Err(anyhow!(
                "generated Poseidon2 V8 coinbase ciphertext has wrong size"
            ));
        }
        let (ciphertext_hash, ciphertext_size) = metadata
            .ok_or_else(|| anyhow!("generated Poseidon2 V8 coinbase ciphertext exceeds cap"))?;
        let mut action = PendingAction {
            tx_hash: ActionId48::ZERO,
            binding: protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
            family_id: FAMILY_SHIELDED_POOL,
            action_id: ACTION_MINT_POSEIDON2_V8_COINBASE,
            anchor: [0u8; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: vec![ciphertext_hash],
            ciphertext_sizes: vec![ciphertext_size],
            public_args: args.encode(),
            fee: 0,
            candidate_artifact: None,
        };
        action.tx_hash = pending_action_hash(&action);
        validate_coinbase_action_payload(&action)?;
        Ok(action)
    }

    #[cfg(test)]
    pub(crate) fn verify_independent_smallwood_actions_for_template(
        &self,
        state: &NativeState,
        height: u64,
        timestamp_ms: u64,
        actions: &[PendingAction],
    ) -> Result<()> {
        self.verify_independent_smallwood_actions_against_parent(
            &state.best,
            &state.commitment_tree,
            height,
            timestamp_ms,
            actions,
        )
        .map(|_| ())
        .map_err(NativeIndependentProofPreflightFailure::into_anyhow)
    }

    fn verify_independent_smallwood_actions_against_parent(
        &self,
        best: &NativeBlockMeta,
        commitment_tree: &CommitmentTreeState,
        height: u64,
        timestamp_ms: u64,
        actions: &[PendingAction],
    ) -> std::result::Result<
        NativeIndependentProofPreflightSuccess,
        NativeIndependentProofPreflightFailure,
    > {
        validate_native_block_proof_policy(best.height, height, actions)
            .map_err(NativeIndependentProofPreflightFailure::deterministic)?;

        let v8_actions = actions
            .iter()
            .filter(|action| is_poseidon2_v8_action(action))
            .collect::<Vec<_>>();
        let canonical_poseidon2_v8_action_ids = if v8_actions.is_empty() {
            Vec::new()
        } else {
            self.verify_poseidon2_v8_action_batch_against_parent(&v8_actions, best, height)
                .map_err(NativeIndependentProofPreflightFailure::deterministic)?
        };

        let mut transfer_actions = Vec::new();
        let mut transfer_starts = Vec::new();
        let mut next_commitment_start = commitment_tree.leaf_count();
        for action in actions {
            if is_legacy_shielded_transfer_action(action) {
                transfer_actions.push(action.clone());
                transfer_starts.push(next_commitment_start);
            }
            let commitment_count = u64::try_from(action.commitments.len()).map_err(|_| {
                NativeIndependentProofPreflightFailure::deterministic(anyhow!(
                    "native independent proof commitment count exceeds u64"
                ))
            })?;
            next_commitment_start = next_commitment_start
                .checked_add(commitment_count)
                .ok_or_else(|| {
                    NativeIndependentProofPreflightFailure::deterministic(anyhow!(
                        "native independent proof commitment start overflow"
                    ))
                })?;
        }
        if transfer_actions.is_empty() {
            return Ok(NativeIndependentProofPreflightSuccess {
                verified_da_encoding: None,
                canonical_poseidon2_v8_action_ids,
            });
        }

        let materialized = materialize_native_action_payloads_at_starts(
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
            &transfer_actions,
            &transfer_starts,
        )
        .map_err(NativeIndependentProofPreflightFailure::transient)?;
        let mut transactions = Vec::with_capacity(transfer_actions.len());
        let mut artifacts = Vec::with_capacity(transfer_actions.len());
        for (action, payload) in transfer_actions.iter().zip(materialized.iter()) {
            let (tx, artifact) = consensus_tx_and_artifact_from_action(action, payload)
                .map_err(NativeIndependentProofPreflightFailure::deterministic)?;
            transactions.push(tx);
            artifacts.push(artifact);
        }

        let transfer_refs = transfer_actions.iter().collect::<Vec<_>>();
        let expected_tree = preview_commitment_tree(commitment_tree, &transfer_refs)
            .map_err(NativeIndependentProofPreflightFailure::deterministic)?;
        let expected_kernel_root =
            consensus::types::kernel_root_from_shielded_root(&expected_tree.root());
        let da_params = native_da_params_for_transactions(&transactions)
            .map_err(NativeIndependentProofPreflightFailure::deterministic)?;
        let da_encoding = consensus::encode_da_blob(&transactions, da_params).map_err(|err| {
            NativeIndependentProofPreflightFailure::deterministic(anyhow!(
                "native independent proof DA encoding failed: {err}"
            ))
        })?;
        let tx_count = u32::try_from(transactions.len()).map_err(|_| {
            NativeIndependentProofPreflightFailure::deterministic(anyhow!(
                "native independent proof tx_count exceeds u32"
            ))
        })?;
        let header = consensus::BlockHeader {
            version: 1,
            height,
            view: 0,
            timestamp_ms: timestamp_ms.max(best.timestamp_ms.saturating_add(1)),
            parent_hash: best.hash,
            state_root: expected_tree.root(),
            kernel_root: expected_kernel_root,
            // The independent tx-leaf verifier does not consume the block-level
            // nullifier accumulator. Mempool/block state admission owns that
            // check, so avoid cloning the full canonical nullifier set here.
            nullifier_root: NATIVE_EMPTY_DIGEST48,
            proof_commitment: consensus::types::compute_proof_commitment(&transactions),
            da_root: da_encoding.root(),
            da_params,
            version_commitment: consensus::types::compute_version_commitment(&transactions),
            tx_count,
            fee_commitment: consensus::types::compute_fee_commitment(&transactions),
            supply_digest: best.supply_digest,
            validator_set_commitment: [0u8; 48],
            signature_aggregate: Vec::new(),
            signature_bitmap: None,
            pow: None,
        };
        let block = consensus::types::Block {
            header,
            transactions,
            coinbase: None,
            proven_batch: None,
            block_artifact: None,
            tx_validity_claims: None,
            tx_statements_commitment: None,
            proof_verification_mode: consensus::types::ProofVerificationMode::InlineRequired,
        };
        let backend_inputs =
            consensus::proof_interface::BlockBackendInputs::from_tx_validity_artifacts(artifacts);
        let verifier = consensus::proof::ParallelProofVerifier::new();
        #[cfg(test)]
        self.independent_proof_backend_invocations
            .fetch_add(1, Ordering::Relaxed);
        let verified_tree =
            <consensus::proof::ParallelProofVerifier as consensus::proof_interface::ProofVerifier>::verify_block_with_backend(
                &verifier,
                &block,
                Some(&backend_inputs),
                commitment_tree,
            )
            .map_err(|err| {
                let message = anyhow!("native independent SmallWood proof preflight failed: {err}");
                if native_proof_error_is_deterministic(&err) {
                    NativeIndependentProofPreflightFailure::deterministic(message)
                } else {
                    NativeIndependentProofPreflightFailure::transient(message)
                }
            })?;
        if verified_tree.root() != expected_tree.root() {
            return Err(NativeIndependentProofPreflightFailure::deterministic(
                anyhow!("native independent SmallWood proof preflight state root mismatch"),
            ));
        }
        Ok(NativeIndependentProofPreflightSuccess {
            verified_da_encoding: Some(NativeVerifiedDaEncoding {
                transfer_hashes: transfer_actions
                    .iter()
                    .map(|action| action.tx_hash)
                    .collect(),
                params: da_params,
                encoding: Arc::new(da_encoding),
            }),
            canonical_poseidon2_v8_action_ids,
        })
    }

    fn preflight_pending_transfer_proof_against_parent(
        &self,
        pending: &PendingAction,
        best: &NativeBlockMeta,
        commitment_tree: &CommitmentTreeState,
    ) -> std::result::Result<(), NativeIndependentProofPreflightFailure> {
        if !is_shielded_transfer_action(pending) {
            return Ok(());
        }
        let height = best.height.checked_add(1).ok_or_else(|| {
            NativeIndependentProofPreflightFailure::transient(anyhow!(
                "native proof preflight height overflow"
            ))
        })?;
        if is_poseidon2_v8_action(pending) {
            return self
                .preflight_poseidon2_v8_action_against_parent(pending, best, height)
                .map_err(NativeIndependentProofPreflightFailure::deterministic);
        }
        self.verify_independent_smallwood_actions_against_parent(
            best,
            commitment_tree,
            height,
            current_time_ms(),
            std::slice::from_ref(pending),
        )
        .map(|_| ())
    }

    /// Test-only access to the exact pending-transfer proof preflight. This
    /// neither grants proof authority nor records a cache result; production
    /// ingress reaches the same private routine only after its authority gate.
    #[cfg(test)]
    pub(crate) fn preflight_pending_transfer_proof_for_test(
        &self,
        pending: &PendingAction,
    ) -> Result<()> {
        let (best, commitment_tree) = {
            let state = self.state.read();
            (state.best.clone(), state.commitment_tree.clone())
        };
        self.preflight_pending_transfer_proof_against_parent(pending, &best, &commitment_tree)
            .map_err(NativeIndependentProofPreflightFailure::into_anyhow)
    }

    fn poseidon2_v8_store_synced_to_parent(
        &self,
        production: poseidon2_v8_verifier::Poseidon2V8ProductionBinding,
        parent: &NativeBlockMeta,
    ) -> Result<poseidon2_v8_state::Poseidon2V8StateStore> {
        self.poseidon2_v8_store_synced_to_parent_tip(production, parent.height, parent.hash)
    }

    fn poseidon2_v8_store_synced_to_parent_tip(
        &self,
        production: poseidon2_v8_verifier::Poseidon2V8ProductionBinding,
        parent_height: u64,
        parent_hash: [u8; 32],
    ) -> Result<poseidon2_v8_state::Poseidon2V8StateStore> {
        let genesis = self.load_canonical_block_at_height_unverified(0)?;
        if genesis.hash != production.activation_genesis_hash() {
            return Err(anyhow!(
                "native V8 activation capability names a different genesis block"
            ));
        }
        let genesis_checkpoint = poseidon2_v8_state::Poseidon2V8Checkpoint::new(
            0,
            genesis.hash,
            production.stablecoin_genesis_root(),
        );
        let store = poseidon2_v8_state::Poseidon2V8StateStore::open(
            &self.db,
            genesis_checkpoint,
            production.note_genesis_root(),
        )
        .map_err(|error| anyhow!("open native V8 canonical state failed: {error}"))?;
        let mut tip = store
            .tip()
            .map_err(|error| anyhow!("read native V8 canonical tip failed: {error}"))?;
        if tip.height() > parent_height {
            return Err(anyhow!(
                "native V8 canonical tip is ahead of the requested parent"
            ));
        }
        let canonical_tip_hash = self
            .hash_by_height(tip.height())?
            .ok_or_else(|| anyhow!("missing canonical block at native V8 tip height"))?;
        if canonical_tip_hash != tip.block_hash() {
            return Err(anyhow!(
                "native V8 canonical tip is on a different branch; reorg planning is required"
            ));
        }

        while tip.height() < parent_height {
            let height = tip
                .height()
                .checked_add(1)
                .ok_or_else(|| anyhow!("native V8 replay height overflow"))?;
            let meta = self.load_canonical_block_at_height_unverified(height)?;
            if meta.parent_hash != tip.block_hash() {
                return Err(anyhow!(
                    "native V8 canonical replay parent mismatch at height {height}"
                ));
            }
            self.apply_poseidon2_v8_canonical_block_to_store(production, &store, &meta)?;
            tip = store
                .tip()
                .map_err(|error| anyhow!("read native V8 replay tip failed: {error}"))?;
        }
        if tip.height() != parent_height || tip.block_hash() != parent_hash {
            return Err(anyhow!(
                "native V8 canonical state did not converge on the requested parent"
            ));
        }
        Ok(store)
    }

    fn preflight_poseidon2_v8_action_against_parent(
        &self,
        pending: &PendingAction,
        best: &NativeBlockMeta,
        height: u64,
    ) -> Result<()> {
        let mut actions = {
            let state = self.state.read();
            if state.best.height != best.height || state.best.hash != best.hash {
                return Err(anyhow!(
                    "canonical state changed before native V8 mempool batch preflight"
                ));
            }
            state
                .pending_actions
                .values()
                .filter(|action| is_poseidon2_v8_action(action))
                .cloned()
                .collect::<Vec<_>>()
        };
        if !actions
            .iter()
            .any(|action| action.tx_hash == pending.tx_hash)
        {
            actions.push(pending.clone());
        }
        let action_refs = actions.iter().collect::<Vec<_>>();
        self.verify_poseidon2_v8_action_batch_against_parent(&action_refs, best, height)
            .map(|_| ())
    }

    /// Select the deterministic V8 order from canonical parser output. This
    /// pass is an ordering hint only. The returned order gains validity solely
    /// when the source verifier runs below and the planner exact-rechecks the
    /// proof-bound transitions.
    fn prepare_poseidon2_v8_action_order_against_parent(
        &self,
        actions: &[&PendingAction],
        best: &NativeBlockMeta,
        height: u64,
    ) -> Result<(
        poseidon2_v8_verifier::Poseidon2V8ProductionBinding,
        poseidon2_v8_state::Poseidon2V8StateStore,
        poseidon2_v8_state::Poseidon2V8Checkpoint,
        Vec<ActionId48>,
    )> {
        if actions.is_empty() {
            return Err(anyhow!("native V8 order preparation requires an action"));
        }
        if actions.len() > MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK {
            return Err(anyhow!(
                "native V8 pending batch carries {} actions; source-owned limit is {MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK}",
                actions.len()
            ));
        }
        validate_block_action_byte_budget(
            u32::try_from(actions.len())
                .map_err(|_| anyhow!("native V8 pending action count exceeds u32"))?,
            actions.len(),
            actions.iter().map(|action| action.encoded_size()),
        )?;
        let production =
            poseidon2_v8_verifier::Poseidon2V8ProductionBinding::require_source_at(height)
                .map_err(|error| anyhow!("native V8 preflight authority rejected: {error}"))?;
        let views = actions
            .iter()
            .map(|action| {
                poseidon2_v8_verifier::Poseidon2V8ActionView::from_pending(
                    production, height, action,
                )
                .map_err(|error| anyhow!("native V8 pending action rejected: {error}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let store = self.poseidon2_v8_store_synced_to_parent(production, best)?;
        let checkpoint = store
            .tip()
            .map_err(|error| anyhow!("read native V8 pending checkpoint failed: {error}"))?;
        let leaves = views
            .iter()
            .map(|view| view.exact_native_leaf())
            .collect::<Vec<_>>();
        let ordering_hints = views
            .iter()
            .copied()
            .map(|view| {
                view.ordering_transition_hint()
                    .map_err(|error| anyhow!("native V8 ordering hint rejected: {error}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let hinted = recorded_poseidon2_v8_actions(actions, &leaves, &ordering_hints)?;
        let plan = poseidon2_v8_pending::plan_poseidon2_v8_pending_chain(
            checkpoint,
            &hinted,
            poseidon2_v8_pending::Poseidon2V8PendingCaps::new(
                production.max_proof_actions_per_block(),
                MAX_NATIVE_BLOCK_ACTION_BYTES,
            ),
        )
        .map_err(|error| anyhow!("native V8 candidate ordering rejected: {error}"))?;
        if plan.selected_action_ids() != plan.ordered_action_ids()
            || !plan.deferred_action_ids().is_empty()
            || plan.selected_legacy_da_bytes() != 0
        {
            return Err(anyhow!(
                "native V8 candidate order exceeds the source count or encoded-byte cap"
            ));
        }
        Ok((
            production,
            store,
            checkpoint,
            plan.ordered_action_ids().to_vec(),
        ))
    }

    fn verify_poseidon2_v8_action_batch_against_parent(
        &self,
        actions: &[&PendingAction],
        best: &NativeBlockMeta,
        height: u64,
    ) -> Result<Vec<ActionId48>> {
        if actions.is_empty() {
            return Ok(Vec::new());
        }
        let (production, store, checkpoint, ordered_ids) =
            self.prepare_poseidon2_v8_action_order_against_parent(actions, best, height)?;
        let actions_by_id = actions
            .iter()
            .map(|action| (action.tx_hash, *action))
            .collect::<BTreeMap<_, _>>();
        let ordered = ordered_ids
            .iter()
            .map(|action_id| {
                actions_by_id.get(action_id).copied().ok_or_else(|| {
                    anyhow!("native V8 canonical order references an absent action id")
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let views = ordered
            .iter()
            .map(|action| {
                poseidon2_v8_verifier::Poseidon2V8ActionView::from_pending(
                    production, height, action,
                )
                .map_err(|error| anyhow!("native V8 pending action rejected: {error}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut candidate_hash_preimage = Vec::with_capacity(48 * ordered.len());
        for action in &ordered {
            candidate_hash_preimage.extend_from_slice(action.tx_hash.as_bytes());
        }
        let mut candidate_hash = crypto::hashes::blake2_256(&candidate_hash_preimage);
        if candidate_hash == best.hash {
            candidate_hash[0] ^= 1;
        }
        let context = poseidon2_v8_state::Poseidon2V8BlockContext::new(
            best.height,
            best.hash,
            height,
            candidate_hash,
        )
        .map_err(|error| anyhow!("native V8 pending block context rejected: {error}"))?;
        let leaves = views
            .iter()
            .map(|view| view.exact_native_leaf())
            .collect::<Vec<_>>();
        let block = poseidon2_v8_state::Poseidon2V8UnverifiedBlock::new(context, &leaves)
            .map_err(|error| anyhow!("native V8 pending leaf rejected: {error}"))?;
        let mut verifier = RecordingPoseidon2V8Verifier::new(production.connector());
        let verified_tip = store
            .verify_uncommitted_block(block, &mut verifier)
            .map_err(|error| {
                anyhow!("native V8 pending proof/state preflight rejected: {error}")
            })?;
        let recorded = recorded_poseidon2_v8_actions(&ordered, &leaves, verifier.transitions())?;
        let pending_plan = poseidon2_v8_pending::plan_poseidon2_v8_pending_chain(
            checkpoint,
            &recorded,
            poseidon2_v8_pending::Poseidon2V8PendingCaps::new(
                production.max_proof_actions_per_block(),
                MAX_NATIVE_BLOCK_ACTION_BYTES,
            ),
        )
        .map_err(|error| anyhow!("native V8 pending dependency plan rejected: {error}"))?;
        let supplied_ids = ordered
            .iter()
            .map(|action| action.tx_hash)
            .collect::<Vec<_>>();
        if pending_plan.ordered_action_ids() != supplied_ids.as_slice()
            || pending_plan.selected_action_ids() != supplied_ids.as_slice()
            || !pending_plan.deferred_action_ids().is_empty()
            || pending_plan.selected_final_root() != verified_tip.root()
            || pending_plan.selected_legacy_da_bytes() != 0
        {
            return Err(anyhow!(
                "native V8 pending dependency plan disagrees with exact verified block order/caps"
            ));
        }
        Ok(ordered_ids)
    }

    fn apply_poseidon2_v8_canonical_block_to_store(
        &self,
        production: poseidon2_v8_verifier::Poseidon2V8ProductionBinding,
        store: &poseidon2_v8_state::Poseidon2V8StateStore,
        meta: &NativeBlockMeta,
    ) -> Result<()> {
        let actions = decode_block_actions(meta)?;
        verify_decoded_action_root(&actions, meta, "native V8 canonical replay action root")?;
        validate_coinbase_route_at_height(&actions, meta.height)?;
        validate_poseidon2_v8_replay_window(production, meta.height, &actions)?;
        let v8_actions = actions
            .iter()
            .filter(|action| is_poseidon2_v8_action(action))
            .collect::<Vec<_>>();
        let views = v8_actions
            .iter()
            .map(|action| {
                poseidon2_v8_verifier::Poseidon2V8ActionView::from_pending(
                    production,
                    meta.height,
                    *action,
                )
                .map_err(|error| {
                    anyhow!(
                        "native V8 canonical replay action at height {} rejected: {error}",
                        meta.height
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let leaves = views
            .iter()
            .map(|view| view.exact_native_leaf())
            .collect::<Vec<_>>();
        let checkpoint = store
            .tip()
            .map_err(|error| anyhow!("read native V8 canonical replay tip failed: {error}"))?;
        let parent_height = meta
            .height
            .checked_sub(1)
            .ok_or_else(|| anyhow!("native V8 canonical replay cannot apply genesis"))?;
        let context = poseidon2_v8_state::Poseidon2V8BlockContext::new(
            parent_height,
            meta.parent_hash,
            meta.height,
            meta.hash,
        )
        .map_err(|error| {
            anyhow!(
                "native V8 canonical replay context at height {} rejected: {error}",
                meta.height
            )
        })?;
        let trailing_coinbase = poseidon2_v8_coinbase_commitment_for_actions(&actions)?;
        let block = poseidon2_v8_state::Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
            context,
            &leaves,
            trailing_coinbase,
        )
        .map_err(|error| {
            anyhow!(
                "native V8 canonical replay leaf batch at height {} rejected: {error}",
                meta.height
            )
        })?;
        let mut verifier = RecordingPoseidon2V8Verifier::new(production.connector());
        let plan = store
            .plan_verified_reorganization(&[], &[block], &mut verifier)
            .map_err(|error| {
                anyhow!(
                    "native V8 canonical replay state at height {} rejected: {error}",
                    meta.height
                )
            })?;
        let ordered_root = verify_recorded_poseidon2_v8_block_order(
            checkpoint,
            &v8_actions,
            &leaves,
            verifier.transitions(),
            "native V8 canonical replay action order rejected",
        )?;
        if ordered_root != plan.final_tip().root() {
            return Err(anyhow!(
                "native V8 canonical replay planner final root mismatch at height {}",
                meta.height
            ));
        }
        let applied_tip = store
            .apply_verified_canonical_plan(&plan)
            .map_err(|error| {
                anyhow!(
                    "apply native V8 canonical replay state at height {} failed: {error}",
                    meta.height
                )
            })?;
        if applied_tip != plan.final_tip() {
            return Err(anyhow!(
                "native V8 canonical replay readback mismatch at height {}",
                meta.height
            ));
        }
        Ok(())
    }

    fn reconcile_poseidon2_v8_canonical_history(&self, chain: &[NativeBlockMeta]) -> Result<()> {
        let genesis = chain
            .first()
            .ok_or_else(|| anyhow!("native V8 startup reconciliation has no genesis"))?;
        let Some(production) =
            poseidon2_v8_verifier::Poseidon2V8ProductionBinding::from_source_for_replay()
                .map_err(|error| anyhow!("native V8 startup authority rejected: {error}"))?
        else {
            for meta in chain.iter().skip(1) {
                if decode_block_actions(meta)?
                    .iter()
                    .any(action_uses_poseidon2_v8_state)
                {
                    return Err(anyhow!(
                        "canonical history contains Poseidon2 V8 without an active production capability"
                    ));
                }
            }
            return Ok(());
        };

        let genesis_checkpoint = poseidon2_v8_state::Poseidon2V8Checkpoint::new(
            genesis.height,
            genesis.hash,
            production.stablecoin_genesis_root(),
        );
        if genesis.hash != production.activation_genesis_hash() {
            return Err(anyhow!(
                "native V8 startup capability names a different genesis block"
            ));
        }
        let scratch_db = sled::Config::new()
            .temporary(true)
            .open()
            .map_err(|error| {
                anyhow!("open native V8 startup verification store failed: {error}")
            })?;
        let scratch = poseidon2_v8_state::Poseidon2V8StateStore::open(
            &scratch_db,
            genesis_checkpoint,
            production.note_genesis_root(),
        )
        .map_err(|error| {
            anyhow!("initialize native V8 startup verification store failed: {error}")
        })?;

        // This is the proof-verification pass. It always starts from genesis;
        // no durable checkpoint or record is trusted as an acceptance cache.
        for meta in chain.iter().skip(1) {
            self.apply_poseidon2_v8_canonical_block_to_store(production, &scratch, meta)?;
        }

        let durable = poseidon2_v8_state::Poseidon2V8StateStore::open(
            &self.db,
            genesis_checkpoint,
            production.note_genesis_root(),
        )
        .map_err(|error| anyhow!("open durable native V8 startup state failed: {error}"))?;
        let durable_tip = durable
            .tip()
            .map_err(|error| anyhow!("read durable native V8 startup tip failed: {error}"))?;
        let durable_height = usize::try_from(durable_tip.height())
            .map_err(|_| anyhow!("durable native V8 startup height exceeds usize"))?;
        let durable_meta = chain.get(durable_height).ok_or_else(|| {
            anyhow!("durable native V8 startup tip is ahead of canonical history")
        })?;
        if durable_meta.height != durable_tip.height()
            || durable_meta.hash != durable_tip.block_hash()
        {
            return Err(anyhow!(
                "durable native V8 startup tip is not on the canonical branch"
            ));
        }

        // A fresh node or interrupted verified catch-up may safely resume from
        // its exact canonical typed tip. Every block was already verified in
        // the scratch pass and is verified again before durable application.
        for meta in chain.iter().skip(durable_height.saturating_add(1)) {
            self.apply_poseidon2_v8_canonical_block_to_store(production, &durable, meta)?;
        }
        if !durable
            .exact_rows_equal(&scratch)
            .map_err(|error| anyhow!("compare native V8 startup state failed: {error}"))?
        {
            return Err(anyhow!(
                "durable native V8 rows differ from exact source-verified canonical replay"
            ));
        }
        Ok(())
    }

    pub(crate) fn plan_poseidon2_v8_block_against_parent(
        &self,
        parent: &NativeBlockMeta,
        meta: &NativeBlockMeta,
        actions: &[PendingAction],
    ) -> Result<
        Option<(
            poseidon2_v8_state::Poseidon2V8StateStore,
            poseidon2_v8_state::Poseidon2V8CanonicalPlan,
        )>,
    > {
        self.plan_poseidon2_v8_block_against_parent_tip(parent.height, parent.hash, meta, actions)
    }

    fn plan_poseidon2_v8_block_against_parent_tip(
        &self,
        parent_height: u64,
        parent_hash: [u8; 32],
        meta: &NativeBlockMeta,
        actions: &[PendingAction],
    ) -> Result<
        Option<(
            poseidon2_v8_state::Poseidon2V8StateStore,
            poseidon2_v8_state::Poseidon2V8CanonicalPlan,
        )>,
    > {
        let Some(production) =
            poseidon2_v8_verifier::Poseidon2V8ProductionBinding::from_source_at(meta.height)
                .map_err(|error| anyhow!("native V8 block authority rejected: {error}"))?
        else {
            if actions.iter().any(action_uses_poseidon2_v8_state) {
                return Err(anyhow!(
                    "native block carries Poseidon2 V8 without an active production capability"
                ));
            }
            return Ok(None);
        };
        let store =
            self.poseidon2_v8_store_synced_to_parent_tip(production, parent_height, parent_hash)?;
        let plan = self.plan_poseidon2_v8_block_in_store(
            production,
            &store,
            parent_height,
            parent_hash,
            meta,
            actions,
        )?;
        Ok(Some((store, plan)))
    }

    fn plan_poseidon2_v8_block_in_store(
        &self,
        production: poseidon2_v8_verifier::Poseidon2V8ProductionBinding,
        store: &poseidon2_v8_state::Poseidon2V8StateStore,
        parent_height: u64,
        parent_hash: [u8; 32],
        meta: &NativeBlockMeta,
        actions: &[PendingAction],
    ) -> Result<poseidon2_v8_state::Poseidon2V8CanonicalPlan> {
        validate_coinbase_route_at_height(actions, meta.height)?;
        let v8_actions = actions
            .iter()
            .filter(|action| is_poseidon2_v8_action(action))
            .collect::<Vec<_>>();
        let views = v8_actions
            .iter()
            .map(|action| {
                poseidon2_v8_verifier::Poseidon2V8ActionView::from_pending(
                    production,
                    meta.height,
                    *action,
                )
                .map_err(|error| anyhow!("native V8 block action rejected: {error}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let leaves = views
            .iter()
            .map(|view| view.exact_native_leaf())
            .collect::<Vec<_>>();
        let checkpoint = store
            .tip()
            .map_err(|error| anyhow!("read native V8 block checkpoint failed: {error}"))?;
        let context = poseidon2_v8_state::Poseidon2V8BlockContext::new(
            parent_height,
            parent_hash,
            meta.height,
            meta.hash,
        )
        .map_err(|error| anyhow!("native V8 block context rejected: {error}"))?;
        let trailing_coinbase = poseidon2_v8_coinbase_commitment_for_actions(actions)?;
        let block = poseidon2_v8_state::Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
            context,
            &leaves,
            trailing_coinbase,
        )
        .map_err(|error| anyhow!("native V8 block leaf batch rejected: {error}"))?;
        let mut verifier = RecordingPoseidon2V8Verifier::new(production.connector());
        let plan = store
            .plan_verified_reorganization(&[], &[block], &mut verifier)
            .map_err(|error| {
                anyhow!("native V8 block proof/state verification rejected: {error}")
            })?;
        let ordered_root = verify_recorded_poseidon2_v8_block_order(
            checkpoint,
            &v8_actions,
            &leaves,
            verifier.transitions(),
            "native V8 block action order rejected",
        )?;
        if ordered_root != plan.final_tip().root() {
            return Err(anyhow!(
                "native V8 block planner final root differs from exact typed state plan"
            ));
        }
        Ok(plan)
    }

    /// Verify a block against any already-stored parent. Canonical-tip
    /// extension uses the durable typed tip directly. Side branches build a
    /// read-only detach/attach plan from their canonical common ancestor, so
    /// arrival order cannot make a valid sibling or deeper fork child
    /// unverifiable and canonical-prefix proofs are not redundantly replayed.
    pub(crate) fn verify_poseidon2_v8_block_against_stored_parent(
        &self,
        parent: &NativeBlockMeta,
        meta: &NativeBlockMeta,
        actions: &[PendingAction],
    ) -> Result<()> {
        verify_decoded_action_root(actions, meta, "native V8 candidate branch action root")?;
        if meta.parent_hash != parent.hash || meta.height != parent.height.saturating_add(1) {
            return Err(anyhow!(
                "native V8 candidate branch metadata does not extend the supplied parent"
            ));
        }
        let has_v8 = actions.iter().any(action_uses_poseidon2_v8_state);
        let Some(production) =
            poseidon2_v8_verifier::Poseidon2V8ProductionBinding::from_source_at(meta.height)
                .map_err(|error| anyhow!("native V8 fork authority rejected: {error}"))?
        else {
            if has_v8 {
                return Err(anyhow!(
                    "native fork block carries Poseidon2 V8 without an active production capability"
                ));
            }
            return Ok(());
        };
        // Empty V8 lanes do not need a branch-local proof replay during peer
        // admission.  A winning reorganization still plans and atomically
        // applies every empty/non-empty attach block, so the typed checkpoint
        // remains height/hash exact without making zero-V8 peer traffic cost
        // O(fork depth) verifier work.
        if !has_v8 {
            return Ok(());
        }

        let canonical_tip_matches = {
            let state = self.state.read();
            state.best.height == parent.height && state.best.hash == parent.hash
        };
        if canonical_tip_matches {
            let _ = self.plan_poseidon2_v8_block_against_parent(parent, meta, actions)?;
            return Ok(());
        }

        let canonical_tip = self.best_meta();
        let (ancestor, mut attach_metas) =
            self.stored_branch_suffix_from_canonical_ancestor(parent)?;
        attach_metas.push(meta.clone());
        let detach_tip_first = ((ancestor.height.saturating_add(1))..=canonical_tip.height)
            .rev()
            .map(|height| {
                self.hash_by_height(height)?
                    .ok_or_else(|| anyhow!("missing canonical V8 detach block at height {height}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let store = self.poseidon2_v8_store_synced_to_parent(production, &canonical_tip)?;

        let mut attach_actions = attach_metas
            .iter()
            .take(attach_metas.len().saturating_sub(1))
            .map(|branch_meta| {
                let decoded = decode_block_actions(branch_meta)?;
                verify_decoded_action_root(
                    &decoded,
                    branch_meta,
                    "native V8 stored branch action root",
                )?;
                Ok(decoded)
            })
            .collect::<Result<Vec<_>>>()?;
        attach_actions.push(actions.to_vec());
        let attach_views = attach_metas
            .iter()
            .zip(attach_actions.iter())
            .map(|(branch_meta, branch_actions)| {
                validate_coinbase_route_at_height(branch_actions, branch_meta.height)?;
                validate_poseidon2_v8_replay_window(
                    production,
                    branch_meta.height,
                    branch_actions,
                )?;
                let count = branch_actions
                    .iter()
                    .filter(|action| is_poseidon2_v8_proof_authority_action(action))
                    .count();
                if count > MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK {
                    return Err(anyhow!(
                        "native V8 stored branch block {} exceeds the source-owned {}-action limit",
                        branch_meta.height,
                        MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK
                    ));
                }
                branch_actions
                    .iter()
                    .filter(|action| is_poseidon2_v8_action(action))
                    .map(|action| {
                        poseidon2_v8_verifier::Poseidon2V8ActionView::from_pending(
                            production,
                            branch_meta.height,
                            action,
                        )
                        .map_err(|error| {
                            anyhow!(
                                "native V8 stored branch action at height {} rejected: {error}",
                                branch_meta.height
                            )
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;
        let attach_leaves = attach_views
            .iter()
            .map(|views| {
                views
                    .iter()
                    .map(|view| view.exact_native_leaf())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let attach_blocks = attach_metas
            .iter()
            .zip(attach_actions.iter())
            .zip(attach_leaves.iter())
            .map(|((branch_meta, branch_actions), leaves)| {
                let parent_height = branch_meta
                    .height
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("native V8 stored branch cannot attach genesis"))?;
                let context = poseidon2_v8_state::Poseidon2V8BlockContext::new(
                    parent_height,
                    branch_meta.parent_hash,
                    branch_meta.height,
                    branch_meta.hash,
                )
                .map_err(|error| anyhow!("native V8 stored branch context rejected: {error}"))?;
                let trailing_coinbase =
                    poseidon2_v8_coinbase_commitment_for_actions(branch_actions)?;
                poseidon2_v8_state::Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
                    context,
                    leaves,
                    trailing_coinbase,
                )
                .map_err(|error| anyhow!("native V8 stored branch leaves rejected: {error}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut verifier = RecordingPoseidon2V8Verifier::new(production.connector());
        let plan = store
            .plan_verified_reorganization(&detach_tip_first, &attach_blocks, &mut verifier)
            .map_err(|error| anyhow!("native V8 stored branch verification rejected: {error}"))?;

        let mut transition_offset = 0usize;
        let mut ordered_checkpoint = plan.attach_parent();
        for (((branch_meta, branch_actions), views), leaves) in attach_metas
            .iter()
            .zip(attach_actions.iter())
            .zip(attach_views.iter())
            .zip(attach_leaves.iter())
        {
            let transition_end = transition_offset
                .checked_add(views.len())
                .ok_or_else(|| anyhow!("native V8 stored branch transition offset overflow"))?;
            let transitions = verifier
                .transitions()
                .get(transition_offset..transition_end)
                .ok_or_else(|| anyhow!("native V8 stored branch transition count mismatch"))?;
            transition_offset = transition_end;
            if ordered_checkpoint.height().saturating_add(1) != branch_meta.height
                || ordered_checkpoint.block_hash() != branch_meta.parent_hash
            {
                return Err(anyhow!(
                    "native V8 stored branch checkpoint does not match parent at height {}",
                    branch_meta.height
                ));
            }
            let v8_actions = branch_actions
                .iter()
                .filter(|action| is_poseidon2_v8_action(action))
                .collect::<Vec<_>>();
            let next_root = verify_recorded_poseidon2_v8_block_order(
                ordered_checkpoint,
                &v8_actions,
                leaves,
                transitions,
                "native V8 stored branch action order rejected",
            )?;
            ordered_checkpoint = poseidon2_v8_state::Poseidon2V8Checkpoint::new(
                branch_meta.height,
                branch_meta.hash,
                next_root,
            );
        }
        if transition_offset != verifier.transitions().len()
            || ordered_checkpoint != plan.final_tip()
        {
            return Err(anyhow!(
                "native V8 stored branch typed replay did not converge on the candidate tip"
            ));
        }
        Ok(())
    }

    fn plan_poseidon2_v8_reorganization(
        &self,
        old_blocks: &[NativeCanonicalBlockDelta],
        new_blocks: &[NativeCanonicalBlockDelta],
    ) -> Result<
        Option<(
            poseidon2_v8_state::Poseidon2V8StateStore,
            poseidon2_v8_state::Poseidon2V8CanonicalPlan,
        )>,
    > {
        let has_v8 = old_blocks
            .iter()
            .chain(new_blocks.iter())
            .flat_map(|delta| delta.actions.iter())
            .any(action_uses_poseidon2_v8_state);
        let Some(production) =
            poseidon2_v8_verifier::Poseidon2V8ProductionBinding::from_source_for_replay()
                .map_err(|error| anyhow!("native V8 reorg authority rejected: {error}"))?
        else {
            if has_v8 {
                return Err(anyhow!(
                    "native reorg carries Poseidon2 V8 without an active production capability"
                ));
            }
            return Ok(None);
        };

        for delta in old_blocks.iter().chain(new_blocks.iter()) {
            validate_coinbase_route_at_height(&delta.actions, delta.meta.height)?;
            validate_poseidon2_v8_replay_window(production, delta.meta.height, &delta.actions)?;
            let count = delta
                .actions
                .iter()
                .filter(|action| is_poseidon2_v8_proof_authority_action(action))
                .count();
            if count > MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK {
                return Err(anyhow!(
                    "native V8 reorg block {} exceeds the source-owned {}-action limit",
                    delta.meta.height,
                    MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK
                ));
            }
        }

        let loaded_tip_parent;
        let old_tip = if let Some(delta) = old_blocks.last() {
            &delta.meta
        } else {
            let first = new_blocks
                .first()
                .ok_or_else(|| anyhow!("native V8 reorg has no replacement blocks"))?;
            loaded_tip_parent = self
                .header_by_hash(&first.meta.parent_hash)?
                .ok_or_else(|| anyhow!("native V8 tip extension parent is not stored"))?;
            if loaded_tip_parent.hash != first.meta.parent_hash
                || loaded_tip_parent.height.saturating_add(1) != first.meta.height
            {
                return Err(anyhow!(
                    "native V8 tip extension parent metadata does not match the replacement suffix"
                ));
            }
            &loaded_tip_parent
        };
        let store = self.poseidon2_v8_store_synced_to_parent(production, old_tip)?;
        let detach_tip_first = old_blocks
            .iter()
            .rev()
            .map(|delta| delta.meta.hash)
            .collect::<Vec<_>>();

        let attach_views = new_blocks
            .iter()
            .map(|delta| {
                delta
                    .actions
                    .iter()
                    .filter(|action| is_poseidon2_v8_action(action))
                    .map(|action| {
                        poseidon2_v8_verifier::Poseidon2V8ActionView::from_pending(
                            production,
                            delta.meta.height,
                            action,
                        )
                        .map_err(|error| {
                            anyhow!(
                                "native V8 replacement action at height {} rejected: {error}",
                                delta.meta.height
                            )
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;
        let attach_leaves = attach_views
            .iter()
            .map(|views| {
                views
                    .iter()
                    .map(|view| view.exact_native_leaf())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let attach_blocks = new_blocks
            .iter()
            .zip(attach_leaves.iter())
            .map(|(delta, leaves)| {
                let parent_height = delta
                    .meta
                    .height
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("native V8 replacement block cannot be genesis"))?;
                let context = poseidon2_v8_state::Poseidon2V8BlockContext::new(
                    parent_height,
                    delta.meta.parent_hash,
                    delta.meta.height,
                    delta.meta.hash,
                )
                .map_err(|error| {
                    anyhow!(
                        "native V8 replacement context at height {} rejected: {error}",
                        delta.meta.height
                    )
                })?;
                let trailing_coinbase =
                    poseidon2_v8_coinbase_commitment_for_actions(&delta.actions)?;
                poseidon2_v8_state::Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
                    context,
                    leaves,
                    trailing_coinbase,
                )
                .map_err(|error| {
                    anyhow!(
                        "native V8 replacement leaf batch at height {} rejected: {error}",
                        delta.meta.height
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut verifier = RecordingPoseidon2V8Verifier::new(production.connector());
        let plan = store
            .plan_verified_reorganization(&detach_tip_first, &attach_blocks, &mut verifier)
            .map_err(|error| anyhow!("native V8 replacement suffix rejected: {error}"))?;
        let mut transition_offset = 0usize;
        let mut ordered_checkpoint = plan.attach_parent();
        for ((delta, views), leaves) in new_blocks
            .iter()
            .zip(attach_views.iter())
            .zip(attach_leaves.iter())
        {
            let transition_end = transition_offset
                .checked_add(views.len())
                .ok_or_else(|| anyhow!("native V8 reorg transition offset overflow"))?;
            let transitions = verifier
                .transitions()
                .get(transition_offset..transition_end)
                .ok_or_else(|| anyhow!("native V8 reorg verifier transition count mismatch"))?;
            transition_offset = transition_end;
            let v8_actions = delta
                .actions
                .iter()
                .filter(|action| is_poseidon2_v8_action(action))
                .collect::<Vec<_>>();
            if ordered_checkpoint.height().saturating_add(1) != delta.meta.height
                || ordered_checkpoint.block_hash() != delta.meta.parent_hash
            {
                return Err(anyhow!(
                    "native V8 replacement planner checkpoint does not match block parent at height {}",
                    delta.meta.height
                ));
            }
            let next_root = verify_recorded_poseidon2_v8_block_order(
                ordered_checkpoint,
                &v8_actions,
                leaves,
                transitions,
                "native V8 replacement block action order rejected",
            )?;
            ordered_checkpoint = poseidon2_v8_state::Poseidon2V8Checkpoint::new(
                delta.meta.height,
                delta.meta.hash,
                next_root,
            );
        }
        if transition_offset != verifier.transitions().len() {
            return Err(anyhow!(
                "native V8 reorg verifier returned unassigned transitions"
            ));
        }
        if ordered_checkpoint != plan.final_tip() {
            return Err(anyhow!(
                "native V8 reorg action-order checkpoint differs from typed state plan"
            ));
        }
        Ok(Some((store, plan)))
    }

    /// Build the typed V8 detach/attach plan without retaining complete native
    /// block bodies.  Only V8 proof-authority actions are kept across the pass;
    /// those exact leaf bytes are the minimum input required by the source
    /// verifier to authorize one atomic canonical plan.
    fn plan_poseidon2_v8_stored_reorganization_streaming(
        &self,
        canonical_tip: &NativeBlockMeta,
        ancestry: &[NativePowMetaProjection],
        common_ancestor_index: usize,
        supplied_suffix: &[NativeBlockMeta],
    ) -> Result<
        Option<(
            poseidon2_v8_state::Poseidon2V8StateStore,
            poseidon2_v8_state::Poseidon2V8CanonicalPlan,
        )>,
    > {
        let common_ancestor = ancestry
            .get(common_ancestor_index)
            .copied()
            .ok_or_else(|| anyhow!("native V8 stored reorg ancestor index is out of range"))?;
        if self.hash_by_height(common_ancestor.height)? != Some(common_ancestor.hash) {
            return Err(anyhow!(
                "native V8 stored reorg ancestor is no longer canonical"
            ));
        }

        let production =
            poseidon2_v8_verifier::Poseidon2V8ProductionBinding::from_source_for_replay()
                .map_err(|error| anyhow!("native V8 stored reorg authority rejected: {error}"))?;
        let supplied_start = ancestry
            .len()
            .checked_sub(supplied_suffix.len())
            .ok_or_else(|| anyhow!("native V8 supplied suffix exceeds its branch ancestry"))?;
        for (projection, supplied) in ancestry[supplied_start..]
            .iter()
            .zip(supplied_suffix.iter())
        {
            if *projection != NativePowMetaProjection::from(supplied) {
                return Err(anyhow!(
                    "native V8 supplied suffix projection changed before verification at height {}",
                    projection.height
                ));
            }
        }
        let mut retained_attach_actions = Vec::<Vec<PendingAction>>::new();
        let mut retained_attach_coinbases = Vec::new();
        let attach_projections = &ancestry[common_ancestor_index.saturating_add(1)..];
        let mut has_v8 = false;
        for (offset, projection) in attach_projections.iter().copied().enumerate() {
            let ancestry_index = common_ancestor_index
                .saturating_add(1)
                .saturating_add(offset);
            let (actions, height) = if ancestry_index >= supplied_start {
                let meta = supplied_suffix
                    .get(ancestry_index.saturating_sub(supplied_start))
                    .ok_or_else(|| anyhow!("native V8 supplied suffix index is out of range"))?;
                let actions = decode_block_actions(meta)?;
                verify_decoded_action_root(
                    &actions,
                    meta,
                    "native V8 supplied branch action root",
                )?;
                (actions, meta.height)
            } else {
                #[cfg(test)]
                let _decoded_guard = self.begin_streaming_stored_meta_decode();
                let meta = self
                    .load_exact_stored_meta_for_projection(
                        projection,
                        "native V8 stored reorg attach scan",
                    )
                    .map_err(anyhow::Error::from)?;
                let actions = decode_block_actions(&meta)?;
                verify_decoded_action_root(&actions, &meta, "native V8 stored reorg action root")?;
                (actions, meta.height)
            };
            validate_coinbase_route_at_height(&actions, height)?;
            let block_has_v8 = actions.iter().any(action_uses_poseidon2_v8_state);
            has_v8 |= block_has_v8;
            let trailing_coinbase = poseidon2_v8_coinbase_commitment_for_actions(&actions)?;
            if let Some(production) = production {
                validate_poseidon2_v8_replay_window(production, height, &actions)?;
                let authority_count = actions
                    .iter()
                    .filter(|action| is_poseidon2_v8_proof_authority_action(action))
                    .count();
                if authority_count > MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK {
                    return Err(anyhow!(
                        "native V8 stored reorg block {} exceeds the source-owned {}-action limit",
                        height,
                        MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK
                    ));
                }
            }
            retained_attach_actions
                .push(actions.into_iter().filter(is_poseidon2_v8_action).collect());
            retained_attach_coinbases.push(trailing_coinbase);
        }

        let detach_tip_first = if common_ancestor.height < canonical_tip.height {
            ((common_ancestor.height.saturating_add(1))..=canonical_tip.height)
                .rev()
                .map(|height| {
                    self.hash_by_height(height)?.ok_or_else(|| {
                        anyhow!("missing canonical V8 detach block at height {height}")
                    })
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        if production.is_none() {
            for hash in &detach_tip_first {
                #[cfg(test)]
                let _decoded_guard = self.begin_streaming_stored_meta_decode();
                let meta = self
                    .header_by_hash(hash)?
                    .ok_or_else(|| anyhow!("missing canonical V8 detach block {}", hex32(hash)))?;
                has_v8 |= decode_block_actions(&meta)?
                    .iter()
                    .any(action_uses_poseidon2_v8_state);
            }
            if has_v8 {
                return Err(anyhow!(
                    "native stored reorg carries Poseidon2 V8 without an active production capability"
                ));
            }
            return Ok(None);
        }
        let production = production.expect("checked active V8 replay binding");
        let store = self.poseidon2_v8_store_synced_to_parent(production, canonical_tip)?;
        let attach_views = attach_projections
            .iter()
            .zip(retained_attach_actions.iter())
            .map(|(projection, actions)| {
                actions
                    .iter()
                    .map(|action| {
                        poseidon2_v8_verifier::Poseidon2V8ActionView::from_pending(
                            production,
                            projection.height,
                            action,
                        )
                        .map_err(|error| {
                            anyhow!(
                                "native V8 stored replacement action at height {} rejected: {error}",
                                projection.height
                            )
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;
        let attach_leaves = attach_views
            .iter()
            .map(|views| {
                views
                    .iter()
                    .map(|view| view.exact_native_leaf())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let attach_blocks = attach_projections
            .iter()
            .zip(attach_leaves.iter())
            .zip(retained_attach_coinbases.iter().copied())
            .map(|((projection, leaves), trailing_coinbase)| {
                let parent_height = projection
                    .height
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("native V8 stored replacement cannot attach genesis"))?;
                let context = poseidon2_v8_state::Poseidon2V8BlockContext::new(
                    parent_height,
                    projection.parent_hash,
                    projection.height,
                    projection.hash,
                )
                .map_err(|error| {
                    anyhow!(
                        "native V8 stored replacement context at height {} rejected: {error}",
                        projection.height
                    )
                })?;
                poseidon2_v8_state::Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
                    context,
                    leaves,
                    trailing_coinbase,
                )
                .map_err(|error| {
                    anyhow!(
                        "native V8 stored replacement leaves at height {} rejected: {error}",
                        projection.height
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut verifier = RecordingPoseidon2V8Verifier::new(production.connector());
        let plan = store
            .plan_verified_reorganization(&detach_tip_first, &attach_blocks, &mut verifier)
            .map_err(|error| anyhow!("native V8 stored replacement suffix rejected: {error}"))?;

        let mut transition_offset = 0usize;
        let mut ordered_checkpoint = plan.attach_parent();
        for (((projection, actions), views), leaves) in attach_projections
            .iter()
            .zip(retained_attach_actions.iter())
            .zip(attach_views.iter())
            .zip(attach_leaves.iter())
        {
            let transition_end = transition_offset
                .checked_add(views.len())
                .ok_or_else(|| anyhow!("native V8 stored reorg transition offset overflow"))?;
            let transitions = verifier
                .transitions()
                .get(transition_offset..transition_end)
                .ok_or_else(|| anyhow!("native V8 stored reorg transition count mismatch"))?;
            transition_offset = transition_end;
            if ordered_checkpoint.height().saturating_add(1) != projection.height
                || ordered_checkpoint.block_hash() != projection.parent_hash
            {
                return Err(anyhow!(
                    "native V8 stored reorg checkpoint does not match parent at height {}",
                    projection.height
                ));
            }
            let action_refs = actions.iter().collect::<Vec<_>>();
            let next_root = verify_recorded_poseidon2_v8_block_order(
                ordered_checkpoint,
                &action_refs,
                leaves,
                transitions,
                "native V8 stored replacement action order rejected",
            )?;
            ordered_checkpoint = poseidon2_v8_state::Poseidon2V8Checkpoint::new(
                projection.height,
                projection.hash,
                next_root,
            );
        }
        if transition_offset != verifier.transitions().len()
            || ordered_checkpoint != plan.final_tip()
        {
            return Err(anyhow!(
                "native V8 stored reorg typed replay did not converge on the candidate tip"
            ));
        }
        Ok(Some((store, plan)))
    }

    fn pending_rejection_cache_key(
        parent_hash: &[u8; 32],
        semantic_hash: &ActionSemanticId48,
    ) -> NativePendingRejectionKey {
        NativePendingRejectionKey {
            parent_hash: *parent_hash,
            semantic_id: *semantic_hash,
        }
    }

    pub(crate) fn rejected_pending_action_is_cached(
        &self,
        parent_hash: &[u8; 32],
        semantic_hash: &ActionSemanticId48,
    ) -> bool {
        let key = Self::pending_rejection_cache_key(parent_hash, semantic_hash);
        self.rejected_pending_actions
            .lock()
            .contains_at(&key, Instant::now())
    }

    fn remember_rejected_pending_action(
        &self,
        parent_hash: &[u8; 32],
        semantic_hash: ActionSemanticId48,
    ) {
        let key = Self::pending_rejection_cache_key(parent_hash, &semantic_hash);
        self.rejected_pending_actions
            .lock()
            .insert_at(key, Instant::now());
    }

    pub(crate) fn begin_pending_proof_admission(
        &self,
        pending: &PendingAction,
    ) -> Result<Option<ActionSemanticId48>> {
        let (_, semantic_hash) = validate_pending_action_identity(pending)?;
        self.begin_validated_pending_proof_admission(semantic_hash)
    }

    fn begin_validated_pending_proof_admission(
        &self,
        semantic_hash: ActionSemanticId48,
    ) -> Result<Option<ActionSemanticId48>> {
        let parent_hash = self.best_tip().1;
        if self.rejected_pending_action_is_cached(&parent_hash, &semantic_hash) {
            return Err(anyhow!(
                "native pending action was deterministically rejected recently"
            ));
        }
        Ok(self
            .pending_proof_admissions_in_flight
            .lock()
            .insert(semantic_hash)
            .then_some(semantic_hash))
    }

    #[cfg(test)]
    pub(crate) fn finish_pending_proof_admission(&self, semantic_hash: &ActionSemanticId48) {
        self.pending_proof_admissions_in_flight
            .lock()
            .remove(semantic_hash);
    }

    pub(crate) fn pending_proof_admission_guard(
        &self,
        key: ActionSemanticId48,
    ) -> NativePendingProofAdmissionGuard {
        NativePendingProofAdmissionGuard {
            in_flight: Arc::clone(&self.pending_proof_admissions_in_flight),
            key,
        }
    }

    pub(crate) fn mineable_actions_for_work(
        &self,
        state: &NativeState,
        work: &NativeWork,
    ) -> Vec<PendingAction> {
        if work.tx_count == 0 {
            return Vec::new();
        }
        if let Some(actions) = work.prepared_actions.as_ref() {
            if prepared_mining_actions_match_state(state, actions) {
                return actions.as_ref().clone();
            }
        }
        // A work package without its exact prepared action snapshot is stale.
        // Never substitute the current mempool: a same-count replacement could
        // otherwise be hashed under commitments from a different body.
        Vec::new()
    }

    pub(crate) fn cached_native_work_template(&self, require_fresh: bool) -> Option<NativeWork> {
        let entry = self.work_template_cache.lock().clone()?;
        if require_fresh && entry.built_at.elapsed() >= NATIVE_WORK_TEMPLATE_REFRESH_INTERVAL {
            return None;
        }
        let state = self.state.read();
        if entry.work.parent_hash != state.best.hash
            || entry.work.height != state.best.height.checked_add(1)?
        {
            return None;
        }
        let actions = entry
            .work
            .prepared_actions
            .as_ref()
            .map(|actions| actions.as_slice())
            .unwrap_or(&[]);
        if !prepared_mining_actions_match_state(&state, actions) {
            return None;
        }
        Some(entry.work)
    }

    pub(crate) fn prepare_work(&self) -> Result<NativeWork> {
        self.ensure_native_storage_healthy()?;
        if let Some(work) = self.cached_native_work_template(true) {
            return Ok(work);
        }
        let stale_but_valid = self.cached_native_work_template(false);
        // One miner refreshes an expired but still-valid template. Siblings
        // continue hashing that template rather than idling for proof/DA work.
        // If no valid template exists, wait for the single builder.
        let _build_guard = match self.work_template_build_lock.try_lock() {
            Some(guard) => guard,
            None => {
                if let Some(work) = stale_but_valid {
                    return Ok(work);
                }
                self.work_template_build_lock.lock()
            }
        };
        if let Some(work) = self.cached_native_work_template(true) {
            return Ok(work);
        }
        let _template_permit = Arc::clone(&self.work_template_proof_semaphore)
            .try_acquire_owned()
            .map_err(|_| anyhow!("native work-template proof verifier already in flight"))?;
        let _proof_permit = Arc::clone(&self.pending_proof_admission_semaphore)
            .try_acquire_owned()
            .map_err(|_| anyhow!("native proof verifier at capacity; retry work preparation"))?;
        self.quarantine_inactive_pending_actions()?;
        #[cfg(test)]
        self.work_template_build_invocations
            .fetch_add(1, Ordering::Relaxed);
        let (work, cacheable) =
            self.prepare_work_inner(true, false, MAX_NATIVE_WORK_TEMPLATE_SNAPSHOT_RETRIES)?;
        if cacheable {
            *self.work_template_cache.lock() = Some(NativeWorkTemplateCacheEntry {
                work: work.clone(),
                built_at: Instant::now(),
            });
        }
        Ok(work)
    }

    fn individually_invalid_smallwood_actions(
        &self,
        best: &NativeBlockMeta,
        commitment_tree: &CommitmentTreeState,
        actions: &[PendingAction],
    ) -> Vec<PendingAction> {
        actions
            .par_iter()
            .filter(|action| is_shielded_transfer_action(action))
            .filter_map(|action| {
                match self.preflight_pending_transfer_proof_against_parent(
                    action,
                    best,
                    commitment_tree,
                ) {
                    Ok(()) => None,
                    Err(failure) if failure.is_deterministic() => {
                        self.remember_rejected_pending_action(
                            &best.hash,
                            pending_action_semantic_hash(action),
                        );
                        warn!(
                            tx_hash = %hex48(action.tx_hash.as_bytes()),
                            error = %failure.error,
                            "isolated deterministically invalid native pending proof"
                        );
                        Some(action.clone())
                    }
                    Err(failure) => {
                        warn!(
                            tx_hash = %hex48(action.tx_hash.as_bytes()),
                            error = %failure.error,
                            "native pending proof isolation hit a transient dependency failure"
                        );
                        None
                    }
                }
            })
            .collect()
    }

    fn restore_removed_pending_action_rows(
        &self,
        rows: &[(PendingAction, Vec<u8>)],
        context: &'static str,
    ) -> Result<()> {
        let restore: sled::transaction::TransactionResult<(), String> =
            self.action_tree.transaction(|action_tree| {
                for (action, encoded) in rows {
                    match action_tree.get(action.tx_hash.as_ref())? {
                        Some(current) if current.as_ref() == encoded.as_slice() => {}
                        Some(_) => {
                            return Err(sled::transaction::ConflictableTransactionError::Abort(
                                format!(
                                    "pending action {} changed during {context}",
                                    hex48(action.tx_hash.as_bytes())
                                ),
                            ));
                        }
                        None => {
                            action_tree
                                .insert(action.tx_hash.as_bytes().to_vec(), encoded.clone())?;
                        }
                    }
                }
                Ok(())
            });
        restore.map_err(|err| anyhow!("{context} transaction failed: {err}"))?;
        self.db
            .flush()
            .with_context(|| format!("{context} durability barrier failed"))?;
        Ok(())
    }

    fn persist_sidecar_rows_exact(
        &self,
        tree: &sled::Tree,
        writes: &BTreeMap<Vec<u8>, Vec<u8>>,
        previous: &BTreeMap<Vec<u8>, Option<Vec<u8>>>,
        context: &'static str,
    ) -> Result<()> {
        let stage_result: sled::transaction::TransactionResult<(), String> =
            tree.transaction(|tree| {
                for (key, value) in writes {
                    let current = tree.get(key.as_slice())?.map(|bytes| bytes.to_vec());
                    if current != previous.get(key).cloned().flatten() {
                        return Err(sled::transaction::ConflictableTransactionError::Abort(
                            format!("sidecar row changed before {context}"),
                        ));
                    }
                    tree.insert(key.clone(), value.clone())?;
                }
                Ok(())
            });
        stage_result.map_err(|err| anyhow!("atomic {context} failed: {err}"))
    }

    fn rollback_sidecar_rows_exact(
        &self,
        tree: &sled::Tree,
        writes: &BTreeMap<Vec<u8>, Vec<u8>>,
        previous: &BTreeMap<Vec<u8>, Option<Vec<u8>>>,
        context: &'static str,
    ) -> Result<()> {
        let rollback: sled::transaction::TransactionResult<(), String> = tree.transaction(|tree| {
            for (key, value) in writes {
                let current = tree.get(key.as_slice())?.map(|bytes| bytes.to_vec());
                if current.as_deref() != Some(value.as_slice()) {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        format!("sidecar row changed before {context}"),
                    ));
                }
                match previous.get(key).cloned().flatten() {
                    Some(previous) => {
                        tree.insert(key.clone(), previous)?;
                    }
                    None => {
                        tree.remove(key.clone())?;
                    }
                }
            }
            Ok(())
        });
        rollback.map_err(|err| anyhow!("atomic {context} failed: {err}"))?;
        self.db
            .flush()
            .with_context(|| format!("{context} durability barrier failed"))?;
        Ok(())
    }

    fn quarantine_invalid_pending_actions(
        &self,
        invalid: &[PendingAction],
        context: &'static str,
        operation: NativeStorageDurabilityOperation,
    ) -> Result<usize> {
        if invalid.is_empty() {
            return Ok(0);
        }
        let _persistence_epoch = self.pending_action_persistence_lock.lock();
        let (pending_generation, victims) = {
            let state = self.state.read();
            let victims = invalid
                .iter()
                .filter_map(|action| {
                    state
                        .pending_actions
                        .get(&action.tx_hash)
                        .filter(|current| current.encode() == action.encode())
                        .map(|current| (current.clone(), current.encode()))
                })
                .collect::<Vec<_>>();
            (
                self.pending_action_generation.load(Ordering::Acquire),
                victims,
            )
        };
        if victims.is_empty() {
            return Ok(0);
        }
        let quarantine_result: sled::transaction::TransactionResult<(), String> =
            self.action_tree.transaction(|action_tree| {
                for (action, encoded) in &victims {
                    match action_tree.get(action.tx_hash.as_ref())? {
                        Some(current) if current.as_ref() == encoded.as_slice() => {}
                        _ => {
                            return Err(sled::transaction::ConflictableTransactionError::Abort(
                                format!(
                                    "pending action {} changed before quarantine",
                                    hex48(action.tx_hash.as_bytes())
                                ),
                            ));
                        }
                    }
                }
                for (action, _) in &victims {
                    action_tree.remove(action.tx_hash.as_bytes().to_vec())?;
                }
                Ok(())
            });
        quarantine_result
            .map_err(|err| anyhow!("atomic native invalid-proof quarantine failed: {err}"))?;
        if let Err(flush_error) = self.flush_native_durability_barrier(context, operation) {
            let rollback = self.restore_removed_pending_action_rows(
                &victims,
                "invalid-action quarantine rollback",
            );
            return Err(match rollback {
                Ok(()) => flush_error,
                Err(rollback_error) => {
                    self.poison_native_storage();
                    anyhow!(
                        "{flush_error}; invalid-action quarantine rollback failed: {rollback_error}; storage fail-stop engaged"
                    )
                }
            });
        }
        let mut state = self.state.write();
        let state_matches = self.pending_action_generation.load(Ordering::Acquire)
            == pending_generation
            && victims.iter().all(|(action, encoded)| {
                state
                    .pending_actions
                    .get(&action.tx_hash)
                    .is_some_and(|current| current.encode().as_slice() == encoded.as_slice())
            });
        if !state_matches {
            drop(state);
            self.restore_removed_pending_action_rows(
                &victims,
                "invalid-action quarantine revalidation rollback",
            )?;
            return Err(anyhow!(
                "native pending state changed during invalid-action quarantine"
            ));
        }
        for (action, _) in &victims {
            remove_pending_action_from_state(&mut state, &action.tx_hash);
            warn!(tx_hash = %hex48(action.tx_hash.as_bytes()), "durably quarantined native pending action");
        }
        self.pending_action_generation
            .fetch_add(1, Ordering::Release);
        Ok(victims.len())
    }

    fn sanitize_persisted_pending_smallwood_actions(&self) -> Result<()> {
        let (best, commitment_tree, actions) = {
            let state = self.state.read();
            (
                state.best.clone(),
                state.commitment_tree.clone(),
                select_mineable_actions(&state),
            )
        };
        if !actions.iter().any(is_shielded_transfer_action) {
            return Ok(());
        }
        let Some(height) = best.height.checked_add(1) else {
            return Err(anyhow!("native startup proof-policy height overflow"));
        };
        let proof_header_timestamp_ms = current_time_ms();
        if self
            .verify_independent_smallwood_actions_against_parent(
                &best,
                &commitment_tree,
                height,
                proof_header_timestamp_ms,
                &actions,
            )
            .is_ok()
        {
            return Ok(());
        }

        let invalid =
            self.individually_invalid_smallwood_actions(&best, &commitment_tree, &actions);
        if invalid.is_empty() {
            warn!(
                "persisted native pending proof batch failed while every independent proof passed; retaining actions for safe empty-template fallback"
            );
            return Ok(());
        }
        self.quarantine_invalid_pending_actions(
            &invalid,
            "startup invalid native pending proof quarantine",
            NativeStorageDurabilityOperation::StartupPendingActionRepair,
        )?;

        let (retry_best, retry_commitment_tree, retry_actions) = {
            let state = self.state.read();
            (
                state.best.clone(),
                state.commitment_tree.clone(),
                select_mineable_actions(&state),
            )
        };
        let Some(retry_height) = retry_best.height.checked_add(1) else {
            return Err(anyhow!("native startup proof-policy retry height overflow"));
        };
        if let Err(failure) = self.verify_independent_smallwood_actions_against_parent(
            &retry_best,
            &retry_commitment_tree,
            retry_height,
            proof_header_timestamp_ms,
            &retry_actions,
        ) {
            warn!(
                error = %failure.error,
                "native startup pending proof survivor batch still failed; mining will use the safe empty-template fallback"
            );
        }
        Ok(())
    }

    fn prepare_work_inner(
        &self,
        allow_invalid_proof_recovery: bool,
        force_empty_actions: bool,
        snapshot_retries_remaining: usize,
    ) -> Result<(NativeWork, bool)> {
        let mut cacheable = !force_empty_actions;
        let (best, commitment_tree, mut pending_actions) = {
            let state = self.state.read();
            (
                state.best.clone(),
                state.commitment_tree.clone(),
                select_mineable_actions(&state),
            )
        };
        let (persisted_best, exact_best) = self
            .inspect_stored_pow_metadata(
                &best.hash,
                Some(&best),
                "native persisted best work-template metadata",
            )?
            .ok_or_else(|| anyhow!("missing native block {}", hex32(&best.hash)))?;
        if !exact_best || (persisted_best.height, persisted_best.hash) != (best.height, best.hash) {
            return Err(anyhow!(
                "native persisted best record changed during work-template construction"
            ));
        }
        if self.config.miner_address.is_some() {
            pending_actions.retain(|action| !is_coinbase_action(action));
        }
        if force_empty_actions {
            pending_actions.clear();
        }
        if native_work_template_next_height(best.height).is_none() {
            return Err(native_work_template_admission_error(
                NativeWorkTemplateAdmissionRejection::HeightNotNext,
            ));
        }
        let pow_bits = self.expected_canonical_child_pow_bits(&best)?;
        let cumulative_work = cumulative_work_after(&best.cumulative_work, pow_bits)
            .map_err(|_| NativeWorkTemplateAdmissionRejection::CumulativeWorkOverflow);
        let height = evaluate_native_work_template_admission(NativeWorkTemplateAdmissionInput {
            best_height: best.height,
            cumulative_work_advances: cumulative_work.is_ok(),
        })
        .map_err(native_work_template_admission_error)?;
        let cumulative_work = cumulative_work.map_err(native_work_template_admission_error)?;
        let template_timestamp_ms = current_time_ms();
        let v8_actions = pending_actions
            .iter()
            .filter(|action| is_poseidon2_v8_action(action))
            .collect::<Vec<_>>();
        if !v8_actions.is_empty() {
            let (_, _, _, canonical_v8_ids) =
                self.prepare_poseidon2_v8_action_order_against_parent(&v8_actions, &best, height)?;
            reorder_poseidon2_v8_action_slots(&mut pending_actions, &canonical_v8_ids)?;
        }
        let reserved_coinbase_bytes =
            self.auto_coinbase_action_reservation_bytes_at_height(height)?;
        let reserved_coinbase_count = usize::from(reserved_coinbase_bytes != 0);
        let da_selection = select_native_da_action_prefix_with_reservation(
            &pending_actions,
            reserved_coinbase_count,
            reserved_coinbase_bytes,
            reserved_coinbase_count,
        )?;
        pending_actions = da_selection.selected;
        if !da_selection.individually_unencodable.is_empty() {
            for action in &da_selection.individually_unencodable {
                self.remember_rejected_pending_action(
                    &best.hash,
                    pending_action_semantic_hash(action),
                );
            }
            let quarantined = self.quarantine_invalid_pending_actions(
                &da_selection.individually_unencodable,
                "template unencodable native DA action quarantine",
                NativeStorageDurabilityOperation::PendingActionStage,
            )?;
            if quarantined == 0 {
                return Err(anyhow!(
                    "native individually unencodable DA action changed before quarantine"
                ));
            }
            return self.prepare_work_inner(
                allow_invalid_proof_recovery,
                force_empty_actions,
                snapshot_retries_remaining,
            );
        }
        let mut verified_da_encoding = None;
        if !force_empty_actions {
            match self.verify_independent_smallwood_actions_against_parent(
                &best,
                &commitment_tree,
                height,
                template_timestamp_ms,
                &pending_actions,
            ) {
                Ok(verified) => {
                    reorder_poseidon2_v8_action_slots(
                        &mut pending_actions,
                        &verified.canonical_poseidon2_v8_action_ids,
                    )?;
                    verified_da_encoding = verified.verified_da_encoding;
                }
                Err(failure) => {
                    let err = failure.error;
                    if allow_invalid_proof_recovery {
                        let recovery_actions = pending_actions.clone();
                        let invalid = self.individually_invalid_smallwood_actions(
                            &best,
                            &commitment_tree,
                            &recovery_actions,
                        );
                        if invalid.is_empty() {
                            warn!(
                                error = %err,
                                "native pending proof batch failed while every independent proof passed; using one safe empty template"
                            );
                            return self
                                .prepare_work_inner(false, true, snapshot_retries_remaining)
                                .map(|(work, _)| (work, false));
                        }
                        self.quarantine_invalid_pending_actions(
                            &invalid,
                            "template invalid native pending proof quarantine",
                            NativeStorageDurabilityOperation::PendingActionStage,
                        )?;
                        return self.prepare_work_inner(false, false, snapshot_retries_remaining);
                    }
                    warn!(
                        error = %err,
                        "native pending proof survivor batch failed; using safe empty template"
                    );
                    pending_actions.clear();
                    cacheable = false;
                }
            }
        }
        let snapshot_state = {
            let state = self.state.read();
            let tip_matches = (state.best.height, state.best.hash) == (best.height, best.hash);
            let selected_actions_match = force_empty_actions
                || pending_actions.is_empty()
                || prepared_mining_actions_match_state(&state, &pending_actions);
            if !tip_matches || !selected_actions_match {
                drop(state);
                if snapshot_retries_remaining == 0 {
                    return Err(anyhow!(
                        "native work-template canonical snapshot changed during proof verification"
                    ));
                }
                return self.prepare_work_inner(
                    allow_invalid_proof_recovery,
                    force_empty_actions,
                    snapshot_retries_remaining - 1,
                );
            }
            NativeState {
                best: state.best.clone(),
                header_mmr_peaks: state.header_mmr_peaks.clone(),
                pending_actions: BTreeMap::new(),
                pending_action_semantic_index: BTreeMap::new(),
                pending_action_order_index: BTreeSet::new(),
                pending_nullifiers: BTreeSet::new(),
                pending_bridge_replay_keys: PersistentKeySet48::new(),
                pending_mempool_bytes: 0,
                commitment_tree: state.commitment_tree.clone(),
                nullifiers: state.nullifiers.clone(),
                nullifier_accumulator: state.nullifier_accumulator.clone(),
                consumed_bridge_messages: state.consumed_bridge_messages.clone(),
                stablecoin_policy_authorizations: state.stablecoin_policy_authorizations.clone(),
                staged_ciphertexts: BTreeMap::new(),
                staged_proofs: BTreeMap::new(),
            }
        };
        let mut prepared_coinbase =
            match self.append_auto_coinbase_action(height, &mut pending_actions) {
                Ok(action) => action,
                Err(err) => {
                    cacheable = false;
                    warn!(
                        error = %err,
                        "dropping native pending actions before auto coinbase"
                    );
                    pending_actions.clear();
                    self.append_auto_coinbase_action(height, &mut pending_actions)?
                }
            };
        let (mut actions, mut state_root, mut nullifier_root, mut extrinsics_root, mut tx_count) =
            match preview_pending_roots(&self.da_ciphertext_tree, &snapshot_state, &pending_actions)
            {
                Ok((state_root, nullifier_root, extrinsics_root, tx_count)) => (
                    pending_actions,
                    state_root,
                    nullifier_root,
                    extrinsics_root,
                    tx_count,
                ),
                Err(err) => {
                    cacheable = false;
                    warn!(error = %err, "failed to preview native pending action roots");
                    let mut fallback_actions = Vec::new();
                    prepared_coinbase =
                        self.append_auto_coinbase_action(height, &mut fallback_actions)?;
                    match preview_pending_roots(
                        &self.da_ciphertext_tree,
                        &snapshot_state,
                        &fallback_actions,
                    ) {
                        Ok((state_root, nullifier_root, extrinsics_root, tx_count)) => (
                            fallback_actions,
                            state_root,
                            nullifier_root,
                            extrinsics_root,
                            tx_count,
                        ),
                        Err(fallback_err) => {
                            warn!(
                                error = %fallback_err,
                                "failed to preview native auto coinbase fallback"
                            );
                            (
                                Vec::new(),
                                best.state_root,
                                best.nullifier_root,
                                actions_extrinsics_root(&[]),
                                0,
                            )
                        }
                    }
                }
            };
        if let Some(coinbase) = prepared_coinbase.as_ref() {
            if coinbase.encoded_size() > reserved_coinbase_bytes {
                return Err(anyhow!(
                    "generated native coinbase exceeded its exact template reservation"
                ));
            }
        }
        let final_action_count = u32::try_from(actions.len())
            .map_err(|_| anyhow!("native work-template action count exceeds u32"))?;
        validate_block_action_byte_budget(
            final_action_count,
            actions.len(),
            actions.iter().map(PendingAction::encoded_size),
        )?;
        // Re-evaluate the single source authority over the final template,
        // after miner-local coinbase insertion. This is the convergence point
        // that prevents 512 V8 transaction proofs plus a 513th mint action.
        validate_native_block_proof_policy(best.height, height, &actions)?;
        let timestamp_ms = template_timestamp_ms.max(best.timestamp_ms.saturating_add(1));
        let supply_digest = match advance_native_supply_digest(best.supply_digest, &actions, height)
        {
            Ok(supply_digest) => supply_digest,
            Err(err) => {
                cacheable = false;
                warn!(error = %err, "dropping native pending actions with invalid supply accounting");
                actions = Vec::new();
                state_root = best.state_root;
                nullifier_root = best.nullifier_root;
                extrinsics_root = actions_extrinsics_root(&[]);
                tx_count = 0;
                best.supply_digest
            }
        };
        let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
        let bridge_messages = bridge_messages_from_actions(&actions, height)?;
        let message_root = bridge_message_root(&bridge_messages);
        let message_count = u32::try_from(bridge_messages.len()).unwrap_or(u32::MAX);
        let (header_mmr_root, header_mmr_len) = header_mmr_commitment_after_best(
            &snapshot_state.best,
            &snapshot_state.header_mmr_peaks,
        )?;
        let final_transfer_hashes = actions
            .iter()
            .filter(|action| is_legacy_shielded_transfer_action(action))
            .map(|action| action.tx_hash)
            .collect::<Vec<_>>();
        let (da_params, da_encoding) = match verified_da_encoding
            .filter(|verified| verified.transfer_hashes == final_transfer_hashes)
        {
            Some(verified) => (verified.params, verified.encoding),
            None => {
                let da_transactions =
                    native_consensus_transactions_from_actions(self, &snapshot_state, &actions)?;
                let da_params = native_da_params_for_transactions(&da_transactions)?;
                let da_encoding = consensus::encode_da_blob(&da_transactions, da_params)
                    .map_err(|err| anyhow!("encode native work-template DA blob failed: {err}"))?;
                (da_params, Arc::new(da_encoding))
            }
        };
        let da_root = da_encoding.root();
        let da_blob_len = da_encoding.data_len();
        let da_chunk_count = u32::try_from(da_encoding.chunks().len())
            .map_err(|_| anyhow!("native work-template DA chunk count exceeds u32"))?;
        let pre_header = native_pow_header_from_parts(
            height,
            timestamp_ms,
            best.hash,
            pow_bits,
            [0u8; 32],
            cumulative_work,
            &state_root,
            &kernel_root,
            &nullifier_root,
            &da_root,
            &extrinsics_root,
            &message_root,
            message_count,
            &header_mmr_root,
            header_mmr_len,
            supply_digest,
            tx_count,
        );
        let pre_hash = pre_header.pre_hash();
        {
            let state = self.state.read();
            if (state.best.height, state.best.hash) != (best.height, best.hash)
                || (!actions.is_empty() && !prepared_mining_actions_match_state(&state, &actions))
            {
                drop(state);
                if snapshot_retries_remaining == 0 {
                    return Err(anyhow!(
                        "native work-template canonical snapshot changed during DA construction"
                    ));
                }
                return self.prepare_work_inner(
                    allow_invalid_proof_recovery,
                    force_empty_actions,
                    snapshot_retries_remaining - 1,
                );
            }
        }
        Ok((
            NativeWork {
                height,
                parent_hash: best.hash,
                pre_hash,
                state_root,
                kernel_root,
                nullifier_root,
                extrinsics_root,
                message_root,
                message_count,
                header_mmr_root,
                header_mmr_len,
                cumulative_work,
                supply_digest,
                tx_count,
                da_root,
                da_chunk_size: da_params.chunk_size,
                da_sample_count: da_params.sample_count,
                da_blob_len,
                da_chunk_count,
                timestamp_ms,
                pow_bits,
                prepared_actions: Some(Arc::new(actions)),
            },
            cacheable,
        ))
    }

    fn quarantine_inactive_pending_actions(&self) -> Result<()> {
        let has_inactive = {
            let state = self.state.read();
            if state.pending_actions.is_empty() {
                return Ok(());
            }
            let Some(action_height) = state.best.height.checked_add(1) else {
                return Ok(());
            };
            state.pending_actions.values().any(|action| {
                validate_native_action_version_at_height(
                    action_height,
                    action.binding,
                    action.family_id,
                    action.action_id,
                )
                .is_err()
                    || ensure_native_v3_active_action_route(action, false).is_err()
            })
        };
        if !has_inactive {
            return Ok(());
        }

        let _persistence_epoch = self.pending_action_persistence_lock.lock();
        let (action_height, pending_generation, inactive) = {
            let state = self.state.read();
            let action_height = state
                .best
                .height
                .checked_add(1)
                .ok_or_else(|| anyhow!("native action version policy height overflow"))?;
            let inactive = state
                .pending_actions
                .values()
                .filter(|action| {
                    validate_native_action_version_at_height(
                        action_height,
                        action.binding,
                        action.family_id,
                        action.action_id,
                    )
                    .is_err()
                        || ensure_native_v3_active_action_route(action, false).is_err()
                })
                .map(|action| (action.clone(), action.encode()))
                .collect::<Vec<_>>();
            (
                action_height,
                self.pending_action_generation.load(Ordering::Acquire),
                inactive,
            )
        };
        if inactive.is_empty() {
            return Ok(());
        }

        let quarantine_result: sled::transaction::TransactionResult<(), String> =
            self.action_tree.transaction(|action_tree| {
                for (action, encoded) in &inactive {
                    match action_tree.get(action.tx_hash.as_ref())? {
                        Some(current) if current.as_ref() == encoded.as_slice() => {}
                        _ => {
                            return Err(sled::transaction::ConflictableTransactionError::Abort(
                                format!(
                                    "pending action {} changed before inactive quarantine",
                                    hex48(action.tx_hash.as_bytes())
                                ),
                            ));
                        }
                    }
                }
                for (action, _) in &inactive {
                    action_tree.remove(action.tx_hash.as_bytes().to_vec())?;
                }
                Ok(())
            });
        quarantine_result.map_err(|err| {
            anyhow!("atomic inactive native pending-action quarantine failed: {err}")
        })?;
        if let Err(flush_error) = self.flush_native_durability_barrier(
            "inactive native pending-action quarantine",
            NativeStorageDurabilityOperation::PendingActionStage,
        ) {
            let rollback = self.restore_removed_pending_action_rows(
                &inactive,
                "inactive-action quarantine rollback",
            );
            return Err(match rollback {
                Ok(()) => flush_error,
                Err(rollback_error) => {
                    self.poison_native_storage();
                    anyhow!(
                        "{flush_error}; inactive-action quarantine rollback failed: {rollback_error}; storage fail-stop engaged"
                    )
                }
            });
        }
        let mut state = self.state.write();
        let state_matches = self.pending_action_generation.load(Ordering::Acquire)
            == pending_generation
            && state.best.height.checked_add(1) == Some(action_height)
            && inactive.iter().all(|(action, encoded)| {
                state
                    .pending_actions
                    .get(&action.tx_hash)
                    .is_some_and(|current| current.encode().as_slice() == encoded.as_slice())
            });
        if !state_matches {
            drop(state);
            self.restore_removed_pending_action_rows(
                &inactive,
                "inactive-action quarantine revalidation rollback",
            )?;
            return Err(anyhow!(
                "native state changed during inactive-action quarantine"
            ));
        }
        for (action, _) in &inactive {
            remove_pending_action_from_state(&mut state, &action.tx_hash);
            warn!(
                tx_hash = %hex48(action.tx_hash.as_bytes()),
                action_height,
                "quarantined inactive or non-authorable pending action before mining"
            );
        }
        self.pending_action_generation
            .fetch_add(1, Ordering::Release);
        Ok(())
    }

    fn canonical_state_snapshot(state: &NativeState) -> NativeState {
        NativeState {
            best: state.best.clone(),
            header_mmr_peaks: state.header_mmr_peaks.clone(),
            pending_actions: BTreeMap::new(),
            pending_action_semantic_index: BTreeMap::new(),
            pending_action_order_index: BTreeSet::new(),
            pending_nullifiers: BTreeSet::new(),
            pending_bridge_replay_keys: PersistentKeySet48::new(),
            pending_mempool_bytes: 0,
            commitment_tree: state.commitment_tree.clone(),
            nullifiers: state.nullifiers.clone(),
            nullifier_accumulator: state.nullifier_accumulator.clone(),
            consumed_bridge_messages: state.consumed_bridge_messages.clone(),
            stablecoin_policy_authorizations: state.stablecoin_policy_authorizations.clone(),
            staged_ciphertexts: BTreeMap::new(),
            staged_proofs: BTreeMap::new(),
        }
    }

    /// Canonical commits increment a generation while holding the writer lock.
    /// This makes the final compare O(1) even when the nullifier or bridge sets
    /// are large; the best hash additionally binds the accepted header roots.
    fn canonical_state_matches_snapshot(
        &self,
        live: &NativeState,
        snapshot: &NativeState,
        snapshot_generation: u64,
    ) -> bool {
        self.canonical_state_generation.load(Ordering::Acquire) == snapshot_generation
            && live.best.height == snapshot.best.height
            && live.best.hash == snapshot.best.hash
    }

    pub(crate) fn import_mined_block(
        &self,
        work: &NativeWork,
        seal: NativeSeal,
    ) -> Result<Option<NativeBlockMeta>> {
        self.ensure_native_storage_healthy()?;
        let (snapshot, snapshot_generation, actions) = {
            let state = self.state.read();
            (
                Self::canonical_state_snapshot(&state),
                self.canonical_state_generation.load(Ordering::Acquire),
                self.mineable_actions_for_work(&state, work),
            )
        };
        if evaluate_native_mined_work_admission(native_mined_work_admission_input(
            &snapshot.best,
            work,
        ))
        .is_err()
        {
            return Ok(None);
        }
        let expected_pow_bits = self.expected_child_pow_bits(&snapshot.best)?;
        if work.pow_bits != expected_pow_bits {
            debug!(
                expected_pow_bits,
                observed_pow_bits = work.pow_bits,
                "native mined work no longer matches scheduled PoW bits"
            );
            return Ok(None);
        }

        validate_native_block_proof_policy(snapshot.best.height, work.height, &actions)?;
        let (preview_state_root, preview_nullifier_root, preview_extrinsics_root, preview_tx_count) =
            match preview_pending_roots(&self.da_ciphertext_tree, &snapshot, &actions) {
                Ok(roots) => roots,
                Err(err) => {
                    debug!(error = %err, "native mined work no longer matches pending actions");
                    return Ok(None);
                }
            };
        let preview_kernel_root =
            consensus::types::kernel_root_from_shielded_root(&preview_state_root);
        let preview_bridge_messages = bridge_messages_from_actions(&actions, work.height)?;
        let preview_message_count = u32::try_from(preview_bridge_messages.len())
            .map_err(|_| anyhow!("native bridge message count overflow"))?;
        let preview_message_root = bridge_message_root(&preview_bridge_messages);
        let (expected_header_mmr_root, expected_header_mmr_len) =
            header_mmr_commitment_after_best(&snapshot.best, &snapshot.header_mmr_peaks)?;
        let supply_digest =
            advance_native_supply_digest(snapshot.best.supply_digest, &actions, work.height)?;
        match evaluate_native_block_commitment_admission(NativeBlockCommitmentAdmissionInput {
            tx_count_matches: preview_tx_count == work.tx_count,
            state_root_matches: preview_state_root == work.state_root,
            kernel_root_matches: preview_kernel_root == work.kernel_root,
            nullifier_root_matches: preview_nullifier_root == work.nullifier_root,
            extrinsics_root_matches: preview_extrinsics_root == work.extrinsics_root,
            message_root_matches: preview_message_root == work.message_root,
            message_count_matches: preview_message_count == work.message_count,
            header_mmr_root_matches: work.header_mmr_root == expected_header_mmr_root,
            header_mmr_len_matches: work.header_mmr_len == expected_header_mmr_len,
            supply_digest_matches: supply_digest == work.supply_digest,
        }) {
            Ok(()) => {}
            Err(
                rejection @ (NativeBlockCommitmentAdmissionRejection::HeaderMmrRoot
                | NativeBlockCommitmentAdmissionRejection::HeaderMmrLen),
            ) => {
                return Err(native_block_commitment_admission_error(
                    "native mined block commitment mismatch",
                    rejection,
                ));
            }
            Err(_) => return Ok(None),
        }
        let (fee_total, has_coinbase) = native_block_replay_supply_parts(&actions, work.height)?;
        evaluate_native_block_replay_refinement_for_actions(
            "native mined block replay refinement failed",
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
            &snapshot,
            &actions,
            native_block_replay_refinement_input_from_state(
                &snapshot,
                work.height,
                fee_total,
                has_coinbase,
                supply_digest,
                preview_tx_count == work.tx_count,
                preview_state_root == work.state_root,
                preview_kernel_root == work.kernel_root,
                preview_nullifier_root == work.nullifier_root,
                preview_extrinsics_root == work.extrinsics_root,
                preview_message_root == work.message_root,
                preview_message_count == work.message_count,
                work.header_mmr_root == expected_header_mmr_root,
                work.header_mmr_len == expected_header_mmr_len,
            ),
        )?;
        let meta = NativeBlockMeta {
            chain_id: HEGEMON_CHAIN_ID_V1,
            rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
            height: work.height,
            hash: seal.work_hash,
            parent_hash: work.parent_hash,
            state_root: work.state_root,
            kernel_root: work.kernel_root,
            nullifier_root: work.nullifier_root,
            extrinsics_root: work.extrinsics_root,
            message_root: work.message_root,
            message_count: work.message_count,
            header_mmr_root: work.header_mmr_root,
            header_mmr_len: work.header_mmr_len,
            timestamp_ms: work.timestamp_ms,
            pow_bits: work.pow_bits,
            nonce: seal.nonce,
            work_hash: seal.work_hash,
            cumulative_work: work.cumulative_work,
            supply_digest,
            tx_count: work.tx_count,
            action_bytes: actions.iter().map(Encode::encode).collect(),
            da_root: work.da_root,
            da_chunk_size: work.da_chunk_size,
            da_sample_count: work.da_sample_count,
            da_blob_len: work.da_blob_len,
            da_chunk_count: work.da_chunk_count,
        };
        verify_native_pow_meta(&snapshot.best, &meta, expected_pow_bits)?;

        validate_block_actions_locked(&snapshot, &actions)?;
        verify_native_block_artifacts_locked(self, &snapshot, &actions, &meta)?;
        self.remember_verified_block_in_process(&meta)?;
        let pending_action_effects =
            plan_pending_action_effects(&self.da_ciphertext_tree, &snapshot, &actions)?;
        let mut validated_next_state = snapshot.clone();
        apply_planned_actions_to_memory(
            &mut validated_next_state,
            &actions,
            &pending_action_effects,
        )?;
        if validated_next_state.commitment_tree.root() != work.state_root
            || validated_next_state.nullifier_accumulator.root() != work.nullifier_root
        {
            return Err(anyhow!("native pending action preview mismatch"));
        }

        // Global order is pending/action epoch -> block-store epoch ->
        // canonical-import serialization -> short state snapshot. A contender
        // never holds canonical/state while waiting for either epoch. The
        // canonical guard is released before sled I/O; the two epochs span
        // plan -> transaction -> flush -> RAM publication.
        let persistence_epoch = self.pending_action_persistence_lock.lock();
        let block_store_epoch = self.block_store_persistence_lock.lock();
        let canonical_import_guard = self.canonical_import_lock.lock();
        let (pending_generation, mut next_state) = {
            let state = self.state.read();
            if !self.canonical_state_matches_snapshot(&state, &snapshot, snapshot_generation)
                || !prepared_mining_actions_match_state(&state, &actions)
            {
                debug!(
                    height = work.height,
                    "reclassifying verified mined work after canonical/action snapshot changed during verification"
                );
                drop(state);
                drop(canonical_import_guard);
                drop(block_store_epoch);
                drop(persistence_epoch);
                self.persist_noncanonical_block_record(&meta)?;
                return self
                    .promote_stored_block_if_better_outcome(meta.hash)
                    .map(|outcome| {
                        matches!(outcome, NativeStoredBlockPromotionOutcome::Promoted)
                            .then_some(meta)
                    });
            }
            (
                self.pending_action_generation.load(Ordering::Acquire),
                state.clone(),
            )
        };
        drop(canonical_import_guard);

        apply_planned_actions_to_memory(&mut next_state, &actions, &pending_action_effects)?;
        if next_state.commitment_tree.root() != work.state_root
            || next_state.nullifier_accumulator.root() != work.nullifier_root
        {
            return Err(anyhow!("native pending action commit snapshot mismatch"));
        }
        next_state.header_mmr_peaks = append_header_mmr_peak_state(&snapshot, &meta)?;
        next_state.best = meta.clone();
        let additional_pending_action_removals = self
            .prune_invalid_pending_actions_after_state_advance(
                &mut next_state,
                "native mined block pending action repair",
            )?;
        let checkpoint_rows = Self::canonical_checkpoint_rows(
            &meta,
            &next_state.commitment_tree,
            &next_state.nullifier_accumulator,
            &next_state.header_mmr_peaks,
        )?;
        self.remember_checkpoint_rows_in_process(&checkpoint_rows)?;

        self.commit_mined_block_atomically(
            &actions,
            &pending_action_effects,
            &meta,
            &snapshot.nullifier_accumulator,
            &next_state.nullifier_accumulator,
            &checkpoint_rows,
            &additional_pending_action_removals,
        )?;
        if let Err(err) = self.flush_native_durability_barrier(
            "native mined block commit",
            NativeStorageDurabilityOperation::MinedBlockCommit,
        ) {
            self.poison_native_storage();
            return Err(err
                .context("native mined block durability is uncertain; storage fail-stop engaged"));
        }
        let readback_error = self
            .verify_persisted_canonical_head(&meta, "native mined block commit")
            .err();

        let publication_revalidation_error = {
            let mut state = self.state.write();
            let changed =
                !self.canonical_state_matches_snapshot(&state, &snapshot, snapshot_generation)
                    || self.pending_action_generation.load(Ordering::Acquire) != pending_generation;
            // Supported sidecar/action-tree writers share the epoch and cannot
            // race this publication. Preserve unrelated in-memory policy state,
            // then make RAM match the already durable canonical transaction even
            // if an impossible generation mismatch engages fail-stop below.
            next_state.staged_ciphertexts = state.staged_ciphertexts.clone();
            for action in &actions {
                clear_staged_ciphertext_markers(&mut next_state, action);
            }
            next_state.staged_proofs = state.staged_proofs.clone();
            next_state.stablecoin_policy_authorizations =
                state.stablecoin_policy_authorizations.clone();
            publish_mined_state(&mut state, next_state);
            self.canonical_state_generation
                .fetch_add(1, Ordering::Release);
            self.pending_action_generation
                .fetch_add(1, Ordering::Release);
            changed.then_some(
                "native canonical state changed after durable mined-block commit; durable state was published and storage fail-stop engaged",
            )
        };
        drop(block_store_epoch);
        drop(persistence_epoch);
        if let Some(publication_revalidation_error) = publication_revalidation_error {
            self.poison_native_storage();
            return Err(anyhow!(publication_revalidation_error));
        }
        if let Some(readback_error) = readback_error {
            self.poison_native_storage();
            return Err(readback_error.context(
                "native mined block committed and published but readback failed; storage fail-stop engaged",
            ));
        }
        self.blocks_found.fetch_add(1, Ordering::Relaxed);
        self.broadcast_block_announce(&meta);
        info!(
            height = meta.height,
            hash = %hex32(&meta.hash),
            "native PoW block imported"
        );
        Ok(Some(meta))
    }

    pub(crate) fn import_announced_block(&self, meta: NativeBlockMeta) -> Result<bool> {
        self.ensure_native_storage_healthy()?;
        let (snapshot, snapshot_generation) = {
            let state = self.state.read();
            (
                Self::canonical_state_snapshot(&state),
                self.canonical_state_generation.load(Ordering::Acquire),
            )
        };
        if self.header_by_hash(&meta.hash)?.is_some() {
            return Ok(false);
        }
        let Some(parent) = self.header_by_hash(&meta.parent_hash)? else {
            return Ok(false);
        };
        self.validate_stored_block_meta_parent_chain(&parent)?;
        let expected_pow_bits = self.expected_child_pow_bits(&parent)?;
        validate_announced_block(&parent, &meta, expected_pow_bits)?;
        let (parent_state, branch_checkpoint_rows) = if parent.hash == snapshot.best.hash {
            (
                NativeState {
                    best: snapshot.best.clone(),
                    header_mmr_peaks: snapshot.header_mmr_peaks.clone(),
                    pending_actions: BTreeMap::new(),
                    pending_action_semantic_index: BTreeMap::new(),
                    pending_action_order_index: BTreeSet::new(),
                    pending_nullifiers: BTreeSet::new(),
                    pending_bridge_replay_keys: PersistentKeySet48::new(),
                    pending_mempool_bytes: 0,
                    commitment_tree: snapshot.commitment_tree.clone(),
                    nullifiers: snapshot.nullifiers.clone(),
                    nullifier_accumulator: snapshot.nullifier_accumulator.clone(),
                    consumed_bridge_messages: snapshot.consumed_bridge_messages.clone(),
                    stablecoin_policy_authorizations: snapshot
                        .stablecoin_policy_authorizations
                        .clone(),
                    staged_ciphertexts: BTreeMap::new(),
                    staged_proofs: BTreeMap::new(),
                },
                Vec::new(),
            )
        } else {
            let (ancestor, suffix) = self.stored_branch_suffix_from_canonical_ancestor(&parent)?;
            let ancestor_state = self.canonical_state_at_ancestor(&snapshot, &ancestor)?;
            let replay = self.replay_verified_suffix_from_state(ancestor_state, &suffix)?;
            (replay.state, replay.checkpoint_rows)
        };
        let (expected_header_mmr_root, expected_header_mmr_len) =
            header_mmr_commitment_after_best(&parent_state.best, &parent_state.header_mmr_peaks)?;
        let actions = decode_block_actions(&meta)?;
        verify_decoded_action_root(&actions, &meta, "announced block action root")?;
        validate_native_block_proof_policy(parent_state.best.height, meta.height, &actions)?;
        let (state_root, nullifier_root, extrinsics_root, tx_count) =
            preview_pending_roots(&self.da_ciphertext_tree, &parent_state, &actions)?;
        let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
        let bridge_messages = bridge_messages_from_actions(&actions, meta.height)?;
        let message_root = bridge_message_root(&bridge_messages);
        let message_count = u32::try_from(bridge_messages.len())
            .map_err(|_| anyhow!("native bridge message count overflow"))?;
        let (fee_total, has_coinbase) = native_block_replay_supply_parts(&actions, meta.height)?;
        evaluate_native_block_replay_refinement_for_actions(
            "announced block replay refinement failed",
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
            &parent_state,
            &actions,
            native_block_replay_refinement_input_from_state(
                &parent_state,
                meta.height,
                fee_total,
                has_coinbase,
                meta.supply_digest,
                tx_count == meta.tx_count,
                state_root == meta.state_root,
                kernel_root == meta.kernel_root,
                nullifier_root == meta.nullifier_root,
                extrinsics_root == meta.extrinsics_root,
                message_root == meta.message_root,
                message_count == meta.message_count,
                meta.header_mmr_root == expected_header_mmr_root,
                meta.header_mmr_len == expected_header_mmr_len,
            ),
        )?;
        validate_block_actions_locked(&parent_state, &actions)?;
        verify_native_block_artifacts_locked(self, &parent_state, &actions, &meta)?;
        self.remember_verified_block_in_process(&meta)?;
        let candidate_wins = native_meta_better_than(&meta, &snapshot.best);
        if candidate_wins {
            if parent.hash == snapshot.best.hash {
                let planned =
                    plan_pending_action_effects(&self.da_ciphertext_tree, &parent_state, &actions)?;
                let mut validated_next_state = parent_state.clone();
                apply_planned_actions_to_memory(&mut validated_next_state, &actions, &planned)?;
                if validated_next_state.commitment_tree.root() != meta.state_root
                    || validated_next_state.nullifier_accumulator.root() != meta.nullifier_root
                {
                    return Err(anyhow!("native announced tip extension preview mismatch"));
                }

                let persistence_epoch = self.pending_action_persistence_lock.lock();
                let block_store_epoch = self.block_store_persistence_lock.lock();
                let canonical_import_guard = self.canonical_import_lock.lock();
                let (pending_generation, mut next_state) = {
                    let state = self.state.read();
                    if !self.canonical_state_matches_snapshot(
                        &state,
                        &snapshot,
                        snapshot_generation,
                    ) {
                        drop(state);
                        drop(canonical_import_guard);
                        drop(block_store_epoch);
                        drop(persistence_epoch);
                        self.persist_noncanonical_block_record(&meta)?;
                        return self.promote_stored_block_if_better(meta.hash);
                    }
                    (
                        self.pending_action_generation.load(Ordering::Acquire),
                        state.clone(),
                    )
                };
                drop(canonical_import_guard);

                apply_planned_actions_to_memory(&mut next_state, &actions, &planned)?;
                if next_state.commitment_tree.root() != meta.state_root
                    || next_state.nullifier_accumulator.root() != meta.nullifier_root
                {
                    return Err(anyhow!("native announced tip extension commit mismatch"));
                }
                next_state.header_mmr_peaks = append_header_mmr_peak_state(&snapshot, &meta)?;
                next_state.best = meta.clone();
                let additional_pending_action_removals = self
                    .prune_invalid_pending_actions_after_state_advance(
                        &mut next_state,
                        "native announced block pending action repair",
                    )?;
                let checkpoint_rows = Self::canonical_checkpoint_rows(
                    &meta,
                    &next_state.commitment_tree,
                    &next_state.nullifier_accumulator,
                    &next_state.header_mmr_peaks,
                )?;
                self.remember_checkpoint_rows_in_process(&checkpoint_rows)?;
                self.commit_mined_block_atomically(
                    &actions,
                    &planned,
                    &meta,
                    &parent_state.nullifier_accumulator,
                    &next_state.nullifier_accumulator,
                    &checkpoint_rows,
                    &additional_pending_action_removals,
                )?;
                if let Err(err) = self.flush_native_durability_barrier(
                    "native announced tip extension commit",
                    NativeStorageDurabilityOperation::MinedBlockCommit,
                ) {
                    self.poison_native_storage();
                    return Err(err.context(
                        "native announced tip durability is uncertain; storage fail-stop engaged",
                    ));
                }
                let readback_error = self
                    .verify_persisted_canonical_head(&meta, "native announced tip extension commit")
                    .err();
                let publication_revalidation_error = {
                    let mut state = self.state.write();
                    let changed = !self.canonical_state_matches_snapshot(
                        &state,
                        &snapshot,
                        snapshot_generation,
                    ) || self.pending_action_generation.load(Ordering::Acquire)
                        != pending_generation;
                    next_state.staged_ciphertexts = state.staged_ciphertexts.clone();
                    for action in &actions {
                        clear_staged_ciphertext_markers(&mut next_state, action);
                    }
                    next_state.staged_proofs = state.staged_proofs.clone();
                    next_state.stablecoin_policy_authorizations =
                        state.stablecoin_policy_authorizations.clone();
                    publish_mined_state(&mut state, next_state);
                    self.canonical_state_generation
                        .fetch_add(1, Ordering::Release);
                    self.pending_action_generation
                        .fetch_add(1, Ordering::Release);
                    changed.then_some(
                        "native canonical state changed after durable announced-tip commit; durable state was published and storage fail-stop engaged",
                    )
                };
                drop(block_store_epoch);
                drop(persistence_epoch);
                if let Some(publication_revalidation_error) = publication_revalidation_error {
                    self.poison_native_storage();
                    return Err(anyhow!(publication_revalidation_error));
                }
                if let Some(readback_error) = readback_error {
                    self.poison_native_storage();
                    return Err(readback_error.context(
                        "native announced tip committed and published but readback failed; storage fail-stop engaged",
                    ));
                }
            } else {
                // Persist the independently verified child before attempting a
                // branch flip. If another canonical writer wins the race, the
                // valid candidate remains available to descendants and the
                // bounded fresh-snapshot promotion retry below can reclassify
                // it without retransmission.
                self.persist_noncanonical_block_record(&meta)?;
                let mut verified_replay = self.replay_verified_suffix_from_state(
                    parent_state.clone(),
                    std::slice::from_ref(&meta),
                )?;
                let mut checkpoint_rows = branch_checkpoint_rows;
                checkpoint_rows.append(&mut verified_replay.checkpoint_rows);
                verified_replay.checkpoint_rows = checkpoint_rows;
                let reorg_result = self.reorganize_chain_to_best_from_snapshot(
                    &snapshot,
                    snapshot_generation,
                    vec![meta.clone()],
                    Some(verified_replay),
                    NativeAtomicCommitKind::CanonicalSuffixReorgCommit,
                );
                if let Err(err) = reorg_result {
                    if self.canonical_state_generation.load(Ordering::Acquire)
                        != snapshot_generation
                    {
                        return self.promote_stored_block_if_better(meta.hash);
                    }
                    return Err(err);
                }
            }
            Ok(true)
        } else {
            self.persist_noncanonical_block_record(&meta)?;
            Ok(false)
        }
    }

    /// PR 203 outcome surface over the proof-authoritative import path above.
    /// The wrapper classifies storage state only; it never bypasses the exact
    /// action, proof, V8 transition, or atomic publication checks performed by
    /// `import_announced_block`.
    pub(crate) fn import_announced_block_with_outcome(
        &self,
        meta: NativeBlockMeta,
    ) -> Result<NativeAnnouncedBlockImportOutcome> {
        self.import_announced_block_with_outcome_ref(&meta)
    }

    pub(crate) fn import_announced_block_with_outcome_ref(
        &self,
        meta: &NativeBlockMeta,
    ) -> Result<NativeAnnouncedBlockImportOutcome> {
        if let Some((_, exact_match)) =
            self.inspect_stored_pow_metadata(&meta.hash, Some(meta), "known native block announce")?
        {
            if !exact_match {
                return Err(anyhow!(
                    "announced native block aliases a stored hash with different metadata"
                ));
            }
            let best_tip = self.best_fork_choice_tip();
            if best_tip.hash != meta.hash && native_meta_better_than_tip(meta, best_tip) {
                return self
                    .promote_stored_block_if_better_outcome(meta.hash)
                    .map(|outcome| match outcome {
                        NativeStoredBlockPromotionOutcome::Promoted => {
                            NativeAnnouncedBlockImportOutcome::CanonicalAdvanced
                        }
                        NativeStoredBlockPromotionOutcome::AlreadyCanonical
                        | NativeStoredBlockPromotionOutcome::NotBetter => {
                            NativeAnnouncedBlockImportOutcome::AlreadyKnown
                        }
                    });
            }
            return Ok(NativeAnnouncedBlockImportOutcome::AlreadyKnown);
        }
        if self.header_by_hash(&meta.parent_hash)?.is_none() {
            return Ok(NativeAnnouncedBlockImportOutcome::MissingParent);
        }
        if self.import_announced_block(meta.clone())? {
            return Ok(NativeAnnouncedBlockImportOutcome::CanonicalAdvanced);
        }
        if self.header_by_hash(&meta.hash)?.is_some() {
            Ok(NativeAnnouncedBlockImportOutcome::StoredNoncanonical)
        } else {
            Ok(NativeAnnouncedBlockImportOutcome::MissingParent)
        }
    }

    pub(crate) fn persist_noncanonical_block_record(&self, meta: &NativeBlockMeta) -> Result<()> {
        let _block_store_epoch = self.block_store_persistence_lock.lock();
        if let Some(best_record) = self.meta_tree.get(META_BEST_KEY)? {
            let best: NativeBlockMeta = bincode::deserialize(best_record.as_ref())
                .context("decode durable native best record before fork persistence")?;
            if best.hash == meta.hash {
                if best != *meta {
                    return Err(anyhow!(
                        "stored native block aliases the canonical hash with different metadata"
                    ));
                }
                // A competing importer may have committed this exact block while
                // verification ran. Do not recreate its now-obsolete fork marker.
                return Ok(());
            }
        }
        evaluate_native_atomic_commit_manifest_admission(
            native_noncanonical_block_record_manifest(),
        )
        .map_err(|rejection| {
            native_atomic_commit_manifest_admission_error(
                "native noncanonical block record manifest",
                rejection,
            )
        })?;
        let block_record = bincode::serialize(meta)?;
        let fork_record = native_noncanonical_fork_record(meta, &block_record)?;
        let fork_key = native_noncanonical_fork_key(&meta.hash);
        let fork_value = fork_record.encode();
        let verified_key = native_verified_block_record_key(&meta.hash);
        let verified_digest = native_verified_block_body_digest_from_encoded(&block_record)?;
        let persist_result: sled::transaction::TransactionResult<(), std::convert::Infallible> =
            (&self.block_tree, &self.meta_tree).transaction(|(block_tree, meta_tree)| {
                block_tree.insert(meta.hash.to_vec(), block_record.clone())?;
                meta_tree.insert(verified_key.clone(), verified_digest.to_vec())?;
                meta_tree.insert(fork_key.clone(), fork_value.clone())?;
                Ok(())
            });
        persist_result
            .map_err(|err| anyhow!("atomic verified noncanonical block record failed: {err}"))?;
        self.flush_native_durability_barrier(
            "noncanonical native block record",
            NativeStorageDurabilityOperation::NoncanonicalBlockRecord,
        )?;
        Ok(())
    }

    pub(crate) fn remember_verified_block_in_process(&self, meta: &NativeBlockMeta) -> Result<()> {
        let digest = native_in_process_verified_block_body_digest(meta)?;
        let mut cache = self.in_process_verified_blocks.lock();
        if cache.entries.insert(meta.hash, digest).is_some() {
            cache.order.retain(|hash| *hash != meta.hash);
        }
        cache.order.push_back(meta.hash);
        while cache.entries.len() > MAX_NATIVE_IN_PROCESS_VERIFIED_BLOCKS {
            let Some(oldest) = cache.order.pop_front() else {
                break;
            };
            cache.entries.remove(&oldest);
        }
        Ok(())
    }

    fn remember_canonical_checkpoint_in_process(
        &self,
        checkpoint: NativeCanonicalStateCheckpointV1,
    ) {
        let mut cache = self.in_process_canonical_checkpoints.lock();
        if cache
            .entries
            .insert(checkpoint.block_hash, checkpoint.clone())
            .is_some()
        {
            cache.order.retain(|hash| *hash != checkpoint.block_hash);
        }
        cache.order.push_back(checkpoint.block_hash);
        while cache.entries.len() > MAX_NATIVE_IN_PROCESS_CANONICAL_CHECKPOINTS {
            let Some(oldest) = cache.order.pop_front() else {
                break;
            };
            cache.entries.remove(&oldest);
        }
    }

    fn in_process_canonical_checkpoint(
        &self,
        meta: &NativeBlockMeta,
    ) -> Result<Option<NativeCanonicalStateCheckpointV1>> {
        let checkpoint = self
            .in_process_canonical_checkpoints
            .lock()
            .entries
            .get(&meta.hash)
            .cloned();
        let Some(checkpoint) = checkpoint else {
            return Ok(None);
        };
        validate_native_canonical_state_checkpoint(&checkpoint, meta)?;
        Ok(Some(checkpoint))
    }

    fn remember_checkpoint_rows_in_process(
        &self,
        rows: &NativeCanonicalCheckpointRows,
    ) -> Result<()> {
        let checkpoint = decode_scale_exact::<NativeCanonicalStateCheckpointV1>(
            &rows.1,
            "native in-process canonical checkpoint",
        )?;
        self.remember_canonical_checkpoint_in_process(checkpoint);
        Ok(())
    }

    pub(crate) fn load_canonical_state_checkpoint(
        &self,
        meta: &NativeBlockMeta,
    ) -> Result<Option<NativeCanonicalStateCheckpointV1>> {
        let Some(encoded) = self
            .meta_tree
            .get(native_canonical_state_checkpoint_key(&meta.hash))?
        else {
            return Ok(None);
        };
        let checkpoint = decode_scale_exact::<NativeCanonicalStateCheckpointV1>(
            encoded.as_ref(),
            "native canonical state checkpoint",
        )?;
        validate_native_canonical_state_checkpoint(&checkpoint, meta)?;
        Ok(Some(checkpoint))
    }

    pub(crate) fn canonical_checkpoint_rows(
        meta: &NativeBlockMeta,
        commitment_tree: &CommitmentTreeState,
        nullifier_accumulator: &NullifierAccumulator,
        header_mmr_peaks: &[Hash32],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let checkpoint = native_canonical_state_checkpoint(
            meta,
            commitment_tree,
            nullifier_accumulator,
            header_mmr_peaks,
        )?;
        Ok((
            native_canonical_state_checkpoint_key(&meta.hash),
            checkpoint.encode(),
            native_verified_block_record_key(&meta.hash),
            checkpoint.block_body_digest.to_vec(),
        ))
    }

    #[cfg(test)]
    pub(crate) fn validate_and_persist_noncanonical_sync_batch(
        &self,
        anchor_hash: [u8; 32],
        metas: &[NativeBlockMeta],
    ) -> Result<usize> {
        for meta in metas {
            if self.classify_supplied_block_record(meta)?
                == NativeSuppliedBlockRecordStatus::KnownExact
            {
                return Err(anyhow!(
                    "native sync side-branch batch includes already known block {}",
                    hex32(&meta.hash)
                ));
            }
        }
        let persistence = self
            .validate_and_persist_mixed_noncanonical_sync_batch(anchor_hash, metas)
            .map_err(anyhow::Error::from)?;
        debug_assert_eq!(persistence.already_known, 0);
        Ok(persistence.newly_stored)
    }

    pub(crate) fn classify_supplied_block_record(
        &self,
        meta: &NativeBlockMeta,
    ) -> Result<NativeSuppliedBlockRecordStatus> {
        let inspected = self.inspect_stored_pow_metadata(
            &meta.hash,
            Some(meta),
            "native supplied sync block record",
        )?;
        evaluate_native_supplied_block_record_classification(
            NativeSuppliedBlockRecordClassificationInput {
                stored_record_present: inspected.is_some(),
                stored_record_exact: inspected.is_some_and(|(_, exact_match)| exact_match),
            },
        )
        .map_err(|_| {
            anyhow!(
                "known native sync block does not match supplied metadata {}",
                hex32(&meta.hash)
            )
        })
    }

    pub(crate) fn validate_and_persist_mixed_noncanonical_sync_batch(
        &self,
        anchor_hash: [u8; 32],
        metas: &[NativeBlockMeta],
    ) -> std::result::Result<NativeNoncanonicalSyncBatchPersistence, NativeChainLoadError> {
        if metas.is_empty() {
            return Ok(NativeNoncanonicalSyncBatchPersistence {
                newly_stored: 0,
                already_known: 0,
            });
        }
        // Serialize exact row classification, proof-authoritative replay, and
        // selective durability with every production block-record writer. A
        // row classified Missing therefore cannot become a conflicting stored
        // record before this batch is applied.
        let _block_store_epoch = self.block_store_persistence_lock.lock();
        if metas[0].parent_hash != anchor_hash {
            return Err(NativeChainLoadError::Corrupt(anyhow!(
                "native sync side-branch batch does not extend its stored anchor"
            )));
        }
        for pair in metas.windows(2) {
            if pair[0].height.checked_add(1) != Some(pair[1].height)
                || pair[1].parent_hash != pair[0].hash
            {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "native sync side-branch batch is not contiguous at height {}",
                    pair[1].height
                )));
            }
        }

        let mut missing = Vec::new();
        let mut already_known = 0usize;
        for meta in metas {
            match self
                .classify_supplied_block_record(meta)
                .map_err(NativeChainLoadError::Corrupt)?
            {
                NativeSuppliedBlockRecordStatus::KnownExact => {
                    already_known = already_known.saturating_add(1);
                }
                NativeSuppliedBlockRecordStatus::Missing => missing.push(meta),
            }
        }

        let replayed = self.replay_stored_ancestry_with_suffix_streaming(anchor_hash, metas)?;
        let expected_tip = metas.last().expect("nonempty side-branch batch");
        if replayed.best != *expected_tip {
            return Err(NativeChainLoadError::Corrupt(anyhow!(
                "native sync side-branch replay did not reach the response tip"
            )));
        }
        drop(replayed);

        // Legacy replay intentionally excludes the typed V8 verifier. Build
        // one exact read-only detach/attach plan for the stored anchor plus
        // the complete supplied suffix before any missing block row is made
        // durable. Classification remains stable under the block-store epoch.
        let canonical_tip = self.best_meta();
        let mut ancestry = self.compact_stored_pow_ancestry_to_hash(anchor_hash)?;
        ancestry.extend(metas.iter().map(NativePowMetaProjection::from));
        let mut common_ancestor_index = None;
        for (index, projection) in ancestry.iter().enumerate().rev() {
            if self
                .hash_by_height(projection.height)
                .map_err(NativeChainLoadError::Corrupt)?
                == Some(projection.hash)
            {
                common_ancestor_index = Some(index);
                break;
            }
        }
        let common_ancestor_index = common_ancestor_index.ok_or_else(|| {
            NativeChainLoadError::Corrupt(anyhow!(
                "native sync side-branch batch has no canonical common ancestor"
            ))
        })?;
        if common_ancestor_index.saturating_add(1) < ancestry.len() {
            self.plan_poseidon2_v8_stored_reorganization_streaming(
                &canonical_tip,
                &ancestry,
                common_ancestor_index,
                metas,
            )
            .map_err(NativeChainLoadError::Corrupt)?;
        }

        let newly_stored = self.persist_validated_noncanonical_block_record_ref_batch(
            &missing,
            "native sync noncanonical block-record batch manifest",
            "validated native sync side-branch batch",
        )?;
        Ok(NativeNoncanonicalSyncBatchPersistence {
            newly_stored,
            already_known,
        })
    }

    #[cfg(test)]
    pub(crate) fn persist_validated_noncanonical_block_record_batch(
        &self,
        metas: &[NativeBlockMeta],
        manifest_context: &'static str,
        durability_context: &'static str,
    ) -> Result<usize> {
        let refs = metas.iter().collect::<Vec<_>>();
        self.persist_validated_noncanonical_block_record_ref_batch(
            &refs,
            manifest_context,
            durability_context,
        )
    }

    fn persist_validated_noncanonical_block_record_ref_batch(
        &self,
        metas: &[&NativeBlockMeta],
        manifest_context: &'static str,
        durability_context: &'static str,
    ) -> Result<usize> {
        if metas.is_empty() {
            return Ok(0);
        }
        evaluate_native_atomic_commit_manifest_admission(
            native_noncanonical_block_record_batch_manifest(metas.len()),
        )
        .map_err(|rejection| {
            native_atomic_commit_manifest_admission_error(manifest_context, rejection)
        })?;
        let mut batch = sled::Batch::default();
        for &meta in metas {
            batch.insert(meta.hash.to_vec(), bincode::serialize(meta)?);
        }
        self.block_tree
            .apply_batch(batch)
            .with_context(|| format!("persist {durability_context}"))?;
        self.flush_native_durability_barrier(
            durability_context,
            NativeStorageDurabilityOperation::NoncanonicalBlockRecord,
        )?;
        Ok(metas.len())
    }

    pub(crate) fn validate_stored_block_meta_parent_chain(
        &self,
        meta: &NativeBlockMeta,
    ) -> Result<()> {
        if meta.height == 0 {
            return verify_native_block_meta_projection(None, meta, None).with_context(|| {
                format!(
                    "validate stored native parent metadata at genesis ({})",
                    hex32(&meta.hash)
                )
            });
        }
        let parent = self
            .header_by_hash(&meta.parent_hash)?
            .ok_or_else(|| anyhow!("missing stored native parent for {}", hex32(&meta.hash)))?;
        let expected_pow_bits = self.expected_child_pow_bits(&parent)?;
        verify_native_block_meta_projection(Some(&parent), meta, Some(expected_pow_bits))
            .with_context(|| {
                format!(
                    "validate stored native parent metadata at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                )
            })
    }

    pub(crate) fn flush_native_durability_barrier(
        &self,
        context: &'static str,
        operation: NativeStorageDurabilityOperation,
    ) -> Result<()> {
        flush_native_db_durability_barrier(&self.db, context, operation)
    }

    pub(crate) fn broadcast_block_announce(&self, meta: &NativeBlockMeta) {
        self.last_announce_height
            .store(meta.height, Ordering::Relaxed);
        let Some(sync_tx) = self.sync_tx.lock().clone() else {
            return;
        };
        let encoded = match self.block_body_send_cache.lock().encode_meta(meta) {
            Ok(encoded) => encoded,
            Err(err) => {
                warn!(error = %err, "failed to cache native block announce body");
                return;
            }
        };
        let announce = match native_block_announce_message_from_encoded(
            meta,
            encoded.bytes.len(),
            encoded.locator.clone(),
        ) {
            Ok(announce) => announce,
            Err(err) => {
                warn!(error = %err, "failed to build native block announce transport");
                return;
            }
        };
        let payload = match encode_sync_message(&announce) {
            Ok(payload) => payload,
            Err(err) => {
                warn!(error = %err, "failed to encode native block announcement");
                return;
            }
        };
        let message = DirectedProtocolMessage {
            target: None,
            message: ProtocolMessage {
                protocol: NATIVE_SYNC_PROTOCOL_ID,
                payload,
            },
        };
        if let Err(err) = sync_tx.try_send(message) {
            debug!(error = %err, "failed to queue native block announce");
        } else {
            info!(
                height = meta.height,
                hash = %hex32(&meta.hash),
                "queued native block announcement"
            );
        }
    }

    pub(crate) fn peer_relayable_pending_actions_from(
        &self,
        start: usize,
        limit: usize,
        max_bytes: usize,
    ) -> Vec<PendingAction> {
        if limit == 0 || max_bytes == 0 {
            return Vec::new();
        }
        let state = self.state.read();
        let pending = state
            .pending_actions
            .values()
            .filter(|action| pending_action_peer_relayable(action))
            .collect::<Vec<_>>();
        if pending.is_empty() {
            return Vec::new();
        }
        let start = start % pending.len();
        let mut selected = Vec::new();
        let mut selected_bytes = 0usize;
        for offset in 0..pending.len() {
            if selected.len() >= limit {
                break;
            }
            let action = pending[(start + offset) % pending.len()];
            let action_bytes = pending_action_mempool_bytes(action).max(1);
            if !selected.is_empty() && selected_bytes.saturating_add(action_bytes) > max_bytes {
                break;
            }
            selected_bytes = selected_bytes.saturating_add(action_bytes);
            selected.push(action.clone());
            if selected_bytes >= max_bytes {
                break;
            }
        }
        selected
    }

    pub(crate) fn rebroadcast_peer_relayable_pending_actions(&self) {
        let start = self.pending_action_rebroadcast_cursor.fetch_add(
            NATIVE_SYNC_PENDING_ACTION_REBROADCAST_LIMIT as u64,
            Ordering::Relaxed,
        ) as usize;
        let actions = self.peer_relayable_pending_actions_from(
            start,
            NATIVE_SYNC_PENDING_ACTION_REBROADCAST_LIMIT,
            NATIVE_SYNC_PENDING_ACTION_REBROADCAST_BYTES,
        );
        if actions.is_empty() {
            return;
        }
        let action_bytes = actions.iter().fold(0usize, |total, action| {
            total.saturating_add(pending_action_mempool_bytes(action))
        });
        debug!(
            action_count = actions.len(),
            action_bytes, "rebroadcasting native pending actions to peers"
        );
        for action in actions {
            self.broadcast_pending_action(&action);
        }
    }

    pub(crate) fn broadcast_pending_action(&self, action: &PendingAction) {
        if !pending_action_peer_relayable(action) {
            return;
        }
        let action_bytes = action.encode();
        if action_bytes.len() > MAX_NATIVE_SYNC_PENDING_ACTION_BYTES {
            warn!(
                tx_hash = %hex48(action.tx_hash.as_bytes()),
                action_bytes = action_bytes.len(),
                max_bytes = MAX_NATIVE_SYNC_PENDING_ACTION_BYTES,
                "refusing to relay oversized native pending action"
            );
            return;
        }
        let Some(sync_tx) = self.sync_tx.lock().clone() else {
            return;
        };
        let relay = NativeSyncMessage::PendingAction {
            action: action_bytes,
        };
        let payload = match encode_sync_message(&relay) {
            Ok(payload) => payload,
            Err(err) => {
                warn!(
                    tx_hash = %hex48(action.tx_hash.as_bytes()),
                    error = %err,
                    "failed to encode native pending action relay"
                );
                return;
            }
        };
        let message = DirectedProtocolMessage {
            target: None,
            message: ProtocolMessage {
                protocol: NATIVE_SYNC_PROTOCOL_ID,
                payload,
            },
        };
        if let Err(err) = sync_tx.try_send(message) {
            warn!(
                tx_hash = %hex48(action.tx_hash.as_bytes()),
                error = %err,
                "failed to queue native pending action relay"
            );
        }
    }

    pub(crate) fn block_range(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<NativeBlockMeta>> {
        self.sync_response_block_range(from_height, to_height)
            .map(|(_, blocks, _)| blocks)
    }

    pub(crate) fn sync_response_block_range(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<(u64, Vec<NativeBlockMeta>, Option<NativeSyncChunkOffer>)> {
        let best_height = self.best_height();
        let Some(range) = native_sync_response_range(NativeSyncResponseRangeInput {
            from_height,
            to_height,
            best_height,
            max_blocks: MAX_NATIVE_SYNC_RESPONSE_BLOCKS,
        }) else {
            return Ok((best_height, Vec::new(), None));
        };
        let initial_parent_hash = if range.from_height == 0 {
            None
        } else {
            Some(
                self.load_canonical_block_at_height_unverified(range.from_height - 1)?
                    .hash,
            )
        };
        let (blocks, previous_parent_anchor_verified, oversized_first_block) =
            load_native_sync_response_prefix_with(
                best_height,
                range,
                initial_parent_hash,
                |height| self.load_canonical_sync_block_at_height(height),
            )?;
        let Some(published_to_height) = blocks.last().map(|block| block.height) else {
            return Ok((best_height, Vec::new(), oversized_first_block));
        };
        let published_range = NativeSyncRange {
            from_height: range.from_height,
            to_height: published_to_height,
        };
        let action_bodies_verified = native_sync_verified_action_body_count(&blocks);
        evaluate_native_sync_block_range_publication_admission(
            native_sync_block_range_publication_admission_input(
                published_range,
                &blocks,
                blocks.len(),
                action_bodies_verified,
                previous_parent_anchor_verified,
            ),
        )
        .map_err(|rejection| {
            anyhow!(
                "native sync block range publication admission: {}",
                rejection.label()
            )
        })?;
        Ok((
            best_height,
            native_sync_block_range_publication_rows(blocks),
            None,
        ))
    }

    pub(crate) fn load_canonical_sync_block_at_height(
        &self,
        height: u64,
    ) -> Result<NativeBlockMeta> {
        let meta = self.load_canonical_block_at_height_unverified(height)?;
        let parent = if meta.height == 0 {
            None
        } else {
            Some(self.load_canonical_block_at_height_unverified(height.saturating_sub(1))?)
        };
        self.verify_loaded_canonical_sync_block(&meta, parent.as_ref())?;
        Ok(meta)
    }

    fn verify_loaded_canonical_sync_block(
        &self,
        meta: &NativeBlockMeta,
        parent: Option<&NativeBlockMeta>,
    ) -> Result<()> {
        if meta.height == 0 {
            verify_native_block_meta_projection(None, meta, None)
                .context("validate genesis native sync block metadata")?;
        } else {
            let parent = parent.ok_or_else(|| {
                anyhow!(
                    "missing canonical parent metadata for native sync block {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                )
            })?;
            let expected_pow_bits = self.expected_canonical_child_pow_bits(&parent)?;
            verify_native_block_meta_projection(Some(&parent), meta, Some(expected_pow_bits))
                .with_context(|| {
                    format!(
                        "validate canonical native sync block metadata at height {} ({})",
                        meta.height,
                        hex32(&meta.hash)
                    )
                })?;
            verify_canonical_sync_block_body(meta).with_context(|| {
                format!(
                    "validate canonical native sync block body at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                )
            })?;
        }
        Ok(())
    }

    pub(crate) fn load_canonical_block_at_height_unverified(
        &self,
        height: u64,
    ) -> Result<NativeBlockMeta> {
        let hash = self
            .hash_by_height(height)?
            .ok_or_else(|| anyhow!("missing canonical height index for native block {height}"))?;
        let meta = self.header_by_hash(&hash)?.ok_or_else(|| {
            anyhow!(
                "missing native block record for canonical height {} ({})",
                height,
                hex32(&hash)
            )
        })?;
        if meta.hash != hash {
            return Err(anyhow!(
                "canonical height {} points to {} but block metadata hash is {}",
                height,
                hex32(&hash),
                hex32(&meta.hash)
            ));
        }
        if meta.height != height {
            return Err(anyhow!(
                "canonical height {} points to block metadata at height {} ({})",
                height,
                meta.height,
                hex32(&hash)
            ));
        }
        if meta.hash != meta.work_hash {
            return Err(anyhow!(
                "canonical native block {} has hash/work-hash mismatch: {} != {}",
                height,
                hex32(&meta.hash),
                hex32(&meta.work_hash)
            ));
        }
        Ok(meta)
    }

    #[cfg(test)]
    pub(crate) fn chain_to_hash(
        &self,
        hash: [u8; 32],
    ) -> std::result::Result<Vec<NativeBlockMeta>, NativeChainLoadError> {
        let chain = load_chain_to_hash(&self.block_tree, hash)?;
        #[cfg(test)]
        {
            self.chain_reconstruction_count
                .fetch_add(1, Ordering::Relaxed);
            self.block_meta_load_count.fetch_add(
                u64::try_from(chain.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            self.block_meta_decode_count.fetch_add(
                u64::try_from(chain.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        Ok(chain)
    }

    #[cfg(test)]
    pub(crate) fn reset_block_meta_load_counters(&self) {
        self.block_meta_load_count.store(0, Ordering::Relaxed);
        self.block_meta_decode_count.store(0, Ordering::Relaxed);
        self.chain_reconstruction_count.store(0, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn block_meta_load_counters(&self) -> (u64, u64) {
        (
            self.block_meta_load_count.load(Ordering::Relaxed),
            self.chain_reconstruction_count.load(Ordering::Relaxed),
        )
    }

    #[cfg(test)]
    pub(crate) fn block_meta_decode_count(&self) -> u64 {
        self.block_meta_decode_count.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn reset_streaming_replay_stored_meta_counters(&self) {
        assert_eq!(
            self.streaming_replay_live_stored_meta_count
                .load(Ordering::Relaxed),
            0,
            "cannot reset streaming replay counters while a stored metadata body is live"
        );
        self.streaming_replay_peak_stored_meta_count
            .store(0, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn streaming_replay_stored_meta_counters(&self) -> (u64, u64) {
        (
            self.streaming_replay_live_stored_meta_count
                .load(Ordering::Relaxed),
            self.streaming_replay_peak_stored_meta_count
                .load(Ordering::Relaxed),
        )
    }

    #[cfg(test)]
    fn begin_streaming_stored_meta_decode(&self) -> NativeStreamingStoredMetaDecodeGuard<'_> {
        let live = self
            .streaming_replay_live_stored_meta_count
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.streaming_replay_peak_stored_meta_count
            .fetch_max(live, Ordering::Relaxed);
        NativeStreamingStoredMetaDecodeGuard { node: self }
    }

    pub(crate) fn header_hashes_to_hash(
        &self,
        hash: [u8; 32],
    ) -> std::result::Result<Vec<Hash32>, NativeChainLoadError> {
        Ok(self
            .compact_stored_pow_ancestry_to_hash(hash)?
            .into_iter()
            .map(|meta| meta.hash)
            .collect())
    }

    fn compact_stored_pow_ancestry_to_hash(
        &self,
        hash: [u8; 32],
    ) -> std::result::Result<Vec<NativePowMetaProjection>, NativeChainLoadError> {
        let mut reverse_ancestry = Vec::new();
        let mut cursor = hash;
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(cursor) {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "stored native block parent cycle at {}",
                    hex32(&cursor)
                )));
            }
            let projection = self
                .inspect_stored_pow_metadata(
                    &cursor,
                    None,
                    "native streaming noncanonical ancestry",
                )?
                .map(|(projection, _)| projection)
                .ok_or_else(|| NativeChainLoadError::MissingAncestor {
                    hash_hex: hex32(&cursor),
                })?;
            reverse_ancestry.push(projection);
            if projection.height == 0 {
                break;
            }
            cursor = projection.parent_hash;
        }
        reverse_ancestry.reverse();
        for (index, projection) in reverse_ancestry.iter().enumerate() {
            let expected_height = u64::try_from(index)
                .map_err(|_| anyhow!("native streaming replay height overflow"))?;
            if projection.height != expected_height {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "native streaming replay height mismatch at {}: expected {} observed {}",
                    hex32(&projection.hash),
                    expected_height,
                    projection.height
                )));
            }
            if let Some(parent) = index
                .checked_sub(1)
                .and_then(|parent_index| reverse_ancestry.get(parent_index))
            {
                if projection.parent_hash != parent.hash {
                    return Err(NativeChainLoadError::Corrupt(anyhow!(
                        "native streaming replay parent mismatch at height {}: expected {} observed {}",
                        projection.height,
                        hex32(&parent.hash),
                        hex32(&projection.parent_hash)
                    )));
                }
            }
        }
        Ok(reverse_ancestry)
    }

    fn inspect_stored_pow_metadata(
        &self,
        hash: &[u8; 32],
        expected: Option<&NativeBlockMeta>,
        context: &str,
    ) -> Result<Option<(NativePowMetaProjection, bool)>> {
        #[cfg(test)]
        self.block_meta_load_count.fetch_add(1, Ordering::Relaxed);
        let Some(bytes) = self.block_tree.get(hash)? else {
            return Ok(None);
        };
        let (projection, exact_match) =
            inspect_native_pow_metadata_bincode_exact(&bytes, expected, context)?;
        if projection.hash != *hash {
            return Err(anyhow!(
                "stored native block hash mismatch: key={} embedded={}",
                hex32(hash),
                hex32(&projection.hash)
            ));
        }
        if projection.hash != projection.work_hash {
            return Err(anyhow!(
                "stored native block work-hash mismatch: hash={} work_hash={}",
                hex32(&projection.hash),
                hex32(&projection.work_hash)
            ));
        }
        Ok(Some((projection, exact_match)))
    }

    fn load_exact_stored_meta_for_projection(
        &self,
        projection: NativePowMetaProjection,
        context: &'static str,
    ) -> std::result::Result<NativeBlockMeta, NativeChainLoadError> {
        let meta = self.header_by_hash(&projection.hash)?.ok_or_else(|| {
            NativeChainLoadError::MissingAncestor {
                hash_hex: hex32(&projection.hash),
            }
        })?;
        if NativePowMetaProjection::from(&meta) != projection {
            return Err(NativeChainLoadError::Corrupt(anyhow!(
                "{context} stored metadata changed during admission at {}",
                hex32(&projection.hash)
            )));
        }
        Ok(meta)
    }

    fn local_canonical_reorg_phase_error(
        context: &'static str,
        error: NativeChainLoadError,
    ) -> NativeChainLoadError {
        match error {
            NativeChainLoadError::MissingAncestor { hash_hex } => NativeChainLoadError::Corrupt(
                anyhow!("{context}: locally admitted native block disappeared at {hash_hex}"),
            ),
            NativeChainLoadError::Corrupt(error) => {
                NativeChainLoadError::Corrupt(error.context(context))
            }
        }
    }

    fn action_identities_from_stored_ancestry_streaming(
        &self,
        ancestry: &[NativePowMetaProjection],
    ) -> std::result::Result<
        (BTreeSet<ActionId48>, BTreeSet<ActionSemanticId48>),
        NativeChainLoadError,
    > {
        let mut action_ids = BTreeSet::new();
        let mut semantic_ids = BTreeSet::new();
        for projection in ancestry.iter().copied().skip(1) {
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            let meta = self.load_exact_stored_meta_for_projection(
                projection,
                "native canonical reorg action-identity scan",
            )?;
            for action in decode_block_actions(&meta)? {
                if !action_ids.insert(action.tx_hash)
                    || !semantic_ids.insert(pending_action_semantic_hash(&action))
                {
                    return Err(NativeChainLoadError::Corrupt(anyhow!(
                        "native canonical ancestry contains a duplicate action identity"
                    )));
                }
            }
        }
        Ok((action_ids, semantic_ids))
    }

    fn canonical_undos_from_stored_ancestry_streaming(
        &self,
        ancestry: &[NativePowMetaProjection],
        first_replacement_index: usize,
    ) -> std::result::Result<(Vec<NativeCanonicalUndoV1>, u64, u64, usize), NativeChainLoadError>
    {
        if first_replacement_index == 0 || first_replacement_index > ancestry.len() {
            return Err(NativeChainLoadError::Corrupt(anyhow!(
                "native canonical undo replacement index is outside the stored ancestry"
            )));
        }
        let mut commitment_start = 0u64;
        let mut nullifier_start = 0u64;
        let mut ciphertext_index_count = 0usize;
        let mut ciphertext_overlay = BTreeMap::<[u8; 48], Option<Vec<u8>>>::new();
        let mut undos = Vec::with_capacity(ancestry.len().saturating_sub(first_replacement_index));

        for (index, projection) in ancestry.iter().copied().enumerate().skip(1) {
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            let meta = self.load_exact_stored_meta_for_projection(
                projection,
                "native canonical reorg undo scan",
            )?;
            let actions = decode_block_actions(&meta)?;
            verify_decoded_action_root(&actions, &meta, "native canonical reorg undo action root")?;
            let commitment_count = actions.iter().try_fold(0usize, |count, action| {
                count
                    .checked_add(action.commitments.len())
                    .ok_or_else(|| anyhow!("native canonical undo commitment count overflow"))
            })?;
            let nullifier_count = actions.iter().try_fold(0usize, |count, action| {
                count
                    .checked_add(action.nullifiers.len())
                    .ok_or_else(|| anyhow!("native canonical undo nullifier count overflow"))
            })?;
            let mut ciphertext_index_entries = Vec::new();
            for action in &actions {
                if action.ciphertext_hashes.len() != action.ciphertext_sizes.len() {
                    return Err(NativeChainLoadError::Corrupt(anyhow!(
                        "native canonical undo ciphertext metadata count mismatch"
                    )));
                }
                if owns_legacy_ciphertext_da_rows(action) {
                    for (offset, hash) in action.ciphertext_hashes.iter().enumerate() {
                        let offset_u64 = u64::try_from(offset).map_err(|_| {
                            anyhow!("native canonical undo ciphertext offset exceeds u64")
                        })?;
                        let mut value = Vec::with_capacity(NATIVE_CIPHERTEXT_INDEX_VALUE_BYTES);
                        value.extend_from_slice(action.tx_hash.as_bytes());
                        value.extend_from_slice(&action.ciphertext_sizes[offset].to_le_bytes());
                        value.extend_from_slice(&offset_u64.to_le_bytes());
                        ciphertext_index_entries.push((*hash, value));
                    }
                }
            }
            ciphertext_index_count = ciphertext_index_count
                .checked_add(ciphertext_index_entries.len())
                .ok_or_else(|| anyhow!("native canonical undo ciphertext count overflow"))?;

            // A full canonical rebuild clears the ciphertext index before
            // writing the replacement chain. Seed first occurrences as absent
            // rather than reading values from the branch being replaced.
            for (hash, _) in &ciphertext_index_entries {
                ciphertext_overlay.entry(*hash).or_insert(None);
            }
            let undo = self.canonical_undo_from_parts(
                &meta,
                commitment_start,
                commitment_count,
                nullifier_start,
                nullifier_count,
                &ciphertext_index_entries,
                &mut ciphertext_overlay,
            )?;
            if index >= first_replacement_index {
                undos.push(undo);
            }
            commitment_start =
                commitment_start
                    .checked_add(u64::try_from(commitment_count).map_err(|_| {
                        anyhow!("native canonical undo commitment count exceeds u64")
                    })?)
                    .ok_or_else(|| anyhow!("native canonical undo commitment cursor overflow"))?;
            nullifier_start =
                nullifier_start
                    .checked_add(u64::try_from(nullifier_count).map_err(|_| {
                        anyhow!("native canonical undo nullifier count exceeds u64")
                    })?)
                    .ok_or_else(|| anyhow!("native canonical undo nullifier cursor overflow"))?;
        }

        Ok((
            undos,
            commitment_start,
            nullifier_start,
            ciphertext_index_count,
        ))
    }

    fn staged_ciphertext_removals_from_stored_ancestry_streaming(
        &self,
        ancestry: &[NativePowMetaProjection],
        state: &mut NativeState,
    ) -> std::result::Result<Vec<[u8; 48]>, NativeChainLoadError> {
        let mut removals = Vec::new();
        for projection in ancestry.iter().copied() {
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            let meta = self.load_exact_stored_meta_for_projection(
                projection,
                "native canonical reorg staged-removal scan",
            )?;
            for action in decode_block_actions(&meta)? {
                if owns_legacy_ciphertext_da_rows(&action) {
                    removals.extend(action.ciphertext_hashes.iter().copied());
                    clear_staged_ciphertext_markers(state, &action);
                }
            }
        }
        Ok(removals)
    }

    fn orphaned_actions_from_old_branch_suffix_compact(
        &self,
        old_best: &NativeBlockMeta,
        admitted_new_ancestry: &[NativePowMetaProjection],
        new_action_ids: &BTreeSet<ActionId48>,
        new_semantic_ids: &BTreeSet<ActionSemanticId48>,
    ) -> std::result::Result<Vec<PendingAction>, NativeChainLoadError> {
        let mut cursor = old_best.hash;
        let mut expected_height = old_best.height;
        let mut seen = BTreeSet::new();
        let mut orphaned_hashes = Vec::new();
        loop {
            if !seen.insert(cursor) {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "stored native block parent cycle at {}",
                    hex32(&cursor)
                )));
            }
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            let meta = self.header_by_hash(&cursor)?.ok_or_else(|| {
                NativeChainLoadError::MissingAncestor {
                    hash_hex: hex32(&cursor),
                }
            })?;
            if cursor == old_best.hash && meta != *old_best {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "stored native old-branch tip does not match the canonical snapshot"
                )));
            }
            if meta.height != expected_height {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "stored native old-branch height mismatch at {}: expected {} observed {}",
                    hex32(&cursor),
                    expected_height,
                    meta.height
                )));
            }
            let shared = usize::try_from(meta.height)
                .ok()
                .and_then(|height| admitted_new_ancestry.get(height))
                .filter(|new_meta| new_meta.hash == meta.hash);
            if let Some(new_meta) = shared {
                if NativePowMetaProjection::from(&meta) != *new_meta {
                    return Err(NativeChainLoadError::Corrupt(anyhow!(
                        "shared native reorg ancestor metadata mismatch at height {} ({})",
                        meta.height,
                        hex32(&meta.hash)
                    )));
                }
                break;
            }
            if meta.height == 0 {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "native reorg old branch has no ancestor in the admitted chain"
                )));
            }
            orphaned_hashes.push(meta.hash);
            cursor = meta.parent_hash;
            expected_height = meta
                .height
                .checked_sub(1)
                .ok_or_else(|| anyhow!("native old-branch parent height underflow"))?;
        }

        let mut orphaned = Vec::new();
        for hash in orphaned_hashes.into_iter().rev() {
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            let meta = self.header_by_hash(&hash)?.ok_or_else(|| {
                NativeChainLoadError::MissingAncestor {
                    hash_hex: hex32(&hash),
                }
            })?;
            for action in decode_block_actions(&meta)? {
                if !new_action_ids.contains(&action.tx_hash)
                    && !new_semantic_ids.contains(&pending_action_semantic_hash(&action))
                {
                    orphaned.push(action);
                }
            }
        }
        Ok(orphaned)
    }

    #[cfg(test)]
    pub(crate) fn orphaned_actions_from_old_branch_suffix_compact_for_test(
        &self,
        old_best: &NativeBlockMeta,
        admitted_new_chain: &[NativeBlockMeta],
        new_action_ids: &BTreeSet<ActionId48>,
        new_semantic_ids: &BTreeSet<ActionSemanticId48>,
    ) -> std::result::Result<Vec<PendingAction>, NativeChainLoadError> {
        let admitted_new_ancestry = admitted_new_chain
            .iter()
            .map(NativePowMetaProjection::from)
            .collect::<Vec<_>>();
        self.orphaned_actions_from_old_branch_suffix_compact(
            old_best,
            &admitted_new_ancestry,
            new_action_ids,
            new_semantic_ids,
        )
    }

    fn admit_compact_stored_canonical_reorg_chain(
        &self,
        ancestry: &[NativePowMetaProjection],
        height_entries: &[(u64, [u8; 32])],
    ) -> std::result::Result<(), NativeChainLoadError> {
        let expected_genesis = genesis_meta(self.config.pow_bits)?;
        let genesis_matches_expected = ancestry
            .first()
            .is_some_and(|genesis| genesis == &NativePowMetaProjection::from(&expected_genesis))
            && self
                .inspect_stored_pow_metadata(
                    &expected_genesis.hash,
                    Some(&expected_genesis),
                    "native compact canonical reorg genesis",
                )?
                .is_some_and(|(_, exact_match)| exact_match);
        let canonical_heights_contiguous = ancestry
            .iter()
            .enumerate()
            .all(|(index, meta)| u64::try_from(index).ok() == Some(meta.height));
        let canonical_parent_hashes_contiguous = ancestry
            .windows(2)
            .all(|pair| pair[1].parent_hash == pair[0].hash);
        let height_entries_match_chain = ancestry.len() == height_entries.len()
            && ancestry
                .iter()
                .zip(height_entries)
                .all(|(meta, (height, hash))| meta.height == *height && meta.hash == *hash);
        evaluate_native_canonical_reorg_chain_admission(NativeCanonicalReorgChainAdmissionInput {
            chain_nonempty: !ancestry.is_empty(),
            genesis_matches_expected,
            best_metadata_matches_chain: ancestry.last().is_some(),
            canonical_heights_contiguous,
            canonical_chain_ids_match: ancestry
                .iter()
                .all(|meta| meta.chain_id == HEGEMON_CHAIN_ID_V1),
            canonical_rules_hashes_match: ancestry
                .iter()
                .all(|meta| meta.rules_hash == HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE),
            canonical_hashes_match_work_hashes: ancestry
                .iter()
                .all(|meta| meta.hash == meta.work_hash),
            canonical_parent_hashes_contiguous,
            block_record_count_matches_chain: true,
            block_records_match_chain: true,
            height_entry_count_matches_chain: ancestry.len() == height_entries.len(),
            height_entries_match_chain,
        })
        .map_err(|rejection| {
            NativeChainLoadError::Corrupt(native_canonical_reorg_chain_admission_error(rejection))
        })
    }

    fn stored_pow_parent<'a>(
        &self,
        parent: &'a NativeBlockMeta,
        context: &str,
    ) -> Result<&'a NativeBlockMeta> {
        let (_, exact_match) = self
            .inspect_stored_pow_metadata(&parent.hash, Some(parent), context)?
            .ok_or_else(|| anyhow!("missing native block {}", hex32(&parent.hash)))?;
        if !exact_match {
            return Err(anyhow!(
                "{context} supplied native PoW parent metadata does not match stored record {}",
                hex32(&parent.hash)
            ));
        }
        Ok(parent)
    }

    fn pow_retarget_anchor_from_parent(
        &self,
        parent: &NativeBlockMeta,
        new_height: u64,
        validated_batch_prefix: &[NativeBlockMeta],
    ) -> Result<Option<NativePowMetaProjection>> {
        let Some(anchor_steps) =
            consensus::pow::pow_retarget_anchor_steps(parent.height, new_height)
        else {
            return Ok(None);
        };

        let mut cursor = NativePowMetaProjection::from(parent);
        for _ in 0..anchor_steps {
            let expected_height = cursor.height.checked_sub(1).ok_or_else(|| {
                anyhow!(
                    "native PoW retarget anchor underflow at parent height {}",
                    parent.height
                )
            })?;
            let ancestor = if let Some(ancestor) = validated_batch_prefix
                .iter()
                .rev()
                .find(|meta| meta.hash == cursor.parent_hash)
            {
                NativePowMetaProjection::from(ancestor)
            } else {
                self.inspect_stored_pow_metadata(
                    &cursor.parent_hash,
                    None,
                    "native PoW retarget ancestor",
                )?
                .map(|(projection, _)| projection)
                .ok_or_else(|| {
                    anyhow!(
                        "native PoW retarget missing ancestor {} below parent height {}",
                        hex32(&cursor.parent_hash),
                        parent.height
                    )
                })?
            };
            if ancestor.height != expected_height {
                return Err(anyhow!(
                    "native PoW retarget ancestor height mismatch for {}: expected {}, got {}",
                    hex32(&ancestor.hash),
                    expected_height,
                    ancestor.height
                ));
            }
            cursor = ancestor;
        }
        Ok(Some(cursor))
    }

    pub(crate) fn expected_child_pow_bits(&self, parent: &NativeBlockMeta) -> Result<u32> {
        let parent = self.stored_pow_parent(parent, "native PoW schedule")?;
        let new_height = parent
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow!("native PoW child height overflow"))?;
        let anchor_timestamp_ms = self
            .pow_retarget_anchor_from_parent(parent, new_height, &[])?
            .map(|anchor| anchor.timestamp_ms);
        consensus::pow::expected_pow_bits_from_schedule(
            self.config.pow_bits,
            parent.pow_bits,
            parent.height,
            new_height,
            parent.timestamp_ms,
            anchor_timestamp_ms,
        )
        .map_err(|err| anyhow!("native PoW bits schedule failed: {err}"))
    }

    pub(crate) fn expected_canonical_child_pow_bits(
        &self,
        parent: &NativeBlockMeta,
    ) -> Result<u32> {
        let parent = self.stored_pow_parent(parent, "canonical native PoW schedule")?;
        let indexed_parent_hash = self.hash_by_height(parent.height)?.ok_or_else(|| {
            anyhow!(
                "missing canonical height index for native PoW parent at height {}",
                parent.height
            )
        })?;
        if indexed_parent_hash != parent.hash {
            return Err(anyhow!(
                "canonical height index at {} does not reference supplied native PoW parent: indexed={} supplied={}",
                parent.height,
                hex32(&indexed_parent_hash),
                hex32(&parent.hash)
            ));
        }
        let new_height = parent
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow!("native PoW child height overflow"))?;
        let anchor = self.pow_retarget_anchor_from_parent(parent, new_height, &[])?;
        let anchor_timestamp_ms = if let Some(anchor) = anchor {
            let indexed_anchor_hash = self.hash_by_height(anchor.height)?.ok_or_else(|| {
                anyhow!(
                    "missing canonical height index for native PoW retarget anchor at height {}",
                    anchor.height
                )
            })?;
            if indexed_anchor_hash != anchor.hash {
                return Err(anyhow!(
                    "canonical height index at {} does not reference supplied parent ancestry: indexed={} ancestry={}",
                    anchor.height,
                    hex32(&indexed_anchor_hash),
                    hex32(&anchor.hash)
                ));
            }
            Some(anchor.timestamp_ms)
        } else {
            None
        };
        consensus::pow::expected_pow_bits_from_schedule(
            self.config.pow_bits,
            parent.pow_bits,
            parent.height,
            new_height,
            parent.timestamp_ms,
            anchor_timestamp_ms,
        )
        .map_err(|err| anyhow!("native PoW bits schedule failed: {err}"))
    }

    pub(crate) fn expected_sync_batch_child_pow_bits(
        &self,
        parent: &NativeBlockMeta,
        validated_batch_prefix: &[NativeBlockMeta],
    ) -> Result<u32> {
        let parent = if let Some(validated_parent) = validated_batch_prefix.last() {
            if validated_parent != parent {
                return Err(anyhow!(
                    "native sync PoW parent does not match validated batch prefix tip"
                ));
            }
            validated_parent
        } else {
            self.stored_pow_parent(parent, "native sync PoW schedule")?
        };
        let new_height = parent
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow!("native PoW child height overflow"))?;
        let anchor_timestamp_ms = self
            .pow_retarget_anchor_from_parent(parent, new_height, validated_batch_prefix)?
            .map(|anchor| anchor.timestamp_ms);
        consensus::pow::expected_pow_bits_from_schedule(
            self.config.pow_bits,
            parent.pow_bits,
            parent.height,
            new_height,
            parent.timestamp_ms,
            anchor_timestamp_ms,
        )
        .map_err(|err| anyhow!("native PoW bits schedule failed: {err}"))
    }

    #[cfg(test)]
    pub(crate) fn replay_state_to_hash(&self, hash: [u8; 32]) -> Result<NativeState> {
        let chain = self.chain_to_hash(hash)?;
        self.replay_chain_state(&chain)
    }

    /// Exact restart regression seam: replay every canonical stored body
    /// through the production verifier path that records the in-process
    /// checkpoints required before a side-branch reorganization. It neither
    /// authorizes a route nor writes durable state.
    #[cfg(test)]
    pub(crate) fn verify_canonical_checkpoints_after_restart_for_test(
        &self,
        hash: [u8; 32],
    ) -> Result<NativeState> {
        let chain = self.chain_to_hash(hash)?;
        let genesis = chain
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("empty native canonical checkpoint replay"))?;
        let mut state = Self::replay_state_from_genesis(genesis);
        for (index, meta) in chain.iter().enumerate().skip(1) {
            let expected_pow_bits = native_expected_child_pow_bits_for_chain_index(
                &chain,
                index - 1,
                self.config.pow_bits,
            )?;
            self.replay_stored_block_into_state(&mut state, meta.clone(), expected_pow_bits)?;
        }
        Ok(state)
    }

    fn replay_state_from_genesis(genesis: NativeBlockMeta) -> NativeState {
        NativeState {
            header_mmr_peaks: header_mmr_peaks_from_hashes(&[genesis.hash]),
            best: genesis,
            pending_actions: BTreeMap::new(),
            pending_action_semantic_index: BTreeMap::new(),
            pending_action_order_index: BTreeSet::new(),
            pending_nullifiers: BTreeSet::new(),
            pending_bridge_replay_keys: PersistentKeySet48::new(),
            pending_mempool_bytes: 0,
            commitment_tree: CommitmentTreeState::default(),
            nullifiers: PersistentKeySet48::new(),
            nullifier_accumulator: NullifierAccumulator::new(),
            consumed_bridge_messages: PersistentKeySet48::new(),
            stablecoin_policy_authorizations: BTreeSet::new(),
            staged_ciphertexts: BTreeMap::new(),
            staged_proofs: BTreeMap::new(),
        }
    }

    fn replay_block_into_state(
        &self,
        state: &mut NativeState,
        meta: NativeBlockMeta,
        expected_pow_bits: u32,
    ) -> Result<()> {
        verify_native_block_meta_projection(Some(&state.best), &meta, Some(expected_pow_bits))
            .with_context(|| {
                format!(
                    "replay stored native block metadata at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                )
            })?;
        let actions = decode_block_actions(&meta)?;
        verify_decoded_action_root(&actions, &meta, "native replay action root")?;
        validate_block_actions_locked(state, &actions)?;
        let (state_root, nullifier_root, extrinsics_root, tx_count) =
            preview_pending_roots_with_archive(
                &self.da_ciphertext_tree,
                Some(&self.ciphertext_archive_tree),
                state,
                &actions,
            )?;
        let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
        let bridge_messages = bridge_messages_from_actions(&actions, meta.height)?;
        let message_root = bridge_message_root(&bridge_messages);
        let message_count = u32::try_from(bridge_messages.len())
            .map_err(|_| anyhow!("native bridge message count overflow"))?;
        let (expected_header_mmr_root, expected_header_mmr_len) =
            header_mmr_commitment_after_best(&state.best, &state.header_mmr_peaks)?;
        let (fee_total, has_coinbase) = native_block_replay_supply_parts(&actions, meta.height)?;
        evaluate_native_block_replay_refinement_for_actions(
            "native replay refinement failed",
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
            state,
            &actions,
            native_block_replay_refinement_input_from_state(
                state,
                meta.height,
                fee_total,
                has_coinbase,
                meta.supply_digest,
                tx_count == meta.tx_count,
                state_root == meta.state_root,
                kernel_root == meta.kernel_root,
                nullifier_root == meta.nullifier_root,
                extrinsics_root == meta.extrinsics_root,
                message_root == meta.message_root,
                message_count == meta.message_count,
                meta.header_mmr_root == expected_header_mmr_root,
                meta.header_mmr_len == expected_header_mmr_len,
            ),
        )?;
        verify_native_block_artifacts_locked(self, state, &actions, &meta)?;
        apply_actions_to_memory_with_archive(
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
            state,
            &actions,
        )?;
        state.header_mmr_peaks = append_header_mmr_peak_state(state, &meta)?;
        state.best = meta;
        Ok(())
    }

    pub(crate) fn replay_chain_state(&self, chain: &[NativeBlockMeta]) -> Result<NativeState> {
        let genesis = chain
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("empty native chain replay"))?;
        let mut state = Self::replay_state_from_genesis(genesis);
        for (index, meta) in chain.iter().enumerate().skip(1) {
            let expected_pow_bits = native_expected_child_pow_bits_for_chain_index(
                chain,
                index - 1,
                self.config.pow_bits,
            )?;
            self.replay_block_into_state(&mut state, meta.clone(), expected_pow_bits)?;
        }
        Ok(state)
    }

    fn expected_projection_child_pow_bits(
        &self,
        ancestry: &[NativePowMetaProjection],
        parent_index: usize,
    ) -> Result<u32> {
        let parent = ancestry
            .get(parent_index)
            .ok_or_else(|| anyhow!("native streaming replay parent index out of range"))?;
        let new_height = parent
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow!("native PoW child height overflow"))?;
        let anchor_timestamp_ms = if let Some(anchor_steps) =
            consensus::pow::pow_retarget_anchor_steps(parent.height, new_height)
        {
            let anchor_steps = usize::try_from(anchor_steps)
                .map_err(|_| anyhow!("native PoW retarget anchor step overflow"))?;
            let anchor_index = parent_index.checked_sub(anchor_steps).ok_or_else(|| {
                anyhow!(
                    "native PoW retarget missing anchor history at parent height {}",
                    parent.height
                )
            })?;
            Some(
                ancestry
                    .get(anchor_index)
                    .ok_or_else(|| anyhow!("native streaming replay anchor index out of range"))?
                    .timestamp_ms,
            )
        } else {
            None
        };
        consensus::pow::expected_pow_bits_from_schedule(
            self.config.pow_bits,
            parent.pow_bits,
            parent.height,
            new_height,
            parent.timestamp_ms,
            anchor_timestamp_ms,
        )
        .map_err(|err| anyhow!("native PoW bits schedule failed: {err}"))
    }

    fn replay_stored_block_into_state(
        &self,
        state: &mut NativeState,
        meta: NativeBlockMeta,
        expected_pow_bits: u32,
    ) -> Result<()> {
        verify_native_block_meta_projection(Some(&state.best), &meta, Some(expected_pow_bits))
            .with_context(|| {
                format!(
                    "replay stored native block metadata at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                )
            })?;
        let actions = decode_block_actions(&meta)?;
        verify_decoded_action_root(&actions, &meta, "native replay action root")?;
        validate_native_block_proof_policy(state.best.height, meta.height, &actions)?;
        validate_block_actions_locked(state, &actions)?;
        let (state_root, nullifier_root, extrinsics_root, tx_count) =
            preview_pending_roots_with_archive(
                &self.da_ciphertext_tree,
                Some(&self.ciphertext_archive_tree),
                state,
                &actions,
            )?;
        let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
        let bridge_messages = bridge_messages_from_actions(&actions, meta.height)?;
        let message_root = bridge_message_root(&bridge_messages);
        let message_count = u32::try_from(bridge_messages.len())
            .map_err(|_| anyhow!("native bridge message count overflow"))?;
        let (expected_header_mmr_root, expected_header_mmr_len) =
            header_mmr_commitment_after_best(&state.best, &state.header_mmr_peaks)?;
        let (fee_total, has_coinbase) = native_block_replay_supply_parts(&actions, meta.height)?;
        evaluate_native_block_replay_refinement_for_actions(
            "native replay refinement failed",
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
            state,
            &actions,
            native_block_replay_refinement_input_from_state(
                state,
                meta.height,
                fee_total,
                has_coinbase,
                meta.supply_digest,
                tx_count == meta.tx_count,
                state_root == meta.state_root,
                kernel_root == meta.kernel_root,
                nullifier_root == meta.nullifier_root,
                extrinsics_root == meta.extrinsics_root,
                message_root == meta.message_root,
                message_count == meta.message_count,
                meta.header_mmr_root == expected_header_mmr_root,
                meta.header_mmr_len == expected_header_mmr_len,
            ),
        )?;
        #[cfg(test)]
        if actions.iter().any(is_shielded_transfer_action) {
            self.historical_block_proof_replay_invocations
                .fetch_add(1, Ordering::Relaxed);
        }
        verify_native_legacy_block_artifacts_locked(self, state, &actions, &meta)?;
        self.remember_verified_block_in_process(&meta)?;
        apply_actions_to_memory_with_archive(
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
            state,
            &actions,
        )?;
        state.header_mmr_peaks = append_header_mmr_peak_state(state, &meta)?;
        state.best = meta;
        let checkpoint = native_canonical_state_checkpoint(
            &state.best,
            &state.commitment_tree,
            &state.nullifier_accumulator,
            &state.header_mmr_peaks,
        )?;
        self.remember_canonical_checkpoint_in_process(checkpoint);
        Ok(())
    }

    pub(crate) fn stored_branch_suffix_from_canonical_ancestor(
        &self,
        target: &NativeBlockMeta,
    ) -> Result<(NativeBlockMeta, Vec<NativeBlockMeta>)> {
        let mut cursor = target.clone();
        let mut reversed_suffix = Vec::new();
        loop {
            let canonical_hash = self
                .height_tree
                .get(height_key(cursor.height))?
                .and_then(|bytes| bytes.as_ref().try_into().ok());
            if canonical_hash == Some(cursor.hash) {
                reversed_suffix.reverse();
                return Ok((cursor, reversed_suffix));
            }
            if cursor.height == 0 {
                return Err(anyhow!(
                    "native side branch does not share the active V2 genesis"
                ));
            }
            reversed_suffix.push(cursor.clone());
            let parent = self.header_by_hash(&cursor.parent_hash)?.ok_or_else(|| {
                anyhow!(
                    "missing native side-branch parent {} below height {}",
                    hex32(&cursor.parent_hash),
                    cursor.height
                )
            })?;
            if parent.hash != cursor.parent_hash
                || parent.height.saturating_add(1) != cursor.height
                || parent.chain_id != cursor.chain_id
                || parent.rules_hash != cursor.rules_hash
            {
                return Err(anyhow!(
                    "invalid native side-branch parent link at height {}",
                    cursor.height
                ));
            }
            cursor = parent;
        }
    }

    /// Split a caller-supplied contiguous branch at its last canonical block.
    /// Sync may possess a fully verified candidate prefix that has not yet
    /// been persisted; requiring hash-addressed parent rows before replay
    /// would drop that valid branch. The canonical ancestor itself is reloaded
    /// from local storage, while every supplied suffix block remains subject to
    /// the normal full replay/PoW/action validation before atomic publication.
    fn supplied_branch_suffix_from_canonical_ancestor(
        &self,
        chain: &[NativeBlockMeta],
    ) -> Result<(NativeBlockMeta, Vec<NativeBlockMeta>)> {
        let mut canonical_ancestor = None;
        for (index, meta) in chain.iter().enumerate().rev() {
            if self.hash_by_height(meta.height)? == Some(meta.hash) {
                canonical_ancestor = Some((index, meta));
                break;
            }
        }
        let (ancestor_index, supplied_ancestor) = canonical_ancestor
            .ok_or_else(|| anyhow!("supplied native reorg branch has no canonical ancestor"))?;
        let ancestor = self
            .load_canonical_block_at_height_unverified(supplied_ancestor.height)
            .with_context(|| {
                format!(
                    "load supplied native reorg ancestor at height {}",
                    supplied_ancestor.height
                )
            })?;
        if ancestor.hash != supplied_ancestor.hash {
            return Err(anyhow!(
                "supplied native reorg ancestor changed during branch resolution"
            ));
        }
        let suffix = chain[ancestor_index.saturating_add(1)..].to_vec();
        if suffix.is_empty() {
            return Err(anyhow!("supplied native reorg target is already canonical"));
        }
        Ok((ancestor, suffix))
    }

    pub(crate) fn canonical_state_at_ancestor(
        &self,
        snapshot: &NativeState,
        ancestor: &NativeBlockMeta,
    ) -> Result<NativeState> {
        if ancestor.height > snapshot.best.height {
            return Err(anyhow!("native branch ancestor exceeds canonical tip"));
        }
        if ancestor.hash == snapshot.best.hash {
            return Ok(snapshot.clone());
        }
        let (commitment_tree, nullifier_accumulator, header_mmr_peaks) = if ancestor.height == 0 {
            (
                CommitmentTreeState::default(),
                NullifierAccumulator::new(),
                header_mmr_peaks_from_hashes(&[ancestor.hash]),
            )
        } else {
            let checkpoint = self
                .in_process_canonical_checkpoint(ancestor)?
                .ok_or_else(|| {
                    anyhow!(
                        "canonical ancestor checkpoint at height {} ({}) was not verified in this process",
                        ancestor.height,
                        hex32(&ancestor.hash)
                    )
                })?;
            validate_native_canonical_state_checkpoint(&checkpoint, ancestor)?
        };

        let mut state = snapshot.clone();
        let first_orphan_height = ancestor
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow!("native branch ancestor height overflow"))?;
        for height in first_orphan_height..=snapshot.best.height {
            let orphan = self.load_canonical_block_at_height_unverified(height)?;
            for action in decode_block_actions(&orphan)? {
                for nullifier in action.nullifiers.iter().copied() {
                    if !state.nullifiers.remove(&nullifier) {
                        return Err(anyhow!(
                            "canonical checkpoint rollback missing nullifier {}",
                            hex48(&nullifier)
                        ));
                    }
                }
                if let Some(replay_key) = bridge_inbound_replay_key_from_action(&action)? {
                    if !state.consumed_bridge_messages.remove(&replay_key) {
                        return Err(anyhow!(
                            "canonical checkpoint rollback missing bridge replay key {}",
                            hex48(&replay_key)
                        ));
                    }
                }
            }
        }
        state.best = ancestor.clone();
        state.commitment_tree = commitment_tree;
        state.nullifier_accumulator = nullifier_accumulator;
        state.header_mmr_peaks = header_mmr_peaks;
        if state.nullifier_accumulator.leaf_count()
            != u64::try_from(state.nullifiers.len())
                .map_err(|_| anyhow!("native nullifier set length exceeds u64"))?
        {
            return Err(anyhow!(
                "native canonical checkpoint nullifier count mismatch at height {}",
                ancestor.height
            ));
        }
        Ok(state)
    }

    fn plan_canonical_suffix_deltas(
        &self,
        base_state: &NativeState,
        suffix: &[NativeBlockMeta],
    ) -> Result<Vec<NativeCanonicalBlockDelta>> {
        let mut planning_state = base_state.clone();
        let mut deltas = Vec::with_capacity(suffix.len());
        for meta in suffix {
            if meta.parent_hash != planning_state.best.hash
                || meta.height != planning_state.best.height.saturating_add(1)
            {
                return Err(anyhow!(
                    "native canonical delta suffix is not contiguous at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                ));
            }
            let encoded = bincode::serialize(meta)
                .context("encode native canonical suffix block for delta commit")?;
            #[cfg(test)]
            {
                self.reorg_suffix_blocks_examined
                    .fetch_add(1, Ordering::Relaxed);
                self.reorg_suffix_body_bytes_examined.fetch_add(
                    u64::try_from(encoded.len()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
            }
            let actions = decode_block_actions(meta)?;
            let commitment_start = planning_state.commitment_tree.leaf_count();
            let planned = plan_materialized_action_effects_with_archive(
                &self.da_ciphertext_tree,
                Some(&self.ciphertext_archive_tree),
                &planning_state,
                &actions,
            )?;
            let mut commitment_entries = Vec::new();
            let mut ciphertext_archive_entries = Vec::new();
            let mut bridge_replay_entries = Vec::new();
            let mut ciphertext_index_entries = Vec::new();
            let ordered_nullifiers = actions
                .iter()
                .flat_map(|action| action.nullifiers.iter().copied())
                .collect::<Vec<_>>();
            let nullifier_append = planning_state
                .nullifier_accumulator
                .plan_indexed_append(ordered_nullifiers)
                .map_err(|err| anyhow!("plan native canonical suffix nullifiers failed: {err}"))?;

            for (action, effect) in actions.iter().zip(planned.iter()) {
                if action.ciphertext_hashes.len() != action.ciphertext_sizes.len() {
                    return Err(anyhow!(
                        "native canonical suffix ciphertext metadata count mismatch"
                    ));
                }
                for (offset, commitment) in action.commitments.iter().enumerate() {
                    let index = effect
                        .commitment_start
                        .checked_add(u64::try_from(offset).map_err(|_| {
                            anyhow!("native canonical suffix commitment offset overflow")
                        })?)
                        .ok_or_else(|| {
                            anyhow!("native canonical suffix commitment index overflow")
                        })?;
                    commitment_entries.push((index, *commitment));
                }
                for (offset, bytes) in effect.ciphertexts.iter().enumerate() {
                    let index = effect
                        .commitment_start
                        .checked_add(u64::try_from(offset).map_err(|_| {
                            anyhow!("native canonical suffix ciphertext offset overflow")
                        })?)
                        .ok_or_else(|| {
                            anyhow!("native canonical suffix ciphertext archive index overflow")
                        })?;
                    ciphertext_archive_entries.push((index, bytes.clone()));
                }
                if let Some(replay_key) = effect.replay_key {
                    bridge_replay_entries.push(replay_key);
                }
                if owns_legacy_ciphertext_da_rows(action) {
                    for (offset, hash) in action.ciphertext_hashes.iter().enumerate() {
                        let offset = u64::try_from(offset)
                            .map_err(|_| anyhow!("native ciphertext row offset exceeds u64"))?;
                        let mut value = Vec::with_capacity(NATIVE_CIPHERTEXT_INDEX_VALUE_BYTES);
                        value.extend_from_slice(action.tx_hash.as_bytes());
                        value.extend_from_slice(
                            &action.ciphertext_sizes[offset as usize].to_le_bytes(),
                        );
                        value.extend_from_slice(&offset.to_le_bytes());
                        ciphertext_index_entries.push((*hash, value));
                    }
                }
            }

            apply_planned_actions_to_memory(&mut planning_state, &actions, &planned)?;
            if planning_state.commitment_tree.root() != meta.state_root
                || planning_state.nullifier_accumulator != nullifier_append.next_accumulator
                || planning_state.nullifier_accumulator.root() != meta.nullifier_root
            {
                return Err(anyhow!(
                    "native canonical suffix delta does not match block state roots at height {}",
                    meta.height
                ));
            }
            planning_state.best = meta.clone();
            deltas.push(NativeCanonicalBlockDelta {
                meta: meta.clone(),
                encoded,
                actions,
                commitment_start,
                commitment_entries,
                ciphertext_archive_entries,
                nullifier_append,
                bridge_replay_entries,
                ciphertext_index_entries,
            });
        }
        Ok(deltas)
    }

    fn canonical_undo_from_delta(
        &self,
        delta: &NativeCanonicalBlockDelta,
        ciphertext_overlay: &mut BTreeMap<[u8; 48], Option<Vec<u8>>>,
    ) -> Result<NativeCanonicalUndoV1> {
        self.canonical_undo_from_parts(
            &delta.meta,
            delta.commitment_start,
            delta.commitment_entries.len(),
            delta.nullifier_append.base_leaf_count,
            delta.nullifier_append.rows.len(),
            &delta.ciphertext_index_entries,
            ciphertext_overlay,
        )
    }

    fn canonical_undo_from_parts(
        &self,
        meta: &NativeBlockMeta,
        commitment_start: u64,
        commitment_count: usize,
        nullifier_start: u64,
        nullifier_count: usize,
        ciphertext_index_entries: &[([u8; 48], Vec<u8>)],
        ciphertext_overlay: &mut BTreeMap<[u8; 48], Option<Vec<u8>>>,
    ) -> Result<NativeCanonicalUndoV1> {
        let mut ciphertext_index_undo = Vec::with_capacity(ciphertext_index_entries.len());
        for (hash, replacement) in ciphertext_index_entries {
            let previous = if let Some(previous) = ciphertext_overlay.get(hash) {
                previous.clone()
            } else {
                self.ciphertext_index_tree
                    .get(hash.as_slice())?
                    .map(|bytes| bytes.to_vec())
            };
            if previous
                .as_ref()
                .is_some_and(|value| value.len() != NATIVE_CIPHERTEXT_INDEX_VALUE_BYTES)
            {
                return Err(anyhow!(
                    "native ciphertext index row has invalid length before canonical append"
                ));
            }
            ciphertext_index_undo.push(NativeCiphertextIndexUndoV1 {
                hash: *hash,
                previous,
            });
            ciphertext_overlay.insert(*hash, Some(replacement.clone()));
        }
        let commitment_count = u64::try_from(commitment_count)
            .map_err(|_| anyhow!("native canonical undo commitment count exceeds u64"))?;
        let nullifier_count = u64::try_from(nullifier_count)
            .map_err(|_| anyhow!("native canonical undo nullifier count exceeds u64"))?;
        let mut undo = NativeCanonicalUndoV1 {
            schema_version: NATIVE_CANONICAL_UNDO_SCHEMA_V1,
            rules_hash: meta.rules_hash,
            height: meta.height,
            block_hash: meta.hash,
            parent_hash: meta.parent_hash,
            block_body_digest: native_in_process_verified_block_body_digest(meta)?,
            commitment_start,
            commitment_count,
            nullifier_start,
            nullifier_count,
            ciphertext_index_undo,
            record_digest: [0u8; 48],
        };
        undo.record_digest = native_canonical_undo_digest(&undo);
        Ok(undo)
    }

    fn validate_canonical_undo_for_delta(
        &self,
        undo: &NativeCanonicalUndoV1,
        delta: &NativeCanonicalBlockDelta,
    ) -> Result<()> {
        let commitment_count = u64::try_from(delta.commitment_entries.len())
            .map_err(|_| anyhow!("native canonical delta commitment count exceeds u64"))?;
        let nullifier_count = u64::try_from(delta.nullifier_append.rows.len())
            .map_err(|_| anyhow!("native canonical delta nullifier count exceeds u64"))?;
        let ciphertext_hashes_match =
            undo.ciphertext_index_undo.len() == delta.ciphertext_index_entries.len()
                && undo
                    .ciphertext_index_undo
                    .iter()
                    .zip(delta.ciphertext_index_entries.iter())
                    .all(|(undo, (hash, _))| {
                        undo.hash == *hash
                            && undo.previous.as_ref().is_none_or(|value| {
                                value.len() == NATIVE_CIPHERTEXT_INDEX_VALUE_BYTES
                            })
                    });
        if undo.schema_version != NATIVE_CANONICAL_UNDO_SCHEMA_V1
            || undo.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE
            || undo.rules_hash != delta.meta.rules_hash
            || undo.height != delta.meta.height
            || undo.block_hash != delta.meta.hash
            || undo.parent_hash != delta.meta.parent_hash
            || undo.block_body_digest != native_in_process_verified_block_body_digest(&delta.meta)?
            || undo.commitment_start != delta.commitment_start
            || undo.commitment_count != commitment_count
            || undo.nullifier_start != delta.nullifier_append.base_leaf_count
            || undo.nullifier_count != nullifier_count
            || !ciphertext_hashes_match
            || undo.record_digest != native_canonical_undo_digest(undo)
        {
            return Err(anyhow!(
                "native canonical undo identity/delta mismatch at height {} ({})",
                delta.meta.height,
                hex32(&delta.meta.hash)
            ));
        }
        Ok(())
    }

    fn load_canonical_undo_for_delta(
        &self,
        delta: &NativeCanonicalBlockDelta,
    ) -> Result<NativeCanonicalUndoV1> {
        let encoded = self
            .meta_tree
            .get(native_canonical_undo_key(&delta.meta.hash))?
            .ok_or_else(|| {
                anyhow!(
                    "missing native canonical undo at height {} ({})",
                    delta.meta.height,
                    hex32(&delta.meta.hash)
                )
            })?;
        let undo = decode_scale_exact::<NativeCanonicalUndoV1>(
            encoded.as_ref(),
            "native canonical undo record",
        )?;
        self.validate_canonical_undo_for_delta(&undo, delta)?;
        Ok(undo)
    }

    fn plan_reorg_ciphertext_index_mutations(
        &self,
        old_blocks: &[NativeCanonicalBlockDelta],
        new_blocks: &[NativeCanonicalBlockDelta],
    ) -> Result<(
        Vec<NativeCanonicalUndoV1>,
        Vec<NativeCanonicalUndoV1>,
        Vec<NativeCiphertextIndexMutation>,
    )> {
        let old_undos = old_blocks
            .iter()
            .map(|delta| self.load_canonical_undo_for_delta(delta))
            .collect::<Result<Vec<_>>>()?;
        let mut overlay = BTreeMap::<[u8; 48], Option<Vec<u8>>>::new();
        let mut mutations = Vec::new();
        for (delta, undo) in old_blocks.iter().zip(old_undos.iter()).rev() {
            for ((hash, current_value), undo_row) in delta
                .ciphertext_index_entries
                .iter()
                .zip(undo.ciphertext_index_undo.iter())
                .rev()
            {
                let observed = if let Some(observed) = overlay.get(hash) {
                    observed.clone()
                } else {
                    self.ciphertext_index_tree
                        .get(hash.as_slice())?
                        .map(|bytes| bytes.to_vec())
                };
                if undo_row.hash != *hash || observed.as_deref() != Some(current_value.as_slice()) {
                    return Err(anyhow!(
                        "native canonical ciphertext index changed before suffix rollback at height {}",
                        delta.meta.height
                    ));
                }
                mutations.push(NativeCiphertextIndexMutation {
                    hash: *hash,
                    expected: observed,
                    replacement: undo_row.previous.clone(),
                });
                overlay.insert(*hash, undo_row.previous.clone());
            }
        }

        let mut new_undos = Vec::with_capacity(new_blocks.len());
        for delta in new_blocks {
            let undo = self.canonical_undo_from_delta(delta, &mut overlay)?;
            for ((hash, replacement), undo_row) in delta
                .ciphertext_index_entries
                .iter()
                .zip(undo.ciphertext_index_undo.iter())
            {
                mutations.push(NativeCiphertextIndexMutation {
                    hash: *hash,
                    expected: undo_row.previous.clone(),
                    replacement: Some(replacement.clone()),
                });
            }
            new_undos.push(undo);
        }
        Ok((old_undos, new_undos, mutations))
    }

    fn strip_replay_only_meta_payload(meta: &mut NativeBlockMeta) {
        meta.action_bytes = Vec::new();
    }

    fn replay_stored_ancestry_with_suffix_streaming(
        &self,
        anchor_hash: [u8; 32],
        suffix: &[NativeBlockMeta],
    ) -> std::result::Result<NativeState, NativeChainLoadError> {
        self.replay_stored_ancestry_with_checkpoints_streaming(anchor_hash, suffix, None)
            .map(|replay| replay.state)
    }

    fn replay_stored_ancestry_with_checkpoints_streaming(
        &self,
        anchor_hash: [u8; 32],
        suffix: &[NativeBlockMeta],
        checkpoint_after_height: Option<u64>,
    ) -> std::result::Result<NativeVerifiedSuffixReplay, NativeChainLoadError> {
        let mut ancestry = self.compact_stored_pow_ancestry_to_hash(anchor_hash)?;
        let genesis_projection = *ancestry
            .first()
            .ok_or_else(|| anyhow!("empty native streaming replay ancestry"))?;
        let mut checkpoint_rows = Vec::new();
        let mut state = {
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            let mut genesis = self
                .header_by_hash(&genesis_projection.hash)?
                .ok_or_else(|| NativeChainLoadError::MissingAncestor {
                    hash_hex: hex32(&genesis_projection.hash),
                })?;
            if NativePowMetaProjection::from(&genesis) != genesis_projection {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "native streaming replay stored genesis changed during admission"
                )));
            }
            let expected_genesis = genesis_meta(self.config.pow_bits)?;
            if genesis != expected_genesis {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "native streaming replay genesis does not match configured genesis"
                )));
            }
            if ancestry.len() > 1 || !suffix.is_empty() {
                Self::strip_replay_only_meta_payload(&mut genesis);
            }
            Self::replay_state_from_genesis(genesis)
        };

        for index in 1..ancestry.len() {
            let projection = ancestry[index];
            let expected_pow_bits =
                self.expected_projection_child_pow_bits(&ancestry, index - 1)?;
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            let meta = self.header_by_hash(&projection.hash)?.ok_or_else(|| {
                NativeChainLoadError::MissingAncestor {
                    hash_hex: hex32(&projection.hash),
                }
            })?;
            if NativePowMetaProjection::from(&meta) != projection {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "native streaming replay stored metadata changed during admission at {}",
                    hex32(&projection.hash)
                )));
            }
            self.replay_stored_block_into_state(&mut state, meta, expected_pow_bits)?;
            if checkpoint_after_height.is_some_and(|height| projection.height > height) {
                checkpoint_rows.push(Self::canonical_checkpoint_rows(
                    &state.best,
                    &state.commitment_tree,
                    &state.nullifier_accumulator,
                    &state.header_mmr_peaks,
                )?);
            }
            if index + 1 < ancestry.len() || !suffix.is_empty() {
                Self::strip_replay_only_meta_payload(&mut state.best);
            }
        }

        for (index, meta) in suffix.iter().enumerate() {
            let parent_index = ancestry
                .len()
                .checked_sub(1)
                .ok_or_else(|| anyhow!("empty native streaming replay ancestry"))?;
            let expected_pow_bits =
                self.expected_projection_child_pow_bits(&ancestry, parent_index)?;
            self.replay_stored_block_into_state(&mut state, meta.clone(), expected_pow_bits)?;
            ancestry.push(NativePowMetaProjection::from(meta));
            if checkpoint_after_height.is_some_and(|height| meta.height > height) {
                checkpoint_rows.push(Self::canonical_checkpoint_rows(
                    &state.best,
                    &state.commitment_tree,
                    &state.nullifier_accumulator,
                    &state.header_mmr_peaks,
                )?);
            }
            if index + 1 < suffix.len() {
                Self::strip_replay_only_meta_payload(&mut state.best);
            }
        }
        Ok(NativeVerifiedSuffixReplay {
            state,
            checkpoint_rows,
        })
    }

    pub(crate) fn replay_verified_suffix_from_state(
        &self,
        mut state: NativeState,
        suffix: &[NativeBlockMeta],
    ) -> Result<NativeVerifiedSuffixReplay> {
        let mut checkpoint_rows = Vec::with_capacity(suffix.len());
        for (index, meta) in suffix.iter().enumerate() {
            if meta.parent_hash != state.best.hash
                || meta.height != state.best.height.saturating_add(1)
            {
                return Err(anyhow!(
                    "native verified suffix is not contiguous at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                ));
            }
            // A prior same-process verification is diagnostic only. The
            // replay helper unconditionally reruns the exact proofs.
            let expected_pow_bits =
                self.expected_sync_batch_child_pow_bits(&state.best, &suffix[..index])?;
            self.replay_stored_block_into_state(&mut state, meta.clone(), expected_pow_bits)?;
            checkpoint_rows.push(Self::canonical_checkpoint_rows(
                meta,
                &state.commitment_tree,
                &state.nullifier_accumulator,
                &state.header_mmr_peaks,
            )?);
        }
        Ok(NativeVerifiedSuffixReplay {
            state,
            checkpoint_rows,
        })
    }

    /// Verify and publish one bounded canonical-tip extension as a single
    /// durable transaction. The method owns the branch lock order; callers
    /// must not hold `state` while proof replay or persistence runs.
    pub(crate) fn commit_sync_tip_extension_batch(
        &self,
        metas: &[NativeBlockMeta],
    ) -> Result<usize> {
        self.ensure_native_storage_healthy()?;
        if metas.is_empty() {
            return Ok(0);
        }
        if metas.len() > MAX_NATIVE_SYNC_IMPORT_BATCH_BLOCKS {
            return Err(anyhow!(
                "native sync tip-extension batch exceeds the atomic import cap"
            ));
        }
        let (snapshot, snapshot_generation) = {
            let state = self.state.read();
            (
                Self::canonical_state_snapshot(&state),
                self.canonical_state_generation.load(Ordering::Acquire),
            )
        };
        if metas[0].parent_hash != snapshot.best.hash {
            return Err(anyhow!(
                "native sync tip-extension batch does not extend the canonical tip"
            ));
        }
        for (index, meta) in metas.iter().enumerate() {
            let expected_parent = if index == 0 {
                &snapshot.best
            } else {
                &metas[index - 1]
            };
            if meta.parent_hash != expected_parent.hash
                || meta.height != expected_parent.height.saturating_add(1)
            {
                return Err(anyhow!(
                    "native sync tip-extension batch is not contiguous at height {}",
                    meta.height
                ));
            }
            if self.classify_supplied_block_record(meta)?
                != NativeSuppliedBlockRecordStatus::Missing
            {
                return Err(anyhow!(
                    "native sync tip-extension batch includes an already stored block {}",
                    hex32(&meta.hash)
                ));
            }
        }

        let mut supplied_chain = Vec::with_capacity(metas.len().saturating_add(1));
        supplied_chain.push(snapshot.best.clone());
        supplied_chain.extend_from_slice(metas);
        self.reorganize_chain_to_best_from_snapshot(
            &snapshot,
            snapshot_generation,
            supplied_chain,
            None,
            NativeAtomicCommitKind::TipExtensionBatchCommit,
        )?;
        Ok(metas.len())
    }

    pub(crate) fn reorganize_chain_to_best(&self, new_chain: Vec<NativeBlockMeta>) -> Result<()> {
        let (snapshot, snapshot_generation) = {
            let state = self.state.read();
            (
                Self::canonical_state_snapshot(&state),
                self.canonical_state_generation.load(Ordering::Acquire),
            )
        };
        let verified_replay = if new_chain.len() > 1 {
            let (ancestor, replacement_suffix) =
                self.supplied_branch_suffix_from_canonical_ancestor(&new_chain)?;
            let base_state = self.canonical_state_at_ancestor(&snapshot, &ancestor)?;
            Some(self.replay_verified_suffix_from_state(base_state, &replacement_suffix)?)
        } else {
            None
        };
        self.reorganize_chain_to_best_from_snapshot(
            &snapshot,
            snapshot_generation,
            new_chain,
            verified_replay,
            NativeAtomicCommitKind::CanonicalSuffixReorgCommit,
        )
    }

    fn promote_stored_block_if_better_outcome(
        &self,
        block_hash: [u8; 32],
    ) -> Result<NativeStoredBlockPromotionOutcome> {
        // A verified candidate may race a sibling or tip extension after its
        // expensive proof work. Reclassify against at most two fresh snapshots:
        // persistence already guarantees the candidate is not lost if both
        // attempts race, while the bound prevents attacker-driven retry loops.
        for _ in 0..2 {
            let (snapshot, snapshot_generation) = {
                let state = self.state.read();
                (
                    Self::canonical_state_snapshot(&state),
                    self.canonical_state_generation.load(Ordering::Acquire),
                )
            };
            if snapshot.best.hash == block_hash {
                return Ok(NativeStoredBlockPromotionOutcome::AlreadyCanonical);
            }
            let target = self
                .header_by_hash(&block_hash)?
                .ok_or_else(|| anyhow!("unknown stored native block {}", hex32(&block_hash)))?;
            if !native_meta_better_than(&target, &snapshot.best) {
                return Ok(NativeStoredBlockPromotionOutcome::NotBetter);
            }
            match self.reorganize_chain_to_best_from_snapshot(
                &snapshot,
                snapshot_generation,
                vec![target],
                None,
                NativeAtomicCommitKind::CanonicalSuffixReorgCommit,
            ) {
                Ok(()) => return Ok(NativeStoredBlockPromotionOutcome::Promoted),
                Err(_)
                    if self.canonical_state_generation.load(Ordering::Acquire)
                        != snapshot_generation =>
                {
                    continue;
                }
                Err(err) => return Err(err),
            }
        }
        Ok(if self.state.read().best.hash == block_hash {
            NativeStoredBlockPromotionOutcome::AlreadyCanonical
        } else {
            NativeStoredBlockPromotionOutcome::NotBetter
        })
    }

    pub(crate) fn promote_stored_block_if_better(&self, block_hash: [u8; 32]) -> Result<bool> {
        self.promote_stored_block_if_better_outcome(block_hash)
            .map(|outcome| outcome != NativeStoredBlockPromotionOutcome::NotBetter)
    }

    /// Adopt a fully prestored branch using proof-authoritative replay and the
    /// canonical suffix transaction. `None` means a concurrent canonical
    /// advance made the target nonwinning before publication.
    pub(crate) fn reorganize_stored_chain_to_best(
        &self,
        block_hash: [u8; 32],
        prestored_block_records: usize,
    ) -> std::result::Result<Option<NativeCanonicalReorgPersistence>, NativeChainLoadError> {
        self.ensure_native_storage_healthy()
            .map_err(NativeChainLoadError::Corrupt)?;
        let (snapshot, snapshot_generation) = {
            let state = self.state.read();
            (
                Self::canonical_state_snapshot(&state),
                self.canonical_state_generation.load(Ordering::Acquire),
            )
        };
        if snapshot.best.hash == block_hash {
            return Ok(Some(NativeCanonicalReorgPersistence {
                prestored_block_records,
                canonical_transaction_block_record_writes: 0,
            }));
        }
        let ancestry = self.compact_stored_pow_ancestry_to_hash(block_hash)?;
        let tip_projection = ancestry.last().copied().ok_or_else(|| {
            NativeChainLoadError::Corrupt(anyhow!("empty native compact canonical ancestry"))
        })?;
        let target = {
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            self.load_exact_stored_meta_for_projection(
                tip_projection,
                "native compact canonical reorg target",
            )?
        };
        if target.hash != block_hash {
            return Err(NativeChainLoadError::Corrupt(anyhow!(
                "native stored reorg ancestry does not end at the requested target"
            )));
        }
        if !native_meta_better_than(&target, &snapshot.best) {
            return Ok(None);
        }
        let height_entries = ancestry
            .iter()
            .map(|meta| (meta.height, meta.hash))
            .collect::<Vec<_>>();
        self.admit_compact_stored_canonical_reorg_chain(&ancestry, &height_entries)?;
        let mut common_ancestor_index = None;
        for (index, projection) in ancestry.iter().enumerate().rev() {
            if self
                .hash_by_height(projection.height)
                .map_err(NativeChainLoadError::Corrupt)?
                == Some(projection.hash)
            {
                common_ancestor_index = Some(index);
                break;
            }
        }
        let common_ancestor_index = common_ancestor_index.ok_or_else(|| {
            NativeChainLoadError::Corrupt(anyhow!(
                "native stored reorg has no canonical common ancestor"
            ))
        })?;
        let common_ancestor = ancestry[common_ancestor_index];
        let replacement_suffix = &ancestry[common_ancestor_index.saturating_add(1)..];
        if replacement_suffix.is_empty() {
            return Ok(None);
        }
        if prestored_block_records > replacement_suffix.len() {
            return Err(NativeChainLoadError::Corrupt(anyhow!(
                "native stored reorg prestored count exceeds the replacement suffix"
            )));
        }

        let (new_action_ids, new_semantic_ids) = self
            .action_identities_from_stored_ancestry_streaming(&ancestry)
            .map_err(|error| {
                Self::local_canonical_reorg_phase_error(
                    "native canonical reorg action-identity scan",
                    error,
                )
            })?;
        let orphaned_actions = self
            .orphaned_actions_from_old_branch_suffix_compact(
                &snapshot.best,
                &ancestry,
                &new_action_ids,
                &new_semantic_ids,
            )
            .map_err(|error| {
                Self::local_canonical_reorg_phase_error("native old-branch scan", error)
            })?;
        let mut replay = self
            .replay_stored_ancestry_with_checkpoints_streaming(
                block_hash,
                &[],
                Some(common_ancestor.height),
            )
            .map_err(|error| {
                Self::local_canonical_reorg_phase_error("native canonical reorg replay", error)
            })?;
        if replay.state.best != target {
            return Err(NativeChainLoadError::Corrupt(anyhow!(
                "native canonical reorg replay did not reach the exact target"
            )));
        }
        Self::strip_replay_only_meta_payload(&mut replay.state.best);
        let canonical_index_plan = plan_canonical_index_rebuild_from_loader(
            ancestry.len().saturating_sub(1),
            |index| {
                let projection =
                    ancestry
                        .get(index.saturating_add(1))
                        .copied()
                        .ok_or_else(|| {
                            anyhow!("native compact canonical index projection out of range")
                        })?;
                #[cfg(test)]
                let _decoded_guard = self.begin_streaming_stored_meta_decode();
                self.load_exact_stored_meta_for_projection(
                    projection,
                    "native compact canonical index rebuild",
                )
                .map_err(anyhow::Error::from)
            },
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
        )
        .map_err(NativeChainLoadError::Corrupt)?;
        let (
            canonical_undos,
            undo_commitment_count,
            undo_nullifier_count,
            undo_ciphertext_index_count,
        ) = self
            .canonical_undos_from_stored_ancestry_streaming(
                &ancestry,
                common_ancestor_index.saturating_add(1),
            )
            .map_err(|error| {
                Self::local_canonical_reorg_phase_error("native canonical reorg undo scan", error)
            })?;
        let planned_commitment_count = u64::try_from(canonical_index_plan.commitment_entries.len())
            .map_err(|_| {
                NativeChainLoadError::Corrupt(anyhow!(
                    "native canonical reorg commitment plan exceeds u64"
                ))
            })?;
        let planned_nullifier_count = u64::try_from(canonical_index_plan.nullifier_entries.len())
            .map_err(|_| {
            NativeChainLoadError::Corrupt(anyhow!(
                "native canonical reorg nullifier plan exceeds u64"
            ))
        })?;
        if canonical_undos.len() != replacement_suffix.len()
            || undo_commitment_count != planned_commitment_count
            || undo_nullifier_count != planned_nullifier_count
            || undo_ciphertext_index_count != canonical_index_plan.ciphertext_index_entries.len()
        {
            return Err(NativeChainLoadError::Corrupt(anyhow!(
                "native canonical reorg undo scan does not match the rebuilt canonical indexes"
            )));
        }
        let poseidon2_v8_reorg = self
            .plan_poseidon2_v8_stored_reorganization_streaming(
                &snapshot.best,
                &ancestry,
                common_ancestor_index,
                &[],
            )
            .map_err(NativeChainLoadError::Corrupt)?;

        let persistence_epoch = self.pending_action_persistence_lock.lock();
        let block_store_epoch = self.block_store_persistence_lock.lock();
        let canonical_import_guard = self.canonical_import_lock.lock();
        let (pending_generation, mut pending) = {
            let state = self.state.read();
            if !self.canonical_state_matches_snapshot(&state, &snapshot, snapshot_generation)
                || !native_meta_better_than(&target, &state.best)
            {
                return Ok(None);
            }
            replay.state.staged_ciphertexts = state.staged_ciphertexts.clone();
            replay.state.staged_proofs = state.staged_proofs.clone();
            replay.state.stablecoin_policy_authorizations =
                state.stablecoin_policy_authorizations.clone();
            (
                self.pending_action_generation.load(Ordering::Acquire),
                state.pending_actions.clone(),
            )
        };
        drop(canonical_import_guard);

        for action_id in &new_action_ids {
            pending.remove(action_id);
        }
        pending
            .retain(|_, action| !new_semantic_ids.contains(&pending_action_semantic_hash(action)));
        let staged_ciphertext_removals = self
            .staged_ciphertext_removals_from_stored_ancestry_streaming(
                replacement_suffix,
                &mut replay.state,
            )
            .map_err(|error| {
                Self::local_canonical_reorg_phase_error(
                    "native canonical reorg staged-removal scan",
                    error,
                )
            })?;
        pending = revalidate_reorg_pending_actions(&replay.state, pending, orphaned_actions);
        let pending_entries = pending
            .values()
            .map(|action| (action.tx_hash, action.encode()))
            .collect::<Vec<_>>();
        replace_pending_actions_in_state(&mut replay.state, pending)
            .map_err(NativeChainLoadError::Corrupt)?;
        replay.state.best = {
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            self.load_exact_stored_meta_for_projection(
                tip_projection,
                "native compact canonical reorg final tip",
            )?
        };

        let known_block_count = ancestry.len().saturating_sub(prestored_block_records);
        evaluate_native_canonical_reorg_persistence_admission(
            NativeCanonicalReorgPersistenceAdmissionInput {
                replacement_block_count: ancestry.len(),
                known_block_count,
                classified_missing_block_count: prestored_block_records,
                supplied_missing_block_count: prestored_block_records,
                connected_exact_known_rows: true,
                suffix_fully_validated: true,
                noncanonical_batch_block_record_writes: prestored_block_records,
                noncanonical_batch_durability_flushed: true,
                durable_records_match_replacement: true,
                canonical_transaction_block_record_writes: 0,
            },
        )
        .map_err(|rejection| {
            NativeChainLoadError::Corrupt(anyhow!(
                "native canonical reorg persistence admission: {rejection:?}"
            ))
        })?;
        let v8_plan = poseidon2_v8_reorg.as_ref().map(|(_, plan)| plan);
        self.commit_reorg_state_atomically(
            canonical_index_plan,
            &height_entries,
            &replay.checkpoint_rows,
            &canonical_undos,
            &pending_entries,
            &replay.state.best,
            &staged_ciphertext_removals,
            v8_plan,
        )
        .map_err(NativeChainLoadError::Corrupt)?;
        if let Err(error) = self.flush_native_durability_barrier(
            "native compact canonical reorg commit",
            NativeStorageDurabilityOperation::CanonicalReorgCommit,
        ) {
            self.poison_native_storage();
            return Err(NativeChainLoadError::Corrupt(error.context(
                "native stored reorg durability is uncertain; storage fail-stop engaged",
            )));
        }
        let readback_error = self
            .verify_persisted_canonical_head(
                &replay.state.best,
                "native compact canonical reorg commit",
            )
            .err()
            .or_else(|| {
                poseidon2_v8_reorg.as_ref().and_then(|(store, plan)| {
                    store
                        .verify_canonical_plan_readback(plan)
                        .map_err(|error| anyhow!("native V8 stored reorg readback failed: {error}"))
                        .err()
                })
            });
        let publication_revalidation_error = {
            let mut state = self.state.write();
            let changed =
                !self.canonical_state_matches_snapshot(&state, &snapshot, snapshot_generation)
                    || self.pending_action_generation.load(Ordering::Acquire) != pending_generation;
            replay.state.staged_ciphertexts = state.staged_ciphertexts.clone();
            for hash in &staged_ciphertext_removals {
                replay.state.staged_ciphertexts.remove(&hex48(hash));
            }
            replay.state.staged_proofs = state.staged_proofs.clone();
            replay.state.stablecoin_policy_authorizations =
                state.stablecoin_policy_authorizations.clone();
            publish_reorganized_state(&mut state, replay.state);
            self.canonical_state_generation
                .fetch_add(1, Ordering::Release);
            self.pending_action_generation
                .fetch_add(1, Ordering::Release);
            changed.then_some(
                "native canonical state changed after durable stored reorg commit; durable state was published and storage fail-stop engaged",
            )
        };
        drop(block_store_epoch);
        drop(persistence_epoch);
        if let Some(message) = publication_revalidation_error {
            self.poison_native_storage();
            return Err(NativeChainLoadError::Corrupt(anyhow!(message)));
        }
        if let Some(error) = readback_error {
            self.poison_native_storage();
            return Err(NativeChainLoadError::Corrupt(error.context(
                "native stored reorg committed and published but readback failed; storage fail-stop engaged",
            )));
        }
        Ok(Some(NativeCanonicalReorgPersistence {
            prestored_block_records,
            canonical_transaction_block_record_writes: 0,
        }))
    }

    fn reorganize_chain_to_best_from_snapshot(
        &self,
        snapshot: &NativeState,
        snapshot_generation: u64,
        new_chain: Vec<NativeBlockMeta>,
        verified_replay: Option<NativeVerifiedSuffixReplay>,
        commit_kind: NativeAtomicCommitKind,
    ) -> Result<()> {
        if !matches!(
            commit_kind,
            NativeAtomicCommitKind::TipExtensionBatchCommit
                | NativeAtomicCommitKind::CanonicalSuffixReorgCommit
        ) {
            return Err(anyhow!("invalid native canonical suffix commit kind"));
        }
        self.ensure_native_storage_healthy()?;
        let target = new_chain
            .last()
            .cloned()
            .ok_or_else(|| anyhow!("empty native reorg target"))?;
        if !native_meta_better_than(&target, &snapshot.best) {
            return Err(anyhow!(
                "native reorg target does not beat the canonical tip"
            ));
        }
        // A sync caller may supply a validated contiguous prefix whose rows do
        // not exist locally yet. Other hot paths pass only a stored target and
        // retain O(fork-depth) backwards traversal.
        let (ancestor, new_suffix) = if new_chain.len() > 1 {
            self.supplied_branch_suffix_from_canonical_ancestor(&new_chain)?
        } else {
            self.stored_branch_suffix_from_canonical_ancestor(&target)?
        };
        if new_suffix.is_empty() {
            return Err(anyhow!("native reorg target is already canonical"));
        }
        let first_orphan_height = ancestor
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow!("native reorg ancestor height overflow"))?;
        let old_suffix = (first_orphan_height..=snapshot.best.height)
            .map(|height| self.load_canonical_block_at_height_unverified(height))
            .collect::<Result<Vec<_>>>()?;
        if old_suffix.is_empty() && ancestor.hash != snapshot.best.hash {
            return Err(anyhow!(
                "native canonical suffix has no orphaned rows but does not extend the tip"
            ));
        }
        for (offset, meta) in new_suffix.iter().enumerate() {
            let expected_parent = if offset == 0 {
                &ancestor
            } else {
                &new_suffix[offset - 1]
            };
            if meta.height != expected_parent.height.saturating_add(1)
                || meta.parent_hash != expected_parent.hash
                || meta.chain_id != HEGEMON_CHAIN_ID_V1
                || meta.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE
                || meta.hash != meta.work_hash
            {
                return Err(anyhow!(
                    "native reorg replacement suffix metadata mismatch at height {}",
                    meta.height
                ));
            }
        }
        let base_state = self.canonical_state_at_ancestor(snapshot, &ancestor)?;

        let NativeVerifiedSuffixReplay {
            state: mut new_state,
            checkpoint_rows,
        } = match verified_replay {
            Some(replay) => replay,
            None => self.replay_verified_suffix_from_state(base_state.clone(), &new_suffix)?,
        };
        if new_state.best != target {
            return Err(anyhow!(
                "native verified suffix replay tip does not match reorg target"
            ));
        }
        let old_blocks = self.plan_canonical_suffix_deltas(&base_state, &old_suffix)?;
        let new_blocks = self.plan_canonical_suffix_deltas(&base_state, &new_suffix)?;
        let old_tip_accumulator = old_blocks
            .last()
            .map(|delta| &delta.nullifier_append.next_accumulator)
            .unwrap_or(&base_state.nullifier_accumulator);
        let new_tip_accumulator = new_blocks
            .last()
            .map(|delta| &delta.nullifier_append.next_accumulator)
            .unwrap_or(&base_state.nullifier_accumulator);
        let old_tip_commitment_count = old_blocks
            .last()
            .map(|delta| {
                delta
                    .commitment_start
                    .checked_add(u64::try_from(delta.commitment_entries.len()).unwrap_or(u64::MAX))
                    .unwrap_or(u64::MAX)
            })
            .unwrap_or_else(|| base_state.commitment_tree.leaf_count());
        let new_tip_commitment_count = new_blocks
            .last()
            .map(|delta| {
                delta
                    .commitment_start
                    .checked_add(u64::try_from(delta.commitment_entries.len()).unwrap_or(u64::MAX))
                    .unwrap_or(u64::MAX)
            })
            .unwrap_or_else(|| base_state.commitment_tree.leaf_count());
        if old_tip_accumulator != &snapshot.nullifier_accumulator
            || new_tip_accumulator != &new_state.nullifier_accumulator
            || old_tip_commitment_count != snapshot.commitment_tree.leaf_count()
            || new_tip_commitment_count != new_state.commitment_tree.leaf_count()
        {
            return Err(anyhow!(
                "native reorg suffix delta frontiers do not match old/new canonical state"
            ));
        }
        // Historical replay above deliberately excludes the V8 verifier so it
        // can rebuild legacy state independently of the typed V8 store. Finish
        // exact V8 proof and state-transition planning here, before any
        // supplied suffix row can be durably prestored. The resulting typed
        // plan is reused by the canonical transaction below.
        let poseidon2_v8_reorg = self.plan_poseidon2_v8_reorganization(&old_blocks, &new_blocks)?;
        let new_action_hashes = new_blocks
            .iter()
            .flat_map(|delta| delta.actions.iter().map(|action| action.tx_hash))
            .collect::<BTreeSet<_>>();
        let new_action_semantic_hashes = new_blocks
            .iter()
            .flat_map(|delta| delta.actions.iter().map(pending_action_semantic_hash))
            .collect::<BTreeSet<_>>();
        let decoded_action_ids = new_blocks
            .iter()
            .flat_map(|delta| delta.actions.iter().map(|action| action.tx_hash))
            .collect::<Vec<_>>();
        if decoded_action_ids.len() != new_action_hashes.len() {
            return Err(anyhow!(
                "native canonical suffix contains a duplicate action identity"
            ));
        }
        let orphaned = old_blocks
            .iter()
            .flat_map(|delta| delta.actions.iter())
            .filter(|action| {
                !new_action_hashes.contains(&action.tx_hash)
                    && !new_action_semantic_hashes.contains(&pending_action_semantic_hash(action))
            })
            .cloned()
            .collect::<Vec<_>>();
        let staged_ciphertext_removals = new_blocks
            .iter()
            .flat_map(|delta| delta.actions.iter())
            .filter(|action| owns_legacy_ciphertext_da_rows(action))
            .flat_map(|action| action.ciphertext_hashes.iter().copied())
            .collect::<Vec<_>>();

        // Canonical/action-tree writers take pending epoch -> block-store epoch
        // -> canonical serialization -> short state. The canonical guard is
        // released before sled I/O; only the epochs span durable mutation and
        // RAM publication, so unrelated state readers/writers remain live.
        let persistence_epoch = self.pending_action_persistence_lock.lock();
        let block_store_epoch = self.block_store_persistence_lock.lock();
        let canonical_import_guard = self.canonical_import_lock.lock();
        let (pending_generation, current_pending, mut pending) = {
            let state = self.state.read();
            if !self.canonical_state_matches_snapshot(&state, snapshot, snapshot_generation) {
                return Err(anyhow!(
                    "native canonical state changed during reorg validation"
                ));
            }
            new_state.staged_ciphertexts = state.staged_ciphertexts.clone();
            new_state.staged_proofs = state.staged_proofs.clone();
            new_state.stablecoin_policy_authorizations =
                state.stablecoin_policy_authorizations.clone();
            (
                self.pending_action_generation.load(Ordering::Acquire),
                state.pending_actions.clone(),
                state.pending_actions.clone(),
            )
        };
        drop(canonical_import_guard);
        for hash in &new_action_hashes {
            pending.remove(hash);
        }
        pending.retain(|_, action| {
            !new_action_semantic_hashes.contains(&pending_action_semantic_hash(action))
        });
        for delta in &new_blocks {
            for action in &delta.actions {
                clear_staged_ciphertext_markers(&mut new_state, action);
            }
        }
        if commit_kind == NativeAtomicCommitKind::CanonicalSuffixReorgCommit {
            pending = revalidate_reorg_pending_actions(&new_state, pending, orphaned);
        } else if !orphaned.is_empty() {
            return Err(anyhow!(
                "native tip-extension batch unexpectedly contains orphaned actions"
            ));
        }
        let next_pending_entries = pending
            .values()
            .map(|action| (action.tx_hash, action.encode()))
            .collect::<BTreeMap<_, _>>();
        let current_pending_entries = current_pending
            .values()
            .map(|action| (action.tx_hash, action.encode()))
            .collect::<BTreeMap<_, _>>();
        let pending_removals = current_pending_entries
            .iter()
            .filter(|(hash, encoded)| next_pending_entries.get(hash) != Some(*encoded))
            .map(|(hash, encoded)| (*hash, encoded.clone()))
            .collect::<Vec<_>>();
        let pending_upserts = next_pending_entries
            .iter()
            .filter(|(hash, encoded)| current_pending_entries.get(hash) != Some(*encoded))
            .map(|(hash, encoded)| (*hash, encoded.clone()))
            .collect::<Vec<_>>();
        let (pending_removals, pending_upserts, tip_action_removals) = match commit_kind {
            NativeAtomicCommitKind::TipExtensionBatchCommit => {
                if !pending_upserts.is_empty()
                    || pending_removals
                        .iter()
                        .any(|(hash, _)| !new_action_hashes.contains(hash))
                {
                    return Err(anyhow!(
                        "native tip-extension batch changed pending rows outside its decoded actions"
                    ));
                }
                (Vec::new(), Vec::new(), decoded_action_ids)
            }
            NativeAtomicCommitKind::CanonicalSuffixReorgCommit => {
                (pending_removals, pending_upserts, Vec::new())
            }
            _ => return Err(anyhow!("invalid native canonical suffix commit kind")),
        };
        replace_pending_actions_in_state(&mut new_state, pending)?;
        let (old_undos, new_undos, ciphertext_index_mutations) =
            self.plan_reorg_ciphertext_index_mutations(&old_blocks, &new_blocks)?;
        let commit_plan = NativeReorgSuffixCommitPlan {
            old_blocks,
            new_blocks,
            old_undos,
            new_undos,
            ciphertext_index_mutations,
            pending_removals,
            pending_upserts,
            tip_action_removals,
            staged_ciphertext_removals,
            checkpoint_rows,
        };
        if commit_kind == NativeAtomicCommitKind::CanonicalSuffixReorgCommit {
            // Canonical suffix transactions only compare content-addressed
            // block records. Exact legacy and V8 verification has completed;
            // under the existing pending -> block-store epoch order, prestore
            // only missing rows as one separately flushed noncanonical batch.
            let mut missing = Vec::new();
            for delta in &commit_plan.new_blocks {
                if self.classify_supplied_block_record(&delta.meta)?
                    == NativeSuppliedBlockRecordStatus::Missing
                {
                    missing.push(&delta.meta);
                }
            }
            self.persist_validated_noncanonical_block_record_ref_batch(
                &missing,
                "native canonical reorg candidate block-record batch manifest",
                "native canonical reorg candidate block-record batch",
            )?;
        }
        self.commit_reorg_suffix_atomically(
            &commit_plan,
            &new_state.best,
            &new_state.nullifier_accumulator,
            poseidon2_v8_reorg,
            commit_kind,
        )?;
        if let Err(err) = self.flush_native_durability_barrier(
            "native canonical reorg commit",
            NativeStorageDurabilityOperation::CanonicalReorgCommit,
        ) {
            self.poison_native_storage();
            return Err(
                err.context("native reorg durability is uncertain; storage fail-stop engaged")
            );
        }
        let readback_error = self
            .verify_persisted_canonical_head(&new_state.best, "native canonical reorg commit")
            .err();

        let publication_revalidation_error = {
            let mut state = self.state.write();
            let changed =
                !self.canonical_state_matches_snapshot(&state, snapshot, snapshot_generation)
                    || self.pending_action_generation.load(Ordering::Acquire) != pending_generation;
            new_state.staged_ciphertexts = state.staged_ciphertexts.clone();
            for hash in &commit_plan.staged_ciphertext_removals {
                new_state.staged_ciphertexts.remove(&hex48(hash));
            }
            new_state.staged_proofs = state.staged_proofs.clone();
            new_state.stablecoin_policy_authorizations =
                state.stablecoin_policy_authorizations.clone();
            publish_reorganized_state(&mut state, new_state);
            self.canonical_state_generation
                .fetch_add(1, Ordering::Release);
            self.pending_action_generation
                .fetch_add(1, Ordering::Release);
            changed.then_some(
                "native canonical state changed after durable reorg commit; durable state was published and storage fail-stop engaged",
            )
        };
        drop(block_store_epoch);
        drop(persistence_epoch);
        if let Some(publication_revalidation_error) = publication_revalidation_error {
            self.poison_native_storage();
            return Err(anyhow!(publication_revalidation_error));
        }
        if let Some(readback_error) = readback_error {
            self.poison_native_storage();
            return Err(readback_error.context(
                "native reorg committed and published but readback failed; storage fail-stop engaged",
            ));
        }
        Ok(())
    }

    pub(crate) fn prune_invalid_pending_actions_after_state_advance(
        &self,
        state: &mut NativeState,
        context: &'static str,
    ) -> Result<Vec<ActionId48>> {
        if state.pending_actions.is_empty() {
            return Ok(Vec::new());
        }

        let original_pending = std::mem::take(&mut state.pending_actions);
        replace_pending_actions_in_state(state, BTreeMap::new())?;
        let original_hashes = original_pending.keys().copied().collect::<BTreeSet<_>>();
        let retained = revalidate_pending_actions_after_state_advance(state, original_pending);
        let retained_hashes = retained.keys().copied().collect::<BTreeSet<_>>();
        let mut dropped = original_hashes
            .difference(&retained_hashes)
            .copied()
            .collect::<BTreeSet<_>>();
        replace_pending_actions_in_state(state, retained)?;
        if self.config.miner_address.is_some() {
            let pending_before_coinbase_prune =
                state.pending_actions.keys().copied().collect::<Vec<_>>();
            prune_auto_coinbase_actions_from_pending(state, context);
            for hash in pending_before_coinbase_prune {
                if !state.pending_actions.contains_key(&hash) {
                    dropped.insert(hash);
                }
            }
        }

        let dropped = dropped.into_iter().collect::<Vec<_>>();
        if !dropped.is_empty() {
            info!(
                context,
                dropped_count = dropped.len(),
                "planned native pending-action prune with canonical state advance"
            );
        }
        Ok(dropped)
    }

    fn commit_reorg_suffix_atomically(
        &self,
        plan: &NativeReorgSuffixCommitPlan,
        best: &NativeBlockMeta,
        next_nullifier_accumulator: &NullifierAccumulator,
        poseidon2_v8_reorg: Option<(
            poseidon2_v8_state::Poseidon2V8StateStore,
            poseidon2_v8_state::Poseidon2V8CanonicalPlan,
        )>,
        commit_kind: NativeAtomicCommitKind,
    ) -> Result<()> {
        if plan.old_blocks.len() != plan.old_undos.len()
            || plan.new_blocks.len() != plan.new_undos.len()
            || plan.new_blocks.last().map(|delta| &delta.meta) != Some(best)
            || next_nullifier_accumulator.root() != best.nullifier_root
        {
            ::core::result::Result::<(), anyhow::Error>::Err((|| {
                anyhow!("native canonical suffix commit plan shape mismatch")
            })())?;
        }
        for (delta, undo) in plan.old_blocks.iter().zip(plan.old_undos.iter()) {
            self.validate_canonical_undo_for_delta(undo, delta)?;
        }
        for (delta, undo) in plan.new_blocks.iter().zip(plan.new_undos.iter()) {
            self.validate_canonical_undo_for_delta(undo, delta)?;
        }

        let new_block_metas = plan
            .new_blocks
            .iter()
            .map(|delta| (delta.meta.hash, &delta.meta))
            .collect::<BTreeMap<_, _>>();
        let mut checkpoint_keys = BTreeSet::new();
        let mut verified_keys = BTreeSet::new();
        let mut best_checkpoint_present = false;
        for (checkpoint_key, checkpoint_value, verified_key, verified_value) in
            &plan.checkpoint_rows
        {
            let checkpoint = decode_scale_exact::<NativeCanonicalStateCheckpointV1>(
                checkpoint_value,
                "native reorg suffix canonical checkpoint row",
            )?;
            let meta = new_block_metas.get(&checkpoint.block_hash).ok_or_else(|| {
                anyhow!(
                    "native reorg suffix checkpoint references an uncommitted block {}",
                    hex32(&checkpoint.block_hash)
                )
            })?;
            validate_native_canonical_state_checkpoint(&checkpoint, meta)?;
            if checkpoint_key.as_slice()
                != native_canonical_state_checkpoint_key(&checkpoint.block_hash)
                || verified_key.as_slice()
                    != native_verified_block_record_key(&checkpoint.block_hash)
                || verified_value.as_slice() != native_verified_block_body_digest(meta)?.as_slice()
                || !checkpoint_keys.insert(checkpoint_key.clone())
                || !verified_keys.insert(verified_key.clone())
            {
                ::core::result::Result::<(), anyhow::Error>::Err((|| {
                    anyhow!("native reorg suffix checkpoint/verified row identity mismatch")
                })())?;
            }
            best_checkpoint_present |= checkpoint.block_hash == best.hash;
        }
        if best.height > 0 && !best_checkpoint_present {
            ::core::result::Result::<(), anyhow::Error>::Err((|| {
                anyhow!("native reorg suffix commit is missing the best-state checkpoint")
            })())?;
        }

        let v8_plan = poseidon2_v8_reorg.as_ref().map(|(_, v8_plan)| v8_plan);
        let suffix_manifest = match commit_kind {
            NativeAtomicCommitKind::TipExtensionBatchCommit => {
                self::native_tip_extension_batch_commit_manifest(plan, v8_plan)?
            }
            NativeAtomicCommitKind::CanonicalSuffixReorgCommit => {
                if !plan.tip_action_removals.is_empty() {
                    return Err(anyhow!(
                        "native stored reorg commit contains tip-extension removals"
                    ));
                }
                self::native_canonical_suffix_reorg_commit_manifest(plan, v8_plan)?
            }
            _ => return Err(anyhow!("invalid native canonical suffix commit kind")),
        };
        let best_record = bincode::serialize(best)?;
        let nullifier_accumulator_record = next_nullifier_accumulator
            .encode()
            .map_err(|err| anyhow!("encode reorg suffix nullifier accumulator failed: {err}"))?;
        self::__hegemon_pinned_sled::transaction::Transactional::transaction(
            &(
                &self.meta_tree,
                &self.height_tree,
                &self.block_tree,
                &self.commitment_tree,
                &self.nullifier_tree,
                &self.bridge_inbound_tree,
                &self.ciphertext_index_tree,
                &self.ciphertext_archive_tree,
                &self.da_ciphertext_tree,
                &self.action_tree,
                &self.poseidon2_v8_tree,
            ),
            |(
                    meta_tree,
                    height_tree,
                    block_tree,
                    commitment_tree,
                    nullifier_tree,
                    bridge_inbound_tree,
                    ciphertext_index_tree,
                    ciphertext_archive_tree,
                    da_ciphertext_tree,
                    action_tree,
                    poseidon2_v8_tree,
                )| {
                    self::apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction(
                        poseidon2_v8_tree,
                        poseidon2_v8_reorg
                            .as_ref()
                            .map(|(_, v8_plan)| v8_plan),
                        suffix_manifest,
                        "native canonical suffix reorg manifest",
                    )?;
                    for delta in &plan.old_blocks {
                        let height_key_bytes = height_key(delta.meta.height);
                        if height_tree.get(height_key_bytes.as_slice())?.as_deref()
                            != Some(delta.meta.hash.as_slice())
                        {
                            return Err(
                                sled::transaction::ConflictableTransactionError::Abort(format!(
                                    "canonical height row changed before suffix rollback at {}",
                                    delta.meta.height
                                )),
                            );
                        }
                        height_tree.remove(height_key_bytes.to_vec())?;
                        for (index, commitment) in &delta.commitment_entries {
                            let key = index.to_be_bytes();
                            if commitment_tree.get(key.as_slice())?.as_deref()
                                != Some(commitment.as_slice())
                            {
                                return Err(sled::transaction::ConflictableTransactionError::Abort(
                                    format!(
                                        "canonical commitment row changed before suffix rollback at index {index}"
                                    ),
                                ));
                            }
                            commitment_tree.remove(key.to_vec())?;
                        }
                        for (index, bytes) in &delta.ciphertext_archive_entries {
                            let key = index.to_be_bytes();
                            if ciphertext_archive_tree.get(key.as_slice())?.as_deref()
                                != Some(bytes.as_slice())
                            {
                                return Err(sled::transaction::ConflictableTransactionError::Abort(
                                    format!(
                                        "canonical ciphertext archive changed before suffix rollback at index {index}"
                                    ),
                                ));
                            }
                            ciphertext_archive_tree.remove(key.to_vec())?;
                        }
                        for (index, nullifier) in &delta.nullifier_append.rows {
                            if nullifier_tree.get(nullifier.as_slice())?.as_deref()
                                != Some(index.to_be_bytes().as_slice())
                            {
                                return Err(sled::transaction::ConflictableTransactionError::Abort(
                                    "canonical nullifier row changed before suffix rollback"
                                        .to_string(),
                                ));
                            }
                            nullifier_tree.remove(nullifier.to_vec())?;
                        }
                        for replay_key in &delta.bridge_replay_entries {
                            if bridge_inbound_tree.get(replay_key.as_slice())?.as_deref()
                                != Some(b"1".as_slice())
                            {
                                return Err(sled::transaction::ConflictableTransactionError::Abort(
                                    "canonical bridge replay row changed before suffix rollback"
                                        .to_string(),
                                ));
                            }
                            bridge_inbound_tree.remove(replay_key.to_vec())?;
                        }
                    }

                    for mutation in &plan.ciphertext_index_mutations {
                        let observed = ciphertext_index_tree
                            .get(mutation.hash.as_slice())?
                            .map(|bytes| bytes.to_vec());
                        if observed != mutation.expected {
                            return Err(sled::transaction::ConflictableTransactionError::Abort(
                                "canonical ciphertext index changed during suffix delta"
                                    .to_string(),
                            ));
                        }
                        match &mutation.replacement {
                            Some(replacement) => {
                                ciphertext_index_tree
                                    .insert(mutation.hash.to_vec(), replacement.clone())?;
                            }
                            None => {
                                ciphertext_index_tree.remove(mutation.hash.to_vec())?;
                            }
                        }
                    }

                    for delta in &plan.new_blocks {
                        let stored = block_tree.get(delta.meta.hash.as_slice())?;
                        match (commit_kind, stored) {
                            (NativeAtomicCommitKind::TipExtensionBatchCommit, None) => {
                                block_tree.insert(delta.meta.hash.to_vec(), delta.encoded.clone())?;
                            }
                            (
                                NativeAtomicCommitKind::CanonicalSuffixReorgCommit,
                                Some(current),
                            ) if current.as_ref() == delta.encoded.as_slice() => {}
                            (NativeAtomicCommitKind::TipExtensionBatchCommit, Some(_)) => {
                                return Err(sled::transaction::ConflictableTransactionError::Abort(
                                    "native tip-extension block became stored before atomic commit"
                                        .to_string(),
                                ));
                            }
                            (NativeAtomicCommitKind::CanonicalSuffixReorgCommit, None) => {
                                return Err(sled::transaction::ConflictableTransactionError::Abort(
                                    "native stored reorg replacement is not durably prestored"
                                        .to_string(),
                                ));
                            }
                            (NativeAtomicCommitKind::CanonicalSuffixReorgCommit, Some(_)) => {
                                return Err(sled::transaction::ConflictableTransactionError::Abort(
                                    "native stored reorg block body changed before canonical commit"
                                        .to_string(),
                                ));
                            }
                            _ => {
                                return Err(sled::transaction::ConflictableTransactionError::Abort(
                                    "invalid native canonical suffix commit kind".to_string(),
                                ));
                            }
                        }
                        let height_key_bytes = height_key(delta.meta.height);
                        if height_tree.get(height_key_bytes.as_slice())?.is_some() {
                            return Err(sled::transaction::ConflictableTransactionError::Abort(
                                "native reorg height row survived suffix rollback".to_string(),
                            ));
                        }
                        height_tree.insert(height_key_bytes.to_vec(), delta.meta.hash.to_vec())?;
                        for (index, commitment) in &delta.commitment_entries {
                            let key = index.to_be_bytes();
                            if commitment_tree.get(key.as_slice())?.is_some() {
                                return Err(sled::transaction::ConflictableTransactionError::Abort(
                                    "native reorg commitment index survived suffix rollback"
                                        .to_string(),
                                ));
                            }
                            commitment_tree.insert(key.to_vec(), commitment.to_vec())?;
                        }
                        for (index, bytes) in &delta.ciphertext_archive_entries {
                            let key = index.to_be_bytes();
                            if ciphertext_archive_tree.get(key.as_slice())?.is_some() {
                                return Err(sled::transaction::ConflictableTransactionError::Abort(
                                    "native reorg ciphertext archive index survived suffix rollback"
                                        .to_string(),
                                ));
                            }
                            ciphertext_archive_tree.insert(key.to_vec(), bytes.clone())?;
                        }
                        for (index, nullifier) in &delta.nullifier_append.rows {
                            if nullifier_tree.get(nullifier.as_slice())?.is_some() {
                                return Err(sled::transaction::ConflictableTransactionError::Abort(
                                    "native reorg nullifier survived suffix rollback".to_string(),
                                ));
                            }
                            nullifier_tree
                                .insert(nullifier.to_vec(), index.to_be_bytes().to_vec())?;
                        }
                        for replay_key in &delta.bridge_replay_entries {
                            if bridge_inbound_tree.get(replay_key.as_slice())?.is_some() {
                                return Err(sled::transaction::ConflictableTransactionError::Abort(
                                    "native reorg bridge replay survived suffix rollback"
                                        .to_string(),
                                ));
                            }
                            bridge_inbound_tree.insert(replay_key.to_vec(), b"1".to_vec())?;
                        }
                        meta_tree.remove(native_noncanonical_fork_key(&delta.meta.hash))?;
                    }

                    for (hash, expected) in &plan.pending_removals {
                        if action_tree.get(hash.as_ref())?.as_deref()
                            != Some(expected.as_slice())
                        {
                            return Err(sled::transaction::ConflictableTransactionError::Abort(
                                "pending action changed before reorg suffix removal".to_string(),
                            ));
                        }
                        action_tree.remove(hash.as_bytes().to_vec())?;
                    }
                    for hash in &plan.tip_action_removals {
                        action_tree.remove(hash.as_bytes().to_vec())?;
                    }
                    for (hash, encoded) in &plan.pending_upserts {
                        match action_tree.get(hash.as_ref())? {
                            Some(current) if current.as_ref() == encoded.as_slice() => {}
                            Some(_) => {
                                return Err(sled::transaction::ConflictableTransactionError::Abort(
                                    "pending action changed before reorg suffix upsert".to_string(),
                                ));
                            }
                            None => {
                                action_tree.insert(hash.as_bytes().to_vec(), encoded.clone())?;
                            }
                        }
                    }
                    for hash in &plan.staged_ciphertext_removals {
                        da_ciphertext_tree.remove(hash.to_vec())?;
                    }
                    meta_tree.insert(META_BEST_KEY.to_vec(), best_record.clone())?;
                    meta_tree.insert(
                        META_NULLIFIER_ACCUMULATOR_KEY.to_vec(),
                        nullifier_accumulator_record.clone(),
                    )?;
                    for (checkpoint_key, checkpoint_value, verified_key, verified_value) in
                        &plan.checkpoint_rows
                    {
                        meta_tree.insert(checkpoint_key.clone(), checkpoint_value.clone())?;
                        meta_tree.insert(verified_key.clone(), verified_value.clone())?;
                    }
                    for (delta, undo) in plan.new_blocks.iter().zip(plan.new_undos.iter()) {
                        meta_tree.insert(native_canonical_undo_key(&delta.meta.hash), undo.encode())?;
                    }
                Ok(())
            },
        )
            .map_err(|err| anyhow!("atomic native reorg suffix commit failed: {err}"))?;
        if let Some((store, v8_plan)) = poseidon2_v8_reorg {
            store
                .verify_canonical_plan_readback(&v8_plan)
                .map_err(|error| anyhow!("native V8 reorg commit readback failed: {error}"))?;
        }
        #[cfg(test)]
        {
            let row_mutations = plan
                .old_blocks
                .iter()
                .chain(plan.new_blocks.iter())
                .map(|delta| {
                    1usize
                        + delta.commitment_entries.len()
                        + delta.ciphertext_archive_entries.len()
                        + delta.nullifier_append.rows.len()
                        + delta.bridge_replay_entries.len()
                })
                .sum::<usize>()
                .saturating_add(plan.ciphertext_index_mutations.len())
                .saturating_add(plan.pending_removals.len())
                .saturating_add(plan.tip_action_removals.len())
                .saturating_add(plan.pending_upserts.len());
            self.reorg_index_mutations.fetch_add(
                u64::try_from(row_mutations).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        Ok(())
    }

    pub(crate) fn commit_reorg_state_atomically(
        &self,
        canonical_index_plan: NativeCanonicalIndexPlan,
        height_entries: &[(u64, [u8; 32])],
        checkpoint_rows: &[NativeCanonicalCheckpointRows],
        canonical_undos: &[NativeCanonicalUndoV1],
        pending_entries: &[(ActionId48, Vec<u8>)],
        best: &NativeBlockMeta,
        staged_ciphertext_removals: &[[u8; 48]],
        poseidon2_v8_plan: Option<&poseidon2_v8_state::Poseidon2V8CanonicalPlan>,
    ) -> Result<()> {
        let mut planned_nullifier_keys = PersistentKeySet48::new();
        if canonical_index_plan
            .nullifier_entries
            .iter()
            .any(|(_, nullifier)| !planned_nullifier_keys.insert(*nullifier))
        {
            return Err(anyhow!(
                "native reorg nullifier index contains a duplicate key"
            ));
        }
        let planned_nullifier_accumulator =
            NullifierAccumulator::from_indexed_rows(&canonical_index_plan.nullifier_entries)
                .map_err(|err| anyhow!("rebuild reorg nullifier accumulator failed: {err}"))?;
        if planned_nullifier_accumulator.root() != best.nullifier_root {
            return Err(anyhow!(
                "native reorg nullifier accumulator does not match best metadata"
            ));
        }
        let nullifier_accumulator_record = planned_nullifier_accumulator
            .encode()
            .map_err(|err| anyhow!("encode reorg nullifier accumulator failed: {err}"))?;
        let height_keys = collect_tree_keys(&self.height_tree, "native height")?;
        let commitment_keys = collect_tree_keys(&self.commitment_tree, "native commitment")?;
        let nullifier_keys = collect_tree_keys(&self.nullifier_tree, "native nullifier")?;
        let bridge_replay_keys =
            collect_tree_keys(&self.bridge_inbound_tree, "native bridge replay")?;
        let ciphertext_index_keys =
            collect_tree_keys(&self.ciphertext_index_tree, "native ciphertext index")?;
        let ciphertext_archive_keys =
            collect_tree_keys(&self.ciphertext_archive_tree, "native ciphertext archive")?;
        let action_keys = collect_tree_keys(&self.action_tree, "native pending action")?;
        let best_record = bincode::serialize(best)?;
        let mut checkpoint_keys = BTreeSet::new();
        let mut verified_keys = BTreeSet::new();
        let mut checkpoint_frontiers = BTreeMap::new();
        let mut best_checkpoint_present = false;
        for (checkpoint_key, checkpoint_value, verified_key, verified_value) in checkpoint_rows {
            let checkpoint = decode_scale_exact::<NativeCanonicalStateCheckpointV1>(
                checkpoint_value,
                "native reorg canonical checkpoint row",
            )?;
            let meta = self
                .header_by_hash(&checkpoint.block_hash)?
                .ok_or_else(|| {
                    anyhow!(
                        "native reorg checkpoint references a missing durable block {}",
                        hex32(&checkpoint.block_hash)
                    )
                })?;
            let (checkpoint_commitment_tree, checkpoint_nullifier_accumulator, _) =
                validate_native_canonical_state_checkpoint(&checkpoint, &meta)?;
            if checkpoint_key.as_slice()
                != native_canonical_state_checkpoint_key(&checkpoint.block_hash)
                || verified_key.as_slice()
                    != native_verified_block_record_key(&checkpoint.block_hash)
                || verified_value.as_slice() != native_verified_block_body_digest(&meta)?.as_slice()
                || !checkpoint_keys.insert(checkpoint_key.clone())
                || !verified_keys.insert(verified_key.clone())
                || checkpoint_frontiers
                    .insert(
                        checkpoint.block_hash,
                        (
                            checkpoint_commitment_tree.leaf_count(),
                            checkpoint_nullifier_accumulator.leaf_count(),
                        ),
                    )
                    .is_some()
            {
                return Err(anyhow!(
                    "native reorg canonical checkpoint/verified row identity mismatch"
                ));
            }
            best_checkpoint_present |= checkpoint.block_hash == best.hash;
        }
        if best.height > 0 && !best_checkpoint_present {
            return Err(anyhow!(
                "native reorg commit is missing the best-state checkpoint"
            ));
        }
        let mut undo_hashes = BTreeSet::new();
        let mut best_undo_present = false;
        for undo in canonical_undos {
            let meta = self.header_by_hash(&undo.block_hash)?.ok_or_else(|| {
                anyhow!(
                    "native reorg undo references a missing durable block {}",
                    hex32(&undo.block_hash)
                )
            })?;
            let expected_frontiers = checkpoint_frontiers.get(&undo.block_hash).copied();
            let undo_commitment_end = undo.commitment_start.checked_add(undo.commitment_count);
            let undo_nullifier_end = undo.nullifier_start.checked_add(undo.nullifier_count);
            if undo.schema_version != NATIVE_CANONICAL_UNDO_SCHEMA_V1
                || undo.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE
                || undo.rules_hash != meta.rules_hash
                || undo.height != meta.height
                || undo.block_hash != meta.hash
                || undo.parent_hash != meta.parent_hash
                || undo.block_body_digest != native_in_process_verified_block_body_digest(&meta)?
                || expected_frontiers != undo_commitment_end.zip(undo_nullifier_end)
                || undo.ciphertext_index_undo.iter().any(|row| {
                    row.previous
                        .as_ref()
                        .is_some_and(|value| value.len() != NATIVE_CIPHERTEXT_INDEX_VALUE_BYTES)
                })
                || undo.record_digest != native_canonical_undo_digest(undo)
                || !undo_hashes.insert(undo.block_hash)
            {
                return Err(anyhow!(
                    "native reorg canonical undo identity/frontier mismatch at height {} ({})",
                    undo.height,
                    hex32(&undo.block_hash)
                ));
            }
            best_undo_present |= undo.block_hash == best.hash;
        }
        if undo_hashes.len() != checkpoint_frontiers.len()
            || checkpoint_frontiers
                .keys()
                .any(|hash| !undo_hashes.contains(hash))
            || (best.height > 0 && !best_undo_present)
        {
            return Err(anyhow!(
                "native reorg canonical undo rows do not exactly cover the checkpoint suffix"
            ));
        }
        let reorg_manifest = NativeAtomicCommitManifestAdmissionInput {
            source_poseidon2_v8_plan_count: usize::from(poseidon2_v8_plan.is_some()),
            // Only the shared transaction helper may replace this sentinel
            // with the number of typed V8 plans actually applied.
            poseidon2_v8_plan_application_count: UNOBSERVED_POSEIDON2_V8_PLAN_APPLICATION_COUNT,
            ..native_reorg_commit_manifest(
                &canonical_index_plan,
                height_entries,
                pending_entries,
                staged_ciphertext_removals.len(),
            )
        };
        let NativeCanonicalIndexPlan {
            commitment_entries,
            nullifier_entries,
            bridge_replay_entries,
            ciphertext_index_entries,
            ciphertext_archive_entries,
        } = canonical_index_plan;

        let commit_result: sled::transaction::TransactionResult<(), String> = (
            &self.meta_tree,
            &self.height_tree,
            &self.commitment_tree,
            &self.nullifier_tree,
            &self.bridge_inbound_tree,
            &self.ciphertext_index_tree,
            &self.ciphertext_archive_tree,
            &self.da_ciphertext_tree,
            &self.action_tree,
            &self.poseidon2_v8_tree,
        )
            .transaction(
                |(
                    meta_tree,
                    height_tree,
                    commitment_tree,
                    nullifier_tree,
                    bridge_inbound_tree,
                    ciphertext_index_tree,
                    ciphertext_archive_tree,
                    da_ciphertext_tree,
                    action_tree,
                    poseidon2_v8_tree,
                )| {
                    self::apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction(
                        poseidon2_v8_tree,
                        poseidon2_v8_plan,
                        reorg_manifest,
                        "native canonical reorg manifest",
                    )?;
                    for key in &height_keys {
                        height_tree.remove(key.clone())?;
                    }
                    for key in &commitment_keys {
                        commitment_tree.remove(key.clone())?;
                    }
                    for key in &nullifier_keys {
                        nullifier_tree.remove(key.clone())?;
                    }
                    for key in &bridge_replay_keys {
                        bridge_inbound_tree.remove(key.clone())?;
                    }
                    for key in &ciphertext_index_keys {
                        ciphertext_index_tree.remove(key.clone())?;
                    }
                    for key in &ciphertext_archive_keys {
                        ciphertext_archive_tree.remove(key.clone())?;
                    }
                    for key in &action_keys {
                        action_tree.remove(key.clone())?;
                    }

                    for (height, hash) in height_entries {
                        height_tree.insert(height_key(*height).to_vec(), hash.to_vec())?;
                    }
                    for (index, commitment) in &commitment_entries {
                        commitment_tree
                            .insert(index.to_be_bytes().to_vec(), commitment.to_vec())?;
                    }
                    for (index, bytes) in &ciphertext_archive_entries {
                        ciphertext_archive_tree
                            .insert(index.to_be_bytes().to_vec(), bytes.clone())?;
                    }
                    for (index, nullifier) in &nullifier_entries {
                        nullifier_tree.insert(nullifier.to_vec(), index.to_be_bytes().to_vec())?;
                    }
                    for replay_key in &bridge_replay_entries {
                        bridge_inbound_tree.insert(replay_key.to_vec(), b"1".to_vec())?;
                    }
                    for (hash, value) in &ciphertext_index_entries {
                        ciphertext_index_tree.insert(hash.to_vec(), value.clone())?;
                    }
                    for hash in staged_ciphertext_removals {
                        da_ciphertext_tree.remove(hash.to_vec())?;
                    }
                    for (tx_hash, encoded) in pending_entries {
                        action_tree.insert(tx_hash.as_bytes().to_vec(), encoded.clone())?;
                    }
                    meta_tree.insert(META_BEST_KEY.to_vec(), best_record.clone())?;
                    meta_tree.insert(
                        META_NULLIFIER_ACCUMULATOR_KEY.to_vec(),
                        nullifier_accumulator_record.clone(),
                    )?;
                    for (checkpoint_key, checkpoint_value, verified_key, verified_value) in
                        checkpoint_rows
                    {
                        meta_tree.insert(checkpoint_key.clone(), checkpoint_value.clone())?;
                        meta_tree.insert(verified_key.clone(), verified_value.clone())?;
                    }
                    for undo in canonical_undos {
                        meta_tree
                            .insert(native_canonical_undo_key(&undo.block_hash), undo.encode())?;
                    }
                    Ok(())
                },
            );
        commit_result.map_err(|err| anyhow!("atomic native reorg commit failed: {err}"))?;
        Ok(())
    }

    pub(crate) fn commit_canonical_index_repair_atomically(
        &self,
        canonical_index_plan: NativeCanonicalIndexPlan,
    ) -> Result<()> {
        let mut planned_nullifier_keys = PersistentKeySet48::new();
        if canonical_index_plan
            .nullifier_entries
            .iter()
            .any(|(_, nullifier)| !planned_nullifier_keys.insert(*nullifier))
        {
            return Err(anyhow!("repaired nullifier index contains a duplicate key"));
        }
        let planned_nullifier_accumulator =
            NullifierAccumulator::from_indexed_rows(&canonical_index_plan.nullifier_entries)
                .map_err(|err| anyhow!("rebuild repaired nullifier accumulator failed: {err}"))?;
        let best_nullifier_root = self.state.read().best.nullifier_root;
        if planned_nullifier_accumulator.root() != best_nullifier_root {
            return Err(anyhow!(
                "repaired nullifier accumulator does not match canonical best metadata"
            ));
        }
        let nullifier_accumulator_record = planned_nullifier_accumulator
            .encode()
            .map_err(|err| anyhow!("encode repaired nullifier accumulator failed: {err}"))?;
        let commitment_keys = collect_tree_keys(&self.commitment_tree, "native commitment")?;
        let nullifier_keys = collect_tree_keys(&self.nullifier_tree, "native nullifier")?;
        let bridge_replay_keys =
            collect_tree_keys(&self.bridge_inbound_tree, "native bridge replay")?;
        let ciphertext_index_keys =
            collect_tree_keys(&self.ciphertext_index_tree, "native ciphertext index")?;
        let ciphertext_archive_keys =
            collect_tree_keys(&self.ciphertext_archive_tree, "native ciphertext archive")?;
        evaluate_native_atomic_commit_manifest_admission(native_canonical_index_repair_manifest(
            &canonical_index_plan,
        ))
        .map_err(|rejection| {
            native_atomic_commit_manifest_admission_error(
                "native canonical index repair manifest",
                rejection,
            )
        })?;
        let NativeCanonicalIndexPlan {
            commitment_entries,
            nullifier_entries,
            bridge_replay_entries,
            ciphertext_index_entries,
            ciphertext_archive_entries,
        } = canonical_index_plan;

        let repair_result: sled::transaction::TransactionResult<(), std::convert::Infallible> = (
            &self.meta_tree,
            &self.commitment_tree,
            &self.nullifier_tree,
            &self.bridge_inbound_tree,
            &self.ciphertext_index_tree,
            &self.ciphertext_archive_tree,
        )
            .transaction(
                |(
                    meta_tree,
                    commitment_tree,
                    nullifier_tree,
                    bridge_inbound_tree,
                    ciphertext_index_tree,
                    ciphertext_archive_tree,
                )| {
                    for key in &commitment_keys {
                        commitment_tree.remove(key.clone())?;
                    }
                    for key in &nullifier_keys {
                        nullifier_tree.remove(key.clone())?;
                    }
                    for key in &bridge_replay_keys {
                        bridge_inbound_tree.remove(key.clone())?;
                    }
                    for key in &ciphertext_index_keys {
                        ciphertext_index_tree.remove(key.clone())?;
                    }
                    for key in &ciphertext_archive_keys {
                        ciphertext_archive_tree.remove(key.clone())?;
                    }

                    for (index, commitment) in &commitment_entries {
                        commitment_tree
                            .insert(index.to_be_bytes().to_vec(), commitment.to_vec())?;
                    }
                    for (index, bytes) in &ciphertext_archive_entries {
                        ciphertext_archive_tree
                            .insert(index.to_be_bytes().to_vec(), bytes.clone())?;
                    }
                    for (index, nullifier) in &nullifier_entries {
                        nullifier_tree.insert(nullifier.to_vec(), index.to_be_bytes().to_vec())?;
                    }
                    for replay_key in &bridge_replay_entries {
                        bridge_inbound_tree.insert(replay_key.to_vec(), b"1".to_vec())?;
                    }
                    for (hash, value) in &ciphertext_index_entries {
                        ciphertext_index_tree.insert(hash.to_vec(), value.clone())?;
                    }
                    meta_tree.insert(
                        META_NULLIFIER_ACCUMULATOR_KEY.to_vec(),
                        nullifier_accumulator_record.clone(),
                    )?;
                    Ok(())
                },
            );
        repair_result
            .map_err(|err| anyhow!("atomic native canonical index repair failed: {err}"))?;
        self.flush_native_durability_barrier(
            "native canonical index repair",
            NativeStorageDurabilityOperation::CanonicalIndexRepair,
        )?;
        Ok(())
    }

    pub(crate) fn commit_mined_block_atomically(
        &self,
        actions: &[PendingAction],
        planned: &[NativePlannedActionEffect],
        meta: &NativeBlockMeta,
        parent_nullifier_accumulator: &NullifierAccumulator,
        next_nullifier_accumulator: &NullifierAccumulator,
        checkpoint_rows: &NativeCanonicalCheckpointRows,
        additional_pending_action_removals: &[ActionId48],
    ) -> Result<()> {
        let expected_action_bytes: Vec<Vec<u8>> = actions.iter().map(Encode::encode).collect();
        if meta.action_bytes != expected_action_bytes {
            ::core::result::Result::<(), anyhow::Error>::Err((|| {
                anyhow!("native mined block action bytes mismatch committed actions")
            })())?;
        }
        let (parent_projection, _) = self
            .inspect_stored_pow_metadata(
                &meta.parent_hash,
                None,
                "native mined-block V8 canonical parent",
            )?
            .ok_or_else(|| anyhow!("missing native parent block for V8 canonical planning"))?;
        if parent_projection.height.checked_add(1) != Some(meta.height)
            || parent_projection.hash != meta.parent_hash
        {
            return Err(anyhow!(
                "native mined-block V8 canonical parent does not precede the committed block"
            ));
        }
        let v8_commit = self.plan_poseidon2_v8_block_against_parent_tip(
            parent_projection.height,
            parent_projection.hash,
            meta,
            actions,
        )?;
        let mined_manifest = super::native_mined_block_commit_manifest(
            actions,
            planned,
            v8_commit.as_ref().map(|(_, plan)| plan),
        );
        let mut commitment_entries = Vec::new();
        let mut ciphertext_archive_entries = Vec::new();
        let mut appended_nullifiers = Vec::new();
        let mut bridge_replay_entries = Vec::new();
        let mut ciphertext_index_entries = Vec::new();
        let mut pending_action_removals = Vec::new();
        let mut staged_ciphertext_removals = Vec::new();

        for (action, effect) in actions.iter().zip(planned.iter()) {
            if action.ciphertext_hashes.len() != action.ciphertext_sizes.len() {
                ::core::result::Result::<(), anyhow::Error>::Err((|| {
                    anyhow!(
                        "native mined block ciphertext metadata count mismatch: hashes={} sizes={}",
                        action.ciphertext_hashes.len(),
                        action.ciphertext_sizes.len()
                    )
                })())?;
            }

            for (offset, commitment) in action.commitments.iter().enumerate() {
                let offset = u64::try_from(offset)
                    .map_err(|_| anyhow!("native mined block commitment offset overflow"))?;
                let index = effect
                    .commitment_start
                    .checked_add(offset)
                    .ok_or_else(|| anyhow!("native mined block commitment index overflow"))?;
                commitment_entries.push((index, *commitment));
            }
            for (offset, bytes) in effect.ciphertexts.iter().enumerate() {
                let offset = u64::try_from(offset)
                    .map_err(|_| anyhow!("native mined block ciphertext offset overflow"))?;
                let index = effect
                    .commitment_start
                    .checked_add(offset)
                    .ok_or_else(|| anyhow!("native mined block ciphertext index overflow"))?;
                ciphertext_archive_entries.push((index, bytes.clone()));
            }

            appended_nullifiers.extend(action.nullifiers.iter().copied());
            if let Some(replay_key) = effect.replay_key {
                bridge_replay_entries.push(replay_key);
            }

            if owns_legacy_ciphertext_da_rows(action) {
                for (idx, hash) in action.ciphertext_hashes.iter().enumerate() {
                    let size = action.ciphertext_sizes[idx];
                    let idx = u64::try_from(idx).map_err(|_| {
                        anyhow!("native mined block ciphertext row offset overflow")
                    })?;
                    let mut value = Vec::with_capacity(NATIVE_CIPHERTEXT_INDEX_VALUE_BYTES);
                    value.extend_from_slice(action.tx_hash.as_bytes());
                    value.extend_from_slice(&size.to_le_bytes());
                    value.extend_from_slice(&idx.to_le_bytes());
                    ciphertext_index_entries.push((*hash, value));
                }
            }

            pending_action_removals.push(action.tx_hash);
            if owns_legacy_ciphertext_da_rows(action) {
                staged_ciphertext_removals.extend(action.ciphertext_hashes.iter().copied());
            }
        }

        let mut recomputed_nullifier_accumulator = parent_nullifier_accumulator.clone();
        let mut appended_nullifier_keys = PersistentKeySet48::new();
        for nullifier in &appended_nullifiers {
            if !appended_nullifier_keys.insert(*nullifier)
                || self.nullifier_tree.contains_key(nullifier.as_slice())?
            {
                ::core::result::Result::<(), anyhow::Error>::Err((|| {
                    anyhow!(
                        "native mined nullifier index contains an already-spent or duplicate key"
                    )
                })())?;
            }
        }
        recomputed_nullifier_accumulator
            .append_all(appended_nullifiers.iter().copied())
            .map_err(|err| anyhow!("append mined nullifier accumulator failed: {err}"))?;
        if &recomputed_nullifier_accumulator != next_nullifier_accumulator
            || next_nullifier_accumulator.root() != meta.nullifier_root
        {
            ::core::result::Result::<(), anyhow::Error>::Err((|| {
                anyhow!("native mined nullifier accumulator does not match committed metadata")
            })())?;
        }
        let nullifier_accumulator_record = next_nullifier_accumulator
            .encode()
            .map_err(|err| anyhow!("encode mined nullifier accumulator failed: {err}"))?;
        let mut nullifier_entries = Vec::with_capacity(appended_nullifiers.len());
        let mut nullifier_index = parent_nullifier_accumulator.leaf_count();
        for nullifier in appended_nullifiers.iter().copied() {
            nullifier_entries.push((nullifier_index, nullifier));
            nullifier_index = nullifier_index
                .checked_add(1)
                .ok_or_else(|| anyhow!("native mined nullifier index overflow"))?;
        }
        if nullifier_index != next_nullifier_accumulator.leaf_count() {
            ::core::result::Result::<(), anyhow::Error>::Err((|| {
                anyhow!("native mined nullifier index count does not match accumulator")
            })())?;
        }

        let (checkpoint_key, checkpoint_value, verified_key, verified_value) = checkpoint_rows;
        let checkpoint = decode_scale_exact::<NativeCanonicalStateCheckpointV1>(
            checkpoint_value,
            "native mined canonical checkpoint row",
        )?;
        validate_native_canonical_state_checkpoint(&checkpoint, meta)?;
        if checkpoint_key.as_slice() != native_canonical_state_checkpoint_key(&meta.hash)
            || verified_key.as_slice() != native_verified_block_record_key(&meta.hash)
            || verified_value.as_slice() != native_verified_block_body_digest(meta)?.as_slice()
        {
            ::core::result::Result::<(), anyhow::Error>::Err((|| {
                anyhow!("native mined canonical checkpoint/verified row identity mismatch")
            })())?;
        }

        let block_record = bincode::serialize(meta)?;
        let commitment_start = checkpoint
            .commitment_leaf_count
            .checked_sub(
                u64::try_from(commitment_entries.len())
                    .map_err(|_| anyhow!("native mined commitment count exceeds u64"))?,
            )
            .ok_or_else(|| anyhow!("native mined commitment checkpoint underflow"))?;
        if commitment_entries
            .first()
            .is_some_and(|(index, _)| *index != commitment_start)
        {
            ::core::result::Result::<(), anyhow::Error>::Err((|| {
                anyhow!("native mined commitment entries do not start at the parent frontier")
            })())?;
        }
        let planned_nullifier_append = parent_nullifier_accumulator
            .plan_indexed_append(appended_nullifiers.iter().copied())
            .map_err(|err| anyhow!("plan mined canonical undo nullifiers failed: {err}"))?;
        if planned_nullifier_append.rows != nullifier_entries
            || &planned_nullifier_append.next_accumulator != next_nullifier_accumulator
        {
            ::core::result::Result::<(), anyhow::Error>::Err((|| {
                anyhow!("native mined nullifier delta does not match canonical append")
            })())?;
        }
        let mut ciphertext_overlay = BTreeMap::new();
        let canonical_undo = self.canonical_undo_from_parts(
            meta,
            commitment_start,
            commitment_entries.len(),
            planned_nullifier_append.base_leaf_count,
            planned_nullifier_append.rows.len(),
            &ciphertext_index_entries,
            &mut ciphertext_overlay,
        )?;
        let canonical_undo_key = native_canonical_undo_key(&meta.hash);
        let canonical_undo_value = canonical_undo.encode();
        let best_record = block_record.clone();
        let height_key = height_key(meta.height);
        self::__hegemon_pinned_sled::transaction::Transactional::transaction(
            &(
                &self.meta_tree,
                &self.height_tree,
                &self.block_tree,
                &self.commitment_tree,
                &self.nullifier_tree,
                &self.bridge_inbound_tree,
                &self.ciphertext_index_tree,
                &self.ciphertext_archive_tree,
                &self.da_ciphertext_tree,
                &self.action_tree,
                &self.poseidon2_v8_tree,
            ),
            |(
                meta_tree,
                height_tree,
                block_tree,
                commitment_tree,
                nullifier_tree,
                bridge_inbound_tree,
                ciphertext_index_tree,
                ciphertext_archive_tree,
                da_ciphertext_tree,
                action_tree,
                poseidon2_v8_tree,
            )| {
                self::apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction(
                    poseidon2_v8_tree,
                    v8_commit.as_ref().map(|(_, plan)| plan),
                    mined_manifest,
                    "native mined block commit manifest",
                )?;
                block_tree.insert(meta.hash.to_vec(), block_record.clone())?;
                height_tree.insert(height_key.to_vec(), meta.hash.to_vec())?;
                meta_tree.insert(META_BEST_KEY.to_vec(), best_record.clone())?;
                meta_tree.insert(
                    META_NULLIFIER_ACCUMULATOR_KEY.to_vec(),
                    nullifier_accumulator_record.clone(),
                )?;
                meta_tree.insert(checkpoint_key.clone(), checkpoint_value.clone())?;
                meta_tree.insert(verified_key.clone(), verified_value.clone())?;
                meta_tree.insert(canonical_undo_key.clone(), canonical_undo_value.clone())?;
                meta_tree.remove(native_noncanonical_fork_key(&meta.hash))?;

                for (index, commitment) in &commitment_entries {
                    commitment_tree.insert(index.to_be_bytes().to_vec(), commitment.to_vec())?;
                }
                for (index, bytes) in &ciphertext_archive_entries {
                    ciphertext_archive_tree.insert(index.to_be_bytes().to_vec(), bytes.clone())?;
                }
                for (index, nullifier) in &nullifier_entries {
                    nullifier_tree.insert(nullifier.to_vec(), index.to_be_bytes().to_vec())?;
                }
                for replay_key in &bridge_replay_entries {
                    bridge_inbound_tree.insert(replay_key.to_vec(), b"1".to_vec())?;
                }
                for (hash, value) in &ciphertext_index_entries {
                    ciphertext_index_tree.insert(hash.to_vec(), value.clone())?;
                }
                for hash in &pending_action_removals {
                    action_tree.remove(hash.as_bytes().to_vec())?;
                }
                for hash in additional_pending_action_removals {
                    action_tree.remove(hash.as_bytes().to_vec())?;
                }
                for hash in &staged_ciphertext_removals {
                    da_ciphertext_tree.remove(hash.to_vec())?;
                }
                Ok(())
            },
        )
        .map_err(|err| anyhow!("atomic native mined block commit failed: {err}"))?;
        if let Some((store, plan)) = &v8_commit {
            store
                .verify_canonical_plan_readback(plan)
                .map_err(|error| anyhow!("native V8 mined commit readback failed: {error}"))?;
        }
        Ok(())
    }

    fn current_canonical_checkpoint_matches_loaded_state(&self) -> Result<bool> {
        let state = self.state.read();
        let Some(checkpoint) = self.load_canonical_state_checkpoint(&state.best)? else {
            return Ok(false);
        };
        let (commitment_tree, nullifier_accumulator, header_mmr_peaks) =
            validate_native_canonical_state_checkpoint(&checkpoint, &state.best)?;
        Ok(commitment_tree == state.commitment_tree
            && nullifier_accumulator == state.nullifier_accumulator
            && header_mmr_peaks == state.header_mmr_peaks)
    }

    fn ensure_current_canonical_checkpoint(&self) -> Result<()> {
        if self.current_canonical_checkpoint_matches_loaded_state()? {
            return Ok(());
        }
        let rows = {
            let state = self.state.read();
            Self::canonical_checkpoint_rows(
                &state.best,
                &state.commitment_tree,
                &state.nullifier_accumulator,
                &state.header_mmr_peaks,
            )?
        };
        let (checkpoint_key, checkpoint_value, verified_key, verified_value) = rows;
        let result: sled::transaction::TransactionResult<(), std::convert::Infallible> =
            self.meta_tree.transaction(|meta_tree| {
                meta_tree.insert(checkpoint_key.clone(), checkpoint_value.clone())?;
                meta_tree.insert(verified_key.clone(), verified_value.clone())?;
                Ok(())
            });
        result.map_err(|err| anyhow!("persist native canonical checkpoint failed: {err}"))?;
        self.flush_native_durability_barrier(
            "native canonical checkpoint repair",
            NativeStorageDurabilityOperation::CanonicalIndexRepair,
        )
    }

    pub(crate) fn ensure_ciphertext_archive_index(
        &self,
        canonical_chain: &ValidatedCanonicalChainSnapshot,
    ) -> Result<()> {
        // A checkpoint and its body digest live in the same local sled DB and
        // are therefore diagnostic, not an authenticated proof-validity
        // certificate. Every restart and every reorg replay re-verifies
        // historical SmallWood proofs; process-local entries populated by an
        // audit/import remain diagnostic only.
        let chain = canonical_chain.blocks();
        let replayed_state = self.replay_chain_state(chain)?;
        self.reconcile_poseidon2_v8_canonical_history(chain)?;
        self.validate_loaded_state_matches_replay(&replayed_state)?;
        let canonical_index_plan = plan_canonical_index_rebuild(
            chain,
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
        )?;
        if self.canonical_index_matches_plan(&canonical_index_plan)? {
            return Ok(());
        }

        warn!(
            commitments = canonical_index_plan.commitment_entries.len(),
            nullifiers = canonical_index_plan.nullifier_entries.len(),
            bridge_replay = canonical_index_plan.bridge_replay_entries.len(),
            ciphertext_index = canonical_index_plan.ciphertext_index_entries.len(),
            ciphertext_archive = canonical_index_plan.ciphertext_archive_entries.len(),
            "rebuilding canonical native indexes after validated replay"
        );
        self.commit_canonical_index_repair_atomically(canonical_index_plan)?;
        Ok(())
    }

    pub(crate) fn validate_loaded_state_matches_replay(
        &self,
        replayed: &NativeState,
    ) -> Result<()> {
        let state = self.state.read();
        if state.best != replayed.best {
            return Err(anyhow!("startup canonical replay best metadata mismatch"));
        }
        if state.commitment_tree != replayed.commitment_tree {
            return Err(anyhow!("startup canonical replay commitment tree mismatch"));
        }
        if state.nullifiers != replayed.nullifiers {
            return Err(anyhow!("startup canonical replay nullifier set mismatch"));
        }
        if state.nullifier_accumulator != replayed.nullifier_accumulator {
            return Err(anyhow!(
                "startup canonical replay nullifier accumulator mismatch"
            ));
        }
        if state.consumed_bridge_messages != replayed.consumed_bridge_messages {
            return Err(anyhow!(
                "startup canonical replay bridge replay set mismatch"
            ));
        }
        Ok(())
    }

    pub(crate) fn canonical_index_matches_plan(
        &self,
        plan: &NativeCanonicalIndexPlan,
    ) -> Result<bool> {
        if self.commitment_tree.len() != plan.commitment_entries.len()
            || self.nullifier_tree.len() != plan.nullifier_entries.len()
            || self.bridge_inbound_tree.len() != plan.bridge_replay_entries.len()
            || self.ciphertext_index_tree.len() != plan.ciphertext_index_entries.len()
            || self.ciphertext_archive_tree.len() != plan.ciphertext_archive_entries.len()
        {
            return Ok(false);
        }
        for (index, commitment) in &plan.commitment_entries {
            if self.commitment_tree.get(index.to_be_bytes())?.as_deref()
                != Some(commitment.as_slice())
            {
                return Ok(false);
            }
        }
        for (index, nullifier) in &plan.nullifier_entries {
            if self.nullifier_tree.get(nullifier.as_slice())?.as_deref()
                != Some(index.to_be_bytes().as_slice())
            {
                return Ok(false);
            }
        }
        let expected_nullifier_accumulator =
            NullifierAccumulator::from_indexed_rows(&plan.nullifier_entries)
                .map_err(|err| anyhow!("rebuild planned nullifier accumulator failed: {err}"))?
                .encode()
                .map_err(|err| anyhow!("encode planned nullifier accumulator failed: {err}"))?;
        if self
            .meta_tree
            .get(META_NULLIFIER_ACCUMULATOR_KEY)?
            .as_deref()
            != Some(expected_nullifier_accumulator.as_slice())
        {
            return Ok(false);
        }
        for replay_key in &plan.bridge_replay_entries {
            if self
                .bridge_inbound_tree
                .get(replay_key.as_slice())?
                .as_deref()
                != Some(b"1".as_slice())
            {
                return Ok(false);
            }
        }
        for (hash, value) in &plan.ciphertext_index_entries {
            if self.ciphertext_index_tree.get(hash.as_slice())?.as_deref() != Some(value.as_slice())
            {
                return Ok(false);
            }
        }
        for (index, bytes) in &plan.ciphertext_archive_entries {
            if self
                .ciphertext_archive_tree
                .get(index.to_be_bytes())?
                .as_deref()
                != Some(bytes.as_slice())
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn header_by_hash(&self, hash: &[u8; 32]) -> Result<Option<NativeBlockMeta>> {
        #[cfg(test)]
        self.full_block_body_load_invocations
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        {
            self.block_meta_load_count.fetch_add(1, Ordering::Relaxed);
            self.block_meta_decode_count.fetch_add(1, Ordering::Relaxed);
        }
        load_block_meta_by_hash(&self.block_tree, hash)
    }

    /// Return one exact 1 MiB-or-smaller chunk of the canonical SCALE action
    /// body for a hash-addressed canonical block. The full action body is
    /// checked against the header count/root and every action's self id before
    /// any bytes are released. A second height-index lookup closes the reorg
    /// race between initial canonicality admission and response construction.
    pub(crate) fn canonical_action_body_chunk(
        &self,
        block_hash: [u8; 32],
        chunk_index: u32,
    ) -> Result<Option<NativeActionBodyRpcChunk>> {
        let Some(meta) = self.header_by_hash(&block_hash)? else {
            return Ok(None);
        };
        if meta.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE {
            return Err(anyhow!(
                "chain_getBlockActionsChunk serves only active native blocks"
            ));
        }
        if self.hash_by_height(meta.height)? != Some(block_hash) {
            return Err(anyhow!(
                "chain_getBlockActionsChunk block is not canonical at height {}",
                meta.height
            ));
        }

        self.validate_stored_block_meta_parent_chain(&meta)
            .context("chain_getBlockActionsChunk header admission failed")?;
        verify_canonical_sync_block_body(&meta)
            .context("chain_getBlockActionsChunk action id/root admission failed")?;
        let encoded = encode_native_action_body_v3(&meta.action_bytes)
            .context("chain_getBlockActionsChunk action-body encoding failed")?;
        let action_body_len = usize::try_from(encoded.len)
            .map_err(|_| anyhow!("canonical action-body length exceeds host usize"))?;
        if action_body_len != encoded.bytes.len() {
            return Err(anyhow!(
                "canonical action-body encoded length does not match its bytes"
            ));
        }
        let chunk_count = native_block_body_chunk_count(action_body_len)?;
        if chunk_index >= chunk_count {
            return Err(anyhow!(
                "chain_getBlockActionsChunk chunk_index {} out of range for {} chunks",
                chunk_index,
                chunk_count
            ));
        }
        let chunk_index_usize = usize::try_from(chunk_index)
            .map_err(|_| anyhow!("canonical action-body chunk index exceeds host usize"))?;
        let start = chunk_index_usize
            .checked_mul(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES)
            .ok_or_else(|| anyhow!("canonical action-body chunk offset overflow"))?;
        let end = start
            .checked_add(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES)
            .map(|end| end.min(action_body_len))
            .ok_or_else(|| anyhow!("canonical action-body chunk end overflow"))?;
        let bytes = encoded
            .bytes
            .get(start..end)
            .ok_or_else(|| anyhow!("canonical action-body chunk range exceeds body"))?
            .to_vec();
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES {
            return Err(anyhow!(
                "canonical action-body chunk violates the bounded response size"
            ));
        }

        if self.hash_by_height(meta.height)? != Some(block_hash) {
            return Err(anyhow!(
                "chain_getBlockActionsChunk block changed canonicality during response construction"
            ));
        }
        Ok(Some(NativeActionBodyRpcChunk {
            block_hash,
            height: meta.height,
            parent_hash: meta.parent_hash,
            tx_count: meta.tx_count,
            extrinsics_root: meta.extrinsics_root,
            action_body_hash: encoded.hash,
            action_body_len: encoded.len,
            chunk_index,
            chunk_count,
            bytes,
        }))
    }

    pub(crate) fn canonical_da_encoding_for_block(
        &self,
        block_hash: [u8; 32],
    ) -> Result<Arc<state_da::DaEncoding>> {
        if let Some(encoding) = self
            .da_encoding_cache
            .lock()
            .entries
            .get(&block_hash)
            .cloned()
        {
            return Ok(encoding);
        }

        // RPC dispatch already runs on a bounded blocking pool. Serialize the
        // expensive RS rebuild without holding state or sled locks, then
        // recheck the cache so concurrent identical requests are single-flight.
        let _build_guard = self.da_encoding_build_lock.lock();
        if let Some(encoding) = self
            .da_encoding_cache
            .lock()
            .entries
            .get(&block_hash)
            .cloned()
        {
            return Ok(encoding);
        }

        let meta = self
            .header_by_hash(&block_hash)?
            .ok_or_else(|| anyhow!("unknown native block {}", hex32(&block_hash)))?;
        if meta.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE {
            return Err(anyhow!(
                "DA chunks are served only for active native V3 blocks"
            ));
        }
        let actions = decode_block_actions(&meta)?;
        for action in &actions {
            ensure_native_v3_active_action_route(action, true)?;
        }
        let materialized = materialize_native_action_payloads_at_starts(
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
            &actions,
            &vec![0u64; actions.len()],
        )?;
        let transactions = actions
            .iter()
            .zip(materialized.iter())
            .filter(|(action, _)| is_legacy_shielded_transfer_action(action))
            .map(|(action, payload)| {
                consensus_tx_and_artifact_from_action(action, payload).map(|(tx, _)| tx)
            })
            .collect::<Result<Vec<_>>>()?;
        let params = native_da_params_for_transactions(&transactions)?;
        let encoding = consensus::encode_da_blob(&transactions, params)
            .map_err(|err| anyhow!("rebuild native block DA encoding failed: {err}"))?;
        let chunk_count = u32::try_from(encoding.chunks().len())
            .map_err(|_| anyhow!("native DA chunk count exceeds u32"))?;
        evaluate_native_da_metadata_admission(NativeDaMetadataAdmissionInput {
            da_root_matches: meta.da_root == encoding.root(),
            da_chunk_size_matches: meta.da_chunk_size == params.chunk_size,
            da_sample_count_matches: meta.da_sample_count == params.sample_count,
            da_blob_len_matches: meta.da_blob_len == encoding.data_len(),
            da_chunk_count_matches: meta.da_chunk_count == chunk_count,
        })
        .map_err(native_da_metadata_admission_error)?;

        let encoding = Arc::new(encoding);
        let mut cache = self.da_encoding_cache.lock();
        if !cache.entries.contains_key(&block_hash) {
            while cache.entries.len() >= MAX_NATIVE_DA_ENCODING_CACHE_BLOCKS {
                let Some(oldest) = cache.order.pop_front() else {
                    cache.entries.clear();
                    break;
                };
                cache.entries.remove(&oldest);
            }
            cache.order.push_back(block_hash);
            cache.entries.insert(block_hash, Arc::clone(&encoding));
        }
        Ok(encoding)
    }

    pub(crate) fn hash_by_height(&self, height: u64) -> Result<Option<[u8; 32]>> {
        self.height_tree
            .get(height_key(height))?
            .map(|bytes| {
                let slice = bytes.as_ref();
                if slice.len() != 32 {
                    return Err(anyhow!("stored block hash has invalid length"));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(slice);
                Ok(hash)
            })
            .transpose()
    }

    pub(crate) fn verify_persisted_canonical_head(
        &self,
        meta: &NativeBlockMeta,
        context: &str,
    ) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_canonical_readback
            .swap(false, Ordering::AcqRel)
        {
            return Err(anyhow!("injected canonical post-commit readback failure"));
        }
        let best_bytes = self
            .meta_tree
            .get(META_BEST_KEY)?
            .ok_or_else(|| anyhow!("{context} missing persisted best pointer"))?;
        let (persisted_best, exact_best) = inspect_native_pow_metadata_bincode_exact(
            &best_bytes,
            Some(meta),
            &format!("{context} persisted best metadata"),
        )?;
        if !exact_best {
            return Err(anyhow!(
                "{context} persisted best pointer mismatch: expected height {} hash {}, got height {} hash {}",
                meta.height,
                hex32(&meta.hash),
                persisted_best.height,
                hex32(&persisted_best.hash)
            ));
        }

        let persisted_height_hash = self
            .hash_by_height(meta.height)?
            .ok_or_else(|| anyhow!("{context} missing canonical height index {}", meta.height))?;
        if persisted_height_hash != meta.hash {
            return Err(anyhow!(
                "{context} canonical height {} points to {}, expected {}",
                meta.height,
                hex32(&persisted_height_hash),
                hex32(&meta.hash)
            ));
        }

        let (_, exact_block) = self
            .inspect_stored_pow_metadata(
                &meta.hash,
                Some(meta),
                &format!("{context} persisted block record"),
            )?
            .ok_or_else(|| {
                anyhow!(
                    "{context} missing persisted block record for {}",
                    hex32(&meta.hash)
                )
            })?;
        if !exact_block {
            return Err(anyhow!(
                "{context} persisted block record mismatch at height {} ({})",
                meta.height,
                hex32(&meta.hash)
            ));
        }
        Ok(())
    }

    pub(crate) fn best_meta(&self) -> NativeBlockMeta {
        #[cfg(test)]
        self.best_meta_clone_invocations
            .fetch_add(1, Ordering::Relaxed);
        self.state.read().best.clone()
    }

    /// Return only the scalar canonical-tip fields needed by networking and
    /// sync scheduling.  A block body can approach 64 MiB, so callers that do
    /// not need it must never pay `NativeBlockMeta::clone` on a Tokio worker.
    pub(crate) fn best_tip(&self) -> (u64, [u8; 32]) {
        let state = self.state.read();
        (state.best.height, state.best.hash)
    }

    pub(crate) fn best_fork_choice_tip(&self) -> NativeForkChoiceTip {
        let state = self.state.read();
        NativeForkChoiceTip {
            height: state.best.height,
            hash: state.best.hash,
            cumulative_work: state.best.cumulative_work,
        }
    }

    pub(crate) fn best_height(&self) -> u64 {
        self.state.read().best.height
    }

    pub(crate) fn best_pow_bits(&self) -> u32 {
        self.state.read().best.pow_bits
    }

    /// Render the fixed header view while borrowing the canonical tip. This
    /// deliberately avoids cloning `action_bytes`, which can approach 64 MiB.
    pub(crate) fn best_header_json(&self) -> Value {
        let state = self.state.read();
        header_json(&state.best)
    }

    #[cfg(test)]
    pub(crate) fn reset_best_meta_clone_invocations(&self) {
        self.best_meta_clone_invocations.store(0, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn best_meta_clone_invocations(&self) -> u64 {
        self.best_meta_clone_invocations.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn reset_full_block_body_load_invocations(&self) {
        self.full_block_body_load_invocations
            .store(0, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn full_block_body_load_invocations(&self) -> u64 {
        self.full_block_body_load_invocations
            .load(Ordering::Relaxed)
    }

    pub(crate) fn mining_status(&self) -> Value {
        let (difficulty, block_height, next_pow_bits) = {
            let state = self.state.read();
            (
                state.best.pow_bits,
                state.best.height,
                self.expected_canonical_child_pow_bits(&state.best).ok(),
            )
        };
        let (syncing, sync_target_height) = self.sync_status_fields();
        json!({
            "is_mining": self.mining.load(Ordering::SeqCst),
            "threads": self.mining_threads.load(Ordering::Relaxed),
            "hash_rate": self.hash_rate(),
            "blocks_found": self.blocks_found.load(Ordering::Relaxed),
            "difficulty": difficulty,
            "next_difficulty": next_pow_bits,
            "block_height": block_height,
            "syncing": syncing,
            "sync_target_height": sync_target_height,
            "mining_sync_gate_open": self.mining_sync_gate_allows_work(),
            "bootstrap_authoring": self.config.bootstrap_mining_authoring,
        })
    }

    pub(crate) fn consensus_status(&self) -> Value {
        let (height, best_hash, state_root, nullifier_root, supply_digest) = {
            let state = self.state.read();
            (
                state.best.height,
                state.best.hash,
                state.best.state_root,
                state.best.nullifier_root,
                state.best.supply_digest,
            )
        };
        let (syncing, sync_target_height) = self.sync_status_fields();
        json!({
            "height": height,
            "best_hash": hex32(&best_hash),
            "state_root": hex48(&state_root),
            "nullifier_root": hex48(&nullifier_root),
            "supply_digest": supply_digest,
            "syncing": syncing,
            "sync_target_height": sync_target_height,
            "peers": self.network_peer_count(),
        })
    }

    pub(crate) fn telemetry_snapshot(&self) -> Value {
        let (tx_count, blocks_imported) = {
            let state = self.state.read();
            (state.pending_actions.len() as u64, state.best.height)
        };
        json!({
            "uptime_secs": self.start_instant.elapsed().as_secs(),
            "tx_count": tx_count,
            "blocks_imported": blocks_imported,
            "blocks_mined": self.blocks_found.load(Ordering::Relaxed),
            "memory_bytes": 0u64,
            "network_rx_bytes": 0u64,
            "network_tx_bytes": 0u64,
        })
    }

    pub(crate) fn storage_footprint(&self) -> Value {
        json!({
            "total_bytes": Value::Null,
            "exact_bytes_available": false,
            "blocks_entries": self.block_tree.len() as u64,
            "state_entries": self.meta_tree.len() as u64,
            "transactions_entries": self.action_tree.len() as u64,
            "nullifiers_entries": self.nullifier_tree.len() as u64,
        })
    }

    pub(crate) fn node_config_snapshot(&self, policy: RpcMethodPolicy) -> Value {
        if policy != RpcMethodPolicy::Unsafe {
            return json!({
                "chainSpecId": self.config.chain_spec_id(),
                "chainSpecName": "Hegemon",
                "chainType": self.config.chain_type(),
                "rpcMethods": self.config.rpc_methods,
                "redacted": true,
            });
        }

        json!({
            "nodeName": self.config.node_name,
            "chainSpecId": self.config.chain_spec_id(),
            "chainSpecName": "Hegemon",
            "chainType": self.config.chain_type(),
            "basePath": self.config.base_path.display().to_string(),
            "p2pListenAddr": self.config.p2p_listen_addr,
            "rpcListenAddr": self.config.rpc_addr.to_string(),
            "rpcMethods": self.config.rpc_methods,
            "rpcExternal": self.config.rpc_external,
            "bootstrapNodes": self.config.seeds,
            "bootstrapMiningAuthoring": self.config.bootstrap_mining_authoring,
            "pqVerbose": env_bool("HEGEMON_PQ_VERBOSE"),
            "maxPeers": self.config.max_peers,
            "redacted": false,
        })
    }

    pub(crate) fn rpc_policy(&self) -> Result<RpcMethodPolicy> {
        rpc_method_policy(&self.config.rpc_methods, self.config.rpc_external)
    }

    pub(crate) fn note_status(&self) -> Value {
        let state = self.state.read();
        let root = state.commitment_tree.root();
        let leaf_count = state.commitment_tree.leaf_count();
        json!({
            "leaf_count": leaf_count,
            "depth": COMMITMENT_TREE_DEPTH as u64,
            "root": hex48(&root),
            "next_index": leaf_count,
        })
    }

    pub(crate) fn latest_block(&self) -> Value {
        let (height, hash, state_root, nullifier_root, supply_digest, timestamp_ms) = {
            let state = self.state.read();
            (
                state.best.height,
                state.best.hash,
                state.best.state_root,
                state.best.nullifier_root,
                state.best.supply_digest,
                state.best.timestamp_ms,
            )
        };
        json!({
            "height": height,
            "hash": hex32(&hash),
            "state_root": hex48(&state_root),
            "nullifier_root": hex48(&nullifier_root),
            "supply_digest": supply_digest,
            "timestamp": timestamp_ms,
        })
    }

    pub(crate) fn pending_extrinsics(&self) -> Value {
        let state = self.state.read();
        Value::Array(
            state
                .pending_actions
                .values()
                .map(|action| json!(hex48(action.tx_hash.as_bytes())))
                .collect(),
        )
    }

    pub(crate) fn wallet_commitments(&self, params: Value) -> Result<Value> {
        let page = pagination_from_params(params)?;
        let mut entries = Vec::new();
        let total = self.state.read().commitment_tree.leaf_count();
        let end = wallet_page_end(page, total)?;
        let sources = self.wallet_commitment_sources_for_range(page.start, end)?;
        for index in page.start..end {
            let commitment = self.load_wallet_commitment_at(index)?;
            let commitment_hex = hex48(&commitment);
            entries.push(json!({
                "index": index,
                "value": commitment_hex,
                "commitment": commitment_hex,
                "source": sources.get(&index).copied().unwrap_or("unknown"),
            }));
        }
        Ok(json!({
            "entries": entries,
            "total": total,
            "has_more": end < total,
        }))
    }

    pub(crate) fn wallet_ciphertexts(&self, params: Value) -> Result<Value> {
        let page = pagination_from_params(params)?;
        let (entries, total) = self.ciphertext_entries_page(page)?;
        Ok(json!({
            "entries": entries,
            "total": total,
            "has_more": page.start.saturating_add(page.limit) < total,
        }))
    }

    pub(crate) fn ciphertext_entries_page(
        &self,
        page: NativePagination,
    ) -> Result<(Vec<Value>, u64)> {
        use base64::Engine;

        let leaf_count = self.state.read().commitment_tree.leaf_count();
        let mut entries = Vec::new();
        let end = wallet_page_end(page, leaf_count)?;
        for index in page.start..end {
            let value = self.load_wallet_ciphertext_at(index)?;
            entries.push(json!({
                "index": index,
                "ciphertext": base64::engine::general_purpose::STANDARD.encode(value.as_slice()),
            }));
        }
        Ok((entries, leaf_count))
    }

    pub(crate) fn wallet_commitment_sources_for_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<BTreeMap<u64, &'static str>> {
        let mut sources = BTreeMap::new();
        if start >= end {
            return Ok(sources);
        }

        let best_height = self.state.read().best.height;
        let mut commitment_index = 0u64;
        for height in 1..=best_height {
            if commitment_index >= end {
                break;
            }
            let meta = self.load_canonical_block_at_height_unverified(height)?;
            for action in decode_block_actions(&meta)? {
                let source = wallet_commitment_source_label(&action);
                for _ in &action.commitments {
                    if commitment_index >= start && commitment_index < end {
                        sources.insert(commitment_index, source);
                    }
                    commitment_index = commitment_index
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("native commitment source index overflow"))?;
                    if commitment_index >= end {
                        break;
                    }
                }
                if commitment_index >= end {
                    break;
                }
            }
        }
        Ok(sources)
    }

    pub(crate) fn load_wallet_commitment_at(&self, index: u64) -> Result<[u8; 48]> {
        let value = self
            .commitment_tree
            .get(height_key(index))?
            .ok_or_else(|| anyhow!("native commitment archive index gap: missing {index}"))?;
        if value.len() != 48 {
            return Err(anyhow!(
                "native commitment archive value has invalid length: expected 48, got {}",
                value.len()
            ));
        }
        let mut commitment = [0u8; 48];
        commitment.copy_from_slice(value.as_ref());
        Ok(commitment)
    }

    pub(crate) fn load_wallet_ciphertext_at(&self, index: u64) -> Result<Vec<u8>> {
        let value = self
            .ciphertext_archive_tree
            .get(height_key(index))?
            .ok_or_else(|| anyhow!("native ciphertext archive index gap: missing {index}"))?;
        validate_wallet_ciphertext_archive_value(value.as_ref())?;
        Ok(value.to_vec())
    }

    pub(crate) fn wallet_nullifiers(&self, params: Value) -> Result<Value> {
        let page = pagination_from_params(params)?;
        let state = self.state.read();
        let total = state.nullifiers.len() as u64;
        let nullifiers = state
            .nullifiers
            .iter()
            .skip(page.start as usize)
            .take(page.limit as usize)
            .map(hex48)
            .collect::<Vec<_>>();
        Ok(json!({
            "nullifiers": nullifiers,
            "total": total,
            "has_more": page.start.saturating_add(page.limit) < total,
        }))
    }

    pub(crate) fn is_valid_anchor(&self, params: Value) -> Result<Value> {
        let raw = first_param(&params)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("hegemon_isValidAnchor requires a 48-byte anchor hex string"))?;
        let anchor = parse_hex48(raw).ok_or_else(|| anyhow!("invalid anchor hex"))?;
        let state = self.state.read();
        Ok(json!(state.commitment_tree.contains_root(&anchor)))
    }

    fn pause_pending_action_group_commit_before_drain_for_test(&self) {
        #[cfg(test)]
        {
            self.pending_action_group_commit_test
                .before_drain_entered
                .store(true, Ordering::Release);
            self.pending_action_group_commit_test.wake.notify_all();
            let mut wait = self.pending_action_group_commit_test.wait_lock.lock();
            while self
                .pending_action_group_commit_test
                .hold_before_drain
                .load(Ordering::Acquire)
            {
                self.pending_action_group_commit_test.wake.wait(&mut wait);
            }
        }
    }

    #[cfg(test)]
    fn pause_pending_action_group_commit_before_flush_for_test(&self) {
        self.pending_action_group_commit_test
            .before_flush_entered
            .store(true, Ordering::Release);
        self.pending_action_group_commit_test.wake.notify_all();
        let mut wait = self.pending_action_group_commit_test.wait_lock.lock();
        while self
            .pending_action_group_commit_test
            .hold_before_flush
            .load(Ordering::Acquire)
        {
            self.pending_action_group_commit_test.wake.wait(&mut wait);
        }
    }

    fn take_pending_action_group_commit_batch(&self) -> Vec<NativePendingActionCommitRequest> {
        self.pause_pending_action_group_commit_before_drain_for_test();
        let deadline = Instant::now() + NATIVE_PENDING_ACTION_GROUP_COMMIT_WINDOW;
        let mut group = self.pending_action_group_commit.state.lock();
        loop {
            let batch_saturated = group.queue.len()
                >= MAX_NATIVE_PENDING_ACTION_GROUP_COMMIT_ACTIONS
                || group.queued_bytes >= MAX_NATIVE_PENDING_ACTION_GROUP_COMMIT_BYTES;
            let now = Instant::now();
            if batch_saturated || now >= deadline {
                break;
            }
            self.pending_action_group_commit
                .wake
                .wait_for(&mut group, deadline.saturating_duration_since(now));
        }

        let mut batch = Vec::new();
        let mut batch_bytes = 0usize;
        while let Some(request) = group.queue.front() {
            let next_bytes = batch_bytes.saturating_add(request.pending_encoded.len());
            if !batch.is_empty()
                && (batch.len() >= MAX_NATIVE_PENDING_ACTION_GROUP_COMMIT_ACTIONS
                    || next_bytes > MAX_NATIVE_PENDING_ACTION_GROUP_COMMIT_BYTES)
            {
                break;
            }
            let Some(request) = group.queue.pop_front() else {
                break;
            };
            group.queued_bytes = group
                .queued_bytes
                .saturating_sub(request.pending_encoded.len());
            batch_bytes = next_bytes;
            batch.push(request);
        }
        batch
    }

    fn flush_pending_action_group_commit(&self) -> Result<()> {
        #[cfg(test)]
        {
            self.pending_action_group_commit_test
                .flush_invocations
                .fetch_add(1, Ordering::Relaxed);
            self.pause_pending_action_group_commit_before_flush_for_test();
            if self
                .pending_action_group_commit_test
                .fail_next_flush
                .swap(false, Ordering::AcqRel)
            {
                return Err(anyhow!(
                    "injected native pending-action group flush failure"
                ));
            }
        }
        self.flush_native_durability_barrier(
            "native pending-action group commit",
            NativeStorageDurabilityOperation::PendingActionStage,
        )
    }

    fn rollback_pending_action_group_commit_persistence(
        &self,
        batch: &[NativePendingActionCommitRequest],
        accepted_indices: &[usize],
        dropped_candidates: &[(PendingAction, Vec<u8>)],
    ) -> Result<()> {
        let rollback: sled::transaction::TransactionResult<(), String> =
            (&self.action_tree, &self.da_proof_tree).transaction(|(action_tree, da_proof_tree)| {
                for index in accepted_indices {
                    let request = &batch[*index];
                    if action_tree
                        .get(request.pending.tx_hash.as_ref())?
                        .is_some_and(|current| {
                            current.as_ref() == request.pending_encoded.as_slice()
                        })
                    {
                        action_tree.remove(request.pending.tx_hash.as_bytes().to_vec())?;
                    }
                }
                for (candidate, encoded) in dropped_candidates {
                    match action_tree.get(candidate.tx_hash.as_ref())? {
                        Some(current) if current.as_ref() == encoded.as_slice() => {}
                        Some(_) => {
                            return Err(sled::transaction::ConflictableTransactionError::Abort(
                                format!(
                                    "candidate {} changed during pending-action rollback",
                                    hex48(candidate.tx_hash.as_bytes())
                                ),
                            ));
                        }
                        None => {
                            action_tree
                                .insert(candidate.tx_hash.as_bytes().to_vec(), encoded.clone())?;
                        }
                    }
                }
                for index in accepted_indices {
                    let Some((binding_hash, proof)) = &batch[*index].consumed_staged_proof else {
                        continue;
                    };
                    match da_proof_tree.get(binding_hash.as_slice())? {
                        Some(current) if current.as_ref() == proof.as_slice() => {}
                        Some(_) => {
                            // A concurrent sidecar replacement supersedes the consumed
                            // value and must never be overwritten by rollback.
                        }
                        None => {
                            da_proof_tree.insert(binding_hash.to_vec(), proof.clone())?;
                        }
                    }
                }
                Ok(())
            });
        rollback.map_err(|err| anyhow!("rollback native pending-action group failed: {err}"))?;
        self.db
            .flush()
            .map_err(|err| anyhow!("flush native pending-action rollback failed: {err}"))?;
        Ok(())
    }

    fn process_pending_action_group_commit_batch(
        &self,
        batch: &[NativePendingActionCommitRequest],
    ) -> Vec<std::result::Result<NativePendingActionStageDisposition, String>> {
        if let Err(err) = self.ensure_native_storage_healthy() {
            return vec![Err(err.to_string()); batch.len()];
        }
        let mut outcomes = vec![None; batch.len()];
        let mut requires_commit = vec![false; batch.len()];
        let _persistence_epoch = self.pending_action_persistence_lock.lock();

        let (
            expected_tip,
            expected_canonical_generation,
            expected_pending_generation,
            accepted_indices,
            dropped_candidates,
        ) = {
            let state = self.state.read();
            let expected_tip = (state.best.height, state.best.hash);
            let expected_canonical_generation =
                self.canonical_state_generation.load(Ordering::Acquire);
            let expected_pending_generation =
                self.pending_action_generation.load(Ordering::Acquire);
            let mut projected_count = state.pending_actions.len();
            let mut projected_bytes = state.pending_mempool_bytes;
            let mut accepted_indices = Vec::new();
            let mut accepted_tx_hashes = BTreeSet::new();
            let mut accepted_semantic_hashes = BTreeSet::new();
            let mut accepted_nullifiers = BTreeSet::new();
            let mut accepted_bridge_replay_keys = BTreeSet::new();
            let mut consumed_staged_proofs = BTreeSet::new();
            let mut dropped_candidates = Vec::new();
            let mut candidates_projected_dropped = false;

            for (index, request) in batch.iter().enumerate() {
                let reject = |error: anyhow::Error| {
                    Err::<NativePendingActionStageDisposition, String>(error.to_string())
                };
                if request.pending_encoded != request.pending.encode() {
                    outcomes[index] = Some(reject(anyhow!(
                        "native pending-action group encoded bytes mismatch"
                    )));
                    continue;
                }
                if request.verified_tip.is_some_and(|tip| tip != expected_tip) {
                    outcomes[index] = Some(Ok(NativePendingActionStageDisposition::TipChanged));
                    continue;
                }
                if is_poseidon2_v8_action(&request.pending)
                    && request.verified_tip != Some(expected_tip)
                {
                    outcomes[index] = Some(reject(anyhow!(
                        "native V8 pending action lacks proof/state verification at the canonical tip"
                    )));
                    continue;
                }
                if projected_count >= MAX_NATIVE_MEMPOOL_ACTIONS {
                    outcomes[index] = Some(reject(anyhow!("native mempool full")));
                    continue;
                }
                let budget = NativeMempoolByteBudgetAdmissionInput {
                    pending_bytes: projected_bytes,
                    candidate_bytes: request.pending_encoded.len(),
                    max_bytes: MAX_NATIVE_MEMPOOL_ACTION_BYTES,
                };
                let next_projected_bytes =
                    match evaluate_native_mempool_byte_budget_admission(budget) {
                        Ok(total) => total,
                        Err(rejection) => {
                            outcomes[index] = Some(reject(native_resource_budget_admission_error(
                                budget.pending_bytes,
                                budget.candidate_bytes,
                                budget.max_bytes,
                                rejection,
                            )));
                            continue;
                        }
                    };

                let tx_duplicate = state.pending_actions.contains_key(&request.pending.tx_hash)
                    || accepted_tx_hashes.contains(&request.pending.tx_hash);
                if tx_duplicate {
                    if request.ignore_duplicate {
                        outcomes[index] = Some(Ok(NativePendingActionStageDisposition::Duplicate));
                        if accepted_tx_hashes.contains(&request.pending.tx_hash) {
                            requires_commit[index] = true;
                        }
                    } else {
                        outcomes[index] = Some(reject(anyhow!("duplicate pending action")));
                    }
                    continue;
                }
                let semantic_duplicate = pending_action_semantic_duplicate_exists(
                    &state,
                    &request.pending_semantic_hash,
                ) || accepted_semantic_hashes
                    .contains(&request.pending_semantic_hash);
                if semantic_duplicate {
                    if request.ignore_duplicate {
                        outcomes[index] = Some(Ok(NativePendingActionStageDisposition::Duplicate));
                        if accepted_semantic_hashes.contains(&request.pending_semantic_hash) {
                            requires_commit[index] = true;
                        }
                    } else {
                        outcomes[index] =
                            Some(reject(anyhow!("duplicate semantic pending action")));
                    }
                    continue;
                }
                #[cfg(test)]
                let validation = if request.bypass_active_route_for_group_engine_test {
                    validate_pending_action_against_mempool_state_for_group_engine_test(
                        &state,
                        &request.pending,
                    )
                } else {
                    validate_pending_action_against_mempool_state(&state, &request.pending)
                };
                #[cfg(not(test))]
                let validation =
                    validate_pending_action_against_mempool_state(&state, &request.pending);
                if let Err(err) = validation {
                    outcomes[index] = Some(reject(err));
                    continue;
                }
                if request
                    .pending
                    .nullifiers
                    .iter()
                    .any(|nullifier| accepted_nullifiers.contains(nullifier))
                {
                    outcomes[index] = Some(reject(anyhow!(
                        "duplicate nullifier across native pending actions"
                    )));
                    continue;
                }
                let replay_key = match bridge_inbound_replay_key_from_action(&request.pending) {
                    Ok(replay_key) => replay_key,
                    Err(err) => {
                        outcomes[index] = Some(reject(err));
                        continue;
                    }
                };
                if replay_key.is_some_and(|key| accepted_bridge_replay_keys.contains(&key)) {
                    outcomes[index] =
                        Some(reject(anyhow!("inbound bridge message already pending")));
                    continue;
                }
                if let Some((binding_hash, proof)) = &request.consumed_staged_proof {
                    let proof_key = hex64(binding_hash);
                    let staged_matches = state
                        .staged_proofs
                        .get(&proof_key)
                        .is_some_and(|current| current == proof);
                    if !staged_matches {
                        let message = if state.staged_proofs.contains_key(&proof_key) {
                            "staged proof changed before native pending action stage"
                        } else {
                            "staged proof missing before native pending action stage"
                        };
                        outcomes[index] = Some(reject(anyhow!(message)));
                        continue;
                    }
                    if !consumed_staged_proofs.insert(*binding_hash) {
                        outcomes[index] = Some(reject(anyhow!(
                            "staged proof already reserved by pending-action group"
                        )));
                        continue;
                    }
                }

                projected_count = projected_count.saturating_add(1);
                projected_bytes = next_projected_bytes;
                accepted_tx_hashes.insert(request.pending.tx_hash);
                accepted_semantic_hashes.insert(request.pending_semantic_hash);
                accepted_nullifiers.extend(request.pending.nullifiers.iter().copied());
                if let Some(replay_key) = replay_key {
                    accepted_bridge_replay_keys.insert(replay_key);
                }
                accepted_indices.push(index);
                requires_commit[index] = true;
                outcomes[index] = Some(Ok(NativePendingActionStageDisposition::Inserted));

                if is_shielded_transfer_action(&request.pending) && !candidates_projected_dropped {
                    for hash in pending_candidate_artifact_hashes(&state) {
                        let Some(candidate) = state.pending_actions.get(&hash) else {
                            continue;
                        };
                        projected_count = projected_count.saturating_sub(1);
                        projected_bytes =
                            projected_bytes.saturating_sub(pending_action_mempool_bytes(candidate));
                        dropped_candidates.push((candidate.clone(), candidate.encode()));
                    }
                    candidates_projected_dropped = true;
                }
            }

            if accepted_indices
                .iter()
                .any(|index| is_poseidon2_v8_action(&batch[*index].pending))
            {
                let mut projected_v8 = state
                    .pending_actions
                    .values()
                    .filter(|action| is_poseidon2_v8_action(action))
                    .collect::<Vec<_>>();
                projected_v8.extend(
                    accepted_indices
                        .iter()
                        .map(|index| &batch[*index].pending)
                        .filter(|action| is_poseidon2_v8_action(action)),
                );
                let aggregate_verification = state
                    .best
                    .height
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("native V8 pending batch height overflow"))
                    .and_then(|candidate_height| {
                        self.verify_poseidon2_v8_action_batch_against_parent(
                            &projected_v8,
                            &state.best,
                            candidate_height,
                        )
                    });
                if let Err(error) = aggregate_verification {
                    let error = format!(
                        "native V8 pending aggregate proof/state verification rejected: {error}"
                    );
                    for index in accepted_indices.drain(..) {
                        requires_commit[index] = false;
                        outcomes[index] = Some(Err(error.clone()));
                    }
                    dropped_candidates.clear();
                }
            }

            (
                expected_tip,
                expected_canonical_generation,
                expected_pending_generation,
                accepted_indices,
                dropped_candidates,
            )
        };

        if accepted_indices.is_empty() {
            return outcomes
                .into_iter()
                .map(|outcome| {
                    outcome.unwrap_or_else(|| {
                        Err("native pending-action group produced no outcome".to_owned())
                    })
                })
                .collect();
        }

        #[cfg(test)]
        if self
            .pending_action_group_commit_test
            .fail_next_transaction
            .swap(false, Ordering::AcqRel)
        {
            let error = "injected native pending-action group transaction failure".to_owned();
            for (index, requires_commit) in requires_commit.iter().copied().enumerate() {
                if requires_commit {
                    outcomes[index] = Some(Err(error.clone()));
                }
            }
            return outcomes.into_iter().map(Option::unwrap).collect();
        }

        let persisted: sled::transaction::TransactionResult<(), String> =
            (&self.action_tree, &self.da_proof_tree).transaction(|(action_tree, da_proof_tree)| {
                for (candidate, encoded) in &dropped_candidates {
                    match action_tree.get(candidate.tx_hash.as_ref())? {
                        Some(current) if current.as_ref() == encoded.as_slice() => {}
                        _ => {
                            return Err(sled::transaction::ConflictableTransactionError::Abort(
                                format!(
                                    "candidate {} changed before pending-action commit",
                                    hex48(candidate.tx_hash.as_bytes())
                                ),
                            ));
                        }
                    }
                }
                for index in &accepted_indices {
                    let request = &batch[*index];
                    if action_tree.get(request.pending.tx_hash.as_ref())?.is_some() {
                        return Err(sled::transaction::ConflictableTransactionError::Abort(
                            format!(
                                "pending action {} appeared before group commit",
                                hex48(request.pending.tx_hash.as_bytes())
                            ),
                        ));
                    }
                    if let Some((binding_hash, proof)) = &request.consumed_staged_proof {
                        match da_proof_tree.get(binding_hash.as_slice())? {
                            Some(current) if current.as_ref() == proof.as_slice() => {}
                            _ => {
                                return Err(
                                    sled::transaction::ConflictableTransactionError::Abort(
                                        format!(
                                            "staged proof {} changed before group commit",
                                            hex64(binding_hash)
                                        ),
                                    ),
                                );
                            }
                        }
                    }
                }
                for (candidate, _) in &dropped_candidates {
                    action_tree.remove(candidate.tx_hash.as_bytes().to_vec())?;
                }
                for index in &accepted_indices {
                    let request = &batch[*index];
                    action_tree.insert(
                        request.pending.tx_hash.as_bytes().to_vec(),
                        request.pending_encoded.clone(),
                    )?;
                    if let Some((binding_hash, _)) = &request.consumed_staged_proof {
                        da_proof_tree.remove(binding_hash.to_vec())?;
                    }
                }
                Ok(())
            });
        if let Err(err) = persisted {
            let error = format!("atomic native pending-action group failed: {err}");
            for (index, requires_commit) in requires_commit.iter().copied().enumerate() {
                if requires_commit {
                    outcomes[index] = Some(Err(error.clone()));
                }
            }
            return outcomes.into_iter().map(Option::unwrap).collect();
        }

        if let Err(flush_error) = self.flush_pending_action_group_commit() {
            let rollback = self.rollback_pending_action_group_commit_persistence(
                batch,
                &accepted_indices,
                &dropped_candidates,
            );
            let error = match rollback {
                Ok(()) => format!("native pending-action group durability failed: {flush_error}"),
                Err(rollback_error) => {
                    self.poison_native_storage();
                    format!(
                        "native pending-action group durability failed: {flush_error}; {rollback_error}; storage fail-stop engaged"
                    )
                }
            };
            for (index, requires_commit) in requires_commit.iter().copied().enumerate() {
                if requires_commit {
                    outcomes[index] = Some(Err(error.clone()));
                }
            }
            return outcomes.into_iter().map(Option::unwrap).collect();
        }

        let publication_error = {
            let mut state = self.state.write();
            let tip_matches = (state.best.height, state.best.hash) == expected_tip
                && self.canonical_state_generation.load(Ordering::Acquire)
                    == expected_canonical_generation;
            let pending_matches = self.pending_action_generation.load(Ordering::Acquire)
                == expected_pending_generation;
            let exact_pending_matches = dropped_candidates.iter().all(|(candidate, encoded)| {
                state
                    .pending_actions
                    .get(&candidate.tx_hash)
                    .is_some_and(|current| current.encode().as_slice() == encoded.as_slice())
            }) && accepted_indices.iter().all(|index| {
                !state
                    .pending_actions
                    .contains_key(&batch[*index].pending.tx_hash)
            });
            if !tip_matches || !pending_matches || !exact_pending_matches {
                Some(if !tip_matches {
                    "canonical state changed during pending-action durability".to_owned()
                } else {
                    "pending state changed during pending-action durability".to_owned()
                })
            } else {
                let mut published_candidates = Vec::new();
                let mut published_actions = Vec::new();
                let mut error = None;
                for (candidate, _) in &dropped_candidates {
                    if let Some(removed) =
                        remove_pending_action_from_state(&mut state, &candidate.tx_hash)
                    {
                        published_candidates.push(removed);
                    }
                }
                for index in &accepted_indices {
                    let request = &batch[*index];
                    match insert_pending_action_into_state(&mut state, request.pending.clone()) {
                        Ok(_) => published_actions.push(request.pending.tx_hash),
                        Err(err) => {
                            error = Some(format!(
                                "publish durable pending-action group failed: {err}"
                            ));
                            break;
                        }
                    }
                }
                if let Some(error) = error {
                    for hash in published_actions.iter().rev() {
                        remove_pending_action_from_state(&mut state, hash);
                    }
                    let mut rollback_error = None;
                    for candidate in published_candidates {
                        if let Err(restore_error) =
                            insert_pending_action_into_state(&mut state, candidate)
                        {
                            rollback_error = Some(restore_error);
                            break;
                        }
                    }
                    if rollback_error.is_some() {
                        self.poison_native_storage();
                    }
                    Some(match rollback_error {
                        Some(rollback_error) => {
                            format!("{error}; in-memory rollback failed: {rollback_error}")
                        }
                        None => error,
                    })
                } else {
                    for index in &accepted_indices {
                        if let Some((binding_hash, proof)) = &batch[*index].consumed_staged_proof {
                            let proof_key = hex64(binding_hash);
                            if state
                                .staged_proofs
                                .get(&proof_key)
                                .is_some_and(|current| current == proof)
                            {
                                state.staged_proofs.remove(&proof_key);
                            }
                        }
                    }
                    self.pending_action_generation
                        .fetch_add(1, Ordering::Release);
                    None
                }
            }
        };

        if let Some(publication_error) = publication_error {
            let rollback = self.rollback_pending_action_group_commit_persistence(
                batch,
                &accepted_indices,
                &dropped_candidates,
            );
            let error = match rollback {
                Ok(()) => publication_error,
                Err(rollback_error) => {
                    self.poison_native_storage();
                    format!("{publication_error}; {rollback_error}; storage fail-stop engaged")
                }
            };
            for (index, requires_commit) in requires_commit.iter().copied().enumerate() {
                if requires_commit {
                    outcomes[index] = Some(Err(error.clone()));
                }
            }
        }

        outcomes.into_iter().map(Option::unwrap).collect()
    }

    fn stage_pending_action_through_group_commit(
        &self,
        pending: PendingAction,
        pending_encoded: Vec<u8>,
        pending_semantic_hash: ActionSemanticId48,
        verified_tip: Option<(u64, [u8; 32])>,
        consumed_staged_proof: Option<([u8; 64], Vec<u8>)>,
        ignore_duplicate: bool,
        #[cfg(test)] bypass_active_route_for_group_engine_test: bool,
    ) -> Result<NativePendingActionStageDisposition> {
        self.ensure_native_storage_healthy()?;
        if pending_encoded.len() > MAX_NATIVE_PENDING_ACTION_GROUP_COMMIT_BYTES {
            return Err(anyhow!(
                "native pending action exceeds group-commit batch byte limit"
            ));
        }
        let completion = Arc::new(NativePendingActionCommitCompletion::new());
        {
            let mut group = self.pending_action_group_commit.state.lock();
            let queued_bytes = group
                .queued_bytes
                .checked_add(pending_encoded.len())
                .ok_or_else(|| anyhow!("native pending-action group queue byte overflow"))?;
            if group.queue.len() >= MAX_NATIVE_PENDING_ACTION_GROUP_COMMIT_QUEUE
                || queued_bytes > MAX_NATIVE_PENDING_ACTION_GROUP_COMMIT_QUEUE_BYTES
            {
                return Err(anyhow!(
                    "native pending-action durability queue at capacity; retry submission"
                ));
            }
            group.queued_bytes = queued_bytes;
            group.queue.push_back(NativePendingActionCommitRequest {
                pending,
                pending_encoded,
                pending_semantic_hash,
                verified_tip,
                consumed_staged_proof,
                ignore_duplicate,
                #[cfg(test)]
                bypass_active_route_for_group_engine_test,
                completion: Arc::clone(&completion),
            });
            self.pending_action_group_commit.wake.notify_all();
        }

        loop {
            if let Some(result) = completion.result.lock().take() {
                return result.map_err(anyhow::Error::msg);
            }
            let become_leader = {
                let mut group = self.pending_action_group_commit.state.lock();
                if !group.active {
                    group.active = true;
                    true
                } else {
                    self.pending_action_group_commit.wake.wait(&mut group);
                    false
                }
            };
            if !become_leader {
                continue;
            }

            let _leader = NativePendingActionGroupLeaderGuard {
                group: &self.pending_action_group_commit,
            };
            let batch = self.take_pending_action_group_commit_batch();
            if batch.is_empty() {
                continue;
            }
            let mut completion_guard = NativePendingActionBatchCompletionGuard {
                batch,
                completed: false,
            };
            let results = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                #[cfg(test)]
                if self
                    .pending_action_group_commit_test
                    .panic_after_drain
                    .swap(false, Ordering::AcqRel)
                {
                    panic!("injected pending-action group leader panic");
                }
                self.process_pending_action_group_commit_batch(&completion_guard.batch)
            }))
            .unwrap_or_else(|_| {
                vec![
                    Err("native pending-action group commit panicked".to_owned());
                    completion_guard.batch.len()
                ]
            });
            let mut results = results.into_iter();
            for request in &completion_guard.batch {
                *request.completion.result.lock() = Some(results.next().unwrap_or_else(|| {
                    Err("native pending-action group omitted a completion".to_owned())
                }));
            }
            completion_guard.completed = true;
        }
    }

    /// Test-only entry into the durable batching mechanism. This deliberately
    /// skips RPC/relay proof preflight so high-concurrency tests measure the
    /// group-commit transaction, durability, publication, and panic recovery
    /// rather than exhausting the separately bounded proof lanes. The normal
    /// batch processor still enforces exact identity, mempool, nullifier,
    /// semantic-index, and byte-budget invariants. This seam intentionally
    /// bypasses the outer route and authoring-policy gates; every production
    /// caller enables both gates.
    #[cfg(test)]
    pub(crate) fn stage_pending_action_group_commit_for_test(
        &self,
        pending: PendingAction,
        peer_duplicate_semantics: bool,
    ) -> Result<PendingAction> {
        let (_, pending_semantic_hash) = validate_pending_action_identity(&pending)?;
        let pending_encoded = pending.encode();
        match self.stage_pending_action_through_group_commit(
            pending.clone(),
            pending_encoded,
            pending_semantic_hash,
            None,
            None,
            peer_duplicate_semantics,
            true,
        )? {
            NativePendingActionStageDisposition::Inserted => Ok(pending),
            NativePendingActionStageDisposition::Duplicate => {
                Err(anyhow!("test pending action was a duplicate"))
            }
            NativePendingActionStageDisposition::TipChanged => Err(anyhow!(
                "canonical tip changed during direct group-commit test"
            )),
        }
    }

    /// Test-only entry that models a V8 action whose individual proof/state
    /// preflight returned a token for the current tip. The batch's aggregate
    /// count, byte, and root-chain checks remain authoritative; production
    /// obtains such a token only from the source verifier.
    #[cfg(test)]
    pub(crate) fn stage_poseidon2_v8_pending_action_group_commit_for_test(
        &self,
        pending: PendingAction,
    ) -> Result<PendingAction> {
        if !is_poseidon2_v8_action(&pending) {
            return Err(anyhow!("test V8 group seam requires action 10"));
        }
        let (_, pending_semantic_hash) = validate_pending_action_identity(&pending)?;
        let pending_encoded = pending.encode();
        let best = self.best_meta();
        match self.stage_pending_action_through_group_commit(
            pending.clone(),
            pending_encoded,
            pending_semantic_hash,
            Some((best.height, best.hash)),
            None,
            false,
            true,
        )? {
            NativePendingActionStageDisposition::Inserted => Ok(pending),
            NativePendingActionStageDisposition::Duplicate => {
                Err(anyhow!("test V8 pending action was a duplicate"))
            }
            NativePendingActionStageDisposition::TipChanged => Err(anyhow!(
                "canonical tip changed during direct V8 group-commit test"
            )),
        }
    }

    pub(crate) fn submit_action(&self, request: Value) -> Value {
        let action = match self.validate_and_stage_action(request) {
            Ok(action) => action,
            Err(err) => {
                return serde_json::json!({
                "success": false,
                "tx_hash": null,
                "error": err.to_string(),
                });
            }
        };

        let tx_hash = hex48(action.tx_hash.as_bytes());
        self.broadcast_pending_action(&action);
        json!({
            "success": true,
            "tx_hash": tx_hash,
            "error": null,
        })
    }

    fn authorized_inline_pending_action(
        binding: KernelVersionBinding,
        family_id: u16,
        action_id: u16,
        nullifiers: Vec<[u8; 48]>,
        public_args: Vec<u8>,
    ) -> Result<PendingAction> {
        let args: ShieldedTransferInlineArgs =
            decode_scale_exact(&public_args, "shielded inline action args")?;
        let (_, ciphertext_hashes, ciphertext_sizes) = admitted_inline_ciphertext_metadata(
            public_args.len(),
            args.proof.len(),
            &args.ciphertexts,
        )?;
        validate_binding_hash(
            args.anchor,
            &nullifiers,
            &args.commitments,
            &ciphertext_hashes,
            args.balance_slot_asset_ids,
            args.fee,
            args.binding_hash,
            args.stablecoin,
        )?;
        Ok(PendingAction {
            tx_hash: ActionId48::ZERO,
            binding,
            family_id,
            action_id,
            anchor: args.anchor,
            nullifiers,
            commitments: args.commitments,
            ciphertext_hashes,
            ciphertext_sizes,
            public_args,
            fee: args.fee,
            candidate_artifact: None,
        })
    }

    /// Run the exact JSON, request-projection, base64, SCALE, inline-resource,
    /// and binding-hash stages used by production after its outer route and
    /// version-authority gates. This does not stage, verify, or authorize an
    /// action and is absent from production binaries.
    #[cfg(test)]
    pub(crate) fn parse_inline_action_rpc_after_authority_for_test(
        &self,
        request: Value,
    ) -> Result<PendingAction> {
        let request = decode_submit_action_rpc_request(request)?;
        if (request.family_id, request.action_id)
            != (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE)
        {
            return Err(anyhow!(
                "test inline RPC seam requires the inline transfer route"
            ));
        }
        let binding = KernelVersionBinding {
            circuit: request.binding_circuit,
            crypto: request.binding_crypto,
        };
        let public_args = admit_native_action_request_projection(&request)?;
        let nullifiers = request
            .new_nullifiers
            .iter()
            .map(|raw| parse_hex48(raw).ok_or_else(|| anyhow!("invalid nullifier hex")))
            .collect::<Result<Vec<_>>>()?;
        Self::authorized_inline_pending_action(
            binding,
            request.family_id,
            request.action_id,
            nullifiers,
            public_args,
        )
    }

    pub(crate) fn validate_and_stage_action(&self, request: Value) -> Result<PendingAction> {
        let request = decode_submit_action_rpc_request(request)?;
        ensure_native_v3_active_action_route_ids(request.family_id, request.action_id, false)?;
        let binding = KernelVersionBinding {
            circuit: request.binding_circuit,
            crypto: request.binding_crypto,
        };
        let current_height = self.best_height();
        let action_height = validate_native_action_authoring_version_policy(
            current_height,
            binding,
            request.family_id,
            request.action_id,
        )?;
        let public_args = admit_native_action_request_projection(&request)?;
        let outer_nullifier_route =
            native_submit_action_uses_outer_nullifiers(request.family_id, request.action_id);
        let mut consumed_staged_proof: Option<([u8; 64], Vec<u8>)> = None;
        let nullifiers = if outer_nullifier_route {
            request
                .new_nullifiers
                .iter()
                .map(|raw| parse_hex48(raw).ok_or_else(|| anyhow!("invalid nullifier hex")))
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };

        let mut pending = match (request.family_id, request.action_id) {
            (
                FAMILY_BRIDGE,
                ACTION_BRIDGE_OUTBOUND | ACTION_BRIDGE_INBOUND | ACTION_REGISTER_BRIDGE_VERIFIER,
            ) => PendingAction {
                tx_hash: ActionId48::ZERO,
                binding,
                family_id: request.family_id,
                action_id: request.action_id,
                anchor: [0u8; 48],
                nullifiers: Vec::new(),
                commitments: Vec::new(),
                ciphertext_hashes: Vec::new(),
                ciphertext_sizes: Vec::new(),
                public_args,
                fee: 0,
                candidate_artifact: None,
            },
            (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE) => {
                Self::authorized_inline_pending_action(
                    binding,
                    request.family_id,
                    request.action_id,
                    nullifiers,
                    public_args,
                )?
            }
            (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_SIDECAR) => {
                let mut args: ShieldedTransferSidecarArgs =
                    decode_scale_exact(&public_args, "shielded sidecar action args")?;
                let public_args = if args.proof.is_empty() {
                    let proof_key = hex64(&args.binding_hash);
                    let proof = self
                        .state
                        .read()
                        .staged_proofs
                        .get(&proof_key)
                        .cloned()
                        .ok_or_else(|| anyhow!("missing staged proof for {proof_key}"))?;
                    consumed_staged_proof = Some((args.binding_hash, proof.clone()));
                    args.proof = proof;
                    args.encode()
                } else {
                    public_args
                };
                validate_binding_hash(
                    args.anchor,
                    &nullifiers,
                    &args.commitments,
                    &args.ciphertext_hashes,
                    args.balance_slot_asset_ids,
                    args.fee,
                    args.binding_hash,
                    args.stablecoin,
                )?;
                PendingAction {
                    tx_hash: ActionId48::ZERO,
                    binding,
                    family_id: request.family_id,
                    action_id: request.action_id,
                    anchor: args.anchor,
                    nullifiers,
                    commitments: args.commitments,
                    ciphertext_hashes: args.ciphertext_hashes,
                    ciphertext_sizes: args.ciphertext_sizes,
                    public_args,
                    fee: args.fee,
                    candidate_artifact: None,
                }
            }
            (FAMILY_SHIELDED_POOL, ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE) => {
                let production =
                    poseidon2_v8_verifier::Poseidon2V8ProductionBinding::require_source_at(
                        action_height,
                    )
                    .map_err(|error| anyhow!("native V8 RPC authority rejected: {error}"))?;
                poseidon2_v8_verifier::pending_poseidon2_v8_action_from_inline_args(
                    production,
                    action_height,
                    binding,
                    public_args,
                )
                .map_err(|error| anyhow!("native V8 RPC action rejected: {error}"))?
            }
            (FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT) => {
                return Err(anyhow!(
                    "candidate artifact submissions are retired; blocks carry independent SmallWood transaction proofs"
                ));
            }
            (FAMILY_SHIELDED_POOL, ACTION_MINT_COINBASE) => {
                return Err(anyhow!(
                    "coinbase actions are internal mining outputs and cannot be submitted"
                ));
            }
            (_, other) => return Err(anyhow!("unsupported native action {other}")),
        };

        self.validate_action_state(&pending)?;
        let (pending_action_id, pending_semantic_hash) = pending_action_identity_hashes(&pending);
        pending.tx_hash = pending_action_id;
        let pending_encoded = pending.encode();
        let proof_admission = if is_shielded_transfer_action(&pending) {
            let admission_key = self
                .begin_validated_pending_proof_admission(pending_semantic_hash)?
                .ok_or_else(|| {
                    anyhow!("native pending action proof verification already in flight")
                })?;
            let admission_guard = self.pending_proof_admission_guard(admission_key);
            let local_permit = match Arc::clone(&self.local_pending_proof_admission_semaphore)
                .try_acquire_owned()
            {
                Ok(permit) => permit,
                Err(_) => {
                    return Err(anyhow!(
                        "native local pending proof verifier at capacity; retry submission"
                    ));
                }
            };
            let permit =
                match Arc::clone(&self.pending_proof_admission_semaphore).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        return Err(anyhow!(
                            "native pending proof verifier at capacity; retry submission"
                        ));
                    }
                };
            Some((admission_guard, local_permit, permit))
        } else {
            None
        };

        let stage_result = (|| -> Result<PendingAction> {
            for preflight_attempt in 0..MAX_NATIVE_PENDING_PROOF_PREFLIGHT_RETRIES {
                let verified_tip = if is_shielded_transfer_action(&pending) {
                    let (best, commitment_tree) = {
                        let state = self.state.read();
                        if state.pending_actions.len() >= MAX_NATIVE_MEMPOOL_ACTIONS {
                            return Err(anyhow!("native mempool full"));
                        }
                        validate_mempool_byte_budget_for_state(
                            &state,
                            &pending,
                            MAX_NATIVE_MEMPOOL_ACTION_BYTES,
                        )?;
                        if state.pending_actions.contains_key(&pending.tx_hash) {
                            return Err(anyhow!("duplicate pending action"));
                        }
                        if pending_action_semantic_duplicate_exists(&state, &pending_semantic_hash)
                        {
                            return Err(anyhow!("duplicate semantic pending action"));
                        }
                        validate_pending_action_against_mempool_state(&state, &pending)?;
                        (state.best.clone(), state.commitment_tree.clone())
                    };
                    if self.rejected_pending_action_is_cached(&best.hash, &pending_semantic_hash) {
                        return Err(anyhow!(
                            "native pending action was deterministically rejected recently"
                        ));
                    }
                    if let Err(failure) = self.preflight_pending_transfer_proof_against_parent(
                        &pending,
                        &best,
                        &commitment_tree,
                    ) {
                        let tip_changed = {
                            let state = self.state.read();
                            (state.best.height, state.best.hash) != (best.height, best.hash)
                        };
                        if tip_changed {
                            if preflight_attempt + 1 < MAX_NATIVE_PENDING_PROOF_PREFLIGHT_RETRIES {
                                continue;
                            }
                            return Err(anyhow!(
                                "canonical state changed during failed native proof preflight; retry submission"
                            ));
                        }
                        if failure.is_deterministic() {
                            self.remember_rejected_pending_action(
                                &best.hash,
                                pending_semantic_hash,
                            );
                        }
                        return Err(failure.into_anyhow());
                    }
                    Some((best.height, best.hash))
                } else {
                    None
                };

                match self.stage_pending_action_through_group_commit(
                    pending.clone(),
                    pending_encoded.clone(),
                    pending_semantic_hash,
                    verified_tip,
                    consumed_staged_proof.clone(),
                    false,
                    #[cfg(test)]
                    false,
                )? {
                    NativePendingActionStageDisposition::Inserted => return Ok(pending),
                    NativePendingActionStageDisposition::Duplicate => {
                        return Err(anyhow!("duplicate pending action"));
                    }
                    NativePendingActionStageDisposition::TipChanged => {
                        if preflight_attempt + 1 < MAX_NATIVE_PENDING_PROOF_PREFLIGHT_RETRIES {
                            continue;
                        }
                        return Err(anyhow!(
                            "canonical state changed during native proof preflight; retry submission"
                        ));
                    }
                }
            }

            Err(anyhow!(
                "native pending action proof preflight retry budget exhausted"
            ))
        })();
        drop(proof_admission);
        stage_result
    }

    pub(crate) fn stage_relayed_pending_action(
        &self,
        pending: PendingAction,
    ) -> Result<Option<PendingAction>> {
        let (_, semantic_hash) = validate_pending_action_identity(&pending)?;
        self.stage_relayed_pending_action_with_identity(pending, semantic_hash)
    }

    pub(crate) fn stage_relayed_pending_action_with_identity(
        &self,
        pending: PendingAction,
        pending_semantic_hash: ActionSemanticId48,
    ) -> Result<Option<PendingAction>> {
        ensure_native_v3_active_action_route(&pending, false)?;
        if !pending_action_peer_relayable(&pending) {
            return Err(anyhow!("native pending action route is not peer-relayable"));
        }
        if pending_semantic_hash != pending_action_semantic_id_from_action_id(pending.tx_hash) {
            return Err(anyhow!("native pending action semantic identity mismatch"));
        }
        if pending_action_mempool_bytes(&pending) > MAX_NATIVE_SYNC_PENDING_ACTION_BYTES {
            return Err(anyhow!(
                "native pending action exceeds peer relay limit of {MAX_NATIVE_SYNC_PENDING_ACTION_BYTES} bytes"
            ));
        }
        let initial_parent_hash = self.best_tip().1;
        if is_shielded_transfer_action(&pending)
            && self.rejected_pending_action_is_cached(&initial_parent_hash, &pending_semantic_hash)
        {
            return Err(anyhow!(
                "native pending action was deterministically rejected recently"
            ));
        }
        let pending_encoded = pending.encode();
        for preflight_attempt in 0..MAX_NATIVE_PENDING_PROOF_PREFLIGHT_RETRIES {
            let verified_tip = if is_shielded_transfer_action(&pending) {
                let (best, commitment_tree) = {
                    let state = self.state.read();
                    if state.pending_actions.len() >= MAX_NATIVE_MEMPOOL_ACTIONS {
                        return Err(anyhow!("native mempool full"));
                    }
                    validate_mempool_byte_budget_for_state(
                        &state,
                        &pending,
                        MAX_NATIVE_MEMPOOL_ACTION_BYTES,
                    )?;
                    if state.pending_actions.contains_key(&pending.tx_hash)
                        || pending_action_semantic_duplicate_exists(&state, &pending_semantic_hash)
                    {
                        return Ok(None);
                    }
                    validate_pending_action_against_mempool_state(&state, &pending)?;
                    (state.best.clone(), state.commitment_tree.clone())
                };
                if self.rejected_pending_action_is_cached(&best.hash, &pending_semantic_hash) {
                    return Err(anyhow!(
                        "native pending action was deterministically rejected recently"
                    ));
                }
                if let Err(failure) = self.preflight_pending_transfer_proof_against_parent(
                    &pending,
                    &best,
                    &commitment_tree,
                ) {
                    let tip_changed = {
                        let state = self.state.read();
                        (state.best.height, state.best.hash) != (best.height, best.hash)
                    };
                    if tip_changed {
                        if preflight_attempt + 1 < MAX_NATIVE_PENDING_PROOF_PREFLIGHT_RETRIES {
                            continue;
                        }
                        return Err(anyhow!(
                            "canonical state changed during failed relayed native proof preflight; retry relay"
                        ));
                    }
                    if failure.is_deterministic() {
                        self.remember_rejected_pending_action(&best.hash, pending_semantic_hash);
                    }
                    return Err(failure.into_anyhow());
                }
                Some((best.height, best.hash))
            } else {
                None
            };

            match self.stage_pending_action_through_group_commit(
                pending.clone(),
                pending_encoded.clone(),
                pending_semantic_hash,
                verified_tip,
                None,
                true,
                #[cfg(test)]
                false,
            )? {
                NativePendingActionStageDisposition::Inserted => return Ok(Some(pending)),
                NativePendingActionStageDisposition::Duplicate => return Ok(None),
                NativePendingActionStageDisposition::TipChanged => {
                    if preflight_attempt + 1 < MAX_NATIVE_PENDING_PROOF_PREFLIGHT_RETRIES {
                        continue;
                    }
                    return Err(anyhow!(
                        "canonical state changed during relayed native proof preflight; retry relay"
                    ));
                }
            }
        }
        Err(anyhow!(
            "relayed native pending action proof preflight retry budget exhausted"
        ))
    }

    pub(crate) fn validate_action_state(&self, action: &PendingAction) -> Result<()> {
        let state = self.state.read();
        validate_pending_action_against_mempool_state(&state, action)
    }

    pub(crate) fn submit_transaction(&self, _bundle: Value) -> Value {
        json!({
            "success": false,
            "tx_id": null,
            "error": "generic transaction submission is disabled; use hegemon_submitAction",
        })
    }

    pub(crate) fn submit_ciphertexts(&self, request: Value) -> Result<Value> {
        self.ensure_native_storage_healthy()?;
        let request = decode_submit_ciphertexts_rpc_request(request)?;
        let ciphertexts = request
            .ciphertexts
            .as_ref()
            .ok_or_else(|| anyhow!("da_submitCiphertexts requires ciphertexts array"))?;
        evaluate_native_ciphertext_sidecar_request_admission(
            NativeSidecarRequestCountAdmissionInput {
                item_count: ciphertexts.len(),
                max_items: MAX_NATIVE_DA_CIPHERTEXT_UPLOADS,
            },
        )
        .map_err(native_sidecar_upload_admission_error)?;
        let mut results = Vec::with_capacity(ciphertexts.len());
        let mut prepared_ciphertexts: Vec<([u8; 48], Vec<u8>, u32)> =
            Vec::with_capacity(ciphertexts.len());
        for ciphertext in ciphertexts {
            let raw =
                parse_bytes_value(ciphertext, MAX_CIPHERTEXT_BYTES, "ciphertext upload item")?;
            if raw.len() > MAX_CIPHERTEXT_BYTES {
                return Err(anyhow!(
                    "ciphertext size {} exceeds limit {}",
                    raw.len(),
                    MAX_CIPHERTEXT_BYTES
                ));
            }
            let hash = ciphertext_hash_bytes(&raw);
            let hash_hex = hex48(&hash);
            let size = u32::try_from(raw.len()).unwrap_or(u32::MAX);
            prepared_ciphertexts.push((hash, raw, size));
            results.push(json!({
                "hash": hash_hex,
                "size": size,
            }));
        }

        // Sidecar publication shares the action-tree persistence epoch because
        // canonical commits consume ciphertext rows in the same transaction as
        // pending-action removals. Only the epoch spans sled I/O; ordinary
        // state readers and unrelated state writers remain live during fsync.
        let _persistence_epoch = self.pending_action_persistence_lock.lock();
        self.ensure_native_storage_healthy()?;
        let (expected_staged_ciphertexts, staged_ciphertexts) = {
            let state = self.state.read();
            let expected = state.staged_ciphertexts.clone();
            let mut projected = expected.clone();
            for (hash, _, size) in &prepared_ciphertexts {
                let hash_hex = hex48(hash);
                evaluate_native_ciphertext_sidecar_capacity_admission(
                    NativeSidecarCapacityAdmissionInput {
                        staged_count: projected.len(),
                        max_staged_count: MAX_NATIVE_STAGED_CIPHERTEXTS,
                        replaces_existing: projected.contains_key(&hash_hex),
                    },
                )
                .map_err(native_sidecar_upload_admission_error)?;
                projected.insert(hash_hex, *size);
            }
            (expected, projected)
        };
        let writes = prepared_ciphertexts
            .iter()
            .map(|(hash, raw, _)| (hash.to_vec(), raw.clone()))
            .collect::<BTreeMap<_, _>>();
        let previous = writes
            .keys()
            .map(|key| {
                Ok((
                    key.clone(),
                    self.da_ciphertext_tree
                        .get(key.as_slice())?
                        .map(|bytes| bytes.to_vec()),
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        self.persist_sidecar_rows_exact(
            &self.da_ciphertext_tree,
            &writes,
            &previous,
            "native staged ciphertext upload",
        )?;
        if let Err(flush_error) = self.flush_native_durability_barrier(
            "native staged ciphertext upload",
            NativeStorageDurabilityOperation::CiphertextSidecarStage,
        ) {
            let rollback = self.rollback_sidecar_rows_exact(
                &self.da_ciphertext_tree,
                &writes,
                &previous,
                "native staged ciphertext upload rollback",
            );
            return Err(match rollback {
                Ok(()) => flush_error,
                Err(rollback_error) => {
                    self.poison_native_storage();
                    anyhow!("{flush_error}; {rollback_error}; storage fail-stop engaged")
                }
            });
        }
        let mut state = self.state.write();
        if state.staged_ciphertexts != expected_staged_ciphertexts {
            drop(state);
            let rollback = self.rollback_sidecar_rows_exact(
                &self.da_ciphertext_tree,
                &writes,
                &previous,
                "native staged ciphertext publication rollback",
            );
            return Err(match rollback {
                Ok(()) => anyhow!("staged ciphertext state changed during durability"),
                Err(rollback_error) => {
                    self.poison_native_storage();
                    anyhow!(
                        "staged ciphertext state changed during durability; {rollback_error}; storage fail-stop engaged"
                    )
                }
            });
        }
        publish_staged_ciphertexts(&mut state, staged_ciphertexts);
        Ok(Value::Array(results))
    }

    pub(crate) fn submit_proofs(&self, request: Value) -> Result<Value> {
        self.ensure_native_storage_healthy()?;
        let request = decode_submit_proofs_rpc_request(request)?;
        let proofs = request
            .proofs
            .as_ref()
            .ok_or_else(|| anyhow!("da_submitProofs requires proofs array"))?;
        evaluate_native_proof_sidecar_request_admission(NativeSidecarRequestCountAdmissionInput {
            item_count: proofs.len(),
            max_items: MAX_NATIVE_DA_PROOF_UPLOADS,
        })
        .map_err(native_sidecar_upload_admission_error)?;
        let mut results = Vec::with_capacity(proofs.len());
        let mut prepared_proofs: Vec<([u8; 64], Vec<u8>)> = Vec::with_capacity(proofs.len());
        // Preserve the cheap resource gate before artifact binding decode
        // without cloning every staged proof body on the RPC hot path.
        let (mut preflight_staged_bytes, mut preflight_staged_sizes) = {
            let state = self.state.read();
            (
                staged_proof_bytes(&state.staged_proofs),
                state
                    .staged_proofs
                    .iter()
                    .map(|(key, proof)| (key.clone(), proof.len()))
                    .collect::<BTreeMap<_, _>>(),
            )
        };
        for item in proofs {
            let binding_hash_value = item.binding_hash.as_deref();
            let binding_hash_bytes = binding_hash_value.and_then(parse_hex64);
            let proof_value = item.proof.as_ref();
            evaluate_native_proof_sidecar_metadata_admission(
                NativeProofSidecarMetadataAdmissionInput {
                    binding_hash_present: binding_hash_value.is_some(),
                    binding_hash_valid: binding_hash_bytes.is_some(),
                    proof_present: proof_value.is_some(),
                },
            )
            .map_err(native_sidecar_upload_admission_error)?;
            let binding_hash_bytes = binding_hash_bytes.expect("validated binding_hash hex shape");
            let binding_hash_key = hex64(&binding_hash_bytes);
            let proof = parse_bytes_value(
                proof_value.expect("validated proof presence"),
                NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
                "proof item proof",
            )?;
            let existing_bytes = preflight_staged_sizes
                .get(&binding_hash_key)
                .copied()
                .unwrap_or_default();
            let byte_budget = NativeStagedProofByteBudgetAdmissionInput {
                staged_bytes: preflight_staged_bytes,
                existing_bytes,
                proof_bytes: proof.len(),
                max_bytes: MAX_NATIVE_STAGED_PROOF_BYTES,
            };
            preflight_staged_bytes = evaluate_native_staged_proof_byte_budget_admission(
                byte_budget,
            )
            .map_err(|rejection| {
                native_resource_budget_admission_error(
                    byte_budget
                        .staged_bytes
                        .saturating_sub(byte_budget.existing_bytes),
                    byte_budget.proof_bytes,
                    byte_budget.max_bytes,
                    rejection,
                )
            })?;
            evaluate_native_proof_sidecar_capacity_admission(NativeSidecarCapacityAdmissionInput {
                staged_count: preflight_staged_sizes.len(),
                max_staged_count: MAX_NATIVE_STAGED_PROOFS,
                replaces_existing: preflight_staged_sizes.contains_key(&binding_hash_key),
            })
            .map_err(native_sidecar_upload_admission_error)?;
            preflight_staged_sizes.insert(binding_hash_key.clone(), proof.len());
            evaluate_native_proof_sidecar_decoded_admission(
                NativeProofSidecarDecodedAdmissionInput {
                    proof_bytes: proof.len(),
                    max_proof_bytes: NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
                    proof_binding_hash_matches_key:
                        native_tx_leaf_artifact_binding_hash_matches_key(binding_hash_bytes, &proof),
                },
            )
            .map_err(native_sidecar_upload_admission_error)?;
            let proof_hash =
                hash48_with_parts(&[b"da-proof-v1", binding_hash_bytes.as_slice(), &proof]);
            let proof_hash_hex = hex48(&proof_hash);
            let size = u32::try_from(proof.len()).unwrap_or(u32::MAX);
            prepared_proofs.push((binding_hash_bytes, proof.clone()));
            results.push(json!({
                "binding_hash": binding_hash_key,
                "proof_hash": proof_hash_hex,
                "size": size,
            }));
        }

        let _persistence_epoch = self.pending_action_persistence_lock.lock();
        self.ensure_native_storage_healthy()?;
        let (expected_staged_proofs, staged_proofs) = {
            let state = self.state.read();
            let expected = state.staged_proofs.clone();
            let mut projected = expected.clone();
            for (binding_hash, proof) in &prepared_proofs {
                let binding_hash_key = hex64(binding_hash);
                validate_staged_proof_byte_budget(
                    &projected,
                    &binding_hash_key,
                    proof.len(),
                    MAX_NATIVE_STAGED_PROOF_BYTES,
                )?;
                evaluate_native_proof_sidecar_capacity_admission(
                    NativeSidecarCapacityAdmissionInput {
                        staged_count: projected.len(),
                        max_staged_count: MAX_NATIVE_STAGED_PROOFS,
                        replaces_existing: projected.contains_key(&binding_hash_key),
                    },
                )
                .map_err(native_sidecar_upload_admission_error)?;
                projected.insert(binding_hash_key, proof.clone());
            }
            (expected, projected)
        };
        let writes = prepared_proofs
            .iter()
            .map(|(binding_hash, proof)| (binding_hash.to_vec(), proof.clone()))
            .collect::<BTreeMap<_, _>>();
        let previous = writes
            .keys()
            .map(|key| {
                Ok((
                    key.clone(),
                    self.da_proof_tree
                        .get(key.as_slice())?
                        .map(|bytes| bytes.to_vec()),
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        self.persist_sidecar_rows_exact(
            &self.da_proof_tree,
            &writes,
            &previous,
            "native staged proof upload",
        )?;
        if let Err(flush_error) = self.flush_native_durability_barrier(
            "native staged proof upload",
            NativeStorageDurabilityOperation::ProofSidecarStage,
        ) {
            let rollback = self.rollback_sidecar_rows_exact(
                &self.da_proof_tree,
                &writes,
                &previous,
                "native staged proof upload rollback",
            );
            return Err(match rollback {
                Ok(()) => flush_error,
                Err(rollback_error) => {
                    self.poison_native_storage();
                    anyhow!("{flush_error}; {rollback_error}; storage fail-stop engaged")
                }
            });
        }
        let mut state = self.state.write();
        if state.staged_proofs != expected_staged_proofs {
            drop(state);
            let rollback = self.rollback_sidecar_rows_exact(
                &self.da_proof_tree,
                &writes,
                &previous,
                "native staged proof publication rollback",
            );
            return Err(match rollback {
                Ok(()) => anyhow!("staged proof state changed during durability"),
                Err(rollback_error) => {
                    self.poison_native_storage();
                    anyhow!(
                        "staged proof state changed during durability; {rollback_error}; storage fail-stop engaged"
                    )
                }
            });
        }
        publish_staged_proofs(&mut state, staged_proofs);
        Ok(Value::Array(results))
    }

    pub(crate) fn hash_rate(&self) -> f64 {
        let elapsed = self.start_instant.elapsed().as_secs_f64();
        if elapsed <= 0.0 {
            return 0.0;
        }
        self.mining_hashes.load(Ordering::Relaxed) as f64 / elapsed
    }
}
