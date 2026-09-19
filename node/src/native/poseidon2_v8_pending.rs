//! Typed pending-chain planning for the SmallWood/Poseidon2 V8 lane.
//!
//! This module consumes only public transitions returned by the exact V8
//! verifier.  It deliberately does not parse proofs, inspect the legacy
//! transaction carrier, or consult the activation capability.  Pending actions
//! may be reordered into their unique root-dependency chain for block-template
//! construction.  Already-carried block actions must instead pass
//! [`verify_poseidon2_v8_block_order`] in their supplied order.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use super::poseidon2_v8_state::{
    Poseidon2V8Checkpoint, Poseidon2V8Nullifier, Poseidon2V8PublicTransition, Poseidon2V8Root,
    Poseidon2V8StablecoinEffect,
};
use super::{
    ActionId48, MAX_NATIVE_BLOCK_ACTION_BYTES, MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK,
    POSEIDON2_V8_MAX_PENDING_ACTION_BYTES,
};

/// A canonical pending action paired with the public transition extracted by
/// exact V8 proof verification.
///
/// `encoded_bytes` is the full canonical `PendingAction` encoding used by the
/// native block byte budget. `exact_leaf_bytes` is tracked separately so the
/// planner cannot mistake a nonempty outer carrier for a present proof leaf.
/// Production callers derive the former from `Encode::encoded_size` on the
/// already-canonical, action-id-bound carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Poseidon2V8PendingAction {
    action_id: ActionId48,
    encoded_bytes: usize,
    exact_leaf_bytes: usize,
    max_encoded_bytes: usize,
    transition: Poseidon2V8PublicTransition,
}

impl Poseidon2V8PendingAction {
    pub(crate) fn new(
        action_id: ActionId48,
        canonical_encoded_bytes: usize,
        exact_native_leaf: &[u8],
        transition: Poseidon2V8PublicTransition,
    ) -> Self {
        Self {
            action_id,
            encoded_bytes: canonical_encoded_bytes,
            exact_leaf_bytes: exact_native_leaf.len(),
            // Production callers supply a contextually decoded, source-verified
            // exact leaf. Select the larger cap only for exact additive framing;
            // unknown/historical forms retain the old conservative ceiling.
            max_encoded_bytes: if protocol_shielded_pool::poseidon2_production_transport::preflight_poseidon2_production_smza_native_leaf_exact(exact_native_leaf).is_ok() {
                super::POSEIDON2_V8_SMZA_MAX_PENDING_ACTION_BYTES
            } else {
                POSEIDON2_V8_MAX_PENDING_ACTION_BYTES
            },
            transition,
        }
    }

    pub(crate) const fn action_id(self) -> ActionId48 {
        self.action_id
    }

    pub(crate) const fn encoded_bytes(self) -> usize {
        self.encoded_bytes
    }

    pub(crate) const fn transition(self) -> Poseidon2V8PublicTransition {
        self.transition
    }
}

/// Aggregate native-block limits applied to the deterministic V8 prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Poseidon2V8PendingCaps {
    max_actions: usize,
    max_action_bytes: usize,
}

impl Poseidon2V8PendingCaps {
    pub(crate) const fn new(max_actions: usize, max_action_bytes: usize) -> Self {
        Self {
            max_actions,
            max_action_bytes,
        }
    }

    pub(crate) const fn native_block() -> Self {
        Self::new(
            MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK,
            MAX_NATIVE_BLOCK_ACTION_BYTES,
        )
    }
}

/// A unique full pending chain and the maximal aggregate-cap-bounded prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Poseidon2V8PendingPlan {
    ordered_action_ids: Vec<ActionId48>,
    selected_action_ids: Vec<ActionId48>,
    deferred_action_ids: Vec<ActionId48>,
    selected_action_bytes: usize,
    selected_final_root: Poseidon2V8Root,
    full_final_root: Poseidon2V8Root,
}

impl Poseidon2V8PendingPlan {
    pub(crate) fn ordered_action_ids(&self) -> &[ActionId48] {
        &self.ordered_action_ids
    }

    pub(crate) fn selected_action_ids(&self) -> &[ActionId48] {
        &self.selected_action_ids
    }

    pub(crate) fn deferred_action_ids(&self) -> &[ActionId48] {
        &self.deferred_action_ids
    }

    pub(crate) const fn selected_action_bytes(&self) -> usize {
        self.selected_action_bytes
    }

    pub(crate) const fn selected_final_root(&self) -> Poseidon2V8Root {
        self.selected_final_root
    }

    pub(crate) const fn full_final_root(&self) -> Poseidon2V8Root {
        self.full_final_root
    }

    /// V8 actions never consume the historical 48-byte transfer DA budget.
    pub(crate) const fn selected_legacy_da_bytes(&self) -> usize {
        0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum Poseidon2V8PendingError {
    #[error("V8 pending action has an empty exact native leaf")]
    EmptyAction { action_id: ActionId48 },
    #[error("V8 pending action has an empty canonical outer carrier")]
    EmptyCarrier { action_id: ActionId48 },
    #[error("V8 pending action carrier is shorter than its exact native leaf")]
    CarrierShorterThanLeaf { action_id: ActionId48 },
    #[error("V8 pending action carrier exceeds its route-specific byte cap")]
    CarrierTooLarge {
        action_id: ActionId48,
        observed: usize,
        maximum: usize,
    },
    #[error("duplicate V8 pending action id")]
    DuplicateActionId { action_id: ActionId48 },
    #[error("V8 pending action authenticates the wrong parent height")]
    ParentHeightMismatch {
        action_id: ActionId48,
        expected: u64,
        observed: u64,
    },
    #[error("V8 pending stablecoin effect disagrees with its public roots")]
    StablecoinEffectMismatch {
        action_id: ActionId48,
        effect: Poseidon2V8StablecoinEffect,
        before_root: Poseidon2V8Root,
        after_root: Poseidon2V8Root,
    },
    #[error("duplicate exact 56-byte V8 nullifier in pending chain")]
    DuplicateNullifier {
        action_id: ActionId48,
        nullifier: Poseidon2V8Nullifier,
    },
    #[error("ambiguous V8 pending siblings share one before root")]
    AmbiguousSibling {
        before_root: Poseidon2V8Root,
        first_action_id: ActionId48,
        second_action_id: ActionId48,
    },
    #[error("V8 pending root graph contains a cycle")]
    Cycle { root: Poseidon2V8Root },
    #[error("V8 pending root chain has a gap")]
    Gap {
        expected_root: Poseidon2V8Root,
        remaining_actions: usize,
    },
    #[error("supplied V8 block order does not continue the canonical root chain")]
    BlockOrderMismatch {
        index: usize,
        expected_root: Poseidon2V8Root,
        observed_root: Poseidon2V8Root,
    },
    #[error("supplied V8 block order is not canonical at one stablecoin root")]
    BlockCanonicalOrderMismatch {
        index: usize,
        expected_action_id: ActionId48,
        observed_action_id: ActionId48,
    },
    #[error("V8 pending aggregate action-byte accounting overflow")]
    ActionBytesOverflow,
}

/// Build the unique dependency order and choose its maximal deterministic
/// prefix under the supplied aggregate count and byte caps.
///
/// The prefix never skips an oversized candidate to include a descendant: once
/// either cap is reached, that action and the entire suffix remain deferred.
pub(crate) fn plan_poseidon2_v8_pending_chain(
    checkpoint: Poseidon2V8Checkpoint,
    actions: &[Poseidon2V8PendingAction],
    caps: Poseidon2V8PendingCaps,
) -> Result<Poseidon2V8PendingPlan, Poseidon2V8PendingError> {
    let index = validate_and_index_actions(checkpoint, actions)?;
    reject_root_cycles(actions, &index)?;
    let (ordered_indices, cursor) = canonical_order_indices(checkpoint.root(), actions, &index)?;

    let ordered_action_ids = ordered_indices
        .iter()
        .map(|index| actions[*index].action_id)
        .collect::<Vec<_>>();
    let mut selected_action_ids = Vec::new();
    let mut selected_action_bytes = 0usize;
    let mut selected_final_root = checkpoint.root();

    for action_index in ordered_indices.iter().copied() {
        let action = actions[action_index];
        if selected_action_ids.len() >= caps.max_actions {
            break;
        }
        let next_bytes = selected_action_bytes
            .checked_add(action.encoded_bytes)
            .ok_or(Poseidon2V8PendingError::ActionBytesOverflow)?;
        if next_bytes > caps.max_action_bytes {
            break;
        }
        selected_action_ids.push(action.action_id);
        selected_action_bytes = next_bytes;
        selected_final_root = action.transition.after_root();
    }

    let deferred_action_ids = ordered_action_ids[selected_action_ids.len()..].to_vec();
    Ok(Poseidon2V8PendingPlan {
        ordered_action_ids,
        selected_action_ids,
        deferred_action_ids,
        selected_action_bytes,
        selected_final_root,
        full_final_root: cursor,
    })
}

/// Verify block-carried V8 actions exactly as supplied.
///
/// Consensus/import callers must use this function rather than the pending
/// planner: root-dependent block order is committed by the block action root
/// and is not repaired by topological sorting.
pub(crate) fn verify_poseidon2_v8_block_order(
    checkpoint: Poseidon2V8Checkpoint,
    actions: &[Poseidon2V8PendingAction],
) -> Result<Poseidon2V8Root, Poseidon2V8PendingError> {
    let index = validate_and_index_actions(checkpoint, actions)?;
    reject_root_cycles(actions, &index)?;
    let (canonical_indices, final_root) =
        canonical_order_indices(checkpoint.root(), actions, &index)?;

    let mut cursor = checkpoint.root();
    for (index, (action, expected_index)) in actions
        .iter()
        .copied()
        .zip(canonical_indices.iter().copied())
        .enumerate()
    {
        let observed_root = action.transition.before_root();
        if observed_root != cursor {
            return Err(Poseidon2V8PendingError::BlockOrderMismatch {
                index,
                expected_root: cursor,
                observed_root,
            });
        }
        let expected_action_id = actions[expected_index].action_id;
        if action.action_id != expected_action_id {
            return Err(Poseidon2V8PendingError::BlockCanonicalOrderMismatch {
                index,
                expected_action_id,
                observed_action_id: action.action_id,
            });
        }
        cursor = action.transition.after_root();
    }
    debug_assert_eq!(cursor, final_root);
    Ok(final_root)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Poseidon2V8RootBucket {
    neutral_indices: Vec<usize>,
    advancing_index: Option<usize>,
}

fn validate_and_index_actions(
    checkpoint: Poseidon2V8Checkpoint,
    actions: &[Poseidon2V8PendingAction],
) -> Result<BTreeMap<Poseidon2V8Root, Poseidon2V8RootBucket>, Poseidon2V8PendingError> {
    let mut sorted_indices = (0..actions.len()).collect::<Vec<_>>();
    sorted_indices.sort_unstable_by_key(|index| actions[*index].action_id);

    let mut action_ids = BTreeSet::new();
    let mut nullifiers = BTreeSet::new();
    let mut by_before_root = BTreeMap::<Poseidon2V8Root, Poseidon2V8RootBucket>::new();
    for action_index in sorted_indices {
        let action = actions[action_index];
        if action.exact_leaf_bytes == 0 {
            return Err(Poseidon2V8PendingError::EmptyAction {
                action_id: action.action_id,
            });
        }
        if action.encoded_bytes == 0 {
            return Err(Poseidon2V8PendingError::EmptyCarrier {
                action_id: action.action_id,
            });
        }
        if action.encoded_bytes < action.exact_leaf_bytes {
            return Err(Poseidon2V8PendingError::CarrierShorterThanLeaf {
                action_id: action.action_id,
            });
        }
        if action.encoded_bytes > action.max_encoded_bytes {
            return Err(Poseidon2V8PendingError::CarrierTooLarge {
                action_id: action.action_id,
                observed: action.encoded_bytes,
                maximum: action.max_encoded_bytes,
            });
        }
        if !action_ids.insert(action.action_id) {
            return Err(Poseidon2V8PendingError::DuplicateActionId {
                action_id: action.action_id,
            });
        }
        let observed_height = action.transition.parent_height();
        if observed_height != checkpoint.height() {
            return Err(Poseidon2V8PendingError::ParentHeightMismatch {
                action_id: action.action_id,
                expected: checkpoint.height(),
                observed: observed_height,
            });
        }
        if !action.transition.stablecoin_effect_matches_roots() {
            return Err(Poseidon2V8PendingError::StablecoinEffectMismatch {
                action_id: action.action_id,
                effect: action.transition.stablecoin_effect(),
                before_root: action.transition.before_root(),
                after_root: action.transition.after_root(),
            });
        }
        for nullifier in action.transition.nullifiers().into_iter().flatten() {
            if !nullifiers.insert(nullifier) {
                return Err(Poseidon2V8PendingError::DuplicateNullifier {
                    action_id: action.action_id,
                    nullifier,
                });
            }
        }

        let before_root = action.transition.before_root();
        let bucket = by_before_root.entry(before_root).or_default();
        match action.transition.stablecoin_effect() {
            Poseidon2V8StablecoinEffect::DisabledNoWrite => {
                // `sorted_indices` is ordered by canonical action id, so this
                // is the exact deterministic neutral order committed to a
                // block at this stablecoin root.
                bucket.neutral_indices.push(action_index);
            }
            Poseidon2V8StablecoinEffect::Mint | Poseidon2V8StablecoinEffect::Burn => {
                if let Some(first_index) = bucket.advancing_index.replace(action_index) {
                    return Err(Poseidon2V8PendingError::AmbiguousSibling {
                        before_root,
                        first_action_id: actions[first_index].action_id,
                        second_action_id: action.action_id,
                    });
                }
            }
        }
    }
    Ok(by_before_root)
}

/// Produce the only canonical order: all neutral actions at the current root
/// in action-id order, followed by the root's optional Mint/Burn edge. The
/// advancing edge moves the cursor and repeats the rule at the next root.
fn canonical_order_indices(
    checkpoint_root: Poseidon2V8Root,
    actions: &[Poseidon2V8PendingAction],
    index: &BTreeMap<Poseidon2V8Root, Poseidon2V8RootBucket>,
) -> Result<(Vec<usize>, Poseidon2V8Root), Poseidon2V8PendingError> {
    let mut cursor = checkpoint_root;
    let mut ordered = Vec::with_capacity(actions.len());
    let mut visited_roots = BTreeSet::new();

    while let Some(bucket) = index.get(&cursor) {
        if !visited_roots.insert(cursor) {
            break;
        }
        ordered.extend(bucket.neutral_indices.iter().copied());
        let Some(advancing_index) = bucket.advancing_index else {
            break;
        };
        ordered.push(advancing_index);
        cursor = actions[advancing_index].transition.after_root();
    }

    if ordered.len() != actions.len() {
        return Err(Poseidon2V8PendingError::Gap {
            expected_root: cursor,
            remaining_actions: actions.len() - ordered.len(),
        });
    }
    Ok((ordered, cursor))
}

/// Detect every cycle in the functional graph of Mint/Burn edges, including
/// disconnected cycles. Disabled/no-write actions are not graph edges: they
/// leave the stablecoin root unchanged and are ordered inside their root bucket.
fn reject_root_cycles(
    actions: &[Poseidon2V8PendingAction],
    index: &BTreeMap<Poseidon2V8Root, Poseidon2V8RootBucket>,
) -> Result<(), Poseidon2V8PendingError> {
    let mut complete = BTreeSet::new();
    for start in index.keys().copied() {
        if complete.contains(&start) {
            continue;
        }
        let mut path = Vec::new();
        let mut path_roots = BTreeSet::new();
        let mut cursor = start;
        while let Some(action_index) = index.get(&cursor).and_then(|bucket| bucket.advancing_index)
        {
            if complete.contains(&cursor) {
                break;
            }
            if !path_roots.insert(cursor) {
                return Err(Poseidon2V8PendingError::Cycle { root: cursor });
            }
            path.push(cursor);
            cursor = actions[action_index].transition.after_root();
        }
        complete.extend(path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::poseidon2_v8_state::{Poseidon2V8NoteTreeState, Poseidon2V8Nullifier};

    fn root(seed: u64) -> Poseidon2V8Root {
        Poseidon2V8Root::new(core::array::from_fn(|index| seed + index as u64)).unwrap()
    }

    fn action_id(seed: u8) -> ActionId48 {
        ActionId48::new([seed; 48])
    }

    fn nullifier(limbs: [u64; 7]) -> Poseidon2V8Nullifier {
        Poseidon2V8Nullifier::new(limbs).unwrap()
    }

    fn checkpoint(root: Poseidon2V8Root) -> Poseidon2V8Checkpoint {
        Poseidon2V8Checkpoint::new(41, [0x41; 32], root)
    }

    fn pending(
        id_seed: u8,
        byte_len: usize,
        before: Poseidon2V8Root,
        after: Poseidon2V8Root,
    ) -> Poseidon2V8PendingAction {
        let bytes = vec![id_seed; byte_len];
        Poseidon2V8PendingAction::new(
            action_id(id_seed),
            bytes.len(),
            &bytes,
            Poseidon2V8PublicTransition::new(41, before, after),
        )
    }

    fn pending_with_nullifier(
        id_seed: u8,
        before: Poseidon2V8Root,
        after: Poseidon2V8Root,
        nullifier: Poseidon2V8Nullifier,
    ) -> Poseidon2V8PendingAction {
        let bytes = [id_seed; 8];
        let note_anchor = Poseidon2V8NoteTreeState::new_empty().unwrap().root();
        Poseidon2V8PendingAction::new(
            action_id(id_seed),
            bytes.len(),
            &bytes,
            Poseidon2V8PublicTransition::new_with_shielded_state(
                41,
                before,
                after,
                note_anchor,
                [Some(nullifier), None],
                [None, None],
            ),
        )
    }

    fn neutral_pending(
        id_seed: u8,
        byte_len: usize,
        root: Poseidon2V8Root,
    ) -> Poseidon2V8PendingAction {
        let bytes = vec![id_seed; byte_len];
        Poseidon2V8PendingAction::new(
            action_id(id_seed),
            bytes.len(),
            &bytes,
            Poseidon2V8PublicTransition::new_with_stablecoin_effect(
                41,
                root,
                root,
                Poseidon2V8StablecoinEffect::DisabledNoWrite,
            ),
        )
    }

    #[test]
    fn pending_order_follows_root_dependencies_not_hash_or_input_order() {
        let a = root(10);
        let b = root(20);
        let c = root(30);
        let (child_seed, parent_seed) = (1u8..=u8::MAX)
            .flat_map(|child_seed| {
                (1u8..=u8::MAX).map(move |parent_seed| (child_seed, parent_seed))
            })
            .find(|(child_seed, parent_seed)| {
                child_seed != parent_seed
                    && crate::native::pending_action_semantic_id_from_action_id(action_id(
                        *child_seed,
                    )) < crate::native::pending_action_semantic_id_from_action_id(action_id(
                        *parent_seed,
                    ))
            })
            .expect("two fixture action ids have strict semantic-hash order");
        // The dependent child sorts first by the production semantic hash and
        // is supplied first. Root dependency must still place its parent first.
        let child = pending(child_seed, 5, b, c);
        let parent = pending(parent_seed, 4, a, b);
        assert!(
            crate::native::pending_action_semantic_id_from_action_id(child.action_id())
                < crate::native::pending_action_semantic_id_from_action_id(parent.action_id())
        );

        let plan = plan_poseidon2_v8_pending_chain(
            checkpoint(a),
            &[child, parent],
            Poseidon2V8PendingCaps::new(2, 9),
        )
        .unwrap();

        assert_eq!(
            plan.ordered_action_ids(),
            &[parent.action_id(), child.action_id()]
        );
        assert_eq!(plan.selected_action_ids(), plan.ordered_action_ids());
        assert_eq!(plan.selected_final_root(), c);
        assert_eq!(plan.full_final_root(), c);
    }

    #[test]
    fn aggregate_caps_choose_one_deterministic_prefix_without_skipping() {
        let a = root(10);
        let b = root(20);
        let c = root(30);
        let d = root(40);
        let actions = [
            pending(3, 4, a, b),
            pending(2, 5, b, c),
            pending(1, 1, c, d),
        ];

        let plan = plan_poseidon2_v8_pending_chain(
            checkpoint(a),
            &actions,
            Poseidon2V8PendingCaps::new(3, 9),
        )
        .unwrap();
        assert_eq!(
            plan.selected_action_ids(),
            &[actions[0].action_id(), actions[1].action_id()]
        );
        assert_eq!(plan.deferred_action_ids(), &[actions[2].action_id()]);
        assert_eq!(plan.selected_action_bytes(), 9);
        assert_eq!(plan.selected_final_root(), c);
        assert_eq!(plan.full_final_root(), d);

        let byte_limited = plan_poseidon2_v8_pending_chain(
            checkpoint(a),
            &actions,
            Poseidon2V8PendingCaps::new(3, 8),
        )
        .unwrap();
        assert_eq!(
            byte_limited.selected_action_ids(),
            &[actions[0].action_id()]
        );
        assert_eq!(
            byte_limited.deferred_action_ids(),
            &[actions[1].action_id(), actions[2].action_id()]
        );
        assert_eq!(byte_limited.selected_action_bytes(), 4);
        assert_eq!(byte_limited.selected_final_root(), b);

        let count_limited = plan_poseidon2_v8_pending_chain(
            checkpoint(a),
            &actions,
            Poseidon2V8PendingCaps::new(1, usize::MAX),
        )
        .unwrap();
        assert_eq!(
            count_limited.selected_action_ids(),
            &[actions[0].action_id()]
        );
        assert_eq!(
            count_limited.deferred_action_ids(),
            &[actions[1].action_id(), actions[2].action_id()]
        );
        assert_eq!(count_limited.selected_final_root(), b);
    }

    #[test]
    fn aggregate_bytes_count_the_full_outer_carrier_not_only_the_exact_leaf() {
        let a = root(10);
        let b = root(20);
        let leaf = [7u8; 4];
        let action = Poseidon2V8PendingAction::new(
            action_id(7),
            9,
            &leaf,
            Poseidon2V8PublicTransition::new(41, a, b),
        );

        let deferred = plan_poseidon2_v8_pending_chain(
            checkpoint(a),
            &[action],
            Poseidon2V8PendingCaps::new(1, 8),
        )
        .unwrap();
        assert!(deferred.selected_action_ids().is_empty());
        assert_eq!(deferred.deferred_action_ids(), &[action.action_id()]);

        let selected = plan_poseidon2_v8_pending_chain(
            checkpoint(a),
            &[action],
            Poseidon2V8PendingCaps::new(1, 9),
        )
        .unwrap();
        assert_eq!(selected.selected_action_ids(), &[action.action_id()]);
        assert_eq!(selected.selected_action_bytes(), 9);

        let oversized = Poseidon2V8PendingAction::new(
            action_id(8),
            POSEIDON2_V8_MAX_PENDING_ACTION_BYTES + 1,
            &leaf,
            Poseidon2V8PublicTransition::new(41, a, b),
        );
        assert!(matches!(
            plan_poseidon2_v8_pending_chain(
                checkpoint(a),
                &[oversized],
                Poseidon2V8PendingCaps::native_block(),
            ),
            Err(Poseidon2V8PendingError::CarrierTooLarge {
                observed,
                maximum,
                ..
            }) if observed == POSEIDON2_V8_MAX_PENDING_ACTION_BYTES + 1
                && maximum == POSEIDON2_V8_MAX_PENDING_ACTION_BYTES
        ));
    }

    #[test]
    fn exact_56_byte_nullifiers_are_not_truncated_to_legacy_width() {
        let a = root(10);
        let b = root(20);
        let c = root(30);
        let first = nullifier([1, 2, 3, 4, 5, 6, 7]);
        let same_first_48_bytes = nullifier([1, 2, 3, 4, 5, 6, 8]);
        let actions = [
            pending_with_nullifier(1, a, b, first),
            pending_with_nullifier(2, b, c, same_first_48_bytes),
        ];

        let plan = plan_poseidon2_v8_pending_chain(
            checkpoint(a),
            &actions,
            Poseidon2V8PendingCaps::new(2, 16),
        )
        .unwrap();
        assert_eq!(plan.selected_action_ids().len(), 2);

        let duplicate = [
            pending_with_nullifier(1, a, b, first),
            pending_with_nullifier(2, b, c, first),
        ];
        assert!(matches!(
            plan_poseidon2_v8_pending_chain(
                checkpoint(a),
                &duplicate,
                Poseidon2V8PendingCaps::new(2, 16),
            ),
            Err(Poseidon2V8PendingError::DuplicateNullifier { nullifier, .. })
                if nullifier == first
        ));
    }

    #[test]
    fn rejects_gaps_two_action_cycles_and_ambiguous_siblings() {
        let a = root(10);
        let b = root(20);
        let c = root(30);
        let d = root(40);

        assert!(matches!(
            plan_poseidon2_v8_pending_chain(
                checkpoint(a),
                &[pending(1, 1, b, c)],
                Poseidon2V8PendingCaps::new(1, 1),
            ),
            Err(Poseidon2V8PendingError::Gap { .. })
        ));
        assert!(matches!(
            plan_poseidon2_v8_pending_chain(
                checkpoint(a),
                &[pending(1, 1, a, b), pending(2, 1, b, a)],
                Poseidon2V8PendingCaps::new(2, 2),
            ),
            Err(Poseidon2V8PendingError::Cycle { .. })
        ));
        assert!(matches!(
            plan_poseidon2_v8_pending_chain(
                checkpoint(a),
                &[pending(1, 1, a, b), pending(2, 1, a, d)],
                Poseidon2V8PendingCaps::new(2, 2),
            ),
            Err(Poseidon2V8PendingError::AmbiguousSibling { .. })
        ));
    }

    #[test]
    fn one_disabled_no_write_transition_is_neutral_but_mint_and_burn_self_loops_reject() {
        let a = root(10);
        let b = root(20);
        let leaf = [0x51u8];
        let neutral = Poseidon2V8PendingAction::new(
            action_id(1),
            leaf.len(),
            &leaf,
            Poseidon2V8PublicTransition::new_with_stablecoin_effect(
                41,
                a,
                a,
                Poseidon2V8StablecoinEffect::DisabledNoWrite,
            ),
        );
        let plan = plan_poseidon2_v8_pending_chain(
            checkpoint(a),
            &[neutral],
            Poseidon2V8PendingCaps::new(1, leaf.len()),
        )
        .unwrap();
        assert_eq!(plan.selected_action_ids(), &[neutral.action_id()]);
        assert_eq!(plan.selected_final_root(), a);
        assert_eq!(plan.full_final_root(), a);
        assert_eq!(
            verify_poseidon2_v8_block_order(checkpoint(a), &[neutral]).unwrap(),
            a
        );

        let forged_disabled_write = Poseidon2V8PendingAction::new(
            action_id(2),
            leaf.len(),
            &leaf,
            Poseidon2V8PublicTransition::new_with_stablecoin_effect(
                41,
                a,
                b,
                Poseidon2V8StablecoinEffect::DisabledNoWrite,
            ),
        );
        assert!(matches!(
            plan_poseidon2_v8_pending_chain(
                checkpoint(a),
                &[forged_disabled_write],
                Poseidon2V8PendingCaps::new(1, leaf.len()),
            ),
            Err(Poseidon2V8PendingError::StablecoinEffectMismatch {
                action_id: observed,
                ..
            }) if observed == forged_disabled_write.action_id()
        ));
        assert!(matches!(
            verify_poseidon2_v8_block_order(checkpoint(a), &[forged_disabled_write]),
            Err(Poseidon2V8PendingError::StablecoinEffectMismatch { .. })
        ));

        for effect in [
            Poseidon2V8StablecoinEffect::Mint,
            Poseidon2V8StablecoinEffect::Burn,
        ] {
            let state_writing_self_loop = Poseidon2V8PendingAction::new(
                action_id(2),
                leaf.len(),
                &leaf,
                Poseidon2V8PublicTransition::new_with_stablecoin_effect(41, a, a, effect),
            );
            assert!(matches!(
                plan_poseidon2_v8_pending_chain(
                    checkpoint(a),
                    &[state_writing_self_loop],
                    Poseidon2V8PendingCaps::new(1, leaf.len()),
                ),
                Err(Poseidon2V8PendingError::StablecoinEffectMismatch { .. })
            ));
            assert!(matches!(
                verify_poseidon2_v8_block_order(checkpoint(a), &[state_writing_self_loop]),
                Err(Poseidon2V8PendingError::StablecoinEffectMismatch { .. })
            ));
        }
    }

    #[test]
    fn neutral_actions_are_canonical_by_action_id_then_the_unique_advancing_edge_runs() {
        let a = root(10);
        let b = root(20);
        let c = root(30);
        let neutral_high = neutral_pending(90, 3, a);
        let neutral_low = neutral_pending(10, 4, a);
        let advance = pending(2, 5, a, b);
        let neutral_after = neutral_pending(1, 6, b);
        let advance_after = pending(200, 7, b, c);
        let supplied = [
            advance_after,
            neutral_after,
            advance,
            neutral_high,
            neutral_low,
        ];

        let plan = plan_poseidon2_v8_pending_chain(
            checkpoint(a),
            &supplied,
            Poseidon2V8PendingCaps::new(supplied.len(), usize::MAX),
        )
        .unwrap();
        assert_eq!(
            plan.ordered_action_ids(),
            &[
                neutral_low.action_id(),
                neutral_high.action_id(),
                advance.action_id(),
                neutral_after.action_id(),
                advance_after.action_id(),
            ]
        );
        assert_eq!(plan.full_final_root(), c);

        let canonical = [
            neutral_low,
            neutral_high,
            advance,
            neutral_after,
            advance_after,
        ];
        assert_eq!(
            verify_poseidon2_v8_block_order(checkpoint(a), &canonical).unwrap(),
            c
        );

        let wrong_neutral_order = [
            neutral_high,
            neutral_low,
            advance,
            neutral_after,
            advance_after,
        ];
        assert!(matches!(
            verify_poseidon2_v8_block_order(checkpoint(a), &wrong_neutral_order),
            Err(Poseidon2V8PendingError::BlockCanonicalOrderMismatch {
                index: 0,
                expected_action_id,
                observed_action_id,
            }) if expected_action_id == neutral_low.action_id()
                && observed_action_id == neutral_high.action_id()
        ));
    }

    #[test]
    fn neutral_siblings_are_allowed_but_two_advancing_siblings_still_reject() {
        let a = root(10);
        let b = root(20);
        let c = root(30);
        let neutral_a = neutral_pending(2, 1, a);
        let neutral_b = neutral_pending(1, 1, a);
        assert!(plan_poseidon2_v8_pending_chain(
            checkpoint(a),
            &[neutral_a, neutral_b],
            Poseidon2V8PendingCaps::new(2, 2),
        )
        .is_ok());

        assert!(matches!(
            plan_poseidon2_v8_pending_chain(
                checkpoint(a),
                &[pending(1, 1, a, b), pending(2, 1, a, c)],
                Poseidon2V8PendingCaps::new(2, 2),
            ),
            Err(Poseidon2V8PendingError::AmbiguousSibling { .. })
        ));
    }

    #[test]
    fn native_v8_count_cap_is_source_owned_at_512_and_bytes_remain_independent() {
        assert_eq!(MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK, 512);
        let caps = Poseidon2V8PendingCaps::native_block();
        assert_eq!(caps.max_actions, 512);
        assert_eq!(caps.max_action_bytes, MAX_NATIVE_BLOCK_ACTION_BYTES);
    }

    #[test]
    fn block_verifier_rejects_reverse_order_instead_of_reordering() {
        let a = root(10);
        let b = root(20);
        let c = root(30);
        let parent = pending(200, 4, a, b);
        let child = pending(1, 5, b, c);

        assert_eq!(
            verify_poseidon2_v8_block_order(checkpoint(a), &[parent, child]).unwrap(),
            c
        );
        assert!(matches!(
            verify_poseidon2_v8_block_order(checkpoint(a), &[child, parent]),
            Err(Poseidon2V8PendingError::BlockOrderMismatch {
                index: 0,
                expected_root,
                observed_root,
            }) if expected_root == a && observed_root == b
        ));
    }

    #[test]
    fn parent_height_and_empty_native_leaf_are_rejected() {
        let a = root(10);
        let b = root(20);
        let wrong_height = Poseidon2V8PendingAction::new(
            action_id(1),
            1,
            &[1],
            Poseidon2V8PublicTransition::new(40, a, b),
        );
        assert!(matches!(
            plan_poseidon2_v8_pending_chain(
                checkpoint(a),
                &[wrong_height],
                Poseidon2V8PendingCaps::new(1, 1),
            ),
            Err(Poseidon2V8PendingError::ParentHeightMismatch {
                expected: 41,
                observed: 40,
                ..
            })
        ));

        let empty = Poseidon2V8PendingAction::new(
            action_id(2),
            0,
            &[],
            Poseidon2V8PublicTransition::new(41, a, b),
        );
        assert!(matches!(
            plan_poseidon2_v8_pending_chain(
                checkpoint(a),
                &[empty],
                Poseidon2V8PendingCaps::new(1, 1),
            ),
            Err(Poseidon2V8PendingError::EmptyAction { .. })
        ));
    }

    #[test]
    fn v8_prefix_contributes_zero_legacy_da_bytes() {
        let a = root(10);
        let b = root(20);
        let plan = plan_poseidon2_v8_pending_chain(
            checkpoint(a),
            &[pending(1, 123, a, b)],
            Poseidon2V8PendingCaps::native_block(),
        )
        .unwrap();

        assert_eq!(plan.selected_action_bytes(), 123);
        assert_eq!(plan.selected_legacy_da_bytes(), 0);
    }
}
