import SmzaRp05ReplayAnchorBridge
import SmzaRp05NativeMerkleFrameBoundary

/-!
# One successful native note append: field-level readback interface

The source `Poseidon2V8NoteTreeState::append` checks capacity, folds 32
frontier levels, updates count/root/frontier, preserves defaults, and then
deduplicates/trims root history. `verify_attach` copies the parent's history
before processing any output, so admission cannot use this append's new root.

`SourceAppendReadback` records those *separate* observable field equations.
It is not an assertion that compiled Rust satisfies them: the caller still
has to establish the readback from a successful Rust append, including the
primitive boundary isolated in `SmzaRp05NativeMerkleFrameBoundary` and the
pre-block set-membership projection. The theorem below then derives a genuine
`NativeReplay.push`, the new full-tree root, and the accepted anchor's
ancestor prefix. No proof or consensus bytes are added.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05NativeAppendReadback

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05RetainedAnchorPrefixes
open HegemonCrypto.SmallWood.SmzaRp05NativeFrontierModel
open HegemonCrypto.SmallWood.SmzaRp05FrontierCarryStep
open HegemonCrypto.SmallWood.SmzaRp05ReplayAnchorBridge

set_option autoImplicit false

/-- Field-by-field extraction target for a *successful* source append.
In particular, the final equation includes source deduplication and trim,
not merely equality of the latest root. -/
structure SourceAppendReadback
    (before after : FrontierState) (commitment : Digest) : Prop where
  capacity : before.leafCount < 2 ^ merkleDepth
  leafCount : after.leafCount = before.leafCount + 1
  root : after.root = (frontierAppend before commitment).current
  frontier : after.frontier = (frontierAppend before commitment).frontier
  defaults : after.defaults = before.defaults
  history : after.history = retainAfterAppend before.history
    (frontierAppend before commitment).current

private theorem frontier_state_ext
    {left right : FrontierState}
    (countEq : left.leafCount = right.leafCount)
    (rootEq : left.root = right.root)
    (frontierEq : left.frontier = right.frontier)
    (defaultsEq : left.defaults = right.defaults)
    (historyEq : left.history = right.history) : left = right := by
  cases left with
  | mk leftCount leftRoot leftFrontier leftDefaults leftHistory =>
      cases right with
      | mk rightCount rightRoot rightFrontier rightDefaults rightHistory =>
          cases countEq
          cases rootEq
          cases frontierEq
          cases defaultsEq
          cases historyEq
          rfl

theorem readback_is_model_append
    {before after : FrontierState} {commitment : Digest}
    (readback : SourceAppendReadback before after commitment) :
    SmzaRp05NativeFrontierModel.append before commitment = some after := by
  have rootEq := readback.root
  have frontierEq := readback.frontier
  have historyEq := readback.history
  generalize hOut : frontierAppend before commitment = output
    at rootEq frontierEq historyEq
  have afterEq : after =
      { leafCount := before.leafCount + 1
        root := output.current
        frontier := output.frontier
        defaults := before.defaults
        history := retainAfterAppend before.history
          output.current } := by
    apply frontier_state_ext
    · exact readback.leafCount
    · exact rootEq
    · exact frontierEq
    · exact readback.defaults
    · exact historyEq
  unfold SmzaRp05NativeFrontierModel.append
  rw [if_pos readback.capacity]
  rw [hOut]
  rw [afterEq]

/-- The readback, not a root-equality shortcut, closes one replay step.
The anchor is checked against the copied parent history before this append. -/
theorem successful_append_preserves_replay_and_anchor
    {before after : FrontierState} {log : List Digest}
    (prior : NativeReplay before log) (commitment : Digest)
    (readback : SourceAppendReadback before after commitment)
    (preBlockHistory : List Digest)
    (preBlockHistoryEq : preBlockHistory = before.history)
    (anchor : Digest) (admitted : anchor ∈ preBlockHistory) :
    NativeReplay after (log ++ [commitment]) ∧
    after.root = rootOfLog (log ++ [commitment]) ∧
    (∃ ancestorLog, IsAncestorPrefix ancestorLog log ∧
      anchor = rootOfLog ancestorLog) := by
  have sourceAppend := readback_is_model_append readback
  have afterEq : after =
      { leafCount := before.leafCount + 1
        root := (frontierAppend before commitment).current
        frontier := (frontierAppend before commitment).frontier
        defaults := before.defaults
        history := retainAfterAppend before.history
          (frontierAppend before commitment).current } := by
    unfold SmzaRp05NativeFrontierModel.append at sourceAppend
    rw [if_pos readback.capacity] at sourceAppend
    exact (Option.some.inj sourceAppend).symm
  have replayAfter : NativeReplay after (log ++ [commitment]) := by
    rw [afterEq]
    exact .push prior commitment readback.capacity
  have parentMember : anchor ∈ before.history := by
    rw [← preBlockHistoryEq]
    exact admitted
  exact ⟨replayAfter, native_replay_root_of_log replayAfter,
    replay_pre_block_anchor_has_ancestor_prefix prior anchor parentMember⟩

end HegemonCrypto.SmallWood.SmzaRp05NativeAppendReadback
