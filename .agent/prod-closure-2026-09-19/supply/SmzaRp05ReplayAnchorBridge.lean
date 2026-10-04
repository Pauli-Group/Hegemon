import SmzaRp05FrontierCarryStep

/-!
# Replay frontier to retained-anchor prefix

The source-shaped replay transition carries more than a correct current root:
its retained history comes from genesis and successful appends.  This module
threads that reachability witness through the proved 32-level carry invariant,
then transfers a pre-block `root_history` membership to a concrete ancestor
append prefix.  Equal roots need not imply equal leaf counts.

This is a theorem about `NativeReplay`, not an unconditional claim about Rust
states decoded from storage.  The implementation bridge still has to relate
successful Rust `new_empty`/`append`, verified block ordering, and startup
scratch-replay/readback to `NativeReplay`; it also needs Rust/Lean digest
equivalence.  No proof field or consensus byte is introduced here.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ReplayAnchorBridge

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05RetainedAnchorPrefixes
open HegemonCrypto.SmallWood.SmzaRp05NativeFrontierModel
open HegemonCrypto.SmallWood.SmzaRp05FrontierCarryStep

set_option autoImplicit false

/-- The pure history paired with a replayed frontier is itself append-reachable.
This stronger refinement is necessary: equality of the current root alone
would not authenticate older roots retained in `history`. -/
theorem native_replay_has_reachable_refinement
    {native : FrontierState} {log : List Digest}
    (replay : NativeReplay native log) :
    ∃ ghost : NoteHistory,
      ghost.log = log ∧ Refines native ghost ∧ Reachable ghost := by
  induction replay with
  | start =>
      exact ⟨genesis, rfl, new_empty_refines, .start⟩
  | @push priorState priorLog prior commitment capacity ih =>
      rcases ih with ⟨ghost, ghostLog, refines, reachable⟩
      have priorGhost : NativeReplay priorState ghost.log := by
        simpa [ghostLog] using prior
      have priorSlots := native_replay_slots_correct priorGhost
      have transition := append_refines frontier_append_root_correct
        priorState ghost commitment priorGhost refines priorSlots capacity
      let nextGhost := SmzaRp05RetainedAnchorPrefixes.append ghost commitment
      refine ⟨nextGhost, ?_, ?_, ?_⟩
      · simp [nextGhost, SmzaRp05RetainedAnchorPrefixes.append, ghostLog]
      · exact transition.2
      · exact .push reachable commitment

/-- Admission against the replayed *parent* history yields a real ancestor
append prefix. Deduplication and trimming cannot fabricate an anchor. -/
theorem replay_pre_block_anchor_has_ancestor_prefix
    {parent : FrontierState} {log : List Digest}
    (replay : NativeReplay parent log)
    (anchor : Digest) (admitted : anchor ∈ parent.history) :
    ∃ ancestorLog, IsAncestorPrefix ancestorLog log ∧
      anchor = rootOfLog ancestorLog := by
  obtain ⟨ghost, ghostLog, refines, reachable⟩ :=
    native_replay_has_reachable_refinement replay
  have ghostAdmitted : PreBlockAnchorAccepted ghost anchor := by
    rw [PreBlockAnchorAccepted, ← refines.2.2.1]
    exact admitted
  obtain ⟨ancestorLog, ancestor, equalRoot⟩ :=
    accepted_anchor_has_ancestor_prefix reachable anchor ghostAdmitted
  exact ⟨ancestorLog, by simpa [ghostLog] using ancestor, equalRoot⟩

end HegemonCrypto.SmallWood.SmzaRp05ReplayAnchorBridge
