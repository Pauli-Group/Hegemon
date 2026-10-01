import SmzaRp05NativeFrontierModel

/-!
# Generic one-bit frontier carry

This is deliberately one induction step for any level below 32. The even
branch takes the default right subtree; the odd branch takes the completed
left subtree certified by `FrontierSlotsCorrect`. No per-level fixture list
or hash-equality assumption is introduced.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05FrontierCarryStep

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05RetainedAnchorPrefixes
open HegemonCrypto.SmallWood.SmzaRp05NativeFrontierModel
open HegemonCrypto.SmallWood.SmzaRp05KnownEmptySupply

set_option autoImplicit false

private theorem default_node_getD (level : Nat) (bound : level < merkleDepth) :
    defaultNodes.getD level knownEmptyLeaf = defaultNode level := by
  have indexBound : level < defaultNodes.length := by
    simp [defaultNodes]
    omega
  rw [List.getD_eq_getElem _ _ indexBound]
  simp [defaultNodes]

theorem generic_carry_step : CarryStepCorrect := by
  intro state log commitment level cursor count defaults slots levelBound invariant
  rcases invariant with ⟨position, current, higher⟩
  let n := log.length
  let width := 2 ^ level
  let base := n - n % width
  let nextBase := n - n % 2 ^ (level + 1)
  have widthPos : 0 < width := by simp [width]
  have remainderBound : n % width < width := Nat.mod_lt _ widthPos
  have nEq : base + n % width = n := by
    dsimp [base]
    exact Nat.sub_add_cancel (Nat.mod_le _ _)
  have higherNext : ∀ later, level + 1 ≤ later → later < merkleDepth →
      (frontierLevel state.defaults level cursor).frontier.getD later knownEmptyLeaf =
        state.frontier.getD later knownEmptyLeaf := by
    intro later lower upper
    rw [frontier_level_higher_slot_unchanged state.defaults level later cursor
      (by omega)]
    exact higher later (by omega) upper
  constructor
  · simp only [frontierLevel]
    split_ifs <;> rw [position] <;>
      simp [Nat.pow_succ, Nat.div_div_eq_div_mul, Nat.mul_comm]
  constructor
  · by_cases bit : (n / width) % 2 = 0
    · have sameBase : nextBase = base := by
        exact even_bit_same_base n level (by simpa [width] using bit)
      have rightOutside : (log ++ [commitment]).length ≤ base + width := by
        simp only [List.length_append, List.length_cons, List.length_nil]
        omega
      have rightDefault := subtree_beyond_log_is_default level
        (base + width) (log ++ [commitment]) rightOutside
      have defaultWord : state.defaults.getD level knownEmptyLeaf =
          defaultNode level := by
        rw [defaults]
        exact default_node_getD level levelBound
      have bitLog : (log.length / 2 ^ level) % 2 = 0 := by
        simpa [n, width] using bit
      simp only [frontierLevel]
      rw [position]
      rw [if_pos bitLog]
      simp only [defaultWord]
      have rootBase : log.length - log.length % 2 ^ level = base := by
        dsimp [base, n, width]
      have rightBase : log.length - log.length % 2 ^ (level + 1) = base := by
        simpa [n, nextBase] using sameBase
      rw [rightBase, rootFromLog, current, rootBase, rightDefault]
    · have odd : (n / width) % 2 = 1 := by omega
      have previousBase : nextBase + width = base := by
        exact odd_bit_previous_base n level (by simpa [width] using odd)
      have completed : nextBase + 2 ^ level ≤ log.length := by
        simpa [width, previousBase] using
          (show base ≤ n by dsimp [base, n]; omega)
      have stable := subtree_before_append_unchanged level nextBase
        log commitment completed
      have originalSlot : state.frontier.getD level knownEmptyLeaf =
          rootFromLog level nextBase log := by
        have source := slots level levelBound (by simpa [width] using odd)
        simpa [nextBase] using source
      have cursorSlot : cursor.frontier.getD level knownEmptyLeaf =
          rootFromLog level nextBase log := by
        rw [higher level (by omega) levelBound]
        exact originalSlot
      have oddLog : (log.length / 2 ^ level) % 2 = 1 := by
        simpa [n, width] using odd
      simp only [frontierLevel]
      rw [position]
      have notEven : ¬(log.length / 2 ^ level) % 2 = 0 := by
        rw [oddLog]
        decide
      rw [if_neg notEven]
      have rootBase : log.length - log.length % 2 ^ level = base := by
        dsimp [base, n, width]
      have rightChild :
          log.length - log.length % 2 ^ (level + 1) + 2 ^ level = base := by
        simpa [n, nextBase, width] using previousBase
      rw [rootFromLog, cursorSlot, current, rootBase, rightChild, stable]
  · exact higherNext

def slotAfterAppend (state : FrontierState) (log : List Digest)
    (commitment : Digest) (level : Nat) : Digest :=
  if (log.length / 2 ^ level) % 2 = 0 then
    rootFromLog level (log.length - log.length % 2 ^ level)
      (log ++ [commitment])
  else state.frontier.getD level knownEmptyLeaf

/-- Once a level has been visited, later levels never change its slot.
This derives the exact final frontier word at every level from the same
generic carry invariant used for the root, without listing 32 cases. -/
theorem visited_frontier_slots
    (state : FrontierState) (log : List Digest)
    (commitment : Digest)
    (countEq : state.leafCount = log.length)
    (defaults : state.defaults = defaultNodes)
    (slots : FrontierSlotsCorrect state log)
    (shape : state.frontier.length = merkleDepth)
    (count : Nat) (countBound : count ≤ merkleDepth)
    (level : Nat) (levelBound : level < merkleDepth) :
    (((List.range count).foldl (fun cursor level => frontierLevel state.defaults level cursor)
      { current := commitment
        position := state.leafCount
        frontier := state.frontier }).frontier).getD level knownEmptyLeaf =
      if level < count then slotAfterAppend state log commitment level
      else state.frontier.getD level knownEmptyLeaf := by
  induction count with
  | zero => simp
  | succ count ih =>
      have lower : count < merkleDepth := by omega
      let cursor := (List.range count).foldl
        (fun cursor level => frontierLevel state.defaults level cursor)
        { current := commitment
          position := state.leafCount
          frontier := state.frontier }
      have cursorShape : cursor.frontier.length = merkleDepth := by
        dsimp [cursor]
        rw [frontier_fold_preserves_length]
        exact shape
      have carry := carry_induction generic_carry_step state log commitment
        countEq defaults slots count (by omega)
      rw [List.range_succ, List.foldl_append]
      simp only [List.foldl_cons, List.foldl_nil]
      by_cases same : level = count
      · subst level
        have position := carry.1
        have current := carry.2.1
        have own := frontier_level_own_slot state.defaults count cursor
          (by rw [cursorShape]; exact lower)
        rw [position] at own
        rw [own]
        have prior := ih (by omega)
        dsimp [cursor] at position current ⊢
        simp only [if_pos (Nat.lt_succ_self count), slotAfterAppend]
        by_cases parity : (log.length / 2 ^ count) % 2 = 0
        · rw [current]
          simp only [if_pos parity]
        · have priorSlot := prior
          simp only [if_neg (Nat.lt_irrefl count)] at priorSlot
          simp only [if_neg parity]
          exact priorSlot
      · have untouched := frontier_level_other_slot_unchanged
          state.defaults count level cursor same
        rw [untouched]
        have prior := ih (by omega)
        rw [prior]
        by_cases before : level < count
        · have nextVisited : level < count + 1 := by omega
          simp only [if_pos before, if_pos nextVisited]
        · have notBefore : ¬level < count := by omega
          have notNext : ¬level < count + 1 := by omega
          simp only [if_neg notBefore, if_neg notNext]

private theorem successor_base_cases (position level : Nat)
    (newBit : ((position + 1) / 2 ^ level) % 2 = 1) :
    let width := 2 ^ level
    let oldBase := position - position % (2 * width)
    let newBase := position + 1 - (position + 1) % (2 * width)
    if (position / width) % 2 = 0 then
      newBase = position - position % width
    else newBase = oldBase := by
  intro width oldBase newBase
  have widthPos : 0 < width := by simp [width]
  by_cases divides : width ∣ position + 1
  · have quotient := Nat.succ_div_of_dvd divides
    have oldEven : (position / width) % 2 = 0 := by
      rw [quotient] at newBit
      omega
    rw [if_pos oldEven]
    have newRem : (position + 1) % width = 0 := Nat.mod_eq_zero_of_dvd divides
    have oldRem : position % width + 1 = width := by
      have before := Nat.mod_add_div position width
      have after := Nat.mod_add_div (position + 1) width
      rw [newRem, quotient] at after
      nlinarith
    have newOdd := odd_bit_previous_base (position + 1) level
      (by simpa [width] using newBit)
    have power : 2 ^ (level + 1) = 2 * width := by
      simp [width, pow_succ, Nat.mul_comm]
    rw [power] at newOdd
    rw [newRem] at newOdd
    dsimp [newBase]
    omega
  · have quotient := Nat.succ_div_of_not_dvd divides
    have oldOdd : (position / width) % 2 = 1 := by
      rw [quotient] at newBit
      exact newBit
    have notOldEven : ¬(position / width) % 2 = 0 := by
      rw [oldOdd]
      decide
    rw [if_neg notOldEven]
    have before := Nat.mod_add_div position width
    have after := Nat.mod_add_div (position + 1) width
    rw [quotient] at after
    have nextRem : (position + 1) % width = position % width + 1 := by
      nlinarith
    have oldBaseRule := odd_bit_previous_base position level
      (by simpa [width] using oldOdd)
    have newBaseRule := odd_bit_previous_base (position + 1) level
      (by simpa [width] using newBit)
    have power : 2 ^ (level + 1) = 2 * width := by
      simp [width, pow_succ, Nat.mul_comm]
    rw [power] at oldBaseRule newBaseRule
    rw [nextRem] at newBaseRule
    have newBasePlus : newBase + width = position - position % width := by
      simpa [newBase, width, nextRem] using newBaseRule
    have oldBasePlus : oldBase + width = position - position % width := by
      simpa [oldBase] using oldBaseRule
    exact Nat.add_right_cancel (newBasePlus.trans oldBasePlus.symm)

/-- The frontier slot invariant survives one source-shaped append. A newly
set bit is the subtree just completed by the carry; a bit already set keeps
its prior completed subtree, since that subtree ends before the append. -/
theorem generic_frontier_slots_step : FrontierSlotsStepCorrect := by
  intro state log commitment replay countEq defaults slots capacity level levelBound newBit
  have shape := native_replay_frontier_shape replay
  have finalSlot := visited_frontier_slots state log commitment countEq
    defaults slots shape merkleDepth (Nat.le_refl _) level levelBound
  have finalValue :
      (frontierAppend state commitment).frontier.getD level knownEmptyLeaf =
        slotAfterAppend state log commitment level := by
    simpa [frontierAppend, levelBound] using finalSlot
  rw [finalValue]
  have successor := successor_base_cases log.length level (by
    simpa only [List.length_append, List.length_cons, List.length_nil,
      Nat.add_zero] using newBit)
  by_cases oldEven : (log.length / 2 ^ level) % 2 = 0
  · have baseEq :
        (log.length + 1) - (log.length + 1) % 2 ^ (level + 1) =
          log.length - log.length % 2 ^ level := by
      have source := successor
      rw [if_pos oldEven] at source
      simpa [pow_succ, Nat.mul_comm] using source
    simp [slotAfterAppend, oldEven, baseEq]
  · have oldOdd : (log.length / 2 ^ level) % 2 = 1 := by omega
    have baseEq :
        (log.length + 1) - (log.length + 1) % 2 ^ (level + 1) =
          log.length - log.length % 2 ^ (level + 1) := by
      have source := successor
      rw [if_neg oldEven] at source
      simpa [pow_succ, Nat.mul_comm] using source
    have completed :
        (log.length - log.length % 2 ^ (level + 1)) + 2 ^ level ≤
          log.length := by
      have previous := odd_bit_previous_base log.length level oldOdd
      omega
    have stable := subtree_before_append_unchanged level
      (log.length - log.length % 2 ^ (level + 1))
      log commitment completed
    have oldSlot := slots level levelBound oldOdd
    simpa [slotAfterAppend, oldEven, baseEq, stable] using oldSlot

theorem native_replay_slots_correct
    {state : FrontierState} {log : List Digest}
    (replay : NativeReplay state log) :
    FrontierSlotsCorrect state log :=
  replay_slots_of_generic_step generic_frontier_slots_step replay

theorem replay_frontier_append_root
    (native : FrontierState) (ghost : NoteHistory)
    (commitment : Digest)
    (_replay : NativeReplay native ghost.log)
    (refines : Refines native ghost)
    (slots : FrontierSlotsCorrect native ghost.log)
    (capacity : native.leafCount < 2 ^ merkleDepth) :
    (frontierAppend native commitment).current =
      rootOfLog (ghost.log ++ [commitment]) := by
  exact frontier_root_of_carry_step generic_carry_step native ghost.log
    commitment refines.1 refines.2.2.2 slots capacity

theorem frontier_append_root_correct : FrontierAppendRootCorrect := by
  intro native ghost commitment replay refines slots capacity
  exact replay_frontier_append_root native ghost commitment replay
    refines slots capacity

theorem replay_frontier_root_from_generic_slot_step
    (slotStep : FrontierSlotsStepCorrect)
    (native : FrontierState) (ghost : NoteHistory)
    (commitment : Digest)
    (replay : NativeReplay native ghost.log)
    (refines : Refines native ghost)
    (capacity : native.leafCount < 2 ^ merkleDepth) :
    (frontierAppend native commitment).current =
      rootOfLog (ghost.log ++ [commitment]) := by
  exact frontier_append_root_correct native ghost commitment replay refines
    (replay_slots_of_generic_step slotStep replay) capacity

/-- Replay alone supplies the slot invariant needed for the 32-level carry;
there is no extra state hypothesis at an append. -/
theorem replay_frontier_append_root_correct
    (native : FrontierState) (ghost : NoteHistory)
    (commitment : Digest)
    (replay : NativeReplay native ghost.log)
    (refines : Refines native ghost)
    (capacity : native.leafCount < 2 ^ merkleDepth) :
    (frontierAppend native commitment).current =
      rootOfLog (ghost.log ++ [commitment]) := by
  exact replay_frontier_root_from_generic_slot_step
    generic_frontier_slots_step native ghost commitment replay refines capacity

/-- Every native replay state has a pure append-history witness, including
its current root and retained root history. This induction uses the proved
slot preservation and carry step, not a free frontier-correctness premise. -/
theorem native_replay_has_refinement
    {native : FrontierState} {log : List Digest}
    (replay : NativeReplay native log) :
    ∃ ghost : NoteHistory, ghost.log = log ∧ Refines native ghost := by
  induction replay with
  | start =>
      exact ⟨genesis, rfl, new_empty_refines⟩
  | @push priorState priorLog prior commitment capacity ih =>
      rcases ih with ⟨ghost, ghostLog, refines⟩
      have priorGhost : NativeReplay priorState ghost.log := by
        simpa [ghostLog] using prior
      have priorSlots := native_replay_slots_correct priorGhost
      have transition := append_refines frontier_append_root_correct
        priorState ghost commitment priorGhost refines priorSlots capacity
      let nextGhost := SmzaRp05RetainedAnchorPrefixes.append ghost commitment
      refine ⟨nextGhost, ?_, ?_⟩
      · simp [nextGhost, SmzaRp05RetainedAnchorPrefixes.append, ghostLog]
      · exact transition.2

theorem native_replay_root_of_log
    {native : FrontierState} {log : List Digest}
    (replay : NativeReplay native log) :
    native.root = rootOfLog log := by
  obtain ⟨ghost, ghostLog, refines⟩ := native_replay_has_refinement replay
  simpa [ghostLog] using refines.2.1

end HegemonCrypto.SmallWood.SmzaRp05FrontierCarryStep
