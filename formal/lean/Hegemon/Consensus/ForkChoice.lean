import Hegemon.Bytes

namespace Hegemon
namespace Consensus

abbrev Hash32 := List Byte

structure ForkChoiceTip where
  work : Nat
  height : Nat
  hash : Hash32
deriving DecidableEq, Repr

def lexLt : List Byte -> List Byte -> Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | left :: leftTail, right :: rightTail =>
      if left = right then
        lexLt leftTail rightTail
      else
        left < right

def betterThan (candidate current : ForkChoiceTip) : Bool :=
  if candidate.work > current.work then
    true
  else if candidate.work < current.work then
    false
  else if candidate.height > current.height then
    true
  else if candidate.height < current.height then
    false
  else
    lexLt candidate.hash current.hash

def selectBest (current candidate : ForkChoiceTip) : ForkChoiceTip :=
  if betterThan candidate current then candidate else current

structure ForkChoiceSelectionFacts (current candidate selected : ForkChoiceTip) : Prop where
  selected_eq : selected = selectBest current candidate
  selected_current_or_candidate : selected = current ∨ selected = candidate
  candidate_selected_when_better : betterThan candidate current = true -> selected = candidate
  current_selected_when_not_better : betterThan candidate current = false -> selected = current

theorem lexLt_irrefl (bytes : List Byte) :
    lexLt bytes bytes = false := by
  induction bytes with
  | nil =>
      rfl
  | cons _ tail ih =>
      unfold lexLt
      simp [ih]

theorem higher_work_wins
    {candidate current : ForkChoiceTip}
    (h : candidate.work > current.work) :
    betterThan candidate current = true := by
  unfold betterThan
  simp [h]

theorem lower_work_loses
    {candidate current : ForkChoiceTip}
    (h : candidate.work < current.work) :
    betterThan candidate current = false := by
  unfold betterThan
  have notHigher : ¬ candidate.work > current.work := by
    intro higher
    exact Nat.lt_asymm h higher
  simp [notHigher, h]

theorem equal_work_higher_height_wins
    {candidate current : ForkChoiceTip}
    (sameWork : candidate.work = current.work)
    (h : candidate.height > current.height) :
    betterThan candidate current = true := by
  unfold betterThan
  simp [sameWork, h]

theorem equal_work_lower_height_loses
    {candidate current : ForkChoiceTip}
    (sameWork : candidate.work = current.work)
    (h : candidate.height < current.height) :
    betterThan candidate current = false := by
  unfold betterThan
  have notHigher : ¬ candidate.height > current.height := by
    intro higher
    exact Nat.lt_asymm h higher
  simp [sameWork, notHigher, h]

theorem equal_work_height_uses_hash_order
    {candidate current : ForkChoiceTip}
    (sameWork : candidate.work = current.work)
    (sameHeight : candidate.height = current.height) :
    betterThan candidate current = lexLt candidate.hash current.hash := by
  unfold betterThan
  simp [sameWork, sameHeight]

theorem same_tip_not_better
    {candidate current : ForkChoiceTip}
    (sameWork : candidate.work = current.work)
    (sameHeight : candidate.height = current.height)
    (sameHash : candidate.hash = current.hash) :
    betterThan candidate current = false := by
  rw [equal_work_height_uses_hash_order sameWork sameHeight, sameHash]
  exact lexLt_irrefl current.hash

theorem selectBest_higher_work_returns_candidate
    {candidate current : ForkChoiceTip}
    (h : candidate.work > current.work) :
    selectBest current candidate = candidate := by
  unfold selectBest
  simp [higher_work_wins h]

theorem selectBest_lower_work_keeps_current
    {candidate current : ForkChoiceTip}
    (h : candidate.work < current.work) :
    selectBest current candidate = current := by
  unfold selectBest
  simp [lower_work_loses h]

theorem selectBest_is_current_or_candidate
    (current candidate : ForkChoiceTip) :
    selectBest current candidate = current ∨ selectBest current candidate = candidate := by
  unfold selectBest
  cases h : betterThan candidate current <;> simp

theorem betterThan_true_implies_work_not_lower
    {candidate current : ForkChoiceTip}
    (h : betterThan candidate current = true) :
    current.work <= candidate.work := by
  unfold betterThan at h
  by_cases higher : candidate.work > current.work
  · exact Nat.le_of_lt higher
  · by_cases lower : candidate.work < current.work
    · simp [higher, lower] at h
    · exact Nat.le_of_not_gt lower

theorem selectBest_work_not_lower
    (current candidate : ForkChoiceTip) :
    current.work <= (selectBest current candidate).work := by
  unfold selectBest
  cases h : betterThan candidate current
  · simp
  · have notLower := betterThan_true_implies_work_not_lower
      (candidate := candidate) (current := current) h
    simp [notLower]

theorem selectBest_candidate_when_better
    {current candidate : ForkChoiceTip}
    (h : betterThan candidate current = true) :
    selectBest current candidate = candidate := by
  unfold selectBest
  simp [h]

theorem selectBest_current_when_not_better
    {current candidate : ForkChoiceTip}
    (h : betterThan candidate current = false) :
    selectBest current candidate = current := by
  unfold selectBest
  simp [h]

theorem selectBest_selection_facts
    (current candidate : ForkChoiceTip) :
    ForkChoiceSelectionFacts current candidate (selectBest current candidate) := by
  constructor
  · rfl
  · exact selectBest_is_current_or_candidate current candidate
  · intro h
    exact selectBest_candidate_when_better h
  · intro h
    exact selectBest_current_when_not_better h

theorem selectBest_equal_work_height_lower_hash_returns_candidate
    {candidate current : ForkChoiceTip}
    (sameWork : candidate.work = current.work)
    (sameHeight : candidate.height = current.height)
    (hashLower : lexLt candidate.hash current.hash = true) :
    selectBest current candidate = candidate := by
  unfold selectBest
  rw [equal_work_height_uses_hash_order sameWork sameHeight]
  simp [hashLower]

theorem selectBest_equal_work_height_not_lower_hash_keeps_current
    {candidate current : ForkChoiceTip}
    (sameWork : candidate.work = current.work)
    (sameHeight : candidate.height = current.height)
    (hashNotLower : lexLt candidate.hash current.hash = false) :
    selectBest current candidate = current := by
  unfold selectBest
  rw [equal_work_height_uses_hash_order sameWork sameHeight]
  simp [hashNotLower]

end Consensus
end Hegemon
