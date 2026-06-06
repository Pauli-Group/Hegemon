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

end Consensus
end Hegemon
