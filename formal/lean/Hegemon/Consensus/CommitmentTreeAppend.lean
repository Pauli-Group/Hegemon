namespace Hegemon
namespace Consensus
namespace CommitmentTreeAppend

inductive SiblingSide where
  | left
  | right
deriving DecidableEq, Repr

structure AppendStep where
  level : Nat
  position : Nat
  siblingSide : SiblingSide
  siblingIsDefault : Bool
deriving DecidableEq, Repr

structure AppendSummary where
  priorLeafCount : Nat
  leafIndex : Nat
  resultLeafCount : Nat
  priorHistoryLen : Nat
  resultHistoryLen : Nat
  trace : List AppendStep
deriving DecidableEq, Repr

def positionAtLevel (leafIndex level : Nat) : Nat :=
  leafIndex / (2 ^ level)

def appendStepAt (leafIndex level : Nat) : AppendStep :=
  let position := positionAtLevel leafIndex level
  if position % 2 = 0 then
    {
      level := level,
      position := position,
      siblingSide := SiblingSide.right,
      siblingIsDefault := true
    }
  else
    {
      level := level,
      position := position,
      siblingSide := SiblingSide.left,
      siblingIsDefault := false
    }

def appendTrace (depth leafIndex : Nat) : List AppendStep :=
  (List.range depth).map (appendStepAt leafIndex)

def retainedHistoryLen (historyLimit appendCount : Nat) : Nat :=
  let totalRoots := appendCount + 1
  if historyLimit = 0 then
    totalRoots
  else
    min historyLimit totalRoots

def appendSummary (depth historyLimit priorLeafCount : Nat) : AppendSummary :=
  {
    priorLeafCount := priorLeafCount,
    leafIndex := priorLeafCount,
    resultLeafCount := priorLeafCount + 1,
    priorHistoryLen := retainedHistoryLen historyLimit priorLeafCount,
    resultHistoryLen := retainedHistoryLen historyLimit (priorLeafCount + 1),
    trace := appendTrace depth priorLeafCount
  }

def appendSummaries (depth historyLimit initialLeafCount appendCount : Nat) : List AppendSummary :=
  (List.range appendCount).map (fun offset =>
    appendSummary depth historyLimit (initialLeafCount + offset))

theorem append_summary_leaf_index_eq_prior
    (depth historyLimit priorLeafCount : Nat) :
    (appendSummary depth historyLimit priorLeafCount).leafIndex = priorLeafCount := by
  rfl

theorem append_summary_result_count_eq_prior_plus_one
    (depth historyLimit priorLeafCount : Nat) :
    (appendSummary depth historyLimit priorLeafCount).resultLeafCount =
      priorLeafCount + 1 := by
  rfl

theorem append_trace_length (depth leafIndex : Nat) :
    (appendTrace depth leafIndex).length = depth := by
  simp [appendTrace]

theorem first_append_all_right_default_depth4 :
    (appendSummary 4 3 0).trace =
      [
        { level := 0, position := 0, siblingSide := SiblingSide.right, siblingIsDefault := true },
        { level := 1, position := 0, siblingSide := SiblingSide.right, siblingIsDefault := true },
        { level := 2, position := 0, siblingSide := SiblingSide.right, siblingIsDefault := true },
        { level := 3, position := 0, siblingSide := SiblingSide.right, siblingIsDefault := true }
      ] := by
  decide

theorem second_append_starts_left_depth4 :
    (appendSummary 4 3 1).trace =
      [
        { level := 0, position := 1, siblingSide := SiblingSide.left, siblingIsDefault := false },
        { level := 1, position := 0, siblingSide := SiblingSide.right, siblingIsDefault := true },
        { level := 2, position := 0, siblingSide := SiblingSide.right, siblingIsDefault := true },
        { level := 3, position := 0, siblingSide := SiblingSide.right, siblingIsDefault := true }
      ] := by
  decide

theorem bounded_history_len_after_four_appends :
    retainedHistoryLen 3 4 = 3 := by
  decide

theorem zero_history_limit_is_unbounded_after_one_append :
    retainedHistoryLen 0 1 = 2 := by
  decide

end CommitmentTreeAppend
end Consensus
end Hegemon
