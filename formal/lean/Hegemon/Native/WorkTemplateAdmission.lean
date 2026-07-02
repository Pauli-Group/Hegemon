namespace Hegemon
namespace Native
namespace WorkTemplateAdmission

def u64Max : Nat := 18446744073709551615

def checkedAddOneU64 (value : Nat) : Option Nat :=
  if value < u64Max then some (value + 1) else none

inductive WorkTemplateReject where
  | heightNotNext
  | cumulativeWorkOverflow
deriving DecidableEq, Repr

structure WorkTemplateInput where
  bestHeight : Nat
  cumulativeWorkAdvances : Bool
deriving DecidableEq, Repr

def evaluateWorkTemplate
    (input : WorkTemplateInput) : Except WorkTemplateReject Nat :=
  match checkedAddOneU64 input.bestHeight with
  | none => Except.error WorkTemplateReject.heightNotNext
  | some nextHeight =>
      if input.cumulativeWorkAdvances = false then
        Except.error WorkTemplateReject.cumulativeWorkOverflow
      else
        Except.ok nextHeight

def workTemplateAccepts (input : WorkTemplateInput) : Bool :=
  match evaluateWorkTemplate input with
  | Except.ok _ => true
  | Except.error _ => false

def workTemplatePreconditions (input : WorkTemplateInput) : Bool :=
  (checkedAddOneU64 input.bestHeight).isSome && input.cumulativeWorkAdvances

theorem accepts_iff_work_template_preconditions
    {input : WorkTemplateInput} :
    workTemplateAccepts input = true ↔
      workTemplatePreconditions input = true := by
  unfold workTemplateAccepts workTemplatePreconditions evaluateWorkTemplate
  cases next : checkedAddOneU64 input.bestHeight <;>
    cases advances : input.cumulativeWorkAdvances <;>
    simp

def valid : WorkTemplateInput :=
  {
    bestHeight := 41,
    cumulativeWorkAdvances := true
  }

theorem valid_accepts :
    evaluateWorkTemplate valid = Except.ok 42 := by
  rfl

def heightOverflow : WorkTemplateInput :=
  {
    bestHeight := u64Max,
    cumulativeWorkAdvances := true
  }

theorem height_overflow_rejects :
    evaluateWorkTemplate heightOverflow =
      Except.error WorkTemplateReject.heightNotNext := by
  rfl

def cumulativeWorkOverflow : WorkTemplateInput :=
  {
    bestHeight := 41,
    cumulativeWorkAdvances := false
  }

theorem cumulative_work_overflow_rejects :
    evaluateWorkTemplate cumulativeWorkOverflow =
      Except.error WorkTemplateReject.cumulativeWorkOverflow := by
  rfl

def height_precedes_work_overflow_input : WorkTemplateInput :=
  {
    bestHeight := u64Max,
    cumulativeWorkAdvances := false
  }

theorem height_precedes_work_overflow :
    evaluateWorkTemplate height_precedes_work_overflow_input =
      Except.error WorkTemplateReject.heightNotNext := by
  rfl

def maxPredecessorAcceptsMaxHeight : WorkTemplateInput :=
  {
    bestHeight := u64Max - 1,
    cumulativeWorkAdvances := true
  }

theorem max_predecessor_accepts_max_height :
    evaluateWorkTemplate maxPredecessorAcceptsMaxHeight =
      Except.ok u64Max := by
  rfl

end WorkTemplateAdmission
end Native
end Hegemon
