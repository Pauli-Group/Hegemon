import Hegemon.Native.ActionStateEffect

namespace Hegemon
namespace Native
namespace ActionPlanApplicationAdmission

open Hegemon.Native.ActionStateEffect

inductive ActionPlanApplicationReject where
  | planLengthMismatch
  | plannedStartMismatch
  | commitmentIndexOverflow
deriving DecidableEq, Repr

structure ActionPlanApplicationInput where
  leafStart : Nat
  actionCommitmentCounts : List Nat
  plannedStarts : List Nat
deriving DecidableEq, Repr

structure ActionPlanApplicationOutput where
  nextLeafCount : Nat
  appliedActionCount : Nat
deriving DecidableEq, Repr

def evaluateActionPlanApplicationFrom :
    Nat ->
    List Nat ->
    List Nat ->
    Nat ->
    Except ActionPlanApplicationReject ActionPlanApplicationOutput
  | leaf, [], [], applied =>
      Except.ok { nextLeafCount := leaf, appliedActionCount := applied }
  | _leaf, [], _ :: _, _applied =>
      Except.error ActionPlanApplicationReject.planLengthMismatch
  | _leaf, _ :: _, [], _applied =>
      Except.error ActionPlanApplicationReject.planLengthMismatch
  | leaf, commitmentCount :: restCounts, plannedStart :: restStarts, applied =>
      if plannedStart = leaf then
        match checkedAddU64 leaf commitmentCount with
        | none =>
            Except.error ActionPlanApplicationReject.commitmentIndexOverflow
        | some nextLeaf =>
            evaluateActionPlanApplicationFrom
              nextLeaf
              restCounts
              restStarts
              (applied + 1)
      else
        Except.error ActionPlanApplicationReject.plannedStartMismatch

def evaluateActionPlanApplication
    (input : ActionPlanApplicationInput) :
    Except ActionPlanApplicationReject ActionPlanApplicationOutput :=
  evaluateActionPlanApplicationFrom
    input.leafStart
    input.actionCommitmentCounts
    input.plannedStarts
    0

def actionPlanApplicationAccepts
    (input : ActionPlanApplicationInput) : Bool :=
  match evaluateActionPlanApplication input with
  | Except.ok _ => true
  | Except.error _ => false

def actionPlanApplicationPreconditions
    (input : ActionPlanApplicationInput) : Bool :=
  actionPlanApplicationAccepts input

theorem accepts_iff_plan_application_preconditions
    (input : ActionPlanApplicationInput) :
    actionPlanApplicationAccepts input =
      actionPlanApplicationPreconditions input := by
  rfl

def validTwoActionPlan : ActionPlanApplicationInput :=
  {
    leafStart := 10,
    actionCommitmentCounts := [2, 1],
    plannedStarts := [10, 12]
  }

theorem valid_two_action_plan_accepts :
    evaluateActionPlanApplication validTwoActionPlan =
      Except.ok { nextLeafCount := 13, appliedActionCount := 2 } := by
  rfl

def emptyPlan : ActionPlanApplicationInput :=
  {
    leafStart := 42,
    actionCommitmentCounts := [],
    plannedStarts := []
  }

theorem empty_plan_accepts :
    evaluateActionPlanApplication emptyPlan =
      Except.ok { nextLeafCount := 42, appliedActionCount := 0 } := by
  rfl

def missingPlannedStart : ActionPlanApplicationInput :=
  {
    leafStart := 0,
    actionCommitmentCounts := [1],
    plannedStarts := []
  }

theorem missing_planned_start_rejects :
    evaluateActionPlanApplication missingPlannedStart =
      Except.error ActionPlanApplicationReject.planLengthMismatch := by
  rfl

def extraPlannedStart : ActionPlanApplicationInput :=
  {
    leafStart := 0,
    actionCommitmentCounts := [],
    plannedStarts := [0]
  }

theorem extra_planned_start_rejects :
    evaluateActionPlanApplication extraPlannedStart =
      Except.error ActionPlanApplicationReject.planLengthMismatch := by
  rfl

def firstPlannedStartMismatch : ActionPlanApplicationInput :=
  {
    leafStart := 10,
    actionCommitmentCounts := [1],
    plannedStarts := [9]
  }

theorem first_planned_start_mismatch_rejects :
    evaluateActionPlanApplication firstPlannedStartMismatch =
      Except.error ActionPlanApplicationReject.plannedStartMismatch := by
  rfl

def secondPlannedStartMismatch : ActionPlanApplicationInput :=
  {
    leafStart := 10,
    actionCommitmentCounts := [2, 1],
    plannedStarts := [10, 11]
  }

theorem second_planned_start_mismatch_rejects :
    evaluateActionPlanApplication secondPlannedStartMismatch =
      Except.error ActionPlanApplicationReject.plannedStartMismatch := by
  rfl

def commitmentOverflow : ActionPlanApplicationInput :=
  {
    leafStart := u64Max,
    actionCommitmentCounts := [1],
    plannedStarts := [u64Max]
  }

theorem commitment_overflow_rejects :
    evaluateActionPlanApplication commitmentOverflow =
      Except.error ActionPlanApplicationReject.commitmentIndexOverflow := by
  rfl

def planned_start_precedes_overflow_input : ActionPlanApplicationInput :=
  {
    leafStart := u64Max,
    actionCommitmentCounts := [1],
    plannedStarts := [0]
  }

theorem planned_start_precedes_overflow :
    evaluateActionPlanApplication planned_start_precedes_overflow_input =
      Except.error ActionPlanApplicationReject.plannedStartMismatch := by
  rfl

def zeroCommitmentPlan : ActionPlanApplicationInput :=
  {
    leafStart := u64Max,
    actionCommitmentCounts := [0],
    plannedStarts := [u64Max]
  }

theorem zero_commitment_at_max_leaf_accepts :
    evaluateActionPlanApplication zeroCommitmentPlan =
      Except.ok { nextLeafCount := u64Max, appliedActionCount := 1 } := by
  rfl

end ActionPlanApplicationAdmission
end Native
end Hegemon
