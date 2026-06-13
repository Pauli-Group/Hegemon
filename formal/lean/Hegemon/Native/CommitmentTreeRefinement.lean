import Hegemon.Consensus.TreeTransition
import Hegemon.Native.ActionPlanApplicationAdmission
import Hegemon.Native.ActionStreamEffect

namespace Hegemon
namespace Native
namespace CommitmentTreeRefinement

open Hegemon.Consensus.TreeTransition
open Hegemon.Native.ActionPlanApplicationAdmission
open Hegemon.Native.ActionStateEffect
open Hegemon.Native.ActionStreamEffect

def streamCommitmentCounts (actions : List StreamAction) : List Nat :=
  actions.map fun action => action.commitmentCount

def commitmentStartsFrom : Nat -> List StreamAction -> Option (Nat × List Nat)
  | leaf, [] => some (leaf, [])
  | leaf, action :: rest =>
      if action.commitmentCount = action.ciphertextCount then
        match checkedAddU64 leaf action.commitmentCount with
        | none => none
        | some nextLeaf =>
            match commitmentStartsFrom nextLeaf rest with
            | none => none
            | some (finalLeaf, starts) => some (finalLeaf, leaf :: starts)
      else
        none

def planInputFromAcceptedStream
    (input : ActionStreamInput)
    (output : ActionStreamOutput) :
    ActionPlanApplicationInput :=
  {
    leafStart := input.leafStart,
    actionCommitmentCounts := streamCommitmentCounts input.actions,
    plannedStarts := output.plannedStarts
  }

theorem accepted_stream_from_commitment_starts_from
    {leaf importedNullifiers importedReplays : Nat}
    {spent consumed plannedStarts : List Nat}
    {actions : List StreamAction}
    {output : ActionStreamOutput}
    (accepted :
      evaluateActionStreamFrom
        leaf
        spent
        consumed
        actions
        plannedStarts
        importedNullifiers
        importedReplays =
          Except.ok output) :
    ∃ suffix,
      commitmentStartsFrom leaf actions =
        some (output.nextLeafCount, suffix) ∧
      output.plannedStarts = plannedStarts ++ suffix := by
  induction actions generalizing leaf spent consumed plannedStarts
      importedNullifiers importedReplays output with
  | nil =>
      cases output with
      | mk nextLeafCount importedNullifierCount importedBridgeReplayCount
          outputPlannedStarts =>
          simp [evaluateActionStreamFrom] at accepted
          rcases accepted with
            ⟨hLeaf, _hNullifiers, _hReplays, hStarts⟩
          subst nextLeafCount
          subst outputPlannedStarts
          exact ⟨[], rfl, by simp⟩
  | cons action rest ih =>
      unfold evaluateActionStreamFrom at accepted
      by_cases countMatches :
          action.commitmentCount = action.ciphertextCount
      · simp [countMatches] at accepted
        cases nextLeafResult :
            checkedAddU64 leaf action.ciphertextCount with
        | none =>
            simp [nextLeafResult] at accepted
        | some nextLeaf =>
            cases importResult :
                importNullifiers spent action.nullifiers with
            | error rejection =>
                simp [nextLeafResult, importResult] at accepted
            | ok importedPair =>
                cases importedPair with
                | mk nextSpent nullifierImports =>
                    cases bridgeResult :
                        importBridgeReplay
                          consumed
                          action.bridgeReplayKey with
                    | error rejection =>
                        simp [
                          nextLeafResult,
                          importResult,
                          bridgeResult
                        ] at accepted
                    | ok bridgePair =>
                        cases bridgePair with
                        | mk nextConsumed replayImports =>
                            simp [
                              nextLeafResult,
                              importResult,
                              bridgeResult
                            ] at accepted
                            rcases ih accepted with
                              ⟨suffix, suffixOk, startsOk⟩
                            refine ⟨leaf :: suffix, ?_, ?_⟩
                            · simp [
                                commitmentStartsFrom,
                                countMatches,
                                nextLeafResult
                              ]
                              rw [suffixOk]
                            · rw [startsOk]
                              simp [List.append_assoc]
      · simp [countMatches] at accepted

theorem accepted_stream_commitment_starts_from
    {input : ActionStreamInput}
    {output : ActionStreamOutput}
    (accepted :
      evaluateActionStreamEffect input = Except.ok output) :
    commitmentStartsFrom input.leafStart input.actions =
      some (output.nextLeafCount, output.plannedStarts) := by
  unfold evaluateActionStreamEffect at accepted
  rcases accepted_stream_from_commitment_starts_from accepted with
    ⟨suffix, startsOk, plannedOk⟩
  simp at plannedOk
  rw [← plannedOk] at startsOk
  exact startsOk

theorem commitment_starts_plan_application_from_accepts
    {leaf finalLeaf applied : Nat}
    {actions : List StreamAction}
    {starts : List Nat}
    (startsOk :
      commitmentStartsFrom leaf actions = some (finalLeaf, starts)) :
    evaluateActionPlanApplicationFrom
        leaf
        (streamCommitmentCounts actions)
        starts
        applied =
      Except.ok
        {
          nextLeafCount := finalLeaf,
          appliedActionCount := applied + actions.length
        } := by
  induction actions generalizing leaf finalLeaf starts applied with
  | nil =>
      simp [commitmentStartsFrom] at startsOk
      rcases startsOk with ⟨hLeaf, hStarts⟩
      subst finalLeaf
      subst starts
      rfl
  | cons action rest ih =>
      unfold commitmentStartsFrom at startsOk
      by_cases countMatches :
          action.commitmentCount = action.ciphertextCount
      · simp [countMatches] at startsOk
        cases nextLeafResult :
            checkedAddU64 leaf action.ciphertextCount with
        | none =>
            simp [nextLeafResult] at startsOk
        | some nextLeaf =>
            cases restResult :
                commitmentStartsFrom nextLeaf rest with
            | none =>
                simp [nextLeafResult, restResult] at startsOk
            | some pair =>
                cases pair with
                | mk restFinal restStarts =>
                    simp [
                      nextLeafResult,
                      restResult
                    ] at startsOk
                    rcases startsOk with ⟨hFinal, hStarts⟩
                    subst finalLeaf
                    subst starts
                    have recOk :
                        evaluateActionPlanApplicationFrom
                            nextLeaf
                            (streamCommitmentCounts rest)
                            restStarts
                            (applied + 1) =
                          Except.ok
                            {
                              nextLeafCount := restFinal,
                              appliedActionCount :=
                                (applied + 1) + rest.length
                            } :=
                      ih (applied := applied + 1) restResult
                    have appliedCountEq :
                        (applied + 1) + rest.length =
                          applied + (rest.length + 1) := by
                      rw [Nat.add_assoc]
                      rw [Nat.add_comm 1 rest.length]
                    simp [
                      evaluateActionPlanApplicationFrom,
                      streamCommitmentCounts,
                      countMatches,
                      nextLeafResult
                    ]
                    change
                      evaluateActionPlanApplicationFrom
                          nextLeaf
                          (streamCommitmentCounts rest)
                          restStarts
                          (applied + 1) =
                        Except.ok
                          {
                            nextLeafCount := restFinal,
                            appliedActionCount :=
                              applied + (rest.length + 1)
                          }
                    rw [recOk]
                    simp [appliedCountEq]
      · simp [countMatches] at startsOk

theorem commitment_starts_plan_application_accepts
    {leaf finalLeaf : Nat}
    {actions : List StreamAction}
    {starts : List Nat}
    (startsOk :
      commitmentStartsFrom leaf actions = some (finalLeaf, starts)) :
    evaluateActionPlanApplication
        {
          leafStart := leaf,
          actionCommitmentCounts := streamCommitmentCounts actions,
          plannedStarts := starts
        } =
      Except.ok
        {
          nextLeafCount := finalLeaf,
          appliedActionCount := actions.length
        } := by
  unfold evaluateActionPlanApplication
  simpa using
    commitment_starts_plan_application_from_accepts
      (applied := 0)
      startsOk

theorem accepted_stream_canonical_plan_accepts
    {input : ActionStreamInput}
    {output : ActionStreamOutput}
    (accepted :
      evaluateActionStreamEffect input = Except.ok output) :
    ∃ planOutput,
      evaluateActionPlanApplication
          (planInputFromAcceptedStream input output) =
        Except.ok planOutput ∧
      planOutput.nextLeafCount = output.nextLeafCount ∧
      planOutput.appliedActionCount = input.actions.length := by
  have startsOk :
      commitmentStartsFrom input.leafStart input.actions =
        some (output.nextLeafCount, output.plannedStarts) :=
    accepted_stream_commitment_starts_from accepted
  have planOk :
      evaluateActionPlanApplication
          (planInputFromAcceptedStream input output) =
        Except.ok
          {
            nextLeafCount := output.nextLeafCount,
            appliedActionCount := input.actions.length
          } := by
    simpa [planInputFromAcceptedStream]
      using commitment_starts_plan_application_accepts startsOk
  exact
    ⟨
      {
        nextLeafCount := output.nextLeafCount,
        appliedActionCount := input.actions.length
      },
      planOk,
      rfl,
      rfl
    ⟩

theorem accepted_stream_tree_transition_refines_applied_root
    {input : ActionStreamInput}
    {output : ActionStreamOutput}
    {treeInput : TreeTransitionInput}
    (streamAccepted :
      evaluateActionStreamEffect input = Except.ok output)
    (treeAccepted : treeTransitionAccepts treeInput = true) :
    ∃ planOutput,
      evaluateActionPlanApplication
          (planInputFromAcceptedStream input output) =
        Except.ok planOutput ∧
      planOutput.nextLeafCount = output.nextLeafCount ∧
      acceptedAppliedRoot treeInput = some treeInput.appliedRoot := by
  rcases accepted_stream_canonical_plan_accepts streamAccepted with
    ⟨planOutput, planOk, nextLeafOk, _appliedOk⟩
  exact
    ⟨
      planOutput,
      planOk,
      nextLeafOk,
      accepted_transition_returns_applied_root treeInput treeAccepted
    ⟩

end CommitmentTreeRefinement
end Native
end Hegemon
