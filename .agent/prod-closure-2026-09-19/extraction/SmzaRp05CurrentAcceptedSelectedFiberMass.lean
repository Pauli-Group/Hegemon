import SmzaRp05CurrentAcceptedSelectorProjectionTransport
import SmzaRp05CurrentOrdinarySoundnessComposition
import SmzaRp05CurrentSelectedCurrentAdviceEventMass
import SmzaRp05OrdinarySoundnessExecution

/-! # Accepted X-view selector mass on the ordinary fixed fibers

This composes the original physical-branch selector projection with the
checked fixed-fiber disintegration.  The same selected branch, workspace,
and Born amplitudes are retained throughout.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSelectedFiberMass

open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.FiniteOracleDatabase
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRoleDomainConditioning
open SmzaRp05ConditionedExecution
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05CurrentSelectedChallengeClaims
open SmzaRp05CurrentSelectedCurrentAdviceEventMass
open SmzaRp05CurrentNonchallengeSelectorTransport
open SmzaRp05CurrentAcceptedSelectorProjectionTransport
open SmzaRp05OrdinarySoundnessExecution
open SmzaRp05CurrentOrdinarySoundnessComposition
open SmzaRp05AdaptiveRetainedAdviceTransport (physical_run_to_mixed_same_fiber)
open SmzaRp05AdaptivePhysicalReadBound (physicalBranchesFintype)
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 14000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

/-- Sum the same accepted X-view selector over literal physical branches,
then disintegrate it into the exact selected-state masses used by the
ordinary current-advice bound.  Only selector-to-claim consistency and the
checked role-domain separation are inputs; neither is a probability bound. -/
theorem accepted_xview_selector_mass_le_ordinary_selected_fiber_mass
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (select : Branches decode program →
      (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput Counter)) →
      SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (selectorClaims : ∀ branch view work, select branch view work →
      ∀ claim (member : claim ∈ unrecognizedActiveBranchClaims ctx blockCap
        encode decode program branch),
        view ⟨claim.1.val,
          by
            apply Finset.mem_filter.mpr
            exact ⟨Finset.mem_univ _, of_decide_eq_true
              (List.mem_filter.mp member).2⟩⟩ = some claim.2)
    (outside : ∀ key, key ∈ fixedOtherKeys ctx blockCap →
      key ∉ nonchallengeRawKeySet ctx) :
    letI := physicalBranchesFintype decode program
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
    (∑ branch : Branches decode program,
      normSquared (workspaceEventProjection
        (fun work database => select branch (xView (nonchallengeRawKeySet ctx) database) work)
        (physicalRun encode decode program branch initial))) ≤
    (∑ branch : Branches decode program,
      ∑ fixed : FixedTable ctx blockCap,
        normSquared (selectedRoleState ctx blockCap encode decode program branch fixed
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap initial))
          (select branch))) := by
  classical
  letI := physicalBranchesFintype decode program
  dsimp only
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
  calc
    (∑ branch : Branches decode program,
      normSquared (workspaceEventProjection
        (fun work database => select branch (xView (nonchallengeRawKeySet ctx) database) work)
        (physicalRun encode decode program branch initial))) ≤
    (∑ branch : Branches decode program,
      normSquared (nonchallengeSelectorProjection (nonchallengeRawKeySet ctx)
        (branchXRoleSelector ctx blockCap encode decode program branch
          (nonchallengeRawKeySet ctx)
          (by
            intro claim member
            apply Finset.mem_filter.mpr
            exact ⟨Finset.mem_univ _, of_decide_eq_true
              (List.mem_filter.mp member).2⟩)
          (select branch))
        (otherRoleTransform ctx blockCap
          (physicalRun encode decode program branch initial)))) := by
      apply Finset.sum_le_sum
      intro branch _
      exact accepted_xview_selector_mass_le_branch_selector_mass
        ctx blockCap encode decode program branch (select branch)
        (physicalRun encode decode program branch initial)
        (selectorClaims branch) outside
    _ = (∑ branch : Branches decode program,
        ∑ fixed : FixedTable ctx blockCap,
          normSquared (workspaceEventProjection
            (HegemonCrypto.SmallWood.SmzaRp05CurrentNonchallengeSelectorFiberMass.activeNonchallengeSelectorEvent ctx blockCap
              (nonchallengeRawKeySet ctx)
              (nonchallenge_raw_key_set_unrecognized ctx)
              (branchXRoleSelector ctx blockCap encode decode program branch
                (nonchallengeRawKeySet ctx)
                (by
                  intro claim member
                  apply Finset.mem_filter.mpr
                  exact ⟨Finset.mem_univ _, of_decide_eq_true
                    (List.mem_filter.mp member).2⟩)
                (select branch)))
            (fixedFiberToActive ctx blockCap dummy fixed
              (otherRoleTransform ctx blockCap
                (physicalRun encode decode program branch initial))))) := by
      exact ordinary_selected_branch_mass_eq_same_fiber_sum
        ordinaryProgram registers encode decode program ctx blockCap dummy select
    _ = (∑ branch : Branches decode program,
        ∑ fixed : FixedTable ctx blockCap,
          normSquared (selectedRoleState ctx blockCap encode decode program branch fixed
            (fixedFiberToActive ctx blockCap dummy fixed
              (otherRoleTransform ctx blockCap initial))
            (select branch))) := by
      apply Finset.sum_congr rfl
      intro branch _
      apply Finset.sum_congr rfl
      intro fixed _
      unfold selectedRoleState
      have mixedEq := physical_run_to_mixed_same_fiber ctx blockCap dummy fixed
        encode decode program branch initial
      rw [← mixedEq]
      rfl

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSelectedFiberMass
