import SmzaRp05OrdinarySoundnessStandardTotal
import SmzaRp05CurrentSelectedChallengeClaims
import SmzaRp05AdaptiveRetainedAdviceTransport

/-! # Selected current claims on the original ordinary-prefix Born measure

This file lifts the selected challenge-claim readout inequality through the
literal physical answer branches and their exact fixed-table fibers.  The
selector may depend on the branch, its X-restricted database view, and the
classical workspace; no branch-only reduction or per-fiber renormalization is
used. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentOrdinarySoundnessComposition

open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.FiniteOracleDatabase
open SmzaChallengeStageTargets (Role)
open SmzaRoleDomainConditioning
open SmzaRp05ConditionedExecution
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05OrdinarySoundnessExecution
open SmzaRp05OrdinarySoundnessStandardTotal
open SmzaRp05AdaptiveRetainedAdviceTransport
open SmzaRp05AdaptivePhysicalReadBound (physicalBranchesFintype)
open SmzaRp05CurrentNonchallengeSelectorTransport
open SmzaRp05CurrentNonchallengeSelectorFiberMass
open SmzaRp05CurrentSelectedChallengeClaims
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

private def selectedBranchView
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (select : Branches decode program →
      (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput Counter)) →
        SmzaRp05CurrentAdaptiveExecution.Work
          (Counter := Counter) (BaseWork := BaseWork) → Prop) :
    (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput Counter)) →
      SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork) → Prop :=
  branchXRoleSelector ctx blockCap encode decode program branch
    (nonchallengeRawKeySet ctx)
    (by
      intro claim member
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
        of_decide_eq_true (List.mem_filter.mp member).2⟩)
    (select branch)

private def selectedBranchState
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (fixed : FixedTable ctx blockCap)
    (initial : ActiveState ctx blockCap)
    (select : Branches decode program →
      (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput Counter)) →
        SmzaRp05CurrentAdaptiveExecution.Work
          (Counter := Counter) (BaseWork := BaseWork) → Prop) :
    ActiveState ctx blockCap :=
  workspaceEventProjection
    (fun work database => selectedBranchView ctx blockCap encode decode
      program branch select
      (activeXView ctx blockCap (nonchallengeRawKeySet ctx)
        (nonchallenge_raw_key_set_unrecognized ctx) database)
      work.original.2.2)
    (mixedRun ctx blockCap fixed encode decode program branch initial)

private def selectedChallengeClaims
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program) :
    List (ActiveKey ctx.role blockCap ctx.keyBytes × VectorOutput Counter) :=
  recognizedActiveChallengeClaims ctx blockCap encode decode program branch

/-- Exact fixed-fiber disintegration for an arbitrary branch-indexed selector
of the literal X-view and workspace.  The right side is the same physical
answer branch run under the matching fixed table, not a rerun or normalized
conditional experiment. -/
theorem ordinary_selected_branch_mass_eq_same_fiber_sum
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (select : Branches decode program →
      (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput Counter)) →
        SmzaRp05CurrentAdaptiveExecution.Work
          (Counter := Counter) (BaseWork := BaseWork) → Prop) :
    letI := physicalBranchesFintype decode program
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
    (∑ branch : Branches decode program,
      normSquared (nonchallengeSelectorProjection (nonchallengeRawKeySet ctx)
        (selectedBranchView ctx blockCap encode decode program branch select)
        (otherRoleTransform ctx blockCap
          (physicalRun encode decode program branch initial)))) =
    (∑ branch : Branches decode program,
      ∑ fixed : FixedTable ctx blockCap,
        normSquared (workspaceEventProjection
          (activeNonchallengeSelectorEvent ctx blockCap
            (nonchallengeRawKeySet ctx)
            (nonchallenge_raw_key_set_unrecognized ctx)
            (selectedBranchView ctx blockCap encode decode program branch select))
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap
              (physicalRun encode decode program branch initial))))) := by
  classical
  letI := physicalBranchesFintype decode program
  dsimp only
  apply Finset.sum_congr rfl
  intro branch _
  exact ordinary_physical_branch_selector_mass_eq_active_fiber_sum
    ordinaryProgram registers encode decode program branch ctx blockCap dummy
    (nonchallengeRawKeySet ctx)
    (nonchallenge_raw_key_set_unrecognized ctx)
    (selectedBranchView ctx blockCap encode decode program branch select)

/-- The selected challenge answers account for all but the actual finite
readout loss on that same selected branch/fiber state. Summing preserves the
original Born weights across ordinary-prefix execution, measured verifier
branches, and fixed tables. This is a derived inequality, not a supplied
probability premise. -/
theorem ordinary_selected_challenge_claim_mass_lower
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (select : Branches decode program →
      (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput Counter)) →
        SmzaRp05CurrentAdaptiveExecution.Work
          (Counter := Counter) (BaseWork := BaseWork) → Prop) :
    letI := physicalBranchesFintype decode program
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
    (∑ branch : Branches decode program,
      normSquared (nonchallengeSelectorProjection (nonchallengeRawKeySet ctx)
        (selectedBranchView ctx blockCap encode decode program branch select)
        (otherRoleTransform ctx blockCap
          (physicalRun encode decode program branch initial)))) ≤
    (∑ branch : Branches decode program,
      ∑ fixed : FixedTable ctx blockCap,
        (normSquared (databaseEventProjection
          (ClaimsDatabaseEvent
            (selectedChallengeClaims ctx blockCap encode decode program branch))
          (selectedBranchState ctx blockCap encode decode program branch fixed
            (fixedFiberToActive ctx blockCap dummy fixed
              (otherRoleTransform ctx blockCap initial)) select)) +
        (((2 * (selectedChallengeClaims ctx blockCap encode decode program branch).toFinset.card : Nat) : ℝ) /
          Fintype.card (VectorOutput Counter)) *
          normSquared (selectedBranchState ctx blockCap encode decode program branch fixed
            (fixedFiberToActive ctx blockCap dummy fixed
              (otherRoleTransform ctx blockCap initial)) select))) := by
  classical
  dsimp only
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
  letI := physicalBranchesFintype decode program
  rw [ordinary_selected_branch_mass_eq_same_fiber_sum
    ordinaryProgram registers encode decode program ctx blockCap dummy select]
  apply Finset.sum_le_sum
  intro branch _
  apply Finset.sum_le_sum
  intro fixed _
  have lower := actual_selected_challenge_claim_event_mass_lower_on_all_x_keys
    ctx blockCap fixed encode decode program branch
    (fixedFiberToActive ctx blockCap dummy fixed
      (otherRoleTransform ctx blockCap initial))
    (fun view work => select branch view work)
  have mixedEq := physical_run_to_mixed_same_fiber ctx blockCap dummy fixed
    encode decode program branch initial
  -- The actual selected event on this active fiber is exactly the event in
  -- the mixed-branch claim theorem; `physical_run_to_mixed_same_fiber` keeps
  -- its answer branch and amplitude unchanged.
  rw [mixedEq]
  dsimp only [selectedBranchView, selectedBranchState,
    selectedChallengeClaims, activeNonchallengeSelectorEvent, initial] at *
  exact lower

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentOrdinarySoundnessComposition
