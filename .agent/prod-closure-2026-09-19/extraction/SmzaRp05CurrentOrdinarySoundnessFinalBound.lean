import SmzaRp05CurrentOrdinaryReadoutBudget
import SmzaRp05CurrentSelectedCurrentAdviceEventMass
import SmzaRp05CurrentSelectedChallengeClaims
import SmzaRp05CurrentAdviceDependentPhysicalMass
import SmzaRp05Current406EventSpec
import SmzaRp05OrdinaryCurrentAdviceMass
import SmzaRp05OrdinarySoundnessPhysicalMass

/-! # Scalar composition for ordinary current soundness

This composes support-wise role-event classification with the corrected
current-advice estimates, actual physical collision estimates, and the
finite-readout loss.  The only classifier input is pointwise support
coverage; no event probability or branch-mass estimate is assumed.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentOrdinarySoundnessFinalBound

open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.FiniteOracleDatabase
open SmzaChallengeStageTargets (Role)
open SmzaRoleDomainConditioning
open SmzaRp05ConditionedExecution
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05CurrentSelectedCurrentAdviceEventMass
open SmzaRp05CurrentSelectedChallengeClaims
open SmzaRp05CurrentAdviceDependentPhysicalMass (currentAdviceEventSpec)
open SmzaRp05Current406EventSpec (current406Bound)
open SmzaRp05OrdinaryCurrentAdviceMass
open SmzaRp05OrdinarySoundnessPhysicalMass
open SmzaRp05OrdinarySoundnessExecution
open SmzaRp05OrdinarySoundnessStandardTotal (initialized_ordinary_run_standard_total)
open SmzaRp05RoleReadTotality (StandardOn)
open SmzaRp05CurrentOrdinaryReadoutBudget
open SmzaRp05CurrentPhysicalNonchallengeClaims (branchNonchallengeClaims)
open SmzaRp05PartialReadout (claimFailureProjection)
open SmzaRp05CurrentFilteredCollisionEventSpec (filteredCollisionEventSpec)
open SmzaRp05AdaptivePhysicalReadBound (ReadsAtMost ReadsWithinKeys physicalBranchesFintype)
open SmzaRp05PhysicalAcceptedReplayLite (Branches physicalRun)
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8Smz9CoherentVectorMerkle (VectorOutput)

local notation "RawInput" => V8SmzaOracleParser.RawInput
local notation "RawDigest" => V8SmzaOracleParser.RawDigest

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option maxRecDepth 12000
set_option maxHeartbeats 2000000
set_option exponentiation.threshold 1024

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

private theorem combine_scalar_budgets
    (a b c d e f g h : ℝ)
    (hab : a ≤ b + c) (hdc : d + c ≤ e)
    (hbf : b ≤ f) (hgh : g ≤ h) :
    a + d + g ≤ f + e + h := by
  linarith

/-- Same-branch selected-role mass, parser-none readout failure, and
role-specific collision mass are bounded by corrected current-406 event
mass, the combined readout budget, and the ordinary collision estimate.

`included` is the only role-classifier premise: every nonzero selected
coefficient either satisfies that fixed table's current-advice event or has
lost a recognized challenge answer.  It is pointwise support coverage, not
a supplied probability bound.  The two norm factors are kept explicit: the
readout estimate is on the post-prefix Born state, while the physical
current-advice and collision theorems are scaled by the incoming register
norm.
-/
theorem ordinary_selected_readout_collision_scalar_bound
    (contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork))
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (depth : Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (readBound : ReadsAtMost decode depth program)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys program)
    (supportWithin : finish + depth ≤ cap) (queriesWithin : queries + depth ≤ cap)
    (blockCap : Role → Nat)
    (dummy : ∀ role : Role,
      ActiveKey (emptyAuthorizationContexts contexts role).role blockCap
        (emptyAuthorizationContexts contexts role).keyBytes)
    (select : ∀ role : Role, Branches decode program →
      (XKey (nonchallengeRawKeySet (emptyAuthorizationContexts contexts role)) →
        Option (VectorOutput Counter)) →
      SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (included : ∀ (role : Role) (branch : Branches decode program)
        (fixed : FixedTable (emptyAuthorizationContexts contexts role) blockCap)
        (basis : Basis (ActiveKey (emptyAuthorizationContexts contexts role).role
          blockCap (emptyAuthorizationContexts contexts role).keyBytes)
          (VectorOutput Counter) (VectorOutput Counter)
          (ActiveMemory (emptyAuthorizationContexts contexts role))),
      selectedRoleState (emptyAuthorizationContexts contexts role) blockCap
        encode decode program branch fixed
        (fixedFiberToActive (emptyAuthorizationContexts contexts role) blockCap
          (dummy role) fixed
          (otherRoleTransform (emptyAuthorizationContexts contexts role) blockCap
            (ordinaryRun ordinaryProgram
              (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))))
        (select role branch) basis ≠ 0 →
      SmzaRp05ActualEventRecertification.event
          (currentAdviceEventSpec (emptyAuthorizationContexts contexts role)
            blockCap fixed cap)
          (activeMemoryEquiv (emptyAuthorizationContexts contexts role) basis.workspace)
          basis.database ∨
        ¬ ClaimsDatabaseEvent
          (recognizedActiveChallengeClaims (emptyAuthorizationContexts contexts role)
            blockCap encode decode program branch) basis.database) :
    letI := physicalBranchesFintype decode program
    (∑ role : Role, ∑ branch : Branches decode program,
      ∑ fixed : FixedTable (emptyAuthorizationContexts contexts role) blockCap,
        normSquared (selectedRoleState (emptyAuthorizationContexts contexts role)
          blockCap encode decode program branch fixed
          (fixedFiberToActive (emptyAuthorizationContexts contexts role) blockCap
            (dummy role) fixed
            (otherRoleTransform (emptyAuthorizationContexts contexts role) blockCap
              (ordinaryRun ordinaryProgram
                (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))))
          (select role branch))) +
    (∑ role : Role, ∑ branch : Branches decode program,
      ∑ fixed : FixedTable (emptyAuthorizationContexts contexts role) blockCap,
        normSquared (workspaceEventProjection
          (fun memory database => SmzaRp05ActualEventRecertification.event
            (filteredCollisionEventSpec
              (activeContext (emptyAuthorizationContexts contexts role) blockCap fixed)
              cap)
            (activeMemoryEquiv (emptyAuthorizationContexts contexts role) memory)
            database)
          (fixedFiberToActive (emptyAuthorizationContexts contexts role) blockCap
            (dummy role) fixed
            (otherRoleTransform (emptyAuthorizationContexts contexts role) blockCap
              (physicalRun encode decode program branch
                (ordinaryRun ordinaryProgram
                  (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))))))) +
    (∑ role : Role, ∑ branch : Branches decode program,
      normSquared (claimFailureProjection
        (branchNonchallengeClaims
          (emptyAuthorizationContexts contexts role).keyBytes encode decode program branch)
        (physicalRun encode decode program branch
          (ordinaryRun ordinaryProgram
            (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))))) ≤
      (∑ role : Role,
        (6 * (cap : ℝ)^2 * current406Bound
          (emptyAuthorizationContexts contexts role).role cap) *
          normSquared (partialRandomOracleState
            (Output := VectorOutput Counter) ∅ registers)) +
      (16 * (depth : ℝ) / Fintype.card (VectorOutput Counter)) *
        normSquared (ordinaryRun ordinaryProgram
          (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) +
      (∑ _role : Role,
        (6 * (cap : ℝ)^2 * ((((cap : Rat) / (2 ^ 512 : Rat) : Rat) : ℝ))) *
          normSquared (partialRandomOracleState
            (Output := VectorOutput Counter) ∅ registers)) := by
  classical
  letI := physicalBranchesFintype decode program
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
  let roleCtx (role : Role) := emptyAuthorizationContexts contexts role
  let selectedMass := ∑ role : Role, ∑ branch : Branches decode program,
    ∑ fixed : FixedTable (roleCtx role) blockCap,
      normSquared (selectedRoleState (roleCtx role) blockCap encode decode program
        branch fixed (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
          (otherRoleTransform (roleCtx role) blockCap initial)) (select role branch))
  let selectedEventMass := ∑ role : Role, ∑ branch : Branches decode program,
    ∑ fixed : FixedTable (roleCtx role) blockCap,
      normSquared (workspaceEventProjection
        (fun memory database => SmzaRp05ActualEventRecertification.event
          (currentAdviceEventSpec (roleCtx role) blockCap fixed cap)
          (activeMemoryEquiv (roleCtx role) memory) database)
        (selectedRoleState (roleCtx role) blockCap encode decode program branch fixed
          (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
            (otherRoleTransform (roleCtx role) blockCap initial))
          (select role branch)))
  let claimFailure := ∑ role : Role, ∑ branch : Branches decode program,
    ∑ fixed : FixedTable (roleCtx role) blockCap,
      normSquared (databaseEventProjection
        (fun database => ¬ ClaimsDatabaseEvent
          (recognizedActiveChallengeClaims (roleCtx role) blockCap encode decode program branch)
          database)
        (selectedRoleState (roleCtx role) blockCap encode decode program branch fixed
          (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
            (otherRoleTransform (roleCtx role) blockCap initial)) (select role branch)))
  let nonchallengeFailure := ∑ role : Role, ∑ branch : Branches decode program,
    normSquared (claimFailureProjection
      (branchNonchallengeClaims (roleCtx role).keyBytes encode decode program branch)
      (physicalRun encode decode program branch initial))
  let collisionMass := ∑ role : Role, ∑ fixed : FixedTable (roleCtx role) blockCap,
    ∑ branch : Branches decode program,
      normSquared (workspaceEventProjection
        (fun memory database => SmzaRp05ActualEventRecertification.event
          (filteredCollisionEventSpec (activeContext (roleCtx role) blockCap fixed) cap)
          (activeMemoryEquiv (roleCtx role) memory) database)
        (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
          (otherRoleTransform (roleCtx role) blockCap
            (physicalRun encode decode program branch initial))))
  let incomingNorm := normSquared
    (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
  let prefixNorm := normSquared initial
  let currentBudget := ∑ role : Role,
    (6 * (cap : ℝ)^2 * current406Bound (roleCtx role).role cap) * incomingNorm
  let readoutBudget :=
    (16 * (depth : ℝ) / Fintype.card (VectorOutput Counter)) * prefixNorm
  let collisionBudget := ∑ role : Role,
    (6 * (cap : ℝ)^2 * ((((cap : Rat) / (2 ^ 512 : Rat) : Rat) : ℝ))) * incomingNorm
  have selectedSplit : selectedMass ≤ selectedEventMass + claimFailure := by
    dsimp only [selectedMass, selectedEventMass, claimFailure, roleCtx]
    rw [← Finset.sum_add_distrib]
    apply Finset.sum_le_sum
    intro role _
    rw [← Finset.sum_add_distrib]
    apply Finset.sum_le_sum
    intro branch _
    rw [← Finset.sum_add_distrib]
    apply Finset.sum_le_sum
    intro fixed _
    exact selected_role_state_mass_le_current_advice_plus_missing_claims
      (emptyAuthorizationContexts contexts role) blockCap encode decode program branch fixed
      (fixedFiberToActive (emptyAuthorizationContexts contexts role) blockCap
        (dummy role) fixed (otherRoleTransform (emptyAuthorizationContexts contexts role)
          blockCap initial)) (select role branch)
      (fun memory database => SmzaRp05ActualEventRecertification.event
        (currentAdviceEventSpec (emptyAuthorizationContexts contexts role) blockCap fixed cap)
        (activeMemoryEquiv (emptyAuthorizationContexts contexts role) memory) database)
      (included role branch fixed)
  have selectedEventBound : selectedEventMass ≤ currentBudget := by
    dsimp only [selectedEventMass, roleCtx, incomingNorm]
    apply Finset.sum_le_sum
    intro role _
    simpa using ordinary_selected_current_advice_event_mass_le contexts
      ordinaryProgram registers role blockCap (dummy role) depth encode decode program
      readBound keys keysWithin supportWithin queriesWithin (select role)
  have readoutBound := ordinary_four_role_total_readout_loss_le
    (fun role => roleCtx role) ordinaryProgram registers depth encode decode program
    readBound keys keysWithin blockCap dummy select
  have collisionBound : collisionMass ≤ collisionBudget := by
    dsimp only [collisionMass, roleCtx, incomingNorm]
    have standardTotal := initialized_ordinary_run_standard_total ordinaryProgram registers
    have standard : StandardOn keys
        (ordinaryRun ordinaryProgram
          (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) := by
      intro key _
      exact standardTotal key
    apply Finset.sum_le_sum
    intro role _
    simpa using ordinary_filtered_collision_fiber_mass_le
      contexts ordinaryProgram role blockCap (dummy role) registers depth encode decode
      program readBound keys keysWithin supportWithin queriesWithin standard
  have combinedReadout : nonchallengeFailure + claimFailure ≤
      readoutBudget := by
    dsimp only [nonchallengeFailure, claimFailure, roleCtx, prefixNorm, initial]
    have bound := readoutBound
    dsimp only at bound
    exact bound
  have mainBound : selectedMass + collisionMass + nonchallengeFailure ≤
      currentBudget + readoutBudget + collisionBudget := by
    calc
      selectedMass + collisionMass + nonchallengeFailure =
          selectedMass + nonchallengeFailure + collisionMass := by ring
      _ ≤ currentBudget + readoutBudget + collisionBudget :=
        combine_scalar_budgets selectedMass selectedEventMass claimFailure
          nonchallengeFailure readoutBudget currentBudget collisionMass collisionBudget
          selectedSplit combinedReadout selectedEventBound collisionBound
  have collisionMassOrder : collisionMass =
      ∑ role : Role, ∑ branch : Branches decode program,
        ∑ fixed : FixedTable (roleCtx role) blockCap,
          normSquared (workspaceEventProjection
            (fun memory database => SmzaRp05ActualEventRecertification.event
              (filteredCollisionEventSpec (activeContext (roleCtx role) blockCap fixed) cap)
              (activeMemoryEquiv (roleCtx role) memory) database)
            (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
              (otherRoleTransform (roleCtx role) blockCap
                (physicalRun encode decode program branch initial)))) := by
    dsimp only [collisionMass]
    apply Finset.sum_congr rfl
    intro role _
    exact Finset.sum_comm
  rw [← collisionMassOrder]
  simpa only [selectedMass, nonchallengeFailure, collisionMass, roleCtx, initial,
    incomingNorm, prefixNorm, currentBudget, readoutBudget, collisionBudget] using mainBound

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentOrdinarySoundnessFinalBound
