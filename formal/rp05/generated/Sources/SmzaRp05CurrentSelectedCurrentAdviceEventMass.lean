import SmzaRp05CurrentSelectedChallengeClaims
import SmzaRp05CurrentAdviceDependentPhysicalMass
import SmzaRp05AdaptivePhysicalReadBound
import SmzaRp05OrdinaryCurrentAdviceMass

/-! # Selected-state current-advice event mass

The selector and recognized challenge claims classify every supported basis
of the same selected mixed state. This converts that pointwise classification
into a diagonal-projection mass split, then compares its current-advice term
with the unselected fixed-fiber event mass. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedCurrentAdviceEventMass

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRoleDomainConditioning
open SmzaRp05ConditionedExecution
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05CurrentSelectedChallengeClaims
open SmzaRp05CurrentAdviceDependentPhysicalMass
open SmzaRp05Current406EventSpec
open SmzaRp05OrdinaryCurrentAdviceMass
open SmzaRp05DependentAdviceEvent
open SmzaRp05OrdinarySoundnessExecution
open SmzaRp05AdaptivePhysicalReadBound (ReadsAtMost ReadsWithinKeys)
open SmzaRp05AdaptiveRetainedAdviceTransport
open SmzaRp05AdaptivePhysicalReadBound (physicalBranchesFintype)
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8Smz9CoherentVectorMerkle (VectorOutput)

local notation "RawInput" => V8SmzaOracleParser.RawInput
local notation "RawDigest" => V8SmzaOracleParser.RawDigest

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

abbrev SelectedWork := SmzaRp05CurrentAdaptiveExecution.Work
  (Counter := Counter) (BaseWork := BaseWork)

/-- Support-wise coverage by the desired event or by the missing-claims
event implies a mass bound on the same unnormalized state. -/
theorem norm_squared_le_workspace_event_add_missing_claim_mass
    {Input Output Phase Workspace : Type}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (event : Workspace → Database Input Output → Prop)
    (claims : List (Input × Output))
    (state : HegemonCrypto.CmsCompressedOracle.State Input Output Phase Workspace)
    (covered : ∀ basis : HegemonCrypto.CmsCompressedOracle.Basis
        Input Output Phase Workspace,
      state basis ≠ 0 →
        event basis.workspace basis.database ∨
          ¬ ClaimsDatabaseEvent claims basis.database) :
    normSquared state ≤
      normSquared (workspaceEventProjection event state) +
        normSquared (databaseEventProjection
          (fun database => ¬ ClaimsDatabaseEvent claims database) state) := by
  classical
  unfold normSquared workspaceEventProjection databaseEventProjection
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_le_sum
  intro basis _
  by_cases selected : event basis.workspace basis.database
  · simp only [selected, if_pos]
    apply le_add_of_nonneg_right
    exact Complex.normSq_nonneg _
  · by_cases nonzero : state basis ≠ 0
    · have missing := (covered basis nonzero).resolve_left selected
      simp [selected, missing]
    · have stateZero : state basis = 0 := by simpa using nonzero
      simp [selected, stateZero]

/-- A second workspace-event projection cannot increase the mass already
selected by a first one. -/
theorem workspace_event_mass_after_workspace_projection_le
    {Input Output Phase Workspace : Type}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (event selector : Workspace → Database Input Output → Prop)
    (state : HegemonCrypto.CmsCompressedOracle.State Input Output Phase Workspace) :
    normSquared (workspaceEventProjection event
      (workspaceEventProjection selector state)) ≤
        normSquared (workspaceEventProjection event state) := by
  classical
  unfold normSquared workspaceEventProjection
  apply Finset.sum_le_sum
  intro basis _
  by_cases selected : event basis.workspace basis.database
  · by_cases chosen : selector basis.workspace basis.database
    · simp [selected, chosen]
    · simp [selected, chosen]
      exact Complex.normSq_nonneg _
  · simp [selected]

/-- The actual selector state used by the ordinary readout budget, exposed
here to compose its event and missing-claim masses on one mixed run. -/
def selectedRoleState
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (fixed : FixedTable ctx blockCap)
    (initial : SmzaRp05ConditionedExecution.ActiveState ctx blockCap)
    (select : (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput Counter)) →
      SelectedWork (Counter := Counter) (BaseWork := BaseWork) → Prop) :
    SmzaRp05ConditionedExecution.ActiveState ctx blockCap :=
  workspaceEventProjection
    (fun work database =>
      branchXRoleSelector ctx blockCap encode decode program branch
        (nonchallengeRawKeySet ctx)
        (by
          intro claim member
          exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
            of_decide_eq_true (List.mem_filter.mp member).2⟩)
        select
        (activeXView ctx blockCap (nonchallengeRawKeySet ctx)
          (nonchallenge_raw_key_set_unrecognized ctx) database)
        work.original.2.2)
    (mixedRun ctx blockCap fixed encode decode program branch initial)

/-- Support-aware selected-state classification splits its mass between the
current-advice event and the complement of recognized challenge claims. The
`included` premise is the deterministic classifier obligation, not a
probability premise. -/
theorem selected_role_state_mass_le_current_advice_plus_missing_claims
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (fixed : FixedTable ctx blockCap)
    (initial : SmzaRp05ConditionedExecution.ActiveState ctx blockCap)
    (select : (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput Counter)) →
      SelectedWork (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (currentEvent : SmzaRp05ConditionedExecution.ActiveMemory ctx →
      Database (ActiveKey ctx.role blockCap ctx.keyBytes)
        (VectorOutput Counter) → Prop)
    (included : ∀ basis : HegemonCrypto.CmsCompressedOracle.Basis
        (ActiveKey ctx.role blockCap ctx.keyBytes)
        (VectorOutput Counter) (VectorOutput Counter)
        (SmzaRp05ConditionedExecution.ActiveMemory ctx),
      selectedRoleState ctx blockCap encode decode program branch fixed initial select
          basis ≠ 0 →
        currentEvent basis.workspace basis.database ∨
          ¬ ClaimsDatabaseEvent
            (recognizedActiveChallengeClaims ctx blockCap encode decode program branch)
            basis.database) :
    normSquared
        (selectedRoleState ctx blockCap encode decode program branch fixed initial select) ≤
      normSquared (workspaceEventProjection currentEvent
        (selectedRoleState ctx blockCap encode decode program branch fixed initial select)) +
      normSquared (databaseEventProjection
        (fun database => ¬ ClaimsDatabaseEvent
          (recognizedActiveChallengeClaims ctx blockCap encode decode program branch)
          database)
        (selectedRoleState ctx blockCap encode decode program branch fixed initial select)) := by
  exact norm_squared_le_workspace_event_add_missing_claim_mass
    currentEvent (recognizedActiveChallengeClaims ctx blockCap encode decode program branch)
    (selectedRoleState ctx blockCap encode decode program branch fixed initial select) included

/-- Selected current-advice event mass is at most the same event mass on the
unselected fixed fiber of the original physical branch. -/
theorem selected_role_current_advice_event_mass_le_physical_fiber
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (fixed : FixedTable ctx blockCap)
    (initial : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (select : (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput Counter)) →
      SelectedWork (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (cap : Nat) :
    normSquared (workspaceEventProjection
      (fun memory database =>
        SmzaRp05ActualEventRecertification.event
          (currentAdviceEventSpec ctx blockCap fixed cap)
          (activeMemoryEquiv ctx memory) database)
      (selectedRoleState ctx blockCap encode decode program branch fixed
        (fixedFiberToActive ctx blockCap dummy fixed
          (otherRoleTransform ctx blockCap
            initial)) select)) ≤
    normSquared (workspaceEventProjection
      (fun memory database =>
        SmzaRp05ActualEventRecertification.event
          (currentAdviceEventSpec ctx blockCap fixed cap)
          (activeMemoryEquiv ctx memory) database)
      (fixedFiberToActive ctx blockCap dummy fixed
        (otherRoleTransform ctx blockCap
          (physicalRun encode decode program branch initial)))) := by
  let selector : SmzaRp05ConditionedExecution.ActiveMemory ctx →
      Database (ActiveKey ctx.role blockCap ctx.keyBytes)
        (VectorOutput Counter) → Prop := fun work database =>
    branchXRoleSelector ctx blockCap encode decode program branch
      (nonchallengeRawKeySet ctx)
      (by
        intro claim member
        exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
          of_decide_eq_true (List.mem_filter.mp member).2⟩)
      select
      (activeXView ctx blockCap (nonchallengeRawKeySet ctx)
        (nonchallenge_raw_key_set_unrecognized ctx) database)
      work.original.2.2
  have stateEq :
      selectedRoleState ctx blockCap encode decode program branch fixed
        (fixedFiberToActive ctx blockCap dummy fixed
          (otherRoleTransform ctx blockCap
            initial)) select =
      workspaceEventProjection selector
        (fixedFiberToActive ctx blockCap dummy fixed
          (otherRoleTransform ctx blockCap
            (physicalRun encode decode program branch initial))) := by
    unfold selectedRoleState selector
    rw [← physical_run_to_mixed_same_fiber ctx blockCap dummy _
      encode decode program branch initial]
  rw [stateEq]
  exact workspace_event_mass_after_workspace_projection_le
    (fun memory database =>
        SmzaRp05ActualEventRecertification.event
          (currentAdviceEventSpec ctx blockCap fixed cap)
        (activeMemoryEquiv ctx memory) database)
    selector _

/-- Sum the selected event masses over actual fixed fibers and answer
branches. Its right side is precisely the fiber sum from
`physical_current_advice_current406_mass_eq_fiber_sum`. -/
theorem selected_role_current_advice_event_mass_le_fiber_sum
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (initial : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (select : Branches decode program →
      (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput Counter)) →
        SelectedWork (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (cap : Nat) :
    letI := physicalBranchesFintype decode program
    (∑ branch : Branches decode program, ∑ fixed : FixedTable ctx blockCap,
      normSquared (workspaceEventProjection
        (fun memory database =>
        SmzaRp05ActualEventRecertification.event
          (currentAdviceEventSpec ctx blockCap fixed cap)
            (activeMemoryEquiv ctx memory) database)
        (selectedRoleState ctx blockCap encode decode program branch fixed
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap initial))
          (select branch)))) ≤
    (∑ branch : Branches decode program, ∑ fixed : FixedTable ctx blockCap,
      normSquared (workspaceEventProjection
        (fun memory database =>
          SmzaRp05ActualEventRecertification.event
            (currentAdviceEventSpec ctx blockCap fixed cap)
            (activeMemoryEquiv ctx memory) database)
        (fixedFiberToActive ctx blockCap dummy fixed
          (otherRoleTransform ctx blockCap
            (physicalRun encode decode program branch initial))))) := by
  classical
  letI := physicalBranchesFintype decode program
  apply Finset.sum_le_sum
  intro branch _
  apply Finset.sum_le_sum
  intro fixed _
  exact selected_role_current_advice_event_mass_le_physical_fiber
    ctx blockCap dummy encode decode program branch fixed initial
    (select branch) cap

/-- Per-role scalar selected-event estimate for the exact ordinary-prefix
incoming state. The selected event sum is first moved to the unselected
physical fixed-fiber sum, then identified with the dependent current-advice
event mass and bounded by the checked ordinary-prefix theorem. -/
theorem ordinary_selected_current_advice_event_mass_le
    (contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork))
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (role : Role) (blockCap : Role → Nat)
    (dummy : ActiveKey (emptyAuthorizationContexts contexts role).role blockCap
      (emptyAuthorizationContexts contexts role).keyBytes)
    (depth : Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (suffix : Program Result) (readBound : ReadsAtMost decode depth suffix)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys suffix)
    (supportWithin : finish + depth ≤ cap) (queriesWithin : queries + depth ≤ cap)
    (select : Branches decode suffix →
      (XKey (nonchallengeRawKeySet
        (emptyAuthorizationContexts contexts role)) → Option (VectorOutput Counter)) →
        SelectedWork (Counter := Counter) (BaseWork := BaseWork) → Prop) :
    (letI := physicalBranchesFintype decode suffix
      ∑ branch : Branches decode suffix, ∑ fixed : FixedTable
        (emptyAuthorizationContexts contexts role) blockCap,
        normSquared (workspaceEventProjection
          (fun memory database =>
            SmzaRp05ActualEventRecertification.event
              (currentAdviceEventSpec (emptyAuthorizationContexts contexts role)
                blockCap fixed cap)
              (activeMemoryEquiv (emptyAuthorizationContexts contexts role) memory)
              database)
          (selectedRoleState (emptyAuthorizationContexts contexts role) blockCap
            encode decode suffix branch fixed
            (fixedFiberToActive (emptyAuthorizationContexts contexts role) blockCap dummy
              fixed (otherRoleTransform (emptyAuthorizationContexts contexts role) blockCap
                (ordinaryRun ordinaryProgram
                  (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))))
            (select branch)))) ≤
      (6 * (cap : ℝ)^2 *
        current406Bound (emptyAuthorizationContexts contexts role).role cap) *
        normSquared (partialRandomOracleState
          (Output := VectorOutput Counter) ∅ registers) := by
  classical
  letI := physicalBranchesFintype decode suffix
  let ctx := emptyAuthorizationContexts contexts role
  let incoming := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
  have selectedToFiber :=
    selected_role_current_advice_event_mass_le_fiber_sum
      ctx blockCap dummy encode decode suffix incoming select cap
  have fiberIdentity :=
    physical_current_advice_current406_mass_eq_fiber_sum
      ctx blockCap dummy cap encode decode suffix incoming
  have ordinaryBound := ordinary_current_advice_current406_mass_le
    contexts ordinaryProgram role blockCap dummy registers depth encode decode suffix
    readBound keys keysWithin supportWithin queriesWithin
  calc
    _ ≤ (∑ branch : Branches decode suffix, ∑ fixed : FixedTable ctx blockCap,
          normSquared (workspaceEventProjection
            (fun memory database =>
              SmzaRp05ActualEventRecertification.event
                (currentAdviceEventSpec ctx blockCap fixed cap)
                (activeMemoryEquiv ctx memory) database)
            (fixedFiberToActive ctx blockCap dummy fixed
              (otherRoleTransform ctx blockCap
                (physicalRun encode decode suffix branch incoming))))) := by
          simpa [ctx, incoming] using selectedToFiber
    _ = (∑ fixed : FixedTable ctx blockCap, ∑ branch : Branches decode suffix,
          normSquared (workspaceEventProjection
            (fun memory database =>
              SmzaRp05ActualEventRecertification.event
                (currentAdviceEventSpec ctx blockCap fixed cap)
                (activeMemoryEquiv ctx memory) database)
            (fixedFiberToActive ctx blockCap dummy fixed
              (otherRoleTransform ctx blockCap
                (physicalRun encode decode suffix branch incoming))))) := by
          rw [Finset.sum_comm]
    _ = (∑ branch : Branches decode suffix,
          normSquared (workspaceEventProjection
            (dependentFixedEvent ctx blockCap
              (currentAdviceFixedEvent ctx blockCap))
            (otherRoleTransform ctx blockCap
              (physicalRun encode decode suffix branch incoming)))) := by
          exact fiberIdentity.symm
    _ ≤ (6 * (cap : ℝ)^2 * current406Bound ctx.role cap) *
          normSquared (partialRandomOracleState
            (Output := VectorOutput Counter) ∅ registers) := by
          simpa [ctx, incoming] using ordinaryBound

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedCurrentAdviceEventMass
