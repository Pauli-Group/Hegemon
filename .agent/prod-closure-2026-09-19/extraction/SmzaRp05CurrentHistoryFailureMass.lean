import SmzaRp05CurrentHistoryFailureCoverage
import SmzaRp05CurrentHistoryCollisionMass
import SmzaRecordedTracePath
import SmzaRp05CurrentHistorySelectorContexts
import SmzaRp05CurrentAcceptedBranchMassCoverage
import SmzaRp05CurrentAcceptedSelectedFiberMass
import SmzaRp05CurrentOrdinarySoundnessFinalBound
import SmzaRp05CurrentAcceptedOrdinaryMassBound
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentSelectedChallengeClaims
import SmzaRp05PhysicalAcceptedReplayLite
import SmzaRp05AdaptivePhysicalReadBound
import SmzaRp05OrdinarySoundnessExecution
import SmzaRp05TracePrefixes
import SmzaRp05ConcreteSuffix
import SmzaRp05CurrentGroupedContext
import SmzaRp05CurrentAdaptiveExecution
import SmzaRp05CurrentAcceptedSelectorClaims
import SmzaRp05CurrentSelectedChallengeClaims
import SmzaRp05ChallengeRecordErasure
import SmzaRp05GroupedSuffix
import HegemonCrypto.SmallWoodV8Smz9CoherentMerkleInstrument
import SmzaRp05CurrentSelectedCurrentAdviceEventMass
import SmzaRp05CurrentPublicStatementTransport
import SmzaRp05CurrentRoleLabels
import SmzaRp05PartialReadout
import SmzaRp05OrdinarySoundnessStandardTotal
import SmzaRp05CurrentFilteredCollisionEventSpec
import SmzaRp05ActualEventRecertification
import SmzaRoleDomainConditioning

/-! # One global failure-mass cover for an accepted verifier history

The stage index is existential inside each of four role selectors.  The
resulting union is charged once on the original history state; it is not a
sum of per-stage failures.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryFailureMass

open scoped Classical BigOperators
open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge (workspaceEventProjection)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent databaseEventProjection)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaChallengeStageTargets (Role)
open SmzaRp05ConditionedExecution
  (FixedTable XKey xView otherRoleTransform fixedFiberToActive)
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05CurrentHistoryVerifierProgram
  (HistoryStage historyProgram)
open SmzaRp05CurrentHistorySelectorContexts (historyStageProducer)
open SmzaRp05CurrentHistoryFailureCoverage
  (currentHistoryFailureWitness currentHistoryFailureRoleSelector
    accepted_history_failure_witness_implies_global_collision_or_role_or_nonchallenge_readout)
open SmzaRp05CurrentAcceptedBranchMassCoverage
  (accepted_branch_mass_le_selector_collision_missing)
open SmzaRp05CurrentAcceptedSelectedFiberMass
  (accepted_xview_selector_mass_le_ordinary_selected_fiber_mass)
open SmzaRp05CurrentAcceptedOrdinaryMassBound (actualProgram)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode)
open SmzaRp05CurrentSelectedChallengeClaims
  (nonchallengeRawKeySet nonchallenge_raw_key_set_unrecognized)
open SmzaRp05CurrentSelectedChallengeClaims (unrecognizedActiveBranchClaims)
open SmzaRp05CurrentAcceptedSelectorClaims (unrecognized_active_claim_mem_branch_claims)
open SmzaRp05CurrentPhysicalNonchallengeClaims (branchNonchallengeClaims)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult physicalRun)
open SmzaRp05AdaptivePhysicalReadBound (physicalBranchesFintype)
open SmzaRp05OrdinarySoundnessExecution
  (OrdinaryPrefix ordinaryRun emptyAuthorizationContexts)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative)
open SmzaRecordedTracePath (RecordsCollisionFree)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification (V8PublicStatement)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass
  (selectedRoleState workspace_event_mass_after_workspace_projection_le)
open SmzaRp05PartialReadout (claimFailureProjection)
open SmzaRp05CurrentHistoryCollisionMass
  (historyErasedCollision original_history_erased_collision_mass_le_current_filtered_fibers)
open SmzaRp05OrdinarySoundnessStandardTotal (ordinary_physical_branch_fixed_other_total)
open SmzaRp05CurrentFilteredCollisionEventSpec (filteredCollisionEventSpec)
open SmzaRp05ActualEventRecertification (event)
open SmzaRoleDomainConditioning (ActiveKey RoleActive)
open SmzaRp05ConditionedExecution
  (activeContext activeMemoryEquiv fixedOtherKeys mem_fixed_other_keys)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05CurrentRoleLabels (currentRawInputDecidableEq)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 18000
set_option maxHeartbeats 1600000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

local instance : DecidableEq RawInput := currentRawInputDecidableEq

def emptyHistoryAdvice (model : RelationModel) (role : Role) :
    AllEarlierTables model role := fun _ _ _ _ => none

def historyContext (stages : List HistoryStage) (model : RelationModel)
    (bounded : ModelWithinProtocol model) (commonNs : Namespace) :
    Role → Context (Key := Key (historyProgram stages))
      (Counter := GroupCounter) (BaseWork := BaseWork) :=
  fun role => currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
    model bounded commonNs role (emptyHistoryAdvice model role) 28 28 (fun _ => ∅)

/-- The full-extraction failure event is the existential over actual accepted
terminal observers of the one already accepted history branch. -/
def historyFailureEvent
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (fallback : RawDigest)
    (typed : ∀ _i : Fin stages.length, Hegemon.Transaction.Poseidon2V8SemanticSpecification.V8PublicStatement)
    (fuel : Nat) (model : RelationModel) (bounded : ModelWithinProtocol model)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (database : Database (Key (historyProgram stages)) (VectorOutput GroupCounter)) : Prop :=
  currentHistoryFailureWitness (BaseWork := BaseWork) stages commonNs stageNsEq
    model bounded (emptyHistoryAdvice model) fallback
    typed fuel historyBranch
    (xView (nonchallengeRawKeySet
      (historyContext (BaseWork := BaseWork) stages model bounded commonNs .decsMatrix)) database)

theorem history_selector_supplies_unrecognized_claims
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest) (fuel : Nat)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (role : Role)
    (view : XKey (nonchallengeRawKeySet
      (historyContext (BaseWork := BaseWork) stages model bounded commonNs role)) →
      Option (VectorOutput GroupCounter))
    (selected : currentHistoryFailureRoleSelector (BaseWork := BaseWork)
      stages commonNs stageNsEq model bounded (emptyHistoryAdvice model)
      fallback fuel historyBranch role view)
    (blockCap : Role → Nat) :
    ∀ claim (member : claim ∈ unrecognizedActiveBranchClaims
      (historyContext (BaseWork := BaseWork) stages model bounded commonNs role) blockCap
      (encode (historyProgram stages)) groupedDecode (historyProgram stages) historyBranch),
      view ⟨claim.1.val,
        by
          apply Finset.mem_filter.mpr
          exact ⟨Finset.mem_univ _, of_decide_eq_true
            (List.mem_filter.mp member).2⟩⟩ = some claim.2 := by
  rcases selected with ⟨completion, viewMatches, historyComplete, _stageReadback⟩
  intro claim member
  have branchMember := unrecognized_active_claim_mem_branch_claims
    (historyContext (BaseWork := BaseWork) stages model bounded commonNs role) blockCap
    (encode (historyProgram stages)) groupedDecode (historyProgram stages)
    historyBranch claim member
  have keyMember : claim.1.val ∈ nonchallengeRawKeySet
      (historyContext (BaseWork := BaseWork) stages model bounded commonNs role) := by
    apply Finset.mem_filter.mpr
    exact ⟨Finset.mem_univ _, of_decide_eq_true
      (List.mem_filter.mp member).2⟩
  exact (viewMatches claim.1.val keyMember).symm.trans
    (historyComplete (claim.1.val, claim.2) branchMember)

private theorem database_event_mass_after_workspace_projection_le
    {Input Output Phase Workspace : Type}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (event : Database Input Output → Prop)
    (selector : Workspace → Database Input Output → Prop)
    (state : State Input Output Phase Workspace) :
    normSquared (databaseEventProjection event (workspaceEventProjection selector state)) ≤
      normSquared (databaseEventProjection event state) := by
  classical
  unfold normSquared databaseEventProjection workspaceEventProjection
  apply Finset.sum_le_sum
  intro basis _
  by_cases eventAt : event basis.database
  · by_cases selected : selector basis.workspace basis.database
    · simp [eventAt, selected]
    · simp [eventAt, selected]
      exact Complex.normSq_nonneg _
  · simp [eventAt]

private theorem normSquared_nonnegative
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (state : State Input Output Phase Workspace) :
    0 ≤ normSquared state := by
  unfold normSquared
  exact Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _)

/-- The complete-history full-extraction failure projection is covered once
by the global erased-record collision, four existential-index role selectors,
and the one missing nonchallenge history readout.  Branch and Born weights
are those of the original history execution. -/
theorem history_failure_projection_mass_le_global_roles_collision_missing
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (typed : ∀ _i : Fin stages.length, V8PublicStatement)
    (parsed : ∀ i : Fin stages.length,
      parseCurrentPublicStatement? (stages[i.val]).statement = some (typed i))
    (fallback : RawDigest) (fuel : Nat) (enough : 25 ≤ fuel)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix (Key := Key (historyProgram stages))
      (Counter := GroupCounter) (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key (historyProgram stages))
      (Phase := VectorOutput GroupCounter)
      (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ)
    (blockCap : Role → Nat)
    (_dummy : ∀ role : Role,
      ActiveKey (emptyAuthorizationContexts (BaseWork := BaseWork)
        (historyContext (BaseWork := BaseWork) stages model bounded commonNs) role).role blockCap
        (emptyAuthorizationContexts (BaseWork := BaseWork)
          (historyContext (BaseWork := BaseWork) stages model bounded commonNs) role).keyBytes) :
    let program := historyProgram stages
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    letI := physicalBranchesFintype groupedDecode program
    (∑ branch : Branches groupedDecode program,
      if branchResult groupedDecode program branch = some () then
        normSquared (workspaceEventProjection
          (fun (_work : Work (Counter := GroupCounter) (BaseWork := BaseWork)) database =>
            historyFailureEvent (BaseWork := BaseWork)
            stages commonNs stageNsEq
            fallback typed fuel model bounded branch database)
          (physicalRun (encode program) groupedDecode program branch initial))
      else 0) ≤
      (∑ role : Role, ∑ branch : Branches groupedDecode program,
        normSquared (workspaceEventProjection
          (fun (_work : Work (Counter := GroupCounter) (BaseWork := BaseWork)) database =>
            currentHistoryFailureRoleSelector
            (BaseWork := BaseWork) stages commonNs stageNsEq model bounded
            (emptyHistoryAdvice model) fallback fuel branch role
            (xView (nonchallengeRawKeySet
      (historyContext (BaseWork := BaseWork) stages model bounded commonNs role)) database))
          (physicalRun (encode program) groupedDecode program branch initial))) +
    (∑ branch : Branches groupedDecode program,
        normSquared (workspaceEventProjection
          (historyErasedCollision
              (emptyAuthorizationContexts (BaseWork := BaseWork)
              (historyContext (BaseWork := BaseWork) stages model bounded commonNs) .decsMatrix))
          (physicalRun (encode program) groupedDecode program branch initial))) +
      (∑ branch : Branches groupedDecode program,
        normSquared (databaseEventProjection
          (fun database => ¬ ClaimsDatabaseEvent
            (branchNonchallengeClaims
              (emptyAuthorizationContexts (BaseWork := BaseWork)
                (historyContext (BaseWork := BaseWork) stages model bounded commonNs) .decsMatrix).keyBytes
              (encode program) groupedDecode program branch) database)
          (physicalRun (encode program) groupedDecode program branch initial))) := by
  classical
  let program := historyProgram stages
  let contexts := historyContext (BaseWork := BaseWork) stages model bounded commonNs
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
  let ctx := emptyAuthorizationContexts (BaseWork := BaseWork) contexts .decsMatrix
  letI := physicalBranchesFintype groupedDecode program
  dsimp only
  let missingClaims (branch : Branches groupedDecode program) :=
    branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch
  let selector (role : Role) (branch : Branches groupedDecode program) :
      Work (Counter := GroupCounter) (BaseWork := BaseWork) →
        Database (Key program) (VectorOutput GroupCounter) → Prop :=
    fun _work database => currentHistoryFailureRoleSelector (BaseWork := BaseWork)
      stages commonNs stageNsEq model bounded (emptyHistoryAdvice model)
      fallback fuel branch role
      (xView (nonchallengeRawKeySet (contexts role)) database)
  let collision := historyErasedCollision ctx
  let branchCharge (branch : Branches groupedDecode program) :=
    (∑ role : Role, normSquared (workspaceEventProjection
      (selector role branch)
      (physicalRun (encode program) groupedDecode program branch initial))) +
    normSquared (workspaceEventProjection collision
      (physicalRun (encode program) groupedDecode program branch initial)) +
    normSquared (databaseEventProjection
      (fun database => ¬ ClaimsDatabaseEvent (missingClaims branch) database)
      (physicalRun (encode program) groupedDecode program branch initial))
  refine le_trans (b := ∑ branch : Branches groupedDecode program, branchCharge branch) ?_ ?_
  · apply Finset.sum_le_sum
    intro branch _
    let original := physicalRun (encode program) groupedDecode program branch initial
    let failurePredicate : Work (Counter := GroupCounter) (BaseWork := BaseWork) →
        Database (Key program) (VectorOutput GroupCounter) → Prop :=
      fun _ database => historyFailureEvent (BaseWork := BaseWork)
        stages commonNs stageNsEq fallback typed
        fuel model bounded branch database
    let failureState := workspaceEventProjection failurePredicate original
    have covered : ∀ basis : Basis (Key program) (VectorOutput GroupCounter)
        (VectorOutput GroupCounter) (Work (Counter := GroupCounter) (BaseWork := BaseWork)),
        failureState basis ≠ 0 → branchResult groupedDecode program branch = some () →
        ClaimsDatabaseEvent (missingClaims branch) basis.database →
        collision basis.workspace basis.database ∨
          ∃ role, selector role branch basis.workspace basis.database := by
      intro basis support accepted claimsComplete
      have originalSupport : original basis ≠ 0 := by
        intro zero
        dsimp only [failureState, failurePredicate, workspaceEventProjection] at support
        rw [zero] at support
        simp at support
      have originalMassNe : normSquared original ≠ 0 := by
        intro zeroMass
        have oneTerm : Complex.normSq (original basis) ≤ normSquared original :=
          Finset.single_le_sum (fun _ _ => Complex.normSq_nonneg _)
            (Finset.mem_univ basis)
        have normZero : Complex.normSq (original basis) = 0 := by
          rw [zeroMass] at oneTerm
          exact le_antisymm oneTerm (Complex.normSq_nonneg _)
        exact originalSupport (Complex.normSq_eq_zero.mp normZero)
      have failure : historyFailureEvent (BaseWork := BaseWork)
          stages commonNs stageNsEq fallback typed
          fuel model bounded branch basis.database := by
        dsimp only [failureState, failurePredicate, workspaceEventProjection] at support
        by_contra absent
        simp [absent] at support
      have historyCover := accepted_history_failure_witness_implies_global_collision_or_role_or_nonchallenge_readout
        (BaseWork := BaseWork) stages commonNs stageNsEq typed parsed fuel enough
        model bounded (emptyHistoryAdvice model) fallback branch initial
        originalMassNe basis.database failure
      rcases historyCover with collisionAt | ⟨role, roleSelected⟩ | missingAt
      · exact Or.inl collisionAt
      · exact Or.inr ⟨role, roleSelected⟩
      · exact False.elim (missingAt claimsComplete)
    have perBranchRaw := accepted_branch_mass_le_selector_collision_missing
      (Index := Role) (branchResult groupedDecode program branch = some ())
      failureState (missingClaims branch) collision (selector · branch) covered
    have perBranch :
        (if branchResult groupedDecode program branch = some () then
          normSquared failureState else 0) ≤
        normSquared (workspaceEventProjection collision failureState) +
          (∑ role : Role, normSquared (workspaceEventProjection
            (selector role branch) failureState)) +
          normSquared (databaseEventProjection
            (fun database => ¬ ClaimsDatabaseEvent (missingClaims branch) database)
            failureState) := by
      by_cases accepted : branchResult groupedDecode program branch = some ()
      · simpa only [if_pos accepted, collision, selector, missingClaims] using perBranchRaw
      · simpa only [if_neg accepted, collision, selector, missingClaims] using perBranchRaw
    have collisionBound := workspace_event_mass_after_workspace_projection_le
      collision failurePredicate original
    have missingBound := database_event_mass_after_workspace_projection_le
      (fun database => ¬ ClaimsDatabaseEvent (missingClaims branch) database)
      failurePredicate original
    have selectorBound :
        (∑ role : Role, normSquared (workspaceEventProjection
          (selector role branch) failureState)) ≤
        ∑ role : Role, normSquared (workspaceEventProjection
          (selector role branch) original) := by
      apply Finset.sum_le_sum
      intro role _
      exact workspace_event_mass_after_workspace_projection_le
        (selector role branch) failurePredicate original
    dsimp only [collision, selector, missingClaims] at perBranch ⊢
    calc
      (if branchResult groupedDecode program branch = some () then
        normSquared failureState else 0) ≤
        normSquared (workspaceEventProjection collision failureState) +
          (∑ role : Role, normSquared (workspaceEventProjection
            (selector role branch) failureState)) +
          normSquared (databaseEventProjection
            (fun database => ¬ ClaimsDatabaseEvent (missingClaims branch) database)
            failureState) := perBranch
      _ ≤
        branchCharge branch := by
        calc
          normSquared (workspaceEventProjection collision failureState) +
              (∑ role : Role, normSquared (workspaceEventProjection
                (selector role branch) failureState)) +
              normSquared (databaseEventProjection
                (fun database => ¬ ClaimsDatabaseEvent (missingClaims branch) database)
                failureState) ≤
            normSquared (workspaceEventProjection collision original) +
              (∑ role : Role, normSquared (workspaceEventProjection
                (selector role branch) original)) +
              normSquared (databaseEventProjection
                (fun database => ¬ ClaimsDatabaseEvent (missingClaims branch) database)
                original) := by
              exact add_le_add (add_le_add collisionBound selectorBound) missingBound
          _ = branchCharge branch := by
            simp only [branchCharge]
            ac_rfl
  · simp only [branchCharge, Finset.sum_add_distrib]
    rw [Finset.sum_comm]

/-! The raw union cover now enters the exact fixed-fiber inputs consumed by
the ordinary scalar theorem.  A single existential stage selector is kept
inside each selected role mass; it is never expanded into a transaction sum. -/

theorem history_failure_projection_mass_le_scalar_lhs
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (typed : ∀ _i : Fin stages.length, V8PublicStatement)
    (parsed : ∀ i : Fin stages.length,
      parseCurrentPublicStatement? (stages[i.val]).statement = some (typed i))
    (fallback : RawDigest) (fuel : Nat) (enough : 25 ≤ fuel)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix (Key := Key (historyProgram stages))
      (Counter := GroupCounter) (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key (historyProgram stages))
      (Phase := VectorOutput GroupCounter)
      (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ)
    (blockCap : Role → Nat) (collisionCap : Nat)
    (dummy : ∀ role : Role,
      ActiveKey (emptyAuthorizationContexts (BaseWork := BaseWork)
        (historyContext (BaseWork := BaseWork) stages model bounded commonNs) role).role blockCap
        (emptyAuthorizationContexts (BaseWork := BaseWork)
          (historyContext (BaseWork := BaseWork) stages model bounded commonNs) role).keyBytes) :
    let program := historyProgram stages
    let contexts := historyContext (BaseWork := BaseWork) stages model bounded commonNs
    let roleCtx := fun role => emptyAuthorizationContexts (BaseWork := BaseWork) contexts role
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    letI := physicalBranchesFintype groupedDecode program
    (∑ branch : Branches groupedDecode program,
      if branchResult groupedDecode program branch = some () then
        normSquared (workspaceEventProjection
          (fun (_work : Work (Counter := GroupCounter) (BaseWork := BaseWork)) database =>
            historyFailureEvent (BaseWork := BaseWork)
            stages commonNs stageNsEq
            fallback typed fuel model bounded branch database)
          (physicalRun (encode program) groupedDecode program branch initial)
        ) else 0) ≤
    (∑ role : Role, ∑ branch : Branches groupedDecode program,
      ∑ fixed : FixedTable (roleCtx role) blockCap,
        normSquared (selectedRoleState (roleCtx role) blockCap (encode program)
          groupedDecode program branch fixed
          (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
            (otherRoleTransform (roleCtx role) blockCap initial))
          (fun view (_work : Work (Counter := GroupCounter) (BaseWork := BaseWork)) =>
            currentHistoryFailureRoleSelector (BaseWork := BaseWork)
            stages commonNs stageNsEq model bounded (emptyHistoryAdvice model)
            fallback fuel branch role view))) +
    (∑ role : Role, ∑ branch : Branches groupedDecode program,
      ∑ fixed : FixedTable (roleCtx role) blockCap,
        normSquared (workspaceEventProjection
          (fun memory database => event
            (filteredCollisionEventSpec (activeContext (roleCtx role) blockCap fixed)
              collisionCap)
            (activeMemoryEquiv (roleCtx role) memory) database)
          (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
            (otherRoleTransform (roleCtx role) blockCap
              (physicalRun (encode program) groupedDecode program branch initial))))) +
    (∑ role : Role, ∑ branch : Branches groupedDecode program,
      normSquared (claimFailureProjection
        (branchNonchallengeClaims (roleCtx role).keyBytes (encode program)
          groupedDecode program branch)
        (physicalRun (encode program) groupedDecode program branch initial))) := by
  classical
  let program := historyProgram stages
  let contexts := historyContext (BaseWork := BaseWork) stages model bounded commonNs
  let roleCtx (role : Role) := emptyAuthorizationContexts (BaseWork := BaseWork) contexts role
  let ctx := roleCtx .decsMatrix
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
  letI := physicalBranchesFintype groupedDecode program
  dsimp only
  let xSelector (role : Role) (branch : Branches groupedDecode program) :
      (XKey (nonchallengeRawKeySet (roleCtx role)) →
        Option (VectorOutput GroupCounter)) →
      Work (Counter := GroupCounter) (BaseWork := BaseWork) → Prop :=
    fun view _work => currentHistoryFailureRoleSelector (BaseWork := BaseWork)
      stages commonNs stageNsEq model bounded (emptyHistoryAdvice model)
      fallback fuel branch role view
  let selector (role : Role) (branch : Branches groupedDecode program) :=
    fun work database => xSelector role branch
      (xView (nonchallengeRawKeySet (roleCtx role)) database) work
  let selectedFiberMass := ∑ role : Role, ∑ branch : Branches groupedDecode program,
    ∑ fixed : FixedTable (roleCtx role) blockCap,
      normSquared (selectedRoleState (roleCtx role) blockCap (encode program)
        groupedDecode program branch fixed
        (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
          (otherRoleTransform (roleCtx role) blockCap initial)) (xSelector role branch))
  let collisionFiberMass := ∑ role : Role, ∑ branch : Branches groupedDecode program,
    ∑ fixed : FixedTable (roleCtx role) blockCap,
      normSquared (workspaceEventProjection
        (fun memory database => event
          (filteredCollisionEventSpec (activeContext (roleCtx role) blockCap fixed)
            collisionCap)
          (activeMemoryEquiv (roleCtx role) memory) database)
        (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
          (otherRoleTransform (roleCtx role) blockCap
            (physicalRun (encode program) groupedDecode program branch initial))))
  let missingFiberMass := ∑ role : Role, ∑ branch : Branches groupedDecode program,
    normSquared (claimFailureProjection
      (branchNonchallengeClaims (roleCtx role).keyBytes (encode program)
        groupedDecode program branch)
      (physicalRun (encode program) groupedDecode program branch initial))
  let rawSelectorMass := ∑ role : Role, ∑ branch : Branches groupedDecode program,
    normSquared (workspaceEventProjection (selector role branch)
      (physicalRun (encode program) groupedDecode program branch initial))
  let rawCollisionMass := ∑ branch : Branches groupedDecode program,
    normSquared (workspaceEventProjection (historyErasedCollision ctx)
      (physicalRun (encode program) groupedDecode program branch initial))
  let rawMissingMass := ∑ branch : Branches groupedDecode program,
    normSquared (databaseEventProjection
      (fun database => ¬ ClaimsDatabaseEvent
        (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch)
        database)
      (physicalRun (encode program) groupedDecode program branch initial))
  have rawBound := history_failure_projection_mass_le_global_roles_collision_missing
    stages commonNs stageNsEq typed parsed fallback fuel enough model bounded
    ordinaryProgram registers blockCap dummy
  have rawSelectorBound : rawSelectorMass ≤ selectedFiberMass := by
    dsimp only [rawSelectorMass, selectedFiberMass, selector, xSelector]
    apply Finset.sum_le_sum
    intro role _
    have roleBound := accepted_xview_selector_mass_le_ordinary_selected_fiber_mass
      (roleCtx role) ordinaryProgram registers (encode program) groupedDecode program
      blockCap (dummy role)
      (xSelector role)
      (by
        intro branch view work selected claim member
        exact history_selector_supplies_unrecognized_claims stages commonNs stageNsEq
          model bounded fallback fuel branch role view selected blockCap claim member)
      (by
        intro key member nonchallenge
        have parsedNone := nonchallenge_raw_key_set_unrecognized (roleCtx role) key nonchallenge
        have fixedOther := (mem_fixed_other_keys (roleCtx role) blockCap key).mp member
        exact fixedOther (by simp [RoleActive, parsedNone]))
    simpa only [roleCtx, contexts, historyContext, currentGroupedContext,
      emptyHistoryAdvice, selector] using roleBound
  have rawCollisionBound : rawCollisionMass ≤ collisionFiberMass := by
    dsimp only [rawCollisionMass, collisionFiberMass]
    rw [Finset.sum_comm]
    apply Finset.sum_le_sum
    intro branch _
    have one := original_history_erased_collision_mass_le_current_filtered_fibers
      ctx blockCap (dummy .decsMatrix) collisionCap (by intro base; rfl)
      (physicalRun (encode program) groupedDecode program branch initial)
      (ordinary_physical_branch_fixed_other_total ordinaryProgram registers
        (encode program) groupedDecode program branch ctx blockCap)
    have oneRole :
        (∑ fixed : FixedTable (roleCtx .decsMatrix) blockCap,
          normSquared (workspaceEventProjection
      (fun memory database => event
              (filteredCollisionEventSpec
                (activeContext (roleCtx .decsMatrix) blockCap fixed) collisionCap)
              (activeMemoryEquiv (roleCtx .decsMatrix) memory) database)
            (fixedFiberToActive (roleCtx .decsMatrix) blockCap
              (dummy .decsMatrix) fixed
              (otherRoleTransform (roleCtx .decsMatrix) blockCap
                (physicalRun (encode program) groupedDecode program branch initial))))) ≤
        ∑ role : Role, ∑ fixed : FixedTable (roleCtx role) blockCap,
          normSquared (workspaceEventProjection
            (fun memory database => event
              (filteredCollisionEventSpec (activeContext (roleCtx role) blockCap fixed)
                collisionCap)
              (activeMemoryEquiv (roleCtx role) memory) database)
            (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
              (otherRoleTransform (roleCtx role) blockCap
                (physicalRun (encode program) groupedDecode program branch initial)))) := by
      exact Finset.single_le_sum
        (s := (Finset.univ : Finset Role))
        (f := fun role : Role =>
          ∑ fixed : FixedTable (roleCtx role) blockCap,
            normSquared (workspaceEventProjection
              (fun memory database => event
                (filteredCollisionEventSpec
                  (activeContext (roleCtx role) blockCap fixed) collisionCap)
                (activeMemoryEquiv (roleCtx role) memory) database)
              (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
                (otherRoleTransform (roleCtx role) blockCap
                  (physicalRun (encode program) groupedDecode program branch initial)))))
        (fun role _ => Finset.sum_nonneg (fun fixed _ => normSquared_nonnegative _))
        (Finset.mem_univ Role.decsMatrix)
    calc
      normSquared (workspaceEventProjection (historyErasedCollision ctx)
        (physicalRun (encode program) groupedDecode program branch initial)) ≤ _ := by
          simpa only [ctx, roleCtx, contexts, historyContext, emptyHistoryAdvice,
            currentGroupedContext] using one
      _ ≤ _ := by
        simpa only [roleCtx, contexts, historyContext, emptyHistoryAdvice,
          currentGroupedContext] using oneRole
  have rawMissingBound : rawMissingMass ≤ missingFiberMass := by
    dsimp only [rawMissingMass, missingFiberMass]
    calc
      (∑ branch : Branches groupedDecode program,
        normSquared (databaseEventProjection
          (fun database => ¬ ClaimsDatabaseEvent
            (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch)
            database)
          (physicalRun (encode program) groupedDecode program branch initial))) ≤
      (∑ branch : Branches groupedDecode program, ∑ role : Role,
        normSquared (claimFailureProjection
          (branchNonchallengeClaims (roleCtx role).keyBytes (encode program)
            groupedDecode program branch)
          (physicalRun (encode program) groupedDecode program branch initial))) := by
        apply Finset.sum_le_sum
        intro branch _
        dsimp only [claimFailureProjection]
        have claimsEq : ∀ role : Role,
            branchNonchallengeClaims (roleCtx role).keyBytes (encode program)
              groupedDecode program branch =
            branchNonchallengeClaims ctx.keyBytes (encode program)
              groupedDecode program branch := by
          intro role
          rfl
        rw [claimsEq]
        exact Finset.single_le_sum (fun _ _ => normSquared_nonnegative _)
          (Finset.mem_univ Role.decsMatrix)
      _ = missingFiberMass := by
        rw [Finset.sum_comm]
  dsimp only [rawSelectorMass, rawCollisionMass, rawMissingMass,
    selectedFiberMass, collisionFiberMass, missingFiberMass] at rawBound ⊢
  calc
    _ ≤ rawSelectorMass + rawCollisionMass + rawMissingMass := rawBound
    _ ≤ selectedFiberMass + collisionFiberMass + missingFiberMass := by
      exact add_le_add (add_le_add rawSelectorBound rawCollisionBound) rawMissingBound

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryFailureMass
