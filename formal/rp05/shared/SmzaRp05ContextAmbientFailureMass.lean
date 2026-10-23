import SmzaRp05CurrentHistoryCollisionMass
import SmzaRp05ContextAmbientSampleEvent
import SmzaRp05CurrentAcceptedMassToScalar
import SmzaRp05CurrentAcceptedBranchMassCoverage
import SmzaRp05CurrentAcceptedSelectedFiberMass
import SmzaRp05CurrentAcceptedSelectorClaims
import SmzaRp05CurrentPhysicalBranchClaimsConsistent
import SmzaRp05CurrentClaimsXViewCompletion
import SmzaRp05CurrentFullOrRoleXViewCoverage
import SmzaRp05CurrentFullOrRoleExtraction
import SmzaRp05CurrentOrdinarySoundnessFinalBound

/-! # Guard-free full-extraction failure mass on ordinary fibers

The branch amplitudes below are projected onto failure of the designated
full-extraction selector on their own nonchallenge X-view.  This isolates the
actual full-or-role failure event without a global no-packed-witness premise.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ContextAmbientFailureMass

open scoped Classical BigOperators
open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge (workspaceEventProjection)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent databaseEventProjection)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05ConditionedExecution
  (FixedTable XKey xView activeContext activeMemoryEquiv fixedFiberToActive
    otherRoleTransform fixedOtherKeys mem_fixed_other_keys)
open SmzaRoleDomainConditioning (ActiveKey RoleActive)
open SmzaRp05CurrentAcceptedMassToScalar
  (currentAcceptedMassContexts)
open SmzaRp05CurrentAcceptedOrdinaryMassBound
  (actualProgram collision ordinary_original_collision_mass_le_fiber_sum)
open SmzaRp05CurrentAcceptedBranchMassCoverage
  (accepted_branch_mass_le_selector_collision_missing)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05CurrentAcceptedSelectedFiberMass
  (accepted_xview_selector_mass_le_ordinary_selected_fiber_mass)
open SmzaRp05PartialReadout (claimFailureProjection)
open SmzaRp05CurrentAcceptedSelectorClaims
  (unrecognized_active_claim_mem_branch_claims)
open SmzaRp05CurrentSelectedChallengeClaims
  (nonchallengeRawKeySet nonchallenge_raw_key_set_unrecognized
    unrecognizedActiveBranchClaims)
open SmzaRp05CurrentPhysicalNonchallengeClaims (branchNonchallengeClaims)
open SmzaRp05CurrentPhysicalBranchClaimsConsistent
  (nonzero_physical_branch_claims_consistent)
open SmzaRp05CurrentClaimsXViewCompletion (claims_completion_preserving_view)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp05CurrentFullOrRoleExtraction
  (currentAcceptedXViewFailureRoleSelector)
open SmzaRp05CurrentFullOrRoleXViewCoverage
  (currentAcceptedXViewFullSuccessSelector
    accepted_nonchallenge_consistent_branch_has_full_or_failure_selector_or_collision)
open SmzaRp05CurrentNonchallengeRecordView
  (grouped_one_statement_view_eq_of_nonchallenge_key_agreement)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys branchAnswers branchClaims branchResult physicalRun)
open SmzaRp05AdaptivePhysicalReadBound (physicalBranchesFintype)
open SmzaRp05OrdinarySoundnessExecution
  (OrdinaryPrefix ordinaryRun emptyAuthorizationContexts)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative groupZero)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05ActualEventRecertification (event)
open SmzaRp05CurrentFilteredCollisionEventSpec (filteredCollisionEventSpec)
open V8SmzaOracleParser (RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
  (V8PublicStatement encodePublicStatement)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 18000
set_option maxHeartbeats 1600000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]


open SmzaRp05ContextAmbientDecoder (ParsedContext fixedNamespaceContextProgram)
open SmzaRp05ContextAmbientCoverage
  (ambientXViewFullSuccessSelector ambientXViewFailureRoleSelector
   accepted_context_has_ambient_full_or_failure_selector_or_collision)

/-- One global erased-record collision, with no sum over produced contexts. -/
def globalErasedCollision
    (producer : Program ParsedContext) (ns : Namespace) :
    Work (Counter := GroupCounter) (BaseWork := BaseWork) →
      Database (Key (fixedNamespaceContextProgram ns producer))
        (VectorOutput GroupCounter) → Prop :=
  fun _ database => ¬ SmzaRecordedTracePath.RecordsCollisionFree
    (SmzaRp05ChallengeRecordErasure.eraseChallengeRecords
      (V8Smz9CoherentMerkleInstrument.rawRecords
        (fun key => groupRepresentative (included (fixedNamespaceContextProgram ns producer) key))
        (V8Smz9CoherentVectorMerkle.vectorOutputBytes groupZero) database))

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

private theorem failure_selector_supplies_unrecognized_claims
    (producer : Program ParsedContext)
    (ns : Namespace) (fallback : RawDigest)
    (fuel : Nat)
    (ctx : Context (Key := Key (fixedNamespaceContextProgram ns producer))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (role : Role)
    (branch : Branches groupedDecode (fixedNamespaceContextProgram ns producer))
    (view : XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput GroupCounter))
    (selected : ambientXViewFailureRoleSelector producer ns
      fallback fuel ctx role branch view) :
    ∀ claim (member : claim ∈ unrecognizedActiveBranchClaims ctx blockCap
      (encode (fixedNamespaceContextProgram ns producer)) groupedDecode
      (fixedNamespaceContextProgram ns producer) branch),
      view ⟨claim.1.val,
        by
          apply Finset.mem_filter.mpr
          exact ⟨Finset.mem_univ _, of_decide_eq_true
            (List.mem_filter.mp member).2⟩⟩ = some claim.2 := by
  dsimp only [ambientXViewFailureRoleSelector] at selected
  rcases selected with ⟨database, viewMatches, recordedClaims, _evidence⟩
  intro claim member
  have branchMember := unrecognized_active_claim_mem_branch_claims
    ctx blockCap (encode (fixedNamespaceContextProgram ns producer))
    groupedDecode (fixedNamespaceContextProgram ns producer) branch claim member
  have claimValue := recordedClaims (claim.1.val, claim.2) branchMember
  have keyMember : claim.1.val ∈ nonchallengeRawKeySet ctx := by
    apply Finset.mem_filter.mpr
    exact ⟨Finset.mem_univ _, of_decide_eq_true
      (List.mem_filter.mp member).2⟩
  exact (viewMatches claim.1.val keyMember).symm.trans claimValue

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

/-- The accepted mass restricted to failure of the full designated
extraction is covered by the original collision, the four concrete
guard-free role selectors, and missing nonchallenge branch claims.  The
full-success selector is evaluated on precisely the X-view of each original
physical branch. -/
theorem accepted_failure_projection_mass_le_collision_failure_missing
    (producer : Program ParsedContext)
    (ns : Namespace) (fallback : RawDigest)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : AllEarlierTables model .decsMatrix)
    (outerFuel innerFuel : Nat)
    (initial : State
      (Key (fixedNamespaceContextProgram ns producer))
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (Work (Counter := GroupCounter) (BaseWork := BaseWork))) :
    let program := fixedNamespaceContextProgram ns producer
    let ctx := currentGroupedContext (BaseWork := BaseWork) program model bounded
      ns .decsMatrix advice outerFuel innerFuel (fun _ => ∅)
    letI := physicalBranchesFintype groupedDecode program
    (∑ branch : Branches groupedDecode program,
      if branchResult groupedDecode program branch = some () then
        normSquared (workspaceEventProjection
          (fun _work database => ¬ ambientXViewFullSuccessSelector
            producer ns fallback fuel ctx branch
            (xView (nonchallengeRawKeySet ctx) database))
          (physicalRun (encode program) groupedDecode program branch initial))
      else 0) ≤
    (∑ branch : Branches groupedDecode program,
      (normSquared (workspaceEventProjection
        (globalErasedCollision producer ns)
        (physicalRun (encode program) groupedDecode program branch initial)) +
      (∑ role : Role,
        normSquared (workspaceEventProjection
          (fun _work database => ambientXViewFailureRoleSelector
            producer ns fallback fuel ctx role branch
            (xView (nonchallengeRawKeySet ctx) database))
          (physicalRun (encode program) groupedDecode program branch initial))) +
      normSquared (databaseEventProjection
        (fun database => ¬ ClaimsDatabaseEvent
          (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode
            program branch) database)
        (physicalRun (encode program) groupedDecode program branch initial)))) := by
  classical
  let program := fixedNamespaceContextProgram ns producer
  let ctx : Context (Key := Key (fixedNamespaceContextProgram ns producer))
      (Counter := GroupCounter) (BaseWork := BaseWork) :=
    currentGroupedContext (BaseWork := BaseWork)
      (fixedNamespaceContextProgram ns producer)
      model bounded ns .decsMatrix advice outerFuel innerFuel (fun _ => ∅)
  letI := physicalBranchesFintype groupedDecode program
  dsimp only
  apply Finset.sum_le_sum
  intro branch _
  let original := physicalRun (encode program) groupedDecode program branch initial
  let fullFailure : Work (Counter := GroupCounter) (BaseWork := BaseWork) →
      Database (Key program) (VectorOutput GroupCounter) → Prop :=
    fun _ database => ¬ ambientXViewFullSuccessSelector producer ns fallback fuel ctx branch
      (xView (nonchallengeRawKeySet ctx) database)
  let failureState := workspaceEventProjection fullFailure original
  have covered : ∀ basis : Basis (Key program) (VectorOutput GroupCounter)
      (VectorOutput GroupCounter) (Work (Counter := GroupCounter) (BaseWork := BaseWork)),
      failureState basis ≠ 0 → branchResult groupedDecode program branch = some () →
      ClaimsDatabaseEvent (branchNonchallengeClaims ctx.keyBytes (encode program)
        groupedDecode program branch) basis.database →
      globalErasedCollision producer ns basis.workspace basis.database ∨
        ∃ role, ambientXViewFailureRoleSelector producer ns fallback fuel ctx role branch
          (xView (nonchallengeRawKeySet ctx) basis.database) := by
    intro basis support accepted nonchallengeClaims
    dsimp only [program] at *
    have originalSupport : original basis ≠ 0 := by
      intro zero
      dsimp only [failureState, fullFailure, workspaceEventProjection] at support
      rw [zero] at support
      simp at support
    have notFull : fullFailure basis.workspace basis.database := by
      dsimp only [failureState, fullFailure, workspaceEventProjection] at support
      by_contra notFailed
      simp [notFailed] at support
    have originalMassNe : normSquared original ≠ 0 := by
      intro zeroMass
      have oneTerm : Complex.normSq (original basis) ≤ normSquared original :=
        Finset.single_le_sum (fun _ _ => Complex.normSq_nonneg _)
          (Finset.mem_univ basis)
      have normZero : Complex.normSq (original basis) = 0 := by
        rw [zeroMass] at oneTerm
        exact le_antisymm oneTerm (Complex.normSq_nonneg _)
      exact originalSupport (Complex.normSq_eq_zero.mp normZero)
    let claims := branchClaims (branchKeys (encode program) groupedDecode program branch)
      (branchAnswers (encode program) groupedDecode program branch)
    have consistent : ∃ completion : Database (Key program) (VectorOutput GroupCounter),
        ClaimsDatabaseEvent claims completion := by
      simpa only [claims] using nonzero_physical_branch_claims_consistent
        (encode program) groupedDecode program branch initial originalMassNe
    have viewClaims : ∀ claim ∈ claims, ∀ member : claim.1 ∈ nonchallengeRawKeySet ctx,
        (xView (nonchallengeRawKeySet ctx) basis.database) ⟨claim.1, member⟩ =
          some claim.2 := by
      intro claim claimMember member
      have nonchallenge : claim ∈ branchNonchallengeClaims ctx.keyBytes
          (encode program) groupedDecode program branch := by
        unfold branchNonchallengeClaims
        apply List.mem_filter.mpr
        refine ⟨claimMember, ?_⟩
        have parsedNone := nonchallenge_raw_key_set_unrecognized ctx claim.1 member
        simp [parsedNone]
      calc
        (xView (nonchallengeRawKeySet ctx) basis.database) ⟨claim.1, member⟩ =
            basis.database claim.1 := rfl
        _ = some claim.2 := nonchallengeClaims claim nonchallenge
    obtain ⟨completion, completionClaims, completionView⟩ :=
      claims_completion_preserving_view claims (nonchallengeRawKeySet ctx)
        (xView (nonchallengeRawKeySet ctx) basis.database) consistent viewClaims
    have sameView : xView (nonchallengeRawKeySet ctx) completion =
        xView (nonchallengeRawKeySet ctx) basis.database := by
      funext key
      exact completionView key.val key.property
    have result := accepted_context_has_ambient_full_or_failure_selector_or_collision
      producer ns branch accepted completion completionClaims
      fallback fuel enough ctx
    -- The completion retains the branch's full claims; the view identity
    -- transfers both the full and failure selector back to this basis.
    rcases result with collisionAt | fullAt | ⟨role, failed⟩
    · have agreesOnX : ∀ key,
          parseStageQuery (groupRepresentative (included program key)) = none →
          completion key = basis.database key := by
        intro key parsedNone
        have member : key ∈ nonchallengeRawKeySet ctx := by
          apply Finset.mem_filter.mpr
          refine ⟨Finset.mem_univ _, ?_⟩
          simpa only [show ctx.keyBytes key = groupRepresentative
            (included program key) from rfl] using parsedNone
        calc
          completion key = (xView (nonchallengeRawKeySet ctx) completion) ⟨key, member⟩ := rfl
          _ = (xView (nonchallengeRawKeySet ctx) basis.database) ⟨key, member⟩ := by
            rw [sameView]
          _ = basis.database key := rfl
      rcases collisionAt with ⟨c, _producerAtCompletion, filteredCollision⟩
      have globalCollision : ¬ SmzaRecordedTracePath.RecordsCollisionFree
          (SmzaRp05ChallengeRecordErasure.eraseChallengeRecords
            (V8Smz9CoherentMerkleInstrument.rawRecords
              (fun key => groupRepresentative (included program key))
              (V8Smz9CoherentVectorMerkle.vectorOutputBytes groupZero) completion)) := by
        intro collisionFree
        apply filteredCollision
        intro left right digest leftMember rightMember
        exact collisionFree left right digest
          (Finset.mem_filter.mp leftMember).1 (Finset.mem_filter.mp rightMember).1
      have recordsEq :=
        SmzaRp05CurrentNonchallengeRecordView.grouped_erased_raw_records_eq_of_nonchallenge_key_agreement
          program completion basis.database agreesOnX
      have collisionOriginal : globalErasedCollision producer ns
          basis.workspace basis.database := by
        dsimp only [globalErasedCollision]
        rw [← recordsEq]
        exact globalCollision
      exact Or.inl collisionOriginal
    · rw [sameView] at fullAt
      exact False.elim (notFull fullAt)
    · rw [sameView] at failed
      exact Or.inr ⟨role, failed⟩
  have split := accepted_branch_mass_le_selector_collision_missing
    (Index := Role) (branchResult groupedDecode program branch = some ())
    failureState
    (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch)
    (globalErasedCollision producer ns)
    (fun role _work database => ambientXViewFailureRoleSelector
      producer ns fallback fuel ctx role branch
      (xView (nonchallengeRawKeySet ctx) database))
    covered
  have collisionBound :=
    SmzaRp05CurrentSelectedCurrentAdviceEventMass.workspace_event_mass_after_workspace_projection_le
    (globalErasedCollision producer ns) fullFailure original
  have selectorBound :
      (∑ role : Role,
        normSquared (workspaceEventProjection
          (fun _work database => ambientXViewFailureRoleSelector producer ns fallback fuel ctx role branch
            (xView (nonchallengeRawKeySet ctx) database)) failureState)) ≤
      ∑ role : Role,
        normSquared (workspaceEventProjection
          (fun _work database => ambientXViewFailureRoleSelector producer ns fallback fuel ctx role branch
            (xView (nonchallengeRawKeySet ctx) database)) original) := by
    apply Finset.sum_le_sum
    intro role _
    exact SmzaRp05CurrentSelectedCurrentAdviceEventMass.workspace_event_mass_after_workspace_projection_le
      (fun _work database => ambientXViewFailureRoleSelector producer ns fallback fuel ctx role branch
        (xView (nonchallengeRawKeySet ctx) database)) fullFailure original
  have missingBound := database_event_mass_after_workspace_projection_le
    (fun database => ¬ ClaimsDatabaseEvent
      (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch)
      database) fullFailure original
  calc
    (if branchResult groupedDecode program branch = some () then
      normSquared failureState else 0) ≤
        normSquared (workspaceEventProjection (globalErasedCollision producer ns)
          failureState) +
        (∑ role : Role,
          normSquared (workspaceEventProjection
            (fun _work database => ambientXViewFailureRoleSelector producer ns fallback fuel ctx role branch
              (xView (nonchallengeRawKeySet ctx) database)) failureState)) +
        normSquared (databaseEventProjection
          (fun database => ¬ ClaimsDatabaseEvent
            (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch)
            database) failureState) := by
      by_cases acceptedBranch : branchResult groupedDecode program branch = some ()
      · rw [if_pos acceptedBranch] at split ⊢
        exact split
      · rw [if_neg acceptedBranch] at split ⊢
        exact split
    _ ≤ normSquared (workspaceEventProjection (globalErasedCollision producer ns)
          original) +
        (∑ role : Role,
          normSquared (workspaceEventProjection
            (fun _work database => ambientXViewFailureRoleSelector producer ns fallback fuel ctx role branch
              (xView (nonchallengeRawKeySet ctx) database)) original)) +
        normSquared (databaseEventProjection
          (fun database => ¬ ClaimsDatabaseEvent
            (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch)
            database) original) := by
      exact add_le_add (add_le_add collisionBound selectorBound) missingBound


theorem ordinary_original_collision_mass_le_fiber_sum
    (producer : Program ParsedContext)
    (ns : Namespace)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (role : Role) (advice : AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix
      (Key := Key (fixedNamespaceContextProgram ns producer))
      (Counter := GroupCounter) (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis
      (Input := Key (fixedNamespaceContextProgram ns producer))
      (Phase := VectorOutput GroupCounter)
      (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ)
    (blockCap : Role → Nat)
    (dummy : ActiveKey role blockCap
      (currentGroupedContext (BaseWork := BaseWork)
        (fixedNamespaceContextProgram ns producer) model bounded
        ns role advice outerFuel innerFuel (fun _ => ∅)).keyBytes) :
    let program := fixedNamespaceContextProgram ns producer
    let ctx := currentGroupedContext (BaseWork := BaseWork) program model bounded
      ns role advice outerFuel innerFuel (fun _ => ∅)
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    letI := physicalBranchesFintype groupedDecode program
    (∑ branch : Branches groupedDecode program,
      normSquared (workspaceEventProjection (globalErasedCollision producer ns)
        (physicalRun (encode program) groupedDecode program branch initial))) ≤
    (∑ branch : Branches groupedDecode program,
      ∑ fixed : FixedTable ctx blockCap,
        normSquared (workspaceEventProjection
          (fun memory database => event
            (filteredCollisionEventSpec (activeContext ctx blockCap fixed) cap)
            (activeMemoryEquiv ctx memory) database)
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap
              (physicalRun (encode program) groupedDecode program branch initial))))) := by
  classical
  let program := fixedNamespaceContextProgram ns producer
  let ctx := currentGroupedContext (BaseWork := BaseWork) program model bounded
    ns role advice outerFuel innerFuel (fun _ => ∅)
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
  letI := physicalBranchesFintype groupedDecode program
  dsimp only
  apply Finset.sum_le_sum
  intro branch _
  exact SmzaRp05CurrentHistoryCollisionMass.original_history_erased_collision_mass_le_current_filtered_fibers
    ctx blockCap dummy cap (fun _ => rfl)
    (physicalRun (encode program) groupedDecode program branch initial)
    (SmzaRp05OrdinarySoundnessStandardTotal.ordinary_physical_branch_fixed_other_total ordinaryProgram registers
      (encode program) groupedDecode program branch ctx blockCap)

end
end HegemonCrypto.SmallWood.SmzaRp05ContextAmbientFailureMass
