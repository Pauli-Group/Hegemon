import SmzaRp05ContextAmbientFailureMass
import SmzaRp05ContextAmbientFourRole
import SmzaRp05CurrentAcceptedBranchMassCoverage
import SmzaRp05CurrentAcceptedDecsExtractionFailureEvent
import SmzaRp05CurrentAcceptedExtractionFailureMass
import SmzaRp05CurrentAcceptedMassToScalar
import SmzaRp05CurrentAcceptedSelectedFiberMass
import SmzaRp05CurrentAcceptedSelectorClaims
import SmzaRp05CurrentAcceptedSoundnessEndpoint
import SmzaRp05CurrentClaimsXViewCompletion
import SmzaRp05CurrentFullOrRoleExtraction
import SmzaRp05CurrentFullOrRoleXViewCoverage
import SmzaRp05CurrentOrdinaryInitializedLedger
import SmzaRp05CurrentOrdinarySoundnessFinalBound
import SmzaRp05CurrentPhysicalBranchClaimsConsistent
import SmzaRp05CurrentProtocolModelBound
import SmzaRp05SourceReadSchedule

/-! # Guard-free full-extraction failure mass on ordinary fibers

The branch amplitudes below are projected onto failure of the designated
full-extraction selector on their own nonchallenge X-view.  This isolates the
actual full-or-role failure event without a global no-packed-witness premise.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ContextAmbientScalar

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
open SmzaRp05ContextAmbientCoverage (ambientXViewFullSuccessSelector ambientXViewFailureRoleSelector)
open SmzaRp05ContextAmbientFailureMass (globalErasedCollision)
def ambientMassContexts
    (producer : Program ParsedContext)
    (ns : SmzaRp05LeafNamespace.Namespace)
     (model : RelationModel)
    (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role)
    (outerFuel innerFuel : Nat) :
    Role → Context (Key := Key (fixedNamespaceContextProgram ns producer))
      (Counter := GroupCounter) (BaseWork := BaseWork) :=
  fun role => currentGroupedContext (BaseWork := BaseWork)
    (fixedNamespaceContextProgram ns producer)
    model bounded ns role
    (advice role) outerFuel innerFuel (fun _ => ∅)

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
    (ns : Namespace)  (fallback : RawDigest)
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

theorem accepted_failure_projection_mass_le_scalar_lhs
    (producer : Program ParsedContext)
    (ns : Namespace)  (fallback : RawDigest)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role)
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
    (dummy : ∀ role : Role,
      ActiveKey (emptyAuthorizationContexts
        (ambientMassContexts (BaseWork := BaseWork)
          producer ns model bounded advice outerFuel innerFuel) role).role
        blockCap
        (emptyAuthorizationContexts
          (ambientMassContexts (BaseWork := BaseWork)
            producer ns model bounded advice outerFuel innerFuel) role).keyBytes) :
    let program := fixedNamespaceContextProgram ns producer
    let contexts := ambientMassContexts (BaseWork := BaseWork)
      producer ns model bounded advice outerFuel innerFuel
    let roleCtx := fun role => emptyAuthorizationContexts contexts role
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    letI := physicalBranchesFintype groupedDecode program
    (∑ branch : Branches groupedDecode program,
      if branchResult groupedDecode program branch = some () then
        normSquared (workspaceEventProjection
          (fun _work database => ¬ ambientXViewFullSuccessSelector
            producer ns fallback fuel (contexts .decsMatrix)
            branch (xView (nonchallengeRawKeySet (contexts .decsMatrix)) database))
          (physicalRun (encode program) groupedDecode program branch initial))
      else 0) ≤
    (∑ role : Role, ∑ branch : Branches groupedDecode program,
      ∑ fixed : FixedTable (roleCtx role) blockCap,
        normSquared (selectedRoleState (roleCtx role) blockCap (encode program)
          groupedDecode program branch fixed
          (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
            (otherRoleTransform (roleCtx role) blockCap initial))
          (fun view _work => ambientXViewFailureRoleSelector producer ns fallback fuel (roleCtx role) role branch view))) +
    (∑ role : Role, ∑ branch : Branches groupedDecode program,
      ∑ fixed : FixedTable (roleCtx role) blockCap,
        normSquared (workspaceEventProjection
          (fun memory database => event
            (filteredCollisionEventSpec (activeContext (roleCtx role) blockCap fixed) cap)
            (activeMemoryEquiv (roleCtx role) memory) database)
          (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
            (otherRoleTransform (roleCtx role) blockCap
              (physicalRun (encode program) groupedDecode program branch initial))))) +
    (∑ role : Role, ∑ branch : Branches groupedDecode program,
      normSquared (claimFailureProjection
        (branchNonchallengeClaims (roleCtx role).keyBytes (encode program) groupedDecode
          program branch)
        (physicalRun (encode program) groupedDecode program branch initial))) := by
  classical
  let program := fixedNamespaceContextProgram ns producer
  letI := physicalBranchesFintype groupedDecode program
  let contexts := ambientMassContexts (BaseWork := BaseWork)
    producer ns model bounded advice outerFuel innerFuel
  let roleCtx := fun role => emptyAuthorizationContexts contexts role
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
  let ctx := contexts .decsMatrix
  let select : ∀ role : Role, Branches groupedDecode program →
      (XKey (nonchallengeRawKeySet (roleCtx role)) →
        Option (VectorOutput GroupCounter)) →
      Work (Counter := GroupCounter) (BaseWork := BaseWork) → Prop :=
    fun role branch view _work => ambientXViewFailureRoleSelector producer ns fallback fuel (roleCtx role) role branch view
  let selectedFiberMass := ∑ role : Role, ∑ branch : Branches groupedDecode program,
    ∑ fixed : FixedTable (roleCtx role) blockCap,
      normSquared (selectedRoleState (roleCtx role) blockCap (encode program)
        groupedDecode program branch fixed
        (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
          (otherRoleTransform (roleCtx role) blockCap initial)) (select role branch))
  let collisionFiberMass := ∑ role : Role, ∑ branch : Branches groupedDecode program,
    ∑ fixed : FixedTable (roleCtx role) blockCap,
      normSquared (workspaceEventProjection
        (fun memory database => event
          (filteredCollisionEventSpec (activeContext (roleCtx role) blockCap fixed) cap)
          (activeMemoryEquiv (roleCtx role) memory) database)
        (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
          (otherRoleTransform (roleCtx role) blockCap
            (physicalRun (encode program) groupedDecode program branch initial))))
  let missingMass := ∑ role : Role, ∑ branch : Branches groupedDecode program,
    normSquared (claimFailureProjection
      (branchNonchallengeClaims (roleCtx role).keyBytes (encode program) groupedDecode
        program branch)
      (physicalRun (encode program) groupedDecode program branch initial))
  let rawCollisionMass := ∑ branch : Branches groupedDecode program,
    normSquared (workspaceEventProjection
      (globalErasedCollision producer ns)
      (physicalRun (encode program) groupedDecode program branch initial))
  let rawSelectorMass := ∑ role : Role, ∑ branch : Branches groupedDecode program,
    normSquared (workspaceEventProjection
      (fun _work database => ambientXViewFailureRoleSelector producer ns fallback fuel ctx role branch
        (xView (nonchallengeRawKeySet ctx) database))
      (physicalRun (encode program) groupedDecode program branch initial))
  let rawMissingMass := ∑ branch : Branches groupedDecode program,
    normSquared (databaseEventProjection
      (fun database => ¬ ClaimsDatabaseEvent
        (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch)
        database)
      (physicalRun (encode program) groupedDecode program branch initial))
  dsimp only
  have split := SmzaRp05ContextAmbientFailureMass.accepted_failure_projection_mass_le_collision_failure_missing
    producer ns fallback fuel enough model bounded
    (advice .decsMatrix) outerFuel innerFuel initial
  have split' :
      (∑ branch : Branches groupedDecode program,
        if branchResult groupedDecode program branch = some () then
          normSquared (workspaceEventProjection
            (fun _work database => ¬ ambientXViewFullSuccessSelector
              producer ns fallback fuel ctx branch
              (xView (nonchallengeRawKeySet ctx) database))
            (physicalRun (encode program) groupedDecode program branch initial))
        else 0) ≤ rawCollisionMass + rawSelectorMass + rawMissingMass := by
    calc
      _ ≤ ∑ branch : Branches groupedDecode program,
          (normSquared (workspaceEventProjection
            (globalErasedCollision producer ns)
            (physicalRun (encode program) groupedDecode program branch initial)) +
          (∑ role : Role, normSquared (workspaceEventProjection
            (fun _work database => ambientXViewFailureRoleSelector producer ns fallback fuel ctx role branch
              (xView (nonchallengeRawKeySet ctx) database))
            (physicalRun (encode program) groupedDecode program branch initial))) +
          normSquared (databaseEventProjection
            (fun database => ¬ ClaimsDatabaseEvent
              (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode
                program branch) database)
            (physicalRun (encode program) groupedDecode program branch initial))) := by
          simpa only [program, ctx, contexts, ambientMassContexts, initial] using split
      _ = rawCollisionMass + rawSelectorMass + rawMissingMass := by
          dsimp only [rawCollisionMass, rawSelectorMass, rawMissingMass]
          simp only [Finset.sum_add_distrib]
          rw [Finset.sum_comm]
  have selectorBound : rawSelectorMass ≤ selectedFiberMass := by
    dsimp only [rawSelectorMass, selectedFiberMass, select]
    apply Finset.sum_le_sum
    intro role _
    have roleBound := accepted_xview_selector_mass_le_ordinary_selected_fiber_mass
      (roleCtx role) ordinaryProgram registers (encode program) groupedDecode program
      blockCap (dummy role)
      (fun branch view _work => ambientXViewFailureRoleSelector producer ns fallback fuel (roleCtx role) role branch view)
      (by
        intro branch view work selected claim member
        exact failure_selector_supplies_unrecognized_claims producer ns fallback fuel (roleCtx role) blockCap role branch view selected claim member)
      (by
        intro key member nonchallenge
        have parsedNone := nonchallenge_raw_key_set_unrecognized (roleCtx role) key nonchallenge
        have fixedOther := (mem_fixed_other_keys (roleCtx role) blockCap key).mp member
        exact fixedOther (by simp [RoleActive, parsedNone]))
    have roleBound' :
        (∑ branch : Branches groupedDecode program,
          normSquared (workspaceEventProjection
            (fun _work database => ambientXViewFailureRoleSelector producer ns fallback fuel (roleCtx role) role branch
              (xView (nonchallengeRawKeySet (roleCtx role)) database))
            (physicalRun (encode program) groupedDecode program branch initial))) ≤
        (∑ branch : Branches groupedDecode program,
          ∑ fixed : FixedTable (roleCtx role) blockCap,
            normSquared (selectedRoleState (roleCtx role) blockCap (encode program)
              groupedDecode program branch fixed
              (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
                (otherRoleTransform (roleCtx role) blockCap initial))
              (select role branch))) := by
      convert roleBound using 1
    calc
      (∑ branch : Branches groupedDecode program,
        normSquared (workspaceEventProjection
          (fun _work database => ambientXViewFailureRoleSelector producer ns fallback fuel ctx role branch
            (xView (nonchallengeRawKeySet ctx) database))
          (physicalRun (encode program) groupedDecode program branch initial))) =
      (∑ branch : Branches groupedDecode program,
        normSquared (workspaceEventProjection
          (fun _work database => ambientXViewFailureRoleSelector producer ns fallback fuel (roleCtx role) role branch
            (xView (nonchallengeRawKeySet (roleCtx role)) database))
          (physicalRun (encode program) groupedDecode program branch initial))) := by
        apply Finset.sum_congr rfl
        intro branch _
        congr 1
      _ ≤ _ := roleBound'
  have collisionRawBound := SmzaRp05ContextAmbientFailureMass.ordinary_original_collision_mass_le_fiber_sum
    producer ns model bounded .decsMatrix (advice .decsMatrix)
    outerFuel innerFuel ordinaryProgram registers blockCap (dummy .decsMatrix)
  have collisionEmbedding :
      (∑ branch : Branches groupedDecode program,
        ∑ fixed : FixedTable (roleCtx .decsMatrix) blockCap,
          normSquared (workspaceEventProjection
            (fun memory database => event
              (filteredCollisionEventSpec
                (activeContext (roleCtx .decsMatrix) blockCap fixed) cap)
              (activeMemoryEquiv (roleCtx .decsMatrix) memory) database)
            (fixedFiberToActive (roleCtx .decsMatrix) blockCap
              (dummy .decsMatrix) fixed
              (otherRoleTransform (roleCtx .decsMatrix) blockCap
                (physicalRun (encode program) groupedDecode program branch initial))))) ≤
      collisionFiberMass := by
    dsimp only [collisionFiberMass]
    let perRole : Role → ℝ := fun role =>
      ∑ branch : Branches groupedDecode program,
        ∑ fixed : FixedTable (roleCtx role) blockCap,
          normSquared (workspaceEventProjection
            (fun memory database => event
              (filteredCollisionEventSpec (activeContext (roleCtx role) blockCap fixed) cap)
              (activeMemoryEquiv (roleCtx role) memory) database)
            (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
              (otherRoleTransform (roleCtx role) blockCap
                (physicalRun (encode program) groupedDecode program branch initial))))
    change perRole .decsMatrix ≤ ∑ role : Role, perRole role
    apply Finset.single_le_sum
    · intro role _
      dsimp only [perRole]
      apply Finset.sum_nonneg
      intro branch _
      apply Finset.sum_nonneg
      intro fixed _
      exact normSquared_nonnegative _
    · exact Finset.mem_univ Role.decsMatrix
  have collisionBound : rawCollisionMass ≤ collisionFiberMass := by
    calc
      rawCollisionMass ≤
          (∑ branch : Branches groupedDecode program,
            ∑ fixed : FixedTable (roleCtx .decsMatrix) blockCap,
              normSquared (workspaceEventProjection
                (fun memory database => event
                  (filteredCollisionEventSpec
                    (activeContext (roleCtx .decsMatrix) blockCap fixed) cap)
                  (activeMemoryEquiv (roleCtx .decsMatrix) memory) database)
                (fixedFiberToActive (roleCtx .decsMatrix) blockCap (dummy .decsMatrix) fixed
                  (otherRoleTransform (roleCtx .decsMatrix) blockCap
                    (physicalRun (encode program) groupedDecode program branch initial))))) := by
            convert collisionRawBound using 1; rfl
      _ ≤ collisionFiberMass := collisionEmbedding
  have missingEmbedding : rawMissingMass ≤ missingMass := by
    dsimp only [rawMissingMass, missingMass]
    calc
      (∑ branch : Branches groupedDecode program,
        normSquared (databaseEventProjection
          (fun database => ¬ ClaimsDatabaseEvent
            (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch)
            database)
          (physicalRun (encode program) groupedDecode program branch initial))) ≤
      (∑ branch : Branches groupedDecode program, ∑ role : Role,
        normSquared (claimFailureProjection
          (branchNonchallengeClaims (roleCtx role).keyBytes (encode program) groupedDecode
            program branch)
          (physicalRun (encode program) groupedDecode program branch initial))) := by
        apply Finset.sum_le_sum
        intro branch _
        dsimp only [claimFailureProjection]
        exact Finset.single_le_sum (fun (_role : Role) _ => normSquared_nonnegative _)
          (Finset.mem_univ Role.decsMatrix)
      _ = ∑ role : Role, ∑ branch : Branches groupedDecode program,
          normSquared (claimFailureProjection
            (branchNonchallengeClaims (roleCtx role).keyBytes (encode program) groupedDecode
              program branch)
            (physicalRun (encode program) groupedDecode program branch initial)) := by
        rw [Finset.sum_comm]
  linarith [split', selectorBound, collisionBound, missingEmbedding]

end
end HegemonCrypto.SmallWood.SmzaRp05ContextAmbientScalar

/-! # Current accepted full-extraction failure endpoint

This endpoint bounds failure of the designated full-extraction selector on
the same accepted physical branch and its own nonchallenge X-view. The
four-role guard-free dispatcher supplies event inclusion pointwise; the
ordinary scalar ledger supplies the numeric threshold. No extraction witness,
event-coverage, or probability premise is accepted from the caller.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ContextAmbientEndpoint

open SmzaRp05ContextAmbientDecoder (ParsedContext fixedNamespaceContextProgram)
open SmzaRp05OrdinarySoundnessExecution (OrdinaryPrefix)
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge (workspaceEventProjection)
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRp05CurrentAdaptiveExecution (Work)
open SmzaRp05ConditionedExecution
  (FixedTable fixedFiberToActive otherRoleTransform activeMemoryEquiv ActiveMemory)
open SmzaRoleDomainConditioning (ActiveKey unrecognized_is_active)
open SmzaRp05CurrentAcceptedOrdinaryMassBound (actualProgram)
open SmzaRp05ContextAmbientScalar (ambientMassContexts)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05ContextAmbientFourRole
  (grouped_four_role_failure_support_implies_current_advice_event_or_missing_claims)
open SmzaRp05CurrentSelectedChallengeClaims (recognizedActiveChallengeClaims)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix GroupCounter GroupComplement groupEncode groupKeyOf
    groupRepresentative groupAddress groupZero group_address_complement)
open SmzaRp05ActualEventRecertification (event)
open SmzaRp05OrdinarySoundnessExecution
  (ordinaryRun emptyAuthorizationContexts)
open SmzaRp05AdaptivePhysicalReadBound
  (ReadsAtMost ReadsWithinKeys physicalBranchesFintype)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult physicalRun)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol protocolBlockCap PhysicalInput)
open SmzaRp05RelationRefinement (relationModel GeneratedCertificates)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentOrdinarySoundnessFinalBound
  (ordinary_selected_readout_collision_scalar_bound)
open SmzaRp05CurrentOrdinaryInitializedLedger (ordinary_scalar_rhs_below_130)
open SmzaRp05CurrentProtocolModelBound
  (current_model_within_protocol current_protocol_positive_caps)
open SmzaRp05SourceReadSchedule
  (readBudget source_reads_within_budget source_reads_within_finite_address_space)
open SmzaRp05GroupedSuffix (GroupCounter)
open SmzaRp05ContextAmbientCoverage (ambientXViewFailureRoleSelector)
open SmzaRp05ContextAmbientCoverage (ambientXViewFullSuccessSelector)
open SmzaRp05ConditionedExecution (XKey xView)
open SmzaRp05CurrentSelectedChallengeClaims (nonchallengeRawKeySet)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8SmzaOracleParser (RawDigest)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
  (V8PublicStatement encodePublicStatement)
open SmzaRp05CurrentAdviceDependentPhysicalMass (currentAdviceEventSpec)

attribute [local irreducible]
  HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates.currentDsl

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 18000
set_option maxHeartbeats 1600000
set_option linter.unusedSectionVars false

private theorem group_encode_ne_empty
    (key : CanonicalRolePrefix × GroupCounter) :
    groupEncode key ≠ ([] : PhysicalInput) := by
  rcases key with ⟨rolePrefix, counter⟩
  have encodedLength : (groupEncode (rolePrefix, counter)).length =
      rolePrefix.leading.length + 8 := by
    simp [groupEncode, V8Smz9RawCounterCompiler.counterInput,
      V8Smz9RawCounterCompiler.boundedCounterInput,
      HegemonCrypto.CanonicalBytes.encodeLE_length]
  intro encoded
  rw [encoded] at encodedLength
  simp at encodedLength

private theorem empty_group_key_representative_unparsed :
    parseStageQuery (groupRepresentative (groupKeyOf ([] : PhysicalInput))) = none := by
  let fallbackComplement : GroupComplement :=
    ⟨[], by
      intro member
      rcases member with ⟨key, encoded⟩
      exact group_encode_ne_empty key encoded⟩
  have address : groupAddress ([] : PhysicalInput) =
      (Sum.inr fallbackComplement, groupZero) := by
    simpa [fallbackComplement] using group_address_complement fallbackComplement
  have keyEq : groupKeyOf ([] : PhysicalInput) = Sum.inr fallbackComplement := by
    change (groupAddress ([] : PhysicalInput)).1 = Sum.inr fallbackComplement
    rw [address]
  rw [keyEq]
  change parseStageQuery ([] : PhysicalInput) = none
  decide

private noncomputable def currentAcceptedFallbackKey {Result : Type}
    (program : Program Result) : Key program := by
  classical
  exact ⟨groupKeyOf ([] : PhysicalInput), Finset.mem_insert_self _ _⟩

/-- The accepted branch's full-extraction-failure projection is below the
ordinary 130-bit threshold. The selector is checked on the original branch's
own X-view, and the scalar/event bridge is derived in this theorem. -/
theorem actual_accepted_full_extraction_failure_mass_below_130_bits
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ParsedContext)
    (ns : Namespace)  (fallback : RawDigest)
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix
      (Key := Key (fixedNamespaceContextProgram ns producer))
      (Counter := GroupCounter) (BaseWork := BaseWork)
      (cap := cap) 0 finish queries)
    (registers : RegisterBasis
      (Input := Key (fixedNamespaceContextProgram ns producer))
      (Phase := VectorOutput GroupCounter)
      (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ)
    (incomingUnit : normSquared
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers) = 1)
    (queriesWithin : queries + readBudget groupedDecode
      (fixedNamespaceContextProgram ns producer) ≤ cap)
    (capBound : cap ≤ 3 * 2 ^ 64) :
    let program := fixedNamespaceContextProgram ns producer
    let contexts := ambientMassContexts (BaseWork := BaseWork)
      producer ns (relationModel currentDsl
        SmzaRp05GeneratedCertificates.certificates)
      current_model_within_protocol (fun _ => fun _ _ _ _ => none) 28 28
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    let ctx := contexts .decsMatrix
    letI := physicalBranchesFintype groupedDecode program
    (∑ branch : Branches groupedDecode program,
      if branchResult groupedDecode program branch = some () then
        normSquared (workspaceEventProjection
          (fun _work database => ¬ ambientXViewFullSuccessSelector
            producer ns fallback 28 ctx branch
            (xView (nonchallengeRawKeySet ctx) database))
          (physicalRun (encode program) groupedDecode program branch initial))
      else 0) < ((1 / (2 : Rat)^130 : Rat) : ℝ) := by
  classical
  let program := fixedNamespaceContextProgram ns producer
  let certificates : GeneratedCertificates currentDsl :=
    SmzaRp05GeneratedCertificates.certificates
  let bounded : ModelWithinProtocol (relationModel currentDsl certificates) :=
    current_model_within_protocol
  let blockCap : Role → Nat := protocolBlockCap
  obtain ⟨positiveDecsMatrixCap, positivePiopMatrixCap,
    positivePiopOpeningCap⟩ := current_protocol_positive_caps
  let model := relationModel currentDsl certificates
  let advice : ∀ role : Role, AllEarlierTables model role :=
    fun _ => fun _ _ _ _ => none
  let contexts := ambientMassContexts (BaseWork := BaseWork)
    producer ns model bounded advice 28 28
  let roleCtx := fun role => emptyAuthorizationContexts contexts role
  let dummy : ∀ role : Role, ActiveKey (roleCtx role).role blockCap
      (roleCtx role).keyBytes := by
    intro role
    refine ⟨currentAcceptedFallbackKey program, ?_⟩
    change SmzaRoleDomainConditioning.RoleActive role blockCap
      (roleCtx role).keyBytes (currentAcceptedFallbackKey program)
    apply unrecognized_is_active
    change parseStageQuery
      (groupRepresentative (included program (currentAcceptedFallbackKey program))) = none
    simpa [currentAcceptedFallbackKey, included] using
      empty_group_key_representative_unparsed
  let select := fun (role : Role) branch view (_work : Work
      (Counter := GroupCounter) (BaseWork := BaseWork)) =>
    ambientXViewFailureRoleSelector producer ns fallback 28
      (roleCtx role) role branch view
  let depth := readBudget groupedDecode program
  have readBound : ReadsAtMost groupedDecode depth program :=
    source_reads_within_budget groupedDecode program
  let keys : List (Key program) := (Finset.univ : Finset (Key program)).toList
  have keysWithin : ReadsWithinKeys (encode program) groupedDecode keys program := by
    simpa [keys] using source_reads_within_finite_address_space
      (encode program) groupedDecode program
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
  letI := physicalBranchesFintype groupedDecode program
  have finishEq : finish = queries := by
    simpa using
      SmzaRp05CurrentAcceptedSoundnessEndpoint.ordinaryPrefix_finish_eq_start_add_queries
        ordinaryProgram
  have queriesWithinDepth : queries + depth ≤ cap := by
    simpa only [depth, program] using queriesWithin
  have supportWithin : finish + depth ≤ cap := by
    rw [finishEq]
    exact queriesWithinDepth
  have included :
      ∀ (role : Role) (branch : Branches groupedDecode program)
        (fixed : FixedTable (roleCtx role) blockCap)
        (basis : Basis (ActiveKey (roleCtx role).role blockCap
          (roleCtx role).keyBytes) (VectorOutput GroupCounter)
          (VectorOutput GroupCounter) (ActiveMemory (roleCtx role))),
        selectedRoleState (roleCtx role) blockCap (encode program) groupedDecode
          program branch fixed
          (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
            (otherRoleTransform (roleCtx role) blockCap initial))
          (select role branch) basis ≠ 0 →
          event (currentAdviceEventSpec (roleCtx role) blockCap fixed cap)
            (activeMemoryEquiv (roleCtx role) basis.workspace) basis.database ∨
          ¬ ClaimsDatabaseEvent
            (recognizedActiveChallengeClaims (roleCtx role) blockCap
              (encode program) groupedDecode program branch) basis.database := by
    intro role branch fixed basis selectedNonzero
    exact grouped_four_role_failure_support_implies_current_advice_event_or_missing_claims
      (BaseWork := BaseWork) producer ns fallback
      certificates bounded blockCap positiveDecsMatrixCap positivePiopMatrixCap
      positivePiopOpeningCap role branch fixed (dummy role) initial basis cap
      selectedNonzero
  have massBound :=
    SmzaRp05ContextAmbientScalar.accepted_failure_projection_mass_le_scalar_lhs
      (BaseWork := BaseWork) producer ns fallback
      28 (by decide) model bounded advice 28 28 ordinaryProgram registers blockCap dummy
  have scalarBound := ordinary_selected_readout_collision_scalar_bound
    contexts ordinaryProgram registers depth (encode program) groupedDecode program
    readBound keys keysWithin supportWithin queriesWithin blockCap dummy select included
  have numericBound := ordinary_scalar_rhs_below_130
    ordinaryProgram registers depth incomingUnit capBound queriesWithinDepth
  exact lt_of_le_of_lt (le_trans massBound scalarBound) numericBound

end
end HegemonCrypto.SmallWood.SmzaRp05ContextAmbientEndpoint