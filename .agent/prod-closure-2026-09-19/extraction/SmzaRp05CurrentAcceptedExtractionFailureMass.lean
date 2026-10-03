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

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedExtractionFailureMass

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
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (fuel : Nat)
    (ctx : Context (Key := Key (actualProgram producer ns statement pending nonce))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (role : Role)
    (branch : Branches groupedDecode (actualProgram producer ns statement pending nonce))
    (view : XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput GroupCounter))
    (selected : currentAcceptedXViewFailureRoleSelector producer ns statement pending nonce
      fallback fuel ctx role branch view) :
    ∀ claim (member : claim ∈ unrecognizedActiveBranchClaims ctx blockCap
      (encode (actualProgram producer ns statement pending nonce)) groupedDecode
      (actualProgram producer ns statement pending nonce) branch),
      view ⟨claim.1.val,
        by
          apply Finset.mem_filter.mpr
          exact ⟨Finset.mem_univ _, of_decide_eq_true
            (List.mem_filter.mp member).2⟩⟩ = some claim.2 := by
  dsimp only [currentAcceptedXViewFailureRoleSelector] at selected
  rcases selected with ⟨database, viewMatches, recordedClaims, _evidence⟩
  intro claim member
  have branchMember := unrecognized_active_claim_mem_branch_claims
    ctx blockCap (encode (actualProgram producer ns statement pending nonce))
    groupedDecode (actualProgram producer ns statement pending nonce) branch claim member
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
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? statement = some typed)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : AllEarlierTables model .decsMatrix)
    (outerFuel innerFuel : Nat)
    (initial : State
      (Key (actualProgram producer ns statement pending nonce))
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (Work (Counter := GroupCounter) (BaseWork := BaseWork))) :
    let program := actualProgram producer ns statement pending nonce
    let ctx := currentGroupedContext (BaseWork := BaseWork) program model bounded
      ns .decsMatrix advice outerFuel innerFuel (fun _ => ∅)
    letI := physicalBranchesFintype groupedDecode program
    (∑ branch : Branches groupedDecode program,
      if branchResult groupedDecode program branch = some () then
        normSquared (workspaceEventProjection
          (fun _work database => ¬ currentAcceptedXViewFullSuccessSelector
            producer ns statement pending nonce fallback typed fuel ctx branch
            (xView (nonchallengeRawKeySet ctx) database))
          (physicalRun (encode program) groupedDecode program branch initial))
      else 0) ≤
    (∑ branch : Branches groupedDecode program,
      (normSquared (workspaceEventProjection
        (collision producer ns statement pending nonce)
        (physicalRun (encode program) groupedDecode program branch initial)) +
      (∑ role : Role,
        normSquared (workspaceEventProjection
          (fun _work database => currentAcceptedXViewFailureRoleSelector
            producer ns statement pending nonce fallback fuel ctx role branch
            (xView (nonchallengeRawKeySet ctx) database))
          (physicalRun (encode program) groupedDecode program branch initial))) +
      normSquared (databaseEventProjection
        (fun database => ¬ ClaimsDatabaseEvent
          (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode
            program branch) database)
        (physicalRun (encode program) groupedDecode program branch initial)))) := by
  classical
  let program := actualProgram producer ns statement pending nonce
  let ctx : Context (Key := Key (producer.bind fun wire =>
      verifierProgram ns currentDsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork) :=
    currentGroupedContext (BaseWork := BaseWork)
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
      model bounded ns .decsMatrix advice outerFuel innerFuel (fun _ => ∅)
  letI := physicalBranchesFintype groupedDecode program
  dsimp only
  apply Finset.sum_le_sum
  intro branch _
  let original := physicalRun (encode program) groupedDecode program branch initial
  let fullFailure : Work (Counter := GroupCounter) (BaseWork := BaseWork) →
      Database (Key program) (VectorOutput GroupCounter) → Prop :=
    fun _ database => ¬ currentAcceptedXViewFullSuccessSelector producer ns statement
      pending nonce fallback typed fuel ctx branch
      (xView (nonchallengeRawKeySet ctx) database)
  let failureState := workspaceEventProjection fullFailure original
  have covered : ∀ basis : Basis (Key program) (VectorOutput GroupCounter)
      (VectorOutput GroupCounter) (Work (Counter := GroupCounter) (BaseWork := BaseWork)),
      failureState basis ≠ 0 → branchResult groupedDecode program branch = some () →
      ClaimsDatabaseEvent (branchNonchallengeClaims ctx.keyBytes (encode program)
        groupedDecode program branch) basis.database →
      collision producer ns statement pending nonce basis.workspace basis.database ∨
        ∃ role, currentAcceptedXViewFailureRoleSelector producer ns statement pending
          nonce fallback fuel ctx role branch
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
    have result := accepted_nonchallenge_consistent_branch_has_full_or_failure_selector_or_collision
      producer ns statement pending nonce branch accepted completion completionClaims
      fallback typed parsed fuel enough ctx
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
      have recordsEq := grouped_one_statement_view_eq_of_nonchallenge_key_agreement
        program completion basis.database agreesOnX (globalLeafStatement ns)
        statement.toBytes
      have collisionOriginal : collision producer ns statement pending nonce
          basis.workspace basis.database := by
        dsimp [collision] at collisionAt ⊢
        rw [← recordsEq]
        exact collisionAt
      exact Or.inl collisionOriginal
    · rw [sameView] at fullAt
      exact False.elim (notFull fullAt)
    · rw [sameView] at failed
      exact Or.inr ⟨role, failed⟩
  have split := accepted_branch_mass_le_selector_collision_missing
    (Index := Role) (branchResult groupedDecode program branch = some ())
    failureState
    (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch)
    (collision producer ns statement pending nonce)
    (fun role _work database => currentAcceptedXViewFailureRoleSelector
      producer ns statement pending nonce fallback fuel ctx role branch
      (xView (nonchallengeRawKeySet ctx) database))
    covered
  have collisionBound :=
    SmzaRp05CurrentSelectedCurrentAdviceEventMass.workspace_event_mass_after_workspace_projection_le
    (collision producer ns statement pending nonce) fullFailure original
  have selectorBound :
      (∑ role : Role,
        normSquared (workspaceEventProjection
          (fun _work database => currentAcceptedXViewFailureRoleSelector producer ns statement
            pending nonce fallback fuel ctx role branch
            (xView (nonchallengeRawKeySet ctx) database)) failureState)) ≤
      ∑ role : Role,
        normSquared (workspaceEventProjection
          (fun _work database => currentAcceptedXViewFailureRoleSelector producer ns statement
            pending nonce fallback fuel ctx role branch
            (xView (nonchallengeRawKeySet ctx) database)) original) := by
    apply Finset.sum_le_sum
    intro role _
    exact SmzaRp05CurrentSelectedCurrentAdviceEventMass.workspace_event_mass_after_workspace_projection_le
      (fun _work database => currentAcceptedXViewFailureRoleSelector producer ns statement
        pending nonce fallback fuel ctx role branch
        (xView (nonchallengeRawKeySet ctx) database)) fullFailure original
  have missingBound := database_event_mass_after_workspace_projection_le
    (fun database => ¬ ClaimsDatabaseEvent
      (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch)
      database) fullFailure original
  calc
    (if branchResult groupedDecode program branch = some () then
      normSquared failureState else 0) ≤
        normSquared (workspaceEventProjection (collision producer ns statement pending nonce)
          failureState) +
        (∑ role : Role,
          normSquared (workspaceEventProjection
            (fun _work database => currentAcceptedXViewFailureRoleSelector producer ns statement
              pending nonce fallback fuel ctx role branch
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
    _ ≤ normSquared (workspaceEventProjection (collision producer ns statement pending nonce)
          original) +
        (∑ role : Role,
          normSquared (workspaceEventProjection
            (fun _work database => currentAcceptedXViewFailureRoleSelector producer ns statement
              pending nonce fallback fuel ctx role branch
              (xView (nonchallengeRawKeySet ctx) database)) original)) +
        normSquared (databaseEventProjection
          (fun database => ¬ ClaimsDatabaseEvent
            (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch)
            database) original) := by
      exact add_le_add (add_le_add collisionBound selectorBound) missingBound

/-- The raw failure-projected accepted mass is bounded by the exact same
three-term scalar left side used by the ordinary theorem: selected fixed
fibers, four-role filtered-collision fibers, and four-role missing-claim
mass.  The initialization and every branch amplitude are unchanged. -/
theorem accepted_failure_projection_mass_le_scalar_lhs
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? statement = some typed)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix
      (Key := Key (actualProgram producer ns statement pending nonce))
      (Counter := GroupCounter) (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis
      (Input := Key (actualProgram producer ns statement pending nonce))
      (Phase := VectorOutput GroupCounter)
      (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ)
    (blockCap : Role → Nat)
    (dummy : ∀ role : Role,
      ActiveKey (emptyAuthorizationContexts
        (currentAcceptedMassContexts (BaseWork := BaseWork)
          producer ns statement pending nonce model bounded advice outerFuel innerFuel) role).role
        blockCap
        (emptyAuthorizationContexts
          (currentAcceptedMassContexts (BaseWork := BaseWork)
            producer ns statement pending nonce model bounded advice outerFuel innerFuel) role).keyBytes) :
    let program := actualProgram producer ns statement pending nonce
    let contexts := currentAcceptedMassContexts (BaseWork := BaseWork)
      producer ns statement pending nonce model bounded advice outerFuel innerFuel
    let roleCtx := fun role => emptyAuthorizationContexts contexts role
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    letI := physicalBranchesFintype groupedDecode program
    (∑ branch : Branches groupedDecode program,
      if branchResult groupedDecode program branch = some () then
        normSquared (workspaceEventProjection
          (fun _work database => ¬ currentAcceptedXViewFullSuccessSelector
            producer ns statement pending nonce fallback typed fuel (contexts .decsMatrix)
            branch (xView (nonchallengeRawKeySet (contexts .decsMatrix)) database))
          (physicalRun (encode program) groupedDecode program branch initial))
      else 0) ≤
    (∑ role : Role, ∑ branch : Branches groupedDecode program,
      ∑ fixed : FixedTable (roleCtx role) blockCap,
        normSquared (selectedRoleState (roleCtx role) blockCap (encode program)
          groupedDecode program branch fixed
          (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
            (otherRoleTransform (roleCtx role) blockCap initial))
          (fun view _work => currentAcceptedXViewFailureRoleSelector producer ns statement
            pending nonce fallback fuel (roleCtx role) role branch view))) +
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
  let program := actualProgram producer ns statement pending nonce
  letI := physicalBranchesFintype groupedDecode program
  let contexts := currentAcceptedMassContexts (BaseWork := BaseWork)
    producer ns statement pending nonce model bounded advice outerFuel innerFuel
  let roleCtx := fun role => emptyAuthorizationContexts contexts role
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
  let ctx := contexts .decsMatrix
  let select : ∀ role : Role, Branches groupedDecode program →
      (XKey (nonchallengeRawKeySet (roleCtx role)) →
        Option (VectorOutput GroupCounter)) →
      Work (Counter := GroupCounter) (BaseWork := BaseWork) → Prop :=
    fun role branch view _work => currentAcceptedXViewFailureRoleSelector producer ns
      statement pending nonce fallback fuel (roleCtx role) role branch view
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
      (collision producer ns statement pending nonce)
      (physicalRun (encode program) groupedDecode program branch initial))
  let rawSelectorMass := ∑ role : Role, ∑ branch : Branches groupedDecode program,
    normSquared (workspaceEventProjection
      (fun _work database => currentAcceptedXViewFailureRoleSelector producer ns statement
        pending nonce fallback fuel ctx role branch
        (xView (nonchallengeRawKeySet ctx) database))
      (physicalRun (encode program) groupedDecode program branch initial))
  let rawMissingMass := ∑ branch : Branches groupedDecode program,
    normSquared (databaseEventProjection
      (fun database => ¬ ClaimsDatabaseEvent
        (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch)
        database)
      (physicalRun (encode program) groupedDecode program branch initial))
  dsimp only
  have split := accepted_failure_projection_mass_le_collision_failure_missing
    producer ns statement pending nonce fallback typed parsed fuel enough model bounded
    (advice .decsMatrix) outerFuel innerFuel initial
  have split' :
      (∑ branch : Branches groupedDecode program,
        if branchResult groupedDecode program branch = some () then
          normSquared (workspaceEventProjection
            (fun _work database => ¬ currentAcceptedXViewFullSuccessSelector
              producer ns statement pending nonce fallback typed fuel ctx branch
              (xView (nonchallengeRawKeySet ctx) database))
            (physicalRun (encode program) groupedDecode program branch initial))
        else 0) ≤ rawCollisionMass + rawSelectorMass + rawMissingMass := by
    calc
      _ ≤ ∑ branch : Branches groupedDecode program,
          (normSquared (workspaceEventProjection
            (collision producer ns statement pending nonce)
            (physicalRun (encode program) groupedDecode program branch initial)) +
          (∑ role : Role, normSquared (workspaceEventProjection
            (fun _work database => currentAcceptedXViewFailureRoleSelector producer ns statement
              pending nonce fallback fuel ctx role branch
              (xView (nonchallengeRawKeySet ctx) database))
            (physicalRun (encode program) groupedDecode program branch initial))) +
          normSquared (databaseEventProjection
            (fun database => ¬ ClaimsDatabaseEvent
              (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode
                program branch) database)
            (physicalRun (encode program) groupedDecode program branch initial))) := by
          simpa only [program, ctx, contexts, currentAcceptedMassContexts, initial] using split
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
      (fun branch view _work => currentAcceptedXViewFailureRoleSelector producer ns statement
        pending nonce fallback fuel (roleCtx role) role branch view)
      (by
        intro branch view work selected claim member
        exact failure_selector_supplies_unrecognized_claims producer ns statement pending
          nonce fallback fuel (roleCtx role) blockCap role branch view selected claim member)
      (by
        intro key member nonchallenge
        have parsedNone := nonchallenge_raw_key_set_unrecognized (roleCtx role) key nonchallenge
        have fixedOther := (mem_fixed_other_keys (roleCtx role) blockCap key).mp member
        exact fixedOther (by simp [RoleActive, parsedNone]))
    have roleBound' :
        (∑ branch : Branches groupedDecode program,
          normSquared (workspaceEventProjection
            (fun _work database => currentAcceptedXViewFailureRoleSelector producer ns statement
              pending nonce fallback fuel (roleCtx role) role branch
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
          (fun _work database => currentAcceptedXViewFailureRoleSelector producer ns statement
            pending nonce fallback fuel ctx role branch
            (xView (nonchallengeRawKeySet ctx) database))
          (physicalRun (encode program) groupedDecode program branch initial))) =
      (∑ branch : Branches groupedDecode program,
        normSquared (workspaceEventProjection
          (fun _work database => currentAcceptedXViewFailureRoleSelector producer ns statement
            pending nonce fallback fuel (roleCtx role) role branch
            (xView (nonchallengeRawKeySet (roleCtx role)) database))
          (physicalRun (encode program) groupedDecode program branch initial))) := by
        apply Finset.sum_congr rfl
        intro branch _
        congr 1
      _ ≤ _ := roleBound'
  have collisionRawBound := ordinary_original_collision_mass_le_fiber_sum
    producer ns statement pending nonce model bounded .decsMatrix (advice .decsMatrix)
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

end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedExtractionFailureMass
