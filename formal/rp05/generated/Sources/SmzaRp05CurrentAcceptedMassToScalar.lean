import SmzaRp05CurrentAcceptedOrdinaryMassBound
import SmzaRp05CurrentAcceptedConcreteSelectedMass
import SmzaRp05CurrentOrdinarySoundnessFinalBound
import SmzaRp05CurrentGroupedContext
import SmzaRp05OrdinarySoundnessExecution
import HegemonCrypto.CmsCompressedOracle
import HegemonCrypto.CmsOracleDatabaseBridge

/-! # Accepted branch mass to the ordinary scalar-bound left side

Compose the actual accepted-branch split with the literal selected-state and
original-collision fiber sums. The only changes of summation index are
nonnegative finite-sum enlargements; no event-coverage or probability premise
is introduced here.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedMassToScalar

open scoped Classical BigOperators
open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CmsAdaptiveClaimBridge (workspaceEventProjection)
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent databaseEventProjection)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaChallengeStageTargets (Role)
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05ConditionedExecution
  (FixedTable XKey xView activeContext activeMemoryEquiv fixedFiberToActive
    otherRoleTransform)
open SmzaRoleDomainConditioning (ActiveKey)
open SmzaRp05CurrentAcceptedOrdinaryMassBound
  (actualProgram collision actual_accepted_failure_mass_le_selector_collision_missing
    ordinary_original_collision_mass_le_fiber_sum)
open SmzaRp05CurrentAcceptedConcreteSelectedMass
  (current_grouped_accepted_selector_mass_le_selected_fibers)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05CurrentAcceptedXViewRoleCoverage (currentAcceptedXViewRoleSelector)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode)
open SmzaRp05CurrentSelectedChallengeClaims (nonchallengeRawKeySet)
open SmzaRp05CurrentPhysicalNonchallengeClaims (branchNonchallengeClaims)
open SmzaRp05CurrentFilteredCollisionEventSpec (filteredCollisionEventSpec)
open SmzaRp05ActualEventRecertification (event)
open SmzaRp05PartialReadout (claimFailureProjection)
open SmzaRp05OrdinarySoundnessExecution
  (OrdinaryPrefix ordinaryRun emptyAuthorizationContexts)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult physicalRun)
open SmzaRp05AdaptivePhysicalReadBound (physicalBranchesFintype)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05GroupedSuffix (GroupCounter groupZero)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8SmzaOracleParser (RawDigest)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
  (V8PublicStatement encodePublicStatement)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 16000
set_option maxHeartbeats 1600000
set_option linter.unusedSectionVars false
set_option exponentiation.threshold 1024

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

attribute [local irreducible]
  HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates.currentDsl

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

/-- The four scalar roles share the exact grouped key embedding and use the
same empty-authorization current context as the accepted branch split. -/
def currentAcceptedMassContexts
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (model : RelationModel)
    (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role)
    (outerFuel innerFuel : Nat) :
    Role → Context (Key := Key (actualProgram
      producer ns statement pending nonce))
      (Counter := GroupCounter) (BaseWork := BaseWork) :=
  fun role => currentGroupedContext (BaseWork := BaseWork)
    (actualProgram producer ns statement pending nonce)
    model bounded ns role
    (advice role) outerFuel innerFuel (fun _ => ∅)

/-- The scalar selector uses the per-role context. Its raw X-view is
definitionally the same as the reference `.decsMatrix` view in the branch
split because every grouped context has the same `keyBytes` map. -/
def currentAcceptedMassSelector
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest) (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? statement = some typed)
    (noPackedWitness : ¬ ∃ packed,
      SmzaRp05Components.program.AcceptsPacked (encodePublicStatement typed) packed)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role)
    (outerFuel innerFuel : Nat) :
    ∀ role : Role, Branches groupedDecode
      (actualProgram producer ns statement pending nonce) →
      (XKey (nonchallengeRawKeySet
        (emptyAuthorizationContexts
          (currentAcceptedMassContexts (BaseWork := BaseWork) producer ns statement pending
            nonce model bounded advice outerFuel innerFuel) role)) →
        Option (VectorOutput GroupCounter)) →
      Work (Counter := GroupCounter) (BaseWork := BaseWork) → Prop :=
  fun role branch view work =>
    currentAcceptedXViewRoleSelector producer ns statement pending nonce fallback typed
      parsed noPackedWitness fuel enough
      (emptyAuthorizationContexts
        (currentAcceptedMassContexts (BaseWork := BaseWork) producer ns statement pending nonce
          model bounded advice outerFuel innerFuel) role)
      (by intro key; rfl) role branch view work

/-- The actual accepted-invalid branch mass is at most the exact three-term
left side of `ordinary_selected_readout_collision_scalar_bound`: selected
fixed-fiber mass, four-role original-collision fiber mass, and four-role
nonchallenge failure mass. All norms are unnormalized squared norms from the
same ordinary initial state. -/
theorem actual_accepted_branch_mass_le_scalar_lhs
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? statement = some typed)
    (noPackedWitness : ¬ ∃ packed,
      SmzaRp05Components.program.AcceptsPacked (encodePublicStatement typed) packed)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix
      (Key := Key (actualProgram producer ns statement pending nonce))
      (Counter := GroupCounter) (BaseWork := BaseWork)
      (cap := cap) 0 finish queries)
    (registers : RegisterBasis
      (Input := Key (actualProgram producer ns statement pending nonce))
      (Phase := VectorOutput GroupCounter)
      (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ)
    (blockCap : Role → Nat)
    (dummy : ∀ role : Role,
      ActiveKey (emptyAuthorizationContexts
        (currentAcceptedMassContexts (BaseWork := BaseWork)
          producer ns statement pending nonce model
          bounded advice outerFuel innerFuel) role).role blockCap
        (emptyAuthorizationContexts
          (currentAcceptedMassContexts (BaseWork := BaseWork)
            producer ns statement pending nonce model
            bounded advice outerFuel innerFuel) role).keyBytes) :
    let program := actualProgram producer ns statement pending nonce
    let contexts := currentAcceptedMassContexts (BaseWork := BaseWork)
      producer ns statement pending nonce model
      bounded advice outerFuel innerFuel
    let roleCtx := fun role => emptyAuthorizationContexts contexts role
    let select := currentAcceptedMassSelector (BaseWork := BaseWork)
      producer ns statement pending nonce fallback
      typed parsed noPackedWitness fuel enough model bounded advice outerFuel innerFuel
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    letI := physicalBranchesFintype groupedDecode program
    (∑ branch : Branches groupedDecode program,
      if branchResult groupedDecode program branch = some () then
        normSquared (physicalRun (encode program) groupedDecode program branch initial)
      else 0) ≤
    (∑ role : Role, ∑ branch : Branches groupedDecode program,
      ∑ fixed : FixedTable (roleCtx role) blockCap,
        normSquared (selectedRoleState (roleCtx role) blockCap (encode program)
          groupedDecode program branch fixed
          (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
            (otherRoleTransform (roleCtx role) blockCap initial))
          (select role branch))) +
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
  let contexts := currentAcceptedMassContexts (BaseWork := BaseWork)
    producer ns statement pending nonce model
    bounded advice outerFuel innerFuel
  let roleCtx := fun role => emptyAuthorizationContexts contexts role
  let select := currentAcceptedMassSelector (BaseWork := BaseWork)
    producer ns statement pending nonce fallback
    typed parsed noPackedWitness fuel enough model bounded advice outerFuel innerFuel
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
  let ctx := contexts .decsMatrix
  letI := physicalBranchesFintype groupedDecode program
  dsimp only

  let rawCollisionMass := ∑ branch : Branches groupedDecode program,
    normSquared (workspaceEventProjection
      (collision producer ns statement pending nonce)
      (physicalRun (encode program) groupedDecode program branch initial))
  let rawSelectorMass := ∑ role : Role, ∑ branch : Branches groupedDecode program,
    normSquared (workspaceEventProjection
      (fun work database => currentAcceptedXViewRoleSelector producer ns statement pending
        nonce fallback typed parsed noPackedWitness fuel enough ctx (by intro key; rfl)
        role branch (xView (nonchallengeRawKeySet ctx) database) work)
      (physicalRun (encode program) groupedDecode program branch initial))
  let rawMissingMass := ∑ branch : Branches groupedDecode program,
    normSquared (databaseEventProjection
      (fun database => ¬ ClaimsDatabaseEvent
        (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch)
        database)
      (physicalRun (encode program) groupedDecode program branch initial))
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

  have split := actual_accepted_failure_mass_le_selector_collision_missing
    producer ns statement pending nonce fallback typed parsed noPackedWitness fuel enough
    model bounded (advice .decsMatrix) outerFuel innerFuel initial
  have split' :
      (∑ branch : Branches groupedDecode program,
        if branchResult groupedDecode program branch = some () then
          normSquared (physicalRun (encode program) groupedDecode program branch initial)
        else 0) ≤ rawCollisionMass + rawSelectorMass + rawMissingMass := by
    calc
      _ ≤ ∑ branch : Branches groupedDecode program,
          (normSquared (workspaceEventProjection
            (collision producer ns statement pending nonce)
            (physicalRun (encode program) groupedDecode program branch initial)) +
          (∑ role : Role, normSquared (workspaceEventProjection
            (fun work database => currentAcceptedXViewRoleSelector producer ns statement
              pending nonce fallback typed parsed noPackedWitness fuel enough ctx
              (by intro key; rfl) role branch
              (xView (nonchallengeRawKeySet ctx) database) work)
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
    dsimp only [rawSelectorMass, selectedFiberMass]
    apply Finset.sum_le_sum
    intro role _
    have roleBound := current_grouped_accepted_selector_mass_le_selected_fibers
      producer ns statement pending nonce fallback typed parsed noPackedWitness fuel enough
      model bounded advice outerFuel innerFuel role ordinaryProgram registers blockCap
      (dummy role)
    have roleBound' :
        (∑ branch : Branches groupedDecode program,
          normSquared (workspaceEventProjection
            (fun work database => currentAcceptedXViewRoleSelector producer ns statement
              pending nonce fallback typed parsed noPackedWitness fuel enough (roleCtx role)
              (by intro key; rfl) role branch
              (xView (nonchallengeRawKeySet (roleCtx role)) database) work)
            (physicalRun (encode program) groupedDecode program branch initial))) ≤
        (∑ branch : Branches groupedDecode program,
          ∑ fixed : FixedTable (roleCtx role) blockCap,
            normSquared (selectedRoleState (roleCtx role) blockCap (encode program)
              groupedDecode program branch fixed
              (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
                (otherRoleTransform (roleCtx role) blockCap initial))
              (select role branch))) := by
      convert roleBound using 1 <;> rfl
    calc
      (∑ branch : Branches groupedDecode program,
        normSquared (workspaceEventProjection
          (fun work database => currentAcceptedXViewRoleSelector producer ns statement
            pending nonce fallback typed parsed noPackedWitness fuel enough ctx
            (by intro key; rfl) role branch
            (xView (nonchallengeRawKeySet ctx) database) work)
          (physicalRun (encode program) groupedDecode program branch initial))) =
      (∑ branch : Branches groupedDecode program,
        normSquared (workspaceEventProjection
          (fun work database => currentAcceptedXViewRoleSelector producer ns statement
            pending nonce fallback typed parsed noPackedWitness fuel enough (roleCtx role)
            (by intro key; rfl) role branch
            (xView (nonchallengeRawKeySet (roleCtx role)) database) work)
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
    · exact Finset.mem_univ (Role.decsMatrix)
        
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
        exact Finset.single_le_sum (fun (_role : Role) _ =>
          normSquared_nonnegative _)
          (Finset.mem_univ (Role.decsMatrix))
      _ = ∑ role : Role, ∑ branch : Branches groupedDecode program,
          normSquared (claimFailureProjection
            (branchNonchallengeClaims (roleCtx role).keyBytes (encode program) groupedDecode
              program branch)
            (physicalRun (encode program) groupedDecode program branch initial)) := by
        rw [Finset.sum_comm]

  linarith [split', selectorBound, collisionBound, missingEmbedding]

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedMassToScalar
