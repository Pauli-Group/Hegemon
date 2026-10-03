import SmzaRp05CurrentAcceptedCompletionCoverage
import SmzaRp05CurrentAcceptedBranchMassCoverage
import SmzaRp05CurrentAcceptedCollisionMassTransport
import SmzaRp05CurrentAcceptedConcreteSelectedMass
import SmzaRp05CurrentGroupedContext

/-! # Accepted current verifier mass on its original physical branches

The accepted branch predicate is the result of the actual producer followed
by the current verifier. Its support coverage is derived from completion of
that same branch's claims. Neither coverage nor a probability bound is an
input. The collision projection is on the original, unconditioned branch.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedOrdinaryMassBound

open scoped Classical BigOperators
open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaChallengeStageTargets (Role)
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05ConditionedExecution (XKey xView)
open SmzaRp05ConditionedExecution
  (FixedTable fixedFiberToActive otherRoleTransform activeContext activeMemoryEquiv)
open SmzaRoleDomainConditioning (ActiveKey)
open SmzaRp05CurrentFilteredCollisionEventSpec (filteredCollisionEventSpec)
open SmzaRp05ActualEventRecertification (event)
open SmzaRp05CurrentAcceptedCollisionMassTransport
  (original_statement_erased_collision_mass_le_current_filtered_fibers)
open SmzaRp05OrdinarySoundnessStandardTotal
  (ordinary_physical_branch_fixed_other_total)
open SmzaRp05CurrentSelectedChallengeClaims (nonchallengeRawKeySet)
open SmzaRp05CurrentPhysicalNonchallengeClaims (branchNonchallengeClaims)
open SmzaRp05CurrentAcceptedCompletionCoverage
open SmzaRp05CurrentAcceptedBranchMassCoverage
open SmzaRp05CurrentAcceptedXViewRoleCoverage (currentAcceptedXViewRoleSelector)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative groupZero)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05OrdinarySoundnessExecution
open SmzaRp05AdaptivePhysicalReadBound (physicalBranchesFintype)
open SmzaRp05PhysicalAcceptedReplayLite (Branches physicalRun branchResult)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords)
open SmzaRp04StatementRecordFilter (oneStatementFilter)
open SmzaRp05FilteredReadback (globalLeafStatement)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8SmzaOracleParser (RawDigest)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 16000
set_option maxHeartbeats 1600000
set_option linter.unusedSectionVars false
set_option exponentiation.threshold 1024

attribute [local irreducible]
  HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates.currentDsl

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

def actualProgram
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32)) : Program Unit :=
  producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire

def collision
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32)) :
    Work (Counter := GroupCounter) (BaseWork := BaseWork) →
      Database (Key (actualProgram producer ns statement pending nonce))
        (VectorOutput GroupCounter) → Prop :=
  fun _ database => ¬ SmzaRecordedTracePath.RecordsCollisionFree
    (oneStatementFilter (globalLeafStatement ns) statement.toBytes
      (eraseChallengeRecords (rawRecords
        (fun key => groupRepresentative
          (included (actualProgram producer ns statement pending nonce) key))
        (vectorOutputBytes groupZero) database)))

/-- The current accepted-invalid branch mass is covered by literal X-view
selectors, one original collision event, and missing nonchallenge claims.
All terms use exactly the same physical branch and incoming state. -/
theorem actual_accepted_failure_mass_le_selector_collision_missing
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? statement = some typed)
    (noPackedWitness : ¬ ∃ packed,
      SmzaRp05Components.program.AcceptsPacked (encodePublicStatement typed) packed)
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
        normSquared (physicalRun (encode program) groupedDecode program branch initial)
      else 0) ≤
    (∑ branch : Branches groupedDecode program,
      (normSquared (workspaceEventProjection
        (collision producer ns statement pending nonce)
        (physicalRun (encode program) groupedDecode program branch initial)) +
      (∑ role : Role,
        normSquared (workspaceEventProjection
          (fun work database => currentAcceptedXViewRoleSelector producer ns statement
            pending nonce fallback typed parsed noPackedWitness fuel enough ctx
            (by intro key; rfl) role branch
            (xView (nonchallengeRawKeySet ctx) database) work)
          (physicalRun (encode program) groupedDecode program branch initial))) +
      normSquared (databaseEventProjection
        (fun database => ¬ ClaimsDatabaseEvent
          (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode
            program branch) database)
        (physicalRun (encode program) groupedDecode program branch initial)))) := by
  classical
  let program := actualProgram producer ns statement pending nonce
  let ctx := currentGroupedContext (BaseWork := BaseWork) program model bounded
    ns .decsMatrix advice outerFuel innerFuel (fun _ => ∅)
  letI := physicalBranchesFintype groupedDecode program
  dsimp only
  apply Finset.sum_le_sum
  intro branch _
  have covered : ∀ basis : Basis (Key program) (VectorOutput GroupCounter)
      (VectorOutput GroupCounter) (Work (Counter := GroupCounter) (BaseWork := BaseWork)),
      physicalRun (encode program) groupedDecode program branch initial basis ≠ 0 →
      branchResult groupedDecode program branch = some () →
      ClaimsDatabaseEvent
        (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch)
        basis.database →
      collision producer ns statement pending nonce basis.workspace basis.database ∨
        ∃ role, currentAcceptedXViewRoleSelector producer ns statement pending nonce
          fallback typed parsed noPackedWitness fuel enough ctx (by intro key; rfl)
          role branch (xView (nonchallengeRawKeySet ctx) basis.database) basis.workspace := by
    intro basis supported accepted recorded
    have massNonzero : normSquared
        (physicalRun (encode program) groupedDecode program branch initial) ≠ 0 := by
      intro zeroMass
      have oneTerm : Complex.normSq
          (physicalRun (encode program) groupedDecode program branch initial basis) ≤
          normSquared (physicalRun (encode program) groupedDecode program branch initial) :=
        Finset.single_le_sum (fun _ _ => Complex.normSq_nonneg _) (Finset.mem_univ basis)
      have normZero : Complex.normSq
          (physicalRun (encode program) groupedDecode program branch initial basis) = 0 := by
        rw [zeroMass] at oneTerm
        exact le_antisymm oneTerm (Complex.normSq_nonneg _)
      exact supported (Complex.normSq_eq_zero.mp normZero)
    exact accepted_nonchallenge_consistent_branch_has_selector_or_collision
      producer ns statement pending nonce fallback typed parsed noPackedWitness fuel enough
      branch accepted ctx (by intro key; rfl) initial massNonzero basis.database recorded
      basis.workspace
  have bound := accepted_branch_mass_le_selector_collision_missing (Index := Role)
    (branchResult groupedDecode program branch = some ())
    (physicalRun (encode program) groupedDecode program branch initial)
    (branchNonchallengeClaims ctx.keyBytes (encode program) groupedDecode program branch)
    (collision producer ns statement pending nonce)
    (fun role work database => currentAcceptedXViewRoleSelector producer ns statement
      pending nonce fallback typed parsed noPackedWitness fuel enough ctx
      (by intro key; rfl) role branch
      (xView (nonchallengeRawKeySet ctx) database) work) covered
  simpa only [program, ctx] using bound

/-- The collision projection in the preceding actual branch split is
charged on its original state. Fixed-coordinate totality is derived from
the initialized ordinary execution, not supplied as a certificate. -/
theorem ordinary_original_collision_mass_le_fiber_sum
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (role : Role) (advice : AllEarlierTables model role)
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
    (dummy : ActiveKey role blockCap
      (currentGroupedContext (BaseWork := BaseWork)
        (actualProgram producer ns statement pending nonce) model bounded
        ns role advice outerFuel innerFuel (fun _ => ∅)).keyBytes) :
    let program := actualProgram producer ns statement pending nonce
    let ctx := currentGroupedContext (BaseWork := BaseWork) program model bounded
      ns role advice outerFuel innerFuel (fun _ => ∅)
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    letI := physicalBranchesFintype groupedDecode program
    (∑ branch : Branches groupedDecode program,
      normSquared (workspaceEventProjection (collision producer ns statement pending nonce)
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
  let program := actualProgram producer ns statement pending nonce
  let ctx := currentGroupedContext (BaseWork := BaseWork) program model bounded
    ns role advice outerFuel innerFuel (fun _ => ∅)
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
  letI := physicalBranchesFintype groupedDecode program
  dsimp only
  apply Finset.sum_le_sum
  intro branch _
  exact original_statement_erased_collision_mass_le_current_filtered_fibers
    ctx blockCap dummy cap statement.toBytes (fun _ => rfl)
    (physicalRun (encode program) groupedDecode program branch initial)
    (ordinary_physical_branch_fixed_other_total ordinaryProgram registers
      (encode program) groupedDecode program branch ctx blockCap)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedOrdinaryMassBound
