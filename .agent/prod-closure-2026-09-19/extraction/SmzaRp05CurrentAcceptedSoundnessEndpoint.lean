import SmzaRp05CurrentAcceptedMassToScalar
import SmzaRp05CurrentAcceptedSelectedEventInclusion
import SmzaRp05CurrentOrdinaryInitializedLedger
import SmzaRp05CurrentOrdinarySoundnessFinalBound
import SmzaRp05CurrentProtocolModelBound
import SmzaRp05SourceReadSchedule

/-! # Actual accepted-invalid soundness endpoint

The endpoint composes the literal accepted-branch mass split, the four-role
selected-support event dispatcher, and the initialized ordinary scalar
ledger. It takes structural execution/budget inputs and input normalization;
it does not accept event coverage or a probability/loss bound as an input.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSoundnessEndpoint

open SmzaRp05OrdinarySoundnessExecution (OrdinaryPrefix)
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open SmzaChallengeStageTargets (Role)
open SmzaRp05CurrentAdaptiveExecution (Work)
open SmzaRp05ConditionedExecution
  (FixedTable fixedFiberToActive otherRoleTransform activeMemoryEquiv ActiveMemory)
open SmzaRoleDomainConditioning (ActiveKey unrecognized_is_active)
open SmzaRp05CurrentAcceptedOrdinaryMassBound (actualProgram)
open SmzaRp05CurrentAcceptedMassToScalar
  (currentAcceptedMassContexts currentAcceptedMassSelector
    actual_accepted_branch_mass_le_scalar_lhs)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05CurrentAcceptedSelectedEventInclusion
  (grouped_selected_support_implies_event_or_missing_claims)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05CurrentSelectedChallengeClaims (recognizedActiveChallengeClaims)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode)
open SmzaRp05CurrentFiniteGroupedProgram (included)
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
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05ConcreteSuffix (protocolBlockCap)
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
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8SmzaOracleParser (RawDigest)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
  (V8PublicStatement encodePublicStatement)
open SmzaChallengeStageTargets (parseStageQuery)
open SmzaRp05ConcreteSuffix (PhysicalInput)
open SmzaRp05CurrentAdviceDependentPhysicalMass (currentAdviceEventSpec)

attribute [local irreducible]
  HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates.currentDsl

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 16000
set_option maxHeartbeats 1600000
set_option linter.unusedSectionVars false

/-- The ordinary schedule's terminal occupied position is its initial
position plus the number of oracle-query constructors. Database-independent
gates preserve the position, while each query constructor advances it once. -/
theorem ordinaryPrefix_finish_eq_start_add_queries
    {KeyType CounterType BaseWork : Type}
    [Fintype KeyType] [DecidableEq KeyType]
    [Fintype CounterType] [DecidableEq CounterType]
    [Fintype BaseWork] [DecidableEq BaseWork]
    {cap start finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix (Key := KeyType) (Counter := CounterType)
      (BaseWork := BaseWork) (cap := cap) start finish queries) :
    finish = start + queries := by
  induction ordinaryProgram with
  | nil budget => simp
  | query occupied room remaining ih =>
      simpa [Nat.add_assoc] using ih
  | privateGate budget within step remaining ih =>
      exact ih

private theorem group_encode_ne_empty
    (key : CanonicalRolePrefix × GroupCounter) :
    groupEncode key ≠ ([] : PhysicalInput) := by
  rcases key with ⟨rolePrefix, counter⟩
  have encodedLength : (groupEncode (rolePrefix, counter)).length =
      rolePrefix.leading.length + 8 := by
    simp [groupEncode,
      V8Smz9RawCounterCompiler.counterInput,
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

/-- The actual verifier's accepted-invalid branch mass is below the ordinary
130-bit ledger threshold. The current-advice inclusion is derived pointwise
from the same accepted execution and selected fibers inside this theorem. -/
theorem actual_accepted_invalid_branch_mass_below_130_bits
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? statement = some typed)
    (noPackedWitness : ¬ ∃ packed,
      SmzaRp05Components.program.AcceptsPacked (encodePublicStatement typed) packed)
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix
      (Key := Key (actualProgram producer ns statement pending nonce))
      (Counter := GroupCounter) (BaseWork := BaseWork)
      (cap := cap) 0 finish queries)
    (registers : RegisterBasis
      (Input := Key (actualProgram producer ns statement pending nonce))
      (Phase := VectorOutput GroupCounter)
      (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ)
    (incomingUnit : normSquared
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers) = 1)
    (queriesWithin : queries + readBudget groupedDecode
      (actualProgram producer ns statement pending nonce) ≤ cap)
    (capBound : cap ≤ 3 * 2 ^ 64)
    :
    let program := actualProgram producer ns statement pending nonce
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    letI := physicalBranchesFintype groupedDecode program
    (∑ branch : Branches groupedDecode program,
      if branchResult groupedDecode program branch = some () then
        normSquared (physicalRun (encode program) groupedDecode program branch initial)
      else 0) < ((1 / (2 : Rat)^130 : Rat) : ℝ) := by
  classical
  let program := actualProgram producer ns statement pending nonce
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
  let contexts := currentAcceptedMassContexts (BaseWork := BaseWork)
    producer ns statement pending nonce model bounded advice 28 28
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
  let select := currentAcceptedMassSelector (BaseWork := BaseWork)
    producer ns statement pending nonce fallback typed parsed noPackedWitness
    28 (by decide) model bounded advice 28 28
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
    simpa using ordinaryPrefix_finish_eq_start_add_queries ordinaryProgram
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
    exact grouped_selected_support_implies_event_or_missing_claims
      (BaseWork := BaseWork) producer ns statement pending nonce fallback typed
      parsed noPackedWitness certificates bounded blockCap
      positiveDecsMatrixCap positivePiopMatrixCap positivePiopOpeningCap
      branch role fixed (dummy role) initial basis cap selectedNonzero
  have massBound := actual_accepted_branch_mass_le_scalar_lhs
    (BaseWork := BaseWork) producer ns statement pending nonce fallback typed
    parsed noPackedWitness 28 (by decide) model bounded advice 28 28
    ordinaryProgram registers blockCap dummy
  have scalarBound := ordinary_selected_readout_collision_scalar_bound
    contexts ordinaryProgram registers depth (encode program) groupedDecode program
    readBound keys keysWithin supportWithin queriesWithin blockCap dummy select included
  have numericBound := ordinary_scalar_rhs_below_130
    ordinaryProgram registers depth incomingUnit capBound queriesWithin
  exact lt_of_le_of_lt (le_trans massBound scalarBound) numericBound

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSoundnessEndpoint
