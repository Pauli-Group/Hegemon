import SmzaRp05CurrentAcceptedExtractionFailureMass
import SmzaRp05CurrentAcceptedDecsExtractionFailureEvent
import SmzaRp05CurrentFullOrRoleExtraction
import SmzaRp05CurrentFullOrRoleXViewCoverage
import SmzaRp05CurrentOrdinaryInitializedLedger
import SmzaRp05CurrentOrdinarySoundnessFinalBound
import SmzaRp05CurrentProtocolModelBound
import SmzaRp05SourceReadSchedule
import SmzaRp05CurrentAcceptedSoundnessEndpoint

/-! # Current accepted full-extraction failure endpoint

This endpoint bounds failure of the designated full-extraction selector on
the same accepted physical branch and its own nonchallenge X-view. The
four-role guard-free dispatcher supplies event inclusion pointwise; the
ordinary scalar ledger supplies the numeric threshold. No extraction witness,
event-coverage, or probability premise is accepted from the caller.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedExtractionFailureEndpoint

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
open SmzaRp05CurrentAcceptedMassToScalar
  (currentAcceptedMassContexts)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05CurrentAcceptedDecsExtractionFailureEvent
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
open SmzaRp05CurrentFullOrRoleExtraction (currentAcceptedXViewFailureRoleSelector)
open SmzaRp05CurrentFullOrRoleXViewCoverage (currentAcceptedXViewFullSuccessSelector)
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
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? statement = some typed)
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
    (capBound : cap ≤ 3 * 2 ^ 64) :
    let program := actualProgram producer ns statement pending nonce
    let contexts := currentAcceptedMassContexts (BaseWork := BaseWork)
      producer ns statement pending nonce (relationModel currentDsl
        SmzaRp05GeneratedCertificates.certificates)
      current_model_within_protocol (fun _ => fun _ _ _ _ => none) 28 28
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    let ctx := contexts .decsMatrix
    letI := physicalBranchesFintype groupedDecode program
    (∑ branch : Branches groupedDecode program,
      if branchResult groupedDecode program branch = some () then
        normSquared (workspaceEventProjection
          (fun _work database => ¬ currentAcceptedXViewFullSuccessSelector
            producer ns statement pending nonce fallback typed 28 ctx branch
            (xView (nonchallengeRawKeySet ctx) database))
          (physicalRun (encode program) groupedDecode program branch initial))
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
  let select := fun (role : Role) branch view (_work : Work
      (Counter := GroupCounter) (BaseWork := BaseWork)) =>
    currentAcceptedXViewFailureRoleSelector producer ns statement pending nonce fallback 28
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
      (BaseWork := BaseWork) producer ns statement pending nonce fallback
      certificates bounded blockCap positiveDecsMatrixCap positivePiopMatrixCap
      positivePiopOpeningCap role branch fixed (dummy role) initial basis cap
      selectedNonzero
  have massBound :=
    SmzaRp05CurrentAcceptedExtractionFailureMass.accepted_failure_projection_mass_le_scalar_lhs
      (BaseWork := BaseWork) producer ns statement pending nonce fallback typed parsed
      28 (by decide) model bounded advice 28 28 ordinaryProgram registers blockCap dummy
  have scalarBound := ordinary_selected_readout_collision_scalar_bound
    contexts ordinaryProgram registers depth (encode program) groupedDecode program
    readBound keys keysWithin supportWithin queriesWithin blockCap dummy select included
  have numericBound := ordinary_scalar_rhs_below_130
    ordinaryProgram registers depth incomingUnit capBound queriesWithinDepth
  exact lt_of_le_of_lt (le_trans massBound scalarBound) numericBound

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedExtractionFailureEndpoint
