import SmzaRp05CurrentHistoryFailureMass
import SmzaRp05CurrentHistoryFailureEventScalarBridge
import SmzaRp05CurrentOrdinaryInitializedLedger
import SmzaRp05CurrentOrdinarySoundnessFinalBound
import SmzaRp05CurrentProtocolModelBound
import SmzaRp05CurrentAcceptedSoundnessEndpoint
import SmzaRp05SourceReadSchedule
import SmzaRp05OriginalBornOutcomeMass

/-! # One initialized extraction-loss bound for the actual verifier history

The history-stage index stays existential inside the four role selectors.
This consumer does not sum individual transaction bounds. Its public premises
are the actual parsed statements, initialized ordinary execution and lifetime
query schedule, not extraction, probability or coverage certificates.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryExtractionFailureEndpoint

open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge (workspaceEventProjection)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRp05CurrentAdaptiveExecution (Work)
open SmzaRp05ConditionedExecution
  (FixedTable ActiveMemory fixedFiberToActive otherRoleTransform activeMemoryEquiv)
open SmzaRoleDomainConditioning (ActiveKey unrecognized_is_active)
open SmzaRp05CurrentHistoryVerifierProgram (HistoryStage historyProgram)
open SmzaRp05CurrentHistoryFailureMass
  (emptyHistoryAdvice historyContext historyFailureEvent
    history_failure_projection_mass_le_scalar_lhs)
open SmzaRp05CurrentHistoryFailureCoverage (currentHistoryFailureRoleSelector)
open SmzaRp05CurrentHistoryFailureEventScalarBridge
  (history_failure_role_support_implies_current_advice_event_or_missing_claims)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05CurrentSelectedChallengeClaims
  (nonchallengeRawKeySet recognizedActiveChallengeClaims)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix GroupCounter GroupComplement groupEncode groupKeyOf
    groupRepresentative groupAddress groupZero group_address_complement)
open SmzaRp05ActualEventRecertification (event)
open SmzaRp05OrdinarySoundnessExecution
  (OrdinaryPrefix ordinaryRun emptyAuthorizationContexts)
open SmzaRp05AdaptivePhysicalReadBound
  (ReadsAtMost ReadsWithinKeys physicalBranchesFintype)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult physicalRun)
open SmzaRp05ConcreteSuffix (PhysicalInput protocolBlockCap)
open SmzaRp05RelationRefinement (relationModel GeneratedCertificates)
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
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8SmzaOracleParser (RawDigest)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification (V8PublicStatement)
open SmzaRp05CurrentAdviceDependentPhysicalMass (currentAdviceEventSpec)

attribute [local irreducible] SmzaRp05GeneratedCertificates.currentDsl

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 18000
set_option maxHeartbeats 1600000
set_option linter.unusedSectionVars false

private theorem group_encode_ne_empty (key : CanonicalRolePrefix × GroupCounter) :
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

private def historyFallbackKey (stages : List HistoryStage) : Key (historyProgram stages) :=
  ⟨groupKeyOf ([] : PhysicalInput), Finset.mem_insert_self _ _⟩

/-- A single bound on accepted extraction failure anywhere in the original
history. There is no transaction-count multiplier and no supplied inclusion
or probability premise. -/
theorem actual_accepted_history_extraction_failure_mass_below_130_bits
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (typed : ∀ _i : Fin stages.length, V8PublicStatement)
    (parsed : ∀ i : Fin stages.length,
      parseCurrentPublicStatement? (stages[i.val]).statement = some (typed i))
    (fallback : RawDigest)
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix (Key := Key (historyProgram stages))
      (Counter := GroupCounter) (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key (historyProgram stages))
      (Phase := VectorOutput GroupCounter)
      (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ)
    (incomingUnit : normSquared
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers) = 1)
    (queriesWithin : queries + readBudget groupedDecode (historyProgram stages) ≤ cap)
    (capBound : cap ≤ 3 * 2 ^ 64) :
    let program := historyProgram stages
    let model := relationModel currentDsl SmzaRp05GeneratedCertificates.certificates
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    letI := physicalBranchesFintype groupedDecode program
    (∑ branch : Branches groupedDecode program,
      if branchResult groupedDecode program branch = some () then
        normSquared (workspaceEventProjection
          (fun _work database => historyFailureEvent (BaseWork := BaseWork)
            stages commonNs stageNsEq fallback typed 28 model
            current_model_within_protocol branch database)
          (physicalRun (encode program) groupedDecode program branch initial))
      else 0) < ((1 / (2 : Rat)^130 : Rat) : ℝ) := by
  classical
  let program := historyProgram stages
  let certificates : GeneratedCertificates currentDsl := SmzaRp05GeneratedCertificates.certificates
  let model := relationModel currentDsl certificates
  let bounded := current_model_within_protocol
  let contexts := historyContext (BaseWork := BaseWork) stages model bounded commonNs
  let roleCtx := fun role => emptyAuthorizationContexts contexts role
  let blockCap : Role → Nat := protocolBlockCap
  obtain ⟨positiveDecsMatrixCap, positivePiopMatrixCap, positivePiopOpeningCap⟩ :=
    current_protocol_positive_caps
  let dummy : ∀ role : Role, ActiveKey (roleCtx role).role blockCap
      (roleCtx role).keyBytes := by
    intro role
    refine ⟨historyFallbackKey stages, ?_⟩
    apply unrecognized_is_active
    change parseStageQuery (groupRepresentative
      (included program (historyFallbackKey stages))) = none
    simpa [historyFallbackKey, included] using empty_group_key_representative_unparsed
  let select := fun (role : Role) branch view
      (_work : Work (Counter := GroupCounter) (BaseWork := BaseWork)) =>
    currentHistoryFailureRoleSelector (BaseWork := BaseWork) stages commonNs stageNsEq
      model bounded (emptyHistoryAdvice model) fallback 28 branch role view
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
    simpa using SmzaRp05CurrentAcceptedSoundnessEndpoint.ordinaryPrefix_finish_eq_start_add_queries
      ordinaryProgram
  have queriesWithinDepth : queries + depth ≤ cap := queriesWithin
  have supportWithin : finish + depth ≤ cap := by rw [finishEq]; exact queriesWithinDepth
  have included :
      ∀ (role : Role) (branch : Branches groupedDecode program)
        (fixed : FixedTable (roleCtx role) blockCap)
        (basis : Basis (ActiveKey (roleCtx role).role blockCap (roleCtx role).keyBytes)
          (VectorOutput GroupCounter) (VectorOutput GroupCounter) (ActiveMemory (roleCtx role))),
      selectedRoleState (roleCtx role) blockCap (encode program) groupedDecode program branch fixed
        (fixedFiberToActive (roleCtx role) blockCap (dummy role) fixed
          (otherRoleTransform (roleCtx role) blockCap initial)) (select role branch) basis ≠ 0 →
      event (currentAdviceEventSpec (roleCtx role) blockCap fixed cap)
          (activeMemoryEquiv (roleCtx role) basis.workspace) basis.database ∨
        ¬ ClaimsDatabaseEvent (recognizedActiveChallengeClaims (roleCtx role) blockCap
          (encode program) groupedDecode program branch) basis.database := by
    intro role branch fixed basis selectedNonzero
    exact history_failure_role_support_implies_current_advice_event_or_missing_claims
      (BaseWork := BaseWork) stages commonNs stageNsEq certificates bounded fallback
      blockCap positiveDecsMatrixCap positivePiopMatrixCap positivePiopOpeningCap
      branch role fixed (dummy role) initial basis cap selectedNonzero
  have massBound := history_failure_projection_mass_le_scalar_lhs
    (BaseWork := BaseWork) stages commonNs stageNsEq typed parsed fallback 28 (by decide)
    model bounded ordinaryProgram registers blockCap cap dummy
  have scalarBound := ordinary_selected_readout_collision_scalar_bound contexts ordinaryProgram
    registers depth (encode program) groupedDecode program readBound keys keysWithin supportWithin
    queriesWithin blockCap dummy select included
  have numericBound := ordinary_scalar_rhs_below_130 ordinaryProgram registers depth incomingUnit
    capBound queriesWithinDepth
  exact lt_of_le_of_lt (le_trans massBound scalarBound) numericBound

/-- The same initialized history bound on the literal original branch/basis
outcome carrier used by the ledger and induced-game consumers. No arbitrary
mass function, successful-selector premise or acceptance renormalization is
an argument. -/
theorem actual_accepted_history_extraction_outcome_mass_below_130_bits
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (typed : ∀ _i : Fin stages.length, V8PublicStatement)
    (parsed : ∀ i : Fin stages.length,
      parseCurrentPublicStatement? (stages[i.val]).statement = some (typed i))
    (fallback : RawDigest)
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix (Key := Key (historyProgram stages))
      (Counter := GroupCounter) (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key (historyProgram stages))
      (Phase := VectorOutput GroupCounter)
      (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ)
    (incomingUnit : normSquared
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers) = 1)
    (queriesWithin : queries + readBudget groupedDecode (historyProgram stages) ≤ cap)
    (capBound : cap ≤ 3 * 2 ^ 64) :
    let program := historyProgram stages
    let model := relationModel currentDsl SmzaRp05GeneratedCertificates.certificates
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    letI := physicalBranchesFintype groupedDecode program
    SmzaRp05CurrentAuthorizationCertificate.outcomeEventMass
      (SmzaRp05OriginalBornOutcomeMass.originalOutcomeWeight
        (fun branch => physicalRun (encode program) groupedDecode program branch initial))
      (fun outcome => branchResult groupedDecode program outcome.1 = some () ∧
        historyFailureEvent (BaseWork := BaseWork) stages commonNs stageNsEq
          fallback typed 28 model current_model_within_protocol
          outcome.1 outcome.2.database) < ((1 / (2 : Rat)^130 : Rat) : ℝ) := by
  classical
  let program := historyProgram stages
  let model := relationModel currentDsl SmzaRp05GeneratedCertificates.certificates
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
  letI := physicalBranchesFintype groupedDecode program
  change SmzaRp05CurrentAuthorizationCertificate.outcomeEventMass
    (SmzaRp05OriginalBornOutcomeMass.originalOutcomeWeight
      (fun branch => physicalRun (encode program) groupedDecode program branch initial))
    (fun outcome => branchResult groupedDecode program outcome.1 = some () ∧
      historyFailureEvent (BaseWork := BaseWork) stages commonNs stageNsEq
        fallback typed 28 model current_model_within_protocol
        outcome.1 outcome.2.database) < ((1 / (2 : Rat)^130 : Rat) : ℝ)
  rw [SmzaRp05OriginalBornOutcomeMass.original_accepted_event_mass_eq_projection_sum
    (fun branch => physicalRun (encode program) groupedDecode program branch initial)
    (fun branch => branchResult groupedDecode program branch = some ())
    (fun branch _work database => historyFailureEvent (BaseWork := BaseWork)
      stages commonNs stageNsEq fallback typed 28 model
      current_model_within_protocol branch database)]
  simpa only [program, model, initial] using
    actual_accepted_history_extraction_failure_mass_below_130_bits
    stages commonNs stageNsEq typed parsed fallback ordinaryProgram registers
    incomingUnit queriesWithin capBound

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryExtractionFailureEndpoint
