import SmzaRp05CurrentAcceptedPiopExtractionFailureEvent
import SmzaRp05CurrentFullOrRoleExtraction
import SmzaRp05CurrentAcceptedMatrixFailureEvent
import SmzaRp05ConditionedExecution
import SmzaRp05CurrentAdviceDependentPhysicalMass
import SmzaRp05CurrentAcceptedXViewRoleCoverage
import SmzaRp05CurrentSelectedXViewClaims
import SmzaRp05CurrentSelectedCurrentAdviceEventMass
import SmzaRp05CurrentSelectedChallengeClaims
import SmzaRp05CurrentGroupedContext
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05Current406ActiveFiberEvent
import SmzaRp05Current406EventSpec
import SmzaRp05CurrentMatrixRoleEvent
import SmzaRp05CurrentSourceRoleEvent
import SmzaRp05CurrentAcceptedDecsSampleOutputBinding
import SmzaRp05CurrentAcceptedQuerySupport
import SmzaRp05CurrentAcceptedDecsSourceEvent
import SmzaRp05CurrentAcceptedDecsSourceCoverage
import SmzaRp05CurrentAcceptedFilteredCausalSourceBad
import SmzaRp05CurrentAcceptedFilteredCausalRetention
import SmzaRp05CurrentAcceptedFixedEarlierCells
import SmzaRp05AdaptiveRetainedAdviceTransport
import SmzaRp05CurrentExecutedEarlierAdvice
import SmzaRp05CurrentAcceptedCausalPayloads
import SmzaRp05CurrentAcceptedCausalPayloadIdentity
import SmzaRp05CurrentCausalNonchallengeRetention
import SmzaRp05CurrentAcceptedNonleafRoleReadback
import SmzaRp05CurrentAcceptedFilteredRoleTraces
import SmzaRp05CurrentExecutedSamplerSemantics
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05CurrentGroupedRoutes
import SmzaRp05CurrentRoleLabels
import SmzaRp05ChallengeRecordErasure
import SmzaRp04StatementRecordFilter
import SmzaRp05FilteredReadback
import SmzaRp05FilteredDecoderInstability
import SmzaRp05CurrentTracePrefixes406
import SmzaRp05AcceptedRoleLabels
import SmzaRp05CertifiedReplayScheduleFrames
import SmzaRp05CurrentAcceptedRoleQueryReadback
import SmzaRp05ExecutableChallengeStage
import SmzaRp05FilteredDecoderInstability
import SmzaRp05ExecutablePcsClosureClean
import SmzaRp05ExecutablePcsClosureSampling
import SmzaRp05OrdinarySoundnessExecution
import SmzaRp05GeneratedCertificates

/-! # Selected accepted-execution support inside the current advice event

This module starts the four-role inclusion at the same accepted physical
branch and selected fixed fiber used by the scalar endpoint. The event-side
advice is constructed from that fixed fiber; the placeholder context advice
is not used as a classifier premise.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsExtractionFailureEvent

open scoped Classical
open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CanonicalBytes (encodeLE)
open HegemonCrypto.CmsCompressedOracle (Basis)
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge (workspaceEventProjection)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaChallengeStageTargets (Role)
open SmzaRoleDomainConditioning (ActiveKey)
open SmzaRp05ConditionedExecution
  (ActiveState FixedTable XKey fixedFiberToActive otherRoleTransform mergeFixedActive
    activeXView)
open SmzaRp05CurrentAdaptiveExecution (Context)
open SmzaRp05CurrentAdaptiveExecution (CmsState)
open SmzaRp05ActualEventRecertification (event)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05RelationRefinement (relationModel GeneratedCertificates)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05ExecutableChallengeStage (counterInput)
open HegemonCrypto.SmallWoodTranscript (decsFixedSamplingDomain)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative groupZero)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05CurrentSelectedChallengeClaims
  (recognizedActiveChallengeClaims nonchallengeRawKeySet
    nonchallenge_raw_key_set_unrecognized)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05CurrentFullOrRoleExtraction (currentAcceptedXViewFailureRoleSelector)
open SmzaRp05CurrentAcceptedPiopExtractionFailureEvent
  (grouped_piop_failure_support_implies_current_advice_event_or_missing_claims)
open SmzaRp05CurrentAcceptedPiopExtractionFailureEvent
  (selected_xview_failure_role_replays_on_completion)
open SmzaRp05CurrentSelectedXViewClaims (selected_support_supplies_full_branch_claims)
open SmzaRp05CurrentAdviceDependentPhysicalMass (currentAdviceEventSpec)
open SmzaRp05CurrentAdviceDependentPhysicalMass
  (currentAdviceActiveContext currentAdviceContextAtFixed)
open SmzaRp05CurrentFixedEarlierAdvice (currentFixedAdvice)
open SmzaRp05CurrentAcceptedFixedEarlierReadback
  (currentFixedEarlierAdviceFamily currentFixedEarlierAdviceFamily_active)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05Current406ActiveFiberEvent (current406_base_merged_iff_active)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys branchAnswers branchClaims branchResult physicalRun)
open SmzaRp05CurrentGroupedClaimRetention
  (actual_program_grouped_claims_replay_and_retain)
open SmzaRp05CurrentAcceptedMatrixFailureEvent
  (accepted_execution_matrix_bad_yields_role_event)
open SmzaRp05Current406EventSpec (current406Base current406EventSpec)
open SmzaRp05CurrentMatrixRoleEvent (currentMatrixRoleEvent406)
open SmzaRp05CurrentSourceRoleEvent (currentSourceMatrixRoleEvent406)
open SmzaRp05CurrentSourceRoleEvent (currentSourceRoleEvent406)
open SmzaRp05CurrentAcceptedDecsSampleOutputBinding
  (accepted_current_decs_sample_output_binding)
open SmzaRp05CurrentAcceptedQuerySupport (Position Query)
open SmzaRp05CurrentAcceptedDecsSourceEvent (source_bad_on_same_causal_trace_yields_event)
open SmzaRp05CurrentAcceptedDecsSourceCoverage
  (source_bad_on_same_trace_yields_event_of_family)
open SmzaRp05CurrentAcceptedFilteredCausalSourceBad
  (filtered_classifier_source_bad_to_causal)
open SmzaRp05CurrentAcceptedFilteredCausalRetention
  (accepted_execution_supplies_filtered_causal_records)
open SmzaRp05CurrentAcceptedFixedEarlierCells
  (same_stage_fixed_decs_sample_earlier_readback same_stage_current_fixed_opening_scan)
open SmzaRp05AdaptiveRetainedAdviceTransport (physical_run_to_mixed_same_fiber)
open SmzaRp05CurrentExecutedEarlierAdvice (currentOracleAllAdvice)
open SmzaRp05AcceptedRoleLabels (EarlierReadback CausalPayloads)
open SmzaRp05CurrentCausalNonchallengeRetention
  (accepted_execution_causal_record_memberships)
open SmzaRp05CurrentAcceptedNonleafRoleReadback
  (accepted_stages_raw_nonleaf_outer_preambles)
open SmzaRp05CurrentAcceptedFilteredRoleTraces
  (current_stages_supply_filtered_role_traces currentOuterTarget)
open SmzaRp05CurrentExecutedSamplerSemantics
  (pcs_query_execution_exposes_clean_scan)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes)
open SmzaRp05CurrentRoleLabels (targetOfRaw preambleFromTrace)
open SmzaRp05CurrentSelectedChallengeClaims
  (branchXRoleSelector nonchallengeRawKeySet nonchallenge_raw_key_set_unrecognized)
open SmzaRp05ChallengeRecordErasure
  (eraseChallengeRecords global_extract_filtered_erase_challenge)
open SmzaRp04StatementRecordFilter (oneStatementFilter nonleafFilter keepOneStatement)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext)
open SmzaRp05CurrentTracePrefixes406 (currentSourceBad406 currentSourcePrefix406)
open SmzaRp05AcceptedRoleLabels (causalOracle causalTrace)
open SmzaRp05CertifiedReplaySchedule (ordinary_counter_roundtrip)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix groupKeyOf groupEncode groupAddress group_address_encode)
open SmzaRp05Current406EventSpec (currentRoleEvent406Explicit)
open SmzaRp05CurrentAcceptedXViewRoleCoverage (noWitnessRoleFailure)
open SmzaChallengeStageTargets (StageQuery parseStageQuery)
open V8Smz9AdaptiveFiniteAccounting (baseOpeningPoints)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9CoherentVectorMerkle (vectorOutputBytes)
open V8Smz9CoherentMerkleGeometry (extract)
open V8SmzaOracleParser (RawDigest)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification

attribute [local irreducible] SmzaRp05GeneratedCertificates.currentDsl

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1600000
set_option linter.unusedSectionVars false

local instance : DecidableEq V8SmzaOracleParser.RawInput :=
  SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq
local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

private def actualVerifierProgram (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) : Program Unit :=
  producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire

private def emptyInitialAdvice (model : RelationModel) (role : Role) :
    AllEarlierTables model role := fun _ _ _ _ => none

private def groupedRoleContext
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (model : RelationModel)
    (bounded : ModelWithinProtocol model) (role : Role) :
    Context (Key := Key (actualVerifierProgram producer ns statement pending nonce))
      (Counter := GroupCounter) (BaseWork := BaseWork) :=
  currentGroupedContext (actualVerifierProgram producer ns statement pending nonce)
    model bounded ns role (emptyInitialAdvice model role) 28 28 (fun _ => ∅)

private def groupedFailureSelector
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (fuel : Nat) (model : RelationModel) (bounded : ModelWithinProtocol model)
    (role : Role)
    (branch : Branches groupedDecode
      (actualVerifierProgram producer ns statement pending nonce)) :
    (view : XKey (nonchallengeRawKeySet
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        model bounded role)) →
        Option (VectorOutput GroupCounter)) →
      SmzaRp05CurrentAdaptiveExecution.Work (Counter := GroupCounter)
        (BaseWork := BaseWork) → Prop :=
  let ctx := groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
    model bounded role
  fun view _work => currentAcceptedXViewFailureRoleSelector producer ns statement pending nonce
    fallback fuel ctx role branch view

private theorem classifier_query_eq_executed_sample_query
    (indexes : List Nat)
    (coordinates : Fin 38 → SmzaRp05CurrentAcceptedQuerySupport.Position)
    (classified sampled : SmzaRp05CurrentAcceptedQuerySupport.Query)
    (indexesLength : indexes.length = 38)
    (coordinateIndexes : ∀ j : Fin 38,
      (coordinates j).val = indexes.getD j.val 0)
    (classifiedImage : classified.val = Finset.univ.image coordinates)
    (sampledImage : sampled.val.image Fin.val = indexes.toFinset) :
    classified = sampled := by
  classical
  have coordinateImage :
      Finset.univ.image (Fin.val ∘ coordinates) = indexes.toFinset := by
    ext value
    simp only [Finset.mem_image, Finset.mem_univ, true_and, List.mem_toFinset]
    constructor
    · rintro ⟨j, h⟩
      change (coordinates j).val = value at h
      rw [coordinateIndexes j] at h
      have bound : j.val < indexes.length := by rw [indexesLength]; exact j.isLt
      rw [List.getD_eq_getElem indexes 0 bound] at h
      exact h ▸ List.getElem_mem bound
    · intro member
      obtain ⟨i, bound, same⟩ := List.mem_iff_getElem.mp member
      let j : Fin 38 := ⟨i, by omega⟩
      refine ⟨j, ?_⟩
      change (coordinates j).val = value
      rw [coordinateIndexes j, List.getD_eq_getElem indexes 0 bound]
      simpa [j] using same
  have classifiedValueImage : classified.val.image Fin.val = indexes.toFinset := by
    rw [classifiedImage, Finset.image_image]
    simpa only [Function.comp_apply] using coordinateImage
  have sameValues : classified.val = sampled.val := by
    apply Finset.ext
    intro position
    constructor
    · intro member
      have mapped : position.val ∈ classified.val.image Fin.val :=
        Finset.mem_image.mpr ⟨position, member, rfl⟩
      have inIndexes : position.val ∈ indexes.toFinset := by
        simpa only [classifiedValueImage] using mapped
      have inSampleImage : position.val ∈ sampled.val.image Fin.val := by
        rw [sampledImage]
        exact inIndexes
      obtain ⟨other, otherMember, valueEq⟩ := Finset.mem_image.mp inSampleImage
      have equal : position = other := Fin.ext valueEq.symm
      simpa [equal] using otherMember
    · intro member
      have mapped : position.val ∈ sampled.val.image Fin.val :=
        Finset.mem_image.mpr ⟨position, member, rfl⟩
      have inIndexes : position.val ∈ indexes.toFinset := by
        rw [← sampledImage]
        exact mapped
      have inClassifiedImage : position.val ∈ classified.val.image Fin.val := by
        rw [classifiedValueImage]
        exact inIndexes
      obtain ⟨other, otherMember, valueEq⟩ := Finset.mem_image.mp inClassifiedImage
      have equal : position = other := Fin.ext valueEq.symm
      simpa [equal] using otherMember
  exact Subtype.ext sameValues

/-! The matrix constructor is the first role slice. Its bad-matrix arm is
read from the transferred same-database classifier, then the accepted matrix
event constructor recovers the literal counter-zero grouped cell and trace.
-/

theorem grouped_decs_matrix_failure_support_implies_current_advice_event_or_missing_claims
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (certificates : GeneratedCertificates currentDsl)
    (bounded : ModelWithinProtocol (relationModel currentDsl certificates))
    (blockCap : Role → Nat)
    (branch : Branches groupedDecode
      (actualVerifierProgram producer ns statement pending nonce))
    (fixed : FixedTable
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded .decsMatrix) blockCap)
    (dummy : ActiveKey .decsMatrix blockCap
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded .decsMatrix).keyBytes)
    (initial : CmsState
      (Key := Key (actualVerifierProgram producer ns statement pending nonce))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (basis : Basis (ActiveKey .decsMatrix blockCap
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded .decsMatrix).keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (SmzaRp05ConditionedExecution.ActiveMemory
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded .decsMatrix)))
    (cap : Nat)
    (support : selectedRoleState
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded .decsMatrix)
      blockCap (encode (actualVerifierProgram producer ns statement pending nonce))
      groupedDecode (actualVerifierProgram producer ns statement pending nonce)
      branch fixed
      (fixedFiberToActive
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded .decsMatrix)
        blockCap dummy fixed (otherRoleTransform
          (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
            (relationModel currentDsl certificates) bounded .decsMatrix)
          blockCap initial))
      (groupedFailureSelector (BaseWork := BaseWork) producer ns statement pending nonce fallback 28 (relationModel currentDsl certificates)
        bounded .decsMatrix branch) basis ≠ 0) :
    event (currentAdviceEventSpec
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded .decsMatrix)
      blockCap fixed cap)
      (SmzaRp05ConditionedExecution.activeMemoryEquiv
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded .decsMatrix) basis.workspace)
      basis.database ∨
    ¬ ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded .decsMatrix)
        blockCap (encode (actualVerifierProgram producer ns statement pending nonce))
        groupedDecode (actualVerifierProgram producer ns statement pending nonce) branch)
      basis.database := by
  classical
  let model := relationModel currentDsl certificates
  let program := actualVerifierProgram producer ns statement pending nonce
  let ctx := groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce model bounded .decsMatrix
  let select := groupedFailureSelector (BaseWork := BaseWork) producer ns statement pending nonce fallback 28 model bounded .decsMatrix branch
  let fiberInitial := fixedFiberToActive ctx blockCap dummy fixed
    (otherRoleTransform ctx blockCap initial)
  by_cases challengeClaims : ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims ctx blockCap (encode program) groupedDecode program branch)
      basis.database
  · have evidence := selected_xview_failure_role_replays_on_completion
      producer ns statement pending nonce fallback 28
      ctx blockCap (by intro key; rfl) branch fixed
      fiberInitial basis challengeClaims support
    rcases evidence with ⟨recordsCollisionFree, wire, transcript, producerSuccess,
      verifierAccepted, transcriptSuccess, execution, pcs, coordinates, query, input,
      ordered, image, indexes, inputRecord, hashRecord, currentOutcome, labelOutcome,
      roleFailure⟩
    have selectedJoin := selected_support_supplies_full_branch_claims ctx blockCap
      (encode program) groupedDecode program branch fixed
      fiberInitial select basis support challengeClaims
    have mergedClaims := selectedJoin.2.1
    let completed := mergeFixedActive ctx blockCap fixed basis.database
    let oracle := finiteGroupedDatabaseOracle program completed fallback
    have claims : ClaimsDatabaseEvent
        (branchClaims (branchKeys (encode program) groupedDecode program branch)
          (branchAnswers (encode program) groupedDecode program branch)) completed := by
      simpa only [completed] using mergedClaims
    have actualRecord := actual_program_grouped_claims_replay_and_retain
      program branch completed claims fallback
    have actualSuccess : program.eval oracle = some () := by
      change (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire).eval
        oracle = some ()
      change producer.eval oracle = some wire at producerSuccess
      change (verifierProgram ns currentDsl statement pending nonce wire).eval oracle = some ()
        at verifierAccepted
      rw [Program.eval_bind, producerSuccess]
      exact verifierAccepted
    have accepted : branchResult groupedDecode program branch = some () := by
      have recordResult : (program.record oracle).1 = branchResult groupedDecode program branch :=
        congrArg Prod.fst actualRecord.1
      calc
        branchResult groupedDecode program branch = (program.record oracle).1 := recordResult.symm
        _ = program.eval oracle := Program.record_result oracle program
        _ = some () := actualSuccess
    have noWitness : noWitnessRoleFailure .decsMatrix ns statement pending nonce wire
        oracle transcript execution pcs
        (eraseChallengeRecords (rawRecords
          (fun key => groupRepresentative (included program key))
          (vectorOutputBytes groupZero) completed)) 28 input query := by
      have ctxRole : ctx.role = .decsMatrix := rfl
      rw [← ctxRole]
      simpa only [oracle, completed, program, actualVerifierProgram] using roleFailure
    dsimp only [noWitnessRoleFailure] at noWitness
    have matrixBad := noWitness
    have roleEvent := accepted_execution_matrix_bad_yields_role_event
      producer ns currentDsl statement pending nonce branch accepted completed claims
      fallback model bounded (currentFixedAdvice ctx blockCap fixed)
      28 28 (by decide) (by decide) ∅ (by simp) wire transcript execution pcs
      producerSuccess verifierAccepted transcriptSuccess recordsCollisionFree matrixBad
    let adjusted := { ctx with advice := currentFixedAdvice ctx blockCap fixed }
    have baseAccepted : current406Base adjusted ∅ completed := by
      change currentMatrixRoleEvent406 model ns ctx.keyBytes ctx.counter ctx.routes
        (currentFixedAdvice ctx blockCap fixed) ctx.outerFuel ctx.innerFuel ∅ completed
      exact roleEvent
    have activeEvent := (current406_base_merged_iff_active adjusted blockCap fixed
      basis.database ∅).mp baseAccepted
    have specEventEq : event (currentAdviceEventSpec ctx blockCap fixed cap)
        (SmzaRp05ConditionedExecution.activeMemoryEquiv ctx basis.workspace)
        basis.database =
      currentRoleEvent406Explicit adjusted.model adjusted.leafNamespace
        (fun key => adjusted.keyBytes key.val) adjusted.counter adjusted.routes adjusted.role
        adjusted.advice adjusted.outerFuel adjusted.innerFuel ∅ basis.database := by
      change currentRoleEvent406Explicit ctx.model ctx.leafNamespace
        (fun key => ctx.keyBytes key.val) ctx.counter ctx.routes ctx.role
        (currentFixedAdvice ctx blockCap fixed) ctx.outerFuel ctx.innerFuel ∅ basis.database =
        currentRoleEvent406Explicit adjusted.model adjusted.leafNamespace
          (fun key => adjusted.keyBytes key.val) adjusted.counter adjusted.routes adjusted.role
          adjusted.advice adjusted.outerFuel adjusted.innerFuel ∅ basis.database
      rfl
    rw [specEventEq]
    exact Or.inl activeEvent
  · exact Or.inr challengeClaims

/-- Transport the DECS-sample classifier's single bad query to the actual
accepted sample output and construct the source event on the same trace. -/
theorem grouped_decs_sample_failure_support_implies_current_advice_event_or_missing_claims
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (certificates : GeneratedCertificates currentDsl)
    (bounded : ModelWithinProtocol (relationModel currentDsl certificates))
    (blockCap : Role → Nat)
    (positiveDecsMatrixCap : 0 < blockCap .decsMatrix)
    (positivePiopOpeningCap : 0 < blockCap .piopOpening)
    (branch : Branches groupedDecode
      (actualVerifierProgram producer ns statement pending nonce))
    (fixed : FixedTable
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded .decsSample) blockCap)
    (dummy : ActiveKey .decsSample blockCap
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded .decsSample).keyBytes)
    (initial : CmsState
      (Key := Key (actualVerifierProgram producer ns statement pending nonce))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (basis : Basis (ActiveKey .decsSample blockCap
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded .decsSample).keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (SmzaRp05ConditionedExecution.ActiveMemory
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded .decsSample)))
    (cap : Nat)
    (support : selectedRoleState
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded .decsSample)
      blockCap (encode (actualVerifierProgram producer ns statement pending nonce))
      groupedDecode (actualVerifierProgram producer ns statement pending nonce)
      branch fixed
      (fixedFiberToActive
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded .decsSample)
        blockCap dummy fixed (otherRoleTransform
          (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
            (relationModel currentDsl certificates) bounded .decsSample)
          blockCap initial))
      (groupedFailureSelector (BaseWork := BaseWork) producer ns statement pending nonce fallback 28 (relationModel currentDsl certificates)
        bounded .decsSample branch) basis ≠ 0) :
    event (currentAdviceEventSpec
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded .decsSample)
      blockCap fixed cap)
      (SmzaRp05ConditionedExecution.activeMemoryEquiv
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded .decsSample) basis.workspace)
      basis.database ∨
    ¬ ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded .decsSample)
        blockCap (encode (actualVerifierProgram producer ns statement pending nonce))
        groupedDecode (actualVerifierProgram producer ns statement pending nonce) branch)
      basis.database := by
  classical
  let model := relationModel currentDsl certificates
  let program := actualVerifierProgram producer ns statement pending nonce
  let ctx := groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce model bounded .decsSample
  let select := groupedFailureSelector (BaseWork := BaseWork) producer ns statement pending nonce fallback 28 model bounded .decsSample branch
  let fiberInitial := fixedFiberToActive ctx blockCap dummy fixed
    (otherRoleTransform ctx blockCap initial)
  by_cases challengeClaims : ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims ctx blockCap (encode program) groupedDecode program branch)
      basis.database
  · have evidence := selected_xview_failure_role_replays_on_completion
      producer ns statement pending nonce fallback 28
      ctx blockCap (by intro key; rfl) branch fixed
      fiberInitial basis challengeClaims support
    rcases evidence with ⟨recordsCollisionFree, wire, transcript, producerSuccess,
      verifierAccepted, transcriptSuccess, execution, pcs, coordinates, query, input,
      ordered, image, indexes, inputRecord, hashRecord, currentOutcome, labelOutcome,
      roleFailure⟩
    have selectedJoin := selected_support_supplies_full_branch_claims ctx blockCap
      (encode program) groupedDecode program branch fixed
      fiberInitial select basis support challengeClaims
    have mergedClaims := selectedJoin.2.1
    let completed := mergeFixedActive ctx blockCap fixed basis.database
    let oracle := finiteGroupedDatabaseOracle program completed fallback
    have claims : ClaimsDatabaseEvent
        (branchClaims (branchKeys (encode program) groupedDecode program branch)
          (branchAnswers (encode program) groupedDecode program branch)) completed := by
      simpa only [completed] using mergedClaims
    have actualRecord := actual_program_grouped_claims_replay_and_retain
      program branch completed claims fallback
    have actualSuccess : program.eval oracle = some () := by
      change producer.eval oracle = some wire at producerSuccess
      change (verifierProgram ns currentDsl statement pending nonce wire).eval oracle = some ()
        at verifierAccepted
      change (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire).eval
        oracle = some ()
      rw [Program.eval_bind, producerSuccess]
      exact verifierAccepted
    have accepted : branchResult groupedDecode program branch = some () := by
      have recordResult : (program.record oracle).1 = branchResult groupedDecode program branch :=
        congrArg Prod.fst actualRecord.1
      calc
        branchResult groupedDecode program branch = (program.record oracle).1 := recordResult.symm
        _ = program.eval oracle := Program.record_result oracle program
        _ = some () := actualSuccess
    have nonchallengeRetained : ∀ call,
        call ∈ ((verifierProgram ns currentDsl statement pending nonce wire).record oracle).2 →
        parseStageQuery call.1 = none →
          call ∈ rawRecords (fun key => groupRepresentative (included program key))
            (vectorOutputBytes groupZero) completed := by
      intro call member queryNone
      have inProgram := Program.bind_log_right oracle producer
        (fun output => verifierProgram ns currentDsl statement pending nonce output)
        wire producerSuccess member
      have inProgramRecord : call ∈ (program.record oracle).2 := by
        simpa [program, actualVerifierProgram] using inProgram
      have recordLog := congrArg Prod.snd actualRecord.1
      change (program.record oracle).2 =
        SmzaRp05PhysicalAcceptedReplayLite.rawLog groupedDecode program branch at recordLog
      have inRawLog : call ∈ SmzaRp05PhysicalAcceptedReplayLite.rawLog groupedDecode program branch := by
        rw [recordLog] at inProgramRecord
        exact inProgramRecord
      exact actualRecord.2 call inRawLog queryNone
    let fullRecords := rawRecords (fun key => groupRepresentative (included program key))
      (vectorOutputBytes groupZero) completed
    let filteredRecords := oneStatementFilter (globalLeafStatement ns) statement.toBytes
      (eraseChallengeRecords fullRecords)
    have filterEq : filteredRecords = oneStatementFilter (globalLeafStatement ns)
        statement.toBytes (eraseChallengeRecords fullRecords) := rfl
    have noWitness : noWitnessRoleFailure .decsSample ns statement pending nonce wire oracle
        transcript execution pcs (eraseChallengeRecords fullRecords) 28 input query := by
      have ctxRole : ctx.role = .decsSample := rfl
      rw [← ctxRole]
      simpa only [oracle, completed, program, fullRecords, actualVerifierProgram] using roleFailure
    dsimp only [noWitnessRoleFailure] at noWitness
    rcases noWitness with ⟨matrixGood, fpp, openingPayload, parsedInput, inputNormalized,
      suffix, parsedOpening, openingNormalized, claimsRead, classifierBad⟩
    have causal := filtered_classifier_source_bad_to_causal
      ns currentDsl statement pending nonce wire oracle transcript execution pcs
      fullRecords filteredRecords filterEq recordsCollisionFree verifierAccepted
      transcriptSuccess nonchallengeRetained 28 (by decide) input query hashRecord fpp openingPayload
      inputNormalized parsedOpening openingNormalized matrixGood classifierBad
    rcases causal with ⟨trace, traceEq, messages, fppBytesEq, coefficientsEq,
      causalMatrixGood, causalBad⟩
    have sampleBinding := accepted_current_decs_sample_output_binding
      producer ns currentDsl statement pending nonce branch completed claims fallback model bounded
      wire transcript execution producerSuccess pcs verifierAccepted transcriptSuccess
    rcases sampleBinding with ⟨_branchOk, vector, sampledQuery, callRecorded, sampleRead,
      sampledImage, _actualQuery⟩
    have suppliedClean : transcript.pendingXofFailure = false := by
      obtain ⟨cleanTranscript, cleanTranscriptSuccess, transcriptClean, _, _⟩ :=
        SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns currentDsl
          statement pending statement.toBytes (statementBindingWords statement) nonce wire oracle
          verifierAccepted
      have sameTranscript : cleanTranscript = transcript :=
        Option.some.inj (cleanTranscriptSuccess.symm.trans transcriptSuccess)
      rw [← sameTranscript]
      exact transcriptClean
    have transcriptCleanData :=
      SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix
        ns currentDsl statement pending statement.toBytes (statementBindingWords statement)
        nonce wire oracle transcript execution suppliedClean
    have openingCleanData := SmzaRp05ExecutablePcsClosureClean.pcs_stages_clean ns
      execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement) wire.tapes wire.paths
      oracle execution.hashFpp execution.pcsPending pcs transcriptCleanData.1
    rcases openingCleanData with
      ⟨openingPendingClean, queryWords, decsWords, queryScan, decsScan, postSampled⟩
    have sampledPendingClean : pcs.sampledPending = false := by
      have merkleCore := SmzaRp05ExecutableChallengeStage.post_merkle_has_executed_core
        ns oracle pcs.merkleInput pcs.post pcs.postExecuted
      have postClean : pcs.post.pending = false := pcs.pendingReturned.symm.trans transcriptCleanData.1
      have inputPendingClean : pcs.merkleInput.pendingXofFailure = false := by
        have pendingEq := postClean.symm.trans merkleCore.2.2.1
        rw [postSampled] at pendingEq
        simp [SmzaRp05ExecutableChallengeStage.pendingFailure] at pendingEq
        exact pendingEq
      have pendingTag := SmzaRp05ExecutablePcsClosureClean.merkle_input_pending
        wire.salt statement.toBytes pcs.sampledPending pcs.indexes pcs.rows
        execution.decs.maskingEvals wire.tapes wire.paths pcs.merkleInput pcs.inputBuilt
      rw [inputPendingClean] at pendingTag
      exact pendingTag.symm
    obtain ⟨_pendingFalse, _words, _scan, _indexesEq, indexesLength, _indexesNodup⟩ :=
      pcs_query_execution_exposes_clean_scan pcs sampledPendingClean
    have selectedQueryEq := classifier_query_eq_executed_sample_query pcs.indexes
      coordinates query sampledQuery indexesLength indexes image sampledImage
    have causalBadSample : currentSourceBad406
        (currentSourcePrefix406 (causalOracle ns trace) messages.fpp
          (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
            (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
          (baseOpeningPoints execution.opening.1)
          (SmzaRp05TracePrefixes.queryCoefficients messages.decs) causalMatrixGood)
        sampledQuery := by
      rw [← selectedQueryEq]
      exact causalBad
    let keyBytes := fun key : Key program => groupRepresentative (included program key)
    let callInput := counterInput decsFixedSamplingDomain pcs.openingDigest 0
    let callKey := encode program callInput
    let stageQuery : StageQuery := ⟨.decsSample, pcs.openingDigest, 0, 0⟩
    let zeroCounter : Fin (2 ^ 64) := ⟨0, by norm_num⟩
    let leading : V8SmzaOracleParser.RawInput :=
      encodeLE 8 V8SmzaOracleParser.profileDomain.length ++
        V8SmzaOracleParser.profileDomain ++
        encodeLE 8 decsFixedSamplingDomain.length ++ decsFixedSamplingDomain ++
        encodeLE 8 8 ++ List.ofFn pcs.openingDigest
    have parsedZero : parseStageQuery (leading ++ encodeLE 8 0) = some stageQuery := by
      change parseStageQuery
        (SmzaRp05ExecutableChallengeStage.counterInput decsFixedSamplingDomain pcs.openingDigest 0) = _
      simpa only [SmzaChallengeStageTargets.roleDomain,
        SmzaRp05ExecutableChallengeStage.counterInput, zeroCounter, Fin.val_mk, stageQuery] using
        ordinary_counter_roundtrip .decsSample (by decide) pcs.openingDigest zeroCounter
    let rolePrefix : CanonicalRolePrefix :=
      ⟨.decsSample, leading, ⟨stageQuery, parsedZero, rfl⟩⟩
    have encodedZero : groupEncode (rolePrefix, groupZero) = callInput := by
      change leading ++ encodeLE 8 0 = _
      rfl
    have represented := SmzaRp05CurrentFiniteGroupedProgram.answer_log_group_keys_represented
      groupedDecode program branch (callInput, vector) callRecorded
    have keyIdentity : included program (encode program callInput) = Sum.inl rolePrefix := by
      calc
        included program (encode program callInput) = groupKeyOf callInput := represented
        _ = Sum.inl rolePrefix := by
          change (groupAddress callInput).1 = _
          rw [← encodedZero]
          exact congrArg Prod.fst (group_address_encode rolePrefix groupZero)
    have representativeParsed : parseStageQuery (keyBytes callKey) = some stageQuery := by
      change parseStageQuery (groupRepresentative (included program (encode program callInput))) = _
      rw [keyIdentity]
      have representativeParsed' : parseStageQuery
          (groupRepresentative (Sum.inl rolePrefix)) = some stageQuery := by
        simpa only [groupRepresentative, groupEncode, rolePrefix, groupZero,
          V8Smz9CoherentVectorMerkle.canonicalRepresentative,
          V8Smz9RawCounterCompiler.boundedCounterInput,
          V8Smz9RawCounterCompiler.counterInput, Fin.val_mk] using parsedZero
      exact representativeParsed'
    have roleRead := current_actual_grouped_role_call_readback program branch
      (callInput, vector) callRecorded completed claims fallback .decsSample stageQuery
      representativeParsed rfl rfl
    obtain ⟨_, _, _, _, targetRead, stored, _, _⟩ := roleRead
    have retainedOuter := accepted_stages_raw_nonleaf_outer_preambles
      producer ns currentDsl statement pending nonce completed fallback wire transcript execution pcs
      verifierAccepted transcriptSuccess 28 (by decide) recordsCollisionFree nonchallengeRetained
    have outerReadback : preambleFromTrace ns .decsSample
        (extract (globalOnlineNext ns)
          (nonleafFilter (globalLeafStatement ns) fullRecords) 28 .decs pcs.openingDigest) =
          some statement.toBytes := by
      change preambleFromTrace ns .decsSample
        (extract (globalOnlineNext ns)
          (nonleafFilter (globalLeafStatement ns)
            (rawRecords
              (fun key => groupRepresentative
                (included (producer.bind fun candidate =>
                  verifierProgram ns currentDsl statement pending nonce candidate) key))
              (vectorOutputBytes groupZero) completed))
          28 .decs pcs.openingDigest) = some statement.toBytes
      exact retainedOuter .decsSample
    have filteredTraces := current_stages_supply_filtered_role_traces
      producer ns currentDsl statement pending nonce completed fallback
      wire transcript execution pcs verifierAccepted transcriptSuccess 28 (by decide)
      recordsCollisionFree nonchallengeRetained
    have filteredTraceReadback :
        extract (globalOnlineNext ns) filteredRecords 28 .decs pcs.openingDigest =
          causalTrace
            (extract (globalOnlineNext ns) filteredRecords 28 .decs pcs.openingDigest)
            .decsSample := by
      simpa only [fullRecords, filteredRecords, program, actualVerifierProgram,
        stageQuery, currentOuterTarget] using filteredTraces.2 .decsSample
    have filteredEraseEq := global_extract_filtered_erase_challenge ns fullRecords
      (keepOneStatement (globalLeafStatement ns) statement.toBytes) 28 .decs stageQuery.target
    have innerReadback : extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes fullRecords)
        28 .decs stageQuery.target = causalTrace trace .decsSample := by
      calc
        extract (globalOnlineNext ns)
            (oneStatementFilter (globalLeafStatement ns) statement.toBytes fullRecords)
            28 .decs stageQuery.target = extract (globalOnlineNext ns) filteredRecords
              28 .decs stageQuery.target := by
                rw [filterEq]
                simpa only [oneStatementFilter, keepOneStatement] using filteredEraseEq.symm
        _ = causalTrace trace .decsSample := by
          rw [traceEq]
          simpa only [stageQuery] using filteredTraceReadback
    have filteredMemberships := accepted_execution_supplies_filtered_causal_records
      ns currentDsl statement pending nonce wire oracle transcript execution pcs
      fullRecords filteredRecords filterEq verifierAccepted transcriptSuccess nonchallengeRetained
    rcases filteredMemberships with ⟨openingFiltered, finalFiltered, hashFiltered⟩
    have coefficientsClean : pcs.post.pending = false :=
      pcs.pendingReturned.symm.trans transcriptCleanData.1
    have openingClean : execution.openingPending = false := openingPendingClean
    have actualEarlier := SmzaRp05CurrentExecutedEarlierAdvice.actual_execution_supplies_earlier_readback
      currentDsl certificates statement ns pending nonce wire oracle transcript execution pcs
      filteredRecords recordsCollisionFree openingFiltered finalFiltered hashFiltered
      coefficientsClean suppliedClean openingClean
    obtain ⟨earlierTrace, earlierTraceEq, earlierMessages, oracleEarlier⟩ := actualEarlier
    have sourceTraceEq : earlierTrace = trace := by rw [earlierTraceEq, traceEq]
    have oracleEarlierOnTrace : EarlierReadback model statement
        (fun selected => currentOracleAllAdvice model oracle selected statement)
        messages
        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
          (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening := by
      cases sourceTraceEq
      have sameMessages :=
        SmzaRp05CurrentAcceptedCausalPayloadIdentity.causal_payloads_unique
          earlierMessages messages
      rw [sameMessages] at oracleEarlier
      exact oracleEarlier
    let selector : SmzaRp05ConditionedExecution.ActiveMemory ctx →
        Database (ActiveKey ctx.role blockCap ctx.keyBytes) (VectorOutput GroupCounter) → Prop :=
      fun work activeDatabase => branchXRoleSelector ctx blockCap (encode program) groupedDecode
        program branch (nonchallengeRawKeySet ctx)
        (by
          intro claim member
          exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
            of_decide_eq_true (List.mem_filter.mp member).2⟩)
        select (activeXView ctx blockCap (nonchallengeRawKeySet ctx)
          (nonchallenge_raw_key_set_unrecognized ctx) activeDatabase) work.original.2.2
    have physicalNonzero : fixedFiberToActive ctx blockCap dummy fixed
        (otherRoleTransform ctx blockCap (physicalRun (encode program) groupedDecode program branch initial))
        basis ≠ 0 := by
      have supportPhysical := support
      unfold selectedRoleState at supportPhysical
      rw [← physical_run_to_mixed_same_fiber ctx blockCap dummy fixed
        (encode program) groupedDecode program branch initial] at supportPhysical
      change workspaceEventProjection selector
        (fixedFiberToActive ctx blockCap dummy fixed
          (otherRoleTransform ctx blockCap
            (physicalRun (encode program) groupedDecode program branch initial))) basis ≠ 0
        at supportPhysical
      unfold workspaceEventProjection at supportPhysical
      by_cases selectorHit : selector basis.workspace basis.database
      · simpa [selectorHit] using supportPhysical
      · simp [selectorHit] at supportPhysical
    have fixedOpening := same_stage_current_fixed_opening_scan
      producer ns currentDsl statement pending nonce branch accepted completed claims fallback
      model bounded .decsSample (currentFixedAdvice ctx blockCap fixed) 28 28 (fun _ => ∅)
      blockCap dummy fixed initial basis physicalNonzero (by decide) positivePiopOpeningCap wire
      producerSuccess verifierAccepted transcript transcriptSuccess execution pcs
    have causalPayloads := SmzaRp05CurrentAcceptedCausalPayloads.current_causal_payloads_and_targets_of_stages
      ns currentDsl statement pending nonce wire oracle transcript execution pcs
      filteredRecords recordsCollisionFree openingFiltered finalFiltered hashFiltered
    rcases causalPayloads with ⟨payloadTrace, payloadTraceEq, payloadMessages,
      fppDigest, piopDigest, decsDigest⟩
    have payloadTraceSame : payloadTrace = trace := by rw [payloadTraceEq, traceEq]
    let payloadMessagesOnTrace : CausalPayloads ns trace :=
      payloadTraceSame ▸ payloadMessages
    have payloadMessagesSame :=
      SmzaRp05CurrentAcceptedCausalPayloadIdentity.causal_payloads_unique
        payloadMessagesOnTrace messages
    have fppDigestOnTrace :
      V8SmzaOracleParser.digestAt messages.fpp.bytes 0 = pcs.post.root := by
      have digestOnPayload :
          V8SmzaOracleParser.digestAt payloadMessagesOnTrace.fpp.bytes 0 = pcs.post.root := by
        cases payloadTraceSame
        simpa only [payloadMessagesOnTrace] using fppDigest
      rw [← payloadMessagesSame]
      exact digestOnPayload
    have decsDigestOnTrace :
        V8SmzaOracleParser.digestAt messages.decs.bytes 0 = wire.hPiop := by
      have digestOnPayload :
          V8SmzaOracleParser.digestAt payloadMessagesOnTrace.decs.bytes 0 = wire.hPiop := by
        cases payloadTraceSame
        simpa only [payloadMessagesOnTrace] using decsDigest
      rw [← payloadMessagesSame]
      exact digestOnPayload
    have earlierFixed := same_stage_fixed_decs_sample_earlier_readback
      producer ns currentDsl statement pending nonce branch accepted completed claims fallback
      certificates bounded (currentFixedAdvice ctx blockCap fixed) 28 28 (fun _ => ∅)
      blockCap dummy fixed initial basis physicalNonzero positiveDecsMatrixCap wire producerSuccess
      verifierAccepted transcript transcriptSuccess execution pcs fixedOpening messages
      decsDigestOnTrace fppDigestOnTrace oracleEarlierOnTrace
    let adviceFamily : (selected : Role) → AllEarlierTables model selected :=
      fun selected => currentFixedEarlierAdviceFamily ctx blockCap fixed oracle selected
    have ctxRole : ctx.role = .decsSample := rfl
    have familyAtSample : adviceFamily .decsSample = currentFixedAdvice ctx blockCap fixed := by
      change currentFixedEarlierAdviceFamily ctx blockCap fixed oracle ctx.role = _
      exact currentFixedEarlierAdviceFamily_active ctx blockCap fixed oracle
    have sampledBad : currentSourceBad406
        (currentSourcePrefix406 (causalOracle ns trace) messages.fpp
          (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
            (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
          (baseOpeningPoints execution.opening.1)
          (SmzaRp05TracePrefixes.queryCoefficients messages.decs) causalMatrixGood)
        sampledQuery := by
      rw [← selectedQueryEq]
      exact causalBad
    have roleEvent := source_bad_on_same_trace_yields_event_of_family
      model ns keyBytes groupZero (currentGroupedRoutes model bounded)
      (currentFixedAdvice ctx blockCap fixed) adviceFamily familyAtSample 28 28 ∅ completed
      statement (by simp) callKey vector stored stageQuery representativeParsed rfl targetRead
      sampledQuery sampleRead trace messages
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening
      earlierFixed causalMatrixGood sampledBad outerReadback innerReadback
    let adjusted := { ctx with advice := currentFixedAdvice ctx blockCap fixed }
    have baseAccepted : current406Base adjusted ∅ completed := by
      change currentSourceRoleEvent406 model ns ctx.keyBytes ctx.counter ctx.routes
        (currentFixedAdvice ctx blockCap fixed) ctx.outerFuel ctx.innerFuel ∅ completed
      exact roleEvent
    have activeEvent := (current406_base_merged_iff_active adjusted blockCap fixed
      basis.database ∅).mp baseAccepted
    have specEventEq : event (currentAdviceEventSpec ctx blockCap fixed cap)
        (SmzaRp05ConditionedExecution.activeMemoryEquiv ctx basis.workspace) basis.database =
      currentRoleEvent406Explicit adjusted.model adjusted.leafNamespace
        (fun key => adjusted.keyBytes key.val) adjusted.counter adjusted.routes adjusted.role
        adjusted.advice adjusted.outerFuel adjusted.innerFuel ∅ basis.database := by
      change currentRoleEvent406Explicit ctx.model ctx.leafNamespace
        (fun key => ctx.keyBytes key.val) ctx.counter ctx.routes ctx.role
        (currentFixedAdvice ctx blockCap fixed) ctx.outerFuel ctx.innerFuel ∅ basis.database =
        currentRoleEvent406Explicit adjusted.model adjusted.leafNamespace
          (fun key => adjusted.keyBytes key.val) adjusted.counter adjusted.routes adjusted.role
          adjusted.advice adjusted.outerFuel adjusted.innerFuel ∅ basis.database
      rfl
    rw [specEventEq]
    exact Or.inl activeEvent
  · exact Or.inr challengeClaims

/-- Dispatch the guard-free accepted-extraction failure support over all
four currently counted roles. Every arm returns the current fixed-advice
event for that same basis or the exact missing-recognized-claims alternative. -/
theorem grouped_four_role_failure_support_implies_current_advice_event_or_missing_claims
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (certificates : GeneratedCertificates currentDsl)
    (bounded : ModelWithinProtocol (relationModel currentDsl certificates))
    (blockCap : Role → Nat)
    (positiveDecsMatrixCap : 0 < blockCap .decsMatrix)
    (positivePiopMatrixCap : 0 < blockCap .piopMatrix)
    (positivePiopOpeningCap : 0 < blockCap .piopOpening)
    (role : Role)
    (branch : Branches groupedDecode
      (actualVerifierProgram producer ns statement pending nonce))
    (fixed : FixedTable
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded role) blockCap)
    (dummy : ActiveKey role blockCap
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded role).keyBytes)
    (initial : CmsState
      (Key := Key (actualVerifierProgram producer ns statement pending nonce))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (basis : Basis (ActiveKey role blockCap
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded role).keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (SmzaRp05ConditionedExecution.ActiveMemory
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded role)))
    (cap : Nat)
    (support : selectedRoleState
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded role)
      blockCap (encode (actualVerifierProgram producer ns statement pending nonce))
      groupedDecode (actualVerifierProgram producer ns statement pending nonce)
      branch fixed
      (fixedFiberToActive
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded role)
        blockCap dummy fixed (otherRoleTransform
          (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
            (relationModel currentDsl certificates) bounded role)
          blockCap initial))
      (groupedFailureSelector (BaseWork := BaseWork) producer ns statement pending nonce fallback 28
        (relationModel currentDsl certificates) bounded role branch) basis ≠ 0) :
    event (currentAdviceEventSpec
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded role)
      blockCap fixed cap)
      (SmzaRp05ConditionedExecution.activeMemoryEquiv
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded role) basis.workspace)
      basis.database ∨
    ¬ ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded role)
        blockCap (encode (actualVerifierProgram producer ns statement pending nonce))
        groupedDecode (actualVerifierProgram producer ns statement pending nonce) branch)
      basis.database := by
  cases role with
  | decsMatrix =>
      exact grouped_decs_matrix_failure_support_implies_current_advice_event_or_missing_claims
        producer ns statement pending nonce fallback certificates bounded blockCap branch
        fixed dummy initial basis cap support
  | decsSample =>
      exact grouped_decs_sample_failure_support_implies_current_advice_event_or_missing_claims
        producer ns statement pending nonce fallback certificates bounded blockCap
        positiveDecsMatrixCap positivePiopOpeningCap branch fixed dummy initial basis cap support
  | piopMatrix =>
      exact grouped_piop_failure_support_implies_current_advice_event_or_missing_claims
        producer ns statement pending nonce fallback certificates bounded blockCap .matrix
        positiveDecsMatrixCap positivePiopMatrixCap branch fixed dummy initial basis cap support
  | piopOpening =>
      exact grouped_piop_failure_support_implies_current_advice_event_or_missing_claims
        producer ns statement pending nonce fallback certificates bounded blockCap .opening
        positiveDecsMatrixCap positivePiopMatrixCap branch fixed dummy initial basis cap support


end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsExtractionFailureEvent
