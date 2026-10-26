import SmzaRp05ContextAmbientPiop
import SmzaRp05ContextAmbientSampleEvent
import SmzaRp05ContextAmbientSampleSupport
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
namespace HegemonCrypto.SmallWood.SmzaRp05ContextAmbientFourRole

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


open SmzaRp05ContextAmbientDecoder (ParsedContext fixedNamespaceContextProgram)
open SmzaRp05ContextAmbientCoverage (ambientXViewFailureRoleSelector)

private def groupedRoleContext
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ParsedContext)
    (ns : SmzaRp05LeafNamespace.Namespace)
 (model : RelationModel)
    (bounded : ModelWithinProtocol model) (role : Role) :
    Context (Key := Key (fixedNamespaceContextProgram ns producer))
      (Counter := GroupCounter) (BaseWork := BaseWork) :=
  currentGroupedContext (fixedNamespaceContextProgram ns producer)
    model bounded ns role (emptyInitialAdvice model role) 28 28 (fun _ => ∅)

private def groupedFailureSelector
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ParsedContext)
    (ns : SmzaRp05LeafNamespace.Namespace)
 (fallback : RawDigest)
    (fuel : Nat) (model : RelationModel) (bounded : ModelWithinProtocol model)
    (role : Role)
    (branch : Branches groupedDecode
      (fixedNamespaceContextProgram ns producer)) :
    (view : XKey (nonchallengeRawKeySet
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        model bounded role)) →
        Option (VectorOutput GroupCounter)) →
      SmzaRp05CurrentAdaptiveExecution.Work (Counter := GroupCounter)
        (BaseWork := BaseWork) → Prop :=
  let ctx := groupedRoleContext (BaseWork := BaseWork) producer ns
    model bounded role
  fun view _work => ambientXViewFailureRoleSelector producer ns
    fallback fuel ctx role branch view

theorem grouped_four_role_failure_support_implies_current_advice_event_or_missing_claims
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ParsedContext)
    (ns : SmzaRp05LeafNamespace.Namespace)
 (fallback : RawDigest)
    (certificates : GeneratedCertificates currentDsl)
    (bounded : ModelWithinProtocol (relationModel currentDsl certificates))
    (blockCap : Role → Nat)
    (positiveDecsMatrixCap : 0 < blockCap .decsMatrix)
    (positivePiopMatrixCap : 0 < blockCap .piopMatrix)
    (positivePiopOpeningCap : 0 < blockCap .piopOpening)
    (role : Role)
    (branch : Branches groupedDecode
      (fixedNamespaceContextProgram ns producer))
    (fixed : FixedTable
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        (relationModel currentDsl certificates) bounded role) blockCap)
    (dummy : ActiveKey role blockCap
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        (relationModel currentDsl certificates) bounded role).keyBytes)
    (initial : CmsState
      (Key := Key (fixedNamespaceContextProgram ns producer))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (basis : Basis (ActiveKey role blockCap
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        (relationModel currentDsl certificates) bounded role).keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (SmzaRp05ConditionedExecution.ActiveMemory
        (groupedRoleContext (BaseWork := BaseWork) producer ns
          (relationModel currentDsl certificates) bounded role)))
    (cap : Nat)
    (support : selectedRoleState
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        (relationModel currentDsl certificates) bounded role)
      blockCap (encode (fixedNamespaceContextProgram ns producer))
      groupedDecode (fixedNamespaceContextProgram ns producer)
      branch fixed
      (fixedFiberToActive
        (groupedRoleContext (BaseWork := BaseWork) producer ns
          (relationModel currentDsl certificates) bounded role)
        blockCap dummy fixed (otherRoleTransform
          (groupedRoleContext (BaseWork := BaseWork) producer ns
            (relationModel currentDsl certificates) bounded role)
          blockCap initial))
      (groupedFailureSelector (BaseWork := BaseWork) producer ns fallback 28
        (relationModel currentDsl certificates) bounded role branch) basis ≠ 0) :
    event (currentAdviceEventSpec
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        (relationModel currentDsl certificates) bounded role)
      blockCap fixed cap)
      (SmzaRp05ConditionedExecution.activeMemoryEquiv
        (groupedRoleContext (BaseWork := BaseWork) producer ns
          (relationModel currentDsl certificates) bounded role) basis.workspace)
      basis.database ∨
    ¬ ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims
        (groupedRoleContext (BaseWork := BaseWork) producer ns
          (relationModel currentDsl certificates) bounded role)
        blockCap (encode (fixedNamespaceContextProgram ns producer))
        groupedDecode (fixedNamespaceContextProgram ns producer) branch)
      basis.database := by
  cases role with
  | decsMatrix =>
      exact SmzaRp05ContextAmbientMatrixSupport.grouped_decs_matrix_failure_support_implies_current_advice_event_or_missing_claims
        producer ns fallback certificates bounded blockCap branch
        fixed dummy initial basis cap support
  | decsSample =>
      exact SmzaRp05ContextAmbientSampleEvent.grouped_decs_sample_failure_support_implies_current_advice_event_or_missing_claims
        producer ns fallback certificates bounded blockCap
        positiveDecsMatrixCap positivePiopOpeningCap branch fixed dummy initial basis cap support
  | piopMatrix =>
      exact SmzaRp05CurrentAcceptedPiopExtractionFailureEventAmbientPiop.grouped_piop_failure_support_implies_current_advice_event_or_missing_claims
        producer ns fallback certificates bounded blockCap .matrix
        positiveDecsMatrixCap positivePiopMatrixCap branch fixed dummy initial basis cap support
  | piopOpening =>
      exact SmzaRp05CurrentAcceptedPiopExtractionFailureEventAmbientPiop.grouped_piop_failure_support_implies_current_advice_event_or_missing_claims
        producer ns fallback certificates bounded blockCap .opening
        positiveDecsMatrixCap positivePiopMatrixCap branch fixed dummy initial basis cap support


end
end HegemonCrypto.SmallWood.SmzaRp05ContextAmbientFourRole
